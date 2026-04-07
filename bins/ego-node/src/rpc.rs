use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use ego_core::{AccountType, Address, AlgorithmId, Balance, Block, KeyPair, PublicKey, StateManager, Transaction};
use ego_core::state::{MIN_VALIDATOR_STAKE, ValidatorStatus};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::mpsc;
use tower_http::cors::CorsLayer;

use crate::mempool::ShardedMempool;
use crate::supervisor::NodeSupervisor;

pub struct RpcState {
    pub state_manager:  StateManager,
    pub peer_id:        String,

    pub node_address:   String,

    pub node_pubkey:    String,

    pub node_keypair:   KeyPair,

    pub payout_address: Option<String>,
    pub pending_txs:    ShardedMempool,

    pub recent_blocks:  Mutex<Vec<BlockSummary>>,
    pub node_stats:     Mutex<NodeStats>,

    pub nonce:          Mutex<u64>,

    pub supervisor:     Arc<NodeSupervisor>,

    pub faucet_claims:  Mutex<HashMap<String, u64>>,

    /// Per-IP write-rate tracker: (request_count, window_start)
    pub write_rate:     Mutex<HashMap<IpAddr, (u32, Instant)>>,

    /// Channel for sending tx bytes to the daemon gossip loop (mempool propagation).
    pub mempool_gossip_tx: mpsc::UnboundedSender<Vec<u8>>,

    /// Known peer HTTP RPC addresses: peer_id_hex → "http://ip:port"
    pub peer_rpc_addrs: Mutex<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlockSummary {
    pub height:    u64,
    pub hash:      String,
    pub tx_count:  usize,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct NodeStats {
    pub uptime_seconds:               u64,
    pub messages_sent:                u64,
    pub messages_received:            u64,
    pub bytes_sent:                   u64,
    pub bytes_received:               u64,
    pub peer_connections_established: u64,
    pub pending_tx_count:             usize,
    pub shard_count:                  usize,
}

/// Returns `true` if the request is within the allowed rate, `false` to reject with 429.
/// Allows `max_per_sec` write operations per IP per second.
fn rate_ok(state: &RpcState, ip: IpAddr, max_per_sec: u32) -> bool {
    let mut map = state.write_rate.lock().unwrap();
    let now = Instant::now();
    let entry = map.entry(ip).or_insert((0, now));
    if now.duration_since(entry.1).as_secs() >= 1 {
        *entry = (1, now);
        true
    } else if entry.0 < max_per_sec {
        entry.0 += 1;
        true
    } else {
        false
    }
}

pub fn make_router(state: Arc<RpcState>) -> Router {
    Router::new()
        .route("/",                   get(root))
        .route("/health",             get(health))
        .route("/chain/blocks",       get(chain_blocks))
        .route("/block/:height",      get(block_by_height))
        .route("/balance/:address",   get(balance))
        .route("/nonce/:address",     get(get_nonce))
        .route("/account/:address",   get(get_account_state))
        .route("/tx/submit",          post(tx_submit))
        .route("/tx/:hash",           get(get_tx_by_hash))
        .route("/chain/transactions", get(chain_transactions))
        .route("/chain/finalized",    get(chain_finalized))
        .route("/node/stats",         get(node_stats))
        .route("/node/identity",      get(node_identity))
        .route("/faucet",             get(faucet))
        .route("/tx/broadcast",       post(tx_broadcast))
        .route("/block/broadcast",    post(block_broadcast))
        .route("/blocks/range",       get(blocks_range))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn root() -> impl IntoResponse {
    Json(serde_json::json!({
        "name":    "Ego Blockchain Node",
        "version": env!("CARGO_PKG_VERSION"),
        "docs":    "/health · /chain/blocks · /chain/transactions · /balance/:address · /node/identity · /faucet?to=<address>",
    }))
}

async fn health(State(s): State<Arc<RpcState>>) -> impl IntoResponse {
    let height    = s.state_manager.get_block_height();
    let node_health = s.supervisor.health().await;
    Json(serde_json::json!({
        "status":       node_health.status,
        "block_height": height.0,
        "peer_id":      &s.peer_id,
        "uptime_secs":  node_health.uptime_secs,
        "components":   node_health.components,
    }))
}

async fn chain_blocks(_s: State<Arc<RpcState>>) -> impl IntoResponse {
    // Serve newest 500 blocks from the persistent store — no memory pressure.
    let blocks = crate::store::get_blocks(500);
    Json(blocks)
}

async fn block_broadcast(
    State(s):          State<Arc<RpcState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body):        Json<serde_json::Value>,
) -> impl IntoResponse {
    if !rate_ok(&s, peer.ip(), 5) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": "rate limit exceeded" }))).into_response();
    }
    // Parse as a typed Block — rejects arbitrary JSON.
    let block: Block = match serde_json::from_value(body.clone()) {
        Ok(b) => b,
        Err(e) => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("invalid block: {e}") })),
        ).into_response(),
    };
    // Structural sanity check (tx_count header field matches body, etc.).
    if let Err(e) = block.validate_structure() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("block structure invalid: {e}") })),
        ).into_response();
    }

    // ── Consensus gate #1: proposer must be a registered Active validator ─────
    let validator = match s.state_manager.get_validator(&block.header.core.proposer) {
        Some(v) => v,
        None => return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "proposer is not a registered validator" })),
        ).into_response(),
    };
    if !matches!(validator.status, ValidatorStatus::Active) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "proposer validator is not Active",
                "status": format!("{:?}", validator.status),
            })),
        ).into_response();
    }
    if validator.total_stake.as_u128() < MIN_VALIDATOR_STAKE {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "proposer stake below minimum",
                "stake":   validator.total_stake.as_u128(),
                "minimum": MIN_VALIDATOR_STAKE,
            })),
        ).into_response();
    }

    // ── Consensus gate #2: PoST recency — validator must have been active within 2 epochs ──
    let current_epoch = s.state_manager.get_current_epoch();
    if current_epoch > 2 && validator.last_active_epoch + 2 < current_epoch {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "validator PoST proof is stale",
                "last_active_epoch": validator.last_active_epoch,
                "current_epoch":     current_epoch,
            })),
        ).into_response();
    }

    // Look up the proposer's full account for key access (Ed25519 / Dilithium).
    let account = match s.state_manager.get_account(&block.header.core.proposer) {
        Some(a) => a,
        None => return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "proposer account not found on-chain" })),
        ).into_response(),
    };

    // ── Consensus gate #3: VRF proof verification ─────────────────────────────
    // Require a valid Ed25519 VRF proof that produced vrf_output.
    // Construction: proof = Ed25519_sign(SK, BLAKE2s(dilithium_pk || epoch || height))
    //               output = BLAKE2s("ego/vrf/v1:" || proof)
    {
        let proof_bytes = match block.header.core.vrf_proof.as_deref() {
            Some(p) if p.len() == 64 => p,
            Some(_) => return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "vrf_proof must be exactly 64 bytes" })),
            ).into_response(),
            None => return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "missing vrf_proof" })),
            ).into_response(),
        };

        // Retrieve the proposer's Ed25519 public key from their on-chain account.
        // (vrf input is keyed by dilithium_pk which is always present)
        let ed_pk = match account.ed25519_pk.as_deref() {
            Some(k) if k.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(k);
                PublicKey::ed25519(arr)
            }
            _ => return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "proposer has no Ed25519 public key for VRF verification" })),
            ).into_response(),
        };

        // Reconstruct the VRF input: BLAKE2s(dilithium_pk || epoch_le || height_le)
        let epoch  = block.header.core.epoch.as_u64();
        let height = block.header.core.height.as_u64();
        let vrf_input = ego_core::hash_multiple(&[
            account.dilithium_pk.as_slice(),
            &epoch.to_le_bytes(),
            &height.to_le_bytes(),
        ]);

        // Verify the Ed25519 signature (proof) over the VRF input.
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(proof_bytes);
        let ed_sig = ego_core::Signature::ed25519(sig_arr);
        match ego_core::verify_signature(&ed_pk, vrf_input.as_bytes(), &ed_sig) {
            Ok(true) => {}
            _ => return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "invalid VRF proof signature" })),
            ).into_response(),
        }

        // Verify the vrf_output field matches BLAKE2s("ego/vrf/v1:" || proof).
        let expected_output = ego_core::hash_multiple(&[b"ego/vrf/v1:", proof_bytes]);
        if block.header.core.vrf_output != *expected_output.as_bytes() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "vrf_output does not match proof" })),
            ).into_response();
        }
    }

    // ── Verify proposer signature using public keys from on-chain account ─────
    match s.state_manager.get_account(&block.header.core.proposer) {
        Some(account) => {
            let dil_pk = PublicKey::new(AlgorithmId::MlDsa2, account.dilithium_pk.clone());
            let ed_pk  = account.ed25519_pk.as_ref()
                .map(|k| PublicKey::new(AlgorithmId::Ed25519, k.clone()));
            match block.verify_signature(&dil_pk, ed_pk.as_ref()) {
                Ok(true) => {}
                Ok(false) => return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": "invalid block signature" })),
                ).into_response(),
                Err(e) => return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": format!("block signature check error: {e}") })),
                ).into_response(),
            }
        }
        // No account means no public key on chain — reject; the bootstrap loophole is closed.
        None => return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "proposer has no on-chain account; cannot verify signature" })),
        ).into_response(),
    }

    let height = block.header.core.height.as_u64();
    if crate::store::block_exists(height) {
        return (StatusCode::OK, Json(serde_json::json!({ "status": "already known" }))).into_response();
    }
    crate::store::insert_block(height, &body);
    (StatusCode::ACCEPTED, Json(serde_json::json!({ "status": "accepted" }))).into_response()
}

async fn block_by_height(
    Path(height): Path<u64>,
    State(s):     State<Arc<RpcState>>,
) -> impl IntoResponse {

    {
        let blocks = s.recent_blocks.lock().unwrap();
        if let Some(b) = blocks.iter().find(|b| b.height == height) {
            return (StatusCode::OK, Json(serde_json::to_value(b).unwrap())).into_response();
        }
    }

    if let Some(b) = crate::store::get_block_by_height(height) {
        return (StatusCode::OK, Json(b)).into_response();
    }
    (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "block not found" }))).into_response()
}

async fn balance(
    Path(addr_str): Path<String>,
    State(s):       State<Arc<RpcState>>,
) -> impl IntoResponse {
    let bytes = match hex::decode(addr_str.trim_start_matches("0x")) {
        Ok(b) if b.len() == 20 => {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid address — expected 20-byte hex" })),
            ).into_response();
        }
    };
    let addr = Address::new(bytes);

    let balance_raw = s.state_manager
        .get_account(&addr)
        .map(|a| a.balance.0)
        .unwrap_or(0u128);

    const UEGOC_PER_EGOC: u128 = 1_000_000;
    (StatusCode::OK, Json(serde_json::json!({
        "address":       format!("0x{}", hex::encode(addr.as_bytes())),
        "balance_uegoc": balance_raw,
        "balance_egoc":  balance_raw / UEGOC_PER_EGOC,
    }))).into_response()
}

async fn get_nonce(
    Path(addr_str): Path<String>,
    State(s):       State<Arc<RpcState>>,
) -> impl IntoResponse {
    let bytes = match hex::decode(addr_str.trim_start_matches("0x")) {
        Ok(b) if b.len() == 20 => { let mut a = [0u8; 20]; a.copy_from_slice(&b); a }
        _ => return (StatusCode::BAD_REQUEST,
                     Json(serde_json::json!({ "error": "invalid address — expected 20-byte hex" }))).into_response(),
    };
    let addr = Address::new(bytes);
    match s.state_manager.get_account(&addr) {
        Some(acc) => (StatusCode::OK, Json(serde_json::json!({
            "address": format!("0x{}", hex::encode(addr.as_bytes())),
            "nonce":   acc.nonce,
        }))).into_response(),
        None => (StatusCode::NOT_FOUND,
                 Json(serde_json::json!({ "error": "account not found" }))).into_response(),
    }
}

async fn get_account_state(
    Path(addr_str): Path<String>,
    State(s):       State<Arc<RpcState>>,
) -> impl IntoResponse {
    let bytes = match hex::decode(addr_str.trim_start_matches("0x")) {
        Ok(b) if b.len() == 20 => { let mut a = [0u8; 20]; a.copy_from_slice(&b); a }
        _ => return (StatusCode::BAD_REQUEST,
                     Json(serde_json::json!({ "error": "invalid address — expected 20-byte hex" }))).into_response(),
    };
    let addr = Address::new(bytes);
    match s.state_manager.get_account(&addr) {
        Some(acc) => {
            const UEGOC_PER_EGOC: u128 = 1_000_000;
            (StatusCode::OK, Json(serde_json::json!({
                "address":       format!("0x{}", hex::encode(addr.as_bytes())),
                "balance_uegoc": acc.balance.as_u128(),
                "balance_egoc":  acc.balance.as_u128() / UEGOC_PER_EGOC,
                "nonce":         acc.nonce,
                "account_type":  format!("{:?}", acc.account_type),
                "storage_used":  acc.storage_used,
                "storage_quota": acc.storage_quota,
            }))).into_response()
        }
        None => (StatusCode::NOT_FOUND,
                 Json(serde_json::json!({ "error": "account not found" }))).into_response(),
    }
}

async fn get_tx_by_hash(
    Path(hash): Path<String>,
    _s:         State<Arc<RpcState>>,
) -> impl IntoResponse {
    match crate::store::get_tx_by_hash(&hash) {
        Some(v) => (StatusCode::OK, Json(v)).into_response(),
        None    => (StatusCode::NOT_FOUND,
                    Json(serde_json::json!({ "error": "transaction not found" }))).into_response(),
    }
}

/// Probabilistic finality: blocks older than FINALITY_DEPTH are considered final.
const FINALITY_DEPTH: u64 = 6;

async fn chain_finalized(State(s): State<Arc<RpcState>>) -> impl IntoResponse {
    let tip = s.state_manager.get_block_height().0;
    let finalized = tip.saturating_sub(FINALITY_DEPTH);
    Json(serde_json::json!({
        "finalized_height": finalized,
        "tip_height":       tip,
        "finality_depth":   FINALITY_DEPTH,
        "finality_model":   "probabilistic-confirmations",
    }))
}

#[derive(Deserialize)]
struct TxSubmitBody {
    tx: serde_json::Value,
}

async fn tx_submit(
    State(s):                         State<Arc<RpcState>>,
    ConnectInfo(peer):                ConnectInfo<SocketAddr>,
    Json(body):                       Json<TxSubmitBody>,
) -> impl IntoResponse {
    if !rate_ok(&s, peer.ip(), 20) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": "rate limit exceeded" }))).into_response();
    }
    if s.pending_txs.len() as usize >= crate::mempool::MAX_TOTAL {
        return (StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({ "error": "mempool full" }))
        ).into_response();
    }
    match serde_json::from_value::<Transaction>(body.tx) {
        Ok(tx) => {
            match tx.verify_signature() {
                Ok(true) => {}
                Ok(false) => return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": "invalid transaction signature" })),
                ).into_response(),
                Err(e) => return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": format!("signature check error: {e}") })),
                ).into_response(),
            }
            // ── Nonce + balance validation ─────────────────────────────────────
            if let Some(account) = s.state_manager.get_account(&tx.from) {
                let expected_nonce = account.nonce + 1;
                if tx.nonce != expected_nonce {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error":          "invalid nonce",
                            "expected":       expected_nonce,
                            "got":            tx.nonce,
                        })),
                    ).into_response();
                }
                if let ego_core::TransactionPayload::Transfer { amount, .. } = &tx.payload {
                    if account.balance.as_u128() < amount.as_u128() {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({
                                "error":   "insufficient balance",
                                "balance": account.balance.as_u128(),
                                "amount":  amount.as_u128(),
                            })),
                        ).into_response();
                    }
                }
            } else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "sender account not found" })),
                ).into_response();
            }
            let hash = hex::encode(tx.hash.as_bytes());
            let tx_bytes = serde_json::to_vec(&tx).unwrap_or_default();
            match s.pending_txs.insert(tx) {
                Err("duplicate") => {
                    return (StatusCode::ACCEPTED, Json(serde_json::json!({ "tx_hash": hash, "status": "duplicate" }))).into_response();
                }
                Err("full") => {
                    return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": "mempool full" }))).into_response();
                }
                _ => {}
            }
            // Propagate to peers via gossipsub.
            if !tx_bytes.is_empty() {
                let _ = s.mempool_gossip_tx.send(tx_bytes);
            }
            (StatusCode::ACCEPTED, Json(serde_json::json!({ "tx_hash": hash }))).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        ).into_response(),
    }
}

async fn chain_transactions(_s: State<Arc<RpcState>>) -> impl IntoResponse {
    Json(crate::store::get_txs(100))
}

async fn tx_broadcast(
    State(s):          State<Arc<RpcState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body):        Json<serde_json::Value>,
) -> impl IntoResponse {
    if !rate_ok(&s, peer.ip(), 20) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": "rate limit exceeded" }))).into_response();
    }
    // Parse as a typed Transaction — rejects arbitrary JSON that doesn't match the schema.
    let tx: Transaction = match serde_json::from_value(body.clone()) {
        Ok(t) => t,
        Err(e) => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("invalid transaction: {e}") })),
        ).into_response(),
    };
    // Verify Ed25519 + Dilithium dual signature before touching the store.
    match tx.verify_signature() {
        Ok(true) => {}
        Ok(false) => return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid transaction signature" })),
        ).into_response(),
        Err(e) => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("signature check error: {e}") })),
        ).into_response(),
    }
    // ── Nonce + balance validation ─────────────────────────────────────────────
    if let Some(account) = s.state_manager.get_account(&tx.from) {
        let expected_nonce = account.nonce + 1;
        if tx.nonce != expected_nonce {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error":    "invalid nonce",
                    "expected": expected_nonce,
                    "got":      tx.nonce,
                })),
            ).into_response();
        }
        if let ego_core::TransactionPayload::Transfer { amount, .. } = &tx.payload {
            if account.balance.as_u128() < amount.as_u128() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error":   "insufficient balance",
                        "balance": account.balance.as_u128(),
                        "amount":  amount.as_u128(),
                    })),
                ).into_response();
            }
        }
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "sender account not found" })),
        ).into_response();
    }
    let hash = hex::encode(tx.hash.as_bytes());
    if crate::store::tx_exists(&hash) {
        return (StatusCode::OK, Json(serde_json::json!({ "status": "already known" }))).into_response();
    }
    let ts = tx.timestamp.as_secs() as i64;
    crate::store::insert_tx(&hash, ts, &body);
    (StatusCode::ACCEPTED, Json(serde_json::json!({ "status": "accepted" }))).into_response()
}

async fn node_stats(State(s): State<Arc<RpcState>>) -> impl IntoResponse {
    let mut stats = s.node_stats.lock().unwrap().clone();
    stats.pending_tx_count = s.pending_txs.len() as usize;
    Json(stats)
}

async fn node_identity(State(s): State<Arc<RpcState>>) -> impl IntoResponse {
    let balance_raw = {

        let addr_hex = s.node_address.trim_start_matches("0x");
        if let Ok(bytes) = hex::decode(addr_hex) {
            if bytes.len() == 20 {
                let mut arr = [0u8; 20];
                arr.copy_from_slice(&bytes);
                let addr = Address::new(arr);
                s.state_manager.get_account(&addr).map(|a| a.balance.0).unwrap_or(0u128)
            } else { 0u128 }
        } else { 0u128 }
    };
    const UEGOC_PER_EGOC: u128 = 1_000_000;
    Json(serde_json::json!({
        "address":        &s.node_address,
        "public_key_hex": &s.node_pubkey,
        "peer_id":        &s.peer_id,
        "payout_address": &s.payout_address,
        "balance_uegoc":  balance_raw,
        "balance_egoc":   balance_raw / UEGOC_PER_EGOC,
    }))
}

#[derive(Deserialize)]
struct FaucetQuery {
    to: String,
}

async fn faucet(
    State(s): State<Arc<RpcState>>,
    axum::extract::Query(q): axum::extract::Query<FaucetQuery>,
) -> impl IntoResponse {
    const FAUCET_AMOUNT_UEGOC: u64 = 100 * 1_000_000;
    const COOLDOWN_SECS: u64 = 86400;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    {
        let mut claims = s.faucet_claims.lock().unwrap();
        if let Some(&last) = claims.get(&q.to) {
            if now - last < COOLDOWN_SECS {
                let wait = COOLDOWN_SECS - (now - last);
                return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({
                    "error": "faucet cooldown",
                    "wait_seconds": wait,
                    "next_available_unix": last + COOLDOWN_SECS,
                }))).into_response();
            }
        }
        claims.insert(q.to.clone(), now);
    }

    let addr_bytes = match hex::decode(q.to.trim_start_matches("0x")) {
        Ok(b) if b.len() == 20 => {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": "invalid address — expected 20-byte hex"
            }))).into_response();
        }
    };
    let addr = Address::new(addr_bytes);
    if s.state_manager.get_account(&addr).is_none() {
        let _ = s.state_manager.create_account(addr.clone(), AccountType::EOA);
    }
    if let Some(mut acc) = s.state_manager.get_account(&addr) {
        if acc.credit(Balance(FAUCET_AMOUNT_UEGOC as u128)).is_ok() {
            s.state_manager.set_account(acc.clone());
            crate::store::save_account(addr.as_bytes(), &acc);
        }
    }

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "to": q.to,
        "amount_egoc": 100,
        "amount_uegoc": FAUCET_AMOUNT_UEGOC,
        "tx_hash": format!("faucet_{:x}", now),
    }))).into_response()
}

#[derive(Deserialize)]
struct BlockRangeQuery {
    from:  u64,
    count: Option<u64>,
}

async fn blocks_range(
    State(_s): State<Arc<RpcState>>,
    axum::extract::Query(q): axum::extract::Query<BlockRangeQuery>,
) -> impl IntoResponse {
    let count = q.count.unwrap_or(100).min(200);
    let blocks = crate::store::get_blocks_range(q.from, count);
    Json(blocks)
}

pub async fn serve(addr: &str, state: Arc<RpcState>) -> anyhow::Result<()> {
    let app = make_router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(addr, "HTTP RPC listening");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}
