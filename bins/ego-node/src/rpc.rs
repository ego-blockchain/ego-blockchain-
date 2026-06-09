use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use ego_core::{AccountType, Address, AlgorithmId, Balance, Block, KeyPair, PublicKey, Signature, StateManager, Transaction};
use ego_core::state::{MIN_VALIDATOR_STAKE, ValidatorStatus};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sysinfo::{System, CpuRefreshKind};
use chrono;
use hex;
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

    /// Dilithium-derived bech32 address (e.g. `egot1...`) — the form used in
    /// compute offers, reservations, and BFT vote messages.
    pub node_bech32_address: String,

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

    /// Authorized renters: reservation_id -> buyer_address
    pub active_renters: Mutex<HashMap<String, String>>,

    /// Known peer HTTP RPC addresses: peer_id_hex → "http://ip:port"
    pub peer_rpc_addrs: Mutex<HashMap<String, String>>,
}

#[derive(Deserialize)]
struct ChainQuery {
    #[serde(rename = "fromHeight")]
    from_height: Option<u64>,
    limit: Option<u64>,
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
        .route("/node/usage",         post(handle_usage))
        .route("/exec",               post(handle_exec))
        .route("/block/broadcast",    post(block_broadcast))
        .route("/compute/offers",     get(list_offers))
        .route("/compute/reservations", get(list_reservations))
        .route("/blocks/range",       get(blocks_range))
        .route("/rpc",                post(json_rpc))
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

async fn list_offers() -> impl IntoResponse {
    let offers = crate::store::list_compute_offers();
    Json(offers)
}

async fn list_reservations() -> impl IntoResponse {
    let auths = crate::store::list_compute_auths();
    Json(auths)
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

async fn chain_blocks(_s: State<Arc<RpcState>>, axum::extract::Query(q): axum::extract::Query<ChainQuery>) -> impl IntoResponse {
    let from = q.from_height.unwrap_or(0);
    let limit = q.limit.unwrap_or(500).min(1000);
    let blocks = crate::store::get_blocks_range(from, limit);
    Json(blocks)
}

async fn block_broadcast(
    State(s):          State<Arc<RpcState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body):        Json<serde_json::Value>,
) -> impl IntoResponse {
    if !rate_ok(&s, peer.ip(), 20) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({ "error": "rate limit exceeded" }))).into_response();
    }
    let height: u64 = body["header"]["core"]["height"]
        .as_u64()
        .or_else(|| body["height"].as_u64())
        .unwrap_or(0);
    if height == 0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "missing height" }))).into_response();
    }
    if crate::store::block_exists(height) {
        return (StatusCode::OK, Json(serde_json::json!({ "status": "already known" }))).into_response();
    }

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

    // ── Consensus gate #4: Quorum Certificate (QC) check ──────────────────────
    let qc_weight = block.header.qc.voting_power as f64;
    let total_weight = crate::consensus_integration::total_active_drs_weight(&s.state_manager);
    if !crate::consensus_integration::has_finality(&s.state_manager, qc_weight, total_weight) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "insufficient quorum certificate weight" }))).into_response();
    }

    let height = block.header.core.height.as_u64();
    if crate::store::block_exists(height) {
        return (StatusCode::OK, Json(serde_json::json!({ "status": "already known" }))).into_response();
    }

    // ── Execute Block & Distribute Rewards ────────────────────────────────────
    let mut touched: std::collections::HashSet<Address> = std::collections::HashSet::new();
    for tx in &block.body.transactions {
        touched.insert(tx.from.clone());
        if let ego_core::TransactionPayload::Transfer { to, .. } = &tx.payload {
            touched.insert(to.clone());
        }
        let _ = s.state_manager.execute_transaction(tx);
        s.pending_txs.remove(&hex::encode(tx.hash.as_bytes()));
    }
    s.state_manager.increment_block_height();
    let _ = s.state_manager.compute_state_root();

    // Persist all accounts touched by this block so state survives restarts.
    let acct_pairs: Vec<([u8; 20], ego_core::Account)> = touched.iter()
        .filter_map(|addr| {
            s.state_manager.get_account(addr).map(|acc| (*addr.as_bytes(), acc))
        })
        .collect();
    let batch: Vec<(&[u8; 20], &ego_core::Account)> = acct_pairs.iter()
        .map(|(k, v)| (k, v))
        .collect();
    if !batch.is_empty() {
        crate::store::save_accounts_batch(&batch);
    }
    crate::store::save_reward_pool(s.state_manager.get_reward_pool_remaining());
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

async fn chain_transactions(
    State(s): State<Arc<RpcState>>,
    axum::extract::Query(q): axum::extract::Query<ChainQuery>
) -> impl IntoResponse {
    let from = q.from_height.unwrap_or(0);
    let limit = q.limit.unwrap_or(100) as usize;
    
    // Fetch blocks in range and collect their transactions
    let blocks = crate::store::get_blocks_range(from, 50); // Small window for tx collection
    let mut txs: Vec<serde_json::Value> = Vec::new();
    for block in blocks {
        let height = block["header"]["core"]["height"].as_u64().unwrap_or(0);
        // Note: ego-node store implementation for per-block txs would go here
    }
    Json(crate::store::get_txs(limit))
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
    if !tx_bytes.is_empty() {
        let _ = s.mempool_gossip_tx.send(tx_bytes);
    }
    (StatusCode::ACCEPTED, Json(serde_json::json!({ "status": "accepted", "tx_hash": hash }))).into_response()
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

/// Self-attesting reservation payload included by the buyer in /exec and
/// /node/usage requests. Lets the provider authenticate the request without
/// relying on the ego-compute-v1 gossip topic having reached this node.
///
/// Extra fields on the buyer side (period_minutes, breach_count, etc.) are
/// accepted and ignored thanks to serde's default behaviour.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ReservationAttestation {
    reservation_id:   String,
    #[serde(default)] offer_id: String,
    buyer_address:    String,
    provider_address: String,
    status:           String,
    expires_at:       i64,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ExecRequest {
    reservation_id: String,
    command: String,
    timestamp: i64,
    /// Hex-encoded Ed25519 signature (kept for back-compat; not the
    /// authoritative auth signal — wallet addresses are Dilithium-derived).
    signature: String,
    /// Hex-encoded Ed25519 public key (back-compat only).
    public_key: String,

    /// Hex-encoded Dilithium-2 public key. Authoritative for buyer-address
    /// derivation: `EgoAddress::from_dilithium_pk(pk, 1, EOA)` must equal the
    /// wallet bech32 address.
    #[serde(default)]
    dilithium_public_key: String,
    /// Hex-encoded Dilithium-2 signature over `{reservation_id}:{command}:{timestamp}`.
    #[serde(default)]
    dilithium_signature: String,

    /// Optional self-attesting reservation payload. Lets the request
    /// authenticate via the chain-derived path when active_renters has not
    /// been hydrated by gossip.
    #[serde(default)]
    reservation: Option<ReservationAttestation>,
}

/// Hex-encoded lowercase 20-byte address. Returns `None` if the input is not a
/// recognisable bech32 ego address.
fn ego_addr_to_hex(addr: &str) -> Option<String> {
    let hrp = if addr.starts_with("egot") { "egot" }
              else if addr.starts_with("ego1") || addr.starts_with("ego") { "ego" }
              else { return None; };
    ego_core::EgoAddress::from_bech32(addr, hrp)
        .ok()
        .map(|a| hex::encode(a.payload()))
}

/// Normalised equality check across bech32 and hex address formats.
fn addresses_match(a: &str, b: &str) -> bool {
    if a.eq_ignore_ascii_case(b) {
        return true;
    }
    let norm = |s: &str| {
        ego_addr_to_hex(s).unwrap_or_else(|| s.trim_start_matches("0x").to_lowercase())
    };
    norm(a) == norm(b)
}

/// Resolves and verifies the buyer address authorised for a /exec or
/// /node/usage request. Tries the in-memory cache and persistent store first,
/// then falls back to chain-derived verification using the attestation
/// embedded in the request itself.
///
/// `derived_bech32` is the Dilithium-derived bech32 address from the request's
/// Dilithium public key (used for the attestation buyer-match check).
fn resolve_buyer_addr(
    s: &Arc<RpcState>,
    req: &ExecRequest,
    derived_bech32: &str,
) -> Result<String, (StatusCode, String)> {
    if let Some(addr) = s.active_renters.lock().unwrap().get(&req.reservation_id).cloned() {
        return Ok(addr);
    }
    if let Some(addr) = crate::store::get_compute_auth(&req.reservation_id) {
        s.active_renters.lock().unwrap().insert(req.reservation_id.clone(), addr.clone());
        return Ok(addr);
    }

    let att = req.reservation.as_ref().ok_or_else(|| (
        StatusCode::UNAUTHORIZED,
        format!("Unauthorized: reservation {} not cached and no attestation provided", req.reservation_id),
    ))?;

    if att.reservation_id != req.reservation_id {
        return Err((StatusCode::BAD_REQUEST,
            "Attestation reservation_id does not match request".to_string()));
    }
    if !addresses_match(&att.provider_address, &s.node_bech32_address) {
        return Err((StatusCode::FORBIDDEN, format!(
            "Attestation provider_address {} does not match this node {}",
            att.provider_address, s.node_bech32_address)));
    }
    if !addresses_match(&att.buyer_address, derived_bech32) {
        return Err((StatusCode::FORBIDDEN, format!(
            "Dilithium key derives {}, but attestation claims buyer {}",
            derived_bech32, att.buyer_address)));
    }
    if att.status != "active" {
        return Err((StatusCode::FORBIDDEN, format!("Reservation status is '{}', not active", att.status)));
    }
    let now = chrono::Utc::now().timestamp();
    if att.expires_at <= now {
        return Err((StatusCode::FORBIDDEN, "Reservation expired".to_string()));
    }

    crate::store::insert_compute_auth(&req.reservation_id, &att.buyer_address);
    s.active_renters.lock().unwrap().insert(req.reservation_id.clone(), att.buyer_address.clone());
    tracing::info!("✅ Hydrated reservation {} from buyer-presented attestation (provider={})",
        req.reservation_id, s.node_address);
    Ok(att.buyer_address.clone())
}

/// Derives the wallet's bech32 address (`egot1...`) from a Dilithium-2 public
/// key. The HRP is derived from the local node's address so testnet/mainnet
/// builds work without extra wiring.
fn derive_bech32_from_dilithium(dil_pk: &[u8], node_address: &str) -> Option<String> {
    let hrp = if node_address.starts_with("egot") { "egot" } else { "ego" };
    let chain_id: u32 = if hrp == "egot" { 1 } else { 0 };
    ego_core::EgoAddress::from_dilithium_pk(dil_pk, chain_id, ego_core::AddressType::EOA)
        .to_bech32(hrp)
        .ok()
}

/// Shared timestamp + signature verification for /exec and /node/usage.
/// Returns the authorised buyer address on success.
///
/// The Dilithium signature is the authoritative auth signal — the wallet
/// address is derived from the Dilithium public key, so a valid signature +
/// matching address proves the request comes from the wallet owner. Ed25519
/// fields are accepted but not verified (kept for back-compat).
fn verify_request_auth(
    s: &Arc<RpcState>,
    req: &ExecRequest,
    signed_msg: &str,
) -> Result<String, (StatusCode, String)> {
    let now = chrono::Utc::now().timestamp();
    if (now - req.timestamp).abs() > 30 {
        return Err((StatusCode::BAD_REQUEST, "Request expired (timestamp mismatch)".to_string()));
    }

    let dil_pk_bytes = hex::decode(&req.dilithium_public_key)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid Dilithium public key encoding".to_string()))?;
    if dil_pk_bytes.is_empty() {
        return Err((StatusCode::BAD_REQUEST,
            "Missing dilithium_public_key (required for wallet auth)".to_string()));
    }

    let derived_bech32 = derive_bech32_from_dilithium(&dil_pk_bytes, &s.node_bech32_address)
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to derive bech32 address".to_string()))?;

    let buyer_addr = resolve_buyer_addr(s, req, &derived_bech32)?;
    if !addresses_match(&buyer_addr, &derived_bech32) {
        return Err((StatusCode::FORBIDDEN, format!(
            "Dilithium key derives {}, but reservation belongs to {}", derived_bech32, buyer_addr)));
    }

    let dil_sig_bytes = hex::decode(&req.dilithium_signature)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid Dilithium signature encoding".to_string()))?;
    if dil_sig_bytes.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Missing dilithium_signature".to_string()));
    }
    let dil_pk = PublicKey::new(ego_core::AlgorithmId::MlDsa2, dil_pk_bytes);
    let dil_sig = Signature::dilithium2(dil_sig_bytes);

    match ego_core::verify_signature(&dil_pk, signed_msg.as_bytes(), &dil_sig) {
        Ok(true)  => Ok(buyer_addr),
        Ok(false) => Err((StatusCode::UNAUTHORIZED, "Invalid Dilithium signature".to_string())),
        Err(e)    => Err((StatusCode::UNAUTHORIZED, format!("Signature verify error: {e}"))),
    }
}

async fn handle_usage(
    State(s): State<Arc<RpcState>>,
    Json(req): Json<ExecRequest>,
) -> impl IntoResponse {
    let signed = format!("{}:{}:{}", req.reservation_id, req.command, req.timestamp);
    if let Err((status, msg)) = verify_request_auth(&s, &req, &signed) {
        tracing::warn!("❌ Usage Auth Failed for {}: {}", req.reservation_id, msg);
        return (status, msg).into_response();
    }

    let mut sys = System::new();
    sys.refresh_cpu_specifics(CpuRefreshKind::new().with_cpu_usage());
    sys.refresh_memory();

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    sys.refresh_cpu_usage();

    let cpu_usage = sys.global_cpu_usage();
    let ram_used = sys.used_memory() as f64 / (1024.0 * 1024.0 * 1024.0);

    let gpu_usage = std::process::Command::new("nvidia-smi")
        .args(["--query-gpu=utilization.gpu", "--format=csv,noheader,nounits"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<i32>().ok())
        .unwrap_or(0);

    (StatusCode::OK, Json(json!({
        "cpu": cpu_usage,
        "ram_used_gb": ram_used,
        "gpu": gpu_usage
    }))).into_response()
}

async fn handle_exec(
    State(s): State<Arc<RpcState>>,
    Json(req): Json<ExecRequest>,
) -> impl IntoResponse {
    let signed = format!("{}:{}:{}", req.reservation_id, req.command, req.timestamp);
    let buyer_addr = match verify_request_auth(&s, &req, &signed) {
        Ok(addr) => addr,
        Err((status, msg)) => {
            tracing::warn!("❌ Exec Auth Failed for {}: {}", req.reservation_id, msg);
            return (status, msg).into_response();
        }
    };

    tracing::info!("📡 Remote Exec [Auth: {}]: {}", buyer_addr, req.command);

    let output = if cfg!(target_os = "windows") {
        std::process::Command::new("powershell").args(["-Command", &req.command]).output()
    } else {
        std::process::Command::new("sh").args(["-c", &req.command]).output()
    };

    match output {
        Ok(o) => {
            let combined = String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr);
            if o.status.success() {
                (StatusCode::OK, combined).into_response()
            } else {
                (StatusCode::BAD_REQUEST, combined).into_response()
            }
        },
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("System Error: {e}")).into_response(),
    }
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

#[derive(Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method:  String,
    #[serde(default)]
    params:  serde_json::Value,
    id:      serde_json::Value,
}

async fn json_rpc(
    State(s):          State<Arc<RpcState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req):         Json<JsonRpcRequest>,
) -> impl IntoResponse {
    macro_rules! rpc_err {
        ($code:expr, $msg:expr) => {
            Json(serde_json::json!({
                "jsonrpc": "2.0",
                "error": { "code": $code, "message": $msg },
                "id": req.id,
            })).into_response()
        };
    }
    if req.jsonrpc != "2.0" {
        return rpc_err!(-32600i32, "Invalid Request: jsonrpc must be \"2.0\"");
    }
    let p = &req.params;
    let result: serde_json::Value = match req.method.as_str() {
        "ego_blockNumber" => {
            serde_json::json!(format!("0x{:x}", s.state_manager.get_block_height().0))
        }
        "ego_chainId" => serde_json::json!("0x1"),
        "ego_getBalance" => {
            let addr_str = p[0].as_str().unwrap_or_default();
            let bytes = match hex::decode(addr_str.trim_start_matches("0x")) {
                Ok(b) if b.len() == 20 => { let mut a = [0u8; 20]; a.copy_from_slice(&b); a }
                _ => return rpc_err!(-32602i32, "Invalid address"),
            };
            let addr = Address::new(bytes);
            let bal = s.state_manager.get_account(&addr).map(|a| a.balance.0).unwrap_or(0u128);
            serde_json::json!(format!("0x{:x}", bal))
        }
        "ego_getNonce" => {
            let addr_str = p[0].as_str().unwrap_or_default();
            let bytes = match hex::decode(addr_str.trim_start_matches("0x")) {
                Ok(b) if b.len() == 20 => { let mut a = [0u8; 20]; a.copy_from_slice(&b); a }
                _ => return rpc_err!(-32602i32, "Invalid address"),
            };
            let addr = Address::new(bytes);
            let nonce = s.state_manager.get_account(&addr).map(|a| a.nonce).unwrap_or(0);
            serde_json::json!(format!("0x{:x}", nonce))
        }
        "ego_getTransactionByHash" => {
            let hash = p[0].as_str().unwrap_or_default();
            crate::store::get_tx_by_hash(hash).unwrap_or(serde_json::Value::Null)
        }
        "ego_getBlockByHeight" => {
            let height = if let Some(h) = p[0].as_u64() {
                h
            } else {
                u64::from_str_radix(p[0].as_str().unwrap_or("0").trim_start_matches("0x"), 16)
                    .unwrap_or(0)
            };
            crate::store::get_block_by_height(height).unwrap_or(serde_json::Value::Null)
        }
        "ego_sendRawTransaction" => {
            if !rate_ok(&s, peer.ip(), 20) {
                return rpc_err!(-32005i32, "Rate limit exceeded");
            }
            if s.pending_txs.len() as usize >= crate::mempool::MAX_TOTAL {
                return rpc_err!(-32006i32, "Mempool full");
            }
            let tx: Transaction = match serde_json::from_value(p[0].clone()) {
                Ok(t) => t,
                Err(e) => return rpc_err!(-32602i32, format!("Invalid tx: {e}")),
            };
            match tx.verify_signature() {
                Ok(true) => {}
                Ok(false) => return rpc_err!(-32003i32, "Invalid signature"),
                Err(e)    => return rpc_err!(-32003i32, format!("Signature error: {e}")),
            }
            if let Some(account) = s.state_manager.get_account(&tx.from) {
                let expected_nonce = account.nonce + 1;
                if tx.nonce != expected_nonce {
                    return rpc_err!(-32007i32,
                        format!("Invalid nonce: expected {expected_nonce}, got {}", tx.nonce));
                }
                if let ego_core::TransactionPayload::Transfer { amount, .. } = &tx.payload {
                    if account.balance.as_u128() < amount.as_u128() {
                        return rpc_err!(-32008i32, "Insufficient balance");
                    }
                }
            } else {
                return rpc_err!(-32009i32, "Sender account not found");
            }
            let hash = hex::encode(tx.hash.as_bytes());
            let tx_bytes = serde_json::to_vec(&tx).unwrap_or_default();
            match s.pending_txs.insert(tx) {
                Err("duplicate") => return rpc_err!(-32010i32, "Duplicate transaction"),
                Err("full")      => return rpc_err!(-32006i32, "Mempool full"),
                Err(e)           => return rpc_err!(-32011i32, format!("Mempool error: {e}")),
                Ok(_) => {}
            }
            if !tx_bytes.is_empty() { let _ = s.mempool_gossip_tx.send(tx_bytes); }
            serde_json::json!(format!("0x{}", hash))
        }
        "ego_getNodeInfo" => serde_json::json!({
            "peer_id":    &s.peer_id,
            "address":    &s.node_address,
            "public_key": &s.node_pubkey,
        }),
        other => return rpc_err!(-32601i32, format!("Method not found: {other}")),
    };
    Json(serde_json::json!({ "jsonrpc": "2.0", "result": result, "id": req.id })).into_response()
}

pub async fn serve(addr: &str, state: Arc<RpcState>) -> anyhow::Result<()> {
    let app = make_router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(addr, "HTTP RPC listening");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}
