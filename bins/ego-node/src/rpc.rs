//! Ego-Node HTTP JSON-RPC layer.
//!
//! Endpoints
//! ---------
//! GET  /health                → { status, block_height, peer_id }
//! GET  /chain/blocks          → [{ height, hash, tx_count, timestamp }]  (last 50)
//! GET  /block/:height         → { height, hash, tx_count, timestamp }
//! GET  /balance/:address      → { address, balance_uegoc, balance_egoc }
//! POST /tx/submit             → { tx_hash }   (body: JSON Transaction)
//! GET  /chain/transactions    → [Transaction]  (last 50 pending)
//! GET  /node/stats            → NodeStats JSON
//! GET  /node/identity         → { address, public_key_hex, peer_id, payout_address }
//! GET  /faucet?to=<address>   → { success, amount_egoc, tx_hash }  (testnet only, 100 EGOC/24h)

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use ego_core::{AccountType, Address, Balance, KeyPair, StateManager, Transaction};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tower_http::cors::CorsLayer;

use crate::supervisor::NodeSupervisor;

// ── Shared state ─────────────────────────────────────────────────────────────

pub struct RpcState {
    pub state_manager:  StateManager,
    pub peer_id:        String,
    /// Bech32 ego address of this node (rewards accumulate here).
    pub node_address:   String,
    /// Hex-encoded Ed25519 public key of the node keypair.
    pub node_pubkey:    String,
    /// Node keypair — used to sign auto-payout transactions.
    pub node_keypair:   KeyPair,
    /// Optional external address to auto-forward earned rewards.
    pub payout_address: Option<String>,
    pub pending_txs:    Mutex<Vec<Transaction>>,
    /// Simple recent-block ring buffer (height, hash, tx_count, ts)
    pub recent_blocks:  Mutex<Vec<BlockSummary>>,
    pub node_stats:     Mutex<NodeStats>,
    /// Monotonic nonce for outgoing TXs from this node.
    pub nonce:          Mutex<u64>,
    /// Supervisor — tracks component health for the /health endpoint.
    pub supervisor:     Arc<NodeSupervisor>,
    /// Faucet: last claim time per address (unix timestamp seconds).
    pub faucet_claims:  Mutex<std::collections::HashMap<String, u64>>,
    /// Transactions broadcast from desktop clients (LedgerTx JSON, last 500).
    pub broadcast_txs:  Mutex<Vec<serde_json::Value>>,
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

// ── Router ────────────────────────────────────────────────────────────────────

pub fn make_router(state: Arc<RpcState>) -> Router {
    Router::new()
        .route("/",                   get(root))
        .route("/health",             get(health))
        .route("/chain/blocks",       get(chain_blocks))
        .route("/block/:height",      get(block_by_height))
        .route("/balance/:address",   get(balance))
        .route("/tx/submit",          post(tx_submit))
        .route("/chain/transactions", get(chain_transactions))
        .route("/node/stats",         get(node_stats))
        .route("/node/identity",      get(node_identity))
        .route("/faucet",             get(faucet))
        .route("/tx/broadcast",       post(tx_broadcast))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

// ── Handlers ──────────────────────────────────────────────────────────────────

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

async fn chain_blocks(State(s): State<Arc<RpcState>>) -> impl IntoResponse {
    let blocks = s.recent_blocks.lock().unwrap().clone();
    Json(blocks)
}

async fn block_by_height(
    Path(height): Path<u64>,
    State(s):     State<Arc<RpcState>>,
) -> impl IntoResponse {
    let blocks = s.recent_blocks.lock().unwrap();
    match blocks.iter().find(|b| b.height == height) {
        Some(b) => (StatusCode::OK, Json(serde_json::to_value(b).unwrap())).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "block not found" })),
        ).into_response(),
    }
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

#[derive(Deserialize)]
struct TxSubmitBody {
    tx: serde_json::Value,
}

async fn tx_submit(
    State(s):   State<Arc<RpcState>>,
    Json(body): Json<TxSubmitBody>,
) -> impl IntoResponse {
    match serde_json::from_value::<Transaction>(body.tx) {
        Ok(tx) => {
            let hash = hex::encode(tx.hash.as_bytes());
            s.pending_txs.lock().unwrap().push(tx);
            (StatusCode::ACCEPTED, Json(serde_json::json!({ "tx_hash": hash }))).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        ).into_response(),
    }
}

async fn chain_transactions(State(s): State<Arc<RpcState>>) -> impl IntoResponse {
    let mut result: Vec<serde_json::Value> = {
        let txs = s.pending_txs.lock().unwrap();
        let start = txs.len().saturating_sub(50);
        txs[start..].iter()
            .map(|tx| serde_json::json!({
                "hash":  hex::encode(tx.hash.as_bytes()),
                "nonce": tx.nonce,
                "from":  format!("0x{}", hex::encode(tx.from.as_bytes())),
            }))
            .collect()
    };
    // Append broadcast transactions from desktop clients (newest first).
    let broadcast = s.broadcast_txs.lock().unwrap();
    let bstart = broadcast.len().saturating_sub(50);
    result.extend_from_slice(&broadcast[bstart..]);
    result.sort_by(|a, b| {
        let ta = a.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0);
        let tb = b.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0);
        tb.cmp(&ta)
    });
    Json(result)
}

/// Accept a raw LedgerTx JSON from desktop clients and store it for the explorer.
async fn tx_broadcast(
    State(s):   State<Arc<RpcState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let mut txs = s.broadcast_txs.lock().unwrap();
    // Avoid duplicates by hash.
    let hash = body.get("hash").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if !hash.is_empty() && txs.iter().any(|t| t.get("hash").and_then(|v| v.as_str()) == Some(&hash)) {
        return (StatusCode::OK, Json(serde_json::json!({ "status": "already known" }))).into_response();
    }
    txs.push(body);
    // Keep last 500 only.
    if txs.len() > 500 { let excess = txs.len() - 500; txs.drain(0..excess); }
    (StatusCode::ACCEPTED, Json(serde_json::json!({ "status": "accepted" }))).into_response()
}

async fn node_stats(State(s): State<Arc<RpcState>>) -> impl IntoResponse {
    let mut stats = s.node_stats.lock().unwrap().clone();
    stats.pending_tx_count = s.pending_txs.lock().unwrap().len();
    Json(stats)
}

async fn node_identity(State(s): State<Arc<RpcState>>) -> impl IntoResponse {
    let balance_raw = {
        // Parse bech32 / hex address to get the on-chain balance
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

// ── Faucet ────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct FaucetQuery {
    to: String,
}

async fn faucet(
    State(s): State<Arc<RpcState>>,
    axum::extract::Query(q): axum::extract::Query<FaucetQuery>,
) -> impl IntoResponse {
    const FAUCET_AMOUNT_UEGOC: u64 = 100 * 1_000_000; // 100 EGOC
    const COOLDOWN_SECS: u64 = 86400; // 24 hours

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Check cooldown
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

    // Credit the balance: parse address, get-or-create account, then credit it.
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
        acc.credit(Balance(FAUCET_AMOUNT_UEGOC as u128));
        s.state_manager.set_account(acc);
    }

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "to": q.to,
        "amount_egoc": 100,
        "amount_uegoc": FAUCET_AMOUNT_UEGOC,
        "tx_hash": format!("faucet_{:x}", now),
    }))).into_response()
}

// ── Startup helper ────────────────────────────────────────────────────────────

/// Spawn the HTTP server on `addr` (e.g. "0.0.0.0:8545").
pub async fn serve(addr: &str, state: Arc<RpcState>) -> anyhow::Result<()> {
    let app = make_router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(addr, "HTTP RPC listening");
    axum::serve(listener, app).await?;
    Ok(())
}
