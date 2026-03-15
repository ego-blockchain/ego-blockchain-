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

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use ego_core::{Address, StateManager, Transaction};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tower_http::cors::CorsLayer;

// ── Shared state ─────────────────────────────────────────────────────────────

pub struct RpcState {
    pub state_manager: StateManager,
    pub peer_id:       String,
    pub pending_txs:   Mutex<Vec<Transaction>>,
    /// Simple recent-block ring buffer (height, hash, tx_count, ts)
    pub recent_blocks: Mutex<Vec<BlockSummary>>,
    pub node_stats:    Mutex<NodeStats>,
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
        .route("/health",             get(health))
        .route("/chain/blocks",       get(chain_blocks))
        .route("/block/:height",      get(block_by_height))
        .route("/balance/:address",   get(balance))
        .route("/tx/submit",          post(tx_submit))
        .route("/chain/transactions", get(chain_transactions))
        .route("/node/stats",         get(node_stats))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn health(State(s): State<Arc<RpcState>>) -> impl IntoResponse {
    let height = s.state_manager.get_block_height();
    Json(serde_json::json!({
        "status":       "ok",
        "block_height": height.0,
        "peer_id":      &s.peer_id,
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
    let txs = s.pending_txs.lock().unwrap();
    let start = txs.len().saturating_sub(50);
    let slice: Vec<serde_json::Value> = txs[start..].iter()
        .map(|tx| serde_json::json!({
            "hash": hex::encode(tx.hash.as_bytes()),
            "nonce": tx.nonce,
            "from": format!("0x{}", hex::encode(tx.from.as_bytes())),
        }))
        .collect();
    Json(slice)
}

async fn node_stats(State(s): State<Arc<RpcState>>) -> impl IntoResponse {
    let mut stats = s.node_stats.lock().unwrap().clone();
    stats.pending_tx_count = s.pending_txs.lock().unwrap().len();
    Json(stats)
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
