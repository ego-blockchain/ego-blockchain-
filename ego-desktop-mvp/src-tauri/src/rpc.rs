//! JSON-RPC 2.0 + WebSocket server — exposes all Ego chain functions to
//! external applications (JS SDK, dApps, explorer, mobile clients).
//!
//! Listens on 127.0.0.1:47395.
//!   POST /          — JSON-RPC 2.0 (single + batch)
//!   GET  /ws        — WebSocket subscriptions
//!   GET  /health    — "ok" liveness probe
//!
//! This is the gateway for the @ego-blockchain/sdk TypeScript package and
//! any third-party dApp that wants to talk to a local Ego node.

use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{net::SocketAddr, sync::Arc};

// ── JSON-RPC types ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct RpcRequest {
    jsonrpc: String,
    method:  String,
    #[serde(default)]
    params:  Value,
    id:      Option<Value>,
}

#[derive(Debug, Serialize)]
struct RpcResponse {
    jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    result:  Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error:   Option<RpcError>,
    id:      Option<Value>,
}

#[derive(Debug, Serialize)]
struct RpcError {
    code:    i32,
    message: String,
}

impl RpcResponse {
    fn ok(id: Option<Value>, result: Value) -> Self {
        Self { jsonrpc: "2.0", result: Some(result), error: None, id }
    }
    fn err(id: Option<Value>, code: i32, msg: &str) -> Self {
        Self { jsonrpc: "2.0", result: None, error: Some(RpcError { code, message: msg.into() }), id }
    }
}

// ── Shared application state ───────────────────────────────────────────────────

/// Subscribers waiting for chain events over WebSocket.
type Subscribers = Arc<tokio::sync::broadcast::Sender<Value>>;

// ── Router ─────────────────────────────────────────────────────────────────────

pub async fn start_rpc_server() {
    let (broadcast_tx, _) = tokio::sync::broadcast::channel::<Value>(1024);
    // Wire the sender into the global so broadcast_block_header / broadcast_tx_event work.
    init_broadcast(broadcast_tx.clone());
    let subs: Subscribers = Arc::new(broadcast_tx);

    let app = Router::new()
        .route("/",       post(rpc_handler))
        .route("/ws",     get(ws_handler))
        .route("/health", get(health))
        .with_state(subs);

    let rpc_port: u16 = std::env::var("EGO_RPC_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(47395);
    let addr = SocketAddr::from(([0, 0, 0, 0], rpc_port));
    eprintln!("[RPC] JSON-RPC server listening on http://{}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap_or_else(|e| eprintln!("[RPC] Server error: {}", e));
}

// ── Health ─────────────────────────────────────────────────────────────────────

async fn health() -> &'static str { "ok" }

// ── JSON-RPC handler ───────────────────────────────────────────────────────────

async fn rpc_handler(
    State(_subs): State<Subscribers>,
    Json(body): Json<Value>,
) -> Response {
    // Support both single requests and batch arrays
    if body.is_array() {
        let batch: Vec<Value> = body.as_array().unwrap()
            .iter()
            .map(|r| {
                if let Ok(req) = serde_json::from_value::<RpcRequest>(r.clone()) {
                    serde_json::to_value(handle_method(req)).unwrap_or(Value::Null)
                } else {
                    serde_json::to_value(
                        RpcResponse::err(None, -32600, "Invalid Request")
                    ).unwrap_or(Value::Null)
                }
            })
            .collect();
        Json(json!(batch)).into_response()
    } else {
        match serde_json::from_value::<RpcRequest>(body) {
            Ok(req) => Json(serde_json::to_value(handle_method(req)).unwrap_or(Value::Null)).into_response(),
            Err(_)  => (StatusCode::BAD_REQUEST,
                        Json(RpcResponse::err(None, -32600, "Invalid Request"))).into_response(),
        }
    }
}

fn handle_method(req: RpcRequest) -> RpcResponse {
    if req.jsonrpc != "2.0" {
        return RpcResponse::err(req.id, -32600, "Only JSON-RPC 2.0 is supported");
    }

    let p = &req.params;
    match req.method.as_str() {

        // ── Wallet ──────────────────────────────────────────────────────────
        "wallet.getBalance" => {
            let addr = p["address"].as_str().unwrap_or_default();
            let bal  = crate::chain_db::balance_of(addr);
            RpcResponse::ok(req.id, json!({ "uegoc": bal, "egoc": bal as f64 / 1_000_000.0 }))
        }

        "wallet.getTransactionHistory" => {
            let addr  = p["address"].as_str().unwrap_or_default();
            let limit = p["limit"].as_u64().unwrap_or(50) as usize;
            let txs   = crate::chain_db::get_address_txs(addr, limit);
            RpcResponse::ok(req.id, json!(txs))
        }

        "wallet.getTransaction" => {
            let hash = p["hash"].as_str().unwrap_or_default();
            let tx   = crate::chain_db::get_tx_by_hash(hash);
            RpcResponse::ok(req.id, json!(tx))
        }

        // ── Chain ────────────────────────────────────────────────────────────
        "chain.getBlocks" => {
            let from  = p["fromHeight"].as_u64().unwrap_or(0);
            let limit = p["limit"].as_u64().unwrap_or(50) as u32;
            let blocks = crate::chain_db::get_blocks_range(from, limit);
            RpcResponse::ok(req.id, json!(blocks))
        }

        "chain.getBlockHeaders" => {
            let from  = p["fromHeight"].as_u64().unwrap_or(0);
            let limit = p["limit"].as_u64().unwrap_or(100) as u32;
            let hdrs  = crate::chain_db::get_block_headers(from, limit);
            RpcResponse::ok(req.id, json!(hdrs))
        }

        "chain.getTxProof" => {
            let hash = p["txHash"].as_str().unwrap_or_default();
            let tx   = crate::chain_db::get_tx_by_hash(hash);
            let proof = tx.and_then(|t| t.block_height).and_then(|h| {
                let txs = crate::chain_db::get_txs_for_block(h);
                let hashes: Vec<&str> = txs.iter().map(|t| t.hash.as_str()).collect();
                crate::chain_db::prove_tx_inclusion(&hashes, hash)
            });
            RpcResponse::ok(req.id, json!(proof))
        }

        "chain.verifyTxProof" => {
            let proof = match serde_json::from_value::<crate::chain_db::MerkleProof>(p.clone()) {
                Ok(p)  => p,
                Err(e) => return RpcResponse::err(req.id, -32602, &e.to_string()),
            };
            RpcResponse::ok(req.id, json!({ "valid": crate::chain_db::verify_merkle_proof(&proof) }))
        }

        "chain.getNetworkStats" => {
            let stats = crate::chain_db::get_network_stats_db();
            let price = crate::p2p::get_egoc_price_usd();
            let peers = crate::p2p::get_known_peers().len();
            let view  = crate::p2p::current_view();
            RpcResponse::ok(req.id, json!({
                "blockCount":      stats.block_count,
                "txCount":         stats.tx_count,
                "peerCount":       peers,
                "finalizedHeight": crate::chain_db::finalized_height(),
                "egocPriceUsd":    price,
                "currentView":     view,
            }))
        }

        "chain.getEgocPrice" => {
            RpcResponse::ok(req.id, json!({ "usd": crate::p2p::get_egoc_price_usd() }))
        }

        "chain.getFinalizedHeight" => {
            RpcResponse::ok(req.id, json!({ "height": crate::chain_db::finalized_height() }))
        }

        // ── Contracts ────────────────────────────────────────────────────────
        "contract.getState" => {
            let addr   = p["contractAddr"].as_str().unwrap_or_default();
            let prefix = p["prefix"].as_str().unwrap_or_default();
            let key    = p["key"].as_str().unwrap_or_default();
            let exec   = ego_vm::Executor::new(crate::ledger::contracts_dir());
            let val    = exec.ok().and_then(|e| {
                let state = e.store.load_state(addr);
                state.get(prefix, key).map(hex::encode)
            });
            RpcResponse::ok(req.id, json!({ "value": val }))
        }

        "contract.listDeployed" => {
            let contracts_path = crate::ledger::contracts_dir().join("contracts");
            let mut out = Vec::new();
            if let Ok(entries) = std::fs::read_dir(&contracts_path) {
                for entry in entries.flatten() {
                    let addr = entry.file_name().to_string_lossy().to_string();
                    if let Ok(exec) = ego_vm::Executor::new(crate::ledger::contracts_dir()) {
                        if let Some(m) = exec.store.load_manifest(&addr) {
                            out.push(json!({
                                "address":    addr,
                                "name":       m.name,
                                "deployer":   m.deployer,
                                "deployedAt": m.deployed_at,
                                "codeHash":   m.code_hash,
                            }));
                        }
                    }
                }
            }
            RpcResponse::ok(req.id, json!(out))
        }

        // ── P2P ──────────────────────────────────────────────────────────────
        "p2p.getPeers" => {
            let peers = crate::p2p::get_known_peers();
            RpcResponse::ok(req.id, json!(peers))
        }

        "p2p.getCurrentView" => {
            RpcResponse::ok(req.id, json!({
                "view":   crate::p2p::current_view(),
                "leader": crate::p2p::leader_for_view(crate::p2p::current_view()),
            }))
        }

        // ── Unknown method ────────────────────────────────────────────────────
        _ => RpcResponse::err(req.id, -32601, &format!("Method not found: {}", req.method)),
    }
}

// ── WebSocket subscription handler ────────────────────────────────────────────

async fn ws_handler(
    ws:           WebSocketUpgrade,
    State(subs):  State<Subscribers>,
) -> Response {
    ws.on_upgrade(move |socket| handle_ws(socket, subs))
}

async fn handle_ws(mut socket: WebSocket, subs: Subscribers) {
    let mut rx = subs.subscribe();
    loop {
        tokio::select! {
            // Forward chain events to the connected client
            Ok(event) = rx.recv() => {
                let msg = Message::Text(event.to_string());
                if socket.send(msg).await.is_err() { break; }
            }
            // Receive subscription requests from the client
            Some(Ok(msg)) = socket.recv() => {
                if let Message::Text(text) = msg {
                    if let Ok(req) = serde_json::from_str::<Value>(&text) {
                        let method = req["method"].as_str().unwrap_or("");
                        match method {
                            "subscribe" | "unsubscribe" => {
                                // Acknowledge subscription
                                let ack = json!({ "type": "subscribed", "topic": req["topic"] });
                                let _ = socket.send(Message::Text(ack.to_string())).await;
                            }
                            _ => {}
                        }
                    }
                } else if let Message::Close(_) = msg {
                    break;
                }
            }
            else => break,
        }
    }
}

// ── Block / TX event broadcaster (called from chain update path) ───────────────

/// Broadcast a new block header to all WebSocket subscribers.
/// Call this from `merge_remote_chain_inner` and `mine_batch_db`.
pub fn broadcast_block_header(block: &crate::ledger::LedgerBlock) {
    if let Some(tx) = BROADCAST_TX.get() {
        let header = crate::chain_db::LightBlockHeader::from(block);
        let event = json!({ "type": "block", "data": header });
        let _ = tx.send(event);
    }
}

/// Broadcast a confirmed transaction to all WebSocket subscribers.
pub fn broadcast_tx_event(tx: &crate::ledger::LedgerTx) {
    if let Some(sender) = BROADCAST_TX.get() {
        let event = json!({ "type": "transaction", "data": tx });
        let _ = sender.send(event);
    }
}

static BROADCAST_TX: std::sync::OnceLock<tokio::sync::broadcast::Sender<Value>> =
    std::sync::OnceLock::new();

/// Called once at startup to wire the broadcast channel into the global.
pub fn init_broadcast(tx: tokio::sync::broadcast::Sender<Value>) {
    let _ = BROADCAST_TX.set(tx);
}
