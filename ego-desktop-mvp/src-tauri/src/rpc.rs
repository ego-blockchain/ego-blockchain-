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

async fn rpc_handler(
    State(_subs): State<Subscribers>,
    Json(body): Json<Value>,
) -> Response {

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

        // ── Ethereum-compatible JSON-RPC (EIP-1474 subset) ────────────────────
        // Allows standard Ethereum tooling (MetaMask, ethers.js, cast, etc.)
        // to connect to the Ego network via chain ID 1399.

        "net_version" => RpcResponse::ok(req.id, json!("1399")),

        "eth_chainId" => RpcResponse::ok(req.id, json!("0x577")), // 1399

        "eth_blockNumber" => {
            let h = crate::chain_db::get_network_stats_db().block_count;
            RpcResponse::ok(req.id, json!(format!("0x{:x}", h)))
        }

        "eth_getBalance" => {
            // params: [address, block_tag]
            let addr = p[0].as_str().unwrap_or_default();
            let bal  = crate::chain_db::balance_of(addr);
            // Return balance as hex wei (1 uEGOC = 1e12 wei to fit ERC-20 18-decimal convention)
            RpcResponse::ok(req.id, json!(format!("0x{:x}", bal as u128 * 1_000_000_000_000u128)))
        }

        "eth_getTransactionCount" => {
            // Return nonce from ledger if it matches our wallet, else 0.
            let ledger = crate::ledger::Ledger::load();
            let nonce = if p[0].as_str().unwrap_or_default() == ledger.address {
                ledger.nonce
            } else { 0 };
            RpcResponse::ok(req.id, json!(format!("0x{:x}", nonce)))
        }

        "eth_gasPrice" => {
            // Ego uses RU (resource units), not gas. Return 1 Gwei as a convention.
            RpcResponse::ok(req.id, json!("0x3b9aca00")) // 1 Gwei
        }

        "eth_estimateGas" => {
            // Stub: return standard ETH transfer gas (21 000).
            RpcResponse::ok(req.id, json!("0x5208"))
        }

        "eth_getBlockByNumber" | "eth_getBlockByHash" => {
            let stats = crate::chain_db::get_network_stats_db();
            let h = stats.block_count.saturating_sub(1);
            RpcResponse::ok(req.id, json!({
                "number":           format!("0x{:x}", h),
                "hash":             format!("0x{:064x}", h),
                "parentHash":       format!("0x{:064x}", h.saturating_sub(1)),
                "transactionsRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "transactions":     [],
                "gasLimit":         "0x1c9c380",
                "gasUsed":          "0x0",
                "timestamp":        format!("0x{:x}", chrono::Utc::now().timestamp()),
            }))
        }

        "eth_sendRawTransaction" => {
            // EVM-encoded transactions are not yet supported; use wallet.send instead.
            RpcResponse::err(req.id, -32003,
                "EVM raw transactions not supported. Use the Ego native wallet.send method.")
        }

        "eth_call" => {
            // Read-only contract state query via ego_vm.
            let to     = p["to"].as_str().unwrap_or_default();
            let prefix = p["data"].as_str().unwrap_or("state");
            if to.is_empty() {
                return RpcResponse::err(req.id, -32602, "Missing 'to' field");
            }
            let exec = ego_vm::Executor::new(crate::ledger::contracts_dir());
            let val  = exec.ok().and_then(|e| {
                let state = e.store.load_state(to);
                state.get(prefix, "value").map(hex::encode)
            });
            RpcResponse::ok(req.id, json!(val.unwrap_or_else(|| "0x".into())))
        }

        "eth_getLogs" => {
            // Return an empty log set; full log indexing is on the roadmap.
            RpcResponse::ok(req.id, json!([]))
        }

        _ => RpcResponse::err(req.id, -32601, &format!("Method not found: {}", req.method)),
    }
}

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

            Ok(event) = rx.recv() => {
                let msg = Message::Text(event.to_string());
                if socket.send(msg).await.is_err() { break; }
            }

            Some(Ok(msg)) = socket.recv() => {
                if let Message::Text(text) = msg {
                    if let Ok(req) = serde_json::from_str::<Value>(&text) {
                        let method = req["method"].as_str().unwrap_or("");
                        match method {
                            "subscribe" | "unsubscribe" => {

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

pub fn broadcast_block_header(block: &crate::ledger::LedgerBlock) {
    if let Some(tx) = BROADCAST_TX.get() {
        let header = crate::chain_db::LightBlockHeader::from(block);
        let event = json!({ "type": "block", "data": header });
        let _ = tx.send(event);
    }
}

pub fn broadcast_tx_event(tx: &crate::ledger::LedgerTx) {
    if let Some(sender) = BROADCAST_TX.get() {
        let event = json!({ "type": "transaction", "data": tx });
        let _ = sender.send(event);
    }
}

static BROADCAST_TX: std::sync::OnceLock<tokio::sync::broadcast::Sender<Value>> =
    std::sync::OnceLock::new();

pub fn init_broadcast(tx: tokio::sync::broadcast::Sender<Value>) {
    let _ = BROADCAST_TX.set(tx);
}
