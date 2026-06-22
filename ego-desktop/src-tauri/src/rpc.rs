use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode, Uri},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use hyper::body::to_bytes as body_to_bytes;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
};

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

fn rpc_bind_ip() -> IpAddr {
    std::env::var("EGO_RPC_BIND")
        .ok()
        .and_then(|v| v.parse::<IpAddr>().ok())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

fn https_bind_ip() -> IpAddr {
    std::env::var("EGO_HTTPS_BIND")
        .ok()
        .and_then(|v| v.parse::<IpAddr>().ok())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

fn rpc_is_public() -> bool {
    !rpc_bind_ip().is_loopback()
}

fn is_allowed_cors_origin(origin: &str) -> bool {
    matches!(origin, "tauri://localhost" | "https://tauri.localhost")
        || origin == "http://localhost"
        || origin == "https://localhost"
        || origin == "http://127.0.0.1"
        || origin == "https://127.0.0.1"
        || origin.starts_with("http://localhost:")
        || origin.starts_with("https://localhost:")
        || origin.starts_with("http://127.0.0.1:")
        || origin.starts_with("https://127.0.0.1:")
        || origin.starts_with("chrome-extension://")
        || origin.starts_with("moz-extension://")
}

fn apply_cors_headers(resp: &mut Response, origin: Option<&str>) {
    if let Some(origin) = origin.filter(|o| is_allowed_cors_origin(o)) {
        if let Ok(origin_value) = HeaderValue::from_str(origin) {
            resp.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin_value);
            resp.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("GET, POST, OPTIONS"));
            resp.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("Content-Type, Authorization"));
            resp.headers_mut().insert(header::VARY, HeaderValue::from_static("Origin"));
        }
    }
}

// ── Router ─────────────────────────────────────────────────────────────────────

async fn cors_layer<B>(req: Request<B>, next: Next<B>) -> Response {
    let origin = req.headers()
        .get(header::ORIGIN)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    if req.method() == Method::OPTIONS {
        if origin.as_deref().map(is_allowed_cors_origin).unwrap_or(false) {
            let mut resp = StatusCode::OK.into_response();
            apply_cors_headers(&mut resp, origin.as_deref());
            return resp;
        }
        return StatusCode::FORBIDDEN.into_response();
    }
    let mut resp = next.run(req).await;
    apply_cors_headers(&mut resp, origin.as_deref());
    resp
}

async fn resolve_site(Path(name): Path<String>) -> Response {
    let name = name.trim().to_lowercase();
    match crate::chain_db::get_hosted_site_raw(&name) {
        Some(raw) => Json(raw).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "site not found"}))).into_response(),
    }
}

async fn list_nodes() -> Response {
    let rpc_port: u16 = std::env::var("EGO_RPC_PORT")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(47395);
    let mut urls = vec![format!("http://localhost:{}", rpc_port)];
    if let Ok(ip) = local_ip_address::local_ip() {
        let s = ip.to_string();
        if s != "127.0.0.1" {
            urls.push(format!("http://{}:{}", s, rpc_port));
        }
    }
    urls.extend(crate::p2p::get_known_node_urls());
    Json(json!({ "nodes": urls })).into_response()
}

async fn hosting_nodes(Path(domain): Path<String>) -> Response {
    let nodes = crate::chain_db::get_nodes_for_domain(&domain);
    Json(json!({ "domain": domain, "nodes": nodes })).into_response()
}

async fn hosting_announce(Json(record): Json<crate::chain_db::HostingNodeRecord>) -> Response {
    if record.node_id.is_empty() || record.endpoint.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"missing fields"}))).into_response();
    }
    if rpc_is_public() && record.signature.is_empty() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"missing signature"}))).into_response();
    }
    let sign_msg = format!("ego/hosting/v1:{}:{}:{}", record.node_id, record.endpoint, record.last_seen);
    if !record.signature.is_empty() {
        let sig_valid = crate::p2p::get_peer_ed25519_pubkey(&record.node_id)
            .map(|pk| {
                use ed25519_dalek::{Signature, VerifyingKey, Verifier};
                let vk = VerifyingKey::from_bytes(&pk);
                let sb = hex::decode(&record.signature).unwrap_or_default();
                match (vk, <[u8;64]>::try_from(sb.as_slice())) {
                    (Ok(vk), Ok(s)) => vk.verify(sign_msg.as_bytes(), &Signature::from_bytes(&s)).is_ok(),
                    _ => false,
                }
            })
            .unwrap_or(false);
        if !sig_valid {
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"invalid signature"}))).into_response();
        }
    }
    crate::chain_db::upsert_hosting_node(&record);
    StatusCode::OK.into_response()
}

pub async fn start_rpc_server() {
    let (broadcast_tx, _) = tokio::sync::broadcast::channel::<Value>(1024);
    init_broadcast(broadcast_tx.clone());
    let subs: Subscribers = Arc::new(broadcast_tx);

    let app = Router::new()
        .route("/",                       post(rpc_handler))
        .route("/ws",                     get(ws_handler))
        .route("/health",                 get(health))
        .route("/site/:name",             get(gateway_index))
        .route("/site/:name/*file_path",  get(gateway_file))
        .route("/site-status/:name",      get(site_status))
        .route("/cid/:cid",               get(gateway_cid))
        .route("/file/:cid",              get(gateway_cid))
        .route("/resolve/:name",          get(resolve_site))
        .route("/nodes",                  get(list_nodes))
        .route("/hosting/nodes/:domain",  get(hosting_nodes))
        .route("/hosting/announce",       post(hosting_announce))
        .route("/faucet",                 get(faucet_handler))
        .route("/chain/blocks",           get(chain_blocks))
        .route("/chain/transactions",     get(chain_transactions))
        .fallback(vhost_handler)
        .with_state(subs)
        .layer(middleware::from_fn(cors_layer));

    let rpc_port: u16 = std::env::var("EGO_RPC_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(47395);
    let addr = SocketAddr::from((rpc_bind_ip(), rpc_port));
    eprintln!("[RPC] JSON-RPC server listening on http://{}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap_or_else(|e| eprintln!("[RPC] Server error: {}", e));
}

// ── Health ─────────────────────────────────────────────────────────────────────

async fn health() -> Json<Value> {
    let (tip, fin, txc) = tokio::task::spawn_blocking(|| {
        (
            crate::chain_db::latest_block_info().0,
            crate::chain_db::finalized_height(),
            crate::chain_db::tx_count(),
        )
    })
    .await
    .unwrap_or((0, 0, 0));
    Json(json!({
        "status":           "ok",
        "block_height":     tip,
        "chain_tip":        tip,
        "finalized_height": fin,
        "tx_count":         txc,
    }))
}

// ── Read-only chain endpoints (public block explorer backend) ────────────────────

#[derive(Debug, Deserialize)]
struct ChainQuery {
    #[serde(rename = "fromHeight")]
    from_height: Option<u64>,
    limit:       Option<u32>,
}

async fn chain_blocks(Query(q): Query<ChainQuery>) -> Json<Vec<crate::ledger::LedgerBlock>> {
    let blocks = tokio::task::spawn_blocking(move || {
        let limit = q.limit.unwrap_or(500).min(1000);
        let tip   = crate::chain_db::latest_block_info().0;
        let start = match q.from_height {
            Some(f) => f.max(1),
            None    => tip.saturating_sub(limit as u64).saturating_add(1).max(1),
        };
        crate::chain_db::get_blocks_range(start, limit)
    })
    .await
    .unwrap_or_default();
    Json(blocks)
}

async fn chain_transactions(Query(q): Query<ChainQuery>) -> Json<Vec<crate::ledger::LedgerTx>> {
    let txs = tokio::task::spawn_blocking(move || {
        let limit = q.limit.unwrap_or(500).min(1000);
        let tip   = crate::chain_db::latest_block_info().0;
        let start = match q.from_height {
            Some(f) => f.max(1),
            None    => tip.saturating_sub(limit as u64).saturating_add(1).max(1),
        };
        crate::chain_db::get_blocks_range(start, limit)
            .iter()
            .flat_map(|b| crate::chain_db::get_txs_for_block(b.height))
            .collect::<Vec<_>>()
    })
    .await
    .unwrap_or_default();
    Json(txs)
}

// ── Faucet ─────────────────────────────────────────────────────────────────────

static FAUCET_LAST: std::sync::OnceLock<Mutex<HashMap<String, i64>>> = std::sync::OnceLock::new();
const FAUCET_COOLDOWN_SECS: i64 = 60; // Increased to 60s to prevent accidental double-clicks

fn faucet_cooldown() -> std::sync::MutexGuard<'static, HashMap<String, i64>> {
    FAUCET_LAST.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap()
}

#[derive(serde::Deserialize)]
struct FaucetQuery {
    to: String,
    amount: Option<u64>,
}

async fn faucet_handler(Query(q): Query<FaucetQuery>) -> Response {
    let address = q.to.trim().to_string();
    if !address.starts_with("egot1") {
        return Json(json!({ "success": false, "error": "invalid address: must start with egot1" })).into_response();
    }

    let req_amount = q.amount.unwrap_or(1000).min(1000);
    if req_amount == 0 {
        return Json(json!({ "success": false, "error": "amount must be greater than 0" })).into_response();
    }

    let drops_used = crate::chain_db::get_faucet_drops(&address);
    if drops_used >= 1 {
        return Json(json!({
            "success": false,
            "error": "Faucet limit reached (1 drop maximum per address)."
        })).into_response();
    }

    let faucet_amount = req_amount * 1_000_000;

    let now = chrono::Utc::now().timestamp();
    {
        let mut map = faucet_cooldown();
        let last = map.entry(address.clone()).or_insert(0);
        if now - *last < FAUCET_COOLDOWN_SECS {
            let wait = FAUCET_COOLDOWN_SECS - (now - *last);
            return (StatusCode::TOO_MANY_REQUESTS, Json(json!({
                "success": false,
                "error":   format!("cooldown active — try again in {}s", wait),
            }))).into_response();
        }
        *last = now;
    }

    let success = crate::chain_db::grant_testnet_faucet(&address, faucet_amount);
    
    let drops_used_now = crate::chain_db::get_faucet_drops(&address);
    if success {
        Json(json!({
            "success":      true,
            "to":           address,
            "amount_egoc":  req_amount,
            "amount_uegoc": faucet_amount,
            "drops_used":   drops_used_now,
            "message":      "Faucet request queued. Coins will arrive shortly."
        })).into_response()
    } else {
        Json(json!({
            "success": false,
            "error": "Faucet request failed (limit of 10 requests reached, or pool empty)"
        })).into_response()
    }
}

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
            RpcResponse::ok(req.id, json!([]))
        }

        "eth_getTransactionByHash" => {
            let hash = p[0].as_str().unwrap_or_default();
            let clean = hash.strip_prefix("0x").unwrap_or(hash);
            match crate::chain_db::get_tx_by_hash(clean)
                .or_else(|| crate::chain_db::get_tx_by_hash(hash))
            {
                Some(tx) => {
                    let block_hash = tx.block_height.and_then(|h| {
                        crate::chain_db::get_block_by_height(h).map(|b| format!("0x{}", b.hash))
                    });
                    let tx_index = tx.block_height.map(|h| {
                        let txs = crate::chain_db::get_txs_for_block(h);
                        txs.iter().position(|t| t.hash == tx.hash).unwrap_or(0)
                    });
                    RpcResponse::ok(req.id, json!({
                        "hash":             format!("0x{}", tx.hash),
                        "nonce":            format!("0x{:x}", tx.nonce),
                        "blockHash":        block_hash,
                        "blockNumber":      tx.block_height.map(|h| format!("0x{:x}", h)),
                        "transactionIndex": tx_index.map(|i| format!("0x{:x}", i)),
                        "from":             tx.from,
                        "to":               tx.to,
                        "value":            format!("0x{:x}", tx.amount as u128 * 1_000_000_000_000u128),
                        "gas":              "0x5208",
                        "gasPrice":         "0x3b9aca00",
                        "input":            "0x",
                        "v":                "0x0",
                        "r":                "0x0",
                        "s":                "0x0",
                    }))
                }
                None => RpcResponse::ok(req.id, Value::Null),
            }
        }

        "eth_getTransactionReceipt" => {
            let hash = p[0].as_str().unwrap_or_default();
            let clean = hash.strip_prefix("0x").unwrap_or(hash);
            match crate::chain_db::get_tx_by_hash(clean)
                .or_else(|| crate::chain_db::get_tx_by_hash(hash))
            {
                Some(tx) => {
                    let block_hash = tx.block_height.and_then(|h| {
                        crate::chain_db::get_block_by_height(h).map(|b| format!("0x{}", b.hash))
                    });
                    let tx_index = tx.block_height.map(|h| {
                        let txs = crate::chain_db::get_txs_for_block(h);
                        txs.iter().position(|t| t.hash == tx.hash).unwrap_or(0)
                    });
                    let status = if tx.status == "Failed" { "0x0" } else { "0x1" };
                    RpcResponse::ok(req.id, json!({
                        "transactionHash":   format!("0x{}", tx.hash),
                        "transactionIndex":  tx_index.map(|i| format!("0x{:x}", i)),
                        "blockHash":         block_hash,
                        "blockNumber":       tx.block_height.map(|h| format!("0x{:x}", h)),
                        "from":              tx.from,
                        "to":                tx.to,
                        "cumulativeGasUsed": "0x5208",
                        "gasUsed":           "0x5208",
                        "logs":              [],
                        "logsBloom":         "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                        "status":            status,
                    }))
                }
                None => RpcResponse::ok(req.id, Value::Null),
            }
        }

        "eth_getBlockTransactionCountByNumber" => {
            let tag = p[0].as_str().unwrap_or("latest");
            let height = if tag == "latest" {
                crate::chain_db::get_network_stats_db().block_count
            } else {
                u64::from_str_radix(tag.strip_prefix("0x").unwrap_or(tag), 16).unwrap_or(0)
            };
            let count = crate::chain_db::get_txs_for_block(height).len();
            RpcResponse::ok(req.id, json!(format!("0x{:x}", count)))
        }

        "eth_getBlockTransactionCountByHash" => {
            RpcResponse::ok(req.id, json!("0x0"))
        }

        "eth_getCode" => {
            let addr = p[0].as_str().unwrap_or_default();
            if addr.starts_with("egot1") || addr.is_empty() {
                return RpcResponse::ok(req.id, json!("0x"));
            }
            let exec = ego_vm::Executor::new(crate::ledger::contracts_dir());
            let has_code = exec.ok()
                .and_then(|e| e.store.load_manifest(addr))
                .is_some();
            RpcResponse::ok(req.id, json!(if has_code { "0x01" } else { "0x" }))
        }

        "ego_getValidators" => {
            let validators = crate::p2p::get_known_validators_snapshot();
            RpcResponse::ok(req.id, json!({ "validators": validators, "count": validators.len() }))
        }

        "ego_getMempoolStats" => {
            let pool = crate::mempool::get_mempool();
            RpcResponse::ok(req.id, json!({
                "pending":   pool.pending_count(),
                "submitted": pool.submitted_count(),
                "confirmed": pool.confirmed_count(),
            }))
        }

        "eth_subscribe" => {
            let sub_type = p[0].as_str().unwrap_or("newHeads");
            let valid = matches!(sub_type, "newHeads" | "newPendingTransactions" | "logs");
            if !valid {
                return RpcResponse::err(req.id, -32602, &format!("Unknown subscription type: {}", sub_type));
            }
            let sub_id = gen_sub_id();
            sub_channels().subscriptions.lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(sub_id.clone(), sub_type.to_string());
            RpcResponse::ok(req.id, json!(sub_id))
        }

        "eth_unsubscribe" => {
            let sub_id = p[0].as_str().unwrap_or_default();
            let removed = sub_channels().subscriptions.lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(sub_id)
                .is_some();
            RpcResponse::ok(req.id, json!(removed))
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
    let mut rx_broadcast    = subs.subscribe();
    let mut rx_new_heads    = sub_channels().new_heads.subscribe();
    let mut rx_pending_txs  = sub_channels().new_pending_txs.subscribe();

    let mut ws_sub_type: Option<String> = None;

    loop {
        tokio::select! {

            Ok(event) = rx_broadcast.recv() => {
                let msg = Message::Text(event.to_string());
                if socket.send(msg).await.is_err() { break; }
            }

            Ok(event) = rx_new_heads.recv() => {
                if ws_sub_type.as_deref() == Some("newHeads") {
                    if socket.send(Message::Text(event.to_string())).await.is_err() { break; }
                }
            }

            Ok(event) = rx_pending_txs.recv() => {
                if ws_sub_type.as_deref() == Some("newPendingTransactions") {
                    if socket.send(Message::Text(event.to_string())).await.is_err() { break; }
                }
            }

            Some(Ok(msg)) = socket.recv() => {
                match msg {
                    Message::Text(text) => {
                        if let Ok(req) = serde_json::from_str::<RpcRequest>(&text) {
                            let id = req.id.clone();
                            let method = req.method.as_str();
                            match method {
                                "eth_subscribe" => {
                                    let sub_type = req.params[0].as_str().unwrap_or("newHeads");
                                    let valid = matches!(sub_type, "newHeads" | "newPendingTransactions" | "logs");
                                    if valid {
                                        let sub_id = gen_sub_id();
                                        ws_sub_type = Some(sub_type.to_string());
                                        let resp = RpcResponse::ok(id, json!(sub_id));
                                        let _ = socket.send(Message::Text(serde_json::to_string(&resp).unwrap_or_default())).await;
                                    } else {
                                        let resp = RpcResponse::err(id, -32602, &format!("Unknown subscription type: {}", sub_type));
                                        let _ = socket.send(Message::Text(serde_json::to_string(&resp).unwrap_or_default())).await;
                                    }
                                }
                                "eth_unsubscribe" => {
                                    ws_sub_type = None;
                                    let resp = RpcResponse::ok(id, json!(true));
                                    let _ = socket.send(Message::Text(serde_json::to_string(&resp).unwrap_or_default())).await;
                                }
                                "subscribe" | "unsubscribe" => {
                                    let ack = json!({ "type": "subscribed", "topic": req.params["topic"] });
                                    let _ = socket.send(Message::Text(ack.to_string())).await;
                                }
                                _ => {
                                    let resp = handle_method(req);
                                    let _ = socket.send(Message::Text(serde_json::to_string(&resp).unwrap_or_default())).await;
                                }
                            }
                        } else if let Ok(val) = serde_json::from_str::<Value>(&text) {
                            let method = val["method"].as_str().unwrap_or("");
                            if matches!(method, "subscribe" | "unsubscribe") {
                                let ack = json!({ "type": "subscribed", "topic": val["topic"] });
                                let _ = socket.send(Message::Text(ack.to_string())).await;
                            }
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
            else => break,
        }
    }
}

// ── Web3 Hosting Gateway ──────────────────────────────────────────────────────

fn mime_from_path(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" | "htm" => "text/html; charset=utf-8",
        "css"          => "text/css; charset=utf-8",
        "js" | "mjs"   => "application/javascript; charset=utf-8",
        "json"         => "application/json",
        "png"          => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif"          => "image/gif",
        "svg"          => "image/svg+xml",
        "ico"          => "image/x-icon",
        "webp"         => "image/webp",
        "woff"         => "font/woff",
        "woff2"        => "font/woff2",
        "ttf"          => "font/ttf",
        "otf"          => "font/otf",
        "wasm"         => "application/wasm",
        "txt"          => "text/plain; charset=utf-8",
        "xml"          => "application/xml",
        "pdf"          => "application/pdf",
        "mp4"          => "video/mp4",
        "webm"         => "video/webm",
        "ogv"          => "video/ogg",
        "mp3"          => "audio/mpeg",
        "wav"          => "audio/wav",
        "ogg"          => "audio/ogg",
        "aac"          => "audio/aac",
        "m4a"          => "audio/mp4",
        _              => "application/octet-stream",
    }
}

fn read_site_file(path: &std::path::Path, site_name: &str) -> Option<Vec<u8>> {
    let raw = std::fs::read(path).ok()?;
    let key_hex = crate::chain_db::get_hosted_site_raw(site_name)
        .and_then(|v| v["site_key_hex"].as_str().map(|s| s.to_string()))
        .unwrap_or_default();
    crate::commands::hosting::decrypt_site_file(&raw, &key_hex)
}

fn serve_disk_file(path: &std::path::Path) -> Response {
    serve_ranged_file(path, None)
}

fn serve_ranged_file(path: &std::path::Path, range_header: Option<&str>) -> Response {
    let data = match std::fs::read(path) {
        Ok(b)  => b,
        Err(_) => return (StatusCode::NOT_FOUND, "404 Not Found").into_response(),
    };
    let mime  = mime_from_path(path);
    let total = data.len();

    if let Some(range_str) = range_header {
        if let Some((start, end)) = parse_byte_range(range_str, total) {
            let slice = data[start..=end].to_vec();
            let content_range = format!("bytes {}-{}/{}", start, end, total);
            let out_headers = [
                (header::CONTENT_TYPE,   HeaderValue::from_static(mime)),
                (header::CONTENT_RANGE,  HeaderValue::from_str(&content_range).unwrap_or(HeaderValue::from_static(""))),
                (header::ACCEPT_RANGES,  HeaderValue::from_static("bytes")),
                (header::CONTENT_LENGTH, HeaderValue::from_str(&slice.len().to_string()).unwrap_or(HeaderValue::from_static("0"))),
            ];
            return (StatusCode::PARTIAL_CONTENT, out_headers, slice).into_response();
        }
    }

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE,  HeaderValue::from_static(mime)),
            (header::ACCEPT_RANGES, HeaderValue::from_static("bytes")),
        ],
        data,
    ).into_response()
}

fn serve_ranged_bytes(data: Vec<u8>, mime: &'static str, range_header: Option<&str>) -> Response {
    let total = data.len();
    if let Some(range_str) = range_header {
        if let Some((start, end)) = parse_byte_range(range_str, total) {
            let slice = data[start..=end].to_vec();
            let content_range = format!("bytes {}-{}/{}", start, end, total);
            let out_headers = [
                (header::CONTENT_TYPE,   HeaderValue::from_static(mime)),
                (header::CONTENT_RANGE,  HeaderValue::from_str(&content_range).unwrap_or(HeaderValue::from_static(""))),
                (header::ACCEPT_RANGES,  HeaderValue::from_static("bytes")),
                (header::CONTENT_LENGTH, HeaderValue::from_str(&slice.len().to_string()).unwrap_or(HeaderValue::from_static("0"))),
            ];
            return (StatusCode::PARTIAL_CONTENT, out_headers, slice).into_response();
        }
    }
    (StatusCode::OK, [(header::CONTENT_TYPE, HeaderValue::from_static(mime)), (header::ACCEPT_RANGES, HeaderValue::from_static("bytes"))], data).into_response()
}

fn parse_byte_range(range: &str, total: usize) -> Option<(usize, usize)> {
    let range = range.strip_prefix("bytes=")?;
    let mut parts = range.split('-');
    let start_str = parts.next()?;
    let end_str   = parts.next().unwrap_or("");
    if start_str.is_empty() {
        let suffix: usize = end_str.parse().ok()?;
        let start = total.saturating_sub(suffix);
        return Some((start, total.saturating_sub(1)));
    }
    let start: usize = start_str.parse().ok()?;
    let end: usize = if end_str.is_empty() {
        total.saturating_sub(1)
    } else {
        end_str.parse::<usize>().ok()?.min(total.saturating_sub(1))
    };
    if start > end || start >= total { return None; }
    Some((start, end))
}

fn rewrite_flask_html(html: &str, site_name: &str) -> String {
    let pfx = format!("/site/{}/", site_name);
    // Rewrite absolute paths in static HTML attributes
    let patched = html
        .replace(" src=\"/",      &format!(" src=\"{}",      pfx))
        .replace("\tsrc=\"/",     &format!("\tsrc=\"{}",     pfx))
        .replace("\nsrc=\"/",     &format!("\nsrc=\"{}",     pfx))
        .replace(" href=\"/",     &format!(" href=\"{}",     pfx))
        .replace("\thref=\"/",    &format!("\thref=\"{}",    pfx))
        .replace("\nhref=\"/",    &format!("\nhref=\"{}",    pfx))
        .replace(" action=\"/",   &format!(" action=\"{}",   pfx))
        .replace(" srcset=\"/",   &format!(" srcset=\"{}",   pfx))
        .replace(" data-src=\"/", &format!(" data-src=\"{}", pfx))
        .replace(" src='/",       &format!(" src='{}",       pfx))
        .replace(" href='/",      &format!(" href='{}",      pfx))
        .replace(" srcset='/",    &format!(" srcset='{}",    pfx));
    // MutationObserver for paths set dynamically by JS — no history rewrite for Flask
    let p = format!("/site/{}", site_name);
    let observer_js = [
        "<script>(function(){",
        &format!("var P='{}';", p),
        "var AT=['src','href','action','poster','data-src'];",
        "function fix(el){",
        "  if(!el||!el.getAttribute)return;",
        "  AT.forEach(function(a){",
        "    var v=el.getAttribute(a);",
        "    if(v&&v.charAt(0)==='/'&&v.indexOf('//')<0&&!v.startsWith(P)&&!v.startsWith('/site/'))",
        "      el.setAttribute(a,P+v);",
        "  });",
        "}",
        "function fixAll(r){AT.forEach(function(a){try{(r.querySelectorAll('['+a+']')||[]).forEach(fix);}catch(e){}});}",
        "new MutationObserver(function(ms){",
        "  ms.forEach(function(m){",
        "    (m.addedNodes||[]).forEach(function(n){if(n.nodeType===1){fix(n);fixAll(n);}});",
        "    if(m.type==='attributes')fix(m.target);",
        "  });",
        "}).observe(document.documentElement,{childList:true,subtree:true,attributes:true,attributeFilter:AT});",
        "document.addEventListener('DOMContentLoaded',function(){fixAll(document.body||document.documentElement);});",
        "})()</script>",
    ].join("\n");
    // Inject into <head>
    if let Some(i) = patched.find("<head>") {
        let mut s = patched.clone();
        s.insert_str(i + 6, &observer_js);
        s
    } else if let Some(i) = patched.to_lowercase().find("</head>") {
        let mut s = patched.clone();
        s.insert_str(i, &observer_js);
        s
    } else {
        format!("{}{}", observer_js, patched)
    }
}

fn spa_inject_script(site_name: &str) -> String {
    // Build without nested format! to avoid {{ }} escaping confusion.
    // 1. Strips /site/name prefix from location so React Router sees "/"
    // 2. MutationObserver rewrites absolute /foo.png → /site/name/foo.png
    //    for every attribute React sets dynamically after first render.
    let p = format!("/site/{}", site_name);
    let js = [
        "(function(){",
        &format!("var P='{}';", p),
        "if(location.pathname===P||location.pathname.startsWith(P+'/')){",
        "  history.replaceState(null,'',location.pathname.slice(P.length)||'/');",
        "}",
        "var AT=['src','href','action','poster','data-src'];",
        "function fix(el){",
        "  if(!el||!el.getAttribute)return;",
        "  AT.forEach(function(a){",
        "    var v=el.getAttribute(a);",
        "    if(v&&v.charAt(0)==='/'&&v.indexOf('//')<0&&!v.startsWith(P))",
        "      el.setAttribute(a,P+v);",
        "  });",
        "}",
        "function fixAll(r){",
        "  AT.forEach(function(a){",
        "    try{(r.querySelectorAll('['+a+']')||[]).forEach(fix);}catch(e){}",
        "  });",
        "}",
        "new MutationObserver(function(ms){",
        "  ms.forEach(function(m){",
        "    (m.addedNodes||[]).forEach(function(n){if(n.nodeType===1){fix(n);fixAll(n);}});",
        "    if(m.type==='attributes')fix(m.target);",
        "  });",
        "}).observe(document.documentElement,{childList:true,subtree:true,attributes:true,attributeFilter:AT});",
        "document.addEventListener('DOMContentLoaded',function(){fixAll(document.body||document.documentElement);});",
        "})()",
    ].join("\n");
    format!("<script>{}</script>", js)
}

fn serve_html_injected(path: &std::path::Path, site_name: &str) -> Response {
    let raw = read_site_file(path, site_name)
        .or_else(|| std::fs::read(path).ok());
    let html_opt = raw.and_then(|b| String::from_utf8(b).ok());
    match html_opt {
        Some(html) => {
            let pfx = format!("/site/{}/", site_name);
            let patched = html
                .replace(" src=\"/",      &format!(" src=\"{}",      pfx))
                .replace("\tsrc=\"/",     &format!("\tsrc=\"{}",     pfx))
                .replace("\nsrc=\"/",     &format!("\nsrc=\"{}",     pfx))
                .replace(" href=\"/",     &format!(" href=\"{}",     pfx))
                .replace("\thref=\"/",    &format!("\thref=\"{}",    pfx))
                .replace("\nhref=\"/",    &format!("\nhref=\"{}",    pfx))
                .replace(" action=\"/",   &format!(" action=\"{}",   pfx))
                .replace(" srcset=\"/",   &format!(" srcset=\"{}",   pfx))
                .replace(" data-src=\"/", &format!(" data-src=\"{}", pfx))
                .replace(" src='/",       &format!(" src='{}",       pfx))
                .replace(" href='/",      &format!(" href='{}",      pfx))
                .replace(" srcset='/",    &format!(" srcset='{}",    pfx));
            // <base href> for relative paths + SPA history/path-fix script
            let inject = format!("<base href=\"{}\">{}", pfx, spa_inject_script(site_name));
            let final_html = if let Some(i) = patched.find("<head>") {
                let mut s = patched.clone();
                s.insert_str(i + 6, &inject);
                s
            } else if let Some(i) = patched.to_lowercase().find("</head>") {
                let mut s = patched.clone();
                s.insert_str(i, &format!("{}\n", inject));
                s
            } else {
                format!("{}\n{}", inject, patched)
            };
            (StatusCode::OK, [(header::CONTENT_TYPE, "text/html; charset=utf-8")], final_html.into_bytes()).into_response()
        }
        None => serve_disk_file(path),
    }
}

fn serve_css_injected(path: &std::path::Path, site_name: &str) -> Response {
    let raw = read_site_file(path, site_name)
        .or_else(|| std::fs::read(path).ok());
    let css_opt = raw.and_then(|b| String::from_utf8(b).ok());
    match css_opt {
        Some(css) => {
            let pfx     = format!("/site/{}/", site_name);
            let patched = css
                .replace("url(\"/",  &format!("url(\"{}", pfx))
                .replace("url('/",   &format!("url('{}", pfx))
                .replace("url(/",    &format!("url({}", pfx));
            (StatusCode::OK, [(header::CONTENT_TYPE, "text/css; charset=utf-8")], patched.into_bytes()).into_response()
        }
        None => serve_disk_file(path),
    }
}

fn serve_js_injected(path: &std::path::Path, site_name: &str) -> Response {
    let raw = read_site_file(path, site_name)
        .or_else(|| std::fs::read(path).ok());
    let js_opt = raw.and_then(|b| String::from_utf8(b).ok());
    match js_opt {
        Some(js) => {
            let pfx = format!("/site/{}/", site_name);
            // Rewrite absolute ES module imports and dynamic imports
            let patched = js
                .replace("from \"/",    &format!("from \"{}", pfx))
                .replace("from '/",     &format!("from '{}", pfx))
                .replace("import(\"/",  &format!("import(\"{}", pfx))
                .replace("import('/",   &format!("import('{}", pfx));
            (StatusCode::OK, [(header::CONTENT_TYPE, "application/javascript; charset=utf-8")], patched.into_bytes()).into_response()
        }
        None => serve_disk_file(path),
    }
}

fn resolve_site_base(name: &str) -> Option<std::path::PathBuf> {
    let hosting_dir = crate::commands::hosting::hosting_base_dir();

    let owner = crate::chain_db::get_hosted_site_raw(name)
        .and_then(|raw| raw["owner"].as_str().map(|s| s.to_string()));

    let base = if let Some(ref o) = owner {
        hosting_dir.join(o).join(name)
    } else {
        // DB entry missing (e.g. previous failed deploy) — scan filesystem
        let found = std::fs::read_dir(&hosting_dir).ok()?
            .filter_map(|e| e.ok())
            .map(|e| e.path().join(name))
            .find(|p| p.is_dir());
        match found {
            Some(p) => {
                eprintln!("[Hosting] DB entry missing for '{}' — serving from disk fallback", name);
                p
            }
            None => return None,
        }
    };

    if base.is_dir() && std::fs::read_dir(&base).map(|mut d| d.next().is_some()).unwrap_or(false) {
        Some(base)
    } else {
        eprintln!("[Hosting] '{}' found in DB but directory missing or empty at {:?}", name, base);
        None
    }
}

async fn site_status(Path(name): Path<String>) -> Response {
    match crate::python_host::get_startup_state(&name) {
        Some(crate::python_host::StartupState::Ready(port)) =>
            Json(json!({"status":"ready","port":port})).into_response(),
        Some(crate::python_host::StartupState::Failed(e)) =>
            Json(json!({"status":"error","error":e})).into_response(),
        Some(crate::python_host::StartupState::Starting) | None =>
            Json(json!({"status":"starting"})).into_response(),
    }
}

fn loading_page(site_name: &str) -> Response {
    let rpc_port: u16 = std::env::var("EGO_RPC_PORT")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(47395);
    let html = format!(r#"<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Starting {n}…</title>
<style>
body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:#0d1117;font-family:system-ui,sans-serif;color:#e6edf3;}}
.box{{text-align:center;padding:40px;}}
.spinner{{width:48px;height:48px;border:4px solid #30363d;border-top-color:#58a6ff;
border-radius:50%;animation:spin 0.8s linear infinite;margin:0 auto 24px;}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
h2{{margin:0 0 8px;font-size:1.3rem;}}
p{{margin:0;color:#8b949e;font-size:.9rem;}}
.err{{color:#f85149;margin-top:16px;font-size:.85rem;white-space:pre-wrap;max-width:600px;text-align:left;}}
</style></head><body><div class="box">
<div class="spinner" id="sp"></div>
<h2>Starting {n}…</h2>
<p id="msg">Installing dependencies and launching Flask app</p>
<pre class="err" id="err" style="display:none"></pre>
</div>
<script>
var attempts=0;
function poll(){{
  fetch('http://localhost:{p}/site-status/{n}')
    .then(function(r){{return r.json();}})
    .then(function(d){{
      if(d.status==='ready'){{
        window.location.reload();
      }} else if(d.status==='error'){{
        document.getElementById('sp').style.display='none';
        document.getElementById('msg').textContent='Failed to start';
        var e=document.getElementById('err');
        e.style.display='block';
        e.textContent=d.error||'Unknown error';
      }} else {{
        attempts++;
        document.getElementById('msg').textContent='Starting… ('+attempts+'s)';
        setTimeout(poll,1000);
      }}
    }})
    .catch(function(){{setTimeout(poll,2000);}});
}}
poll();
</script></body></html>"#, n = site_name, p = rpc_port);
    (StatusCode::OK, [(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response()
}

fn python_consent_page(site_name: &str) -> impl axum::response::IntoResponse {
    let html = format!(r#"<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Python Execution Request — {n}</title>
<style>
body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:#0d1117;font-family:system-ui,sans-serif;color:#e6edf3;}}
.box{{max-width:520px;padding:40px;background:#161b22;border:1px solid #30363d;border-radius:12px;}}
h2{{margin:0 0 12px;color:#f0883e;}}
p{{color:#8b949e;line-height:1.6;margin:0 0 16px;}}
.warn{{background:#1c1005;border:1px solid #4d2c00;border-radius:8px;padding:12px 16px;
color:#f0883e;font-size:.85rem;margin-bottom:20px;}}
button{{padding:10px 22px;border:none;border-radius:6px;font-size:.95rem;cursor:pointer;margin-right:10px;}}
.allow{{background:#238636;color:#fff;}} .allow:hover{{background:#2ea043;}}
.deny{{background:#21262d;color:#e6edf3;border:1px solid #30363d;}} .deny:hover{{background:#30363d;}}
</style></head><body><div class="box">
<h2>Python Execution Request</h2>
<p>Site <strong>{n}</strong> contains a Python (Flask) application.</p>
<div class="warn">Running Python code grants it <strong>full access</strong> to your desktop, files, and network.
Only proceed if you created this site or fully trust its source.</div>
<p>Would you like to allow <strong>{n}</strong> to execute Python code?</p>
<div>
  <button class="allow" onclick="approve()">Allow Python Execution</button>
  <button class="deny" onclick="window.history.back()">Cancel</button>
</div>
<p id="msg" style="margin-top:16px;font-size:.85rem;color:#58a6ff;display:none">Requesting approval…</p>
</div>
<script>
function approve(){{
  document.getElementById('msg').style.display='block';
  if(window.__TAURI__&&window.__TAURI__.tauri){{
    window.__TAURI__.tauri.invoke('approve_python_site',{{siteName:'{n}'}})
      .then(function(ok){{if(ok){{window.location.reload();}}else{{window.history.back();}}}})
      .catch(function(){{window.location.reload();}});
  }}else{{
    window.location.reload();
  }}
}}
</script></body></html>"#, n = site_name);
    (StatusCode::OK, [(header::CONTENT_TYPE, "text/html; charset=utf-8")], html)
}

async fn proxy_flask(
    site_name: &str,
    base: &std::path::Path,
    flask_path: &str,
    method: Method,
    req_headers: HeaderMap,
    body: hyper::body::Bytes,
) -> Response {
    if !crate::python_host::is_python_trusted(site_name) {
        return python_consent_page(site_name).into_response();
    }
    let port = match crate::python_host::get_startup_state(site_name) {
        Some(crate::python_host::StartupState::Ready(p)) => p,
        Some(crate::python_host::StartupState::Failed(e)) =>
            return (StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Flask app failed to start:\n{e}")).into_response(),
        Some(crate::python_host::StartupState::Starting) | None => {
            crate::python_host::launch_background(site_name, base);
            return loading_page(site_name);
        }
    };
    let url = format!("http://127.0.0.1:{}{}", port,
        if flask_path.is_empty() { "/" } else { flask_path });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let mut builder = match method.as_str() {
        "POST"   => client.post(&url),
        "PUT"    => client.put(&url),
        "DELETE" => client.delete(&url),
        "PATCH"  => client.patch(&url),
        _        => client.get(&url),
    };

    for (k, v) in req_headers.iter() {
        let ks = k.as_str();
        if ks == "host" || ks == "content-length" { continue; }
        if let Ok(rv) = reqwest::header::HeaderValue::from_bytes(v.as_bytes()) {
            builder = builder.header(ks, rv);
        }
    }
    if !body.is_empty() {
        builder = builder.body(body.clone().to_vec());
    }

    match builder.send().await {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let mut out_headers = HeaderMap::new();
            for (k, v) in resp.headers() {
                if k.as_str() == "transfer-encoding" { continue; }
                if let (Ok(kn), Ok(kv)) = (
                    axum::http::HeaderName::from_bytes(k.as_str().as_bytes()),
                    HeaderValue::from_bytes(v.as_bytes()),
                ) {
                    out_headers.insert(kn, kv);
                }
            }
            if let Some(origin) = req_headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
                if is_allowed_cors_origin(origin) {
                    if let Ok(origin_value) = HeaderValue::from_str(origin) {
                        out_headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin_value);
                        out_headers.insert(header::VARY, HeaderValue::from_static("Origin"));
                    }
                }
            }
            let body_bytes = resp.bytes().await.unwrap_or_default();
            // Rewrite absolute paths in HTML responses so /static/... → /site/name/static/...
            let ct = out_headers.get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if ct.contains("text/html") {
                if let Ok(html) = std::str::from_utf8(&body_bytes) {
                    let rewritten = rewrite_flask_html(html, site_name);
                    out_headers.remove(header::CONTENT_LENGTH);
                    return (status, out_headers, rewritten.into_bytes()).into_response();
                }
            }
            (status, out_headers, body_bytes.to_vec()).into_response()
        }
        Err(e) => {
            eprintln!("[PythonHost] proxy error: {e}");
            (StatusCode::BAD_GATEWAY, format!("Flask proxy error: {e}")).into_response()
        }
    }
}

async fn gateway_index(
    Path(name): Path<String>,
    uri: Uri,
    method: Method,
    headers: HeaderMap,
    request: Request<axum::body::Body>,
) -> Response {
    let base = match resolve_site_base(&name) {
        Some(b) => b,
        None => {
            let in_db = crate::chain_db::get_hosted_site_raw(&name).is_some();
            let msg = if in_db {
                format!("Site '{}' is registered but has no files on disk. Re-deploy it.", name)
            } else {
                format!("Site '{}' not found.", name)
            };
            return (StatusCode::NOT_FOUND, msg).into_response();
        }
    };

    if crate::python_host::is_python_site(&base) {
        let pq = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let flask_path = pq.strip_prefix(&format!("/site/{}", name)).unwrap_or("/");
        let body = body_to_bytes(request.into_body()).await.unwrap_or_default();
        return proxy_flask(&name, &base, flask_path, method, headers, body).await;
    }

    let index = base.join("index.html");
    if index.exists() {
        return serve_html_injected(&index, &name);
    }
    if let Ok(mut rd) = std::fs::read_dir(&base) {
        if let Some(Ok(entry)) = rd.next() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("html") {
                return serve_html_injected(&path, &name);
            }
            return serve_disk_file(&path);
        }
    }
    (StatusCode::NOT_FOUND, "Site not found").into_response()
}

async fn gateway_file(
    Path((name, file_path)): Path<(String, String)>,
    uri: Uri,
    method: Method,
    headers: HeaderMap,
    request: Request<axum::body::Body>,
) -> Response {
    let base = match resolve_site_base(&name) {
        Some(b) => b,
        None    => return (StatusCode::NOT_FOUND, "Site not found").into_response(),
    };

    if crate::python_host::is_python_site(&base) {
        let pq  = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let flask_path = pq.strip_prefix(&format!("/site/{}", name)).unwrap_or("/");
        let body = body_to_bytes(request.into_body()).await.unwrap_or_default();
        return proxy_flask(&name, &base, flask_path, method, headers, body).await;
    }

    let rel   = file_path.trim_start_matches('/');
    let full  = base.join(rel);
    if !full.starts_with(&base) {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }
    if full.exists() {
        let range = headers.get(header::RANGE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        return match full.extension().and_then(|e| e.to_str()) {
            Some("html") | Some("htm") => serve_html_injected(&full, &name),
            Some("js")   | Some("mjs") => serve_js_injected(&full, &name),
            Some("css")                => serve_css_injected(&full, &name),
            _ => {
                if let Some(plain) = read_site_file(&full, &name) {
                    let mime = mime_from_path(&full);
                    serve_ranged_bytes(plain, mime, range.as_deref())
                } else {
                    serve_ranged_file(&full, range.as_deref())
                }
            }
        };
    }
    let index = base.join("index.html");
    if index.exists() {
        return serve_html_injected(&index, &name);
    }
    (StatusCode::NOT_FOUND, "Not Found").into_response()
}

async fn gateway_cid(Path(cid): Path<String>) -> Response {
    // 1. Search all locally deployed sites
    let hosting_dir = crate::commands::hosting::hosting_base_dir();
    if let Ok(owners) = std::fs::read_dir(&hosting_dir) {
        for owner_entry in owners.flatten() {
            if let Ok(sites) = std::fs::read_dir(owner_entry.path()) {
                for site in sites.flatten() {
                    let site_name = site.file_name().to_string_lossy().to_string();
                    if let Some(raw) = crate::chain_db::get_hosted_site_raw(&site_name) {
                        if let Some(files) = raw["files"].as_array() {
                            for f in files {
                                if f["cid"].as_str() == Some(cid.as_str()) {
                                    let rel = f["path"].as_str().unwrap_or("").trim_start_matches('/');
                                    return serve_disk_file(&site.path().join(rel));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // 2. Check storage_dir for replicated public files received from peers
    let short    = &cid[cid.len().saturating_sub(16)..];
    let pub_path = crate::ledger::storage_dir().join(format!("{}.pub", short));
    if pub_path.exists() {
        return serve_disk_file(&pub_path);
    }
    (StatusCode::NOT_FOUND, "CID not found").into_response()
}

async fn vhost_handler(headers: HeaderMap, uri: Uri) -> Response {
    let host = headers.get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let host_no_port = host.split(':').next().unwrap_or("");
    let name = match host_no_port.strip_suffix(".localhost") {
        Some(n) if !n.is_empty() => n.to_string(),
        _ => return (StatusCode::NOT_FOUND, "Not found").into_response(),
    };

    let base = match resolve_site_base(&name) {
        Some(b) => b,
        None => {
            let msg = if crate::chain_db::get_hosted_site_raw(&name).is_some() {
                format!("Site '{}' is registered but has no files on disk. Please re-deploy it.", name)
            } else {
                format!("Site '{}' not found.", name)
            };
            return (StatusCode::NOT_FOUND, msg).into_response();
        }
    };

    let path = uri.path().trim_start_matches('/');
    if path.is_empty() {
        let index = base.join("index.html");
        if index.exists() { return serve_disk_file(&index); }
        if let Ok(mut rd) = std::fs::read_dir(&base) {
            if let Some(Ok(e)) = rd.next() { return serve_disk_file(&e.path()); }
        }
        return (StatusCode::NOT_FOUND, "Site not found").into_response();
    }

    let full = base.join(path);
    if !full.starts_with(&base) {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }
    if full.exists() { return serve_disk_file(&full); }
    let index = base.join("index.html");
    if index.exists() { return serve_disk_file(&index); }
    (StatusCode::NOT_FOUND, "Not Found").into_response()
}

// ── HTTPS .eo Gateway ──────────────────────────────────────────────────────────

pub async fn start_https_server() {
    if !crate::tls::certs_exist() {
        eprintln!("[HTTPS] No TLS certs — skipping HTTPS server");
        return;
    }
    let (cert_pem, key_pem) = match crate::tls::get_tls_pem() {
        Some(p) => p,
        None    => { eprintln!("[HTTPS] Failed to load TLS certs"); return; }
    };

    let tls_config = match axum_server::tls_rustls::RustlsConfig::from_pem(
        cert_pem.into_bytes(),
        key_pem.into_bytes(),
    ).await {
        Ok(c)  => c,
        Err(e) => { eprintln!("[HTTPS] TLS config error: {}", e); return; }
    };

    let app = Router::new().fallback(https_eo_handler);

    let bind_ip = https_bind_ip();
    let port: u16 = if std::net::TcpListener::bind((bind_ip, 443)).is_ok() {
        443
    } else {
        std::env::var("EGO_HTTPS_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(47396)
    };
    let _ = crate::tls::HTTPS_PORT.set(port);
    let addr = SocketAddr::from((bind_ip, port));
    eprintln!("[HTTPS] .eo gateway listening on https://{}", addr);

    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await
        .unwrap_or_else(|e| eprintln!("[HTTPS] Server error: {}", e));
}

async fn https_eo_handler(headers: HeaderMap, uri: Uri) -> Response {
    let host = headers.get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let host_no_port = host.split(':').next().unwrap_or("");
    let name = host_no_port
        .strip_suffix(".eo")
        .map(|n| n.strip_prefix("www.").unwrap_or(n))
        .unwrap_or("");

    if name.is_empty() {
        return (StatusCode::NOT_FOUND, "Unknown .eo domain").into_response();
    }

    let base = match resolve_site_base(name) {
        Some(b) => b,
        None    => return (StatusCode::NOT_FOUND, "Site not found").into_response(),
    };

    let path = uri.path().trim_start_matches('/');

    if path.is_empty() {
        let index = base.join("index.html");
        if index.exists() { return serve_disk_file(&index); }
        if let Ok(mut rd) = std::fs::read_dir(&base) {
            if let Some(Ok(e)) = rd.next() { return serve_disk_file(&e.path()); }
        }
        return (StatusCode::NOT_FOUND, "Site not found").into_response();
    }

    let full = base.join(path);
    if !full.starts_with(&base) {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }
    if full.exists() {
        return serve_disk_file(&full);
    }
    let index = base.join("index.html");
    if index.exists() { return serve_disk_file(&index); }
    (StatusCode::NOT_FOUND, "Not Found").into_response()
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

struct SubChannels {
    new_heads:              tokio::sync::broadcast::Sender<Value>,
    new_pending_txs:        tokio::sync::broadcast::Sender<Value>,
    subscriptions:          Mutex<HashMap<String, String>>,
}

static SUB_CHANNELS: std::sync::OnceLock<SubChannels> = std::sync::OnceLock::new();

fn sub_channels() -> &'static SubChannels {
    SUB_CHANNELS.get_or_init(|| {
        let (new_heads, _)       = tokio::sync::broadcast::channel(1024);
        let (new_pending_txs, _) = tokio::sync::broadcast::channel(1024);
        SubChannels {
            new_heads,
            new_pending_txs,
            subscriptions: Mutex::new(HashMap::new()),
        }
    })
}

pub fn notify_new_block(block: &crate::ledger::LedgerBlock) {
    let ch = sub_channels();
    let header = crate::chain_db::LightBlockHeader::from(block);
    let payload = json!({
        "jsonrpc": "2.0",
        "method": "eth_subscription",
        "params": {
            "subscription": "newHeads",
            "result": {
                "number":           format!("0x{:x}", header.height),
                "hash":             format!("0x{}", header.hash),
                "parentHash":       format!("0x{}", header.prev_hash),
                "miner":            header.miner,
                "timestamp":        format!("0x{:x}", header.timestamp),
                "transactionsRoot": format!("0x{}", header.tx_merkle_root),
                "gasLimit":         "0x1c9c380",
                "gasUsed":          "0x0",
            }
        }
    });
    let _ = ch.new_heads.send(payload.clone());
    broadcast_block_header(block);
}

pub fn notify_pending_tx(tx_hash: &str) {
    let ch = sub_channels();
    let payload = json!({
        "jsonrpc": "2.0",
        "method": "eth_subscription",
        "params": {
            "subscription": "newPendingTransactions",
            "result": format!("0x{}", tx_hash)
        }
    });
    let _ = ch.new_pending_txs.send(payload);
}

fn gen_sub_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    static CTR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let seq = CTR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let raw = format!("{}:{}", t.as_nanos(), seq);
    let hash = blake3::hash(raw.as_bytes());
    format!("0x{}", &hash.to_hex()[..16])
}
