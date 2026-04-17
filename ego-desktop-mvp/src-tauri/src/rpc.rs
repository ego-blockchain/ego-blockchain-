use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode, Uri},
    middleware::{self, Next},
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

async fn cors_layer<B>(req: Request<B>, next: Next<B>) -> Response {
    if req.method() == Method::OPTIONS {
        return (
            StatusCode::OK,
            [
                (header::ACCESS_CONTROL_ALLOW_ORIGIN,  HeaderValue::from_static("*")),
                (header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("GET, POST, OPTIONS")),
                (header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("Content-Type")),
            ],
        ).into_response();
    }
    let mut resp = next.run(req).await;
    resp.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
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
        .route("/cid/:cid",               get(gateway_cid))
        .route("/file/:cid",              get(gateway_cid))
        .route("/resolve/:name",          get(resolve_site))
        .route("/nodes",                  get(list_nodes))
        .route("/hosting/nodes/:domain",  get(hosting_nodes))
        .route("/hosting/announce",       post(hosting_announce))
        .with_state(subs)
        .layer(middleware::from_fn(cors_layer));

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
        "wasm"         => "application/wasm",
        "txt"          => "text/plain; charset=utf-8",
        "xml"          => "application/xml",
        "pdf"          => "application/pdf",
        _              => "application/octet-stream",
    }
}

fn serve_disk_file(path: &std::path::Path) -> Response {
    match std::fs::read(path) {
        Ok(bytes) => {
            let mime = mime_from_path(path);
            (StatusCode::OK, [(header::CONTENT_TYPE, mime)], bytes).into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, "404 Not Found").into_response(),
    }
}

fn serve_html_injected(path: &std::path::Path, site_name: &str) -> Response {
    match std::fs::read_to_string(path) {
        Ok(html) => {
            let base_tag = format!("<base href=\"/site/{}/\">", site_name);
            let html_lower = html.to_lowercase();
            let patched = if html_lower.contains("<base ") || html_lower.contains("<base>") {
                html
            } else if let Some(pos) = html_lower.find("<head>") {
                let insert = pos + "<head>".len();
                format!("{}{}{}", &html[..insert], base_tag, &html[insert..])
            } else if let Some(pos) = html_lower.find("<html") {
                let end = html[pos..].find('>').map(|i| pos + i + 1).unwrap_or(pos + 5);
                format!("{}{}{}", &html[..end], base_tag, &html[end..])
            } else {
                format!("{}{}", base_tag, html)
            };
            (StatusCode::OK, [(header::CONTENT_TYPE, "text/html; charset=utf-8")], patched.into_bytes()).into_response()
        }
        Err(_) => serve_disk_file(path),
    }
}

fn resolve_site_base(name: &str) -> Option<std::path::PathBuf> {
    let raw   = crate::chain_db::get_hosted_site_raw(name)?;
    let owner = raw["owner"].as_str()?.to_string();
    let base  = crate::commands::hosting::hosting_base_dir()
        .join(&owner)
        .join(name);
    if base.is_dir() && std::fs::read_dir(&base).map(|mut d| d.next().is_some()).unwrap_or(false) {
        Some(base)
    } else {
        None
    }
}

async fn gateway_index(Path(name): Path<String>) -> Response {
    let base = match resolve_site_base(&name) {
        Some(b) => b,
        None => {
            let in_db = crate::chain_db::get_hosted_site_raw(&name).is_some();
            let msg = if in_db {
                format!("Site '{}' is registered but has no files on disk. Please re-deploy it.", name)
            } else {
                format!("Site '{}' not found.", name)
            };
            return (StatusCode::NOT_FOUND, msg).into_response();
        }
    };
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

async fn gateway_file(Path((name, file_path)): Path<(String, String)>) -> Response {
    let base = match resolve_site_base(&name) {
        Some(b) => b,
        None    => return (StatusCode::NOT_FOUND, "Site not found").into_response(),
    };
    let rel  = file_path.trim_start_matches('/');
    let full = base.join(rel);

    if !full.starts_with(&base) {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }
    if full.exists() {
        if full.extension().and_then(|e| e.to_str()) == Some("html") {
            return serve_html_injected(&full, &name);
        }
        return serve_disk_file(&full);
    }
    // SPA fallback
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

    let port: u16 = if std::net::TcpListener::bind("0.0.0.0:443").is_ok() { 443 } else { 47396 };
    let _ = crate::tls::HTTPS_PORT.set(port);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    eprintln!("[HTTPS] .eo gateway listening on https://0.0.0.0:{}", port);

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
