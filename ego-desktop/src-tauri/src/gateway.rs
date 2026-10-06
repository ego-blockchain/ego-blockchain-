use axum::extract::{ConnectInfo, DefaultBodyLimit};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const DEFAULT_PORT: u16 = 47398;
pub const ANNOUNCE_DOMAIN: &str = "ego/gateway/v1";
pub const GOSSIP_TOPIC: &str = "ego-gateways-v1";

const ANNOUNCE_EVERY: Duration = Duration::from_secs(30 * 60);
const RETRY_UNREACHABLE: Duration = Duration::from_secs(2 * 60);
const ROUTER_LEASE_SECS: u32 = 60 * 60;
const ROUTER_RENEW: Duration = Duration::from_secs(20 * 60);
const REACHED_FOR_SECS: i64 = 60 * 60;
const BOOTSTRAP_SAMPLE: usize = 200;
const GOSSIP_SAMPLE: usize = 1_000;
const SUPERVISE_EVERY: Duration = Duration::from_secs(10);
const PROBE_EVERY: Duration = Duration::from_secs(5 * 60);
const PROBES_PER_ROUND: usize = 3;
const VERIFIED_FOR_SECS: i64 = 60 * 60;
const ENTRY_FRESH_SECS: i64 = 2 * 60 * 60;
const CLOCK_SKEW_SECS: i64 = 300;
const TABLE_MAX: usize = 2_000;
const SHARE_LIMIT: usize = 50;
const MAX_FAILURES: u8 = 2;
const BUCKET_SIZE: f64 = 120.0;
const REFILL_PER_SEC: f64 = 6.0;
const MAX_BODY_BYTES: usize = 64 * 1024;
const NOT_HERE: &str = "That method isn't available on this gateway.";

const PASSTHROUGH: &[&str] = &[
    "wallet.getBalance",
    "wallet.getNonce",
    "wallet.getTransactionHistory",
    "wallet.getTransaction",
    "tx.submit",
    "chain.getNetworkStats",
    "chain.getEgocPrice",
    "chain.getFinalizedHeight",
    "market.params",
    "market.offers",
    "market.offer",
    "market.trade",
    "market.trades",
    "market.profile",
    "market.leaderboard",
    "market.opMemo",
    "market.settleMessage",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Announcement {
    pub endpoint: String,
    pub cert_sha256: String,
    pub node: String,
    pub ts: i64,
    pub pubkey: String,
    pub sig: String,
}

#[derive(Debug, Clone)]
struct Entry {
    announcement: Announcement,
    verified_at: Option<i64>,
    failures: u8,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct GatewayStatus {
    pub enabled: bool,
    pub running: bool,
    pub port: u16,
    pub endpoint: Option<String>,
    pub cert_sha256: Option<String>,
    pub bootstrap_listed: bool,
    pub last_announce: Option<i64>,
    pub reached_from_internet_at: Option<i64>,
    pub router_port_open: Option<bool>,
    pub router_public_ip: Option<String>,
    pub reachable: bool,
    pub known_gateways: usize,
    pub problem: Option<String>,
}

static STATUS: Mutex<Option<GatewayStatus>> = Mutex::new(None);
static BUCKETS: Mutex<Option<HashMap<IpAddr, (f64, Instant)>>> = Mutex::new(None);
static TABLE: Mutex<Option<HashMap<String, Entry>>> = Mutex::new(None);
static OWN: Mutex<Option<Announcement>> = Mutex::new(None);

pub fn port() -> u16 {
    std::env::var("EGO_GATEWAY_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_PORT)
}

pub fn enabled() -> bool {
    match std::env::var("EGO_GATEWAY").as_deref() {
        Ok("0") => false,
        Ok("1") => true,
        _ => !crate::ledger::Ledger::load().gateway_opt_out,
    }
}

pub fn status() -> GatewayStatus {
    let mut s = STATUS.lock().unwrap_or_else(|e| e.into_inner()).clone().unwrap_or_default();
    s.enabled = enabled();
    s.port = port();
    s.known_gateways = TABLE.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|t| t.len()).unwrap_or(0);
    s
}

fn update(f: impl FnOnce(&mut GatewayStatus)) {
    let mut guard = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    f(guard.get_or_insert_with(GatewayStatus::default));
}

fn cert_paths() -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = crate::ledger::base_data_dir();
    (dir.join("gateway_cert.pem"), dir.join("gateway_key.pem"))
}

pub fn certificate() -> Result<(String, String, String), String> {
    let (cert_path, key_path) = cert_paths();
    if !(cert_path.exists() && key_path.exists()) {
        let cert = rcgen::generate_simple_self_signed(vec!["ego-gateway".to_string()]).map_err(|e| e.to_string())?;
        let cert_pem = cert.serialize_pem().map_err(|e| e.to_string())?;
        let key_pem = cert.serialize_private_key_pem();
        crate::utils::atomic_write(&key_path, key_pem.as_bytes()).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
        }
        crate::utils::atomic_write(&cert_path, cert_pem.as_bytes()).map_err(|e| e.to_string())?;
    }
    let cert_pem = std::fs::read_to_string(&cert_path).map_err(|e| e.to_string())?;
    let key_pem = std::fs::read_to_string(&key_path).map_err(|e| e.to_string())?;
    let der = pem_der(&cert_pem).ok_or("The gateway certificate file is damaged.")?;
    Ok((cert_pem, key_pem, hex::encode(Sha256::digest(&der))))
}

fn pem_der(pem: &str) -> Option<Vec<u8>> {
    let body: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    base64::engine::general_purpose::STANDARD.decode(body.trim()).ok()
}

pub fn announcement_bytes(endpoint: &str, cert_sha256: &str, ts: i64) -> Vec<u8> {
    format!("{ANNOUNCE_DOMAIN}\n{endpoint}\n{cert_sha256}\n{ts}").into_bytes()
}

fn is_public(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() || ip.is_broadcast()
        || ip.is_multicast() || ip.is_documentation() || o[0] == 0 || (o[0] == 100 && (64..128).contains(&o[1])) || o[0] >= 240)
}

fn parse_endpoint(endpoint: &str) -> Option<(Ipv4Addr, u16)> {
    let rest = endpoint.strip_prefix("https://")?.strip_suffix("/rpc")?;
    let (host, port) = rest.rsplit_once(':')?;
    let ip: Ipv4Addr = host.parse().ok()?;
    let port: u16 = port.parse().ok()?;
    (is_public(&ip) && port >= 1024 && format!("https://{ip}:{port}/rpc") == endpoint).then_some((ip, port))
}

pub fn check(a: &Announcement, now: i64) -> Result<(), &'static str> {
    use ed25519_dalek::{Signature, VerifyingKey};
    if parse_endpoint(&a.endpoint).is_none() {
        return Err("endpoint");
    }
    if a.ts > now + CLOCK_SKEW_SECS || a.ts < now - ENTRY_FRESH_SECS {
        return Err("time");
    }
    if a.cert_sha256.len() != 64 || !a.cert_sha256.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) {
        return Err("cert");
    }
    let pk: [u8; 32] = hex::decode(&a.pubkey).ok().and_then(|v| v.try_into().ok()).ok_or("pubkey")?;
    let sig: [u8; 64] = hex::decode(&a.sig).ok().and_then(|v| v.try_into().ok()).ok_or("sig")?;
    let key = VerifyingKey::from_bytes(&pk).map_err(|_| "pubkey")?;
    key.verify_strict(&announcement_bytes(&a.endpoint, &a.cert_sha256, a.ts), &Signature::from_bytes(&sig))
        .map_err(|_| "sig")?;
    if crate::market_chain::address_of(&pk) != a.node {
        return Err("node");
    }
    Ok(())
}

pub fn learn(a: Announcement, now: i64) -> bool {
    if check(&a, now).is_err() {
        return false;
    }
    let mut guard = TABLE.lock().unwrap_or_else(|e| e.into_inner());
    let table = guard.get_or_insert_with(HashMap::new);
    table.retain(|_, e| now - e.announcement.ts < ENTRY_FRESH_SECS && e.failures < MAX_FAILURES);
    match table.get_mut(&a.endpoint) {
        Some(existing) if existing.announcement.ts >= a.ts => return false,
        Some(existing) => {
            let same_cert = existing.announcement.cert_sha256 == a.cert_sha256;
            existing.announcement = a;
            if !same_cert {
                existing.verified_at = None;
                existing.failures = 0;
            }
        }
        None => {
            if table.len() >= TABLE_MAX {
                if let Some(oldest) = table.iter().min_by_key(|(_, e)| e.announcement.ts).map(|(k, _)| k.clone()) {
                    table.remove(&oldest);
                }
            }
            table.insert(a.endpoint.clone(), Entry { announcement: a, verified_at: None, failures: 0 });
        }
    }
    true
}

pub fn share(now: i64) -> Vec<Announcement> {
    let mut rng = rand::thread_rng();
    let guard = TABLE.lock().unwrap_or_else(|e| e.into_inner());
    let entries: Vec<&Entry> = guard
        .as_ref()
        .map(|t| t.values().filter(|e| now - e.announcement.ts < ENTRY_FRESH_SECS && e.failures < MAX_FAILURES).collect())
        .unwrap_or_default();
    let mut verified: Vec<Announcement> = entries
        .iter()
        .filter(|e| e.verified_at.map(|t| now - t < VERIFIED_FOR_SECS).unwrap_or(false))
        .map(|e| e.announcement.clone())
        .collect();
    let mut unverified: Vec<Announcement> = entries
        .iter()
        .filter(|e| !e.verified_at.map(|t| now - t < VERIFIED_FOR_SECS).unwrap_or(false))
        .map(|e| e.announcement.clone())
        .collect();
    drop(guard);
    verified.shuffle(&mut rng);
    unverified.shuffle(&mut rng);
    let mut out = Vec::with_capacity(SHARE_LIMIT);
    if let Some(own) = OWN.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        out.push(own);
    }
    for a in verified.into_iter().chain(unverified) {
        if out.len() >= SHARE_LIMIT {
            break;
        }
        if !out.iter().any(|o| o.endpoint == a.endpoint) {
            out.push(a);
        }
    }
    out
}

pub async fn receive_gossip(data: Vec<u8>) {
    if let Ok(a) = serde_json::from_slice::<Announcement>(&data) {
        learn(a, chrono::Utc::now().timestamp());
    }
}

fn cost(method: &str) -> f64 {
    match method {
        "tx.submit" | "chat.submit" => 20.0,
        "chat.feed" => 4.0,
        _ => 1.0,
    }
}

fn allow(ip: IpAddr, cost: f64) -> bool {
    let mut guard = BUCKETS.lock().unwrap_or_else(|e| e.into_inner());
    let buckets = guard.get_or_insert_with(HashMap::new);
    let now = Instant::now();
    if buckets.len() > 100_000 {
        buckets.retain(|_, (_, seen)| now.duration_since(*seen) < Duration::from_secs(600));
    }
    let (tokens, seen) = buckets.entry(ip).or_insert((BUCKET_SIZE, now));
    *tokens = (*tokens + now.duration_since(*seen).as_secs_f64() * REFILL_PER_SEC).min(BUCKET_SIZE);
    *seen = now;
    if *tokens < cost {
        return false;
    }
    *tokens -= cost;
    true
}

fn ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "result": result, "id": id })
}

fn fail(id: Value, code: i32, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "error": { "code": code, "message": message }, "id": id })
}

fn refusal(reason: &str) -> &'static str {
    match reason {
        "banned" => "Community votes removed this address from the chat for now.",
        "time" => "The message's time is off. Check your phone's date and time.",
        "text" => "That message has characters the chat doesn't allow.",
        "signature" => "That message isn't signed by the address it claims to come from.",
        "target" => "That isn't someone you can vote on.",
        "author" => "You can only change your own messages.",
        "rate" => "Slow down a little before sending again.",
        _ => "The chat couldn't take that message. Try again.",
    }
}

async fn chat_feed(params: &Value) -> Result<Value, (i32, String)> {
    let viewer = params["viewer"].as_str().unwrap_or_default().to_string();
    let viewer = if crate::dao_chat::is_address(&viewer) { viewer } else { String::new() };
    let before = params["before"].as_i64();
    let feed = tokio::task::spawn_blocking(move || {
        crate::commands::dao_chat::feed(viewer, before, chrono::Utc::now().timestamp())
    })
    .await
    .map_err(|e| (-32603, e.to_string()))?;
    serde_json::to_value(feed).map_err(|e| (-32603, e.to_string()))
}

async fn chat_submit(params: &Value) -> Result<Value, (i32, String)> {
    let wire: crate::dao_chat::Wire = serde_json::from_value(params["wire"].clone())
        .map_err(|_| (-32602, "That isn't a chat message the network understands.".to_string()))?;
    let local = wire.clone();
    let now = chrono::Utc::now().timestamp();
    let accepted = tokio::task::spawn_blocking(move || crate::dao_chat::accept(&local, now, crate::dao_chat::Source::Gossip))
        .await
        .map_err(|e| (-32603, e.to_string()))?
        .map_err(|reason| (-32000, refusal(reason).to_string()))?;
    if accepted {
        if let Ok(data) = serde_json::to_vec(&wire) {
            crate::p2p::publish_gossip(crate::dao_chat::TOPIC, data).await;
        }
        crate::dao_chat::notify(crate::p2p::APP_HANDLE.get());
    }
    Ok(json!({ "accepted": true, "new": accepted }))
}

async fn storage_capacity() -> Result<Value, (i32, String)> {
    let now = chrono::Utc::now().timestamp();
    let (providers, free) = tokio::task::spawn_blocking(move || crate::p2p::live_storage(now))
        .await
        .map_err(|e| (-32603, e.to_string()))?;
    Ok(json!({ "providers": providers, "free_bytes": free, "updated_at": now }))
}

async fn rpc(ConnectInfo(peer): ConnectInfo<SocketAddr>, Json(body): Json<Value>) -> Response {
    let id = body.get("id").cloned().unwrap_or(Value::Null);
    let method = body.get("method").and_then(Value::as_str).unwrap_or_default().to_string();
    if !allow(peer.ip(), cost(&method)) {
        let reply = fail(id, -32005, "Too many requests from your connection. Wait a moment and try again.");
        return (StatusCode::TOO_MANY_REQUESTS, Json(reply)).into_response();
    }
    if PASSTHROUGH.contains(&method.as_str()) {
        return Json(crate::rpc::dispatch_value(body)).into_response();
    }
    let params = body.get("params").cloned().unwrap_or(Value::Null);
    let result = match method.as_str() {
        "chat.feed" => chat_feed(&params).await,
        "chat.submit" => chat_submit(&params).await,
        "storage.capacity" => storage_capacity().await,
        "gateway.list" => Ok(json!({ "gateways": share(chrono::Utc::now().timestamp()) })),
        _ => Err((-32601, NOT_HERE.to_string())),
    };
    Json(match result {
        Ok(v) => ok(id, v),
        Err((code, message)) => fail(id, code, &message),
    })
    .into_response()
}

async fn health(ConnectInfo(peer): ConnectInfo<SocketAddr>) -> Json<Value> {
    if let IpAddr::V4(ip) = peer.ip() {
        if is_public(&ip) {
            update(|s| s.reached_from_internet_at = Some(chrono::Utc::now().timestamp()));
        }
    }
    Json(json!({ "ok": true, "service": "ego-gateway", "version": env!("CARGO_PKG_VERSION") }))
}

pub fn router() -> Router {
    Router::new()
        .route("/rpc", post(rpc))
        .route("/health", get(health))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

async fn serve(cert_pem: String, key_pem: String) {
    let config = match axum_server::tls_rustls::RustlsConfig::from_pem(cert_pem.into_bytes(), key_pem.into_bytes()).await {
        Ok(c) => c,
        Err(e) => {
            update(|s| s.problem = Some(format!("The gateway couldn't load its certificate: {e}")));
            return;
        }
    };
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port()));
    update(|s| s.running = true);
    let result = axum_server::bind_rustls(addr, config)
        .serve(router().into_make_service_with_connect_info::<SocketAddr>())
        .await;
    update(|s| {
        s.running = false;
        if let Err(e) = result {
            s.problem = Some(format!("The gateway couldn't listen on port {}: {e}", port()));
        }
    });
}

async fn public_ipv4(client: &reqwest::Client) -> Option<Ipv4Addr> {
    for url in ["https://api.ipify.org", "https://ipv4.icanhazip.com"] {
        if let Ok(resp) = client.get(url).send().await {
            if let Ok(text) = resp.text().await {
                if let Ok(ip) = text.trim().parse::<Ipv4Addr>() {
                    if is_public(&ip) {
                        return Some(ip);
                    }
                }
            }
        }
    }
    None
}

async fn make_announcement(client: &reqwest::Client, cert_sha256: &str) -> Result<Announcement, String> {
    let ip = public_ipv4(client).await.ok_or("Couldn't find this computer's public internet address.")?;
    let endpoint = format!("https://{ip}:{}/rpc", port());
    let kp = crate::app::global_app_state()
        .get_keypair()
        .ok_or("Unlock your wallet so the gateway can sign its announcement.")?;
    let ts = chrono::Utc::now().timestamp();
    let pubkey: [u8; 32] = kp.ed25519_public_key().as_bytes()[..32].try_into().map_err(|_| "bad key")?;
    Ok(Announcement {
        sig: hex::encode(kp.sign_ed25519(&announcement_bytes(&endpoint, cert_sha256, ts)).as_bytes()),
        node: crate::market_chain::address_of(&pubkey),
        pubkey: hex::encode(pubkey),
        cert_sha256: cert_sha256.to_string(),
        endpoint,
        ts,
    })
}

async fn tell_bootstrap(client: &reqwest::Client, a: &Announcement) -> Result<bool, String> {
    let resp = client
        .post(format!("{}/gateways/register", crate::p2p::ORACLE_RPC))
        .json(a)
        .send()
        .await
        .map_err(|e| format!("Couldn't update the bootstrap list: {e}"))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(false);
    }
    let code = resp.status();
    let reply: Value = resp.json().await.unwrap_or(Value::Null);
    if !code.is_success() {
        return Err(reply["error"].as_str().map(str::to_string).unwrap_or_else(|| format!("The bootstrap list answered {code}.")));
    }
    Ok(reply["listed"].as_bool().unwrap_or(false))
}

fn should_announce(router_open: Option<bool>, router_ip: Option<&str>, public_ip: &str, reached_at: Option<i64>, now: i64) -> bool {
    let mapped = router_open == Some(true) && router_ip == Some(public_ip);
    let reached = reached_at.map(|t| now - t < REACHED_FOR_SECS).unwrap_or(false);
    mapped || reached
}

fn sampled(node: &str, known: usize, target: usize) -> bool {
    let spread = if known < target {
        return true;
    } else if known >= TABLE_MAX {
        16
    } else {
        known / target + 1
    };
    let digest = Sha256::digest(node.as_bytes());
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(first) % spread as u64 == 0
}

async fn announce_once(client: &reqwest::Client, cert_sha256: &str) -> bool {
    let a = match make_announcement(client, cert_sha256).await {
        Ok(a) => a,
        Err(e) => {
            update(|s| s.problem = Some(e));
            return false;
        }
    };
    let now = chrono::Utc::now().timestamp();
    let public_ip = parse_endpoint(&a.endpoint).map(|(ip, _)| ip.to_string()).unwrap_or_default();
    let snapshot = status();
    let reachable = should_announce(
        snapshot.router_port_open,
        snapshot.router_public_ip.as_deref(),
        &public_ip,
        snapshot.reached_from_internet_at,
        now,
    );
    update(|s| {
        s.endpoint = Some(a.endpoint.clone());
        s.reachable = reachable;
        s.problem = None;
    });
    if !reachable {
        *OWN.lock().unwrap_or_else(|e| e.into_inner()) = None;
        update(|s| s.bootstrap_listed = false);
        return false;
    }
    *OWN.lock().unwrap_or_else(|e| e.into_inner()) = Some(a.clone());
    if sampled(&a.node, snapshot.known_gateways, GOSSIP_SAMPLE) {
        if let Ok(data) = serde_json::to_vec(&a) {
            crate::p2p::publish_gossip(GOSSIP_TOPIC, data).await;
        }
    }
    let listed = if sampled(&a.node, snapshot.known_gateways, BOOTSTRAP_SAMPLE) {
        tell_bootstrap(client, &a).await
    } else {
        Ok(false)
    };
    update(|s| {
        s.last_announce = Some(chrono::Utc::now().timestamp());
        match listed {
            Ok(l) => s.bootstrap_listed = l,
            Err(e) => s.problem = Some(e),
        }
    });
    true
}

async fn announce_loop(cert_sha256: String) {
    let client = match reqwest::Client::builder().timeout(Duration::from_secs(20)).build() {
        Ok(c) => c,
        Err(_) => return,
    };
    loop {
        let wait = if announce_once(&client, &cert_sha256).await { ANNOUNCE_EVERY } else { RETRY_UNREACHABLE };
        tokio::time::sleep(wait).await;
    }
}

async fn find_router() -> Result<igd_next::aio::Gateway<igd_next::aio::tokio::Tokio>, String> {
    igd_next::aio::tokio::search_gateway(igd_next::SearchOptions {
        timeout: Some(Duration::from_secs(5)),
        ..Default::default()
    })
    .await
    .map_err(|e| format!("no UPnP router answered: {e}"))
}

async fn local_ipv4_toward(router: SocketAddr) -> Option<Ipv4Addr> {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket.connect(router).await.ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) if !ip.is_unspecified() => Some(ip),
        _ => None,
    }
}

async fn open_router_port() -> Result<Ipv4Addr, String> {
    let router = find_router().await?;
    let local = local_ipv4_toward(router.addr).await.ok_or("couldn't find this computer's local address")?;
    router
        .add_port(
            igd_next::PortMappingProtocol::TCP,
            port(),
            SocketAddr::from((local, port())),
            ROUTER_LEASE_SECS,
            "Ego Desktop phone gateway",
        )
        .await
        .map_err(|e| format!("the router refused to open port {}: {e}", port()))?;
    match router.get_external_ip().await {
        Ok(IpAddr::V4(ip)) => Ok(ip),
        Ok(_) => Err("the router has no IPv4 address".into()),
        Err(e) => Err(format!("the router didn't give its public address: {e}")),
    }
}

async fn close_router_port() {
    if let Ok(router) = find_router().await {
        let _ = router.remove_port(igd_next::PortMappingProtocol::TCP, port()).await;
    }
}

async fn router_loop() {
    loop {
        match open_router_port().await {
            Ok(ip) => update(|s| {
                s.router_port_open = Some(is_public(&ip));
                s.router_public_ip = Some(ip.to_string());
            }),
            Err(e) => {
                tracing::debug!("[gateway] {e}");
                update(|s| {
                    s.router_port_open = Some(false);
                    s.router_public_ip = None;
                });
            }
        }
        tokio::time::sleep(ROUTER_RENEW).await;
    }
}

async fn probe(client: &reqwest::Client, a: &Announcement) -> bool {
    let health = a.endpoint.trim_end_matches("/rpc").to_string() + "/health";
    let Ok(resp) = client.get(&health).send().await else { return false };
    let der = resp
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(|t| t.peer_certificate())
        .map(|d| d.to_vec());
    let Some(der) = der else { return false };
    if hex::encode(Sha256::digest(&der)) != a.cert_sha256 {
        return false;
    }
    resp.json::<Value>().await.map(|v| v["service"] == "ego-gateway").unwrap_or(false)
}

fn due_for_probe(now: i64) -> Vec<Announcement> {
    let own = OWN.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|a| a.endpoint.clone());
    let guard = TABLE.lock().unwrap_or_else(|e| e.into_inner());
    let mut due: Vec<Announcement> = guard
        .as_ref()
        .map(|t| {
            t.values()
                .filter(|e| Some(&e.announcement.endpoint) != own.as_ref())
                .filter(|e| e.failures < MAX_FAILURES && !e.verified_at.map(|t| now - t < VERIFIED_FOR_SECS).unwrap_or(false))
                .map(|e| e.announcement.clone())
                .collect()
        })
        .unwrap_or_default();
    drop(guard);
    due.shuffle(&mut rand::thread_rng());
    due.truncate(PROBES_PER_ROUND);
    due
}

fn record_probe(endpoint: &str, reachable: bool, now: i64) {
    let mut guard = TABLE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(e) = guard.as_mut().and_then(|t| t.get_mut(endpoint)) {
        if reachable {
            e.verified_at = Some(now);
            e.failures = 0;
        } else {
            e.failures = e.failures.saturating_add(1);
        }
    }
}

async fn probe_loop() {
    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .tls_info(true)
        .timeout(Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };
    loop {
        tokio::time::sleep(PROBE_EVERY).await;
        let now = chrono::Utc::now().timestamp();
        for a in due_for_probe(now) {
            let reachable = probe(&client, &a).await;
            record_probe(&a.endpoint, reachable, chrono::Utc::now().timestamp());
        }
    }
}

pub async fn supervise() {
    let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    loop {
        let want = tokio::task::spawn_blocking(enabled).await.unwrap_or(false);
        let alive = tasks.first().map(|h| !h.is_finished()).unwrap_or(false);
        if want && !alive {
            for t in tasks.drain(..) {
                t.abort();
            }
            match tokio::task::spawn_blocking(certificate).await {
                Ok(Ok((cert, key, fingerprint))) => {
                    update(|s| {
                        s.cert_sha256 = Some(fingerprint.clone());
                        s.problem = None;
                    });
                    tasks.push(tokio::spawn(serve(cert, key)));
                    tasks.push(tokio::spawn(router_loop()));
                    tasks.push(tokio::spawn(announce_loop(fingerprint)));
                    tasks.push(tokio::spawn(probe_loop()));
                }
                Ok(Err(e)) => update(|s| s.problem = Some(e)),
                Err(e) => update(|s| s.problem = Some(e.to_string())),
            }
        } else if !want && !tasks.is_empty() {
            for t in tasks.drain(..) {
                t.abort();
            }
            *OWN.lock().unwrap_or_else(|e| e.into_inner()) = None;
            tokio::spawn(close_router_port());
            update(|s| {
                s.running = false;
                s.bootstrap_listed = false;
                s.reachable = false;
                s.router_port_open = None;
                s.router_public_ip = None;
                s.problem = None;
            });
        }
        tokio::time::sleep(SUPERVISE_EVERY).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed(key: &SigningKey, endpoint: &str, cert: &str, ts: i64) -> Announcement {
        let pk = key.verifying_key().to_bytes();
        Announcement {
            endpoint: endpoint.into(),
            cert_sha256: cert.into(),
            node: crate::market_chain::address_of(&pk),
            ts,
            pubkey: hex::encode(pk),
            sig: hex::encode(key.sign(&announcement_bytes(endpoint, cert, ts)).to_bytes()),
        }
    }

    #[test]
    fn the_bucket_throttles_one_address_and_not_another() {
        let a: IpAddr = "203.0.113.7".parse().unwrap();
        let b: IpAddr = "203.0.113.8".parse().unwrap();
        let mut sent = 0;
        while allow(a, cost("tx.submit")) {
            sent += 1;
            assert!(sent < 100);
        }
        assert_eq!(sent, (BUCKET_SIZE / 20.0) as usize);
        assert!(allow(b, cost("wallet.getBalance")));
    }

    #[test]
    fn only_public_addresses_are_announced() {
        for private in ["10.0.0.1", "192.168.1.5", "172.16.0.1", "127.0.0.1", "100.64.0.1", "169.254.1.1"] {
            assert!(!is_public(&private.parse().unwrap()), "{private}");
        }
        assert!(is_public(&"8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn the_certificate_fingerprint_comes_from_the_saved_pem() {
        let cert = rcgen::generate_simple_self_signed(vec!["ego-gateway".to_string()]).unwrap();
        let pem = cert.serialize_pem().unwrap();
        let der = pem_der(&pem).unwrap();
        assert!(!der.is_empty());
        assert_eq!(hex::encode(Sha256::digest(&der)), hex::encode(Sha256::digest(&pem_der(&pem).unwrap())));
    }

    #[test]
    fn announcements_must_be_signed_by_the_named_node() {
        let now = 1_800_000_000;
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let cert = "cd".repeat(32);
        let good = signed(&key, "https://8.8.8.8:47398/rpc", &cert, now);
        assert_eq!(check(&good, now), Ok(()));
        let mut moved = good.clone();
        moved.endpoint = "https://1.1.1.1:47398/rpc".into();
        assert_eq!(check(&moved, now), Err("sig"));
        let mut other = good.clone();
        other.node = crate::market_chain::address_of(&[1u8; 32]);
        assert_eq!(check(&other, now), Err("node"));
        assert_eq!(check(&signed(&key, "https://192.168.0.2:47398/rpc", &cert, now), now), Err("endpoint"));
        assert_eq!(check(&good, now + ENTRY_FRESH_SECS + 1), Err("time"));
    }

    #[test]
    fn the_table_keeps_the_newest_word_and_shares_checked_gateways_first() {
        let now = chrono::Utc::now().timestamp();
        let key = SigningKey::from_bytes(&[6u8; 32]);
        let cert = "ef".repeat(32);
        assert!(learn(signed(&key, "https://203.0.114.1:47398/rpc", &cert, now - 60), now));
        assert!(!learn(signed(&key, "https://203.0.114.1:47398/rpc", &cert, now - 120), now), "older news is ignored");
        assert!(learn(signed(&key, "https://203.0.114.2:47398/rpc", &cert, now - 30), now));
        record_probe("https://203.0.114.2:47398/rpc", true, now);
        let shared = share(now);
        let first_checked = shared.iter().position(|a| a.endpoint == "https://203.0.114.2:47398/rpc").unwrap();
        let unchecked = shared.iter().position(|a| a.endpoint == "https://203.0.114.1:47398/rpc").unwrap();
        assert!(first_checked < unchecked);
        record_probe("https://203.0.114.1:47398/rpc", false, now);
        record_probe("https://203.0.114.1:47398/rpc", false, now);
        assert!(!share(now).iter().any(|a| a.endpoint == "https://203.0.114.1:47398/rpc"), "two failed checks drop a gateway");
    }

    #[test]
    fn only_a_reachable_computer_is_announced() {
        let now = 1_800_000_000;
        assert!(should_announce(Some(true), Some("8.8.8.8"), "8.8.8.8", None, now));
        assert!(!should_announce(Some(true), Some("100.64.0.9"), "8.8.8.8", None, now), "a router behind the provider's shared address is not enough");
        assert!(!should_announce(Some(false), None, "8.8.8.8", None, now));
        assert!(!should_announce(None, None, "8.8.8.8", None, now));
        assert!(should_announce(Some(false), None, "8.8.8.8", Some(now - 60), now), "a manual port forward counts once someone reached it");
        assert!(!should_announce(Some(false), None, "8.8.8.8", Some(now - 2 * 3_600), now));
    }

    #[test]
    fn a_large_network_only_sends_a_sample_to_the_bootstrap_list() {
        let nodes: Vec<String> = (0..4_000).map(|i| format!("egot1node{i}")).collect();
        assert!(nodes.iter().all(|n| sampled(n, 50, BOOTSTRAP_SAMPLE)), "a small network registers everyone");
        let some = nodes.iter().filter(|n| sampled(n, 1_000, BOOTSTRAP_SAMPLE)).count();
        assert!((500..1_000).contains(&some), "{some}");
        let few = nodes.iter().filter(|n| sampled(n, TABLE_MAX, BOOTSTRAP_SAMPLE)).count();
        assert!((150..350).contains(&few), "{few}");
        assert_eq!(sampled("egot1same", 1_500, GOSSIP_SAMPLE), sampled("egot1same", 1_500, GOSSIP_SAMPLE));
    }

    #[test]
    fn announcements_are_domain_separated() {
        assert_eq!(
            announcement_bytes("https://203.0.113.7:47398/rpc", "ab", 5),
            b"ego/gateway/v1\nhttps://203.0.113.7:47398/rpc\nab\n5".to_vec()
        );
    }

    #[tokio::test]
    async fn the_gateway_only_answers_what_phones_need() {
        let peer: SocketAddr = "198.51.100.9:5000".parse().unwrap();
        let call = |method: &str| json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": {} });
        for blocked in ["shielded.exportNotes", "contract.query", "anything.else"] {
            let resp = rpc(ConnectInfo(peer), Json(call(blocked))).await;
            let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
            let v: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(v["error"]["code"], -32601, "{blocked}");
        }
        for (method, field) in [("storage.capacity", "providers"), ("gateway.list", "gateways")] {
            let resp = rpc(ConnectInfo(peer), Json(call(method))).await;
            let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
            let v: Value = serde_json::from_slice(&body).unwrap();
            assert!(!v["result"][field].is_null(), "{method}: {v}");
        }
    }
}
