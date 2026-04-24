mod acme;
mod dns;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use once_cell::sync::Lazy;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::Arc,
    time::Duration,
};

const GENESIS_HASH:  &str = "ego00000000000000000000000000000000000000000000000000000000genesis2";
const GENESIS_MINER: &str = "egot1genesis0000000000000000000000000000000000";
const GENESIS_TS:    i64  = 1_744_588_800;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, warn};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostingNodeRecord {
    pub node_id:   String,
    pub endpoint:  String,
    pub sites:     Vec<String>,
    pub domains:   Vec<String>,
    pub last_seen: i64,
}

type HostingNodes = HashMap<String, HostingNodeRecord>;

// ── Price types ────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PriceEntry {
    pub usd: f64,
    pub updated_at: i64,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub stale: bool,
}

type PriceMap = HashMap<String, PriceEntry>;

// ── Chain types ────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ChainState {
    pub blocks:       Vec<Value>,
    pub transactions: Vec<Value>,
}

const MAX_BLOCKS: usize       = 50_000;
const MAX_TRANSACTIONS: usize = 500_000;

impl ChainState {
    fn merge_block(&mut self, block: Value) {
        let height = block["height"].as_u64().unwrap_or(0);
        if let Some(pos) = self.blocks.iter().position(|b| b["height"].as_u64() == Some(height)) {
            self.blocks[pos] = block;
        } else {
            self.blocks.push(block);
            if self.blocks.len() > MAX_BLOCKS {
                self.blocks.sort_by_key(|b| b["height"].as_u64().unwrap_or(0));
                self.blocks = self.blocks.split_off(self.blocks.len() - MAX_BLOCKS);
            }
        }
    }

    fn merge_txs(&mut self, txs: Vec<Value>) {
        for tx in txs {
            let hash = tx["hash"].as_str().unwrap_or("").to_string();
            if hash.is_empty() { continue; }
            if !self.transactions.iter().any(|t| t["hash"].as_str() == Some(&hash)) {
                self.transactions.push(tx);
            }
        }
        if self.transactions.len() > MAX_TRANSACTIONS {
            self.transactions = self.transactions.split_off(self.transactions.len() - MAX_TRANSACTIONS);
        }
    }

    fn sorted_blocks(&self) -> Vec<Value> {
        let mut v = self.blocks.clone();
        v.sort_by(|a, b| {
            b["height"].as_u64().unwrap_or(0).cmp(&a["height"].as_u64().unwrap_or(0))
        });
        v
    }

    fn sorted_txs(&self) -> Vec<Value> {
        let mut v = self.transactions.clone();
        v.sort_by(|a, b| {
            b["timestamp"].as_i64().unwrap_or(0).cmp(&a["timestamp"].as_i64().unwrap_or(0))
        });
        v
    }
}

fn chain_data_path() -> std::path::PathBuf {
    std::env::var("ORACLE_DATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/var/lib/ego-oracle/chain.json"))
}

fn genesis_chain_state() -> ChainState {
    ChainState {
        blocks: vec![json!({
            "height":    0,
            "hash":      GENESIS_HASH,
            "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "miner":     GENESIS_MINER,
            "timestamp": GENESIS_TS,
            "tx_count":  0,
            "size_bytes": 0,
            "reward":    0,
        })],
        transactions: vec![],
    }
}

fn load_chain() -> ChainState {
    let path = chain_data_path();
    if let Ok(data) = std::fs::read_to_string(&path) {
        if let Ok(mut state) = serde_json::from_str::<ChainState>(&data) {
            if !state.blocks.iter().any(|b| b["height"].as_u64() == Some(0)) {
                let mut g = genesis_chain_state();
                state.blocks.push(g.blocks.remove(0));
            }
            info!("Loaded chain state from disk: {} blocks, {} txs", state.blocks.len(), state.transactions.len());
            return state;
        }
    }
    info!("No persisted chain state found, seeding genesis");
    genesis_chain_state()
}

fn save_chain(chain: &ChainState) {
    let path = chain_data_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match serde_json::to_string(chain) {
        Ok(data) => { let _ = std::fs::write(&path, data); }
        Err(e) => { error!("Failed to serialize chain state: {}", e); }
    }
}

// ── App state ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub prices:        Arc<RwLock<PriceMap>>,
    pub chain:         Arc<RwLock<ChainState>>,
    pub client:        Client,
    pub hosting_nodes: Arc<RwLock<HostingNodes>>,
    pub ego_nodes:     Arc<RwLock<Vec<String>>>,
    pub acme:          Arc<acme::AcmeState>,
}

const EGOC_USD: f64 = 0.01;
const EGOC_SUPPLY: u64 = 1_000_000_000;
const EGOC_MARKET_CAP: f64 = EGOC_USD * EGOC_SUPPLY as f64;

static BINANCE_SYMBOLS: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("BTC", "BTCUSDT");
    m.insert("ETH", "ETHUSDT");
    m.insert("SOL", "SOLUSDT");
    m.insert("BNB", "BNBUSDT");
    m.insert("MATIC", "MATICUSDT");
    m
});

// ── Price fetching ─────────────────────────────────────────────────────────────

async fn fetch_coingecko(client: &Client) -> anyhow::Result<HashMap<String, f64>> {
    let url = "https://api.coingecko.com/api/v3/simple/price\
               ?ids=ethereum,bitcoin,solana,binancecoin,matic-network\
               &vs_currencies=usd";
    let resp: Value = client.get(url).timeout(Duration::from_secs(10)).send().await?
        .error_for_status()?.json().await?;
    let mut out = HashMap::new();
    for (id, sym) in &[("bitcoin","BTC"),("ethereum","ETH"),("solana","SOL"),("binancecoin","BNB"),("matic-network","MATIC")] {
        if let Some(price) = resp[id]["usd"].as_f64() { out.insert(sym.to_string(), price); }
    }
    Ok(out)
}

async fn fetch_binance(client: &Client) -> anyhow::Result<HashMap<String, f64>> {
    #[derive(Deserialize)]
    struct Ticker { symbol: String, price: String }
    let tickers: Vec<Ticker> = client.get("https://api.binance.com/api/v3/ticker/price")
        .timeout(Duration::from_secs(10)).send().await?.error_for_status()?.json().await?;
    let reverse: HashMap<&str, &str> = BINANCE_SYMBOLS.iter().map(|(s, t)| (*t, *s)).collect();
    let mut out = HashMap::new();
    for t in &tickers {
        if let Some(&sym) = reverse.get(t.symbol.as_str()) {
            if let Ok(price) = t.price.parse::<f64>() { out.insert(sym.to_string(), price); }
        }
    }
    Ok(out)
}

fn average_maps(a: HashMap<String, f64>, b: HashMap<String, f64>) -> HashMap<String, f64> {
    let mut result = HashMap::new();
    let keys: std::collections::HashSet<String> = a.keys().chain(b.keys()).cloned().collect();
    for key in keys {
        let price = match (a.get(&key), b.get(&key)) {
            (Some(&pa), Some(&pb)) => (pa + pb) / 2.0,
            (Some(&pa), None) => pa,
            (None, Some(&pb)) => pb,
            _ => continue,
        };
        result.insert(key, price);
    }
    result
}

async fn refresh_prices(state: AppState) {
    let now = Utc::now().timestamp();
    let (cg_result, bn_result) = (fetch_coingecko(&state.client).await, fetch_binance(&state.client).await);
    let (merged, stale) = match (cg_result, bn_result) {
        (Ok(cg), Ok(bn)) => { info!("Prices from CoinGecko+Binance"); (average_maps(cg, bn), false) }
        (Ok(cg), Err(e)) => { warn!("Binance failed ({})", e); (cg, false) }
        (Err(e), Ok(bn)) => { warn!("CoinGecko failed ({})", e); (bn, false) }
        (Err(e1), Err(e2)) => { error!("Both price sources failed: {} {}", e1, e2); (HashMap::new(), true) }
    };
    let mut prices = state.prices.write().await;
    if stale { for e in prices.values_mut() { e.stale = true; } return; }
    for (sym, usd) in merged { prices.insert(sym, PriceEntry { usd, updated_at: now, stale: false }); }
    prices.insert("EGOC".to_string(), PriceEntry { usd: EGOC_USD, updated_at: now, stale: false });
}

async fn price_refresh_task(state: AppState) {
    loop { refresh_prices(state.clone()).await; tokio::time::sleep(Duration::from_secs(30)).await; }
}

// ── Handlers: prices ──────────────────────────────────────────────────────────

async fn handle_prices(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.prices.read().await.clone())
}

async fn handle_price(State(state): State<AppState>, Path(symbol): Path<String>) -> impl IntoResponse {
    let sym = symbol.to_uppercase();
    let prices = state.prices.read().await;
    if let Some(entry) = prices.get(&sym) {
        (StatusCode::OK, Json(json!({ "symbol": sym, "usd": entry.usd, "updated_at": entry.updated_at, "stale": entry.stale })))
    } else {
        (StatusCode::NOT_FOUND, Json(json!({ "error": format!("symbol '{}' not found", sym) })))
    }
}

async fn handle_egoc(State(state): State<AppState>) -> impl IntoResponse {
    let updated_at = state.prices.read().await.get("EGOC").map(|e| e.updated_at).unwrap_or_else(|| Utc::now().timestamp());
    Json(json!({ "symbol": "EGOC", "usd": EGOC_USD, "market_cap": EGOC_MARKET_CAP, "supply": EGOC_SUPPLY, "updated_at": updated_at }))
}

// ── Handlers: chain ───────────────────────────────────────────────────────────

async fn handle_chain_blocks(State(state): State<AppState>) -> impl IntoResponse {
    let chain = state.chain.read().await;
    Json(chain.sorted_blocks())
}

async fn handle_chain_transactions(State(state): State<AppState>) -> impl IntoResponse {
    let chain = state.chain.read().await;
    Json(chain.sorted_txs())
}

#[derive(Deserialize)]
struct SubmitPayload {
    #[serde(default)]
    block: Option<Value>,
    #[serde(default)]
    blocks: Vec<Value>,
    #[serde(default)]
    transactions: Vec<Value>,
}

async fn handle_chain_submit(
    State(state): State<AppState>,
    Json(payload): Json<SubmitPayload>,
) -> impl IntoResponse {
    let mut chain = state.chain.write().await;

    if let Some(block) = payload.block {
        let height = block["height"].as_u64().unwrap_or(0);
        chain.merge_block(block);
        info!("Oracle: accepted block #{}", height);
    }
    for block in payload.blocks {
        chain.merge_block(block);
    }
    chain.merge_txs(payload.transactions);

    let snapshot = chain.clone();
    drop(chain);
    tokio::task::spawn_blocking(move || save_chain(&snapshot));

    let chain = state.chain.read().await;
    (StatusCode::OK, Json(json!({ "ok": true, "blocks": chain.blocks.len(), "txs": chain.transactions.len() })))
}

// ── Handlers: hosting node registry ──────────────────────────────────────

async fn handle_hosting_announce(
    State(state): State<AppState>,
    Json(record): Json<HostingNodeRecord>,
) -> impl IntoResponse {
    let mut nodes = state.hosting_nodes.write().await;
    nodes.insert(record.node_id.clone(), record);
    StatusCode::OK
}

async fn handle_hosting_nodes(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> impl IntoResponse {
    let now = Utc::now().timestamp();
    let nodes = state.hosting_nodes.read().await;
    let matching: Vec<&HostingNodeRecord> = nodes.values()
        .filter(|n| n.last_seen > now - 900)
        .filter(|n| n.domains.iter().any(|d| d == &domain) || n.sites.iter().any(|s| s == &domain))
        .collect();
    Json(json!({ "domain": domain, "nodes": matching }))
}

async fn handle_nodes_register(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    if let Some(endpoint) = body["endpoint"].as_str() {
        let ep = endpoint.trim_end_matches('/').to_string();
        let mut nodes = state.ego_nodes.write().await;
        if !nodes.contains(&ep) {
            info!("[Registry] Ego node registered: {}", ep);
            nodes.push(ep);
        }
    }
    StatusCode::OK
}

// ── Handlers: TLS cert automation (Let's Encrypt DNS-01) ─────────────────

#[derive(serde::Deserialize)]
struct CertRequest { domain: String }

async fn handle_cert_request(
    State(state): State<AppState>,
    Json(body): Json<CertRequest>,
) -> impl IntoResponse {
    let domain = body.domain.trim().to_lowercase();
    if domain.is_empty() || !domain.contains('.') {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid domain" })));
    }
    state.acme.request(domain.clone()).await;
    (StatusCode::ACCEPTED, Json(json!({ "domain": domain, "status": "pending" })))
}

async fn handle_cert_status(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> impl IntoResponse {
    match state.acme.status(&domain).await {
        Some(status) => (StatusCode::OK, Json(serde_json::to_value(&status).unwrap_or_default())),
        None         => (StatusCode::NOT_FOUND, Json(json!({ "error": "no cert request found" }))),
    }
}

// ── Handler: health ───────────────────────────────────────────────────────────

async fn handle_health(State(state): State<AppState>) -> impl IntoResponse {
    let prices = state.prices.read().await;
    let chain  = state.chain.read().await;
    let last_update = prices.values().map(|e| e.updated_at).max().unwrap_or(0);
    let tip = chain.blocks.iter().map(|b| b["height"].as_u64().unwrap_or(0)).max().unwrap_or(0);
    Json(json!({
        "status":       "ok",
        "prices_count": prices.len(),
        "last_update":  last_update,
        "chain_blocks": chain.blocks.len(),
        "chain_tip":    tip,
        "chain_txs":    chain.transactions.len(),
    }))
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ego_oracle=info,tower_http=warn".parse().unwrap()),
        )
        .init();

    let port: u16 = std::env::var("PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(8547);
    info!("Ego Oracle starting on port {}", port);

    let client = Client::builder().user_agent("ego-oracle/1.0").build().expect("failed to build HTTP client");

    let mut initial_prices: PriceMap = HashMap::new();
    initial_prices.insert("EGOC".to_string(), PriceEntry { usd: EGOC_USD, updated_at: Utc::now().timestamp(), stale: false });

    let acme_state = acme::AcmeState::new();

    let state = AppState {
        prices:        Arc::new(RwLock::new(initial_prices)),
        chain:         Arc::new(RwLock::new(load_chain())),
        client,
        hosting_nodes: Arc::new(RwLock::new(HashMap::new())),
        ego_nodes:     Arc::new(RwLock::new(Vec::new())),
        acme:          acme_state,
    };

    tokio::spawn(price_refresh_task(state.clone()));

    let relay_ip_str = std::env::var("RELAY_PUBLIC_IP").unwrap_or_else(|_| "127.0.0.1".to_string());
    let dns_upstream  = std::env::var("DNS_UPSTREAM").unwrap_or_else(|_| "8.8.8.8:53".to_string());
    let relay_ip: [u8; 4] = relay_ip_str.split('.')
        .map(|p| p.parse::<u8>().unwrap_or(0))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap_or([127, 0, 0, 1]);
    let dns_nodes      = state.hosting_nodes.clone();
    let dns_challenges = state.acme.challenges.clone();
    tokio::spawn(async move {
        dns::run_dns_server(relay_ip, dns_upstream, dns_nodes, dns_challenges).await;
    });

    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);

    let app = Router::new()
        .route("/health",                   get(handle_health))
        .route("/prices",                   get(handle_prices))
        .route("/price/:symbol",            get(handle_price))
        .route("/egoc",                     get(handle_egoc))
        .route("/chain/blocks",             get(handle_chain_blocks))
        .route("/chain/transactions",       get(handle_chain_transactions))
        .route("/chain/submit",             post(handle_chain_submit))
        .route("/hosting/announce",         post(handle_hosting_announce))
        .route("/hosting/nodes/:domain",    get(handle_hosting_nodes))
        .route("/nodes/register",           post(handle_nodes_register))
        .route("/cert/request",             post(handle_cert_request))
        .route("/cert/status/:domain",      get(handle_cert_status))
        .layer(cors)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .expect("failed to bind port");

    info!("Listening on http://0.0.0.0:{}", port);
    axum::serve(listener, app).await.expect("server error");
}
