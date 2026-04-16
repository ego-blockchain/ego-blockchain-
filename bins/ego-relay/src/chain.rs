use axum::{
    extract::State,
    http::StatusCode,
    Json, Router,
    routing::{get, post},
};
use rocksdb::{Options, DB};
use serde_json::Value;
use std::sync::{Arc, Mutex, OnceLock, RwLock};

static CHAIN_BLOCKS_DB: OnceLock<Arc<Mutex<DB>>>    = OnceLock::new();
static CHAIN_TXS_DB:    OnceLock<Arc<Mutex<DB>>>    = OnceLock::new();
static KNOWN_EGO_NODES: OnceLock<RwLock<Vec<String>>> = OnceLock::new();

fn node_store() -> &'static RwLock<Vec<String>> {
    KNOWN_EGO_NODES.get_or_init(|| RwLock::new(Vec::new()))
}

pub fn register_ego_node(url: &str) {
    let url = url.trim_end_matches('/').to_string();
    if let Ok(mut w) = node_store().write() {
        if !w.contains(&url) { w.push(url); }
    }
}

pub fn get_known_ego_nodes() -> Vec<String> {
    node_store().read().map(|r| r.clone()).unwrap_or_default()
}

fn blocks_db() -> Arc<Mutex<DB>> {
    CHAIN_BLOCKS_DB.get_or_init(|| {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        Arc::new(Mutex::new(DB::open(&opts, "chain_blocks.db").expect("open chain_blocks.db")))
    }).clone()
}

fn txs_db() -> Arc<Mutex<DB>> {
    CHAIN_TXS_DB.get_or_init(|| {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        Arc::new(Mutex::new(DB::open(&opts, "chain_txs.db").expect("open chain_txs.db")))
    }).clone()
}

pub fn store_tx(tx: &Value) {
    let hash = tx.get("hash").and_then(|h| h.as_str()).unwrap_or("").to_string();
    if hash.is_empty() { return; }
    if let Ok(val) = serde_json::to_vec(tx) {
        let _ = txs_db().lock().unwrap().put(hash.as_bytes(), val);
    }
}

#[derive(Clone)]
pub struct ChainStore;

pub fn new_chain_store() -> ChainStore {
    blocks_db();
    txs_db();
    ChainStore
}

pub fn chain_router(store: ChainStore) -> Router {
    Router::new()
        .route("/block/broadcast",    post(post_block))
        .route("/chain/blocks",       get(get_blocks))
        .route("/chain/transactions", get(get_transactions))
        .route("/nodes/register",     post(register_node))
        .with_state(store)
}

async fn register_node(Json(body): Json<Value>) -> StatusCode {
    if let Some(url) = body.get("endpoint").and_then(|v| v.as_str()) {
        register_ego_node(url);
        tracing::info!("[Chain] Ego node registered: {}", url);
    }
    StatusCode::OK
}

async fn post_block(
    State(_): State<ChainStore>,
    Json(block): Json<Value>,
) -> StatusCode {
    let height = block.get("height").and_then(|h| h.as_u64()).unwrap_or(u64::MAX);
    let key = height.to_be_bytes();
    if let Ok(val) = serde_json::to_vec(&block) {
        let _ = blocks_db().lock().unwrap().put(key, val);
    }
    StatusCode::OK
}

async fn get_blocks(State(_): State<ChainStore>) -> (StatusCode, Json<Vec<Value>>) {
    let db = blocks_db();
    let db = db.lock().unwrap();
    let mut blocks: Vec<Value> = db
        .iterator(rocksdb::IteratorMode::Start)
        .filter_map(|r| r.ok())
        .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
        .collect();
    blocks.sort_by_key(|b| b.get("height").and_then(|h| h.as_u64()).unwrap_or(0));
    (StatusCode::OK, Json(blocks))
}

async fn get_transactions(State(_): State<ChainStore>) -> (StatusCode, Json<Vec<Value>>) {
    let db = txs_db();
    let db = db.lock().unwrap();
    let txs: Vec<Value> = db
        .iterator(rocksdb::IteratorMode::Start)
        .filter_map(|r| r.ok())
        .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
        .collect();
    (StatusCode::OK, Json(txs))
}
