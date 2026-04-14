use axum::{
    extract::State,
    http::StatusCode,
    Json, Router,
    routing::{get, post},
};
use rocksdb::{Options, DB};
use serde_json::Value;
use std::sync::{Arc, Mutex};

const CF_BLOCKS: &str = "blocks";
const CF_TXS:   &str  = "txs";

pub struct ChainStore {
    blocks_db: Arc<Mutex<DB>>,
    txs_db:    Arc<Mutex<DB>>,
}

impl Clone for ChainStore {
    fn clone(&self) -> Self {
        ChainStore { blocks_db: self.blocks_db.clone(), txs_db: self.txs_db.clone() }
    }
}

pub fn new_chain_store() -> ChainStore {
    let mut opts = Options::default();
    opts.create_if_missing(true);
    let blocks_db = DB::open(&opts, "chain_blocks.db").expect("open chain_blocks.db");
    let txs_db    = DB::open(&opts, "chain_txs.db").expect("open chain_txs.db");
    ChainStore {
        blocks_db: Arc::new(Mutex::new(blocks_db)),
        txs_db:    Arc::new(Mutex::new(txs_db)),
    }
}

pub fn chain_router(store: ChainStore) -> Router {
    Router::new()
        .route("/block/broadcast",      post(post_block))
        .route("/tx/broadcast",         post(post_tx))
        .route("/chain/blocks",         get(get_blocks))
        .route("/chain/transactions",   get(get_transactions))
        .with_state(store)
}

async fn post_block(
    State(store): State<ChainStore>,
    Json(block): Json<Value>,
) -> StatusCode {
    let height = block.get("height").and_then(|h| h.as_u64()).unwrap_or(u64::MAX);
    let key = height.to_be_bytes();
    let val = serde_json::to_vec(&block).unwrap_or_default();
    let _ = store.blocks_db.lock().unwrap().put(key, val);
    StatusCode::OK
}

async fn post_tx(
    State(store): State<ChainStore>,
    Json(tx): Json<Value>,
) -> StatusCode {
    let hash = tx.get("hash").and_then(|h| h.as_str()).unwrap_or("").to_string();
    if hash.is_empty() { return StatusCode::BAD_REQUEST; }
    let val = serde_json::to_vec(&tx).unwrap_or_default();
    let _ = store.txs_db.lock().unwrap().put(hash.as_bytes(), val);
    StatusCode::OK
}

async fn get_blocks(State(store): State<ChainStore>) -> (StatusCode, Json<Vec<Value>>) {
    let db = store.blocks_db.lock().unwrap();
    let mut blocks: Vec<Value> = db
        .iterator(rocksdb::IteratorMode::Start)
        .filter_map(|r| r.ok())
        .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
        .collect();
    blocks.sort_by_key(|b| b.get("height").and_then(|h| h.as_u64()).unwrap_or(0));
    (StatusCode::OK, Json(blocks))
}

async fn get_transactions(State(store): State<ChainStore>) -> (StatusCode, Json<Vec<Value>>) {
    let db = store.txs_db.lock().unwrap();
    let txs: Vec<Value> = db
        .iterator(rocksdb::IteratorMode::Start)
        .filter_map(|r| r.ok())
        .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
        .collect();
    (StatusCode::OK, Json(txs))
}
