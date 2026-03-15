//! Ego Blockchain Event Indexer (EGO-14)
//!
//! Subscribes to the ego-node block stream, extracts contract events from
//! transaction data, stores them in SQLite, and serves a query REST API.
//!
//! Ports
//! -----
//!   ego-node  →  8545  (source)
//!   ego-indexer → 8546 (query API, this binary)
//!
//! Endpoints
//! ---------
//!   GET  /events             → filtered event query (ascending)
//!   GET  /events/latest      → filtered event query (descending, default limit 10)
//!   GET  /status             → { indexed_height, node_url, event_count }
//!   GET  /subscriptions      → list active webhooks
//!   POST /subscriptions      → register webhook
//!   DELETE /subscriptions/:id → remove webhook

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
};
use clap::Parser;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::interval;
use tower_http::cors::CorsLayer;
use tracing::{error, info, warn};

// ── CLI config ────────────────────────────────────────────────────────────────

#[derive(Parser, Debug, Clone)]
#[command(name = "ego-indexer", about = "Ego Blockchain event indexer (EGO-14)")]
struct Config {
    /// ego-node RPC base URL
    #[arg(long, env = "EGO_INDEXER_NODE_URL", default_value = "http://localhost:8545")]
    node_url: String,

    /// Bind address for the query API
    #[arg(long, env = "EGO_INDEXER_LISTEN", default_value = "0.0.0.0:8546")]
    listen: String,

    /// SQLite database file path
    #[arg(long, env = "EGO_INDEXER_DB", default_value = "./ego-indexer.db")]
    db: String,

    /// Block polling interval in milliseconds
    #[arg(long, env = "EGO_INDEXER_POLL_MS", default_value_t = 200)]
    poll_interval_ms: u64,
}

// ── Domain types ──────────────────────────────────────────────────────────────

/// A fully-hydrated event record as stored in SQLite and returned by the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedEvent {
    pub id:               i64,
    pub block_height:     u64,
    pub tx_hash:          String,
    pub contract_address: String,
    pub event_name:       String,
    pub topic0:           Option<String>,
    pub topic1:           Option<String>,
    pub data:             Value,
    pub timestamp:        u64,
}

/// Raw event as embedded in a transaction's `data.events[]` array by a contract.
#[derive(Debug, Deserialize)]
struct RawEvent {
    event_name: String,
    contract:   String,
    #[serde(default)]
    topics:     Vec<String>,
    #[serde(default)]
    data:       Value,
}

/// Minimal block summary returned by GET /chain/blocks.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct BlockSummary {
    height:    u64,
    hash:      String,
    timestamp: u64,
}

/// Minimal transaction as returned by the node (we only need the data field).
#[derive(Debug, Deserialize)]
struct RawTx {
    #[serde(default)]
    hash: String,
    #[serde(default)]
    data: Value,
}

/// Block detail response from GET /block/:height.
#[derive(Debug, Deserialize)]
struct BlockDetail {
    height:    u64,
    timestamp: u64,
    #[serde(default)]
    txs:       Vec<RawTx>,
}

// ── Subscription types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id:         String,
    pub url:        String,
    pub contract:   Option<String>,
    pub event_name: Option<String>,
    pub created_at: u64,
}

#[derive(Debug, Deserialize)]
struct SubscriptionRequest {
    url:        String,
    contract:   Option<String>,
    event_name: Option<String>,
}

// ── Shared application state ──────────────────────────────────────────────────

struct AppState {
    db:            Arc<Mutex<Connection>>,
    node_url:      String,
    subscriptions: Arc<Mutex<HashMap<String, Subscription>>>,
}

// ── Database setup ────────────────────────────────────────────────────────────

fn setup_db(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS events (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            block_height     INTEGER NOT NULL,
            tx_hash          TEXT    NOT NULL,
            contract_address TEXT    NOT NULL,
            event_name       TEXT    NOT NULL,
            topic0           TEXT,
            topic1           TEXT,
            data_json        TEXT    NOT NULL,
            timestamp        INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_contract   ON events(contract_address);
        CREATE INDEX IF NOT EXISTS idx_event_name ON events(event_name);
        CREATE INDEX IF NOT EXISTS idx_block      ON events(block_height);
        CREATE TABLE IF NOT EXISTS indexed_height (
            id     INTEGER PRIMARY KEY CHECK (id = 1),
            height INTEGER NOT NULL DEFAULT 0
        );
        INSERT OR IGNORE INTO indexed_height(id, height) VALUES (1, 0);
        ",
    )
    .context("failed to set up database schema")?;
    Ok(())
}

// ── Helper: current unix timestamp ───────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Indexer loop ──────────────────────────────────────────────────────────────

async fn run_indexer(
    db:            Arc<Mutex<Connection>>,
    node_url:      String,
    poll_ms:       u64,
    subscriptions: Arc<Mutex<HashMap<String, Subscription>>>,
) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("failed to build HTTP client");

    let mut ticker = interval(Duration::from_millis(poll_ms));

    loop {
        ticker.tick().await;

        if let Err(e) = index_once(&client, &db, &node_url, &subscriptions).await {
            warn!("indexer tick error: {e:#}");
        }
    }
}

async fn index_once(
    client:        &reqwest::Client,
    db:            &Arc<Mutex<Connection>>,
    node_url:      &str,
    subscriptions: &Arc<Mutex<HashMap<String, Subscription>>>,
) -> Result<()> {
    // 1. Fetch the current indexed height from SQLite.
    let last_height: u64 = {
        let conn = db.lock().unwrap();
        conn.query_row(
            "SELECT height FROM indexed_height WHERE id = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0) as u64
    };

    // 2. Fetch the recent blocks list from the node.
    let blocks_url = format!("{node_url}/chain/blocks");
    let resp = client
        .get(&blocks_url)
        .send()
        .await
        .context("GET /chain/blocks failed")?;

    if !resp.status().is_success() {
        return Ok(()); // node not ready yet — skip silently
    }

    let blocks: Vec<BlockSummary> = resp
        .json()
        .await
        .context("failed to parse /chain/blocks JSON")?;

    // 3. Find new blocks (height > last_height), sorted ascending.
    let mut new_blocks: Vec<&BlockSummary> = blocks
        .iter()
        .filter(|b| b.height > last_height)
        .collect();
    new_blocks.sort_by_key(|b| b.height);

    if new_blocks.is_empty() {
        return Ok(());
    }

    info!(
        "indexing {} new block(s): heights {}..{}",
        new_blocks.len(),
        new_blocks.first().map(|b| b.height).unwrap_or(0),
        new_blocks.last().map(|b| b.height).unwrap_or(0),
    );

    // 4. For each new block, fetch details and index events.
    for block in new_blocks {
        let events = fetch_and_parse_block(client, node_url, block).await;
        match events {
            Ok(evts) => {
                let count = evts.len();
                if count > 0 {
                    info!("block {} → {} event(s)", block.height, count);
                }
                let fired: Vec<IndexedEvent> = {
                    let conn = db.lock().unwrap();
                    let mut inserted = Vec::new();
                    for evt in evts {
                        match insert_event(&conn, &evt) {
                            Ok(id) => {
                                let mut full = evt.clone();
                                full.id = id;
                                inserted.push(full);
                            }
                            Err(e) => warn!("failed to insert event: {e:#}"),
                        }
                    }
                    // Advance the indexed height.
                    if let Err(e) = conn.execute(
                        "UPDATE indexed_height SET height = ?1 WHERE id = 1",
                        params![block.height as i64],
                    ) {
                        warn!("failed to update indexed_height: {e}");
                    }
                    inserted
                };

                // 5. Fire webhooks for matching subscriptions (non-blocking).
                if !fired.is_empty() {
                    let subs: Vec<Subscription> = {
                        subscriptions
                            .lock()
                            .unwrap()
                            .values()
                            .cloned()
                            .collect()
                    };
                    for evt in fired {
                        for sub in &subs {
                            if subscription_matches(sub, &evt) {
                                let sub_clone = sub.clone();
                                let evt_clone = evt.clone();
                                tokio::spawn(async move {
                                    deliver_webhook(&sub_clone, &evt_clone).await;
                                });
                            }
                        }
                    }
                }
            }
            Err(e) => {
                warn!("failed to process block {}: {e:#}", block.height);
                // Still advance height so we don't retry permanently bad blocks.
                let conn = db.lock().unwrap();
                let _ = conn.execute(
                    "UPDATE indexed_height SET height = ?1 WHERE id = 1",
                    params![block.height as i64],
                );
            }
        }
    }

    Ok(())
}

/// Fetch block details and extract all contract events from transactions.
async fn fetch_and_parse_block(
    client:   &reqwest::Client,
    node_url: &str,
    summary:  &BlockSummary,
) -> Result<Vec<IndexedEvent>> {
    let url = format!("{node_url}/block/{}", summary.height);
    let resp = client
        .get(&url)
        .send()
        .await
        .context("GET /block/{height} failed")?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        // Block not yet available — return empty, will retry next tick.
        return Ok(vec![]);
    }

    let body = resp.text().await.context("failed to read block body")?;

    // The node may return just the BlockSummary (no txs field) for recent blocks.
    // Attempt to parse as BlockDetail; fall back gracefully.
    let detail: BlockDetail = match serde_json::from_str(&body) {
        Ok(d) => d,
        Err(_) => {
            // Possibly the /chain/blocks format — no transaction data available.
            return Ok(vec![]);
        }
    };

    let mut events = Vec::new();

    for tx in &detail.txs {
        // Parse events embedded in tx.data.events (EGO-14 Section 2).
        if let Some(raw_events) = tx.data.get("events").and_then(|v| v.as_array()) {
            for raw in raw_events {
                match serde_json::from_value::<RawEvent>(raw.clone()) {
                    Ok(re) => {
                        let topic0 = re.topics.first().cloned();
                        let topic1 = re.topics.get(1).cloned();
                        events.push(IndexedEvent {
                            id:               0, // filled after INSERT
                            block_height:     detail.height,
                            tx_hash:          tx.hash.clone(),
                            contract_address: re.contract,
                            event_name:       re.event_name,
                            topic0,
                            topic1,
                            data:             re.data,
                            timestamp:        detail.timestamp,
                        });
                    }
                    Err(e) => {
                        warn!("malformed event in tx {}: {e}", tx.hash);
                    }
                }
            }
        }
    }

    Ok(events)
}

fn insert_event(conn: &Connection, evt: &IndexedEvent) -> Result<i64> {
    conn.execute(
        "INSERT INTO events
            (block_height, tx_hash, contract_address, event_name, topic0, topic1, data_json, timestamp)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            evt.block_height as i64,
            evt.tx_hash,
            evt.contract_address,
            evt.event_name,
            evt.topic0,
            evt.topic1,
            serde_json::to_string(&evt.data).unwrap_or_else(|_| "{}".to_string()),
            evt.timestamp as i64,
        ],
    )
    .context("INSERT event failed")?;
    Ok(conn.last_insert_rowid())
}

// ── Webhook delivery ──────────────────────────────────────────────────────────

fn subscription_matches(sub: &Subscription, evt: &IndexedEvent) -> bool {
    if let Some(ref c) = sub.contract {
        if *c != evt.contract_address {
            return false;
        }
    }
    if let Some(ref en) = sub.event_name {
        if *en != evt.event_name {
            return false;
        }
    }
    true
}

async fn deliver_webhook(sub: &Subscription, evt: &IndexedEvent) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            error!("webhook client build failed: {e}");
            return;
        }
    };

    let payload = match serde_json::to_string(evt) {
        Ok(p) => p,
        Err(e) => {
            error!("failed to serialise event for webhook: {e}");
            return;
        }
    };

    let delays = [1u64, 2, 4]; // seconds — exponential backoff (3 retries)
    for (attempt, &delay_secs) in delays.iter().enumerate() {
        match client
            .post(&sub.url)
            .header("Content-Type", "application/json")
            .header("X-Ego-Event", &evt.event_name)
            .body(payload.clone())
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                return; // delivered
            }
            Ok(resp) => {
                warn!(
                    "webhook {} attempt {}/{} → HTTP {}; retrying in {}s",
                    sub.url, attempt + 1, delays.len(), resp.status(), delay_secs,
                );
            }
            Err(e) => {
                warn!(
                    "webhook {} attempt {}/{} → error: {e}; retrying in {}s",
                    sub.url, attempt + 1, delays.len(), delay_secs,
                );
            }
        }
        tokio::time::sleep(Duration::from_secs(delay_secs)).await;
    }

    warn!("webhook {} failed after 3 attempts; dropping delivery for event {}", sub.url, evt.event_name);
}

// ── Query API handlers ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct EventQuery {
    contract:   Option<String>,
    event:      Option<String>,
    from_block: Option<u64>,
    to_block:   Option<u64>,
    limit:      Option<u64>,
    offset:     Option<u64>,
}

/// Build a list of rows from a prepared statement with dynamic WHERE clauses.
/// Returns events ordered by block_height ASC, id ASC.
async fn query_events(
    State(state): State<Arc<AppState>>,
    Query(params): Query<EventQuery>,
) -> impl IntoResponse {
    let limit  = params.limit.unwrap_or(100).min(1000);
    let offset = params.offset.unwrap_or(0);

    match query_events_inner(&state.db, &params, limit, offset, false) {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        ).into_response(),
    }
}

/// Same as query_events but ordered DESC (latest first). Default limit 10.
async fn query_latest_events(
    State(state): State<Arc<AppState>>,
    Query(mut params): Query<EventQuery>,
) -> impl IntoResponse {
    params.limit = Some(params.limit.unwrap_or(10).min(1000));
    let limit  = params.limit.unwrap();
    let offset = params.offset.unwrap_or(0);

    match query_events_inner(&state.db, &params, limit, offset, true) {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        ).into_response(),
    }
}

fn query_events_inner(
    db:         &Arc<Mutex<Connection>>,
    params:     &EventQuery,
    limit:      u64,
    offset:     u64,
    descending: bool,
) -> Result<Vec<IndexedEvent>> {
    let conn = db.lock().unwrap();

    // Build WHERE clauses and positional parameter list dynamically.
    let mut conditions: Vec<String> = Vec::new();
    let mut values: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

    if let Some(ref c) = params.contract {
        conditions.push(format!("contract_address = ?{}", values.len() + 1));
        values.push(Box::new(c.clone()));
    }
    if let Some(ref e) = params.event {
        conditions.push(format!("event_name = ?{}", values.len() + 1));
        values.push(Box::new(e.clone()));
    }
    if let Some(fb) = params.from_block {
        conditions.push(format!("block_height >= ?{}", values.len() + 1));
        values.push(Box::new(fb as i64));
    }
    if let Some(tb) = params.to_block {
        conditions.push(format!("block_height <= ?{}", values.len() + 1));
        values.push(Box::new(tb as i64));
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let order = if descending {
        "ORDER BY block_height DESC, id DESC"
    } else {
        "ORDER BY block_height ASC, id ASC"
    };

    let limit_idx  = values.len() + 1;
    let offset_idx = values.len() + 2;

    let sql = format!(
        "SELECT id, block_height, tx_hash, contract_address, event_name,
                topic0, topic1, data_json, timestamp
         FROM events
         {where_clause}
         {order}
         LIMIT ?{limit_idx} OFFSET ?{offset_idx}",
    );

    values.push(Box::new(limit as i64));
    values.push(Box::new(offset as i64));

    let refs: Vec<&dyn rusqlite::ToSql> = values.iter().map(|v| v.as_ref()).collect();

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(refs.as_slice(), |row| {
        let data_json: String = row.get(7)?;
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, Option<String>>(6)?,
            data_json,
            row.get::<_, i64>(8)?,
        ))
    })?;

    let mut events = Vec::new();
    for row in rows {
        let (id, block_height, tx_hash, contract_address, event_name,
             topic0, topic1, data_json, timestamp) = row?;

        let data: Value = serde_json::from_str(&data_json).unwrap_or(Value::Object(Default::default()));
        events.push(IndexedEvent {
            id,
            block_height: block_height as u64,
            tx_hash,
            contract_address,
            event_name,
            topic0,
            topic1,
            data,
            timestamp: timestamp as u64,
        });
    }

    Ok(events)
}

async fn indexer_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let conn = state.db.lock().unwrap();

    let height: i64 = conn
        .query_row("SELECT height FROM indexed_height WHERE id = 1", [], |r| r.get(0))
        .unwrap_or(0);

    let event_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
        .unwrap_or(0);

    Json(serde_json::json!({
        "indexed_height": height,
        "node_url":       &state.node_url,
        "event_count":    event_count,
    }))
}

// ── Subscription handlers ─────────────────────────────────────────────────────

async fn list_subscriptions(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let subs: Vec<Subscription> = state
        .subscriptions
        .lock()
        .unwrap()
        .values()
        .cloned()
        .collect();
    Json(subs)
}

async fn create_subscription(
    State(state): State<Arc<AppState>>,
    Json(body):   Json<SubscriptionRequest>,
) -> impl IntoResponse {
    if body.url.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "url is required" })),
        ).into_response();
    }

    let sub = Subscription {
        id:         format!("sub_{}", uuid::Uuid::new_v4().simple()),
        url:        body.url,
        contract:   body.contract,
        event_name: body.event_name,
        created_at: unix_now(),
    };

    state
        .subscriptions
        .lock()
        .unwrap()
        .insert(sub.id.clone(), sub.clone());

    info!("registered webhook subscription {} → {}", sub.id, sub.url);
    (StatusCode::CREATED, Json(sub)).into_response()
}

async fn remove_subscription(
    Path(id):     Path<String>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let removed = state.subscriptions.lock().unwrap().remove(&id).is_some();
    if removed {
        info!("removed webhook subscription {id}");
        StatusCode::NO_CONTENT.into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "subscription not found" })),
        ).into_response()
    }
}

// ── Router ────────────────────────────────────────────────────────────────────

fn make_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/events",              get(query_events))
        .route("/events/latest",       get(query_latest_events))
        .route("/status",              get(indexer_status))
        .route("/subscriptions",       get(list_subscriptions))
        .route("/subscriptions",       post(create_subscription))
        .route("/subscriptions/:id",   delete(remove_subscription))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    let cfg = Config::parse();

    info!("ego-indexer starting");
    info!("  node URL       : {}", cfg.node_url);
    info!("  listen         : {}", cfg.listen);
    info!("  db path        : {}", cfg.db);
    info!("  poll interval  : {}ms", cfg.poll_interval_ms);

    // Open and initialise the SQLite database.
    let conn = Connection::open(&cfg.db)
        .with_context(|| format!("failed to open database at {}", cfg.db))?;
    setup_db(&conn).context("database setup failed")?;

    let db = Arc::new(Mutex::new(conn));
    let subscriptions: Arc<Mutex<HashMap<String, Subscription>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let state = Arc::new(AppState {
        db:            Arc::clone(&db),
        node_url:      cfg.node_url.clone(),
        subscriptions: Arc::clone(&subscriptions),
    });

    // Spawn the background indexer loop.
    let indexer_db   = Arc::clone(&db);
    let indexer_node = cfg.node_url.clone();
    let indexer_subs = Arc::clone(&subscriptions);
    let poll_ms      = cfg.poll_interval_ms;

    tokio::spawn(async move {
        run_indexer(indexer_db, indexer_node, poll_ms, indexer_subs).await;
    });

    // Start the HTTP API server.
    let router   = make_router(state);
    let listener = tokio::net::TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("failed to bind to {}", cfg.listen))?;

    info!("ego-indexer query API listening on http://{}", cfg.listen);
    axum::serve(listener, router)
        .await
        .context("axum server error")?;

    Ok(())
}
