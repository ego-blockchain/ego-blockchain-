/// Real-time on-chain alert system.
///
/// Ego nodes POST confirmed transactions to `/tx/broadcast` after each block.
/// This module analyses the stream for anomalies and writes alerts to RocksDB.
///
/// Alert conditions:
///   large_transfer  — single tx amount > LARGE_TX_THRESHOLD
///   rapid_drain     — same sender sends ≥ RAPID_DRAIN_COUNT txs within
///                     RAPID_DRAIN_WINDOW_SECS, total > RAPID_DRAIN_TOTAL
///   new_addr_spend  — address with no prior activity spends > NEW_ADDR_THRESHOLD
///   block_spike     — a single block contains > BLOCK_SPIKE_TX_COUNT txs
///
/// GET /alerts          → last 200 alerts, newest first
/// GET /alerts?since=ts → alerts with triggered_at > ts (Unix seconds)
/// POST /tx/broadcast   → submit a confirmed transaction (from any node)
/// POST /block/alert    → submit a whole block for spike detection

use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use rocksdb::{Options, DB};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

// ── Thresholds (in uEGOC — 1 EGOC = 1_000_000 uEGOC) ────────────────────────

/// Single transfer above this triggers large_transfer alert: 10,000 EGOC
const LARGE_TX_THRESHOLD: u64 = 10_000 * 1_000_000;

/// New address (zero prior sends in our window) spending above this: 5,000 EGOC
const NEW_ADDR_THRESHOLD: u64 = 5_000 * 1_000_000;

/// Rapid-drain: min number of sends from same address within the window
const RAPID_DRAIN_COUNT: usize = 3;

/// Rapid-drain: time window in seconds
const RAPID_DRAIN_WINDOW_SECS: u64 = 60;

/// Rapid-drain: combined total above this: 50,000 EGOC
const RAPID_DRAIN_TOTAL: u64 = 50_000 * 1_000_000;

/// Block spike: tx count above this triggers an alert
const BLOCK_SPIKE_TX_COUNT: u32 = 200;

/// How long to keep alerts and tx records in RocksDB
const ALERT_TTL_SECS: u64 = 7 * 24 * 3600;

/// How many recent txs per address we track for rapid-drain detection
const ADDR_WINDOW_SIZE: usize = 20;

// ── Data types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundTx {
    pub hash:       String,
    pub from:       String,
    pub to:         String,
    pub amount:     u64,
    pub tx_type:    String,
    pub timestamp:  i64,
    #[serde(default)]
    pub block_height: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundBlock {
    pub height:   u64,
    pub hash:     String,
    pub tx_count: u32,
    pub timestamp: i64,
    pub miner:    String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    LargeTransfer,
    RapidDrain,
    NewAddrLargeSpend,
    BlockSpike,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id:           String,
    pub kind:         AlertKind,
    pub triggered_at: u64,
    pub address:      String,
    pub amount_uegoc: u64,
    pub detail:       String,
    pub tx_hash:      Option<String>,
    pub block_height: Option<u64>,
}

// ── In-memory address window for rapid-drain detection ───────────────────────

#[derive(Default)]
struct AddrWindow {
    /// (timestamp_secs, amount_uegoc) for recent sends
    sends: Vec<(u64, u64)>,
}

impl AddrWindow {
    fn add(&mut self, ts: u64, amount: u64) {
        self.sends.push((ts, amount));
        if self.sends.len() > ADDR_WINDOW_SIZE {
            self.sends.remove(0);
        }
    }

    /// Count of sends and total amount within the last RAPID_DRAIN_WINDOW_SECS.
    fn window_stats(&self, now: u64) -> (usize, u64) {
        let cutoff = now.saturating_sub(RAPID_DRAIN_WINDOW_SECS);
        let recent: Vec<_> = self.sends.iter().filter(|(ts, _)| *ts >= cutoff).collect();
        let total: u64 = recent.iter().map(|(_, a)| a).sum();
        (recent.len(), total)
    }

    /// True if this address has any sends recorded (used for new-addr detection).
    fn is_new(&self) -> bool {
        self.sends.is_empty()
    }
}

// ── Store ─────────────────────────────────────────────────────────────────────

pub struct AlertStore {
    db:           Arc<DB>,
    /// In-memory per-address send history for rapid-drain / new-addr detection.
    addr_windows: Mutex<HashMap<String, AddrWindow>>,
    /// Already-seen tx hashes to avoid duplicate processing.
    seen_hashes:  Mutex<std::collections::HashSet<String>>,
}

impl Clone for AlertStore {
    fn clone(&self) -> Self {
        AlertStore {
            db:           self.db.clone(),
            addr_windows: Mutex::new(HashMap::new()),
            seen_hashes:  Mutex::new(std::collections::HashSet::new()),
        }
    }
}

pub fn new_alert_store() -> AlertStore {
    let mut opts = Options::default();
    opts.create_if_missing(true);
    let db = DB::open_with_ttl(&opts, "alerts.db", Duration::from_secs(ALERT_TTL_SECS))
        .expect("Failed to open alerts RocksDB");
    AlertStore {
        db:           Arc::new(db),
        addr_windows: Mutex::new(HashMap::new()),
        seen_hashes:  Mutex::new(std::collections::HashSet::new()),
    }
}

// ── Alert persistence ─────────────────────────────────────────────────────────

fn alert_key(triggered_at: u64, id: &str) -> Vec<u8> {
    // Big-endian timestamp prefix so RocksDB iteration is chronological.
    let mut k = triggered_at.to_be_bytes().to_vec();
    k.extend_from_slice(b":");
    k.extend_from_slice(id.as_bytes());
    k
}

fn save_alert(db: &DB, alert: &Alert) {
    if let Ok(bytes) = serde_json::to_vec(alert) {
        let key = alert_key(alert.triggered_at, &alert.id);
        let _ = db.put(key, bytes);
    }
}

fn load_alerts(db: &DB, since: u64, limit: usize) -> Vec<Alert> {
    let mut alerts: Vec<Alert> = db
        .iterator(rocksdb::IteratorMode::End)
        .filter_map(|r| {
            let (_, v) = r.ok()?;
            let a: Alert = serde_json::from_slice(&v).ok()?;
            if a.triggered_at >= since { Some(a) } else { None }
        })
        .take(limit)
        .collect();
    alerts.sort_by(|a, b| b.triggered_at.cmp(&a.triggered_at));
    alerts
}

// ── Core detection logic ──────────────────────────────────────────────────────

impl AlertStore {
    pub fn process_tx(&self, tx: &InboundTx) {
        // Skip system/reward transactions — only user-initiated transfers matter.
        let skip_types = ["reward", "coinbase", "faucet"];
        if skip_types.iter().any(|t| tx.tx_type.contains(t)) { return; }
        if tx.from.is_empty() || tx.from.starts_with("egot1node") || tx.from.starts_with("egot1fau") { return; }

        // Dedup.
        {
            let mut seen = self.seen_hashes.lock().unwrap();
            if !seen.insert(tx.hash.clone()) { return; }
            if seen.len() > 50_000 { seen.clear(); } // prevent unbounded growth
        }

        let now = now_secs();
        let mut new_alerts: Vec<Alert> = Vec::new();

        {
            let mut windows = self.addr_windows.lock().unwrap();
            let window = windows.entry(tx.from.clone()).or_default();

            // ── New-address large spend ───────────────────────────────────────
            if window.is_new() && tx.amount > NEW_ADDR_THRESHOLD {
                new_alerts.push(Alert {
                    id:           blake3_id(&format!("new_addr:{}:{}", tx.from, tx.hash)),
                    kind:         AlertKind::NewAddrLargeSpend,
                    triggered_at: now,
                    address:      tx.from.clone(),
                    amount_uegoc: tx.amount,
                    detail:       format!(
                        "New address spent {:.2} EGOC in first observed transaction",
                        tx.amount as f64 / 1_000_000.0
                    ),
                    tx_hash:      Some(tx.hash.clone()),
                    block_height: tx.block_height,
                });
            }

            // ── Large single transfer ─────────────────────────────────────────
            if tx.amount > LARGE_TX_THRESHOLD {
                new_alerts.push(Alert {
                    id:           blake3_id(&format!("large:{}:{}", tx.from, tx.hash)),
                    kind:         AlertKind::LargeTransfer,
                    triggered_at: now,
                    address:      tx.from.clone(),
                    amount_uegoc: tx.amount,
                    detail:       format!(
                        "{:.2} EGOC transferred from {} → {}",
                        tx.amount as f64 / 1_000_000.0,
                        short(&tx.from), short(&tx.to)
                    ),
                    tx_hash:      Some(tx.hash.clone()),
                    block_height: tx.block_height,
                });
            }

            // Record this send for rapid-drain window.
            window.add(now, tx.amount);

            // ── Rapid drain ───────────────────────────────────────────────────
            let (count, total) = window.window_stats(now);
            if count >= RAPID_DRAIN_COUNT && total > RAPID_DRAIN_TOTAL {
                let drain_id = blake3_id(&format!("drain:{}:{}", tx.from, now / 30)); // deduplicate per 30-second bucket
                new_alerts.push(Alert {
                    id:           drain_id,
                    kind:         AlertKind::RapidDrain,
                    triggered_at: now,
                    address:      tx.from.clone(),
                    amount_uegoc: total,
                    detail:       format!(
                        "{} sends totalling {:.2} EGOC from {} within {}s",
                        count, total as f64 / 1_000_000.0,
                        short(&tx.from), RAPID_DRAIN_WINDOW_SECS
                    ),
                    tx_hash:      Some(tx.hash.clone()),
                    block_height: tx.block_height,
                });
            }
        }

        for alert in &new_alerts {
            eprintln!("[Alert] {:?} — {}", alert.kind, alert.detail);
            save_alert(&self.db, alert);
        }
    }

    pub fn process_block(&self, block: &InboundBlock) {
        if block.tx_count <= BLOCK_SPIKE_TX_COUNT { return; }
        let now = now_secs();
        let alert = Alert {
            id:           blake3_id(&format!("spike:{}:{}", block.height, block.hash)),
            kind:         AlertKind::BlockSpike,
            triggered_at: now,
            address:      block.miner.clone(),
            amount_uegoc: 0,
            detail:       format!(
                "Block #{} contains {} transactions (threshold: {})",
                block.height, block.tx_count, BLOCK_SPIKE_TX_COUNT
            ),
            tx_hash:      None,
            block_height: Some(block.height),
        };
        eprintln!("[Alert] BlockSpike — {}", alert.detail);
        save_alert(&self.db, &alert);
    }
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AlertsQuery {
    pub since: Option<u64>,
    pub limit: Option<usize>,
}

async fn handle_tx_broadcast(
    State(store): State<AlertStore>,
    Json(tx):     Json<serde_json::Value>,
) -> StatusCode {
    if let Ok(inbound) = serde_json::from_value::<InboundTx>(tx.clone()) {
        store.process_tx(&inbound);
    }
    crate::chain::store_tx(&tx);
    StatusCode::OK
}

async fn handle_block_alert(
    State(store):  State<AlertStore>,
    Json(block):   Json<InboundBlock>,
) -> StatusCode {
    store.process_block(&block);
    StatusCode::OK
}

async fn handle_get_alerts(
    State(store):  State<AlertStore>,
    Query(params): Query<AlertsQuery>,
) -> Json<Vec<Alert>> {
    let since = params.since.unwrap_or(0);
    let limit = params.limit.unwrap_or(200).min(500);
    Json(load_alerts(&store.db, since, limit))
}

pub fn alert_router(store: AlertStore) -> Router {
    Router::new()
        .route("/tx/broadcast",  post(handle_tx_broadcast))
        .route("/block/alert",   post(handle_block_alert))
        .route("/alerts",        get(handle_get_alerts))
        .with_state(store)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn blake3_id(input: &str) -> String {
    blake3::hash(input.as_bytes()).to_hex()[..16].to_string()
}

fn short(addr: &str) -> String {
    if addr.len() > 16 {
        format!("{}…{}", &addr[..10], &addr[addr.len()-4..])
    } else {
        addr.to_string()
    }
}
