//! Ego Relay Server — libp2p circuit relay v2 + HTTP chain/peer API.
//!
//! HTTP endpoints:
//!   GET  /chain                   — full global blockchain
//!   POST /chain/tx                — submit a confirmed transaction
//!   POST /chain/block             — submit a mined block
//!   GET  /peers                   — list all known peer endpoints
//!   POST /peers                   — register/update your relay circuit address
//!   POST /inbox/:address          — store a message for an offline peer
//!   GET  /inbox/:address          — fetch and clear pending messages (called on startup)
//!   GET  /health                  — liveness probe
//!   POST /users/register          — register name + email, send verification email
//!   GET  /users/verify/:token     — verify email (browser link)
//!   GET  /users/:address          — get registration/verification status
//!   POST /users/reset-pin         — send PIN reset email
//!   POST /tx/pending              — hold a tx, send email confirmation to user
//!   GET  /tx/confirm/:token       — user clicks → tx executes
//!   GET  /tx/cancel/:token        — user clicks → tx cancelled
//!   GET  /tx/status/:token        — desktop polls for confirmation status
//!   POST /poc/event               — submit signed Proof of Coverage beacon event
//!   GET  /poc/score/:address      — DRS score + validator rank for an address
//!   GET  /poc/validators          — ranked list of active PoC validators

use axum::{
    extract::{Path, State},
    http::{HeaderValue, Method, StatusCode},
    routing::{get, post},
    Json, Router,
};
use ed25519_dalek::{Verifier, VerifyingKey};
use tower_http::cors::{Any, CorsLayer};
use futures::StreamExt;
use lettre::{
    message::header::ContentType,
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use libp2p::{
    gossipsub, identify, kad, noise, ping, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, SwarmBuilder,
};
use std::sync::OnceLock;
use tokio::sync::mpsc as tokio_mpsc;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    sync::{Arc, RwLock},
    time::Duration,
};
use uuid::Uuid;

// ── SMTP config (loaded from .env / environment) ──────────────────────────────

#[derive(Clone)]
struct Config {
    smtp_host:     String,
    smtp_port:     u16,
    smtp_user:     String,
    smtp_pass:     String,
    smtp_from:     String,
    support_email: String,
    base_url:      String,
}

impl Config {
    fn from_env() -> Self {
        Self {
            smtp_host:     std::env::var("SMTP_HOST").expect("SMTP_HOST not set"),
            smtp_port:     std::env::var("SMTP_PORT").ok()
                               .and_then(|p| p.parse().ok()).unwrap_or(465),
            smtp_user:     std::env::var("SMTP_USER").expect("SMTP_USER not set"),
            smtp_pass:     std::env::var("SMTP_PASS").expect("SMTP_PASS not set"),
            smtp_from:     std::env::var("SMTP_FROM").expect("SMTP_FROM not set"),
            support_email: std::env::var("SUPPORT_EMAIL").expect("SUPPORT_EMAIL not set"),
            base_url:      std::env::var("BASE_URL").expect("BASE_URL not set"),
        }
    }
}

// ── Chain data model ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SharedChain {
    blocks:       Vec<LedgerBlock>,
    transactions: Vec<LedgerTx>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerBlock {
    height:     u64,
    hash:       String,
    prev_hash:  String,
    timestamp:  i64,
    miner:      String,
    tx_count:   u32,
    size_bytes: u64,
    reward:     u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerTx {
    hash:         String,
    from:         String,
    to:           String,
    amount:       u64,
    memo:         Option<String>,
    timestamp:    i64,
    signature:    String,
    status:       String,
    block_height: Option<u64>,
    #[serde(default)]
    nonce: u64,
    /// Hex-encoded Ed25519 public key — required for relay-side signature verification.
    #[serde(default)]
    public_key_ed25519: String,
}

impl SharedChain {
    /// Recalculate balance for an address from confirmed transactions only.
    fn balance_of(&self, address: &str) -> u64 {
        let incoming: u64 = self.transactions.iter()
            .filter(|t| t.to == address && t.status == "Confirmed")
            .map(|t| t.amount).sum();
        let outgoing: u64 = self.transactions.iter()
            .filter(|t| t.from == address && t.status == "Confirmed")
            .map(|t| t.amount).sum();
        incoming.saturating_sub(outgoing)
    }

    /// Highest confirmed nonce for an address (0 if none).
    fn last_nonce(&self, address: &str) -> u64 {
        self.transactions.iter()
            .filter(|t| t.from == address && t.status == "Confirmed")
            .map(|t| t.nonce)
            .max()
            .unwrap_or(0)
    }
}

// ── Proof of Coverage (PoC) data model ───────────────────────────────────────

const POC_EVENTS_PATH: &str = "poc_events.json";
/// Minimum number of validators with PoC scores before the block gate activates.
/// Below this threshold the network is in bootstrap mode and any miner is accepted.
const POC_BOOTSTRAP_THRESHOLD: usize = 3;
/// Maximum one PoC event per address per 10 minutes (prevents spam).
const POC_RATE_LIMIT_SECS: i64 = 600;

fn quality_score(q: &str) -> u32 {
    match q { "Excellent" => 4, "Good" => 3, "Fair" => 2, "Poor" => 1, _ => 0 }
}

fn poc_reward_uegoc(q: &str) -> u64 {
    match q { "Excellent" => 22_222, "Good" => 16_666, "Fair" => 11_111, "Poor" => 5_555, _ => 0 }
}

/// Canonical bytes that must be signed for a PoC event (matches desktop).
fn poc_signing_bytes(address: &str, quality: &str, peers: u32, h3_cell: &str, timestamp: i64) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"ego/poc/v1:");
    v.extend_from_slice(address.as_bytes());
    v.extend_from_slice(b":");
    v.extend_from_slice(quality.as_bytes());
    v.extend_from_slice(b":");
    v.extend_from_slice(&peers.to_le_bytes());
    v.extend_from_slice(b":");
    v.extend_from_slice(h3_cell.as_bytes());
    v.extend_from_slice(b":");
    v.extend_from_slice(&timestamp.to_le_bytes());
    v
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PocEventRecord {
    id:           String,
    address:      String,
    quality:      String,
    peers:        u32,
    h3_cell:      Option<String>,
    timestamp:    i64,
    signature:    String,
    public_key:   String,
    reward_uegoc: u64,
    accepted_at:  i64,
}

fn load_poc_events() -> Vec<PocEventRecord> {
    fs::read_to_string(POC_EVENTS_PATH)
        .ok()
        .and_then(|d| serde_json::from_str(&d).ok())
        .unwrap_or_default()
}

fn save_poc_events(events: &[PocEventRecord]) {
    if let Ok(data) = serde_json::to_string_pretty(events) {
        let _ = fs::write(POC_EVENTS_PATH, data);
    }
}

/// DRS score = Σ quality_pts(last 24h) × ln(1 + count_24h)
/// Inspired by whitepaper DRS formula; simplified for testnet with PoC as primary signal.
fn compute_drs_score(events: &[PocEventRecord], address: &str) -> f64 {
    let cutoff = chrono::Utc::now().timestamp() - 86_400;
    let recent: Vec<_> = events.iter()
        .filter(|e| e.address == address && e.timestamp >= cutoff)
        .collect();
    if recent.is_empty() { return 0.0; }
    let total_pts: u32 = recent.iter().map(|e| quality_score(&e.quality)).sum();
    total_pts as f64 * (1.0_f64 + recent.len() as f64).ln()
}

type PocState = Arc<RwLock<Vec<PocEventRecord>>>;

/// Sender for gossip publishes pushed from HTTP handlers into the swarm loop.
/// Holds (topic_string, message_bytes).
static RELAY_GOSSIP_TX: OnceLock<tokio_mpsc::UnboundedSender<(String, Vec<u8>)>> =
    OnceLock::new();

// ── Persistent chain storage ──────────────────────────────────────────────────

const CHAIN_PATH: &str = "chain.json";

fn load_chain() -> SharedChain {
    if let Ok(data) = fs::read_to_string(CHAIN_PATH) {
        if let Ok(c) = serde_json::from_str::<SharedChain>(&data) {
            return c;
        }
    }
    SharedChain::default()
}

fn save_chain(chain: &SharedChain) {
    if let Ok(data) = serde_json::to_string_pretty(chain) {
        let _ = fs::write(CHAIN_PATH, data);
    }
}

/// Canonical bytes that were signed by the sender — must match desktop exactly.
fn tx_signing_bytes(from: &str, to: &str, amount: u64, nonce: u64, timestamp: i64) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"ego/tx/v1:");
    v.extend_from_slice(from.as_bytes());
    v.extend_from_slice(b":");
    v.extend_from_slice(to.as_bytes());
    v.extend_from_slice(b":");
    v.extend_from_slice(&amount.to_le_bytes());
    v.extend_from_slice(b":");
    v.extend_from_slice(&nonce.to_le_bytes());
    v.extend_from_slice(b":");
    v.extend_from_slice(&timestamp.to_le_bytes());
    v
}

// ── Peer directory ────────────────────────────────────────────────────────────

const PEERS_PATH: &str = "peers.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PeerEntry {
    address:   String,
    name:      String,
    endpoint:  String,
    last_seen: i64,
    #[serde(default)]
    city:    Option<String>,
    #[serde(default)]
    country: Option<String>,
    /// True when this desktop peer is also running as a relay server.
    /// Returned in GET /peers so other nodes can use it as a hop.
    #[serde(default)]
    is_relay: bool,
}

fn load_peers() -> Vec<PeerEntry> {
    if let Ok(data) = fs::read_to_string(PEERS_PATH) {
        if let Ok(p) = serde_json::from_str::<Vec<PeerEntry>>(&data) {
            return p;
        }
    }
    Vec::new()
}

fn save_peers(peers: &[PeerEntry]) {
    if let Ok(data) = serde_json::to_string_pretty(peers) {
        let _ = fs::write(PEERS_PATH, data);
    }
}

// ── Inbox (store-and-forward) ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InboxMessage {
    payload:   String,   // empty string if stored on disk
    deposited: i64,
    from_addr: String,
    #[serde(default)]
    disk_path: Option<String>,  // set if payload is on disk
}

// ── User registration ─────────────────────────────────────────────────────────

const USERS_PATH: &str = "users.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserRecord {
    address:          String,
    name:             String,
    email:            String,
    email_verified:   bool,
    verify_token:     Option<String>,
    pin_reset_token:  Option<String>,
    pin_reset_expiry: Option<i64>,
    registered_at:    i64,
    #[serde(default)]
    pending_email:       Option<String>,
    #[serde(default)]
    email_change_token:  Option<String>,
}

fn load_users() -> Vec<UserRecord> {
    fs::read_to_string(USERS_PATH)
        .ok()
        .and_then(|d| serde_json::from_str(&d).ok())
        .unwrap_or_default()
}

fn save_users(users: &[UserRecord]) {
    if let Ok(data) = serde_json::to_string_pretty(users) {
        let _ = fs::write(USERS_PATH, data);
    }
}

// ── Pending transactions ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingTx {
    token:      String,
    address:    String,
    email:      String,
    tx_json:    String,
    block_json: String,
    created_at: i64,
    tx_type:    String,
    amount:     u64,
    to:         String,
}

// ── Shared HTTP state ─────────────────────────────────────────────────────────

type ChainState   = Arc<RwLock<SharedChain>>;
type PeersState   = Arc<RwLock<Vec<PeerEntry>>>;
type InboxState   = Arc<RwLock<HashMap<String, Vec<InboxMessage>>>>;
type UsersState   = Arc<RwLock<Vec<UserRecord>>>;
type PendingState = Arc<RwLock<Vec<PendingTx>>>;

#[derive(Clone)]
struct AppState {
    chain:      ChainState,
    peers:      PeersState,
    inbox:      InboxState,
    users:      UsersState,
    pending:    PendingState,
    poc_events: PocState,
    mailer:     Arc<AsyncSmtpTransport<Tokio1Executor>>,
    config:     Arc<Config>,
}

// ── Email helpers ─────────────────────────────────────────────────────────────

async fn send_email(
    mailer:  &AsyncSmtpTransport<Tokio1Executor>,
    from:    &str,
    to:      &str,
    subject: &str,
    body:    String,
) {
    let msg = match Message::builder()
        .from(from.parse().unwrap())
        .to(match to.parse() { Ok(m) => m, Err(_) => return })
        .subject(subject)
        .header(ContentType::TEXT_HTML)
        .body(body)
    {
        Ok(m)  => m,
        Err(e) => { eprintln!("[email] build error: {}", e); return; }
    };
    match mailer.send(msg).await {
        Ok(_)  => println!("[email] Sent to {}", to),
        Err(e) => eprintln!("[email] Send error to {}: {}", to, e),
    }
}

fn email_html(title: &str, body: &str) -> String {
    format!(r#"<!DOCTYPE html><html><head><meta charset="utf-8">
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:0}}
.wrap{{max-width:560px;margin:40px auto;background:#1e293b;border-radius:16px;overflow:hidden;border:1px solid #334155}}
.hdr{{background:linear-gradient(135deg,#3b82f6,#8b5cf6);padding:32px;text-align:center}}
.logo{{width:56px;height:56px;background:rgba(255,255,255,.2);border-radius:14px;display:inline-block;
       font-size:28px;font-weight:900;color:#fff;line-height:56px;margin-bottom:12px}}
.hdr h1{{color:#fff;margin:0;font-size:20px}}
.body{{padding:32px}}
.btn{{display:inline-block;background:#3b82f6;color:#fff!important;text-decoration:none;
      padding:14px 28px;border-radius:10px;font-weight:600;font-size:15px;margin:20px 0}}
.btn-red{{background:#ef4444}}
.foot{{padding:20px 32px;border-top:1px solid #334155;text-align:center;font-size:12px;color:#64748b}}
p{{line-height:1.6;color:#cbd5e1}}
.code{{background:#0f172a;border-radius:8px;padding:16px;font-family:monospace;font-size:13px;
       color:#34d399;word-break:break-all;margin:12px 0;border:1px solid #334155}}
table td{{padding:10px;font-size:14px}}
</style></head><body><div class="wrap">
<div class="hdr"><div class="logo">E</div><h1>{title}</h1></div>
<div class="body">{body}</div>
<div class="foot">Ego Blockchain · Quantum-Safe Decentralized Network<br>
<a href="https://egoblockchain.com" style="color:#3b82f6">egoblockchain.com</a></div>
</div></body></html>"#, title = title, body = body)
}

fn mask_email(email: &str) -> String {
    if let Some(at) = email.find('@') {
        let local = &email[..at];
        let domain = &email[at..];
        let show = if local.len() <= 2 { 1 } else { 2 };
        format!("{}***{}", &local[..show], domain)
    } else {
        "***".into()
    }
}

// ── HTTP handlers — unchanged originals ──────────────────────────────────────

async fn get_chain(State(s): State<AppState>) -> Json<SharedChain> {
    Json(s.chain.read().unwrap().clone())
}

async fn health() -> &'static str { "ok" }

async fn get_peers(State(s): State<AppState>) -> Json<Vec<PeerEntry>> {
    Json(s.peers.read().unwrap().clone())
}

async fn post_peer(
    State(s): State<AppState>,
    Json(entry): Json<PeerEntry>,
) -> StatusCode {
    if entry.address.is_empty() || entry.endpoint.is_empty() {
        return StatusCode::BAD_REQUEST;
    }
    let mut list = s.peers.write().unwrap();
    let now = chrono::Utc::now().timestamp();
    if let Some(existing) = list.iter_mut().find(|p| p.address == entry.address) {
        existing.endpoint  = entry.endpoint.clone();
        existing.name      = entry.name.clone();
        existing.last_seen = now;
        existing.is_relay  = entry.is_relay;
        if entry.city.is_some()    { existing.city    = entry.city.clone(); }
        if entry.country.is_some() { existing.country = entry.country.clone(); }
        if entry.is_relay { println!("[peers] Updated endpoint for {} → {} [RELAY]", entry.address, entry.endpoint); }
        else              { println!("[peers] Updated endpoint for {} → {}", entry.address, entry.endpoint); }
    } else {
        if entry.is_relay { println!("[peers] New relay node {} → {}", entry.address, entry.endpoint); }
        else              { println!("[peers] New peer {} → {}", entry.address, entry.endpoint); }
        list.push(PeerEntry { last_seen: now, ..entry });
    }
    let cutoff = now - 600;
    list.retain(|p| p.last_seen >= cutoff);
    save_peers(&list);
    StatusCode::OK
}

async fn post_tx(
    State(s): State<AppState>,
    Json(tx): Json<LedgerTx>,
) -> StatusCode {
    // ── 1. Basic sanity ───────────────────────────────────────────────────
    if tx.from.is_empty() || tx.to.is_empty() || tx.amount == 0 {
        println!("[chain] Rejected tx: missing fields");
        return StatusCode::BAD_REQUEST;
    }

    // ── 2. Signature verification ─────────────────────────────────────────
    if tx.public_key_ed25519.is_empty() || tx.signature.is_empty() {
        println!("[chain] Rejected tx {}: missing public key or signature", tx.hash);
        return StatusCode::BAD_REQUEST;
    }
    let pk_bytes = match hex::decode(&tx.public_key_ed25519) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            println!("[chain] Rejected tx {}: invalid public key hex", tx.hash);
            return StatusCode::BAD_REQUEST;
        }
    };
    let pk_arr: [u8; 32] = pk_bytes.try_into().unwrap();
    let verifying_key = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(k) => k,
        Err(_) => {
            println!("[chain] Rejected tx {}: invalid public key", tx.hash);
            return StatusCode::BAD_REQUEST;
        }
    };
    let sig_bytes = match hex::decode(&tx.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => {
            println!("[chain] Rejected tx {}: invalid signature hex", tx.hash);
            return StatusCode::BAD_REQUEST;
        }
    };
    let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    let signing_bytes = tx_signing_bytes(&tx.from, &tx.to, tx.amount, tx.nonce, tx.timestamp);
    if verifying_key.verify(&signing_bytes, &sig).is_err() {
        println!("[chain] Rejected tx {}: signature invalid", tx.hash);
        return StatusCode::UNAUTHORIZED;
    }

    // ── 3. Timestamp freshness (reject if older than 10 minutes) ─────────
    let now = chrono::Utc::now().timestamp();
    if (now - tx.timestamp).abs() > 600 {
        println!("[chain] Rejected tx {}: timestamp too old/future", tx.hash);
        return StatusCode::BAD_REQUEST;
    }

    let mut chain = s.chain.write().unwrap();

    // ── 4. Nonce enforcement (strictly increasing per address) ────────────
    let last = chain.last_nonce(&tx.from);
    if tx.nonce == 0 || tx.nonce <= last {
        println!("[chain] Rejected tx {}: nonce {} <= last confirmed {}", tx.hash, tx.nonce, last);
        return StatusCode::CONFLICT;
    }

    // ── 5. Server-side balance check ──────────────────────────────────────
    // Special case: genesis/faucet transactions are always allowed.
    if tx.from != "egot1faucet000000000000000000000000000000000000" {
        let balance = chain.balance_of(&tx.from);
        if tx.amount > balance {
            println!("[chain] Rejected tx {}: insufficient balance ({} > {})", tx.hash, tx.amount, balance);
            return StatusCode::BAD_REQUEST;
        }
    }

    // ── 6. Accept — relay is the authority; accepted txs are always Confirmed ──
    let mut tx = tx;
    tx.status = "Confirmed".to_string();
    if let Some(existing) = chain.transactions.iter_mut().find(|t| t.hash == tx.hash) {
        if existing.status != "Confirmed" {
            existing.status = "Confirmed".to_string();
            save_chain(&chain);
        }
    } else {
        println!("[chain] ✓ Verified tx {} from {} → {} ({} uEGOC)", tx.hash, tx.from, tx.to, tx.amount);
        // Gossip to all connected desktop peers so they learn about this tx
        // even if they have no direct contact relationship with the sender.
        if let Some(gtx) = RELAY_GOSSIP_TX.get() {
            // Use the same TxBroadcast shape the desktop gossip handler expects.
            let stub_block = LedgerBlock { height: 0, hash: String::new(), prev_hash: String::new(),
                timestamp: 0, miner: String::new(), tx_count: 1, size_bytes: 0, reward: 0 };
            if let Ok(bytes) = serde_json::to_vec(&serde_json::json!({
                "type": "tx_broadcast",
                "tx": &tx,
                "block": stub_block,
            })) {
                let _ = gtx.send(("ego-txs-v1".to_string(), bytes));
            }
        }
        chain.transactions.push(tx);
        save_chain(&chain);
    }
    StatusCode::OK
}

async fn post_block(
    State(s): State<AppState>,
    Json(block): Json<LedgerBlock>,
) -> StatusCode {
    // ── PoC gate ──────────────────────────────────────────────────────────────
    // Blocks may only be proposed by miners that have proven coverage (DRS > 0).
    // During bootstrap (< POC_BOOTSTRAP_THRESHOLD active validators) we allow
    // any miner so the network can get started without a chicken-and-egg problem.
    {
        let poc = s.poc_events.read().unwrap();
        let unique_validators = poc.iter()
            .map(|e| e.address.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len();
        if unique_validators >= POC_BOOTSTRAP_THRESHOLD {
            let miner_score = compute_drs_score(&poc, &block.miner);
            if miner_score == 0.0 {
                println!("[chain] Rejected block #{} from {}: no PoC score (validators={})",
                    block.height, block.miner, unique_validators);
                return StatusCode::FORBIDDEN;
            }
        }
    }

    let mut chain = s.chain.write().unwrap();

    // ── Chain linkage check ────────────────────────────────────────────────────
    // Reject a block whose prev_hash doesn't connect to the current tip.
    if let Some(tip) = chain.blocks.last() {
        if block.height == tip.height + 1 && block.prev_hash != tip.hash {
            println!("[chain] Rejected block #{}: prev_hash mismatch (got {}, want {})",
                block.height, block.prev_hash, tip.hash);
            return StatusCode::BAD_REQUEST;
        }
    }

    if !chain.blocks.iter().any(|b| b.hash == block.hash) {
        println!("[chain] ✓ Block #{} hash {} miner {}", block.height, block.hash, block.miner);
        chain.blocks.push(block);
        chain.blocks.sort_by_key(|b| b.height);
        save_chain(&chain);
    }
    StatusCode::OK
}

const INBOX_DISK_THRESHOLD: usize = 1 * 1024 * 1024; // 1 MB
const INBOX_DIR: &str = "inbox_files";

async fn post_inbox(
    Path(address): Path<String>,
    State(s): State<AppState>,
    Json(msg): Json<InboxMessage>,
) -> StatusCode {
    if address.is_empty() || (msg.payload.is_empty() && msg.disk_path.is_none()) {
        return StatusCode::BAD_REQUEST;
    }
    let _ = std::fs::create_dir_all(INBOX_DIR);

    let stored_msg = if msg.payload.len() > INBOX_DISK_THRESHOLD {
        // Write payload to disk
        let file_name = format!("{}/{}_{}.bin", INBOX_DIR, address, uuid::Uuid::new_v4());
        if let Err(e) = std::fs::write(&file_name, msg.payload.as_bytes()) {
            eprintln!("[inbox] Failed to write to disk: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
        println!("[inbox] Stored large message for {} on disk ({} bytes)", 
            address, msg.payload.len());
        InboxMessage {
            payload:   String::new(),
            deposited: msg.deposited,
            from_addr: msg.from_addr,
            disk_path: Some(file_name),
        }
    } else {
        msg
    };

    let mut map = s.inbox.write().unwrap();
    let bucket = map.entry(address.clone()).or_default();
    if !bucket.iter().any(|m| m.disk_path == stored_msg.disk_path && !stored_msg.disk_path.is_none())
        && !bucket.iter().any(|m| !m.payload.is_empty() && m.payload == stored_msg.payload) {
        bucket.push(stored_msg);
    }
    StatusCode::OK
}

async fn get_inbox(
    Path(address): Path<String>,
    State(s): State<AppState>,
) -> Json<Vec<InboxMessage>> {
    let mut map = s.inbox.write().unwrap();
    let msgs = map.remove(&address).unwrap_or_default();
    if msgs.is_empty() {
        return Json(vec![]);
    }
    println!("[inbox] Delivering {} message(s) to {}", msgs.len(), address);

    // Rehydrate disk-backed messages
    let mut result = Vec::new();
    for msg in msgs {
        if let Some(ref path) = msg.disk_path {
            match std::fs::read_to_string(path) {
                Ok(payload) => {
                    let _ = std::fs::remove_file(path); // clean up
                    result.push(InboxMessage {
                        payload,
                        deposited: msg.deposited,
                        from_addr: msg.from_addr,
                        disk_path: None,
                    });
                }
                Err(e) => {
                    eprintln!("[inbox] Failed to read disk message {}: {}", path, e);
                }
            }
        } else {
            result.push(msg);
        }
    }
    Json(result)
}

// ── HTTP handlers — new email/user/tx endpoints ───────────────────────────────

#[derive(Debug, Deserialize)]
struct RegisterRequest {
    address: String,
    name:    String,
    email:   String,
}

#[derive(Debug, Serialize)]
struct ApiResponse {
    success: bool,
    message: String,
}

async fn post_register(
    State(s): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    if req.address.is_empty() || req.name.is_empty() || req.email.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(ApiResponse {
            success: false, message: "address, name and email required".into(),
        }));
    }
    let token = Uuid::new_v4().to_string();
    let now   = chrono::Utc::now().timestamp();
    {
        let mut users = s.users.write().unwrap();
        if let Some(u) = users.iter_mut().find(|u| u.address == req.address) {
            u.name = req.name.clone(); u.email = req.email.clone();
            u.verify_token = Some(token.clone()); u.email_verified = false;
        } else {
            users.push(UserRecord {
                address: req.address.clone(), name: req.name.clone(),
                email: req.email.clone(), email_verified: false,
                verify_token: Some(token.clone()), pin_reset_token: None,
                pin_reset_expiry: None, registered_at: now, pending_email: None, email_change_token: None,
            });
        }
        save_users(&users);
    }
    let verify_url = format!("{}/users/verify/{}", s.config.base_url, token);
    let user_body  = email_html("Verify Your Email", &format!(
        r#"<p>Hi <strong>{name}</strong>,</p>
        <p>Welcome to Ego Blockchain! Click below to verify your email and see your recovery phrase.</p>
        <p style="text-align:center"><a href="{url}" class="btn">✓ Verify Email Address</a></p>
        <p style="font-size:13px;color:#94a3b8">Or paste this link in your browser:<br>
        <span class="code">{url}</span></p>"#,
        name = req.name, url = verify_url,
    ));
    send_email(&s.mailer, &s.config.smtp_from, &req.email, "Verify your Ego Blockchain email", user_body).await;

    println!("[users] Registered {} <{}>", req.name, req.email);
    (StatusCode::OK, Json(ApiResponse { success: true, message: "Verification email sent.".into() }))
}

async fn get_verify(
    Path(token): Path<String>,
    State(s): State<AppState>,
) -> (StatusCode, axum::response::Html<String>) {
    let mut users = s.users.write().unwrap();
    if let Some(user) = users.iter_mut().find(|u| u.verify_token.as_deref() == Some(&token)) {
        user.email_verified = true;
        user.verify_token   = None;
        let name = user.name.clone();
        save_users(&users);
        return (StatusCode::OK, axum::response::Html(format!(r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Email Verified</title>
<style>body{{font-family:sans-serif;background:#0f172a;color:#e2e8f0;display:flex;
align-items:center;justify-content:center;min-height:100vh;margin:0}}
.card{{background:#1e293b;border-radius:16px;padding:48px;text-align:center;
max-width:400px;border:1px solid #334155}}
.icon{{font-size:64px;margin-bottom:16px}}h1{{color:#34d399;margin:0 0 12px}}
p{{color:#94a3b8}}a{{color:#3b82f6}}</style></head>
<body><div class="card"><div class="icon">✅</div>
<h1>Email Verified!</h1>
<p>Welcome, <strong style="color:#e2e8f0">{name}</strong>!</p>
<p>Your wallet is now fully activated. Return to the Ego Desktop app to see your recovery phrase.</p>
<p style="margin-top:24px"><a href="https://egoblockchain.com">egoblockchain.com</a></p>
</div></body></html>"#, name = name)));
    }
    (StatusCode::BAD_REQUEST,
     axum::response::Html("<h1>Invalid or expired verification link.</h1>".into()))
}

#[derive(Debug, Serialize)]
struct UserStatusResponse {
    registered:     bool,
    email_verified: bool,
    name:           String,
    email_masked:   String,
}

async fn get_user(
    Path(address): Path<String>,
    State(s): State<AppState>,
) -> Json<UserStatusResponse> {
    let users = s.users.read().unwrap();
    if let Some(u) = users.iter().find(|u| u.address == address) {
        Json(UserStatusResponse {
            registered: true, email_verified: u.email_verified,
            name: u.name.clone(), email_masked: mask_email(&u.email),
        })
    } else {
        Json(UserStatusResponse {
            registered: false, email_verified: false,
            name: String::new(), email_masked: String::new(),
        })
    }
}

#[derive(Debug, Deserialize)]
struct ChangeEmailRequest { address: String, new_email: String }

async fn post_change_email(
    State(s): State<AppState>,
    Json(req): Json<ChangeEmailRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    let new_email = req.new_email.trim().to_lowercase();
    if !new_email.contains('@') {
        return (StatusCode::BAD_REQUEST, Json(ApiResponse {
            success: false, message: "Invalid email address".into(),
        }));
    }

    let token = uuid::Uuid::new_v4().to_string();
    let base_url = s.config.base_url.clone();
    let (mailer_clone, from_clone, name_clone) = {
        let mut users = s.users.write().unwrap();
        let user = match users.iter_mut().find(|u| u.address == req.address) {
            Some(u) => u,
            None => return (StatusCode::NOT_FOUND, Json(ApiResponse {
                success: false, message: "Address not registered".into(),
            })),
        };
        if !user.email_verified {
            return (StatusCode::BAD_REQUEST, Json(ApiResponse {
                success: false, message: "Current email is not verified".into(),
            }));
        }
        if user.email == new_email {
            return (StatusCode::BAD_REQUEST, Json(ApiResponse {
                success: false, message: "New email is the same as current email".into(),
            }));
        }
        user.pending_email      = Some(new_email.clone());
        user.email_change_token = Some(token.clone());
        let name = user.name.clone();
        save_users(&users);
        (s.mailer.clone(), s.config.smtp_from.clone(), name)
    };

    let verify_url = format!("{}/users/verify-email-change/{}", base_url, token);
    let body = format!(
        "Hi {name},\n\nClick the link below to confirm your new email address for Ego Desktop:\n\n{url}\n\nIf you did not request this change, ignore this email — your current address stays active.\n\nEgo Blockchain Team",
        name = name_clone, url = verify_url
    );
    let _ = send_email(&mailer_clone, &from_clone, &new_email, "Confirm your new Ego email", body).await;

    (StatusCode::OK, Json(ApiResponse { success: true, message: "Verification email sent to new address.".into() }))
}

async fn get_verify_email_change(
    Path(token): Path<String>,
    State(s): State<AppState>,
) -> (StatusCode, axum::response::Html<String>) {
    let mut users = s.users.write().unwrap();
    if let Some(user) = users.iter_mut().find(|u| u.email_change_token.as_deref() == Some(&token)) {
        if let Some(new_email) = user.pending_email.take() {
            user.email              = new_email;
            user.email_change_token = None;
            save_users(&users);
            return (StatusCode::OK, axum::response::Html(r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Email Updated</title>
<style>body{font-family:sans-serif;background:#0f172a;color:#e2e8f0;display:flex;
align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#1e293b;border-radius:16px;padding:48px;text-align:center;
max-width:400px;border:1px solid #334155}
.icon{font-size:64px;margin-bottom:16px}h1{color:#34d399;margin:0 0 12px}
p{color:#94a3b8}a{color:#3b82f6}</style></head>
<body><div class="card"><div class="icon">✅</div>
<h1>Email Updated!</h1>
<p>Your Ego Desktop email address has been changed successfully.</p>
<p style="margin-top:24px"><a href="https://egoblockchain.com">egoblockchain.com</a></p>
</div></body></html>"#.into()));
        }
    }
    (StatusCode::BAD_REQUEST,
     axum::response::Html("<h1>Invalid or expired email change link.</h1>".into()))
}

#[derive(Debug, Deserialize)]
struct ResetPinRequest { address: String }

async fn post_reset_pin(
    State(s): State<AppState>,
    Json(req): Json<ResetPinRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    let result = {
        let mut users = s.users.write().unwrap();
        if let Some(user) = users.iter_mut().find(|u| u.address == req.address) {
            if !user.email_verified {
                return (StatusCode::BAD_REQUEST, Json(ApiResponse {
                    success: false, message: "Email not verified".into(),
                }));
            }
            let token  = Uuid::new_v4().to_string();
            let expiry = chrono::Utc::now().timestamp() + 3600;
            let email  = user.email.clone();
            let name   = user.name.clone();
            user.pin_reset_token  = Some(token.clone());
            user.pin_reset_expiry = Some(expiry);
            save_users(&users);
            Some((email, name, token))
        } else {
            None
        }
    }; // lock dropped here

    match result {
        None => (StatusCode::NOT_FOUND, Json(ApiResponse {
            success: false, message: "Address not registered".into(),
        })),
        Some((email, name, token)) => {
            let reset_url = format!("{}/users/pin-reset/{}", s.config.base_url, token);
            let body = email_html("Reset Your PIN", &format!(
                r#"<p>Hi <strong>{name}</strong>,</p>
                <p>Click below to reset your Ego Blockchain security PIN. This link expires in 1 hour.</p>
                <p style="text-align:center"><a href="{url}" class="btn">Reset My PIN</a></p>
                <p style="font-size:13px;color:#94a3b8">If you did not request this, ignore this email.</p>"#,
                name = name, url = reset_url,
            ));
            send_email(&s.mailer, &s.config.smtp_from, &email, "Reset your Ego Blockchain PIN", body).await;
            (StatusCode::OK, Json(ApiResponse { success: true, message: "PIN reset email sent.".into() }))
        }
    }
}

#[derive(Debug, Deserialize)]
struct PendingTxRequest {
    address:    String,
    tx_json:    String,
    block_json: String,
    tx_type:    String,
    amount:     u64,
    to:         String,
}

async fn post_pending_tx(
    State(s): State<AppState>,
    Json(req): Json<PendingTxRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    let (email, name) = {
        let users = s.users.read().unwrap();
        match users.iter().find(|u| u.address == req.address && u.email_verified) {
            Some(u) => (u.email.clone(), u.name.clone()),
            None    => return (StatusCode::BAD_REQUEST, Json(ApiResponse {
                success: false, message: "No verified email for this address".into(),
            })),
        }
    };
    let token    = Uuid::new_v4().to_string();
    let now      = chrono::Utc::now().timestamp();
    let amount_f = format!("{:.4}", req.amount as f64 / 1_000_000.0);
    {
        let mut pending = s.pending.write().unwrap();
        pending.retain(|p| p.address != req.address);
        pending.push(PendingTx {
            token: token.clone(), address: req.address.clone(), email: email.clone(),
            tx_json: req.tx_json, block_json: req.block_json, created_at: now,
            tx_type: req.tx_type.clone(), amount: req.amount, to: req.to.clone(),
        });
    }
    let confirm_url = format!("{}/tx/confirm/{}", s.config.base_url, token);
    let cancel_url  = format!("{}/tx/cancel/{}", s.config.base_url, token);
    let action = match req.tx_type.as_str() {
        "stake" => format!("Stake {} EGOC", amount_f),
        _       => format!("Send {} EGOC", amount_f),
    };
    let body = email_html("Confirm Your Transaction", &format!(
        r#"<p>Hi <strong>{name}</strong>,</p>
        <p>A transaction is waiting for your confirmation:</p>
        <table style="width:100%;border-collapse:collapse;margin:16px 0">
          <tr style="background:#0f172a"><td style="color:#94a3b8">Action</td><td><strong>{action}</strong></td></tr>
          <tr><td style="color:#94a3b8">Amount</td><td style="color:#34d399;font-weight:700">{amount} EGOC</td></tr>
          <tr style="background:#0f172a"><td style="color:#94a3b8">From</td>
              <td style="font-family:monospace;font-size:11px">{from}</td></tr>
        </table>
        <p style="text-align:center">
          <a href="{confirm}" class="btn" style="margin-right:12px">✓ Confirm</a>
          <a href="{cancel}" class="btn btn-red">✕ Cancel</a>
        </p>
        <p style="font-size:12px;color:#64748b">This link expires in 30 minutes.</p>"#,
        name = name, action = action, amount = amount_f,
        from = req.address, confirm = confirm_url, cancel = cancel_url,
    ));
    send_email(&s.mailer, &s.config.smtp_from, &email, &format!("Confirm: {}", action), body).await;
    println!("[tx] Pending tx for {} — awaiting email confirm", req.address);
    // Return the token as the message so the desktop can poll /tx/status/:token
    (StatusCode::OK, Json(ApiResponse { success: true, message: token }))
}

async fn get_confirm_tx(
    Path(token): Path<String>,
    State(s): State<AppState>,
) -> (StatusCode, axum::response::Html<String>) {
    let ptx = {
        let mut pending = s.pending.write().unwrap();
        match pending.iter().position(|p| p.token == token) {
            Some(i) => {
                let tx = pending.remove(i);
                if chrono::Utc::now().timestamp() - tx.created_at > 1800 {
                    return (StatusCode::BAD_REQUEST,
                        axum::response::Html("<h1>This confirmation link has expired.</h1>".into()));
                }
                tx
            }
            None => return (StatusCode::NOT_FOUND,
                axum::response::Html("<h1>Transaction not found or already processed.</h1>".into())),
        }
    };
    let tx: LedgerTx = match serde_json::from_str(&ptx.tx_json) {
        Ok(t)  => t,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR,
            axum::response::Html("<h1>Invalid tx data.</h1>".into())),
    };
    let block: LedgerBlock = match serde_json::from_str(&ptx.block_json) {
        Ok(b)  => b,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR,
            axum::response::Html("<h1>Invalid block data.</h1>".into())),
    };
    {
        let mut chain = s.chain.write().unwrap();
        if !chain.transactions.iter().any(|t| t.hash == tx.hash) {
            chain.transactions.push(tx.clone());
            chain.blocks.push(block);
            chain.blocks.sort_by_key(|b| b.height);
            save_chain(&chain);
            println!("[tx] Confirmed tx {} for {}", tx.hash, ptx.address);
        }
    }
    let amount_f = format!("{:.4}", ptx.amount as f64 / 1_000_000.0);
    (StatusCode::OK, axum::response::Html(format!(r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Transaction Confirmed</title>
<style>body{{font-family:sans-serif;background:#0f172a;color:#e2e8f0;display:flex;
align-items:center;justify-content:center;min-height:100vh;margin:0}}
.card{{background:#1e293b;border-radius:16px;padding:48px;text-align:center;
max-width:440px;border:1px solid #334155}}
.icon{{font-size:64px;margin-bottom:16px}}h1{{color:#34d399;margin:0 0 12px}}
.amount{{color:#34d399;font-size:28px;font-weight:700;margin:16px 0}}
p{{color:#94a3b8;line-height:1.6}}
.hash{{font-family:monospace;font-size:11px;word-break:break-all;background:#0f172a;
padding:12px;border-radius:8px;margin-top:16px}}</style></head>
<body><div class="card"><div class="icon">✅</div>
<h1>Transaction Confirmed!</h1>
<div class="amount">{amount} EGOC</div>
<p>Your transaction has been recorded on the Ego Blockchain.</p>
<div class="hash">{hash}</div>
<p style="margin-top:24px">You can close this page and return to Ego Desktop.</p>
</div></body></html>"#, amount = amount_f, hash = tx.hash)))
}

async fn get_cancel_tx(
    Path(token): Path<String>,
    State(s): State<AppState>,
) -> (StatusCode, axum::response::Html<String>) {
    let mut pending = s.pending.write().unwrap();
    if pending.iter().position(|p| p.token == token).map(|i| pending.remove(i)).is_some() {
        println!("[tx] Cancelled pending tx token {}", &token[..8]);
        return (StatusCode::OK, axum::response::Html(r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Cancelled</title>
<style>body{font-family:sans-serif;background:#0f172a;color:#e2e8f0;display:flex;
align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#1e293b;border-radius:16px;padding:48px;text-align:center;
max-width:400px;border:1px solid #334155}
.icon{font-size:64px;margin-bottom:16px}h1{color:#ef4444;margin:0 0 12px}
p{color:#94a3b8}</style></head>
<body><div class="card"><div class="icon">❌</div>
<h1>Transaction Cancelled</h1>
<p>Your transaction has been cancelled. No funds were moved.</p>
</div></body></html>"#.into()));
    }
    (StatusCode::NOT_FOUND, axum::response::Html("<h1>Transaction not found.</h1>".into()))
}

#[derive(Debug, Serialize)]
struct TxStatusResponse { status: String }

async fn get_tx_status(
    Path(token): Path<String>,
    State(s): State<AppState>,
) -> Json<TxStatusResponse> {
    let pending = s.pending.read().unwrap();
    if let Some(p) = pending.iter().find(|p| p.token == token) {
        let age = chrono::Utc::now().timestamp() - p.created_at;
        return Json(TxStatusResponse {
            status: if age > 1800 { "expired".into() } else { "pending".into() },
        });
    }
    Json(TxStatusResponse { status: "confirmed".into() })
}

// ── PoC HTTP handlers ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct PocEventRequest {
    address:    String,
    quality:    String,
    peers:      u32,
    h3_cell:    Option<String>,
    timestamp:  i64,
    signature:  String,
    public_key: String,
}

/// POST /poc/event — submit a signed Proof of Coverage beacon event.
async fn post_poc_event(
    State(s): State<AppState>,
    Json(req): Json<PocEventRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    // 1. Validate quality value
    if !["Excellent", "Good", "Fair", "Poor"].contains(&req.quality.as_str()) {
        return (StatusCode::BAD_REQUEST, Json(ApiResponse {
            success: false, message: "Invalid quality level".into(),
        }));
    }

    // 2. Timestamp freshness ±30 minutes
    let now = chrono::Utc::now().timestamp();
    if (now - req.timestamp).abs() > 1800 {
        return (StatusCode::BAD_REQUEST, Json(ApiResponse {
            success: false, message: "Timestamp out of range (±30 min)".into(),
        }));
    }

    // 3. Ed25519 signature verification
    let pk_bytes = match hex::decode(&req.public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(ApiResponse {
            success: false, message: "Invalid public key".into(),
        })),
    };
    let pk_arr: [u8; 32] = pk_bytes.try_into().unwrap();
    let verifying_key = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(ApiResponse {
            success: false, message: "Invalid public key bytes".into(),
        })),
    };
    let sig_bytes = match hex::decode(&req.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(ApiResponse {
            success: false, message: "Invalid signature".into(),
        })),
    };
    let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    let h3 = req.h3_cell.as_deref().unwrap_or("");
    let signing_bytes = poc_signing_bytes(&req.address, &req.quality, req.peers, h3, req.timestamp);
    if verifying_key.verify(&signing_bytes, &sig).is_err() {
        println!("[poc] Rejected event from {}: bad signature", req.address);
        return (StatusCode::UNAUTHORIZED, Json(ApiResponse {
            success: false, message: "Invalid signature".into(),
        }));
    }

    // 4. Rate-limit: max 1 event per address per POC_RATE_LIMIT_SECS
    let reward = poc_reward_uegoc(&req.quality);
    {
        let mut events = s.poc_events.write().unwrap();
        let cutoff = now - POC_RATE_LIMIT_SECS;
        if events.iter().any(|e| e.address == req.address && e.timestamp > cutoff) {
            return (StatusCode::TOO_MANY_REQUESTS, Json(ApiResponse {
                success: false, message: format!("Rate limit: 1 PoC event per {} minutes",
                    POC_RATE_LIMIT_SECS / 60),
            }));
        }
        events.push(PocEventRecord {
            id:          uuid::Uuid::new_v4().to_string(),
            address:     req.address.clone(),
            quality:     req.quality.clone(),
            peers:       req.peers,
            h3_cell:     req.h3_cell.clone(),
            timestamp:   req.timestamp,
            signature:   req.signature.clone(),
            public_key:  req.public_key.clone(),
            reward_uegoc: reward,
            accepted_at: now,
        });
        // Prune events older than 30 days to keep the file manageable
        let cutoff_30d = now - 86_400 * 30;
        events.retain(|e| e.timestamp >= cutoff_30d);
        save_poc_events(&events);
    }

    // 5. Emit coverage reward tx from faucet address on the shared chain
    if reward > 0 {
        let reward_hash = format!("0xpoc-{}-{}",
            &req.address[req.address.len().saturating_sub(8)..], req.timestamp);
        let mut chain = s.chain.write().unwrap();
        if !chain.transactions.iter().any(|t| t.hash == reward_hash) {
            let faucet       = "egot1faucet000000000000000000000000000000000000";
            let nonce        = chain.last_nonce(faucet) + 1;
            let block_height = chain.blocks.last().map(|b| b.height);
            chain.transactions.push(LedgerTx {
                hash:               reward_hash,
                from:               faucet.into(),
                to:                 req.address.clone(),
                amount:             reward,
                memo:               Some(format!("PoC coverage reward ({})", req.quality)),
                timestamp:          now,
                signature:          "relay-issued".into(),
                status:             "Confirmed".into(),
                block_height,
                nonce,
                public_key_ed25519: String::new(),
            });
            save_chain(&chain);
        }
    }

    println!("[poc] ✓ Event from {} quality={} peers={} reward={}uEGOC",
        req.address, req.quality, req.peers, reward);
    (StatusCode::OK, Json(ApiResponse {
        success: true,
        message: format!("PoC event accepted, reward: {} uEGOC (DRS updated)", reward),
    }))
}

#[derive(Debug, Serialize)]
struct DrsScoreResponse {
    address:        String,
    drs_score:      f64,
    events_24h:     u32,
    total_events:   u64,
    last_event:     Option<i64>,
    is_validator:   bool,
    validator_rank: Option<usize>,
}

/// GET /poc/score/:address — DRS score and validator status for an address.
async fn get_poc_score(
    Path(address): Path<String>,
    State(s): State<AppState>,
) -> Json<DrsScoreResponse> {
    let events  = s.poc_events.read().unwrap();
    let now     = chrono::Utc::now().timestamp();
    let cutoff  = now - 86_400;
    let events_24h   = events.iter().filter(|e| e.address == address && e.timestamp >= cutoff).count() as u32;
    let total_events = events.iter().filter(|e| e.address == address).count() as u64;
    let last_event   = events.iter().filter(|e| e.address == address).map(|e| e.timestamp).max();
    let drs_score    = compute_drs_score(&events, &address);

    // Rank among all validators (any address with drs_score > 0)
    let mut all: Vec<(String, f64)> = events.iter()
        .map(|e| e.address.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .map(|a| { let sc = compute_drs_score(&events, &a); (a, sc) })
        .filter(|(_, sc)| *sc > 0.0)
        .collect();
    all.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let validator_rank = all.iter().position(|(a, _)| *a == address).map(|i| i + 1);

    Json(DrsScoreResponse {
        address, drs_score, events_24h, total_events, last_event,
        is_validator: drs_score > 0.0,
        validator_rank,
    })
}

#[derive(Debug, Serialize)]
struct ValidatorInfo {
    address:    String,
    drs_score:  f64,
    events_24h: u32,
    last_event: Option<i64>,
    rank:       usize,
}

/// GET /poc/validators — ranked list of active PoC validators (last 24 h).
async fn get_poc_validators(
    State(s): State<AppState>,
) -> Json<Vec<ValidatorInfo>> {
    let events = s.poc_events.read().unwrap();
    let now    = chrono::Utc::now().timestamp();
    let cutoff = now - 86_400;

    let mut addr_map: std::collections::HashMap<String, (u32, Option<i64>)> = std::collections::HashMap::new();
    for e in events.iter() {
        let entry = addr_map.entry(e.address.clone()).or_insert((0, None));
        if e.timestamp >= cutoff { entry.0 += 1; }
        entry.1 = Some(entry.1.map(|t: i64| t.max(e.timestamp)).unwrap_or(e.timestamp));
    }

    let mut validators: Vec<ValidatorInfo> = addr_map.iter()
        .filter(|(_, (cnt, _))| *cnt > 0)
        .map(|(addr, (cnt, last))| ValidatorInfo {
            address:    addr.clone(),
            drs_score:  compute_drs_score(&events, addr),
            events_24h: *cnt,
            last_event: *last,
            rank:       0,
        })
        .collect();
    validators.sort_by(|a, b| b.drs_score.partial_cmp(&a.drs_score)
        .unwrap_or(std::cmp::Ordering::Equal));
    for (i, v) in validators.iter_mut().enumerate() { v.rank = i + 1; }
    Json(validators)
}

// ── libp2p relay behaviour ────────────────────────────────────────────────────

#[derive(NetworkBehaviour)]
struct RelayBehaviour {
    relay:     relay::Behaviour,
    identify:  identify::Behaviour,
    ping:      ping::Behaviour,
    /// Gossipsub: fans out chain tx/block messages to all connected desktop nodes.
    gossipsub: gossipsub::Behaviour,
    /// Kademlia: the relay is the bootstrap node for the DHT network.
    kad:       kad::Behaviour<kad::store::MemoryStore>,
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok(); // load .env if present (silent if missing)

    let cfg = Config::from_env();

    let identity = load_or_create_identity();
    let peer_id  = identity.public().to_peer_id();

    let p2p_port = std::env::var("EGO_RELAY_PORT")
        .ok().and_then(|p| p.parse::<u16>().ok()).unwrap_or(4001);
    let http_port = std::env::var("EGO_HTTP_PORT")
        .ok().and_then(|p| p.parse::<u16>().ok()).unwrap_or(8080);

    // Build SMTP mailer
    let creds  = Credentials::new(cfg.smtp_user.clone(), cfg.smtp_pass.clone());
    let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.smtp_host)
        .unwrap()
        .port(cfg.smtp_port)
        .credentials(creds)
        .build();

    let poc_loaded = load_poc_events();
    let state = AppState {
        chain:      Arc::new(RwLock::new(load_chain())),
        peers:      Arc::new(RwLock::new(load_peers())),
        inbox:      Arc::new(RwLock::new(HashMap::new())),
        users:      Arc::new(RwLock::new(load_users())),
        pending:    Arc::new(RwLock::new(Vec::new())),
        poc_events: Arc::new(RwLock::new(poc_loaded)),
        mailer:     Arc::new(mailer),
        config:     Arc::new(cfg),
    };
    {
        let c   = state.chain.read().unwrap();
        let p   = state.peers.read().unwrap();
        let u   = state.users.read().unwrap();
        let poc = state.poc_events.read().unwrap();
        println!("[chain] Loaded {} blocks, {} txs from {}", c.blocks.len(), c.transactions.len(), CHAIN_PATH);
        println!("[peers] Loaded {} known peers from {}", p.len(), PEERS_PATH);
        println!("[users] Loaded {} registered users", u.len());
        println!("[poc]   Loaded {} coverage events ({} unique validators)",
            poc.len(),
            poc.iter().map(|e| e.address.as_str()).collect::<std::collections::HashSet<_>>().len());
    }

    let http_addr   = format!("0.0.0.0:{}", http_port);
    let state_clone = state.clone();
    tokio::spawn(async move {
        let app = Router::new()
            .route("/chain",                get(get_chain))
            .route("/chain/tx",             post(post_tx))
            .route("/chain/block",          post(post_block))
            .route("/peers",                get(get_peers).post(post_peer))
            .route("/inbox/:address",       get(get_inbox).post(post_inbox))
            .route("/health",               get(health))
            // ── new endpoints ──
            .route("/users/register",                  post(post_register))
            .route("/users/verify/:token",             get(get_verify))
            .route("/users/verify-email-change/:token",get(get_verify_email_change))
            .route("/users/change-email",              post(post_change_email))
            .route("/users/confirm-email-change/:token", get(get_confirm_email_change))
            .route("/users/reset-pin",                 post(post_reset_pin))
            .route("/users/pin-reset/:token",          get(get_pin_reset))
            .route("/users/pin-reset-confirm",          post(post_pin_reset_confirm))
            .route("/users/pin-reset-status/:address", get(get_pin_reset_status))
            .route("/users/:address",                  get(get_user))
            .route("/tx/pending",           post(post_pending_tx))
            .route("/tx/confirm/:token",    get(get_confirm_tx))
            .route("/tx/cancel/:token",     get(get_cancel_tx))
            .route("/tx/status/:token",     get(get_tx_status))
            // ── PoC / DRS ──
            .route("/poc/event",            post(post_poc_event))
            .route("/poc/score/:address",   get(get_poc_score))
            .route("/poc/validators",       get(get_poc_validators))
            .with_state(state_clone)
            .layer(
                CorsLayer::new()
                    .allow_origin(Any)
                    .allow_methods([Method::GET, Method::POST])
                    .allow_headers(Any),
            )
            .layer(axum::extract::DefaultBodyLimit::max(50 * 1024 * 1024));

        let listener = tokio::net::TcpListener::bind(&http_addr).await
            .expect("HTTP bind failed");
        println!("[http] Listening on {}", http_addr);
        axum::serve(listener, app).await.expect("HTTP server error");
    });

    let mut swarm = SwarmBuilder::with_existing_identity(identity.clone())
        .with_tokio()
        .with_tcp(tcp::Config::default().nodelay(true), noise::Config::new, yamux::Config::default)
        .expect("TCP transport")
        .with_behaviour(|key| {
            // ── Gossipsub ─────────────────────────────────────────────────────
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(10))
                .validation_mode(gossipsub::ValidationMode::Permissive)
                .max_transmit_size(512 * 1024)
                .build()
                .expect("relay gossipsub config");
            let gossipsub_behaviour = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::RandomAuthor,
                gossipsub_config,
            )
            .expect("relay gossipsub::Behaviour");

            // ── Kademlia ──────────────────────────────────────────────────────
            // The relay IS the bootstrap node — it just answers DHT queries.
            let store = kad::store::MemoryStore::new(peer_id);
            let mut kad_behaviour = kad::Behaviour::new(peer_id, store);
            kad_behaviour.set_mode(Some(kad::Mode::Server));

            RelayBehaviour {
                relay: relay::Behaviour::new(
                    peer_id,
                    relay::Config {
                        max_reservations:          1024,
                        max_reservations_per_peer: 32,
                        reservation_duration:      Duration::from_secs(3600),
                        max_circuits:              2048,
                        max_circuits_per_peer:     128,
                        max_circuit_duration:      Duration::from_secs(7200),
                        max_circuit_bytes:         0,
                        ..Default::default()
                    },
                ),
                identify: identify::Behaviour::new(
                    identify::Config::new("/ego/identify/1.0.0".to_string(), key.public())
                        .with_interval(Duration::from_secs(60)),
                ),
                ping: ping::Behaviour::new(
                    ping::Config::new().with_interval(Duration::from_secs(30)),
                ),
                gossipsub: gossipsub_behaviour,
                kad: kad_behaviour,
            }
        })
        .expect("behaviour")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(3600)))
        .build();

    let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", p2p_port).parse().unwrap();
    swarm.listen_on(listen_addr).expect("listen");

    // ── Gossipsub: subscribe to chain topics ──────────────────────────────────
    let tx_topic    = gossipsub::IdentTopic::new("ego-txs-v1");
    let blk_topic   = gossipsub::IdentTopic::new("ego-blocks-v1");
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&tx_topic);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&blk_topic);

    // ── Gossip channel: HTTP handlers publish here; swarm loop drains it ──────
    let (gossip_tx, mut gossip_rx) =
        tokio_mpsc::unbounded_channel::<(String, Vec<u8>)>();
    let _ = RELAY_GOSSIP_TX.set(gossip_tx);

    // Clone AppState for use inside the gossipsub message handler
    let state_gossip = state.clone();

    println!("╔═══════════════════════════════════════════╗");
    println!("║       Ego Relay + Chain Seed v0.4.0       ║");
    println!("╚═══════════════════════════════════════════╝");
    println!("Peer ID   : {}", peer_id);
    println!("P2P port  : {}", p2p_port);
    println!("HTTP port : {}", http_port);

    loop {
        tokio::select! {
            // ── Gossip publish from HTTP handlers ─────────────────────────────
            Some((topic_str, data)) = gossip_rx.recv() => {
                let topic = gossipsub::IdentTopic::new(topic_str.clone());
                match swarm.behaviour_mut().gossipsub.publish(topic, data) {
                    Ok(_) => {}
                    Err(gossipsub::PublishError::NoPeersSubscribedToTopic) => {}
                    Err(e) => eprintln!("[relay] gossip publish '{}': {:?}", topic_str, e),
                }
            }

            // ── Swarm events ──────────────────────────────────────────────────
            event = swarm.select_next_some() => match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                println!("[relay] Listening on {}", address);
            }
            SwarmEvent::ConnectionEstablished { peer_id: pid, .. } => {
                println!("[relay] Peer connected: {}", pid);
            }
            SwarmEvent::ConnectionClosed { peer_id: pid, .. } => {
                println!("[relay] Peer disconnected: {}", pid);
            }
            SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(
                relay::Event::ReservationReqAccepted { src_peer_id, .. },
            )) => {
                println!("[relay] Reservation accepted for {}", src_peer_id);
            }
            SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(
                relay::Event::CircuitReqAccepted { src_peer_id, dst_peer_id, .. },
            )) => {
                println!("[relay] Circuit: {} -> {}", src_peer_id, dst_peer_id);
            }

            // ── Gossipsub: incoming tx/block from any desktop peer ────────────
            SwarmEvent::Behaviour(RelayBehaviourEvent::Gossipsub(
                gossipsub::Event::Message { message, .. },
            )) => {
                let topic = message.topic.to_string();
                if topic == "ego-txs-v1" {
                    // Deserialize as the TxBroadcast envelope desktop uses
                    #[derive(serde::Deserialize)]
                    struct TxEnvelope { tx: LedgerTx }
                    if let Ok(env) = serde_json::from_slice::<TxEnvelope>(&message.data) {
                        let mut chain = state_gossip.chain.write().unwrap();
                        if !chain.transactions.iter().any(|t| t.hash == env.tx.hash) {
                            let mut tx = env.tx;
                            tx.status = "Confirmed".to_string();
                            println!("[gossip] Accepted tx {} via gossipsub", tx.hash);
                            chain.transactions.push(tx);
                            save_chain(&chain);
                        }
                    }
                } else if topic == "ego-blocks-v1" {
                    #[derive(serde::Deserialize)]
                    struct BlkEnvelope { blocks: Vec<LedgerBlock>, #[serde(default)] transactions: Vec<LedgerTx> }
                    if let Ok(env) = serde_json::from_slice::<BlkEnvelope>(&message.data) {
                        let mut chain = state_gossip.chain.write().unwrap();
                        let mut changed = false;
                        for blk in env.blocks {
                            if !chain.blocks.iter().any(|b| b.hash == blk.hash) {
                                chain.blocks.push(blk); changed = true;
                            }
                        }
                        for tx in env.transactions {
                            if !chain.transactions.iter().any(|t| t.hash == tx.hash) {
                                chain.transactions.push(tx); changed = true;
                            }
                        }
                        if changed { save_chain(&chain); }
                    }
                }
            }

            SwarmEvent::Behaviour(RelayBehaviourEvent::Gossipsub(_)) => {}

            // ── Kademlia ──────────────────────────────────────────────────────
            SwarmEvent::Behaviour(RelayBehaviourEvent::Kad(
                kad::Event::RoutingUpdated { peer, .. },
            )) => {
                println!("[kad] Routing updated: {}", peer);
            }
            SwarmEvent::Behaviour(RelayBehaviourEvent::Kad(_)) => {}

            _ => {}
        } // end match event
        } // end select!
    }
}


async fn get_confirm_email_change(
    Path(token): Path<String>,
    State(s): State<AppState>,
) -> (StatusCode, axum::response::Html<String>) {
    let mut users = s.users.write().unwrap();
    let result = users.iter_mut().find(|u| {
        u.verify_token.as_deref()
            .map(|t| t.starts_with(&format!("email_change:{}:", token)))
            .unwrap_or(false)
    }).map(|u| {
        let new_email = u.verify_token.as_deref().unwrap_or("")
            .splitn(3, ':').nth(2).unwrap_or("").to_string();
        u.email = new_email.clone();
        u.verify_token = None;
        new_email
    });
    save_users(&users);
    drop(users);
    match result {
        Some(new_email) => (StatusCode::OK, axum::response::Html(format!(r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Email Updated</title>
<style>body{{font-family:sans-serif;background:#0f172a;color:#e2e8f0;display:flex;
align-items:center;justify-content:center;min-height:100vh;margin:0}}
.card{{background:#1e293b;border-radius:16px;padding:48px;text-align:center;max-width:400px}}
.icon{{font-size:64px}}h1{{color:#34d399}}</style></head>
<body><div class="card"><div class="icon">✅</div>
<h1>Email Updated!</h1>
<p>Your account email is now <strong>{}</strong>.</p>
</div></body></html>"#, new_email))),
        None => (StatusCode::BAD_REQUEST,
            axum::response::Html("<h1>Invalid or expired link.</h1>".into())),
    }
}


async fn get_pin_reset(
    Path(token): Path<String>,
    State(s): State<AppState>,
) -> (StatusCode, axum::response::Html<String>) {
    let now = chrono::Utc::now().timestamp();
    let users = s.users.read().unwrap();
    let valid = users.iter().any(|u| {
        u.pin_reset_token.as_deref() == Some(&token)
            && u.pin_reset_expiry.map(|e| e > now).unwrap_or(false)
    });
    drop(users);
    if valid {
        (StatusCode::OK, axum::response::Html(format!(r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Set New PIN</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:16px}}
.card{{background:#1e293b;border-radius:20px;padding:40px 32px;width:100%;max-width:420px;border:1px solid #334155;box-shadow:0 25px 50px rgba(0,0,0,0.5)}}
.logo{{text-align:center;margin-bottom:24px;font-size:40px}}
h1{{text-align:center;font-size:22px;font-weight:700;margin-bottom:8px}}
.sub{{text-align:center;color:#94a3b8;font-size:14px;margin-bottom:32px}}
label{{display:block;font-size:13px;color:#94a3b8;margin-bottom:6px;margin-top:16px}}
.input-wrap{{position:relative}}
input{{width:100%;background:#0f172a;border:1px solid #334155;border-radius:12px;padding:14px 48px 14px 16px;font-size:15px;color:#e2e8f0;outline:none;transition:border-color .2s}}
input:focus{{border-color:#3b82f6}}
.eye{{position:absolute;right:14px;top:50%;transform:translateY(-50%);background:none;border:none;color:#64748b;cursor:pointer;font-size:18px;padding:4px;line-height:1}}
.eye:hover{{color:#94a3b8}}
.strength{{height:4px;border-radius:2px;margin-top:8px;transition:all .3s;background:#334155;overflow:hidden}}
.strength-bar{{height:100%;border-radius:2px;transition:all .3s;width:0}}
.strength-label{{font-size:11px;color:#64748b;margin-top:4px;text-align:right}}
button.submit{{width:100%;margin-top:24px;background:#3b82f6;color:white;border:none;border-radius:12px;padding:15px;font-size:16px;font-weight:600;cursor:pointer;transition:background .2s}}
button.submit:hover{{background:#2563eb}}
button.submit:disabled{{background:#334155;color:#64748b;cursor:not-allowed}}
.msg{{margin-top:16px;padding:12px 16px;border-radius:10px;font-size:13px;text-align:center;display:none}}
.msg.error{{background:#450a0a;border:1px solid #7f1d1d;color:#fca5a5;display:block}}
.msg.success{{background:#052e16;border:1px solid #14532d;color:#86efac;display:block}}
.match-icon{{position:absolute;right:48px;top:50%;transform:translateY(-50%);font-size:14px}}
</style></head>
<body>
<div class="card">
  <div class="logo">🔐</div>
  <h1>Set New PIN</h1>
  <p class="sub">Choose a new security PIN for your Ego Wallet</p>

  <label>New PIN</label>
  <div class="input-wrap">
    <input type="password" id="pin1" placeholder="Enter new PIN" oninput="checkStrength()" autocomplete="new-password"/>
    <button class="eye" onclick="toggle('pin1','eye1')" type="button"><span id="eye1">👁</span></button>
  </div>
  <div class="strength"><div class="strength-bar" id="sbar"></div></div>
  <div class="strength-label" id="slabel"></div>

  <label>Confirm PIN</label>
  <div class="input-wrap">
    <input type="password" id="pin2" placeholder="Confirm your PIN" oninput="checkMatch()" autocomplete="new-password"/>
    <span class="match-icon" id="match-icon"></span>
    <button class="eye" onclick="toggle('pin2','eye2')" type="button"><span id="eye2">👁</span></button>
  </div>

  <div class="msg" id="msg"></div>
  <button class="submit" id="btn" onclick="submit()" disabled>Set PIN</button>
</div>
<script>
const TOKEN = '{token}';
function toggle(id, eyeId) {{
  const el = document.getElementById(id);
  const eye = document.getElementById(eyeId);
  if (el.type === 'password') {{ el.type = 'text'; eye.textContent = '🙈'; }}
  else {{ el.type = 'password'; eye.textContent = '👁'; }}
}}
function checkStrength() {{
  const v = document.getElementById('pin1').value;
  const bar = document.getElementById('sbar');
  const lbl = document.getElementById('slabel');
  let score = 0;
  if (v.length >= 4) score++;
  if (v.length >= 8) score++;
  if (/[0-9]/.test(v) && /[a-zA-Z]/.test(v)) score++;
  if (/[^a-zA-Z0-9]/.test(v)) score++;
  const colors = ['#ef4444','#f97316','#eab308','#22c55e'];
  const labels = ['Too short','Weak','Good','Strong'];
  if (v.length === 0) {{ bar.style.width='0'; lbl.textContent=''; }}
  else {{ bar.style.width=(score*25)+'%'; bar.style.background=colors[score-1]||colors[0]; lbl.textContent=labels[score-1]||labels[0]; }}
  checkMatch();
}}
function checkMatch() {{
  const p1 = document.getElementById('pin1').value;
  const p2 = document.getElementById('pin2').value;
  const icon = document.getElementById('match-icon');
  const btn = document.getElementById('btn');
  if (p2.length === 0) {{ icon.textContent=''; btn.disabled=true; return; }}
  if (p1 === p2 && p1.length >= 4) {{ icon.textContent='✅'; btn.disabled=false; }}
  else {{ icon.textContent='❌'; btn.disabled=true; }}
}}
async function submit() {{
  const pin = document.getElementById('pin1').value;
  const btn = document.getElementById('btn');
  const msg = document.getElementById('msg');
  if (pin.length < 4) {{ showMsg('PIN must be at least 4 characters.', false); return; }}
  btn.disabled = true; btn.textContent = 'Saving…';
  try {{
    const r = await fetch('/users/pin-reset-confirm', {{
      method: 'POST',
      headers: {{'Content-Type':'application/json'}},
      body: JSON.stringify({{ token: TOKEN, new_pin_hash: pin }})
    }});
    const d = await r.json();
    if (d.success) {{
      showMsg('✅ PIN updated! You can close this window.', true);
      btn.textContent = 'Done';
    }} else {{
      showMsg(d.message || 'Error. Please try again.', false);
      btn.disabled = false; btn.textContent = 'Set PIN';
    }}
  }} catch {{ showMsg('Network error. Please try again.', false); btn.disabled=false; btn.textContent='Set PIN'; }}
}}
function showMsg(text, ok) {{
  const msg = document.getElementById('msg');
  msg.textContent = text;
  msg.className = 'msg ' + (ok ? 'success' : 'error');
}}
</script>
</body></html>"#, token = token)))
    } else {
        (StatusCode::BAD_REQUEST, axum::response::Html(r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Invalid Link</title>
<style>body{{font-family:sans-serif;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh}}
.card{{background:#1e293b;border-radius:16px;padding:48px;text-align:center;max-width:400px;border:1px solid #7f1d1d}}
h1{{color:#f87171}}</style></head>
<body><div class="card"><div style="font-size:48px">❌</div>
<h1>Invalid or Expired Link</h1>
<p style="color:#94a3b8;margin-top:12px">This PIN reset link has expired or already been used.</p>
</div></body></html>"#.into()))
    }
}


#[derive(Debug, Deserialize)]
struct PinResetConfirmRequest {
    token: String,
    new_pin_hash: String,
}

async fn post_pin_reset_confirm(
    State(s): State<AppState>,
    Json(req): Json<PinResetConfirmRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    let now = chrono::Utc::now().timestamp();
    let mut users = s.users.write().unwrap();
    if let Some(user) = users.iter_mut().find(|u| {
        u.pin_reset_token.as_deref() == Some(&req.token)
            && u.pin_reset_expiry.map(|e| e > now).unwrap_or(false)
    }) {
        // Store new PIN alongside confirmed marker so app can retrieve and apply it
        user.pin_reset_token  = Some(format!("confirmed:{}:{}", req.token, req.new_pin_hash));
        user.pin_reset_expiry = Some(now + 300);
        save_users(&users);
        (StatusCode::OK, Json(ApiResponse { success: true, message: "PIN reset confirmed.".into() }))
    } else {
        (StatusCode::BAD_REQUEST, Json(ApiResponse { success: false, message: "Invalid or expired token.".into() }))
    }
}

async fn get_pin_reset_status(
    Path(address): Path<String>,
    State(s): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    let users = s.users.read().unwrap();
    let token_val = users.iter().find(|u| u.address == address)
        .and_then(|u| u.pin_reset_token.clone());
    drop(users);

    if let Some(ref t) = token_val {
        if t.starts_with("confirmed:") {
            // Extract new PIN: format is "confirmed:{token}:{pin}"
            let parts: Vec<&str> = t.splitn(3, ':').collect();
            let new_pin = if parts.len() == 3 { parts[2].to_string() } else { String::new() };
            // Clear token so it can only be used once
            let mut users = s.users.write().unwrap();
            if let Some(u) = users.iter_mut().find(|u| u.address == address) {
                u.pin_reset_token  = None;
                u.pin_reset_expiry = None;
                save_users(&users);
            }
            return (StatusCode::OK, Json(serde_json::json!({
                "confirmed": true,
                "new_pin": new_pin
            })));
        }
    }
    (StatusCode::OK, Json(serde_json::json!({ "confirmed": false })))
}

fn load_or_create_identity() -> libp2p::identity::Keypair {
    let path = "relay_identity.bin";
    if let Ok(bytes) = fs::read(path) {
        if let Ok(kp) = libp2p::identity::Keypair::from_protobuf_encoding(&bytes) {
            return kp;
        }
    }
    let kp = libp2p::identity::Keypair::generate_ed25519();
    if let Ok(bytes) = kp.to_protobuf_encoding() {
        fs::write(path, bytes).expect("write identity");
    }
    kp
}
