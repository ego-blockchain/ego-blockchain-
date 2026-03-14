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
    extract::{ConnectInfo, Path, State},
    http::{HeaderValue, Method, StatusCode},
    routing::{get, post},
    Json, Router,
};
use std::net::SocketAddr;
use ed25519_dalek::{Verifier, VerifyingKey};
use pqcrypto_dilithium::dilithium2;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as PqPublicKey};
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
    /// Which shard produced this block. Default=0 for legacy blocks.
    #[serde(default)]
    shard_id:   u32,
    /// Coinbase TX hash — the miner self-issues their block reward.
    /// None for genesis and relay-mined blocks (legacy).
    #[serde(default)]
    coinbase_tx: Option<String>,
}

/// A node that claims to hold a specific CID (registered via POST /shard/:id/cid).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CidHolder {
    cid:           String,
    holder_addr:   String,
    endpoint:      String,
    shard_id:      u32,
    registered_at: i64,
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
    /// Hex-encoded Ed25519 public key — kept for backward compat.
    #[serde(default)]
    public_key_ed25519: String,
    /// Hex-encoded Dilithium2 public key (1312 bytes = 2624 hex chars).
    /// Mathematically derives the egot1 address — quantum-safe ownership proof.
    #[serde(default)]
    dilithium_pubkey: String,
    /// Hex-encoded Dilithium2 detached signature over canonical tx bytes.
    #[serde(default)]
    dilithium_signature: String,
    /// Which shard (0–SHARD_COUNT-1) this tx belongs to.  Default=0 for old clients.
    #[serde(default)]
    shard_id: u32,
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


type PocState = Arc<RwLock<Vec<PocEventRecord>>>;

/// Sender for gossip publishes pushed from HTTP handlers into the swarm loop.
/// Holds (topic_string, message_bytes).
static RELAY_GOSSIP_TX: OnceLock<tokio_mpsc::UnboundedSender<(String, Vec<u8>)>> =
    OnceLock::new();

// ── Persistent chain storage ──────────────────────────────────────────────────

const CHAIN_PATH: &str = "chain.json";

/// The genesis block is hardcoded — identical on every relay and every desktop node.
/// No one controls it; it is defined by the source code.
const GENESIS_HASH: &str  = "ego00000000000000000000000000000000000000000000000000000000genesis1";
const GENESIS_MINER: &str = "ego1genesis000000000000000000000000000000000000";
const GENESIS_TS: i64     = 1_741_910_400; // 2026-03-14 00:00:00 UTC — chain birth

fn genesis_block() -> LedgerBlock {
    LedgerBlock {
        height:     0,
        hash:       GENESIS_HASH.into(),
        prev_hash:  "0000000000000000000000000000000000000000000000000000000000000000".into(),
        timestamp:  GENESIS_TS,
        miner:      GENESIS_MINER.into(),
        tx_count:   0,
        size_bytes: 0,
        reward:     0,
        shard_id:   0,
        coinbase_tx: None,
    }
}

fn load_chain() -> SharedChain {
    if let Ok(data) = fs::read_to_string(CHAIN_PATH) {
        if let Ok(chain) = serde_json::from_str::<SharedChain>(&data) {
            if !chain.blocks.is_empty() {
                return chain;
            }
        }
    }
    // Fresh chain — seed with hardcoded genesis block
    let mut chain = SharedChain::default();
    chain.blocks.push(genesis_block());
    save_chain(&chain);
    chain
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
type PendingState     = Arc<RwLock<Vec<PendingTx>>>;
type KeyRegistryState = Arc<RwLock<HashMap<String, String>>>;
type ShardPoolState    = Arc<RwLock<HashMap<u32, Vec<LedgerTx>>>>;
/// cid → vec of holders (multiple nodes can hold the same CID).
type CidRegistryState  = Arc<RwLock<HashMap<String, Vec<CidHolder>>>>;

// ── Rate limiter ──────────────────────────────────────────────────────────────
//
// Fixed-window per-IP counter. No extra crates needed.
// Each protected endpoint gets its own limiter with independent limits.

struct RateLimiter {
    /// ip_string → (hit_count, window_start_unix_secs)
    windows: std::sync::RwLock<HashMap<String, (u32, i64)>>,
    /// Max hits allowed per window.
    limit: u32,
    /// Window size in seconds.
    window_secs: i64,
}

impl RateLimiter {
    fn new(limit: u32, window_secs: i64) -> Arc<Self> {
        Arc::new(Self {
            windows: std::sync::RwLock::new(HashMap::new()),
            limit,
            window_secs,
        })
    }

    /// Returns true if the request is allowed, false if rate-limited.
    fn check(&self, ip: &str) -> bool {
        let now = chrono::Utc::now().timestamp();
        let mut map = self.windows.write().unwrap();
        let entry = map.entry(ip.to_string()).or_insert((0, now));
        if now - entry.1 >= self.window_secs {
            // New window — reset counter.
            *entry = (1, now);
            true
        } else if entry.0 < self.limit {
            entry.0 += 1;
            true
        } else {
            false
        }
    }

    /// Periodically call this to evict stale windows and prevent unbounded growth.
    fn evict_stale(&self) {
        let now = chrono::Utc::now().timestamp();
        let mut map = self.windows.write().unwrap();
        map.retain(|_, (_, start)| now - *start < self.window_secs * 10);
    }
}

type RateLimiterState = Arc<RateLimiter>;

const CID_REGISTRY_PATH: &str = "cid_registry.json";

fn load_cid_registry() -> HashMap<String, Vec<CidHolder>> {
    std::fs::read_to_string(CID_REGISTRY_PATH)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_cid_registry(reg: &HashMap<String, Vec<CidHolder>>) {
    if let Ok(data) = serde_json::to_string_pretty(reg) {
        let _ = std::fs::write(CID_REGISTRY_PATH, data);
    }
}

// ── PoRep / PoST data model ───────────────────────────────────────────────────

const POREP_REGISTRY_PATH: &str = "porep_registry.json";
const POST_CHALLENGES_PATH: &str = "post_challenges.json";

/// Number of Merkle proofs the prover must supply per PoST window.
const POST_N_CHALLENGES: usize = 8;
/// PoST window duration in seconds (30 minutes, matches desktop).
const POST_WINDOW_SECS: i64 = 30 * 60;
/// How many windows without a proof before we mark the sector as faulted.
const POST_FAULT_AFTER_WINDOWS: i64 = 3;

// ── EGOC Tokenomics ───────────────────────────────────────────────────────────

/// Hard cap: 1 billion EGOC = 1 × 10¹⁵ uEGOC.
const TOTAL_SUPPLY_UEGOC:         u64 = 1_000_000_000_000_000;
const POOL_GENESIS_UEGOC:         u64 = 150_000_000_000_000; // 15 % — pre-mined genesis
const POOL_BLOCK_UEGOC:           u64 = 300_000_000_000_000; // 30 % — block rewards
const POOL_STORAGE_UEGOC:         u64 = 250_000_000_000_000; // 25 % — PoST storage rewards
const POOL_COVERAGE_UEGOC:        u64 = 200_000_000_000_000; // 20 % — PoC coverage rewards
const POOL_ECOSYSTEM_UEGOC:       u64 = 100_000_000_000_000; // 10 % — ecosystem / grants
/// Per-block reward for desktop miners (before halving).
const INITIAL_BLOCK_REWARD_UEGOC: u64 = 50_000_000;          // 50 EGOC
/// Halving every 2.1 M blocks per shard (≈ 2 years at ~30 s target block time).
const HALVING_INTERVAL:           u64 = 2_100_000;
/// Minimum combined DRS required for block-mining eligibility.
const MIN_DRS:                    f64 = 0.5;

// ── Stake registry ────────────────────────────────────────────────────────────

const STAKE_REGISTRY_PATH: &str = "stake_registry.json";

/// An address's reported stake amount, updated when the desktop calls POST /stake/update.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StakeRecord {
    address:      String,
    amount_uegoc: u64,
    updated_at:   i64,
}

type StakeRegistryState = Arc<RwLock<HashMap<String, StakeRecord>>>;

fn load_stake_registry() -> HashMap<String, StakeRecord> {
    std::fs::read_to_string(STAKE_REGISTRY_PATH)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_stake_registry(reg: &HashMap<String, StakeRecord>) {
    if let Ok(data) = serde_json::to_string_pretty(reg) {
        let _ = std::fs::write(STAKE_REGISTRY_PATH, data);
    }
}

/// A registered PoRep commitment for one stored file.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PoRepSector {
    cid:             String,
    prover_addr:     String,
    /// Merkle root of the encrypted file (hex, 64 chars).
    comm_d:          String,
    /// H(comm_d ‖ replica_id ‖ "ego/porep/v1") (hex).
    comm_r:          String,
    n_real_leaves:   usize,
    n_padded_leaves: usize,
    sector_id:       u64,
    file_size:       u64,
    registered_at:   i64,
    expiry:          i64,
    last_challenged: Option<i64>,
    last_proved:     Option<i64>,
    windows_proved:  u64,
    windows_missed:  u64,
    status:          String, // "active" | "faulted" | "expired"
}

/// A pending PoST challenge issued by the relay for one sector.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PostChallenge {
    challenge_id:    String,
    cid:             String,
    prover_addr:     String,
    comm_d:          String,
    n_real_leaves:   usize,
    n_padded_leaves: usize,
    /// 32-byte random seed (hex) — deterministically selects which leaves to prove.
    challenge_seed:  String,
    issued_at:       i64,
    /// Unix deadline: prover must respond before this time.
    deadline:        i64,
}

fn load_porep_registry() -> HashMap<String, PoRepSector> {
    std::fs::read_to_string(POREP_REGISTRY_PATH)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_porep_registry(reg: &HashMap<String, PoRepSector>) {
    if let Ok(data) = serde_json::to_string_pretty(reg) {
        let _ = std::fs::write(POREP_REGISTRY_PATH, data);
    }
}

fn load_post_challenges() -> HashMap<String, Vec<PostChallenge>> {
    // Key: prover_addr → pending challenges for that prover
    std::fs::read_to_string(POST_CHALLENGES_PATH)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_post_challenges(chs: &HashMap<String, Vec<PostChallenge>>) {
    if let Ok(data) = serde_json::to_string_pretty(chs) {
        let _ = std::fs::write(POST_CHALLENGES_PATH, data);
    }
}

// ── PoST Merkle-proof verification (mirrors proof.rs in desktop) ──────────────
//
// We duplicate the tiny verification logic here rather than import the desktop
// crate — keeps the relay as a single self-contained binary.

fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

fn blake3_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

/// Verify one Merkle proof against a registered root.
fn verify_merkle_proof(
    leaf_index:  u64,
    leaf:        &[u8; 32],
    path:        &[[u8; 32]],
    root:        &[u8; 32],
    n_padded:    usize,
) -> bool {
    let mut current = *leaf;
    let mut pos     = n_padded as u64 + leaf_index;
    for sibling in path {
        current = if pos % 2 == 0 {
            blake3_pair(&current, sibling)
        } else {
            blake3_pair(sibling, &current)
        };
        pos /= 2;
    }
    &current == root
}

/// Derive challenge leaf indices from a seed (identical to desktop `derive_challenge_indices`).
fn derive_challenge_indices(seed: &[u8; 32], n_real: usize) -> Vec<u64> {
    (0..POST_N_CHALLENGES).map(|i| {
        let mut h = blake3::Hasher::new();
        h.update(seed);
        h.update(&(i as u64).to_le_bytes());
        let raw = u64::from_le_bytes(h.finalize().as_bytes()[..8].try_into().unwrap());
        raw % n_real as u64
    }).collect()
}

/// Verify all POST_N_CHALLENGES proofs against comm_d + challenge_seed.
fn verify_post_proofs(
    proofs_json:    &[serde_json::Value],
    comm_d:         &[u8; 32],
    challenge_seed: &[u8; 32],
    n_real:         usize,
    n_padded:       usize,
) -> bool {
    if proofs_json.len() != POST_N_CHALLENGES { return false; }
    let expected_indices = derive_challenge_indices(challenge_seed, n_real);
    for (proof_val, &expected_idx) in proofs_json.iter().zip(expected_indices.iter()) {
        let leaf_index = match proof_val["leaf_index"].as_u64() { Some(v) => v, None => return false };
        if leaf_index != expected_idx { return false; }
        let leaf_hex  = match proof_val["leaf"].as_str()         { Some(v) => v, None => return false };
        let path_arr  = match proof_val["path"].as_array()       { Some(v) => v, None => return false };
        let leaf_bytes = match hex::decode(leaf_hex).ok().and_then(|b| b.try_into().ok()) {
            Some(arr) => arr,
            None      => return false,
        };
        let path_bytes: Option<Vec<[u8; 32]>> = path_arr.iter().map(|h| {
            h.as_str()
                .and_then(|s| hex::decode(s).ok())
                .and_then(|b| b.try_into().ok())
        }).collect();
        let path = match path_bytes { Some(p) => p, None => return false };
        if !verify_merkle_proof(leaf_index, &leaf_bytes, &path, comm_d, n_padded) {
            return false;
        }
    }
    true
}

type PoRepState      = Arc<RwLock<HashMap<String, PoRepSector>>>;
type PostChalState   = Arc<RwLock<HashMap<String, Vec<PostChallenge>>>>;

// ── Combined DRS (Deterministic Reward Scoring) ───────────────────────────────────
//
// DRS = 0.40 × poc_score + 0.40 × post_score + 0.20 × stake_score
//
// poc_score   = Σ quality_pts(last 24 h) × ln(1 + event_count_24h)
// post_score  = active_sectors × proof_ratio × ln(1 + total_GB)
// stake_score = ln(1 + staked_EGOC / 100)

#[derive(Debug, Clone, Copy)]
struct DrsComponents {
    combined: f64,
    poc:      f64,
    post:     f64,
    stake:    f64,
}

fn compute_combined_drs(
    address:        &str,
    poc_events:     &[PocEventRecord],
    porep_sectors:  &HashMap<String, PoRepSector>,
    stake_registry: &HashMap<String, StakeRecord>,
) -> DrsComponents {
    let now    = chrono::Utc::now().timestamp();
    let cutoff = now - 86_400;

    // ── PoC component (40 %) ──────────────────────────────────────────────
    let poc_recent: Vec<&PocEventRecord> = poc_events.iter()
        .filter(|e| e.address == address && e.timestamp >= cutoff)
        .collect();
    let poc_score = if poc_recent.is_empty() {
        0.0_f64
    } else {
        let pts: u32 = poc_recent.iter().map(|e| quality_score(&e.quality)).sum();
        pts as f64 * (1.0_f64 + poc_recent.len() as f64).ln()
    };

    // ── PoST component (40 %) ─────────────────────────────────────────────
    let sectors: Vec<&PoRepSector> = porep_sectors.values()
        .filter(|s| s.prover_addr == address && s.status == "active")
        .collect();
    let active      = sectors.len() as f64;
    let total_bytes: u64 = sectors.iter().map(|s| s.file_size).sum();
    let total_gb    = total_bytes as f64 / 1_000_000_000.0;
    let proved:  f64 = sectors.iter().map(|s| s.windows_proved).sum::<u64>() as f64;
    let total_w: f64 = sectors.iter()
        .map(|s| s.windows_proved + s.windows_missed)
        .sum::<u64>() as f64;
    let ratio       = if total_w > 0.0 { proved / total_w } else { 0.0 };
    let post_score  = active * ratio * (1.0 + total_gb).ln();

    // ── Stake component (20 %) ────────────────────────────────────────────
    let staked_uegoc = stake_registry.get(address)
        .map(|r| r.amount_uegoc)
        .unwrap_or(0) as f64;
    let staked_egoc  = staked_uegoc / 1_000_000.0;
    let stake_score  = (1.0 + staked_egoc / 100.0).ln();

    DrsComponents {
        combined: 0.40 * poc_score + 0.40 * post_score + 0.20 * stake_score,
        poc:      poc_score,
        post:     post_score,
        stake:    stake_score,
    }
}

/// Number of shards. Each shard processes transactions independently.
/// Increase this as validator count grows (target: 1 shard per ~25 validators).
const SHARD_COUNT: u32 = 4;

/// Derive a shard ID from a wallet address string.
/// Uses the same XOR-fold algorithm as ego-core::calculate_shard_for_address
/// so desktop clients and the relay always agree on shard assignment.
fn shard_for_address(address: &str) -> u32 {
    let mut h: u32 = 0;
    for (i, b) in address.bytes().enumerate() {
        h ^= (b as u32) << (8 * (i % 4));
    }
    h % SHARD_COUNT
}

const KEY_REGISTRY_PATH: &str = "key_registry.json";

fn load_key_registry() -> HashMap<String, String> {
    std::fs::read_to_string(KEY_REGISTRY_PATH)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_key_registry(reg: &HashMap<String, String>) {
    if let Ok(data) = serde_json::to_string_pretty(reg) {
        let _ = std::fs::write(KEY_REGISTRY_PATH, data);
    }
}

#[derive(Clone)]
struct AppState {
    chain:          ChainState,
    peers:          PeersState,
    inbox:          InboxState,
    users:          UsersState,
    pending:        PendingState,
    poc_events:     PocState,
    key_registry:   KeyRegistryState,
    shard_pools:    ShardPoolState,
    cid_registry:   CidRegistryState,
    /// PoRep sector commitments — keyed by CID.
    porep_sectors:  PoRepState,
    /// Pending PoST challenges — keyed by prover_addr.
    post_challenges: PostChalState,
    /// Stake amounts reported by desktop nodes after staking — keyed by address.
    stake_registry:  StakeRegistryState,
    rl_inbox:       RateLimiterState, // 20 req/min — POST /inbox
    rl_cid:         RateLimiterState, // 60 req/min — POST /shard/:id/cid
    rl_register:    RateLimiterState, // 5  req/min — POST /users/register
    rl_tx_pending:  RateLimiterState, // 10 req/min — POST /tx/pending
    mailer:         Arc<AsyncSmtpTransport<Tokio1Executor>>,
    config:         Arc<Config>,
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

    let signing_bytes = tx_signing_bytes(&tx.from, &tx.to, tx.amount, tx.nonce, tx.timestamp);

    // ── 2a. Dilithium2 signature verification (quantum-safe, preferred) ───
    // Required when dilithium_pubkey is present (all new clients send both).
    // The Dilithium public key mathematically derives the egot1 address,
    // so a valid Dilithium signature is a complete proof of address ownership.
    let has_dilithium = !tx.dilithium_pubkey.is_empty() && !tx.dilithium_signature.is_empty();
    if has_dilithium {
        let pk_bytes = match hex::decode(&tx.dilithium_pubkey) {
            Ok(b) if b.len() == 1312 => b,
            _ => {
                println!("[chain] Rejected tx {}: invalid Dilithium pubkey", tx.hash);
                return StatusCode::BAD_REQUEST;
            }
        };
        let sig_bytes = match hex::decode(&tx.dilithium_signature) {
            Ok(b) if b.len() == 2420 => b,
            _ => {
                println!("[chain] Rejected tx {}: invalid Dilithium signature", tx.hash);
                return StatusCode::BAD_REQUEST;
            }
        };
        let pk  = match dilithium2::PublicKey::from_bytes(&pk_bytes) {
            Ok(k) => k,
            Err(_) => {
                println!("[chain] Rejected tx {}: malformed Dilithium pubkey", tx.hash);
                return StatusCode::BAD_REQUEST;
            }
        };
        let sig = match dilithium2::DetachedSignature::from_bytes(&sig_bytes) {
            Ok(s) => s,
            Err(_) => {
                println!("[chain] Rejected tx {}: malformed Dilithium signature", tx.hash);
                return StatusCode::BAD_REQUEST;
            }
        };
        if dilithium2::verify_detached_signature(&sig, &signing_bytes, &pk).is_err() {
            println!("[chain] Rejected tx {}: Dilithium signature invalid", tx.hash);
            return StatusCode::UNAUTHORIZED;
        }
    }

    // ── 2b. Ed25519 signature verification (kept for backward compat) ─────
    // Still verified when present. Old clients (pre-quantum upgrade) send only this.
    if !tx.public_key_ed25519.is_empty() && !tx.signature.is_empty() {
        let pk_bytes = match hex::decode(&tx.public_key_ed25519) {
            Ok(b) if b.len() == 32 => b,
            _ => {
                println!("[chain] Rejected tx {}: invalid Ed25519 pubkey", tx.hash);
                return StatusCode::BAD_REQUEST;
            }
        };
        let pk_arr: [u8; 32] = pk_bytes.try_into().unwrap();
        let verifying_key = match VerifyingKey::from_bytes(&pk_arr) {
            Ok(k) => k,
            Err(_) => {
                println!("[chain] Rejected tx {}: invalid Ed25519 key", tx.hash);
                return StatusCode::BAD_REQUEST;
            }
        };
        let sig_bytes = match hex::decode(&tx.signature) {
            Ok(b) if b.len() == 64 => b,
            _ => {
                println!("[chain] Rejected tx {}: invalid Ed25519 signature hex", tx.hash);
                return StatusCode::BAD_REQUEST;
            }
        };
        let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        if verifying_key.verify(&signing_bytes, &sig).is_err() {
            println!("[chain] Rejected tx {}: Ed25519 signature invalid", tx.hash);
            return StatusCode::UNAUTHORIZED;
        }
    } else if !has_dilithium {
        // Neither signature present — reject.
        println!("[chain] Rejected tx {}: no signature provided", tx.hash);
        return StatusCode::BAD_REQUEST;
    }

    // ── 3. Address → key binding ──────────────────────────────────────────
    // Prefer binding to the Dilithium key (address IS derived from Dilithium pubkey —
    // this makes the binding cryptographically tight, not just first-come-first-served).
    // Fall back to Ed25519 binding for old clients.
    {
        let mut registry = s.key_registry.write().unwrap();
        let binding_key = if has_dilithium { &tx.dilithium_pubkey } else { &tx.public_key_ed25519 };
        match registry.get(&tx.from) {
            Some(bound_key) if bound_key != binding_key => {
                println!("[chain] Rejected tx {}: key mismatch for address {}", tx.hash, tx.from);
                return StatusCode::UNAUTHORIZED;
            }
            None => {
                registry.insert(tx.from.clone(), binding_key.clone());
                save_key_registry(&registry);
                let short = &binding_key[..16.min(binding_key.len())];
                println!("[chain] Bound address {} → {} key {}…",
                    tx.from,
                    if has_dilithium { "Dilithium" } else { "Ed25519" },
                    short);
            }
            Some(_) => {}
        }
    }

    // ── 4. Timestamp freshness (reject if older than 10 minutes) ─────────
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
    tx.status  = "Confirmed".to_string();
    tx.shard_id = shard_for_address(&tx.from);

    let is_cross_shard = shard_for_address(&tx.to) != tx.shard_id;

    if let Some(existing) = chain.transactions.iter_mut().find(|t| t.hash == tx.hash) {
        if existing.status != "Confirmed" {
            existing.status  = "Confirmed".to_string();
            existing.shard_id = tx.shard_id;
            save_chain(&chain);
        }
    } else {
        println!(
            "[chain] ✓ Verified tx {} shard={}{} from {} → {} ({} uEGOC)",
            tx.hash, tx.shard_id,
            if is_cross_shard { " (cross-shard)" } else { "" },
            tx.from, tx.to, tx.amount
        );
        // Gossip to all connected desktop peers
        if let Some(gtx) = RELAY_GOSSIP_TX.get() {
            let stub_block = LedgerBlock { height: 0, hash: String::new(), prev_hash: String::new(),
                timestamp: 0, miner: String::new(), tx_count: 1, size_bytes: 0, reward: 0, shard_id: tx.shard_id, coinbase_tx: None };
            if let Ok(bytes) = serde_json::to_vec(&serde_json::json!({
                "type": "tx_broadcast",
                "tx": &tx,
                "block": stub_block,
            })) {
                let _ = gtx.send(("ego-txs-v1".to_string(), bytes));
            }
        }
        // Route into the sender's shard pool (cap at 50K per shard)
        {
            let mut pools = s.shard_pools.write().unwrap();
            let pool = pools.entry(tx.shard_id).or_default();
            pool.push(tx.clone());
            if pool.len() > 50_000 {
                pool.drain(0..1_000); // evict oldest 1K entries on overflow
            }
        }
        let from_shard = tx.shard_id;
        let to_shard   = shard_for_address(&tx.to);
        let tx_hash    = tx.hash.clone();
        chain.transactions.push(tx);
        save_chain(&chain);
        drop(chain); // release write lock before gossip

        // Gossip a cross-shard receipt so destination-shard validators learn
        // about incoming transfers (foundation for future shard finalisation).
        if is_cross_shard {
            if let Some(gtx) = RELAY_GOSSIP_TX.get() {
                if let Ok(bytes) = serde_json::to_vec(&serde_json::json!({
                    "type": "cross_shard_receipt",
                    "from_shard": from_shard,
                    "to_shard":   to_shard,
                    "tx_hash":    tx_hash,
                })) {
                    let _ = gtx.send(("ego-shards-v1".to_string(), bytes));
                }
            }
        }
    }
    StatusCode::OK
}

async fn post_block(
    State(s): State<AppState>,
    Json(block): Json<LedgerBlock>,
) -> StatusCode {
    // ── DRS gate ──────────────────────────────────────────────────────────────
    // After bootstrap (≥ POC_BOOTSTRAP_THRESHOLD active PoC validators) a miner
    // must have combined_DRS ≥ MIN_DRS, driven by PoC + PoST performance.
    // Staking is NOT a hard requirement — it contributes 20% to DRS score
    // (more stake = higher DRS = larger reward share) but does not block mining.
    {
        let poc   = s.poc_events.read().unwrap();
        let unique_validators = poc.iter()
            .map(|e| e.address.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len();
        if unique_validators >= POC_BOOTSTRAP_THRESHOLD {
            let porep = s.porep_sectors.read().unwrap();
            let stake = s.stake_registry.read().unwrap();
            let drs = compute_combined_drs(&block.miner, &poc, &porep, &stake);
            if drs.combined < MIN_DRS {
                println!("[chain] Rejected block #{} from {}: DRS {:.4} < {:.2} (validators={})",
                    block.height, block.miner, drs.combined, MIN_DRS, unique_validators);
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

    // ── Coinbase validation ────────────────────────────────────────────────────
    // If the block carries a coinbase_tx, verify the miner paid themselves
    // exactly the correct halving-era reward and that the block pool cap holds.
    if let Some(ref cb_hash) = block.coinbase_tx {
        let era = block.height / HALVING_INTERVAL;
        let expected_reward = INITIAL_BLOCK_REWARD_UEGOC >> era.min(63);
        // Find the coinbase TX in the submitted transactions
        let cb_tx = chain.transactions.iter().find(|t| &t.hash == cb_hash);
        if let Some(tx) = cb_tx {
            if tx.to != block.miner {
                println!("[chain] Rejected block #{}: coinbase recipient {} != miner {}",
                    block.height, tx.to, block.miner);
                return StatusCode::FORBIDDEN;
            }
            if tx.amount != expected_reward {
                println!("[chain] Rejected block #{}: coinbase amount {} != expected {}",
                    block.height, tx.amount, expected_reward);
                return StatusCode::FORBIDDEN;
            }
            // Pool cap check
            let already_issued = pool_emitted(&chain, "block reward");
            if already_issued + expected_reward > POOL_BLOCK_UEGOC {
                println!("[chain] Rejected block #{}: block reward pool exhausted", block.height);
                return StatusCode::FORBIDDEN;
            }
        } else {
            println!("[chain] Rejected block #{}: coinbase TX {} not found", block.height, cb_hash);
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

/// Hard limit: inbox messages carrying file data must go P2P, not through the relay.
/// This prevents the relay from being overwhelmed at scale (1M users × multi-MB files).
const INBOX_FILE_SIZE_LIMIT: usize = 512 * 1024; // 512 KB

async fn post_inbox(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(address): Path<String>,
    State(s): State<AppState>,
    Json(msg): Json<InboxMessage>,
) -> StatusCode {
    if !s.rl_inbox.check(&addr.ip().to_string()) {
        return StatusCode::TOO_MANY_REQUESTS;
    }
    if address.is_empty() || (msg.payload.is_empty() && msg.disk_path.is_none()) {
        return StatusCode::BAD_REQUEST;
    }
    // Reject large file payloads — FileData must travel P2P, not through the relay.
    // The desktop falls back here only for small control messages (FileRequest, etc.).
    if msg.payload.len() > INBOX_FILE_SIZE_LIMIT {
        // Check if it looks like a FileData message (contains enc_data_b64)
        if msg.payload.contains("\"file_data\"") || msg.payload.contains("enc_data_b64") {
            eprintln!("[inbox] Rejected large FileData ({} bytes) for {} — must use P2P",
                msg.payload.len(), address);
            return StatusCode::PAYLOAD_TOO_LARGE;
        }
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
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(s): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    if !s.rl_register.check(&addr.ip().to_string()) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(ApiResponse {
            success: false, message: "Too many registration attempts".into(),
        }));
    }
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
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(s): State<AppState>,
    Json(req): Json<PendingTxRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    if !s.rl_tx_pending.check(&addr.ip().to_string()) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(ApiResponse {
            success: false, message: "Too many requests".into(),
        }));
    }
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

// ── Per-shard block miner ─────────────────────────────────────────────────────

const RELAY_MINER_ADDR: &str = "egot1relay000000000000000000000000000000000000";
const SHARD_BLOCK_INTERVAL_SECS: u64 = 5;

/// Mine one block per shard from confirmed-but-unblocked txs in that shard pool.
/// Called from a background tokio task every SHARD_BLOCK_INTERVAL_SECS.
fn mine_shard_block(chain: &mut SharedChain, shard_id: u32) -> Option<LedgerBlock> {
    // Collect indices of confirmed txs in this shard without a block_height
    let unblocked_hashes: Vec<String> = chain.transactions.iter()
        .filter(|t| t.shard_id == shard_id && t.status == "Confirmed" && t.block_height.is_none())
        .map(|t| t.hash.clone())
        .collect();

    if unblocked_hashes.is_empty() { return None; }

    // Next height for this shard
    let height = chain.blocks.iter()
        .filter(|b| b.shard_id == shard_id)
        .map(|b| b.height)
        .max()
        .map(|h| h + 1)
        .unwrap_or(1);

    let prev_hash = chain.blocks.iter()
        .filter(|b| b.shard_id == shard_id)
        .max_by_key(|b| b.height)
        .map(|b| b.hash.clone())
        .unwrap_or_else(|| GENESIS_HASH.into());

    let now        = chrono::Utc::now().timestamp();
    let tx_count   = unblocked_hashes.len() as u32;
    let size_bytes = chain.transactions.iter()
        .filter(|t| unblocked_hashes.contains(&t.hash))
        .map(|t| t.amount.to_string().len() as u64 + 200)
        .sum::<u64>();

    // Block hash = hex of XOR-fold of all tx hashes + height + shard_id
    let hash_input = format!("{shard_id}:{height}:{prev_hash}:{now}");
    let block_hash = format!("{:016x}", hash_input.bytes()
        .enumerate()
        .fold(height ^ (shard_id as u64 * 0xDEAD_BEEF), |acc, (i, b)| {
            acc ^ ((b as u64) << (8 * (i % 8)))
        }));

    // Block reward with halving: reward halves every HALVING_INTERVAL blocks.
    let era           = height / HALVING_INTERVAL;
    let block_reward  = INITIAL_BLOCK_REWARD_UEGOC >> era.min(63);

    let block = LedgerBlock {
        height,
        hash:       block_hash.clone(),
        prev_hash,
        timestamp:  now,
        miner:      RELAY_MINER_ADDR.into(),
        tx_count,
        size_bytes,
        reward:     block_reward,
        shard_id,
        coinbase_tx: None,
    };

    // Assign block_height to all txs in this block
    for tx in chain.transactions.iter_mut() {
        if unblocked_hashes.contains(&tx.hash) {
            tx.block_height = Some(height);
        }
    }

    chain.blocks.push(block.clone());
    Some(block)
}

/// Spawn one background task per shard to periodically mine blocks.
fn start_shard_miners(state: AppState) {
    for shard_id in 0..SHARD_COUNT {
        let state2 = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                std::time::Duration::from_secs(SHARD_BLOCK_INTERVAL_SECS)
            );
            loop {
                interval.tick().await;
                let block = {
                    let mut chain = state2.chain.write().unwrap();
                    let blk = mine_shard_block(&mut chain, shard_id);
                    if blk.is_some() { save_chain(&chain); }
                    blk
                };
                if let Some(blk) = block {
                    println!("[shard-{shard_id}] Mined block #{} ({} txs)", blk.height, blk.tx_count);
                    // Gossip the new block so desktop peers update their chain
                    if let Some(gtx) = RELAY_GOSSIP_TX.get() {
                        if let Ok(bytes) = serde_json::to_vec(&serde_json::json!({
                            "type": "chain_sync_response",
                            "blocks": [&blk],
                            "transactions": [],
                        })) {
                            let _ = gtx.send(("ego-blocks-v1".to_string(), bytes));
                        }
                    }
                }
            }
        });
    }
}

// ── Shard endpoints ───────────────────────────────────────────────────────────

/// GET /shards — overview of all shards with tx counts and cross-shard stats.
async fn get_shards(State(s): State<AppState>) -> Json<serde_json::Value> {
    let pools = s.shard_pools.read().unwrap();
    let chain = s.chain.read().unwrap();
    let shards: Vec<serde_json::Value> = (0..SHARD_COUNT).map(|id| {
        let pending   = pools.get(&id).map(|v| v.len()).unwrap_or(0);
        let confirmed = chain.transactions.iter()
            .filter(|t| t.shard_id == id && t.status == "Confirmed")
            .count();
        let cross_out = chain.transactions.iter()
            .filter(|t| t.shard_id == id && shard_for_address(&t.to) != id && t.status == "Confirmed")
            .count();
        serde_json::json!({
            "shard_id":          id,
            "pending_txs":       pending,
            "confirmed_txs":     confirmed,
            "cross_shard_out":   cross_out,
        })
    }).collect();

    let total_confirmed: usize = shards.iter()
        .map(|s| s["confirmed_txs"].as_u64().unwrap_or(0) as usize)
        .sum();
    let total_cross: usize = shards.iter()
        .map(|s| s["cross_shard_out"].as_u64().unwrap_or(0) as usize)
        .sum();

    Json(serde_json::json!({
        "shard_count":       SHARD_COUNT,
        "total_confirmed":   total_confirmed,
        "total_cross_shard": total_cross,
        "shards":            shards,
    }))
}

/// GET /shard/:id/txs — all transactions routed to a specific shard.
async fn get_shard_txs(
    Path(id): Path<u32>,
    State(s): State<AppState>,
) -> Result<Json<Vec<LedgerTx>>, StatusCode> {
    if id >= SHARD_COUNT { return Err(StatusCode::NOT_FOUND); }
    let pools = s.shard_pools.read().unwrap();
    Ok(Json(pools.get(&id).cloned().unwrap_or_default()))
}

/// GET /shard/:id/stats — detailed stats for a single shard.
async fn get_shard_stats(
    Path(id): Path<u32>,
    State(s): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if id >= SHARD_COUNT { return Err(StatusCode::NOT_FOUND); }
    let chain = s.chain.read().unwrap();

    let confirmed_txs: Vec<&LedgerTx> = chain.transactions.iter()
        .filter(|t| t.shard_id == id && t.status == "Confirmed")
        .collect();

    let volume_uegoc: u64 = confirmed_txs.iter().map(|t| t.amount).sum();
    let cross_out = confirmed_txs.iter()
        .filter(|t| shard_for_address(&t.to) != id)
        .count();
    let cross_in = chain.transactions.iter()
        .filter(|t| t.shard_id != id && shard_for_address(&t.to) == id && t.status == "Confirmed")
        .count();

    // Rough TPS: confirmed txs / elapsed seconds since first tx in this shard
    let tps = {
        let first_ts = confirmed_txs.iter().map(|t| t.timestamp).min().unwrap_or(0);
        let last_ts  = confirmed_txs.iter().map(|t| t.timestamp).max().unwrap_or(0);
        let elapsed  = (last_ts - first_ts).max(1) as f64;
        confirmed_txs.len() as f64 / elapsed
    };

    Ok(Json(serde_json::json!({
        "shard_id":        id,
        "confirmed_txs":   confirmed_txs.len(),
        "volume_uegoc":    volume_uegoc,
        "cross_shard_out": cross_out,
        "cross_shard_in":  cross_in,
        "tps_lifetime":    (tps * 100.0).round() / 100.0,
        "shard_count":     SHARD_COUNT,
    })))
}

/// Signed CID registration request — prevents strangers from poisoning the registry.
/// The Ed25519 signature proves the submitter controls the holder_addr key.
#[derive(Debug, Deserialize)]
struct RegisterCidRequest {
    cid:         String,
    holder_addr: String,
    endpoint:    String,
    timestamp:   i64,
    /// Ed25519 hex signature over "cid:holder_addr:timestamp"
    signature:   String,
    /// Hex-encoded Ed25519 public key (32 bytes = 64 hex chars)
    public_key:  String,
}

/// POST /shard/:id/cid — register that this node holds a specific CID.
/// Requires a valid Ed25519 signature to prevent registry poisoning.
async fn post_shard_cid(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(id): Path<u32>,
    State(s): State<AppState>,
    Json(req): Json<RegisterCidRequest>,
) -> StatusCode {
    if !s.rl_cid.check(&addr.ip().to_string()) {
        return StatusCode::TOO_MANY_REQUESTS;
    }
    if id >= SHARD_COUNT || req.cid.is_empty() || req.holder_addr.is_empty() {
        return StatusCode::BAD_REQUEST;
    }
    // Verify timestamp freshness (±5 minutes)
    let now = chrono::Utc::now().timestamp();
    if (now - req.timestamp).abs() > 300 {
        return StatusCode::BAD_REQUEST;
    }
    // Verify Ed25519 signature over "cid:holder_addr:timestamp"
    let sign_bytes = format!("{}:{}:{}", req.cid, req.holder_addr, req.timestamp).into_bytes();
    let pk_bytes = match hex::decode(&req.public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => return StatusCode::BAD_REQUEST,
    };
    let pk_arr: [u8; 32] = pk_bytes.try_into().unwrap();
    let verifying_key = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(k) => k,
        Err(_) => return StatusCode::BAD_REQUEST,
    };
    let sig_bytes = match hex::decode(&req.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => return StatusCode::BAD_REQUEST,
    };
    let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    if verifying_key.verify(&sign_bytes, &sig).is_err() {
        println!("[shard-{id}] Rejected CID registration from {}: bad signature", addr.ip());
        return StatusCode::UNAUTHORIZED;
    }
    let mut reg = s.cid_registry.write().unwrap();
    let holders = reg.entry(req.cid.clone()).or_default();
    if let Some(existing) = holders.iter_mut().find(|h| h.holder_addr == req.holder_addr) {
        existing.endpoint      = req.endpoint.clone();
        existing.registered_at = now;
    } else {
        holders.push(CidHolder {
            cid:           req.cid.clone(),
            holder_addr:   req.holder_addr.clone(),
            endpoint:      req.endpoint.clone(),
            shard_id:      id,
            registered_at: now,
        });
        println!("[shard-{id}] CID registered: {} by {}", &req.cid[..16.min(req.cid.len())], req.holder_addr);
    }
    save_cid_registry(&reg);
    StatusCode::OK
}

/// GET /shard/:id/cid/:cid — find all nodes that hold a specific CID.
/// Desktop uses this to discover file holders it doesn't have as contacts.
async fn get_shard_cid(
    Path((id, cid)): Path<(u32, String)>,
    State(s): State<AppState>,
) -> Result<Json<Vec<CidHolder>>, StatusCode> {
    if id >= SHARD_COUNT { return Err(StatusCode::NOT_FOUND); }
    let reg = s.cid_registry.read().unwrap();
    let holders = reg.get(&cid)
        .map(|v| v.iter().filter(|h| h.shard_id == id).cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    Ok(Json(holders))
}

/// GET /shard/:id/files — list all CIDs registered on this shard (for explorer/debugging).
async fn get_shard_files(
    Path(id): Path<u32>,
    State(s): State<AppState>,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
    if id >= SHARD_COUNT { return Err(StatusCode::NOT_FOUND); }
    let reg = s.cid_registry.read().unwrap();
    let files: Vec<serde_json::Value> = reg.iter()
        .filter_map(|(cid, holders)| {
            let shard_holders: Vec<_> = holders.iter()
                .filter(|h| h.shard_id == id)
                .collect();
            if shard_holders.is_empty() { return None; }
            Some(serde_json::json!({
                "cid":          cid,
                "holder_count": shard_holders.len(),
                "holders":      shard_holders.iter().map(|h| &h.holder_addr).collect::<Vec<_>>(),
            }))
        })
        .collect();
    Ok(Json(files))
}

// ── PoRep / PoST HTTP handlers ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct PoRepCommitRequest {
    cid:             String,
    prover_addr:     String,
    comm_d:          String,
    comm_r:          String,
    n_real_leaves:   usize,
    n_padded_leaves: usize,
    sector_id:       u64,
    file_size:       u64,
    expiry:          i64,
    timestamp:       i64,
    signature:       String,
    public_key:      String,
}

/// POST /porep/commit — register a PoRep sector commitment.
/// Requires an Ed25519 signature over "cid:comm_d:timestamp" to prevent spoofing.
async fn post_porep_commit(
    State(s): State<AppState>,
    Json(req): Json<PoRepCommitRequest>,
) -> StatusCode {
    if req.cid.is_empty() || req.prover_addr.is_empty()
        || req.comm_d.len() != 64 || req.comm_r.len() != 64
        || req.n_real_leaves == 0
    {
        return StatusCode::BAD_REQUEST;
    }
    // Freshness check ±5 minutes
    let now = chrono::Utc::now().timestamp();
    if (now - req.timestamp).abs() > 300 {
        return StatusCode::BAD_REQUEST;
    }
    // Verify signature over "cid:comm_d:timestamp"
    let sign_bytes = format!("{}:{}:{}", req.cid, req.comm_d, req.timestamp).into_bytes();
    let pk_bytes: [u8; 32] = match hex::decode(&req.public_key)
        .ok().and_then(|b| b.try_into().ok())
    {
        Some(arr) => arr,
        None => return StatusCode::BAD_REQUEST,
    };
    let verifying_key = match VerifyingKey::from_bytes(&pk_bytes) {
        Ok(k)  => k,
        Err(_) => return StatusCode::BAD_REQUEST,
    };
    let sig_bytes: [u8; 64] = match hex::decode(&req.signature)
        .ok().and_then(|b| b.try_into().ok())
    {
        Some(arr) => arr,
        None => return StatusCode::BAD_REQUEST,
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    if verifying_key.verify(&sign_bytes, &sig).is_err() {
        println!("[porep] Rejected commit from {}: bad signature", req.prover_addr);
        return StatusCode::UNAUTHORIZED;
    }
    // Verify comm_r = blake3(comm_d || replica_id || "ego/porep/v1")
    // where replica_id = blake3(prover_addr:cid)
    {
        let comm_d_bytes: [u8; 32] = match hex::decode(&req.comm_d)
            .ok().and_then(|b| b.try_into().ok())
        {
            Some(arr) => arr,
            None => return StatusCode::BAD_REQUEST,
        };
        let replica_id = {
            let mut h = blake3::Hasher::new();
            h.update(req.prover_addr.as_bytes());
            h.update(b":");
            h.update(req.cid.as_bytes());
            *h.finalize().as_bytes()
        };
        let expected_comm_r = {
            let mut h = blake3::Hasher::new();
            h.update(&comm_d_bytes);
            h.update(&replica_id);
            h.update(b"ego/porep/v1");
            *h.finalize().as_bytes()
        };
        if hex::encode(expected_comm_r) != req.comm_r {
            println!("[porep] Rejected commit: comm_r mismatch for {}", req.cid);
            return StatusCode::BAD_REQUEST;
        }
    }

    let sector = PoRepSector {
        cid:             req.cid.clone(),
        prover_addr:     req.prover_addr.clone(),
        comm_d:          req.comm_d.clone(),
        comm_r:          req.comm_r.clone(),
        n_real_leaves:   req.n_real_leaves,
        n_padded_leaves: req.n_padded_leaves,
        sector_id:       req.sector_id,
        file_size:       req.file_size,
        registered_at:   now,
        expiry:          req.expiry,
        last_challenged: None,
        last_proved:     None,
        windows_proved:  0,
        windows_missed:  0,
        status:          "active".into(),
    };

    {
        let mut reg = s.porep_sectors.write().unwrap();
        let is_new  = !reg.contains_key(&req.cid);
        reg.insert(req.cid.clone(), sector);
        save_porep_registry(&reg);
        if is_new {
            println!("[porep] ✓ New sector: {} prover={} leaves={}",
                &req.cid[..16.min(req.cid.len())], req.prover_addr, req.n_real_leaves);
        }
    }
    StatusCode::OK
}

/// GET /post/challenges/:address — return pending PoST challenges for a prover.
async fn get_post_challenges(
    Path(address): Path<String>,
    State(s): State<AppState>,
) -> Json<Vec<PostChallenge>> {
    let map = s.post_challenges.read().unwrap();
    let now = chrono::Utc::now().timestamp();
    let challenges: Vec<PostChallenge> = map.get(&address)
        .map(|v| v.iter().filter(|c| c.deadline > now).cloned().collect())
        .unwrap_or_default();
    Json(challenges)
}

#[derive(Debug, Deserialize)]
struct PostProofRequest {
    challenge_id:    String,
    cid:             String,
    prover_addr:     String,
    comm_d:          String,
    n_real_leaves:   usize,
    n_padded_leaves: usize,
    proofs:          Vec<serde_json::Value>, // MerkleProof JSON objects
    timestamp:       i64,
    signature:       String,
    public_key:      String,
}

/// POST /post/proof — submit Merkle proofs in response to a PoST challenge.
/// Relay verifies proofs, marks sector as proved, issues storage reward TX.
async fn post_post_proof(
    State(s): State<AppState>,
    Json(req): Json<PostProofRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    // Freshness ±5 min
    let now = chrono::Utc::now().timestamp();
    if (now - req.timestamp).abs() > 300 {
        return (StatusCode::BAD_REQUEST, Json(ApiResponse {
            success: false, message: "Timestamp out of range".into() }));
    }
    // Signature over "challenge_id:cid:timestamp"
    let sign_bytes = format!("{}:{}:{}", req.challenge_id, req.cid, req.timestamp).into_bytes();
    let pk_arr: [u8; 32] = match hex::decode(&req.public_key)
        .ok().and_then(|b| b.try_into().ok())
    {
        Some(a) => a, None => return (StatusCode::BAD_REQUEST, Json(ApiResponse {
            success: false, message: "Invalid public key".into() })),
    };
    let vk = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(k)  => k,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(ApiResponse {
            success: false, message: "Bad public key".into() })),
    };
    let sig_arr: [u8; 64] = match hex::decode(&req.signature)
        .ok().and_then(|b| b.try_into().ok())
    {
        Some(a) => a, None => return (StatusCode::BAD_REQUEST, Json(ApiResponse {
            success: false, message: "Invalid signature".into() })),
    };
    if vk.verify(&sign_bytes, &ed25519_dalek::Signature::from_bytes(&sig_arr)).is_err() {
        return (StatusCode::UNAUTHORIZED, Json(ApiResponse {
            success: false, message: "Signature invalid".into() }));
    }
    // Find the pending challenge
    let challenge_seed_hex = {
        let map = s.post_challenges.read().unwrap();
        let ch  = map.get(&req.prover_addr)
            .and_then(|v| v.iter().find(|c| c.challenge_id == req.challenge_id))
            .cloned();
        match ch {
            Some(c) if c.deadline > now => c.challenge_seed.clone(),
            Some(_) => return (StatusCode::GONE, Json(ApiResponse {
                success: false, message: "Challenge expired".into() })),
            None => return (StatusCode::NOT_FOUND, Json(ApiResponse {
                success: false, message: "Challenge not found".into() })),
        }
    };
    // Decode comm_d and challenge_seed
    let comm_d: [u8; 32] = match hex::decode(&req.comm_d)
        .ok().and_then(|b| b.try_into().ok())
    {
        Some(a) => a, None => return (StatusCode::BAD_REQUEST, Json(ApiResponse {
            success: false, message: "Invalid comm_d".into() })),
    };
    let seed: [u8; 32] = match hex::decode(&challenge_seed_hex)
        .ok().and_then(|b| b.try_into().ok())
    {
        Some(a) => a, None => return (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse {
            success: false, message: "Internal: bad seed".into() })),
    };
    // Verify Merkle proofs
    if !verify_post_proofs(&req.proofs, &comm_d, &seed, req.n_real_leaves, req.n_padded_leaves) {
        println!("[post] ✗ Proof INVALID for {} prover={}", &req.cid[..16.min(req.cid.len())], req.prover_addr);
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(ApiResponse {
            success: false, message: "Proof verification failed".into() }));
    }
    // Mark proved + remove challenge
    let reward_uegoc = {
        let mut reg = s.porep_sectors.write().unwrap();
        if let Some(sector) = reg.get_mut(&req.cid) {
            sector.last_proved    = Some(now);
            sector.windows_proved += 1;
            if sector.status == "faulted" { sector.status = "active".into(); }
        }
        save_porep_registry(&reg);
        // Reward = 0.5 EGOC / GB / day ≈ per 30-min window:
        //   file_size_bytes * 0.5 EGOC/GB/day * (1 day/48 windows) * 1_000_000 uEGOC/EGOC
        //   = file_size * 0.5 / 1e9 / 48 * 1e6 = file_size * 10416 / 1e9
        let file_size = reg.get(&req.cid).map(|s| s.file_size).unwrap_or(0);
        (file_size as f64 * 10_416.0 / 1_000_000_000.0).max(10.0) as u64
    };
    {
        let mut map = s.post_challenges.write().unwrap();
        if let Some(v) = map.get_mut(&req.prover_addr) {
            v.retain(|c| c.challenge_id != req.challenge_id);
        }
        save_post_challenges(&map);
    }
    // Issue storage reward TX from faucet — check pool cap before issuing
    {
        let faucet    = "egot1faucet000000000000000000000000000000000000";
        let mut chain = s.chain.write().unwrap();
        let storage_used = pool_emitted(&chain, "PoST storage reward");
        let supply_used  = total_emitted(&chain);
        let capped_reward = if storage_used + reward_uegoc > POOL_STORAGE_UEGOC
            || supply_used + reward_uegoc > TOTAL_SUPPLY_UEGOC
        {
            println!("[post] Storage pool cap reached: storage_used={} cap={}", storage_used, POOL_STORAGE_UEGOC);
            0
        } else {
            reward_uegoc
        };
        let reward_hash = format!("0xpost-{}-{}", &req.cid[..8.min(req.cid.len())], now);
        if capped_reward > 0 && !chain.transactions.iter().any(|t| t.hash == reward_hash) {
            let nonce = chain.last_nonce(faucet) + 1;
            let bh    = chain.blocks.last().map(|b| b.height);
            chain.transactions.push(LedgerTx {
                hash:               reward_hash.clone(),
                from:               faucet.into(),
                to:                 req.prover_addr.clone(),
                amount:             capped_reward,
                memo:               Some(format!("PoST storage reward ({} window)", &req.cid[..8.min(req.cid.len())])),
                timestamp:          now,
                signature:          "relay-post-reward".into(),
                status:             "Confirmed".into(),
                block_height:       bh,
                nonce,
                public_key_ed25519:  String::new(),
                dilithium_pubkey:    String::new(),
                dilithium_signature: String::new(),
                shard_id: shard_for_address(&req.prover_addr),
            });
            save_chain(&chain);
        }
    }
    println!("[post] ✓ Proved {} prover={} reward={}uEGOC",
        &req.cid[..16.min(req.cid.len())], req.prover_addr, reward_uegoc);
    (StatusCode::OK, Json(ApiResponse {
        success: true,
        message: format!("Proof accepted, reward: {} uEGOC", reward_uegoc),
    }))
}

/// GET /post/score/:address — PoST stats for an address (active sectors, proved windows, etc.)
async fn get_post_score(
    Path(address): Path<String>,
    State(s): State<AppState>,
) -> Json<serde_json::Value> {
    let reg  = s.porep_sectors.read().unwrap();
    let sectors: Vec<&PoRepSector> = reg.values()
        .filter(|sec| sec.prover_addr == address)
        .collect();
    let active  = sectors.iter().filter(|s| s.status == "active").count();
    let proved  = sectors.iter().map(|s| s.windows_proved).sum::<u64>();
    let missed  = sectors.iter().map(|s| s.windows_missed).sum::<u64>();
    let last    = sectors.iter().filter_map(|s| s.last_proved).max();
    Json(serde_json::json!({
        "address":        address,
        "active_sectors": active,
        "proved_windows": proved,
        "fault_count":    missed,
        "last_proved":    last,
    }))
}

/// GET /porep/sectors/:address — list all registered sectors for an address.
async fn get_porep_sectors(
    Path(address): Path<String>,
    State(s): State<AppState>,
) -> Json<Vec<PoRepSector>> {
    let reg = s.porep_sectors.read().unwrap();
    let sectors: Vec<PoRepSector> = reg.values()
        .filter(|sec| sec.prover_addr == address)
        .cloned()
        .collect();
    Json(sectors)
}

/// Background task: issue PoST challenges for all active sectors every 30 minutes.
fn start_post_challenger(state: AppState) {
    tokio::spawn(async move {
        // Stagger first run by 5 minutes so it doesn't coincide with startup.
        tokio::time::sleep(std::time::Duration::from_secs(300)).await;
        let mut interval = tokio::time::interval(
            std::time::Duration::from_secs(POST_WINDOW_SECS as u64)
        );
        loop {
            interval.tick().await;
            let now  = chrono::Utc::now().timestamp();
            let sectors_to_challenge: Vec<PoRepSector> = {
                let reg = state.porep_sectors.read().unwrap();
                reg.values()
                    .filter(|s| s.status == "active" && s.expiry > now)
                    .filter(|s| s.last_challenged.map(|t| now - t >= POST_WINDOW_SECS).unwrap_or(true))
                    .cloned()
                    .collect()
            };
            if sectors_to_challenge.is_empty() { continue; }

            let mut chal_map = state.post_challenges.write().unwrap();
            let mut reg      = state.porep_sectors.write().unwrap();
            let mut issued   = 0u32;

            for sector in &sectors_to_challenge {
                // Generate 32-byte random challenge seed.
                let mut seed = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);

                let challenge = PostChallenge {
                    challenge_id:    uuid::Uuid::new_v4().to_string(),
                    cid:             sector.cid.clone(),
                    prover_addr:     sector.prover_addr.clone(),
                    comm_d:          sector.comm_d.clone(),
                    n_real_leaves:   sector.n_real_leaves,
                    n_padded_leaves: sector.n_padded_leaves,
                    challenge_seed:  hex::encode(seed),
                    issued_at:       now,
                    deadline:        now + POST_WINDOW_SECS,
                };

                chal_map
                    .entry(sector.prover_addr.clone())
                    .or_default()
                    .push(challenge);

                // Update last_challenged and detect missed windows.
                if let Some(sec) = reg.get_mut(&sector.cid) {
                    if let Some(last_ch) = sec.last_challenged {
                        if let Some(last_pr) = sec.last_proved {
                            if last_pr < last_ch {
                                // Previous challenge was not answered in time.
                                sec.windows_missed += 1;
                                if sec.windows_missed as i64 >= POST_FAULT_AFTER_WINDOWS {
                                    sec.status = "faulted".into();
                                    println!("[post] Sector {} FAULTED ({}x missed)",
                                        &sec.cid[..16.min(sec.cid.len())], sec.windows_missed);
                                }
                            }
                        } else {
                            // Never proved — count as missed if challenged before.
                            sec.windows_missed += 1;
                        }
                    }
                    sec.last_challenged = Some(now);
                }
                issued += 1;
            }
            save_post_challenges(&chal_map);
            save_porep_registry(&reg);
            if issued > 0 {
                println!("[post] Issued {} PoST challenge(s)", issued);
            }
        }
    });
}

/// Sum all confirmed faucet emissions whose memo starts with `memo_prefix`.
/// Used to enforce per-pool emission caps.
fn pool_emitted(chain: &SharedChain, memo_prefix: &str) -> u64 {
    let faucet = "egot1faucet000000000000000000000000000000000000";
    chain.transactions.iter()
        .filter(|t| t.from == faucet && t.status == "Confirmed")
        .filter(|t| t.memo.as_deref().map(|m| m.starts_with(memo_prefix)).unwrap_or(false))
        .map(|t| t.amount)
        .sum()
}

/// Sum all confirmed faucet emissions (total circulating supply from faucet).
fn total_emitted(chain: &SharedChain) -> u64 {
    let faucet = "egot1faucet000000000000000000000000000000000000";
    chain.transactions.iter()
        .filter(|t| t.from == faucet && t.status == "Confirmed")
        .map(|t| t.amount)
        .sum()
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

    // 5. Emit coverage reward tx — check pool cap before issuing
    let reward = {
        let chain_read = s.chain.read().unwrap();
        let coverage_used = pool_emitted(&chain_read, "PoC coverage reward");
        let supply_used   = total_emitted(&chain_read);
        if coverage_used + reward > POOL_COVERAGE_UEGOC || supply_used + reward > TOTAL_SUPPLY_UEGOC {
            println!("[poc] Pool cap reached for {}: coverage_used={} cap={}", req.address, coverage_used, POOL_COVERAGE_UEGOC);
            0 // emit nothing
        } else {
            reward
        }
    };
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
                public_key_ed25519:  String::new(),
                dilithium_pubkey:    String::new(),
                dilithium_signature: String::new(),
                shard_id: shard_for_address(&req.address),
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
    address:         String,
    drs_score:       f64,
    poc_component:   f64,
    post_component:  f64,
    stake_component: f64,
    events_24h:      u32,
    total_events:    u64,
    last_event:      Option<i64>,
    is_validator:    bool,
    validator_rank:  Option<usize>,
}

/// GET /poc/score/:address — combined DRS score and validator status for an address.
async fn get_poc_score(
    Path(address): Path<String>,
    State(s): State<AppState>,
) -> Json<DrsScoreResponse> {
    let events  = s.poc_events.read().unwrap();
    let porep   = s.porep_sectors.read().unwrap();
    let stake   = s.stake_registry.read().unwrap();
    let now     = chrono::Utc::now().timestamp();
    let cutoff  = now - 86_400;
    let events_24h   = events.iter().filter(|e| e.address == address && e.timestamp >= cutoff).count() as u32;
    let total_events = events.iter().filter(|e| e.address == address).count() as u64;
    let last_event   = events.iter().filter(|e| e.address == address).map(|e| e.timestamp).max();
    let drs          = compute_combined_drs(&address, &events, &porep, &stake);
    let drs_score    = drs.combined;

    // Rank among all validators (any address with combined DRS > 0)
    let mut all: Vec<(String, f64)> = events.iter()
        .map(|e| e.address.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .map(|a| { let sc = compute_combined_drs(&a, &events, &porep, &stake).combined; (a, sc) })
        .filter(|(_, sc)| *sc > 0.0)
        .collect();
    all.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let validator_rank = all.iter().position(|(a, _)| *a == address).map(|i| i + 1);

    Json(DrsScoreResponse {
        address,
        drs_score,
        poc_component:   drs.poc,
        post_component:  drs.post,
        stake_component: drs.stake,
        events_24h,
        total_events,
        last_event,
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

/// GET /poc/validators — ranked list of active validators by combined DRS (last 24 h).
async fn get_poc_validators(
    State(s): State<AppState>,
) -> Json<Vec<ValidatorInfo>> {
    let events = s.poc_events.read().unwrap();
    let porep  = s.porep_sectors.read().unwrap();
    let stake  = s.stake_registry.read().unwrap();
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
            drs_score:  compute_combined_drs(addr, &events, &porep, &stake).combined,
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

// ── Stake update + Tokenomics endpoints ──────────────────────────────────────

#[derive(Debug, Deserialize)]
struct StakeUpdateRequest {
    address:      String,
    amount_uegoc: u64,
    timestamp:    i64,
    /// Ed25519 signature over "stake:{address}:{amount_uegoc}:{timestamp}"
    signature:    String,
    public_key:   String,
}

/// POST /stake/update — desktop calls this after staking/unstaking to keep the
/// relay's stake registry up-to-date for DRS scoring.
async fn post_stake_update(
    State(s): State<AppState>,
    Json(req): Json<StakeUpdateRequest>,
) -> StatusCode {
    if req.address.is_empty() { return StatusCode::BAD_REQUEST; }
    // Freshness ±5 min
    let now = chrono::Utc::now().timestamp();
    if (now - req.timestamp).abs() > 300 { return StatusCode::BAD_REQUEST; }
    // Verify Ed25519 signature over "stake:address:amount:timestamp"
    let sign_bytes = format!("stake:{}:{}:{}", req.address, req.amount_uegoc, req.timestamp)
        .into_bytes();
    let pk_arr: [u8; 32] = match hex::decode(&req.public_key)
        .ok().and_then(|b| b.try_into().ok())
    {
        Some(a) => a,
        None    => return StatusCode::BAD_REQUEST,
    };
    let vk = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(k)  => k,
        Err(_) => return StatusCode::BAD_REQUEST,
    };
    let sig_arr: [u8; 64] = match hex::decode(&req.signature)
        .ok().and_then(|b| b.try_into().ok())
    {
        Some(a) => a,
        None    => return StatusCode::BAD_REQUEST,
    };
    if vk.verify(&sign_bytes, &ed25519_dalek::Signature::from_bytes(&sig_arr)).is_err() {
        println!("[stake] Rejected update from {}: bad signature", req.address);
        return StatusCode::UNAUTHORIZED;
    }
    let mut reg = s.stake_registry.write().unwrap();
    reg.insert(req.address.clone(), StakeRecord {
        address:      req.address.clone(),
        amount_uegoc: req.amount_uegoc,
        updated_at:   now,
    });
    save_stake_registry(&reg);
    println!("[stake] Updated: {} → {} uEGOC ({:.4} EGOC)",
        req.address, req.amount_uegoc, req.amount_uegoc as f64 / 1_000_000.0);
    StatusCode::OK
}

/// GET /tokenomics — total supply, emission pools, halving schedule, staking stats.
async fn get_tokenomics(State(s): State<AppState>) -> Json<serde_json::Value> {
    let chain = s.chain.read().unwrap();
    let stake = s.stake_registry.read().unwrap();

    // Circulating supply = confirmed outbound from faucet (genesis + all rewards)
    let faucet = "egot1faucet000000000000000000000000000000000000";
    let emitted: u64 = chain.transactions.iter()
        .filter(|t| t.from == faucet && t.status == "Confirmed")
        .map(|t| t.amount)
        .sum();

    // Block rewards recorded in chain blocks
    let block_rewards_issued: u64 = chain.blocks.iter().map(|b| b.reward).sum();

    // Current halving era (max block height across all shards)
    let max_height = chain.blocks.iter().map(|b| b.height).max().unwrap_or(0);
    let era               = max_height / HALVING_INTERVAL;
    let current_reward    = INITIAL_BLOCK_REWARD_UEGOC >> era.min(63);
    let next_halving_blk  = (era + 1) * HALVING_INTERVAL;
    let blocks_to_halving = next_halving_blk.saturating_sub(max_height);

    // Staking stats
    let total_staked: u64 = stake.values().map(|r| r.amount_uegoc).sum();
    let active_stakers    = stake.values().filter(|r| r.amount_uegoc > 0).count();

    Json(serde_json::json!({
        "total_supply_uegoc":  TOTAL_SUPPLY_UEGOC,
        "total_supply_egoc":   TOTAL_SUPPLY_UEGOC as f64 / 1_000_000.0,
        "circulating_uegoc":   emitted,
        "circulating_egoc":    emitted as f64 / 1_000_000.0,
        "circulating_pct":     if TOTAL_SUPPLY_UEGOC > 0 {
                                   (emitted as f64 / TOTAL_SUPPLY_UEGOC as f64 * 100.0 * 100.0).round() / 100.0
                               } else { 0.0 },
        "emission_pools": {
            "genesis":        { "cap_uegoc": POOL_GENESIS_UEGOC,   "pct": 15 },
            "block_rewards":  { "cap_uegoc": POOL_BLOCK_UEGOC,     "pct": 30 },
            "storage":        { "cap_uegoc": POOL_STORAGE_UEGOC,   "pct": 25 },
            "coverage":       { "cap_uegoc": POOL_COVERAGE_UEGOC,  "pct": 20 },
            "ecosystem":      { "cap_uegoc": POOL_ECOSYSTEM_UEGOC, "pct": 10 },
        },
        "block_rewards_issued_uegoc": block_rewards_issued,
        "halving": {
            "era":                      era,
            "interval_blocks":          HALVING_INTERVAL,
            "current_reward_uegoc":     current_reward,
            "current_reward_egoc":      current_reward as f64 / 1_000_000.0,
            "blocks_to_next_halving":   blocks_to_halving,
            "next_halving_at_block":    next_halving_blk,
            "max_block_height":         max_height,
        },
        "staking": {
            "total_staked_uegoc":  total_staked,
            "total_staked_egoc":   total_staked as f64 / 1_000_000.0,
            "active_stakers":      active_stakers,
        },
        "drs": {
            "min_drs_to_mine":  MIN_DRS,
            "note": "Staking is not required to mine — it boosts DRS (20% weight) for higher reward share",
            "weights": { "poc": 0.40, "post": 0.40, "stake": 0.20 },
        },
    }))
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

    let poc_loaded    = load_poc_events();
    let chain_loaded  = load_chain();

    // Pre-populate per-shard pools from confirmed on-disk transactions so
    // GET /shard/:id/stats shows accurate history on a fresh relay restart.
    let initial_shard_pools: HashMap<u32, Vec<LedgerTx>> = {
        let mut pools: HashMap<u32, Vec<LedgerTx>> = HashMap::new();
        for tx in &chain_loaded.transactions {
            let sid = shard_for_address(&tx.from);
            pools.entry(sid).or_default().push(tx.clone());
        }
        pools
    };

    let state = AppState {
        chain:           Arc::new(RwLock::new(chain_loaded)),
        peers:           Arc::new(RwLock::new(load_peers())),
        inbox:           Arc::new(RwLock::new(HashMap::new())),
        users:           Arc::new(RwLock::new(load_users())),
        pending:         Arc::new(RwLock::new(Vec::new())),
        poc_events:      Arc::new(RwLock::new(poc_loaded)),
        key_registry:    Arc::new(RwLock::new(load_key_registry())),
        shard_pools:     Arc::new(RwLock::new(initial_shard_pools)),
        cid_registry:    Arc::new(RwLock::new(load_cid_registry())),
        porep_sectors:   Arc::new(RwLock::new(load_porep_registry())),
        post_challenges: Arc::new(RwLock::new(load_post_challenges())),
        stake_registry:  Arc::new(RwLock::new(load_stake_registry())),
        rl_inbox:        RateLimiter::new(20,  60),
        rl_cid:          RateLimiter::new(60,  60),
        rl_register:     RateLimiter::new(5,   60),
        rl_tx_pending:   RateLimiter::new(10,  60),
        mailer:          Arc::new(mailer),
        config:          Arc::new(cfg),
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
            // ── Sharding ──
            .route("/shards",               get(get_shards))
            .route("/shard/:id/txs",        get(get_shard_txs))
            .route("/shard/:id/stats",      get(get_shard_stats))
            .route("/shard/:id/files",      get(get_shard_files))
            .route("/shard/:id/cid",        post(post_shard_cid))
            .route("/shard/:id/cid/:cid",   get(get_shard_cid))
            // ── PoRep / PoST ──
            .route("/porep/commit",              post(post_porep_commit))
            .route("/porep/sectors/:address",    get(get_porep_sectors))
            .route("/post/challenges/:address",  get(get_post_challenges))
            .route("/post/proof",                post(post_post_proof))
            .route("/post/score/:address",       get(get_post_score))
            // ── PoC / DRS ──
            .route("/poc/event",            post(post_poc_event))
            .route("/poc/score/:address",   get(get_poc_score))
            .route("/poc/validators",       get(get_poc_validators))
            // ── Staking + Tokenomics ──
            .route("/stake/update",         post(post_stake_update))
            .route("/tokenomics",           get(get_tokenomics))
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
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .await.expect("HTTP server error");
    });

    // Background task: evict stale rate-limiter windows every 60 seconds.
    {
        let rl_inbox      = state.rl_inbox.clone();
        let rl_cid        = state.rl_cid.clone();
        let rl_register   = state.rl_register.clone();
        let rl_tx_pending = state.rl_tx_pending.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                rl_inbox.evict_stale();
                rl_cid.evict_stale();
                rl_register.evict_stale();
                rl_tx_pending.evict_stale();
            }
        });
    }

    // Start PoST challenger: issues Merkle challenges to registered sectors every 30 min.
    start_post_challenger(state.clone());
    println!("[post]  PoST challenger started ({}s window)", POST_WINDOW_SECS);

    // Start one block-mining task per shard (runs every SHARD_BLOCK_INTERVAL_SECS).
    start_shard_miners(state.clone());
    println!("[shard] Started {} per-shard block miners ({}s interval)",
        SHARD_COUNT, SHARD_BLOCK_INTERVAL_SECS);

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
    let shard_topic = gossipsub::IdentTopic::new("ego-shards-v1");
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&tx_topic);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&blk_topic);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&shard_topic);

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
