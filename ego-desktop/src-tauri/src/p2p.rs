use crate::commands::messenger::{load_contacts, save_contacts, Contact};
use crate::ledger::{base_data_dir, load_chain, save_chain, LedgerBlock, LedgerTx, GENESIS_HASH};
use chrono::Utc;
use futures::StreamExt;
use futures::{AsyncReadExt, AsyncWriteExt};
use libp2p::{
    autonat, dcutr, gossipsub, identify, kad, mdns, noise, ping, relay, upnp,
    request_response::{self, OutboundRequestId, ProtocolSupport},
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, StreamProtocol, SwarmBuilder,
};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::{collections::HashMap, io, sync::{Mutex, OnceLock}, time::Duration};
use tauri::Manager;
use tokio::sync::{mpsc, oneshot};

/// Bounded gossip channel — prevents OOM when gossip consumers fall behind.
const GOSSIP_CHANNEL_CAPACITY: usize = 10_000;
static GOSSIP_TX: OnceLock<mpsc::Sender<(String, Vec<u8>)>> = OnceLock::new();

static DEAD_PEER_CACHE: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();
const DEAD_PEER_SILENCE_SECS: i64 = 300;

static RELAY_LAST_DIALED: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();
const RELAY_DIAL_COOLDOWN_SECS: i64 = 30;

fn relay_dial_cooldown() -> std::sync::MutexGuard<'static, HashMap<String, i64>> {
    RELAY_LAST_DIALED.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap()
}

static PEER_CHAIN_PUSH_LAST: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();
const CHAIN_PUSH_COOLDOWN_SECS: i64 = 30;

static PEER_ANNOUNCE_REPLY_LAST: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();
const ANNOUNCE_REPLY_COOLDOWN_SECS: i64 = 60;

static SYNC_REPLY_LAST: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();
const SYNC_REPLY_COOLDOWN_MS: i64 = 1_500;
const CHAIN_PUSH_COOLDOWN_MS: i64 = 100;
const SNAPSHOT_SERVE_MIN_LAG: u64 = 16;

static BLOCK_REJECT_LAST: OnceLock<Mutex<HashMap<(u64, String), i64>>> = OnceLock::new();
const BLOCK_REJECT_LOG_COOLDOWN_SECS: i64 = 30;

fn chain_push_allowed(endpoint: &str) -> bool {
    let now = Utc::now().timestamp_millis();
    let mut map = PEER_CHAIN_PUSH_LAST.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
    let last = map.entry(endpoint.to_string()).or_insert(0);
    if now - *last >= CHAIN_PUSH_COOLDOWN_MS {
        *last = now;
        true
    } else {
        false
    }
}

fn sync_reply_allowed(endpoint: &str) -> bool {
    let now = Utc::now().timestamp_millis();
    let mut map = SYNC_REPLY_LAST.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
    let last = map.entry(endpoint.to_string()).or_insert(0);
    if now - *last >= SYNC_REPLY_COOLDOWN_MS {
        *last = now;
        true
    } else {
        false
    }
}

fn announce_reply_allowed(endpoint: &str) -> bool {
    let now = Utc::now().timestamp();
    let mut map = PEER_ANNOUNCE_REPLY_LAST.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
    let last = map.entry(endpoint.to_string()).or_insert(0);
    if now - *last >= ANNOUNCE_REPLY_COOLDOWN_SECS {
        *last = now;
        true
    } else {
        false
    }
}

fn can_dial_relay(addr: &str) -> bool {
    let now = chrono::Utc::now().timestamp();
    let mut map = relay_dial_cooldown();
    if let Some(&last) = map.get(addr) {
        if now - last < RELAY_DIAL_COOLDOWN_SECS { return false; }
    }
    map.insert(addr.to_string(), now);
    true
}

fn is_peer_silenced(ep: &str) -> bool {
    let now = chrono::Utc::now().timestamp();
    let mut map = DEAD_PEER_CACHE.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
    if let Some(&last) = map.get(ep) {
        if now - last < DEAD_PEER_SILENCE_SECS { return true; }
    }
    map.insert(ep.to_string(), now);
    false
}

static PEER_COMMITMENTS: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

fn peer_commitments() -> std::sync::MutexGuard<'static, HashMap<String, String>> {
    PEER_COMMITMENTS.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap()
}

pub fn get_peer_comm_r(cid: &str) -> Option<String> {
    peer_commitments().get(cid).cloned()
}

fn record_peer_commitment(cid: &str, prover_addr: &str, comm_r: &str, signature: &str) -> bool {
    let sign_input = format!("porep:{}:{}:{}", prover_addr, cid, comm_r);
    let pk_opt = get_peer_ed25519_pubkey(prover_addr);
    if let Some(pk) = pk_opt {
        use ed25519_dalek::{Signature as DS, VerifyingKey, Verifier};
        if let Ok(vk) = VerifyingKey::from_bytes(&pk) {
            let sig_bytes = hex::decode(signature).unwrap_or_default();
            if let Ok(arr) = <[u8; 64]>::try_from(sig_bytes.as_slice()) {
                if vk.verify(sign_input.as_bytes(), &DS::from_bytes(&arr)).is_err() {
                    return false;
                }
            }
        }
    }
    peer_commitments().insert(cid.to_string(), comm_r.to_string());
    true
}

pub static DHT_CMD_TX: OnceLock<mpsc::Sender<DhtCommand>> = OnceLock::new();

pub static APP_HANDLE: OnceLock<tauri::AppHandle<tauri::Wry>> = OnceLock::new();

pub static NETWORK_BEST_HEIGHT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn note_network_height(height: u64) {
    NETWORK_BEST_HEIGHT.fetch_max(height, std::sync::atomic::Ordering::Relaxed);
}

pub static SUSPENDING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static SUSPEND_TS: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
const SUSPEND_GATE_MAX_SECS: i64 = 180;
static POWER_EVENT_TX: OnceLock<tokio::sync::mpsc::UnboundedSender<bool>> = OnceLock::new();

pub fn notify_power_event(going_to_sleep: bool) {
    if let Some(tx) = POWER_EVENT_TX.get() {
        let _ = tx.send(going_to_sleep);
    }
}

pub fn proposing_suspended() -> bool {
    if !SUSPENDING.load(std::sync::atomic::Ordering::Relaxed) {
        return false;
    }
    let now = chrono::Utc::now().timestamp();
    if now - SUSPEND_TS.load(std::sync::atomic::Ordering::Relaxed) >= SUSPEND_GATE_MAX_SECS {
        SUSPENDING.store(false, std::sync::atomic::Ordering::Relaxed);
        return false;
    }
    true
}

pub async fn run_power_event_loop() {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<bool>();
    let _ = POWER_EVENT_TX.set(tx);
    while let Some(sleeping) = rx.recv().await {
        if sleeping {
            SUSPENDING.store(true, std::sync::atomic::Ordering::Relaxed);
            SUSPEND_TS.store(chrono::Utc::now().timestamp(), std::sync::atomic::Ordering::Relaxed);
            eprintln!("[Power] System is suspending — pausing proposing and notifying peers");
            broadcast_validator_leaving().await;
        } else {
            SUSPENDING.store(false, std::sync::atomic::Ordering::Relaxed);
            eprintln!("[Power] System resumed — reconnecting and resyncing");
            bump_payout_floor();
            tokio::spawn(dial_bootstrap_peers());
            tokio::spawn(sync_chain_from_peers());
            let app = APP_HANDLE.get().cloned();
            tokio::spawn(async move { broadcast_peer_announce(app.as_ref()).await; });
            touch_proposal_timestamp();
        }
    }
}

async fn broadcast_validator_leaving() {
    let (my_addr, seed) = match tokio::task::spawn_blocking(|| {
        (crate::ledger::Ledger::load().address, get_ed25519_seed())
    }).await {
        Ok(v) => v,
        Err(_) => return,
    };
    let Some(seed_32) = seed else { return };
    if my_addr.is_empty() { return; }
    let ts = chrono::Utc::now().timestamp();
    let payload = format!("leaving:{}:{}", my_addr, ts);
    let signature = {
        use ed25519_dalek::{Signer, SigningKey};
        hex::encode(SigningKey::from_bytes(&seed_32).sign(payload.as_bytes()).to_bytes())
    };
    let msg = P2PMessage::ValidatorLeaving { address: my_addr, timestamp: ts, signature };
    if let Ok(data) = serde_json::to_vec(&msg) {
        publish_gossip("ego-peers-v1", data).await;
    }
    for p in load_peer_cache().into_iter().filter(|p| !p.endpoint.is_empty()) {
        let msg_clone = msg.clone();
        tokio::spawn(async move { let _ = send_message(&p.endpoint, &msg_clone).await; });
    }
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
}

fn handle_validator_leaving(address: &str, timestamp: i64, signature: &str) {
    if address.is_empty() { return; }
    let local = local_validator_mutex().lock().unwrap().clone();
    if address == local { return; }
    let now = chrono::Utc::now().timestamp();
    if (now - timestamp).abs() > 120 { return; }
    let Some(pk_bytes) = get_peer_ed25519_pubkey(address) else { return };
    use ed25519_dalek::{Signature as DalekSig, Verifier, VerifyingKey};
    let Ok(vk) = VerifyingKey::from_bytes(&pk_bytes) else { return };
    let Ok(sig_bytes) = hex::decode(signature) else { return };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes) else { return };
    let payload = format!("leaving:{}:{}", address, timestamp);
    if vk.verify(payload.as_bytes(), &DalekSig::from_bytes(&sig_arr)).is_err() { return; }
    if validator_last_seen().remove(address).is_some() {
        eprintln!("[Power] Validator {} announced suspend/shutdown — dropped from the live committee", address);
    }
}

static SEED_CACHE: std::sync::RwLock<Option<[u8; 32]>> = std::sync::RwLock::new(None);

pub fn prime_ed25519_seed_cache() {
    eprintln!("[Startup] prime_ed25519_seed_cache: calling load_seed (DPAPI)…");
    let result = crate::ledger::load_seed().ok().flatten().and_then(|b| {
        if b.len() >= 32 { let mut a = [0u8; 32]; a.copy_from_slice(&b[..32]); Some(a) } else { None }
    });
    eprintln!("[Startup] prime_ed25519_seed_cache: seed loaded (found={})", result.is_some());
    if let Ok(mut cache) = SEED_CACHE.write() { *cache = result; }
}

#[derive(Debug)]
pub enum DhtCommand {
    PutPeer { key: String, value: Vec<u8> },
    GetPeers { key: String },

    DialPeer { addr: String },
}

pub fn p2p_port() -> u16 {
    std::env::var("EGO_P2P_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(47393)
}

pub fn https_port() -> u16 {
    std::env::var("EGO_HTTPS_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(47396) // Default to 47396 if not set
}
pub const P2P_PORT: u16 = 47393;

pub const RELAY_NODES: &[&str] = &[
    "/dns4/rpc.egoblockchain.com/tcp/4001/p2p/12D3KooWJ2t1k3nhpsXKxa44eUsggQ9rAzELeVv34Eav8qA5t9y",
    "/dns4/egorelay.egoblockchain.com/tcp/4001/p2p/12D3KooWFFjZdk4nhpsXKxa44eUsggQ9rAzELeVv34Eav8qA5t9y",
    "/dns4/relay2.egoblockchain.com/tcp/4001/p2p/12D3KooWJ2t1k3nhpsXKxa44eUsggQ9rAzELeVv34Eav8qA5t9y",
    "/dns4/relay3.egoblockchain.com/tcp/4001/p2p/12D3KooWK3u2k3nhpsXKxa44eUsggQ9rAzELeVv34Eav8qA5t9y",
    "/dns4/relay4.egoblockchain.com/tcp/4001/p2p/12D3KooWL4v3k3nhpsXKxa44eUsggQ9rAzELeVv34Eav8qA5t9y",
];

/// Always-on, publicly-reachable validator anchors. Unlike RELAY_NODES (circuit
/// relays), these are dialed DIRECTLY — a stable connection that doesn't depend on
/// relay NAT-traversal, so nodes reliably exchange validator announcements + gossip
/// and form a quorum. A node dialing its own address here is harmlessly self-rejected.
pub const BOOTSTRAP_PEERS: &[&str] = &[
    "/ip4/40.233.82.42/tcp/47393/p2p/12D3KooWBJthxzWdKk4FgwKWn98oytdzr9BDnrb6MJ1LynnU3Spz",
];

fn shuffled_relay_nodes() -> Vec<&'static str> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos()
        .hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    let seed = hasher.finish() as usize;
    let mut nodes: Vec<&'static str> = RELAY_NODES.to_vec();
    let n = nodes.len();
    for i in (1..n).rev() {
        let j = (seed.wrapping_add(i.wrapping_mul(6364136223846793005))) % (i + 1);
        nodes.swap(i, j);
    }
    nodes
}

static EGOC_PRICE_USD: std::sync::OnceLock<std::sync::Mutex<f64>> = std::sync::OnceLock::new();

static PRICE_SAMPLES: std::sync::OnceLock<std::sync::Mutex<std::collections::VecDeque<(f64, u64)>>> =
    std::sync::OnceLock::new();

const PRICE_WINDOW: usize = 20;
const ORACLE_STAKE_WEIGHT: u64 = u64::MAX / PRICE_WINDOW as u64;
const MAX_GOSSIP_DEVIATION: f64 = 0.50;

fn price_samples() -> std::sync::MutexGuard<'static, std::collections::VecDeque<(f64, u64)>> {
    PRICE_SAMPLES
        .get_or_init(|| std::sync::Mutex::new(std::collections::VecDeque::with_capacity(PRICE_WINDOW + 1)))
        .lock()
        .unwrap()
}

pub const EGOC_DEFAULT_PRICE_USD: f64 = 2.45;

pub fn get_egoc_price_usd() -> f64 {
    let samples = price_samples();
    if samples.len() >= 3 {
        let total_stake: u64 = samples.iter().map(|(_, s)| *s).sum();
        let half = total_stake / 2;
        let mut sorted: Vec<(f64, u64)> = samples.iter().cloned().collect();
        sorted.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
        let mut cum = 0u64;
        for (price, stake) in &sorted {
            cum += stake;
            if cum >= half { return *price; }
        }
        sorted.last().map(|(p, _)| *p).unwrap_or(EGOC_DEFAULT_PRICE_USD)
    } else {
        *EGOC_PRICE_USD.get_or_init(|| std::sync::Mutex::new(EGOC_DEFAULT_PRICE_USD)).lock().unwrap()
    }
}

fn set_egoc_price_usd(price: f64) {
    if price <= 0.0 { return; }
    *EGOC_PRICE_USD.get_or_init(|| std::sync::Mutex::new(EGOC_DEFAULT_PRICE_USD)).lock().unwrap() = price;
    let mut samples = price_samples();
    samples.push_back((price, ORACLE_STAKE_WEIGHT));
    if samples.len() > PRICE_WINDOW { samples.pop_front(); }
}

pub fn record_gossip_price(price: f64, stake_weight: u64) {
    if price <= 0.0 || price > 1_000_000.0 { return; }
    let baseline = *EGOC_PRICE_USD
        .get_or_init(|| std::sync::Mutex::new(EGOC_DEFAULT_PRICE_USD))
        .lock()
        .unwrap();
    if baseline > 0.0 && (price - baseline).abs() / baseline > MAX_GOSSIP_DEVIATION {
        return;
    }
    let mut samples = price_samples();
    samples.push_back((price, stake_weight.max(1)));
    if samples.len() > PRICE_WINDOW { samples.pop_front(); }
}


// CoinGecko coin IDs to try in order.
const COINGECKO_IDS: &[&str] = &["ego-coin", "egocoin", "egoc"];

pub async fn fetch_and_cache_egoc_price() {
    // Price discovery now relies exclusively on the BFT gossip median weighting
    // via `ego-price-v1`. CoinGecko and Oracle Web2 dependencies are removed.
    let price = tokio::task::spawn_blocking(get_egoc_price_usd).await.unwrap_or(EGOC_DEFAULT_PRICE_USD);
    tracing::debug!("[Price] Network median price: ${:.6}", price);
}


pub const ORACLE_RPCS: &[&str] = &[
    "https://rpc.egoblockchain.com",
    "https://rpc2.egoblockchain.com",
    "https://rpc3.egoblockchain.com",
];


pub const ORACLE_RPC: &str = ORACLE_RPCS[0];

/// Ego Relay HTTP endpoint — alert system (port 4002)
pub const RELAY_RPC: &str = "https://relay.egoblockchain.com:4002";


async fn oracle_get(client: &reqwest::Client, path: &str) -> Option<reqwest::Response> {
    for base in ORACLE_RPCS {
        match client.get(format!("{}{}", base, path)).send().await {
            Ok(r) if r.status().is_success() => return Some(r),
            _ => continue,
        }
    }
    None
}


fn oracle_submit_token() -> Option<String> {
    std::env::var("EGO_ORACLE_SUBMIT_TOKEN").ok().filter(|s| !s.trim().is_empty())
}

/// A designated ARCHIVE writer holds the submit token and pushes EVERY block
/// (belt-and-suspenders indexer). Ordinary nodes don't hold the token and don't
/// need it — see push_block_to_oracle: every node pushes the blocks IT produced,
/// which the oracle accepts on the block's quorum certificate (no shared secret).
pub fn is_oracle_writer() -> bool {
    oracle_submit_token().is_some()
}

/// Feeding the public explorer is on by default. A node contributes exactly the
/// blocks it produced, so total oracle load is ~1 push per block regardless of
/// network size. Set EGO_ORACLE_NO_PUSH=1 to opt a node out entirely.
pub fn oracle_push_enabled() -> bool {
    !std::env::var("EGO_ORACLE_NO_PUSH").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false)
}

async fn oracle_post(client: &reqwest::Client, path: &str, body: &serde_json::Value) {
    let token = oracle_submit_token();
    for base in ORACLE_RPCS {
        let mut req = client.post(format!("{}{}", base, path)).json(body);
        if let Some(ref t) = token {
            req = req.header("X-Ego-Submit-Token", t);
        }
        match req.send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    eprintln!("[Oracle] {}{} accepted (HTTP {})", base, path, status.as_u16());
                    return;
                }
                if status.as_u16() == 401 {
                    eprintln!("[Oracle] {}{} REJECTED 401 — token mismatch (EGO_ORACLE_SUBMIT_TOKEN vs oracle ORACLE_SUBMIT_TOKEN)", base, path);
                } else {
                    let body_txt = resp.text().await.unwrap_or_default();
                    eprintln!("[Oracle] {}{} failed: HTTP {} {}", base, path, status.as_u16(),
                        body_txt.chars().take(160).collect::<String>());
                }
            }
            Err(e) => {
                eprintln!("[Oracle] {}{} unreachable: {}", base, path, e);
            }
        }
    }
}


pub async fn oracle_post_pub(client: &reqwest::Client, path: &str, body: &serde_json::Value) {
    oracle_post(client, path, body).await;
}

pub async fn push_block_to_oracle(block: &crate::ledger::LedgerBlock, txs: &[crate::ledger::LedgerTx]) {
    // Two ways to be allowed to feed the oracle, NEITHER needing a shipped secret:
    //  1. I produced this block (block.miner == my address) — one push per block
    //     across the whole network, and the oracle accepts it on its quorum
    //     certificate (a forged block can't fake the BFT signatures).
    //  2. I'm a designated archive node holding the submit token — pushes all.
    if !oracle_push_enabled() {
        eprintln!("[Oracle] push skipped for block #{}: EGO_ORACLE_NO_PUSH is set", block.height);
        return;
    }
    let my_addr = local_validator_mutex().lock().unwrap().clone();
    let i_produced = !my_addr.is_empty() && block.miner == my_addr;
    let writer = is_oracle_writer();
    if !i_produced && !writer {
        eprintln!(
            "[Oracle] push skipped for block #{}: not producer (miner={}, me={}) and not archive writer",
            block.height, &block.miner[..block.miner.len().min(20)], &my_addr[..my_addr.len().min(20)],
        );
        return;
    }
    eprintln!("[Oracle] pushing block #{} (i_produced={}, writer={})", block.height, i_produced, writer);
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };
    // Re-push the last few ancestors alongside the new block, so a transient
    // submit failure for any of them is backfilled by the very next block —
    // keeps the oracle feed gap-free without waiting for the next snapshot.
    let mut extra_blocks: Vec<serde_json::Value> = Vec::new();
    for back in 1..=4u64 {
        if block.height > back {
            if let Some(parent) = crate::chain_db::get_block_by_height(block.height - back) {
                if let Ok(v) = serde_json::to_value(&parent) {
                    extra_blocks.push(v);
                }
            }
        }
    }
    let body = serde_json::json!({
        "block":        block,
        "blocks":       extra_blocks,
        "transactions": txs,
    });
    oracle_post(&client, "/chain/submit", &body).await;
}

pub static RELAY_CIRCUIT_READY: AtomicBool = AtomicBool::new(false);

pub static IS_PUBLIC_REACHABLE: AtomicBool = AtomicBool::new(false);

static IS_RELAY_SERVER: AtomicBool = AtomicBool::new(false);

pub fn relay_mode_active() -> bool { IS_RELAY_SERVER.load(Ordering::Relaxed) }


static DIRECT_PEER_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);


const MIN_DIRECT_PEERS_RELAY_OPTIONAL: usize = 10;


const MIN_CACHED_PEERS_FOR_DIRECT_BOOT: usize = 5;


static PEER_SEED_VOTES: OnceLock<std::sync::Mutex<std::collections::HashMap<String, u32>>> =
    OnceLock::new();
static PEER_SEED_MSG_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
const SEED_VOTE_WINDOW: usize = 20;


static PENDING_VOTES: std::sync::OnceLock<std::sync::Mutex<HashMap<String, Vec<String>>>> =
    std::sync::OnceLock::new();

fn pending_votes() -> std::sync::MutexGuard<'static, HashMap<String, Vec<String>>> {
    PENDING_VOTES
        .get_or_init(|| std::sync::Mutex::new(HashMap::new()))
        .lock()
        .unwrap()
}

static BLS_SECRET_KEY: OnceLock<blst::min_pk::SecretKey> = OnceLock::new();

static PENDING_BLS_SIGS: std::sync::OnceLock<std::sync::Mutex<HashMap<String, HashMap<String, Vec<u8>>>>> =
    std::sync::OnceLock::new();

fn pending_bls_sigs() -> std::sync::MutexGuard<'static, HashMap<String, HashMap<String, Vec<u8>>>> {
    PENDING_BLS_SIGS
        .get_or_init(|| std::sync::Mutex::new(HashMap::new()))
        .lock()
        .unwrap()
}

static PEER_BLS_PUBKEYS: std::sync::OnceLock<std::sync::Mutex<HashMap<String, Vec<u8>>>> =
    std::sync::OnceLock::new();

fn peer_bls_pubkeys() -> std::sync::MutexGuard<'static, HashMap<String, Vec<u8>>> {
    PEER_BLS_PUBKEYS
        .get_or_init(|| std::sync::Mutex::new(HashMap::new()))
        .lock()
        .unwrap()
}

pub fn get_peer_bls_pubkey_hex(address: &str) -> Option<String> {
    if let Some(b) = peer_bls_pubkeys().get(address) {
        return Some(hex::encode(b));
    }
    if let Some(pk_hex) = crate::chain_db::get_validator_bls_pubkey(address) {
        if let Ok(bytes) = hex::decode(&pk_hex) {
            peer_bls_pubkeys().insert(address.to_string(), bytes);
            return Some(pk_hex);
        }
    }
    None
}

// Protocol transactions (e.g., collateral slash/return) bypassed from the standard mempool.
static PENDING_PROTOCOL_TXS: OnceLock<Mutex<Vec<LedgerTx>>> = OnceLock::new();

pub fn push_protocol_tx(tx: LedgerTx) {
    PENDING_PROTOCOL_TXS.get_or_init(|| Mutex::new(Vec::new())).lock().unwrap().push(tx);
}

// Per-peer available storage advertised via DataManifest gossip.
static PEER_STORAGE: std::sync::OnceLock<std::sync::Mutex<HashMap<String, f64>>> =
    std::sync::OnceLock::new();

fn peer_storage() -> std::sync::MutexGuard<'static, HashMap<String, f64>> {
    PEER_STORAGE
        .get_or_init(|| std::sync::Mutex::new(HashMap::new()))
        .lock()
        .unwrap()
}

/// Returns (total_allocated_gb, total_available_gb, node_count) across all known peers + self.
pub fn get_network_capacity() -> (f64, f64, usize) {
    let ledger     = crate::ledger::Ledger::load();
    let self_addr  = ledger.address.clone();
    let self_used  = ledger.stored_files.iter().map(|f| f.encrypted_size as f64).sum::<f64>() / 1_000_000_000.0;
    let self_alloc = ledger.storage_allocated_bytes as f64 / 1_000_000_000.0;
    let self_avail = (self_alloc - self_used).max(0.0);

    let peers      = peer_storage();
    let peer_avail: f64 = peers.values().sum();
    let peer_count = peers.len();

    let total_avail = self_avail + peer_avail;
    let total_alloc = (total_avail / 0.85).max(self_alloc); // 85% headroom assumption
    let node_count  = peer_count + if self_addr.is_empty() { 0 } else { 1 };
    (total_alloc, total_avail, node_count)
}

static KNOWN_VALIDATORS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
    std::sync::OnceLock::new();

fn known_validators() -> std::sync::MutexGuard<'static, std::collections::HashSet<String>> {
    KNOWN_VALIDATORS
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
        .lock()
        .expect("known_validators lock poisoned")
}



const MAX_VALIDATORS: usize = 1_000_000;


static SLASHED_VALIDATORS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
    std::sync::OnceLock::new();

fn slashed_validators() -> std::sync::MutexGuard<'static, std::collections::HashSet<String>> {
    SLASHED_VALIDATORS
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
        .lock()
        .unwrap()
}

static WRONG_VOTE_COUNTS: std::sync::OnceLock<std::sync::Mutex<HashMap<String, u32>>> =
    std::sync::OnceLock::new();

fn wrong_vote_counts() -> std::sync::MutexGuard<'static, HashMap<String, u32>> {
    WRONG_VOTE_COUNTS
        .get_or_init(|| std::sync::Mutex::new(HashMap::new()))
        .lock()
        .unwrap()
}


static FINALIZED_AT_HEIGHT: std::sync::OnceLock<std::sync::Mutex<HashMap<u64, String>>> =
    std::sync::OnceLock::new();

fn finalized_at_height() -> std::sync::MutexGuard<'static, HashMap<u64, String>> {
    FINALIZED_AT_HEIGHT
        .get_or_init(|| std::sync::Mutex::new(HashMap::new()))
        .lock()
        .unwrap()
}

static HARD_FINALIZED_HEIGHTS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<u64>>> =
    std::sync::OnceLock::new();

fn hard_finalized_heights() -> std::sync::MutexGuard<'static, std::collections::HashSet<u64>> {
    HARD_FINALIZED_HEIGHTS
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
        .lock()
        .unwrap()
}

// Maps (validator_address, block_height) → (first_block_hash, first_signature).
// If they vote a different hash at the same height = equivocation → slash + on-chain proof.
static VOTES_CAST: std::sync::OnceLock<std::sync::Mutex<HashMap<(String, u64), (String, String)>>> =
    std::sync::OnceLock::new();

fn votes_cast() -> std::sync::MutexGuard<'static, HashMap<(String, u64), (String, String)>> {
    VOTES_CAST
        .get_or_init(|| std::sync::Mutex::new(HashMap::new()))
        .lock()
        .unwrap()
}

// Persistent anti-equivocation lock for THIS node's OWN votes: height → the block
// hash this node committed its vote to. Unlike VOTES_CAST (which is wiped per view
// change for liveness), this lock survives view changes and is only released once the
// height is decided (finalized) or pruned as ancient. It guarantees the node casts at
// most ONE effective vote per height, so two conflicting blocks can never each gather
// a quorum — closing the safety hole where the per-view vote-lock wipe let a node vote
// for competing blocks across views and fork the chain at a single height.
static SELF_VOTE_LOCK: std::sync::OnceLock<std::sync::Mutex<HashMap<u64, (u64, String)>>> =
    std::sync::OnceLock::new();

fn self_vote_lock() -> std::sync::MutexGuard<'static, HashMap<u64, (u64, String)>> {
    SELF_VOTE_LOCK
        .get_or_init(|| std::sync::Mutex::new(HashMap::new()))
        .lock()
        .unwrap()
}

// Atomically reserve this node's single vote for `height` on `hash`, as seen in
// `view`. Returns true if the node may vote/broadcast for this block; false if it is
// locked on a DIFFERENT block that it must not abandon.
//
// Equivocation safety vs. liveness: the lock is permanent ONCE the height is decided
// (a block there reached a QC — recorded in finalized_at_height / hard_finalized_heights);
// after that no competing block may ever be voted, so two QCs can never form at one
// height. But while the height is still UNDECIDED, a lock on a block that never reached
// a quorum may be abandoned in favour of a strictly higher view's proposal. This is
// HotStuff's "unlock in a higher view that carries no committed block": without it, two
// nodes that locked different blocks at one height during a transient dueling-proposal
// burst deadlock forever — no QC ever forms, so the old (permanent) lock never frees and
// the chain livelocks in endless view changes. Safe for the small-committee regime: a
// second QC at a height needs this node's own vote, and finalization is recorded
// synchronously, so a node always observes "decided" before it could re-lock.
fn try_lock_self_vote(height: u64, hash: &str, view: u64) -> bool {
    let decided = finalized_at_height().contains_key(&height)
        || hard_finalized_heights().contains(&height);
    let mut lock = self_vote_lock();
    match lock.entry(height) {
        std::collections::hash_map::Entry::Occupied(mut e) => {
            let (locked_view, locked_hash) = e.get().clone();
            if locked_hash == hash {
                if view > locked_view { e.insert((view, hash.to_string())); }
                true
            } else if !decided && view > locked_view {
                eprintln!(
                    "[BFT] Self-vote lock at #{} moved {}…→{}… (view {}>{}, height undecided) — breaking dueling-proposal deadlock",
                    height,
                    &locked_hash[..8.min(locked_hash.len())],
                    &hash[..8.min(hash.len())],
                    view, locked_view,
                );
                e.insert((view, hash.to_string()));
                true
            } else {
                false
            }
        }
        std::collections::hash_map::Entry::Vacant(e) => {
            e.insert((view, hash.to_string()));
            true
        }
    }
}

const WRONG_VOTE_THRESHOLD: u32 = 2;

// ── Validator pubkey registry ──────────────────────────────────────────────────
// Maps validator address → hex-encoded ML-DSA-44 (Dilithium2) public key.
// Populated on PeerAnnounce. Used to verify BFT vote signatures.
static VALIDATOR_PUBKEYS: std::sync::OnceLock<std::sync::Mutex<HashMap<String, String>>> =
    std::sync::OnceLock::new();

fn validator_pubkeys() -> std::sync::MutexGuard<'static, HashMap<String, String>> {
    VALIDATOR_PUBKEYS
        .get_or_init(|| std::sync::Mutex::new(HashMap::new()))
        .lock()
        .unwrap()
}

/// Construct the v2 `ConsensusHost` (the `ego-consensus-core` BftEngine) that DRIVES the
/// live chain by default. Built from the local keypair plus the LIVE validator set (self +
/// recently-seen peers), each mapped to its engine `Address` via its Dilithium public key
/// (the default post-quantum scheme). Returns `None` until we have our own identity AND a
/// quorum-sized set with known Dilithium keys — below that the chain halts (no solo fork).
pub fn build_shadow_consensus_host() -> Option<crate::consensus_host::ConsensusHost> {
    use crate::consensus_host::{address_from_dilithium, build_validator_set, ConsensusHost};

    let my_addr = crate::ledger::Ledger::load().address;
    if my_addr.is_empty() { return None; }
    let seed = get_ed25519_seed()?;
    let kp = ego_core::KeyPair::from_bytes(&seed).ok()?;
    let my_dil_raw = kp.dilithium_public_key().key_data;

    // v2 builds its committee from the LIVE validator set (self + recently-seen peers
    // with exchanged Dilithium keys), so it bootstraps straight from PeerAnnounce WITHOUT
    // needing on-chain registration first, and never drops an active peer (the cause of
    // the inline `vs(len=1)` stalls). For an isolated pair this is {self, peer} identically
    // on both nodes; the engine derives the SAME Address from kp.dilithium_public_key().
    let source = live_validators();
    let mut pairs: Vec<(String, ego_core::Address)> = Vec::new();
    {
        let pubkeys = validator_pubkeys();
        for addr in &source {
            let dil_raw = if *addr == my_addr {
                my_dil_raw.clone()
            } else {
                match pubkeys.get(addr).and_then(|h| hex::decode(h).ok()) {
                    Some(b) if !b.is_empty() => b,
                    _ => continue, // peer's Dilithium key not yet known — skip
                }
            };
            pairs.push((addr.clone(), address_from_dilithium(dil_raw)));
        }
    }
    // Include self even before our own validator_register is committed on-chain.
    if !pairs.iter().any(|(a, _)| a == &my_addr) {
        pairs.push((my_addr.clone(), address_from_dilithium(my_dil_raw)));
    }
    if pairs.len() < crate::mempool::min_validators_for_finality() {
        return None;
    }

    let (set, _bech32_by_addr) = build_validator_set(&pairs);
    let host = ConsensusHost::new(kp, set);
    // Align with peers at the live chain tip: the next height to produce is tip+1, so
    // two nodes that didn't start simultaneously still agree on the proposer schedule.
    let next_height = crate::chain_db::latest_block_info().0 + 1;
    host.seed_height(next_height);
    Some(host)
}

// ── Consensus-v2 driver (DEFAULT live engine) ────────────────────────────────────
// Runs the ego-consensus-core BftEngine over a dedicated gossip topic. By default it is
// LIVE: it proposes real LedgerBlocks, persists them on QC, and the inline BFT is gated
// off. With EGO_CONSENSUS_LEGACY=1 the inline BFT drives instead; with LEGACY+SHADOW the
// engine runs alongside inline writing nothing to disk (parity logging only).
const V2_TOPIC: &str = "ego-bftv2-v1";

static SHADOW_HOST: std::sync::OnceLock<std::sync::Mutex<Option<crate::consensus_host::ConsensusHost>>> =
    std::sync::OnceLock::new();
fn shadow_host_lock() -> std::sync::MutexGuard<'static, Option<crate::consensus_host::ConsensusHost>> {
    SHADOW_HOST.get_or_init(|| std::sync::Mutex::new(None)).lock().unwrap()
}
/// v2 is the DEFAULT consensus — it drives the real chain and the inline BFT is gated
/// off. No configuration required; ordinary users get this automatically. The ONLY knob
/// is an emergency escape hatch: set `EGO_CONSENSUS_LEGACY=1` to fall back to the inline
/// BFT (e.g. if a v2 issue is found in the field, before a fix ships).
pub(crate) fn consensus_v2_live_enabled() -> bool { std::env::var("EGO_CONSENSUS_LEGACY").is_err() }
/// The v2 engine runs (live by default, or shadow-alongside-inline when LEGACY+SHADOW).
fn consensus_v2_active() -> bool { consensus_v2_live_enabled() || std::env::var("EGO_CONSENSUS_V2_SHADOW").is_ok() }
static SHADOW_LAST_PROPOSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX);
static V2_HEARTBEAT_TS: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
// Pacemaker state: the (height<<16|round) we're currently sitting in, and when we entered
// it. If we stay past V2_VIEW_TIMEOUT_MS without finalizing, we broadcast a view-change.
static V2_VIEW_KEY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX);
static V2_VIEW_ENTERED_MS: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
const V2_VIEW_TIMEOUT_MS: i64 = 4_000;

// In LIVE mode, the LedgerBlock payload each v2 BlockHeader commits to, keyed by the
// engine header hash — so when a QC forms for that header we persist the right block.
static V2_PENDING_BLOCKS: std::sync::OnceLock<std::sync::Mutex<HashMap<ego_core::Hash, (crate::ledger::LedgerBlock, Vec<LedgerTx>)>>> =
    std::sync::OnceLock::new();
fn v2_pending_blocks() -> std::sync::MutexGuard<'static, HashMap<ego_core::Hash, (crate::ledger::LedgerBlock, Vec<LedgerTx>)>> {
    V2_PENDING_BLOCKS.get_or_init(|| std::sync::Mutex::new(HashMap::new())).lock().unwrap()
}

// Out-of-order buffers: a proposal or vote for height N can arrive BEFORE we finalize N-1
// (gossip race). We keep these by height and replay them once the engine reaches N, rather
// than dropping them — dropping strands the chain (observed live: reject #60 then finalize
// #59 → permanent stall, because the proposer had already moved past #60).
type V2Proposal = (ego_consensus_core::bft::BlockHeader, crate::ledger::LedgerBlock, Vec<LedgerTx>);
static V2_FUTURE_PROPOSALS: std::sync::OnceLock<std::sync::Mutex<HashMap<u64, V2Proposal>>> = std::sync::OnceLock::new();
static V2_FUTURE_VOTES: std::sync::OnceLock<std::sync::Mutex<HashMap<u64, Vec<ego_consensus_core::bft::Vote>>>> = std::sync::OnceLock::new();
const V2_FUTURE_WINDOW: u64 = 256; // how far ahead we buffer
fn v2_future_proposals() -> std::sync::MutexGuard<'static, HashMap<u64, V2Proposal>> {
    V2_FUTURE_PROPOSALS.get_or_init(|| std::sync::Mutex::new(HashMap::new())).lock().unwrap()
}
fn v2_future_votes() -> std::sync::MutexGuard<'static, HashMap<u64, Vec<ego_consensus_core::bft::Vote>>> {
    V2_FUTURE_VOTES.get_or_init(|| std::sync::Mutex::new(HashMap::new())).lock().unwrap()
}
fn v2_engine_height() -> Option<u64> {
    shadow_host_lock().as_ref().map(|h| h.current_height())
}

static V2_COMMITTEE_SIG: std::sync::OnceLock<std::sync::Mutex<String>> = std::sync::OnceLock::new();
static V2_PENDING_SIG: std::sync::OnceLock<std::sync::Mutex<String>> = std::sync::OnceLock::new();
static V2_PENDING_SINCE: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
static V2_RECONFIG_LAST_CHECK: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
const V2_RECONFIG_STABILITY_SECS: i64 = 12;
fn v2_committee_sig() -> std::sync::MutexGuard<'static, String> {
    V2_COMMITTEE_SIG.get_or_init(|| std::sync::Mutex::new(String::new())).lock().unwrap()
}
fn v2_pending_sig() -> std::sync::MutexGuard<'static, String> {
    V2_PENDING_SIG.get_or_init(|| std::sync::Mutex::new(String::new())).lock().unwrap()
}
fn live_committee_sig() -> String {
    let mut v = live_validators();
    v.sort();
    v.join(",")
}

async fn maybe_reconfigure_committee() {
    if !consensus_v2_live_enabled() { return; }
    if shadow_host_lock().is_none() { return; }

    let now = chrono::Utc::now().timestamp();
    if now - V2_RECONFIG_LAST_CHECK.load(Ordering::Relaxed) < 2 { return; }
    V2_RECONFIG_LAST_CHECK.store(now, Ordering::Relaxed);

    let cur_sig = live_committee_sig();
    if cur_sig == *v2_committee_sig() {
        if !v2_pending_sig().is_empty() { v2_pending_sig().clear(); }
        return;
    }
    {
        let mut pending = v2_pending_sig();
        if *pending != cur_sig {
            *pending = cur_sig.clone();
            V2_PENDING_SINCE.store(now, Ordering::Relaxed);
            return;
        }
    }
    if now - V2_PENDING_SINCE.load(Ordering::Relaxed) < V2_RECONFIG_STABILITY_SECS { return; }

    if live_validators().len() < crate::mempool::MIN_VALIDATORS_FOR_FINALITY {
        return;
    }

    let built = tokio::task::spawn_blocking(build_shadow_consensus_host).await.ok().flatten();
    if let Some(host) = built {
        let tip = crate::chain_db::latest_block_info().0 + 1;
        host.seed_height(tip);
        let (n, q) = (host.validator_set().len(), host.quorum_size());
        *shadow_host_lock() = Some(host);
        v2_future_proposals().clear();
        v2_future_votes().clear();
        *v2_committee_sig() = cur_sig;
        v2_pending_sig().clear();
        eprintln!("[ConsensusV2/LIVE] committee reconfigured → validators={} quorum={} (seeded h={})", n, q, tip);
    }
}

/// Build the stored shadow host once we have a quorum-sized validator set. Returns true
/// if a host is available. The build (DPAPI seed load) runs off the async executor.
async fn ensure_shadow_host() -> bool {
    if shadow_host_lock().is_some() { return true; }
    let built = tokio::task::spawn_blocking(build_shadow_consensus_host).await.ok().flatten();
    let mut built_now = false;
    {
        let mut guard = shadow_host_lock();
        if guard.is_none() {
            if let Some(h) = built {
                let mode = if consensus_v2_live_enabled() { "LIVE" } else { "shadow" };
                eprintln!("[ConsensusV2/{}] host built — validators={} quorum={} scheme=Dilithium",
                    mode, h.validator_set().len(), h.quorum_size());
                *guard = Some(h);
                built_now = true;
            }
        }
    }
    if built_now {
        *v2_committee_sig() = live_committee_sig();
    }
    shadow_host_lock().is_some()
}

async fn shadow_publish(msg: &P2PMessage) {
    if let Ok(data) = serde_json::to_vec(msg) {
        publish_gossip(V2_TOPIC, data).await;
    }
}

/// A v2 proposal arrived (or we just produced our own): in LIVE mode remember the
/// LedgerBlock payload so we can persist it on QC; then vote, publish, and self-count.
pub async fn shadow_on_proposal(
    header: ego_consensus_core::bft::BlockHeader,
    block: crate::ledger::LedgerBlock,
    txs: Vec<LedgerTx>,
) {
    if !consensus_v2_active() { return; }
    note_network_height(header.height);

    // Route by height. A proposal can arrive before we finalize its parent (gossip race):
    // buffer it and replay once the engine reaches that height, rather than dropping it.
    if let Some(cur) = v2_engine_height() {
        if header.height < cur { return; } // stale — already past this height
        if header.height > cur {
            if header.height <= cur + V2_FUTURE_WINDOW {
                v2_future_proposals().insert(header.height, (header, block, txs));
            }
            return;
        }
    }

    if consensus_v2_live_enabled() {
        // Never trust a proposer: validate the block before voting/persisting.
        let tip = crate::chain_db::latest_block_info().1;
        if block.prev_hash != tip {
            eprintln!("[ConsensusV2/LIVE] reject #{} — prev_hash {:.12} != tip {:.12}",
                header.height, block.prev_hash, tip);
            return;
        }
        if header.tx_root != crate::consensus_host::hash_from_hex(&block.tx_merkle_root)
            || header.state_root != crate::consensus_host::hash_from_hex(&block.state_root)
        {
            eprintln!("[ConsensusV2/LIVE] reject #{} — header roots do not commit to the block", header.height);
            return;
        }
        let (b, t) = (block.clone(), txs.clone());
        let valid = tokio::task::spawn_blocking(move || crate::chain_db::validate_proposal_block(&b, &t))
            .await.unwrap_or_else(|_| Err("validation task panicked".into()));
        if let Err(e) = valid {
            eprintln!("[ConsensusV2/LIVE] reject #{} — invalid block: {}", header.height, e);
            return;
        }
        v2_pending_blocks().insert(header.block_hash(), (block, txs));
    }
    let vote = {
        let guard = shadow_host_lock();
        guard.as_ref().and_then(|h| h.on_proposal(&header))
    };
    if let Some(v) = vote {
        let tag = if consensus_v2_live_enabled() { "LIVE" } else { "shadow" };
        eprintln!("[ConsensusV2/{}] voted h={} round={}", tag, header.height, v.round);
        shadow_publish(&P2PMessage::BftV2Vote { vote: v.clone() }).await;
        shadow_on_vote(v).await;
    }
}

/// A v2 vote arrived (or our own): tally it; on QC, advance the engine. In LIVE mode
/// PERSIST the agreed LedgerBlock to the real chain; in shadow mode just log.
pub async fn shadow_on_vote(vote: ego_consensus_core::bft::Vote) {
    if !consensus_v2_active() { return; }

    // Route by height: a vote for height N can outrun the proposal it certifies (or our
    // own finalization of N-1). Buffer future-height votes and replay them when the engine
    // reaches N, so the QC still forms instead of being lost.
    if let Some(cur) = v2_engine_height() {
        if vote.height < cur { return; }
        if vote.height > cur {
            if vote.height <= cur + V2_FUTURE_WINDOW {
                v2_future_votes().entry(vote.height).or_default().push(vote);
            }
            return;
        }
    }

    let decided = {
        let guard = shadow_host_lock();
        guard.as_ref().and_then(|h| {
            h.on_vote(&vote).and_then(|qc| {
                h.proposed_header().map(|hdr| {
                    let ht = hdr.height;
                    let hash = hdr.block_hash();
                    let vc = qc.voter_count() as u32;
                    let ok = h.finalize(hdr, qc);
                    (ht, hash, vc, ok)
                })
            })
        })
    };
    let Some((ht, hash, vc, ok)) = decided else { return };
    if consensus_v2_live_enabled() {
        let payload = v2_pending_blocks().remove(&hash);
        if let Some((block, txs)) = payload {
            let bh = block.hash.clone();
            // Copy for the explorer feed before the block is moved into the commit task.
            let (block_for_oracle, txs_for_oracle) = (block.clone(), txs.clone());
            let persisted = tokio::task::spawn_blocking(move || {
                crate::chain_db::commit_staged_block(&block, &txs, vc)
            }).await.unwrap_or(false);
            if persisted {
                // Fire-and-forget the finalized block to the oracle's read-only chain index
                // so the public explorer can display it. NOT in the consensus path.
                tokio::spawn(async move { push_block_to_oracle(&block_for_oracle, &txs_for_oracle).await; });
            }
            eprintln!("[ConsensusV2/LIVE] finalized h={} ({} votes) — persisted={} block={:.12}",
                ht, vc, persisted, bh);
            if persisted {
                touch_proposal_timestamp();
            } else {
                // The engine advanced past this height on the QC, but the chain did NOT
                // record the block. Re-seed the engine to the real tip so it retries this
                // height instead of racing ahead of a chain that's missing the block.
                let real_next = crate::chain_db::latest_block_info().0 + 1;
                if let Some(h) = shadow_host_lock().as_ref() { h.seed_height(real_next); }
                eprintln!("[ConsensusV2/LIVE] persist FAILED h={} — re-seeded engine to {}", ht, real_next);
            }
        } else {
            eprintln!("[ConsensusV2/LIVE] QC h={} but no LedgerBlock payload cached — cannot persist", ht);
        }
        v2_pending_blocks().retain(|_, (b, _)| b.height >= ht);
    } else {
        eprintln!("[ConsensusV2/shadow] QC formed h={} — WOULD finalize {} (ok={}, NOT persisted)",
            ht, &hash.to_hex()[..12], ok);
    }
}

/// A v2 view-change arrived.
pub async fn shadow_on_view_change(msg: ego_consensus_core::fork_choice::ViewChangeMsg) {
    if !consensus_v2_active() { return; }
    let new_round = {
        let guard = shadow_host_lock();
        guard.as_ref().and_then(|h| h.on_view_change(msg))
    };
    if let Some(r) = new_round {
        let tag = if consensus_v2_live_enabled() { "LIVE" } else { "shadow" };
        eprintln!("[ConsensusV2/{}] view-change quorum → round {}", tag, r);
    }
}

/// Periodic driver: when we're the v2 leader for the current (height, round) and haven't
/// proposed it yet, build a candidate (real block in LIVE, empty in shadow), propose,
/// publish, and self-vote.
pub async fn shadow_v2_tick() {
    if !consensus_v2_active() || !ensure_shadow_host().await { return; }
    if proposing_suspended() { return; }

    // Follow the live validator set: rebuild the committee when a node joins/drops (so a
    // dropped validator can't block quorum and a rejoiner is re-included).
    maybe_reconfigure_committee().await;

    // If the chain advanced via block-sync while the engine lagged (e.g. we just restarted
    // and caught up from peers), pull the engine forward to the real tip so it proposes and
    // votes at the correct height instead of re-running an already-finalized one.
    if consensus_v2_live_enabled() {
        let real_next = crate::chain_db::latest_block_info().0 + 1;
        let guard = shadow_host_lock();
        if let Some(h) = guard.as_ref() {
            if h.current_height() < real_next { h.seed_height(real_next); }
        }
    }

    // Replay any buffered out-of-order messages for the height we're now on, and prune
    // anything we've already passed. This is what unsticks the proposal-before-parent race:
    // once we advance to N, the buffered proposal + votes for N are processed and N finalizes.
    if let Some(cur) = v2_engine_height() {
        let prop = {
            let mut b = v2_future_proposals();
            b.retain(|&h, _| h >= cur);
            b.remove(&cur)
        };
        let votes = {
            let mut b = v2_future_votes();
            b.retain(|&h, _| h >= cur);
            b.remove(&cur)
        };
        if let Some((header, block, txs)) = prop {
            Box::pin(shadow_on_proposal(header, block, txs)).await;
        }
        if let Some(vs) = votes {
            for v in vs { Box::pin(shadow_on_vote(v)).await; }
        }
    }

    // Heartbeat (~5s): proves the engine is alive and shows whether we're the proposer
    // for this height — so a node correctly WAITING for the peer's proposal is visibly
    // distinct from "v2 not running".
    {
        let now = chrono::Utc::now().timestamp();
        if now - V2_HEARTBEAT_TS.load(Ordering::Relaxed) >= 5 {
            V2_HEARTBEAT_TS.store(now, Ordering::Relaxed);
            let guard = shadow_host_lock();
            if let Some(h) = guard.as_ref() {
                let tag = if consensus_v2_live_enabled() { "LIVE" } else { "shadow" };
                eprintln!("[ConsensusV2/{}] alive — h={} round={} i_am_proposer={} validators={}",
                    tag, h.current_height(), h.current_round(), h.is_proposer(), h.validator_set().len());
            }
        }
    }

    // ── Idle gate ─────────────────────────────────────────────────────────────
    // Block production is DEMAND-driven, not tick-driven. With an empty mempool,
    // no proposal in flight and a young tip there is nothing to decide: don't
    // propose (each empty block mints a coinbase — observed live at 1.35 empty
    // blocks/sec ≈ 9,600 EGOC/day for nothing) and don't fire the pacemaker
    // (idle view-changes would storm every timeout). One empty heartbeat block
    // per EMPTY_BLOCK_INTERVAL_S keeps the chain demonstrably alive.
    {
        let inflight = {
            let guard = shadow_host_lock();
            guard.as_ref().and_then(|h| h.proposed_header()).is_some()
        };
        let due = inflight
            || crate::mempool::get_mempool().pending_count() > 0
            || {
                let (tip_h, _) = crate::chain_db::latest_block_info();
                let tip_ts = crate::chain_db::get_block_by_height(tip_h)
                    .map(|b| b.timestamp)
                    .unwrap_or(0);
                chrono::Utc::now().timestamp() - tip_ts
                    >= crate::mempool::EMPTY_BLOCK_INTERVAL_S as i64
            };
        if !due {
            V2_VIEW_ENTERED_MS.store(chrono::Utc::now().timestamp_millis(), Ordering::Relaxed);
            return;
        }
    }

    // ── Pacemaker ─────────────────────────────────────────────────────────────
    // If we sit at the same (height, round) too long without finalizing — the elected
    // proposer is offline, can't build a block, or its proposal isn't reaching us — rotate
    // the proposer by broadcasting a view-change. The round advances ONLY on a quorum of
    // view-changes, so it cannot run away like the inline view counter. Without this a
    // stalled proposer halts the chain forever (observed live: stuck at h=1 round=0).
    if consensus_v2_live_enabled() {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let view_key = {
            let g = shadow_host_lock();
            g.as_ref().map(|h| (h.current_height() << 16) | (h.current_round() as u64 & 0xFFFF))
        };
        if let Some(key) = view_key {
            let prev = V2_VIEW_KEY.swap(key, Ordering::Relaxed);
            if prev != key {
                V2_VIEW_ENTERED_MS.store(now_ms, Ordering::Relaxed); // entered a new view
            } else if now_ms - V2_VIEW_ENTERED_MS.load(Ordering::Relaxed) >= V2_VIEW_TIMEOUT_MS {
                let vc = { let g = shadow_host_lock(); g.as_ref().and_then(|h| h.trigger_view_change()) };
                if let Some(vc) = vc {
                    eprintln!("[ConsensusV2/LIVE] view timeout (key={:#x}) — broadcasting view-change", key);
                    shadow_publish(&P2PMessage::BftV2ViewChange { msg: vc.clone() }).await;
                    shadow_on_view_change(vc).await; // count our own toward quorum
                }
                V2_VIEW_ENTERED_MS.store(now_ms, Ordering::Relaxed); // re-arm; avoid a VC storm
            }
        }
    }

    // Decide if it's our turn and reserve this (height, round) under the lock.
    let my_turn = {
        let guard = shadow_host_lock();
        guard.as_ref().map_or(false, |h| {
            if !h.is_proposer() { return false; }
            let key = (h.current_height() << 16) | (h.current_round() as u64 & 0xFFFF);
            SHADOW_LAST_PROPOSED.swap(key, std::sync::atomic::Ordering::Relaxed) != key
        })
    };
    if !my_turn { return; }

    // Build the candidate (real txs in LIVE, empty otherwise) OFF the lock.
    let (candidate, stamped) = if consensus_v2_live_enabled() {
        match build_live_candidate().await { Some(v) => v, None => return }
    } else {
        (crate::ledger::LedgerBlock::default(), vec![])
    };

    // Propose through the engine (header commits to the candidate's roots).
    let header = {
        let guard = shadow_host_lock();
        match guard.as_ref().and_then(|h| h.propose(&candidate)) {
            Some(hdr) => hdr,
            None => return,
        }
    };
    let tag = if consensus_v2_live_enabled() { "LIVE" } else { "shadow" };
    eprintln!("[ConsensusV2/{}] proposed h={} txs={}", tag, header.height, stamped.len());
    shadow_publish(&P2PMessage::BftV2Proposal {
        header: header.clone(), block: candidate.clone(), transactions: stamped.clone(),
    }).await;
    shadow_on_proposal(header, candidate, stamped).await; // our own self-vote
}

/// Build a real LedgerBlock candidate from the mempool for the v2 LIVE proposer,
/// mirroring the inline proposer's assembly so the persisted block is fully valid.
async fn build_live_candidate() -> Option<(crate::ledger::LedgerBlock, Vec<LedgerTx>)> {
    let miner = crate::ledger::Ledger::load().address;
    if miner.is_empty() { return None; }
    let seed = get_ed25519_seed()?;
    let (_, prev_hash) = crate::chain_db::latest_block_info();

    let mut all_txs = crate::mempool::get_mempool().drain_all();
    {
        let mut seen = std::collections::HashSet::new();
        all_txs.retain(|tx| !tx.hash.is_empty() && seen.insert(tx.hash.clone()));
    }

    let poc_slot = crate::poc::current_slot();
    let combined_ticket = {
        use ed25519_dalek::{SigningKey, Signer};
        let slot_seed = crate::poc::slot_seed(&prev_hash, poc_slot);
        let sig = SigningKey::from_bytes(&seed).sign(&slot_seed);
        let ticket = *blake3::hash(&sig.to_bytes()).as_bytes();
        format!("{}:{}", hex::encode(ticket), hex::encode(sig.to_bytes()))
    };

    tokio::task::spawn_blocking(move || {
        crate::chain_db::build_block_proposal(&all_txs, &miner, &combined_ticket, poc_slot)
    }).await.ok()
}

pub fn register_validator_pubkey(address: &str, dilithium_pubkey_hex: &str) {
    if address.is_empty() || dilithium_pubkey_hex.is_empty() { return; }
    validator_pubkeys().insert(address.to_string(), dilithium_pubkey_hex.to_string());
}

/// This node's own Ed25519 public key (hex), or "" if the seed isn't loaded.
fn my_ed25519_pubkey_hex() -> String {
    match get_ed25519_seed() {
        Some(seed) => {
            use ed25519_dalek::SigningKey;
            hex::encode(SigningKey::from_bytes(&seed).verifying_key().as_bytes())
        }
        None => String::new(),
    }
}

/// If `pubkey_hex` derives `address`, cache it for future verifications and
/// return true. Lets a node learn a voter's key directly from the vote that
/// carries it, instead of waiting for the voter's announce to propagate.
fn learn_voter_pubkey(address: &str, pubkey_hex: &str) -> bool {
    if address.is_empty() || pubkey_hex.len() != 64 { return false; }
    let Ok(bytes) = hex::decode(pubkey_hex) else { return false; };
    if bytes.len() != 32 { return false; }
    let derived = ego_core::EgoAddress::from_public_key_bytes(&bytes, 1, ego_core::AddressType::EOA)
        .to_bech32("egot").unwrap_or_default();
    if derived != address { return false; }
    record_peer_ed25519(address, pubkey_hex);
    true
}

/// Verify a BFT signature, accepting an inline pubkey carried with the vote.
/// The inline key is only trusted after `learn_voter_pubkey` confirms it derives
/// the claimed address, so it cannot be used to vote as someone else.
fn verify_bft_sig_with_key(address: &str, data: &str, sig_hex: &str, pubkey_hex: &str) -> bool {
    if !pubkey_hex.is_empty() {
        learn_voter_pubkey(address, pubkey_hex);
    }
    verify_bft_sig(address, data, sig_hex)
}

fn verify_bft_sig(address: &str, data: &str, sig_hex: &str) -> bool {
    let pubkey = match get_peer_ed25519_pubkey(address) {
        Some(pk) => pk,
        None => {
            eprintln!("[BFT] Unknown Ed25519 pubkey for {} — rejecting signature", address);
            return false;
        }
    };
    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) if b.len() == 64 => b,
        _ => return false,
    };
    use ed25519_dalek::{VerifyingKey, Signature as DalekSig, Verifier};
    let vk = match VerifyingKey::from_bytes(&pubkey) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig_arr: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig = DalekSig::from_bytes(&sig_arr);
    vk.verify(data.as_bytes(), &sig).is_ok()
}

// ── Per-peer gossip rate limiter ───────────────────────────────────────────────
// Counts messages per peer per second. Peers exceeding the cap are ignored.
// This prevents a single peer from flooding the network (DDoS layer 1).
const MAX_MSGS_PER_SEC: u32 = 500;

#[derive(Clone, Copy)]
struct RateState {
    count: u32,
    window_start: i64,
    logged_this_window: bool,
}

static PEER_MSG_RATE: std::sync::OnceLock<std::sync::Mutex<HashMap<String, RateState>>> =
    std::sync::OnceLock::new();

fn peer_msg_rate() -> std::sync::MutexGuard<'static, HashMap<String, RateState>> {
    PEER_MSG_RATE
        .get_or_init(|| std::sync::Mutex::new(HashMap::new()))
        .lock()
        .unwrap()
}

/// Returns true if the peer is within rate limits. False = flooding, drop the message.
fn check_peer_rate(peer_id: &str) -> bool {
    let now = chrono::Utc::now().timestamp();
    let mut rates = peer_msg_rate();
    let entry = rates.entry(peer_id.to_string()).or_insert(RateState {
        count: 0, window_start: now, logged_this_window: false,
    });
    if now > entry.window_start {
        *entry = RateState { count: 1, window_start: now, logged_this_window: false };
        true
    } else {
        entry.count += 1;
        if entry.count > MAX_MSGS_PER_SEC {
            if !entry.logged_this_window {
                eprintln!("[P2P] Rate-limiting flood from {} (>{} msgs/s — further drops silenced for this second)",
                    peer_id, MAX_MSGS_PER_SEC);
                entry.logged_this_window = true;
            }
            false
        } else {
            true
        }
    }
}

/// Restores all persisted validator pubkeys from RocksDB into the in-memory
/// peer key maps. This ensures BFT vote verification works after a node restart.
pub fn restore_validator_keys_from_db() {
    let restored_validators = crate::chain_db::load_known_validators();
    let mut ed_count = 0;
    let mut bls_count = 0;
    for addr in restored_validators {
        if addr.is_empty() { continue; }
        // Restore Ed25519 (required for BFT vote signature verification)
        if let Some(ed_pk_hex) = crate::chain_db::get_validator_ed25519_pubkey(&addr) {
             record_peer_ed25519(&addr, &ed_pk_hex);
             ed_count += 1;
        }
        // Restore BLS (required for Quorum Certificate/Finalization verification)
        if let Some(bls_pk_hex) = crate::chain_db::get_validator_bls_pubkey(&addr) {
             if let Ok(bytes) = hex::decode(&bls_pk_hex) {
                 peer_bls_pubkeys().insert(addr.clone(), bytes);
                 bls_count += 1;
             }
        }
    }
    if ed_count > 0 || bls_count > 0 {
        eprintln!("[BFT] Restored {} Ed25519 and {} BLS validator keys from DB", ed_count, bls_count);
    }
}

static CURRENT_VIEW: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

static LAST_PROPOSAL_TS: std::sync::atomic::AtomicI64 =
    std::sync::atomic::AtomicI64::new(0);


static CONSECUTIVE_EMPTY_VIEWS: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(0);


const SOLO_DEADLOCK_VIEWS: u32 = 3;

static STUCK_AT_NEXT_VIEW: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

static STUCK_VIEWCHANGE_CYCLES: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(0);

static LIVENESS_STALLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
const SOLO_STALL_SECS: i64 = 15;
const SOLO_ALONE_STALL_SECS: i64 = 4;

/// Validators recently evicted via the deadlock-eviction path. Each entry
/// holds the wall-clock timestamp until which the address should NOT be
/// re-registered, regardless of incoming gossip echoes. Without this, a
/// disconnected peer's stale gossip messages keep re-adding it to the
/// committee within milliseconds of every eviction, causing an infinite
/// 1↔2 oscillation that prevents view advancement.
const EVICTION_COOLDOWN_SECS: i64 = 90;
static EVICTION_COOLDOWN: std::sync::OnceLock<std::sync::Mutex<HashMap<String, i64>>> =
    std::sync::OnceLock::new();
fn eviction_cooldown() -> std::sync::MutexGuard<'static, HashMap<String, i64>> {
    EVICTION_COOLDOWN.get_or_init(|| std::sync::Mutex::new(HashMap::new())).lock().unwrap()
}
pub fn is_in_eviction_cooldown(addr: &str) -> bool {
    let now = chrono::Utc::now().timestamp();
    let mut map = eviction_cooldown();
    if let Some(&until) = map.get(addr) {
        if now < until { return true; }
        map.remove(addr);
    }
    false
}
pub fn record_eviction_cooldown(addr: &str) {
    let until = chrono::Utc::now().timestamp() + EVICTION_COOLDOWN_SECS;
    eviction_cooldown().insert(addr.to_string(), until);
}

fn should_solo_commit_now() -> bool {
    let allow_solo_fork = std::env::var("EGO_ALLOW_SOLO_FORK")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !allow_solo_fork {
        return false;
    }
    let committee_alone = known_validators().len() <= 1;
    let deadlocked = STUCK_VIEWCHANGE_CYCLES.load(Ordering::Relaxed) >= SOLO_DEADLOCK_VIEWS
        || LIVENESS_STALLED.load(Ordering::Relaxed);
    committee_alone || deadlocked
}

pub static ORACLE_GAP_FILL_NEEDED: AtomicBool = AtomicBool::new(false);
pub static LAST_BLOCK_FINALIZED_TS: std::sync::atomic::AtomicI64 =
    std::sync::atomic::AtomicI64::new(0);

static LAST_FORK_SYNC_TS: std::sync::atomic::AtomicI64 =
    std::sync::atomic::AtomicI64::new(0);


static PENDING_PROPOSALS: std::sync::OnceLock<std::sync::Mutex<HashMap<u64, String>>> =
    std::sync::OnceLock::new();

fn pending_proposals() -> std::sync::MutexGuard<'static, HashMap<u64, String>> {
    PENDING_PROPOSALS.get_or_init(|| std::sync::Mutex::new(HashMap::new())).lock().unwrap()
}

static VIEW_CHANGE_VOTES: std::sync::OnceLock<std::sync::Mutex<HashMap<u64, Vec<String>>>> =
    std::sync::OnceLock::new();

static STAGED_BLOCK: std::sync::OnceLock<std::sync::Mutex<Option<(crate::ledger::LedgerBlock, Vec<crate::ledger::LedgerTx>)>>> =
    std::sync::OnceLock::new();

pub fn staged_block() -> std::sync::MutexGuard<'static, Option<(crate::ledger::LedgerBlock, Vec<crate::ledger::LedgerTx>)>> {
    STAGED_BLOCK.get_or_init(|| std::sync::Mutex::new(None)).lock().expect("staged_block lock poisoned")
}

static LOCKED_QC_HEIGHT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

const VIEW_CHANGE_TIMEOUT_SECS: i64 = 5;

fn view_change_votes() -> std::sync::MutexGuard<'static, HashMap<u64, Vec<String>>> {
    VIEW_CHANGE_VOTES.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap()
}

pub fn current_view() -> u64 { CURRENT_VIEW.load(Ordering::Relaxed) }

fn advance_view(v: u64) { CURRENT_VIEW.store(v, Ordering::Relaxed); }


// ── PoRep outstanding challenge tracker ───────────────────────────────────────

#[derive(Debug)]
struct OutstandingChallenge {
    /// BLAKE3(nonce_bytes || enc_block_bytes) — what the correct prover MUST return.
    expected_hash: String,
    /// Address of the node being challenged.
    prover:        String,
    /// Unix ms timestamp when the challenge was issued (for timeout detection).
    issued_at_ms:  i64,
    /// CID of the file this block belongs to (for eviction on failure).
    manifest_cid:  String,
}

/// Consecutive PoRep failures per prover address. Resets on any pass.
/// Key: prover address. Value: consecutive fail count.
static POREP_CONSECUTIVE_FAILS: std::sync::OnceLock<
    std::sync::Mutex<HashMap<String, u32>>
> = std::sync::OnceLock::new();

fn porep_consecutive_fails() -> std::sync::MutexGuard<'static, HashMap<String, u32>> {
    POREP_CONSECUTIVE_FAILS
        .get_or_init(|| std::sync::Mutex::new(HashMap::new()))
        .lock()
        .unwrap()
}

const POREP_MAX_CONSECUTIVE_FAILS: u32 = 3;

fn porep_record_fail(prover: &str) -> u32 {
    let mut map = porep_consecutive_fails();
    let c = map.entry(prover.to_string()).or_insert(0);
    *c += 1;
    *c
}

fn porep_record_pass(prover: &str) {
    porep_consecutive_fails().remove(prover);
}

fn porep_evict_peer(prover: &str, manifest_cid: &str) {
    let mut ledger = crate::ledger::Ledger::load();
    let mut changed = false;
    for file in ledger.stored_files.iter_mut() {
        if file.cid == manifest_cid || manifest_cid.is_empty() {
            let before = file.replica_peers.len();
            file.replica_peers.retain(|p| p != prover);
            // Failed proofs are disqualifying, not a nap: no grace window — the
            // recruitment gate sees the hole immediately and replaces the peer.
            file.replica_last_ack.remove(prover);
            file.replica_grace.remove(prover);
            if file.replica_peers.len() < before {
                changed = true;
                eprintln!(
                    "[PoRep] Evicted {} from replica_peers of {} after {} consecutive failures — triggering re-replication",
                    &prover[..prover.len().min(20)],
                    &file.cid[..file.cid.len().min(16)],
                    POREP_MAX_CONSECUTIVE_FAILS
                );
            }
        }
    }
    if changed {
        let _ = ledger.save();
    }
}

static REJOIN_CHALLENGE_LAST: std::sync::OnceLock<std::sync::Mutex<HashMap<String, i64>>> =
    std::sync::OnceLock::new();
const REJOIN_CHALLENGE_MIN_INTERVAL_SECS: i64 = 120;

/// Challenge a grace-window holder that reported back, so it can rejoin the
/// replica set only by proving it still has the data (zero re-transfer).
async fn issue_rejoin_challenge(manifest_cid: &str, prover: &str) {
    {
        let key = format!("{}:{}", manifest_cid, prover);
        let now = chrono::Utc::now().timestamp();
        let mut map = REJOIN_CHALLENGE_LAST
            .get_or_init(|| std::sync::Mutex::new(HashMap::new()))
            .lock().unwrap();
        let last = map.get(&key).copied().unwrap_or(0);
        if now - last < REJOIN_CHALLENGE_MIN_INTERVAL_SECS { return; }
        map.insert(key, now);
    }

    let my_addr = tokio::task::spawn_blocking(|| crate::ledger::Ledger::load().address)
        .await.unwrap_or_default();
    if my_addr.is_empty() || my_addr == prover { return; }

    let manifest = match crate::blocks::load_manifest(manifest_cid) {
        Ok(m) => m,
        Err(_) => return,
    };
    if manifest.blocks.is_empty() { return; }

    let now_ms = chrono::Utc::now().timestamp_millis();
    let block_idx = (now_ms as usize) % manifest.blocks.len();
    let block_cid = manifest.blocks[block_idx].block_cid.clone();
    if !crate::blocks::have_block(&block_cid) { return; }
    let enc_block = match crate::blocks::load_block(&block_cid) {
        Ok(b) => b,
        Err(_) => return,
    };

    let nonce_input = format!("porep-rejoin:{}:{}:{}", prover, block_cid, now_ms);
    let nonce_bytes = *blake3::hash(nonce_input.as_bytes()).as_bytes();
    let nonce_hex   = hex::encode(nonce_bytes);

    let mut hasher = blake3::Hasher::new();
    hasher.update(&nonce_bytes);
    hasher.update(&enc_block);
    let expected_hash = hasher.finalize().to_hex().to_string();

    let challenge_key = format!("{}:{}", block_cid, nonce_hex);
    outstanding_challenges().insert(challenge_key, OutstandingChallenge {
        expected_hash,
        prover: prover.to_string(),
        issued_at_ms: now_ms,
        manifest_cid: manifest_cid.to_string(),
    });

    let challenge = P2PMessage::StorageProofChallenge {
        manifest_cid: manifest_cid.to_string(),
        block_cid,
        nonce: nonce_hex,
        challenger: my_addr,
    };
    if let Ok(data) = serde_json::to_vec(&challenge) {
        publish_gossip("ego-storage-v1", data).await;
        eprintln!(
            "[Replication] Rejoin challenge sent to {} for {} — it re-enters the replica set only on a valid proof",
            &prover[..prover.len().min(20)],
            &manifest_cid[..manifest_cid.len().min(16)]
        );
    }
}

/// A prover passed a PoRep challenge: if it was sitting in this file's 24h grace
/// window, it has proven possession — move it back into the replica set with zero
/// re-transfer. No-op for ordinary (non-grace) challenge passes.
fn porep_rejoin_on_pass(prover: &str, manifest_cid: &str) {
    let mut ledger = crate::ledger::Ledger::load();
    let now = chrono::Utc::now().timestamp();
    let mut changed = false;
    for file in ledger.stored_files.iter_mut() {
        if file.cid != manifest_cid || file.replication_role != "master" { continue; }
        if file.replica_grace.remove(prover).is_none() { continue; }
        changed = true;
        if file.replica_peers.len() < MIN_REPLICAS && !file.replica_peers.iter().any(|p| p == prover) {
            file.replica_peers.push(prover.to_string());
            file.replica_last_ack.insert(prover.to_string(), now);
            eprintln!(
                "[Replication] {} proved possession within the 24h grace — rejoined {} as replica ({}/{}), zero bytes re-transferred",
                &prover[..prover.len().min(20)],
                &file.cid[..file.cid.len().min(16)],
                file.replica_peers.len(), MIN_REPLICAS
            );
        } else {
            eprintln!(
                "[Replication] {} proved possession for {} but the replica set is already full — released from grace",
                &prover[..prover.len().min(20)],
                &file.cid[..file.cid.len().min(16)]
            );
        }
    }
    if changed {
        let _ = ledger.save();
    }
}

/// Key: `{block_cid}:{nonce_hex}`.
/// Value: what we expect the prover to return, plus metadata for timeout handling.
static OUTSTANDING_CHALLENGES: std::sync::OnceLock<
    std::sync::Mutex<HashMap<String, OutstandingChallenge>>
> = std::sync::OnceLock::new();

fn outstanding_challenges() -> std::sync::MutexGuard<
    'static, HashMap<String, OutstandingChallenge>
> {
    OUTSTANDING_CHALLENGES
        .get_or_init(|| std::sync::Mutex::new(HashMap::new()))
        .lock()
        .unwrap()
}

// ── Peer banning (invalid-block flood protection) ─────────────────────────────
/// Peers that send more than this many invalid blocks within a session are banned.
const PEER_INVALID_BLOCK_THRESHOLD: u32 = 5;
/// Banned peers are silenced for this many seconds before we give them another chance.
const PEER_BAN_SECS: i64 = 3_600;

static BANNED_PEERS: std::sync::OnceLock<std::sync::Mutex<HashMap<String, i64>>> =
    std::sync::OnceLock::new();
static PEER_INVALID_COUNTS: std::sync::OnceLock<std::sync::Mutex<HashMap<String, u32>>> =
    std::sync::OnceLock::new();

fn banned_peers() -> std::sync::MutexGuard<'static, HashMap<String, i64>> {
    BANNED_PEERS.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap()
}
fn peer_invalid_counts() -> std::sync::MutexGuard<'static, HashMap<String, u32>> {
    PEER_INVALID_COUNTS.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap()
}

/// Returns true if the peer is currently banned (sent too many invalid blocks).
fn is_peer_banned(peer_id: &str) -> bool {
    let now = chrono::Utc::now().timestamp();
    let mut bans = banned_peers();
    if let Some(&ban_until) = bans.get(peer_id) {
        if now < ban_until { return true; }
        // Ban expired — lift it.
        bans.remove(peer_id);
        peer_invalid_counts().remove(peer_id);
    }
    false
}

/// Record one invalid block from a peer. Bans the peer when the threshold is exceeded.
fn record_peer_invalid_block(peer_id: &str) {
    let count = {
        let mut counts = peer_invalid_counts();
        let c = counts.entry(peer_id.to_string()).or_insert(0);
        *c += 1;
        *c
    };
    if count >= PEER_INVALID_BLOCK_THRESHOLD {
        let ban_until = chrono::Utc::now().timestamp() + PEER_BAN_SECS;
        banned_peers().insert(peer_id.to_string(), ban_until);
        eprintln!(
            "[P2P] Banned peer {} for {}s — {} invalid blocks",
            peer_id, PEER_BAN_SECS, count
        );
    }
}


pub fn elect_proposer_for_next_slot() -> Option<String> {
    // This is called from sync code, so blocking is fine.
    let my_addr = crate::ledger::Ledger::load().address;
    if my_addr.is_empty() { return None; }


    let mut vs = crate::chain_db::registered_validators_sorted();
    if vs.is_empty() {
        vs = eligible_validators_sorted();
    }
    vs.sort_unstable(); // Deterministic sort to prevent split-brain
    if vs.len() <= 10 && !vs.is_empty() {
        let next_height = crate::chain_db::latest_block_info().0 + 1;
        let idx = (next_height as usize).wrapping_rem(vs.len());
        return vs.get(idx).cloned();
    }

    // This is called from sync code, so blocking is fine.
    let seed_bytes = crate::ledger::load_seed().ok().flatten()?;
    let mut seed_32 = [0u8; 32];
    seed_32.copy_from_slice(&seed_bytes);

    let (latest_h, prev_hash) = crate::chain_db::latest_block_info();
    let next_height = latest_h + 1;

    let vrf_in  = crate::bft_committee::vrf_input(
        &prev_hash, next_height, crate::bft_committee::VRF_ROLE_PROPOSER,
    );
    let ticket  = crate::bft_committee::sign_vrf_ticket(&seed_32, &vrf_in);

    let validators: Vec<String> = known_validators().iter().cloned().collect();
    let my_drs    = crate::bft_committee::compute_drs_weight(&my_addr);
    let total_drs = crate::bft_committee::total_drs_weight(&validators);

    if crate::bft_committee::qualifies_proposer_for_network(
        &ticket,
        my_drs,
        total_drs,
        validators.len(),
    ) {
        Some(my_addr)
    } else {
        None
    }
}

#[allow(dead_code)] // kept for historical reference — now redirects to VRF election
fn _elect_proposer_legacy() -> Option<String> {
    let validators: Vec<String> = known_validators().iter().cloned().collect();
    validators.into_iter().max_by(|a, b| {
        let da = crate::bft_committee::compute_drs_weight(a);
        let db = crate::bft_committee::compute_drs_weight(b);
        da.partial_cmp(&db).unwrap_or(std::cmp::Ordering::Equal)
    })
}

/// Legacy shim used by view-change messages.  Redirects to DRS-weighted election.
pub fn leader_for_view(_view: u64) -> Option<String> {
    elect_proposer_for_next_slot()
}


pub fn slash_validator(address: &str, reason: &str) {
    tracing::warn!("Slashing validator {} — {}", address, reason);
    known_validators().remove(address);
    slashed_validators().insert(address.to_string());
    crate::chain_db::persist_slashed_validator(address);
    crate::chain_db::remove_persisted_validator(address);
}

pub fn mark_validator_slashed_local(address: &str) {
    known_validators().remove(address);
    slashed_validators().insert(address.to_string());
}

pub async fn broadcast_equivocation_tx(
    accused: String,
    height: u64,
    hash_a: String,
    sig_a: String,
    hash_b: String,
    sig_b: String,
) {
    let ledger = crate::ledger::Ledger::load();
    let my_addr = tokio::task::spawn_blocking(|| crate::ledger::Ledger::load().address)
        .await.unwrap_or_default();
    if my_addr.is_empty() { return; }

    let accused_pk = get_peer_ed25519_pubkey(&accused)
        .map(|k| hex::encode(k))
        .unwrap_or_default();

    let payload = crate::chain_db::EquivocationProofPayload {
        accused: accused.clone(),
        height, hash_a, sig_a, hash_b, sig_b,
        accused_ed25519_pubkey: accused_pk,
        reporter: my_addr.clone(),
    };

    let memo = crate::chain_db::encode_equivocation_proof_payload(&payload);
    let expected_hash = crate::chain_db::equivocation_proof_hash(&memo);

    // Get reporter signature
    let (signature, public_key_ed25519) = match current_wallet_announce_keys() {
        (_, vrf_pk) if !vrf_pk.is_empty() => {
            let seed = crate::ledger::load_seed().ok().flatten()
                .unwrap_or_default();
            let mut arr = [0u8; 32]; arr.copy_from_slice(&seed[..32]);
            let sig = ego_core::KeyPair::from_bytes(&arr).map(|kp| hex::encode(kp.sign_ed25519(expected_hash.as_bytes()).as_bytes())).unwrap_or_default();
            (sig, vrf_pk)
        },
        _ => return,
    };

    let tx = crate::ledger::LedgerTx {
        hash: expected_hash, from: my_addr, to: accused, amount: 0, fee_uegoc: 0, nonce: 0,
        memo: Some(memo), timestamp: chrono::Utc::now().timestamp(),
        signature, public_key_ed25519, status: "Pending".to_string(), tx_type: "equivocation_proof".to_string(),
        ..crate::ledger::LedgerTx::default()
    };

    let _ = crate::mempool::get_mempool().push(tx.clone());
    broadcast_pending_tx(tx).await;
}



static PEER_ED25519_KEYS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, [u8; 32]>>> =
    std::sync::OnceLock::new();

fn peer_ed25519_keys() -> std::sync::MutexGuard<'static, std::collections::HashMap<String, [u8; 32]>> {
    PEER_ED25519_KEYS
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
        .lock().unwrap()
}


fn record_peer_ed25519(address: &str, pubkey_hex: &str) {
    if address.is_empty() || pubkey_hex.len() != 64 { return; }
    if let Ok(bytes) = hex::decode(pubkey_hex) {
        if let Ok(arr) = bytes.try_into() {
            peer_ed25519_keys().insert(address.to_string(), arr);
            crate::chain_db::persist_validator_ed25519_pubkey(address, pubkey_hex);
        }
    }
}


pub fn get_peer_ed25519_pubkey(address: &str) -> Option<[u8; 32]> {
    if let Some(pk) = peer_ed25519_keys().get(address).copied() {
        return Some(pk);
    }
    if let Some(pk_hex) = crate::chain_db::get_validator_ed25519_pubkey(address) {
        if let Ok(bytes) = hex::decode(&pk_hex) {
            if let Ok(arr) = bytes.try_into() {
                peer_ed25519_keys().insert(address.to_string(), arr);
                return Some(arr);
            }
        }
    }
    None
}


static VALIDATOR_LAST_SEEN: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, i64>>> =
    std::sync::OnceLock::new();

fn validator_last_seen() -> std::sync::MutexGuard<'static, std::collections::HashMap<String, i64>> {
    VALIDATOR_LAST_SEEN.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
        .lock().unwrap()
}

static VALIDATOR_FIRST_SEEN: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, i64>>> =
    std::sync::OnceLock::new();

fn validator_first_seen() -> std::sync::MutexGuard<'static, std::collections::HashMap<String, i64>> {
    VALIDATOR_FIRST_SEEN.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
        .lock().unwrap()
}

pub fn evict_stale_validators(ttl_secs: i64) {
    let now   = chrono::Utc::now().timestamp();
    let local = local_validator_mutex().lock().unwrap().clone();
    // Refresh the local node's timestamp so it never evicts itself.
    if !local.is_empty() {
        validator_last_seen().insert(local.clone(), now);
    }
    let mut stale: Vec<String> = validator_last_seen()
        .iter()
        .filter(|(addr, &ts)| now - ts > ttl_secs && **addr != local)
        .map(|(addr, _)| addr.clone())
        .collect();
    if stale.is_empty() {
        return;
    }

    let mut seen  = validator_last_seen();
    let mut known = known_validators();
    for addr in &stale {
        seen.remove(addr);
        known.remove(addr);
        tracing::warn!("[BFT] Evicted offline validator {}", addr);
    }
}

/// Liveness window. A peer validator counts toward the committee only if we've
/// seen its announce within this window. Without it, a restarted node treats
/// validators restored from DB (possibly long dead) as live committee members —
/// inflating quorum with ghosts that can never vote, so the round stalls and no
/// block is ever finalized.
pub const VALIDATOR_LIVENESS_SECS: i64 = 180;

/// The LIVE validator committee: ourselves plus every peer validator whose
/// announce we've seen within VALIDATOR_LIVENESS_SECS. This is the single source
/// of truth for both quorum gating and proposer election, so two connected nodes
/// agree on the committee and a lone node never believes it has quorum with stale
/// peers it can't actually reach.
pub fn live_validators() -> Vec<String> {
    let now   = chrono::Utc::now().timestamp();
    let local = local_validator_mutex().lock().unwrap().clone();
    let seen  = validator_last_seen();
    let mut out: Vec<String> = known_validators().iter()
        .filter(|a| !a.is_empty())
        .filter(|a| **a == local
            || seen.get(*a).map(|&t| now - t < VALIDATOR_LIVENESS_SECS).unwrap_or(false))
        .cloned()
        .collect();
    if !local.is_empty() && !out.contains(&local) {
        out.push(local);
    }
    out
}

pub fn known_validator_count() -> usize {
    live_validators().len()
}

/// Real count of nodes currently participating in consensus: peer validators seen
/// within the last 180s, plus self. This is the genuine "Active Nodes" figure — the
/// Explorer previously reported the local wallet count, which has nothing to do with
/// network connectivity (always 1 per machine, connected or not).
pub fn active_node_count() -> usize {
    let now   = chrono::Utc::now().timestamp();
    let local = local_validator_mutex().lock().unwrap().clone();
    let seen  = validator_last_seen();
    let peers = known_validators().iter()
        .filter(|a| !a.is_empty() && **a != local)
        .filter(|a| seen.get(*a).map(|&t| now - t < 180).unwrap_or(false))
        .count();
    peers + 1
}

pub fn min_validator_stake_uegoc() -> u64 {
    std::env::var("EGO_MIN_VALIDATOR_STAKE")
        .ok().and_then(|v| v.parse().ok())
        .unwrap_or(100 * 1_000_000)
}

/// Has any known validator met the stake floor? Once true, the network has
/// "graduated" from unstaked bootstrap to stake-gated validation.
fn network_has_staked_validator() -> bool {
    let min = min_validator_stake_uegoc();
    known_validators().iter().any(|a| crate::ledger::get_validator_stake(a) >= min)
}



pub fn is_eligible_validator(addr: &str) -> bool {
    // If the network is small (dev mode), allow unstaked nodes to participate
    if known_validator_count() < 3 || !network_has_staked_validator() { return true; }
    // ENFORCE STAKE GATE AFTER BOOTSTRAP WINDOW
    let (height, _) = crate::chain_db::latest_block_info();
    if height < 5000 && !network_has_staked_validator() { 
        return true; 
    }
    crate::ledger::get_validator_stake(addr) >= min_validator_stake_uegoc()
}

/// Sorted list of stake-eligible validators — the set leader election rotates
/// over, so an unstaked Sybil can't be elected proposer.
fn eligible_validators_sorted() -> Vec<String> {
    // Prefer the ON-CHAIN registered validator set for leader election. It is read
    // from the shared committed chain, so it is IDENTICAL on every node — all nodes
    // therefore agree on the single round-robin proposer for each height and can
    // never duel. It also excludes relay/public peers that merely announced (same
    // genesis hash) but never registered on THIS chain — those otherwise polluted
    // each node's live set differently and broke leader agreement, producing two
    // competing proposals whose votes split 1/2 forever under load.
    let slashed = slashed_validators();
    let registered: Vec<String> = crate::chain_db::registered_validators_sorted()
        .into_iter()
        .filter(|a| !slashed.contains(a))
        .collect();
    if !registered.is_empty() {
        let mut vs = registered;
        vs.sort();
        return vs;
    }
    // Pure-genesis bootstrap: nobody has a committed validator_register yet, so fall
    // back to the live set (self + recently-seen peers, excluding DB ghosts).
    let mut vs: Vec<String> = live_validators().into_iter()
        .filter(|a| is_eligible_validator(a))
        .collect();
    vs.sort();
    vs
}

pub fn register_known_validator(address: &str) {
    if address.is_empty() { return; }
    if slashed_validators().contains(address) { return; }
    if is_in_eviction_cooldown(address) {
        // Recently evicted; ignore gossip echoes that would re-add this peer
        // before the cooldown expires.
        return;
    }
    let min_stake: u64 = std::env::var("EGO_MIN_VALIDATOR_STAKE")
        .ok().and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if min_stake > 0 {
        let stake = crate::ledger::get_validator_stake(address);
        if stake < min_stake {
            tracing::debug!("Ignoring validator {} — stake {} below floor {}", address, stake, min_stake);
            return;
        }
    }

    let now = chrono::Utc::now().timestamp();
    validator_last_seen().insert(address.to_string(), now);
    validator_first_seen().entry(address.to_string()).or_insert(now);

    let mut set = known_validators();
    if set.len() >= MAX_VALIDATORS {
        if let Some(evict) = set.iter().next().cloned() {
            set.remove(&evict);
        }
    }
    let newly_added = set.insert(address.to_string());
    let total = set.len();
    drop(set);
    if newly_added {
        let local = local_validator_mutex().lock().unwrap().clone();
        if *address != local {
            tracing::info!("Validator registered: {} — committee now {} validator(s)", address, total);
        }
    }
    crate::chain_db::persist_known_validator(address);
    crate::poc::seed_peer_score_from_stake(address);
}

pub fn committee_admission_open() -> bool {
    known_validators().len() < crate::mempool::MIN_VALIDATORS_FOR_FINALITY
        || !crate::chain_db::chain_has_graduated_sticky(64)
}

pub fn register_announced_validator(address: &str) {
    if address.is_empty() { return; }
    if committee_admission_open() {
        register_known_validator(address);
        return;
    }
    if known_validators().contains(address) {
        if live_validators().len() < crate::mempool::MIN_VALIDATORS_FOR_FINALITY {
            register_known_validator(address);
        }
        return;
    }
    tracing::debug!(
        "Announce from {} noted — joins the committee once it votes or proposes at our tip",
        address
    );
}

static LOCAL_VALIDATOR_ADDR: std::sync::OnceLock<std::sync::Mutex<String>> = std::sync::OnceLock::new();

fn local_validator_mutex() -> &'static std::sync::Mutex<String> {
    LOCAL_VALIDATOR_ADDR.get_or_init(|| std::sync::Mutex::new(String::new()))
}

pub fn set_local_validator(address: &str) {
    if address.is_empty() { return; }
    let mut local = local_validator_mutex().lock().unwrap();
    if *local != address {
        if !local.is_empty() {
            known_validators().remove(&*local);
        }
        *local = address.to_string();
    }
    drop(local);
    register_known_validator(address);
}

pub fn local_validator_is_unset() -> bool {
    local_validator_mutex().lock().map(|v| v.is_empty()).unwrap_or(true)
}

pub fn ensure_local_validator_identity() -> bool {
    // This is called from sync code, so blocking is fine.
    let ledger = crate::ledger::Ledger::load();
    if ledger.address.is_empty() { return false; }
    if BLS_SECRET_KEY.get().is_none() {
        if let Ok(Some(seed_bytes)) = crate::ledger::load_seed() {
            if seed_bytes.len() == 32 {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&seed_bytes);
                let vk_hex = {
                    use ed25519_dalek::SigningKey;
                    hex::encode(SigningKey::from_bytes(&seed).verifying_key().as_bytes())
                };
                record_peer_ed25519(&ledger.address, &vk_hex);
                let bls_sk = crate::bls_agg::derive_bls_key(&seed_bytes);
                let bls_pk_bytes = crate::bls_agg::bls_pubkey(&bls_sk);
                crate::chain_db::persist_validator_bls_pubkey(&ledger.address, &hex::encode(&bls_pk_bytes));
                peer_bls_pubkeys().insert(ledger.address.clone(), bls_pk_bytes);
                let _ = BLS_SECRET_KEY.set(bls_sk);
            }
        }
    }
    set_local_validator(&ledger.address);
    true
}


const VALIDATOR_WARMUP_SECS: i64 = 10;

fn warmed_validator_count() -> usize {
    let now = chrono::Utc::now().timestamp();
    let all: Vec<String> = known_validators().iter().cloned().collect();
    let first = validator_first_seen();
    all.iter()
        .filter(|addr| is_eligible_validator(addr)) // stake-gated (Sybil resistance)
        .filter(|addr| {
            first.get(*addr).map(|&t| now - t >= VALIDATOR_WARMUP_SECS).unwrap_or(false)
        })
        .count()
        .max(1)
}

fn bft_threshold() -> usize {
    evict_stale_validators(VALIDATOR_LIVENESS_SECS);
    let min_validators = crate::mempool::min_validators_for_finality();
    let registered = crate::chain_db::registered_validators_sorted();
    let (n_total, effective) = if !registered.is_empty() {
        let slashed = slashed_validators();
        let n_reg = registered.iter().filter(|a| !slashed.contains(*a)).count();
        // A validator_register tx is permanent — the on-chain registry only ever
        // grows, so an address that registered once and never came back would
        // otherwise inflate the quorum bar forever, eventually making it
        // impossible for the currently-active minority to ever finalize again.
        // Only count registered validators actually seen recently; the honest
        // minimum floor (min_validators) still applies, so this can only ever
        // relax an artificially inflated requirement, never drop below "no solo."
        let live: std::collections::HashSet<String> = live_validators().into_iter().collect();
        let n_live_reg = registered.iter().filter(|a| !slashed.contains(*a) && live.contains(*a)).count();
        let eff = n_live_reg.max(min_validators).min(crate::bft_committee::COMMITTEE_SIZE);
        (n_reg, eff)
    } else {
        let snapshot: Vec<String> = known_validators().iter().cloned().collect();
        let nt = snapshot.iter().filter(|a| is_eligible_validator(a)).count();
        let n  = warmed_validator_count();
        // No solo production: a block ALWAYS requires a real ≥`min_validators`
        // distinct-validator quorum, even at pre-registration genesis. A lone node
        // therefore halts (threshold 2, only its own vote) instead of solo-producing
        // a private fork that can never reconcile with the network once a peer joins.
        let eff = n.max(min_validators).min(crate::bft_committee::COMMITTEE_SIZE);
        (nt, eff)
    };
    eprintln!("[BFT] Committee size: {} effective / {} total validators", effective, n_total);
    (effective * 2 + 2) / 3
}

/// Returns true if the set of voters represents ≥ ⅔ of total staked EGOC.
/// This is the stake-weighted quorum check — prevents Sybil attacks where an
/// attacker registers many low-stake nodes to reach the node-count threshold.
/// Both bft_threshold() AND this must pass before a block is finalized.
const STAKE_QUORUM_ENFORCE_HEIGHT: u64 = 1;

const MIN_VALIDATORS_FOR_STAKE_QUORUM: usize = 10;
const MIN_STAKE_FOR_QUORUM_UEGOC: u64 = 10_000_000_000_000; // 10M EGOC collectively staked

fn stake_quorum_reached(voters: &[String]) -> bool {
    let current_height = crate::chain_db::block_count();

    if current_height < STAKE_QUORUM_ENFORCE_HEIGHT {
        return true;
    }

    if warmed_validator_count() < MIN_VALIDATORS_FOR_STAKE_QUORUM {
        return true;
    }

    let validators = known_validators();
    if validators.is_empty() { return true; }

    let total_stake: u64 = validators.iter()
        .map(|addr| crate::ledger::get_validator_stake(addr))
        .sum();

    if total_stake < MIN_STAKE_FOR_QUORUM_UEGOC {
        return true;
    }

    let voter_stake: u64 = voters.iter()
        .filter(|v| validators.contains(*v))
        .map(|addr| crate::ledger::get_validator_stake(addr))
        .sum();

    let ok = voter_stake * 3 >= total_stake * 2;
    if !ok {
        tracing::warn!("Stake quorum not reached: voter_stake={} total_stake={} (need >=2/3)",
            voter_stake, total_stake);
    }
    ok
}


static PEER_RELAY_NODES: std::sync::OnceLock<std::sync::Mutex<HashMap<String, String>>> =
    std::sync::OnceLock::new();


static DHT_SEEN_MSGS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
    std::sync::OnceLock::new();

fn dht_seen() -> std::sync::MutexGuard<'static, std::collections::HashSet<String>> {
    DHT_SEEN_MSGS
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
        .lock()
        .unwrap()
}

fn peer_relay_nodes() -> std::sync::MutexGuard<'static, HashMap<String, String>> {
    PEER_RELAY_NODES
        .get_or_init(|| std::sync::Mutex::new(HashMap::new()))
        .lock()
        .unwrap()
}

pub fn get_discovered_relay_nodes() -> Vec<String> {
    peer_relay_nodes().values().cloned().collect()
}

pub(crate) fn current_wallet_announce_keys() -> (String, String) {
    if let Some(kp) = crate::app::global_app_state().get_keypair() {
        return (
            hex::encode(kp.dilithium_public_key().key_data),
            hex::encode(kp.ed25519_public_key().as_bytes()),
        );
    }

    let seed_bytes = match crate::ledger::load_seed().ok().flatten() {
        Some(bytes) if bytes.len() >= 32 => bytes,
        _ => return (String::new(), String::new()),
    };
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes[..32]);

    let vrf_hex = {
        use ed25519_dalek::SigningKey;
        hex::encode(SigningKey::from_bytes(&seed).verifying_key().as_bytes())
    };
    let dilithium_hex = std::fs::read(crate::ledger::data_dir().join("pq_keys.bin"))
        .ok()
        .and_then(|bytes| {
            let unprotected = crate::utils::os_unprotect(&bytes);
            ego_core::KeyPair::from_pq_cache(&unprotected, &seed)
                .or_else(|_| ego_core::KeyPair::from_pq_cache(&bytes, &seed))
                .ok()
        })
        .map(|kp| hex::encode(kp.dilithium_public_key().key_data))
        .unwrap_or_default();

    (dilithium_hex, vrf_hex)
}

fn current_wallet_keypair_for_announce() -> Option<ego_core::KeyPair> {
    if let Some(kp) = crate::app::global_app_state().get_keypair() {
        return Some(kp);
    }
    let seed_bytes = crate::ledger::load_seed().ok().flatten()?;
    if seed_bytes.len() < 32 { return None; }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes[..32]);
    let pq = std::fs::read(crate::ledger::data_dir().join("pq_keys.bin")).ok()?;
    ego_core::KeyPair::from_pq_cache(&pq, &seed).ok()
}

fn peer_announce_signing_data(
    address: &str,
    endpoint: &str,
    endpoints: &[String],
    coverage_score: u64,
    dilithium_pubkey: &str,
    vrf_pubkey: &str,
    staked_amount: u64,
    genesis_hash: &str,
    machine_id: &str,
) -> Vec<u8> {
    format!(
        "ego/peer-announce/v2:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        address,
        endpoint,
        endpoints.join(","),
        coverage_score,
        dilithium_pubkey,
        vrf_pubkey,
        staked_amount,
        genesis_hash,
        machine_id,
    ).into_bytes()
}

pub(crate) fn sign_peer_announce(
    address: &str,
    endpoint: &str,
    endpoints: &[String],
    coverage_score: u64,
    dilithium_pubkey: &str,
    vrf_pubkey: &str,
    staked_amount: u64,
    genesis_hash: &str,
    machine_id: &str,
) -> String {
    let data = peer_announce_signing_data(
        address, endpoint, endpoints, coverage_score, dilithium_pubkey, vrf_pubkey, staked_amount, genesis_hash, machine_id
    );
    // Prefer a Dilithium signature when the PQ keypair is available (post-quantum,
    // and verifiable by every peer). When it isn't loaded, fall back to an Ed25519
    // signature derived from the seed — the address is Ed25519-derived, so this is
    // a valid identity proof and lets the node still join the committee instead of
    // announcing an unsigned, always-rejected identity.
    if let Some(kp) = current_wallet_keypair_for_announce() {
        return hex::encode(kp.sign_dilithium(&data).signature_data);
    }
    if let Some(seed) = get_ed25519_seed() {
        use ed25519_dalek::{Signer, SigningKey};
        return hex::encode(SigningKey::from_bytes(&seed).sign(&data).to_bytes());
    }
    String::new()
}

fn verify_peer_announce_identity(
    address: &str,
    endpoint: &str,
    endpoints: &[String],
    coverage_score: u64,
    dilithium_pubkey: &str,
    vrf_pubkey: &str,
    staked_amount: u64,
    genesis_hash: &str,
    machine_id: &str,
    signature: &str,
) -> bool {
    // The canonical Ego address is Ed25519-derived (see KeyPair::derive_address),
    // so a peer's identity can be proven with EITHER its Dilithium key (legacy /
    // PQ-capable nodes) or its Ed25519 key. Accepting Ed25519 is essential: a node
    // whose Dilithium keypair isn't loaded (no pq_keys.bin) announces an
    // Ed25519-only identity, and rejecting it left it permanently out of the
    // validator committee — the real reason quorum never formed.
    let dil_pk: Option<Vec<u8>> = hex::decode(dilithium_pubkey).ok().filter(|b| !b.is_empty());
    let ed_pk: Option<Vec<u8>>  = hex::decode(vrf_pubkey).ok().filter(|b| b.len() == 32);

    let dil_derived = dil_pk.as_ref().map(|b| ego_core::EgoAddress::from_dilithium_pk(
        b, 1, ego_core::AddressType::EOA,
    ).to_bech32("egot").unwrap_or_default());
    let ed_derived = ed_pk.as_ref().map(|b| ego_core::EgoAddress::from_public_key_bytes(
        b, 1, ego_core::AddressType::EOA,
    ).to_bech32("egot").unwrap_or_default());

    if dil_derived.as_deref() != Some(address) && ed_derived.as_deref() != Some(address) {
        tracing::debug!("[P2P] Rejected peer {} - announced keys do not derive this address", address);
        return false;
    }
    let sig = match hex::decode(signature) {
        Ok(bytes) if !bytes.is_empty() => bytes,
        _ => return false,
    };
    let data = peer_announce_signing_data(
        address, endpoint, endpoints, coverage_score, dilithium_pubkey, vrf_pubkey, staked_amount, genesis_hash, machine_id
    );

    // Ed25519 path (preferred, and cryptographically sound: the address IS the
    // Ed25519 key). A 64-byte Ed25519 signature over the announce by the address's
    // key proves identity — and works for nodes without a loaded Dilithium key.
    if ed_derived.as_deref() == Some(address) {
        if let Some(ref ed_bytes) = ed_pk {
            use ed25519_dalek::{Signature as EdSig, Verifier, VerifyingKey};
            if let (Ok(pk_arr), Ok(sig_arr)) = (
                <[u8; 32]>::try_from(ed_bytes.as_slice()),
                <[u8; 64]>::try_from(sig.as_slice()),
            ) {
                if let Ok(vk) = VerifyingKey::from_bytes(&pk_arr) {
                    if vk.verify(&data, &EdSig::from_bytes(&sig_arr)).is_ok() {
                        return true;
                    }
                }
            }
        }
    }

    // Dilithium path (legacy / PQ-capable nodes that sign the announce with
    // Dilithium). The address gate above already passed, so verify the Dilithium
    // signature against the announced Dilithium key.
    if let Some(ref dil_bytes) = dil_pk {
        let pk = ego_core::PublicKey::dilithium2(dil_bytes.clone());
        let dsig = ego_core::Signature::dilithium2(sig.clone());
        if ego_core::verify_signature(&pk, &data, &dsig).unwrap_or(false) {
            return true;
        }
        // Fallback for v1 peers
        let data_legacy = format!(
            "ego/peer-announce/v1:{}:{}:{}:{}:{}:{}:{}",
            address, endpoint, coverage_score, dilithium_pubkey, vrf_pubkey, staked_amount, genesis_hash
        ).into_bytes();
        if ego_core::verify_signature(&pk, &data_legacy, &dsig).unwrap_or(false) {
            return true;
        }
    }

    false
}

// ── Wire protocol ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum P2PMessage {
    ContactRequest {
        from_addr:       String,
        from_name:       String,
        from_ed25519:    String,
        from_kyber:      String,
        from_shared_key: String,
        from_endpoint:   String,
        #[serde(default)]
        bundle_token:    Option<String>,
    },
    ContactResponse {
        from_addr:     String,
        from_name:     String,
        from_ed25519:  String,
        from_kyber:    String,
        approved:      bool,
        shared_key:    String,
        #[serde(default)]
        from_endpoint: String,
    },
    /// A contact telling us their profile picture changed. Carries only the
    /// avatar — the contact's name is whatever the local user set it to.
    ProfileUpdate {
        from_addr: String,
        avatar:    String,
    },
    /// Any messenger message, encrypted to one recipient and broadcast on the
    /// gossip mesh. Direct dials and DHT records both fail whenever every peer
    /// sits behind NAT on relay circuits; the gossip mesh is the only transport
    /// that keeps working there, so it carries a sealed envelope as a fallback.
    /// Only `to` is in the clear — enough to drop other people's envelopes
    /// without doing any crypto, and nothing else about the pair leaks.
    SealedDm {
        to:      String,
        eph_pub: String,
        nonce:   String,
        ct:      String,
        id:      String,
    },
    PeerAnnounce {
        address:  String,
        name:     String,
        endpoint: String,
        #[serde(default)]
        endpoints: Vec<String>,
        #[serde(default)]
        city:    Option<String>,
        #[serde(default)]
        country: Option<String>,
        #[serde(default)]
        lat: Option<f64>,
        #[serde(default)]
        lon: Option<f64>,
        #[serde(default)]
        coverage_score: u64,
        #[serde(default, alias = "ed25519_pubkey")]
        dilithium_pubkey: String,
        #[serde(default)]
        vrf_pubkey: String,
        #[serde(default)]
        staked_amount: u64,
        #[serde(default)]
        genesis_hash: String,
        #[serde(default)]
        signature: String,
        #[serde(default)]
        machine_id: String,
    },
    ChatMessage {
        bundle: String,
        #[serde(default)]
        seq: u64,
    },
    // Sent by the reader back to the original sender when they open a chat and
    // see previously-unread messages — lets the sender show "Read" on their
    // own outgoing bubbles. Metadata only (message IDs, not content), so it
    // isn't run through the chat double-ratchet like ChatMessage is.
    ReadReceipt {
        from:        String,
        to:          String,
        message_ids: Vec<String>,
    },
    TxBroadcast {
        tx:    LedgerTx,
        block: LedgerBlock,
    },
    ChainSyncRequest {
        requester_endpoint: String,
        #[serde(default)]
        from_height: u64,
    },
    ChainSyncResponse {
        blocks:       Vec<LedgerBlock>,
        transactions: Vec<LedgerTx>,
    },
    SnapshotRequest {
        requester_endpoint: String,
        #[serde(default)]
        have_height: u64,
    },
    SnapshotResponse {
        snapshot: crate::chain_db::StateSnapshot,
    },
    PeerListRequest {
        requester_endpoint: String,
    },
    PeerListResponse {
        peers: Vec<PeerEntry>,
    },
    PeerSeedGossip {
        multiaddrs: Vec<String>,
        known_count: u32,
    },
    FileRequest {
        cid: String,
        requester_addr: String,
        requester_endpoint: String,
    },
    FileData {
        cid: String,
        enc_data_b64: String,
        file_name: String,
        key_nonce_hex: String, 
    },
    FileChunk {
        cid:          String,
        chunk_index:  u32,
        total_chunks: u32,
        data_b64:     String,
        file_name:    String,
    },
    FileChunkComplete {
        cid:       String,
        file_name: String,
        enc_data_b64: String,
    },

    DataManifest {
        from_addr:    String,
        cids:         Vec<String>,
        available_gb: f64,
        is_relay:     bool,     
        endpoint:     String,
    },
    PinRequest {
        cid:           String,
        from_addr:     String,
        from_endpoint: String,
        /// Total storage fee for this deal so the slave can compute its collateral (20%).
        #[serde(default)]
        storage_fee_uegoc: u64,
        /// Deal expiry so slave knows how long to hold and when collateral is returned.
        #[serde(default)]
        expiry: i64,
    },

    PinAck {
        cid:      String,
        accepted: bool,
        reason:   String,
        #[serde(default)]
        from_addr: String,
    },

    /// Master → slaves: "I still hold this CID, replica is healthy"
    ReplicaHeartbeat {
        cid:         String,
        master_addr: String,
        timestamp:   i64,
        /// When the sender became master for this CID. Used to resolve split-brain:
        /// the LATER promotion wins (the failover master that actually served while
        /// the old master was dark), falling back to lowest address on a tie.
        #[serde(default)]
        master_since: i64,
    },

    /// Slave → master: "I'm alive and still hold this CID." Lets the master track
    /// per-replica liveness, move silent replicas into the 24h rejoin grace window,
    /// and proof-challenge returning ones instead of re-transferring the data.
    ReplicaHeartbeatAck {
        cid:          String,
        replica_addr: String,
        timestamp:    i64,
    },

    /// Slave → network: "Master {master_addr} has not responded for {MASTER_TIMEOUT_SECS}s.
    ///  I am promoting myself to master and need a new slave."
    ReplicaPromote {
        cid:          String,
        new_master:   String,
        old_master:   String,
        timestamp:    i64,
    },
    BlockProposal {
        block:        LedgerBlock,
        transactions: Vec<LedgerTx>,
        proposer:     String,
        signature:    String,
        #[serde(default)]
        vrf_ticket:   String,
        /// The consensus view this proposal was created in. Lets committee members
        /// adopt the leader's view (pacemaker sync) and reject proposals from anyone
        /// who is not the deterministic leader of that view — so two desynced nodes
        /// can't both have their competing proposals voted into a quorum.
        #[serde(default)]
        view:         u64,
        #[serde(default)]
        proposer_pubkey: String,
    },

    // ── Consensus-v2 (ego-consensus-core BftEngine) ──────────────────────────
    // The post-quantum HotStuff engine that will replace the inline BFT above.
    // SHADOW PATH: defined so the messages can coexist on the wire during cutover;
    // they are NOT yet produced or routed into live consensus.
    /// Engine proposal: the `BlockHeader` that votes are cast over, plus the full
    /// `LedgerBlock` payload it commits to (gossiped so the committee can validate +
    /// persist it).
    BftV2Proposal {
        header:       ego_consensus_core::bft::BlockHeader,
        block:        LedgerBlock,
        transactions: Vec<LedgerTx>,
    },
    /// Engine vote (ed25519 or Dilithium per the active `SigScheme`).
    BftV2Vote {
        vote: ego_consensus_core::bft::Vote,
    },
    /// Engine view-change (carries the sender's high-QC for HotStuff safety).
    BftV2ViewChange {
        msg: ego_consensus_core::fork_choice::ViewChangeMsg,
    },

    ValidatorLeaving {
        address:   String,
        timestamp: i64,
        signature: String,
    },

    BlockVote {
        block_hash: String,
        height:     u64,
        voter:      String,
        signature:  String,
        timestamp:  i64,
        #[serde(default)]
        vrf_ticket: String,
        #[serde(default)]
        prev_hash:  String,
        #[serde(default)]
        bls_sig:    String,
        #[serde(default)]
        bls_pubkey: String,
        /// Voter's Ed25519 pubkey (hex). Carried with the vote so any receiver can
        /// verify the signature without having first seen the voter's announce —
        /// it is trusted only after confirming it derives `voter`'s address.
        #[serde(default)]
        voter_pubkey: String,
    },
    BlockFinalized {
        block:        LedgerBlock,
        transactions: Vec<LedgerTx>,
        votes:        Vec<serde_json::Value>,
        #[serde(default)]
        agg_bls_sig:  String,
        #[serde(default)]
        bls_pubkeys:  Vec<String>,
    },
    ShardAnnounce {
        from_addr:          String,
        from_endpoint:      String,
        held_shards:        Vec<u32>,
        uptime_secs:        u64,
        network_node_count: u32,
        shard_count:        u32,
    },
    /// Slave promotes itself to master after detecting master is offline.
    MasterPromotion {
        shard_id:      u32,
        new_master:    String,
        new_endpoint:  String,
        former_master: String,
        timestamp:     i64,
    },
    /// Slave asks master to send blocks for a specific shard starting from `from_height`.
    ShardDataRequest {
        shard_id:             u32,
        from_height:          u64,
        requester_address:    String,
        requester_endpoint:   String,
    },
    ShardDataResponse {
        shard_id:     u32,
        blocks:       Vec<LedgerBlock>,
        transactions: Vec<LedgerTx>,
    },
    /// Route a block-height query to the correct shard holder (Phase 3).
    ShardBlockQuery {
        block_height:       u64,
        requester_address:  String,
        requester_endpoint: String,
    },
    /// Response to ShardBlockQuery.
    ShardBlockResponse {
        block_height: u64,
        blocks:       Vec<LedgerBlock>,
        transactions: Vec<LedgerTx>,
    },
    ShardVacancyNotice {
        shard_id:        u32,
        current_holders: u32,
    },
    ShardVolunteer {
        shard_id:           u32,
        volunteer_address:  String,
        volunteer_endpoint: String,
    },
    ManifestRequest {
        manifest_cid:       String,
        requester_addr:     String,
        requester_endpoint: String,
    },
    ManifestData {
        manifest_cid:  String,
        manifest_json: String, 
        key_hex64:     String,  
        file_name:     String,
        from_addr:     String,
    },
    BlockRequest {
        block_cid:          String,
        manifest_cid:       String,  
        requester_addr:     String,
        requester_endpoint: String,
    },
    BlockData {
        block_cid:    String,
        manifest_cid: String,
        enc_b64:      String,  
        from_addr:    String,
    },
    ViewChange {
        view:      u64,
        voter:     String,
        signature: String,
        timestamp: i64,
    },
    HeaderSyncRequest {
        from_height: u64,
        limit:       u32,
    },
    HeaderSyncResponse {
        headers: Vec<crate::chain_db::LightBlockHeader>,
    },
    /// Broadcast when a node fails a PoSt challenge.
    /// Recipients independently verify by requesting the block from `accused_addr`.
    /// If they can't retrieve it or the comm_r doesn't match, they record the slash.
    StorageCommit {
        prover_addr: String,
        cid:         String,
        comm_r:      String,
        file_size:   u64,
        expiry:      i64,
        signature:   String,
    },
    SlashChallenge {
        accused_addr:    String,  // node that failed the proof
        cid:             String,  // file CID
        block_cid:       String,  // specific block that was challenged
        challenge_slot:  i64,     // deterministic time slot (now / POST_CHECK_INTERVAL_SECS)
        comm_r:          String,  // expected replica commitment for that block
        reporter_addr:   String,
        reporter_sig:    String,  // ed25519 over "slash:{accused}:{cid}:{block_cid}:{slot}"
    },
    /// PoRep spot-check (Item 17).
    ///
    /// Protocol (verifiable without either side holding a full copy):
    ///
    ///   1. Challenger picks a random block from the file's manifest.
    ///   2. Challenger loads the encrypted block from its own disk and computes
    ///      expected_response = BLAKE3(nonce_bytes || enc_block_bytes).
    ///   3. Challenger stores (block_cid, nonce) → expected_response locally.
    ///   4. Challenger broadcasts StorageProofChallenge.
    ///   5. Prover reads its own copy of enc_block, computes BLAKE3(nonce || enc_block)
    ///      and replies with StorageProofResponse.
    ///   6. Challenger compares the response against the locally computed expected.
    ///      Match → prover holds a valid replica.
    ///      Mismatch / timeout → penalise prover's coverage score.
    ///
    /// Security: the nonce is derived from BLAKE3(prover||cid||timestamp_ms||counter)
    /// — unpredictable by the prover before the challenge is broadcast.
    StorageProofChallenge {
        manifest_cid: String,  // file manifest CID
        block_cid:    String,  // specific block to prove
        nonce:        String,  // hex-encoded 32-byte challenge nonce
        challenger:   String,  // challenger address
    },
    StorageProofResponse {
        block_cid:     String,
        nonce:         String,
        response_hash: String,
        prover:        String,
    },
    HostingAnnounce {
        record: crate::chain_db::HostingNodeRecord,
    },
    ComputeAnnounce {
        node: crate::chain_db::ComputeNodeRecord,
    },
    ComputeJobPost {
        job: crate::chain_db::ComputeJob,
    },
    ComputeJobAccept {
        job_id:          String,
        worker_address:  String,
        worker_endpoint: String,
    },
    ComputeJobComplete {
        job_id:     String,
        output_cid: String,
        worker:     String,
    },
    ComputeJobCancel {
        job_id:         String,
        poster_address: String,
    },
    ComputeHeartbeat {
        job_id:    String,
        worker:    String,
        timestamp: i64,
    },
    CapacityOfferBroadcast {
        offer: crate::chain_db::ComputeCapacityOffer,
    },
    CapacityOfferCancelled {
        offer_id: String,
    },
    ClusterBookingCreated {
        booking: crate::chain_db::ClusterBooking,
    },
    ClusterNodeJoined {
        cluster_id:       String,
        provider_address: String,
        wg_pubkey:        String,
        endpoint:         String,
    },
    ClusterNodeHeartbeat {
        cluster_id:       String,
        provider_address: String,
        timestamp:        i64,
    },
    ClusterTerminated {
        cluster_id: String,
    },
    ReservationBooked {
        reservation: crate::chain_db::ComputeReservation,
        #[serde(default)]
        ssh_public_key: Option<String>,
    },
    ReservationHeartbeat {
        reservation_id: String,
        provider:       String,
        timestamp:      i64,
    },
    ReservationTerminated {
        reservation_id: String,
        by:             String,
        reason:         String,
    },
    StorageDealCreated { deal: crate::chain_db::StorageDeal },
    StorageDealProof { deal_id: String, provider: String, timestamp: i64 },
    StorageDealTerminated { deal_id: String, by: String },
    EquivocationProof {
        accused:  String,
        height:   u64,
        hash_a:   String,
        sig_a:    String,
        hash_b:   String,
        sig_b:    String,
        reporter: String,
    },
    ShardTxRoute {
        shard_id: u32,
        tx:       LedgerTx,
    },
    ShardRebalance {
        proposed_shard_count: u32,
        effective_at_height:  u64,
        proposer:             String,
    },
    PocEventBroadcast {
        address:   String,
        quality:   String,
        peers:     u32,
        timestamp: i64,
        signature: String,
    },
    PocBeacon {
        beacon_id:  String,
        address:    String,
        machine_id: String,
        cell:       String,
        epoch:      u64,
        timestamp:  i64,
        transport:  String,
        signature:  String,
    },
    PocWitnessReceipt {
        beacon_id:          String,
        beaconer:           String,
        witness:            String,
        witness_machine_id: String,
        witness_cell:       String,
        latency_ms:         u32,
        rssi_dbm:           i32,
        timestamp:          i64,
        signature:          String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEntry {
    pub address:   String,
    pub endpoint:  String,
    pub last_seen: i64,
    #[serde(default)]
    pub city:    Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub lat: Option<f64>,
    #[serde(default)]
    pub lon: Option<f64>,
}



#[derive(Debug, Clone, Default)]
struct EgoCodec;
impl request_response::Codec for EgoCodec {
    type Protocol = StreamProtocol;
    type Request  = P2PMessage;
    type Response = ();

    fn read_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _: &'life1 Self::Protocol,
        io: &'life2 mut T,
    ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = io::Result<Self::Request>> + ::core::marker::Send + 'async_trait>>
    where
        T: futures::io::AsyncRead + Unpin + Send + 'async_trait,
        'life0: 'async_trait, 'life1: 'async_trait, 'life2: 'async_trait, Self: 'async_trait,
    {
        Box::pin(async move {
            let mut len_buf = [0u8; 4];
            AsyncReadExt::read_exact(io, &mut len_buf).await?;
            let len = u32::from_be_bytes(len_buf) as usize;
            if len > 512 * 1024 * 1024 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "message too large"));
            }
            let mut buf = vec![0u8; len];
            AsyncReadExt::read_exact(io, &mut buf).await?;
            serde_json::from_slice(&buf)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        })
    }

    fn read_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _: &'life1 Self::Protocol,
        io: &'life2 mut T,
    ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = io::Result<Self::Response>> + ::core::marker::Send + 'async_trait>>
    where
        T: futures::io::AsyncRead + Unpin + Send + 'async_trait,
        'life0: 'async_trait, 'life1: 'async_trait, 'life2: 'async_trait, Self: 'async_trait,
    {
        Box::pin(async move {
            // Read ack byte — ignore errors (old peers send nothing)
            let mut buf = [0u8; 1];
            let _ = AsyncReadExt::read_exact(io, &mut buf).await;
            Ok(())
        })
    }

    fn write_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _: &'life1 Self::Protocol,
        io: &'life2 mut T,
        req: Self::Request,
    ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = io::Result<()>> + ::core::marker::Send + 'async_trait>>
    where
        T: futures::io::AsyncWrite + Unpin + Send + 'async_trait,
        'life0: 'async_trait, 'life1: 'async_trait, 'life2: 'async_trait, Self: 'async_trait,
    {
        Box::pin(async move {
            let data = serde_json::to_vec(&req)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            AsyncWriteExt::write_all(io, &(data.len() as u32).to_be_bytes()).await?;
            AsyncWriteExt::write_all(io, &data).await?;
            AsyncWriteExt::flush(io).await
        })
    }

    fn write_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _: &'life1 Self::Protocol,
        io: &'life2 mut T,
        _: Self::Response,
    ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = io::Result<()>> + ::core::marker::Send + 'async_trait>>
    where
        T: futures::io::AsyncWrite + Unpin + Send + 'async_trait,
        'life0: 'async_trait, 'life1: 'async_trait, 'life2: 'async_trait, Self: 'async_trait,
    {
        Box::pin(async move {
            // Write ack byte — ignore errors (remote may have already closed)
            let _ = AsyncWriteExt::write_all(io, &[0u8]).await;
            let _ = AsyncWriteExt::flush(io).await;
            Ok(())
        })
    }
}

// ── Compute exec protocol (libp2p request/response with payload) ─────────────
//
// Carries remote-shell commands ("EXEC") and resource probes ("METRICS") from
// a buyer's desktop to a provider's desktop over the existing libp2p swarm.
// This replaces the legacy HTTP `:8545/exec` flow, which required an ego-node
// daemon and was unreachable across NAT/firewalls.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeExecRequest {
    pub reservation_id:       String,
    pub command:              String,
    pub timestamp:            i64,
    pub dilithium_signature:  String,
    pub dilithium_public_key: String,
    /// "EXEC" runs the command as a shell process; "METRICS" returns sysinfo.
    pub kind:                 String,
    /// Self-attesting reservation, used when the provider doesn't yet have a
    /// cached entry. Signed implicitly because the buyer-key derivation must
    /// match `reservation.buyer_address`.
    #[serde(default)]
    pub reservation:          Option<crate::chain_db::ComputeReservation>,
    /// Base64 file content for `kind = "PUT"` (renter → sandbox upload). The
    /// signed `command` carries the destination filename; transport is already
    /// noise-encrypted and peer-authenticated, so the blob rides unsigned.
    #[serde(default)]
    pub payload:              Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeExecResponse {
    pub ok:    bool,
    /// Status code (HTTP-style: 200 OK, 401, 403, 500…). Helps the buyer's UI
    /// distinguish "auth failed" from "command crashed".
    pub status: u16,
    /// stdout+stderr for EXEC, JSON for METRICS, error text on failure.
    pub body:  String,
}

#[derive(Debug, Clone, Default)]
struct ExecCodec;
impl request_response::Codec for ExecCodec {
    type Protocol = StreamProtocol;
    type Request  = ComputeExecRequest;
    type Response = ComputeExecResponse;

    fn read_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _: &'life1 Self::Protocol,
        io: &'life2 mut T,
    ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = io::Result<Self::Request>> + ::core::marker::Send + 'async_trait>>
    where
        T: futures::io::AsyncRead + Unpin + Send + 'async_trait,
        'life0: 'async_trait, 'life1: 'async_trait, 'life2: 'async_trait, Self: 'async_trait,
    {
        Box::pin(async move {
            let mut len_buf = [0u8; 4];
            AsyncReadExt::read_exact(io, &mut len_buf).await?;
            let len = u32::from_be_bytes(len_buf) as usize;
            if len > 8 * 1024 * 1024 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "exec request too large"));
            }
            let mut buf = vec![0u8; len];
            AsyncReadExt::read_exact(io, &mut buf).await?;
            serde_json::from_slice(&buf)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        })
    }

    fn read_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _: &'life1 Self::Protocol,
        io: &'life2 mut T,
    ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = io::Result<Self::Response>> + ::core::marker::Send + 'async_trait>>
    where
        T: futures::io::AsyncRead + Unpin + Send + 'async_trait,
        'life0: 'async_trait, 'life1: 'async_trait, 'life2: 'async_trait, Self: 'async_trait,
    {
        Box::pin(async move {
            let mut len_buf = [0u8; 4];
            AsyncReadExt::read_exact(io, &mut len_buf).await?;
            let len = u32::from_be_bytes(len_buf) as usize;
            if len > 16 * 1024 * 1024 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "exec response too large"));
            }
            let mut buf = vec![0u8; len];
            AsyncReadExt::read_exact(io, &mut buf).await?;
            serde_json::from_slice(&buf)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        })
    }

    fn write_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _: &'life1 Self::Protocol,
        io: &'life2 mut T,
        req: Self::Request,
    ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = io::Result<()>> + ::core::marker::Send + 'async_trait>>
    where
        T: futures::io::AsyncWrite + Unpin + Send + 'async_trait,
        'life0: 'async_trait, 'life1: 'async_trait, 'life2: 'async_trait, Self: 'async_trait,
    {
        Box::pin(async move {
            let data = serde_json::to_vec(&req)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            AsyncWriteExt::write_all(io, &(data.len() as u32).to_be_bytes()).await?;
            AsyncWriteExt::write_all(io, &data).await?;
            AsyncWriteExt::flush(io).await
        })
    }

    fn write_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _: &'life1 Self::Protocol,
        io: &'life2 mut T,
        resp: Self::Response,
    ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = io::Result<()>> + ::core::marker::Send + 'async_trait>>
    where
        T: futures::io::AsyncWrite + Unpin + Send + 'async_trait,
        'life0: 'async_trait, 'life1: 'async_trait, 'life2: 'async_trait, Self: 'async_trait,
    {
        Box::pin(async move {
            let data = serde_json::to_vec(&resp)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            AsyncWriteExt::write_all(io, &(data.len() as u32).to_be_bytes()).await?;
            AsyncWriteExt::write_all(io, &data).await?;
            AsyncWriteExt::flush(io).await
        })
    }
}

// ── Network behaviour ─────────────────────────────────────────────────────────

#[derive(NetworkBehaviour)]
struct EgoBehaviour {
    relay_client:     relay::client::Behaviour,
    /// Relay server — any node with a public IP automatically serves as a circuit
    /// relay for NAT'd peers.  Fully decentralised: no dedicated relay servers needed.
    relay_server:     relay::Behaviour,
    dcutr:            dcutr::Behaviour,
    identify:         identify::Behaviour,
    request_response: request_response::Behaviour<EgoCodec>,
    /// Dedicated request/response channel for compute-exec calls (carries
    /// stdout/stderr payloads on the way back, so it needs its own codec).
    compute_exec:     request_response::Behaviour<ExecCodec>,
    autonat:          autonat::Behaviour,
    ping:             ping::Behaviour,
    gossipsub:        gossipsub::Behaviour,
    kad:              kad::Behaviour<kad::store::MemoryStore>,
    /// Zero-config local-network discovery. Two nodes on the same LAN find and
    /// connect to each other directly over mDNS — no relay, no oracle, no NAT
    /// traversal — so same-network peers always form a committee even when the
    /// public relay path is flaky.
    mdns:             mdns::tokio::Behaviour,
    /// Automatic router port-mapping (UPnP-IGD / NAT-PMP). Asks the home router to
    /// open a port for us so the node becomes DIRECTLY reachable from the internet
    /// with no manual firewall config and no admin prompt — the same mechanism
    /// IPFS uses to "just work" behind consumer routers on every OS.
    upnp:             upnp::tokio::Behaviour,
    /// Raw byte-stream channel used by the in-browser app tunnel
    /// (`/ego/tunnel/1`) — relays a renter's local TCP connection to a web app
    /// running inside the rental's Docker sandbox.
    stream:           libp2p_stream::Behaviour,
}

// ── Swarm command channel ─────────────────────────────────────────────────────

pub enum SwarmCmd {
    Send {
        peer_addr: Multiaddr,
        msg:       P2PMessage,
        reply:     oneshot::Sender<Result<(), String>>,
    },
    GetEndpoint {
        reply: oneshot::Sender<String>,
    },
    GossipPublish {
        topic: String,
        data:  Vec<u8>,
    },
    ComputeExec {
        peer_addr: Multiaddr,
        req:       ComputeExecRequest,
        reply:     oneshot::Sender<Result<ComputeExecResponse, String>>,
    },
    /// Ensure a connection to the peer in `peer_addr` exists (dialling if
    /// needed), then reply with its PeerId. Used before opening a tunnel stream.
    Dial {
        peer_addr: Multiaddr,
        reply:     oneshot::Sender<Result<PeerId, String>>,
    },
}

static SWARM_TX: OnceLock<mpsc::Sender<SwarmCmd>> = OnceLock::new();

// ── In-browser app tunnel ───────────────────────────────────────────────────
//
// A raw bidirectional byte stream that relays a renter's local TCP connection
// (their browser) to a web app (Jupyter, Gradio, …) running inside the rental's
// Docker sandbox. It rides the existing libp2p connection, so it inherits NAT
// traversal. The first frame on every stream is a length-prefixed signed
// handshake; the provider authenticates it exactly like a compute-exec request
// before connecting to the container's published host port.

const TUNNEL_PROTOCOL: StreamProtocol = StreamProtocol::new("/ego/tunnel/1");

/// Clonable handle to open outbound `/ego/tunnel/1` streams. Set once the swarm
/// is built; cloned per connection (cheap) so opens don't serialise.
static TUNNEL_CONTROL: OnceLock<libp2p_stream::Control> = OnceLock::new();

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelHandshake {
    pub reservation_id:       String,
    pub container_port:       u16,
    pub timestamp:            i64,
    pub dilithium_public_key: String,
    pub dilithium_signature:  String,
    #[serde(default)]
    pub reservation:          Option<crate::chain_db::ComputeReservation>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Sends a compute-exec request to `endpoint` (a libp2p multiaddr containing
/// the provider's peer ID) and waits for the response. Replaces the old
/// HTTP `:8545/exec` flow with a NAT-traversing libp2p call.
pub async fn compute_exec(endpoint: &str, req: ComputeExecRequest) -> Result<ComputeExecResponse, String> {
    let tx = SWARM_TX.get().ok_or_else(|| "P2P not started".to_string())?;
    let peer_addr: Multiaddr = endpoint
        .parse()
        .map_err(|e| format!("Invalid multiaddr '{}': {}", endpoint, e))?;
    let (reply_tx, reply_rx) = oneshot::channel();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tx.send(SwarmCmd::ComputeExec { peer_addr, req, reply: reply_tx }),
    )
    .await
    .map_err(|_| "Swarm channel send timed out".to_string())?
    .map_err(|_| "Swarm channel closed".to_string())?;
    tokio::time::timeout(std::time::Duration::from_secs(180), reply_rx)
        .await
        .map_err(|_| "Compute-exec reply timed out".to_string())?
        .map_err(|_| "Swarm dropped reply".to_string())?
}

/// Tries each endpoint in priority order (LAN → public → relay circuit).
/// Returns the first successful response or the last error.
pub async fn compute_exec_any(endpoints: &[String], req: &ComputeExecRequest) -> Result<ComputeExecResponse, String> {
    if endpoints.is_empty() {
        return Err("No endpoints available".to_string());
    }
    let mut sorted: Vec<String> = endpoints.iter()
        .filter(|ep| !ep.contains("/ip4/169.254."))
        .cloned()
        .collect();
    if sorted.is_empty() {
        return Err("No reachable endpoints (all link-local filtered)".to_string());
    }
    sorted.sort_by_key(|ep| {
        if ep.contains("/ip4/192.168.") || ep.contains("/ip4/10.") || ep.contains("/ip4/172.") { 0usize }
        else if ep.contains("/p2p-circuit") { 2 }
        else { 1 }
    });
    let mut last_err = String::new();
    for ep in &sorted {
        match compute_exec(ep, req.clone()).await {
            Ok(r)  => return Ok(r),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// Provider-side handler: invoked when an inbound libp2p compute-exec request
/// arrives. Verifies the buyer's signed reservation attestation, then either
/// runs the command (kind="EXEC") or gathers usage metrics (kind="METRICS").
async fn serve_compute_exec(req: ComputeExecRequest) -> ComputeExecResponse {
    let now = chrono::Utc::now().timestamp();
    if (now - req.timestamp).abs() > 30 {
        return ComputeExecResponse { ok: false, status: 400, body: "Request expired (timestamp mismatch)".into() };
    }

    let dil_pk_bytes = match hex::decode(&req.dilithium_public_key) {
        Ok(b) if !b.is_empty() => b,
        _ => return ComputeExecResponse { ok: false, status: 400, body: "Missing/invalid dilithium_public_key".into() },
    };

    let my_addr = crate::ledger::Ledger::load().address;
    let hrp = if my_addr.starts_with("egot") { "egot" } else { "ego" };
    let chain_id: u32 = if hrp == "egot" { 1 } else { 0 };
    let derived_bech32 = match ego_core::EgoAddress::from_dilithium_pk(
        &dil_pk_bytes, chain_id, ego_core::AddressType::EOA,
    ).to_bech32(hrp) {
        Ok(s)  => s,
        Err(_) => return ComputeExecResponse { ok: false, status: 500, body: "Failed to derive bech32 address".into() },
    };

    // Trust order: locally stored reservation > buyer-supplied attestation.
    let reservation = crate::chain_db::get_compute_reservation(&req.reservation_id)
        .or_else(|| req.reservation.clone());
    let reservation = match reservation {
        Some(r) => r,
        None    => return ComputeExecResponse {
            ok: false, status: 401,
            body: format!("Unknown reservation {} and no attestation provided", req.reservation_id),
        },
    };

    if reservation.reservation_id != req.reservation_id {
        return ComputeExecResponse { ok: false, status: 400, body: "Reservation id mismatch".into() };
    }
    if !exec_addrs_match(&reservation.provider_address, &my_addr) {
        return ComputeExecResponse {
            ok: false, status: 403,
            body: format!("Reservation provider {} does not match this node {}",
                reservation.provider_address, my_addr),
        };
    }
    if !exec_addrs_match(&reservation.buyer_address, &derived_bech32) {
        return ComputeExecResponse {
            ok: false, status: 403,
            body: format!("Dilithium key derives {}, but reservation buyer is {}",
                derived_bech32, reservation.buyer_address),
        };
    }
    if reservation.status != "active" {
        return ComputeExecResponse {
            ok: false, status: 403,
            body: format!("Reservation status is '{}', not active", reservation.status),
        };
    }
    if reservation.expires_at <= now {
        return ComputeExecResponse { ok: false, status: 403, body: "Reservation expired".into() };
    }

    let dil_sig_bytes = match hex::decode(&req.dilithium_signature) {
        Ok(b) if !b.is_empty() => b,
        _ => return ComputeExecResponse { ok: false, status: 400, body: "Missing/invalid dilithium_signature".into() },
    };
    let dil_pk  = ego_core::PublicKey::new(ego_core::AlgorithmId::MlDsa2, dil_pk_bytes);
    let dil_sig = ego_core::Signature::dilithium2(dil_sig_bytes);
    let signed_msg = format!("{}:{}:{}", req.reservation_id, req.command, req.timestamp);
    match ego_core::verify_signature(&dil_pk, signed_msg.as_bytes(), &dil_sig) {
        Ok(true)  => {}
        Ok(false) => return ComputeExecResponse { ok: false, status: 401, body: "Invalid Dilithium signature".into() },
        Err(e)    => return ComputeExecResponse { ok: false, status: 401, body: format!("Signature verify error: {e}") },
    }

    match req.kind.as_str() {
        "METRICS" => {
            // Prefer real per-rental stats from the Docker sandbox. These reflect
            // only the renter's own workload, capped to what they paid for.
            let res_probe = reservation.clone();
            let sandboxed = tokio::task::spawn_blocking(move || crate::sandbox::metrics(&res_probe))
                .await.ok().flatten();

            let (cpu, ram_used_gb, gpu, os, is_sandbox): (f32, f64, i32, &str, bool) =
                if let Some((c, r, g)) = sandboxed {
                    (c, r, g, "linux", true)
                } else {
                    // Fallback: no sandbox runtime — report the host machine, honestly.
                    use sysinfo::{System, CpuRefreshKind};
                    let mut sys = System::new();
                    sys.refresh_cpu_specifics(CpuRefreshKind::new().with_cpu_usage());
                    sys.refresh_memory();
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    sys.refresh_cpu();
                    let cpu = sys.global_cpu_info().cpu_usage();
                    let ram_used_gb = (sys.used_memory() as f64 / 1_073_741_824.0)
                        .min(reservation.ram_gb as f64);
                    let gpu = std::process::Command::new("nvidia-smi")
                        .args(["--query-gpu=utilization.gpu", "--format=csv,noheader,nounits"])
                        .output()
                        .ok()
                        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<i32>().ok())
                        .unwrap_or(0);
                    let host_os = if cfg!(target_os = "windows") { "windows" }
                                  else if cfg!(target_os = "macos") { "macos" }
                                  else { "linux" };
                    (cpu, ram_used_gb, gpu, host_os, false)
                };
            let body = serde_json::json!({
                "cpu": cpu, "ram_used_gb": ram_used_gb, "gpu": gpu,
                "os": os, "sandboxed": is_sandbox,
            }).to_string();
            ComputeExecResponse { ok: true, status: 200, body }
        }
        "SPECS" => {
            use sysinfo::System;
            let mut sys = System::new_all();
            sys.refresh_all();
            let cpu_model = sys.cpus().first()
                .map(|c| c.brand().trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "Unknown CPU".into());
            let cores     = sys.cpus().len();
            let total_ram = sys.total_memory() as f64 / 1_073_741_824.0;
            let used_ram  = sys.used_memory()  as f64 / 1_073_741_824.0;
            let os = if cfg!(target_os = "windows") { "Windows" }
                     else if cfg!(target_os = "macos") { "macOS" }
                     else { "Linux" };
            let gpu = std::process::Command::new("nvidia-smi")
                .args(["--query-gpu=name,memory.total", "--format=csv,noheader"])
                .output().ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim()
                    .lines().map(|l| l.trim()).collect::<Vec<_>>().join(", "))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "No CUDA GPU detected".into());
            let isolation = if tokio::task::spawn_blocking(crate::sandbox::docker_available).await.unwrap_or(false) {
                format!("Docker sandbox — your commands run isolated, capped to {} core(s) / {} GB RAM{}",
                    reservation.cpu_cores, reservation.ram_gb,
                    if reservation.gpu_count > 0 { format!(" / {} GPU", reservation.gpu_count) } else { String::new() })
            } else {
                "none — provider has no Docker runtime; commands share the host (no resource cap)".to_string()
            };
            let body = format!(
                "Remote host hardware (the provider machine you rented)\n\
                 ----------------------------------------------\n\
                 OS:        {os}\n\
                 CPU:       {cpu_model}\n\
                 Cores:     {cores} physical/logical  (you rented {})\n\
                 RAM:       {used_ram:.1} GB in use / {total_ram:.1} GB total  (you rented {} GB)\n\
                 GPU:       {gpu}\n\
                 Isolation: {isolation}",
                reservation.cpu_cores, reservation.ram_gb,
            );
            ComputeExecResponse { ok: true, status: 200, body }
        }
        "PUT" | "APPEND" | "GET" | "GETR" | "LIST" => {
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            let docker = tokio::task::spawn_blocking(crate::sandbox::docker_available).await.unwrap_or(false);
            match req.kind.as_str() {
                "PUT" | "APPEND" => {
                    let bytes = match req.payload.as_ref().and_then(|b| STANDARD.decode(b).ok()) {
                        Some(b) => b,
                        None => return ComputeExecResponse { ok: false, status: 400, body: "Missing or invalid file payload".into() },
                    };
                    let res2 = reservation.clone();
                    let path = req.command.clone();
                    let append = req.kind == "APPEND";
                    let r = tokio::task::spawn_blocking(move || {
                        if docker {
                            if append { crate::sandbox::append_file(&res2, &path, &bytes) }
                            else      { crate::sandbox::put_file(&res2, &path, &bytes) }
                        } else {
                            if append { crate::sandbox::append_file_host(&res2, &path, &bytes) }
                            else      { crate::sandbox::put_file_host(&res2, &path, &bytes) }
                        }
                    }).await.unwrap_or_else(|e| Err(e.to_string()));
                    match r {
                        Ok(())  => ComputeExecResponse { ok: true,  status: 200, body: "ok".into() },
                        Err(e)  => ComputeExecResponse { ok: false, status: 400, body: e },
                    }
                }
                "GET" => {
                    let res2 = reservation.clone();
                    let path = req.command.clone();
                    let r = tokio::task::spawn_blocking(move || {
                        if docker { crate::sandbox::get_file(&res2, &path) }
                        else      { crate::sandbox::get_file_host(&res2, &path) }
                    }).await.unwrap_or_else(|e| Err(e.to_string()));
                    match r {
                        Ok(bytes) => ComputeExecResponse { ok: true, status: 200, body: STANDARD.encode(bytes) },
                        Err(e)    => ComputeExecResponse { ok: false, status: 400, body: e },
                    }
                }
                "GETR" => {
                    let mut parts = req.command.rsplitn(3, ':');
                    let len    = parts.next().and_then(|s| s.parse::<u64>().ok());
                    let offset = parts.next().and_then(|s| s.parse::<u64>().ok());
                    let name   = parts.next().map(|s| s.to_string());
                    let (name, offset, len) = match (name, offset, len) {
                        (Some(n), Some(o), Some(l)) => (n, o, l),
                        _ => return ComputeExecResponse { ok: false, status: 400, body: "Bad range request".into() },
                    };
                    let res2 = reservation.clone();
                    let r = tokio::task::spawn_blocking(move || {
                        if docker { crate::sandbox::read_range(&res2, &name, offset, len) }
                        else      { crate::sandbox::read_range_host(&res2, &name, offset, len) }
                    }).await.unwrap_or_else(|e| Err(e.to_string()));
                    match r {
                        Ok(bytes) => ComputeExecResponse { ok: true, status: 200, body: STANDARD.encode(bytes) },
                        Err(e)    => ComputeExecResponse { ok: false, status: 400, body: e },
                    }
                }
                _ => {
                    let res2 = reservation.clone();
                    let r = tokio::task::spawn_blocking(move || {
                        if docker { crate::sandbox::list_files(&res2) }
                        else      { crate::sandbox::list_files_host(&res2) }
                    }).await.unwrap_or_else(|e| Err(e.to_string()));
                    match r {
                        Ok(files) => {
                            let arr: Vec<_> = files.into_iter()
                                .map(|(name, size)| serde_json::json!({ "name": name, "size": size }))
                                .collect();
                            ComputeExecResponse { ok: true, status: 200, body: serde_json::Value::Array(arr).to_string() }
                        }
                        Err(e) => ComputeExecResponse { ok: false, status: 400, body: e },
                    }
                }
            }
        }
        "BENCH" => {
            let body = tokio::task::spawn_blocking(|| {
                let start = std::time::Instant::now();
                let mut s = 0.0f64;
                for i in 0..5_000_000u64 { s += (i as f64).sin(); }
                let secs = start.elapsed().as_secs_f64().max(1e-9);
                format!(
                    "AI speed test on the remote host\n\
                     ----------------------------------------------\n\
                     5,000,000 sin() ops in {secs:.3} s\n\
                     ~ {:.1} million ops/sec\n\
                     (lower time = faster hardware; checksum {s:.4})",
                    5.0 / secs,
                )
            }).await.unwrap_or_else(|e| format!("Benchmark failed: {e}"));
            ComputeExecResponse { ok: true, status: 200, body }
        }
        _ => {
            // Run inside the reservation's Docker sandbox when available; this
            // enforces the rented CPU/RAM/GPU caps and isolates the renter from
            // the host. Fall back to host shell when Docker isn't installed.
            let docker = tokio::task::spawn_blocking(crate::sandbox::docker_available)
                .await.unwrap_or(false);
            let result: Result<std::process::Output, String> = if docker {
                let res2 = reservation.clone();
                let cmd2 = req.command.clone();
                tokio::task::spawn_blocking(move || crate::sandbox::exec_in(&res2, &cmd2))
                    .await.unwrap_or_else(|e| Err(format!("sandbox join error: {e}")))
            } else {
                run_shell_command(&req.command).await.map_err(|e| format!("System error: {e}"))
            };
            match result {
                Ok(o) => {
                    let combined = String::from_utf8_lossy(&o.stdout).to_string()
                        + &String::from_utf8_lossy(&o.stderr);
                    ComputeExecResponse {
                        ok:     o.status.success(),
                        status: if o.status.success() { 200 } else { 400 },
                        body:   combined,
                    }
                }
                Err(e) => ComputeExecResponse { ok: false, status: 500, body: e },
            }
        }
    }
}

/// Runs a shell command, hunting for a usable shell binary because Tauri's
/// child-process environment on Windows doesn't always include the
/// WindowsPowerShell directory in PATH. Falls through PowerShell → pwsh → cmd.
async fn run_shell_command(command: &str) -> std::io::Result<std::process::Output> {
    if cfg!(target_os = "windows") {
        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        let candidates: Vec<(String, Vec<&'static str>)> = vec![
            (format!("{}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", system_root),
                vec!["-NoProfile", "-Command"]),
            ("powershell.exe".to_string(),
                vec!["-NoProfile", "-Command"]),
            ("pwsh.exe".to_string(),
                vec!["-NoProfile", "-Command"]),
            (format!("{}\\System32\\cmd.exe", system_root),
                vec!["/C"]),
            ("cmd.exe".to_string(),
                vec!["/C"]),
        ];
        let mut last_err: Option<std::io::Error> = None;
        for (prog, args) in candidates {
            let mut cmd = tokio::process::Command::new(&prog);
            for a in &args { cmd.arg(a); }
            cmd.arg(command);
            match cmd.output().await {
                Ok(o) => return Ok(o),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    last_err = Some(e);
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        Err(last_err.unwrap_or_else(|| std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No usable shell found (tried powershell, pwsh, cmd)",
        )))
    } else {
        tokio::process::Command::new("sh")
            .args(["-c", command])
            .output().await
    }
}

/// Address-equality check tolerant of bech32 vs hex representations.
fn exec_addrs_match(a: &str, b: &str) -> bool {
    if a.eq_ignore_ascii_case(b) { return true; }
    let to_hex = |s: &str| {
        let hrp = if s.starts_with("egot") { "egot" }
                  else if s.starts_with("ego1") || s.starts_with("ego") { "ego" }
                  else { return s.trim_start_matches("0x").to_lowercase(); };
        ego_core::EgoAddress::from_bech32(s, hrp)
            .map(|a| hex::encode(a.payload()))
            .unwrap_or_else(|_| s.trim_start_matches("0x").to_lowercase())
    };
    to_hex(a) == to_hex(b)
}

// ── In-browser app tunnel implementation ────────────────────────────────────

/// Copy bytes in both directions between two futures-io streams until either
/// side closes, then half-close the opposite writer so the peer sees EOF.
async fn pipe_streams<A, B>(a: A, b: B)
where
    A: futures::AsyncRead + futures::AsyncWrite + Unpin,
    B: futures::AsyncRead + futures::AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = a.split();
    let (mut br, mut bw) = b.split();
    let a_to_b = async {
        let _ = futures::io::copy(&mut ar, &mut bw).await;
        let _ = bw.close().await;
    };
    let b_to_a = async {
        let _ = futures::io::copy(&mut br, &mut aw).await;
        let _ = aw.close().await;
    };
    futures::future::join(a_to_b, b_to_a).await;
}

/// Authenticate a tunnel handshake the same way `serve_compute_exec` does:
/// the Dilithium key must derive the reservation's buyer address, the signature
/// must cover `TUNNEL:<res>:<port>:<ts>`, and the reservation must be ours+active.
fn validate_tunnel_handshake(hs: &TunnelHandshake) -> Result<crate::chain_db::ComputeReservation, String> {
    let now = chrono::Utc::now().timestamp();
    if (now - hs.timestamp).abs() > 30 {
        return Err("handshake expired (timestamp mismatch)".into());
    }
    let dil_pk_bytes = hex::decode(&hs.dilithium_public_key).map_err(|_| "bad dilithium_public_key")?;
    if dil_pk_bytes.is_empty() { return Err("missing dilithium_public_key".into()); }

    let my_addr  = crate::ledger::Ledger::load().address;
    let hrp      = if my_addr.starts_with("egot") { "egot" } else { "ego" };
    let chain_id = if hrp == "egot" { 1 } else { 0 };
    let derived  = ego_core::EgoAddress::from_dilithium_pk(&dil_pk_bytes, chain_id, ego_core::AddressType::EOA)
        .to_bech32(hrp).map_err(|_| "failed to derive bech32 address")?;

    let reservation = crate::chain_db::get_compute_reservation(&hs.reservation_id)
        .or_else(|| hs.reservation.clone())
        .ok_or_else(|| format!("unknown reservation {}", hs.reservation_id))?;
    if reservation.reservation_id != hs.reservation_id { return Err("reservation id mismatch".into()); }
    if !exec_addrs_match(&reservation.provider_address, &my_addr) { return Err("not this node's reservation".into()); }
    if !exec_addrs_match(&reservation.buyer_address, &derived)    { return Err("key does not match reservation buyer".into()); }
    if reservation.status != "active" { return Err(format!("reservation status is '{}'", reservation.status)); }
    if reservation.expires_at <= now  { return Err("reservation expired".into()); }

    let dil_pk  = ego_core::PublicKey::new(ego_core::AlgorithmId::MlDsa2, dil_pk_bytes);
    let sig_raw = hex::decode(&hs.dilithium_signature).map_err(|_| "bad dilithium_signature")?;
    let dil_sig = ego_core::Signature::dilithium2(sig_raw);
    let signed  = format!("TUNNEL:{}:{}:{}", hs.reservation_id, hs.container_port, hs.timestamp);
    match ego_core::verify_signature(&dil_pk, signed.as_bytes(), &dil_sig) {
        Ok(true) => Ok(reservation),
        _        => Err("invalid Dilithium signature".into()),
    }
}

/// Provider side: handle one inbound tunnel stream — read+verify the handshake,
/// ack, then relay to the container's published host port.
async fn serve_tunnel_stream<S>(mut stream: S) -> Result<(), String>
where
    S: futures::AsyncRead + futures::AsyncWrite + Unpin,
{
    let mut len_buf = [0u8; 4];
    AsyncReadExt::read_exact(&mut stream, &mut len_buf).await.map_err(|e| e.to_string())?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 64 * 1024 { return Err("handshake too large".into()); }
    let mut buf = vec![0u8; len];
    AsyncReadExt::read_exact(&mut stream, &mut buf).await.map_err(|e| e.to_string())?;
    let hs: TunnelHandshake = serde_json::from_slice(&buf).map_err(|e| e.to_string())?;

    let reservation = match validate_tunnel_handshake(&hs) {
        Ok(r)  => r,
        Err(e) => {
            // 0 = rejected; renter aborts without piping.
            let _ = AsyncWriteExt::write_all(&mut stream, &[0u8]).await;
            let _ = AsyncWriteExt::flush(&mut stream).await;
            return Err(e);
        }
    };

    let res_id = reservation.reservation_id.clone();
    let cport  = hs.container_port;
    let host_port = tokio::task::spawn_blocking(move || crate::sandbox::mapped_port(&res_id, cport))
        .await.map_err(|e| e.to_string())?
        .unwrap_or(cport);

    let tcp = match tokio::net::TcpStream::connect(("127.0.0.1", host_port)).await {
        Ok(t)  => t,
        Err(e) => {
            let _ = AsyncWriteExt::write_all(&mut stream, &[0u8]).await;
            let _ = AsyncWriteExt::flush(&mut stream).await;
            return Err(format!("app not reachable on port {host_port}: {e}"));
        }
    };

    // 1 = accepted.
    AsyncWriteExt::write_all(&mut stream, &[1u8]).await.map_err(|e| e.to_string())?;
    AsyncWriteExt::flush(&mut stream).await.map_err(|e| e.to_string())?;

    use tokio_util::compat::TokioAsyncReadCompatExt;
    pipe_streams(stream, tcp.compat()).await;
    Ok(())
}

/// Ensure a connection to one of `endpoints` exists; returns the provider PeerId.
async fn dial_provider_any(endpoints: &[String]) -> Result<PeerId, String> {
    let tx = SWARM_TX.get().ok_or("P2P not started")?;
    let mut sorted: Vec<String> = endpoints.iter()
        .filter(|e| !e.contains("/ip4/169.254."))
        .cloned().collect();
    sorted.sort_by_key(|ep| {
        if ep.contains("/ip4/192.168.") || ep.contains("/ip4/10.") || ep.contains("/ip4/172.") { 0usize }
        else if ep.contains("/p2p-circuit") { 2 } else { 1 }
    });
    let mut last = "no reachable endpoints".to_string();
    for ep in &sorted {
        let addr: Multiaddr = match ep.parse() { Ok(a) => a, Err(e) => { last = format!("bad addr: {e}"); continue; } };
        let (rtx, rrx) = oneshot::channel();
        if tx.send(SwarmCmd::Dial { peer_addr: addr, reply: rtx }).await.is_err() {
            return Err("swarm channel closed".into());
        }
        match tokio::time::timeout(Duration::from_secs(20), rrx).await {
            Ok(Ok(Ok(pid))) => return Ok(pid),
            Ok(Ok(Err(e)))  => last = e,
            Ok(Err(_))      => last = "dial reply dropped".into(),
            Err(_)          => last = "dial timed out".into(),
        }
    }
    Err(last)
}

/// Renter side: open a local TCP listener that tunnels every browser connection
/// to the rental's web app over libp2p. Returns the local `127.0.0.1:<port>`.
pub async fn open_app_tunnel(
    reservation: crate::chain_db::ComputeReservation,
    container_port: u16,
    endpoints: &[String],
    kp: &ego_core::KeyPair,
) -> Result<String, String> {
    let control = TUNNEL_CONTROL.get().ok_or("P2P tunnel not ready")?.clone();
    let peer_id = dial_provider_any(endpoints).await?;

    let ts     = chrono::Utc::now().timestamp();
    let signed = format!("TUNNEL:{}:{}:{}", reservation.reservation_id, container_port, ts);
    let hs = TunnelHandshake {
        reservation_id:       reservation.reservation_id.clone(),
        container_port,
        timestamp:            ts,
        dilithium_public_key: hex::encode(&kp.dilithium_public_key().key_data),
        dilithium_signature:  hex::encode(&kp.sign_dilithium(signed.as_bytes()).signature_data),
        reservation:          Some(reservation.clone()),
    };
    let hs_bytes = serde_json::to_vec(&hs).map_err(|e| e.to_string())?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(|e| e.to_string())?;
    let local_port = listener.local_addr().map_err(|e| e.to_string())?.port();

    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await { Ok(x) => x, Err(_) => break };
            let mut control = control.clone();
            let hs_bytes = hs_bytes.clone();
            tokio::spawn(async move {
                let mut stream = match control.open_stream(peer_id, TUNNEL_PROTOCOL).await {
                    Ok(s)  => s,
                    Err(e) => { tracing::debug!("[tunnel] open_stream failed: {e}"); return; }
                };
                let len = (hs_bytes.len() as u32).to_be_bytes();
                if AsyncWriteExt::write_all(&mut stream, &len).await.is_err() { return; }
                if AsyncWriteExt::write_all(&mut stream, &hs_bytes).await.is_err() { return; }
                if AsyncWriteExt::flush(&mut stream).await.is_err() { return; }
                let mut ack = [0u8; 1];
                if AsyncReadExt::read_exact(&mut stream, &mut ack).await.is_err() || ack[0] != 1 {
                    tracing::debug!("[tunnel] provider rejected handshake");
                    return;
                }
                use tokio_util::compat::TokioAsyncReadCompatExt;
                pipe_streams(stream, tcp.compat()).await;
            });
        }
    });

    Ok(format!("127.0.0.1:{local_port}"))
}

pub async fn send_message(endpoint: &str, msg: &P2PMessage) -> Result<(), String> {
    let tx = SWARM_TX.get().ok_or_else(|| "P2P not started".to_string())?;
    let peer_addr: Multiaddr = endpoint
        .parse()
        .map_err(|e| format!("Invalid multiaddr '{}': {}", endpoint, e))?;
    let (reply_tx, reply_rx) = oneshot::channel();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tx.send(SwarmCmd::Send { peer_addr, msg: msg.clone(), reply: reply_tx }),
    )
    .await
    .map_err(|_| "Swarm channel send timed out".to_string())?
    .map_err(|_| "Swarm channel closed".to_string())?;
        tokio::time::timeout(std::time::Duration::from_secs(60), reply_rx)
        .await
        .map_err(|_| "Swarm reply timed out".to_string())?
        .map_err(|_| "Swarm dropped reply".to_string())?
}


pub async fn send_message_any(endpoints: &[String], msg: &P2PMessage) -> Result<(), String> {
    if endpoints.is_empty() {
        return Err("No endpoints available".to_string());
    }
    // Sort: LAN (0) → public IP (1) → relay circuit (2)
    let mut sorted: Vec<String> = endpoints.iter()
        .filter(|ep| !ep.contains("/ip4/169.254."))
        .cloned()
        .collect();
    if sorted.is_empty() {
        return Err("No reachable endpoints (all link-local filtered)".to_string());
    }
    sorted.sort_by_key(|ep| {
        if ep.contains("/ip4/192.168.") || ep.contains("/ip4/10.") || ep.contains("/ip4/172.") {
            0usize
        } else if ep.contains("/p2p-circuit") {
            2
        } else {
            1
        }
    });
    let mut last_err = String::new();
    for ep in &sorted {
        match send_message(ep, msg).await {
            Ok(_)  => {
                tracing::debug!("[P2P] Connected via {}", ep);
                return Ok(());
            }
            Err(e) => {
                let relay_noise = e.contains("resource limit exceeded")
                    || e.contains("Relay has no reservation")
                    || e.contains("no reservation for destination");
                if !relay_noise && !is_peer_silenced(ep) {
                    eprintln!("[P2P] Failed {}: {}", ep, e);
                }
                last_err = e;
            }
        }
    }
    Err(last_err)
}

pub async fn get_public_endpoint() -> String {
    let Some(tx) = SWARM_TX.get() else { return String::new(); };
    let (reply_tx, reply_rx) = oneshot::channel();
    let send = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tx.send(SwarmCmd::GetEndpoint { reply: reply_tx }),
    ).await;
    if send.is_err() || send.unwrap().is_err() { return String::new(); }
    tokio::time::timeout(std::time::Duration::from_secs(3), reply_rx)
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or_default()
}


pub async fn wait_for_public_endpoint(timeout_secs: u64) -> String {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if RELAY_CIRCUIT_READY.load(Ordering::Relaxed) {
            let ep = get_public_endpoint().await;
            if ep.contains("/p2p-circuit") {
                return ep;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return get_public_endpoint().await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

pub fn get_local_ip() -> String {
    if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
        let _ = sock.connect("8.8.8.8:80");
        if let Ok(addr) = sock.local_addr() {
            let ip = addr.ip().to_string();
            if ip != "0.0.0.0" { return ip; }
        }
    }
    "127.0.0.1".to_string()
}

pub fn get_local_endpoint() -> String {
    format!("/ip4/{}/tcp/{}", get_local_ip(), p2p_port())
}


pub async fn start_udp_discovery(_app: tauri::AppHandle) {}
pub async fn broadcast_udp_announce() {}
pub async fn gossip_peer_list() {}


pub async fn publish_gossip(topic: &str, data: Vec<u8>) {
    if let Some(tx) = GOSSIP_TX.get() {
        if tx.try_send((topic.to_string(), data)).is_err() {
            eprintln!("[Gossip] Channel full or closed — dropping message on topic {}", topic);
        }
    }
}

fn my_coverage_cell_and_geo() -> (String, f64, f64) {
    let state = crate::app::global_app_state();
    let cache = state.cache.lock().unwrap();
    if let Some(loc) = cache.coverage_status.as_ref().and_then(|cs| cs.location.as_ref()) {
        let lat = (loc.latitude * 100.0).round() / 100.0;
        let lon = (loc.longitude * 100.0).round() / 100.0;
        (crate::commands::coverage::derive_h3_cell(loc.latitude, loc.longitude), lat, lon)
    } else {
        (String::new(), 0.0, 0.0)
    }
}

pub async fn broadcast_poc_beacon() -> Option<String> {
    let my_addr = tokio::task::spawn_blocking(|| crate::ledger::Ledger::load().address)
        .await.unwrap_or_default();
    if my_addr.is_empty() { return None; }
    let machine_id = crate::commands::coverage::get_machine_id_cached();
    let (cell, _lat, _lon) = my_coverage_cell_and_geo();
    let now   = chrono::Utc::now().timestamp();
    let epoch = crate::poc::poc_epoch(now);
    let mut nonce = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    let beacon_id = hex::encode(blake3::hash(
        format!("{}:{}:{}", my_addr, epoch, hex::encode(nonce)).as_bytes()
    ).as_bytes());
    let transport = "internet".to_string();
    let bytes = crate::poc::beacon_signing_bytes(&beacon_id, &my_addr, &machine_id, &cell, epoch, now, &transport);
    let signature = crate::poc::sign_with_node_key(&bytes)?;
    let msg = P2PMessage::PocBeacon {
        beacon_id: beacon_id.clone(),
        address: my_addr,
        machine_id,
        cell,
        epoch,
        timestamp: now,
        transport,
        signature,
    };
    let data = serde_json::to_vec(&msg).ok()?;
    crate::poc::start_beacon(&beacon_id, now);
    publish_gossip("ego-poc-v1", data).await;
    eprintln!("[PoC] beacon {} published (epoch {})", &beacon_id[..12], epoch);
    Some(beacon_id)
}

async fn handle_poc_beacon(
    beacon_id: String, address: String, machine_id: String, cell: String,
    epoch: u64, timestamp: i64, transport: String, signature: String,
) {
    let short = &address[..address.len().min(20)];
    let now = chrono::Utc::now().timestamp();
    if (now - timestamp).abs() > crate::poc::POC_BEACON_FRESH_SECS {
        eprintln!("[PoC] beacon from {} rejected: stale ({}s)", short, (now - timestamp).abs());
        return;
    }
    let expected_epoch = crate::poc::poc_epoch(timestamp);
    if epoch != expected_epoch && epoch != expected_epoch.saturating_sub(1) {
        eprintln!("[PoC] beacon from {} rejected: epoch mismatch", short);
        return;
    }
    let (my_addr, _) = tokio::task::spawn_blocking(|| {
        (crate::ledger::Ledger::load().address, ())
    }).await.unwrap_or_default();
    if my_addr.is_empty() || my_addr == address { return; }
    let my_machine = crate::commands::coverage::get_machine_id_cached();
    if !machine_id.is_empty() && machine_id == my_machine && !crate::poc::poc_same_machine_allowed() {
        eprintln!("[PoC] beacon from {} rejected: same machine (set EGO_POC_SAME_MACHINE=1 on single-PC testnets)", short);
        return;
    }
    let bytes = crate::poc::beacon_signing_bytes(&beacon_id, &address, &machine_id, &cell, epoch, timestamp, &transport);
    if !crate::poc::verify_peer_sig(&address, &bytes, &signature) {
        eprintln!("[PoC] beacon from {} rejected: signature unverifiable (no announced ed25519 key yet?)", short);
        return;
    }
    if !crate::poc::should_witness(&address, epoch) { return; }
    eprintln!("[PoC] witnessing beacon {} from {}", &beacon_id[..12.min(beacon_id.len())], short);

    let (witness_cell, _lat, _lon) = my_coverage_cell_and_geo();
    let latency_ms = ((now - timestamp).max(0) as u32).saturating_mul(1000).min(120_000);
    let rssi_dbm = 0i32;
    let wbytes = crate::poc::witness_signing_bytes(
        &beacon_id, &address, &my_addr, &my_machine, &witness_cell, latency_ms, rssi_dbm, now,
    );
    let Some(wsig) = crate::poc::sign_with_node_key(&wbytes) else { return; };
    let receipt = P2PMessage::PocWitnessReceipt {
        beacon_id,
        beaconer: address,
        witness: my_addr,
        witness_machine_id: my_machine,
        witness_cell,
        latency_ms,
        rssi_dbm,
        timestamp: now,
        signature: wsig,
    };
    if let Ok(data) = serde_json::to_vec(&receipt) {
        publish_gossip("ego-poc-v1", data).await;
    }
}

async fn handle_poc_witness(
    beacon_id: String, beaconer: String, witness: String, witness_machine_id: String,
    witness_cell: String, latency_ms: u32, rssi_dbm: i32, timestamp: i64, signature: String,
) {
    let my_addr = tokio::task::spawn_blocking(|| crate::ledger::Ledger::load().address)
        .await.unwrap_or_default();
    if my_addr.is_empty() || beaconer != my_addr || witness == my_addr { return; }
    let now = chrono::Utc::now().timestamp();
    if (now - timestamp).abs() > crate::poc::POC_BEACON_FRESH_SECS { return; }
    let my_machine = crate::commands::coverage::get_machine_id_cached();
    if !witness_machine_id.is_empty() && witness_machine_id == my_machine && !crate::poc::poc_same_machine_allowed() {
        eprintln!("[PoC] receipt from {} rejected: same machine", &witness[..witness.len().min(20)]);
        return;
    }
    let bytes = crate::poc::witness_signing_bytes(
        &beacon_id, &beaconer, &witness, &witness_machine_id, &witness_cell, latency_ms, rssi_dbm, timestamp,
    );
    if !crate::poc::verify_peer_sig(&witness, &bytes, &signature) {
        eprintln!("[PoC] receipt from {} rejected: signature unverifiable", &witness[..witness.len().min(20)]);
        return;
    }
    let accepted = crate::poc::add_witness(&beacon_id, crate::poc::PocWitnessRecord {
        witness:    witness.clone(),
        machine_id: witness_machine_id,
        cell:       witness_cell,
        latency_ms,
        timestamp,
        signature,
    });
    if accepted {
        eprintln!("[PoC] witness receipt accepted from {} ({}ms)", &witness[..witness.len().min(20)], latency_ms);
    }
}

pub async fn broadcast_tx(tx: LedgerTx, block: LedgerBlock) {
    // This is an async function, so all blocking calls must be wrapped.
    let msg = P2PMessage::TxBroadcast { tx: tx.clone(), block: block.clone() };

    if let Ok(data) = serde_json::to_vec(&msg) {
        publish_gossip("ego-txs-v1", data).await;
    }

    let my_addr = tokio::task::spawn_blocking(|| crate::ledger::Ledger::load().address)
        .await.unwrap_or_default();
    set_local_validator(&my_addr);

    let (dil_pk_hex, vk_hex) = current_wallet_announce_keys();
    if !dil_pk_hex.is_empty() {
        register_validator_pubkey(&my_addr, &dil_pk_hex);
    }
    if !vk_hex.is_empty() {
        record_peer_ed25519(&my_addr, &vk_hex);
    }

    let mut seen_eps: std::collections::HashSet<String> = Default::default();
    let mut endpoints: Vec<String> = Vec::new();

    let contacts = tokio::task::spawn_blocking(load_contacts)
        .await.unwrap_or_default();
    let is_reachable = |ep: &str| !ep.contains("/ip4/169.254.");

    for c in contacts.iter().filter(|c| c.status == "approved" && !c.endpoint.is_empty()) {
        if is_reachable(&c.endpoint) && seen_eps.insert(c.endpoint.clone()) {
            endpoints.push(c.endpoint.clone());
        }
        for ep in &c.all_endpoints {
            if is_reachable(ep) && seen_eps.insert(ep.clone()) { endpoints.push(ep.clone()); }
        }
    }
    let peer_cache = tokio::task::spawn_blocking(load_peer_cache).await.unwrap_or_default();

    for p in peer_cache.iter().filter(|p| !p.endpoint.is_empty()) {
        if is_reachable(&p.endpoint) && seen_eps.insert(p.endpoint.clone()) {
            endpoints.push(p.endpoint.clone());
        }
    }

    use rand::seq::SliceRandom;
    let mut rng = rand::thread_rng();
    endpoints.shuffle(&mut rng);
    endpoints.truncate(12);

    for endpoint in endpoints {
        let msg_clone = msg.clone();
        tokio::spawn(async move {
            if let Err(e) = send_message(&endpoint, &msg_clone).await {
                if !e.contains("none of the requested protocols") {
                    eprintln!("[P2P] broadcast_tx direct to {}: {}", endpoint, e);
                }
            }
        });
    }

    // Direct send to cached peers ensures early validator discovery before gossip connects
    for p in load_peer_cache().iter().filter(|p| !p.endpoint.is_empty()) {
        let ep = p.endpoint.clone();
        let msg_clone = msg.clone();
        tokio::spawn(async move {
            let _ = send_message_any(&[ep], &msg_clone).await;
        });
    }
    tokio::spawn(try_proactive_proposal());
}

pub async fn broadcast_pending_tx(tx: LedgerTx) {
    let msg = P2PMessage::TxBroadcast { tx: tx.clone(), block: LedgerBlock::default() };
    if let Ok(data) = serde_json::to_vec(&msg) {
        publish_gossip("ego-txs-v1", data).await;
    }
    
    // Direct send to cached peers ensures delivery before gossip mesh connects
    for p in load_peer_cache().iter().filter(|p| !p.endpoint.is_empty()) {
        let ep = p.endpoint.clone();
        let msg_clone = msg.clone();
        tokio::spawn(async move {
            let _ = send_message_any(&[ep], &msg_clone).await;
        });
    }
    
    tokio::spawn(try_proactive_proposal());
}

pub async fn sync_chain_from_peers() {
    static LAST_SYNC_REQ: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
    static LAST_FROM_HEIGHT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX);
    static STUCK_ROUNDS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let now = chrono::Utc::now().timestamp_millis();
    let last = LAST_SYNC_REQ.load(std::sync::atomic::Ordering::Relaxed);
    if now - last < 2_000 { return; }
    LAST_SYNC_REQ.store(now, std::sync::atomic::Ordering::Relaxed);

    let my_endpoint = get_public_endpoint().await;
    let my_height = tokio::task::spawn_blocking(|| crate::chain_db::latest_block_info().0)
        .await.unwrap_or(0);
    let from_height = my_height.saturating_sub(1);

    if LAST_FROM_HEIGHT.swap(from_height, std::sync::atomic::Ordering::Relaxed) == from_height {
        let stuck = STUCK_ROUNDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        if stuck >= 5 && stuck % 5 == 0 {
            tracing::warn!(
                "[Sync] Block sync stuck at height {} for {} rounds — falling back to state snapshot",
                my_height, stuck
            );
            request_snapshot_from_peers(my_height).await;
        }
    } else {
        STUCK_ROUNDS.store(0, std::sync::atomic::Ordering::Relaxed);
    }

    let msg = P2PMessage::ChainSyncRequest { requester_endpoint: my_endpoint.clone(), from_height };

    // Broadcast request over gossip to reach NAT-traversing peers
    if let Ok(data) = serde_json::to_vec(&msg) {
        publish_gossip("ego-sync-v1", data).await;
    }

    let mut seen_eps: std::collections::HashSet<String> = Default::default();
    let mut endpoints: Vec<String> = Vec::new();

    let contacts = tokio::task::spawn_blocking(load_contacts).await.unwrap_or_default();
    for c in contacts.iter().filter(|c| !c.endpoint.is_empty()) {
        let ep = c.endpoint.clone();
        if !ep.is_empty() && seen_eps.insert(ep.clone()) { endpoints.push(ep); }
        for ep in &c.all_endpoints {
            if seen_eps.insert(ep.clone()) { endpoints.push(ep.clone()); }
        }
    }
    let peer_cache = tokio::task::spawn_blocking(load_peer_cache).await.unwrap_or_default();
    for p in peer_cache.iter().filter(|p| !p.endpoint.is_empty()) {
        if seen_eps.insert(p.endpoint.clone()) { endpoints.push(p.endpoint.clone()); }
    }

    use rand::seq::SliceRandom;
    let mut rng = rand::thread_rng();
    endpoints.shuffle(&mut rng);
    endpoints.truncate(5);
    let local_peer_id = my_endpoint.split("/p2p/").last().unwrap_or("");

    for endpoint in endpoints {
        if !local_peer_id.is_empty() && endpoint.contains(local_peer_id) { continue; }
        let msg_clone = msg.clone();
        tokio::spawn(async move {
            if let Err(e) = send_message(&endpoint, &msg_clone).await {
                if !e.contains("none of the requested protocols") && !is_peer_silenced(&endpoint) {
                    eprintln!("[P2P] sync request to {}: {}", endpoint, e);
                }
            }
        });
    }
}

pub async fn send_direct_peer_announce(target_endpoint: String) {
    if target_endpoint.is_empty() { return; }
    let my_addr = tokio::task::spawn_blocking(crate::ledger::Ledger::load)
        .await.map(|l| l.address).unwrap_or_default();
    if my_addr.is_empty() { return; }
    let my_ep = get_public_endpoint().await;
    if my_ep.is_empty() { return; }
    let coverage_score = crate::poc::my_coverage_score();
    let staked_amount = tokio::task::spawn_blocking(crate::ledger::Ledger::load)
        .await.map(|l| l.staked_amount).unwrap_or(0);
    let (dil_hex, vrf_hex) = current_wallet_announce_keys();
    let endpoints = vec![my_ep.clone()];
    let genesis_hash = crate::ledger::GENESIS_HASH.to_string();
    let machine_id = crate::commands::coverage::get_machine_id_cached();
    let (my_city, my_country, my_lat, my_lon) = {
        let state = crate::app::global_app_state();
        let cache = state.cache.lock().unwrap();
        if let Some(loc) = cache.coverage_status.as_ref().and_then(|cs| cs.location.as_ref()) {
            (
                loc.city.clone(),
                loc.country.clone(),
                Some((loc.latitude * 100.0).round() / 100.0),
                Some((loc.longitude * 100.0).round() / 100.0),
            )
        } else { (None, None, None, None) }
    };
    let signature = sign_peer_announce(
        &my_addr, &my_ep, &endpoints, coverage_score,
        &dil_hex, &vrf_hex, staked_amount, &genesis_hash, &machine_id,
    );
    let announce = P2PMessage::PeerAnnounce {
        address: my_addr, name: "Ego Node".to_string(),
        endpoint: my_ep, endpoints,
        city: my_city, country: my_country, lat: my_lat, lon: my_lon,
        coverage_score, dilithium_pubkey: dil_hex, vrf_pubkey: vrf_hex,
        staked_amount, genesis_hash, signature, machine_id,
    };
    if let Err(e) = send_message_any(&[target_endpoint.clone()], &announce).await {
        if !e.contains("none of the requested protocols") {
            tracing::debug!("[P2P] direct PeerAnnounce to {}: {}", target_endpoint, e);
        }
    }
}

pub async fn broadcast_peer_announce(app: Option<&tauri::AppHandle<tauri::Wry>>) {
    let state = crate::app::global_app_state();
    let (address, registry, active_id) = tokio::task::spawn_blocking(
        || {
            (
            crate::ledger::Ledger::load().address,
            crate::ledger::load_registry(),
            crate::ledger::get_active_wallet_id(),
        )
    }).await.unwrap_or_default();
    if address.is_empty() { return; }
    let my_endpoint = get_public_endpoint().await;
    let name = registry.wallets.iter()
        .find(|w| w.id == active_id)
        .map(|w| w.name.clone())
        .unwrap_or_else(|| "Ego Node".to_string());
    let (my_city, my_country, my_lat, my_lon) = {
        let cache = state.cache.lock().unwrap();
        if let Some(ref cs) = cache.coverage_status {
            if let Some(ref loc) = cs.location {
                (
                    loc.city.clone(),
                    loc.country.clone(),
                    Some((loc.latitude * 100.0).round() / 100.0),
                    Some((loc.longitude * 100.0).round() / 100.0),
                )
            } else { (None, None, None, None) }
        } else { (None, None, None, None) }
    };

    {
        state.upsert_peer(crate::app::PeerInfo {
            address:   address.clone(),
            name:      name.clone(),
            endpoint:  my_endpoint.clone(),
            last_seen: Utc::now().timestamp(),
            city:      my_city.clone(),
            country:   my_country.clone(),
            lat:       my_lat,
            lon:       my_lon,
        });
    }
    let local_peer_id = {
        let ep = my_endpoint.clone();
        ep.split("/p2p/").last().unwrap_or("").to_string()
    };
    let mut all_endpoints = vec![my_endpoint.clone()];
    if let Ok(ifaces) = local_ip_address::list_afinet_netifas() {
        for (_name, ip) in ifaces {
            if ip.is_ipv4() && !ip.is_loopback() {
                let ep = format!("/ip4/{}/tcp/{}/p2p/{}", ip, p2p_port(), local_peer_id);
                if !all_endpoints.contains(&ep) {
                    all_endpoints.push(ep);
                }
            }
        }
    }

    let coverage_score = crate::poc::my_coverage_score();
    let (dilithium_pubkey_hex, vrf_pubkey_hex) = current_wallet_announce_keys();
    let staked_amount = tokio::task::spawn_blocking(crate::ledger::Ledger::load)
        .await.map(|l| l.staked_amount).unwrap_or(0);
    let genesis_hash = crate::ledger::GENESIS_HASH.to_string();
    let machine_id = crate::commands::coverage::get_machine_id_cached();
    let signature = sign_peer_announce(
        &address,
        &my_endpoint,
        &all_endpoints,
        coverage_score,
        &dilithium_pubkey_hex,
        &vrf_pubkey_hex,
        staked_amount,
        &genesis_hash,
        &machine_id,
    );
    let msg = P2PMessage::PeerAnnounce {
        address, name,
        endpoint:  my_endpoint,
        endpoints: all_endpoints,
        city:      my_city,
        country:   my_country,
        lat:       my_lat,
        lon:       my_lon,
        coverage_score,
        dilithium_pubkey: dilithium_pubkey_hex,
        vrf_pubkey: vrf_pubkey_hex,
        staked_amount,
        genesis_hash,
        signature,
        machine_id,
    };


    if let Ok(data) = serde_json::to_vec(&msg) {
        publish_gossip("ego-peers-v1", data).await;
    }


    let contacts = tokio::task::spawn_blocking(load_contacts).await.unwrap_or_default();
    for contact in contacts.iter().filter(|c| c.status == "approved" && !c.endpoint.is_empty()) {
        let endpoint = contact.endpoint.clone();
        if endpoint.is_empty() { continue; }
        let msg_clone = msg.clone();
        let all_eps = contact.all_endpoints.clone();
        tokio::spawn(async move {
            let mut eps = if all_eps.is_empty() { vec![endpoint.clone()] } else { all_eps };
            if !eps.contains(&endpoint) { eps.push(endpoint.clone()); }
            if let Err(e) = send_message_any(&eps, &msg_clone).await {
                if !e.contains("none of the requested protocols") && !is_peer_silenced(&endpoint) {
                    eprintln!("[P2P] peer announce to {}: {}", endpoint, e);
                }
            }
        });
    }

    // Direct send to cached peers ensures early validator discovery before gossip connects
    let peer_cache = tokio::task::spawn_blocking(load_peer_cache).await.unwrap_or_default();
    for p in peer_cache.iter().filter(|p| !p.endpoint.is_empty()) {
        let ep = p.endpoint.clone();
        let msg_clone = msg.clone();
        tokio::spawn(async move {
            let _ = send_message_any(&[ep], &msg_clone).await;
        });
    }
}


pub async fn broadcast_data_manifest() {
    let ledger = tokio::task::spawn_blocking(crate::ledger::Ledger::load)
        .await.unwrap_or_default();
    if ledger.address.is_empty() { return; }
    let cids: Vec<String> = ledger.stored_files.iter()
        .filter(|f| !f.local_path.is_empty() && !f.local_path.starts_with("sender:"))
        .map(|f| f.cid.clone())
        .collect();
    let used: u64 = ledger.stored_files.iter().map(|f| f.encrypted_size).sum();
    let capacity  = ledger.storage_allocated_bytes;
    let avail_gb  = if capacity > used {
        (capacity - used) as f64 / 1_000_000_000.0
    } else { 0.0 };
    let endpoint = get_public_endpoint().await;
    let msg = P2PMessage::DataManifest {
        from_addr:    ledger.address,
        cids,
        available_gb: avail_gb,
        is_relay:     IS_RELAY_SERVER.load(Ordering::Relaxed),
        endpoint,
    };

    if let Ok(data) = serde_json::to_vec(&msg) {
        publish_gossip("ego-shards-v1", data).await;
    }

    {
        let ledger2 = tokio::task::spawn_blocking(crate::ledger::Ledger::load)
            .await.unwrap_or_default();
        let endpoint = get_public_endpoint().await;
        let addr     = ledger2.address.clone();
        let cids2: Vec<String> = ledger2.stored_files.iter()
            .filter(|f| !f.local_path.is_empty() && !f.local_path.starts_with("sender:"))
            .map(|f| f.cid.clone())
            .collect();
        if !addr.is_empty() && !endpoint.is_empty() {
            tokio::spawn(async move {
                for cid in &cids2 {
                    register_cid_on_relay(cid, &addr, &endpoint).await;
                }
            });
        }
    }

    let contacts = tokio::task::spawn_blocking(load_contacts).await.unwrap_or_default();
    for contact in contacts.iter().filter(|c| c.status == "approved" && !c.endpoint.is_empty()) {
        let ep = contact.endpoint.clone();
        if ep.is_empty() { continue; }
        let all_eps = contact.all_endpoints.clone();
        let msg2    = msg.clone();
        tokio::spawn(async move {
            let mut eps = if all_eps.is_empty() { vec![ep.clone()] } else { all_eps };
            if !eps.contains(&ep) { eps.push(ep); }
            if let Err(e) = send_message_any(&eps, &msg2).await {
                if !e.contains("none of the requested protocols") {
                    eprintln!("[P2P] DataManifest failed: {}", e);
                }
            }
        });
    }
}

pub fn get_known_peers() -> Vec<String> {
    load_peer_cache()
        .into_iter()
        .map(|p| p.address)
        .filter(|a| !a.is_empty())
        .collect()
}

static KNOWN_NODE_URLS: std::sync::OnceLock<std::sync::RwLock<Vec<String>>> =
    std::sync::OnceLock::new();

fn node_url_store() -> &'static std::sync::RwLock<Vec<String>> {
    KNOWN_NODE_URLS.get_or_init(|| std::sync::RwLock::new(Vec::new()))
}

pub fn register_node_url(url: &str) {
    if let Ok(mut w) = node_url_store().write() {
        let url = url.trim_end_matches('/').to_string();
        if !w.contains(&url) {
            w.push(url);
        }
    }
}

pub fn get_known_node_urls() -> Vec<String> {
    node_url_store().read().map(|r| r.clone()).unwrap_or_default()
}

pub async fn register_with_relay_as_ego_node() {
    // Deprecated: Node registration is now fully P2P via Kademlia DHT
}

pub fn gossip_hosting_node(record: &crate::chain_db::HostingNodeRecord) {
    let record = record.clone();
    tokio::spawn(async move {
        let msg = P2PMessage::HostingAnnounce { record: record.clone() };
        if let Ok(data) = serde_json::to_vec(&msg) {
            publish_gossip("ego-hosting-v1", data).await;
        }
    });
}

/// Snapshot of currently known validator addresses.
/// Used by poc.rs to compute total DRS weight for the PoC lottery.
pub fn get_known_validators_snapshot() -> Vec<String> {
    known_validators().iter().cloned().collect()
}

/// Returns true if we have at least one direct P2P connection.
/// Used to gate operations that require network (e.g. DHT publish).
pub fn has_connectivity() -> bool {
    DIRECT_PEER_COUNT.load(std::sync::atomic::Ordering::Relaxed) > 0
}

pub async fn broadcast_shard_announce() {
    let ledger = crate::ledger::Ledger::load();
    let my_addr = ledger.address.clone();
    if my_addr.is_empty() { return; }
    let endpoint = get_public_endpoint().await;
    let map = crate::sharding::load_shard_map();
    let all_nodes: Vec<String> = map.assignments.iter()
        .map(|a| a.node_address.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter().collect();
    let held: Vec<u32> = crate::sharding::my_shards(&my_addr, &map, &all_nodes)
        .into_iter().map(|(id, _)| id).collect();
    let msg = crate::p2p::P2PMessage::ShardAnnounce {
        from_addr:          my_addr,
        from_endpoint:      endpoint,
        held_shards:        if held.is_empty() { vec![0] } else { held },
        uptime_secs:        0,
        network_node_count: map.network_node_count.max(1),
        shard_count:        map.shard_count.max(1),
    };
    if let Ok(data) = serde_json::to_vec(&msg) {
        publish_gossip("ego-shards-v1", data).await;
    }
}

pub async fn broadcast_compute_msg(msg: P2PMessage) {
    if let Ok(data) = serde_json::to_vec(&msg) {
        publish_gossip("ego-compute-v1", data).await;
    }
}

pub async fn broadcast_master_promotion(shard_id: u32, new_master: &str, new_endpoint: &str, former_master: &str) {
    let msg = crate::p2p::P2PMessage::MasterPromotion {
        shard_id,
        new_master:    new_master.to_string(),
        new_endpoint:  new_endpoint.to_string(),
        former_master: former_master.to_string(),
        timestamp:     chrono::Utc::now().timestamp(),
    };
    if let Ok(data) = serde_json::to_vec(&msg) {
        publish_gossip("ego-shards-v1", data).await;
    }
}

pub async fn route_tx_to_shard_master(shard_id: u32, tx: crate::ledger::LedgerTx) {
    if let Some(endpoint) = crate::sharding::get_shard_master(shard_id) {
        let msg = P2PMessage::ShardTxRoute { shard_id, tx: tx.clone() };
        if let Err(_) = send_message_any(&[endpoint], &msg).await {
            let _ = crate::mempool::get_mempool().push(tx);
        }
    } else {
        let _ = crate::mempool::get_mempool().push(tx);
    }
}

pub async fn propose_shard_rebalance(new_count: u32) {
    let current_height = crate::chain_db::latest_block_info().0;
    let effective_at_height = current_height + 100;
    let own_address = crate::ledger::Ledger::load().address;
    crate::sharding::set_agreed_shard_count(new_count, effective_at_height);
    let msg = P2PMessage::ShardRebalance {
        proposed_shard_count: new_count,
        effective_at_height,
        proposer: own_address,
    };
    if let Ok(data) = serde_json::to_vec(&msg) {
        publish_gossip("ego-shard-rebalance-v1", data).await;
    }
}

pub async fn run_shard_rebalance_monitor() {
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        let known_count = get_known_validators_snapshot().len() as u32 + 1;
        let computed = crate::sharding::compute_shard_count(known_count);
        let agreed = crate::sharding::get_agreed_shard_count();
        if computed != agreed {
            tracing::info!("Computed shard count {} differs from agreed {}, proposing rebalance", computed, agreed);
            propose_shard_rebalance(computed).await;
        }
    }
}

pub async fn push_shard_data_to_slaves() {
    let map = crate::sharding::load_shard_map();
    if map.shard_count <= 1 { return; }

    let my_addr = crate::ledger::Ledger::load().address;
    if my_addr.is_empty() { return; }
    let my_ep = get_public_endpoint().await;

    let all_nodes: Vec<String> = map.assignments.iter()
        .map(|a| a.node_address.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter().collect();

    let chain = load_chain();

    for (shard_id, role) in crate::sharding::my_shards(&my_addr, &map, &all_nodes) {
        if role != crate::sharding::ShardRole::Master { continue; }

        // Find slave endpoints for this shard
        let slave_eps: Vec<String> = map.assignments.iter()
            .filter(|a| a.shard_id == shard_id && a.role == crate::sharding::ShardRole::Slave && !a.node_endpoint.is_empty())
            .map(|a| a.node_endpoint.clone())
            .collect();

        if slave_eps.is_empty() { continue; }

        let (blocks, txs) = crate::sharding::get_shard_blocks(shard_id, 0, &chain, &map);
        if blocks.is_empty() { continue; }

        let response = P2PMessage::ShardDataResponse { shard_id, blocks, transactions: txs };
        let eps_clone = slave_eps.clone();
        tokio::spawn(async move {
            for ep in &eps_clone {
                let _ = send_message_any(&[ep.clone()], &response).await;
            }
        });
    }
}


pub async fn request_file_pinning(cids: Vec<String>) {
    if cids.is_empty() { return; }
    let ledger = tokio::task::spawn_blocking(crate::ledger::Ledger::load)
        .await.unwrap_or_default();
    if ledger.address.is_empty() { return; }

    let replica_map: std::collections::HashMap<String, Vec<String>> = ledger.stored_files.iter()
        .map(|f| (f.cid.clone(), f.replica_peers.clone()))
        .collect();

    let my_ep    = get_public_endpoint().await;
    let contacts = tokio::task::spawn_blocking(load_contacts).await.unwrap_or_default();
    for contact in contacts.iter().filter(|c| c.status == "approved" && !c.endpoint.is_empty()) {
        let contact_addr = contact.address.clone();
        let ep = contact.endpoint.clone();
        if ep.is_empty() { continue; }
        let all_eps = contact.all_endpoints.clone();
        let from    = ledger.address.clone();
        let my_ep2  = my_ep.clone();

        let cids_to_send: Vec<String> = cids.iter()
            .filter(|cid| {
                replica_map.get(*cid)
                    .map(|replicas| !replicas.contains(&contact_addr))
                    .unwrap_or(true)
            })
            .cloned()
            .collect();

        if cids_to_send.is_empty() { continue; }

        tokio::spawn(async move {
            let mut eps = if all_eps.is_empty() { vec![ep.clone()] } else { all_eps };
            if !eps.contains(&ep) { eps.push(ep); }
            for cid in cids_to_send {
                let (fee, expiry) = {
                    tokio::task::spawn_blocking(crate::ledger::Ledger::load).await
                        .map(|l| l.stored_files.iter()
                        .find(|f| f.cid == cid)
                        .map(|f| (f.storage_fee_uegoc, f.expiry))
                        .unwrap_or((0, 0))).unwrap_or((0,0))
                };
                let msg = P2PMessage::PinRequest {
                    cid,
                    from_addr:         from.clone(),
                    from_endpoint:     my_ep2.clone(),
                    storage_fee_uegoc: fee,
                    expiry,
                };
                if let Err(e) = send_message_any(&eps, &msg).await {
                    if !e.contains("none of the requested protocols") {
                        eprintln!("[P2P] PinRequest failed: {}", e);
                    }
                    break;
                }
            }
        });
    }
}


/// How long (seconds) without a heartbeat before a slave declares the master dead.
const MASTER_TIMEOUT_SECS: i64 = 5 * 60; // 5 minutes
const MIN_REPLICAS: usize = 2;            // 1 master + 2 slaves
/// Rejoin window for a dark holder: within it the holder re-proves possession and
/// rejoins with zero re-transfer; past it, it's evicted and a new replica recruited.
const REPLICA_GRACE_SECS: i64 = 24 * 3600;
/// Escrow is never streamed for wall-clock time that predates this process epoch —
/// a master returning from sleep must not pay (or pay itself) for the dark gap.
static PAYOUT_FLOOR_TS: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

pub fn bump_payout_floor() {
    PAYOUT_FLOOR_TS.store(chrono::Utc::now().timestamp(), std::sync::atomic::Ordering::Relaxed);
}
const UNDER_REPLICATED_WARN_SECS:     i64 = 3_600;      // 1 hour  → warning + immediate retry
const UNDER_REPLICATED_CRITICAL_SECS: i64 = 86_400;     // 24 hours → critical alert
const STORAGE_PAYOUT_INTERVAL_SECS:   i64 = 3_600;      // stream escrow at most hourly
const STORAGE_FEES_POOL: &str = "egot1storagefees000000000000000000000000000000";

pub async fn check_file_replication() {
    // Replicate as soon as there is at least one OTHER node to hold a copy. A client's
    // paid-for data must never live on a single machine that can be turned off — with 2
    // nodes we keep 2 copies, with 3+ we reach the full MIN_REPLICAS. (Previously gated to
    // >50 validators, which left every early-network file on a single master = data loss
    // the moment that user shut down.)
    if known_validator_count() < 2 { return; }
    let _guard = crate::ledger::TX_MUTEX.lock().await; // This is fine, it's a tokio mutex
    let mut ledger = tokio::task::spawn_blocking(crate::ledger::Ledger::load)
        .await.unwrap_or_default();
    if ledger.address.is_empty() { return; }
    let my_addr = ledger.address.clone();
    let now     = chrono::Utc::now().timestamp();

    let mut need_save   = false;
    let mut pin_needed: Vec<String> = Vec::new();
    let mut payouts: Vec<(String, u64, String)> = Vec::new(); // (recipient, amount_uegoc, cid)

    // ── Re-publish under-distributed Active files when connectivity returns ───
    // Files stored while offline have replication_role="" and replica_peers=[].
    // The master/slave logic below will pick them up on the next tick once connected.

    for file in ledger.stored_files.iter_mut() {
        if file.status != "Active" { continue; }
        if file.from_egosafe && file.replication_role.is_empty() { continue; }
        let has_data = !file.local_path.is_empty() && !file.local_path.starts_with("sender:");

        // ── Assign initial role ───────────────────────────────────────────
        if file.replication_role.is_empty() && has_data {
            file.replication_role = "master".to_string();
            file.master_last_seen = now;
            file.master_since     = now;
            need_save = true;
        }

        match file.replication_role.as_str() {

            // ── MASTER duties ─────────────────────────────────────────────
            "master" => {
                // ── Replica liveness → 24h rejoin grace ───────────────────
                // A replica silent past MASTER_TIMEOUT_SECS stops being paid and
                // enters the grace window; within 24h it can re-prove possession
                // and rejoin without re-transfer, after that it's gone for good.
                let silent: Vec<String> = file.replica_peers.iter()
                    .filter(|addr| {
                        let last = file.replica_last_ack.get(*addr).copied().unwrap_or(0);
                        if last == 0 { return false; }
                        now - last > MASTER_TIMEOUT_SECS
                    })
                    .cloned()
                    .collect();
                for addr in &file.replica_peers {
                    file.replica_last_ack.entry(addr.clone()).or_insert(now);
                }
                for addr in silent {
                    file.replica_peers.retain(|p| p != &addr);
                    file.replica_last_ack.remove(&addr);
                    file.replica_grace.insert(addr.clone(), now);
                    need_save = true;
                    tracing::warn!(
                        "Replication: replica {} for {} went dark — entering 24h rejoin grace",
                        &addr[..20.min(addr.len())],
                        &file.cid[..16.min(file.cid.len())]
                    );
                }
                let expired: Vec<String> = file.replica_grace.iter()
                    .filter(|(_, &since)| now - since > REPLICA_GRACE_SECS)
                    .map(|(a, _)| a.clone())
                    .collect();
                for addr in expired {
                    file.replica_grace.remove(&addr);
                    need_save = true;
                    tracing::warn!(
                        "Replication: {} did not return within the 24h grace for {} — evicted permanently",
                        &addr[..20.min(addr.len())],
                        &file.cid[..16.min(file.cid.len())]
                    );
                }

                // ── Per-period escrow release ─────────────────────────────
                // Stream the uploader's prepaid fee to the CURRENT proven holders
                // (this master + live replica_peers) pro-rata for the elapsed time,
                // capped at the deal window and the remaining escrow. Because only
                // the live master runs this — and a promoted slave resets its payout
                // clock to `now` — an offline master earns nothing for time it isn't
                // serving: payment follows the data.
                if file.storage_fee_uegoc > file.storage_fee_paid_uegoc
                    && file.expiry > file.stored_at
                {
                    let floor = {
                        let f = PAYOUT_FLOOR_TS.load(std::sync::atomic::Ordering::Relaxed);
                        if f == 0 {
                            PAYOUT_FLOOR_TS.store(now, std::sync::atomic::Ordering::Relaxed);
                            now
                        } else {
                            f
                        }
                    };
                    let last = if file.last_storage_payout_ts > 0 {
                        file.last_storage_payout_ts
                    } else {
                        file.stored_at
                    };
                    let last = last.max(floor);
                    let until = now.min(file.expiry);
                    if until - last >= STORAGE_PAYOUT_INTERVAL_SECS {
                        let duration  = (file.expiry - file.stored_at) as u128;
                        let elapsed   = (until - last) as u128;
                        let remaining = file.storage_fee_uegoc - file.storage_fee_paid_uegoc;
                        let accrued   = (file.storage_fee_uegoc as u128 * elapsed / duration) as u64;
                        let amount    = accrued.min(remaining);
                        if amount > 0 {
                            // Current proven holders: self (unless proof-suspended) plus
                            // the live replicas (PoRep evicts dead/failed ones, so this
                            // list is exactly who is actually holding the data now).
                            let mut holders: Vec<String> = Vec::new();
                            if file.proof_suspended_until <= now {
                                holders.push(my_addr.clone());
                            }
                            for p in &file.replica_peers { holders.push(p.clone()); }

                            let n = holders.len() as u64;
                            if n > 0 {
                                let share = amount / n;
                                if share > 0 {
                                    let dust = amount - share * n; // give remainder to first holder
                                    for (i, haddr) in holders.iter().enumerate() {
                                        let amt = if i == 0 { share + dust } else { share };
                                        payouts.push((haddr.clone(), amt, file.cid.clone()));
                                    }
                                    file.storage_fee_paid_uegoc += amount;
                                    file.last_storage_payout_ts = until;
                                    need_save = true;
                                }
                            }
                        }
                    }
                }

                // Broadcast heartbeat to all known slaves
                let hb = P2PMessage::ReplicaHeartbeat {
                    cid:          file.cid.clone(),
                    master_addr:  my_addr.clone(),
                    timestamp:    now,
                    master_since: file.master_since,
                };
                let peers = tokio::task::spawn_blocking(load_peer_cache)
                    .await.unwrap_or_default();
                for peer in &peers {
                    if !peer.endpoint.is_empty() {
                        let _ = send_message_any(&[peer.endpoint.clone()], &hb).await;
                    }
                }

                // ── Recruitment gate ──────────────────────────────────────
                // A slot covered by a holder in its 24h grace does NOT trigger a
                // replacement (anti-churn: sleeping laptops come back with their
                // copy intact) — UNLESS redundancy is critical: with zero live
                // replicas the master is the only copy, and a fresh replica is
                // recruited immediately regardless of grace.
                let live    = file.replica_peers.len();
                let in_grace = file.replica_grace.len();
                let recruit = live == 0 || live + in_grace < MIN_REPLICAS;

                if live == 0 {
                    if file.under_replicated_since == 0 {
                        file.under_replicated_since = now;
                        need_save = true;
                    }
                    let under_secs = now - file.under_replicated_since;
                    if under_secs >= UNDER_REPLICATED_CRITICAL_SECS {
                        tracing::error!(
                            "CRITICAL: {} has 0 live replicas for {}h — file at risk of loss",
                            &file.cid[..16.min(file.cid.len())],
                            under_secs / 3600
                        );
                    } else if under_secs >= UNDER_REPLICATED_WARN_SECS {
                        tracing::warn!(
                            "{} has 0 live replicas for {}min — requesting replication",
                            &file.cid[..16.min(file.cid.len())],
                            under_secs / 60
                        );
                    } else {
                        tracing::info!("Replication: {} has 0/{} live replicas — requesting",
                            &file.cid[..16.min(file.cid.len())], MIN_REPLICAS);
                    }
                } else if file.under_replicated_since != 0 {
                    file.under_replicated_since = 0;
                    need_save = true;
                }

                if recruit {
                    if live > 0 {
                        tracing::info!(
                            "Replication: {} has {}/{} live replicas ({} in grace) — requesting more",
                            &file.cid[..16.min(file.cid.len())],
                            live, MIN_REPLICAS, in_grace);
                    }
                    pin_needed.push(file.cid.clone());
                } else if live < MIN_REPLICAS {
                    tracing::debug!(
                        "Replication: {} at {}/{} live — hole covered by {} grace holder(s), not recruiting",
                        &file.cid[..16.min(file.cid.len())],
                        live, MIN_REPLICAS, in_grace);
                }
            }

            // ── SLAVE duties ──────────────────────────────────────────────
            "slave" => {
                let master_alive = file.master_last_seen > 0
                    && (now - file.master_last_seen) < MASTER_TIMEOUT_SECS;

                if !master_alive {
                    // Master has not sent a heartbeat within the timeout window.
                    // Promote self to master and broadcast to find a new slave.
                    tracing::warn!("Replication: slave promoting to master for {} (master {} silent for {}s)",
                        &file.cid[..16.min(file.cid.len())],
                        &file.replica_master,
                        now - file.master_last_seen);

                    let old_master = file.replica_master.clone();
                    file.replication_role = "master".to_string();
                    file.replica_master   = String::new();
                    file.master_last_seen = now;
                    file.master_since     = now;
                    // Start the escrow payout clock at promotion: this node only earns for
                    // the data from the moment it takes over serving it, never the dead
                    // master's unserved gap.
                    file.last_storage_payout_ts = now;
                    // The dead master keeps its copy on disk: give it the 24h rejoin
                    // grace instead of dropping it — if it returns and re-proves
                    // possession it rejoins as a slave with zero re-transfer.
                    file.replica_peers.retain(|p| p != &old_master);
                    file.replica_last_ack.remove(&old_master);
                    if !old_master.is_empty() {
                        file.replica_grace.insert(old_master.clone(), now);
                    }
                    need_save = true;

                    // Broadcast promotion so other slaves know who the new master is
                    let promote_msg = P2PMessage::ReplicaPromote {
                        cid:        file.cid.clone(),
                        new_master: my_addr.clone(),
                        old_master,
                        timestamp:  now,
                    };
                    let peers = tokio::task::spawn_blocking(load_peer_cache)
                        .await.unwrap_or_default();
                    for peer in &peers {
                        if !peer.endpoint.is_empty() {
                            let _ = send_message_any(&[peer.endpoint.clone()], &promote_msg).await;
                        }
                    }

                    // Immediately request a new slave
                    pin_needed.push(file.cid.clone());
                }
            }

            _ => {}
        }
    }

    if need_save {
        tokio::task::spawn_blocking(move || ledger.save())
            .await.unwrap_or(Ok(())).ok();
    }
    if !pin_needed.is_empty() {
        request_file_pinning(pin_needed).await;
    }
    if !payouts.is_empty() {
        let now2 = now;
        tokio::task::spawn_blocking(move || {
            let mut chain = crate::ledger::load_chain();
            for (to, amount, cid) in payouts {
                let h = format!("0x{}", ego_core::hash_data(
                    format!("storage-escrow:{}:{}:{}", cid, to, now2).as_bytes()
                ).to_hex());
                chain.transactions.push(crate::ledger::LedgerTx {
                    hash: h,
                    from: STORAGE_FEES_POOL.into(),
                    to,
                    amount,
                    memo: Some(format!("Storage escrow release: {}", &cid[..16.min(cid.len())])),
                    timestamp: now2,
                    signature: "provider".into(),
                    status: "Confirmed".into(),
                    ..crate::ledger::LedgerTx::default()
                });
            }
            let _ = crate::ledger::save_chain(&chain);
        }).await.ok();
    }
}



fn peer_cache_path() -> std::path::PathBuf { base_data_dir().join("peers.json") }

pub fn load_peer_cache() -> Vec<PeerEntry> {
    let data = std::fs::read_to_string(peer_cache_path()).unwrap_or_default();
    let mut peers: Vec<PeerEntry> = serde_json::from_str(&data).unwrap_or_default();
    let cutoff = Utc::now().timestamp() - 30 * 86_400;
    peers.retain(|p| p.last_seen >= cutoff);
    peers
}

fn save_peer_cache(peers: &[PeerEntry]) {
    if let Ok(data) = serde_json::to_string_pretty(peers) {
        let _ = crate::utils::atomic_write(&peer_cache_path(), data.as_bytes());
    }
}

pub fn upsert_peer_cache(entry: PeerEntry) {
    let mut peers = load_peer_cache();
    if let Some(e) = peers.iter_mut().find(|p| p.address == entry.address) {
        e.endpoint  = entry.endpoint;
        e.last_seen = entry.last_seen;
    } else {
        peers.push(entry);
    }
    save_peer_cache(&peers);
}

// ── Identity ──────────────────────────────────────────────────────────────────

fn load_or_create_identity() -> libp2p::identity::Keypair {
    let path = base_data_dir().join("p2p_identity.bin");
    if let Ok(raw) = std::fs::read(&path) {
        // os_unprotect handles DPAPI blobs (Windows), legacy keyring sentinels
        // (macOS/Linux migration) and plain protobuf alike.
        let bytes = crate::utils::os_unprotect(&raw);
        if let Ok(kp) = libp2p::identity::Keypair::from_protobuf_encoding(&bytes) {
            // Migrate: if the file held a sentinel (the old macOS/Linux path that
            // hijacked the wallet-seed Keychain slot) or plaintext needing DPAPI,
            // re-save in the current on-disk format and stop depending on the
            // shared Keychain item.
            let desired = crate::utils::os_protect(&bytes);
            if raw != desired {
                let _ = crate::utils::atomic_write(&path, &desired);
            }
            return kp;
        }
    }
    let kp = libp2p::identity::Keypair::generate_ed25519();
    if let Ok(pb) = kp.to_protobuf_encoding() {
        let protected = crate::utils::os_protect(&pb);
        let _ = crate::utils::atomic_write(&path, &protected);
    }
    kp
}

// ── Swarm entry point ─────────────────────────────────────────────────────────

pub async fn start_p2p_server(app: Option<tauri::AppHandle<tauri::Wry>>) {
    if let Some(h) = app.clone() {
        let _ = APP_HANDLE.set(h);
    }
    if std::env::var("EGO_RELAY_SERVER").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false) {
        IS_RELAY_SERVER.store(true, Ordering::Relaxed);
        tracing::info!("Node configured as Relay/Bootstrap Server via EGO_RELAY_SERVER");
    }

    #[cfg(target_os = "windows")]
    tokio::task::spawn_blocking(ensure_firewall_rule).await.ok();

    let identity      = load_or_create_identity();
    let local_peer_id = identity.public().to_peer_id();
    tracing::info!("Local peer ID: {}", local_peer_id);

    // HTTPS gateway for .eo domains
    eprintln!("[HTTPS] .eo gateway listening on https://127.0.0.1:{}", https_port());

    let mut swarm = match build_swarm(identity).await {
        Ok(s)  => s,
        Err(e) => { tracing::error!("Failed to build swarm: {}", e); return; }
    };

    if let Err(e) = swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{}", p2p_port()).parse().unwrap()) {
        tracing::error!("TCP listen failed: {}", e);
    }
    // QUIC (UDP) on every platform — it is the transport DCUtR hole-punching works
    // best over, so two NAT'd peers can form a DIRECT connection without any inbound
    // firewall rule. Previously disabled on Windows; re-enabled so Windows nodes get
    // the same NAT traversal as Linux/macOS.
    if let Err(e) = swarm.listen_on(format!("/ip4/0.0.0.0/udp/{}/quic-v1", p2p_port()).parse().unwrap()) {
        tracing::error!("QUIC listen failed: {}", e);
    }

    // ── In-browser app tunnel: publish the control + accept inbound streams ──
    {
        let mut control = swarm.behaviour().stream.new_control();
        let _ = TUNNEL_CONTROL.set(control.clone());
        match control.accept(TUNNEL_PROTOCOL) {
            Ok(mut incoming) => {
                tokio::spawn(async move {
                    while let Some((peer, stream)) = incoming.next().await {
                        tokio::spawn(async move {
                            if let Err(e) = serve_tunnel_stream(stream).await {
                                tracing::debug!("[tunnel] stream from {peer} ended: {e}");
                            }
                        });
                    }
                });
            }
            Err(e) => tracing::error!("[tunnel] failed to register accept handler: {e}"),
        }
    }

    // relay PeerId → base transport addr (no /p2p/<id> suffix)
    // e.g.  12D3KooWPj6m... → /ip4/40.233.82.42/tcp/4001
    let mut relay_addrs: HashMap<PeerId, Multiaddr> = HashMap::new();
    let mut relay_connected_count = 0usize;
    for relay_str in shuffled_relay_nodes() {
        if let Ok(addr) = relay_str.parse::<Multiaddr>() {
            if let Some(pid) = peer_id_from_multiaddr(&addr) {
                relay_addrs.insert(pid, strip_p2p_suffix(&addr));
            }
            if can_dial_relay(relay_str) {
                eprintln!("[P2P] Dialling relay {} (attempt {}/{})", relay_str, relay_connected_count + 1, RELAY_NODES.len());
                let _ = swarm.dial(addr);
            }
            relay_connected_count += 1;
        }
    }


    {
        let cached = load_peer_cache();
        if cached.len() >= MIN_CACHED_PEERS_FOR_DIRECT_BOOT {
            tracing::info!("{} cached peers — attempting relay-free bootstrap", cached.len());
        }
        let active_relay_ids: std::collections::HashSet<String> = RELAY_NODES.iter()
            .filter_map(|r| r.parse::<Multiaddr>().ok())
            .filter_map(|m| peer_id_from_multiaddr(&m))
            .map(|pid| pid.to_string())
            .collect();
        for peer in cached.iter().filter(|p| !p.endpoint.is_empty()).take(30) {
            let ep = &peer.endpoint;
            let is_old_relay = ep.contains("egorelay2.") || ep.contains("egorelay3.")
                || ep.contains("egorelay4.") || ep.contains("egorelay5.");
            let is_active_relay = active_relay_ids.iter().any(|id| ep.contains(id.as_str()));
            if is_old_relay || is_active_relay { continue; }
            if let Ok(addr) = ep.parse::<Multiaddr>() {
                let _ = swarm.dial(addr);
            }
        }
    }

    if let Ok(peers_env) = std::env::var("EGO_DIRECT_PEERS") {
        for addr_str in peers_env.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if let Ok(addr) = addr_str.parse::<Multiaddr>() {
                eprintln!("[P2P] Dialling direct peer: {}", addr);
                let _ = swarm.dial(addr.clone());

                if let Some(pid) = peer_id_from_multiaddr(&addr) {
                    upsert_peer_cache(PeerEntry {
                        address:   pid.to_string(),
                        endpoint:  addr.to_string(),
                        last_seen: chrono::Utc::now().timestamp(),
                        city:      None,
                        country:   None,
                        lat:       None,
                        lon:       None,
                    });
                }
            }
        }
    }

    // ── Gossipsub subscriptions ───────────────────────────────────────────────
    let tx_topic       = gossipsub::IdentTopic::new("ego-txs-v1");
    let block_topic    = gossipsub::IdentTopic::new("ego-blocks-v1");
    let proposal_topic = gossipsub::IdentTopic::new("ego-proposals-v1");
    let vote_topic     = gossipsub::IdentTopic::new("ego-votes-v1");
    let peers_topic    = gossipsub::IdentTopic::new("ego-peers-v1");
    let vc_topic       = gossipsub::IdentTopic::new("ego-viewchange-v1");
    
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&tx_topic);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&block_topic);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&proposal_topic);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&vote_topic);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&peers_topic);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&vc_topic);
    // Consensus-v2 shadow topic (cutover step 2). Subscribed always (cheap); only
    // produces/consumes when EGO_CONSENSUS_V2_SHADOW is set.
    let bftv2_topic = gossipsub::IdentTopic::new(V2_TOPIC);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&bftv2_topic);

    let shard_topic = gossipsub::IdentTopic::new("ego-shards-v1");
    swarm.behaviour_mut().gossipsub.subscribe(&shard_topic).ok();

    let price_topic = gossipsub::IdentTopic::new("ego-price-v1");
    swarm.behaviour_mut().gossipsub.subscribe(&price_topic).ok();

    let storage_topic = gossipsub::IdentTopic::new("ego-storage-v1");
    swarm.behaviour_mut().gossipsub.subscribe(&storage_topic).ok();

    let sync_req_topic = gossipsub::IdentTopic::new("ego-sync-v1");
    swarm.behaviour_mut().gossipsub.subscribe(&sync_req_topic).ok();

    let snapshot_topic = gossipsub::IdentTopic::new("ego-snapshot-v1");
    swarm.behaviour_mut().gossipsub.subscribe(&snapshot_topic).ok();

    let hosting_topic = gossipsub::IdentTopic::new("ego-hosting-v1");
    swarm.behaviour_mut().gossipsub.subscribe(&hosting_topic).ok();

    let compute_topic = gossipsub::IdentTopic::new("ego-compute-v1");
    swarm.behaviour_mut().gossipsub.subscribe(&compute_topic).ok();

    let shard_tx_topic = gossipsub::IdentTopic::new("ego-shard-txs-v1");
    swarm.behaviour_mut().gossipsub.subscribe(&shard_tx_topic).ok();

    let shard_rebalance_topic = gossipsub::IdentTopic::new("ego-shard-rebalance-v1");
    swarm.behaviour_mut().gossipsub.subscribe(&shard_rebalance_topic).ok();

    let poc_topic = gossipsub::IdentTopic::new("ego-poc-v1");
    swarm.behaviour_mut().gossipsub.subscribe(&poc_topic).ok();

    let dm_topic = gossipsub::IdentTopic::new(DM_TOPIC);
    swarm.behaviour_mut().gossipsub.subscribe(&dm_topic).ok();

    let _ = swarm.behaviour_mut().kad.bootstrap();


    let (gossip_unbounded_tx, mut gossip_rx) =
        mpsc::channel::<(String, Vec<u8>)>(GOSSIP_CHANNEL_CAPACITY);
    let _ = GOSSIP_TX.set(gossip_unbounded_tx);


    let (dht_cmd_tx, mut dht_cmd_rx) = mpsc::channel::<DhtCommand>(10_000);
    let _ = DHT_CMD_TX.set(dht_cmd_tx);

    let (tx, mut rx) = mpsc::channel::<SwarmCmd>(64);
    let _ = SWARM_TX.set(tx);

    let mut external_addrs:   Vec<Multiaddr> = Vec::new();
    if let Ok(pub_addr) = std::env::var("EGO_PUBLIC_ADDR") {
        if let Ok(addr) = pub_addr.trim().parse::<Multiaddr>() {
            swarm.add_external_address(addr.clone());
            external_addrs.push(addr.clone());
            IS_PUBLIC_REACHABLE.store(true, Ordering::Relaxed);
            crate::app::global_app_state().set_public_endpoint(best_endpoint(&external_addrs, &local_peer_id));
            eprintln!("[P2P] EGO_PUBLIC_ADDR set — advertising direct public address {}", addr);
        }
    }
    let mut pending_sends:    HashMap<PeerId, Vec<(P2PMessage, oneshot::Sender<Result<(), String>>)>> = HashMap::new();
    let mut in_flight:        HashMap<OutboundRequestId, oneshot::Sender<Result<(), String>>> = HashMap::new();
    let mut circuit_listener: Option<libp2p_core::transport::ListenerId> = None;

    // Compute-exec state — separate maps so a long-running shell command
    // doesn't block ordinary P2P messaging.
    let mut pending_exec_sends: HashMap<PeerId, Vec<(ComputeExecRequest, oneshot::Sender<Result<ComputeExecResponse, String>>)>> = HashMap::new();
    let mut exec_in_flight:     HashMap<OutboundRequestId, oneshot::Sender<Result<ComputeExecResponse, String>>> = HashMap::new();
    let (exec_resp_tx, mut exec_resp_rx) = mpsc::channel::<(request_response::ResponseChannel<ComputeExecResponse>, ComputeExecResponse)>(64);

    // Callers waiting for a connection to be established before opening a tunnel.
    let mut pending_dials: HashMap<PeerId, Vec<oneshot::Sender<Result<PeerId, String>>>> = HashMap::new();

    // Restore validator pubkeys from DB so BFT verification works after a node restart
    restore_validator_keys_from_db();

    let mut relay_retry = tokio::time::interval(Duration::from_secs(60));
    relay_retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    relay_retry.tick().await;

    let mut kad_discovery = tokio::time::interval(Duration::from_secs(300));
    kad_discovery.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    kad_discovery.tick().await;


    let mut peer_seed_bcast = tokio::time::interval(Duration::from_secs(300));
    peer_seed_bcast.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    peer_seed_bcast.tick().await;


    let mut dht_inbox_poll = tokio::time::interval(Duration::from_secs(30));
    dht_inbox_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    dht_inbox_poll.tick().await; // skip first immediate tick


    let mut announce_tick = tokio::time::interval(Duration::from_secs(45));
    announce_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    announce_tick.tick().await;

    let mut termination_rebcast = tokio::time::interval(Duration::from_secs(300));
    termination_rebcast.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    termination_rebcast.tick().await;

    if std::env::var("EGO_DATA_DIR").is_ok() && crate::ledger::load_seed().ok().flatten().is_none() {
        let _ = std::fs::create_dir_all(crate::ledger::data_dir());
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        if let Ok(_) = crate::ledger::save_seed(&seed) {
            if let Ok(kp) = ego_core::KeyPair::from_bytes(&seed) {
                if let Ok(addr) = kp.derive_bech32_address(1, ego_core::AddressType::EOA, "egot") {
                    let _guard = crate::ledger::TX_MUTEX.lock().await;
                    let mut ledger = crate::ledger::Ledger::load();
                    ledger.address = addr.clone();
                    let mn = kp.derive_bech32_address(0, ego_core::AddressType::EOA, "ego").unwrap_or_default();
                    ledger.mainnet_address = mn;
                    let _ = ledger.save();
                    eprintln!("[P2P] Auto-generated node identity: {}", addr);

                    let mut reg = crate::ledger::load_registry();
                    reg.active_id = "wallet_0".to_string();
                    reg.wallets.clear();
                    reg.wallets.push(crate::ledger::WalletEntry {
                        id:         "wallet_0".to_string(),
                        name:       "Node Wallet".to_string(),
                        address:    addr.clone(),
                        created_at: chrono::Utc::now().timestamp(),
                    });
                    let _ = crate::ledger::save_registry(&reg);
                }
            }
        }
    }

    {
        let _ = ensure_local_validator_identity();

        for addr in crate::chain_db::load_slashed_validators() {
            slashed_validators().insert(addr);
        }

        crate::ledger::reconcile_stake_state();


        crate::chain_db::restore_nonces_from_db();

        {
            let fin_h = crate::chain_db::finalized_height();
            if fin_h > 0 {
                let mut hard = hard_finalized_heights();
                let mut fin_map = finalized_at_height();
                let start_h = fin_h.saturating_sub(10_000).max(1);
                for h in start_h..=fin_h {
                    if let Some(hash) = crate::chain_db::get_block_hash_at(h) {
                        hard.insert(h);
                        fin_map.insert(h, hash);
                    }
                }
                tracing::info!("Restored {} finalized heights from DB", hard.len());
            }
            LAST_BLOCK_FINALIZED_TS.store(chrono::Utc::now().timestamp(), Ordering::Relaxed);
        }

        {
            let saved = crate::chain_db::restore_pending_votes_from_db();
            if !saved.is_empty() {
                let mut votes = pending_votes();
                for (bh, voters) in saved {
                    let entry = votes.entry(bh).or_default();
                    for v in voters {
                        if !entry.contains(&v) { entry.push(v); }
                    }
                }
                tracing::info!("Restored in-flight BFT votes from DB");
            }
        }


        {
            let slashed = crate::chain_db::load_slashed_validators()
                .into_iter()
                .collect::<std::collections::HashSet<_>>();
            let restored = crate::chain_db::load_known_validators();
            if !restored.is_empty() {
                let now = chrono::Utc::now().timestamp();
                let mut first = validator_first_seen();
                let mut last  = validator_last_seen();
                let mut set   = known_validators();
                for addr in &restored {
                    if addr.is_empty() || slashed.contains(addr) { continue; }
                    first.insert(addr.clone(), now - VALIDATOR_WARMUP_SECS - 1);
                    // Restored from DB ≠ currently online. Mark them as last-seen
                    // in the past so they do NOT count as a live committee member
                    // until they actually re-announce. Otherwise a restarted node
                    // believes a dead peer is live, thinks it has quorum, and
                    // stalls forever waiting for votes that never come.
                    last.insert(addr.clone(), now - VALIDATOR_LIVENESS_SECS - 1);
                    if set.len() < MAX_VALIDATORS {
                        set.insert(addr.clone());
                    }
                }
                tracing::info!("Restored {} known validators from DB (pending re-announce before they count toward quorum)", restored.len());
            }
        }
    }

    loop {
        tokio::select! {
            Some((topic_str, data)) = gossip_rx.recv() => {
                let topic = gossipsub::IdentTopic::new(topic_str.clone());
                match swarm.behaviour_mut().gossipsub.publish(topic, data) {
                    Ok(_) => {}
                    Err(gossipsub::PublishError::NoPeersSubscribedToTopic) => {}
                    Err(e) => eprintln!("[Gossip] publish '{}': {:?}", topic_str, e),
                }
            }

            cmd = rx.recv() => {
                let Some(cmd) = cmd else { break; };
                match cmd {
                    SwarmCmd::Send { peer_addr, msg, reply } => {
                        handle_send(&mut swarm, peer_addr, msg, reply,
                            &mut pending_sends, &mut in_flight);
                    }
                    SwarmCmd::GetEndpoint { reply } => {
                        let ep = best_endpoint(&external_addrs, &local_peer_id);
                        let _ = reply.send(ep);
                    }
                    SwarmCmd::GossipPublish { topic, data } => {
                        let t = gossipsub::IdentTopic::new(topic.clone());
                        match swarm.behaviour_mut().gossipsub.publish(t, data) {
                            Ok(_) => {}
                            Err(gossipsub::PublishError::NoPeersSubscribedToTopic) => {
                                if topic == "ego-poc-v1" {
                                    eprintln!("[PoC] publish on {}: no peers subscribed yet", topic);
                                }
                            }
                            Err(e) => eprintln!("[Gossip] publish '{}': {:?}", topic, e),
                        }
                    }
                    SwarmCmd::ComputeExec { peer_addr, req, reply } => {
                        handle_compute_exec_send(&mut swarm, peer_addr, req, reply,
                            &mut pending_exec_sends, &mut exec_in_flight);
                    }
                    SwarmCmd::Dial { peer_addr, reply } => {
                        match peer_id_from_multiaddr(&peer_addr) {
                            Some(pid) if pid == *swarm.local_peer_id() => {
                                let _ = reply.send(Err("Refusing self-dial".into()));
                            }
                            Some(pid) if swarm.is_connected(&pid) => {
                                let _ = reply.send(Ok(pid));
                            }
                            Some(pid) => {
                                pending_dials.entry(pid).or_default().push(reply);
                                let _ = swarm.dial(peer_addr);
                            }
                            None => { let _ = reply.send(Err(format!("No peer ID in multiaddr: {}", peer_addr))); }
                        }
                    }
                }
            }

            event = swarm.select_next_some() => {
                handle_event(
                    event, app.as_ref(),
                    &mut external_addrs, &mut pending_sends, &mut in_flight,
                    &mut pending_exec_sends, &mut exec_in_flight, &exec_resp_tx,
                    &mut swarm, &relay_addrs,
                    &mut circuit_listener, &mut pending_dials,
                ).await;
            }

            // Compute-exec response from a spawned exec task — feed back to
            // the libp2p behaviour so the buyer's outbound request completes.
            Some((channel, resp)) = exec_resp_rx.recv() => {
                let _ = swarm.behaviour_mut().compute_exec.send_response(channel, resp);
            }

        _ = announce_tick.tick() => {
            let app_clone = app.as_ref().cloned();
            tokio::spawn(async move {
                broadcast_peer_announce(app_clone.as_ref()).await;
            });
        }

        _ = termination_rebcast.tick() => {
            tokio::spawn(async move {
                let my_addr = crate::ledger::Ledger::load().address;
                let terminated: Vec<_> = tokio::task::spawn_blocking(move || {
                    crate::chain_db::list_compute_reservations()
                        .into_iter()
                        .filter(|r| r.buyer_address == my_addr && r.status == "terminated")
                        .collect()
                }).await.unwrap_or_default();
                for res in terminated {
                    let msg = P2PMessage::ReservationTerminated {
                        reservation_id: res.reservation_id.clone(),
                        by:     "buyer".to_string(),
                        reason: "rebcast".to_string(),
                    };
                    broadcast_compute_msg(msg).await;
                }
            });
        }

            // ── Relay circuit retry ───────────────────────────────────────────
            _ = peer_seed_bcast.tick() => {

                let peers = load_peer_cache();
                let multiaddrs: Vec<String> = peers.iter()
                    .filter(|p| !p.endpoint.is_empty())
                    .take(20)
                    .map(|p| p.endpoint.clone())
                    .collect();
                if !multiaddrs.is_empty() {
                    if let Ok(data) = serde_json::to_vec(&P2PMessage::PeerSeedGossip {
                        multiaddrs,
                        known_count: peers.len() as u32,
                    }) {
                        publish_gossip("ego-peers-v1", data).await;
                    }
                }
            }

            _ = relay_retry.tick() => {
                if let Ok(peers_env) = std::env::var("EGO_DIRECT_PEERS") {
                    for addr_str in peers_env.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                        if let Ok(addr) = addr_str.parse::<Multiaddr>() {
                            if let Some(pid) = peer_id_from_multiaddr(&addr) {
                                if !swarm.is_connected(&pid) {
                                    eprintln!("[P2P] Direct peer {} not connected — redialling", addr_str);
                                    let _ = swarm.dial(addr);
                                }
                            } else {
                                let _ = swarm.dial(addr);
                            }
                        }
                    }
                }
                if DIRECT_PEER_COUNT.load(Ordering::Relaxed) >= MIN_DIRECT_PEERS_RELAY_OPTIONAL
                    && has_circuit_addr(&external_addrs)
                {

                    continue;
                }
                if !has_circuit_addr(&external_addrs) {
                    let mut circuit_registered = false;
                    for relay_str in shuffled_relay_nodes() {
                        if circuit_registered { break; }
                        if let Ok(addr) = relay_str.parse::<Multiaddr>() {
                            let relay_pid = peer_id_from_multiaddr(&addr);
                            let connected = relay_pid
                                .map(|p| swarm.is_connected(&p))
                                .unwrap_or(false);
                            if connected && circuit_listener.is_none() {
                                let circuit_str = format!("{}/p2p-circuit", relay_str);
                                if let Ok(caddr) = circuit_str.parse::<Multiaddr>() {
                                    match swarm.listen_on(caddr) {
                                        Ok(lid) => {
                                            circuit_listener = Some(lid);
                                            circuit_registered = true;
                                            tracing::info!("Relay circuit registered via {}", relay_str);
                                        }
                                        Err(e) => tracing::warn!("Re-register failed on {}: {}", relay_str, e),
                                    }
                                }
                            } else if !connected {
                                if can_dial_relay(relay_str) {
                                    eprintln!("[P2P] Relay {} not connected — redialling", relay_str);
                                    let _ = swarm.dial(addr);
                                }
                            }
                        }
                    }


                    for endpoint in get_discovered_relay_nodes() {
                        if let Ok(addr) = endpoint.parse::<Multiaddr>() {
                            if let Some(relay_pid) = peer_id_from_multiaddr(&addr) {
                                if !relay_addrs.contains_key(&relay_pid) {
                                    relay_addrs.insert(relay_pid, strip_p2p_suffix(&addr));
                                    let _ = swarm.dial(addr);
                                    eprintln!("[P2P] Phase 2: dialing community relay {}", endpoint);
                                }
                            }
                        }
                    }
                }
            }

            Some(cmd) = dht_cmd_rx.recv() => {
                match cmd {
                    DhtCommand::PutPeer { key, value } => {
                        let record = kad::Record {
                            key:       kad::RecordKey::new(&key),
                            value,
                            publisher: None,
                            expires:   None,
                        };
                        let _ = swarm.behaviour_mut().kad.put_record(
                            record, kad::Quorum::One
                        );
                    }
                    DhtCommand::GetPeers { key } => {
                        swarm.behaviour_mut().kad.get_record(
                            kad::RecordKey::new(&key)
                        );
                    }
                    DhtCommand::DialPeer { addr } => {
                        if let Ok(ma) = addr.parse::<Multiaddr>() {
                            eprintln!("[Relay] Dialling community relay: {}", ma);
                            let _ = swarm.dial(ma);
                        }
                    }
                }
            }

            _ = kad_discovery.tick() => {
                let _ = swarm.behaviour_mut().kad.bootstrap();
                swarm.behaviour_mut().kad.get_record(kad::RecordKey::new(&"ego-peers-v1"));
            }

            _ = dht_inbox_poll.tick() => {
                let app2: Option<tauri::AppHandle<tauri::Wry>> = app.as_ref().cloned();
                tokio::spawn(async move {
                    const TRANSFER_TIMEOUT_SECS: i64 = 600;
                    let now = chrono::Utc::now().timestamp();
                    let ledger = tokio::task::spawn_blocking(crate::ledger::Ledger::load)
                        .await.unwrap_or_default();
                    let mut timed_out: Vec<String> = Vec::new();
                    let mut missing: Vec<(String, Vec<String>)> = Vec::new();

                    for file in &ledger.stored_files {
                        if !file.cid.starts_with("egomfd1")
                            || file.status == "Failed"
                            || file.status == "Received"
                        { continue; }

                        if file.blocks_total > 0 && file.blocks_received < file.blocks_total {
                            let last = if file.last_block_at > 0 { file.last_block_at } else { file.stored_at };
                            if last > 0 && now - last > TRANSFER_TIMEOUT_SECS {
                                timed_out.push(file.cid.clone());
                                continue;
                            }
                            if let Ok(manifest) = crate::blocks::load_manifest(&file.cid) {
                                let blocks = crate::blocks::missing_blocks(&manifest);
                                if !blocks.is_empty() {
                                    missing.push((file.cid.clone(), blocks));
                                }
                            }
                        }
                    }

                    for (_, block_cids) in missing {
                        if let Some(tx) = DHT_CMD_TX.get() {
                            for block_cid in block_cids {
                                let _ = tx.send(DhtCommand::GetPeers {
                                    key: format!("ego-block:{}", block_cid),
                                });
                            }
                        }
                    }

                    if !timed_out.is_empty() {
                    let _guard = crate::ledger::TX_MUTEX.lock().await;
                        let mut ledger2 = tokio::task::spawn_blocking(crate::ledger::Ledger::load)
                            .await.unwrap_or_default();
                        for cid in &timed_out {
                            if let Some(f) = ledger2.stored_files.iter_mut().find(|f| &f.cid == cid) {
                                f.status = "Failed".to_string();
                                eprintln!("[Blocks] Transfer timed out ({}s): {}", TRANSFER_TIMEOUT_SECS, &cid[..cid.len().min(20)]);
                            }
                        }
                        let _ = tokio::task::spawn_blocking(move || ledger2.save()).await;
                        if let Some(h) = app2.as_ref() {
                            for cid in &timed_out {
                                let _ = h.emit_all("ego://file-failed", serde_json::json!({ "cid": cid }));
                            }
                        }
                    }
                });
            }
        }
    }
}

fn strip_p2p_suffix(addr: &Multiaddr) -> Multiaddr {
    use libp2p::multiaddr::Protocol;
    addr.iter().filter(|p| !matches!(p, Protocol::P2p(_))).collect()
}

async fn build_swarm(
    identity: libp2p::identity::Keypair,
) -> Result<libp2p::Swarm<EgoBehaviour>, Box<dyn std::error::Error>> {
    let peer_id = identity.public().to_peer_id();
    #[cfg(target_os = "windows")]
    // Disable port_reuse on Windows to prevent loopback OS error 10048
    let tcp_cfg = tcp::Config::default().nodelay(true).port_reuse(false);
    #[cfg(not(target_os = "windows"))]
    let tcp_cfg = tcp::Config::default().nodelay(true);
    let swarm = SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(tcp_cfg, noise::Config::new, yamux::Config::default)?
        .with_quic()
        .with_dns()?
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key, relay_client| {
            // ── Gossipsub ─────────────────────────────────────────────────────
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(10))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .max_transmit_size(32 * 1024 * 1024) // 32 MB max block/proposal size
                .mesh_n_low(6)
                .mesh_n(12)
                .mesh_n_high(24)
                .gossip_factor(0.25)
                .build()
                .expect("gossipsub config");
            let gossipsub_behaviour = gossipsub::Behaviour::new(
                // Signed mode: libp2p signs every gossip message with the node's
                // private key and verifies peer signatures on receive.
                // This prevents message spoofing at the transport layer.
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )
            .expect("gossipsub::Behaviour");


            let mut kad_store_cfg = kad::store::MemoryStoreConfig::default();
            kad_store_cfg.max_value_bytes = 4 * 1024 * 1024; // 4 MB
            let store = kad::store::MemoryStore::with_config(peer_id, kad_store_cfg);
            let mut kad_behaviour = kad::Behaviour::new(peer_id, store);

            for relay_str in RELAY_NODES {
                if let Ok(addr) = relay_str.parse::<Multiaddr>() {
                    if let Some(relay_pid) = peer_id_from_multiaddr(&addr) {
                        kad_behaviour.add_address(&relay_pid, strip_p2p_suffix(&addr));
                    }
                }
            }

            // Eclipse attack defense:
            //  - Bootstrap is diverse across 3 independent relay nodes (RELAY_NODES above),
            //    so an attacker must compromise all three to isolate this node.
            //  - Kademlia provides probabilistic diverse routing; XOR-metric bucket
            //    distribution prevents any single region of the keyspace from being
            //    monopolised by colluding peers.
            //  - No single peer should be trusted as the sole chain authority; all
            //    received chain data is validated against GENESIS_HASH and BFT rules.
            for entry in load_peer_cache() {
                if entry.endpoint.is_empty() { continue; }
                if let Ok(addr) = entry.endpoint.parse::<Multiaddr>() {
                    if let Some(pid) = peer_id_from_multiaddr(&addr) {
                        kad_behaviour.add_address(&pid, strip_p2p_suffix(&addr));
                    } else {

                        if let Ok(pid) = entry.address.parse::<PeerId>() {
                            kad_behaviour.add_address(&pid, addr);
                        }
                    }
                }
            }

            kad_behaviour.set_mode(Some(kad::Mode::Server));

            EgoBehaviour {
                relay_client,
                relay_server: relay::Behaviour::new(peer_id, relay::Config {
                    max_reservations:          4096,
                    max_reservations_per_peer: 64,
                    reservation_duration:      Duration::from_secs(3600),
                    max_circuits:              4096,
                    max_circuits_per_peer:     256,
                    max_circuit_duration:      Duration::from_secs(7200),
                    max_circuit_bytes:         u64::MAX,
                    ..Default::default()
                }),
                dcutr:    dcutr::Behaviour::new(peer_id),
                identify: identify::Behaviour::new(
                    identify::Config::new("/ego/identify/1.0.0".to_string(), key.public())
                        .with_interval(Duration::from_secs(60)),
                ),
                request_response: request_response::Behaviour::new(
                    [(StreamProtocol::new("/ego/msg/1.1.0"), ProtocolSupport::Full)],
                    request_response::Config::default()
                        .with_request_timeout(Duration::from_secs(120)),
                ),
                compute_exec: request_response::Behaviour::new(
                    [(StreamProtocol::new("/ego/compute-exec/1.0.0"), ProtocolSupport::Full)],
                    request_response::Config::default()
                        .with_request_timeout(Duration::from_secs(180)),
                ),
                autonat: autonat::Behaviour::new(peer_id, autonat::Config::default()),
                ping: ping::Behaviour::new(
                    ping::Config::new()
                        .with_interval(Duration::from_secs(15))
                        // Short timeout so a dead connection (e.g. after a LAN/WiFi change)
                        // is detected in ~20s and closed → ConnectionClosed → relay/peer
                        // redial re-establishes connectivity on the new network.
                        .with_timeout(Duration::from_secs(20)),
                ),
                gossipsub: gossipsub_behaviour,
                kad:       kad_behaviour,
                mdns:      mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)
                               .expect("mdns behaviour"),
                upnp:      upnp::tokio::Behaviour::default(),
                stream:    libp2p_stream::Behaviour::new(),
            }
        })?
        .with_swarm_config(|c| {
            c.with_max_negotiating_inbound_streams(2048)
             .with_idle_connection_timeout(Duration::from_secs(86400))
             .with_per_connection_event_buffer_size(128)
             .with_notify_handler_buffer_size(std::num::NonZeroUsize::new(2048).unwrap())
        })
        .build();
    Ok(swarm)
}


fn handle_send(
    swarm:         &mut libp2p::Swarm<EgoBehaviour>,
    peer_addr:     Multiaddr,
    msg:           P2PMessage,
    reply:         oneshot::Sender<Result<(), String>>,
    pending_sends: &mut HashMap<PeerId, Vec<(P2PMessage, oneshot::Sender<Result<(), String>>)>>,
    in_flight:     &mut HashMap<OutboundRequestId, oneshot::Sender<Result<(), String>>>,
) {
    let peer_id = match peer_id_from_multiaddr(&peer_addr) {
        Some(id) => id,
        None => {
            let _ = reply.send(Err(format!("No peer ID in multiaddr: {}", peer_addr)));
            return;
        }
    };

    let local_id = swarm.local_peer_id();
    if &peer_id == local_id {
        let _ = reply.send(Err("Refusing self-dial (ID match)".to_string()));
        return;
    }

    if swarm.is_connected(&peer_id) {
        let req_id = swarm.behaviour_mut().request_response.send_request(&peer_id, msg);
        in_flight.insert(req_id, reply);
    } else {
        pending_sends.entry(peer_id).or_default().push((msg, reply));
        let _ = swarm.dial(peer_addr);
    }
}

fn handle_compute_exec_send(
    swarm:              &mut libp2p::Swarm<EgoBehaviour>,
    peer_addr:          Multiaddr,
    req:                ComputeExecRequest,
    reply:              oneshot::Sender<Result<ComputeExecResponse, String>>,
    pending_exec_sends: &mut HashMap<PeerId, Vec<(ComputeExecRequest, oneshot::Sender<Result<ComputeExecResponse, String>>)>>,
    exec_in_flight:     &mut HashMap<OutboundRequestId, oneshot::Sender<Result<ComputeExecResponse, String>>>,
) {
    let peer_id = match peer_id_from_multiaddr(&peer_addr) {
        Some(id) => id,
        None => {
            let _ = reply.send(Err(format!("No peer ID in multiaddr: {}", peer_addr)));
            return;
        }
    };

    if &peer_id == swarm.local_peer_id() {
        let _ = reply.send(Err("Refusing self-dial (ID match)".to_string()));
        return;
    }

    if swarm.is_connected(&peer_id) {
        let req_id = swarm.behaviour_mut().compute_exec.send_request(&peer_id, req);
        exec_in_flight.insert(req_id, reply);
    } else {
        pending_exec_sends.entry(peer_id).or_default().push((req, reply));
        let _ = swarm.dial(peer_addr);
    }
}

fn peer_id_from_multiaddr(addr: &Multiaddr) -> Option<PeerId> {
    use libp2p::multiaddr::Protocol;
    addr.iter().filter_map(|p| {
        if let Protocol::P2p(pid) = p { Some(pid) } else { None }
    }).last()
}


fn best_endpoint(external_addrs: &[Multiaddr], peer_id: &PeerId) -> String {
    let pid_str = peer_id.to_string();

    let is_public = |a: &Multiaddr| {
        let s = a.to_string();
        !s.starts_with("/ip4/127.")     &&
        !s.starts_with("/ip4/10.")      &&
        !s.starts_with("/ip4/192.168.") &&
        !s.starts_with("/ip4/172.")
    };

    if IS_PUBLIC_REACHABLE.load(Ordering::Relaxed) {
        if let Some(a) = external_addrs.iter()
            .find(|a| { let s = a.to_string(); is_public(a) && !s.contains("/p2p-circuit") })
        {
            let s = a.to_string();
            return if s.contains("/p2p/") { s } else { format!("{}/p2p/{}", s, pid_str) };
        }
    }

    if let Some(a) = external_addrs.iter().find(|a| a.to_string().contains("/p2p-circuit")) {
        let s = a.to_string();
        return if s.contains(&pid_str) { s } else { format!("{}/p2p/{}", s, pid_str) };
    }
    let base = external_addrs.iter().find(|a| is_public(a))
        .or_else(|| external_addrs.first())
        .map(|a| a.to_string())
        .unwrap_or_else(|| format!("/ip4/{}/tcp/{}", get_local_ip(), p2p_port()));
    if base.contains("/p2p/") { base } else { format!("{}/p2p/{}", base, pid_str) }
}

fn has_circuit_addr(addrs: &[Multiaddr]) -> bool {
    addrs.iter().any(|a| a.to_string().contains("/p2p-circuit"))
}


fn build_circuit_addr(
    relay_base:    &Multiaddr,
    relay_peer_id: &PeerId,
    our_peer_id:   &PeerId,
) -> Option<Multiaddr> {
    format!("{}/p2p/{}/p2p-circuit/p2p/{}", relay_base, relay_peer_id, our_peer_id)
        .parse()
        .ok()
}


fn inject_circuit(
    circuit:        Multiaddr,
    external_addrs: &mut Vec<Multiaddr>,
    app:            Option<&tauri::AppHandle<tauri::Wry>>,
    local_peer_id:  &PeerId,
) {
    if !external_addrs.contains(&circuit) {
        tracing::info!("Circuit injected: {}", circuit);
        external_addrs.push(circuit);
    }
    RELAY_CIRCUIT_READY.store(true, Ordering::Relaxed);
    let ep    = best_endpoint(external_addrs, local_peer_id);
    let state = crate::app::global_app_state();
    state.set_public_endpoint(ep.clone());
    state.set_upnp_status(Ok(()));
    if let Some(h) = app {
        let _ = h.emit_all("ego://p2p-status-changed", ());
    }

    let app_clone = app.cloned();
    tokio::spawn(async move {

        tokio::time::sleep(Duration::from_millis(300)).await;
        broadcast_peer_announce(app_clone.as_ref()).await;
        eprintln!("[P2P] Re-announced after relay circuit confirmed");

        let addr = crate::ledger::Ledger::load().address;
        if !addr.is_empty() {
            eprintln!("[Messenger] Relay inbox polling for {}", &addr[..addr.len().min(20)]);
        }
    });
}

async fn handle_event(
    event:              SwarmEvent<EgoBehaviourEvent>,
    app:                Option<&tauri::AppHandle<tauri::Wry>>,
    external_addrs:     &mut Vec<Multiaddr>,
    pending_sends:      &mut HashMap<PeerId, Vec<(P2PMessage, oneshot::Sender<Result<(), String>>)>>,
    in_flight:          &mut HashMap<OutboundRequestId, oneshot::Sender<Result<(), String>>>,
    pending_exec_sends: &mut HashMap<PeerId, Vec<(ComputeExecRequest, oneshot::Sender<Result<ComputeExecResponse, String>>)>>,
    exec_in_flight:     &mut HashMap<OutboundRequestId, oneshot::Sender<Result<ComputeExecResponse, String>>>,
    exec_resp_tx:       &mpsc::Sender<(request_response::ResponseChannel<ComputeExecResponse>, ComputeExecResponse)>,
    swarm:              &mut libp2p::Swarm<EgoBehaviour>,
    relay_addrs:        &HashMap<PeerId, Multiaddr>,
    circuit_listener:   &mut Option<libp2p_core::transport::ListenerId>,
    pending_dials:      &mut HashMap<PeerId, Vec<oneshot::Sender<Result<PeerId, String>>>>,
) {
    match event {

        SwarmEvent::ListenerClosed { listener_id, reason, .. } => {
            let is_circuit = circuit_listener.as_ref()
                .map(|id| *id == listener_id)
                .unwrap_or(false);
            if is_circuit {
                tracing::warn!("Circuit listener closed ({:?}) — will re-register", reason);
                *circuit_listener = None;
                RELAY_CIRCUIT_READY.store(false, Ordering::Relaxed);
                external_addrs.retain(|a| !a.to_string().contains("/p2p-circuit"));
            }
        }

        SwarmEvent::NewListenAddr { address, .. } => {
            let addr_str = address.to_string();
            eprintln!("[P2P] Listening on {}", addr_str);

            if addr_str.contains("/p2p-circuit") {
                let peer_id = *swarm.local_peer_id();
                let pid_str = peer_id.to_string();

                let full: Multiaddr = if addr_str.contains(&pid_str) {
                    address.clone()
                } else {
                    format!("{}/p2p/{}", addr_str, pid_str)
                        .parse()
                        .unwrap_or(address.clone())
                };
                tracing::info!("Relay circuit LIVE (NewListenAddr): {}", full);
                inject_circuit(full, external_addrs, app, &peer_id);
            }
        }

        SwarmEvent::ConnectionEstablished { peer_id, endpoint: conn_endpoint, .. } => {
            eprintln!("[P2P] Connected to {}", peer_id);

            if let Some(waiters) = pending_dials.remove(&peer_id) {
                for w in waiters { let _ = w.send(Ok(peer_id)); }
            }

            if !relay_addrs.contains_key(&peer_id) {
                let n = DIRECT_PEER_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                if n == MIN_DIRECT_PEERS_RELAY_OPTIONAL {
                    tracing::info!("{} direct peers — relay no longer required for bootstrap", n);
                }
            }

            if let Some(relay_base) = relay_addrs.get(&peer_id) {
                let our_peer_id = *swarm.local_peer_id();
                let circuit_str = format!("{}/p2p/{}/p2p-circuit", relay_base, peer_id);
                let circuit_str_clone = circuit_str.clone();
                match circuit_str_clone.parse::<Multiaddr>() {
                    Ok(circuit_addr) => {

                        if circuit_listener.is_some() {
                            eprintln!("[P2P] Relay already reserved — skipping duplicate ConnectionEstablished for {}", peer_id);
                        } else {
                        eprintln!("[P2P] Reserving relay slot: {}", circuit_str);
                        match swarm.listen_on(circuit_addr) {
                            Ok(lid) => {
                                *circuit_listener = Some(lid);
                                eprintln!("[P2P] Relay reservation requested ✓");
                                if let Some(full_circuit) = build_circuit_addr(
                                    relay_base, &peer_id, &our_peer_id,
                                ) {
                                    inject_circuit(full_circuit, external_addrs, app, &our_peer_id);
                                }
                            }
                            Err(e) => tracing::error!("Relay listen error: {}", e),
                        }
                        }
                    }
                    Err(e) => eprintln!("[P2P] Bad circuit addr '{}': {}", circuit_str_clone, e),
                }
            }

            swarm.behaviour_mut().identify.push(std::iter::once(peer_id));

            if let Some(pending) = pending_sends.remove(&peer_id) {
                eprintln!("[P2P] Flushing {} queued message(s) to {} on connect", pending.len(), peer_id);
                for (msg, reply) in pending {
                    let req_id = swarm.behaviour_mut()
                        .request_response.send_request(&peer_id, msg);
                    in_flight.insert(req_id, reply);
                }
            }

            if let Some(pending) = pending_exec_sends.remove(&peer_id) {
                eprintln!("[P2P] Flushing {} queued exec request(s) to {} on connect", pending.len(), peer_id);
                for (req, reply) in pending {
                    let req_id = swarm.behaviour_mut()
                        .compute_exec.send_request(&peer_id, req);
                    exec_in_flight.insert(req_id, reply);
                }
            }

            // Pull any blocks we missed while this peer was unreachable.
            // 1-second delay lets gossip subscriptions exchange first.
            if !relay_addrs.contains_key(&peer_id) {
                tokio::spawn(async {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    sync_chain_from_peers().await;
                });
            }

            // Re-gossip our PeerAnnounce after a peer connects so the validator
            // committee forms reliably. A single publish is routinely lost: the
            // peer's topic subscription arrives just AFTER the connection is up,
            // and across NATs the only working link is the relay circuit, which
            // flaps (DCUtR hole-punching frequently fails). While we are still
            // below quorum, repeat the announce for ~20s so at least one publish
            // lands on a live, subscribed connection — this forms the committee
            // over gossip instead of the request-response path, which times out
            // over the relay. Once quorum exists, a single announce is enough, so
            // healthy/large networks don't pay the repeated-signing cost.
            let app_clone = app.cloned();
            tokio::spawn(async move {
                if known_validator_count() < crate::mempool::min_validators_for_finality() {
                    for _ in 0..7 {
                        broadcast_peer_announce(app_clone.as_ref()).await;
                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    }
                } else {
                    broadcast_peer_announce(app_clone.as_ref()).await;
                }
            });

            if !relay_addrs.contains_key(&peer_id) {
                let remote = conn_endpoint.get_remote_address().to_string();
                let direct_ep = if remote.contains("/p2p/") {
                    remote
                } else {
                    format!("{}/p2p/{}", remote, peer_id)
                };
                tokio::spawn(async move {
                    for _ in 0..3 {
                        send_direct_peer_announce(direct_ep.clone()).await;
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    }
                });
            }
        }

        SwarmEvent::ConnectionClosed { peer_id, num_established, .. } => {
            if !relay_addrs.contains_key(&peer_id) && num_established == 0 {
                let _ = DIRECT_PEER_COUNT.fetch_update(
                    Ordering::Relaxed, Ordering::Relaxed,
                    |v| Some(v.saturating_sub(1)),
                );
                if let Ok(peers_env) = std::env::var("EGO_DIRECT_PEERS") {
                    for addr_str in peers_env.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                        if let Ok(addr) = addr_str.parse::<Multiaddr>() {
                            eprintln!("[P2P] Direct peer {} disconnected — redialling {}", peer_id, addr_str);
                            let _ = swarm.dial(addr);
                        }
                    }
                }
            }
            if relay_addrs.contains_key(&peer_id) {
                tracing::info!("Relay {} connection closed ({} remaining)", peer_id, num_established);
                if num_established == 0 {
                    tracing::warn!("All relay connections gone — clearing circuit");
                    RELAY_CIRCUIT_READY.store(false, Ordering::Relaxed);
                    external_addrs.retain(|a| !a.to_string().contains("/p2p-circuit"));
                    if let Some(id) = circuit_listener.take() {
                        swarm.remove_listener(id);
                    }
                    if let Some(base_addr) = relay_addrs.get(&peer_id) {
                        let dial_str = format!("{}/p2p/{}", base_addr, peer_id);
                        if let Ok(ma) = dial_str.parse::<Multiaddr>() {
                            eprintln!("[P2P] Relay gone — immediate redial");
                            let _ = swarm.dial(ma);
                        }
                    }
                }
            }
            if let Some(pending) = pending_sends.remove(&peer_id) {
                for (_, reply) in pending {
                    let _ = reply.send(Err("Connection closed before send".into()));
                }
            }
            if let Some(pending) = pending_exec_sends.remove(&peer_id) {
                for (_, reply) in pending {
                    let _ = reply.send(Err("Connection closed before exec send".into()));
                }
            }
        }

        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            let err_str = error.to_string();
            let benign = err_str.contains("Missing relay peer id")
                || err_str.contains("multiaddresses is malformed")
                || err_str.contains("os error 10048")
                || err_str.contains("resource limit exceeded")
                || err_str.contains("Relay has no reservation")
                || err_str.contains("no reservation for destination");
            if !benign {
                tracing::debug!("[P2P] Dial error {:?}: {}", peer_id, error);
            }
            if let Some(pid) = peer_id {
                if err_str.contains("WrongPeerId") || err_str.contains("Unexpected peer") {
                    let pid_str = pid.to_string();
                    let mut peers = load_peer_cache();
                    let before = peers.len();
                    peers.retain(|p| !p.endpoint.contains(&pid_str));
                    if peers.len() < before {
                        save_peer_cache(&peers);
                        eprintln!("[P2P] Evicted stale peer cache entries for old peer ID {}", pid_str);
                    }
                }
                if let Some(pending) = pending_sends.remove(&pid) {
                    for (_, reply) in pending {
                        let _ = reply.send(Err(format!("Cannot reach peer: {}", error)));
                    }
                }
                if let Some(pending) = pending_exec_sends.remove(&pid) {
                    for (_, reply) in pending {
                        let _ = reply.send(Err(format!("Cannot reach peer for exec: {}", error)));
                    }
                }
                if let Some(waiters) = pending_dials.remove(&pid) {
                    for w in waiters {
                        let _ = w.send(Err(format!("Cannot reach peer: {}", error)));
                    }
                }
            }
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::Identify(
            identify::Event::Received { peer_id: remote_peer_id, info, .. },
        )) => {
            let observed = info.observed_addr.clone();
            swarm.add_external_address(observed.clone());
            if !external_addrs.contains(&observed) {
                external_addrs.push(observed.clone());
                eprintln!("[P2P] Observed external address: {}", observed);
            }
            if !RELAY_CIRCUIT_READY.load(Ordering::Relaxed) {
                let peer_id = *swarm.local_peer_id();
                crate::app::global_app_state().set_public_endpoint(best_endpoint(external_addrs, &peer_id));
                if let Some(h) = app {
                    let _ = h.emit_all("ego://p2p-status-changed", ());
                }
            }

            let pid_str = remote_peer_id.to_string();
            let best_ep: Option<String> = info.listen_addrs.iter()
                .filter(|a| {
                    let s = a.to_string();
                    !s.contains("/ip4/127.") && !s.contains("/ip4/169.254.")
                })
                .min_by_key(|a| {
                    let s = a.to_string();
                    if s.contains("/p2p-circuit") { 2usize }
                    else if s.starts_with("/ip4/192.168.") || s.starts_with("/ip4/10.") { 0 }
                    else { 1 }
                })
                .map(|a| {
                    let s = a.to_string();
                    if s.contains("/p2p/") { s } else { format!("{}/p2p/{}", s, pid_str) }
                })
                .or_else(|| {
                    info.listen_addrs.iter()
                        .filter(|a| !a.to_string().contains("/ip4/169.254."))
                        .next()
                        .map(|a| {
                            let s = a.to_string();
                            if s.contains("/p2p/") { s } else { format!("{}/p2p/{}", s, pid_str) }
                        })
                });
            if let Some(ep) = best_ep {
                upsert_peer_cache(PeerEntry {
                    address:   pid_str.clone(),
                    endpoint:  ep,
                    last_seen: chrono::Utc::now().timestamp(),
                    city:      None,
                    country:   None,
                    lat:       None,
                    lon:       None,
                });
            }
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::RelayClient(
            relay::client::Event::ReservationReqAccepted { relay_peer_id, .. },
        )) => {
            tracing::info!("Relay reservation ACCEPTED via {}", relay_peer_id);
            let our_peer_id = *swarm.local_peer_id();
            if let Some(relay_base) = relay_addrs.get(&relay_peer_id) {
                if let Some(circuit) = build_circuit_addr(relay_base, &relay_peer_id, &our_peer_id) {
                    inject_circuit(circuit, external_addrs, app, &our_peer_id);
                }
            }

            for (peer_id, pending) in pending_sends.drain() {
                eprintln!("[P2P] Flushing {} queued messages to {} after reservation", pending.len(), peer_id);
                for (msg, reply) in pending {
                    let req_id = swarm.behaviour_mut()
                        .request_response.send_request(&peer_id, msg);
                    in_flight.insert(req_id, reply);
                }
            }
            for (peer_id, pending) in pending_exec_sends.drain() {
                for (req, reply) in pending {
                    let req_id = swarm.behaviour_mut()
                        .compute_exec.send_request(&peer_id, req);
                    exec_in_flight.insert(req_id, reply);
                }
            }
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::RelayClient(event)) => {
            eprintln!("[P2P] Relay client event: {:?}", event);
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::RelayServer(
            relay::Event::ReservationReqAccepted { src_peer_id, .. }
        )) => {
            eprintln!("[Relay] Serving reservation for peer {}", src_peer_id);
        }
        SwarmEvent::Behaviour(EgoBehaviourEvent::RelayServer(
            relay::Event::CircuitReqAccepted { src_peer_id, dst_peer_id, .. }
        )) => {
            eprintln!("[Relay] Relaying circuit: {} → {}", src_peer_id, dst_peer_id);
        }
        SwarmEvent::Behaviour(EgoBehaviourEvent::RelayServer(_)) => {}

        // Zero-config LAN discovery: dial every peer mDNS finds on the local
        // network directly. This is how two machines on the same network form a
        // committee without depending on the public relay (which flaps across
        // NATs and dies under Windows port exhaustion). Direct LAN links are
        // stable, so BFT vote rounds actually complete.
        SwarmEvent::Behaviour(EgoBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
            for (peer, addr) in list {
                if peer == *swarm.local_peer_id() { continue; }
                if swarm.is_connected(&peer) { continue; }
                eprintln!("[mDNS] Discovered LAN peer {} at {} — dialling directly", peer, addr);
                let dial_addr = addr.clone().with_p2p(peer).unwrap_or(addr);
                let _ = swarm.dial(dial_addr);
            }
        }
        SwarmEvent::Behaviour(EgoBehaviourEvent::Mdns(mdns::Event::Expired(_))) => {}

        // UPnP: the router opened a port for us, so we're now directly reachable
        // from the internet — advertise the public address and stop routing new
        // peers through the relay. No firewall rule, no admin, on any OS.
        SwarmEvent::Behaviour(EgoBehaviourEvent::Upnp(upnp::Event::NewExternalAddr(addr))) => {
            eprintln!("[UPnP] Router mapped a public address: {} — node is now directly reachable", addr);
            IS_PUBLIC_REACHABLE.store(true, Ordering::Relaxed);
            if !external_addrs.contains(&addr) {
                external_addrs.push(addr.clone());
            }
            let peer_id = *swarm.local_peer_id();
            crate::app::global_app_state().set_public_endpoint(best_endpoint(external_addrs, &peer_id));
            if let Some(h) = app {
                let _ = h.emit_all("ego://p2p-status-changed", ());
            }
        }
        SwarmEvent::Behaviour(EgoBehaviourEvent::Upnp(upnp::Event::ExpiredExternalAddr(addr))) => {
            external_addrs.retain(|a| a != &addr);
        }
        SwarmEvent::Behaviour(EgoBehaviourEvent::Upnp(upnp::Event::GatewayNotFound)) => {
            tracing::debug!("[UPnP] No UPnP-capable router found — relying on relay + hole-punching");
        }
        SwarmEvent::Behaviour(EgoBehaviourEvent::Upnp(upnp::Event::NonRoutableGateway)) => {
            tracing::debug!("[UPnP] Router is not internet-routable — relying on relay + hole-punching");
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::Autonat(
            autonat::Event::StatusChanged { new, .. },
        )) => {
            let state = crate::app::global_app_state();
            match new {
                autonat::NatStatus::Public(addr) => {
                    eprintln!("[P2P] AutoNAT: public at {} — advertising DIRECT address so peers don't route through the relay", addr);
                    state.set_upnp_status(Ok(()));
                    IS_PUBLIC_REACHABLE.store(true, Ordering::Relaxed);
                    if !external_addrs.contains(&addr) {
                        external_addrs.push(addr.clone());
                    }
                    // Re-advertise our endpoint as the DIRECT address (even if the relay
                    // circuit is up) so peers connect to us directly — this offloads the relay.
                    {
                        let peer_id = *swarm.local_peer_id();
                        state.set_public_endpoint(best_endpoint(external_addrs, &peer_id));
                        if let Some(h) = app {
                            let _ = h.emit_all("ego://p2p-status-changed", ());
                        }
                    }

                    let peer_id = *swarm.local_peer_id();
                    let relay_ma = format!("{}/p2p/{}", addr, peer_id);
                    let dht_key  = format!("ego-relay:{}", hex::encode(blake3::hash(peer_id.to_bytes().as_ref()).as_bytes()));
                    let value    = relay_ma.as_bytes().to_vec();
                    save_dht_record_to_cache(&dht_key, &value);
                    if let Some(tx) = DHT_CMD_TX.get() {
                        let _ = tx.send(DhtCommand::PutPeer { key: dht_key, value });
                    }
                    eprintln!("[Relay] Advertised as community relay: {}", relay_ma);
                }
                autonat::NatStatus::Private => {
                    eprintln!("[P2P] AutoNAT: behind NAT — relay required");
                    IS_PUBLIC_REACHABLE.store(false, Ordering::Relaxed);
                    state.set_upnp_status(Err("Behind NAT — using relay".into()));
                    if let Some(h) = app {
                        let _ = h.emit_all("ego://p2p-status-changed", ());
                    }
                }
                autonat::NatStatus::Unknown => {}
            }
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::RequestResponse(
            request_response::Event::Message {
                message: request_response::Message::Request { request, channel, .. }, ..
            },
        )) => {
            let _ = swarm.behaviour_mut().request_response.send_response(channel, ());
            let app2 = app.cloned();
            tokio::spawn(async move { handle_incoming(request, app2.as_ref()).await; });
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::RequestResponse(
            request_response::Event::Message {
                message: request_response::Message::Response { request_id, .. }, ..
            },
        )) => {
            if let Some(reply) = in_flight.remove(&request_id) {
                let _ = reply.send(Ok(()));
            }
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::RequestResponse(
            request_response::Event::OutboundFailure { request_id, error, .. },
        )) => {
            if let Some(reply) = in_flight.remove(&request_id) {
                let _ = reply.send(Err(format!("Network error: {}", error)));
            }
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::ComputeExec(
            request_response::Event::Message {
                message: request_response::Message::Request { request, channel, .. }, ..
            },
        )) => {
            let tx = exec_resp_tx.clone();
            tokio::spawn(async move {
                let resp = serve_compute_exec(request).await;
                let _ = tx.send((channel, resp)).await;
            });
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::ComputeExec(
            request_response::Event::Message {
                message: request_response::Message::Response { request_id, response, .. }, ..
            },
        )) => {
            if let Some(reply) = exec_in_flight.remove(&request_id) {
                let _ = reply.send(Ok(response));
            }
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::ComputeExec(
            request_response::Event::OutboundFailure { request_id, error, .. },
        )) => {
            if let Some(reply) = exec_in_flight.remove(&request_id) {
                let _ = reply.send(Err(format!("Network error: {}", error)));
            }
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::ComputeExec(_)) => {}

        SwarmEvent::Behaviour(EgoBehaviourEvent::Dcutr(event)) => {
            eprintln!("[P2P] DCUtR: {:?}", event);
        }

        // Ping-based dead-connection detection. libp2p keeps a connection "open" long after
        // the underlying socket dies (e.g. a LAN/WiFi change) — the idle timeout is 24h and a
        // relay reservation keeps a stream active, so ConnectionClosed never fires on its own
        // and the redial logic below never runs → the chain stalls with peers it can't reach.
        // When ping fails (no response within the 20s timeout), the connection is dead: close
        // it so ConnectionClosed fires and the relay/peer redial re-establishes connectivity.
        SwarmEvent::Behaviour(EgoBehaviourEvent::Ping(ping::Event { peer, connection, result })) => {
            if result.is_err() {
                eprintln!("[P2P] Ping failed to {} — closing dead connection to force redial", peer);
                swarm.close_connection(connection);
            }
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::Gossipsub(
            gossipsub::Event::Message { propagation_source, message, .. },
        )) => {
            // ── Per-peer rate limit + ban check (DDoS protection) ─────────────
            // Drop messages from peers that exceed MAX_MSGS_PER_SEC or are banned.
            let peer_id_str = propagation_source.to_string();
            if is_peer_banned(&peer_id_str) {
                return; // banned for sending too many invalid blocks
            }
            if !check_peer_rate(&peer_id_str) {
                return;
            }
            let topic = message.topic.to_string();
            if topic == V2_TOPIC {
                // Consensus-v2 messages → handle_incoming. The BftV2* arms feed the live
                // engine that drives the chain by default (inline only with LEGACY=1).
                if let Ok(msg) = serde_json::from_slice::<P2PMessage>(&message.data) {
                    let app2 = app.cloned();
                    tokio::spawn(async move { handle_incoming(msg, app2.as_ref()).await; });
                }
            } else if topic == DM_TOPIC {
                // Sealed messenger envelope. Every node forwards these; only the
                // addressee holds the key that opens one, so everyone else drops
                // it after a string compare — no crypto on other people's mail.
                if let Ok(P2PMessage::SealedDm { to, eph_pub, nonce, ct, id }) =
                    serde_json::from_slice::<P2PMessage>(&message.data)
                {
                    let app2 = app.cloned();
                    tokio::spawn(async move {
                        let my_addr = tokio::task::spawn_blocking(|| crate::ledger::Ledger::load().address)
                            .await.unwrap_or_default();
                        if my_addr.is_empty() || to != my_addr {
                            return;
                        }
                        if dm_already_seen(&id) {
                            return;
                        }
                        let Some(inner) = open_dm(&eph_pub, &nonce, &ct) else {
                            eprintln!("[DM] Sealed envelope addressed to us could not be opened");
                            return;
                        };
                        eprintln!("[DM] Sealed envelope opened from gossip — delivering");
                        handle_incoming(inner, app2.as_ref()).await;
                    });
                }
            } else if topic == "ego-txs-v1" {

                match serde_json::from_slice::<P2PMessage>(&message.data) {
                    Ok(P2PMessage::TxBroadcast { tx, block }) => {
                        let app2 = app.cloned();
                        tokio::spawn(async move { apply_incoming_tx(tx, block, app2.as_ref()).await; });
                    }
                    _ => {}
                }
            } else if topic == "ego-blocks-v1" {
                match serde_json::from_slice::<P2PMessage>(&message.data) {
                    Ok(P2PMessage::ChainSyncResponse { blocks, transactions }) => {
                        let app2 = app.cloned();
                        tokio::spawn(async move { merge_remote_chain(blocks, transactions, app2.as_ref()).await; });
                    }
                    Ok(P2PMessage::BlockFinalized { mut block, transactions, votes, agg_bls_sig, bls_pubkeys }) => {
                        let block_hash = block.hash.clone();
                        let height     = block.height;
                        let app2 = app.cloned();
                        let source_pid = propagation_source.to_string();
                        // If the producer's block arrived without a QC, build one from the
                        // vote signatures this node collected and attach it before the first
                        // persist — write_block_batch is idempotent on hash, so a block can
                        // only acquire its certificate on first write. Must run before
                        // process_inbound_qc_finalization, which clears pending_bls_sigs.
                        attach_local_qc_if_missing(&mut block);
                        tokio::spawn(async move {
                            let local_tip = tokio::task::spawn_blocking(|| crate::chain_db::latest_block_info().0).await.unwrap_or(0);
                            if height > local_tip + 1 {
                                static LAST_GAP_REQ: AtomicI64 = AtomicI64::new(0);
                                let now = Utc::now().timestamp_millis();
                                if now - LAST_GAP_REQ.load(Ordering::Relaxed) > 2000 {
                                    LAST_GAP_REQ.store(now, Ordering::Relaxed);
                                    if height > local_tip + crate::chain_db::SNAPSHOT_BLOCK_WINDOW as u64 {
                                        request_snapshot_from_peers(local_tip).await;
                                    } else {
                                        request_gap_backfill(local_tip, &source_pid).await;
                                    }
                                }
                            }
                            if process_inbound_qc_finalization(&block_hash, height, &votes, &agg_bls_sig, &bls_pubkeys) {
                                merge_remote_chain_trusted(vec![block], transactions, app2.as_ref()).await;
                            }
                        });
                    }
                    Ok(P2PMessage::EquivocationProof { accused, height, hash_a, sig_a, hash_b, sig_b, reporter }) => {
                        if !slashed_validators().contains(&accused) {
                            let vote_data_a = crate::bft_committee::vote_signing_data(&hash_a, height, &accused);
                            let vote_data_b = crate::bft_committee::vote_signing_data(&hash_b, height, &accused);
                            let sig_a_valid = !sig_a.is_empty() && verify_bft_sig(&accused, &vote_data_a, &sig_a);
                            let sig_b_valid = !sig_b.is_empty() && verify_bft_sig(&accused, &vote_data_b, &sig_b);
                            if sig_a_valid && sig_b_valid && hash_a != hash_b {
                    tracing::warn!("Peer {} reported equivocation by {} — broadcasting proof TX to mempool", reporter, accused);
                    tokio::spawn(async move {
                        broadcast_equivocation_tx(accused, height, hash_a, sig_a, hash_b, sig_b).await;
                    });
                            }
                        }
                    }
                    _ => {}
                }
            } else if topic == "ego-proposals-v1" {
                if let Ok(P2PMessage::BlockProposal { block, transactions, proposer, signature, vrf_ticket, view, proposer_pubkey }) =
                    serde_json::from_slice::<P2PMessage>(&message.data)
                {
                    learn_voter_pubkey(&proposer, &proposer_pubkey);
                    note_network_height(block.height);
                    // Only count validators building on our chain.
                    // A stranger on a different fork has a prev_hash we don't know.
                    let our_tip = crate::chain_db::latest_block_info().0;
                    let prev_known = block.height <= 1
                        || block.height == our_tip + 1
                        || crate::chain_db::get_block_hash_at(block.height.saturating_sub(1))
                            .map(|h| h == block.prev_hash)
                            .unwrap_or(false);
                    if prev_known { register_known_validator(&proposer); }
                    let app2 = app.cloned();
                    tokio::spawn(async move {
                        handle_block_proposal(block, transactions, proposer, signature, vrf_ticket, view, app2.as_ref()).await;
                    });
                }
            } else if topic == "ego-votes-v1" {
                if let Ok(P2PMessage::BlockVote { block_hash, height, voter, signature, timestamp, vrf_ticket, prev_hash, bls_sig, bls_pubkey, voter_pubkey }) =
                    serde_json::from_slice::<P2PMessage>(&message.data)
                {
                    // Learn the voter's key directly from the vote (verified to derive
                    // their address) so signature verification doesn't depend on the
                    // announce having arrived first.
                    learn_voter_pubkey(&voter, &voter_pubkey);
                    note_network_height(height);
                    // Only register voter if they're voting on a block on our chain.
                    let our_height = crate::chain_db::latest_block_info().0;
                    let vote_on_our_chain = height == our_height + 1
                        || crate::chain_db::get_block_hash_at(height.saturating_sub(1))
                            .map(|h| h == prev_hash)
                            .unwrap_or(false);
                    if vote_on_our_chain { register_known_validator(&voter); }
                    let app2 = app.cloned();
                        tokio::spawn(async move {
                            handle_block_vote(block_hash, height, voter, signature, timestamp, vrf_ticket, prev_hash, bls_sig, bls_pubkey, app2).await;
                    });
                }
            } else if topic == "ego-sync-v1" {
                if let Ok(P2PMessage::ChainSyncRequest { requester_endpoint, from_height }) =
                    serde_json::from_slice::<P2PMessage>(&message.data)
                {
                    if !requester_endpoint.is_empty() && sync_reply_allowed(&requester_endpoint) {
                        let ep = requester_endpoint.clone();
                        tokio::spawn(async move {
                            let (blocks, transactions) = tokio::task::spawn_blocking(move || {
                                if crate::chain_db::block_count() == 0 { return (vec![], vec![]); }
                                let start = from_height.max(1);
                                let blocks = crate::chain_db::get_blocks_range(start, 500);
                                let transactions: Vec<crate::ledger::LedgerTx> = blocks.iter()
                                    .flat_map(|b| crate::chain_db::get_txs_for_block(b.height))
                                    .collect();
                                (blocks, transactions)
                            }).await.unwrap_or_default();
                            if blocks.is_empty() { return; }
                            tracing::info!("sync-v1: sending {} blocks ({} txs) from height {} to {}",
                                blocks.len(), transactions.len(), from_height.max(1),
                                blocks.last().map(|b| b.height).unwrap_or(from_height));
                            let response = P2PMessage::ChainSyncResponse { blocks, transactions };

                            // Send response via gossip to bypass NAT dial-back issues
                            if let Ok(data) = serde_json::to_vec(&response) {
                                publish_gossip("ego-blocks-v1", data).await;
                            }
                        });
                    }
                }
            } else if topic == "ego-snapshot-v1" {
                if let Ok(P2PMessage::SnapshotRequest { requester_endpoint, have_height }) =
                    serde_json::from_slice::<P2PMessage>(&message.data)
                {
                    let local_tip = crate::chain_db::latest_block_info().0;
                    if local_tip > have_height + SNAPSHOT_SERVE_MIN_LAG
                        && !requester_endpoint.is_empty()
                        && sync_reply_allowed(&requester_endpoint)
                    {
                        tokio::spawn(async move {
                            let snap = match tokio::task::spawn_blocking(crate::chain_db::export_state_snapshot).await {
                                Ok(s) => s,
                                Err(_) => return,
                            };
                            if snap.height <= have_height { return; }
                            let resp = P2PMessage::SnapshotResponse { snapshot: snap };
                            let _ = send_message(&requester_endpoint, &resp).await;
                        });
                    }
                }
            } else if topic == "ego-price-v1" {

                if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&message.data) {
                    if let Some(price) = json["price"].as_f64() {
                        let stake = json["stake_weight_uegoc"].as_u64().unwrap_or(0);
                        record_gossip_price(price, stake);
                    }
                }
            } else if topic == "ego-storage-v1" {
                match serde_json::from_slice::<P2PMessage>(&message.data) {
                    Ok(P2PMessage::StorageCommit { prover_addr, cid, comm_r, signature, .. }) => {
                        if !prover_addr.is_empty() && !cid.is_empty() && !comm_r.is_empty() {
                            record_peer_commitment(&cid, &prover_addr, &comm_r, &signature);
                        }
                    }
                    // PoRep challenges/responses and replica liveness acks are
                    // published on this topic — route them to their handlers
                    // (previously only StorageCommit was parsed here, so gossiped
                    // proofs never reached handle_incoming).
                    Ok(msg @ P2PMessage::StorageProofChallenge { .. })
                    | Ok(msg @ P2PMessage::StorageProofResponse { .. })
                    | Ok(msg @ P2PMessage::ReplicaHeartbeatAck { .. }) => {
                        let app2 = app.cloned();
                        tokio::spawn(async move { handle_incoming(msg, app2.as_ref()).await; });
                    }
                    _ => {}
                }
            } else if topic == "ego-viewchange-v1" {

                if let Ok(P2PMessage::ViewChange { view, voter, signature, timestamp: _ }) =
                    serde_json::from_slice::<P2PMessage>(&message.data)
                {

                    if !slashed_validators().contains(&voter) {
                        let app2 = app.cloned();
                        tokio::spawn(async move {
                            let vote_data = format!("viewchange:{}:{}", view, voter);
                            let is_valid = match get_peer_ed25519_pubkey(&voter) {
                                Some(pk) => {
                                    use ed25519_dalek::{Signature as DS, VerifyingKey, Verifier};
                                    if let (Ok(vk), Ok(sig_bytes)) = (VerifyingKey::from_bytes(&pk), hex::decode(&signature)) {
                                        if let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes.as_slice()) {
                                            vk.verify(vote_data.as_bytes(), &DS::from_bytes(&sig_arr)).is_ok()
                                        } else { false }
                                    } else { false }
                                },
                                None => known_validators().contains(&voter),
                            };
                            if is_valid {
                                handle_view_change_msg(view, voter).await;
                                if let Some(ref h) = app2 {
                                    let _ = h.emit_all("ego://view-changed", serde_json::json!({ "view": view }));
                                }
                            } else {
                                tracing::debug!("[BFT] Invalid ViewChange signature from {}", voter);
                            }
                        });
                    }
                }
            } else if topic == "ego-peers-v1" {

                match serde_json::from_slice::<P2PMessage>(&message.data) {
                    Ok(msg @ P2PMessage::PeerAnnounce { .. }) => {
                        let app2 = app.cloned();
                        tokio::spawn(async move { handle_incoming(msg, app2.as_ref()).await; });
                    }
                    Ok(P2PMessage::ValidatorLeaving { address, timestamp, signature }) => {
                        handle_validator_leaving(&address, timestamp, &signature);
                    }
                    Ok(P2PMessage::PeerSeedGossip { multiaddrs, known_count }) => {

                        let msg_n = PEER_SEED_MSG_COUNT
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                        let reset = msg_n % SEED_VOTE_WINDOW == 0;
                        let window_pos = if reset { SEED_VOTE_WINDOW } else { msg_n % SEED_VOTE_WINDOW };
                        let majority = ((window_pos as f32) * 0.5).ceil() as u32;

                        let mut to_dial: Vec<String> = Vec::new();
                        {
                            let mut votes = PEER_SEED_VOTES
                                .get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
                                .lock().unwrap();
                            if reset { votes.clear(); }
                            for addr in &multiaddrs {
                                let cnt = votes.entry(addr.clone()).or_insert(0);
                                *cnt += 1;

                                if *cnt >= majority && majority >= 2 {
                                    to_dial.push(addr.clone());
                                }
                            }
                        }

                        let known: std::collections::HashSet<String> =
                            load_peer_cache().into_iter().map(|p| p.endpoint).collect();
                        for addr_str in to_dial {
                            if !known.contains(&addr_str) {
                                if let Some(tx) = DHT_CMD_TX.get() {
                                    let _ = tx.send(DhtCommand::DialPeer { addr: addr_str });
                                }
                            }
                        }
                        if known_count >= 100 {

                            static MATURITY_LOGGED: AtomicBool = AtomicBool::new(false);
                            if !MATURITY_LOGGED.swap(true, Ordering::Relaxed) {
                                tracing::info!("Network maturity reached ({} known peers) — relay is fully optional", known_count);
                            }
                        }
                    }
                    _ => {}
                }
            } else if topic == "ego-hosting-v1" {
                if let Ok(P2PMessage::HostingAnnounce { record }) =
                    serde_json::from_slice::<P2PMessage>(&message.data)
                {
                    let r2 = record.clone();
                    tokio::spawn(async move {
                        tokio::task::spawn_blocking(move || crate::chain_db::upsert_hosting_node(&r2)).await.ok();
                    });
                    tokio::spawn(async move {
                        let client = reqwest::Client::builder()
                            .timeout(std::time::Duration::from_secs(5))
                            .build()
                            .unwrap_or_default();
                        for oracle in ORACLE_RPCS {
                            let url = format!("{}/hosting/announce", oracle);
                            let _ = client.post(&url).json(&record).send().await;
                        }
                    });
                }
            } else if topic == "ego-compute-v1" {
                match serde_json::from_slice::<P2PMessage>(&message.data) {
                    Ok(P2PMessage::ComputeAnnounce { node }) => {
                        tokio::spawn(async move {
                            let n = node.clone();
                            tokio::task::spawn_blocking(move || crate::chain_db::upsert_compute_node(&n)).await.ok();
                            if !node.endpoint.is_empty() {
                                upsert_peer_cache(PeerEntry {
                                    address: node.address.clone(),
                                    endpoint: node.endpoint.clone(),
                                    last_seen: chrono::Utc::now().timestamp(),
                                    city: None,
                                    country: None,
                                    lat: None,
                                    lon: None,
                                });
                            }
                        });
                    }
                    Ok(P2PMessage::ComputeJobPost { job }) => {
                        tokio::spawn(async move {
                            tokio::task::spawn_blocking(move || crate::chain_db::upsert_compute_job(&job)).await.ok();
                        });
                    }
                    Ok(P2PMessage::ComputeJobAccept { job_id, worker_address, .. }) => {
                        tokio::spawn(async move {
                            tokio::task::spawn_blocking(move || {
                                if let Some(mut job) = crate::chain_db::get_compute_job(&job_id) {
                                    if job.status == "posted"
                                        && !worker_address.is_empty()
                                        && job.worker_address.is_empty()
                                    {
                                        job.status         = "accepted".to_string();
                                        job.worker_address = worker_address;
                                        job.accepted_at    = Some(chrono::Utc::now().timestamp());
                                        crate::chain_db::upsert_compute_job(&job);
                                    }
                                }
                            }).await.ok();
                        });
                    }
                    Ok(P2PMessage::ComputeJobComplete { job_id, output_cid, .. }) => {
                        tokio::spawn(async move {
                            tokio::task::spawn_blocking(move || {
                                if let Some(mut job) = crate::chain_db::get_compute_job(&job_id) {
                                    if (job.status == "accepted" || job.status == "running")
                                        && !job.worker_address.is_empty()
                                    {
                                        job.status       = "completed".to_string();
                                        job.output_cid   = output_cid;
                                        job.completed_at = Some(chrono::Utc::now().timestamp());
                                        crate::chain_db::upsert_compute_job(&job);
                                    }
                                }
                            }).await.ok();
                        });
                    }
                    Ok(P2PMessage::ComputeJobCancel { job_id, .. }) => {
                        tokio::spawn(async move {
                            tokio::task::spawn_blocking(move || {
                                if let Some(mut job) = crate::chain_db::get_compute_job(&job_id) {
                                    if job.status == "posted" {
                                        job.status = "cancelled".to_string();
                                        crate::chain_db::upsert_compute_job(&job);
                                    }
                                }
                            }).await.ok();
                        });
                    }
                    Ok(P2PMessage::ComputeHeartbeat { job_id, worker, timestamp }) => {
                        tokio::spawn(async move {
                            tokio::task::spawn_blocking(move || {
                                if let Some(mut job) = crate::chain_db::get_compute_job(&job_id) {
                                    if job.worker_address == worker && job.status == "accepted" {
                                        job.status = "running".to_string();
                                        job.accepted_at = Some(timestamp);
                                        crate::chain_db::upsert_compute_job(&job);
                                    }
                                }
                            }).await.ok();
                        });
                    }
                    Ok(P2PMessage::CapacityOfferBroadcast { offer }) => {
                        tokio::spawn(async move {
                            tokio::task::spawn_blocking(move || crate::chain_db::upsert_compute_offer(&offer)).await.ok();
                        });
                    }
                    Ok(P2PMessage::CapacityOfferCancelled { offer_id }) => {
                        tokio::spawn(async move {
                            tokio::task::spawn_blocking(move || {
                                if let Some(mut offer) = crate::chain_db::get_compute_offer(&offer_id) {
                                    if offer.status == "open" {
                                        offer.status = "cancelled".to_string();
                                        crate::chain_db::upsert_compute_offer(&offer);
                                    }
                                }
                            }).await.ok();
                        });
                    }
                    Ok(P2PMessage::ClusterBookingCreated { booking }) => {
                        let app2 = app.cloned();
                        tokio::spawn(async move {
                            let cluster_id = booking.cluster_id.clone();
                            let is_new = tokio::task::spawn_blocking(move || {
                                if crate::chain_db::get_cluster_booking(&booking.cluster_id).is_none() {
                                    crate::chain_db::upsert_cluster_booking(&booking);
                                    true
                                } else {
                                    false
                                }
                            }).await.unwrap_or(false);
                            if is_new {
                                if let Some(h) = app2 {
                                    crate::commands::cluster::auto_join_cluster(cluster_id, h).await;
                                }
                            }
                        });
                    }
                    Ok(P2PMessage::ClusterNodeJoined { cluster_id, provider_address, wg_pubkey, endpoint }) => {
                        tokio::spawn(async move {
                            tokio::task::spawn_blocking(move || {
                                if let Some(mut b) = crate::chain_db::get_cluster_booking(&cluster_id) {
                                    let now = chrono::Utc::now().timestamp();
                                    for node in b.nodes.iter_mut() {
                                        if node.provider_address == provider_address
                                            && node.wg_pubkey.is_empty()
                                        {
                                            node.wg_pubkey         = wg_pubkey.clone();
                                            node.endpoint          = endpoint.clone();
                                            node.status            = "active".to_string();
                                            node.joined_at         = now;
                                            node.last_heartbeat_at = now;
                                            break;
                                        }
                                    }
                                    let all_active = b.nodes.iter().all(|n| n.status == "active");
                                    if all_active { b.status = "active".to_string(); }
                                    crate::chain_db::upsert_cluster_booking(&b);
                                }
                            }).await.ok();
                        });
                    }
                    Ok(P2PMessage::ClusterNodeHeartbeat { cluster_id, provider_address, .. }) => {
                        tokio::spawn(async move {
                            tokio::task::spawn_blocking(move || {
                                if let Some(mut b) = crate::chain_db::get_cluster_booking(&cluster_id) {
                                    let now = chrono::Utc::now().timestamp();
                                    for node in b.nodes.iter_mut() {
                                        if node.provider_address == provider_address {
                                            node.last_heartbeat_at = now;
                                            node.status = "active".to_string();
                                            break;
                                        }
                                    }
                                    crate::chain_db::upsert_cluster_booking(&b);
                                }
                            }).await.ok();
                        });
                    }
                    Ok(P2PMessage::ClusterTerminated { cluster_id }) => {
                        tokio::spawn(async move {
                            tokio::task::spawn_blocking(move || {
                                if let Some(mut b) = crate::chain_db::get_cluster_booking(&cluster_id) {
                                    b.status = "terminated".to_string();
                                    crate::chain_db::upsert_cluster_booking(&b);
                                }
                            }).await.ok();
                        });
                    }
                    Ok(P2PMessage::ReservationBooked { reservation, ssh_public_key }) => {
                        let my_addr = crate::ledger::Ledger::load().address;
                        // Robust comparison supporting hex (0x) vs bech32 (egot1)
                        let is_for_me = if reservation.provider_address == my_addr {
                            true
                        } else {
                            let my_hex = ego_core::EgoAddress::from_bech32(&my_addr, "egot").map(|a| hex::encode(a.as_bytes())).unwrap_or_default();
                            reservation.provider_address.to_lowercase().trim_start_matches("0x") == my_hex
                        };
                        let key_to_auth = ssh_public_key.clone();

                        tokio::spawn(async move {
                            if is_for_me {
                                if let Some(key) = key_to_auth {
                                    let _ = crate::commands::compute::authorize_ssh_key(&key);
                                }
                                // Pre-build the isolated sandbox so the renter's
                                // first console command doesn't wait on an image pull.
                                let res_warm = reservation.clone();
                                tokio::task::spawn_blocking(move || {
                                    if res_warm.status == "active" {
                                        crate::sandbox::prewarm_image();
                                        let _ = crate::sandbox::ensure_container(&res_warm);
                                    }
                                }).await.ok();
                            }
                            tokio::task::spawn_blocking(move || {
                                if crate::chain_db::get_compute_reservation(&reservation.reservation_id).is_none() {
                                    crate::chain_db::upsert_compute_reservation(&reservation);
                                }
                            }).await.ok();
                        });
                    }
                    Ok(P2PMessage::ReservationHeartbeat { reservation_id, provider, .. }) => {
                        tokio::spawn(async move {
                            tokio::task::spawn_blocking(move || {
                                if let Some(mut res) = crate::chain_db::get_compute_reservation(&reservation_id) {
                                    if res.provider_address == provider && res.status == "active" {
                                        res.last_heartbeat_at = chrono::Utc::now().timestamp();
                                        crate::chain_db::upsert_compute_reservation(&res);
                                    }
                                }
                            }).await.ok();
                        });
                    }
                    Ok(P2PMessage::ReservationTerminated { reservation_id, by, reason }) => {
                        let app2 = app.cloned();
                        tokio::spawn(async move {
                            // Determine our perspective (buyer / provider / other)
                            // so the frontend can phrase the toast correctly,
                            // then update local chain state.
                            let res_id_for_blocking = reservation_id.clone();
                            let res = tokio::task::spawn_blocking(move || {
                                let r = crate::chain_db::get_compute_reservation(&res_id_for_blocking);
                                if let Some(ref existing) = r {
                                    let mut updated = existing.clone();
                                    updated.status = "terminated".to_string();
                                    crate::chain_db::upsert_compute_reservation(&updated);
                                }
                                r
                            }).await.ok().flatten();

                            // Tear down the isolated sandbox + its workspace volume.
                            // No-op if Docker is absent or no container exists.
                            let rid = reservation_id.clone();
                            tokio::task::spawn_blocking(move || crate::sandbox::destroy(&rid)).await.ok();

                            if let Some(handle) = app2 {
                                let perspective = res.as_ref().map(|r| {
                                    let me = crate::ledger::Ledger::load().address;
                                    if r.buyer_address == me { "buyer" }
                                    else if r.provider_address == me { "provider" }
                                    else { "observer" }
                                }).unwrap_or("observer");

                                let _ = handle.emit_all("ego://reservation-terminated", serde_json::json!({
                                    "reservation_id": reservation_id,
                                    "by":             by,
                                    "reason":         reason,
                                    "perspective":    perspective,
                                }));
                            }
                        });
                    }
                    Ok(P2PMessage::StorageDealCreated { deal }) => {
                        tokio::spawn(async move {
                            tokio::task::spawn_blocking(move || crate::chain_db::upsert_storage_deal(&deal)).await.ok();
                        });
                    }
                    Ok(P2PMessage::StorageDealProof { deal_id, provider, timestamp }) => {
                        tokio::spawn(async move {
                            tokio::task::spawn_blocking(move || {
                                if let Some(mut deal) = crate::chain_db::get_storage_deal(&deal_id) {
                                    if deal.provider_address == provider && deal.status == "active" {
                                        deal.last_proof_at = timestamp;
                                        crate::chain_db::upsert_storage_deal(&deal);
                                    }
                                }
                            }).await.ok();
                        });
                    }
                    Ok(P2PMessage::StorageDealTerminated { deal_id, .. }) => {
                        tokio::spawn(async move {
                            tokio::task::spawn_blocking(move || {
                                if let Some(mut deal) = crate::chain_db::get_storage_deal(&deal_id) {
                                    deal.status = "terminated".to_string();
                                    crate::chain_db::upsert_storage_deal(&deal);
                                }
                            }).await.ok();
                        });
                    }
                    Ok(P2PMessage::EquivocationProof { accused, height, hash_a, sig_a, hash_b, sig_b, reporter }) => {
                        if !slashed_validators().contains(&accused) {
                        let vote_data_a = crate::bft_committee::vote_signing_data(&hash_a, height, &accused);
                        let vote_data_b = crate::bft_committee::vote_signing_data(&hash_b, height, &accused);
                        let sig_a_valid = !sig_a.is_empty() && verify_bft_sig(&accused, &vote_data_a, &sig_a);
                        let sig_b_valid = !sig_b.is_empty() && verify_bft_sig(&accused, &vote_data_b, &sig_b);
                        if sig_a_valid && sig_b_valid && hash_a != hash_b {
                    tracing::warn!("Peer {} reported equivocation by {} — broadcasting proof TX to mempool", reporter, accused);
                    tokio::spawn(async move {
                        broadcast_equivocation_tx(accused, height, hash_a, sig_a, hash_b, sig_b).await;
                    });
                        }
                    }
                    }
                    _ => {}
                }
            } else if topic == "ego-shards-v1" {
                match serde_json::from_slice::<P2PMessage>(&message.data) {
                    Ok(P2PMessage::ShardAnnounce { from_addr, from_endpoint, held_shards, uptime_secs, network_node_count, shard_count }) => {
                        crate::sharding::handle_shard_announce_update(&from_addr, &from_endpoint, &held_shards, uptime_secs, network_node_count, shard_count);
                    }
                    Ok(P2PMessage::MasterPromotion { shard_id, new_master, new_endpoint, former_master, timestamp }) => {
                        tracing::info!("MasterPromotion: shard {} → new master {} (was {})", shard_id, new_master, former_master);
                        let mut map = crate::sharding::load_shard_map();
                        if let Some(old) = map.assignments.iter_mut().find(|a| a.shard_id == shard_id && a.node_address == former_master) {
                            old.role = crate::sharding::ShardRole::Observer;
                        }
                        if let Some(new_m) = map.assignments.iter_mut().find(|a| a.shard_id == shard_id && a.node_address == new_master) {
                            new_m.role = crate::sharding::ShardRole::Master;
                            new_m.node_endpoint = new_endpoint.clone();
                            new_m.last_seen = timestamp;
                        } else {
                            map.assignments.push(crate::sharding::ShardAssignment {
                                shard_id,
                                role: crate::sharding::ShardRole::Master,
                                node_address: new_master.clone(),
                                node_endpoint: new_endpoint.clone(),
                                last_seen: timestamp,
                                uptime_secs: 0,
                            });
                        }
                        let _ = crate::sharding::save_shard_map(&map);

                        let my_addr = crate::ledger::Ledger::load().address;
                        let my_ep   = get_public_endpoint().await;
                        let updated = crate::sharding::load_shard_map();
                        let all_nodes: Vec<String> = updated.assignments.iter()
                            .map(|a| a.node_address.clone())
                            .collect::<std::collections::HashSet<_>>()
                            .into_iter().collect();
                        let is_slave = crate::sharding::my_shards(&my_addr, &updated, &all_nodes)
                            .iter().any(|(sid, role)| *sid == shard_id && *role == crate::sharding::ShardRole::Slave);
                        if is_slave && !new_endpoint.is_empty() {
                            let my_ep2 = my_ep.clone();
                            let my_a2  = my_addr.clone();
                            let ep2    = new_endpoint.clone();
                            let chain  = load_chain();
                            let from_h = crate::sharding::last_shard_height(shard_id, &chain, &updated);
                            tokio::spawn(async move {
                                let req = P2PMessage::ShardDataRequest {
                                    shard_id,
                                    from_height:        from_h,
                                    requester_address:  my_a2,
                                    requester_endpoint: my_ep2,
                                };
                                let _ = send_message_any(&[ep2], &req).await;
                            });
                        }
                    }
                    _ => {}
                }
            } else if topic == "ego-shard-txs-v1" {
                if let Ok(P2PMessage::ShardTxRoute { shard_id, tx }) =
                    serde_json::from_slice::<P2PMessage>(&message.data)
                {
                    let my_addr = crate::ledger::Ledger::load().address;
                    let map = crate::sharding::load_shard_map();
                    let all_nodes: Vec<String> = map.assignments.iter()
                        .map(|a| a.node_address.clone())
                        .collect::<std::collections::HashSet<_>>()
                        .into_iter().collect();
                    let my_shard_ids: Vec<u32> = crate::sharding::my_shards(&my_addr, &map, &all_nodes)
                        .into_iter().map(|(id, _)| id).collect();
                    if my_shard_ids.contains(&shard_id) {
                        let _ = crate::mempool::get_mempool().push(tx);
                    } else {
                        tokio::spawn(async move {
                            route_tx_to_shard_master(shard_id, tx).await;
                        });
                    }
                }
            } else if topic == "ego-shard-rebalance-v1" {
                if let Ok(P2PMessage::ShardRebalance { proposed_shard_count, effective_at_height, proposer }) =
                    serde_json::from_slice::<P2PMessage>(&message.data)
                {
                    let current = crate::sharding::get_agreed_shard_count();
                    if proposed_shard_count != current && proposed_shard_count >= 1 {
                        tracing::info!("Shard rebalance proposal: {} shards (from {}), effective at block {}",
                            proposed_shard_count, &proposer[..16.min(proposer.len())], effective_at_height);
                        crate::sharding::set_agreed_shard_count(proposed_shard_count, effective_at_height);
                    }
                }
            } else if topic == "ego-poc-v1" {
            match serde_json::from_slice::<P2PMessage>(&message.data) {
                Ok(P2PMessage::PocBeacon { beacon_id, address, machine_id, cell, epoch, timestamp, transport, signature }) => {
                    tokio::spawn(handle_poc_beacon(beacon_id, address, machine_id, cell, epoch, timestamp, transport, signature));
                }
                Ok(P2PMessage::PocWitnessReceipt { beacon_id, beaconer, witness, witness_machine_id, witness_cell, latency_ms, rssi_dbm, timestamp, signature }) => {
                    tokio::spawn(handle_poc_witness(beacon_id, beaconer, witness, witness_machine_id, witness_cell, latency_ms, rssi_dbm, timestamp, signature));
                }
                Ok(P2PMessage::PocEventBroadcast { address, quality, peers, timestamp: _, signature: _ }) => {
                    if IS_RELAY_SERVER.load(Ordering::Relaxed) {
                        eprintln!("[Oracle] Received PoC Gossip from {}: quality={}, peers={}", address, quality, peers);
                    }
                }
                _ => {}
            }
            }
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::Gossipsub(
            gossipsub::Event::Subscribed { peer_id: pid, topic },
        )) => {
            eprintln!("[Gossip] {} subscribed to {}", pid, topic);
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::Gossipsub(_)) => {}

        SwarmEvent::Behaviour(EgoBehaviourEvent::Kad(
            kad::Event::RoutingUpdated { peer, addresses, .. },
        )) => {
            eprintln!("[DHT] Routing updated: {} ({} addrs)", peer, addresses.len());

            if let Some(addr) = addresses.iter().next() {
                let full: Multiaddr = format!("{}/p2p/{}", addr, peer)
                    .parse()
                    .unwrap_or_else(|_| addr.clone());
                let _ = swarm.dial(full);
            }
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::Kad(
            kad::Event::OutboundQueryProgressed { result, .. },
        )) => {
            match result {
                kad::QueryResult::Bootstrap(Ok(kad::BootstrapOk { num_remaining, .. })) => {
                    if num_remaining == 0 {
                        eprintln!("[DHT] Bootstrap complete");
                    }
                }
                kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(rec))) => {
                    let key_str = String::from_utf8_lossy(rec.record.key.as_ref()).to_string();

                    if key_str.starts_with("ego-manifest:") {

                        let manifest_cid = key_str.trim_start_matches("ego-manifest:").to_string();
                        if let Ok(manifest) = serde_json::from_slice::<crate::blocks::FileManifest>(&rec.record.value) {

                            let _ = crate::blocks::save_manifest(&manifest);
                            eprintln!("[DHT] Manifest {} received from DHT ({} blocks)", &manifest_cid[..16.min(manifest_cid.len())], manifest.blocks.len());

                            let app2 = app.cloned();
                            let mcid = manifest_cid.clone();
                            tokio::spawn(async move {
                                process_received_manifest(&mcid, app2.as_ref()).await;
                            });
                        }
                    } else if key_str.starts_with("ego-block:") {

                        let block_cid = key_str.trim_start_matches("ego-block:").to_string();
                        if !crate::blocks::have_block(&block_cid) {
                            let _ = crate::blocks::save_block(&block_cid, &rec.record.value);
                            eprintln!("[DHT] Block {} received from DHT ({} bytes)", &block_cid[..16.min(block_cid.len())], rec.record.value.len());

                            let app2 = app.cloned();
                            tokio::spawn(async move {
                                check_block_completes_manifests(&block_cid, app2.as_ref()).await;
                            });
                        }
                    } else if key_str.starts_with("ego-relay:") {

                        let relay_ma = String::from_utf8_lossy(&rec.record.value).to_string();
                        if !relay_ma.is_empty() && relay_ma.contains("/p2p/") {
                            save_dht_record_to_cache(&key_str, &rec.record.value);

                            if let Some(m) = PEER_RELAY_NODES.get() {
                                m.lock().unwrap().insert(relay_ma.clone(), relay_ma.clone());
                            }
                            eprintln!("[Relay] Discovered community relay via DHT: {}", relay_ma);
                            if let Some(tx) = DHT_CMD_TX.get() {
                                let _ = tx.send(DhtCommand::DialPeer { addr: relay_ma });
                            }
                        }
                    } else if key_str.starts_with("ego-inbox:") {

                        let value = rec.record.value.clone();
                        if !value.is_empty() {
                            if let Ok(msg) = serde_json::from_slice::<P2PMessage>(&value) {
                                let app2 = app.cloned();
                                let key2 = key_str.clone();
                                eprintln!("[DHT-Inbox] Processing message from {}", key2);
                                tokio::spawn(async move { handle_incoming(msg, app2.as_ref()).await; });

                                if let Some(tx) = DHT_CMD_TX.get() {
                                    let _ = tx.send(DhtCommand::PutPeer {
                                        key:   key_str,
                                        value: vec![],
                                    });
                                }
                            }
                        }
                    } else {

                        if let Ok(peer_info) = serde_json::from_slice::<serde_json::Value>(&rec.record.value) {
                            let endpoint = peer_info["endpoint"].as_str().unwrap_or("");
                            if !endpoint.is_empty() {
                                if let Ok(addr) = endpoint.parse::<Multiaddr>() {
                                    let _ = swarm.dial(addr);
                                    eprintln!("[DHT] Discovered peer via DHT: {}", endpoint);
                                }
                            }
                        }
                    }
                }
                kad::QueryResult::GetRecord(Err(_)) => {}
                _ => {}
            }
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::Kad(_)) => {}

        _ => {}
    }
}

pub async fn handle_incoming(msg: P2PMessage, app: Option<&tauri::AppHandle<tauri::Wry>>) {
    match msg {
        // ── Consensus-v2 (BftEngine) — the live consensus path ───────────────
        // Feed the engine that drives the real chain: validate + vote on proposals,
        // tally votes, persist the agreed LedgerBlock on QC. Inline runs instead only
        // under EGO_CONSENSUS_LEGACY=1.
        P2PMessage::BftV2Proposal { header, block, transactions } => {
            shadow_on_proposal(header, block, transactions).await;
        }
        P2PMessage::BftV2Vote { vote } => {
            shadow_on_vote(vote).await;
        }
        P2PMessage::BftV2ViewChange { msg } => {
            shadow_on_view_change(msg).await;
        }

        // Unsealed in the gossip arm of handle_event, which then dispatches the
        // inner message here. Keeping the unseal out of this function is what
        // stops handle_incoming from having to call itself.
        P2PMessage::SealedDm { .. } => {}

        P2PMessage::ContactRequest {
            from_addr, from_name, from_ed25519, from_kyber, from_shared_key, from_endpoint, bundle_token,
        } => {
            // Validate bundle token — drop silently if revoked
            let my_token = tokio::task::spawn_blocking(crate::ledger::Ledger::load)
                .await.unwrap_or_default().bundle_token;
            if !my_token.is_empty() {
                match &bundle_token {
                    Some(t) if t == &my_token => {}
                    // old / missing token — the card it came from was revoked.
                    // Logged because it is otherwise indistinguishable from the
                    // request never arriving at all.
                    _ => {
                        eprintln!(
                            "[Messenger] Dropped contact request from {} — card token {} does not match the current one",
                            from_addr,
                            bundle_token.as_deref().unwrap_or("<absent>"),
                        );
                        return;
                    }
                }
            }
            eprintln!("[Messenger] Contact request accepted from {} ({})", from_name, from_addr);
            let _cg = crate::commands::messenger::CONTACTS_LOCK.lock().unwrap();
            let mut contacts = load_contacts();
            if let Some(existing) = contacts.iter_mut().find(|c| c.address == from_addr) {
                if !from_endpoint.is_empty() && existing.endpoint != from_endpoint {
                    existing.endpoint = from_endpoint.clone();
                    let _ = save_contacts(&contacts);
                }
                return;
            }
            let contact = Contact {
                address:            from_addr.clone(),
                name:               from_name.clone(),
                ed25519_pubkey:     from_ed25519,
                kyber_pubkey:       from_kyber,
                shared_key_hex:     from_shared_key,
                status:             "pending_in".to_string(),
                added_at:           Utc::now().timestamp(),
                endpoint:           from_endpoint,
                all_endpoints:      Vec::new(),
                ratchet_send_chain: String::new(),
                ratchet_recv_chain: String::new(),
                ratchet_send_count: 0,
                ratchet_recv_count: 0,
                bundle_token:       None,
                avatar:             String::new(),
                last_request_at:    0,
            };
            contacts.push(contact.clone());
            let _ = save_contacts(&contacts);
            if let Some(h) = app {
                crate::commands::notifications::notify(h, "Contact Request", &format!("{} wants to connect with you", from_name));
                let _ = h.emit_all("ego://contact-request", &contact);
            }
        }

        P2PMessage::FileChunk { .. } => {
            eprintln!("[P2P] FileChunk ignored — 50MB max file size enforced at upload");
        }

        P2PMessage::FileChunkComplete { .. } => {
            eprintln!("[P2P] FileChunkComplete ignored — 50MB max file size enforced at upload");
        }

        P2PMessage::DataManifest { from_addr, cids, available_gb, is_relay, endpoint } => {
            eprintln!("[P2P] DataManifest from {} — {} CIDs, {:.1}GB free, relay={}",
                from_addr, cids.len(), available_gb, is_relay);

            // Track per-peer available storage for network capacity calculation.
            if !from_addr.is_empty() {
                peer_storage().insert(from_addr.clone(), available_gb);
            }

            if is_relay && !endpoint.is_empty() {
                peer_relay_nodes().insert(from_addr.clone(), endpoint.clone());
                eprintln!("[relay-server] Discovered community relay node at {}", endpoint);
            }
            if let Some(h) = app {
                let _ = h.emit_all("ego://data-manifest", serde_json::json!({
                    "from_addr":    from_addr,
                    "cid_count":    cids.len(),
                    "available_gb": available_gb,
                    "is_relay":     is_relay,
                }));
            }
        }

        P2PMessage::PinRequest { cid, from_addr, from_endpoint, storage_fee_uegoc, expiry } => {
            eprintln!("[P2P] PinRequest for {} from {} fee={} expiry={}", cid, from_addr, storage_fee_uegoc, expiry);
            let ledger    = crate::ledger::Ledger::load();
            let used: u64 = ledger.stored_files.iter().map(|f| f.encrypted_size).sum();
            let capacity  = ledger.storage_allocated_bytes;
            let has_file  = ledger.stored_files.iter()
                .any(|f| f.cid == cid && !f.local_path.is_empty() && !f.local_path.starts_with("sender:"));
            let my_addr   = ledger.address.clone(); // This is line 6145 in the user's code (approx)
            let ep        = from_endpoint.clone();

            // Collateral = 20% of deal fee.  Slave must have enough balance to lock it.
            let collateral   = storage_fee_uegoc / 5;
            let chain        = crate::ledger::load_chain();
            let balance      = chain.balance_of(&my_addr);
            let can_collateral = collateral == 0 || balance >= collateral;

            if has_file {
                let my_addr2 = my_addr.clone();
                tokio::spawn(async move {
                    let _ = send_message_any(&[ep], &P2PMessage::PinAck {
                        cid, accepted: true, reason: "Already stored".into(),
                        from_addr: my_addr2,
                    }).await;
                });
            } else if capacity > 0 && used + 10_000_000 < capacity && can_collateral {

            let _guard = crate::ledger::TX_MUTEX.lock().await; // This is fine, it's a tokio mutex
            let mut ledger2 = crate::ledger::Ledger::load();
                // ── Lock collateral on-chain ──────────────────────────────
                if collateral > 0 {
                    let now2       = chrono::Utc::now().timestamp();
                    let nonce      = ledger2.nonce + 1;
                    let sign_input = format!("lock_collateral:{}:{}:{}", my_addr, cid, nonce);
                    let sig_hex    = crate::ledger::load_seed().ok().flatten()
                        .and_then(|s| { let mut a = [0u8;32]; a.copy_from_slice(&s[..32]); ego_core::KeyPair::from_bytes(&a).ok() })
                        .map(|kp| hex::encode(kp.sign_ed25519(sign_input.as_bytes()).as_bytes()))
                        .unwrap_or_default();
                    let tx_hash = format!("0x{}", ego_core::hash_data(sign_input.as_bytes()).to_hex());
                    let mut chain2 = crate::ledger::load_chain();
                    chain2.transactions.push(crate::ledger::LedgerTx {
                        hash:        tx_hash.clone(),
                        from:        my_addr.clone(),
                        to:          "egot1collateral000000000000000000000000000000".into(),
                        amount:      collateral,
                        memo:        Some(format!("lock_collateral: {}", &cid[..16.min(cid.len())])),
                        timestamp:   now2, signature: sig_hex, status: "Confirmed".into(),
                        block_height: None, nonce,
                        tx_type:     "lock_collateral".into(),
                        cid:         cid.clone(),
                        ..crate::ledger::LedgerTx::default()
                    });
                    chain2.mine_block(&tx_hash, &my_addr);
                    let _ = crate::ledger::save_chain(&chain2);
                    eprintln!("[Collateral] Locked {} uEGOC for cid={}", collateral, &cid[..16.min(cid.len())]);
                }

                // Record ourselves as a slave for this CID
                {
                    ledger2.nonce += if collateral > 0 { 1 } else { 0 };
                    let now2 = chrono::Utc::now().timestamp();
                    if !ledger2.stored_files.iter().any(|f| f.cid == cid) {
                        ledger2.stored_files.push(crate::ledger::StoredFile {
                            cid:                    cid.clone(),
                            status:                 "Active".into(),
                            local_path:             format!("sender:{}", from_addr),
                            replication_role:       "slave".into(),
                            replica_master:         from_addr.clone(),
                            master_last_seen:       now2,
                            storage_fee_uegoc:      storage_fee_uegoc,
                            expiry:                 if expiry > 0 { expiry } else { now2 + 30 * 86_400 },
                            collateral_locked_uegoc: collateral,
                            owner:                  from_addr.clone(), // owner = uploader, not us
                            ..Default::default()
                        });
                        let _ = ledger2.save();
                    }
                }

                let my_ep = get_public_endpoint().await;
                let cid2  = cid.clone();
                let ep2   = ep.clone();
                let my_addr2 = my_addr.clone();
                tokio::spawn(async move {
                    let _ = send_message_any(&[ep2.clone()], &P2PMessage::FileRequest {
                        cid: cid2.clone(),
                        requester_addr:     my_addr,
                        requester_endpoint: my_ep,
                    }).await;
                    let _ = send_message_any(&[ep2], &P2PMessage::PinAck {
                        cid: cid2, accepted: true, reason: "Pinning".into(),
                        from_addr: my_addr2,
                    }).await;
                });
            } else {
                let reason = if !can_collateral {
                    format!("Insufficient balance for collateral ({} uEGOC required)", collateral)
                } else {
                    "Insufficient capacity".into()
                };
                let my_addr2 = my_addr.clone();
                tokio::spawn(async move {
                    let _ = send_message_any(&[ep], &P2PMessage::PinAck {
                        cid, accepted: false, reason,
                        from_addr: my_addr2,
                    }).await;
                });
            }
        }

        P2PMessage::PinAck { cid, accepted, reason, from_addr: ack_from } => {
            eprintln!("[P2P] PinAck for {} — accepted={} reason={}", cid, accepted, reason);

            if accepted && !ack_from.is_empty() {
                let _guard = crate::ledger::TX_MUTEX.lock().await;
                let mut ledger = tokio::task::spawn_blocking(crate::ledger::Ledger::load)
                    .await.unwrap_or_default();
                let mut changed = false;

                let now = chrono::Utc::now().timestamp();
                for f in ledger.stored_files.iter_mut() {
                    if f.cid == cid && !f.replica_peers.contains(&ack_from) {
                        f.replica_peers.push(ack_from.clone());
                        if f.replica_peers.len() > MIN_REPLICAS {
                            f.replica_peers.truncate(MIN_REPLICAS);
                        }
                        if f.replica_peers.contains(&ack_from) {
                            f.replica_last_ack.insert(ack_from.clone(), now);
                            f.replica_grace.remove(&ack_from);
                        }
                        changed = true;
                        eprintln!("[Replication] {} pinned by {} ({}/{} replicas)",
                            cid, ack_from, f.replica_peers.len(), MIN_REPLICAS);
                    }
                }

                // Providers are NOT paid a lump sum on pin. The uploader's fee is held in
                // escrow and streamed per-period to the CURRENT proven holders by
                // check_file_replication (master duty), so revenue follows the data when a
                // master fails over to a slave.
                if changed {
                    tokio::task::spawn_blocking(move || { let _ = ledger.save(); }).await.ok();
                }
            }
        }

        // ── Master → slave heartbeat ──────────────────────────────────────
        P2PMessage::ReplicaHeartbeat { cid, master_addr, timestamp, master_since } => {
            let _guard = crate::ledger::TX_MUTEX.lock().await;
            let mut ledger = tokio::task::spawn_blocking(crate::ledger::Ledger::load)
                .await.unwrap_or_default();
            let my_addr = ledger.address.clone();
            let now = chrono::Utc::now().timestamp();
            let mut changed  = false;
            let mut send_ack = false;
            for f in ledger.stored_files.iter_mut() {
                if f.cid != cid { continue; }
                let has_data = !f.local_path.is_empty() && !f.local_path.starts_with("sender:");
                if f.replication_role == "slave" && f.replica_master == master_addr {
                    f.master_last_seen = timestamp;
                    send_ack = has_data;
                    changed = true;
                } else if f.replication_role == "slave"
                    && f.replica_master != master_addr
                    && now - f.master_last_seen > MASTER_TIMEOUT_SECS
                {
                    // Our recorded master is dark but someone else is actively
                    // mastering this CID (we slept through the ReplicaPromote) —
                    // adopt the live master and announce ourselves so it can
                    // proof-challenge us back in from its grace window.
                    eprintln!("[Replication] Adopting live master {} for {} (old master {} is dark)",
                        master_addr, &cid[..16.min(cid.len())], f.replica_master);
                    f.replica_master   = master_addr.clone();
                    f.master_last_seen = timestamp;
                    send_ack = has_data;
                    changed = true;
                } else if f.replication_role == "master" && master_addr != my_addr {
                    // Split-brain: two nodes claim master for the same CID (a slave
                    // promoted itself while the real master was dark, and the old
                    // master returned still believing it's master). The LATER
                    // promotion wins — that's the failover node that actually kept
                    // serving the file while the other was gone. Tie (both legacy
                    // heartbeats without master_since) → lower address, as before.
                    let step_down = master_since > f.master_since
                        || (master_since == f.master_since && master_addr.as_str() < my_addr.as_str());
                    if step_down {
                        f.replication_role = "slave".to_string();
                        f.replica_master   = master_addr.clone();
                        f.master_last_seen = timestamp;
                        f.replica_last_ack.clear();
                        f.replica_grace.clear();
                        f.master_since = 0;
                        send_ack = has_data;
                        changed = true;
                        eprintln!("[Replication] Split-brain resolved for {} — stepping down to slave of {} (their promotion is newer)",
                            &cid[..16.min(cid.len())], master_addr);
                    }
                    // else: our promotion is newer (or we win the tie) → we remain
                    // master; the competing node steps down on OUR heartbeat.
                }
            }
            if changed { tokio::task::spawn_blocking(move || ledger.save()).await.ok(); }
            if send_ack && !my_addr.is_empty() {
                let ack = P2PMessage::ReplicaHeartbeatAck {
                    cid,
                    replica_addr: my_addr,
                    timestamp: now,
                };
                if let Ok(data) = serde_json::to_vec(&ack) {
                    tokio::spawn(async move { publish_gossip("ego-storage-v1", data).await; });
                }
            }
        }

        // ── Slave → master liveness ack ───────────────────────────────────
        P2PMessage::ReplicaHeartbeatAck { cid, replica_addr, .. } => {
            if replica_addr.is_empty() { return; }
            let _guard = crate::ledger::TX_MUTEX.lock().await;
            let mut ledger = tokio::task::spawn_blocking(crate::ledger::Ledger::load)
                .await.unwrap_or_default();
            if replica_addr == ledger.address { return; }
            let now = chrono::Utc::now().timestamp();
            let mut changed = false;
            let mut challenge_rejoin = false;
            for f in ledger.stored_files.iter_mut() {
                if f.cid != cid || f.replication_role != "master" { continue; }
                if f.replica_peers.contains(&replica_addr) {
                    f.replica_last_ack.insert(replica_addr.clone(), now);
                    changed = true;
                } else if f.replica_grace.contains_key(&replica_addr) {
                    // A dark holder is back within its grace window: verify it still
                    // has the data (PoRep challenge) before letting it rejoin —
                    // never on its word alone.
                    challenge_rejoin = true;
                }
            }
            if changed { tokio::task::spawn_blocking(move || ledger.save()).await.ok(); }
            if challenge_rejoin {
                issue_rejoin_challenge(&cid, &replica_addr).await;
            }
        }

        // ── Slave promoted itself to master — update our records ──────────
        P2PMessage::ReplicaPromote { cid, new_master, old_master, .. } => {
            let my_addr = tokio::task::spawn_blocking(|| crate::ledger::Ledger::load().address)
                .await.unwrap_or_default();
            let _guard = crate::ledger::TX_MUTEX.lock().await;
            let mut ledger = tokio::task::spawn_blocking(crate::ledger::Ledger::load)
                .await.unwrap_or_default();
            let mut changed = false;
            for f in ledger.stored_files.iter_mut() {
                if f.cid != cid { continue; }
                // If we were a slave pointing to the dead master, update our master pointer
                if f.replication_role == "slave" && f.replica_master == old_master {
                    f.replica_master   = new_master.clone();
                    f.master_last_seen = chrono::Utc::now().timestamp();
                    changed = true;
                    eprintln!("[Replication] Slave updated master {} → {} for {}",
                        old_master, new_master, &cid[..16.min(cid.len())]);
                }
                // If we were the master (somehow still alive), step down — new master takes over
                if f.replication_role == "master" && f.replica_peers.contains(&new_master) && my_addr != new_master {
                    f.replication_role = "slave".to_string();
                    f.replica_master   = new_master.clone();
                    f.master_last_seen = chrono::Utc::now().timestamp();
                    changed = true;
                    eprintln!("[Replication] Stepping down as master for {} — new master is {}",
                        &cid[..16.min(cid.len())], new_master);
                }
            }
            if changed { tokio::task::spawn_blocking(move || ledger.save()).await.ok(); }
        }

        P2PMessage::ContactResponse {
            from_addr, from_name, from_ed25519, from_kyber, approved, shared_key, from_endpoint,
        } => {
            let _cg = crate::commands::messenger::CONTACTS_LOCK.lock().unwrap();
            let mut contacts = load_contacts();
            if approved {
                if let Some(p) = contacts.iter_mut()
                    .find(|c| c.shared_key_hex == shared_key
                           && (c.status == "pending_out" || c.status == "approved"))
                {
                    let already_approved = p.status == "approved";
                    p.address        = from_addr.clone();
                    // Only take the peer's declared name on first approval. After
                    // that the local name is the user's — a duplicate response
                    // (the gossip fallback sends a second copy by design) must not
                    // reset a contact they renamed.
                    if !already_approved {
                        p.name = from_name.clone();
                    }
                    p.ed25519_pubkey = from_ed25519;
                    p.kyber_pubkey   = from_kyber;
                    p.status         = "approved".to_string();
                    if !from_endpoint.is_empty() {
                        p.endpoint = from_endpoint;
                    }
                    let contact = p.clone();
                    let _ = save_contacts(&contacts);
                    if !already_approved {
                        if let Some(h) = app {
                            crate::commands::notifications::notify(h, "Contact Request Accepted!", &format!("{} accepted your request", from_name));
                            let _ = h.emit_all("ego://contact-approved", &contact);
                        }
                        // They just became a contact — send them our picture.
                        let avatar = crate::ledger::Ledger::load().avatar;
                        if !avatar.is_empty() {
                            tokio::spawn(async move {
                                crate::commands::messenger::broadcast_profile(avatar).await;
                            });
                        }
                    }
                }
            } else {
                contacts.retain(|c| !(c.status == "pending_out" && c.shared_key_hex == shared_key));
                let _ = save_contacts(&contacts);
                if let Some(h) = app {
                    crate::commands::notifications::notify(h, "Contact Request Declined", "Your contact request was declined.");
                    let _ = h.emit_all("ego://contact-declined", ());
                }
            }
        }

        P2PMessage::PeerAnnounce { address, name, endpoint, endpoints, city, country, lat, lon, coverage_score, dilithium_pubkey, vrf_pubkey, staked_amount, genesis_hash, signature, machine_id } => {
            if genesis_hash != crate::ledger::GENESIS_HASH {
                tracing::warn!("[P2P] Rejected peer {} — Parallel network attempt detected (Genesis mismatch)", address);
                return;
            }

            // NOTE: No hardware-ID / IP uniqueness rejection. Rewards are weighted
            // by DRS (real storage + coverage), so running several nodes — from one
            // PC or behind the same WiFi/NAT — earns nothing without genuine
            // contribution and can't cheat the system. Rejecting co-located peers
            // only broke legitimate users on the same network.
            let _ = &machine_id;

            let identity_verified = verify_peer_announce_identity(
                &address,
                &endpoint,
                &endpoints,
                coverage_score,
                &dilithium_pubkey,
                &vrf_pubkey,
                staked_amount,
                &genesis_hash,
                &machine_id,
                &signature,
            );
            if identity_verified {
                register_validator_pubkey(&address, &dilithium_pubkey);
                if !vrf_pubkey.is_empty() { record_peer_ed25519(&address, &vrf_pubkey); }
                register_announced_validator(&address);
            } else if staked_amount > 0 || coverage_score > 0 || !dilithium_pubkey.is_empty() || !vrf_pubkey.is_empty() {
                tracing::warn!(
                    "PeerAnnounce from {} FAILED identity verification — not registering as validator (genesis_match={}, has_dil={}, has_vrf={})",
                    address,
                    genesis_hash == crate::ledger::GENESIS_HASH,
                    !dilithium_pubkey.is_empty(),
                    !vrf_pubkey.is_empty(),
                );
            }
            if !endpoint.is_empty() {
                let _cg = crate::commands::messenger::CONTACTS_LOCK.lock().unwrap();
                let mut contacts = load_contacts();
                if let Some(c) = contacts.iter_mut().find(|c| c.address == address) {
                    let relay_in   = endpoint.contains("/p2p-circuit");
                    let relay_curr = c.endpoint.contains("/p2p-circuit");
                    if (relay_in || !relay_curr) && c.endpoint != endpoint {
                        eprintln!("[P2P] Updated contact {} endpoint → {}", address, endpoint);
                        c.endpoint = endpoint.clone();
                    }

                    if !endpoints.is_empty() {
                        c.all_endpoints = endpoints.clone();
                    }
                    let _ = save_contacts(&contacts);
                }
            }
            crate::app::global_app_state().upsert_peer(crate::app::PeerInfo {
                address:   address.clone(),
                name,
                endpoint:  endpoint.clone(),
                last_seen: Utc::now().timestamp(),
            city:      city.clone(),
            country:   country.clone(),
            lat,
            lon,
            });
            upsert_peer_cache(PeerEntry {
                address:   address.clone(),
                endpoint:  endpoint.clone(),
                last_seen: Utc::now().timestamp(),
            city,
            country,
            lat,
            lon,
            });

            if !endpoint.is_empty() {
                let ep = endpoint.clone();
                let addr_clone = address.clone();
                let my_addr = tokio::task::spawn_blocking(|| crate::ledger::Ledger::load().address).await.unwrap_or_default();
                tokio::spawn(async move {
                    crate::commands::outbox::flush_for(&addr_clone, Some(&ep)).await;
                });

                if chain_push_allowed(&endpoint) {
                    let ep2 = endpoint.clone();
                    let my_addr = tokio::task::spawn_blocking(|| crate::ledger::Ledger::load().address).await.unwrap_or_default();
                    tokio::spawn(async move {
                        let (blocks, transactions) = tokio::task::spawn_blocking(|| {
                        let tip = crate::chain_db::latest_block_info().0;
                        if tip == 0 { return (vec![], vec![]); }
                        let start = tip.saturating_sub(200).max(1);
                        let blocks = crate::chain_db::get_blocks_range(start, 200);
                            let transactions: Vec<crate::ledger::LedgerTx> = blocks.iter()
                                .flat_map(|b| crate::chain_db::get_txs_for_block(b.height))
                                .collect();
                            (blocks, transactions)
                        }).await.unwrap_or_default();
                        if blocks.is_empty() { return; }
                        let response = P2PMessage::ChainSyncResponse { blocks, transactions };
                        if let Err(e) = send_message_any(&[ep2.clone()], &response).await {
                            if !e.contains("none of the requested protocols") {
                                tracing::debug!("[P2P] proactive chain push to {}: {}", ep2, e);
                            }
                        }
                    });
                }

                if announce_reply_allowed(&endpoint) {
                    let ep3 = endpoint.clone();
                    tokio::spawn(async move {
                        send_direct_peer_announce(ep3).await;
                    });
                }
            }

        }
P2PMessage::ChatMessage { bundle, seq } => {
    match crate::commands::messenger::receive_message_inner(&bundle, seq) {
        Ok((msg, is_new)) => {
            if !is_new {

                return;
            }
            if msg.message_type == "file_bundle" {
                use base64::Engine as _;
                let parts: Vec<&str> = msg.content.splitn(5, ':').collect();
                let file_name = parts.get(3)
                    .and_then(|n| base64::engine::general_purpose::STANDARD.decode(n).ok())
                    .and_then(|b| String::from_utf8(b).ok())
                    .unwrap_or_else(|| "File".to_string());

                {
                    let content_clone = msg.content.clone();
                    let from_for_import = msg.from.clone();
                    let app_import = app.cloned();
                    tokio::spawn(async move {
                        crate::commands::notifications::try_auto_import(
                            app_import.as_ref(), &content_clone, &from_for_import,
                        ).await;
                    });
                }
            } else {

                {
                    let now = chrono::Utc::now().timestamp();
                    crate::app::global_app_state().pending_chat_address.lock().unwrap().replace((msg.from.clone(), now));
                }
                let preview = crate::commands::messenger::truncate_preview(&msg.content, 40);
                if let Some(h) = app {
                    // Title is who it's from, looked up fresh — rename a contact
                    // and the next notification already says the new name.
                    let sender = crate::commands::messenger::contact_display_name(&msg.from);
                    crate::commands::notifications::notify(h, &sender, &preview);
                }
            }
            if let Some(h) = app {
                let _ = h.emit_all("ego://message-received", &msg);
            }
        }
        Err(e) => eprintln!("[P2P] Decrypt error: {}", e),
    }
}

P2PMessage::ProfileUpdate { from_addr, avatar } => {
    // Same ceiling the setter enforces — a peer doesn't get to park an
    // unbounded blob in our contacts file.
    const MAX_AVATAR_BYTES: usize = 96 * 1024;
    if avatar.len() > MAX_AVATAR_BYTES
        || (!avatar.is_empty()
            && (!avatar.starts_with("data:image/") || !avatar.contains(";base64,")))
    {
        eprintln!("[Messenger] Rejected profile picture from {}", from_addr);
        return;
    }
    let updated = {
        let _cg = crate::commands::messenger::CONTACTS_LOCK.lock().unwrap();
        let mut contacts = load_contacts();
        match contacts.iter_mut()
            .find(|c| c.address == from_addr && c.status == "approved")
        {
            Some(c) if c.avatar != avatar => {
                c.avatar = avatar;
                let _ = save_contacts(&contacts);
                true
            }
            _ => false,
        }
    };
    if updated {
        if let Some(h) = app {
            let _ = h.emit_all("ego://contact-updated", &from_addr);
        }
    }
}

P2PMessage::ReadReceipt { from, to, message_ids } => {
    let my_addr = tokio::task::spawn_blocking(|| crate::ledger::Ledger::load().address)
        .await.unwrap_or_default();
    if my_addr.is_empty() || to != my_addr || message_ids.is_empty() { return; }
    let updated = crate::commands::messenger::mark_messages_read_by_recipient(&from, &message_ids);
    if updated > 0 {
        if let Some(h) = app {
            let _ = h.emit_all("ego://messages-read-receipt", serde_json::json!({ "contact": from }));
        }
    }
}

        P2PMessage::TxBroadcast { tx, block } => {
            apply_incoming_tx(tx, block, app).await;
        }

        P2PMessage::ValidatorLeaving { address, timestamp, signature } => {
            handle_validator_leaving(&address, timestamp, &signature);
        }

        P2PMessage::BlockProposal { block, transactions, proposer, signature, vrf_ticket, view, proposer_pubkey } => {
            learn_voter_pubkey(&proposer, &proposer_pubkey);
            note_network_height(block.height);
            let our_tip = crate::chain_db::latest_block_info().0;
            let prev_known = block.height <= 1
                || block.height == our_tip + 1
                || crate::chain_db::get_block_hash_at(block.height.saturating_sub(1))
                    .map(|h| h == block.prev_hash)
                    .unwrap_or(false);
            if prev_known { register_known_validator(&proposer); }
            handle_block_proposal(block, transactions, proposer, signature, vrf_ticket, view, app).await;
        }

        P2PMessage::BlockVote { block_hash, height, voter, signature, timestamp, vrf_ticket, prev_hash, bls_sig, bls_pubkey, voter_pubkey } => {
            learn_voter_pubkey(&voter, &voter_pubkey);
            note_network_height(height);
            let our_height = crate::chain_db::latest_block_info().0;
            let vote_on_our_chain = height == our_height + 1
                || crate::chain_db::get_block_hash_at(height.saturating_sub(1))
                    .map(|h| h == prev_hash)
                    .unwrap_or(false);
            if vote_on_our_chain { register_known_validator(&voter); }
            handle_block_vote(block_hash, height, voter, signature, timestamp, vrf_ticket, prev_hash, bls_sig, bls_pubkey, app.cloned()).await;
        }


        P2PMessage::BlockFinalized { mut block, transactions, votes, agg_bls_sig, bls_pubkeys } => {
            let block_hash = block.hash.clone();
            let height     = block.height;
            // Attach a locally-assembled QC before first persist if the producer's
            // block lacks one (see attach_local_qc_if_missing); must precede
            // process_inbound_qc_finalization, which clears the collected sigs.
            attach_local_qc_if_missing(&mut block);
            if process_inbound_qc_finalization(&block_hash, height, &votes, &agg_bls_sig, &bls_pubkeys) {
                merge_remote_chain_trusted(vec![block], transactions, app).await;
            }
        }


        P2PMessage::ChainSyncRequest { requester_endpoint, from_height } => {
            if !requester_endpoint.is_empty() && sync_reply_allowed(&requester_endpoint) {
                tokio::spawn(async move {
                    let (blocks, transactions) = tokio::task::spawn_blocking(move || {
                    let start = from_height.max(1);
                    let blocks = crate::chain_db::get_blocks_range(start, 500); // 500 blocks per jump
                        let transactions: Vec<crate::ledger::LedgerTx> = blocks.iter()
                            .flat_map(|b| crate::chain_db::get_txs_for_block(b.height))
                            .collect();
                        (blocks, transactions)
                    }).await.unwrap_or_default();
                    tracing::debug!("[P2P] sync reply: {} blocks ({} txs) from height {}",
                        blocks.len(), transactions.len(), from_height + 1);
                    let response = P2PMessage::ChainSyncResponse { blocks, transactions };
                    if let Ok(data) = serde_json::to_vec(&response) {
                        publish_gossip("ego-blocks-v1", data).await;
                    }
                });
            }
        }

        P2PMessage::SnapshotRequest { requester_endpoint, have_height } => {
            let local_tip = crate::chain_db::latest_block_info().0;
            if local_tip > have_height + SNAPSHOT_SERVE_MIN_LAG
                && !requester_endpoint.is_empty()
                && sync_reply_allowed(&requester_endpoint)
            {
                tokio::spawn(async move {
                    let snap = match tokio::task::spawn_blocking(crate::chain_db::export_state_snapshot).await {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                    if snap.height <= have_height { return; }
                    let resp = P2PMessage::SnapshotResponse { snapshot: snap };
                    let _ = send_message(&requester_endpoint, &resp).await;
                });
            }
        }

        P2PMessage::SnapshotResponse { snapshot } => {
            let local_tip = crate::chain_db::latest_block_info().0;
            if snapshot.height > local_tip {
                let h = snapshot.height;
                let ok = tokio::task::spawn_blocking(move || crate::chain_db::import_state_snapshot(&snapshot))
                    .await.map(|r| r.is_ok()).unwrap_or(false);
                if ok {
                    eprintln!("[P2PSnapshot] checkpoint-synced to height {} from peer (local was {})", h, local_tip);
                }
            }
        }

        P2PMessage::HeaderSyncRequest { from_height, limit } => {

            let headers  = crate::chain_db::get_block_headers(from_height, limit.min(10_000));
            let response = P2PMessage::HeaderSyncResponse { headers };
            let ep = get_public_endpoint().await;
            tokio::spawn(async move {
                let _ = send_message_any(&[ep], &response).await;
            });
        }

        P2PMessage::HeaderSyncResponse { headers } => {
            eprintln!("[LightClient] Received {} block headers", headers.len());
            if let Some(h) = app {
                let _ = h.emit_all("ego://headers-received", &headers);
            }
        }

        P2PMessage::ChainSyncResponse { blocks, transactions } => {
            merge_remote_chain(blocks, transactions, app).await;
        }

        P2PMessage::ShardDataRequest { shard_id, from_height, requester_address: _, requester_endpoint } => {
            if !requester_endpoint.is_empty() {
                let chain = load_chain();
                let map   = crate::sharding::load_shard_map();
                let (blocks, txs) = crate::sharding::get_shard_blocks(shard_id, from_height, &chain, &map);
                let response = P2PMessage::ShardDataResponse { shard_id, blocks, transactions: txs };
                tokio::spawn(async move {
                    if let Err(e) = send_message_any(&[requester_endpoint.clone()], &response).await {
                        eprintln!("[Sharding] shard data reply to {}: {}", requester_endpoint, e);
                    }
                });
            }
        }

        P2PMessage::ShardDataResponse { shard_id, blocks, transactions } => {
            eprintln!("[Sharding] received {} blocks for shard {}", blocks.len(), shard_id);
            merge_remote_chain(blocks, transactions, app).await;
        }


        P2PMessage::ShardBlockQuery { block_height, requester_address: _, requester_endpoint } => {
            let chain = load_chain();
            let map   = crate::sharding::load_shard_map();
            let shard_id = crate::sharding::shard_for_height(block_height, map.shard_count);
            let (blocks, txs) = crate::sharding::get_shard_blocks(shard_id, block_height.saturating_sub(1), &chain, &map);
            let resp = P2PMessage::ShardBlockResponse { block_height, blocks, transactions: txs };
            tokio::spawn(async move {
                let _ = send_message_any(&[requester_endpoint.clone()], &resp).await;
            });
        }

        P2PMessage::ShardBlockResponse { block_height: _, blocks, transactions } => {
            merge_remote_chain(blocks, transactions, app).await;
        }


        P2PMessage::ShardVacancyNotice { shard_id, current_holders } => {

            if current_holders < crate::sharding::REPLICATION_FACTOR {
                let my_addr = crate::ledger::Ledger::load().address;
                if my_addr.is_empty() { return; }
                let my_ep = get_public_endpoint().await;
                let map   = crate::sharding::load_shard_map();
                if crate::sharding::should_volunteer_for_shard(shard_id, &my_addr, &map) {
                    let volunteer = P2PMessage::ShardVolunteer {
                        shard_id,
                        volunteer_address:  my_addr,
                        volunteer_endpoint: my_ep,
                    };
                    if let Ok(data) = serde_json::to_vec(&volunteer) {
                        publish_gossip("ego-shards-v1", data).await;
                    }
                }
            }
        }

        P2PMessage::ShardVolunteer { shard_id, volunteer_address, volunteer_endpoint } => {

            let my_addr = crate::ledger::Ledger::load().address;
            if my_addr.is_empty() { return; }
            let map = crate::sharding::load_shard_map();
            let all_nodes: Vec<String> = map.assignments.iter()
                .map(|a| a.node_address.clone())
                .collect::<std::collections::HashSet<_>>()
                .into_iter().collect();
            let is_master = crate::sharding::my_shards(&my_addr, &map, &all_nodes)
                .iter().any(|(sid, role)| *sid == shard_id && *role == crate::sharding::ShardRole::Master);
            if !is_master { return; }

            eprintln!("[Sharding] Volunteer accepted: {} for shard {}", volunteer_address, shard_id);

            let mut updated = crate::sharding::load_shard_map();
            updated.assignments.retain(|a| !(a.shard_id == shard_id && a.node_address == volunteer_address));
            updated.assignments.push(crate::sharding::ShardAssignment {
                shard_id,
                role:          crate::sharding::ShardRole::Slave,
                node_address:  volunteer_address.clone(),
                node_endpoint: volunteer_endpoint.clone(),
                last_seen:     chrono::Utc::now().timestamp(),
                uptime_secs:   0,
            });
            let _ = crate::sharding::save_shard_map(&updated);

            let chain      = load_chain();
            let (blocks, txs) = crate::sharding::get_shard_blocks(shard_id, 0, &chain, &updated);
            let resp = P2PMessage::ShardDataResponse { shard_id, blocks, transactions: txs };
            tokio::spawn(async move {
                let _ = send_message_any(&[volunteer_endpoint.clone()], &resp).await;
            });
        }

        P2PMessage::PeerListRequest { requester_endpoint } => {
            let peers    = load_peer_cache();
            let response = P2PMessage::PeerListResponse { peers };
            tokio::spawn(async move {
                let eps = vec![requester_endpoint.clone()];
                if let Err(e) = send_message_any(&eps, &response).await {
                    eprintln!("[P2P] peer list reply: {}", e);
                }
            });
        }

        P2PMessage::PeerListResponse { peers } => {
            let my_ep = get_public_endpoint().await;
            for peer in peers {
                if peer.endpoint.is_empty() || peer.endpoint == my_ep { continue; }
                upsert_peer_cache(PeerEntry {
                    address:   peer.address,
                    endpoint:  peer.endpoint,
                    last_seen: Utc::now().timestamp(),
                    city:      peer.city,
                    country:   peer.country,
                    lat:       peer.lat,
                    lon:       peer.lon,
                });
            }
        }

        P2PMessage::PeerSeedGossip { .. } => {}

P2PMessage::FileRequest { cid, requester_addr, requester_endpoint } => {
    eprintln!("[P2P] FileRequest for {} from {} at {}", cid, requester_addr, requester_endpoint);
    let ledger  = crate::ledger::Ledger::load();
    let my_addr = ledger.address.clone();

    if let Some(file) = ledger.stored_files.iter().find(|f| f.cid == cid).cloned() {
        if file.local_path.is_empty() || file.local_path.starts_with("sender:") {
            eprintln!("[P2P] FileRequest: we don't have the data for {}", cid);
            return;
        }

        if cid.starts_with("egomfd1") {
            let ep = requester_endpoint.clone();
            let addr = requester_addr.clone();
            let key_hex64 = hex::encode(crate::ledger::unprotect_key_bytes(&file.key_nonce_hex));
            let file_name = file.name.clone();
            tokio::spawn(async move {
                match crate::blocks::load_manifest(&cid) {
                    Err(e) => eprintln!("[P2P] ManifestData: load failed: {}", e),
                    Ok(manifest) => {
                        match serde_json::to_string(&manifest) {
                            Err(e) => eprintln!("[P2P] ManifestData: serialize failed: {}", e),
                            Ok(manifest_json) => {
                                let response = P2PMessage::ManifestData {
                                    manifest_cid: cid.clone(),
                                    manifest_json,
                                    key_hex64,
                                    file_name,
                                    from_addr: my_addr.clone(),
                                };
                                let eps = vec![ep.clone()];
                                if let Err(e) = send_message_any(&eps, &response).await {
                                    eprintln!("[P2P] ManifestData direct failed: {} — relay inbox", e);
                                    crate::commands::messenger::deposit_in_relay_inbox(
                                        &addr, &my_addr, &response,
                                    ).await;
                                } else {
                                    eprintln!("[P2P] ManifestData sent for {} ({} blocks)", &cid[..16], manifest.blocks.len());
                                }
                            }
                        }
                    }
                }
            });
            return;
        }

        match std::fs::read(&file.local_path) {
            Err(e) => eprintln!("[P2P] FileRequest: read failed {}: {}", file.local_path, e),
            Ok(enc_bytes) => {
                use base64::Engine as _;
                let key_nonce_hex = hex::encode(crate::ledger::unprotect_key_bytes(&file.key_nonce_hex));
                let file_name     = file.name.clone();
                let cid2          = cid.clone();
                let ep            = requester_endpoint.clone();
                let addr          = requester_addr.clone();

                // Limit legacy non-chunked memory buffering to 50MB to prevent OOM
                const RELAY_LIMIT: usize = 50 * 1024 * 1024;

                tokio::spawn(async move {
                    if enc_bytes.len() > RELAY_LIMIT {
                        eprintln!("[P2P] File too large ({} bytes) — 50 MB max", enc_bytes.len());
                        return;
                    }

                    let enc_data_b64 = base64::engine::general_purpose::STANDARD.encode(&enc_bytes);
                    let response = P2PMessage::FileData {
                        cid:           cid2.clone(),
                        enc_data_b64,
                        file_name,
                        key_nonce_hex,
                    };

                    let eps = vec![ep.clone()];
                    if let Err(e) = send_message_any(&eps, &response).await {
                        eprintln!("[P2P] FileData direct failed: {} — relay inbox", e);
                        crate::commands::messenger::deposit_in_relay_inbox(
                            &addr, &my_addr, &response,
                        ).await;
                    } else {
                        eprintln!("[P2P] FileData sent OK for {}", cid2);
                    }
                });
            }
        }
    } else {
        eprintln!("[P2P] FileRequest: CID {} not found in our ledger", cid);
    }
}

        P2PMessage::ShardAnnounce { from_addr, from_endpoint, held_shards, uptime_secs, network_node_count, shard_count } => {
            crate::sharding::handle_shard_announce_update(&from_addr, &from_endpoint, &held_shards, uptime_secs, network_node_count, shard_count);
        }

        P2PMessage::MasterPromotion { shard_id, new_master, new_endpoint, former_master, timestamp } => {
            eprintln!("[Sharding] MasterPromotion (direct): shard {} → new master {} (was {})", shard_id, new_master, former_master);
            let mut map = crate::sharding::load_shard_map();
            if let Some(old) = map.assignments.iter_mut().find(|a| a.shard_id == shard_id && a.node_address == former_master) {
                old.role = crate::sharding::ShardRole::Observer;
            }
            if let Some(new_m) = map.assignments.iter_mut().find(|a| a.shard_id == shard_id && a.node_address == new_master) {
                new_m.role = crate::sharding::ShardRole::Master;
                new_m.node_endpoint = new_endpoint.clone();
                new_m.last_seen = timestamp;
            } else {
                map.assignments.push(crate::sharding::ShardAssignment {
                    shard_id,
                    role: crate::sharding::ShardRole::Master,
                    node_address: new_master,
                    node_endpoint: new_endpoint,
                    last_seen: timestamp,
                    uptime_secs: 0,
                });
            }
            let _ = crate::sharding::save_shard_map(&map);
        }

P2PMessage::FileData { cid, enc_data_b64, file_name, key_nonce_hex } => {
    use base64::Engine as _;
    eprintln!("[P2P] FileData received for {} ({} chars b64)", cid, enc_data_b64.len());
    match base64::engine::general_purpose::STANDARD.decode(&enc_data_b64) {
        Err(e) => eprintln!("[P2P] FileData decode failed: {}", e),
        Ok(enc_bytes) => {
            let storage  = crate::ledger::storage_dir();
            let short    = &cid[cid.len().saturating_sub(16)..];

            // Public (unencrypted) hosting files — store as .pub, skip decrypt
            if key_nonce_hex == "public" {
                let pub_path = storage.join(format!("{}.pub", short));
                if let Err(e) = std::fs::write(&pub_path, &enc_bytes) {
                    eprintln!("[P2P] Public FileData write failed: {}", e);
                    return;
                }
            let _guard = crate::ledger::TX_MUTEX.lock().await; // This is fine, it's a tokio mutex
                let pub_str = pub_path.to_string_lossy().to_string();
                let now2    = chrono::Utc::now().timestamp();
                let mut ledger2 = crate::ledger::Ledger::load();
                if let Some(f) = ledger2.stored_files.iter_mut().find(|f| f.cid == cid) {
                    f.local_path      = pub_str.clone();
                    f.key_nonce_hex   = "public".to_string();
                    f.status          = "Active".to_string();
                } else {
                    let my_addr = ledger2.address.clone();
                    ledger2.stored_files.push(crate::ledger::StoredFile {
                        cid:              cid.clone(),
                        name:             file_name.clone(),
                        original_size:    enc_bytes.len() as u64,
                        encrypted_size:   enc_bytes.len() as u64,
                        stored_at:        now2,
                        expiry:           now2 + 365 * 86_400,
                        status:           "Active".to_string(),
                        key_nonce_hex:    "public".to_string(),
                        local_path:       pub_str,
                        owner:            my_addr,
                        replication_role: "slave".to_string(),
                        ..Default::default()
                    });
                }
                let _ = ledger2.save();
                eprintln!("[P2P] Public FileData saved for {}", cid);
                if let Some(h) = app {
                    let _ = h.emit_all("ego://file-downloaded", serde_json::json!({ "cid": cid }));
                }
                return;
            }

            let enc_path = storage.join(format!("{}.enc", short));
            if let Err(e) = std::fs::write(&enc_path, &enc_bytes) {
                eprintln!("[P2P] FileData write failed: {}", e);
                return;
            }
        let _guard = crate::ledger::TX_MUTEX.lock().await; // This is fine, it's a tokio mutex
            let mut ledger = crate::ledger::Ledger::load();
            let enc_str    = enc_path.to_string_lossy().to_string();
            if let Some(f) = ledger.stored_files.iter_mut().find(|f| f.cid == cid) {
                if f.status != "Active" {
                    f.local_path = enc_str.clone();
                    if !key_nonce_hex.is_empty() {
                        f.key_nonce_hex = crate::ledger::protect_key_hex(&key_nonce_hex).unwrap_or(key_nonce_hex.clone());
                    }
                    if f.name.is_empty() { f.name = file_name.clone(); }
                    f.status = "Received".to_string();
                }
            } else {

                let now = chrono::Utc::now().timestamp();
                let my_addr = ledger.address.clone();
                ledger.stored_files.push(crate::ledger::StoredFile {
                    cid:             cid.clone(),
                    name:            file_name,
                    original_size:   enc_bytes.len() as u64,
                    encrypted_size:  enc_bytes.len() as u64,
                    duration_months: 0,
                    stored_at:       now,
                    expiry:          0,
                    status:          "Received".to_string(),
                    key_nonce_hex:   crate::ledger::protect_key_hex(&key_nonce_hex).unwrap_or(key_nonce_hex),
                    local_path:      enc_str,
                    owner:           my_addr,
                    ..Default::default()
                });
            }
            let _ = ledger.save();
            eprintln!("[P2P] FileData saved for {}", cid);
            if let Some(h) = app {
                let _ = h.emit_all("ego://file-downloaded", serde_json::json!({ "cid": cid }));
            }
        }
    }
}

        P2PMessage::ManifestRequest { manifest_cid, requester_addr, requester_endpoint } => {
            eprintln!("[Blocks] ManifestRequest for {} from {}", &manifest_cid[..16.min(manifest_cid.len())], requester_addr);
            let ledger  = crate::ledger::Ledger::load();
            let my_addr = ledger.address.clone();
            if let Some(file) = ledger.stored_files.iter().find(|f| f.cid == manifest_cid).cloned() {
                let ep      = requester_endpoint.clone();
                let addr    = requester_addr.clone();
                tokio::spawn(async move {
                    match crate::blocks::load_manifest(&manifest_cid) {
                        Err(e) => eprintln!("[Blocks] ManifestRequest: load failed: {}", e),
                        Ok(manifest) => {
                            match serde_json::to_string(&manifest) {
                                Err(e) => eprintln!("[Blocks] ManifestRequest: serialize: {}", e),
                                Ok(manifest_json) => {
                                    let response = P2PMessage::ManifestData {
                                        manifest_cid: manifest_cid.clone(),
                                        manifest_json,
                                        key_hex64:   hex::encode(crate::ledger::unprotect_key_bytes(&file.key_nonce_hex)),
                                        file_name:   file.name,
                                        from_addr:   my_addr.clone(),
                                    };
                                    let eps = vec![ep.clone()];
                                    if let Err(e) = send_message_any(&eps, &response).await {
                                        eprintln!("[Blocks] ManifestData direct failed: {} — inbox", e);
                                        crate::commands::messenger::deposit_in_relay_inbox(&addr, &my_addr, &response).await;
                                    }
                                }
                            }
                        }
                    }
                });
            }
        }

        P2PMessage::ManifestData { manifest_cid, manifest_json, key_hex64, file_name, from_addr } => {
            eprintln!("[Blocks] ManifestData received for {}", &manifest_cid[..16.min(manifest_cid.len())]);
            match serde_json::from_str::<crate::blocks::FileManifest>(&manifest_json) {
                Err(e) => eprintln!("[Blocks] ManifestData parse error: {}", e),
                Ok(manifest) => {

                    let _ = crate::blocks::save_manifest(&manifest);
                    let blocks_total = manifest.blocks.len() as u32;

                    {
                    let _guard = crate::ledger::TX_MUTEX.lock().await;
                        let mut ledger = tokio::task::spawn_blocking(crate::ledger::Ledger::load)
                            .await.unwrap_or_default();
                        let my_addr    = ledger.address.clone();
                        if let Some(f) = ledger.stored_files.iter_mut().find(|f| f.cid == manifest_cid) {
                            f.key_nonce_hex  = crate::ledger::protect_key_hex(&key_hex64).unwrap_or_else(|_| key_hex64.clone());
                            f.blocks_total   = blocks_total;
                            f.blocks_received = crate::blocks::blocks_received_count(&manifest);
                            f.manifest_cid   = manifest_cid.clone();
                            if f.name.is_empty() { f.name = file_name.clone(); }
                            let _ = tokio::task::spawn_blocking(move || ledger.save()).await;
                        }
                    }

                    let missing = crate::blocks::missing_blocks(&manifest);
                    eprintln!("[Blocks] Need {}/{} blocks for {}", missing.len(), blocks_total, &manifest_cid[..16.min(manifest_cid.len())]);
                    let my_addr    = crate::ledger::Ledger::load().address;
                    let my_ep      = get_public_endpoint().await;
                    let contacts = tokio::task::spawn_blocking(load_contacts)
                        .await.unwrap_or_default();
                    let sender_ep = {
                        let contacts = load_contacts();
                        contacts.iter().find(|c| c.address == from_addr)
                            .map(|c| c.endpoint.clone())
                            .unwrap_or_default()
                    };
                    for block_cid in missing {
                        let req = P2PMessage::BlockRequest {
                            block_cid:          block_cid.clone(),
                            manifest_cid:       manifest_cid.clone(),
                            requester_addr:     my_addr.clone(),
                            requester_endpoint: my_ep.clone(),
                        };

                        if let Some(tx) = crate::p2p::DHT_CMD_TX.get() {
                            let dht_key = format!("ego-block:{}", block_cid);
                            let _ = tx.send(crate::p2p::DhtCommand::GetPeers { key: dht_key });
                        }

                        if !sender_ep.is_empty() {
                            let ep2  = sender_ep.clone();
                            let req2 = req.clone();
                            tokio::spawn(async move {
                                let _ = send_message_any(&[ep2], &req2).await;
                            });
                        }

                        {
                            let from2   = from_addr.clone();
                            let myaddr2 = my_addr.clone();
                            let req3    = req.clone();
                            tokio::spawn(async move {
                                crate::commands::messenger::deposit_in_relay_inbox(
                                    &from2, &myaddr2, &req3,
                                ).await;
                                eprintln!("[Blocks] BlockRequest deposited in sender inbox for {}",
                                    &block_cid[..16.min(block_cid.len())]);
                            });
                        }
                    }

                    {
                        let app2 = app.cloned();
                        let mcid = manifest_cid.clone();
                        tokio::spawn(async move {
                            update_ledger_for_block(&mcid, app2.as_ref()).await;
                        });
                    }
                }
            }
        }

        P2PMessage::BlockRequest { block_cid, manifest_cid, requester_addr, requester_endpoint } => {
            eprintln!("[Blocks] BlockRequest for {} from {}", &block_cid[..16.min(block_cid.len())], requester_addr);
            if crate::blocks::have_block(&block_cid) {
                use base64::Engine as _;
                match crate::blocks::load_block(&block_cid) {
                    Err(e) => eprintln!("[Blocks] BlockRequest: load failed: {}", e),
                    Ok(enc_bytes) => {

                        let enc_b64    = base64::engine::general_purpose::STANDARD.encode(&enc_bytes);
                        let my_addr    = crate::ledger::Ledger::load().address;
                        let ep         = requester_endpoint.clone();
                        let addr       = requester_addr.clone();
                        let response = P2PMessage::BlockData {
                            block_cid:    block_cid.clone(),
                            manifest_cid: manifest_cid.clone(),
                            enc_b64,
                            from_addr:    my_addr.clone(),
                        };
                        tokio::spawn(async move {
                            if let Err(e) = send_message_any(&[ep.clone()], &response).await {
                                eprintln!("[Blocks] BlockData direct failed: {} — inbox", e);
                                crate::commands::messenger::deposit_in_relay_inbox(&addr, &my_addr, &response).await;
                            } else {
                                eprintln!("[Blocks] BlockData sent: {}", &block_cid[..16.min(block_cid.len())]);
                            }
                        });
                    }
                }
            } else {
                eprintln!("[Blocks] BlockRequest: block {} not found", &block_cid[..16.min(block_cid.len())]);
            }
        }

        P2PMessage::BlockData { block_cid, manifest_cid, enc_b64, from_addr: _ } => {
            use base64::Engine as _;
            eprintln!("[Blocks] BlockData received: {}", &block_cid[..16.min(block_cid.len())]);
            match base64::engine::general_purpose::STANDARD.decode(&enc_b64) {
                Err(e) => eprintln!("[Blocks] BlockData decode failed: {}", e),
                Ok(enc_bytes) => {
                    if !crate::blocks::have_block(&block_cid) {
                        let _ = crate::blocks::save_block(&block_cid, &enc_bytes);
                    }

                    let app2 = app.cloned();
                    let mcid = manifest_cid.clone();
                    tokio::spawn(async move {
                        update_ledger_for_block(&mcid, app2.as_ref()).await;
                    });
                }
            }
        }

        P2PMessage::ViewChange { view, voter, signature, timestamp: _ } => {
            let vote_data = format!("viewchange:{}:{}", view, voter);
            let is_valid = match get_peer_ed25519_pubkey(&voter) {
                Some(pk) => {
                    use ed25519_dalek::{Signature as DS, VerifyingKey, Verifier};
                    if let (Ok(vk), Ok(sig_bytes)) = (VerifyingKey::from_bytes(&pk), hex::decode(&signature)) {
                        if let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes.as_slice()) {
                            vk.verify(vote_data.as_bytes(), &DS::from_bytes(&sig_arr)).is_ok()
                        } else { false }
                    } else { false }
                },
                None => known_validators().contains(&voter),
            };
            if is_valid {
                handle_view_change_msg(view, voter).await;
            } else {
                tracing::debug!("[BFT] Invalid ViewChange signature from {}", voter);
            }
        }

        P2PMessage::SlashChallenge {
            accused_addr, cid, block_cid, challenge_slot, comm_r, reporter_addr, reporter_sig
        } => {
            eprintln!("[Slash] SlashChallenge: accused={} cid={} slot={}", accused_addr, &cid[..16.min(cid.len())], challenge_slot);

            // 1. Reject stale challenges (> 12 h old).
            let now  = chrono::Utc::now().timestamp();
            let slot_ts = challenge_slot * crate::proof::POST_CHECK_INTERVAL_SECS;
            if now - slot_ts > 12 * 3600 {
                eprintln!("[Slash] Stale challenge from {} — ignoring", reporter_addr);
                return;
            }

            // 2. Verify reporter's Ed25519 signature using the peer pubkey cache.
            let sign_msg = format!("slash:{}:{}:{}:{}", accused_addr, cid, block_cid, challenge_slot);
            let current_height = crate::chain_db::block_count();
            const SLASH_SIG_ENFORCE_HEIGHT: u64 = 500;
            let sig_valid = match get_peer_ed25519_pubkey(&reporter_addr) {
                Some(pk_bytes) => {
                    use ed25519_dalek::{Signature as DS, VerifyingKey, Verifier};
                    let vk = VerifyingKey::from_bytes(&pk_bytes);
                    let sig_bytes = hex::decode(&reporter_sig).unwrap_or_default();
                    let sig_arr: Result<[u8; 64], _> = sig_bytes.try_into();
                    match (vk, sig_arr) {
                        (Ok(vk), Ok(sa)) => vk.verify(sign_msg.as_bytes(), &DS::from_bytes(&sa)).is_ok(),
                        _ => false,
                    }
                }
                None => {
                    if current_height >= SLASH_SIG_ENFORCE_HEIGHT {
                        eprintln!("[Slash] Unknown reporter {} — rejecting above height {}", reporter_addr, SLASH_SIG_ENFORCE_HEIGHT);
                        false
                    } else {
                        true
                    }
                }
            };
            if !sig_valid {
                eprintln!("[Slash] Invalid reporter signature from {} — ignoring", reporter_addr);
                return;
            }

            // 3a. Cross-check reported comm_r against what we received via StorageCommit gossip.
            //     If the network-known comm_r doesn't match what the reporter claims, reject.
            if let Some(known_comm_r) = get_peer_comm_r(&cid) {
                if !comm_r.is_empty() && known_comm_r != comm_r {
                    eprintln!("[Slash] comm_r mismatch for {} — reporter may be lying (known={} reported={})",
                        &cid[..16.min(cid.len())], &known_comm_r[..16.min(known_comm_r.len())], &comm_r[..16.min(comm_r.len())]);
                    return;
                }
            }

            // 3b. Independent verification: try to fetch the challenged block from accused.
            //    If accused serves the block, verify its comm_r.
            let accused_ep = {
                let contacts = load_contacts();
                contacts.iter().find(|c| c.address == accused_addr)
                    .map(|c| c.endpoint.clone())
                    .unwrap_or_default()
            };
            let my_addr = crate::ledger::Ledger::load().address;
            let my_ep   = get_public_endpoint().await;

            let verification_passed = if !accused_ep.is_empty() {
                // Send a BlockRequest and wait briefly for response via relay inbox.
                let req = P2PMessage::BlockRequest {
                    block_cid:          block_cid.clone(),
                    manifest_cid:       cid.clone(),
                    requester_addr:     my_addr.clone(),
                    requester_endpoint: my_ep.clone(),
                };
                // We deposit and check our inbox — the accused has ~30s to respond.
                // For now we record the slash immediately; a future version can add a
                // wait-and-retract mechanism.
                crate::commands::messenger::deposit_in_relay_inbox(&accused_addr, &my_addr, &req).await;
                false  // assume failed until proven otherwise
            } else {
                false  // can't reach accused — treat as failed
            };

            if !verification_passed {
                // 4. Route slash_storage to the mempool for BFT consensus.
                use crate::ledger::LedgerTx;
            let _guard = crate::ledger::TX_MUTEX.lock().await;
            let mut ledger2 = crate::ledger::Ledger::load();
                let nonce = crate::ledger::Ledger::load().nonce + 1;
                let sign_input = format!("external_slash:{}:{}:{}", my_addr, accused_addr, now);
                let sig_hex = crate::ledger::load_seed().ok().flatten()
                    .and_then(|s| { let mut a=[0u8;32]; a.copy_from_slice(&s[..32]); ego_core::KeyPair::from_bytes(&a).ok() })
                    .map(|kp| hex::encode(kp.sign_ed25519(sign_input.as_bytes()).as_bytes()))
                    .unwrap_or_default();
                let tx_hash = format!("0x{}", ego_core::hash_data(sign_input.as_bytes()).to_hex());
                
                let tx = LedgerTx {
                    hash:            tx_hash.clone(),
                    from:            accused_addr.clone(),
                    to:              "egot1slashpool0000000000000000000000000000000".into(),
                    amount:          0,
                    memo:            Some(format!("external_slash by {} | cid {}", &reporter_addr[..16.min(reporter_addr.len())], &cid[..16.min(cid.len())])),
                    timestamp:       now,
                    signature:       sig_hex,
                    status:          "Pending".into(),
                    block_height:    None,
                    nonce,
                    tx_type:         "slash_storage".into(),
                    cid:             cid.clone(),
                    ..LedgerTx::default()
                };

                ledger2.nonce = nonce;
                let _ = ledger2.save();
                
                let _ = crate::mempool::get_mempool().push(tx.clone());
                tokio::spawn(async move {
                    broadcast_pending_tx(tx).await;
                });
                
                eprintln!("[Slash] Broadcasted external slash to mempool for {} | tx {}", &accused_addr[..16.min(accused_addr.len())], &tx_hash[..18]);
            }
        }

        P2PMessage::StorageCommit { prover_addr, cid, comm_r, signature, .. } => {
            if !prover_addr.is_empty() && !cid.is_empty() && !comm_r.is_empty() {
                record_peer_commitment(&cid, &prover_addr, &comm_r, &signature);
            }
        }

        // ── Item 17: PoRep BLAKE3 spot-check — correct verifiable protocol ─────
        //
        // PROVER side: receives challenge for a specific block it claims to store.
        // Reads the encrypted block from disk, computes BLAKE3(nonce || enc_block),
        // replies with the 32-byte hash (64 hex chars).
        //
        // VERIFIER side: see StorageProofResponse handler below.
        P2PMessage::StorageProofChallenge { manifest_cid, block_cid, nonce, challenger } => {
            let ledger  = crate::ledger::Ledger::load();
            let my_addr = ledger.address.clone();
            // Only respond if we're not the challenger (no self-challenges).
            if my_addr == challenger || my_addr.is_empty() { return; }

            // Respond only if we have this block on disk.
            if !crate::blocks::have_block(&block_cid) { return; }

            let enc_block = match crate::blocks::load_block(&block_cid) {
                Ok(b)  => b,
                Err(e) => {
                    eprintln!("[PoRep] Cannot load block {} for challenge: {}", &block_cid[..block_cid.len().min(16)], e);
                    return;
                }
            };
            let nonce_bytes = hex::decode(&nonce).unwrap_or_default();
            if nonce_bytes.is_empty() { return; }

            let mut hasher = blake3::Hasher::new();
            hasher.update(&nonce_bytes);
            hasher.update(&enc_block);
            let response_hash = hasher.finalize().to_hex().to_string();

            let resp = P2PMessage::StorageProofResponse {
                block_cid:     block_cid.clone(),
                nonce:         nonce.clone(),
                response_hash,
                prover:        my_addr,
            };
            let _ = manifest_cid; // for logging
            if let Ok(data) = serde_json::to_vec(&resp) {
                tokio::spawn(async move {
                    publish_gossip("ego-storage-v1", data).await;
                });
            }
        }

        // VERIFIER side: look up the outstanding challenge and compare hashes.
        P2PMessage::HostingAnnounce { .. } => {}
        P2PMessage::ComputeAnnounce { .. } => {}
        P2PMessage::ComputeJobPost { .. } => {}
        P2PMessage::ComputeJobAccept { .. } => {}
        P2PMessage::ComputeJobComplete { .. } => {}
        P2PMessage::ComputeJobCancel { .. } => {}
        P2PMessage::ComputeHeartbeat { .. } => {}
        P2PMessage::CapacityOfferBroadcast { .. } => {}
        P2PMessage::CapacityOfferCancelled { .. } => {}
        P2PMessage::ClusterBookingCreated { .. } => {}
        P2PMessage::ClusterNodeJoined { .. } => {}
        P2PMessage::ClusterNodeHeartbeat { .. } => {}
        P2PMessage::ClusterTerminated { .. } => {}
        P2PMessage::ReservationBooked { .. } => {}
        P2PMessage::ReservationHeartbeat { .. } => {}
        P2PMessage::ReservationTerminated { .. } => {}
        P2PMessage::StorageDealCreated { .. } => {}
        P2PMessage::StorageDealProof { .. } => {}
        P2PMessage::StorageDealTerminated { .. } => {}
        P2PMessage::EquivocationProof { .. } => {}

        P2PMessage::PocEventBroadcast { .. } => {}

        P2PMessage::PocBeacon { beacon_id, address, machine_id, cell, epoch, timestamp, transport, signature } => {
            handle_poc_beacon(beacon_id, address, machine_id, cell, epoch, timestamp, transport, signature).await;
        }

        P2PMessage::PocWitnessReceipt { beacon_id, beaconer, witness, witness_machine_id, witness_cell, latency_ms, rssi_dbm, timestamp, signature } => {
            handle_poc_witness(beacon_id, beaconer, witness, witness_machine_id, witness_cell, latency_ms, rssi_dbm, timestamp, signature).await;
        }

        P2PMessage::ShardRebalance { .. } => {}

        P2PMessage::ShardTxRoute { shard_id, tx } => {
            let my_addr = crate::ledger::Ledger::load().address;
            let map = crate::sharding::load_shard_map();
            let all_nodes: Vec<String> = map.assignments.iter()
                .map(|a| a.node_address.clone())
                .collect::<std::collections::HashSet<_>>()
                .into_iter().collect();
            let my_shard_ids: Vec<u32> = crate::sharding::my_shards(&my_addr, &map, &all_nodes)
                .into_iter().map(|(id, _)| id).collect();
            if my_shard_ids.contains(&shard_id) {
                        let _ = crate::mempool::get_mempool().push(tx);
            } else {
                tokio::spawn(async move {
                    route_tx_to_shard_master(shard_id, tx).await;
                });
            }
        }

        P2PMessage::StorageProofResponse { block_cid, nonce, response_hash, prover } => {
            let key = format!("{}:{}", block_cid, nonce);
            let result = {
                let mut challenges = outstanding_challenges();
                challenges.remove(&key)
            };
            match result {
                None => {
                    // Not our challenge (another node issued it) — ignore.
                }
                Some(expected) => {
                    if expected.prover != prover {
                        // Response is from a different node than we challenged — ignore.
                        return;
                    }
                    if response_hash == expected.expected_hash {
                        eprintln!(
                            "[PoRep] PASS: {} proved storage of block {} (nonce={:.8}…)",
                            &prover[..prover.len().min(20)],
                            &block_cid[..block_cid.len().min(16)],
                            nonce
                        );
                        let current = crate::poc::get_peer_score(&prover);
                        let boosted  = (current + 5).min(crate::poc::MAX_COVERAGE_SCORE);
                        crate::poc::record_peer_score(&prover, boosted);
                        porep_record_pass(&prover);
                        porep_rejoin_on_pass(&prover, &expected.manifest_cid);
                    } else {
                        eprintln!(
                            "[PoRep] FAIL: {} returned wrong hash for block {} (expected={:.8}… got={:.8}…) — penalising",
                            &prover[..prover.len().min(20)],
                            &block_cid[..block_cid.len().min(16)],
                            expected.expected_hash, response_hash
                        );
                        let current = crate::poc::get_peer_score(&prover);
                        let penalised = current.saturating_sub(500).max(1);
                        crate::poc::record_peer_score(&prover, penalised);
                        let fails = porep_record_fail(&prover);
                        if fails >= POREP_MAX_CONSECUTIVE_FAILS {
                            porep_consecutive_fails().remove(&prover);
                            porep_evict_peer(&prover, &expected.manifest_cid);
                        }
                    }
                }
            }
        }
    }
}

async fn update_ledger_for_block(manifest_cid: &str, app: Option<&tauri::AppHandle<tauri::Wry>>) {
    let Ok(manifest) = crate::blocks::load_manifest(manifest_cid) else { return; };
    let received = crate::blocks::blocks_received_count(&manifest);
    let total    = manifest.blocks.len() as u32;

    let _guard = crate::ledger::TX_MUTEX.lock().await;
    let mut ledger = tokio::task::spawn_blocking(crate::ledger::Ledger::load)
        .await.unwrap_or_default();
    if let Some(f) = ledger.stored_files.iter_mut().find(|f| f.cid == manifest_cid) {
        if f.status == "Failed" { return; } // already timed out; don't overwrite
        let prev = f.blocks_received;
        f.blocks_received = received;
        if received > prev {
            f.last_block_at = chrono::Utc::now().timestamp();
        }
        if received >= total && f.status != "Active" {
            f.status     = "Received".to_string();
            f.local_path = crate::blocks::manifest_path(manifest_cid)
                .to_string_lossy().to_string();
        }
        let _ = tokio::task::spawn_blocking(move || ledger.save()).await;
    }

    if let Some(h) = app {
        let _ = h.emit_all("ego://block-progress", serde_json::json!({
            "manifest_cid": manifest_cid,
            "blocks_received": received,
            "blocks_total": total,
        }));
    }

    if received >= total {
        eprintln!("[Blocks] All {} blocks received for {}", total, &manifest_cid[..16.min(manifest_cid.len())]);
        if let Some(h) = app {
            let _ = h.emit_all("ego://file-downloaded", serde_json::json!({ "cid": manifest_cid }));
        }

        // FIX 1: Register self as a CID holder in the relay registry so any peer
        // can discover us and request blocks directly — not just the original uploader.
        let (cid2, addr2) = (
            manifest_cid.to_string(),
            tokio::task::spawn_blocking(|| crate::ledger::Ledger::load().address).await.unwrap_or_default()
        );
        let expiry2 = crate::ledger::Ledger::load()
            .stored_files.iter().find(|f| f.cid == cid2)
            .map(|f| f.expiry).unwrap_or(0);
        tokio::spawn(async move {
            let endpoint = get_public_endpoint().await;
            if !endpoint.is_empty() && !addr2.is_empty() {
                register_cid_on_relay(&cid2, &addr2, &endpoint).await;
                eprintln!("[Blocks] Registered as holder for {} in relay registry", &cid2[..16.min(cid2.len())]);
            }
        });
    }
}

async fn process_received_manifest(manifest_cid: &str, app: Option<&tauri::AppHandle<tauri::Wry>>) {
    let Ok(manifest) = crate::blocks::load_manifest(manifest_cid) else { return; };
    let total    = manifest.blocks.len() as u32;
    let received = crate::blocks::blocks_received_count(&manifest);

    {
        let _guard = crate::ledger::TX_MUTEX.lock().await;
        let mut ledger = crate::ledger::Ledger::load();
        if let Some(f) = ledger.stored_files.iter_mut().find(|f| f.cid == manifest_cid) {
            if f.status != "Failed" {
                let now = chrono::Utc::now().timestamp();
                f.blocks_total    = total;
                let prev = f.blocks_received;
                f.blocks_received = received;
                f.manifest_cid    = manifest_cid.to_string();
                // Record manifest arrival as first progress timestamp
                if f.last_block_at == 0 || received > prev {
                    f.last_block_at = now;
                }
                if received >= total && f.status != "Active" {
                    f.status     = "Received".to_string();
                    f.local_path = crate::blocks::manifest_path(manifest_cid)
                        .to_string_lossy().to_string();
                }
                let _ = ledger.save();
            }
        }
    }

    if let Some(h) = app {
        let _ = h.emit_all("ego://block-progress", serde_json::json!({
            "manifest_cid": manifest_cid,
            "blocks_received": received,
            "blocks_total": total,
        }));
    }

    if received >= total {
        eprintln!("[Blocks] All {} blocks present at manifest arrival for {}", total, &manifest_cid[..16.min(manifest_cid.len())]);
        if let Some(h) = app {
            let _ = h.emit_all("ego://file-downloaded", serde_json::json!({ "cid": manifest_cid }));
        }
        return;
    }

    let sender_addr = {
        let ledger = tokio::task::spawn_blocking(crate::ledger::Ledger::load).await.unwrap_or_default();
        ledger.stored_files.iter()
            .find(|f| f.cid == manifest_cid)
            .and_then(|f| f.local_path.strip_prefix("sender:"))
            .map(|s| s.to_string())
            .unwrap_or_default()
    };
    let my_addr = crate::ledger::Ledger::load().address;
    let my_ep   = get_public_endpoint().await;
    
    for block_cid in crate::blocks::missing_blocks(&manifest) {

        if let Some(tx) = DHT_CMD_TX.get() {
            let _ = tx.send(DhtCommand::GetPeers { key: format!("ego-block:{}", block_cid) });
        }

        if !sender_addr.is_empty() {
            let req = P2PMessage::BlockRequest {
                block_cid:          block_cid.clone(),
                manifest_cid:       manifest_cid.to_string(),
                requester_addr:     my_addr.clone(),
                requester_endpoint: my_ep.clone(),
            };
            let sender2 = sender_addr.clone();
            let my2     = my_addr.clone();
            let bcid    = block_cid.clone();
            tokio::spawn(async move {
                crate::commands::messenger::deposit_in_relay_inbox(&sender2, &my2, &req).await;
                eprintln!("[Blocks] BlockRequest→inbox for {}", &bcid[..16.min(bcid.len())]);
            });
        }
    }
}

async fn check_block_completes_manifests(block_cid: &str, app: Option<&tauri::AppHandle<tauri::Wry>>) {
    let ledger = tokio::task::spawn_blocking(crate::ledger::Ledger::load)
        .await.unwrap_or_default();
    for file in &ledger.stored_files {
        if file.cid.starts_with("egomfd1") && file.blocks_received < file.blocks_total {
            if let Ok(manifest) = crate::blocks::load_manifest(&file.cid) {
                let has_this = manifest.blocks.iter().any(|b| b.block_cid == block_cid);
                if has_this {
                    let mcid = file.cid.clone();
                    let app2 = app.cloned();
                    tokio::spawn(async move {
                        update_ledger_for_block(&mcid, app2.as_ref()).await;
                    });
                }
            }
        }
    }
}

fn validate_block(block: &crate::ledger::LedgerBlock, _chain: &crate::ledger::SharedChain) -> bool {
    // This is called from a blocking context, so it's fine.
    if block.height == 0 {
        return block.hash == crate::ledger::GENESIS_HASH;
    }

    let parent = crate::chain_db::get_block_by_height(block.height.saturating_sub(1));
    if parent.map(|p| p.hash != block.prev_hash).unwrap_or(true) {
        eprintln!("[Validate] Block #{} rejected: unknown prev_hash {}", block.height, block.prev_hash);
        return false;
    }

    if crate::chain_db::get_block_by_height(block.height).map(|b| b.hash == block.hash).unwrap_or(false) {
        eprintln!("[Validate] Block #{} rejected: hash {:.8} already in chain", block.height, block.hash);
        return false;
    }

    let base_reward = crate::tokenomics::block_reward_at(block.height);
    if block.reward != 0 && block.reward < base_reward / 2 {
        eprintln!("[Validate] Block #{} rejected: reward {} below floor {}",
            block.height, block.reward, base_reward / 2);
        return false;
    }

    // H3: hash verification is UNCONDITIONAL — a block can no longer skip it by
    // presenting an empty tx_merkle_root, and the legacy v1 hash (which committed
    // none of the block's contents) is no longer accepted. Every non-genesis
    // block must match the v2 or v3 hash, both of which commit tx_merkle_root and
    // poc_ticket (v3 also state_root).
    let expected_v2_hash = crate::chain_db::block_hash_for(
        &block.prev_hash, block.height, &block.miner,
        block.timestamp, &block.tx_merkle_root, &block.poc_ticket,
    );

    // v3: state_root committed into hash.
    let expected_v3_hash = if !block.state_root.is_empty() {
        crate::chain_db::block_hash_v3(
            &block.prev_hash, block.height, &block.miner,
            block.timestamp, &block.tx_merkle_root, &block.poc_ticket, &block.state_root,
        )
    } else {
        String::new()
    };
    let valid = block.hash == expected_v2_hash
        || (!expected_v3_hash.is_empty() && block.hash == expected_v3_hash);
    if !valid {
        eprintln!(
            "[Validate] Block #{} rejected: hash mismatch (stored={:.8}… v2={:.8}… v3={:.8}…)",
            block.height, block.hash, expected_v2_hash,
            if expected_v3_hash.is_empty() { "n/a".to_string() } else { expected_v3_hash[..8.min(expected_v3_hash.len())].to_string() }
        );
        return false;
    }

    true
}

async fn apply_incoming_tx(tx: LedgerTx, block: LedgerBlock, app: Option<&tauri::AppHandle<tauri::Wry>>) {
    // We only care about pending mempool transactions over the ego-txs-v1 topic.
    // Full blocks are synced and verified via ego-blocks-v1. Older relay nodes
    // might send TxBroadcast with full blocks, which causes spurious errors.
    if block.height > 0 {
        return;
    }

    if crate::chain_db::get_tx_by_hash(&tx.hash).is_none() {
        if let Err(e) = crate::ledger::verify_incoming_tx(&tx) {
            tracing::debug!("[P2P] Rejected incoming mempool tx {}: {}", tx.hash, e);
            return;
        }
        let _ = crate::mempool::get_mempool().push(tx);
        tokio::spawn(try_proactive_proposal());
    }
}

fn execute_contract_txs(chain: &crate::ledger::SharedChain, txs: &[crate::ledger::LedgerTx]) {
    let height    = chain.blocks.last().map(|b| b.height).unwrap_or(0);
    let timestamp = chrono::Utc::now().timestamp();
    let contracts_dir = crate::ledger::contracts_dir();

    let exec = match ego_vm::Executor::new(contracts_dir) {
        Ok(e)  => e,
        Err(e) => { eprintln!("[VM] Executor init failed: {}", e); return; }
    };

    for tx in txs {
        match tx.tx_type.as_str() {
            "deploy" => {
                if tx.wasm_code.is_empty() { continue; }
                let wasm_bytes = match hex::decode(&tx.wasm_code) {
                    Ok(b)  => b,
                    Err(_) => continue,
                };
                let init_args = hex::decode(&tx.call_args).unwrap_or_default();
                match exec.deploy(&wasm_bytes, &tx.from, &init_args, height, timestamp,
                                  ego_vm::types::DEFAULT_DEPLOY_FUEL) {
                    Ok(r)  => eprintln!("[VM] Deployed contract {} (RU={})", r.contract_address, r.ru_used),
                    Err(e) => eprintln!("[VM] Deploy failed for tx {}: {}", tx.hash, e),
                }
            }
            "call" => {
                if tx.contract_addr.is_empty() || tx.entrypoint.is_empty() { continue; }
                let call_args = hex::decode(&tx.call_args).unwrap_or_default();
                match exec.call(&tx.contract_addr, &tx.from, &tx.entrypoint,
                                &call_args, height, timestamp,
                                ego_vm::types::DEFAULT_CALL_FUEL) {
                    Ok(r)  => eprintln!("[VM] Called {}.{}() — success={} RU={}",
                                        tx.contract_addr, tx.entrypoint, r.success, r.ru_used),
                    Err(e) => eprintln!("[VM] Call failed for tx {}: {}", tx.hash, e),
                }
            }
            "governance" => {

                handle_governance_tx(&tx);
            }
            _ => {}
        }
    }
}

fn handle_governance_tx(tx: &LedgerTx) {
    // Only registered validators may vote.
    if !known_validators().contains(&tx.from) {
        eprintln!("[Governance] Rejected vote from non-validator {}", tx.from);
        return;
    }

    let feature     = &tx.contract_addr;
    let action      = &tx.entrypoint;
    let activate_at = tx.amount; // block height encoded as amount

    if feature.is_empty() || (action != "enable" && action != "disable") {
        eprintln!("[Governance] Malformed governance tx from {}", tx.from);
        return;
    }

    let proposal = crate::chain_db::record_governance_vote(feature, action, activate_at, &tx.from);
    let threshold = bft_threshold();

    eprintln!("[Governance] Vote '{}:{}' from {} ({}/{} needed, activates at block {})",
        action, feature, tx.from, proposal.votes.len(), threshold, activate_at);

    // Activate once both node-count AND stake-weight quorums are reached.
    if !proposal.activated
        && proposal.votes.len() >= threshold
        && stake_quorum_reached(&proposal.votes)
    {
        crate::chain_db::activate_feature(feature, action);
        eprintln!("[Governance] ✓ '{}' {} approved — takes effect at block {}",
            feature, action, activate_at);
    }
}

async fn request_gap_backfill(from_height: u64, source_peer_id: &str) {
    let my_endpoint = get_public_endpoint().await;
    let msg = P2PMessage::ChainSyncRequest { requester_endpoint: my_endpoint, from_height };
    for ep in load_peer_cache().into_iter().map(|p| p.endpoint) {
        if !ep.is_empty() && ep.contains(source_peer_id) {
            let _ = send_message(&ep, &msg).await;
            return;
        }
    }
    if let Ok(data) = serde_json::to_vec(&msg) {
        publish_gossip("ego-sync-v1", data).await;
    }
}

pub async fn request_snapshot_from_peers(have_height: u64) {
    let my_endpoint = get_public_endpoint().await;
    if my_endpoint.is_empty() { return; }
    let msg = P2PMessage::SnapshotRequest { requester_endpoint: my_endpoint, have_height };
    if let Ok(data) = serde_json::to_vec(&msg) {
        publish_gossip("ego-snapshot-v1", data).await;
    }
}

async fn merge_remote_chain(
    blocks: Vec<LedgerBlock>, transactions: Vec<LedgerTx>, app: Option<&tauri::AppHandle<tauri::Wry>>,
) {
    merge_remote_chain_inner(blocks, transactions, app, false).await;
}

async fn merge_remote_chain_trusted(
    blocks: Vec<LedgerBlock>, transactions: Vec<LedgerTx>, app: Option<&tauri::AppHandle<tauri::Wry>>,
) {
    merge_remote_chain_inner(blocks, transactions, app, true).await;
}

fn merge_remote_chain_blocking(
    mut blocks: Vec<LedgerBlock>,
    transactions: Vec<LedgerTx>,
    trusted: bool,
) -> (bool, bool) {
    // Fork detection at the boundary: if the first block's parent doesn't match our local history.
    if let Some(first) = blocks.first() {
        if first.height > 1 {
            if let Some(lph) = crate::chain_db::get_block_hash_at(first.height - 1) {
                if lph != first.prev_hash {
                    // We diverged somewhere BEFORE the first block in this set.
                    // Trigger a deeper sync to find the common ancestor.
                    tracing::debug!("[P2P] Fork detected at boundary: block #{} prev_hash {} != local #{} hash {}. Syncing...", 
                        first.height, first.prev_hash, first.height - 1, lph);
                    return (false, true);
                }
            }
        }
    }

    let mut unique_txs = Vec::new();
    let mut seen_tx_hashes = std::collections::HashSet::new();
    for tx in transactions {
        if seen_tx_hashes.insert(tx.hash.clone()) {
            unique_txs.push(tx);
        }
    }

    let mut new_txs: Vec<LedgerTx> = Vec::new();
    let mut new_blocks: Vec<LedgerBlock> = Vec::new();
    let mut peer_ahead = false;

    if trusted {
        blocks.sort_unstable_by_key(|b| b.height);

        let diverge_height: Option<u64> = blocks.iter()
            .filter(|b| b.height > 0)
            .find(|b| {
                crate::chain_db::get_block_by_height(b.height)
                    .map(|local| local.hash != b.hash)
                    .unwrap_or(false)
            })
            .map(|b| b.height);

        if let Some(dh) = diverge_height {
            let last_hard = {
                let hard_final = hard_finalized_heights();
                hard_final.iter().max().copied().unwrap_or(0)
            };
            if dh <= last_hard {
                // Only protect local chain if it MATCHES the BFT-finalized hash at dh.
                // If local chain has a different block at dh than what was finalized,
                // we are on the wrong fork and should accept the oracle's canonical chain.
                let finalized_hash = finalized_at_height().get(&dh).cloned();
                let local_hash     = crate::chain_db::get_block_by_height(dh).map(|b| b.hash);
                let oracle_hash    = blocks.iter().find(|b| b.height == dh).map(|b| b.hash.clone());
                let local_is_finalized_chain = finalized_hash.is_some() && finalized_hash == local_hash;
                let oracle_matches_finalized  = finalized_hash.is_some() && finalized_hash == oracle_hash;

                if local_is_finalized_chain && !oracle_matches_finalized {
                    let now = chrono::Utc::now().timestamp();
                    let last_fin = LAST_BLOCK_FINALIZED_TS.load(Ordering::Relaxed);
                    let stuck_secs = now - last_fin;
                
                // If we have very few validators (solo fork), override local finality 
                // much faster (30s) so a non-technical user doesn't stay stuck.
                let override_timeout = if known_validator_count() < 3 { 30 } else { 120 };

                if last_fin > 0 && stuck_secs > override_timeout {
                        eprintln!(
                            "[Oracle] Chain stuck for {}s — overriding hard-finality at height {} to adopt oracle fork",
                            stuck_secs, dh
                        );
                        { hard_finalized_heights().retain(|&h| h < dh); }
                        { finalized_at_height().retain(|&h, _| h < dh); }
                        for tx in crate::chain_db::truncate_from(dh) {
                            let _ = crate::mempool::get_mempool().push(tx);
                        }
                    } else {
                        tracing::debug!(
                            "[Oracle] Reorg blocked at height {} — local chain matches BFT-finalized block (oracle is on different fork)",
                            dh
                        );
                    }
                } else {
                    // Local chain diverges from what BFT actually finalized, or oracle
                    // is offering the finalized block — accept the reorg.
                    tracing::info!(
                        "[BFT/Oracle] Reorg: adopting canonical trusted block at height {} (local was on wrong fork)",
                        dh
                    );
                    { hard_finalized_heights().retain(|&h| h < dh); }
                    { finalized_at_height().retain(|&h, _| h < dh); }
                    for tx in crate::chain_db::truncate_from(dh) {
                        let _ = crate::mempool::get_mempool().push(tx);
                    }
                }
            } else {
                eprintln!("[BFT/Oracle] Reorg: trusted blocks diverge from local chain at height {} — truncating to adopt", dh);
                for tx in crate::chain_db::truncate_from(dh) {
                    let _ = crate::mempool::get_mempool().push(tx);
                }
            }
        }

        for block in blocks {
            if block.height == 0 { continue; }
                
                let parent_height = block.height - 1;
                let has_parent = parent_height == 0 
                    || crate::chain_db::get_block_by_height(parent_height).is_some() 
                    || new_blocks.iter().any(|b| b.height == parent_height);
                
                if !has_parent {
                    static LAST_DEFER_LOG: AtomicI64 = AtomicI64::new(0);
                    let now = Utc::now().timestamp();
                    let last = LAST_DEFER_LOG.load(Ordering::Relaxed);
                    
                    if now - last > 5 { // Only log deferral every 5 seconds
                        tracing::info!("[P2P] Blocks starting at #{} deferred (syncing missing parents...)", block.height);
                        LAST_DEFER_LOG.store(now, Ordering::Relaxed);
                    }
                    peer_ahead = true;
                    continue; // Skip appending this block until parent is synced
                }

            if crate::chain_db::get_block_by_height(block.height).is_none() {
                new_blocks.push(block);
            }
        }
    } else {
        blocks.sort_unstable_by_key(|b| b.height);

        let remote_tip = blocks.iter().filter(|b| b.height > 0).map(|b| b.height).max().unwrap_or(0);
        let (local_tip, local_tip_hash) = crate::chain_db::latest_block_info();

        let mut should_reorg = false;
        let diverge_height: Option<u64> = blocks.iter()
            .filter(|b| b.height > 0)
            .find(|b| crate::chain_db::get_block_by_height(b.height)
                .map(|loc| loc.hash != b.hash).unwrap_or(false))
            .map(|b| b.height);

        if let Some(dh) = diverge_height {
            let remote_has_quorum = blocks.iter().any(|b| b.height >= dh && b.vote_count >= 2);
            let is_remote_longer = remote_tip > local_tip;

            // How many confirmed local blocks would this reorg delete.
            let reorg_depth = local_tip.saturating_sub(dh) + 1;
            // A single-block lead is never enough justification to reorg more than
            // MAX_SAFE_REORG_DEPTH blocks. The remote must be ahead by at least half
            // the reorg depth — so wiping 100 blocks requires 50-block lead, not 1.
            const MAX_SAFE_REORG_DEPTH: u64 = 50;
            let remote_lead = remote_tip.saturating_sub(local_tip);
            let deep_reorg_allowed = reorg_depth <= MAX_SAFE_REORG_DEPTH
                || remote_lead >= reorg_depth / 2
                || remote_has_quorum && remote_lead >= 10;

            if !deep_reorg_allowed {
                eprintln!("[P2P] Deep reorg ({} blocks from height {}) blocked: remote lead {} is too small (need ≥{})",
                    reorg_depth, dh, remote_lead, reorg_depth / 2);
                return (false, false);
            }

            if is_remote_longer || (remote_tip == local_tip && remote_has_quorum) {
                should_reorg = true;
            } else if remote_tip == local_tip {
                // Tie-breaker for symmetric forks: compare hashes to guarantee convergence
                if let Some(local_div_block) = crate::chain_db::get_block_by_height(dh) {
                    if let Some(remote_div_block) = blocks.iter().find(|b| b.height == dh) {
                        if remote_div_block.vote_count > local_div_block.vote_count
                            || (remote_div_block.vote_count == local_div_block.vote_count
                                && remote_div_block.hash > local_div_block.hash)
                        {
                            should_reorg = true;
                        }
                    }
                }
            }

            if should_reorg {
                peer_ahead = true;
                let hard_set = hard_finalized_heights();
                let last_hard = hard_set.iter().max().copied().unwrap_or(0);
                drop(hard_set);

                // Never override hard-finality for deep reorgs, regardless of vote status.
                // (Previously local_is_solo could trigger this — that's the bug that let
                // fresh nodes wipe hundreds of confirmed blocks.)
                let remote_is_heavier = remote_tip > local_tip + 10;
                let override_hard = dh <= last_hard
                    && (remote_has_quorum || remote_tip > local_tip + 20)
                    && remote_is_heavier
                    && reorg_depth <= MAX_SAFE_REORG_DEPTH;

                if dh > last_hard || override_hard {
                    if override_hard {
                        eprintln!("[P2P] BFT Override: Remote has quorum, bypassing hard-finality at {}", last_hard);
                        { hard_finalized_heights().retain(|&h| h < dh); }
                        { finalized_at_height().retain(|&h, _| h < dh); }
                    }
                    eprintln!("[P2P] Reorg: remote tip {} >= local {}, truncating {} blocks from height {}",
                        remote_tip, local_tip, reorg_depth, dh);
                    for tx in crate::chain_db::truncate_from(dh) {
                        let _ = crate::mempool::get_mempool().push(tx);
                    }
                } else {
                    eprintln!("[P2P] Reorg at height {} blocked — hard-finalized at {}", dh, last_hard);
                    return (false, false);
                }
            } else {
                eprintln!("[P2P] Ignoring weaker divergent chain from peer (local tip {} >= remote {}).", local_tip, remote_tip);
                return (false, false);
            }
        }

        for block in blocks {
            if block.height == 0 { continue; }

            if block.height > 0 {
                let parent_height = block.height - 1;
                let has_parent = parent_height == 0 
                    || crate::chain_db::get_block_by_height(parent_height).is_some() 
                    || new_blocks.iter().any(|b: &LedgerBlock| b.height == parent_height);
                
                let expected_prev = if parent_height == 0 {
                    crate::ledger::GENESIS_HASH.to_string()
                } else if parent_height == local_tip {
                    local_tip_hash.clone()
                } else if let Some(parent) = new_blocks.last() {
                    parent.hash.clone()
                } else if let Some(parent) = crate::chain_db::get_block_by_height(parent_height) {
                    parent.hash.clone()
                } else if let Some(parent) = new_blocks.iter().find(|b| b.height == parent_height) {
                    parent.hash.clone()
                } else {
                    block.prev_hash.clone()
                };

                if !has_parent && block.height > local_tip {
                    tracing::debug!("[P2P] Missing parent for block #{}, forcing sync from peers", block.height);
                    peer_ahead = true;
                    continue; 
                }

                if block.prev_hash != expected_prev {
                    tracing::debug!(
                        "[P2P] Block #{} rejected: prev_hash mismatch. Forcing sync to resolve fork.",
                        block.height
                    );
                    peer_ahead = true;
                    continue;
                }
            }

            if let Some(existing) = crate::chain_db::get_block_by_height(block.height) {
                if existing.hash == block.hash { continue; }
            }

            let base_reward = crate::tokenomics::block_reward_at(block.height);
            let reward_ok = crate::chain_db::emission_v2_active(block.height)
                || block.reward == 0
                || block.reward >= base_reward / 2;
            if !reward_ok {
                tracing::debug!("[P2P] Block #{} rejected: reward {} below base {}",
                    block.height, block.reward, base_reward);
                continue;
            }

            let mut parts = block.poc_ticket.splitn(2, ':');
            let ticket_hex = parts.next().unwrap_or("");
            let sig_hex    = parts.next().unwrap_or("");
            if !crate::poc::verify_ticket(
                ticket_hex, sig_hex, &block.miner, &block.prev_hash, block.poc_slot, block.height,
            ) {
                tracing::debug!("[P2P] Block #{} rejected: invalid PoC ticket", block.height);
                continue;
            }

            let mut block_txs: Vec<LedgerTx> = {
                let mut seen = std::collections::HashSet::new();
                unique_txs.iter()
                    .filter(|tx| tx.block_height == Some(block.height))
                    .filter(|tx| seen.insert(tx.hash.clone()))
                    .cloned()
                    .collect()
            };
            let claimed = block.tx_count as usize;
            if block_txs.len() > claimed {
                let cb_hash = block.coinbase_tx.as_deref().unwrap_or("").to_string();
                block_txs.sort_by_key(|tx| {
                    if tx.hash == cb_hash { 0u8 }
                    else if crate::ledger::is_protocol_system_tx(tx) { 1 }
                    else { 2 }
                });
                block_txs.truncate(claimed);
            }
            if let Err(reason) = crate::chain_db::validate_peer_block(&block, &block_txs) {
                let now = Utc::now().timestamp();
                let key = (block.height, reason[..reason.len().min(40)].to_string());
                let mut last_map = BLOCK_REJECT_LAST.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
                let last = last_map.get(&key).copied().unwrap_or(0);
                if now - last >= BLOCK_REJECT_LOG_COOLDOWN_SECS {
                    if reason.contains("missing local parent") || reason.contains("invalid PoC ticket") {
                        tracing::debug!("[P2P] Block #{} rejected: {}", block.height, reason);
                    } else {
                        tracing::warn!("[P2P] Block #{} rejected: {}", block.height, reason);
                    }
                    last_map.insert(key, now);
                }
                continue;
            }

            // Write immediately so the next block's parent check finds this block in the DB.
            if !trusted {
                let block_txs_now: Vec<LedgerTx> = block_txs.iter()
                    .filter(|tx| crate::ledger::verify_confirmed_tx_sig(tx).is_ok())
                    .cloned()
                    .collect();
                if !crate::chain_db::append_trusted_block(&block, &block_txs_now) {
                    continue;
                }
            }
            new_blocks.push(block);
        }
    }

    let accepted_heights: std::collections::HashSet<u64> =
        new_blocks.iter().map(|b| b.height).collect();
    for tx in unique_txs {
        if let Some(h) = tx.block_height {
            if !accepted_heights.contains(&h) {
                continue;
            }
        }
        let verify_result = if tx.block_height.is_some() {
            crate::ledger::verify_confirmed_tx_sig(&tx)
        } else {
            crate::ledger::verify_incoming_tx(&tx)
        };
        match verify_result {
            Ok(())      => new_txs.push(tx),
            Err(reason) => eprintln!("[P2P] Sync TX {} rejected — {}", tx.hash, reason),
        }
    }

    if new_blocks.is_empty() && new_txs.is_empty() { return (false, peer_ahead); }

    for block in &new_blocks {
        let block_txs: Vec<LedgerTx> = new_txs.iter()
            .filter(|tx| tx.block_height == Some(block.height))
            .cloned()
            .collect();
        if trusted {
            if !crate::chain_db::append_trusted_block(block, &block_txs) {
                continue;
            }
        }
        for tx in block_txs.iter() {
            if !tx.hash.is_empty() {
                crate::commands::tx_pending::remove(&tx.hash);
            }
            if !tx.from.is_empty() && tx.from != crate::chain_db::NODE_POOL_ADDR {
            tracing::debug!("[TX] {:.12} Confirmed — block #{}", tx.hash, block.height);
            }
        }
    }

    if let Some(max_height) = new_blocks.iter().map(|b| b.height).max() {
        tracing::info!("[Sync] Synced to block #{} — touching proposal timestamp", max_height);
        touch_proposal_timestamp();
    }

    let pool = crate::mempool::get_mempool();
    for tx in &new_txs {
        let is_user_tx = !tx.from.is_empty() && tx.from != crate::chain_db::NODE_POOL_ADDR
            && !tx.hash.is_empty()
            && crate::chain_db::get_tx_by_hash(&tx.hash).is_none()
            && !new_blocks.iter().any(|b| Some(b.height) == tx.block_height);
        if is_user_tx { let _ = pool.push(tx.clone()); }
    }

    if let Some(tip) = new_blocks.iter().max_by_key(|b| b.height) {
        crate::rpc::notify_new_block(tip);
    }

    (true, peer_ahead)
}

async fn merge_remote_chain_inner(
    blocks: Vec<LedgerBlock>, transactions: Vec<LedgerTx>, app: Option<&tauri::AppHandle<tauri::Wry>>,
    trusted: bool,
) {
    if let Some(max_h) = blocks.iter().map(|b| b.height).max() {
        note_network_height(max_h);
    }
    let received_full_chunk = blocks.len() >= 500;

    let (any_new, peer_ahead) = tokio::task::spawn_blocking(move || {
        merge_remote_chain_blocking(blocks, transactions, trusted)
    }).await.unwrap_or((false, false));

    if any_new {
        // If the remote chain advanced past our staged block's height, that block
        // lost fork-choice. Return its TXs to the mempool before it gets discarded.
        let new_tip = crate::chain_db::latest_block_info().0;
        {
            let mut staged = staged_block();
            if let Some((b, stamped)) = staged.as_ref() {
                // Clear staged block if it's already in the chain OR if it's 
                // way in the future (lost context due to reorg)
                if b.height <= new_tip || b.height > new_tip + 1 {
                    let pool = crate::mempool::get_mempool();
                    for tx in stamped.iter().filter(|t| !t.from.is_empty() && t.from != crate::chain_db::NODE_POOL_ADDR) {
                        if crate::chain_db::get_tx_by_hash(&tx.hash).is_none() {
                            eprintln!("[Sync] TX {:.12} returned to mempool — staged block #{} superseded by remote tip #{}", tx.hash, b.height, new_tip);
                            let mut pending_tx = tx.clone();
                            pending_tx.status = "Pending".to_string();
                            pending_tx.block_height = None;
                            let _ = pool.push(pending_tx);
                        }
                    }
                    staged.take();
                }
            }
        }
        if let Some(h) = app {
            let _ = h.emit_all("ego://chain-updated", ());
        }
        tokio::spawn(try_proactive_proposal());

        if oracle_push_enabled() {
            let tip_h = crate::chain_db::latest_block_info().0;
            tokio::spawn(async move {
                let fetched = tokio::task::spawn_blocking(move || {
                    crate::chain_db::get_block_by_height(tip_h)
                        .map(|b| (b, crate::chain_db::get_txs_for_block(tip_h)))
                }).await.ok().flatten();
                if let Some((b, txs)) = fetched {
                    push_block_to_oracle(&b, &txs).await;
                }
            });
        }
    }

    if peer_ahead || received_full_chunk {
        tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
            sync_chain_from_peers().await;
        });
    }
    if peer_ahead {
        ORACLE_GAP_FILL_NEEDED.store(true, Ordering::Relaxed);
    }
}


/// Oracle-backed peer rendezvous. Registers THIS node's dialable relayed
/// endpoint with the oracle and dials every other registered node, so two
/// NAT'd machines behind the same relay actually find and connect to each
/// other (otherwise each runs an isolated solo chain — "Active Nodes: 1" — and
/// transactions never cross). Pure-P2P DHT discovery alone was not bridging
/// remote nodes; this is the reliable centralized fallback for the testnet.
/// Dial the always-on public validator anchors directly. Cheap + idempotent —
/// libp2p ignores a dial to an already-connected peer and self-rejects our own
/// address, so it's safe to call on startup and on every discovery tick.
pub async fn dial_bootstrap_peers() {
    let Some(tx) = SWARM_TX.get() else { return };
    let mut dialed = 0usize;
    for ep in BOOTSTRAP_PEERS {
        let addr: Multiaddr = match ep.parse() { Ok(a) => a, Err(_) => continue };
        let (rtx, _rrx) = oneshot::channel();
        if tx.send(SwarmCmd::Dial { peer_addr: addr, reply: rtx }).await.is_ok() {
            dialed += 1;
        }
    }
    if dialed > 0 {
        eprintln!("[P2P] dialed {} direct bootstrap peer(s)", dialed);
    }
}

pub async fn oracle_peer_discovery_tick() {
    dial_bootstrap_peers().await;

    let my_ep = get_public_endpoint().await;
    let allow_direct = std::env::var("EGO_DIRECT_PEERS").is_ok();
    let my_ep_dialable = my_ep.contains("/p2p-circuit")
        || IS_PUBLIC_REACHABLE.load(Ordering::Relaxed)
        || (allow_direct && !my_ep.is_empty());

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    if my_ep_dialable {
        oracle_post_pub(&client, "/nodes/register",
            &serde_json::json!({ "endpoint": my_ep })).await;
    }

    #[derive(serde::Deserialize, Default)]
    struct NodesResp { nodes: Vec<String> }
    let resp = match oracle_get(&client, "/nodes").await {
        Some(r) => r.json::<NodesResp>().await.unwrap_or_default(),
        None => return,
    };

    let Some(tx) = SWARM_TX.get() else { return };
    let mut dialed = 0usize;
    for ep in resp.nodes {
        let ep = ep.trim_end_matches('/').to_string();
        if ep.is_empty() || ep == my_ep { continue; }
        let is_circuit = ep.contains("/p2p-circuit");
        let is_private = ep.contains("/ip4/127.")
            || ep.contains("/ip4/10.")
            || ep.contains("/ip4/192.168.")
            || ep.contains("/ip4/169.254.")
            || ep.contains("/ip6/::1");
        if !is_circuit && is_private && !allow_direct { continue; }
        let addr: Multiaddr = match ep.parse() { Ok(a) => a, Err(_) => continue };
        let (rtx, _rrx) = oneshot::channel();
        if tx.send(SwarmCmd::Dial { peer_addr: addr, reply: rtx }).await.is_ok() {
            dialed += 1;
        }
    }
    if dialed > 0 {
        eprintln!("[Oracle] peer discovery: dialed {} peer(s) from oracle registry", dialed);
    }
}


pub(crate) fn get_ed25519_seed() -> Option<[u8; 32]> {
    if let Ok(cache) = SEED_CACHE.read() {
        if let Some(seed) = *cache {
            return Some(seed);
        }
    }
    if let Ok(Some(bytes)) = crate::ledger::load_seed() {
        if bytes.len() >= 32 {
            let mut a = [0u8; 32];
            a.copy_from_slice(&bytes[..32]);
            if let Ok(mut cache) = SEED_CACHE.write() { *cache = Some(a); }
            return Some(a);
        }
    }
    None
}

fn bft_sign(data: &str) -> Option<String> {
    use ed25519_dalek::{SigningKey, Signer};
    let seed_bytes = crate::ledger::load_seed().ok().flatten()?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let sig = SigningKey::from_bytes(&seed).sign(data.as_bytes());
    Some(hex::encode(sig.to_bytes()))
}

fn bls_vote_fields(block_hash_bytes: &[u8]) -> (String, String) {
    match BLS_SECRET_KEY.get() {
        Some(sk) => {
            let sig = crate::bls_agg::bls_sign(sk, block_hash_bytes);
            let pk  = crate::bls_agg::bls_pubkey(sk);
            (hex::encode(sig), hex::encode(pk))
        }
        None => (String::new(), String::new()),
    }
}

fn attach_local_qc_if_missing(block: &mut crate::ledger::LedgerBlock) {
    if !block.agg_bls_sig.is_empty() && !block.bls_pubkeys.is_empty() {
        return;
    }
    let collected: HashMap<String, Vec<u8>> = match pending_bls_sigs().get(&block.hash) {
        Some(e) if !e.is_empty() => e.clone(),
        _ => return,
    };
    let pks = peer_bls_pubkeys();
    let mut pk_list: Vec<String> = Vec::new();
    let mut sig_list: Vec<Vec<u8>> = Vec::new();
    for (voter, sig) in collected.iter() {
        if let Some(pk) = pks.get(voter) {
            pk_list.push(hex::encode(pk));
            sig_list.push(sig.clone());
        }
    }
    drop(pks);
    if sig_list.is_empty() {
        return;
    }
    if let Ok(agg) = crate::bls_agg::aggregate_signatures(&sig_list) {
        block.agg_bls_sig = hex::encode(&agg);
        block.bls_pubkeys = pk_list;
    }
}

/// Emit a one-time on-chain `validator_register` tx binding this node's address
/// to its BLS public key (memo `valreg:<bls_hex>:<bind_sig_hex>`, where bind_sig
/// is the Ed25519 signature over the BLS pubkey bytes). The oracle and other
/// nodes use this to know which validator a QC's BLS key belongs to, and thus
/// its stake weight. Skips if an identical registration is already on-chain.
pub fn is_observer() -> bool {
    std::env::var("EGO_OBSERVER")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub fn maybe_emit_validator_registration() {
    if is_observer() { return; }
    let seed = match get_ed25519_seed() { Some(s) => s, None => return };
    let bls_sk = match BLS_SECRET_KEY.get() { Some(s) => s, None => return };
    let ledger = crate::ledger::Ledger::load();
    let addr = ledger.address.clone();
    if addr.is_empty() { return; }

    if crate::chain_db::emission_v2_active(crate::chain_db::latest_block_info().0.saturating_add(1)) {
        let floor = min_validator_stake_uegoc();
        let staked = crate::ledger::get_validator_stake(&addr);
        if staked < floor {
            eprintln!(
                "[Validator] Registration deferred — stake {} uEGOC below the {} uEGOC floor (stake first; registration carries emission weight under emission v2)",
                staked, floor
            );
            return;
        }
    }

    let bls_pk_hex = hex::encode(crate::bls_agg::bls_pubkey(bls_sk));
    let bls_pk_bytes = crate::bls_agg::bls_pubkey(bls_sk);
    use ed25519_dalek::{SigningKey, Signer};
    let sk = SigningKey::from_bytes(&seed);
    let ed_pk_hex = hex::encode(sk.verifying_key().as_bytes());
    let bind_sig_hex = hex::encode(sk.sign(&bls_pk_bytes).to_bytes());
    let memo = format!("valreg:{}:{}", bls_pk_hex, bind_sig_hex);

    // Skip if we already registered this exact BLS key on-chain.
    let already = crate::chain_db::get_tx_history_for_addr(&addr)
        .into_iter()
        .any(|tx| tx.tx_type == "validator_register"
            && tx.memo.as_deref() == Some(memo.as_str()));
    if already { return; }

    let nonce = ledger.nonce + 1;
    let ts = chrono::Utc::now().timestamp();
    let sign_bytes = crate::ledger::tx_signing_bytes_v2(&addr, &addr, 0, nonce, ts, 1, &memo);
    let signature = hex::encode(sk.sign(&sign_bytes).to_bytes());
    let hash = format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex());

    let tx = crate::ledger::LedgerTx {
        hash,
        from: addr.clone(),
        to: addr.clone(),
        amount: 0,
        fee_uegoc: 0,
        memo: Some(memo),
        timestamp: ts,
        status: "Pending".into(),
        nonce,
        public_key_ed25519: ed_pk_hex,
        signature,
        tx_type: "validator_register".into(),
        tx_version: 2,
        chain_id: 1,
        ..crate::ledger::LedgerTx::default()
    };

    match crate::mempool::get_mempool().push(tx) {
        Ok(()) => {
            let mut l = crate::ledger::Ledger::load();
            l.nonce = nonce;
            let _ = l.save();
            eprintln!("[Validator] Emitted on-chain registration binding {} ↔ BLS key", &addr[..addr.len().min(16)]);
        }
        Err(e) => eprintln!("[Validator] Registration NOT emitted: {}", e),
    }
}

fn proposal_signing_data(block_hash: &str, height: u64) -> String {
    format!("proposal:{}:{}", block_hash, height)
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum ProposalAuth {
    Valid,
    Disqualified,
    Invalid,
}

fn verify_block_proposal_auth(
    block: &LedgerBlock,
    proposer: &str,
    signature: &str,
    vrf_ticket: &str,
) -> ProposalAuth {
    if proposer.is_empty() || proposer != block.miner {
        eprintln!("[BFT] Proposal rejected: proposer does not match block miner");
        return ProposalAuth::Invalid;
    }
    if !known_validators().contains(proposer) {
        eprintln!("[BFT] Proposal rejected: proposer {} is not a confirmed validator", proposer);
        return ProposalAuth::Invalid;
    }
    let sig_data = proposal_signing_data(&block.hash, block.height);
    if signature.is_empty() || !verify_bft_sig(proposer, &sig_data, signature) {
        eprintln!("[BFT] Proposal #{} rejected: invalid proposer signature from {}", block.height, proposer);
        return ProposalAuth::Invalid;
    }
    // Small committees (≤10) elect the proposer by deterministic ROUND-ROBIN, not
    // by VRF. The proposer is already authenticated above by its Ed25519 proposal
    // signature + validator membership, so the VRF ticket is NOT the authority
    // here — and verifying it as if it were caused a fatal false-negative under
    // burst load (a transiently mismatched ticket made a node reject the genuine
    // round-robin leader's block, then propose its own competing one → dueling
    // proposers → split votes → deadlock). Only the VRF-election regime (>10
    // validators) gates on the ticket.
    let all_validators: Vec<String> = known_validators().iter().cloned().collect();
    if all_validators.len() <= 10 {
        return ProposalAuth::Valid;
    }

    let ticket_bytes = match hex::decode(vrf_ticket) {
        Ok(bytes) => bytes,
        Err(_) => {
            eprintln!("[BFT] Proposal #{} rejected: malformed proposer VRF ticket", block.height);
            return ProposalAuth::Invalid;
        }
    };
    let pubkey = match get_peer_ed25519_pubkey(proposer) {
        Some(pk) => pk,
        None => {
            tracing::debug!("[BFT] Proposal #{}: Ed25519 key for {} not yet cached — skipping VRF check", block.height, proposer);
            return ProposalAuth::Valid;
        }
    };
    let vrf_in = crate::bft_committee::vrf_input(
        &block.prev_hash,
        block.height,
        crate::bft_committee::VRF_ROLE_PROPOSER,
    );
    if !crate::bft_committee::verify_vrf_ticket(&pubkey, &vrf_in, &ticket_bytes) {
        eprintln!("[BFT] Proposal #{} rejected: invalid proposer VRF signature", block.height);
        return ProposalAuth::Invalid;
    }
    // Use only warmed validators for DRS share so newly-discovered relay
    // nodes don't dilute the share and cause spurious "did not qualify" rejections.
    let n_warmed = warmed_validator_count();
    let drs_validators: Vec<String> = {
        let now   = chrono::Utc::now().timestamp();
        let first = validator_first_seen();
        let all   = known_validators();
        let warmed: Vec<String> = all.iter()
            .filter(|addr| first.get(*addr).map(|&t| now - t >= VALIDATOR_WARMUP_SECS).unwrap_or(false))
            .cloned()
            .collect();
        if warmed.is_empty() { all.iter().cloned().collect() } else { warmed }
    };
    let proposer_drs = crate::bft_committee::compute_drs_weight(proposer);
    let total_drs = crate::bft_committee::total_drs_weight(&drs_validators);

    if !crate::bft_committee::qualifies_proposer_for_network(
        &ticket_bytes,
        proposer_drs,
        total_drs,
        n_warmed,
    ) {
        eprintln!("[BFT] Proposal #{} rejected: proposer VRF ticket did not qualify", block.height);
        return ProposalAuth::Disqualified;
    }
    ProposalAuth::Valid
}

async fn handle_block_proposal(
    block: LedgerBlock,
    transactions: Vec<LedgerTx>,
    proposer: String,
    signature: String,
    vrf_ticket: String,
    proposal_view: u64,
    app: Option<&tauri::AppHandle<tauri::Wry>>,
) {
    if is_observer() { return; }
    let (my_addr, seed_arr_opt) = match tokio::task::spawn_blocking(|| {
        let addr = crate::ledger::Ledger::load().address;
        let seed = get_ed25519_seed();
        (addr, seed)
    }).await {
        Ok(v)  => v,
        Err(_) => return,
    };
    if my_addr.is_empty() { return; }
    if my_addr == proposer { return; }
    let seed_arr = match seed_arr_opt {
        Some(s) => s,
        None    => return,
    };

    let local_tip = crate::chain_db::block_count().saturating_sub(1);

    // If the proposal is for a height we haven't reached yet via sync, 
    // ignore it and trigger a sync instead.
    if block.height > local_tip + 1 {
        tokio::spawn(sync_chain_from_peers());
        return;
    }

    if block.height <= local_tip {
        return;
    }


    let auth = verify_block_proposal_auth(&block, &proposer, &signature, &vrf_ticket);
    if auth != ProposalAuth::Valid {
        // Only ban on cryptographic / structural failure. VRF disqualification
        // is honest probabilistic behaviour — the proposer was elected via
        // round-robin or fallback but their ticket fell above threshold.
        let catching_up = block.height > local_tip + 2;
        if auth == ProposalAuth::Invalid && !catching_up {
            record_peer_invalid_block(&proposer);
        }
        return;
    }


    let vrf_in  = crate::bft_committee::vrf_input(&block.prev_hash, block.height, crate::bft_committee::VRF_ROLE_COMMITTEE);
    let ticket  = crate::bft_committee::sign_vrf_ticket(&seed_arr, &vrf_in);
    let all_validators: Vec<String> = known_validators().iter().cloned().collect();
    let my_drs    = crate::bft_committee::compute_drs_weight(&my_addr);
    let total_drs = crate::bft_committee::total_drs_weight(&all_validators);

    let n_validators = all_validators.len();
    let effective_committee = n_validators.min(crate::bft_committee::MAX_COMMITTEE_SIZE);
    if !crate::bft_committee::qualifies_committee(&ticket, my_drs, total_drs, n_validators) {
        eprintln!("[BFT] Proposal #{} — VRF committee disqualified (my_drs={:.4} total_drs={:.4} effective={}/{} validators)",
            block.height, my_drs, total_drs, effective_committee, n_validators);
        return;
    }
    eprintln!("[BFT] Proposal #{} — committee qualified (effective={}/{} validators)",
        block.height, effective_committee, n_validators);

    let locked_height = LOCKED_QC_HEIGHT.load(Ordering::Relaxed);
    let parent_height = block.height.saturating_sub(1);
    if parent_height < locked_height {
        eprintln!("[BFT] Safety violation: proposal #{} parent #{} is older than locked QC #{}", block.height, parent_height, locked_height);
        return;
    }

    // ── 2. Block-level structural validation ─────────────────────────────────
    let chain = load_chain();
    {
        let parent_height = block.height.saturating_sub(1);
        let parent_hash = if parent_height == 0 {
            Some(crate::ledger::GENESIS_HASH.to_string())
        } else {
            crate::chain_db::get_block_by_height(parent_height).map(|b| b.hash)
        };

        match parent_hash {
            Some(ph) if ph == block.prev_hash => {} // OK
            Some(ph) => {
                eprintln!("[BFT] Fork detected — block #{} from {} references prev_hash {:.16}… (we have {:.16}…)",
                    block.height, proposer, block.prev_hash, ph);
                tokio::spawn(sync_chain_from_peers());
                return;
            }
            None => {
                tracing::debug!("[BFT] Missing parent for block #{} — requesting sync", block.height);
                tokio::spawn(sync_chain_from_peers());
                return;
            }
        }
    }
    if !validate_block(&block, &chain) {
        eprintln!("[BFT] Committee: rejected proposal for block #{} from {} — structural validation failed",
            block.height, proposer);
        record_peer_invalid_block(&proposer);
        return;
    }

    // ── 3. PoC ticket check ───────────────────────────────────────────────────
    {
        let mut parts = block.poc_ticket.splitn(2, ':');
        let ticket_hex = parts.next().unwrap_or("");
        let sig_hex    = parts.next().unwrap_or("");
        let valid = crate::poc::verify_ticket(
            ticket_hex, sig_hex, &proposer, &block.prev_hash, block.poc_slot, block.height,
        );
        if !valid {
            eprintln!("[BFT] Committee: rejected proposal #{} from {} — invalid PoC ticket",
                block.height, proposer);
            return;
        }
    }


    if let Err(reason) = crate::chain_db::validate_proposal_block(&block, &transactions) {
        eprintln!(
            "[BFT] Committee: rejected proposal #{} from {} - block/tx integrity failed: {}",
            block.height, proposer, reason
        );
        record_peer_invalid_block(&proposer);
        return;
    }

    for tx in &transactions {
        // Skip coinbase (system reward tx) — its amount is validated below.
        if Some(&tx.hash) == block.coinbase_tx.as_ref() { continue; }
        if crate::ledger::is_protocol_system_tx(tx) { continue; }
        if let Err(reason) = crate::ledger::verify_incoming_tx_with_miner(tx, &proposer) {
            eprintln!("[TX] {:.12} Rejected — {} (in proposal #{} from {:.16})",
                tx.hash, reason, block.height, proposer);
            eprintln!("[BFT] Committee: rejected proposal #{} from {} — tx {} invalid: {}",
                block.height, proposer, tx.hash, reason);
            return;
        }
    }


    let tx_fees_sum: u64 = transactions.iter()
        .filter(|t| Some(&t.hash) != block.coinbase_tx.as_ref()
                 && t.tx_type != "fee_distribution")
        .map(|t| t.fee_uegoc)
        .sum();
    let emission_v2 = crate::chain_db::emission_v2_active(block.height);
    let expected_reward = crate::chain_db::expected_block_reward(
        block.height, block.timestamp, tx_fees_sum, &block.prev_hash,
    );
    let expected_contributor_fee = crate::tokenomics::contributor_fee_share(tx_fees_sum);

    if let Some(ref cb_hash) = block.coinbase_tx {
        match transactions.iter().find(|t| &t.hash == cb_hash) {
            Some(cb) => {
                let reward_invalid = if emission_v2 {
                    cb.amount > expected_reward || cb.amount != block.reward
                } else {
                    cb.amount != expected_reward
                };
                if reward_invalid || cb.to != proposer {
                    eprintln!(
                        "[BFT] Committee: rejected proposal #{} — invalid coinbase \
                         (amount={} expected={}, to={} proposer={})",
                        block.height, cb.amount, expected_reward, cb.to, proposer
                    );
                    return;
                }
            }
            None => {
                if block.reward != 0 {
                    eprintln!("[BFT] Committee: rejected proposal #{} — coinbase tx missing", block.height);
                    return;
                }
            }
        }
    }

    if expected_contributor_fee > 0 {
        let sf_tx = transactions.iter().find(|t| t.tx_type == "fee_distribution");
        match sf_tx {
            Some(sf) if sf.amount == expected_contributor_fee
                     && sf.to == crate::chain_db::NODE_POOL_ADDR => {}
            Some(sf) => {
                eprintln!(
                    "[BFT] Committee: rejected proposal #{} — invalid contributor fee tx \
                     (amount={} expected={}, to={})",
                    block.height, sf.amount, expected_contributor_fee, sf.to
                );
                return;
            }
            None => {
                eprintln!(
                    "[BFT] Committee: rejected proposal #{} — contributor fee tx missing (expected {})",
                    block.height, expected_contributor_fee
                );
                return;
            }
        }
    }

    // ── 6. Dedup: skip if we already voted at this height (avoids equivocation) ─
    {
        let cast = votes_cast();
        if cast.contains_key(&(my_addr.clone(), block.height)) { return; }
    }
    {
        let votes = pending_votes();
        if let Some(voters) = votes.get(&block.hash) {
            if voters.contains(&my_addr) { return; }
        }
    }
    // Persistent anti-equivocation reservation: refuse to vote (and broadcast) a
    // competing block at a height we already locked. VOTES_CAST above is wiped on
    // view change for liveness, so it alone can't stop a node from voting for two
    // blocks at one height across views — this lock survives view changes and is the
    // authoritative gate that prevents both halves of a split from reaching quorum.
    if !try_lock_self_vote(block.height, &block.hash, proposal_view) {
        eprintln!("[BFT] Not voting proposal #{} — locked on a decided/higher-view block (anti-equivocation)", block.height);
        return;
    }


    pending_proposals().insert(block.height, proposer.clone());

    touch_proposal_timestamp();

    {
        let mut staged = staged_block();
        let should_stage = staged.as_ref()
            .map(|(b, _)| b.hash != block.hash)
            .unwrap_or(true);
        if should_stage {
            *staged = Some((block.clone(), transactions.clone()));
        }
    }

    // ── 9. Sign and broadcast vote ─────────────────────────────────────────────
    let vote_data = crate::bft_committee::vote_signing_data(&block.hash, block.height, &my_addr);
    let signature = {
        use ed25519_dalek::{SigningKey, Signer};
        hex::encode(SigningKey::from_bytes(&seed_arr).sign(vote_data.as_bytes()).to_bytes())
    };
    let vrf_ticket_hex = hex::encode(&ticket);

    eprintln!("[BFT] Self-selected as committee for block #{} — voting", block.height);

    let block_hash_bytes = hex::decode(&block.hash).unwrap_or_default();
    let (my_bls_sig, my_bls_pk) = bls_vote_fields(&block_hash_bytes);

    let vote = P2PMessage::BlockVote {
        block_hash: block.hash.clone(),
        height:     block.height,
        voter:      my_addr.clone(),
        signature:  signature.clone(),
        timestamp:  chrono::Utc::now().timestamp(),
        vrf_ticket: vrf_ticket_hex.clone(),
        prev_hash:  block.prev_hash.clone(),
        bls_sig:    my_bls_sig.clone(),
        bls_pubkey: my_bls_pk.clone(),
        voter_pubkey: my_ed25519_pubkey_hex(),
    };

    if let Ok(data) = serde_json::to_vec(&vote) {
        publish_gossip("ego-votes-v1", data).await;
    }

    handle_block_vote(block.hash, block.height, my_addr, signature, chrono::Utc::now().timestamp(), vrf_ticket_hex, block.prev_hash, my_bls_sig, my_bls_pk, app.cloned()).await;
}

async fn handle_block_vote(
    block_hash:  String,
    height:      u64,
    voter:       String,
    signature:   String,
    timestamp:   i64,
    vrf_ticket:  String,
    prev_hash:   String,
    bls_sig:     String,
    bls_pubkey:  String,
    app:         Option<tauri::AppHandle<tauri::Wry>>,
) {
    if slashed_validators().contains(&voter) {
        eprintln!("[BFT] Ignoring vote from slashed validator {}", voter);
        return;
    }

    let local_tip = crate::chain_db::block_count().saturating_sub(1);
    if height <= local_tip {
        return;
    }

    let my_addr_local = crate::ledger::Ledger::load().address;
    let is_self_vote  = voter == my_addr_local;

    const VRF_ENFORCE_HEIGHT: u64 = 10;
    if !is_self_vote {
        if vrf_ticket.is_empty() || prev_hash.is_empty() {
            if height >= VRF_ENFORCE_HEIGHT {
                eprintln!("[BFT] Vote from {} at #{} rejected — VRF ticket required above height {}",
                    voter, height, VRF_ENFORCE_HEIGHT);
                return;
            }
        } else {
            let ticket_bytes = match hex::decode(&vrf_ticket) {
                Ok(b) => b,
                Err(_) => {
                    eprintln!("[BFT] Malformed vrf_ticket from {}", voter);
                    return;
                }
            };
            let pubkey_opt = get_peer_ed25519_pubkey(&voter);
            match pubkey_opt {
                None => {
                    if height >= VRF_ENFORCE_HEIGHT {
                        eprintln!("[BFT] Unknown Ed25519 pubkey for {} at #{} — dropping vote", voter, height);
                        return;
                    }
                }
                Some(pubkey) => {
                    let vrf_in = crate::bft_committee::vrf_input(&prev_hash, height, crate::bft_committee::VRF_ROLE_COMMITTEE);
                    if !crate::bft_committee::verify_vrf_ticket(&pubkey, &vrf_in, &ticket_bytes) {
                        eprintln!("[BFT] Invalid VRF ticket from {} at height {}", voter, height);
                        return;
                    }
                    let all_validators: Vec<String> = known_validators().iter().cloned().collect();
                    let voter_drs = crate::bft_committee::compute_drs_weight(&voter);
                    let total_drs = crate::bft_committee::total_drs_weight(&all_validators);
                    if !crate::bft_committee::qualifies_committee(&ticket_bytes, voter_drs, total_drs, all_validators.len()) {
                        eprintln!("[BFT] Vote from {} rejected — VRF ticket below committee threshold", voter);
                        return;
                    }
                }
            }
        }
    }

    // ── BFT vote signature verification ───────────────────────────────────
    let vote_data = crate::bft_committee::vote_signing_data(&block_hash, height, &voter);
    if !is_self_vote && !voter.is_empty()
        && (signature.is_empty() || !verify_bft_sig(&voter, &vote_data, &signature))
    {
        eprintln!("[BFT] Invalid vote signature from {} at height {} — dropping", voter, height);
        return;
    }

    // ── Anti-equivocation lock (safety) ────────────────────────────────────
    // This node may back exactly ONE block per height. The lock is atomic
    // (single guard) and persists across view changes, so two conflicting
    // blocks can never each collect this node's vote — which is what made both
    // halves of a split reach a 2-of-2 quorum and hard-finalize, forking the
    // chain at one height. Only enforced for our OWN vote; peer equivocation is
    // handled separately (slashing + EquivocationProof).
    if is_self_vote && !try_lock_self_vote(height, &block_hash, current_view()) {
        eprintln!(
            "[BFT] Refusing to count own vote for block {} at height {} — locked on a different block (anti-equivocation)",
            &block_hash[..8.min(block_hash.len())], height
        );
        return;
    }

    // Collect this validator's BLS pubkey + vote signature the moment the vote is
    // verified — BEFORE any finalization-state early return below. A vote that
    // lands after the height is already in finalized_at_height still deposits its
    // signature, so the proposer can always assemble the FULL quorum certificate
    // and attach it to the committed/gossiped block. Storing it only after the
    // early return (the old location) starved the aggregate under pipelining
    // races, leaving agg_bls_sig empty and halting the chain at graduation when
    // the QC ratchet starts demanding a certificate on every child.
    if !bls_pubkey.is_empty() {
        if let Ok(pk_bytes) = hex::decode(&bls_pubkey) {
            peer_bls_pubkeys().insert(voter.clone(), pk_bytes);
            crate::chain_db::persist_validator_bls_pubkey(&voter, &bls_pubkey);
        }
    }
    if !bls_sig.is_empty() {
        if let Ok(sig_bytes) = hex::decode(&bls_sig) {
            pending_bls_sigs().entry(block_hash.clone()).or_default().insert(voter.clone(), sig_bytes);
        }
    }

    let prior_vote: Option<(String, String)> = {
        let mut cast = votes_cast();
        let key = (voter.clone(), height);
        let prior = cast.get(&key).cloned();
        if let Some((ref prior_hash, _)) = prior {
            if *prior_hash == block_hash {
                return;
            }
        }
        cast.insert(key, (block_hash.clone(), signature.clone()));
        prior
    };

    let finalized_canonical = {
        // Scoping the lock ensures the MutexGuard is dropped before any .await
        let finalized = finalized_at_height();
        finalized.get(&height).cloned()
    };

    if let Some(canonical_hash) = finalized_canonical {
        let block_exists = tokio::task::spawn_blocking(move || {
            crate::chain_db::get_block_by_height(height).is_some()
        }).await.unwrap_or(false);

        // Only skip if the block is actually committed to the database
        if canonical_hash != block_hash && block_exists {
            eprintln!("[BFT] Note: {} voted for alternate block {} at already-finalized height {}", voter, &block_hash[..8.min(block_hash.len())], height);
            return;
        }
        return;
    }

    let threshold = bft_threshold();

    let should_finalize = {
        let mut votes = pending_votes();
        let voters = votes.entry(block_hash.clone()).or_default();
        // Sybil gate: an unstaked validator's vote does not count toward quorum
        // (unless the network is still bootstrapping — see is_eligible_validator).
        if !is_eligible_validator(&voter) {
            eprintln!("[BFT] Ignoring vote for block #{} from unstaked validator {} (below stake floor)", height, voter);
        } else if !voters.contains(&voter) {
            voters.push(voter.clone());
            crate::chain_db::persist_pending_vote(&block_hash, &voter);
            let my_addr = crate::ledger::Ledger::load().address;
            if voter == my_addr {
                crate::tokenomics::record_block_participation();
            }
            eprintln!("[BFT] Vote for block #{} from {} ({}/{} votes)",
                height, voter, voters.len(), threshold);
        }

        voters.len() >= threshold && stake_quorum_reached(voters)
    };

    if !should_finalize { return; }

    let already_finalized = {
        let mut fin = finalized_at_height();
        match fin.entry(height) {
            std::collections::hash_map::Entry::Occupied(_) => true,
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(block_hash.clone());
                false
            }
        }
    };
    if already_finalized {
        eprintln!("[BFT] Block #{} already finalized by QC/solo path — clearing staged block, touching timer", height);
        {
            let mut staged = staged_block();
            if staged.as_ref().map(|(b, _)| b.hash == block_hash && b.height == height).unwrap_or(false) {
                staged.take();
            }
        }
        touch_proposal_timestamp();
        // Pipeline the next view from this path too (a node that finalized via the
        // QC/gossip path otherwise waits out the 5s timeout, gating the quorum).
        if known_validators().len() >= 2 { request_pipeline_next(); }
        return;
    }

    let finalized_voters = pending_votes().get(&block_hash).cloned().unwrap_or_default();
    let finalized_bls_sigs = pending_bls_sigs().get(&block_hash).cloned().unwrap_or_default();
    let final_vote_count = finalized_voters.len();
    eprintln!("[BFT] Block #{} FINALIZED with {} votes (threshold={})",
        height, final_vote_count, threshold);

    // No solo production: a block always needs a real ≥quorum of distinct
    // validators (see bft_threshold). A lone node halts instead of bypassing
    // the quorum check, so it can never solo-finalize a private fork.
    let is_solo_bootstrap = false;

    if final_vote_count >= threshold && !is_solo_bootstrap {
        let mut hard = hard_finalized_heights();
        hard.insert(height);
        LOCKED_QC_HEIGHT.fetch_max(height, Ordering::Relaxed);
        if height > 0 && height % 10_000 == 0 {
            let cutoff = height.saturating_sub(20_000);
            hard.retain(|&h| h >= cutoff);
            finalized_at_height().retain(|&h, _| h >= cutoff);
        }
    }
    LAST_BLOCK_FINALIZED_TS.store(chrono::Utc::now().timestamp(), Ordering::Relaxed);
    crate::tokenomics::record_block_produced();

    CONSECUTIVE_EMPTY_VIEWS.store(0, Ordering::Relaxed);

    pending_proposals().remove(&height);

    // Clean up equivocation tracker for heights older than 100 blocks.
    {
        let cutoff = height.saturating_sub(100);
        votes_cast().retain(|(_, h), _| *h >= cutoff);
        // The persistent self-vote lock is released only here (a height was
        // decided) and for ancient heights — never on a bare view change, so a
        // node can't be tricked into voting a second block at an undecided height.
        self_vote_lock().retain(|h, _| *h >= cutoff);
    }

    {
        let all_hashes: Vec<String> = pending_votes().keys().cloned().collect();
        for h in &all_hashes {
            crate::chain_db::clear_pending_votes_for_block(h);
        }
    }
    pending_votes().clear();
    pending_bls_sigs().clear();

    let staged_opt: Option<(crate::ledger::LedgerBlock, Vec<LedgerTx>)> = {
        let mut staged = staged_block();
        if staged.as_ref().map(|(b, _)| b.hash == block_hash).unwrap_or(false) {
            staged.take()
        } else {
            // Our staged block (if any) lost fork-choice — return its TXs to the mempool
            // so they get picked up by the next block proposal.
            if let Some((b, stamped)) = staged.as_ref() {
                if b.height == height {
                    let pool = crate::mempool::get_mempool();
                    for tx in stamped.iter().filter(|t| !t.from.is_empty() && t.from != crate::chain_db::NODE_POOL_ADDR) {
                        if crate::chain_db::get_tx_by_hash(&tx.hash).is_none() {
                            eprintln!("[BFT] TX {:.12} returned to mempool — block #{} fork-choice lost", tx.hash, height);
                            let mut pending_tx = tx.clone();
                            pending_tx.status = "Pending".to_string();
                            pending_tx.block_height = None;
                            let _ = pool.push(pending_tx);
                        }
                    }
                    staged.take();
                }
            }
            None
        }
    };

    let app_handle = app.clone();
    let (block, block_txs) = match staged_opt {
        Some((mut b, txs)) => {
            {
                let pks = peer_bls_pubkeys(); // Guard is local and no await follows inside this block
                let mut pk_list: Vec<String> = Vec::new();
                let mut sig_list: Vec<Vec<u8>> = Vec::new();
                
                for voter in &finalized_voters {
                    if let (Some(pk), Some(sig)) = (pks.get(voter), finalized_bls_sigs.get(voter)) {
                        pk_list.push(hex::encode(pk));
                        sig_list.push(sig.clone());
                    }
                }
                drop(pks);
                
                if !sig_list.is_empty() {
                    if let Ok(agg) = crate::bls_agg::aggregate_signatures(&sig_list) {
                        b.agg_bls_sig = hex::encode(&agg);
                        b.bls_pubkeys = pk_list;
                    }
                }
            }
            eprintln!("[BFT] committing block #{} to RocksDB ({} votes)", height, final_vote_count);
            let vote_count_u32 = final_vote_count as u32;
            let b_c   = b.clone();
            let txs_c = txs.clone();
            let committed = tokio::task::spawn_blocking(move || {
                crate::chain_db::commit_staged_block(&b_c, &txs_c, vote_count_u32)
            }).await.unwrap_or(false);
            eprintln!("[BFT] commit_staged_block done — block #{} ok={}", height, committed);
            if !committed {
                let pool = crate::mempool::get_mempool();
                for tx in txs.iter().filter(|t| !t.from.is_empty() && t.from != crate::chain_db::NODE_POOL_ADDR) {
                    if crate::chain_db::get_tx_by_hash(&tx.hash).is_none() {
                        let _ = pool.push(tx.clone());
                    }
                }
                touch_proposal_timestamp();
                return;
            }
            if !is_solo_bootstrap {
                crate::chain_db::pipeline_commit(height);
                // Happy-path: signal the view-change monitor to propose the next
                // block immediately instead of waiting out the 5s proposal timeout.
                request_pipeline_next();
            } else {
                crate::chain_db::pipeline_commit(height + 2);
            }
            touch_proposal_timestamp();
            (b, txs)
        }
        None => {
            let bh_c = block_hash.clone();
            let (opt_b, opt_txs) = tokio::task::spawn_blocking(move || {
                let b = crate::chain_db::get_block_by_height(height);
                let txs = b.as_ref()
                    .filter(|blk| blk.hash == bh_c)
                    .map(|_| crate::chain_db::get_txs_for_block(height));
                (b, txs)
            }).await.unwrap_or((None, None));
            match (opt_b, opt_txs) {
                (Some(b), Some(txs)) if b.hash == block_hash => {
                    crate::chain_db::pipeline_commit(height);
                    touch_proposal_timestamp();
                    if known_validators().len() >= 2 { request_pipeline_next(); }
                    (b, txs)
                }
                _ => {
                    eprintln!("[BFT] Block {} not staged or committed — will arrive via sync", block_hash);
                    tokio::spawn(sync_chain_from_peers());
                    return;
                }
            }
        }
    };

    for tx in block_txs.iter() {
        if !tx.hash.is_empty() {
            crate::commands::tx_pending::remove(&tx.hash);
        }
        if !tx.from.is_empty() && tx.from != crate::chain_db::NODE_POOL_ADDR {
            tracing::debug!("[TX] {:.12} Confirmed — block #{}", tx.hash, height);
        }
    }

    let votes_json: Vec<serde_json::Value> = {
        let cast = votes_cast();
        finalized_voters
            .iter()
            .map(|v| {
                let sig = cast.get(&(v.clone(), height))
                    .map(|(_, s)| s.as_str())
                    .unwrap_or("");
                let voter_pk = get_peer_ed25519_pubkey(v)
                    .map(hex::encode)
                    .unwrap_or_default();
                serde_json::json!({"voter": v, "signature": sig, "voter_pubkey": voter_pk})
            })
            .collect()
    };

    let (agg_bls_sig, bls_pubkeys) = (block.agg_bls_sig.clone(), block.bls_pubkeys.clone());

    let finalized = P2PMessage::BlockFinalized {
        block:        block.clone(),
        transactions: block_txs.clone(),
        votes:        votes_json,
        agg_bls_sig,
        bls_pubkeys,
    };

    if let Ok(data) = serde_json::to_vec(&finalized) {
        publish_gossip("ego-blocks-v1", data).await;
    }

    {
        let mut b = block.clone();
        b.vote_count = final_vote_count as u32;
        let txs = block_txs.clone();
        tokio::spawn(async move { push_block_to_oracle(&b, &txs).await; });
    }

    crate::rpc::notify_new_block(&block);
    if let Some(h) = app_handle {
        let _ = h.emit_all("ego://chain-updated", ());
    }
}


fn process_inbound_qc_finalization(
    block_hash:  &str,
    height:      u64,
    votes:       &[serde_json::Value],
    agg_bls_sig: &str,
    bls_pubkeys: &[String],
) -> bool {
    {
        let fin = finalized_at_height();
        if fin.contains_key(&height) {
            return fin.get(&height).map(|h| h == block_hash).unwrap_or(false);
        }
    }

    let threshold = bft_threshold();
    
    // Allow solo-mined blocks (0 or 1 votes) to be accepted if the network
    // has not yet met the minimum validator threshold to form a BFT quorum.
    // No solo production: a block always needs a real ≥quorum of distinct
    // validators (see bft_threshold). A lone node halts instead of bypassing
    // the quorum check, so it can never solo-finalize a private fork.
    let is_solo_bootstrap = false;

    if !is_solo_bootstrap && votes.len() < threshold {
        eprintln!(
            "[QC] Block #{} ({:.8}…): only {} votes, need {} — ignoring peer finalization claim",
            height, block_hash, votes.len(), threshold
        );
        return false;
    }

    if !agg_bls_sig.is_empty() && !bls_pubkeys.is_empty() {
        let block_hash_bytes = hex::decode(block_hash).unwrap_or_default();
        let sig_bytes = hex::decode(agg_bls_sig).unwrap_or_default();
        let pubkeys: Vec<Vec<u8>> = bls_pubkeys.iter().filter_map(|pk| hex::decode(pk).ok()).collect();
        
        if crate::bls_agg::verify_aggregate(&sig_bytes, &pubkeys, &block_hash_bytes)
            && crate::chain_db::qc_signers_registered(bls_pubkeys) {
            let known: Vec<String> = known_validators().iter().cloned().collect();
            let pks = peer_bls_pubkeys();
            let mut verified_voters = Vec::new();
            for (voter, pk) in pks.iter() {
                // Sybil gate: only stake-eligible signers count toward the QC.
                if bls_pubkeys.contains(&hex::encode(pk)) && known.contains(voter)
                    && is_eligible_validator(voter) {
                    verified_voters.push(voter.clone());
                }
            }

            // Drop locks before calling stake_quorum_reached to prevent deadlock
            drop(pks);
            
            if verified_voters.len() >= threshold && stake_quorum_reached(&verified_voters) {
                finalized_at_height().insert(height, block_hash.to_string());
                pending_proposals().remove(&height);
                CONSECUTIVE_EMPTY_VIEWS.store(0, Ordering::Relaxed);
                touch_proposal_timestamp();
                if !is_solo_bootstrap {
                    let mut hard = hard_finalized_heights();
                    hard.insert(height);
                    LOCKED_QC_HEIGHT.fetch_max(height, Ordering::Relaxed);
                    if height > 0 && height % 10_000 == 0 {
                        let cutoff = height.saturating_sub(20_000);
                        hard.retain(|&h| h >= cutoff);
                        finalized_at_height().retain(|&h, _| h >= cutoff);
                    }
                }
                LAST_BLOCK_FINALIZED_TS.store(chrono::Utc::now().timestamp(), Ordering::Relaxed);
            tokio::spawn(try_proactive_proposal());
                return true;
            }
        }
    }

    let known = known_validators();
    let mut verified_voters: Vec<String> = Vec::new();
    let mut seen_voters = std::collections::HashSet::new();
    for v in votes {
        let voter = match v.get("voter").and_then(|x| x.as_str()) {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };
        if !seen_voters.insert(voter.to_string()) { continue; }
        let sig_hex = v.get("signature").and_then(|x| x.as_str()).unwrap_or("");
        if sig_hex.is_empty() { continue; }
        if !known.contains(voter) { continue; }
        let voter_pk = v.get("voter_pubkey").and_then(|x| x.as_str()).unwrap_or("");
        let vote_data = crate::bft_committee::vote_signing_data(block_hash, height, voter);
        if verify_bft_sig_with_key(voter, &vote_data, sig_hex, voter_pk) {
            verified_voters.push(voter.to_string());
        }
    }
    drop(known);
    let verified = verified_voters.len();

    if !is_solo_bootstrap && verified < threshold {
        eprintln!(
            "[QC] Block #{} ({:.8}…): only {}/{} votes verified — rejected",
            height, block_hash, verified, threshold
        );
        return false;
    }
    if !is_solo_bootstrap && !stake_quorum_reached(&verified_voters) {
        eprintln!(
            "[QC] Block #{} ({:.8}...): verified votes did not reach stake quorum - rejected",
            height, block_hash
        );
        return false;
    }

    eprintln!(
        "[QC] Block #{} ({:.8}…) finalized via gossip — {}/{} sigs verified",
        height, block_hash, verified, threshold
    );

    finalized_at_height().insert(height, block_hash.to_string());
    pending_proposals().remove(&height);

    {
        let all_hashes: Vec<String> = pending_votes().keys().cloned().collect();
        for h in &all_hashes {
            crate::chain_db::clear_pending_votes_for_block(h);
        }
    }
    pending_votes().clear();
    pending_bls_sigs().clear();

    if !is_solo_bootstrap {
        let mut hard = hard_finalized_heights();
        hard.insert(height);
        LOCKED_QC_HEIGHT.fetch_max(height, Ordering::Relaxed);
        if height > 0 && height % 10_000 == 0 {
            let cutoff = height.saturating_sub(20_000);
            hard.retain(|&h| h >= cutoff);
            finalized_at_height().retain(|&h, _| h >= cutoff);
        }
    }

    CONSECUTIVE_EMPTY_VIEWS.store(0, Ordering::Relaxed);
    touch_proposal_timestamp();
    LAST_BLOCK_FINALIZED_TS.store(chrono::Utc::now().timestamp(), Ordering::Relaxed);
    tokio::spawn(try_proactive_proposal());
    true
}

pub async fn push_tx_to_relay(_tx: &crate::ledger::LedgerTx, _block: &crate::ledger::LedgerBlock) {}

pub fn touch_proposal_timestamp() {
    LAST_PROPOSAL_TS.store(chrono::Utc::now().timestamp(), Ordering::Relaxed);
}

async fn handle_view_change_msg(view: u64, voter: String) {
    register_announced_validator(&voter);
    if !known_validators().contains(&voter) { return; }
    let threshold = bft_threshold().max(1);

    let (my_addr, block_count_now, seed_32_opt) = match tokio::task::spawn_blocking(|| {
        let addr  = crate::ledger::Ledger::load().address;
        let count = crate::chain_db::block_count();
        let seed  = get_ed25519_seed();
        (addr, count, seed)
    }).await {
        Ok(v)  => v,
        Err(_) => return,
    };

    {
        let my_view = current_view();
        let our_chain_next = block_count_now;
        // Allow substantial jumps to catch up to the network proposers
        let view_jump_limit = my_view.max(our_chain_next).saturating_add(100_000);
        // Sync to the peer's view whenever they're ahead by ANY amount — including
        // exactly one. The off-by-one case is the common one under async timing:
        // if we only jumped when the peer was 2+ ahead, two nodes a single view
        // apart would each count only their own ViewChange (1/2 forever) and the
        // chain would deadlock. Jumping on `view > my_view` adds our vote to the
        // peer's view so the round reaches quorum and a new leader is elected.
        if view > my_view && view <= view_jump_limit {
            if !my_addr.is_empty() && voter != my_addr {
                // Peer is ahead: jump to their view to stay in sync with the leader rotation
                let target_view = view;
                advance_view(view);
                eprintln!(
                    "[HotStuff] View sync: jumped {} → {} (peer {} is ahead)",
                    my_view, view.saturating_sub(1), &voter[..voter.len().min(20)]
                );
                {
                    let mut votes = view_change_votes();
                    let voters = votes.entry(view).or_default();
                    if !voters.contains(&my_addr) {
                        voters.push(my_addr.clone());
                    }
                }
                if let Some(seed_32) = seed_32_opt {
                    let vote_data = format!("viewchange:{}:{}", view, my_addr);
                    let sig = {
                        use ed25519_dalek::{SigningKey, Signer};
                        hex::encode(SigningKey::from_bytes(&seed_32).sign(vote_data.as_bytes()).to_bytes())
                    };
                    let ts  = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    let msg = P2PMessage::ViewChange { view, voter: my_addr.clone(), signature: sig, timestamp: ts };
                    if let Ok(data) = serde_json::to_vec(&msg) {
                        publish_gossip("ego-viewchange-v1", data).await;
                    }
                }
                touch_proposal_timestamp();
            }
        } else if view > view_jump_limit {
                if voter != my_addr {
                    tracing::debug!(
                        "[HotStuff] Ignoring ViewChange from {} for view {} — too far beyond our view (limit={})",
                        &voter[..voter.len().min(20)], view, view_jump_limit
                    );
                    return;
                }
        }
    }

    let should_advance = {
        let mut votes = view_change_votes();
        let voters = votes.entry(view).or_default();
        if !voters.contains(&voter) {
            voters.push(voter.clone());
        }
        let count = voters.len();
        eprintln!("[HotStuff] ViewChange for view {} from {} ({}/{} votes)", view, voter, count, threshold);
        count >= threshold
    };

    if !should_advance { return; }

    let current = current_view();
    if view <= current { return; }

    advance_view(view);
    eprintln!("[HotStuff] Advanced to view {} — electing new leader", view);

    view_change_votes().retain(|v, _| *v >= view);

    // ── Item 16: Accurate offline proposer penalty ─────────────────────────
    // Only penalise a proposer who EXPLICITLY broadcast a proposal (revealing
    // themselves) but then failed to get it finalized before the view timed out.
    // We NEVER penalise based on VRF heuristics — that would punish nodes that
    // legitimately won the lottery but whose proposal just didn't arrive in time.
    {
        let current_height = block_count_now;
        // Remove the entry atomically so we don't double-penalise.
        if let Some(offline_proposer) = pending_proposals().remove(&current_height) {
            crate::ledger::penalise_missed_proposal(&offline_proposer);
            eprintln!(
                "[HotStuff] Explicit proposer {} failed to finalize block #{} — penalty applied",
                &offline_proposer[..offline_proposer.len().min(20)], current_height
            );
        }
        // No penalty if no proposal was broadcast — the proposer's VRF win is
        // secret until they reveal it, so silence is not provable misconduct.
    }

    if my_addr.is_empty() { return; }

    if known_validators().is_empty() {
        return;
    }

    // On each view advance, clear votes_cast for heights that haven't been
    // finalized yet.  This allows the node to vote for new proposals at those
    // heights in the new view without triggering the equivocation guard.
    {
        votes_cast().retain(|(_, h), _| *h < block_count_now);
    }
    
    {
        let all_hashes: Vec<String> = pending_votes().keys().cloned().collect();
        for h in &all_hashes {
            crate::chain_db::clear_pending_votes_for_block(h);
        }
        pending_votes().clear();
        pending_bls_sigs().clear();
    }

    // ── Liveness: VRF self-selection + deterministic fallback ─────────────
    // Increment the empty-view counter.  If it hits FALLBACK_AFTER_EMPTY_VIEWS,
    // fall back to the highest-DRS node so the chain never permanently stalls.
    let empty_views = CONSECUTIVE_EMPTY_VIEWS.fetch_add(1, Ordering::Relaxed) + 1;

    if empty_views >= crate::bft_committee::FALLBACK_AFTER_EMPTY_VIEWS {
        // Deterministic fallback: highest-DRS node proposes unconditionally.
        // This fires at most once per chain-stall event (CONSECUTIVE_EMPTY_VIEWS
        // resets to 0 when a block is finalized).
        CONSECUTIVE_EMPTY_VIEWS.store(0, Ordering::Relaxed);
        eprintln!(
            "[HotStuff] {} consecutive empty views — activating deterministic fallback for view {}",
            empty_views, view
        );
        let validators = eligible_validators_sorted();
        let fallback_idx    = (block_count_now as usize).wrapping_rem(validators.len().max(1));
        let fallback_leader = validators.get(fallback_idx).cloned().unwrap_or_default();
        if fallback_leader == my_addr {
            eprintln!("[HotStuff] Fallback: round-robin elected us for view {} — proposing", view);
            tokio::spawn(async move { propose_block_as_leader_forced().await; });
        } else {
            eprintln!("[HotStuff] Fallback: round-robin elected {} for view {}", &fallback_leader[..12.min(fallback_leader.len())], view);
        }
    } else {
        let vs = eligible_validators_sorted();
        let n_validators = vs.len();
        if n_validators <= 10 {
            let idx = (block_count_now as usize).wrapping_rem(vs.len().max(1));
            if vs.get(idx).map(|v| v == &my_addr).unwrap_or(false) {
                eprintln!("[HotStuff] Round-robin elected us for height {} ({}/{}) — proposing block", block_count_now, idx + 1, vs.len());
                tokio::spawn(async move { propose_block_as_leader().await; });
            }
        } else {
            if let Some(ref winner) = elect_proposer_for_next_slot() {
                if winner == &my_addr {
                    eprintln!("[HotStuff] VRF won — leader for view {} — proposing block", view);
                    tokio::spawn(async move { propose_block_as_leader().await; });
                }
            }
        }
    }
}

pub async fn propose_block_as_leader() {
    if is_observer() { return; }
    if consensus_v2_live_enabled() { return; } // v2 engine drives the chain when live
    // No solo: never propose (or self-lock) a block while below quorum. A lone node
    // would otherwise stage + self-vote a block that can never finalize, then refuse
    // the peer's canonical block when it joins (permanent 1/1 split). Wait for a
    // real committee — once ≥quorum validators are live, the leader proposes.
    if known_validator_count() < crate::mempool::min_validators_for_finality() { return; }

    let init = tokio::task::spawn_blocking(|| {
        let miner = crate::ledger::Ledger::load().address;
        if miner.is_empty() { return None; }
        let (latest_h, prev_hash) = crate::chain_db::latest_block_info();
        let next_height = latest_h + 1;
        let seed_32 = get_ed25519_seed()?;
        Some((miner, prev_hash, next_height, seed_32))
    }).await.unwrap_or(None);

    let (miner, prev_hash, next_height, seed_32) = match init {
        Some(v) => v,
        None    => { touch_proposal_timestamp(); return; }
    };

    let vrf_in     = crate::bft_committee::vrf_input(&prev_hash, next_height, crate::bft_committee::VRF_ROLE_PROPOSER);
    let vrf_ticket = crate::bft_committee::sign_vrf_ticket(&seed_32, &vrf_in);

    let validators: Vec<String> = known_validators().iter().cloned().collect();
    let my_drs    = crate::bft_committee::compute_drs_weight(&miner);
    let total_drs = crate::bft_committee::total_drs_weight(&validators);

    if validators.len() > 10 {
        if !crate::bft_committee::qualifies_proposer_for_network(
            &vrf_ticket,
            my_drs,
            total_drs,
            validators.len(),
        ) {
            return;
        }
        eprintln!("[BFT] VRF election won — proposer for block #{}", next_height);
    } else {
        // Authoritative round-robin leader gate: ONLY the elected leader for this
        // height may stage/propose/self-lock a block. Every caller (reactive tx path,
        // stall timer, view-change) funnels through here, so checking once centrally
        // makes off-turn proposals impossible — without this a node that just received
        // a tx proposes its own block off-turn and duels the real leader → 1/1 split.
        let vs = eligible_validators_sorted();
        if !vs.is_empty() {
            let idx = (next_height as usize).wrapping_rem(vs.len());
            if vs.get(idx).map(|v| v != &miner).unwrap_or(true) {
                return;
            }
        }
        eprintln!("[BFT] Round-robin election won — proposer for block #{}", next_height);
    }

    // Re-use the staged block if we already proposed for this height.
    // This prevents draining the mempool empty on subsequent view elections
    // while the same block height is still awaiting committee votes.
    let reuse_data: Option<(crate::ledger::LedgerBlock, Vec<LedgerTx>)> = {
        let staged = staged_block();
        staged.as_ref()
            .filter(|(b, _)| b.height == next_height && b.miner == miner)
            .map(|(b, t)| (b.clone(), t.clone()))
    };
    if let Some((block, stamped)) = reuse_data {
        if should_solo_commit_now() {
            let bh      = block.hash.clone();
            let bheight = block.height;
            tokio::task::spawn_blocking(move || bft_solo_commit(&bh, bheight)).await.ok();
            touch_proposal_timestamp();
            return;
        }
        let sig_data  = format!("proposal:{}:{}", block.hash, block.height);
        let signature = {
            use ed25519_dalek::{SigningKey, Signer};
            hex::encode(SigningKey::from_bytes(&seed_32).sign(sig_data.as_bytes()).to_bytes())
        };
        let vrf_in2     = crate::bft_committee::vrf_input(&prev_hash, next_height, crate::bft_committee::VRF_ROLE_PROPOSER);
        let vrf_ticket2 = crate::bft_committee::sign_vrf_ticket(&seed_32, &vrf_in2);
        let proposal = P2PMessage::BlockProposal {
            block:        block.clone(),
            transactions: stamped,
            proposer:     miner.clone(),
            signature,
            vrf_ticket:   hex::encode(&vrf_ticket2),
            view:         current_view(),
            proposer_pubkey: my_ed25519_pubkey_hex(),
        };
        if let Ok(data) = serde_json::to_vec(&proposal) {
            publish_gossip("ego-proposals-v1", data).await;
        }
        eprintln!("[BFT] Re-broadcasting staged proposal for block #{} (mempool unchanged)", next_height);
        
        let committee_vrf_in     = crate::bft_committee::vrf_input(&block.prev_hash, block.height, crate::bft_committee::VRF_ROLE_COMMITTEE);
        let committee_ticket     = crate::bft_committee::sign_vrf_ticket(&seed_32, &committee_vrf_in);
        let committee_ticket_hex = hex::encode(&committee_ticket);
        let self_vote_data       = crate::bft_committee::vote_signing_data(&block.hash, block.height, &miner);
        let self_sig = {
            use ed25519_dalek::{SigningKey, Signer};
            hex::encode(SigningKey::from_bytes(&seed_32).sign(self_vote_data.as_bytes()).to_bytes())
        };
        let block_hash_bytes = hex::decode(&block.hash).unwrap_or_default();
        let (self_bls_sig, self_bls_pk) = bls_vote_fields(&block_hash_bytes);
        let self_vote = P2PMessage::BlockVote {
            block_hash: block.hash.clone(),
            height:     block.height,
            voter:      miner.clone(),
            signature:  self_sig.clone(),
            timestamp:  chrono::Utc::now().timestamp(),
            vrf_ticket: committee_ticket_hex.clone(),
            prev_hash:  block.prev_hash.clone(),
            bls_sig:    self_bls_sig.clone(),
            bls_pubkey: self_bls_pk.clone(),
            voter_pubkey: my_ed25519_pubkey_hex(),
        };
        if try_lock_self_vote(block.height, &block.hash, current_view()) {
            if let Ok(data) = serde_json::to_vec(&self_vote) {
                publish_gossip("ego-votes-v1", data).await;
            }
        } else {
            eprintln!("[BFT] Suppressing self-vote for #{} — locked on a different block (anti-equivocation)", block.height);
        }
        
        let bh = block.hash.clone();
        let bhgt = block.height;
        let m = miner.clone();
        let ss = self_sig;
        let ts = chrono::Utc::now().timestamp();
        let ct = committee_ticket_hex;
        let ph = block.prev_hash.clone();
        let bs = self_bls_sig;
        let bp = self_bls_pk;
        tokio::spawn(async move {
            handle_block_vote(bh, bhgt, m, ss, ts, ct, ph, bs, bp, None).await;
        });
        
        touch_proposal_timestamp();
        return;
    }

    let is_solo = should_solo_commit_now();
    let pool    = crate::mempool::get_mempool();
    let txs     = pool.drain_all();

    let oracle_rewards = fetch_pending_post_rewards().await;
    let post_proof_ids: Vec<String> = oracle_rewards.iter().map(|t| t.hash.clone()).collect();
    let mut all_txs = txs.clone();
    all_txs.extend(oracle_rewards);

    // Inject pending protocol transactions (e.g. collateral slashes)
    let protocol_txs: Vec<_> = PENDING_PROTOCOL_TXS
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap()
        .drain(..)
        .collect();
    all_txs.extend(protocol_txs);

    let poc_slot = crate::poc::current_slot();
    let (poc_ticket, poc_sig) = {
        use ed25519_dalek::{SigningKey, Signer};
        let slot_seed = crate::poc::slot_seed(&prev_hash, poc_slot);
        let sig       = SigningKey::from_bytes(&seed_32).sign(&slot_seed);
        let sig_hex   = hex::encode(sig.to_bytes());
        let ticket    = *blake3::hash(&sig.to_bytes()).as_bytes();
        (hex::encode(ticket), sig_hex)
    };
    let combined_ticket = if poc_ticket.is_empty() { String::new() }
                          else { format!("{}:{}", poc_ticket, poc_sig) };

    if !post_proof_ids.is_empty() {
        tokio::spawn(notify_post_rewards_claimed(post_proof_ids));
    }

    {
        let mut seen = std::collections::HashSet::new();
        all_txs.retain(|tx| !tx.hash.is_empty() && seen.insert(tx.hash.clone()));
    }

    let miner_c = miner.clone();
    let (block, stamped) = match tokio::task::spawn_blocking(move || {
        crate::chain_db::build_block_proposal(&all_txs, &miner_c, &combined_ticket, poc_slot)
    }).await {
        Ok(v)  => v,
        Err(_) => return,
    };

    {
        let mut staged = staged_block();
        *staged = Some((block.clone(), stamped.clone()));
    }

    let accepted_hashes: std::collections::HashSet<_> = stamped.iter().map(|t| t.hash.clone()).collect();
    for tx in &txs {
        if !accepted_hashes.contains(&tx.hash) {
            crate::commands::tx_pending::remove(&tx.hash);
            if let Some(app) = APP_HANDLE.get() {
                let my_addr = crate::ledger::Ledger::load().address;
                if tx.from == my_addr {
                    crate::commands::notifications::notify(
                        app,
                        "Transaction Failed",
                        &format!("Your transaction of {:.2} EGOC was rejected (e.g. insufficient balance).", tx.amount as f64 / 1_000_000.0)
                    );
                }
                let _ = app.emit_all("ego://chain-updated", ());
            }
        }
    }

    let sig_data  = format!("proposal:{}:{}", block.hash, block.height);
    let signature = {
        use ed25519_dalek::{SigningKey, Signer};
        hex::encode(SigningKey::from_bytes(&seed_32).sign(sig_data.as_bytes()).to_bytes())
    };

    let proposal = P2PMessage::BlockProposal {
        block:        block.clone(),
        transactions: stamped.clone(),
        proposer:     miner.clone(),
        signature,
        vrf_ticket:   hex::encode(&vrf_ticket),
        view:         current_view(),
        proposer_pubkey: my_ed25519_pubkey_hex(),
    };

    if let Ok(data) = serde_json::to_vec(&proposal) {
        publish_gossip("ego-proposals-v1", data).await;
    }

    let committee_vrf_in     = crate::bft_committee::vrf_input(&block.prev_hash, block.height, crate::bft_committee::VRF_ROLE_COMMITTEE);
    let committee_ticket     = crate::bft_committee::sign_vrf_ticket(&seed_32, &committee_vrf_in);
    let committee_ticket_hex = hex::encode(&committee_ticket);
    let self_vote_data       = crate::bft_committee::vote_signing_data(&block.hash, block.height, &miner);
    {
        let self_sig = {
            use ed25519_dalek::{SigningKey, Signer};
            hex::encode(SigningKey::from_bytes(&seed_32).sign(self_vote_data.as_bytes()).to_bytes())
        };
        let block_hash_bytes = hex::decode(&block.hash).unwrap_or_default();
        let (self_bls_sig, self_bls_pk) = bls_vote_fields(&block_hash_bytes);
        let self_vote = P2PMessage::BlockVote {
            block_hash: block.hash.clone(),
            height:     block.height,
            voter:      miner.clone(),
            signature:  self_sig.clone(),
            timestamp:  chrono::Utc::now().timestamp(),
            vrf_ticket: committee_ticket_hex.clone(),
            prev_hash:  block.prev_hash.clone(),
            bls_sig:    self_bls_sig.clone(),
            bls_pubkey: self_bls_pk.clone(),
            voter_pubkey: my_ed25519_pubkey_hex(),
        };
        if try_lock_self_vote(block.height, &block.hash, current_view()) {
            if let Ok(data) = serde_json::to_vec(&self_vote) {
                publish_gossip("ego-votes-v1", data).await;
            }
        } else {
            eprintln!("[BFT] Suppressing self-vote for #{} — locked on a different block (anti-equivocation)", block.height);
        }
        
        if !is_solo {
            let bh = block.hash.clone();
            let bhgt = block.height;
            let m = miner.clone();
            let ss = self_sig;
            let ts = chrono::Utc::now().timestamp();
            let ct = committee_ticket_hex;
            let ph = block.prev_hash.clone();
            let bs = self_bls_sig;
            let bp = self_bls_pk;
            tokio::spawn(async move {
                handle_block_vote(bh, bhgt, m, ss, ts, ct, ph, bs, bp, None).await;
            });
        }
    }

    if is_solo {
        let bh      = block.hash.clone();
        let bheight = block.height;
        tokio::task::spawn_blocking(move || bft_solo_commit(&bh, bheight)).await.ok();
        touch_proposal_timestamp();
        eprintln!("[BFT] Solo block #{} committed", block.height);
    } else {
        touch_proposal_timestamp();
        eprintln!("[BFT] Block #{} proposed (miner={}) — awaiting committee votes",
            block.height, &miner[..12.min(miner.len())]);
    }
}

pub fn bft_solo_commit(block_hash: &str, height: u64) {
    // This is called from a blocking context, so it's fine.
    let staged_opt: Option<(LedgerBlock, Vec<LedgerTx>)> = {
        let mut s = staged_block();
        if s.as_ref().map(|(b, _)| b.hash == block_hash).unwrap_or(false) {
            s.take()
        } else {
            None
        }
    };
    if let Some((b, stamped)) = staged_opt {
        if !crate::chain_db::commit_staged_block(&b, &stamped, 1) {
            let pool = crate::mempool::get_mempool();
            for tx in stamped.iter().filter(|t| !t.from.is_empty() && t.from != crate::chain_db::NODE_POOL_ADDR) {
                if crate::chain_db::get_tx_by_hash(&tx.hash).is_none() {
                    let mut pending_tx = tx.clone();
                    pending_tx.status = "Pending".to_string();
                    pending_tx.block_height = None;
                            let _ = pool.push(pending_tx);
                }
            }
            return;
        }
        CONSECUTIVE_EMPTY_VIEWS.store(0, Ordering::Relaxed);
        pending_proposals().remove(&height);
        pending_votes().remove(block_hash);

        crate::rpc::notify_new_block(&b);
        if let Some(h) = APP_HANDLE.get() {
            let _ = h.emit_all("ego://chain-updated", ()); // This is fine, it's a handle
            // The balance update logic inside write_block_batch already handles async correctly.
            let new_bal = crate::chain_db::balance_of(&crate::ledger::Ledger::load().address);
            let _ = h.emit_all("wallet-balance-updated", serde_json::json!({
                "balance_uegoc": new_bal,
                "balance_formatted": format!("{:.2} EGOC", new_bal as f64 / 1_000_000.0)
            }));
        }
        let mut b2 = b.clone();
        b2.vote_count = 1;
        let s2  = stamped.clone();
        tokio::spawn(async move { push_block_to_oracle(&b2, &s2).await; });
        let b_broadcast   = b.clone();
        let txs_broadcast = stamped.clone();
        tokio::spawn(async move {
            let msg = P2PMessage::ChainSyncResponse {
                blocks:       vec![b_broadcast],
                transactions: txs_broadcast,
            };
            if let Ok(data) = serde_json::to_vec(&msg) {
                publish_gossip("ego-blocks-v1", data).await;
            }
        });
        tokio::spawn(try_proactive_proposal());
    }
}

pub fn try_proactive_proposal() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>> {
    Box::pin(async move {
        // Debounce rapid sequential calls to prevent task spam
        static IN_FLIGHT: AtomicBool = AtomicBool::new(false);
        if IN_FLIGHT.swap(true, Ordering::Relaxed) { return; }

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        IN_FLIGHT.store(false, Ordering::Relaxed);

        let has_txs = crate::mempool::get_mempool().pending_count() > 0;
        let has_proto = !PENDING_PROTOCOL_TXS
            .get_or_init(|| std::sync::Mutex::new(Vec::new()))
            .lock()
            .unwrap()
            .is_empty();

        if !has_txs && !has_proto {
            return;
        }

        if let Some(winner) = elect_proposer_for_next_slot() {
            let my_addr = tokio::task::spawn_blocking(|| crate::ledger::Ledger::load().address)
                .await
                .unwrap_or_default();
            if winner == my_addr {
                propose_block_as_leader().await;
            }
        }
    })
}


/// Like `propose_block_as_leader` but skips the VRF qualification check.
/// Called by the deterministic liveness fallback after FALLBACK_AFTER_EMPTY_VIEWS
/// consecutive view changes with no block — prevents chain death.
pub async fn propose_block_as_leader_forced() {
    if is_observer() { return; }
    if consensus_v2_live_enabled() { return; } // v2 engine drives the chain when live
    // No solo: never propose while below quorum (see propose_block_as_leader).
    if known_validator_count() < crate::mempool::min_validators_for_finality() { return; }

    let init = tokio::task::spawn_blocking(|| {
        let miner = crate::ledger::Ledger::load().address;
        if miner.is_empty() { return None; }
        let (latest_h, prev_hash) = crate::chain_db::latest_block_info();
        let next_height = latest_h + 1;
        let seed_32 = get_ed25519_seed()?;
        Some((miner, prev_hash, next_height, seed_32))
    }).await.unwrap_or(None);

    let (miner, prev_hash, next_height, seed_32) = match init {
        Some(v) => v,
        None    => { touch_proposal_timestamp(); return; }
    };

    // Same authoritative round-robin leader gate as propose_block_as_leader: even the
    // deterministic fallback only lets the ELECTED leader propose, so it breaks a
    // stall without introducing an off-turn competing block.
    {
        let vs = eligible_validators_sorted();
        if !vs.is_empty() {
            let idx = (next_height as usize).wrapping_rem(vs.len());
            if vs.get(idx).map(|v| v != &miner).unwrap_or(true) {
                return;
            }
        }
    }

    // Re-use staged block if already proposed for this height (same as propose_block_as_leader).
    let reuse_data: Option<(crate::ledger::LedgerBlock, Vec<LedgerTx>)> = {
        let staged = staged_block();
        staged.as_ref()
            .filter(|(b, _)| b.height == next_height && b.miner == miner)
            .map(|(b, t)| (b.clone(), t.clone()))
    };
    if let Some((block, stamped)) = reuse_data {
        if should_solo_commit_now() {
            let bh      = block.hash.clone();
            let bheight = block.height;
            tokio::task::spawn_blocking(move || bft_solo_commit(&bh, bheight)).await.ok();
            touch_proposal_timestamp();
            eprintln!("[BFT] FALLBACK solo commit for staged block #{}", block.height);
            return;
        }
        let sig_data  = format!("proposal:{}:{}", block.hash, block.height);
        let signature = {
            use ed25519_dalek::{SigningKey, Signer};
            hex::encode(SigningKey::from_bytes(&seed_32).sign(sig_data.as_bytes()).to_bytes())
        };
        let vrf_in2     = crate::bft_committee::vrf_input(&prev_hash, next_height, crate::bft_committee::VRF_ROLE_PROPOSER);
        let vrf_ticket2 = crate::bft_committee::sign_vrf_ticket(&seed_32, &vrf_in2);
        let proposal = P2PMessage::BlockProposal {
            block:        block.clone(),
            transactions: stamped,
            proposer:     miner.clone(),
            signature,
            vrf_ticket:   hex::encode(&vrf_ticket2),
            view:         current_view(),
            proposer_pubkey: my_ed25519_pubkey_hex(),
        };
        if let Ok(data) = serde_json::to_vec(&proposal) {
            publish_gossip("ego-proposals-v1", data).await;
        }
        eprintln!("[BFT] FALLBACK re-broadcasting staged proposal for block #{}", next_height);
        
        let committee_vrf_in     = crate::bft_committee::vrf_input(&block.prev_hash, block.height, crate::bft_committee::VRF_ROLE_COMMITTEE);
        let committee_ticket     = crate::bft_committee::sign_vrf_ticket(&seed_32, &committee_vrf_in);
        let committee_ticket_hex = hex::encode(&committee_ticket);
        let self_vote_data       = crate::bft_committee::vote_signing_data(&block.hash, block.height, &miner);
        let self_sig = {
            use ed25519_dalek::{SigningKey, Signer};
            hex::encode(SigningKey::from_bytes(&seed_32).sign(self_vote_data.as_bytes()).to_bytes())
        };
        let block_hash_bytes = hex::decode(&block.hash).unwrap_or_default();
        let (self_bls_sig, self_bls_pk) = bls_vote_fields(&block_hash_bytes);
        let self_vote = P2PMessage::BlockVote {
            block_hash: block.hash.clone(),
            height:     block.height,
            voter:      miner.clone(),
            signature:  self_sig.clone(),
            timestamp:  chrono::Utc::now().timestamp(),
            vrf_ticket: committee_ticket_hex.clone(),
            prev_hash:  block.prev_hash.clone(),
            bls_sig:    self_bls_sig.clone(),
            bls_pubkey: self_bls_pk.clone(),
            voter_pubkey: my_ed25519_pubkey_hex(),
        };
        if try_lock_self_vote(block.height, &block.hash, current_view()) {
            if let Ok(data) = serde_json::to_vec(&self_vote) {
                publish_gossip("ego-votes-v1", data).await;
            }
        } else {
            eprintln!("[BFT] Suppressing self-vote for #{} — locked on a different block (anti-equivocation)", block.height);
        }
        
        let bh = block.hash.clone();
        let bhgt = block.height;
        let m = miner.clone();
        let ss = self_sig;
        let ts = chrono::Utc::now().timestamp();
        let ct = committee_ticket_hex;
        let ph = block.prev_hash.clone();
        let bs = self_bls_sig;
        let bp = self_bls_pk;
        tokio::spawn(async move {
            handle_block_vote(bh, bhgt, m, ss, ts, ct, ph, bs, bp, None).await;
        });
        
        touch_proposal_timestamp();
        return;
    }

    let is_solo = should_solo_commit_now();
    let pool = crate::mempool::get_mempool();
    let txs  = pool.drain_all();

    let oracle_rewards = fetch_pending_post_rewards().await;
    let post_proof_ids: Vec<String> = oracle_rewards.iter().map(|t| t.hash.clone()).collect();
    let mut all_txs = txs.clone();
    all_txs.extend(oracle_rewards);

    // Inject pending protocol transactions (e.g. collateral slashes)
    let protocol_txs: Vec<_> = PENDING_PROTOCOL_TXS
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap()
        .drain(..)
        .collect();
    all_txs.extend(protocol_txs);

    let poc_slot = crate::poc::current_slot();
    let (poc_ticket, poc_sig) = {
        use ed25519_dalek::{SigningKey, Signer};
        let slot_seed = crate::poc::slot_seed(&prev_hash, poc_slot);
        let sig       = SigningKey::from_bytes(&seed_32).sign(&slot_seed);
        let sig_hex   = hex::encode(sig.to_bytes());
        let ticket    = *blake3::hash(&sig.to_bytes()).as_bytes();
        (hex::encode(ticket), sig_hex)
    };
    let combined_ticket = if poc_ticket.is_empty() { String::new() }
                          else { format!("{}:{}", poc_ticket, poc_sig) };

    if !post_proof_ids.is_empty() {
        tokio::spawn(notify_post_rewards_claimed(post_proof_ids));
    }

    {
        let mut seen = std::collections::HashSet::new();
        all_txs.retain(|tx| !tx.hash.is_empty() && seen.insert(tx.hash.clone()));
    }

    let miner_c = miner.clone();
    let (block, stamped) = match tokio::task::spawn_blocking(move || {
        crate::chain_db::build_block_proposal(&all_txs, &miner_c, &combined_ticket, poc_slot)
    }).await {
        Ok(v)  => v,
        Err(_) => return,
    };

    {
        let mut staged = staged_block();
        *staged = Some((block.clone(), stamped.clone()));
    }

    let accepted_hashes: std::collections::HashSet<_> = stamped.iter().map(|t| t.hash.clone()).collect();
    for tx in &txs {
        if !accepted_hashes.contains(&tx.hash) {
            crate::commands::tx_pending::remove(&tx.hash);
            if let Some(app) = APP_HANDLE.get() {
                let my_addr = crate::ledger::Ledger::load().address;
                if tx.from == my_addr {
                    crate::commands::notifications::notify(
                        app,
                        "Transaction Failed",
                        &format!("Your transaction of {:.2} EGOC was rejected (e.g. insufficient balance).", tx.amount as f64 / 1_000_000.0)
                    );
                }
                let _ = app.emit_all("ego://chain-updated", ());
            }
        }
    }

    let sig_data  = format!("proposal:{}:{}", block.hash, block.height);
    let signature = {
        use ed25519_dalek::{SigningKey, Signer};
        hex::encode(SigningKey::from_bytes(&seed_32).sign(sig_data.as_bytes()).to_bytes())
    };
    let vrf_in2       = crate::bft_committee::vrf_input(&prev_hash, next_height, crate::bft_committee::VRF_ROLE_PROPOSER);
    let vrf_ticket2   = crate::bft_committee::sign_vrf_ticket(&seed_32, &vrf_in2);

    let proposal = P2PMessage::BlockProposal {
        block:        block.clone(),
        transactions: stamped.clone(),
        proposer:     miner.clone(),
        signature,
        vrf_ticket:   hex::encode(&vrf_ticket2),
        view:         current_view(),
        proposer_pubkey: my_ed25519_pubkey_hex(),
    };

    if let Ok(data) = serde_json::to_vec(&proposal) {
        publish_gossip("ego-proposals-v1", data).await;
    }

    let committee_vrf_in     = crate::bft_committee::vrf_input(&block.prev_hash, block.height, crate::bft_committee::VRF_ROLE_COMMITTEE);
    let committee_ticket     = crate::bft_committee::sign_vrf_ticket(&seed_32, &committee_vrf_in);
    let committee_ticket_hex = hex::encode(&committee_ticket);
    let self_vote_data       = crate::bft_committee::vote_signing_data(&block.hash, block.height, &miner);
    {
        let self_sig = {
            use ed25519_dalek::{SigningKey, Signer};
            hex::encode(SigningKey::from_bytes(&seed_32).sign(self_vote_data.as_bytes()).to_bytes())
        };
        let block_hash_bytes = hex::decode(&block.hash).unwrap_or_default();
        let (fb_bls_sig, fb_bls_pk) = bls_vote_fields(&block_hash_bytes);
        let self_vote = P2PMessage::BlockVote {
            block_hash: block.hash.clone(),
            height:     block.height,
            voter:      miner.clone(),
            signature:  self_sig.clone(),
            timestamp:  chrono::Utc::now().timestamp(),
            vrf_ticket: committee_ticket_hex.clone(),
            prev_hash:  block.prev_hash.clone(),
            bls_sig:    fb_bls_sig.clone(),
            bls_pubkey: fb_bls_pk.clone(),
            voter_pubkey: my_ed25519_pubkey_hex(),
        };
        if try_lock_self_vote(block.height, &block.hash, current_view()) {
            if let Ok(data) = serde_json::to_vec(&self_vote) {
                publish_gossip("ego-votes-v1", data).await;
            }
        } else {
            eprintln!("[BFT] Suppressing self-vote for #{} — locked on a different block (anti-equivocation)", block.height);
        }
        
        if !is_solo {
            let bh = block.hash.clone();
            let bhgt = block.height;
            let m = miner.clone();
            let ss = self_sig;
            let ts = chrono::Utc::now().timestamp();
            let ct = committee_ticket_hex;
            let ph = block.prev_hash.clone();
            let bs = fb_bls_sig;
            let bp = fb_bls_pk;
            tokio::spawn(async move {
                handle_block_vote(bh, bhgt, m, ss, ts, ct, ph, bs, bp, None).await;
            });
        }
    }

    if is_solo {
        let bh      = block.hash.clone();
        let bheight = block.height;
        tokio::task::spawn_blocking(move || bft_solo_commit(&bh, bheight)).await.ok();
        touch_proposal_timestamp();
        eprintln!("[BFT] Solo fallback block #{} committed", block.height);
    } else {
        touch_proposal_timestamp();
        eprintln!(
            "[BFT] FALLBACK block #{} proposed by highest-DRS node {} — awaiting committee votes",
            next_height, &miner[..12.min(miner.len())]
        );
    }
}

/// Set by the commit path to ask the view-change monitor to drive the next
/// proposal immediately (happy-path pipelining) rather than waiting out the 5s
/// proposal timeout. The monitor — not the vote handler — performs the view
/// change, which keeps it out of the vote→propose async recursion chain.
static PIPELINE_NEXT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn request_pipeline_next() {
    PIPELINE_NEXT.store(true, Ordering::Relaxed);
}

pub async fn run_view_change_monitor() {

    tokio::time::sleep(std::time::Duration::from_secs(15)).await;

    touch_proposal_timestamp();

    // Unambiguous banner: which consensus engine is actually driving this binary.
    if consensus_v2_live_enabled() {
        eprintln!("[Consensus] ENGINE = v2 BftEngine (Dilithium) — LIVE; inline BFT gated off. (EGO_CONSENSUS_LEGACY=1 reverts to inline.)");
    } else if consensus_v2_active() {
        eprintln!("[Consensus] ENGINE = inline HotStuff (EGO_CONSENSUS_LEGACY) with v2 running in SHADOW alongside.");
    } else {
        eprintln!("[Consensus] ENGINE = inline HotStuff (EGO_CONSENSUS_LEGACY).");
    }

    // 250ms tick so the happy-path pipeline signal is picked up quickly; the 5s
    // timeout below is still the fallback for a silent/faulty proposer.
    let mut interval = tokio::time::interval(std::time::Duration::from_millis(250));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut _tick_count: u64 = 0;
    loop {
        interval.tick().await;
        _tick_count += 1;

        // Housekeeping/logging at ~1s and ~10s cadence respectively (not every 250ms).
        if _tick_count % 4 == 0 {
            evict_stale_validators(VALIDATOR_LIVENESS_SECS);
        }
        if _tick_count % 40 == 0 {
            eprintln!("[ViewMon] alive — tick #{} validators={}", _tick_count, known_validators().len());
        }

        // Drive the v2 engine that runs consensus by default: propose a real block when
        // we're its leader, publish + self-vote; receive-side handlers tally votes/QCs and
        // persist on quorum. (Inline BFT drives instead only under EGO_CONSENSUS_LEGACY=1.)
        shadow_v2_tick().await;

        if local_validator_is_unset() {
            let registered = tokio::task::spawn_blocking(ensure_local_validator_identity)
                .await.unwrap_or(false);
            if registered {
                eprintln!("[BFT] Registered local validator (late wallet init)");
            }
        }

        if known_validators().is_empty() { continue; }

        // Fire immediately if the commit path requested pipelining; otherwise wait
        // for the proposal timeout.
        let pipeline = PIPELINE_NEXT.swap(false, Ordering::Relaxed);
        let now  = chrono::Utc::now().timestamp();
        let last = LAST_PROPOSAL_TS.load(Ordering::Relaxed);
        if !pipeline && (last == 0 || now - last < VIEW_CHANGE_TIMEOUT_SECS) { continue; }

        let view_init = tokio::task::spawn_blocking(|| {
            let chain_next = crate::chain_db::latest_block_info().0 + 1;
            let my_addr    = crate::ledger::Ledger::load().address;
            if my_addr.is_empty() { return None; }
            let seed = get_ed25519_seed()?;
            Some((chain_next, my_addr, seed))
        }).await.unwrap_or(None);
        let (chain_next, my_addr, seed_32) = match view_init {
            Some(v) => v,
            None    => continue,
        };
        let next_view = chain_next.max(current_view() + 1);

        {
            let vs = eligible_validators_sorted();
            if !vs.is_empty() {
                let round = current_view().saturating_sub(chain_next);
                let idx = (chain_next as usize)
                    .wrapping_add(round as usize)
                    .wrapping_rem(vs.len());
                let leader = vs.get(idx).cloned().unwrap_or_default();
                let vs_short: Vec<String> = vs.iter().map(|a| a.chars().take(14).collect()).collect();
                eprintln!(
                    "[LeaderDbg] height={} round={} vs(len={})=[{}] idx={} leader={} me={} i_am_leader={}",
                    chain_next, round, vs.len(), vs_short.join(", "), idx,
                    leader.chars().take(14).collect::<String>(),
                    my_addr.chars().take(14).collect::<String>(),
                    leader == my_addr,
                );
                if leader == my_addr {
                    eprintln!("[HotStuff] Stall timeout — round-robin leader for height {} — proposing directly", chain_next);
                    tokio::spawn(async move { propose_block_as_leader().await; });
                    touch_proposal_timestamp();
                    STUCK_VIEWCHANGE_CYCLES.store(0, Ordering::Relaxed);
                    continue;
                }
            }
        }

        if pipeline {
            // Healthy progression after a commit — not a stuck/timeout event, so
            // don't accrue deadlock cycles.
            STUCK_VIEWCHANGE_CYCLES.store(0, Ordering::Relaxed);
            STUCK_AT_NEXT_VIEW.store(next_view, Ordering::Relaxed);
        } else {
            let prev_stuck = STUCK_AT_NEXT_VIEW.swap(next_view, Ordering::Relaxed);
            let cycles = if prev_stuck == next_view {
                let c = STUCK_VIEWCHANGE_CYCLES.fetch_add(1, Ordering::Relaxed) + 1;
                if c >= 10 { // Wait 30 seconds before permanently evicting a validator
                    STUCK_VIEWCHANGE_CYCLES.store(0, Ordering::Relaxed);
                    eprintln!(
                        "[HotStuff] ViewChange deadlock at view {} — halting to preserve BFT safety (waiting for peers to reconnect)",
                        next_view
                    );
                }
                c
            } else {
                STUCK_VIEWCHANGE_CYCLES.store(1, Ordering::Relaxed);
                1
            };
            eprintln!("[HotStuff] Proposal timeout — broadcasting ViewChange for view {} (stuck cycle {})", next_view, cycles);

            // Deadlock escape: stuck at the same view across SOLO_DEADLOCK_VIEWS
            // timeouts means the committee is unreachable (can't gather a
            // ViewChange quorum). Fall back to solo so a partitioned /
            // single-operator node keeps producing instead of looping forever.
            // should_solo_commit_now() gates this (returns false on a
            // quorum-graduated chain unless EGO_ALLOW_SOLO_FORK=1). The solo commit
            // advances the chain → STUCK_VIEWCHANGE_CYCLES resets → BFT retries.
            if cycles >= SOLO_DEADLOCK_VIEWS && should_solo_commit_now() {
                eprintln!("[HotStuff] ViewChange deadlock at view {} — solo-producing to restore liveness", next_view);
                tokio::spawn(async { propose_block_as_leader_forced().await; });
                touch_proposal_timestamp();
                continue;
            }
            eprintln!("[HotStuff] Proposal timeout — broadcasting ViewChange for view {}", next_view);
        }

        let vote_data = format!("viewchange:{}:{}", next_view, my_addr);
        let sig = {
            use ed25519_dalek::{SigningKey, Signer};
            hex::encode(SigningKey::from_bytes(&seed_32).sign(vote_data.as_bytes()).to_bytes())
        };
        let ts = now;

        let msg = P2PMessage::ViewChange { view: next_view, voter: my_addr.clone(), signature: sig, timestamp: ts };
        if let Ok(data) = serde_json::to_vec(&msg) {
            publish_gossip("ego-viewchange-v1", data).await;
        }

        handle_view_change_msg(next_view, my_addr).await;

        touch_proposal_timestamp();
    }
}

/// Independent liveness watchdog: detects a stalled chain by the only signal that
/// can't be fooled by the view-change machinery — the chain HEIGHT not advancing.
/// If it hasn't moved for SOLO_STALL_SECS, flag LIVENESS_STALLED (so
/// should_solo_commit_now flips to solo) and force a proposal so a partitioned /
/// single-operator node keeps producing instead of hanging on ViewChange forever.
/// Runs on its own task so a stuck view-change monitor can't take it down. Gated
/// by should_solo_commit_now (no-op on a quorum-graduated chain unless
/// EGO_ALLOW_SOLO_FORK=1, so it can never fork past the QC ratchet).
pub async fn run_solo_liveness_watchdog() {
    let startup_delay = 20;
    tokio::time::sleep(std::time::Duration::from_secs(startup_delay)).await;
    let mut last_height = crate::chain_db::latest_block_info().0;
    let mut last_advance = chrono::Utc::now().timestamp();
    let mut last_heartbeat = 0i64;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let h   = crate::chain_db::latest_block_info().0;
        let now = chrono::Utc::now().timestamp();

        if h > last_height && h > 0 {
            last_height  = h;
            last_advance = now;
            LIVENESS_STALLED.store(false, Ordering::Relaxed);
            continue;
        }

        let stalled_for = now - last_advance;

        if now - last_heartbeat >= 30 {
            last_heartbeat = now;
            eprintln!(
                "[Liveness] watchdog alive — height={} stalled={}s validators={}",
                h, stalled_for, known_validators().len()
            );
        }

        let stall_threshold = if known_validators().len() <= 1 { SOLO_ALONE_STALL_SECS } else { SOLO_STALL_SECS };
        if stalled_for < stall_threshold { continue; }
        if known_validators().is_empty() { continue; }

        LIVENESS_STALLED.store(true, Ordering::Relaxed);
        if should_solo_commit_now() {
            eprintln!(
                "[Liveness] Chain stalled {}s at height {} — solo-producing to restore liveness",
                stalled_for, h
            );
            if tokio::time::timeout(
                std::time::Duration::from_secs(8),
                propose_block_as_leader_forced(),
            ).await.is_err() {
                eprintln!("[Liveness] block production timed out (swarm busy) — will retry");
            }
            last_advance = now;
        } else {
            eprintln!(
                "[Liveness] Chain stalled {}s at height {} but solo is not permitted \
                 (peers still reachable, or chain is quorum-finalized) — \
                 holding for a quorum",
                stalled_for, h
            );
        }
    }
}

fn emit_sync_status(state: &str, local: u64, target: u64, after_sleep: bool) {
    if let Some(h) = APP_HANDLE.get() {
        let _ = h.emit_all("ego://sync-status", serde_json::json!({
            "state": state,
            "local": local,
            "target": target,
            "after_sleep": after_sleep,
        }));
    }
}

pub async fn run_sync_status_watcher() {
    const LAG_ENTER: u64 = 8;
    const LAG_EXIT: u64 = 2;
    const SLEEP_GAP_SECS: i64 = 30;
    const CHECKING_GRACE_SECS: i64 = 20;

    let mut last_tick = chrono::Utc::now().timestamp();
    let mut state = 0u8;
    let mut checking_since = 0i64;
    let mut after_sleep = false;
    let mut last_progress_emit = 0i64;

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let now = chrono::Utc::now().timestamp();
        let woke = now - last_tick > SLEEP_GAP_SECS;
        last_tick = now;

        let local = crate::chain_db::latest_block_info().0;
        let best = NETWORK_BEST_HEIGHT.load(Ordering::Relaxed).max(local);
        let behind = best.saturating_sub(local);

        if woke {
            eprintln!("[SyncStatus] Wake from sleep detected — reconnecting and checking the chain tip");
            SUSPENDING.store(false, Ordering::Relaxed);
            bump_payout_floor();
            tokio::spawn(dial_bootstrap_peers());
            tokio::spawn(sync_chain_from_peers());
            if state != 2 {
                state = 1;
                checking_since = now;
                after_sleep = true;
                emit_sync_status("checking", local, best, true);
            }
            continue;
        }

        match state {
            0 => {
                if behind >= LAG_ENTER {
                    state = 2;
                    after_sleep = false;
                    last_progress_emit = now;
                    eprintln!("[SyncStatus] {} blocks behind the network — catching up", behind);
                    emit_sync_status("catching_up", local, best, false);
                    if let Some(h) = APP_HANDLE.get() {
                        crate::commands::notifications::notify(
                            h,
                            "Catching up with the network",
                            "Your node fell behind and is syncing blocks. Block creation resumes automatically once caught up.",
                        );
                    }
                }
            }
            1 => {
                if behind > LAG_EXIT {
                    state = 2;
                    last_progress_emit = now;
                    eprintln!("[SyncStatus] {} blocks behind after wake — catching up", behind);
                    emit_sync_status("catching_up", local, best, after_sleep);
                    if let Some(h) = APP_HANDLE.get() {
                        crate::commands::notifications::notify(
                            h,
                            "Catching up after sleep",
                            "Your node is syncing the blocks it missed. Block creation resumes automatically once caught up.",
                        );
                    }
                } else if now - checking_since >= CHECKING_GRACE_SECS {
                    state = 0;
                    after_sleep = false;
                    emit_sync_status("synced", local, best, false);
                }
            }
            _ => {
                if behind <= LAG_EXIT {
                    state = 0;
                    after_sleep = false;
                    eprintln!("[SyncStatus] Caught up to the network at height {}", local);
                    emit_sync_status("synced", local, best, false);
                    if let Some(h) = APP_HANDLE.get() {
                        crate::commands::notifications::notify(
                            h,
                            "Back in sync",
                            "Your node caught up and is creating blocks again.",
                        );
                    }
                } else if now - last_progress_emit >= 2 {
                    last_progress_emit = now;
                    emit_sync_status("catching_up", local, best, after_sleep);
                }
            }
        }
    }
}

pub async fn register_cid_on_relay(cid: &str, holder_addr: &str, endpoint: &str) {
    dht_register_cid(cid, holder_addr, endpoint).await;
}

pub async fn register_porep_commitment(
    cid:         &str,
    prover_addr: &str,
    _comm_d:     &str,
    comm_r:      &str,
    _n_real_leaves:   usize,
    _n_padded_leaves: usize,
    _sector_id: u64,
    file_size:  u64,
    expiry:     i64,
) {
    if cid.is_empty() || comm_r.is_empty() || prover_addr.is_empty() { return; }

    let sign_input = format!("porep:{}:{}:{}", prover_addr, cid, comm_r);
    let signature = get_ed25519_seed()
        .and_then(|s| ego_core::KeyPair::from_bytes(&s).ok())
        .map(|kp| hex::encode(kp.sign_ed25519(sign_input.as_bytes()).as_bytes()))
        .unwrap_or_default();

    if signature.is_empty() { return; }

    let msg = P2PMessage::StorageCommit {
        prover_addr: prover_addr.to_string(),
        cid:         cid.to_string(),
        comm_r:      comm_r.to_string(),
        file_size,
        expiry,
        signature,
    };

    if let Ok(data) = serde_json::to_vec(&msg) {
        publish_gossip("ego-storage-v1", data).await;
    }
}

pub fn generate_local_challenges(
    prover_addr: &str,
    stored_files: &[crate::ledger::StoredFile],
) -> Vec<serde_json::Value> {
    if stored_files.is_empty() { return vec![]; }

    let (tip_height, _) = crate::chain_db::latest_block_info();
    let epoch = tip_height / 100;
    let block_hash = crate::chain_db::get_block_hash_at((epoch * 100).max(1))
        .unwrap_or_else(|| crate::chain_db::get_tip_hash());

    stored_files.iter().enumerate().map(|(i, file)| {
        let seed_input = format!("{}:{}:{}:{}", block_hash, prover_addr, file.cid, epoch);
        let seed_bytes = blake3::hash(seed_input.as_bytes());
        let seed_hex = seed_bytes.to_hex().to_string();

        let challenge_id = format!("local-{}-{}-{}", epoch, i, &file.cid[..8.min(file.cid.len())]);
        let n_real = ((file.original_size / 4096) + 1).min(1024) as u64;
        let n_padded = n_real.next_power_of_two();

        serde_json::json!({
            "challenge_id": challenge_id,
            "cid": file.cid,
            "challenge_seed": seed_hex,
            "n_real_leaves": n_real,
            "n_padded_leaves": n_padded,
            "comm_d": file.cid,
            "challenge_block_hash": block_hash,
            "source": "local",
        })
    }).collect()
}

pub async fn fetch_post_challenges(prover_addr: &str) -> Vec<serde_json::Value> {
    if prover_addr.trim().is_empty() { return vec![]; }

    let (tip_height, _) = tokio::task::spawn_blocking(crate::chain_db::latest_block_info).await.unwrap_or((0, String::new()));
    let epoch = tip_height / 100;
    let block_hash = tokio::task::spawn_blocking(move || crate::chain_db::get_block_hash_at((epoch * 100).max(1))
        .unwrap_or_else(|| crate::chain_db::get_tip_hash())).await.unwrap_or_default();
    
    let deals = tokio::task::spawn_blocking(crate::chain_db::list_storage_deals).await.unwrap_or_default();
    deals.iter()
        .filter(|d| d.provider_address == prover_addr && d.status == "active")
        .enumerate()
        .map(|(i, deal)| {
            let seed_input = format!("{}:{}:{}:{}", block_hash, prover_addr, deal.cid, epoch);
            let seed_bytes = blake3::hash(seed_input.as_bytes());
            let seed_hex = seed_bytes.to_hex().to_string();
            let challenge_id = format!("chain-{}-{}-{}", epoch, i, &deal.cid[..8.min(deal.cid.len())]);
            let n_padded = deal.n_real_leaves.next_power_of_two();
            serde_json::json!({
                "challenge_id": challenge_id,
                "cid": deal.cid,
                "challenge_seed": seed_hex,
                "n_real_leaves": deal.n_real_leaves,
                "n_padded_leaves": n_padded,
                "comm_d": deal.comm_d_hex,
                "challenge_block_hash": block_hash,
                "source": "chain",
            })
        }).collect()
}

pub async fn fetch_pending_post_rewards() -> Vec<crate::ledger::LedgerTx> {
    // Removed Web2 Oracle dependency - rewards must be minted by proposer via BFT
    vec![]
}

pub async fn notify_post_rewards_claimed(proof_ids: Vec<String>) {
    // Deprecated Oracle endpoint
}

pub async fn submit_post_proof(payload: serde_json::Value) -> bool {
    // Shifted from HTTP POST to Oracle -> pure P2P gossip
    if let Ok(data) = serde_json::to_vec(&payload) {
        publish_gossip("ego-storage-v1", data).await;
        return true;
    }
    false
}

#[derive(Debug, Clone, Default)]
pub struct CidHolder {
    pub holder_addr: String,
    pub endpoint:    String,
}

pub async fn find_cid_holders(cid: &str) -> Vec<CidHolder> {
    let cid = cid.trim();
    if cid.is_empty() {
        return vec![];
    }

    dht_find_cid(cid).await;

    let mut holders = Vec::new();
    if let Some(value) = read_dht_cached_value(&format!("ego-cid:{}", cid)) {
        if let Ok(record) = serde_json::from_slice::<serde_json::Value>(&value) {
            let holder_addr = record["holder_addr"].as_str().unwrap_or_default().to_string();
            let endpoint = record["endpoint"].as_str().unwrap_or_default().to_string();
            if !holder_addr.is_empty() || !endpoint.is_empty() {
                holders.push(CidHolder { holder_addr, endpoint });
            }
        }
    }

    holders
}

pub async fn dht_register_cid(cid: &str, holder_addr: &str, endpoint: &str) {
    let record = serde_json::json!({
        "cid":         cid,
        "holder_addr": holder_addr,
        "endpoint":    endpoint,
        "ts":          chrono::Utc::now().timestamp(),
    });
    let key = format!("ego-cid:{}", cid);
    if let Ok(v) = serde_json::to_vec(&record) {
        if let Some(tx) = DHT_CMD_TX.get() {
            let _ = tx.send(DhtCommand::PutPeer { key, value: v });
        }
    }
}

pub async fn dht_find_cid(cid: &str) {
    let key = format!("ego-cid:{}", cid);
    if let Some(tx) = DHT_CMD_TX.get() {
        let _ = tx.send(DhtCommand::GetPeers { key });
    }
}

pub async fn fetch_peers_from_relay(_app: Option<&tauri::AppHandle<tauri::Wry>>) {
    dht_discover_peers().await;
}

fn dht_cache_path() -> std::path::PathBuf { base_data_dir().join("dht_cache.json") }

fn read_dht_cached_value(key: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;

    let data = std::fs::read_to_string(dht_cache_path()).ok()?;
    let map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&data).ok()?;
    let b64 = map.get(key)?.as_str()?;
    base64::engine::general_purpose::STANDARD.decode(b64).ok()
}

fn save_dht_record_to_cache(key: &str, value: &[u8]) {
    use base64::Engine as _;
    let path = dht_cache_path();
    let data = std::fs::read_to_string(&path).unwrap_or_default();
    let mut map: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&data).unwrap_or_default();

    map.insert(key.to_string(), serde_json::Value::String(
        base64::engine::general_purpose::STANDARD.encode(value)
    ));
    if let Ok(serialized) = serde_json::to_string(&map) {
        let _ = crate::utils::atomic_write(&path, serialized.as_bytes());
    }
}

pub async fn restore_dht_cache() {
    use base64::Engine as _;
    let path = dht_cache_path();
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(_) => return,
    };
    let map: serde_json::Map<String, serde_json::Value> =
        match serde_json::from_str(&data) {
            Ok(m) => m,
            Err(_) => return,
        };
    let Some(tx) = DHT_CMD_TX.get() else { return };
    let mut count = 0;
    for (key, val) in &map {
        if let Some(b64) = val.as_str() {
            if let Ok(value) = base64::engine::general_purpose::STANDARD.decode(b64) {
                let _ = tx.send(DhtCommand::PutPeer { key: key.clone(), value });
                count += 1;
            }
        }
    }
    if count > 0 {
        eprintln!("[DHT] Restored {} cached records from disk", count);
    }
}

pub async fn dht_publish_self(address: &str, endpoint: &str, name: &str) {
    let record_value = serde_json::json!({
        "address":  address,
        "endpoint": endpoint,
        "name":     name,
        "ts":       chrono::Utc::now().timestamp(),
    });
    let value = match serde_json::to_vec(&record_value) {
        Ok(v) => v,
        Err(_) => return,
    };

    let key = format!("ego-peer:{}", address);

    save_dht_record_to_cache(&key, &value);
    if let Some(tx) = DHT_CMD_TX.get() {
        let _ = tx.send(DhtCommand::PutPeer { key, value });
    }
}

pub async fn dht_discover_peers() {
    let key = "ego-peers-v1".to_string();
    if let Some(tx) = DHT_CMD_TX.get() {
        let _ = tx.send(DhtCommand::GetPeers { key });
    }
}

pub async fn dht_discover_relays() {
    let Some(tx) = DHT_CMD_TX.get() else { return };

    let cache_path = dht_cache_path();
    if let Ok(data) = std::fs::read(&cache_path) {
        if let Ok(map) = serde_json::from_slice::<std::collections::HashMap<String, String>>(&data) {
            for key in map.keys().filter(|k| k.starts_with("ego-relay:")) {
                let _ = tx.send(DhtCommand::GetPeers { key: key.clone() });
            }
        }
    }
}

fn inbox_key(recipient_addr: &str, sender_addr: &str) -> String {
    let rh = hex::encode(blake3::hash(recipient_addr.as_bytes()).as_bytes());
    let sh = hex::encode(blake3::hash(sender_addr.as_bytes()).as_bytes());
    format!("ego-inbox:{}:{}", rh, sh)
}

/// Well-known per-recipient key with no sender component — the only DHT key
/// a recipient can query without already knowing who's trying to reach them.
/// `dht_inbox_poll` blind-polls exactly this key every tick, independent of
/// its local cache. Used for first-contact handshake messages (ContactRequest
/// / ContactResponse), where the recipient by definition doesn't yet know the
/// sender's address to derive the sender-specific `inbox_key`.
fn doorbell_key(recipient_addr: &str) -> String {
    format!("ego-inbox:{}", hex::encode(blake3::hash(recipient_addr.as_bytes()).as_bytes()))
}

pub async fn dht_inbox_deposit(from_addr: &str, to_addr: &str, msg: &P2PMessage) {
    let Ok(value) = serde_json::to_vec(msg) else { return };
    // ContactRequest/ContactResponse are first-contact messages: the recipient
    // can't have `inbox_key(to, from)` in their local cache to discover it
    // (they don't know `from` yet), so those go to the sender-agnostic
    // doorbell key that gets blind-polled unconditionally instead.
    let key = match msg {
        P2PMessage::ContactRequest { .. } | P2PMessage::ContactResponse { .. } => doorbell_key(to_addr),
        _ => inbox_key(to_addr, from_addr),
    };
    save_dht_record_to_cache(&key, &value);
    if let Some(tx) = DHT_CMD_TX.get() {
        let _ = tx.send(DhtCommand::PutPeer { key, value });
        eprintln!("[DHT-Inbox] Deposited message for {} in DHT", &to_addr[..12.min(to_addr.len())]);
    }
}

pub async fn dht_inbox_poll(my_addr: &str) {
    if my_addr.is_empty() { return; }

    let my_prefix = format!("ego-inbox:{}:",
        hex::encode(blake3::hash(my_addr.as_bytes()).as_bytes()));

    let cache_path = dht_cache_path();
    let data = std::fs::read_to_string(&cache_path).unwrap_or_default();
    let map: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&data).unwrap_or_default();

    let Some(tx) = DHT_CMD_TX.get() else { return };

    let _ = tx.send(DhtCommand::GetPeers { key: doorbell_key(my_addr) });

    let mut queried = 0;
    for key in map.keys() {
        if key.starts_with(&my_prefix) {
            let _ = tx.send(DhtCommand::GetPeers { key: key.clone() });
            queried += 1;
        }
    }
    if queried > 0 {
        eprintln!("[DHT-Inbox] Polling {} inbox slot(s) in DHT", queried);
    }
}

// ── Sealed gossip DM ─────────────────────────────────────────────────────────
// Fallback transport for messenger traffic. Direct request-response needs a
// dialable circuit and the DHT needs the record to land on a peer the recipient
// later queries; both are unreliable when every node is NAT'd behind one relay.
// Gossip reaches the whole mesh regardless, so a message sealed to the
// recipient's identity key rides it without exposing anything to the relay or
// to the other nodes forwarding it.

pub const DM_TOPIC: &str = "ego-dm-v1";

static DM_SEEN: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();
const DM_SEEN_TTL_SECS: i64 = 3600;

fn dm_already_seen(id: &str) -> bool {
    let now = Utc::now().timestamp();
    let mut map = DM_SEEN.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
    map.retain(|_, ts| now - *ts < DM_SEEN_TTL_SECS);
    if map.contains_key(id) {
        return true;
    }
    map.insert(id.to_string(), now);
    false
}

/// Contact records hold ed25519 keys as hex (old bundles, and the requester's
/// own key) or base64 (v2 bundles). Accept both.
fn decode_pubkey32(s: &str) -> Option<[u8; 32]> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    let raw = hex::decode(trimmed).ok().filter(|b| b.len() == 32).or_else(|| {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .ok()
            .filter(|b| b.len() == 32)
    })?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Some(out)
}

fn ed25519_pub_to_x25519(ed: &[u8; 32]) -> Option<x25519_dalek::PublicKey> {
    let point = curve25519_dalek::edwards::CompressedEdwardsY(*ed).decompress()?;
    Some(x25519_dalek::PublicKey::from(point.to_montgomery().to_bytes()))
}

/// x25519 counterpart of this wallet's ed25519 identity key. ed25519 signing
/// keys expand as `sha512(seed)[..32]`, and x25519-dalek clamps on use, so this
/// is the same scalar the sender's `ed25519_pub_to_x25519` derives a point for.
fn my_x25519_secret() -> Option<x25519_dalek::StaticSecret> {
    let seed = crate::ledger::load_seed().ok().flatten()?;
    if seed.len() < 32 {
        return None;
    }
    use sha2::{Digest, Sha512};
    let expanded = Sha512::digest(&seed[..32]);
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&expanded[..32]);
    Some(x25519_dalek::StaticSecret::from(sk))
}

fn dm_cipher_key(shared: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("ego dm seal v1", shared)
}

pub fn seal_dm(to_addr: &str, to_ed25519: &str, inner: &P2PMessage) -> Option<P2PMessage> {
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
    use rand::RngCore;

    let their_x = ed25519_pub_to_x25519(&decode_pubkey32(to_ed25519)?)?;

    let mut eph_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut eph_bytes);
    let eph_secret = x25519_dalek::StaticSecret::from(eph_bytes);
    let eph_public = x25519_dalek::PublicKey::from(&eph_secret);
    let shared     = eph_secret.diffie_hellman(&their_x);

    let cipher = Aes256Gcm::new_from_slice(&dm_cipher_key(shared.as_bytes())).ok()?;
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let plaintext = serde_json::to_vec(inner).ok()?;
    let ct = cipher.encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref()).ok()?;

    let ct_hex = hex::encode(&ct);
    Some(P2PMessage::SealedDm {
        to:      to_addr.to_string(),
        eph_pub: hex::encode(eph_public.as_bytes()),
        nonce:   hex::encode(nonce_bytes),
        id:      hex::encode(&blake3::hash(ct_hex.as_bytes()).as_bytes()[..16]),
        ct:      ct_hex,
    })
}

fn open_dm(eph_pub: &str, nonce_hex: &str, ct_hex: &str) -> Option<P2PMessage> {
    open_dm_with(&my_x25519_secret()?, eph_pub, nonce_hex, ct_hex)
}

fn open_dm_with(
    secret:    &x25519_dalek::StaticSecret,
    eph_pub:   &str,
    nonce_hex: &str,
    ct_hex:    &str,
) -> Option<P2PMessage> {
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};

    let mut eph = [0u8; 32];
    let raw = hex::decode(eph_pub).ok()?;
    if raw.len() != 32 {
        return None;
    }
    eph.copy_from_slice(&raw);

    let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(eph));
    let cipher = Aes256Gcm::new_from_slice(&dm_cipher_key(shared.as_bytes())).ok()?;

    let nonce_bytes = hex::decode(nonce_hex).ok()?;
    if nonce_bytes.len() != 12 {
        return None;
    }
    let ct = hex::decode(ct_hex).ok()?;
    let pt = cipher.decrypt(Nonce::from_slice(&nonce_bytes), ct.as_ref()).ok()?;
    serde_json::from_slice::<P2PMessage>(&pt).ok()
}

/// Seal `inner` to `to_addr` and broadcast it on the mesh. Returns false only
/// when the contact's identity key is unusable, so callers can log it.
pub async fn gossip_sealed_dm(to_addr: &str, to_ed25519: &str, inner: &P2PMessage) -> bool {
    let Some(sealed) = seal_dm(to_addr, to_ed25519, inner) else {
        return false;
    };
    let Ok(data) = serde_json::to_vec(&sealed) else {
        return false;
    };
    publish_gossip(DM_TOPIC, data).await;
    true
}

#[cfg(test)]
mod sealed_dm_tests {
    use super::*;

    fn x25519_secret_from_seed(seed: &[u8; 32]) -> x25519_dalek::StaticSecret {
        use sha2::{Digest, Sha512};
        let expanded = Sha512::digest(seed);
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&expanded[..32]);
        x25519_dalek::StaticSecret::from(sk)
    }

    /// The sender converts the recipient's published ed25519 key to a
    /// montgomery point; the recipient derives a scalar straight from its seed.
    /// If those two ever stop describing the same keypair, every sealed
    /// envelope silently fails to open.
    #[test]
    fn ed25519_pub_converts_to_the_recipients_own_x25519_key() {
        let seed = [7u8; 32];
        let ed_pub = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();

        let from_public = ed25519_pub_to_x25519(&ed_pub).expect("decompress");
        let from_secret = x25519_dalek::PublicKey::from(&x25519_secret_from_seed(&seed));

        assert_eq!(from_public.as_bytes(), from_secret.as_bytes());
    }

    #[test]
    fn sealed_envelope_round_trips_to_the_addressee() {
        let seed = [42u8; 32];
        let ed_pub = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();

        let inner = P2PMessage::ChatMessage {
            bundle: "egomsg1:a:b:1:text:00:ff".to_string(),
            seq:    3,
        };
        let sealed = seal_dm("egot1recipient", &hex::encode(ed_pub), &inner).expect("seal");

        let P2PMessage::SealedDm { to, eph_pub, nonce, ct, id } = sealed else {
            panic!("seal_dm produced the wrong variant");
        };
        assert_eq!(to, "egot1recipient");
        assert!(!id.is_empty());

        let opened = open_dm_with(&x25519_secret_from_seed(&seed), &eph_pub, &nonce, &ct)
            .expect("addressee opens its own envelope");
        match opened {
            P2PMessage::ChatMessage { bundle, seq } => {
                assert_eq!(bundle, "egomsg1:a:b:1:text:00:ff");
                assert_eq!(seq, 3);
            }
            other => panic!("unexpected inner message: {:?}", other),
        }

        // A different wallet must not be able to open it.
        assert!(open_dm_with(&x25519_secret_from_seed(&[9u8; 32]), &eph_pub, &nonce, &ct).is_none());
    }

    /// v2 cards carry base64 keys, older ones and locally-built records carry
    /// hex; both have to seal.
    #[test]
    fn identity_keys_decode_from_hex_and_base64() {
        use base64::Engine as _;
        let raw = [3u8; 32];
        let hex_form = hex::encode(raw);
        let b64_form = base64::engine::general_purpose::STANDARD.encode(raw);

        assert_eq!(decode_pubkey32(&hex_form), Some(raw));
        assert_eq!(decode_pubkey32(&b64_form), Some(raw));
        assert_eq!(decode_pubkey32(""), None);
        assert_eq!(decode_pubkey32("not-a-key"), None);
    }
}

pub async fn dht_publish_shard_assignments(address: &str, endpoint: &str) {
    let map = crate::sharding::load_shard_map();
    if map.shard_count <= 1 { return; }

    let all_nodes: Vec<String> = map.assignments.iter()
        .map(|a| a.node_address.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter().collect();

    let held: Vec<u32> = crate::sharding::my_shards(address, &map, &all_nodes)
        .into_iter().map(|(id, _)| id).collect();

    for shard_id in held {
        let key = format!("ego-shard:{}", shard_id);
        let value = serde_json::json!({
            "shard_id":  shard_id,
            "address":   address,
            "endpoint":  endpoint,
            "ts":        chrono::Utc::now().timestamp(),
        });
        if let Ok(v) = serde_json::to_vec(&value) {
            if let Some(tx) = DHT_CMD_TX.get() {
                let _ = tx.send(DhtCommand::PutPeer { key, value: v });
            }
        }
    }
}

pub async fn dht_query_shard_holders(shard_id: u32) {
    let key = format!("ego-shard:{}", shard_id);
    if let Some(tx) = DHT_CMD_TX.get() {
        let _ = tx.send(DhtCommand::GetPeers { key });
    }
}

pub async fn broadcast_vacancy_notices() {
    let map = crate::sharding::load_shard_map();
    if map.shard_count <= 1 { return; }

    let vacant = crate::sharding::detect_vacant_shards(&map);
    for (shard_id, current_holders) in vacant {
        tracing::debug!("[Sharding] Shard {} under-replicated: {}/{} holders",
            shard_id, current_holders, crate::sharding::REPLICATION_FACTOR);
        let notice = P2PMessage::ShardVacancyNotice { shard_id, current_holders };
        if let Ok(data) = serde_json::to_vec(&notice) {
            publish_gossip("ego-shards-v1", data).await;
        }
    }
}

pub async fn query_block_from_shard(block_height: u64) {
    let map = crate::sharding::load_shard_map();
    if map.shard_count <= 1 { return; }

    let shard_id = crate::sharding::shard_for_height(block_height, map.shard_count);

    let now = chrono::Utc::now().timestamp();
    let holder_ep = map.assignments.iter()
        .find(|a| a.shard_id == shard_id && !a.node_endpoint.is_empty() && now - a.last_seen < 300)
        .map(|a| a.node_endpoint.clone());

    let my_addr = crate::ledger::Ledger::load().address;
    let my_ep   = get_public_endpoint().await;

    if let Some(ep) = holder_ep {
        let req = P2PMessage::ShardBlockQuery {
            block_height,
            requester_address:  my_addr,
            requester_endpoint: my_ep,
        };
        tokio::spawn(async move {
            let _ = send_message_any(&[ep], &req).await;
        });
    }
}

pub async fn get_relay_endpoint(address: &str) -> Option<String> {
    let address = address.trim();
    if address.is_empty() {
        return None;
    }

    if let Some(endpoint) = load_peer_cache().into_iter()
        .find(|p| p.address == address && !p.endpoint.trim().is_empty())
        .map(|p| p.endpoint)
    {
        return Some(endpoint);
    }

    let now = chrono::Utc::now().timestamp();
    if let Some(endpoint) = crate::sharding::load_shard_map().assignments.into_iter()
        .find(|a| a.node_address == address && !a.node_endpoint.trim().is_empty() && now - a.last_seen < 600)
        .map(|a| a.node_endpoint)
    {
        return Some(endpoint);
    }

    if let Some(value) = read_dht_cached_value(&format!("ego-peer:{}", address)) {
        if let Ok(record) = serde_json::from_slice::<serde_json::Value>(&value) {
            let endpoint = record["endpoint"].as_str().unwrap_or_default().trim().to_string();
            if !endpoint.is_empty() {
                return Some(endpoint);
            }
        }
    }

    None
}

#[cfg(target_os = "windows")]
fn ensure_firewall_rule() {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    // Program-based rule first: allow ALL inbound traffic for the Ego Desktop
    // binary. A port rule for 47393 alone does NOT cover mDNS multicast (UDP
    // 5353), so same-LAN peers could never discover each other. Allowing the
    // program covers the P2P port, mDNS, and any future ports in one rule.
    if let Ok(exe) = std::env::current_exe() {
        let exe_str = exe.to_string_lossy().to_string();
        let name = "Ego Desktop (allow app)";
        let exists = std::process::Command::new("netsh")
            .args(["advfirewall", "firewall", "show", "rule", &format!("name={}", name)])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map(|o| o.status.success() && !o.stdout.is_empty())
            .unwrap_or(false);
        if !exists {
            let _ = std::process::Command::new("netsh")
                .args([
                    "advfirewall", "firewall", "add", "rule",
                    &format!("name={}", name),
                    "dir=in", "action=allow",
                    &format!("program={}", exe_str),
                    "enable=yes", "profile=any",
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .output();
        }
    }

    for (name, proto, port) in [
        (format!("Ego Desktop P2P TCP {}", p2p_port()), "TCP", p2p_port()),
        (format!("Ego Desktop P2P UDP {}", p2p_port()), "UDP", p2p_port()),
        // mDNS multicast — required for zero-config same-LAN peer discovery.
        ("Ego Desktop mDNS UDP 5353".to_string(), "UDP", 5353),
    ] {
        let check = std::process::Command::new("netsh")
            .args(["advfirewall", "firewall", "show", "rule", &format!("name={}", name)])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        if let Ok(out) = check {
            if out.status.success() && !out.stdout.is_empty() { continue; }
        }
        let _ = std::process::Command::new("netsh")
            .args([
                "advfirewall", "firewall", "add", "rule",
                &format!("name={}", name),
                "dir=in", "action=allow",
                &format!("protocol={}", proto),
                &format!("localport={}", port),
                "enable=yes", "profile=any",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    }
}

#[cfg(not(target_os = "windows"))]
fn ensure_firewall_rule() {}


pub async fn run_porep_challenge_loop() {
    // Wait for p2p to fully start before issuing challenges.
    tokio::time::sleep(Duration::from_secs(60)).await;

    const CHALLENGE_INTERVAL_SECS: u64   = 300;  // issue new challenges every 5 min
    const CHALLENGE_TIMEOUT_SECS:  i64   = 600;  // 10 min to respond before penalty
    const MISSED_CHALLENGE_PENALTY: u64  = 100;  // coverage score deduction for timeout
    const MAX_CHALLENGES_PER_ROUND: usize = 5;

    let mut interval = tokio::time::interval(Duration::from_secs(CHALLENGE_INTERVAL_SECS));
    let mut round_counter: u64 = 0;

    loop {
        interval.tick().await;
        round_counter += 1;

        let my_addr = crate::ledger::Ledger::load().address;
        if my_addr.is_empty() { continue; }

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);

        // ── Expire outstanding challenges that timed out ──────────────────
        {
            let mut challenges = outstanding_challenges();
            let expired: Vec<String> = challenges
                .iter()
                .filter(|(_, c)| (now_ms / 1000) - (c.issued_at_ms / 1000) >= CHALLENGE_TIMEOUT_SECS)
                .map(|(k, _)| k.clone())
                .collect();
            let mut evictions: Vec<(String, String)> = Vec::new();
            for key in expired {
                if let Some(c) = challenges.remove(&key) {
                    eprintln!(
                        "[PoRep] TIMEOUT: {} did not respond for block …{} — penalty -{}",
                        &c.prover[..c.prover.len().min(20)],
                        &key[key.len().saturating_sub(12)..],
                        MISSED_CHALLENGE_PENALTY
                    );
                    let current  = crate::poc::get_peer_score(&c.prover);
                    let penalised = current.saturating_sub(MISSED_CHALLENGE_PENALTY).max(1);
                    crate::poc::record_peer_score(&c.prover, penalised);
                    let fails = porep_record_fail(&c.prover);
                    if fails >= POREP_MAX_CONSECUTIVE_FAILS {
                        evictions.push((c.prover.clone(), c.manifest_cid.clone()));
                        porep_consecutive_fails().remove(&c.prover);
                    }
                }
            }
            drop(challenges);
            for (prover, cid) in evictions {
                porep_evict_peer(&prover, &cid);
            }
        }


        let ledger = crate::ledger::Ledger::load();
        let mut challenged = 0usize;

        for file in &ledger.stored_files {
            if challenged >= MAX_CHALLENGES_PER_ROUND { break; }
            if file.replica_peers.is_empty() { continue; }

            // Load the manifest to get block entries.
            let manifest = match crate::blocks::load_manifest(&file.cid) {
                Ok(m)  => m,
                Err(_) => continue,
            };
            if manifest.blocks.is_empty() { continue; }


            let prover_idx  = round_counter as usize % file.replica_peers.len();
            let prover       = &file.replica_peers[prover_idx];
            let block_idx    = (round_counter as usize + prover_idx) % manifest.blocks.len();
            let block_entry  = &manifest.blocks[block_idx];
            let block_cid    = &block_entry.block_cid;

            // Skip if we don't have the block on disk (can't verify response).
            if !crate::blocks::have_block(block_cid) { continue; }

            let enc_block = match crate::blocks::load_block(block_cid) {
                Ok(b)  => b,
                Err(_) => continue,
            };


            let nonce_input = format!("porep-challenge:{}:{}:{}:{}", prover, block_cid, now_ms, round_counter);
            let nonce_bytes = *blake3::hash(nonce_input.as_bytes()).as_bytes();
            let nonce_hex   = hex::encode(&nonce_bytes);


            let mut hasher = blake3::Hasher::new();
            hasher.update(&nonce_bytes);
            hasher.update(&enc_block);
            let expected_hash = hasher.finalize().to_hex().to_string();


            let challenge_key = format!("{}:{}", block_cid, nonce_hex);
            outstanding_challenges().insert(challenge_key, OutstandingChallenge {
                expected_hash,
                prover: prover.clone(),
                issued_at_ms: now_ms,
                manifest_cid: file.cid.clone(),
            });

            let challenge = P2PMessage::StorageProofChallenge {
                manifest_cid: file.cid.clone(),
                block_cid:    block_cid.clone(),
                nonce:        nonce_hex.clone(),
                challenger:   my_addr.clone(),
            };

            if let Ok(data) = serde_json::to_vec(&challenge) {
                publish_gossip("ego-storage-v1", data).await;
                eprintln!(
                    "[PoRep] Challenged {} for block …{} (round {})",
                    &prover[..prover.len().min(20)],
                    &block_cid[block_cid.len().saturating_sub(12)..],
                    round_counter
                );
                challenged += 1;
            }
      
        }
    }
}
