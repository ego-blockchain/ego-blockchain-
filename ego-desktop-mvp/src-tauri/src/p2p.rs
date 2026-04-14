use crate::commands::messenger::{load_contacts, save_contacts, Contact};
use crate::ledger::{base_data_dir, load_chain, save_chain, LedgerBlock, LedgerTx, GENESIS_HASH};
use chrono::Utc;
use futures::StreamExt;
use futures::{AsyncReadExt, AsyncWriteExt};
use libp2p::{
    autonat, dcutr, gossipsub, identify, kad, noise, ping, relay,
    request_response::{self, OutboundRequestId, ProtocolSupport},
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, StreamProtocol, SwarmBuilder,
};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{collections::HashMap, io, sync::{Mutex, OnceLock}, time::Duration};
use tauri::Manager;
use tokio::sync::{mpsc, oneshot};

/// Bounded gossip channel — prevents OOM when gossip consumers fall behind.
const GOSSIP_CHANNEL_CAPACITY: usize = 10_000;
static GOSSIP_TX: OnceLock<mpsc::Sender<(String, Vec<u8>)>> = OnceLock::new();

static DEAD_PEER_CACHE: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();
const DEAD_PEER_SILENCE_SECS: i64 = 300;

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

pub static DHT_CMD_TX: OnceLock<mpsc::UnboundedSender<DhtCommand>> = OnceLock::new();

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
pub const P2P_PORT: u16 = 47393;

pub const RELAY_NODES: &[&str] = &[
    "/dns4/EgoRelay.egoblockchain.com/tcp/4001/p2p/12D3KooWFFjZdk4nhpsXKxa44eUsggQ9rAzELeVv34Eav8qA5t9y",
];

static EGOC_PRICE_USD: std::sync::OnceLock<std::sync::Mutex<f64>> = std::sync::OnceLock::new();

static PRICE_SAMPLES: std::sync::OnceLock<std::sync::Mutex<std::collections::VecDeque<f64>>> =
    std::sync::OnceLock::new();

const PRICE_WINDOW: usize = 21;

fn price_samples() -> std::sync::MutexGuard<'static, std::collections::VecDeque<f64>> {
    PRICE_SAMPLES
        .get_or_init(|| std::sync::Mutex::new(std::collections::VecDeque::with_capacity(PRICE_WINDOW + 1)))
        .lock()
        .unwrap()
}

/// Current market price of EGOC in USD. Used as default until oracle/CoinGecko overrides it.
pub const EGOC_DEFAULT_PRICE_USD: f64 = 2.45;

pub fn get_egoc_price_usd() -> f64 {
    let samples = price_samples();
    if samples.len() >= 3 {
        let mut sorted: Vec<f64> = samples.iter().cloned().collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        sorted[sorted.len() / 2]
    } else {
        *EGOC_PRICE_USD.get_or_init(|| std::sync::Mutex::new(EGOC_DEFAULT_PRICE_USD)).lock().unwrap()
    }
}

fn set_egoc_price_usd(price: f64) {
    if price <= 0.0 { return; }
    *EGOC_PRICE_USD.get_or_init(|| std::sync::Mutex::new(EGOC_DEFAULT_PRICE_USD)).lock().unwrap() = price;
    let mut samples = price_samples();
    samples.push_back(price);
    if samples.len() > PRICE_WINDOW { samples.pop_front(); }
}


pub fn record_gossip_price(price: f64) {
    if price <= 0.0 || price > 1_000_000.0 { return; } 
    let mut samples = price_samples();
    samples.push_back(price);
    if samples.len() > PRICE_WINDOW { samples.pop_front(); }
}


// CoinGecko coin IDs to try in order.
const COINGECKO_IDS: &[&str] = &["ego-coin", "egocoin", "egoc"];

pub async fn fetch_and_cache_egoc_price() {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .user_agent("EgoDesktop/1.0")
        .build()
        .unwrap_or_default();

    // ── 1. Try oracle first ───────────────────────────────────────────────────
    if let Some(resp) = oracle_get(&client, "/price/egoc").await {
        if let Ok(json) = resp.json::<serde_json::Value>().await {
            if let Some(price) = json["price_usd"].as_f64().filter(|&p| p > 0.0) {
                let old = get_egoc_price_usd();
                set_egoc_price_usd(price);
                if (price - old).abs() / old > 0.05 {
                    eprintln!("[Price] EGOC/USD (oracle): ${:.6} → ${:.6}", old, price);
                }
                if let Ok(data) = serde_json::to_vec(&serde_json::json!({ "price": price })) {
                    publish_gossip("ego-price-v1", data).await;
                }
                return;
            }
        }
    }

    // ── 2. Fallback: CoinGecko free API ──────────────────────────────────────
    for coin_id in COINGECKO_IDS {
        let url = format!(
            "https://api.coingecko.com/api/v3/simple/price?ids={}&vs_currencies=usd",
            coin_id
        );
        if let Ok(resp) = client.get(&url).send().await {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(price) = json[coin_id]["usd"].as_f64().filter(|&p| p > 0.0) {
                    let old = get_egoc_price_usd();
                    set_egoc_price_usd(price);
                    eprintln!("[Price] EGOC/USD (coingecko/{coin_id}): ${:.6} → ${:.6}", old, price);
                    if let Ok(data) = serde_json::to_vec(&serde_json::json!({ "price": price })) {
                        publish_gossip("ego-price-v1", data).await;
                    }
                    return;
                }
            }
        }
    }

    eprintln!("[Price] All price sources failed — keeping ${:.6}", get_egoc_price_usd());
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


async fn oracle_post(client: &reqwest::Client, path: &str, body: &serde_json::Value) {
    for base in ORACLE_RPCS {
        if let Ok(resp) = client.post(format!("{}{}", base, path)).json(body).send().await {
            if resp.status().is_success() { return; } 
        }
    }
}


pub async fn oracle_post_pub(client: &reqwest::Client, path: &str, body: &serde_json::Value) {
    oracle_post(client, path, body).await;
}

static RELAY_CIRCUIT_READY: AtomicBool = AtomicBool::new(false);


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



const MAX_VALIDATORS: usize = 10_000;


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

pub fn register_validator_pubkey(address: &str, dilithium_pubkey_hex: &str) {
    if address.is_empty() || dilithium_pubkey_hex.is_empty() { return; }
    validator_pubkeys().insert(address.to_string(), dilithium_pubkey_hex.to_string());
}

/// Verify an ML-DSA-44 BFT signature. Fail-closed: unknown validator → reject.
fn verify_bft_sig(address: &str, data: &str, sig_hex: &str) -> bool {
    let pubkey_hex = match validator_pubkeys().get(address).cloned() {
        Some(k) => k,
        None    => {
            eprintln!("[BFT] Unknown ML-DSA-44 pubkey for {} — rejecting vote", address);
            return false;
        }
    };
    let pubkey_bytes = match hex::decode(&pubkey_hex) {
        Ok(b) if !b.is_empty() => b,
        _ => return false,
    };
    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) if !b.is_empty() => b,
        _ => return false,
    };
    let pk  = ego_core::PublicKey::dilithium2(pubkey_bytes);
    let sig = ego_core::Signature::dilithium2(sig_bytes);
    ego_core::verify_signature(&pk, data.as_bytes(), &sig).unwrap_or(false)
}

// ── Per-peer gossip rate limiter ───────────────────────────────────────────────
// Counts messages per peer per second. Peers exceeding the cap are ignored.
// This prevents a single peer from flooding the network (DDoS layer 1).
const MAX_MSGS_PER_SEC: u32 = 50;

static PEER_MSG_RATE: std::sync::OnceLock<std::sync::Mutex<HashMap<String, (u32, i64)>>> =
    std::sync::OnceLock::new();

fn peer_msg_rate() -> std::sync::MutexGuard<'static, HashMap<String, (u32, i64)>> {
    PEER_MSG_RATE
        .get_or_init(|| std::sync::Mutex::new(HashMap::new()))
        .lock()
        .unwrap()
}

/// Returns true if the peer is within rate limits. False = flooding, drop the message.
fn check_peer_rate(peer_id: &str) -> bool {
    let now = chrono::Utc::now().timestamp();
    let mut rates = peer_msg_rate();
    let entry = rates.entry(peer_id.to_string()).or_insert((0, now));
    if now > entry.1 {
        *entry = (1, now); // new second — reset
        true
    } else {
        entry.0 += 1;
        if entry.0 > MAX_MSGS_PER_SEC {
            eprintln!("[P2P] Rate-limiting flood from {} ({} msgs/s)", peer_id, entry.0);
            false
        } else {
            true
        }
    }
}

static CURRENT_VIEW: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

static LAST_PROPOSAL_TS: std::sync::atomic::AtomicI64 =
    std::sync::atomic::AtomicI64::new(0);

/// Counts consecutive view changes that produced no new block.
/// Resets to 0 when a block is finalized.
/// Triggers a deterministic (highest-DRS) fallback when it reaches
/// FALLBACK_AFTER_EMPTY_VIEWS.
static CONSECUTIVE_EMPTY_VIEWS: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(0);

/// Maps block_height → proposer_address for in-flight proposals.
/// Populated when a BlockProposal is accepted by the committee (after structural
/// validation), cleared when the block is finalized.  If a view change fires
/// while an entry exists, that proposer explicitly failed to deliver → penalise.
static PENDING_PROPOSALS: std::sync::OnceLock<std::sync::Mutex<HashMap<u64, String>>> =
    std::sync::OnceLock::new();

fn pending_proposals() -> std::sync::MutexGuard<'static, HashMap<u64, String>> {
    PENDING_PROPOSALS.get_or_init(|| std::sync::Mutex::new(HashMap::new())).lock().unwrap()
}

static VIEW_CHANGE_VOTES: std::sync::OnceLock<std::sync::Mutex<HashMap<u64, Vec<String>>>> =
    std::sync::OnceLock::new();

static STAGED_BLOCK: std::sync::OnceLock<std::sync::Mutex<Option<(crate::ledger::LedgerBlock, Vec<crate::ledger::LedgerTx>)>>> =
    std::sync::OnceLock::new();

fn staged_block() -> std::sync::MutexGuard<'static, Option<(crate::ledger::LedgerBlock, Vec<crate::ledger::LedgerTx>)>> {
    STAGED_BLOCK.get_or_init(|| std::sync::Mutex::new(None)).lock().expect("staged_block lock poisoned")
}

const VIEW_CHANGE_TIMEOUT_SECS: i64 = 10;

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

/// Elect the block proposer for the next chain height using VRF self-selection.
///
/// Each node with a seed checks if its VRF ticket qualifies (ticket_float < threshold).
/// If this node qualifies, it returns its own address; otherwise None.
/// The deterministic fallback (max DRS weight) is intentionally removed —
/// every round must go through VRF so no single node can predict future proposers.
pub fn elect_proposer_for_next_slot() -> Option<String> {
    let my_addr = crate::ledger::Ledger::load().address;
    if my_addr.is_empty() { return None; }

    let seed_bytes = crate::ledger::load_seed()?;
    let mut seed_32 = [0u8; 32];
    seed_32.copy_from_slice(&seed_bytes);

    let prev_hash   = crate::chain_db::get_tip_hash();
    let next_height = crate::chain_db::block_count() + 1;

    let vrf_in  = crate::bft_committee::vrf_input(
        &prev_hash, next_height, crate::bft_committee::VRF_ROLE_PROPOSER,
    );
    let ticket  = crate::bft_committee::sign_vrf_ticket(&seed_32, &vrf_in);

    let validators: Vec<String> = known_validators().iter().cloned().collect();
    let my_drs    = crate::bft_committee::compute_drs_weight(&my_addr);
    let total_drs = crate::bft_committee::total_drs_weight(&validators);

    if crate::bft_committee::qualifies_proposer(&ticket, my_drs, total_drs) {
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
    eprintln!("[BFT] Slashing validator {} — {}", address, reason);
    known_validators().remove(address);
    slashed_validators().insert(address.to_string());
    // Persist to RocksDB so slashes survive node restarts.
    crate::chain_db::persist_slashed_validator(address);


    let staked     = crate::ledger::get_validator_stake(address);
    let slash_burn = staked / 10;
    if slash_burn > 0 {
        crate::chain_db::burn_from_staking_pool(slash_burn);
        crate::ledger::record_validator_stake(address, slash_burn, false);
        eprintln!("[BFT] Burned {} uEGOC from {}'s stake (10% slash penalty)", slash_burn, address);
    }


    let ts   = chrono::Utc::now().timestamp();
    let data = format!("slash:{}:{}:{}", address, ts, slash_burn);
    let hash = format!("0x{}", hex::encode(
        ego_core::hash_data(data.as_bytes()).as_bytes()
    ));
    let mut chain = load_chain();
    chain.transactions.push(crate::ledger::LedgerTx {
        hash,
        from:      "egot1system0000000000000000000000000000000000000".into(),
        to:        address.to_string(),
        amount:    slash_burn,
        memo:      Some(format!("SLASH: {reason} (burned {} uEGOC)", slash_burn)),
        timestamp: ts,
        signature: "system".into(),
        status:    "Confirmed".into(),
        ..crate::ledger::LedgerTx::default()
    });
    let _ = save_chain(&chain);
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
        }
    }
}


pub fn get_peer_ed25519_pubkey(address: &str) -> Option<[u8; 32]> {
    peer_ed25519_keys().get(address).copied()
}


pub fn register_known_validator(address: &str) {
    if address.is_empty() { return; }
    if slashed_validators().contains(address) { return; }


    {
        let set = known_validators();
        if set.len() >= 3 && !set.contains(address) {
            let staked = crate::ledger::get_validator_stake(address);
            if staked < crate::tokenomics::MIN_STAKE_PROGRAM_UEGOC {

                let ledger = crate::ledger::Ledger::load();
                let is_self = ledger.address == address;
                let local_staked = ledger.staked_amount;
                if !is_self || local_staked < crate::tokenomics::MIN_STAKE_PROGRAM_UEGOC {
                    eprintln!("[BFT] Rejected validator {} — stake {} uEGOC < minimum {} uEGOC",
                        address, staked, crate::tokenomics::MIN_STAKE_PROGRAM_UEGOC);
                    return;
                }
            }
        }
    } // release lock before re-acquiring below

    let mut set = known_validators();
    if set.len() >= MAX_VALIDATORS {
        if let Some(evict) = set.iter().next().cloned() {
            set.remove(&evict);
        }
    }
    set.insert(address.to_string());
}


fn bft_threshold() -> usize {
    let n = known_validators().len();
    match n {
        0 | 1 => 1,
        2     => 2,
        _     => (n * 2 / 3) + 1,
    }
}

/// Returns true if the set of voters represents ≥ ⅔ of total staked EGOC.
/// This is the stake-weighted quorum check — prevents Sybil attacks where an
/// attacker registers many low-stake nodes to reach the node-count threshold.
/// Both bft_threshold() AND this must pass before a block is finalized.
// Enforce stake-weighted quorum after only 10 blocks to close the bootstrap attack window.
const STAKE_QUORUM_ENFORCE_HEIGHT: u64 = 10;

fn stake_quorum_reached(voters: &[String]) -> bool {
    let current_height = crate::chain_db::block_count();

    let validators = known_validators();
    if validators.is_empty() { return true; }

    let total_stake: u64 = validators.iter()
        .map(|addr| crate::ledger::get_validator_stake(addr))
        .sum();

    if total_stake == 0 {
        return true;
    }

    let voter_stake: u64 = voters.iter()
        .filter(|v| validators.contains(*v))
        .map(|addr| crate::ledger::get_validator_stake(addr))
        .sum();

    voter_stake * 3 > total_stake * 2
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
        coverage_score: u64,
        #[serde(default, alias = "ed25519_pubkey")]
        dilithium_pubkey: String,
        #[serde(default)]
        vrf_pubkey: String,
    },
    ChatMessage {
        bundle: String,
        #[serde(default)]
        seq: u64,
    },
    TxBroadcast {
        tx:    LedgerTx,
        block: LedgerBlock,
    },
    ChainSyncRequest {
        requester_endpoint: String,
    },
    ChainSyncResponse {
        blocks:       Vec<LedgerBlock>,
        transactions: Vec<LedgerTx>,
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
    },
    BlockFinalized {
        block:        LedgerBlock,
        transactions: Vec<LedgerTx>,
        votes:        Vec<serde_json::Value>,
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
        block_cid:     String,  // echoed
        nonce:         String,  // echoed (anti-replay)
        /// hex(BLAKE3(nonce_bytes || enc_block_bytes)) — 32 bytes = 64 hex chars.
        /// Small, verifiable, does not reveal plaintext.
        response_hash: String,
        prover:        String,  // prover address
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
    autonat:          autonat::Behaviour,
    ping:             ping::Behaviour,
    gossipsub:        gossipsub::Behaviour,
    kad:              kad::Behaviour<kad::store::MemoryStore>,
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
}

static SWARM_TX: OnceLock<mpsc::Sender<SwarmCmd>> = OnceLock::new();

// ── Public API ────────────────────────────────────────────────────────────────

pub async fn send_message(endpoint: &str, msg: &P2PMessage) -> Result<(), String> {
    let tx = SWARM_TX.get().ok_or_else(|| "P2P not started".to_string())?;
    let peer_addr: Multiaddr = endpoint
        .parse()
        .map_err(|e| format!("Invalid multiaddr '{}': {}", endpoint, e))?;
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(SwarmCmd::Send { peer_addr, msg: msg.clone(), reply: reply_tx })
        .await
        .map_err(|_| "Swarm channel closed".to_string())?;
    reply_rx.await.map_err(|_| "Swarm dropped reply".to_string())?
}


pub async fn send_message_any(endpoints: &[String], msg: &P2PMessage) -> Result<(), String> {
    if endpoints.is_empty() {
        return Err("No endpoints available".to_string());
    }
    // Sort: LAN (0) → public IP (1) → relay circuit (2)
    let mut sorted = endpoints.to_vec();
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
                eprintln!("[P2P] Connected via {}", ep);
                return Ok(());
            }
            Err(e) => {
                if !is_peer_silenced(ep) {
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
    if tx.send(SwarmCmd::GetEndpoint { reply: reply_tx }).await.is_err() {
        return String::new();
    }
    reply_rx.await.unwrap_or_default()
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

pub async fn broadcast_tx(tx: LedgerTx, block: LedgerBlock) {

    let msg = P2PMessage::TxBroadcast { tx: tx.clone(), block: block.clone() };

    if let Ok(data) = serde_json::to_vec(&msg) {
        publish_gossip("ego-txs-v1", data).await;
    }

    let my_addr = crate::ledger::Ledger::load().address;
    register_known_validator(&my_addr);

    if let Some(seed_bytes) = crate::ledger::load_seed() {
        if seed_bytes.len() == 32 {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&seed_bytes);
            if let Ok(kp) = ego_core::KeyPair::from_bytes(&seed) {
                let dil_pk_hex = hex::encode(kp.dilithium_public_key().key_data);
                register_validator_pubkey(&my_addr, &dil_pk_hex);
            }
            let vk_hex = {
                use ed25519_dalek::SigningKey;
                hex::encode(SigningKey::from_bytes(&seed).verifying_key().as_bytes())
            };
            record_peer_ed25519(&my_addr, &vk_hex);
        }
    }

    let mut seen_eps: std::collections::HashSet<String> = Default::default();
    let mut endpoints: Vec<String> = Vec::new();

    let contacts = load_contacts();
    for c in contacts.iter().filter(|c| c.status == "approved" && !c.endpoint.is_empty()) {
        if seen_eps.insert(c.endpoint.clone()) {
            endpoints.push(c.endpoint.clone());
        }
        for ep in &c.all_endpoints {
            if seen_eps.insert(ep.clone()) { endpoints.push(ep.clone()); }
        }
    }
    for p in load_peer_cache().iter().filter(|p| !p.endpoint.is_empty()) {
        if seen_eps.insert(p.endpoint.clone()) {
            endpoints.push(p.endpoint.clone());
        }
    }

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
}

pub async fn broadcast_pending_tx(tx: LedgerTx) {
    let msg = P2PMessage::TxBroadcast { tx, block: LedgerBlock::default() };
    if let Ok(data) = serde_json::to_vec(&msg) {
        publish_gossip("ego-txs-v1", data).await;
    }
}

pub async fn sync_chain_from_peers() {
    let my_endpoint = get_public_endpoint().await;
    let msg = P2PMessage::ChainSyncRequest { requester_endpoint: my_endpoint.clone() };

    if let Ok(data) = serde_json::to_vec(&msg) {
        publish_gossip("ego-sync-v1", data).await;
    }

    let mut seen_eps: std::collections::HashSet<String> = Default::default();
    let mut endpoints: Vec<String> = Vec::new();

    for c in load_contacts().iter().filter(|c| !c.endpoint.is_empty()) {
        if seen_eps.insert(c.endpoint.clone()) { endpoints.push(c.endpoint.clone()); }
        for ep in &c.all_endpoints {
            if seen_eps.insert(ep.clone()) { endpoints.push(ep.clone()); }
        }
    }
    for p in load_peer_cache().iter().filter(|p| !p.endpoint.is_empty()) {
        if seen_eps.insert(p.endpoint.clone()) { endpoints.push(p.endpoint.clone()); }
    }

    for endpoint in endpoints {
        let msg_clone = msg.clone();
        tokio::spawn(async move {
            if let Err(e) = send_message_any(&[endpoint.clone()], &msg_clone).await {
                if !e.contains("none of the requested protocols") && !is_peer_silenced(&endpoint) {
                    eprintln!("[P2P] sync request to {}: {}", endpoint, e);
                }
            }
        });
    }
}

pub async fn broadcast_peer_announce(app: &tauri::AppHandle) {
    let address = crate::ledger::Ledger::load().address.clone();
    if address.is_empty() { return; }
    let my_endpoint = get_public_endpoint().await;
    let registry  = crate::ledger::load_registry();
    let active_id = crate::ledger::get_active_wallet_id();
    let name = registry.wallets.iter()
        .find(|w| w.id == active_id)
        .map(|w| w.name.clone())
        .unwrap_or_else(|| "Ego Node".to_string());


    let (my_city, my_country) = {
        let state = app.state::<crate::app::AppState>();
        let cache = state.cache.lock().unwrap();
        if let Some(ref cs) = cache.coverage_status {
            if let Some(ref loc) = cs.location {
                (loc.city.clone(), loc.country.clone())
            } else { (None, None) }
        } else { (None, None) }
    };

    {
        let state = app.state::<crate::app::AppState>();
        state.upsert_peer(crate::app::PeerInfo {
            address:   address.clone(),
            name:      name.clone(),
            endpoint:  my_endpoint.clone(),
            last_seen: Utc::now().timestamp(),
            city:      my_city.clone(),
            country:   my_country.clone(),
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
    let (dilithium_pubkey_hex, vrf_pubkey_hex) = {
        crate::ledger::load_seed()
            .and_then(|b| {
                if b.len() != 32 { return None; }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                let kp = ego_core::KeyPair::from_bytes(&arr).ok()?;
                let dil = hex::encode(kp.dilithium_public_key().key_data);
                let vk  = {
                    use ed25519_dalek::SigningKey;
                    hex::encode(SigningKey::from_bytes(&arr).verifying_key().as_bytes())
                };
                Some((dil, vk))
            })
            .unwrap_or_default()
    };
    let msg = P2PMessage::PeerAnnounce {
        address, name,
        endpoint:  my_endpoint,
        endpoints: all_endpoints,
        city:      my_city,
        country:   my_country,
        coverage_score,
        dilithium_pubkey: dilithium_pubkey_hex,
        vrf_pubkey: vrf_pubkey_hex,
    };


    if let Ok(data) = serde_json::to_vec(&msg) {
        publish_gossip("ego-peers-v1", data).await;
    }


    for contact in load_contacts().iter().filter(|c| c.status == "approved" && !c.endpoint.is_empty()) {
        let endpoint  = contact.endpoint.clone();
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
}


pub async fn broadcast_data_manifest() {
    let ledger = crate::ledger::Ledger::load();
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
        let ledger2  = crate::ledger::Ledger::load();
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

    for contact in load_contacts().iter().filter(|c| c.status == "approved" && !c.endpoint.is_empty()) {
        let ep      = contact.endpoint.clone();
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
    let ledger = crate::ledger::Ledger::load();
    if ledger.address.is_empty() { return; }
    let my_ep = get_public_endpoint().await;
    for contact in load_contacts().iter().filter(|c| c.status == "approved" && !c.endpoint.is_empty()) {
        let ep      = contact.endpoint.clone();
        let all_eps = contact.all_endpoints.clone();
        let from    = ledger.address.clone();
        let my_ep2  = my_ep.clone();
        let cids2   = cids.clone();
        tokio::spawn(async move {
            let mut eps = if all_eps.is_empty() { vec![ep.clone()] } else { all_eps };
            if !eps.contains(&ep) { eps.push(ep); }
            for cid in cids2 {
                // Include deal terms so the slave can lock the right collateral amount.
                let (fee, expiry) = {
                    let l = crate::ledger::Ledger::load();
                    l.stored_files.iter()
                        .find(|f| f.cid == cid)
                        .map(|f| (f.storage_fee_uegoc, f.expiry))
                        .unwrap_or((0, 0))
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

pub async fn check_file_replication() {
    let mut ledger = crate::ledger::Ledger::load();
    if ledger.address.is_empty() { return; }
    let my_addr = ledger.address.clone();
    let now     = chrono::Utc::now().timestamp();

    let mut need_save   = false;
    let mut pin_needed: Vec<String> = Vec::new();

    // ── Re-publish under-distributed Active files when connectivity returns ───
    // Files stored while offline have replication_role="" and replica_peers=[].
    // The master/slave logic below will pick them up on the next tick once connected.

    for file in ledger.stored_files.iter_mut() {
        if file.status != "Active" { continue; }
        let has_data = !file.local_path.is_empty() && !file.local_path.starts_with("sender:");

        // ── Assign initial role ───────────────────────────────────────────
        if file.replication_role.is_empty() && has_data {
            file.replication_role = "master".to_string();
            file.master_last_seen = now;
            need_save = true;
        }

        match file.replication_role.as_str() {

            // ── MASTER duties ─────────────────────────────────────────────
            "master" => {
                // Broadcast heartbeat to all known slaves
                let hb = P2PMessage::ReplicaHeartbeat {
                    cid:         file.cid.clone(),
                    master_addr: my_addr.clone(),
                    timestamp:   now,
                };
                let peers = load_peer_cache();
                for peer in &peers {
                    if !peer.endpoint.is_empty() {
                        let _ = send_message_any(&[peer.endpoint.clone()], &hb).await;
                    }
                }

                // If under-replicated, request more slaves
                if file.replica_peers.len() < MIN_REPLICAS {
                    eprintln!("[Replication] Master: {} has {}/{} replicas — requesting more",
                        &file.cid[..16.min(file.cid.len())],
                        file.replica_peers.len(), MIN_REPLICAS);
                    pin_needed.push(file.cid.clone());
                }
            }

            // ── SLAVE duties ──────────────────────────────────────────────
            "slave" => {
                let master_alive = file.master_last_seen > 0
                    && (now - file.master_last_seen) < MASTER_TIMEOUT_SECS;

                if !master_alive {
                    // Master has not sent a heartbeat within the timeout window.
                    // Promote self to master and broadcast to find a new slave.
                    eprintln!("[Replication] Slave promoting to master for {} (master {} silent for {}s)",
                        &file.cid[..16.min(file.cid.len())],
                        &file.replica_master,
                        now - file.master_last_seen);

                    let old_master = file.replica_master.clone();
                    file.replication_role = "master".to_string();
                    file.replica_master   = String::new();
                    file.master_last_seen = now;
                    // Remove the dead master from replica list
                    file.replica_peers.retain(|p| p != &old_master);
                    need_save = true;

                    // Broadcast promotion so other slaves know who the new master is
                    let promote_msg = P2PMessage::ReplicaPromote {
                        cid:        file.cid.clone(),
                        new_master: my_addr.clone(),
                        old_master,
                        timestamp:  now,
                    };
                    let peers = load_peer_cache();
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
        let _ = ledger.save();
    }
    if !pin_needed.is_empty() {
        request_file_pinning(pin_needed).await;
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
        // Decrypt with DPAPI (no-op on non-Windows). Handles both legacy
        // plaintext protobuf and the new DPAPI-protected format.
        let bytes = crate::utils::os_unprotect(&raw);
        if let Ok(kp) = libp2p::identity::Keypair::from_protobuf_encoding(&bytes) {
            // Re-save with DPAPI protection if it was stored as plaintext.
            if raw == bytes {
                if let Ok(pb) = kp.to_protobuf_encoding() {
                    let protected = crate::utils::os_protect(&pb);
                    let _ = crate::utils::atomic_write(&path, &protected);
                }
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

pub async fn start_p2p_server(app: tauri::AppHandle) {
    #[cfg(target_os = "windows")]
    ensure_firewall_rule();

    let identity      = load_or_create_identity();
    let local_peer_id = identity.public().to_peer_id();
    eprintln!("[P2P] Local peer ID: {}", local_peer_id);

    let mut swarm = match build_swarm(identity).await {
        Ok(s)  => s,
        Err(e) => { eprintln!("[P2P] Failed to build swarm: {}", e); return; }
    };

    if let Err(e) = swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{}", p2p_port()).parse().unwrap()) {
        eprintln!("[P2P] TCP listen: {}", e);
    }
    if let Err(e) = swarm.listen_on(format!("/ip4/0.0.0.0/udp/{}/quic-v1", p2p_port()).parse().unwrap()) {
        eprintln!("[P2P] QUIC listen: {}", e);
    }

    // relay PeerId → base transport addr (no /p2p/<id> suffix)
    // e.g.  12D3KooWPj6m... → /ip4/40.233.82.42/tcp/4001
    let mut relay_addrs: HashMap<PeerId, Multiaddr> = HashMap::new();
    for relay_str in RELAY_NODES {
        if let Ok(addr) = relay_str.parse::<Multiaddr>() {
            if let Some(pid) = peer_id_from_multiaddr(&addr) {
                relay_addrs.insert(pid, strip_p2p_suffix(&addr));
            }
            eprintln!("[P2P] Dialling relay {}", relay_str);
            let _ = swarm.dial(addr);
        }
    }


    {
        let cached = load_peer_cache();
        if cached.len() >= MIN_CACHED_PEERS_FOR_DIRECT_BOOT {
            eprintln!("[P2P] {} cached peers — attempting relay-free bootstrap", cached.len());
        }
        for peer in cached.iter().filter(|p| !p.endpoint.is_empty()).take(30) {
            if let Ok(addr) = peer.endpoint.parse::<Multiaddr>() {
                let _ = swarm.dial(addr);
            }
        }
    }

    if let Ok(peers_env) = std::env::var("EGO_DIRECT_PEERS") {
        for addr_str in peers_env.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if let Ok(addr) = addr_str.parse::<Multiaddr>() {
                eprintln!("[P2P] Dialling direct peer: {}", addr);
                let _ = swarm.dial(addr);
            }
        }
    }

    // ── Gossipsub subscriptions ───────────────────────────────────────────────
    let tx_topic       = gossipsub::IdentTopic::new("ego-txs-v1");
    let block_topic    = gossipsub::IdentTopic::new("ego-blocks-v1");
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&tx_topic);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&block_topic);

    let proposal_topic = gossipsub::IdentTopic::new("ego-proposals-v1");
    let vote_topic     = gossipsub::IdentTopic::new("ego-votes-v1");
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&proposal_topic);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&vote_topic);

    let shard_topic = gossipsub::IdentTopic::new("ego-shards-v1");
    swarm.behaviour_mut().gossipsub.subscribe(&shard_topic).ok();


    let peers_topic = gossipsub::IdentTopic::new("ego-peers-v1");
    swarm.behaviour_mut().gossipsub.subscribe(&peers_topic).ok();

    let price_topic = gossipsub::IdentTopic::new("ego-price-v1");
    swarm.behaviour_mut().gossipsub.subscribe(&price_topic).ok();


    let vc_topic = gossipsub::IdentTopic::new("ego-viewchange-v1");
    swarm.behaviour_mut().gossipsub.subscribe(&vc_topic).ok();

    let storage_topic = gossipsub::IdentTopic::new("ego-storage-v1");
    swarm.behaviour_mut().gossipsub.subscribe(&storage_topic).ok();

    let sync_req_topic = gossipsub::IdentTopic::new("ego-sync-v1");
    swarm.behaviour_mut().gossipsub.subscribe(&sync_req_topic).ok();


    let _ = swarm.behaviour_mut().kad.bootstrap();


    let (gossip_unbounded_tx, mut gossip_rx) =
        mpsc::channel::<(String, Vec<u8>)>(GOSSIP_CHANNEL_CAPACITY);
    let _ = GOSSIP_TX.set(gossip_unbounded_tx);


    let (dht_cmd_tx, mut dht_cmd_rx) = mpsc::unbounded_channel::<DhtCommand>();
    let _ = DHT_CMD_TX.set(dht_cmd_tx);

    let (tx, mut rx) = mpsc::channel::<SwarmCmd>(64);
    let _ = SWARM_TX.set(tx);

    let mut external_addrs:   Vec<Multiaddr> = Vec::new();
    let mut pending_sends:    HashMap<PeerId, Vec<(P2PMessage, oneshot::Sender<Result<(), String>>)>> = HashMap::new();
    let mut in_flight:        HashMap<OutboundRequestId, oneshot::Sender<Result<(), String>>> = HashMap::new();
    let mut circuit_listener: Option<libp2p_core::transport::ListenerId> = None;

    let mut relay_retry = tokio::time::interval(Duration::from_secs(15));
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


    if std::env::var("EGO_DATA_DIR").is_ok() && crate::ledger::load_seed().is_none() {
        let _ = std::fs::create_dir_all(crate::ledger::data_dir());
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        if let Ok(_) = crate::ledger::save_seed(&seed) {
            if let Ok(kp) = ego_core::KeyPair::from_bytes(&seed) {
                if let Ok(addr) = kp.derive_bech32_address(1, ego_core::AddressType::EOA, "egot") {
                    let mut ledger = crate::ledger::Ledger::load();
                    if ledger.address.is_empty() {
                        ledger.address = addr.clone();
                        let mn = kp.derive_bech32_address(0, ego_core::AddressType::EOA, "ego").unwrap_or_default();
                        ledger.mainnet_address = mn;
                        ledger.staked_amount = 1_000_000;
                        let _ = ledger.save();
                        eprintln!("[P2P] Auto-generated node identity: {}", addr);
                    }
                }
            }
        }
    }

    {
        let ledger = crate::ledger::Ledger::load();
        if ledger.staked_amount > 0 && !ledger.address.is_empty() {
            crate::ledger::record_validator_stake(&ledger.address, ledger.staked_amount, true);
        }
        if !ledger.address.is_empty() {
            register_known_validator(&ledger.address);
        }
        // Restore persisted slash records so bans survive node restarts.
        for addr in crate::chain_db::load_slashed_validators() {
            slashed_validators().insert(addr);
        }
        // Reconcile local stake state against confirmed chain — clears optimistic stake
        // records whose TX was never mined (e.g. app crashed before confirmation).
        crate::ledger::reconcile_stake_state();

        // Restore confirmed nonces from RocksDB so replay protection holds after restart.
        // Without this NONCE_STORE resets to 0 and any past signed TX can be replayed.
        crate::chain_db::restore_nonces_from_db();

        // Restore in-flight BFT votes from RocksDB (Item 6: votes survive restart).
        // This lets us continue counting towards quorum even if the node rebooted
        // mid-round — prevents consensus stalls on single-shard partitions.
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
                eprintln!("[BFT] Restored in-flight votes from DB");
            }
        }
    }

    loop {
        tokio::select! {
            // ── Gossip publish (from broadcast_tx / publish_gossip) ───────────
            Some((topic_str, data)) = gossip_rx.recv() => {
                let topic = gossipsub::IdentTopic::new(topic_str.clone());
                match swarm.behaviour_mut().gossipsub.publish(topic, data) {
                    Ok(_) => {}
                    // InsufficientPeers is normal at startup — suppress silently.
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
                            Err(gossipsub::PublishError::NoPeersSubscribedToTopic) => {}
                            Err(e) => eprintln!("[Gossip] publish '{}': {:?}", topic, e),
                        }
                    }
                }
            }

            event = swarm.select_next_some() => {
                handle_event(
                    event, &app,
                    &mut external_addrs, &mut pending_sends, &mut in_flight,
                    &mut swarm, &relay_addrs,
                    &mut circuit_listener,
                ).await;
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
                if DIRECT_PEER_COUNT.load(Ordering::Relaxed) >= MIN_DIRECT_PEERS_RELAY_OPTIONAL
                    && has_circuit_addr(&external_addrs)
                {

                    continue;
                }
                if !has_circuit_addr(&external_addrs) {
                    for relay_str in RELAY_NODES {
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
                                            eprintln!("[P2P] Re-registering relay circuit");
                                        }
                                        Err(e) => eprintln!("[P2P] Re-register failed: {}", e),
                                    }
                                }
                            } else if !connected {
                                eprintln!("[P2P] Relay not connected — redialling {}", relay_str);
                                let _ = swarm.dial(addr);
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
                const TRANSFER_TIMEOUT_SECS: i64 = 600; // 10 minutes
                let now = chrono::Utc::now().timestamp();
                let ledger = crate::ledger::Ledger::load();
                let mut timed_out: Vec<String> = Vec::new();

                for file in &ledger.stored_files {
                    if !file.cid.starts_with("egomfd1")
                        || file.status == "Failed"
                        || file.status == "Received"
                    { continue; }

                    if file.blocks_total > 0 && file.blocks_received < file.blocks_total {
                        // Check for stalled transfer
                        let last = if file.last_block_at > 0 { file.last_block_at } else { file.stored_at };
                        if last > 0 && now - last > TRANSFER_TIMEOUT_SECS {
                            timed_out.push(file.cid.clone());
                            continue;
                        }
                        // Re-request missing blocks
                        if let Some(tx) = DHT_CMD_TX.get() {
                            if let Ok(manifest) = crate::blocks::load_manifest(&file.cid) {
                                for block_cid in crate::blocks::missing_blocks(&manifest) {
                                    let _ = tx.send(DhtCommand::GetPeers {
                                        key: format!("ego-block:{}", block_cid),
                                    });
                                }
                            }
                        }
                    }
                }
                drop(ledger);

                if !timed_out.is_empty() {
                    let mut ledger = crate::ledger::Ledger::load();
                    for cid in &timed_out {
                        if let Some(f) = ledger.stored_files.iter_mut().find(|f| &f.cid == cid) {
                            f.status = "Failed".to_string();
                            eprintln!("[Blocks] Transfer timed out ({}s): {}", TRANSFER_TIMEOUT_SECS, &cid[..cid.len().min(20)]);
                        }
                    }
                    let _ = ledger.save();
                    for cid in &timed_out {
                        let _ = app.emit_all("ego://file-failed", serde_json::json!({ "cid": cid }));
                    }
                }
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
    let swarm = SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(tcp::Config::default().nodelay(true), noise::Config::new, yamux::Config::default)?
        .with_quic()
        .with_dns()?
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key, relay_client| {
            // ── Gossipsub ─────────────────────────────────────────────────────
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(10))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .max_transmit_size(512 * 1024) // 512 KB
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
                    max_reservations:          512,
                    max_reservations_per_peer: 4,
                    reservation_duration:      Duration::from_secs(3600),
                    max_circuits:              1024,
                    max_circuits_per_peer:     32,
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
                autonat: autonat::Behaviour::new(peer_id, autonat::Config::default()),
                    ping: ping::Behaviour::new(
                        ping::Config::new()
                            .with_interval(Duration::from_secs(15))  
                            .with_timeout(Duration::from_secs(10)),
                    ),
                gossipsub: gossipsub_behaviour,
                kad:       kad_behaviour,
            }
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(86400)))
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
    if swarm.is_connected(&peer_id) {
        let req_id = swarm.behaviour_mut().request_response.send_request(&peer_id, msg);
        in_flight.insert(req_id, reply);
    } else {
        pending_sends.entry(peer_id).or_default().push((msg, reply));
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

    if let Some(a) = external_addrs.iter().find(|a| a.to_string().contains("/p2p-circuit")) {
        let s = a.to_string();
        return if s.contains(&pid_str) { s } else { format!("{}/p2p/{}", s, pid_str) };
    }

    let is_public = |a: &Multiaddr| {
        let s = a.to_string();
        !s.starts_with("/ip4/127.")     &&
        !s.starts_with("/ip4/10.")      &&
        !s.starts_with("/ip4/192.168.") &&
        !s.starts_with("/ip4/172.")
    };
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
    app:            &tauri::AppHandle,
    local_peer_id:  &PeerId,
) {
    if !external_addrs.contains(&circuit) {
        eprintln!("[P2P] ✓ Circuit injected: {}", circuit);
        external_addrs.push(circuit);
    }
    RELAY_CIRCUIT_READY.store(true, Ordering::Relaxed);
    let ep    = best_endpoint(external_addrs, local_peer_id);
    let state = app.state::<crate::app::AppState>();
    state.set_public_endpoint(ep.clone());
    state.set_upnp_status(Ok(()));
    let _ = app.emit_all("ego://p2p-status-changed", ());

    let app_clone = app.clone();
    tokio::spawn(async move {

        tokio::time::sleep(Duration::from_millis(300)).await;
        broadcast_peer_announce(&app_clone).await;
        eprintln!("[P2P] Re-announced after relay circuit confirmed");

        let addr = crate::ledger::Ledger::load().address;
        if !addr.is_empty() {
            eprintln!("[Messenger] Relay inbox polling for {}", &addr[..addr.len().min(20)]);
        }
    });
}

async fn handle_event(
    event:            SwarmEvent<EgoBehaviourEvent>,
    app:              &tauri::AppHandle,
    external_addrs:   &mut Vec<Multiaddr>,
    pending_sends:    &mut HashMap<PeerId, Vec<(P2PMessage, oneshot::Sender<Result<(), String>>)>>,
    in_flight:        &mut HashMap<OutboundRequestId, oneshot::Sender<Result<(), String>>>,
    swarm:            &mut libp2p::Swarm<EgoBehaviour>,
    relay_addrs:      &HashMap<PeerId, Multiaddr>,
    circuit_listener: &mut Option<libp2p_core::transport::ListenerId>,
) {
    match event {

        SwarmEvent::ListenerClosed { listener_id, reason, .. } => {
            let is_circuit = circuit_listener.as_ref()
                .map(|id| *id == listener_id)
                .unwrap_or(false);
            if is_circuit {
                eprintln!("[P2P] Circuit listener closed ({:?}) — will re-register", reason);
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
                eprintln!("[P2P] ✓ Relay circuit LIVE (NewListenAddr): {}", full);
                inject_circuit(full, external_addrs, app, &peer_id);
            }
        }

        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            eprintln!("[P2P] Connected to {}", peer_id);

            if !relay_addrs.contains_key(&peer_id) {
                let n = DIRECT_PEER_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                if n == MIN_DIRECT_PEERS_RELAY_OPTIONAL {
                    eprintln!("[P2P] {} direct peers — relay no longer required for bootstrap", n);
                }
            }

            if let Some(relay_base) = relay_addrs.get(&peer_id) {
                let our_peer_id = *swarm.local_peer_id();
                let circuit_str = format!("{}/p2p/{}/p2p-circuit", relay_base, peer_id);
                match circuit_str.parse::<Multiaddr>() {
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
                            Err(e) => eprintln!("[P2P] Relay listen error: {}", e),
                        }
                        }
                    }
                    Err(e) => eprintln!("[P2P] Bad circuit addr '{}': {}", circuit_str, e),
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
        }

        SwarmEvent::ConnectionClosed { peer_id, num_established, .. } => {
            if !relay_addrs.contains_key(&peer_id) && num_established == 0 {

                let _ = DIRECT_PEER_COUNT.fetch_update(
                    Ordering::Relaxed, Ordering::Relaxed,
                    |v| Some(v.saturating_sub(1)),
                );
            }
            if relay_addrs.contains_key(&peer_id) {
                eprintln!("[P2P] Relay {} connection closed ({} remaining)", peer_id, num_established);
                if num_established == 0 {

                    eprintln!("[P2P] All relay connections gone — clearing circuit");
                    RELAY_CIRCUIT_READY.store(false, Ordering::Relaxed);
                    external_addrs.retain(|a| !a.to_string().contains("/p2p-circuit"));
                    if let Some(id) = circuit_listener.take() {
                        swarm.remove_listener(id);
                    }
                }

            }
            if let Some(pending) = pending_sends.remove(&peer_id) {
                for (_, reply) in pending {
                    let _ = reply.send(Err("Connection closed before send".into()));
                }
            }
        }

        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            eprintln!("[P2P] Dial error {:?}: {}", peer_id, error);
            if let Some(pid) = peer_id {
                if let Some(pending) = pending_sends.remove(&pid) {
                    for (_, reply) in pending {
                        let _ = reply.send(Err(format!("Cannot reach peer: {}", error)));
                    }
                }
            }
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::Identify(
            identify::Event::Received { info, .. },
        )) => {
            let observed = info.observed_addr.clone();
            swarm.add_external_address(observed.clone());
            if !external_addrs.contains(&observed) {
                external_addrs.push(observed.clone());
                eprintln!("[P2P] Observed external address: {}", observed);
            }
            if !RELAY_CIRCUIT_READY.load(Ordering::Relaxed) {
                let peer_id = *swarm.local_peer_id();
                let state   = app.state::<crate::app::AppState>();
                state.set_public_endpoint(best_endpoint(external_addrs, &peer_id));
                let _ = app.emit_all("ego://p2p-status-changed", ());
            }
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::RelayClient(
            relay::client::Event::ReservationReqAccepted { relay_peer_id, .. },
        )) => {
            eprintln!("[P2P] ✓ Relay reservation ACCEPTED via {}", relay_peer_id);
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

        SwarmEvent::Behaviour(EgoBehaviourEvent::Autonat(
            autonat::Event::StatusChanged { new, .. },
        )) => {
            let state = app.state::<crate::app::AppState>();
            match new {
                autonat::NatStatus::Public(addr) => {
                    eprintln!("[P2P] AutoNAT: public at {}", addr);
                    state.set_upnp_status(Ok(()));
                    if !external_addrs.contains(&addr) {
                        external_addrs.push(addr.clone());
                    }
                    if !RELAY_CIRCUIT_READY.load(Ordering::Relaxed) {
                        let peer_id = *swarm.local_peer_id();
                        state.set_public_endpoint(best_endpoint(external_addrs, &peer_id));
                        let _ = app.emit_all("ego://p2p-status-changed", ());
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
                    state.set_upnp_status(Err("Behind NAT — using relay".into()));
                    let _ = app.emit_all("ego://p2p-status-changed", ());
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
            let app = app.clone();
            tokio::spawn(async move { handle_incoming(request, &app).await; });
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

        SwarmEvent::Behaviour(EgoBehaviourEvent::Dcutr(event)) => {
            eprintln!("[P2P] DCUtR: {:?}", event);
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
            if topic == "ego-txs-v1" {

                if let Ok(P2PMessage::TxBroadcast { tx, block }) =
                    serde_json::from_slice::<P2PMessage>(&message.data)
                {
                    let app2 = app.clone();
                    tokio::spawn(async move { apply_incoming_tx(tx, block, &app2).await; });
                }
            } else if topic == "ego-blocks-v1" {
                match serde_json::from_slice::<P2PMessage>(&message.data) {
                    Ok(P2PMessage::ChainSyncResponse { blocks, transactions }) => {
                        let app2 = app.clone();
                        tokio::spawn(async move { merge_remote_chain(blocks, transactions, &app2).await; });
                    }
                    Ok(P2PMessage::BlockFinalized { block, transactions, votes }) => {
                        let block_hash = block.hash.clone();
                        let height     = block.height;
                        let app2 = app.clone();
                        tokio::spawn(async move {
                            merge_remote_chain(vec![block], transactions, &app2).await;
                            // Verify QC (threshold + ML-DSA-44 sigs) before updating
                            // consensus state.  Prevents a single peer from forging finality.
                            process_inbound_qc_finalization(&block_hash, height, &votes);
                        });
                    }
                    _ => {}
                }
            } else if topic == "ego-proposals-v1" {
                if let Ok(P2PMessage::BlockProposal { block, transactions, proposer, .. }) =
                    serde_json::from_slice::<P2PMessage>(&message.data)
                {

                    register_known_validator(&proposer);
                    let app2 = app.clone();
                    tokio::spawn(async move {
                        handle_block_proposal(block, transactions, proposer, &app2).await;
                    });
                }
            } else if topic == "ego-votes-v1" {
                if let Ok(P2PMessage::BlockVote { block_hash, height, voter, signature, timestamp, vrf_ticket, prev_hash }) =
                    serde_json::from_slice::<P2PMessage>(&message.data)
                {
                    register_known_validator(&voter);
                    let app2 = app.clone();
                    tokio::spawn(async move {
                        handle_block_vote(block_hash, height, voter, signature, timestamp, vrf_ticket, prev_hash, &app2).await;
                    });
                }
            } else if topic == "ego-sync-v1" {
                if let Ok(P2PMessage::ChainSyncRequest { requester_endpoint }) =
                    serde_json::from_slice::<P2PMessage>(&message.data)
                {
                    if !requester_endpoint.is_empty() && crate::chain_db::block_count() > 0 {
                        let ep = requester_endpoint.clone();
                        tokio::spawn(async move {
                            let chain = crate::ledger::load_chain();
                            let response = P2PMessage::ChainSyncResponse {
                                blocks:       chain.blocks,
                                transactions: chain.transactions,
                            };
                            if let Err(e) = send_message_any(&[ep.clone()], &response).await {
                                if !e.contains("none of the requested protocols") {
                                    eprintln!("[P2P] sync-v1 response to {}: {}", ep, e);
                                }
                            }
                        });
                    }
                }
            } else if topic == "ego-price-v1" {

                if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&message.data) {
                    if let Some(price) = json["price"].as_f64() {
                        record_gossip_price(price);
                    }
                }
            } else if topic == "ego-storage-v1" {
                if let Ok(P2PMessage::StorageCommit { prover_addr, cid, comm_r, signature, .. }) =
                    serde_json::from_slice::<P2PMessage>(&message.data)
                {
                    if !prover_addr.is_empty() && !cid.is_empty() && !comm_r.is_empty() {
                        record_peer_commitment(&cid, &prover_addr, &comm_r, &signature);
                    }
                }
            } else if topic == "ego-viewchange-v1" {

                if let Ok(P2PMessage::ViewChange { view, voter, .. }) =
                    serde_json::from_slice::<P2PMessage>(&message.data)
                {

                    if !slashed_validators().contains(&voter) {
                        let app2 = app.clone();
                        tokio::spawn(async move {
                            handle_view_change_msg(view, voter).await;
                            let _ = app2.emit_all("ego://view-changed", serde_json::json!({ "view": view }));
                        });
                    }
                }
            } else if topic == "ego-peers-v1" {

                match serde_json::from_slice::<P2PMessage>(&message.data) {
                    Ok(msg @ P2PMessage::PeerAnnounce { .. }) => {
                        let app2 = app.clone();
                        tokio::spawn(async move { handle_incoming(msg, &app2).await; });
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
                                eprintln!("[P2P] Network maturity reached ({} known peers) — relay is fully optional", known_count);
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
                        eprintln!("[Sharding] MasterPromotion: shard {} → new master {} (was {})", shard_id, new_master, former_master);
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

                            let app2 = app.clone();
                            let mcid = manifest_cid.clone();
                            tokio::spawn(async move {
                                process_received_manifest(&mcid, &app2).await;
                            });
                        }
                    } else if key_str.starts_with("ego-block:") {

                        let block_cid = key_str.trim_start_matches("ego-block:").to_string();
                        if !crate::blocks::have_block(&block_cid) {
                            let _ = crate::blocks::save_block(&block_cid, &rec.record.value);
                            eprintln!("[DHT] Block {} received from DHT ({} bytes)", &block_cid[..16.min(block_cid.len())], rec.record.value.len());

                            let app2 = app.clone();
                            tokio::spawn(async move {
                                check_block_completes_manifests(&block_cid, &app2).await;
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
                                let app2 = app.clone();
                                let key2 = key_str.clone();
                                eprintln!("[DHT-Inbox] Processing message from {}", key2);
                                tokio::spawn(async move { handle_incoming(msg, &app2).await; });

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

pub async fn handle_incoming(msg: P2PMessage, app: &tauri::AppHandle) {
    match msg {
        P2PMessage::ContactRequest {
            from_addr, from_name, from_ed25519, from_kyber, from_shared_key, from_endpoint, bundle_token,
        } => {
            // Validate bundle token — drop silently if revoked
            let my_token = crate::ledger::Ledger::load().bundle_token;
            if !my_token.is_empty() {
                match &bundle_token {
                    Some(t) if t == &my_token => {}
                    _ => return, // old / missing token — bundle has been revoked
                }
            }
            let _cg = crate::commands::messenger::CONTACTS_LOCK.lock().unwrap();
            let mut contacts = load_contacts();
            if let Some(existing) = contacts.iter_mut().find(|c| c.address == from_addr) {
                if !from_endpoint.is_empty() && existing.endpoint != from_endpoint {
                    existing.endpoint = from_endpoint;
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
            };
            contacts.push(contact.clone());
            let _ = save_contacts(&contacts);
            crate::commands::notifications::notify(&app, "Contact Request", &format!("{} wants to connect with you", from_name));
            let _ = app.emit_all("ego://contact-request", &contact);
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
            let _ = app.emit_all("ego://data-manifest", serde_json::json!({
                "from_addr":    from_addr,
                "cid_count":    cids.len(),
                "available_gb": available_gb,
                "is_relay":     is_relay,
            }));
        }

        P2PMessage::PinRequest { cid, from_addr, from_endpoint, storage_fee_uegoc, expiry } => {
            eprintln!("[P2P] PinRequest for {} from {} fee={} expiry={}", cid, from_addr, storage_fee_uegoc, expiry);
            let ledger    = crate::ledger::Ledger::load();
            let used: u64 = ledger.stored_files.iter().map(|f| f.encrypted_size).sum();
            let capacity  = ledger.storage_allocated_bytes;
            let has_file  = ledger.stored_files.iter()
                .any(|f| f.cid == cid && !f.local_path.is_empty() && !f.local_path.starts_with("sender:"));
            let my_addr   = ledger.address.clone();
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

                // ── Lock collateral on-chain ──────────────────────────────
                if collateral > 0 {
                    let now2       = chrono::Utc::now().timestamp();
                    let nonce      = ledger.nonce + 1;
                    let sign_input = format!("lock_collateral:{}:{}:{}", my_addr, cid, nonce);
                    let sig_hex    = crate::ledger::load_seed()
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
                    let mut ledger2 = crate::ledger::Ledger::load();
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
                let mut ledger = crate::ledger::Ledger::load();
                let mut changed = false;
                let mut provider_payment: Option<(String, String, u64)> = None; // (from, to, amount)

                for f in ledger.stored_files.iter_mut() {
                    if f.cid == cid && !f.replica_peers.contains(&ack_from) {
                        f.replica_peers.push(ack_from.clone());
                        if f.replica_peers.len() > MIN_REPLICAS {
                            f.replica_peers.truncate(MIN_REPLICAS);
                        }
                        changed = true;
                        eprintln!("[Replication] {} pinned by {} ({}/{} replicas)",
                            cid, ack_from, f.replica_peers.len(), MIN_REPLICAS);

                        // Pay the new slave their share of the storage fee.
                        // Fee splits equally among (MIN_REPLICAS + 1) providers:
                        // master + MIN_REPLICAS slaves.
                        if f.storage_fee_uegoc > 0 {
                            let share = f.storage_fee_uegoc / (MIN_REPLICAS as u64 + 1);
                            if share > 0 {
                                provider_payment = Some((
                                    "egot1storagefees000000000000000000000000000000".to_string(),
                                    ack_from.clone(),
                                    share,
                                ));
                            }
                        }
                    }
                }

                if changed {
                    // Also pay self (master) their share on first replica confirmation
                    let master_share = ledger.stored_files.iter()
                        .find(|f| f.cid == cid)
                        .filter(|f| f.replica_peers.len() == 1) // only on first slave
                        .and_then(|f| {
                            let share = f.storage_fee_uegoc / (MIN_REPLICAS as u64 + 1);
                            if share > 0 { Some((ledger.address.clone(), share)) } else { None }
                        });

                    let now = chrono::Utc::now().timestamp();
                    let mut chain = crate::ledger::load_chain();

                    if let Some((_, to, amount)) = provider_payment {
                        let h = format!("0x{}", ego_core::hash_data(
                            format!("provider-pay:{}:{}:{}", cid, to, now).as_bytes()
                        ).to_hex());
                        chain.transactions.push(crate::ledger::LedgerTx {
                            hash: h, from: "egot1storagefees000000000000000000000000000000".into(),
                            to, amount,
                            memo: Some(format!("Storage provider reward: {}", &cid[..16.min(cid.len())])),
                            timestamp: now, signature: "provider".into(),
                            status: "Confirmed".into(),
                            ..crate::ledger::LedgerTx::default()
                        });
                    }
                    if let Some((to, amount)) = master_share {
                        let h = format!("0x{}", ego_core::hash_data(
                            format!("master-pay:{}:{}:{}", cid, to, now).as_bytes()
                        ).to_hex());
                        chain.transactions.push(crate::ledger::LedgerTx {
                            hash: h, from: "egot1storagefees000000000000000000000000000000".into(),
                            to, amount,
                            memo: Some(format!("Storage master reward: {}", &cid[..16.min(cid.len())])),
                            timestamp: now, signature: "provider".into(),
                            status: "Confirmed".into(),
                            ..crate::ledger::LedgerTx::default()
                        });
                    }
                    let _ = crate::ledger::save_chain(&chain);
                    let _ = ledger.save();
                }
            }
        }

        // ── Master → slave heartbeat ──────────────────────────────────────
        P2PMessage::ReplicaHeartbeat { cid, master_addr, timestamp } => {
            let mut ledger = crate::ledger::Ledger::load();
            let mut changed = false;
            for f in ledger.stored_files.iter_mut() {
                if f.cid == cid && f.replication_role == "slave" && f.replica_master == master_addr {
                    f.master_last_seen = timestamp;
                    changed = true;
                }
            }
            if changed { let _ = ledger.save(); }
        }

        // ── Slave promoted itself to master — update our records ──────────
        P2PMessage::ReplicaPromote { cid, new_master, old_master, .. } => {
            let my_addr = crate::ledger::Ledger::load().address;
            let mut ledger = crate::ledger::Ledger::load();
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
            if changed { let _ = ledger.save(); }
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
                    p.name           = from_name.clone();
                    p.ed25519_pubkey = from_ed25519;
                    p.kyber_pubkey   = from_kyber;
                    p.status         = "approved".to_string();
                    if !from_endpoint.is_empty() {
                        p.endpoint = from_endpoint;
                    }
                    let contact = p.clone();
                    let _ = save_contacts(&contacts);
                    if !already_approved {
                        crate::commands::notifications::notify(&app, "Contact Request Accepted!", &format!("{} accepted your request", from_name));
                        let _ = app.emit_all("ego://contact-approved", &contact);
                    }
                }
            } else {
                contacts.retain(|c| !(c.status == "pending_out" && c.shared_key_hex == shared_key));
                let _ = save_contacts(&contacts);
                crate::commands::notifications::notify(&app, "Contact Request Declined", "Your contact request was declined.");
                let _ = app.emit_all("ego://contact-declined", ());
            }
        }

        P2PMessage::PeerAnnounce { address, name, endpoint, endpoints, city, country, coverage_score, dilithium_pubkey, vrf_pubkey } => {
            register_known_validator(&address);

            if coverage_score > 0 { crate::poc::record_peer_score(&address, coverage_score); }
            if !dilithium_pubkey.is_empty() { register_validator_pubkey(&address, &dilithium_pubkey); }
            if !vrf_pubkey.is_empty() { record_peer_ed25519(&address, &vrf_pubkey); }
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
            let state = app.state::<crate::app::AppState>();
            state.upsert_peer(crate::app::PeerInfo {
                address:   address.clone(),
                name,
                endpoint:  endpoint.clone(),
                last_seen: Utc::now().timestamp(),
                city,
                country,
            });
            upsert_peer_cache(PeerEntry {
                address:   address.clone(),
                endpoint:  endpoint.clone(),
                last_seen: Utc::now().timestamp(),
                city:      None,
                country:   None,
            });

            if !endpoint.is_empty() {
                let ep = endpoint.clone();
                let addr_clone = address.clone();
                tokio::spawn(async move {
                    crate::commands::outbox::flush_for(&addr_clone, Some(&ep)).await;
                });

                let tip = crate::chain_db::block_count();
                if tip > 0 {
                    let ep2 = endpoint.clone();
                    tokio::spawn(async move {
                        let chain = crate::ledger::load_chain();
                        let response = P2PMessage::ChainSyncResponse {
                            blocks:       chain.blocks,
                            transactions: chain.transactions,
                        };
                        if let Err(e) = send_message_any(&[ep2.clone()], &response).await {
                            if !e.contains("none of the requested protocols") {
                                eprintln!("[P2P] proactive chain push to {}: {}", ep2, e);
                            }
                        }
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
                    let app_import = app.clone();
                    tokio::spawn(async move {
                        crate::commands::notifications::try_auto_import(
                            &app_import, &content_clone, &from_for_import,
                        ).await;
                    });
                }
            } else {

                {
                    let state = app.state::<crate::app::AppState>();
                    *state.pending_chat_address.lock().unwrap() = Some(msg.from.clone());
                }
                let preview = if msg.content.len() > 40 {
                    format!("{}…", &msg.content[..40])
                } else {
                    msg.content.clone()
                };
                crate::commands::notifications::notify(&app, "New Message", &preview);
            }
            let _ = app.emit_all("ego://message-received", &msg);
        }
        Err(e) => eprintln!("[P2P] Decrypt error: {}", e),
    }
}

        P2PMessage::TxBroadcast { tx, block } => {
            apply_incoming_tx(tx, block, app).await;
        }

        P2PMessage::BlockProposal { block, transactions, proposer, .. } => {
            register_known_validator(&proposer);
            handle_block_proposal(block, transactions, proposer, app).await;
        }

        P2PMessage::BlockVote { block_hash, height, voter, signature, timestamp, vrf_ticket, prev_hash } => {
            register_known_validator(&voter);
            handle_block_vote(block_hash, height, voter, signature, timestamp, vrf_ticket, prev_hash, app).await;
        }

        P2PMessage::BlockFinalized { block, transactions, votes } => {
            let block_hash = block.hash.clone();
            let height     = block.height;
            merge_remote_chain(vec![block], transactions, app).await;
            process_inbound_qc_finalization(&block_hash, height, &votes);
        }

        P2PMessage::ChainSyncRequest { requester_endpoint } => {
            let chain    = load_chain();
            let response = P2PMessage::ChainSyncResponse {
                blocks:       chain.blocks,
                transactions: chain.transactions,
            };
            tokio::spawn(async move {
                let eps = vec![requester_endpoint.clone()];
                if let Err(e) = send_message_any(&eps, &response).await {
                    eprintln!("[P2P] chain sync reply: {}", e);
                }
            });
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

            let _ = app.emit_all("ego://headers-received", &headers);
        }

        P2PMessage::ChainSyncResponse { blocks, transactions } => {
            merge_remote_chain(blocks, transactions, app).await;
        }

        P2PMessage::ShardDataRequest { shard_id, from_height, requester_address: _, requester_endpoint } => {
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

        P2PMessage::ShardDataResponse { shard_id, blocks, transactions } => {
            eprintln!("[Sharding] received {} blocks for shard {}", blocks.len(), shard_id);
            merge_remote_chain(blocks, transactions, app).await;
        }

        P2PMessage::ShardBlockQuery { block_height, requester_address: _, requester_endpoint } => {
            let chain = load_chain();
            let map   = crate::sharding::load_shard_map();
            let shard_id = crate::sharding::shard_for_height(
                block_height, map.total_blocks.max(1), map.shard_count
            );
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
                    city:      None,
                    country:   None,
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
            let enc_path = storage.join(format!("{}.enc", short));
            if let Err(e) = std::fs::write(&enc_path, &enc_bytes) {
                eprintln!("[P2P] FileData write failed: {}", e);
                return;
            }
            let mut ledger = crate::ledger::Ledger::load();
            let enc_str    = enc_path.to_string_lossy().to_string();
            if let Some(f) = ledger.stored_files.iter_mut().find(|f| f.cid == cid) {
                f.local_path = enc_str.clone();
                if !key_nonce_hex.is_empty() { f.key_nonce_hex = key_nonce_hex.clone(); }
                if f.name.is_empty() { f.name = file_name.clone(); }
                f.status = "Received".to_string();
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
                    key_nonce_hex,
                    local_path:      enc_str,
                    owner:           my_addr,
                    ..Default::default()
                });
            }
            let _ = ledger.save();
            eprintln!("[P2P] FileData saved for {}", cid);
            let _ = app.emit_all("ego://file-downloaded", serde_json::json!({ "cid": cid }));
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
                        let mut ledger = crate::ledger::Ledger::load();
                        let my_addr    = ledger.address.clone();
                        if let Some(f) = ledger.stored_files.iter_mut().find(|f| f.cid == manifest_cid) {
                            f.key_nonce_hex  = crate::ledger::protect_key_hex(&key_hex64);
                            f.blocks_total   = blocks_total;
                            f.blocks_received = crate::blocks::blocks_received_count(&manifest);
                            f.manifest_cid   = manifest_cid.clone();
                            if f.name.is_empty() { f.name = file_name.clone(); }
                            let _ = ledger.save();
                        }
                    }

                    let missing = crate::blocks::missing_blocks(&manifest);
                    eprintln!("[Blocks] Need {}/{} blocks for {}", missing.len(), blocks_total, &manifest_cid[..16.min(manifest_cid.len())]);
                    let my_addr    = crate::ledger::Ledger::load().address;
                    let my_ep      = get_public_endpoint().await;

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

                    // If all blocks are already on disk (from DHT or a previous run),
                    // update the ledger status and emit file-downloaded now.
                    {
                        let app2 = app.clone();
                        let mcid = manifest_cid.clone();
                        tokio::spawn(async move {
                            update_ledger_for_block(&mcid, &app2).await;
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

                        if let Some(tx) = DHT_CMD_TX.get() {
                            let dht_key = format!("ego-block:{}", block_cid);
                            let _ = tx.send(DhtCommand::PutPeer { key: dht_key, value: enc_bytes.clone() });
                            eprintln!("[Blocks] Block {} published to DHT global store", &block_cid[..16.min(block_cid.len())]);
                        }
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

                    let app2 = app.clone();
                    let mcid = manifest_cid.clone();
                    tokio::spawn(async move {
                        update_ledger_for_block(&mcid, &app2).await;
                    });
                }
            }
        }

        P2PMessage::ViewChange { view, voter, .. } => {
            handle_view_change_msg(view, voter).await;
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
                // 4. Record slash_storage for accused in our chain.
                use crate::ledger::{load_chain, save_chain, LedgerTx};
                let nonce = crate::ledger::Ledger::load().nonce + 1;
                let sign_input = format!("external_slash:{}:{}:{}", my_addr, accused_addr, now);
                let sig_hex = crate::ledger::load_seed()
                    .and_then(|s| { let mut a=[0u8;32]; a.copy_from_slice(&s[..32]); ego_core::KeyPair::from_bytes(&a).ok() })
                    .map(|kp| hex::encode(kp.sign_ed25519(sign_input.as_bytes()).as_bytes()))
                    .unwrap_or_default();
                let tx_hash = format!("0x{}", ego_core::hash_data(sign_input.as_bytes()).to_hex());
                let mut chain = load_chain();
                chain.transactions.push(LedgerTx {
                    hash:            tx_hash.clone(),
                    from:            accused_addr.clone(),
                    to:              "egot1slashpool0000000000000000000000000000000".into(),
                    amount:          0,
                    memo:            Some(format!("external_slash by {} | cid {}", &reporter_addr[..16.min(reporter_addr.len())], &cid[..16.min(cid.len())])),
                    timestamp:       now,
                    signature:       sig_hex,
                    status:          "Confirmed".into(),
                    block_height:    None,
                    nonce,
                    tx_type:         "slash_storage".into(),
                    cid:             cid.clone(),
                    ..LedgerTx::default()
                });
                chain.mine_block(&tx_hash, &my_addr);
                let mut ledger2 = crate::ledger::Ledger::load();
                ledger2.nonce = nonce;
                let _ = ledger2.save();
                let _ = save_chain(&chain);
                eprintln!("[Slash] Recorded external slash for {} | tx {}", &accused_addr[..16.min(accused_addr.len())], &tx_hash[..18]);
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
                        // Proof valid — update coverage score positively (small reward).
                        let current = crate::poc::get_peer_score(&prover);
                        let boosted  = (current + 5).min(crate::poc::MAX_COVERAGE_SCORE);
                        crate::poc::record_peer_score(&prover, boosted);
                    } else {
                        eprintln!(
                            "[PoRep] FAIL: {} returned wrong hash for block {} (expected={:.8}… got={:.8}…) — penalising",
                            &prover[..prover.len().min(20)],
                            &block_cid[..block_cid.len().min(16)],
                            expected.expected_hash, response_hash
                        );
                        // Wrong hash = corrupted or fake replica → heavy penalty.
                        let current = crate::poc::get_peer_score(&prover);
                        let penalised = current.saturating_sub(500).max(1);
                        crate::poc::record_peer_score(&prover, penalised);
                    }
                }
            }
        }
    }
}

async fn update_ledger_for_block(manifest_cid: &str, app: &tauri::AppHandle) {
    let Ok(manifest) = crate::blocks::load_manifest(manifest_cid) else { return; };
    let received = crate::blocks::blocks_received_count(&manifest);
    let total    = manifest.blocks.len() as u32;

    let mut ledger = crate::ledger::Ledger::load();
    if let Some(f) = ledger.stored_files.iter_mut().find(|f| f.cid == manifest_cid) {
        if f.status == "Failed" { return; } // already timed out; don't overwrite
        let prev = f.blocks_received;
        f.blocks_received = received;
        if received > prev {
            f.last_block_at = chrono::Utc::now().timestamp();
        }
        if received >= total {
            f.status     = "Received".to_string();
            f.local_path = crate::blocks::manifest_path(manifest_cid)
                .to_string_lossy().to_string();
        }
        let _ = ledger.save();
    }

    let _ = app.emit_all("ego://block-progress", serde_json::json!({
        "manifest_cid": manifest_cid,
        "blocks_received": received,
        "blocks_total": total,
    }));

    if received >= total {
        eprintln!("[Blocks] All {} blocks received for {}", total, &manifest_cid[..16.min(manifest_cid.len())]);
        let _ = app.emit_all("ego://file-downloaded", serde_json::json!({ "cid": manifest_cid }));

        // FIX 1: Register self as a CID holder in the relay registry so any peer
        // can discover us and request blocks directly — not just the original uploader.
        let cid2  = manifest_cid.to_string();
        let addr2 = crate::ledger::Ledger::load().address;
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

async fn process_received_manifest(manifest_cid: &str, app: &tauri::AppHandle) {
    let Ok(manifest) = crate::blocks::load_manifest(manifest_cid) else { return; };
    let total    = manifest.blocks.len() as u32;
    let received = crate::blocks::blocks_received_count(&manifest);

    {
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
                if received >= total {
                    f.status     = "Received".to_string();
                    f.local_path = crate::blocks::manifest_path(manifest_cid)
                        .to_string_lossy().to_string();
                }
                let _ = ledger.save();
            }
        }
    }

    let _ = app.emit_all("ego://block-progress", serde_json::json!({
        "manifest_cid": manifest_cid,
        "blocks_received": received,
        "blocks_total": total,
    }));

    if received >= total {
        eprintln!("[Blocks] All {} blocks present at manifest arrival for {}", total, &manifest_cid[..16.min(manifest_cid.len())]);
        let _ = app.emit_all("ego://file-downloaded", serde_json::json!({ "cid": manifest_cid }));
        return;
    }

    let sender_addr = {
        let ledger = crate::ledger::Ledger::load();
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

async fn check_block_completes_manifests(block_cid: &str, app: &tauri::AppHandle) {
    let ledger = crate::ledger::Ledger::load();
    for file in &ledger.stored_files {
        if file.cid.starts_with("egomfd1") && file.blocks_received < file.blocks_total {
            if let Ok(manifest) = crate::blocks::load_manifest(&file.cid) {
                let has_this = manifest.blocks.iter().any(|b| b.block_cid == block_cid);
                if has_this {
                    let mcid = file.cid.clone();
                    let app2 = app.clone();
                    tokio::spawn(async move {
                        update_ledger_for_block(&mcid, &app2).await;
                    });
                }
            }
        }
    }
}

fn validate_block(block: &crate::ledger::LedgerBlock, chain: &crate::ledger::SharedChain) -> bool {

    if block.height == 0 {
        return block.hash == crate::ledger::GENESIS_HASH;
    }

    let prev_exists = chain.blocks.iter().any(|b| b.hash == block.prev_hash);
    if !prev_exists {
        eprintln!("[Validate] Block #{} rejected: unknown prev_hash {}", block.height, block.prev_hash);
        return false;
    }

    if chain.blocks.iter().any(|b| b.hash == block.hash) {
        return false;
    }

    let expected_reward = crate::tokenomics::block_reward_at(block.height);
    if block.reward != expected_reward && block.reward != 0 {
        eprintln!("[Validate] Block #{} rejected: reward {} != expected {}",
            block.height, block.reward, expected_reward);
        return false;
    }

    if let Some(ref cb_hash) = block.coinbase_tx {
        let cb_tx = chain.transactions.iter().find(|t| &t.hash == cb_hash);
        match cb_tx {
            Some(tx) => {
                if tx.to != block.miner || tx.amount != expected_reward {
                    eprintln!("[Validate] Block #{} rejected: invalid coinbase tx (to={}, amount={}, miner={}, expected={})",
                        block.height, tx.to, tx.amount, block.miner, expected_reward);
                    return false;
                }
            }
            None => {
                if block.reward != 0 {
                    eprintln!("[Validate] Block #{} rejected: coinbase TX {} not found",
                        block.height, cb_hash);
                    return false;
                }
            }
        }
    }


    if !block.tx_merkle_root.is_empty() {
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
        // Legacy v1 hash (pre-merkle blocks).
        let v1_hash = {
            let v1_input = format!("{}{}{}{}", block.prev_hash, block.height, block.miner, block.timestamp);
            blake3::hash(v1_input.as_bytes()).to_hex().to_string()
        };
        let valid = block.hash == expected_v2_hash
            || block.hash == v1_hash
            || (!expected_v3_hash.is_empty() && block.hash == expected_v3_hash);
        if !valid {
            eprintln!(
                "[Validate] Block #{} rejected: hash mismatch (stored={:.8}… v2={:.8}… v3={:.8}…)",
                block.height, block.hash, expected_v2_hash,
                if expected_v3_hash.is_empty() { "n/a".to_string() } else { expected_v3_hash[..8.min(expected_v3_hash.len())].to_string() }
            );
            return false;
        }
    }

    true
}

async fn apply_incoming_tx(tx: LedgerTx, block: LedgerBlock, app: &tauri::AppHandle) {
    if block.height == 0 {
        if crate::chain_db::get_tx_by_hash(&tx.hash).is_none() {
            if let Ok(()) = crate::ledger::verify_incoming_tx(&tx) {
                crate::mempool::get_mempool().push(tx);
            }
        }
        return;
    }

    let expected_reward = crate::tokenomics::block_reward_at(block.height);
    if block.reward != expected_reward && block.reward != 0 {
        eprintln!("[P2P] TxBroadcast: block #{} rejected — reward {} != expected {}",
            block.height, block.reward, expected_reward);
        return;
    }

    // Verify the block was produced by the legitimate PoC slot winner.
    {
        let mut parts = block.poc_ticket.splitn(2, ':');
        let ticket_hex = parts.next().unwrap_or("");
        let sig_hex    = parts.next().unwrap_or("");
        if !crate::poc::verify_ticket(
            ticket_hex, sig_hex, &block.miner, &block.prev_hash, block.poc_slot, block.height,
        ) {
            eprintln!("[P2P] TxBroadcast: block #{} rejected — invalid PoC ticket", block.height);
            return;
        }
    }

    if let Err(reason) = crate::ledger::verify_incoming_tx_with_miner(&tx, &block.miner) {
        eprintln!("[P2P] TxBroadcast: TX {} rejected — {}", tx.hash, reason);
        return;
    }

    if crate::chain_db::get_tx_by_hash(&tx.hash).is_some() {
        return;
    }

    if crate::chain_db::get_block_by_height(block.height).is_none() {
        crate::chain_db::append_peer_block(&block, &[tx]);
        let _ = app.emit_all("ego://chain-updated", ());
    } else {
        crate::mempool::get_mempool().push(tx);
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

async fn merge_remote_chain(
    blocks: Vec<LedgerBlock>, transactions: Vec<LedgerTx>, app: &tauri::AppHandle,
) {
    merge_remote_chain_inner(blocks, transactions, app, false).await;
}

async fn merge_remote_chain_trusted(
    blocks: Vec<LedgerBlock>, transactions: Vec<LedgerTx>, app: &tauri::AppHandle,
) {
    merge_remote_chain_inner(blocks, transactions, app, true).await;
}

async fn merge_remote_chain_inner(
    mut blocks: Vec<LedgerBlock>, transactions: Vec<LedgerTx>, app: &tauri::AppHandle,
    trusted: bool,
) {

    let mut new_txs: Vec<LedgerTx> = Vec::new();
    let mut new_blocks: Vec<LedgerBlock> = Vec::new();

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
            eprintln!("[Oracle] Reorg: local chain diverges at height {} — truncating and adopting oracle chain", dh);
            crate::chain_db::truncate_from(dh);
        }

        for block in blocks {
            if block.height == 0 { continue; }
            if crate::chain_db::get_block_by_height(block.height).is_none() {
                new_blocks.push(block);
            }
        }
    } else {

    for block in blocks {
        if block.height == 0 { continue; }


        if block.height > 0 {
            let parent_height = block.height - 1;
            let expected_prev = if parent_height == 0 {
                crate::ledger::GENESIS_HASH.to_string()
            } else if let Some(parent) = crate::chain_db::get_block_by_height(parent_height) {
                parent.hash.clone()
            } else {
                block.prev_hash.clone()
            };
            if block.prev_hash != expected_prev {
                let our_tip = crate::chain_db::block_count();
                if block.height > our_tip {
                    eprintln!(
                        "[P2P] Fork detected at #{}: remote is ahead ({} > {}), triggering resync",
                        block.height, block.height, our_tip
                    );
                } else {
                    eprintln!(
                        "[P2P] Block #{} rejected: prev_hash mismatch (got {} expected {})",
                        block.height,
                        &block.prev_hash[..8.min(block.prev_hash.len())],
                        &expected_prev[..8.min(expected_prev.len())]
                    );
                }
                continue;
            }
        }

        {

            let expected_reward = crate::tokenomics::block_reward_at(block.height);
            let reward_ok = block.reward == expected_reward || block.reward == 0;
            if !reward_ok {
                eprintln!("[P2P] Block #{} rejected: reward {} != expected {}",
                    block.height, block.reward, expected_reward);
                continue;
            }

            let mut parts = block.poc_ticket.splitn(2, ':');
            let ticket_hex = parts.next().unwrap_or("");
            let sig_hex    = parts.next().unwrap_or("");
            if !crate::poc::verify_ticket(
                ticket_hex, sig_hex, &block.miner, &block.prev_hash, block.poc_slot, block.height,
            ) {
                eprintln!("[P2P] Block #{} rejected: invalid PoC ticket", block.height);
                continue;
            }

            new_blocks.push(block);
        }
    }

    } // end else (untrusted path)

    for tx in transactions {

        match crate::ledger::verify_incoming_tx(&tx) {
            Ok(())       => new_txs.push(tx),
            Err(reason)  => eprintln!("[P2P] Sync TX {} rejected — {}", tx.hash, reason),
        }
    }

    if new_blocks.is_empty() && new_txs.is_empty() { return; }

    for block in &new_blocks {
        let block_txs: Vec<LedgerTx> = new_txs.iter()
            .filter(|tx| tx.block_height == Some(block.height))
            .cloned()
            .collect();
        crate::chain_db::append_peer_block(block, &block_txs);
    }

    let pool = crate::mempool::get_mempool();
    for tx in &new_txs {
        let is_user_tx = tx.tx_type != "reward" && tx.tx_type != "coinbase"
            && !tx.hash.is_empty()
            && crate::chain_db::get_tx_by_hash(&tx.hash).is_none()
            && !new_blocks.iter().any(|b| Some(b.height) == tx.block_height);
        if is_user_tx {
            pool.push(tx.clone());
        }
    }

    let _ = app.emit_all("ego://chain-updated", ());
}

pub async fn oracle_sync_chain() {
    let chain = load_chain();
    if chain.blocks.is_empty() && chain.transactions.is_empty() { return; }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .unwrap_or_default();
    for block in &chain.blocks {
        if let Ok(body) = serde_json::to_value(block) {
            oracle_post(&client, "/block/broadcast", &body).await;
        }
        // Forward block metadata to relay for block-spike detection.
        let relay_block_url = format!("{}/block/alert", RELAY_RPC);
        let relay_block_body = serde_json::json!({
            "height":   block.height,
            "hash":     block.hash,
            "tx_count": block.tx_count,
            "timestamp": block.timestamp,
            "miner":    block.miner,
        });
        let _ = client.post(&relay_block_url).json(&relay_block_body).send().await;
    }
    for tx in &chain.transactions {
        if let Ok(body) = serde_json::to_value(tx) {
            oracle_post(&client, "/tx/broadcast", &body).await;
            // Also forward to relay alert system for anomaly detection.
            let relay_tx_url = format!("{}/tx/broadcast", RELAY_RPC);
            let _ = client.post(&relay_tx_url).json(&body).send().await;
        }
    }
    eprintln!("[Oracle] Synced {} blocks, {} txs to Oracle + Relay",
        chain.blocks.len(), chain.transactions.len());
}

pub async fn fetch_chain_from_oracle(app: &tauri::AppHandle) {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    let blocks: Vec<crate::ledger::LedgerBlock> = match oracle_get(&client, "/chain/blocks").await {
        Some(resp) => resp.json().await.unwrap_or_default(),
        None => { eprintln!("[Oracle] fetch blocks: all endpoints unreachable"); vec![] }
    };

    let transactions: Vec<crate::ledger::LedgerTx> = match oracle_get(&client, "/chain/transactions").await {
        Some(resp) => resp.json().await.unwrap_or_default(),
        None => { eprintln!("[Oracle] fetch txs: all endpoints unreachable"); vec![] }
    };

    if blocks.is_empty() && transactions.is_empty() {
        eprintln!("[Oracle] chain empty or unreachable — skipping merge");
        return;
    }


    if let Some(genesis) = blocks.iter().find(|b| b.height == 0) {
        if genesis.hash != GENESIS_HASH {
            eprintln!(
                "[Oracle] REJECTED: remote genesis hash {} does not match expected {}",
                genesis.hash, GENESIS_HASH
            );
            return;
        }
    }

    merge_remote_chain_trusted(blocks, transactions, app).await;
    eprintln!("[Oracle] Chain merged from Oracle RPC (trusted)");
}

fn bft_sign(data: &str) -> Option<String> {
    let seed_bytes = crate::ledger::load_seed()?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let kp = ego_core::KeyPair::from_bytes(&seed).ok()?;

    let sig = kp.sign_dilithium(data.as_bytes());
    Some(hex::encode(sig.as_bytes()))
}

async fn handle_block_proposal(
    block: LedgerBlock,
    transactions: Vec<LedgerTx>,
    proposer: String,
    app: &tauri::AppHandle,
) {
    let my_addr = crate::ledger::Ledger::load().address;
    if my_addr.is_empty() { return; }


    if my_addr == proposer { return; }

    let seed_bytes = match crate::ledger::load_seed() {
        Some(b) if b.len() == 32 => b,
        _ => return,
    };
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed_bytes);

    let vrf_in  = crate::bft_committee::vrf_input(&block.prev_hash, block.height, crate::bft_committee::VRF_ROLE_COMMITTEE);
    let ticket  = crate::bft_committee::sign_vrf_ticket(&seed_arr, &vrf_in);
    let all_validators: Vec<String> = known_validators().iter().cloned().collect();
    let my_drs    = crate::bft_committee::compute_drs_weight(&my_addr);
    let total_drs = crate::bft_committee::total_drs_weight(&all_validators);

    if !crate::bft_committee::qualifies_committee(&ticket, my_drs, total_drs) {
        return;
    }

    // ── 2. Block-level structural validation ─────────────────────────────────
    let chain = load_chain();
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


    for tx in &transactions {
        // Skip coinbase (system reward tx) — its amount is validated below.
        if Some(&tx.hash) == block.coinbase_tx.as_ref() { continue; }
        if let Err(reason) = crate::ledger::verify_incoming_tx_with_miner(tx, &proposer) {
            eprintln!("[BFT] Committee: rejected proposal #{} from {} — tx {} invalid: {}",
                block.height, proposer, tx.hash, reason);
            return;
        }
    }


    let expected_reward = crate::tokenomics::block_reward_at(block.height);
    if let Some(ref cb_hash) = block.coinbase_tx {
        match transactions.iter().find(|t| &t.hash == cb_hash) {
            Some(cb) => {
                if cb.amount != expected_reward || cb.to != proposer {
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

    // ── 6. Dedup: skip if we already voted for this block ────────────────────
    {
        let votes = pending_votes();
        if let Some(voters) = votes.get(&block.hash) {
            if voters.contains(&my_addr) { return; }
        }
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
    let signature = match bft_sign(&vote_data) {
        Some(s) => s,
        None    => { eprintln!("[BFT] Cannot sign vote — no key"); return; }
    };
    let vrf_ticket_hex = hex::encode(&ticket);

    eprintln!("[BFT] Self-selected as committee for block #{} — voting", block.height);

    let vote = P2PMessage::BlockVote {
        block_hash: block.hash.clone(),
        height:     block.height,
        voter:      my_addr.clone(),
        signature:  signature.clone(),
        timestamp:  chrono::Utc::now().timestamp(),
        vrf_ticket: vrf_ticket_hex.clone(),
        prev_hash:  block.prev_hash.clone(),
    };

    if let Ok(data) = serde_json::to_vec(&vote) {
        publish_gossip("ego-votes-v1", data).await;
    }

    handle_block_vote(block.hash, block.height, my_addr, signature, chrono::Utc::now().timestamp(), vrf_ticket_hex, block.prev_hash, app).await;
}

async fn handle_block_vote(
    block_hash:  String,
    height:      u64,
    voter:       String,
    signature:   String,
    timestamp:   i64,
    vrf_ticket:  String,
    prev_hash:   String,
    app:         &tauri::AppHandle,
) {
    if slashed_validators().contains(&voter) {
        eprintln!("[BFT] Ignoring vote from slashed validator {}", voter);
        return;
    }


    const VRF_ENFORCE_HEIGHT: u64 = 10;
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
                if !crate::bft_committee::qualifies_committee(&ticket_bytes, voter_drs, total_drs) {
                    eprintln!("[BFT] Vote from {} rejected — VRF ticket below committee threshold", voter);
                    return;
                }
            }
        }
    }

    // ── Dilithium vote signature verification ──────────────────────────────
    let vote_data = crate::bft_committee::vote_signing_data(&block_hash, height, &voter);
    if !voter.is_empty() && !signature.is_empty() && !verify_bft_sig(&voter, &vote_data, &signature) {
        eprintln!("[BFT] Invalid vote signature from {} at height {} — dropping", voter, height);
        return;
    }


    {
        let mut cast = votes_cast();
        let key = (voter.clone(), height);
        if let Some((prior_hash, prior_sig)) = cast.get(&key) {
            if *prior_hash != block_hash {
                let reason = format!(
                    "equivocation at height {}: voted {} and {}",
                    height, &prior_hash[..8.min(prior_hash.len())], &block_hash[..8.min(block_hash.len())]
                );
                // Clone before dropping the lock guard to avoid borrow-after-move.
                let prior_hash_c = prior_hash.clone();
                let prior_sig_c  = prior_sig.clone();
                let proof_payload = format!(
                    "equivocation:{}:h{}:sig1={}:sig2={}",
                    voter, height, prior_sig_c, signature
                );
                drop(cast);
                eprintln!("[BFT] EQUIVOCATION detected: {} — {}", voter, reason);
                slash_validator(&voter, &reason);
                // Submit a signed on-chain evidence tx so every full node can verify
                // the slash independently.  Signed by the detector (us), not the equivocator.
                {
                    let tx_hash = blake3::hash(proof_payload.as_bytes()).to_hex().to_string();
                    let my_ledger   = crate::ledger::Ledger::load();
                    let my_addr_det = my_ledger.address.clone();
                    // Sign tx_hash with local Ed25519 key.
                    let (det_sig_hex, det_pubkey_hex): (String, String) = crate::ledger::load_seed()
                        .and_then(|s| {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&s[..32.min(s.len())]);
                            ego_core::KeyPair::from_bytes(&arr).ok()
                        })
                        .map(|kp| (
                            hex::encode(kp.sign_ed25519(tx_hash.as_bytes()).as_bytes()),
                            hex::encode(kp.ed25519_public_key().as_bytes()),
                        ))
                        .unwrap_or_else(|| (String::new(), String::new()));

                    if !det_sig_hex.is_empty() {
                        let proof_tx = crate::ledger::LedgerTx {
                            hash:                 tx_hash,
                            from:                 my_addr_det,
                            to:                   "egot1slashpool0000000000000000000000000000000".to_string(),
                            amount:               0,
                            fee_uegoc:            0,
                            priority_fee_uegoc:   0,
                            timestamp:            chrono::Utc::now().timestamp(),
                            status:               "Pending".to_string(),
                            tx_type:              "equivocation_proof".to_string(),
                            signature:            det_sig_hex,
                            public_key_ed25519:   det_pubkey_hex,
                            memo:                 Some(format!(
                                "{{\"equivocator\":\"{}\",\"height\":{},\
                                 \"hash_a\":\"{}\",\"hash_b\":\"{}\",\
                                 \"sig_a\":\"{}\",\"sig_b\":\"{}\"}}",
                                voter, height,
                                prior_hash_c, block_hash,
                                prior_sig_c,  signature
                            )),
                            ..Default::default()
                        };
                        crate::mempool::get_mempool().push(proof_tx);
                    }
                }
                return;
            }
        } else {
            cast.insert(key, (block_hash.clone(), signature.clone()));
        }
    }

    {
        let finalized = finalized_at_height();
        if let Some(canonical) = finalized.get(&height) {
            if *canonical != block_hash {
                let mut counts = wrong_vote_counts();
                let count = counts.entry(voter.clone()).or_insert(0);
                *count += 1;
                eprintln!("[BFT] Wrong vote #{} from {} at height {} (voted {} expected {})",
                    count, voter, height, &block_hash[..8.min(block_hash.len())],
                    &canonical[..8.min(canonical.len())]);
                if *count >= WRONG_VOTE_THRESHOLD {
                    let reason = format!("{} wrong votes at height {}", count, height);
                    drop(counts);
                    slash_validator(&voter, &reason);
                }
                return;
            }
        }
    }

    let threshold = bft_threshold();

    let should_finalize = {
        let mut votes = pending_votes();
        let voters = votes.entry(block_hash.clone()).or_default();
        if !voters.contains(&voter) {
            voters.push(voter.clone());
            // Persist the vote to RocksDB so BFT state survives node restarts.
            // (Item 6: BFT votes are no longer ephemeral.)
            crate::chain_db::persist_pending_vote(&block_hash, &voter);
            eprintln!("[BFT] Vote for block #{} from {} ({}/{} votes)",
                height, voter, voters.len(), threshold);
        }

        voters.len() >= threshold && stake_quorum_reached(voters)
    };

    if !should_finalize { return; }

    if finalized_at_height().contains_key(&height) {
        return;
    }

    let final_vote_count = pending_votes().get(&block_hash).map(|v| v.len()).unwrap_or(0);
    eprintln!("[BFT] Block #{} FINALIZED with {} votes (threshold={})",
        height, final_vote_count, threshold);

    finalized_at_height().insert(height, block_hash.clone());


    CONSECUTIVE_EMPTY_VIEWS.store(0, Ordering::Relaxed);


    pending_proposals().remove(&height);

    // Clean up equivocation tracker for heights older than 100 blocks.
    {
        let cutoff = height.saturating_sub(100);
        votes_cast().retain(|(_, h), _| *h >= cutoff);
    }

    {
        let all_hashes: Vec<String> = pending_votes().keys().cloned().collect();
        for h in &all_hashes {
            crate::chain_db::clear_pending_votes_for_block(h);
        }
    }
    pending_votes().clear();

    let staged_opt: Option<(crate::ledger::LedgerBlock, Vec<LedgerTx>)> = {
        let mut staged = staged_block();
        if staged.as_ref().map(|(b, _)| b.hash == block_hash).unwrap_or(false) {
            staged.take()
        } else {
            None
        }
    };

    let (block, block_txs) = match staged_opt {
        Some((b, txs)) => {
            crate::chain_db::commit_staged_block(&b, &txs);
            crate::chain_db::pipeline_commit(height);
            (b, txs)
        }
        None => {
            match crate::chain_db::get_block_by_height(height) {
                Some(b) if b.hash == block_hash => {
                    let txs = crate::chain_db::get_txs_for_block(height);
                    crate::chain_db::pipeline_commit(height);
                    (b, txs)
                }
                _ => {
                    eprintln!("[BFT] Block {} not staged or committed — will arrive via sync", block_hash);
                    return;
                }
            }
        }
    };

    let votes_json: Vec<serde_json::Value> = {
        let cast = votes_cast();
        pending_votes()
            .get(&block_hash)
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|v| {
                let sig = cast.get(&(v.clone(), height))
                    .map(|(_, s)| s.as_str())
                    .unwrap_or("");
                serde_json::json!({"voter": v, "signature": sig})
            })
            .collect()
    };

    let finalized = P2PMessage::BlockFinalized {
        block:        block.clone(),
        transactions: block_txs,
        votes:        votes_json,
    };

    if let Ok(data) = serde_json::to_vec(&finalized) {
        publish_gossip("ego-blocks-v1", data).await;
    }

    let _ = app.emit_all("ego://chain-updated", ());
}


fn process_inbound_qc_finalization(block_hash: &str, height: u64, votes: &[serde_json::Value]) {
    // Guard: already finalized (this node collected 2f+1 votes itself).
    {
        let fin = finalized_at_height();
        if fin.contains_key(&height) {
            return;
        }
    }

    let threshold = bft_threshold();

    // ── 1. Quorum size check ──────────────────────────────────────────────────
    if votes.len() < threshold {
        eprintln!(
            "[QC] Block #{} ({:.8}…): only {} votes, need {} — ignoring peer finalization claim",
            height, block_hash, votes.len(), threshold
        );
        return;
    }

    // ── 2 & 3. Signature + known-validator verification ──────────────────────
    // Count votes whose ML-DSA-44 sig is valid and whose voter is a known validator.
    let vote_data_prefix = crate::bft_committee::vote_signing_data(block_hash, height, "");
    let known = known_validators();
    let mut verified: usize = 0;
    for v in votes {
        let voter = match v.get("voter").and_then(|x| x.as_str()) {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };
        let sig_hex = v.get("signature").and_then(|x| x.as_str()).unwrap_or("");
        if sig_hex.is_empty() { continue; }

        // voter must be a registered committee member
        if !known.contains(voter) { continue; }

        // vote_signing_data includes the voter address — rebuild per-voter
        let vote_data = crate::bft_committee::vote_signing_data(block_hash, height, voter);
        let _ = vote_data_prefix.as_str(); // silence unused warning
        if verify_bft_sig(voter, &vote_data, sig_hex) {
            verified += 1;
        }
    }
    drop(known);

    if verified < threshold {
        eprintln!(
            "[QC] Block #{} ({:.8}…): only {}/{} votes verified — rejected",
            height, block_hash, verified, threshold
        );
        return;
    }

    eprintln!(
        "[QC] Block #{} ({:.8}…) finalized via gossip — {}/{} sigs verified",
        height, block_hash, verified, threshold
    );

    // ── Update consensus state ────────────────────────────────────────────────
    finalized_at_height().insert(height, block_hash.to_string());
    pending_proposals().remove(&height);

    {
        let all_hashes: Vec<String> = pending_votes().keys().cloned().collect();
        for h in &all_hashes {
            crate::chain_db::clear_pending_votes_for_block(h);
        }
    }
    pending_votes().clear();

    CONSECUTIVE_EMPTY_VIEWS.store(0, Ordering::Relaxed);
}

pub async fn push_tx_to_relay(_tx: &crate::ledger::LedgerTx, _block: &crate::ledger::LedgerBlock) {}

pub fn touch_proposal_timestamp() {
    LAST_PROPOSAL_TS.store(chrono::Utc::now().timestamp(), Ordering::Relaxed);
}

async fn handle_view_change_msg(view: u64, voter: String) {
    register_known_validator(&voter);
    let threshold = bft_threshold().max(1);

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
        let current_height = crate::chain_db::block_count() + 1;
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

    let my_addr = crate::ledger::Ledger::load().address;
    if my_addr.is_empty() { return; }

    if known_validators().len() < crate::bft_committee::MIN_COMMITTEE_NET {
        return;
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
        let validators: Vec<String> = known_validators().iter().cloned().collect();
        if let Some(fallback_leader) = validators.iter().max_by(|a, b| {
            let da = crate::bft_committee::compute_drs_weight(a);
            let db = crate::bft_committee::compute_drs_weight(b);
            da.partial_cmp(&db).unwrap_or(std::cmp::Ordering::Equal)
        }) {
            if fallback_leader == &my_addr {
                eprintln!("[HotStuff] Fallback: we are highest-DRS node — proposing for view {}", view);
                tokio::spawn(async move { propose_block_as_leader_forced().await; });
            }
        }
    } else {
        // Normal path: VRF self-selection.
        // elect_proposer_for_next_slot() returns Some(my_addr) only if this node
        // won the VRF lottery (threshold scaled by EXPECTED_PROPOSERS_PER_SLOT).
        if let Some(ref winner) = elect_proposer_for_next_slot() {
            if winner == &my_addr {
                eprintln!("[HotStuff] VRF won — leader for view {} — proposing block", view);
                tokio::spawn(async move { propose_block_as_leader().await; });
            }
        }
    }
}

pub async fn propose_block_as_leader() {
    if known_validators().len() < crate::bft_committee::MIN_COMMITTEE_NET { return; }
    let miner = crate::ledger::Ledger::load().address;
    if miner.is_empty() { return; }

    let prev_hash   = crate::chain_db::get_tip_hash();
    let next_height = crate::chain_db::block_count() + 1;

    let seed_bytes = match crate::ledger::load_seed() {
        Some(b) => b,
        None    => return,
    };
    let mut seed_32 = [0u8; 32];
    seed_32.copy_from_slice(&seed_bytes);

    let vrf_in     = crate::bft_committee::vrf_input(&prev_hash, next_height, crate::bft_committee::VRF_ROLE_PROPOSER);
    let vrf_ticket = crate::bft_committee::sign_vrf_ticket(&seed_32, &vrf_in);

    let validators: Vec<String> = known_validators().iter().cloned().collect();
    let my_drs     = crate::bft_committee::compute_drs_weight(&miner);
    let total_drs  = crate::bft_committee::total_drs_weight(&validators);

    if !crate::bft_committee::qualifies_proposer(&vrf_ticket, my_drs, total_drs) {
        return;
    }
    eprintln!("[BFT] VRF election won — proposer for block #{}", next_height);

    let pool = crate::mempool::get_mempool();
    let is_solo = known_validators().len() <= 1;
    if pool.pending_count() == 0 && !is_solo { return; }
    let txs = pool.drain_all();

    let (poc_ticket, poc_sig) = crate::poc::check_slot_winner(&prev_hash)
        .unwrap_or_else(|| (String::new(), String::new()));
    let poc_slot = crate::poc::current_slot();

    let combined_ticket = if poc_ticket.is_empty() { String::new() }
                          else { format!("{}:{}", poc_ticket, poc_sig) };

    let (block, stamped) = crate::chain_db::build_block_proposal(&txs, &miner, &combined_ticket, poc_slot);

    {
        let mut staged = staged_block();
        *staged = Some((block.clone(), stamped));
    }

    let sig_data  = format!("proposal:{}:{}", block.hash, block.height);
    let signature = bft_sign(&sig_data).unwrap_or_default();

    let proposal = P2PMessage::BlockProposal {
        block:        block.clone(),
        transactions: txs,
        proposer:     miner.clone(),
        signature,
        vrf_ticket:   hex::encode(&vrf_ticket),
    };

    if let Ok(data) = serde_json::to_vec(&proposal) {
        publish_gossip("ego-proposals-v1", data).await;
    }

    let committee_vrf_in = crate::bft_committee::vrf_input(&block.prev_hash, block.height, crate::bft_committee::VRF_ROLE_COMMITTEE);
    let committee_ticket = crate::bft_committee::sign_vrf_ticket(&seed_32, &committee_vrf_in);
    let committee_ticket_hex = hex::encode(&committee_ticket);
    let self_vote_data = crate::bft_committee::vote_signing_data(&block.hash, block.height, &miner);
    if let Some(self_sig) = bft_sign(&self_vote_data) {
        {
            let mut pv = pending_votes();
            let voters = pv.entry(block.hash.clone()).or_default();
            if !voters.contains(&miner) {
                voters.push(miner.clone());
                crate::chain_db::persist_pending_vote(&block.hash, &miner);
            }
        }
        votes_cast().insert((miner.clone(), block.height), (block.hash.clone(), self_sig.clone()));
        let self_vote = P2PMessage::BlockVote {
            block_hash: block.hash.clone(),
            height:     block.height,
            voter:      miner.clone(),
            signature:  self_sig,
            timestamp:  chrono::Utc::now().timestamp(),
            vrf_ticket: committee_ticket_hex,
            prev_hash:  block.prev_hash.clone(),
        };
        if let Ok(data) = serde_json::to_vec(&self_vote) {
            publish_gossip("ego-votes-v1", data).await;
        }
    }

    if is_solo {
        bft_solo_commit(&block.hash, block.height);
        eprintln!("[BFT] Solo block #{} committed", block.height);
    } else {
        touch_proposal_timestamp();
        eprintln!("[BFT] Block #{} proposed (miner={}) — awaiting committee votes",
            block.height, &miner[..12.min(miner.len())]);
    }
}

fn bft_solo_commit(block_hash: &str, height: u64) {
    let staged_opt = {
        let mut s = staged_block();
        if s.as_ref().map(|(b, _)| b.hash == block_hash).unwrap_or(false) {
            s.take()
        } else {
            None
        }
    };
    if let Some((b, stamped)) = staged_opt {
        crate::chain_db::commit_staged_block(&b, &stamped);
        crate::chain_db::pipeline_commit(height);
        finalized_at_height().insert(height, block_hash.to_string());
        CONSECUTIVE_EMPTY_VIEWS.store(0, Ordering::Relaxed);
        pending_proposals().remove(&height);
        pending_votes().remove(block_hash);
        for tx in stamped.iter().filter(|t| t.tx_type != "reward" && t.tx_type != "coinbase") {
            crate::commands::tx_pending::remove(&tx.hash);
        }
    }
}

/// Like `propose_block_as_leader` but skips the VRF qualification check.
/// Called by the deterministic liveness fallback after FALLBACK_AFTER_EMPTY_VIEWS
/// consecutive view changes with no block — prevents chain death.
pub async fn propose_block_as_leader_forced() {
    if known_validators().len() < crate::bft_committee::MIN_COMMITTEE_NET { return; }
    let miner = crate::ledger::Ledger::load().address;
    if miner.is_empty() { return; }

    let prev_hash   = crate::chain_db::get_tip_hash();
    let next_height = crate::chain_db::block_count() + 1;

    let seed_bytes = match crate::ledger::load_seed() {
        Some(b) if b.len() == 32 => b,
        _ => return,
    };
    let mut seed_32 = [0u8; 32];
    seed_32.copy_from_slice(&seed_bytes);

    let is_solo = known_validators().len() <= 1;
    let pool = crate::mempool::get_mempool();
    let txs  = pool.drain_all();

    let (poc_ticket, poc_sig) = crate::poc::check_slot_winner(&prev_hash)
        .unwrap_or_else(|| (String::new(), String::new()));
    let poc_slot      = crate::poc::current_slot();
    let combined_ticket = if poc_ticket.is_empty() { String::new() }
                          else { format!("{}:{}", poc_ticket, poc_sig) };

    let (block, stamped) = crate::chain_db::build_block_proposal(&txs, &miner, &combined_ticket, poc_slot);

    {
        let mut staged = staged_block();
        *staged = Some((block.clone(), stamped));
    }

    let sig_data  = format!("proposal:{}:{}", block.hash, block.height);
    let signature = bft_sign(&sig_data).unwrap_or_default();

    let proposal = P2PMessage::BlockProposal {
        block:        block.clone(),
        transactions: txs,
        proposer:     miner.clone(),
        signature,
        vrf_ticket:   String::new(),
    };

    if let Ok(data) = serde_json::to_vec(&proposal) {
        publish_gossip("ego-proposals-v1", data).await;
    }

    let committee_vrf_in = crate::bft_committee::vrf_input(&block.prev_hash, block.height, crate::bft_committee::VRF_ROLE_COMMITTEE);
    let committee_ticket = crate::bft_committee::sign_vrf_ticket(&seed_32, &committee_vrf_in);
    let committee_ticket_hex = hex::encode(&committee_ticket);
    let self_vote_data = crate::bft_committee::vote_signing_data(&block.hash, block.height, &miner);
    if let Some(self_sig) = bft_sign(&self_vote_data) {
        {
            let mut pv = pending_votes();
            let voters = pv.entry(block.hash.clone()).or_default();
            if !voters.contains(&miner) {
                voters.push(miner.clone());
                crate::chain_db::persist_pending_vote(&block.hash, &miner);
            }
        }
        votes_cast().insert((miner.clone(), block.height), (block.hash.clone(), self_sig.clone()));
        let self_vote = P2PMessage::BlockVote {
            block_hash: block.hash.clone(),
            height:     block.height,
            voter:      miner.clone(),
            signature:  self_sig,
            timestamp:  chrono::Utc::now().timestamp(),
            vrf_ticket: committee_ticket_hex,
            prev_hash:  block.prev_hash.clone(),
        };
        if let Ok(data) = serde_json::to_vec(&self_vote) {
            publish_gossip("ego-votes-v1", data).await;
        }
    }

    if is_solo {
        bft_solo_commit(&block.hash, block.height);
        eprintln!("[BFT] Solo fallback block #{} committed", block.height);
    } else {
        touch_proposal_timestamp();
        eprintln!(
            "[BFT] FALLBACK block #{} proposed by highest-DRS node {} — awaiting committee votes",
            next_height, &miner[..12.min(miner.len())]
        );
    }
}

pub async fn run_view_change_monitor() {

    tokio::time::sleep(std::time::Duration::from_secs(15)).await;

    touch_proposal_timestamp();

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(3));
    loop {
        interval.tick().await;

        if known_validators().is_empty() { continue; }

        let now  = chrono::Utc::now().timestamp();
        let last = LAST_PROPOSAL_TS.load(Ordering::Relaxed);
        if last == 0 || now - last < VIEW_CHANGE_TIMEOUT_SECS { continue; }

        let next_view = current_view() + 1;
        let my_addr   = crate::ledger::Ledger::load().address;
        if my_addr.is_empty() { continue; }

        eprintln!("[HotStuff] Proposal timeout — broadcasting ViewChange for view {}", next_view);

        let vote_data = format!("viewchange:{}:{}", next_view, my_addr);
        let sig       = bft_sign(&vote_data).unwrap_or_default();
        let ts        = now;

        let msg = P2PMessage::ViewChange { view: next_view, voter: my_addr.clone(), signature: sig, timestamp: ts };
        if let Ok(data) = serde_json::to_vec(&msg) {
            publish_gossip("ego-viewchange-v1", data).await;
        }

        {
            let mut votes = view_change_votes();
            let voters = votes.entry(next_view).or_default();
            if !voters.contains(&my_addr) {
                voters.push(my_addr.clone());
            }
        }

        touch_proposal_timestamp();
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
    let signature = crate::ledger::load_seed()
        .and_then(|s| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&s[..32]);
            ego_core::KeyPair::from_bytes(&arr).ok()
        })
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

pub async fn fetch_post_challenges(_prover_addr: &str) -> Vec<serde_json::Value> {
    vec![]
}

pub async fn submit_post_proof(_payload: serde_json::Value) -> bool {
    false
}

#[derive(Debug, Clone, Default)]
pub struct CidHolder {
    pub holder_addr: String,
    pub endpoint:    String,
}

pub async fn find_cid_holders(cid: &str) -> Vec<CidHolder> {
    dht_find_cid(cid).await;
    vec![]
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

pub async fn fetch_peers_from_relay(_app: &tauri::AppHandle) {
    dht_discover_peers().await;
}

fn dht_cache_path() -> std::path::PathBuf { base_data_dir().join("dht_cache.json") }

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

pub async fn dht_inbox_deposit(from_addr: &str, to_addr: &str, msg: &P2PMessage) {
    let Ok(value) = serde_json::to_vec(msg) else { return };
    let key = inbox_key(to_addr, from_addr);
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

    let _ = tx.send(DhtCommand::GetPeers {
        key: format!("ego-inbox:{}", hex::encode(blake3::hash(my_addr.as_bytes()).as_bytes())),
    });

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
        eprintln!("[Sharding] Shard {} under-replicated: {}/{} holders",
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

    let shard_id = crate::sharding::shard_for_height(
        block_height, map.total_blocks.max(1), map.shard_count
    );

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

pub async fn get_relay_endpoint(_address: &str) -> Option<String> {
    None
}

#[cfg(target_os = "windows")]
fn ensure_firewall_rule() {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    for (name, proto, port) in [
        (format!("Ego Desktop P2P TCP {}", p2p_port()), "TCP", p2p_port()),
        (format!("Ego Desktop P2P UDP {}", p2p_port()), "UDP", p2p_port()),
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

// ── PoRep spot-check loop (Item 17) ───────────────────────────────────────────

/// Periodically challenges replica peers to prove they still hold the encrypted
/// blocks they committed to.
///
/// Protocol (fully verifiable — no ZK required):
///
///   Challenger (this node) holds the manifest + encrypted blocks on disk.
///   1. Pick a random block from a file where this node is challenger.
///   2. Generate nonce = BLAKE3(prover_addr || block_cid || timestamp_ms).
///      Unpredictable to prover before the challenge is broadcast.
///   3. Compute expected = BLAKE3(nonce || enc_block) locally.
///   4. Broadcast StorageProofChallenge; store (block_cid:nonce) → expected.
///   5. On StorageProofResponse: compare response_hash to expected.
///      Correct → small coverage boost (+5).
///      Wrong   → heavy penalty (-500).
///      Timeout → moderate penalty (-100).
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
                }
            }
        }

        // ── Issue new challenges ──────────────────────────────────────────
        // We only challenge files for which WE have the encrypted blocks on disk
        // (so we can verify the response).  We look for files where:
        //   a) this node uploaded/downloaded them (manifest + blocks present), AND
        //   b) at least one replica_peer (storage provider) exists to challenge.
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

            // Choose a deterministic-but-unpredictable block index per round.
            // round_counter + prover_index makes it different each round.
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

            // Generate nonce: BLAKE3(prover || block_cid || timestamp_ms || counter).
            // This is unpredictable to the prover before the challenge is broadcast
            // because timestamp_ms is only known when we actually send it.
            let nonce_input = format!("porep-challenge:{}:{}:{}:{}", prover, block_cid, now_ms, round_counter);
            let nonce_bytes = *blake3::hash(nonce_input.as_bytes()).as_bytes();
            let nonce_hex   = hex::encode(&nonce_bytes);

            // Compute expected response locally (what a correct prover MUST return).
            let mut hasher = blake3::Hasher::new();
            hasher.update(&nonce_bytes);
            hasher.update(&enc_block);
            let expected_hash = hasher.finalize().to_hex().to_string();

            // Store the expected hash before broadcasting (race-free).
            let challenge_key = format!("{}:{}", block_cid, nonce_hex);
            outstanding_challenges().insert(challenge_key, OutstandingChallenge {
                expected_hash,
                prover: prover.clone(),
                issued_at_ms: now_ms,
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
