use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};
use once_cell::sync::OnceCell;
use std::collections::HashMap;

static SESSION_START_TS: AtomicU64 = AtomicU64::new(0);

pub fn init_session_start() {
    let now = chrono::Utc::now().timestamp() as u64;
    SESSION_START_TS.compare_exchange(0, now, Ordering::Relaxed, Ordering::Relaxed).ok();
}

fn uptime_hours() -> u64 {
    let start = SESSION_START_TS.load(Ordering::Relaxed);
    if start == 0 { return 0; }
    let now = chrono::Utc::now().timestamp() as u64;
    (now.saturating_sub(start) / 3600).min(720)
}

static PEER_SCORES: OnceCell<Mutex<HashMap<String, u64>>> = OnceCell::new();

const MAX_PEER_SCORES: usize = 50_000;

fn peer_scores() -> std::sync::MutexGuard<'static, HashMap<String, u64>> {
    PEER_SCORES.get_or_init(|| Mutex::new(HashMap::new())).lock().expect("peer_scores lock poisoned")
}

/// Get the last known coverage score for a peer address.
pub fn get_peer_score(addr: &str) -> u64 {
    peer_scores().get(addr).copied().unwrap_or(0)
}

pub const MAX_COVERAGE_SCORE: u64 = 3_220; // 2000 storage + 720 uptime + 500 relay

pub fn seed_peer_score_from_stake(addr: &str) {
    if addr.is_empty() || get_peer_score(addr) > 0 { return; }
    let stake = crate::ledger::get_validator_stake(addr);
    if stake == 0 { return; }
    let per_10_egoc = stake / (crate::tokenomics::UEGOC_PER_EGOC * 10);
    let base = per_10_egoc.min(100).max(1);
    record_peer_score(addr, base);
}

pub fn record_peer_score(address: &str, score: u64) {
    if address.is_empty() || score == 0 { return; }
    let capped = score.min(MAX_COVERAGE_SCORE);
    let mut map = peer_scores();
    if map.len() >= MAX_PEER_SCORES && !map.contains_key(address) {
        if let Some(min_key) = map.iter().min_by_key(|(_, v)| *v).map(|(k, _)| k.clone()) {
            map.remove(&min_key);
        }
    }
    map.insert(address.to_string(), capped);
}

/// Estimated total network coverage = sum of all known peer scores + this node.
fn network_coverage_score(my_score: u64) -> u64 {
    let peers_total: u64 = peer_scores().values().sum();
    (peers_total + my_score).max(my_score) // at minimum our own score
}

// ── Coverage score ────────────────────────────────────────────────────────────

/// This node's coverage score.

pub fn my_coverage_score() -> u64 {
    let ledger = crate::ledger::Ledger::load();

    // Oracle-reported score for this node takes precedence — it is externally
    // verified and not self-inflatable. Fall back to local estimate only when
    // the oracle has never reported a score (e.g. brand-new node).
    if !ledger.address.is_empty() {
        let oracle_score = get_peer_score(&ledger.address);
        if oracle_score > 0 {
            return oracle_score.min(MAX_COVERAGE_SCORE);
        }
    }

    let actual_stored: u64 = ledger.stored_files.iter().map(|f| f.encrypted_size).sum();
    let storage_pts = (actual_stored / 1_000_000_000).min(2_000);
    let uptime_pts  = uptime_hours();
    let relay_pts   = (crate::p2p::get_known_peers().len() as u64 * 5).min(500);

    (storage_pts + uptime_pts + relay_pts).max(1)
}

pub fn current_slot() -> u64 {
    let now_ms = chrono::Utc::now().timestamp_millis() as u64;
    now_ms / crate::mempool::BATCH_INTERVAL_MS
}

pub fn slot_seed(prev_hash: &str, slot: u64) -> [u8; 32] {
    let mut input = Vec::with_capacity(prev_hash.len() + 8);
    input.extend_from_slice(prev_hash.as_bytes());
    input.extend_from_slice(&slot.to_le_bytes());
    *blake3::hash(&input).as_bytes()
}

fn compute_ticket(slot_seed: &[u8; 32]) -> Option<([u8; 32], String)> {
    if let Some(kp) = crate::app::global_app_state().get_keypair() {
        let sig = kp.sign_ed25519(slot_seed);
        let sig_hex = hex::encode(sig.as_bytes());
        let ticket = *blake3::hash(sig.as_bytes()).as_bytes();
        return Some((ticket, sig_hex));
    }

    let seed = crate::p2p::get_ed25519_seed()?;

    use ed25519_dalek::{Signer, SigningKey};
    let sig = SigningKey::from_bytes(&seed).sign(slot_seed);
    let sig_bytes = sig.to_bytes();
    let sig_hex = hex::encode(sig_bytes);
    let ticket = *blake3::hash(&sig_bytes).as_bytes();
    Some((ticket, sig_hex))
}

fn ticket_wins(ticket: &[u8; 32], my_score: u64, network_score: u64) -> bool {
    if network_score == 0 || my_score >= network_score {
        return true;
    }
    let t = u64::from_be_bytes(ticket[0..8].try_into().unwrap_or([0xff; 8]));

    (t as u128) * (network_score as u128) < (u64::MAX as u128) * (my_score as u128)
}

pub fn check_slot_winner(prev_hash: &str) -> Option<(String, String)> {
    let ledger = crate::ledger::Ledger::load();
    if ledger.address.is_empty() { return None; }

    let slot = current_slot();
    let seed = slot_seed(prev_hash, slot);

    let (ticket, sig_hex) = compute_ticket(&seed)?;


    let all_validators = crate::p2p::get_known_validators_snapshot();

    if all_validators.is_empty() {
        let ticket_hex = hex::encode(ticket);
        eprintln!("[PoC] Solo slot {} — ticket {}…", slot, &ticket_hex[..16]);
        return Some((ticket_hex, sig_hex));
    }

    let my_drs    = crate::bft_committee::compute_drs_weight(&ledger.address);
    let total_drs = crate::bft_committee::total_drs_weight(&all_validators);

    if crate::bft_committee::qualifies_proposer_for_network(
        &ticket,
        my_drs,
        total_drs,
        all_validators.len(),
    ) {
        let ticket_hex = hex::encode(ticket);
        eprintln!(
            "[PoC] Won slot {} — DRS {:.2}/{:.2} — ticket {}…",
            slot, my_drs, total_drs, &ticket_hex[..16]
        );
        Some((ticket_hex, sig_hex))
    } else {
        None
    }
}

pub const POC_EPOCH_SECS: i64 = 240;
pub const POC_BEACON_FRESH_SECS: i64 = 120;
pub const POC_MAX_WITNESSES: usize = 22;
const POC_WITNESSED_EPOCHS_CAP: usize = 10_000;

#[derive(Debug, Clone)]
pub struct PocWitnessRecord {
    pub witness:    String,
    pub machine_id: String,
    pub cell:       String,
    pub latency_ms: u32,
    pub timestamp:  i64,
    pub signature:  String,
}

static ACTIVE_BEACON: OnceCell<Mutex<Option<(String, i64)>>> = OnceCell::new();
static BEACON_WITNESSES: OnceCell<Mutex<HashMap<String, PocWitnessRecord>>> = OnceCell::new();
static WITNESSED_EPOCHS: OnceCell<Mutex<HashMap<String, u64>>> = OnceCell::new();

fn active_beacon() -> std::sync::MutexGuard<'static, Option<(String, i64)>> {
    ACTIVE_BEACON.get_or_init(|| Mutex::new(None)).lock().expect("active_beacon lock poisoned")
}

fn beacon_witnesses() -> std::sync::MutexGuard<'static, HashMap<String, PocWitnessRecord>> {
    BEACON_WITNESSES.get_or_init(|| Mutex::new(HashMap::new())).lock().expect("beacon_witnesses lock poisoned")
}

fn witnessed_epochs() -> std::sync::MutexGuard<'static, HashMap<String, u64>> {
    WITNESSED_EPOCHS.get_or_init(|| Mutex::new(HashMap::new())).lock().expect("witnessed_epochs lock poisoned")
}

pub fn poc_epoch(ts: i64) -> u64 {
    (ts / POC_EPOCH_SECS).max(0) as u64
}

pub fn poc_same_machine_allowed() -> bool {
    std::env::var("EGO_POC_SAME_MACHINE").map(|v| v == "1").unwrap_or(false)
}

pub fn beacon_signing_bytes(
    beacon_id: &str, address: &str, machine_id: &str,
    cell: &str, epoch: u64, timestamp: i64, transport: &str,
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"ego/poc-beacon/v1:");
    v.extend_from_slice(beacon_id.as_bytes());   v.push(b':');
    v.extend_from_slice(address.as_bytes());     v.push(b':');
    v.extend_from_slice(machine_id.as_bytes());  v.push(b':');
    v.extend_from_slice(cell.as_bytes());        v.push(b':');
    v.extend_from_slice(&epoch.to_le_bytes());   v.push(b':');
    v.extend_from_slice(&timestamp.to_le_bytes()); v.push(b':');
    v.extend_from_slice(transport.as_bytes());
    v
}

pub fn witness_signing_bytes(
    beacon_id: &str, beaconer: &str, witness: &str, witness_machine_id: &str,
    witness_cell: &str, latency_ms: u32, rssi_dbm: i32, timestamp: i64,
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"ego/poc-witness/v1:");
    v.extend_from_slice(beacon_id.as_bytes());          v.push(b':');
    v.extend_from_slice(beaconer.as_bytes());           v.push(b':');
    v.extend_from_slice(witness.as_bytes());            v.push(b':');
    v.extend_from_slice(witness_machine_id.as_bytes()); v.push(b':');
    v.extend_from_slice(witness_cell.as_bytes());       v.push(b':');
    v.extend_from_slice(&latency_ms.to_le_bytes());     v.push(b':');
    v.extend_from_slice(&rssi_dbm.to_le_bytes());       v.push(b':');
    v.extend_from_slice(&timestamp.to_le_bytes());
    v
}

pub fn sign_with_node_key(bytes: &[u8]) -> Option<String> {
    if let Some(kp) = crate::app::global_app_state().get_keypair() {
        return Some(hex::encode(kp.sign_ed25519(bytes).as_bytes()));
    }
    let seed = crate::p2p::get_ed25519_seed()?;
    use ed25519_dalek::{Signer, SigningKey};
    let sig = SigningKey::from_bytes(&seed).sign(bytes);
    Some(hex::encode(sig.to_bytes()))
}

pub fn verify_peer_sig(address: &str, bytes: &[u8], sig_hex: &str) -> bool {
    let Some(pk_bytes) = crate::p2p::get_peer_ed25519_pubkey(address) else { return false; };
    use ed25519_dalek::{Signature as DalekSig, Verifier, VerifyingKey};
    let Ok(vk) = VerifyingKey::from_bytes(&pk_bytes) else { return false; };
    let Ok(sig_raw) = hex::decode(sig_hex) else { return false; };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_raw.as_slice()) else { return false; };
    vk.verify(bytes, &DalekSig::from_bytes(&sig_arr)).is_ok()
}

pub fn start_beacon(beacon_id: &str, timestamp: i64) {
    *active_beacon() = Some((beacon_id.to_string(), timestamp));
    beacon_witnesses().clear();
}

pub fn current_beacon() -> Option<(String, i64)> {
    active_beacon().clone()
}

pub fn add_witness(beacon_id: &str, record: PocWitnessRecord) -> bool {
    let matches_active = active_beacon()
        .as_ref()
        .map(|(id, _)| id == beacon_id)
        .unwrap_or(false);
    if !matches_active { return false; }
    let mut w = beacon_witnesses();
    if w.len() >= POC_MAX_WITNESSES && !w.contains_key(&record.witness) { return false; }
    w.insert(record.witness.clone(), record);
    true
}

pub fn take_beacon_older_than(cutoff_ts: i64) -> Option<(String, Vec<PocWitnessRecord>)> {
    let mut active = active_beacon();
    match active.as_ref() {
        Some((_, sent)) if *sent <= cutoff_ts => {}
        _ => return None,
    }
    let (id, _) = active.take().unwrap();
    let records: Vec<PocWitnessRecord> = beacon_witnesses().drain().map(|(_, r)| r).collect();
    Some((id, records))
}

pub fn should_witness(beaconer: &str, epoch: u64) -> bool {
    let mut map = witnessed_epochs();
    if map.get(beaconer).copied() == Some(epoch) { return false; }
    if map.len() >= POC_WITNESSED_EPOCHS_CAP && !map.contains_key(beaconer) {
        map.retain(|_, e| *e + 2 >= epoch);
        if map.len() >= POC_WITNESSED_EPOCHS_CAP { return false; }
    }
    map.insert(beaconer.to_string(), epoch);
    true
}

const POC_ENFORCE_HEIGHT: u64 = 100_000;

pub fn verify_ticket(
    ticket_hex:   &str,
    sig_hex:      &str,
    proposer:     &str,
    prev_hash:    &str,
    poc_slot:         u64,
    block_height: u64,
) -> bool {
    if ticket_hex.is_empty() || sig_hex.is_empty() {

        if block_height < POC_ENFORCE_HEIGHT {
            return true;
        }
        eprintln!("[PoC] Block #{} rejected — missing PoC ticket (enforcement active above height {})",
            block_height, POC_ENFORCE_HEIGHT);
        return false;
    }

    let seed = slot_seed(prev_hash, poc_slot);

    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let expected_ticket = hex::encode(blake3::hash(&sig_bytes).as_bytes());
    if expected_ticket != ticket_hex {
        eprintln!("[PoC] Ticket mismatch from proposer {}", proposer);
        return false;
    }
    let ticket_bytes: [u8; 32] = match hex::decode(ticket_hex).ok().and_then(|b| b.try_into().ok()) {
        Some(bytes) => bytes,
        None => return false,
    };

    let ed25519_pk = crate::p2p::get_peer_ed25519_pubkey(proposer);
    match ed25519_pk {
        None => {

            if block_height < POC_ENFORCE_HEIGHT {
                return true;
            }
            eprintln!("[PoC] Block #{} rejected — unknown proposer {} (pubkey not in peer cache)", block_height, proposer);
            return false;
        }
        Some(pk_bytes) => {
            use ed25519_dalek::{Signature as DalekSig, VerifyingKey, Verifier};
            let vk = match VerifyingKey::from_bytes(&pk_bytes) {
                Ok(k) => k,
                Err(_) => return false,
            };
            let sig_arr: [u8; 64] = match sig_bytes.try_into() {
                Ok(a) => a,
                Err(_) => return false,
            };
            let dalek_sig = DalekSig::from_bytes(&sig_arr);
            if vk.verify(&seed, &dalek_sig).is_err() {
                return false;
            }
            let _ = ticket_bytes;
            true
        }
    }
}
