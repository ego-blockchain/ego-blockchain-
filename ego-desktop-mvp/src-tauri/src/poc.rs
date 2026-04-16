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

    let actual_stored: u64 = ledger.stored_files.iter().map(|f| f.encrypted_size).sum();
    let storage_pts = (actual_stored / 1_000_000_000).min(2_000);

    let uptime_pts = uptime_hours();

    let relay_pts = (crate::p2p::get_known_peers().len() as u64 * 5).min(500);

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
    let seed_bytes = crate::ledger::load_seed()?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let kp = ego_core::KeyPair::from_bytes(&seed).ok()?;

    let sig = kp.sign_ed25519(slot_seed);
    let sig_hex = hex::encode(&sig.signature_data);

    let ticket = *blake3::hash(&sig.signature_data).as_bytes();
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

    // ── DRS-weighted lottery (same metric as BFT proposer election) ──────────
    // Previously used coverage-only weights, which diverged from the BFT VRF
    // (which uses DRS = stake + coverage).  Using DRS here ensures the PoC
    // ticket lottery and the BFT consensus lottery agree on who is eligible.
    let all_validators = crate::p2p::get_known_validators_snapshot();
    let my_drs    = crate::bft_committee::compute_drs_weight(&ledger.address);
    let total_drs = if all_validators.is_empty() {
        // No peers known yet (bootstrap) — use coverage-only fallback so
        // the genesis node can still produce blocks.
        let my_score = my_coverage_score();
        my_score as f64 / 10.0 // same COVERAGE_PER_WEIGHT as bft_committee
    } else {
        crate::bft_committee::total_drs_weight(&all_validators)
    };

    if crate::bft_committee::qualifies_proposer(&ticket, my_drs, total_drs) {
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

const POC_ENFORCE_HEIGHT: u64 = 10_000;

pub fn verify_ticket(
    ticket_hex:   &str,
    sig_hex:      &str,
    proposer:     &str,
    prev_hash:    &str,
    slot:         u64,
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

    let seed = slot_seed(prev_hash, slot);

    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let expected_ticket = hex::encode(blake3::hash(&sig_bytes).as_bytes());
    if expected_ticket != ticket_hex {
        eprintln!("[PoC] Ticket mismatch from proposer {}", proposer);
        return false;
    }

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
                Err(_) => return true,
            };
            let sig_arr: [u8; 64] = match sig_bytes.try_into() {
                Ok(a) => a,
                Err(_) => return false,
            };
            let dalek_sig = DalekSig::from_bytes(&sig_arr);
            vk.verify(&seed, &dalek_sig).is_ok()
        }
    }
}
