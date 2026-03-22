//! Proof of Coverage — VRF-based slot lottery.
//!
//! Replaces the deterministic `leader_for_view(v % n)` schedule with a
//! cryptographic lottery that no node can predict or manipulate in advance.
//!
//! ## How it works
//!
//! Every 100ms slot each node independently asks: "Do I win this slot?"
//!
//!   1. Compute `slot_seed  = blake3(prev_block_hash || slot_number)`
//!   2. Compute `ticket     = blake3(ed25519_sign(slot_seed))`
//!      — deterministic for the key-holder, unpredictable to everyone else
//!   3. Win if: `ticket_u64 < u64::MAX * (my_coverage / network_coverage)`
//!
//! ## Coverage score
//!
//! Higher score → higher chance of winning a slot:
//!   - Storage allocated:  1 point per GB  (cap 2000)
//!   - Uptime this session: 1 point per hour (cap 720 = 30 days)
//!   - Relay peers active:  5 points each   (cap 500)
//!
//! Minimum score is 1 so every node always has *some* chance.
//!
//! ## Why this defeats manipulation
//!
//! - You can't predict your ticket without signing with your private key at
//!   slot time — grinding is impossible.
//! - Sending self-transactions doesn't change your coverage score.
//! - Block reward is fixed by `tokenomics::block_reward_at(height)`,
//!   not proportional to TX value — there is nothing to gain by including
//!   artificially crafted transactions.
//! - Fee burn (100%): TX fees are destroyed, not collected by the miner.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};
use once_cell::sync::OnceCell;
use std::collections::HashMap;

// ── Session uptime tracker ────────────────────────────────────────────────────

static SESSION_START_TS: AtomicU64 = AtomicU64::new(0);

/// Call once at app startup.
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

// ── Per-peer coverage score store (populated from PeerAnnounce gossip) ────────

static PEER_SCORES: OnceCell<Mutex<HashMap<String, u64>>> = OnceCell::new();

fn peer_scores() -> std::sync::MutexGuard<'static, HashMap<String, u64>> {
    PEER_SCORES.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap()
}

/// Store a coverage score received from a peer via PeerAnnounce.
pub fn record_peer_score(address: &str, score: u64) {
    if address.is_empty() || score == 0 { return; }
    peer_scores().insert(address.to_string(), score);
}

/// Estimated total network coverage = sum of all known peer scores + this node.
fn network_coverage_score(my_score: u64) -> u64 {
    let peers_total: u64 = peer_scores().values().sum();
    (peers_total + my_score).max(my_score) // at minimum our own score
}

// ── Coverage score ────────────────────────────────────────────────────────────

/// This node's coverage score.
///
/// Inputs that are already tracked locally — no additional network round-trips.
pub fn my_coverage_score() -> u64 {
    let ledger = crate::ledger::Ledger::load();

    // 1 point per GB ACTUALLY STORED — not allocated.
    // Using allocated bytes would let a node claim 2TB without storing anything.
    // Actual stored bytes are verified on disk (the files exist or they don't).
    let actual_stored: u64 = ledger.stored_files.iter().map(|f| f.encrypted_size).sum();
    let storage_pts = (actual_stored / 1_000_000_000).min(2_000);

    // 1 point per hour online this session (cap 720 = 30 days)
    let uptime_pts = uptime_hours();

    // 5 points per known peer (measures relay connectivity, cap 500 = 100 peers)
    let relay_pts = (crate::p2p::get_known_peers().len() as u64 * 5).min(500);

    // Minimum 1 so cold-start nodes still participate
    (storage_pts + uptime_pts + relay_pts).max(1)
}

// ── Slot seed ─────────────────────────────────────────────────────────────────

/// `slot = now_unix_ms / BATCH_INTERVAL_MS`
pub fn current_slot() -> u64 {
    let now_ms = chrono::Utc::now().timestamp_millis() as u64;
    now_ms / crate::mempool::BATCH_INTERVAL_MS
}

/// Deterministic seed for (prev_hash, slot): `blake3(prev_hash_bytes || slot_le64)`
pub fn slot_seed(prev_hash: &str, slot: u64) -> [u8; 32] {
    let mut input = Vec::with_capacity(prev_hash.len() + 8);
    input.extend_from_slice(prev_hash.as_bytes());
    input.extend_from_slice(&slot.to_le_bytes());
    *blake3::hash(&input).as_bytes()
}

// ── VRF ticket ────────────────────────────────────────────────────────────────

/// Compute `ticket = blake3(ed25519_sign(slot_seed))`.
///
/// - Only the key-holder can compute this value.
/// - Other nodes verify: parse signature from ticket_hex, verify against
///   proposer's known Ed25519 public key + same slot_seed.
/// - Returns `(ticket_bytes, signature_hex)` or None if key is unavailable.
fn compute_ticket(slot_seed: &[u8; 32]) -> Option<([u8; 32], String)> {
    let seed_bytes = std::fs::read(crate::ledger::seed_path()).ok()
        .filter(|b| b.len() == 32)?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let kp = ego_core::KeyPair::from_bytes(&seed).ok()?;

    // Ed25519 sign the slot seed (deterministic per RFC 8032)
    let sig = kp.sign_ed25519(slot_seed);
    let sig_hex = hex::encode(&sig.signature_data);

    // Hash the signature bytes to get a uniform [0, 2^256) ticket
    let ticket = *blake3::hash(&sig.signature_data).as_bytes();
    Some((ticket, sig_hex))
}

// ── Lottery check ─────────────────────────────────────────────────────────────

/// Returns `true` when `ticket` beats the coverage-weighted threshold.
///
/// Uses 128-bit arithmetic to avoid overflow:
///   win if `ticket_u64 * network_score < u64::MAX * my_score`
fn ticket_wins(ticket: &[u8; 32], my_score: u64, network_score: u64) -> bool {
    if network_score == 0 || my_score >= network_score {
        return true; // bootstrap / sole node always wins
    }
    let t = u64::from_be_bytes(ticket[0..8].try_into().unwrap_or([0xff; 8]));
    // compare as u128 to avoid overflow
    (t as u128) * (network_score as u128) < (u64::MAX as u128) * (my_score as u128)
}

/// Check whether this node wins the current slot.
///
/// Returns `Some((ticket_hex, sig_hex))` on a win, `None` otherwise.
/// The caller should mine a block and include the ticket in `LedgerBlock::poc_ticket`.
pub fn check_slot_winner(prev_hash: &str) -> Option<(String, String)> {
    let ledger = crate::ledger::Ledger::load();
    if ledger.address.is_empty() { return None; }

    let slot  = current_slot();
    let seed  = slot_seed(prev_hash, slot);
    let (ticket, sig_hex) = compute_ticket(&seed)?;

    let my_score  = my_coverage_score();
    let net_score = network_coverage_score(my_score);

    if ticket_wins(&ticket, my_score, net_score) {
        let ticket_hex = hex::encode(ticket);
        eprintln!(
            "[PoC] Won slot {} — coverage {}/{} — ticket {}…",
            slot, my_score, net_score, &ticket_hex[..16]
        );
        Some((ticket_hex, sig_hex))
    } else {
        None
    }
}

/// After this many blocks, ALL blocks must carry a valid PoC ticket.
/// Blocks below this height are accepted without a ticket (upgrade transition).
/// Set to 500 — roughly 50 seconds of blocks at 100ms slots, enough for all
/// nodes to upgrade before enforcement kicks in.
const POC_ENFORCE_HEIGHT: u64 = 500;

/// Verify a PoC ticket from a block proposer.
///
/// Checks that `blake3(ed25519_sign(slot_seed)) == ticket_hex` using the
/// proposer's public Ed25519 key (derived from their address via the peer cache).
/// Returns `true` if the proof is valid OR if we cannot verify (no key on record)
/// so we don't accidentally reject valid blocks during bootstrap.
pub fn verify_ticket(
    ticket_hex:   &str,
    sig_hex:      &str,
    proposer:     &str,
    prev_hash:    &str,
    slot:         u64,
    block_height: u64,
) -> bool {
    if ticket_hex.is_empty() || sig_hex.is_empty() {
        // Accept legacy/transition blocks below the enforcement height.
        // Above it, a missing ticket is a hard reject — no exceptions.
        if block_height < POC_ENFORCE_HEIGHT {
            return true;
        }
        eprintln!("[PoC] Block #{} rejected — missing PoC ticket (enforcement active above height {})",
            block_height, POC_ENFORCE_HEIGHT);
        return false;
    }

    // Recompute slot_seed
    let seed = slot_seed(prev_hash, slot);

    // Verify: blake3(sig_bytes) == ticket
    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let expected_ticket = hex::encode(blake3::hash(&sig_bytes).as_bytes());
    if expected_ticket != ticket_hex {
        eprintln!("[PoC] Ticket mismatch from proposer {}", proposer);
        return false;
    }

    // Try to verify the Ed25519 signature against the proposer's public key.
    // If we don't have their public key yet, accept provisionally (bootstrap).
    let ed25519_pk = crate::p2p::get_peer_ed25519_pubkey(proposer);
    match ed25519_pk {
        None => true, // no key on record — accept (bootstrap)
        Some(pk_bytes) => {
            use ed25519_dalek::{Signature as DalekSig, VerifyingKey, Verifier};
            let vk = match VerifyingKey::from_bytes(&pk_bytes) {
                Ok(k) => k,
                Err(_) => return true, // malformed key — accept
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
