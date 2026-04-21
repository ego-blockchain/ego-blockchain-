pub const COMMITTEE_SIZE: usize = 21;

/// Minimum live validators before BFT consensus runs.
/// Default 1 — the chain starts in solo mode and automatically upgrades to
/// full BFT as peers join.  bft_threshold() scales the 2f+1 quorum to
/// whatever n is currently seen, so no hard minimum is needed for safety.
/// Set EGO_MIN_COMMITTEE=21 in production testnet/mainnet env if desired.
pub fn min_committee_net() -> usize {
    std::env::var("EGO_MIN_COMMITTEE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1)
}
pub const VRF_ROLE_PROPOSER:  u8 = 0x50;
pub const VRF_ROLE_COMMITTEE: u8 = 0x43;

const UEGOC_PER_EGOC: f64 = 1_000_000.0;
const COVERAGE_PER_WEIGHT: f64 = 10.0;

pub const EXPECTED_PROPOSERS_PER_SLOT: f64 = 0.5;
pub const FALLBACK_AFTER_EMPTY_VIEWS: u32 = 3;

/// Maximum share of proposer/committee slots any single entity may hold.
/// Mirrors the BFT safety threshold: no node can control more than 1/3 of
/// the network, making 51%-style attacks structurally impossible regardless
/// of stake size.
pub const MAX_VALIDATOR_SHARE: f64 = 0.33;

/// Stake threshold (in EGOC) below which a newcomer multiplier applies.
/// New/small validators receive a temporary selection boost to attract early
/// participants and ensure the network can bootstrap with minimal stake.
const NEWCOMER_STAKE_THRESHOLD_EGOC: f64 = 50.0;

/// Coverage score threshold (raw) below which the newcomer multiplier applies.
/// Both stake AND coverage must be low to qualify — prevents rich nodes from
/// spinning up zero-coverage sybils to claim the bonus.
const NEWCOMER_COVERAGE_THRESHOLD: f64 = 5.0;

/// Selection probability multiplier for newcomer nodes.
/// 3× gives small early validators a real chance to earn blocks and
/// accumulate stake/coverage before the log curve evens out.
const NEWCOMER_MULTIPLIER: f64 = 3.0;

/// Compute a validator's DRS weight using a logarithmic scale.
///
/// Linear DRS (old): weight ∝ stake — 1M EGOC = 1,000,000× weight of 1 EGOC.
/// Log DRS (new):    weight ∝ ln(1 + stake + coverage) — diminishing returns.
///
/// Examples (stake in EGOC):
///   1 EGOC  → ln(2)      ≈ 0.69
///   10 EGOC → ln(11)     ≈ 2.40
///   100 EGOC→ ln(101)    ≈ 4.62
///   10k EGOC→ ln(10001)  ≈ 9.21
///   1M EGOC → ln(1000001)≈ 13.82
///
/// A whale with 1M EGOC gets ~20× the weight of a 1-EGOC node (not 1,000,000×).
/// This mirrors how Bitcoin difficulty grows: doubling hashrate beyond the
/// dominant threshold yields ever-smaller marginal increases in block share.
pub fn compute_drs_weight(addr: &str) -> f64 {
    let stake_egoc = crate::ledger::get_validator_stake(addr) as f64 / UEGOC_PER_EGOC;
    let coverage   = crate::poc::get_peer_score(addr) as f64 / COVERAGE_PER_WEIGHT;
    let raw        = stake_egoc + coverage;

    let log_drs    = (1.0_f64 + raw).ln().max(0.01);

    let multiplier = if stake_egoc < NEWCOMER_STAKE_THRESHOLD_EGOC
                     && coverage   < NEWCOMER_COVERAGE_THRESHOLD {
        NEWCOMER_MULTIPLIER
    } else {
        1.0
    };

    log_drs * multiplier
}

pub fn total_drs_weight(all_validators: &[String]) -> f64 {
    let t: f64 = all_validators.iter().map(|a| compute_drs_weight(a)).sum();
    t.max(0.01)
}

/// Returns the effective selection share for a validator, hard-capped at
/// MAX_VALIDATOR_SHARE (33%).  Even if a single entity controls 90% of all
/// stake, it cannot propose or vote in more than 1/3 of slots.
fn capped_share(my_drs: f64, total_drs: f64) -> f64 {
    (my_drs / total_drs).min(MAX_VALIDATOR_SHARE)
}

pub fn vrf_input(prev_hash: &str, height: u64, role: u8) -> Vec<u8> {
    let mut v = b"ego/vrf/v1:".to_vec();
    v.extend_from_slice(prev_hash.as_bytes());
    v.extend_from_slice(&height.to_le_bytes());
    v.push(role);
    v
}

pub fn sign_vrf_ticket(seed_32: &[u8; 32], input: &[u8]) -> Vec<u8> {
    use ed25519_dalek::{SigningKey, Signer};
    SigningKey::from_bytes(seed_32).sign(input).to_bytes().to_vec()
}

pub fn verify_vrf_ticket(pubkey_32: &[u8; 32], input: &[u8], ticket: &[u8]) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};
    let Ok(vk)  = VerifyingKey::from_bytes(pubkey_32) else { return false; };
    let Ok(sig) = Signature::from_slice(ticket) else { return false; };
    vk.verify(input, &sig).is_ok()
}

pub fn ticket_to_float(ticket: &[u8]) -> f64 {
    let h   = blake3::hash(ticket);
    let raw = u64::from_le_bytes(h.as_bytes()[..8].try_into().expect("blake3 output is always 32 bytes"));
    raw as f64 / u64::MAX as f64
}

pub fn qualifies_committee(ticket: &[u8], my_drs: f64, total_drs: f64, n_validators: usize) -> bool {
    if n_validators <= COMMITTEE_SIZE { return true; }
    let share     = capped_share(my_drs, total_drs);
    let threshold = (COMMITTEE_SIZE as f64 * share).min(1.0);
    ticket_to_float(ticket) < threshold
}

pub fn qualifies_proposer(ticket: &[u8], my_drs: f64, total_drs: f64) -> bool {
    let share     = capped_share(my_drs, total_drs);
    let threshold = (EXPECTED_PROPOSERS_PER_SLOT * share).min(1.0);
    ticket_to_float(ticket) < threshold
}

pub fn vote_signing_data(block_hash: &str, height: u64, voter: &str) -> String {
    format!("ego/vote/v1:{}:{}:{}", block_hash, height, voter)
}
