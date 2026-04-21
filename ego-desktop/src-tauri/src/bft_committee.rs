pub const COMMITTEE_SIZE: usize = 21;


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


pub const MAX_VALIDATOR_SHARE: f64 = 0.33;


const NEWCOMER_STAKE_THRESHOLD_EGOC: f64 = 50.0;


const NEWCOMER_COVERAGE_THRESHOLD: f64 = 5.0;


const NEWCOMER_MULTIPLIER: f64 = 3.0;


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
