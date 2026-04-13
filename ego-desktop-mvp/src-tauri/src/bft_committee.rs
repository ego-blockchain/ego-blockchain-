pub const COMMITTEE_SIZE: usize = 21;
pub const MIN_COMMITTEE_NET: usize = 3;
pub const VRF_ROLE_PROPOSER:  u8 = 0x50;
pub const VRF_ROLE_COMMITTEE: u8 = 0x43;

const UEGOC_PER_EGOC: f64 = 1_000_000.0;
const COVERAGE_PER_WEIGHT: f64 = 10.0;


pub const EXPECTED_PROPOSERS_PER_SLOT: f64 = 2.0;


pub const FALLBACK_AFTER_EMPTY_VIEWS: u32 = 3;

pub fn compute_drs_weight(addr: &str) -> f64 {
    let stake    = crate::ledger::get_validator_stake(addr) as f64 / UEGOC_PER_EGOC;
    let coverage = crate::poc::get_peer_score(addr) as f64 / COVERAGE_PER_WEIGHT;
    (stake + coverage).max(0.01)
}

pub fn total_drs_weight(all_validators: &[String]) -> f64 {
    let t: f64 = all_validators.iter().map(|a| compute_drs_weight(a)).sum();
    t.max(0.01)
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

pub fn qualifies_committee(ticket: &[u8], my_drs: f64, total_drs: f64) -> bool {
    let threshold = (COMMITTEE_SIZE as f64 * my_drs / total_drs).min(1.0);
    ticket_to_float(ticket) < threshold
}

pub fn qualifies_proposer(ticket: &[u8], my_drs: f64, total_drs: f64) -> bool {
    let threshold = (EXPECTED_PROPOSERS_PER_SLOT * my_drs / total_drs).min(1.0);
    ticket_to_float(ticket) < threshold
}

pub fn vote_signing_data(block_hash: &str, height: u64, voter: &str) -> String {
    format!("ego/vote/v1:{}:{}:{}", block_hash, height, voter)
}
