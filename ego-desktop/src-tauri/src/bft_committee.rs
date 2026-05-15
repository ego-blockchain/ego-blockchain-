
pub const COMMITTEE_SIZE: usize = 21;

pub const MAX_COMMITTEE_SIZE: usize = 150;


pub const MIN_LIVE_VALIDATORS: usize = 2;


pub fn min_committee_net() -> usize {
    std::env::var("EGO_MIN_COMMITTEE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(MIN_LIVE_VALIDATORS)
}
pub const VRF_ROLE_PROPOSER:  u8 = 0x50;
pub const VRF_ROLE_COMMITTEE: u8 = 0x43;

const UEGOC_PER_EGOC: f64 = 1_000_000.0;
const COVERAGE_PER_WEIGHT: f64 = 10.0;

pub const EXPECTED_PROPOSERS_PER_SLOT: f64 = 1.5;

pub fn expected_proposers_for_network(n: usize) -> f64 {

    let n_f = n.max(1) as f64;
    (1.5 + 6.0 / n_f).min(n_f)
}
pub const FALLBACK_AFTER_EMPTY_VIEWS: u32 = 2;


pub const MAX_VALIDATOR_SHARE: f64 = 0.33;


const NEWCOMER_STAKE_THRESHOLD_EGOC: f64 = 50.0;


const NEWCOMER_COVERAGE_THRESHOLD: f64 = 5.0;


const NEWCOMER_MULTIPLIER: f64 = 3.0;


pub fn compute_drs_weight(addr: &str) -> f64 {
    let stake_egoc = crate::ledger::get_validator_stake(addr) as f64 / UEGOC_PER_EGOC;
    let coverage   = crate::poc::get_peer_score(addr) as f64 / COVERAGE_PER_WEIGHT;
    // Coverage & storage contribution is the primary signal (3×).
    // Staking is a secondary optional boost (0.5×).
    let raw        = coverage * 3.0 + stake_egoc * 0.5;

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
    crate::ecvrf::ecvrf_prove(seed_32, input)
        .map(|p| p.to_vec())
        .unwrap_or_else(|| {
            use ed25519_dalek::{SigningKey, Signer};
            SigningKey::from_bytes(seed_32).sign(input).to_bytes().to_vec()
        })
}

pub fn verify_vrf_ticket(pubkey_32: &[u8; 32], input: &[u8], ticket: &[u8]) -> bool {
    if ticket.len() == 80 {
        crate::ecvrf::ecvrf_verify(pubkey_32, input, ticket)
    } else {
        use ed25519_dalek::{Signature, VerifyingKey, Verifier};
        let Ok(vk)  = VerifyingKey::from_bytes(pubkey_32) else { return false; };
        let Ok(sig) = Signature::from_slice(ticket) else { return false; };
        vk.verify(input, &sig).is_ok()
    }
}

pub fn ticket_to_float(ticket: &[u8]) -> f64 {
    let hash_bytes = if ticket.len() == 80 {
        crate::ecvrf::ecvrf_proof_to_hash(ticket)
    } else {
        *blake3::hash(ticket).as_bytes()
    };
    let raw = u64::from_le_bytes(hash_bytes[..8].try_into().expect("32-byte hash"));
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

pub fn qualifies_proposer_for_network(
    ticket: &[u8],
    my_drs: f64,
    total_drs: f64,
    n_validators: usize,
) -> bool {
    if n_validators <= MIN_LIVE_VALIDATORS { return true; }
    let raw_share = capped_share(my_drs, total_drs);
    let share = if n_validators <= COMMITTEE_SIZE {
        raw_share.max(1.0 / n_validators as f64)
    } else {
        raw_share
    };
    let expected  = expected_proposers_for_network(n_validators);
    let threshold = (expected * share).min(1.0);
    ticket_to_float(ticket) < threshold
}

pub fn vote_signing_data(block_hash: &str, height: u64, voter: &str) -> String {
    format!("ego/vote/v1:{}:{}:{}", block_hash, height, voter)
}
