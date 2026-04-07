use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};

pub const REVEAL_WINDOW_BLOCKS: u64 = 5;

pub const EXPIRY_BLOCKS: u64 = 10;

pub const COMMIT_RU_COST: u64 = 10_000;

pub const REVEAL_RU_COST: u64 = 50_000;

pub const EXPIRY_PENALTY_RU: u64 = 5_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {

    pub commit_hash: [u8; 32],

    pub submitter: [u8; 20],

    pub block_height: u64,

    pub revealed: bool,

    pub expired: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitRevealPair {

    pub commitment: Commitment,

    pub tx_data: Vec<u8>,

    pub nonce: u64,
}

pub struct MevProtection;

impl MevProtection {

    pub fn compute_commit_hash(tx_data: &[u8], nonce: u64, secret: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Blake2s256::new();
        hasher.update(tx_data);
        hasher.update(nonce.to_le_bytes());
        hasher.update(secret);
        hasher.finalize().into()
    }

    pub fn verify_reveal(
        commitment: &Commitment,
        tx_data: &[u8],
        nonce: u64,
        secret: &[u8; 32],
    ) -> bool {
        let expected = Self::compute_commit_hash(tx_data, nonce, secret);

        constant_time_eq(&expected, &commitment.commit_hash)
    }

    pub fn is_reveal_valid(commitment: &Commitment, current_block: u64) -> bool {
        let min_block = commitment.block_height + 1;
        let max_block = commitment.block_height + REVEAL_WINDOW_BLOCKS;
        current_block >= min_block
            && current_block <= max_block
            && !commitment.revealed
            && !commitment.expired
    }

    pub fn expire_commitment(commitment: &mut Commitment, current_block: u64) {
        if current_block > commitment.block_height + EXPIRY_BLOCKS {
            commitment.expired = true;
        }
    }

    pub fn validate_reveal(
        commitment: &Commitment,
        tx_data: Vec<u8>,
        nonce: u64,
        secret: &[u8; 32],
        current_block: u64,
        caller: &[u8; 20],
    ) -> Result<CommitRevealPair, RevealError> {

        if &commitment.submitter != caller {
            return Err(RevealError::UnauthorizedCaller);
        }

        if !Self::is_reveal_valid(commitment, current_block) {
            if commitment.revealed {
                return Err(RevealError::AlreadyRevealed);
            }
            if commitment.expired {
                return Err(RevealError::CommitmentExpired);
            }
            if current_block <= commitment.block_height {
                return Err(RevealError::SameBlockReveal);
            }
            return Err(RevealError::OutsideRevealWindow);
        }

        if !Self::verify_reveal(commitment, &tx_data, nonce, secret) {
            return Err(RevealError::HashMismatch);
        }

        Ok(CommitRevealPair {
            commitment: commitment.clone(),
            tx_data,
            nonce,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevealError {

    UnauthorizedCaller,

    AlreadyRevealed,

    CommitmentExpired,

    SameBlockReveal,

    OutsideRevealWindow,

    HashMismatch,
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_submitter() -> [u8; 20] {
        [0xABu8; 20]
    }

    fn make_secret() -> [u8; 32] {
        [0x42u8; 32]
    }

    fn make_commitment(block_height: u64) -> (Commitment, Vec<u8>, u64, [u8; 32]) {
        let tx_data = b"swap(EGOC, 1000, USDC, 950)".to_vec();
        let nonce: u64 = 1;
        let secret = make_secret();
        let hash = MevProtection::compute_commit_hash(&tx_data, nonce, &secret);
        let commitment = Commitment {
            commit_hash: hash,
            submitter: make_submitter(),
            block_height,
            revealed: false,
            expired: false,
        };
        (commitment, tx_data, nonce, secret)
    }

    #[test]
    fn commit_reveal_roundtrip() {
        let (commitment, tx_data, nonce, secret) = make_commitment(10);

        assert!(MevProtection::verify_reveal(&commitment, &tx_data, nonce, &secret));

        assert!(MevProtection::is_reveal_valid(&commitment, 11));

        let result = MevProtection::validate_reveal(
            &commitment,
            tx_data.clone(),
            nonce,
            &secret,
            11,
            &make_submitter(),
        );
        assert!(result.is_ok());
        let pair = result.unwrap();
        assert_eq!(pair.tx_data, tx_data);
        assert_eq!(pair.nonce, nonce);
    }

    #[test]
    fn wrong_secret_fails() {
        let (commitment, tx_data, nonce, _correct_secret) = make_commitment(10);
        let wrong_secret = [0xFFu8; 32];

        assert!(!MevProtection::verify_reveal(&commitment, &tx_data, nonce, &wrong_secret));
    }

    #[test]
    fn wrong_tx_data_fails() {
        let (commitment, _tx_data, nonce, secret) = make_commitment(10);
        let tampered = b"swap(EGOC, 9999, USDC, 1)".to_vec();

        assert!(!MevProtection::verify_reveal(&commitment, &tampered, nonce, &secret));
    }

    #[test]
    fn reveal_window_enforced() {
        let (commitment, _tx_data, _nonce, _secret) = make_commitment(10);

        assert!(MevProtection::is_reveal_valid(&commitment, 15));

        assert!(!MevProtection::is_reveal_valid(&commitment, 16));
    }

    #[test]
    fn same_block_reveal_rejected() {
        let (commitment, tx_data, nonce, secret) = make_commitment(10);

        assert!(!MevProtection::is_reveal_valid(&commitment, 10));

        let result = MevProtection::validate_reveal(
            &commitment,
            tx_data,
            nonce,
            &secret,
            10,
            &make_submitter(),
        );
        assert_eq!(result, Err(RevealError::SameBlockReveal));
    }

    #[test]
    fn unauthorized_caller_rejected() {
        let (commitment, tx_data, nonce, secret) = make_commitment(10);
        let attacker = [0x00u8; 20];

        let result =
            MevProtection::validate_reveal(&commitment, tx_data, nonce, &secret, 11, &attacker);
        assert_eq!(result, Err(RevealError::UnauthorizedCaller));
    }

    #[test]
    fn expiry_marks_commitment() {
        let (mut commitment, _tx, _n, _s) = make_commitment(10);

        MevProtection::expire_commitment(&mut commitment, 20);
        assert!(!commitment.expired);

        MevProtection::expire_commitment(&mut commitment, 21);
        assert!(commitment.expired);
    }

    #[test]
    fn double_reveal_rejected() {
        let (mut commitment, tx_data, nonce, secret) = make_commitment(10);
        commitment.revealed = true;

        let result = MevProtection::validate_reveal(
            &commitment,
            tx_data,
            nonce,
            &secret,
            11,
            &make_submitter(),
        );
        assert_eq!(result, Err(RevealError::AlreadyRevealed));
    }

    #[test]
    fn hash_is_deterministic() {
        let tx_data = b"test_tx".to_vec();
        let nonce = 42u64;
        let secret = [0x11u8; 32];

        let h1 = MevProtection::compute_commit_hash(&tx_data, nonce, &secret);
        let h2 = MevProtection::compute_commit_hash(&tx_data, nonce, &secret);
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_nonces_produce_different_hashes() {
        let tx_data = b"test_tx".to_vec();
        let secret = [0x11u8; 32];

        let h1 = MevProtection::compute_commit_hash(&tx_data, 1, &secret);
        let h2 = MevProtection::compute_commit_hash(&tx_data, 2, &secret);
        assert_ne!(h1, h2);
    }

    #[test]
    fn constant_time_eq_correctness() {
        let a = [0u8; 32];
        let b = [0u8; 32];
        let c = {
            let mut x = [0u8; 32];
            x[31] = 1;
            x
        };
        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }
}
