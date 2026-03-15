//! EGO-24 MEV Protection — Commit-Reveal Scheme
//!
//! Protects DEX users from front-running and sandwich attacks.
//! Users commit a hash of their transaction in block N,
//! then reveal and execute in block N+1 to N+5.
//!
//! Specification: `eips/EGO-24.md`

use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};

/// Maximum number of blocks a commitment remains valid for reveal.
/// Commit submitted at block B can be revealed at blocks B+1 .. B+REVEAL_WINDOW_BLOCKS.
pub const REVEAL_WINDOW_BLOCKS: u64 = 5;

/// Number of blocks after which an unrevealed commitment is considered expired.
pub const EXPIRY_BLOCKS: u64 = 10;

/// RU cost of submitting a commit transaction (cheap placeholder).
pub const COMMIT_RU_COST: u64 = 10_000;

/// RU cost of submitting a reveal transaction (same as a normal tx, since it executes tx_data).
pub const REVEAL_RU_COST: u64 = 50_000;

/// RU penalty charged to the submitter of an expired unrevealed commitment.
pub const EXPIRY_PENALTY_RU: u64 = 5_000;

/// On-chain record of a submitted commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    /// `blake2s(tx_data || nonce_le_bytes || secret)` — 32 bytes.
    pub commit_hash: [u8; 32],
    /// Address of the account that submitted the commit transaction.
    pub submitter: [u8; 20],
    /// Block height at which the commit was included.
    pub block_height: u64,
    /// Whether the reveal has been successfully processed.
    pub revealed: bool,
    /// Whether the reveal window has passed without a valid reveal.
    pub expired: bool,
}

/// A matched commit-reveal pair, held in memory during reveal processing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitRevealPair {
    /// The original on-chain commitment.
    pub commitment: Commitment,
    /// The transaction bytes from the reveal.
    pub tx_data: Vec<u8>,
    /// The nonce from the reveal.
    pub nonce: u64,
}

/// Core MEV protection logic (stateless helper methods).
///
/// State (the mapping from `commit_hash` to `Commitment`) is managed by the
/// calling consensus/VM layer; this struct provides pure functions for hash
/// computation and validation.
pub struct MevProtection;

impl MevProtection {
    /// Compute the commit hash: `blake2s(tx_data || nonce_le_bytes || secret)`.
    ///
    /// # Arguments
    /// * `tx_data` — serialised transaction bytes
    /// * `nonce`   — per-user counter, prevents replay of the same commitment
    /// * `secret`  — 32-byte random value known only to the user
    ///
    /// # Returns
    /// 32-byte Blake2s digest used as the commitment identifier.
    pub fn compute_commit_hash(tx_data: &[u8], nonce: u64, secret: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Blake2s256::new();
        hasher.update(tx_data);
        hasher.update(nonce.to_le_bytes());
        hasher.update(secret);
        hasher.finalize().into()
    }

    /// Verify that a reveal matches a commitment.
    ///
    /// Recomputes `blake2s(tx_data || nonce_le_bytes || secret)` and compares
    /// it against `commitment.commit_hash` using a constant-time comparison.
    ///
    /// # Returns
    /// `true` if the reveal is valid, `false` otherwise.
    pub fn verify_reveal(
        commitment: &Commitment,
        tx_data: &[u8],
        nonce: u64,
        secret: &[u8; 32],
    ) -> bool {
        let expected = Self::compute_commit_hash(tx_data, nonce, secret);
        // Constant-time comparison to avoid timing side-channels.
        constant_time_eq(&expected, &commitment.commit_hash)
    }

    /// Check whether a commitment is within its valid reveal window at `current_block`.
    ///
    /// Rules (EGO-24 §2):
    /// - Earliest valid reveal: `commit_block + 1` (same-block reveal is forbidden)
    /// - Latest valid reveal: `commit_block + REVEAL_WINDOW_BLOCKS`
    /// - Commitment must not already be revealed or expired.
    pub fn is_reveal_valid(commitment: &Commitment, current_block: u64) -> bool {
        let min_block = commitment.block_height + 1; // same-block reveal forbidden
        let max_block = commitment.block_height + REVEAL_WINDOW_BLOCKS;
        current_block >= min_block
            && current_block <= max_block
            && !commitment.revealed
            && !commitment.expired
    }

    /// Mark a commitment as expired if its reveal window has passed.
    ///
    /// Called by the consensus layer at the start of each block to sweep
    /// commitments older than `EXPIRY_BLOCKS`.
    pub fn expire_commitment(commitment: &mut Commitment, current_block: u64) {
        if current_block > commitment.block_height + EXPIRY_BLOCKS {
            commitment.expired = true;
        }
    }

    /// Validate a full reveal attempt, returning a structured result.
    ///
    /// This is the main entry point called by the VM when processing a
    /// `reveal(commit_hash, tx_data, nonce, secret)` transaction.
    ///
    /// # Returns
    /// `Ok(CommitRevealPair)` if the reveal is valid and should be executed.
    /// `Err(RevealError)` describing the specific validation failure.
    pub fn validate_reveal(
        commitment: &Commitment,
        tx_data: Vec<u8>,
        nonce: u64,
        secret: &[u8; 32],
        current_block: u64,
        caller: &[u8; 20],
    ) -> Result<CommitRevealPair, RevealError> {
        // 1. Submitter must match caller.
        if &commitment.submitter != caller {
            return Err(RevealError::UnauthorizedCaller);
        }

        // 2. Reveal window must be valid.
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

        // 3. Hash must match.
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

/// Errors returned by `MevProtection::validate_reveal`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevealError {
    /// The caller is not the original committer.
    UnauthorizedCaller,
    /// The commitment has already been successfully revealed.
    AlreadyRevealed,
    /// The reveal window has closed without a successful reveal.
    CommitmentExpired,
    /// Attempt to reveal in the same block as the commit (forbidden by EGO-24 §8).
    SameBlockReveal,
    /// Current block is outside the `[commit_block+1, commit_block+REVEAL_WINDOW_BLOCKS]` range.
    OutsideRevealWindow,
    /// `blake2s(tx_data || nonce || secret)` does not match the stored `commit_hash`.
    HashMismatch,
}

/// Constant-time byte-slice equality to prevent timing attacks on hash comparison.
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

    /// Happy path: commit at block 10, reveal at block 11.
    #[test]
    fn commit_reveal_roundtrip() {
        let (commitment, tx_data, nonce, secret) = make_commitment(10);

        // Hash verification must succeed with correct inputs.
        assert!(MevProtection::verify_reveal(&commitment, &tx_data, nonce, &secret));

        // Reveal window check at block 11 (next block after commit).
        assert!(MevProtection::is_reveal_valid(&commitment, 11));

        // validate_reveal should return Ok.
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

    /// Using the wrong secret must cause verify_reveal to return false.
    #[test]
    fn wrong_secret_fails() {
        let (commitment, tx_data, nonce, _correct_secret) = make_commitment(10);
        let wrong_secret = [0xFFu8; 32];

        assert!(!MevProtection::verify_reveal(&commitment, &tx_data, nonce, &wrong_secret));
    }

    /// Using the wrong tx_data must cause verify_reveal to return false.
    #[test]
    fn wrong_tx_data_fails() {
        let (commitment, _tx_data, nonce, secret) = make_commitment(10);
        let tampered = b"swap(EGOC, 9999, USDC, 1)".to_vec(); // attacker-modified

        assert!(!MevProtection::verify_reveal(&commitment, &tampered, nonce, &secret));
    }

    /// Reveal at block commit+6 is outside the 5-block window; must return false.
    #[test]
    fn reveal_window_enforced() {
        let (commitment, _tx_data, _nonce, _secret) = make_commitment(10);

        // Block 15 = commit_block(10) + 5 = last valid block.
        assert!(MevProtection::is_reveal_valid(&commitment, 15));

        // Block 16 = commit_block(10) + 6 = outside window.
        assert!(!MevProtection::is_reveal_valid(&commitment, 16));
    }

    /// Same-block reveal (current_block == commit_block) must be rejected.
    #[test]
    fn same_block_reveal_rejected() {
        let (commitment, tx_data, nonce, secret) = make_commitment(10);

        // current_block == commit_block → same-block reveal is forbidden.
        assert!(!MevProtection::is_reveal_valid(&commitment, 10));

        let result = MevProtection::validate_reveal(
            &commitment,
            tx_data,
            nonce,
            &secret,
            10, // same block
            &make_submitter(),
        );
        assert_eq!(result, Err(RevealError::SameBlockReveal));
    }

    /// Revealing with the wrong caller address must be rejected.
    #[test]
    fn unauthorized_caller_rejected() {
        let (commitment, tx_data, nonce, secret) = make_commitment(10);
        let attacker = [0x00u8; 20];

        let result =
            MevProtection::validate_reveal(&commitment, tx_data, nonce, &secret, 11, &attacker);
        assert_eq!(result, Err(RevealError::UnauthorizedCaller));
    }

    /// Commitments past EXPIRY_BLOCKS must be marked expired.
    #[test]
    fn expiry_marks_commitment() {
        let (mut commitment, _tx, _n, _s) = make_commitment(10);

        // Block 20 = commit_block(10) + 10 → NOT expired yet (must be strictly greater).
        MevProtection::expire_commitment(&mut commitment, 20);
        assert!(!commitment.expired);

        // Block 21 = commit_block(10) + 11 → expired.
        MevProtection::expire_commitment(&mut commitment, 21);
        assert!(commitment.expired);
    }

    /// Revealed commitments must be rejected on a second reveal attempt.
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

    /// compute_commit_hash is deterministic: same inputs → same hash.
    #[test]
    fn hash_is_deterministic() {
        let tx_data = b"test_tx".to_vec();
        let nonce = 42u64;
        let secret = [0x11u8; 32];

        let h1 = MevProtection::compute_commit_hash(&tx_data, nonce, &secret);
        let h2 = MevProtection::compute_commit_hash(&tx_data, nonce, &secret);
        assert_eq!(h1, h2);
    }

    /// Different nonces must produce different hashes (prevents nonce-reuse attacks).
    #[test]
    fn different_nonces_produce_different_hashes() {
        let tx_data = b"test_tx".to_vec();
        let secret = [0x11u8; 32];

        let h1 = MevProtection::compute_commit_hash(&tx_data, 1, &secret);
        let h2 = MevProtection::compute_commit_hash(&tx_data, 2, &secret);
        assert_ne!(h1, h2);
    }

    /// constant_time_eq is correct for equal and unequal inputs.
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
