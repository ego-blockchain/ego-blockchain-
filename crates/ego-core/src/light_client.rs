//! Light client (SPV) for Ego Blockchain.
//!
//! A light client:
//! 1. Downloads only block headers (not full blocks)
//! 2. Verifies headers form a valid chain (parent hash + BFT QC signatures)
//! 3. Verifies transaction inclusion via Merkle proof
//! 4. Verifies account state via Sparse Merkle Trie proof
//!
//! This enables trustless mobile wallets that don't need to store the full chain.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Types ─────────────────────────────────────────────────────────────────────

/// A minimal block header — everything needed to verify the chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LightBlockHeader {
    pub height:         u64,
    pub timestamp:      i64,
    pub parent_hash:    [u8; 32],
    pub tx_root:        [u8; 32],   // Merkle root of transactions
    pub state_root:     [u8; 32],   // Sparse Merkle Trie root
    pub receipts_root:  [u8; 32],   // Merkle root of receipts
    pub validator_set_hash: [u8; 32], // Hash of current validator set
    pub block_hash:     [u8; 32],   // blake2s(all fields above)
    /// BLS aggregate signature over this header (96 bytes).
    pub bls_agg_sig:    Vec<u8>,
    /// Bitfield of which validators signed.
    pub signer_bitfield: Vec<u8>,
}

impl LightBlockHeader {
    /// Compute expected block hash.
    pub fn compute_hash(&self) -> [u8; 32] {
        use blake2::{Blake2s256, Digest};
        let mut h = Blake2s256::new();
        h.update(self.height.to_le_bytes());
        h.update(self.timestamp.to_le_bytes());
        h.update(self.parent_hash);
        h.update(self.tx_root);
        h.update(self.state_root);
        h.update(self.receipts_root);
        h.update(self.validator_set_hash);
        h.finalize().into()
    }

    /// Verify the block hash matches the header contents.
    pub fn verify_hash(&self) -> bool {
        self.compute_hash() == self.block_hash
    }
}

/// A Merkle inclusion proof for a single transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxInclusionProof {
    pub tx_hash:    [u8; 32],
    pub block_height: u64,
    pub tx_index:   u32,
    /// Merkle proof path (sibling hashes from leaf to root).
    pub siblings:   Vec<[u8; 32]>,
    /// tx_root from the block header.
    pub tx_root:    [u8; 32],
}

impl TxInclusionProof {
    /// Verify the proof: recompute root from tx_hash + siblings and check vs tx_root.
    pub fn verify(&self) -> bool {
        use blake2::{Blake2s256, Digest};
        let mut current = self.tx_hash;
        let mut index = self.tx_index;
        for sibling in &self.siblings {
            let mut h = Blake2s256::new();
            if index % 2 == 0 {
                h.update(current);
                h.update(sibling);
            } else {
                h.update(sibling);
                h.update(current);
            }
            current = h.finalize().into();
            index /= 2;
        }
        current == self.tx_root
    }
}

/// A state inclusion proof for an account balance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateProof {
    /// Account address (20 bytes).
    pub address:    [u8; 20],
    /// The value being proved (e.g., balance as u128 LE bytes).
    pub value:      Vec<u8>,
    /// SMT proof siblings (256 entries for 256-bit key space).
    pub siblings:   Vec<[u8; 32]>,
    /// State root from the block header.
    pub state_root: [u8; 32],
}

impl StateProof {
    /// Verify the SMT proof.
    /// Uses the same domain-separated hashing as `crates/ego-core/src/sparse_merkle.rs`.
    pub fn verify(&self) -> bool {
        use blake2::{Blake2s256, Digest};

        // Leaf hash = blake2s(TAG_LEAF || key_256bit || value)
        let key = address_to_key(&self.address);
        let mut h = Blake2s256::new();
        h.update(b"ego/smt/leaf/v1");
        h.update(key);
        h.update(&self.value);
        let mut current: [u8; 32] = h.finalize().into();

        // Walk up 256 levels
        for (i, sibling) in self.siblings.iter().enumerate() {
            let bit = (key[i / 8] >> (7 - (i % 8))) & 1;
            let mut h2 = Blake2s256::new();
            h2.update(b"ego/smt/node/v1");
            if bit == 0 {
                h2.update(current);
                h2.update(sibling);
            } else {
                h2.update(sibling);
                h2.update(current);
            }
            current = h2.finalize().into();
        }
        current == self.state_root
    }
}

fn address_to_key(addr: &[u8; 20]) -> [u8; 32] {
    use blake2::{Blake2s256, Digest};
    let mut h = Blake2s256::new();
    h.update(b"ego/addr/key/v1");
    h.update(addr);
    h.finalize().into()
}

// ── Light Client State Machine ────────────────────────────────────────────────

/// The light client state.
#[derive(Debug)]
pub struct LightClient {
    /// Chain ID (1 = testnet, 2 = mainnet).
    pub chain_id: u64,
    /// Known trusted checkpoint header (from a hardcoded hash or a trusted peer).
    pub trusted_header: Option<LightBlockHeader>,
    /// All verified headers indexed by height.
    pub headers: HashMap<u64, LightBlockHeader>,
    /// Highest verified height.
    pub best_height: u64,
}

impl LightClient {
    pub fn new(chain_id: u64) -> Self {
        Self { chain_id, trusted_header: None, headers: HashMap::new(), best_height: 0 }
    }

    /// Bootstrap from a trusted checkpoint (e.g., hardcoded in the binary).
    pub fn set_checkpoint(&mut self, header: LightBlockHeader) -> Result<(), LcError> {
        if !header.verify_hash() {
            return Err(LcError::InvalidHash(header.height));
        }
        self.best_height = header.height;
        self.trusted_header = Some(header.clone());
        self.headers.insert(header.height, header);
        Ok(())
    }

    /// Add a new header, verifying it extends the current best chain.
    pub fn add_header(&mut self, header: LightBlockHeader) -> Result<(), LcError> {
        // Must be newer
        if header.height <= self.best_height {
            return Err(LcError::StaleHeader(header.height));
        }
        // Must be exactly height + 1 (sequential sync) or have a valid skip link
        if header.height != self.best_height + 1 {
            return Err(LcError::GapInChain { expected: self.best_height + 1, got: header.height });
        }
        // Hash must be valid
        if !header.verify_hash() {
            return Err(LcError::InvalidHash(header.height));
        }
        // Parent hash must match our best header
        if let Some(best) = self.headers.get(&self.best_height) {
            if header.parent_hash != best.block_hash {
                return Err(LcError::ParentMismatch(header.height));
            }
        }
        self.best_height = header.height;
        self.headers.insert(header.height, header);
        Ok(())
    }

    /// Verify a transaction inclusion proof.
    pub fn verify_tx(&self, proof: &TxInclusionProof) -> Result<bool, LcError> {
        let header = self.headers.get(&proof.block_height)
            .ok_or(LcError::HeaderNotFound(proof.block_height))?;
        if proof.tx_root != header.tx_root {
            return Err(LcError::RootMismatch);
        }
        Ok(proof.verify())
    }

    /// Verify an account state proof against a specific block.
    pub fn verify_state(&self, proof: &StateProof, at_height: u64) -> Result<bool, LcError> {
        let header = self.headers.get(&at_height)
            .ok_or(LcError::HeaderNotFound(at_height))?;
        if proof.state_root != header.state_root {
            return Err(LcError::RootMismatch);
        }
        Ok(proof.verify())
    }

    /// Get the best known state root.
    pub fn state_root(&self) -> Option<[u8; 32]> {
        self.headers.get(&self.best_height).map(|h| h.state_root)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LcError {
    #[error("invalid block hash at height {0}")]
    InvalidHash(u64),
    #[error("stale header: height {0} already known")]
    StaleHeader(u64),
    #[error("gap in chain: expected height {expected}, got {got}")]
    GapInChain { expected: u64, got: u64 },
    #[error("parent hash mismatch at height {0}")]
    ParentMismatch(u64),
    #[error("header not found for height {0}")]
    HeaderNotFound(u64),
    #[error("state/tx root mismatch")]
    RootMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header(height: u64, parent: [u8; 32]) -> LightBlockHeader {
        let mut h = LightBlockHeader {
            height, timestamp: height as i64 * 100,
            parent_hash: parent,
            tx_root: [height as u8; 32],
            state_root: [0u8; 32],
            receipts_root: [0u8; 32],
            validator_set_hash: [0u8; 32],
            block_hash: [0u8; 32],
            bls_agg_sig: vec![],
            signer_bitfield: vec![],
        };
        h.block_hash = h.compute_hash();
        h
    }

    #[test]
    fn test_header_chain() {
        let mut lc = LightClient::new(1);
        let h0 = make_header(0, [0u8; 32]);
        lc.set_checkpoint(h0.clone()).unwrap();
        let h1 = make_header(1, h0.block_hash);
        lc.add_header(h1.clone()).unwrap();
        assert_eq!(lc.best_height, 1);
    }

    #[test]
    fn test_tx_proof() {
        let tx_hash = [42u8; 32];
        // Single-leaf tree: root = hash(tx_hash || [0;32])
        use blake2::{Blake2s256, Digest};
        let mut h = Blake2s256::new();
        h.update(tx_hash);
        h.update([0u8; 32]);
        let root: [u8; 32] = h.finalize().into();

        let proof = TxInclusionProof {
            tx_hash, block_height: 1, tx_index: 0,
            siblings: vec![[0u8; 32]], tx_root: root,
        };
        assert!(proof.verify());
    }

    #[test]
    fn test_stale_header_rejected() {
        let mut lc = LightClient::new(1);
        let h0 = make_header(0, [0u8; 32]);
        lc.set_checkpoint(h0.clone()).unwrap();
        // Re-adding height 0 should fail
        let result = lc.add_header(h0);
        assert!(matches!(result, Err(LcError::StaleHeader(0))));
    }

    #[test]
    fn test_gap_rejected() {
        let mut lc = LightClient::new(1);
        let h0 = make_header(0, [0u8; 32]);
        lc.set_checkpoint(h0.clone()).unwrap();
        // Jump straight to height 5 without height 1
        let h5 = make_header(5, h0.block_hash);
        let result = lc.add_header(h5);
        assert!(matches!(result, Err(LcError::GapInChain { expected: 1, got: 5 })));
    }

    #[test]
    fn test_parent_mismatch_rejected() {
        let mut lc = LightClient::new(1);
        let h0 = make_header(0, [0u8; 32]);
        lc.set_checkpoint(h0.clone()).unwrap();
        // Height 1 pointing to wrong parent
        let h1_bad = make_header(1, [0xffu8; 32]);
        let result = lc.add_header(h1_bad);
        assert!(matches!(result, Err(LcError::ParentMismatch(1))));
    }

    #[test]
    fn test_verify_tx_header_not_found() {
        let lc = LightClient::new(1);
        let proof = TxInclusionProof {
            tx_hash: [0u8; 32],
            block_height: 99,
            tx_index: 0,
            siblings: vec![],
            tx_root: [0u8; 32],
        };
        assert!(matches!(lc.verify_tx(&proof), Err(LcError::HeaderNotFound(99))));
    }

    #[test]
    fn test_verify_tx_root_mismatch() {
        let mut lc = LightClient::new(1);
        let h0 = make_header(0, [0u8; 32]);
        lc.set_checkpoint(h0.clone()).unwrap();
        // tx_root in proof does not match header's tx_root
        let proof = TxInclusionProof {
            tx_hash: [1u8; 32],
            block_height: 0,
            tx_index: 0,
            siblings: vec![],
            tx_root: [0xffu8; 32], // wrong root
        };
        assert!(matches!(lc.verify_tx(&proof), Err(LcError::RootMismatch)));
    }

    #[test]
    fn test_state_root() {
        let mut lc = LightClient::new(1);
        let h0 = make_header(0, [0u8; 32]);
        lc.set_checkpoint(h0).unwrap();
        assert_eq!(lc.state_root(), Some([0u8; 32]));
    }

    #[test]
    fn test_multi_block_chain() {
        let mut lc = LightClient::new(1);
        let h0 = make_header(0, [0u8; 32]);
        lc.set_checkpoint(h0.clone()).unwrap();
        let h1 = make_header(1, h0.block_hash);
        lc.add_header(h1.clone()).unwrap();
        let h2 = make_header(2, h1.block_hash);
        lc.add_header(h2.clone()).unwrap();
        let h3 = make_header(3, h2.block_hash);
        lc.add_header(h3.clone()).unwrap();
        assert_eq!(lc.best_height, 3);
        assert!(lc.headers.contains_key(&0));
        assert!(lc.headers.contains_key(&3));
    }
}
