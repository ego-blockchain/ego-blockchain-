//! Cryptographic proofs for storage verification.
//!
//! Implements a Merkle-tree-based PoRep/PoST protocol:
//!
//! **PoRep (Proof of Replication)**
//!   At store-time the prover computes a Merkle tree over the encrypted file
//!   (1 KB leaves, blake3 hashing) and derives:
//!     comm_d  = Merkle root of the encrypted file chunks
//!     replica_id = blake3(prover_addr ‖ cid)
//!     comm_r  = blake3(comm_d ‖ replica_id ‖ "ego/porep/v1")
//!   These are registered on the relay together with the leaf counts.
//!
//! **PoST (Proof of Space-Time)**
//!   Every 30 minutes the relay issues a random challenge_seed.
//!   The prover derives 8 leaf indices deterministically from the seed and
//!   supplies one Merkle proof per challenged leaf. The relay verifies each
//!   proof against the registered comm_d. No file content is revealed.

use serde::{Deserialize, Serialize};

/// Leaf size in bytes (1 KB).
pub const CHUNK_SIZE: usize = 1024;
/// Number of Merkle proofs per PoST window.
pub const POST_N_CHALLENGES: usize = 8;
/// Domain-separation tag for comm_r derivation.
pub const POREP_TAG: &[u8] = b"ego/porep/v1";
/// PoST window duration in seconds (30 minutes).
pub const POST_WINDOW_SECS: i64 = 30 * 60;

// ── Internal helpers ─────────────────────────────────────────────────────────

fn hash_bytes(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

// ── Merkle tree ───────────────────────────────────────────────────────────────

/// An in-memory Merkle tree built over fixed-size file chunks.
///
/// Layout (1-indexed):
///   Root   →  nodes[1]
///   Leaves →  nodes[n_padded .. 2*n_padded]  (0-indexed among leaves: leaf i at nodes[n_padded + i])
///   Padding leaves are all zeros.
pub struct MerkleTree {
    pub root: [u8; 32],
    nodes: Vec<[u8; 32]>,
    pub n_padded: usize,
    pub n_real: usize,
}

impl MerkleTree {
    /// Build a Merkle tree from the raw data bytes.
    pub fn build(data: &[u8]) -> Self {
        let leaves: Vec<[u8; 32]> = data
            .chunks(CHUNK_SIZE)
            .map(|chunk| hash_bytes(chunk))
            .collect();

        let n_real   = leaves.len().max(1);
        let n_padded = n_real.next_power_of_two();

        // 1-indexed: node[0] unused, node[1] = root, leaves at n_padded..2*n_padded
        let mut nodes = vec![[0u8; 32]; 2 * n_padded + 1];

        for (i, leaf) in leaves.iter().enumerate() {
            nodes[n_padded + i] = *leaf;
        }
        // Padding leaves stay [0u8;32].

        for i in (1..n_padded).rev() {
            nodes[i] = hash_pair(&nodes[2 * i], &nodes[2 * i + 1]);
        }

        MerkleTree { root: nodes[1], nodes, n_padded, n_real }
    }

    /// Generate a Merkle proof for the leaf at `leaf_idx` (0-based, must be < n_real).
    pub fn proof(&self, leaf_idx: usize) -> MerkleProof {
        let mut path = Vec::new();
        let mut pos  = self.n_padded + leaf_idx;
        let leaf     = self.nodes[pos];

        while pos > 1 {
            // Sibling: flip the last bit of pos.
            let sibling = if pos % 2 == 0 { pos + 1 } else { pos - 1 };
            path.push(self.nodes[sibling]);
            pos /= 2;
        }

        MerkleProof { leaf_index: leaf_idx as u64, leaf, path }
    }
}

// ── MerkleProof ───────────────────────────────────────────────────────────────

/// A Merkle inclusion proof for one leaf.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// 0-based leaf index within the real leaf set.
    pub leaf_index: u64,
    /// Hash of the challenged leaf (blake3 of 1 KB chunk).
    pub leaf: [u8; 32],
    /// Sibling hashes from leaf up to (but not including) the root.
    pub path: Vec<[u8; 32]>,
}

impl MerkleProof {
    /// Verify this proof against `root`, using `n_padded` as the padded leaf count.
    pub fn verify(&self, root: &[u8; 32], n_padded: usize) -> bool {
        let mut current = self.leaf;
        let mut pos     = n_padded as u64 + self.leaf_index;

        for sibling in &self.path {
            current = if pos % 2 == 0 {
                hash_pair(&current, sibling) // current is left child
            } else {
                hash_pair(sibling, &current) // current is right child
            };
            pos /= 2;
        }

        &current == root
    }
}

// ── PoRep commitment ──────────────────────────────────────────────────────────

/// The commitment registered on the relay after a file is sealed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoRepCommitment {
    /// Merkle root of encrypted file chunks.
    pub comm_d: [u8; 32],
    /// H(comm_d ‖ replica_id ‖ POREP_TAG).
    pub comm_r: [u8; 32],
    /// H(prover_addr ‖ cid).
    pub replica_id: [u8; 32],
    /// Number of real (non-padding) leaves.
    pub n_real_leaves: usize,
    /// Next power-of-two ≥ n_real_leaves.
    pub n_padded_leaves: usize,
}

/// Compute the PoRep commitment for an encrypted file.
///
/// `enc_bytes` — the bytes that will be written to disk (nonce ‖ ciphertext).
/// `prover_addr` — the wallet's egot1 address.
/// `cid` — the content identifier of the *plaintext* (egocid1…).
pub fn compute_porep_commitment(
    enc_bytes:   &[u8],
    prover_addr: &str,
    cid:         &str,
) -> PoRepCommitment {
    let tree = MerkleTree::build(enc_bytes);
    let comm_d = tree.root;

    let replica_id = {
        let mut h = blake3::Hasher::new();
        h.update(prover_addr.as_bytes());
        h.update(b":");
        h.update(cid.as_bytes());
        *h.finalize().as_bytes()
    };

    let comm_r = {
        let mut h = blake3::Hasher::new();
        h.update(&comm_d);
        h.update(&replica_id);
        h.update(POREP_TAG);
        *h.finalize().as_bytes()
    };

    PoRepCommitment {
        comm_d,
        comm_r,
        replica_id,
        n_real_leaves:   tree.n_real,
        n_padded_leaves: tree.n_padded,
    }
}

// ── PoST challenge/proof ─────────────────────────────────────────────────────

/// Derive the `POST_N_CHALLENGES` leaf indices for a given challenge seed.
///
/// Both prover and verifier call this — they must produce identical indices.
pub fn derive_challenge_indices(
    challenge_seed: &[u8; 32],
    n_real_leaves:  usize,
) -> Vec<usize> {
    (0..POST_N_CHALLENGES)
        .map(|i| {
            let mut h = blake3::Hasher::new();
            h.update(challenge_seed);
            h.update(&(i as u64).to_le_bytes());
            let raw = u64::from_le_bytes(
                h.finalize().as_bytes()[..8].try_into().unwrap(),
            );
            (raw % n_real_leaves as u64) as usize
        })
        .collect()
}

/// Generate PoST proofs for all challenged leaf positions over an encrypted file.
pub fn generate_post_proofs(
    enc_bytes:      &[u8],
    challenge_seed: &[u8; 32],
    n_real_leaves:  usize,
) -> Vec<MerkleProof> {
    let tree    = MerkleTree::build(enc_bytes);
    let indices = derive_challenge_indices(challenge_seed, n_real_leaves);
    indices.iter().map(|&idx| tree.proof(idx)).collect()
}

/// Verify a set of PoST proofs against a registered commitment.
///
/// Returns true only if:
///   - exactly POST_N_CHALLENGES proofs are present
///   - each proof targets the expected leaf index (derived from seed)
///   - each Merkle proof is valid against `comm_d`
pub fn verify_post_proofs(
    proofs:          &[MerkleProof],
    comm_d:          &[u8; 32],
    challenge_seed:  &[u8; 32],
    n_real_leaves:   usize,
    n_padded_leaves: usize,
) -> bool {
    if proofs.len() != POST_N_CHALLENGES { return false; }
    let expected = derive_challenge_indices(challenge_seed, n_real_leaves);
    for (proof, &expected_idx) in proofs.iter().zip(expected.iter()) {
        if proof.leaf_index != expected_idx as u64 { return false; }
        if !proof.verify(comm_d, n_padded_leaves)  { return false; }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::OsRng, RngCore};

    #[test]
    fn roundtrip_merkle_proof() {
        let mut data = vec![0u8; 4096]; // 4 chunks
        OsRng.fill_bytes(&mut data);
        let tree = MerkleTree::build(&data);
        for idx in 0..tree.n_real {
            let proof = tree.proof(idx);
            assert!(proof.verify(&tree.root, tree.n_padded), "proof failed for leaf {idx}");
        }
    }

    #[test]
    fn post_proof_roundtrip() {
        let mut data = vec![0u8; 32 * 1024]; // 32 chunks
        OsRng.fill_bytes(&mut data);
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let tree   = MerkleTree::build(&data);
        let proofs = generate_post_proofs(&data, &seed, tree.n_real);
        assert!(verify_post_proofs(&proofs, &tree.root, &seed, tree.n_real, tree.n_padded));
    }

    #[test]
    fn tampered_proof_fails() {
        let mut data = vec![0u8; 8 * 1024];
        OsRng.fill_bytes(&mut data);
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let tree   = MerkleTree::build(&data);
        let mut proofs = generate_post_proofs(&data, &seed, tree.n_real);
        // Corrupt the first leaf hash
        proofs[0].leaf[0] ^= 0xFF;
        assert!(!verify_post_proofs(&proofs, &tree.root, &seed, tree.n_real, tree.n_padded));
    }
}
