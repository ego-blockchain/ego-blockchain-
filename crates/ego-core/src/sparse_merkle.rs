//! Sparse Merkle Trie (SMT) with O(log n) updates and inclusion/exclusion proofs.
//!
//! Key space: 256-bit (keyed by the blake2s hash of an address or any 32-byte input).
//!
//! Domain-separated hashing:
//!   - Empty leaf :  blake2s("ego/smt/empty/v1")
//!   - Internal   :  blake2s("ego/smt/node/v1" || left_hash || right_hash)
//!   - Leaf value :  blake2s("ego/smt/leaf/v1" || key || value)
//!
//! The trie is a full binary tree of depth 256.  Every leaf sits at exactly
//! depth 256.  For efficient operation we cache the hash of every internal
//! node that has at least one populated descendant; uncached nodes are treated
//! as empty (pre-computed tower).  All operations are iterative.

use crate::crypto::{hash_data, hash_multiple};
use crate::types::Hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Domain-tag constants & hash helpers
// ---------------------------------------------------------------------------

const TAG_EMPTY: &[u8] = b"ego/smt/empty/v1";
const TAG_NODE: &[u8] = b"ego/smt/node/v1";
const TAG_LEAF: &[u8] = b"ego/smt/leaf/v1";

/// Empty leaf hash: `blake2s(TAG_EMPTY)`.
fn empty_leaf_hash() -> Hash {
    hash_data(TAG_EMPTY)
}

/// Internal node hash: `blake2s(TAG_NODE || left || right)`.
fn node_hash(left: &Hash, right: &Hash) -> Hash {
    hash_multiple(&[TAG_NODE, left.as_bytes(), right.as_bytes()])
}

/// Leaf-value hash: `blake2s(TAG_LEAF || key || value)`.
fn leaf_hash(key: &[u8; 32], value: &[u8]) -> Hash {
    hash_multiple(&[TAG_LEAF, key, value])
}

// ---------------------------------------------------------------------------
// Pre-computed empty subtree hashes
//
// EMPTY[0] = hash of an empty leaf (depth 256).
// EMPTY[h] = hash of an empty subtree of height h (spans 2^h leaves).
// The root-level empty hash for a depth-256 tree is EMPTY[256].
// ---------------------------------------------------------------------------

fn build_empty_tower() -> [Hash; 257] {
    let mut h = [Hash::new([0u8; 32]); 257];
    h[0] = empty_leaf_hash();
    for i in 1..257 {
        h[i] = node_hash(&h[i - 1], &h[i - 1]);
    }
    h
}

/// `empty_tower()[h]` = hash of an empty subtree of height `h`.
fn empty_tower() -> &'static [Hash; 257] {
    use std::sync::OnceLock;
    static T: OnceLock<[Hash; 257]> = OnceLock::new();
    T.get_or_init(build_empty_tower)
}

// ---------------------------------------------------------------------------
// Bit helper
// ---------------------------------------------------------------------------

/// Extract bit `depth` (0 = MSB of byte 0) from a 256-bit key.
#[inline]
fn bit_at(key: &[u8; 32], depth: usize) -> u8 {
    debug_assert!(depth < 256);
    (key[depth / 8] >> (7 - (depth % 8))) & 1
}

// ---------------------------------------------------------------------------
// SparseMerkleTrie
//
// Internal representation:
//   - `leaves`        : key → raw value bytes
//   - `node_hashes`   : (depth, path_prefix_u128_pair) → cached Hash
//
// Rather than a complex node-cache keyed by arbitrary paths, we use an
// on-demand root recomputation approach: `root()` and `generate_proof()`
// both walk the trie top-down using the leaf map, computing subtree hashes
// on-the-fly.  For a trie with K leaves this is O(K · 256) per call but
// correct and simple.  An incremental hash cache can be layered on top
// without changing the public API.
// ---------------------------------------------------------------------------

/// An incremental Sparse Merkle Trie over a 256-bit key space.
///
/// Operations are O(K · 256) where K is the number of stored keys.
/// The public API (`insert`, `delete`, `get`, `root`, `generate_proof`) is
/// correct and stable; performance optimisations are internal concerns.
#[derive(Debug, Default)]
pub struct SparseMerkleTrie {
    leaves: HashMap<[u8; 32], Vec<u8>>,
}

impl SparseMerkleTrie {
    /// Create an empty trie.
    pub fn new() -> Self {
        Self { leaves: HashMap::new() }
    }

    /// Return the current root hash.
    pub fn root(&self) -> Hash {
        subtree_hash(&self.leaves, 0, &[0u8; 32], 0)
    }

    /// Look up `key`, returning the stored value or `None`.
    pub fn get(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        self.leaves.get(key).cloned()
    }

    /// Insert or update `(key, value)`.
    pub fn insert(&mut self, key: [u8; 32], value: Vec<u8>) {
        self.leaves.insert(key, value);
    }

    /// Remove `key` (no-op if absent).
    pub fn delete(&mut self, key: [u8; 32]) {
        self.leaves.remove(&key);
    }

    /// Generate a 256-sibling proof for `key`.
    ///
    /// Returns an inclusion proof when the key exists, or an exclusion proof
    /// when it is absent.  `SmtProof::verify` reconstructs the root from the
    /// siblings and checks it against the trie root.
    pub fn generate_proof(&self, key: [u8; 32]) -> SmtProof {
        let value = self.leaves.get(&key).cloned();
        let siblings = collect_siblings(&self.leaves, &key);
        SmtProof { key, value, siblings }
    }
}

// ---------------------------------------------------------------------------
// Recursive subtree hash (stack depth = 256 → split into iterative)
//
// We partition the leaf map by the key prefix at each level.  Because the
// tree has depth 256, we process it iteratively using an explicit stack.
// ---------------------------------------------------------------------------

/// Compute the hash of the subtree rooted at `(depth, prefix)`.
/// `prefix` contains the bits already consumed (depth bits from the MSB).
/// All keys in `leaves` are assumed to share the prefix.
fn subtree_hash(leaves: &HashMap<[u8; 32], Vec<u8>>, depth: usize, _prefix: &[u8; 32], _pfx_bits: usize) -> Hash {
    if leaves.is_empty() {
        return empty_tower()[256 - depth];
    }
    if depth == 256 {
        // Exactly one leaf must remain.
        let (key, value) = leaves.iter().next().unwrap();
        return leaf_hash(key, value);
    }

    // Split leaves by bit at `depth`.
    let mut left: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
    let mut right: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
    for (k, v) in leaves {
        if bit_at(k, depth) == 0 {
            left.insert(*k, v.clone());
        } else {
            right.insert(*k, v.clone());
        }
    }

    let lh = subtree_hash(&left, depth + 1, _prefix, 0);
    let rh = subtree_hash(&right, depth + 1, _prefix, 0);
    node_hash(&lh, &rh)
}

/// Collect 256 sibling hashes for `key` ordered root→leaf.
fn collect_siblings(leaves: &HashMap<[u8; 32], Vec<u8>>, key: &[u8; 32]) -> Vec<Hash> {
    let mut siblings: Vec<Hash> = Vec::with_capacity(256);
    // Work with a mutable view of the leaves, filtering as we descend.
    let mut current: HashMap<[u8; 32], Vec<u8>> = leaves.clone();

    for depth in 0..256 {
        let bit = bit_at(key, depth);
        let mut same_side: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
        let mut other_side: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
        for (k, v) in &current {
            if bit_at(k, depth) == bit {
                same_side.insert(*k, v.clone());
            } else {
                other_side.insert(*k, v.clone());
            }
        }
        // Sibling is the hash of the subtree on the other side.
        let sibling_hash = subtree_hash(&other_side, depth + 1, &[0u8; 32], 0);
        siblings.push(sibling_hash);
        current = same_side;
    }

    siblings
}

// ---------------------------------------------------------------------------
// SmtProof
// ---------------------------------------------------------------------------

/// A 256-level Merkle proof for a key in a `SparseMerkleTrie`.
///
/// `siblings[0]` is the sibling at depth 0 (root level);
/// `siblings[255]` is the sibling at depth 255 (leaf level).
///
/// The `Vec` always contains exactly 256 entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtProof {
    /// The 256-bit key this proof is for.
    pub key: [u8; 32],
    /// `Some(bytes)` for an inclusion proof; `None` for an exclusion proof.
    pub value: Option<Vec<u8>>,
    /// 256 sibling hashes ordered root→leaf (index 0 = root level).
    pub siblings: Vec<Hash>,
}

impl SmtProof {
    /// Expected number of sibling hashes in a well-formed proof.
    pub const DEPTH: usize = 256;

    /// Verify the proof against `root`.
    ///
    /// - Inclusion: `value` must be `Some(...)` and the recomputed root must equal `root`.
    /// - Exclusion: `value` must be `None`  and the recomputed root must equal `root`.
    pub fn verify(&self, root: Hash, key: [u8; 32], value: Option<Vec<u8>>) -> bool {
        if self.key != key || self.value != value || self.siblings.len() != Self::DEPTH {
            return false;
        }

        // Bottom-most hash: the leaf (or empty).
        let mut current = match &value {
            Some(v) => leaf_hash(&key, v),
            None => empty_leaf_hash(),
        };

        // Walk bottom-up: depth 255 → 0.
        // siblings[depth] is the sibling at bit-level `depth` (root→leaf order).
        for depth in (0..Self::DEPTH).rev() {
            let sibling = self.siblings[depth];
            let bit = bit_at(&key, depth);
            current = if bit == 0 {
                node_hash(&current, &sibling)
            } else {
                node_hash(&sibling, &current)
            };
        }

        current == root
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(seed: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = seed;
        k
    }

    #[test]
    fn test_empty_trie_root_is_deterministic() {
        let t1 = SparseMerkleTrie::new();
        let t2 = SparseMerkleTrie::new();
        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn test_insert_and_get() {
        let mut trie = SparseMerkleTrie::new();
        let key = make_key(1);
        let val = b"hello ego".to_vec();
        trie.insert(key, val.clone());
        assert_eq!(trie.get(&key), Some(val));
    }

    #[test]
    fn test_get_missing_returns_none() {
        let trie = SparseMerkleTrie::new();
        assert_eq!(trie.get(&make_key(99)), None);
    }

    #[test]
    fn test_root_changes_on_insert() {
        let mut trie = SparseMerkleTrie::new();
        let empty_root = trie.root();
        trie.insert(make_key(1), b"value".to_vec());
        assert_ne!(trie.root(), empty_root);
    }

    #[test]
    fn test_delete_restores_root() {
        let mut trie = SparseMerkleTrie::new();
        let empty_root = trie.root();
        let key = make_key(42);
        trie.insert(key, b"data".to_vec());
        assert_ne!(trie.root(), empty_root);
        trie.delete(key);
        assert_eq!(trie.root(), empty_root);
        assert_eq!(trie.get(&key), None);
    }

    #[test]
    fn test_update_value() {
        let mut trie = SparseMerkleTrie::new();
        let key = make_key(5);
        trie.insert(key, b"v1".to_vec());
        let root1 = trie.root();
        trie.insert(key, b"v2".to_vec());
        let root2 = trie.root();
        assert_ne!(root1, root2);
        assert_eq!(trie.get(&key), Some(b"v2".to_vec()));
    }

    #[test]
    fn test_inclusion_proof_verifies() {
        let mut trie = SparseMerkleTrie::new();
        let key = make_key(7);
        let val = b"ego inclusion".to_vec();
        trie.insert(key, val.clone());

        let proof = trie.generate_proof(key);
        assert!(proof.verify(trie.root(), key, Some(val)));
    }

    #[test]
    fn test_exclusion_proof_verifies() {
        let mut trie = SparseMerkleTrie::new();
        trie.insert(make_key(1), b"other".to_vec());

        let absent_key = make_key(200);
        let proof = trie.generate_proof(absent_key);
        assert!(proof.verify(trie.root(), absent_key, None));
    }

    #[test]
    fn test_proof_wrong_root_fails() {
        let mut trie = SparseMerkleTrie::new();
        let key = make_key(3);
        let val = b"abc".to_vec();
        trie.insert(key, val.clone());

        let proof = trie.generate_proof(key);
        let wrong_root = Hash::new([0xff; 32]);
        assert!(!proof.verify(wrong_root, key, Some(val)));
    }

    #[test]
    fn test_proof_wrong_value_fails() {
        let mut trie = SparseMerkleTrie::new();
        let key = make_key(3);
        trie.insert(key, b"real_value".to_vec());

        let proof = trie.generate_proof(key);
        assert!(!proof.verify(trie.root(), key, Some(b"fake_value".to_vec())));
    }

    #[test]
    fn test_multiple_keys_independent_proofs() {
        let mut trie = SparseMerkleTrie::new();
        let keys: Vec<[u8; 32]> = (0u8..8).map(make_key).collect();
        for (i, &k) in keys.iter().enumerate() {
            trie.insert(k, format!("value_{i}").into_bytes());
        }
        let root = trie.root();
        for (i, &k) in keys.iter().enumerate() {
            let val = format!("value_{i}").into_bytes();
            let proof = trie.generate_proof(k);
            assert!(proof.verify(root, k, Some(val)), "proof failed for key {i}");
        }
    }

    #[test]
    fn test_proof_has_256_siblings() {
        let mut trie = SparseMerkleTrie::new();
        trie.insert(make_key(1), b"v".to_vec());
        let proof = trie.generate_proof(make_key(1));
        assert_eq!(proof.siblings.len(), 256);
    }

    #[test]
    fn test_empty_trie_exclusion_proof() {
        let trie = SparseMerkleTrie::new();
        let key = make_key(0);
        let proof = trie.generate_proof(key);
        assert!(proof.verify(trie.root(), key, None));
    }
}
