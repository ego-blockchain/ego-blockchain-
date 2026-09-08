//! Merkle tree over note commitments, native and in-circuit.
//!
//! The pool records every commitment ever deposited. A withdrawal has to prove
//! its note is one of them without saying which, and a Merkle tree is what
//! makes that cheap: the prover shows a path from a leaf to the root that
//! everybody already knows, and the path reveals nothing about the leaf's
//! position beyond what the prover chooses to reveal, which is nothing.
//!
//! # Node hashing
//!
//! Nodes are `Poseidon(MERKLE_NODE_DOMAIN, left, right)`. The domain tag is
//! distinct from the commitment and nullifier tags on purpose. Without it, a
//! two-input node hash and a two-input nullifier hash would be the same
//! function, and a value that is a valid leaf could be reinterpreted as a
//! valid interior node or the reverse. Structural confusion of that kind is a
//! classic way a Merkle proof is forged.
//!
//! # Empty leaves
//!
//! An empty slot is `Fr::zero()`, and `zeros[i]` is the root of an all-empty
//! subtree of height `i`. A subtree entirely beyond the filled leaves is never
//! hashed; its root is `zeros[level]`. That is what lets a depth-20 tree
//! (a million slots) with three leaves in it be built in a few dozen hashes.
//!
//! # This is the reference implementation
//!
//! `root()` and `path()` recompute from the leaf vector each call, O(n) hashes.
//! That is exactly what the circuit is tested against and it is correct, but
//! a pool with a million notes wants an incremental tree that caches filled
//! subtrees, the way Tornado's contract does. That is an optimisation to be
//! built against this and checked for equality with it, not a replacement for
//! it.

use crate::poseidon_gadget::{poseidon_hash_gadget, PoseidonGadgetParams};
use ark_bn254::Fr;
use ark_ff::Zero;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;
use light_poseidon::{Poseidon, PoseidonHasher};

/// Distinct from `SHIELDED_COMMITMENT_DOMAIN` (1) and `SHIELDED_NULLIFIER_DOMAIN` (2).
pub const MERKLE_NODE_DOMAIN: u64 = 3;

/// Depth the pool will use: 2^20 = 1,048,576 notes. Tests use a small depth
/// so they run in milliseconds; nothing here depends on the value.
pub const POOL_TREE_DEPTH: usize = 20;

pub fn hash_node(left: Fr, right: Fr) -> Fr {
    let mut p = Poseidon::<Fr>::with_domain_tag_circom(2, Fr::from(MERKLE_NODE_DOMAIN))
        .expect("width 3 is in the bn254_x5 table");
    p.hash(&[left, right]).expect("two inputs for width 3")
}

#[derive(Debug, Clone, PartialEq)]
pub struct MerklePath {
    /// Sibling at each level, leaf level first.
    pub siblings: Vec<Fr>,
    /// Whether our node is the right child at each level, leaf level first.
    pub is_right: Vec<bool>,
}

impl MerklePath {
    /// The root this path claims, for `leaf`. Compare against the tree's root.
    pub fn compute_root(&self, leaf: Fr) -> Fr {
        self.siblings
            .iter()
            .zip(&self.is_right)
            .fold(leaf, |cur, (sib, right)| {
                if *right { hash_node(*sib, cur) } else { hash_node(cur, *sib) }
            })
    }

    pub fn depth(&self) -> usize {
        self.siblings.len()
    }
}

#[derive(Debug, Clone)]
pub struct MerkleTree {
    depth: usize,
    leaves: Vec<Fr>,
    zeros: Vec<Fr>,
}

impl MerkleTree {
    pub fn new(depth: usize) -> Self {
        let mut zeros = Vec::with_capacity(depth + 1);
        zeros.push(Fr::zero());
        for i in 1..=depth {
            let below = zeros[i - 1];
            zeros.push(hash_node(below, below));
        }
        Self { depth, leaves: Vec::new(), zeros }
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn capacity(&self) -> usize {
        1usize << self.depth
    }

    /// Append a leaf and return its index. Append-only, like the pool's
    /// commitment list: a leaf is never removed, because removing one would
    /// reveal which note was spent.
    pub fn insert(&mut self, leaf: Fr) -> Result<usize, String> {
        if self.leaves.len() >= self.capacity() {
            return Err(format!("tree of depth {} is full", self.depth));
        }
        self.leaves.push(leaf);
        Ok(self.leaves.len() - 1)
    }

    /// Node `idx` at `level`; level 0 is the leaves, level `depth` is the root.
    fn node(&self, level: usize, idx: usize) -> Fr {
        if level == 0 {
            return self.leaves.get(idx).copied().unwrap_or(self.zeros[0]);
        }
        // Everything under this node is beyond the filled leaves: it is the
        // all-empty subtree, whose root is precomputed.
        if (idx << level) >= self.leaves.len() {
            return self.zeros[level];
        }
        hash_node(self.node(level - 1, 2 * idx), self.node(level - 1, 2 * idx + 1))
    }

    pub fn root(&self) -> Fr {
        self.node(self.depth, 0)
    }

    pub fn path(&self, index: usize) -> Result<MerklePath, String> {
        if index >= self.leaves.len() {
            return Err(format!("no leaf at index {index}; tree has {}", self.leaves.len()));
        }
        let mut siblings = Vec::with_capacity(self.depth);
        let mut is_right = Vec::with_capacity(self.depth);
        let mut idx = index;
        for level in 0..self.depth {
            let right = idx & 1 == 1;
            let sibling_idx = if right { idx - 1 } else { idx + 1 };
            siblings.push(self.node(level, sibling_idx));
            is_right.push(right);
            idx >>= 1;
        }
        Ok(MerklePath { siblings, is_right })
    }
}

/// Recompute the root in-circuit from a leaf and its path. The caller enforces
/// equality with the public root; this only computes.
///
/// At each level the prover's bit decides which side the current node sits
/// on. Both orderings are selected with `conditionally_select` rather than
/// branching, because a circuit cannot branch: both candidates are computed
/// and the bit picks one, and the bit is itself constrained to be 0 or 1 by
/// its allocation as a `Boolean`.
pub fn merkle_root_gadget(
    leaf: &FpVar<Fr>,
    siblings: &[FpVar<Fr>],
    is_right: &[Boolean<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    if siblings.len() != is_right.len() {
        return Err(SynthesisError::Unsatisfiable);
    }
    let params = PoseidonGadgetParams::circom(2).map_err(|_| SynthesisError::Unsatisfiable)?;
    let domain = Fr::from(MERKLE_NODE_DOMAIN);
    let mut cur = leaf.clone();
    for (sib, right) in siblings.iter().zip(is_right) {
        let left_child = FpVar::conditionally_select(right, sib, &cur)?;
        let right_child = FpVar::conditionally_select(right, &cur, sib)?;
        cur = poseidon_hash_gadget(&params, domain, &[left_child, right_child])?;
    }
    Ok(cur)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon_gadget::{SHIELDED_COMMITMENT_DOMAIN, SHIELDED_NULLIFIER_DOMAIN};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::{test_rng, UniformRand};

    const DEPTH: usize = 4;

    fn leaf(i: u64) -> Fr {
        Fr::from(1_000 + i)
    }

    fn tree_with(n: usize) -> MerkleTree {
        let mut t = MerkleTree::new(DEPTH);
        for i in 0..n {
            t.insert(leaf(i as u64)).unwrap();
        }
        t
    }

    #[test]
    fn the_node_domain_is_distinct_from_the_note_domains() {
        // Structural confusion between a leaf and an interior node is how a
        // Merkle proof gets forged. These must never coincide.
        assert_ne!(MERKLE_NODE_DOMAIN, SHIELDED_COMMITMENT_DOMAIN);
        assert_ne!(MERKLE_NODE_DOMAIN, SHIELDED_NULLIFIER_DOMAIN);
    }

    #[test]
    fn an_empty_tree_has_the_precomputed_empty_root() {
        let t = MerkleTree::new(DEPTH);
        assert_eq!(t.root(), t.zeros[DEPTH]);
    }

    #[test]
    fn a_single_leaf_hashes_up_against_empty_siblings() {
        let t = tree_with(1);
        let mut expected = leaf(0);
        for level in 0..DEPTH {
            expected = hash_node(expected, t.zeros[level]);
        }
        assert_eq!(t.root(), expected);
    }

    #[test]
    fn every_leaf_has_a_path_that_reproduces_the_root() {
        // Seven leaves in a sixteen-slot tree: an odd count, so some nodes have
        // a real left child and an empty right one.
        let t = tree_with(7);
        let root = t.root();
        for i in 0..7 {
            let p = t.path(i).unwrap();
            assert_eq!(p.depth(), DEPTH);
            assert_eq!(p.compute_root(leaf(i as u64)), root, "leaf {i}");
        }
    }

    #[test]
    fn a_path_for_one_leaf_does_not_authenticate_another() {
        let t = tree_with(7);
        let p = t.path(2).unwrap();
        assert_ne!(p.compute_root(leaf(3)), t.root());
    }

    #[test]
    fn inserting_changes_the_root() {
        let mut t = tree_with(3);
        let before = t.root();
        t.insert(leaf(3)).unwrap();
        assert_ne!(t.root(), before);
    }

    #[test]
    fn the_tree_refuses_to_overflow() {
        let mut t = MerkleTree::new(2);
        for i in 0..4 {
            t.insert(leaf(i)).unwrap();
        }
        assert!(t.insert(leaf(4)).is_err());
        assert_eq!(t.len(), 4);
    }

    #[test]
    fn a_path_is_refused_for_a_leaf_that_does_not_exist() {
        let t = tree_with(3);
        assert!(t.path(3).is_err());
    }

    /// The in-circuit root must equal the native one for every leaf, or a
    /// legitimate withdrawal would fail to verify.
    #[test]
    fn the_gadget_reproduces_the_native_root_for_every_leaf() {
        let t = tree_with(7);
        let root = t.root();
        for i in 0..7 {
            let p = t.path(i).unwrap();
            let cs = ConstraintSystem::<Fr>::new_ref();
            let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf(i as u64))).unwrap();
            let sibs: Vec<FpVar<Fr>> = p
                .siblings
                .iter()
                .map(|s| FpVar::new_witness(cs.clone(), || Ok(*s)).unwrap())
                .collect();
            let bits: Vec<Boolean<Fr>> = p
                .is_right
                .iter()
                .map(|b| Boolean::new_witness(cs.clone(), || Ok(*b)).unwrap())
                .collect();
            let got = merkle_root_gadget(&leaf_var, &sibs, &bits).unwrap();
            assert!(cs.is_satisfied().unwrap());
            assert_eq!(got.value().unwrap(), root, "leaf {i}");
        }
    }

    #[test]
    fn a_tampered_sibling_changes_the_in_circuit_root() {
        let t = tree_with(5);
        let p = t.path(1).unwrap();
        let mut rng = test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf(1))).unwrap();
        let mut sibs: Vec<FpVar<Fr>> = p
            .siblings
            .iter()
            .map(|s| FpVar::new_witness(cs.clone(), || Ok(*s)).unwrap())
            .collect();
        sibs[2] = FpVar::new_witness(cs.clone(), || Ok(Fr::rand(&mut rng))).unwrap();
        let bits: Vec<Boolean<Fr>> = p
            .is_right
            .iter()
            .map(|b| Boolean::new_witness(cs.clone(), || Ok(*b)).unwrap())
            .collect();
        let got = merkle_root_gadget(&leaf_var, &sibs, &bits).unwrap();
        assert_ne!(got.value().unwrap(), t.root());
    }

    #[test]
    fn a_flipped_direction_bit_changes_the_in_circuit_root() {
        let t = tree_with(5);
        let p = t.path(1).unwrap();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf(1))).unwrap();
        let sibs: Vec<FpVar<Fr>> = p
            .siblings
            .iter()
            .map(|s| FpVar::new_witness(cs.clone(), || Ok(*s)).unwrap())
            .collect();
        let mut flipped = p.is_right.clone();
        flipped[0] = !flipped[0];
        let bits: Vec<Boolean<Fr>> = flipped
            .iter()
            .map(|b| Boolean::new_witness(cs.clone(), || Ok(*b)).unwrap())
            .collect();
        let got = merkle_root_gadget(&leaf_var, &sibs, &bits).unwrap();
        assert_ne!(got.value().unwrap(), t.root());
    }

    #[test]
    fn a_mismatched_path_length_is_refused() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let l = FpVar::new_witness(cs.clone(), || Ok(leaf(0))).unwrap();
        let s = FpVar::new_witness(cs.clone(), || Ok(leaf(1))).unwrap();
        assert!(merkle_root_gadget(&l, &[s], &[]).is_err());
    }
}
