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
//! # Two native trees, one answer
//!
//! `MerkleTree` keeps every level and is what a prover uses: it needs every
//! leaf anyway to compute a path, and with the levels cached an insert costs
//! one hash per level, a root nothing, and a path one lookup per level.
//!
//! `IncrementalTree` keeps only the frontier, one node per level, the way
//! Tornado's contract does. That is what consensus persists: an insert is
//! one hash per level and the entire state is a few hundred bytes, so a
//! million-note pool costs a validator the same per deposit as an empty one.
//! It cannot produce paths, which is fine, because validators never need one.
//!
//! The two are checked against each other after every insert, and both are
//! checked against a plain recursive definition of the root.

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

/// `zeros[i]` is the root of an all-empty subtree of height `i`, so
/// `zeros[0]` is an empty leaf and `zeros[depth]` the root of an empty tree.
pub fn empty_subtree_roots(depth: usize) -> Vec<Fr> {
    let mut zeros = Vec::with_capacity(depth + 1);
    zeros.push(Fr::zero());
    for i in 1..=depth {
        let below = zeros[i - 1];
        zeros.push(hash_node(below, below));
    }
    zeros
}

/// The siblings from a leaf up to the root, and on which side the leaf's
/// ancestor sits at each level.
#[derive(Debug, Clone, PartialEq)]
pub struct MerklePath {
    pub siblings: Vec<Fr>,
    pub is_right: Vec<bool>,
}

impl MerklePath {
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

/// The full tree, every level cached. Append-only.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    depth: usize,
    /// `levels[0]` holds the leaves; `levels[h]` holds every node of height
    /// `h` with at least one real leaf beneath it. Nodes beyond the end of a
    /// level are empty subtrees, whose roots are `zeros[h]`.
    levels: Vec<Vec<Fr>>,
    zeros: Vec<Fr>,
}

impl MerkleTree {
    pub fn new(depth: usize) -> Self {
        Self { depth, levels: vec![Vec::new(); depth + 1], zeros: empty_subtree_roots(depth) }
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn len(&self) -> usize {
        self.levels[0].len()
    }

    pub fn is_empty(&self) -> bool {
        self.levels[0].is_empty()
    }

    pub fn capacity(&self) -> usize {
        1usize << self.depth
    }

    pub fn leaves(&self) -> &[Fr] {
        &self.levels[0]
    }

    fn node(&self, level: usize, idx: usize) -> Fr {
        self.levels[level].get(idx).copied().unwrap_or(self.zeros[level])
    }

    /// Append a leaf and rehash its ancestors: one hash per level.
    pub fn insert(&mut self, leaf: Fr) -> Result<usize, String> {
        if self.len() >= self.capacity() {
            return Err(format!("tree of depth {} is full", self.depth));
        }
        let index = self.len();
        self.levels[0].push(leaf);
        let mut idx = index;
        for level in 0..self.depth {
            let parent = idx >> 1;
            let h = hash_node(self.node(level, parent * 2), self.node(level, parent * 2 + 1));
            let above = &mut self.levels[level + 1];
            if parent < above.len() {
                above[parent] = h;
            } else {
                above.push(h);
            }
            idx = parent;
        }
        Ok(index)
    }

    pub fn root(&self) -> Fr {
        self.node(self.depth, 0)
    }

    pub fn path(&self, index: usize) -> Result<MerklePath, String> {
        if index >= self.len() {
            return Err(format!("no leaf at index {index}; tree has {}", self.len()));
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

/// The frontier of the same tree: for each level, the most recent node that
/// still needs a right-hand sibling. Enough to append and to know the root,
/// and nothing more, so it is what gets persisted.
#[derive(Debug, Clone, PartialEq)]
pub struct IncrementalTree {
    depth: usize,
    next_index: usize,
    frontier: Vec<Fr>,
    root: Fr,
    zeros: Vec<Fr>,
}

impl IncrementalTree {
    pub fn new(depth: usize) -> Self {
        let zeros = empty_subtree_roots(depth);
        Self { depth, next_index: 0, frontier: zeros[..depth].to_vec(), root: zeros[depth], zeros }
    }

    /// Rebuild from persisted parts. The parts are trusted to have come from
    /// `parts()`; only their shape is checked here.
    pub fn from_parts(depth: usize, next_index: usize, frontier: Vec<Fr>, root: Fr) -> Result<Self, String> {
        if frontier.len() != depth {
            return Err(format!("frontier has {} entries for depth {depth}", frontier.len()));
        }
        if next_index > (1usize << depth) {
            return Err(format!("next index {next_index} exceeds a depth-{depth} tree"));
        }
        Ok(Self { depth, next_index, frontier, root, zeros: empty_subtree_roots(depth) })
    }

    pub fn parts(&self) -> (usize, usize, &[Fr], Fr) {
        (self.depth, self.next_index, &self.frontier, self.root)
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn len(&self) -> usize {
        self.next_index
    }

    pub fn is_empty(&self) -> bool {
        self.next_index == 0
    }

    pub fn capacity(&self) -> usize {
        1usize << self.depth
    }

    pub fn root(&self) -> Fr {
        self.root
    }

    pub fn frontier(&self) -> &[Fr] {
        &self.frontier
    }

    /// Append a leaf: one hash per level. At each level the new node is either
    /// a left child, in which case it is remembered as the frontier and hashed
    /// against an empty right sibling, or a right child, hashed against the
    /// frontier node its left sibling left behind.
    pub fn insert(&mut self, leaf: Fr) -> Result<usize, String> {
        if self.next_index >= self.capacity() {
            return Err(format!("tree of depth {} is full", self.depth));
        }
        let index = self.next_index;
        let mut cur = leaf;
        let mut idx = index;
        for level in 0..self.depth {
            if idx & 1 == 0 {
                self.frontier[level] = cur;
                cur = hash_node(cur, self.zeros[level]);
            } else {
                cur = hash_node(self.frontier[level], cur);
            }
            idx >>= 1;
        }
        self.root = cur;
        self.next_index += 1;
        Ok(index)
    }
}

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
    /// The plain definition, with nothing cached: the root of a subtree is the
    /// hash of its children, and an empty subtree is `zeros[height]`.
    fn reference_node(leaves: &[Fr], zeros: &[Fr], level: usize, idx: usize) -> Fr {
        if level == 0 {
            return leaves.get(idx).copied().unwrap_or(zeros[0]);
        }
        if (idx << level) >= leaves.len() {
            return zeros[level];
        }
        hash_node(
            reference_node(leaves, zeros, level - 1, 2 * idx),
            reference_node(leaves, zeros, level - 1, 2 * idx + 1),
        )
    }

    #[test]
    fn the_cached_tree_matches_the_recursive_definition_at_every_size() {
        let zeros = empty_subtree_roots(DEPTH);
        let mut t = MerkleTree::new(DEPTH);
        for n in 0..=(1usize << DEPTH) {
            assert_eq!(t.root(), reference_node(t.leaves(), &zeros, DEPTH, 0), "{n} leaves");
            if n < (1usize << DEPTH) {
                t.insert(leaf(n as u64)).unwrap();
            }
        }
    }

    #[test]
    fn the_incremental_tree_matches_the_full_tree_after_every_insert() {
        let depth = 5;
        let mut rng = test_rng();
        let mut full = MerkleTree::new(depth);
        let mut inc = IncrementalTree::new(depth);
        assert_eq!(inc.root(), full.root(), "empty");
        for i in 0..(1usize << depth) {
            let l = Fr::rand(&mut rng);
            assert_eq!(full.insert(l).unwrap(), i);
            assert_eq!(inc.insert(l).unwrap(), i);
            assert_eq!(inc.root(), full.root(), "after leaf {i}");
        }
        assert!(full.insert(Fr::rand(&mut rng)).is_err());
        assert!(inc.insert(Fr::rand(&mut rng)).is_err());
        assert_eq!(inc.len(), full.len());
    }

    #[test]
    fn an_incremental_tree_starts_at_the_empty_root() {
        assert_eq!(IncrementalTree::new(DEPTH).root(), MerkleTree::new(DEPTH).root());
    }

    #[test]
    fn an_incremental_tree_round_trips_through_its_parts() {
        let mut inc = IncrementalTree::new(DEPTH);
        for i in 0..7 {
            inc.insert(leaf(i)).unwrap();
        }
        let (depth, next, frontier, root) = inc.parts();
        let mut restored = IncrementalTree::from_parts(depth, next, frontier.to_vec(), root).unwrap();
        assert_eq!(restored, inc);
        restored.insert(leaf(7)).unwrap();
        inc.insert(leaf(7)).unwrap();
        assert_eq!(restored.root(), inc.root());
        assert_eq!(restored.root(), tree_with(8).root());
    }

    #[test]
    fn parts_of_the_wrong_shape_are_refused() {
        let zeros = empty_subtree_roots(DEPTH);
        assert!(IncrementalTree::from_parts(DEPTH, 0, zeros[..DEPTH - 1].to_vec(), zeros[DEPTH]).is_err());
        assert!(IncrementalTree::from_parts(DEPTH, (1 << DEPTH) + 1, zeros[..DEPTH].to_vec(), zeros[DEPTH]).is_err());
        assert!(IncrementalTree::from_parts(DEPTH, 1 << DEPTH, zeros[..DEPTH].to_vec(), zeros[DEPTH]).is_ok());
    }
}
