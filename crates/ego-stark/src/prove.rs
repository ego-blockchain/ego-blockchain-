use crate::air::{build_trace, root_of, MerklePathAir, PublicInputs, TRACE_LEN};
use crate::merkle::MerklePath;
use crate::{Digest, Elem, Hash};
use winterfell::crypto::DefaultRandomCoin;
use winterfell::crypto::MerkleTree as VectorCommit;
use winterfell::math::FieldElement;
use winterfell::{
    AcceptableOptions, AuxRandElements, ConstraintCompositionCoefficients,
    DefaultConstraintEvaluator, DefaultTraceLde, FieldExtension, PartitionOptions, Proof,
    ProofOptions, Prover, StarkDomain, TraceInfo, TracePolyTable, TraceTable,
};

pub type Coin = DefaultRandomCoin<Hash>;
pub type Vc = VectorCommit<Hash>;

pub fn default_options() -> ProofOptions {
    ProofOptions::new(28, 8, 8, FieldExtension::Quadratic, 8, 255)
}

pub struct MerklePathProver {
    options: ProofOptions,
}

impl MerklePathProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }
}

impl Prover for MerklePathProver {
    type BaseField = Elem;
    type Air = MerklePathAir;
    type Trace = TraceTable<Elem>;
    type HashFn = Hash;
    type VC = Vc;
    type RandomCoin = Coin;
    type TraceLde<E: FieldElement<BaseField = Elem>> = DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Elem>> =
        DefaultConstraintEvaluator<'a, MerklePathAir, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        PublicInputs { root: root_of(trace) }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Elem>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &winterfell::matrix::ColMatrix<Elem>,
        domain: &StarkDomain<Elem>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Elem>>(
        &self,
        air: &'a MerklePathAir,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

#[derive(Debug)]
pub struct MembershipProof {
    pub proof: Proof,
    pub root: Digest,
}

impl MembershipProof {
    pub fn size_bytes(&self) -> usize {
        self.proof.to_bytes().len()
    }
}

pub fn prove_membership(
    leaf: Digest,
    path: &MerklePath,
    options: ProofOptions,
) -> Result<MembershipProof, String> {
    if path.compute_root(leaf) != path_root(leaf, path) {
        return Err("path does not reproduce its own root".into());
    }
    let trace = build_trace(leaf, path);
    let root = root_of(&trace);
    if root != path.compute_root(leaf) {
        return Err("trace root disagrees with the native path".into());
    }
    let prover = MerklePathProver::new(options);
    let proof = prover.prove(trace).map_err(|e| e.to_string())?;
    Ok(MembershipProof { proof, root })
}

fn path_root(leaf: Digest, path: &MerklePath) -> Digest {
    path.compute_root(leaf)
}

pub fn verify_membership(proof: MembershipProof, options: &ProofOptions) -> Result<(), String> {
    let pub_inputs = PublicInputs { root: proof.root };
    winterfell::verify::<MerklePathAir, Hash, Coin, Vc>(
        proof.proof,
        pub_inputs,
        &AcceptableOptions::OptionSet(vec![options.clone()]),
    )
    .map_err(|e| e.to_string())
}

pub fn verify_against_root(
    proof: Proof,
    root: Digest,
    options: &ProofOptions,
) -> Result<(), String> {
    winterfell::verify::<MerklePathAir, Hash, Coin, Vc>(
        proof,
        PublicInputs { root },
        &AcceptableOptions::OptionSet(vec![options.clone()]),
    )
    .map_err(|e| e.to_string())
}

pub const EXPECTED_TRACE_LEN: usize = TRACE_LEN;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{MerkleTree, POOL_TREE_DEPTH};
    use crate::note::Note;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn rng() -> StdRng {
        StdRng::from_entropy()
    }

    fn tree_with(n: usize, rng: &mut StdRng) -> (MerkleTree, Vec<Digest>) {
        let mut t = MerkleTree::new(POOL_TREE_DEPTH);
        let mut leaves = Vec::new();
        for _ in 0..n {
            let l = Note::random(1_000_000, rng).leaf().unwrap();
            t.insert(l).unwrap();
            leaves.push(l);
        }
        (t, leaves)
    }

    #[test]
    fn the_pool_depth_matches_the_trace_shape() {
        assert_eq!(POOL_TREE_DEPTH, crate::air::POOL_TREE_DEPTH);
        assert_eq!(EXPECTED_TRACE_LEN, crate::air::CYCLE * POOL_TREE_DEPTH);
        assert!(EXPECTED_TRACE_LEN.is_power_of_two(), "a STARK trace must be a power of two");
    }

    #[test]
    fn the_trace_reproduces_the_native_root() {
        let mut r = rng();
        let (tree, leaves) = tree_with(9, &mut r);
        for (i, leaf) in leaves.iter().enumerate() {
            let path = tree.path(i).unwrap();
            let trace = crate::air::build_trace(*leaf, &path);
            assert_eq!(
                crate::air::root_of(&trace),
                tree.root(),
                "the trace and the native tree disagree at leaf {i}"
            );
        }
    }

    #[test]
    fn an_honest_membership_proof_verifies() {
        let mut r = rng();
        let (tree, leaves) = tree_with(5, &mut r);
        let options = default_options();
        let path = tree.path(3).unwrap();
        let proof = prove_membership(leaves[3], &path, options.clone()).unwrap();
        assert_eq!(proof.root, tree.root());
        assert!(proof.size_bytes() > 0);
        assert!(verify_membership(proof, &options).is_ok());
    }

    #[test]
    fn every_leaf_in_the_tree_can_prove_itself() {
        let mut r = rng();
        let (tree, leaves) = tree_with(4, &mut r);
        let options = default_options();
        for (i, leaf) in leaves.iter().enumerate() {
            let path = tree.path(i).unwrap();
            let proof = prove_membership(*leaf, &path, options.clone()).unwrap();
            assert!(verify_membership(proof, &options).is_ok(), "leaf {i}");
        }
    }

    #[test]
    fn a_proof_does_not_verify_against_a_different_root() {
        let mut r = rng();
        let (tree, leaves) = tree_with(5, &mut r);
        let options = default_options();
        let path = tree.path(1).unwrap();
        let proof = prove_membership(leaves[1], &path, options.clone()).unwrap();

        let other = Note::random(1, &mut r).leaf().unwrap();
        assert!(
            verify_against_root(proof.proof, other, &options).is_err(),
            "a membership proof must be bound to the root it was made against"
        );
    }

    #[test]
    fn a_leaf_that_is_not_in_the_tree_cannot_reach_its_root() {
        let mut r = rng();
        let (tree, _) = tree_with(5, &mut r);
        let options = default_options();
        let stranger = Note::random(7, &mut r).leaf().unwrap();
        let path = tree.path(2).unwrap();

        let proof = prove_membership(stranger, &path, options.clone()).unwrap();
        assert_ne!(proof.root, tree.root(), "an outsider's leaf reaches a different root");
        assert!(
            verify_against_root(proof.proof, tree.root(), &options).is_err(),
            "and that proof must not verify against the real root"
        );
    }

    #[test]
    fn a_tampered_sibling_reaches_a_different_root() {
        let mut r = rng();
        let (tree, leaves) = tree_with(6, &mut r);
        let mut path = tree.path(4).unwrap();
        path.siblings[0] = Note::random(3, &mut r).leaf().unwrap();
        let trace = crate::air::build_trace(leaves[4], &path);
        assert_ne!(crate::air::root_of(&trace), tree.root());
    }

    #[test]
    fn a_flipped_direction_bit_reaches_a_different_root() {
        let mut r = rng();
        let (tree, leaves) = tree_with(6, &mut r);
        let mut path = tree.path(4).unwrap();
        path.is_right[0] = !path.is_right[0];
        let trace = crate::air::build_trace(leaves[4], &path);
        assert_ne!(crate::air::root_of(&trace), tree.root());
    }

    #[test]
    fn the_proof_stays_small_enough_to_put_in_a_transaction() {
        let mut r = rng();
        let (tree, leaves) = tree_with(3, &mut r);
        let options = default_options();
        let path = tree.path(0).unwrap();
        let proof = prove_membership(leaves[0], &path, options).unwrap();
        let size = proof.size_bytes();
        assert!(size < 200_000, "{size} bytes is too large to carry per transaction");
        assert!(size > 1_000, "{size} bytes is implausibly small for a STARK");
    }
}
