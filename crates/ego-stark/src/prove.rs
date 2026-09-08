use crate::air::{
    build_trace, nullifier_of, root_of, PublicInputs, Witness, WithdrawAir, POOL_TREE_DEPTH,
    TRACE_LEN,
};
use crate::merkle::MerklePath;
use crate::note::{leaf_for, withdrawal_binding, Note, NoteError};
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

pub struct WithdrawProver {
    options: ProofOptions,
    public: PublicInputs,
}

impl Prover for WithdrawProver {
    type BaseField = Elem;
    type Air = WithdrawAir;
    type Trace = TraceTable<Elem>;
    type HashFn = Hash;
    type VC = Vc;
    type RandomCoin = Coin;
    type TraceLde<E: FieldElement<BaseField = Elem>> = DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Elem>> =
        DefaultConstraintEvaluator<'a, WithdrawAir, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> PublicInputs {
        self.public.clone()
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
        air: &'a WithdrawAir,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

#[derive(Debug)]
pub struct Withdrawal {
    pub proof: Proof,
    pub public: PublicInputs,
}

impl Withdrawal {
    pub fn size_bytes(&self) -> usize {
        self.proof.to_bytes().len()
    }
}

pub fn prove_withdrawal(
    note: &Note,
    path: &MerklePath,
    recipient: &[u8; 32],
    fee_uegoc: u64,
    options: ProofOptions,
) -> Result<Withdrawal, String> {
    if path.depth() != POOL_TREE_DEPTH {
        return Err(format!("path depth {} is not {POOL_TREE_DEPTH}", path.depth()));
    }
    if fee_uegoc >= note.value_uegoc {
        return Err("the fee would consume the whole note".into());
    }
    let amount = note.value_uegoc;
    let commitment = note.commitment().map_err(err)?;
    let leaf = leaf_for(&commitment, amount).map_err(err)?;
    if path.compute_root(leaf) == crate::merkle::empty_subtree_roots(POOL_TREE_DEPTH)[POOL_TREE_DEPTH]
    {
        return Err("the path leads to an empty tree".into());
    }
    let binding = withdrawal_binding(recipient, fee_uegoc).map_err(err)?;

    let (secret, rho) = note.witness();
    let witness = Witness { secret, rho, amount: Elem::new(amount), path: path.clone() };
    let trace = build_trace(&witness);

    let computed_root = root_of(&trace);
    if computed_root != path.compute_root(leaf) {
        return Err("the trace root disagrees with the native path".into());
    }
    if nullifier_of(&trace) != note.nullifier() {
        return Err("the trace nullifier disagrees with the note".into());
    }

    let public = PublicInputs {
        root: computed_root,
        nullifier: note.nullifier(),
        amount,
        binding,
    };
    let prover = WithdrawProver { options, public: public.clone() };
    let proof = prover.prove(trace).map_err(|e| e.to_string())?;
    Ok(Withdrawal { proof, public })
}

fn err(e: NoteError) -> String {
    format!("{e:?}")
}

pub fn verify_withdrawal(
    proof: Proof,
    public: PublicInputs,
    options: &ProofOptions,
) -> Result<(), String> {
    winterfell::verify::<WithdrawAir, Hash, Coin, Vc>(
        proof,
        public,
        &AcceptableOptions::OptionSet(vec![options.clone()]),
    )
    .map_err(|e| e.to_string())
}

pub const EXPECTED_TRACE_LEN: usize = TRACE_LEN;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::MerkleTree;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const AMOUNT: u64 = 1_000_000;
    const FEE: u64 = 1_000;

    fn rng() -> StdRng {
        StdRng::from_entropy()
    }

    fn recipient() -> [u8; 32] {
        [0xAB; 32]
    }

    fn funded(n: usize, rng: &mut StdRng) -> (MerkleTree, Vec<Note>) {
        let mut tree = MerkleTree::new(POOL_TREE_DEPTH);
        let mut notes = Vec::new();
        for _ in 0..n {
            let note = Note::random(AMOUNT, rng);
            tree.insert(note.leaf().unwrap()).unwrap();
            notes.push(note);
        }
        (tree, notes)
    }

    #[test]
    fn the_trace_shape_is_a_power_of_two() {
        assert!(EXPECTED_TRACE_LEN.is_power_of_two());
        assert_eq!(EXPECTED_TRACE_LEN, 256);
    }

    #[test]
    fn an_honest_withdrawal_verifies() {
        let mut r = rng();
        let (tree, notes) = funded(4, &mut r);
        let options = default_options();
        let path = tree.path(2).unwrap();
        let w = prove_withdrawal(&notes[2], &path, &recipient(), FEE, options.clone()).unwrap();
        assert_eq!(w.public.root, tree.root());
        assert_eq!(w.public.nullifier, notes[2].nullifier());
        assert_eq!(w.public.amount, AMOUNT);
        assert!(verify_withdrawal(w.proof, w.public, &options).is_ok());
    }

    #[test]
    fn every_note_in_the_pool_can_spend_itself() {
        let mut r = rng();
        let (tree, notes) = funded(3, &mut r);
        let options = default_options();
        for (i, note) in notes.iter().enumerate() {
            let path = tree.path(i).unwrap();
            let w = prove_withdrawal(note, &path, &recipient(), FEE, options.clone()).unwrap();
            assert!(verify_withdrawal(w.proof, w.public, &options).is_ok(), "note {i}");
        }
    }

    #[test]
    fn the_proof_is_bound_to_its_nullifier() {
        let mut r = rng();
        let (tree, notes) = funded(3, &mut r);
        let options = default_options();
        let path = tree.path(1).unwrap();
        let w = prove_withdrawal(&notes[1], &path, &recipient(), FEE, options.clone()).unwrap();
        let mut hijacked = w.public.clone();
        hijacked.nullifier = notes[0].nullifier();
        assert!(
            verify_withdrawal(w.proof, hijacked, &options).is_err(),
            "swapping the nullifier must invalidate the proof"
        );
    }

    #[test]
    fn the_proof_is_bound_to_its_root() {
        let mut r = rng();
        let (tree, notes) = funded(3, &mut r);
        let options = default_options();
        let path = tree.path(0).unwrap();
        let w = prove_withdrawal(&notes[0], &path, &recipient(), FEE, options.clone()).unwrap();
        let mut hijacked = w.public.clone();
        hijacked.root = notes[1].leaf().unwrap();
        assert!(verify_withdrawal(w.proof, hijacked, &options).is_err());
    }

    #[test]
    fn the_proof_is_bound_to_its_amount() {
        let mut r = rng();
        let (tree, notes) = funded(3, &mut r);
        let options = default_options();
        let path = tree.path(0).unwrap();
        let w = prove_withdrawal(&notes[0], &path, &recipient(), FEE, options.clone()).unwrap();
        let mut hijacked = w.public.clone();
        hijacked.amount = AMOUNT * 2;
        assert!(
            verify_withdrawal(w.proof, hijacked, &options).is_err(),
            "claiming a different amount must invalidate the proof"
        );
    }

    #[test]
    fn the_proof_is_bound_to_the_recipient_and_the_fee() {
        let mut r = rng();
        let (tree, notes) = funded(3, &mut r);
        let options = default_options();
        let path = tree.path(0).unwrap();
        let w = prove_withdrawal(&notes[0], &path, &recipient(), FEE, options.clone()).unwrap();

        let mut redirected = w.public.clone();
        redirected.binding = withdrawal_binding(&[0xCD; 32], FEE).unwrap();
        assert!(
            verify_withdrawal(w.proof.clone(), redirected, &options).is_err(),
            "a relayer must not be able to redirect the payout"
        );

        let mut overcharged = w.public.clone();
        overcharged.binding = withdrawal_binding(&recipient(), FEE + 1).unwrap();
        assert!(
            verify_withdrawal(w.proof, overcharged, &options).is_err(),
            "a relayer must not be able to raise the fee"
        );
    }

    #[test]
    fn a_note_that_is_not_in_the_pool_cannot_reach_its_root() {
        let mut r = rng();
        let (tree, _) = funded(4, &mut r);
        let options = default_options();
        let stranger = Note::random(AMOUNT, &mut r);
        let path = tree.path(1).unwrap();
        let w = prove_withdrawal(&stranger, &path, &recipient(), FEE, options.clone()).unwrap();
        assert_ne!(w.public.root, tree.root(), "an outsider reaches a different root");
        let mut claimed = w.public.clone();
        claimed.root = tree.root();
        assert!(verify_withdrawal(w.proof, claimed, &options).is_err());
    }

    #[test]
    fn a_note_deposited_at_a_different_amount_cannot_be_spent_for_more() {
        let mut r = rng();
        let mut tree = MerkleTree::new(POOL_TREE_DEPTH);
        let note = Note::random(10_000_000, &mut r);
        let understated = leaf_for(&note.commitment().unwrap(), 1_000_000).unwrap();
        tree.insert(understated).unwrap();
        let options = default_options();
        let path = tree.path(0).unwrap();
        let w = prove_withdrawal(&note, &path, &recipient(), FEE, options).unwrap();
        assert_ne!(
            w.public.root,
            tree.root(),
            "a note claiming more than was deposited is not under the real root"
        );
    }

    #[test]
    fn a_fee_that_eats_the_note_is_refused() {
        let mut r = rng();
        let (tree, notes) = funded(2, &mut r);
        let path = tree.path(0).unwrap();
        assert!(
            prove_withdrawal(&notes[0], &path, &recipient(), AMOUNT, default_options()).is_err()
        );
    }

    #[test]
    fn a_path_of_the_wrong_depth_is_refused() {
        let mut r = rng();
        let (_, notes) = funded(1, &mut r);
        let shallow = MerkleTree::new(4);
        let mut t = shallow;
        t.insert(notes[0].leaf().unwrap()).unwrap();
        let path = t.path(0).unwrap();
        assert!(
            prove_withdrawal(&notes[0], &path, &recipient(), FEE, default_options()).is_err()
        );
    }

    #[test]
    fn the_proof_stays_small_enough_to_carry() {
        let mut r = rng();
        let (tree, notes) = funded(2, &mut r);
        let options = default_options();
        let path = tree.path(0).unwrap();
        let w = prove_withdrawal(&notes[0], &path, &recipient(), FEE, options).unwrap();
        let size = w.size_bytes();
        assert!(size < 200_000, "{size} bytes is too large per transaction");
        assert!(size > 1_000, "{size} bytes is implausibly small for a STARK");
    }
}
