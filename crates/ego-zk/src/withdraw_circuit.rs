//! The withdrawal circuit for the shielded pool.
//!
//! # What a withdrawal proves
//!
//! Publicly: a Merkle root, a nullifier, an amount, and a recipient.
//! Privately: a note (value, secret, rho) and a path in the commitment tree.
//!
//! The proof establishes, without revealing the note or its position:
//!
//! 1. `Poseidon(LEAF, Poseidon(COMMITMENT, value, secret, rho), amount)` is a
//!    leaf under the public root. The outer hash is the important half: the
//!    chain builds the same one at deposit time from the commitment in the
//!    memo and the amount it actually received, so a commitment made for one
//!    value has no leaf under any other amount.
//! 2. The public nullifier is `Poseidon(NULLIFIER, secret, rho)` for that same
//!    secret and rho. This is what stops one note being spent twice: the pool
//!    records nullifiers, and a second spend of the same note would have to
//!    publish the same one.
//! 3. `amount == value`. A note is spent whole. The verifier builds the public
//!    amount from the transaction's `u64`, so the note's value is pinned to a
//!    64-bit quantity without any range proof, and there is no field
//!    arithmetic to wrap.
//! 4. A public binding value is tied into the proof. The chain sets it to a
//!    hash of the recipient and the fee, so a relayer who submits the
//!    transaction on the prover's behalf can neither redirect the payout nor
//!    raise the fee: changing either changes a public input and invalidates
//!    the proof.
//!
//! # Why the leaf carries the amount
//!
//! The value a withdrawal pays out lives inside the commitment, chosen by the
//! depositor, and the chain cannot see it: it has neither the secret nor rho.
//! An earlier version put the bare commitment in the tree, so nothing related
//! the value proved here to the amount actually deposited, and a one-EGOC
//! deposit could be withdrawn as ten thousand with an entirely honest proof.
//! Hashing the amount into the leaf closes that: the chain fixes one half of
//! the leaf from a number it saw for itself.
//!
//! # Why a note is spent whole
//!
//! An earlier version allowed `amount <= value`. Without a change output, the
//! difference was not returned to the spender; it stayed in the pool with no
//! nullifier that could ever release it. Equality removes that trap at the
//! protocol level rather than trusting every wallet to avoid it. Fixed
//! denominations, enforced by the chain on deposit and withdrawal, are what
//! keep the amount from identifying the note.
//!
//! # What the accounting layer still checks
//!
//! `shielded.rs::withdraw` independently enforces solvency and the
//! never-more-than-deposited rule. The proof narrows what a spender can
//! *claim*; the accounting still decides what may be *paid*. Neither is the
//! only thing between the pool and zero.
//!
//! # What the tests do and do not establish
//!
//! The negative tests below are the closest thing to a soundness check that
//! tests can offer: each one hands the circuit a dishonest witness of a kind an
//! attacker would try, and requires the constraint system to reject it. They
//! cover the attacks the author thought of. Soundness is the claim that *no*
//! dishonest witness passes, which is a universal statement over an infinite
//! space and cannot be reached by enumeration. That is why the pool remains
//! disabled until this has been reviewed by somebody who does this for a
//! living, and it is stated here so nobody reads a green test suite as that
//! review.

use crate::merkle::merkle_root_gadget;
use crate::poseidon_gadget::{commitment_gadget, leaf_gadget, nullifier_gadget};
use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
// Re-exported so the pool can name proof and key types without depending on
// ark-groth16 itself and having to keep a second copy of the version pin.
pub use ark_groth16::{Proof, ProvingKey, VerifyingKey};
pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};

/// One withdrawal. Every field is `Option` because the same struct serves for
/// setup, where no values exist and only the shape matters, and for proving.
#[derive(Clone, Debug)]
pub struct WithdrawCircuit {
    pub depth: usize,
    // Public inputs, in the order `public_inputs` lists them.
    pub root: Option<Fr>,
    pub nullifier: Option<Fr>,
    pub amount: Option<Fr>,
    pub recipient: Option<Fr>,
    // Private witness.
    pub value: Option<Fr>,
    pub secret: Option<Fr>,
    pub rho: Option<Fr>,
    pub siblings: Option<Vec<Fr>>,
    pub is_right: Option<Vec<bool>>,
}

impl WithdrawCircuit {
    /// The circuit's shape and nothing else, for key generation.
    pub fn blank(depth: usize) -> Self {
        Self {
            depth,
            root: None,
            nullifier: None,
            amount: None,
            recipient: None,
            value: None,
            secret: None,
            rho: None,
            siblings: None,
            is_right: None,
        }
    }

    /// The public inputs in allocation order. The verifier must be given
    /// exactly this, so it is defined once here rather than assembled by hand
    /// at each call site, where the order would drift. `recipient` is the
    /// binding slot; what it binds is the chain's decision, not the circuit's.
    pub fn public_inputs(root: Fr, nullifier: Fr, amount: Fr, recipient: Fr) -> Vec<Fr> {
        vec![root, nullifier, amount, recipient]
    }
}

impl ConstraintSynthesizer<Fr> for WithdrawCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let WithdrawCircuit {
            depth,
            root,
            nullifier,
            amount,
            recipient,
            value,
            secret,
            rho,
            siblings,
            is_right,
        } = self;

        let root_in = FpVar::new_input(cs.clone(), || root.ok_or(SynthesisError::AssignmentMissing))?;
        let nullifier_in =
            FpVar::new_input(cs.clone(), || nullifier.ok_or(SynthesisError::AssignmentMissing))?;
        let amount_in =
            FpVar::new_input(cs.clone(), || amount.ok_or(SynthesisError::AssignmentMissing))?;
        let recipient_in =
            FpVar::new_input(cs.clone(), || recipient.ok_or(SynthesisError::AssignmentMissing))?;

        let value_w = FpVar::new_witness(cs.clone(), || value.ok_or(SynthesisError::AssignmentMissing))?;
        let secret_w =
            FpVar::new_witness(cs.clone(), || secret.ok_or(SynthesisError::AssignmentMissing))?;
        let rho_w = FpVar::new_witness(cs.clone(), || rho.ok_or(SynthesisError::AssignmentMissing))?;

        let siblings_ref = &siblings;
        let is_right_ref = &is_right;
        let sibling_vars: Vec<FpVar<Fr>> = (0..depth)
            .map(|i| {
                FpVar::new_witness(cs.clone(), || {
                    siblings_ref
                        .as_ref()
                        .and_then(|v| v.get(i).copied())
                        .ok_or(SynthesisError::AssignmentMissing)
                })
            })
            .collect::<Result<_, _>>()?;
        let direction_vars: Vec<Boolean<Fr>> = (0..depth)
            .map(|i| {
                Boolean::new_witness(cs.clone(), || {
                    is_right_ref
                        .as_ref()
                        .and_then(|v| v.get(i).copied())
                        .ok_or(SynthesisError::AssignmentMissing)
                })
            })
            .collect::<Result<_, _>>()?;

        // 1. The note is in the tree, under the amount it was deposited for.
        let commitment = commitment_gadget(&value_w, &secret_w, &rho_w)?;
        let leaf = leaf_gadget(&commitment, &amount_in)?;
        let computed_root = merkle_root_gadget(&leaf, &sibling_vars, &direction_vars)?;
        computed_root.enforce_equal(&root_in)?;

        // 2. The nullifier is this note's, not one for some other note.
        let computed_nullifier = nullifier_gadget(&secret_w, &rho_w)?;
        computed_nullifier.enforce_equal(&nullifier_in)?;

        // 3. The note is spent whole: its value is the public amount.
        value_w.enforce_equal(&amount_in)?;

        // 4. Bind the public binding value. Multiplying it by itself emits one
        // constraint that mentions it, so it is a genuine part of the
        // statement being proved rather than a public input the circuit never
        // touches.
        let _bound = &recipient_in * &recipient_in;

        Ok(())
    }
}

pub fn setup<R: RngCore + CryptoRng>(
    depth: usize,
    rng: &mut R,
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), String> {
    Groth16::<Bn254>::circuit_specific_setup(WithdrawCircuit::blank(depth), rng)
        .map_err(|e| e.to_string())
}

pub fn prove<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    circuit: WithdrawCircuit,
    rng: &mut R,
) -> Result<Proof<Bn254>, String> {
    Groth16::<Bn254>::prove(pk, circuit, rng).map_err(|e| e.to_string())
}

pub fn verify(
    vk: &VerifyingKey<Bn254>,
    public_inputs: &[Fr],
    proof: &Proof<Bn254>,
) -> Result<bool, String> {
    Groth16::<Bn254>::verify(vk, public_inputs, proof).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::MerkleTree;
    use crate::poseidon_gadget::{
        SHIELDED_COMMITMENT_DOMAIN, SHIELDED_LEAF_DOMAIN, SHIELDED_NULLIFIER_DOMAIN,
    };
    use ark_ff::One;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use ark_std::{test_rng, UniformRand};
    use light_poseidon::{Poseidon, PoseidonHasher};

    const DEPTH: usize = 4;

    /// Groth16 needs a CryptoRng. `test_rng()` returns `impl Rng`, which erases
    /// that impl; a seeded StdRng keeps the tests deterministic and satisfies it.
    fn crypto_rng() -> StdRng {
        StdRng::seed_from_u64(7)
    }

    fn native(domain: u64, inputs: &[Fr]) -> Fr {
        let mut p = Poseidon::<Fr>::with_domain_tag_circom(inputs.len(), Fr::from(domain)).unwrap();
        p.hash(inputs).unwrap()
    }

    struct Fixture {
        tree: MerkleTree,
        index: usize,
        value: Fr,
        secret: Fr,
        rho: Fr,
        recipient: Fr,
    }

    /// The tree leaf for a note deposited at `amount`, exactly as the chain
    /// builds it: the commitment wrapped with the amount it received.
    fn leaf_of(value: Fr, secret: Fr, rho: Fr, amount: Fr) -> Fr {
        let commitment = native(SHIELDED_COMMITMENT_DOMAIN, &[value, secret, rho]);
        native(SHIELDED_LEAF_DOMAIN, &[commitment, amount])
    }

    /// A tree with other people's notes around ours, so the path is not
    /// trivial. The note is deposited at its own value, which is the honest
    /// case; `deposited_at` builds the dishonest one.
    fn fixture_fr(value: Fr) -> Fixture {
        deposited_at(value, value)
    }

    /// A note whose commitment says `value` but which was deposited for
    /// `amount`. The chain allows this to be *written*, because it cannot see
    /// the value; the circuit is what must refuse to spend it.
    fn deposited_at(value: Fr, amount: Fr) -> Fixture {
        let mut rng = test_rng();
        let mut tree = MerkleTree::new(DEPTH);
        for i in 0..3u64 {
            tree.insert(Fr::from(500 + i)).unwrap();
        }
        let secret = Fr::rand(&mut rng);
        let rho = Fr::rand(&mut rng);
        let index = tree.insert(leaf_of(value, secret, rho, amount)).unwrap();
        tree.insert(Fr::from(999u64)).unwrap();
        Fixture { tree, index, value, secret, rho, recipient: Fr::rand(&mut rng) }
    }

    fn fixture(value: u64) -> Fixture {
        fixture_fr(Fr::from(value))
    }

    fn circuit(f: &Fixture, amount: u64) -> WithdrawCircuit {
        let path = f.tree.path(f.index).unwrap();
        WithdrawCircuit {
            depth: DEPTH,
            root: Some(f.tree.root()),
            nullifier: Some(native(SHIELDED_NULLIFIER_DOMAIN, &[f.secret, f.rho])),
            amount: Some(Fr::from(amount)),
            recipient: Some(f.recipient),
            value: Some(f.value),
            secret: Some(f.secret),
            rho: Some(f.rho),
            siblings: Some(path.siblings),
            is_right: Some(path.is_right),
        }
    }

    fn satisfied(c: WithdrawCircuit) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        cs.is_satisfied().unwrap()
    }

    fn inputs_of(c: &WithdrawCircuit) -> Vec<Fr> {
        WithdrawCircuit::public_inputs(
            c.root.unwrap(),
            c.nullifier.unwrap(),
            c.amount.unwrap(),
            c.recipient.unwrap(),
        )
    }

    #[test]
    fn an_honest_withdrawal_satisfies_the_constraints_and_verifies() {
        let f = fixture(1_000);
        let c = circuit(&f, 1_000);
        assert!(satisfied(c.clone()));

        let mut rng = crypto_rng();
        let (pk, vk) = setup(DEPTH, &mut rng).unwrap();
        let proof = prove(&pk, c.clone(), &mut rng).unwrap();
        assert!(verify(&vk, &inputs_of(&c), &proof).unwrap());
    }

    /// The inflation case.
    #[test]
    fn withdrawing_more_than_the_note_holds_is_refused() {
        let f = fixture(1_000);
        assert!(!satisfied(circuit(&f, 1_001)));
    }

    /// The stuck-change case: a partial spend is refused rather than quietly
    /// abandoning the remainder in the pool.
    #[test]
    fn withdrawing_less_than_the_note_holds_is_refused() {
        let f = fixture(1_000);
        assert!(!satisfied(circuit(&f, 999)));
        assert!(!satisfied(circuit(&f, 0)));
    }

    /// The inflation case that matters most, because the chain cannot catch
    /// it: a commitment made for 10,000 deposited by transferring 1. The leaf
    /// the chain wrote binds the 1, so no proof for 10,000 has a path to it.
    #[test]
    fn a_note_committed_for_more_than_was_deposited_cannot_be_spent() {
        let f = deposited_at(Fr::from(10_000u64), Fr::from(1u64));
        assert!(!satisfied(circuit(&f, 10_000)), "cannot withdraw the committed value");
        assert!(!satisfied(circuit(&f, 1)), "nor the deposited one, the commitment disagrees");
    }

    /// And the reverse, so the binding is an equality rather than a bound.
    #[test]
    fn a_note_committed_for_less_than_was_deposited_cannot_be_spent() {
        let f = deposited_at(Fr::from(1u64), Fr::from(10_000u64));
        assert!(!satisfied(circuit(&f, 1)));
        assert!(!satisfied(circuit(&f, 10_000)));
    }

    /// The leaf is the commitment wrapped with the amount, so the bare
    /// commitment must not itself be a spendable leaf.
    #[test]
    fn a_bare_commitment_in_the_tree_is_not_spendable() {
        let mut rng = test_rng();
        let (value, secret, rho) = (Fr::from(1_000u64), Fr::rand(&mut rng), Fr::rand(&mut rng));
        let mut tree = MerkleTree::new(DEPTH);
        let index = tree.insert(native(SHIELDED_COMMITMENT_DOMAIN, &[value, secret, rho])).unwrap();
        let f = Fixture { tree, index, value, secret, rho, recipient: Fr::rand(&mut rng) };
        assert!(!satisfied(circuit(&f, 1_000)));
    }

    #[test]
    fn a_note_that_is_not_in_the_tree_is_refused() {
        let f = fixture(1_000);
        let mut c = circuit(&f, 1_000);
        // A real path, but for somebody else's leaf.
        let other = f.tree.path(0).unwrap();
        c.siblings = Some(other.siblings);
        c.is_right = Some(other.is_right);
        assert!(!satisfied(c));
    }

    #[test]
    fn the_wrong_secret_is_refused() {
        let f = fixture(1_000);
        let mut c = circuit(&f, 1_000);
        c.secret = Some(Fr::rand(&mut test_rng()) + Fr::one());
        assert!(!satisfied(c));
    }

    /// The double-spend guard depends on this: a spender must not be able to
    /// publish a nullifier of their choosing.
    #[test]
    fn a_nullifier_for_a_different_note_is_refused() {
        let f = fixture(1_000);
        let mut c = circuit(&f, 1_000);
        c.nullifier = Some(Fr::rand(&mut test_rng()));
        assert!(!satisfied(c));
    }

    #[test]
    fn a_root_the_note_is_not_under_is_refused() {
        let f = fixture(1_000);
        let mut c = circuit(&f, 1_000);
        c.root = Some(Fr::rand(&mut test_rng()));
        assert!(!satisfied(c));
    }

    /// A note whose value is not a `u64` can never be spent, because the
    /// verifier only ever supplies amounts built from one. Such a note cannot
    /// be deposited either, since deposits carry a `u64`; this pins the
    /// circuit's side of that agreement.
    #[test]
    fn a_value_beyond_64_bits_can_never_match_a_u64_amount() {
        let too_big = Fr::from(u64::MAX) + Fr::one();
        let f = fixture_fr(too_big);
        assert!(!satisfied(circuit(&f, u64::MAX)));
        assert!(!satisfied(circuit(&f, 0)));
    }

    /// Without this, a relayer submitting the transaction could send the money
    /// to themselves, or keep most of it as the fee.
    #[test]
    fn the_proof_is_bound_to_the_recipient() {
        let f = fixture(1_000);
        let c = circuit(&f, 1_000);
        let mut rng = crypto_rng();
        let (pk, vk) = setup(DEPTH, &mut rng).unwrap();
        let proof = prove(&pk, c.clone(), &mut rng).unwrap();

        let hijacked = WithdrawCircuit::public_inputs(
            c.root.unwrap(),
            c.nullifier.unwrap(),
            c.amount.unwrap(),
            Fr::rand(&mut rng),
        );
        assert!(!verify(&vk, &hijacked, &proof).unwrap());
        assert!(verify(&vk, &inputs_of(&c), &proof).unwrap(), "the honest inputs still verify");
    }

    #[test]
    fn a_proof_does_not_verify_for_a_different_amount() {
        let f = fixture(1_000);
        let c = circuit(&f, 1_000);
        let mut rng = crypto_rng();
        let (pk, vk) = setup(DEPTH, &mut rng).unwrap();
        let proof = prove(&pk, c.clone(), &mut rng).unwrap();
        let more = WithdrawCircuit::public_inputs(
            c.root.unwrap(),
            c.nullifier.unwrap(),
            Fr::from(900u64),
            c.recipient.unwrap(),
        );
        assert!(!verify(&vk, &more, &proof).unwrap());
    }

    /// Sanity on size: the whole point of Poseidon is that this stays small
    /// enough to prove on a laptop.
    #[test]
    fn the_constraint_count_stays_small() {
        let f = fixture(1_000);
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit(&f, 1_000).generate_constraints(cs.clone()).unwrap();
        let n = cs.num_constraints();
        assert!(n < 5_000, "{n} constraints at depth {DEPTH}; something is being recomputed");
        assert!(n > 500, "{n} constraints is too few to be enforcing what this claims");
    }
}
