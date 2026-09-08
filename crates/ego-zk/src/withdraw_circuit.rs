//! The withdrawal circuit for the shielded pool.
//!
//! # What a withdrawal proves
//!
//! Publicly: a Merkle root, a nullifier, an amount, and a recipient.
//! Privately: a note (value, secret, rho) and a path in the commitment tree.
//!
//! The proof establishes, without revealing the note or its position:
//!
//! 1. `Poseidon(COMMITMENT, value, secret, rho)` is a leaf under the public root.
//! 2. The public nullifier is `Poseidon(NULLIFIER, secret, rho)` for that same
//!    secret and rho. This is what stops one note being spent twice: the pool
//!    records nullifiers, and a second spend of the same note would have to
//!    publish the same one.
//! 3. `amount <= value`, established as a range constraint rather than a
//!    comparison. Circuits work over a field, where `value - amount` never
//!    goes negative but wraps to something enormous. So `value`, `amount` and
//!    their difference are each constrained to fit in 64 bits, and a wrapped
//!    difference cannot.
//! 4. The recipient is bound into the proof. A relayer who submits the
//!    transaction on the prover's behalf cannot redirect the payout, because
//!    changing the recipient changes a public input and invalidates the proof.
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
use crate::poseidon_gadget::{commitment_gadget, nullifier_gadget};
use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};

/// Note values are `u64` micro-EGOC natively; the circuit bounds them to match.
pub const VALUE_BITS: usize = 64;

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
    /// at each call site, where the order would drift.
    pub fn public_inputs(root: Fr, nullifier: Fr, amount: Fr, recipient: Fr) -> Vec<Fr> {
        vec![root, nullifier, amount, recipient]
    }
}

/// The low `n` bits of `v`, little-endian.
fn low_bits_le(v: Fr, n: usize) -> Vec<bool> {
    let bits = v.into_bigint().to_bits_le();
    (0..n).map(|i| bits.get(i).copied().unwrap_or(false)).collect()
}

/// Constrain `x` to `[0, 2^n)`.
///
/// Allocates `n` boolean witnesses and requires that they reconstruct `x`.
/// Each `Boolean` allocation constrains its bit to be 0 or 1, so the prover
/// cannot smuggle a non-bit in. A value at or above `2^n` has no `n`-bit
/// representation, so no choice of bits satisfies the equality.
fn enforce_bounded(
    cs: &ConstraintSystemRef<Fr>,
    x: &FpVar<Fr>,
    n: usize,
) -> Result<(), SynthesisError> {
    // Compute the honest bits once, outside the closures. In setup mode there
    // is no value and the closures are never invoked, so this is simply None.
    let honest: Option<Vec<bool>> = x.value().ok().map(|v| low_bits_le(v, n));
    let bits: Vec<Boolean<Fr>> = (0..n)
        .map(|i| {
            Boolean::new_witness(cs.clone(), || {
                honest
                    .as_ref()
                    .map(|b| b[i])
                    .ok_or(SynthesisError::AssignmentMissing)
            })
        })
        .collect::<Result<_, _>>()?;
    let rebuilt = Boolean::le_bits_to_fp(&bits)?;
    rebuilt.enforce_equal(x)
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

        // 1. The note is in the tree.
        let commitment = commitment_gadget(&value_w, &secret_w, &rho_w)?;
        let computed_root = merkle_root_gadget(&commitment, &sibling_vars, &direction_vars)?;
        computed_root.enforce_equal(&root_in)?;

        // 2. The nullifier is this note's, not one for some other note.
        let computed_nullifier = nullifier_gadget(&secret_w, &rho_w)?;
        computed_nullifier.enforce_equal(&nullifier_in)?;

        // 3. amount <= value, as three range constraints. All three are needed:
        // bounding only the difference would let a huge amount wrap the
        // difference back into range, and bounding only value and amount would
        // let a negative difference wrap to something enormous.
        enforce_bounded(&cs, &value_w, VALUE_BITS)?;
        enforce_bounded(&cs, &amount_in, VALUE_BITS)?;
        let difference = &value_w - &amount_in;
        enforce_bounded(&cs, &difference, VALUE_BITS)?;

        // 4. Bind the recipient. Multiplying it by itself emits one constraint
        // that mentions it, so it is a genuine part of the statement being
        // proved rather than a public input the circuit never touches.
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
    use crate::poseidon_gadget::{SHIELDED_COMMITMENT_DOMAIN, SHIELDED_NULLIFIER_DOMAIN};
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

    /// A tree with other people's notes around ours, so the path is not trivial.
    fn fixture_fr(value: Fr) -> Fixture {
        let mut rng = test_rng();
        let mut tree = MerkleTree::new(DEPTH);
        for i in 0..3u64 {
            tree.insert(Fr::from(500 + i)).unwrap();
        }
        let secret = Fr::rand(&mut rng);
        let rho = Fr::rand(&mut rng);
        let commitment = native(SHIELDED_COMMITMENT_DOMAIN, &[value, secret, rho]);
        let index = tree.insert(commitment).unwrap();
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
        let c = circuit(&f, 400);
        assert!(satisfied(c.clone()));

        let mut rng = crypto_rng();
        let (pk, vk) = setup(DEPTH, &mut rng).unwrap();
        let proof = prove(&pk, c.clone(), &mut rng).unwrap();
        assert!(verify(&vk, &inputs_of(&c), &proof).unwrap());
    }

    #[test]
    fn withdrawing_exactly_the_full_value_is_allowed() {
        let f = fixture(1_000);
        assert!(satisfied(circuit(&f, 1_000)));
    }

    /// The inflation case. A field never goes negative, so this must be caught
    /// by the range constraints, not by any comparison.
    #[test]
    fn withdrawing_more_than_the_note_holds_is_refused() {
        let f = fixture(1_000);
        assert!(!satisfied(circuit(&f, 1_001)));
    }

    #[test]
    fn a_note_that_is_not_in_the_tree_is_refused() {
        let f = fixture(1_000);
        let mut c = circuit(&f, 100);
        // A real path, but for somebody else's leaf.
        let other = f.tree.path(0).unwrap();
        c.siblings = Some(other.siblings);
        c.is_right = Some(other.is_right);
        assert!(!satisfied(c));
    }

    #[test]
    fn the_wrong_secret_is_refused() {
        let f = fixture(1_000);
        let mut c = circuit(&f, 100);
        c.secret = Some(Fr::rand(&mut test_rng()) + Fr::one());
        assert!(!satisfied(c));
    }

    /// The double-spend guard depends on this: a spender must not be able to
    /// publish a nullifier of their choosing.
    #[test]
    fn a_nullifier_for_a_different_note_is_refused() {
        let f = fixture(1_000);
        let mut c = circuit(&f, 100);
        c.nullifier = Some(Fr::rand(&mut test_rng()));
        assert!(!satisfied(c));
    }

    #[test]
    fn a_root_the_note_is_not_under_is_refused() {
        let f = fixture(1_000);
        let mut c = circuit(&f, 100);
        c.root = Some(Fr::rand(&mut test_rng()));
        assert!(!satisfied(c));
    }

    /// The circuit takes its value as a field element, so the 64-bit bound is
    /// its own responsibility, not something the `u64` type provides for it.
    /// A prover supplying `2^64` directly must be refused.
    #[test]
    fn a_value_beyond_64_bits_is_refused_even_when_supplied_directly() {
        let too_big = Fr::from(u64::MAX) + Fr::one();
        let f = fixture_fr(too_big);
        assert!(!satisfied(circuit(&f, 1)));
    }

    /// Without this, a relayer submitting the transaction could send the money
    /// to themselves.
    #[test]
    fn the_proof_is_bound_to_the_recipient() {
        let f = fixture(1_000);
        let c = circuit(&f, 250);
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
        let c = circuit(&f, 250);
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
        circuit(&f, 100).generate_constraints(cs.clone()).unwrap();
        let n = cs.num_constraints();
        assert!(n < 5_000, "{n} constraints at depth {DEPTH}; something is being recomputed");
        assert!(n > 500, "{n} constraints is too few to be enforcing what this claims");
    }
}
