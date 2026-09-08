use crate::{
    hash_with_domain, secret_to_elems, Digest, Elem, DOMAIN_BINDING, DOMAIN_COMMITMENT,
    DOMAIN_LEAF, DOMAIN_NULLIFIER,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use winterfell::math::fields::f64::BaseElement;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteError {
    ValueOutOfRange,
}

pub const MAX_NOTE_VALUE: u64 = u64::MAX >> 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Note {
    pub value_uegoc: u64,
    pub owner_secret: [u8; 32],
    pub rho: [u8; 32],
}

impl Note {
    pub fn random<R: RngCore + CryptoRng>(value_uegoc: u64, rng: &mut R) -> Self {
        let mut owner_secret = [0u8; 32];
        let mut rho = [0u8; 32];
        rng.fill_bytes(&mut owner_secret);
        rng.fill_bytes(&mut rho);
        Self { value_uegoc, owner_secret, rho }
    }

    pub fn value_elem(&self) -> Result<Elem, NoteError> {
        value_to_elem(self.value_uegoc)
    }

    pub fn witness(&self) -> ([Elem; crate::SECRET_ELEMS], [Elem; crate::SECRET_ELEMS]) {
        (secret_to_elems(&self.owner_secret), secret_to_elems(&self.rho))
    }

    pub fn commitment(&self) -> Result<Digest, NoteError> {
        let (secret, rho) = self.witness();
        let mut inputs = Vec::with_capacity(2 * crate::SECRET_ELEMS);
        inputs.extend_from_slice(&secret);
        inputs.extend_from_slice(&rho);
        Ok(hash_with_domain(DOMAIN_COMMITMENT, &inputs))
    }

    pub fn nullifier(&self) -> Digest {
        let (secret, rho) = self.witness();
        let mut inputs = Vec::with_capacity(2 * crate::SECRET_ELEMS);
        inputs.extend_from_slice(&secret);
        inputs.extend_from_slice(&rho);
        hash_with_domain(DOMAIN_NULLIFIER, &inputs)
    }

    pub fn leaf(&self) -> Result<Digest, NoteError> {
        Ok(leaf_for(&self.commitment()?, self.value_uegoc)?)
    }
}

pub fn value_to_elem(value_uegoc: u64) -> Result<Elem, NoteError> {
    if value_uegoc > MAX_NOTE_VALUE {
        return Err(NoteError::ValueOutOfRange);
    }
    Ok(BaseElement::new(value_uegoc))
}

pub fn leaf_for(commitment: &Digest, amount_uegoc: u64) -> Result<Digest, NoteError> {
    let amount = value_to_elem(amount_uegoc)?;
    let mut inputs = Vec::with_capacity(5);
    inputs.extend_from_slice(commitment.as_elements());
    inputs.push(amount);
    Ok(hash_with_domain(DOMAIN_LEAF, &inputs))
}

pub fn withdrawal_binding(recipient: &[u8; 32], fee_uegoc: u64) -> Result<Digest, NoteError> {
    let fee = value_to_elem(fee_uegoc)?;
    let mut inputs = Vec::with_capacity(5);
    inputs.extend_from_slice(&secret_to_elems(recipient));
    inputs.push(fee);
    Ok(hash_with_domain(DOMAIN_BINDING, &inputs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn rng() -> StdRng {
        StdRng::from_entropy()
    }

    fn note(value: u64, s: u8, r: u8) -> Note {
        Note { value_uegoc: value, owner_secret: [s; 32], rho: [r; 32] }
    }

    #[test]
    fn a_commitment_hides_its_owner() {
        assert_ne!(note(100, 1, 1).commitment(), note(100, 2, 1).commitment());
        assert_ne!(note(100, 1, 1).commitment(), note(100, 1, 2).commitment());
    }

    #[test]
    fn the_commitment_does_not_carry_the_value_but_the_leaf_does() {
        assert_eq!(
            note(100, 1, 1).commitment(),
            note(200, 1, 1).commitment(),
            "the depositor publishes this before the chain knows the amount"
        );
        assert_ne!(
            note(100, 1, 1).leaf(),
            note(200, 1, 1).leaf(),
            "the amount is bound where the chain can build it: in the leaf"
        );
    }

    #[test]
    fn the_nullifier_does_not_depend_on_the_value() {
        assert_eq!(note(100, 1, 1).nullifier(), note(999, 1, 1).nullifier());
        assert_ne!(note(100, 1, 1).nullifier(), note(100, 2, 1).nullifier());
        assert_ne!(note(100, 1, 1).nullifier(), note(100, 1, 2).nullifier());
    }

    #[test]
    fn a_commitment_is_never_its_own_nullifier() {
        let n = note(100, 7, 9);
        assert_ne!(n.commitment().unwrap(), n.nullifier());
    }

    #[test]
    fn the_leaf_binds_the_commitment_to_one_amount() {
        let c = note(1_000, 3, 4).commitment().unwrap();
        assert_ne!(leaf_for(&c, 1_000).unwrap(), leaf_for(&c, 1_001).unwrap());
        assert_ne!(leaf_for(&c, 1_000).unwrap(), c);
        assert_eq!(leaf_for(&c, 1_000).unwrap(), note(1_000, 3, 4).leaf().unwrap());
    }

    #[test]
    fn a_note_deposited_at_the_wrong_amount_has_a_different_leaf() {
        let n = note(10_000, 5, 5);
        let honest = n.leaf().unwrap();
        let as_deposited = leaf_for(&n.commitment().unwrap(), 1).unwrap();
        assert_ne!(honest, as_deposited);
    }

    #[test]
    fn a_value_that_does_not_fit_the_field_is_refused() {
        assert_eq!(value_to_elem(MAX_NOTE_VALUE), Ok(BaseElement::new(MAX_NOTE_VALUE)));
        assert_eq!(value_to_elem(MAX_NOTE_VALUE + 1), Err(NoteError::ValueOutOfRange));
        assert_eq!(value_to_elem(u64::MAX), Err(NoteError::ValueOutOfRange));
        let big = Note { value_uegoc: u64::MAX, owner_secret: [1; 32], rho: [1; 32] };
        assert_eq!(big.leaf(), Err(NoteError::ValueOutOfRange));
        assert_eq!(leaf_for(&big.commitment().unwrap(), u64::MAX), Err(NoteError::ValueOutOfRange));
    }

    /// Every hash the note layer performs must avoid an input length of eight,
    /// because Rescue's merge is exactly hash_elements over eight and a node
    /// hash would then be indistinguishable from a note hash.
    #[test]
    fn no_note_hash_absorbs_exactly_eight_elements() {
        let commitment_inputs = 1 + 2 * crate::SECRET_ELEMS;
        let nullifier_inputs = 1 + 2 * crate::SECRET_ELEMS;
        let leaf_inputs = 1 + crate::DIGEST_ELEMS + 1;
        let binding_inputs = 1 + crate::SECRET_ELEMS + 1;
        for (what, n) in [
            ("commitment", commitment_inputs),
            ("nullifier", nullifier_inputs),
            ("leaf", leaf_inputs),
            ("binding", binding_inputs),
        ] {
            assert_ne!(n, 8, "{what} absorbs eight elements, which is a node hash");
            assert!(n <= 8, "{what} absorbs {n}, which costs a second permutation");
        }
    }

    #[test]
    fn the_binding_depends_on_both_recipient_and_fee() {
        let r = [0xABu8; 32];
        let a = withdrawal_binding(&r, 7).unwrap();
        assert_ne!(a, withdrawal_binding(&[0xACu8; 32], 7).unwrap());
        assert_ne!(a, withdrawal_binding(&r, 8).unwrap());
        assert_eq!(a, withdrawal_binding(&r, 7).unwrap());
    }

    #[test]
    fn random_notes_do_not_repeat() {
        let mut r = rng();
        let mut commitments = std::collections::HashSet::new();
        let mut nullifiers = std::collections::HashSet::new();
        for _ in 0..500 {
            let n = Note::random(1_000_000, &mut r);
            assert!(commitments.insert(crate::digest_to_bytes(&n.commitment().unwrap())));
            assert!(nullifiers.insert(crate::digest_to_bytes(&n.nullifier())));
        }
    }

    #[test]
    fn every_derived_value_is_a_different_function_of_the_same_note() {
        let n = note(1_234, 11, 22);
        let c = crate::digest_to_bytes(&n.commitment().unwrap());
        let nf = crate::digest_to_bytes(&n.nullifier());
        let l = crate::digest_to_bytes(&n.leaf().unwrap());
        let all = [c, nf, l];
        let set: std::collections::HashSet<[u8; 32]> = all.iter().copied().collect();
        assert_eq!(set.len(), all.len());
    }
}
