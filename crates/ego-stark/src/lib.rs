pub mod air;
pub mod merkle;
pub mod note;
pub mod prove;

pub use note::{Note, NoteError};

use winterfell::crypto::hashers::Rp64_256;
use winterfell::crypto::{ElementHasher, Hasher};
use winterfell::math::fields::f64::BaseElement;
use winterfell::math::{FieldElement, StarkField};

pub type Elem = BaseElement;
pub type Hash = Rp64_256;
pub type Digest = <Rp64_256 as Hasher>::Digest;

pub const DIGEST_ELEMS: usize = 4;
pub const DIGEST_BYTES: usize = 32;

pub const DOMAIN_COMMITMENT: u64 = 1;
pub const DOMAIN_NULLIFIER: u64 = 2;
pub const DOMAIN_LEAF: u64 = 3;
pub const DOMAIN_BINDING: u64 = 4;

pub const SECRET_ELEMS: usize = 4;
pub const SECRET_BITS_PER_ELEM: u32 = 63;

pub fn digest_to_bytes(d: &Digest) -> [u8; DIGEST_BYTES] {
    let mut out = [0u8; DIGEST_BYTES];
    for (i, e) in d.as_elements().iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&e.as_int().to_le_bytes());
    }
    out
}

pub fn digest_from_bytes(bytes: &[u8; DIGEST_BYTES]) -> Option<Digest> {
    let mut elems = [BaseElement::ZERO; DIGEST_ELEMS];
    for (i, e) in elems.iter_mut().enumerate() {
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        let raw = u64::from_le_bytes(chunk);
        if raw >= BaseElement::MODULUS {
            return None;
        }
        *e = BaseElement::new(raw);
    }
    Some(Digest::new(elems))
}

pub fn secret_to_elems(bytes: &[u8; 32]) -> [Elem; SECRET_ELEMS] {
    let mut out = [BaseElement::ZERO; SECRET_ELEMS];
    for (i, e) in out.iter_mut().enumerate() {
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        let raw = u64::from_le_bytes(chunk) & ((1u64 << SECRET_BITS_PER_ELEM) - 1);
        *e = BaseElement::new(raw);
    }
    out
}

pub fn hash_with_domain(domain: u64, inputs: &[Elem]) -> Digest {
    let mut buf = Vec::with_capacity(inputs.len() + 1);
    buf.push(BaseElement::new(domain));
    buf.extend_from_slice(inputs);
    Hash::hash_elements(&buf)
}

pub fn merge_nodes(left: &Digest, right: &Digest) -> Digest {
    Hash::merge(&[*left, *right])
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};

    fn rng() -> StdRng {
        StdRng::from_entropy()
    }

    #[test]
    fn a_digest_round_trips_through_bytes() {
        let mut r = rng();
        for _ in 0..256 {
            let mut seed = [0u8; 32];
            r.fill_bytes(&mut seed);
            let d = hash_with_domain(DOMAIN_COMMITMENT, &secret_to_elems(&seed));
            let bytes = digest_to_bytes(&d);
            assert_eq!(digest_from_bytes(&bytes), Some(d));
        }
    }

    #[test]
    fn bytes_that_are_not_a_canonical_field_element_are_refused() {
        let mut bytes = [0xFFu8; 32];
        assert_eq!(digest_from_bytes(&bytes), None);
        bytes = [0u8; 32];
        assert!(digest_from_bytes(&bytes).is_some());
        let mut edge = [0u8; 32];
        edge[..8].copy_from_slice(&(BaseElement::MODULUS - 1).to_le_bytes());
        assert!(digest_from_bytes(&edge).is_some());
        edge[..8].copy_from_slice(&BaseElement::MODULUS.to_le_bytes());
        assert_eq!(digest_from_bytes(&edge), None);
    }

    #[test]
    fn secret_encoding_is_injective() {
        let mut seen = std::collections::HashSet::new();
        let mut r = rng();
        for _ in 0..2_000 {
            let mut seed = [0u8; 32];
            r.fill_bytes(&mut seed);
            let masked: Vec<u64> = secret_to_elems(&seed).iter().map(|e| e.as_int()).collect();
            assert!(seen.insert(masked), "two secrets collapsed to one field encoding");
        }
    }

    #[test]
    fn secret_elements_stay_below_the_modulus() {
        let all_ones = [0xFFu8; 32];
        for e in secret_to_elems(&all_ones) {
            assert!(e.as_int() < BaseElement::MODULUS);
            assert!(e.as_int() < (1u64 << SECRET_BITS_PER_ELEM));
        }
    }

    #[test]
    fn masking_only_clears_the_top_bit_of_each_lane() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[0] = 1;
        b[0] = 2;
        assert_ne!(secret_to_elems(&a), secret_to_elems(&b));
        let mut hi = [0u8; 32];
        hi[7] = 0x80;
        assert_eq!(secret_to_elems(&hi)[0].as_int(), 0);
    }

    #[test]
    fn a_node_hash_cannot_be_produced_as_a_domain_hash() {
        let mut r = rng();
        let mut a_bytes = [0u8; 32];
        let mut b_bytes = [0u8; 32];
        r.fill_bytes(&mut a_bytes);
        r.fill_bytes(&mut b_bytes);
        let a = hash_with_domain(DOMAIN_COMMITMENT, &secret_to_elems(&a_bytes));
        let b = hash_with_domain(DOMAIN_COMMITMENT, &secret_to_elems(&b_bytes));

        let node = merge_nodes(&a, &b);
        let mut eight = Vec::new();
        eight.extend_from_slice(a.as_elements());
        eight.extend_from_slice(b.as_elements());
        assert_eq!(
            node,
            Hash::hash_elements(&eight),
            "merge really is hash_elements over eight, which is why every other call carries a domain"
        );
        assert_ne!(node, hash_with_domain(DOMAIN_LEAF, &eight));
        assert_ne!(node, hash_with_domain(DOMAIN_COMMITMENT, &eight));
        assert_ne!(node, hash_with_domain(DOMAIN_NULLIFIER, &eight));
    }

    #[test]
    fn the_domains_separate_identical_inputs() {
        let mut r = rng();
        let mut seed = [0u8; 32];
        r.fill_bytes(&mut seed);
        let input = secret_to_elems(&seed);
        let c = hash_with_domain(DOMAIN_COMMITMENT, &input);
        let n = hash_with_domain(DOMAIN_NULLIFIER, &input);
        let l = hash_with_domain(DOMAIN_LEAF, &input);
        let b = hash_with_domain(DOMAIN_BINDING, &input);
        let all = [c, n, l, b];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "domains {i} and {j} agree on one input");
            }
        }
    }

    #[test]
    fn the_domain_constants_are_distinct() {
        let all = [DOMAIN_COMMITMENT, DOMAIN_NULLIFIER, DOMAIN_LEAF, DOMAIN_BINDING];
        let set: std::collections::HashSet<u64> = all.iter().copied().collect();
        assert_eq!(set.len(), all.len());
        assert!(!set.contains(&0), "zero is what an uninitialised tag looks like");
    }

    #[test]
    fn hashing_is_deterministic() {
        let mut r = rng();
        let mut seed = [0u8; 32];
        r.fill_bytes(&mut seed);
        let input = secret_to_elems(&seed);
        assert_eq!(
            hash_with_domain(DOMAIN_COMMITMENT, &input),
            hash_with_domain(DOMAIN_COMMITMENT, &input)
        );
    }

    #[test]
    fn appending_zeros_changes_the_hash() {
        let base = [Elem::new(1), Elem::new(2)];
        let padded = [Elem::new(1), Elem::new(2), Elem::ZERO];
        assert_ne!(
            hash_with_domain(DOMAIN_COMMITMENT, &base),
            hash_with_domain(DOMAIN_COMMITMENT, &padded)
        );
    }
}
