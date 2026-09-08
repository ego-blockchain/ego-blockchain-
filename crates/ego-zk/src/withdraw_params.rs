use ark_bn254::Bn254;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use blake2::{Blake2s256, Digest};
use std::sync::OnceLock;

pub const DEPTH: usize = crate::merkle::POOL_TREE_DEPTH;

static PK_BYTES: &[u8] = include_bytes!("../params/withdraw_pk.bin");
static VK_BYTES: &[u8] = include_bytes!("../params/withdraw_vk.bin");

pub fn proving_key() -> &'static ProvingKey<Bn254> {
    static PK: OnceLock<ProvingKey<Bn254>> = OnceLock::new();
    PK.get_or_init(|| {
        ProvingKey::<Bn254>::deserialize_compressed_unchecked(PK_BYTES)
            .expect("the embedded proving key decodes")
    })
}

pub fn verifying_key() -> &'static VerifyingKey<Bn254> {
    static VK: OnceLock<VerifyingKey<Bn254>> = OnceLock::new();
    VK.get_or_init(|| {
        VerifyingKey::<Bn254>::deserialize_compressed(VK_BYTES)
            .expect("the embedded verifying key decodes and is on-curve")
    })
}

pub fn verifying_key_digest() -> String {
    hex::encode(Blake2s256::digest(VK_BYTES))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::MerkleTree;
    use crate::poseidon_gadget::{
        SHIELDED_COMMITMENT_DOMAIN, SHIELDED_LEAF_DOMAIN, SHIELDED_NULLIFIER_DOMAIN,
    };
    use crate::withdraw_circuit::{prove, verify, WithdrawCircuit};
    use ark_bn254::Fr;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use ark_std::UniformRand;
    use light_poseidon::{Poseidon, PoseidonHasher};

    fn native(domain: u64, inputs: &[Fr]) -> Fr {
        let mut p = Poseidon::<Fr>::with_domain_tag_circom(inputs.len(), Fr::from(domain)).unwrap();
        p.hash(inputs).unwrap()
    }

    #[test]
    fn the_embedded_keys_belong_to_one_setup() {
        assert_eq!(&proving_key().vk, verifying_key());
        assert_eq!(verifying_key_digest().len(), 64);
    }

    #[test]
    fn the_embedded_keys_prove_and_verify_at_the_pool_depth() {
        let mut rng = StdRng::seed_from_u64(9);
        let mut tree = MerkleTree::new(DEPTH);
        tree.insert(Fr::from(77u64)).unwrap();
        let (value, secret, rho) = (Fr::from(1_000_000u64), Fr::rand(&mut rng), Fr::rand(&mut rng));
        let commitment = native(SHIELDED_COMMITMENT_DOMAIN, &[value, secret, rho]);
        let index = tree.insert(native(SHIELDED_LEAF_DOMAIN, &[commitment, value])).unwrap();
        let path = tree.path(index).unwrap();
        let binding = Fr::rand(&mut rng);
        let c = WithdrawCircuit {
            depth: DEPTH,
            root: Some(tree.root()),
            nullifier: Some(native(SHIELDED_NULLIFIER_DOMAIN, &[secret, rho])),
            amount: Some(value),
            recipient: Some(binding),
            value: Some(value),
            secret: Some(secret),
            rho: Some(rho),
            siblings: Some(path.siblings),
            is_right: Some(path.is_right),
        };
        let proof = prove(proving_key(), c, &mut rng).unwrap();
        let inputs = WithdrawCircuit::public_inputs(
            tree.root(),
            native(SHIELDED_NULLIFIER_DOMAIN, &[secret, rho]),
            value,
            binding,
        );
        assert!(verify(verifying_key(), &inputs, &proof).unwrap());
        let wrong = WithdrawCircuit::public_inputs(
            tree.root(),
            native(SHIELDED_NULLIFIER_DOMAIN, &[secret, rho]),
            value,
            Fr::rand(&mut rng),
        );
        assert!(!verify(verifying_key(), &wrong, &proof).unwrap());
    }
}
