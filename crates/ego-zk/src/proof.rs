use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use rand::{CryptoRng, RngCore};

use crate::error::ZkError;

// ---------------------------------------------------------------------------
// ZkProof — serializable proof + verifying key bundle
// ---------------------------------------------------------------------------

/// Serialized Groth16 proof together with the verifying key, ready for
/// transport over RPC or storage on-chain.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ZkProof {
    /// Canonical-serialized `ark_groth16::Proof<Bn254>`.
    pub proof_bytes: Vec<u8>,
    /// Canonical-serialized `ark_groth16::VerifyingKey<Bn254>`.
    pub vk_bytes: Vec<u8>,
}

impl ZkProof {
    /// Serialize to a flat byte vector: 8-byte LE proof_len, proof, vk.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.proof_bytes.len() + self.vk_bytes.len());
        let plen = self.proof_bytes.len() as u64;
        out.extend_from_slice(&plen.to_le_bytes());
        out.extend_from_slice(&self.proof_bytes);
        out.extend_from_slice(&self.vk_bytes);
        out
    }

    /// Deserialize from the flat byte format produced by `to_bytes`.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ZkError> {
        if data.len() < 8 {
            return Err(ZkError::SerializationError(
                "buffer too short for ZkProof header".into(),
            ));
        }
        let plen = u64::from_le_bytes(data[..8].try_into().unwrap()) as usize;
        if data.len() < 8 + plen {
            return Err(ZkError::SerializationError(
                "buffer too short for proof bytes".into(),
            ));
        }
        let proof_bytes = data[8..8 + plen].to_vec();
        let vk_bytes = data[8 + plen..].to_vec();
        Ok(Self { proof_bytes, vk_bytes })
    }
}

// ---------------------------------------------------------------------------
// StateTransitionCircuit
// ---------------------------------------------------------------------------

/// Placeholder R1CS circuit that encodes the public statement:
///   "I know witnesses such that old_state_root and new_state_root are valid"
///
/// Public inputs  : old_root bytes (32 × Fr), new_root bytes (32 × Fr)
/// Private witness: a single field element equal to Fr::one()
///
/// Constraint: witness * Fr::one() == Fr::one()
///
/// Phase 2 will replace this with full Merkle-trie update logic.
#[derive(Clone)]
pub struct StateTransitionCircuit {
    /// Plaintext old state root (32 bytes).
    pub old_state_root: [u8; 32],
    /// Plaintext new state root (32 bytes).
    pub new_state_root: [u8; 32],
}

impl ConstraintSynthesizer<Fr> for StateTransitionCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> Result<(), SynthesisError> {
        // --- Public inputs: one Fr per byte of old_root and new_root ----------
        for &byte in self.old_state_root.iter().chain(self.new_state_root.iter()) {
            cs.new_input_variable(|| Ok(Fr::from(byte)))?;
        }

        // --- Private witness: Fr::one() ---------------------------------------
        let witness_var = cs.new_witness_variable(|| Ok(Fr::from(1u64)))?;

        // --- Constraint: witness * 1 = 1 --------------------------------------
        // Expressed as a linear combination:
        //   (witness) * (1) - (1) = 0
        // i.e. a = witness, b = 1 (constant), c = 1 (constant).
        cs.enforce_constraint(
            // a: witness
            ark_relations::lc!() + witness_var,
            // b: 1  (the constant variable)
            ark_relations::lc!() + Variable::One,
            // c: 1
            ark_relations::lc!() + Variable::One,
        )?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ZkProver
// ---------------------------------------------------------------------------

pub struct ZkProver;

impl ZkProver {
    /// Groth16 trusted setup for `StateTransitionCircuit`.
    /// Returns `(proving_key, verifying_key)`.
    pub fn setup<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), ZkError> {
        let circuit = StateTransitionCircuit {
            old_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
        };
        Groth16::<Bn254>::circuit_specific_setup(circuit, rng)
            .map_err(|e| ZkError::SetupError(e.to_string()))
    }

    /// Generate a Groth16 proof for the given state transition.
    pub fn prove<R: RngCore + CryptoRng>(
        pk: &ProvingKey<Bn254>,
        old_root_bytes: [u8; 32],
        new_root_bytes: [u8; 32],
        rng: &mut R,
    ) -> Result<ZkProof, ZkError> {
        let circuit = StateTransitionCircuit {
            old_state_root: old_root_bytes,
            new_state_root: new_root_bytes,
        };

        // Public inputs mirror the circuit's `new_input_variable` calls.
        let public_inputs: Vec<Fr> = old_root_bytes
            .iter()
            .chain(new_root_bytes.iter())
            .map(|&b| Fr::from(b))
            .collect();

        let proof = Groth16::<Bn254>::prove(pk, circuit, rng)
            .map_err(|e| ZkError::ProvingError(e.to_string()))?;

        // Serialize proof
        let mut proof_bytes = Vec::new();
        proof
            .serialize_compressed(&mut proof_bytes)
            .map_err(|e| ZkError::SerializationError(e.to_string()))?;

        // Serialize verifying key
        let mut vk_bytes = Vec::new();
        pk.vk
            .serialize_compressed(&mut vk_bytes)
            .map_err(|e| ZkError::SerializationError(e.to_string()))?;

        // Verify immediately to catch setup/prove mismatches early
        let ok = Groth16::<Bn254>::verify(&pk.vk, &public_inputs, &proof)
            .map_err(|_| ZkError::VerificationError)?;
        if !ok {
            return Err(ZkError::ProvingError(
                "self-verification after prove() failed".into(),
            ));
        }

        Ok(ZkProof { proof_bytes, vk_bytes })
    }

    /// Verify a `ZkProof` against the stated state roots.
    pub fn verify(
        vk: &VerifyingKey<Bn254>,
        proof: &ZkProof,
        old_root: [u8; 32],
        new_root: [u8; 32],
    ) -> Result<bool, ZkError> {
        // Deserialize proof
        let ark_proof =
            ark_groth16::Proof::<Bn254>::deserialize_compressed(proof.proof_bytes.as_slice())
                .map_err(|e| ZkError::SerializationError(e.to_string()))?;

        let public_inputs: Vec<Fr> = old_root
            .iter()
            .chain(new_root.iter())
            .map(|&b| Fr::from(b))
            .collect();

        Groth16::<Bn254>::verify(vk, &public_inputs, &ark_proof)
            .map_err(|_| ZkError::VerificationError)
    }
}

// ---------------------------------------------------------------------------
// Helpers: convert a 32-byte root to/from its Fr representation
// (one Fr per byte; lossless since each byte fits in the BN254 scalar field)
// ---------------------------------------------------------------------------

/// Encode a 32-byte root as a `Vec<Fr>` for use as public inputs.
pub fn root_to_field_elements(root: &[u8; 32]) -> Vec<Fr> {
    root.iter().map(|&b| Fr::from(b)).collect()
}

/// Extract a single byte back from an `Fr` that was created with `Fr::from(byte)`.
pub fn field_element_to_byte(fe: &Fr) -> u8 {
    fe.into_bigint().as_ref()[0] as u8
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_setup_prove_verify_roundtrip() {
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

        let old_root = [1u8; 32];
        let new_root = [2u8; 32];

        let (pk, vk) = ZkProver::setup(&mut rng).expect("setup failed");
        let zk_proof = ZkProver::prove(&pk, old_root, new_root, &mut rng)
            .expect("prove failed");

        let valid = ZkProver::verify(&vk, &zk_proof, old_root, new_root)
            .expect("verify error");
        assert!(valid, "proof should verify");
    }

    #[test]
    fn test_zkproof_serialization_roundtrip() {
        let proof = ZkProof {
            proof_bytes: vec![1, 2, 3, 4],
            vk_bytes: vec![5, 6, 7, 8],
        };
        let bytes = proof.to_bytes();
        let decoded = ZkProof::from_bytes(&bytes).expect("from_bytes failed");
        assert_eq!(decoded.proof_bytes, proof.proof_bytes);
        assert_eq!(decoded.vk_bytes, proof.vk_bytes);
    }
}
