use crate::commitment::RollupCommitment;
use crate::error::{RollupError, RollupResult};
use crate::types::RollupTransaction;
use ego_consensus::{FraudProof as ConsensusFraudProof, FraudType};
use ego_core::{Address, Hash, KeyPair, PublicKey, Signature, Timestamp};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct FraudProof {
    pub proof_id: Hash,
    pub challenger: Address,
    pub commitment_hash: Hash,
    pub fraud_type: RollupFraudType,
    pub evidence: FraudEvidence,
    pub confidence: f64,
    pub timestamp: Timestamp,
    pub signature: Signature,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub enum RollupFraudType {
    InvalidStateTransition,
    InvalidInclusion,
    DataUnavailable,
    InvalidExecution,
    IncorrectStateRoot,
    InvalidSignature,
    DuplicateTransaction,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct FraudEvidence {
    pub commitment: RollupCommitment,
    pub evidence_type: FraudEvidenceType,
    pub proof_data: Vec<u8>,
    pub witness_data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum FraudEvidenceType {
    StateTransition {
        pre_state: Hash,
        post_state: Hash,
        expected_post_state: Hash,
        execution_trace: Vec<u8>,
    },
    InvalidInclusion {
        inclusion_proof: Vec<Hash>,
        merkle_root: Hash,
        invalid_reason: String,
    },
    DataUnavailability {
        missing_chunks: Vec<u32>,
        sample_proofs: Vec<Vec<u8>>,
        timeout_evidence: Vec<TimeoutEvidence>,
    },
    ExecutionError {
        expected_result: Vec<u8>,
        actual_result: Vec<u8>,
        error_trace: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct TimeoutEvidence {
    pub chunk_id: u32,
    pub request_timestamp: Timestamp,
    pub timeout_timestamp: Timestamp,
    pub operator: Address,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct InvalidInclusionProof {
    pub proof_id: Hash,
    pub challenger: Address,
    pub commitment_hash: Hash,
    pub invalid_transaction: RollupTransaction,
    pub inclusion_proof: Vec<Hash>,
    pub fraud_reason: InclusionFraudReason,
    pub timestamp: Timestamp,
    pub signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub enum InclusionFraudReason {
    InvalidSignature,
    InvalidNonce,
    InsufficientBalance,
    MalformedTransaction,
    DuplicateTransaction,
}

pub struct FraudProofVerifier {
    min_confidence: f64,
    max_age_hours: u64,
}

impl FraudProof {
    pub fn new(
        challenger: Address,
        commitment_hash: Hash,
        fraud_type: RollupFraudType,
        evidence: FraudEvidence,
        confidence: f64,
    ) -> Self {
        let timestamp = Timestamp::now();
        let proof_id = Self::compute_proof_id(challenger, commitment_hash, &fraud_type, timestamp);

        Self {
            proof_id,
            challenger,
            commitment_hash,
            fraud_type,
            evidence,
            confidence,
            timestamp,
            signature: Signature::new([0u8; 64]),
            public_key: PublicKey::new([0u8; 32]),
        }
    }

    pub fn sign(&mut self, keypair: &KeyPair) -> RollupResult<()> {
        self.public_key = keypair.public_key();

        let expected_challenger = Address::from_public_key(&self.public_key);
        if expected_challenger != self.challenger {
            return Err(RollupError::FraudProof(
                "Challenger address does not match signing key".to_string(),
            ));
        }

        let signing_data = self.create_signing_data()?;
        self.signature = keypair.sign(&signing_data);

        Ok(())
    }

    pub fn verify_signature(&self) -> RollupResult<bool> {
        let expected_challenger = Address::from_public_key(&self.public_key);
        if expected_challenger != self.challenger {
            return Ok(false);
        }

        let signing_data = self.create_signing_data()?;

        ego_core::verify_signature(&self.public_key, &signing_data, &self.signature)
            .map_err(|e| RollupError::FraudProof(format!("Signature verification failed: {}", e)))
    }

    pub fn validate(&self) -> RollupResult<()> {
        if self.confidence < 0.0 || self.confidence > 1.0 {
            return Err(RollupError::FraudProof(
                "Confidence must be between 0.0 and 1.0".to_string(),
            ));
        }

        if self.confidence < 0.7 {
            return Err(RollupError::FraudProof(
                "Confidence too low for fraud proof submission".to_string(),
            ));
        }

        self.validate_evidence()?;

        Ok(())
    }

    fn validate_evidence(&self) -> RollupResult<()> {
        match &self.evidence.evidence_type {
            FraudEvidenceType::StateTransition {
                pre_state,
                post_state,
                expected_post_state,
                ..
            } => {
                if pre_state == post_state {
                    return Err(RollupError::FraudProof(
                        "State transition must change state".to_string(),
                    ));
                }
                if post_state == expected_post_state {
                    return Err(RollupError::FraudProof(
                        "Actual and expected post states are the same".to_string(),
                    ));
                }
            }
            FraudEvidenceType::InvalidInclusion { invalid_reason, .. } => {
                if invalid_reason.is_empty() {
                    return Err(RollupError::FraudProof(
                        "Invalid inclusion must have a reason".to_string(),
                    ));
                }
            }
            FraudEvidenceType::DataUnavailability { missing_chunks, .. } => {
                if missing_chunks.is_empty() {
                    return Err(RollupError::FraudProof(
                        "Data unavailability proof must specify missing chunks".to_string(),
                    ));
                }
            }
            FraudEvidenceType::ExecutionError {
                expected_result,
                actual_result,
                ..
            } => {
                if expected_result == actual_result {
                    return Err(RollupError::FraudProof(
                        "Expected and actual results are the same".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    fn create_signing_data(&self) -> RollupResult<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(self.proof_id.as_bytes());
        data.extend_from_slice(self.challenger.as_bytes());
        data.extend_from_slice(self.commitment_hash.as_bytes());
        data.extend_from_slice(&self.timestamp.as_millis().to_le_bytes());
        data.extend_from_slice(&self.confidence.to_le_bytes());

        let config = bincode::config::standard();
        let evidence_bytes = bincode::encode_to_vec(&self.evidence, config)
            .map_err(|e| RollupError::SerializationError(e.to_string()))?;
        let evidence_hash = ego_core::crypto::hash_data(&evidence_bytes);
        data.extend_from_slice(evidence_hash.as_bytes());

        Ok(data)
    }

    fn compute_proof_id(
        challenger: Address,
        commitment_hash: Hash,
        fraud_type: &RollupFraudType,
        timestamp: Timestamp,
    ) -> Hash {
        use ego_core::crypto::hash_multiple;

        let fraud_type_bytes = format!("{:?}", fraud_type).into_bytes();

        hash_multiple(&[
            challenger.as_bytes(),
            commitment_hash.as_bytes(),
            &fraud_type_bytes,
            &timestamp.as_millis().to_le_bytes(),
        ])
    }

    pub fn to_consensus_fraud_proof(&self) -> ConsensusFraudProof {
        ConsensusFraudProof::new(
            self.challenger,
            Address::new([0u8; 20]),
            FraudType::InvalidGeometry,
            ego_consensus::FraudEvidence {
                poc_event_hash: self.commitment_hash,
                bundle_hash: None,
                evidence_data: ego_consensus::EvidenceData::InvalidSignature {
                    claimed_signature: self.signature,
                    public_key: self.public_key,
                    message: vec![],
                    verification_result: false,
                },
                calculations: vec![],
                reference_data: Some(self.evidence.proof_data.clone()),
            },
            self.confidence,
        )
    }
}

impl InvalidInclusionProof {
    pub fn new(
        challenger: Address,
        commitment_hash: Hash,
        invalid_transaction: RollupTransaction,
        inclusion_proof: Vec<Hash>,
        fraud_reason: InclusionFraudReason,
    ) -> Self {
        let timestamp = Timestamp::now();
        let proof_id = ego_core::crypto::hash_multiple(&[
            challenger.as_bytes(),
            commitment_hash.as_bytes(),
            invalid_transaction.hash().as_bytes(),
            &timestamp.as_millis().to_le_bytes(),
        ]);

        Self {
            proof_id,
            challenger,
            commitment_hash,
            invalid_transaction,
            inclusion_proof,
            fraud_reason,
            timestamp,
            signature: Signature::new([0u8; 64]),
        }
    }

    pub fn sign(&mut self, keypair: &KeyPair) -> RollupResult<()> {
        let signing_data = self.create_signing_data()?;
        self.signature = keypair.sign(&signing_data);
        Ok(())
    }

    pub fn verify_signature(&self, public_key: &PublicKey) -> RollupResult<bool> {
        let expected_challenger = Address::from_public_key(public_key);
        if expected_challenger != self.challenger {
            return Ok(false);
        }

        let signing_data = self.create_signing_data()?;
        ego_core::verify_signature(public_key, &signing_data, &self.signature)
            .map_err(|e| RollupError::FraudProof(format!("Signature verification failed: {}", e)))
    }

    pub fn validate(&self) -> RollupResult<()> {
        match self.fraud_reason {
            InclusionFraudReason::InvalidSignature => {
                if self.invalid_transaction.inner.verify_signature()? {
                    return Err(RollupError::FraudProof(
                        "Transaction signature is actually valid".to_string(),
                    ));
                }
            }
            InclusionFraudReason::MalformedTransaction => {}
            _ => {}
        }

        Ok(())
    }

    fn create_signing_data(&self) -> RollupResult<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(self.proof_id.as_bytes());
        data.extend_from_slice(self.challenger.as_bytes());
        data.extend_from_slice(self.commitment_hash.as_bytes());
        data.extend_from_slice(self.invalid_transaction.hash().as_bytes());
        data.extend_from_slice(&self.timestamp.as_millis().to_le_bytes());

        let fraud_reason_bytes = format!("{:?}", self.fraud_reason).into_bytes();
        data.extend_from_slice(&fraud_reason_bytes);

        Ok(data)
    }
}

impl FraudProofVerifier {
    pub fn new(min_confidence: f64, max_age_hours: u64) -> Self {
        Self {
            min_confidence,
            max_age_hours,
        }
    }

    pub fn verify_fraud_proof(&self, proof: &FraudProof) -> RollupResult<bool> {
        proof.validate()?;

        if proof.confidence < self.min_confidence {
            return Ok(false);
        }

        let age_hours = (Timestamp::now().as_millis() - proof.timestamp.as_millis()) / 3_600_000;
        if age_hours > self.max_age_hours {
            return Ok(false);
        }

        if !proof.verify_signature()? {
            return Ok(false);
        }

        self.verify_evidence(proof)?;

        Ok(true)
    }

    fn verify_evidence(&self, proof: &FraudProof) -> RollupResult<bool> {
        match &proof.evidence.evidence_type {
            FraudEvidenceType::StateTransition {
                pre_state,
                post_state,
                expected_post_state,
                ..
            } => Ok(post_state != expected_post_state && pre_state != post_state),
            FraudEvidenceType::InvalidInclusion {
                inclusion_proof,
                merkle_root,
                ..
            } => self.verify_inclusion_proof(inclusion_proof, merkle_root),
            FraudEvidenceType::DataUnavailability { missing_chunks, .. } => {
                Ok(!missing_chunks.is_empty())
            }
            FraudEvidenceType::ExecutionError {
                expected_result,
                actual_result,
                ..
            } => Ok(expected_result != actual_result),
        }
    }

    fn verify_inclusion_proof(
        &self,
        _inclusion_proof: &[Hash],
        _merkle_root: &Hash,
    ) -> RollupResult<bool> {
        Ok(true)
    }

    pub fn execute_fraud_proof(&self, proof: &FraudProof) -> RollupResult<FraudProofResult> {
        if !self.verify_fraud_proof(proof)? {
            return Ok(FraudProofResult {
                success: false,
                slash_amount: 0,
                challenger_reward: 0,
                reason: "Fraud proof verification failed".to_string(),
            });
        }

        let base_slash = match proof.fraud_type {
            RollupFraudType::InvalidStateTransition => 500_000,
            RollupFraudType::InvalidInclusion => 300_000,
            RollupFraudType::DataUnavailable => 200_000,
            RollupFraudType::InvalidExecution => 400_000,
            RollupFraudType::IncorrectStateRoot => 600_000,
            RollupFraudType::InvalidSignature => 100_000,
            RollupFraudType::DuplicateTransaction => 150_000,
        };

        let confidence_multiplier = proof.confidence;
        let slash_amount = (base_slash as f64 * confidence_multiplier) as u64;
        let challenger_reward = slash_amount / 2;

        Ok(FraudProofResult {
            success: true,
            slash_amount,
            challenger_reward,
            reason: format!("Rollup fraud proven: {:?}", proof.fraud_type),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudProofResult {
    pub success: bool,
    pub slash_amount: u64,
    pub challenger_reward: u64,
    pub reason: String,
}

impl Default for FraudProofVerifier {
    fn default() -> Self {
        Self::new(0.8, 24)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::{Balance, KeyPair, ShardId, Transaction, TransactionPayload};

    fn create_test_commitment() -> RollupCommitment {
        RollupCommitment {
            commitment_hash: Hash::new([1u8; 32]),
            operator: Address::new([1u8; 20]),
            rollup_id: "test-rollup".to_string(),
            state_root: Hash::new([2u8; 32]),
            previous_state_root: Hash::new([3u8; 32]),
            tx_root: Hash::new([4u8; 32]),
            da_root: Hash::new([5u8; 32]),
            proofs_root: Hash::new([6u8; 32]),
            tx_count: 1,
            block_range: (1000, 1000),
            l1_block_number: 1000,
            timestamp: Timestamp::now(),
            operator_signature: Signature::new([0u8; 64]),
            proof_data: vec![],
            da_chunks: vec![],
            gas_used: 21000,
            version: 1,
        }
    }

    fn create_test_transaction() -> RollupTransaction {
        let inner = Transaction::new(
            Address::new([1u8; 20]),
            1,
            TransactionPayload::Transfer {
                to: Address::new([2u8; 20]),
                amount: Balance::from_egoc(100),
                memo: None,
            },
            ShardId::new(0).unwrap(),
            None,
        );

        crate::types::RollupTransaction::new(inner, 1, 1000)
    }

    #[test]
    fn test_fraud_proof_creation() {
        let challenger = Address::new([1u8; 20]);
        let commitment_hash = Hash::new([1u8; 32]);
        let commitment = create_test_commitment();

        let evidence = FraudEvidence {
            commitment,
            evidence_type: FraudEvidenceType::StateTransition {
                pre_state: Hash::new([1u8; 32]),
                post_state: Hash::new([2u8; 32]),
                expected_post_state: Hash::new([3u8; 32]),
                execution_trace: vec![],
            },
            proof_data: vec![],
            witness_data: None,
        };

        let proof = FraudProof::new(
            challenger,
            commitment_hash,
            RollupFraudType::InvalidStateTransition,
            evidence,
            0.9,
        );

        assert_eq!(proof.challenger, challenger);
        assert_eq!(proof.commitment_hash, commitment_hash);
        assert_eq!(proof.fraud_type, RollupFraudType::InvalidStateTransition);
        assert_eq!(proof.confidence, 0.9);
    }

    #[test]
    fn test_fraud_proof_signing() {
        let keypair = KeyPair::generate();
        let challenger = Address::from_public_key(&keypair.public_key());
        let commitment = create_test_commitment();

        let evidence = FraudEvidence {
            commitment,
            evidence_type: FraudEvidenceType::InvalidInclusion {
                inclusion_proof: vec![],
                merkle_root: Hash::new([1u8; 32]),
                invalid_reason: "Invalid signature".to_string(),
            },
            proof_data: vec![],
            witness_data: None,
        };

        let mut proof = FraudProof::new(
            challenger,
            Hash::new([1u8; 32]),
            RollupFraudType::InvalidInclusion,
            evidence,
            0.85,
        );

        assert!(proof.sign(&keypair).is_ok());
        assert!(proof.verify_signature().unwrap());
    }

    #[test]
    fn test_fraud_proof_validation() {
        let challenger = Address::new([1u8; 20]);
        let commitment = create_test_commitment();

        let evidence = FraudEvidence {
            commitment,
            evidence_type: FraudEvidenceType::DataUnavailability {
                missing_chunks: vec![1, 2, 3],
                sample_proofs: vec![],
                timeout_evidence: vec![],
            },
            proof_data: vec![],
            witness_data: None,
        };

        let proof = FraudProof::new(
            challenger,
            Hash::new([1u8; 32]),
            RollupFraudType::DataUnavailable,
            evidence,
            0.8,
        );

        assert!(proof.validate().is_ok());
    }

    #[test]
    fn test_invalid_inclusion_proof() {
        let challenger = Address::new([1u8; 20]);
        let commitment_hash = Hash::new([1u8; 32]);
        let rollup_transaction = create_test_transaction();

        let proof = InvalidInclusionProof::new(
            challenger,
            commitment_hash,
            rollup_transaction,
            vec![],
            InclusionFraudReason::InvalidSignature,
        );

        assert_eq!(proof.challenger, challenger);
        assert_eq!(proof.fraud_reason, InclusionFraudReason::InvalidSignature);
    }

    #[test]
    fn test_fraud_proof_verifier() {
        let verifier = FraudProofVerifier::default();
        let challenger = Address::new([1u8; 20]);
        let commitment = create_test_commitment();

        let evidence = FraudEvidence {
            commitment,
            evidence_type: FraudEvidenceType::ExecutionError {
                expected_result: vec![1, 2, 3],
                actual_result: vec![4, 5, 6],
                error_trace: "Execution mismatch".to_string(),
            },
            proof_data: vec![],
            witness_data: None,
        };

        let proof = FraudProof::new(
            challenger,
            Hash::new([1u8; 32]),
            RollupFraudType::InvalidExecution,
            evidence,
            0.9,
        );
        assert!(proof.validate().is_ok());
    }

    #[test]
    fn test_fraud_proof_execution() {
        let verifier = FraudProofVerifier::default();
        let keypair = KeyPair::generate();
        let challenger = Address::from_public_key(&keypair.public_key());
        let commitment = create_test_commitment();

        let evidence = FraudEvidence {
            commitment,
            evidence_type: FraudEvidenceType::StateTransition {
                pre_state: Hash::new([1u8; 32]),
                post_state: Hash::new([2u8; 32]),
                expected_post_state: Hash::new([3u8; 32]),
                execution_trace: vec![],
            },
            proof_data: vec![],
            witness_data: None,
        };

        let mut proof = FraudProof::new(
            challenger,
            Hash::new([1u8; 32]),
            RollupFraudType::IncorrectStateRoot,
            evidence,
            0.9,
        );

        proof.sign(&keypair).unwrap();

        let result = verifier.execute_fraud_proof(&proof).unwrap();
        assert!(result.success);
        assert!(result.slash_amount > 0);
        assert!(result.challenger_reward > 0);
    }
}
