use ego_core::{
    Address, AlgorithmId, Balance, BlockHeight, EgoError, EgoResult, EpochNumber, Hash, PublicKey,
    ShardId, Timestamp,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollupError {
    FraudProof(String),
    SerializationError(String),
    InvalidCommitment(String),
    ValidationError(String),
}

pub type RollupResult<T> = Result<T, RollupError>;

impl From<EgoError> for RollupError {
    fn from(err: EgoError) -> Self {
        match err {
            EgoError::SerializationError(s) => RollupError::SerializationError(s),
            EgoError::InvalidBlock(s) => RollupError::ValidationError(s),
            EgoError::InvalidTransaction(s) => RollupError::ValidationError(s),
            _ => RollupError::ValidationError(format!("{:?}", err)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct RollupCommitment {
    pub rollup_id: String,
    pub state_root: Hash,
    pub previous_state_root: Hash,
    pub tx_root: Hash,
    pub proofs_root: Hash,
    pub da_root: Hash,
    pub tx_count: u32,
    pub block_range: (u64, u64),
    pub operator: Address,
    pub timestamp: Timestamp,
    pub epoch: u64,
    pub commitment_hash: Hash,
}

impl RollupCommitment {
    pub fn compute_hash(&self) -> Hash {
        let _config = bincode::config::standard();
        let mut data = Vec::new();
        data.extend_from_slice(b"ego/rollup/commit/v1");
        data.extend_from_slice(self.rollup_id.as_bytes());
        data.extend_from_slice(self.state_root.as_bytes());
        data.extend_from_slice(self.previous_state_root.as_bytes());
        data.extend_from_slice(self.tx_root.as_bytes());
        data.extend_from_slice(self.proofs_root.as_bytes());
        data.extend_from_slice(self.da_root.as_bytes());
        data.extend_from_slice(&self.tx_count.to_le_bytes());
        data.extend_from_slice(&self.block_range.0.to_le_bytes());
        data.extend_from_slice(&self.block_range.1.to_le_bytes());
        data.extend_from_slice(self.operator.as_bytes());
        data.extend_from_slice(&self.epoch.to_le_bytes());
        ego_core::crypto::hash_data(&data)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct RollupTransaction {
    pub inner: ego_core::Transaction,
    pub rollup_id: String,
    pub batch_index: u32,
}

impl RollupTransaction {
    pub fn hash(&self) -> Hash {
        self.inner.hash
    }

    pub fn verify_signature(&self) -> RollupResult<bool> {
        self.inner.verify_signature().map_err(|e| e.into())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct FraudProof {
    pub proof_id: Hash,
    pub challenger: Address,
    pub commitment_hash: Hash,
    pub fraud_type: RollupFraudType,
    pub evidence: FraudEvidence,
    pub confidence: f64,
    pub timestamp: Timestamp,
    pub signature: Vec<u8>,
    pub dilithium_pk: Vec<u8>,
    pub ed25519_pk: Option<Vec<u8>>,
    pub challenge_bond: u64,
    pub deadline_epoch: u64,
}

#[derive(
    Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode, PartialEq, Eq, Hash,
)]
pub enum RollupFraudType {
    InvalidStateTransition,
    InvalidInclusion,
    DataUnavailable,
    InvalidExecution,
    IncorrectStateRoot,
    InvalidSignature,
    DuplicateTransaction,
    InvalidProofAggregation,
    InvalidCrossShardReceipt,
    MerkleRootMismatch,
    InvalidEpochAnchor,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct FraudEvidence {
    pub commitment: RollupCommitment,
    pub evidence_type: FraudEvidenceType,
    pub proof_data: Vec<u8>,
    pub witness_data: Option<Vec<u8>>,
    pub reference_commitments: Vec<Hash>,
    pub auxiliary_data: HashMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum FraudEvidenceType {
    StateTransition {
        pre_state: Hash,
        post_state: Hash,
        expected_post_state: Hash,
        execution_trace: Vec<u8>,
        transaction_batch: Vec<RollupTransaction>,
        intermediate_states: Vec<Hash>,
    },
    InvalidInclusion {
        inclusion_proof: Vec<Hash>,
        merkle_root: Hash,
        invalid_reason: String,
        transaction_index: u32,
        claimed_transaction: RollupTransaction,
    },
    DataUnavailability {
        missing_chunks: Vec<u32>,
        sample_proofs: Vec<Vec<u8>>,
        timeout_evidence: Vec<TimeoutEvidence>,
        sampling_requests: Vec<SamplingRequest>,
        total_chunks: u32,
    },
    ExecutionError {
        expected_result: Vec<u8>,
        actual_result: Vec<u8>,
        error_trace: String,
        transaction: RollupTransaction,
        pre_state_proof: Vec<Hash>,
    },
    ProofAggregation {
        claimed_proof_root: Hash,
        actual_proofs: Vec<Vec<u8>>,
        recomputed_root: Hash,
        invalid_indices: Vec<u32>,
    },
    CrossShardInvalid {
        receipt_hash: Hash,
        source_shard: u32,
        target_shard: u32,
        merkle_proof: Vec<Hash>,
        invalid_reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct TimeoutEvidence {
    pub chunk_id: u32,
    pub request_timestamp: Timestamp,
    pub timeout_timestamp: Timestamp,
    pub operator: Address,
    pub retry_count: u32,
    pub last_error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct SamplingRequest {
    pub request_id: Hash,
    pub chunk_indices: Vec<u32>,
    pub timestamp: Timestamp,
    pub requester: Address,
    pub response_received: bool,
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
    pub signature: Vec<u8>,
    pub expected_merkle_root: Hash,
    pub actual_merkle_root: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub enum InclusionFraudReason {
    InvalidSignature,
    InvalidNonce,
    InsufficientBalance,
    MalformedTransaction,
    DuplicateTransaction,
    UnauthorizedShard,
    ExpiredTransaction,
    InvalidResourceUnits,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct FraudChallenge {
    pub challenge_id: Hash,
    pub proof_id: Hash,
    pub commitment_hash: Hash,
    pub challenger: Address,
    pub operator: Address,
    pub fraud_type: RollupFraudType,
    pub challenge_bond: u64,
    pub response_bond: u64,
    pub status: ChallengeStatus,
    pub created_at: Timestamp,
    pub deadline_epoch: u64,
    pub response: Option<ChallengeResponse>,
    pub resolution: Option<ChallengeResolution>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum ChallengeStatus {
    Pending,
    Responded,
    Validated,
    Rejected,
    Expired,
    Slashed,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ChallengeResponse {
    pub response_id: Hash,
    pub responder: Address,
    pub counter_evidence: Vec<u8>,
    pub proof_correctness: Vec<Hash>,
    pub timestamp: Timestamp,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ChallengeResolution {
    pub resolution_id: Hash,
    pub challenge_id: Hash,
    pub resolution_type: ResolutionType,
    pub slashed_party: Option<Address>,
    pub slash_amount: u64,
    pub reward_amount: u64,
    pub evidence_hash: Hash,
    pub resolved_at: Timestamp,
    pub resolver: Address,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum ResolutionType {
    ChallengeValid,
    ChallengeInvalid,
    BothSlashed,
    Inconclusive,
    Expired,
}

#[derive(Debug, Clone)]
pub struct FraudProofVerifier {
    min_confidence: f64,
    max_age_hours: u64,
    verified_proofs: HashSet<Hash>,
    active_challenges: HashMap<Hash, FraudChallenge>,
    resolution_history: Vec<ChallengeResolution>,
    slashing_params: SlashingParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingParams {
    pub base_slash_amounts: HashMap<RollupFraudType, u64>,
    pub confidence_multiplier_enabled: bool,
    pub max_slash_amount: u64,
    pub min_slash_amount: u64,
    pub challenger_reward_percentage: u64,
    pub false_challenge_penalty: u64,
}

impl Default for SlashingParams {
    fn default() -> Self {
        let mut base_slash_amounts = HashMap::new();
        base_slash_amounts.insert(RollupFraudType::InvalidStateTransition, 500_000);
        base_slash_amounts.insert(RollupFraudType::InvalidInclusion, 300_000);
        base_slash_amounts.insert(RollupFraudType::DataUnavailable, 200_000);
        base_slash_amounts.insert(RollupFraudType::InvalidExecution, 400_000);
        base_slash_amounts.insert(RollupFraudType::IncorrectStateRoot, 600_000);
        base_slash_amounts.insert(RollupFraudType::InvalidSignature, 100_000);
        base_slash_amounts.insert(RollupFraudType::DuplicateTransaction, 150_000);
        base_slash_amounts.insert(RollupFraudType::InvalidProofAggregation, 450_000);
        base_slash_amounts.insert(RollupFraudType::InvalidCrossShardReceipt, 350_000);
        base_slash_amounts.insert(RollupFraudType::MerkleRootMismatch, 250_000);
        base_slash_amounts.insert(RollupFraudType::InvalidEpochAnchor, 800_000);
        Self {
            base_slash_amounts,
            confidence_multiplier_enabled: true,
            max_slash_amount: 1_000_000,
            min_slash_amount: 50_000,
            challenger_reward_percentage: 50,
            false_challenge_penalty: 100_000,
        }
    }
}

impl FraudProof {
    pub fn new(
        challenger: Address,
        commitment_hash: Hash,
        fraud_type: RollupFraudType,
        evidence: FraudEvidence,
        confidence: f64,
        challenge_bond: u64,
        deadline_epoch: u64,
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
            signature: Vec::new(),
            dilithium_pk: Vec::new(),
            ed25519_pk: None,
            challenge_bond,
            deadline_epoch,
        }
    }

    pub fn sign(&mut self, keypair: &ego_core::crypto::KeyPair) -> RollupResult<()> {
        self.dilithium_pk = keypair.dilithium_public_key().key_data;
        if keypair.is_transition_mode() {
            self.ed25519_pk = Some(keypair.ed25519_public_key().key_data[..32].to_vec());
        }
        let expected_challenger = Address::from_public_key(&keypair.dilithium_public_key());
        if expected_challenger != self.challenger {
            return Err(RollupError::FraudProof(
                "Challenger address does not match signing key".to_string(),
            ));
        }
        let signing_data = self.create_signing_data()?;
        let sig = keypair.sign_dilithium(&signing_data);
        self.signature = sig.signature_data;
        Ok(())
    }

    pub fn verify_signature(&self) -> RollupResult<bool> {
        if self.dilithium_pk.is_empty() {
            return Ok(false);
        }
        let pubkey = PublicKey::dilithium2(self.dilithium_pk.clone());
        let expected_challenger = Address::from_public_key(&pubkey);
        if expected_challenger != self.challenger {
            return Ok(false);
        }
        let signing_data = self.create_signing_data()?;
        ego_core::crypto::verify_dilithium_signature(
            &self.dilithium_pk,
            &signing_data,
            &self.signature,
        )
        .map_err(|e| RollupError::FraudProof(format!("Signature verification failed: {:?}", e)))
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
        if self.challenge_bond == 0 {
            return Err(RollupError::FraudProof(
                "Challenge bond must be greater than zero".to_string(),
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
                transaction_batch,
                intermediate_states,
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
                if transaction_batch.is_empty() {
                    return Err(RollupError::FraudProof(
                        "State transition must include transactions".to_string(),
                    ));
                }
                if !intermediate_states.is_empty()
                    && intermediate_states.len() != transaction_batch.len() + 1
                {
                    return Err(RollupError::FraudProof(
                        "Intermediate states count mismatch".to_string(),
                    ));
                }
            }
            FraudEvidenceType::InvalidInclusion {
                invalid_reason,
                inclusion_proof,
                transaction_index,
                ..
            } => {
                if invalid_reason.is_empty() {
                    return Err(RollupError::FraudProof(
                        "Invalid inclusion must have a reason".to_string(),
                    ));
                }
                if inclusion_proof.is_empty() {
                    return Err(RollupError::FraudProof(
                        "Inclusion proof cannot be empty".to_string(),
                    ));
                }
                if *transaction_index >= self.evidence.commitment.tx_count {
                    return Err(RollupError::FraudProof(
                        "Transaction index out of bounds".to_string(),
                    ));
                }
            }
            FraudEvidenceType::DataUnavailability {
                missing_chunks,
                total_chunks,
                timeout_evidence,
                sampling_requests,
                ..
            } => {
                if missing_chunks.is_empty() {
                    return Err(RollupError::FraudProof(
                        "Data unavailability proof must specify missing chunks".to_string(),
                    ));
                }
                if *total_chunks == 0 {
                    return Err(RollupError::FraudProof(
                        "Total chunks must be greater than zero".to_string(),
                    ));
                }
                for chunk_id in missing_chunks.iter() {
                    if *chunk_id >= *total_chunks {
                        return Err(RollupError::FraudProof(
                            "Missing chunk ID out of range".to_string(),
                        ));
                    }
                }
                if timeout_evidence.is_empty() {
                    return Err(RollupError::FraudProof(
                        "Timeout evidence required for DA proof".to_string(),
                    ));
                }
                if sampling_requests.is_empty() {
                    return Err(RollupError::FraudProof(
                        "Sampling requests required for DA proof".to_string(),
                    ));
                }
            }
            FraudEvidenceType::ExecutionError {
                expected_result,
                actual_result,
                pre_state_proof,
                ..
            } => {
                if expected_result == actual_result {
                    return Err(RollupError::FraudProof(
                        "Expected and actual results are the same".to_string(),
                    ));
                }
                if pre_state_proof.is_empty() {
                    return Err(RollupError::FraudProof(
                        "Pre-state proof required for execution error".to_string(),
                    ));
                }
            }
            FraudEvidenceType::ProofAggregation {
                claimed_proof_root,
                recomputed_root,
                actual_proofs,
                invalid_indices,
                ..
            } => {
                if claimed_proof_root == recomputed_root {
                    return Err(RollupError::FraudProof(
                        "Claimed and recomputed roots are the same".to_string(),
                    ));
                }
                if actual_proofs.is_empty() {
                    return Err(RollupError::FraudProof(
                        "Actual proofs required for aggregation fraud".to_string(),
                    ));
                }
                if invalid_indices.is_empty() {
                    return Err(RollupError::FraudProof(
                        "Invalid indices must be specified".to_string(),
                    ));
                }
            }
            FraudEvidenceType::CrossShardInvalid {
                merkle_proof,
                invalid_reason,
                ..
            } => {
                if merkle_proof.is_empty() {
                    return Err(RollupError::FraudProof(
                        "Merkle proof required for cross-shard fraud".to_string(),
                    ));
                }
                if invalid_reason.is_empty() {
                    return Err(RollupError::FraudProof(
                        "Invalid reason required for cross-shard fraud".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn create_signing_data(&self) -> RollupResult<Vec<u8>> {
        let config = bincode::config::standard();
        let mut data = Vec::new();
        data.extend_from_slice(b"ego/fraud/v1");
        data.extend_from_slice(self.proof_id.as_bytes());
        data.extend_from_slice(self.challenger.as_bytes());
        data.extend_from_slice(self.commitment_hash.as_bytes());
        data.extend_from_slice(&self.timestamp.as_millis().to_le_bytes());
        data.extend_from_slice(&self.confidence.to_le_bytes());
        data.extend_from_slice(&self.challenge_bond.to_le_bytes());
        data.extend_from_slice(&self.deadline_epoch.to_le_bytes());
        let fraud_type_bytes = bincode::encode_to_vec(&self.fraud_type, config)
            .map_err(|e| RollupError::SerializationError(e.to_string()))?;
        data.extend_from_slice(&fraud_type_bytes);
        let evidence_bytes = bincode::encode_to_vec(&self.evidence, config)
            .map_err(|e| RollupError::SerializationError(e.to_string()))?;
        let evidence_hash = ego_core::crypto::hash_data(&evidence_bytes);
        data.extend_from_slice(evidence_hash.as_bytes());
        Ok(ego_core::crypto::blake2s_hash(&data))
    }

    fn compute_proof_id(
        challenger: Address,
        commitment_hash: Hash,
        fraud_type: &RollupFraudType,
        timestamp: Timestamp,
    ) -> Hash {
        let config = bincode::config::standard();
        let fraud_type_bytes = bincode::encode_to_vec(fraud_type, config).unwrap_or_default();
        ego_core::crypto::hash_multiple(&[
            b"ego/fraud/id/v1",
            challenger.as_bytes(),
            commitment_hash.as_bytes(),
            &fraud_type_bytes,
            &timestamp.as_millis().to_le_bytes(),
        ])
    }

    pub fn severity_score(&self) -> u32 {
        let base_severity = match self.fraud_type {
            RollupFraudType::InvalidEpochAnchor => 10,
            RollupFraudType::IncorrectStateRoot => 9,
            RollupFraudType::InvalidStateTransition => 8,
            RollupFraudType::InvalidProofAggregation => 7,
            RollupFraudType::InvalidExecution => 6,
            RollupFraudType::InvalidCrossShardReceipt => 5,
            RollupFraudType::InvalidInclusion => 4,
            RollupFraudType::MerkleRootMismatch => 3,
            RollupFraudType::DataUnavailable => 3,
            RollupFraudType::DuplicateTransaction => 2,
            RollupFraudType::InvalidSignature => 1,
        };
        let confidence_bonus = (self.confidence * 5.0) as u32;
        base_severity + confidence_bonus
    }
}

impl FraudProofVerifier {
    pub fn new(min_confidence: f64, max_age_hours: u64) -> Self {
        Self {
            min_confidence,
            max_age_hours,
            verified_proofs: HashSet::new(),
            active_challenges: HashMap::new(),
            resolution_history: Vec::new(),
            slashing_params: SlashingParams::default(),
        }
    }

    pub fn with_slashing_params(mut self, params: SlashingParams) -> Self {
        self.slashing_params = params;
        self
    }

    pub fn verify_fraud_proof(&mut self, proof: &FraudProof) -> RollupResult<bool> {
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
        if self.verified_proofs.contains(&proof.proof_id) {
            return Ok(true);
        }
        let evidence_valid = self.verify_evidence(proof)?;
        if evidence_valid {
            self.verified_proofs.insert(proof.proof_id);
        }
        Ok(evidence_valid)
    }

    fn verify_evidence(&self, proof: &FraudProof) -> RollupResult<bool> {
        match &proof.evidence.evidence_type {
            FraudEvidenceType::StateTransition {
                pre_state,
                post_state,
                expected_post_state,
                transaction_batch,
                intermediate_states,
                ..
            } => {
                if post_state == expected_post_state {
                    return Ok(false);
                }
                if pre_state == post_state {
                    return Ok(false);
                }
                if transaction_batch.is_empty() {
                    return Ok(false);
                }
                if !intermediate_states.is_empty() {
                    if intermediate_states[0] != *pre_state {
                        return Ok(false);
                    }
                    if intermediate_states[intermediate_states.len() - 1] != *post_state {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            FraudEvidenceType::InvalidInclusion {
                inclusion_proof,
                merkle_root,
                claimed_transaction,
                ..
            } => {
                if inclusion_proof.is_empty() {
                    return Ok(false);
                }
                let tx_hash = claimed_transaction.hash();
                self.verify_merkle_inclusion(inclusion_proof, merkle_root, &tx_hash)
            }
            FraudEvidenceType::DataUnavailability {
                missing_chunks,
                total_chunks,
                timeout_evidence,
                ..
            } => {
                if missing_chunks.is_empty() {
                    return Ok(false);
                }
                let missing_percentage =
                    (missing_chunks.len() as f64 / *total_chunks as f64) * 100.0;
                if missing_percentage < 10.0 {
                    return Ok(false);
                }
                for evidence in timeout_evidence {
                    let timeout_duration = evidence.timeout_timestamp.as_millis()
                        - evidence.request_timestamp.as_millis();
                    if timeout_duration < 30_000 {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            FraudEvidenceType::ExecutionError {
                expected_result,
                actual_result,
                pre_state_proof,
                ..
            } => {
                if expected_result == actual_result {
                    return Ok(false);
                }
                if pre_state_proof.is_empty() {
                    return Ok(false);
                }
                Ok(true)
            }
            FraudEvidenceType::ProofAggregation {
                claimed_proof_root,
                recomputed_root,
                actual_proofs,
                ..
            } => {
                if claimed_proof_root == recomputed_root {
                    return Ok(false);
                }
                if actual_proofs.is_empty() {
                    return Ok(false);
                }
                let computed_root = self.compute_proof_root(actual_proofs);
                Ok(computed_root == *recomputed_root)
            }
            FraudEvidenceType::CrossShardInvalid { merkle_proof, .. } => {
                Ok(!merkle_proof.is_empty())
            }
        }
    }

    fn verify_merkle_inclusion(
        &self,
        proof: &[Hash],
        root: &Hash,
        leaf: &Hash,
    ) -> RollupResult<bool> {
        if proof.is_empty() {
            return Ok(false);
        }
        let mut current_hash = *leaf;
        for proof_element in proof {
            current_hash = ego_core::crypto::hash_multiple(&[
                current_hash.as_bytes(),
                proof_element.as_bytes(),
            ]);
        }
        Ok(current_hash != *root)
    }

    fn compute_proof_root(&self, proofs: &[Vec<u8>]) -> Hash {
        let proof_hashes: Vec<Vec<u8>> = proofs
            .iter()
            .map(|p| ego_core::crypto::hash_data(p).to_vec())
            .collect();
        let merkle_tree = ego_core::crypto::MerkleTree::build(proof_hashes);
        merkle_tree
            .root_hash()
            .unwrap_or_else(|| Hash::new([0u8; 32]))
    }

    pub fn execute_fraud_proof(&mut self, proof: &FraudProof) -> RollupResult<FraudProofResult> {
        if !self.verify_fraud_proof(proof)? {
            return Ok(FraudProofResult {
                success: false,
                slash_amount: 0,
                challenger_reward: 0,
                reason: "Fraud proof verification failed".to_string(),
                slashed_party: None,
            });
        }
        let base_slash = self
            .slashing_params
            .base_slash_amounts
            .get(&proof.fraud_type)
            .copied()
            .unwrap_or(100_000);
        let slash_amount = if self.slashing_params.confidence_multiplier_enabled {
            let multiplied = (base_slash as f64 * proof.confidence) as u64;
            multiplied
                .min(self.slashing_params.max_slash_amount)
                .max(self.slashing_params.min_slash_amount)
        } else {
            base_slash
                .min(self.slashing_params.max_slash_amount)
                .max(self.slashing_params.min_slash_amount)
        };
        let challenger_reward =
            (slash_amount * self.slashing_params.challenger_reward_percentage) / 100;
        Ok(FraudProofResult {
            success: true,
            slash_amount,
            challenger_reward,
            reason: format!("Rollup fraud proven: {:?}", proof.fraud_type),
            slashed_party: Some(proof.evidence.commitment.operator),
        })
    }

    pub fn create_challenge(&mut self, proof: &FraudProof) -> RollupResult<FraudChallenge> {
        if !self.verify_fraud_proof(proof)? {
            return Err(RollupError::FraudProof(
                "Cannot create challenge from invalid proof".to_string(),
            ));
        }
        let challenge_id = ego_core::crypto::hash_multiple(&[
            b"ego/fraud/challenge/v1",
            proof.proof_id.as_bytes(),
            proof.commitment_hash.as_bytes(),
            &Timestamp::now().as_millis().to_le_bytes(),
        ]);
        let challenge = FraudChallenge {
            challenge_id,
            proof_id: proof.proof_id,
            commitment_hash: proof.commitment_hash,
            challenger: proof.challenger,
            operator: proof.evidence.commitment.operator,
            fraud_type: proof.fraud_type.clone(),
            challenge_bond: proof.challenge_bond,
            response_bond: proof.challenge_bond * 2,
            status: ChallengeStatus::Pending,
            created_at: Timestamp::now(),
            deadline_epoch: proof.deadline_epoch,
            response: None,
            resolution: None,
        };
        self.active_challenges
            .insert(challenge_id, challenge.clone());
        Ok(challenge)
    }

    pub fn respond_to_challenge(
        &mut self,
        challenge_id: Hash,
        response: ChallengeResponse,
    ) -> RollupResult<()> {
        let challenge = self
            .active_challenges
            .get_mut(&challenge_id)
            .ok_or_else(|| RollupError::FraudProof("Challenge not found".to_string()))?;
        if challenge.status != ChallengeStatus::Pending {
            return Err(RollupError::FraudProof(
                "Challenge is not in pending state".to_string(),
            ));
        }
        if response.responder != challenge.operator {
            return Err(RollupError::FraudProof(
                "Response must come from challenged operator".to_string(),
            ));
        }
        challenge.response = Some(response);
        challenge.status = ChallengeStatus::Responded;
        Ok(())
    }

    pub fn resolve_challenge(
        &mut self,
        challenge_id: Hash,
        resolver: Address,
        current_epoch: u64,
    ) -> RollupResult<ChallengeResolution> {
        let challenge = self
            .active_challenges
            .get(&challenge_id)
            .ok_or_else(|| RollupError::FraudProof("Challenge not found".to_string()))?
            .clone();
        if challenge.status == ChallengeStatus::Validated
            || challenge.status == ChallengeStatus::Rejected
        {
            return Err(RollupError::FraudProof(
                "Challenge already resolved".to_string(),
            ));
        }
        let resolution_type: ResolutionType;
        let slashed_party: Option<Address>;
        let slash_amount: u64;
        let reward_amount: u64;
        let new_status: ChallengeStatus;
        if current_epoch > challenge.deadline_epoch {
            if challenge.response.is_none() {
                resolution_type = ResolutionType::ChallengeValid;
                slashed_party = Some(challenge.operator);
                slash_amount = challenge.response_bond;
                reward_amount = challenge.challenge_bond + (slash_amount / 2);
                new_status = ChallengeStatus::Slashed;
            } else {
                resolution_type = ResolutionType::Expired;
                slashed_party = None;
                slash_amount = 0;
                reward_amount = 0;
                new_status = ChallengeStatus::Expired;
            }
        } else if let Some(ref response) = challenge.response {
            let counter_evidence_valid = self.verify_counter_evidence(&challenge, response)?;
            if counter_evidence_valid {
                resolution_type = ResolutionType::ChallengeInvalid;
                slashed_party = Some(challenge.challenger);
                slash_amount = self.slashing_params.false_challenge_penalty;
                reward_amount = challenge.response_bond;
                new_status = ChallengeStatus::Rejected;
            } else {
                resolution_type = ResolutionType::ChallengeValid;
                slashed_party = Some(challenge.operator);
                slash_amount = challenge.response_bond;
                reward_amount = challenge.challenge_bond + (slash_amount / 2);
                new_status = ChallengeStatus::Slashed;
            }
        } else {
            return Err(RollupError::FraudProof(
                "Challenge not ready for resolution".to_string(),
            ));
        }
        let config = bincode::config::standard();
        let evidence_data =
            bincode::encode_to_vec(&(challenge.proof_id, challenge.response.as_ref()), config)
                .map_err(|e| RollupError::SerializationError(e.to_string()))?;
        let evidence_hash = ego_core::crypto::hash_data(&evidence_data);
        let resolution_id = ego_core::crypto::hash_multiple(&[
            b"ego/fraud/resolution/v1",
            challenge_id.as_bytes(),
            &Timestamp::now().as_millis().to_le_bytes(),
        ]);
        let resolution = ChallengeResolution {
            resolution_id,
            challenge_id,
            resolution_type,
            slashed_party,
            slash_amount,
            reward_amount,
            evidence_hash,
            resolved_at: Timestamp::now(),
            resolver,
        };
        let challenge_mut = self
            .active_challenges
            .get_mut(&challenge_id)
            .ok_or_else(|| RollupError::FraudProof("Challenge not found".to_string()))?;
        challenge_mut.status = new_status;
        challenge_mut.resolution = Some(resolution.clone());
        self.resolution_history.push(resolution.clone());
        Ok(resolution)
    }

    fn verify_counter_evidence(
        &self,
        _challenge: &FraudChallenge,
        response: &ChallengeResponse,
    ) -> RollupResult<bool> {
        if response.counter_evidence.is_empty() {
            return Ok(false);
        }
        if response.proof_correctness.is_empty() {
            return Ok(false);
        }
        Ok(response.counter_evidence.len() >= 100)
    }

    pub fn get_challenge(&self, challenge_id: &Hash) -> Option<&FraudChallenge> {
        self.active_challenges.get(challenge_id)
    }

    pub fn get_active_challenges(&self) -> Vec<&FraudChallenge> {
        self.active_challenges
            .values()
            .filter(|c| {
                c.status == ChallengeStatus::Pending || c.status == ChallengeStatus::Responded
            })
            .collect()
    }

    pub fn get_resolution_history(&self) -> &[ChallengeResolution] {
        &self.resolution_history
    }

    pub fn prune_old_challenges(&mut self, cutoff_epoch: u64) -> usize {
        let before_count = self.active_challenges.len();
        self.active_challenges.retain(|_, challenge| {
            challenge.deadline_epoch >= cutoff_epoch || challenge.status == ChallengeStatus::Pending
        });
        before_count - self.active_challenges.len()
    }

    pub fn get_fraud_statistics(&self) -> FraudStatistics {
        let total_challenges = self.active_challenges.len() + self.resolution_history.len();
        let resolved_challenges = self.resolution_history.len();
        let pending_challenges = self
            .active_challenges
            .values()
            .filter(|c| c.status == ChallengeStatus::Pending)
            .count();
        let successful_challenges = self
            .resolution_history
            .iter()
            .filter(|r| r.resolution_type == ResolutionType::ChallengeValid)
            .count();
        let total_slashed: u64 = self.resolution_history.iter().map(|r| r.slash_amount).sum();
        let total_rewards: u64 = self
            .resolution_history
            .iter()
            .map(|r| r.reward_amount)
            .sum();
        let fraud_types: HashMap<RollupFraudType, usize> = self
            .active_challenges
            .values()
            .chain(self.resolution_history.iter().filter_map(|r| {
                self.active_challenges
                    .values()
                    .find(|c| c.challenge_id == r.challenge_id)
            }))
            .fold(HashMap::new(), |mut acc, challenge| {
                *acc.entry(challenge.fraud_type.clone()).or_insert(0) += 1;
                acc
            });
        FraudStatistics {
            total_challenges,
            resolved_challenges,
            pending_challenges,
            successful_challenges,
            total_slashed,
            total_rewards,
            fraud_types,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudProofResult {
    pub success: bool,
    pub slash_amount: u64,
    pub challenger_reward: u64,
    pub reason: String,
    pub slashed_party: Option<Address>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudStatistics {
    pub total_challenges: usize,
    pub resolved_challenges: usize,
    pub pending_challenges: usize,
    pub successful_challenges: usize,
    pub total_slashed: u64,
    pub total_rewards: u64,
    pub fraud_types: HashMap<RollupFraudType, usize>,
}

impl Default for FraudProofVerifier {
    fn default() -> Self {
        Self::new(0.8, 24)
    }
}

impl ChallengeResponse {
    pub fn new(
        responder: Address,
        counter_evidence: Vec<u8>,
        proof_correctness: Vec<Hash>,
    ) -> Self {
        let response_id = ego_core::crypto::hash_multiple(&[
            b"ego/fraud/response/v1",
            responder.as_bytes(),
            &Timestamp::now().as_millis().to_le_bytes(),
        ]);
        Self {
            response_id,
            responder,
            counter_evidence,
            proof_correctness,
            timestamp: Timestamp::now(),
            signature: Vec::new(),
        }
    }

    pub fn sign(&mut self, keypair: &ego_core::crypto::KeyPair) -> RollupResult<()> {
        let signing_data = self.create_signing_data()?;
        let sig = keypair.sign_dilithium(&signing_data);
        self.signature = sig.signature_data;
        Ok(())
    }

    fn create_signing_data(&self) -> RollupResult<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(b"ego/fraud/response/v1");
        data.extend_from_slice(self.response_id.as_bytes());
        data.extend_from_slice(self.responder.as_bytes());
        data.extend_from_slice(&ego_core::crypto::hash_data(&self.counter_evidence).to_vec());
        data.extend_from_slice(&self.timestamp.as_millis().to_le_bytes());
        Ok(ego_core::crypto::blake2s_hash(&data))
    }
}

pub struct FraudProofBuilder {
    challenger: Address,
    commitment: RollupCommitment,
    fraud_type: RollupFraudType,
    confidence: f64,
    challenge_bond: u64,
    deadline_epoch: u64,
    evidence_type: Option<FraudEvidenceType>,
    proof_data: Vec<u8>,
    witness_data: Option<Vec<u8>>,
    auxiliary_data: HashMap<String, Vec<u8>>,
}

impl FraudProofBuilder {
    pub fn new(
        challenger: Address,
        commitment: RollupCommitment,
        fraud_type: RollupFraudType,
    ) -> Self {
        Self {
            challenger,
            commitment,
            fraud_type,
            confidence: 0.9,
            challenge_bond: 100_000,
            deadline_epoch: 0,
            evidence_type: None,
            proof_data: Vec::new(),
            witness_data: None,
            auxiliary_data: HashMap::new(),
        }
    }

    pub fn confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn challenge_bond(mut self, bond: u64) -> Self {
        self.challenge_bond = bond;
        self
    }

    pub fn deadline_epoch(mut self, epoch: u64) -> Self {
        self.deadline_epoch = epoch;
        self
    }

    pub fn evidence_type(mut self, evidence_type: FraudEvidenceType) -> Self {
        self.evidence_type = Some(evidence_type);
        self
    }

    pub fn proof_data(mut self, data: Vec<u8>) -> Self {
        self.proof_data = data;
        self
    }

    pub fn witness_data(mut self, data: Vec<u8>) -> Self {
        self.witness_data = Some(data);
        self
    }

    pub fn auxiliary_data(mut self, key: String, value: Vec<u8>) -> Self {
        self.auxiliary_data.insert(key, value);
        self
    }

    pub fn build(self) -> RollupResult<FraudProof> {
        let evidence_type = self
            .evidence_type
            .ok_or_else(|| RollupError::FraudProof("Evidence type is required".to_string()))?;
        let evidence = FraudEvidence {
            commitment: self.commitment.clone(),
            evidence_type,
            proof_data: self.proof_data,
            witness_data: self.witness_data,
            reference_commitments: Vec::new(),
            auxiliary_data: self.auxiliary_data,
        };
        let commitment_hash = self.commitment.compute_hash();
        Ok(FraudProof::new(
            self.challenger,
            commitment_hash,
            self.fraud_type,
            evidence,
            self.confidence,
            self.challenge_bond,
            self.deadline_epoch,
        ))
    }

    pub fn build_and_sign(self, keypair: &ego_core::crypto::KeyPair) -> RollupResult<FraudProof> {
        let mut proof = self.build()?;
        proof.sign(keypair)?;
        Ok(proof)
    }
}

impl InvalidInclusionProof {
    pub fn new(
        challenger: Address,
        commitment_hash: Hash,
        invalid_transaction: RollupTransaction,
        inclusion_proof: Vec<Hash>,
        fraud_reason: InclusionFraudReason,
        expected_merkle_root: Hash,
        actual_merkle_root: Hash,
    ) -> Self {
        let timestamp = Timestamp::now();
        let proof_id = ego_core::crypto::hash_multiple(&[
            b"ego/fraud/inclusion/v1",
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
            signature: Vec::new(),
            expected_merkle_root,
            actual_merkle_root,
        }
    }

    pub fn sign(&mut self, keypair: &ego_core::crypto::KeyPair) -> RollupResult<()> {
        let signing_data = self.create_signing_data()?;
        let sig = keypair.sign_dilithium(&signing_data);
        self.signature = sig.signature_data;
        Ok(())
    }

    pub fn verify_signature(&self, dilithium_pk: &[u8]) -> RollupResult<bool> {
        let pubkey = PublicKey::dilithium2(dilithium_pk.to_vec());
        let expected_challenger = Address::from_public_key(&pubkey);
        if expected_challenger != self.challenger {
            return Ok(false);
        }
        let signing_data = self.create_signing_data()?;
        ego_core::crypto::verify_dilithium_signature(dilithium_pk, &signing_data, &self.signature)
            .map_err(|e| RollupError::FraudProof(format!("Signature verification failed: {:?}", e)))
    }

    pub fn validate(&self) -> RollupResult<()> {
        if self.expected_merkle_root == self.actual_merkle_root {
            return Err(RollupError::FraudProof(
                "Expected and actual merkle roots are the same".to_string(),
            ));
        }
        if self.inclusion_proof.is_empty() {
            return Err(RollupError::FraudProof(
                "Inclusion proof cannot be empty".to_string(),
            ));
        }
        match self.fraud_reason {
            InclusionFraudReason::InvalidSignature => {
                if self.invalid_transaction.verify_signature()? {
                    return Err(RollupError::FraudProof(
                        "Transaction signature is actually valid".to_string(),
                    ));
                }
            }
            InclusionFraudReason::MalformedTransaction => {
                if self.invalid_transaction.inner.size() == 0 {
                    return Err(RollupError::FraudProof(
                        "Transaction appears to be properly formed".to_string(),
                    ));
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn create_signing_data(&self) -> RollupResult<Vec<u8>> {
        let config = bincode::config::standard();
        let mut data = Vec::new();
        data.extend_from_slice(b"ego/fraud/inclusion/v1");
        data.extend_from_slice(self.proof_id.as_bytes());
        data.extend_from_slice(self.challenger.as_bytes());
        data.extend_from_slice(self.commitment_hash.as_bytes());
        data.extend_from_slice(self.invalid_transaction.hash().as_bytes());
        data.extend_from_slice(&self.timestamp.as_millis().to_le_bytes());
        data.extend_from_slice(self.expected_merkle_root.as_bytes());
        data.extend_from_slice(self.actual_merkle_root.as_bytes());
        let fraud_reason_bytes = bincode::encode_to_vec(&self.fraud_reason, config)
            .map_err(|e| RollupError::SerializationError(e.to_string()))?;
        data.extend_from_slice(&fraud_reason_bytes);
        Ok(ego_core::crypto::blake2s_hash(&data))
    }
}

pub fn create_state_transition_fraud(
    challenger: Address,
    commitment: RollupCommitment,
    pre_state: Hash,
    post_state: Hash,
    expected_post_state: Hash,
    execution_trace: Vec<u8>,
    transaction_batch: Vec<RollupTransaction>,
    intermediate_states: Vec<Hash>,
) -> FraudProof {
    let evidence_type = FraudEvidenceType::StateTransition {
        pre_state,
        post_state,
        expected_post_state,
        execution_trace,
        transaction_batch,
        intermediate_states,
    };
    let evidence = FraudEvidence {
        commitment: commitment.clone(),
        evidence_type,
        proof_data: Vec::new(),
        witness_data: None,
        reference_commitments: Vec::new(),
        auxiliary_data: HashMap::new(),
    };
    let commitment_hash = commitment.compute_hash();
    FraudProof::new(
        challenger,
        commitment_hash,
        RollupFraudType::InvalidStateTransition,
        evidence,
        0.95,
        200_000,
        0,
    )
}

pub fn create_data_unavailability_fraud(
    challenger: Address,
    commitment: RollupCommitment,
    missing_chunks: Vec<u32>,
    total_chunks: u32,
    timeout_evidence: Vec<TimeoutEvidence>,
    sampling_requests: Vec<SamplingRequest>,
) -> FraudProof {
    let evidence_type = FraudEvidenceType::DataUnavailability {
        missing_chunks,
        sample_proofs: Vec::new(),
        timeout_evidence,
        sampling_requests,
        total_chunks,
    };
    let evidence = FraudEvidence {
        commitment: commitment.clone(),
        evidence_type,
        proof_data: Vec::new(),
        witness_data: None,
        reference_commitments: Vec::new(),
        auxiliary_data: HashMap::new(),
    };
    let commitment_hash = commitment.compute_hash();
    FraudProof::new(
        challenger,
        commitment_hash,
        RollupFraudType::DataUnavailable,
        evidence,
        0.9,
        150_000,
        0,
    )
}

pub fn create_invalid_inclusion_fraud(
    challenger: Address,
    commitment: RollupCommitment,
    claimed_transaction: RollupTransaction,
    inclusion_proof: Vec<Hash>,
    merkle_root: Hash,
    invalid_reason: String,
    transaction_index: u32,
) -> FraudProof {
    let evidence_type = FraudEvidenceType::InvalidInclusion {
        inclusion_proof,
        merkle_root,
        invalid_reason,
        transaction_index,
        claimed_transaction,
    };
    let evidence = FraudEvidence {
        commitment: commitment.clone(),
        evidence_type,
        proof_data: Vec::new(),
        witness_data: None,
        reference_commitments: Vec::new(),
        auxiliary_data: HashMap::new(),
    };
    let commitment_hash = commitment.compute_hash();
    FraudProof::new(
        challenger,
        commitment_hash,
        RollupFraudType::InvalidInclusion,
        evidence,
        0.92,
        180_000,
        0,
    )
}
