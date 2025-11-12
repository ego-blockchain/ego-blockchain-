use dashmap::DashMap;
use ego_core::{
    Account, Address, AlgorithmId, Balance, BlockHeight, EgoError, EgoResult, Hash, PublicKey,
    ShardId, Timestamp, Transaction, TransactionPayload,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
pub type InvalidInclusionProof = FraudEvidenceType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollupError {
    FraudProof(String),
    SerializationError(String),
    InvalidCommitment(String),
    ValidationError(String),
    InsufficientBond(String),
    ChallengeExpired(String),
    UnauthorizedChallenger(String),
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
    pub shard_id: ShardId,
    pub operator_signature: Vec<u8>,
    pub operator_dilithium_pk: Vec<u8>,
}

impl RollupCommitment {
    pub fn compute_hash(&self) -> Hash {
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
        data.extend_from_slice(&self.shard_id.as_u32().to_le_bytes());
        ego_core::crypto::hash_data(&data)
    }

    pub fn verify_operator_signature(&self) -> RollupResult<bool> {
        if self.operator_dilithium_pk.is_empty() || self.operator_signature.is_empty() {
            return Ok(false);
        }
        let pubkey = PublicKey::dilithium2(self.operator_dilithium_pk.clone());
        let expected_operator = Address::from_public_key(&pubkey);
        if expected_operator != self.operator {
            return Ok(false);
        }
        let signing_data = self.compute_hash();
        ego_core::crypto::verify_dilithium_signature(
            &self.operator_dilithium_pk,
            signing_data.as_bytes(),
            &self.operator_signature,
        )
        .map_err(|e| {
            RollupError::ValidationError(format!("Signature verification failed: {:?}", e))
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct RollupTransaction {
    pub inner: Transaction,
    pub rollup_id: String,
    pub batch_index: u32,
    pub inclusion_proof: Vec<Hash>,
}

impl RollupTransaction {
    pub fn hash(&self) -> Hash {
        self.inner.hash
    }

    pub fn verify_signature(&self) -> RollupResult<bool> {
        self.inner.verify_signature().map_err(|e| e.into())
    }

    pub fn verify_inclusion(&self, merkle_root: &Hash) -> RollupResult<bool> {
        if self.inclusion_proof.is_empty() {
            return Ok(false);
        }
        let mut current_hash = self.hash();
        for proof_element in &self.inclusion_proof {
            current_hash = ego_core::crypto::hash_multiple(&[
                current_hash.as_bytes(),
                proof_element.as_bytes(),
            ]);
        }
        Ok(current_hash == *merkle_root)
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
    pub shard_id: ShardId,
    pub priority: u8,
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
    InsufficientCollateral,
    UnauthorizedOperator,
    InvalidDRSScore,
    DeployPolicyViolation,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct FraudEvidence {
    pub commitment: RollupCommitment,
    pub evidence_type: FraudEvidenceType,
    pub proof_data: Vec<u8>,
    pub witness_data: Option<Vec<u8>>,
    pub reference_commitments: Vec<Hash>,
    pub auxiliary_data: HashMap<String, Vec<u8>>,
    pub state_proof: Option<StateProof>,
    pub drs_evidence: Option<DRSEvidence>,
    pub deploy_evidence: Option<DeployEvidence>,
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
        account_proofs: Vec<AccountStateProof>,
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
        da_commitment: Hash,
    },
    ExecutionError {
        expected_result: Vec<u8>,
        actual_result: Vec<u8>,
        error_trace: String,
        transaction: RollupTransaction,
        pre_state_proof: Vec<Hash>,
        ru_consumed: u64,
        ru_limit: u64,
    },
    ProofAggregation {
        claimed_proof_root: Hash,
        actual_proofs: Vec<Vec<u8>>,
        recomputed_root: Hash,
        invalid_indices: Vec<u32>,
        proof_type: ProofAggregationType,
    },
    CrossShardInvalid {
        receipt_hash: Hash,
        source_shard: u32,
        target_shard: u32,
        merkle_proof: Vec<Hash>,
        invalid_reason: String,
        receipt_nonce: u64,
    },
    DRSManipulation {
        node_id: Address,
        claimed_score: f64,
        actual_score: f64,
        evidence_bundle_hash: Hash,
        manipulation_type: DRSManipulationType,
    },
    DeployViolation {
        deployer: Address,
        deploy_id: Hash,
        violation_type: DeployViolationType,
        policy_snapshot: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct StateProof {
    pub state_root: Hash,
    pub account_proofs: Vec<AccountStateProof>,
    pub storage_proofs: Vec<StorageProof>,
    pub validator_set_proof: Vec<Hash>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct AccountStateProof {
    pub address: Address,
    pub balance: Balance,
    pub nonce: u64,
    pub storage_quota: u64,
    pub merkle_proof: Vec<Hash>,
    pub account_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct StorageProof {
    pub chunk_id: Hash,
    pub data_hash: Hash,
    pub size: u64,
    pub triad_info: TriadProof,
    pub merkle_proof: Vec<Hash>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct TriadProof {
    pub primary: Address,
    pub replica_a: Address,
    pub replica_b: Address,
    pub diversity_score: f64,
    pub health_scores: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DRSEvidence {
    pub node_id: Address,
    pub epoch: u64,
    pub components: DRSComponentsEvidence,
    pub penalties: DRSPenaltiesEvidence,
    pub claimed_multiplier: f64,
    pub actual_multiplier: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DRSComponentsEvidence {
    pub uptime: f64,
    pub post_pass: f64,
    pub inv_latency: f64,
    pub poc_quality: f64,
    pub serve_ratio: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DRSPenaltiesEvidence {
    pub failed_post: u32,
    pub replay_or_incoherence: u32,
    pub equivocation: u32,
    pub total_penalty: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub enum DRSManipulationType {
    FakeUptime,
    FalsifiedPoStResults,
    FalsifiedPoCResults,
    IncorrectPenaltyCalculation,
    ComponentWeightManipulation,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DeployEvidence {
    pub deployer: Address,
    pub deploy_id: Hash,
    pub deploy_record: Vec<u8>,
    pub quota_snapshot: Vec<u8>,
    pub credits_snapshot: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub enum DeployViolationType {
    QuotaExceeded,
    InsufficientCredits,
    BondNotPaid,
    HumanVerificationMissing,
    AIPatternDetected,
    BlacklistedCode,
    DuplicateContract,
    SizeExceeded,
    RateLimitExceeded,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub enum ProofAggregationType {
    PoSt,
    PoRep,
    PoC,
    Mixed,
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
    pub response_time_ms: Option<u64>,
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
    pub shard_id: ShardId,
    pub priority: u8,
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
    pub dilithium_pk: Vec<u8>,
    pub state_recomputation: Option<StateRecomputationProof>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct StateRecomputationProof {
    pub initial_state: Hash,
    pub final_state: Hash,
    pub transaction_hashes: Vec<Hash>,
    pub intermediate_roots: Vec<Hash>,
    pub execution_logs: Vec<ExecutionLog>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ExecutionLog {
    pub tx_hash: Hash,
    pub ru_consumed: u64,
    pub state_changes: Vec<StateChange>,
    pub events: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct StateChange {
    pub account: Address,
    pub field: String,
    pub old_value: Vec<u8>,
    pub new_value: Vec<u8>,
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
    pub drs_impact: Option<DRSImpact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum ResolutionType {
    ChallengeValid,
    ChallengeInvalid,
    BothSlashed,
    Inconclusive,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DRSImpact {
    pub affected_node: Address,
    pub score_penalty: f64,
    pub multiplier_adjustment: f64,
    pub epochs_affected: u64,
}

#[derive(Debug, Clone)]
pub struct FraudProofVerifier {
    min_confidence: f64,
    max_age_hours: u64,
    verified_proofs: Arc<DashMap<Hash, FraudProof>>,
    active_challenges: Arc<DashMap<Hash, FraudChallenge>>,
    resolution_history: Arc<Mutex<VecDeque<ChallengeResolution>>>,
    slashing_params: Arc<Mutex<SlashingParams>>,
    fraud_statistics: Arc<Mutex<FraudStatistics>>,
    drs_integration: bool,
    deploy_policy_integration: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingParams {
    pub base_slash_amounts: HashMap<RollupFraudType, u64>,
    pub confidence_multiplier_enabled: bool,
    pub max_slash_amount: u64,
    pub min_slash_amount: u64,
    pub challenger_reward_percentage: u64,
    pub false_challenge_penalty: u64,
    pub drs_penalty_enabled: bool,
    pub drs_penalty_duration_epochs: u64,
    pub min_challenge_bond: u64,
    pub operator_collateral_requirement: u64,
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
        base_slash_amounts.insert(RollupFraudType::InsufficientCollateral, 400_000);
        base_slash_amounts.insert(RollupFraudType::UnauthorizedOperator, 700_000);
        base_slash_amounts.insert(RollupFraudType::InvalidDRSScore, 500_000);
        base_slash_amounts.insert(RollupFraudType::DeployPolicyViolation, 300_000);
        Self {
            base_slash_amounts,
            confidence_multiplier_enabled: true,
            max_slash_amount: 1_000_000,
            min_slash_amount: 50_000,
            challenger_reward_percentage: 50,
            false_challenge_penalty: 100_000,
            drs_penalty_enabled: true,
            drs_penalty_duration_epochs: 10,
            min_challenge_bond: 10_000,
            operator_collateral_requirement: 1_000_000,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FraudStatistics {
    pub total_challenges: u64,
    pub resolved_challenges: u64,
    pub pending_challenges: u64,
    pub successful_challenges: u64,
    pub total_slashed: u64,
    pub total_rewards: u64,
    pub fraud_types: HashMap<RollupFraudType, u64>,
    pub avg_confidence: f64,
    pub avg_resolution_time_hours: f64,
    pub slashed_operators: HashSet<Address>,
    pub top_challengers: Vec<(Address, u64)>,
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
        shard_id: ShardId,
    ) -> Self {
        let timestamp = Timestamp::now();
        let proof_id = Self::compute_proof_id(challenger, commitment_hash, &fraud_type, timestamp);
        let priority = Self::compute_priority(&fraud_type, confidence);
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
            shard_id,
            priority,
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
            return Err(RollupError::InsufficientBond(
                "Challenge bond must be greater than zero".to_string(),
            ));
        }
        if !self.evidence.commitment.verify_operator_signature()? {
            return Err(RollupError::ValidationError(
                "Commitment operator signature is invalid".to_string(),
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
                account_proofs,
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
                if account_proofs.is_empty() {
                    return Err(RollupError::FraudProof(
                        "Account state proofs required for state transition".to_string(),
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
                da_commitment,
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
                if *da_commitment == Hash::ZERO {
                    return Err(RollupError::FraudProof(
                        "DA commitment hash required".to_string(),
                    ));
                }
            }
            FraudEvidenceType::ExecutionError {
                expected_result,
                actual_result,
                pre_state_proof,
                ru_consumed,
                ru_limit,
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
                if ru_consumed > ru_limit {
                    return Err(RollupError::FraudProof(
                        "RU consumed exceeds limit".to_string(),
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
                receipt_nonce,
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
                if *receipt_nonce == 0 {
                    return Err(RollupError::FraudProof(
                        "Valid receipt nonce required".to_string(),
                    ));
                }
            }
            FraudEvidenceType::DRSManipulation {
                claimed_score,
                actual_score,
                evidence_bundle_hash,
                ..
            } => {
                if claimed_score == actual_score {
                    return Err(RollupError::FraudProof(
                        "Claimed and actual DRS scores are the same".to_string(),
                    ));
                }
                if *evidence_bundle_hash == Hash::ZERO {
                    return Err(RollupError::FraudProof(
                        "Evidence bundle hash required for DRS fraud".to_string(),
                    ));
                }
                if *claimed_score < 0.0
                    || *claimed_score > 1.0
                    || *actual_score < 0.0
                    || *actual_score > 1.0
                {
                    return Err(RollupError::FraudProof(
                        "DRS scores must be between 0.0 and 1.0".to_string(),
                    ));
                }
            }
            FraudEvidenceType::DeployViolation {
                deployer,
                deploy_id,
                policy_snapshot,
                ..
            } => {
                if *deploy_id == Hash::ZERO {
                    return Err(RollupError::FraudProof(
                        "Valid deploy ID required".to_string(),
                    ));
                }
                if policy_snapshot.is_empty() {
                    return Err(RollupError::FraudProof(
                        "Policy snapshot required for deploy violation".to_string(),
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
        data.extend_from_slice(&self.shard_id.as_u32().to_le_bytes());
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

    fn compute_priority(fraud_type: &RollupFraudType, confidence: f64) -> u8 {
        let base_priority: u8 = match fraud_type {
            RollupFraudType::InvalidEpochAnchor => 255,
            RollupFraudType::UnauthorizedOperator => 250,
            RollupFraudType::IncorrectStateRoot => 240,
            RollupFraudType::InvalidStateTransition => 230,
            RollupFraudType::InvalidProofAggregation => 220,
            RollupFraudType::InvalidExecution => 210,
            RollupFraudType::InvalidDRSScore => 200,
            RollupFraudType::InvalidCrossShardReceipt => 190,
            RollupFraudType::InsufficientCollateral => 180,
            RollupFraudType::DeployPolicyViolation => 170,
            RollupFraudType::InvalidInclusion => 160,
            RollupFraudType::MerkleRootMismatch => 150,
            RollupFraudType::DataUnavailable => 140,
            RollupFraudType::DuplicateTransaction => 130,
            RollupFraudType::InvalidSignature => 120,
        };
        let confidence_bonus = (confidence * 10.0) as u8;
        base_priority.saturating_add(confidence_bonus).min(255)
    }

    pub fn severity_score(&self) -> u32 {
        let base_severity = match self.fraud_type {
            RollupFraudType::InvalidEpochAnchor => 10,
            RollupFraudType::UnauthorizedOperator => 9,
            RollupFraudType::IncorrectStateRoot => 9,
            RollupFraudType::InvalidStateTransition => 8,
            RollupFraudType::InvalidProofAggregation => 7,
            RollupFraudType::InvalidExecution => 6,
            RollupFraudType::InvalidDRSScore => 6,
            RollupFraudType::InvalidCrossShardReceipt => 5,
            RollupFraudType::InsufficientCollateral => 5,
            RollupFraudType::DeployPolicyViolation => 4,
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
            verified_proofs: Arc::new(DashMap::new()),
            active_challenges: Arc::new(DashMap::new()),
            resolution_history: Arc::new(Mutex::new(VecDeque::new())),
            slashing_params: Arc::new(Mutex::new(SlashingParams::default())),
            fraud_statistics: Arc::new(Mutex::new(FraudStatistics::default())),
            drs_integration: true,
            deploy_policy_integration: true,
        }
    }

    pub fn with_slashing_params(mut self, params: SlashingParams) -> Self {
        *self.slashing_params.lock().unwrap() = params;
        self
    }

    pub fn with_integrations(mut self, drs: bool, deploy_policy: bool) -> Self {
        self.drs_integration = drs;
        self.deploy_policy_integration = deploy_policy;
        self
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
        if self.verified_proofs.contains_key(&proof.proof_id) {
            return Ok(true);
        }
        let slashing_params = self.slashing_params.lock().unwrap();
        if proof.challenge_bond < slashing_params.min_challenge_bond {
            return Err(RollupError::InsufficientBond(format!(
                "Challenge bond {} is below minimum {}",
                proof.challenge_bond, slashing_params.min_challenge_bond
            )));
        }
        drop(slashing_params);
        let evidence_valid = self.verify_evidence(proof)?;
        if evidence_valid {
            self.verified_proofs.insert(proof.proof_id, proof.clone());
            let mut stats = self.fraud_statistics.lock().unwrap();
            *stats
                .fraud_types
                .entry(proof.fraud_type.clone())
                .or_insert(0) += 1;
            stats.avg_confidence = (stats.avg_confidence * stats.total_challenges as f64
                + proof.confidence)
                / (stats.total_challenges + 1) as f64;
            stats.total_challenges += 1;
        }
        Ok(evidence_valid)
    }

    fn verify_evidence(&self, proof: &FraudProof) -> RollupResult<bool> {
        match &proof.evidence.evidence_type {
            FraudEvidenceType::StateTransition {
                pre_state,
                post_state,
                expected_post_state,
                execution_trace: _, // Add this line
                transaction_batch,
                intermediate_states,
                account_proofs,
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
                for tx in transaction_batch {
                    if !tx.verify_signature()? {
                        return Ok(true);
                    }
                }
                if !intermediate_states.is_empty() {
                    if intermediate_states[0] != *pre_state {
                        return Ok(false);
                    }
                    if intermediate_states[intermediate_states.len() - 1] != *post_state {
                        return Ok(false);
                    }
                }
                if account_proofs.is_empty() {
                    return Ok(false);
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
                let inclusion_valid =
                    self.verify_merkle_inclusion(inclusion_proof, merkle_root, &tx_hash)?;
                if !claimed_transaction.verify_signature()? {
                    return Ok(true);
                }
                Ok(!inclusion_valid)
            }
            FraudEvidenceType::DataUnavailability {
                missing_chunks,
                total_chunks,
                timeout_evidence,
                sampling_requests,
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
                let responded_requests = sampling_requests
                    .iter()
                    .filter(|r| r.response_received)
                    .count();
                let response_rate = responded_requests as f64 / sampling_requests.len() as f64;
                if response_rate > 0.9 {
                    return Ok(false);
                }
                Ok(true)
            }
            FraudEvidenceType::ExecutionError {
                expected_result,
                actual_result,
                pre_state_proof,
                transaction,
                ru_consumed,
                ru_limit,
                ..
            } => {
                if expected_result == actual_result {
                    return Ok(false);
                }
                if pre_state_proof.is_empty() {
                    return Ok(false);
                }
                if !transaction.verify_signature()? {
                    return Ok(true);
                }
                if ru_consumed > ru_limit {
                    return Ok(true);
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
                Ok(computed_root == *recomputed_root && computed_root != *claimed_proof_root)
            }
            FraudEvidenceType::CrossShardInvalid {
                merkle_proof,
                receipt_hash,
                source_shard,
                target_shard,
                ..
            } => {
                if merkle_proof.is_empty() {
                    return Ok(false);
                }
                if *source_shard == *target_shard {
                    return Ok(true);
                }
                Ok(true)
            }
            FraudEvidenceType::DRSManipulation {
                claimed_score,
                actual_score,
                evidence_bundle_hash,
                ..
            } => {
                if !self.drs_integration {
                    return Ok(false);
                }
                if claimed_score == actual_score {
                    return Ok(false);
                }
                if *evidence_bundle_hash == Hash::ZERO {
                    return Ok(false);
                }
                let score_diff = (claimed_score - actual_score).abs();
                if score_diff < 0.05 {
                    return Ok(false);
                }
                Ok(true)
            }
            FraudEvidenceType::DeployViolation {
                deploy_id,
                policy_snapshot,
                ..
            } => {
                if !self.deploy_policy_integration {
                    return Ok(false);
                }
                if *deploy_id == Hash::ZERO || policy_snapshot.is_empty() {
                    return Ok(false);
                }
                Ok(true)
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
        Ok(current_hash == *root)
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

    pub fn execute_fraud_proof(&self, proof: &FraudProof) -> RollupResult<FraudProofResult> {
        if !self.verify_fraud_proof(proof)? {
            return Ok(FraudProofResult {
                success: false,
                slash_amount: 0,
                challenger_reward: 0,
                reason: "Fraud proof verification failed".to_string(),
                slashed_party: None,
                drs_impact: None,
            });
        }
        let slashing_params = self.slashing_params.lock().unwrap();
        let base_slash = slashing_params
            .base_slash_amounts
            .get(&proof.fraud_type)
            .copied()
            .unwrap_or(100_000);
        let slash_amount = if slashing_params.confidence_multiplier_enabled {
            let multiplied = (base_slash as f64 * proof.confidence) as u64;
            multiplied
                .min(slashing_params.max_slash_amount)
                .max(slashing_params.min_slash_amount)
        } else {
            base_slash
                .min(slashing_params.max_slash_amount)
                .max(slashing_params.min_slash_amount)
        };
        let challenger_reward = (slash_amount * slashing_params.challenger_reward_percentage) / 100;
        let drs_impact = if slashing_params.drs_penalty_enabled && self.drs_integration {
            Some(DRSImpact {
                affected_node: proof.evidence.commitment.operator,
                score_penalty: 0.15,
                multiplier_adjustment: -0.2,
                epochs_affected: slashing_params.drs_penalty_duration_epochs,
            })
        } else {
            None
        };
        let mut stats = self.fraud_statistics.lock().unwrap();
        stats.total_slashed += slash_amount;
        stats.total_rewards += challenger_reward;
        stats
            .slashed_operators
            .insert(proof.evidence.commitment.operator);
        drop(stats);
        Ok(FraudProofResult {
            success: true,
            slash_amount,
            challenger_reward,
            reason: format!("Rollup fraud proven: {:?}", proof.fraud_type),
            slashed_party: Some(proof.evidence.commitment.operator),
            drs_impact,
        })
    }

    pub fn create_challenge(&self, proof: &FraudProof) -> RollupResult<FraudChallenge> {
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
            shard_id: proof.shard_id,
            priority: proof.priority,
        };
        self.active_challenges
            .insert(challenge_id, challenge.clone());
        let mut stats = self.fraud_statistics.lock().unwrap();
        stats.pending_challenges += 1;
        drop(stats);
        Ok(challenge)
    }

    pub fn respond_to_challenge(
        &self,
        challenge_id: Hash,
        response: ChallengeResponse,
    ) -> RollupResult<()> {
        let mut challenge = self
            .active_challenges
            .get_mut(&challenge_id)
            .ok_or_else(|| RollupError::FraudProof("Challenge not found".to_string()))?;
        if challenge.status != ChallengeStatus::Pending {
            return Err(RollupError::FraudProof(
                "Challenge is not in pending state".to_string(),
            ));
        }
        if response.responder != challenge.operator {
            return Err(RollupError::UnauthorizedChallenger(
                "Response must come from challenged operator".to_string(),
            ));
        }
        if !response.verify_signature()? {
            return Err(RollupError::FraudProof(
                "Invalid response signature".to_string(),
            ));
        }
        challenge.response = Some(response);
        challenge.status = ChallengeStatus::Responded;
        Ok(())
    }

    pub fn resolve_challenge(
        &self,
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
        let slashing_params = self.slashing_params.lock().unwrap();
        let resolution_type: ResolutionType;
        let slashed_party: Option<Address>;
        let slash_amount: u64;
        let reward_amount: u64;
        let new_status: ChallengeStatus;
        let drs_impact: Option<DRSImpact>;
        if current_epoch > challenge.deadline_epoch {
            if challenge.response.is_none() {
                resolution_type = ResolutionType::ChallengeValid;
                slashed_party = Some(challenge.operator);
                slash_amount = challenge.response_bond;
                reward_amount = challenge.challenge_bond + (slash_amount / 2);
                new_status = ChallengeStatus::Slashed;
                drs_impact = if slashing_params.drs_penalty_enabled && self.drs_integration {
                    Some(DRSImpact {
                        affected_node: challenge.operator,
                        score_penalty: 0.20,
                        multiplier_adjustment: -0.25,
                        epochs_affected: slashing_params.drs_penalty_duration_epochs,
                    })
                } else {
                    None
                };
            } else {
                resolution_type = ResolutionType::Expired;
                slashed_party = None;
                slash_amount = 0;
                reward_amount = 0;
                new_status = ChallengeStatus::Expired;
                drs_impact = None;
            }
        } else if let Some(ref response) = challenge.response {
            let counter_evidence_valid = self.verify_counter_evidence(&challenge, response)?;
            if counter_evidence_valid {
                resolution_type = ResolutionType::ChallengeInvalid;
                slashed_party = Some(challenge.challenger);
                slash_amount = slashing_params.false_challenge_penalty;
                reward_amount = challenge.response_bond;
                new_status = ChallengeStatus::Rejected;
                drs_impact = if slashing_params.drs_penalty_enabled && self.drs_integration {
                    Some(DRSImpact {
                        affected_node: challenge.challenger,
                        score_penalty: 0.10,
                        multiplier_adjustment: -0.15,
                        epochs_affected: slashing_params.drs_penalty_duration_epochs / 2,
                    })
                } else {
                    None
                };
            } else {
                resolution_type = ResolutionType::ChallengeValid;
                slashed_party = Some(challenge.operator);
                slash_amount = challenge.response_bond;
                reward_amount = challenge.challenge_bond + (slash_amount / 2);
                new_status = ChallengeStatus::Slashed;
                drs_impact = if slashing_params.drs_penalty_enabled && self.drs_integration {
                    Some(DRSImpact {
                        affected_node: challenge.operator,
                        score_penalty: 0.15,
                        multiplier_adjustment: -0.20,
                        epochs_affected: slashing_params.drs_penalty_duration_epochs,
                    })
                } else {
                    None
                };
            }
        } else {
            return Err(RollupError::FraudProof(
                "Challenge not ready for resolution".to_string(),
            ));
        }
        drop(slashing_params);
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
            resolution_type: resolution_type.clone(),
            slashed_party,
            slash_amount,
            reward_amount,
            evidence_hash,
            resolved_at: Timestamp::now(),
            resolver,
            drs_impact: drs_impact.clone(),
        };
        let mut challenge_mut = self
            .active_challenges
            .get_mut(&challenge_id)
            .ok_or_else(|| RollupError::FraudProof("Challenge not found".to_string()))?;
        challenge_mut.status = new_status;
        challenge_mut.resolution = Some(resolution.clone());
        drop(challenge_mut);
        let mut resolution_history = self.resolution_history.lock().unwrap();
        resolution_history.push_back(resolution.clone());
        if resolution_history.len() > 10000 {
            resolution_history.pop_front();
        }
        drop(resolution_history);
        let mut stats = self.fraud_statistics.lock().unwrap();
        stats.resolved_challenges += 1;
        if stats.pending_challenges > 0 {
            stats.pending_challenges -= 1;
        }
        if resolution_type == ResolutionType::ChallengeValid {
            stats.successful_challenges += 1;
        }
        stats.total_slashed += slash_amount;
        stats.total_rewards += reward_amount;
        if let Some(party) = slashed_party {
            stats.slashed_operators.insert(party);
        }
        let entry = stats
            .top_challengers
            .iter_mut()
            .find(|(addr, _)| *addr == challenge.challenger);
        if let Some((_, count)) = entry {
            *count += 1;
        } else {
            stats.top_challengers.push((challenge.challenger, 1));
        }
        stats.top_challengers.sort_by(|a, b| b.1.cmp(&a.1));
        stats.top_challengers.truncate(100);
        drop(stats);
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
        if let Some(ref recomputation) = response.state_recomputation {
            if recomputation.transaction_hashes.is_empty() {
                return Ok(false);
            }
            if recomputation.intermediate_roots.len() != recomputation.transaction_hashes.len() + 1
            {
                return Ok(false);
            }
            if recomputation.initial_state != recomputation.intermediate_roots[0] {
                return Ok(false);
            }
            if recomputation.final_state
                != recomputation.intermediate_roots[recomputation.intermediate_roots.len() - 1]
            {
                return Ok(false);
            }
        }
        Ok(response.counter_evidence.len() >= 100)
    }

    pub fn get_challenge(&self, challenge_id: &Hash) -> Option<FraudChallenge> {
        self.active_challenges.get(challenge_id).map(|c| c.clone())
    }

    pub fn get_active_challenges(&self) -> Vec<FraudChallenge> {
        self.active_challenges
            .iter()
            .filter(|entry| {
                entry.status == ChallengeStatus::Pending
                    || entry.status == ChallengeStatus::Responded
            })
            .map(|entry| entry.clone())
            .collect()
    }

    pub fn get_challenges_by_shard(&self, shard_id: ShardId) -> Vec<FraudChallenge> {
        self.active_challenges
            .iter()
            .filter(|entry| entry.shard_id == shard_id)
            .map(|entry| entry.clone())
            .collect()
    }

    pub fn get_resolution_history(&self) -> Vec<ChallengeResolution> {
        self.resolution_history
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .collect()
    }

    pub fn get_recent_resolutions(&self, limit: usize) -> Vec<ChallengeResolution> {
        let history = self.resolution_history.lock().unwrap();
        history.iter().rev().take(limit).cloned().collect()
    }

    pub fn prune_old_challenges(&self, cutoff_epoch: u64) -> usize {
        let before_count = self.active_challenges.len();
        self.active_challenges.retain(|_, challenge| {
            challenge.deadline_epoch >= cutoff_epoch || challenge.status == ChallengeStatus::Pending
        });
        let pruned = before_count - self.active_challenges.len();

        let mut stats = self.fraud_statistics.lock().unwrap();
        if stats.pending_challenges >= pruned as u64 {
            stats.pending_challenges -= pruned as u64;
        }
        drop(stats);

        pruned
    }

    pub fn get_fraud_statistics(&self) -> FraudStatistics {
        self.fraud_statistics.lock().unwrap().clone()
    }

    pub fn get_operator_fraud_history(&self, operator: &Address) -> OperatorFraudHistory {
        let challenges: Vec<FraudChallenge> = self
            .active_challenges
            .iter()
            .filter(|entry| entry.operator == *operator)
            .map(|entry| entry.clone())
            .collect();

        let resolutions: Vec<ChallengeResolution> = self
            .resolution_history
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.slashed_party == Some(*operator))
            .cloned()
            .collect();

        let total_challenges = challenges.len() + resolutions.len();
        let slashed_count = resolutions.iter().filter(|r| r.slash_amount > 0).count();
        let total_slashed: u64 = resolutions.iter().map(|r| r.slash_amount).sum();

        let fraud_types: HashMap<RollupFraudType, u64> = {
            let mut all_challenges: Vec<FraudChallenge> = challenges.iter().cloned().collect();

            for r in resolutions.iter() {
                if let Some(challenge) = self.active_challenges.get(&r.challenge_id) {
                    all_challenges.push(challenge.clone());
                }
            }

            all_challenges
                .into_iter()
                .fold(HashMap::new(), |mut acc, challenge| {
                    *acc.entry(challenge.fraud_type.clone()).or_insert(0) += 1;
                    acc
                })
        };

        OperatorFraudHistory {
            operator: *operator,
            total_challenges: total_challenges as u64,
            slashed_count: slashed_count as u64,
            total_slashed,
            fraud_types,
            recent_challenges: challenges.into_iter().take(10).collect(),
            recent_resolutions: resolutions.into_iter().take(10).collect(),
        }
    }

    pub fn get_challenger_statistics(&self, challenger: &Address) -> ChallengerStatistics {
        let challenges: Vec<FraudChallenge> = self
            .active_challenges
            .iter()
            .filter(|entry| entry.challenger == *challenger)
            .map(|entry| entry.clone())
            .collect();

        let resolutions: Vec<ChallengeResolution> = self
            .resolution_history
            .lock()
            .unwrap()
            .iter()
            .filter(|r| {
                self.active_challenges
                    .iter()
                    .any(|c| c.challenge_id == r.challenge_id && c.challenger == *challenger)
            })
            .cloned()
            .collect();

        let successful = resolutions
            .iter()
            .filter(|r| r.resolution_type == ResolutionType::ChallengeValid)
            .count();
        let failed = resolutions
            .iter()
            .filter(|r| r.resolution_type == ResolutionType::ChallengeInvalid)
            .count();
        let total_rewards: u64 = resolutions.iter().map(|r| r.reward_amount).sum();
        let total_penalties: u64 = resolutions
            .iter()
            .filter(|r| r.slashed_party == Some(*challenger))
            .map(|r| r.slash_amount)
            .sum();

        let success_rate = if !resolutions.is_empty() {
            (successful as f64 / resolutions.len() as f64) * 100.0
        } else {
            0.0
        };

        ChallengerStatistics {
            challenger: *challenger,
            total_challenges: challenges.len() as u64 + resolutions.len() as u64,
            successful_challenges: successful as u64,
            failed_challenges: failed as u64,
            success_rate,
            total_rewards,
            total_penalties,
            net_gain: total_rewards.saturating_sub(total_penalties),
        }
    }

    pub fn update_statistics(&self) {
        let active_count = self
            .active_challenges
            .iter()
            .filter(|entry| {
                entry.status == ChallengeStatus::Pending
                    || entry.status == ChallengeStatus::Responded
            })
            .count();

        let mut stats = self.fraud_statistics.lock().unwrap();
        stats.pending_challenges = active_count as u64;

        let resolutions = self.resolution_history.lock().unwrap();
        if !resolutions.is_empty() {
            let total_time: u64 = resolutions
                .iter()
                .map(|r| {
                    if let Some(challenge) = self.active_challenges.get(&r.challenge_id) {
                        (r.resolved_at.as_millis() - challenge.created_at.as_millis()) / 3_600_000
                    } else {
                        0
                    }
                })
                .sum();
            stats.avg_resolution_time_hours = total_time as f64 / resolutions.len() as f64;
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
    pub drs_impact: Option<DRSImpact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorFraudHistory {
    pub operator: Address,
    pub total_challenges: u64,
    pub slashed_count: u64,
    pub total_slashed: u64,
    pub fraud_types: HashMap<RollupFraudType, u64>,
    pub recent_challenges: Vec<FraudChallenge>,
    pub recent_resolutions: Vec<ChallengeResolution>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengerStatistics {
    pub challenger: Address,
    pub total_challenges: u64,
    pub successful_challenges: u64,
    pub failed_challenges: u64,
    pub success_rate: f64,
    pub total_rewards: u64,
    pub total_penalties: u64,
    pub net_gain: u64,
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
            dilithium_pk: Vec::new(),
            state_recomputation: None,
        }
    }

    pub fn with_state_recomputation(mut self, recomputation: StateRecomputationProof) -> Self {
        self.state_recomputation = Some(recomputation);
        self
    }

    pub fn sign(&mut self, keypair: &ego_core::crypto::KeyPair) -> RollupResult<()> {
        self.dilithium_pk = keypair.dilithium_public_key().key_data.clone();
        let expected_responder = Address::from_public_key(&keypair.dilithium_public_key());
        if expected_responder != self.responder {
            return Err(RollupError::FraudProof(
                "Responder address does not match signing key".to_string(),
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
        let expected_responder = Address::from_public_key(&pubkey);
        if expected_responder != self.responder {
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

    fn create_signing_data(&self) -> RollupResult<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(b"ego/fraud/response/v1");
        data.extend_from_slice(self.response_id.as_bytes());
        data.extend_from_slice(self.responder.as_bytes());
        data.extend_from_slice(&ego_core::crypto::hash_data(&self.counter_evidence).to_vec());
        data.extend_from_slice(&self.timestamp.as_millis().to_le_bytes());
        if let Some(ref recomputation) = self.state_recomputation {
            let config = bincode::config::standard();
            let recomp_bytes = bincode::encode_to_vec(recomputation, config)
                .map_err(|e| RollupError::SerializationError(e.to_string()))?;
            data.extend_from_slice(&ego_core::crypto::hash_data(&recomp_bytes).to_vec());
        }
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
    shard_id: ShardId,
    evidence_type: Option<FraudEvidenceType>,
    proof_data: Vec<u8>,
    witness_data: Option<Vec<u8>>,
    auxiliary_data: HashMap<String, Vec<u8>>,
    state_proof: Option<StateProof>,
    drs_evidence: Option<DRSEvidence>,
    deploy_evidence: Option<DeployEvidence>,
}

impl FraudProofBuilder {
    pub fn new(
        challenger: Address,
        commitment: RollupCommitment,
        fraud_type: RollupFraudType,
    ) -> Self {
        Self {
            challenger,
            shard_id: commitment.shard_id,
            commitment,
            fraud_type,
            confidence: 0.9,
            challenge_bond: 100_000,
            deadline_epoch: 0,
            evidence_type: None,
            proof_data: Vec::new(),
            witness_data: None,
            auxiliary_data: HashMap::new(),
            state_proof: None,
            drs_evidence: None,
            deploy_evidence: None,
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

    pub fn shard_id(mut self, shard_id: ShardId) -> Self {
        self.shard_id = shard_id;
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

    pub fn state_proof(mut self, proof: StateProof) -> Self {
        self.state_proof = Some(proof);
        self
    }

    pub fn drs_evidence(mut self, evidence: DRSEvidence) -> Self {
        self.drs_evidence = Some(evidence);
        self
    }

    pub fn deploy_evidence(mut self, evidence: DeployEvidence) -> Self {
        self.deploy_evidence = Some(evidence);
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
            state_proof: self.state_proof,
            drs_evidence: self.drs_evidence,
            deploy_evidence: self.deploy_evidence,
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
            self.shard_id,
        ))
    }

    pub fn build_and_sign(self, keypair: &ego_core::crypto::KeyPair) -> RollupResult<FraudProof> {
        let mut proof = self.build()?;
        proof.sign(keypair)?;
        Ok(proof)
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
    account_proofs: Vec<AccountStateProof>,
) -> FraudProof {
    let evidence_type = FraudEvidenceType::StateTransition {
        pre_state,
        post_state,
        expected_post_state,
        execution_trace,
        transaction_batch,
        intermediate_states,
        account_proofs,
    };
    let evidence = FraudEvidence {
        commitment: commitment.clone(),
        evidence_type,
        proof_data: Vec::new(),
        witness_data: None,
        reference_commitments: Vec::new(),
        auxiliary_data: HashMap::new(),
        state_proof: None,
        drs_evidence: None,
        deploy_evidence: None,
    };
    let commitment_hash = commitment.compute_hash();
    let shard_id = commitment.shard_id;
    FraudProof::new(
        challenger,
        commitment_hash,
        RollupFraudType::InvalidStateTransition,
        evidence,
        0.95,
        200_000,
        0,
        shard_id,
    )
}

pub fn create_data_unavailability_fraud(
    challenger: Address,
    commitment: RollupCommitment,
    missing_chunks: Vec<u32>,
    total_chunks: u32,
    timeout_evidence: Vec<TimeoutEvidence>,
    sampling_requests: Vec<SamplingRequest>,
    da_commitment: Hash,
) -> FraudProof {
    let evidence_type = FraudEvidenceType::DataUnavailability {
        missing_chunks,
        sample_proofs: Vec::new(),
        timeout_evidence,
        sampling_requests,
        total_chunks,
        da_commitment,
    };
    let evidence = FraudEvidence {
        commitment: commitment.clone(),
        evidence_type,
        proof_data: Vec::new(),
        witness_data: None,
        reference_commitments: Vec::new(),
        auxiliary_data: HashMap::new(),
        state_proof: None,
        drs_evidence: None,
        deploy_evidence: None,
    };
    let commitment_hash = commitment.compute_hash();
    let shard_id = commitment.shard_id;
    FraudProof::new(
        challenger,
        commitment_hash,
        RollupFraudType::DataUnavailable,
        evidence,
        0.9,
        150_000,
        0,
        shard_id,
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
        state_proof: None,
        drs_evidence: None,
        deploy_evidence: None,
    };
    let commitment_hash = commitment.compute_hash();
    let shard_id = commitment.shard_id;
    FraudProof::new(
        challenger,
        commitment_hash,
        RollupFraudType::InvalidInclusion,
        evidence,
        0.92,
        180_000,
        0,
        shard_id,
    )
}

pub fn create_drs_manipulation_fraud(
    challenger: Address,
    commitment: RollupCommitment,
    node_id: Address,
    claimed_score: f64,
    actual_score: f64,
    evidence_bundle_hash: Hash,
    manipulation_type: DRSManipulationType,
    drs_evidence: DRSEvidence,
) -> FraudProof {
    let evidence_type = FraudEvidenceType::DRSManipulation {
        node_id,
        claimed_score,
        actual_score,
        evidence_bundle_hash,
        manipulation_type,
    };
    let evidence = FraudEvidence {
        commitment: commitment.clone(),
        evidence_type,
        proof_data: Vec::new(),
        witness_data: None,
        reference_commitments: Vec::new(),
        auxiliary_data: HashMap::new(),
        state_proof: None,
        drs_evidence: Some(drs_evidence),
        deploy_evidence: None,
    };
    let commitment_hash = commitment.compute_hash();
    let shard_id = commitment.shard_id;
    FraudProof::new(
        challenger,
        commitment_hash,
        RollupFraudType::InvalidDRSScore,
        evidence,
        0.88,
        160_000,
        0,
        shard_id,
    )
}

pub fn create_deploy_violation_fraud(
    challenger: Address,
    commitment: RollupCommitment,
    deployer: Address,
    deploy_id: Hash,
    violation_type: DeployViolationType,
    policy_snapshot: Vec<u8>,
    deploy_evidence: DeployEvidence,
) -> FraudProof {
    let evidence_type = FraudEvidenceType::DeployViolation {
        deployer,
        deploy_id,
        violation_type,
        policy_snapshot,
    };
    let evidence = FraudEvidence {
        commitment: commitment.clone(),
        evidence_type,
        proof_data: Vec::new(),
        witness_data: None,
        reference_commitments: Vec::new(),
        auxiliary_data: HashMap::new(),
        state_proof: None,
        drs_evidence: None,
        deploy_evidence: Some(deploy_evidence),
    };
    let commitment_hash = commitment.compute_hash();
    let shard_id = commitment.shard_id;
    FraudProof::new(
        challenger,
        commitment_hash,
        RollupFraudType::DeployPolicyViolation,
        evidence,
        0.85,
        140_000,
        0,
        shard_id,
    )
}

pub fn create_cross_shard_invalid_fraud(
    challenger: Address,
    commitment: RollupCommitment,
    receipt_hash: Hash,
    source_shard: u32,
    target_shard: u32,
    merkle_proof: Vec<Hash>,
    invalid_reason: String,
    receipt_nonce: u64,
) -> FraudProof {
    let evidence_type = FraudEvidenceType::CrossShardInvalid {
        receipt_hash,
        source_shard,
        target_shard,
        merkle_proof,
        invalid_reason,
        receipt_nonce,
    };
    let evidence = FraudEvidence {
        commitment: commitment.clone(),
        evidence_type,
        proof_data: Vec::new(),
        witness_data: None,
        reference_commitments: Vec::new(),
        auxiliary_data: HashMap::new(),
        state_proof: None,
        drs_evidence: None,
        deploy_evidence: None,
    };
    let commitment_hash = commitment.compute_hash();
    let shard_id = commitment.shard_id;
    FraudProof::new(
        challenger,
        commitment_hash,
        RollupFraudType::InvalidCrossShardReceipt,
        evidence,
        0.87,
        170_000,
        0,
        shard_id,
    )
}

pub fn verify_fraud_proof_batch(
    verifier: &FraudProofVerifier,
    proofs: &[FraudProof],
) -> RollupResult<Vec<bool>> {
    let mut results = Vec::with_capacity(proofs.len());
    for proof in proofs {
        match verifier.verify_fraud_proof(proof) {
            Ok(valid) => results.push(valid),
            Err(_) => results.push(false),
        }
    }
    Ok(results)
}

pub fn execute_fraud_proof_batch(
    verifier: &FraudProofVerifier,
    proofs: &[FraudProof],
) -> Vec<RollupResult<FraudProofResult>> {
    proofs
        .iter()
        .map(|proof| verifier.execute_fraud_proof(proof))
        .collect()
}
