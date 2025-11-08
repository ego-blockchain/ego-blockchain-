use crate::da::{DAChunk, DataAvailability};
use crate::error::{RollupError, RollupResult};
use crate::operator::RollupBatch;
use crate::types::{ChallengeStatus, CommitmentStatus};
use ego_core::{
    Address, Balance, BlockHeight, DualSignature, EpochNumber, Hash, PROTOCOL_VERSION, PublicKey,
    ShardId, Timestamp,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::Mutex;

const DOMAIN_TAG_COMMITMENT: &[u8] = b"ego/rollup/commitment/v1";
const DOMAIN_TAG_CHALLENGE: &[u8] = b"ego/rollup/challenge/v1";
const MAX_COMMITMENTS_IN_MEMORY: usize = 10000;
const MAX_CHALLENGE_EVIDENCE_SIZE: usize = 1024 * 1024;
const DEFAULT_CHALLENGE_BOND: u128 = 10_000_000_000;
const MIN_DA_SAMPLE_SIZE: usize = 3;
const MAX_CHALLENGE_RESPONSE_ATTEMPTS: u32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct RollupCommitment {
    pub commitment_hash: Hash,
    pub operator: Address,
    pub rollup_id: String,
    pub state_root: Hash,
    pub previous_state_root: Hash,
    pub tx_root: Hash,
    pub da_root: Hash,
    pub proofs_root: Hash,
    pub events_root_post: Hash,
    pub events_root_poc: Hash,
    pub receipts_root: Hash,
    pub tx_count: u32,
    pub block_range: (u64, u64),
    pub l1_block_number: u64,
    pub timestamp: Timestamp,
    pub operator_signature: DualSignature,
    pub proof_data: Vec<u8>,
    pub da_chunks: Vec<u32>,
    pub gas_used: u64,
    pub ru_consumed: u64,
    pub version: u32,
    pub protocol_version: u32,
    pub chain_id: u32,
    pub network_id: u32,
    pub shard_id: ShardId,
    pub epoch: EpochNumber,
    pub fraud_proof_window: u64,
    pub min_validity_proof: Vec<u8>,
    pub deploy_credits_used: u64,
    pub storage_credits_used: u64,
    pub drs_weighted_rewards: bool,
    pub human_verified_deploys: u32,
    pub ai_flagged_deploys: u32,
    pub post_proofs_included: u32,
    pub poc_proofs_included: u32,
    pub cross_shard_receipts_count: u32,
    pub cellular_optimized: bool,
    pub pq_signatures_used: u32,
    pub legacy_signatures_used: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollupCommit {
    pub commitment: RollupCommitment,
    pub status: CommitmentStatus,
    pub challenge_deadline: Option<Timestamp>,
    pub finalization_time: Option<Timestamp>,
    pub associated_batches: Vec<Hash>,
    pub da_availability: DAAvailabilityStatus,
    pub verification_count: u32,
    pub last_verified: Option<Timestamp>,
    pub challenges: Vec<Hash>,
    pub response_attempts: u32,
    pub slashing_amount: Balance,
    pub drs_score_snapshot: f64,
    pub operator_reputation: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DAAvailabilityStatus {
    Unknown,
    Available,
    PartiallyAvailable { missing_chunks: Vec<u32> },
    Unavailable,
    Verifying { progress: u8 },
}

pub struct CommitmentManager {
    commitments: HashMap<Hash, RollupCommit>,
    operator_commitments: HashMap<Address, VecDeque<Hash>>,
    pending_challenges: HashMap<Hash, ChallengeInfo>,
    resolved_challenges: HashMap<Hash, ResolvedChallenge>,
    da_manager: Arc<Mutex<DataAvailability>>,
    challenge_period_blocks: u64,
    response_window_blocks: u64,
    chain_id: u32,
    network_id: u32,
    fraud_proof_window: u64,
    commitment_queue: VecDeque<Hash>,
    finalized_queue: VecDeque<Hash>,
    operator_bonds: HashMap<Address, Balance>,
    operator_stats: HashMap<Address, OperatorStats>,
    epoch_commitments: HashMap<u64, Vec<Hash>>,
    shard_commitments: HashMap<u32, Vec<Hash>>,
    cellular_safe_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChallengeInfo {
    challenger: Address,
    challenge_hash: Hash,
    commitment_hash: Hash,
    challenge_type: ChallengeType,
    submitted_at: Timestamp,
    deadline: Timestamp,
    bond_amount: Balance,
    evidence: Vec<u8>,
    evidence_hash: Hash,
    response_count: u32,
    status: ChallengeInfoStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
enum ChallengeInfoStatus {
    Pending,
    UnderReview,
    Responded,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResolvedChallenge {
    challenge_hash: Hash,
    commitment_hash: Hash,
    challenger: Address,
    operator: Address,
    challenge_type: ChallengeType,
    successful: bool,
    resolved_at: Timestamp,
    slashing_amount: Balance,
    bond_returned: Balance,
    resolution_evidence: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChallengeType {
    InvalidStateTransition,
    DataUnavailability,
    InvalidProof,
    InvalidInclusion,
    InvalidAggregation,
    InvalidDRSCalculation,
    InvalidDeployPolicy,
    MissingHumanVerification,
    PQSignatureViolation,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct OperatorStats {
    total_commitments: u64,
    finalized_commitments: u64,
    challenged_commitments: u64,
    slashed_commitments: u64,
    total_transactions: u64,
    total_gas_used: u64,
    total_ru_consumed: u64,
    avg_finalization_time_ms: u64,
    successful_challenges_against: u32,
    failed_challenges_against: u32,
    reputation_score: u32,
    last_commitment_time: Option<Timestamp>,
    cellular_optimized_count: u64,
}

impl RollupCommitment {
    pub fn new(
        operator: Address,
        rollup_id: String,
        batch: &RollupBatch,
        da_root: Hash,
        proofs_root: Hash,
        events_root_post: Hash,
        events_root_poc: Hash,
        receipts_root: Hash,
        l1_block_number: u64,
        fraud_proof_window: u64,
    ) -> Self {
        let tx_root = batch.tx_root;
        let commitment_hash = Self::compute_commitment_hash(
            &operator,
            &batch.prev_state_root,
            &batch.new_state_root,
            &tx_root,
            &da_root,
            &proofs_root,
            &events_root_post,
            &events_root_poc,
            &receipts_root,
            l1_block_number,
            batch.chain_id,
            batch.network_id,
            batch.shard_id,
            batch.epoch,
        );

        let cellular_optimized = batch.transactions.len() <= 500 && batch.gas_used <= 5_000_000;

        let mut pq_sigs = 0u32;
        let mut legacy_sigs = 0u32;
        for tx in &batch.transactions {
            if tx.signature.dilithium_sig.is_some() {
                pq_sigs += 1;
            }
            if tx.signature.ed25519_sig.is_some() {
                legacy_sigs += 1;
            }
        }

        Self {
            commitment_hash,
            operator,
            rollup_id,
            state_root: batch.new_state_root,
            previous_state_root: batch.prev_state_root,
            tx_root,
            da_root,
            proofs_root,
            events_root_post,
            events_root_poc,
            receipts_root,
            tx_count: batch.transactions.len() as u32,
            block_range: (batch.l1_block_number, batch.l1_block_number),
            l1_block_number,
            timestamp: batch.timestamp,
            operator_signature: DualSignature::new(None, None),
            proof_data: Vec::new(),
            da_chunks: Vec::new(),
            gas_used: batch.gas_used,
            ru_consumed: 0,
            version: crate::ROLLUP_VERSION,
            protocol_version: PROTOCOL_VERSION,
            chain_id: batch.chain_id,
            network_id: batch.network_id,
            shard_id: batch.shard_id,
            epoch: batch.epoch,
            fraud_proof_window,
            min_validity_proof: Vec::new(),
            deploy_credits_used: 0,
            storage_credits_used: 0,
            drs_weighted_rewards: true,
            human_verified_deploys: 0,
            ai_flagged_deploys: 0,
            post_proofs_included: 0,
            poc_proofs_included: 0,
            cross_shard_receipts_count: 0,
            cellular_optimized,
            pq_signatures_used: pq_sigs,
            legacy_signatures_used: legacy_sigs,
        }
    }

    pub fn from_batch(batch: &RollupBatch, fraud_proof_window: u64) -> RollupResult<Self> {
        let da_root = Hash::ZERO;
        let proofs_root = Hash::ZERO;
        let events_root_post = Hash::ZERO;
        let events_root_poc = Hash::ZERO;
        let receipts_root = Hash::ZERO;

        Ok(Self::new(
            batch.operator,
            format!("rollup_shard_{}", batch.shard_id.as_u32()),
            batch,
            da_root,
            proofs_root,
            events_root_post,
            events_root_poc,
            receipts_root,
            batch.l1_block_number,
            fraud_proof_window,
        ))
    }

    pub fn sign(&mut self, keypair: &ego_core::crypto::KeyPair) -> RollupResult<()> {
        let expected_operator = Address::from_public_key(&keypair.dilithium_public_key());
        if expected_operator != self.operator {
            return Err(RollupError::InvalidCommitment(
                "Operator address does not match signing key".to_string(),
            ));
        }

        let signing_data = self.create_signing_data()?;
        self.operator_signature = keypair.sign_hybrid(&signing_data, false);
        self.commitment_hash = self.compute_hash();
        Ok(())
    }

    pub fn verify_signature(&self, operator_dilithium_pk: &PublicKey) -> RollupResult<bool> {
        let expected_operator = Address::from_public_key(operator_dilithium_pk);
        if expected_operator != self.operator {
            return Ok(false);
        }

        let signing_data = self.create_signing_data()?;

        if let Some(ref dilithium_sig) = self.operator_signature.dilithium_sig {
            ego_core::crypto::verify_signature(operator_dilithium_pk, &signing_data, dilithium_sig)
                .map_err(|e| RollupError::VerificationFailed(e.to_string()))
        } else {
            Ok(false)
        }
    }

    pub fn validate(&self) -> RollupResult<()> {
        if self.tx_count == 0 {
            return Err(RollupError::InvalidCommitment(
                "Commitment must contain at least one transaction".to_string(),
            ));
        }

        if self.block_range.0 > self.block_range.1 {
            return Err(RollupError::InvalidCommitment(
                "Invalid block range".to_string(),
            ));
        }

        if self.state_root == Hash::ZERO {
            return Err(RollupError::InvalidCommitment(
                "State root cannot be zero".to_string(),
            ));
        }

        if self.version != crate::ROLLUP_VERSION {
            return Err(RollupError::InvalidCommitment(format!(
                "Unsupported rollup version: expected {}, got {}",
                crate::ROLLUP_VERSION,
                self.version
            )));
        }

        if self.protocol_version != PROTOCOL_VERSION {
            return Err(RollupError::InvalidCommitment(format!(
                "Protocol version mismatch: expected {}, got {}",
                PROTOCOL_VERSION, self.protocol_version
            )));
        }

        if self.fraud_proof_window == 0 {
            return Err(RollupError::InvalidCommitment(
                "Fraud proof window must be greater than zero".to_string(),
            ));
        }

        if self.tx_root == Hash::ZERO {
            return Err(RollupError::InvalidCommitment(
                "Transaction root cannot be zero".to_string(),
            ));
        }

        if self.da_root == Hash::ZERO && !self.da_chunks.is_empty() {
            return Err(RollupError::InvalidCommitment(
                "DA root required when DA chunks present".to_string(),
            ));
        }

        Ok(())
    }

    pub fn validate_with_deploy_policy(
        &self,
        deploy_stats: &DeployStatsSnapshot,
    ) -> RollupResult<()> {
        self.validate()?;

        if self.human_verified_deploys + self.ai_flagged_deploys > self.tx_count {
            return Err(RollupError::InvalidCommitment(
                "Deploy counts exceed transaction count".to_string(),
            ));
        }

        if self.ai_flagged_deploys > deploy_stats.max_ai_flagged_per_commitment {
            return Err(RollupError::InvalidCommitment(format!(
                "Too many AI-flagged deploys: {} > {}",
                self.ai_flagged_deploys, deploy_stats.max_ai_flagged_per_commitment
            )));
        }

        if self.deploy_credits_used > deploy_stats.max_deploy_credits_per_commitment {
            return Err(RollupError::InvalidCommitment(
                "Deploy credits usage exceeds limit".to_string(),
            ));
        }

        Ok(())
    }

    pub fn validate_with_drs(&self, drs_params: &DRSValidationParams) -> RollupResult<()> {
        self.validate()?;

        if !self.drs_weighted_rewards && drs_params.require_drs_weighting {
            return Err(RollupError::InvalidCommitment(
                "DRS weighted rewards required".to_string(),
            ));
        }

        if self.post_proofs_included < drs_params.min_post_proofs_per_commitment {
            return Err(RollupError::InvalidCommitment(format!(
                "Insufficient PoSt proofs: {} < {}",
                self.post_proofs_included, drs_params.min_post_proofs_per_commitment
            )));
        }

        Ok(())
    }

    pub fn validate_pq_transition(&self, pq_config: &PQTransitionConfig) -> RollupResult<()> {
        self.validate()?;

        if pq_config.pq_only_required {
            if let Some(deadline) = pq_config.legacy_deadline_epoch {
                if self.epoch.as_u64() >= deadline && self.legacy_signatures_used > 0 {
                    return Err(RollupError::InvalidCommitment(
                        "Legacy signatures no longer allowed after deadline".to_string(),
                    ));
                }
            }
        }

        let total_sigs = self.pq_signatures_used + self.legacy_signatures_used;
        if total_sigs != self.tx_count {
            return Err(RollupError::InvalidCommitment(
                "Signature count mismatch with transaction count".to_string(),
            ));
        }

        Ok(())
    }

    pub fn is_reproducible(&self, other: &Self) -> bool {
        self.state_root == other.state_root
            && self.tx_root == other.tx_root
            && self.da_root == other.da_root
            && self.proofs_root == other.proofs_root
            && self.events_root_post == other.events_root_post
            && self.events_root_poc == other.events_root_poc
            && self.receipts_root == other.receipts_root
            && self.tx_count == other.tx_count
            && self.block_range == other.block_range
            && self.chain_id == other.chain_id
            && self.network_id == other.network_id
            && self.shard_id == other.shard_id
    }

    pub fn compute_hash(&self) -> Hash {
        Self::compute_commitment_hash(
            &self.operator,
            &self.previous_state_root,
            &self.state_root,
            &self.tx_root,
            &self.da_root,
            &self.proofs_root,
            &self.events_root_post,
            &self.events_root_poc,
            &self.receipts_root,
            self.l1_block_number,
            self.chain_id,
            self.network_id,
            self.shard_id,
            self.epoch,
        )
    }

    fn create_signing_data(&self) -> RollupResult<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(DOMAIN_TAG_COMMITMENT);
        data.extend_from_slice(self.operator.as_bytes());
        data.extend_from_slice(self.rollup_id.as_bytes());
        data.extend_from_slice(self.state_root.as_bytes());
        data.extend_from_slice(self.previous_state_root.as_bytes());
        data.extend_from_slice(self.tx_root.as_bytes());
        data.extend_from_slice(self.da_root.as_bytes());
        data.extend_from_slice(self.proofs_root.as_bytes());
        data.extend_from_slice(self.events_root_post.as_bytes());
        data.extend_from_slice(self.events_root_poc.as_bytes());
        data.extend_from_slice(self.receipts_root.as_bytes());
        data.extend_from_slice(&self.tx_count.to_le_bytes());
        data.extend_from_slice(&self.block_range.0.to_le_bytes());
        data.extend_from_slice(&self.block_range.1.to_le_bytes());
        data.extend_from_slice(&self.l1_block_number.to_le_bytes());
        data.extend_from_slice(&self.timestamp.as_millis().to_le_bytes());
        data.extend_from_slice(&self.gas_used.to_le_bytes());
        data.extend_from_slice(&self.ru_consumed.to_le_bytes());
        data.extend_from_slice(&self.version.to_le_bytes());
        data.extend_from_slice(&self.protocol_version.to_le_bytes());
        data.extend_from_slice(&self.chain_id.to_le_bytes());
        data.extend_from_slice(&self.network_id.to_le_bytes());
        data.extend_from_slice(&self.shard_id.as_u32().to_le_bytes());
        data.extend_from_slice(&self.epoch.as_u64().to_le_bytes());
        data.extend_from_slice(&self.fraud_proof_window.to_le_bytes());

        Ok(ego_core::crypto::blake2s_hash(&data))
    }

    fn compute_commitment_hash(
        operator: &Address,
        prev_state_root: &Hash,
        state_root: &Hash,
        tx_root: &Hash,
        da_root: &Hash,
        proofs_root: &Hash,
        events_root_post: &Hash,
        events_root_poc: &Hash,
        receipts_root: &Hash,
        l1_block_number: u64,
        chain_id: u32,
        network_id: u32,
        shard_id: ShardId,
        epoch: EpochNumber,
    ) -> Hash {
        ego_core::crypto::hash_multiple(&[
            DOMAIN_TAG_COMMITMENT,
            operator.as_bytes(),
            prev_state_root.as_bytes(),
            state_root.as_bytes(),
            tx_root.as_bytes(),
            da_root.as_bytes(),
            proofs_root.as_bytes(),
            events_root_post.as_bytes(),
            events_root_poc.as_bytes(),
            receipts_root.as_bytes(),
            &l1_block_number.to_le_bytes(),
            &chain_id.to_le_bytes(),
            &network_id.to_le_bytes(),
            &shard_id.as_u32().to_le_bytes(),
            &epoch.as_u64().to_le_bytes(),
        ])
    }

    pub fn size(&self) -> usize {
        let config = bincode::config::standard();
        bincode::encode_to_vec(self, config)
            .map(|data| data.len())
            .unwrap_or(0)
    }

    pub fn is_cellular_optimized(&self) -> bool {
        self.cellular_optimized && self.size() <= 512 * 1024
    }

    pub fn set_da_root(&mut self, da_root: Hash) {
        self.da_root = da_root;
        self.commitment_hash = self.compute_hash();
    }

    pub fn set_proofs_root(&mut self, proofs_root: Hash) {
        self.proofs_root = proofs_root;
        self.commitment_hash = self.compute_hash();
    }

    pub fn set_events_roots(&mut self, events_root_post: Hash, events_root_poc: Hash) {
        self.events_root_post = events_root_post;
        self.events_root_poc = events_root_poc;
        self.commitment_hash = self.compute_hash();
    }

    pub fn set_receipts_root(&mut self, receipts_root: Hash) {
        self.receipts_root = receipts_root;
        self.commitment_hash = self.compute_hash();
    }

    pub fn add_proof_data(&mut self, proof_data: Vec<u8>) {
        self.proof_data = proof_data;
    }

    pub fn add_validity_proof(&mut self, validity_proof: Vec<u8>) {
        self.min_validity_proof = validity_proof;
    }

    pub fn set_resource_usage(
        &mut self,
        deploy_credits: u64,
        storage_credits: u64,
        ru_consumed: u64,
    ) {
        self.deploy_credits_used = deploy_credits;
        self.storage_credits_used = storage_credits;
        self.ru_consumed = ru_consumed;
    }

    pub fn set_deploy_stats(&mut self, human_verified: u32, ai_flagged: u32) {
        self.human_verified_deploys = human_verified;
        self.ai_flagged_deploys = ai_flagged;
    }

    pub fn set_proof_counts(&mut self, post_proofs: u32, poc_proofs: u32) {
        self.post_proofs_included = post_proofs;
        self.poc_proofs_included = poc_proofs;
    }

    pub fn set_cross_shard_count(&mut self, count: u32) {
        self.cross_shard_receipts_count = count;
    }
}

impl CommitmentManager {
    pub fn new(
        da_manager: Arc<Mutex<DataAvailability>>,
        challenge_period_blocks: u64,
        response_window_blocks: u64,
        chain_id: u32,
        network_id: u32,
        fraud_proof_window: u64,
        cellular_safe_mode: bool,
    ) -> Self {
        Self {
            commitments: HashMap::new(),
            operator_commitments: HashMap::new(),
            pending_challenges: HashMap::new(),
            resolved_challenges: HashMap::new(),
            da_manager,
            challenge_period_blocks,
            response_window_blocks,
            chain_id,
            network_id,
            fraud_proof_window,
            commitment_queue: VecDeque::new(),
            finalized_queue: VecDeque::new(),
            operator_bonds: HashMap::new(),
            operator_stats: HashMap::new(),
            epoch_commitments: HashMap::new(),
            shard_commitments: HashMap::new(),
            cellular_safe_mode,
        }
    }

    pub fn submit_commitment(
        &mut self,
        mut commitment: RollupCommitment,
        da_chunks: Vec<DAChunk>,
    ) -> RollupResult<Hash> {
        commitment.validate()?;

        if commitment.chain_id != self.chain_id {
            return Err(RollupError::InvalidCommitment(format!(
                "Chain ID mismatch: expected {}, got {}",
                self.chain_id, commitment.chain_id
            )));
        }

        if commitment.network_id != self.network_id {
            return Err(RollupError::InvalidCommitment(format!(
                "Network ID mismatch: expected {}, got {}",
                self.network_id, commitment.network_id
            )));
        }

        if self.cellular_safe_mode && !commitment.is_cellular_optimized() {
            return Err(RollupError::InvalidCommitment(
                "Commitment not cellular-optimized in cellular-safe mode".to_string(),
            ));
        }

        if self.commitments.len() >= MAX_COMMITMENTS_IN_MEMORY {
            self.prune_old_commitments()?;
        }

        let chunk_ids: Vec<u32> = da_chunks.iter().map(|c| c.chunk_id).collect();
        commitment.da_chunks = chunk_ids;

        let challenge_deadline = Timestamp::from_millis(
            commitment.timestamp.as_millis() + (self.challenge_period_blocks * 12000),
        );

        let operator_bond = self
            .operator_bonds
            .get(&commitment.operator)
            .copied()
            .unwrap_or(Balance::ZERO);
        if operator_bond < Balance::new(DEFAULT_CHALLENGE_BOND) {
            return Err(RollupError::InsufficientBond {
                required: Balance::new(DEFAULT_CHALLENGE_BOND).as_u128(),
                available: operator_bond.as_u128(),
            });
        }

        let drs_score = self.get_operator_drs_score(&commitment.operator);

        let commit = RollupCommit {
            commitment: commitment.clone(),
            status: CommitmentStatus::Pending,
            challenge_deadline: Some(challenge_deadline),
            finalization_time: None,
            associated_batches: Vec::new(),
            da_availability: DAAvailabilityStatus::Unknown,
            verification_count: 0,
            last_verified: None,
            challenges: Vec::new(),
            response_attempts: 0,
            slashing_amount: Balance::ZERO,
            drs_score_snapshot: drs_score,
            operator_reputation: self.get_operator_reputation(&commitment.operator),
        };

        let commitment_hash = commitment.commitment_hash;

        self.commitments.insert(commitment_hash, commit);

        self.operator_commitments
            .entry(commitment.operator)
            .or_insert_with(VecDeque::new)
            .push_back(commitment_hash);

        self.commitment_queue.push_back(commitment_hash);

        self.epoch_commitments
            .entry(commitment.epoch.as_u64())
            .or_insert_with(Vec::new)
            .push(commitment_hash);

        self.shard_commitments
            .entry(commitment.shard_id.as_u32())
            .or_insert_with(Vec::new)
            .push(commitment_hash);

        self.update_operator_stats(&commitment.operator, |stats| {
            stats.total_commitments += 1;
            stats.total_transactions += commitment.tx_count as u64;
            stats.total_gas_used += commitment.gas_used;
            stats.total_ru_consumed += commitment.ru_consumed;
            stats.last_commitment_time = Some(commitment.timestamp);
            if commitment.cellular_optimized {
                stats.cellular_optimized_count += 1;
            }
        });

        Ok(commitment_hash)
    }

    pub fn challenge_commitment(
        &mut self,
        commitment_hash: Hash,
        challenger: Address,
        challenge_type: ChallengeType,
        bond_amount: Balance,
        evidence: Vec<u8>,
    ) -> RollupResult<Hash> {
        if evidence.len() > MAX_CHALLENGE_EVIDENCE_SIZE {
            return Err(RollupError::InvalidChallenge(
                "Challenge evidence too large".to_string(),
            ));
        }

        let commit = self
            .commitments
            .get_mut(&commitment_hash)
            .ok_or_else(|| RollupError::InvalidCommitment("Commitment not found".to_string()))?;

        match &commit.status {
            CommitmentStatus::Pending => {}
            CommitmentStatus::Finalized => {
                return Err(RollupError::ChallengePeriodExpired);
            }
            CommitmentStatus::Challenged(_) => {
                if commit.challenges.len() >= 3 {
                    return Err(RollupError::InvalidCommitment(
                        "Maximum challenges reached".to_string(),
                    ));
                }
            }
            CommitmentStatus::Slashed => {
                return Err(RollupError::InvalidCommitment(
                    "Commitment already slashed".to_string(),
                ));
            }
        }

        if let Some(deadline) = commit.challenge_deadline {
            if Timestamp::now() > deadline {
                return Err(RollupError::ChallengePeriodExpired);
            }
        }

        let challenger_bond = self
            .operator_bonds
            .get(&challenger)
            .copied()
            .unwrap_or(Balance::ZERO);
        if challenger_bond < bond_amount {
            return Err(RollupError::InsufficientBond {
                required: bond_amount.as_u128(),
                available: challenger_bond.as_u128(),
            });
        }

        let mut data = Vec::new();
        data.extend_from_slice(DOMAIN_TAG_CHALLENGE);
        data.extend_from_slice(challenger.as_bytes());
        data.extend_from_slice(commitment_hash.as_bytes());
        data.extend_from_slice(&challenge_type.to_u8().to_le_bytes());
        data.extend_from_slice(&Timestamp::now().as_millis().to_le_bytes());
        let challenge_hash = ego_core::crypto::hash_data(&data);

        let evidence_hash = ego_core::crypto::hash_data(&evidence);

        let response_deadline = Timestamp::from_millis(
            Timestamp::now().as_millis() + (self.response_window_blocks * 12000),
        );

        let challenge_info = ChallengeInfo {
            challenger,
            challenge_hash,
            commitment_hash,
            challenge_type: challenge_type.clone(),
            submitted_at: Timestamp::now(),
            deadline: response_deadline,
            bond_amount,
            evidence,
            evidence_hash,
            response_count: 0,
            status: ChallengeInfoStatus::Pending,
        };

        commit.status = CommitmentStatus::Challenged(ChallengeStatus::Pending {
            challenger,
            challenge_hash,
            deadline: response_deadline,
        });

        commit.challenges.push(challenge_hash);

        self.pending_challenges
            .insert(challenge_hash, challenge_info);

        Ok(challenge_hash)
    }

    pub fn respond_to_challenge(
        &mut self,
        challenge_hash: Hash,
        operator: Address,
        response_evidence: Vec<u8>,
    ) -> RollupResult<()> {
        let challenge_info = self
            .pending_challenges
            .get_mut(&challenge_hash)
            .ok_or_else(|| RollupError::FraudProof("Challenge not found".to_string()))?;

        if challenge_info.status != ChallengeInfoStatus::Pending {
            return Err(RollupError::InvalidChallenge(
                "Challenge not in pending state".to_string(),
            ));
        }

        if Timestamp::now() > challenge_info.deadline {
            return Err(RollupError::InvalidChallenge(
                "Challenge response deadline expired".to_string(),
            ));
        }

        let commit = self
            .commitments
            .get_mut(&challenge_info.commitment_hash)
            .ok_or_else(|| RollupError::InvalidCommitment("Commitment not found".to_string()))?;

        if commit.commitment.operator != operator {
            return Err(RollupError::InvalidCommitment(
                "Only operator can respond".to_string(),
            ));
        }

        if commit.response_attempts >= MAX_CHALLENGE_RESPONSE_ATTEMPTS {
            return Err(RollupError::InvalidChallenge(
                "Maximum response attempts exceeded".to_string(),
            ));
        }

        challenge_info.response_count += 1;
        challenge_info.status = ChallengeInfoStatus::Responded;
        commit.response_attempts += 1;

        Ok(())
    }

    pub fn resolve_challenge(
        &mut self,
        challenge_hash: Hash,
        successful: bool,
        resolution_evidence: Vec<u8>,
    ) -> RollupResult<()> {
        let challenge_info = self
            .pending_challenges
            .remove(&challenge_hash)
            .ok_or_else(|| RollupError::FraudProof("Challenge not found".to_string()))?;

        let commit = self
            .commitments
            .get_mut(&challenge_info.commitment_hash)
            .ok_or_else(|| RollupError::InvalidCommitment("Commitment not found".to_string()))?;

        let operator = commit.commitment.operator;
        let slashing_amount = if successful {
            let base_slash = Balance::new(DEFAULT_CHALLENGE_BOND);
            let reputation_multiplier = (100 - commit.operator_reputation.min(50)) as f64 / 100.0;
            Balance::new((base_slash.as_u128() as f64 * (1.0 + reputation_multiplier)) as u128)
        } else {
            Balance::ZERO
        };

        let bond_returned = if successful {
            challenge_info.bond_amount
        } else {
            Balance::ZERO
        };

        let resolved = ResolvedChallenge {
            challenge_hash,
            commitment_hash: challenge_info.commitment_hash,
            challenger: challenge_info.challenger,
            operator,
            challenge_type: challenge_info.challenge_type,
            successful,
            resolved_at: Timestamp::now(),
            slashing_amount,
            bond_returned,
            resolution_evidence,
        };

        self.resolved_challenges.insert(challenge_hash, resolved);

        if successful {
            commit.status = CommitmentStatus::Slashed;
            commit.slashing_amount = slashing_amount;

            if let Some(bond) = self.operator_bonds.get_mut(&operator) {
                *bond = bond.checked_sub(slashing_amount).unwrap_or(Balance::ZERO);
            }

            if let Some(challenger_bond) = self.operator_bonds.get_mut(&challenge_info.challenger) {
                *challenger_bond = challenger_bond
                    .checked_add(bond_returned)
                    .unwrap_or(*challenger_bond);
            }

            self.update_operator_stats(&operator, |stats| {
                stats.slashed_commitments += 1;
                stats.successful_challenges_against += 1;
                if stats.reputation_score > 10 {
                    stats.reputation_score -= 10;
                }
            });
        } else {
            commit.status = CommitmentStatus::Finalized;
            commit.finalization_time = Some(Timestamp::now());
            self.finalized_queue
                .push_back(challenge_info.commitment_hash);

            self.update_operator_stats(&operator, |stats| {
                stats.finalized_commitments += 1;
                stats.failed_challenges_against += 1;
                if stats.reputation_score < 100 {
                    stats.reputation_score += 1;
                }
            });
        }

        Ok(())
    }

    pub fn finalize_expired_commitments(&mut self, _current_block: u64) -> Vec<Hash> {
        let mut finalized = Vec::new();
        let current_time = Timestamp::now();
        let mut stats_updates: Vec<(Address, u64, u64)> = Vec::new();

        for (hash, commit) in &mut self.commitments {
            if let CommitmentStatus::Pending = commit.status {
                if let Some(deadline) = commit.challenge_deadline {
                    if current_time > deadline {
                        commit.status = CommitmentStatus::Finalized;
                        commit.finalization_time = Some(current_time);
                        finalized.push(*hash);
                        self.finalized_queue.push_back(*hash);

                        let operator = commit.commitment.operator;
                        let elapsed = current_time
                            .as_millis()
                            .saturating_sub(commit.commitment.timestamp.as_millis());
                        stats_updates.push((operator, elapsed, 1));
                    }
                }
            }
        }

        for (operator, elapsed, count) in stats_updates {
            self.update_operator_stats(&operator, |stats| {
                stats.finalized_commitments += count;
                let total_count = stats.finalized_commitments;
                stats.avg_finalization_time_ms =
                    ((stats.avg_finalization_time_ms * (total_count - 1)) + elapsed) / total_count;
            });
        }

        finalized
    }

    pub fn get_commitment(&self, hash: Hash) -> Option<&RollupCommit> {
        self.commitments.get(&hash)
    }

    pub fn get_commitment_mut(&mut self, hash: Hash) -> Option<&mut RollupCommit> {
        self.commitments.get_mut(&hash)
    }

    pub fn get_operator_commitments(&self, operator: Address) -> Vec<Hash> {
        self.operator_commitments
            .get(&operator)
            .map(|queue| queue.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn get_pending_commitments(&self) -> Vec<Hash> {
        self.commitments
            .iter()
            .filter(|(_, commit)| matches!(commit.status, CommitmentStatus::Pending))
            .map(|(hash, _)| *hash)
            .collect()
    }

    pub fn get_challenged_commitments(&self) -> Vec<Hash> {
        self.commitments
            .iter()
            .filter(|(_, commit)| matches!(commit.status, CommitmentStatus::Challenged(_)))
            .map(|(hash, _)| *hash)
            .collect()
    }

    pub fn get_finalized_commitments(&self) -> Vec<Hash> {
        self.commitments
            .iter()
            .filter(|(_, commit)| matches!(commit.status, CommitmentStatus::Finalized))
            .map(|(hash, _)| *hash)
            .collect()
    }

    pub fn get_shard_commitments(&self, shard_id: u32) -> Vec<Hash> {
        self.shard_commitments
            .get(&shard_id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn get_epoch_commitments(&self, epoch: u64) -> Vec<Hash> {
        self.epoch_commitments
            .get(&epoch)
            .cloned()
            .unwrap_or_default()
    }

    pub fn verify_da_availability(
        &mut self,
        commitment_hash: Hash,
        sample_size: usize,
    ) -> RollupResult<bool> {
        let commit = self
            .commitments
            .get_mut(&commitment_hash)
            .ok_or_else(|| RollupError::DataAvailability("Commitment not found".to_string()))?;

        let chunk_count = commit.commitment.da_chunks.len();
        if chunk_count == 0 {
            commit.da_availability = DAAvailabilityStatus::Unavailable;
            return Ok(false);
        }

        let effective_sample_size = sample_size.max(MIN_DA_SAMPLE_SIZE).min(chunk_count);
        let sample_indices: Vec<u32> = (0..effective_sample_size)
            .map(|i| {
                let idx = (i * chunk_count) / effective_sample_size;
                commit.commitment.da_chunks[idx]
            })
            .collect();

        commit.da_availability = DAAvailabilityStatus::Verifying {
            progress: ((sample_indices.len() * 100) / chunk_count) as u8,
        };

        let result = {
            let mut da_manager = self
                .da_manager
                .lock()
                .map_err(|e| RollupError::DataAvailability(format!("Lock poisoned: {}", e)))?;
            da_manager.sample_chunks(commitment_hash, sample_indices.clone())
        };

        match result {
            Ok(chunks) => {
                let commit = self.commitments.get_mut(&commitment_hash).unwrap();
                if chunks.len() == sample_indices.len() {
                    commit.da_availability = DAAvailabilityStatus::Available;
                    commit.verification_count += 1;
                    commit.last_verified = Some(Timestamp::now());
                    Ok(true)
                } else {
                    let missing: Vec<u32> = sample_indices
                        .into_iter()
                        .filter(|&idx| !chunks.iter().any(|c| c.chunk_id == idx))
                        .collect();

                    commit.da_availability = DAAvailabilityStatus::PartiallyAvailable {
                        missing_chunks: missing,
                    };
                    commit.verification_count += 1;
                    commit.last_verified = Some(Timestamp::now());
                    Ok(false)
                }
            }
            Err(_) => {
                let commit = self.commitments.get_mut(&commitment_hash).unwrap();
                commit.da_availability = DAAvailabilityStatus::Unavailable;
                commit.verification_count += 1;
                commit.last_verified = Some(Timestamp::now());
                Ok(false)
            }
        }
    }

    pub fn get_commitment_stats(&self) -> CommitmentStats {
        let mut stats = CommitmentStats::default();

        for commit in self.commitments.values() {
            stats.total_commitments += 1;

            match &commit.status {
                CommitmentStatus::Pending => stats.pending_commitments += 1,
                CommitmentStatus::Challenged(_) => stats.challenged_commitments += 1,
                CommitmentStatus::Finalized => stats.finalized_commitments += 1,
                CommitmentStatus::Slashed => stats.slashed_commitments += 1,
            }

            match &commit.da_availability {
                DAAvailabilityStatus::Available => stats.available_da += 1,
                DAAvailabilityStatus::PartiallyAvailable { .. } => {
                    stats.partially_available_da += 1
                }
                DAAvailabilityStatus::Unavailable => stats.unavailable_da += 1,
                DAAvailabilityStatus::Unknown | DAAvailabilityStatus::Verifying { .. } => {
                    stats.unknown_da += 1
                }
            }

            stats.total_transactions += commit.commitment.tx_count as u64;
            stats.total_gas_used += commit.commitment.gas_used;
            stats.total_ru_consumed += commit.commitment.ru_consumed;
            stats.total_deploy_credits_used += commit.commitment.deploy_credits_used;
            stats.total_storage_credits_used += commit.commitment.storage_credits_used;
            stats.total_post_proofs += commit.commitment.post_proofs_included as u64;
            stats.total_poc_proofs += commit.commitment.poc_proofs_included as u64;

            if commit.commitment.cellular_optimized {
                stats.cellular_optimized_commitments += 1;
            }

            stats.pq_signature_usage += commit.commitment.pq_signatures_used as u64;
            stats.legacy_signature_usage += commit.commitment.legacy_signatures_used as u64;
        }

        stats
    }

    pub fn associate_batch(&mut self, commitment_hash: Hash, batch_hash: Hash) -> RollupResult<()> {
        let commit = self
            .commitments
            .get_mut(&commitment_hash)
            .ok_or_else(|| RollupError::InvalidCommitment("Commitment not found".to_string()))?;

        if !commit.associated_batches.contains(&batch_hash) {
            commit.associated_batches.push(batch_hash);
        }

        Ok(())
    }

    pub fn get_challenge_info(&self, challenge_hash: Hash) -> Option<&ChallengeInfo> {
        self.pending_challenges.get(&challenge_hash)
    }

    pub fn get_resolved_challenge(&self, challenge_hash: Hash) -> Option<&ResolvedChallenge> {
        self.resolved_challenges.get(&challenge_hash)
    }

    pub fn cleanup_old_commitments(&mut self, retention_epochs: u64, current_epoch: u64) -> usize {
        let cutoff_epoch = current_epoch.saturating_sub(retention_epochs);
        let mut removed = 0;

        self.commitments.retain(|hash, commit| {
            let should_keep = commit.commitment.epoch.as_u64() >= cutoff_epoch
                || !matches!(
                    commit.status,
                    CommitmentStatus::Finalized | CommitmentStatus::Slashed
                );

            if !should_keep {
                self.operator_commitments
                    .get_mut(&commit.commitment.operator)
                    .map(|queue| queue.retain(|h| h != hash));

                self.epoch_commitments
                    .get_mut(&commit.commitment.epoch.as_u64())
                    .map(|vec| vec.retain(|h| h != hash));

                self.shard_commitments
                    .get_mut(&commit.commitment.shard_id.as_u32())
                    .map(|vec| vec.retain(|h| h != hash));

                removed += 1;
            }

            should_keep
        });

        self.commitment_queue
            .retain(|h| self.commitments.contains_key(h));
        self.finalized_queue
            .retain(|h| self.commitments.contains_key(h));

        removed
    }

    pub fn verify_commitment_chain(&self, commitment_hashes: &[Hash]) -> RollupResult<bool> {
        if commitment_hashes.is_empty() {
            return Ok(true);
        }

        for i in 1..commitment_hashes.len() {
            let prev_commit = self
                .get_commitment(commitment_hashes[i - 1])
                .ok_or_else(|| {
                    RollupError::InvalidCommitment("Previous commitment not found".to_string())
                })?;

            let curr_commit = self.get_commitment(commitment_hashes[i]).ok_or_else(|| {
                RollupError::InvalidCommitment("Current commitment not found".to_string())
            })?;

            if curr_commit.commitment.previous_state_root != prev_commit.commitment.state_root {
                return Ok(false);
            }

            if curr_commit.commitment.block_range.0 < prev_commit.commitment.block_range.1 {
                return Ok(false);
            }

            if curr_commit.commitment.shard_id != prev_commit.commitment.shard_id {
                return Ok(false);
            }
        }

        Ok(true)
    }

    pub fn set_operator_bond(&mut self, operator: Address, bond: Balance) {
        self.operator_bonds.insert(operator, bond);
    }

    pub fn get_operator_bond(&self, operator: &Address) -> Balance {
        self.operator_bonds
            .get(operator)
            .copied()
            .unwrap_or(Balance::ZERO)
    }

    pub fn get_operator_stats(&self, operator: &Address) -> Option<&OperatorStats> {
        self.operator_stats.get(operator)
    }

    pub fn get_operator_reputation(&self, operator: &Address) -> u32 {
        self.operator_stats
            .get(operator)
            .map(|stats| stats.reputation_score)
            .unwrap_or(50)
    }

    pub fn get_operator_drs_score(&self, operator: &Address) -> f64 {
        self.operator_stats
            .get(operator)
            .and_then(|stats| {
                if stats.total_commitments == 0 {
                    return None;
                }

                let success_rate =
                    stats.finalized_commitments as f64 / stats.total_commitments as f64;
                let challenge_resistance = 1.0
                    - (stats.successful_challenges_against as f64
                        / stats.total_commitments.max(1) as f64);
                let cellular_optimization =
                    stats.cellular_optimized_count as f64 / stats.total_commitments as f64;

                Some(
                    (success_rate * 0.5 + challenge_resistance * 0.3 + cellular_optimization * 0.2)
                        .clamp(0.0, 1.0),
                )
            })
            .unwrap_or(0.5)
    }

    fn update_operator_stats<F>(&mut self, operator: &Address, update_fn: F)
    where
        F: FnOnce(&mut OperatorStats),
    {
        let stats = self
            .operator_stats
            .entry(*operator)
            .or_insert_with(OperatorStats::default);
        update_fn(stats);
    }

    fn prune_old_commitments(&mut self) -> RollupResult<()> {
        if self.commitments.len() < MAX_COMMITMENTS_IN_MEMORY {
            return Ok(());
        }

        let to_remove = self.commitments.len() - (MAX_COMMITMENTS_IN_MEMORY * 80 / 100);
        let mut removed = 0;

        while removed < to_remove && !self.finalized_queue.is_empty() {
            if let Some(hash) = self.finalized_queue.pop_front() {
                if let Some(commit) = self.commitments.get(&hash) {
                    if matches!(
                        commit.status,
                        CommitmentStatus::Finalized | CommitmentStatus::Slashed
                    ) {
                        self.commitments.remove(&hash);
                        removed += 1;
                    }
                }
            }
        }

        Ok(())
    }

    pub fn get_commitment_by_tx_root(&self, tx_root: Hash) -> Option<Hash> {
        self.commitments
            .iter()
            .find(|(_, commit)| commit.commitment.tx_root == tx_root)
            .map(|(hash, _)| *hash)
    }

    pub fn verify_commitment_signature(
        &self,
        commitment_hash: Hash,
        public_key: &PublicKey,
    ) -> RollupResult<bool> {
        let commit = self
            .commitments
            .get(&commitment_hash)
            .ok_or_else(|| RollupError::InvalidCommitment("Commitment not found".to_string()))?;

        commit.commitment.verify_signature(public_key)
    }

    pub fn get_cellular_safe_mode(&self) -> bool {
        self.cellular_safe_mode
    }

    pub fn set_cellular_safe_mode(&mut self, enabled: bool) {
        self.cellular_safe_mode = enabled;
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CommitmentStats {
    pub total_commitments: u64,
    pub pending_commitments: u64,
    pub challenged_commitments: u64,
    pub finalized_commitments: u64,
    pub slashed_commitments: u64,
    pub available_da: u64,
    pub partially_available_da: u64,
    pub unavailable_da: u64,
    pub unknown_da: u64,
    pub total_transactions: u64,
    pub total_gas_used: u64,
    pub total_ru_consumed: u64,
    pub total_deploy_credits_used: u64,
    pub total_storage_credits_used: u64,
    pub total_post_proofs: u64,
    pub total_poc_proofs: u64,
    pub cellular_optimized_commitments: u64,
    pub pq_signature_usage: u64,
    pub legacy_signature_usage: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployStatsSnapshot {
    pub max_ai_flagged_per_commitment: u32,
    pub max_deploy_credits_per_commitment: u64,
    pub require_human_verification: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DRSValidationParams {
    pub require_drs_weighting: bool,
    pub min_post_proofs_per_commitment: u32,
    pub min_drs_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQTransitionConfig {
    pub pq_only_required: bool,
    pub legacy_deadline_epoch: Option<u64>,
    pub min_pq_signature_ratio: f64,
}

impl ChallengeType {
    pub fn from_string(s: &str) -> Option<Self> {
        match s {
            "invalid_state_transition" => Some(ChallengeType::InvalidStateTransition),
            "data_unavailability" => Some(ChallengeType::DataUnavailability),
            "invalid_proof" => Some(ChallengeType::InvalidProof),
            "invalid_inclusion" => Some(ChallengeType::InvalidInclusion),
            "invalid_aggregation" => Some(ChallengeType::InvalidAggregation),
            "invalid_drs_calculation" => Some(ChallengeType::InvalidDRSCalculation),
            "invalid_deploy_policy" => Some(ChallengeType::InvalidDeployPolicy),
            "missing_human_verification" => Some(ChallengeType::MissingHumanVerification),
            "pq_signature_violation" => Some(ChallengeType::PQSignatureViolation),
            _ => None,
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            ChallengeType::InvalidStateTransition => "invalid_state_transition".to_string(),
            ChallengeType::DataUnavailability => "data_unavailability".to_string(),
            ChallengeType::InvalidProof => "invalid_proof".to_string(),
            ChallengeType::InvalidInclusion => "invalid_inclusion".to_string(),
            ChallengeType::InvalidAggregation => "invalid_aggregation".to_string(),
            ChallengeType::InvalidDRSCalculation => "invalid_drs_calculation".to_string(),
            ChallengeType::InvalidDeployPolicy => "invalid_deploy_policy".to_string(),
            ChallengeType::MissingHumanVerification => "missing_human_verification".to_string(),
            ChallengeType::PQSignatureViolation => "pq_signature_violation".to_string(),
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            ChallengeType::InvalidStateTransition => 1,
            ChallengeType::DataUnavailability => 2,
            ChallengeType::InvalidProof => 3,
            ChallengeType::InvalidInclusion => 4,
            ChallengeType::InvalidAggregation => 5,
            ChallengeType::InvalidDRSCalculation => 6,
            ChallengeType::InvalidDeployPolicy => 7,
            ChallengeType::MissingHumanVerification => 8,
            ChallengeType::PQSignatureViolation => 9,
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(ChallengeType::InvalidStateTransition),
            2 => Some(ChallengeType::DataUnavailability),
            3 => Some(ChallengeType::InvalidProof),
            4 => Some(ChallengeType::InvalidInclusion),
            5 => Some(ChallengeType::InvalidAggregation),
            6 => Some(ChallengeType::InvalidDRSCalculation),
            7 => Some(ChallengeType::InvalidDeployPolicy),
            8 => Some(ChallengeType::MissingHumanVerification),
            9 => Some(ChallengeType::PQSignatureViolation),
            _ => None,
        }
    }
}
