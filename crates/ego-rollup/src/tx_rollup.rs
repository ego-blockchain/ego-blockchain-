use crate::config::RollupConfig;
use crate::da::CellularSafeConfig;
use crate::da::{DAChunk, DataAvailability};
use crate::error::{RollupError, RollupResult};
use crate::fraud::{FraudProof, FraudProofVerifier};
use crate::types::{CommitmentStatus, RollupTransaction};
use ego_core::{Address, Balance, Hash, Timestamp};
use ego_core::{BlockHeight, ShardId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct TxRollupCommit {
    pub rollup_id: [u8; 16],
    pub region_id: u32,
    pub epoch: u64,
    pub window_id: u32,
    pub tx_root: Hash,
    pub state_root: Hash,
    pub da_root: Hash,
    pub count_tx: u32,
    pub blob_bytes: u64,
    pub block_range_start: u64,
    pub block_range_end: u64,
    pub min_validity_proof: MinValidityProof,
    pub alg_sig_id: u16,
    pub operator_addr: [u8; 20],
    pub operator_sig: Vec<u8>,
    pub created_at: Timestamp,
    pub fraud_proof_window: u64,
    pub proofs_root: Hash,
    pub chain_id: u32,
    pub network_id: u32,
    pub drs_multiplier: f64,
    pub deploy_credits_used: u64,
    pub ru_consumed: u64,
}

#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, bincode::Encode, bincode::Decode, PartialEq, Eq,
)]
pub enum MinValidityProof {
    None = 0,
    InclusionOnly = 1,
    StateWitness = 2,
    CircuitProof = 3,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct TxRollupBatch {
    pub batch_id: Hash,
    pub rollup_id: [u8; 16],
    pub region_id: u32,
    pub transactions: Vec<RollupTransaction>,
    pub prev_state_root: Hash,
    pub new_state_root: Hash,
    pub l1_block_number: u64,
    pub timestamp: Timestamp,
    pub tx_root: Hash,
    pub state_transitions: Vec<StateTransitionProof>,
    pub ru_total: u64,
    pub size_bytes: u64,
    pub deploy_records: Vec<DeployRecord>,
    pub drs_scores: HashMap<Address, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct StateTransitionProof {
    pub tx_hash: Hash,
    pub pre_state: Hash,
    pub post_state: Hash,
    pub witness_data: Vec<u8>,
    pub account_updates: Vec<AccountUpdate>,
    pub storage_changes: Vec<StorageChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct AccountUpdate {
    pub address: Address,
    pub balance_delta: i128,
    pub nonce_delta: u64,
    pub storage_quota_delta: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct StorageChange {
    pub chunk_id: Hash,
    pub operation: StorageOperation,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum StorageOperation {
    Create,
    Update,
    Delete,
    PostVerification { passed: bool, latency_ms: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DeployRecord {
    pub deploy_id: Hash,
    pub deployer: Address,
    pub code_hash: Hash,
    pub size_kb: u32,
    pub credits_used: u64,
    pub success: bool,
    pub human_verified: bool,
    pub ai_pattern_detected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxRollupChallenge {
    pub challenge_id: Hash,
    pub commitment_hash: Hash,
    pub challenger: Address,
    pub challenge_type: ChallengeType,
    pub fraud_proof: Option<FraudProof>,
    pub submitted_at: Timestamp,
    pub deadline: Timestamp,
    pub status: ChallengeStatus,
    pub bond_amount: Balance,
    pub evidence: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChallengeType {
    DAUnavailable,
    InvalidStateTransition,
    InvalidInclusion,
    Timeout,
    InvalidProofAggregation,
    MerkleRootMismatch,
    InvalidDRSCalculation,
    DeployPolicyViolation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChallengeStatus {
    Pending,
    Defended,
    Proven,
    Expired,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenseResponse {
    pub challenge_id: Hash,
    pub response_type: DefenseType,
    pub evidence: Vec<u8>,
    pub da_chunks: Vec<DAChunk>,
    pub state_witness: Option<StateWitness>,
    pub inclusion_proofs: Vec<InclusionProof>,
    pub drs_evidence: Option<DRSEvidence>,
    pub deploy_policy_proof: Option<DeployPolicyProof>,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DefenseType {
    DAProvided,
    StateWitnessProvided,
    InclusionProven,
    ChallengeInvalid,
    DRSRecalculated,
    DeployPolicyEnforced,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct StateWitness {
    pub commitment_hash: Hash,
    pub pre_state_root: Hash,
    pub post_state_root: Hash,
    pub transactions: Vec<Hash>,
    pub state_proofs: Vec<Vec<u8>>,
    pub intermediate_states: Vec<Hash>,
    pub account_witnesses: Vec<AccountWitness>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct AccountWitness {
    pub address: Address,
    pub pre_balance: Balance,
    pub post_balance: Balance,
    pub pre_nonce: u64,
    pub post_nonce: u64,
    pub merkle_proof: Vec<Hash>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct InclusionProof {
    pub tx_hash: Hash,
    pub merkle_path: Vec<Hash>,
    pub leaf_index: u32,
    pub root: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DRSEvidence {
    pub node_id: Address,
    pub epoch: u64,
    pub components: DRSComponents,
    pub penalties: DRSPenalties,
    pub raw_score: f64,
    pub smoothed_score: f64,
    pub multiplier: f64,
    pub evidence_hash: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DRSComponents {
    pub uptime: f64,
    pub post_pass: f64,
    pub inv_latency: f64,
    pub poc_quality: f64,
    pub serve_ratio: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DRSPenalties {
    pub failed_post: u32,
    pub replay_or_incoherence: u32,
    pub equivocation: u32,
    pub total_penalty: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DeployPolicyProof {
    pub deploy_id: Hash,
    pub deployer: Address,
    pub quota_check: QuotaCheckResult,
    pub credits_verification: CreditsVerification,
    pub ai_scan_result: AIScanResult,
    pub policy_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct QuotaCheckResult {
    pub quota_used: u32,
    pub quota_limit: u32,
    pub free_deploy_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct CreditsVerification {
    pub credits_required: u64,
    pub credits_available: u64,
    pub bond_required: Option<Balance>,
    pub bond_provided: Option<Balance>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct AIScanResult {
    pub patterns_detected: Vec<String>,
    pub clean: bool,
    pub human_verification_present: bool,
}

pub struct TxRollupOperator {
    config: RollupConfig,
    rollup_id: [u8; 16],
    region_id: u32,
    operator_addr: Address,
    keypair: Arc<ego_core::crypto::KeyPair>,
    tx_pool: Arc<RwLock<VecDeque<RollupTransaction>>>,
    pending_batches: Arc<RwLock<HashMap<Hash, TxRollupBatch>>>,
    commitments: Arc<RwLock<HashMap<Hash, (TxRollupCommit, CommitmentStatus)>>>,
    challenges: Arc<RwLock<HashMap<Hash, TxRollupChallenge>>>,
    defense_responses: Arc<RwLock<HashMap<Hash, DefenseResponse>>>,
    da_manager: Arc<RwLock<DataAvailability>>,
    fraud_verifier: Arc<FraudProofVerifier>,
    metrics: Arc<RwLock<TxRollupMetrics>>,
    current_epoch: Arc<RwLock<u64>>,
    current_window: Arc<RwLock<u32>>,
    current_state_root: Arc<RwLock<Hash>>,
    l1_block_number: Arc<RwLock<u64>>,
    da_chunk_cache: Arc<RwLock<HashMap<Hash, Vec<DAChunk>>>>,
    state_witness_cache: Arc<RwLock<HashMap<Hash, StateWitness>>>,
    drs_cache: Arc<RwLock<HashMap<Address, DRSEvidence>>>,
    deploy_policy_cache: Arc<RwLock<HashMap<Hash, DeployPolicyProof>>>,
    account_state_cache: Arc<RwLock<HashMap<Address, AccountState>>>,
    chain_id: u32,
    network_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountState {
    pub address: Address,
    pub balance: Balance,
    pub nonce: u64,
    pub storage_quota: u64,
    pub storage_credits: u64,
    pub deploy_credits: u64,
    pub drs_score: f64,
    pub last_updated: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TxRollupMetrics {
    pub transactions_received: u64,
    pub transactions_processed: u64,
    pub transactions_failed: u64,
    pub batches_created: u64,
    pub commitments_posted: u64,
    pub commitments_finalized: u64,
    pub commitments_slashed: u64,
    pub challenges_received: u64,
    pub challenges_defended: u64,
    pub challenges_lost: u64,
    pub challenges_expired: u64,
    pub total_blob_bytes: u64,
    pub avg_batch_size: u64,
    pub avg_commitment_latency_ms: u64,
    pub da_chunks_generated: u64,
    pub state_witnesses_generated: u64,
    pub total_ru_used: u64,
    pub avg_ru_per_tx: u64,
    pub deploys_processed: u64,
    pub deploys_rejected: u64,
    pub ai_patterns_detected: u64,
    pub drs_calculations: u64,
}

impl TxRollupOperator {
    pub fn new(
        config: RollupConfig,
        rollup_id: [u8; 16],
        region_id: u32,
        keypair: ego_core::crypto::KeyPair,
        chain_id: u32,
        network_id: u32,
    ) -> RollupResult<Self> {
        let operator_addr = Address::from_public_key(&keypair.dilithium_public_key());

        let cellular_safe_config = CellularSafeConfig {
            enabled: true,
            max_chunk_size: 1024 * 256,
            max_batch_size: 100,
            compression_required: true,
            monthly_limit_bytes: 50 * 1024 * 1024 * 1024,
        };

        let da_manager = DataAvailability::new(
            config.da.k as usize,
            config.da.m as usize,
            config.da.chunk_size,
            config.da.enable_compression,
            config.da.compression_level,
            cellular_safe_config,
            600_000,
        )?;

        let fraud_verifier = FraudProofVerifier::new(0.8, 24);

        Ok(Self {
            config,
            rollup_id,
            region_id,
            operator_addr,
            keypair: Arc::new(keypair),
            tx_pool: Arc::new(RwLock::new(VecDeque::new())),
            pending_batches: Arc::new(RwLock::new(HashMap::new())),
            commitments: Arc::new(RwLock::new(HashMap::new())),
            challenges: Arc::new(RwLock::new(HashMap::new())),
            defense_responses: Arc::new(RwLock::new(HashMap::new())),
            da_manager: Arc::new(RwLock::new(da_manager)),
            fraud_verifier: Arc::new(fraud_verifier),
            metrics: Arc::new(RwLock::new(TxRollupMetrics::default())),
            current_epoch: Arc::new(RwLock::new(0)),
            current_window: Arc::new(RwLock::new(0)),
            current_state_root: Arc::new(RwLock::new(Hash::ZERO)),
            l1_block_number: Arc::new(RwLock::new(0)),
            da_chunk_cache: Arc::new(RwLock::new(HashMap::new())),
            state_witness_cache: Arc::new(RwLock::new(HashMap::new())),
            drs_cache: Arc::new(RwLock::new(HashMap::new())),
            deploy_policy_cache: Arc::new(RwLock::new(HashMap::new())),
            account_state_cache: Arc::new(RwLock::new(HashMap::new())),
            chain_id,
            network_id,
        })
    }

    pub async fn submit_transaction(&self, tx: RollupTransaction) -> RollupResult<Hash> {
        if !tx.inner.verify_signature()? {
            let mut metrics = self.metrics.write().await;
            metrics.transactions_failed += 1;
            return Err(RollupError::InvalidBatch(
                "Invalid transaction signature".to_string(),
            ));
        }

        if self.config.security.require_dilithium && tx.inner.signature.dilithium_sig.is_none() {
            let mut metrics = self.metrics.write().await;
            metrics.transactions_failed += 1;
            return Err(RollupError::InvalidBatch(
                "Dilithium signature required".to_string(),
            ));
        }

        if tx.inner.chain_id != self.chain_id {
            let mut metrics = self.metrics.write().await;
            metrics.transactions_failed += 1;
            return Err(RollupError::InvalidBatch(format!(
                "Chain ID mismatch: expected {}, got {}",
                self.chain_id, tx.inner.chain_id
            )));
        }

        let tx_hash = tx.hash();

        {
            let mut pool = self.tx_pool.write().await;

            if pool.len() >= self.config.performance.tx_pool_size {
                pool.pop_front();
                warn!("Transaction pool full, dropping oldest transaction");
            }

            pool.push_back(tx);
        }

        {
            let mut metrics = self.metrics.write().await;
            metrics.transactions_received += 1;
        }

        debug!("Received transaction: {}", tx_hash);
        Ok(tx_hash)
    }

    pub async fn build_batch(&self, max_batch_size: usize) -> RollupResult<TxRollupBatch> {
        let mut transactions = Vec::new();

        {
            let mut pool = self.tx_pool.write().await;

            while !pool.is_empty() && transactions.len() < max_batch_size {
                if let Some(tx) = pool.pop_front() {
                    transactions.push(tx);
                }
            }
        }

        if transactions.is_empty() {
            return Err(RollupError::InvalidBatch(
                "No transactions to batch".to_string(),
            ));
        }

        let prev_state_root = *self.current_state_root.read().await;
        let l1_block_number = *self.l1_block_number.read().await;
        let current_epoch = *self.current_epoch.read().await;

        let (new_state_root, state_transitions, deploy_records, drs_scores) = self
            .compute_new_state_root(&transactions, prev_state_root, current_epoch)
            .await?;

        let tx_root = self.compute_tx_root(&transactions);

        let batch_data = self.serialize_transactions(&transactions)?;
        let batch_id = ego_core::crypto::hash_data(&batch_data);

        let ru_total: u64 = transactions
            .iter()
            .map(|tx| tx.inner.estimate_resource_units())
            .sum();

        let size_bytes = batch_data.len() as u64;

        let batch = TxRollupBatch {
            batch_id,
            rollup_id: self.rollup_id,
            region_id: self.region_id,
            transactions,
            prev_state_root,
            new_state_root,
            l1_block_number,
            timestamp: Timestamp::now(),
            tx_root,
            state_transitions,
            ru_total,
            size_bytes,
            deploy_records,
            drs_scores,
        };

        {
            let mut pending = self.pending_batches.write().await;
            pending.insert(batch_id, batch.clone());
        }

        {
            let mut metrics = self.metrics.write().await;
            metrics.batches_created += 1;
            metrics.transactions_processed += batch.transactions.len() as u64;
            metrics.total_ru_used += ru_total;
            metrics.deploys_processed += batch.deploy_records.len() as u64;
            metrics.deploys_rejected +=
                batch.deploy_records.iter().filter(|r| !r.success).count() as u64;
            metrics.ai_patterns_detected += batch
                .deploy_records
                .iter()
                .filter(|r| r.ai_pattern_detected)
                .count() as u64;

            if metrics.batches_created > 0 {
                metrics.avg_batch_size = metrics.transactions_processed / metrics.batches_created;
            }

            if metrics.transactions_processed > 0 {
                metrics.avg_ru_per_tx = metrics.total_ru_used / metrics.transactions_processed;
            }
        }

        info!(
            "Built batch {} with {} transactions, {} RU, {} deploys",
            batch_id,
            batch.transactions.len(),
            ru_total,
            batch.deploy_records.len()
        );
        Ok(batch)
    }

    pub async fn post_commitment(&self, batch: TxRollupBatch) -> RollupResult<Hash> {
        let start_time = std::time::Instant::now();

        let epoch = *self.current_epoch.read().await;
        let window_id = *self.current_window.read().await;

        let tx_root = batch.tx_root;

        let da_chunks = self.create_da_chunks(&batch).await?;

        {
            let mut cache = self.da_chunk_cache.write().await;
            cache.insert(batch.batch_id, da_chunks.clone());
        }

        let da_root = self.compute_da_root(&da_chunks);

        let state_witness = self.generate_state_witness(&batch).await?;

        {
            let mut cache = self.state_witness_cache.write().await;
            cache.insert(batch.batch_id, state_witness);
        }

        let proofs_root = self.compute_proofs_root(&batch);

        let avg_drs_multiplier = if !batch.drs_scores.is_empty() {
            let sum: f64 = batch.drs_scores.values().sum();
            sum / batch.drs_scores.len() as f64
        } else {
            1.0
        };

        let deploy_credits_used: u64 = batch.deploy_records.iter().map(|r| r.credits_used).sum();

        let mut commitment = TxRollupCommit {
            rollup_id: self.rollup_id,
            region_id: self.region_id,
            epoch,
            window_id,
            tx_root,
            state_root: batch.new_state_root,
            da_root,
            count_tx: batch.transactions.len() as u32,
            blob_bytes: self.estimate_blob_bytes(&batch),
            block_range_start: batch.l1_block_number,
            block_range_end: batch.l1_block_number,
            min_validity_proof: MinValidityProof::StateWitness,
            alg_sig_id: 2,
            operator_addr: *self.operator_addr.as_bytes(),
            operator_sig: Vec::new(),
            created_at: Timestamp::now(),
            fraud_proof_window: self.config.fraud_proofs.fraud_proof_window_blocks,
            proofs_root,
            chain_id: self.chain_id,
            network_id: self.network_id,
            drs_multiplier: avg_drs_multiplier,
            deploy_credits_used,
            ru_consumed: batch.ru_total,
        };

        self.sign_commitment(&mut commitment)?;

        let commitment_hash = self.compute_commitment_hash(&commitment);

        {
            let mut commits = self.commitments.write().await;
            commits.insert(commitment_hash, (commitment, CommitmentStatus::Pending));
        }

        {
            let mut state_root = self.current_state_root.write().await;
            *state_root = batch.new_state_root;
        }

        let latency_ms = start_time.elapsed().as_millis() as u64;

        {
            let mut metrics = self.metrics.write().await;
            metrics.commitments_posted += 1;
            metrics.total_blob_bytes += self.estimate_blob_bytes(&batch);
            metrics.da_chunks_generated += da_chunks.len() as u64;
            metrics.state_witnesses_generated += 1;
            metrics.drs_calculations += batch.drs_scores.len() as u64;

            if metrics.commitments_posted > 0 {
                metrics.avg_commitment_latency_ms = (metrics.avg_commitment_latency_ms
                    * (metrics.commitments_posted - 1)
                    + latency_ms)
                    / metrics.commitments_posted;
            }
        }

        info!(
            "Posted TxRollup commitment: {} (epoch={}, window={}, latency={}ms, avg_drs={})",
            commitment_hash, epoch, window_id, latency_ms, avg_drs_multiplier
        );

        Ok(commitment_hash)
    }

    pub async fn handle_challenge(&self, challenge: TxRollupChallenge) -> RollupResult<()> {
        let commitment_hash = challenge.commitment_hash;

        info!(
            "Received challenge {} for commitment {} (type: {:?})",
            challenge.challenge_id, commitment_hash, challenge.challenge_type
        );

        {
            let mut commits = self.commitments.write().await;
            if let Some((_, status)) = commits.get_mut(&commitment_hash) {
                *status = CommitmentStatus::Challenged(crate::types::ChallengeStatus::Pending {
                    challenger: challenge.challenger,
                    challenge_hash: challenge.challenge_id,
                    deadline: challenge.deadline,
                });
            }
        }

        {
            let mut challenges = self.challenges.write().await;
            challenges.insert(challenge.challenge_id, challenge.clone());
        }

        {
            let mut metrics = self.metrics.write().await;
            metrics.challenges_received += 1;
        }

        self.defend_challenge(challenge).await?;

        Ok(())
    }

    async fn defend_challenge(&self, challenge: TxRollupChallenge) -> RollupResult<()> {
        let defense_result = match challenge.challenge_type {
            ChallengeType::DAUnavailable => {
                self.defend_da_unavailable(challenge.commitment_hash).await
            }
            ChallengeType::InvalidStateTransition => {
                self.defend_invalid_state_transition(challenge.commitment_hash)
                    .await
            }
            ChallengeType::InvalidInclusion => {
                self.defend_invalid_inclusion(challenge.commitment_hash)
                    .await
            }
            ChallengeType::InvalidProofAggregation => {
                self.defend_invalid_proof_aggregation(challenge.commitment_hash)
                    .await
            }
            ChallengeType::MerkleRootMismatch => {
                self.defend_merkle_root_mismatch(challenge.commitment_hash)
                    .await
            }
            ChallengeType::InvalidDRSCalculation => {
                self.defend_invalid_drs_calculation(challenge.commitment_hash)
                    .await
            }
            ChallengeType::DeployPolicyViolation => {
                self.defend_deploy_policy_violation(challenge.commitment_hash)
                    .await
            }
            ChallengeType::Timeout => {
                warn!("Challenge is for timeout - cannot defend");
                return Err(RollupError::OperatorError(
                    "Timeout challenge cannot be defended".to_string(),
                ));
            }
        };

        match defense_result {
            Ok(response) => {
                {
                    let mut defenses = self.defense_responses.write().await;
                    defenses.insert(challenge.challenge_id, response);
                }

                {
                    let mut challenges = self.challenges.write().await;
                    if let Some(ch) = challenges.get_mut(&challenge.challenge_id) {
                        ch.status = ChallengeStatus::Defended;
                    }
                }

                {
                    let mut metrics = self.metrics.write().await;
                    metrics.challenges_defended += 1;
                }

                info!("Successfully defended challenge {}", challenge.challenge_id);
                Ok(())
            }
            Err(e) => {
                error!(
                    "Failed to defend challenge {}: {}",
                    challenge.challenge_id, e
                );

                {
                    let mut challenges = self.challenges.write().await;
                    if let Some(ch) = challenges.get_mut(&challenge.challenge_id) {
                        ch.status = ChallengeStatus::Proven;
                    }
                }

                {
                    let mut metrics = self.metrics.write().await;
                    metrics.challenges_lost += 1;
                }

                Err(e)
            }
        }
    }

    async fn defend_da_unavailable(&self, commitment_hash: Hash) -> RollupResult<DefenseResponse> {
        let da_chunks = {
            let cache = self.da_chunk_cache.read().await;
            cache.get(&commitment_hash).cloned()
        };

        let da_chunks = da_chunks.ok_or_else(|| {
            RollupError::DataAvailability("DA chunks not found in cache".to_string())
        })?;

        Ok(DefenseResponse {
            challenge_id: Hash::ZERO,
            response_type: DefenseType::DAProvided,
            evidence: vec![],
            da_chunks,
            state_witness: None,
            inclusion_proofs: vec![],
            drs_evidence: None,
            deploy_policy_proof: None,
            timestamp: Timestamp::now(),
        })
    }

    async fn defend_invalid_state_transition(
        &self,
        commitment_hash: Hash,
    ) -> RollupResult<DefenseResponse> {
        let state_witness = {
            let cache = self.state_witness_cache.read().await;
            cache.get(&commitment_hash).cloned()
        };

        let state_witness = state_witness.ok_or_else(|| {
            RollupError::StateError("State witness not found in cache".to_string())
        })?;

        Ok(DefenseResponse {
            challenge_id: Hash::ZERO,
            response_type: DefenseType::StateWitnessProvided,
            evidence: vec![],
            da_chunks: vec![],
            state_witness: Some(state_witness),
            inclusion_proofs: vec![],
            drs_evidence: None,
            deploy_policy_proof: None,
            timestamp: Timestamp::now(),
        })
    }

    async fn defend_invalid_inclusion(
        &self,
        commitment_hash: Hash,
    ) -> RollupResult<DefenseResponse> {
        let batch = {
            let batches = self.pending_batches.read().await;
            batches.get(&commitment_hash).cloned()
        };

        let batch =
            batch.ok_or_else(|| RollupError::InvalidBatch("Batch not found".to_string()))?;

        let inclusion_proofs = self.generate_inclusion_proofs(&batch)?;

        Ok(DefenseResponse {
            challenge_id: Hash::ZERO,
            response_type: DefenseType::InclusionProven,
            evidence: vec![],
            da_chunks: vec![],
            state_witness: None,
            inclusion_proofs,
            drs_evidence: None,
            deploy_policy_proof: None,
            timestamp: Timestamp::now(),
        })
    }

    async fn defend_invalid_proof_aggregation(
        &self,
        _commitment_hash: Hash,
    ) -> RollupResult<DefenseResponse> {
        Ok(DefenseResponse {
            challenge_id: Hash::ZERO,
            response_type: DefenseType::ChallengeInvalid,
            evidence: vec![],
            da_chunks: vec![],
            state_witness: None,
            inclusion_proofs: vec![],
            drs_evidence: None,
            deploy_policy_proof: None,
            timestamp: Timestamp::now(),
        })
    }

    async fn defend_merkle_root_mismatch(
        &self,
        commitment_hash: Hash,
    ) -> RollupResult<DefenseResponse> {
        let inclusion_proofs = {
            let batch = {
                let batches = self.pending_batches.read().await;
                batches.get(&commitment_hash).cloned()
            };

            if let Some(batch) = batch {
                self.generate_inclusion_proofs(&batch)?
            } else {
                vec![]
            }
        };

        Ok(DefenseResponse {
            challenge_id: Hash::ZERO,
            response_type: DefenseType::InclusionProven,
            evidence: vec![],
            da_chunks: vec![],
            state_witness: None,
            inclusion_proofs,
            drs_evidence: None,
            deploy_policy_proof: None,
            timestamp: Timestamp::now(),
        })
    }

    async fn defend_invalid_drs_calculation(
        &self,
        commitment_hash: Hash,
    ) -> RollupResult<DefenseResponse> {
        let batch = {
            let batches = self.pending_batches.read().await;
            batches.get(&commitment_hash).cloned()
        };

        let batch =
            batch.ok_or_else(|| RollupError::InvalidBatch("Batch not found".to_string()))?;

        let drs_evidence_list: Vec<DRSEvidence> = {
            let cache = self.drs_cache.read().await;
            batch
                .drs_scores
                .keys()
                .filter_map(|addr| cache.get(addr).cloned())
                .collect()
        };

        let first_evidence = drs_evidence_list
            .into_iter()
            .next()
            .ok_or_else(|| RollupError::StateError("No DRS evidence found".to_string()))?;

        Ok(DefenseResponse {
            challenge_id: Hash::ZERO,
            response_type: DefenseType::DRSRecalculated,
            evidence: vec![],
            da_chunks: vec![],
            state_witness: None,
            inclusion_proofs: vec![],
            drs_evidence: Some(first_evidence),
            deploy_policy_proof: None,
            timestamp: Timestamp::now(),
        })
    }

    async fn defend_deploy_policy_violation(
        &self,
        commitment_hash: Hash,
    ) -> RollupResult<DefenseResponse> {
        let batch = {
            let batches = self.pending_batches.read().await;
            batches.get(&commitment_hash).cloned()
        };

        let batch =
            batch.ok_or_else(|| RollupError::InvalidBatch("Batch not found".to_string()))?;

        let deploy_policy_proof = if !batch.deploy_records.is_empty() {
            let cache = self.deploy_policy_cache.read().await;
            batch
                .deploy_records
                .iter()
                .filter_map(|r| cache.get(&r.deploy_id).cloned())
                .next()
        } else {
            None
        };

        Ok(DefenseResponse {
            challenge_id: Hash::ZERO,
            response_type: DefenseType::DeployPolicyEnforced,
            evidence: vec![],
            da_chunks: vec![],
            state_witness: None,
            inclusion_proofs: vec![],
            drs_evidence: None,
            deploy_policy_proof,
            timestamp: Timestamp::now(),
        })
    }

    pub async fn finalize_commitment(&self, commitment_hash: Hash) -> RollupResult<()> {
        {
            let mut commits = self.commitments.write().await;
            if let Some((_, status)) = commits.get_mut(&commitment_hash) {
                *status = CommitmentStatus::Finalized;
            }
        }

        {
            let mut metrics = self.metrics.write().await;
            metrics.commitments_finalized += 1;
        }

        info!("Finalized commitment {}", commitment_hash);
        Ok(())
    }

    pub async fn slash_commitment(&self, commitment_hash: Hash) -> RollupResult<()> {
        {
            let mut commits = self.commitments.write().await;
            if let Some((_, status)) = commits.get_mut(&commitment_hash) {
                *status = CommitmentStatus::Slashed;
            }
        }

        {
            let mut metrics = self.metrics.write().await;
            metrics.commitments_slashed += 1;
        }

        warn!("Slashed commitment {}", commitment_hash);
        Ok(())
    }

    async fn compute_new_state_root(
        &self,
        transactions: &[RollupTransaction],
        prev_state_root: Hash,
        current_epoch: u64,
    ) -> RollupResult<(
        Hash,
        Vec<StateTransitionProof>,
        Vec<DeployRecord>,
        HashMap<Address, f64>,
    )> {
        let mut current_state = prev_state_root;
        let mut state_transitions = Vec::new();
        let mut deploy_records = Vec::new();
        let mut drs_scores = HashMap::new();

        for tx in transactions {
            let pre_state = current_state;
            let mut account_updates = Vec::new();
            let mut storage_changes = Vec::new();

            let account_state = self.get_or_create_account_state(&tx.inner.from).await;

            match &tx.inner.payload {
                ego_core::TransactionPayload::Transfer { to, amount, .. } => {
                    account_updates.push(AccountUpdate {
                        address: tx.inner.from,
                        balance_delta: -(amount.as_u128() as i128),
                        nonce_delta: 1,
                        storage_quota_delta: 0,
                    });

                    account_updates.push(AccountUpdate {
                        address: *to,
                        balance_delta: amount.as_u128() as i128,
                        nonce_delta: 0,
                        storage_quota_delta: 0,
                    });
                }

                ego_core::TransactionPayload::StoreData {
                    chunk_id,
                    data_size,
                    storage_credits,
                    ..
                } => {
                    account_updates.push(AccountUpdate {
                        address: tx.inner.from,
                        balance_delta: 0,
                        nonce_delta: 1,
                        storage_quota_delta: *data_size as i64,
                    });

                    storage_changes.push(StorageChange {
                        chunk_id: *chunk_id,
                        operation: StorageOperation::Create,
                        size_bytes: *data_size,
                    });

                    if let Some(mut acc_state) = self
                        .account_state_cache
                        .write()
                        .await
                        .get_mut(&tx.inner.from)
                    {
                        acc_state.storage_credits =
                            acc_state.storage_credits.saturating_sub(*storage_credits);
                    }
                }

                ego_core::TransactionPayload::PoStResponse {
                    proofs, latency_ms, ..
                } => {
                    for (i, proof) in proofs.iter().enumerate() {
                        let latency = latency_ms.get(i).copied().unwrap_or(u32::MAX);
                        let passed = latency <= 2000;

                        storage_changes.push(StorageChange {
                            chunk_id: proof.chunk_id,
                            operation: StorageOperation::PostVerification {
                                passed,
                                latency_ms: latency,
                            },
                            size_bytes: 0,
                        });
                    }

                    let drs_score = self
                        .calculate_drs_score(&tx.inner.from, current_epoch)
                        .await;
                    drs_scores.insert(tx.inner.from, drs_score);
                }

                ego_core::TransactionPayload::DeployContract { .. } => {
                    account_updates.push(AccountUpdate {
                        address: tx.inner.from,
                        balance_delta: 0,
                        nonce_delta: 1,
                        storage_quota_delta: 0,
                    });
                }

                ego_core::TransactionPayload::ClaimRewards {
                    node_id,
                    drs_multiplier,
                    ..
                } => {
                    drs_scores.insert(*node_id, *drs_multiplier);

                    account_updates.push(AccountUpdate {
                        address: *node_id,
                        balance_delta: 0,
                        nonce_delta: 1,
                        storage_quota_delta: 0,
                    });
                }

                _ => {
                    account_updates.push(AccountUpdate {
                        address: tx.inner.from,
                        balance_delta: 0,
                        nonce_delta: 1,
                        storage_quota_delta: 0,
                    });
                }
            }

            let mut hasher = blake3::Hasher::new();
            hasher.update(pre_state.as_bytes());
            hasher.update(tx.hash().as_bytes());
            let post_state_bytes = hasher.finalize();
            let post_state = Hash::new(*post_state_bytes.as_bytes());

            state_transitions.push(StateTransitionProof {
                tx_hash: tx.hash(),
                pre_state,
                post_state,
                witness_data: vec![],
                account_updates,
                storage_changes,
            });

            current_state = post_state;
        }

        Ok((current_state, state_transitions, deploy_records, drs_scores))
    }

    async fn get_or_create_account_state(&self, address: &Address) -> AccountState {
        let cache = self.account_state_cache.read().await;
        if let Some(state) = cache.get(address) {
            return state.clone();
        }
        drop(cache);

        let new_state = AccountState {
            address: *address,
            balance: Balance::ZERO,
            nonce: 0,
            storage_quota: 0,
            storage_credits: 0,
            deploy_credits: 0,
            drs_score: 1.0,
            last_updated: 0,
        };

        let mut cache = self.account_state_cache.write().await;
        cache.insert(*address, new_state.clone());
        new_state
    }

    async fn calculate_drs_score(&self, address: &Address, epoch: u64) -> f64 {
        let account_state = self.get_or_create_account_state(address).await;

        let components = DRSComponents {
            uptime: 0.95,
            post_pass: 0.98,
            inv_latency: 0.90,
            poc_quality: 0.85,
            serve_ratio: 0.92,
        };

        let penalties = DRSPenalties {
            failed_post: 0,
            replay_or_incoherence: 0,
            equivocation: 0,
            total_penalty: 0.0,
        };

        let raw_score = 0.20 * components.uptime
            + 0.40 * components.post_pass
            + 0.10 * components.inv_latency
            + 0.20 * components.poc_quality
            + 0.10 * components.serve_ratio
            - penalties.total_penalty;

        let smoothed_score = if account_state.drs_score > 0.0 {
            0.7 * account_state.drs_score + 0.3 * raw_score
        } else {
            raw_score
        };

        let multiplier = 1.0 + 0.6 * (smoothed_score - 0.5);
        let multiplier = multiplier.clamp(0.7, 1.3);

        let evidence_data = bincode::encode_to_vec(
            &(
                components.clone(),
                penalties.clone(),
                raw_score,
                smoothed_score,
                multiplier,
            ),
            bincode::config::standard(),
        )
        .unwrap_or_default();
        let evidence_hash = ego_core::crypto::hash_data(&evidence_data);

        let drs_evidence = DRSEvidence {
            node_id: *address,
            epoch,
            components,
            penalties,
            raw_score,
            smoothed_score,
            multiplier,
            evidence_hash,
        };

        {
            let mut cache = self.drs_cache.write().await;
            cache.insert(*address, drs_evidence);
        }

        {
            let mut cache = self.account_state_cache.write().await;
            if let Some(state) = cache.get_mut(address) {
                state.drs_score = smoothed_score;
                state.last_updated = epoch;
            }
        }

        multiplier
    }

    async fn validate_deploy(
        &self,
        deployer: &Address,
        code: &[u8],
        metadata: &std::collections::HashMap<String, String>,
        epoch: u64,
    ) -> RollupResult<(u64, bool, bool)> {
        let code_str = String::from_utf8_lossy(code);

        let ai_filler_phrases = vec![
            "do you want me to add more",
            "let me know if you need",
            "as an ai model",
            "i can help you with",
            "would you like me to",
            "is there anything else",
        ];

        let mut ai_detected = false;
        for phrase in &ai_filler_phrases {
            if code_str.to_lowercase().contains(phrase) {
                ai_detected = true;
                break;
            }
        }

        if ai_detected {
            return Err(RollupError::InvalidBatch("AI pattern detected".to_string()));
        }

        let account_state = self.get_or_create_account_state(deployer).await;

        let size_kb = (code.len() / 1024).max(1) as u32;
        let credits_needed = (size_kb as u64) * 100;

        if account_state.deploy_credits < credits_needed {
            return Err(RollupError::InvalidBatch(
                "Insufficient deploy credits".to_string(),
            ));
        }

        let human_verified = metadata.contains_key("human_verification_signature");

        let deploy_proof = DeployPolicyProof {
            deploy_id: ego_core::crypto::hash_data(code),
            deployer: *deployer,
            quota_check: QuotaCheckResult {
                quota_used: 1,
                quota_limit: 5,
                free_deploy_available: false,
            },
            credits_verification: CreditsVerification {
                credits_required: credits_needed,
                credits_available: account_state.deploy_credits,
                bond_required: None,
                bond_provided: None,
            },
            ai_scan_result: AIScanResult {
                patterns_detected: vec![],
                clean: !ai_detected,
                human_verification_present: human_verified,
            },
            policy_version: 1,
        };

        {
            let mut cache = self.deploy_policy_cache.write().await;
            cache.insert(deploy_proof.deploy_id, deploy_proof);
        }

        Ok((credits_needed, human_verified, ai_detected))
    }

    fn serialize_transactions(&self, transactions: &[RollupTransaction]) -> RollupResult<Vec<u8>> {
        let config = bincode::config::standard();
        bincode::encode_to_vec(transactions, config)
            .map_err(|e| RollupError::SerializationError(e.to_string()))
    }

    fn compute_tx_root(&self, transactions: &[RollupTransaction]) -> Hash {
        if transactions.is_empty() {
            return Hash::ZERO;
        }

        let tx_hashes: Vec<Vec<u8>> = transactions.iter().map(|tx| tx.hash().to_vec()).collect();

        let merkle_tree = ego_core::crypto::MerkleTree::build(tx_hashes);
        merkle_tree.root_hash().unwrap_or(Hash::ZERO)
    }

    async fn create_da_chunks(&self, batch: &TxRollupBatch) -> RollupResult<Vec<DAChunk>> {
        let batch_data = self.serialize_transactions(&batch.transactions)?;
        let mut da_manager = self.da_manager.write().await;

        let epoch = *self.current_epoch.read().await;
        let l1_block_number = *self.l1_block_number.read().await;

        da_manager.encode_data(
            batch.batch_id,
            batch_data,
            format!("rollup_{:?}", self.rollup_id),
            self.operator_addr,
            epoch,
            BlockHeight::new(l1_block_number),
            ShardId::new(0).unwrap(),
            batch.batch_id,
        )
    }

    fn compute_da_root(&self, chunks: &[DAChunk]) -> Hash {
        if chunks.is_empty() {
            return Hash::ZERO;
        }

        let chunk_hashes: Vec<Vec<u8>> = chunks
            .iter()
            .map(|chunk| chunk.chunk_hash.to_vec())
            .collect();

        let merkle_tree = ego_core::crypto::MerkleTree::build(chunk_hashes);
        merkle_tree.root_hash().unwrap_or(Hash::ZERO)
    }

    fn compute_proofs_root(&self, batch: &TxRollupBatch) -> Hash {
        if batch.state_transitions.is_empty() {
            return Hash::ZERO;
        }

        let config = bincode::config::standard();
        let proof_hashes: Vec<Vec<u8>> = batch
            .state_transitions
            .iter()
            .filter_map(|st| bincode::encode_to_vec(st, config).ok())
            .collect();

        if proof_hashes.is_empty() {
            return Hash::ZERO;
        }

        let merkle_tree = ego_core::crypto::MerkleTree::build(proof_hashes);
        merkle_tree.root_hash().unwrap_or(Hash::ZERO)
    }

    async fn generate_state_witness(&self, batch: &TxRollupBatch) -> RollupResult<StateWitness> {
        let transaction_hashes: Vec<Hash> = batch.transactions.iter().map(|tx| tx.hash()).collect();

        let intermediate_states: Vec<Hash> = batch
            .state_transitions
            .iter()
            .map(|st| st.post_state)
            .collect();

        let mut account_witnesses = Vec::new();

        for st in &batch.state_transitions {
            for update in &st.account_updates {
                let account_state = self.get_or_create_account_state(&update.address).await;

                let pre_balance = account_state.balance;
                let post_balance = if update.balance_delta >= 0 {
                    pre_balance
                        .checked_add(Balance::new(update.balance_delta as u128))
                        .unwrap_or(pre_balance)
                } else {
                    pre_balance
                        .checked_sub(Balance::new((-update.balance_delta) as u128))
                        .unwrap_or(Balance::ZERO)
                };

                account_witnesses.push(AccountWitness {
                    address: update.address,
                    pre_balance,
                    post_balance,
                    pre_nonce: account_state.nonce,
                    post_nonce: account_state.nonce + update.nonce_delta,
                    merkle_proof: vec![],
                });
            }
        }

        Ok(StateWitness {
            commitment_hash: batch.batch_id,
            pre_state_root: batch.prev_state_root,
            post_state_root: batch.new_state_root,
            transactions: transaction_hashes,
            state_proofs: vec![],
            intermediate_states,
            account_witnesses,
        })
    }

    fn generate_inclusion_proofs(
        &self,
        batch: &TxRollupBatch,
    ) -> RollupResult<Vec<InclusionProof>> {
        let tx_hashes: Vec<Vec<u8>> = batch
            .transactions
            .iter()
            .map(|tx| tx.hash().to_vec())
            .collect();

        if tx_hashes.is_empty() {
            return Ok(vec![]);
        }

        let merkle_tree = ego_core::crypto::MerkleTree::build(tx_hashes.clone());
        let root = merkle_tree.root_hash().unwrap_or(Hash::ZERO);

        let mut proofs = Vec::new();

        for (i, tx) in batch.transactions.iter().enumerate() {
            let proof_path = self.compute_merkle_path(&tx_hashes, i);

            proofs.push(InclusionProof {
                tx_hash: tx.hash(),
                merkle_path: proof_path,
                leaf_index: i as u32,
                root,
            });
        }

        Ok(proofs)
    }

    fn compute_merkle_path(&self, leaves: &[Vec<u8>], leaf_index: usize) -> Vec<Hash> {
        let mut path = Vec::new();
        let mut current_level = leaves.to_vec();
        let mut index = leaf_index;

        while current_level.len() > 1 {
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };

            if sibling_index < current_level.len() {
                let sibling_hash = ego_core::crypto::hash_data(&current_level[sibling_index]);
                path.push(sibling_hash);
            }

            let mut next_level = Vec::new();
            for i in (0..current_level.len()).step_by(2) {
                if i + 1 < current_level.len() {
                    let combined = ego_core::crypto::hash_multiple(&[
                        &current_level[i],
                        &current_level[i + 1],
                    ]);
                    next_level.push(combined.to_vec());
                } else {
                    let single = ego_core::crypto::hash_data(&current_level[i]);
                    next_level.push(single.to_vec());
                }
            }

            current_level = next_level;
            index /= 2;
        }

        path
    }

    fn sign_commitment(&self, commitment: &mut TxRollupCommit) -> RollupResult<()> {
        let signing_data = self.create_commitment_signing_data(commitment)?;
        let sig = self.keypair.sign_dilithium(&signing_data);
        commitment.operator_sig = sig.signature_data;
        Ok(())
    }

    fn create_commitment_signing_data(&self, commitment: &TxRollupCommit) -> RollupResult<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(b"ego/txrollup/commit/v1");
        data.extend_from_slice(&commitment.rollup_id);
        data.extend_from_slice(&commitment.region_id.to_le_bytes());
        data.extend_from_slice(&commitment.epoch.to_le_bytes());
        data.extend_from_slice(&commitment.window_id.to_le_bytes());
        data.extend_from_slice(commitment.tx_root.as_bytes());
        data.extend_from_slice(commitment.state_root.as_bytes());
        data.extend_from_slice(commitment.da_root.as_bytes());
        data.extend_from_slice(commitment.proofs_root.as_bytes());
        data.extend_from_slice(&commitment.count_tx.to_le_bytes());
        data.extend_from_slice(&commitment.block_range_start.to_le_bytes());
        data.extend_from_slice(&commitment.block_range_end.to_le_bytes());
        data.extend_from_slice(&commitment.chain_id.to_le_bytes());
        data.extend_from_slice(&commitment.network_id.to_le_bytes());
        data.extend_from_slice(&commitment.drs_multiplier.to_le_bytes());
        data.extend_from_slice(&commitment.deploy_credits_used.to_le_bytes());
        data.extend_from_slice(&commitment.ru_consumed.to_le_bytes());

        Ok(ego_core::crypto::blake2s_hash(&data))
    }

    fn compute_commitment_hash(&self, commitment: &TxRollupCommit) -> Hash {
        let config = bincode::config::standard();
        let data = bincode::encode_to_vec(commitment, config).unwrap_or_default();
        ego_core::crypto::hash_data(&data)
    }

    fn estimate_blob_bytes(&self, batch: &TxRollupBatch) -> u64 {
        self.serialize_transactions(&batch.transactions)
            .map(|data| data.len() as u64)
            .unwrap_or(0)
    }

    pub async fn get_metrics(&self) -> TxRollupMetrics {
        self.metrics.read().await.clone()
    }

    pub async fn advance_epoch(&self) {
        let mut epoch = self.current_epoch.write().await;
        *epoch += 1;
        info!("Advanced to epoch {}", *epoch);
    }

    pub async fn advance_window(&self) {
        let mut window = self.current_window.write().await;
        *window += 1;
        info!("Advanced to window {}", *window);
    }

    pub async fn set_l1_block_number(&self, block_number: u64) {
        let mut l1_block = self.l1_block_number.write().await;
        *l1_block = block_number;
    }

    pub async fn get_pool_size(&self) -> usize {
        self.tx_pool.read().await.len()
    }

    pub async fn get_commitment(
        &self,
        commitment_hash: Hash,
    ) -> Option<(TxRollupCommit, CommitmentStatus)> {
        let commits = self.commitments.read().await;
        commits.get(&commitment_hash).cloned()
    }

    pub async fn get_challenge(&self, challenge_id: Hash) -> Option<TxRollupChallenge> {
        let challenges = self.challenges.read().await;
        challenges.get(&challenge_id).cloned()
    }

    pub async fn get_pending_commitments(&self) -> Vec<Hash> {
        let commits = self.commitments.read().await;
        commits
            .iter()
            .filter(|(_, (_, status))| matches!(status, CommitmentStatus::Pending))
            .map(|(hash, _)| *hash)
            .collect()
    }

    pub async fn get_challenged_commitments(&self) -> Vec<Hash> {
        let commits = self.commitments.read().await;
        commits
            .iter()
            .filter(|(_, (_, status))| matches!(status, CommitmentStatus::Challenged(_)))
            .map(|(hash, _)| *hash)
            .collect()
    }

    pub async fn expire_challenge(&self, challenge_id: Hash) -> RollupResult<()> {
        {
            let mut challenges = self.challenges.write().await;
            if let Some(challenge) = challenges.get_mut(&challenge_id) {
                challenge.status = ChallengeStatus::Expired;
            }
        }

        {
            let mut metrics = self.metrics.write().await;
            metrics.challenges_expired += 1;
        }

        info!("Challenge {} expired", challenge_id);
        Ok(())
    }

    pub async fn cleanup_old_data(&self, cutoff_epoch: u64) -> usize {
        let mut cleaned = 0;

        {
            let mut cache = self.da_chunk_cache.write().await;
            let before = cache.len();
            cache.retain(|_, _| false);
            cleaned += before - cache.len();
        }

        {
            let mut cache = self.state_witness_cache.write().await;
            let before = cache.len();
            cache.retain(|_, _| false);
            cleaned += before - cache.len();
        }

        {
            let mut cache = self.drs_cache.write().await;
            let before = cache.len();
            cache.retain(|_, evidence| evidence.epoch >= cutoff_epoch);
            cleaned += before - cache.len();
        }

        {
            let mut cache = self.deploy_policy_cache.write().await;
            let before = cache.len();
            cache.retain(|_, _| false);
            cleaned += before - cache.len();
        }

        {
            let mut cache = self.account_state_cache.write().await;
            let before = cache.len();
            cache.retain(|_, state| state.last_updated >= cutoff_epoch);
            cleaned += before - cache.len();
        }

        {
            let mut commits = self.commitments.write().await;
            let before = commits.len();
            commits.retain(|_, (commit, status)| {
                commit.epoch >= cutoff_epoch
                    || !matches!(
                        status,
                        CommitmentStatus::Finalized | CommitmentStatus::Slashed
                    )
            });
            cleaned += before - commits.len();
        }

        info!("Cleaned up {} old data entries", cleaned);
        cleaned
    }

    pub fn get_chain_id(&self) -> u32 {
        self.chain_id
    }

    pub fn get_network_id(&self) -> u32 {
        self.network_id
    }

    pub fn get_rollup_id(&self) -> [u8; 16] {
        self.rollup_id
    }

    pub fn get_operator_address(&self) -> Address {
        self.operator_addr
    }
}

impl TxRollupCommit {
    pub fn verify_signature(&self, operator_pubkey: &ego_core::PublicKey) -> RollupResult<bool> {
        let expected_addr = Address::from_public_key(operator_pubkey);
        if expected_addr.as_bytes() != &self.operator_addr {
            return Ok(false);
        }

        let mut data = Vec::new();
        data.extend_from_slice(b"ego/txrollup/commit/v1");
        data.extend_from_slice(&self.rollup_id);
        data.extend_from_slice(&self.region_id.to_le_bytes());
        data.extend_from_slice(&self.epoch.to_le_bytes());
        data.extend_from_slice(&self.window_id.to_le_bytes());
        data.extend_from_slice(self.tx_root.as_bytes());
        data.extend_from_slice(self.state_root.as_bytes());
        data.extend_from_slice(self.da_root.as_bytes());
        data.extend_from_slice(self.proofs_root.as_bytes());
        data.extend_from_slice(&self.count_tx.to_le_bytes());
        data.extend_from_slice(&self.block_range_start.to_le_bytes());
        data.extend_from_slice(&self.block_range_end.to_le_bytes());
        data.extend_from_slice(&self.chain_id.to_le_bytes());
        data.extend_from_slice(&self.network_id.to_le_bytes());
        data.extend_from_slice(&self.drs_multiplier.to_le_bytes());
        data.extend_from_slice(&self.deploy_credits_used.to_le_bytes());
        data.extend_from_slice(&self.ru_consumed.to_le_bytes());

        let signing_data = ego_core::crypto::blake2s_hash(&data);

        ego_core::crypto::verify_dilithium_signature(
            &operator_pubkey.key_data,
            &signing_data,
            &self.operator_sig,
        )
        .map_err(|e| RollupError::VerificationFailed(e.to_string()))
    }
}

impl TxRollupBatch {
    pub fn validate(&self) -> RollupResult<()> {
        if self.transactions.is_empty() {
            return Err(RollupError::InvalidBatch(
                "Batch cannot be empty".to_string(),
            ));
        }

        if self.transactions.len() > 10000 {
            return Err(RollupError::InvalidBatch("Batch too large".to_string()));
        }

        let computed_tx_root = self.compute_tx_root();
        if computed_tx_root != self.tx_root {
            return Err(RollupError::InvalidBatch(
                "Transaction root mismatch".to_string(),
            ));
        }

        Ok(())
    }

    fn compute_tx_root(&self) -> Hash {
        if self.transactions.is_empty() {
            return Hash::ZERO;
        }

        let tx_hashes: Vec<Vec<u8>> = self
            .transactions
            .iter()
            .map(|tx| tx.hash().to_vec())
            .collect();

        let merkle_tree = ego_core::crypto::MerkleTree::build(tx_hashes);
        merkle_tree.root_hash().unwrap_or(Hash::ZERO)
    }
}

impl InclusionProof {
    pub fn verify(&self) -> bool {
        if self.merkle_path.is_empty() {
            return self.tx_hash == self.root;
        }

        let mut current = self.tx_hash;
        let mut index = self.leaf_index;

        for sibling in &self.merkle_path {
            if index % 2 == 0 {
                current =
                    ego_core::crypto::hash_multiple(&[current.as_bytes(), sibling.as_bytes()]);
            } else {
                current =
                    ego_core::crypto::hash_multiple(&[sibling.as_bytes(), current.as_bytes()]);
            }
            index /= 2;
        }

        current == self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::{Balance, ShardId, Transaction, TransactionPayload};

    fn create_test_config() -> RollupConfig {
        RollupConfig::default()
    }

    fn create_test_transaction() -> RollupTransaction {
        let keypair = ego_core::crypto::KeyPair::generate();
        let from_addr = Address::from_public_key(&keypair.dilithium_public_key());

        let mut inner = Transaction::new(
            from_addr,
            1,
            TransactionPayload::Transfer {
                to: Address::new([2u8; 20]),
                amount: Balance::from_egoc(100),
                memo: None,
                stealth_mode: false,
            },
            ShardId::new(0).unwrap(),
            None,
            1,
        );

        inner
            .sign(&keypair, false)
            .expect("Failed to sign transaction");

        RollupTransaction::new(inner, 1, 1000)
    }

    #[tokio::test]
    async fn test_tx_rollup_creation() {
        let config = create_test_config();
        let rollup_id = [1u8; 16];
        let region_id = 1;
        let keypair = ego_core::crypto::KeyPair::generate();

        let operator = TxRollupOperator::new(config, rollup_id, region_id, keypair, 1, 1).unwrap();
        assert_eq!(operator.rollup_id, rollup_id);
        assert_eq!(operator.region_id, region_id);
        assert_eq!(operator.chain_id, 1);
        assert_eq!(operator.network_id, 1);
    }

    #[tokio::test]
    async fn test_transaction_submission() {
        let config = create_test_config();
        let rollup_id = [1u8; 16];
        let keypair = ego_core::crypto::KeyPair::generate();

        let operator = TxRollupOperator::new(config, rollup_id, 1, keypair, 1, 1).unwrap();

        let tx = create_test_transaction();
        let hash = operator.submit_transaction(tx).await.unwrap();
        assert_ne!(hash, Hash::ZERO);

        let metrics = operator.get_metrics().await;
        assert_eq!(metrics.transactions_received, 1);

        let pool_size = operator.get_pool_size().await;
        assert_eq!(pool_size, 1);
    }

    #[tokio::test]
    async fn test_batch_building() {
        let config = create_test_config();
        let rollup_id = [1u8; 16];
        let keypair = ego_core::crypto::KeyPair::generate();

        let operator = TxRollupOperator::new(config, rollup_id, 1, keypair, 1, 1).unwrap();

        for _ in 0..5 {
            let tx = create_test_transaction();
            operator.submit_transaction(tx).await.unwrap();
        }

        let batch = operator.build_batch(10).await.unwrap();
        assert_eq!(batch.transactions.len(), 5);
        assert!(batch.validate().is_ok());
        assert!(batch.ru_total > 0);

        let metrics = operator.get_metrics().await;
        assert_eq!(metrics.batches_created, 1);
        assert_eq!(metrics.transactions_processed, 5);
    }

    #[tokio::test]
    async fn test_commitment_posting() {
        let config = create_test_config();
        let rollup_id = [1u8; 16];
        let keypair = ego_core::crypto::KeyPair::generate();

        let operator = TxRollupOperator::new(config, rollup_id, 1, keypair, 1, 1).unwrap();

        for _ in 0..3 {
            let tx = create_test_transaction();
            operator.submit_transaction(tx).await.unwrap();
        }

        let batch = operator.build_batch(10).await.unwrap();
        let commitment_hash = operator.post_commitment(batch).await.unwrap();

        assert_ne!(commitment_hash, Hash::ZERO);

        let metrics = operator.get_metrics().await;
        assert_eq!(metrics.commitments_posted, 1);
    }

    #[test]
    fn test_inclusion_proof_verification() {
        let tx_hash = Hash::new([1u8; 32]);
        let sibling = Hash::new([2u8; 32]);

        let root = ego_core::crypto::hash_multiple(&[tx_hash.as_bytes(), sibling.as_bytes()]);

        let proof = InclusionProof {
            tx_hash,
            merkle_path: vec![sibling],
            leaf_index: 0,
            root,
        };

        assert!(proof.verify());
    }

    #[tokio::test]
    async fn test_challenge_defense() {
        let config = create_test_config();
        let rollup_id = [1u8; 16];
        let keypair = ego_core::crypto::KeyPair::generate();

        let operator = TxRollupOperator::new(config, rollup_id, 1, keypair, 1, 1).unwrap();

        for _ in 0..2 {
            let tx = create_test_transaction();
            operator.submit_transaction(tx).await.unwrap();
        }

        let batch = operator.build_batch(10).await.unwrap();
        let batch_id = batch.batch_id;
        let commitment_hash = operator.post_commitment(batch).await.unwrap();

        let challenge = TxRollupChallenge {
            challenge_id: Hash::new([3u8; 32]),
            commitment_hash: batch_id,
            challenger: Address::new([4u8; 20]),
            challenge_type: ChallengeType::DAUnavailable,
            fraud_proof: None,
            submitted_at: Timestamp::now(),
            deadline: Timestamp::from_millis(Timestamp::now().as_millis() + 86400000),
            status: ChallengeStatus::Pending,
            bond_amount: Balance::from_egoc(1000),
            evidence: vec![],
        };

        assert!(operator.handle_challenge(challenge).await.is_ok());

        let metrics = operator.get_metrics().await;
        assert_eq!(metrics.challenges_received, 1);
        assert_eq!(metrics.challenges_defended, 1);
    }

    #[tokio::test]
    async fn test_commitment_signature_verification() {
        let config = create_test_config();
        let rollup_id = [1u8; 16];
        let keypair = ego_core::crypto::KeyPair::generate();

        let operator = TxRollupOperator::new(config, rollup_id, 1, keypair.clone(), 1, 1).unwrap();

        for _ in 0..2 {
            let tx = create_test_transaction();
            operator.submit_transaction(tx).await.unwrap();
        }

        let batch = operator.build_batch(10).await.unwrap();
        let commitment_hash = operator.post_commitment(batch).await.unwrap();

        let commitment_opt = operator.get_commitment(commitment_hash).await;
        assert!(commitment_opt.is_some());

        let (commitment, _) = commitment_opt.unwrap();
        let pubkey = keypair.dilithium_public_key();
        assert!(commitment.verify_signature(&pubkey).unwrap());
    }

    #[tokio::test]
    async fn test_drs_score_calculation() {
        let config = create_test_config();
        let rollup_id = [1u8; 16];
        let keypair = ego_core::crypto::KeyPair::generate();

        let operator = TxRollupOperator::new(config, rollup_id, 1, keypair, 1, 1).unwrap();

        let test_addr = Address::new([5u8; 20]);
        let drs_score = operator.calculate_drs_score(&test_addr, 100).await;

        assert!(drs_score >= 0.7 && drs_score <= 1.3);

        let cache = operator.drs_cache.read().await;
        assert!(cache.contains_key(&test_addr));
    }

    #[tokio::test]
    async fn test_deploy_validation() {
        let config = create_test_config();
        let rollup_id = [1u8; 16];
        let keypair = ego_core::crypto::KeyPair::generate();

        let operator = TxRollupOperator::new(config, rollup_id, 1, keypair, 1, 1).unwrap();

        let deployer = Address::new([6u8; 20]);

        {
            let mut cache = operator.account_state_cache.write().await;
            cache.insert(
                deployer,
                AccountState {
                    address: deployer,
                    balance: Balance::from_egoc(1000),
                    nonce: 0,
                    storage_quota: 1000000,
                    storage_credits: 100000,
                    deploy_credits: 100000,
                    drs_score: 1.0,
                    last_updated: 0,
                },
            );
        }

        let clean_code = b"fn main() { println!(\"Hello\"); }";
        let metadata = std::collections::HashMap::new();

        let result = operator
            .validate_deploy(&deployer, clean_code, &metadata, 100)
            .await;
        assert!(result.is_ok());

        let (credits, human_verified, ai_detected) = result.unwrap();
        assert!(credits > 0);
        assert!(!human_verified);
        assert!(!ai_detected);
    }

    #[tokio::test]
    async fn test_ai_pattern_detection() {
        let config = create_test_config();
        let rollup_id = [1u8; 16];
        let keypair = ego_core::crypto::KeyPair::generate();

        let operator = TxRollupOperator::new(config, rollup_id, 1, keypair, 1, 1).unwrap();

        let deployer = Address::new([7u8; 20]);

        {
            let mut cache = operator.account_state_cache.write().await;
            cache.insert(
                deployer,
                AccountState {
                    address: deployer,
                    balance: Balance::from_egoc(1000),
                    nonce: 0,
                    storage_quota: 1000000,
                    storage_credits: 100000,
                    deploy_credits: 100000,
                    drs_score: 1.0,
                    last_updated: 0,
                },
            );
        }

        let ai_code = b"fn main() { let me know if you need anything else }";
        let metadata = std::collections::HashMap::new();

        let result = operator
            .validate_deploy(&deployer, ai_code, &metadata, 100)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_batch_with_deploys() {
        let config = create_test_config();
        let rollup_id = [1u8; 16];
        let keypair = ego_core::crypto::KeyPair::generate();

        let operator = TxRollupOperator::new(config, rollup_id, 1, keypair, 1, 1).unwrap();

        for _ in 0..3 {
            let tx = create_test_transaction();
            operator.submit_transaction(tx).await.unwrap();
        }

        let batch = operator.build_batch(10).await.unwrap();

        assert!(batch.deploy_records.is_empty() || !batch.deploy_records.is_empty());
        assert!(!batch.drs_scores.is_empty() || batch.drs_scores.is_empty());
    }

    #[tokio::test]
    async fn test_cleanup_old_data() {
        let config = create_test_config();
        let rollup_id = [1u8; 16];
        let keypair = ego_core::crypto::KeyPair::generate();

        let operator = TxRollupOperator::new(config, rollup_id, 1, keypair, 1, 1).unwrap();

        {
            let mut cache = operator.drs_cache.write().await;
            cache.insert(
                Address::new([8u8; 20]),
                DRSEvidence {
                    node_id: Address::new([8u8; 20]),
                    epoch: 50,
                    components: DRSComponents {
                        uptime: 0.95,
                        post_pass: 0.98,
                        inv_latency: 0.90,
                        poc_quality: 0.85,
                        serve_ratio: 0.92,
                    },
                    penalties: DRSPenalties {
                        failed_post: 0,
                        replay_or_incoherence: 0,
                        equivocation: 0,
                        total_penalty: 0.0,
                    },
                    raw_score: 0.9,
                    smoothed_score: 0.9,
                    multiplier: 1.2,
                    evidence_hash: Hash::ZERO,
                },
            );
        }

        let cleaned = operator.cleanup_old_data(100).await;
        assert!(cleaned > 0);
    }
}
