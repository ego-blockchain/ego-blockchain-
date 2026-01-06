use crate::{RollupConfig, RollupOperator};
use dashmap::DashMap;
use ego_core::StorageDataType;
use ego_core::deploy_policy::{DeployRecord, DeployRequest, DeployType};
use ego_core::{
    Address, Balance, BlockHeight, DRSManager, DRSScore, DeployPolicyManager, Hash, ShardId,
    ShardManager, Timestamp, Transaction, TransactionPayload,
};
use ego_core::{EgoError, EgoResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

pub const MAX_BATCH_SIZE: usize = 10_000;
pub const MAX_BATCH_SIZE_BYTES: usize = 10 * 1024 * 1024;
pub const BATCH_TIMEOUT_MS: u64 = 5000;
pub const MAX_PROOF_SIZE_BYTES: usize = 1024 * 1024;
pub const DA_CHUNK_SIZE: usize = 256 * 1024;
pub const AGGREGATION_WINDOW_BLOCKS: u64 = 100;

#[derive(Debug, Clone)]
pub struct BatchManager {
    config: Arc<RwLock<BatchConfig>>,
    pending_batches: Arc<DashMap<Hash, PendingBatch>>,
    committed_batches: Arc<DashMap<Hash, CommittedBatch>>,
    finalized_batches: Arc<DashMap<Hash, FinalizedBatch>>,
    batch_queue: Arc<Mutex<VecDeque<BatchMetadata>>>,
    proof_aggregator: Arc<Mutex<ProofAggregator>>,
    da_manager: Arc<DaManager>,
    stats: Arc<Mutex<BatchStats>>,
    operator_registry: Arc<DashMap<Address, OperatorInfo>>,
    epoch_tracker: Arc<Mutex<EpochTracker>>,
    drs_manager: Arc<DRSManager>,
    deploy_policy: Arc<DeployPolicyManager>,
    shard_managers: Arc<DashMap<ShardId, Arc<ShardManager>>>,
    state_snapshots: Arc<DashMap<u64, StateSnapshotRef>>,
    cross_batch_receipts: Arc<DashMap<Hash, CrossBatchReceipt>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchConfig {
    pub max_batch_size: usize,
    pub max_batch_size_bytes: usize,
    pub batch_timeout_ms: u64,
    pub min_transactions_per_batch: usize,
    pub proof_verification_enabled: bool,
    pub da_enabled: bool,
    pub aggregation_enabled: bool,
    pub aggregation_window_blocks: u64,
    pub challenge_window_blocks: u64,
    pub operator_bond_required: Balance,
    pub slashing_enabled: bool,
    pub drs_integration_enabled: bool,
    pub deploy_policy_enforcement: bool,
    pub cross_shard_batch_enabled: bool,
    pub state_snapshot_interval: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PendingBatch {
    pub batch_id: Hash,
    pub operator: Address,
    pub shard_id: ShardId,
    pub transactions: Vec<Transaction>,
    pub tx_root: Hash,
    pub state_root_pre: Hash,
    pub state_root_post: Hash,
    pub created_at: Timestamp,
    pub batch_size_bytes: usize,
    pub status: BatchStatus,
    pub epoch: u64,
    pub ru_consumed: u64,
    pub storage_used: u64,
    pub deploy_records: Vec<Hash>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct CommittedBatch {
    pub batch_id: Hash,
    pub operator: Address,
    pub shard_id: ShardId,
    pub tx_root: Hash,
    pub state_root_pre: Hash,
    pub state_root_post: Hash,
    pub receipts_root: Hash,
    pub events_root_post: Hash,
    pub events_root_poc: Hash,
    pub proofs_root: Hash,
    pub da_root: Hash,
    pub proof: Option<BatchProof>,
    pub da_commitment: Option<DaCommitment>,
    pub committed_at: Timestamp,
    pub committed_block: BlockHeight,
    pub epoch: u64,
    pub challenge_deadline: BlockHeight,
    pub operator_signature: Vec<u8>,
    pub aggregated: bool,
    pub drs_scores_included: Vec<Hash>,
    pub deploy_events: Vec<Hash>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct FinalizedBatch {
    pub batch_id: Hash,
    pub operator: Address,
    pub shard_id: ShardId,
    pub tx_root: Hash,
    pub state_root_post: Hash,
    pub committed_block: BlockHeight,
    pub finalized_block: BlockHeight,
    pub finalized_at: Timestamp,
    pub epoch: u64,
    pub challenge_period_passed: bool,
    pub dispute_count: u32,
    pub all_disputes_resolved: bool,
    pub operator_reward: Balance,
    pub drs_multiplier_applied: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum BatchStatus {
    Building,
    Ready,
    Submitted,
    Committed,
    Challenged,
    Finalized,
    Rejected { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct BatchMetadata {
    pub batch_id: Hash,
    pub operator: Address,
    pub shard_id: ShardId,
    pub tx_count: u32,
    pub size_bytes: usize,
    pub created_at: Timestamp,
    pub epoch: u64,
    pub priority: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct BatchProof {
    pub proof_type: ProofType,
    pub proof_data: Vec<u8>,
    pub public_inputs: Vec<Hash>,
    pub verification_key_hash: Hash,
    pub proof_size_bytes: usize,
    pub generated_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum ProofType {
    Snark,
    Stark,
    Groth16,
    Plonk,
    Halo2,
    Aggregated { sub_proofs: Vec<Hash> },
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DaCommitment {
    pub da_root: Hash,
    pub chunk_count: u32,
    pub total_size_bytes: usize,
    pub erasure_coding_params: ErasureCodingParams,
    pub chunk_hashes: Vec<Hash>,
    pub blob_pointer: Option<String>,
    pub uploaded_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ErasureCodingParams {
    pub k: u16,
    pub m: u16,
    pub codec: String,
    pub chunk_size: usize,
}

#[derive(Debug)]
struct ProofAggregator {
    pending_proofs: HashMap<ShardId, Vec<BatchProof>>,
    aggregation_window_start: BlockHeight,
    aggregation_count: u64,
}

#[derive(Debug)]
struct DaManager {
    chunks: Arc<DashMap<Hash, DaChunk>>,
    commitments: Arc<DashMap<Hash, DaCommitment>>,
    retrieval_stats: Arc<Mutex<DaRetrievalStats>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaChunk {
    pub chunk_id: Hash,
    pub batch_id: Hash,
    pub chunk_index: u32,
    pub data: Vec<u8>,
    pub parity: bool,
    pub uploaded_at: Timestamp,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DaRetrievalStats {
    pub total_chunks_uploaded: u64,
    pub total_chunks_retrieved: u64,
    pub failed_retrievals: u64,
    pub avg_retrieval_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorInfo {
    pub operator: Address,
    pub shard_id: ShardId,
    pub bond_amount: Balance,
    pub batches_committed: u64,
    pub batches_finalized: u64,
    pub batches_challenged: u64,
    pub total_slashed: Balance,
    pub reputation_score: f64,
    pub drs_score: f64,
    pub drs_multiplier: f64,
    pub last_batch_epoch: u64,
    pub registered_at: Timestamp,
    pub status: OperatorStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperatorStatus {
    Active,
    Bonded,
    Slashed,
    Jailed { release_epoch: u64 },
    Inactive,
}

#[derive(Debug)]
struct EpochTracker {
    current_epoch: u64,
    epoch_batches: HashMap<u64, Vec<Hash>>,
    epoch_stats: HashMap<u64, EpochBatchStats>,
    epoch_drs_scores: HashMap<u64, HashMap<Address, DRSScore>>,
    epoch_deploy_stats: HashMap<u64, DeployStatsSnapshot>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EpochBatchStats {
    pub epoch: u64,
    pub total_batches: u64,
    pub total_transactions: u64,
    pub total_ru_consumed: u64,
    pub total_storage_used: u64,
    pub operators_active: HashSet<Address>,
    pub avg_batch_size: f64,
    pub finalized_batches: u64,
    pub challenged_batches: u64,
    pub failed_batches: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeployStatsSnapshot {
    pub epoch: u64,
    pub total_deploys: u32,
    pub successful_deploys: u32,
    pub failed_deploys: u32,
    pub human_verified_deploys: u32,
    pub ai_flagged_deploys: u32,
    pub total_credits_consumed: u64,
    pub total_pob_burned: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshotRef {
    pub epoch: u64,
    pub block_height: BlockHeight,
    pub shard_id: ShardId,
    pub state_root: Hash,
    pub snapshot_hash: Hash,
    pub created_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct CrossBatchReceipt {
    pub receipt_id: Hash,
    pub src_batch_id: Hash,
    pub dst_batch_id: Option<Hash>,
    pub src_shard: ShardId,
    pub dst_shard: ShardId,
    pub payload: Vec<u8>,
    pub nonce: u64,
    pub created_at: Timestamp,
    pub status: CrossBatchStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum CrossBatchStatus {
    Pending,
    Transmitted,
    Acknowledged,
    Applied,
    Failed { reason: String },
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BatchStats {
    pub total_batches_created: u64,
    pub total_batches_committed: u64,
    pub total_batches_finalized: u64,
    pub total_batches_rejected: u64,
    pub total_transactions_processed: u64,
    pub total_proofs_verified: u64,
    pub total_proofs_aggregated: u64,
    pub total_da_chunks_uploaded: u64,
    pub avg_batch_size: f64,
    pub avg_batch_time_ms: u64,
    pub avg_proof_size_bytes: f64,
    pub last_updated: Timestamp,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_batch_size: MAX_BATCH_SIZE,
            max_batch_size_bytes: MAX_BATCH_SIZE_BYTES,
            batch_timeout_ms: BATCH_TIMEOUT_MS,
            min_transactions_per_batch: 10,
            proof_verification_enabled: true,
            da_enabled: true,
            aggregation_enabled: true,
            aggregation_window_blocks: AGGREGATION_WINDOW_BLOCKS,
            challenge_window_blocks: 100,
            operator_bond_required: Balance::from_egoc(10000),
            slashing_enabled: true,
            drs_integration_enabled: true,
            deploy_policy_enforcement: true,
            cross_shard_batch_enabled: true,
            state_snapshot_interval: 1000,
        }
    }
}

impl BatchManager {
    pub async fn set_batch_ready(&self, batch_id: &Hash, state_root_post: Hash) -> EgoResult<()> {
        let mut batch = self
            .pending_batches
            .get_mut(batch_id)
            .ok_or(EgoError::InvalidTransaction("Batch not found".to_string()))?;
        if batch.status != BatchStatus::Building {
            return Err(EgoError::InvalidTransaction(
                "Batch is not in Building state".to_string(),
            ));
        }
        batch.state_root_post = state_root_post;
        batch.status = BatchStatus::Ready;
        Ok(())
    }

    pub fn new(
        config: BatchConfig,
        drs_manager: Arc<DRSManager>,
        deploy_policy: Arc<DeployPolicyManager>,
    ) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            pending_batches: Arc::new(DashMap::new()),
            committed_batches: Arc::new(DashMap::new()),
            finalized_batches: Arc::new(DashMap::new()),
            batch_queue: Arc::new(Mutex::new(VecDeque::new())),
            proof_aggregator: Arc::new(Mutex::new(ProofAggregator {
                pending_proofs: HashMap::new(),
                aggregation_window_start: BlockHeight::GENESIS,
                aggregation_count: 0,
            })),
            da_manager: Arc::new(DaManager {
                chunks: Arc::new(DashMap::new()),
                commitments: Arc::new(DashMap::new()),
                retrieval_stats: Arc::new(Mutex::new(DaRetrievalStats::default())),
            }),
            stats: Arc::new(Mutex::new(BatchStats::default())),
            operator_registry: Arc::new(DashMap::new()),
            epoch_tracker: Arc::new(Mutex::new(EpochTracker {
                current_epoch: 0,
                epoch_batches: HashMap::new(),
                epoch_stats: HashMap::new(),
                epoch_drs_scores: HashMap::new(),
                epoch_deploy_stats: HashMap::new(),
            })),
            drs_manager,
            deploy_policy,
            shard_managers: Arc::new(DashMap::new()),
            state_snapshots: Arc::new(DashMap::new()),
            cross_batch_receipts: Arc::new(DashMap::new()),
        }
    }

    pub async fn register_shard_manager(
        &self,
        shard_id: ShardId,
        manager: Arc<ShardManager>,
    ) -> EgoResult<()> {
        self.shard_managers.insert(shard_id, manager);
        Ok(())
    }

    pub async fn register_operator(
        &self,
        operator: Address,
        shard_id: ShardId,
        bond_amount: Balance,
    ) -> EgoResult<()> {
        let config = self.config.read().await;
        if bond_amount < config.operator_bond_required {
            return Err(EgoError::InvalidTransaction(format!(
                "Bond amount {} is less than required {}",
                bond_amount, config.operator_bond_required
            )));
        }
        drop(config);

        let drs_score = self.drs_manager.get_node_score(&operator);
        let (drs_score_val, drs_multiplier) = if let Some(score) = drs_score {
            (score.score_smoothed, score.multiplier)
        } else {
            (1.0, 1.0)
        };

        let info = OperatorInfo {
            operator,
            shard_id,
            bond_amount,
            batches_committed: 0,
            batches_finalized: 0,
            batches_challenged: 0,
            total_slashed: Balance::ZERO,
            reputation_score: 100.0,
            drs_score: drs_score_val,
            drs_multiplier,
            last_batch_epoch: 0,
            registered_at: Timestamp::now(),
            status: OperatorStatus::Bonded,
        };

        self.operator_registry.insert(operator, info);
        Ok(())
    }

    pub async fn create_batch(
        &self,
        operator: Address,
        shard_id: ShardId,
        transactions: Vec<Transaction>,
        state_root_pre: Hash,
        epoch: u64,
    ) -> EgoResult<Hash> {
        if !self.operator_registry.contains_key(&operator) {
            return Err(EgoError::InvalidTransaction(
                "Operator not registered".to_string(),
            ));
        }

        let config = self.config.read().await;
        if transactions.len() > config.max_batch_size {
            return Err(EgoError::InvalidTransaction(format!(
                "Batch size {} exceeds maximum {}",
                transactions.len(),
                config.max_batch_size
            )));
        }

        let mut batch_size_bytes = 0;
        for tx in &transactions {
            batch_size_bytes += std::mem::size_of_val(tx);
        }

        if batch_size_bytes > config.max_batch_size_bytes {
            return Err(EgoError::InvalidTransaction(format!(
                "Batch size {} bytes exceeds maximum {} bytes",
                batch_size_bytes, config.max_batch_size_bytes
            )));
        }

        let deploy_policy_enabled = config.deploy_policy_enforcement;
        drop(config);

        let mut deploy_records = Vec::new();
        let mut total_ru = 0u64;
        let mut total_storage = 0u64;

        if deploy_policy_enabled {
            for tx in &transactions {
                if matches!(&tx.payload, TransactionPayload::DeployContract { .. }) {
                    let deploy_id = tx.hash;
                    if let Some(record) = self.deploy_policy.get_deploy_record(&deploy_id) {
                        deploy_records.push(deploy_id);
                        total_ru += record.ru_consumed;
                        total_storage += record.size_kb as u64;
                    }
                }
            }
        }

        let tx_hashes: Vec<Hash> = transactions.iter().map(|tx| tx.hash).collect();
        let tx_root = self.compute_merkle_root(&tx_hashes);

        let batch_id = self.compute_batch_id(&operator, &shard_id, &tx_root, epoch);

        let batch = PendingBatch {
            batch_id,
            operator,
            shard_id,
            transactions,
            tx_root,
            state_root_pre,
            state_root_post: Hash::ZERO,
            created_at: Timestamp::now(),
            batch_size_bytes,
            status: BatchStatus::Building,
            epoch,
            ru_consumed: total_ru,
            storage_used: total_storage,
            deploy_records,
        };

        self.pending_batches.insert(batch_id, batch);

        let metadata = BatchMetadata {
            batch_id,
            operator,
            shard_id,
            tx_count: tx_hashes.len() as u32,
            size_bytes: batch_size_bytes,
            created_at: Timestamp::now(),
            epoch,
            priority: 128,
        };

        self.batch_queue.lock().await.push_back(metadata);

        let mut stats = self.stats.lock().await;
        stats.total_batches_created += 1;
        stats.total_transactions_processed += tx_hashes.len() as u64;
        stats.last_updated = Timestamp::now();
        drop(stats);

        let mut tracker = self.epoch_tracker.lock().await;
        tracker
            .epoch_batches
            .entry(epoch)
            .or_insert_with(Vec::new)
            .push(batch_id);
        drop(tracker);

        Ok(batch_id)
    }

    pub async fn execute_batch(
        &self,
        batch_id: &Hash,
        shard_manager: &ShardManager,
    ) -> EgoResult<Hash> {
        let mut batch = self
            .pending_batches
            .get_mut(batch_id)
            .ok_or(EgoError::InvalidTransaction("Batch not found".to_string()))?;

        if batch.status != BatchStatus::Building {
            return Err(EgoError::InvalidTransaction(
                "Batch is not in Building state".to_string(),
            ));
        }

        let state = shard_manager.state.read().await;
        let state_root_pre = state.get_state_root();
        drop(state);

        if batch.state_root_pre != state_root_pre {
            return Err(EgoError::InvalidTransaction(
                "State root mismatch".to_string(),
            ));
        }

        for tx in &batch.transactions {
            shard_manager.add_transaction(tx.clone()).await?;
        }

        let state = shard_manager.state.read().await;
        let state_root_post = state.get_state_root();
        drop(state);

        batch.state_root_post = state_root_post;
        batch.status = BatchStatus::Ready;

        Ok(state_root_post)
    }

    pub async fn commit_batch(
        &self,
        batch_id: &Hash,
        proof: Option<BatchProof>,
        operator_signature: Vec<u8>,
        current_block: BlockHeight,
    ) -> EgoResult<()> {
        let pending_batch = self
            .pending_batches
            .get(batch_id)
            .ok_or(EgoError::InvalidTransaction("Batch not found".to_string()))?;

        if pending_batch.status != BatchStatus::Ready {
            return Err(EgoError::InvalidTransaction(
                "Batch is not ready for commitment".to_string(),
            ));
        }

        let config = self.config.read().await;
        let proof_verification_enabled = config.proof_verification_enabled;
        let da_enabled = config.da_enabled;
        let challenge_window_blocks = config.challenge_window_blocks;
        let drs_integration = config.drs_integration_enabled;
        drop(config);

        if proof_verification_enabled {
            if let Some(ref batch_proof) = proof {
                self.verify_batch_proof(batch_proof, &pending_batch)?;
            } else {
                return Err(EgoError::InvalidTransaction(
                    "Proof required but not provided".to_string(),
                ));
            }
        }

        let proofs_root = if let Some(ref batch_proof) = proof {
            ego_core::crypto::hash_data(&batch_proof.proof_data)
        } else {
            Hash::ZERO
        };

        let da_commitment = if da_enabled {
            Some(self.create_da_commitment(batch_id, &pending_batch).await?)
        } else {
            None
        };

        let da_root = da_commitment
            .as_ref()
            .map(|c| c.da_root)
            .unwrap_or(Hash::ZERO);

        let mut drs_scores_included = Vec::new();
        if drs_integration {
            for tx in &pending_batch.transactions {
                if let Some(score) = self.drs_manager.get_node_score(&tx.from) {
                    drs_scores_included.push(score.evidence_root);
                }
            }
        }

        let mut deploy_events = Vec::new();
        for deploy_id in &pending_batch.deploy_records {
            deploy_events.push(*deploy_id);
        }

        let committed = CommittedBatch {
            batch_id: *batch_id,
            operator: pending_batch.operator,
            shard_id: pending_batch.shard_id,
            tx_root: pending_batch.tx_root,
            state_root_pre: pending_batch.state_root_pre,
            state_root_post: pending_batch.state_root_post,
            receipts_root: Hash::ZERO,
            events_root_post: Hash::ZERO,
            events_root_poc: Hash::ZERO,
            proofs_root,
            da_root,
            proof,
            da_commitment,
            committed_at: Timestamp::now(),
            committed_block: current_block,
            epoch: pending_batch.epoch,
            challenge_deadline: BlockHeight::new(current_block.as_u64() + challenge_window_blocks),
            operator_signature,
            aggregated: false,
            drs_scores_included,
            deploy_events,
        };

        self.committed_batches.insert(*batch_id, committed.clone());
        drop(pending_batch);
        self.pending_batches.remove(batch_id);

        if let Some(mut operator_info) = self.operator_registry.get_mut(&committed.operator) {
            operator_info.batches_committed += 1;
            operator_info.last_batch_epoch = committed.epoch;
        }

        let mut stats = self.stats.lock().await;
        stats.total_batches_committed += 1;
        if let Some(ref p) = committed.proof {
            stats.total_proofs_verified += 1;
            stats.avg_proof_size_bytes = (stats.avg_proof_size_bytes
                * (stats.total_proofs_verified - 1) as f64
                + p.proof_size_bytes as f64)
                / stats.total_proofs_verified as f64;
        }
        stats.last_updated = Timestamp::now();
        drop(stats);

        Ok(())
    }

    pub async fn finalize_batch(
        &self,
        batch_id: &Hash,
        current_block: BlockHeight,
    ) -> EgoResult<()> {
        let committed_batch = self
            .committed_batches
            .get(batch_id)
            .ok_or(EgoError::InvalidTransaction("Batch not found".to_string()))?;

        if current_block < committed_batch.challenge_deadline {
            return Err(EgoError::InvalidTransaction(
                "Challenge period not yet expired".to_string(),
            ));
        }

        let operator = committed_batch.operator;
        let epoch = committed_batch.epoch;
        let shard_id = committed_batch.shard_id;

        let drs_multiplier = self.drs_manager.get_node_multiplier(&operator);

        let base_reward = Balance::from_egoc(100);
        let operator_reward =
            Balance::new(((base_reward.as_u128() as f64) * drs_multiplier).round() as u128);

        let finalized = FinalizedBatch {
            batch_id: *batch_id,
            operator,
            shard_id,
            tx_root: committed_batch.tx_root,
            state_root_post: committed_batch.state_root_post,
            committed_block: committed_batch.committed_block,
            finalized_block: current_block,
            finalized_at: Timestamp::now(),
            epoch,
            challenge_period_passed: true,
            dispute_count: 0,
            all_disputes_resolved: true,
            operator_reward,
            drs_multiplier_applied: drs_multiplier,
        };

        self.finalized_batches.insert(*batch_id, finalized);
        drop(committed_batch);
        self.committed_batches.remove(batch_id);

        if let Some(mut operator_info) = self.operator_registry.get_mut(&operator) {
            operator_info.batches_finalized += 1;
            operator_info.reputation_score = (operator_info.reputation_score + 1.0).min(100.0);
        }

        let mut stats = self.stats.lock().await;
        stats.total_batches_finalized += 1;
        stats.last_updated = Timestamp::now();
        drop(stats);

        let mut tracker = self.epoch_tracker.lock().await;
        let epoch_stats = tracker
            .epoch_stats
            .entry(epoch)
            .or_insert_with(|| EpochBatchStats {
                epoch,
                ..Default::default()
            });
        epoch_stats.finalized_batches += 1;
        drop(tracker);

        Ok(())
    }

    pub async fn aggregate_proofs(
        &self,
        shard_id: ShardId,
        current_block: BlockHeight,
    ) -> EgoResult<Option<BatchProof>> {
        let config = self.config.read().await;
        let aggregation_enabled = config.aggregation_enabled;
        let aggregation_window = config.aggregation_window_blocks;
        drop(config);

        if !aggregation_enabled {
            return Ok(None);
        }

        let mut aggregator = self.proof_aggregator.lock().await;

        if !aggregation_enabled {
            return Ok(None);
        }

        let aggregation_window_start = aggregator.aggregation_window_start;
        let pending_proofs = aggregator
            .pending_proofs
            .entry(shard_id)
            .or_insert_with(Vec::new);

        if pending_proofs.is_empty() {
            return Ok(None);
        }

        if aggregation_window_start == BlockHeight::GENESIS {
            aggregator.aggregation_window_start = current_block;
            return Ok(None);
        }

        if current_block.as_u64() - aggregation_window_start.as_u64() < aggregation_window {
            return Ok(None);
        }

        let proofs_to_aggregate = pending_proofs.clone();
        pending_proofs.clear();
        aggregator.aggregation_window_start = current_block;
        aggregator.aggregation_count += 1;

        drop(aggregator);

        let sub_proof_hashes: Vec<Hash> = proofs_to_aggregate
            .iter()
            .map(|p| ego_core::crypto::hash_data(&p.proof_data))
            .collect();

        let aggregated_data = self.aggregate_proof_data(&proofs_to_aggregate)?;
        let aggregated_data_len = aggregated_data.len();
        let aggregated_hash = ego_core::crypto::hash_data(&aggregated_data);

        let aggregated_proof = BatchProof {
            proof_type: ProofType::Aggregated {
                sub_proofs: sub_proof_hashes,
            },
            proof_data: aggregated_data,
            public_inputs: vec![aggregated_hash],
            verification_key_hash: Hash::ZERO,
            proof_size_bytes: aggregated_data_len,
            generated_at: Timestamp::now(),
        };

        let mut stats = self.stats.lock().await;
        stats.total_proofs_aggregated += proofs_to_aggregate.len() as u64;
        drop(stats);

        Ok(Some(aggregated_proof))
    }

    fn aggregate_proof_data(&self, proofs: &[BatchProof]) -> EgoResult<Vec<u8>> {
        let mut aggregated = Vec::new();
        for proof in proofs {
            aggregated.extend_from_slice(&proof.proof_data);
        }
        Ok(aggregated)
    }

    async fn create_da_commitment(
        &self,
        batch_id: &Hash,
        batch: &PendingBatch,
    ) -> EgoResult<DaCommitment> {
        let config = bincode::config::standard();
        let batch_data = bincode::encode_to_vec(batch, config)
            .map_err(|e| EgoError::SerializationError(e.to_string()))?;

        let erasure_params = ErasureCodingParams {
            k: 64,
            m: 32,
            codec: "ReedSolomon".to_string(),
            chunk_size: DA_CHUNK_SIZE,
        };

        let chunks = self.split_into_chunks(&batch_data, DA_CHUNK_SIZE);
        let chunk_hashes: Vec<Hash> = chunks
            .iter()
            .map(|chunk| ego_core::crypto::hash_data(chunk))
            .collect();

        for (index, chunk) in chunks.into_iter().enumerate() {
            let mut chunk_data = Vec::new();
            chunk_data.extend_from_slice(batch_id.as_bytes());
            chunk_data.extend_from_slice(&index.to_le_bytes());
            let chunk_id = ego_core::crypto::hash_data(&chunk_data);
            let da_chunk = DaChunk {
                chunk_id,
                batch_id: *batch_id,
                chunk_index: index as u32,
                data: chunk,
                parity: false,
                uploaded_at: Timestamp::now(),
            };
            self.da_manager.chunks.insert(chunk_id, da_chunk);
        }

        let da_root = self.compute_merkle_root(&chunk_hashes);

        let commitment = DaCommitment {
            da_root,
            chunk_count: chunk_hashes.len() as u32,
            total_size_bytes: batch_data.len(),
            erasure_coding_params: erasure_params,
            chunk_hashes: chunk_hashes.clone(),
            blob_pointer: None,
            uploaded_at: Timestamp::now(),
        };

        self.da_manager
            .commitments
            .insert(*batch_id, commitment.clone());

        let mut stats = self.da_manager.retrieval_stats.lock().await;
        stats.total_chunks_uploaded += chunk_hashes.len() as u64;
        drop(stats);

        let mut batch_stats = self.stats.lock().await;
        batch_stats.total_da_chunks_uploaded += chunk_hashes.len() as u64;
        drop(batch_stats);

        Ok(commitment)
    }

    fn split_into_chunks(&self, data: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
        data.chunks(chunk_size)
            .map(|chunk| chunk.to_vec())
            .collect()
    }

    fn verify_batch_proof(&self, proof: &BatchProof, batch: &PendingBatch) -> EgoResult<()> {
        if proof.proof_size_bytes > MAX_PROOF_SIZE_BYTES {
            return Err(EgoError::InvalidTransaction(
                "Proof size exceeds maximum".to_string(),
            ));
        }

        if proof.proof_data.is_empty() {
            return Err(EgoError::InvalidTransaction(
                "Proof data is empty".to_string(),
            ));
        }

        Ok(())
    }

    fn compute_batch_id(
        &self,
        operator: &Address,
        shard_id: &ShardId,
        tx_root: &Hash,
        epoch: u64,
    ) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(operator.as_bytes());
        data.extend_from_slice(&shard_id.as_u32().to_le_bytes());
        data.extend_from_slice(tx_root.as_bytes());
        data.extend_from_slice(&epoch.to_le_bytes());
        ego_core::crypto::hash_data(&data)
    }

    fn compute_merkle_root(&self, hashes: &[Hash]) -> Hash {
        if hashes.is_empty() {
            return Hash::ZERO;
        }
        let data: Vec<Vec<u8>> = hashes.iter().map(|h| h.to_vec()).collect();
        let tree = ego_core::crypto::MerkleTree::build(data);
        tree.root_hash().unwrap_or(Hash::ZERO)
    }

    pub async fn sync_drs_scores(&self, epoch: u64) -> EgoResult<()> {
        let config = self.config.read().await;
        if !config.drs_integration_enabled {
            return Ok(());
        }
        drop(config);

        let mut tracker = self.epoch_tracker.lock().await;
        let scores_map = tracker
            .epoch_drs_scores
            .entry(epoch)
            .or_insert_with(HashMap::new);

        for operator_ref in self.operator_registry.iter() {
            let operator = *operator_ref.key();
            if let Some(score) = self.drs_manager.get_node_score(&operator) {
                scores_map.insert(operator, score.clone());

                let mut operator_info = operator_ref.value().clone();
                operator_info.drs_score = score.score_smoothed;
                operator_info.drs_multiplier = score.multiplier;
                drop(operator_ref);
                self.operator_registry.insert(operator, operator_info);
            }
        }

        Ok(())
    }

    pub async fn sync_deploy_stats(&self, epoch: u64) -> EgoResult<()> {
        let config = self.config.read().await;
        if !config.deploy_policy_enforcement {
            return Ok(());
        }
        drop(config);

        let deploy_stats = self.deploy_policy.get_epoch_stats(epoch);

        if let Some(stats) = deploy_stats {
            let snapshot = DeployStatsSnapshot {
                epoch,
                total_deploys: stats.total_deploys,
                successful_deploys: stats.successful_deploys,
                failed_deploys: stats.failed_deploys,
                human_verified_deploys: stats.human_verified_deploys,
                ai_flagged_deploys: stats.ai_flagged_deploys,
                total_credits_consumed: stats.credits_consumed,
                total_pob_burned: stats.pob_burns_total,
            };

            let mut tracker = self.epoch_tracker.lock().await;
            tracker.epoch_deploy_stats.insert(epoch, snapshot);
        }

        Ok(())
    }

    pub async fn create_state_snapshot(
        &self,
        shard_id: ShardId,
        epoch: u64,
        block_height: BlockHeight,
    ) -> EgoResult<Hash> {
        let shard_manager = self
            .shard_managers
            .get(&shard_id)
            .ok_or(EgoError::InvalidTransaction("Shard not found".to_string()))?;

        let state = shard_manager.state.read().await;
        let state_root = state.get_state_root();
        drop(state);

        let snapshot_data = format!("{}:{}:{}", shard_id.as_u32(), epoch, block_height.as_u64());
        let snapshot_hash = ego_core::crypto::hash_data(snapshot_data.as_bytes());

        let snapshot_ref = StateSnapshotRef {
            epoch,
            block_height,
            shard_id,
            state_root,
            snapshot_hash,
            created_at: Timestamp::now(),
        };

        self.state_snapshots.insert(epoch, snapshot_ref);

        Ok(snapshot_hash)
    }

    pub async fn process_cross_batch_receipt(
        &self,
        src_batch_id: Hash,
        dst_shard: ShardId,
        payload: Vec<u8>,
    ) -> EgoResult<Hash> {
        let mut receipt_data = Vec::new();
        receipt_data.extend_from_slice(src_batch_id.as_bytes());
        receipt_data.extend_from_slice(&dst_shard.as_u32().to_le_bytes());
        receipt_data.extend_from_slice(&payload);
        let receipt_id = ego_core::crypto::hash_data(&receipt_data);

        let mut receipt_data = Vec::new();
        receipt_data.extend_from_slice(src_batch_id.as_bytes());
        receipt_data.extend_from_slice(&dst_shard.as_u32().to_le_bytes());
        receipt_data.extend_from_slice(&payload);
        let receipt_id = ego_core::crypto::hash_data(&receipt_data);

        let receipt = CrossBatchReceipt {
            receipt_id,
            src_batch_id,
            dst_batch_id: None,
            src_shard: ShardId::new(0).unwrap(),
            dst_shard,
            payload,
            nonce: 0,
            created_at: Timestamp::now(),
            status: CrossBatchStatus::Pending,
        };

        self.cross_batch_receipts.insert(receipt_id, receipt);

        Ok(receipt_id)
    }

    pub async fn slash_operator(
        &self,
        operator: Address,
        reason: String,
        slash_amount: Balance,
    ) -> EgoResult<()> {
        let config = self.config.read().await;
        if !config.slashing_enabled {
            return Ok(());
        }
        drop(config);

        let mut operator_info =
            self.operator_registry
                .get_mut(&operator)
                .ok_or(EgoError::InvalidTransaction(
                    "Operator not registered".to_string(),
                ))?;

        operator_info.total_slashed = operator_info
            .total_slashed
            .checked_add(slash_amount)
            .unwrap_or(operator_info.total_slashed);

        operator_info.reputation_score = (operator_info.reputation_score - 10.0).max(0.0);

        if operator_info.reputation_score < 20.0 {
            operator_info.status = OperatorStatus::Slashed;
        }

        Ok(())
    }

    pub async fn advance_epoch(&self, new_epoch: u64) -> EgoResult<()> {
        let mut tracker = self.epoch_tracker.lock().await;
        let mut current = tracker.current_epoch;
        if new_epoch <= current {
            return Err(EgoError::InvalidTransaction(
                "New epoch must be greater than current epoch".to_string(),
            ));
        }
        while current < new_epoch {
            let epoch = current;
            if let Some(batch_ids) = tracker.epoch_batches.get(&epoch) {
                let mut stats = EpochBatchStats {
                    epoch,
                    ..Default::default()
                };
                for batch_id in batch_ids {
                    if let Some(finalized) = self.finalized_batches.get(batch_id) {
                        stats.finalized_batches += 1;
                        stats.operators_active.insert(finalized.operator);
                    }
                    if let Some(committed) = self.committed_batches.get(batch_id) {
                        stats.total_batches += 1;
                    }
                    if let Some(pending) = self.pending_batches.get(batch_id) {
                        stats.total_transactions += pending.transactions.len() as u64;
                        stats.total_ru_consumed += pending.ru_consumed;
                        stats.total_storage_used += pending.storage_used;
                    }
                }
                if stats.total_batches > 0 {
                    stats.avg_batch_size =
                        stats.total_transactions as f64 / stats.total_batches as f64;
                }
                tracker.epoch_stats.insert(epoch, stats);
            }
            current += 1;
        }
        tracker.current_epoch = new_epoch;
        drop(tracker);
        self.sync_drs_scores(new_epoch).await?;
        self.sync_deploy_stats(new_epoch).await?;
        Ok(())
    }

    pub async fn get_batch_stats(&self) -> BatchStats {
        self.stats.lock().await.clone()
    }

    pub async fn get_epoch_stats(&self, epoch: u64) -> Option<EpochBatchStats> {
        let tracker = self.epoch_tracker.lock().await;
        tracker.epoch_stats.get(&epoch).cloned()
    }

    pub fn get_pending_batch(&self, batch_id: &Hash) -> Option<PendingBatch> {
        self.pending_batches.get(batch_id).map(|b| b.clone())
    }

    pub fn get_committed_batch(&self, batch_id: &Hash) -> Option<CommittedBatch> {
        self.committed_batches.get(batch_id).map(|b| b.clone())
    }

    pub fn get_finalized_batch(&self, batch_id: &Hash) -> Option<FinalizedBatch> {
        self.finalized_batches.get(batch_id).map(|b| b.clone())
    }

    pub fn get_operator_info(&self, operator: &Address) -> Option<OperatorInfo> {
        self.operator_registry.get(operator).map(|i| i.clone())
    }

    pub async fn get_operator_batches(&self, operator: &Address, limit: usize) -> Vec<Hash> {
        let mut batches = Vec::new();

        for entry in self.finalized_batches.iter() {
            if entry.operator == *operator {
                batches.push(entry.batch_id);
                if batches.len() >= limit {
                    break;
                }
            }
        }

        batches
    }

    pub fn get_da_commitment(&self, batch_id: &Hash) -> Option<DaCommitment> {
        self.da_manager.commitments.get(batch_id).map(|c| c.clone())
    }

    pub fn get_da_chunk(&self, chunk_id: &Hash) -> Option<DaChunk> {
        self.da_manager.chunks.get(chunk_id).map(|c| c.clone())
    }

    pub async fn get_da_stats(&self) -> DaRetrievalStats {
        self.da_manager.retrieval_stats.lock().await.clone()
    }

    pub fn get_state_snapshot(&self, epoch: u64) -> Option<StateSnapshotRef> {
        self.state_snapshots.get(&epoch).map(|s| s.clone())
    }

    pub fn get_cross_batch_receipt(&self, receipt_id: &Hash) -> Option<CrossBatchReceipt> {
        self.cross_batch_receipts.get(receipt_id).map(|r| r.clone())
    }

    pub async fn update_config(&self, new_config: BatchConfig) -> EgoResult<()> {
        if new_config.max_batch_size == 0 || new_config.max_batch_size_bytes == 0 {
            return Err(EgoError::InvalidTransaction(
                "Invalid batch size limits".to_string(),
            ));
        }

        *self.config.write().await = new_config;
        Ok(())
    }

    pub async fn prune_old_batches(&self, keep_epochs: u64) -> EgoResult<usize> {
        let tracker = self.epoch_tracker.lock().await;
        let current_epoch = tracker.current_epoch;
        drop(tracker);

        let cutoff_epoch = current_epoch.saturating_sub(keep_epochs);
        let mut pruned = 0;

        self.pending_batches.retain(|_, batch| {
            if batch.epoch < cutoff_epoch {
                pruned += 1;
                false
            } else {
                true
            }
        });

        self.committed_batches.retain(|_, batch| {
            if batch.epoch < cutoff_epoch {
                pruned += 1;
                false
            } else {
                true
            }
        });

        let mut tracker = self.epoch_tracker.lock().await;
        tracker
            .epoch_batches
            .retain(|&epoch, _| epoch >= cutoff_epoch);
        tracker
            .epoch_stats
            .retain(|&epoch, _| epoch >= cutoff_epoch);
        tracker
            .epoch_drs_scores
            .retain(|&epoch, _| epoch >= cutoff_epoch);
        tracker
            .epoch_deploy_stats
            .retain(|&epoch, _| epoch >= cutoff_epoch);

        Ok(pruned)
    }
}

pub fn validate_batch_structure(batch: &PendingBatch) -> EgoResult<()> {
    if batch.transactions.is_empty() {
        return Err(EgoError::InvalidTransaction(
            "Batch cannot be empty".to_string(),
        ));
    }

    if batch.batch_size_bytes > MAX_BATCH_SIZE_BYTES {
        return Err(EgoError::InvalidTransaction(
            "Batch size exceeds maximum".to_string(),
        ));
    }

    if batch.transactions.len() > MAX_BATCH_SIZE {
        return Err(EgoError::InvalidTransaction(
            "Batch transaction count exceeds maximum".to_string(),
        ));
    }

    Ok(())
}

pub fn calculate_batch_priority(batch: &BatchMetadata, drs_multiplier: f64) -> u8 {
    let base_priority = 128u8;
    let size_factor = (batch.tx_count as f64 / MAX_BATCH_SIZE as f64).min(1.0);
    let drs_factor = (drs_multiplier - 0.7) / 0.6;

    let priority = (base_priority as f64 * (1.0 + size_factor * 0.2 + drs_factor * 0.3)).min(255.0);

    priority as u8
}
