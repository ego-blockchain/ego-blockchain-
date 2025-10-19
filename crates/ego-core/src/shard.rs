use crate::{
    Account, Address, AlgorithmId, Balance, Block, BlockHeight,
    CrossShardReceipt as TxCrossShardReceipt, DualSignature, EgoError, EgoResult, Hash, PublicKey,
    ShardId, SliceId, StateManager, Timestamp, Transaction, TransactionPayload, TransactionResult,
    PROTOCOL_VERSION,
};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{interval, Duration};

pub const MAX_TXS_PER_BLOCK: usize = 10_000;
pub const TARGET_BLOCK_TIME_MS: u64 = 2_000;
pub const MAX_CROSS_SHARD_RECEIPTS_PER_EPOCH: usize = 100_000;
pub const RECEIPT_DEADLINE_EPOCHS: u64 = 100;
pub const MAX_BLOCKS_IN_MEMORY: usize = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardConfig {
    pub shard_id: ShardId,
    pub committee_size: u32,
    pub replication_factor: u8,
    pub max_txs_per_block: u32,
    pub target_block_time_ms: u64,
    pub micro_slot_duration_ms: u64,
    pub epoch_duration_blocks: u64,
    pub cross_shard_enabled: bool,
    pub storage_config: ShardStorageConfig,
    pub preferred_slices: Vec<String>,
    pub geo_constraints: Option<GeoConstraints>,
    pub pob_config: PoBConfig,
    pub drs_config: DRSConfig,
    pub cellular_safe_config: CellularSafeConfig,
    pub pq_transition_config: PQTransitionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardStorageConfig {
    pub max_storage_per_node: u64,
    pub proof_frequency: u64,
    pub retention_period: u64,
    pub erasure_coding: ErasureCodingConfig,
    pub gc_config: GarbageCollectionConfig,
    pub porep_params: PoRepParams,
    pub post_params: PoStParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureCodingConfig {
    pub data_chunks: u8,
    pub parity_chunks: u8,
    pub chunk_size: u32,
    pub codec: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GarbageCollectionConfig {
    pub frequency: u64,
    pub threshold: f64,
    pub aggressive_mode: bool,
    pub prune_old_bodies: bool,
    pub prune_old_receipts: bool,
    pub prune_old_events: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoRepParams {
    pub sector_size: u64,
    pub layers: u8,
    pub base_degree: u8,
    pub tree_arity: u8,
    pub params_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoStParams {
    pub windows_per_day: u32,
    pub challenges_per_sector: u32,
    pub sla_ms: u32,
    pub sectors_per_partition: u32,
    pub enable_aggregation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoConstraints {
    pub allowed_regions: Vec<String>,
    pub max_latency_ms: u32,
    pub min_nodes_per_region: u32,
    pub h3_resolution: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoBConfig {
    pub enabled: bool,
    pub storage_credit_price: u64,
    pub deploy_credit_price: u64,
    pub burn_address: Address,
    pub floors_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DRSConfig {
    pub weight_uptime: f64,
    pub weight_post_pass: f64,
    pub weight_inv_latency: f64,
    pub weight_poc: f64,
    pub weight_serve: f64,
    pub penalty_failed_post: f64,
    pub penalty_replay: f64,
    pub penalty_equivocation: f64,
    pub penalty_max: f64,
    pub smoothing_alpha: f64,
    pub multiplier_slope: f64,
    pub multiplier_min: f64,
    pub multiplier_max: f64,
    pub post_sla_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellularSafeConfig {
    pub enabled: bool,
    pub max_monthly_data_gb: u64,
    pub wifi_only_operations: Vec<String>,
    pub throttle_threshold_gb: u64,
    pub proof_rate_hz: f64,
    pub proof_batch_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQTransitionConfig {
    pub transition_epoch: u64,
    pub migration_period_epochs: u64,
    pub pq_only_required: bool,
    pub supported_algorithms: Vec<u16>,
    pub legacy_deadline_epoch: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochInfo {
    pub epoch_number: u64,
    pub start_block: BlockHeight,
    pub end_block: BlockHeight,
    pub start_time: Timestamp,
    pub committee: Vec<Address>,
    pub leader_schedule: Vec<Address>,
    pub vrf_seed: [u8; 32],
    pub stats: EpochStats,
    pub total_rewards: Balance,
    pub reward_buckets: RewardBuckets,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EpochStats {
    pub blocks_produced: u64,
    pub transactions_processed: u64,
    pub avg_block_time_ms: u64,
    pub cross_shard_txs: u64,
    pub storage_proofs_verified: u64,
    pub coverage_proofs_verified: u64,
    pub network_utilization: f64,
    pub avg_tps: f64,
    pub total_ru_consumed: u64,
    pub total_storage_credits_burned: u64,
    pub total_deploy_credits_burned: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RewardBuckets {
    pub storage_rewards: Balance,
    pub consensus_rewards: Balance,
    pub coverage_rewards: Balance,
    pub retrieval_rewards: Balance,
    pub dao_treasury: Balance,
}

#[derive(Debug)]
pub struct TransactionPool {
    pending: Arc<DashMap<u8, VecDeque<Transaction>>>,
    by_hash: Arc<DashMap<Hash, Transaction>>,
    by_sender: Arc<DashMap<Address, VecDeque<Transaction>>>,
    stats: Arc<Mutex<PoolStats>>,
    max_pool_size: u64,
    max_txs_per_sender: usize,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PoolStats {
    pub pending_count: usize,
    pub pool_size_bytes: u64,
    pub avg_tx_age_ms: u64,
    pub txs_added: u64,
    pub txs_removed: u64,
    pub txs_rejected: u64,
    pub last_updated: Timestamp,
}

#[derive(Debug)]
pub struct CrossShardManager {
    outbound_receipts: Arc<DashMap<ShardId, VecDeque<CrossShardReceipt>>>,
    inbound_receipts: Arc<DashMap<ShardId, VecDeque<CrossShardReceipt>>>,
    receipt_acks: Arc<DashMap<Hash, ReceiptAck>>,
    processed_nonces: Arc<DashMap<(ShardId, ShardId), HashSet<u64>>>,
    stats: Arc<Mutex<CrossShardStats>>,
    shard_topology: Arc<RwLock<HashMap<ShardId, ShardInfo>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct CrossShardReceipt {
    pub src_shard: ShardId,
    pub dst_shard: ShardId,
    pub src_block_hash: Hash,
    pub tx_id: Hash,
    pub payload: Vec<u8>,
    pub nonce: u64,
    pub deadline_epoch: u64,
    pub merkle_proof: Vec<Hash>,
    pub signature: DualSignature,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptAck {
    pub receipt_hash: Hash,
    pub ack_shard: ShardId,
    pub ack_timestamp: Timestamp,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardInfo {
    pub shard_id: ShardId,
    pub block_height: BlockHeight,
    pub state_root: Hash,
    pub last_finalized_epoch: u64,
    pub active_validators: Vec<Address>,
    pub status: ShardStatus,
    pub last_updated: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShardStatus {
    Active,
    Syncing,
    Paused,
    Reorganizing,
    Offline,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CrossShardStats {
    pub receipts_sent: u64,
    pub receipts_received: u64,
    pub receipts_pending: u64,
    pub avg_receipt_latency_ms: u64,
    pub failed_receipts: u64,
    pub last_updated: Timestamp,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ShardMetrics {
    pub tps: f64,
    pub bps: f64,
    pub avg_tx_latency_ms: u64,
    pub storage_utilization: f64,
    pub network_usage_bps: u64,
    pub active_nodes: u32,
    pub consensus_participation: f64,
    pub current_ru_usage: u64,
    pub post_success_rate: f64,
    pub poc_quality_avg: f64,
    pub last_updated: Timestamp,
}

#[derive(Debug)]
pub struct ShardManager {
    pub config: ShardConfig,
    pub state: Arc<RwLock<StateManager>>,
    blocks: Arc<RwLock<VecDeque<Block>>>,
    pub current_epoch: Arc<RwLock<EpochInfo>>,
    tx_pool: Arc<TransactionPool>,
    cross_shard: Arc<CrossShardManager>,
    metrics: Arc<RwLock<ShardMetrics>>,
    total_blocks: Arc<AtomicU64>,
    total_transactions: Arc<AtomicU64>,
    chain_id: u32,
    network_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardStats {
    pub shard_id: ShardId,
    pub current_block_height: BlockHeight,
    pub current_epoch: EpochInfo,
    pub state_stats: crate::state::StateStats,
    pub pool_stats: PoolStats,
    pub metrics: ShardMetrics,
    pub blocks_stored: u64,
    pub cross_shard_stats: CrossShardStats,
    pub total_blocks: u64,
    pub total_transactions: u64,
}

impl Default for ShardConfig {
    fn default() -> Self {
        Self {
            shard_id: ShardId::new(0).unwrap(),
            committee_size: 21,
            replication_factor: 3,
            max_txs_per_block: MAX_TXS_PER_BLOCK as u32,
            target_block_time_ms: TARGET_BLOCK_TIME_MS,
            micro_slot_duration_ms: 100,
            epoch_duration_blocks: 12_000,
            cross_shard_enabled: true,
            storage_config: ShardStorageConfig::default(),
            preferred_slices: Vec::new(),
            geo_constraints: None,
            pob_config: PoBConfig::default(),
            drs_config: DRSConfig::default(),
            cellular_safe_config: CellularSafeConfig::default(),
            pq_transition_config: PQTransitionConfig::default(),
        }
    }
}

impl Default for ShardStorageConfig {
    fn default() -> Self {
        Self {
            max_storage_per_node: 100 * 1024 * 1024 * 1024,
            proof_frequency: 100,
            retention_period: 100_000,
            erasure_coding: ErasureCodingConfig::default(),
            gc_config: GarbageCollectionConfig::default(),
            porep_params: PoRepParams::default(),
            post_params: PoStParams::default(),
        }
    }
}

impl Default for ErasureCodingConfig {
    fn default() -> Self {
        Self {
            data_chunks: 64,
            parity_chunks: 32,
            chunk_size: 1024 * 1024, // 1 MB
            codec: "ReedSolomon".to_string(),
        }
    }
}

impl Default for GarbageCollectionConfig {
    fn default() -> Self {
        Self {
            frequency: 1000,
            threshold: 0.8,
            aggressive_mode: false,
            prune_old_bodies: true,
            prune_old_receipts: true,
            prune_old_events: true,
        }
    }
}

impl Default for PoRepParams {
    fn default() -> Self {
        Self {
            sector_size: 32 * 1024 * 1024 * 1024,
            layers: 11,
            base_degree: 6,
            tree_arity: 8,
            params_version: 1,
        }
    }
}

impl Default for PoStParams {
    fn default() -> Self {
        Self {
            windows_per_day: 48,
            challenges_per_sector: 24,
            sla_ms: 600_000,
            sectors_per_partition: 2349,
            enable_aggregation: true,
        }
    }
}

impl Default for PoBConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            storage_credit_price: 100,
            deploy_credit_price: 1000,
            burn_address: Address::new([0u8; 20]),
            floors_enabled: false,
        }
    }
}

impl Default for DRSConfig {
    fn default() -> Self {
        Self {
            weight_uptime: 0.20,
            weight_post_pass: 0.40,
            weight_inv_latency: 0.10,
            weight_poc: 0.20,
            weight_serve: 0.10,
            penalty_failed_post: 0.10,
            penalty_replay: 0.20,
            penalty_equivocation: 0.40,
            penalty_max: 0.5,
            smoothing_alpha: 0.3,
            multiplier_slope: 0.6,
            multiplier_min: 0.7,
            multiplier_max: 1.3,
            post_sla_ms: 600_000,
        }
    }
}

impl Default for CellularSafeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_monthly_data_gb: 50,
            wifi_only_operations: vec![
                "heavy_compute".to_string(),
                "large_storage".to_string(),
                "bulk_sync".to_string(),
                "firmware_update".to_string(),
            ],
            throttle_threshold_gb: 5,
            proof_rate_hz: 0.5,
            proof_batch_size: 100,
        }
    }
}

impl Default for PQTransitionConfig {
    fn default() -> Self {
        Self {
            transition_epoch: 0,
            migration_period_epochs: 1000,
            pq_only_required: false,
            supported_algorithms: vec![
                AlgorithmId::MlDsa2.as_u16(),
                AlgorithmId::Ed25519.as_u16(),
                AlgorithmId::MlKem768.as_u16(),
            ],
            legacy_deadline_epoch: None,
        }
    }
}

impl TransactionPool {
    pub fn new() -> Self {
        Self {
            pending: Arc::new(DashMap::new()),
            by_hash: Arc::new(DashMap::new()),
            by_sender: Arc::new(DashMap::new()),
            stats: Arc::new(Mutex::new(PoolStats::default())),
            max_pool_size: 100 * 1024 * 1024,
            max_txs_per_sender: 1000,
        }
    }

    pub async fn add_transaction(&self, tx: Transaction) -> EgoResult<()> {
        if self.by_hash.contains_key(&tx.hash) {
            return Ok(());
        }

        if let Some(sender_txs) = self.by_sender.get(&tx.from) {
            if sender_txs.len() >= self.max_txs_per_sender {
                let mut stats = self.stats.lock().await;
                stats.txs_rejected += 1;
                return Err(EgoError::InvalidTransaction(
                    "Sender has too many pending transactions".to_string(),
                ));
            }
        }

        let priority = self.calculate_priority(&tx);

        self.pending
            .entry(priority)
            .or_insert_with(VecDeque::new)
            .push_back(tx.clone());

        self.by_hash.insert(tx.hash, tx.clone());

        self.by_sender
            .entry(tx.from)
            .or_insert_with(VecDeque::new)
            .push_back(tx);

        let mut stats = self.stats.lock().await;
        stats.pending_count = self.by_hash.len();
        stats.txs_added += 1;
        stats.last_updated = Timestamp::now();

        Ok(())
    }

    pub async fn remove_transaction(&self, tx_hash: &Hash) {
        if let Some((_, tx)) = self.by_hash.remove(tx_hash) {
            let priority = self.calculate_priority(&tx);

            if let Some(mut queue) = self.pending.get_mut(&priority) {
                queue.retain(|t| t.hash != *tx_hash);
                if queue.is_empty() {
                    drop(queue);
                    self.pending.remove(&priority);
                }
            }

            if let Some(mut sender_txs) = self.by_sender.get_mut(&tx.from) {
                sender_txs.retain(|t| t.hash != *tx_hash);
                if sender_txs.is_empty() {
                    drop(sender_txs);
                    self.by_sender.remove(&tx.from);
                }
            }

            if let Ok(mut stats) = self.stats.try_lock() {
                stats.pending_count = self.by_hash.len();
                stats.txs_removed += 1;
                stats.last_updated = Timestamp::now();
            }
        }
    }

    pub async fn get_transactions_for_block(&self, max_count: usize) -> Vec<Transaction> {
        let mut transactions = Vec::new();
        let mut count = 0;

        let mut priorities: Vec<u8> = self.pending.iter().map(|entry| *entry.key()).collect();
        priorities.sort_by(|a, b| b.cmp(a));

        for priority in priorities {
            if count >= max_count {
                break;
            }

            if let Some(mut queue) = self.pending.get_mut(&priority) {
                while let Some(tx) = queue.pop_front() {
                    transactions.push(tx);
                    count += 1;

                    if count >= max_count {
                        break;
                    }
                }

                if queue.is_empty() {
                    drop(queue);
                    self.pending.remove(&priority);
                }
            }
        }

        transactions
    }

    fn calculate_priority(&self, tx: &Transaction) -> u8 {
        if tx.priority_hint > 0 {
            return tx.priority_hint;
        }

        match &tx.payload {
            TransactionPayload::SystemOperation { epoch_anchor, .. } => {
                if *epoch_anchor {
                    255
                } else {
                    240
                }
            }
            TransactionPayload::PQTransition { .. } => 230,
            TransactionPayload::PoStResponse { .. } | TransactionPayload::PoStChallenge { .. } => {
                200
            }
            TransactionPayload::PoCWitnessReport { .. } => 180,
            TransactionPayload::CrossShard { .. } => 160,
            TransactionPayload::RollupCommit { .. } => 140,
            TransactionPayload::ChallengeFraud { .. } => 130,
            TransactionPayload::ResolveFraudChallenge { .. } => 125,
            TransactionPayload::SubmitProofBatch { .. } => 120,
            TransactionPayload::UpdateDRS { .. } => 100,
            TransactionPayload::ClaimRewards { .. } => 90,
            TransactionPayload::DeployContract { .. } => 80,
            TransactionPayload::Stake { .. } | TransactionPayload::Delegate { .. } => 60,
            TransactionPayload::Transfer { .. } => 40,
            TransactionPayload::StreamStoragePayment { .. } => 35,
            TransactionPayload::PayRetrievalFee { .. } => 30,
            _ => 20,
        }
    }

    pub async fn get_stats(&self) -> PoolStats {
        self.stats.lock().await.clone()
    }

    pub fn get_transaction(&self, hash: &Hash) -> Option<Transaction> {
        self.by_hash.get(hash).map(|entry| entry.clone())
    }

    pub fn get_pending_count(&self) -> usize {
        self.by_hash.len()
    }

    pub async fn clear(&self) {
        self.pending.clear();
        self.by_hash.clear();
        self.by_sender.clear();

        let mut stats = self.stats.lock().await;
        stats.pending_count = 0;
        stats.pool_size_bytes = 0;
    }
}

impl CrossShardManager {
    pub fn new() -> Self {
        Self {
            outbound_receipts: Arc::new(DashMap::new()),
            inbound_receipts: Arc::new(DashMap::new()),
            receipt_acks: Arc::new(DashMap::new()),
            processed_nonces: Arc::new(DashMap::new()),
            stats: Arc::new(Mutex::new(CrossShardStats::default())),
            shard_topology: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_outbound_receipt(&self, receipt: CrossShardReceipt) -> EgoResult<()> {
        let key = (receipt.src_shard, receipt.dst_shard);
        if let Some(nonces) = self.processed_nonces.get(&key) {
            if nonces.contains(&receipt.nonce) {
                return Err(EgoError::InvalidTransaction(
                    "Receipt nonce already processed".to_string(),
                ));
            }
        }

        self.outbound_receipts
            .entry(receipt.dst_shard)
            .or_insert_with(VecDeque::new)
            .push_back(receipt.clone());

        let mut stats = self.stats.lock().await;
        stats.receipts_sent += 1;
        stats.receipts_pending += 1;
        stats.last_updated = Timestamp::now();

        Ok(())
    }

    pub async fn add_inbound_receipt(&self, receipt: CrossShardReceipt) -> EgoResult<()> {
        let key = (receipt.src_shard, receipt.dst_shard);
        if let Some(nonces) = self.processed_nonces.get(&key) {
            if nonces.contains(&receipt.nonce) {
                return Err(EgoError::InvalidTransaction(
                    "Receipt already processed".to_string(),
                ));
            }
        }

        self.inbound_receipts
            .entry(receipt.src_shard)
            .or_insert_with(VecDeque::new)
            .push_back(receipt.clone());

        self.processed_nonces
            .entry(key)
            .or_insert_with(HashSet::new)
            .insert(receipt.nonce);

        let mut stats = self.stats.lock().await;
        stats.receipts_received += 1;
        stats.last_updated = Timestamp::now();

        Ok(())
    }

    pub async fn acknowledge_receipt(
        &self,
        receipt_hash: Hash,
        ack_shard: ShardId,
        success: bool,
        error: Option<String>,
    ) -> EgoResult<()> {
        let ack = ReceiptAck {
            receipt_hash,
            ack_shard,
            ack_timestamp: Timestamp::now(),
            success,
            error,
        };

        self.receipt_acks.insert(receipt_hash, ack);

        let mut stats = self.stats.lock().await;
        if stats.receipts_pending > 0 {
            stats.receipts_pending -= 1;
        }
        if !success {
            stats.failed_receipts += 1;
        }
        stats.last_updated = Timestamp::now();

        Ok(())
    }

    pub async fn get_outbound_receipts(&self, dst_shard: &ShardId) -> Vec<CrossShardReceipt> {
        self.outbound_receipts
            .get(dst_shard)
            .map(|queue| queue.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub async fn get_inbound_receipts(&self, src_shard: &ShardId) -> Vec<CrossShardReceipt> {
        self.inbound_receipts
            .get(src_shard)
            .map(|queue| queue.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub async fn update_shard_info(&self, info: ShardInfo) {
        let mut topology = self.shard_topology.write().await;
        topology.insert(info.shard_id, info);
    }

    pub async fn get_shard_info(&self, shard_id: &ShardId) -> Option<ShardInfo> {
        let topology = self.shard_topology.read().await;
        topology.get(shard_id).cloned()
    }

    pub async fn get_stats(&self) -> CrossShardStats {
        self.stats.lock().await.clone()
    }

    pub async fn prune_expired_receipts(&self, current_epoch: u64) -> usize {
        let mut pruned = 0;

        for mut entry in self.outbound_receipts.iter_mut() {
            let queue = entry.value_mut();
            let original_len = queue.len();
            queue.retain(|receipt| receipt.deadline_epoch >= current_epoch);
            pruned += original_len - queue.len();
        }

        for mut entry in self.inbound_receipts.iter_mut() {
            let queue = entry.value_mut();
            let original_len = queue.len();
            queue.retain(|receipt| receipt.deadline_epoch >= current_epoch);
            pruned += original_len - queue.len();
        }

        pruned
    }
}

impl ShardManager {
    pub fn new(config: ShardConfig, chain_id: u32, network_id: u32) -> Self {
        let state = Arc::new(RwLock::new(StateManager::new(chain_id, network_id)));
        let blocks = Arc::new(RwLock::new(VecDeque::new()));
        let tx_pool = Arc::new(TransactionPool::new());
        let cross_shard = Arc::new(CrossShardManager::new());

        let (total_rewards, reward_buckets) = Self::calculate_epoch_rewards_static(0);

        let current_epoch = Arc::new(RwLock::new(EpochInfo {
            epoch_number: 0,
            start_block: BlockHeight::GENESIS,
            end_block: BlockHeight::new(config.epoch_duration_blocks),
            start_time: Timestamp::now(),
            committee: Vec::new(),
            leader_schedule: Vec::new(),
            vrf_seed: [0u8; 32],
            stats: EpochStats::default(),
            total_rewards,
            reward_buckets,
        }));

        Self {
            config,
            state,
            blocks,
            current_epoch,
            tx_pool,
            cross_shard,
            metrics: Arc::new(RwLock::new(ShardMetrics::default())),
            total_blocks: Arc::new(AtomicU64::new(0)),
            total_transactions: Arc::new(AtomicU64::new(0)),
            chain_id,
            network_id,
        }
    }

    pub async fn add_transaction(&self, tx: Transaction) -> EgoResult<()> {
        if !tx.verify_signature()? {
            return Err(EgoError::InvalidTransaction(
                "Invalid transaction signature".to_string(),
            ));
        }

        if tx.shard_id != self.config.shard_id {
            return Err(EgoError::InvalidTransaction(format!(
                "Transaction belongs to shard {}, not {}",
                tx.shard_id.as_u32(),
                self.config.shard_id.as_u32()
            )));
        }

        let state = self.state.read().await;
        if let Some(account) = state.get_account(&tx.from) {
            tx.validate_against_account(&account)?;
        } else {
            return Err(EgoError::AccountNotFound {
                account_id: tx.from.to_string(),
            });
        }
        drop(state);

        self.tx_pool.add_transaction(tx).await?;

        Ok(())
    }

    pub async fn get_transactions_for_block(&self, max_count: usize) -> Vec<Transaction> {
        let max = max_count.min(self.config.max_txs_per_block as usize);
        self.tx_pool.get_transactions_for_block(max).await
    }

    pub async fn process_block(&self, mut block: Block) -> EgoResult<()> {
        block.validate_structure()?;

        if block.header.core.shard_id != self.config.shard_id {
            return Err(EgoError::InvalidBlock(
                "Block belongs to different shard".to_string(),
            ));
        }

        let mut transaction_results = Vec::new();
        let mut cross_shard_receipts = Vec::new();

        {
            let mut state = self.state.write().await;

            for tx in &block.body.transactions {
                match state.execute_transaction(tx) {
                    Ok(mut result) => {
                        result.tx_hash = tx.hash;

                        if !result.cross_shard_receipts.is_empty() {
                            for receipt in &result.cross_shard_receipts {
                                cross_shard_receipts.push(CrossShardReceipt {
                                    src_shard: self.config.shard_id,
                                    dst_shard: receipt.dst_shard,
                                    src_block_hash: block.hash,
                                    tx_id: tx.hash,
                                    payload: receipt.payload.clone(),
                                    nonce: receipt.nonce,
                                    deadline_epoch: receipt.deadline_epoch,
                                    merkle_proof: Vec::new(),
                                    signature: tx.signature.clone(),
                                    timestamp: Timestamp::now(),
                                });
                            }
                        }

                        transaction_results.push(result);
                    }
                    Err(e) => {
                        transaction_results.push(TransactionResult {
                            tx_hash: tx.hash,
                            success: false,
                            error: Some(e.to_string()),
                            ru_used: 0,
                            storage_used: 0,
                            state_changes: Vec::new(),
                            events: Vec::new(),
                            cross_shard_receipts: Vec::new(),
                            pq_verification_result: None,
                            proof_verifications: Vec::new(),
                        });
                    }
                }
            }

            let new_state_root = state.compute_state_root();
            block.set_state_root(new_state_root);

            state.set_block_height(block.header.core.height);
        }

        for receipt in cross_shard_receipts {
            self.cross_shard.add_outbound_receipt(receipt).await?;
        }

        block.add_transaction_results(transaction_results);

        self.update_metrics(&block).await;

        {
            let mut blocks = self.blocks.write().await;
            blocks.push_back(block.clone());

            while blocks.len() > MAX_BLOCKS_IN_MEMORY {
                blocks.pop_front();
            }
        }

        for tx in &block.body.transactions {
            self.tx_pool.remove_transaction(&tx.hash).await;
        }

        self.total_blocks.fetch_add(1, Ordering::SeqCst);
        self.total_transactions
            .fetch_add(block.header.core.tx_count as u64, Ordering::SeqCst);

        if block.header.core.height.as_u64() >= self.current_epoch.read().await.end_block.as_u64() {
            self.start_new_epoch(block.header.core.height.next())
                .await?;
        }

        Ok(())
    }

    async fn start_new_epoch(&self, start_block: BlockHeight) -> EgoResult<()> {
        let mut epoch = self.current_epoch.write().await;

        let new_epoch_number = epoch.epoch_number + 1;
        let end_block = BlockHeight::new(start_block.as_u64() + self.config.epoch_duration_blocks);

        let mut vrf_seed = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut vrf_seed);

        let committee = self.select_committee().await;

        let (total_rewards, reward_buckets) = self.calculate_epoch_rewards(new_epoch_number);

        *epoch = EpochInfo {
            epoch_number: new_epoch_number,
            start_block,
            end_block,
            start_time: Timestamp::now(),
            committee,
            leader_schedule: Vec::new(),
            vrf_seed,
            stats: EpochStats::default(),
            total_rewards,
            reward_buckets,
        };

        self.cross_shard
            .prune_expired_receipts(new_epoch_number)
            .await;

        {
            let state = self.state.read().await;
            if state.should_prune() {
                drop(state);
                let mut state = self.state.write().await;
                state.prune_old_data(new_epoch_number)?;
            }
        }

        Ok(())
    }

    async fn select_committee(&self) -> Vec<Address> {
        let state = self.state.read().await;
        let validators = state.get_active_validators();

        let mut committee: Vec<Address> = validators
            .into_iter()
            .take(self.config.committee_size as usize)
            .map(|v| v.address)
            .collect();

        committee
    }

    fn calculate_epoch_rewards_static(epoch: u64) -> (Balance, RewardBuckets) {
        let base_emission = 1_000_000_000_000u128;

        let halvings = epoch / 525_600;
        let emission = base_emission >> halvings.min(10);

        let total_rewards = Balance::new(emission);

        let reward_buckets = RewardBuckets {
            storage_rewards: Balance::new(emission * 40 / 100),
            consensus_rewards: Balance::new(emission * 30 / 100),
            coverage_rewards: Balance::new(emission * 20 / 100),
            retrieval_rewards: Balance::new(emission * 5 / 100),
            dao_treasury: Balance::new(emission * 5 / 100),
        };

        (total_rewards, reward_buckets)
    }

    fn calculate_epoch_rewards(&self, epoch: u64) -> (Balance, RewardBuckets) {
        Self::calculate_epoch_rewards_static(epoch)
    }

    async fn update_metrics(&self, block: &Block) {
        let mut metrics = self.metrics.write().await;
        let now = Timestamp::now();

        let block_time_s = self.config.target_block_time_ms as f64 / 1000.0;
        metrics.tps = block.header.core.tx_count as f64 / block_time_s;

        metrics.bps = 1.0 / block_time_s;

        let state = self.state.read().await;
        let stats = state.get_stats();
        metrics.storage_utilization = stats.total_storage_bytes as f64
            / self.config.storage_config.max_storage_per_node as f64;

        if stats.total_post_challenges > 0 {
            metrics.post_success_rate = stats.post_pass_rate / 100.0;
        }

        metrics.active_nodes = stats.active_validators;

        metrics.last_updated = now;

        let mut epoch = self.current_epoch.write().await;
        epoch.stats.blocks_produced += 1;
        epoch.stats.transactions_processed += block.header.core.tx_count as u64;
        epoch.stats.avg_tps = metrics.tps;
    }

    pub async fn get_stats(&self) -> ShardStats {
        let state = self.state.read().await;
        let state_stats = state.get_stats();
        let pool_stats = self.tx_pool.get_stats().await;
        let blocks = self.blocks.read().await;
        let current_epoch = self.current_epoch.read().await.clone();
        let metrics = self.metrics.read().await.clone();
        let cross_shard_stats = self.cross_shard.get_stats().await;

        ShardStats {
            shard_id: self.config.shard_id,
            current_block_height: state.get_block_height(),
            current_epoch,
            state_stats,
            pool_stats,
            metrics,
            blocks_stored: blocks.len() as u64,
            cross_shard_stats,
            total_blocks: self.total_blocks.load(Ordering::SeqCst),
            total_transactions: self.total_transactions.load(Ordering::SeqCst),
        }
    }

    pub async fn get_recent_blocks(&self, count: usize) -> Vec<Block> {
        let blocks = self.blocks.read().await;
        blocks.iter().rev().take(count).cloned().collect()
    }

    pub async fn get_block_by_height(&self, height: BlockHeight) -> Option<Block> {
        let blocks = self.blocks.read().await;
        blocks
            .iter()
            .find(|b| b.header.core.height == height)
            .cloned()
    }

    pub async fn get_block_by_hash(&self, hash: &Hash) -> Option<Block> {
        let blocks = self.blocks.read().await;
        blocks.iter().find(|b| b.hash == *hash).cloned()
    }

    pub async fn get_current_epoch(&self) -> EpochInfo {
        self.current_epoch.read().await.clone()
    }

    pub fn get_config(&self) -> &ShardConfig {
        &self.config
    }

    pub async fn start_background_tasks(self: Arc<Self>) {
        let manager = Arc::clone(&self);
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                let metrics = manager.metrics.read().await;
                let _ = metrics;
            }
        });

        let manager = Arc::clone(&self);
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
            }
        });

        let manager = Arc::clone(&self);
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(3600));
            loop {
                interval.tick().await;
                let state = manager.state.read().await;
                if state.should_prune() {
                    drop(state);
                    let mut state = manager.state.write().await;
                    let current_epoch = state.get_current_epoch();
                    let _ = state.prune_old_data(current_epoch);
                }
            }
        });
    }

    pub async fn validate_cellular_safe(&self, tx: &Transaction) -> EgoResult<()> {
        if !self.config.cellular_safe_config.enabled {
            return Ok(());
        }

        let state = self.state.read().await;
        let account = state
            .get_account(&tx.from)
            .ok_or(EgoError::AccountNotFound {
                account_id: tx.from.to_string(),
            })?;

        if !account.is_cellular_safe() {
            return Ok(());
        }

        match &tx.payload {
            TransactionPayload::StoreData { data_size, .. } => {
                let size_gb = *data_size / (1024 * 1024 * 1024);
                if size_gb > 0 && !account.within_data_limits(size_gb) {
                    return Err(EgoError::InvalidTransaction(
                        "Transaction exceeds cellular data limits".to_string(),
                    ));
                }
            }
            TransactionPayload::SubmitProofBatch { proofs, .. } => {
                if proofs.len() > self.config.cellular_safe_config.proof_batch_size as usize {
                    return Err(EgoError::InvalidTransaction(
                        "Proof batch size exceeds cellular-safe limit".to_string(),
                    ));
                }
            }
            _ => {}
        }

        Ok(())
    }

    pub async fn validate_pq_transition(&self, tx: &Transaction) -> EgoResult<()> {
        let current_epoch = self.state.read().await.get_current_epoch();

        if self.config.pq_transition_config.pq_only_required {
            if tx.signature.ed25519_sig.is_some() {
                if let Some(deadline) = self.config.pq_transition_config.legacy_deadline_epoch {
                    if current_epoch >= deadline {
                        return Err(EgoError::InvalidTransaction(
                            "Ed25519 signatures no longer accepted after deadline".to_string(),
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

pub fn create_test_shard_config(shard_id: u32) -> ShardConfig {
    ShardConfig {
        shard_id: ShardId::new(shard_id).unwrap(),
        committee_size: 7,
        max_txs_per_block: 1000,
        target_block_time_ms: 2000,
        epoch_duration_blocks: 100,
        ..Default::default()
    }
}
