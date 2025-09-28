use crate::{
    Block, BlockHeight, EgoResult, Hash, ShardId, StateManager, Timestamp, Transaction,
    TransactionResult,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardStorageConfig {
    pub max_storage_per_node: u64,
    pub proof_frequency: u64,
    pub retention_period: u64,
    pub erasure_coding: ErasureCodingConfig,
    pub gc_config: GarbageCollectionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureCodingConfig {
    pub data_chunks: u8,
    pub parity_chunks: u8,
    pub chunk_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GarbageCollectionConfig {
    pub frequency: u64,
    pub threshold: f64,
    pub aggressive_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoConstraints {
    pub allowed_regions: Vec<String>,
    pub max_latency_ms: u32,
    pub min_nodes_per_region: u32,
}

#[derive(Debug)]
pub struct ShardManager {
    pub config: ShardConfig,
    pub state: Arc<RwLock<StateManager>>,
    blocks: Arc<RwLock<VecDeque<Block>>>,
    pub current_epoch: EpochInfo,
    tx_pool: Arc<RwLock<TransactionPool>>,
    cross_shard_state: CrossShardManager,
    metrics: ShardMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochInfo {
    pub epoch_number: u64,
    pub start_block: crate::BlockHeight,
    pub end_block: crate::BlockHeight,
    pub start_time: Timestamp,
    pub committee: Vec<crate::Address>,
    pub leader_schedule: Vec<crate::Address>,
    pub stats: EpochStats,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EpochStats {
    pub blocks_produced: u64,
    pub transactions_processed: u64,
    pub avg_block_time_ms: u64,
    pub cross_shard_txs: u64,
    pub storage_proofs_verified: u64,
    pub network_utilization: f64,
}

#[derive(Debug, Default)]
pub struct TransactionPool {
    pending: HashMap<u8, VecDeque<Transaction>>,
    by_hash: HashMap<Hash, Transaction>,
    stats: PoolStats,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PoolStats {
    pub pending_count: usize,
    pub pool_size_bytes: u64,
    pub avg_tx_age_ms: u64,
    pub txs_added: u64,
    pub txs_removed: u64,
}

#[derive(Debug)]
pub struct CrossShardManager {
    outbound_receipts: HashMap<ShardId, VecDeque<crate::block::CrossShardReceipt>>,
    inbound_receipts: HashMap<ShardId, VecDeque<crate::block::CrossShardReceipt>>,
    receipt_acks: HashMap<Hash, bool>,
    stats: CrossShardStats,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CrossShardStats {
    pub receipts_sent: u64,
    pub receipts_received: u64,
    pub receipts_pending: u64,
    pub avg_receipt_latency_ms: u64,
    pub failed_receipts: u64,
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
    pub last_updated: Timestamp,
}

impl Default for ShardConfig {
    fn default() -> Self {
        Self {
            shard_id: ShardId::new(0).unwrap(),
            committee_size: 21,
            replication_factor: 3,
            max_txs_per_block: crate::MAX_TXS_PER_BLOCK as u32,
            target_block_time_ms: crate::TARGET_BLOCK_TIME_MS,
            micro_slot_duration_ms: 100,
            epoch_duration_blocks: 1000,
            cross_shard_enabled: true,
            storage_config: ShardStorageConfig::default(),
            preferred_slices: Vec::new(),
            geo_constraints: None,
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
        }
    }
}

impl Default for ErasureCodingConfig {
    fn default() -> Self {
        Self {
            data_chunks: 4,
            parity_chunks: 2,
            chunk_size: 1024 * 1024,
        }
    }
}

impl Default for GarbageCollectionConfig {
    fn default() -> Self {
        Self {
            frequency: 1000,
            threshold: 0.8,
            aggressive_mode: false,
        }
    }
}

impl ShardManager {
    pub fn new(config: ShardConfig) -> Self {
        let state = Arc::new(RwLock::new(StateManager::new()));
        let blocks = Arc::new(RwLock::new(VecDeque::new()));
        let tx_pool = Arc::new(RwLock::new(TransactionPool::new()));

        let current_epoch = EpochInfo {
            epoch_number: 0,
            start_block: BlockHeight::GENESIS,
            end_block: BlockHeight::new(config.epoch_duration_blocks),
            start_time: Timestamp::now(),
            committee: Vec::new(),
            leader_schedule: Vec::new(),
            stats: EpochStats::default(),
        };

        Self {
            config,
            state,
            blocks,
            current_epoch,
            tx_pool,
            cross_shard_state: CrossShardManager::new(),
            metrics: ShardMetrics::default(),
        }
    }

    pub async fn add_transaction(&self, tx: Transaction) -> EgoResult<()> {
        let mut pool = self.tx_pool.write().await;
        pool.add_transaction(tx)?;
        Ok(())
    }

    pub async fn get_transactions_for_block(&self, max_count: usize) -> Vec<Transaction> {
        let mut pool = self.tx_pool.write().await;
        pool.get_transactions_for_block(max_count)
    }

    pub async fn process_block(&mut self, mut block: Block) -> EgoResult<()> {
        block.validate_structure()?;

        let mut transaction_results = Vec::new();
        {
            let mut state = self.state.write().await;

            for tx in &block.body.transactions {
                match state.execute_transaction(tx) {
                    Ok(mut result) => {
                        result.tx_hash = tx.hash;
                        transaction_results.push(result);
                    }
                    Err(e) => {
                        transaction_results.push(TransactionResult {
                            tx_hash: tx.hash,
                            success: false,
                            error: Some(e.to_string()),
                            compute_used: 0,
                            storage_used: 0,
                            state_changes: Vec::new(),
                            events: Vec::new(),
                            cross_shard_receipts: Vec::new(),
                        });
                    }
                }
            }

            let new_state_root = state.compute_state_root();
            block.set_state_root(new_state_root);

            state.set_block_height(block.header.core.height);
        }

        block.add_transaction_results(transaction_results);

        self.update_metrics(&block).await;

        {
            let mut blocks = self.blocks.write().await;
            blocks.push_back(block.clone());

            while blocks.len() > 1000 {
                blocks.pop_front();
            }
        }

        {
            let mut pool = self.tx_pool.write().await;
            for tx in &block.body.transactions {
                pool.remove_transaction(&tx.hash);
            }
        }

        if block.header.core.height.as_u64() >= self.current_epoch.end_block.as_u64() {
            self.start_new_epoch(block.header.core.height.next())
                .await?;
        }

        Ok(())
    }

    async fn start_new_epoch(&mut self, start_block: BlockHeight) -> EgoResult<()> {
        let new_epoch_number = self.current_epoch.epoch_number + 1;
        let end_block = BlockHeight::new(start_block.as_u64() + self.config.epoch_duration_blocks);

        self.current_epoch = EpochInfo {
            epoch_number: new_epoch_number,
            start_block,
            end_block,
            start_time: Timestamp::now(),
            committee: self.select_committee().await,
            leader_schedule: Vec::new(),
            stats: EpochStats::default(),
        };

        Ok(())
    }

    async fn select_committee(&self) -> Vec<crate::Address> {
        Vec::new()
    }

    async fn update_metrics(&mut self, block: &Block) {
        let now = Timestamp::now();

        let block_time_ms = self.config.target_block_time_ms as f64 / 1000.0;
        self.metrics.tps = block.header.core.tx_count as f64 / block_time_ms;

        self.metrics.bps = 1.0 / block_time_ms;

        let state = self.state.read().await;
        let stats = state.get_stats();
        self.metrics.storage_utilization = stats.total_storage_bytes as f64
            / self.config.storage_config.max_storage_per_node as f64;

        self.metrics.last_updated = now;
    }

    pub async fn get_stats(&self) -> ShardStats {
        let state = self.state.read().await;
        let state_stats = state.get_stats();
        let pool = self.tx_pool.read().await;
        let pool_stats = pool.get_stats();
        let blocks = self.blocks.read().await;

        ShardStats {
            shard_id: self.config.shard_id,
            current_block_height: state.get_block_height(),
            current_epoch: self.current_epoch.clone(),
            state_stats,
            pool_stats,
            metrics: self.metrics.clone(),
            blocks_stored: blocks.len() as u64,
            cross_shard_stats: self.cross_shard_state.get_stats(),
        }
    }

    pub async fn get_recent_blocks(&self, count: usize) -> Vec<Block> {
        let blocks = self.blocks.read().await;
        blocks.iter().rev().take(count).cloned().collect()
    }
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
}

impl TransactionPool {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            by_hash: HashMap::new(),
            stats: PoolStats::default(),
        }
    }

    pub fn add_transaction(&mut self, tx: Transaction) -> EgoResult<()> {
        if self.by_hash.contains_key(&tx.hash) {
            return Ok(());
        }

        let priority = self.calculate_priority(&tx);

        self.pending
            .entry(priority)
            .or_insert_with(VecDeque::new)
            .push_back(tx.clone());

        self.by_hash.insert(tx.hash, tx);

        self.stats.pending_count = self.by_hash.len();
        self.stats.txs_added += 1;

        Ok(())
    }

    pub fn remove_transaction(&mut self, tx_hash: &Hash) {
        if let Some(tx) = self.by_hash.remove(tx_hash) {
            let priority = self.calculate_priority(&tx);

            if let Some(queue) = self.pending.get_mut(&priority) {
                queue.retain(|t| t.hash != *tx_hash);
                if queue.is_empty() {
                    self.pending.remove(&priority);
                }
            }

            self.stats.pending_count = self.by_hash.len();
            self.stats.txs_removed += 1;
        }
    }

    pub fn get_transactions_for_block(&mut self, max_count: usize) -> Vec<Transaction> {
        let mut transactions = Vec::new();
        let mut count = 0;

        let mut priorities: Vec<u8> = self.pending.keys().cloned().collect();
        priorities.sort_by(|a, b| b.cmp(a));

        for priority in priorities {
            if count >= max_count {
                break;
            }

            if let Some(queue) = self.pending.get_mut(&priority) {
                while let Some(tx) = queue.pop_front() {
                    transactions.push(tx);
                    count += 1;

                    if count >= max_count {
                        break;
                    }
                }

                if queue.is_empty() {
                    self.pending.remove(&priority);
                }
            }
        }

        transactions
    }

    fn calculate_priority(&self, tx: &Transaction) -> u8 {
        match &tx.payload {
            crate::TransactionPayload::SystemOperation { .. } => 255,
            crate::TransactionPayload::CrossShard { .. } => 200,
            crate::TransactionPayload::SubmitProof { .. } => 150,
            crate::TransactionPayload::RollupCommit { .. } => 100,
            crate::TransactionPayload::Transfer { .. } => 50,
            _ => 25,
        }
    }

    pub fn get_stats(&self) -> PoolStats {
        self.stats.clone()
    }
}

impl CrossShardManager {
    pub fn new() -> Self {
        Self {
            outbound_receipts: HashMap::new(),
            inbound_receipts: HashMap::new(),
            receipt_acks: HashMap::new(),
            stats: CrossShardStats::default(),
        }
    }

    pub fn get_stats(&self) -> CrossShardStats {
        self.stats.clone()
    }
}
