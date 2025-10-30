use crate::batch::{BatchBuilder, BatchProcessor, RollupBatch};
use crate::commitment::{CommitmentManager, RollupCommitment};
use crate::config::RollupConfig;
use crate::da::{DAChunk, DataAvailability};
use crate::error::{RollupError, RollupResult};
use crate::metrics::RollupMetrics;
use crate::state::RollupState;
use crate::types::{OperatorInfo, RollupTransaction};
use ego_core::{Address, Hash, KeyPair, Timestamp};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use tokio::time::{Duration, Instant, interval};
use tracing::{debug, error, info, warn};

pub struct RollupOperator {
    config: RollupConfig,
    keypair: Arc<KeyPair>,
    address: Address,
    state: Arc<RwLock<RollupState>>,
    da_manager: Arc<RwLock<DataAvailability>>,
    commitment_manager: Arc<RwLock<CommitmentManager>>,
    batch_processor: Arc<BatchProcessor>,

    tx_pool: Arc<RwLock<VecDeque<RollupTransaction>>>,
    pending_batches: Arc<RwLock<HashMap<Hash, RollupBatch>>>,

    metrics: Arc<RwLock<RollupMetrics>>,

    tx_receiver: Option<mpsc::UnboundedReceiver<RollupTransaction>>,
    batch_sender: Option<mpsc::UnboundedSender<RollupBatch>>,

    is_active: Arc<RwLock<bool>>,
    bond_amount: u64,
    last_commit_time: Arc<RwLock<Option<Timestamp>>>,

    edge_nodes: Vec<String>,
    current_slice: Option<String>,
}

pub struct OperatorNode {
    operator: RollupOperator,
    network_handle: Option<tokio::task::JoinHandle<()>>,
    batch_handle: Option<tokio::task::JoinHandle<()>>,
    commit_handle: Option<tokio::task::JoinHandle<()>>,
}

impl RollupOperator {
    pub fn new(
        config: RollupConfig,
        keypair: KeyPair,
        state: RollupState,
        bond_amount: u64,
    ) -> RollupResult<Self> {
        let address = Address::from_public_key(&keypair.public_key());

        let da_manager = DataAvailability::new(
            config.da.k,
            config.da.m,
            config.da.chunk_size,
            config.da.enable_compression,
            config.da.compression_level,
        )?;

        let commitment_manager = CommitmentManager::new(
            da_manager.clone(),
            config.fraud_proofs.challenge_period,
            config.fraud_proofs.response_window,
        );

        let state_arc = Arc::new(RwLock::new(state));
        let batch_processor = BatchProcessor::new(state_arc.clone(), config.clone());

        Ok(Self {
            config: config.clone(),
            keypair: Arc::new(keypair),
            address,
            state: state_arc,
            da_manager: Arc::new(RwLock::new(da_manager)),
            commitment_manager: Arc::new(RwLock::new(commitment_manager)),
            batch_processor: Arc::new(batch_processor),
            tx_pool: Arc::new(RwLock::new(VecDeque::new())),
            pending_batches: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(RollupMetrics::default())),
            tx_receiver: None,
            batch_sender: None,
            is_active: Arc::new(RwLock::new(false)),
            bond_amount,
            last_commit_time: Arc::new(RwLock::new(None)),
            edge_nodes: config.five_g.edge_nodes.clone(),
            current_slice: config.five_g.slice_id.clone(),
        })
    }

    pub async fn start(&mut self) -> RollupResult<()> {
        info!("Starting rollup operator {}", self.address);

        self.config.validate()?;

        if self.bond_amount < self.config.operator.bond_amount {
            return Err(RollupError::InsufficientBond {
                required: self.config.operator.bond_amount,
                available: self.bond_amount,
            });
        }

        let (_tx_sender, tx_receiver) = mpsc::unbounded_channel();
        let (batch_sender, _batch_receiver) = mpsc::unbounded_channel();

        self.tx_receiver = Some(tx_receiver);
        self.batch_sender = Some(batch_sender);

        {
            let mut is_active = self.is_active.write().await;
            *is_active = true;
        }

        info!("✅ Rollup operator {} started successfully", self.address);
        Ok(())
    }

    pub async fn stop(&mut self) -> RollupResult<()> {
        info!("Stopping rollup operator {}", self.address);

        {
            let mut is_active = self.is_active.write().await;
            *is_active = false;
        }

        self.flush_pending_transactions().await?;

        self.tx_receiver = None;
        self.batch_sender = None;

        info!("✅ Rollup operator {} stopped", self.address);
        Ok(())
    }

    pub async fn submit_transaction(&self, tx: RollupTransaction) -> RollupResult<Hash> {
        if !tx.inner.verify_signature()? {
            return Err(RollupError::InvalidBatch(
                "Invalid transaction signature".to_string(),
            ));
        }

        {
            let mut pool = self.tx_pool.write().await;
            pool.push_back(tx.clone());

            if pool.len() > self.config.performance.tx_pool_size {
                pool.pop_front();
                warn!("Transaction pool full, dropping oldest transaction");
            }
        }

        {
            let mut metrics = self.metrics.write().await;
            metrics.transactions_received += 1;
        }

        Ok(tx.hash())
    }

    pub async fn process_transactions(&self) -> RollupResult<()> {
        let mut builder =
            BatchBuilder::new(self.address, self.config.operator.max_batch_size, 1_000_000);

        let mut processed_count = 0;
        let batch_start = Instant::now();

        {
            let mut pool = self.tx_pool.write().await;

            while let Some(tx) = pool.pop_front() {
                if builder.can_add_transaction(&tx) {
                    if builder.add_transaction(tx)? {
                        processed_count += 1;
                    }
                } else {
                    pool.push_front(tx);
                    break;
                }

                if batch_start.elapsed()
                    > Duration::from_secs(self.config.operator.batch_timeout_secs)
                {
                    break;
                }

                if self.config.five_g.enabled && builder.is_5g_ready() {
                    break;
                }
            }
        }

        if processed_count > 0 {
            self.create_and_process_batch(builder).await?;
        }

        Ok(())
    }

    async fn create_and_process_batch(&self, builder: BatchBuilder) -> RollupResult<()> {
        let current_block = 1000;
        let prev_state_root = {
            let state = self.state.read().await;
            state.compute_state_root()
        };

        let batch = builder.build(current_block, prev_state_root)?;
        let batch_hash = batch.hash();

        info!(
            "Processing batch {} with {} transactions",
            batch_hash,
            batch.transactions.len()
        );

        let processed_batch = if self.config.five_g.enabled {
            self.batch_processor.process_batch_5g(batch).await?
        } else {
            self.batch_processor.process_batch(batch).await?
        };

        {
            let mut pending = self.pending_batches.write().await;
            pending.insert(batch_hash, processed_batch.clone());
        }

        let da_chunks = self.create_da_chunks(&processed_batch).await?;

        let commitment = self.create_commitment(&processed_batch, &da_chunks).await?;

        self.post_commitment(commitment, da_chunks).await?;

        {
            let mut metrics = self.metrics.write().await;
            metrics.batches_built += 1;
            metrics.transactions_processed += processed_batch.transactions.len() as u64;
        }

        Ok(())
    }

    async fn create_da_chunks(&self, batch: &RollupBatch) -> RollupResult<Vec<DAChunk>> {
        let config = bincode::config::standard();
        let batch_data = bincode::encode_to_vec(batch, config)
            .map_err(|e| RollupError::SerializationError(e.to_string()))?;

        let mut da_manager = self.da_manager.write().await;
        da_manager.encode_data(batch.batch_id, batch_data)
    }

    async fn create_commitment(
        &self,
        batch: &RollupBatch,
        da_chunks: &[DAChunk],
    ) -> RollupResult<RollupCommitment> {
        let chunk_hashes: Vec<Vec<u8>> = da_chunks
            .iter()
            .map(|chunk| chunk.chunk_hash.to_vec())
            .collect();

        let merkle_tree = ego_core::crypto::MerkleTree::build(chunk_hashes);
        let da_root = merkle_tree.root_hash().unwrap_or(Hash::ZERO);

        let proofs_root = Hash::new([0u8; 32]);

        let mut commitment = RollupCommitment::new(
            self.address,
            "ego-rollup".to_string(),
            batch,
            da_root,
            proofs_root,
            batch.l1_block_number,
        );

        commitment.sign(&self.keypair)?;

        Ok(commitment)
    }

    async fn post_commitment(
        &self,
        commitment: RollupCommitment,
        da_chunks: Vec<DAChunk>,
    ) -> RollupResult<Hash> {
        let commitment_hash = commitment.commitment_hash;

        {
            let mut manager = self.commitment_manager.write().await;
            manager.submit_commitment(commitment, da_chunks)?;
        }

        {
            let mut last_commit = self.last_commit_time.write().await;
            *last_commit = Some(Timestamp::now());
        }

        {
            let mut metrics = self.metrics.write().await;
            metrics.commits_posted += 1;
        }

        info!("Posted commitment {}", commitment_hash);
        Ok(commitment_hash)
    }

    async fn flush_pending_transactions(&self) -> RollupResult<()> {
        let pool_size = {
            let pool = self.tx_pool.read().await;
            pool.len()
        };

        if pool_size > 0 {
            info!("Flushing {} pending transactions", pool_size);
            self.process_transactions().await?;
        }

        Ok(())
    }

    pub async fn get_operator_info(&self) -> OperatorInfo {
        let metrics = self.metrics.read().await;
        let last_commit = self.last_commit_time.read().await;
        let is_active = self.is_active.read().await;

        OperatorInfo {
            address: self.address,
            bond_amount: self.bond_amount,
            is_active: *is_active,
            last_commit: *last_commit,
            total_commits: metrics.commits_posted,
            successful_challenges: 0,
            failed_challenges: 0,
            slash_count: 0,
            reputation_score: 1.0,
        }
    }

    pub async fn get_metrics(&self) -> RollupMetrics {
        self.metrics.read().await.clone()
    }

    pub async fn handle_challenge(
        &self,
        commitment_hash: Hash,
        challenge_hash: Hash,
    ) -> RollupResult<()> {
        info!(
            "Handling challenge {} for commitment {}",
            challenge_hash, commitment_hash
        );

        {
            let mut metrics = self.metrics.write().await;
            metrics.commits_challenged += 1;
        }

        Ok(())
    }

    pub fn is_5g_optimized(&self) -> bool {
        self.config.five_g.enabled && self.current_slice.is_some()
    }

    pub fn target_latency(&self) -> Duration {
        self.config.target_latency()
    }

    pub async fn switch_slice(&mut self, slice_id: String) -> RollupResult<()> {
        if !self.config.five_g.enabled {
            return Err(RollupError::ConfigError("5G not enabled".to_string()));
        }

        self.current_slice = Some(slice_id.clone());
        info!("Switched to 5G slice: {}", slice_id);
        Ok(())
    }
}

impl OperatorNode {
    pub fn new(operator: RollupOperator) -> Self {
        Self {
            operator,
            network_handle: None,
            batch_handle: None,
            commit_handle: None,
        }
    }

    pub async fn start(&mut self) -> RollupResult<()> {
        self.operator.start().await?;

        // Start background tasks
        self.start_batch_processing().await?;
        self.start_commit_scheduling().await?;

        Ok(())
    }

    pub async fn stop(&mut self) -> RollupResult<()> {
        if let Some(handle) = self.batch_handle.take() {
            handle.abort();
        }
        if let Some(handle) = self.commit_handle.take() {
            handle.abort();
        }
        if let Some(handle) = self.network_handle.take() {
            handle.abort();
        }

        self.operator.stop().await?;
        Ok(())
    }

    async fn start_batch_processing(&mut self) -> RollupResult<()> {
        let operator = self.operator.clone();
        let batch_timeout = Duration::from_secs(operator.config.operator.batch_timeout_secs);

        let handle = tokio::spawn(async move {
            let mut interval = interval(batch_timeout);

            loop {
                interval.tick().await;

                if let Err(e) = operator.process_transactions().await {
                    error!("Batch processing error: {}", e);
                }
            }
        });

        self.batch_handle = Some(handle);
        Ok(())
    }

    async fn start_commit_scheduling(&mut self) -> RollupResult<()> {
        let operator = self.operator.clone();
        let commit_frequency = Duration::from_secs(operator.config.operator.commit_frequency_secs);

        let handle = tokio::spawn(async move {
            let mut interval = interval(commit_frequency);

            loop {
                interval.tick().await;

                let pending_count = {
                    let pending = operator.pending_batches.read().await;
                    pending.len()
                };

                if pending_count > 0 {
                    debug!("Scheduled commit check: {} pending batches", pending_count);
                }
            }
        });

        self.commit_handle = Some(handle);
        Ok(())
    }

    pub async fn submit_transaction(&self, tx: RollupTransaction) -> RollupResult<Hash> {
        self.operator.submit_transaction(tx).await
    }

    pub async fn get_operator_info(&self) -> OperatorInfo {
        self.operator.get_operator_info().await
    }

    pub async fn get_metrics(&self) -> RollupMetrics {
        self.operator.get_metrics().await
    }
}

impl Clone for RollupOperator {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            keypair: self.keypair.clone(),
            address: self.address,
            state: self.state.clone(),
            da_manager: self.da_manager.clone(),
            commitment_manager: self.commitment_manager.clone(),
            batch_processor: self.batch_processor.clone(),
            tx_pool: self.tx_pool.clone(),
            pending_batches: self.pending_batches.clone(),
            metrics: self.metrics.clone(),
            tx_receiver: None,
            batch_sender: None,
            is_active: self.is_active.clone(),
            bond_amount: self.bond_amount,
            last_commit_time: self.last_commit_time.clone(),
            edge_nodes: self.edge_nodes.clone(),
            current_slice: self.current_slice.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::{Balance, KeyPair, ShardId, Transaction, TransactionPayload};

    fn create_test_config() -> RollupConfig {
        RollupConfig::default()
    }

    fn create_test_transaction() -> RollupTransaction {
        let inner = Transaction::new(
            Address::new([1u8; 20]),
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

        crate::types::RollupTransaction::new(inner, 1, 1000)
    }

    #[tokio::test]
    async fn test_operator_creation() {
        let config = create_test_config();
        let keypair = KeyPair::generate();
        let state = RollupState::new();

        let operator = RollupOperator::new(config, keypair, state, 1_000_000).unwrap();
        assert_eq!(operator.bond_amount, 1_000_000);
        assert!(!operator.is_5g_optimized());
    }

    #[tokio::test]
    async fn test_operator_start_stop() {
        let config = create_test_config();
        let keypair = KeyPair::generate();
        let state = RollupState::new();

        let mut operator = RollupOperator::new(config, keypair, state, 1_000_000).unwrap();

        assert!(operator.start().await.is_ok());
        assert!(operator.stop().await.is_ok());
    }

    #[tokio::test]
    async fn test_transaction_submission() {
        let config = create_test_config();
        let keypair = KeyPair::generate();
        let state = RollupState::new();

        let mut operator = RollupOperator::new(config, keypair, state, 1_000_000).unwrap();
        operator.start().await.unwrap();

        let tx = create_test_transaction();
        let tx_hash = operator.submit_transaction(tx).await.unwrap();

        assert_ne!(tx_hash, Hash::ZERO);

        let metrics = operator.get_metrics().await;
        assert_eq!(metrics.transactions_received, 1);
    }

    #[tokio::test]
    async fn test_operator_node() {
        let config = create_test_config();
        let keypair = KeyPair::generate();
        let state = RollupState::new();

        let operator = RollupOperator::new(config, keypair, state, 1_000_000).unwrap();
        let mut node = OperatorNode::new(operator);

        assert!(node.start().await.is_ok());
        assert!(node.stop().await.is_ok());
    }

    #[tokio::test]
    async fn test_5g_optimization() {
        let mut config = create_test_config();
        config.five_g.enabled = true;
        config.five_g.slice_id = Some("test-slice".to_string());

        let keypair = KeyPair::generate();
        let state = RollupState::new();

        let operator = RollupOperator::new(config, keypair, state, 1_000_000).unwrap();
        assert!(operator.is_5g_optimized());
        assert_eq!(operator.target_latency(), Duration::from_millis(10));
    }
}
