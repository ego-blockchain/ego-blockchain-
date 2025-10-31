use crate::batch::{BatchBuilder, BatchProcessor, RollupBatch};
use crate::commitment::{CommitmentManager, RollupCommitment};
use crate::config::RollupConfig;
use crate::da::{DAChunk, DataAvailability};
use crate::error::{RollupError, RollupResult};
use crate::metrics::{PerformanceTracker, RollupMetrics, SystemAlerts};
use crate::state::RollupState;
use crate::types::{OperatorInfo, RollupTransaction};
use ego_core::{Address, Hash, ShardId, Timestamp};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio::time::{Duration, Instant, interval};
use tracing::{debug, error, info, warn};

pub struct RollupOperator {
    config: RollupConfig,
    keypair: Arc<ego_core::crypto::KeyPair>,
    address: Address,
    state: Arc<RwLock<RollupState>>,
    da_manager: Arc<RwLock<DataAvailability>>,
    commitment_manager: Arc<RwLock<CommitmentManager>>,
    batch_processor: Arc<BatchProcessor>,
    tx_pool: Arc<RwLock<VecDeque<RollupTransaction>>>,
    pending_batches: Arc<RwLock<HashMap<Hash, RollupBatch>>>,
    finalized_batches: Arc<RwLock<HashMap<Hash, RollupBatch>>>,
    metrics: Arc<RwLock<RollupMetrics>>,
    performance_tracker: Arc<Mutex<PerformanceTracker>>,
    alerts: Arc<RwLock<SystemAlerts>>,
    tx_receiver: Option<mpsc::UnboundedReceiver<RollupTransaction>>,
    batch_sender: Option<mpsc::UnboundedSender<RollupBatch>>,
    commitment_sender: Option<mpsc::UnboundedSender<RollupCommitment>>,
    is_active: Arc<RwLock<bool>>,
    bond_amount: u64,
    last_commit_time: Arc<RwLock<Option<Timestamp>>>,
    last_batch_time: Arc<RwLock<Option<Timestamp>>>,
    edge_nodes: Vec<String>,
    current_slice: Option<String>,
    shard_id: ShardId,
    epoch: Arc<RwLock<u64>>,
    connection_type: Arc<RwLock<ConnectionType>>,
    cellular_data_used_mb: Arc<RwLock<u64>>,
    successful_challenges: Arc<RwLock<u64>>,
    failed_challenges: Arc<RwLock<u64>>,
    slash_count: Arc<RwLock<u64>>,
}

pub struct OperatorNode {
    operator: Arc<RollupOperator>,
    network_handle: Option<tokio::task::JoinHandle<()>>,
    batch_handle: Option<tokio::task::JoinHandle<()>>,
    commit_handle: Option<tokio::task::JoinHandle<()>>,
    metrics_handle: Option<tokio::task::JoinHandle<()>>,
    cellular_monitor_handle: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionType {
    Cellular5G,
    Cellular4G,
    WiFi,
    Ethernet,
    Unknown,
}

impl RollupOperator {
    pub fn new(
        config: RollupConfig,
        keypair: ego_core::crypto::KeyPair,
        state: RollupState,
        bond_amount: u64,
        shard_id: ShardId,
    ) -> RollupResult<Self> {
        let address = Address::from_public_key(&keypair.dilithium_public_key());

        let da_manager = DataAvailability::new(
            config.da.k as usize,
            config.da.m as usize,
            config.da.chunk_size,
            config.da.enable_compression,
            config.da.compression_level,
        )?;

        let commitment_manager = CommitmentManager::new(
            da_manager.clone(),
            config.fraud_proofs.challenge_period_blocks,
            config.fraud_proofs.response_window_blocks,
            config.chain_id,
            config.network_id,
            config.fraud_proofs.fraud_proof_window_blocks,
        );

        let state_arc = Arc::new(RwLock::new(state));
        let batch_processor =
            BatchProcessor::new(state_arc.clone(), config.clone(), Arc::new(keypair.clone()));

        let connection_type = if config.five_g.enabled {
            ConnectionType::Cellular5G
        } else {
            ConnectionType::WiFi
        };

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
            finalized_batches: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(RollupMetrics::default())),
            performance_tracker: Arc::new(Mutex::new(PerformanceTracker::new(1000))),
            alerts: Arc::new(RwLock::new(SystemAlerts::new())),
            tx_receiver: None,
            batch_sender: None,
            commitment_sender: None,
            is_active: Arc::new(RwLock::new(false)),
            bond_amount,
            last_commit_time: Arc::new(RwLock::new(None)),
            last_batch_time: Arc::new(RwLock::new(None)),
            edge_nodes: config.five_g.edge_nodes.clone(),
            current_slice: config.five_g.slice_id.clone(),
            shard_id,
            epoch: Arc::new(RwLock::new(0)),
            connection_type: Arc::new(RwLock::new(connection_type)),
            cellular_data_used_mb: Arc::new(RwLock::new(0)),
            successful_challenges: Arc::new(RwLock::new(0)),
            failed_challenges: Arc::new(RwLock::new(0)),
            slash_count: Arc::new(RwLock::new(0)),
        })
    }

    pub async fn start(&mut self) -> RollupResult<()> {
        info!(
            "Starting rollup operator {} on shard {}",
            self.address,
            self.shard_id.as_u32()
        );

        self.config.validate()?;

        if (self.bond_amount as u128) < self.config.operator.bond_amount.as_u128() {
            return Err(RollupError::InsufficientBond {
                required: self.config.operator.bond_amount.as_u128() as u64,
                available: self.bond_amount,
            });
        }

        let (_tx_sender, tx_receiver) = mpsc::unbounded_channel();
        let (batch_sender, _batch_receiver) = mpsc::unbounded_channel();
        let (commitment_sender, _commitment_receiver) = mpsc::unbounded_channel();

        self.tx_receiver = Some(tx_receiver);
        self.batch_sender = Some(batch_sender);
        self.commitment_sender = Some(commitment_sender);

        {
            let mut is_active = self.is_active.write().await;
            *is_active = true;
        }

        if self.config.five_g.cellular_safe_mode {
            info!(
                "✅ Cellular safe mode enabled with {} MB/month limit",
                self.config.five_g.max_cellular_data_gb_per_month * 1024
            );
        }

        if self.config.security.require_dilithium {
            info!("✅ PQ-only mode: Dilithium-2 signatures required");
        }

        info!(
            "✅ Rollup operator {} started successfully on shard {}",
            self.address,
            self.shard_id.as_u32()
        );
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
        self.commitment_sender = None;

        let metrics = self.metrics.read().await;
        info!(
            "Final operator stats: {} batches, {} commits, {} transactions",
            metrics.batches_processed, metrics.commits_posted, metrics.transactions_processed
        );

        info!("✅ Rollup operator {} stopped", self.address);
        Ok(())
    }

    pub async fn submit_transaction(&self, tx: RollupTransaction) -> RollupResult<Hash> {
        let start_time = Instant::now();

        if !tx.inner.verify_signature()? {
            return Err(RollupError::InvalidBatch(
                "Invalid transaction signature".to_string(),
            ));
        }

        if self.config.security.require_dilithium && tx.inner.signature.dilithium_sig.is_none() {
            return Err(RollupError::InvalidBatch(
                "Dilithium signature required in PQ-only mode".to_string(),
            ));
        }

        if tx.inner.chain_id != self.config.chain_id {
            return Err(RollupError::InvalidBatch(format!(
                "Chain ID mismatch: expected {}, got {}",
                self.config.chain_id, tx.inner.chain_id
            )));
        }

        if tx.inner.shard_id != self.shard_id {
            return Err(RollupError::InvalidBatch(
                "Transaction shard mismatch".to_string(),
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

            let verification_time = start_time.elapsed().as_millis() as u64;
            let has_dilithium = tx.inner.signature.dilithium_sig.is_some();
            let has_ed25519 = tx.inner.signature.ed25519_sig.is_some();
            metrics.record_signature(has_dilithium, has_ed25519, verification_time);
        }

        {
            let mut tracker = self.performance_tracker.lock().await;
            tracker.end_timing("tx_submission");
        }

        Ok(tx.hash())
    }

    pub async fn process_transactions(&self) -> RollupResult<()> {
        let mut tracker = self.performance_tracker.lock().await;
        tracker.start_timing("batch_processing");
        drop(tracker);

        let mut builder = BatchBuilder::new(
            self.address,
            self.config.operator.max_batch_size,
            self.config.operator.max_gas_limit,
            self.config.chain_id,
            self.config.network_id,
            self.shard_id,
        );

        let mut processed_count = 0;
        let batch_start = Instant::now();
        let is_cellular = self.is_on_cellular().await;

        {
            let mut pool = self.tx_pool.write().await;

            while let Some(tx) = pool.pop_front() {
                if builder.can_add_transaction(&tx) {
                    match builder.add_transaction(tx.clone()) {
                        Ok(added) => {
                            if added {
                                processed_count += 1;
                            } else {
                                pool.push_front(tx);
                                break;
                            }
                        }
                        Err(e) => {
                            warn!("Failed to add transaction to batch: {}", e);
                            let mut metrics = self.metrics.write().await;
                            metrics.transactions_failed += 1;
                            metrics.record_error("tx_add_failed");
                        }
                    }
                } else {
                    pool.push_front(tx);
                    break;
                }

                if batch_start.elapsed() > self.config.get_batch_timeout() {
                    debug!("Batch timeout reached");
                    break;
                }

                if is_cellular && self.config.five_g.cellular_safe_mode {
                    if builder.is_cellular_safe() {
                        debug!("Cellular safe batch size reached");
                        break;
                    }
                } else if self.config.five_g.enabled && builder.is_5g_ready() {
                    debug!("5G optimized batch size reached");
                    break;
                }
            }
        }

        if processed_count > 0 {
            self.create_and_process_batch(builder, batch_start).await?;
        } else {
            debug!("No transactions to process");
        }

        let mut tracker = self.performance_tracker.lock().await;
        tracker.end_timing("batch_processing");

        Ok(())
    }

    async fn create_and_process_batch(
        &self,
        builder: BatchBuilder,
        batch_start: Instant,
    ) -> RollupResult<()> {
        let epoch = *self.epoch.read().await;
        let current_block = epoch * 100 + 1000;

        let prev_state_root = {
            let state = self.state.read().await;
            state.compute_state_root()
        };

        let epoch_number = ego_core::EpochNumber::new(epoch);

        let batch = builder.build(current_block, prev_state_root, epoch_number)?;
        let batch_hash = batch.hash();
        let tx_count = batch.transactions.len();

        info!(
            "Processing batch {} with {} transactions on shard {}",
            batch_hash,
            tx_count,
            self.shard_id.as_u32()
        );

        let processing_start = Instant::now();

        let processed_batch = if self.config.five_g.enabled {
            self.batch_processor.process_batch_5g(batch).await?
        } else {
            self.batch_processor.process_batch(batch).await?
        };

        let processing_time = processing_start.elapsed().as_millis() as u64;

        {
            let mut pending = self.pending_batches.write().await;
            pending.insert(batch_hash, processed_batch.clone());
        }

        let da_chunks = self.create_da_chunks(&processed_batch).await?;

        let commitment = self.create_commitment(&processed_batch, &da_chunks).await?;

        let is_cellular = self.is_on_cellular().await;
        let batch_size_bytes = processed_batch.size_bytes as u64;

        if is_cellular {
            let mut cellular_data = self.cellular_data_used_mb.write().await;
            *cellular_data += batch_size_bytes / (1024 * 1024);
        }

        self.post_commitment(commitment, da_chunks).await?;

        {
            let mut last_batch = self.last_batch_time.write().await;
            *last_batch = Some(Timestamp::now());
        }

        let total_time = batch_start.elapsed().as_millis() as u64;

        {
            let mut metrics = self.metrics.write().await;
            metrics.batches_built += 1;
            metrics.transactions_processed += tx_count as u64;
            metrics.total_ru_used += processed_batch.gas_used;

            let is_cellular_safe = processed_batch.is_cellular_safe();
            let is_5g = self.config.five_g.enabled;
            metrics.record_batch_processed(processing_time, is_cellular_safe, is_5g);
            metrics.record_data_usage(batch_size_bytes, is_cellular);

            if total_time > self.config.target_latency().as_millis() as u64 {
                metrics.latency_target_breaches += 1;
            }
        }

        info!(
            "Batch {} processed in {}ms (processing: {}ms)",
            batch_hash, total_time, processing_time
        );

        Ok(())
    }

    async fn create_da_chunks(&self, batch: &RollupBatch) -> RollupResult<Vec<DAChunk>> {
        let mut tracker = self.performance_tracker.lock().await;
        tracker.start_timing("da_encoding");
        drop(tracker);

        let config = bincode::config::standard();
        let batch_data = bincode::encode_to_vec(batch, config)
            .map_err(|e| RollupError::SerializationError(e.to_string()))?;

        let original_size = batch_data.len();

        let mut da_manager = self.da_manager.write().await;
        let epoch = *self.epoch.read().await;

        let chunks = da_manager.encode_data(
            batch.batch_id,
            batch_data,
            self.config.rollup_id.clone(),
            self.address,
            epoch,
        )?;

        let encoded_size: usize = chunks.iter().map(|c| c.data.len()).sum();

        {
            let mut metrics = self.metrics.write().await;
            metrics.record_erasure_coding(original_size, encoded_size);
            metrics.da_chunks_encoded += chunks.len() as u64;
        }

        let mut tracker = self.performance_tracker.lock().await;
        tracker.end_timing("da_encoding");

        Ok(chunks)
    }

    async fn create_commitment(
        &self,
        batch: &RollupBatch,
        da_chunks: &[DAChunk],
    ) -> RollupResult<RollupCommitment> {
        let mut tracker = self.performance_tracker.lock().await;
        tracker.start_timing("commitment_creation");
        drop(tracker);

        let chunk_hashes: Vec<Vec<u8>> = da_chunks
            .iter()
            .map(|chunk| chunk.chunk_hash.to_vec())
            .collect();

        let merkle_tree = ego_core::crypto::MerkleTree::build(chunk_hashes);
        let da_root = merkle_tree.root_hash().unwrap_or(Hash::ZERO);

        let proofs_root = Hash::new([0u8; 32]);

        let mut commitment = RollupCommitment::new(
            self.address,
            self.config.rollup_id.clone(),
            batch,
            da_root,
            proofs_root,
            batch.l1_block_number,
            self.config.fraud_proofs.fraud_proof_window_blocks,
        );

        commitment.sign(&self.keypair)?;

        let mut tracker = self.performance_tracker.lock().await;
        tracker.end_timing("commitment_creation");

        Ok(commitment)
    }

    async fn post_commitment(
        &self,
        commitment: RollupCommitment,
        da_chunks: Vec<DAChunk>,
    ) -> RollupResult<Hash> {
        let commitment_hash = commitment.commitment_hash;
        let commit_start = Instant::now();

        let is_cellular = self.is_on_cellular().await;
        let use_wifi = self.config.is_wifi_only_operation("commitment_post");

        if is_cellular && use_wifi {
            warn!("Deferring commitment post until WiFi available (cellular-safe mode)");
            return Ok(commitment_hash);
        }

        {
            let mut manager = self.commitment_manager.write().await;
            manager.submit_commitment(commitment, da_chunks)?;
        }

        {
            let mut last_commit = self.last_commit_time.write().await;
            *last_commit = Some(Timestamp::now());
        }

        let commit_latency = commit_start.elapsed().as_millis() as u64;

        {
            let mut metrics = self.metrics.write().await;
            metrics.record_commit(commit_latency);
        }

        info!(
            "Posted commitment {} in {}ms",
            commitment_hash, commit_latency
        );
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

    pub async fn finalize_commitment(&self, commitment_hash: Hash) -> RollupResult<()> {
        info!("Finalizing commitment {}", commitment_hash);

        {
            let mut pending = self.pending_batches.write().await;
            if let Some(batch) = pending.remove(&commitment_hash) {
                let mut finalized = self.finalized_batches.write().await;
                finalized.insert(commitment_hash, batch);
            }
        }

        {
            let mut metrics = self.metrics.write().await;
            metrics.record_commit_finalized();
        }

        Ok(())
    }

    pub async fn get_operator_info(&self) -> OperatorInfo {
        let metrics = self.metrics.read().await;
        let last_commit = self.last_commit_time.read().await;
        let is_active = self.is_active.read().await;
        let successful = *self.successful_challenges.read().await;
        let failed = *self.failed_challenges.read().await;
        let slashes = *self.slash_count.read().await;

        let reputation_score =
            self.calculate_reputation_score(metrics.commits_finalized, successful, failed, slashes);

        OperatorInfo {
            address: self.address,
            bond_amount: self.bond_amount,
            is_active: *is_active,
            last_commit: *last_commit,
            total_commits: metrics.commits_posted,
            successful_challenges: successful,
            failed_challenges: failed,
            slash_count: slashes,
            reputation_score,
            drs_score: 1.0,
            avg_latency_ms: metrics.avg_commit_latency_ms,
            total_ru_processed: metrics.total_ru_used,
            cellular_safe_batches: metrics.cellular_safe_batches,
            five_g_optimized: self.config.five_g.enabled,
        }
    }

    fn calculate_reputation_score(
        &self,
        finalized_commits: u64,
        successful_challenges: u64,
        failed_challenges: u64,
        slashes: u64,
    ) -> f64 {
        if finalized_commits == 0 {
            return 1.0;
        }

        let base_score = finalized_commits as f64 / (finalized_commits + slashes + 1) as f64;
        let challenge_penalty = (failed_challenges as f64 * 0.1).min(0.3);
        let slash_penalty = (slashes as f64 * 0.2).min(0.5);

        (base_score - challenge_penalty - slash_penalty)
            .max(0.0)
            .min(1.0)
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
            metrics.challenge_responses += 1;
        }

        Ok(())
    }

    pub async fn handle_slash(&self, commitment_hash: Hash, slash_amount: u64) -> RollupResult<()> {
        warn!(
            "Operator {} slashed for commitment {}: {} EGOC",
            self.address, commitment_hash, slash_amount
        );

        {
            let mut slash_count = self.slash_count.write().await;
            *slash_count += 1;
        }

        {
            let mut metrics = self.metrics.write().await;
            metrics.commits_slashed += 1;
            metrics.slashing_penalties += slash_amount;
        }

        Ok(())
    }

    pub async fn advance_epoch(&self) -> RollupResult<()> {
        let mut epoch = self.epoch.write().await;
        *epoch += 1;

        info!("Advanced to epoch {}", *epoch);

        {
            let metrics = self.metrics.read().await;
            let mut alerts = self.alerts.write().await;
            alerts.check_metrics(&metrics);
        }

        Ok(())
    }

    pub fn is_5g_optimized(&self) -> bool {
        self.config.five_g.enabled && self.current_slice.is_some()
    }

    pub fn target_latency(&self) -> Duration {
        self.config.target_latency()
    }

    pub async fn is_on_cellular(&self) -> bool {
        let conn_type = self.connection_type.read().await;
        matches!(
            *conn_type,
            ConnectionType::Cellular5G | ConnectionType::Cellular4G
        )
    }

    pub async fn switch_connection(&self, connection_type: ConnectionType) -> RollupResult<()> {
        let mut conn = self.connection_type.write().await;
        let old_type = conn.clone();
        *conn = connection_type.clone();

        {
            let mut metrics = self.metrics.write().await;
            metrics.network_switches += 1;
        }

        info!(
            "Switched connection from {:?} to {:?}",
            old_type, connection_type
        );
        Ok(())
    }

    pub async fn switch_slice(&mut self, slice_id: String) -> RollupResult<()> {
        if !self.config.five_g.enabled {
            return Err(RollupError::ConfigError("5G not enabled".to_string()));
        }

        self.current_slice = Some(slice_id.clone());
        info!("Switched to 5G slice: {}", slice_id);
        Ok(())
    }

    pub async fn check_cellular_budget(&self) -> RollupResult<bool> {
        let cellular_used = *self.cellular_data_used_mb.read().await;
        let max_allowed = self.config.five_g.max_cellular_data_gb_per_month * 1024;

        if cellular_used >= max_allowed {
            warn!(
                "Cellular data budget exceeded: {} MB / {} MB",
                cellular_used, max_allowed
            );
            return Ok(false);
        }

        Ok(true)
    }

    pub async fn get_performance_summary(
        &self,
    ) -> HashMap<String, crate::metrics::PerformanceSummary> {
        let tracker = self.performance_tracker.lock().await;
        tracker.summary()
    }

    pub async fn reset_metrics(&self) {
        let mut metrics = self.metrics.write().await;
        *metrics = RollupMetrics::default();
        info!("Metrics reset");
    }
}

impl OperatorNode {
    pub fn new(operator: RollupOperator) -> Self {
        Self {
            operator: Arc::new(operator),
            network_handle: None,
            batch_handle: None,
            commit_handle: None,
            metrics_handle: None,
            cellular_monitor_handle: None,
        }
    }

    pub async fn start(&mut self) -> RollupResult<()> {
        let mut operator_mut =
            Arc::try_unwrap(self.operator.clone()).unwrap_or_else(|arc| (*arc).clone());

        operator_mut.start().await?;

        self.operator = Arc::new(operator_mut);

        self.start_batch_processing().await?;
        self.start_commit_scheduling().await?;
        self.start_metrics_monitoring().await?;

        if self.operator.config.five_g.cellular_safe_mode {
            self.start_cellular_monitoring().await?;
        }

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
        if let Some(handle) = self.metrics_handle.take() {
            handle.abort();
        }
        if let Some(handle) = self.cellular_monitor_handle.take() {
            handle.abort();
        }

        let mut operator_mut =
            Arc::try_unwrap(self.operator.clone()).unwrap_or_else(|arc| (*arc).clone());

        operator_mut.stop().await?;

        Ok(())
    }

    async fn start_batch_processing(&mut self) -> RollupResult<()> {
        let operator = self.operator.clone();
        let batch_timeout = Duration::from_secs(operator.config.operator.batch_timeout_secs);

        let handle = tokio::spawn(async move {
            let mut interval = interval(batch_timeout);

            loop {
                interval.tick().await;

                let is_active = *operator.is_active.read().await;
                if !is_active {
                    break;
                }

                if let Err(e) = operator.process_transactions().await {
                    error!("Batch processing error: {}", e);
                    let mut metrics = operator.metrics.write().await;
                    metrics.record_error("batch_processing");
                }
            }

            info!("Batch processing task stopped");
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

                let is_active = *operator.is_active.read().await;
                if !is_active {
                    break;
                }

                let pending_count = {
                    let pending = operator.pending_batches.read().await;
                    pending.len()
                };

                if pending_count > 0 {
                    debug!("Scheduled commit check: {} pending batches", pending_count);

                    if let Err(e) = operator.advance_epoch().await {
                        error!("Epoch advancement error: {}", e);
                    }
                }
            }

            info!("Commit scheduling task stopped");
        });

        self.commit_handle = Some(handle);
        Ok(())
    }

    async fn start_metrics_monitoring(&mut self) -> RollupResult<()> {
        let operator = self.operator.clone();
        let monitoring_interval = Duration::from_secs(60);

        let handle = tokio::spawn(async move {
            let mut interval = interval(monitoring_interval);

            loop {
                interval.tick().await;

                let is_active = *operator.is_active.read().await;
                if !is_active {
                    break;
                }

                let metrics = operator.metrics.read().await;
                let mut alerts = operator.alerts.write().await;

                alerts.check_metrics(&metrics);

                if !metrics.is_healthy() {
                    warn!("Operator health check failed: {}", metrics.summary());
                }

                drop(metrics);
                drop(alerts);
            }

            info!("Metrics monitoring task stopped");
        });

        self.metrics_handle = Some(handle);
        Ok(())
    }

    async fn start_cellular_monitoring(&mut self) -> RollupResult<()> {
        let operator = self.operator.clone();
        let check_interval = Duration::from_secs(300);

        let handle = tokio::spawn(async move {
            let mut interval = interval(check_interval);

            loop {
                interval.tick().await;

                let is_active = *operator.is_active.read().await;
                if !is_active {
                    break;
                }

                if let Ok(within_budget) = operator.check_cellular_budget().await {
                    if !within_budget {
                        warn!("Cellular data budget exceeded, switching to WiFi-only mode");

                        if let Err(e) = operator.switch_connection(ConnectionType::WiFi).await {
                            error!("Failed to switch to WiFi: {}", e);
                        }
                    }
                }
            }

            info!("Cellular monitoring task stopped");
        });

        self.cellular_monitor_handle = Some(handle);
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

    pub async fn finalize_commitment(&self, commitment_hash: Hash) -> RollupResult<()> {
        self.operator.finalize_commitment(commitment_hash).await
    }

    pub async fn handle_challenge(
        &self,
        commitment_hash: Hash,
        challenge_hash: Hash,
    ) -> RollupResult<()> {
        self.operator
            .handle_challenge(commitment_hash, challenge_hash)
            .await
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
            finalized_batches: self.finalized_batches.clone(),
            metrics: self.metrics.clone(),
            performance_tracker: self.performance_tracker.clone(),
            alerts: self.alerts.clone(),
            tx_receiver: None,
            batch_sender: None,
            commitment_sender: None,
            is_active: self.is_active.clone(),
            bond_amount: self.bond_amount,
            last_commit_time: self.last_commit_time.clone(),
            last_batch_time: self.last_batch_time.clone(),
            edge_nodes: self.edge_nodes.clone(),
            current_slice: self.current_slice.clone(),
            shard_id: self.shard_id,
            epoch: self.epoch.clone(),
            connection_type: self.connection_type.clone(),
            cellular_data_used_mb: self.cellular_data_used_mb.clone(),
            successful_challenges: self.successful_challenges.clone(),
            failed_challenges: self.failed_challenges.clone(),
            slash_count: self.slash_count.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::{Balance, Transaction, TransactionPayload};

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
        let keypair = ego_core::crypto::KeyPair::generate();
        let state = RollupState::new();
        let shard_id = ShardId::new(0).unwrap();

        let operator = RollupOperator::new(config, keypair, state, 1_000_000, shard_id).unwrap();
        assert_eq!(operator.bond_amount, 1_000_000);
        assert!(!operator.is_5g_optimized());
    }

    #[tokio::test]
    async fn test_operator_start_stop() {
        let config = create_test_config();
        let keypair = ego_core::crypto::KeyPair::generate();
        let state = RollupState::new();
        let shard_id = ShardId::new(0).unwrap();

        let mut operator =
            RollupOperator::new(config, keypair, state, 1_000_000, shard_id).unwrap();

        assert!(operator.start().await.is_ok());
        assert!(operator.stop().await.is_ok());
    }

    #[tokio::test]
    async fn test_transaction_submission() {
        let config = create_test_config();
        let keypair = ego_core::crypto::KeyPair::generate();
        let state = RollupState::new();
        let shard_id = ShardId::new(0).unwrap();

        let mut operator =
            RollupOperator::new(config, keypair, state, 1_000_000, shard_id).unwrap();
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
        let keypair = ego_core::crypto::KeyPair::generate();
        let state = RollupState::new();
        let shard_id = ShardId::new(0).unwrap();

        let operator = RollupOperator::new(config, keypair, state, 1_000_000, shard_id).unwrap();
        let mut node = OperatorNode::new(operator);

        assert!(node.start().await.is_ok());
        assert!(node.stop().await.is_ok());
    }

    #[tokio::test]
    async fn test_5g_optimization() {
        let mut config = create_test_config();
        config.five_g.enabled = true;
        config.five_g.slice_id = Some("test-slice".to_string());

        let keypair = ego_core::crypto::KeyPair::generate();
        let state = RollupState::new();
        let shard_id = ShardId::new(0).unwrap();

        let operator = RollupOperator::new(config, keypair, state, 1_000_000, shard_id).unwrap();
        assert!(operator.is_5g_optimized());
        assert_eq!(operator.target_latency(), Duration::from_millis(10));
    }

    #[tokio::test]
    async fn test_cellular_safe_mode() {
        let mut config = create_test_config();
        config.five_g.cellular_safe_mode = true;
        config.five_g.max_cellular_data_gb_per_month = 5;

        let keypair = ego_core::crypto::KeyPair::generate();
        let state = RollupState::new();
        let shard_id = ShardId::new(0).unwrap();

        let operator = RollupOperator::new(config, keypair, state, 1_000_000, shard_id).unwrap();

        assert!(operator.check_cellular_budget().await.unwrap());
    }

    #[tokio::test]
    async fn test_reputation_calculation() {
        let config = create_test_config();
        let keypair = ego_core::crypto::KeyPair::generate();
        let state = RollupState::new();
        let shard_id = ShardId::new(0).unwrap();

        let operator = RollupOperator::new(config, keypair, state, 1_000_000, shard_id).unwrap();

        let score = operator.calculate_reputation_score(100, 5, 2, 0);
        assert!(score > 0.8 && score <= 1.0);
    }

    #[tokio::test]
    async fn test_connection_switching() {
        let config = create_test_config();
        let keypair = ego_core::crypto::KeyPair::generate();
        let state = RollupState::new();
        let shard_id = ShardId::new(0).unwrap();

        let operator = RollupOperator::new(config, keypair, state, 1_000_000, shard_id).unwrap();

        assert!(
            operator
                .switch_connection(ConnectionType::WiFi)
                .await
                .is_ok()
        );
        assert!(!operator.is_on_cellular().await);

        assert!(
            operator
                .switch_connection(ConnectionType::Cellular5G)
                .await
                .is_ok()
        );
        assert!(operator.is_on_cellular().await);
    }
}
