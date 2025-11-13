use ego_core::{
    Address, Balance, DualSignature, EgoError, EgoResult, EpochNumber, Hash, PublicKey, ShardId,
    StateManager, Timestamp, Transaction, TransactionResult,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{Duration, Instant};

const MAX_BATCH_SIZE: usize = 10_000;
const MAX_BATCH_SIZE_CELLULAR: usize = 1_000;
const MAX_BATCH_SIZE_5G: usize = 5_000;
const MAX_BATCH_GAS: u64 = 50_000_000;
const BATCH_TIMEOUT_MS: u64 = 5000;
const BATCH_TIMEOUT_5G_MS: u64 = 100;
const COMMIT_FREQUENCY_SECS: u64 = 30;
const CHALLENGE_WINDOW_BLOCKS: u64 = 7200;
const DA_CHUNK_SIZE: usize = 256 * 1024;
const ERASURE_K: u16 = 64;
const ERASURE_M: u16 = 32;
const MAX_CELLULAR_DATA_GB_MONTH: u64 = 5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorConfig {
    pub rollup_id: String,
    pub chain_id: u32,
    pub network_id: u32,
    pub shard_id: ShardId,
    pub bond_amount: Balance,
    pub max_batch_size: usize,
    pub max_gas_limit: u64,
    pub batch_timeout_ms: u64,
    pub commit_frequency_secs: u64,
    pub challenge_window_blocks: u64,
    pub da_chunk_size: usize,
    pub erasure_k: u16,
    pub erasure_m: u16,
    pub enable_compression: bool,
    pub compression_level: u32,
    pub cellular_safe_mode: bool,
    pub max_cellular_data_gb_month: u64,
    pub enable_5g: bool,
    pub slice_id: Option<String>,
    pub edge_nodes: Vec<String>,
    pub require_dilithium: bool,
    pub wifi_only_operations: Vec<String>,
    pub drs_enabled: bool,
    pub deploy_policy_enabled: bool,
    pub enable_ai_pattern_detection: bool,
    pub require_human_verification: bool,
}

impl Default for OperatorConfig {
    fn default() -> Self {
        Self {
            rollup_id: "ego-rollup-0".to_string(),
            chain_id: 1,
            network_id: 1,
            shard_id: ShardId::new(0).unwrap(),
            bond_amount: Balance::from_egoc(1_000_000),
            max_batch_size: MAX_BATCH_SIZE,
            max_gas_limit: MAX_BATCH_GAS,
            batch_timeout_ms: BATCH_TIMEOUT_MS,
            commit_frequency_secs: COMMIT_FREQUENCY_SECS,
            challenge_window_blocks: CHALLENGE_WINDOW_BLOCKS,
            da_chunk_size: DA_CHUNK_SIZE,
            erasure_k: ERASURE_K,
            erasure_m: ERASURE_M,
            enable_compression: true,
            compression_level: 6,
            cellular_safe_mode: true,
            max_cellular_data_gb_month: MAX_CELLULAR_DATA_GB_MONTH,
            enable_5g: false,
            slice_id: None,
            edge_nodes: Vec::new(),
            require_dilithium: false,
            wifi_only_operations: vec![
                "commitment_post".to_string(),
                "da_upload".to_string(),
                "large_storage".to_string(),
            ],
            drs_enabled: true,
            deploy_policy_enabled: true,
            enable_ai_pattern_detection: true,
            require_human_verification: false,
        }
    }
}

impl OperatorConfig {
    pub fn batch_timeout(&self) -> Duration {
        Duration::from_millis(self.batch_timeout_ms)
    }

    pub fn target_latency(&self) -> Duration {
        if self.enable_5g {
            Duration::from_millis(10)
        } else {
            Duration::from_millis(250)
        }
    }

    pub fn cellular_batch_size(&self) -> usize {
        if self.enable_5g {
            MAX_BATCH_SIZE_5G
        } else {
            MAX_BATCH_SIZE_CELLULAR
        }
    }

    pub fn is_wifi_only_operation(&self, operation: &str) -> bool {
        self.cellular_safe_mode && self.wifi_only_operations.contains(&operation.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct RollupBatch {
    pub batch_id: Hash,
    pub rollup_id: String,
    pub operator: Address,
    pub transactions: Vec<Transaction>,
    pub transaction_results: Vec<TransactionResult>,
    pub prev_state_root: Hash,
    pub new_state_root: Hash,
    pub tx_root: Hash,
    pub receipts_root: Hash,
    pub proof_events_root: Hash,
    pub deploy_events_root: Hash,
    pub drs_events_root: Hash,
    pub l1_block_number: u64,
    pub epoch: EpochNumber,
    pub timestamp: Timestamp,
    pub gas_used: u64,
    pub size_bytes: usize,
    pub chain_id: u32,
    pub network_id: u32,
    pub shard_id: ShardId,
    pub operator_signature: DualSignature,
    pub is_cellular_safe: bool,
    pub is_5g_optimized: bool,
    pub drs_scores_applied: u32,
    pub deploy_requests_processed: u32,
}

impl RollupBatch {
    pub fn compute_batch_id(&self) -> Hash {
        let config = bincode::config::standard();
        let mut data = Vec::new();
        data.extend_from_slice(b"ego/rollup/batch/v1");
        data.extend_from_slice(self.rollup_id.as_bytes());
        data.extend_from_slice(self.operator.as_bytes());
        data.extend_from_slice(&self.l1_block_number.to_le_bytes());
        data.extend_from_slice(&self.epoch.as_u64().to_le_bytes());
        data.extend_from_slice(self.prev_state_root.as_bytes());
        data.extend_from_slice(&self.chain_id.to_le_bytes());
        data.extend_from_slice(&self.network_id.to_le_bytes());
        data.extend_from_slice(&self.shard_id.as_u32().to_le_bytes());

        for tx in &self.transactions {
            data.extend_from_slice(tx.hash.as_bytes());
        }

        ego_core::crypto::hash_data(&data)
    }

    pub fn sign(&mut self, keypair: &ego_core::crypto::KeyPair) -> EgoResult<()> {
        let signing_data = self.compute_batch_id();
        self.operator_signature = keypair.sign_hybrid(signing_data.as_bytes(), false);
        Ok(())
    }

    pub fn verify_signature(&self, dilithium_pk: &PublicKey) -> EgoResult<bool> {
        let signing_data = self.compute_batch_id();
        if let Some(ref sig) = self.operator_signature.dilithium_sig {
            ego_core::crypto::verify_signature(dilithium_pk, signing_data.as_bytes(), sig)
        } else {
            Ok(false)
        }
    }

    pub fn is_cellular_safe(&self) -> bool {
        self.is_cellular_safe
    }

    pub fn is_5g_ready(&self) -> bool {
        self.is_5g_optimized
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DAChunk {
    pub chunk_index: u32,
    pub total_chunks: u32,
    pub chunk_hash: Hash,
    pub data: Vec<u8>,
    pub batch_id: Hash,
    pub rollup_id: String,
    pub operator: Address,
    pub epoch: u64,
    pub timestamp: Timestamp,
}

impl DAChunk {
    pub fn new(
        chunk_index: u32,
        total_chunks: u32,
        data: Vec<u8>,
        batch_id: Hash,
        rollup_id: String,
        operator: Address,
        epoch: u64,
    ) -> Self {
        let chunk_hash = ego_core::crypto::hash_data(&data);
        Self {
            chunk_index,
            total_chunks,
            chunk_hash,
            data,
            batch_id,
            rollup_id,
            operator,
            epoch,
            timestamp: Timestamp::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollupCommitmentData {
    pub commitment_hash: Hash,
    pub rollup_id: String,
    pub operator: Address,
    pub batch_id: Hash,
    pub state_root: Hash,
    pub previous_state_root: Hash,
    pub tx_root: Hash,
    pub proofs_root: Hash,
    pub da_root: Hash,
    pub deploy_root: Hash,
    pub drs_root: Hash,
    pub tx_count: u32,
    pub block_range: (u64, u64),
    pub epoch: u64,
    pub timestamp: Timestamp,
    pub operator_signature: DualSignature,
    pub fraud_proof_window: u64,
    pub min_validity_proof: Vec<u8>,
    pub chain_id: u32,
    pub network_id: u32,
}

impl RollupCommitmentData {
    pub fn new(
        operator: Address,
        rollup_id: String,
        batch: &RollupBatch,
        da_root: Hash,
        proofs_root: Hash,
        deploy_root: Hash,
        drs_root: Hash,
        l1_block: u64,
        fraud_proof_window: u64,
        chain_id: u32,
        network_id: u32,
    ) -> Self {
        let mut commitment = Self {
            commitment_hash: Hash::ZERO,
            rollup_id,
            operator,
            batch_id: batch.batch_id,
            state_root: batch.new_state_root,
            previous_state_root: batch.prev_state_root,
            tx_root: batch.tx_root,
            proofs_root,
            da_root,
            deploy_root,
            drs_root,
            tx_count: batch.transactions.len() as u32,
            block_range: (l1_block, l1_block),
            epoch: batch.epoch.as_u64(),
            timestamp: Timestamp::now(),
            operator_signature: DualSignature::new(None, None),
            fraud_proof_window,
            min_validity_proof: Vec::new(),
            chain_id,
            network_id,
        };
        commitment.commitment_hash = commitment.compute_hash();
        commitment
    }

    pub fn compute_hash(&self) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(b"ego/rollup/commit/v1");
        data.extend_from_slice(self.rollup_id.as_bytes());
        data.extend_from_slice(self.operator.as_bytes());
        data.extend_from_slice(self.batch_id.as_bytes());
        data.extend_from_slice(self.state_root.as_bytes());
        data.extend_from_slice(self.previous_state_root.as_bytes());
        data.extend_from_slice(self.tx_root.as_bytes());
        data.extend_from_slice(self.da_root.as_bytes());
        data.extend_from_slice(self.deploy_root.as_bytes());
        data.extend_from_slice(self.drs_root.as_bytes());
        data.extend_from_slice(&self.tx_count.to_le_bytes());
        data.extend_from_slice(&self.epoch.to_le_bytes());
        data.extend_from_slice(&self.chain_id.to_le_bytes());
        data.extend_from_slice(&self.network_id.to_le_bytes());
        ego_core::crypto::hash_data(&data)
    }

    pub fn sign(&mut self, keypair: &ego_core::crypto::KeyPair) -> EgoResult<()> {
        let signing_data = self.compute_hash();
        self.operator_signature = keypair.sign_hybrid(signing_data.as_bytes(), false);
        self.commitment_hash = self.compute_hash();
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionType {
    Cellular5G,
    Cellular4G,
    WiFi,
    Ethernet,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorMetrics {
    pub transactions_received: u64,
    pub transactions_processed: u64,
    pub transactions_failed: u64,
    pub batches_built: u64,
    pub batches_processed: u64,
    pub commits_posted: u64,
    pub commits_finalized: u64,
    pub commits_challenged: u64,
    pub commits_slashed: u64,
    pub challenge_responses: u64,
    pub total_ru_used: u64,
    pub da_chunks_encoded: u64,
    pub da_chunks_uploaded: u64,
    pub cellular_safe_batches: u64,
    pub five_g_optimized_batches: u64,
    pub network_switches: u64,
    pub cellular_data_mb: u64,
    pub wifi_data_mb: u64,
    pub avg_batch_time_ms: u64,
    pub avg_commit_latency_ms: u64,
    pub slashing_penalties: u64,
    pub dilithium_signatures: u64,
    pub ed25519_signatures: u64,
    pub hybrid_signatures: u64,
    pub latency_target_breaches: u64,
    pub deploy_requests_evaluated: u64,
    pub deploy_requests_accepted: u64,
    pub deploy_requests_rejected: u64,
    pub drs_scores_computed: u64,
    pub ai_patterns_detected: u64,
    pub human_verifications_required: u64,
    pub errors: HashMap<String, u64>,
}

impl Default for OperatorMetrics {
    fn default() -> Self {
        Self {
            transactions_received: 0,
            transactions_processed: 0,
            transactions_failed: 0,
            batches_built: 0,
            batches_processed: 0,
            commits_posted: 0,
            commits_finalized: 0,
            commits_challenged: 0,
            commits_slashed: 0,
            challenge_responses: 0,
            total_ru_used: 0,
            da_chunks_encoded: 0,
            da_chunks_uploaded: 0,
            cellular_safe_batches: 0,
            five_g_optimized_batches: 0,
            network_switches: 0,
            cellular_data_mb: 0,
            wifi_data_mb: 0,
            avg_batch_time_ms: 0,
            avg_commit_latency_ms: 0,
            slashing_penalties: 0,
            dilithium_signatures: 0,
            ed25519_signatures: 0,
            hybrid_signatures: 0,
            latency_target_breaches: 0,
            deploy_requests_evaluated: 0,
            deploy_requests_accepted: 0,
            deploy_requests_rejected: 0,
            drs_scores_computed: 0,
            ai_patterns_detected: 0,
            human_verifications_required: 0,
            errors: HashMap::new(),
        }
    }
}

impl OperatorMetrics {
    pub fn record_batch(&mut self, time_ms: u64, is_cellular_safe: bool, is_5g: bool) {
        self.batches_processed += 1;
        if is_cellular_safe {
            self.cellular_safe_batches += 1;
        }
        if is_5g {
            self.five_g_optimized_batches += 1;
        }
        self.avg_batch_time_ms = (self.avg_batch_time_ms * (self.batches_processed - 1) + time_ms)
            / self.batches_processed;
    }

    pub fn record_commit(&mut self, latency_ms: u64) {
        self.commits_posted += 1;
        self.avg_commit_latency_ms = (self.avg_commit_latency_ms * (self.commits_posted - 1)
            + latency_ms)
            / self.commits_posted;
    }

    pub fn record_signature(&mut self, has_dilithium: bool, has_ed25519: bool) {
        if has_dilithium && has_ed25519 {
            self.hybrid_signatures += 1;
        } else if has_dilithium {
            self.dilithium_signatures += 1;
        } else if has_ed25519 {
            self.ed25519_signatures += 1;
        }
    }

    pub fn record_data_usage(&mut self, bytes: u64, is_cellular: bool) {
        let mb = bytes / (1024 * 1024);
        if is_cellular {
            self.cellular_data_mb += mb;
        } else {
            self.wifi_data_mb += mb;
        }
    }

    pub fn record_error(&mut self, error_type: &str) {
        *self.errors.entry(error_type.to_string()).or_insert(0) += 1;
    }

    pub fn record_deploy_decision(&mut self, accepted: bool) {
        self.deploy_requests_evaluated += 1;
        if accepted {
            self.deploy_requests_accepted += 1;
        } else {
            self.deploy_requests_rejected += 1;
        }
    }

    pub fn record_drs_computation(&mut self) {
        self.drs_scores_computed += 1;
    }

    pub fn record_ai_pattern_detection(&mut self) {
        self.ai_patterns_detected += 1;
    }

    pub fn record_human_verification_required(&mut self) {
        self.human_verifications_required += 1;
    }

    pub fn is_healthy(&self) -> bool {
        if self.batches_processed == 0 {
            return true;
        }
        let failure_rate = self.transactions_failed as f64 / self.transactions_processed as f64;
        let challenge_rate = self.commits_challenged as f64 / self.commits_posted.max(1) as f64;
        failure_rate < 0.05 && challenge_rate < 0.1 && self.commits_slashed == 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorInfo {
    pub address: Address,
    pub rollup_id: String,
    pub bond_amount: u64,
    pub is_active: bool,
    pub last_commit: Option<Timestamp>,
    pub total_commits: u64,
    pub successful_challenges: u64,
    pub failed_challenges: u64,
    pub slash_count: u64,
    pub reputation_score: f64,
    pub drs_score: f64,
    pub avg_latency_ms: u64,
    pub total_ru_processed: u64,
    pub cellular_safe_batches: u64,
    pub five_g_optimized: bool,
    pub deploy_acceptance_rate: f64,
}

pub struct BatchBuilder {
    operator: Address,
    rollup_id: String,
    transactions: Vec<Transaction>,
    max_batch_size: usize,
    max_gas_limit: u64,
    current_gas: u64,
    chain_id: u32,
    network_id: u32,
    shard_id: ShardId,
}

impl BatchBuilder {
    pub fn new(
        operator: Address,
        rollup_id: String,
        max_batch_size: usize,
        max_gas_limit: u64,
        chain_id: u32,
        network_id: u32,
        shard_id: ShardId,
    ) -> Self {
        Self {
            operator,
            rollup_id,
            transactions: Vec::new(),
            max_batch_size,
            max_gas_limit,
            current_gas: 0,
            chain_id,
            network_id,
            shard_id,
        }
    }

    pub fn can_add_transaction(&self, tx: &Transaction) -> bool {
        if self.transactions.len() >= self.max_batch_size {
            return false;
        }
        let tx_gas = tx.estimate_resource_units();
        if self.current_gas + tx_gas > self.max_gas_limit {
            return false;
        }
        true
    }

    pub fn add_transaction(&mut self, tx: Transaction) -> EgoResult<bool> {
        if !self.can_add_transaction(&tx) {
            return Ok(false);
        }
        let tx_gas = tx.estimate_resource_units();
        self.transactions.push(tx);
        self.current_gas += tx_gas;
        Ok(true)
    }

    pub fn is_cellular_safe(&self) -> bool {
        self.transactions.len() <= MAX_BATCH_SIZE_CELLULAR
    }

    pub fn is_5g_ready(&self) -> bool {
        self.transactions.len() >= MAX_BATCH_SIZE_5G / 2
    }

    pub fn build(
        self,
        l1_block: u64,
        prev_state_root: Hash,
        epoch: EpochNumber,
    ) -> EgoResult<RollupBatch> {
        let tx_hashes: Vec<Vec<u8>> = self
            .transactions
            .iter()
            .map(|tx| tx.hash.to_vec())
            .collect();
        let merkle_tree = ego_core::crypto::MerkleTree::build(tx_hashes);
        let tx_root = merkle_tree.root_hash().unwrap_or(Hash::ZERO);

        let config = bincode::config::standard();
        let size_bytes = bincode::encode_to_vec(&self.transactions, config)
            .map(|data| data.len())
            .unwrap_or(0);

        let is_cellular_safe = self.is_cellular_safe();
        let is_5g_optimized = self.is_5g_ready();

        let mut batch = RollupBatch {
            batch_id: Hash::ZERO,
            rollup_id: self.rollup_id,
            operator: self.operator,
            transactions: self.transactions,
            transaction_results: Vec::new(),
            prev_state_root,
            new_state_root: Hash::ZERO,
            tx_root,
            receipts_root: Hash::ZERO,
            proof_events_root: Hash::ZERO,
            deploy_events_root: Hash::ZERO,
            drs_events_root: Hash::ZERO,
            l1_block_number: l1_block,
            epoch,
            timestamp: Timestamp::now(),
            gas_used: self.current_gas,
            size_bytes,
            chain_id: self.chain_id,
            network_id: self.network_id,
            shard_id: self.shard_id,
            operator_signature: DualSignature::new(None, None),
            is_cellular_safe,
            is_5g_optimized,
            drs_scores_applied: 0,
            deploy_requests_processed: 0,
        };

        batch.batch_id = batch.compute_batch_id();
        Ok(batch)
    }
}

pub struct DataAvailability {
    k: usize,
    m: usize,
    chunk_size: usize,
    enable_compression: bool,
    compression_level: u32,
}

impl DataAvailability {
    pub fn new(
        k: usize,
        m: usize,
        chunk_size: usize,
        enable_compression: bool,
        compression_level: u32,
    ) -> EgoResult<Self> {
        if k == 0 || m == 0 {
            return Err(EgoError::InvalidTransaction(
                "Invalid erasure coding parameters".to_string(),
            ));
        }
        Ok(Self {
            k,
            m,
            chunk_size,
            enable_compression,
            compression_level,
        })
    }

    pub fn encode_data(
        &self,
        batch_id: Hash,
        data: Vec<u8>,
        rollup_id: String,
        operator: Address,
        epoch: u64,
    ) -> EgoResult<Vec<DAChunk>> {
        let processed_data = if self.enable_compression {
            self.compress_data(&data)?
        } else {
            data
        };

        let chunks = self.split_into_chunks(&processed_data);
        let total_chunks = chunks.len() as u32;

        let da_chunks: Vec<DAChunk> = chunks
            .into_iter()
            .enumerate()
            .map(|(idx, chunk_data)| {
                DAChunk::new(
                    idx as u32,
                    total_chunks,
                    chunk_data,
                    batch_id,
                    rollup_id.clone(),
                    operator,
                    epoch,
                )
            })
            .collect();

        Ok(da_chunks)
    }

    fn compress_data(&self, data: &[u8]) -> EgoResult<Vec<u8>> {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(self.compression_level));
        encoder
            .write_all(data)
            .map_err(|e| EgoError::SerializationError(e.to_string()))?;
        encoder
            .finish()
            .map_err(|e| EgoError::SerializationError(e.to_string()))
    }

    fn split_into_chunks(&self, data: &[u8]) -> Vec<Vec<u8>> {
        data.chunks(self.chunk_size)
            .map(|chunk| chunk.to_vec())
            .collect()
    }
}

impl Clone for DataAvailability {
    fn clone(&self) -> Self {
        Self {
            k: self.k,
            m: self.m,
            chunk_size: self.chunk_size,
            enable_compression: self.enable_compression,
            compression_level: self.compression_level,
        }
    }
}

pub struct RollupOperator {
    config: OperatorConfig,
    keypair: Arc<ego_core::crypto::KeyPair>,
    address: Address,
    state_manager: Arc<RwLock<StateManager>>,
    da_manager: Arc<RwLock<DataAvailability>>,
    tx_pool: Arc<RwLock<VecDeque<Transaction>>>,
    pending_batches: Arc<RwLock<HashMap<Hash, RollupBatch>>>,
    finalized_batches: Arc<RwLock<HashMap<Hash, RollupBatch>>>,
    pending_commitments: Arc<RwLock<HashMap<Hash, RollupCommitmentData>>>,
    metrics: Arc<RwLock<OperatorMetrics>>,
    is_active: Arc<RwLock<bool>>,
    last_commit_time: Arc<RwLock<Option<Timestamp>>>,
    last_batch_time: Arc<RwLock<Option<Timestamp>>>,
    epoch: Arc<RwLock<u64>>,
    connection_type: Arc<RwLock<ConnectionType>>,
    cellular_data_used_mb: Arc<RwLock<u64>>,
    successful_challenges: Arc<RwLock<u64>>,
    failed_challenges: Arc<RwLock<u64>>,
    slash_count: Arc<RwLock<u64>>,
    deploy_policy_manager: Arc<RwLock<Option<ego_core::deploy_policy::DeployPolicyManager>>>,
    drs_manager: Arc<RwLock<Option<ego_core::drs::DRSManager>>>,
}

impl RollupOperator {
    pub fn new(
        config: OperatorConfig,
        keypair: ego_core::crypto::KeyPair,
        state_manager: StateManager,
    ) -> EgoResult<Self> {
        let address = Address::from_public_key(&keypair.dilithium_public_key());

        let da_manager = DataAvailability::new(
            config.erasure_k as usize,
            config.erasure_m as usize,
            config.da_chunk_size,
            config.enable_compression,
            config.compression_level,
        )?;

        let connection_type = if config.enable_5g {
            ConnectionType::Cellular5G
        } else {
            ConnectionType::WiFi
        };

        let deploy_policy_manager = if config.deploy_policy_enabled {
            let policy_config = ego_core::deploy_policy::DeployPolicyConfig {
                free_deploys_per_epoch: 5,
                min_stake_for_quota: Balance::from_egoc(1000),
                credits_per_kb: 100,
                credits_per_ru: 10,
                max_deploy_size_kb: 1024,
                max_ru_per_deploy: 10000,
                deploy_bond_amount: Balance::new(1000000),
                bond_lock_duration_blocks: 1000,
                bond_slash_threshold: 3,
                max_deploys_per_epoch: 10000,
                max_deploys_per_user_per_epoch: 50,
                max_total_size_per_epoch_gb: 100,
                enable_dedup: true,
                dedup_lookback_epochs: 10,
                pob_floor_enabled: false,
                pob_floor_per_kb: 50,
                pob_floor_per_ru: 5,
                anti_spam_enabled: true,
                max_deploys_per_hour: 10,
                max_deploys_per_day: 50,
                min_deploy_interval_seconds: 60,
                human_verification_required: config.require_human_verification,
                ai_pattern_detection_enabled: config.enable_ai_pattern_detection,
                emergency_mode: false,
                whitelist_only_mode: false,
            };
            Some(ego_core::deploy_policy::DeployPolicyManager::new(
                policy_config,
            ))
        } else {
            None
        };

        let drs_manager = if config.drs_enabled {
            let drs_config = ego_core::drs::DRSConfig::default();
            Some(ego_core::drs::DRSManager::new(drs_config))
        } else {
            None
        };

        Ok(Self {
            config,
            keypair: Arc::new(keypair),
            address,
            state_manager: Arc::new(RwLock::new(state_manager)),
            da_manager: Arc::new(RwLock::new(da_manager)),
            tx_pool: Arc::new(RwLock::new(VecDeque::new())),
            pending_batches: Arc::new(RwLock::new(HashMap::new())),
            finalized_batches: Arc::new(RwLock::new(HashMap::new())),
            pending_commitments: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(OperatorMetrics::default())),
            is_active: Arc::new(RwLock::new(false)),
            last_commit_time: Arc::new(RwLock::new(None)),
            last_batch_time: Arc::new(RwLock::new(None)),
            epoch: Arc::new(RwLock::new(0)),
            connection_type: Arc::new(RwLock::new(connection_type)),
            cellular_data_used_mb: Arc::new(RwLock::new(0)),
            successful_challenges: Arc::new(RwLock::new(0)),
            failed_challenges: Arc::new(RwLock::new(0)),
            slash_count: Arc::new(RwLock::new(0)),
            deploy_policy_manager: Arc::new(RwLock::new(deploy_policy_manager)),
            drs_manager: Arc::new(RwLock::new(drs_manager)),
        })
    }

    pub async fn start(&mut self) -> EgoResult<()> {
        let mut is_active = self.is_active.write().await;
        *is_active = true;
        Ok(())
    }

    pub async fn stop(&mut self) -> EgoResult<()> {
        let mut is_active = self.is_active.write().await;
        *is_active = false;
        self.flush_pending_transactions().await?;
        Ok(())
    }

    pub async fn submit_transaction(&self, tx: Transaction) -> EgoResult<Hash> {
        if !tx.verify_signature()? {
            return Err(EgoError::InvalidTransaction(
                "Invalid transaction signature".to_string(),
            ));
        }

        if self.config.require_dilithium && tx.signature.dilithium_sig.is_none() {
            return Err(EgoError::InvalidTransaction(
                "Dilithium signature required".to_string(),
            ));
        }

        if tx.chain_id != self.config.chain_id {
            return Err(EgoError::InvalidTransaction(
                "Chain ID mismatch".to_string(),
            ));
        }

        if tx.shard_id != self.config.shard_id {
            return Err(EgoError::InvalidTransaction(
                "Shard ID mismatch".to_string(),
            ));
        }

        let tx_hash = tx.hash;

        {
            let mut pool = self.tx_pool.write().await;
            pool.push_back(tx.clone());
        }

        {
            let mut metrics = self.metrics.write().await;
            metrics.transactions_received += 1;
            let has_dilithium = tx.signature.dilithium_sig.is_some();
            let has_ed25519 = tx.signature.ed25519_sig.is_some();
            metrics.record_signature(has_dilithium, has_ed25519);
        }

        Ok(tx_hash)
    }

    pub async fn process_transactions(&self) -> EgoResult<()> {
        let batch_start = Instant::now();
        let is_cellular = self.is_on_cellular().await;
        let max_size = if is_cellular && self.config.cellular_safe_mode {
            self.config.cellular_batch_size()
        } else {
            self.config.max_batch_size
        };

        let mut builder = BatchBuilder::new(
            self.address,
            self.config.rollup_id.clone(),
            max_size,
            self.config.max_gas_limit,
            self.config.chain_id,
            self.config.network_id,
            self.config.shard_id,
        );

        let mut processed_count = 0;

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
                        Err(_) => {
                            let mut metrics = self.metrics.write().await;
                            metrics.transactions_failed += 1;
                            metrics.record_error("tx_add_failed");
                        }
                    }
                } else {
                    pool.push_front(tx);
                    break;
                }

                if batch_start.elapsed() > self.config.batch_timeout() {
                    break;
                }
            }
        }

        if processed_count > 0 {
            self.create_and_process_batch(builder, batch_start).await?;
        }

        Ok(())
    }

    async fn create_and_process_batch(
        &self,
        builder: BatchBuilder,
        batch_start: Instant,
    ) -> EgoResult<()> {
        let epoch = *self.epoch.read().await;
        let current_block = epoch * 100 + 1000;

        let prev_state_root = {
            let state = self.state_manager.read().await;
            state.compute_state_root()
        };

        let epoch_number = EpochNumber::new(epoch);
        let batch = builder.build(current_block, prev_state_root, epoch_number)?;
        let batch_hash = batch.batch_id;
        let tx_count = batch.transactions.len();

        let processing_start = Instant::now();
        let processed_batch = self.process_batch(batch).await?;
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
            metrics.record_batch(
                processing_time,
                processed_batch.is_cellular_safe,
                processed_batch.is_5g_optimized,
            );
            metrics.record_data_usage(batch_size_bytes, is_cellular);

            if total_time > self.config.target_latency().as_millis() as u64 {
                metrics.latency_target_breaches += 1;
            }
        }

        Ok(())
    }

    async fn process_batch(&self, mut batch: RollupBatch) -> EgoResult<RollupBatch> {
        let mut state = self.state_manager.write().await;
        let mut results = Vec::new();
        let mut deploy_events = Vec::new();
        let mut drs_events = Vec::new();

        for tx in &batch.transactions {
            let result = state.execute_transaction(tx)?;
            results.push(result);
        }

        if self.config.deploy_policy_enabled {
            let mut deploy_mgr_lock = self.deploy_policy_manager.write().await;
            if let Some(ref mut deploy_mgr) = *deploy_mgr_lock {
                for tx in &batch.transactions {
                    if let ego_core::TransactionPayload::DeployContract { .. } = &tx.payload {
                        let staker_stake = state.get_account(&tx.from).map(|acc| acc.balance);
                        let request = ego_core::deploy_policy::DeployRequest {
                            deployer: tx.from,
                            deploy_type: ego_core::deploy_policy::DeployType::SmartContract {
                                code_size_kb: 100,
                                estimated_ru: 5000,
                            },
                            code: vec![],
                            metadata: HashMap::new(),
                            use_free_quota: true,
                            preferred_shard: Some(self.config.shard_id.as_u32()),
                            human_verification_signature: None,
                            dilithium_verification_pk: None,
                        };
                        match deploy_mgr.evaluate_deploy_request(
                            &request,
                            staker_stake,
                            batch.l1_block_number,
                        ) {
                            Ok(decision) => {
                                let accepted = matches!(
                                    decision,
                                    ego_core::deploy_policy::DeployDecision::AcceptWithFreeQuota { .. } |
                                    ego_core::deploy_policy::DeployDecision::AcceptWithCredits { .. }
                                );
                                let mut metrics = self.metrics.write().await;
                                metrics.record_deploy_decision(accepted);
                                drop(metrics);
                                batch.deploy_requests_processed += 1;
                                deploy_events.push(tx.hash);
                            }
                            Err(_) => {
                                let mut metrics = self.metrics.write().await;
                                metrics.record_deploy_decision(false);
                            }
                        }
                    }
                }
            }
        }

        if self.config.drs_enabled {
            let drs_mgr_lock = self.drs_manager.read().await;
            if let Some(ref drs_mgr) = *drs_mgr_lock {
                for tx in &batch.transactions {
                    if let Some(account) = state.get_account(&tx.from) {
                        let evidence = ego_core::drs::create_evidence_bundle_from_account(
                            &account,
                            batch.epoch.as_u64(),
                            vec![],
                            None,
                        );

                        match drs_mgr.calculate_drs_score(evidence) {
                            Ok(score) => {
                                batch.drs_scores_applied += 1;
                                drs_events.push(tx.hash);

                                let mut metrics = self.metrics.write().await;
                                metrics.record_drs_computation();
                            }
                            Err(_) => {}
                        }
                    }
                }
            }
        }

        batch.transaction_results = results;
        batch.new_state_root = state.compute_state_root();

        let receipt_hashes: Vec<Vec<u8>> = batch
            .transaction_results
            .iter()
            .map(|r| r.tx_hash.to_vec())
            .collect();
        let receipts_tree = ego_core::crypto::MerkleTree::build(receipt_hashes);
        batch.receipts_root = receipts_tree.root_hash().unwrap_or(Hash::ZERO);

        if !deploy_events.is_empty() {
            let deploy_tree = ego_core::crypto::MerkleTree::build(
                deploy_events.iter().map(|h| h.to_vec()).collect(),
            );
            batch.deploy_events_root = deploy_tree.root_hash().unwrap_or(Hash::ZERO);
        }

        if !drs_events.is_empty() {
            let drs_tree = ego_core::crypto::MerkleTree::build(
                drs_events.iter().map(|h| h.to_vec()).collect(),
            );
            batch.drs_events_root = drs_tree.root_hash().unwrap_or(Hash::ZERO);
        }

        batch.sign(&self.keypair)?;

        Ok(batch)
    }

    async fn create_da_chunks(&self, batch: &RollupBatch) -> EgoResult<Vec<DAChunk>> {
        let config = bincode::config::standard();
        let batch_data = bincode::encode_to_vec(batch, config)
            .map_err(|e| EgoError::SerializationError(e.to_string()))?;

        let mut da_manager = self.da_manager.write().await;
        let epoch = *self.epoch.read().await;

        let chunks = da_manager.encode_data(
            batch.batch_id,
            batch_data,
            self.config.rollup_id.clone(),
            self.address,
            epoch,
        )?;

        {
            let mut metrics = self.metrics.write().await;
            metrics.da_chunks_encoded += chunks.len() as u64;
        }

        Ok(chunks)
    }

    async fn create_commitment(
        &self,
        batch: &RollupBatch,
        da_chunks: &[DAChunk],
    ) -> EgoResult<RollupCommitmentData> {
        let chunk_hashes: Vec<Vec<u8>> = da_chunks
            .iter()
            .map(|chunk| chunk.chunk_hash.to_vec())
            .collect();

        let merkle_tree = ego_core::crypto::MerkleTree::build(chunk_hashes);
        let da_root = merkle_tree.root_hash().unwrap_or(Hash::ZERO);
        let proofs_root = Hash::ZERO;

        let mut commitment = RollupCommitmentData::new(
            self.address,
            self.config.rollup_id.clone(),
            batch,
            da_root,
            proofs_root,
            batch.deploy_events_root,
            batch.drs_events_root,
            batch.l1_block_number,
            self.config.challenge_window_blocks,
            self.config.chain_id,
            self.config.network_id,
        );

        commitment.sign(&self.keypair)?;

        Ok(commitment)
    }

    async fn post_commitment(
        &self,
        commitment: RollupCommitmentData,
        da_chunks: Vec<DAChunk>,
    ) -> EgoResult<Hash> {
        let commitment_hash = commitment.commitment_hash;
        let commit_start = Instant::now();

        let is_cellular = self.is_on_cellular().await;
        let use_wifi = self.config.is_wifi_only_operation("commitment_post");

        if is_cellular && use_wifi {
            return Ok(commitment_hash);
        }

        {
            let mut pending = self.pending_commitments.write().await;
            pending.insert(commitment_hash, commitment);
        }

        {
            let mut last_commit = self.last_commit_time.write().await;
            *last_commit = Some(Timestamp::now());
        }

        let commit_latency = commit_start.elapsed().as_millis() as u64;

        {
            let mut metrics = self.metrics.write().await;
            metrics.record_commit(commit_latency);
            metrics.da_chunks_uploaded += da_chunks.len() as u64;
        }

        Ok(commitment_hash)
    }

    async fn flush_pending_transactions(&self) -> EgoResult<()> {
        let pool_size = {
            let pool = self.tx_pool.read().await;
            pool.len()
        };

        if pool_size > 0 {
            self.process_transactions().await?;
        }

        Ok(())
    }

    pub async fn finalize_commitment(&self, commitment_hash: Hash) -> EgoResult<()> {
        {
            let mut pending = self.pending_batches.write().await;
            if let Some(batch) = pending.remove(&commitment_hash) {
                let mut finalized = self.finalized_batches.write().await;
                finalized.insert(commitment_hash, batch);
            }
        }

        {
            let mut pending_commits = self.pending_commitments.write().await;
            pending_commits.remove(&commitment_hash);
        }

        {
            let mut metrics = self.metrics.write().await;
            metrics.commits_finalized += 1;
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

        let deploy_acceptance_rate = if metrics.deploy_requests_evaluated > 0 {
            metrics.deploy_requests_accepted as f64 / metrics.deploy_requests_evaluated as f64
        } else {
            1.0
        };

        OperatorInfo {
            address: self.address,
            rollup_id: self.config.rollup_id.clone(),
            bond_amount: self.config.bond_amount.as_u128() as u64,
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
            five_g_optimized: self.config.enable_5g,
            deploy_acceptance_rate,
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

    pub async fn get_metrics(&self) -> OperatorMetrics {
        self.metrics.read().await.clone()
    }

    pub async fn handle_challenge(
        &self,
        commitment_hash: Hash,
        _challenge_hash: Hash,
    ) -> EgoResult<()> {
        {
            let mut metrics = self.metrics.write().await;
            metrics.commits_challenged += 1;
            metrics.challenge_responses += 1;
        }

        let pending = self.pending_commitments.read().await;
        if pending.contains_key(&commitment_hash) {
            let mut successful = self.successful_challenges.write().await;
            *successful += 1;
        } else {
            let mut failed = self.failed_challenges.write().await;
            *failed += 1;
        }

        Ok(())
    }

    pub async fn handle_slash(&self, _commitment_hash: Hash, slash_amount: u64) -> EgoResult<()> {
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

    pub async fn advance_epoch(&self) -> EgoResult<()> {
        let mut epoch = self.epoch.write().await;
        let new_epoch = *epoch + 1;
        *epoch = new_epoch;

        if self.config.deploy_policy_enabled {
            let mut deploy_mgr_lock = self.deploy_policy_manager.write().await;
            if let Some(ref mut deploy_mgr) = *deploy_mgr_lock {
                deploy_mgr.advance_epoch(new_epoch)?;
            }
        }

        if self.config.drs_enabled {
            let drs_mgr_lock = self.drs_manager.read().await;
            if let Some(ref drs_mgr) = *drs_mgr_lock {
                let _ = drs_mgr.finalize_epoch(new_epoch);
            }
        }

        Ok(())
    }

    pub async fn is_on_cellular(&self) -> bool {
        let conn_type = self.connection_type.read().await;
        matches!(
            *conn_type,
            ConnectionType::Cellular5G | ConnectionType::Cellular4G
        )
    }

    pub async fn switch_connection(&self, connection_type: ConnectionType) -> EgoResult<()> {
        let mut conn = self.connection_type.write().await;
        *conn = connection_type;

        {
            let mut metrics = self.metrics.write().await;
            metrics.network_switches += 1;
        }

        Ok(())
    }

    pub async fn check_cellular_budget(&self) -> EgoResult<bool> {
        let cellular_used = *self.cellular_data_used_mb.read().await;
        let max_allowed = self.config.max_cellular_data_gb_month * 1024;

        if cellular_used >= max_allowed {
            return Ok(false);
        }

        Ok(true)
    }

    pub async fn reset_metrics(&self) {
        let mut metrics = self.metrics.write().await;
        *metrics = OperatorMetrics::default();
    }

    pub async fn get_batch(&self, batch_hash: Hash) -> Option<RollupBatch> {
        let pending = self.pending_batches.read().await;
        if let Some(batch) = pending.get(&batch_hash) {
            return Some(batch.clone());
        }

        let finalized = self.finalized_batches.read().await;
        finalized.get(&batch_hash).cloned()
    }

    pub async fn get_commitment(&self, commitment_hash: Hash) -> Option<RollupCommitmentData> {
        let pending = self.pending_commitments.read().await;
        pending.get(&commitment_hash).cloned()
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn rollup_id(&self) -> &str {
        &self.config.rollup_id
    }

    pub fn shard_id(&self) -> ShardId {
        self.config.shard_id
    }

    pub async fn update_deploy_policy_config(
        &self,
        new_config: ego_core::deploy_policy::DeployPolicyConfig,
    ) -> EgoResult<()> {
        let mut deploy_mgr_lock = self.deploy_policy_manager.write().await;
        if let Some(ref mut deploy_mgr) = *deploy_mgr_lock {
            deploy_mgr.update_config(new_config)?;
        }
        Ok(())
    }

    pub async fn update_drs_config(&self, new_config: ego_core::drs::DRSConfig) -> EgoResult<()> {
        let drs_mgr_lock = self.drs_manager.read().await;
        if let Some(ref drs_mgr) = *drs_mgr_lock {
            drs_mgr.update_config(new_config)?;
        }
        Ok(())
    }

    pub async fn get_deploy_policy_stats(
        &self,
    ) -> Option<ego_core::deploy_policy::EpochDeployStats> {
        let deploy_mgr_lock = self.deploy_policy_manager.read().await;
        if let Some(ref deploy_mgr) = *deploy_mgr_lock {
            let epoch = deploy_mgr.get_current_epoch();
            deploy_mgr.get_epoch_stats(epoch)
        } else {
            None
        }
    }

    pub async fn get_drs_epoch_stats(&self, epoch: u64) -> Option<ego_core::drs::EpochStats> {
        let drs_mgr_lock = self.drs_manager.read().await;
        if let Some(ref drs_mgr) = *drs_mgr_lock {
            drs_mgr.get_epoch_stats(epoch)
        } else {
            None
        }
    }
}

impl Clone for RollupOperator {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            keypair: self.keypair.clone(),
            address: self.address,
            state_manager: self.state_manager.clone(),
            da_manager: self.da_manager.clone(),
            tx_pool: self.tx_pool.clone(),
            pending_batches: self.pending_batches.clone(),
            finalized_batches: self.finalized_batches.clone(),
            pending_commitments: self.pending_commitments.clone(),
            metrics: self.metrics.clone(),
            is_active: self.is_active.clone(),
            last_commit_time: self.last_commit_time.clone(),
            last_batch_time: self.last_batch_time.clone(),
            epoch: self.epoch.clone(),
            connection_type: self.connection_type.clone(),
            cellular_data_used_mb: self.cellular_data_used_mb.clone(),
            successful_challenges: self.successful_challenges.clone(),
            failed_challenges: self.failed_challenges.clone(),
            slash_count: self.slash_count.clone(),
            deploy_policy_manager: self.deploy_policy_manager.clone(),
            drs_manager: self.drs_manager.clone(),
        }
    }
}

pub struct OperatorNode {
    operator: Arc<RollupOperator>,
    batch_handle: Option<tokio::task::JoinHandle<()>>,
    commit_handle: Option<tokio::task::JoinHandle<()>>,
    metrics_handle: Option<tokio::task::JoinHandle<()>>,
    cellular_monitor_handle: Option<tokio::task::JoinHandle<()>>,
    deploy_policy_handle: Option<tokio::task::JoinHandle<()>>,
    drs_update_handle: Option<tokio::task::JoinHandle<()>>,
}

impl OperatorNode {
    pub fn new(operator: RollupOperator) -> Self {
        Self {
            operator: Arc::new(operator),
            batch_handle: None,
            commit_handle: None,
            metrics_handle: None,
            cellular_monitor_handle: None,
            deploy_policy_handle: None,
            drs_update_handle: None,
        }
    }

    pub async fn start(&mut self) -> EgoResult<()> {
        let operator_clone = Arc::clone(&self.operator);
        let mut operator_mut =
            Arc::try_unwrap(operator_clone).unwrap_or_else(|arc| RollupOperator::clone(&arc));

        operator_mut.start().await?;
        self.operator = Arc::new(operator_mut);

        self.start_batch_processing().await?;
        self.start_commit_scheduling().await?;
        self.start_metrics_monitoring().await?;

        if self.operator.config.cellular_safe_mode {
            self.start_cellular_monitoring().await?;
        }

        if self.operator.config.deploy_policy_enabled {
            self.start_deploy_policy_monitoring().await?;
        }

        if self.operator.config.drs_enabled {
            self.start_drs_updates().await?;
        }

        Ok(())
    }

    pub async fn stop(&mut self) -> EgoResult<()> {
        if let Some(handle) = self.batch_handle.take() {
            handle.abort();
        }
        if let Some(handle) = self.commit_handle.take() {
            handle.abort();
        }
        if let Some(handle) = self.metrics_handle.take() {
            handle.abort();
        }
        if let Some(handle) = self.cellular_monitor_handle.take() {
            handle.abort();
        }
        if let Some(handle) = self.deploy_policy_handle.take() {
            handle.abort();
        }
        if let Some(handle) = self.drs_update_handle.take() {
            handle.abort();
        }

        let operator_clone = Arc::clone(&self.operator);
        let mut operator_mut =
            Arc::try_unwrap(operator_clone).unwrap_or_else(|arc| RollupOperator::clone(&arc));

        operator_mut.stop().await?;

        Ok(())
    }

    async fn start_batch_processing(&mut self) -> EgoResult<()> {
        let operator = self.operator.clone();
        let batch_timeout = operator.config.batch_timeout();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(batch_timeout);

            loop {
                interval.tick().await;

                let is_active = *operator.is_active.read().await;
                if !is_active {
                    break;
                }

                if let Err(_e) = operator.process_transactions().await {
                    let mut metrics = operator.metrics.write().await;
                    metrics.record_error("batch_processing");
                }
            }
        });

        self.batch_handle = Some(handle);
        Ok(())
    }

    async fn start_commit_scheduling(&mut self) -> EgoResult<()> {
        let operator = self.operator.clone();
        let commit_frequency = Duration::from_secs(operator.config.commit_frequency_secs);

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(commit_frequency);

            loop {
                interval.tick().await;

                let is_active = *operator.is_active.read().await;
                if !is_active {
                    break;
                }

                if let Err(_e) = operator.advance_epoch().await {}
            }
        });

        self.commit_handle = Some(handle);
        Ok(())
    }

    async fn start_metrics_monitoring(&mut self) -> EgoResult<()> {
        let operator = self.operator.clone();
        let monitoring_interval = Duration::from_secs(60);

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(monitoring_interval);

            loop {
                interval.tick().await;

                let is_active = *operator.is_active.read().await;
                if !is_active {
                    break;
                }

                let metrics = operator.metrics.read().await;
                if !metrics.is_healthy() {}
            }
        });

        self.metrics_handle = Some(handle);
        Ok(())
    }

    async fn start_cellular_monitoring(&mut self) -> EgoResult<()> {
        let operator = self.operator.clone();
        let check_interval = Duration::from_secs(300);

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(check_interval);

            loop {
                interval.tick().await;

                let is_active = *operator.is_active.read().await;
                if !is_active {
                    break;
                }

                if let Ok(within_budget) = operator.check_cellular_budget().await {
                    if !within_budget {
                        let _ = operator.switch_connection(ConnectionType::WiFi).await;
                    }
                }
            }
        });

        self.cellular_monitor_handle = Some(handle);
        Ok(())
    }

    async fn start_deploy_policy_monitoring(&mut self) -> EgoResult<()> {
        let operator = self.operator.clone();
        let check_interval = Duration::from_secs(120);

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(check_interval);

            loop {
                interval.tick().await;

                let is_active = *operator.is_active.read().await;
                if !is_active {
                    break;
                }

                if let Some(stats) = operator.get_deploy_policy_stats().await {
                    if stats.rejected_spam > 100 {
                        let mut metrics = operator.metrics.write().await;
                        metrics.record_error("high_spam_rate");
                    }
                }
            }
        });

        self.deploy_policy_handle = Some(handle);
        Ok(())
    }

    async fn start_drs_updates(&mut self) -> EgoResult<()> {
        let operator = self.operator.clone();
        let update_interval = Duration::from_secs(180);

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(update_interval);

            loop {
                interval.tick().await;

                let is_active = *operator.is_active.read().await;
                if !is_active {
                    break;
                }

                let epoch = *operator.epoch.read().await;
                if let Some(stats) = operator.get_drs_epoch_stats(epoch).await {
                    if stats.total_nodes > 0 {
                        let mut metrics = operator.metrics.write().await;
                        metrics.record_drs_computation();
                    }
                }
            }
        });

        self.drs_update_handle = Some(handle);
        Ok(())
    }

    pub async fn submit_transaction(&self, tx: Transaction) -> EgoResult<Hash> {
        self.operator.submit_transaction(tx).await
    }

    pub async fn get_operator_info(&self) -> OperatorInfo {
        self.operator.get_operator_info().await
    }

    pub async fn get_metrics(&self) -> OperatorMetrics {
        self.operator.get_metrics().await
    }

    pub async fn finalize_commitment(&self, commitment_hash: Hash) -> EgoResult<()> {
        self.operator.finalize_commitment(commitment_hash).await
    }

    pub async fn handle_challenge(
        &self,
        commitment_hash: Hash,
        challenge_hash: Hash,
    ) -> EgoResult<()> {
        self.operator
            .handle_challenge(commitment_hash, challenge_hash)
            .await
    }

    pub async fn handle_slash(&self, commitment_hash: Hash, slash_amount: u64) -> EgoResult<()> {
        self.operator
            .handle_slash(commitment_hash, slash_amount)
            .await
    }

    pub async fn switch_connection(&self, connection_type: ConnectionType) -> EgoResult<()> {
        self.operator.switch_connection(connection_type).await
    }

    pub async fn check_cellular_budget(&self) -> EgoResult<bool> {
        self.operator.check_cellular_budget().await
    }

    pub async fn reset_metrics(&self) {
        self.operator.reset_metrics().await
    }

    pub async fn get_batch(&self, batch_hash: Hash) -> Option<RollupBatch> {
        self.operator.get_batch(batch_hash).await
    }

    pub async fn get_commitment(&self, commitment_hash: Hash) -> Option<RollupCommitmentData> {
        self.operator.get_commitment(commitment_hash).await
    }

    pub async fn update_deploy_policy_config(
        &self,
        new_config: ego_core::deploy_policy::DeployPolicyConfig,
    ) -> EgoResult<()> {
        self.operator.update_deploy_policy_config(new_config).await
    }

    pub async fn update_drs_config(&self, new_config: ego_core::drs::DRSConfig) -> EgoResult<()> {
        self.operator.update_drs_config(new_config).await
    }

    pub async fn get_deploy_policy_stats(
        &self,
    ) -> Option<ego_core::deploy_policy::EpochDeployStats> {
        self.operator.get_deploy_policy_stats().await
    }

    pub async fn get_drs_epoch_stats(&self, epoch: u64) -> Option<ego_core::drs::EpochStats> {
        self.operator.get_drs_epoch_stats(epoch).await
    }

    pub fn operator(&self) -> Arc<RollupOperator> {
        Arc::clone(&self.operator)
    }

    pub fn address(&self) -> Address {
        self.operator.address()
    }

    pub fn rollup_id(&self) -> &str {
        self.operator.rollup_id()
    }

    pub fn shard_id(&self) -> ShardId {
        self.operator.shard_id()
    }

    pub async fn is_active(&self) -> bool {
        *self.operator.is_active.read().await
    }

    pub async fn advance_epoch(&self) -> EgoResult<()> {
        self.operator.advance_epoch().await
    }
}

pub fn create_test_operator_config(
    rollup_id: String,
    shard_id: u32,
    enable_5g: bool,
) -> OperatorConfig {
    OperatorConfig {
        rollup_id,
        chain_id: 1,
        network_id: 1,
        shard_id: ShardId::new(shard_id).unwrap(),
        bond_amount: Balance::from_egoc(100_000),
        max_batch_size: if enable_5g {
            MAX_BATCH_SIZE_5G
        } else {
            MAX_BATCH_SIZE_CELLULAR
        },
        max_gas_limit: MAX_BATCH_GAS,
        batch_timeout_ms: if enable_5g {
            BATCH_TIMEOUT_5G_MS
        } else {
            BATCH_TIMEOUT_MS
        },
        commit_frequency_secs: COMMIT_FREQUENCY_SECS,
        challenge_window_blocks: CHALLENGE_WINDOW_BLOCKS,
        da_chunk_size: DA_CHUNK_SIZE,
        erasure_k: ERASURE_K,
        erasure_m: ERASURE_M,
        enable_compression: true,
        compression_level: 6,
        cellular_safe_mode: !enable_5g,
        max_cellular_data_gb_month: MAX_CELLULAR_DATA_GB_MONTH,
        enable_5g,
        slice_id: None,
        edge_nodes: Vec::new(),
        require_dilithium: true,
        wifi_only_operations: vec!["commitment_post".to_string(), "da_upload".to_string()],
        drs_enabled: true,
        deploy_policy_enabled: true,
        enable_ai_pattern_detection: true,
        require_human_verification: false,
    }
}

pub fn create_test_operator(
    rollup_id: String,
    shard_id: u32,
    keypair: ego_core::crypto::KeyPair,
) -> EgoResult<RollupOperator> {
    let config = create_test_operator_config(rollup_id, shard_id, false);
    let state_manager = StateManager::new(config.chain_id, config.network_id);
    RollupOperator::new(config, keypair, state_manager)
}

pub async fn estimate_batch_size(transactions: &[Transaction]) -> usize {
    let config = bincode::config::standard();
    bincode::encode_to_vec(transactions, config)
        .map(|data| data.len())
        .unwrap_or(0)
}

pub async fn estimate_da_overhead(batch_size: usize, erasure_k: u16, erasure_m: u16) -> usize {
    let total_chunks = erasure_k + erasure_m;
    let overhead_ratio = total_chunks as f64 / erasure_k as f64;
    (batch_size as f64 * overhead_ratio) as usize
}

pub fn calculate_cellular_data_usage(
    batches_processed: u64,
    avg_batch_size_kb: u64,
    da_overhead_ratio: f64,
) -> u64 {
    let base_usage = batches_processed * avg_batch_size_kb;
    let total_usage = (base_usage as f64 * (1.0 + da_overhead_ratio)) as u64;
    total_usage / 1024
}

pub fn is_within_cellular_budget(current_usage_mb: u64, max_monthly_gb: u64) -> bool {
    current_usage_mb < (max_monthly_gb * 1024)
}

pub async fn validate_rollup_commitment(
    commitment: &RollupCommitmentData,
    operator_pubkey: &PublicKey,
) -> EgoResult<bool> {
    let signing_data = commitment.compute_hash();

    if let Some(ref sig) = commitment.operator_signature.dilithium_sig {
        ego_core::crypto::verify_signature(operator_pubkey, signing_data.as_bytes(), sig)
    } else {
        Ok(false)
    }
}

pub async fn validate_batch_integrity(
    batch: &RollupBatch,
    operator_pubkey: &PublicKey,
) -> EgoResult<bool> {
    batch.verify_signature(operator_pubkey)
}

pub fn calculate_commitment_hash(
    batch_id: Hash,
    state_root: Hash,
    tx_root: Hash,
    da_root: Hash,
    deploy_root: Hash,
    drs_root: Hash,
    epoch: u64,
) -> Hash {
    let mut data = Vec::new();
    data.extend_from_slice(b"ego/rollup/commit/v1");
    data.extend_from_slice(batch_id.as_bytes());
    data.extend_from_slice(state_root.as_bytes());
    data.extend_from_slice(tx_root.as_bytes());
    data.extend_from_slice(da_root.as_bytes());
    data.extend_from_slice(deploy_root.as_bytes());
    data.extend_from_slice(drs_root.as_bytes());
    data.extend_from_slice(&epoch.to_le_bytes());
    ego_core::crypto::hash_data(&data)
}

pub fn estimate_commitment_latency(
    connection_type: ConnectionType,
    commitment_size_kb: u64,
) -> Duration {
    let base_latency_ms = match connection_type {
        ConnectionType::Cellular5G => 10,
        ConnectionType::Cellular4G => 50,
        ConnectionType::WiFi => 20,
        ConnectionType::Ethernet => 5,
        ConnectionType::Unknown => 100,
    };

    let bandwidth_mbps = match connection_type {
        ConnectionType::Cellular5G => 100.0,
        ConnectionType::Cellular4G => 20.0,
        ConnectionType::WiFi => 50.0,
        ConnectionType::Ethernet => 100.0,
        ConnectionType::Unknown => 10.0,
    };

    let transfer_time_ms = (commitment_size_kb as f64 * 8.0) / (bandwidth_mbps * 1000.0) * 1000.0;
    let total_latency_ms = base_latency_ms + transfer_time_ms as u64;

    Duration::from_millis(total_latency_ms)
}

pub fn should_switch_to_wifi(
    cellular_usage_mb: u64,
    max_monthly_gb: u64,
    threshold_pct: f64,
) -> bool {
    let max_mb = max_monthly_gb * 1024;
    let threshold_mb = (max_mb as f64 * threshold_pct) as u64;
    cellular_usage_mb >= threshold_mb
}

pub fn calculate_operator_reputation(
    total_commits: u64,
    finalized_commits: u64,
    successful_challenges: u64,
    failed_challenges: u64,
    slashes: u64,
) -> f64 {
    if total_commits == 0 {
        return 1.0;
    }

    let finalization_rate = finalized_commits as f64 / total_commits as f64;
    let challenge_success_rate = if successful_challenges + failed_challenges > 0 {
        successful_challenges as f64 / (successful_challenges + failed_challenges) as f64
    } else {
        1.0
    };

    let slash_penalty = (slashes as f64 * 0.2).min(0.5);

    let reputation = (finalization_rate * 0.5 + challenge_success_rate * 0.5 - slash_penalty)
        .max(0.0)
        .min(1.0);

    reputation
}

pub fn estimate_batch_gas(transactions: &[Transaction]) -> u64 {
    transactions
        .iter()
        .map(|tx| tx.estimate_resource_units())
        .sum()
}

pub fn can_fit_in_batch(
    current_gas: u64,
    current_count: usize,
    tx_gas: u64,
    max_gas: u64,
    max_count: usize,
) -> bool {
    current_gas + tx_gas <= max_gas && current_count < max_count
}

pub async fn compress_batch_data(data: &[u8], compression_level: u32) -> EgoResult<Vec<u8>> {
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(compression_level));
    encoder
        .write_all(data)
        .map_err(|e| EgoError::SerializationError(e.to_string()))?;
    encoder
        .finish()
        .map_err(|e| EgoError::SerializationError(e.to_string()))
}

pub async fn decompress_batch_data(compressed_data: &[u8]) -> EgoResult<Vec<u8>> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;

    let mut decoder = ZlibDecoder::new(compressed_data);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| EgoError::SerializationError(e.to_string()))?;
    Ok(decompressed)
}

pub fn calculate_da_chunk_count(
    data_size: usize,
    chunk_size: usize,
    erasure_k: u16,
    erasure_m: u16,
) -> u32 {
    let data_chunks = (data_size + chunk_size - 1) / chunk_size;
    let total_chunks = erasure_k + erasure_m;
    let erasure_groups = (data_chunks + erasure_k as usize - 1) / erasure_k as usize;
    (erasure_groups * total_chunks as usize) as u32
}

pub fn validate_operator_config(config: &OperatorConfig) -> EgoResult<()> {
    if config.max_batch_size == 0 {
        return Err(EgoError::InvalidTransaction(
            "max_batch_size cannot be zero".to_string(),
        ));
    }

    if config.max_gas_limit == 0 {
        return Err(EgoError::InvalidTransaction(
            "max_gas_limit cannot be zero".to_string(),
        ));
    }

    if config.erasure_k == 0 || config.erasure_m == 0 {
        return Err(EgoError::InvalidTransaction(
            "erasure coding parameters cannot be zero".to_string(),
        ));
    }

    if config.da_chunk_size == 0 {
        return Err(EgoError::InvalidTransaction(
            "da_chunk_size cannot be zero".to_string(),
        ));
    }

    if config.bond_amount.as_u128() == 0 {
        return Err(EgoError::InvalidTransaction(
            "bond_amount cannot be zero".to_string(),
        ));
    }

    Ok(())
}
