use crate::error::{RollupError, RollupResult};
use ego_core::{Address, AlgorithmId, Balance, Hash, ShardId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollupConfig {
    pub chain_id: u32,
    pub network_id: u32,
    pub rollup_id: String,
    pub protocol_version: u32,
    pub l1_contract: Address,
    pub operator: OperatorConfig,
    pub da: DAConfig,
    pub fraud_proofs: FraudProofConfig,
    pub network: NetworkConfig,
    pub performance: PerformanceConfig,
    pub five_g: FiveGConfig,
    pub security: SecurityConfig,
    pub storage: StorageConfig,
    pub sharding: ShardingConfig,
    pub proofs: ProofsConfig,
    pub drs: DRSConfig,
    pub economics: EconomicsConfig,
    pub cellular: CellularConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorConfig {
    pub address: Address,
    pub dilithium_pk: Vec<u8>,
    pub mlkem_pk: Vec<u8>,
    pub ed25519_pk: Option<Vec<u8>>,
    pub bond_amount: Balance,
    pub collateral_locked: Balance,
    pub max_batch_size: u32,
    pub min_batch_size: u32,
    pub max_gas_limit: u64,
    pub batch_timeout_secs: u64,
    pub commit_frequency_secs: u64,
    pub auto_batch: bool,
    pub l1_gas_price: u64,
    pub max_pending_batches: u32,
    pub max_concurrent_commits: u32,
    pub enable_batch_compression: bool,
    pub compression_level: i32,
    pub enable_snark_aggregation: bool,
    pub attestation_required: bool,
    pub device_cert_path: Option<PathBuf>,
    pub tpm_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DAConfig {
    pub k: u16,
    pub m: u16,
    pub n: u16,
    pub chunk_size: usize,
    pub sample_size: usize,
    pub enable_compression: bool,
    pub compression_level: i32,
    pub storage_duration_epochs: u64,
    pub replication_factor: u8,
    pub enable_erasure_coding: bool,
    pub max_blob_size: usize,
    pub anchor_window_hours: u64,
    pub response_window_blocks: u64,
    pub chunk_serve_timeout_ms: u64,
    pub enable_ipfs: bool,
    pub ipfs_gateway: Option<String>,
    pub enable_car_snapshots: bool,
    pub enable_ipns: bool,
    pub max_evidence_bundle_size: usize,
    pub daily_anchor_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudProofConfig {
    pub challenge_period_blocks: u64,
    pub response_window_blocks: u64,
    pub min_confidence: f64,
    pub max_age_hours: u64,
    pub min_failure_rate: f64,
    pub enable_snark_aggregation: bool,
    pub challenge_bond: Balance,
    pub fraud_proof_window_blocks: u64,
    pub max_challenges_per_commitment: u32,
    pub slashing_percentage: u16,
    pub challenger_reward_percentage: u16,
    pub enable_optimistic_verification: bool,
    pub dispute_resolution_timeout_blocks: u64,
    pub min_stake_to_challenge: Balance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub listen_address: String,
    pub listen_port: u16,
    pub bootstrap_peers: Vec<String>,
    pub max_peers: u32,
    pub connection_timeout: Duration,
    pub enable_mdns: bool,
    pub gossip: GossipConfig,
    pub enable_nat_traversal: bool,
    pub max_bandwidth_mbps: u32,
    pub enable_quic: bool,
    pub enable_tcp: bool,
    pub enable_upnp: bool,
    pub relay_enabled: bool,
    pub relay_max_circuits: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipConfig {
    pub heartbeat_interval: Duration,
    pub max_message_size: usize,
    pub duplicate_cache_time: Duration,
    pub validation_mode: ValidationMode,
    pub mesh_n: usize,
    pub mesh_n_low: usize,
    pub mesh_n_high: usize,
    pub gossip_lazy: usize,
    pub gossip_factor: f64,
    pub opportunistic_graft_ticks: u64,
    pub prune_backoff: Duration,
    pub topics: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationMode {
    Strict,
    Permissive,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub worker_threads: usize,
    pub batch_parallelism: usize,
    pub state_cache_size: usize,
    pub tx_pool_size: usize,
    pub enable_metrics: bool,
    pub metrics_port: u16,
    pub metrics_address: String,
    pub enable_profiling: bool,
    pub max_concurrent_batches: usize,
    pub proof_verification_threads: usize,
    pub signature_verification_batch_size: usize,
    pub cpu_budget_per_batch: u64,
    pub enable_backpressure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiveGConfig {
    pub enabled: bool,
    pub slice_id: Option<String>,
    pub qos_class: u8,
    pub latency_target_ms: u32,
    pub bandwidth_mbps: u32,
    pub enable_edge_computing: bool,
    pub edge_nodes: Vec<String>,
    pub cellular_safe_mode: bool,
    pub max_cellular_data_gb_per_month: u64,
    pub wifi_only_operations: Vec<String>,
    pub urllc_enabled: bool,
    pub embb_enabled: bool,
    pub mmtc_enabled: bool,
    pub network_slice_params: NetworkSliceParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSliceParams {
    pub slice_differentiator: u8,
    pub slice_service_type: u8,
    pub session_ambr_ul: u64,
    pub session_ambr_dl: u64,
    pub priority_level: u8,
    pub resource_type: ResourceType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceType {
    GBR,
    NonGBR,
    DelayGBR,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub enable_pq_signatures: bool,
    pub require_dilithium: bool,
    pub transition_mode: bool,
    pub enable_ed25519_fallback: bool,
    pub pq_only_mode: bool,
    pub pq_transition_phase: u8,
    pub legacy_support_end_epoch: Option<u64>,
    pub max_tx_size_bytes: usize,
    pub enable_rate_limiting: bool,
    pub rate_limit_per_second: u32,
    pub enable_tpm: bool,
    pub enable_secure_boot: bool,
    pub enable_encrypted_disk: bool,
    pub enable_attestation: bool,
    pub attestation_interval_blocks: u64,
    pub supported_algorithms: Vec<u16>,
    pub required_algorithms: Vec<u16>,
    pub enable_slh_dsa_anchors: bool,
    pub kyber_kem_enabled: bool,
    pub x25519_fallback_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub data_dir: PathBuf,
    pub enable_pruning: bool,
    pub keep_epochs: u64,
    pub snapshot_interval_epochs: u64,
    pub max_storage_gb: u64,
    pub enable_compression: bool,
    pub compression_algorithm: CompressionAlgorithm,
    pub db_backend: DatabaseBackend,
    pub rocksdb_config: RocksDBConfig,
    pub enable_state_snapshots: bool,
    pub enable_archival_mode: bool,
    pub archival_replication_factor: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompressionAlgorithm {
    Zstd,
    Lz4,
    Snappy,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DatabaseBackend {
    RocksDB,
    SurrealDB,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RocksDBConfig {
    pub max_open_files: i32,
    pub write_buffer_size: usize,
    pub max_write_buffer_number: i32,
    pub target_file_size_base: u64,
    pub level_zero_file_num_compaction_trigger: i32,
    pub enable_statistics: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardingConfig {
    pub enabled: bool,
    pub num_shards: u32,
    pub shard_ids: Vec<ShardId>,
    pub per_shard_mempool: bool,
    pub per_shard_consensus: bool,
    pub cross_shard_enabled: bool,
    pub cross_shard_receipt_timeout_blocks: u64,
    pub shard_prefix_bits: u8,
    pub enable_global_finality: bool,
    pub finality_committee_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofsConfig {
    pub post_enabled: bool,
    pub porep_enabled: bool,
    pub poc_enabled: bool,
    pub post_frequency_epochs: u64,
    pub post_window_duration_epochs: u64,
    pub post_sla_ms: u32,
    pub post_challenge_count: u32,
    pub post_partition_size: u32,
    pub porep_sector_size_gib: u32,
    pub porep_params_version: u32,
    pub porep_stacked_drg_layers: u8,
    pub porep_base_degree: u8,
    pub poc_beacon_frequency_hz: f64,
    pub poc_witness_min_count: u32,
    pub poc_h3_resolution: u8,
    pub poc_quality_min: f64,
    pub enable_gpu_proving: bool,
    pub gpu_device_id: Option<u32>,
    pub enable_batch_verification: bool,
    pub proof_aggregation_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DRSConfig {
    pub enabled: bool,
    pub calculation_epoch_interval: u64,
    pub uptime_weight: f64,
    pub post_latency_weight: f64,
    pub post_pass_rate_weight: f64,
    pub poc_quality_weight: f64,
    pub serve_ratio_weight: f64,
    pub density_penalty_weight: f64,
    pub multiplier_min: f64,
    pub multiplier_max: f64,
    pub weights_version: u32,
    pub enable_puc: bool,
    pub puc_coefficient_range: (f64, f64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicsConfig {
    pub enable_emissions: bool,
    pub initial_supply: Balance,
    pub emission_rate_per_epoch: Balance,
    pub halving_interval_epochs: u64,
    pub storage_bucket_percentage: u16,
    pub consensus_bucket_percentage: u16,
    pub coverage_bucket_percentage: u16,
    pub dao_bucket_percentage: u16,
    pub enable_feeless_ux: bool,
    pub pob_burn_enabled: bool,
    pub storage_credits_rate: u64,
    pub deploy_credits_rate: u64,
    pub free_deploy_quota_per_epoch: u32,
    pub deploy_bond_amount: Balance,
    pub deploy_bond_duration_blocks: u64,
    pub retrieval_fee_per_gb: Balance,
    pub enable_staking: bool,
    pub min_stake_amount: Balance,
    pub validator_commission_max: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellularConfig {
    pub enabled: bool,
    pub safe_mode_default: bool,
    pub max_monthly_usage_gb: u64,
    pub throttle_threshold_gb: u64,
    pub enable_cost_tracking: bool,
    pub max_monthly_cost_usd: f64,
    pub enable_wifi_offload: bool,
    pub offload_threshold_percentage: u8,
    pub heavy_operations_wifi_only: bool,
    pub batch_operations_enabled: bool,
    pub batch_window_secs: u64,
    pub compression_mandatory: bool,
    pub enable_usage_alerts: bool,
    pub alert_threshold_percentage: u8,
}

impl Default for RollupConfig {
    fn default() -> Self {
        Self {
            chain_id: 1,
            network_id: 1,
            rollup_id: "ego-rollup-1".to_string(),
            protocol_version: 1,
            l1_contract: Address::new([0u8; 20]),
            operator: OperatorConfig::default(),
            da: DAConfig::default(),
            fraud_proofs: FraudProofConfig::default(),
            network: NetworkConfig::default(),
            performance: PerformanceConfig::default(),
            five_g: FiveGConfig::default(),
            security: SecurityConfig::default(),
            storage: StorageConfig::default(),
            sharding: ShardingConfig::default(),
            proofs: ProofsConfig::default(),
            drs: DRSConfig::default(),
            economics: EconomicsConfig::default(),
            cellular: CellularConfig::default(),
        }
    }
}

impl Default for OperatorConfig {
    fn default() -> Self {
        Self {
            address: Address::new([0u8; 20]),
            dilithium_pk: vec![0u8; 1312],
            mlkem_pk: vec![0u8; 1184],
            ed25519_pk: None,
            bond_amount: Balance::new(1_000_000_000_000_000_000),
            collateral_locked: Balance::ZERO,
            max_batch_size: 1000,
            min_batch_size: 1,
            max_gas_limit: 10_000_000,
            batch_timeout_secs: 30,
            commit_frequency_secs: 300,
            auto_batch: true,
            l1_gas_price: 20_000_000_000,
            max_pending_batches: 10,
            max_concurrent_commits: 5,
            enable_batch_compression: true,
            compression_level: 6,
            enable_snark_aggregation: false,
            attestation_required: true,
            device_cert_path: None,
            tpm_enabled: false,
        }
    }
}

impl Default for DAConfig {
    fn default() -> Self {
        Self {
            k: 128,
            m: 64,
            n: 192,
            chunk_size: 65536,
            sample_size: 16,
            enable_compression: true,
            compression_level: 6,
            storage_duration_epochs: 7200,
            replication_factor: 3,
            enable_erasure_coding: true,
            max_blob_size: 10 * 1024 * 1024,
            anchor_window_hours: 24,
            response_window_blocks: 100,
            chunk_serve_timeout_ms: 300,
            enable_ipfs: true,
            ipfs_gateway: None,
            enable_car_snapshots: true,
            enable_ipns: true,
            max_evidence_bundle_size: 50 * 1024 * 1024,
            daily_anchor_enabled: true,
        }
    }
}

impl Default for FraudProofConfig {
    fn default() -> Self {
        Self {
            challenge_period_blocks: 1000,
            response_window_blocks: 100,
            min_confidence: 0.8,
            max_age_hours: 24,
            min_failure_rate: 0.6,
            enable_snark_aggregation: false,
            challenge_bond: Balance::new(100_000_000_000_000_000),
            fraud_proof_window_blocks: 1000,
            max_challenges_per_commitment: 5,
            slashing_percentage: 1000,
            challenger_reward_percentage: 500,
            enable_optimistic_verification: true,
            dispute_resolution_timeout_blocks: 500,
            min_stake_to_challenge: Balance::new(50_000_000_000_000_000),
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_address: "0.0.0.0".to_string(),
            listen_port: 9100,
            bootstrap_peers: vec![],
            max_peers: 50,
            connection_timeout: Duration::from_secs(30),
            enable_mdns: true,
            gossip: GossipConfig::default(),
            enable_nat_traversal: true,
            max_bandwidth_mbps: 1000,
            enable_quic: true,
            enable_tcp: true,
            enable_upnp: true,
            relay_enabled: true,
            relay_max_circuits: 32,
        }
    }
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval: Duration::from_secs(10),
            max_message_size: 2 * 1024 * 1024,
            duplicate_cache_time: Duration::from_secs(120),
            validation_mode: ValidationMode::Strict,
            mesh_n: 6,
            mesh_n_low: 4,
            mesh_n_high: 12,
            gossip_lazy: 6,
            gossip_factor: 0.25,
            opportunistic_graft_ticks: 60,
            prune_backoff: Duration::from_secs(60),
            topics: vec![
                "ego/tx".to_string(),
                "ego/headers".to_string(),
                "ego/proofs".to_string(),
                "ego/receipts".to_string(),
                "ego/finality/commits".to_string(),
            ],
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            worker_threads: num_cpus::get(),
            batch_parallelism: 4,
            state_cache_size: 10000,
            tx_pool_size: 50000,
            enable_metrics: true,
            metrics_port: 9090,
            metrics_address: "127.0.0.1".to_string(),
            enable_profiling: false,
            max_concurrent_batches: 5,
            proof_verification_threads: num_cpus::get(),
            signature_verification_batch_size: 128,
            cpu_budget_per_batch: 1_000_000,
            enable_backpressure: true,
        }
    }
}

impl Default for FiveGConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            slice_id: None,
            qos_class: 1,
            latency_target_ms: 10,
            bandwidth_mbps: 100,
            enable_edge_computing: false,
            edge_nodes: vec![],
            cellular_safe_mode: true,
            max_cellular_data_gb_per_month: 5,
            wifi_only_operations: vec![
                "large_storage".to_string(),
                "heavy_compute".to_string(),
                "bulk_sync".to_string(),
                "full_state_sync".to_string(),
                "archival_snapshot".to_string(),
            ],
            urllc_enabled: false,
            embb_enabled: false,
            mmtc_enabled: false,
            network_slice_params: NetworkSliceParams::default(),
        }
    }
}

impl Default for NetworkSliceParams {
    fn default() -> Self {
        Self {
            slice_differentiator: 1,
            slice_service_type: 1,
            session_ambr_ul: 100_000_000,
            session_ambr_dl: 100_000_000,
            priority_level: 5,
            resource_type: ResourceType::NonGBR,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_pq_signatures: true,
            require_dilithium: true,
            transition_mode: false,
            enable_ed25519_fallback: false,
            pq_only_mode: false,
            pq_transition_phase: 1,
            legacy_support_end_epoch: None,
            max_tx_size_bytes: 100 * 1024,
            enable_rate_limiting: true,
            rate_limit_per_second: 100,
            enable_tpm: false,
            enable_secure_boot: false,
            enable_encrypted_disk: false,
            enable_attestation: true,
            attestation_interval_blocks: 1000,
            supported_algorithms: vec![
                AlgorithmId::MlDsa2.as_u16(),
                AlgorithmId::Ed25519.as_u16(),
                AlgorithmId::MlKem768.as_u16(),
            ],
            required_algorithms: vec![AlgorithmId::MlDsa2.as_u16()],
            enable_slh_dsa_anchors: false,
            kyber_kem_enabled: true,
            x25519_fallback_enabled: false,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./rollup-data"),
            enable_pruning: true,
            keep_epochs: 100,
            snapshot_interval_epochs: 1000,
            max_storage_gb: 100,
            enable_compression: true,
            compression_algorithm: CompressionAlgorithm::Zstd,
            db_backend: DatabaseBackend::RocksDB,
            rocksdb_config: RocksDBConfig::default(),
            enable_state_snapshots: true,
            enable_archival_mode: false,
            archival_replication_factor: 3,
        }
    }
}

impl Default for RocksDBConfig {
    fn default() -> Self {
        Self {
            max_open_files: 1000,
            write_buffer_size: 128 * 1024 * 1024,
            max_write_buffer_number: 4,
            target_file_size_base: 64 * 1024 * 1024,
            level_zero_file_num_compaction_trigger: 4,
            enable_statistics: true,
        }
    }
}

impl Default for ShardingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            num_shards: 1,
            shard_ids: vec![ShardId::new(0).unwrap()],
            per_shard_mempool: true,
            per_shard_consensus: true,
            cross_shard_enabled: false,
            cross_shard_receipt_timeout_blocks: 1000,
            shard_prefix_bits: 4,
            enable_global_finality: true,
            finality_committee_size: 64,
        }
    }
}

impl Default for ProofsConfig {
    fn default() -> Self {
        Self {
            post_enabled: true,
            porep_enabled: true,
            poc_enabled: false,
            post_frequency_epochs: 1,
            post_window_duration_epochs: 1,
            post_sla_ms: 8000,
            post_challenge_count: 32,
            post_partition_size: 2349,
            porep_sector_size_gib: 32,
            porep_params_version: 1,
            porep_stacked_drg_layers: 11,
            porep_base_degree: 6,
            poc_beacon_frequency_hz: 1.0,
            poc_witness_min_count: 3,
            poc_h3_resolution: 8,
            poc_quality_min: 0.5,
            enable_gpu_proving: false,
            gpu_device_id: None,
            enable_batch_verification: true,
            proof_aggregation_enabled: true,
        }
    }
}

impl Default for DRSConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            calculation_epoch_interval: 1,
            uptime_weight: 0.2,
            post_latency_weight: 0.2,
            post_pass_rate_weight: 0.2,
            poc_quality_weight: 0.2,
            serve_ratio_weight: 0.1,
            density_penalty_weight: 0.1,
            multiplier_min: 0.7,
            multiplier_max: 1.3,
            weights_version: 1,
            enable_puc: false,
            puc_coefficient_range: (0.8, 1.2),
        }
    }
}

impl Default for EconomicsConfig {
    fn default() -> Self {
        Self {
            enable_emissions: true,
            initial_supply: Balance::new(1_000_000_000_000_000_000_000_000),
            emission_rate_per_epoch: Balance::new(1_000_000_000_000_000_000),
            halving_interval_epochs: 525600,
            storage_bucket_percentage: 4000,
            consensus_bucket_percentage: 3000,
            coverage_bucket_percentage: 2000,
            dao_bucket_percentage: 1000,
            enable_feeless_ux: true,
            pob_burn_enabled: true,
            storage_credits_rate: 1000,
            deploy_credits_rate: 500,
            free_deploy_quota_per_epoch: 5,
            deploy_bond_amount: Balance::new(1_000_000_000_000_000),
            deploy_bond_duration_blocks: 1000,
            retrieval_fee_per_gb: Balance::new(100_000_000_000_000),
            enable_staking: true,
            min_stake_amount: Balance::new(1_000_000_000_000_000_000),
            validator_commission_max: 2000,
        }
    }
}

impl Default for CellularConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            safe_mode_default: true,
            max_monthly_usage_gb: 5,
            throttle_threshold_gb: 4,
            enable_cost_tracking: true,
            max_monthly_cost_usd: 50.0,
            enable_wifi_offload: true,
            offload_threshold_percentage: 80,
            heavy_operations_wifi_only: true,
            batch_operations_enabled: true,
            batch_window_secs: 10,
            compression_mandatory: true,
            enable_usage_alerts: true,
            alert_threshold_percentage: 90,
        }
    }
}

impl RollupConfig {
    pub fn validate(&self) -> RollupResult<()> {
        if self.chain_id == 0 {
            return Err(RollupError::ConfigError("Chain ID must be > 0".to_string()));
        }

        if self.network_id == 0 {
            return Err(RollupError::ConfigError(
                "Network ID must be > 0".to_string(),
            ));
        }

        if self.rollup_id.is_empty() {
            return Err(RollupError::ConfigError(
                "Rollup ID cannot be empty".to_string(),
            ));
        }

        if self.protocol_version == 0 {
            return Err(RollupError::ConfigError(
                "Protocol version must be > 0".to_string(),
            ));
        }

        self.validate_da()?;
        self.validate_operator()?;
        self.validate_fraud_proofs()?;
        self.validate_five_g()?;
        self.validate_security()?;
        self.validate_storage()?;
        self.validate_sharding()?;
        self.validate_proofs()?;
        self.validate_drs()?;
        self.validate_economics()?;
        self.validate_cellular()?;

        Ok(())
    }

    fn validate_da(&self) -> RollupResult<()> {
        if (self.da.k + self.da.m) != self.da.n {
            return Err(RollupError::ConfigError(
                "DA parameters: k + m must equal n".to_string(),
            ));
        }

        if self.da.k == 0 || self.da.m == 0 {
            return Err(RollupError::ConfigError(
                "DA parameters: k and m must be > 0".to_string(),
            ));
        }

        if self.da.sample_size > self.da.k as usize {
            return Err(RollupError::ConfigError(
                "DA sample size cannot exceed k".to_string(),
            ));
        }

        if self.da.chunk_size == 0 {
            return Err(RollupError::ConfigError(
                "DA chunk size must be > 0".to_string(),
            ));
        }

        if self.da.replication_factor < 1 || self.da.replication_factor > 5 {
            return Err(RollupError::ConfigError(
                "DA replication factor must be between 1 and 5".to_string(),
            ));
        }

        if self.da.max_blob_size == 0 {
            return Err(RollupError::ConfigError(
                "DA max blob size must be > 0".to_string(),
            ));
        }

        if self.da.anchor_window_hours == 0 {
            return Err(RollupError::ConfigError(
                "DA anchor window must be > 0".to_string(),
            ));
        }

        Ok(())
    }

    fn validate_operator(&self) -> RollupResult<()> {
        if self.operator.bond_amount.as_u128() < 100_000_000_000_000_000 {
            return Err(RollupError::ConfigError(
                "Operator bond must be at least 0.1 EGOC".to_string(),
            ));
        }

        if self.operator.max_batch_size == 0 {
            return Err(RollupError::ConfigError(
                "Max batch size must be > 0".to_string(),
            ));
        }

        if self.operator.max_gas_limit == 0 {
            return Err(RollupError::ConfigError(
                "Max gas limit must be > 0".to_string(),
            ));
        }

        if self.operator.min_batch_size > self.operator.max_batch_size {
            return Err(RollupError::ConfigError(
                "Min batch size cannot exceed max batch size".to_string(),
            ));
        }

        if self.operator.batch_timeout_secs == 0 {
            return Err(RollupError::ConfigError(
                "Batch timeout must be > 0".to_string(),
            ));
        }

        if self.operator.commit_frequency_secs == 0 {
            return Err(RollupError::ConfigError(
                "Commit frequency must be > 0".to_string(),
            ));
        }

        if self.operator.dilithium_pk.is_empty() {
            return Err(RollupError::ConfigError(
                "Operator Dilithium public key is required".to_string(),
            ));
        }

        if self.operator.mlkem_pk.is_empty() {
            return Err(RollupError::ConfigError(
                "Operator ML-KEM public key is required".to_string(),
            ));
        }

        if self.operator.attestation_required && self.operator.device_cert_path.is_none() {
            return Err(RollupError::ConfigError(
                "Device certificate path required when attestation is enabled".to_string(),
            ));
        }

        Ok(())
    }

    fn validate_fraud_proofs(&self) -> RollupResult<()> {
        if self.fraud_proofs.min_confidence < 0.5 || self.fraud_proofs.min_confidence > 1.0 {
            return Err(RollupError::ConfigError(
                "Fraud proof confidence must be between 0.5 and 1.0".to_string(),
            ));
        }

        if self.fraud_proofs.challenge_period_blocks < 100 {
            return Err(RollupError::ConfigError(
                "Challenge period must be at least 100 blocks".to_string(),
            ));
        }

        if self.fraud_proofs.response_window_blocks == 0 {
            return Err(RollupError::ConfigError(
                "Response window must be > 0".to_string(),
            ));
        }

        if self.fraud_proofs.fraud_proof_window_blocks == 0 {
            return Err(RollupError::ConfigError(
                "Fraud proof window must be > 0".to_string(),
            ));
        }

        if self.fraud_proofs.challenge_bond.as_u128() == 0 {
            return Err(RollupError::ConfigError(
                "Challenge bond must be > 0".to_string(),
            ));
        }

        if self.fraud_proofs.slashing_percentage > 10000 {
            return Err(RollupError::ConfigError(
                "Slashing percentage cannot exceed 100%".to_string(),
            ));
        }

        if self.fraud_proofs.challenger_reward_percentage > 10000 {
            return Err(RollupError::ConfigError(
                "Challenger reward percentage cannot exceed 100%".to_string(),
            ));
        }

        Ok(())
    }

    fn validate_five_g(&self) -> RollupResult<()> {
        if self.five_g.enabled {
            if self.five_g.latency_target_ms == 0 {
                return Err(RollupError::ConfigError(
                    "5G latency target must be > 0".to_string(),
                ));
            }

            if self.five_g.bandwidth_mbps == 0 {
                return Err(RollupError::ConfigError(
                    "5G bandwidth allocation must be > 0".to_string(),
                ));
            }

            if self.five_g.qos_class > 9 {
                return Err(RollupError::ConfigError(
                    "5G QoS class must be between 0 and 9".to_string(),
                ));
            }

            if self.five_g.cellular_safe_mode && self.five_g.max_cellular_data_gb_per_month == 0 {
                return Err(RollupError::ConfigError(
                    "Max cellular data must be > 0 when cellular safe mode is enabled".to_string(),
                ));
            }
        }

        Ok(())
    }

    fn validate_security(&self) -> RollupResult<()> {
        if self.security.max_tx_size_bytes == 0 {
            return Err(RollupError::ConfigError(
                "Max transaction size must be > 0".to_string(),
            ));
        }

        if self.security.enable_rate_limiting && self.security.rate_limit_per_second == 0 {
            return Err(RollupError::ConfigError(
                "Rate limit must be > 0 when rate limiting is enabled".to_string(),
            ));
        }

        if self.security.pq_transition_phase > 3 {
            return Err(RollupError::ConfigError(
                "PQ transition phase must be between 0 and 3".to_string(),
            ));
        }

        if self.security.required_algorithms.is_empty() {
            return Err(RollupError::ConfigError(
                "At least one required algorithm must be specified".to_string(),
            ));
        }

        if self.security.pq_only_mode && !self.security.require_dilithium {
            return Err(RollupError::ConfigError(
                "Dilithium must be required in PQ-only mode".to_string(),
            ));
        }

        Ok(())
    }

    fn validate_storage(&self) -> RollupResult<()> {
        if self.storage.data_dir.as_os_str().is_empty() {
            return Err(RollupError::ConfigError(
                "Storage data directory cannot be empty".to_string(),
            ));
        }

        if self.storage.enable_pruning && self.storage.keep_epochs == 0 {
            return Err(RollupError::ConfigError(
                "Keep epochs must be > 0 when pruning is enabled".to_string(),
            ));
        }

        if self.storage.max_storage_gb == 0 {
            return Err(RollupError::ConfigError(
                "Max storage must be > 0".to_string(),
            ));
        }

        if self.storage.archival_replication_factor < 1
            || self.storage.archival_replication_factor > 5
        {
            return Err(RollupError::ConfigError(
                "Archival replication factor must be between 1 and 5".to_string(),
            ));
        }

        Ok(())
    }

    fn validate_sharding(&self) -> RollupResult<()> {
        if self.sharding.enabled {
            if self.sharding.num_shards == 0 {
                return Err(RollupError::ConfigError(
                    "Number of shards must be > 0".to_string(),
                ));
            }

            if self.sharding.shard_ids.len() != self.sharding.num_shards as usize {
                return Err(RollupError::ConfigError(
                    "Shard IDs count must match number of shards".to_string(),
                ));
            }

            if self.sharding.shard_prefix_bits > 8 {
                return Err(RollupError::ConfigError(
                    "Shard prefix bits cannot exceed 8".to_string(),
                ));
            }

            if self.sharding.cross_shard_enabled
                && self.sharding.cross_shard_receipt_timeout_blocks == 0
            {
                return Err(RollupError::ConfigError(
                    "Cross-shard receipt timeout must be > 0 when cross-shard is enabled"
                        .to_string(),
                ));
            }

            if self.sharding.enable_global_finality && self.sharding.finality_committee_size == 0 {
                return Err(RollupError::ConfigError(
                    "Finality committee size must be > 0 when global finality is enabled"
                        .to_string(),
                ));
            }
        }

        Ok(())
    }

    fn validate_proofs(&self) -> RollupResult<()> {
        if self.proofs.post_enabled {
            if self.proofs.post_frequency_epochs == 0 {
                return Err(RollupError::ConfigError(
                    "PoSt frequency must be > 0".to_string(),
                ));
            }

            if self.proofs.post_sla_ms == 0 {
                return Err(RollupError::ConfigError("PoSt SLA must be > 0".to_string()));
            }

            if self.proofs.post_challenge_count == 0 {
                return Err(RollupError::ConfigError(
                    "PoSt challenge count must be > 0".to_string(),
                ));
            }

            if self.proofs.post_partition_size == 0 {
                return Err(RollupError::ConfigError(
                    "PoSt partition size must be > 0".to_string(),
                ));
            }
        }

        if self.proofs.porep_enabled {
            if self.proofs.porep_sector_size_gib == 0 {
                return Err(RollupError::ConfigError(
                    "PoRep sector size must be > 0".to_string(),
                ));
            }

            if self.proofs.porep_stacked_drg_layers == 0 {
                return Err(RollupError::ConfigError(
                    "PoRep stacked DRG layers must be > 0".to_string(),
                ));
            }

            if self.proofs.porep_base_degree == 0 {
                return Err(RollupError::ConfigError(
                    "PoRep base degree must be > 0".to_string(),
                ));
            }
        }

        if self.proofs.poc_enabled {
            if self.proofs.poc_beacon_frequency_hz <= 0.0 {
                return Err(RollupError::ConfigError(
                    "PoC beacon frequency must be > 0".to_string(),
                ));
            }

            if self.proofs.poc_witness_min_count < 3 {
                return Err(RollupError::ConfigError(
                    "PoC minimum witness count must be >= 3".to_string(),
                ));
            }

            if self.proofs.poc_quality_min < 0.0 || self.proofs.poc_quality_min > 1.0 {
                return Err(RollupError::ConfigError(
                    "PoC quality minimum must be between 0.0 and 1.0".to_string(),
                ));
            }
        }

        Ok(())
    }

    fn validate_drs(&self) -> RollupResult<()> {
        if self.drs.enabled {
            let total_weight = self.drs.uptime_weight
                + self.drs.post_latency_weight
                + self.drs.post_pass_rate_weight
                + self.drs.poc_quality_weight
                + self.drs.serve_ratio_weight
                + self.drs.density_penalty_weight;

            if (total_weight - 1.0).abs() > 0.001 {
                return Err(RollupError::ConfigError(
                    "DRS weights must sum to 1.0".to_string(),
                ));
            }

            if self.drs.multiplier_min > self.drs.multiplier_max {
                return Err(RollupError::ConfigError(
                    "DRS multiplier min cannot exceed max".to_string(),
                ));
            }

            if self.drs.multiplier_min <= 0.0 {
                return Err(RollupError::ConfigError(
                    "DRS multiplier min must be > 0".to_string(),
                ));
            }

            if self.drs.calculation_epoch_interval == 0 {
                return Err(RollupError::ConfigError(
                    "DRS calculation epoch interval must be > 0".to_string(),
                ));
            }

            if self.drs.enable_puc {
                let (min, max) = self.drs.puc_coefficient_range;
                if min > max {
                    return Err(RollupError::ConfigError(
                        "PUC coefficient min cannot exceed max".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    fn validate_economics(&self) -> RollupResult<()> {
        if self.economics.enable_emissions {
            if self.economics.initial_supply.as_u128() == 0 {
                return Err(RollupError::ConfigError(
                    "Initial supply must be > 0".to_string(),
                ));
            }

            if self.economics.emission_rate_per_epoch.as_u128() == 0 {
                return Err(RollupError::ConfigError(
                    "Emission rate per epoch must be > 0".to_string(),
                ));
            }

            let total_percentage = self.economics.storage_bucket_percentage
                + self.economics.consensus_bucket_percentage
                + self.economics.coverage_bucket_percentage
                + self.economics.dao_bucket_percentage;

            if total_percentage != 10000 {
                return Err(RollupError::ConfigError(
                    "Bucket percentages must sum to 100%".to_string(),
                ));
            }
        }

        if self.economics.enable_staking {
            if self.economics.min_stake_amount.as_u128() == 0 {
                return Err(RollupError::ConfigError(
                    "Minimum stake amount must be > 0".to_string(),
                ));
            }

            if self.economics.validator_commission_max > 10000 {
                return Err(RollupError::ConfigError(
                    "Validator commission max cannot exceed 100%".to_string(),
                ));
            }
        }

        if self.economics.pob_burn_enabled {
            if self.economics.storage_credits_rate == 0 {
                return Err(RollupError::ConfigError(
                    "Storage credits rate must be > 0".to_string(),
                ));
            }

            if self.economics.deploy_credits_rate == 0 {
                return Err(RollupError::ConfigError(
                    "Deploy credits rate must be > 0".to_string(),
                ));
            }
        }

        Ok(())
    }

    fn validate_cellular(&self) -> RollupResult<()> {
        if self.cellular.enabled {
            if self.cellular.safe_mode_default {
                if self.cellular.max_monthly_usage_gb == 0 {
                    return Err(RollupError::ConfigError(
                        "Max monthly usage must be > 0 in cellular safe mode".to_string(),
                    ));
                }

                if self.cellular.throttle_threshold_gb > self.cellular.max_monthly_usage_gb {
                    return Err(RollupError::ConfigError(
                        "Throttle threshold cannot exceed max monthly usage".to_string(),
                    ));
                }
            }

            if self.cellular.enable_wifi_offload && self.cellular.offload_threshold_percentage > 100
            {
                return Err(RollupError::ConfigError(
                    "WiFi offload threshold cannot exceed 100%".to_string(),
                ));
            }

            if self.cellular.enable_usage_alerts && self.cellular.alert_threshold_percentage > 100 {
                return Err(RollupError::ConfigError(
                    "Usage alert threshold cannot exceed 100%".to_string(),
                ));
            }

            if self.cellular.batch_operations_enabled && self.cellular.batch_window_secs == 0 {
                return Err(RollupError::ConfigError(
                    "Batch window must be > 0 when batch operations are enabled".to_string(),
                ));
            }
        }

        Ok(())
    }

    pub fn from_file(path: &str) -> RollupResult<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| RollupError::ConfigError(format!("Failed to read config file: {}", e)))?;

        let config: Self = toml::from_str(&content)
            .map_err(|e| RollupError::ConfigError(format!("Failed to parse config: {}", e)))?;

        config.validate()?;
        Ok(config)
    }

    pub fn to_file(&self, path: &str) -> RollupResult<()> {
        self.validate()?;

        let content = toml::to_string_pretty(self)
            .map_err(|e| RollupError::ConfigError(format!("Failed to serialize config: {}", e)))?;

        std::fs::write(path, content)
            .map_err(|e| RollupError::ConfigError(format!("Failed to write config file: {}", e)))?;

        Ok(())
    }

    pub fn is_5g_optimized(&self) -> bool {
        self.five_g.enabled && self.five_g.slice_id.is_some()
    }

    pub fn is_cellular_safe(&self) -> bool {
        self.five_g.enabled && self.five_g.cellular_safe_mode
    }

    pub fn is_cellular_enabled(&self) -> bool {
        self.cellular.enabled
    }

    pub fn target_latency(&self) -> Duration {
        if self.five_g.enabled {
            Duration::from_millis(self.five_g.latency_target_ms as u64)
        } else {
            Duration::from_millis(250)
        }
    }

    pub fn da_redundancy_factor(&self) -> f64 {
        self.da.n as f64 / self.da.k as f64
    }

    pub fn expected_chunk_serve_time(&self) -> Duration {
        Duration::from_millis(self.da.chunk_serve_timeout_ms)
    }

    pub fn is_wifi_only_operation(&self, operation: &str) -> bool {
        self.cellular.heavy_operations_wifi_only
            && self
                .five_g
                .wifi_only_operations
                .contains(&operation.to_string())
    }

    pub fn get_batch_timeout(&self) -> Duration {
        Duration::from_secs(self.operator.batch_timeout_secs)
    }

    pub fn get_commit_frequency(&self) -> Duration {
        Duration::from_secs(self.operator.commit_frequency_secs)
    }

    pub fn should_enable_pq(&self) -> bool {
        self.security.enable_pq_signatures
    }

    pub fn requires_dilithium(&self) -> bool {
        self.security.require_dilithium
    }

    pub fn is_transition_mode(&self) -> bool {
        self.security.transition_mode
    }

    pub fn is_pq_only_mode(&self) -> bool {
        self.security.pq_only_mode
    }

    pub fn max_batch_size(&self) -> u32 {
        self.operator.max_batch_size
    }

    pub fn max_gas_limit(&self) -> u64 {
        self.operator.max_gas_limit
    }

    pub fn get_challenge_period_blocks(&self) -> u64 {
        self.fraud_proofs.challenge_period_blocks
    }

    pub fn get_response_window_blocks(&self) -> u64 {
        self.fraud_proofs.response_window_blocks
    }

    pub fn get_fraud_proof_window_blocks(&self) -> u64 {
        self.fraud_proofs.fraud_proof_window_blocks
    }

    pub fn get_challenge_bond(&self) -> Balance {
        self.fraud_proofs.challenge_bond
    }

    pub fn get_operator_address(&self) -> Address {
        self.operator.address
    }

    pub fn get_operator_bond(&self) -> Balance {
        self.operator.bond_amount
    }

    pub fn get_shard_ids(&self) -> Vec<ShardId> {
        self.sharding.shard_ids.clone()
    }

    pub fn is_sharding_enabled(&self) -> bool {
        self.sharding.enabled
    }

    pub fn num_shards(&self) -> u32 {
        self.sharding.num_shards
    }

    pub fn is_cross_shard_enabled(&self) -> bool {
        self.sharding.cross_shard_enabled
    }

    pub fn estimate_monthly_cellular_usage_mb(&self) -> u64 {
        let batches_per_day = (86400 / self.operator.commit_frequency_secs) as u64;
        let avg_batch_size_kb = if self.operator.enable_batch_compression {
            128
        } else {
            256
        };
        let monthly_batches = batches_per_day * 30;
        (monthly_batches * avg_batch_size_kb) / 1024
    }

    pub fn is_within_cellular_budget(&self, current_usage_gb: u64) -> bool {
        if !self.cellular.safe_mode_default {
            return true;
        }
        current_usage_gb < self.cellular.max_monthly_usage_gb
    }

    pub fn should_throttle_cellular(&self, current_usage_gb: u64) -> bool {
        if !self.cellular.safe_mode_default {
            return false;
        }
        current_usage_gb >= self.cellular.throttle_threshold_gb
    }

    pub fn should_alert_cellular_usage(&self, current_usage_gb: u64) -> bool {
        if !self.cellular.enable_usage_alerts {
            return false;
        }
        let threshold = (self.cellular.max_monthly_usage_gb
            * self.cellular.alert_threshold_percentage as u64)
            / 100;
        current_usage_gb >= threshold
    }

    pub fn optimize_for_5g(&mut self) {
        if self.five_g.enabled {
            self.operator.max_batch_size = self.operator.max_batch_size.min(500);
            self.operator.batch_timeout_secs = self.operator.batch_timeout_secs.min(10);
            self.operator.commit_frequency_secs = self.operator.commit_frequency_secs.min(60);
            self.da.chunk_size = self.da.chunk_size.min(32768);
            self.network.max_bandwidth_mbps = self.five_g.bandwidth_mbps;
            self.operator.enable_batch_compression = true;
            self.operator.compression_level = 6;
        }
    }

    pub fn optimize_for_cellular(&mut self) {
        if self.cellular.safe_mode_default {
            self.operator.max_batch_size = self.operator.max_batch_size.min(250);
            self.da.enable_compression = true;
            self.da.compression_level = 9;
            self.operator.commit_frequency_secs = self.operator.commit_frequency_secs.max(300);
            self.operator.enable_batch_compression = true;
            self.operator.compression_level = 9;
            self.cellular.compression_mandatory = true;
            self.cellular.batch_operations_enabled = true;
        }
    }

    pub fn optimize_for_latency(&mut self) {
        if self.five_g.enabled && self.five_g.urllc_enabled {
            self.operator.batch_timeout_secs = 5;
            self.operator.commit_frequency_secs = 30;
            self.network.gossip.heartbeat_interval = Duration::from_millis(500);
            self.da.chunk_serve_timeout_ms = 100;
        }
    }

    pub fn get_supported_algorithms(&self) -> Vec<u16> {
        self.security.supported_algorithms.clone()
    }

    pub fn get_required_algorithms(&self) -> Vec<u16> {
        self.security.required_algorithms.clone()
    }

    pub fn is_algorithm_supported(&self, algorithm_id: u16) -> bool {
        self.security.supported_algorithms.contains(&algorithm_id)
    }

    pub fn is_algorithm_required(&self, algorithm_id: u16) -> bool {
        self.security.required_algorithms.contains(&algorithm_id)
    }

    pub fn get_gossip_topics(&self) -> Vec<String> {
        let mut topics = self.network.gossip.topics.clone();

        if self.sharding.enabled {
            for shard_id in &self.sharding.shard_ids {
                topics.push(format!("ego/shard/{}/tx", shard_id.as_u32()));
                topics.push(format!("ego/shard/{}/headers", shard_id.as_u32()));
                topics.push(format!("ego/shard/{}/receipts", shard_id.as_u32()));
                topics.push(format!("ego/shard/{}/proofs", shard_id.as_u32()));
            }
        }

        if self.proofs.poc_enabled {
            topics.push("ego/poc/beacons".to_string());
            topics.push("ego/poc/witnesses".to_string());
        }

        if self.da.enable_ipfs {
            topics.push("ego/storage/placement".to_string());
            topics.push("ego/storage/repair".to_string());
        }

        topics
    }

    pub fn get_drs_weights(&self) -> HashMap<String, f64> {
        let mut weights = HashMap::new();
        weights.insert("uptime".to_string(), self.drs.uptime_weight);
        weights.insert("post_latency".to_string(), self.drs.post_latency_weight);
        weights.insert("post_pass_rate".to_string(), self.drs.post_pass_rate_weight);
        weights.insert("poc_quality".to_string(), self.drs.poc_quality_weight);
        weights.insert("serve_ratio".to_string(), self.drs.serve_ratio_weight);
        weights.insert(
            "density_penalty".to_string(),
            self.drs.density_penalty_weight,
        );
        weights
    }

    pub fn get_emission_bucket_percentages(&self) -> HashMap<String, u16> {
        let mut buckets = HashMap::new();
        buckets.insert(
            "storage".to_string(),
            self.economics.storage_bucket_percentage,
        );
        buckets.insert(
            "consensus".to_string(),
            self.economics.consensus_bucket_percentage,
        );
        buckets.insert(
            "coverage".to_string(),
            self.economics.coverage_bucket_percentage,
        );
        buckets.insert("dao".to_string(), self.economics.dao_bucket_percentage);
        buckets
    }

    pub fn is_post_enabled(&self) -> bool {
        self.proofs.post_enabled
    }

    pub fn is_porep_enabled(&self) -> bool {
        self.proofs.porep_enabled
    }

    pub fn is_poc_enabled(&self) -> bool {
        self.proofs.poc_enabled
    }

    pub fn is_drs_enabled(&self) -> bool {
        self.drs.enabled
    }

    pub fn get_post_sla_duration(&self) -> Duration {
        Duration::from_millis(self.proofs.post_sla_ms as u64)
    }

    pub fn should_enable_gpu_proving(&self) -> bool {
        self.proofs.enable_gpu_proving
    }

    pub fn get_worker_threads(&self) -> usize {
        self.performance.worker_threads
    }

    pub fn get_proof_verification_threads(&self) -> usize {
        self.performance.proof_verification_threads
    }

    pub fn is_metrics_enabled(&self) -> bool {
        self.performance.enable_metrics
    }

    pub fn get_metrics_endpoint(&self) -> String {
        format!(
            "{}:{}",
            self.performance.metrics_address, self.performance.metrics_port
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_validation() {
        let config = RollupConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_da_params_validation() {
        let mut config = RollupConfig::default();
        config.da.k = 100;
        config.da.m = 50;
        config.da.n = 140;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_5g_optimization_detection() {
        let mut config = RollupConfig::default();
        assert!(!config.is_5g_optimized());

        config.five_g.enabled = true;
        config.five_g.slice_id = Some("slice-1".to_string());
        assert!(config.is_5g_optimized());
    }

    #[test]
    fn test_da_redundancy_calculation() {
        let config = RollupConfig::default();
        let redundancy = config.da_redundancy_factor();
        assert_eq!(redundancy, 192.0 / 128.0);
    }

    #[test]
    fn test_target_latency() {
        let mut config = RollupConfig::default();
        assert_eq!(config.target_latency(), Duration::from_millis(250));

        config.five_g.enabled = true;
        config.five_g.latency_target_ms = 10;
        assert_eq!(config.target_latency(), Duration::from_millis(10));
    }

    #[test]
    fn test_cellular_safe_mode() {
        let mut config = RollupConfig::default();
        config.five_g.enabled = true;
        config.five_g.cellular_safe_mode = true;
        assert!(config.is_cellular_safe());

        assert!(config.is_wifi_only_operation("large_storage"));
        assert!(!config.is_wifi_only_operation("small_transfer"));
    }

    #[test]
    fn test_5g_optimization() {
        let mut config = RollupConfig::default();
        config.operator.max_batch_size = 10000;
        config.five_g.enabled = true;
        config.five_g.bandwidth_mbps = 200;

        config.optimize_for_5g();

        assert!(config.operator.max_batch_size <= 500);
        assert!(config.operator.batch_timeout_secs <= 10);
        assert_eq!(config.network.max_bandwidth_mbps, 200);
    }

    #[test]
    fn test_cellular_optimization() {
        let mut config = RollupConfig::default();
        config.cellular.safe_mode_default = true;

        config.optimize_for_cellular();

        assert!(config.operator.max_batch_size <= 250);
        assert!(config.da.enable_compression);
        assert_eq!(config.da.compression_level, 9);
    }

    #[test]
    fn test_fraud_proof_config_validation() {
        let mut config = RollupConfig::default();
        config.fraud_proofs.challenge_period_blocks = 50;
        assert!(config.validate().is_err());

        config.fraud_proofs.challenge_period_blocks = 1000;
        config.fraud_proofs.fraud_proof_window_blocks = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_chain_id_validation() {
        let mut config = RollupConfig::default();
        config.chain_id = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_cellular_budget_check() {
        let mut config = RollupConfig::default();
        config.cellular.safe_mode_default = true;
        config.cellular.max_monthly_usage_gb = 5;

        assert!(config.is_within_cellular_budget(3));
        assert!(!config.is_within_cellular_budget(6));
    }

    #[test]
    fn test_monthly_usage_estimate() {
        let config = RollupConfig::default();
        let usage = config.estimate_monthly_cellular_usage_mb();
        assert!(usage > 0);
    }

    #[test]
    fn test_sharding_validation() {
        let mut config = RollupConfig::default();
        config.sharding.enabled = true;
        config.sharding.num_shards = 2;
        config.sharding.shard_ids = vec![ShardId::new(0).unwrap()];
        assert!(config.validate().is_err());

        config.sharding.shard_ids = vec![ShardId::new(0).unwrap(), ShardId::new(1).unwrap()];
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_drs_weights_validation() {
        let mut config = RollupConfig::default();
        config.drs.enabled = true;
        config.drs.uptime_weight = 0.5;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_economics_bucket_validation() {
        let mut config = RollupConfig::default();
        config.economics.storage_bucket_percentage = 5000;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_pq_mode_validation() {
        let mut config = RollupConfig::default();
        config.security.pq_only_mode = true;
        config.security.require_dilithium = false;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_gossip_topics_generation() {
        let mut config = RollupConfig::default();
        config.sharding.enabled = true;
        config.sharding.num_shards = 2;
        config.sharding.shard_ids = vec![ShardId::new(0), ShardId::new(1)];

        let topics = config.get_gossip_topics();
        assert!(topics.contains(&"ego/shard/0/tx".to_string()));
        assert!(topics.contains(&"ego/shard/1/headers".to_string()));
    }

    #[test]
    fn test_cellular_throttle() {
        let mut config = RollupConfig::default();
        config.cellular.safe_mode_default = true;
        config.cellular.max_monthly_usage_gb = 5;
        config.cellular.throttle_threshold_gb = 4;

        assert!(!config.should_throttle_cellular(3));
        assert!(config.should_throttle_cellular(4));
    }

    #[test]
    fn test_usage_alert() {
        let mut config = RollupConfig::default();
        config.cellular.enable_usage_alerts = true;
        config.cellular.max_monthly_usage_gb = 5;
        config.cellular.alert_threshold_percentage = 90;

        assert!(!config.should_alert_cellular_usage(4));
        assert!(config.should_alert_cellular_usage(5));
    }
}
