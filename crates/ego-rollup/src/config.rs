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
    pub deploy_policy: DeployPolicyConfig,
    pub ai_content_filter: AIContentFilterConfig,
    pub device: DeviceConfig,
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
    pub se_enabled: bool,
    pub threshold_signature_members: u32,
    pub ota_update_enabled: bool,
    pub firmware_allowlist_path: Option<PathBuf>,
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
    pub compression_algorithm: CompressionAlgorithm,
    pub storage_duration_epochs: u64,
    pub replication_factor: u8,
    pub enable_erasure_coding: bool,
    pub max_blob_size: usize,
    pub anchor_window_hours: u64,
    pub response_window_blocks: u64,
    pub chunk_serve_timeout_ms: u64,
    pub enable_car_snapshots: bool,
    pub max_evidence_bundle_size: usize,
    pub daily_anchor_enabled: bool,
    pub sampling_failure_threshold: f64,
    pub chunk_availability_timeout_blocks: u64,
    pub da_sampling_client_enabled: bool,
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
    pub da_unavailability_proof_enabled: bool,
    pub invalid_inclusion_proof_enabled: bool,
    pub invalid_state_transition_proof_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub listen_address: String,
    pub listen_port: u16,
    pub bootstrap_peers: Vec<String>,
    pub max_peers: u32,
    #[serde(
        serialize_with = "serde_helpers::serialize_duration",
        deserialize_with = "serde_helpers::deserialize_duration"
    )]
    pub connection_timeout: Duration,
    pub enable_mdns: bool,
    pub gossip: GossipConfig,
    pub enable_nat_traversal: bool,
    pub enable_dcutr: bool,
    pub max_bandwidth_mbps: u32,
    pub enable_quic: bool,
    pub enable_tcp: bool,
    pub enable_upnp: bool,
    pub relay_enabled: bool,
    pub relay_max_circuits: u32,
    pub peer_scoring_enabled: bool,
    pub peer_ban_threshold: i32,
    pub peer_ban_duration_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipConfig {
    #[serde(
        serialize_with = "serde_helpers::serialize_duration",
        deserialize_with = "serde_helpers::deserialize_duration"
    )]
    pub heartbeat_interval: Duration,
    pub max_message_size: usize,
    #[serde(
        serialize_with = "serde_helpers::serialize_duration",
        deserialize_with = "serde_helpers::deserialize_duration"
    )]
    pub duplicate_cache_time: Duration,
    pub validation_mode: ValidationMode,
    pub mesh_n: usize,
    pub mesh_n_low: usize,
    pub mesh_n_high: usize,
    pub gossip_lazy: usize,
    pub gossip_factor: f64,
    pub opportunistic_graft_ticks: u64,
    #[serde(
        serialize_with = "serde_helpers::serialize_duration",
        deserialize_with = "serde_helpers::deserialize_duration"
    )]
    pub prune_backoff: Duration,
    pub topics: Vec<String>,
    pub per_topic_backpressure_enabled: bool,
    pub per_topic_rate_limit: HashMap<String, u32>,
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
    pub backpressure_threshold: f64,
    pub max_memory_usage_mb: usize,
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
    pub integrated_gnb_enabled: bool,
    pub five_g_core_components: FiveGCoreComponents,
    pub spectrum_config: SpectrumConfig,
    pub micro_slots_enabled: bool,
    pub micro_slot_duration_ms: u32,
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
pub struct FiveGCoreComponents {
    pub amf_enabled: bool,
    pub smf_enabled: bool,
    pub upf_enabled: bool,
    pub ausf_enabled: bool,
    pub udm_enabled: bool,
    pub pcf_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpectrumConfig {
    pub band: String,
    pub frequency_mhz: u32,
    pub bandwidth_mhz: u32,
    pub cbrs_enabled: bool,
    pub sas_enabled: bool,
    pub compliance_checks_enabled: bool,
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
    pub hw_root_of_trust_enabled: bool,
    pub key_rotation_enabled: bool,
    pub key_rotation_interval_epochs: u64,
    pub session_key_derivation: SessionKeyDerivation,
    pub identity_binding_required: bool,
    pub downgrade_attack_protection: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionKeyDerivation {
    HybridXChaCha20Poly1305,
    KyberOnlyXChaCha20Poly1305,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub data_dir: PathBuf,
    pub enable_pruning: bool,
    pub keep_epochs: u64,
    pub prune_interval_epochs: u64,
    pub snapshot_interval_epochs: u64,
    pub max_storage_gb: u64,
    pub enable_compression: bool,
    pub compression_algorithm: CompressionAlgorithm,
    pub db_backend: DatabaseBackend,
    pub rocksdb_config: RocksDBConfig,
    pub enable_state_snapshots: bool,
    pub enable_archival_mode: bool,
    pub archival_replication_factor: u8,
    pub keep_headers_forever: bool,
    pub keep_qcs_forever: bool,
    pub prune_old_bodies: bool,
    pub prune_old_receipts: bool,
    pub prune_old_events: bool,
    pub prune_expired_storage: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompressionAlgorithm {
    #[serde(rename = "zstd")]
    Zstd,
    #[serde(rename = "lz4")]
    Lz4,
    #[serde(rename = "snappy")]
    Snappy,
    #[serde(rename = "none")]
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseBackend {
    #[serde(rename = "rocksdb")]
    RocksDB,
    #[serde(rename = "surrealdb")]
    SurrealDB,
    #[serde(rename = "custom")]
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
    pub block_cache_size: usize,
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
    pub shard_mapping_strategy: ShardMappingStrategy,
    pub max_cross_shard_receipts_per_epoch: usize,
    pub receipt_deadline_epochs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShardMappingStrategy {
    PrefixBased,
    HashBased,
    RangeBased,
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
    pub porep_merkle_tree_arity: u8,
    pub poc_beacon_frequency_hz: f64,
    pub poc_witness_min_count: u32,
    pub poc_h3_resolution: u8,
    pub poc_quality_min: f64,
    pub poc_distance_max_km: f64,
    pub poc_path_loss_exponent_range: (f64, f64),
    pub poc_rsrp_rmse_threshold_db: f64,
    pub poc_density_cap_per_cell: u32,
    pub enable_gpu_proving: bool,
    pub gpu_device_id: Option<u32>,
    pub enable_batch_verification: bool,
    pub proof_aggregation_enabled: bool,
    pub proof_compression_enabled: bool,
    pub enable_co_beacon: bool,
    pub fake_poc_mode: bool,
    pub windows_per_day: u32,
    pub challenges_per_sector: u32,
    pub sectors_per_partition: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DRSConfig {
    pub enabled: bool,
    pub calculation_epoch_interval: u64,
    pub w_uptime: f64,
    pub w_post_pass: f64,
    pub w_inv_latency: f64,
    pub w_poc: f64,
    pub w_serve: f64,
    pub a1_failed_post: f64,
    pub a2_replay_incoherence: f64,
    pub a3_equivocation: f64,
    pub p_max: f64,
    pub sla_ms: u64,
    pub smoothing_alpha: f64,
    pub multiplier_slope_beta: f64,
    pub m_min: f64,
    pub m_max: f64,
    pub density_penalty_rate: f64,
    pub density_min_multiplier: f64,
    pub high_band_threshold: f64,
    pub mid_band_threshold: f64,
    pub weights_version: u32,
    pub enable_puc: bool,
    pub puc_coefficient_range: (f64, f64),
    pub puc_metrics: PUCMetrics,
    pub density_penalty_h3_resolution: u8,
    pub density_dwell_threshold_percentage: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PUCMetrics {
    pub uptime_percent_weight: f64,
    pub peer_degree_weight: f64,
    pub relay_bytes_weight: f64,
    pub iot_sessions_weight: f64,
    pub shard_demand_score_weight: f64,
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
    pub ru_metering_enabled: bool,
    pub pob_floor_min: u64,
    pub storage_credit_to_byte_months: u64,
    pub min_validator_stake: u128,
    pub min_storage_collateral: u128,
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
    pub baseline_usage_gb_per_month: u64,
    pub enable_internet_sharing: bool,
    pub sharing_rate_limit_mbps: u32,
    pub sharing_pricing_per_gb: Balance,
    pub proof_rate_hz: f64,
    pub proof_batch_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployPolicyConfig {
    pub enabled: bool,
    pub free_deploys_per_epoch: u32,
    pub min_stake_for_quota: Balance,
    pub credits_per_kb: u64,
    pub credits_per_ru: u64,
    pub max_deploy_size_kb: u32,
    pub max_ru_per_deploy: u64,
    pub deploy_bond_amount: Balance,
    pub bond_lock_duration_blocks: u64,
    pub bond_slash_threshold: u32,
    pub max_deploys_per_epoch: u32,
    pub max_deploys_per_user_per_epoch: u32,
    pub max_total_size_per_epoch_gb: u32,
    pub enable_dedup: bool,
    pub dedup_lookback_epochs: u64,
    pub pob_floor_enabled: bool,
    pub pob_floor_per_kb: u64,
    pub pob_floor_per_ru: u64,
    pub anti_spam_enabled: bool,
    pub max_deploys_per_hour: u32,
    pub max_deploys_per_day: u32,
    pub min_deploy_interval_seconds: u64,
    pub human_verification_required: bool,
    pub ai_pattern_detection_enabled: bool,
    pub emergency_mode: bool,
    pub whitelist_only_mode: bool,
    pub code_hash_cache_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIContentFilterConfig {
    pub enabled: bool,
    pub filter_patterns: Vec<String>,
    pub require_human_verification: bool,
    pub dilithium_signature_required: bool,
    pub human_verified_tag_required: bool,
    pub rejection_on_detection: bool,
    pub zk_verification_enabled: bool,
    pub zk_proof_required_for_sensitive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConfig {
    pub ego_device_only: bool,
    pub ue_embedded_antennas: bool,
    pub hardware_requirements: HardwareRequirements,
    pub os_stack: OSStackConfig,
    pub provisioning: ProvisioningConfig,
    pub certification: CertificationConfig,
    pub lifecycle: LifecycleConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareRequirements {
    pub min_ram_gb: u32,
    pub min_storage_gb: u32,
    pub architecture: String,
    pub modem_required: bool,
    pub gps_required: bool,
    pub tpm_se_required: bool,
    pub external_antennas_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OSStackConfig {
    pub preferred_os: String,
    pub erlang_otp_enabled: bool,
    pub go_libp2p_sidecar: bool,
    pub rust_ports_enabled: bool,
    pub rocksdb_backend: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningConfig {
    pub manufacturing_ca_required: bool,
    pub device_cert_enrollment: bool,
    pub attestation_nonce_verification: bool,
    pub role_tokens_by_sku: bool,
    pub periodic_re_attestation_enabled: bool,
    pub re_attestation_interval_blocks: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificationConfig {
    pub ptcrb_required: bool,
    pub operator_iot_required: bool,
    pub sar_emc_compliance: bool,
    pub fcc_certified: bool,
    pub ce_certified: bool,
    pub device_cert_sn_label: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleConfig {
    pub auto_update_enabled: bool,
    pub ota_update_policy: OTAUpdatePolicy,
    pub firmware_signing_threshold: u32,
    pub health_reporting_enabled: bool,
    pub decommission_key_wipe: bool,
    pub revocation_check_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OTAUpdatePolicy {
    Automatic,
    Manual,
    Scheduled,
}

mod serde_helpers {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize_duration<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(duration.as_secs())
    }

    pub fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
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
            deploy_policy: DeployPolicyConfig::default(),
            ai_content_filter: AIContentFilterConfig::default(),
            device: DeviceConfig::default(),
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
            se_enabled: false,
            threshold_signature_members: 3,
            ota_update_enabled: true,
            firmware_allowlist_path: None,
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
            compression_algorithm: CompressionAlgorithm::Zstd,
            storage_duration_epochs: 7200,
            replication_factor: 3,
            enable_erasure_coding: true,
            max_blob_size: 10 * 1024 * 1024,
            anchor_window_hours: 24,
            response_window_blocks: 100,
            chunk_serve_timeout_ms: 300,
            enable_car_snapshots: true,
            max_evidence_bundle_size: 50 * 1024 * 1024,
            daily_anchor_enabled: true,
            sampling_failure_threshold: 0.6,
            chunk_availability_timeout_blocks: 1000,
            da_sampling_client_enabled: true,
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
            da_unavailability_proof_enabled: true,
            invalid_inclusion_proof_enabled: true,
            invalid_state_transition_proof_enabled: true,
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
            enable_dcutr: true,
            max_bandwidth_mbps: 1000,
            enable_quic: true,
            enable_tcp: true,
            enable_upnp: true,
            relay_enabled: true,
            relay_max_circuits: 32,
            peer_scoring_enabled: true,
            peer_ban_threshold: -100,
            peer_ban_duration_secs: 3600,
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
            per_topic_backpressure_enabled: true,
            per_topic_rate_limit: HashMap::new(),
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
            backpressure_threshold: 0.8,
            max_memory_usage_mb: 4096,
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
            integrated_gnb_enabled: false,
            five_g_core_components: FiveGCoreComponents::default(),
            spectrum_config: SpectrumConfig::default(),
            micro_slots_enabled: false,
            micro_slot_duration_ms: 100,
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

impl Default for FiveGCoreComponents {
    fn default() -> Self {
        Self {
            amf_enabled: false,
            smf_enabled: false,
            upf_enabled: false,
            ausf_enabled: false,
            udm_enabled: false,
            pcf_enabled: false,
        }
    }
}

impl Default for SpectrumConfig {
    fn default() -> Self {
        Self {
            band: "n48".to_string(),
            frequency_mhz: 3550,
            bandwidth_mhz: 20,
            cbrs_enabled: false,
            sas_enabled: false,
            compliance_checks_enabled: true,
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
            hw_root_of_trust_enabled: true,
            key_rotation_enabled: true,
            key_rotation_interval_epochs: 10000,
            session_key_derivation: SessionKeyDerivation::HybridXChaCha20Poly1305,
            identity_binding_required: true,
            downgrade_attack_protection: true,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./rollup-data"),
            enable_pruning: true,
            keep_epochs: 100,
            prune_interval_epochs: 10,
            snapshot_interval_epochs: 1000,
            max_storage_gb: 100,
            enable_compression: true,
            compression_algorithm: CompressionAlgorithm::Zstd,
            db_backend: DatabaseBackend::RocksDB,
            rocksdb_config: RocksDBConfig::default(),
            enable_state_snapshots: true,
            enable_archival_mode: false,
            archival_replication_factor: 3,
            keep_headers_forever: true,
            keep_qcs_forever: true,
            prune_old_bodies: true,
            prune_old_receipts: true,
            prune_old_events: true,
            prune_expired_storage: true,
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
            block_cache_size: 256 * 1024 * 1024,
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
            shard_mapping_strategy: ShardMappingStrategy::PrefixBased,
            max_cross_shard_receipts_per_epoch: 100_000,
            receipt_deadline_epochs: 100,
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
            porep_merkle_tree_arity: 8,
            poc_beacon_frequency_hz: 1.0,
            poc_witness_min_count: 3,
            poc_h3_resolution: 8,
            poc_quality_min: 0.5,
            poc_distance_max_km: 8.0,
            poc_path_loss_exponent_range: (2.0, 3.5),
            poc_rsrp_rmse_threshold_db: 8.0,
            poc_density_cap_per_cell: 3,
            enable_gpu_proving: false,
            gpu_device_id: None,
            enable_batch_verification: true,
            proof_aggregation_enabled: true,
            proof_compression_enabled: true,
            enable_co_beacon: true,
            fake_poc_mode: true,
            windows_per_day: 48,
            challenges_per_sector: 24,
            sectors_per_partition: 2349,
        }
    }
}

impl Default for DRSConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            calculation_epoch_interval: 1,
            w_uptime: 0.20,
            w_post_pass: 0.40,
            w_inv_latency: 0.10,
            w_poc: 0.20,
            w_serve: 0.10,
            a1_failed_post: 0.10,
            a2_replay_incoherence: 0.20,
            a3_equivocation: 0.40,
            p_max: 0.5,
            sla_ms: 600_000,
            smoothing_alpha: 0.3,
            multiplier_slope_beta: 0.6,
            m_min: 0.7,
            m_max: 1.3,
            density_penalty_rate: 0.10,
            density_min_multiplier: 0.40,
            high_band_threshold: 0.8,
            mid_band_threshold: 0.5,
            weights_version: 1,
            enable_puc: false,
            puc_coefficient_range: (0.8, 1.2),
            puc_metrics: PUCMetrics::default(),
            density_penalty_h3_resolution: 12,
            density_dwell_threshold_percentage: 10,
        }
    }
}

impl Default for PUCMetrics {
    fn default() -> Self {
        Self {
            uptime_percent_weight: 0.2,
            peer_degree_weight: 0.2,
            relay_bytes_weight: 0.2,
            iot_sessions_weight: 0.2,
            shard_demand_score_weight: 0.2,
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
            ru_metering_enabled: true,
            pob_floor_min: 1000,
            storage_credit_to_byte_months: 1000,
            min_validator_stake: 100_000_000_000,
            min_storage_collateral: 10_000_000_000,
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
            baseline_usage_gb_per_month: 1,
            enable_internet_sharing: false,
            sharing_rate_limit_mbps: 50,
            sharing_pricing_per_gb: Balance::new(500_000_000_000_000),
            proof_rate_hz: 0.5,
            proof_batch_size: 100,
        }
    }
}

impl Default for DeployPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
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
            human_verification_required: false,
            ai_pattern_detection_enabled: true,
            emergency_mode: false,
            whitelist_only_mode: false,
            code_hash_cache_size: 1000,
        }
    }
}

impl Default for AIContentFilterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            filter_patterns: vec![
                "do you want me to".to_string(),
                "let me know if you need".to_string(),
                "as an ai model".to_string(),
                "i'm an ai".to_string(),
                "anything else".to_string(),
            ],
            require_human_verification: true,
            dilithium_signature_required: true,
            human_verified_tag_required: true,
            rejection_on_detection: true,
            zk_verification_enabled: false,
            zk_proof_required_for_sensitive: false,
        }
    }
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            ego_device_only: false,
            ue_embedded_antennas: true,
            hardware_requirements: HardwareRequirements::default(),
            os_stack: OSStackConfig::default(),
            provisioning: ProvisioningConfig::default(),
            certification: CertificationConfig::default(),
            lifecycle: LifecycleConfig::default(),
        }
    }
}

impl Default for HardwareRequirements {
    fn default() -> Self {
        Self {
            min_ram_gb: 4,
            min_storage_gb: 64,
            architecture: "aarch64".to_string(),
            modem_required: false,
            gps_required: false,
            tpm_se_required: false,
            external_antennas_count: 0,
        }
    }
}

impl Default for OSStackConfig {
    fn default() -> Self {
        Self {
            preferred_os: "Ubuntu".to_string(),
            erlang_otp_enabled: true,
            go_libp2p_sidecar: true,
            rust_ports_enabled: true,
            rocksdb_backend: true,
        }
    }
}

impl Default for ProvisioningConfig {
    fn default() -> Self {
        Self {
            manufacturing_ca_required: false,
            device_cert_enrollment: false,
            attestation_nonce_verification: true,
            role_tokens_by_sku: false,
            periodic_re_attestation_enabled: true,
            re_attestation_interval_blocks: 1000,
        }
    }
}

impl Default for CertificationConfig {
    fn default() -> Self {
        Self {
            ptcrb_required: false,
            operator_iot_required: false,
            sar_emc_compliance: false,
            fcc_certified: false,
            ce_certified: false,
            device_cert_sn_label: false,
        }
    }
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            auto_update_enabled: true,
            ota_update_policy: OTAUpdatePolicy::Automatic,
            firmware_signing_threshold: 2,
            health_reporting_enabled: true,
            decommission_key_wipe: true,
            revocation_check_enabled: true,
        }
    }
}

impl RollupConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.chain_id == 0 {
            return Err("Chain ID must be > 0".to_string());
        }

        if self.network_id == 0 {
            return Err("Network ID must be > 0".to_string());
        }

        if self.rollup_id.is_empty() {
            return Err("Rollup ID cannot be empty".to_string());
        }

        if self.protocol_version == 0 {
            return Err("Protocol version must be > 0".to_string());
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
        self.validate_deploy_policy()?;
        self.validate_device()?;

        Ok(())
    }

    fn validate_da(&self) -> Result<(), String> {
        if (self.da.k + self.da.m) != self.da.n {
            return Err("DA parameters: k + m must equal n".to_string());
        }

        if self.da.k == 0 || self.da.m == 0 {
            return Err("DA parameters: k and m must be > 0".to_string());
        }

        if self.da.sample_size > self.da.k as usize {
            return Err("DA sample size cannot exceed k".to_string());
        }

        if self.da.chunk_size == 0 {
            return Err("DA chunk size must be > 0".to_string());
        }

        if self.da.replication_factor < 1 || self.da.replication_factor > 5 {
            return Err("DA replication factor must be between 1 and 5".to_string());
        }

        if self.da.max_blob_size == 0 {
            return Err("DA max blob size must be > 0".to_string());
        }

        if self.da.anchor_window_hours == 0 {
            return Err("DA anchor window must be > 0".to_string());
        }

        if self.da.sampling_failure_threshold < 0.5 || self.da.sampling_failure_threshold > 1.0 {
            return Err("DA sampling failure threshold must be between 0.5 and 1.0".to_string());
        }

        Ok(())
    }

    fn validate_operator(&self) -> Result<(), String> {
        if self.operator.bond_amount.as_u128() < 100_000_000_000_000_000 {
            return Err("Operator bond must be at least 0.1 EGOC".to_string());
        }

        if self.operator.max_batch_size == 0 {
            return Err("Max batch size must be > 0".to_string());
        }

        if self.operator.max_gas_limit == 0 {
            return Err("Max gas limit must be > 0".to_string());
        }

        if self.operator.min_batch_size > self.operator.max_batch_size {
            return Err("Min batch size cannot exceed max batch size".to_string());
        }

        if self.operator.batch_timeout_secs == 0 {
            return Err("Batch timeout must be > 0".to_string());
        }

        if self.operator.commit_frequency_secs == 0 {
            return Err("Commit frequency must be > 0".to_string());
        }

        if self.operator.dilithium_pk.is_empty() {
            return Err("Operator Dilithium public key is required".to_string());
        }

        if self.operator.mlkem_pk.is_empty() {
            return Err("Operator ML-KEM public key is required".to_string());
        }

        if self.operator.attestation_required && self.operator.device_cert_path.is_none() {
            return Err("Device certificate path required when attestation is enabled".to_string());
        }

        if self.operator.threshold_signature_members < 2 {
            return Err("Threshold signature members must be >= 2".to_string());
        }

        Ok(())
    }

    fn validate_fraud_proofs(&self) -> Result<(), String> {
        if self.fraud_proofs.min_confidence < 0.5 || self.fraud_proofs.min_confidence > 1.0 {
            return Err("Fraud proof confidence must be between 0.5 and 1.0".to_string());
        }

        if self.fraud_proofs.challenge_period_blocks < 100 {
            return Err("Challenge period must be at least 100 blocks".to_string());
        }

        if self.fraud_proofs.response_window_blocks == 0 {
            return Err("Response window must be > 0".to_string());
        }

        if self.fraud_proofs.fraud_proof_window_blocks == 0 {
            return Err("Fraud proof window must be > 0".to_string());
        }

        if self.fraud_proofs.challenge_bond.as_u128() == 0 {
            return Err("Challenge bond must be > 0".to_string());
        }

        if self.fraud_proofs.slashing_percentage > 10000 {
            return Err("Slashing percentage cannot exceed 100%".to_string());
        }

        if self.fraud_proofs.challenger_reward_percentage > 10000 {
            return Err("Challenger reward percentage cannot exceed 100%".to_string());
        }

        Ok(())
    }

    fn validate_five_g(&self) -> Result<(), String> {
        if self.five_g.enabled {
            if self.five_g.latency_target_ms == 0 {
                return Err("5G latency target must be > 0".to_string());
            }

            if self.five_g.bandwidth_mbps == 0 {
                return Err("5G bandwidth allocation must be > 0".to_string());
            }

            if self.five_g.qos_class > 9 {
                return Err("5G QoS class must be between 0 and 9".to_string());
            }

            if self.five_g.cellular_safe_mode && self.five_g.max_cellular_data_gb_per_month == 0 {
                return Err(
                    "Max cellular data must be > 0 when cellular safe mode is enabled".to_string(),
                );
            }

            if self.five_g.micro_slots_enabled && self.five_g.micro_slot_duration_ms == 0 {
                return Err("Micro slot duration must be > 0 when enabled".to_string());
            }

            if self.five_g.spectrum_config.bandwidth_mhz == 0 {
                return Err("Spectrum bandwidth must be > 0".to_string());
            }
        }

        Ok(())
    }

    fn validate_security(&self) -> Result<(), String> {
        if self.security.max_tx_size_bytes == 0 {
            return Err("Max transaction size must be > 0".to_string());
        }

        if self.security.enable_rate_limiting && self.security.rate_limit_per_second == 0 {
            return Err("Rate limit must be > 0 when rate limiting is enabled".to_string());
        }

        if self.security.pq_transition_phase > 3 {
            return Err("PQ transition phase must be between 0 and 3".to_string());
        }

        if self.security.required_algorithms.is_empty() {
            return Err("At least one required algorithm must be specified".to_string());
        }

        if self.security.pq_only_mode && !self.security.require_dilithium {
            return Err("Dilithium must be required in PQ-only mode".to_string());
        }

        if self.security.key_rotation_enabled && self.security.key_rotation_interval_epochs == 0 {
            return Err("Key rotation interval must be > 0 when enabled".to_string());
        }

        Ok(())
    }

    fn validate_storage(&self) -> Result<(), String> {
        if self.storage.data_dir.as_os_str().is_empty() {
            return Err("Storage data directory cannot be empty".to_string());
        }

        if self.storage.enable_pruning && self.storage.keep_epochs == 0 {
            return Err("Keep epochs must be > 0 when pruning is enabled".to_string());
        }

        if self.storage.max_storage_gb == 0 {
            return Err("Max storage must be > 0".to_string());
        }

        if self.storage.archival_replication_factor < 1
            || self.storage.archival_replication_factor > 5
        {
            return Err("Archival replication factor must be between 1 and 5".to_string());
        }

        if self.storage.enable_pruning && self.storage.prune_interval_epochs == 0 {
            return Err("Prune interval must be > 0 when pruning is enabled".to_string());
        }

        Ok(())
    }

    fn validate_sharding(&self) -> Result<(), String> {
        if self.sharding.enabled {
            if self.sharding.num_shards == 0 {
                return Err("Number of shards must be > 0".to_string());
            }

            if self.sharding.shard_ids.len() != self.sharding.num_shards as usize {
                return Err("Shard IDs count must match number of shards".to_string());
            }

            if self.sharding.shard_prefix_bits > 8 {
                return Err("Shard prefix bits cannot exceed 8".to_string());
            }

            if self.sharding.cross_shard_enabled
                && self.sharding.cross_shard_receipt_timeout_blocks == 0
            {
                return Err(
                    "Cross-shard receipt timeout must be > 0 when cross-shard is enabled"
                        .to_string(),
                );
            }

            if self.sharding.enable_global_finality && self.sharding.finality_committee_size == 0 {
                return Err(
                    "Finality committee size must be > 0 when global finality is enabled"
                        .to_string(),
                );
            }

            if self.sharding.max_cross_shard_receipts_per_epoch == 0 {
                return Err("Max cross-shard receipts per epoch must be > 0".to_string());
            }

            if self.sharding.receipt_deadline_epochs == 0 {
                return Err("Receipt deadline epochs must be > 0".to_string());
            }
        }

        Ok(())
    }

    fn validate_proofs(&self) -> Result<(), String> {
        if self.proofs.post_enabled {
            if self.proofs.post_frequency_epochs == 0 {
                return Err("PoSt frequency must be > 0".to_string());
            }

            if self.proofs.post_sla_ms == 0 {
                return Err("PoSt SLA must be > 0".to_string());
            }

            if self.proofs.post_challenge_count == 0 {
                return Err("PoSt challenge count must be > 0".to_string());
            }

            if self.proofs.post_partition_size == 0 {
                return Err("PoSt partition size must be > 0".to_string());
            }

            if self.proofs.windows_per_day == 0 {
                return Err("PoSt windows per day must be > 0".to_string());
            }

            if self.proofs.challenges_per_sector == 0 {
                return Err("PoSt challenges per sector must be > 0".to_string());
            }

            if self.proofs.sectors_per_partition == 0 {
                return Err("PoSt sectors per partition must be > 0".to_string());
            }
        }

        if self.proofs.porep_enabled {
            if self.proofs.porep_sector_size_gib == 0 {
                return Err("PoRep sector size must be > 0".to_string());
            }

            if self.proofs.porep_stacked_drg_layers == 0 {
                return Err("PoRep stacked DRG layers must be > 0".to_string());
            }

            if self.proofs.porep_base_degree == 0 {
                return Err("PoRep base degree must be > 0".to_string());
            }

            if self.proofs.porep_merkle_tree_arity == 0 {
                return Err("PoRep Merkle tree arity must be > 0".to_string());
            }
        }

        if self.proofs.poc_enabled {
            if self.proofs.poc_beacon_frequency_hz <= 0.0 {
                return Err("PoC beacon frequency must be > 0".to_string());
            }

            if self.proofs.poc_witness_min_count < 3 {
                return Err("PoC minimum witness count must be >= 3".to_string());
            }

            if self.proofs.poc_quality_min < 0.0 || self.proofs.poc_quality_min > 1.0 {
                return Err("PoC quality minimum must be between 0.0 and 1.0".to_string());
            }

            if self.proofs.poc_distance_max_km <= 0.0 {
                return Err("PoC max distance must be > 0".to_string());
            }

            let (min_exp, max_exp) = self.proofs.poc_path_loss_exponent_range;
            if min_exp > max_exp || min_exp < 0.0 {
                return Err("PoC path loss exponent range is invalid".to_string());
            }
        }

        Ok(())
    }

    fn validate_drs(&self) -> Result<(), String> {
        if self.drs.enabled {
            let total_weight = self.drs.w_uptime
                + self.drs.w_post_pass
                + self.drs.w_inv_latency
                + self.drs.w_poc
                + self.drs.w_serve;

            if (total_weight - 1.0).abs() > 0.001 {
                return Err("DRS weights must sum to 1.0".to_string());
            }

            if self.drs.m_min > self.drs.m_max {
                return Err("DRS multiplier min cannot exceed max".to_string());
            }

            if self.drs.m_min <= 0.0 {
                return Err("DRS multiplier min must be > 0".to_string());
            }

            if self.drs.calculation_epoch_interval == 0 {
                return Err("DRS calculation epoch interval must be > 0".to_string());
            }

            if self.drs.enable_puc {
                let (min, max) = self.drs.puc_coefficient_range;
                if min > max {
                    return Err("PUC coefficient min cannot exceed max".to_string());
                }

                let puc_total = self.drs.puc_metrics.uptime_percent_weight
                    + self.drs.puc_metrics.peer_degree_weight
                    + self.drs.puc_metrics.relay_bytes_weight
                    + self.drs.puc_metrics.iot_sessions_weight
                    + self.drs.puc_metrics.shard_demand_score_weight;

                if (puc_total - 1.0).abs() > 0.001 {
                    return Err("PUC metrics weights must sum to 1.0".to_string());
                }
            }

            if self.drs.density_penalty_rate < 0.0 || self.drs.density_penalty_rate > 1.0 {
                return Err("Density penalty rate must be between 0.0 and 1.0".to_string());
            }

            if self.drs.density_min_multiplier < 0.0 || self.drs.density_min_multiplier > 1.0 {
                return Err(
                    "Density penalty min multiplier must be between 0.0 and 1.0".to_string()
                );
            }

            if self.drs.high_band_threshold <= self.drs.mid_band_threshold {
                return Err(
                    "DRS high band threshold must be greater than mid band threshold".to_string(),
                );
            }
        }

        Ok(())
    }

    fn validate_economics(&self) -> Result<(), String> {
        if self.economics.enable_emissions {
            if self.economics.initial_supply.as_u128() == 0 {
                return Err("Initial supply must be > 0".to_string());
            }

            if self.economics.emission_rate_per_epoch.as_u128() == 0 {
                return Err("Emission rate per epoch must be > 0".to_string());
            }

            let total_percentage = self.economics.storage_bucket_percentage
                + self.economics.consensus_bucket_percentage
                + self.economics.coverage_bucket_percentage
                + self.economics.dao_bucket_percentage;

            if total_percentage != 10000 {
                return Err("Bucket percentages must sum to 100%".to_string());
            }
        }

        if self.economics.enable_staking {
            if self.economics.min_stake_amount.as_u128() == 0 {
                return Err("Minimum stake amount must be > 0".to_string());
            }

            if self.economics.validator_commission_max > 10000 {
                return Err("Validator commission max cannot exceed 100%".to_string());
            }
        }

        if self.economics.pob_burn_enabled {
            if self.economics.storage_credits_rate == 0 {
                return Err("Storage credits rate must be > 0".to_string());
            }

            if self.economics.deploy_credits_rate == 0 {
                return Err("Deploy credits rate must be > 0".to_string());
            }

            if self.economics.storage_credit_to_byte_months == 0 {
                return Err("Storage credit to byte months rate must be > 0".to_string());
            }
        }

        if self.economics.min_validator_stake == 0 {
            return Err("Min validator stake must be > 0".to_string());
        }

        if self.economics.min_storage_collateral == 0 {
            return Err("Min storage collateral must be > 0".to_string());
        }

        Ok(())
    }

    fn validate_cellular(&self) -> Result<(), String> {
        if self.cellular.enabled {
            if self.cellular.safe_mode_default {
                if self.cellular.max_monthly_usage_gb == 0 {
                    return Err("Max monthly usage must be > 0 in cellular safe mode".to_string());
                }

                if self.cellular.throttle_threshold_gb > self.cellular.max_monthly_usage_gb {
                    return Err("Throttle threshold cannot exceed max monthly usage".to_string());
                }
            }

            if self.cellular.enable_wifi_offload && self.cellular.offload_threshold_percentage > 100
            {
                return Err("WiFi offload threshold cannot exceed 100%".to_string());
            }

            if self.cellular.enable_usage_alerts && self.cellular.alert_threshold_percentage > 100 {
                return Err("Usage alert threshold cannot exceed 100%".to_string());
            }

            if self.cellular.batch_operations_enabled && self.cellular.batch_window_secs == 0 {
                return Err(
                    "Batch window must be > 0 when batch operations are enabled".to_string()
                );
            }

            if self.cellular.enable_internet_sharing && self.cellular.sharing_rate_limit_mbps == 0 {
                return Err(
                    "Sharing rate limit must be > 0 when internet sharing is enabled".to_string(),
                );
            }

            if self.cellular.proof_rate_hz <= 0.0 {
                return Err("Proof rate Hz must be > 0".to_string());
            }

            if self.cellular.proof_batch_size == 0 {
                return Err("Proof batch size must be > 0".to_string());
            }
        }

        Ok(())
    }

    fn validate_deploy_policy(&self) -> Result<(), String> {
        if self.deploy_policy.enabled {
            if self.deploy_policy.credits_per_kb == 0 {
                return Err("Deploy credits per KB must be > 0".to_string());
            }

            if self.deploy_policy.credits_per_ru == 0 {
                return Err("Deploy credits per RU must be > 0".to_string());
            }

            if self.deploy_policy.max_deploy_size_kb == 0 {
                return Err("Max deploy size must be > 0".to_string());
            }

            if self.deploy_policy.max_ru_per_deploy == 0 {
                return Err("Max RU per deploy must be > 0".to_string());
            }

            if self.deploy_policy.max_deploys_per_epoch == 0 {
                return Err("Hard cap deploys per epoch must be > 0".to_string());
            }

            if self.deploy_policy.enable_dedup && self.deploy_policy.code_hash_cache_size == 0 {
                return Err(
                    "Code hash cache size must be > 0 when deduplication is enabled".to_string(),
                );
            }

            if self.deploy_policy.bond_slash_threshold == 0 {
                return Err("Bond slash threshold must be > 0".to_string());
            }

            if self.deploy_policy.anti_spam_enabled {
                if self.deploy_policy.max_deploys_per_hour == 0 {
                    return Err("Max deploys per hour must be > 0".to_string());
                }

                if self.deploy_policy.max_deploys_per_day == 0 {
                    return Err("Max deploys per day must be > 0".to_string());
                }
            }
        }

        Ok(())
    }

    fn validate_device(&self) -> Result<(), String> {
        if self.device.ego_device_only {
            if self.device.hardware_requirements.min_ram_gb == 0 {
                return Err("Minimum RAM must be > 0".to_string());
            }

            if self.device.hardware_requirements.min_storage_gb == 0 {
                return Err("Minimum storage must be > 0".to_string());
            }

            if self.device.provisioning.periodic_re_attestation_enabled
                && self.device.provisioning.re_attestation_interval_blocks == 0
            {
                return Err("Re-attestation interval must be > 0 when enabled".to_string());
            }

            if self.device.lifecycle.firmware_signing_threshold < 1 {
                return Err("Firmware signing threshold must be >= 1".to_string());
            }
        }

        Ok(())
    }

    pub fn from_file(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file: {}", e))?;

        let config: Self =
            toml::from_str(&content).map_err(|e| format!("Failed to parse config: {}", e))?;

        config.validate()?;
        Ok(config)
    }

    pub fn to_file(&self, path: &str) -> Result<(), String> {
        self.validate()?;

        let content = toml::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;

        std::fs::write(path, content).map_err(|e| format!("Failed to write config file: {}", e))?;

        Ok(())
    }

    pub fn to_shard_config(&self, shard_id: ShardId) -> ego_core::shard::ShardConfig {
        ego_core::shard::ShardConfig {
            shard_id,
            committee_size: self.sharding.finality_committee_size,
            replication_factor: self.da.replication_factor,
            max_txs_per_block: self.operator.max_batch_size,
            target_block_time_ms: (self.operator.commit_frequency_secs * 1000
                / self.sharding.num_shards.max(1) as u64),
            micro_slot_duration_ms: self.five_g.micro_slot_duration_ms as u64,
            epoch_duration_blocks: 12_000,
            cross_shard_enabled: self.sharding.cross_shard_enabled,
            storage_config: self.to_shard_storage_config(),
            preferred_slices: vec![],
            geo_constraints: None,
            pob_config: self.to_pob_config(),
            drs_config: self.to_shard_drs_config(),
            cellular_safe_config: self.to_cellular_safe_config(),
            pq_transition_config: self.to_pq_transition_config(),
        }
    }

    pub fn to_shard_storage_config(&self) -> ego_core::shard::ShardStorageConfig {
        ego_core::shard::ShardStorageConfig {
            max_storage_per_node: self.storage.max_storage_gb * 1024 * 1024 * 1024,
            proof_frequency: self.proofs.post_frequency_epochs,
            retention_period: self.storage.keep_epochs,
            erasure_coding: ego_core::shard::ErasureCodingConfig {
                data_chunks: self.da.k as u8,
                parity_chunks: self.da.m as u8,
                chunk_size: self.da.chunk_size as u32,
                codec: "ReedSolomon".to_string(),
            },
            gc_config: ego_core::shard::GarbageCollectionConfig {
                frequency: self.storage.prune_interval_epochs,
                threshold: 0.8,
                aggressive_mode: false,
                prune_old_bodies: self.storage.prune_old_bodies,
                prune_old_receipts: self.storage.prune_old_receipts,
                prune_old_events: self.storage.prune_old_events,
            },
            porep_params: ego_core::shard::PoRepParams {
                sector_size: (self.proofs.porep_sector_size_gib as u64) * 1024 * 1024 * 1024,
                layers: self.proofs.porep_stacked_drg_layers,
                base_degree: self.proofs.porep_base_degree,
                tree_arity: self.proofs.porep_merkle_tree_arity,
                params_version: self.proofs.porep_params_version,
            },
            post_params: ego_core::shard::PoStParams {
                windows_per_day: self.proofs.windows_per_day,
                challenges_per_sector: self.proofs.challenges_per_sector,
                sla_ms: self.proofs.post_sla_ms,
                sectors_per_partition: self.proofs.sectors_per_partition,
                enable_aggregation: self.proofs.proof_aggregation_enabled,
            },
        }
    }

    pub fn to_pob_config(&self) -> ego_core::shard::PoBConfig {
        ego_core::shard::PoBConfig {
            enabled: self.economics.pob_burn_enabled,
            storage_credit_price: self.economics.storage_credits_rate,
            deploy_credit_price: self.economics.deploy_credits_rate,
            burn_address: Address::new([0u8; 20]),
            floors_enabled: self.deploy_policy.pob_floor_enabled,
        }
    }

    pub fn to_shard_drs_config(&self) -> ego_core::shard::DRSConfig {
        ego_core::shard::DRSConfig {
            weight_uptime: self.drs.w_uptime,
            weight_post_pass: self.drs.w_post_pass,
            weight_inv_latency: self.drs.w_inv_latency,
            weight_poc: self.drs.w_poc,
            weight_serve: self.drs.w_serve,
            penalty_failed_post: self.drs.a1_failed_post,
            penalty_replay: self.drs.a2_replay_incoherence,
            penalty_equivocation: self.drs.a3_equivocation,
            penalty_max: self.drs.p_max,
            smoothing_alpha: self.drs.smoothing_alpha,
            multiplier_slope: self.drs.multiplier_slope_beta,
            multiplier_min: self.drs.m_min,
            multiplier_max: self.drs.m_max,
            post_sla_ms: self.drs.sla_ms,
        }
    }

    pub fn to_cellular_safe_config(&self) -> ego_core::shard::CellularSafeConfig {
        ego_core::shard::CellularSafeConfig {
            enabled: self.cellular.enabled && self.cellular.safe_mode_default,
            max_monthly_data_gb: self.cellular.max_monthly_usage_gb,
            wifi_only_operations: self.five_g.wifi_only_operations.clone(),
            throttle_threshold_gb: self.cellular.throttle_threshold_gb,
            proof_rate_hz: self.cellular.proof_rate_hz,
            proof_batch_size: self.cellular.proof_batch_size,
        }
    }

    pub fn to_pq_transition_config(&self) -> ego_core::shard::PQTransitionConfig {
        ego_core::shard::PQTransitionConfig {
            transition_epoch: 0,
            migration_period_epochs: 1000,
            pq_only_required: self.security.pq_only_mode,
            supported_algorithms: self.security.supported_algorithms.clone(),
            legacy_deadline_epoch: self.security.legacy_support_end_epoch,
        }
    }

    pub fn to_deploy_policy_manager_config(&self) -> ego_core::deploy_policy::DeployPolicyConfig {
        ego_core::deploy_policy::DeployPolicyConfig {
            free_deploys_per_epoch: self.deploy_policy.free_deploys_per_epoch,
            min_stake_for_quota: self.deploy_policy.min_stake_for_quota,
            credits_per_kb: self.deploy_policy.credits_per_kb,
            credits_per_ru: self.deploy_policy.credits_per_ru,
            max_deploy_size_kb: self.deploy_policy.max_deploy_size_kb,
            max_ru_per_deploy: self.deploy_policy.max_ru_per_deploy,
            deploy_bond_amount: self.deploy_policy.deploy_bond_amount,
            bond_lock_duration_blocks: self.deploy_policy.bond_lock_duration_blocks,
            bond_slash_threshold: self.deploy_policy.bond_slash_threshold,
            max_deploys_per_epoch: self.deploy_policy.max_deploys_per_epoch,
            max_deploys_per_user_per_epoch: self.deploy_policy.max_deploys_per_user_per_epoch,
            max_total_size_per_epoch_gb: self.deploy_policy.max_total_size_per_epoch_gb,
            enable_dedup: self.deploy_policy.enable_dedup,
            dedup_lookback_epochs: self.deploy_policy.dedup_lookback_epochs,
            pob_floor_enabled: self.deploy_policy.pob_floor_enabled,
            pob_floor_per_kb: self.deploy_policy.pob_floor_per_kb,
            pob_floor_per_ru: self.deploy_policy.pob_floor_per_ru,
            anti_spam_enabled: self.deploy_policy.anti_spam_enabled,
            max_deploys_per_hour: self.deploy_policy.max_deploys_per_hour,
            max_deploys_per_day: self.deploy_policy.max_deploys_per_day,
            min_deploy_interval_seconds: self.deploy_policy.min_deploy_interval_seconds,
            human_verification_required: self.deploy_policy.human_verification_required,
            ai_pattern_detection_enabled: self.deploy_policy.ai_pattern_detection_enabled,
            emergency_mode: self.deploy_policy.emergency_mode,
            whitelist_only_mode: self.deploy_policy.whitelist_only_mode,
        }
    }

    pub fn to_drs_config(&self) -> ego_core::drs::DRSConfig {
        ego_core::drs::DRSConfig {
            w_uptime: self.drs.w_uptime,
            w_post_pass: self.drs.w_post_pass,
            w_inv_latency: self.drs.w_inv_latency,
            w_poc: self.drs.w_poc,
            w_serve: self.drs.w_serve,
            a1_failed_post: self.drs.a1_failed_post,
            a2_replay_incoherence: self.drs.a2_replay_incoherence,
            a3_equivocation: self.drs.a3_equivocation,
            p_max: self.drs.p_max,
            sla_ms: self.drs.sla_ms,
            smoothing_alpha: self.drs.smoothing_alpha,
            multiplier_slope_beta: self.drs.multiplier_slope_beta,
            m_min: self.drs.m_min,
            m_max: self.drs.m_max,
            density_penalty_rate: self.drs.density_penalty_rate,
            density_min_multiplier: self.drs.density_min_multiplier,
            high_band_threshold: self.drs.high_band_threshold,
            mid_band_threshold: self.drs.mid_band_threshold,
        }
    }

    pub fn to_state_pruning_config(&self) -> ego_core::state::PruningConfig {
        ego_core::state::PruningConfig {
            enabled: self.storage.enable_pruning,
            keep_epochs: self.storage.keep_epochs,
            prune_interval_epochs: self.storage.prune_interval_epochs,
            keep_headers_forever: self.storage.keep_headers_forever,
            keep_state_snapshots: self.storage.enable_state_snapshots,
            snapshot_interval_epochs: self.storage.snapshot_interval_epochs,
            prune_old_bodies: self.storage.prune_old_bodies,
            prune_old_receipts: self.storage.prune_old_receipts,
            prune_old_events: self.storage.prune_old_events,
            prune_expired_storage: self.storage.prune_expired_storage,
        }
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
            for res in 0..=self.proofs.poc_h3_resolution {
                topics.push(format!("ego/poc/h3/{}", res));
            }
            topics.push("ego/poc/beacons".to_string());
            topics.push("ego/poc/witnesses".to_string());
        }

        topics.push("ego/storage/placement".to_string());
        topics.push("ego/storage/repair".to_string());

        topics
    }

    pub fn get_drs_weights(&self) -> HashMap<String, f64> {
        let mut weights = HashMap::new();
        weights.insert("uptime".to_string(), self.drs.w_uptime);
        weights.insert("post_pass".to_string(), self.drs.w_post_pass);
        weights.insert("inv_latency".to_string(), self.drs.w_inv_latency);
        weights.insert("poc".to_string(), self.drs.w_poc);
        weights.insert("serve".to_string(), self.drs.w_serve);
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

    pub fn is_ego_device_only(&self) -> bool {
        self.device.ego_device_only
    }

    pub fn requires_tpm_se(&self) -> bool {
        self.device.ego_device_only && self.device.hardware_requirements.tpm_se_required
    }

    pub fn get_density_penalty_multiplier(&self, device_count: u32) -> f64 {
        if device_count <= 1 {
            return 1.0;
        }

        let penalty = 1.0 - (self.drs.density_penalty_rate * (device_count - 1) as f64);
        penalty.max(self.drs.density_min_multiplier)
    }

    pub fn calculate_deploy_credits_needed(&self, code_size_kb: u64, ru_estimate: u64) -> u64 {
        let size_credits = code_size_kb * self.deploy_policy.credits_per_kb;
        let ru_credits = ru_estimate * self.deploy_policy.credits_per_ru;
        size_credits + ru_credits
    }

    pub fn should_filter_ai_content(&self) -> bool {
        self.ai_content_filter.enabled
    }

    pub fn detect_ai_filler(&self, content: &str) -> bool {
        if !self.ai_content_filter.enabled {
            return false;
        }

        let content_lower = content.to_lowercase();
        for pattern in &self.ai_content_filter.filter_patterns {
            if content_lower.contains(&pattern.to_lowercase()) {
                return true;
            }
        }
        false
    }

    pub fn requires_human_verification(&self) -> bool {
        self.ai_content_filter.enabled && self.ai_content_filter.require_human_verification
    }

    pub fn get_session_key_derivation(&self) -> SessionKeyDerivation {
        self.security.session_key_derivation
    }

    pub fn is_identity_binding_required(&self) -> bool {
        self.security.identity_binding_required
    }

    pub fn has_downgrade_protection(&self) -> bool {
        self.security.downgrade_attack_protection
    }

    pub fn is_internet_sharing_enabled(&self) -> bool {
        self.cellular.enable_internet_sharing
    }

    pub fn get_sharing_rate_limit_mbps(&self) -> u32 {
        self.cellular.sharing_rate_limit_mbps
    }

    pub fn get_sharing_price_per_gb(&self) -> Balance {
        self.cellular.sharing_pricing_per_gb
    }

    pub fn is_fake_poc_mode(&self) -> bool {
        self.proofs.fake_poc_mode
    }

    pub fn get_poc_density_cap(&self) -> u32 {
        self.proofs.poc_density_cap_per_cell
    }

    pub fn get_poc_max_distance_km(&self) -> f64 {
        self.proofs.poc_distance_max_km
    }

    pub fn enable_5g_core_components(&mut self, enable: bool) {
        self.five_g.five_g_core_components.amf_enabled = enable;
        self.five_g.five_g_core_components.smf_enabled = enable;
        self.five_g.five_g_core_components.upf_enabled = enable;
        self.five_g.five_g_core_components.ausf_enabled = enable;
        self.five_g.five_g_core_components.udm_enabled = enable;
        self.five_g.five_g_core_components.pcf_enabled = enable;
    }

    pub fn enable_ego_device_mode(&mut self) {
        self.device.ego_device_only = true;
        self.device.hardware_requirements.tpm_se_required = true;
        self.device.provisioning.manufacturing_ca_required = true;
        self.device.provisioning.device_cert_enrollment = true;
        self.device.certification.ptcrb_required = true;
        self.device.certification.operator_iot_required = true;
        self.security.enable_tpm = true;
        self.security.enable_secure_boot = true;
        self.security.hw_root_of_trust_enabled = true;
    }

    pub fn get_anchor_window_duration(&self) -> Duration {
        Duration::from_secs(self.da.anchor_window_hours * 3600)
    }

    pub fn get_puc_metrics(&self) -> &PUCMetrics {
        &self.drs.puc_metrics
    }

    pub fn is_puc_enabled(&self) -> bool {
        self.drs.enable_puc
    }

    pub fn get_ru_metering_enabled(&self) -> bool {
        self.economics.ru_metering_enabled
    }

    pub fn get_pob_floor_min(&self) -> u64 {
        self.economics.pob_floor_min
    }

    pub fn should_enable_co_beacon(&self) -> bool {
        self.proofs.enable_co_beacon
    }

    pub fn get_micro_slot_duration(&self) -> Duration {
        if self.five_g.micro_slots_enabled {
            Duration::from_millis(self.five_g.micro_slot_duration_ms as u64)
        } else {
            Duration::from_millis(1000)
        }
    }

    pub fn get_spectrum_band(&self) -> &str {
        &self.five_g.spectrum_config.band
    }

    pub fn is_cbrs_enabled(&self) -> bool {
        self.five_g.spectrum_config.cbrs_enabled
    }

    pub fn requires_attestation(&self) -> bool {
        self.operator.attestation_required || self.security.enable_attestation
    }

    pub fn get_attestation_interval(&self) -> u64 {
        self.security.attestation_interval_blocks
    }

    pub fn get_ota_update_policy(&self) -> OTAUpdatePolicy {
        self.device.lifecycle.ota_update_policy
    }

    pub fn get_firmware_signing_threshold(&self) -> u32 {
        self.device.lifecycle.firmware_signing_threshold
    }

    pub fn should_dedup_deploys(&self) -> bool {
        self.deploy_policy.enabled && self.deploy_policy.enable_dedup
    }

    pub fn get_deploy_bond(&self) -> Balance {
        self.deploy_policy.deploy_bond_amount
    }

    pub fn get_free_deploy_quota(&self) -> u32 {
        self.deploy_policy.free_deploys_per_epoch
    }

    pub fn get_storage_credit_rate(&self) -> u64 {
        self.economics.storage_credits_rate
    }

    pub fn get_deploy_credit_rate(&self) -> u64 {
        self.economics.deploy_credits_rate
    }

    pub fn convert_pob_to_storage_credits(&self, pob_amount: Balance) -> u64 {
        (pob_amount.as_u128() / self.economics.storage_credits_rate as u128) as u64
    }

    pub fn convert_pob_to_deploy_credits(&self, pob_amount: Balance) -> u64 {
        (pob_amount.as_u128() / self.economics.deploy_credits_rate as u128) as u64
    }

    pub fn get_replication_factor(&self) -> u8 {
        self.da.replication_factor
    }

    pub fn is_da_sampling_enabled(&self) -> bool {
        self.da.da_sampling_client_enabled
    }

    pub fn get_da_sampling_threshold(&self) -> f64 {
        self.da.sampling_failure_threshold
    }

    pub fn is_optimistic_verification_enabled(&self) -> bool {
        self.fraud_proofs.enable_optimistic_verification
    }

    pub fn get_slashing_percentage(&self) -> u16 {
        self.fraud_proofs.slashing_percentage
    }

    pub fn get_challenger_reward_percentage(&self) -> u16 {
        self.fraud_proofs.challenger_reward_percentage
    }

    pub fn is_backpressure_enabled(&self) -> bool {
        self.performance.enable_backpressure
    }

    pub fn get_backpressure_threshold(&self) -> f64 {
        self.performance.backpressure_threshold
    }

    pub fn get_cpu_budget_per_batch(&self) -> u64 {
        self.performance.cpu_budget_per_batch
    }

    pub fn get_signature_batch_size(&self) -> usize {
        self.performance.signature_verification_batch_size
    }

    pub fn is_peer_scoring_enabled(&self) -> bool {
        self.network.peer_scoring_enabled
    }

    pub fn get_peer_ban_threshold(&self) -> i32 {
        self.network.peer_ban_threshold
    }

    pub fn get_dcutr_enabled(&self) -> bool {
        self.network.enable_dcutr
    }

    pub fn get_compression_algorithm(&self) -> CompressionAlgorithm {
        self.da.compression_algorithm
    }

    pub fn should_keep_headers_forever(&self) -> bool {
        self.storage.keep_headers_forever
    }

    pub fn should_keep_qcs_forever(&self) -> bool {
        self.storage.keep_qcs_forever
    }

    pub fn get_shard_mapping_strategy(&self) -> ShardMappingStrategy {
        self.sharding.shard_mapping_strategy
    }

    pub fn get_max_cross_shard_receipts(&self) -> usize {
        self.sharding.max_cross_shard_receipts_per_epoch
    }

    pub fn get_receipt_deadline_epochs(&self) -> u64 {
        self.sharding.receipt_deadline_epochs
    }

    pub fn get_min_validator_stake(&self) -> u128 {
        self.economics.min_validator_stake
    }

    pub fn get_min_storage_collateral(&self) -> u128 {
        self.economics.min_storage_collateral
    }

    pub fn get_ai_filter_patterns(&self) -> &[String] {
        &self.ai_content_filter.filter_patterns
    }

    pub fn requires_dilithium_verification(&self) -> bool {
        self.ai_content_filter.dilithium_signature_required
    }

    pub fn get_post_windows_per_day(&self) -> u32 {
        self.proofs.windows_per_day
    }

    pub fn get_post_challenges_per_sector(&self) -> u32 {
        self.proofs.challenges_per_sector
    }

    pub fn get_sectors_per_partition(&self) -> u32 {
        self.proofs.sectors_per_partition
    }

    pub fn get_porep_sector_size_bytes(&self) -> u64 {
        (self.proofs.porep_sector_size_gib as u64) * 1024 * 1024 * 1024
    }

    pub fn create_test_config() -> Self {
        let mut config = Self::default();
        config.chain_id = 99;
        config.network_id = 99;
        config.rollup_id = "ego-rollup-test".to_string();
        config.operator.max_batch_size = 100;
        config.operator.batch_timeout_secs = 10;
        config.operator.commit_frequency_secs = 30;
        config.sharding.enabled = true;
        config.sharding.num_shards = 2;
        config.sharding.shard_ids = vec![ShardId::new(0).unwrap(), ShardId::new(1).unwrap()];
        config.storage.enable_pruning = false;
        config.proofs.fake_poc_mode = true;
        config
    }

    pub fn create_production_config() -> Self {
        let mut config = Self::default();
        config.operator.enable_batch_compression = true;
        config.operator.compression_level = 9;
        config.security.pq_only_mode = true;
        config.security.require_dilithium = true;
        config.security.enable_tpm = true;
        config.security.enable_secure_boot = true;
        config.storage.enable_pruning = true;
        config.storage.keep_epochs = 1000;
        config.proofs.fake_poc_mode = false;
        config.proofs.poc_enabled = true;
        config.drs.enabled = true;
        config.deploy_policy.enabled = true;
        config.deploy_policy.human_verification_required = true;
        config.ai_content_filter.enabled = true;
        config
    }

    pub fn create_5g_optimized_config() -> Self {
        let mut config = Self::default();
        config.five_g.enabled = true;
        config.five_g.cellular_safe_mode = true;
        config.five_g.urllc_enabled = true;
        config.five_g.latency_target_ms = 5;
        config.five_g.bandwidth_mbps = 100;
        config.cellular.enabled = true;
        config.cellular.safe_mode_default = true;
        config.cellular.max_monthly_usage_gb = 10;
        config.cellular.heavy_operations_wifi_only = true;
        config.cellular.batch_operations_enabled = true;
        config.cellular.compression_mandatory = true;
        config.operator.enable_batch_compression = true;
        config.operator.compression_level = 9;
        config.da.enable_compression = true;
        config.da.compression_level = 9;
        config.optimize_for_5g();
        config.optimize_for_cellular();
        config.optimize_for_latency();
        config
    }

    pub fn create_ego_device_config() -> Self {
        let mut config = Self::default();
        config.enable_ego_device_mode();
        config.device.hardware_requirements.modem_required = true;
        config.device.hardware_requirements.gps_required = true;
        config.device.provisioning.manufacturing_ca_required = true;
        config.device.provisioning.device_cert_enrollment = true;
        config.device.provisioning.periodic_re_attestation_enabled = true;
        config.device.certification.ptcrb_required = true;
        config.device.certification.operator_iot_required = true;
        config.device.lifecycle.auto_update_enabled = true;
        config.device.lifecycle.ota_update_policy = OTAUpdatePolicy::Automatic;
        config.security.enable_tpm = true;
        config.security.enable_secure_boot = true;
        config.security.enable_attestation = true;
        config.operator.attestation_required = true;
        config.operator.tpm_enabled = true;
        config.operator.se_enabled = true;
        config
    }
}
