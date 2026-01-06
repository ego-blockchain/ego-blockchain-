use ego_core::{
    Account, AccountType, Address, Balance, Block, BlockHeight, EgoError, EgoResult, EpochNumber,
    Hash, ShardId, Transaction, TransactionPayload,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub total_blocks: u64,
    pub total_transactions: u64,
    pub active_validators: u32,
    pub active_storage_providers: u32,
    pub active_devices: u32,
    pub total_staked: Balance,
    pub network_hash_rate: u64,
    pub avg_block_time_ms: u64,
    pub tps_current: f64,
    pub tps_peak: f64,
    pub total_storage_capacity_gb: u64,
    pub total_storage_used_gb: u64,
    pub total_shards: u32,
    pub cross_shard_transactions: u64,
    pub rollup_commits: u64,
    pub poc_events_total: u64,
    pub post_proofs_total: u64,
    pub porep_seals_total: u64,
    pub drs_updates_total: u64,
    pub fraud_proofs_submitted: u64,
    pub fraud_proofs_valid: u64,
    pub pq_adoption_rate: f64,
    pub cellular_node_count: u32,
    pub wifi_node_count: u32,
    pub hybrid_node_count: u32,
    pub total_bandwidth_used_gb: u64,
    pub cellular_bandwidth_gb: u64,
    pub epoch: EpochNumber,
    pub last_updated: u64,
    pub deploy_requests_total: u64,
    pub deploy_requests_accepted: u64,
    pub deploy_requests_rejected: u64,
    pub free_deploys_used: u64,
    pub credits_consumed_total: u64,
    pub pob_burns_total: u64,
    pub deploy_bonds_collected: Balance,
    pub deploy_bonds_slashed: Balance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardMetrics {
    pub shard_id: ShardId,
    pub block_height: BlockHeight,
    pub total_transactions: u64,
    pub pending_transactions: u32,
    pub active_accounts: u32,
    pub state_size_mb: u64,
    pub cross_shard_receipts_sent: u64,
    pub cross_shard_receipts_received: u64,
    pub avg_block_time_ms: u64,
    pub tps: f64,
    pub validator_count: u32,
    pub storage_provider_count: u32,
    pub last_block_hash: Hash,
    pub last_block_timestamp: u64,
    pub epoch_deploys: u64,
    pub epoch_ru_consumed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorMetrics {
    pub validator_address: Address,
    pub blocks_proposed: u64,
    pub blocks_validated: u64,
    pub votes_cast: u64,
    pub missed_blocks: u32,
    pub uptime_percent: f64,
    pub stake_amount: Balance,
    pub delegated_stake: Balance,
    pub commission_rate: u16,
    pub rewards_earned: Balance,
    pub slashing_events: u32,
    pub last_active_epoch: u64,
    pub qc_participation_rate: f64,
    pub pq_compliance: bool,
    pub dilithium_signatures: u64,
    pub hybrid_signatures: u64,
    pub puc_coefficient: f64,
    pub peer_degree: u16,
    pub relay_bytes: u64,
    pub iot_sessions: u32,
    pub shard_demand_score: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProviderMetrics {
    pub provider_address: Address,
    pub storage_capacity_gb: u64,
    pub storage_allocated_gb: u64,
    pub storage_utilization_percent: f64,
    pub active_sectors: u32,
    pub sealed_sectors: u64,
    pub faulty_sectors: u32,
    pub post_proofs_submitted: u64,
    pub post_proofs_passed: u64,
    pub post_proofs_failed: u64,
    pub post_success_rate: f64,
    pub avg_post_latency_ms: u32,
    pub consecutive_misses: u32,
    pub porep_proofs_submitted: u64,
    pub repairs_completed: u64,
    pub promotions: u32,
    pub storage_rewards: Balance,
    pub retrieval_fees: Balance,
    pub post_rewards: Balance,
    pub total_earned: Balance,
    pub total_slashed: Balance,
    pub health_score: u64,
    pub drs_score: f64,
    pub drs_multiplier: f64,
    pub last_audit_epoch: u64,
    pub collateral_locked: Balance,
    pub triad_primary_count: u32,
    pub triad_replica_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceMetrics {
    pub device_address: Address,
    pub device_id: String,
    pub geohash: Option<String>,
    pub h3_cell: Option<String>,
    pub poc_events: u64,
    pub witness_reports: u64,
    pub beacon_transmissions: u64,
    pub avg_signal_quality: f64,
    pub poc_quality_score: f64,
    pub coverage_rewards: Balance,
    pub cellular_safe_mode: bool,
    pub cellular_data_used_mb: u64,
    pub wifi_data_used_mb: u64,
    pub monthly_cellular_estimate_mb: u64,
    pub bandwidth_shared_gb: u64,
    pub connection_type: ConnectionType,
    pub last_poc_timestamp: u64,
    pub density_multiplier: f64,
    pub co_beacon_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConnectionType {
    Cellular5G,
    Cellular4G,
    WiFi,
    Ethernet,
    Unknown,
}

impl Default for NetworkMetrics {
    fn default() -> Self {
        Self {
            total_blocks: 0,
            total_transactions: 0,
            active_validators: 0,
            active_storage_providers: 0,
            active_devices: 0,
            total_staked: Balance::ZERO,
            network_hash_rate: 0,
            avg_block_time_ms: 0,
            tps_current: 0.0,
            tps_peak: 0.0,
            total_storage_capacity_gb: 0,
            total_storage_used_gb: 0,
            total_shards: 1,
            cross_shard_transactions: 0,
            rollup_commits: 0,
            poc_events_total: 0,
            post_proofs_total: 0,
            porep_seals_total: 0,
            drs_updates_total: 0,
            fraud_proofs_submitted: 0,
            fraud_proofs_valid: 0,
            pq_adoption_rate: 0.0,
            cellular_node_count: 0,
            wifi_node_count: 0,
            hybrid_node_count: 0,
            total_bandwidth_used_gb: 0,
            cellular_bandwidth_gb: 0,
            epoch: EpochNumber::new(0),
            last_updated: Self::current_timestamp(),
            deploy_requests_total: 0,
            deploy_requests_accepted: 0,
            deploy_requests_rejected: 0,
            free_deploys_used: 0,
            credits_consumed_total: 0,
            pob_burns_total: 0,
            deploy_bonds_collected: Balance::ZERO,
            deploy_bonds_slashed: Balance::ZERO,
        }
    }
}

impl NetworkMetrics {
    pub fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    pub fn update_timestamp(&mut self) {
        self.last_updated = Self::current_timestamp();
    }

    pub fn storage_utilization_percent(&self) -> f64 {
        if self.total_storage_capacity_gb == 0 {
            return 0.0;
        }
        (self.total_storage_used_gb as f64 / self.total_storage_capacity_gb as f64) * 100.0
    }

    pub fn fraud_proof_accuracy(&self) -> f64 {
        if self.fraud_proofs_submitted == 0 {
            return 0.0;
        }
        (self.fraud_proofs_valid as f64 / self.fraud_proofs_submitted as f64) * 100.0
    }

    pub fn deploy_acceptance_rate(&self) -> f64 {
        if self.deploy_requests_total == 0 {
            return 0.0;
        }
        (self.deploy_requests_accepted as f64 / self.deploy_requests_total as f64) * 100.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMetrics {
    pub proof_type: ProofType,
    pub total_submitted: u64,
    pub total_verified: u64,
    pub total_failed: u64,
    pub avg_latency_ms: u32,
    pub p50_latency_ms: u32,
    pub p95_latency_ms: u32,
    pub p99_latency_ms: u32,
    pub success_rate: f64,
    pub sla_compliance_rate: f64,
    pub batch_submissions: u64,
    pub cellular_optimized_count: u64,
    pub evidence_bundles_uploaded: u64,
    pub evidence_bundle_size_avg_mb: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProofType {
    PoSt,
    PoRep,
    PoC,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DRSMetrics {
    pub node_address: Address,
    pub current_score: f64,
    pub current_multiplier: f64,
    pub uptime_score: f64,
    pub post_pass_rate: f64,
    pub post_latency_score: f64,
    pub poc_quality_score: f64,
    pub serve_ratio: f64,
    pub density_penalty: f64,
    pub last_update_epoch: u64,
    pub rewards_multiplier_applied: u64,
    pub score_history: Vec<DRSScoreSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DRSScoreSnapshot {
    pub epoch: u64,
    pub score: f64,
    pub multiplier: f64,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployMetrics {
    pub total_deploys: u64,
    pub successful_deploys: u64,
    pub failed_deploys: u64,
    pub rejected_deploys: u64,
    pub free_quota_deploys: u64,
    pub credits_deploys: u64,
    pub total_credits_used: u64,
    pub total_pob_burned: u64,
    pub avg_deploy_size_kb: u32,
    pub avg_ru_per_deploy: u64,
    pub bonds_collected: Balance,
    pub bonds_slashed: Balance,
    pub blacklisted_contracts: u32,
    pub duplicate_contracts_rejected: u32,
    pub spam_rejected: u32,
    pub ai_pattern_detected: u32,
    pub human_verified: u32,
    pub last_deploy_timestamp: u64,
    pub epoch_deploys: u64,
}

impl Default for DeployMetrics {
    fn default() -> Self {
        Self {
            total_deploys: 0,
            successful_deploys: 0,
            failed_deploys: 0,
            rejected_deploys: 0,
            free_quota_deploys: 0,
            credits_deploys: 0,
            total_credits_used: 0,
            total_pob_burned: 0,
            avg_deploy_size_kb: 0,
            avg_ru_per_deploy: 0,
            bonds_collected: Balance::ZERO,
            bonds_slashed: Balance::ZERO,
            blacklisted_contracts: 0,
            duplicate_contracts_rejected: 0,
            spam_rejected: 0,
            ai_pattern_detected: 0,
            human_verified: 0,
            last_deploy_timestamp: 0,
            epoch_deploys: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RollupMetrics {
    pub rollup_id: String,
    pub operator: Address,
    pub batches_built: u64,
    pub batches_processed: u64,
    pub commits_posted: u64,
    pub commits_finalized: u64,
    pub commits_challenged: u64,
    pub commits_slashed: u64,
    pub transactions_received: u64,
    pub transactions_processed: u64,
    pub transactions_failed: u64,
    pub total_ru_used: u64,
    pub avg_batch_processing_time_ms: u64,
    pub avg_commit_latency_ms: u64,
    pub finalize_ratio: f64,
    pub da_chunks_encoded: u64,
    pub da_chunks_served: u64,
    pub da_sample_failures: u64,
    pub da_serve_latency_ms: u64,
    pub fraud_proofs_submitted: u64,
    pub fraud_proofs_valid: u64,
    pub fraud_proofs_invalid: u64,
    pub challenge_responses: u64,
    pub cellular_safe_batches: u64,
    pub five_g_batches: u64,
    pub wifi_batches: u64,
    pub edge_processing_time_ms: u64,
    pub network_switches: u64,
    pub latency_target_breaches: u64,
    pub total_fees_collected: Balance,
    pub operator_rewards: Balance,
    pub slashing_penalties: Balance,
    pub challenger_rewards: Balance,
    pub compression_ratio: f64,
    pub erasure_coding_overhead: f64,
    pub monthly_cellular_estimate_mb: u64,
    pub start_time: u64,
    pub last_updated: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQCryptoMetrics {
    pub total_dilithium_signatures: u64,
    pub total_ed25519_signatures: u64,
    pub total_hybrid_signatures: u64,
    pub total_slh_dsa_signatures: u64,
    pub total_kyber_exchanges: u64,
    pub total_x25519_exchanges: u64,
    pub pq_handshakes: u64,
    pub hybrid_handshakes: u64,
    pub avg_dilithium_sign_time_ms: u64,
    pub avg_dilithium_verify_time_ms: u64,
    pub avg_kyber_encap_time_ms: u64,
    pub avg_kyber_decap_time_ms: u64,
    pub batch_verifications: u64,
    pub avg_batch_verify_time_ms: u64,
    pub pq_adoption_rate: f64,
    pub transition_phase: u8,
    pub pq_only_accounts: u32,
    pub hybrid_accounts: u32,
    pub legacy_accounts: u32,
    pub downgrade_attempts_detected: u32,
    pub signature_verification_failures: u64,
}

impl Default for PQCryptoMetrics {
    fn default() -> Self {
        Self {
            total_dilithium_signatures: 0,
            total_ed25519_signatures: 0,
            total_hybrid_signatures: 0,
            total_slh_dsa_signatures: 0,
            total_kyber_exchanges: 0,
            total_x25519_exchanges: 0,
            pq_handshakes: 0,
            hybrid_handshakes: 0,
            avg_dilithium_sign_time_ms: 0,
            avg_dilithium_verify_time_ms: 0,
            avg_kyber_encap_time_ms: 0,
            avg_kyber_decap_time_ms: 0,
            batch_verifications: 0,
            avg_batch_verify_time_ms: 0,
            pq_adoption_rate: 0.0,
            transition_phase: 1,
            pq_only_accounts: 0,
            hybrid_accounts: 0,
            legacy_accounts: 0,
            downgrade_attempts_detected: 0,
            signature_verification_failures: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellularMetrics {
    pub total_cellular_nodes: u32,
    pub cellular_safe_transactions: u64,
    pub wifi_only_transactions: u64,
    pub throttled_operations: u64,
    pub total_cellular_data_gb: u64,
    pub total_wifi_data_gb: u64,
    pub avg_cellular_cost_per_tx: f64,
    pub nodes_near_limit: u32,
    pub nodes_exceeded_limit: u32,
    pub monthly_cellular_avg_gb: f64,
    pub cellular_efficiency_score: f64,
    pub bandwidth_sharing_enabled_nodes: u32,
    pub total_bandwidth_shared_gb: u64,
}

impl Default for CellularMetrics {
    fn default() -> Self {
        Self {
            total_cellular_nodes: 0,
            cellular_safe_transactions: 0,
            wifi_only_transactions: 0,
            throttled_operations: 0,
            total_cellular_data_gb: 0,
            total_wifi_data_gb: 0,
            avg_cellular_cost_per_tx: 0.0,
            nodes_near_limit: 0,
            nodes_exceeded_limit: 0,
            monthly_cellular_avg_gb: 0.0,
            cellular_efficiency_score: 0.0,
            bandwidth_sharing_enabled_nodes: 0,
            total_bandwidth_shared_gb: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochMetrics {
    pub epoch: u64,
    pub start_time: u64,
    pub end_time: Option<u64>,
    pub blocks_produced: u64,
    pub transactions_processed: u64,
    pub total_ru_consumed: u64,
    pub validators_active: u32,
    pub storage_providers_active: u32,
    pub rewards_distributed: Balance,
    pub slashing_penalties: Balance,
    pub post_challenges_issued: u64,
    pub post_responses_received: u64,
    pub poc_events: u64,
    pub drs_updates: u64,
    pub cross_shard_receipts: u64,
    pub rollup_commits: u64,
    pub fraud_proofs: u64,
    pub epoch_finalized: bool,
    pub deploys_submitted: u64,
    pub deploys_accepted: u64,
    pub deploys_rejected: u64,
}

#[derive(Debug)]
pub struct PerformanceTracker {
    operation_times: HashMap<String, Vec<Duration>>,
    start_times: HashMap<String, Instant>,
    max_samples: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSummary {
    pub operation: String,
    pub avg_duration_ms: u64,
    pub p50_duration_ms: u64,
    pub p95_duration_ms: u64,
    pub p99_duration_ms: u64,
    pub min_duration_ms: u64,
    pub max_duration_ms: u64,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemAlerts {
    pub active_alerts: Vec<Alert>,
    pub alert_history: Vec<Alert>,
    pub alert_thresholds: AlertThresholds,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub alert_type: AlertType,
    pub severity: AlertSeverity,
    pub message: String,
    pub timestamp: u64,
    pub resolved: bool,
    pub resolution_time: Option<u64>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AlertType {
    HighLatency,
    DAFailure,
    ChallengeSLABreach,
    HighDisputeRate,
    RepeatedInvalidations,
    BondNearingMinimum,
    NetworkPartition,
    OperatorOffline,
    FraudDetected,
    SystemOverload,
    CellularDataLimitApproaching,
    CellularDataLimitExceeded,
    PostProofFailure,
    PocEventMissing,
    CrossShardReceiptFailure,
    CompressionFailure,
    ErasureCodingFailure,
    PQSignatureFailure,
    BatchVerificationFailure,
    ValidatorMissedBlocks,
    StorageProviderHealthLow,
    DRSScoreLow,
    TriadPlacementFailure,
    SectorFaulty,
    DensityPenaltyHigh,
    DeployQuotaExceeded,
    DeploySpamDetected,
    DeployAIPatternDetected,
    DeployBondSlashed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThresholds {
    pub max_batch_processing_time_ms: u64,
    pub max_da_serve_time_ms: u64,
    pub min_da_availability_percent: f64,
    pub max_challenge_response_time_ms: u64,
    pub max_dispute_rate_percent: f64,
    pub min_bond_threshold: u64,
    pub max_finalization_time_ms: u64,
    pub cellular_data_warning_percent: f64,
    pub cellular_data_critical_percent: f64,
    pub max_cellular_data_mb_per_month: u64,
    pub min_post_success_rate: f64,
    pub max_post_latency_ms: u64,
    pub min_poc_event_rate: f64,
    pub max_signature_verification_time_ms: u64,
    pub max_compression_ratio: f64,
    pub min_validator_uptime_percent: f64,
    pub max_validator_missed_blocks: u32,
    pub min_storage_health_score: u64,
    pub min_drs_score: f64,
    pub max_density_penalty: f64,
    pub max_consecutive_post_misses: u32,
    pub max_deploy_spam_score: u32,
    pub max_deploy_rejection_rate: f64,
    pub min_deploy_human_verification_rate: f64,
}

impl Default for AlertThresholds {
    fn default() -> Self {
        Self {
            max_batch_processing_time_ms: 5000,
            max_da_serve_time_ms: 300,
            min_da_availability_percent: 95.0,
            max_challenge_response_time_ms: 60000,
            max_dispute_rate_percent: 5.0,
            min_bond_threshold: 100000,
            max_finalization_time_ms: 3600000,
            cellular_data_warning_percent: 80.0,
            cellular_data_critical_percent: 95.0,
            max_cellular_data_mb_per_month: 5000,
            min_post_success_rate: 0.95,
            max_post_latency_ms: 8000,
            min_poc_event_rate: 0.9,
            max_signature_verification_time_ms: 100,
            max_compression_ratio: 0.9,
            min_validator_uptime_percent: 95.0,
            max_validator_missed_blocks: 5,
            min_storage_health_score: 80000,
            min_drs_score: 0.7,
            max_density_penalty: 0.3,
            max_consecutive_post_misses: 2,
            max_deploy_spam_score: 100,
            max_deploy_rejection_rate: 0.5,
            min_deploy_human_verification_rate: 0.8,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub timestamp: u64,
    pub network: NetworkMetrics,
    pub shards: Vec<ShardMetrics>,
    pub validators: Vec<ValidatorMetrics>,
    pub storage_providers: Vec<StorageProviderMetrics>,
    pub devices: Vec<DeviceMetrics>,
    pub proofs: Vec<ProofMetrics>,
    pub drs_scores: Vec<DRSMetrics>,
    pub rollups: Vec<RollupMetrics>,
    pub pq_crypto: PQCryptoMetrics,
    pub cellular: CellularMetrics,
    pub epoch: EpochMetrics,
    pub performance: HashMap<String, PerformanceSummary>,
    pub deploy: DeployMetrics,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AlertStats {
    pub total_alerts: u64,
    pub active_alerts: u64,
    pub resolved_alerts: u64,
    pub info_alerts: u64,
    pub warning_alerts: u64,
    pub error_alerts: u64,
    pub critical_alerts: u64,
    pub avg_resolution_time_ms: u64,
}

impl PerformanceTracker {
    pub fn new(max_samples: usize) -> Self {
        Self {
            operation_times: HashMap::new(),
            start_times: HashMap::new(),
            max_samples,
        }
    }

    pub fn start_timing(&mut self, operation: &str) {
        self.start_times
            .insert(operation.to_string(), Instant::now());
    }

    pub fn end_timing(&mut self, operation: &str) {
        if let Some(start_time) = self.start_times.remove(operation) {
            let duration = start_time.elapsed();
            let times = self
                .operation_times
                .entry(operation.to_string())
                .or_insert_with(Vec::new);
            times.push(duration);
            if times.len() > self.max_samples {
                times.remove(0);
            }
        }
    }

    pub fn record_duration(&mut self, operation: &str, duration: Duration) {
        let times = self
            .operation_times
            .entry(operation.to_string())
            .or_insert_with(Vec::new);
        times.push(duration);
        if times.len() > self.max_samples {
            times.remove(0);
        }
    }

    pub fn avg_time(&self, operation: &str) -> Option<Duration> {
        let times = self.operation_times.get(operation)?;
        if times.is_empty() {
            return None;
        }
        let total: Duration = times.iter().sum();
        Some(total / times.len() as u32)
    }

    pub fn percentile_time(&self, operation: &str, percentile: f64) -> Option<Duration> {
        let mut times = self.operation_times.get(operation)?.clone();
        if times.is_empty() {
            return None;
        }
        times.sort();
        let index = ((times.len() as f64 * percentile / 100.0) as usize).min(times.len() - 1);
        Some(times[index])
    }

    pub fn min_time(&self, operation: &str) -> Option<Duration> {
        let times = self.operation_times.get(operation)?;
        times.iter().min().copied()
    }

    pub fn max_time(&self, operation: &str) -> Option<Duration> {
        let times = self.operation_times.get(operation)?;
        times.iter().max().copied()
    }

    pub fn summary(&self) -> HashMap<String, PerformanceSummary> {
        let mut summary = HashMap::new();
        for operation in self.operation_times.keys() {
            if let (Some(avg), Some(p50), Some(p95), Some(p99), Some(min), Some(max)) = (
                self.avg_time(operation),
                self.percentile_time(operation, 50.0),
                self.percentile_time(operation, 95.0),
                self.percentile_time(operation, 99.0),
                self.min_time(operation),
                self.max_time(operation),
            ) {
                let count = self
                    .operation_times
                    .get(operation)
                    .map(|v| v.len())
                    .unwrap_or(0) as u64;
                summary.insert(
                    operation.clone(),
                    PerformanceSummary {
                        operation: operation.clone(),
                        avg_duration_ms: avg.as_millis() as u64,
                        p50_duration_ms: p50.as_millis() as u64,
                        p95_duration_ms: p95.as_millis() as u64,
                        p99_duration_ms: p99.as_millis() as u64,
                        min_duration_ms: min.as_millis() as u64,
                        max_duration_ms: max.as_millis() as u64,
                        count,
                    },
                );
            }
        }
        summary
    }

    pub fn reset(&mut self) {
        self.operation_times.clear();
        self.start_times.clear();
    }

    pub fn clear_operation(&mut self, operation: &str) {
        self.operation_times.remove(operation);
        self.start_times.remove(operation);
    }
}

impl SystemAlerts {
    pub fn new() -> Self {
        Self {
            active_alerts: Vec::new(),
            alert_history: Vec::new(),
            alert_thresholds: AlertThresholds::default(),
        }
    }

    pub fn with_thresholds(thresholds: AlertThresholds) -> Self {
        Self {
            active_alerts: Vec::new(),
            alert_history: Vec::new(),
            alert_thresholds: thresholds,
        }
    }

    pub fn create_alert(
        &mut self,
        alert_type: AlertType,
        severity: AlertSeverity,
        message: String,
    ) -> String {
        self.create_alert_with_metadata(alert_type, severity, message, HashMap::new())
    }

    pub fn create_alert_with_metadata(
        &mut self,
        alert_type: AlertType,
        severity: AlertSeverity,
        message: String,
        metadata: HashMap<String, String>,
    ) -> String {
        let alert_id = format!(
            "alert_{}_{}",
            self.alert_history.len(),
            alert_type_to_string(&alert_type)
        );
        let timestamp = NetworkMetrics::current_timestamp();

        let alert = Alert {
            id: alert_id.clone(),
            alert_type,
            severity,
            message,
            timestamp,
            resolved: false,
            resolution_time: None,
            metadata,
        };

        self.active_alerts.push(alert.clone());
        self.alert_history.push(alert);

        alert_id
    }

    pub fn resolve_alert(&mut self, alert_id: &str) -> bool {
        let timestamp = NetworkMetrics::current_timestamp();

        if let Some(pos) = self.active_alerts.iter().position(|a| a.id == alert_id) {
            self.active_alerts.remove(pos);
        }

        if let Some(alert) = self.alert_history.iter_mut().find(|a| a.id == alert_id) {
            alert.resolved = true;
            alert.resolution_time = Some(timestamp);
            return true;
        }

        false
    }

    pub fn get_alerts_by_severity(&self, severity: AlertSeverity) -> Vec<&Alert> {
        self.active_alerts
            .iter()
            .filter(|a| a.severity == severity)
            .collect()
    }

    pub fn get_alerts_by_type(&self, alert_type: AlertType) -> Vec<&Alert> {
        self.active_alerts
            .iter()
            .filter(|a| a.alert_type == alert_type)
            .collect()
    }

    pub fn get_alert_stats(&self) -> AlertStats {
        let mut stats = AlertStats::default();

        for alert in &self.alert_history {
            stats.total_alerts += 1;

            match alert.severity {
                AlertSeverity::Info => stats.info_alerts += 1,
                AlertSeverity::Warning => stats.warning_alerts += 1,
                AlertSeverity::Error => stats.error_alerts += 1,
                AlertSeverity::Critical => stats.critical_alerts += 1,
            }

            if alert.resolved {
                stats.resolved_alerts += 1;
                if let Some(resolution_time) = alert.resolution_time {
                    let resolution_duration = resolution_time - alert.timestamp;
                    stats.avg_resolution_time_ms += resolution_duration;
                }
            }
        }

        stats.active_alerts = self.active_alerts.len() as u64;

        if stats.resolved_alerts > 0 {
            stats.avg_resolution_time_ms /= stats.resolved_alerts;
        }

        stats
    }

    pub fn prune_old_alerts(&mut self, retention_hours: u64) -> usize {
        let current_time = NetworkMetrics::current_timestamp();
        let cutoff = current_time - (retention_hours * 3_600_000);

        let before_count = self.alert_history.len();

        self.alert_history
            .retain(|alert| alert.timestamp >= cutoff || !alert.resolved);

        before_count - self.alert_history.len()
    }
}

impl Default for SystemAlerts {
    fn default() -> Self {
        Self::new()
    }
}

pub struct MetricsCollector {
    network_metrics: Arc<Mutex<NetworkMetrics>>,
    shard_metrics: Arc<Mutex<HashMap<ShardId, ShardMetrics>>>,
    validator_metrics: Arc<Mutex<HashMap<Address, ValidatorMetrics>>>,
    storage_provider_metrics: Arc<Mutex<HashMap<Address, StorageProviderMetrics>>>,
    device_metrics: Arc<Mutex<HashMap<Address, DeviceMetrics>>>,
    proof_metrics: Arc<Mutex<HashMap<ProofType, ProofMetrics>>>,
    drs_metrics: Arc<Mutex<HashMap<Address, DRSMetrics>>>,
    rollup_metrics: Arc<Mutex<HashMap<String, RollupMetrics>>>,
    pq_crypto_metrics: Arc<Mutex<PQCryptoMetrics>>,
    cellular_metrics: Arc<Mutex<CellularMetrics>>,
    epoch_metrics: Arc<Mutex<HashMap<u64, EpochMetrics>>>,
    performance_tracker: Arc<Mutex<PerformanceTracker>>,
    alerts: Arc<Mutex<SystemAlerts>>,
    deploy_metrics: Arc<Mutex<DeployMetrics>>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            network_metrics: Arc::new(Mutex::new(NetworkMetrics::default())),
            shard_metrics: Arc::new(Mutex::new(HashMap::new())),
            validator_metrics: Arc::new(Mutex::new(HashMap::new())),
            storage_provider_metrics: Arc::new(Mutex::new(HashMap::new())),
            device_metrics: Arc::new(Mutex::new(HashMap::new())),
            proof_metrics: Arc::new(Mutex::new(HashMap::new())),
            drs_metrics: Arc::new(Mutex::new(HashMap::new())),
            rollup_metrics: Arc::new(Mutex::new(HashMap::new())),
            pq_crypto_metrics: Arc::new(Mutex::new(PQCryptoMetrics::default())),
            cellular_metrics: Arc::new(Mutex::new(CellularMetrics::default())),
            epoch_metrics: Arc::new(Mutex::new(HashMap::new())),
            performance_tracker: Arc::new(Mutex::new(PerformanceTracker::new(1000))),
            alerts: Arc::new(Mutex::new(SystemAlerts::new())),
            deploy_metrics: Arc::new(Mutex::new(DeployMetrics::default())),
        }
    }

    pub fn record_block(&self, block: &Block) -> EgoResult<()> {
        let mut network = self.network_metrics.lock().unwrap();
        network.total_blocks += 1;
        network.total_transactions += block.header.core.tx_count as u64;
        network.epoch = block.header.core.epoch;
        network.update_timestamp();

        let block_time_ms = if network.total_blocks > 1 {
            let time_diff = block.header.core.timestamp.as_millis()
                - (network.last_updated - network.avg_block_time_ms);
            time_diff
        } else {
            0
        };

        if network.total_blocks > 1 {
            network.avg_block_time_ms = (network.avg_block_time_ms * (network.total_blocks - 1)
                + block_time_ms)
                / network.total_blocks;
        }

        let mut shard_metrics = self.shard_metrics.lock().unwrap();
        let shard = shard_metrics
            .entry(block.header.core.shard_id)
            .or_insert_with(|| ShardMetrics {
                shard_id: block.header.core.shard_id,
                block_height: BlockHeight::GENESIS,
                total_transactions: 0,
                pending_transactions: 0,
                active_accounts: 0,
                state_size_mb: 0,
                cross_shard_receipts_sent: 0,
                cross_shard_receipts_received: 0,
                avg_block_time_ms: 0,
                tps: 0.0,
                validator_count: 0,
                storage_provider_count: 0,
                last_block_hash: Hash::ZERO,
                last_block_timestamp: 0,
                epoch_deploys: 0,
                epoch_ru_consumed: 0,
            });

        shard.block_height = block.header.core.height;
        shard.total_transactions += block.header.core.tx_count as u64;
        shard.cross_shard_receipts_sent += block.body.cross_shard_receipts.len() as u64;
        shard.last_block_hash = block.hash;
        shard.last_block_timestamp = block.header.core.timestamp.as_millis();

        network.cross_shard_transactions += block.body.cross_shard_receipts.len() as u64;
        network.rollup_commits += block.body.rollup_commitments.len() as u64;

        let poc_events = block
            .body
            .proof_events
            .iter()
            .filter(|e| matches!(e.proof_type, ego_core::ProofEventType::PoC))
            .count() as u64;
        let post_events = block
            .body
            .proof_events
            .iter()
            .filter(|e| matches!(e.proof_type, ego_core::ProofEventType::PoSt))
            .count() as u64;

        network.poc_events_total += poc_events;
        network.post_proofs_total += post_events;
        network.drs_updates_total += block.body.drs_events.len() as u64;
        network.fraud_proofs_submitted += block.body.fraud_proofs.len() as u64;

        let pq_rate = block.get_pq_adoption_rate();
        network.pq_adoption_rate = (network.pq_adoption_rate * (network.total_blocks - 1) as f64
            + pq_rate)
            / network.total_blocks as f64;

        let mut pq_metrics = self.pq_crypto_metrics.lock().unwrap();
        pq_metrics.total_dilithium_signatures +=
            block.header.core.pq_signature_count.dilithium_sigs as u64;
        pq_metrics.total_ed25519_signatures +=
            block.header.core.pq_signature_count.ed25519_sigs as u64;
        pq_metrics.total_hybrid_signatures +=
            block.header.core.pq_signature_count.hybrid_sigs as u64;
        pq_metrics.total_slh_dsa_signatures +=
            block.header.core.pq_signature_count.slh_dsa_sigs as u64;

        let total_sigs = pq_metrics.total_dilithium_signatures
            + pq_metrics.total_ed25519_signatures
            + pq_metrics.total_hybrid_signatures;
        if total_sigs > 0 {
            pq_metrics.pq_adoption_rate = ((pq_metrics.total_dilithium_signatures
                + pq_metrics.total_hybrid_signatures)
                as f64
                / total_sigs as f64)
                * 100.0;
        }

        let mut cellular = self.cellular_metrics.lock().unwrap();
        cellular.cellular_safe_transactions +=
            block.header.metadata.cellular_stats.cellular_safe_txs as u64;
        cellular.wifi_only_transactions +=
            block.header.metadata.cellular_stats.wifi_only_txs as u64;
        cellular.throttled_operations +=
            block.header.metadata.cellular_stats.throttled_operations as u64;
        cellular.total_cellular_data_gb += block
            .header
            .metadata
            .cellular_stats
            .total_data_bytes_cellular
            / (1024 * 1024 * 1024);
        cellular.total_wifi_data_gb +=
            block.header.metadata.cellular_stats.total_data_bytes_wifi / (1024 * 1024 * 1024);

        network.cellular_bandwidth_gb += cellular.total_cellular_data_gb;
        network.total_bandwidth_used_gb +=
            cellular.total_cellular_data_gb + cellular.total_wifi_data_gb;

        Ok(())
    }

    pub fn record_transaction(&self, tx: &Transaction) -> EgoResult<()> {
        if tx.signature.dilithium_sig.is_some() && tx.signature.ed25519_sig.is_some() {
            let mut pq_metrics = self.pq_crypto_metrics.lock().unwrap();
            pq_metrics.total_hybrid_signatures += 1;
        } else if tx.signature.dilithium_sig.is_some() {
            let mut pq_metrics = self.pq_crypto_metrics.lock().unwrap();
            pq_metrics.total_dilithium_signatures += 1;
        } else if tx.signature.ed25519_sig.is_some() {
            let mut pq_metrics = self.pq_crypto_metrics.lock().unwrap();
            pq_metrics.total_ed25519_signatures += 1;
        }

        if tx.requires_slh_dsa() {
            let mut pq_metrics = self.pq_crypto_metrics.lock().unwrap();
            pq_metrics.total_slh_dsa_signatures += 1;
        }

        match &tx.payload {
            TransactionPayload::StoreData { .. } => {
                let mut cellular = self.cellular_metrics.lock().unwrap();
                cellular.wifi_only_transactions += 1;
            }
            TransactionPayload::SubmitProofBatch { .. }
            | TransactionPayload::PoStResponse { .. }
            | TransactionPayload::PoCWitnessReport { .. } => {
                let mut cellular = self.cellular_metrics.lock().unwrap();
                cellular.cellular_safe_transactions += 1;
            }
            TransactionPayload::DeployContract { .. } => {
                let mut deploy = self.deploy_metrics.lock().unwrap();
                deploy.total_deploys += 1;
                deploy.last_deploy_timestamp = NetworkMetrics::current_timestamp();
            }
            _ => {}
        }

        Ok(())
    }

    pub fn record_deploy_decision(
        &self,
        accepted: bool,
        free_quota_used: bool,
        credits_used: u64,
        size_kb: u32,
        ru_consumed: u64,
        rejection_reason: Option<&str>,
    ) -> EgoResult<()> {
        let mut deploy = self.deploy_metrics.lock().unwrap();
        let mut network = self.network_metrics.lock().unwrap();

        network.deploy_requests_total += 1;

        if accepted {
            deploy.successful_deploys += 1;
            network.deploy_requests_accepted += 1;

            if free_quota_used {
                deploy.free_quota_deploys += 1;
                network.free_deploys_used += 1;
            } else {
                deploy.credits_deploys += 1;
            }

            deploy.total_credits_used += credits_used;
            network.credits_consumed_total += credits_used;

            let total_successful = deploy.successful_deploys;
            deploy.avg_deploy_size_kb = ((deploy.avg_deploy_size_kb as u64
                * (total_successful - 1))
                + size_kb as u64) as u32
                / total_successful as u32;
            deploy.avg_ru_per_deploy = ((deploy.avg_ru_per_deploy * (total_successful - 1))
                + ru_consumed)
                / total_successful;
        } else {
            deploy.rejected_deploys += 1;
            network.deploy_requests_rejected += 1;

            if let Some(reason) = rejection_reason {
                if reason.contains("spam") || reason.contains("Anti-spam") {
                    deploy.spam_rejected += 1;
                } else if reason.contains("Duplicate") {
                    deploy.duplicate_contracts_rejected += 1;
                } else if reason.contains("AI") || reason.contains("filler") {
                    deploy.ai_pattern_detected += 1;
                }
            }
        }

        Ok(())
    }

    pub fn record_deploy_bond_event(&self, collected: bool, amount: Balance) -> EgoResult<()> {
        let mut deploy = self.deploy_metrics.lock().unwrap();
        let mut network = self.network_metrics.lock().unwrap();

        if collected {
            deploy.bonds_collected = deploy
                .bonds_collected
                .checked_add(amount)
                .unwrap_or(deploy.bonds_collected);
            network.deploy_bonds_collected = network
                .deploy_bonds_collected
                .checked_add(amount)
                .unwrap_or(network.deploy_bonds_collected);
        } else {
            deploy.bonds_slashed = deploy
                .bonds_slashed
                .checked_add(amount)
                .unwrap_or(deploy.bonds_slashed);
            network.deploy_bonds_slashed = network
                .deploy_bonds_slashed
                .checked_add(amount)
                .unwrap_or(network.deploy_bonds_slashed);
        }

        Ok(())
    }

    pub fn record_deploy_pob_burn(&self, amount: u64) -> EgoResult<()> {
        let mut deploy = self.deploy_metrics.lock().unwrap();
        let mut network = self.network_metrics.lock().unwrap();

        deploy.total_pob_burned += amount;
        network.pob_burns_total += amount;

        Ok(())
    }

    pub fn record_deploy_verification(
        &self,
        human_verified: bool,
        ai_detected: bool,
    ) -> EgoResult<()> {
        let mut deploy = self.deploy_metrics.lock().unwrap();

        if human_verified {
            deploy.human_verified += 1;
        }

        if ai_detected {
            deploy.ai_pattern_detected += 1;
        }

        Ok(())
    }

    pub fn update_validator_metrics(&self, address: Address, account: &Account) -> EgoResult<()> {
        if !account.is_validator() {
            return Ok(());
        }

        let mut validators = self.validator_metrics.lock().unwrap();
        let validator = validators
            .entry(address)
            .or_insert_with(|| ValidatorMetrics {
                validator_address: address,
                blocks_proposed: 0,
                blocks_validated: 0,
                votes_cast: 0,
                missed_blocks: 0,
                uptime_percent: 100.0,
                stake_amount: Balance::ZERO,
                delegated_stake: Balance::ZERO,
                commission_rate: 0,
                rewards_earned: Balance::ZERO,
                slashing_events: 0,
                last_active_epoch: 0,
                qc_participation_rate: 100.0,
                pq_compliance: false,
                dilithium_signatures: 0,
                hybrid_signatures: 0,
                puc_coefficient: 1.0,
                peer_degree: 0,
                relay_bytes: 0,
                iot_sessions: 0,
                shard_demand_score: 0,
            });

        if let Some(ref validator_info) = account.validator_info {
            validator.commission_rate = validator_info.commission_rate;
            validator.pq_compliance = account.is_pq_only_mode();
        }

        if let Some(ref staking_info) = account.staking_info {
            validator.stake_amount = staking_info.staked_amount;
            validator.delegated_stake = staking_info.delegated_stake;
            validator.rewards_earned = staking_info.rewards_earned;
            validator.slashing_events = staking_info.slashing_events.len() as u32;
            validator.uptime_percent = staking_info.performance.uptime_percentage as f64 / 1000.0;
        }

        let mut network = self.network_metrics.lock().unwrap();
        if account
            .validator_info
            .as_ref()
            .map_or(false, |v| v.is_active)
        {
            network.active_validators += 1;
        }

        Ok(())
    }

    pub fn update_storage_provider_metrics(
        &self,
        address: Address,
        account: &Account,
    ) -> EgoResult<()> {
        if !account.is_storage_provider() {
            return Ok(());
        }

        let mut providers = self.storage_provider_metrics.lock().unwrap();

        if let Some(ref provider_info) = account.storage_provider_info {
            let provider = providers
                .entry(address)
                .or_insert_with(|| StorageProviderMetrics {
                    provider_address: address,
                    storage_capacity_gb: 0,
                    storage_allocated_gb: 0,
                    storage_utilization_percent: 0.0,
                    active_sectors: 0,
                    sealed_sectors: 0,
                    faulty_sectors: 0,
                    post_proofs_submitted: 0,
                    post_proofs_passed: 0,
                    post_proofs_failed: 0,
                    post_success_rate: 0.0,
                    avg_post_latency_ms: 0,
                    consecutive_misses: 0,
                    porep_proofs_submitted: 0,
                    repairs_completed: 0,
                    promotions: 0,
                    storage_rewards: Balance::ZERO,
                    retrieval_fees: Balance::ZERO,
                    post_rewards: Balance::ZERO,
                    total_earned: Balance::ZERO,
                    total_slashed: Balance::ZERO,
                    health_score: 0,
                    drs_score: 1.0,
                    drs_multiplier: 1.0,
                    last_audit_epoch: 0,
                    collateral_locked: Balance::ZERO,
                    triad_primary_count: 0,
                    triad_replica_count: 0,
                });

            provider.storage_capacity_gb = provider_info.storage_capacity / (1024 * 1024 * 1024);
            provider.storage_allocated_gb = provider_info.storage_allocated / (1024 * 1024 * 1024);
            provider.storage_utilization_percent = if provider_info.storage_capacity > 0 {
                (provider_info.storage_allocated as f64 / provider_info.storage_capacity as f64)
                    * 100.0
            } else {
                0.0
            };
            provider.active_sectors = provider_info.active_sectors.len() as u32;
            provider.sealed_sectors = provider_info.postrep_stats.sectors_sealed;
            provider.faulty_sectors = provider_info.postrep_stats.sectors_faulty;
            provider.post_proofs_submitted = provider_info.postrep_stats.post_proofs_submitted;
            provider.post_proofs_passed = provider_info.postrep_stats.challenges_answered;
            provider.post_proofs_failed = provider_info.postrep_stats.challenges_missed;
            provider.post_success_rate = provider_info.postrep_stats.post_pass_rate;
            provider.avg_post_latency_ms = provider_info.postrep_stats.avg_post_latency_ms;
            provider.consecutive_misses = provider_info.postrep_stats.consecutive_misses;
            provider.porep_proofs_submitted = provider_info.postrep_stats.porep_proofs_submitted;
            provider.repairs_completed = provider_info.postrep_stats.repairs_completed;
            provider.promotions = provider_info.postrep_stats.promotions;
            provider.storage_rewards = provider_info.earnings.storage_rewards;
            provider.retrieval_fees = provider_info.earnings.retrieval_fees;
            provider.post_rewards = provider_info.earnings.post_rewards;
            provider.total_earned = provider_info.earnings.total_earned;
            provider.total_slashed = provider_info.earnings.total_slashed;
            provider.health_score = provider_info.health_score;
            provider.last_audit_epoch = provider_info.last_audit_epoch;
            provider.collateral_locked = provider_info.collateral_locked;

            if let Some(drs_score) = account.last_drs_score {
                provider.drs_score = drs_score as f64 / 1000.0;
                provider.drs_multiplier = (drs_score as f64 / 100000.0).clamp(0.7, 1.3);
            }

            let mut network = self.network_metrics.lock().unwrap();
            network.active_storage_providers += 1;
            network.total_storage_capacity_gb += provider.storage_capacity_gb;
            network.total_storage_used_gb += provider.storage_allocated_gb;
            network.porep_seals_total += provider.porep_proofs_submitted;
        }

        Ok(())
    }

    pub fn update_device_metrics(&self, address: Address, account: &Account) -> EgoResult<()> {
        if !account.is_device() {
            return Ok(());
        }
        let mut devices = self.device_metrics.lock().unwrap();
        if let Some(ref device_caps) = account.device_capabilities {
            let device = devices.entry(address).or_insert_with(|| DeviceMetrics {
                device_address: address,
                device_id: String::new(),
                geohash: None,
                h3_cell: None,
                poc_events: 0,
                witness_reports: 0,
                beacon_transmissions: 0,
                avg_signal_quality: 0.0,
                poc_quality_score: 0.0,
                coverage_rewards: Balance::ZERO,
                cellular_safe_mode: true,
                cellular_data_used_mb: 0,
                wifi_data_used_mb: 0,
                monthly_cellular_estimate_mb: 0,
                bandwidth_shared_gb: 0,
                connection_type: ConnectionType::Unknown,
                last_poc_timestamp: 0,
                density_multiplier: 1.0,
                co_beacon_verified: false,
            });
            if let AccountType::Device { device_id, geohash } = &account.account_type {
                device.device_id = device_id.clone();
                device.geohash = geohash.clone();
            }
            device.cellular_safe_mode = device_caps.cellular_safe;
            device.cellular_data_used_mb = device_caps.cost_awareness.current_month_usage_gb * 1024;
            device.monthly_cellular_estimate_mb =
                device_caps.cost_awareness.cellular_throttle_threshold_gb * 1024;
            if device_caps.cellular_safe {
                let mut network = self.network_metrics.lock().unwrap();
                network.cellular_node_count += 1;
            }
            let mut network = self.network_metrics.lock().unwrap();
            network.active_devices += 1;
        }
        Ok(())
    }
}

impl MetricsCollector {
    pub fn record_proof_submission(
        &self,
        proof_type: ProofType,
        latency_ms: u32,
        verified: bool,
        cellular_optimized: bool,
    ) -> EgoResult<()> {
        let mut proofs = self.proof_metrics.lock().unwrap();
        let proof = proofs.entry(proof_type).or_insert_with(|| ProofMetrics {
            proof_type,
            total_submitted: 0,
            total_verified: 0,
            total_failed: 0,
            avg_latency_ms: 0,
            p50_latency_ms: 0,
            p95_latency_ms: 0,
            p99_latency_ms: 0,
            success_rate: 0.0,
            sla_compliance_rate: 0.0,
            batch_submissions: 0,
            cellular_optimized_count: 0,
            evidence_bundles_uploaded: 0,
            evidence_bundle_size_avg_mb: 0.0,
        });

        proof.total_submitted += 1;
        if verified {
            proof.total_verified += 1;
        } else {
            proof.total_failed += 1;
        }

        if cellular_optimized {
            proof.cellular_optimized_count += 1;
        }

        proof.avg_latency_ms = ((proof.avg_latency_ms as u64 * (proof.total_submitted - 1))
            + latency_ms as u64) as u32
            / proof.total_submitted as u32;

        proof.success_rate = (proof.total_verified as f64 / proof.total_submitted as f64) * 100.0;

        let sla_ms = match proof_type {
            ProofType::PoSt => 8000,
            ProofType::PoRep => 10000,
            ProofType::PoC => 5000,
        };

        if latency_ms <= sla_ms {
            proof.sla_compliance_rate =
                ((proof.sla_compliance_rate * (proof.total_submitted - 1) as f64) + 1.0)
                    / proof.total_submitted as f64;
        } else {
            proof.sla_compliance_rate = (proof.sla_compliance_rate
                * (proof.total_submitted - 1) as f64)
                / proof.total_submitted as f64;
        }

        Ok(())
    }

    pub fn update_drs_metrics(
        &self,
        node_address: Address,
        score: f64,
        multiplier: f64,
        epoch: u64,
        components: (f64, f64, f64, f64, f64, f64),
    ) -> EgoResult<()> {
        let mut drs_map = self.drs_metrics.lock().unwrap();
        let drs = drs_map.entry(node_address).or_insert_with(|| DRSMetrics {
            node_address,
            current_score: 0.0,
            current_multiplier: 1.0,
            uptime_score: 0.0,
            post_pass_rate: 0.0,
            post_latency_score: 0.0,
            poc_quality_score: 0.0,
            serve_ratio: 0.0,
            density_penalty: 0.0,
            last_update_epoch: 0,
            rewards_multiplier_applied: 0,
            score_history: Vec::new(),
        });

        drs.current_score = score;
        drs.current_multiplier = multiplier;
        drs.uptime_score = components.0;
        drs.post_pass_rate = components.1;
        drs.post_latency_score = components.2;
        drs.poc_quality_score = components.3;
        drs.serve_ratio = components.4;
        drs.density_penalty = components.5;
        drs.last_update_epoch = epoch;
        drs.rewards_multiplier_applied += 1;

        drs.score_history.push(DRSScoreSnapshot {
            epoch,
            score,
            multiplier,
            timestamp: NetworkMetrics::current_timestamp(),
        });

        if drs.score_history.len() > 1000 {
            drs.score_history.remove(0);
        }

        Ok(())
    }

    pub fn record_rollup_commit(
        &self,
        rollup_id: &str,
        operator: Address,
        tx_count: u32,
        latency_ms: u64,
    ) -> EgoResult<()> {
        let mut rollups = self.rollup_metrics.lock().unwrap();
        let rollup = rollups
            .entry(rollup_id.to_string())
            .or_insert_with(|| RollupMetrics {
                rollup_id: rollup_id.to_string(),
                operator,
                batches_built: 0,
                batches_processed: 0,
                commits_posted: 0,
                commits_finalized: 0,
                commits_challenged: 0,
                commits_slashed: 0,
                transactions_received: 0,
                transactions_processed: 0,
                transactions_failed: 0,
                total_ru_used: 0,
                avg_batch_processing_time_ms: 0,
                avg_commit_latency_ms: 0,
                finalize_ratio: 0.0,
                da_chunks_encoded: 0,
                da_chunks_served: 0,
                da_sample_failures: 0,
                da_serve_latency_ms: 0,
                fraud_proofs_submitted: 0,
                fraud_proofs_valid: 0,
                fraud_proofs_invalid: 0,
                challenge_responses: 0,
                cellular_safe_batches: 0,
                five_g_batches: 0,
                wifi_batches: 0,
                edge_processing_time_ms: 0,
                network_switches: 0,
                latency_target_breaches: 0,
                total_fees_collected: Balance::ZERO,
                operator_rewards: Balance::ZERO,
                slashing_penalties: Balance::ZERO,
                challenger_rewards: Balance::ZERO,
                compression_ratio: 1.0,
                erasure_coding_overhead: 1.5,
                monthly_cellular_estimate_mb: 0,
                start_time: NetworkMetrics::current_timestamp(),
                last_updated: NetworkMetrics::current_timestamp(),
            });

        rollup.commits_posted += 1;
        rollup.transactions_processed += tx_count as u64;

        rollup.avg_commit_latency_ms =
            ((rollup.avg_commit_latency_ms * (rollup.commits_posted - 1)) + latency_ms)
                / rollup.commits_posted;

        rollup.last_updated = NetworkMetrics::current_timestamp();

        Ok(())
    }

    pub fn record_rollup_batch(&self, rollup_id: &str, batch_time_ms: u64) -> EgoResult<()> {
        let mut rollups = self.rollup_metrics.lock().unwrap();
        if let Some(rollup) = rollups.get_mut(rollup_id) {
            rollup.batches_built += 1;
            rollup.avg_batch_processing_time_ms = ((rollup.avg_batch_processing_time_ms
                * (rollup.batches_built - 1))
                + batch_time_ms)
                / rollup.batches_built;
        }
        Ok(())
    }

    pub fn record_rollup_da_activity(
        &self,
        rollup_id: &str,
        chunks_encoded: u64,
        chunks_served: u64,
        sample_failures: u64,
        serve_latency_ms: u64,
    ) -> EgoResult<()> {
        let mut rollups = self.rollup_metrics.lock().unwrap();
        if let Some(rollup) = rollups.get_mut(rollup_id) {
            rollup.da_chunks_encoded += chunks_encoded;
            rollup.da_chunks_served += chunks_served;
            rollup.da_sample_failures += sample_failures;
            if chunks_served > 0 {
                rollup.da_serve_latency_ms = ((rollup.da_serve_latency_ms
                    * (rollup.da_chunks_served - chunks_served))
                    + (serve_latency_ms * chunks_served))
                    / rollup.da_chunks_served;
            }
        }
        Ok(())
    }

    pub fn record_rollup_fraud_proof(&self, rollup_id: &str, valid: bool) -> EgoResult<()> {
        let mut rollups = self.rollup_metrics.lock().unwrap();
        if let Some(rollup) = rollups.get_mut(rollup_id) {
            rollup.fraud_proofs_submitted += 1;
            if valid {
                rollup.fraud_proofs_valid += 1;
            } else {
                rollup.fraud_proofs_invalid += 1;
            }
        }
        Ok(())
    }

    pub fn record_rollup_finalization(&self, rollup_id: &str, finalized: bool) -> EgoResult<()> {
        let mut rollups = self.rollup_metrics.lock().unwrap();
        if let Some(rollup) = rollups.get_mut(rollup_id) {
            if finalized {
                rollup.commits_finalized += 1;
            }
            rollup.finalize_ratio = if rollup.commits_posted > 0 {
                (rollup.commits_finalized as f64 / rollup.commits_posted as f64) * 100.0
            } else {
                0.0
            };
        }
        Ok(())
    }

    pub fn record_pq_crypto_operation(
        &self,
        operation: PQCryptoOperation,
        duration_ms: u64,
    ) -> EgoResult<()> {
        let mut pq_metrics = self.pq_crypto_metrics.lock().unwrap();

        match operation {
            PQCryptoOperation::DilithiumSign => {
                pq_metrics.avg_dilithium_sign_time_ms = if pq_metrics.total_dilithium_signatures > 0
                {
                    ((pq_metrics.avg_dilithium_sign_time_ms
                        * pq_metrics.total_dilithium_signatures)
                        + duration_ms)
                        / (pq_metrics.total_dilithium_signatures + 1)
                } else {
                    duration_ms
                };
            }
            PQCryptoOperation::DilithiumVerify => {
                pq_metrics.avg_dilithium_verify_time_ms =
                    if pq_metrics.total_dilithium_signatures > 0 {
                        ((pq_metrics.avg_dilithium_verify_time_ms
                            * pq_metrics.total_dilithium_signatures)
                            + duration_ms)
                            / (pq_metrics.total_dilithium_signatures + 1)
                    } else {
                        duration_ms
                    };
            }
            PQCryptoOperation::KyberEncapsulate => {
                pq_metrics.total_kyber_exchanges += 1;
                pq_metrics.avg_kyber_encap_time_ms = ((pq_metrics.avg_kyber_encap_time_ms
                    * (pq_metrics.total_kyber_exchanges - 1))
                    + duration_ms)
                    / pq_metrics.total_kyber_exchanges;
            }
            PQCryptoOperation::KyberDecapsulate => {
                pq_metrics.avg_kyber_decap_time_ms = ((pq_metrics.avg_kyber_decap_time_ms
                    * pq_metrics.total_kyber_exchanges)
                    + duration_ms)
                    / (pq_metrics.total_kyber_exchanges + 1);
            }
            PQCryptoOperation::HandshakePQ => {
                pq_metrics.pq_handshakes += 1;
            }
            PQCryptoOperation::HandshakeHybrid => {
                pq_metrics.hybrid_handshakes += 1;
            }
            PQCryptoOperation::BatchVerify => {
                pq_metrics.batch_verifications += 1;
                pq_metrics.avg_batch_verify_time_ms = ((pq_metrics.avg_batch_verify_time_ms
                    * (pq_metrics.batch_verifications - 1))
                    + duration_ms)
                    / pq_metrics.batch_verifications;
            }
        }

        Ok(())
    }

    pub fn start_epoch(&self, epoch: u64) -> EgoResult<()> {
        let mut epochs = self.epoch_metrics.lock().unwrap();
        epochs.insert(
            epoch,
            EpochMetrics {
                epoch,
                start_time: NetworkMetrics::current_timestamp(),
                end_time: None,
                blocks_produced: 0,
                transactions_processed: 0,
                total_ru_consumed: 0,
                validators_active: 0,
                storage_providers_active: 0,
                rewards_distributed: Balance::ZERO,
                slashing_penalties: Balance::ZERO,
                post_challenges_issued: 0,
                post_responses_received: 0,
                poc_events: 0,
                drs_updates: 0,
                cross_shard_receipts: 0,
                rollup_commits: 0,
                fraud_proofs: 0,
                epoch_finalized: false,
                deploys_submitted: 0,
                deploys_accepted: 0,
                deploys_rejected: 0,
            },
        );
        Ok(())
    }

    pub fn finalize_epoch(&self, epoch: u64) -> EgoResult<()> {
        let mut epochs = self.epoch_metrics.lock().unwrap();
        if let Some(epoch_metrics) = epochs.get_mut(&epoch) {
            epoch_metrics.end_time = Some(NetworkMetrics::current_timestamp());
            epoch_metrics.epoch_finalized = true;
        }
        Ok(())
    }

    pub fn update_epoch_deploy_stats(
        &self,
        epoch: u64,
        submitted: u64,
        accepted: u64,
        rejected: u64,
    ) -> EgoResult<()> {
        let mut epochs = self.epoch_metrics.lock().unwrap();
        if let Some(epoch_metrics) = epochs.get_mut(&epoch) {
            epoch_metrics.deploys_submitted += submitted;
            epoch_metrics.deploys_accepted += accepted;
            epoch_metrics.deploys_rejected += rejected;
        }
        Ok(())
    }

    pub fn check_and_create_alerts(&self) -> EgoResult<()> {
        let mut alerts = self.alerts.lock().unwrap();
        let network = self.network_metrics.lock().unwrap();
        let validators = self.validator_metrics.lock().unwrap();
        let providers = self.storage_provider_metrics.lock().unwrap();
        let cellular = self.cellular_metrics.lock().unwrap();
        let pq_metrics = self.pq_crypto_metrics.lock().unwrap();
        let deploy = self.deploy_metrics.lock().unwrap();

        for (addr, validator) in validators.iter() {
            if validator.uptime_percent < alerts.alert_thresholds.min_validator_uptime_percent {
                let mut metadata = HashMap::new();
                metadata.insert("validator".to_string(), format!("{}", addr));
                metadata.insert(
                    "uptime_percent".to_string(),
                    format!("{:.2}", validator.uptime_percent),
                );

                alerts.create_alert_with_metadata(
                    AlertType::ValidatorMissedBlocks,
                    AlertSeverity::Warning,
                    format!(
                        "Validator {} low uptime: {:.2}%",
                        addr, validator.uptime_percent
                    ),
                    metadata,
                );
            }

            if validator.missed_blocks > alerts.alert_thresholds.max_validator_missed_blocks {
                let mut metadata = HashMap::new();
                metadata.insert("validator".to_string(), format!("{}", addr));
                metadata.insert(
                    "missed_blocks".to_string(),
                    validator.missed_blocks.to_string(),
                );

                alerts.create_alert_with_metadata(
                    AlertType::ValidatorMissedBlocks,
                    AlertSeverity::Error,
                    format!(
                        "Validator {} missed {} blocks",
                        addr, validator.missed_blocks
                    ),
                    metadata,
                );
            }
        }

        for (addr, provider) in providers.iter() {
            if provider.health_score < alerts.alert_thresholds.min_storage_health_score {
                let mut metadata = HashMap::new();
                metadata.insert("provider".to_string(), format!("{}", addr));
                metadata.insert(
                    "health_score".to_string(),
                    provider.health_score.to_string(),
                );

                alerts.create_alert_with_metadata(
                    AlertType::StorageProviderHealthLow,
                    AlertSeverity::Warning,
                    format!(
                        "Storage provider {} health score low: {}",
                        addr, provider.health_score
                    ),
                    metadata,
                );
            }

            if provider.post_success_rate < alerts.alert_thresholds.min_post_success_rate {
                let mut metadata = HashMap::new();
                metadata.insert("provider".to_string(), format!("{}", addr));
                metadata.insert(
                    "success_rate".to_string(),
                    format!("{:.2}", provider.post_success_rate),
                );

                alerts.create_alert_with_metadata(
                    AlertType::PostProofFailure,
                    AlertSeverity::Error,
                    format!(
                        "Storage provider {} PoSt success rate low: {:.2}%",
                        addr, provider.post_success_rate
                    ),
                    metadata,
                );
            }

            if provider.consecutive_misses > alerts.alert_thresholds.max_consecutive_post_misses {
                let mut metadata = HashMap::new();
                metadata.insert("provider".to_string(), format!("{}", addr));
                metadata.insert(
                    "consecutive_misses".to_string(),
                    provider.consecutive_misses.to_string(),
                );

                alerts.create_alert_with_metadata(
                    AlertType::PostProofFailure,
                    AlertSeverity::Critical,
                    format!(
                        "Storage provider {} has {} consecutive PoSt misses",
                        addr, provider.consecutive_misses
                    ),
                    metadata,
                );
            }

            if provider.faulty_sectors > 0 {
                let mut metadata = HashMap::new();
                metadata.insert("provider".to_string(), format!("{}", addr));
                metadata.insert(
                    "faulty_sectors".to_string(),
                    provider.faulty_sectors.to_string(),
                );

                alerts.create_alert_with_metadata(
                    AlertType::SectorFaulty,
                    AlertSeverity::Warning,
                    format!(
                        "Storage provider {} has {} faulty sectors",
                        addr, provider.faulty_sectors
                    ),
                    metadata,
                );
            }
        }

        let total_cellular = cellular.total_cellular_data_gb;
        let max_monthly_gb = alerts.alert_thresholds.max_cellular_data_mb_per_month / 1024;
        if total_cellular > 0 && max_monthly_gb > 0 {
            let usage_percent = (total_cellular as f64 / max_monthly_gb as f64) * 100.0;

            if usage_percent >= alerts.alert_thresholds.cellular_data_critical_percent {
                let mut metadata = HashMap::new();
                metadata.insert("usage_gb".to_string(), total_cellular.to_string());
                metadata.insert("limit_gb".to_string(), max_monthly_gb.to_string());
                metadata.insert("usage_percent".to_string(), format!("{:.1}", usage_percent));

                alerts.create_alert_with_metadata(
                    AlertType::CellularDataLimitExceeded,
                    AlertSeverity::Critical,
                    format!(
                        "Cellular data limit exceeded: {:.1}% of {} GB",
                        usage_percent, max_monthly_gb
                    ),
                    metadata,
                );
            } else if usage_percent >= alerts.alert_thresholds.cellular_data_warning_percent {
                let mut metadata = HashMap::new();
                metadata.insert("usage_gb".to_string(), total_cellular.to_string());
                metadata.insert("limit_gb".to_string(), max_monthly_gb.to_string());
                metadata.insert("usage_percent".to_string(), format!("{:.1}", usage_percent));

                alerts.create_alert_with_metadata(
                    AlertType::CellularDataLimitApproaching,
                    AlertSeverity::Warning,
                    format!(
                        "Cellular data approaching limit: {:.1}% of {} GB",
                        usage_percent, max_monthly_gb
                    ),
                    metadata,
                );
            }
        }

        if pq_metrics.avg_dilithium_verify_time_ms
            > alerts.alert_thresholds.max_signature_verification_time_ms
        {
            let mut metadata = HashMap::new();
            metadata.insert(
                "avg_verify_time_ms".to_string(),
                pq_metrics.avg_dilithium_verify_time_ms.to_string(),
            );

            alerts.create_alert_with_metadata(
                AlertType::PQSignatureFailure,
                AlertSeverity::Warning,
                format!(
                    "PQ signature verification slow: {}ms",
                    pq_metrics.avg_dilithium_verify_time_ms
                ),
                metadata,
            );
        }

        if deploy.total_deploys > 0 {
            let rejection_rate = deploy.rejected_deploys as f64 / deploy.total_deploys as f64;
            if rejection_rate > alerts.alert_thresholds.max_deploy_rejection_rate {
                let mut metadata = HashMap::new();
                metadata.insert(
                    "rejection_rate".to_string(),
                    format!("{:.2}", rejection_rate),
                );
                metadata.insert("rejected".to_string(), deploy.rejected_deploys.to_string());
                metadata.insert("total".to_string(), deploy.total_deploys.to_string());

                alerts.create_alert_with_metadata(
                    AlertType::DeploySpamDetected,
                    AlertSeverity::Warning,
                    format!("High deploy rejection rate: {:.1}%", rejection_rate * 100.0),
                    metadata,
                );
            }
        }

        if deploy.total_deploys > 0 && deploy.ai_pattern_detected as u64 > deploy.total_deploys / 10
        {
            let mut metadata = HashMap::new();
            metadata.insert(
                "ai_detected".to_string(),
                deploy.ai_pattern_detected.to_string(),
            );
            metadata.insert("total".to_string(), deploy.total_deploys.to_string());

            alerts.create_alert_with_metadata(
                AlertType::DeployAIPatternDetected,
                AlertSeverity::Warning,
                format!(
                    "High AI pattern detection in deploys: {} out of {}",
                    deploy.ai_pattern_detected, deploy.total_deploys
                ),
                metadata,
            );
        }

        Ok(())
    }

    pub fn get_snapshot(&self) -> MetricsSnapshot {
        let network = self.network_metrics.lock().unwrap().clone();
        let shards: Vec<ShardMetrics> = self
            .shard_metrics
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        let validators: Vec<ValidatorMetrics> = self
            .validator_metrics
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        let storage_providers: Vec<StorageProviderMetrics> = self
            .storage_provider_metrics
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        let devices: Vec<DeviceMetrics> = self
            .device_metrics
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        let proofs: Vec<ProofMetrics> = self
            .proof_metrics
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        let drs_scores: Vec<DRSMetrics> =
            self.drs_metrics.lock().unwrap().values().cloned().collect();
        let rollups: Vec<RollupMetrics> = self
            .rollup_metrics
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        let pq_crypto = self.pq_crypto_metrics.lock().unwrap().clone();
        let cellular = self.cellular_metrics.lock().unwrap().clone();
        let performance = self.performance_tracker.lock().unwrap().summary();
        let deploy = self.deploy_metrics.lock().unwrap().clone();

        let current_epoch = network.epoch.as_u64();
        let epoch = self
            .epoch_metrics
            .lock()
            .unwrap()
            .get(&current_epoch)
            .cloned()
            .unwrap_or(EpochMetrics {
                epoch: current_epoch,
                start_time: NetworkMetrics::current_timestamp(),
                end_time: None,
                blocks_produced: 0,
                transactions_processed: 0,
                total_ru_consumed: 0,
                validators_active: 0,
                storage_providers_active: 0,
                rewards_distributed: Balance::ZERO,
                slashing_penalties: Balance::ZERO,
                post_challenges_issued: 0,
                post_responses_received: 0,
                poc_events: 0,
                drs_updates: 0,
                cross_shard_receipts: 0,
                rollup_commits: 0,
                fraud_proofs: 0,
                epoch_finalized: false,
                deploys_submitted: 0,
                deploys_accepted: 0,
                deploys_rejected: 0,
            });

        MetricsSnapshot {
            timestamp: NetworkMetrics::current_timestamp(),
            network,
            shards,
            validators,
            storage_providers,
            devices,
            proofs,
            drs_scores,
            rollups,
            pq_crypto,
            cellular,
            epoch,
            performance,
            deploy,
        }
    }

    pub fn get_performance_tracker(&self) -> Arc<Mutex<PerformanceTracker>> {
        Arc::clone(&self.performance_tracker)
    }

    pub fn get_alerts(&self) -> Arc<Mutex<SystemAlerts>> {
        Arc::clone(&self.alerts)
    }

    pub fn reset_metrics(&self) {
        *self.network_metrics.lock().unwrap() = NetworkMetrics::default();
        self.shard_metrics.lock().unwrap().clear();
        self.validator_metrics.lock().unwrap().clear();
        self.storage_provider_metrics.lock().unwrap().clear();
        self.device_metrics.lock().unwrap().clear();
        self.proof_metrics.lock().unwrap().clear();
        self.drs_metrics.lock().unwrap().clear();
        self.rollup_metrics.lock().unwrap().clear();
        *self.pq_crypto_metrics.lock().unwrap() = PQCryptoMetrics::default();
        *self.cellular_metrics.lock().unwrap() = CellularMetrics::default();
        self.epoch_metrics.lock().unwrap().clear();
        self.performance_tracker.lock().unwrap().reset();
        *self.deploy_metrics.lock().unwrap() = DeployMetrics::default();
    }

    pub fn export_metrics_json(&self) -> EgoResult<String> {
        let snapshot = self.get_snapshot();
        serde_json::to_string_pretty(&snapshot)
            .map_err(|e| EgoError::SerializationError(e.to_string()))
    }

    pub fn import_metrics_json(&self, json: &str) -> EgoResult<()> {
        let snapshot: MetricsSnapshot =
            serde_json::from_str(json).map_err(|e| EgoError::SerializationError(e.to_string()))?;

        *self.network_metrics.lock().unwrap() = snapshot.network;
        *self.pq_crypto_metrics.lock().unwrap() = snapshot.pq_crypto;
        *self.cellular_metrics.lock().unwrap() = snapshot.cellular;
        *self.deploy_metrics.lock().unwrap() = snapshot.deploy;

        let mut shards = self.shard_metrics.lock().unwrap();
        for shard in snapshot.shards {
            shards.insert(shard.shard_id, shard);
        }

        let mut validators = self.validator_metrics.lock().unwrap();
        for validator in snapshot.validators {
            validators.insert(validator.validator_address, validator);
        }

        let mut providers = self.storage_provider_metrics.lock().unwrap();
        for provider in snapshot.storage_providers {
            providers.insert(provider.provider_address, provider);
        }

        let mut devices = self.device_metrics.lock().unwrap();
        for device in snapshot.devices {
            devices.insert(device.device_address, device);
        }

        let mut proofs = self.proof_metrics.lock().unwrap();
        for proof in snapshot.proofs {
            proofs.insert(proof.proof_type, proof);
        }

        let mut drs_map = self.drs_metrics.lock().unwrap();
        for drs in snapshot.drs_scores {
            drs_map.insert(drs.node_address, drs);
        }

        let mut rollups = self.rollup_metrics.lock().unwrap();
        for rollup in snapshot.rollups {
            rollups.insert(rollup.rollup_id.clone(), rollup);
        }

        Ok(())
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PQCryptoOperation {
    DilithiumSign,
    DilithiumVerify,
    KyberEncapsulate,
    KyberDecapsulate,
    HandshakePQ,
    HandshakeHybrid,
    BatchVerify,
}

fn alert_type_to_string(alert_type: &AlertType) -> &str {
    match alert_type {
        AlertType::HighLatency => "high_latency",
        AlertType::DAFailure => "da_failure",
        AlertType::ChallengeSLABreach => "challenge_sla_breach",
        AlertType::HighDisputeRate => "high_dispute_rate",
        AlertType::RepeatedInvalidations => "repeated_invalidations",
        AlertType::BondNearingMinimum => "bond_nearing_minimum",
        AlertType::NetworkPartition => "network_partition",
        AlertType::OperatorOffline => "operator_offline",
        AlertType::FraudDetected => "fraud_detected",
        AlertType::SystemOverload => "system_overload",
        AlertType::CellularDataLimitApproaching => "cellular_data_limit_approaching",
        AlertType::CellularDataLimitExceeded => "cellular_data_limit_exceeded",
        AlertType::PostProofFailure => "post_proof_failure",
        AlertType::PocEventMissing => "poc_event_missing",
        AlertType::CrossShardReceiptFailure => "cross_shard_receipt_failure",
        AlertType::CompressionFailure => "compression_failure",
        AlertType::ErasureCodingFailure => "erasure_coding_failure",
        AlertType::PQSignatureFailure => "pq_signature_failure",
        AlertType::BatchVerificationFailure => "batch_verification_failure",
        AlertType::ValidatorMissedBlocks => "validator_missed_blocks",
        AlertType::StorageProviderHealthLow => "storage_provider_health_low",
        AlertType::DRSScoreLow => "drs_score_low",
        AlertType::TriadPlacementFailure => "triad_placement_failure",
        AlertType::SectorFaulty => "sector_faulty",
        AlertType::DensityPenaltyHigh => "density_penalty_high",
        AlertType::DeployQuotaExceeded => "deploy_quota_exceeded",
        AlertType::DeploySpamDetected => "deploy_spam_detected",
        AlertType::DeployAIPatternDetected => "deploy_ai_pattern_detected",
        AlertType::DeployBondSlashed => "deploy_bond_slashed",
    }
}

pub fn calculate_network_health_score(snapshot: &MetricsSnapshot) -> f64 {
    let mut score = 100.0;

    if snapshot.network.active_validators == 0 {
        score -= 20.0;
    }

    let avg_validator_uptime: f64 = if !snapshot.validators.is_empty() {
        snapshot
            .validators
            .iter()
            .map(|v| v.uptime_percent)
            .sum::<f64>()
            / snapshot.validators.len() as f64
    } else {
        0.0
    };
    if avg_validator_uptime < 95.0 {
        score -= (95.0 - avg_validator_uptime) * 0.5;
    }

    let avg_storage_health: f64 = if !snapshot.storage_providers.is_empty() {
        snapshot
            .storage_providers
            .iter()
            .map(|p| p.health_score as f64)
            .sum::<f64>()
            / snapshot.storage_providers.len() as f64
    } else {
        100000.0
    };
    if avg_storage_health < 80000.0 {
        score -= ((80000.0 - avg_storage_health) / 1000.0).min(15.0);
    }

    let avg_post_success: f64 = if !snapshot.storage_providers.is_empty() {
        snapshot
            .storage_providers
            .iter()
            .map(|p| p.post_success_rate)
            .sum::<f64>()
            / snapshot.storage_providers.len() as f64
    } else {
        100.0
    };
    if avg_post_success < 95.0 {
        score -= (95.0 - avg_post_success) * 0.3;
    }

    if snapshot.pq_crypto.pq_adoption_rate < 50.0 {
        score -= (50.0 - snapshot.pq_crypto.pq_adoption_rate) * 0.1;
    }

    if snapshot.cellular.nodes_exceeded_limit > 0 {
        score -= snapshot.cellular.nodes_exceeded_limit as f64 * 0.5;
    }

    if snapshot.deploy.total_deploys > 0 {
        let rejection_rate =
            snapshot.deploy.rejected_deploys as f64 / snapshot.deploy.total_deploys as f64;
        if rejection_rate > 0.3 {
            score -= (rejection_rate - 0.3) * 20.0;
        }
    }

    score.max(0.0).min(100.0)
}

pub fn calculate_cellular_efficiency(cellular: &CellularMetrics) -> f64 {
    if cellular.cellular_safe_transactions == 0 {
        return 100.0;
    }

    let total_txs = cellular.cellular_safe_transactions + cellular.wifi_only_transactions;
    if total_txs == 0 {
        return 100.0;
    }

    let cellular_safe_ratio = cellular.cellular_safe_transactions as f64 / total_txs as f64 * 100.0;

    let bandwidth_efficiency = if cellular.total_cellular_data_gb > 0 {
        let data_per_tx =
            cellular.total_cellular_data_gb as f64 / cellular.cellular_safe_transactions as f64;
        (1.0 / data_per_tx.max(0.001)).min(100.0)
    } else {
        100.0
    };

    (cellular_safe_ratio * 0.6 + bandwidth_efficiency * 0.4).min(100.0)
}

pub fn calculate_drs_aggregate_score(drs_metrics: &[DRSMetrics]) -> f64 {
    if drs_metrics.is_empty() {
        return 0.0;
    }

    let total_score: f64 = drs_metrics.iter().map(|d| d.current_score).sum();
    total_score / drs_metrics.len() as f64
}

pub fn calculate_deploy_health_score(deploy: &DeployMetrics) -> f64 {
    let mut score = 100.0;

    if deploy.total_deploys > 0 {
        let success_rate = deploy.successful_deploys as f64 / deploy.total_deploys as f64;
        if success_rate < 0.9 {
            score -= (0.9 - success_rate) * 50.0;
        }

        let rejection_rate = deploy.rejected_deploys as f64 / deploy.total_deploys as f64;
        if rejection_rate > 0.2 {
            score -= (rejection_rate - 0.2) * 30.0;
        }

        let ai_detection_rate = deploy.ai_pattern_detected as f64 / deploy.total_deploys as f64;
        if ai_detection_rate > 0.1 {
            score -= (ai_detection_rate - 0.1) * 40.0;
        }

        let human_verification_rate = deploy.human_verified as f64 / deploy.total_deploys as f64;
        if human_verification_rate < 0.8 {
            score -= (0.8 - human_verification_rate) * 20.0;
        }
    }

    score.max(0.0).min(100.0)
}

pub fn format_metrics_summary(snapshot: &MetricsSnapshot) -> String {
    format!(
        "Ego Blockchain Metrics Summary\n\
        ===============================\n\
        Epoch: {} | Blocks: {} | Transactions: {}\n\
        Active Validators: {} | Storage Providers: {} | Devices: {}\n\
        Total Staked: {} | PQ Adoption: {:.1}%\n\
        \n\
        Storage:\n\
        - Capacity: {} GB | Used: {} GB | Utilization: {:.1}%\n\
        - PoSt Proofs: {} | PoRep Seals: {} | PoC Events: {}\n\
        \n\
        Network:\n\
        - Shards: {} | Cross-Shard TXs: {}\n\
        - Rollup Commits: {} | Fraud Proofs: {}\n\
        - TPS Current: {:.2} | Peak: {:.2}\n\
        \n\
        Cellular:\n\
        - Nodes: {} | Data Used: {} GB | Efficiency: {:.1}%\n\
        - Safe Transactions: {} | WiFi Only: {}\n\
        \n\
        Deploy:\n\
        - Total: {} | Accepted: {} | Rejected: {}\n\
        - Free Quota: {} | Credits: {}\n\
        - AI Detected: {} | Human Verified: {}\n\
        - Spam Rejected: {} | Duplicates: {}\n\
        \n\
        Health Score: {:.1}/100 | Deploy Health: {:.1}/100\n",
        snapshot.network.epoch.as_u64(),
        snapshot.network.total_blocks,
        snapshot.network.total_transactions,
        snapshot.network.active_validators,
        snapshot.network.active_storage_providers,
        snapshot.network.active_devices,
        snapshot.network.total_staked,
        snapshot.network.pq_adoption_rate,
        snapshot.network.total_storage_capacity_gb,
        snapshot.network.total_storage_used_gb,
        snapshot.network.storage_utilization_percent(),
        snapshot.network.post_proofs_total,
        snapshot.network.porep_seals_total,
        snapshot.network.poc_events_total,
        snapshot.network.total_shards,
        snapshot.network.cross_shard_transactions,
        snapshot.network.rollup_commits,
        snapshot.network.fraud_proofs_submitted,
        snapshot.network.tps_current,
        snapshot.network.tps_peak,
        snapshot.cellular.total_cellular_nodes,
        snapshot.cellular.total_cellular_data_gb,
        calculate_cellular_efficiency(&snapshot.cellular),
        snapshot.cellular.cellular_safe_transactions,
        snapshot.cellular.wifi_only_transactions,
        snapshot.deploy.total_deploys,
        snapshot.deploy.successful_deploys,
        snapshot.deploy.rejected_deploys,
        snapshot.deploy.free_quota_deploys,
        snapshot.deploy.credits_deploys,
        snapshot.deploy.ai_pattern_detected,
        snapshot.deploy.human_verified,
        snapshot.deploy.spam_rejected,
        snapshot.deploy.duplicate_contracts_rejected,
        calculate_network_health_score(snapshot),
        calculate_deploy_health_score(&snapshot.deploy)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collector_creation() {
        let collector = MetricsCollector::new();
        let snapshot = collector.get_snapshot();
        assert_eq!(snapshot.network.total_blocks, 0);
        assert_eq!(snapshot.network.active_validators, 0);
        assert_eq!(snapshot.deploy.total_deploys, 0);
    }

    #[test]
    fn test_performance_tracker() {
        let mut tracker = PerformanceTracker::new(10);
        tracker.start_timing("test_op");
        std::thread::sleep(std::time::Duration::from_millis(10));
        tracker.end_timing("test_op");

        let avg = tracker.avg_time("test_op").unwrap();
        assert!(avg.as_millis() >= 10);
    }

    #[test]
    fn test_alert_creation() {
        let mut alerts = SystemAlerts::new();
        let id = alerts.create_alert(
            AlertType::HighLatency,
            AlertSeverity::Warning,
            "Test alert".to_string(),
        );

        assert_eq!(alerts.active_alerts.len(), 1);
        assert!(alerts.resolve_alert(&id));
        assert_eq!(alerts.active_alerts.len(), 0);
    }

    #[test]
    fn test_cellular_efficiency_calculation() {
        let mut cellular = CellularMetrics::default();
        cellular.cellular_safe_transactions = 800;
        cellular.wifi_only_transactions = 200;
        cellular.total_cellular_data_gb = 10;

        let efficiency = calculate_cellular_efficiency(&cellular);
        assert!(efficiency > 0.0 && efficiency <= 100.0);
    }

    #[test]
    fn test_network_health_score() {
        let snapshot = MetricsSnapshot {
            timestamp: NetworkMetrics::current_timestamp(),
            network: NetworkMetrics::default(),
            shards: vec![],
            validators: vec![],
            storage_providers: vec![],
            devices: vec![],
            proofs: vec![],
            drs_scores: vec![],
            rollups: vec![],
            pq_crypto: PQCryptoMetrics::default(),
            cellular: CellularMetrics::default(),
            epoch: EpochMetrics {
                epoch: 0,
                start_time: NetworkMetrics::current_timestamp(),
                end_time: None,
                blocks_produced: 0,
                transactions_processed: 0,
                total_ru_consumed: 0,
                validators_active: 0,
                storage_providers_active: 0,
                rewards_distributed: Balance::ZERO,
                slashing_penalties: Balance::ZERO,
                post_challenges_issued: 0,
                post_responses_received: 0,
                poc_events: 0,
                drs_updates: 0,
                cross_shard_receipts: 0,
                rollup_commits: 0,
                fraud_proofs: 0,
                epoch_finalized: false,
                deploys_submitted: 0,
                deploys_accepted: 0,
                deploys_rejected: 0,
            },
            performance: HashMap::new(),
            deploy: DeployMetrics::default(),
        };

        let score = calculate_network_health_score(&snapshot);
        assert!(score >= 0.0 && score <= 100.0);
    }

    #[test]
    fn test_deploy_metrics_recording() {
        let collector = MetricsCollector::new();

        collector
            .record_deploy_decision(true, true, 0, 100, 5000, None)
            .unwrap();
        collector
            .record_deploy_decision(true, false, 1000, 200, 8000, None)
            .unwrap();
        collector
            .record_deploy_decision(false, false, 0, 150, 6000, Some("spam detected"))
            .unwrap();

        let snapshot = collector.get_snapshot();
        assert_eq!(snapshot.deploy.successful_deploys, 2);
        assert_eq!(snapshot.deploy.rejected_deploys, 1);
        assert_eq!(snapshot.deploy.free_quota_deploys, 1);
        assert_eq!(snapshot.deploy.credits_deploys, 1);
        assert_eq!(snapshot.deploy.spam_rejected, 1);
    }

    #[test]
    fn test_deploy_verification_recording() {
        let collector = MetricsCollector::new();

        collector.record_deploy_verification(true, false).unwrap();
        collector.record_deploy_verification(false, true).unwrap();
        collector.record_deploy_verification(true, false).unwrap();

        let snapshot = collector.get_snapshot();
        assert_eq!(snapshot.deploy.human_verified, 2);
        assert_eq!(snapshot.deploy.ai_pattern_detected, 1);
    }

    #[test]
    fn test_deploy_bond_events() {
        let collector = MetricsCollector::new();

        let bond_amount = Balance::new(1000000);
        collector
            .record_deploy_bond_event(true, bond_amount)
            .unwrap();
        collector
            .record_deploy_bond_event(false, bond_amount)
            .unwrap();

        let snapshot = collector.get_snapshot();
        assert_eq!(snapshot.deploy.bonds_collected.as_u128(), 1000000);
        assert_eq!(snapshot.deploy.bonds_slashed.as_u128(), 1000000);
    }

    #[test]
    fn test_deploy_pob_burn() {
        let collector = MetricsCollector::new();

        collector.record_deploy_pob_burn(5000).unwrap();
        collector.record_deploy_pob_burn(3000).unwrap();

        let snapshot = collector.get_snapshot();
        assert_eq!(snapshot.deploy.total_pob_burned, 8000);
        assert_eq!(snapshot.network.pob_burns_total, 8000);
    }

    #[test]
    fn test_deploy_health_score_calculation() {
        let mut deploy = DeployMetrics::default();
        deploy.total_deploys = 100;
        deploy.successful_deploys = 95;
        deploy.rejected_deploys = 5;
        deploy.ai_pattern_detected = 2;
        deploy.human_verified = 85;

        let score = calculate_deploy_health_score(&deploy);
        assert!(score > 80.0 && score <= 100.0);
    }

    #[test]
    fn test_alert_thresholds_for_deploy() {
        let thresholds = AlertThresholds::default();
        assert_eq!(thresholds.max_deploy_spam_score, 100);
        assert_eq!(thresholds.max_deploy_rejection_rate, 0.5);
        assert_eq!(thresholds.min_deploy_human_verification_rate, 0.8);
    }

    #[test]
    fn test_epoch_deploy_stats_update() {
        let collector = MetricsCollector::new();
        collector.start_epoch(0).unwrap();

        collector.update_epoch_deploy_stats(0, 10, 8, 2).unwrap();
        collector.update_epoch_deploy_stats(0, 5, 4, 1).unwrap();

        let epochs = collector.epoch_metrics.lock().unwrap();
        let epoch = epochs.get(&0).unwrap();
        assert_eq!(epoch.deploys_submitted, 15);
        assert_eq!(epoch.deploys_accepted, 12);
        assert_eq!(epoch.deploys_rejected, 3);
    }

    #[test]
    fn test_metrics_export_import() {
        let collector = MetricsCollector::new();
        collector
            .record_deploy_decision(true, true, 0, 100, 5000, None)
            .unwrap();

        let json = collector.export_metrics_json().unwrap();
        assert!(!json.is_empty());

        let new_collector = MetricsCollector::new();
        new_collector.import_metrics_json(&json).unwrap();

        let snapshot = new_collector.get_snapshot();
        assert_eq!(snapshot.deploy.successful_deploys, 1);
    }
}
