use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollupMetrics {
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
    pub total_fees_collected: u64,
    pub operator_rewards: u64,
    pub slashing_penalties: u64,
    pub challenger_rewards: u64,
    pub peer_count: u32,
    pub message_propagation_time_ms: u64,
    pub bandwidth_usage_mb: u64,
    pub cellular_data_usage_mb: u64,
    pub wifi_data_usage_mb: u64,
    pub post_proofs_submitted: u64,
    pub post_proofs_passed: u64,
    pub post_proofs_failed: u64,
    pub porep_seals_completed: u64,
    pub poc_events_published: u64,
    pub poc_witness_reports: u64,
    pub drs_score_events: u64,
    pub cross_shard_receipts: u64,
    pub rollup_commits: u64,
    pub da_unavailability_proofs: u64,
    pub dilithium_signatures: u64,
    pub ed25519_signatures: u64,
    pub hybrid_signatures: u64,
    pub kyber_key_exchanges: u64,
    pub pq_handshakes: u64,
    pub signature_verification_time_ms: u64,
    pub batch_verification_count: u64,
    pub compression_ratio: f64,
    pub erasure_coding_overhead: f64,
    pub monthly_cellular_estimate_mb: u64,
    pub error_counts: HashMap<String, u64>,
    pub last_error_time: Option<u64>,
    pub start_time: u64,
    pub last_updated: u64,
}

#[derive(Debug)]
pub struct PerformanceTracker {
    operation_times: HashMap<String, Vec<Duration>>,
    start_times: HashMap<String, Instant>,
    max_samples: usize,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub timestamp: u64,
    pub metrics: RollupMetrics,
    pub performance_summary: HashMap<String, PerformanceSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSummary {
    pub operation: String,
    pub avg_duration_ms: u64,
    pub p50_duration_ms: u64,
    pub p95_duration_ms: u64,
    pub p99_duration_ms: u64,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub connection_type: ConnectionType,
    pub bandwidth_usage_mbps: f64,
    pub latency_ms: u64,
    pub packet_loss_percent: f64,
    pub quality_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConnectionType {
    Cellular5G,
    Cellular4G,
    WiFi,
    Ethernet,
    Unknown,
}

impl Default for RollupMetrics {
    fn default() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        Self {
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
            total_fees_collected: 0,
            operator_rewards: 0,
            slashing_penalties: 0,
            challenger_rewards: 0,
            peer_count: 0,
            message_propagation_time_ms: 0,
            bandwidth_usage_mb: 0,
            cellular_data_usage_mb: 0,
            wifi_data_usage_mb: 0,
            post_proofs_submitted: 0,
            post_proofs_passed: 0,
            post_proofs_failed: 0,
            porep_seals_completed: 0,
            poc_events_published: 0,
            poc_witness_reports: 0,
            drs_score_events: 0,
            cross_shard_receipts: 0,
            rollup_commits: 0,
            da_unavailability_proofs: 0,
            dilithium_signatures: 0,
            ed25519_signatures: 0,
            hybrid_signatures: 0,
            kyber_key_exchanges: 0,
            pq_handshakes: 0,
            signature_verification_time_ms: 0,
            batch_verification_count: 0,
            compression_ratio: 1.0,
            erasure_coding_overhead: 1.5,
            monthly_cellular_estimate_mb: 0,
            error_counts: HashMap::new(),
            last_error_time: None,
            start_time: now,
            last_updated: now,
        }
    }
}

impl RollupMetrics {
    pub fn update(&mut self) {
        self.last_updated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
    }

    pub fn record_error(&mut self, error_type: &str) {
        *self.error_counts.entry(error_type.to_string()).or_insert(0) += 1;
        self.last_error_time = Some(self.last_updated);
        self.update();
    }

    pub fn uptime_seconds(&self) -> u64 {
        (self.last_updated - self.start_time) / 1000
    }

    pub fn commit_success_rate(&self) -> f64 {
        if self.commits_posted == 0 {
            return 0.0;
        }

        let successful = self.commits_finalized;
        successful as f64 / self.commits_posted as f64
    }

    pub fn fraud_proof_accuracy(&self) -> f64 {
        let total = self.fraud_proofs_valid + self.fraud_proofs_invalid;
        if total == 0 {
            return 0.0;
        }

        self.fraud_proofs_valid as f64 / total as f64
    }

    pub fn transactions_per_second(&self) -> f64 {
        let uptime = self.uptime_seconds();
        if uptime == 0 {
            return 0.0;
        }

        self.transactions_processed as f64 / uptime as f64
    }

    pub fn avg_ru_per_transaction(&self) -> u64 {
        if self.transactions_processed == 0 {
            return 0;
        }

        self.total_ru_used / self.transactions_processed
    }

    pub fn five_g_optimization_rate(&self) -> f64 {
        if self.batches_processed == 0 {
            return 0.0;
        }

        self.five_g_batches as f64 / self.batches_processed as f64
    }

    pub fn cellular_safe_rate(&self) -> f64 {
        if self.batches_processed == 0 {
            return 0.0;
        }

        self.cellular_safe_batches as f64 / self.batches_processed as f64
    }

    pub fn post_success_rate(&self) -> f64 {
        if self.post_proofs_submitted == 0 {
            return 0.0;
        }

        self.post_proofs_passed as f64 / self.post_proofs_submitted as f64
    }

    pub fn da_availability_rate(&self) -> f64 {
        if self.da_chunks_served == 0 {
            return 100.0;
        }

        let available = self.da_chunks_served - self.da_sample_failures;
        available as f64 / self.da_chunks_served as f64 * 100.0
    }

    pub fn pq_adoption_rate(&self) -> f64 {
        let total_sigs =
            self.dilithium_signatures + self.ed25519_signatures + self.hybrid_signatures;
        if total_sigs == 0 {
            return 0.0;
        }

        (self.dilithium_signatures + self.hybrid_signatures) as f64 / total_sigs as f64 * 100.0
    }

    pub fn cellular_data_usage_percent(&self, max_monthly_mb: u64) -> f64 {
        if max_monthly_mb == 0 {
            return 0.0;
        }

        self.cellular_data_usage_mb as f64 / max_monthly_mb as f64 * 100.0
    }

    pub fn estimate_monthly_cellular_usage(&self) -> u64 {
        let uptime_days = (self.uptime_seconds() as f64 / 86400.0).max(1.0);
        let daily_usage = self.cellular_data_usage_mb as f64 / uptime_days;
        (daily_usage * 30.0) as u64
    }

    pub fn is_healthy(&self) -> bool {
        let recent_errors = self.error_counts.values().sum::<u64>();
        let error_rate = if self.transactions_processed > 0 {
            recent_errors as f64 / self.transactions_processed as f64
        } else {
            0.0
        };

        error_rate < 0.01
            && self.finalize_ratio > 0.9
            && self.da_serve_latency_ms < 500
            && self.post_success_rate() > 0.95
            && self.da_availability_rate() > 95.0
    }

    pub fn is_within_cellular_budget(&self, max_monthly_mb: u64) -> bool {
        let estimated = self.estimate_monthly_cellular_usage();
        estimated < max_monthly_mb
    }

    pub fn summary(&self) -> String {
        format!(
            "Rollup Metrics Summary:\n\
            - Uptime: {}s\n\
            - Batches: {} built, {} processed\n\
            - Commits: {} posted, {} finalized ({:.1}% success)\n\
            - Transactions: {} processed ({:.2} TPS)\n\
            - Resource Units: {} total ({} avg per tx)\n\
            - 5G Optimization: {:.1}%\n\
            - Cellular Safe: {:.1}%\n\
            - PoSt Success: {:.1}%\n\
            - DA Availability: {:.1}%\n\
            - PQ Adoption: {:.1}%\n\
            - Cellular Data: {} MB ({} MB/month est.)\n\
            - Health Status: {}",
            self.uptime_seconds(),
            self.batches_built,
            self.batches_processed,
            self.commits_posted,
            self.commits_finalized,
            self.commit_success_rate() * 100.0,
            self.transactions_processed,
            self.transactions_per_second(),
            self.total_ru_used,
            self.avg_ru_per_transaction(),
            self.five_g_optimization_rate() * 100.0,
            self.cellular_safe_rate() * 100.0,
            self.post_success_rate() * 100.0,
            self.da_availability_rate(),
            self.pq_adoption_rate(),
            self.cellular_data_usage_mb,
            self.estimate_monthly_cellular_usage(),
            if self.is_healthy() {
                "Healthy"
            } else {
                "Unhealthy"
            }
        )
    }

    pub fn record_batch_processed(
        &mut self,
        processing_time_ms: u64,
        is_cellular_safe: bool,
        is_5g: bool,
    ) {
        self.batches_processed += 1;

        if is_cellular_safe {
            self.cellular_safe_batches += 1;
        }

        if is_5g {
            self.five_g_batches += 1;
        } else {
            self.wifi_batches += 1;
        }

        self.avg_batch_processing_time_ms =
            (self.avg_batch_processing_time_ms * (self.batches_processed - 1) + processing_time_ms)
                / self.batches_processed;

        self.update();
    }

    pub fn record_commit(&mut self, latency_ms: u64) {
        self.commits_posted += 1;
        self.rollup_commits += 1;

        self.avg_commit_latency_ms = (self.avg_commit_latency_ms * (self.commits_posted - 1)
            + latency_ms)
            / self.commits_posted;

        self.update();
    }

    pub fn record_commit_finalized(&mut self) {
        self.commits_finalized += 1;

        if self.commits_posted > 0 {
            self.finalize_ratio = self.commits_finalized as f64 / self.commits_posted as f64;
        }

        self.update();
    }

    pub fn record_da_chunk_served(&mut self, latency_ms: u64, success: bool) {
        self.da_chunks_served += 1;

        if !success {
            self.da_sample_failures += 1;
        }

        self.da_serve_latency_ms = (self.da_serve_latency_ms * (self.da_chunks_served - 1)
            + latency_ms)
            / self.da_chunks_served;

        self.update();
    }

    pub fn record_post_proof(&mut self, success: bool) {
        self.post_proofs_submitted += 1;

        if success {
            self.post_proofs_passed += 1;
        } else {
            self.post_proofs_failed += 1;
        }

        self.update();
    }

    pub fn record_signature(
        &mut self,
        is_dilithium: bool,
        is_ed25519: bool,
        verification_time_ms: u64,
    ) {
        if is_dilithium && is_ed25519 {
            self.hybrid_signatures += 1;
        } else if is_dilithium {
            self.dilithium_signatures += 1;
        } else if is_ed25519 {
            self.ed25519_signatures += 1;
        }

        let total_verifications =
            self.dilithium_signatures + self.ed25519_signatures + self.hybrid_signatures;
        self.signature_verification_time_ms = (self.signature_verification_time_ms
            * (total_verifications - 1)
            + verification_time_ms)
            / total_verifications;

        self.update();
    }

    pub fn record_data_usage(&mut self, bytes: u64, is_cellular: bool) {
        let mb = bytes / (1024 * 1024);

        self.bandwidth_usage_mb += mb;

        if is_cellular {
            self.cellular_data_usage_mb += mb;
        } else {
            self.wifi_data_usage_mb += mb;
        }

        self.monthly_cellular_estimate_mb = self.estimate_monthly_cellular_usage();

        self.update();
    }

    pub fn record_compression(&mut self, original_size: usize, compressed_size: usize) {
        let ratio = compressed_size as f64 / original_size as f64;

        let count = self.da_chunks_encoded + 1;
        self.compression_ratio =
            (self.compression_ratio * self.da_chunks_encoded as f64 + ratio) / count as f64;

        self.update();
    }

    pub fn record_erasure_coding(&mut self, data_size: usize, encoded_size: usize) {
        let overhead = encoded_size as f64 / data_size as f64;

        let count = self.da_chunks_encoded + 1;
        self.erasure_coding_overhead =
            (self.erasure_coding_overhead * self.da_chunks_encoded as f64 + overhead)
                / count as f64;

        self.da_chunks_encoded += 1;

        self.update();
    }
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

    pub fn median_time(&self, operation: &str) -> Option<Duration> {
        self.percentile_time(operation, 50.0)
    }

    pub fn summary(&self) -> HashMap<String, PerformanceSummary> {
        let mut summary = HashMap::new();

        for operation in self.operation_times.keys() {
            if let (Some(avg), Some(p50), Some(p95), Some(p99)) = (
                self.avg_time(operation),
                self.percentile_time(operation, 50.0),
                self.percentile_time(operation, 95.0),
                self.percentile_time(operation, 99.0),
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
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

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
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

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

    pub fn check_metrics(&mut self, metrics: &RollupMetrics) {
        if metrics.avg_batch_processing_time_ms > self.alert_thresholds.max_batch_processing_time_ms
        {
            let mut metadata = HashMap::new();
            metadata.insert(
                "actual_time_ms".to_string(),
                metrics.avg_batch_processing_time_ms.to_string(),
            );
            metadata.insert(
                "threshold_ms".to_string(),
                self.alert_thresholds
                    .max_batch_processing_time_ms
                    .to_string(),
            );

            self.create_alert_with_metadata(
                AlertType::HighLatency,
                AlertSeverity::Warning,
                format!(
                    "High batch processing time: {}ms > {}ms",
                    metrics.avg_batch_processing_time_ms,
                    self.alert_thresholds.max_batch_processing_time_ms
                ),
                metadata,
            );
        }

        if metrics.da_serve_latency_ms > self.alert_thresholds.max_da_serve_time_ms {
            let mut metadata = HashMap::new();
            metadata.insert(
                "actual_latency_ms".to_string(),
                metrics.da_serve_latency_ms.to_string(),
            );
            metadata.insert(
                "threshold_ms".to_string(),
                self.alert_thresholds.max_da_serve_time_ms.to_string(),
            );

            self.create_alert_with_metadata(
                AlertType::DAFailure,
                AlertSeverity::Error,
                format!(
                    "High DA serve latency: {}ms > {}ms",
                    metrics.da_serve_latency_ms, self.alert_thresholds.max_da_serve_time_ms
                ),
                metadata,
            );
        }

        let da_availability = metrics.da_availability_rate();
        if da_availability < self.alert_thresholds.min_da_availability_percent {
            let mut metadata = HashMap::new();
            metadata.insert(
                "availability_percent".to_string(),
                format!("{:.1}", da_availability),
            );
            metadata.insert(
                "threshold_percent".to_string(),
                format!("{:.1}", self.alert_thresholds.min_da_availability_percent),
            );

            self.create_alert_with_metadata(
                AlertType::DAFailure,
                AlertSeverity::Critical,
                format!(
                    "Low DA availability: {:.1}% < {:.1}%",
                    da_availability, self.alert_thresholds.min_da_availability_percent
                ),
                metadata,
            );
        }

        let dispute_rate = if metrics.commits_posted > 0 {
            metrics.commits_challenged as f64 / metrics.commits_posted as f64 * 100.0
        } else {
            0.0
        };

        if dispute_rate > self.alert_thresholds.max_dispute_rate_percent {
            let mut metadata = HashMap::new();
            metadata.insert("dispute_rate".to_string(), format!("{:.1}", dispute_rate));
            metadata.insert(
                "threshold".to_string(),
                format!("{:.1}", self.alert_thresholds.max_dispute_rate_percent),
            );

            self.create_alert_with_metadata(
                AlertType::HighDisputeRate,
                AlertSeverity::Warning,
                format!(
                    "High dispute rate: {:.1}% > {:.1}%",
                    dispute_rate, self.alert_thresholds.max_dispute_rate_percent
                ),
                metadata,
            );
        }

        if metrics.commits_slashed > 5 {
            let mut metadata = HashMap::new();
            metadata.insert(
                "slashed_count".to_string(),
                metrics.commits_slashed.to_string(),
            );

            self.create_alert_with_metadata(
                AlertType::RepeatedInvalidations,
                AlertSeverity::Error,
                format!(
                    "Repeated invalidations detected: {} slashed commits",
                    metrics.commits_slashed
                ),
                metadata,
            );
        }

        let cellular_usage_percent = metrics
            .cellular_data_usage_percent(self.alert_thresholds.max_cellular_data_mb_per_month);
        if cellular_usage_percent >= self.alert_thresholds.cellular_data_critical_percent {
            let mut metadata = HashMap::new();
            metadata.insert(
                "usage_percent".to_string(),
                format!("{:.1}", cellular_usage_percent),
            );
            metadata.insert(
                "usage_mb".to_string(),
                metrics.cellular_data_usage_mb.to_string(),
            );
            metadata.insert(
                "limit_mb".to_string(),
                self.alert_thresholds
                    .max_cellular_data_mb_per_month
                    .to_string(),
            );

            self.create_alert_with_metadata(
                AlertType::CellularDataLimitExceeded,
                AlertSeverity::Critical,
                format!(
                    "Cellular data limit exceeded: {:.1}% of {} MB",
                    cellular_usage_percent, self.alert_thresholds.max_cellular_data_mb_per_month
                ),
                metadata,
            );
        } else if cellular_usage_percent >= self.alert_thresholds.cellular_data_warning_percent {
            let mut metadata = HashMap::new();
            metadata.insert(
                "usage_percent".to_string(),
                format!("{:.1}", cellular_usage_percent),
            );
            metadata.insert(
                "usage_mb".to_string(),
                metrics.cellular_data_usage_mb.to_string(),
            );
            metadata.insert(
                "limit_mb".to_string(),
                self.alert_thresholds
                    .max_cellular_data_mb_per_month
                    .to_string(),
            );

            self.create_alert_with_metadata(
                AlertType::CellularDataLimitApproaching,
                AlertSeverity::Warning,
                format!(
                    "Cellular data approaching limit: {:.1}% of {} MB",
                    cellular_usage_percent, self.alert_thresholds.max_cellular_data_mb_per_month
                ),
                metadata,
            );
        }

        let post_success_rate = metrics.post_success_rate();
        if post_success_rate < self.alert_thresholds.min_post_success_rate {
            let mut metadata = HashMap::new();
            metadata.insert(
                "success_rate".to_string(),
                format!("{:.1}", post_success_rate),
            );
            metadata.insert(
                "threshold".to_string(),
                format!("{:.1}", self.alert_thresholds.min_post_success_rate),
            );

            self.create_alert_with_metadata(
                AlertType::PostProofFailure,
                AlertSeverity::Error,
                format!(
                    "Low PoSt success rate: {:.1}% < {:.1}%",
                    post_success_rate * 100.0,
                    self.alert_thresholds.min_post_success_rate * 100.0
                ),
                metadata,
            );
        }

        if metrics.signature_verification_time_ms
            > self.alert_thresholds.max_signature_verification_time_ms
        {
            let mut metadata = HashMap::new();
            metadata.insert(
                "verification_time_ms".to_string(),
                metrics.signature_verification_time_ms.to_string(),
            );
            metadata.insert(
                "threshold_ms".to_string(),
                self.alert_thresholds
                    .max_signature_verification_time_ms
                    .to_string(),
            );

            self.create_alert_with_metadata(
                AlertType::PQSignatureFailure,
                AlertSeverity::Warning,
                format!(
                    "High signature verification time: {}ms > {}ms",
                    metrics.signature_verification_time_ms,
                    self.alert_thresholds.max_signature_verification_time_ms
                ),
                metadata,
            );
        }
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
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let cutoff = current_time - (retention_hours * 3_600_000);

        let before_count = self.alert_history.len();

        self.alert_history
            .retain(|alert| alert.timestamp >= cutoff || !alert.resolved);

        before_count - self.alert_history.len()
    }
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
        }
    }
}

impl Default for SystemAlerts {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsSnapshot {
    pub fn capture(metrics: &RollupMetrics, performance_tracker: &PerformanceTracker) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        Self {
            timestamp,
            metrics: metrics.clone(),
            performance_summary: performance_tracker.summary(),
        }
    }
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_rollup_metrics_default() {
        let metrics = RollupMetrics::default();
        assert_eq!(metrics.batches_built, 0);
        assert_eq!(metrics.transactions_processed, 0);
        assert!(metrics.uptime_seconds() >= 0);
    }

    #[test]
    fn test_metrics_calculations() {
        let mut metrics = RollupMetrics::default();
        metrics.commits_posted = 100;
        metrics.commits_finalized = 95;
        metrics.transactions_processed = 1000;
        metrics.total_ru_used = 21_000_000;

        assert_eq!(metrics.commit_success_rate(), 0.95);
        assert_eq!(metrics.avg_ru_per_transaction(), 21_000);
    }

    #[test]
    fn test_performance_tracker() {
        let mut tracker = PerformanceTracker::new(10);

        tracker.start_timing("test_operation");
        thread::sleep(Duration::from_millis(10));
        tracker.end_timing("test_operation");

        let avg_time = tracker.avg_time("test_operation").unwrap();
        assert!(avg_time >= Duration::from_millis(10));
    }

    #[test]
    fn test_system_alerts() {
        let mut alerts = SystemAlerts::new();

        let alert_id = alerts.create_alert(
            AlertType::HighLatency,
            AlertSeverity::Warning,
            "Test alert".to_string(),
        );

        assert_eq!(alerts.active_alerts.len(), 1);
        assert_eq!(alerts.alert_history.len(), 1);

        assert!(alerts.resolve_alert(&alert_id));
        assert_eq!(alerts.active_alerts.len(), 0);
        assert!(alerts.alert_history[0].resolved);
    }

    #[test]
    fn test_metrics_health_check() {
        let mut metrics = RollupMetrics::default();

        metrics.finalize_ratio = 0.95;
        metrics.da_serve_latency_ms = 200;
        metrics.post_proofs_submitted = 100;
        metrics.post_proofs_passed = 96;
        metrics.da_chunks_served = 100;
        metrics.da_sample_failures = 2;

        assert!(metrics.is_healthy());

        metrics.finalize_ratio = 0.5;
        assert!(!metrics.is_healthy());
    }

    #[test]
    fn test_cellular_data_tracking() {
        let mut metrics = RollupMetrics::default();

        metrics.record_data_usage(100 * 1024 * 1024, true);
        assert_eq!(metrics.cellular_data_usage_mb, 100);

        metrics.record_data_usage(50 * 1024 * 1024, false);
        assert_eq!(metrics.wifi_data_usage_mb, 50);
        assert_eq!(metrics.bandwidth_usage_mb, 150);
    }

    #[test]
    fn test_post_metrics() {
        let mut metrics = RollupMetrics::default();

        metrics.record_post_proof(true);
        metrics.record_post_proof(true);
        metrics.record_post_proof(false);

        assert_eq!(metrics.post_proofs_submitted, 3);
        assert_eq!(metrics.post_proofs_passed, 2);
        assert_eq!(metrics.post_proofs_failed, 1);
        assert!((metrics.post_success_rate() - 0.666).abs() < 0.01);
    }

    #[test]
    fn test_pq_signature_tracking() {
        let mut metrics = RollupMetrics::default();

        metrics.record_signature(true, false, 50);
        metrics.record_signature(true, true, 75);
        metrics.record_signature(false, true, 25);

        assert_eq!(metrics.dilithium_signatures, 1);
        assert_eq!(metrics.hybrid_signatures, 1);
        assert_eq!(metrics.ed25519_signatures, 1);
        assert_eq!(metrics.pq_adoption_rate(), 66.66666666666667);
    }

    #[test]
    fn test_cellular_budget() {
        let mut metrics = RollupMetrics::default();
        metrics.cellular_data_usage_mb = 3000;

        assert!(metrics.is_within_cellular_budget(5000));
        assert!(!metrics.is_within_cellular_budget(2500));
    }

    #[test]
    fn test_alert_thresholds() {
        let mut alerts = SystemAlerts::new();
        let mut metrics = RollupMetrics::default();

        metrics.avg_batch_processing_time_ms = 6000;
        alerts.check_metrics(&metrics);

        assert_eq!(alerts.active_alerts.len(), 1);
        assert_eq!(alerts.active_alerts[0].alert_type, AlertType::HighLatency);
    }
}
