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
    pub total_gas_used: u64,

    pub avg_batch_processing_time: u64,
    pub avg_commit_latency: u64,
    pub finalize_ratio: f64,

    pub da_chunks_served: u64,
    pub da_sample_failures: u64,
    pub da_serve_latency_ms: u64,

    pub fraud_proofs_submitted: u64,
    pub fraud_proofs_valid: u64,
    pub fraud_proofs_invalid: u64,
    pub challenge_responses: u64,

    pub five_g_batches: u64,
    pub edge_processing_time: u64,
    pub network_switches: u64,
    pub latency_target_breaches: u64,

    pub total_fees_collected: u64,
    pub operator_rewards: u64,
    pub slashing_penalties: u64,
    pub challenger_rewards: u64,

    pub peer_count: u32,
    pub message_propagation_time: u64,
    pub bandwidth_usage_mb: u64,

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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
            total_gas_used: 0,
            avg_batch_processing_time: 0,
            avg_commit_latency: 0,
            finalize_ratio: 0.0,
            da_chunks_served: 0,
            da_sample_failures: 0,
            da_serve_latency_ms: 0,
            fraud_proofs_submitted: 0,
            fraud_proofs_valid: 0,
            fraud_proofs_invalid: 0,
            challenge_responses: 0,
            five_g_batches: 0,
            edge_processing_time: 0,
            network_switches: 0,
            latency_target_breaches: 0,
            total_fees_collected: 0,
            operator_rewards: 0,
            slashing_penalties: 0,
            challenger_rewards: 0,
            peer_count: 0,
            message_propagation_time: 0,
            bandwidth_usage_mb: 0,
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

    pub fn avg_gas_per_transaction(&self) -> u64 {
        if self.transactions_processed == 0 {
            return 0;
        }

        self.total_gas_used / self.transactions_processed
    }

    pub fn five_g_optimization_rate(&self) -> f64 {
        if self.batches_processed == 0 {
            return 0.0;
        }

        self.five_g_batches as f64 / self.batches_processed as f64
    }

    pub fn is_healthy(&self) -> bool {
        let recent_errors = self.error_counts.values().sum::<u64>();
        let error_rate = if self.transactions_processed > 0 {
            recent_errors as f64 / self.transactions_processed as f64
        } else {
            0.0
        };

        error_rate < 0.01 && self.finalize_ratio > 0.9 && self.da_serve_latency_ms < 500
    }

    pub fn summary(&self) -> String {
        format!(
            "Rollup Metrics Summary:\n\
            - Uptime: {}s\n\
            - Batches: {} built, {} processed\n\
            - Commits: {} posted, {} finalized ({}% success)\n\
            - Transactions: {} processed ({:.2} TPS)\n\
            - 5G Optimization: {:.1}%\n\
            - Health Status: {}",
            self.uptime_seconds(),
            self.batches_built,
            self.batches_processed,
            self.commits_posted,
            self.commits_finalized,
            self.commit_success_rate() * 100.0,
            self.transactions_processed,
            self.transactions_per_second(),
            self.five_g_optimization_rate() * 100.0,
            if self.is_healthy() {
                "Healthy"
            } else {
                "Unhealthy"
            }
        )
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

    pub fn summary(&self) -> HashMap<String, (Duration, Duration, Duration)> {
        let mut summary = HashMap::new();

        for operation in self.operation_times.keys() {
            if let (Some(avg), Some(p95), Some(p99)) = (
                self.avg_time(operation),
                self.percentile_time(operation, 95.0),
                self.percentile_time(operation, 99.0),
            ) {
                summary.insert(operation.clone(), (avg, p95, p99));
            }
        }

        summary
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

    pub fn create_alert(
        &mut self,
        alert_type: AlertType,
        severity: AlertSeverity,
        message: String,
    ) -> String {
        let alert_id = format!("alert_{}", self.alert_history.len());
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
        if metrics.avg_batch_processing_time > self.alert_thresholds.max_batch_processing_time_ms {
            self.create_alert(
                AlertType::HighLatency,
                AlertSeverity::Warning,
                format!(
                    "High batch processing time: {}ms > {}ms",
                    metrics.avg_batch_processing_time,
                    self.alert_thresholds.max_batch_processing_time_ms
                ),
            );
        }

        if metrics.da_serve_latency_ms > self.alert_thresholds.max_da_serve_time_ms {
            self.create_alert(
                AlertType::DAFailure,
                AlertSeverity::Error,
                format!(
                    "High DA serve latency: {}ms > {}ms",
                    metrics.da_serve_latency_ms, self.alert_thresholds.max_da_serve_time_ms
                ),
            );
        }

        let da_availability = if metrics.da_chunks_served > 0 {
            (metrics.da_chunks_served - metrics.da_sample_failures) as f64
                / metrics.da_chunks_served as f64
                * 100.0
        } else {
            100.0
        };

        if da_availability < self.alert_thresholds.min_da_availability_percent {
            self.create_alert(
                AlertType::DAFailure,
                AlertSeverity::Critical,
                format!(
                    "Low DA availability: {:.1}% < {:.1}%",
                    da_availability, self.alert_thresholds.min_da_availability_percent
                ),
            );
        }

        let dispute_rate = if metrics.commits_posted > 0 {
            metrics.commits_challenged as f64 / metrics.commits_posted as f64 * 100.0
        } else {
            0.0
        };

        if dispute_rate > self.alert_thresholds.max_dispute_rate_percent {
            self.create_alert(
                AlertType::HighDisputeRate,
                AlertSeverity::Warning,
                format!(
                    "High dispute rate: {:.1}% > {:.1}%",
                    dispute_rate, self.alert_thresholds.max_dispute_rate_percent
                ),
            );
        }

        if metrics.commits_slashed > 5 {
            self.create_alert(
                AlertType::RepeatedInvalidations,
                AlertSeverity::Error,
                format!(
                    "Repeated invalidations detected: {} slashed commits",
                    metrics.commits_slashed
                ),
            );
        }
    }

    pub fn get_alerts_by_severity(&self, severity: AlertSeverity) -> Vec<&Alert> {
        self.active_alerts
            .iter()
            .filter(|a| a.severity == severity)
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
}

#[derive(Debug, Default)]
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
        }
    }
}

impl Default for SystemAlerts {
    fn default() -> Self {
        Self::new()
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
        metrics.total_gas_used = 21_000_000;

        assert_eq!(metrics.commit_success_rate(), 0.95);
        assert_eq!(metrics.avg_gas_per_transaction(), 21_000);
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
    fn test_alert_thresholds() {
        let mut alerts = SystemAlerts::new();
        let mut metrics = RollupMetrics::default();

        metrics.avg_batch_processing_time = 10000;

        alerts.check_metrics(&metrics);

        let high_latency_alerts = alerts.get_alerts_by_severity(AlertSeverity::Warning);
        assert!(!high_latency_alerts.is_empty());
    }

    #[test]
    fn test_metrics_health_check() {
        let mut metrics = RollupMetrics::default();

        metrics.finalize_ratio = 0.95;
        metrics.da_serve_latency_ms = 200;
        assert!(metrics.is_healthy());

        metrics.finalize_ratio = 0.5;
        assert!(!metrics.is_healthy());
    }

    #[test]
    fn test_error_recording() {
        let mut metrics = RollupMetrics::default();

        metrics.record_error("network_timeout");
        metrics.record_error("network_timeout");
        metrics.record_error("invalid_signature");

        assert_eq!(metrics.error_counts["network_timeout"], 2);
        assert_eq!(metrics.error_counts["invalid_signature"], 1);
        assert!(metrics.last_error_time.is_some());
    }

    #[test]
    fn test_alert_stats() {
        let mut alerts = SystemAlerts::new();

        alerts.create_alert(
            AlertType::HighLatency,
            AlertSeverity::Warning,
            "Test 1".to_string(),
        );
        alerts.create_alert(
            AlertType::DAFailure,
            AlertSeverity::Critical,
            "Test 2".to_string(),
        );

        let stats = alerts.get_alert_stats();
        assert_eq!(stats.total_alerts, 2);
        assert_eq!(stats.active_alerts, 2);
        assert_eq!(stats.warning_alerts, 1);
        assert_eq!(stats.critical_alerts, 1);
    }
}
