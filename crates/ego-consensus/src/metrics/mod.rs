use crate::error::PoCResult;
use ego_core::{Address, Hash, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderMetrics {
    pub node_addr: Address,
    pub sealing_queue_len: u32,
    pub pc1_duration_ms: u64,
    pub pc2_duration_ms: u64,
    pub c1_duration_ms: u64,
    pub c2_duration_ms: u64,
    pub sectors_active: u32,
    pub windows_proven: u64,
    pub post_latency_ms_p50: u64,
    pub post_latency_ms_p95: u64,
    pub miss_counts: u32,
    pub repair_time_hours: f64,
    pub last_updated: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollupMetrics {
    pub proofs_in: u64,
    pub verified_ok: u64,
    pub verified_failed: u64,
    pub agg_build_time_ms: u64,
    pub chain_post_latency_ms: u64,
    pub disputes_in: u32,
    pub disputes_success: u32,
    pub last_updated: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemAlerts {
    pub consecutive_miss_threshold: u32,
    pub anchor_upload_deadline: Timestamp,
    pub gpu_failover_active: bool,
    pub nvme_health_critical: bool,
    pub network_partition_detected: bool,
    pub last_updated: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRootDay {
    pub date: String,
    pub evidence_root: Hash,
    pub bundle_count: u64,
    pub total_proofs: u64,
    pub anchor_cid: Hash,
    pub published_at: Timestamp,
    pub verification_status: VerificationStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationStatus {
    Pending,
    Verified,
    Failed,
    Disputed,
}

pub struct MetricsCollector {
    collector_id: Address,
    provider_metrics: HashMap<Address, ProviderMetrics>,
    rollup_metrics: RollupMetrics,
    system_alerts: SystemAlerts,
    evidence_roots: HashMap<String, EvidenceRootDay>,
}

impl MetricsCollector {
    pub fn new(collector_id: Address) -> Self {
        Self {
            collector_id,
            provider_metrics: HashMap::new(),
            rollup_metrics: RollupMetrics::default(),
            system_alerts: SystemAlerts::default(),
            evidence_roots: HashMap::new(),
        }
    }

    pub async fn start(&mut self) -> PoCResult<()> {
        info!("Starting metrics collector {}", self.collector_id);

        self.start_metrics_aggregation().await?;
        self.start_alert_monitoring().await?;

        info!(
            "✅ Metrics collector {} started successfully",
            self.collector_id
        );
        Ok(())
    }

    pub async fn update_provider_metrics(&mut self, metrics: ProviderMetrics) {
        self.provider_metrics.insert(metrics.node_addr, metrics);
    }

    pub fn get_provider_metrics(&self, node_addr: Address) -> Option<&ProviderMetrics> {
        self.provider_metrics.get(&node_addr)
    }

    pub fn get_rollup_metrics(&self) -> &RollupMetrics {
        &self.rollup_metrics
    }

    pub fn get_system_alerts(&self) -> &SystemAlerts {
        &self.system_alerts
    }

    pub async fn publish_daily_evidence_root(
        &mut self,
        date: String,
        evidence_root: Hash,
        bundle_count: u64,
        total_proofs: u64,
    ) -> PoCResult<Hash> {
        let anchor_cid = self.compute_anchor_cid(&evidence_root, bundle_count);

        let evidence_day = EvidenceRootDay {
            date: date.clone(),
            evidence_root,
            bundle_count,
            total_proofs,
            anchor_cid,
            published_at: Timestamp::now(),
            verification_status: VerificationStatus::Pending,
        };

        self.evidence_roots.insert(date, evidence_day);

        info!(
            "✅ Published daily evidence root: {} with {} bundles (collector {})",
            evidence_root, bundle_count, self.collector_id
        );

        Ok(anchor_cid)
    }

    async fn start_metrics_aggregation(&mut self) -> PoCResult<()> {
        let collector_id = self.collector_id;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));

            loop {
                interval.tick().await;
                debug!("Aggregating metrics (collector {})", collector_id);
            }
        });

        Ok(())
    }

    async fn start_alert_monitoring(&mut self) -> PoCResult<()> {
        let collector_id = self.collector_id;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));

            loop {
                interval.tick().await;
                debug!("Monitoring system alerts (collector {})", collector_id);
            }
        });

        Ok(())
    }

    fn compute_anchor_cid(&self, evidence_root: &Hash, bundle_count: u64) -> Hash {
        use ego_core::crypto::hash_multiple;

        hash_multiple(&[
            evidence_root.as_bytes(),
            &bundle_count.to_le_bytes(),
            &Timestamp::now().as_millis().to_le_bytes(),
        ])
    }

    pub fn generate_audit_report(&self) -> AuditReport {
        let total_providers = self.provider_metrics.len() as u32;
        let avg_sealing_time = if total_providers > 0 {
            self.provider_metrics
                .values()
                .map(|m| {
                    m.pc1_duration_ms + m.pc2_duration_ms + m.c1_duration_ms + m.c2_duration_ms
                })
                .sum::<u64>()
                / total_providers as u64
        } else {
            0
        };

        let total_active_sectors = self
            .provider_metrics
            .values()
            .map(|m| m.sectors_active)
            .sum();

        AuditReport {
            audit_id: Hash::new([1u8; 32]),
            total_providers,
            total_active_sectors,
            avg_sealing_time_ms: avg_sealing_time,
            evidence_roots_published: self.evidence_roots.len() as u64,
            total_proofs_verified: self.rollup_metrics.verified_ok,
            audit_timestamp: Timestamp::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub audit_id: Hash,
    pub total_providers: u32,
    pub total_active_sectors: u32,
    pub avg_sealing_time_ms: u64,
    pub evidence_roots_published: u64,
    pub total_proofs_verified: u64,
    pub audit_timestamp: Timestamp,
}

impl Default for ProviderMetrics {
    fn default() -> Self {
        Self {
            node_addr: Address::new([0u8; 20]),
            sealing_queue_len: 0,
            pc1_duration_ms: 0,
            pc2_duration_ms: 0,
            c1_duration_ms: 0,
            c2_duration_ms: 0,
            sectors_active: 0,
            windows_proven: 0,
            post_latency_ms_p50: 0,
            post_latency_ms_p95: 0,
            miss_counts: 0,
            repair_time_hours: 0.0,
            last_updated: Timestamp::now(),
        }
    }
}

impl Default for RollupMetrics {
    fn default() -> Self {
        Self {
            proofs_in: 0,
            verified_ok: 0,
            verified_failed: 0,
            agg_build_time_ms: 0,
            chain_post_latency_ms: 0,
            disputes_in: 0,
            disputes_success: 0,
            last_updated: Timestamp::now(),
        }
    }
}

impl Default for SystemAlerts {
    fn default() -> Self {
        Self {
            consecutive_miss_threshold: 3,
            anchor_upload_deadline: Timestamp::from_millis(
                Timestamp::now().as_millis() + 86_400_000,
            ),
            gpu_failover_active: false,
            nvme_health_critical: false,
            network_partition_detected: false,
            last_updated: Timestamp::now(),
        }
    }
}

impl PartialEq for VerificationStatus {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (VerificationStatus::Pending, VerificationStatus::Pending) => true,
            (VerificationStatus::Verified, VerificationStatus::Verified) => true,
            (VerificationStatus::Failed, VerificationStatus::Failed) => true,
            (VerificationStatus::Disputed, VerificationStatus::Disputed) => true,
            _ => false,
        }
    }
}

impl Eq for VerificationStatus {}

use tracing::{debug, info};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collector_creation() {
        let collector = MetricsCollector::new(Address::new([1u8; 20]));
        assert_eq!(collector.collector_id, Address::new([1u8; 20]));
        assert_eq!(collector.provider_metrics.len(), 0);
    }

    #[tokio::test]
    async fn test_evidence_root_publishing() {
        let mut collector = MetricsCollector::new(Address::new([1u8; 20]));

        let evidence_root = Hash::new([1u8; 32]);
        let anchor_cid = collector
            .publish_daily_evidence_root("2025-01-01".to_string(), evidence_root, 100, 1000)
            .await
            .unwrap();

        assert!(!anchor_cid.as_bytes().iter().all(|&b| b == 0));
        assert_eq!(collector.evidence_roots.len(), 1);
    }

    #[test]
    fn test_audit_report_generation() {
        let mut collector = MetricsCollector::new(Address::new([1u8; 20]));

        let provider_metrics = ProviderMetrics {
            node_addr: Address::new([2u8; 20]),
            sealing_queue_len: 5,
            sectors_active: 100,
            windows_proven: 50,
            ..Default::default()
        };

        collector
            .provider_metrics
            .insert(Address::new([2u8; 20]), provider_metrics);

        let audit_report = collector.generate_audit_report();
        assert_eq!(audit_report.total_providers, 1);
        assert_eq!(audit_report.total_active_sectors, 100);
    }
}
