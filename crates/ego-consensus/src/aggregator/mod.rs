pub mod bundle;
pub mod node;

pub use bundle::{PoCBundle, PoCEvent};
pub use node::AggregatorNode;

use crate::beacon::BeaconAnnouncement;
use crate::error::PoCResult;
use crate::types::*;
use crate::witness::WitnessReport;
use ego_core::{Address, Hash, Timestamp};
use serde::{Deserialize, Serialize};
use std::future::Future;

pub trait Aggregator: Send + Sync {
    fn aggregator_id(&self) -> Address;
    fn is_active(&self) -> bool;
    fn coverage_region(&self) -> Vec<String>;

    fn process_beacon_announcement(
        &mut self,
        announcement: BeaconAnnouncement,
    ) -> impl Future<Output = PoCResult<()>> + Send;

    fn process_witness_report(
        &mut self,
        report: WitnessReport,
    ) -> impl Future<Output = PoCResult<()>> + Send;

    fn create_poc_bundle(
        &mut self,
        beacon_hash: Hash,
    ) -> impl Future<Output = PoCResult<Option<PoCBundle>>> + Send;

    fn submit_poc_event(&mut self, event: PoCEvent) -> impl Future<Output = PoCResult<()>> + Send;

    fn generate_daily_anchor(&mut self) -> impl Future<Output = PoCResult<Hash>> + Send;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatorStatus {
    pub aggregator_id: Address,
    pub is_active: bool,
    pub coverage_region: Vec<String>,
    pub processed_beacons: u64,
    pub processed_witnesses: u64,
    pub created_bundles: u64,
    pub submitted_events: u64,
    pub fraud_detections: u32,
    pub last_bundle_time: Option<Timestamp>,
    pub last_anchor_time: Option<Timestamp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatorMetrics {
    pub total_beacon_announcements: u64,
    pub total_witness_reports: u64,
    pub valid_witness_sets: u64,
    pub invalid_witness_sets: u64,
    pub coherence_check_failures: u32,
    pub geometry_validation_failures: u32,
    pub bundles_created: u64,
    pub events_submitted: u64,
    pub compression_ratio: f32,
    pub avg_witnesses_per_beacon: f32,
    pub fraud_reports_generated: u32,
    pub last_updated: Timestamp,
}

impl Default for AggregatorStatus {
    fn default() -> Self {
        Self {
            aggregator_id: Address::new([0u8; 20]),
            is_active: false,
            coverage_region: Vec::new(),
            processed_beacons: 0,
            processed_witnesses: 0,
            created_bundles: 0,
            submitted_events: 0,
            fraud_detections: 0,
            last_bundle_time: None,
            last_anchor_time: None,
        }
    }
}

impl Default for AggregatorMetrics {
    fn default() -> Self {
        Self {
            total_beacon_announcements: 0,
            total_witness_reports: 0,
            valid_witness_sets: 0,
            invalid_witness_sets: 0,
            coherence_check_failures: 0,
            geometry_validation_failures: 0,
            bundles_created: 0,
            events_submitted: 0,
            compression_ratio: 1.0,
            avg_witnesses_per_beacon: 0.0,
            fraud_reports_generated: 0,
            last_updated: Timestamp::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessSet {
    pub beacon_hash: Hash,
    pub beacon_announcement: BeaconAnnouncement,
    pub witness_reports: Vec<WitnessReport>,
    pub collection_deadline: Timestamp,
    pub is_complete: bool,
    pub coherence_score: Option<f64>,
    pub coverage_quality: Option<CoverageQuality>,
    pub epoch: u64,
}

impl WitnessSet {
    pub fn new(announcement: BeaconAnnouncement, collection_window_ms: u64, epoch: u64) -> Self {
        let beacon_hash = Hash::new({
            let sig_bytes = announcement.signature.as_bytes();
            let mut hash_bytes = [0u8; 32];
            let len = sig_bytes.len().min(32);
            hash_bytes[..len].copy_from_slice(&sig_bytes[..len]);
            hash_bytes
        });
        let deadline = Timestamp::from_millis(Timestamp::now().as_millis() + collection_window_ms);

        Self {
            beacon_hash,
            beacon_announcement: announcement,
            witness_reports: Vec::new(),
            collection_deadline: deadline,
            is_complete: false,
            coherence_score: None,
            coverage_quality: None,
            epoch,
        }
    }

    pub fn add_witness_report(&mut self, report: WitnessReport) -> bool {
        if report.beacon_id != self.beacon_announcement.beacon_id {
            return false;
        }

        if self
            .witness_reports
            .iter()
            .any(|r| r.witness_id == report.witness_id)
        {
            return false;
        }

        self.witness_reports.push(report);
        true
    }

    pub fn is_expired(&self) -> bool {
        Timestamp::now() > self.collection_deadline
    }

    pub fn witness_count(&self) -> usize {
        self.witness_reports.len()
    }

    pub fn has_sufficient_co_beacon_coverage(&self) -> bool {
        let co_beacon_count = self
            .witness_reports
            .iter()
            .filter(|r| r.co_beacon_verification.is_some())
            .count();

        let total_reports = self.witness_reports.len();
        if total_reports == 0 {
            return false;
        }

        (co_beacon_count as f64 / total_reports as f64) >= crate::CO_BEACON_MIN_FRACTION
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aggregator_status_default() {
        let status = AggregatorStatus::default();
        assert!(!status.is_active);
        assert_eq!(status.processed_beacons, 0);
    }

    #[test]
    fn test_aggregator_metrics_default() {
        let metrics = AggregatorMetrics::default();
        assert_eq!(metrics.total_beacon_announcements, 0);
        assert_eq!(metrics.fraud_reports_generated, 0);
    }

    #[test]
    fn test_witness_set_co_beacon_coverage() {
        use crate::beacon::BeaconAnnouncement;
        use crate::beacon::announcement::BeaconTxParams;
        use crate::types::{Challenge, LocationData};

        let challenge = Challenge {
            challenge_hash: Hash::new([1u8; 32]),
            h3_cell: "872834720ffffff".to_string(),
            nonce: vec![2u8; 16],
            timestamp: Timestamp::now(),
            difficulty: 1,
            reward_scale: 1.0,
        };

        let location = LocationData {
            latitude: 37.7749,
            longitude: -122.4194,
            altitude: Some(10.0),
            accuracy: Some(5.0),
            timestamp: Timestamp::now().as_millis(),
            h3_index: "872834720ffffff".to_string(),
        };

        let announcement = BeaconAnnouncement::new(
            Address::new([1u8; 20]),
            challenge,
            location,
            BeaconTxParams::default(),
        );

        let mut witness_set = WitnessSet::new(announcement, 10_000, 1);

        assert!(!witness_set.has_sufficient_co_beacon_coverage());
    }
}
