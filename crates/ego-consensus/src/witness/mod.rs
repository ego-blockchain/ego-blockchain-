pub mod bridge;
pub mod node;
pub mod report;

pub use node::WitnessNode;
pub use report::WitnessReport;

use crate::beacon::BeaconAnnouncement;
use crate::error::PoCResult;
use crate::types::*;
use ego_core::{Address, Timestamp};
use serde::{Deserialize, Serialize};
use std::future::Future;

pub trait Witness: Send + Sync {
    fn witness_id(&self) -> Address;

    fn is_active(&self) -> bool;

    fn scanning_frequencies(&self) -> Vec<u32>;

    fn process_beacon(
        &mut self,
        beacon: DetectedBeacon,
    ) -> impl Future<Output = PoCResult<Option<WitnessReport>>> + Send;

    fn get_pending_reports(&self) -> Vec<WitnessReport>;

    fn clear_submitted_reports(&mut self, report_hashes: Vec<ego_core::Hash>);

    fn is_cellular_safe(&self) -> bool;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedBeacon {
    pub rf_metrics: RFMetrics,

    pub announcement: Option<BeaconAnnouncement>,

    pub co_beacon_data: Option<CoBeaconData>,

    pub detected_at: Timestamp,

    pub witness_location: LocationData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoBeaconData {
    pub nonce: Vec<u8>,

    pub signature: ego_core::Signature,

    pub rx_timestamp: u64,

    pub metadata: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessStatus {
    pub witness_id: Address,
    pub is_active: bool,
    pub is_scanning: bool,
    pub last_detection: Option<Timestamp>,
    pub detection_rate: f32,
    pub report_success_rate: f64,
    pub cellular_safe_mode: bool,
    pub scanning_frequencies: Vec<u32>,
    pub current_h3_cell: Option<String>,
    pub drs_score: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessMetrics {
    pub total_detections: u64,
    pub valid_reports: u64,
    pub invalid_reports: u64,
    pub duplicate_detections: u64,
    pub avg_rsrp: f32,
    pub coverage_contribution: u64,
    pub fraud_reports: u32,
    pub cellular_violations: u32,
    pub last_updated: Timestamp,
}

impl Default for WitnessStatus {
    fn default() -> Self {
        Self {
            witness_id: Address::new([0u8; 20]),
            is_active: false,
            is_scanning: false,
            last_detection: None,
            detection_rate: 0.0,
            report_success_rate: 0.0,
            cellular_safe_mode: true,
            scanning_frequencies: Vec::new(),
            current_h3_cell: None,
            drs_score: None,
        }
    }
}

impl Default for WitnessMetrics {
    fn default() -> Self {
        Self {
            total_detections: 0,
            valid_reports: 0,
            invalid_reports: 0,
            duplicate_detections: 0,
            avg_rsrp: -100.0,
            coverage_contribution: 0,
            fraud_reports: 0,
            cellular_violations: 0,
            last_updated: Timestamp::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_witness_status_default() {
        let status = WitnessStatus::default();
        assert!(!status.is_active);
        assert!(status.cellular_safe_mode);
        assert_eq!(status.detection_rate, 0.0);
    }

    #[test]
    fn test_witness_metrics_default() {
        let metrics = WitnessMetrics::default();
        assert_eq!(metrics.total_detections, 0);
        assert_eq!(metrics.fraud_reports, 0);
    }
}
