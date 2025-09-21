pub mod announcement;
pub mod node;

pub use announcement::BeaconAnnouncement;
pub use node::BeaconNode;

use crate::config::BeaconConfig;
use crate::error::PoCResult;
use crate::types::*;
use ego_core::{Address, Hash, Timestamp};
use serde::{Deserialize, Serialize};

pub trait Beacon: Send + Sync {
    fn beacon_id(&self) -> Address;

    fn is_authorized(&self) -> bool;

    fn h3_cell(&self) -> Option<String>;

    fn authorized_frequencies(&self) -> Vec<u32>;

    async fn prepare_announcement(&mut self, challenge: Challenge)
    -> PoCResult<BeaconAnnouncement>;

    async fn transmit_beacon(
        &mut self,
        announcement: &BeaconAnnouncement,
    ) -> PoCResult<BeaconTxLog>;

    fn get_tx_log(&self) -> Option<BeaconTxLog>;

    fn is_cellular_safe(&self) -> bool;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconStatus {
    pub beacon_id: Address,
    pub is_active: bool,
    pub last_transmission: Option<Timestamp>,
    pub success_rate: f64,
    pub avg_witnesses_per_beacon: f32,
    pub cellular_safe_mode: bool,
    pub authorized_frequencies: Vec<u32>,
    pub current_h3_cell: Option<String>,
    pub drs_score: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconMetrics {
    pub total_transmissions: u64,
    pub successful_transmissions: u64,
    pub total_witnesses: u64,
    pub avg_coverage_radius_km: f32,
    pub fraud_detections: u32,
    pub cellular_violations: u32,
    pub last_updated: Timestamp,
}

impl Default for BeaconStatus {
    fn default() -> Self {
        Self {
            beacon_id: Address::new([0u8; 20]),
            is_active: false,
            last_transmission: None,
            success_rate: 0.0,
            avg_witnesses_per_beacon: 0.0,
            cellular_safe_mode: true,
            authorized_frequencies: Vec::new(),
            current_h3_cell: None,
            drs_score: None,
        }
    }
}

impl Default for BeaconMetrics {
    fn default() -> Self {
        Self {
            total_transmissions: 0,
            successful_transmissions: 0,
            total_witnesses: 0,
            avg_coverage_radius_km: 0.0,
            fraud_detections: 0,
            cellular_violations: 0,
            last_updated: Timestamp::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_beacon_status_default() {
        let status = BeaconStatus::default();
        assert!(!status.is_active);
        assert!(status.cellular_safe_mode);
        assert_eq!(status.success_rate, 0.0);
    }

    #[test]
    fn test_beacon_metrics_default() {
        let metrics = BeaconMetrics::default();
        assert_eq!(metrics.total_transmissions, 0);
        assert_eq!(metrics.fraud_detections, 0);
    }
}
