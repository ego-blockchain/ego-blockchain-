pub mod announcement;
pub mod node;

pub use announcement::{BeaconAnnouncement, BeaconTxParams, CoBeaconInfo, CoBeaconMethod, ChallengeBinding};
pub use node::BeaconNode;

use crate::error::PoCResult;
use crate::types::*;
use ego_core::{Address, Hash, Timestamp};
use serde::{Deserialize, Serialize};
use std::future::Future;

pub trait Beacon: Send + Sync {
    fn beacon_id(&self) -> Address;

    fn is_authorized(&self) -> bool;

    fn h3_cell(&self) -> Option<String>;

    fn authorized_frequencies(&self) -> Vec<u32>;

    fn prepare_announcement(
        &mut self,
        challenge: Challenge,
    ) -> impl Future<Output = PoCResult<BeaconAnnouncement>> + Send;

    // NEW: Whitepaper - prepare with consensus randomness
    fn prepare_announcement_with_randomness(
        &mut self,
        challenge: Challenge,
        vrf_output: Hash,
        region_id: String,
        epoch: u64,
        slot: u64,
    ) -> impl Future<Output = PoCResult<BeaconAnnouncement>> + Send;

    fn transmit_beacon(
        &mut self,
        announcement: &BeaconAnnouncement,
    ) -> impl Future<Output = PoCResult<BeaconTxLog>> + Send;

    // NEW: Whitepaper - start co-beacon broadcast
    fn start_co_beacon_broadcast(
        &mut self,
        announcement: &BeaconAnnouncement,
    ) -> impl Future<Output = PoCResult<()>> + Send;

    // NEW: Whitepaper - stop co-beacon broadcast
    fn stop_co_beacon_broadcast(&mut self) -> impl Future<Output = PoCResult<()>> + Send;

    fn get_tx_log(&self) -> Option<BeaconTxLog>;

    fn is_cellular_safe(&self) -> bool;
    
    // NEW: Get current epoch
    fn get_current_epoch(&self) -> u64;
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
    // NEW: Whitepaper additions
    pub co_beacon_active: bool,
    pub last_challenge_epoch: Option<u64>,
    pub randomness_source: RandomnessSource,
    pub nr_bands: Vec<u8>, // Authorized NR bands
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
    // NEW: Whitepaper additions
    pub co_beacon_broadcasts: u64,
    pub nonce_binding_successes: u64,
    pub nonce_binding_failures: u64,
    pub challenge_binding_failures: u32,
    pub avg_window_duration_ms: u64,
}

/// Whitepaper: Randomness source for challenge generation
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RandomnessSource {
    None,           // No randomness (basic mode)
    VRF,            // Threshold VRF (whitepaper preferred)
    RANDAO,         // RANDAO + VDF
    Beacon,         // Beacon chain randomness
}

/// Whitepaper: Co-beacon broadcast status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoBeaconStatus {
    pub method: CoBeaconMethod,
    pub is_broadcasting: bool,
    pub nonce: Vec<u8>,
    pub start_time: Timestamp,
    pub end_time: Timestamp,
    pub broadcasts_sent: u64,
    pub witnesses_detected: u32,
}

/// Whitepaper: Challenge schedule for PoC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeSchedule {
    pub region_id: String,
    pub epoch: u64,
    pub slot: u64,
    pub window_start: Timestamp,
    pub window_end: Timestamp,
    pub selected_beacon: Address,
    pub vrf_output: Hash,
}

impl ChallengeSchedule {
    /// Whitepaper: Schedule challenge windows per epoch randomness
    /// R_e = H(vrf_output || region_id || epoch || slot)
    pub fn new(
        region_id: String,
        epoch: u64,
        slot: u64,
        vrf_output: Hash,
        selected_beacon: Address,
    ) -> Self {
        let now = Timestamp::now();
        
        // Whitepaper: W=10s challenge window
        Self {
            region_id,
            epoch,
            slot,
            window_start: now,
            window_end: Timestamp::from_millis(now.as_millis() + 10_000),
            selected_beacon,
            vrf_output,
        }
    }

    /// Check if currently in challenge window
    pub fn is_active(&self) -> bool {
        let now = Timestamp::now();
        now >= self.window_start && now <= self.window_end
    }

    /// Get remaining time in window (ms)
    pub fn remaining_time_ms(&self) -> i64 {
        let now = Timestamp::now();
        (self.window_end.as_millis() as i64) - (now.as_millis() as i64)
    }
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
            co_beacon_active: false,
            last_challenge_epoch: None,
            randomness_source: RandomnessSource::None,
            nr_bands: vec![78], // Default to n78 (3.3-3.8 GHz)
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
            co_beacon_broadcasts: 0,
            nonce_binding_successes: 0,
            nonce_binding_failures: 0,
            challenge_binding_failures: 0,
            avg_window_duration_ms: 10_000, // Whitepaper: W=10s
        }
    }
}

impl Default for CoBeaconStatus {
    fn default() -> Self {
        Self {
            method: CoBeaconMethod::BLE {
                service_uuid: "0000180a-0000-1000-8000-00805f9b34fb".to_string(),
                characteristic_uuid: "00002a29-0000-1000-8000-00805f9b34fb".to_string(),
                tx_power_dbm: -10,
            },
            is_broadcasting: false,
            nonce: Vec::new(),
            start_time: Timestamp::now(),
            end_time: Timestamp::now(),
            broadcasts_sent: 0,
            witnesses_detected: 0,
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
        assert!(!status.co_beacon_active);
        assert_eq!(status.randomness_source, RandomnessSource::None);
        assert_eq!(status.nr_bands, vec![78]);
    }

    #[test]
    fn test_beacon_metrics_default() {
        let metrics = BeaconMetrics::default();
        assert_eq!(metrics.total_transmissions, 0);
        assert_eq!(metrics.fraud_detections, 0);
        assert_eq!(metrics.co_beacon_broadcasts, 0);
        assert_eq!(metrics.avg_window_duration_ms, 10_000);
    }

    #[test]
    fn test_challenge_schedule() {
        let vrf_output = Hash::new([1u8; 32]);
        let beacon = Address::new([2u8; 20]);
        
        let schedule = ChallengeSchedule::new(
            "872834".to_string(),
            100,
            5,
            vrf_output,
            beacon,
        );

        assert_eq!(schedule.region_id, "872834");
        assert_eq!(schedule.epoch, 100);
        assert_eq!(schedule.slot, 5);
        assert!(schedule.is_active());
        assert!(schedule.remaining_time_ms() > 0);
    }

    #[test]
    fn test_randomness_source() {
        assert_eq!(RandomnessSource::None, RandomnessSource::None);
        assert_ne!(RandomnessSource::VRF, RandomnessSource::RANDAO);
    }

    #[test]
    fn test_co_beacon_status_default() {
        let status = CoBeaconStatus::default();
        assert!(!status.is_broadcasting);
        assert_eq!(status.broadcasts_sent, 0);
        assert!(matches!(status.method, CoBeaconMethod::BLE { .. }));
    }

    #[test]
    fn test_challenge_schedule_expiry() {
        let vrf_output = Hash::new([1u8; 32]);
        let beacon = Address::new([2u8; 20]);
        
        let mut schedule = ChallengeSchedule::new(
            "872834".to_string(),
            100,
            5,
            vrf_output,
            beacon,
        );

        // Should be active initially
        assert!(schedule.is_active());

        // Manually set window to past
        let past = Timestamp::from_millis(Timestamp::now().as_millis() - 20_000);
        schedule.window_start = past;
        schedule.window_end = Timestamp::from_millis(past.as_millis() + 10_000);

        // Should no longer be active
        assert!(!schedule.is_active());
        assert!(schedule.remaining_time_ms() < 0);
    }
}