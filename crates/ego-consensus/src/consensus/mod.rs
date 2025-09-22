pub mod engine;
pub mod validation;

pub use engine::{ConsensusConfig, ConsensusEngine};
pub use validation::{ValidationError, ValidationResult};

use crate::aggregator::PoCEvent;
use crate::error::PoCResult;
use crate::types::*;
use ego_core::{Address, Timestamp};
use serde::{Deserialize, Serialize};
use std::future::Future;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusState {
    pub current_epoch: u64,
    pub active_challenges: Vec<Challenge>,
    pub recent_events: Vec<PoCEvent>,
    pub validator_set: Vec<Address>,
    pub fraud_reports: Vec<FraudReport>,
    pub network_stats: PoCNetworkStats,
    pub last_updated: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudReport {
    pub report_id: ego_core::Hash,
    pub reporter: Address,
    pub accused: Address,
    pub fraud_type: crate::FraudType,
    pub evidence: Vec<u8>,
    pub confidence: f64,
    pub timestamp: Timestamp,
    pub status: FraudReportStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FraudReportStatus {
    Pending,
    UnderReview,
    Confirmed,
    Rejected,
    Slashed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusParams {
    pub min_witnesses: usize,
    pub max_witnesses: usize,
    pub witness_timeout_ms: u64,
    pub fraud_threshold: f64,
    pub min_coherence_score: f64,
    pub beacon_interval_ms: u64,
    pub challenge_difficulty: u8,
    pub reward_multiplier: f64,
    pub slash_multiplier: f64,
    pub co_beacon_min_fraction: f64,
}

impl Default for ConsensusParams {
    fn default() -> Self {
        Self {
            min_witnesses: 3,
            max_witnesses: 14,
            witness_timeout_ms: 10_000,
            fraud_threshold: 0.8,
            min_coherence_score: 0.5,
            beacon_interval_ms: 30_000,
            challenge_difficulty: 1,
            reward_multiplier: 1.0,
            slash_multiplier: 2.0,
            co_beacon_min_fraction: 0.5,
        }
    }
}

impl Default for ConsensusState {
    fn default() -> Self {
        Self {
            current_epoch: 0,
            active_challenges: Vec::new(),
            recent_events: Vec::new(),
            validator_set: Vec::new(),
            fraud_reports: Vec::new(),
            network_stats: PoCNetworkStats {
                active_beacons: 0,
                active_witnesses: 0,
                total_coverage_hexes: 0,
                avg_witnesses_per_beacon: 0.0,
                network_quality_score: 0.0,
                fraud_detection_rate: 0.0,
                last_updated: Timestamp::now(),
            },
            last_updated: Timestamp::now(),
        }
    }
}

impl Default for FraudReportStatus {
    fn default() -> Self {
        Self::Pending
    }
}

pub trait ConsensusParticipant: Send + Sync {
    fn participant_id(&self) -> Address;

    fn validate_poc_event(
        &self,
        event: &PoCEvent,
    ) -> impl Future<Output = PoCResult<ValidationResult>> + Send;

    fn submit_fraud_report(
        &mut self,
        report: FraudReport,
    ) -> impl Future<Output = PoCResult<()>> + Send;

    fn get_drs_score(&self) -> Option<f64>;

    fn is_eligible_validator(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consensus_params_default() {
        let params = ConsensusParams::default();
        assert!(params.min_witnesses < params.max_witnesses);
        assert!(params.fraud_threshold <= 1.0);
        assert!(params.min_coherence_score <= 1.0);
        assert_eq!(params.min_witnesses, 3);
        assert_eq!(params.witness_timeout_ms, 10_000);
        assert_eq!(params.co_beacon_min_fraction, 0.5);
    }

    #[test]
    fn test_consensus_state_default() {
        let state = ConsensusState::default();
        assert_eq!(state.current_epoch, 0);
        assert!(state.active_challenges.is_empty());
        assert!(state.recent_events.is_empty());
    }
}
