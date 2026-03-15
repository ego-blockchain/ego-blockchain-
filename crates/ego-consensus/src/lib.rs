pub mod aggregator;
pub mod fee_market;
pub mod mev_protection;
pub mod beacon;
pub mod bridge;
pub mod challenge;
pub mod config;
pub mod consensus;
pub mod deal;
pub mod error;
pub mod fraud_proof;
pub mod h3_coverage;
pub mod metrics;
pub mod porep;
pub mod post;
pub mod repair;
pub mod rf_validation;
pub mod slashing;
pub mod storage;
pub mod types;
pub mod utils;
pub mod witness;

pub use aggregator::{AggregatorNode, PoCBundle, PoCEvent};
pub use beacon::{BeaconAnnouncement, BeaconNode};
pub use config::*;
pub use consensus::{ConsensusConfig, ConsensusEngine, ValidationResult};
pub use deal::{Deal, DealHandler, DealMetrics, StorageProvider};
pub use error::*;
pub use fraud_proof::*;
pub use metrics::{ProviderMetrics, RollupMetrics, SystemAlerts};
pub use porep::{PoRepEvent, PoRepProof, PoRepProvider, SealingJob};
pub use post::{PoStEvent, PoStProof, PoStProvider, WindowSchedule};
pub use repair::{RepairEvent, RepairManager, RepairMetrics};
pub use slashing::{PayoutReceipt, SlashEvent, SlashingManager};
pub use storage::{Storage, StorageMetrics, StorageProvider as StorageProviderTrait};
pub use types::*;
pub use witness::{WitnessNode, WitnessReport};

use ego_core::{Address, Hash, PublicKey, Timestamp};
use serde::{Deserialize, Serialize};
use std::future::Future;

pub const POC_BEACON_INTERVAL_MS: u64 = 30_000;
pub const POC_WITNESS_WINDOW_MS: u64 = 10_000;
pub const POC_AGGREGATION_WINDOW_MS: u64 = 60_000;
pub const POC_MIN_WITNESSES: usize = 3;
pub const POC_MAX_WITNESSES: usize = 14;
pub const POC_CELLULAR_SAFE_RATE_HZ: f32 = 0.75;
pub const POC_BATCH_SIZE: usize = 10;
pub const POC_COMPRESSION_THRESHOLD: usize = 1024;

pub const POREP_SECTOR_SIZE_32GIB: u64 = 32 * 1024 * 1024 * 1024;
pub const POREP_SECTOR_SIZE_64GIB: u64 = 64 * 1024 * 1024 * 1024;
pub const POREP_CHALLENGE_COUNT: u32 = 176;
pub const POREP_PARAMS_VERSION: u32 = 1;

pub const POST_WINDOWS_PER_DAY: u32 = 48;
pub const POST_WINDOW_DURATION_MS: u64 = 1800_000;
pub const POST_CHALLENGES_PER_SECTOR: u32 = 10;
pub const POST_MAX_PARTITIONS: u32 = 2349;

pub const H3_RESOLUTION: u8 = 9;
pub const H3_NEIGHBOR_RINGS: usize = 2;

pub const MIN_RSRP_DBM: i16 = -140;
pub const MAX_RSRP_DBM: i16 = -44;
pub const MIN_RSRQ_DB: i16 = -19;
pub const MAX_RSRQ_DB: i16 = -3;
pub const MIN_SINR_DB: i16 = -20;
pub const MAX_SINR_DB: i16 = 30;
pub const MAX_TIMING_ADVANCE: u32 = 1282;

pub const CO_BEACON_MIN_FRACTION: f64 = 0.5;

pub trait PoCNode: Send + Sync {
    fn node_id(&self) -> Address;
    fn public_key(&self) -> PublicKey;
    fn h3_cell(&self) -> Option<String>;
    fn is_active(&self) -> bool;
    fn last_activity(&self) -> Timestamp;
}

pub type PoCResult<T> = Result<T, PoCError>;

pub trait PoCEventHandler: Send + Sync {
    fn handle_beacon_announcement(
        &mut self,
        announcement: BeaconAnnouncement,
    ) -> impl Future<Output = PoCResult<()>> + Send;

    fn handle_witness_report(
        &mut self,
        report: WitnessReport,
    ) -> impl Future<Output = PoCResult<()>> + Send;

    fn handle_poc_bundle(
        &mut self,
        bundle: PoCBundle,
    ) -> impl Future<Output = PoCResult<()>> + Send;

    fn handle_fraud_proof(
        &mut self,
        proof: FraudProof,
    ) -> impl Future<Output = PoCResult<()>> + Send;

    fn handle_porep_event(
        &mut self,
        event: PoRepEvent,
    ) -> impl Future<Output = PoCResult<()>> + Send;

    fn handle_post_event(&mut self, event: PoStEvent)
    -> impl Future<Output = PoCResult<()>> + Send;

    fn handle_repair_event(
        &mut self,
        event: RepairEvent,
    ) -> impl Future<Output = PoCResult<()>> + Send;

    fn handle_slash_event(
        &mut self,
        event: SlashEvent,
    ) -> impl Future<Output = PoCResult<()>> + Send;
}

pub trait StorageNode: Send + Sync {
    fn node_id(&self) -> Address;
    fn storage_capacity(&self) -> u64;
    fn sector_count(&self) -> u32;
    fn reputation_score(&self) -> f64;

    fn seal_data(&mut self, data: Vec<u8>) -> impl Future<Output = PoCResult<PoRepProof>> + Send;

    fn generate_post_proof(
        &self,
        epoch: u64,
        window_id: u64,
    ) -> impl Future<Output = PoCResult<PoStProof>> + Send;

    fn handle_storage_challenge(
        &self,
        challenge: StorageChallenge,
    ) -> impl Future<Output = PoCResult<StorageResponse>> + Send;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageChallenge {
    pub challenge_id: Hash,
    pub sector_id: u64,
    pub challenge_data: Vec<u8>,
    pub deadline: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageResponse {
    pub challenge_id: Hash,
    pub response_data: Vec<u8>,
    pub proof: Vec<u8>,
    pub timestamp: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert!(POC_BEACON_INTERVAL_MS > POC_WITNESS_WINDOW_MS);
        assert!(POC_AGGREGATION_WINDOW_MS > POC_BEACON_INTERVAL_MS);
        assert!(POC_MIN_WITNESSES < POC_MAX_WITNESSES);
        assert_eq!(POC_MIN_WITNESSES, 3);
        assert_eq!(H3_RESOLUTION, 9);
        assert_eq!(CO_BEACON_MIN_FRACTION, 0.5);

        assert_eq!(POREP_SECTOR_SIZE_32GIB, 32 * 1024 * 1024 * 1024);
        assert_eq!(POREP_CHALLENGE_COUNT, 176);
        assert_eq!(POST_WINDOWS_PER_DAY, 48);
        assert_eq!(POST_WINDOW_DURATION_MS, 1800_000);
    }

    #[test]
    fn test_storage_challenge_creation() {
        let challenge = StorageChallenge {
            challenge_id: Hash::new([1u8; 32]),
            sector_id: 1,
            challenge_data: vec![1, 2, 3, 4],
            deadline: Timestamp::from_millis(Timestamp::now().as_millis() + 60_000),
        };

        assert_eq!(challenge.sector_id, 1);
        assert_eq!(challenge.challenge_data.len(), 4);
    }
}
