pub mod aggregator;
pub mod beacon;
pub mod config;
pub mod consensus;
pub mod error;
pub mod fraud_proof;
pub mod h3_coverage;
pub mod rf_validation;
pub mod types;
pub mod utils;
pub mod witness;

pub use aggregator::{AggregatorNode, PoCBundle, PoCEvent};
pub use beacon::{BeaconAnnouncement, BeaconNode};
pub use config::*;
pub use consensus::{ConsensusConfig, ConsensusEngine, ValidationResult};
pub use error::*;
pub use fraud_proof::*;
pub use types::*;
pub use witness::{WitnessNode, WitnessReport};

use ego_core::{Address, PublicKey, Timestamp};
use std::future::Future;

pub const POC_BEACON_INTERVAL_MS: u64 = 30_000;
pub const POC_WITNESS_WINDOW_MS: u64 = 10_000;
pub const POC_AGGREGATION_WINDOW_MS: u64 = 60_000;
pub const POC_MIN_WITNESSES: usize = 3;
pub const POC_MAX_WITNESSES: usize = 14;
pub const POC_CELLULAR_SAFE_RATE_HZ: f32 = 0.75;
pub const POC_BATCH_SIZE: usize = 10;
pub const POC_COMPRESSION_THRESHOLD: usize = 1024;

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
    }
}
