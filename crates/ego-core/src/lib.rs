pub mod account;
pub mod block;
pub mod crypto;
pub mod deploy_policy;
pub mod drs;
pub mod error;
pub mod rollup;
pub mod shard;
pub mod state;
pub mod transaction;
pub mod types;
pub mod utils;

pub use account::*;
pub use block::{
    Block, BlockBody, BlockHeader, BlockHeaderCore, BlockMetadata, CrossShardReceipt, DRSEvent,
    DeployEvent, NetworkStats, ProofEvent, QuorumCert, ResourcePricing, RollupCommitment,
    ValidatorSignature, WitnessData,
};
pub use crypto::*;
pub use deploy_policy::*;
pub use drs::*;
pub use error::*;
pub use rollup::{
    BatchStatus, Challenge, ChallengeStatus, ChallengeType, FeeStructure, FraudProofConfig,
    RollupAggregator, RollupConfig, RollupMetrics, RollupState, RollupStats, TransactionBatch,
};
pub use shard::*;
pub use state::{
    CrossShardState, JailInfo, SliceConfig, SliceStatus, SliceType, StateManager, StateStats,
    StorageEntry, ValidatorInfo, ValidatorStatus,
};
pub use transaction::{
    AccountUpdates, CrossShardReceipt as TxCrossShardReceipt, SliceOperationType, StateChange,
    StateChangeType, Transaction, TransactionEvent, TransactionPayload, TransactionResult,
};
pub use types::*;
pub use utils::*;

pub const PROTOCOL_VERSION: u32 = 1;
pub const MICRO_SLOT_MS: u64 = 500;
pub const EPOCH_MS: u64 = 1000;
pub const FINALITY_TARGET_S: u64 = 3;
pub const MAX_TXS_PER_BLOCK: usize = 1000;
pub const MAX_ROLLUP_COMMITS_PER_BLOCK: usize = 100;
pub const MAX_SHARD_COUNT: u32 = 1024;
pub const DEFAULT_TRIAD_SIZE: usize = 3;
pub const TARGET_BLOCK_TIME_MS: u64 = 3000;

pub const EGOC_DECIMALS: u8 = 8;
pub const EGOC_BASE_UNIT: u128 = 100_000_000;

pub const DEFAULT_FREE_DEPLOYS_PER_EPOCH: u32 = 5;
pub const DEFAULT_STORAGE_CREDITS_PER_GB_MONTH: u64 = 1000;
pub const DEFAULT_DEPLOY_CREDITS_PER_KB: u64 = 100;
pub const DEFAULT_MIN_STAKE_FOR_QUOTA: u128 = 1000 * EGOC_BASE_UNIT;

pub const DRS_UPDATE_INTERVAL_EPOCHS: u64 = 1;
pub const DRS_SCORE_BOUNDS_MIN: f64 = 0.0;
pub const DRS_SCORE_BOUNDS_MAX: f64 = 100.0;
pub const DRS_DENSITY_PENALTY_RATE: f64 = 0.10;
pub const DRS_DENSITY_MIN_MULTIPLIER: f64 = 0.40;

pub const POC_WITNESS_TIMEOUT_MS: u64 = 30000;
pub const POST_CHALLENGE_WINDOW_BLOCKS: u64 = 100;
pub const PROOF_VERIFICATION_TIMEOUT_MS: u64 = 5000;

pub const STORAGE_REPLICATION_FACTOR: u8 = 3;
pub const STORAGE_PROOF_FREQUENCY_BLOCKS: u64 = 1000;
pub const STORAGE_REPAIR_THRESHOLD_HOURS: u64 = 24;

pub const MAX_SLICES_PER_ACCOUNT: usize = 10;
pub const DEFAULT_SLICE_BANDWIDTH_MBPS: u64 = 100;
pub const DEFAULT_SLICE_LATENCY_MS: u32 = 10;
