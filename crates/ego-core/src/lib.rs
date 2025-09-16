pub mod account;
pub mod block;
pub mod crypto;
pub mod error;
pub mod rollup;
pub mod shard;
pub mod state;
pub mod transaction;
pub mod types;
pub mod utils;

pub use account::*;
pub use block::{Block, BlockBody, BlockHeader, BlockMetadata, NetworkStats, ProofEvent};
pub use crypto::*;
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
    AccountUpdates, SliceOperationType, StateChange, StateChangeType, Transaction,
    TransactionEvent, TransactionPayload, TransactionResult,
};
pub use types::*;
pub use utils::*;

pub const PROTOCOL_VERSION: u32 = 1;
pub const TARGET_BLOCK_TIME_MS: u64 = 100;
pub const TARGET_EPOCH_DURATION_MS: u64 = 1000;
pub const MAX_TXS_PER_BLOCK: usize = 1000;
pub const MAX_ROLLUP_COMMITS_PER_BLOCK: usize = 100;
pub const GLOBAL_FINALITY_TARGET_SECS: u64 = 3;
pub const MAX_SHARD_COUNT: u32 = 1024;
pub const DEFAULT_TRIAD_SIZE: usize = 3;
pub const EGOC_DECIMALS: u8 = 18;
pub const EGOC_BASE_UNIT: u128 = 1_000_000_000_000_000_000;
