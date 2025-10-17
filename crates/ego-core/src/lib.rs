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
pub use crypto::{
    blake2s_hash, blake2s_hash_domain, create_authenticated_transcript, create_handshake_init,
    derive_stealth_address, dilithium_sign, dilithium_verify, hash_data, hash_multiple,
    hkdf_blake2s, hkdf_sha256, verify_dilithium_signature, verify_downgrade_protection,
    verify_dual_signature, verify_identity_binding, verify_signature, verify_slh_dsa_signature,
    xchacha20poly1305_decrypt, xchacha20poly1305_encrypt, AddressType, BatchVerifier, EgoAddress,
    ExportedKeys, ExportedKeysHex, KeyPair, MerkleNode, MerkleProof, MerkleTree, StreamCipher,
};
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
    StorageEntry, ValidatorInfo as StateValidatorInfo, ValidatorStatus,
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

pub const DEFAULT_MAX_PEERS: u32 = 200;
pub const DEFAULT_MAX_TOPICS_PER_ROLE: u32 = 20;
pub const DEFAULT_HEARTBEAT_INTERVAL_MS: u64 = 10000;
pub const DEFAULT_CONNECTION_TIMEOUT_MS: u64 = 30000;

pub const DEFAULT_COMPRESSION_MIN_SIZE: u64 = 1024;
pub const DEFAULT_BATCH_MAX_SIZE_MB: u64 = 10;
pub const DEFAULT_BATCH_MAX_AGE_SECONDS: u64 = 300;
pub const OFF_PEAK_HOURS_START: u8 = 23;
pub const OFF_PEAK_HOURS_END: u8 = 6;

pub use chrono::{DateTime, Utc};
pub use rand;
pub use serde::{Deserialize, Serialize};

#[macro_export]
macro_rules! ego_result {
    ($expr:expr) => {
        match $expr {
            Ok(val) => val,
            Err(err) => return Err(err.into()),
        }
    };
}

#[macro_export]
macro_rules! ego_error {
    ($kind:ident, $msg:expr) => {
        $crate::EgoError::$kind($msg.to_string())
    };
    ($kind:ident) => {
        $crate::EgoError::$kind
    };
}

pub fn current_timestamp() -> Timestamp {
    Timestamp::now()
}

pub fn current_epoch() -> EpochNumber {
    let now = current_timestamp();
    EpochNumber::new(now.as_secs() / EPOCH_MS)
}

pub fn calculate_shard_for_address(address: &Address, shard_count: u32) -> u32 {
    let address_bytes = address.as_bytes();
    let mut hash_value: u32 = 0;

    for (i, &byte) in address_bytes.iter().enumerate() {
        hash_value ^= (byte as u32) << (8 * (i % 4));
    }

    hash_value % shard_count
}

pub fn is_valid_geohash(geohash: &str, precision: usize) -> bool {
    if geohash.len() != precision || precision < 4 || precision > 12 {
        return false;
    }

    const VALID_CHARS: &str = "0123456789bcdefghjkmnpqrstuvwxyz";
    geohash.chars().all(|c| VALID_CHARS.contains(c))
}

pub fn format_balance(balance: &Balance) -> String {
    format!("{:.8} EGOC", balance.to_egoc())
}

pub fn format_storage_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    const THRESHOLD: f64 = 1024.0;

    if bytes == 0 {
        return "0 B".to_string();
    }

    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= THRESHOLD && unit_index < UNITS.len() - 1 {
        size /= THRESHOLD;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.2} {}", size, UNITS[unit_index])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_shard_for_address() {
        let address = Address::new([1u8; 20]);
        let shard = calculate_shard_for_address(&address, 10);
        assert!(shard < 10);
    }

    #[test]
    fn test_format_storage_size() {
        assert_eq!(format_storage_size(0), "0 B");
        assert_eq!(format_storage_size(1024), "1.00 KB");
        assert_eq!(format_storage_size(1024 * 1024), "1.00 MB");
        assert_eq!(format_storage_size(1024 * 1024 * 1024), "1.00 GB");
    }

    #[test]
    fn test_is_valid_geohash() {
        assert!(is_valid_geohash("9q9hvu", 6));
        assert!(!is_valid_geohash("9q9hvu", 5));
        assert!(!is_valid_geohash("9q9hvua", 6));
        assert!(!is_valid_geohash("", 6));
    }

    #[test]
    fn test_current_epoch() {
        let epoch = current_epoch();
        assert!(epoch.as_u64() > 0);
    }
}
