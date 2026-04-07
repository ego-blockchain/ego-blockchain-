pub mod account;
pub mod bls;
pub mod bls_qc;
pub mod block;
pub mod crypto;
pub mod deploy_policy;
pub mod drs;
pub mod error;
pub mod light_client;
pub mod rollup;
pub mod shard;
pub mod sparse_merkle;
pub mod state;
pub mod transaction;
pub mod types;
pub mod utils;

pub use account::*;
pub use bls::{BlsAggregateSignature, BlsError, BlsKeypair, BlsSignature, BLS_DST};
pub use bls_qc::BlsQuorumCertificate;
pub use block::*;
pub use crypto::*;
pub use deploy_policy::*;
pub use drs::*;
pub use error::*;
pub use rollup::*;
pub use shard::*;
pub use sparse_merkle::{SmtProof, SparseMerkleTrie};
pub use state::*;
pub use transaction::*;
// Explicit re-export resolves the ambiguity between transaction::CrossShardReceipt
// and block::CrossShardReceipt (both pulled in via glob re-exports above).
pub use transaction::CrossShardReceipt;
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

pub fn format_bandwidth(bytes_per_sec: u64) -> String {
    const UNITS: &[&str] = &["B/s", "KB/s", "MB/s", "GB/s"];
    const THRESHOLD: f64 = 1024.0;

    if bytes_per_sec == 0 {
        return "0 B/s".to_string();
    }

    let mut rate = bytes_per_sec as f64;
    let mut unit_index = 0;

    while rate >= THRESHOLD && unit_index < UNITS.len() - 1 {
        rate /= THRESHOLD;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes_per_sec, UNITS[unit_index])
    } else {
        format!("{:.2} {}", rate, UNITS[unit_index])
    }
}

pub fn format_duration(millis: u64) -> String {
    if millis < 1000 {
        return format!("{}ms", millis);
    }

    let seconds = millis / 1000;
    if seconds < 60 {
        return format!("{}s", seconds);
    }

    let minutes = seconds / 60;
    if minutes < 60 {
        let remaining_secs = seconds % 60;
        return format!("{}m {}s", minutes, remaining_secs);
    }

    let hours = minutes / 60;
    let remaining_mins = minutes % 60;
    if hours < 24 {
        return format!("{}h {}m", hours, remaining_mins);
    }

    let days = hours / 24;
    let remaining_hours = hours % 24;
    format!("{}d {}h", days, remaining_hours)
}

pub fn format_hash_short(hash: &Hash) -> String {
    let hex = hash.to_hex();
    format!("{}...{}", &hex[..8], &hex[56..])
}

pub fn format_address_short(address: &Address) -> String {
    address.short_display()
}

pub fn validate_commission_rate(rate: u16) -> EgoResult<()> {
    if rate > 10000 {
        return Err(EgoError::InvalidCommissionRate { rate });
    }
    Ok(())
}

pub fn validate_epoch_number(
    epoch: u64,
    current_epoch: u64,
    max_future_epochs: u64,
) -> EgoResult<()> {
    if epoch > current_epoch + max_future_epochs {
        return Err(EgoError::InvalidTransaction(format!(
            "Epoch {} is too far in the future (current: {})",
            epoch, current_epoch
        )));
    }
    Ok(())
}

pub fn validate_timestamp(timestamp: Timestamp, max_future_ms: u64) -> EgoResult<()> {
    let now = Timestamp::now();
    if timestamp.as_millis() > now.as_millis() + max_future_ms {
        return Err(EgoError::InvalidTransaction(
            "Timestamp too far in future".to_string(),
        ));
    }
    Ok(())
}

pub fn calculate_block_reward(epoch: u64) -> Balance {
    let base_emission = 1_000_000_000_000u128;
    let halvings = epoch / 525_600;
    let emission = base_emission >> halvings.min(10);
    Balance::new(emission)
}

pub fn calculate_storage_cost(size_bytes: u64, duration_epochs: u64) -> StorageCredits {
    StorageCredits::for_size_duration(size_bytes, duration_epochs)
}

pub fn calculate_deploy_cost(code_size_kb: u32, ru_estimate: u64) -> DeployCredits {
    DeployCredits::for_code_size(code_size_kb, ru_estimate)
}

pub fn is_off_peak_hour(hour: u8) -> bool {
    if OFF_PEAK_HOURS_START > OFF_PEAK_HOURS_END {
        hour >= OFF_PEAK_HOURS_START || hour < OFF_PEAK_HOURS_END
    } else {
        hour >= OFF_PEAK_HOURS_START && hour < OFF_PEAK_HOURS_END
    }
}

pub fn estimate_tx_resource_units(payload: &TransactionPayload) -> u64 {
    match payload {
        TransactionPayload::Transfer { stealth_mode, .. } => {
            if *stealth_mode {
                500
            } else {
                100
            }
        }
        TransactionPayload::CreateAccount { .. } => 1000,
        TransactionPayload::UpdateAccount { .. } => 500,
        TransactionPayload::StoreData {
            data_size,
            replication_factor,
            ..
        } => 1000 + (*data_size / 1024) * (*replication_factor as u64),
        TransactionPayload::UpdateTriadPlacement { .. } => 800,
        TransactionPayload::SubmitProofBatch { proofs, .. } => 2000 + (proofs.len() as u64 * 100),
        TransactionPayload::PoStChallenge { chunk_ids, .. } => 1500 + (chunk_ids.len() as u64 * 50),
        TransactionPayload::PoStResponse { proofs, .. } => 3000 + (proofs.len() as u64 * 150),
        TransactionPayload::PoCWitnessReport {
            witness_reports, ..
        } => 2000 + (witness_reports.len() as u64 * 100),
        TransactionPayload::RollupCommit {
            tx_count,
            fraud_proofs,
            ..
        } => 5000 + (*tx_count as u64 * 10) + (fraud_proofs.len() as u64 * 500),
        TransactionPayload::ChallengeFraud { .. } => 3000,
        TransactionPayload::ResolveFraudChallenge { .. } => 4000,
        TransactionPayload::ClaimRewards { .. } => 1200,
        TransactionPayload::BuyStorageCredits { .. } => 300,
        TransactionPayload::BuyDeployCredits { .. } => 300,
        TransactionPayload::StreamStoragePayment { .. } => 200,
        TransactionPayload::PayRetrievalFee { .. } => 250,
        TransactionPayload::Stake { .. } => 800,
        TransactionPayload::Unstake { .. } => 600,
        TransactionPayload::Delegate { .. } => 400,
        TransactionPayload::UpdateValidatorMetrics { .. } => 1000,
        TransactionPayload::CrossShard { .. } => 1500,
        TransactionPayload::DeployContract { .. } => 5000,
        TransactionPayload::ExecuteContract { .. } => 2000,
        TransactionPayload::SliceOperation { .. } => 2000,
        TransactionPayload::UpdateDRS { .. } => 1000,
        TransactionPayload::SystemOperation { epoch_anchor, .. } => {
            if *epoch_anchor {
                20000
            } else {
                10000
            }
        }
        TransactionPayload::PQTransition { .. } => 5000,
        TransactionPayload::DAOProposal { .. } => 3000,
        TransactionPayload::DAOVote { .. } => 500,
    }
}

pub fn verify_triad_diversity(
    primary_region: &str,
    replica_a_region: &str,
    replica_b_region: &str,
) -> bool {
    let mut regions = std::collections::HashSet::new();
    regions.insert(primary_region);
    regions.insert(replica_a_region);
    regions.insert(replica_b_region);
    regions.len() >= 2
}

pub fn calculate_triad_diversity_score(
    primary_h3: &str,
    replica_a_h3: &str,
    replica_b_h3: &str,
) -> f64 {
    let mut unique_cells = std::collections::HashSet::new();
    unique_cells.insert(primary_h3);
    unique_cells.insert(replica_a_h3);
    unique_cells.insert(replica_b_h3);

    match unique_cells.len() {
        3 => 1.0,
        2 => 0.66,
        1 => 0.33,
        _ => 0.0,
    }
}

pub fn is_cellular_safe_operation(operation: &str, data_size_bytes: u64) -> bool {
    const CELLULAR_SAFE_THRESHOLD_BYTES: u64 = 10 * 1024 * 1024;

    let heavy_operations = [
        "heavy_compute",
        "large_storage",
        "bulk_sync",
        "firmware_update",
        "full_state_sync",
    ];

    if heavy_operations.contains(&operation) {
        return false;
    }

    data_size_bytes <= CELLULAR_SAFE_THRESHOLD_BYTES
}

pub fn calculate_network_quality_score(
    latency_ms: u32,
    bandwidth_mbps: u64,
    reliability_score: u8,
    packet_loss_percent: f32,
) -> f64 {
    let latency_score = (1000.0 / (latency_ms as f64 + 1.0)).min(100.0);
    let bandwidth_score = (bandwidth_mbps as f64).min(100.0);
    let reliability = reliability_score as f64;
    let loss_score = (100.0 - packet_loss_percent as f64 * 10.0).max(0.0);

    (latency_score * 0.3 + bandwidth_score * 0.1 + reliability * 0.4 + loss_score * 0.2).min(100.0)
}

pub fn should_compress_data(data_size: u64) -> bool {
    data_size >= DEFAULT_COMPRESSION_MIN_SIZE
}

pub fn estimate_compressed_size(original_size: u64) -> u64 {
    (original_size as f64 * 0.7) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_shard_for_address() {
        let address = Address::new([1u8; 20]);
        let shard = calculate_shard_for_address(&address, 10);
        assert!(shard < 10);

        let same_shard = calculate_shard_for_address(&address, 10);
        assert_eq!(shard, same_shard);
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

    #[test]
    fn test_format_balance() {
        let balance = Balance::from_egoc(100);
        let formatted = format_balance(&balance);
        assert!(formatted.contains("100.00000000 EGOC"));
    }

    #[test]
    fn test_validate_commission_rate() {
        assert!(validate_commission_rate(5000).is_ok());
        assert!(validate_commission_rate(10000).is_ok());
        assert!(validate_commission_rate(10001).is_err());
    }

    #[test]
    fn test_calculate_block_reward() {
        let reward = calculate_block_reward(0);
        assert_eq!(reward.as_u128(), 1_000_000_000_000);

        let halved_reward = calculate_block_reward(525_600);
        assert_eq!(halved_reward.as_u128(), 500_000_000_000);
    }

    #[test]
    fn test_is_off_peak_hour() {
        assert!(is_off_peak_hour(23));
        assert!(is_off_peak_hour(0));
        assert!(is_off_peak_hour(5));
        assert!(!is_off_peak_hour(12));
        assert!(!is_off_peak_hour(18));
    }

    #[test]
    fn test_verify_triad_diversity() {
        assert!(verify_triad_diversity("us-east", "eu-west", "ap-south"));
        assert!(verify_triad_diversity("us-east", "us-east", "eu-west"));
        assert!(!verify_triad_diversity("us-east", "us-east", "us-east"));
    }

    #[test]
    fn test_calculate_triad_diversity_score() {
        let score_high = calculate_triad_diversity_score("abc123", "def456", "ghi789");
        assert_eq!(score_high, 1.0);

        let score_mid = calculate_triad_diversity_score("abc123", "abc123", "def456");
        assert_eq!(score_mid, 0.66);

        let score_low = calculate_triad_diversity_score("abc123", "abc123", "abc123");
        assert_eq!(score_low, 0.33);
    }

    #[test]
    fn test_is_cellular_safe_operation() {
        assert!(is_cellular_safe_operation("normal_transfer", 1024));
        assert!(is_cellular_safe_operation("small_proof", 100 * 1024));
        assert!(!is_cellular_safe_operation("heavy_compute", 1024));
        assert!(!is_cellular_safe_operation("normal_op", 20 * 1024 * 1024));
    }

    #[test]
    fn test_calculate_network_quality_score() {
        let score = calculate_network_quality_score(50, 100, 95, 0.1);
        assert!(score > 70.0 && score <= 100.0);

        let poor_score = calculate_network_quality_score(500, 10, 50, 5.0);
        assert!(poor_score < 50.0);
    }

    #[test]
    fn test_should_compress_data() {
        assert!(!should_compress_data(512));
        assert!(should_compress_data(2048));
        assert!(should_compress_data(1024 * 1024));
    }

    #[test]
    fn test_estimate_compressed_size() {
        let original = 1000;
        let compressed = estimate_compressed_size(original);
        assert_eq!(compressed, 700);
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(500), "500ms");
        assert_eq!(format_duration(5000), "5s");
        assert_eq!(format_duration(125000), "2m 5s");
        assert_eq!(format_duration(7200000), "2h 0m");
    }

    #[test]
    fn test_calculate_storage_cost() {
        let cost = calculate_storage_cost(1_000_000_000, 100);
        assert!(cost.as_u64() > 0);
    }

    #[test]
    fn test_calculate_deploy_cost() {
        let cost = calculate_deploy_cost(100, 10000);
        assert_eq!(cost.as_u64(), 100 * 100 + 10000 / 100);
    }

    #[test]
    fn test_estimate_tx_resource_units() {
        let transfer_payload = TransactionPayload::Transfer {
            to: Address::new([0u8; 20]),
            amount: Balance::from_egoc(10),
            memo: None,
            stealth_mode: false,
        };
        let ru = estimate_tx_resource_units(&transfer_payload);
        assert_eq!(ru, 100);

        let stealth_transfer = TransactionPayload::Transfer {
            to: Address::new([0u8; 20]),
            amount: Balance::from_egoc(10),
            memo: None,
            stealth_mode: true,
        };
        let stealth_ru = estimate_tx_resource_units(&stealth_transfer);
        assert_eq!(stealth_ru, 500);
    }

    #[test]
    fn test_format_hash_short() {
        let hash = Hash::new([1u8; 32]);
        let short = format_hash_short(&hash);
        assert!(short.contains("..."));
        assert_eq!(short.len(), 19);
    }

    #[test]
    fn test_validate_epoch_number() {
        assert!(validate_epoch_number(100, 100, 10).is_ok());
        assert!(validate_epoch_number(105, 100, 10).is_ok());
        assert!(validate_epoch_number(200, 100, 10).is_err());
    }

    #[test]
    fn test_validate_timestamp() {
        let now = Timestamp::now();
        assert!(validate_timestamp(now, 300_000).is_ok());

        let future = now.add_millis(100_000);
        assert!(validate_timestamp(future, 300_000).is_ok());

        let far_future = now.add_millis(500_000);
        assert!(validate_timestamp(far_future, 300_000).is_err());
    }

    #[test]
    fn test_format_bandwidth() {
        assert_eq!(format_bandwidth(0), "0 B/s");
        assert_eq!(format_bandwidth(1024), "1.00 KB/s");
        assert_eq!(format_bandwidth(1024 * 1024), "1.00 MB/s");
        assert_eq!(format_bandwidth(1024 * 1024 * 1024), "1.00 GB/s");
    }
}
