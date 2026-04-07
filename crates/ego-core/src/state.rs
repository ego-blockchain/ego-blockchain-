use crate::block::PQSignatureCount;
use crate::transaction::{
    CrossShardReceipt, PQVerificationResult, ProofType, ProofVerificationResult,
};
use crate::{
    Account, AccountType, Address, Balance, BlockHeight, EgoError, EgoResult, Hash, PublicKey,
    ShardId, SliceId, StateChange, StateChangeType, Timestamp, Transaction, TransactionEvent,
    TransactionPayload, TransactionResult,
};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

pub const DEFAULT_PRUNING_EPOCHS: u64 = 100;
pub const DEFAULT_SNAPSHOT_INTERVAL: u64 = 1000;
pub const MAX_CROSS_SHARD_RECEIPTS: usize = 10000;
pub const RECEIPT_DEADLINE_EPOCHS: u64 = 100;
pub const MIN_VALIDATOR_STAKE: u128 = 100_000_000_000;
pub const MIN_STORAGE_COLLATERAL: u128 = 10_000_000_000;

/// Base fee rate: nanoEGOC per resource unit consumed.
/// 1000 nanoEGOC = 0.001 uEGOC per RU.
pub const BASE_FEE_PER_RU: u128 = 1_000;

/// All base fees are burned to this address (20 zero bytes).
pub fn burn_address() -> Address {
    Address::new([0u8; 20])
}

#[derive(Debug, Clone)]
pub struct StateManager {
    accounts: Arc<DashMap<Address, Account>>,

    storage: Arc<DashMap<Hash, StorageEntry>>,

    validators: Arc<DashMap<Address, ValidatorInfo>>,

    slices: Arc<DashMap<String, SliceConfig>>,

    cross_shard_state: Arc<DashMap<ShardId, CrossShardState>>,

    pending_receipts: Arc<DashMap<Hash, PendingReceipt>>,
    processed_receipt_nonces: Arc<DashMap<(ShardId, ShardId), HashSet<u64>>>,

    state_root: Arc<Mutex<Hash>>,
    block_height: Arc<Mutex<BlockHeight>>,

    tx_root: Arc<Mutex<Hash>>,
    receipts_root: Arc<Mutex<Hash>>,
    events_root_post: Arc<Mutex<Hash>>,
    events_root_poc: Arc<Mutex<Hash>>,
    rollup_root: Arc<Mutex<Hash>>,
    da_root: Arc<Mutex<Hash>>,

    stats: Arc<Mutex<StateStats>>,

    pruning_config: PruningConfig,

    chain_id: u32,
    network_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct StorageEntry {
    pub chunk_id: Hash,
    pub data_hash: Hash,
    pub size: u64,
    pub data_type: StorageDataType,

    pub created_at: Timestamp,
    pub expires_at: BlockHeight,
    pub last_audit_epoch: u64,

    pub triad: TriadInfo,

    pub porep_commitment: Hash,
    pub porep_params_version: u32,
    pub post_schedule: PostSchedule,
    pub post_stats: PostStats,

    pub erasure_coding: Option<ErasureCodingParams>,

    pub encryption_envelope: Option<EncryptionMetadata>,
    pub owner: Address,
    pub authorized_readers: Vec<Address>,

    pub storage_credits_locked: u64,
    pub total_paid: Balance,

    pub slice_id: Option<String>,

    pub integrity_verified: bool,
    pub last_verified_epoch: u64,
    pub verification_failures: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum StorageDataType {
    OldBlockBodies { start_height: u64, end_height: u64 },
    StateSnapshot { epoch: u64 },
    ContractCode { code_hash: Hash },
    ContractState { contract_addr: Address, epoch: u64 },

    RollupBatch { rollup_id: String, batch_id: u64 },
    DABlob { epoch: u64 },

    PoStEvidence { epoch: u64, node_id: Address },
    PoCEvidence { epoch: u64, region_id: String },
    PoRepEvidence { sector_id: Hash },

    UserData { app_id: String },
    FileStorage { filename: String, mime_type: String },
    VideoContent { video_id: String },
    TelemetryData { device_id: String, period: String },

    Custom { label: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct TriadInfo {
    pub group_id: String,
    pub primary: TriadMember,
    pub replica_a: TriadMember,
    pub replica_b: TriadMember,
    pub placement_epoch: u64,
    pub diversity_score: f64,
    pub last_health_check: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct TriadMember {
    pub node_id: Address,
    pub sector_id: Hash,
    pub replica_id: Hash,
    pub h3_cell: String,
    pub region: String,
    pub shard_id: u32,
    pub role: TriadRole,
    pub health_score: u64,
    pub consecutive_misses: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum TriadRole {
    Primary,
    ReplicaA,
    ReplicaB,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PostSchedule {
    pub windows_per_day: u32,
    pub challenges_per_window: u32,
    pub sla_ms: u32,
    pub next_window: u64,
    pub last_window: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PostStats {
    pub total_challenges: u64,
    pub passed_challenges: u64,
    pub failed_challenges: u64,
    pub avg_latency_ms: u32,
    pub pass_rate: f64,
    pub last_proof_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ErasureCodingParams {
    pub k: u16,
    pub m: u16,
    pub codec: ErasureCodec,
    pub chunk_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum ErasureCodec {
    ReedSolomon,
    LDPC,
    Fountain,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct EncryptionMetadata {
    pub algorithm: String,
    pub key_refs: Vec<Hash>,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ValidatorInfo {
    pub address: Address,
    pub public_key: PublicKey,

    pub total_stake: Balance,
    pub own_stake: Balance,
    pub delegated_stake: Balance,
    pub commission_rate: u16,

    pub status: ValidatorStatus,
    pub joined_epoch: u64,
    pub last_active_epoch: u64,

    pub performance: ValidatorPerformance,

    pub drs_score: f64,
    pub drs_multiplier: f64,
    pub last_drs_update: u64,

    pub puc_coefficient: f64,
    pub peer_degree: u16,
    pub relay_bytes: u64,
    pub iot_sessions: u32,
    pub shard_demand_score: u16,

    pub jail_info: Option<JailInfo>,
    pub slashing_history: Vec<SlashingEvent>,

    pub hot_set_config: ValidatorHotSetConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum ValidatorStatus {
    Active,
    Inactive,
    Jailed,
    Unbonding { release_epoch: u64 },
    Slashed,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ValidatorPerformance {
    pub blocks_proposed: u64,
    pub blocks_missed: u64,
    pub attestations_made: u64,
    pub attestations_missed: u64,
    pub equivocations: u32,
    pub uptime_score: f64,
    pub attestation_accuracy: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct JailInfo {
    pub jailed_at: BlockHeight,
    pub release_at: BlockHeight,
    pub reason: JailReason,
    pub slashed_amount: Balance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum JailReason {
    ExcessiveMisses { consecutive: u32 },
    Equivocation,
    InvalidProof,
    Downtime { epochs_missed: u64 },
    Slashing,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct SlashingEvent {
    pub timestamp: Timestamp,
    pub epoch: u64,
    pub amount: Balance,
    pub reason: String,
    pub evidence_hash: Hash,
    pub event_type: SlashingType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum SlashingType {
    PostMiss,
    PostInvalid,
    PoCFraud,
    Equivocation,
    DataUnavailability,
    ContractViolation,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ValidatorHotSetConfig {
    pub keep_headers_forever: bool,
    pub keep_qcs_forever: bool,
    pub keep_recent_bodies_epochs: u64,
    pub keep_state_db: bool,
    pub mempool_enabled: bool,
    pub fetch_on_demand_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct SliceConfig {
    pub slice_id: String,
    pub slice_type: SliceType,

    pub owner: Address,
    pub authorized_devices: Vec<Address>,
    pub authorized_contracts: Vec<Address>,

    pub bandwidth_allocation: u64,
    pub latency_target_ms: u32,
    pub reliability_target: u8,
    pub priority: u8,

    pub max_devices: u32,
    pub storage_quota: u64,
    pub compute_quota: u64,

    pub status: SliceStatus,
    pub current_devices: u32,
    pub current_storage_used: u64,
    pub current_bandwidth_used: u64,

    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub expires_at: Option<Timestamp>,

    pub billing_account: Address,
    pub credits_remaining: Balance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum SliceType {
    EMbb,
    Urllc,
    MMtc,
    Custom { name: String, parameters: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum SliceStatus {
    Active,
    Paused,
    Maintenance,
    Inactive,
    QuotaExceeded,
    CreditsExhausted,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct CrossShardState {
    pub shard_id: ShardId,
    pub last_state_root: Hash,
    pub last_block_height: BlockHeight,
    pub last_finalized_epoch: u64,

    pub pending_receipts_out: VecDeque<Hash>,
    pub pending_receipts_in: VecDeque<Hash>,
    pub receipt_nonce: u64,

    pub sync_status: CrossShardSyncStatus,
    pub last_sync_attempt: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum CrossShardSyncStatus {
    Synced,
    Syncing { progress_percent: u8 },
    Stale { epochs_behind: u64 },
    Disconnected,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PendingReceipt {
    pub receipt: CrossShardReceipt,
    pub created_at: Timestamp,
    pub deadline_epoch: u64,
    pub retry_count: u32,
    pub status: ReceiptStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum ReceiptStatus {
    Pending,
    Transmitted,
    Acknowledged,
    Applied,
    Expired,
    Failed { reason: String },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StateStats {
    pub total_accounts: u64,
    pub eoa_accounts: u64,
    pub device_accounts: u64,
    pub validator_accounts: u64,
    pub storage_provider_accounts: u64,
    pub contract_accounts: u64,
    pub total_balance: Balance,

    pub storage_entries: u64,
    pub total_storage_bytes: u64,
    pub archival_chunks: u64,
    pub contract_code_chunks: u64,
    pub user_data_chunks: u64,

    pub active_validators: u32,
    pub jailed_validators: u32,
    pub total_staked: Balance,
    pub average_validator_performance: f64,

    pub active_slices: u32,
    pub total_slice_bandwidth: u64,

    pub pending_cross_shard_receipts: u64,
    pub cross_shard_throughput_per_sec: u64,

    pub total_post_challenges: u64,
    pub post_pass_rate: f64,
    pub sectors_under_post: u64,

    pub last_updated: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PruningConfig {
    pub enabled: bool,
    pub keep_epochs: u64,
    pub prune_interval_epochs: u64,
    pub keep_headers_forever: bool,
    pub keep_state_snapshots: bool,
    pub snapshot_interval_epochs: u64,

    pub prune_old_bodies: bool,
    pub prune_old_receipts: bool,
    pub prune_old_events: bool,
    pub prune_expired_storage: bool,
}

impl Default for PruningConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            keep_epochs: DEFAULT_PRUNING_EPOCHS,
            prune_interval_epochs: 10,
            keep_headers_forever: true,
            keep_state_snapshots: true,
            snapshot_interval_epochs: DEFAULT_SNAPSHOT_INTERVAL,
            prune_old_bodies: true,
            prune_old_receipts: true,
            prune_old_events: true,
            prune_expired_storage: true,
        }
    }
}

impl StateManager {
    pub fn new(chain_id: u32, network_id: u32) -> Self {
        Self {
            accounts: Arc::new(DashMap::new()),
            storage: Arc::new(DashMap::new()),
            validators: Arc::new(DashMap::new()),
            slices: Arc::new(DashMap::new()),
            cross_shard_state: Arc::new(DashMap::new()),
            pending_receipts: Arc::new(DashMap::new()),
            processed_receipt_nonces: Arc::new(DashMap::new()),
            state_root: Arc::new(Mutex::new(Hash::ZERO)),
            block_height: Arc::new(Mutex::new(BlockHeight::GENESIS)),
            tx_root: Arc::new(Mutex::new(Hash::ZERO)),
            receipts_root: Arc::new(Mutex::new(Hash::ZERO)),
            events_root_post: Arc::new(Mutex::new(Hash::ZERO)),
            events_root_poc: Arc::new(Mutex::new(Hash::ZERO)),
            rollup_root: Arc::new(Mutex::new(Hash::ZERO)),
            da_root: Arc::new(Mutex::new(Hash::ZERO)),
            stats: Arc::new(Mutex::new(StateStats::default())),
            pruning_config: PruningConfig::default(),
            chain_id,
            network_id,
        }
    }

    pub fn with_pruning_config(mut self, config: PruningConfig) -> Self {
        self.pruning_config = config;
        self
    }

    pub fn get_account(&self, address: &Address) -> Option<Account> {
        self.accounts.get(address).map(|entry| entry.clone())
    }

    pub fn set_account(&self, account: Account) {
        let address = account.address;
        self.accounts.insert(address, account);
    }

    pub fn account_exists(&self, address: &Address) -> bool {
        self.accounts.contains_key(address)
    }

    /// Returns a snapshot of all accounts for persistence.
    pub fn all_accounts(&self) -> Vec<Account> {
        self.accounts.iter().map(|e| e.value().clone()).collect()
    }

    pub fn create_account(&self, address: Address, account_type: AccountType) -> EgoResult<()> {
        if self.accounts.contains_key(&address) {
            return Err(EgoError::InvalidTransaction(
                "Account already exists".to_string(),
            ));
        }

        let account = match account_type {
            AccountType::EOA => Account::new_eoa(address, vec![0u8; 1312], vec![0u8; 1184]),

            AccountType::Device { device_id, geohash } => {
                let capabilities = crate::account::DeviceCapabilities {
                    bandwidth_capacity: 100_000_000,
                    storage_capacity: 100_000_000,
                    supported_slices: Vec::new(),
                    coverage_area: geohash,
                    hardware_specs: HashMap::new(),
                    last_poc: None,
                    post_stats: Default::default(),
                    cellular_safe: true,
                    max_bandwidth_cellular: 50_000_000,
                    monthly_data_limit_gb: 10,
                    cost_awareness: Default::default(),
                };
                Account::new_device(
                    address,
                    device_id,
                    capabilities,
                    vec![0u8; 1312],
                    vec![0u8; 1184],
                    format!("peer_{}", address),
                )
            }

            AccountType::Validator {
                validator_pubkey,
                commission_rate,
                is_active: _,
            } => Account::new_validator(
                address,
                validator_pubkey,
                commission_rate,
                Balance::ZERO,
                vec![0u8; 1312],
                vec![0u8; 1184],
            )?,

            AccountType::StorageProvider {
                provider_id,
                region,
            } => Account::new_storage_provider(
                address,
                provider_id,
                region,
                1_000_000_000_000,
                vec![0u8; 1312],
                vec![0u8; 1184],
                format!("peer_{}", address),
            ),

            AccountType::Hybrid { roles } => Account::new_hybrid_node(
                address,
                roles,
                1_000_000_000_000,
                vec![0u8; 1312],
                vec![0u8; 1184],
                format!("peer_{}", address),
            ),

            AccountType::Contract {
                code_hash,
                state_root,
            } => {
                return Err(EgoError::InvalidTransaction(
                    "Contract accounts must be created through deployment".to_string(),
                ));
            }

            AccountType::System { purpose } => {
                return Err(EgoError::InvalidTransaction(
                    "System accounts cannot be created directly".to_string(),
                ));
            }
        };

        self.accounts.insert(address, account);
        Ok(())
    }

    pub fn register_storage_entry(&self, entry: StorageEntry) -> EgoResult<()> {
        if self.storage.contains_key(&entry.chunk_id) {
            return Err(EgoError::InvalidTransaction(
                "Storage entry already exists".to_string(),
            ));
        }

        if entry.triad.diversity_score < 0.5 {
            return Err(EgoError::InvalidTransaction(
                "Triad diversity too low".to_string(),
            ));
        }

        for member in [
            &entry.triad.primary,
            &entry.triad.replica_a,
            &entry.triad.replica_b,
        ] {
            let account = self
                .get_account(&member.node_id)
                .ok_or(EgoError::AccountNotFound {
                    account_id: member.node_id.to_string(),
                })?;

            if !account.is_storage_provider() {
                return Err(EgoError::InvalidTransaction(format!(
                    "Node {} is not a storage provider",
                    member.node_id
                )));
            }
        }

        self.storage.insert(entry.chunk_id, entry);
        Ok(())
    }

    pub fn get_storage_entry(&self, chunk_id: &Hash) -> Option<StorageEntry> {
        self.storage.get(chunk_id).map(|e| e.clone())
    }

    pub fn update_post_result(
        &self,
        chunk_id: &Hash,
        node_id: &Address,
        passed: bool,
        latency_ms: u32,
        epoch: u64,
    ) -> EgoResult<()> {
        let mut entry = self
            .storage
            .get_mut(chunk_id)
            .ok_or(EgoError::InvalidTransaction(
                "Storage entry not found".to_string(),
            ))?;

        entry.post_stats.total_challenges += 1;
        entry.last_audit_epoch = epoch;

        if passed {
            entry.post_stats.passed_challenges += 1;
            entry.integrity_verified = true;
            entry.last_verified_epoch = epoch;
            entry.verification_failures = 0;
        } else {
            entry.post_stats.failed_challenges += 1;
            entry.verification_failures += 1;
        }

        entry.post_stats.pass_rate = (entry.post_stats.passed_challenges as f64
            / entry.post_stats.total_challenges as f64)
            * 100.0;

        let total = entry.post_stats.total_challenges;
        entry.post_stats.avg_latency_ms = ((entry.post_stats.avg_latency_ms as u64 * (total - 1)
            + latency_ms as u64)
            / total) as u32;

        let member = match () {
            _ if entry.triad.primary.node_id == *node_id => &mut entry.triad.primary,
            _ if entry.triad.replica_a.node_id == *node_id => &mut entry.triad.replica_a,
            _ if entry.triad.replica_b.node_id == *node_id => &mut entry.triad.replica_b,
            _ => {
                return Err(EgoError::InvalidTransaction(
                    "Node not in triad".to_string(),
                ))
            }
        };

        if passed {
            member.consecutive_misses = 0;
            member.health_score = (member.health_score + 1000).min(100000);
        } else {
            member.consecutive_misses += 1;
            member.health_score = member.health_score.saturating_sub(5000);
        }

        if let Some(mut account) = self.accounts.get_mut(node_id) {
            account.record_post_proof(passed, latency_ms, epoch);
        }

        Ok(())
    }

    pub fn get_chunks_by_data_type(&self, data_type: StorageDataType) -> Vec<StorageEntry> {
        self.storage
            .iter()
            .filter(|entry| entry.data_type == data_type)
            .map(|entry| entry.clone())
            .collect()
    }

    pub fn prune_expired_storage(&self, current_height: BlockHeight) -> EgoResult<Vec<Hash>> {
        if !self.pruning_config.prune_expired_storage {
            return Ok(Vec::new());
        }

        let mut pruned = Vec::new();

        self.storage.retain(|chunk_id, entry| {
            if entry.expires_at <= current_height {
                pruned.push(*chunk_id);
                false
            } else {
                true
            }
        });

        Ok(pruned)
    }

    pub fn register_validator(&self, info: ValidatorInfo) -> EgoResult<()> {
        if info.total_stake.as_u128() < MIN_VALIDATOR_STAKE {
            return Err(EgoError::InvalidTransaction(format!(
                "Minimum stake is {} uEGOC",
                MIN_VALIDATOR_STAKE
            )));
        }

        if info.commission_rate > 10000 {
            return Err(EgoError::InvalidTransaction(
                "Commission rate cannot exceed 100%".to_string(),
            ));
        }

        self.validators.insert(info.address, info);
        Ok(())
    }

    /// Register a validator that qualified via Proof-of-Replication or Proof-of-Coverage.
    /// Does NOT require minimum stake — useful work proof is the entry criterion.
    pub fn register_storage_validator(&self, info: ValidatorInfo) -> EgoResult<()> {
        if info.commission_rate > 10000 {
            return Err(EgoError::InvalidTransaction(
                "Commission rate cannot exceed 100%".to_string(),
            ));
        }
        self.validators.insert(info.address, info);
        Ok(())
    }

    pub fn get_validator(&self, address: &Address) -> Option<ValidatorInfo> {
        self.validators.get(address).map(|v| v.clone())
    }

    pub fn update_validator_metrics(
        &self,
        address: &Address,
        uptime_percent: u8,
        peer_degree: u16,
        relay_bytes: u64,
        iot_sessions: u32,
        shard_demand_score: u16,
        puc_coefficient: f64,
    ) -> EgoResult<()> {
        let mut validator = self
            .validators
            .get_mut(address)
            .ok_or(EgoError::AccountNotFound {
                account_id: address.to_string(),
            })?;

        validator.performance.uptime_score = uptime_percent as f64;
        validator.peer_degree = peer_degree;
        validator.relay_bytes = relay_bytes;
        validator.iot_sessions = iot_sessions;
        validator.shard_demand_score = shard_demand_score;
        validator.puc_coefficient = puc_coefficient.clamp(1.0, 1.25);

        Ok(())
    }

    pub fn update_validator_drs(
        &self,
        address: &Address,
        drs_score: f64,
        drs_multiplier: f64,
        epoch: u64,
    ) -> EgoResult<()> {
        let mut validator = self
            .validators
            .get_mut(address)
            .ok_or(EgoError::AccountNotFound {
                account_id: address.to_string(),
            })?;

        validator.drs_score = drs_score;
        validator.drs_multiplier = drs_multiplier.clamp(0.7, 1.3);
        validator.last_drs_update = epoch;

        if let Some(mut account) = self.accounts.get_mut(address) {
            account.update_drs_score(drs_score, epoch);
        }

        Ok(())
    }

    pub fn jail_validator(
        &self,
        address: &Address,
        reason: JailReason,
        release_epochs: u64,
        slash_amount: Balance,
    ) -> EgoResult<()> {
        let current_height = *self.block_height.lock().unwrap();
        let mut validator = self
            .validators
            .get_mut(address)
            .ok_or(EgoError::AccountNotFound {
                account_id: address.to_string(),
            })?;

        validator.status = ValidatorStatus::Jailed;
        validator.jail_info = Some(JailInfo {
            jailed_at: current_height,
            release_at: BlockHeight::new(current_height.as_u64() + release_epochs),
            reason,
            slashed_amount: slash_amount,
        });

        if slash_amount.as_u128() > 0 {
            validator.total_stake = validator
                .total_stake
                .checked_sub(slash_amount)
                .unwrap_or(Balance::ZERO);
            validator.own_stake = validator
                .own_stake
                .checked_sub(slash_amount)
                .unwrap_or(Balance::ZERO);
        }

        Ok(())
    }

    pub fn get_active_validators(&self) -> Vec<ValidatorInfo> {
        self.validators
            .iter()
            .filter(|entry| entry.status == ValidatorStatus::Active)
            .map(|entry| entry.clone())
            .collect()
    }

    pub fn get_total_staked(&self) -> Balance {
        self.validators
            .iter()
            .map(|entry| entry.total_stake)
            .fold(Balance::ZERO, |acc, stake| {
                acc.checked_add(stake).unwrap_or(acc)
            })
    }

    pub fn create_slice(&self, config: SliceConfig) -> EgoResult<()> {
        if self.slices.contains_key(&config.slice_id) {
            return Err(EgoError::InvalidTransaction(
                "Slice already exists".to_string(),
            ));
        }

        if !self.account_exists(&config.owner) {
            return Err(EgoError::AccountNotFound {
                account_id: config.owner.to_string(),
            });
        }

        self.slices.insert(config.slice_id.clone(), config);
        Ok(())
    }

    pub fn get_slice(&self, slice_id: &str) -> Option<SliceConfig> {
        self.slices.get(slice_id).map(|s| s.clone())
    }

    pub fn authorize_device_for_slice(
        &self,
        slice_id: &str,
        device_addr: Address,
    ) -> EgoResult<()> {
        let mut slice = self
            .slices
            .get_mut(slice_id)
            .ok_or(EgoError::InvalidTransaction("Slice not found".to_string()))?;

        if slice.authorized_devices.contains(&device_addr) {
            return Ok(());
        }

        if slice.current_devices >= slice.max_devices {
            return Err(EgoError::InvalidTransaction(
                "Slice device limit reached".to_string(),
            ));
        }

        slice.authorized_devices.push(device_addr);
        slice.current_devices += 1;

        if let Some(mut account) = self.accounts.get_mut(&device_addr) {
            account.authorize_slice(SliceId::new(slice_id.to_string()));
        }

        Ok(())
    }

    pub fn update_slice_usage(
        &self,
        slice_id: &str,
        storage_used: u64,
        bandwidth_used: u64,
    ) -> EgoResult<()> {
        let mut slice = self
            .slices
            .get_mut(slice_id)
            .ok_or(EgoError::InvalidTransaction("Slice not found".to_string()))?;

        slice.current_storage_used = slice.current_storage_used.saturating_add(storage_used);
        slice.current_bandwidth_used = slice.current_bandwidth_used.saturating_add(bandwidth_used);

        if slice.current_storage_used > slice.storage_quota {
            slice.status = SliceStatus::QuotaExceeded;
        }

        slice.updated_at = Timestamp::now();
        Ok(())
    }

    pub fn init_cross_shard_state(&self, shard_id: ShardId) -> EgoResult<()> {
        if self.cross_shard_state.contains_key(&shard_id) {
            return Ok(());
        }

        let state = CrossShardState {
            shard_id,
            last_state_root: Hash::ZERO,
            last_block_height: BlockHeight::GENESIS,
            last_finalized_epoch: 0,
            pending_receipts_out: VecDeque::new(),
            pending_receipts_in: VecDeque::new(),
            receipt_nonce: 0,
            sync_status: CrossShardSyncStatus::Synced,
            last_sync_attempt: Timestamp::now(),
        };

        self.cross_shard_state.insert(shard_id, state);
        Ok(())
    }

    pub fn add_cross_shard_receipt(&self, receipt: CrossShardReceipt) -> EgoResult<()> {
        let key = (receipt.src_shard, receipt.dst_shard);
        if let Some(nonces) = self.processed_receipt_nonces.get(&key) {
            if nonces.contains(&receipt.nonce) {
                return Err(EgoError::InvalidTransaction(
                    "Receipt nonce already processed".to_string(),
                ));
            }
        }

        let current_epoch = self.get_current_epoch();
        if receipt.deadline_epoch < current_epoch {
            return Err(EgoError::InvalidTransaction(
                "Receipt deadline expired".to_string(),
            ));
        }

        if self.pending_receipts.len() >= MAX_CROSS_SHARD_RECEIPTS {
            return Err(EgoError::InvalidTransaction(
                "Pending receipt queue full".to_string(),
            ));
        }

        let pending = PendingReceipt {
            receipt: receipt.clone(),
            created_at: Timestamp::now(),
            deadline_epoch: receipt.deadline_epoch,
            retry_count: 0,
            status: ReceiptStatus::Pending,
        };

        self.pending_receipts.insert(receipt.tx_id, pending);

        if let Some(mut state) = self.cross_shard_state.get_mut(&receipt.dst_shard) {
            state.pending_receipts_out.push_back(receipt.tx_id);
        }

        Ok(())
    }

    pub fn process_cross_shard_receipt(&self, tx_id: &Hash) -> EgoResult<TransactionResult> {
        let mut pending =
            self.pending_receipts
                .get_mut(tx_id)
                .ok_or(EgoError::InvalidTransaction(
                    "Receipt not found".to_string(),
                ))?;

        let current_epoch = self.get_current_epoch();
        if pending.deadline_epoch < current_epoch {
            pending.status = ReceiptStatus::Expired;
            return Err(EgoError::InvalidTransaction("Receipt expired".to_string()));
        }

        pending.status = ReceiptStatus::Applied;

        let key = (pending.receipt.src_shard, pending.receipt.dst_shard);
        self.processed_receipt_nonces
            .entry(key)
            .or_insert_with(HashSet::new)
            .insert(pending.receipt.nonce);

        drop(pending);
        self.pending_receipts.remove(tx_id);

        Ok(TransactionResult {
            tx_hash: *tx_id,
            success: true,
            error: None,
            ru_used: 1500,
            storage_used: 0,
            state_changes: Vec::new(),
            events: vec![TransactionEvent {
                event_type: "cross_shard_receipt_processed".to_string(),
                data: format!("Receipt {} processed", tx_id),
                block_height: self.get_block_height().as_u64(),
                tx_index: 0,
            }],
            cross_shard_receipts: Vec::new(),
            pq_verification_result: None,
            proof_verifications: Vec::new(),
        })
    }

    /// Apply an inbound cross-shard receipt on the **destination** shard.
    ///
    /// This is called by the relay layer (ego-node) when a receipt arrives over
    /// gossip from another shard.  It:
    ///   1. Checks the nonce hasn't already been applied (replay protection)
    ///   2. Decodes the `CrossShardMessage` from the receipt payload
    ///   3. Credits the recipient / calls the contract
    ///   4. Marks the nonce as processed
    pub fn apply_inbound_receipt(&mut self, receipt: &CrossShardReceipt) -> EgoResult<()> {
        use crate::transaction::CrossShardMessage;

        // Replay protection — reject already-applied nonces.
        let key = (receipt.src_shard, receipt.dst_shard);
        if let Some(nonces) = self.processed_receipt_nonces.get(&key) {
            if nonces.contains(&receipt.nonce) {
                return Err(EgoError::InvalidTransaction(
                    "cross-shard receipt already applied".into(),
                ));
            }
        }

        // Deadline check.
        let current_epoch = self.get_current_epoch();
        if receipt.deadline_epoch < current_epoch {
            return Err(EgoError::InvalidTransaction(
                "cross-shard receipt expired".into(),
            ));
        }

        // Decode the typed message.
        let msg = CrossShardMessage::decode(&receipt.payload).ok_or_else(|| {
            EgoError::InvalidTransaction("cross-shard receipt: malformed payload".into())
        })?;

        // Apply the state change on this shard.
        match msg {
            CrossShardMessage::Transfer { to, amount } => {
                if amount.as_u128() > 0 {
                    let mut recipient = self
                        .get_account(&to)
                        .unwrap_or_else(|| {
                            Account::new_eoa(to, vec![0u8; 1312], vec![0u8; 1184])
                        });
                    recipient.credit(amount)?;
                    self.set_account(recipient);
                }
            }
            CrossShardMessage::ContractCall { contract, method, args, value, original_sender: _ } => {
                // Credit the contract with the transferred value before calling it.
                if value.as_u128() > 0 {
                    let mut contract_acct = self
                        .get_account(&contract)
                        .unwrap_or_else(|| {
                            Account::new_eoa(contract, vec![0u8; 1312], vec![0u8; 1184])
                        });
                    contract_acct.credit(value)?;
                    self.set_account(contract_acct);
                }
                // Contract execution is handled by ego-vm in the node layer after this returns.
                // We emit an event so the node knows to dispatch the call.
                let _ = (contract, method, args); // used by node layer
            }
        }

        // Record nonce as applied — prevents replay.
        self.processed_receipt_nonces
            .entry(key)
            .or_insert_with(HashSet::new)
            .insert(receipt.nonce);

        Ok(())
    }

    pub fn prune_expired_receipts(&self, current_epoch: u64) -> Vec<Hash> {
        let mut expired = Vec::new();

        self.pending_receipts.retain(|tx_id, pending| {
            if pending.deadline_epoch < current_epoch {
                expired.push(*tx_id);
                false
            } else {
                true
            }
        });

        expired
    }

    pub fn execute_transaction(&mut self, tx: &Transaction) -> EgoResult<TransactionResult> {
        let mut sender = self
            .get_account(&tx.from)
            .ok_or(EgoError::AccountNotFound {
                account_id: tx.from.to_string(),
            })?;

        tx.validate_against_account(&sender)?;

        if tx.ru_estimate > tx.ru_limit {
            return Err(EgoError::InvalidTransaction(
                "RU estimate exceeds limit".to_string(),
            ));
        }

        if tx.is_cross_shard() {
            sender.increment_shard_nonce(tx.shard_id.as_u32());
        } else {
            sender.increment_nonce();
        }

        // Collect base fee: ru_limit × BASE_FEE_PER_RU, subsidised by pob_burn_credits.
        // pob_burn_credits are pre-burned PoB credits that offset the fee 1:1.
        let gross_fee = Balance(tx.ru_limit as u128 * BASE_FEE_PER_RU);
        let subsidy   = Balance(tx.pob_burn_credits as u128);
        let net_fee   = gross_fee.saturating_sub(subsidy);
        if net_fee.as_u128() > 0 {
            sender.debit(net_fee)?;
            // Credit burn address — tokens permanently removed from supply.
            let burn_addr = burn_address();
            let mut burn_acct = self
                .get_account(&burn_addr)
                .unwrap_or_else(|| Account::new_eoa(burn_addr, vec![0u8; 1312], vec![0u8; 1184]));
            burn_acct.credit(net_fee)?;
            self.set_account(burn_acct);
        }

        let result = match &tx.payload {
            TransactionPayload::Transfer {
                to,
                amount,
                stealth_mode,
                memo,
            } => self.execute_transfer(&mut sender, *to, *amount, *stealth_mode, memo.as_ref())?,

            TransactionPayload::CreateAccount {
                account_address,
                account_type,
                initial_balance,
                ..
            } => self.execute_create_account(
                &mut sender,
                *account_address,
                account_type.clone(),
                *initial_balance,
            )?,

            TransactionPayload::UpdateAccount {
                account_address,
                updates,
            } => self.execute_update_account(&mut sender, *account_address, updates)?,

            TransactionPayload::StoreData {
                chunk_id,
                data_size,
                duration_epochs,
                data_hash,
                slice_id,
                storage_credits,
                replication_factor,
                triad_placement,
                erasure_coding,
                encryption_envelope,
            } => self.execute_store_data(
                &mut sender,
                *chunk_id,
                *data_size,
                *duration_epochs,
                *data_hash,
                slice_id.clone(),
                *storage_credits,
                *replication_factor,
                triad_placement,
                erasure_coding,
                encryption_envelope,
            )?,

            TransactionPayload::UpdateTriadPlacement {
                chunk_id,
                new_placement,
                reason,
                ..
            } => self.execute_update_triad(&mut sender, *chunk_id, new_placement, reason)?,

            TransactionPayload::SubmitProofBatch {
                proof_type,
                proofs,
                epoch,
                ..
            } => self.execute_proof_batch(&mut sender, proof_type, proofs, *epoch)?,

            TransactionPayload::PoStResponse {
                challenge_hash,
                proofs,
                latency_ms,
                ..
            } => self.execute_post_response(&mut sender, *challenge_hash, proofs, latency_ms)?,

            TransactionPayload::ClaimRewards {
                node_id,
                epoch,
                reward_buckets,
                drs_multiplier,
                ..
            } => self.execute_claim_rewards(
                &mut sender,
                *node_id,
                *epoch,
                reward_buckets,
                *drs_multiplier,
            )?,

            TransactionPayload::BuyStorageCredits {
                amount,
                credits_byte_months,
                ..
            } => self.execute_buy_storage_credits(&mut sender, *amount, *credits_byte_months)?,

            TransactionPayload::BuyDeployCredits {
                amount, credits, ..
            } => self.execute_buy_deploy_credits(&mut sender, *amount, *credits)?,

            TransactionPayload::Stake {
                amount,
                validator_pubkey,
                commission_rate,
                lock_duration_epochs,
            } => self.execute_stake(
                &mut sender,
                *amount,
                validator_pubkey.clone(),
                *commission_rate,
                *lock_duration_epochs,
            )?,

            TransactionPayload::Unstake {
                amount,
                validator_pubkey,
                unlock_epoch,
            } => self.execute_unstake(
                &mut sender,
                *amount,
                validator_pubkey.clone(),
                *unlock_epoch,
            )?,

            TransactionPayload::Delegate {
                amount,
                validator_pubkey,
            } => self.execute_delegate(&mut sender, *amount, validator_pubkey.clone())?,

            TransactionPayload::UpdateValidatorMetrics {
                validator,
                epoch,
                uptime_percent,
                peer_degree,
                relay_bytes,
                iot_sessions,
                shard_demand_score,
                puc_coefficient,
            } => {
                self.update_validator_metrics(
                    validator,
                    *uptime_percent,
                    *peer_degree,
                    *relay_bytes,
                    *iot_sessions,
                    *shard_demand_score,
                    *puc_coefficient,
                )?;
                self.create_success_result(tx.hash, 1000)
            }

            TransactionPayload::CrossShard {
                target_shard,
                message,
                nonce,
                deadline_epoch,
                ..
            } => self.execute_cross_shard(
                &mut sender,
                tx,
                *target_shard,
                message,
                *nonce,
                *deadline_epoch,
            )?,

            TransactionPayload::UpdateDRS {
                node_id,
                epoch,
                final_multiplier,
                uptime_score,
                post_pass_rate,
                poc_quality_score,
                ..
            } => {
                let drs_score =
                    uptime_score * 0.25 + post_pass_rate * 0.35 + poc_quality_score * 0.40;
                self.update_validator_drs(node_id, drs_score, *final_multiplier, *epoch)?;
                self.create_success_result(tx.hash, 1000)
            }

            TransactionPayload::SliceOperation {
                operation,
                slice_id,
                params,
            } => self.execute_slice_operation(&mut sender, operation, slice_id, params)?,

            _ => self.create_success_result(tx.hash, tx.estimate_resource_units()),
        };

        self.set_account(sender);

        self.update_stats();

        Ok(result)
    }

    fn execute_transfer(
        &mut self,
        sender: &mut Account,
        to: Address,
        amount: Balance,
        stealth_mode: bool,
        memo: Option<&String>,
    ) -> EgoResult<TransactionResult> {
        sender.debit(amount)?;

        let mut recipient = self
            .get_account(&to)
            .unwrap_or_else(|| Account::new_eoa(to, vec![0u8; 1312], vec![0u8; 1184]));
        recipient.credit(amount)?;

        self.set_account(recipient);

        let ru_used = if stealth_mode { 500 } else { 100 };

        Ok(TransactionResult {
            tx_hash: Hash::ZERO,
            success: true,
            error: None,
            ru_used,
            storage_used: 0,
            state_changes: vec![
                StateChange {
                    account: sender.address,
                    change_type: StateChangeType::BalanceUpdate,
                    previous_value: Some(
                        sender
                            .balance
                            .checked_add(amount)
                            .unwrap()
                            .as_u128()
                            .to_le_bytes()
                            .to_vec(),
                    ),
                    new_value: sender.balance.as_u128().to_le_bytes().to_vec(),
                },
                StateChange {
                    account: to,
                    change_type: StateChangeType::BalanceUpdate,
                    previous_value: Some(Balance::ZERO.as_u128().to_le_bytes().to_vec()),
                    new_value: amount.as_u128().to_le_bytes().to_vec(),
                },
            ],
            events: vec![TransactionEvent {
                event_type: "transfer".to_string(),
                data: serde_json::json!({
                    "from": sender.address.to_string(),
                    "to": to.to_string(),
                    "amount": amount.to_string(),
                    "stealth": stealth_mode,
                    "memo": memo
                })
                .to_string(),
                block_height: self.get_block_height().as_u64(),
                tx_index: 0,
            }],
            cross_shard_receipts: Vec::new(),
            pq_verification_result: None,
            proof_verifications: Vec::new(),
        })
    }

    fn execute_create_account(
        &mut self,
        sender: &mut Account,
        account_address: Address,
        account_type: AccountType,
        initial_balance: Balance,
    ) -> EgoResult<TransactionResult> {
        sender.debit(initial_balance)?;

        self.create_account(account_address, account_type.clone())?;

        if initial_balance.as_u128() > 0 {
            let mut new_account = self.get_account(&account_address).unwrap();
            new_account.credit(initial_balance)?;
            self.set_account(new_account);
        }

        Ok(TransactionResult {
            tx_hash: Hash::ZERO,
            success: true,
            error: None,
            ru_used: 1000,
            storage_used: 256,
            state_changes: vec![StateChange {
                account: account_address,
                change_type: StateChangeType::AccountCreation,
                previous_value: None,
                new_value: format!("{:?}", account_type).into_bytes(),
            }],
            events: vec![TransactionEvent {
                event_type: "account_created".to_string(),
                data: serde_json::json!({
                    "address": account_address.to_string(),
                    "creator": sender.address.to_string(),
                    "type": format!("{:?}", account_type)
                })
                .to_string(),
                block_height: self.get_block_height().as_u64(),
                tx_index: 0,
            }],
            cross_shard_receipts: Vec::new(),
            pq_verification_result: None,
            proof_verifications: Vec::new(),
        })
    }

    fn execute_update_account(
        &mut self,
        sender: &mut Account,
        account_address: Address,
        updates: &crate::transaction::AccountUpdates,
    ) -> EgoResult<TransactionResult> {
        if sender.address != account_address {
            return Err(EgoError::InvalidTransaction(
                "Can only update own account".to_string(),
            ));
        }

        let mut account = self
            .get_account(&account_address)
            .ok_or(EgoError::AccountNotFound {
                account_id: account_address.to_string(),
            })?;

        if let Some(quota) = updates.storage_quota {
            account.storage_quota = quota;
        }

        for slice_id in &updates.add_slices {
            account.authorize_slice(slice_id.clone());
        }

        for slice_id in &updates.remove_slices {
            account.authorized_slices.retain(|s| s != slice_id);
        }

        if let Some(caps) = &updates.device_capabilities {
            account.device_capabilities = Some(caps.clone());
        }

        self.set_account(account);

        Ok(self.create_success_result(Hash::ZERO, 500))
    }

    fn execute_store_data(
        &mut self,
        sender: &mut Account,
        chunk_id: Hash,
        data_size: u64,
        duration_epochs: u64,
        data_hash: Hash,
        slice_id: SliceId,
        storage_credits: u64,
        replication_factor: u8,
        triad_placement: &crate::transaction::TriadPlacement,
        erasure_coding: &crate::transaction::ErasureCodingParams,
        encryption_envelope: &Option<crate::transaction::EncryptionEnvelope>,
    ) -> EgoResult<TransactionResult> {
        sender.update_storage_usage(data_size)?;

        if !sender.is_authorized_for_slice(&slice_id) {
            return Err(EgoError::UnauthorizedSlice {
                slice_id: slice_id.as_str().to_string(),
            });
        }

        sender.use_storage_credits(storage_credits)?;

        let current_height = self.get_block_height();

        let triad = TriadInfo {
            group_id: triad_placement.group_id.clone(),
            primary: TriadMember {
                node_id: triad_placement.primary.node_id,
                sector_id: Hash::ZERO,
                replica_id: Hash::ZERO,
                h3_cell: triad_placement.primary.h3_cell.clone(),
                region: triad_placement.primary.region.clone(),
                shard_id: triad_placement.primary.shard_id,
                role: TriadRole::Primary,
                health_score: 100000,
                consecutive_misses: 0,
            },
            replica_a: TriadMember {
                node_id: triad_placement.replica_a.node_id,
                sector_id: Hash::ZERO,
                replica_id: Hash::ZERO,
                h3_cell: triad_placement.replica_a.h3_cell.clone(),
                region: triad_placement.replica_a.region.clone(),
                shard_id: triad_placement.replica_a.shard_id,
                role: TriadRole::ReplicaA,
                health_score: 100000,
                consecutive_misses: 0,
            },
            replica_b: TriadMember {
                node_id: triad_placement.replica_b.node_id,
                sector_id: Hash::ZERO,
                replica_id: Hash::ZERO,
                h3_cell: triad_placement.replica_b.h3_cell.clone(),
                region: triad_placement.replica_b.region.clone(),
                shard_id: triad_placement.replica_b.shard_id,
                role: TriadRole::ReplicaB,
                health_score: 100000,
                consecutive_misses: 0,
            },
            placement_epoch: self.get_current_epoch(),
            diversity_score: triad_placement.diversity_score,
            last_health_check: self.get_current_epoch(),
        };

        let storage_entry = StorageEntry {
            chunk_id,
            data_hash,
            size: data_size,
            data_type: StorageDataType::UserData {
                app_id: "default".to_string(),
            },
            created_at: Timestamp::now(),
            expires_at: BlockHeight::new(current_height.as_u64() + duration_epochs),
            last_audit_epoch: 0,
            triad,
            porep_commitment: Hash::ZERO,
            porep_params_version: 1,
            post_schedule: PostSchedule {
                windows_per_day: 48,
                challenges_per_window: 24,
                sla_ms: 2000,
                next_window: self.get_current_epoch() + 1,
                last_window: 0,
            },
            post_stats: PostStats {
                total_challenges: 0,
                passed_challenges: 0,
                failed_challenges: 0,
                avg_latency_ms: 0,
                pass_rate: 100.0,
                last_proof_epoch: 0,
            },
            erasure_coding: Some(ErasureCodingParams {
                k: erasure_coding.k,
                m: erasure_coding.m,
                codec: match erasure_coding.codec {
                    crate::transaction::ErasureCodec::ReedSolomon => ErasureCodec::ReedSolomon,
                    crate::transaction::ErasureCodec::LDPC => ErasureCodec::LDPC,
                    crate::transaction::ErasureCodec::Fountain => ErasureCodec::Fountain,
                },
                chunk_size: data_size / erasure_coding.k as u64,
            }),
            encryption_envelope: encryption_envelope.as_ref().map(|env| EncryptionMetadata {
                algorithm: "XChaCha20-Poly1305".to_string(),
                key_refs: env
                    .kyber_ciphertexts
                    .iter()
                    .map(|ct| crate::crypto::hash_data(ct))
                    .collect(),
                nonce: env.nonce24.to_vec(),
            }),
            owner: sender.address,
            authorized_readers: Vec::new(),
            storage_credits_locked: storage_credits,
            total_paid: Balance::new(storage_credits as u128),
            slice_id: Some(slice_id.as_str().to_string()),
            integrity_verified: false,
            last_verified_epoch: 0,
            verification_failures: 0,
        };

        self.register_storage_entry(storage_entry)?;

        self.update_slice_usage(slice_id.as_str(), data_size, 0)?;

        Ok(TransactionResult {
            tx_hash: Hash::ZERO,
            success: true,
            error: None,
            ru_used: 1000 + (data_size / 1024) * replication_factor as u64,
            storage_used: data_size,
            state_changes: Vec::new(),
            events: vec![TransactionEvent {
                event_type: "data_stored".to_string(),
                data: serde_json::json!({
                    "chunk_id": chunk_id.to_string(),
                    "owner": sender.address.to_string(),
                    "size": data_size,
                    "rf": replication_factor,
                    "slice_id": slice_id.as_str()
                })
                .to_string(),
                block_height: current_height.as_u64(),
                tx_index: 0,
            }],
            cross_shard_receipts: Vec::new(),
            pq_verification_result: None,
            proof_verifications: Vec::new(),
        })
    }

    fn execute_update_triad(
        &mut self,
        _sender: &mut Account,
        chunk_id: Hash,
        new_placement: &crate::transaction::TriadPlacement,
        reason: &crate::transaction::PlacementUpdateReason,
    ) -> EgoResult<TransactionResult> {
        let mut entry = self
            .storage
            .get_mut(&chunk_id)
            .ok_or(EgoError::InvalidTransaction(
                "Storage entry not found".to_string(),
            ))?;

        match reason {
            crate::transaction::PlacementUpdateReason::NodeFailure
            | crate::transaction::PlacementUpdateReason::AuditFailure => {
                entry.triad.last_health_check = self.get_current_epoch();
            }
            crate::transaction::PlacementUpdateReason::Promotion => {}
            crate::transaction::PlacementUpdateReason::Repair => {}
            _ => {}
        }

        entry.triad.diversity_score = new_placement.diversity_score;
        entry.triad.placement_epoch = self.get_current_epoch();

        Ok(self.create_success_result(Hash::ZERO, 800))
    }

    fn execute_proof_batch(
        &mut self,
        sender: &mut Account,
        proof_type: &ProofType,
        proofs: &[crate::transaction::ProofSubmission],
        epoch: u64,
    ) -> EgoResult<TransactionResult> {
        let mut verifications = Vec::new();
        let start_time = std::time::Instant::now();

        for proof in proofs {
            let latency_ok = proof.latency_ms <= 2000;

            if matches!(proof_type, ProofType::PoSt) {
                if let Err(e) = self.update_post_result(
                    &proof.chunk_id,
                    &sender.address,
                    latency_ok,
                    proof.latency_ms,
                    epoch,
                ) {
                    verifications.push(ProofVerificationResult {
                        proof_type: proof_type.clone(),
                        verified: false,
                        latency_within_sla: latency_ok,
                        verification_time_ms: start_time.elapsed().as_millis() as u32,
                    });
                    continue;
                }
            }

            verifications.push(ProofVerificationResult {
                proof_type: proof_type.clone(),
                verified: true,
                latency_within_sla: latency_ok,
                verification_time_ms: start_time.elapsed().as_millis() as u32,
            });
        }

        Ok(TransactionResult {
            tx_hash: Hash::ZERO,
            success: true,
            error: None,
            ru_used: 2000 + (proofs.len() as u64 * 100),
            storage_used: 0,
            state_changes: Vec::new(),
            events: vec![TransactionEvent {
                event_type: "proof_batch_submitted".to_string(),
                data: serde_json::json!({
                    "node": sender.address.to_string(),
                    "proof_type": format!("{:?}", proof_type),
                    "count": proofs.len(),
                    "epoch": epoch
                })
                .to_string(),
                block_height: self.get_block_height().as_u64(),
                tx_index: 0,
            }],
            cross_shard_receipts: Vec::new(),
            pq_verification_result: None,
            proof_verifications: verifications,
        })
    }

    fn execute_post_response(
        &mut self,
        sender: &mut Account,
        challenge_hash: Hash,
        proofs: &[crate::transaction::PoStProof],
        latency_ms: &[u32],
    ) -> EgoResult<TransactionResult> {
        let mut verifications = Vec::new();

        for (i, proof) in proofs.iter().enumerate() {
            let latency = latency_ms.get(i).copied().unwrap_or(u32::MAX);
            let latency_ok = latency <= 2000;

            self.update_post_result(
                &proof.chunk_id,
                &sender.address,
                latency_ok,
                latency,
                self.get_current_epoch(),
            )?;

            verifications.push(ProofVerificationResult {
                proof_type: ProofType::PoSt,
                verified: latency_ok,
                latency_within_sla: latency_ok,
                verification_time_ms: latency,
            });
        }

        Ok(TransactionResult {
            tx_hash: Hash::ZERO,
            success: true,
            error: None,
            ru_used: 3000 + (proofs.len() as u64 * 150),
            storage_used: 0,
            state_changes: Vec::new(),
            events: vec![TransactionEvent {
                event_type: "post_response".to_string(),
                data: serde_json::json!({
                    "node": sender.address.to_string(),
                    "challenge": challenge_hash.to_string(),
                    "proofs": proofs.len()
                })
                .to_string(),
                block_height: self.get_block_height().as_u64(),
                tx_index: 0,
            }],
            cross_shard_receipts: Vec::new(),
            pq_verification_result: None,
            proof_verifications: verifications,
        })
    }

    fn execute_claim_rewards(
        &mut self,
        sender: &mut Account,
        node_id: Address,
        epoch: u64,
        reward_buckets: &crate::transaction::RewardClaim,
        drs_multiplier: f64,
    ) -> EgoResult<TransactionResult> {
        if sender.address != node_id {
            return Err(EgoError::InvalidTransaction(
                "Can only claim own rewards".to_string(),
            ));
        }

        let adjusted_total =
            Balance::new(((reward_buckets.total.as_u128() as f64) * drs_multiplier) as u128);

        sender.credit(adjusted_total)?;

        Ok(TransactionResult {
            tx_hash: Hash::ZERO,
            success: true,
            error: None,
            ru_used: 1200,
            storage_used: 0,
            state_changes: vec![StateChange {
                account: sender.address,
                change_type: StateChangeType::RewardDistribution,
                previous_value: Some(
                    sender
                        .balance
                        .checked_sub(adjusted_total)
                        .unwrap()
                        .as_u128()
                        .to_le_bytes()
                        .to_vec(),
                ),
                new_value: sender.balance.as_u128().to_le_bytes().to_vec(),
            }],
            events: vec![TransactionEvent {
                event_type: "rewards_claimed".to_string(),
                data: serde_json::json!({
                    "node": node_id.to_string(),
                    "epoch": epoch,
                    "storage": reward_buckets.storage_rewards.to_string(),
                    "consensus": reward_buckets.consensus_rewards.to_string(),
                    "coverage": reward_buckets.coverage_rewards.to_string(),
                    "total": adjusted_total.to_string(),
                    "drs_multiplier": drs_multiplier
                })
                .to_string(),
                block_height: self.get_block_height().as_u64(),
                tx_index: 0,
            }],
            cross_shard_receipts: Vec::new(),
            pq_verification_result: None,
            proof_verifications: Vec::new(),
        })
    }

    fn execute_buy_storage_credits(
        &mut self,
        sender: &mut Account,
        amount: Balance,
        credits_byte_months: u64,
    ) -> EgoResult<TransactionResult> {
        sender.debit(amount)?;
        sender.add_storage_credits(credits_byte_months);

        Ok(TransactionResult {
            tx_hash: Hash::ZERO,
            success: true,
            error: None,
            ru_used: 300,
            storage_used: 0,
            state_changes: vec![StateChange {
                account: sender.address,
                change_type: StateChangeType::StorageCreditsUpdate,
                previous_value: Some(
                    (sender.storage_credits - credits_byte_months)
                        .to_le_bytes()
                        .to_vec(),
                ),
                new_value: sender.storage_credits.to_le_bytes().to_vec(),
            }],
            events: vec![TransactionEvent {
                event_type: "storage_credits_purchased".to_string(),
                data: serde_json::json!({
                    "account": sender.address.to_string(),
                    "amount_paid": amount.to_string(),
                    "credits": credits_byte_months
                })
                .to_string(),
                block_height: self.get_block_height().as_u64(),
                tx_index: 0,
            }],
            cross_shard_receipts: Vec::new(),
            pq_verification_result: None,
            proof_verifications: Vec::new(),
        })
    }

    fn execute_buy_deploy_credits(
        &mut self,
        sender: &mut Account,
        amount: Balance,
        credits: u64,
    ) -> EgoResult<TransactionResult> {
        sender.debit(amount)?;
        sender.deploy_credits = sender.deploy_credits.saturating_add(credits);

        Ok(TransactionResult {
            tx_hash: Hash::ZERO,
            success: true,
            error: None,
            ru_used: 300,
            storage_used: 0,
            state_changes: vec![StateChange {
                account: sender.address,
                change_type: StateChangeType::DeployCreditsUpdate,
                previous_value: Some((sender.deploy_credits - credits).to_le_bytes().to_vec()),
                new_value: sender.deploy_credits.to_le_bytes().to_vec(),
            }],
            events: vec![TransactionEvent {
                event_type: "deploy_credits_purchased".to_string(),
                data: serde_json::json!({
                    "account": sender.address.to_string(),
                    "amount_paid": amount.to_string(),
                    "credits": credits
                })
                .to_string(),
                block_height: self.get_block_height().as_u64(),
                tx_index: 0,
            }],
            cross_shard_receipts: Vec::new(),
            pq_verification_result: None,
            proof_verifications: Vec::new(),
        })
    }

    fn execute_stake(
        &mut self,
        sender: &mut Account,
        amount: Balance,
        validator_pubkey: PublicKey,
        commission_rate: Option<u16>,
        lock_duration_epochs: u64,
    ) -> EgoResult<TransactionResult> {
        sender.debit(amount)?;

        let validator_address = Address::from_public_key(&validator_pubkey);

        if let Some(mut validator_info) = self.validators.get_mut(&validator_address) {
            validator_info.total_stake = validator_info
                .total_stake
                .checked_add(amount)
                .ok_or(EgoError::InvalidTransaction("Stake overflow".to_string()))?;

            if validator_address == sender.address {
                validator_info.own_stake = validator_info
                    .own_stake
                    .checked_add(amount)
                    .ok_or(EgoError::InvalidTransaction("Stake overflow".to_string()))?;
            } else {
                validator_info.delegated_stake = validator_info
                    .delegated_stake
                    .checked_add(amount)
                    .ok_or(EgoError::InvalidTransaction("Stake overflow".to_string()))?;
            }

            validator_info.last_active_epoch = self.get_current_epoch();
        } else {
            if validator_address != sender.address || commission_rate.is_none() {
                return Err(EgoError::InvalidTransaction(
                    "Cannot create validator for another address".to_string(),
                ));
            }

            let commission = commission_rate.unwrap();
            if commission > 10000 {
                return Err(EgoError::InvalidTransaction(
                    "Commission rate cannot exceed 100%".to_string(),
                ));
            }

            if amount.as_u128() < MIN_VALIDATOR_STAKE {
                return Err(EgoError::InvalidTransaction(format!(
                    "Minimum validator stake is {} uEGOC",
                    MIN_VALIDATOR_STAKE
                )));
            }

            let validator_info = ValidatorInfo {
                address: validator_address,
                public_key: validator_pubkey.clone(),
                total_stake: amount,
                own_stake: amount,
                delegated_stake: Balance::ZERO,
                commission_rate: commission,
                status: ValidatorStatus::Active,
                joined_epoch: self.get_current_epoch(),
                last_active_epoch: self.get_current_epoch(),
                performance: ValidatorPerformance {
                    blocks_proposed: 0,
                    blocks_missed: 0,
                    attestations_made: 0,
                    attestations_missed: 0,
                    equivocations: 0,
                    uptime_score: 100.0,
                    attestation_accuracy: 100.0,
                },
                drs_score: 1.0,
                drs_multiplier: 1.0,
                last_drs_update: self.get_current_epoch(),
                puc_coefficient: 1.0,
                peer_degree: 0,
                relay_bytes: 0,
                iot_sessions: 0,
                shard_demand_score: 0,
                jail_info: None,
                slashing_history: Vec::new(),
                hot_set_config: ValidatorHotSetConfig {
                    keep_headers_forever: true,
                    keep_qcs_forever: true,
                    keep_recent_bodies_epochs: 100,
                    keep_state_db: true,
                    mempool_enabled: true,
                    fetch_on_demand_enabled: true,
                },
            };

            self.validators.insert(validator_address, validator_info);
        }

        Ok(TransactionResult {
            tx_hash: Hash::ZERO,
            success: true,
            error: None,
            ru_used: 800,
            storage_used: 0,
            state_changes: Vec::new(),
            events: vec![TransactionEvent {
                event_type: "stake".to_string(),
                data: serde_json::json!({
                    "staker": sender.address.to_string(),
                    "validator": validator_address.to_string(),
                    "amount": amount.to_string(),
                    "lock_duration": lock_duration_epochs
                })
                .to_string(),
                block_height: self.get_block_height().as_u64(),
                tx_index: 0,
            }],
            cross_shard_receipts: Vec::new(),
            pq_verification_result: None,
            proof_verifications: Vec::new(),
        })
    }

    fn execute_unstake(
        &mut self,
        sender: &mut Account,
        amount: Balance,
        validator_pubkey: PublicKey,
        unlock_epoch: u64,
    ) -> EgoResult<TransactionResult> {
        let validator_address = Address::from_public_key(&validator_pubkey);

        let mut validator_info =
            self.validators
                .get_mut(&validator_address)
                .ok_or(EgoError::InvalidTransaction(
                    "Validator does not exist".to_string(),
                ))?;

        if validator_info.total_stake < amount {
            return Err(EgoError::InsufficientBalance {
                required: amount.as_u128(),
                available: validator_info.total_stake.as_u128(),
            });
        }

        validator_info.total_stake =
            validator_info
                .total_stake
                .checked_sub(amount)
                .ok_or(EgoError::InvalidTransaction(
                    "Unstake underflow".to_string(),
                ))?;

        if validator_address == sender.address {
            validator_info.own_stake = validator_info
                .own_stake
                .checked_sub(amount)
                .unwrap_or(Balance::ZERO);
        } else {
            validator_info.delegated_stake = validator_info
                .delegated_stake
                .checked_sub(amount)
                .unwrap_or(Balance::ZERO);
        }

        if validator_info.own_stake.as_u128() < MIN_VALIDATOR_STAKE {
            validator_info.status = ValidatorStatus::Unbonding {
                release_epoch: unlock_epoch,
            };
        }

        sender.credit(amount)?;

        Ok(TransactionResult {
            tx_hash: Hash::ZERO,
            success: true,
            error: None,
            ru_used: 600,
            storage_used: 0,
            state_changes: Vec::new(),
            events: vec![TransactionEvent {
                event_type: "unstake".to_string(),
                data: serde_json::json!({
                    "unstaker": sender.address.to_string(),
                    "validator": validator_address.to_string(),
                    "amount": amount.to_string(),
                    "unlock_epoch": unlock_epoch
                })
                .to_string(),
                block_height: self.get_block_height().as_u64(),
                tx_index: 0,
            }],
            cross_shard_receipts: Vec::new(),
            pq_verification_result: None,
            proof_verifications: Vec::new(),
        })
    }

    fn execute_delegate(
        &mut self,
        sender: &mut Account,
        amount: Balance,
        validator_pubkey: PublicKey,
    ) -> EgoResult<TransactionResult> {
        sender.debit(amount)?;

        let validator_address = Address::from_public_key(&validator_pubkey);

        let mut validator_info =
            self.validators
                .get_mut(&validator_address)
                .ok_or(EgoError::InvalidTransaction(
                    "Validator does not exist".to_string(),
                ))?;

        if validator_info.status != ValidatorStatus::Active {
            return Err(EgoError::InvalidTransaction(
                "Cannot delegate to inactive validator".to_string(),
            ));
        }

        validator_info.total_stake = validator_info
            .total_stake
            .checked_add(amount)
            .ok_or(EgoError::InvalidTransaction("Stake overflow".to_string()))?;

        validator_info.delegated_stake = validator_info.delegated_stake.checked_add(amount).ok_or(
            EgoError::InvalidTransaction("Delegation overflow".to_string()),
        )?;

        Ok(TransactionResult {
            tx_hash: Hash::ZERO,
            success: true,
            error: None,
            ru_used: 400,
            storage_used: 0,
            state_changes: Vec::new(),
            events: vec![TransactionEvent {
                event_type: "delegate".to_string(),
                data: serde_json::json!({
                    "delegator": sender.address.to_string(),
                    "validator": validator_address.to_string(),
                    "amount": amount.to_string()
                })
                .to_string(),
                block_height: self.get_block_height().as_u64(),
                tx_index: 0,
            }],
            cross_shard_receipts: Vec::new(),
            pq_verification_result: None,
            proof_verifications: Vec::new(),
        })
    }

    fn execute_cross_shard(
        &mut self,
        sender: &mut Account,
        tx: &Transaction,
        target_shard: ShardId,
        message: &[u8],
        nonce: u64,
        deadline_epoch: u64,
    ) -> EgoResult<TransactionResult> {
        use crate::transaction::CrossShardMessage;

        // Decode and validate the message before touching any state.
        let msg = CrossShardMessage::decode(message).ok_or_else(|| {
            EgoError::InvalidTransaction("CrossShard: malformed message payload".into())
        })?;

        // Debit sender on this (source) shard for Transfer messages.
        // ContractCall value is also debited here; the dest shard credits the contract.
        let locked_amount = match &msg {
            CrossShardMessage::Transfer { amount, .. } => *amount,
            CrossShardMessage::ContractCall { value, .. } => *value,
        };
        if locked_amount.as_u128() > 0 {
            sender.debit(locked_amount)?;
        }

        // Build the receipt that will be relayed to the destination shard.
        // src_block_hash is Hash::ZERO here — it will be filled in by the
        // relay layer (main.rs) after the block is finalized and has a real hash.
        let receipt = CrossShardReceipt {
            src_shard: tx.shard_id,
            dst_shard: target_shard,
            src_block_hash: Hash::ZERO, // filled post-finalization
            tx_id: tx.hash,
            payload: message.to_vec(),
            nonce,
            deadline_epoch,
            merkle_proof: Vec::new(),
        };

        self.add_cross_shard_receipt(receipt.clone())?;

        Ok(TransactionResult {
            tx_hash: tx.hash,
            success: true,
            error: None,
            ru_used: 1500,
            storage_used: message.len() as u64,
            state_changes: Vec::new(),
            events: vec![TransactionEvent {
                event_type: "cross_shard_initiated".to_string(),
                data: serde_json::json!({
                    "from_shard": tx.shard_id.as_u32(),
                    "to_shard": target_shard.as_u32(),
                    "nonce": nonce,
                    "deadline": deadline_epoch,
                    "locked": locked_amount.as_u128(),
                })
                .to_string(),
                block_height: self.get_block_height().as_u64(),
                tx_index: 0,
            }],
            cross_shard_receipts: vec![receipt],
            pq_verification_result: None,
            proof_verifications: Vec::new(),
        })
    }

    fn execute_slice_operation(
        &mut self,
        sender: &mut Account,
        operation: &crate::transaction::SliceOperationType,
        slice_id: &SliceId,
        params: &HashMap<String, String>,
    ) -> EgoResult<TransactionResult> {
        use crate::transaction::SliceOperationType;

        match operation {
            SliceOperationType::Create => {
                let slice_type = params
                    .get("type")
                    .and_then(|t| match t.as_str() {
                        "embb" => Some(SliceType::EMbb),
                        "urllc" => Some(SliceType::Urllc),
                        "mmtc" => Some(SliceType::MMtc),
                        _ => None,
                    })
                    .unwrap_or(SliceType::EMbb);

                let config = SliceConfig {
                    slice_id: slice_id.as_str().to_string(),
                    slice_type,
                    owner: sender.address,
                    authorized_devices: Vec::new(),
                    authorized_contracts: Vec::new(),
                    bandwidth_allocation: params
                        .get("bandwidth")
                        .and_then(|b| b.parse().ok())
                        .unwrap_or(100_000_000),
                    latency_target_ms: params
                        .get("latency")
                        .and_then(|l| l.parse().ok())
                        .unwrap_or(50),
                    reliability_target: 99,
                    priority: 5,
                    max_devices: 1000,
                    storage_quota: 1_000_000_000,
                    compute_quota: 1_000_000,
                    status: SliceStatus::Active,
                    current_devices: 0,
                    current_storage_used: 0,
                    current_bandwidth_used: 0,
                    created_at: Timestamp::now(),
                    updated_at: Timestamp::now(),
                    expires_at: None,
                    billing_account: sender.address,
                    credits_remaining: Balance::new(1_000_000),
                };

                self.create_slice(config)?;
            }

            SliceOperationType::Authorize => {
                let device_addr_str = params.get("device").ok_or(EgoError::InvalidTransaction(
                    "Missing device address".to_string(),
                ))?;
                let device_addr = hex::decode(device_addr_str)
                    .ok()
                    .and_then(|bytes| {
                        if bytes.len() == 20 {
                            let mut arr = [0u8; 20];
                            arr.copy_from_slice(&bytes);
                            Some(Address::new(arr))
                        } else {
                            None
                        }
                    })
                    .ok_or_else(|| {
                        EgoError::InvalidTransaction("Invalid device address".to_string())
                    })?;

                self.authorize_device_for_slice(slice_id.as_str(), device_addr)?;
            }

            SliceOperationType::Pause => {
                if let Some(mut slice) = self.slices.get_mut(slice_id.as_str()) {
                    if slice.owner != sender.address {
                        return Err(EgoError::InvalidTransaction("Not slice owner".to_string()));
                    }
                    slice.status = SliceStatus::Paused;
                }
            }

            SliceOperationType::Resume => {
                if let Some(mut slice) = self.slices.get_mut(slice_id.as_str()) {
                    if slice.owner != sender.address {
                        return Err(EgoError::InvalidTransaction("Not slice owner".to_string()));
                    }
                    slice.status = SliceStatus::Active;
                }
            }

            SliceOperationType::Delete => {
                if let Some(slice) = self.slices.get(slice_id.as_str()) {
                    if slice.owner != sender.address {
                        return Err(EgoError::InvalidTransaction("Not slice owner".to_string()));
                    }
                }
                self.slices.remove(slice_id.as_str());
            }

            _ => {}
        }

        Ok(self.create_success_result(Hash::ZERO, 2000))
    }

    fn create_success_result(&self, tx_hash: Hash, ru_used: u64) -> TransactionResult {
        TransactionResult {
            tx_hash,
            success: true,
            error: None,
            ru_used,
            storage_used: 0,
            state_changes: Vec::new(),
            events: Vec::new(),
            cross_shard_receipts: Vec::new(),
            pq_verification_result: None,
            proof_verifications: Vec::new(),
        }
    }

    pub fn compute_state_root(&self) -> Hash {
        let mut state_items = Vec::new();
        let config = bincode::config::standard();

        for account_ref in self.accounts.iter() {
            let account = account_ref.value();
            if let Ok(serialized) = bincode::encode_to_vec(&account, config) {
                state_items.push(serialized);
            }
        }

        let tree = crate::crypto::MerkleTree::build(state_items);
        tree.root_hash().unwrap_or(Hash::ZERO)
    }

    pub fn compute_storage_root(&self) -> Hash {
        let mut storage_items = Vec::new();
        let config = bincode::config::standard();

        for storage_ref in self.storage.iter() {
            let entry = storage_ref.value();
            if let Ok(serialized) = bincode::encode_to_vec(&entry, config) {
                storage_items.push(serialized);
            }
        }

        let tree = crate::crypto::MerkleTree::build(storage_items);
        tree.root_hash().unwrap_or(Hash::ZERO)
    }

    pub fn update_all_roots(&self) {
        let state_root = self.compute_state_root();
        *self.state_root.lock().unwrap() = state_root;
    }

    pub fn set_tx_root(&self, root: Hash) {
        *self.tx_root.lock().unwrap() = root;
    }

    pub fn set_receipts_root(&self, root: Hash) {
        *self.receipts_root.lock().unwrap() = root;
    }

    pub fn set_events_root_post(&self, root: Hash) {
        *self.events_root_post.lock().unwrap() = root;
    }

    pub fn set_events_root_poc(&self, root: Hash) {
        *self.events_root_poc.lock().unwrap() = root;
    }

    pub fn set_rollup_root(&self, root: Hash) {
        *self.rollup_root.lock().unwrap() = root;
    }

    pub fn set_da_root(&self, root: Hash) {
        *self.da_root.lock().unwrap() = root;
    }

    pub fn get_state_root(&self) -> Hash {
        *self.state_root.lock().unwrap()
    }

    pub fn get_tx_root(&self) -> Hash {
        *self.tx_root.lock().unwrap()
    }

    pub fn get_receipts_root(&self) -> Hash {
        *self.receipts_root.lock().unwrap()
    }

    pub fn get_events_root_post(&self) -> Hash {
        *self.events_root_post.lock().unwrap()
    }

    pub fn get_events_root_poc(&self) -> Hash {
        *self.events_root_poc.lock().unwrap()
    }

    pub fn get_rollup_root(&self) -> Hash {
        *self.rollup_root.lock().unwrap()
    }

    pub fn get_da_root(&self) -> Hash {
        *self.da_root.lock().unwrap()
    }

    pub fn set_block_height(&mut self, height: BlockHeight) {
        *self.block_height.lock().unwrap() = height;
    }

    pub fn get_block_height(&self) -> BlockHeight {
        *self.block_height.lock().unwrap()
    }

    pub fn get_current_epoch(&self) -> u64 {
        self.get_block_height().as_u64() / 12000
    }

    pub fn increment_block_height(&mut self) {
        let mut height = self.block_height.lock().unwrap();
        *height = BlockHeight::new(height.as_u64() + 1);
    }

    fn update_stats(&self) {
        let mut stats = self.stats.lock().unwrap();

        stats.total_accounts = self.accounts.len() as u64;
        stats.storage_entries = self.storage.len() as u64;
        stats.active_validators = self
            .validators
            .iter()
            .filter(|entry| entry.status == ValidatorStatus::Active)
            .count() as u32;
        stats.jailed_validators = self
            .validators
            .iter()
            .filter(|entry| entry.status == ValidatorStatus::Jailed)
            .count() as u32;
        stats.active_slices = self
            .slices
            .iter()
            .filter(|entry| entry.status == SliceStatus::Active)
            .count() as u32;
        stats.pending_cross_shard_receipts = self.pending_receipts.len() as u64;

        let mut eoa = 0u64;
        let mut device = 0u64;
        let mut validator_accts = 0u64;
        let mut storage_provider = 0u64;
        let mut contract = 0u64;
        let mut total_balance = Balance::ZERO;

        for account_ref in self.accounts.iter() {
            let account = account_ref.value();
            total_balance = total_balance
                .checked_add(account.balance)
                .unwrap_or(total_balance);

            match &account.account_type {
                AccountType::EOA => eoa += 1,
                AccountType::Device { .. } => device += 1,
                AccountType::Validator { .. } => validator_accts += 1,
                AccountType::StorageProvider { .. } => storage_provider += 1,
                AccountType::Contract { .. } => contract += 1,
                AccountType::Hybrid { .. } => {}
                AccountType::System { .. } => {}
            }
        }

        stats.eoa_accounts = eoa;
        stats.device_accounts = device;
        stats.validator_accounts = validator_accts;
        stats.storage_provider_accounts = storage_provider;
        stats.contract_accounts = contract;
        stats.total_balance = total_balance;

        let mut total_storage = 0u64;
        let mut archival = 0u64;
        let mut contract_code = 0u64;
        let mut user_data = 0u64;
        let mut total_post_challenges = 0u64;
        let mut passed_challenges = 0u64;
        let mut sectors = 0u64;

        for storage_ref in self.storage.iter() {
            let entry = storage_ref.value();
            total_storage += entry.size;
            sectors += 1;

            match &entry.data_type {
                StorageDataType::OldBlockBodies { .. } => archival += 1,
                StorageDataType::StateSnapshot { .. } => archival += 1,
                StorageDataType::ContractCode { .. } => contract_code += 1,
                StorageDataType::ContractState { .. } => contract_code += 1,
                StorageDataType::UserData { .. } => user_data += 1,
                StorageDataType::FileStorage { .. } => user_data += 1,
                _ => {}
            }

            total_post_challenges += entry.post_stats.total_challenges;
            passed_challenges += entry.post_stats.passed_challenges;
        }

        stats.total_storage_bytes = total_storage;
        stats.archival_chunks = archival;
        stats.contract_code_chunks = contract_code;
        stats.user_data_chunks = user_data;
        stats.total_post_challenges = total_post_challenges;
        stats.post_pass_rate = if total_post_challenges > 0 {
            (passed_challenges as f64 / total_post_challenges as f64) * 100.0
        } else {
            100.0
        };
        stats.sectors_under_post = sectors;

        let mut total_staked = Balance::ZERO;
        let mut total_performance = 0.0;
        let active_val_count = stats.active_validators;

        for validator_ref in self.validators.iter() {
            let validator = validator_ref.value();
            total_staked = total_staked
                .checked_add(validator.total_stake)
                .unwrap_or(total_staked);
            if validator.status == ValidatorStatus::Active {
                total_performance += validator.performance.uptime_score;
            }
        }

        stats.total_staked = total_staked;
        stats.average_validator_performance = if active_val_count > 0 {
            total_performance / active_val_count as f64
        } else {
            0.0
        };

        let mut total_bandwidth = 0u64;
        for slice_ref in self.slices.iter() {
            let slice = slice_ref.value();
            if slice.status == SliceStatus::Active {
                total_bandwidth += slice.current_bandwidth_used;
            }
        }
        stats.total_slice_bandwidth = total_bandwidth;

        stats.last_updated = Timestamp::now();
    }

    pub fn get_stats(&self) -> StateStats {
        self.update_stats();
        self.stats.lock().unwrap().clone()
    }

    pub fn should_prune(&self) -> bool {
        if !self.pruning_config.enabled {
            return false;
        }

        let current_epoch = self.get_current_epoch();
        current_epoch % self.pruning_config.prune_interval_epochs == 0
    }

    pub fn should_create_snapshot(&self) -> bool {
        if !self.pruning_config.keep_state_snapshots {
            return false;
        }

        let current_epoch = self.get_current_epoch();
        current_epoch % self.pruning_config.snapshot_interval_epochs == 0
    }

    pub fn prune_old_data(&self, current_epoch: u64) -> EgoResult<PruningReport> {
        let mut report = PruningReport::default();

        if !self.pruning_config.enabled {
            return Ok(report);
        }

        let cutoff_epoch = current_epoch.saturating_sub(self.pruning_config.keep_epochs);
        let current_height = self.get_block_height();

        if self.pruning_config.prune_expired_storage {
            let pruned_chunks = self.prune_expired_storage(current_height)?;
            report.storage_entries_pruned = pruned_chunks.len() as u64;
        }

        if self.pruning_config.prune_old_receipts {
            let expired_receipts = self.prune_expired_receipts(current_epoch);
            report.receipts_pruned = expired_receipts.len() as u64;
        }

        self.processed_receipt_nonces.retain(|_, nonces| {
            if nonces.len() > 100000 {
                nonces.clear();
                false
            } else {
                true
            }
        });

        Ok(report)
    }

    pub fn create_state_snapshot(&self) -> EgoResult<StateSnapshot> {
        let snapshot = StateSnapshot {
            epoch: self.get_current_epoch(),
            block_height: self.get_block_height(),
            state_root: self.get_state_root(),
            tx_root: self.get_tx_root(),
            receipts_root: self.get_receipts_root(),
            events_root_post: self.get_events_root_post(),
            events_root_poc: self.get_events_root_poc(),
            rollup_root: self.get_rollup_root(),
            da_root: self.get_da_root(),
            timestamp: Timestamp::now(),
            total_accounts: self.accounts.len() as u64,
            total_validators: self.validators.len() as u32,
            total_storage_entries: self.storage.len() as u64,
            stats: self.get_stats(),
        };

        Ok(snapshot)
    }

    pub fn get_accounts_by_type(&self, account_type: AccountType) -> Vec<Account> {
        self.accounts
            .iter()
            .filter(|entry| {
                std::mem::discriminant(&entry.account_type) == std::mem::discriminant(&account_type)
            })
            .map(|entry| entry.clone())
            .collect()
    }

    pub fn get_storage_providers(&self) -> Vec<Account> {
        self.accounts
            .iter()
            .filter(|entry| entry.is_storage_provider())
            .map(|entry| entry.clone())
            .collect()
    }

    pub fn get_validators_by_status(&self, status: ValidatorStatus) -> Vec<ValidatorInfo> {
        self.validators
            .iter()
            .filter(|entry| entry.status == status)
            .map(|entry| entry.clone())
            .collect()
    }

    pub fn get_top_validators_by_stake(&self, limit: usize) -> Vec<ValidatorInfo> {
        let mut validators: Vec<ValidatorInfo> = self
            .validators
            .iter()
            .filter(|entry| entry.status == ValidatorStatus::Active)
            .map(|entry| entry.clone())
            .collect();

        validators.sort_by(|a, b| b.total_stake.cmp(&a.total_stake));
        validators.truncate(limit);
        validators
    }

    pub fn get_sectors_by_node(&self, node_id: &Address) -> Vec<StorageEntry> {
        self.storage
            .iter()
            .filter(|entry| {
                entry.triad.primary.node_id == *node_id
                    || entry.triad.replica_a.node_id == *node_id
                    || entry.triad.replica_b.node_id == *node_id
            })
            .map(|entry| entry.clone())
            .collect()
    }

    pub fn get_failing_sectors(&self, threshold: u32) -> Vec<StorageEntry> {
        self.storage
            .iter()
            .filter(|entry| entry.verification_failures >= threshold)
            .map(|entry| entry.clone())
            .collect()
    }

    pub fn get_slices_by_owner(&self, owner: &Address) -> Vec<SliceConfig> {
        self.slices
            .iter()
            .filter(|entry| entry.owner == *owner)
            .map(|entry| entry.clone())
            .collect()
    }

    pub fn get_cross_shard_state(&self, shard_id: &ShardId) -> Option<CrossShardState> {
        self.cross_shard_state.get(shard_id).map(|s| s.clone())
    }

    pub fn get_pending_receipts_for_shard(&self, dst_shard: &ShardId) -> Vec<PendingReceipt> {
        self.pending_receipts
            .iter()
            .filter(|entry| entry.receipt.dst_shard == *dst_shard)
            .map(|entry| entry.clone())
            .collect()
    }

    pub fn validate_state_transition(&self, from_root: Hash, to_root: Hash) -> EgoResult<bool> {
        Ok(from_root != to_root || self.accounts.is_empty())
    }

    pub fn verify_triad_health(&self, chunk_id: &Hash) -> EgoResult<TriadHealthReport> {
        let entry = self
            .storage
            .get(chunk_id)
            .ok_or(EgoError::InvalidTransaction(
                "Storage entry not found".to_string(),
            ))?;

        let primary_healthy =
            entry.triad.primary.health_score > 50000 && entry.triad.primary.consecutive_misses < 3;
        let replica_a_healthy = entry.triad.replica_a.health_score > 50000
            && entry.triad.replica_a.consecutive_misses < 3;
        let replica_b_healthy = entry.triad.replica_b.health_score > 50000
            && entry.triad.replica_b.consecutive_misses < 3;

        let healthy_count = [primary_healthy, replica_a_healthy, replica_b_healthy]
            .iter()
            .filter(|&&h| h)
            .count();

        Ok(TriadHealthReport {
            chunk_id: *chunk_id,
            primary_healthy,
            replica_a_healthy,
            replica_b_healthy,
            healthy_replicas: healthy_count as u8,
            needs_repair: healthy_count < 2,
            needs_promotion: !primary_healthy && (replica_a_healthy || replica_b_healthy),
            diversity_score: entry.triad.diversity_score,
            last_audit: entry.last_audit_epoch,
        })
    }

    pub fn get_chain_id(&self) -> u32 {
        self.chain_id
    }

    pub fn get_network_id(&self) -> u32 {
        self.network_id
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PruningReport {
    pub storage_entries_pruned: u64,
    pub receipts_pruned: u64,
    pub accounts_pruned: u64,
    pub validators_pruned: u32,
    pub bytes_reclaimed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub epoch: u64,
    pub block_height: BlockHeight,
    pub state_root: Hash,
    pub tx_root: Hash,
    pub receipts_root: Hash,
    pub events_root_post: Hash,
    pub events_root_poc: Hash,
    pub rollup_root: Hash,
    pub da_root: Hash,
    pub timestamp: Timestamp,
    pub total_accounts: u64,
    pub total_validators: u32,
    pub total_storage_entries: u64,
    pub stats: StateStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriadHealthReport {
    pub chunk_id: Hash,
    pub primary_healthy: bool,
    pub replica_a_healthy: bool,
    pub replica_b_healthy: bool,
    pub healthy_replicas: u8,
    pub needs_repair: bool,
    pub needs_promotion: bool,
    pub diversity_score: f64,
    pub last_audit: u64,
}
