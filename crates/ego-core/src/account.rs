use crate::{Address, Balance, EgoError, EgoResult, Hash, PublicKey, SliceId, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct Account {
    pub address: Address,
    pub balance: Balance,
    pub nonce: u64,
    pub per_shard_nonces: Option<HashMap<u32, u64>>,
    pub created_at: Timestamp,
    pub last_activity: Timestamp,

    pub dilithium_pk: Vec<u8>,
    pub ed25519_pk: Option<Vec<u8>>,
    pub mlkem_pk: Vec<u8>,
    pub x25519_pk: Option<Vec<u8>>,
    pub slh_dsa_pk: Option<Vec<u8>>,

    pub storage_quota: u64,
    pub storage_used: u64,
    pub storage_credits: u64,

    pub deploy_credits: u64,
    pub free_deploys_remaining: u32,
    pub deploy_bond_locked_until: Option<Timestamp>,

    pub staking_info: Option<StakingInfo>,
    pub validator_info: Option<ValidatorInfo>,
    pub storage_provider_info: Option<StorageProviderInfo>,

    pub last_drs_score: Option<u64>,
    pub last_drs_epoch: Option<u64>,

    pub account_type: AccountType,
    pub contract_info: Option<ContractInfo>,

    pub peer_id: Option<String>,
    pub tmp_attestation: Option<Vec<u8>>,

    pub authorized_slices: Vec<SliceId>,
    pub device_capabilities: Option<DeviceCapabilities>,
    pub metadata: HashMap<String, String>,

    pub pq_transition_info: Option<PQTransitionInfo>,

    pub hot_set_mode: HotSetMode,
    pub pruning_config: Option<PruningConfig>,
    pub archival_config: Option<ArchivalConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum HotSetMode {
    Validator,
    StorageProvider,
    FullNode,
    LightClient,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PruningConfig {
    pub enabled: bool,
    pub keep_epochs: u64,
    pub prune_interval_epochs: u64,
    pub keep_headers_forever: bool,
    pub keep_state_snapshots: bool,
    pub snapshot_interval_epochs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ArchivalConfig {
    pub store_old_bodies: bool,
    pub store_contract_blobs: bool,
    pub store_state_snapshots: bool,
    pub store_da_blobs: bool,
    pub store_proof_evidence: bool,
    pub store_user_data: bool,
    pub replication_factor: u8,
    pub erasure_coding_params: Option<(u16, u16)>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct StorageProviderInfo {
    pub node_id: Address,
    pub storage_capacity: u64,
    pub storage_allocated: u64,
    pub active_sectors: Vec<SectorInfo>,
    pub collateral_locked: Balance,
    pub postrep_stats: PostRepStats,
    pub earnings: ProviderEarnings,
    pub slashing_history: Vec<SlashingEvent>,
    pub health_score: u64,
    pub last_audit_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct SectorInfo {
    pub sector_id: Hash,
    pub size_bytes: u64,
    pub data_type: DataType,
    pub sealed_at: Timestamp,
    pub expires_at: Timestamp,
    pub replica_id: Hash,
    pub comm_d: Hash,
    pub comm_r: Hash,
    pub triad: TriadInfo,
    pub params_version: u32,
    pub post_frequency: u64,
    pub last_post_epoch: u64,
    pub miss_count: u32,
    pub integrity_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum DataType {
    BlockBodies,
    ContractCode,
    StateSnapshot,
    DABlob,
    ProofEvidence,
    UserData,
    RollupBatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct TriadInfo {
    pub group_id: String,
    pub role: TriadRole,
    pub primary: Address,
    pub replica_a: Address,
    pub replica_b: Address,
    pub placement_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum TriadRole {
    Primary,
    ReplicaA,
    ReplicaB,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PostRepStats {
    pub porep_proofs_submitted: u64,
    pub post_proofs_submitted: u64,
    pub post_pass_rate: f64,
    pub avg_post_latency_ms: u32,
    pub challenges_answered: u64,
    pub challenges_missed: u64,
    pub last_challenge_epoch: u64,
    pub consecutive_misses: u32,
    pub sectors_sealed: u64,
    pub sectors_faulty: u32,
    pub repairs_completed: u64,
    pub promotions: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ProviderEarnings {
    pub storage_rewards: Balance,
    pub retrieval_fees: Balance,
    pub post_rewards: Balance,
    pub total_earned: Balance,
    pub total_slashed: Balance,
    pub pending_payouts: Balance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PQTransitionInfo {
    pub transition_started_epoch: u64,
    pub pq_only_mode: bool,
    pub ed25519_disabled_epoch: Option<u64>,
    pub supported_algorithms: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ContractInfo {
    pub code_hash: Hash,
    pub code_stored_by: CodeStorageMode,
    pub upgrade_policy: UpgradePolicy,
    pub pointer_name: Option<[u8; 32]>,
    pub state_root: Hash,
    pub state_snapshot_sector: Option<Hash>,
    pub last_snapshot_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum CodeStorageMode {
    OnChain,
    PostAudited {
        sector_id: Hash,
        providers: Vec<Address>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum UpgradePolicy {
    Immutable,
    OwnerOnly,
    Governance,
    Timelock { delay_blocks: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum AccountType {
    EOA,
    Device {
        device_id: String,
        geohash: Option<String>,
    },
    Contract {
        code_hash: Hash,
        state_root: Hash,
    },
    System {
        purpose: String,
    },
    Validator {
        validator_pubkey: PublicKey,
        commission_rate: u16,
        is_active: bool,
    },
    StorageProvider {
        provider_id: String,
        region: String,
    },
    Hybrid {
        roles: Vec<NodeRole>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum NodeRole {
    Validator,
    StorageProvider,
    Gateway,
    Rollup,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DeviceCapabilities {
    pub bandwidth_capacity: u64,
    pub storage_capacity: u64,
    pub supported_slices: Vec<SliceId>,
    pub coverage_area: Option<String>,
    pub hardware_specs: HashMap<String, String>,
    pub last_poc: Option<Timestamp>,
    pub post_stats: PostStats,
    pub cellular_safe: bool,
    pub max_bandwidth_cellular: u64,
    pub monthly_data_limit_gb: u64,
    pub cost_awareness: CostAwareness,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct CostAwareness {
    pub cellular_safe_mode: bool,
    pub max_monthly_cost_usd: f64,
    pub current_month_usage_gb: u64,
    pub wifi_only_operations: Vec<String>,
    pub cellular_throttle_threshold_gb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PostStats {
    pub proofs_submitted: u64,
    pub success_rate: u64,
    pub last_proof: Option<Timestamp>,
    pub challenges_responded: u64,
    pub integrity_score: u8,
    pub proof_frequency_hz: f64,
    pub batch_enabled: bool,
}

impl PartialEq for PostStats {
    fn eq(&self, other: &Self) -> bool {
        self.proofs_submitted == other.proofs_submitted
            && self.success_rate == other.success_rate
            && self.last_proof == other.last_proof
            && self.challenges_responded == other.challenges_responded
            && self.integrity_score == other.integrity_score
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct StakingInfo {
    pub staked_amount: Balance,
    pub delegated_stake: Balance,
    pub rewards_earned: Balance,
    pub slashing_events: Vec<SlashingEvent>,
    pub performance: ValidatorPerformance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ValidatorInfo {
    pub validator_pubkey: PublicKey,
    pub commission_rate: u16,
    pub is_active: bool,
    pub jail_info: Option<JailInfo>,
    pub hot_set_config: ValidatorHotSetConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ValidatorHotSetConfig {
    pub keep_headers_forever: bool,
    pub keep_qcs_forever: bool,
    pub keep_recent_bodies_epochs: u64,
    pub keep_state_db: bool,
    pub mempool_enabled: bool,
    pub fetch_on_demand_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct JailInfo {
    pub jailed_at: Timestamp,
    pub release_at: Timestamp,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct SlashingEvent {
    pub timestamp: Timestamp,
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ValidatorPerformance {
    pub blocks_validated: u64,
    pub uptime_percentage: u64,
    pub attestation_accuracy: u64,
    pub last_active_epoch: u64,
    pub penalties: u32,
}

impl Account {
    pub fn new_eoa(address: Address, dilithium_pk: Vec<u8>, mlkem_pk: Vec<u8>) -> Self {
        let now = Timestamp::now();
        Self {
            address,
            balance: Balance::ZERO,
            nonce: 0,
            per_shard_nonces: Some(HashMap::new()),
            created_at: now,
            last_activity: now,
            dilithium_pk,
            ed25519_pk: None,
            mlkem_pk,
            x25519_pk: None,
            slh_dsa_pk: None,
            storage_quota: 1024 * 1024,
            storage_used: 0,
            storage_credits: 0,
            deploy_credits: 0,
            free_deploys_remaining: 0,
            deploy_bond_locked_until: None,
            staking_info: None,
            validator_info: None,
            storage_provider_info: None,
            last_drs_score: None,
            last_drs_epoch: None,
            account_type: AccountType::EOA,
            contract_info: None,
            peer_id: None,
            tmp_attestation: None,
            authorized_slices: Vec::new(),
            device_capabilities: None,
            metadata: HashMap::new(),
            pq_transition_info: Some(PQTransitionInfo {
                transition_started_epoch: 0,
                pq_only_mode: false,
                ed25519_disabled_epoch: None,
                supported_algorithms: vec![
                    crate::AlgorithmId::MlDsa2.as_u16(),
                    crate::AlgorithmId::Ed25519.as_u16(),
                    crate::AlgorithmId::MlKem768.as_u16(),
                ],
            }),
            hot_set_mode: HotSetMode::LightClient,
            pruning_config: None,
            archival_config: None,
        }
    }

    pub fn new_validator(
        address: Address,
        validator_pubkey: PublicKey,
        commission_rate: u16,
        initial_stake: Balance,
        dilithium_pk: Vec<u8>,
        mlkem_pk: Vec<u8>,
    ) -> EgoResult<Self> {
        if commission_rate > 10000 {
            return Err(EgoError::InvalidTransaction(
                "Commission rate cannot exceed 100%".to_string(),
            ));
        }

        let now = Timestamp::now();
        let staking_info = StakingInfo {
            staked_amount: initial_stake,
            delegated_stake: Balance::ZERO,
            rewards_earned: Balance::ZERO,
            slashing_events: Vec::new(),
            performance: ValidatorPerformance {
                blocks_validated: 0,
                uptime_percentage: 100000,
                attestation_accuracy: 100000,
                last_active_epoch: 0,
                penalties: 0,
            },
        };

        let validator_info = ValidatorInfo {
            validator_pubkey: validator_pubkey.clone(),
            commission_rate,
            is_active: true,
            jail_info: None,
            hot_set_config: ValidatorHotSetConfig {
                keep_headers_forever: true,
                keep_qcs_forever: true,
                keep_recent_bodies_epochs: 100,
                keep_state_db: true,
                mempool_enabled: true,
                fetch_on_demand_enabled: true,
            },
        };

        let pruning_config = PruningConfig {
            enabled: true,
            keep_epochs: 100,
            prune_interval_epochs: 10,
            keep_headers_forever: true,
            keep_state_snapshots: true,
            snapshot_interval_epochs: 1000,
        };

        Ok(Self {
            address,
            balance: Balance::ZERO,
            nonce: 0,
            per_shard_nonces: Some(HashMap::new()),
            created_at: now,
            last_activity: now,
            dilithium_pk,
            ed25519_pk: None,
            mlkem_pk,
            x25519_pk: None,
            slh_dsa_pk: None,
            storage_quota: 10 * 1024 * 1024,
            storage_used: 0,
            storage_credits: 10000,
            deploy_credits: 1000,
            free_deploys_remaining: 20,
            deploy_bond_locked_until: None,
            staking_info: Some(staking_info),
            validator_info: Some(validator_info),
            storage_provider_info: None,
            last_drs_score: Some(100000),
            last_drs_epoch: Some(0),
            account_type: AccountType::Validator {
                validator_pubkey,
                commission_rate,
                is_active: true,
            },
            contract_info: None,
            peer_id: None,
            tmp_attestation: None,
            authorized_slices: Vec::new(),
            device_capabilities: None,
            metadata: HashMap::new(),
            pq_transition_info: Some(PQTransitionInfo {
                transition_started_epoch: 0,
                pq_only_mode: false,
                ed25519_disabled_epoch: None,
                supported_algorithms: vec![
                    crate::AlgorithmId::MlDsa2.as_u16(),
                    crate::AlgorithmId::Ed25519.as_u16(),
                    crate::AlgorithmId::MlKem768.as_u16(),
                ],
            }),
            hot_set_mode: HotSetMode::Validator,
            pruning_config: Some(pruning_config),
            archival_config: None,
        })
    }

    pub fn new_storage_provider(
        address: Address,
        provider_id: String,
        region: String,
        storage_capacity: u64,
        dilithium_pk: Vec<u8>,
        mlkem_pk: Vec<u8>,
        peer_id: String,
    ) -> Self {
        let now = Timestamp::now();

        let storage_provider_info = StorageProviderInfo {
            node_id: address,
            storage_capacity,
            storage_allocated: 0,
            active_sectors: Vec::new(),
            collateral_locked: Balance::ZERO,
            postrep_stats: PostRepStats::default(),
            earnings: ProviderEarnings::default(),
            slashing_history: Vec::new(),
            health_score: 100000,
            last_audit_epoch: 0,
        };

        let archival_config = ArchivalConfig {
            store_old_bodies: true,
            store_contract_blobs: true,
            store_state_snapshots: true,
            store_da_blobs: true,
            store_proof_evidence: true,
            store_user_data: true,
            replication_factor: 3,
            erasure_coding_params: Some((64, 32)),
        };

        Self {
            address,
            balance: Balance::ZERO,
            nonce: 0,
            per_shard_nonces: Some(HashMap::new()),
            created_at: now,
            last_activity: now,
            dilithium_pk,
            ed25519_pk: None,
            mlkem_pk,
            x25519_pk: None,
            slh_dsa_pk: None,
            storage_quota: storage_capacity,
            storage_used: 0,
            storage_credits: 1000,
            deploy_credits: 100,
            free_deploys_remaining: 5,
            deploy_bond_locked_until: None,
            staking_info: None,
            validator_info: None,
            storage_provider_info: Some(storage_provider_info),
            last_drs_score: Some(100000),
            last_drs_epoch: Some(0),
            account_type: AccountType::StorageProvider {
                provider_id,
                region,
            },
            contract_info: None,
            peer_id: Some(peer_id),
            tmp_attestation: None,
            authorized_slices: Vec::new(),
            device_capabilities: None,
            metadata: HashMap::new(),
            pq_transition_info: Some(PQTransitionInfo {
                transition_started_epoch: 0,
                pq_only_mode: false,
                ed25519_disabled_epoch: None,
                supported_algorithms: vec![
                    crate::AlgorithmId::MlDsa2.as_u16(),
                    crate::AlgorithmId::Ed25519.as_u16(),
                    crate::AlgorithmId::MlKem768.as_u16(),
                ],
            }),
            hot_set_mode: HotSetMode::StorageProvider,
            pruning_config: None,
            archival_config: Some(archival_config),
        }
    }

    pub fn new_hybrid_node(
        address: Address,
        roles: Vec<NodeRole>,
        storage_capacity: u64,
        dilithium_pk: Vec<u8>,
        mlkem_pk: Vec<u8>,
        peer_id: String,
    ) -> Self {
        let now = Timestamp::now();
        let is_validator = roles.contains(&NodeRole::Validator);
        let is_storage = roles.contains(&NodeRole::StorageProvider);

        let pruning_config = if is_validator {
            Some(PruningConfig {
                enabled: true,
                keep_epochs: 100,
                prune_interval_epochs: 10,
                keep_headers_forever: true,
                keep_state_snapshots: true,
                snapshot_interval_epochs: 1000,
            })
        } else {
            None
        };

        let archival_config = if is_storage {
            Some(ArchivalConfig {
                store_old_bodies: true,
                store_contract_blobs: true,
                store_state_snapshots: true,
                store_da_blobs: true,
                store_proof_evidence: true,
                store_user_data: true,
                replication_factor: 3,
                erasure_coding_params: Some((64, 32)),
            })
        } else {
            None
        };

        let storage_provider_info = if is_storage {
            Some(StorageProviderInfo {
                node_id: address,
                storage_capacity,
                storage_allocated: 0,
                active_sectors: Vec::new(),
                collateral_locked: Balance::ZERO,
                postrep_stats: PostRepStats::default(),
                earnings: ProviderEarnings::default(),
                slashing_history: Vec::new(),
                health_score: 100000,
                last_audit_epoch: 0,
            })
        } else {
            None
        };

        Self {
            address,
            balance: Balance::ZERO,
            nonce: 0,
            per_shard_nonces: Some(HashMap::new()),
            created_at: now,
            last_activity: now,
            dilithium_pk,
            ed25519_pk: None,
            mlkem_pk,
            x25519_pk: None,
            slh_dsa_pk: None,
            storage_quota: storage_capacity,
            storage_used: 0,
            storage_credits: 10000,
            deploy_credits: 1000,
            free_deploys_remaining: 10,
            deploy_bond_locked_until: None,
            staking_info: None,
            validator_info: None,
            storage_provider_info,
            last_drs_score: Some(100000),
            last_drs_epoch: Some(0),
            account_type: AccountType::Hybrid { roles },
            contract_info: None,
            peer_id: Some(peer_id),
            tmp_attestation: None,
            authorized_slices: Vec::new(),
            device_capabilities: None,
            metadata: HashMap::new(),
            pq_transition_info: Some(PQTransitionInfo {
                transition_started_epoch: 0,
                pq_only_mode: false,
                ed25519_disabled_epoch: None,
                supported_algorithms: vec![
                    crate::AlgorithmId::MlDsa2.as_u16(),
                    crate::AlgorithmId::Ed25519.as_u16(),
                    crate::AlgorithmId::MlKem768.as_u16(),
                ],
            }),
            hot_set_mode: HotSetMode::FullNode,
            pruning_config,
            archival_config,
        }
    }

    pub fn new_device(
        address: Address,
        device_id: String,
        capabilities: DeviceCapabilities,
        dilithium_pk: Vec<u8>,
        mlkem_pk: Vec<u8>,
        peer_id: String,
    ) -> Self {
        let now = Timestamp::now();

        Self {
            address,
            balance: Balance::ZERO,
            nonce: 0,
            per_shard_nonces: Some(HashMap::new()),
            created_at: now,
            last_activity: now,
            dilithium_pk,
            ed25519_pk: None,
            mlkem_pk,
            x25519_pk: None,
            slh_dsa_pk: None,
            storage_quota: capabilities.storage_capacity,
            storage_used: 0,
            storage_credits: 100,
            deploy_credits: 10,
            free_deploys_remaining: 5,
            deploy_bond_locked_until: None,
            staking_info: None,
            validator_info: None,
            storage_provider_info: None,
            last_drs_score: None,
            last_drs_epoch: None,
            account_type: AccountType::Device {
                device_id,
                geohash: None,
            },
            contract_info: None,
            peer_id: Some(peer_id),
            tmp_attestation: None,
            authorized_slices: Vec::new(),
            device_capabilities: Some(capabilities),
            metadata: HashMap::new(),
            pq_transition_info: Some(PQTransitionInfo {
                transition_started_epoch: 0,
                pq_only_mode: false,
                ed25519_disabled_epoch: None,
                supported_algorithms: vec![
                    crate::AlgorithmId::MlDsa2.as_u16(),
                    crate::AlgorithmId::Ed25519.as_u16(),
                    crate::AlgorithmId::MlKem768.as_u16(),
                ],
            }),
            hot_set_mode: HotSetMode::LightClient,
            pruning_config: None,
            archival_config: None,
        }
    }

    pub fn add_sector(&mut self, sector: SectorInfo) -> EgoResult<()> {
        let provider_info = self.storage_provider_info.as_mut().ok_or_else(|| {
            EgoError::InvalidTransaction("Account is not a storage provider".to_string())
        })?;

        if provider_info.storage_allocated + sector.size_bytes > provider_info.storage_capacity {
            return Err(EgoError::StorageQuotaExceeded {
                used: provider_info.storage_allocated + sector.size_bytes,
                limit: provider_info.storage_capacity,
            });
        }

        provider_info.storage_allocated += sector.size_bytes;
        provider_info.active_sectors.push(sector);
        provider_info.postrep_stats.sectors_sealed += 1;
        self.last_activity = Timestamp::now();

        Ok(())
    }

    pub fn remove_sector(&mut self, sector_id: &Hash) -> EgoResult<()> {
        let provider_info = self.storage_provider_info.as_mut().ok_or_else(|| {
            EgoError::InvalidTransaction("Account is not a storage provider".to_string())
        })?;

        if let Some(pos) = provider_info
            .active_sectors
            .iter()
            .position(|s| &s.sector_id == sector_id)
        {
            let sector = provider_info.active_sectors.remove(pos);
            provider_info.storage_allocated = provider_info
                .storage_allocated
                .saturating_sub(sector.size_bytes);
            self.last_activity = Timestamp::now();
            Ok(())
        } else {
            Err(EgoError::InvalidTransaction("Sector not found".to_string()))
        }
    }

    pub fn record_post_proof(&mut self, success: bool, latency_ms: u32, epoch: u64) {
        if let Some(ref mut provider_info) = self.storage_provider_info {
            provider_info.postrep_stats.post_proofs_submitted += 1;
            provider_info.last_audit_epoch = epoch;

            if success {
                provider_info.postrep_stats.challenges_answered += 1;
                provider_info.postrep_stats.consecutive_misses = 0;

                let total_challenges = provider_info.postrep_stats.challenges_answered
                    + provider_info.postrep_stats.challenges_missed;
                if total_challenges > 0 {
                    provider_info.postrep_stats.post_pass_rate =
                        (provider_info.postrep_stats.challenges_answered as f64
                            / total_challenges as f64)
                            * 100.0;
                }

                let current_avg = provider_info.postrep_stats.avg_post_latency_ms;
                let count = provider_info.postrep_stats.post_proofs_submitted;
                provider_info.postrep_stats.avg_post_latency_ms =
                    ((current_avg as u64 * (count - 1) + latency_ms as u64) / count) as u32;
            } else {
                provider_info.postrep_stats.challenges_missed += 1;
                provider_info.postrep_stats.consecutive_misses += 1;

                let total_challenges = provider_info.postrep_stats.challenges_answered
                    + provider_info.postrep_stats.challenges_missed;
                if total_challenges > 0 {
                    provider_info.postrep_stats.post_pass_rate =
                        (provider_info.postrep_stats.challenges_answered as f64
                            / total_challenges as f64)
                            * 100.0;
                }
            }

            provider_info.health_score = Self::calculate_health_score_from_info(provider_info);
        }

        self.last_activity = Timestamp::now();
    }

    pub fn calculate_health_score(&self) -> u64 {
        let provider_info = match &self.storage_provider_info {
            Some(info) => info,
            None => return 0,
        };

        Self::calculate_health_score_from_info(provider_info)
    }

    fn calculate_health_score_from_info(provider_info: &StorageProviderInfo) -> u64 {
        let mut score: f64 = 100000.0;

        score *= provider_info.postrep_stats.post_pass_rate / 100.0;

        if provider_info.postrep_stats.consecutive_misses > 0 {
            score *= 0.9_f64.powi(provider_info.postrep_stats.consecutive_misses as i32);
        }

        if provider_info.postrep_stats.avg_post_latency_ms > 2000 {
            let latency_penalty =
                (provider_info.postrep_stats.avg_post_latency_ms as f64 - 2000.0) / 1000.0;
            score *= (1.0 - (latency_penalty * 0.05)).max(0.5);
        }

        let faulty_ratio = provider_info.postrep_stats.sectors_faulty as f64
            / provider_info.postrep_stats.sectors_sealed.max(1) as f64;
        score *= (1.0 - faulty_ratio).max(0.0);

        score.min(100000.0).max(0.0) as u64
    }

    pub fn mark_sector_faulty(&mut self, sector_id: &Hash) -> EgoResult<()> {
        let provider_info = self.storage_provider_info.as_mut().ok_or_else(|| {
            EgoError::InvalidTransaction("Account is not a storage provider".to_string())
        })?;

        if let Some(sector) = provider_info
            .active_sectors
            .iter_mut()
            .find(|s| &s.sector_id == sector_id)
        {
            sector.integrity_verified = false;
            sector.miss_count += 1;
            provider_info.postrep_stats.sectors_faulty += 1;
            provider_info.health_score = Self::calculate_health_score_from_info(provider_info);
            self.last_activity = Timestamp::now();
            Ok(())
        } else {
            Err(EgoError::InvalidTransaction("Sector not found".to_string()))
        }
    }

    pub fn promote_replica(&mut self, sector_id: &Hash, new_role: TriadRole) -> EgoResult<()> {
        let provider_info = self.storage_provider_info.as_mut().ok_or_else(|| {
            EgoError::InvalidTransaction("Account is not a storage provider".to_string())
        })?;

        if let Some(sector) = provider_info
            .active_sectors
            .iter_mut()
            .find(|s| &s.sector_id == sector_id)
        {
            sector.triad.role = new_role;
            provider_info.postrep_stats.promotions += 1;
            self.last_activity = Timestamp::now();
            Ok(())
        } else {
            Err(EgoError::InvalidTransaction("Sector not found".to_string()))
        }
    }

    pub fn record_repair(&mut self, sector_id: &Hash) -> EgoResult<()> {
        let provider_info = self.storage_provider_info.as_mut().ok_or_else(|| {
            EgoError::InvalidTransaction("Account is not a storage provider".to_string())
        })?;

        if let Some(sector) = provider_info
            .active_sectors
            .iter_mut()
            .find(|s| &s.sector_id == sector_id)
        {
            sector.integrity_verified = true;
            sector.miss_count = 0;
            provider_info.postrep_stats.repairs_completed += 1;
            if provider_info.postrep_stats.sectors_faulty > 0 {
                provider_info.postrep_stats.sectors_faulty -= 1;
            }
            provider_info.health_score = Self::calculate_health_score_from_info(provider_info);
            self.last_activity = Timestamp::now();
            Ok(())
        } else {
            Err(EgoError::InvalidTransaction("Sector not found".to_string()))
        }
    }

    pub fn add_provider_earnings(
        &mut self,
        storage: Balance,
        retrieval: Balance,
        post: Balance,
    ) -> EgoResult<()> {
        let provider_info = self.storage_provider_info.as_mut().ok_or_else(|| {
            EgoError::InvalidTransaction("Account is not a storage provider".to_string())
        })?;

        provider_info.earnings.storage_rewards = provider_info
            .earnings
            .storage_rewards
            .saturating_add(storage);
        provider_info.earnings.retrieval_fees = provider_info
            .earnings
            .retrieval_fees
            .saturating_add(retrieval);
        provider_info.earnings.post_rewards =
            provider_info.earnings.post_rewards.saturating_add(post);

        let total_new = storage.saturating_add(retrieval).saturating_add(post);
        provider_info.earnings.total_earned = provider_info
            .earnings
            .total_earned
            .saturating_add(total_new);
        provider_info.earnings.pending_payouts = provider_info
            .earnings
            .pending_payouts
            .saturating_add(total_new);

        self.last_activity = Timestamp::now();
        Ok(())
    }

    pub fn process_provider_payout(&mut self, amount: Balance) -> EgoResult<()> {
        let provider_info = self.storage_provider_info.as_mut().ok_or_else(|| {
            EgoError::InvalidTransaction("Account is not a storage provider".to_string())
        })?;

        if provider_info.earnings.pending_payouts < amount {
            return Err(EgoError::InsufficientBalance {
                required: amount.as_u128(),
                available: provider_info.earnings.pending_payouts.as_u128(),
            });
        }

        provider_info.earnings.pending_payouts = provider_info
            .earnings
            .pending_payouts
            .saturating_sub(amount);
        self.credit(amount);

        Ok(())
    }

    pub fn slash_provider(
        &mut self,
        amount: Balance,
        reason: String,
        evidence_hash: Hash,
        slash_type: SlashingType,
    ) -> EgoResult<()> {
        let provider_info = self.storage_provider_info.as_mut().ok_or_else(|| {
            EgoError::InvalidTransaction("Account is not a storage provider".to_string())
        })?;

        if provider_info.collateral_locked < amount {
            return Err(EgoError::InsufficientBalance {
                required: amount.as_u128(),
                available: provider_info.collateral_locked.as_u128(),
            });
        }

        provider_info.collateral_locked = provider_info.collateral_locked.saturating_sub(amount);
        provider_info.earnings.total_slashed =
            provider_info.earnings.total_slashed.saturating_add(amount);

        let slashing_event = SlashingEvent {
            timestamp: Timestamp::now(),
            amount,
            reason,
            evidence_hash,
            event_type: slash_type,
        };

        provider_info.slashing_history.push(slashing_event);
        provider_info.health_score = Self::calculate_health_score_from_info(provider_info);
        self.last_activity = Timestamp::now();

        Ok(())
    }

    pub fn lock_provider_collateral(&mut self, amount: Balance) -> EgoResult<()> {
        if !self.can_spend(amount) {
            return Err(EgoError::InsufficientBalance {
                required: amount.as_u128(),
                available: self.balance.as_u128(),
            });
        }

        self.debit(amount)?;

        let provider_info = self.storage_provider_info.as_mut().ok_or_else(|| {
            EgoError::InvalidTransaction("Account is not a storage provider".to_string())
        })?;

        provider_info.collateral_locked = provider_info.collateral_locked.saturating_add(amount);
        self.last_activity = Timestamp::now();

        Ok(())
    }

    pub fn unlock_provider_collateral(&mut self, amount: Balance) -> EgoResult<()> {
        let provider_info = self.storage_provider_info.as_mut().ok_or_else(|| {
            EgoError::InvalidTransaction("Account is not a storage provider".to_string())
        })?;

        if provider_info.collateral_locked < amount {
            return Err(EgoError::InsufficientBalance {
                required: amount.as_u128(),
                available: provider_info.collateral_locked.as_u128(),
            });
        }

        provider_info.collateral_locked = provider_info.collateral_locked.saturating_sub(amount);
        self.credit(amount);

        Ok(())
    }

    pub fn get_sector(&self, sector_id: &Hash) -> Option<&SectorInfo> {
        self.storage_provider_info
            .as_ref()?
            .active_sectors
            .iter()
            .find(|s| &s.sector_id == sector_id)
    }

    pub fn get_sectors_by_data_type(&self, data_type: DataType) -> Vec<&SectorInfo> {
        self.storage_provider_info
            .as_ref()
            .map(|info| {
                info.active_sectors
                    .iter()
                    .filter(|s| s.data_type == data_type)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn get_faulty_sectors(&self) -> Vec<&SectorInfo> {
        self.storage_provider_info
            .as_ref()
            .map(|info| {
                info.active_sectors
                    .iter()
                    .filter(|s| !s.integrity_verified || s.miss_count > 0)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn should_prune_epoch(&self, current_epoch: u64) -> bool {
        if let Some(ref pruning_config) = self.pruning_config {
            if !pruning_config.enabled {
                return false;
            }
            current_epoch % pruning_config.prune_interval_epochs == 0
        } else {
            false
        }
    }

    pub fn should_create_snapshot(&self, current_epoch: u64) -> bool {
        if let Some(ref pruning_config) = self.pruning_config {
            if !pruning_config.keep_state_snapshots {
                return false;
            }
            current_epoch % pruning_config.snapshot_interval_epochs == 0
        } else {
            false
        }
    }

    pub fn get_prunable_epoch(&self, current_epoch: u64) -> Option<u64> {
        self.pruning_config.as_ref().and_then(|config| {
            if config.enabled && current_epoch > config.keep_epochs {
                Some(current_epoch - config.keep_epochs)
            } else {
                None
            }
        })
    }

    pub fn can_fetch_on_demand(&self) -> bool {
        match &self.hot_set_mode {
            HotSetMode::Validator => self
                .validator_info
                .as_ref()
                .map(|info| info.hot_set_config.fetch_on_demand_enabled)
                .unwrap_or(false),
            HotSetMode::FullNode => true,
            HotSetMode::StorageProvider => true,
            HotSetMode::LightClient => true,
        }
    }

    pub fn requires_hot_set_data(&self, data_type: &str) -> bool {
        match &self.hot_set_mode {
            HotSetMode::Validator => matches!(
                data_type,
                "headers" | "qcs" | "state_db" | "recent_bodies" | "mempool"
            ),
            HotSetMode::FullNode => matches!(data_type, "headers" | "qcs" | "state_db"),
            HotSetMode::StorageProvider => false,
            HotSetMode::LightClient => matches!(data_type, "headers"),
        }
    }

    pub fn can_spend(&self, amount: Balance) -> bool {
        self.balance.as_u128() >= amount.as_u128()
    }

    pub fn debit(&mut self, amount: Balance) -> EgoResult<()> {
        if !self.can_spend(amount) {
            return Err(EgoError::InsufficientBalance {
                required: amount.as_u128(),
                available: self.balance.as_u128(),
            });
        }

        self.balance = self
            .balance
            .checked_sub(amount)
            .ok_or(EgoError::InsufficientBalance {
                required: amount.as_u128(),
                available: self.balance.as_u128(),
            })?;

        self.last_activity = Timestamp::now();
        Ok(())
    }

    pub fn credit(&mut self, amount: Balance) {
        self.balance = self
            .balance
            .checked_add(amount)
            .unwrap_or(Balance::new(u128::MAX));
        self.last_activity = Timestamp::now();
    }

    pub fn increment_nonce(&mut self) {
        self.nonce = self.nonce.saturating_add(1);
        self.last_activity = Timestamp::now();
    }

    pub fn get_shard_nonce(&self, shard_id: u32) -> u64 {
        self.per_shard_nonces
            .as_ref()
            .and_then(|nonces| nonces.get(&shard_id))
            .copied()
            .unwrap_or(0)
    }

    pub fn increment_shard_nonce(&mut self, shard_id: u32) {
        if let Some(ref mut nonces) = self.per_shard_nonces {
            let current = nonces.get(&shard_id).copied().unwrap_or(0);
            nonces.insert(shard_id, current.saturating_add(1));
        }
    }

    pub fn can_deploy_free(&self) -> bool {
        self.free_deploys_remaining > 0
    }

    pub fn use_free_deploy(&mut self) -> EgoResult<()> {
        if self.free_deploys_remaining == 0 {
            return Err(EgoError::InvalidTransaction(
                "No free deploys remaining".to_string(),
            ));
        }
        self.free_deploys_remaining = self.free_deploys_remaining.saturating_sub(1);
        self.last_activity = Timestamp::now();
        Ok(())
    }

    pub fn can_use_deploy_credits(&self, credits_needed: u64) -> bool {
        self.deploy_credits >= credits_needed
    }

    pub fn use_deploy_credits(&mut self, credits: u64) -> EgoResult<()> {
        if self.deploy_credits < credits {
            return Err(EgoError::InsufficientBalance {
                required: credits as u128,
                available: self.deploy_credits as u128,
            });
        }
        self.deploy_credits = self.deploy_credits.saturating_sub(credits);
        self.last_activity = Timestamp::now();
        Ok(())
    }

    pub fn add_storage_credits(&mut self, credits: u64) {
        self.storage_credits = self.storage_credits.saturating_add(credits);
        self.last_activity = Timestamp::now();
    }

    pub fn use_storage_credits(&mut self, credits: u64) -> EgoResult<()> {
        if self.storage_credits < credits {
            return Err(EgoError::InsufficientBalance {
                required: credits as u128,
                available: self.storage_credits as u128,
            });
        }
        self.storage_credits = self.storage_credits.saturating_sub(credits);
        self.last_activity = Timestamp::now();
        Ok(())
    }

    pub fn update_drs_score(&mut self, score: f64, epoch: u64) {
        self.last_drs_score = Some((score * 1000.0) as u64);
        self.last_drs_epoch = Some(epoch);
        self.last_activity = Timestamp::now();
    }

    pub fn is_authorized_for_slice(&self, slice_id: &SliceId) -> bool {
        self.authorized_slices.contains(slice_id)
    }

    pub fn authorize_slice(&mut self, slice_id: SliceId) {
        if !self.authorized_slices.contains(&slice_id) {
            self.authorized_slices.push(slice_id);
        }
        self.last_activity = Timestamp::now();
    }

    pub fn can_store(&self, additional_bytes: u64) -> bool {
        self.storage_used + additional_bytes <= self.storage_quota
    }

    pub fn update_storage_usage(&mut self, bytes_used: u64) -> EgoResult<()> {
        if !self.can_store(bytes_used) {
            return Err(EgoError::StorageQuotaExceeded {
                used: self.storage_used + bytes_used,
                limit: self.storage_quota,
            });
        }

        self.storage_used += bytes_used;
        self.last_activity = Timestamp::now();
        Ok(())
    }

    pub fn is_pq_only_mode(&self) -> bool {
        self.pq_transition_info
            .as_ref()
            .map_or(false, |info| info.pq_only_mode)
    }

    pub fn supports_algorithm(&self, algorithm_id: u16) -> bool {
        self.pq_transition_info.as_ref().map_or(false, |info| {
            info.supported_algorithms.contains(&algorithm_id)
        })
    }

    pub fn enable_pq_only_mode(&mut self, epoch: u64) {
        if let Some(ref mut pq_info) = self.pq_transition_info {
            pq_info.pq_only_mode = true;
            pq_info.ed25519_disabled_epoch = Some(epoch);
            pq_info
                .supported_algorithms
                .retain(|&id| id != crate::AlgorithmId::Ed25519.as_u16());
        }
        self.last_activity = Timestamp::now();
    }

    pub fn is_cellular_safe(&self) -> bool {
        self.device_capabilities
            .as_ref()
            .map_or(true, |caps| caps.cellular_safe)
    }

    pub fn within_data_limits(&self, data_size_gb: u64) -> bool {
        if let Some(ref caps) = self.device_capabilities {
            caps.cost_awareness.current_month_usage_gb + data_size_gb
                <= caps.cost_awareness.cellular_throttle_threshold_gb
        } else {
            true
        }
    }

    pub fn should_use_wifi_only(&self, operation: &str) -> bool {
        self.device_capabilities.as_ref().map_or(false, |caps| {
            caps.cost_awareness.cellular_safe_mode
                && caps
                    .cost_awareness
                    .wifi_only_operations
                    .contains(&operation.to_string())
        })
    }

    pub fn is_validator(&self) -> bool {
        matches!(self.account_type, AccountType::Validator { .. })
            || matches!(
                self.account_type,
                AccountType::Hybrid { ref roles } if roles.contains(&NodeRole::Validator)
            )
            || self.validator_info.is_some()
    }

    pub fn is_storage_provider(&self) -> bool {
        matches!(self.account_type, AccountType::StorageProvider { .. })
            || matches!(
                self.account_type,
                AccountType::Hybrid { ref roles } if roles.contains(&NodeRole::StorageProvider)
            )
            || self.storage_provider_info.is_some()
    }

    pub fn is_device(&self) -> bool {
        matches!(self.account_type, AccountType::Device { .. })
    }

    pub fn get_validator_pubkey(&self) -> Option<PublicKey> {
        match &self.account_type {
            AccountType::Validator {
                validator_pubkey, ..
            } => Some(validator_pubkey.clone()),
            _ => self
                .validator_info
                .as_ref()
                .map(|info| info.validator_pubkey.clone()),
        }
    }

    pub fn summary(&self) -> String {
        let pq_status = if self.is_pq_only_mode() {
            "PQ-Only"
        } else {
            "Hybrid"
        };

        let role = match &self.account_type {
            AccountType::EOA => "EOA".to_string(),
            AccountType::Device { .. } => "Device".to_string(),
            AccountType::Contract { .. } => "Contract".to_string(),
            AccountType::System { .. } => "System".to_string(),
            AccountType::Validator { .. } => "Validator".to_string(),
            AccountType::StorageProvider { .. } => "Storage Provider".to_string(),
            AccountType::Hybrid { roles } => format!("Hybrid({} roles)", roles.len()),
        };

        let storage_info = if let Some(ref provider) = self.storage_provider_info {
            format!(
                ", Sectors: {}, Health: {}",
                provider.active_sectors.len(),
                provider.health_score
            )
        } else {
            String::new()
        };

        format!(
            "Account {} - Role: {}, Balance: {}, Nonce: {}, Storage: {}/{}, DRS: {:?}, PQ: {}{}",
            self.address,
            role,
            self.balance,
            self.nonce,
            self.storage_used,
            self.storage_quota,
            self.last_drs_score.map(|s| s as f64 / 1000.0),
            pq_status,
            storage_info
        )
    }
}

impl Default for PostRepStats {
    fn default() -> Self {
        Self {
            porep_proofs_submitted: 0,
            post_proofs_submitted: 0,
            post_pass_rate: 100.0,
            avg_post_latency_ms: 0,
            challenges_answered: 0,
            challenges_missed: 0,
            last_challenge_epoch: 0,
            consecutive_misses: 0,
            sectors_sealed: 0,
            sectors_faulty: 0,
            repairs_completed: 0,
            promotions: 0,
        }
    }
}

impl Default for ProviderEarnings {
    fn default() -> Self {
        Self {
            storage_rewards: Balance::ZERO,
            retrieval_fees: Balance::ZERO,
            post_rewards: Balance::ZERO,
            total_earned: Balance::ZERO,
            total_slashed: Balance::ZERO,
            pending_payouts: Balance::ZERO,
        }
    }
}

impl Default for PostStats {
    fn default() -> Self {
        Self {
            proofs_submitted: 0,
            success_rate: 100000,
            last_proof: None,
            challenges_responded: 0,
            integrity_score: 100,
            proof_frequency_hz: 0.5,
            batch_enabled: true,
        }
    }
}

impl Default for CostAwareness {
    fn default() -> Self {
        Self {
            cellular_safe_mode: true,
            max_monthly_cost_usd: 50.0,
            current_month_usage_gb: 0,
            wifi_only_operations: vec![
                "heavy_compute".to_string(),
                "large_storage".to_string(),
                "bulk_sync".to_string(),
            ],
            cellular_throttle_threshold_gb: 5,
        }
    }
}
