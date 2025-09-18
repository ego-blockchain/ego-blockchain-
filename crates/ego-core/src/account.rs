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
    pub mlkem_pk: Option<Vec<u8>>,

    pub storage_quota: u64,
    pub storage_used: u64,
    pub storage_credits: u64,

    pub deploy_credits: u64,
    pub free_deploys_remaining: u32,
    pub deploy_bond_locked_until: Option<Timestamp>,

    pub staking_info: Option<StakingInfo>,
    pub validator_info: Option<ValidatorInfo>,

    pub last_drs_score: Option<u64>,
    pub last_drs_epoch: Option<u64>,

    pub account_type: AccountType,
    pub contract_info: Option<ContractInfo>,

    pub peer_id: Option<String>,
    pub tmp_attestation: Option<Vec<u8>>,

    pub authorized_slices: Vec<SliceId>,
    pub device_capabilities: Option<DeviceCapabilities>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ContractInfo {
    pub code_hash: Hash,
    pub upgrade_policy: UpgradePolicy,
    pub pointer_name: Option<[u8; 32]>,
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DeviceCapabilities {
    pub bandwidth_capacity: u64,
    pub storage_capacity: u64,
    pub supported_slices: Vec<SliceId>,
    pub coverage_area: Option<String>,
    pub hardware_specs: HashMap<String, String>,
    pub last_poc: Option<Timestamp>,
    pub post_stats: PostStats,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PostStats {
    pub proofs_submitted: u64,
    pub success_rate: u64,
    pub last_proof: Option<Timestamp>,
    pub challenges_responded: u64,
    pub integrity_score: u8,
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

impl Eq for PostStats {}

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
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ValidatorPerformance {
    pub blocks_validated: u64,
    pub uptime_percentage: u64,
    pub attestation_accuracy: u64,
    pub last_active_epoch: u64,
    pub penalties: u32,
}

impl PartialEq for ValidatorPerformance {
    fn eq(&self, other: &Self) -> bool {
        self.blocks_validated == other.blocks_validated
            && self.uptime_percentage == other.uptime_percentage
            && self.attestation_accuracy == other.attestation_accuracy
            && self.last_active_epoch == other.last_active_epoch
            && self.penalties == other.penalties
    }
}

impl Eq for ValidatorPerformance {}

impl Account {
    pub fn new_eoa(address: Address, dilithium_pk: Vec<u8>) -> Self {
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
            mlkem_pk: None,
            storage_quota: 1024 * 1024,
            storage_used: 0,
            storage_credits: 0,
            deploy_credits: 0,
            free_deploys_remaining: 0,
            deploy_bond_locked_until: None,
            staking_info: None,
            validator_info: None,
            last_drs_score: None,
            last_drs_epoch: None,
            account_type: AccountType::EOA,
            contract_info: None,
            peer_id: None,
            tmp_attestation: None,
            authorized_slices: Vec::new(),
            device_capabilities: None,
            metadata: HashMap::new(),
        }
    }

    pub fn new_device(
        address: Address,
        device_id: String,
        capabilities: DeviceCapabilities,
        dilithium_pk: Vec<u8>,
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
            mlkem_pk: None,
            storage_quota: capabilities.storage_capacity,
            storage_used: 0,
            storage_credits: 1000,
            deploy_credits: 100,
            free_deploys_remaining: 5,
            deploy_bond_locked_until: None,
            staking_info: None,
            validator_info: None,
            last_drs_score: Some(100000),
            last_drs_epoch: Some(0),
            account_type: AccountType::Device {
                device_id,
                geohash: None,
            },
            contract_info: None,
            peer_id: Some(peer_id),
            tmp_attestation: None,
            authorized_slices: capabilities.supported_slices.clone(),
            device_capabilities: Some(capabilities),
            metadata: HashMap::new(),
        }
    }

    pub fn new_validator(
        address: Address,
        validator_pubkey: PublicKey,
        commission_rate: u16,
        initial_stake: Balance,
        dilithium_pk: Vec<u8>,
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
            validator_pubkey,
            commission_rate,
            is_active: true,
            jail_info: None,
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
            mlkem_pk: None,
            storage_quota: 10 * 1024 * 1024,
            storage_used: 0,
            storage_credits: 10000,
            deploy_credits: 1000,
            free_deploys_remaining: 20,
            deploy_bond_locked_until: None,
            staking_info: Some(staking_info),
            validator_info: Some(validator_info),
            last_drs_score: Some(100000),
            last_drs_epoch: Some(0),
            account_type: AccountType::EOA,
            contract_info: None,
            peer_id: None,
            tmp_attestation: None,
            authorized_slices: Vec::new(),
            device_capabilities: None,
            metadata: HashMap::new(),
        })
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

    pub fn summary(&self) -> String {
        format!(
            "Account {} - Balance: {}, Type: {:?}, Nonce: {}, Storage: {}/{}, DRS: {:?}",
            self.address,
            self.balance,
            self.account_type,
            self.nonce,
            self.storage_used,
            self.storage_quota,
            self.last_drs_score.map(|s| s as f64 / 1000.0)
        )
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
        }
    }
}
