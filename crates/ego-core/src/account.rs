use crate::{Address, Balance, EgoError, EgoResult, Hash, PublicKey, SliceId, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct Account {
    pub address: Address,
    pub balance: Balance,
    pub nonce: u64,
    pub created_at: Timestamp,
    pub last_activity: Timestamp,
    pub storage_quota: u64,
    pub storage_used: u64,
    pub authorized_slices: Vec<SliceId>,
    pub account_type: AccountType,
    pub device_capabilities: Option<DeviceCapabilities>,
    pub staking_info: Option<StakingInfo>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum AccountType {
    User,
    Device {
        device_id: String,
        geohash: Option<String>,
    },
    Validator {
        validator_pubkey: PublicKey,
        commission_rate: u16,
    },
    RollupOperator {
        operator_id: String,
        shard_ids: Vec<u32>,
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
    pub success_rate: f64,
    pub last_proof: Option<Timestamp>,
    pub challenges_responded: u64,
    pub integrity_score: u8,
}

impl PartialEq for PostStats {
    fn eq(&self, other: &Self) -> bool {
        self.proofs_submitted == other.proofs_submitted
            && (self.success_rate - other.success_rate).abs() < f64::EPSILON
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
pub struct SlashingEvent {
    pub timestamp: Timestamp,
    pub amount: Balance,
    pub reason: String,
    pub evidence_hash: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ValidatorPerformance {
    pub blocks_validated: u64,
    pub uptime_percentage: f64,
    pub attestation_accuracy: f64,
    pub last_active_epoch: u64,
    pub penalties: u32,
}

impl PartialEq for ValidatorPerformance {
    fn eq(&self, other: &Self) -> bool {
        self.blocks_validated == other.blocks_validated
            && (self.uptime_percentage - other.uptime_percentage).abs() < f64::EPSILON
            && (self.attestation_accuracy - other.attestation_accuracy).abs() < f64::EPSILON
            && self.last_active_epoch == other.last_active_epoch
            && self.penalties == other.penalties
    }
}

impl Eq for ValidatorPerformance {}

impl Account {
    pub fn new_user(address: Address) -> Self {
        let now = Timestamp::now();
        Self {
            address,
            balance: Balance::ZERO,
            nonce: 0,
            created_at: now,
            last_activity: now,
            storage_quota: 1024 * 1024,
            storage_used: 0,
            authorized_slices: Vec::new(),
            account_type: AccountType::User,
            device_capabilities: None,
            staking_info: None,
            metadata: HashMap::new(),
        }
    }

    pub fn new_device(
        address: Address,
        device_id: String,
        capabilities: DeviceCapabilities,
    ) -> Self {
        let now = Timestamp::now();
        Self {
            address,
            balance: Balance::ZERO,
            nonce: 0,
            created_at: now,
            last_activity: now,
            storage_quota: capabilities.storage_capacity,
            storage_used: 0,
            authorized_slices: capabilities.supported_slices.clone(),
            account_type: AccountType::Device {
                device_id,
                geohash: None,
            },
            device_capabilities: Some(capabilities),
            staking_info: None,
            metadata: HashMap::new(),
        }
    }

    pub fn new_validator(
        address: Address,
        validator_pubkey: PublicKey,
        commission_rate: u16,
        initial_stake: Balance,
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
                uptime_percentage: 100.0,
                attestation_accuracy: 100.0,
                last_active_epoch: 0,
                penalties: 0,
            },
        };

        Ok(Self {
            address,
            balance: Balance::ZERO,
            nonce: 0,
            created_at: now,
            last_activity: now,
            storage_quota: 10 * 1024 * 1024,
            storage_used: 0,
            authorized_slices: Vec::new(),
            account_type: AccountType::Validator {
                validator_pubkey,
                commission_rate,
            },
            device_capabilities: None,
            staking_info: Some(staking_info),
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
            "Account {} - Balance: {}, Type: {:?}, Nonce: {}, Storage: {}/{}",
            self.address,
            self.balance,
            self.account_type,
            self.nonce,
            self.storage_used,
            self.storage_quota
        )
    }
}

impl Default for PostStats {
    fn default() -> Self {
        Self {
            proofs_submitted: 0,
            success_rate: 100.0,
            last_proof: None,
            challenges_responded: 0,
            integrity_score: 100,
        }
    }
}
