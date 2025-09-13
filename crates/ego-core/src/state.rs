use crate::{
    Account, AccountType, Address, Balance, BlockHeight, EgoError, EgoResult, Hash, ShardId,
    Timestamp, Transaction, TransactionPayload, TransactionResult,
};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct StateManager {
    accounts: Arc<DashMap<Address, Account>>,

    storage: Arc<DashMap<Hash, StorageEntry>>,

    validators: Arc<DashMap<Address, ValidatorInfo>>,

    slices: Arc<DashMap<String, SliceConfig>>,

    cross_shard_state: Arc<DashMap<ShardId, CrossShardState>>,

    state_root: Hash,

    block_height: BlockHeight,

    stats: StateStats,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct StorageEntry {
    pub data_hash: Hash,

    pub size: u64,

    pub expires_at: BlockHeight,

    pub provider: Address,

    pub slice_id: Option<String>,

    pub stored_at: Timestamp,

    pub replica_count: u8,

    pub payment: Balance,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ValidatorInfo {
    pub address: Address,

    pub public_key: crate::PublicKey,

    pub total_stake: Balance,

    pub own_stake: Balance,

    pub commission_rate: u16,

    pub status: ValidatorStatus,

    pub performance: ValidatorPerformance,

    pub jail_info: Option<JailInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum ValidatorStatus {
    Active,
    Inactive,
    Jailed,
    Unbonding,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ValidatorPerformance {
    pub blocks_proposed: u64,

    pub blocks_missed: u64,

    pub attestations_made: u64,

    pub attestations_missed: u64,

    pub last_active: BlockHeight,

    pub uptime_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct JailInfo {
    pub jailed_at: BlockHeight,

    pub release_at: BlockHeight,

    pub reason: String,

    pub slashed_amount: Balance,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct SliceConfig {
    pub slice_id: String,

    pub slice_type: SliceType,

    pub authorized_devices: Vec<Address>,

    pub bandwidth_allocation: u64,

    pub latency_ms: u32,

    pub reliability_score: u8,

    pub status: SliceStatus,

    pub created_at: Timestamp,

    pub updated_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum SliceType {
    EMbb,
    Urllc,
    MMtc,
    Custom { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum SliceStatus {
    Active,
    Paused,
    Maintenance,
    Inactive,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct CrossShardState {
    pub shard_id: ShardId,

    pub last_state_root: Hash,

    pub last_block_height: BlockHeight,

    pub pending_receipts: Vec<Hash>,

    pub receipt_nonce: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StateStats {
    pub total_accounts: u64,

    pub total_balance: Balance,

    pub storage_entries: u64,

    pub total_storage_bytes: u64,

    pub active_validators: u32,

    pub total_staked: Balance,

    pub active_slices: u32,

    pub last_updated: Timestamp,
}

impl StateManager {
    pub fn new() -> Self {
        Self {
            accounts: Arc::new(DashMap::new()),
            storage: Arc::new(DashMap::new()),
            validators: Arc::new(DashMap::new()),
            slices: Arc::new(DashMap::new()),
            cross_shard_state: Arc::new(DashMap::new()),
            state_root: Hash::ZERO,
            block_height: BlockHeight::GENESIS,
            stats: StateStats::default(),
        }
    }

    pub fn get_account(&self, address: &Address) -> Option<Account> {
        self.accounts.get(address).map(|entry| entry.clone())
    }

    pub fn set_account(&self, account: Account) {
        let address = account.address;
        self.accounts.insert(address, account);
    }

    /// Create a new account
    pub fn create_account(&self, address: Address, account_type: AccountType) -> EgoResult<()> {
        if self.accounts.contains_key(&address) {
            return Err(EgoError::InvalidTransaction(
                "Account already exists".to_string(),
            ));
        }

        let account = match account_type {
            AccountType::User => Account::new_user(address),
            AccountType::Device {
                device_id,
                geohash: _,
            } => {
                let capabilities = crate::account::DeviceCapabilities {
                    bandwidth_capacity: 100_000_000,
                    storage_capacity: 100_000_000,
                    supported_slices: Vec::new(),
                    coverage_area: None,
                    hardware_specs: HashMap::new(),
                    last_poc: None,
                    post_stats: Default::default(),
                };
                Account::new_device(address, device_id, capabilities)
            }
            AccountType::Validator {
                validator_pubkey,
                commission_rate,
            } => Account::new_validator(address, validator_pubkey, commission_rate, Balance::ZERO)?,
            _ => {
                return Err(EgoError::InvalidTransaction(
                    "Unsupported account type for direct creation".to_string(),
                ));
            }
        };

        self.accounts.insert(address, account);
        Ok(())
    }

    pub fn execute_transaction(&mut self, tx: &Transaction) -> EgoResult<TransactionResult> {
        let mut sender = self
            .get_account(&tx.from)
            .ok_or(EgoError::AccountNotFound {
                account_id: tx.from.to_string(),
            })?;

        tx.validate_against_account(&sender)?;

        sender.increment_nonce();

        let result = match &tx.payload {
            TransactionPayload::Transfer { to, amount, .. } => {
                self.execute_transfer(&mut sender, *to, *amount)?
            }

            TransactionPayload::CreateAccount {
                account_address,
                account_type,
                initial_balance,
            } => self.execute_create_account(
                &mut sender,
                *account_address,
                account_type.clone(),
                *initial_balance,
            )?,

            TransactionPayload::StoreData {
                chunk_id,
                data_size,
                duration,
                data_hash,
                slice_id,
            } => self.execute_store_data(
                &mut sender,
                *chunk_id,
                *data_size,
                *duration,
                *data_hash,
                slice_id.clone(),
            )?,

            TransactionPayload::Stake {
                amount,
                validator_pubkey,
                commission_rate,
            } => self.execute_stake(&mut sender, *amount, *validator_pubkey, *commission_rate)?,

            TransactionPayload::Delegate {
                amount,
                validator_pubkey,
            } => self.execute_delegate(&mut sender, *amount, *validator_pubkey)?,

            _ => TransactionResult {
                tx_hash: tx.hash,
                success: true,
                error: None,
                compute_used: tx.estimate_compute_cost(),
                storage_used: tx.size() as u64,
                state_changes: Vec::new(),
                events: Vec::new(),
                cross_shard_receipts: Vec::new(),
            },
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
    ) -> EgoResult<TransactionResult> {
        sender.debit(amount)?;

        let mut recipient = self
            .get_account(&to)
            .unwrap_or_else(|| Account::new_user(to));
        recipient.credit(amount);

        self.set_account(recipient);

        Ok(TransactionResult {
            tx_hash: Hash::ZERO,
            success: true,
            error: None,
            compute_used: 100,
            storage_used: 0,
            state_changes: vec![
                crate::transaction::StateChange {
                    account: sender.address,
                    change_type: crate::transaction::StateChangeType::BalanceUpdate,
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
                crate::transaction::StateChange {
                    account: to,
                    change_type: crate::transaction::StateChangeType::BalanceUpdate,
                    previous_value: Some(Balance::ZERO.as_u128().to_le_bytes().to_vec()),
                    new_value: amount.as_u128().to_le_bytes().to_vec(),
                },
            ],
            events: vec![crate::transaction::TransactionEvent {
                event_type: "transfer".to_string(),
                data: serde_json::to_string(&serde_json::json!({
                    "from": sender.address.to_string(),
                    "to": to.to_string(),
                    "amount": amount.to_string()
                }))
                .unwrap_or_default(),
                block_height: self.block_height.as_u64(),
                tx_index: 0,
            }],
            cross_shard_receipts: Vec::new(),
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
            new_account.credit(initial_balance);
            self.set_account(new_account);
        }

        let config = bincode::config::standard();
        Ok(TransactionResult {
            tx_hash: Hash::ZERO,
            success: true,
            error: None,
            compute_used: 1000,
            storage_used: 256,
            state_changes: vec![crate::transaction::StateChange {
                account: account_address,
                change_type: crate::transaction::StateChangeType::AccountCreation,
                previous_value: None,
                new_value: bincode::encode_to_vec(&account_type, config).unwrap_or_default(),
            }],
            events: vec![crate::transaction::TransactionEvent {
                event_type: "account_created".to_string(),
                data: serde_json::to_string(&serde_json::json!({
                    "address": account_address.to_string(),
                    "creator": sender.address.to_string()
                }))
                .unwrap_or_default(),
                block_height: self.block_height.as_u64(),
                tx_index: 0,
            }],
            cross_shard_receipts: Vec::new(),
        })
    }

    fn execute_store_data(
        &mut self,
        sender: &mut Account,
        chunk_id: Hash,
        data_size: u64,
        duration: u64,
        data_hash: Hash,
        slice_id: crate::SliceId,
    ) -> EgoResult<TransactionResult> {
        sender.update_storage_usage(data_size)?;

        if !sender.is_authorized_for_slice(&slice_id) {
            return Err(EgoError::UnauthorizedSlice {
                slice_id: slice_id.as_str().to_string(),
            });
        }

        let storage_cost = Balance::new(((data_size * duration) / 1000) as u128);
        sender.debit(storage_cost)?;

        let storage_entry = StorageEntry {
            data_hash,
            size: data_size,
            expires_at: BlockHeight::new(self.block_height.as_u64() + duration),
            provider: sender.address,
            slice_id: Some(slice_id.as_str().to_string()),
            stored_at: Timestamp::now(),
            replica_count: 3,
            payment: storage_cost,
        };

        self.storage.insert(chunk_id, storage_entry);

        Ok(TransactionResult {
            tx_hash: Hash::ZERO,
            success: true,
            error: None,
            compute_used: 1000 + (data_size / 1024),
            storage_used: data_size,
            state_changes: Vec::new(),
            events: vec![crate::transaction::TransactionEvent {
                event_type: "data_stored".to_string(),
                data: serde_json::to_string(&serde_json::json!({
                    "chunk_id": chunk_id.to_string(),
                    "provider": sender.address.to_string(),
                    "size": data_size,
                    "slice_id": slice_id.as_str().to_string()
                }))
                .unwrap_or_default(),
                block_height: self.block_height.as_u64(),
                tx_index: 0,
            }],
            cross_shard_receipts: Vec::new(),
        })
    }

    fn execute_stake(
        &mut self,
        sender: &mut Account,
        amount: Balance,
        validator_pubkey: crate::PublicKey,
        commission_rate: Option<u16>,
    ) -> EgoResult<TransactionResult> {
        sender.debit(amount)?;

        let validator_address = Address::from_public_key(&validator_pubkey);

        if let Some(mut validator_info) = self.validators.get(&validator_address).map(|v| v.clone())
        {
            validator_info.total_stake = validator_info
                .total_stake
                .checked_add(amount)
                .ok_or(EgoError::InvalidTransaction("Stake overflow".to_string()))?;

            if validator_address == sender.address {
                validator_info.own_stake = validator_info
                    .own_stake
                    .checked_add(amount)
                    .ok_or(EgoError::InvalidTransaction("Stake overflow".to_string()))?;
            }

            self.validators.insert(validator_address, validator_info);
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

            let validator_info = ValidatorInfo {
                address: validator_address,
                public_key: validator_pubkey,
                total_stake: amount,
                own_stake: amount,
                commission_rate: commission,
                status: ValidatorStatus::Active,
                performance: ValidatorPerformance {
                    blocks_proposed: 0,
                    blocks_missed: 0,
                    attestations_made: 0,
                    attestations_missed: 0,
                    last_active: self.block_height,
                    uptime_score: 100.0,
                },
                jail_info: None,
            };

            self.validators.insert(validator_address, validator_info);
        }

        Ok(TransactionResult {
            tx_hash: Hash::ZERO,
            success: true,
            error: None,
            compute_used: 800,
            storage_used: 0,
            state_changes: Vec::new(),
            events: vec![crate::transaction::TransactionEvent {
                event_type: "stake".to_string(),
                data: serde_json::to_string(&serde_json::json!({
                    "staker": sender.address.to_string(),
                    "validator": validator_address.to_string(),
                    "amount": amount.to_string()
                }))
                .unwrap_or_default(),
                block_height: self.block_height.as_u64(),
                tx_index: 0,
            }],
            cross_shard_receipts: Vec::new(),
        })
    }

    fn execute_delegate(
        &mut self,
        sender: &mut Account,
        amount: Balance,
        validator_pubkey: crate::PublicKey,
    ) -> EgoResult<TransactionResult> {
        sender.debit(amount)?;

        let validator_address = Address::from_public_key(&validator_pubkey);

        let mut validator_info = self
            .validators
            .get(&validator_address)
            .ok_or(EgoError::InvalidTransaction(
                "Validator does not exist".to_string(),
            ))?
            .clone();

        validator_info.total_stake = validator_info
            .total_stake
            .checked_add(amount)
            .ok_or(EgoError::InvalidTransaction("Stake overflow".to_string()))?;

        self.validators.insert(validator_address, validator_info);

        Ok(TransactionResult {
            tx_hash: Hash::ZERO,
            success: true,
            error: None,
            compute_used: 400,
            storage_used: 0,
            state_changes: Vec::new(),
            events: vec![crate::transaction::TransactionEvent {
                event_type: "delegate".to_string(),
                data: serde_json::to_string(&serde_json::json!({
                    "delegator": sender.address.to_string(),
                    "validator": validator_address.to_string(),
                    "amount": amount.to_string()
                }))
                .unwrap_or_default(),
                block_height: self.block_height.as_u64(),
                tx_index: 0,
            }],
            cross_shard_receipts: Vec::new(),
        })
    }

    fn update_stats(&mut self) {
        self.stats.total_accounts = self.accounts.len() as u64;
        self.stats.storage_entries = self.storage.len() as u64;
        self.stats.active_validators = self
            .validators
            .iter()
            .filter(|entry| entry.status == ValidatorStatus::Active)
            .count() as u32;
        self.stats.active_slices = self
            .slices
            .iter()
            .filter(|entry| entry.status == SliceStatus::Active)
            .count() as u32;

        let mut total_balance = Balance::ZERO;
        let mut total_storage = 0u64;
        let mut total_staked = Balance::ZERO;

        for account_ref in self.accounts.iter() {
            let account = account_ref.value();
            total_balance = total_balance
                .checked_add(account.balance)
                .unwrap_or(total_balance);
        }

        for storage_ref in self.storage.iter() {
            let storage_entry = storage_ref.value();
            total_storage += storage_entry.size;
        }

        for validator_ref in self.validators.iter() {
            let validator = validator_ref.value();
            total_staked = total_staked
                .checked_add(validator.total_stake)
                .unwrap_or(total_staked);
        }

        self.stats.total_balance = total_balance;
        self.stats.total_storage_bytes = total_storage;
        self.stats.total_staked = total_staked;
        self.stats.last_updated = Timestamp::now();
    }

    pub fn compute_state_root(&self) -> Hash {
        let mut state_data = Vec::new();
        let config = bincode::config::standard();

        for account_ref in self.accounts.iter() {
            let account = account_ref.value();
            if let Ok(serialized) = bincode::encode_to_vec(&account, config) {
                state_data.extend_from_slice(&serialized);
            }
        }

        for storage_ref in self.storage.iter() {
            let storage_entry = storage_ref.value();
            if let Ok(serialized) = bincode::encode_to_vec(&storage_entry, config) {
                state_data.extend_from_slice(&serialized);
            }
        }

        for validator_ref in self.validators.iter() {
            let validator = validator_ref.value();
            if let Ok(serialized) = bincode::encode_to_vec(&validator, config) {
                state_data.extend_from_slice(&serialized);
            }
        }

        crate::crypto::hash_data(&state_data)
    }

    pub fn get_stats(&self) -> StateStats {
        self.stats.clone()
    }

    pub fn set_block_height(&mut self, height: BlockHeight) {
        self.block_height = height;
    }

    pub fn get_block_height(&self) -> BlockHeight {
        self.block_height
    }
}

impl Default for StateManager {
    fn default() -> Self {
        Self::new()
    }
}
