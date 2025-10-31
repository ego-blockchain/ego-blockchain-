use crate::error::{RollupError, RollupResult};
use crate::types::RollupTransaction;
use ego_core::{Account, Address, Balance, Hash, Transaction, TransactionResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum RollupStateChange {
    BalanceUpdate {
        address: Address,
        old_balance: Balance,
        new_balance: Balance,
    },
    NonceUpdate {
        address: Address,
        old_nonce: u64,
        new_nonce: u64,
    },
    ContractDeployed {
        address: Address,
        code_hash: Hash,
    },
    Staked {
        address: Address,
        amount: Balance,
    },
    Unstaked {
        address: Address,
        amount: Balance,
    },
    Burned {
        address: Address,
        amount: Balance,
    },
    CrossShardInitiated {
        from: Address,
        target_shard: u32,
        receipt_hash: Hash,
    },
    StorageUpdate {
        address: Address,
        key: Vec<u8>,
        old_value: Option<Vec<u8>>,
        new_value: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
pub struct RollupState {
    accounts: HashMap<Address, Account>,
    storage: HashMap<Address, HashMap<Vec<u8>, Vec<u8>>>,
    nonces: HashMap<Address, u64>,
    block_height: u64,
    state_root: Hash,
    total_supply: Balance,
    contract_code: HashMap<Address, Vec<u8>>,
    cross_shard_pending: HashMap<Hash, CrossShardPending>,
    epoch: u64,
    shard_id: ego_core::ShardId,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct StateTransition {
    pub from_state: Hash,
    pub to_state: Hash,
    pub transaction_hash: Hash,
    pub changes: Vec<RollupStateChange>,
    pub gas_used: u64,
    pub epoch: u64,
    pub timestamp: ego_core::Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct StateDelta {
    pub account_changes: HashMap<Address, AccountDelta>,
    pub storage_changes: HashMap<Address, HashMap<Vec<u8>, StorageChange>>,
    pub nonce_changes: HashMap<Address, u64>,
    pub contract_changes: HashMap<Address, ContractChange>,
    pub cross_shard_changes: Vec<CrossShardChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct AccountDelta {
    pub old_balance: Option<Balance>,
    pub new_balance: Balance,
    pub old_nonce: u64,
    pub new_nonce: u64,
    pub created: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct StorageChange {
    pub old_value: Option<Vec<u8>>,
    pub new_value: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ContractChange {
    pub deployed: bool,
    pub code: Vec<u8>,
    pub storage_root: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct CrossShardChange {
    pub receipt_hash: Hash,
    pub source_shard: u32,
    pub target_shard: u32,
    pub status: CrossShardStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub enum CrossShardStatus {
    Pending,
    Confirmed,
    Failed,
}

#[derive(Debug, Clone)]
pub struct CrossShardPending {
    pub receipt_hash: Hash,
    pub source_shard: ego_core::ShardId,
    pub target_shard: ego_core::ShardId,
    pub payload: Vec<u8>,
    pub timestamp: ego_core::Timestamp,
    pub deadline_epoch: u64,
}

#[derive(Debug, Clone)]
pub struct StateCheckpoint {
    accounts: HashMap<Address, Account>,
    storage: HashMap<Address, HashMap<Vec<u8>, Vec<u8>>>,
    nonces: HashMap<Address, u64>,
    block_height: u64,
    state_root: Hash,
    total_supply: Balance,
    contract_code: HashMap<Address, Vec<u8>>,
    cross_shard_pending: HashMap<Hash, CrossShardPending>,
    epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub state_root: Hash,
    pub block_height: u64,
    pub epoch: u64,
    pub account_count: usize,
    pub total_supply: Balance,
    pub timestamp: ego_core::Timestamp,
    pub shard_id: u32,
}

impl RollupState {
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
            storage: HashMap::new(),
            nonces: HashMap::new(),
            block_height: 0,
            state_root: Hash::ZERO,
            total_supply: Balance::ZERO,
            contract_code: HashMap::new(),
            cross_shard_pending: HashMap::new(),
            epoch: 0,
            shard_id: ego_core::ShardId::new(0).unwrap(),
        }
    }

    pub fn with_shard_id(shard_id: ego_core::ShardId) -> Self {
        Self {
            accounts: HashMap::new(),
            storage: HashMap::new(),
            nonces: HashMap::new(),
            block_height: 0,
            state_root: Hash::ZERO,
            total_supply: Balance::ZERO,
            contract_code: HashMap::new(),
            cross_shard_pending: HashMap::new(),
            epoch: 0,
            shard_id,
        }
    }

    pub fn from_genesis(
        genesis_accounts: Vec<(Address, Balance)>,
        shard_id: ego_core::ShardId,
    ) -> Self {
        let mut state = Self::with_shard_id(shard_id);

        for (address, balance) in genesis_accounts {
            let mut account = Account::new_eoa(address, vec![0u8; 32], vec![0u8; 32]);
            account.credit(balance);
            state.accounts.insert(address, account);
            state.total_supply = state
                .total_supply
                .checked_add(balance)
                .unwrap_or(Balance::new(u128::MAX));
        }

        state.state_root = state.compute_state_root();
        state
    }

    pub async fn execute_transaction(
        &mut self,
        tx: &RollupTransaction,
    ) -> RollupResult<TransactionResult> {
        if !tx.inner.verify_signature()? {
            return Ok(TransactionResult {
                tx_hash: tx.hash(),
                success: false,
                error: Some("Invalid signature".to_string()),
                ru_used: 0,
                storage_used: 0,
                state_changes: vec![],
                events: vec![],
                cross_shard_receipts: vec![],
                pq_verification_result: None,
                proof_verifications: vec![],
            });
        }

        let current_nonce = self.get_nonce(tx.inner.from);
        if tx.rollup_nonce != current_nonce + 1 {
            return Ok(TransactionResult {
                tx_hash: tx.hash(),
                success: false,
                error: Some(format!(
                    "Invalid nonce: expected {}, got {}",
                    current_nonce + 1,
                    tx.rollup_nonce
                )),
                ru_used: 0,
                storage_used: 0,
                state_changes: vec![],
                events: vec![],
                cross_shard_receipts: vec![],
                pq_verification_result: None,
                proof_verifications: vec![],
            });
        }

        let result = self.execute_inner_transaction(&tx.inner).await?;

        if result.success {
            self.increment_nonce(tx.inner.from);
        }

        self.state_root = self.compute_state_root();

        Ok(result)
    }

    async fn execute_inner_transaction(
        &mut self,
        tx: &Transaction,
    ) -> RollupResult<TransactionResult> {
        match &tx.payload {
            ego_core::TransactionPayload::Transfer { to, amount, .. } => {
                self.execute_transfer(tx.from, *to, *amount, tx.hash)
            }
            ego_core::TransactionPayload::DeployContract {
                contract_code_hash,
                constructor_args,
                ..
            } => self.execute_deploy_contract(
                tx.from,
                contract_code_hash.to_vec(),
                constructor_args.clone(),
                tx.hash,
            ),
            ego_core::TransactionPayload::ExecuteContract {
                contract_address,
                method,
                args,
                value,
            } => self.execute_call_contract(
                tx.from,
                *contract_address,
                method.clone(),
                args.clone(),
                *value,
                tx.hash,
            ),
            ego_core::TransactionPayload::Stake { amount, .. } => {
                self.execute_stake(tx.from, *amount, tx.from, tx.hash)
            }
            ego_core::TransactionPayload::Unstake { amount, .. } => {
                self.execute_unstake(tx.from, *amount, tx.hash)
            }
            ego_core::TransactionPayload::CrossShard {
                target_shard,
                message,
                ..
            } => self.execute_cross_shard(tx.from, target_shard.as_u32(), message.clone(), tx.hash),
            _ => Ok(TransactionResult {
                tx_hash: tx.hash,
                success: false,
                error: Some("Unsupported transaction type".to_string()),
                ru_used: 0,
                storage_used: 0,
                state_changes: vec![],
                events: vec![],
                cross_shard_receipts: vec![],
                pq_verification_result: None,
                proof_verifications: vec![],
            }),
        }
    }

    fn execute_transfer(
        &mut self,
        from: Address,
        to: Address,
        amount: Balance,
        tx_hash: Hash,
    ) -> RollupResult<TransactionResult> {
        let mut from_account = self.get_or_create_account(from);
        let mut to_account = self.get_or_create_account(to);

        let old_from_balance = from_account.balance;

        if !from_account.can_spend(amount) {
            return Ok(TransactionResult {
                tx_hash,
                success: false,
                error: Some("Insufficient balance".to_string()),
                ru_used: 21000,
                storage_used: 0,
                state_changes: vec![],
                events: vec![],
                cross_shard_receipts: vec![],
                pq_verification_result: None,
                proof_verifications: vec![],
            });
        }

        from_account
            .debit(amount)
            .map_err(|e| RollupError::StateError(e.to_string()))?;
        to_account.credit(amount);

        self.accounts.insert(from, from_account.clone());
        self.accounts.insert(to, to_account);

        let state_change = ego_core::StateChange {
            account: from,
            change_type: ego_core::StateChangeType::BalanceUpdate,
            previous_value: Some(old_from_balance.as_u128().to_le_bytes().to_vec()),
            new_value: from_account.balance.as_u128().to_le_bytes().to_vec(),
        };

        Ok(TransactionResult {
            tx_hash,
            success: true,
            error: None,
            ru_used: 21000,
            storage_used: 0,
            state_changes: vec![state_change],
            events: vec![],
            cross_shard_receipts: vec![],
            pq_verification_result: None,
            proof_verifications: vec![],
        })
    }

    fn execute_deploy_contract(
        &mut self,
        from: Address,
        code: Vec<u8>,
        _constructor_args: Vec<u8>,
        tx_hash: Hash,
    ) -> RollupResult<TransactionResult> {
        let contract_address = self.compute_contract_address(from, self.get_nonce(from));

        let mut account = self.get_or_create_account(from);
        let deploy_cost = Balance::from_egoc(1);

        if !account.can_spend(deploy_cost) {
            return Ok(TransactionResult {
                tx_hash,
                success: false,
                error: Some("Insufficient balance for deployment".to_string()),
                ru_used: 50000,
                storage_used: 0,
                state_changes: vec![],
                events: vec![],
                cross_shard_receipts: vec![],
                pq_verification_result: None,
                proof_verifications: vec![],
            });
        }

        account
            .debit(deploy_cost)
            .map_err(|e| RollupError::StateError(e.to_string()))?;
        self.accounts.insert(from, account);

        let contract_account = Account::new_eoa(contract_address, vec![0u8; 32], vec![0u8; 32]);
        self.accounts.insert(contract_address, contract_account);
        self.contract_code.insert(contract_address, code.clone());

        let storage_used = code.len() as u64;
        let code_hash = ego_core::crypto::hash_data(&code);

        let state_change = ego_core::StateChange {
            account: contract_address,
            change_type: ego_core::StateChangeType::AccountCreation,
            previous_value: None,
            new_value: code_hash.as_bytes().to_vec(),
        };

        Ok(TransactionResult {
            tx_hash,
            success: true,
            error: None,
            ru_used: 100000 + (code.len() as u64 * 200),
            storage_used,
            state_changes: vec![state_change],
            events: vec![],
            cross_shard_receipts: vec![],
            pq_verification_result: None,
            proof_verifications: vec![],
        })
    }

    fn execute_call_contract(
        &mut self,
        from: Address,
        contract: Address,
        _method: String,
        _args: Vec<u8>,
        value: Balance,
        tx_hash: Hash,
    ) -> RollupResult<TransactionResult> {
        if !self.contract_code.contains_key(&contract) {
            return Ok(TransactionResult {
                tx_hash,
                success: false,
                error: Some("Contract not found".to_string()),
                ru_used: 10000,
                storage_used: 0,
                state_changes: vec![],
                events: vec![],
                cross_shard_receipts: vec![],
                pq_verification_result: None,
                proof_verifications: vec![],
            });
        }

        let mut state_changes = vec![];

        if value > Balance::ZERO {
            let mut from_account = self.get_or_create_account(from);
            let mut contract_account = self.get_or_create_account(contract);

            let old_from_balance = from_account.balance;

            if !from_account.can_spend(value) {
                return Ok(TransactionResult {
                    tx_hash,
                    success: false,
                    error: Some("Insufficient balance".to_string()),
                    ru_used: 25000,
                    storage_used: 0,
                    state_changes: vec![],
                    events: vec![],
                    cross_shard_receipts: vec![],
                    pq_verification_result: None,
                    proof_verifications: vec![],
                });
            }

            from_account
                .debit(value)
                .map_err(|e| RollupError::StateError(e.to_string()))?;
            contract_account.credit(value);

            self.accounts.insert(from, from_account.clone());
            self.accounts.insert(contract, contract_account);

            state_changes.push(ego_core::StateChange {
                account: from,
                change_type: ego_core::StateChangeType::BalanceUpdate,
                previous_value: Some(old_from_balance.as_u128().to_le_bytes().to_vec()),
                new_value: from_account.balance.as_u128().to_le_bytes().to_vec(),
            });
        }

        Ok(TransactionResult {
            tx_hash,
            success: true,
            error: None,
            ru_used: 50000,
            storage_used: 0,
            state_changes,
            events: vec![],
            cross_shard_receipts: vec![],
            pq_verification_result: None,
            proof_verifications: vec![],
        })
    }

    fn execute_stake(
        &mut self,
        from: Address,
        amount: Balance,
        _validator: Address,
        tx_hash: Hash,
    ) -> RollupResult<TransactionResult> {
        let mut account = self.get_or_create_account(from);
        let old_balance = account.balance;

        if !account.can_spend(amount) {
            return Ok(TransactionResult {
                tx_hash,
                success: false,
                error: Some("Insufficient balance for staking".to_string()),
                ru_used: 30000,
                storage_used: 0,
                state_changes: vec![],
                events: vec![],
                cross_shard_receipts: vec![],
                pq_verification_result: None,
                proof_verifications: vec![],
            });
        }

        account
            .debit(amount)
            .map_err(|e| RollupError::StateError(e.to_string()))?;
        self.accounts.insert(from, account.clone());

        let state_change = ego_core::StateChange {
            account: from,
            change_type: ego_core::StateChangeType::BalanceUpdate,
            previous_value: Some(old_balance.as_u128().to_le_bytes().to_vec()),
            new_value: account.balance.as_u128().to_le_bytes().to_vec(),
        };

        Ok(TransactionResult {
            tx_hash,
            success: true,
            error: None,
            ru_used: 40000,
            storage_used: 0,
            state_changes: vec![state_change],
            events: vec![],
            cross_shard_receipts: vec![],
            pq_verification_result: None,
            proof_verifications: vec![],
        })
    }

    fn execute_unstake(
        &mut self,
        from: Address,
        amount: Balance,
        tx_hash: Hash,
    ) -> RollupResult<TransactionResult> {
        let mut account = self.get_or_create_account(from);
        let old_balance = account.balance;
        account.credit(amount);
        self.accounts.insert(from, account.clone());

        let state_change = ego_core::StateChange {
            account: from,
            change_type: ego_core::StateChangeType::BalanceUpdate,
            previous_value: Some(old_balance.as_u128().to_le_bytes().to_vec()),
            new_value: account.balance.as_u128().to_le_bytes().to_vec(),
        };

        Ok(TransactionResult {
            tx_hash,
            success: true,
            error: None,
            ru_used: 35000,
            storage_used: 0,
            state_changes: vec![state_change],
            events: vec![],
            cross_shard_receipts: vec![],
            pq_verification_result: None,
            proof_verifications: vec![],
        })
    }

    fn execute_cross_shard(
        &mut self,
        from: Address,
        target_shard: u32,
        message: Vec<u8>,
        tx_hash: Hash,
    ) -> RollupResult<TransactionResult> {
        let target_shard_id = ego_core::ShardId::new(target_shard)
            .map_err(|e| RollupError::StateError(e.to_string()))?;

        let receipt_hash = ego_core::crypto::hash_multiple(&[
            tx_hash.as_bytes(),
            &target_shard.to_le_bytes(),
            &message,
        ]);

        let pending = CrossShardPending {
            receipt_hash,
            source_shard: self.shard_id,
            target_shard: target_shard_id,
            payload: message.clone(),
            timestamp: ego_core::Timestamp::now(),
            deadline_epoch: self.epoch + 100,
        };

        self.cross_shard_pending.insert(receipt_hash, pending);

        let state_change = ego_core::StateChange {
            account: from,
            change_type: ego_core::StateChangeType::StorageUpdate,
            previous_value: None,
            new_value: receipt_hash.as_bytes().to_vec(),
        };

        Ok(TransactionResult {
            tx_hash,
            success: true,
            error: None,
            ru_used: 60000,
            storage_used: 0,
            state_changes: vec![state_change],
            events: vec![],
            cross_shard_receipts: vec![ego_core::transaction::CrossShardReceipt {
                src_shard: self.shard_id,
                dst_shard: target_shard_id,
                src_block_hash: Hash::ZERO,
                tx_id: tx_hash,
                payload: message,
                nonce: 0,
                deadline_epoch: self.epoch + 100,
                merkle_proof: vec![],
            }],
            pq_verification_result: None,
            proof_verifications: vec![],
        })
    }

    pub fn get_account(&self, address: &Address) -> RollupResult<Account> {
        self.accounts
            .get(address)
            .cloned()
            .ok_or_else(|| RollupError::StateError("Account not found".to_string()))
    }

    pub fn get_or_create_account(&mut self, address: Address) -> Account {
        self.accounts.get(&address).cloned().unwrap_or_else(|| {
            let account = Account::new_eoa(address, vec![0u8; 32], vec![0u8; 32]);
            self.accounts.insert(address, account.clone());
            account
        })
    }

    pub fn get_balance(&self, address: Address) -> Balance {
        self.accounts
            .get(&address)
            .map(|acc| acc.balance)
            .unwrap_or(Balance::ZERO)
    }

    pub fn get_nonce(&self, address: Address) -> u64 {
        self.nonces.get(&address).copied().unwrap_or(0)
    }

    pub fn increment_nonce(&mut self, address: Address) {
        let current = self.get_nonce(address);
        self.nonces.insert(address, current + 1);
    }

    pub fn set_storage(&mut self, address: Address, key: Vec<u8>, value: Vec<u8>) {
        self.storage
            .entry(address)
            .or_insert_with(HashMap::new)
            .insert(key, value);
    }

    pub fn get_storage(&self, address: Address, key: &[u8]) -> Option<Vec<u8>> {
        self.storage.get(&address)?.get(key).cloned()
    }

    pub fn get_contract_code(&self, address: Address) -> Option<Vec<u8>> {
        self.contract_code.get(&address).cloned()
    }

    pub fn compute_state_root(&self) -> Hash {
        let mut data = Vec::new();

        let mut sorted_accounts: Vec<_> = self.accounts.iter().collect();
        sorted_accounts.sort_by_key(|(addr, _)| addr.as_bytes());

        for (address, account) in sorted_accounts {
            data.extend_from_slice(address.as_bytes());
            data.extend_from_slice(&account.balance.as_u128().to_le_bytes());
            data.extend_from_slice(&account.nonce.to_le_bytes());
        }

        let mut sorted_nonces: Vec<_> = self.nonces.iter().collect();
        sorted_nonces.sort_by_key(|(addr, _)| addr.as_bytes());

        for (address, nonce) in sorted_nonces {
            data.extend_from_slice(address.as_bytes());
            data.extend_from_slice(&nonce.to_le_bytes());
        }

        let mut sorted_storage: Vec<_> = self.storage.iter().collect();
        sorted_storage.sort_by_key(|(addr, _)| addr.as_bytes());

        for (address, storage_map) in sorted_storage {
            data.extend_from_slice(address.as_bytes());

            let mut sorted_storage_entries: Vec<_> = storage_map.iter().collect();
            sorted_storage_entries.sort_by_key(|(key, _)| *key);

            for (key, value) in sorted_storage_entries {
                data.extend_from_slice(key);
                data.extend_from_slice(value);
            }
        }

        let mut sorted_contracts: Vec<_> = self.contract_code.iter().collect();
        sorted_contracts.sort_by_key(|(addr, _)| addr.as_bytes());

        for (address, code) in sorted_contracts {
            data.extend_from_slice(address.as_bytes());
            data.extend_from_slice(&ego_core::crypto::hash_data(code).to_vec());
        }

        data.extend_from_slice(&self.epoch.to_le_bytes());
        data.extend_from_slice(&self.shard_id.as_u32().to_le_bytes());

        ego_core::crypto::hash_data(&data)
    }

    pub fn create_state_delta(&self, old_state: &RollupState) -> StateDelta {
        let mut account_changes = HashMap::new();
        let mut storage_changes = HashMap::new();
        let mut nonce_changes = HashMap::new();
        let mut contract_changes = HashMap::new();
        let mut cross_shard_changes = Vec::new();

        for (address, account) in &self.accounts {
            if let Some(old_account) = old_state.accounts.get(address) {
                if account.balance != old_account.balance || account.nonce != old_account.nonce {
                    account_changes.insert(
                        *address,
                        AccountDelta {
                            old_balance: Some(old_account.balance),
                            new_balance: account.balance,
                            old_nonce: old_account.nonce,
                            new_nonce: account.nonce,
                            created: false,
                        },
                    );
                }
            } else {
                account_changes.insert(
                    *address,
                    AccountDelta {
                        old_balance: None,
                        new_balance: account.balance,
                        old_nonce: 0,
                        new_nonce: account.nonce,
                        created: true,
                    },
                );
            }
        }

        for (address, storage_map) in &self.storage {
            let old_storage = old_state.storage.get(address);
            let mut address_storage_changes = HashMap::new();

            for (key, value) in storage_map {
                let old_value = old_storage.and_then(|s| s.get(key));
                if old_value.map(|v| v != value).unwrap_or(true) {
                    address_storage_changes.insert(
                        key.clone(),
                        StorageChange {
                            old_value: old_value.cloned(),
                            new_value: value.clone(),
                        },
                    );
                }
            }

            if !address_storage_changes.is_empty() {
                storage_changes.insert(*address, address_storage_changes);
            }
        }

        for (address, nonce) in &self.nonces {
            let old_nonce = old_state.get_nonce(*address);
            if *nonce != old_nonce {
                nonce_changes.insert(*address, *nonce);
            }
        }

        for (address, code) in &self.contract_code {
            if !old_state.contract_code.contains_key(address) {
                let storage_root = self.compute_contract_storage_root(*address);
                contract_changes.insert(
                    *address,
                    ContractChange {
                        deployed: true,
                        code: code.clone(),
                        storage_root,
                    },
                );
            }
        }

        for (receipt_hash, pending) in &self.cross_shard_pending {
            if !old_state.cross_shard_pending.contains_key(receipt_hash) {
                cross_shard_changes.push(CrossShardChange {
                    receipt_hash: *receipt_hash,
                    source_shard: pending.source_shard.as_u32(),
                    target_shard: pending.target_shard.as_u32(),
                    status: CrossShardStatus::Pending,
                });
            }
        }

        StateDelta {
            account_changes,
            storage_changes,
            nonce_changes,
            contract_changes,
            cross_shard_changes,
        }
    }

    pub fn apply_state_delta(&mut self, delta: &StateDelta) -> RollupResult<()> {
        for (address, account_delta) in &delta.account_changes {
            if account_delta.created {
                let mut account = Account::new_eoa(*address, vec![0u8; 32], vec![0u8; 32]);
                account.balance = account_delta.new_balance;
                account.nonce = account_delta.new_nonce;
                self.accounts.insert(*address, account);
            } else if let Some(account) = self.accounts.get_mut(address) {
                account.balance = account_delta.new_balance;
                account.nonce = account_delta.new_nonce;
            }
        }

        for (address, storage_changes_map) in &delta.storage_changes {
            let storage_map = self.storage.entry(*address).or_insert_with(HashMap::new);
            for (key, storage_change) in storage_changes_map {
                storage_map.insert(key.clone(), storage_change.new_value.clone());
            }
        }

        for (address, nonce) in &delta.nonce_changes {
            self.nonces.insert(*address, *nonce);
        }

        for (address, contract_change) in &delta.contract_changes {
            if contract_change.deployed {
                self.contract_code
                    .insert(*address, contract_change.code.clone());
            }
        }

        self.state_root = self.compute_state_root();

        Ok(())
    }

    pub fn get_state_root(&self) -> Hash {
        self.state_root
    }

    pub fn set_state_root(&mut self, state_root: Hash) {
        self.state_root = state_root;
    }

    pub fn get_block_height(&self) -> u64 {
        self.block_height
    }

    pub fn increment_block_height(&mut self) {
        self.block_height += 1;
    }

    pub fn get_total_supply(&self) -> Balance {
        self.total_supply
    }

    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    pub fn get_epoch(&self) -> u64 {
        self.epoch
    }

    pub fn advance_epoch(&mut self) {
        self.epoch += 1;
        self.cleanup_expired_cross_shard();
    }

    pub fn get_shard_id(&self) -> ego_core::ShardId {
        self.shard_id
    }

    pub fn validate_state_transition(&self, transition: &StateTransition) -> RollupResult<bool> {
        if transition.from_state != self.state_root {
            return Ok(false);
        }

        if transition.changes.is_empty() {
            return Ok(false);
        }

        if transition.epoch < self.epoch {
            return Ok(false);
        }

        Ok(true)
    }

    pub fn checkpoint(&self) -> StateCheckpoint {
        StateCheckpoint {
            accounts: self.accounts.clone(),
            storage: self.storage.clone(),
            nonces: self.nonces.clone(),
            block_height: self.block_height,
            state_root: self.state_root,
            total_supply: self.total_supply,
            contract_code: self.contract_code.clone(),
            cross_shard_pending: self.cross_shard_pending.clone(),
            epoch: self.epoch,
        }
    }

    pub fn restore_checkpoint(&mut self, checkpoint: StateCheckpoint) {
        self.accounts = checkpoint.accounts;
        self.storage = checkpoint.storage;
        self.nonces = checkpoint.nonces;
        self.block_height = checkpoint.block_height;
        self.state_root = checkpoint.state_root;
        self.total_supply = checkpoint.total_supply;
        self.contract_code = checkpoint.contract_code;
        self.cross_shard_pending = checkpoint.cross_shard_pending;
        self.epoch = checkpoint.epoch;
    }

    pub fn create_snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            state_root: self.state_root,
            block_height: self.block_height,
            epoch: self.epoch,
            account_count: self.accounts.len(),
            total_supply: self.total_supply,
            timestamp: ego_core::Timestamp::now(),
            shard_id: self.shard_id.as_u32(),
        }
    }

    pub fn confirm_cross_shard_receipt(&mut self, receipt_hash: Hash) -> RollupResult<()> {
        if self.cross_shard_pending.remove(&receipt_hash).is_some() {
            Ok(())
        } else {
            Err(RollupError::StateError(
                "Cross-shard receipt not found".to_string(),
            ))
        }
    }

    fn cleanup_expired_cross_shard(&mut self) {
        let current_epoch = self.epoch;
        self.cross_shard_pending
            .retain(|_, pending| pending.deadline_epoch >= current_epoch);
    }

    fn compute_contract_address(&self, deployer: Address, nonce: u64) -> Address {
        let mut data = Vec::new();
        data.extend_from_slice(deployer.as_bytes());
        data.extend_from_slice(&nonce.to_le_bytes());
        data.extend_from_slice(b"contract");

        let hash = ego_core::crypto::hash_data(&data);
        let mut addr_bytes = [0u8; 20];
        addr_bytes.copy_from_slice(&hash.as_bytes()[0..20]);
        Address::new(addr_bytes)
    }

    fn compute_contract_storage_root(&self, contract: Address) -> Hash {
        if let Some(storage_map) = self.storage.get(&contract) {
            let mut data = Vec::new();
            let mut sorted_entries: Vec<_> = storage_map.iter().collect();
            sorted_entries.sort_by_key(|(k, _)| *k);

            for (key, value) in sorted_entries {
                data.extend_from_slice(key);
                data.extend_from_slice(value);
            }

            ego_core::crypto::hash_data(&data)
        } else {
            Hash::ZERO
        }
    }

    pub fn get_cross_shard_pending(&self, receipt_hash: &Hash) -> Option<&CrossShardPending> {
        self.cross_shard_pending.get(receipt_hash)
    }

    pub fn pending_cross_shard_count(&self) -> usize {
        self.cross_shard_pending.len()
    }

    pub fn contract_count(&self) -> usize {
        self.contract_code.len()
    }

    pub fn is_contract(&self, address: Address) -> bool {
        self.contract_code.contains_key(&address)
    }

    pub fn total_storage_size(&self) -> usize {
        self.storage
            .values()
            .map(|m| m.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>())
            .sum()
    }
}

impl Default for RollupState {
    fn default() -> Self {
        Self::new()
    }
}

impl StateTransition {
    pub fn new(
        from_state: Hash,
        to_state: Hash,
        transaction_hash: Hash,
        changes: Vec<RollupStateChange>,
        gas_used: u64,
        epoch: u64,
    ) -> Self {
        Self {
            from_state,
            to_state,
            transaction_hash,
            changes,
            gas_used,
            epoch,
            timestamp: ego_core::Timestamp::now(),
        }
    }

    pub fn hash(&self) -> Hash {
        let config = bincode::config::standard();
        let encoded = bincode::encode_to_vec(self, config).unwrap_or_default();
        ego_core::crypto::hash_data(&encoded)
    }
}

impl StateDelta {
    pub fn new() -> Self {
        Self {
            account_changes: HashMap::new(),
            storage_changes: HashMap::new(),
            nonce_changes: HashMap::new(),
            contract_changes: HashMap::new(),
            cross_shard_changes: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.account_changes.is_empty()
            && self.storage_changes.is_empty()
            && self.nonce_changes.is_empty()
            && self.contract_changes.is_empty()
            && self.cross_shard_changes.is_empty()
    }

    pub fn merge(&mut self, other: StateDelta) {
        self.account_changes.extend(other.account_changes);
        for (addr, changes) in other.storage_changes {
            self.storage_changes
                .entry(addr)
                .or_insert_with(HashMap::new)
                .extend(changes);
        }
        self.nonce_changes.extend(other.nonce_changes);
        self.contract_changes.extend(other.contract_changes);
        self.cross_shard_changes.extend(other.cross_shard_changes);
    }
}

impl Default for StateDelta {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::{ShardId, Transaction, TransactionPayload};

    fn create_test_transaction(
        from: Address,
        to: Address,
        amount: Balance,
        nonce: u64,
        chain_id: u32,
    ) -> RollupTransaction {
        let inner = Transaction::new(
            from,
            nonce,
            TransactionPayload::Transfer {
                to,
                amount,
                memo: None,
                stealth_mode: false,
            },
            ShardId::new(0).unwrap(),
            None,
            chain_id,
        );

        crate::types::RollupTransaction::new(inner, nonce, 1000)
    }

    #[tokio::test]
    async fn test_state_creation() {
        let state = RollupState::new();
        assert_eq!(state.get_block_height(), 0);
        assert_eq!(state.get_state_root(), Hash::ZERO);
        assert_eq!(state.account_count(), 0);
        assert_eq!(state.get_epoch(), 0);
    }

    #[tokio::test]
    async fn test_genesis_state() {
        let genesis_accounts = vec![
            (Address::new([1u8; 20]), Balance::from_egoc(1000)),
            (Address::new([2u8; 20]), Balance::from_egoc(500)),
        ];

        let state = RollupState::from_genesis(genesis_accounts, ShardId::new(0).unwrap());
        assert_eq!(state.account_count(), 2);
        assert_eq!(
            state.get_balance(Address::new([1u8; 20])),
            Balance::from_egoc(1000)
        );
        assert_eq!(state.get_total_supply(), Balance::from_egoc(1500));
    }

    #[tokio::test]
    async fn test_transfer_execution() {
        let mut state = RollupState::from_genesis(
            vec![(Address::new([1u8; 20]), Balance::from_egoc(1000))],
            ShardId::new(0).unwrap(),
        );

        let tx = create_test_transaction(
            Address::new([1u8; 20]),
            Address::new([2u8; 20]),
            Balance::from_egoc(100),
            1,
            1,
        );

        let result = state.execute_transaction(&tx).await.unwrap();
        assert!(result.success);

        assert_eq!(
            state.get_balance(Address::new([1u8; 20])),
            Balance::from_egoc(900)
        );
        assert_eq!(
            state.get_balance(Address::new([2u8; 20])),
            Balance::from_egoc(100)
        );
        assert_eq!(state.get_nonce(Address::new([1u8; 20])), 1);
    }

    #[tokio::test]
    async fn test_insufficient_balance() {
        let mut state = RollupState::from_genesis(
            vec![(Address::new([1u8; 20]), Balance::from_egoc(50))],
            ShardId::new(0).unwrap(),
        );

        let tx = create_test_transaction(
            Address::new([1u8; 20]),
            Address::new([2u8; 20]),
            Balance::from_egoc(100),
            1,
            1,
        );

        let result = state.execute_transaction(&tx).await.unwrap();
        assert!(!result.success);
        assert!(result.error.is_some());

        assert_eq!(
            state.get_balance(Address::new([1u8; 20])),
            Balance::from_egoc(50)
        );
        assert_eq!(state.get_nonce(Address::new([1u8; 20])), 0);
    }

    #[tokio::test]
    async fn test_contract_deployment() {
        let mut state = RollupState::from_genesis(
            vec![(Address::new([1u8; 20]), Balance::from_egoc(1000))],
            ShardId::new(0).unwrap(),
        );

        let code = vec![0x60, 0x80, 0x60, 0x40];
        let result = state
            .execute_deploy_contract(
                Address::new([1u8; 20]),
                code.clone(),
                vec![],
                Hash::new([1u8; 32]),
            )
            .unwrap();

        assert!(result.success);
        assert_eq!(state.contract_count(), 1);
    }

    #[test]
    fn test_state_root_computation() {
        let mut state = RollupState::new();
        let initial_root = state.compute_state_root();

        let account = Account::new_eoa(Address::new([1u8; 20]), vec![0u8; 32], vec![0u8; 32]);
        state.accounts.insert(Address::new([1u8; 20]), account);

        let new_root = state.compute_state_root();
        assert_ne!(initial_root, new_root);
    }

    #[test]
    fn test_state_delta() {
        let old_state = RollupState::from_genesis(
            vec![(Address::new([1u8; 20]), Balance::from_egoc(1000))],
            ShardId::new(0).unwrap(),
        );

        let mut new_state = old_state.clone();
        new_state.increment_nonce(Address::new([1u8; 20]));

        let delta = new_state.create_state_delta(&old_state);
        assert_eq!(delta.nonce_changes.len(), 1);
        assert_eq!(delta.nonce_changes[&Address::new([1u8; 20])], 1);
    }

    #[test]
    fn test_checkpoint_restore() {
        let mut state = RollupState::from_genesis(
            vec![(Address::new([1u8; 20]), Balance::from_egoc(1000))],
            ShardId::new(0).unwrap(),
        );

        let checkpoint = state.checkpoint();

        state.increment_nonce(Address::new([1u8; 20]));
        assert_eq!(state.get_nonce(Address::new([1u8; 20])), 1);

        state.restore_checkpoint(checkpoint);
        assert_eq!(state.get_nonce(Address::new([1u8; 20])), 0);
    }

    #[test]
    fn test_epoch_advancement() {
        let mut state = RollupState::new();
        assert_eq!(state.get_epoch(), 0);

        state.advance_epoch();
        assert_eq!(state.get_epoch(), 1);

        state.advance_epoch();
        assert_eq!(state.get_epoch(), 2);
    }

    #[test]
    fn test_cross_shard_execution() {
        let mut state = RollupState::from_genesis(
            vec![(Address::new([1u8; 20]), Balance::from_egoc(1000))],
            ShardId::new(0).unwrap(),
        );

        let result = state
            .execute_cross_shard(
                Address::new([1u8; 20]),
                1,
                vec![0x01, 0x02, 0x03],
                Hash::new([1u8; 32]),
            )
            .unwrap();

        assert!(result.success);
        assert_eq!(state.pending_cross_shard_count(), 1);
        assert!(!result.cross_shard_receipts.is_empty());
    }

    #[test]
    fn test_state_snapshot() {
        let state = RollupState::from_genesis(
            vec![(Address::new([1u8; 20]), Balance::from_egoc(1000))],
            ShardId::new(0).unwrap(),
        );

        let snapshot = state.create_snapshot();
        assert_eq!(snapshot.account_count, 1);
        assert_eq!(snapshot.total_supply, Balance::from_egoc(1000));
        assert_eq!(snapshot.shard_id, 0);
    }
}
