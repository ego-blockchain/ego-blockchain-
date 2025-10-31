use crate::error::{RollupError, RollupResult};
use crate::types::{RollupTransaction, StateChange};
use ego_core::{Account, Address, Balance, Hash, Transaction, TransactionResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct RollupState {
    accounts: HashMap<Address, Account>,
    storage: HashMap<Address, HashMap<Vec<u8>, Vec<u8>>>,
    nonces: HashMap<Address, u64>,
    block_height: u64,
    state_root: Hash,
    total_supply: Balance,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct StateTransition {
    pub from_state: Hash,
    pub to_state: Hash,
    pub transaction_hash: Hash,
    pub changes: Vec<StateChange>,
    pub gas_used: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct StateDelta {
    pub account_changes: HashMap<Address, AccountDelta>,
    pub storage_changes: HashMap<Address, HashMap<Vec<u8>, StorageChange>>,
    pub nonce_changes: HashMap<Address, u64>,
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

impl RollupState {
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
            storage: HashMap::new(),
            nonces: HashMap::new(),
            block_height: 0,
            state_root: Hash::ZERO,
            total_supply: Balance::ZERO,
        }
    }

    pub fn from_genesis(genesis_accounts: Vec<(Address, Balance)>) -> Self {
        let mut state = Self::new();

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
                self.execute_transfer(tx.from, *to, *amount)
            }
            ego_core::TransactionPayload::DeployContract { .. } => Ok(TransactionResult {
                tx_hash: tx.hash,
                success: true,
                error: None,
                ru_used: 100000,
                storage_used: 0,
                state_changes: vec![],
                events: vec![],
                cross_shard_receipts: vec![],
                pq_verification_result: None,
                proof_verifications: vec![],
            }),
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
    ) -> RollupResult<TransactionResult> {
        let mut from_account = self.get_or_create_account(from);
        let mut to_account = self.get_or_create_account(to);

        if !from_account.can_spend(amount) {
            return Ok(TransactionResult {
                tx_hash: Hash::ZERO,
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

        self.accounts.insert(from, from_account);
        self.accounts.insert(to, to_account);

        Ok(TransactionResult {
            tx_hash: Hash::ZERO,
            success: true,
            error: None,
            ru_used: 21000,
            storage_used: 0,
            state_changes: vec![],
            events: vec![],
            cross_shard_receipts: vec![],
            pq_verification_result: None,
            proof_verifications: vec![],
        })
    }

    pub fn get_account(&self, address: Address) -> Option<Account> {
        self.accounts.get(&address).cloned()
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

        ego_core::crypto::hash_data(&data)
    }

    pub fn create_state_delta(&self, old_state: &RollupState) -> StateDelta {
        let mut account_changes = HashMap::new();
        let mut storage_changes = HashMap::new();
        let mut nonce_changes = HashMap::new();

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

        StateDelta {
            account_changes,
            storage_changes,
            nonce_changes,
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

        for (address, storage_changes) in &delta.storage_changes {
            let storage_map = self.storage.entry(*address).or_insert_with(HashMap::new);
            for (key, storage_change) in storage_changes {
                storage_map.insert(key.clone(), storage_change.new_value.clone());
            }
        }

        for (address, nonce) in &delta.nonce_changes {
            self.nonces.insert(*address, *nonce);
        }

        self.state_root = self.compute_state_root();

        Ok(())
    }

    pub fn get_state_root(&self) -> Hash {
        self.state_root
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

    pub fn validate_state_transition(&self, transition: &StateTransition) -> RollupResult<bool> {
        if transition.from_state != self.state_root {
            return Ok(false);
        }

        if transition.changes.is_empty() {
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
        }
    }

    pub fn restore_checkpoint(&mut self, checkpoint: StateCheckpoint) {
        self.accounts = checkpoint.accounts;
        self.storage = checkpoint.storage;
        self.nonces = checkpoint.nonces;
        self.block_height = checkpoint.block_height;
        self.state_root = checkpoint.state_root;
        self.total_supply = checkpoint.total_supply;
    }
}

#[derive(Debug, Clone)]
pub struct StateCheckpoint {
    accounts: HashMap<Address, Account>,
    storage: HashMap<Address, HashMap<Vec<u8>, Vec<u8>>>,
    nonces: HashMap<Address, u64>,
    block_height: u64,
    state_root: Hash,
    total_supply: Balance,
}

impl Default for RollupState {
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
            1, 
        );

        crate::types::RollupTransaction::new(inner, nonce, 1000)
    }

    #[tokio::test]
    async fn test_state_creation() {
        let state = RollupState::new();
        assert_eq!(state.get_block_height(), 0);
        assert_eq!(state.get_state_root(), Hash::ZERO);
        assert_eq!(state.account_count(), 0);
    }

    #[tokio::test]
    async fn test_genesis_state() {
        let genesis_accounts = vec![
            (Address::new([1u8; 20]), Balance::from_egoc(1000)),
            (Address::new([2u8; 20]), Balance::from_egoc(500)),
        ];

        let state = RollupState::from_genesis(genesis_accounts);
        assert_eq!(state.account_count(), 2);
        assert_eq!(
            state.get_balance(Address::new([1u8; 20])),
            Balance::from_egoc(1000)
        );
        assert_eq!(state.get_total_supply(), Balance::from_egoc(1500));
    }

    #[tokio::test]
    async fn test_transfer_execution() {
        let mut state =
            RollupState::from_genesis(vec![(Address::new([1u8; 20]), Balance::from_egoc(1000))]);

        let tx = create_test_transaction(
            Address::new([1u8; 20]),
            Address::new([2u8; 20]),
            Balance::from_egoc(100),
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
        let mut state =
            RollupState::from_genesis(vec![(Address::new([1u8; 20]), Balance::from_egoc(50))]);

        let tx = create_test_transaction(
            Address::new([1u8; 20]),
            Address::new([2u8; 20]),
            Balance::from_egoc(100),
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
    async fn test_invalid_nonce() {
        let mut state =
            RollupState::from_genesis(vec![(Address::new([1u8; 20]), Balance::from_egoc(1000))]);

        let tx = create_test_transaction(
            Address::new([1u8; 20]),
            Address::new([2u8; 20]),
            Balance::from_egoc(100),
            5,
        );

        let result = state.execute_transaction(&tx).await.unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("Invalid nonce"));
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
        let mut old_state =
            RollupState::from_genesis(vec![(Address::new([1u8; 20]), Balance::from_egoc(1000))]);

        let mut new_state = old_state.clone();
        new_state.increment_nonce(Address::new([1u8; 20]));

        let delta = new_state.create_state_delta(&old_state);
        assert_eq!(delta.nonce_changes.len(), 1);
        assert_eq!(delta.nonce_changes[&Address::new([1u8; 20])], 1);
    }

    #[test]
    fn test_checkpoint_restore() {
        let mut state =
            RollupState::from_genesis(vec![(Address::new([1u8; 20]), Balance::from_egoc(1000))]);

        let checkpoint = state.checkpoint();

        state.increment_nonce(Address::new([1u8; 20]));
        assert_eq!(state.get_nonce(Address::new([1u8; 20])), 1);

        state.restore_checkpoint(checkpoint);
        assert_eq!(state.get_nonce(Address::new([1u8; 20])), 0);
    }
}
