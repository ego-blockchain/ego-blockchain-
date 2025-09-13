use crate::{
    Account, Address, Balance, EgoError, EgoResult, Hash, PublicKey, ShardId, Signature, SliceId,
    Timestamp, verify_signature,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct Transaction {
    pub hash: Hash,
    pub from: Address,
    pub nonce: u64,
    pub payload: TransactionPayload,
    pub signature: Signature,
    pub public_key: PublicKey,
    pub timestamp: Timestamp,
    pub shard_id: ShardId,
    pub slice_id: Option<SliceId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum TransactionPayload {
    Transfer {
        to: Address,
        amount: Balance,
        memo: Option<String>,
    },
    CreateAccount {
        account_address: Address,
        account_type: crate::account::AccountType,
        initial_balance: Balance,
    },
    UpdateAccount {
        account_address: Address,
        updates: AccountUpdates,
    },
    StoreData {
        chunk_id: Hash,
        data_size: u64,
        duration: u64,
        data_hash: Hash,
        slice_id: SliceId,
    },
    SubmitProof {
        proof_type: String,
        proof_data: Vec<u8>,
        challenge_hash: Hash,
        location_id: String,
    },
    Stake {
        amount: Balance,
        validator_pubkey: PublicKey,
        commission_rate: Option<u16>,
    },
    Unstake {
        amount: Balance,
        validator_pubkey: PublicKey,
    },
    Delegate {
        amount: Balance,
        validator_pubkey: PublicKey,
    },
    CrossShard {
        target_shard: ShardId,
        message: Vec<u8>,
        response_hash: Option<Hash>,
    },
    RollupCommit {
        rollup_id: String,
        state_root: Hash,
        tx_count: u32,
        block_range: (u64, u64),
    },
    SliceOperation {
        operation: SliceOperationType,
        slice_id: SliceId,
        params: HashMap<String, String>,
    },
    SystemOperation {
        operation_id: String,
        data: Vec<u8>,
        auth_level: u8,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct AccountUpdates {
    pub storage_quota: Option<u64>,
    pub add_slices: Vec<SliceId>,
    pub remove_slices: Vec<SliceId>,
    pub device_capabilities: Option<crate::account::DeviceCapabilities>,
    pub metadata_updates: HashMap<String, Option<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum SliceOperationType {
    Create,
    Update,
    Authorize,
    Revoke,
    Pause,
    Resume,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct TransactionResult {
    pub tx_hash: Hash,
    pub success: bool,
    pub error: Option<String>,
    pub compute_used: u64,
    pub storage_used: u64,
    pub state_changes: Vec<StateChange>,
    pub events: Vec<TransactionEvent>,
    pub cross_shard_receipts: Vec<CrossShardReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct StateChange {
    pub account: Address,
    pub change_type: StateChangeType,
    pub previous_value: Option<Vec<u8>>,
    pub new_value: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum StateChangeType {
    BalanceUpdate,
    NonceUpdate,
    StorageUpdate,
    AccountCreation,
    AccountDeletion,
    SliceAuthorization,
    ValidatorUpdate,
    ContractState,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct TransactionEvent {
    pub event_type: String,
    pub data: String,
    pub block_height: u64,
    pub tx_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct CrossShardReceipt {
    pub from_shard: ShardId,
    pub to_shard: ShardId,
    pub payload: Vec<u8>,
    pub nonce: u64,
    pub timestamp: Timestamp,
}

impl Transaction {
    pub fn new(
        from: Address,
        nonce: u64,
        payload: TransactionPayload,
        shard_id: ShardId,
        slice_id: Option<SliceId>,
    ) -> Self {
        Self {
            hash: Hash::ZERO,
            from,
            nonce,
            payload,
            signature: Signature::new([0u8; 64]),
            public_key: PublicKey::new([0u8; 32]),
            timestamp: Timestamp::now(),
            shard_id,
            slice_id,
        }
    }

    pub fn sign(&mut self, keypair: &crate::crypto::KeyPair) -> EgoResult<()> {
        self.public_key = keypair.public_key();
        let expected_address = Address::from_public_key(&self.public_key);
        if expected_address != self.from {
            return Err(EgoError::InvalidTransaction(
                "Sender address does not match public key".to_string(),
            ));
        }
        let signing_data = self.create_signing_data()?;
        self.signature = keypair.sign(&signing_data);
        self.hash = crate::crypto::hash_multiple(&[&signing_data, self.signature.as_bytes()]);
        Ok(())
    }

    pub fn verify_signature(&self) -> EgoResult<bool> {
        let expected_address = Address::from_public_key(&self.public_key);
        if expected_address != self.from {
            return Ok(false);
        }
        let signing_data = self.create_signing_data()?;
        verify_signature(&self.public_key, &signing_data, &self.signature)
    }

    fn create_signing_data(&self) -> EgoResult<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(self.from.as_bytes());
        data.extend_from_slice(&self.nonce.to_le_bytes());
        data.extend_from_slice(&self.timestamp.as_millis().to_le_bytes());
        data.extend_from_slice(&self.shard_id.as_u32().to_le_bytes());
        if let Some(ref slice_id) = self.slice_id {
            data.extend_from_slice(slice_id.as_str().as_bytes());
        }
        let config = bincode::config::standard();
        let payload_bytes = bincode::encode_to_vec(&self.payload, config)
            .map_err(|e| EgoError::SerializationError(e.to_string()))?;
        data.extend_from_slice(&payload_bytes);
        Ok(data)
    }

    pub fn size(&self) -> usize {
        let config = bincode::config::standard();
        bincode::encode_to_vec(self, config)
            .map(|data| data.len())
            .unwrap_or(0)
    }

    pub fn estimate_compute_cost(&self) -> u64 {
        match &self.payload {
            TransactionPayload::Transfer { .. } => 100,
            TransactionPayload::CreateAccount { .. } => 1000,
            TransactionPayload::UpdateAccount { .. } => 500,
            TransactionPayload::StoreData { data_size, .. } => 1000 + (*data_size / 1024),
            TransactionPayload::SubmitProof { proof_data, .. } => {
                2000 + (proof_data.len() as u64 / 32)
            }
            TransactionPayload::Stake { .. } => 800,
            TransactionPayload::Unstake { .. } => 600,
            TransactionPayload::Delegate { .. } => 400,
            TransactionPayload::CrossShard { .. } => 1500,
            TransactionPayload::RollupCommit { tx_count, .. } => 5000 + (*tx_count as u64 * 10),
            TransactionPayload::SliceOperation { .. } => 2000,
            TransactionPayload::SystemOperation { .. } => 10000,
        }
    }

    pub fn validate_against_account(&self, account: &Account) -> EgoResult<()> {
        if self.nonce != account.nonce + 1 {
            return Err(EgoError::InvalidNonce {
                expected: account.nonce + 1,
                got: self.nonce,
            });
        }
        let now = Timestamp::now();
        if self.timestamp.as_millis() > now.as_millis() + 300_000 {
            return Err(EgoError::InvalidTransaction(
                "Transaction timestamp too far in future".to_string(),
            ));
        }
        if let Some(ref slice_id) = self.slice_id {
            if !account.is_authorized_for_slice(slice_id) {
                return Err(EgoError::UnauthorizedSlice {
                    slice_id: slice_id.as_str().to_string(),
                });
            }
        }
        self.validate_payload_requirements(account)
    }

    fn validate_payload_requirements(&self, account: &Account) -> EgoResult<()> {
        match &self.payload {
            TransactionPayload::Transfer { amount, .. } => {
                if !account.can_spend(*amount) {
                    return Err(EgoError::InsufficientBalance {
                        required: amount.as_u128(),
                        available: account.balance.as_u128(),
                    });
                }
            }
            TransactionPayload::CreateAccount {
                initial_balance, ..
            } => {
                if !account.can_spend(*initial_balance) {
                    return Err(EgoError::InsufficientBalance {
                        required: initial_balance.as_u128(),
                        available: account.balance.as_u128(),
                    });
                }
            }
            TransactionPayload::StoreData { data_size, .. } => {
                if !account.can_store(*data_size) {
                    return Err(EgoError::StorageQuotaExceeded {
                        used: account.storage_used + data_size,
                        limit: account.storage_quota,
                    });
                }
            }
            TransactionPayload::Stake { amount, .. }
            | TransactionPayload::Delegate { amount, .. } => {
                if !account.can_spend(*amount) {
                    return Err(EgoError::InsufficientBalance {
                        required: amount.as_u128(),
                        available: account.balance.as_u128(),
                    });
                }
            }
            _ => {}
        }
        Ok(())
    }
}
