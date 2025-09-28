use crate::{
    Account, Address, AlgorithmId, Balance, EgoError, EgoResult, Hash, PublicKey, ShardId,
    Signature, SliceId, Timestamp, verify_signature,
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
    pub dilithium_signature: Option<Vec<u8>>,
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
        dilithium_pk: Vec<u8>,
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
        storage_credits: u64,
    },
    SubmitProof {
        proof_type: String,
        proof_data: Vec<u8>,
        challenge_hash: Hash,
        location_id: String,
        witness_data: Option<crate::block::WitnessData>,
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
    DeployContract {
        contract_code: Vec<u8>,
        constructor_args: Vec<u8>,
        deploy_credits: u64,
        use_free_quota: bool,
    },
    BuyStorageCredits {
        amount: Balance,
        credits: u64,
    },
    BuyDeployCredits {
        amount: Balance,
        credits: u64,
    },
    UpdateDRS {
        node_id: Address,
        metrics_hash: Hash,
        epoch: u64,
    },
    PoCWitness {
        prover: Address,
        location_data: Vec<u8>,
        signal_data: Vec<u8>,
        witnesses: Vec<Address>,
    },
    PoStChallenge {
        challenged_node: Address,
        challenge_data: Vec<u8>,
        deadline_block: u64,
    },
    PoStResponse {
        challenge_hash: Hash,
        proof_data: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct AccountUpdates {
    pub storage_quota: Option<u64>,
    pub add_slices: Vec<SliceId>,
    pub remove_slices: Vec<SliceId>,
    pub device_capabilities: Option<crate::account::DeviceCapabilities>,
    pub metadata_updates: HashMap<String, Option<String>>,
    pub dilithium_pk: Option<Vec<u8>>,
    pub mlkem_pk: Option<Vec<u8>>,
    pub peer_id: Option<String>,
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
    DRSScoreUpdate,
    StorageCreditsUpdate,
    DeployCreditsUpdate,
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
            signature: Signature::new(AlgorithmId::Ed25519, vec![0u8; 64]),
            public_key: PublicKey::new(AlgorithmId::Ed25519, &[0u8; 32]),
            timestamp: Timestamp::now(),
            shard_id,
            slice_id,
            dilithium_signature: None,
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
        let dilithium_sig = keypair.sign_dilithium(&signing_data);
        self.dilithium_signature = Some(dilithium_sig.signature_data);

        self.hash = crate::crypto::hash_multiple(&[&signing_data, self.signature.as_bytes()]);
        Ok(())
    }

    pub fn verify_signature(&self) -> EgoResult<bool> {
        let expected_address = Address::from_public_key(&self.public_key);
        if expected_address != self.from {
            return Ok(false);
        }

        let signing_data = self.create_signing_data()?;

        let ed25519_valid = verify_signature(&self.public_key, &signing_data, &self.signature)?;

        Ok(ed25519_valid)
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
            TransactionPayload::DeployContract { contract_code, .. } => {
                5000 + (contract_code.len() as u64 / 100)
            }
            TransactionPayload::BuyStorageCredits { .. } => 300,
            TransactionPayload::BuyDeployCredits { .. } => 300,
            TransactionPayload::UpdateDRS { .. } => 1000,
            TransactionPayload::PoCWitness { .. } => 2000,
            TransactionPayload::PoStChallenge { .. } => 1500,
            TransactionPayload::PoStResponse { proof_data, .. } => {
                3000 + (proof_data.len() as u64 / 64)
            }
        }
    }

    pub fn validate_against_account(&self, account: &Account) -> EgoResult<()> {
        let expected_nonce = if self.is_cross_shard() {
            account.get_shard_nonce(self.shard_id.as_u32()) + 1
        } else {
            account.nonce + 1
        };

        if self.nonce != expected_nonce {
            return Err(EgoError::InvalidNonce {
                expected: expected_nonce,
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

    fn is_cross_shard(&self) -> bool {
        matches!(
            self.payload,
            TransactionPayload::CrossShard { .. } | TransactionPayload::RollupCommit { .. }
        )
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
            TransactionPayload::StoreData {
                data_size,
                storage_credits,
                ..
            } => {
                if !account.can_store(*data_size) {
                    return Err(EgoError::StorageQuotaExceeded {
                        used: account.storage_used + data_size,
                        limit: account.storage_quota,
                    });
                }
                if account.storage_credits < *storage_credits {
                    return Err(EgoError::InsufficientBalance {
                        required: *storage_credits as u128,
                        available: account.storage_credits as u128,
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
            TransactionPayload::DeployContract {
                deploy_credits,
                use_free_quota,
                ..
            } => {
                if *use_free_quota {
                    if !account.can_deploy_free() {
                        return Err(EgoError::InvalidTransaction(
                            "No free deploys remaining".to_string(),
                        ));
                    }
                } else if !account.can_use_deploy_credits(*deploy_credits) {
                    return Err(EgoError::InsufficientBalance {
                        required: *deploy_credits as u128,
                        available: account.deploy_credits as u128,
                    });
                }
            }
            TransactionPayload::BuyStorageCredits { amount, .. }
            | TransactionPayload::BuyDeployCredits { amount, .. } => {
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

    pub fn requires_dilithium(&self) -> bool {
        matches!(
            self.payload,
            TransactionPayload::SystemOperation { .. }
                | TransactionPayload::UpdateDRS { .. }
                | TransactionPayload::CreateAccount { .. }
        )
    }

    pub fn get_priority(&self) -> u8 {
        match &self.payload {
            TransactionPayload::SystemOperation { .. } => 255,
            TransactionPayload::PoStChallenge { .. } | TransactionPayload::PoStResponse { .. } => {
                200
            }
            TransactionPayload::PoCWitness { .. } => 180,
            TransactionPayload::CrossShard { .. } => 160,
            TransactionPayload::RollupCommit { .. } => 140,
            TransactionPayload::SubmitProof { .. } => 120,
            TransactionPayload::UpdateDRS { .. } => 100,
            TransactionPayload::DeployContract { .. } => 80,
            TransactionPayload::Stake { .. } | TransactionPayload::Delegate { .. } => 60,
            TransactionPayload::Transfer { .. } => 40,
            _ => 20,
        }
    }
}
