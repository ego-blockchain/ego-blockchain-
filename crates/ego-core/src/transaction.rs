use crate::{
    verify_dual_signature, verify_signature, Account, Address, AlgorithmId, Balance, DualSignature,
    EgoError, EgoResult, Hash, PublicKey, ShardId, SliceId, Timestamp,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct Transaction {
    pub hash: Hash,
    pub from: Address,
    pub nonce: u64,
    pub payload: TransactionPayload,
    pub signature: DualSignature,
    pub public_keys: TransactionPublicKeys,
    pub timestamp: Timestamp,
    pub shard_id: ShardId,
    pub slice_id: Option<SliceId>,
    pub protocol_version: u32,
    pub required_algorithms: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct TransactionPublicKeys {
    pub dilithium_pk: PublicKey,
    pub ed25519_pk: Option<PublicKey>,
    pub mlkem_pk: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum TransactionPayload {
    Transfer {
        to: Address,
        amount: Balance,
        memo: Option<String>,
        stealth_mode: bool,
    },
    CreateAccount {
        account_address: Address,
        account_type: crate::account::AccountType,
        initial_balance: Balance,
        dilithium_pk: Vec<u8>,
        mlkem_pk: Vec<u8>,
        ed25519_pk: Option<Vec<u8>>,
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
        replication_factor: u8,
    },
    SubmitProof {
        proof_type: String,
        proof_data: Vec<u8>,
        challenge_hash: Hash,
        location_id: String,
        witness_data: Option<crate::block::WitnessData>,
        batch_proof: bool,
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
        fraud_proofs: Vec<FraudProof>,
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
        epoch_anchor: bool,
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
        batch_response: bool,
    },
    PQTransition {
        new_algorithms: Vec<u16>,
        disable_legacy: bool,
        transition_epoch: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct FraudProof {
    pub claim_hash: Hash,
    pub proof_data: Vec<u8>,
    pub challenge_period: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct AccountUpdates {
    pub storage_quota: Option<u64>,
    pub add_slices: Vec<SliceId>,
    pub remove_slices: Vec<SliceId>,
    pub device_capabilities: Option<crate::account::DeviceCapabilities>,
    pub metadata_updates: HashMap<String, Option<String>>,
    pub dilithium_pk: Option<Vec<u8>>,
    pub mlkem_pk: Option<Vec<u8>>,
    pub ed25519_pk: Option<Vec<u8>>,
    pub x25519_pk: Option<Vec<u8>>,
    pub peer_id: Option<String>,
    pub pq_transition: Option<crate::account::PQTransitionInfo>,
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
    pub pq_verification_result: Option<PQVerificationResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PQVerificationResult {
    pub dilithium_verified: bool,
    pub ed25519_verified: Option<bool>,
    pub algorithms_used: Vec<u16>,
    pub transition_compliant: bool,
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
    PQTransitionUpdate,
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
            signature: DualSignature::new(None, None),
            public_keys: TransactionPublicKeys {
                dilithium_pk: PublicKey::new(AlgorithmId::MlDsa2, vec![0u8; 1312]),
                ed25519_pk: None,
                mlkem_pk: None,
            },
            timestamp: Timestamp::now(),
            shard_id,
            slice_id,
            protocol_version: crate::PROTOCOL_VERSION,
            required_algorithms: vec![AlgorithmId::MlDsa2.as_u16()],
        }
    }

    pub fn sign(
        &mut self,
        keypair: &crate::crypto::KeyPair,
        transition_mode: bool,
    ) -> EgoResult<()> {
        self.public_keys.dilithium_pk = keypair.dilithium_public_key();

        if transition_mode {
            self.public_keys.ed25519_pk = Some(keypair.public_key());
            self.public_keys.mlkem_pk = Some(keypair.kyber_public_key().key_data);
            self.required_algorithms = vec![
                AlgorithmId::MlDsa2.as_u16(),
                AlgorithmId::Ed25519.as_u16(),
                AlgorithmId::MlKem768.as_u16(),
            ];
        } else {
            self.public_keys.ed25519_pk = None;
            self.required_algorithms = vec![AlgorithmId::MlDsa2.as_u16()];
        }

        let expected_address = Address::from_public_key(&self.public_keys.dilithium_pk);
        if expected_address != self.from {
            return Err(EgoError::InvalidTransaction(
                "Sender address does not match public key".to_string(),
            ));
        }

        let signing_data = self.create_signing_data()?;

        self.signature = keypair.sign_hybrid(&signing_data, transition_mode);

        self.hash = crate::crypto::hash_multiple(&[&signing_data, &self.signature_bytes()]);
        Ok(())
    }

    pub fn verify_signature(&self) -> EgoResult<bool> {
        let expected_address = Address::from_public_key(&self.public_keys.dilithium_pk);
        if expected_address != self.from {
            return Ok(false);
        }

        let signing_data = self.create_signing_data()?;

        if let Some(ref ed25519_pk) = self.public_keys.ed25519_pk {
            verify_dual_signature(
                ed25519_pk,
                &self.public_keys.dilithium_pk,
                &signing_data,
                &self.signature,
            )
        } else {
            if let Some(ref dilithium_sig) = self.signature.dilithium_sig {
                verify_signature(&self.public_keys.dilithium_pk, &signing_data, dilithium_sig)
            } else {
                Ok(false)
            }
        }
    }

    fn create_signing_data(&self) -> EgoResult<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(self.from.as_bytes());
        data.extend_from_slice(&self.nonce.to_le_bytes());
        data.extend_from_slice(&self.timestamp.as_millis().to_le_bytes());
        data.extend_from_slice(&self.shard_id.as_u32().to_le_bytes());
        data.extend_from_slice(&self.protocol_version.to_le_bytes());

        for &alg_id in &self.required_algorithms {
            data.extend_from_slice(&alg_id.to_le_bytes());
        }

        if let Some(ref slice_id) = self.slice_id {
            data.extend_from_slice(slice_id.as_str().as_bytes());
        }

        let config = bincode::config::standard();
        let payload_bytes = bincode::encode_to_vec(&self.payload, config)
            .map_err(|e| EgoError::SerializationError(e.to_string()))?;
        data.extend_from_slice(&payload_bytes);
        Ok(data)
    }

    fn signature_bytes(&self) -> Vec<u8> {
        let config = bincode::config::standard();
        bincode::encode_to_vec(&self.signature, config).unwrap_or_default()
    }

    pub fn size(&self) -> usize {
        let config = bincode::config::standard();
        bincode::encode_to_vec(self, config)
            .map(|data| data.len())
            .unwrap_or(0)
    }

    pub fn estimate_compute_cost(&self) -> u64 {
        let base_cost = match &self.payload {
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
            TransactionPayload::SubmitProof {
                proof_data,
                batch_proof,
                ..
            } => {
                let base = 2000 + (proof_data.len() as u64 / 32);
                if *batch_proof {
                    base / 2
                } else {
                    base
                }
            }
            TransactionPayload::Stake { .. } => 800,
            TransactionPayload::Unstake { .. } => 600,
            TransactionPayload::Delegate { .. } => 400,
            TransactionPayload::CrossShard { .. } => 1500,
            TransactionPayload::RollupCommit {
                tx_count,
                fraud_proofs,
                ..
            } => 5000 + (*tx_count as u64 * 10) + (fraud_proofs.len() as u64 * 100),
            TransactionPayload::SliceOperation { .. } => 2000,
            TransactionPayload::SystemOperation { epoch_anchor, .. } => {
                if *epoch_anchor {
                    20000
                } else {
                    10000
                }
            }
            TransactionPayload::DeployContract { contract_code, .. } => {
                5000 + (contract_code.len() as u64 / 100)
            }
            TransactionPayload::BuyStorageCredits { .. } => 300,
            TransactionPayload::BuyDeployCredits { .. } => 300,
            TransactionPayload::UpdateDRS { .. } => 1000,
            TransactionPayload::PoCWitness { .. } => 2000,
            TransactionPayload::PoStChallenge { .. } => 1500,
            TransactionPayload::PoStResponse {
                proof_data,
                batch_response,
                ..
            } => {
                let base = 3000 + (proof_data.len() as u64 / 64);
                if *batch_response {
                    base / 3
                } else {
                    base
                }
            }
            TransactionPayload::PQTransition { .. } => 5000,
        };

        let signature_cost =
            if self.signature.ed25519_sig.is_some() && self.signature.dilithium_sig.is_some() {
                150
            } else if self.signature.dilithium_sig.is_some() {
                100
            } else {
                50
            };

        base_cost + signature_cost
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

        self.validate_pq_requirements(account)?;
        self.validate_cellular_safe_requirements(account)?;
        self.validate_payload_requirements(account)
    }

    fn validate_pq_requirements(&self, account: &Account) -> EgoResult<()> {
        if account.is_pq_only_mode() {
            if self.signature.ed25519_sig.is_some() {
                return Err(EgoError::InvalidTransaction(
                    "Ed25519 signatures not allowed in PQ-only mode".to_string(),
                ));
            }

            if !self
                .required_algorithms
                .contains(&AlgorithmId::MlDsa2.as_u16())
            {
                return Err(EgoError::InvalidTransaction(
                    "Dilithium signature required in PQ-only mode".to_string(),
                ));
            }
        }

        for &alg_id in &self.required_algorithms {
            if !account.supports_algorithm(alg_id) {
                return Err(EgoError::InvalidTransaction(format!(
                    "Algorithm {:04x} not supported by account",
                    alg_id
                )));
            }
        }

        Ok(())
    }

    fn validate_cellular_safe_requirements(&self, account: &Account) -> EgoResult<()> {
        if !account.is_cellular_safe() {
            return Ok(());
        }

        match &self.payload {
            TransactionPayload::StoreData { data_size, .. } => {
                let size_gb = *data_size / (1024 * 1024 * 1024);
                if size_gb > 0 && !account.within_data_limits(size_gb) {
                    return Err(EgoError::InvalidTransaction(
                        "Transaction exceeds cellular data limits".to_string(),
                    ));
                }

                if account.should_use_wifi_only("large_storage") && size_gb > 1 {
                    return Err(EgoError::InvalidTransaction(
                        "Large storage operations require WiFi connection".to_string(),
                    ));
                }
            }
            TransactionPayload::SubmitProof { proof_data, .. } => {
                if proof_data.len() > 1024 * 1024 && account.should_use_wifi_only("heavy_compute") {
                    return Err(EgoError::InvalidTransaction(
                        "Heavy compute operations require WiFi connection".to_string(),
                    ));
                }
            }
            TransactionPayload::DeployContract { contract_code, .. } => {
                if contract_code.len() > 100 * 1024 && account.should_use_wifi_only("heavy_compute")
                {
                    return Err(EgoError::InvalidTransaction(
                        "Large contract deployments require WiFi connection".to_string(),
                    ));
                }
            }
            _ => {}
        }

        Ok(())
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
            TransactionPayload::SystemOperation { epoch_anchor, .. } => {
                if *epoch_anchor && !account.is_validator() {
                    return Err(EgoError::InvalidTransaction(
                        "Only validators can submit epoch anchor operations".to_string(),
                    ));
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
                | TransactionPayload::PQTransition { .. }
        )
    }

    pub fn requires_slh_dsa(&self) -> bool {
        matches!(
            self.payload,
            TransactionPayload::SystemOperation {
                epoch_anchor: true,
                ..
            }
        )
    }

    pub fn get_priority(&self) -> u8 {
        match &self.payload {
            TransactionPayload::SystemOperation {
                epoch_anchor: true, ..
            } => 255,
            TransactionPayload::SystemOperation { .. } => 240,
            TransactionPayload::PQTransition { .. } => 230,
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
