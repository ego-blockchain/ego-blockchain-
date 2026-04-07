use crate::{
    verify_dual_signature, verify_signature, Account, Address, AlgorithmId, Balance, DualSignature,
    EgoError, EgoResult, Hash, PublicKey, ShardId, SliceId, Timestamp,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const DOMAINTAG_TX_V1: &[u8] = b"ego/tx/v1";
pub const DOMAINTAG_HEADER_V1: &[u8] = b"ego/header/v1";
pub const DOMAINTAG_EVENT_V1: &[u8] = b"ego/event/v1";

/// Typed payload carried inside a `CrossShard` transaction's `message` field.
///
/// Serialized with `serde_json` so it is human-readable in explorers and
/// relay logs.  The receiving shard deserializes this to know what state
/// change to apply.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CrossShardMessage {
    /// Move `amount` uEGOC from the sender (on the source shard) to `to` (on the dest shard).
    Transfer { to: Address, amount: Balance },
    /// Invoke a contract on the destination shard on behalf of the original sender.
    ContractCall {
        contract: Address,
        method: String,
        args: Vec<u8>,
        value: Balance,
        /// Original sender address (on the source shard) — used for access control in the contract.
        original_sender: Address,
    },
}

impl CrossShardMessage {
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}

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
    pub chain_id: u32,
    pub required_algorithms: Vec<u16>,

    pub ru_limit: u64,
    pub ru_estimate: u64,
    pub pob_burn_credits: u64,
    pub priority_hint: u8,
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
        duration_epochs: u64,
        data_hash: Hash,
        slice_id: SliceId,
        storage_credits: u64,
        replication_factor: u8,
        triad_placement: TriadPlacement,
        erasure_coding: ErasureCodingParams,
        encryption_envelope: Option<EncryptionEnvelope>,
    },

    UpdateTriadPlacement {
        chunk_id: Hash,
        group_id: String,
        new_placement: TriadPlacement,
        reason: PlacementUpdateReason,
        signature: Vec<u8>,
    },

    SubmitProofBatch {
        proof_type: ProofType,
        proofs: Vec<ProofSubmission>,
        batch_merkle_root: Hash,
        epoch: u64,
        rollup_id: Option<String>,
    },

    PoStChallenge {
        challenged_node: Address,
        chunk_ids: Vec<Hash>,
        challenge_seed: [u8; 32],
        vrf_proof: Vec<u8>,
        deadline_block: u64,
        epoch: u64,
    },

    PoStResponse {
        challenge_hash: Hash,
        proofs: Vec<PoStProof>,
        batch_merkle_root: Hash,
        latency_ms: Vec<u32>,
    },

    PoCWitnessReport {
        prover: Address,
        location_h3: String,
        witness_reports: Vec<WitnessReport>,
        signal_quality: SignalQuality,
        multi_witness_proof: Vec<u8>,
        timestamp_proof: Vec<u8>,
    },

    RollupCommit {
        rollup_id: String,
        state_root: Hash,
        tx_root: Hash,
        proofs_root: Hash,
        da_root: Hash,
        tx_count: u32,
        block_range: (u64, u64),
        epoch: u64,
        min_validity_proof: Vec<u8>,
        fraud_proofs: Vec<FraudProof>,
        operator_signature: Vec<u8>,
    },

    ChallengeFraud {
        rollup_id: String,
        commit_hash: Hash,
        fraud_type: FraudType,
        proof_data: Vec<u8>,
        challenger: Address,
        challenge_bond: Balance,
    },

    ResolveFraudChallenge {
        challenge_id: Hash,
        resolution: FraudResolution,
        evidence: Vec<u8>,
        slashing_amount: Option<Balance>,
    },

    ClaimRewards {
        node_id: Address,
        epoch: u64,
        reward_buckets: RewardClaim,
        drs_score: f64,
        drs_multiplier: f64,
        evidence_hash: Hash,
    },

    BuyStorageCredits {
        amount: Balance,
        credits_byte_months: u64,
        burn_proof: Hash,
    },

    BuyDeployCredits {
        amount: Balance,
        credits: u64,
        burn_proof: Hash,
    },

    StreamStoragePayment {
        provider: Address,
        chunk_id: Hash,
        credits_consumed: u64,
        period_start: u64,
        period_end: u64,
        audit_passed: bool,
    },

    PayRetrievalFee {
        provider: Address,
        chunk_ids: Vec<Hash>,
        bytes_served: u64,
        rate_per_gb: Balance,
        session_proof: Vec<u8>,
    },

    Stake {
        amount: Balance,
        validator_pubkey: PublicKey,
        lock_duration_epochs: u64,
        commission_rate: Option<u16>,
    },

    Unstake {
        amount: Balance,
        validator_pubkey: PublicKey,
        unlock_epoch: u64,
    },

    Delegate {
        amount: Balance,
        validator_pubkey: PublicKey,
    },

    UpdateValidatorMetrics {
        validator: Address,
        epoch: u64,
        uptime_percent: u8,
        peer_degree: u16,
        relay_bytes: u64,
        iot_sessions: u32,
        shard_demand_score: u16,
        puc_coefficient: f64,
    },

    CrossShard {
        target_shard: ShardId,
        message: Vec<u8>,
        response_hash: Option<Hash>,
        deadline_epoch: u64,
        nonce: u64,
    },

    DeployContract {
        wasm_bytes: Vec<u8>,
        contract_code_hash: Hash,
        constructor_args: Vec<u8>,
        deploy_credits: u64,
        use_free_quota: bool,
        storage_refs: Vec<Hash>,
    },

    ExecuteContract {
        contract_address: Address,
        method: String,
        args: Vec<u8>,
        value: Balance,
    },

    SliceOperation {
        operation: SliceOperationType,
        slice_id: SliceId,
        params: HashMap<String, String>,
    },

    UpdateDRS {
        node_id: Address,
        epoch: u64,
        uptime_score: f64,
        post_latency_score: f64,
        post_pass_rate: f64,
        poc_quality_score: f64,
        serve_ratio: f64,
        density_penalty: f64,
        final_multiplier: f64,
        metrics_hash: Hash,
    },

    SystemOperation {
        operation_id: String,
        data: Vec<u8>,
        auth_level: u8,
        epoch_anchor: bool,
        requires_quorum: bool,
    },

    PQTransition {
        new_algorithms: Vec<u16>,
        disable_legacy: bool,
        transition_epoch: u64,
        migration_period_epochs: u64,
    },

    DAOProposal {
        proposal_type: DAOProposalType,
        title: String,
        params: HashMap<String, Vec<u8>>,
        voting_period_epochs: u64,
        execution_delay_epochs: u64,
    },

    DAOVote {
        proposal_id: Hash,
        vote: bool,
        voting_power: Balance,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct TxOutStealth {
    pub pk_1t: Vec<u8>,
    pub enc: StealthEncryption,
    pub receiver_pk_id: Option<Hash>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct StealthEncryption {
    pub kyber_ct: Vec<u8>,
    pub nonce24: [u8; 24],
    pub aead_ct: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct TriadPlacement {
    pub primary: NodeLocation,
    pub replica_a: NodeLocation,
    pub replica_b: NodeLocation,
    pub group_id: String,
    pub placement_epoch: u64,
    pub diversity_score: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct NodeLocation {
    pub node_id: Address,
    pub h3_cell: String,
    pub shard_id: u32,
    pub region: String,
    pub lat_lon: Option<(f64, f64)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum PlacementUpdateReason {
    NodeFailure,
    AuditFailure,
    Promotion,
    Repair,
    Rebalancing,
    NodeDeactivation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ErasureCodingParams {
    pub k: u16,
    pub m: u16,
    pub codec: ErasureCodec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum ErasureCodec {
    ReedSolomon,
    LDPC,
    Fountain,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct EncryptionEnvelope {
    pub kyber_ciphertexts: Vec<Vec<u8>>,
    pub recipient_addresses: Vec<Address>,
    pub nonce24: [u8; 24],
    pub auth_tag: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum ProofType {
    PoSt,
    PoRep,
    PoC,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ProofSubmission {
    pub chunk_id: Hash,
    pub proof_data: Vec<u8>,
    pub challenge_hash: Hash,
    pub latency_ms: u32,
    pub node_signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PoStProof {
    pub chunk_id: Hash,
    pub merkle_proof: Vec<Hash>,
    pub challenge_response: Vec<u8>,
    pub timestamp: Timestamp,
    pub latency_ms: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct WitnessReport {
    pub witness_id: Address,
    pub signal_strength_dbm: i16,
    pub timing_advance: u16,
    pub snr_db: f32,
    pub path_loss_db: f32,
    pub witness_signature: Vec<u8>,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct SignalQuality {
    pub rsrp_dbm: i16,
    pub rsrq_db: f32,
    pub sinr_db: f32,
    pub cell_id: u32,
    pub confidence_score: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct FraudProof {
    pub claim_hash: Hash,
    pub proof_data: Vec<u8>,
    pub challenge_period_epochs: u64,
    pub fraud_type: FraudType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum FraudType {
    InvalidStateTransition,
    DataUnavailability,
    InvalidProof,
    DoubleSigning,
    InvalidTriadPlacement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum FraudResolution {
    ChallengeValid,
    ChallengeInvalid,
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct RewardClaim {
    pub storage_rewards: Balance,
    pub consensus_rewards: Balance,
    pub coverage_rewards: Balance,
    pub retrieval_fees: Balance,
    pub total: Balance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum DAOProposalType {
    UpdateRewardSplit,
    UpdateDRSWeights,
    UpdateStorageCreditPrice,
    UpdateRetrievalRate,
    UpdateSlashingParams,
    UpdateQuotas,
    Emergency,
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
    pub ru_used: u64,
    pub storage_used: u64,
    pub state_changes: Vec<StateChange>,
    pub events: Vec<TransactionEvent>,
    pub cross_shard_receipts: Vec<CrossShardReceipt>,
    pub pq_verification_result: Option<PQVerificationResult>,
    pub proof_verifications: Vec<ProofVerificationResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ProofVerificationResult {
    pub proof_type: ProofType,
    pub verified: bool,
    pub latency_within_sla: bool,
    pub verification_time_ms: u32,
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
    TriadPlacementUpdate,
    RewardDistribution,
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
    pub src_shard: ShardId,
    pub dst_shard: ShardId,
    pub src_block_hash: Hash,
    pub tx_id: Hash,
    pub payload: Vec<u8>,
    pub nonce: u64,
    pub deadline_epoch: u64,
    pub merkle_proof: Vec<Hash>,
}

impl Transaction {
    pub fn new(
        from: Address,
        nonce: u64,
        payload: TransactionPayload,
        shard_id: ShardId,
        slice_id: Option<SliceId>,
        chain_id: u32,
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
            chain_id,
            required_algorithms: vec![AlgorithmId::MlDsa2.as_u16()],
            ru_limit: 1_000_000,
            ru_estimate: 100_000,
            pob_burn_credits: 0,
            priority_hint: 0,
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
            if self.signature.ed25519_sig.is_some() && self.signature.dilithium_sig.is_some() {
                return verify_dual_signature(
                    ed25519_pk,
                    &self.public_keys.dilithium_pk,
                    &signing_data,
                    &self.signature,
                );
            }
        }

        if let Some(ref dilithium_sig) = self.signature.dilithium_sig {
            verify_signature(&self.public_keys.dilithium_pk, &signing_data, dilithium_sig)
        } else {
            Ok(false)
        }
    }

    fn create_signing_data(&self) -> EgoResult<Vec<u8>> {
        let mut data = Vec::new();

        data.extend_from_slice(DOMAINTAG_TX_V1);

        data.extend_from_slice(self.from.as_bytes());
        data.extend_from_slice(&self.nonce.to_le_bytes());
        data.extend_from_slice(&self.timestamp.as_millis().to_le_bytes());
        data.extend_from_slice(&self.shard_id.as_u32().to_le_bytes());
        data.extend_from_slice(&self.protocol_version.to_le_bytes());
        data.extend_from_slice(&self.chain_id.to_le_bytes());

        data.extend_from_slice(&self.ru_limit.to_le_bytes());
        data.extend_from_slice(&self.ru_estimate.to_le_bytes());
        data.extend_from_slice(&self.pob_burn_credits.to_le_bytes());
        data.extend_from_slice(&[self.priority_hint]);

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

        Ok(crate::crypto::blake2s_hash(&data).to_vec())
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

    pub fn estimate_resource_units(&self) -> u64 {
        let base_ru = match &self.payload {
            TransactionPayload::Transfer { stealth_mode, .. } => {
                if *stealth_mode {
                    500
                } else {
                    100
                }
            }
            TransactionPayload::CreateAccount { .. } => 1000,
            TransactionPayload::UpdateAccount { updates, .. } => {
                let mut ru = 500;
                ru += updates.metadata_updates.len() as u64 * 50;
                ru
            }
            TransactionPayload::StoreData {
                data_size,
                replication_factor,
                ..
            } => 1000 + (*data_size / 1024) * (*replication_factor as u64),
            TransactionPayload::UpdateTriadPlacement { .. } => 800,
            TransactionPayload::SubmitProofBatch { proofs, .. } => {
                2000 + (proofs.len() as u64 * 100)
            }
            TransactionPayload::PoStChallenge { chunk_ids, .. } => {
                1500 + (chunk_ids.len() as u64 * 50)
            }
            TransactionPayload::PoStResponse { proofs, .. } => 3000 + (proofs.len() as u64 * 150),
            TransactionPayload::PoCWitnessReport {
                witness_reports, ..
            } => 2000 + (witness_reports.len() as u64 * 100),
            TransactionPayload::RollupCommit {
                tx_count,
                fraud_proofs,
                ..
            } => 5000 + (*tx_count as u64 * 10) + (fraud_proofs.len() as u64 * 500),
            TransactionPayload::ChallengeFraud { .. } => 3000,
            TransactionPayload::ResolveFraudChallenge { .. } => 4000,
            TransactionPayload::ClaimRewards { .. } => 1200,
            TransactionPayload::BuyStorageCredits { .. } => 300,
            TransactionPayload::BuyDeployCredits { .. } => 300,
            TransactionPayload::StreamStoragePayment { .. } => 200,
            TransactionPayload::PayRetrievalFee { .. } => 250,
            TransactionPayload::Stake { .. } => 800,
            TransactionPayload::Unstake { .. } => 600,
            TransactionPayload::Delegate { .. } => 400,
            TransactionPayload::UpdateValidatorMetrics { .. } => 1000,
            TransactionPayload::CrossShard { .. } => 1500,
            TransactionPayload::DeployContract { .. } => 5000,
            TransactionPayload::ExecuteContract { .. } => 2000,
            TransactionPayload::SliceOperation { .. } => 2000,
            TransactionPayload::UpdateDRS { .. } => 1000,
            TransactionPayload::SystemOperation { epoch_anchor, .. } => {
                if *epoch_anchor {
                    20000
                } else {
                    10000
                }
            }
            TransactionPayload::PQTransition { .. } => 5000,
            TransactionPayload::DAOProposal { .. } => 3000,
            TransactionPayload::DAOVote { .. } => 500,
        };

        let signature_ru =
            if self.signature.ed25519_sig.is_some() && self.signature.dilithium_sig.is_some() {
                150
            } else if self.signature.dilithium_sig.is_some() {
                100
            } else {
                50
            };

        base_ru + signature_ru
    }

    pub fn validate_against_account(&self, account: &Account) -> EgoResult<()> {
        if self.public_keys.dilithium_pk.key_data != account.dilithium_pk {
            return Err(EgoError::InvalidTransaction(
                "Transaction public key does not match account".to_string(),
            ));
        }

        if !self.verify_signature()? {
            return Err(EgoError::InvalidTransaction(
                "Invalid transaction signature".to_string(),
            ));
        }

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

        if self.ru_estimate > self.ru_limit {
            return Err(EgoError::InvalidTransaction(
                "RU estimate exceeds RU limit".to_string(),
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
            TransactionPayload::SubmitProofBatch { proofs, .. } => {
                if proofs.len() > 100 && account.should_use_wifi_only("heavy_compute") {
                    return Err(EgoError::InvalidTransaction(
                        "Large proof batches require WiFi connection".to_string(),
                    ));
                }
            }
            TransactionPayload::DeployContract { .. } => {
                if account.should_use_wifi_only("heavy_compute") {
                    return Err(EgoError::InvalidTransaction(
                        "Contract deployments require WiFi connection".to_string(),
                    ));
                }
            }
            _ => {}
        }

        Ok(())
    }

    pub fn is_cross_shard(&self) -> bool {
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
            TransactionPayload::ChallengeFraud { challenge_bond, .. } => {
                if !account.can_spend(*challenge_bond) {
                    return Err(EgoError::InsufficientBalance {
                        required: challenge_bond.as_u128(),
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
            TransactionPayload::ClaimRewards { node_id, .. } => {
                if *node_id != account.address {
                    return Err(EgoError::InvalidTransaction(
                        "Can only claim rewards for own node".to_string(),
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
                | TransactionPayload::PoStResponse { .. }
                | TransactionPayload::RollupCommit { .. }
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
        if self.priority_hint > 0 {
            return self.priority_hint;
        }

        match &self.payload {
            TransactionPayload::SystemOperation {
                epoch_anchor: true, ..
            } => 255,
            TransactionPayload::SystemOperation { .. } => 240,
            TransactionPayload::PQTransition { .. } => 230,
            TransactionPayload::PoStChallenge { .. } | TransactionPayload::PoStResponse { .. } => {
                200
            }
            TransactionPayload::PoCWitnessReport { .. } => 180,
            TransactionPayload::CrossShard { .. } => 160,
            TransactionPayload::RollupCommit { .. } => 140,
            TransactionPayload::ChallengeFraud { .. } => 130,
            TransactionPayload::ResolveFraudChallenge { .. } => 125,
            TransactionPayload::SubmitProofBatch { .. } => 120,
            TransactionPayload::UpdateDRS { .. } => 100,
            TransactionPayload::ClaimRewards { .. } => 90,
            TransactionPayload::DeployContract { .. } => 80,
            TransactionPayload::Stake { .. } | TransactionPayload::Delegate { .. } => 60,
            TransactionPayload::Transfer { .. } => 40,
            TransactionPayload::StreamStoragePayment { .. } => 35,
            TransactionPayload::PayRetrievalFee { .. } => 30,
            _ => 20,
        }
    }

    pub fn is_proof_transaction(&self) -> bool {
        matches!(
            self.payload,
            TransactionPayload::SubmitProofBatch { .. }
                | TransactionPayload::PoStChallenge { .. }
                | TransactionPayload::PoStResponse { .. }
                | TransactionPayload::PoCWitnessReport { .. }
        )
    }

    pub fn is_storage_transaction(&self) -> bool {
        matches!(
            self.payload,
            TransactionPayload::StoreData { .. }
                | TransactionPayload::UpdateTriadPlacement { .. }
                | TransactionPayload::BuyStorageCredits { .. }
                | TransactionPayload::StreamStoragePayment { .. }
        )
    }

    pub fn is_reward_transaction(&self) -> bool {
        matches!(
            self.payload,
            TransactionPayload::ClaimRewards { .. }
                | TransactionPayload::StreamStoragePayment { .. }
                | TransactionPayload::PayRetrievalFee { .. }
        )
    }

    pub fn get_affected_chunk_ids(&self) -> Vec<Hash> {
        match &self.payload {
            TransactionPayload::StoreData { chunk_id, .. } => vec![*chunk_id],
            TransactionPayload::UpdateTriadPlacement { chunk_id, .. } => vec![*chunk_id],
            TransactionPayload::PoStChallenge { chunk_ids, .. } => chunk_ids.clone(),
            TransactionPayload::PoStResponse { proofs, .. } => {
                proofs.iter().map(|p| p.chunk_id).collect()
            }
            TransactionPayload::SubmitProofBatch { proofs, .. } => {
                proofs.iter().map(|p| p.chunk_id).collect()
            }
            TransactionPayload::PayRetrievalFee { chunk_ids, .. } => chunk_ids.clone(),
            _ => Vec::new(),
        }
    }

    pub fn extract_triad_placement(&self) -> Option<&TriadPlacement> {
        match &self.payload {
            TransactionPayload::StoreData {
                triad_placement, ..
            } => Some(triad_placement),
            _ => None,
        }
    }

    pub fn extract_drs_update(&self) -> Option<DRSUpdateInfo> {
        match &self.payload {
            TransactionPayload::UpdateDRS {
                node_id,
                epoch,
                uptime_score,
                post_latency_score,
                post_pass_rate,
                poc_quality_score,
                serve_ratio,
                density_penalty,
                final_multiplier,
                metrics_hash,
            } => Some(DRSUpdateInfo {
                node_id: *node_id,
                epoch: *epoch,
                uptime_score: *uptime_score,
                post_latency_score: *post_latency_score,
                post_pass_rate: *post_pass_rate,
                poc_quality_score: *poc_quality_score,
                serve_ratio: *serve_ratio,
                density_penalty: *density_penalty,
                final_multiplier: *final_multiplier,
                metrics_hash: *metrics_hash,
            }),
            _ => None,
        }
    }

    pub fn validate_proof_latency(&self, sla_ms: u32) -> EgoResult<()> {
        match &self.payload {
            TransactionPayload::PoStResponse { latency_ms, .. } => {
                for &latency in latency_ms {
                    if latency > sla_ms {
                        return Err(EgoError::InvalidTransaction(format!(
                            "Proof latency {}ms exceeds SLA {}ms",
                            latency, sla_ms
                        )));
                    }
                }
            }
            TransactionPayload::SubmitProofBatch { proofs, .. } => {
                for proof in proofs {
                    if proof.latency_ms > sla_ms {
                        return Err(EgoError::InvalidTransaction(format!(
                            "Proof latency {}ms exceeds SLA {}ms",
                            proof.latency_ms, sla_ms
                        )));
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub fn validate_triad_diversity(&self, min_distance_km: f64) -> EgoResult<()> {
        if let Some(triad) = self.extract_triad_placement() {
            if triad.diversity_score < 0.5 {
                return Err(EgoError::InvalidTransaction(
                    "Triad placement diversity score too low".to_string(),
                ));
            }

            if let (Some(p_latlon), Some(ra_latlon), Some(rb_latlon)) = (
                triad.primary.lat_lon,
                triad.replica_a.lat_lon,
                triad.replica_b.lat_lon,
            ) {
                let dist_p_ra = haversine_distance(p_latlon, ra_latlon);
                let dist_p_rb = haversine_distance(p_latlon, rb_latlon);
                let dist_ra_rb = haversine_distance(ra_latlon, rb_latlon);

                if dist_p_ra < min_distance_km
                    || dist_p_rb < min_distance_km
                    || dist_ra_rb < min_distance_km
                {
                    return Err(EgoError::InvalidTransaction(format!(
                        "Triad nodes too close (min {}km required)",
                        min_distance_km
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn extract_cross_shard_receipt(&self) -> Option<CrossShardReceipt> {
        match &self.payload {
            TransactionPayload::CrossShard {
                target_shard,
                message,
                nonce,
                deadline_epoch,
                ..
            } => Some(CrossShardReceipt {
                src_shard: self.shard_id,
                dst_shard: *target_shard,
                src_block_hash: Hash::ZERO,
                tx_id: self.hash,
                payload: message.clone(),
                nonce: *nonce,
                deadline_epoch: *deadline_epoch,
                merkle_proof: vec![],
            }),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DRSUpdateInfo {
    pub node_id: Address,
    pub epoch: u64,
    pub uptime_score: f64,
    pub post_latency_score: f64,
    pub post_pass_rate: f64,
    pub poc_quality_score: f64,
    pub serve_ratio: f64,
    pub density_penalty: f64,
    pub final_multiplier: f64,
    pub metrics_hash: Hash,
}

fn haversine_distance(coord1: (f64, f64), coord2: (f64, f64)) -> f64 {
    let (lat1, lon1) = coord1;
    let (lat2, lon2) = coord2;

    let r = 6371.0;
    let lat1_rad = lat1.to_radians();
    let lat2_rad = lat2.to_radians();
    let delta_lat = (lat2 - lat1).to_radians();
    let delta_lon = (lon2 - lon1).to_radians();

    let a = (delta_lat / 2.0).sin().powi(2)
        + lat1_rad.cos() * lat2_rad.cos() * (delta_lon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

    r * c
}

pub struct TransactionBuilder {
    from: Address,
    nonce: u64,
    payload: Option<TransactionPayload>,
    shard_id: ShardId,
    slice_id: Option<SliceId>,
    chain_id: u32,
    ru_limit: u64,
    ru_estimate: u64,
    pob_burn_credits: u64,
    priority_hint: u8,
}

impl TransactionBuilder {
    pub fn new(from: Address, nonce: u64, shard_id: ShardId, chain_id: u32) -> Self {
        Self {
            from,
            nonce,
            payload: None,
            shard_id,
            slice_id: None,
            chain_id,
            ru_limit: 1_000_000,
            ru_estimate: 100_000,
            pob_burn_credits: 0,
            priority_hint: 0,
        }
    }

    pub fn payload(mut self, payload: TransactionPayload) -> Self {
        self.payload = Some(payload);
        self
    }

    pub fn slice_id(mut self, slice_id: SliceId) -> Self {
        self.slice_id = Some(slice_id);
        self
    }

    pub fn ru_limit(mut self, ru_limit: u64) -> Self {
        self.ru_limit = ru_limit;
        self
    }

    pub fn ru_estimate(mut self, ru_estimate: u64) -> Self {
        self.ru_estimate = ru_estimate;
        self
    }

    pub fn pob_burn_credits(mut self, pob_burn_credits: u64) -> Self {
        self.pob_burn_credits = pob_burn_credits;
        self
    }

    pub fn priority_hint(mut self, priority_hint: u8) -> Self {
        self.priority_hint = priority_hint;
        self
    }

    pub fn build(self) -> EgoResult<Transaction> {
        let payload = self.payload.ok_or_else(|| {
            EgoError::InvalidTransaction("Transaction payload is required".to_string())
        })?;

        let mut tx = Transaction::new(
            self.from,
            self.nonce,
            payload,
            self.shard_id,
            self.slice_id,
            self.chain_id,
        );
        tx.ru_limit = self.ru_limit;
        tx.ru_estimate = self.ru_estimate;
        tx.pob_burn_credits = self.pob_burn_credits;
        tx.priority_hint = self.priority_hint;

        Ok(tx)
    }

    pub fn build_and_sign(
        self,
        keypair: &crate::crypto::KeyPair,
        transition_mode: bool,
    ) -> EgoResult<Transaction> {
        let mut tx = self.build()?;
        tx.sign(keypair, transition_mode)?;
        Ok(tx)
    }
}
