use crate::{
    crypto::{hash_data, hash_multiple, verify_dual_signature, verify_signature},
    Account, Address, AlgorithmId, Balance, BlockHeight, DualSignature, EgoError, EgoResult,
    EpochNumber, Hash, PublicKey, ShardId, StateManager, Timestamp, Transaction, TransactionResult,
};
use crate::types::{hex_bytes, hex_bytes32, opt_hex_bytes};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const DOMAIN_TAG_BLOCK_CORE: &[u8] = b"ego/core/v1";
pub const DOMAIN_TAG_QC: &[u8] = b"ego/qc/v1";
pub const MAX_TRANSACTIONS_PER_BLOCK: usize = 10_000;
pub const MAX_BLOCK_SIZE_BYTES: usize = 10 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct BlockHeader {
    pub core: BlockHeaderCore,
    pub qc: QuorumCert,
    pub metadata: BlockMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct BlockHeaderCore {
    pub height: BlockHeight,
    pub previous_hash: Hash,
    pub transactions_root: Hash,
    pub state_root: Hash,
    pub receipts_root: Hash,
    pub events_root_post: Hash,
    pub events_root_poc: Hash,
    pub rollup_root: Hash,
    pub da_root: Hash,
    pub timestamp: Timestamp,
    pub shard_id: ShardId,
    pub epoch: EpochNumber,
    pub proposer: Address,
    pub signature: DualSignature,
    pub tx_count: u32,
    pub compute_used: u64,
    pub storage_used: u64,
    pub protocol_version: u32,
    pub chain_id: u32,
    pub network_id: u32,
    pub pq_signature_count: PQSignatureCount,
    #[serde(with = "hex_bytes32")]
    pub vrf_output: [u8; 32],
    #[serde(with = "opt_hex_bytes")]
    pub vrf_proof: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PQSignatureCount {
    pub dilithium_sigs: u32,
    pub ed25519_sigs: u32,
    pub hybrid_sigs: u32,
    pub slh_dsa_sigs: u32,
}

impl Default for PQSignatureCount {
    fn default() -> Self {
        Self {
            dilithium_sigs: 0,
            ed25519_sigs: 0,
            hybrid_sigs: 0,
            slh_dsa_sigs: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct QuorumCert {
    pub view: u64,
    pub height: BlockHeight,
    pub block_hash: Hash,
    pub signatures: Vec<ValidatorSignature>,
    #[serde(with = "opt_hex_bytes")]
    pub aggregated_signature: Option<Vec<u8>>,
    pub voting_power: u64,
    pub timestamp: Timestamp,
    pub pq_compliant: bool,
    pub validator_set_id: u64,
    pub round: u64,
    #[serde(with = "hex_bytes")]
    pub bitmap: Vec<u8>,
    pub signatures_root: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ValidatorSignature {
    pub validator: Address,
    pub signature: DualSignature,
    pub voting_power: u64,
    pub algorithm_used: Vec<u16>,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct BlockMetadata {
    pub protocol_version: u32,
    pub block_size: u64,
    pub cross_shard_receipts: u32,
    pub rollup_commits: u32,
    pub poc_events: u32,
    pub post_events: u32,
    pub resource_pricing: ResourcePricing,
    pub pq_transition_data: PQTransitionData,
    pub cellular_stats: CellularStats,
    pub density_events: u32,
    pub drs_events: u32,
    pub deploy_events: u32,
    pub fraud_proofs: u32,
}

impl PartialEq for BlockMetadata {
    fn eq(&self, other: &Self) -> bool {
        self.protocol_version == other.protocol_version
            && self.block_size == other.block_size
            && self.cross_shard_receipts == other.cross_shard_receipts
            && self.rollup_commits == other.rollup_commits
            && self.poc_events == other.poc_events
            && self.post_events == other.post_events
    }
}

impl Eq for BlockMetadata {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PQTransitionData {
    pub transition_phase: u8,
    pub pq_required_topics: Vec<String>,
    pub legacy_support_end_epoch: Option<u64>,
    pub algorithm_usage_stats: HashMap<u16, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct CellularStats {
    pub cellular_safe_txs: u32,
    pub wifi_only_txs: u32,
    pub throttled_operations: u32,
    pub avg_cellular_cost_per_tx: f64,
    pub total_data_bytes_cellular: u64,
    pub total_data_bytes_wifi: u64,
}

impl PartialEq for CellularStats {
    fn eq(&self, other: &Self) -> bool {
        self.cellular_safe_txs == other.cellular_safe_txs
            && self.wifi_only_txs == other.wifi_only_txs
            && self.throttled_operations == other.throttled_operations
    }
}

impl Eq for CellularStats {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ResourcePricing {
    pub bytes_cost: u64,
    pub ru_cost: u64,
    pub pob_floor: u64,
    pub pq_signature_cost: u64,
    pub cellular_premium: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct NetworkStats {
    pub active_devices: u32,
    pub bandwidth_utilization: u64,
    pub avg_latency_ms: u32,
    pub active_slices: u32,
    pub storage_utilization: u64,
    pub pq_adoption_rate: f64,
    pub cellular_node_count: u32,
}

impl PartialEq for NetworkStats {
    fn eq(&self, other: &Self) -> bool {
        self.active_devices == other.active_devices
            && self.bandwidth_utilization == other.bandwidth_utilization
            && self.avg_latency_ms == other.avg_latency_ms
            && self.active_slices == other.active_slices
            && self.storage_utilization == other.storage_utilization
    }
}

impl Eq for NetworkStats {}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct Block {
    pub header: BlockHeader,
    pub body: BlockBody,
    pub hash: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct BlockBody {
    pub transactions: Vec<Transaction>,
    pub transaction_results: Vec<TransactionResult>,
    pub rollup_commitments: Vec<RollupCommitment>,
    pub cross_shard_receipts: Vec<CrossShardReceipt>,
    pub proof_events: Vec<ProofEvent>,
    pub drs_events: Vec<DRSEvent>,
    pub deploy_events: Vec<DeployEvent>,
    pub pq_transition_events: Vec<PQTransitionEvent>,
    pub density_events: Vec<DensityEvent>,
    pub fraud_proofs: Vec<FraudProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PQTransitionEvent {
    pub event_type: PQTransitionEventType,
    pub affected_accounts: Vec<Address>,
    pub new_algorithms: Vec<u16>,
    pub epoch: u64,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum PQTransitionEventType {
    HybridModeEnabled,
    PQRequiredOnTopic { topic: String },
    PQOnlyModeEnabled,
    LegacyAlgorithmDisabled { algorithm: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct RollupCommitment {
    pub rollup_id: String,
    pub state_root: Hash,
    pub previous_state_root: Hash,
    pub tx_root: Hash,
    pub proofs_root: Hash,
    pub da_root: Hash,
    pub tx_count: u32,
    pub block_range: (u64, u64),
    pub operator_signature: DualSignature,
    pub operator: Address,
    pub timestamp: Timestamp,
    #[serde(with = "hex_bytes")]
    pub proof_data: Vec<u8>,
    pub fraud_proof_window: u64,
    #[serde(with = "hex_bytes")]
    pub min_validity_proof: Vec<u8>,
    pub epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct CrossShardReceipt {
    pub from_shard: ShardId,
    pub to_shard: ShardId,
    pub nonce: u64,
    #[serde(with = "hex_bytes")]
    pub payload: Vec<u8>,
    pub source_tx_hash: Hash,
    pub timestamp: Timestamp,
    pub receipt_hash: Hash,
    pub deadline_epoch: u64,
    pub merkle_proof: Vec<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ProofEvent {
    pub proof_type: ProofEventType,
    pub prover: Address,
    pub challenge_hash: Hash,
    pub proof_data_hash: Hash,
    pub location_id: String,
    pub slice_id: Option<String>,
    pub timestamp: Timestamp,
    pub verified: bool,
    pub latency_ms: u32,
    pub witness_data: Option<WitnessData>,
    pub batch_proof: bool,
    pub cellular_optimized: bool,
    pub evidence_cid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum ProofEventType {
    PoSt,
    PoRep,
    PoC,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct WitnessData {
    pub rsrp: i16,
    pub rsrq: i16,
    pub sinr: i16,
    pub timing_advance: u32,
    pub gps_coords: Option<(i64, i64)>,
    pub witnesses: Vec<Address>,
    pub h3_cell: String,
    pub confidence_score: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DRSEvent {
    pub node_id: Address,
    pub epoch: u64,
    pub score: u64,
    pub multiplier: u64,
    pub components: DRSComponents,
    pub timestamp: Timestamp,
    pub evidence_root: Hash,
    pub weights_version: u32,
    pub params_digest: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DRSComponents {
    pub uptime_score: u64,
    pub post_pass_rate: u64,
    pub post_latency_score: u64,
    pub poc_quality_score: u64,
    pub serve_ratio: u64,
    pub density_penalty: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DeployEvent {
    pub deployer: Address,
    pub contract_address: Option<Address>,
    pub deploy_type: DeployType,
    pub credits_used: u64,
    pub free_deploy_used: bool,
    pub bond_amount: Option<Balance>,
    pub timestamp: Timestamp,
    pub code_hash: Option<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum DeployType {
    Contract { code_size_kb: u32 },
    StorageDeal { data_size_gb: u32 },
    RollupState { state_size_kb: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DensityEvent {
    pub node_id: Address,
    pub h3_cell: String,
    pub device_count: u32,
    pub density_multiplier: u64,
    pub epoch: u64,
    pub timestamp: Timestamp,
    pub evidence_root: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct FraudProof {
    pub claim_hash: Hash,
    #[serde(with = "hex_bytes")]
    pub proof_data: Vec<u8>,
    pub challenge_period_epochs: u64,
    pub fraud_type: FraudType,
    pub challenger: Address,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum FraudType {
    InvalidStateTransition,
    DataUnavailability,
    InvalidProof,
    DoubleSigning,
    InvalidTriadPlacement,
    InvalidInclusion,
    InvalidAggregation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub validation_cost: u64,
    pub state_changes: HashMap<Address, Account>,
    pub pq_compliance: PQComplianceResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQComplianceResult {
    pub compliant: bool,
    pub transition_phase_valid: bool,
    pub signature_algorithm_valid: bool,
    pub downgrade_attack_detected: bool,
    pub issues: Vec<String>,
}

impl Block {
    pub fn new(
        height: BlockHeight,
        previous_hash: Hash,
        shard_id: ShardId,
        epoch: EpochNumber,
        proposer: Address,
        transactions: Vec<Transaction>,
        rollup_commitments: Vec<RollupCommitment>,
        chain_id: u32,
        network_id: u32,
    ) -> Self {
        let timestamp = Timestamp::now();

        let transactions_root = Self::compute_transactions_root(&transactions);

        let tx_count = transactions.len() as u32;
        let compute_used = transactions
            .iter()
            .map(|tx| tx.estimate_resource_units())
            .sum();
        let storage_used = transactions.iter().map(|tx| tx.size() as u64).sum();

        let pq_signature_count = Self::count_pq_signatures(&transactions);

        let mut vrf_output = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut vrf_output);

        let metadata = BlockMetadata {
            protocol_version: crate::PROTOCOL_VERSION,
            block_size: 0,
            cross_shard_receipts: 0,
            rollup_commits: rollup_commitments.len() as u32,
            poc_events: 0,
            post_events: 0,
            resource_pricing: ResourcePricing {
                bytes_cost: 100,
                ru_cost: 10,
                pob_floor: 1000,
                pq_signature_cost: 50,
                cellular_premium: 25,
            },
            pq_transition_data: PQTransitionData {
                transition_phase: 1,
                pq_required_topics: vec!["consensus".to_string()],
                legacy_support_end_epoch: None,
                algorithm_usage_stats: HashMap::new(),
            },
            cellular_stats: CellularStats {
                cellular_safe_txs: 0,
                wifi_only_txs: 0,
                throttled_operations: 0,
                avg_cellular_cost_per_tx: 0.0,
                total_data_bytes_cellular: 0,
                total_data_bytes_wifi: 0,
            },
            density_events: 0,
            drs_events: 0,
            deploy_events: 0,
            fraud_proofs: 0,
        };

        let core = BlockHeaderCore {
            height,
            previous_hash,
            transactions_root,
            state_root: Hash::ZERO,
            receipts_root: Hash::ZERO,
            events_root_post: Hash::ZERO,
            events_root_poc: Hash::ZERO,
            rollup_root: Hash::ZERO,
            da_root: Hash::ZERO,
            timestamp,
            shard_id,
            epoch,
            proposer,
            signature: DualSignature::new(None, None),
            tx_count,
            compute_used,
            storage_used,
            protocol_version: crate::PROTOCOL_VERSION,
            chain_id,
            network_id,
            pq_signature_count,
            vrf_output,
            vrf_proof: None,
        };

        let qc = QuorumCert {
            view: 0,
            height,
            block_hash: Hash::ZERO,
            signatures: Vec::new(),
            aggregated_signature: None,
            voting_power: 0,
            timestamp,
            pq_compliant: true,
            validator_set_id: 0,
            round: 0,
            bitmap: Vec::new(),
            signatures_root: Hash::ZERO,
        };

        let header = BlockHeader { core, qc, metadata };

        let body = BlockBody {
            transactions,
            transaction_results: Vec::new(),
            rollup_commitments,
            cross_shard_receipts: Vec::new(),
            proof_events: Vec::new(),
            drs_events: Vec::new(),
            deploy_events: Vec::new(),
            pq_transition_events: Vec::new(),
            density_events: Vec::new(),
            fraud_proofs: Vec::new(),
        };

        let mut block = Self {
            header,
            body,
            hash: Hash::ZERO,
        };

        block.hash = block.compute_hash();
        block
    }

    fn count_pq_signatures(transactions: &[Transaction]) -> PQSignatureCount {
        let mut count = PQSignatureCount::default();

        for tx in transactions {
            match (&tx.signature.ed25519_sig, &tx.signature.dilithium_sig) {
                (Some(_), Some(_)) => count.hybrid_sigs += 1,
                (None, Some(_)) => count.dilithium_sigs += 1,
                (Some(_), None) => count.ed25519_sigs += 1,
                (None, None) => {}
            }

            if tx.requires_slh_dsa() {
                count.slh_dsa_sigs += 1;
            }
        }

        count
    }

    pub fn compute_hash(&self) -> Hash {
        let config = bincode::config::standard();

        let mut core_copy = self.header.core.clone();
        core_copy.signature = DualSignature::new(None, None);

        let core_bytes = bincode::encode_to_vec(&core_copy, config).unwrap_or_default();
        let qc_bytes = bincode::encode_to_vec(&self.header.qc, config).unwrap_or_default();
        let metadata_bytes =
            bincode::encode_to_vec(&self.header.metadata, config).unwrap_or_default();

        hash_multiple(&[
            DOMAIN_TAG_BLOCK_CORE,
            &core_bytes,
            &qc_bytes,
            &metadata_bytes,
        ])
    }

    fn compute_transactions_root(transactions: &[Transaction]) -> Hash {
        if transactions.is_empty() {
            return Hash::ZERO;
        }

        let tx_hashes: Vec<Vec<u8>> = transactions.iter().map(|tx| tx.hash.to_vec()).collect();

        let merkle_tree = crate::crypto::MerkleTree::build(tx_hashes);
        merkle_tree.root_hash().unwrap_or(Hash::ZERO)
    }

    pub fn sign(
        &mut self,
        keypair: &crate::crypto::KeyPair,
        transition_mode: bool,
    ) -> EgoResult<()> {
        let expected_proposer = Address::from_public_key(&keypair.dilithium_public_key());
        if expected_proposer != self.header.core.proposer {
            return Err(EgoError::InvalidBlock(
                "Proposer address does not match signing key".to_string(),
            ));
        }

        let signing_data = self.create_signing_data()?;
        self.header.core.signature = keypair.sign_hybrid(&signing_data, transition_mode);
        self.hash = self.compute_hash();

        Ok(())
    }

    fn create_signing_data(&self) -> EgoResult<Vec<u8>> {
        let config = bincode::config::standard();

        let mut core_copy = self.header.core.clone();
        core_copy.signature = DualSignature::new(None, None);

        let mut data = Vec::new();
        data.extend_from_slice(DOMAIN_TAG_BLOCK_CORE);

        let core_bytes = bincode::encode_to_vec(&core_copy, config)
            .map_err(|e| EgoError::SerializationError(e.to_string()))?;
        data.extend_from_slice(&core_bytes);

        Ok(hash_data(&data).to_vec())
    }

    pub fn verify_signature(
        &self,
        proposer_dilithium_pk: &PublicKey,
        proposer_ed25519_pk: Option<&PublicKey>,
    ) -> EgoResult<bool> {
        let expected_proposer = Address::from_public_key(proposer_dilithium_pk);
        if expected_proposer != self.header.core.proposer {
            return Ok(false);
        }

        let signing_data = self.create_signing_data()?;

        if let Some(ed25519_pk) = proposer_ed25519_pk {
            verify_dual_signature(
                ed25519_pk,
                proposer_dilithium_pk,
                &signing_data,
                &self.header.core.signature,
            )
        } else {
            if let Some(ref dilithium_sig) = self.header.core.signature.dilithium_sig {
                verify_signature(proposer_dilithium_pk, &signing_data, dilithium_sig)
            } else {
                Ok(false)
            }
        }
    }

    pub fn validate_structure(&self) -> EgoResult<()> {
        if self.header.core.tx_count != self.body.transactions.len() as u32 {
            return Err(EgoError::InvalidBlock(format!(
                "Transaction count mismatch: header={}, body={}",
                self.header.core.tx_count,
                self.body.transactions.len()
            )));
        }

        let computed_tx_root = Self::compute_transactions_root(&self.body.transactions);
        if computed_tx_root != self.header.core.transactions_root {
            return Err(EgoError::InvalidBlock(
                "Transaction root mismatch".to_string(),
            ));
        }

        let computed_hash = self.compute_hash();
        if computed_hash != self.hash {
            return Err(EgoError::InvalidBlock("Block hash mismatch".to_string()));
        }

        if self.body.transactions.len() > MAX_TRANSACTIONS_PER_BLOCK {
            return Err(EgoError::InvalidBlock(format!(
                "Too many transactions: {} > {}",
                self.body.transactions.len(),
                MAX_TRANSACTIONS_PER_BLOCK
            )));
        }

        let block_size = self.size();
        if block_size > MAX_BLOCK_SIZE_BYTES {
            return Err(EgoError::InvalidBlock(format!(
                "Block size exceeds limit: {} > {}",
                block_size, MAX_BLOCK_SIZE_BYTES
            )));
        }

        self.validate_quorum_cert()?;
        self.validate_pq_compliance()?;

        for tx in &self.body.transactions {
            if !tx.verify_signature()? {
                return Err(EgoError::InvalidBlock(format!(
                    "Invalid transaction signature: {}",
                    tx.hash
                )));
            }
        }

        Ok(())
    }

    pub fn validate_quorum_cert(&self) -> EgoResult<()> {
        if self.header.qc.signatures.is_empty() {
            return Ok(());
        }

        let mut total_voting_power = 0u64;
        for validator_sig in &self.header.qc.signatures {
            total_voting_power = total_voting_power.saturating_add(validator_sig.voting_power);
        }

        if total_voting_power != self.header.qc.voting_power {
            return Err(EgoError::InvalidBlock(
                "Voting power mismatch in quorum certificate".to_string(),
            ));
        }

        if self.header.qc.block_hash != self.hash {
            return Err(EgoError::InvalidBlock(
                "QC block hash does not match block hash".to_string(),
            ));
        }

        Ok(())
    }

    pub fn validate_pq_compliance(&self) -> EgoResult<()> {
        let pq_data = &self.header.metadata.pq_transition_data;

        for topic in &pq_data.pq_required_topics {
            if topic == "consensus" && !self.header.qc.pq_compliant {
                return Err(EgoError::InvalidBlock(
                    "Consensus requires PQ compliance but QC is not PQ compliant".to_string(),
                ));
            }
        }

        if let Some(end_epoch) = pq_data.legacy_support_end_epoch {
            if self.header.core.epoch.as_u64() >= end_epoch {
                for tx in &self.body.transactions {
                    if tx.signature.ed25519_sig.is_some() && tx.signature.dilithium_sig.is_none() {
                        return Err(EgoError::InvalidBlock(
                            "Legacy Ed25519-only signatures not allowed after transition period"
                                .to_string(),
                        ));
                    }
                }

                if self.header.core.signature.ed25519_sig.is_some()
                    && self.header.core.signature.dilithium_sig.is_none()
                {
                    return Err(EgoError::InvalidBlock(
                        "Block proposer using legacy Ed25519-only signature after transition"
                            .to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    pub fn size(&self) -> usize {
        let config = bincode::config::standard();
        bincode::encode_to_vec(self, config)
            .map(|data| data.len())
            .unwrap_or(0)
    }

    pub fn is_genesis(&self) -> bool {
        self.header.core.height == BlockHeight::GENESIS
    }

    pub fn summary(&self) -> String {
        let pq_stats = format!(
            "PQ(D:{}, E:{}, H:{}, S:{})",
            self.header.core.pq_signature_count.dilithium_sigs,
            self.header.core.pq_signature_count.ed25519_sigs,
            self.header.core.pq_signature_count.hybrid_sigs,
            self.header.core.pq_signature_count.slh_dsa_sigs,
        );

        format!(
            "Block {} [Shard {}] - Height: {}, TXs: {}, Size: {} bytes, Proposer: {}, DRS Events: {}, {}",
            self.hash,
            self.header.core.shard_id,
            self.header.core.height.as_u64(),
            self.header.core.tx_count,
            self.size(),
            self.header.core.proposer,
            self.body.drs_events.len(),
            pq_stats
        )
    }

    pub fn add_transaction_results(&mut self, results: Vec<TransactionResult>) {
        self.body.transaction_results = results;
        self.update_event_counts();
        self.update_cellular_stats();
        self.update_algorithm_usage_stats();
    }

    pub fn add_cross_shard_receipts(&mut self, receipts: Vec<CrossShardReceipt>) {
        self.body.cross_shard_receipts = receipts;
        self.header.metadata.cross_shard_receipts = self.body.cross_shard_receipts.len() as u32;
    }

    pub fn add_proof_events(&mut self, events: Vec<ProofEvent>) {
        self.body.proof_events = events;
        self.update_event_counts();
    }

    pub fn add_drs_events(&mut self, events: Vec<DRSEvent>) {
        self.body.drs_events = events;
        self.header.metadata.drs_events = self.body.drs_events.len() as u32;
    }

    pub fn add_deploy_events(&mut self, events: Vec<DeployEvent>) {
        self.body.deploy_events = events;
        self.header.metadata.deploy_events = self.body.deploy_events.len() as u32;
    }

    pub fn add_pq_transition_events(&mut self, events: Vec<PQTransitionEvent>) {
        self.body.pq_transition_events = events;
    }

    pub fn add_density_events(&mut self, events: Vec<DensityEvent>) {
        self.body.density_events = events;
        self.header.metadata.density_events = self.body.density_events.len() as u32;
    }

    pub fn add_fraud_proofs(&mut self, proofs: Vec<FraudProof>) {
        self.body.fraud_proofs = proofs;
        self.header.metadata.fraud_proofs = self.body.fraud_proofs.len() as u32;
    }

    fn update_event_counts(&mut self) {
        self.header.metadata.poc_events = self
            .body
            .proof_events
            .iter()
            .filter(|e| matches!(e.proof_type, ProofEventType::PoC))
            .count() as u32;

        self.header.metadata.post_events = self
            .body
            .proof_events
            .iter()
            .filter(|e| matches!(e.proof_type, ProofEventType::PoSt))
            .count() as u32;
    }

    fn update_cellular_stats(&mut self) {
        let mut cellular_safe_count = 0u32;
        let mut wifi_only_count = 0u32;
        let mut total_cellular_bytes = 0u64;
        let mut total_wifi_bytes = 0u64;

        for tx in &self.body.transactions {
            let tx_size = tx.size() as u64;

            if tx.is_storage_transaction() {
                wifi_only_count += 1;
                total_wifi_bytes += tx_size;
            } else if tx.is_proof_transaction() {
                cellular_safe_count += 1;
                total_cellular_bytes += tx_size;
            } else {
                total_cellular_bytes += tx_size;
            }
        }

        self.header.metadata.cellular_stats.cellular_safe_txs = cellular_safe_count;
        self.header.metadata.cellular_stats.wifi_only_txs = wifi_only_count;
        self.header
            .metadata
            .cellular_stats
            .total_data_bytes_cellular = total_cellular_bytes;
        self.header.metadata.cellular_stats.total_data_bytes_wifi = total_wifi_bytes;

        if cellular_safe_count > 0 {
            self.header.metadata.cellular_stats.avg_cellular_cost_per_tx =
                (total_cellular_bytes as f64 * 0.001) / cellular_safe_count as f64;
        }
    }

    fn update_algorithm_usage_stats(&mut self) {
        let mut stats = HashMap::new();

        stats.insert(
            AlgorithmId::MlDsa2.as_u16(),
            self.header.core.pq_signature_count.dilithium_sigs as u64,
        );
        stats.insert(
            AlgorithmId::Ed25519.as_u16(),
            self.header.core.pq_signature_count.ed25519_sigs as u64,
        );

        if self.header.core.pq_signature_count.slh_dsa_sigs > 0 {
            stats.insert(
                AlgorithmId::SlhDsa.as_u16(),
                self.header.core.pq_signature_count.slh_dsa_sigs as u64,
            );
        }

        stats.insert(
            AlgorithmId::MlKem768.as_u16(),
            self.header.core.pq_signature_count.hybrid_sigs as u64,
        );

        self.header
            .metadata
            .pq_transition_data
            .algorithm_usage_stats = stats;
    }

    pub fn set_state_root(&mut self, state_root: Hash) {
        self.header.core.state_root = state_root;
        self.hash = self.compute_hash();
    }

    pub fn set_receipts_root(&mut self, receipts_root: Hash) {
        self.header.core.receipts_root = receipts_root;
        self.hash = self.compute_hash();
    }

    pub fn set_events_root_post(&mut self, events_root: Hash) {
        self.header.core.events_root_post = events_root;
        self.hash = self.compute_hash();
    }

    pub fn set_events_root_poc(&mut self, events_root: Hash) {
        self.header.core.events_root_poc = events_root;
        self.hash = self.compute_hash();
    }

    pub fn set_rollup_root(&mut self, rollup_root: Hash) {
        self.header.core.rollup_root = rollup_root;
        self.hash = self.compute_hash();
    }

    pub fn set_da_root(&mut self, da_root: Hash) {
        self.header.core.da_root = da_root;
        self.hash = self.compute_hash();
    }

    pub fn compute_events_root_post(&self) -> Hash {
        if self.body.proof_events.is_empty() {
            return Hash::ZERO;
        }

        let config = bincode::config::standard();
        let post_events: Vec<Vec<u8>> = self
            .body
            .proof_events
            .iter()
            .filter(|e| matches!(e.proof_type, ProofEventType::PoSt))
            .filter_map(|e| bincode::encode_to_vec(e, config).ok())
            .collect();

        if post_events.is_empty() {
            return Hash::ZERO;
        }

        let merkle_tree = crate::crypto::MerkleTree::build(post_events);
        merkle_tree.root_hash().unwrap_or(Hash::ZERO)
    }

    pub fn compute_events_root_poc(&self) -> Hash {
        if self.body.proof_events.is_empty() {
            return Hash::ZERO;
        }

        let config = bincode::config::standard();
        let poc_events: Vec<Vec<u8>> = self
            .body
            .proof_events
            .iter()
            .filter(|e| matches!(e.proof_type, ProofEventType::PoC))
            .filter_map(|e| bincode::encode_to_vec(e, config).ok())
            .collect();

        if poc_events.is_empty() {
            return Hash::ZERO;
        }

        let merkle_tree = crate::crypto::MerkleTree::build(poc_events);
        merkle_tree.root_hash().unwrap_or(Hash::ZERO)
    }

    pub fn compute_receipts_root(&self) -> Hash {
        if self.body.cross_shard_receipts.is_empty() {
            return Hash::ZERO;
        }

        let config = bincode::config::standard();
        let receipt_hashes: Vec<Vec<u8>> = self
            .body
            .cross_shard_receipts
            .iter()
            .filter_map(|r| bincode::encode_to_vec(r, config).ok())
            .collect();

        let merkle_tree = crate::crypto::MerkleTree::build(receipt_hashes);
        merkle_tree.root_hash().unwrap_or(Hash::ZERO)
    }

    pub fn compute_rollup_root(&self) -> Hash {
        if self.body.rollup_commitments.is_empty() {
            return Hash::ZERO;
        }

        let config = bincode::config::standard();
        let rollup_hashes: Vec<Vec<u8>> = self
            .body
            .rollup_commitments
            .iter()
            .filter_map(|r| bincode::encode_to_vec(r, config).ok())
            .collect();

        let merkle_tree = crate::crypto::MerkleTree::build(rollup_hashes);
        merkle_tree.root_hash().unwrap_or(Hash::ZERO)
    }

    pub fn finalize_roots(&mut self) {
        self.set_events_root_post(self.compute_events_root_post());
        self.set_events_root_poc(self.compute_events_root_poc());
        self.set_receipts_root(self.compute_receipts_root());
        self.set_rollup_root(self.compute_rollup_root());
    }

    pub fn is_pq_compliant(&self) -> bool {
        self.header.qc.pq_compliant && self.header.core.pq_signature_count.dilithium_sigs > 0
    }

    pub fn get_algorithm_usage_stats(&self) -> HashMap<u16, u64> {
        self.header
            .metadata
            .pq_transition_data
            .algorithm_usage_stats
            .clone()
    }

    pub fn validate_against_state(&self, state: &StateManager) -> EgoResult<BlockValidationResult> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut validation_cost = 0u64;

        if self.header.core.chain_id != state.get_chain_id() {
            errors.push(format!(
                "Chain ID mismatch: block={}, state={}",
                self.header.core.chain_id,
                state.get_chain_id()
            ));
        }

        if self.header.core.network_id != state.get_network_id() {
            errors.push(format!(
                "Network ID mismatch: block={}, state={}",
                self.header.core.network_id,
                state.get_network_id()
            ));
        }

        let expected_height = state.get_block_height().next();
        if self.header.core.height != expected_height {
            errors.push(format!(
                "Height mismatch: expected={}, got={}",
                expected_height.as_u64(),
                self.header.core.height.as_u64()
            ));
        }

        for tx in &self.body.transactions {
            validation_cost += tx.estimate_resource_units();

            if tx.chain_id != self.header.core.chain_id {
                errors.push(format!("Transaction {} has wrong chain_id", tx.hash));
            }

            if tx.shard_id != self.header.core.shard_id {
                errors.push(format!(
                    "Transaction {} belongs to different shard",
                    tx.hash
                ));
            }
        }

        if self.header.core.compute_used != validation_cost {
            warnings.push(format!(
                "Compute used mismatch: header={}, calculated={}",
                self.header.core.compute_used, validation_cost
            ));
        }

        let pq_compliance = self.validate_pq_compliance_detailed();

        let valid = errors.is_empty();

        Ok(BlockValidationResult {
            valid,
            errors,
            warnings,
            validation_cost,
            state_changes: HashMap::new(),
            pq_compliance,
        })
    }

    fn validate_pq_compliance_detailed(&self) -> PQComplianceResult {
        let mut issues = Vec::new();
        let mut compliant = true;

        let pq_data = &self.header.metadata.pq_transition_data;

        let transition_phase_valid = pq_data.transition_phase <= 3;
        if !transition_phase_valid {
            issues.push(format!(
                "Invalid transition phase: {}",
                pq_data.transition_phase
            ));
            compliant = false;
        }

        let mut signature_algorithm_valid = true;
        if self.header.core.signature.dilithium_sig.is_none() {
            issues.push("Block signature missing Dilithium component".to_string());
            signature_algorithm_valid = false;
            compliant = false;
        }

        for tx in &self.body.transactions {
            if tx.requires_dilithium() && tx.signature.dilithium_sig.is_none() {
                issues.push(format!(
                    "Transaction {} requires Dilithium but lacks it",
                    tx.hash
                ));
                signature_algorithm_valid = false;
                compliant = false;
            }
        }

        let mut downgrade_attack_detected = false;
        if let Some(end_epoch) = pq_data.legacy_support_end_epoch {
            if self.header.core.epoch.as_u64() >= end_epoch {
                for tx in &self.body.transactions {
                    if tx.signature.ed25519_sig.is_some() && tx.signature.dilithium_sig.is_none() {
                        issues.push(format!(
                            "Downgrade attack: Transaction {} uses Ed25519-only after deadline",
                            tx.hash
                        ));
                        downgrade_attack_detected = true;
                        compliant = false;
                    }
                }
            }
        }

        PQComplianceResult {
            compliant,
            transition_phase_valid,
            signature_algorithm_valid,
            downgrade_attack_detected,
            issues,
        }
    }

    pub fn add_validator_signature(
        &mut self,
        validator: Address,
        signature: DualSignature,
        voting_power: u64,
        algorithm_used: Vec<u16>,
    ) -> EgoResult<()> {
        let validator_sig = ValidatorSignature {
            validator,
            signature,
            voting_power,
            algorithm_used,
            timestamp: Timestamp::now(),
        };

        if self
            .header
            .qc
            .signatures
            .iter()
            .any(|s| s.validator == validator)
        {
            return Err(EgoError::InvalidBlock(
                "Validator already signed".to_string(),
            ));
        }

        self.header.qc.signatures.push(validator_sig);
        self.header.qc.voting_power = self.header.qc.voting_power.saturating_add(voting_power);

        self.update_qc_signatures_root();

        Ok(())
    }

    fn update_qc_signatures_root(&mut self) {
        if self.header.qc.signatures.is_empty() {
            self.header.qc.signatures_root = Hash::ZERO;
            return;
        }

        let config = bincode::config::standard();
        let sig_hashes: Vec<Vec<u8>> = self
            .header
            .qc
            .signatures
            .iter()
            .filter_map(|s| bincode::encode_to_vec(s, config).ok())
            .collect();

        let merkle_tree = crate::crypto::MerkleTree::build(sig_hashes);
        self.header.qc.signatures_root = merkle_tree.root_hash().unwrap_or(Hash::ZERO);
    }

    pub fn verify_quorum(&self, total_stake: u64, quorum_threshold: u64) -> EgoResult<bool> {
        if self.header.qc.signatures.is_empty() {
            return Ok(false);
        }

        let threshold_stake = (total_stake * quorum_threshold) / 10000;

        if self.header.qc.voting_power < threshold_stake {
            return Ok(false);
        }

        Ok(true)
    }

    pub fn get_proposer_rewards(&self) -> Balance {
        let base_reward = Balance::new(1_000_000_000);

        let tx_fees: u128 = self
            .body
            .transactions
            .iter()
            .map(|tx| tx.pob_burn_credits as u128)
            .sum();

        base_reward
            .checked_add(Balance::new(tx_fees))
            .unwrap_or(base_reward)
    }

    pub fn get_validator_rewards(&self, total_reward_pool: Balance) -> Vec<(Address, Balance)> {
        if self.header.qc.signatures.is_empty() {
            return Vec::new();
        }

        let mut rewards = Vec::new();
        let total_voting_power = self.header.qc.voting_power;

        for validator_sig in &self.header.qc.signatures {
            let share = (total_reward_pool.as_u128() * validator_sig.voting_power as u128)
                / total_voting_power as u128;
            rewards.push((validator_sig.validator, Balance::new(share)));
        }

        rewards
    }

    pub fn extract_proof_events_by_type(&self, proof_type: ProofEventType) -> Vec<&ProofEvent> {
        self.body
            .proof_events
            .iter()
            .filter(|e| e.proof_type == proof_type)
            .collect()
    }

    pub fn extract_drs_events_for_epoch(&self, epoch: u64) -> Vec<&DRSEvent> {
        self.body
            .drs_events
            .iter()
            .filter(|e| e.epoch == epoch)
            .collect()
    }

    pub fn extract_density_penalties(&self) -> HashMap<Address, u64> {
        self.body
            .density_events
            .iter()
            .map(|e| (e.node_id, e.density_multiplier))
            .collect()
    }

    pub fn contains_fraud_proofs(&self) -> bool {
        !self.body.fraud_proofs.is_empty()
    }

    pub fn get_fraud_proofs_by_type(&self, fraud_type: FraudType) -> Vec<&FraudProof> {
        self.body
            .fraud_proofs
            .iter()
            .filter(|p| p.fraud_type == fraud_type)
            .collect()
    }

    pub fn verify_rollup_commitments(&self) -> EgoResult<Vec<bool>> {
        let mut results = Vec::new();

        for commitment in &self.body.rollup_commitments {
            let valid = self.verify_rollup_commitment(commitment)?;
            results.push(valid);
        }

        Ok(results)
    }

    fn verify_rollup_commitment(&self, commitment: &RollupCommitment) -> EgoResult<bool> {
        if commitment.tx_count == 0 {
            return Ok(false);
        }

        if commitment.block_range.0 >= commitment.block_range.1 {
            return Ok(false);
        }

        if commitment.fraud_proof_window == 0 {
            return Ok(false);
        }

        Ok(true)
    }

    pub fn get_cross_shard_receipts_for_shard(&self, shard_id: ShardId) -> Vec<&CrossShardReceipt> {
        self.body
            .cross_shard_receipts
            .iter()
            .filter(|r| r.to_shard == shard_id)
            .collect()
    }

    pub fn estimate_storage_cost(&self) -> u64 {
        let block_size = self.size() as u64;
        let base_cost = block_size / 1024;

        let events_cost = (self.body.proof_events.len()
            + self.body.drs_events.len()
            + self.body.density_events.len()) as u64
            * 10;

        base_cost + events_cost
    }

    pub fn is_epoch_boundary(&self, epoch_duration_blocks: u64) -> bool {
        self.header.core.height.as_u64() % epoch_duration_blocks == 0
    }

    pub fn get_cellular_efficiency_score(&self) -> f64 {
        let cellular_stats = &self.header.metadata.cellular_stats;

        if cellular_stats.cellular_safe_txs == 0 {
            return 1.0;
        }

        let total_txs = cellular_stats.cellular_safe_txs + cellular_stats.wifi_only_txs;

        if total_txs == 0 {
            return 1.0;
        }

        (cellular_stats.cellular_safe_txs as f64 / total_txs as f64) * 100.0
    }

    pub fn get_pq_adoption_rate(&self) -> f64 {
        let total_sigs = self.header.core.pq_signature_count.dilithium_sigs
            + self.header.core.pq_signature_count.ed25519_sigs
            + self.header.core.pq_signature_count.hybrid_sigs;

        if total_sigs == 0 {
            return 0.0;
        }

        let pq_sigs = self.header.core.pq_signature_count.dilithium_sigs
            + self.header.core.pq_signature_count.hybrid_sigs;

        (pq_sigs as f64 / total_sigs as f64) * 100.0
    }
}

pub struct BlockBuilder {
    height: BlockHeight,
    previous_hash: Hash,
    shard_id: ShardId,
    epoch: EpochNumber,
    proposer: Address,
    transactions: Vec<Transaction>,
    rollup_commitments: Vec<RollupCommitment>,
    chain_id: u32,
    network_id: u32,
}

impl BlockBuilder {
    pub fn new(
        height: BlockHeight,
        previous_hash: Hash,
        shard_id: ShardId,
        epoch: EpochNumber,
        proposer: Address,
        chain_id: u32,
        network_id: u32,
    ) -> Self {
        Self {
            height,
            previous_hash,
            shard_id,
            epoch,
            proposer,
            transactions: Vec::new(),
            rollup_commitments: Vec::new(),
            chain_id,
            network_id,
        }
    }

    pub fn add_transaction(mut self, tx: Transaction) -> Self {
        self.transactions.push(tx);
        self
    }

    pub fn add_transactions(mut self, txs: Vec<Transaction>) -> Self {
        self.transactions.extend(txs);
        self
    }

    pub fn add_rollup_commitment(mut self, commitment: RollupCommitment) -> Self {
        self.rollup_commitments.push(commitment);
        self
    }

    pub fn build(self) -> Block {
        Block::new(
            self.height,
            self.previous_hash,
            self.shard_id,
            self.epoch,
            self.proposer,
            self.transactions,
            self.rollup_commitments,
            self.chain_id,
            self.network_id,
        )
    }

    pub fn build_and_sign(
        self,
        keypair: &crate::crypto::KeyPair,
        transition_mode: bool,
    ) -> EgoResult<Block> {
        let mut block = self.build();
        block.sign(keypair, transition_mode)?;
        Ok(block)
    }
}
