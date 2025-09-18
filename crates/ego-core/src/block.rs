use crate::{
    Address, BlockHeight, EgoError, EgoResult, EpochNumber, Hash, ShardId, Signature, Timestamp,
    Transaction, TransactionResult,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    pub events_root: Hash,
    pub da_root: Hash,
    pub timestamp: Timestamp,
    pub shard_id: ShardId,
    pub epoch: EpochNumber,
    pub proposer: Address,
    pub signature: Signature,
    pub tx_count: u32,
    pub compute_used: u64,
    pub storage_used: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct QuorumCert {
    pub view: u64,
    pub height: BlockHeight,
    pub block_hash: Hash,
    pub signatures: Vec<ValidatorSignature>,
    pub aggregated_signature: Option<Vec<u8>>,
    pub voting_power: u64,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ValidatorSignature {
    pub validator: Address,
    pub signature: Signature,
    pub voting_power: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct BlockMetadata {
    pub protocol_version: u32,
    pub block_size: u64,
    pub cross_shard_receipts: u32,
    pub rollup_commits: u32,
    pub poc_events: u32,
    pub post_events: u32,
    pub resource_pricing: Option<ResourcePricing>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ResourcePricing {
    pub bytes_cost: u64,
    pub ru_cost: u64,
    pub pob_floor: u64,
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

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct NetworkStats {
    pub active_devices: u32,
    pub bandwidth_utilization: u64,
    pub avg_latency_ms: u32,
    pub active_slices: u32,
    pub storage_utilization: u64,
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct RollupCommitment {
    pub rollup_id: String,
    pub state_root: Hash,
    pub previous_state_root: Hash,
    pub tx_root: Hash,
    pub tx_count: u32,
    pub block_range: (u64, u64),
    pub operator_signature: Signature,
    pub operator: Address,
    pub timestamp: Timestamp,
    pub proof_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct CrossShardReceipt {
    pub from_shard: ShardId,
    pub to_shard: ShardId,
    pub nonce: u64,
    pub payload: Vec<u8>,
    pub source_tx_hash: Hash,
    pub timestamp: Timestamp,
    pub receipt_hash: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ProofEvent {
    pub proof_type: String,
    pub prover: Address,
    pub challenge_hash: Hash,
    pub proof_data: Vec<u8>,
    pub location_id: String,
    pub slice_id: Option<String>,
    pub timestamp: Timestamp,
    pub verified: bool,
    pub witness_data: Option<WitnessData>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct WitnessData {
    pub rsrp: i16,
    pub rsrq: i16,
    pub sinr: i16,
    pub timing_advance: u32,
    pub gps_coords: Option<(i64, i64)>,
    pub witnesses: Vec<Address>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DRSEvent {
    pub node_id: Address,
    pub epoch: u64,
    pub score: u64,
    pub components: DRSComponents,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DRSComponents {
    pub uptime_score: u64,
    pub proof_success_rate: u64,
    pub witness_quality: u64,
    pub coverage_value: u64,
    pub utility_score: u64,
    pub density_multiplier: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DeployEvent {
    pub deployer: Address,
    pub contract_address: Option<Address>,
    pub deploy_type: DeployType,
    pub credits_used: u64,
    pub free_deploy_used: bool,
    pub bond_amount: Option<crate::Balance>,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum DeployType {
    Contract { code_size_kb: u32 },
    StorageDeal { data_size_gb: u32 },
    RollupState { state_size_kb: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub validation_cost: u64,
    pub state_changes: HashMap<Address, crate::account::Account>,
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
    ) -> Self {
        let timestamp = Timestamp::now();

        let transactions_root = Self::compute_transactions_root(&transactions);

        let tx_count = transactions.len() as u32;
        let compute_used = transactions
            .iter()
            .map(|tx| tx.estimate_compute_cost())
            .sum();
        let storage_used = transactions.iter().map(|tx| tx.size() as u64).sum();

        let metadata = BlockMetadata {
            protocol_version: crate::PROTOCOL_VERSION,
            block_size: 0,
            cross_shard_receipts: 0,
            rollup_commits: rollup_commitments.len() as u32,
            poc_events: 0,
            post_events: 0,
            resource_pricing: Some(ResourcePricing {
                bytes_cost: 100,
                ru_cost: 10,
                pob_floor: 1000,
            }),
        };

        let core = BlockHeaderCore {
            height,
            previous_hash,
            transactions_root,
            state_root: Hash::ZERO,
            receipts_root: Hash::ZERO,
            events_root: Hash::ZERO,
            da_root: Hash::ZERO,
            timestamp,
            shard_id,
            epoch,
            proposer,
            signature: Signature::new([0u8; 64]),
            tx_count,
            compute_used,
            storage_used,
        };

        let qc = QuorumCert {
            view: 0,
            height,
            block_hash: Hash::ZERO,
            signatures: Vec::new(),
            aggregated_signature: None,
            voting_power: 0,
            timestamp,
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
        };

        let mut block = Self {
            header,
            body,
            hash: Hash::ZERO,
        };

        block.hash = block.compute_hash();
        block
    }

    pub fn compute_hash(&self) -> Hash {
        let config = bincode::config::standard();
        let header_bytes = bincode::encode_to_vec(&self.header, config).unwrap_or_default();
        crate::crypto::hash_data(&header_bytes)
    }

    fn compute_transactions_root(transactions: &[Transaction]) -> Hash {
        if transactions.is_empty() {
            return Hash::ZERO;
        }

        let tx_hashes: Vec<Vec<u8>> = transactions.iter().map(|tx| tx.hash.to_vec()).collect();

        let merkle_tree = crate::crypto::MerkleTree::build(tx_hashes);
        merkle_tree.root_hash().unwrap_or(Hash::ZERO)
    }

    pub fn sign(&mut self, keypair: &crate::crypto::KeyPair) -> EgoResult<()> {
        let expected_proposer = Address::from_public_key(&keypair.public_key());
        if expected_proposer != self.header.core.proposer {
            return Err(EgoError::InvalidBlock(
                "Proposer address does not match signing key".to_string(),
            ));
        }

        let mut core_copy = self.header.core.clone();
        core_copy.signature = Signature::new([0u8; 64]);

        let config = bincode::config::standard();
        let signing_data = bincode::encode_to_vec(&core_copy, config)
            .map_err(|e| EgoError::SerializationError(e.to_string()))?;

        self.header.core.signature = keypair.sign(&signing_data);
        self.hash = self.compute_hash();

        Ok(())
    }

    pub fn verify_signature(&self, proposer_pubkey: &crate::PublicKey) -> EgoResult<bool> {
        let expected_proposer = Address::from_public_key(proposer_pubkey);
        if expected_proposer != self.header.core.proposer {
            return Ok(false);
        }

        let mut core_copy = self.header.core.clone();
        core_copy.signature = Signature::new([0u8; 64]);

        let config = bincode::config::standard();
        let signing_data = bincode::encode_to_vec(&core_copy, config)
            .map_err(|e| EgoError::SerializationError(e.to_string()))?;

        crate::crypto::verify_signature(proposer_pubkey, &signing_data, &self.header.core.signature)
    }

    pub fn validate_structure(&self) -> EgoResult<()> {
        if self.header.core.tx_count != self.body.transactions.len() as u32 {
            return Err(EgoError::InvalidBlock(
                "Transaction count mismatch".to_string(),
            ));
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

        self.validate_quorum_cert()?;

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
        format!(
            "Block {} [Shard {}] - Height: {}, TXs: {}, Size: {} bytes, Proposer: {}, DRS Events: {}",
            self.hash,
            self.header.core.shard_id,
            self.header.core.height.as_u64(),
            self.header.core.tx_count,
            self.size(),
            self.header.core.proposer,
            self.body.drs_events.len()
        )
    }

    pub fn add_transaction_results(&mut self, results: Vec<TransactionResult>) {
        self.body.transaction_results = results;
        self.update_event_counts();
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
    }

    pub fn add_deploy_events(&mut self, events: Vec<DeployEvent>) {
        self.body.deploy_events = events;
    }

    fn update_event_counts(&mut self) {
        self.header.metadata.poc_events = self
            .body
            .proof_events
            .iter()
            .filter(|e| e.proof_type == "poc")
            .count() as u32;

        self.header.metadata.post_events = self
            .body
            .proof_events
            .iter()
            .filter(|e| e.proof_type == "post")
            .count() as u32;
    }

    pub fn set_state_root(&mut self, state_root: Hash) {
        self.header.core.state_root = state_root;
        self.hash = self.compute_hash();
    }

    pub fn set_da_root(&mut self, da_root: Hash) {
        self.header.core.da_root = da_root;
        self.hash = self.compute_hash();
    }

    pub fn set_events_root(&mut self, events_root: Hash) {
        self.header.core.events_root = events_root;
        self.hash = self.compute_hash();
    }
}
