use crate::{
    Address, BlockHeight, EgoError, EgoResult, EpochNumber, Hash, ShardId, Signature, Timestamp,
    Transaction, TransactionResult,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct BlockHeader {
    pub height: BlockHeight,
    pub previous_hash: Hash,
    pub transactions_root: Hash,
    pub state_root: Hash,
    pub rollup_root: Hash,
    pub timestamp: Timestamp,
    pub shard_id: ShardId,
    pub epoch: EpochNumber,
    pub proposer: Address,
    pub signature: Signature,
    pub tx_count: u32,
    pub compute_used: u64,
    pub storage_used: u64,
    pub metadata: BlockMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct BlockMetadata {
    pub protocol_version: u32,
    pub block_size: u64,
    pub avg_tx_fee: u64,
    pub network_stats: NetworkStats,
    pub cross_shard_receipts: u32,
    pub rollup_commits: u32,
    pub poc_events: u32,
    pub post_events: u32,
}

impl PartialEq for BlockMetadata {
    fn eq(&self, other: &Self) -> bool {
        self.protocol_version == other.protocol_version
            && self.block_size == other.block_size
            && self.avg_tx_fee == other.avg_tx_fee
            && self.network_stats == other.network_stats
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
    pub storage_utilization: f64,
}

impl PartialEq for NetworkStats {
    fn eq(&self, other: &Self) -> bool {
        self.active_devices == other.active_devices
            && self.bandwidth_utilization == other.bandwidth_utilization
            && self.avg_latency_ms == other.avg_latency_ms
            && self.active_slices == other.active_slices
            && (self.storage_utilization - other.storage_utilization).abs() < f64::EPSILON
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
        let rollup_root = Self::compute_rollup_root(&rollup_commitments);

        let tx_count = transactions.len() as u32;
        let compute_used = transactions
            .iter()
            .map(|tx| tx.estimate_compute_cost())
            .sum();
        let storage_used = transactions.iter().map(|tx| tx.size() as u64).sum();

        let network_stats = NetworkStats {
            active_devices: 0,
            bandwidth_utilization: 0,
            avg_latency_ms: 50,
            active_slices: 1,
            storage_utilization: 0.5,
        };

        let metadata = BlockMetadata {
            protocol_version: crate::PROTOCOL_VERSION,
            block_size: 0,
            avg_tx_fee: 0,
            network_stats,
            cross_shard_receipts: 0,
            rollup_commits: rollup_commitments.len() as u32,
            poc_events: 0,
            post_events: 0,
        };

        let header = BlockHeader {
            height,
            previous_hash,
            transactions_root,
            state_root: Hash::ZERO,
            rollup_root,
            timestamp,
            shard_id,
            epoch,
            proposer,
            signature: Signature::new([0u8; 64]),
            tx_count,
            compute_used,
            storage_used,
            metadata,
        };

        let body = BlockBody {
            transactions,
            transaction_results: Vec::new(),
            rollup_commitments,
            cross_shard_receipts: Vec::new(),
            proof_events: Vec::new(),
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

    fn compute_rollup_root(commitments: &[RollupCommitment]) -> Hash {
        if commitments.is_empty() {
            return Hash::ZERO;
        }

        let commitment_hashes: Vec<Vec<u8>> =
            commitments.iter().map(|c| c.state_root.to_vec()).collect();

        let merkle_tree = crate::crypto::MerkleTree::build(commitment_hashes);
        merkle_tree.root_hash().unwrap_or(Hash::ZERO)
    }

    pub fn sign(&mut self, keypair: &crate::crypto::KeyPair) -> EgoResult<()> {
        let expected_proposer = Address::from_public_key(&keypair.public_key());
        if expected_proposer != self.header.proposer {
            return Err(EgoError::InvalidBlock(
                "Proposer address does not match signing key".to_string(),
            ));
        }

        let mut header_copy = self.header.clone();
        header_copy.signature = Signature::new([0u8; 64]);

        let config = bincode::config::standard();
        let signing_data = bincode::encode_to_vec(&header_copy, config)
            .map_err(|e| EgoError::SerializationError(e.to_string()))?;

        self.header.signature = keypair.sign(&signing_data);
        self.hash = self.compute_hash();

        Ok(())
    }

    pub fn verify_signature(&self, proposer_pubkey: &crate::PublicKey) -> EgoResult<bool> {
        let expected_proposer = Address::from_public_key(proposer_pubkey);
        if expected_proposer != self.header.proposer {
            return Ok(false);
        }

        let mut header_copy = self.header.clone();
        header_copy.signature = Signature::new([0u8; 64]);

        let config = bincode::config::standard();
        let signing_data = bincode::encode_to_vec(&header_copy, config)
            .map_err(|e| EgoError::SerializationError(e.to_string()))?;

        crate::crypto::verify_signature(proposer_pubkey, &signing_data, &self.header.signature)
    }

    pub fn validate_structure(&self) -> EgoResult<()> {
        if self.header.tx_count != self.body.transactions.len() as u32 {
            return Err(EgoError::InvalidBlock(
                "Transaction count mismatch".to_string(),
            ));
        }

        let computed_tx_root = Self::compute_transactions_root(&self.body.transactions);
        if computed_tx_root != self.header.transactions_root {
            return Err(EgoError::InvalidBlock(
                "Transaction root mismatch".to_string(),
            ));
        }

        let computed_rollup_root = Self::compute_rollup_root(&self.body.rollup_commitments);
        if computed_rollup_root != self.header.rollup_root {
            return Err(EgoError::InvalidBlock("Rollup root mismatch".to_string()));
        }

        let computed_hash = self.compute_hash();
        if computed_hash != self.hash {
            return Err(EgoError::InvalidBlock("Block hash mismatch".to_string()));
        }

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

    pub fn size(&self) -> usize {
        let config = bincode::config::standard();
        bincode::encode_to_vec(self, config)
            .map(|data| data.len())
            .unwrap_or(0)
    }

    pub fn is_genesis(&self) -> bool {
        self.header.height == BlockHeight::GENESIS
    }

    pub fn summary(&self) -> String {
        format!(
            "Block {} [Shard {}] - Height: {}, TXs: {}, Size: {} bytes, Proposer: {}",
            self.hash,
            self.header.shard_id,
            self.header.height.as_u64(),
            self.header.tx_count,
            self.size(),
            self.header.proposer
        )
    }

    pub fn add_transaction_results(&mut self, results: Vec<TransactionResult>) {
        self.body.transaction_results = results;

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

    pub fn add_cross_shard_receipts(&mut self, receipts: Vec<CrossShardReceipt>) {
        self.body.cross_shard_receipts = receipts;
        self.header.metadata.cross_shard_receipts = self.body.cross_shard_receipts.len() as u32;
    }

    pub fn add_proof_events(&mut self, events: Vec<ProofEvent>) {
        self.body.proof_events = events;

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
        self.header.state_root = state_root;
        self.hash = self.compute_hash();
    }
}
