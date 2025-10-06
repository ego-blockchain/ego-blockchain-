use crate::{
    Address, AlgorithmId, Balance, BlockHeight, EgoError, EgoResult, Hash, ShardId, Signature,
    Timestamp, Transaction, TransactionResult,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

#[derive(Debug)]
pub struct RollupAggregator {
    pub rollup_id: String,
    pub operator: Address,
    pub current_batch: TransactionBatch,
    pub pending_batches: VecDeque<TransactionBatch>,
    pub state: RollupState,
    pub config: RollupConfig,
    pub metrics: RollupMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollupConfig {
    pub max_txs_per_batch: u32,
    pub max_batch_size_bytes: u64,
    pub batch_timeout_ms: u64,
    pub target_shard: ShardId,
    pub min_operator_stake: Balance,
    pub challenge_period: u64,
    pub fraud_proof_config: FraudProofConfig,
    pub fee_structure: FeeStructure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudProofConfig {
    pub challenge_window: u64,
    pub challenge_bond: Balance,
    pub fraud_proof_reward: Balance,
    pub max_proof_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeStructure {
    pub base_fee: Balance,
    pub per_byte_fee: Balance,
    pub operator_commission: u16,
    pub priority_multiplier: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollupState {
    pub state_root: Hash,
    pub previous_state_root: Hash,
    pub next_batch_sequence: u64,
    pub last_committed_batch: u64,
    pub total_transactions: u64,
    pub total_fees_collected: Balance,
    pub operator_stake: Balance,
    pub active_challenges: HashMap<Hash, Challenge>,
    pub last_updated: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionBatch {
    pub sequence: u64,
    pub batch_id: Hash,
    pub transactions: Vec<Transaction>,
    pub results: Vec<TransactionResult>,
    pub pre_state_root: Hash,
    pub post_state_root: Hash,
    pub tx_merkle_root: Hash,
    pub total_fees: Balance,
    pub size_bytes: u64,
    pub created_at: Timestamp,
    pub status: BatchStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BatchStatus {
    Assembling,
    Ready,
    Processing,
    Completed,
    Committed,
    Failed { reason: String },
    Challenged { challenge_id: Hash },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub challenge_id: Hash,
    pub challenger: Address,
    pub batch_sequence: u64,
    pub challenge_type: ChallengeType,
    pub proof_data: Vec<u8>,
    pub bond_amount: Balance,
    pub created_at: Timestamp,
    pub status: ChallengeStatus,
    pub deadline: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeType {
    InvalidStateTransition,
    InvalidTransaction,
    DataAvailability,
    OperatorFraud,
    InvalidMerkleProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeStatus {
    Active,
    ChallengerWins,
    OperatorWins,
    TimedOut,
    Withdrawn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollupCommitment {
    pub rollup_id: String,
    pub sequence: u64,
    pub batch_range: (u64, u64),
    pub previous_state_root: Hash,
    pub new_state_root: Hash,
    pub batches_root: Hash,
    pub total_transactions: u32,
    pub total_fees: Balance,
    pub l1_block_range: (BlockHeight, BlockHeight),
    pub operator_signature: Signature,
    pub timestamp: Timestamp,
    pub challenge_period_end: Timestamp,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RollupMetrics {
    pub total_batches: u64,
    pub total_transactions: u64,
    pub avg_txs_per_batch: f64,
    pub avg_batch_time_ms: u64,
    pub throughput_tps: f64,
    pub success_rate: f64,
    pub active_challenges: u32,
    pub total_fees_collected: Balance,
    pub compression_ratio: f64,
    pub last_updated: Timestamp,
}

impl RollupAggregator {
    pub fn new(rollup_id: String, operator: Address, config: RollupConfig) -> Self {
        let current_batch = TransactionBatch::new(0);
        let state = RollupState::new();

        Self {
            rollup_id,
            operator,
            current_batch,
            pending_batches: VecDeque::new(),
            state,
            config,
            metrics: RollupMetrics::default(),
        }
    }

    pub fn add_transaction(&mut self, tx: Transaction) -> EgoResult<()> {
        if self.current_batch.transactions.len() >= self.config.max_txs_per_batch as usize {
            self.seal_current_batch()?;
        }

        let config = bincode::config::standard();
        let tx_size = bincode::encode_to_vec(&tx, config)
            .map_err(|e| EgoError::SerializationError(e.to_string()))?
            .len() as u64;

        if self.current_batch.size_bytes + tx_size > self.config.max_batch_size_bytes {
            self.seal_current_batch()?;
        }

        self.current_batch.transactions.push(tx);
        self.current_batch.size_bytes += tx_size;
        self.metrics.total_transactions += 1;

        Ok(())
    }

    pub fn seal_current_batch(&mut self) -> EgoResult<()> {
        if self.current_batch.transactions.is_empty() {
            return Ok(());
        }

        let tx_hashes: Vec<Vec<u8>> = self
            .current_batch
            .transactions
            .iter()
            .map(|tx| tx.hash.to_vec())
            .collect();

        let merkle_tree = crate::crypto::MerkleTree::build(tx_hashes);
        self.current_batch.tx_merkle_root = merkle_tree.root_hash().unwrap_or(Hash::ZERO);

        self.current_batch.batch_id = self.compute_batch_id(&self.current_batch);
        self.current_batch.status = BatchStatus::Ready;

        let sealed_batch = std::mem::replace(
            &mut self.current_batch,
            TransactionBatch::new(self.state.next_batch_sequence),
        );

        self.pending_batches.push_back(sealed_batch);
        self.state.next_batch_sequence += 1;
        self.metrics.total_batches += 1;

        Ok(())
    }

    pub fn process_batch(&mut self, batch_sequence: u64) -> EgoResult<()> {
        let batch_index = self
            .pending_batches
            .iter()
            .position(|b| b.sequence == batch_sequence)
            .ok_or(EgoError::InvalidTransaction("Batch not found".to_string()))?;

        let mut batch = self.pending_batches.remove(batch_index).unwrap();

        batch.status = BatchStatus::Processing;
        batch.pre_state_root = self.state.state_root;

        let mut total_fees = Balance::ZERO;
        let mut results = Vec::new();

        for tx in &batch.transactions {
            let fee = self.calculate_transaction_fee(tx);
            total_fees = total_fees.checked_add(fee).unwrap_or(total_fees);

            let result = TransactionResult {
                tx_hash: tx.hash,
                success: true,
                error: None,
                compute_used: tx.estimate_compute_cost(),
                storage_used: tx.size() as u64,
                state_changes: Vec::new(),
                events: Vec::new(),
                cross_shard_receipts: Vec::new(),
                pq_verification_result: None,
            };

            results.push(result);
        }

        batch.results = results;
        batch.total_fees = total_fees;
        batch.post_state_root = self.compute_new_state_root(&batch);
        batch.status = BatchStatus::Completed;

        self.state.state_root = batch.post_state_root;
        self.state.total_transactions += batch.transactions.len() as u64;
        self.state.total_fees_collected = self
            .state
            .total_fees_collected
            .checked_add(total_fees)
            .unwrap_or(self.state.total_fees_collected);
        self.state.last_updated = Timestamp::now();

        self.pending_batches.push_back(batch);
        self.update_metrics();

        Ok(())
    }

    pub fn create_commitment(
        &mut self,
        batch_range: (u64, u64),
        l1_block_range: (BlockHeight, BlockHeight),
    ) -> EgoResult<RollupCommitment> {
        let commitment = RollupCommitment {
            rollup_id: self.rollup_id.clone(),
            sequence: self.state.last_committed_batch + 1,
            batch_range,
            previous_state_root: self.state.previous_state_root,
            new_state_root: self.state.state_root,
            batches_root: self.compute_batches_root(batch_range)?,
            total_transactions: self.calculate_commitment_tx_count(batch_range)?,
            total_fees: self.calculate_commitment_fees(batch_range)?,
            l1_block_range,
            operator_signature: Signature::new(AlgorithmId::Ed25519, vec![0u8; 64]),
            timestamp: Timestamp::now(),
            challenge_period_end: Timestamp::from_millis(
                Timestamp::now().as_millis() + (self.config.challenge_period * 100),
            ),
        };

        Ok(commitment)
    }

    pub fn submit_challenge(
        &mut self,
        challenger: Address,
        batch_sequence: u64,
        challenge_type: ChallengeType,
        proof_data: Vec<u8>,
        bond_amount: Balance,
    ) -> EgoResult<Hash> {
        let challenge_id = Hash::new(rand::random());

        let challenge = Challenge {
            challenge_id,
            challenger,
            batch_sequence,
            challenge_type,
            proof_data,
            bond_amount,
            created_at: Timestamp::now(),
            status: ChallengeStatus::Active,
            deadline: Timestamp::from_millis(
                Timestamp::now().as_millis()
                    + (self.config.fraud_proof_config.challenge_window * 100),
            ),
        };

        self.state.active_challenges.insert(challenge_id, challenge);
        self.metrics.active_challenges += 1;

        Ok(challenge_id)
    }

    pub fn resolve_challenge(
        &mut self,
        challenge_id: Hash,
        resolution: ChallengeStatus,
    ) -> EgoResult<()> {
        let challenge = self.state.active_challenges.get_mut(&challenge_id).ok_or(
            EgoError::InvalidTransaction("Challenge not found".to_string()),
        )?;

        challenge.status = resolution.clone();

        match resolution {
            ChallengeStatus::ChallengerWins => {}
            ChallengeStatus::OperatorWins => {}
            _ => {}
        }

        self.metrics.active_challenges = self.metrics.active_challenges.saturating_sub(1);

        Ok(())
    }

    fn calculate_transaction_fee(&self, tx: &Transaction) -> Balance {
        let base_fee = self.config.fee_structure.base_fee;
        let per_byte_fee = self.config.fee_structure.per_byte_fee;
        let tx_size = tx.size() as u128;

        let byte_fee = Balance::new(per_byte_fee.as_u128() * tx_size);
        base_fee.checked_add(byte_fee).unwrap_or(base_fee)
    }

    fn compute_batch_id(&self, batch: &TransactionBatch) -> Hash {
        let config = bincode::config::standard();
        let data = bincode::encode_to_vec(
            &(
                &self.rollup_id,
                batch.sequence,
                batch.tx_merkle_root,
                batch.created_at,
            ),
            config,
        )
        .unwrap_or_default();

        crate::crypto::hash_data(&data)
    }

    fn compute_new_state_root(&self, _batch: &TransactionBatch) -> Hash {
        Hash::new(rand::random())
    }

    fn compute_batches_root(&self, _batch_range: (u64, u64)) -> EgoResult<Hash> {
        Ok(Hash::new(rand::random()))
    }

    fn calculate_commitment_tx_count(&self, batch_range: (u64, u64)) -> EgoResult<u32> {
        let count = self
            .pending_batches
            .iter()
            .filter(|b| b.sequence >= batch_range.0 && b.sequence <= batch_range.1)
            .map(|b| b.transactions.len() as u32)
            .sum();

        Ok(count)
    }

    fn calculate_commitment_fees(&self, batch_range: (u64, u64)) -> EgoResult<Balance> {
        let total = self
            .pending_batches
            .iter()
            .filter(|b| b.sequence >= batch_range.0 && b.sequence <= batch_range.1)
            .fold(Balance::ZERO, |acc, b| {
                acc.checked_add(b.total_fees).unwrap_or(acc)
            });

        Ok(total)
    }

    fn update_metrics(&mut self) {
        self.metrics.avg_txs_per_batch = if self.metrics.total_batches > 0 {
            self.metrics.total_transactions as f64 / self.metrics.total_batches as f64
        } else {
            0.0
        };

        self.metrics.total_fees_collected = self.state.total_fees_collected;
        self.metrics.last_updated = Timestamp::now();
    }

    pub fn get_stats(&self) -> RollupStats {
        RollupStats {
            rollup_id: self.rollup_id.clone(),
            operator: self.operator,
            state: self.state.clone(),
            current_batch_size: self.current_batch.transactions.len(),
            pending_batches: self.pending_batches.len(),
            metrics: self.metrics.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollupStats {
    pub rollup_id: String,
    pub operator: Address,
    pub state: RollupState,
    pub current_batch_size: usize,
    pub pending_batches: usize,
    pub metrics: RollupMetrics,
}

impl TransactionBatch {
    pub fn new(sequence: u64) -> Self {
        Self {
            sequence,
            batch_id: Hash::ZERO,
            transactions: Vec::new(),
            results: Vec::new(),
            pre_state_root: Hash::ZERO,
            post_state_root: Hash::ZERO,
            tx_merkle_root: Hash::ZERO,
            total_fees: Balance::ZERO,
            size_bytes: 0,
            created_at: Timestamp::now(),
            status: BatchStatus::Assembling,
        }
    }
}

impl RollupState {
    pub fn new() -> Self {
        Self {
            state_root: Hash::ZERO,
            previous_state_root: Hash::ZERO,
            next_batch_sequence: 0,
            last_committed_batch: 0,
            total_transactions: 0,
            total_fees_collected: Balance::ZERO,
            operator_stake: Balance::ZERO,
            active_challenges: HashMap::new(),
            last_updated: Timestamp::now(),
        }
    }
}

impl Default for RollupConfig {
    fn default() -> Self {
        Self {
            max_txs_per_batch: 1000,
            max_batch_size_bytes: 1024 * 1024,
            batch_timeout_ms: 10000,
            target_shard: ShardId::new(0).unwrap(),
            min_operator_stake: Balance::from_egoc(10000),
            challenge_period: 1000,
            fraud_proof_config: FraudProofConfig::default(),
            fee_structure: FeeStructure::default(),
        }
    }
}

impl Default for FraudProofConfig {
    fn default() -> Self {
        Self {
            challenge_window: 500,
            challenge_bond: Balance::from_egoc(100),
            fraud_proof_reward: Balance::from_egoc(1000),
            max_proof_size: 1024 * 1024,
        }
    }
}

impl Default for FeeStructure {
    fn default() -> Self {
        Self {
            base_fee: Balance::new(1000),
            per_byte_fee: Balance::new(10),
            operator_commission: 500,
            priority_multiplier: 1.5,
        }
    }
}
