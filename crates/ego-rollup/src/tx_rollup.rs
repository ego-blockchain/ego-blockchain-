use crate::commitment::RollupCommitment;
use crate::config::RollupConfig;
use crate::da::{DAChunk, DataAvailability};
use crate::error::{RollupError, RollupResult};
use crate::fraud::{FraudProof, FraudProofVerifier};
use crate::metrics::RollupMetrics;
use crate::types::{CommitmentStatus, RollupTransaction};
use ego_core::{Address, Hash, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// TxRollup: Aggregates user transactions for a region/queue
/// Posts commitments and DA blobs; L1 verifies minimal validity and handles disputes
#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct TxRollupCommit {
    pub rollup_id: [u8; 16],
    pub region_id: u32,
    pub epoch: u64,
    pub window_id: u32,
    
    /// Merkle root over transactions
    pub tx_root: Hash,
    
    /// State root after processing transactions
    pub state_root: Hash,
    
    /// Erasure-coded blob manifest root
    pub da_root: Hash,
    
    pub count_tx: u32,
    pub blob_bytes: u64,
    
    /// Block range covered by this commitment
    pub block_range_start: u64,
    pub block_range_end: u64,
    
    /// Minimal validity proof type
    pub min_validity_proof: MinValidityProof,
    
    /// Post-quantum signature (Dilithium-2)
    pub alg_sig_id: u16,
    pub operator_addr: [u8; 20],
    pub operator_sig: Vec<u8>,
    
    pub created_at: Timestamp,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub enum MinValidityProof {
    None = 0,
    InclusionOnly = 1,
    StateWitness = 2,
    CircuitProof = 3,
}

/// Transaction batch for TxRollup
#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct TxRollupBatch {
    pub batch_id: Hash,
    pub rollup_id: [u8; 16],
    pub region_id: u32,
    pub transactions: Vec<RollupTransaction>,
    pub prev_state_root: Hash,
    pub new_state_root: Hash,
    pub l1_block_number: u64,
    pub timestamp: Timestamp,
}

/// Challenge for a TxRollup commitment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxRollupChallenge {
    pub challenge_id: Hash,
    pub commitment_hash: Hash,
    pub challenger: Address,
    pub challenge_type: ChallengeType,
    pub fraud_proof: Option<FraudProof>,
    pub submitted_at: Timestamp,
    pub deadline: Timestamp,
    pub status: ChallengeStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChallengeType {
    DAUnavailable,
    InvalidStateTransition,
    InvalidInclusion,
    Timeout,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChallengeStatus {
    Pending,
    Defended,
    Proven,
    Expired,
}

/// TxRollup operator
pub struct TxRollupOperator {
    config: RollupConfig,
    rollup_id: [u8; 16],
    region_id: u32,
    operator_addr: Address,
    
    /// Transaction pool
    tx_pool: Arc<RwLock<VecDeque<RollupTransaction>>>,
    
    /// Pending batches awaiting commitment
    pending_batches: Arc<RwLock<HashMap<Hash, TxRollupBatch>>>,
    
    /// Posted commitments with their status
    commitments: Arc<RwLock<HashMap<Hash, (TxRollupCommit, CommitmentStatus)>>>,
    
    /// Active challenges
    challenges: Arc<RwLock<HashMap<Hash, TxRollupChallenge>>>,
    
    /// DA manager for erasure coding
    da_manager: Arc<RwLock<DataAvailability>>,
    
    /// Fraud proof verifier
    fraud_verifier: Arc<FraudProofVerifier>,
    
    metrics: Arc<RwLock<TxRollupMetrics>>,
    
    /// Current epoch and window
    current_epoch: Arc<RwLock<u64>>,
    current_window: Arc<RwLock<u32>>,
    
    /// State management
    current_state_root: Arc<RwLock<Hash>>,
    l1_block_number: Arc<RwLock<u64>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TxRollupMetrics {
    pub transactions_received: u64,
    pub transactions_processed: u64,
    pub batches_created: u64,
    pub commitments_posted: u64,
    pub challenges_received: u64,
    pub challenges_defended: u64,
    pub challenges_lost: u64,
    pub total_blob_bytes: u64,
    pub avg_batch_size: u64,
    pub finalized_commitments: u64,
}

impl TxRollupOperator {
    pub fn new(
        config: RollupConfig,
        rollup_id: [u8; 16],
        region_id: u32,
        operator_addr: Address,
    ) -> RollupResult<Self> {
        let da_manager = DataAvailability::new(
            config.da.k,
            config.da.m,
            config.da.chunk_size,
            config.da.enable_compression,
            config.da.compression_level,
        )?;
        
        let fraud_verifier = FraudProofVerifier::new();
        
        Ok(Self {
            config,
            rollup_id,
            region_id,
            operator_addr,
            tx_pool: Arc::new(RwLock::new(VecDeque::new())),
            pending_batches: Arc::new(RwLock::new(HashMap::new())),
            commitments: Arc::new(RwLock::new(HashMap::new())),
            challenges: Arc::new(RwLock::new(HashMap::new())),
            da_manager: Arc::new(RwLock::new(da_manager)),
            fraud_verifier: Arc::new(fraud_verifier),
            metrics: Arc::new(RwLock::new(TxRollupMetrics::default())),
            current_epoch: Arc::new(RwLock::new(0)),
            current_window: Arc::new(RwLock::new(0)),
            current_state_root: Arc::new(RwLock::new(Hash::ZERO)),
            l1_block_number: Arc::new(RwLock::new(0)),
        })
    }
    
    /// Submit a transaction to the rollup
    pub async fn submit_transaction(&self, tx: RollupTransaction) -> RollupResult<Hash> {
        // Verify transaction signature
        if !tx.inner.verify_signature()? {
            return Err(RollupError::InvalidBatch("Invalid transaction signature".to_string()));
        }
        
        let tx_hash = tx.hash();
        
        {
            let mut pool = self.tx_pool.write().await;
            pool.push_back(tx);
            
            // Enforce pool size limit
            if pool.len() > self.config.performance.tx_pool_size {
                pool.pop_front();
                warn!("Transaction pool full, dropping oldest transaction");
            }
        }
        
        {
            let mut metrics = self.metrics.write().await;
            metrics.transactions_received += 1;
        }
        
        debug!("Received transaction: {}", tx_hash);
        Ok(tx_hash)
    }
    
    /// Build a batch from pending transactions
    pub async fn build_batch(&self, max_batch_size: usize) -> RollupResult<TxRollupBatch> {
        let mut transactions = Vec::new();
        
        {
            let mut pool = self.tx_pool.write().await;
            
            while !pool.is_empty() && transactions.len() < max_batch_size {
                if let Some(tx) = pool.pop_front() {
                    transactions.push(tx);
                }
            }
        }
        
        if transactions.is_empty() {
            return Err(RollupError::InvalidBatch("No transactions to batch".to_string()));
        }
        
        let prev_state_root = *self.current_state_root.read().await;
        let l1_block_number = *self.l1_block_number.read().await;
        
        // Compute new state root (simplified - in production this would execute transactions)
        let new_state_root = self.compute_new_state_root(&transactions, prev_state_root).await?;
        
        // Compute batch ID
        let batch_data = self.serialize_transactions(&transactions)?;
        let batch_id = ego_core::crypto::hash_data(&batch_data);
        
        let batch = TxRollupBatch {
            batch_id,
            rollup_id: self.rollup_id,
            region_id: self.region_id,
            transactions,
            prev_state_root,
            new_state_root,
            l1_block_number,
            timestamp: Timestamp::now(),
        };
        
        {
            let mut pending = self.pending_batches.write().await;
            pending.insert(batch_id, batch.clone());
        }
        
        {
            let mut metrics = self.metrics.write().await;
            metrics.batches_created += 1;
            metrics.transactions_processed += batch.transactions.len() as u64;
        }
        
        info!("Built batch {} with {} transactions", batch_id, batch.transactions.len());
        Ok(batch)
    }
    
    /// Post a commitment for a batch to L1
    pub async fn post_commitment(&self, batch: TxRollupBatch) -> RollupResult<Hash> {
        let epoch = *self.current_epoch.read().await;
        let window_id = *self.current_window.read().await;
        
        // Compute transaction root
        let tx_root = self.compute_tx_root(&batch.transactions);
        
        // Create DA chunks for the batch
        let da_chunks = self.create_da_chunks(&batch).await?;
        
        // Compute DA root
        let da_root = self.compute_da_root(&da_chunks);
        
        // Create commitment
        let commitment = TxRollupCommit {
            rollup_id: self.rollup_id,
            region_id: self.region_id,
            epoch,
            window_id,
            tx_root,
            state_root: batch.new_state_root,
            da_root,
            count_tx: batch.transactions.len() as u32,
            blob_bytes: self.estimate_blob_bytes(&batch),
            block_range_start: batch.l1_block_number,
            block_range_end: batch.l1_block_number,
            min_validity_proof: MinValidityProof::StateWitness,
            alg_sig_id: 2, // ML-DSA-2 (Dilithium-2)
            operator_addr: self.operator_addr.as_bytes().try_into().unwrap_or([0u8; 20]),
            operator_sig: Vec::new(), // TODO: Sign with Dilithium-2
            created_at: Timestamp::now(),
        };
        
        let commitment_hash = self.compute_commitment_hash(&commitment);
        
        // Store commitment with Pending status
        {
            let mut commits = self.commitments.write().await;
            commits.insert(commitment_hash, (commitment, CommitmentStatus::Pending));
        }
        
        // Update current state root
        {
            let mut state_root = self.current_state_root.write().await;
            *state_root = batch.new_state_root;
        }
        
        {
            let mut metrics = self.metrics.write().await;
            metrics.commitments_posted += 1;
            metrics.total_blob_bytes += self.estimate_blob_bytes(&batch);
        }
        
        info!("Posted TxRollup commitment: {} (epoch={}, window={})", 
              commitment_hash, epoch, window_id);
        
        Ok(commitment_hash)
    }
    
    /// Handle a challenge to a commitment
    pub async fn handle_challenge(&self, challenge: TxRollupChallenge) -> RollupResult<()> {
        let commitment_hash = challenge.commitment_hash;
        
        info!("Received challenge {} for commitment {}", 
              challenge.challenge_id, commitment_hash);
        
        // Update commitment status
        {
            let mut commits = self.commitments.write().await;
            if let Some((commitment, status)) = commits.get_mut(&commitment_hash) {
                *status = CommitmentStatus::Challenged(crate::types::ChallengeStatus::Pending {
                    challenger: challenge.challenger,
                    challenge_hash: challenge.challenge_id,
                    deadline: challenge.deadline,
                });
            }
        }
        
        // Store challenge
        {
            let mut challenges = self.challenges.write().await;
            challenges.insert(challenge.challenge_id, challenge.clone());
        }
        
        {
            let mut metrics = self.metrics.write().await;
            metrics.challenges_received += 1;
        }
        
        // Attempt to defend
        self.defend_challenge(challenge).await?;
        
        Ok(())
    }
    
    async fn defend_challenge(&self, challenge: TxRollupChallenge) -> RollupResult<()> {
        match challenge.challenge_type {
            ChallengeType::DAUnavailable => {
                // Provide missing DA chunks
                self.provide_da_chunks(challenge.commitment_hash).await?;
            }
            ChallengeType::InvalidStateTransition => {
                // Provide state witness
                self.provide_state_witness(challenge.commitment_hash).await?;
            }
            ChallengeType::InvalidInclusion => {
                // Provide inclusion proofs
                self.provide_inclusion_proofs(challenge.commitment_hash).await?;
            }
            ChallengeType::Timeout => {
                warn!("Challenge is for timeout - cannot defend");
                return Err(RollupError::ChallengeDefenseFailed("Timeout challenge".to_string()));
            }
        }
        
        // Update challenge status
        {
            let mut challenges = self.challenges.write().await;
            if let Some(ch) = challenges.get_mut(&challenge.challenge_id) {
                ch.status = ChallengeStatus::Defended;
            }
        }
        
        {
            let mut metrics = self.metrics.write().await;
            metrics.challenges_defended += 1;
        }
        
        info!("Successfully defended challenge {}", challenge.challenge_id);
        Ok(())
    }
    
    async fn provide_da_chunks(&self, _commitment_hash: Hash) -> RollupResult<()> {
        // TODO: Serve DA chunks to challengers
        Ok(())
    }
    
    async fn provide_state_witness(&self, _commitment_hash: Hash) -> RollupResult<()> {
        // TODO: Generate and provide state witness
        Ok(())
    }
    
    async fn provide_inclusion_proofs(&self, _commitment_hash: Hash) -> RollupResult<()> {
        // TODO: Generate and provide Merkle inclusion proofs
        Ok(())
    }
    
    /// Finalize a commitment after challenge window expires
    pub async fn finalize_commitment(&self, commitment_hash: Hash) -> RollupResult<()> {
        {
            let mut commits = self.commitments.write().await;
            if let Some((_, status)) = commits.get_mut(&commitment_hash) {
                *status = CommitmentStatus::Finalized;
            }
        }
        
        {
            let mut metrics = self.metrics.write().await;
            metrics.finalized_commitments += 1;
        }
        
        info!("Finalized commitment {}", commitment_hash);
        Ok(())
    }
    
    async fn compute_new_state_root(
        &self,
        _transactions: &[RollupTransaction],
        prev_state_root: Hash,
    ) -> RollupResult<Hash> {
        // Simplified - in production this would execute transactions
        // and compute the actual state root
        let mut hasher = blake3::Hasher::new();
        hasher.update(prev_state_root.as_bytes());
        hasher.update(b"new_state");
        
        let hash_bytes = hasher.finalize();
        Ok(Hash::from_bytes(hash_bytes.as_bytes()))
    }
    
    fn serialize_transactions(&self, transactions: &[RollupTransaction]) -> RollupResult<Vec<u8>> {
        let config = bincode::config::standard();
        bincode::encode_to_vec(transactions, config)
            .map_err(|e| RollupError::SerializationError(e.to_string()))
    }
    
    fn compute_tx_root(&self, transactions: &[RollupTransaction]) -> Hash {
        if transactions.is_empty() {
            return Hash::ZERO;
        }
        
        let tx_hashes: Vec<Vec<u8>> = transactions
            .iter()
            .map(|tx| tx.hash().to_vec())
            .collect();
        
        let merkle_tree = ego_core::crypto::MerkleTree::build(tx_hashes);
        merkle_tree.root_hash().unwrap_or(Hash::ZERO)
    }
    
    async fn create_da_chunks(&self, batch: &TxRollupBatch) -> RollupResult<Vec<DAChunk>> {
        let batch_data = self.serialize_transactions(&batch.transactions)?;
        let mut da_manager = self.da_manager.write().await;
        da_manager.encode_data(batch.batch_id, batch_data)
    }
    
    fn compute_da_root(&self, chunks: &[DAChunk]) -> Hash {
        let chunk_hashes: Vec<Vec<u8>> = chunks
            .iter()
            .map(|chunk| chunk.chunk_hash.to_vec())
            .collect();
        
        if chunk_hashes.is_empty() {
            return Hash::ZERO;
        }
        
        let merkle_tree = ego_core::crypto::MerkleTree::build(chunk_hashes);
        merkle_tree.root_hash().unwrap_or(Hash::ZERO)
    }
    
    fn compute_commitment_hash(&self, commitment: &TxRollupCommit) -> Hash {
        let config = bincode::config::standard();
        let data = bincode::encode_to_vec(commitment, config).unwrap_or_default();
        ego_core::crypto::hash_data(&data)
    }
    
    fn estimate_blob_bytes(&self, batch: &TxRollupBatch) -> u64 {
        self.serialize_transactions(&batch.transactions)
            .map(|data| data.len() as u64)
            .unwrap_or(0)
    }
    
    pub async fn get_metrics(&self) -> TxRollupMetrics {
        self.metrics.read().await.clone()
    }
    
    pub async fn advance_epoch(&self) {
        let mut epoch = self.current_epoch.write().await;
        *epoch += 1;
        info!("Advanced to epoch {}", *epoch);
    }
    
    pub async fn advance_window(&self) {
        let mut window = self.current_window.write().await;
        *window += 1;
        info!("Advanced to window {}", *window);
    }
    
    pub async fn get_pool_size(&self) -> usize {
        self.tx_pool.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::{Balance, KeyPair, ShardId, Transaction, TransactionPayload};
    
    fn create_test_config() -> RollupConfig {
        RollupConfig::default()
    }
    
    fn create_test_transaction() -> RollupTransaction {
        let inner = Transaction::new(
            Address::new([1u8; 20]),
            1,
            TransactionPayload::Transfer {
                to: Address::new([2u8; 20]),
                amount: Balance::from_egoc(100),
                memo: None,
            },
            ShardId::new(0).unwrap(),
            None,
        );
        
        RollupTransaction::new(inner, 1, 1000)
    }
    
    #[tokio::test]
    async fn test_tx_rollup_creation() {
        let config = create_test_config();
        let rollup_id = [1u8; 16];
        let region_id = 1;
        let keypair = KeyPair::generate();
        let operator_addr = Address::from_public_key(&keypair.public_key());
        
        let operator = TxRollupOperator::new(config, rollup_id, region_id, operator_addr).unwrap();
        assert_eq!(operator.rollup_id, rollup_id);
        assert_eq!(operator.region_id, region_id);
    }
    
    #[tokio::test]
    async fn test_transaction_submission() {
        let config = create_test_config();
        let rollup_id = [1u8; 16];
        let keypair = KeyPair::generate();
        let operator_addr = Address::from_public_key(&keypair.public_key());
        
        let operator = TxRollupOperator::new(config, rollup_id, 1, operator_addr).unwrap();
        
        let tx = create_test_transaction();
        let hash = operator.submit_transaction(tx).await.unwrap();
        assert_ne!(hash, Hash::ZERO);
        
        let metrics = operator.get_metrics().await;
        assert_eq!(metrics.transactions_received, 1);
        
        let pool_size = operator.get_pool_size().await;
        assert_eq!(pool_size, 1);
    }
    
    #[tokio::test]
    async fn test_batch_building() {
        let config = create_test_config();
        let rollup_id = [1u8; 16];
        let keypair = KeyPair::generate();
        let operator_addr = Address::from_public_key(&keypair.public_key());
        
        let operator = TxRollupOperator::new(config, rollup_id, 1, operator_addr).unwrap();
        
        // Submit multiple transactions
        for _ in 0..5 {
            let tx = create_test_transaction();
            operator.submit_transaction(tx).await.unwrap();
        }
        
        let batch = operator.build_batch(10).await.unwrap();
        assert_eq!(batch.transactions.len(), 5);
        
        let metrics = operator.get_metrics().await;
        assert_eq!(metrics.batches_created, 1);
        assert_eq!(metrics.transactions_processed, 5);
    }
}
