use crate::commitment::RollupCommitment;
use crate::error::{RollupError, RollupResult};
use crate::types::{RollupExecutionResult, RollupTransaction};
use ego_core::{
    Address, Balance, EgoError, EgoResult, EpochNumber, Hash, PROTOCOL_VERSION, ShardId, Timestamp,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

const DOMAIN_TAG_ROLLUP_BATCH: &[u8] = b"ego/rollup/batch/v1";

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct RollupBatch {
    pub batch_id: Hash,
    pub operator: Address,
    pub transactions: Vec<RollupTransaction>,
    pub l1_block_number: u64,
    pub timestamp: Timestamp,
    pub prev_state_root: Hash,
    pub post_state_root: Hash,
    pub execution_results: Vec<RollupExecutionResult>,
    pub gas_used: u64,
    pub size_bytes: usize,
    pub protocol_version: u32,
    pub chain_id: u32,
    pub network_id: u32,
    pub tx_root: Hash,
    pub receipts_root: Hash,
    pub operator_signature: ego_core::DualSignature,
    pub epoch: EpochNumber,
    pub shard_id: ShardId,
}

pub struct BatchBuilder {
    operator: Address,
    max_batch_size: u32,
    max_gas_limit: u64,
    current_transactions: Vec<RollupTransaction>,
    current_gas: u64,
    current_size: usize,
    chain_id: u32,
    network_id: u32,
    shard_id: ShardId,
}

pub struct BatchProcessor {
    state: Arc<RwLock<crate::state::RollupState>>,
    config: crate::config::RollupConfig,
    metrics: Arc<RwLock<crate::metrics::RollupMetrics>>,
    keypair: Arc<ego_core::crypto::KeyPair>,
}

impl RollupBatch {
    pub fn new(
        operator: Address,
        transactions: Vec<RollupTransaction>,
        l1_block_number: u64,
        prev_state_root: Hash,
        chain_id: u32,
        network_id: u32,
        epoch: EpochNumber,
        shard_id: ShardId,
    ) -> Self {
        let batch_id = Self::compute_batch_id(&operator, &transactions, l1_block_number);
        let size_bytes = Self::calculate_size(&transactions);
        let tx_root = Self::compute_tx_root(&transactions);
        let receipts_root = Hash::ZERO;

        Self {
            batch_id,
            operator,
            transactions,
            l1_block_number,
            timestamp: Timestamp::now(),
            prev_state_root,
            post_state_root: Hash::ZERO,
            execution_results: Vec::new(),
            gas_used: 0,
            size_bytes,
            protocol_version: PROTOCOL_VERSION,
            chain_id,
            network_id,
            tx_root,
            receipts_root,
            operator_signature: ego_core::DualSignature::new(None, None),
            epoch,
            shard_id,
        }
    }

    pub fn hash(&self) -> Hash {
        let mut data = Vec::new();

        data.extend_from_slice(self.operator.as_bytes());
        data.extend_from_slice(&self.l1_block_number.to_le_bytes());
        data.extend_from_slice(&self.timestamp.as_millis().to_le_bytes());
        data.extend_from_slice(self.prev_state_root.as_bytes());
        data.extend_from_slice(self.post_state_root.as_bytes());
        data.extend_from_slice(self.tx_root.as_bytes());
        data.extend_from_slice(&self.gas_used.to_le_bytes());
        data.extend_from_slice(&self.protocol_version.to_le_bytes());
        data.extend_from_slice(&self.chain_id.to_le_bytes());
        data.extend_from_slice(&self.network_id.to_le_bytes());
        data.extend_from_slice(&self.epoch.as_u64().to_le_bytes());
        data.extend_from_slice(&self.shard_id.as_u32().to_le_bytes());

        ego_core::crypto::hash_data(&data)
    }

    pub fn validate(&self) -> RollupResult<()> {
        if self.transactions.is_empty() {
            return Err(RollupError::InvalidBatch("Empty batch".to_string()));
        }

        if self.transactions.len() > 10000 {
            return Err(RollupError::InvalidBatch("Batch too large".to_string()));
        }

        let mut account_nonces: HashMap<Address, u64> = HashMap::new();

        for tx in &self.transactions {
            let sender = tx.inner.from;
            let expected_nonce = account_nonces.get(&sender).unwrap_or(&0) + 1;

            if tx.rollup_nonce != expected_nonce {
                return Err(RollupError::InvalidBatch(format!(
                    "Invalid nonce for {}: expected {}, got {}",
                    sender, expected_nonce, tx.rollup_nonce
                )));
            }

            account_nonces.insert(sender, tx.rollup_nonce);
        }

        if self.l1_block_number == 0 {
            return Err(RollupError::InvalidBatch(
                "Invalid L1 block number".to_string(),
            ));
        }

        if !self.execution_results.is_empty()
            && self.execution_results.len() != self.transactions.len()
        {
            return Err(RollupError::InvalidBatch(
                "Execution results count mismatch".to_string(),
            ));
        }

        if self.protocol_version != PROTOCOL_VERSION {
            return Err(RollupError::InvalidBatch(format!(
                "Protocol version mismatch: expected {}, got {}",
                PROTOCOL_VERSION, self.protocol_version
            )));
        }

        let computed_tx_root = Self::compute_tx_root(&self.transactions);
        if computed_tx_root != self.tx_root {
            return Err(RollupError::InvalidBatch(
                "Transaction root mismatch".to_string(),
            ));
        }

        for tx in &self.transactions {
            if tx.inner.chain_id != self.chain_id {
                return Err(RollupError::InvalidBatch(format!(
                    "Transaction chain_id mismatch: expected {}, got {}",
                    self.chain_id, tx.inner.chain_id
                )));
            }

            if tx.inner.shard_id != self.shard_id {
                return Err(RollupError::InvalidBatch(
                    "Transaction shard_id mismatch".to_string(),
                ));
            }
        }

        Ok(())
    }

    pub fn is_5g_optimized(&self) -> bool {
        self.size_bytes <= 1024 * 1024 && self.transactions.len() <= 1000
    }

    pub fn sign(&mut self, keypair: &ego_core::crypto::KeyPair) -> RollupResult<()> {
        let expected_operator = Address::from_public_key(&keypair.dilithium_public_key());
        if expected_operator != self.operator {
            return Err(RollupError::InvalidBatch(
                "Operator address does not match signing key".to_string(),
            ));
        }

        let signing_data = self.create_signing_data()?;
        self.operator_signature = keypair.sign_hybrid(&signing_data, false);
        self.batch_id = self.hash();

        Ok(())
    }

    fn create_signing_data(&self) -> RollupResult<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(DOMAIN_TAG_ROLLUP_BATCH);
        data.extend_from_slice(self.operator.as_bytes());
        data.extend_from_slice(&self.l1_block_number.to_le_bytes());
        data.extend_from_slice(&self.timestamp.as_millis().to_le_bytes());
        data.extend_from_slice(self.prev_state_root.as_bytes());
        data.extend_from_slice(self.post_state_root.as_bytes());
        data.extend_from_slice(self.tx_root.as_bytes());
        data.extend_from_slice(&self.gas_used.to_le_bytes());
        data.extend_from_slice(&self.chain_id.to_le_bytes());
        data.extend_from_slice(&self.network_id.to_le_bytes());
        data.extend_from_slice(&self.epoch.as_u64().to_le_bytes());
        data.extend_from_slice(&self.shard_id.as_u32().to_le_bytes());

        Ok(ego_core::crypto::blake2s_hash(&data))
    }

    pub fn verify_signature(
        &self,
        operator_dilithium_pk: &ego_core::PublicKey,
    ) -> RollupResult<bool> {
        let expected_operator = Address::from_public_key(operator_dilithium_pk);
        if expected_operator != self.operator {
            return Ok(false);
        }

        let signing_data = self.create_signing_data()?;

        if let Some(ref dilithium_sig) = self.operator_signature.dilithium_sig {
            ego_core::crypto::verify_signature(operator_dilithium_pk, &signing_data, dilithium_sig)
                .map_err(|e| {
                    RollupError::InvalidBatch(format!("Signature verification failed: {}", e))
                })
        } else {
            Ok(false)
        }
    }

    fn compute_batch_id(
        operator: &Address,
        transactions: &[RollupTransaction],
        l1_block_number: u64,
    ) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(operator.as_bytes());
        data.extend_from_slice(&l1_block_number.to_le_bytes());

        for tx in transactions {
            data.extend_from_slice(tx.hash().as_bytes());
        }

        ego_core::crypto::hash_data(&data)
    }

    fn calculate_size(transactions: &[RollupTransaction]) -> usize {
        transactions.iter().map(|tx| tx.size()).sum()
    }

    fn compute_tx_root(transactions: &[RollupTransaction]) -> Hash {
        if transactions.is_empty() {
            return Hash::ZERO;
        }

        let tx_hashes: Vec<Vec<u8>> = transactions.iter().map(|tx| tx.hash().to_vec()).collect();

        let merkle_tree = ego_core::crypto::MerkleTree::build(tx_hashes);
        merkle_tree.root_hash().unwrap_or(Hash::ZERO)
    }

    pub fn compute_receipts_root(&self) -> Hash {
        if self.execution_results.is_empty() {
            return Hash::ZERO;
        }

        let config = bincode::config::standard();
        let receipt_hashes: Vec<Vec<u8>> = self
            .execution_results
            .iter()
            .filter_map(|r| bincode::encode_to_vec(r, config).ok())
            .collect();

        let merkle_tree = ego_core::crypto::MerkleTree::build(receipt_hashes);
        merkle_tree.root_hash().unwrap_or(Hash::ZERO)
    }

    pub fn finalize_roots(&mut self) {
        self.receipts_root = self.compute_receipts_root();
        self.batch_id = self.hash();
    }

    pub fn is_cellular_safe(&self) -> bool {
        self.size_bytes <= 512 * 1024 && self.transactions.len() <= 500
    }

    pub fn estimate_bandwidth_cost(&self) -> u64 {
        let base_cost = self.size_bytes as u64;
        let tx_overhead = self.transactions.len() as u64 * 100;
        base_cost + tx_overhead
    }

    pub fn get_transaction_by_hash(&self, hash: &Hash) -> Option<&RollupTransaction> {
        self.transactions.iter().find(|tx| &tx.hash() == hash)
    }

    pub fn get_pq_signature_stats(&self) -> (u32, u32, u32) {
        let mut dilithium_count = 0u32;
        let mut ed25519_count = 0u32;
        let mut hybrid_count = 0u32;

        for tx in &self.transactions {
            match (
                &tx.inner.signature.ed25519_sig,
                &tx.inner.signature.dilithium_sig,
            ) {
                (Some(_), Some(_)) => hybrid_count += 1,
                (None, Some(_)) => dilithium_count += 1,
                (Some(_), None) => ed25519_count += 1,
                (None, None) => {}
            }
        }

        (dilithium_count, ed25519_count, hybrid_count)
    }
}

impl BatchBuilder {
    pub fn new(
        operator: Address,
        max_batch_size: u32,
        max_gas_limit: u64,
        chain_id: u32,
        network_id: u32,
        shard_id: ShardId,
    ) -> Self {
        Self {
            operator,
            max_batch_size,
            max_gas_limit,
            current_transactions: Vec::new(),
            current_gas: 0,
            current_size: 0,
            chain_id,
            network_id,
            shard_id,
        }
    }

    pub fn add_transaction(&mut self, tx: RollupTransaction) -> RollupResult<bool> {
        let tx_gas = tx.inner.estimate_resource_units();
        let tx_size = tx.size();

        if self.current_transactions.len() >= self.max_batch_size as usize {
            return Ok(false);
        }

        if self.current_gas + tx_gas > self.max_gas_limit {
            return Ok(false);
        }

        if tx_size > 100 * 1024 {
            return Err(RollupError::InvalidBatch(
                "Transaction too large for 5G optimization".to_string(),
            ));
        }

        if tx.inner.chain_id != self.chain_id {
            return Err(RollupError::InvalidBatch(format!(
                "Transaction chain_id mismatch: expected {}, got {}",
                self.chain_id, tx.inner.chain_id
            )));
        }

        if tx.inner.shard_id != self.shard_id {
            return Err(RollupError::InvalidBatch(
                "Transaction shard_id mismatch".to_string(),
            ));
        }

        self.current_transactions.push(tx);
        self.current_gas += tx_gas;
        self.current_size += tx_size;

        Ok(true)
    }

    pub fn can_add_transaction(&self, tx: &RollupTransaction) -> bool {
        let tx_gas = tx.inner.estimate_resource_units();

        self.current_transactions.len() < self.max_batch_size as usize
            && self.current_gas + tx_gas <= self.max_gas_limit
            && tx.inner.chain_id == self.chain_id
            && tx.inner.shard_id == self.shard_id
    }

    pub fn build(
        self,
        l1_block_number: u64,
        prev_state_root: Hash,
        epoch: EpochNumber,
    ) -> RollupResult<RollupBatch> {
        if self.current_transactions.is_empty() {
            return Err(RollupError::InvalidBatch(
                "Cannot build empty batch".to_string(),
            ));
        }

        let batch = RollupBatch::new(
            self.operator,
            self.current_transactions,
            l1_block_number,
            prev_state_root,
            self.chain_id,
            self.network_id,
            epoch,
            self.shard_id,
        );

        batch.validate()?;
        Ok(batch)
    }

    pub fn reset(&mut self) {
        self.current_transactions.clear();
        self.current_gas = 0;
        self.current_size = 0;
    }

    pub fn transaction_count(&self) -> usize {
        self.current_transactions.len()
    }

    pub fn current_gas(&self) -> u64 {
        self.current_gas
    }

    pub fn current_size(&self) -> usize {
        self.current_size
    }

    pub fn is_empty(&self) -> bool {
        self.current_transactions.is_empty()
    }

    pub fn is_5g_ready(&self) -> bool {
        self.current_size <= 512 * 1024 && self.current_transactions.len() <= 500
    }

    pub fn is_cellular_safe(&self) -> bool {
        self.current_size <= 256 * 1024 && self.current_transactions.len() <= 250
    }
}

impl BatchProcessor {
    pub fn new(
        state: Arc<RwLock<crate::state::RollupState>>,
        config: crate::config::RollupConfig,
        keypair: Arc<ego_core::crypto::KeyPair>,
    ) -> Self {
        Self {
            state,
            config,
            metrics: Arc::new(RwLock::new(crate::metrics::RollupMetrics::default())),
            keypair,
        }
    }

    pub async fn process_batch(&self, mut batch: RollupBatch) -> RollupResult<RollupBatch> {
        let start_time = std::time::Instant::now();

        batch.validate()?;

        if !batch.verify_signature(&self.keypair.dilithium_public_key())? {
            return Err(RollupError::InvalidBatch(
                "Invalid operator signature".to_string(),
            ));
        }

        let mut execution_results = Vec::new();
        let mut total_gas = 0u64;

        {
            let mut state = self.state.write().await;

            for tx in &batch.transactions {
                let result = self.execute_transaction(&mut state, tx).await?;
                total_gas += result.ru_used;
                execution_results.push(result);
            }

            batch.execution_results = execution_results;
            batch.gas_used = total_gas;
            batch.post_state_root = state.compute_state_root();
        }

        batch.finalize_roots();

        {
            let mut metrics = self.metrics.write().await;
            metrics.batches_processed += 1;
            metrics.transactions_processed += batch.transactions.len() as u64;
            metrics.total_ru_used += total_gas;

            let processing_time = start_time.elapsed();
            metrics.avg_batch_processing_time_ms =
                (metrics.avg_batch_processing_time_ms + processing_time.as_millis() as u64) / 2;

            if batch.is_5g_optimized() {
                metrics.five_g_batches += 1;
            }

            if batch.is_cellular_safe() {
                metrics.cellular_safe_batches += 1;
            }
        }

        Ok(batch)
    }

    async fn execute_transaction(
        &self,
        state: &mut crate::state::RollupState,
        tx: &RollupTransaction,
    ) -> RollupResult<RollupExecutionResult> {
        let result = state.execute_transaction(tx).await?;

        Ok(RollupExecutionResult {
            tx_hash: tx.hash(),
            success: result.success,
            ru_used: result.ru_used,
            state_changes: vec![],
            events: vec![],
            error: result.error,
            gas_refund: 0,
            logs_bloom: None,
        })
    }

    pub async fn get_metrics(&self) -> crate::metrics::RollupMetrics {
        self.metrics.read().await.clone()
    }

    pub async fn process_batch_5g(&self, batch: RollupBatch) -> RollupResult<RollupBatch> {
        if !self.config.five_g.enabled {
            return self.process_batch(batch).await;
        }

        let start_time = std::time::Instant::now();

        let result = if self.config.five_g.enable_edge_computing {
            self.process_batch_parallel(batch).await?
        } else {
            self.process_batch(batch).await?
        };

        let processing_time = start_time.elapsed();

        if processing_time > self.config.target_latency() {
            tracing::warn!(
                "Batch processing exceeded 5G latency target: {}ms > {}ms",
                processing_time.as_millis(),
                self.config.target_latency().as_millis()
            );
        }

        Ok(result)
    }

    async fn process_batch_parallel(&self, mut batch: RollupBatch) -> RollupResult<RollupBatch> {
        batch.validate()?;

        let chunk_size =
            (batch.transactions.len() / self.config.performance.batch_parallelism).max(1);
        let chunks: Vec<_> = batch.transactions.chunks(chunk_size).collect();

        let mut all_results = Vec::new();
        let mut total_gas = 0u64;

        for chunk in chunks {
            let mut chunk_results = Vec::new();
            let mut state = self.state.write().await;

            for tx in chunk {
                let result = self.execute_transaction(&mut state, tx).await?;
                total_gas += result.ru_used;
                chunk_results.push(result);
            }

            all_results.extend(chunk_results);
        }

        batch.execution_results = all_results;
        batch.gas_used = total_gas;

        {
            let state = self.state.read().await;
            batch.post_state_root = state.compute_state_root();
        }

        batch.finalize_roots();

        Ok(batch)
    }

    pub async fn create_rollup_commitment(
        &self,
        batch: &RollupBatch,
    ) -> RollupResult<RollupCommitment> {
        let commitment = RollupCommitment::new(
            batch.operator,
            format!("rollup_{}", batch.shard_id.as_u32()),
            batch,
            Hash::ZERO,
            Hash::ZERO,
            batch.l1_block_number,
            self.config.fraud_proofs.fraud_proof_window_blocks,
        );

        Ok(commitment)
    }

    pub async fn validate_batch_against_state(&self, batch: &RollupBatch) -> RollupResult<bool> {
        batch.validate()?;

        let state = self.state.read().await;

        if batch.prev_state_root != state.compute_state_root() {
            return Ok(false);
        }

        for tx in &batch.transactions {
            let account = state.get_account(&tx.inner.from)?;

            if let Err(_) = tx.inner.validate_against_account(&account) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    pub async fn reset_metrics(&self) {
        let mut metrics = self.metrics.write().await;
        *metrics = crate::metrics::RollupMetrics::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::{EpochNumber, ShardId, Transaction, TransactionPayload};

    fn create_test_transaction(nonce: u64, chain_id: u32) -> RollupTransaction {
        let inner = Transaction::new(
            Address::new([1u8; 20]),
            nonce,
            TransactionPayload::Transfer {
                to: Address::new([2u8; 20]),
                amount: Balance::from_egoc(100),
                memo: None,
                stealth_mode: false,
            },
            ShardId::new(0).unwrap(),
            None,
            chain_id,
        );

        RollupTransaction::new(inner, nonce, 1000)
    }

    #[test]
    fn test_batch_creation() {
        let operator = Address::new([1u8; 20]);
        let transactions = vec![create_test_transaction(1, 1)];
        let batch = RollupBatch::new(
            operator,
            transactions,
            1000,
            Hash::ZERO,
            1,
            1,
            EpochNumber::new(0),
            ShardId::new(0).unwrap(),
        );

        assert_eq!(batch.operator, operator);
        assert_eq!(batch.transactions.len(), 1);
        assert_eq!(batch.l1_block_number, 1000);
        assert_eq!(batch.chain_id, 1);
        assert_eq!(batch.network_id, 1);
    }

    #[test]
    fn test_batch_validation() {
        let operator = Address::new([1u8; 20]);
        let transactions = vec![create_test_transaction(1, 1)];
        let batch = RollupBatch::new(
            operator,
            transactions,
            1000,
            Hash::ZERO,
            1,
            1,
            EpochNumber::new(0),
            ShardId::new(0).unwrap(),
        );

        assert!(batch.validate().is_ok());
    }

    #[test]
    fn test_batch_builder() {
        let operator = Address::new([1u8; 20]);
        let mut builder =
            BatchBuilder::new(operator, 1000, 1000000, 1, 1, ShardId::new(0).unwrap());

        assert!(builder.is_empty());

        let tx = create_test_transaction(1, 1);
        assert!(builder.add_transaction(tx).unwrap());
        assert!(!builder.is_empty());
        assert_eq!(builder.transaction_count(), 1);
    }

    #[test]
    fn test_5g_optimization_detection() {
        let operator = Address::new([1u8; 20]);
        let transactions = vec![create_test_transaction(1, 1)];
        let batch = RollupBatch::new(
            operator,
            transactions,
            1000,
            Hash::ZERO,
            1,
            1,
            EpochNumber::new(0),
            ShardId::new(0).unwrap(),
        );

        assert!(batch.is_5g_optimized());
    }

    #[test]
    fn test_cellular_safe_detection() {
        let operator = Address::new([1u8; 20]);
        let transactions = vec![create_test_transaction(1, 1)];
        let batch = RollupBatch::new(
            operator,
            transactions,
            1000,
            Hash::ZERO,
            1,
            1,
            EpochNumber::new(0),
            ShardId::new(0).unwrap(),
        );

        assert!(batch.is_cellular_safe());
    }

    #[test]
    fn test_tx_root_computation() {
        let operator = Address::new([1u8; 20]);
        let transactions = vec![create_test_transaction(1, 1), create_test_transaction(2, 1)];
        let batch = RollupBatch::new(
            operator,
            transactions.clone(),
            1000,
            Hash::ZERO,
            1,
            1,
            EpochNumber::new(0),
            ShardId::new(0).unwrap(),
        );

        let computed_root = RollupBatch::compute_tx_root(&transactions);
        assert_eq!(batch.tx_root, computed_root);
    }

    #[tokio::test]
    async fn test_batch_processor() {
        let state = Arc::new(RwLock::new(crate::state::RollupState::new()));
        let config = crate::config::RollupConfig::default();
        let keypair = Arc::new(ego_core::crypto::KeyPair::generate());
        let processor = BatchProcessor::new(state, config, keypair);

        let operator = Address::new([1u8; 20]);
        let transactions = vec![create_test_transaction(1, 1)];
        let batch = RollupBatch::new(
            operator,
            transactions,
            1000,
            Hash::ZERO,
            1,
            1,
            EpochNumber::new(0),
            ShardId::new(0).unwrap(),
        );

        assert!(batch.validate().is_ok());
    }
}
