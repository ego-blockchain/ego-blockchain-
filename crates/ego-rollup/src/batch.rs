use crate::error::{RollupError, RollupResult};
use crate::types::{RollupExecutionResult, RollupTransaction};
use ego_core::{Address, Hash, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

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
}

pub struct BatchBuilder {
    operator: Address,
    max_batch_size: u32,
    max_gas_limit: u64,
    current_transactions: Vec<RollupTransaction>,
    current_gas: u64,
    current_size: usize,
}

pub struct BatchProcessor {
    state: Arc<RwLock<crate::state::RollupState>>,
    config: crate::config::RollupConfig,
    metrics: Arc<RwLock<crate::metrics::RollupMetrics>>,
}

impl RollupBatch {
    pub fn new(
        operator: Address,
        transactions: Vec<RollupTransaction>,
        l1_block_number: u64,
        prev_state_root: Hash,
    ) -> Self {
        let batch_id = Self::compute_batch_id(&operator, &transactions, l1_block_number);
        let size_bytes = Self::calculate_size(&transactions);

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
        }
    }

    pub fn hash(&self) -> Hash {
        let config = bincode::config::standard();
        let data = bincode::encode_to_vec(self, config).unwrap_or_default();
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

        Ok(())
    }

    pub fn is_5g_optimized(&self) -> bool {
        self.size_bytes <= 1024 * 1024 && self.transactions.len() <= 1000
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
}

impl BatchBuilder {
    pub fn new(operator: Address, max_batch_size: u32, max_gas_limit: u64) -> Self {
        Self {
            operator,
            max_batch_size,
            max_gas_limit,
            current_transactions: Vec::new(),
            current_gas: 0,
            current_size: 0,
        }
    }

    pub fn add_transaction(&mut self, tx: RollupTransaction) -> RollupResult<bool> {
        let tx_gas = tx.inner.estimate_compute_cost();
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

        self.current_transactions.push(tx);
        self.current_gas += tx_gas;
        self.current_size += tx_size;

        Ok(true)
    }

    pub fn can_add_transaction(&self, tx: &RollupTransaction) -> bool {
        let tx_gas = tx.inner.estimate_compute_cost();

        self.current_transactions.len() < self.max_batch_size as usize
            && self.current_gas + tx_gas <= self.max_gas_limit
    }

    pub fn build(self, l1_block_number: u64, prev_state_root: Hash) -> RollupResult<RollupBatch> {
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
}

impl BatchProcessor {
    pub fn new(
        state: Arc<RwLock<crate::state::RollupState>>,
        config: crate::config::RollupConfig,
    ) -> Self {
        Self {
            state,
            config,
            metrics: Arc::new(RwLock::new(crate::metrics::RollupMetrics::default())),
        }
    }

    pub async fn process_batch(&self, mut batch: RollupBatch) -> RollupResult<RollupBatch> {
        let start_time = std::time::Instant::now();

        batch.validate()?;

        let mut execution_results = Vec::new();
        let mut total_gas = 0u64;

        {
            let mut state = self.state.write().await;

            for tx in &batch.transactions {
                let result = self.execute_transaction(&mut state, tx).await?;
                total_gas += result.gas_used;
                execution_results.push(result);
            }

            batch.execution_results = execution_results;
            batch.gas_used = total_gas;
            batch.post_state_root = state.compute_state_root();
        }

        {
            let mut metrics = self.metrics.write().await;
            metrics.batches_processed += 1;
            metrics.transactions_processed += batch.transactions.len() as u64;
            metrics.total_gas_used += total_gas;

            let processing_time = start_time.elapsed();
            metrics.avg_batch_processing_time =
                (metrics.avg_batch_processing_time + processing_time.as_millis() as u64) / 2;

            if batch.is_5g_optimized() {
                metrics.five_g_batches += 1;
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
            gas_used: result.compute_used,
            state_changes: vec![],
            events: vec![],
            error: result.error,
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
                total_gas += result.gas_used;
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

        Ok(batch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::{Balance, KeyPair, ShardId, Transaction, TransactionPayload};

    fn create_test_transaction(nonce: u64) -> RollupTransaction {
        let inner = Transaction::new(
            Address::new([1u8; 20]),
            nonce,
            TransactionPayload::Transfer {
                to: Address::new([2u8; 20]),
                amount: Balance::from_egoc(100),
                memo: None,
            },
            ShardId::new(0).unwrap(),
            None,
        );

        RollupTransaction::new(inner, nonce, 1000)
    }

    #[test]
    fn test_batch_creation() {
        let operator = Address::new([1u8; 20]);
        let transactions = vec![create_test_transaction(1)];
        let batch = RollupBatch::new(operator, transactions, 1000, Hash::ZERO);

        assert_eq!(batch.operator, operator);
        assert_eq!(batch.transactions.len(), 1);
        assert_eq!(batch.l1_block_number, 1000);
    }

    #[test]
    fn test_batch_validation() {
        let operator = Address::new([1u8; 20]);
        let transactions = vec![create_test_transaction(1)];
        let batch = RollupBatch::new(operator, transactions, 1000, Hash::ZERO);

        assert!(batch.validate().is_ok());
    }

    #[test]
    fn test_batch_builder() {
        let operator = Address::new([1u8; 20]);
        let mut builder = BatchBuilder::new(operator, 1000, 1000000);

        assert!(builder.is_empty());

        let tx = create_test_transaction(1);
        assert!(builder.add_transaction(tx).unwrap());
        assert!(!builder.is_empty());
        assert_eq!(builder.transaction_count(), 1);
    }

    #[test]
    fn test_batch_builder_limits() {
        let operator = Address::new([1u8; 20]);
        let mut builder = BatchBuilder::new(operator, 2, 1000000);

        assert!(builder.add_transaction(create_test_transaction(1)).unwrap());
        assert!(builder.add_transaction(create_test_transaction(2)).unwrap());

        assert!(!builder.add_transaction(create_test_transaction(3)).unwrap());
    }

    #[test]
    fn test_5g_optimization_detection() {
        let operator = Address::new([1u8; 20]);
        let transactions = vec![create_test_transaction(1)];
        let batch = RollupBatch::new(operator, transactions, 1000, Hash::ZERO);

        assert!(batch.is_5g_optimized());
    }

    #[tokio::test]
    async fn test_batch_processor() {
        let state = Arc::new(RwLock::new(crate::state::RollupState::new()));
        let config = crate::config::RollupConfig::default();
        let processor = BatchProcessor::new(state, config);

        let operator = Address::new([1u8; 20]);
        let transactions = vec![create_test_transaction(1)];
        let batch = RollupBatch::new(operator, transactions, 1000, Hash::ZERO);

        assert!(batch.validate().is_ok());
    }
}
