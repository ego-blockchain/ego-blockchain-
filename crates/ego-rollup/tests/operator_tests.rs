#[cfg(test)]
mod tests {
    use ego_core::{
        Address, Balance, DualSignature, EpochNumber, Hash, ShardId, StateManager, Timestamp,
        Transaction, TransactionPayload,
    };
    use ego_rollup::operator::{
        BatchBuilder, ConnectionType, DAChunk, DataAvailability, OperatorConfig, OperatorMetrics,
        OperatorNode, RollupBatch, RollupCommitmentData, RollupOperator,
        calculate_cellular_data_usage, calculate_commitment_hash, calculate_da_chunk_count,
        calculate_operator_reputation, can_fit_in_batch, compress_batch_data, create_test_operator,
        create_test_operator_config, decompress_batch_data, estimate_batch_gas,
        estimate_batch_size, estimate_commitment_latency, estimate_da_overhead,
        is_within_cellular_budget, should_switch_to_wifi, validate_batch_integrity,
        validate_operator_config, validate_rollup_commitment,
    };

    const MAX_BATCH_SIZE: usize = 10_000;
    const MAX_BATCH_SIZE_CELLULAR: usize = 1_000;
    const MAX_BATCH_SIZE_5G: usize = 5_000;
    const BATCH_TIMEOUT_MS: u64 = 5000;

    fn create_test_keypair() -> ego_core::crypto::KeyPair {
        ego_core::crypto::KeyPair::generate()
    }

    fn create_test_transaction(
        from: Address,
        _to: Address,
        _amount: Balance,
        nonce: u64,
        _chain_id: u32,
        shard_id: ShardId,
        keypair: &ego_core::crypto::KeyPair,
    ) -> Transaction {
        let payload = TransactionPayload::Transfer {
            to: _to,
            amount: _amount,
            memo: None,
            stealth_mode: false,
        };

        let mut tx = Transaction::new(from, nonce, payload, shard_id, None, 100000);

        tx.timestamp = Timestamp::now();
        let hash_data = tx.hash.as_bytes();
        tx.signature = keypair.sign_hybrid(hash_data, false);
        tx
    }

    #[test]
    fn test_operator_config_default() {
        let config = OperatorConfig::default();
        assert_eq!(config.rollup_id, "ego-rollup-0");
        assert_eq!(config.chain_id, 1);
        assert_eq!(config.max_batch_size, MAX_BATCH_SIZE);
        assert_eq!(config.enable_compression, true);
        assert_eq!(config.cellular_safe_mode, true);
        assert_eq!(config.drs_enabled, true);
        assert_eq!(config.deploy_policy_enabled, true);
    }

    #[test]
    fn test_operator_config_batch_timeout() {
        let config = OperatorConfig::default();
        let timeout = config.batch_timeout();
        assert_eq!(timeout.as_millis(), BATCH_TIMEOUT_MS as u128);
    }

    #[test]
    fn test_operator_config_target_latency() {
        let mut config = OperatorConfig::default();
        config.enable_5g = false;
        assert_eq!(config.target_latency().as_millis(), 250);

        config.enable_5g = true;
        assert_eq!(config.target_latency().as_millis(), 10);
    }

    #[test]
    fn test_operator_config_cellular_batch_size() {
        let mut config = OperatorConfig::default();
        config.enable_5g = false;
        assert_eq!(config.cellular_batch_size(), MAX_BATCH_SIZE_CELLULAR);

        config.enable_5g = true;
        assert_eq!(config.cellular_batch_size(), MAX_BATCH_SIZE_5G);
    }

    #[test]
    fn test_operator_config_is_wifi_only_operation() {
        let config = OperatorConfig::default();
        assert!(config.is_wifi_only_operation("commitment_post"));
        assert!(config.is_wifi_only_operation("da_upload"));
        assert!(!config.is_wifi_only_operation("tx_processing"));
    }

    #[test]
    fn test_batch_builder_creation() {
        let keypair = create_test_keypair();
        let address = Address::from_public_key(&keypair.dilithium_public_key());
        let shard_id = ShardId::new(0).unwrap();

        let _builder = BatchBuilder::new(
            address,
            "test-rollup".to_string(),
            1000,
            50_000_000,
            1,
            1,
            shard_id,
        );
    }

    #[test]
    fn test_batch_builder_add_transaction() {
        let keypair = create_test_keypair();
        let address = Address::from_public_key(&keypair.dilithium_public_key());
        let shard_id = ShardId::new(0).unwrap();

        let mut builder = BatchBuilder::new(
            address,
            "test-rollup".to_string(),
            1000,
            50_000_000,
            1,
            1,
            shard_id,
        );

        let tx = create_test_transaction(
            address,
            address,
            Balance::new(1000),
            0,
            1,
            shard_id,
            &keypair,
        );

        let result = builder.add_transaction(tx.clone());
        assert!(result.is_ok());
    }

    #[test]
    fn test_batch_builder_can_add_transaction() {
        let keypair = create_test_keypair();
        let address = Address::from_public_key(&keypair.dilithium_public_key());
        let shard_id = ShardId::new(0).unwrap();

        let builder = BatchBuilder::new(
            address,
            "test-rollup".to_string(),
            10,
            50_000_000,
            1,
            1,
            shard_id,
        );

        let tx = create_test_transaction(
            address,
            address,
            Balance::new(1000),
            0,
            1,
            shard_id,
            &keypair,
        );

        assert!(builder.can_add_transaction(&tx));
    }

    #[test]
    fn test_batch_builder_cellular_safe() {
        let keypair = create_test_keypair();
        let address = Address::from_public_key(&keypair.dilithium_public_key());
        let shard_id = ShardId::new(0).unwrap();

        let mut builder = BatchBuilder::new(
            address,
            "test-rollup".to_string(),
            MAX_BATCH_SIZE_CELLULAR + 100,
            50_000_000,
            1,
            1,
            shard_id,
        );

        assert!(builder.is_cellular_safe());

        for i in 0..MAX_BATCH_SIZE_CELLULAR {
            let tx = create_test_transaction(
                address,
                address,
                Balance::new(1000),
                i as u64,
                1,
                shard_id,
                &keypair,
            );
            let _ = builder.add_transaction(tx);
        }

        assert!(builder.is_cellular_safe());

        let tx = create_test_transaction(
            address,
            address,
            Balance::new(1000),
            MAX_BATCH_SIZE_CELLULAR as u64,
            1,
            shard_id,
            &keypair,
        );
        let _ = builder.add_transaction(tx);

        assert!(!builder.is_cellular_safe());
    }

    #[test]
    fn test_batch_builder_5g_ready() {
        let keypair = create_test_keypair();
        let address = Address::from_public_key(&keypair.dilithium_public_key());
        let shard_id = ShardId::new(0).unwrap();

        let mut builder = BatchBuilder::new(
            address,
            "test-rollup".to_string(),
            MAX_BATCH_SIZE_5G,
            50_000_000,
            1,
            1,
            shard_id,
        );

        assert!(!builder.is_5g_ready());

        for i in 0..(MAX_BATCH_SIZE_5G / 2) {
            let tx = create_test_transaction(
                address,
                address,
                Balance::new(1000),
                i as u64,
                1,
                shard_id,
                &keypair,
            );
            let _ = builder.add_transaction(tx);
        }

        assert!(builder.is_5g_ready());
    }

    #[test]
    fn test_rollup_batch_compute_batch_id() {
        let keypair = create_test_keypair();
        let address = Address::from_public_key(&keypair.dilithium_public_key());
        let shard_id = ShardId::new(0).unwrap();

        let batch = RollupBatch {
            batch_id: Hash::ZERO,
            rollup_id: "test-rollup".to_string(),
            operator: address,
            transactions: Vec::new(),
            transaction_results: Vec::new(),
            prev_state_root: Hash::ZERO,
            new_state_root: Hash::ZERO,
            tx_root: Hash::ZERO,
            receipts_root: Hash::ZERO,
            proof_events_root: Hash::ZERO,
            deploy_events_root: Hash::ZERO,
            drs_events_root: Hash::ZERO,
            l1_block_number: 1000,
            epoch: EpochNumber::new(1),
            timestamp: Timestamp::now(),
            gas_used: 0,
            size_bytes: 0,
            chain_id: 1,
            network_id: 1,
            shard_id,
            operator_signature: DualSignature::new(None, None),
            is_cellular_safe: true,
            is_5g_optimized: false,
            drs_scores_applied: 0,
            deploy_requests_processed: 0,
        };

        let batch_id = batch.compute_batch_id();
        assert_ne!(batch_id, Hash::ZERO);
    }

    #[test]
    fn test_rollup_batch_sign_and_verify() {
        let keypair = create_test_keypair();
        let address = Address::from_public_key(&keypair.dilithium_public_key());
        let shard_id = ShardId::new(0).unwrap();

        let mut batch = RollupBatch {
            batch_id: Hash::ZERO,
            rollup_id: "test-rollup".to_string(),
            operator: address,
            transactions: Vec::new(),
            transaction_results: Vec::new(),
            prev_state_root: Hash::ZERO,
            new_state_root: Hash::ZERO,
            tx_root: Hash::ZERO,
            receipts_root: Hash::ZERO,
            proof_events_root: Hash::ZERO,
            deploy_events_root: Hash::ZERO,
            drs_events_root: Hash::ZERO,
            l1_block_number: 1000,
            epoch: EpochNumber::new(1),
            timestamp: Timestamp::now(),
            gas_used: 0,
            size_bytes: 0,
            chain_id: 1,
            network_id: 1,
            shard_id,
            operator_signature: DualSignature::new(None, None),
            is_cellular_safe: true,
            is_5g_optimized: false,
            drs_scores_applied: 0,
            deploy_requests_processed: 0,
        };

        let result = batch.sign(&keypair);
        assert!(result.is_ok());
        assert!(batch.operator_signature.dilithium_sig.is_some());

        let verify_result = batch.verify_signature(&keypair.dilithium_public_key());
        assert!(verify_result.is_ok());
        assert!(verify_result.unwrap());
    }

    #[test]
    fn test_da_chunk_creation() {
        let keypair = create_test_keypair();
        let address = Address::from_public_key(&keypair.dilithium_public_key());
        let data = vec![1, 2, 3, 4, 5];
        let batch_id = Hash::ZERO;

        let chunk = DAChunk::new(
            0,
            10,
            data.clone(),
            batch_id,
            "test-rollup".to_string(),
            address,
            1,
        );

        assert_eq!(chunk.chunk_index, 0);
        assert_eq!(chunk.total_chunks, 10);
        assert_eq!(chunk.data, data);
        assert_ne!(chunk.chunk_hash, Hash::ZERO);
    }

    #[test]
    fn test_data_availability_creation() {
        let result = DataAvailability::new(64, 32, 256 * 1024, true, 6);
        assert!(result.is_ok());

        let result_invalid = DataAvailability::new(0, 32, 256 * 1024, true, 6);
        assert!(result_invalid.is_err());
    }

    #[test]
    fn test_data_availability_encode_data() {
        let keypair = create_test_keypair();
        let address = Address::from_public_key(&keypair.dilithium_public_key());
        let da = DataAvailability::new(64, 32, 1024, true, 6).unwrap();
        let data = vec![1u8; 5000];
        let batch_id = Hash::ZERO;

        let result = da.encode_data(batch_id, data, "test-rollup".to_string(), address, 1);
        assert!(result.is_ok());

        let chunks = result.unwrap();
        assert!(chunks.len() > 0);
    }

    #[test]
    fn test_rollup_commitment_creation() {
        let keypair = create_test_keypair();
        let address = Address::from_public_key(&keypair.dilithium_public_key());
        let shard_id = ShardId::new(0).unwrap();

        let batch = RollupBatch {
            batch_id: Hash::ZERO,
            rollup_id: "test-rollup".to_string(),
            operator: address,
            transactions: Vec::new(),
            transaction_results: Vec::new(),
            prev_state_root: Hash::ZERO,
            new_state_root: Hash::ZERO,
            tx_root: Hash::ZERO,
            receipts_root: Hash::ZERO,
            proof_events_root: Hash::ZERO,
            deploy_events_root: Hash::ZERO,
            drs_events_root: Hash::ZERO,
            l1_block_number: 1000,
            epoch: EpochNumber::new(1),
            timestamp: Timestamp::now(),
            gas_used: 0,
            size_bytes: 0,
            chain_id: 1,
            network_id: 1,
            shard_id,
            operator_signature: DualSignature::new(None, None),
            is_cellular_safe: true,
            is_5g_optimized: false,
            drs_scores_applied: 0,
            deploy_requests_processed: 0,
        };

        let commitment = RollupCommitmentData::new(
            address,
            "test-rollup".to_string(),
            &batch,
            Hash::ZERO,
            Hash::ZERO,
            Hash::ZERO,
            Hash::ZERO,
            1000,
            7200,
            1,
            1,
        );

        assert_eq!(commitment.operator, address);
        assert_eq!(commitment.batch_id, batch.batch_id);
        assert_ne!(commitment.commitment_hash, Hash::ZERO);
    }

    #[test]
    fn test_rollup_commitment_sign() {
        let keypair = create_test_keypair();
        let address = Address::from_public_key(&keypair.dilithium_public_key());
        let shard_id = ShardId::new(0).unwrap();

        let batch = RollupBatch {
            batch_id: Hash::ZERO,
            rollup_id: "test-rollup".to_string(),
            operator: address,
            transactions: Vec::new(),
            transaction_results: Vec::new(),
            prev_state_root: Hash::ZERO,
            new_state_root: Hash::ZERO,
            tx_root: Hash::ZERO,
            receipts_root: Hash::ZERO,
            proof_events_root: Hash::ZERO,
            deploy_events_root: Hash::ZERO,
            drs_events_root: Hash::ZERO,
            l1_block_number: 1000,
            epoch: EpochNumber::new(1),
            timestamp: Timestamp::now(),
            gas_used: 0,
            size_bytes: 0,
            chain_id: 1,
            network_id: 1,
            shard_id,
            operator_signature: DualSignature::new(None, None),
            is_cellular_safe: true,
            is_5g_optimized: false,
            drs_scores_applied: 0,
            deploy_requests_processed: 0,
        };

        let mut commitment = RollupCommitmentData::new(
            address,
            "test-rollup".to_string(),
            &batch,
            Hash::ZERO,
            Hash::ZERO,
            Hash::ZERO,
            Hash::ZERO,
            1000,
            7200,
            1,
            1,
        );

        let result = commitment.sign(&keypair);
        assert!(result.is_ok());
        assert!(commitment.operator_signature.dilithium_sig.is_some());
    }

    #[test]
    fn test_operator_metrics_default() {
        let metrics = OperatorMetrics::default();
        assert_eq!(metrics.transactions_received, 0);
        assert_eq!(metrics.batches_processed, 0);
        assert_eq!(metrics.commits_posted, 0);
        assert!(metrics.is_healthy());
    }

    #[test]
    fn test_operator_metrics_record_batch() {
        let mut metrics = OperatorMetrics::default();
        metrics.record_batch(100, true, false);

        assert_eq!(metrics.batches_processed, 1);
        assert_eq!(metrics.cellular_safe_batches, 1);
        assert_eq!(metrics.five_g_optimized_batches, 0);
        assert_eq!(metrics.avg_batch_time_ms, 100);

        metrics.record_batch(200, true, true);
        assert_eq!(metrics.batches_processed, 2);
        assert_eq!(metrics.five_g_optimized_batches, 1);
        assert_eq!(metrics.avg_batch_time_ms, 150);
    }

    #[test]
    fn test_operator_metrics_record_commit() {
        let mut metrics = OperatorMetrics::default();
        metrics.record_commit(50);

        assert_eq!(metrics.commits_posted, 1);
        assert_eq!(metrics.avg_commit_latency_ms, 50);

        metrics.record_commit(100);
        assert_eq!(metrics.commits_posted, 2);
        assert_eq!(metrics.avg_commit_latency_ms, 75);
    }

    #[test]
    fn test_operator_metrics_record_signature() {
        let mut metrics = OperatorMetrics::default();

        metrics.record_signature(true, true);
        assert_eq!(metrics.hybrid_signatures, 1);

        metrics.record_signature(true, false);
        assert_eq!(metrics.dilithium_signatures, 1);

        metrics.record_signature(false, true);
        assert_eq!(metrics.ed25519_signatures, 1);
    }

    #[test]
    fn test_operator_metrics_record_data_usage() {
        let mut metrics = OperatorMetrics::default();

        metrics.record_data_usage(10 * 1024 * 1024, true);
        assert_eq!(metrics.cellular_data_mb, 10);

        metrics.record_data_usage(20 * 1024 * 1024, false);
        assert_eq!(metrics.wifi_data_mb, 20);
    }

    #[test]
    fn test_operator_metrics_record_error() {
        let mut metrics = OperatorMetrics::default();

        metrics.record_error("test_error");
        assert_eq!(*metrics.errors.get("test_error").unwrap(), 1);

        metrics.record_error("test_error");
        assert_eq!(*metrics.errors.get("test_error").unwrap(), 2);
    }

    #[tokio::test]
    async fn test_rollup_operator_creation() {
        let keypair = create_test_keypair();
        let config = OperatorConfig::default();
        let state_manager = StateManager::new(config.chain_id, config.network_id);

        let result = RollupOperator::new(config, keypair, state_manager);
        assert!(result.is_ok());

        let operator = result.unwrap();
        assert_eq!(operator.rollup_id(), "ego-rollup-0");
    }

    #[tokio::test]
    async fn test_rollup_operator_start_stop() {
        let keypair = create_test_keypair();
        let config = OperatorConfig::default();
        let state_manager = StateManager::new(config.chain_id, config.network_id);

        let mut operator = RollupOperator::new(config, keypair, state_manager).unwrap();

        let result = operator.start().await;
        assert!(result.is_ok());

        let result = operator.stop().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_rollup_operator_submit_transaction_invalid_signature() {
        let keypair = create_test_keypair();
        let address = Address::from_public_key(&keypair.dilithium_public_key());
        let config = OperatorConfig::default();
        let state_manager = StateManager::new(config.chain_id, config.network_id);

        let operator = RollupOperator::new(config.clone(), keypair, state_manager).unwrap();

        let payload = TransactionPayload::Transfer {
            to: address,
            amount: Balance::new(1000),
            memo: None,
            stealth_mode: false,
        };

        let mut tx = Transaction::new(address, 0, payload, config.shard_id, None, 100000);

        tx.signature = DualSignature::new(None, None);

        let result = operator.submit_transaction(tx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_rollup_operator_get_operator_info() {
        let keypair = create_test_keypair();
        let config = OperatorConfig::default();
        let state_manager = StateManager::new(config.chain_id, config.network_id);

        let operator = RollupOperator::new(config, keypair, state_manager).unwrap();
        let info = operator.get_operator_info().await;

        assert_eq!(info.rollup_id, "ego-rollup-0");
        assert_eq!(info.total_commits, 0);
        assert_eq!(info.reputation_score, 1.0);
    }

    #[tokio::test]
    async fn test_rollup_operator_advance_epoch() {
        let keypair = create_test_keypair();
        let config = OperatorConfig::default();
        let state_manager = StateManager::new(config.chain_id, config.network_id);

        let operator = RollupOperator::new(config, keypair, state_manager).unwrap();

        let result = operator.advance_epoch().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_rollup_operator_connection_switching() {
        let keypair = create_test_keypair();
        let config = OperatorConfig::default();
        let state_manager = StateManager::new(config.chain_id, config.network_id);

        let operator = RollupOperator::new(config, keypair, state_manager).unwrap();

        let result = operator.switch_connection(ConnectionType::Cellular5G).await;
        assert!(result.is_ok());

        let is_cellular = operator.is_on_cellular().await;
        assert!(is_cellular);
    }

    #[tokio::test]
    async fn test_rollup_operator_cellular_budget_check() {
        let keypair = create_test_keypair();
        let config = OperatorConfig::default();
        let state_manager = StateManager::new(config.chain_id, config.network_id);

        let operator = RollupOperator::new(config, keypair, state_manager).unwrap();

        let result = operator.check_cellular_budget().await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_rollup_operator_handle_challenge() {
        let keypair = create_test_keypair();
        let config = OperatorConfig::default();
        let state_manager = StateManager::new(config.chain_id, config.network_id);

        let operator = RollupOperator::new(config, keypair, state_manager).unwrap();

        let result = operator.handle_challenge(Hash::ZERO, Hash::ZERO).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_rollup_operator_handle_slash() {
        let keypair = create_test_keypair();
        let config = OperatorConfig::default();
        let state_manager = StateManager::new(config.chain_id, config.network_id);

        let operator = RollupOperator::new(config, keypair, state_manager).unwrap();

        let result = operator.handle_slash(Hash::ZERO, 1000).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_rollup_operator_finalize_commitment() {
        let keypair = create_test_keypair();
        let address = Address::from_public_key(&keypair.dilithium_public_key());
        let config = OperatorConfig::default();
        let state_manager = StateManager::new(config.chain_id, config.network_id);

        let operator = RollupOperator::new(config.clone(), keypair.clone(), state_manager).unwrap();

        let result = operator.finalize_commitment(Hash::ZERO).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_operator_node_creation() {
        let keypair = create_test_keypair();
        let config = OperatorConfig::default();
        let state_manager = StateManager::new(config.chain_id, config.network_id);

        let operator = RollupOperator::new(config, keypair, state_manager).unwrap();
        let node = OperatorNode::new(operator);

        assert_eq!(node.rollup_id(), "ego-rollup-0");
    }

    #[test]
    fn test_calculate_operator_reputation() {
        let reputation = calculate_operator_reputation(100, 95, 5, 2, 0);
        assert!(reputation > 0.8);

        let reputation_low = calculate_operator_reputation(100, 50, 5, 10, 5);
        assert!(reputation_low < 0.5);

        let reputation_zero = calculate_operator_reputation(0, 0, 0, 0, 0);
        assert_eq!(reputation_zero, 1.0);
    }

    #[test]
    fn test_estimate_batch_gas() {
        let keypair = create_test_keypair();
        let address = Address::from_public_key(&keypair.dilithium_public_key());
        let shard_id = ShardId::new(0).unwrap();

        let tx1 = create_test_transaction(
            address,
            address,
            Balance::new(1000),
            0,
            1,
            shard_id,
            &keypair,
        );
        let tx2 = create_test_transaction(
            address,
            address,
            Balance::new(2000),
            1,
            1,
            shard_id,
            &keypair,
        );

        let transactions = vec![tx1, tx2];
        let total_gas = estimate_batch_gas(&transactions);
        assert!(total_gas > 0);
    }

    #[test]
    fn test_can_fit_in_batch() {
        assert!(can_fit_in_batch(1000, 5, 500, 2000, 10));
        assert!(!can_fit_in_batch(1500, 5, 600, 2000, 10));
        assert!(!can_fit_in_batch(1000, 10, 500, 2000, 10));
    }

    #[tokio::test]
    async fn test_compress_and_decompress_batch_data() {
        let data = vec![1u8; 10000];

        let compressed = compress_batch_data(&data, 6).await;
        assert!(compressed.is_ok());

        let compressed_data = compressed.unwrap();
        assert!(compressed_data.len() < data.len());

        let decompressed = decompress_batch_data(&compressed_data).await;
        assert!(decompressed.is_ok());
        assert_eq!(decompressed.unwrap(), data);
    }

    #[test]
    fn test_calculate_da_chunk_count() {
        let chunk_count = calculate_da_chunk_count(1000000, 1024, 64, 32);
        assert!(chunk_count > 0);

        let expected_data_chunks = (1000000 + 1024 - 1) / 1024;
        let expected_groups = (expected_data_chunks + 64 - 1) / 64;
        let expected_total = expected_groups * (64 + 32);
        assert_eq!(chunk_count, expected_total as u32);
    }

    #[test]
    fn test_is_within_cellular_budget() {
        assert!(is_within_cellular_budget(1000, 5));
        assert!(is_within_cellular_budget(5000, 5));
        assert!(!is_within_cellular_budget(5200, 5));
    }

    #[test]
    fn test_should_switch_to_wifi() {
        assert!(!should_switch_to_wifi(1000, 5, 0.8));
        assert!(should_switch_to_wifi(4500, 5, 0.8));
        assert!(should_switch_to_wifi(5000, 5, 0.5));
    }

    #[test]
    fn test_estimate_commitment_latency() {
        let latency_5g = estimate_commitment_latency(ConnectionType::Cellular5G, 100);
        let latency_4g = estimate_commitment_latency(ConnectionType::Cellular4G, 100);
        let latency_wifi = estimate_commitment_latency(ConnectionType::WiFi, 100);

        assert!(latency_5g < latency_4g);
        assert!(latency_wifi < latency_4g);
    }

    #[test]
    fn test_calculate_commitment_hash() {
        let hash = calculate_commitment_hash(
            Hash::ZERO,
            Hash::ZERO,
            Hash::ZERO,
            Hash::ZERO,
            Hash::ZERO,
            Hash::ZERO,
            1,
        );
        assert_ne!(hash, Hash::ZERO);
    }

    #[test]
    fn test_calculate_cellular_data_usage() {
        let usage = calculate_cellular_data_usage(100, 500, 0.5);
        assert_eq!(usage, 73);

        let usage_no_overhead = calculate_cellular_data_usage(100, 500, 0.0);
        assert_eq!(usage_no_overhead, 48);
    }

    #[test]
    fn test_validate_operator_config() {
        let config = OperatorConfig::default();
        let result = validate_operator_config(&config);
        assert!(result.is_ok());

        let mut invalid_config = config.clone();
        invalid_config.max_batch_size = 0;
        let result = validate_operator_config(&invalid_config);
        assert!(result.is_err());

        let mut invalid_config = config.clone();
        invalid_config.erasure_k = 0;
        let result = validate_operator_config(&invalid_config);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_test_operator_config() {
        let config = create_test_operator_config("test-rollup".to_string(), 0, false);
        assert_eq!(config.rollup_id, "test-rollup");
        assert_eq!(config.enable_5g, false);
        assert_eq!(config.max_batch_size, MAX_BATCH_SIZE_CELLULAR);

        let config_5g = create_test_operator_config("test-rollup".to_string(), 0, true);
        assert_eq!(config_5g.enable_5g, true);
        assert_eq!(config_5g.max_batch_size, MAX_BATCH_SIZE_5G);
    }

    #[test]
    fn test_create_test_operator() {
        let keypair = create_test_keypair();
        let result = create_test_operator("test-rollup".to_string(), 0, keypair);
        assert!(result.is_ok());

        let operator = result.unwrap();
        assert_eq!(operator.rollup_id(), "test-rollup");
    }

    #[tokio::test]
    async fn test_estimate_batch_size() {
        let keypair = create_test_keypair();
        let address = Address::from_public_key(&keypair.dilithium_public_key());
        let shard_id = ShardId::new(0).unwrap();

        let tx1 = create_test_transaction(
            address,
            address,
            Balance::new(1000),
            0,
            1,
            shard_id,
            &keypair,
        );
        let tx2 = create_test_transaction(
            address,
            address,
            Balance::new(2000),
            1,
            1,
            shard_id,
            &keypair,
        );

        let transactions = vec![tx1, tx2];
        let size = estimate_batch_size(&transactions).await;
        assert!(size > 0);
    }

    #[tokio::test]
    async fn test_estimate_da_overhead() {
        let overhead = estimate_da_overhead(1000000, 64, 32).await;
        assert!(overhead > 1000000);

        let expected_ratio = (64.0 + 32.0) / 64.0;
        let expected_overhead = (1000000.0 * expected_ratio) as usize;
        assert_eq!(overhead, expected_overhead);
    }

    #[tokio::test]
    async fn test_validate_rollup_commitment() {
        let keypair = create_test_keypair();
        let address = Address::from_public_key(&keypair.dilithium_public_key());
        let shard_id = ShardId::new(0).unwrap();

        let batch = RollupBatch {
            batch_id: Hash::ZERO,
            rollup_id: "test-rollup".to_string(),
            operator: address,
            transactions: Vec::new(),
            transaction_results: Vec::new(),
            prev_state_root: Hash::ZERO,
            new_state_root: Hash::ZERO,
            tx_root: Hash::ZERO,
            receipts_root: Hash::ZERO,
            proof_events_root: Hash::ZERO,
            deploy_events_root: Hash::ZERO,
            drs_events_root: Hash::ZERO,
            l1_block_number: 1000,
            epoch: EpochNumber::new(1),
            timestamp: Timestamp::now(),
            gas_used: 0,
            size_bytes: 0,
            chain_id: 1,
            network_id: 1,
            shard_id,
            operator_signature: DualSignature::new(None, None),
            is_cellular_safe: true,
            is_5g_optimized: false,
            drs_scores_applied: 0,
            deploy_requests_processed: 0,
        };

        let mut commitment = RollupCommitmentData::new(
            address,
            "test-rollup".to_string(),
            &batch,
            Hash::ZERO,
            Hash::ZERO,
            Hash::ZERO,
            Hash::ZERO,
            1000,
            7200,
            1,
            1,
        );

        commitment.sign(&keypair).unwrap();

        let result = validate_rollup_commitment(&commitment, &keypair.dilithium_public_key()).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_validate_batch_integrity() {
        let keypair = create_test_keypair();
        let address = Address::from_public_key(&keypair.dilithium_public_key());
        let shard_id = ShardId::new(0).unwrap();

        let mut batch = RollupBatch {
            batch_id: Hash::ZERO,
            rollup_id: "test-rollup".to_string(),
            operator: address,
            transactions: Vec::new(),
            transaction_results: Vec::new(),
            prev_state_root: Hash::ZERO,
            new_state_root: Hash::ZERO,
            tx_root: Hash::ZERO,
            receipts_root: Hash::ZERO,
            proof_events_root: Hash::ZERO,
            deploy_events_root: Hash::ZERO,
            drs_events_root: Hash::ZERO,
            l1_block_number: 1000,
            epoch: EpochNumber::new(1),
            timestamp: Timestamp::now(),
            gas_used: 0,
            size_bytes: 0,
            chain_id: 1,
            network_id: 1,
            shard_id,
            operator_signature: DualSignature::new(None, None),
            is_cellular_safe: true,
            is_5g_optimized: false,
            drs_scores_applied: 0,
            deploy_requests_processed: 0,
        };

        batch.sign(&keypair).unwrap();

        let result = validate_batch_integrity(&batch, &keypair.dilithium_public_key()).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}
