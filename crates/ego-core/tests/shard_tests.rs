#[cfg(test)]
mod shard_tests {
    use ego_core::block::PQSignatureCount;
    use ego_core::shard::CrossShardReceipt;
    use ego_core::{
        crypto::KeyPair, shard::*, transaction::*, Account, AccountType, Address, AlgorithmId,
        Balance, Block, BlockBody, BlockHeader, BlockHeaderCore, Hash, ShardId, SliceId, Timestamp,
    };
    use std::collections::HashMap;
    use std::sync::Arc;

    const TEST_CHAIN_ID: u32 = 1;
    const TEST_NETWORK_ID: u32 = 1;

    fn create_test_keypair() -> KeyPair {
        KeyPair::generate()
    }

    fn create_test_shard_config(shard_id: u32) -> ShardConfig {
        ShardConfig {
            shard_id: ShardId::from_u32(shard_id),
            ..Default::default()
        }
    }

    fn create_test_account(address: Address, balance: Balance) -> Account {
        let keypair = create_test_keypair();
        Account {
            address,
            balance,
            nonce: 0,
            storage_used: 0,
            storage_quota: 10_000_000_000,
            storage_credits: 1_000_000,
            deploy_credits: 100,
            free_deploys_remaining: 3,
            account_type: AccountType::EOA,
            dilithium_pk: vec![],
            mlkem_pk: vec![],
            ed25519_pk: None,
            x25519_pk: None,
            slh_dsa_pk: None,
            authorized_slices: vec![],
            metadata: HashMap::new(),
            device_capabilities: None,
            peer_id: None,
            pq_transition_info: Some(ego_core::account::PQTransitionInfo {
                transition_started_epoch: 0,
                pq_only_mode: false,
                ed25519_disabled_epoch: None,
                supported_algorithms: vec![
                    AlgorithmId::MlDsa2.as_u16(),
                    AlgorithmId::MlKem768.as_u16(),
                ],
            }),
            per_shard_nonces: Some(HashMap::new()),
            deploy_bond_locked_until: None,
            staking_info: None,
            validator_info: None,
            tmp_attestation: None,
            contract_info: None,
            last_drs_epoch: None,
            last_drs_score: None,
            last_activity: Timestamp::now(),
            created_at: Timestamp::now(),
            hot_set_mode: ego_core::account::HotSetMode::LightClient,
            pruning_config: None,
            archival_config: None,
            storage_provider_info: None,
        }
    }

    fn create_test_transaction(keypair: &KeyPair, nonce: u64, shard_id: ShardId) -> Transaction {
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let payload = TransactionPayload::Transfer {
            to: Address::new([99u8; 20]),
            amount: Balance::from(1000u64),
            memo: Some("Test".to_string()),
            stealth_mode: false,
        };

        let mut tx = Transaction::new(from, nonce, payload, shard_id, None, TEST_CHAIN_ID);
        tx.sign(keypair, false).expect("Failed to sign transaction");
        tx
    }

    fn create_test_block(height: u64, shard_id: ShardId, transactions: Vec<Transaction>) -> Block {
        let transactions_root = if transactions.is_empty() {
            Hash::ZERO
        } else {
            let tx_hashes: Vec<Vec<u8>> = transactions.iter().map(|tx| tx.hash.to_vec()).collect();
            let merkle_tree = ego_core::crypto::MerkleTree::build(tx_hashes);
            merkle_tree.root_hash().unwrap_or(Hash::ZERO)
        };

        let header_core = BlockHeaderCore {
            height: ego_core::BlockHeight::new(height),
            timestamp: Timestamp::now(),
            previous_hash: Hash::ZERO,
            state_root: Hash::ZERO,
            transactions_root,
            receipts_root: Hash::ZERO,
            events_root: Hash::ZERO,
            da_root: Hash::ZERO,
            shard_id,
            proposer: Address::new([1u8; 20]),
            tx_count: transactions.len() as u32,
            protocol_version: ego_core::PROTOCOL_VERSION,
            epoch: ego_core::EpochNumber(0),
            compute_used: 0,
            storage_used: 0,
            pq_signature_count: PQSignatureCount {
                dilithium_sigs: 0,
                ed25519_sigs: 0,
                hybrid_sigs: 0,
                slh_dsa_sigs: 0,
            },
            signature: ego_core::DualSignature::new(None, None),
        };

        let header = BlockHeader {
            core: header_core,
            qc: ego_core::QuorumCert {
                block_hash: Hash::ZERO,
                height: ego_core::BlockHeight::new(height.saturating_sub(1)),
                view: 0,
                aggregated_signature: None,
                voting_power: 0,
                timestamp: Timestamp::now(),
                pq_compliant: false,
                signatures: Vec::new(),
            },
            metadata: ego_core::BlockMetadata {
                protocol_version: ego_core::PROTOCOL_VERSION,
                block_size: 0,
                cross_shard_receipts: 0,
                rollup_commits: 0,
                poc_events: 0,
                post_events: 0,
                resource_pricing: None,
                pq_transition_data: None,
                cellular_stats: None,
            },
        };

        let body = BlockBody {
            transactions,
            transaction_results: Vec::new(),
            cross_shard_receipts: Vec::new(),
            rollup_commitments: Vec::new(),
            proof_events: Vec::new(),
            drs_events: Vec::new(),
            deploy_events: Vec::new(),
            pq_transition_events: Vec::new(),
        };

        let mut block = Block {
            hash: Hash::ZERO,
            header,
            body,
        };

        block.hash = block.compute_hash();
        block
    }

    #[tokio::test]
    async fn test_transaction_pool_add_transaction() {
        let pool = TransactionPool::new();
        let keypair = create_test_keypair();
        let tx = create_test_transaction(&keypair, 1, ShardId::from_u32(0));

        let result = pool.add_transaction(tx.clone()).await;
        assert!(result.is_ok());

        assert_eq!(pool.get_pending_count(), 1);

        let retrieved = pool.get_transaction(&tx.hash);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().hash, tx.hash);
    }

    #[tokio::test]
    async fn test_transaction_pool_duplicate_transaction() {
        let pool = TransactionPool::new();
        let keypair = create_test_keypair();
        let tx = create_test_transaction(&keypair, 1, ShardId::from_u32(0));

        pool.add_transaction(tx.clone()).await.unwrap();
        let result = pool.add_transaction(tx.clone()).await;

        assert!(result.is_ok());
        assert_eq!(pool.get_pending_count(), 1);
    }

    #[tokio::test]
    async fn test_transaction_pool_remove_transaction() {
        let pool = TransactionPool::new();
        let keypair = create_test_keypair();
        let tx = create_test_transaction(&keypair, 1, ShardId::from_u32(0));

        pool.add_transaction(tx.clone()).await.unwrap();
        assert_eq!(pool.get_pending_count(), 1);

        pool.remove_transaction(&tx.hash).await;
        assert_eq!(pool.get_pending_count(), 0);

        let retrieved = pool.get_transaction(&tx.hash);
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_transaction_pool_priority_ordering() {
        let pool = TransactionPool::new();
        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());

        let low_priority_tx = {
            let payload = TransactionPayload::Transfer {
                to: Address::new([1u8; 20]),
                amount: Balance::from(100u64),
                memo: None,
                stealth_mode: false,
            };
            let mut tx =
                Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
            tx.sign(&keypair, false).unwrap();
            tx
        };

        let high_priority_tx = {
            let payload = TransactionPayload::SystemOperation {
                operation_id: "test".to_string(),
                data: vec![1, 2, 3],
                auth_level: 5,
                epoch_anchor: true,
                requires_quorum: true,
            };
            let mut tx =
                Transaction::new(from, 2, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
            tx.sign(&keypair, false).unwrap();
            tx
        };

        pool.add_transaction(low_priority_tx.clone()).await.unwrap();
        pool.add_transaction(high_priority_tx.clone())
            .await
            .unwrap();

        let transactions = pool.get_transactions_for_block(10).await;
        assert_eq!(transactions.len(), 2);
        assert_eq!(transactions[0].hash, high_priority_tx.hash);
        assert_eq!(transactions[1].hash, low_priority_tx.hash);
    }

    #[tokio::test]
    async fn test_transaction_pool_get_transactions_for_block() {
        let pool = TransactionPool::new();
        let keypair = create_test_keypair();

        for i in 1..=10 {
            let tx = create_test_transaction(&keypair, i, ShardId::from_u32(0));
            pool.add_transaction(tx).await.unwrap();
        }

        let transactions = pool.get_transactions_for_block(5).await;
        assert_eq!(transactions.len(), 5);
        assert_eq!(pool.get_pending_count(), 10);
    }

    #[tokio::test]
    async fn test_transaction_pool_clear() {
        let pool = TransactionPool::new();
        let keypair = create_test_keypair();

        for i in 1..=5 {
            let tx = create_test_transaction(&keypair, i, ShardId::from_u32(0));
            pool.add_transaction(tx).await.unwrap();
        }

        assert_eq!(pool.get_pending_count(), 5);

        pool.clear().await;
        assert_eq!(pool.get_pending_count(), 0);
    }

    #[tokio::test]
    async fn test_transaction_pool_stats_tracking() {
        let pool = TransactionPool::new();
        let keypair = create_test_keypair();
        let tx = create_test_transaction(&keypair, 1, ShardId::from_u32(0));

        pool.add_transaction(tx.clone()).await.unwrap();
        let stats = pool.get_stats().await;
        assert_eq!(stats.pending_count, 1);
        assert_eq!(stats.txs_added, 1);

        pool.remove_transaction(&tx.hash).await;
        let stats = pool.get_stats().await;
        assert_eq!(stats.pending_count, 0);
        assert_eq!(stats.txs_removed, 1);
    }

    #[tokio::test]
    async fn test_cross_shard_manager_creation() {
        let manager = CrossShardManager::new();
        let stats = manager.get_stats().await;

        assert_eq!(stats.receipts_sent, 0);
        assert_eq!(stats.receipts_received, 0);
        assert_eq!(stats.receipts_pending, 0);
    }

    #[tokio::test]
    async fn test_cross_shard_add_outbound_receipt() {
        let manager = CrossShardManager::new();
        let _keypair = create_test_keypair();

        let receipt = CrossShardReceipt {
            src_shard: ShardId::from_u32(0),
            dst_shard: ShardId::from_u32(1),
            src_block_hash: Hash::new([1u8; 32]),
            tx_id: Hash::new([2u8; 32]),
            payload: vec![1, 2, 3, 4],
            nonce: 1,
            deadline_epoch: 100,
            merkle_proof: vec![],
            signature: ego_core::DualSignature::new(None, None),
            timestamp: Timestamp::now(),
        };

        let result = manager.add_outbound_receipt(receipt.clone()).await;
        assert!(result.is_ok());

        let stats = manager.get_stats().await;
        assert_eq!(stats.receipts_sent, 1);
        assert_eq!(stats.receipts_pending, 1);

        let outbound = manager.get_outbound_receipts(&ShardId::from_u32(1)).await;
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].nonce, 1);
    }

    #[tokio::test]
    async fn test_cross_shard_add_inbound_receipt() {
        let manager = CrossShardManager::new();

        let receipt = CrossShardReceipt {
            src_shard: ShardId::from_u32(0),
            dst_shard: ShardId::from_u32(1),
            src_block_hash: Hash::new([1u8; 32]),
            tx_id: Hash::new([2u8; 32]),
            payload: vec![1, 2, 3, 4],
            nonce: 1,
            deadline_epoch: 100,
            merkle_proof: vec![],
            signature: ego_core::DualSignature::new(None, None),
            timestamp: Timestamp::now(),
        };

        let result = manager.add_inbound_receipt(receipt.clone()).await;
        assert!(result.is_ok());

        let stats = manager.get_stats().await;
        assert_eq!(stats.receipts_received, 1);

        let inbound = manager.get_inbound_receipts(&ShardId::from_u32(0)).await;
        assert_eq!(inbound.len(), 1);
    }

    #[tokio::test]
    async fn test_cross_shard_duplicate_nonce_rejection() {
        let manager = CrossShardManager::new();

        let receipt1 = CrossShardReceipt {
            src_shard: ShardId::from_u32(0),
            dst_shard: ShardId::from_u32(1),
            src_block_hash: Hash::new([1u8; 32]),
            tx_id: Hash::new([2u8; 32]),
            payload: vec![1, 2, 3],
            nonce: 1,
            deadline_epoch: 100,
            merkle_proof: vec![],
            signature: ego_core::DualSignature::new(None, None),
            timestamp: Timestamp::now(),
        };

        let receipt2 = CrossShardReceipt {
            src_shard: ShardId::from_u32(0),
            dst_shard: ShardId::from_u32(1),
            src_block_hash: Hash::new([3u8; 32]),
            tx_id: Hash::new([4u8; 32]),
            payload: vec![4, 5, 6],
            nonce: 1,
            deadline_epoch: 100,
            merkle_proof: vec![],
            signature: ego_core::DualSignature::new(None, None),
            timestamp: Timestamp::now(),
        };

        manager.add_inbound_receipt(receipt1).await.unwrap();
        let result = manager.add_inbound_receipt(receipt2).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_cross_shard_acknowledge_receipt() {
        let manager = CrossShardManager::new();
        let receipt_hash = Hash::new([1u8; 32]);

        let result = manager
            .acknowledge_receipt(receipt_hash, ShardId::from_u32(1), true, None)
            .await;

        assert!(result.is_ok());

        let stats = manager.get_stats().await;
        assert_eq!(stats.receipts_pending, 0);
    }

    #[tokio::test]
    async fn test_cross_shard_acknowledge_failed_receipt() {
        let manager = CrossShardManager::new();

        let receipt = CrossShardReceipt {
            src_shard: ShardId::from_u32(0),
            dst_shard: ShardId::from_u32(1),
            src_block_hash: Hash::new([1u8; 32]),
            tx_id: Hash::new([2u8; 32]),
            payload: vec![1, 2, 3],
            nonce: 1,
            deadline_epoch: 100,
            merkle_proof: vec![],
            signature: ego_core::DualSignature::new(None, None),
            timestamp: Timestamp::now(),
        };

        manager.add_outbound_receipt(receipt.clone()).await.unwrap();

        let receipt_hash = Hash::new([3u8; 32]);
        manager
            .acknowledge_receipt(
                receipt_hash,
                ShardId::from_u32(1),
                false,
                Some("Validation failed".to_string()),
            )
            .await
            .unwrap();

        let stats = manager.get_stats().await;
        assert_eq!(stats.failed_receipts, 1);
    }

    #[tokio::test]
    async fn test_cross_shard_update_shard_info() {
        let manager = CrossShardManager::new();

        let shard_info = ShardInfo {
            shard_id: ShardId::from_u32(1),
            block_height: ego_core::BlockHeight::new(1000),
            state_root: Hash::new([1u8; 32]),
            last_finalized_epoch: 10,
            active_validators: vec![Address::new([1u8; 20])],
            status: ShardStatus::Active,
            last_updated: Timestamp::now(),
        };

        manager.update_shard_info(shard_info.clone()).await;

        let retrieved = manager.get_shard_info(&ShardId::from_u32(1)).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().shard_id, ShardId::from_u32(1));
    }

    #[tokio::test]
    async fn test_cross_shard_prune_expired_receipts() {
        let manager = CrossShardManager::new();

        let expired_receipt = CrossShardReceipt {
            src_shard: ShardId::from_u32(0),
            dst_shard: ShardId::from_u32(1),
            src_block_hash: Hash::new([1u8; 32]),
            tx_id: Hash::new([2u8; 32]),
            payload: vec![1, 2, 3],
            nonce: 1,
            deadline_epoch: 50,
            merkle_proof: vec![],
            signature: ego_core::DualSignature::new(None, None),
            timestamp: Timestamp::now(),
        };

        let valid_receipt = CrossShardReceipt {
            src_shard: ShardId::from_u32(0),
            dst_shard: ShardId::from_u32(1),
            src_block_hash: Hash::new([3u8; 32]),
            tx_id: Hash::new([4u8; 32]),
            payload: vec![4, 5, 6],
            nonce: 2,
            deadline_epoch: 150,
            merkle_proof: vec![],
            signature: ego_core::DualSignature::new(None, None),
            timestamp: Timestamp::now(),
        };

        manager.add_outbound_receipt(expired_receipt).await.unwrap();
        manager.add_outbound_receipt(valid_receipt).await.unwrap();

        let pruned = manager.prune_expired_receipts(100).await;
        assert_eq!(pruned, 1);

        let outbound = manager.get_outbound_receipts(&ShardId::from_u32(1)).await;
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].nonce, 2);
    }

    #[tokio::test]
    async fn test_shard_manager_creation() {
        let config = create_test_shard_config(0);
        let manager = ShardManager::new(config.clone(), TEST_CHAIN_ID, TEST_NETWORK_ID);

        assert_eq!(manager.config.shard_id, ShardId::from_u32(0));

        let stats = manager.get_stats().await;
        assert_eq!(stats.shard_id, ShardId::from_u32(0));
        assert_eq!(stats.total_blocks, 0);
        assert_eq!(stats.total_transactions, 0);
    }

    #[tokio::test]
    async fn test_shard_manager_add_transaction() {
        let config = create_test_shard_config(0);
        let manager = ShardManager::new(config, TEST_CHAIN_ID, TEST_NETWORK_ID);

        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let mut account = create_test_account(from, Balance::from(100_000u64));

        account.dilithium_pk = keypair.dilithium_public_key().key_data.clone();
        account.mlkem_pk = keypair.kyber_public_key().key_data.clone();

        {
            let mut state = manager.state.write().await;
            state.set_account(account.clone());
        }

        let tx = create_test_transaction(&keypair, 1, ShardId::from_u32(0));
        let result = manager.add_transaction(tx.clone()).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_shard_manager_reject_invalid_signature() {
        let config = create_test_shard_config(0);
        let manager = ShardManager::new(config, TEST_CHAIN_ID, TEST_NETWORK_ID);

        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());

        let payload = TransactionPayload::Transfer {
            to: Address::new([1u8; 20]),
            amount: Balance::from(100u64),
            memo: None,
            stealth_mode: false,
        };

        let mut tx = Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
        tx.signature = ego_core::DualSignature::new(None, None);

        let result = manager.add_transaction(tx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_shard_manager_reject_wrong_shard() {
        let config = create_test_shard_config(0);
        let manager = ShardManager::new(config, TEST_CHAIN_ID, TEST_NETWORK_ID);

        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let account = create_test_account(from, Balance::from(100_000u64));

        {
            let mut state = manager.state.write().await;
            state.set_account(account);
        }

        let tx = create_test_transaction(&keypair, 1, ShardId::from_u32(1));
        let result = manager.add_transaction(tx).await;

        assert!(result.is_err());
    }

    async fn test_shard_manager_get_transactions_for_block() {
        let config = create_test_shard_config(0);
        let manager = ShardManager::new(config, TEST_CHAIN_ID, TEST_NETWORK_ID);

        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let mut account = create_test_account(from, Balance::from(1_000_000u64));

        account.dilithium_pk = keypair.dilithium_public_key().key_data.clone();
        account.mlkem_pk = keypair.kyber_public_key().key_data.clone();

        {
            let mut state = manager.state.write().await;
            state.set_account(account.clone());
        }

        for i in 1..=10 {
            account.nonce = i - 1;
            {
                let mut state = manager.state.write().await;
                state.set_account(account.clone());
            }

            let tx = create_test_transaction(&keypair, i, ShardId::from_u32(0));
            manager.add_transaction(tx).await.unwrap();
        }

        let transactions = manager.get_transactions_for_block(5).await;
        assert_eq!(transactions.len(), 5);

        let block1 = Block {
            hash: Hash::ZERO,
            header: ego_core::BlockHeader {
                core: ego_core::BlockHeaderCore {
                    height: ego_core::BlockHeight::new(1),
                    timestamp: Timestamp::now(),
                    previous_hash: Hash::ZERO,
                    state_root: Hash::ZERO,
                    transactions_root: Hash::ZERO,
                    receipts_root: Hash::ZERO,
                    events_root: Hash::ZERO,
                    da_root: Hash::ZERO,
                    shard_id: ShardId::from_u32(0),
                    proposer: from,
                    tx_count: transactions.len() as u32,
                    protocol_version: ego_core::PROTOCOL_VERSION,
                    epoch: ego_core::EpochNumber(0),
                    compute_used: 0,
                    storage_used: 0,
                    pq_signature_count: PQSignatureCount {
                        dilithium_sigs: 0,
                        ed25519_sigs: 0,
                        hybrid_sigs: 0,
                        slh_dsa_sigs: 0,
                    },
                    signature: ego_core::DualSignature::new(None, None),
                },
                qc: ego_core::QuorumCert {
                    block_hash: Hash::ZERO,
                    height: ego_core::BlockHeight::new(0),
                    view: 0,
                    aggregated_signature: None,
                    voting_power: 0,
                    timestamp: Timestamp::now(),
                    pq_compliant: false,
                    signatures: Vec::new(),
                },
                metadata: ego_core::BlockMetadata {
                    protocol_version: ego_core::PROTOCOL_VERSION,
                    block_size: 0,
                    cross_shard_receipts: 0,
                    rollup_commits: 0,
                    poc_events: 0,
                    post_events: 0,
                    resource_pricing: None,
                    pq_transition_data: None,
                    cellular_stats: None,
                },
            },
            body: ego_core::BlockBody {
                transactions,
                transaction_results: Vec::new(),
                cross_shard_receipts: Vec::new(),
                rollup_commitments: Vec::new(),
                proof_events: Vec::new(),
                drs_events: Vec::new(),
                deploy_events: Vec::new(),
                pq_transition_events: Vec::new(),
            },
        };

        manager.process_block(block1).await.unwrap();

        let stats = manager.get_stats().await;
        assert_eq!(stats.total_blocks, 1);
        assert_eq!(stats.total_transactions, 5);
        assert!(stats.pool_stats.pending_count <= 5);

        let transactions2 = manager.get_transactions_for_block(5).await;
        assert_eq!(transactions2.len(), 5);

        let block2 = Block {
            hash: Hash::ZERO,
            header: ego_core::BlockHeader {
                core: ego_core::BlockHeaderCore {
                    height: ego_core::BlockHeight::new(2),
                    timestamp: Timestamp::now(),
                    previous_hash: Hash::ZERO,
                    state_root: Hash::ZERO,
                    transactions_root: Hash::ZERO,
                    receipts_root: Hash::ZERO,
                    events_root: Hash::ZERO,
                    da_root: Hash::ZERO,
                    shard_id: ShardId::from_u32(0),
                    proposer: from,
                    tx_count: transactions2.len() as u32,
                    protocol_version: ego_core::PROTOCOL_VERSION,
                    epoch: ego_core::EpochNumber(0),
                    compute_used: 0,
                    storage_used: 0,
                    pq_signature_count: PQSignatureCount {
                        dilithium_sigs: 0,
                        ed25519_sigs: 0,
                        hybrid_sigs: 0,
                        slh_dsa_sigs: 0,
                    },
                    signature: ego_core::DualSignature::new(None, None),
                },
                qc: ego_core::QuorumCert {
                    block_hash: Hash::ZERO,
                    height: ego_core::BlockHeight::new(1),
                    view: 0,
                    aggregated_signature: None,
                    voting_power: 0,
                    timestamp: Timestamp::now(),
                    pq_compliant: false,
                    signatures: Vec::new(),
                },
                metadata: ego_core::BlockMetadata {
                    protocol_version: ego_core::PROTOCOL_VERSION,
                    block_size: 0,
                    cross_shard_receipts: 0,
                    rollup_commits: 0,
                    poc_events: 0,
                    post_events: 0,
                    resource_pricing: None,
                    pq_transition_data: None,
                    cellular_stats: None,
                },
            },
            body: ego_core::BlockBody {
                transactions: transactions2,
                transaction_results: Vec::new(),
                cross_shard_receipts: Vec::new(),
                rollup_commitments: Vec::new(),
                proof_events: Vec::new(),
                drs_events: Vec::new(),
                deploy_events: Vec::new(),
                pq_transition_events: Vec::new(),
            },
        };
        manager.process_block(block2).await.unwrap();

        let final_stats = manager.get_stats().await;
        assert_eq!(final_stats.total_blocks, 2);
        assert_eq!(final_stats.total_transactions, 10);
        assert_eq!(final_stats.pool_stats.pending_count, 0);

        let block_at_1 = manager
            .get_block_by_height(ego_core::BlockHeight::new(1))
            .await;
        assert!(block_at_1.is_some());

        let block_at_2 = manager
            .get_block_by_height(ego_core::BlockHeight::new(2))
            .await;
        assert!(block_at_2.is_some());

        let recent = manager.get_recent_blocks(2).await;
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].header.core.height.as_u64(), 2);
        assert_eq!(recent[1].header.core.height.as_u64(), 1);
    }

    #[tokio::test]
    async fn test_multi_shard_cross_communication() {
        let config0 = create_test_shard_config(0);
        let config1 = create_test_shard_config(1);

        let manager0 = Arc::new(ShardManager::new(config0, TEST_CHAIN_ID, TEST_NETWORK_ID));
        let manager1 = Arc::new(ShardManager::new(config1, TEST_CHAIN_ID, TEST_NETWORK_ID));

        let keypair = KeyPair::generate();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let account = Account {
            address: from,
            balance: Balance::from(1_000_000u64),
            nonce: 0,
            storage_used: 0,
            storage_quota: 100_000_000,
            storage_credits: 100_000,
            deploy_credits: 100,
            free_deploys_remaining: 5,
            account_type: AccountType::EOA,
            dilithium_pk: keypair.dilithium_public_key().key_data.clone(),
            mlkem_pk: keypair.kyber_public_key().key_data.clone(),
            ed25519_pk: None,
            x25519_pk: None,
            slh_dsa_pk: None,
            authorized_slices: vec![],
            metadata: HashMap::new(),
            device_capabilities: None,
            peer_id: None,
            pq_transition_info: Some(ego_core::account::PQTransitionInfo {
                transition_started_epoch: 0,
                pq_only_mode: false,
                ed25519_disabled_epoch: None,
                supported_algorithms: vec![
                    ego_core::AlgorithmId::MlDsa2.as_u16(),
                    ego_core::AlgorithmId::MlKem768.as_u16(),
                ],
            }),
            per_shard_nonces: Some(HashMap::new()),
            deploy_bond_locked_until: None,
            staking_info: None,
            validator_info: None,
            tmp_attestation: None,
            contract_info: None,
            last_drs_epoch: None,
            last_drs_score: None,
            last_activity: Timestamp::now(),
            created_at: Timestamp::now(),
            hot_set_mode: ego_core::account::HotSetMode::LightClient,
            pruning_config: None,
            archival_config: None,
            storage_provider_info: None,
        };

        {
            let mut state0 = manager0.state.write().await;
            state0.set_account(account.clone());
            let mut state1 = manager1.state.write().await;
            state1.set_account(account);
        }

        let payload = TransactionPayload::CrossShard {
            target_shard: ShardId::from_u32(1),
            message: b"Hello from shard 0".to_vec(),
            response_hash: None,
            deadline_epoch: 1000,
            nonce: 1,
        };

        let mut tx = Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
        tx.sign(&keypair, false).unwrap();

        manager0.add_transaction(tx.clone()).await.unwrap();

        let transactions = manager0.get_transactions_for_block(10).await;
        assert_eq!(transactions.len(), 1);

        let block = create_test_block(1, ShardId::from_u32(0), transactions);

        manager0.process_block(block).await.unwrap();

        let stats0 = manager0.get_stats().await;
        assert!(
            stats0.cross_shard_stats.receipts_sent > 0
                || stats0.cross_shard_stats.receipts_pending > 0
        );
    }

    #[tokio::test]
    async fn test_proof_transaction_processing() {
        let config = create_test_shard_config(0);
        let manager = Arc::new(ShardManager::new(config, TEST_CHAIN_ID, TEST_NETWORK_ID));

        let keypair = KeyPair::generate();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let account = Account {
            address: from,
            balance: Balance::from(1_000_000u64),
            nonce: 0,
            storage_used: 0,
            storage_quota: 100_000_000,
            storage_credits: 100_000,
            deploy_credits: 100,
            free_deploys_remaining: 5,
            account_type: AccountType::StorageProvider {
                provider_id: Address::new([10u8; 20]).to_string(),
                region: "us-west".to_string(),
            },
            dilithium_pk: keypair.dilithium_public_key().key_data.clone(),
            mlkem_pk: keypair.kyber_public_key().key_data.clone(),
            ed25519_pk: None,
            x25519_pk: None,
            slh_dsa_pk: None,
            authorized_slices: vec![],
            metadata: HashMap::new(),
            device_capabilities: None,
            peer_id: None,
            pq_transition_info: Some(ego_core::account::PQTransitionInfo {
                transition_started_epoch: 0,
                pq_only_mode: false,
                ed25519_disabled_epoch: None,
                supported_algorithms: vec![
                    ego_core::AlgorithmId::MlDsa2.as_u16(),
                    ego_core::AlgorithmId::MlKem768.as_u16(),
                ],
            }),
            per_shard_nonces: Some(HashMap::new()),
            deploy_bond_locked_until: None,
            staking_info: None,
            validator_info: None,
            tmp_attestation: None,
            contract_info: None,
            last_drs_epoch: None,
            last_drs_score: None,
            last_activity: Timestamp::now(),
            created_at: Timestamp::now(),
            hot_set_mode: ego_core::account::HotSetMode::LightClient,
            pruning_config: None,
            archival_config: None,
            storage_provider_info: Some(ego_core::account::StorageProviderInfo {
                node_id: Address::new([10u8; 20]),
                storage_capacity: 1000 * 1024 * 1024 * 1024,
                storage_allocated: 100 * 1024 * 1024 * 1024,
                active_sectors: vec![],
                collateral_locked: Balance::from(10000u64),
                last_audit_epoch: 10,
                postrep_stats: ego_core::account::PostRepStats {
                    porep_proofs_submitted: 0,
                    post_proofs_submitted: 100,
                    post_pass_rate: 99.0,
                    avg_post_latency_ms: 50,
                    challenges_answered: 99,
                    challenges_missed: 1,
                    last_challenge_epoch: 10,
                    consecutive_misses: 0,
                    sectors_sealed: 0,
                    sectors_faulty: 0,
                    repairs_completed: 0,
                    promotions: 0,
                },
                earnings: ego_core::account::ProviderEarnings {
                    storage_rewards: Balance::from(50000u64),
                    retrieval_fees: Balance::from(0u64),
                    post_rewards: Balance::from(0u64),
                    total_earned: Balance::from(50000u64),
                    total_slashed: Balance::from(0u64),
                    pending_payouts: Balance::from(1000u64),
                },
                slashing_history: Vec::new(),
                health_score: 99,
            }),
        };

        {
            let mut state = manager.state.write().await;
            state.set_account(account);
        }

        let payload = TransactionPayload::SubmitProofBatch {
            proof_type: ProofType::PoSt,
            proofs: vec![
                ProofSubmission {
                    chunk_id: Hash::new([1u8; 32]),
                    proof_data: vec![1, 2, 3, 4],
                    challenge_hash: Hash::new([5u8; 32]),
                    latency_ms: 150,
                    node_signature: vec![6, 7, 8],
                },
                ProofSubmission {
                    chunk_id: Hash::new([2u8; 32]),
                    proof_data: vec![9, 10, 11, 12],
                    challenge_hash: Hash::new([13u8; 32]),
                    latency_ms: 200,
                    node_signature: vec![14, 15, 16],
                },
            ],
            batch_merkle_root: Hash::new([17u8; 32]),
            epoch: 10,
            rollup_id: None,
        };

        let mut tx = Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
        tx.sign(&keypair, false).unwrap();

        let result = manager.add_transaction(tx).await;
        assert!(result.is_ok());

        let stats = manager.get_stats().await;
        assert_eq!(stats.pool_stats.pending_count, 1);
    }

    #[tokio::test]
    async fn test_storage_transaction_lifecycle() {
        let config = create_test_shard_config(0);
        let manager = Arc::new(ShardManager::new(config, TEST_CHAIN_ID, TEST_NETWORK_ID));

        let keypair = KeyPair::generate();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let mut account = Account {
            address: from,
            balance: Balance::from(1_000_000u64),
            nonce: 0,
            storage_used: 0,
            storage_quota: 100_000_000,
            storage_credits: 100_000,
            deploy_credits: 100,
            free_deploys_remaining: 5,
            account_type: AccountType::EOA,
            dilithium_pk: keypair.dilithium_public_key().key_data.clone(),
            mlkem_pk: keypair.kyber_public_key().key_data.clone(),
            ed25519_pk: None,
            x25519_pk: None,
            slh_dsa_pk: None,
            authorized_slices: vec![],
            metadata: HashMap::new(),
            device_capabilities: None,
            peer_id: None,
            pq_transition_info: Some(ego_core::account::PQTransitionInfo {
                transition_started_epoch: 0,
                pq_only_mode: false,
                ed25519_disabled_epoch: None,
                supported_algorithms: vec![
                    ego_core::AlgorithmId::MlDsa2.as_u16(),
                    ego_core::AlgorithmId::MlKem768.as_u16(),
                ],
            }),
            per_shard_nonces: Some(HashMap::new()),
            deploy_bond_locked_until: None,
            staking_info: None,
            validator_info: None,
            tmp_attestation: None,
            contract_info: None,
            last_drs_epoch: None,
            last_drs_score: None,
            last_activity: Timestamp::now(),
            created_at: Timestamp::now(),
            hot_set_mode: ego_core::account::HotSetMode::LightClient,
            pruning_config: None,
            archival_config: None,
            storage_provider_info: None,
        };

        {
            let mut state = manager.state.write().await;
            state.set_account(account.clone());
        }

        let buy_credits_payload = TransactionPayload::BuyStorageCredits {
            amount: Balance::from(10_000u64),
            credits_byte_months: 1_000_000,
            burn_proof: Hash::new([1u8; 32]),
        };

        let mut tx1 = Transaction::new(
            from,
            1,
            buy_credits_payload,
            ShardId::from_u32(0),
            None,
            TEST_CHAIN_ID,
        );
        tx1.sign(&keypair, false).unwrap();

        manager.add_transaction(tx1).await.unwrap();

        account.nonce = 1;
        {
            let mut state = manager.state.write().await;
            state.set_account(account.clone());
        }

        let triad = TriadPlacement {
            primary: NodeLocation {
                node_id: Address::new([10u8; 20]),
                h3_cell: "8928308280fffff".to_string(),
                shard_id: 0,
                region: "us-west".to_string(),
                lat_lon: Some((37.7749, -122.4194)),
            },
            replica_a: NodeLocation {
                node_id: Address::new([11u8; 20]),
                h3_cell: "8928308280aaaaa".to_string(),
                shard_id: 0,
                region: "us-east".to_string(),
                lat_lon: Some((40.7128, -74.0060)),
            },
            replica_b: NodeLocation {
                node_id: Address::new([12u8; 20]),
                h3_cell: "8928308280bbbbb".to_string(),
                shard_id: 0,
                region: "eu-west".to_string(),
                lat_lon: Some((51.5074, -0.1278)),
            },
            group_id: "test-group".to_string(),
            placement_epoch: 100,
            diversity_score: 0.9,
        };

        let store_data_payload = TransactionPayload::StoreData {
            chunk_id: Hash::new([2u8; 32]),
            data_size: 1024 * 1024,
            duration_epochs: 100,
            data_hash: Hash::new([3u8; 32]),
            slice_id: ego_core::SliceId::new("test".to_string()),
            storage_credits: 1000,
            replication_factor: 3,
            triad_placement: triad,
            erasure_coding: ErasureCodingParams {
                k: 10,
                m: 4,
                codec: ErasureCodec::ReedSolomon,
            },
            encryption_envelope: None,
        };

        let mut tx2 = Transaction::new(
            from,
            2,
            store_data_payload,
            ShardId::from_u32(0),
            None,
            TEST_CHAIN_ID,
        );
        tx2.sign(&keypair, false).unwrap();

        manager.add_transaction(tx2).await.unwrap();

        let stats = manager.get_stats().await;
        assert_eq!(stats.pool_stats.pending_count, 2);
    }

    #[tokio::test]
    async fn test_concurrent_transaction_processing() {
        let config = create_test_shard_config(0);
        let manager = Arc::new(ShardManager::new(config, TEST_CHAIN_ID, TEST_NETWORK_ID));

        let mut handles = vec![];

        for i in 0..10 {
            let manager_clone = Arc::clone(&manager);
            let handle = tokio::spawn(async move {
                let keypair = KeyPair::generate();
                let from = Address::from_public_key(&keypair.dilithium_public_key());
                let account = Account {
                    address: from,
                    balance: Balance::from(1_000_000u64),
                    nonce: 0,
                    storage_used: 0,
                    storage_quota: 100_000_000,
                    storage_credits: 100_000,
                    deploy_credits: 100,
                    free_deploys_remaining: 5,
                    account_type: AccountType::EOA,
                    dilithium_pk: keypair.dilithium_public_key().key_data.clone(),
                    mlkem_pk: keypair.kyber_public_key().key_data.clone(),
                    ed25519_pk: None,
                    x25519_pk: None,
                    slh_dsa_pk: None,
                    authorized_slices: vec![],
                    metadata: HashMap::new(),
                    device_capabilities: None,
                    peer_id: None,
                    pq_transition_info: Some(ego_core::account::PQTransitionInfo {
                        transition_started_epoch: 0,
                        pq_only_mode: false,
                        ed25519_disabled_epoch: None,
                        supported_algorithms: vec![
                            ego_core::AlgorithmId::MlDsa2.as_u16(),
                            ego_core::AlgorithmId::MlKem768.as_u16(),
                        ],
                    }),
                    per_shard_nonces: Some(HashMap::new()),
                    deploy_bond_locked_until: None,
                    staking_info: None,
                    validator_info: None,
                    tmp_attestation: None,
                    contract_info: None,
                    last_drs_epoch: None,
                    last_drs_score: None,
                    last_activity: Timestamp::now(),
                    created_at: Timestamp::now(),
                    hot_set_mode: ego_core::account::HotSetMode::LightClient,
                    pruning_config: None,
                    archival_config: None,
                    storage_provider_info: None,
                };

                {
                    let mut state = manager_clone.state.write().await;
                    state.set_account(account);
                }

                let payload = TransactionPayload::Transfer {
                    to: Address::new([i as u8; 20]),
                    amount: Balance::from(100u64),
                    memo: None,
                    stealth_mode: false,
                };

                let mut tx =
                    Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
                tx.sign(&keypair, false).unwrap();

                manager_clone.add_transaction(tx).await
            });

            handles.push(handle);
        }

        let results: Vec<_> = futures::future::join_all(handles).await;
        let successful = results
            .iter()
            .filter(|r| r.is_ok() && r.as_ref().unwrap().is_ok())
            .count();

        assert!(successful > 0);
    }

    #[tokio::test]
    async fn test_shard_manager_process_block() {
        let config = create_test_shard_config(0);
        let manager = ShardManager::new(config, TEST_CHAIN_ID, TEST_NETWORK_ID);

        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let mut account = create_test_account(from, Balance::from(100_000u64));
        account.dilithium_pk = keypair.dilithium_public_key().key_data.clone();
        account.mlkem_pk = keypair.kyber_public_key().key_data.clone();

        {
            let mut state = manager.state.write().await;
            state.set_account(account);
        }

        let tx = create_test_transaction(&keypair, 1, ShardId::from_u32(0));
        let block = create_test_block(1, ShardId::from_u32(0), vec![tx.clone()]);

        let result = manager.process_block(block).await;
        assert!(result.is_ok());

        let stats = manager.get_stats().await;
        assert_eq!(stats.total_blocks, 1);
        assert_eq!(stats.total_transactions, 1);
    }

    #[tokio::test]
    async fn test_shard_manager_process_multiple_blocks() {
        let config = create_test_shard_config(0);
        let manager = ShardManager::new(config, TEST_CHAIN_ID, TEST_NETWORK_ID);

        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let mut account = create_test_account(from, Balance::from(1_000_000u64));
        account.dilithium_pk = keypair.dilithium_public_key().key_data.clone();
        account.mlkem_pk = keypair.kyber_public_key().key_data.clone();

        {
            let mut state = manager.state.write().await;
            state.set_account(account.clone());
        }

        for height in 1..=5 {
            account.nonce = height - 1;
            {
                let mut state = manager.state.write().await;
                state.set_account(account.clone());
            }

            let tx = create_test_transaction(&keypair, height, ShardId::from_u32(0));
            let block = create_test_block(height, ShardId::from_u32(0), vec![tx]);

            manager.process_block(block).await.unwrap();
        }

        let stats = manager.get_stats().await;
        assert_eq!(stats.total_blocks, 5);
        assert_eq!(stats.total_transactions, 5);
    }

    #[tokio::test]
    async fn test_shard_manager_get_recent_blocks() {
        let config = create_test_shard_config(0);
        let manager = ShardManager::new(config, TEST_CHAIN_ID, TEST_NETWORK_ID);

        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let mut account = create_test_account(from, Balance::from(1_000_000u64));
        account.dilithium_pk = keypair.dilithium_public_key().key_data.clone();
        account.mlkem_pk = keypair.kyber_public_key().key_data.clone();

        {
            let mut state = manager.state.write().await;
            state.set_account(account.clone());
        }

        for height in 1..=5 {
            account.nonce = height - 1;
            {
                let mut state = manager.state.write().await;
                state.set_account(account.clone());
            }

            let tx = create_test_transaction(&keypair, height, ShardId::from_u32(0));
            let block = create_test_block(height, ShardId::from_u32(0), vec![tx]);
            manager.process_block(block).await.unwrap();
        }

        let recent_blocks = manager.get_recent_blocks(3).await;
        assert_eq!(recent_blocks.len(), 3);
        assert_eq!(recent_blocks[0].header.core.height.as_u64(), 5);
        assert_eq!(recent_blocks[1].header.core.height.as_u64(), 4);
        assert_eq!(recent_blocks[2].header.core.height.as_u64(), 3);
    }

    #[tokio::test]
    async fn test_shard_manager_get_block_by_height() {
        let config = create_test_shard_config(0);
        let manager = ShardManager::new(config, TEST_CHAIN_ID, TEST_NETWORK_ID);

        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let mut account = create_test_account(from, Balance::from(100_000u64));
        account.dilithium_pk = keypair.dilithium_public_key().key_data.clone();
        account.mlkem_pk = keypair.kyber_public_key().key_data.clone();

        {
            let mut state = manager.state.write().await;
            state.set_account(account);
        }

        let tx = create_test_transaction(&keypair, 1, ShardId::from_u32(0));
        let block = create_test_block(1, ShardId::from_u32(0), vec![tx]);
        manager.process_block(block).await.unwrap();

        let retrieved = manager
            .get_block_by_height(ego_core::BlockHeight::new(1))
            .await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().header.core.height.as_u64(), 1);
    }

    #[tokio::test]
    async fn test_shard_manager_current_epoch() {
        let config = create_test_shard_config(0);
        let manager = ShardManager::new(config, TEST_CHAIN_ID, TEST_NETWORK_ID);

        let epoch = manager.get_current_epoch().await;
        assert_eq!(epoch.epoch_number, 0);
        assert_eq!(epoch.start_block, ego_core::BlockHeight::GENESIS);
    }

    #[tokio::test]
    async fn test_shard_manager_epoch_transition() {
        let mut config = create_test_shard_config(0);
        config.epoch_duration_blocks = 5;
        let manager = ShardManager::new(config, TEST_CHAIN_ID, TEST_NETWORK_ID);

        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let mut account = create_test_account(from, Balance::from(1_000_000u64));
        account.dilithium_pk = keypair.dilithium_public_key().key_data.clone();
        account.mlkem_pk = keypair.kyber_public_key().key_data.clone();

        {
            let mut state = manager.state.write().await;
            state.set_account(account.clone());
        }

        for height in 1..=6 {
            account.nonce = height - 1;
            {
                let mut state = manager.state.write().await;
                state.set_account(account.clone());
            }

            let tx = create_test_transaction(&keypair, height, ShardId::from_u32(0));
            let block = create_test_block(height, ShardId::from_u32(0), vec![tx]);
            manager.process_block(block).await.unwrap();
        }

        let epoch = manager.get_current_epoch().await;
        assert_eq!(epoch.epoch_number, 1);
    }

    #[tokio::test]
    async fn test_shard_manager_metrics_update() {
        let config = create_test_shard_config(0);
        let manager = ShardManager::new(config, TEST_CHAIN_ID, TEST_NETWORK_ID);

        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let mut account = create_test_account(from, Balance::from(100_000u64));
        account.dilithium_pk = keypair.dilithium_public_key().key_data.clone();
        account.mlkem_pk = keypair.kyber_public_key().key_data.clone();

        {
            let mut state = manager.state.write().await;
            state.set_account(account);
        }

        let tx = create_test_transaction(&keypair, 1, ShardId::from_u32(0));
        let block = create_test_block(1, ShardId::from_u32(0), vec![tx]);
        manager.process_block(block).await.unwrap();

        let stats = manager.get_stats().await;
        assert!(stats.metrics.tps > 0.0);
        assert!(stats.metrics.bps > 0.0);
    }

    #[test]
    fn test_shard_config_default() {
        let config = ShardConfig::default();

        assert_eq!(config.shard_id, ShardId::from_u32(0));
        assert_eq!(config.committee_size, 21);
        assert_eq!(config.replication_factor, 3);
        assert_eq!(config.max_txs_per_block, MAX_TXS_PER_BLOCK as u32);
        assert_eq!(config.target_block_time_ms, TARGET_BLOCK_TIME_MS);
        assert!(config.cross_shard_enabled);
    }

    #[test]
    fn test_storage_config_default() {
        let config = ShardStorageConfig::default();

        assert_eq!(config.max_storage_per_node, 100 * 1024 * 1024 * 1024);
        assert_eq!(config.proof_frequency, 100);
        assert_eq!(config.retention_period, 100_000);
    }

    #[test]
    fn test_erasure_coding_config_default() {
        let config = ErasureCodingConfig::default();

        assert_eq!(config.data_chunks, 64);
        assert_eq!(config.parity_chunks, 32);
        assert_eq!(config.chunk_size, 1024 * 1024);
        assert_eq!(config.codec, "ReedSolomon");
    }

    #[test]
    fn test_pob_config_default() {
        let config = PoBConfig::default();

        assert!(config.enabled);
        assert_eq!(config.storage_credit_price, 100);
        assert_eq!(config.deploy_credit_price, 1000);
        assert!(!config.floors_enabled);
    }

    #[test]
    fn test_drs_config_default() {
        let config = DRSConfig::default();

        assert_eq!(config.weight_uptime, 0.20);
        assert_eq!(config.weight_post_pass, 0.40);
        assert_eq!(config.weight_inv_latency, 0.10);
        assert_eq!(config.weight_poc, 0.20);
        assert_eq!(config.weight_serve, 0.10);

        let total_weight = config.weight_uptime
            + config.weight_post_pass
            + config.weight_inv_latency
            + config.weight_poc
            + config.weight_serve;
        assert!((total_weight - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_cellular_safe_config_default() {
        let config = CellularSafeConfig::default();

        assert!(config.enabled);
        assert_eq!(config.max_monthly_data_gb, 50);
        assert_eq!(config.throttle_threshold_gb, 5);
        assert_eq!(config.proof_rate_hz, 0.5);
        assert_eq!(config.proof_batch_size, 100);
        assert!(config
            .wifi_only_operations
            .contains(&"heavy_compute".to_string()));
    }

    #[test]
    fn test_pq_transition_config_default() {
        let config = PQTransitionConfig::default();

        assert_eq!(config.transition_epoch, 0);
        assert_eq!(config.migration_period_epochs, 1000);
        assert!(!config.pq_only_required);
        assert!(config
            .supported_algorithms
            .contains(&AlgorithmId::MlDsa2.as_u16()));
        assert!(config
            .supported_algorithms
            .contains(&AlgorithmId::MlKem768.as_u16()));
    }

    #[test]
    fn test_post_params_default() {
        let params = PoStParams::default();

        assert_eq!(params.windows_per_day, 48);
        assert_eq!(params.challenges_per_sector, 24);
        assert_eq!(params.sla_ms, 600_000);
        assert_eq!(params.sectors_per_partition, 2349);
        assert!(params.enable_aggregation);
    }

    #[test]
    fn test_porep_params_default() {
        let params = PoRepParams::default();

        assert_eq!(params.sector_size, 32 * 1024 * 1024 * 1024);
        assert_eq!(params.layers, 11);
        assert_eq!(params.base_degree, 6);
        assert_eq!(params.tree_arity, 8);
        assert_eq!(params.params_version, 1);
    }

    #[test]
    fn test_gc_config_default() {
        let config = GarbageCollectionConfig::default();

        assert_eq!(config.frequency, 1000);
        assert_eq!(config.threshold, 0.8);
        assert!(!config.aggressive_mode);
        assert!(config.prune_old_bodies);
        assert!(config.prune_old_receipts);
        assert!(config.prune_old_events);
    }

    #[tokio::test]
    async fn test_full_block_lifecycle() {
        let config = create_test_shard_config(0);
        let manager = ShardManager::new(config, TEST_CHAIN_ID, TEST_NETWORK_ID);

        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let mut account = create_test_account(from, Balance::from(1_000_000u64));
        account.dilithium_pk = keypair.dilithium_public_key().key_data.clone();
        account.mlkem_pk = keypair.kyber_public_key().key_data.clone();

        {
            let mut state = manager.state.write().await;
            state.set_account(account.clone());
        }

        for i in 1..=3 {
            account.nonce = i - 1;
            {
                let mut state = manager.state.write().await;
                state.set_account(account.clone());
            }

            let tx = create_test_transaction(&keypair, i, ShardId::from_u32(0));
            manager.add_transaction(tx).await.unwrap();
        }

        let transactions = manager.get_transactions_for_block(10).await;
        assert_eq!(transactions.len(), 3);

        let block = create_test_block(1, ShardId::from_u32(0), transactions);
        manager.process_block(block).await.unwrap();

        let stats = manager.get_stats().await;
        assert_eq!(stats.total_blocks, 1);
        assert_eq!(stats.total_transactions, 3);
        assert_eq!(stats.pool_stats.pending_count, 0);
    }

    #[tokio::test]
    async fn test_cross_shard_transaction_flow() {
        let config = create_test_shard_config(0);
        let manager = ShardManager::new(config, TEST_CHAIN_ID, TEST_NETWORK_ID);

        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let mut account = create_test_account(from, Balance::from(100_000u64));
        account.dilithium_pk = keypair.dilithium_public_key().key_data.clone();
        account.mlkem_pk = keypair.kyber_public_key().key_data.clone();

        {
            let mut state = manager.state.write().await;
            state.set_account(account);
        }

        let payload = TransactionPayload::CrossShard {
            target_shard: ShardId::from_u32(1),
            message: vec![1, 2, 3, 4, 5],
            response_hash: Some(Hash::new([90u8; 32])),
            deadline_epoch: 200,
            nonce: 123,
        };

        let mut tx = Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
        tx.sign(&keypair, false).unwrap();

        let block = create_test_block(1, ShardId::from_u32(0), vec![tx]);
        manager.process_block(block).await.unwrap();

        let stats = manager.get_stats().await;
        assert!(
            stats.cross_shard_stats.receipts_sent > 0
                || stats.cross_shard_stats.receipts_pending > 0
        );
    }

    #[tokio::test]
    async fn test_priority_transaction_processing() {
        let config = create_test_shard_config(0);
        let manager = ShardManager::new(config, TEST_CHAIN_ID, TEST_NETWORK_ID);

        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let mut account = create_test_account(from, Balance::from(1_000_000u64));
        account.dilithium_pk = keypair.dilithium_public_key().key_data.clone();
        account.mlkem_pk = keypair.kyber_public_key().key_data.clone();
        account.account_type = AccountType::Validator {
            validator_pubkey: keypair.dilithium_public_key(),
            commission_rate: 10,
            is_active: true,
        };

        {
            let mut state = manager.state.write().await;
            state.set_account(account.clone());
        }

        let low_priority = TransactionPayload::Transfer {
            to: Address::new([1u8; 20]),
            amount: Balance::from(100u64),
            memo: None,
            stealth_mode: false,
        };

        let high_priority = TransactionPayload::PoStResponse {
            challenge_hash: Hash::new([50u8; 32]),
            proofs: vec![],
            batch_merkle_root: Hash::new([70u8; 32]),
            latency_ms: vec![150],
        };

        let mut tx1 = Transaction::new(
            from,
            1,
            low_priority,
            ShardId::from_u32(0),
            None,
            TEST_CHAIN_ID,
        );
        tx1.sign(&keypair, false).unwrap();

        let mut tx2 = Transaction::new(
            from,
            2,
            high_priority,
            ShardId::from_u32(0),
            None,
            TEST_CHAIN_ID,
        );
        tx2.sign(&keypair, false).unwrap();

        manager.add_transaction(tx1.clone()).await.unwrap();

        account.nonce = 1;
        {
            let mut state = manager.state.write().await;
            state.set_account(account.clone());
        }

        manager.add_transaction(tx2.clone()).await.unwrap();

        let transactions = manager.get_transactions_for_block(10).await;
        assert_eq!(transactions.len(), 2);
        assert_eq!(transactions[0].hash, tx2.hash);
        assert_eq!(transactions[1].hash, tx1.hash);
    }

    #[tokio::test]
    async fn test_epoch_reward_calculation() {
        let config = create_test_shard_config(0);
        let manager = ShardManager::new(config, TEST_CHAIN_ID, TEST_NETWORK_ID);

        let epoch = manager.get_current_epoch().await;
        assert!(epoch.total_rewards.as_u128() > 0);

        let buckets = &epoch.reward_buckets;
        let total = buckets.storage_rewards.as_u128()
            + buckets.consensus_rewards.as_u128()
            + buckets.coverage_rewards.as_u128()
            + buckets.retrieval_rewards.as_u128()
            + buckets.dao_treasury.as_u128();

        assert_eq!(total, epoch.total_rewards.as_u128());
    }

    #[tokio::test]
    async fn test_shard_manager_cellular_safe_validation() {
        let mut config = create_test_shard_config(0);
        config.cellular_safe_config.enabled = true;
        config.cellular_safe_config.max_monthly_data_gb = 10;

        let manager = ShardManager::new(config, TEST_CHAIN_ID, TEST_NETWORK_ID);

        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let mut account = create_test_account(from, Balance::from(100_000u64));
        account.device_capabilities = Some(ego_core::account::DeviceCapabilities {
            bandwidth_capacity: 100,
            storage_capacity: 64 * 1024 * 1024 * 1024,
            supported_slices: Vec::new(),
            coverage_area: None,
            hardware_specs: HashMap::new(),
            cellular_safe: true,
            last_poc: None,
            post_stats: ego_core::account::PostStats::default(),
            max_bandwidth_cellular: 10,
            monthly_data_limit_gb: 50,
            cost_awareness: ego_core::account::CostAwareness {
                cellular_safe_mode: true,
                max_monthly_cost_usd: 50.0,
                current_month_usage_gb: 15,
                wifi_only_operations: vec!["large_storage".to_string()],
                cellular_throttle_threshold_gb: 5,
            },
        });

        let triad = TriadPlacement {
            primary: NodeLocation {
                node_id: Address::new([10u8; 20]),
                h3_cell: "8928308280fffff".to_string(),
                shard_id: 0,
                region: "us-west".to_string(),
                lat_lon: Some((37.7749, -122.4194)),
            },
            replica_a: NodeLocation {
                node_id: Address::new([11u8; 20]),
                h3_cell: "8928308280aaaaa".to_string(),
                shard_id: 0,
                region: "us-east".to_string(),
                lat_lon: Some((40.7128, -74.0060)),
            },
            replica_b: NodeLocation {
                node_id: Address::new([12u8; 20]),
                h3_cell: "8928308280bbbbb".to_string(),
                shard_id: 0,
                region: "eu-west".to_string(),
                lat_lon: Some((51.5074, -0.1278)),
            },
            group_id: "test-group".to_string(),
            placement_epoch: 100,
            diversity_score: 0.9,
        };

        let payload = TransactionPayload::StoreData {
            chunk_id: Hash::new([1u8; 32]),
            data_size: 20 * 1024 * 1024 * 1024,
            duration_epochs: 100,
            data_hash: Hash::new([2u8; 32]),
            slice_id: SliceId::new("test".to_string()),
            storage_credits: 1000,
            replication_factor: 3,
            triad_placement: triad,
            erasure_coding: ErasureCodingParams {
                k: 10,
                m: 4,
                codec: ErasureCodec::ReedSolomon,
            },
            encryption_envelope: None,
        };

        let mut tx = Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
        tx.sign(&keypair, false).unwrap();

        let result = manager.validate_cellular_safe(&tx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_shard_manager_pq_transition_validation() {
        let mut config = create_test_shard_config(0);
        config.pq_transition_config.pq_only_required = true;
        config.pq_transition_config.legacy_deadline_epoch = Some(100);

        let manager = ShardManager::new(config, TEST_CHAIN_ID, TEST_NETWORK_ID);

        {
            let mut state = manager.state.write().await;
            state.set_block_height(ego_core::BlockHeight::new(1_212_001));
        }

        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());

        let payload = TransactionPayload::Transfer {
            to: Address::new([1u8; 20]),
            amount: Balance::from(100u64),
            memo: None,
            stealth_mode: false,
        };

        let mut tx = Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);

        tx.sign(&keypair, true).unwrap();

        let ed25519_sig = tx.signature.ed25519_sig.clone();
        tx.signature = ego_core::DualSignature {
            ed25519_sig,
            dilithium_sig: None,
            protocol_version: 1,
        };

        let result = manager.validate_pq_transition(&tx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_block_memory_limit() {
        let config = create_test_shard_config(0);
        let manager = ShardManager::new(config, TEST_CHAIN_ID, TEST_NETWORK_ID);

        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let mut account = create_test_account(from, Balance::from(10_000_000u64));
        account.dilithium_pk = keypair.dilithium_public_key().key_data.clone();
        account.mlkem_pk = keypair.kyber_public_key().key_data.clone();

        {
            let mut state = manager.state.write().await;
            state.set_account(account.clone());
        }

        for height in 1..=(MAX_BLOCKS_IN_MEMORY + 10) {
            account.nonce = height as u64 - 1;
            {
                let mut state = manager.state.write().await;
                state.set_account(account.clone());
            }

            let tx = create_test_transaction(&keypair, height as u64, ShardId::from_u32(0));
            let block = create_test_block(height as u64, ShardId::from_u32(0), vec![tx]);
            manager.process_block(block).await.unwrap();
        }

        let recent_blocks = manager.get_recent_blocks(MAX_BLOCKS_IN_MEMORY + 100).await;
        assert!(recent_blocks.len() <= MAX_BLOCKS_IN_MEMORY);
    }

    #[tokio::test]
    async fn test_multiple_shard_managers() {
        let config0 = create_test_shard_config(0);
        let config1 = create_test_shard_config(1);

        let manager0 = ShardManager::new(config0, TEST_CHAIN_ID, TEST_NETWORK_ID);
        let manager1 = ShardManager::new(config1, TEST_CHAIN_ID, TEST_NETWORK_ID);

        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let mut account = create_test_account(from, Balance::from(100_000u64));

        account.dilithium_pk = keypair.dilithium_public_key().key_data.clone();
        account.mlkem_pk = keypair.kyber_public_key().key_data.clone();

        {
            let mut state0 = manager0.state.write().await;
            state0.set_account(account.clone());
            let mut state1 = manager1.state.write().await;
            state1.set_account(account);
        }

        let tx0 = create_test_transaction(&keypair, 1, ShardId::from_u32(0));
        let tx1 = create_test_transaction(&keypair, 1, ShardId::from_u32(1));

        assert!(manager0.add_transaction(tx0).await.is_ok());
        assert!(manager1.add_transaction(tx1).await.is_ok());

        let stats0 = manager0.get_stats().await;
        let stats1 = manager1.get_stats().await;

        assert_eq!(stats0.shard_id, ShardId::from_u32(0));
        assert_eq!(stats1.shard_id, ShardId::from_u32(1));
    }

    #[tokio::test]
    async fn test_epoch_stats_tracking() {
        let mut config = create_test_shard_config(0);
        config.epoch_duration_blocks = 5;
        let manager = ShardManager::new(config, TEST_CHAIN_ID, TEST_NETWORK_ID);

        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let mut account = create_test_account(from, Balance::from(1_000_000u64));
        account.dilithium_pk = keypair.dilithium_public_key().key_data.clone();
        account.mlkem_pk = keypair.kyber_public_key().key_data.clone();

        {
            let mut state = manager.state.write().await;
            state.set_account(account.clone());
        }

        for height in 1..=3 {
            account.nonce = height - 1;
            {
                let mut state = manager.state.write().await;
                state.set_account(account.clone());
            }

            let tx = create_test_transaction(&keypair, height, ShardId::from_u32(0));
            let block = create_test_block(height, ShardId::from_u32(0), vec![tx]);
            manager.process_block(block).await.unwrap();
        }

        let epoch = manager.get_current_epoch().await;
        assert_eq!(epoch.stats.blocks_produced, 3);
        assert_eq!(epoch.stats.transactions_processed, 3);
        assert!(epoch.stats.avg_tps > 0.0);
    }

    #[tokio::test]
    async fn test_shard_info_management() {
        let manager = CrossShardManager::new();

        let info = ShardInfo {
            shard_id: ShardId::from_u32(0),
            block_height: ego_core::BlockHeight::new(1000),
            state_root: Hash::new([1u8; 32]),
            last_finalized_epoch: 10,
            active_validators: vec![Address::new([1u8; 20]), Address::new([2u8; 20])],
            status: ShardStatus::Active,
            last_updated: Timestamp::now(),
        };

        manager.update_shard_info(info.clone()).await;

        let retrieved = manager.get_shard_info(&ShardId::from_u32(0)).await;
        assert!(retrieved.is_some());

        let shard_info = retrieved.unwrap();
        assert_eq!(shard_info.shard_id, ShardId::from_u32(0));
        assert_eq!(shard_info.block_height.as_u64(), 1000);
        assert_eq!(shard_info.last_finalized_epoch, 10);
        assert_eq!(shard_info.active_validators.len(), 2);
        assert_eq!(shard_info.status, ShardStatus::Active);
    }

    #[test]
    fn test_reward_buckets_sum() {
        let buckets = RewardBuckets {
            storage_rewards: Balance::from(1000u64),
            consensus_rewards: Balance::from(2000u64),
            coverage_rewards: Balance::from(500u64),
            retrieval_rewards: Balance::from(300u64),
            dao_treasury: Balance::from(200u64),
        };

        let total = buckets.storage_rewards.as_u128()
            + buckets.consensus_rewards.as_u128()
            + buckets.coverage_rewards.as_u128()
            + buckets.retrieval_rewards.as_u128()
            + buckets.dao_treasury.as_u128();

        assert_eq!(total, 4000);
    }

    #[test]
    fn test_shard_status_variants() {
        assert_eq!(ShardStatus::Active, ShardStatus::Active);
        assert_ne!(ShardStatus::Active, ShardStatus::Syncing);
        assert_ne!(ShardStatus::Active, ShardStatus::Paused);
        assert_ne!(ShardStatus::Active, ShardStatus::Reorganizing);
        assert_ne!(ShardStatus::Active, ShardStatus::Offline);
    }
}
