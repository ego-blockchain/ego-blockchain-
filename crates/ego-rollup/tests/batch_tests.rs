#[cfg(test)]
mod batch_tests {
    use ego_core::deploy_policy::{DeployPolicyConfig, DeployPolicyManager};
    use ego_core::drs::{DRSConfig, DRSManager};
    use ego_core::{
        Address, AlgorithmId, Balance, BlockHeight, DualSignature, Hash, PublicKey, ShardId,
        SliceId, Timestamp, Transaction, TransactionPayload,
    };
    use ego_rollup::batch::{
        BATCH_TIMEOUT_MS, BatchConfig, BatchManager, BatchMetadata, BatchProof, BatchStats,
        BatchStatus, CrossBatchReceipt, CrossBatchStatus, DA_CHUNK_SIZE, DaChunk, DaCommitment,
        DaRetrievalStats, DeployStatsSnapshot, EpochBatchStats, ErasureCodingParams,
        MAX_BATCH_SIZE, MAX_BATCH_SIZE_BYTES, MAX_PROOF_SIZE_BYTES, OperatorStatus, PendingBatch,
        ProofType, StateSnapshotRef, calculate_batch_priority, validate_batch_structure,
    };
    use std::sync::Arc;

    fn test_address(seed: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[0] = seed;
        Address::new(bytes)
    }

    fn test_hash(seed: u8) -> Hash {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        Hash::new(bytes)
    }

    fn test_transaction(seed: u8) -> Transaction {
        let dilithium_data = vec![seed; 2420];
        let dilithium_pk = PublicKey::new(AlgorithmId::MlDsa2, dilithium_data);
        let ed25519_data = vec![seed; 32];
        let ed25519_pk = PublicKey::new(AlgorithmId::Ed25519, ed25519_data);
        let dilithium_sig_data = vec![seed; 2420];
        let dilithium_sig = ego_core::Signature::new(AlgorithmId::MlDsa2, dilithium_sig_data);
        Transaction {
            hash: test_hash(seed),
            from: test_address(seed),
            public_keys: ego_core::TransactionPublicKeys {
                dilithium_pk,
                ed25519_pk: Some(ed25519_pk),
                mlkem_pk: None,
            },
            signature: DualSignature {
                ed25519_sig: None,
                dilithium_sig: Some(dilithium_sig),
                protocol_version: 1,
            },
            timestamp: Timestamp::now(),
            shard_id: ShardId::new(0).unwrap(),
            payload: TransactionPayload::Transfer {
                to: test_address(seed + 1),
                amount: Balance::new(1000),
                memo: None,
                stealth_mode: false,
            },
            ru_limit: 21000,
            slice_id: Some(SliceId::new("default".to_string())),
            protocol_version: 1,
            chain_id: 1,
            required_algorithms: vec![1u16],
            nonce: seed as u64,
            pob_burn_credits: 0,
            priority_hint: 0,
            ru_estimate: 0,
        }
    }

    async fn setup_batch_manager() -> BatchManager {
        let drs_manager = Arc::new(DRSManager::new(DRSConfig::default()));
        let deploy_policy = Arc::new(DeployPolicyManager::new(DeployPolicyConfig::default()));
        BatchManager::new(BatchConfig::default(), drs_manager, deploy_policy)
    }

    #[tokio::test]
    async fn test_new_batch_manager() {
        let manager = setup_batch_manager().await;
        let stats = manager.get_batch_stats().await;
        assert_eq!(stats.total_batches_created, 0);
        assert_eq!(stats.total_batches_committed, 0);
        assert_eq!(stats.total_batches_finalized, 0);
    }

    #[tokio::test]
    async fn test_default_batch_config() {
        let config = BatchConfig::default();
        assert_eq!(config.max_batch_size, MAX_BATCH_SIZE);
        assert_eq!(config.max_batch_size_bytes, MAX_BATCH_SIZE_BYTES);
        assert_eq!(config.batch_timeout_ms, BATCH_TIMEOUT_MS);
        assert!(config.proof_verification_enabled);
        assert!(config.da_enabled);
        assert!(config.aggregation_enabled);
    }

    #[tokio::test]
    async fn test_register_operator_success() {
        let manager = setup_batch_manager().await;
        let operator = test_address(1);
        let shard_id = ShardId::new(0).unwrap();
        let bond_amount = Balance::from_egoc(10000);

        let result = manager
            .register_operator(operator, shard_id, bond_amount)
            .await;
        assert!(result.is_ok());

        let operator_info = manager.get_operator_info(&operator);
        assert!(operator_info.is_some());
        let info = operator_info.unwrap();
        assert_eq!(info.operator, operator);
        assert_eq!(info.shard_id, shard_id);
        assert_eq!(info.bond_amount, bond_amount);
        assert_eq!(info.batches_committed, 0);
        assert_eq!(info.batches_finalized, 0);
    }

    #[tokio::test]
    async fn test_register_operator_insufficient_bond() {
        let manager = setup_batch_manager().await;
        let operator = test_address(2);
        let shard_id = ShardId::new(0).unwrap();
        let insufficient_bond = Balance::from_egoc(100);

        let result = manager
            .register_operator(operator, shard_id, insufficient_bond)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_batch_success() {
        let manager = setup_batch_manager().await;
        let operator = test_address(3);
        let shard_id = ShardId::new(0).unwrap();

        manager
            .register_operator(operator, shard_id, Balance::from_egoc(10000))
            .await
            .unwrap();

        let transactions = vec![test_transaction(1), test_transaction(2)];
        let state_root = test_hash(10);

        let result = manager
            .create_batch(operator, shard_id, transactions, state_root, 1)
            .await;
        assert!(result.is_ok());

        let batch_id = result.unwrap();
        let batch = manager.get_pending_batch(&batch_id);
        assert!(batch.is_some());

        let batch = batch.unwrap();
        assert_eq!(batch.operator, operator);
        assert_eq!(batch.shard_id, shard_id);
        assert_eq!(batch.transactions.len(), 2);
        assert_eq!(batch.epoch, 1);
    }

    #[tokio::test]
    async fn test_create_batch_unregistered_operator() {
        let manager = setup_batch_manager().await;
        let operator = test_address(4);
        let shard_id = ShardId::new(0).unwrap();
        let transactions = vec![test_transaction(3)];
        let state_root = test_hash(11);

        let result = manager
            .create_batch(operator, shard_id, transactions, state_root, 1)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_batch_exceeds_max_size() {
        let manager = setup_batch_manager().await;
        let operator = test_address(5);
        let shard_id = ShardId::new(0).unwrap();
        manager
            .register_operator(operator, shard_id, Balance::from_egoc(10000))
            .await
            .unwrap();
        let mut test_config = BatchConfig::default();
        test_config.max_batch_size = 10;
        manager.update_config(test_config).await.unwrap();
        let mut transactions = Vec::new();
        for i in 0..11 {
            transactions.push(test_transaction(i as u8));
        }
        let state_root = test_hash(12);
        let result = manager
            .create_batch(operator, shard_id, transactions, state_root, 1)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_batch_updates_stats() {
        let manager = setup_batch_manager().await;
        let operator = test_address(6);
        let shard_id = ShardId::new(0).unwrap();

        manager
            .register_operator(operator, shard_id, Balance::from_egoc(10000))
            .await
            .unwrap();

        let transactions = vec![test_transaction(4), test_transaction(5)];
        let state_root = test_hash(13);

        let stats_before = manager.get_batch_stats().await;
        let initial_batches = stats_before.total_batches_created;
        let initial_txs = stats_before.total_transactions_processed;

        manager
            .create_batch(operator, shard_id, transactions.clone(), state_root, 1)
            .await
            .unwrap();

        let stats_after = manager.get_batch_stats().await;
        assert_eq!(stats_after.total_batches_created, initial_batches + 1);
        assert_eq!(
            stats_after.total_transactions_processed,
            initial_txs + transactions.len() as u64
        );
    }

    #[tokio::test]
    async fn test_commit_batch_without_proof() {
        let manager = setup_batch_manager().await;
        let operator = test_address(7);
        let shard_id = ShardId::new(0).unwrap();

        manager
            .register_operator(operator, shard_id, Balance::from_egoc(10000))
            .await
            .unwrap();

        let transactions = vec![test_transaction(6)];
        let state_root = test_hash(14);

        let batch_id = manager
            .create_batch(operator, shard_id, transactions, state_root, 1)
            .await
            .unwrap();

        let batch = manager.get_pending_batch(&batch_id).unwrap();
        let mut updated_batch = batch.clone();
        updated_batch.status = BatchStatus::Ready;
        updated_batch.state_root_post = test_hash(15);
        drop(batch);

        let result = manager
            .commit_batch(&batch_id, None, vec![1, 2, 3], BlockHeight::new(100))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_commit_batch_with_proof() {
        let manager = setup_batch_manager().await;
        let operator = test_address(8);
        let shard_id = ShardId::new(0).unwrap();
        manager
            .register_operator(operator, shard_id, Balance::from_egoc(10000))
            .await
            .unwrap();
        let transactions = vec![test_transaction(7)];
        let state_root = test_hash(16);
        let batch_id = manager
            .create_batch(operator, shard_id, transactions, state_root, 1)
            .await
            .unwrap();
        manager
            .set_batch_ready(&batch_id, test_hash(17))
            .await
            .unwrap();
        let proof = BatchProof {
            proof_type: ProofType::Snark,
            proof_data: vec![1, 2, 3, 4],
            public_inputs: vec![test_hash(18)],
            verification_key_hash: test_hash(19),
            proof_size_bytes: 4,
            generated_at: Timestamp::now(),
        };
        let result = manager
            .commit_batch(&batch_id, Some(proof), vec![1, 2, 3], BlockHeight::new(100))
            .await;
        assert!(result.is_ok());
        let committed = manager.get_committed_batch(&batch_id);
        assert!(committed.is_some());
    }

    #[tokio::test]
    async fn test_commit_batch_not_ready() {
        let manager = setup_batch_manager().await;
        let operator = test_address(9);
        let shard_id = ShardId::new(0).unwrap();

        manager
            .register_operator(operator, shard_id, Balance::from_egoc(10000))
            .await
            .unwrap();

        let transactions = vec![test_transaction(8)];
        let state_root = test_hash(20);

        let batch_id = manager
            .create_batch(operator, shard_id, transactions, state_root, 1)
            .await
            .unwrap();

        let proof = BatchProof {
            proof_type: ProofType::Plonk,
            proof_data: vec![5, 6, 7],
            public_inputs: vec![test_hash(21)],
            verification_key_hash: test_hash(22),
            proof_size_bytes: 3,
            generated_at: Timestamp::now(),
        };

        let result = manager
            .commit_batch(&batch_id, Some(proof), vec![4, 5, 6], BlockHeight::new(100))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_finalize_batch_success() {
        let manager = setup_batch_manager().await;
        let operator = test_address(10);
        let shard_id = ShardId::new(0).unwrap();
        manager
            .register_operator(operator, shard_id, Balance::from_egoc(10000))
            .await
            .unwrap();
        let transactions = vec![test_transaction(9)];
        let state_root = test_hash(23);
        let batch_id = manager
            .create_batch(operator, shard_id, transactions, state_root, 1)
            .await
            .unwrap();
        manager
            .set_batch_ready(&batch_id, test_hash(24))
            .await
            .unwrap();
        let proof = BatchProof {
            proof_type: ProofType::Groth16,
            proof_data: vec![8, 9, 10],
            public_inputs: vec![test_hash(25)],
            verification_key_hash: test_hash(26),
            proof_size_bytes: 3,
            generated_at: Timestamp::now(),
        };
        manager
            .commit_batch(&batch_id, Some(proof), vec![7, 8, 9], BlockHeight::new(100))
            .await
            .unwrap();
        let result = manager
            .finalize_batch(&batch_id, BlockHeight::new(250))
            .await;
        assert!(result.is_ok());
        let finalized = manager.get_finalized_batch(&batch_id);
        assert!(finalized.is_some());
        let finalized = finalized.unwrap();
        assert_eq!(finalized.operator, operator);
        assert!(finalized.challenge_period_passed);
    }

    #[tokio::test]
    async fn test_finalize_batch_before_challenge_window() {
        let manager = setup_batch_manager().await;
        let operator = test_address(11);
        let shard_id = ShardId::new(0).unwrap();
        manager
            .register_operator(operator, shard_id, Balance::from_egoc(10000))
            .await
            .unwrap();
        let transactions = vec![test_transaction(10)];
        let state_root = test_hash(27);
        let batch_id = manager
            .create_batch(operator, shard_id, transactions, state_root, 1)
            .await
            .unwrap();
        manager
            .set_batch_ready(&batch_id, test_hash(28))
            .await
            .unwrap();
        let proof = BatchProof {
            proof_type: ProofType::Halo2,
            proof_data: vec![11, 12, 13],
            public_inputs: vec![test_hash(29)],
            verification_key_hash: test_hash(30),
            proof_size_bytes: 3,
            generated_at: Timestamp::now(),
        };
        manager
            .commit_batch(
                &batch_id,
                Some(proof),
                vec![10, 11, 12],
                BlockHeight::new(100),
            )
            .await
            .unwrap();
        let result = manager
            .finalize_batch(&batch_id, BlockHeight::new(150))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_batch_status_transitions() {
        let manager = setup_batch_manager().await;
        let operator = test_address(12);
        let shard_id = ShardId::new(0).unwrap();
        manager
            .register_operator(operator, shard_id, Balance::from_egoc(10000))
            .await
            .unwrap();
        let transactions = vec![test_transaction(11)];
        let state_root = test_hash(31);
        let batch_id = manager
            .create_batch(operator, shard_id, transactions, state_root, 1)
            .await
            .unwrap();
        let batch = manager.get_pending_batch(&batch_id).unwrap();
        assert_eq!(batch.status, BatchStatus::Building);
        manager
            .set_batch_ready(&batch_id, test_hash(32))
            .await
            .unwrap();
        let batch = manager.get_pending_batch(&batch_id).unwrap();
        assert_eq!(batch.status, BatchStatus::Ready);
    }

    #[tokio::test]
    async fn test_operator_info_updates() {
        let manager = setup_batch_manager().await;
        let operator = test_address(13);
        let shard_id = ShardId::new(0).unwrap();
        manager
            .register_operator(operator, shard_id, Balance::from_egoc(10000))
            .await
            .unwrap();
        let info_before = manager.get_operator_info(&operator).unwrap();
        assert_eq!(info_before.batches_committed, 0);
        assert_eq!(info_before.batches_finalized, 0);
        let transactions = vec![test_transaction(12)];
        let state_root = test_hash(33);
        let batch_id = manager
            .create_batch(operator, shard_id, transactions, state_root, 1)
            .await
            .unwrap();
        manager
            .set_batch_ready(&batch_id, test_hash(34))
            .await
            .unwrap();
        let proof = BatchProof {
            proof_type: ProofType::Snark,
            proof_data: vec![14, 15, 16],
            public_inputs: vec![test_hash(35)],
            verification_key_hash: test_hash(36),
            proof_size_bytes: 3,
            generated_at: Timestamp::now(),
        };
        manager
            .commit_batch(
                &batch_id,
                Some(proof),
                vec![13, 14, 15],
                BlockHeight::new(100),
            )
            .await
            .unwrap();
        let info_after_commit = manager.get_operator_info(&operator).unwrap();
        assert_eq!(info_after_commit.batches_committed, 1);
        manager
            .finalize_batch(&batch_id, BlockHeight::new(250))
            .await
            .unwrap();
        let info_after_finalize = manager.get_operator_info(&operator).unwrap();
        assert_eq!(info_after_finalize.batches_finalized, 1);
    }

    #[tokio::test]
    async fn test_proof_types() {
        let snark = ProofType::Snark;
        let stark = ProofType::Stark;
        let groth16 = ProofType::Groth16;
        let plonk = ProofType::Plonk;
        let halo2 = ProofType::Halo2;

        assert_ne!(snark, stark);
        assert_ne!(stark, groth16);
        assert_ne!(groth16, plonk);
        assert_ne!(plonk, halo2);
    }

    #[tokio::test]
    async fn test_aggregated_proof_type() {
        let sub_proofs = vec![test_hash(37), test_hash(38), test_hash(39)];
        let aggregated = ProofType::Aggregated {
            sub_proofs: sub_proofs.clone(),
        };

        match aggregated {
            ProofType::Aggregated { sub_proofs: sp } => {
                assert_eq!(sp.len(), 3);
                assert_eq!(sp[0], test_hash(37));
            }
            _ => panic!("Expected Aggregated proof type"),
        }
    }

    #[tokio::test]
    async fn test_batch_metadata() {
        let metadata = BatchMetadata {
            batch_id: test_hash(40),
            operator: test_address(14),
            shard_id: ShardId::new(0).unwrap(),
            tx_count: 100,
            size_bytes: 50000,
            created_at: Timestamp::now(),
            epoch: 5,
            priority: 200,
        };

        assert_eq!(metadata.tx_count, 100);
        assert_eq!(metadata.size_bytes, 50000);
        assert_eq!(metadata.epoch, 5);
        assert_eq!(metadata.priority, 200);
    }

    #[tokio::test]
    async fn test_erasure_coding_params() {
        let params = ErasureCodingParams {
            k: 64,
            m: 32,
            codec: "ReedSolomon".to_string(),
            chunk_size: DA_CHUNK_SIZE,
        };

        assert_eq!(params.k, 64);
        assert_eq!(params.m, 32);
        assert_eq!(params.codec, "ReedSolomon");
        assert_eq!(params.chunk_size, DA_CHUNK_SIZE);
    }

    #[tokio::test]
    async fn test_da_commitment_creation() {
        let chunk_hashes = vec![test_hash(41), test_hash(42), test_hash(43)];
        let commitment = DaCommitment {
            da_root: test_hash(44),
            chunk_count: 3,
            total_size_bytes: 768000,
            erasure_coding_params: ErasureCodingParams {
                k: 64,
                m: 32,
                codec: "ReedSolomon".to_string(),
                chunk_size: DA_CHUNK_SIZE,
            },
            chunk_hashes: chunk_hashes.clone(),
            blob_pointer: Some("ipfs://example".to_string()),
            uploaded_at: Timestamp::now(),
        };

        assert_eq!(commitment.chunk_count, 3);
        assert_eq!(commitment.total_size_bytes, 768000);
        assert_eq!(commitment.chunk_hashes.len(), 3);
        assert!(commitment.blob_pointer.is_some());
    }

    #[tokio::test]
    async fn test_da_chunk() {
        let chunk = DaChunk {
            chunk_id: test_hash(45),
            batch_id: test_hash(46),
            chunk_index: 5,
            data: vec![1, 2, 3, 4, 5],
            parity: false,
            uploaded_at: Timestamp::now(),
        };

        assert_eq!(chunk.chunk_index, 5);
        assert_eq!(chunk.data.len(), 5);
        assert!(!chunk.parity);
    }

    #[tokio::test]
    async fn test_operator_status_variants() {
        let active = OperatorStatus::Active;
        let bonded = OperatorStatus::Bonded;
        let slashed = OperatorStatus::Slashed;
        let jailed = OperatorStatus::Jailed { release_epoch: 100 };
        let inactive = OperatorStatus::Inactive;

        assert_ne!(active, bonded);
        assert_ne!(bonded, slashed);
        assert_ne!(slashed, inactive);

        match jailed {
            OperatorStatus::Jailed { release_epoch } => {
                assert_eq!(release_epoch, 100);
            }
            _ => panic!("Expected Jailed status"),
        }
    }

    #[tokio::test]
    async fn test_epoch_batch_stats_default() {
        let stats = EpochBatchStats::default();
        assert_eq!(stats.total_batches, 0);
        assert_eq!(stats.total_transactions, 0);
        assert_eq!(stats.total_ru_consumed, 0);
        assert_eq!(stats.total_storage_used, 0);
        assert_eq!(stats.finalized_batches, 0);
        assert_eq!(stats.challenged_batches, 0);
        assert_eq!(stats.failed_batches, 0);
    }

    #[tokio::test]
    async fn test_batch_stats_default() {
        let stats = BatchStats::default();
        assert_eq!(stats.total_batches_created, 0);
        assert_eq!(stats.total_batches_committed, 0);
        assert_eq!(stats.total_batches_finalized, 0);
        assert_eq!(stats.total_batches_rejected, 0);
        assert_eq!(stats.total_transactions_processed, 0);
        assert_eq!(stats.total_proofs_verified, 0);
        assert_eq!(stats.total_proofs_aggregated, 0);
    }

    #[tokio::test]
    async fn test_cross_batch_receipt() {
        let receipt = CrossBatchReceipt {
            receipt_id: test_hash(47),
            src_batch_id: test_hash(48),
            dst_batch_id: Some(test_hash(49)),
            src_shard: ShardId::new(0).unwrap(),
            dst_shard: ShardId::new(1).unwrap(),
            payload: vec![10, 20, 30],
            nonce: 42,
            created_at: Timestamp::now(),
            status: CrossBatchStatus::Pending,
        };

        assert_eq!(receipt.nonce, 42);
        assert_eq!(receipt.payload.len(), 3);
        assert_eq!(receipt.status, CrossBatchStatus::Pending);
    }

    #[tokio::test]
    async fn test_cross_batch_status_variants() {
        let pending = CrossBatchStatus::Pending;
        let transmitted = CrossBatchStatus::Transmitted;
        let acknowledged = CrossBatchStatus::Acknowledged;
        let applied = CrossBatchStatus::Applied;
        let failed = CrossBatchStatus::Failed {
            reason: "Error".to_string(),
        };

        assert_ne!(pending, transmitted);
        assert_ne!(transmitted, acknowledged);
        assert_ne!(acknowledged, applied);

        match failed {
            CrossBatchStatus::Failed { reason } => {
                assert_eq!(reason, "Error");
            }
            _ => panic!("Expected Failed status"),
        }
    }

    #[tokio::test]
    async fn test_state_snapshot_ref() {
        let snapshot = StateSnapshotRef {
            epoch: 10,
            block_height: BlockHeight::new(1000),
            shard_id: ShardId::new(0).unwrap(),
            state_root: test_hash(50),
            snapshot_hash: test_hash(51),
            created_at: Timestamp::now(),
        };

        assert_eq!(snapshot.epoch, 10);
        assert_eq!(snapshot.block_height.as_u64(), 1000);
    }

    #[tokio::test]
    async fn test_validate_batch_structure_empty() {
        let batch = PendingBatch {
            batch_id: test_hash(52),
            operator: test_address(15),
            shard_id: ShardId::new(0).unwrap(),
            transactions: vec![],
            tx_root: test_hash(53),
            state_root_pre: test_hash(54),
            state_root_post: test_hash(55),
            created_at: Timestamp::now(),
            batch_size_bytes: 0,
            status: BatchStatus::Building,
            epoch: 1,
            ru_consumed: 0,
            storage_used: 0,
            deploy_records: vec![],
        };

        let result = validate_batch_structure(&batch);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_batch_structure_exceeds_size() {
        let batch = PendingBatch {
            batch_id: test_hash(56),
            operator: test_address(16),
            shard_id: ShardId::new(0).unwrap(),
            transactions: vec![test_transaction(13)],
            tx_root: test_hash(57),
            state_root_pre: test_hash(58),
            state_root_post: test_hash(59),
            created_at: Timestamp::now(),
            batch_size_bytes: MAX_BATCH_SIZE_BYTES + 1,
            status: BatchStatus::Building,
            epoch: 1,
            ru_consumed: 0,
            storage_used: 0,
            deploy_records: vec![],
        };

        let result = validate_batch_structure(&batch);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_batch_structure_valid() {
        let batch = PendingBatch {
            batch_id: test_hash(60),
            operator: test_address(17),
            shard_id: ShardId::new(0).unwrap(),
            transactions: vec![test_transaction(14), test_transaction(15)],
            tx_root: test_hash(61),
            state_root_pre: test_hash(62),
            state_root_post: test_hash(63),
            created_at: Timestamp::now(),
            batch_size_bytes: 5000,
            status: BatchStatus::Building,
            epoch: 1,
            ru_consumed: 100,
            storage_used: 200,
            deploy_records: vec![],
        };

        let result = validate_batch_structure(&batch);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_calculate_batch_priority_base() {
        let metadata = BatchMetadata {
            batch_id: test_hash(64),
            operator: test_address(18),
            shard_id: ShardId::new(0).unwrap(),
            tx_count: 50,
            size_bytes: 25000,
            created_at: Timestamp::now(),
            epoch: 1,
            priority: 0,
        };

        let priority = calculate_batch_priority(&metadata, 1.0);
        assert!(priority >= 128);
        assert!(priority <= 255);
    }

    #[tokio::test]
    async fn test_calculate_batch_priority_with_drs() {
        let metadata = BatchMetadata {
            batch_id: test_hash(65),
            operator: test_address(19),
            shard_id: ShardId::new(0).unwrap(),
            tx_count: 100,
            size_bytes: 50000,
            created_at: Timestamp::now(),
            epoch: 1,
            priority: 0,
        };

        let high_drs_priority = calculate_batch_priority(&metadata, 1.3);
        let low_drs_priority = calculate_batch_priority(&metadata, 0.7);

        assert!(high_drs_priority > low_drs_priority);
    }

    #[tokio::test]
    async fn test_slash_operator() {
        let manager = setup_batch_manager().await;
        let operator = test_address(20);
        let shard_id = ShardId::new(0).unwrap();

        manager
            .register_operator(operator, shard_id, Balance::from_egoc(10000))
            .await
            .unwrap();

        let info_before = manager.get_operator_info(&operator).unwrap();
        let reputation_before = info_before.reputation_score;

        let slash_amount = Balance::from_egoc(500);
        manager
            .slash_operator(operator, "Fraud detected".to_string(), slash_amount)
            .await
            .unwrap();

        let info_after = manager.get_operator_info(&operator).unwrap();
        assert_eq!(info_after.total_slashed, slash_amount);
        assert!(info_after.reputation_score < reputation_before);
    }

    #[tokio::test]
    async fn test_slash_operator_severe() {
        let manager = setup_batch_manager().await;
        let operator = test_address(21);
        let shard_id = ShardId::new(0).unwrap();

        manager
            .register_operator(operator, shard_id, Balance::from_egoc(10000))
            .await
            .unwrap();

        for _ in 0..10 {
            manager
                .slash_operator(
                    operator,
                    "Multiple violations".to_string(),
                    Balance::from_egoc(100),
                )
                .await
                .unwrap();
        }

        let info = manager.get_operator_info(&operator).unwrap();
        assert!(matches!(info.status, OperatorStatus::Slashed));
    }

    #[tokio::test]
    async fn test_advance_epoch() {
        let manager = setup_batch_manager().await;
        let operator = test_address(22);
        let shard_id = ShardId::new(0).unwrap();
        manager
            .register_operator(operator, shard_id, Balance::from_egoc(10000))
            .await
            .unwrap();
        let transactions = vec![test_transaction(16)];
        let state_root = test_hash(66);
        manager
            .create_batch(operator, shard_id, transactions, state_root, 1)
            .await
            .unwrap();
        let result = manager.advance_epoch(2).await;
        assert!(result.is_ok());
        let stats = manager.get_epoch_stats(1).await;
        assert!(stats.is_some());
    }

    #[tokio::test]
    async fn test_advance_epoch_invalid() {
        let manager = setup_batch_manager().await;

        manager.advance_epoch(5).await.unwrap();

        let result = manager.advance_epoch(3).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_update_config() {
        let manager = setup_batch_manager().await;

        let mut new_config = BatchConfig::default();
        new_config.max_batch_size = 5000;
        new_config.batch_timeout_ms = 10000;

        let result = manager.update_config(new_config.clone()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_update_config_invalid() {
        let manager = setup_batch_manager().await;

        let mut invalid_config = BatchConfig::default();
        invalid_config.max_batch_size = 0;

        let result = manager.update_config(invalid_config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_prune_old_batches() {
        let manager = setup_batch_manager().await;
        let operator = test_address(23);
        let shard_id = ShardId::new(0).unwrap();

        manager
            .register_operator(operator, shard_id, Balance::from_egoc(10000))
            .await
            .unwrap();

        for epoch in 1..=5 {
            let transactions = vec![test_transaction(17 + epoch as u8)];
            let state_root = test_hash(67 + epoch as u8);
            manager
                .create_batch(operator, shard_id, transactions, state_root, epoch)
                .await
                .unwrap();
        }

        manager.advance_epoch(10).await.unwrap();

        let pruned = manager.prune_old_batches(3).await.unwrap();
        assert!(pruned > 0);
    }

    #[tokio::test]
    async fn test_get_operator_batches() {
        let manager = setup_batch_manager().await;
        let operator = test_address(24);
        let shard_id = ShardId::new(0).unwrap();
        manager
            .register_operator(operator, shard_id, Balance::from_egoc(10000))
            .await
            .unwrap();
        for i in 0..3 {
            let transactions = vec![test_transaction(20 + i)];
            let state_root = test_hash(70 + i);
            let batch_id = manager
                .create_batch(operator, shard_id, transactions.clone(), state_root, 1)
                .await
                .unwrap();
            manager
                .set_batch_ready(&batch_id, test_hash(80 + i))
                .await
                .unwrap();
            let proof = BatchProof {
                proof_type: ProofType::Snark,
                proof_data: vec![1, 2, 3],
                public_inputs: vec![test_hash(90 + i)],
                verification_key_hash: test_hash(100 + i),
                proof_size_bytes: 3,
                generated_at: Timestamp::now(),
            };
            manager
                .commit_batch(&batch_id, Some(proof), vec![1, 2, 3], BlockHeight::new(100))
                .await
                .unwrap();
            manager
                .finalize_batch(&batch_id, BlockHeight::new(250))
                .await
                .unwrap();
        }
        let batches = manager.get_operator_batches(&operator, 10).await;
        assert_eq!(batches.len(), 3);
    }

    #[tokio::test]
    async fn test_get_operator_batches_limit() {
        let manager = setup_batch_manager().await;
        let operator = test_address(25);
        let shard_id = ShardId::new(0).unwrap();
        manager
            .register_operator(operator, shard_id, Balance::from_egoc(10000))
            .await
            .unwrap();
        for i in 0..10 {
            let transactions = vec![test_transaction(30 + i)];
            let state_root = test_hash(110 + i);
            let batch_id = manager
                .create_batch(operator, shard_id, transactions.clone(), state_root, 1)
                .await
                .unwrap();
            manager
                .set_batch_ready(&batch_id, test_hash(120 + i))
                .await
                .unwrap();
            let proof = BatchProof {
                proof_type: ProofType::Plonk,
                proof_data: vec![1, 2, 3],
                public_inputs: vec![test_hash(130 + i)],
                verification_key_hash: test_hash(140 + i),
                proof_size_bytes: 3,
                generated_at: Timestamp::now(),
            };
            manager
                .commit_batch(&batch_id, Some(proof), vec![1, 2, 3], BlockHeight::new(100))
                .await
                .unwrap();
            manager
                .finalize_batch(&batch_id, BlockHeight::new(250))
                .await
                .unwrap();
        }
        let batches = manager.get_operator_batches(&operator, 5).await;
        assert_eq!(batches.len(), 5);
    }

    #[tokio::test]
    async fn test_da_retrieval_stats() {
        let manager = setup_batch_manager().await;
        let stats = manager.get_da_stats().await;

        assert_eq!(stats.total_chunks_uploaded, 0);
        assert_eq!(stats.total_chunks_retrieved, 0);
        assert_eq!(stats.failed_retrievals, 0);
    }

    #[tokio::test]
    async fn test_get_da_commitment() {
        let manager = setup_batch_manager().await;
        let batch_id = test_hash(150);

        let commitment = manager.get_da_commitment(&batch_id);
        assert!(commitment.is_none());
    }

    #[tokio::test]
    async fn test_get_da_chunk() {
        let manager = setup_batch_manager().await;
        let chunk_id = test_hash(154);

        let retrieved = manager.get_da_chunk(&chunk_id);
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_process_cross_batch_receipt() {
        let manager = setup_batch_manager().await;
        let src_batch_id = test_hash(156);
        let dst_shard = ShardId::new(1).unwrap();
        let payload = vec![100, 101, 102];

        let result = manager
            .process_cross_batch_receipt(src_batch_id, dst_shard, payload.clone())
            .await;
        assert!(result.is_ok());

        let receipt_id = result.unwrap();
        let receipt = manager.get_cross_batch_receipt(&receipt_id);
        assert!(receipt.is_some());

        let receipt = receipt.unwrap();
        assert_eq!(receipt.src_batch_id, src_batch_id);
        assert_eq!(receipt.dst_shard, dst_shard);
        assert_eq!(receipt.payload, payload);
    }

    #[tokio::test]
    async fn test_multiple_operators() {
        let manager = setup_batch_manager().await;
        let shard_id = ShardId::new(0).unwrap();

        for i in 0..5 {
            let operator = test_address(30 + i);
            manager
                .register_operator(operator, shard_id, Balance::from_egoc(10000))
                .await
                .unwrap();

            let info = manager.get_operator_info(&operator);
            assert!(info.is_some());
        }
    }

    #[tokio::test]
    async fn test_batch_with_multiple_transactions() {
        let manager = setup_batch_manager().await;
        let operator = test_address(35);
        let shard_id = ShardId::new(0).unwrap();

        manager
            .register_operator(operator, shard_id, Balance::from_egoc(10000))
            .await
            .unwrap();

        let mut transactions = Vec::new();
        for i in 0..100 {
            transactions.push(test_transaction(40 + i as u8));
        }

        let state_root = test_hash(160);
        let result = manager
            .create_batch(operator, shard_id, transactions.clone(), state_root, 1)
            .await;
        assert!(result.is_ok());

        let batch_id = result.unwrap();
        let batch = manager.get_pending_batch(&batch_id).unwrap();
        assert_eq!(batch.transactions.len(), 100);
    }

    #[tokio::test]
    async fn test_committed_batch_fields() {
        let manager = setup_batch_manager().await;
        let operator = test_address(36);
        let shard_id = ShardId::new(0).unwrap();
        manager
            .register_operator(operator, shard_id, Balance::from_egoc(10000))
            .await
            .unwrap();
        let transactions = vec![test_transaction(50)];
        let state_root = test_hash(161);
        let batch_id = manager
            .create_batch(operator, shard_id, transactions, state_root, 1)
            .await
            .unwrap();
        manager
            .set_batch_ready(&batch_id, test_hash(162))
            .await
            .unwrap();
        let proof = BatchProof {
            proof_type: ProofType::Stark,
            proof_data: vec![20, 21, 22],
            public_inputs: vec![test_hash(163)],
            verification_key_hash: test_hash(164),
            proof_size_bytes: 3,
            generated_at: Timestamp::now(),
        };
        manager
            .commit_batch(
                &batch_id,
                Some(proof.clone()),
                vec![30, 31, 32],
                BlockHeight::new(100),
            )
            .await
            .unwrap();
        let committed = manager.get_committed_batch(&batch_id).unwrap();
        assert_eq!(committed.operator, operator);
        assert_eq!(committed.shard_id, shard_id);
        assert!(committed.proof.is_some());
        assert_eq!(committed.committed_block.as_u64(), 100);
        assert_eq!(committed.epoch, 1);
        assert!(!committed.aggregated);
    }
    #[tokio::test]
    async fn test_finalized_batch_fields() {
        let manager = setup_batch_manager().await;
        let operator = test_address(37);
        let shard_id = ShardId::new(0).unwrap();
        manager
            .register_operator(operator, shard_id, Balance::from_egoc(10000))
            .await
            .unwrap();
        let transactions = vec![test_transaction(51)];
        let state_root = test_hash(165);
        let batch_id = manager
            .create_batch(operator, shard_id, transactions, state_root, 1)
            .await
            .unwrap();
        manager
            .set_batch_ready(&batch_id, test_hash(166))
            .await
            .unwrap();
        let proof = BatchProof {
            proof_type: ProofType::Halo2,
            proof_data: vec![40, 41, 42],
            public_inputs: vec![test_hash(167)],
            verification_key_hash: test_hash(168),
            proof_size_bytes: 3,
            generated_at: Timestamp::now(),
        };
        manager
            .commit_batch(
                &batch_id,
                Some(proof),
                vec![50, 51, 52],
                BlockHeight::new(100),
            )
            .await
            .unwrap();
        manager
            .finalize_batch(&batch_id, BlockHeight::new(250))
            .await
            .unwrap();
        let finalized = manager.get_finalized_batch(&batch_id).unwrap();
        assert_eq!(finalized.operator, operator);
        assert_eq!(finalized.shard_id, shard_id);
        assert_eq!(finalized.finalized_block.as_u64(), 250);
        assert!(finalized.challenge_period_passed);
        assert!(finalized.all_disputes_resolved);
        assert_eq!(finalized.dispute_count, 0);
    }

    #[tokio::test]
    async fn test_epoch_tracking() {
        let manager = setup_batch_manager().await;
        let operator = test_address(40);
        let shard_id = ShardId::new(0).unwrap();
        manager
            .register_operator(operator, shard_id, Balance::from_egoc(10000))
            .await
            .unwrap();
        for epoch in 1..=3 {
            let transactions = vec![test_transaction(54 + epoch as u8)];
            let state_root = test_hash(181 + epoch as u8);
            manager
                .create_batch(operator, shard_id, transactions, state_root, epoch)
                .await
                .unwrap();
        }
        manager.advance_epoch(4).await.unwrap();
        let stats_epoch_1 = manager.get_epoch_stats(1).await;
        assert!(stats_epoch_1.is_some());
    }

    #[tokio::test]
    async fn test_multiple_shards() {
        let manager = setup_batch_manager().await;
        let operator = test_address(41);

        for shard_num in 0..3 {
            let shard_id = ShardId::new(shard_num).unwrap();
            manager
                .register_operator(operator, shard_id, Balance::from_egoc(10000))
                .await
                .unwrap();

            let transactions = vec![test_transaction(60 + shard_num as u8)];
            let state_root = test_hash(190 + shard_num as u8);
            let result = manager
                .create_batch(operator, shard_id, transactions, state_root, 1)
                .await;
            assert!(result.is_ok());
        }
    }

    #[tokio::test]
    async fn test_operator_reputation_updates() {
        let manager = setup_batch_manager().await;
        let operator = test_address(42);
        let shard_id = ShardId::new(0).unwrap();
        manager
            .register_operator(operator, shard_id, Balance::from_egoc(10000))
            .await
            .unwrap();
        let initial_info = manager.get_operator_info(&operator).unwrap();
        let initial_reputation = initial_info.reputation_score;
        for i in 0..5 {
            let transactions = vec![test_transaction(70 + i)];
            let state_root = test_hash(200 + i);
            let batch_id = manager
                .create_batch(operator, shard_id, transactions, state_root, 1)
                .await
                .unwrap();
            manager
                .set_batch_ready(&batch_id, test_hash(210 + i))
                .await
                .unwrap();
            let proof = BatchProof {
                proof_type: ProofType::Groth16,
                proof_data: vec![1, 2, 3],
                public_inputs: vec![test_hash(220 + i)],
                verification_key_hash: test_hash(230 + i),
                proof_size_bytes: 3,
                generated_at: Timestamp::now(),
            };
            manager
                .commit_batch(&batch_id, Some(proof), vec![1, 2, 3], BlockHeight::new(100))
                .await
                .unwrap();
            manager
                .finalize_batch(&batch_id, BlockHeight::new(250))
                .await
                .unwrap();
        }
        let final_info = manager.get_operator_info(&operator).unwrap();
        assert!(final_info.reputation_score >= initial_reputation);
    }

    #[tokio::test]
    async fn test_batch_stats_updates() {
        let manager = setup_batch_manager().await;
        let operator = test_address(43);
        let shard_id = ShardId::new(0).unwrap();

        manager
            .register_operator(operator, shard_id, Balance::from_egoc(10000))
            .await
            .unwrap();

        let initial_stats = manager.get_batch_stats().await;

        let transactions = vec![test_transaction(80), test_transaction(81)];
        let state_root = test_hash(240);

        manager
            .create_batch(operator, shard_id, transactions, state_root, 1)
            .await
            .unwrap();

        let updated_stats = manager.get_batch_stats().await;
        assert!(updated_stats.total_batches_created > initial_stats.total_batches_created);
        assert!(
            updated_stats.total_transactions_processed > initial_stats.total_transactions_processed
        );
    }

    #[tokio::test]
    async fn test_concurrent_batch_creation() {
        let manager = Arc::new(setup_batch_manager().await);

        let mut handles = Vec::new();
        for i in 0..5 {
            let manager_clone = manager.clone();
            let operator = test_address(50 + i);
            let shard_id = ShardId::new(0).unwrap();

            let handle = tokio::spawn(async move {
                manager_clone
                    .register_operator(operator, shard_id, Balance::from_egoc(10000))
                    .await
                    .unwrap();

                let transactions = vec![test_transaction(90 + i)];
                let state_root = test_hash(250 + i);
                manager_clone
                    .create_batch(operator, shard_id, transactions, state_root, 1)
                    .await
            });
            handles.push(handle);
        }

        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok());
        }
    }

    #[tokio::test]
    async fn test_deploy_stats_snapshot() {
        let snapshot = DeployStatsSnapshot {
            epoch: 5,
            total_deploys: 100,
            successful_deploys: 90,
            failed_deploys: 10,
            human_verified_deploys: 80,
            ai_flagged_deploys: 5,
            total_credits_consumed: 5000,
            total_pob_burned: 2000,
        };

        assert_eq!(snapshot.epoch, 5);
        assert_eq!(snapshot.total_deploys, 100);
        assert_eq!(snapshot.successful_deploys, 90);
        assert_eq!(snapshot.failed_deploys, 10);
    }

    #[tokio::test]
    async fn test_batch_with_ru_and_storage() {
        let manager = setup_batch_manager().await;
        let operator = test_address(60);
        let shard_id = ShardId::new(0).unwrap();

        manager
            .register_operator(operator, shard_id, Balance::from_egoc(10000))
            .await
            .unwrap();

        let transactions = vec![test_transaction(100)];
        let state_root = test_hash(255);

        let batch_id = manager
            .create_batch(operator, shard_id, transactions, state_root, 1)
            .await
            .unwrap();

        let batch = manager.get_pending_batch(&batch_id).unwrap();
        assert!(batch.ru_consumed >= 0);
        assert!(batch.storage_used >= 0);
    }

    #[tokio::test]
    async fn test_da_retrieval_stats_default() {
        let stats = DaRetrievalStats::default();
        assert_eq!(stats.total_chunks_uploaded, 0);
        assert_eq!(stats.total_chunks_retrieved, 0);
        assert_eq!(stats.failed_retrievals, 0);
        assert_eq!(stats.avg_retrieval_time_ms, 0);
    }

    #[tokio::test]
    async fn test_proof_verification_disabled() {
        let mut config = BatchConfig::default();
        config.proof_verification_enabled = false;
        let drs_manager = Arc::new(DRSManager::new(DRSConfig::default()));
        let deploy_policy = Arc::new(DeployPolicyManager::new(DeployPolicyConfig::default()));
        let manager = BatchManager::new(config, drs_manager, deploy_policy);
        let operator = test_address(61);
        let shard_id = ShardId::new(0).unwrap();
        manager
            .register_operator(operator, shard_id, Balance::from_egoc(10000))
            .await
            .unwrap();
        let transactions = vec![test_transaction(101)];
        let state_root = test_hash(0);
        let batch_id = manager
            .create_batch(operator, shard_id, transactions, state_root, 1)
            .await
            .unwrap();
        manager
            .set_batch_ready(&batch_id, test_hash(1))
            .await
            .unwrap();
        let result = manager
            .commit_batch(&batch_id, None, vec![1, 2, 3], BlockHeight::new(100))
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_slashing_disabled() {
        let mut config = BatchConfig::default();
        config.slashing_enabled = false;

        let drs_manager = Arc::new(DRSManager::new(DRSConfig::default()));
        let deploy_policy = Arc::new(DeployPolicyManager::new(DeployPolicyConfig::default()));
        let manager = BatchManager::new(config, drs_manager, deploy_policy);

        let operator = test_address(62);
        let shard_id = ShardId::new(0).unwrap();

        manager
            .register_operator(operator, shard_id, Balance::from_egoc(10000))
            .await
            .unwrap();

        let result = manager
            .slash_operator(operator, "Test".to_string(), Balance::from_egoc(100))
            .await;
        assert!(result.is_ok());

        let info = manager.get_operator_info(&operator).unwrap();
        assert_eq!(info.total_slashed, Balance::ZERO);
    }
}
