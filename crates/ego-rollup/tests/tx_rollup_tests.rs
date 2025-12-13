mod tx_rollup_tests {
    use ego_core::{
        Address, Balance, Hash, ShardId, Timestamp,
        crypto::KeyPair,
        transaction::{Transaction, TransactionPayload},
    };
    use ego_rollup::{
        config::RollupConfig,
        tx_rollup::{ChallengeStatus, ChallengeType, TxRollupChallenge, TxRollupOperator},
        types::RollupTransaction,
    };

    fn create_test_config() -> RollupConfig {
        RollupConfig::default()
    }

    fn create_test_transaction() -> RollupTransaction {
        let keypair = KeyPair::generate();
        let from_addr = Address::from_public_key(&keypair.dilithium_public_key());
        let to_addr = Address::new([2u8; 20]);

        let mut inner = Transaction::new(
            from_addr,
            1,
            TransactionPayload::Transfer {
                to: to_addr,
                amount: Balance::from_egoc(100),
                memo: None,
                stealth_mode: false,
            },
            ShardId::new(0).unwrap(),
            None,
            1,
        );
        inner
            .sign(&keypair, false)
            .expect("Failed to sign transaction");

        RollupTransaction::new(inner, 1, 1000)
    }

    #[tokio::test]
    async fn test_tx_rollup_creation() {
        let config = create_test_config();
        let rollup_id = [1u8; 16];
        let region_id = 1;
        let keypair = KeyPair::generate();
        let operator = TxRollupOperator::new(config, rollup_id, region_id, keypair, 1, 1).unwrap();

        assert_eq!(operator.get_rollup_id(), rollup_id);
        assert_eq!(operator.get_chain_id(), 1);
        assert_eq!(operator.get_network_id(), 1);
    }

    #[tokio::test]
    async fn test_transaction_submission() {
        let config = create_test_config();
        let rollup_id = [1u8; 16];
        let keypair = KeyPair::generate();
        let operator = TxRollupOperator::new(config, rollup_id, 1, keypair, 1, 1).unwrap();

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
        let operator = TxRollupOperator::new(config, rollup_id, 1, keypair, 1, 1).unwrap();

        for _ in 0..5 {
            let tx = create_test_transaction();
            operator.submit_transaction(tx).await.unwrap();
        }

        let batch = operator.build_batch(10).await.unwrap();
        assert_eq!(batch.transactions.len(), 5);
        assert!(batch.validate().is_ok());
        assert!(batch.ru_total > 0);

        let metrics = operator.get_metrics().await;
        assert_eq!(metrics.batches_created, 1);
        assert_eq!(metrics.transactions_processed, 5);
    }

    #[tokio::test]
    async fn test_commitment_posting() {
        let config = create_test_config();
        let rollup_id = [1u8; 16];
        let keypair = KeyPair::generate();
        let operator = TxRollupOperator::new(config, rollup_id, 1, keypair, 1, 1).unwrap();

        for _ in 0..3 {
            let tx = create_test_transaction();
            operator.submit_transaction(tx).await.unwrap();
        }

        let batch = operator.build_batch(10).await.unwrap();
        let commitment_hash = operator.post_commitment(batch).await.unwrap();
        assert_ne!(commitment_hash, Hash::ZERO);

        let metrics = operator.get_metrics().await;
        assert_eq!(metrics.commitments_posted, 1);
    }

    #[test]
    fn test_inclusion_proof_verification() {
        let tx_hash = Hash::new([1u8; 32]);
        let sibling = Hash::new([2u8; 32]);
        let root = ego_core::crypto::hash_multiple(&[tx_hash.as_bytes(), sibling.as_bytes()]);

        let proof = ego_rollup::tx_rollup::InclusionProof {
            tx_hash,
            merkle_path: vec![sibling],
            leaf_index: 0,
            root,
        };
        assert!(proof.verify());
    }

    #[tokio::test]
    async fn test_challenge_defense() {
        let config = create_test_config();
        let rollup_id = [1u8; 16];
        let keypair = KeyPair::generate();
        let operator = TxRollupOperator::new(config, rollup_id, 1, keypair, 1, 1).unwrap();

        for _ in 0..2 {
            let tx = create_test_transaction();
            operator.submit_transaction(tx).await.unwrap();
        }

        let batch = operator.build_batch(10).await.unwrap();
        let batch_id = batch.batch_id;
        let _commitment_hash = operator.post_commitment(batch).await.unwrap();

        let challenge = TxRollupChallenge {
            challenge_id: Hash::new([3u8; 32]),
            commitment_hash: batch_id,
            challenger: Address::new([4u8; 20]),
            challenge_type: ChallengeType::DAUnavailable,
            fraud_proof: None,
            submitted_at: Timestamp::now(),
            deadline: Timestamp::from_millis(Timestamp::now().as_millis() + 86400000),
            status: ChallengeStatus::Pending,
            bond_amount: Balance::from_egoc(1000),
            evidence: vec![],
        };

        assert!(operator.handle_challenge(challenge).await.is_ok());

        let metrics = operator.get_metrics().await;
        assert_eq!(metrics.challenges_received, 1);
        assert_eq!(metrics.challenges_defended, 1);
    }

    #[tokio::test]
    async fn test_commitment_signature_verification() {
        let config = create_test_config();
        let rollup_id = [1u8; 16];
        let keypair = KeyPair::generate();
        let operator = TxRollupOperator::new(config, rollup_id, 1, keypair.clone(), 1, 1).unwrap();

        for _ in 0..2 {
            let tx = create_test_transaction();
            operator.submit_transaction(tx).await.unwrap();
        }

        let batch = operator.build_batch(10).await.unwrap();
        let commitment_hash = operator.post_commitment(batch).await.unwrap();

        let commitment_opt = operator.get_commitment(commitment_hash).await;
        assert!(commitment_opt.is_some());

        let (commitment, _) = commitment_opt.unwrap();
        let pubkey = keypair.dilithium_public_key();
        assert!(commitment.verify_signature(&pubkey).unwrap());
    }

    #[tokio::test]
    async fn test_cleanup_old_data() {
        let config = create_test_config();
        let rollup_id = [1u8; 16];
        let keypair = KeyPair::generate();
        let operator = TxRollupOperator::new(config, rollup_id, 1, keypair, 1, 1).unwrap();

        for _ in 0..2 {
            let tx = create_test_transaction();
            operator.submit_transaction(tx).await.unwrap();
        }
        let batch = operator.build_batch(10).await.unwrap();
        let _ = operator.post_commitment(batch).await.unwrap();

        let cleaned = operator.cleanup_old_data(100).await;
        assert!(cleaned >= 0);
    }
}
