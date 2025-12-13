mod verifier_tests {
    use ego_core::{
        Address, Balance, DualSignature, EpochNumber, Hash, ShardId, Timestamp,
        crypto::KeyPair,
        transaction::{Transaction, TransactionPayload},
    };
    use ego_rollup::{
        commitment::RollupCommitment,
        da::{CellularSafeConfig, DataAvailability},
        fraud::FraudProofVerifier,
        state::RollupState,
        types::RollupTransaction,
        verifier::{IssueType, RollupVerifier},
    };

    fn mock_address(id: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[0] = id;
        Address::new(bytes)
    }

    fn create_test_commitment(
        operator: Address,
        operator_sig: DualSignature,
        tx_root: Hash,
        state_root: Hash,
        da_root: Hash,
        proofs_root: Hash,
        tx_count: u32,
        chain_id: u32,
        network_id: u32,
        gas_used: u64,
        timestamp: Timestamp,
    ) -> RollupCommitment {
        RollupCommitment {
            rollup_id: "test-rollup".to_string(),
            operator,
            previous_state_root: state_root,
            state_root,
            tx_root,
            da_root,
            proofs_root,
            tx_count,
            block_range: (0, 0),
            l1_block_number: 1000,
            timestamp,
            gas_used,
            version: 1,
            protocol_version: ego_core::PROTOCOL_VERSION,
            chain_id,
            network_id,
            epoch: EpochNumber(5),
            commitment_hash: Hash::ZERO,
            operator_signature: operator_sig,
            events_root_post: Hash::ZERO,
            events_root_poc: Hash::ZERO,
            receipts_root: Hash::ZERO,
            proof_data: vec![],
            post_proofs_included: 10,
            poc_proofs_included: 5,
            ru_consumed: 0,
            cross_shard_receipts_count: 0,
            cellular_optimized: true,
            da_chunks: vec![],
            deploy_credits_used: 0,
            ai_flagged_deploys: 0,
            human_verified_deploys: 0,
            pq_signatures_used: 1,
            legacy_signatures_used: 0,
            storage_credits_used: 0,
            shard_id: ShardId(0),
            fraud_proof_window: 100,
            min_validity_proof: vec![1],
            drs_weighted_rewards: false,
        }
    }

    #[tokio::test]
    async fn test_verifier_creation() {
        let fraud_verifier = FraudProofVerifier::new(0.9, 24);
        let cellular_safe_config = CellularSafeConfig {
            enabled: true,
            max_chunk_size: 256 * 1024,
            max_batch_size: 100,
            compression_required: true,
            monthly_limit_bytes: 10 * 1024 * 1024 * 1024,
        };
        let da_manager =
            DataAvailability::new(64, 32, 32768, true, 600_000, cellular_safe_config, 1).unwrap();

        let verifier = RollupVerifier::new(fraud_verifier, da_manager, 100, true, false, 1, 1);

        let stats = verifier.get_verification_stats();
        assert_eq!(stats.total_verifications, 0);
    }

    #[tokio::test]
    async fn test_verify_chain_id_mismatch() {
        let keypair = KeyPair::generate();
        let operator = Address::from_public_key(&keypair.dilithium_public_key());
        let pubkey = keypair.dilithium_public_key();

        let fraud_verifier = FraudProofVerifier::new(0.9, 24);
        let cellular_safe_config = CellularSafeConfig {
            enabled: true,
            max_chunk_size: 256 * 1024,
            max_batch_size: 100,
            compression_required: true,
            monthly_limit_bytes: 10 * 1024 * 1024 * 1024,
        };
        let da_manager =
            DataAvailability::new(64, 32, 32768, true, 600_000, cellular_safe_config, 1).unwrap();

        let mut verifier = RollupVerifier::new(fraud_verifier, da_manager, 100, true, false, 1, 1)
            .with_min_da_availability(0.0);
        verifier.register_operator_pubkey(operator, pubkey);

        let state = RollupState::new(1, 1);
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let mut inner = Transaction::new(
            from,
            1,
            TransactionPayload::Transfer {
                to: mock_address(2),
                amount: Balance::from_egoc(100),
                stealth_mode: false,
                memo: None,
            },
            ShardId(0),
            None,
            1,
        );
        inner.sign(&keypair, true).unwrap();
        let tx = RollupTransaction::new(inner, 1, 0);
        let tx_hashes = vec![tx.hash().to_vec()];
        let tx_root = ego_core::crypto::MerkleTree::build(tx_hashes)
            .root_hash()
            .unwrap_or(Hash::ZERO);
        let state_root = state.get_state_root();

        let commitment = create_test_commitment(
            operator,
            DualSignature::new(None, None),
            tx_root,
            state_root,
            tx_root,
            tx_root,
            1,
            2,
            1,
            21000,
            Timestamp::now(),
        );

        let result = verifier
            .verify_commitment(&commitment, &state, &[tx])
            .await
            .unwrap();
        assert!(!result.is_valid);
        assert!(
            result
                .issues
                .iter()
                .any(|i| matches!(i.issue_type, IssueType::ChainIdMismatch))
        );
    }

    #[test]
    fn test_verification_stats_default() {
        let stats = ego_rollup::verifier::VerificationStats::default();
        assert_eq!(stats.total_verifications, 0);
    }

    #[tokio::test]
    async fn test_verify_missing_pq_signature() {
        let keypair = KeyPair::generate();
        let operator = Address::from_public_key(&keypair.dilithium_public_key());

        let fraud_verifier = FraudProofVerifier::new(0.9, 24);
        let cellular_safe_config = CellularSafeConfig {
            enabled: true,
            max_chunk_size: 256 * 1024,
            max_batch_size: 100,
            compression_required: true,
            monthly_limit_bytes: 10 * 1024 * 1024 * 1024,
        };
        let da_manager =
            DataAvailability::new(64, 32, 32768, true, 600_000, cellular_safe_config, 1).unwrap();

        let mut verifier = RollupVerifier::new(fraud_verifier, da_manager, 100, true, false, 1, 1);
        verifier.register_operator_pubkey(operator, keypair.dilithium_public_key());

        let state = RollupState::new(1, 1);
        let commitment = create_test_commitment(
            operator,
            DualSignature::new(None, None),
            Hash::ZERO,
            state.get_state_root(),
            Hash::ZERO,
            Hash::ZERO,
            0,
            1,
            1,
            0,
            Timestamp::now(),
        );

        let result = verifier
            .verify_commitment(&commitment, &state, &[])
            .await
            .unwrap();

        assert!(!result.is_valid);
        assert!(
            result
                .issues
                .iter()
                .any(|i| matches!(i.issue_type, IssueType::PQSignatureRequired))
        );
    }

    #[tokio::test]
    async fn test_verify_ed25519_tx_rejected() {
        let keypair = KeyPair::generate();
        let operator = Address::from_public_key(&keypair.dilithium_public_key());

        let fraud_verifier = FraudProofVerifier::new(0.9, 24);
        let cellular_safe_config = CellularSafeConfig {
            enabled: true,
            max_chunk_size: 256 * 1024,
            max_batch_size: 100,
            compression_required: true,
            monthly_limit_bytes: 10 * 1024 * 1024 * 1024,
        };
        let da_manager =
            DataAvailability::new(64, 32, 32768, true, 600_000, cellular_safe_config, 1).unwrap();

        let mut verifier = RollupVerifier::new(fraud_verifier, da_manager, 100, true, false, 1, 1);
        verifier.register_operator_pubkey(operator, keypair.dilithium_public_key());

        let state = RollupState::new(1, 1);
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let mut inner = Transaction::new(
            from,
            1,
            TransactionPayload::Transfer {
                to: mock_address(2),
                amount: Balance::from_egoc(100),
                stealth_mode: false,
                memo: None,
            },
            ShardId(0),
            None,
            1,
        );
        inner.sign(&keypair, false).unwrap();
        let tx = RollupTransaction::new(inner, 1, 0);

        let tx_hashes = vec![tx.hash().to_vec()];
        let tx_root = ego_core::crypto::MerkleTree::build(tx_hashes)
            .root_hash()
            .unwrap_or(Hash::ZERO);
        let state_root = state.get_state_root();

        let commitment = create_test_commitment(
            operator,
            DualSignature::new(None, None),
            tx_root,
            state_root,
            tx_root,
            tx_root,
            1,
            1,
            1,
            21000,
            Timestamp::now(),
        );

        let result = verifier
            .verify_commitment(&commitment, &state, &[tx])
            .await
            .unwrap();

        assert!(!result.is_valid);
        assert!(result.issues.iter().any(|i| matches!(
            i.issue_type,
            IssueType::InvalidTransactionInclusion
        ) || matches!(
            i.issue_type,
            IssueType::PQSignatureRequired
        )));
    }
}
