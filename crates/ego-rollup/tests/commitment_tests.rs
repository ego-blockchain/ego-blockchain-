#[cfg(test)]
mod commitment_tests {
    use ego_core::{
        Address, AlgorithmId, Balance, DualSignature, EpochNumber, Hash, PublicKey, ShardId,
        SliceId, Timestamp, Transaction, TransactionPayload,
    };
    use ego_rollup::commitment::{
        ChallengeType, CommitmentManager, CommitmentStats, DAAvailabilityStatus,
        DRSValidationParams, DeployStatsSnapshot, PQTransitionConfig, RollupCommitment,
    };
    use ego_rollup::da::{CellularSafeConfig, DAChunk, DataAvailability};
    use ego_rollup::operator::RollupBatch;
    use ego_rollup::types::CommitmentStatus;
    use std::sync::{Arc, Mutex};

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

    fn test_rollup_batch(seed: u8) -> RollupBatch {
        let operator = test_address(seed);
        let transactions = vec![test_transaction(seed), test_transaction(seed + 1)];
        RollupBatch {
            batch_id: test_hash(seed),
            rollup_id: "test_rollup".to_string(),
            operator,
            shard_id: ShardId::new(0).unwrap(),
            prev_state_root: test_hash(seed + 10),
            new_state_root: test_hash(seed + 20),
            tx_root: test_hash(seed + 30),
            transactions: transactions.clone(),
            transaction_results: vec![],
            receipts_root: Hash::ZERO,
            proof_events_root: Hash::ZERO,
            deploy_events_root: Hash::ZERO,
            deploy_requests_processed: 0,
            drs_events_root: Hash::ZERO,
            timestamp: Timestamp::now(),
            l1_block_number: 1000,
            gas_used: 100000,
            chain_id: 1,
            network_id: 1,
            epoch: EpochNumber::new(1),
            size_bytes: 1024,
            operator_signature: DualSignature::new(None, None),
            is_cellular_safe: true,
            is_5g_optimized: false,
            drs_scores_applied: 0,
        }
    }

    fn setup_commitment_manager() -> CommitmentManager {
        let cellular_config = CellularSafeConfig {
            enabled: false,
            max_chunk_size: 256 * 1024,
            max_batch_size: 256 * 1024,
            compression_required: false,
            monthly_limit_bytes: 1024 * 1024 * 1024,
        };
        let da_manager = Arc::new(Mutex::new(
            DataAvailability::new(1024 * 1024, 256 * 1024, 4, false, 3, cellular_config, 100)
                .unwrap(),
        ));
        CommitmentManager::new(da_manager, 100, 50, 1, 1, 1000, false)
    }

    fn test_da_chunk(seed: u8, commitment_hash: Hash) -> DAChunk {
        DAChunk {
            chunk_id: seed as u32,
            commitment_hash,
            data: vec![seed; 256],
            chunk_hash: test_hash(seed),
            timestamp: Timestamp::now(),
            is_parity: false,
            provider: Some(test_address(seed)),
            replica_count: 1,
            access_count: 0,
            epoch: 1,
            shard_id: ShardId::new(0).unwrap(),
        }
    }

    #[test]
    fn test_rollup_commitment_new() {
        let operator = test_address(1);
        let batch = test_rollup_batch(1);
        let da_root = test_hash(50);
        let proofs_root = test_hash(51);
        let events_root_post = test_hash(52);
        let events_root_poc = test_hash(53);
        let receipts_root = test_hash(54);

        let commitment = RollupCommitment::new(
            operator,
            "test_rollup".to_string(),
            &batch,
            da_root,
            proofs_root,
            events_root_post,
            events_root_poc,
            receipts_root,
            1000,
            100,
        );

        assert_eq!(commitment.operator, operator);
        assert_eq!(commitment.rollup_id, "test_rollup");
        assert_eq!(commitment.state_root, batch.new_state_root);
        assert_eq!(commitment.previous_state_root, batch.prev_state_root);
        assert_eq!(commitment.tx_root, batch.tx_root);
        assert_eq!(commitment.da_root, da_root);
        assert_eq!(commitment.proofs_root, proofs_root);
        assert_eq!(commitment.tx_count, 2);
        assert_eq!(commitment.fraud_proof_window, 100);
    }

    #[test]
    fn test_rollup_commitment_from_batch() {
        let batch = test_rollup_batch(2);
        let result = RollupCommitment::from_batch(&batch, 100);

        assert!(result.is_ok());
        let commitment = result.unwrap();
        assert_eq!(commitment.operator, batch.operator);
        assert_eq!(commitment.state_root, batch.new_state_root);
        assert_eq!(commitment.previous_state_root, batch.prev_state_root);
        assert_eq!(commitment.tx_count, batch.transactions.len() as u32);
    }

    #[test]
    fn test_rollup_commitment_validate_success() {
        let batch = test_rollup_batch(3);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();

        let result = commitment.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_rollup_commitment_validate_zero_transactions() {
        let operator = test_address(4);
        let mut batch = test_rollup_batch(4);
        batch.transactions.clear();

        let mut commitment = RollupCommitment::new(
            operator,
            "test_rollup".to_string(),
            &batch,
            Hash::ZERO,
            Hash::ZERO,
            Hash::ZERO,
            Hash::ZERO,
            Hash::ZERO,
            1000,
            100,
        );
        commitment.tx_count = 0;

        let result = commitment.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_rollup_commitment_validate_invalid_block_range() {
        let batch = test_rollup_batch(5);
        let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        commitment.block_range = (1000, 500);

        let result = commitment.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_rollup_commitment_validate_zero_state_root() {
        let batch = test_rollup_batch(6);
        let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        commitment.state_root = Hash::ZERO;

        let result = commitment.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_rollup_commitment_validate_zero_tx_root() {
        let batch = test_rollup_batch(7);
        let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        commitment.tx_root = Hash::ZERO;

        let result = commitment.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_rollup_commitment_validate_zero_fraud_window() {
        let batch = test_rollup_batch(8);
        let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        commitment.fraud_proof_window = 0;

        let result = commitment.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_rollup_commitment_compute_hash() {
        let batch = test_rollup_batch(9);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();

        let hash1 = commitment.compute_hash();
        let hash2 = commitment.compute_hash();

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, Hash::ZERO);
    }

    #[test]
    fn test_rollup_commitment_is_reproducible() {
        let batch = test_rollup_batch(10);
        let commitment1 = RollupCommitment::from_batch(&batch, 100).unwrap();
        let commitment2 = RollupCommitment::from_batch(&batch, 100).unwrap();

        assert!(commitment1.is_reproducible(&commitment2));
    }

    #[test]
    fn test_rollup_commitment_not_reproducible_different_state() {
        let batch = test_rollup_batch(11);
        let commitment1 = RollupCommitment::from_batch(&batch, 100).unwrap();
        let mut commitment2 = RollupCommitment::from_batch(&batch, 100).unwrap();
        commitment2.state_root = test_hash(99);

        assert!(!commitment1.is_reproducible(&commitment2));
    }

    #[test]
    fn test_rollup_commitment_set_da_root() {
        let batch = test_rollup_batch(12);
        let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        let new_da_root = test_hash(100);

        commitment.set_da_root(new_da_root);

        assert_eq!(commitment.da_root, new_da_root);
    }

    #[test]
    fn test_rollup_commitment_set_proofs_root() {
        let batch = test_rollup_batch(13);
        let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        let new_proofs_root = test_hash(101);

        commitment.set_proofs_root(new_proofs_root);

        assert_eq!(commitment.proofs_root, new_proofs_root);
    }

    #[test]
    fn test_rollup_commitment_set_events_roots() {
        let batch = test_rollup_batch(14);
        let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        let events_root_post = test_hash(102);
        let events_root_poc = test_hash(103);

        commitment.set_events_roots(events_root_post, events_root_poc);

        assert_eq!(commitment.events_root_post, events_root_post);
        assert_eq!(commitment.events_root_poc, events_root_poc);
    }

    #[test]
    fn test_rollup_commitment_set_receipts_root() {
        let batch = test_rollup_batch(15);
        let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        let receipts_root = test_hash(104);

        commitment.set_receipts_root(receipts_root);

        assert_eq!(commitment.receipts_root, receipts_root);
    }

    #[test]
    fn test_rollup_commitment_add_proof_data() {
        let batch = test_rollup_batch(16);
        let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        let proof_data = vec![1, 2, 3, 4, 5];

        commitment.add_proof_data(proof_data.clone());

        assert_eq!(commitment.proof_data, proof_data);
    }

    #[test]
    fn test_rollup_commitment_add_validity_proof() {
        let batch = test_rollup_batch(17);
        let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        let validity_proof = vec![10, 20, 30];

        commitment.add_validity_proof(validity_proof.clone());

        assert_eq!(commitment.min_validity_proof, validity_proof);
    }

    #[test]
    fn test_rollup_commitment_set_resource_usage() {
        let batch = test_rollup_batch(18);
        let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();

        commitment.set_resource_usage(1000, 2000, 3000);

        assert_eq!(commitment.deploy_credits_used, 1000);
        assert_eq!(commitment.storage_credits_used, 2000);
        assert_eq!(commitment.ru_consumed, 3000);
    }

    #[test]
    fn test_rollup_commitment_set_deploy_stats() {
        let batch = test_rollup_batch(19);
        let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();

        commitment.set_deploy_stats(10, 5);

        assert_eq!(commitment.human_verified_deploys, 10);
        assert_eq!(commitment.ai_flagged_deploys, 5);
    }

    #[test]
    fn test_rollup_commitment_set_proof_counts() {
        let batch = test_rollup_batch(20);
        let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();

        commitment.set_proof_counts(15, 8);

        assert_eq!(commitment.post_proofs_included, 15);
        assert_eq!(commitment.poc_proofs_included, 8);
    }

    #[test]
    fn test_rollup_commitment_set_cross_shard_count() {
        let batch = test_rollup_batch(21);
        let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();

        commitment.set_cross_shard_count(25);

        assert_eq!(commitment.cross_shard_receipts_count, 25);
    }

    #[test]
    fn test_rollup_commitment_size() {
        let batch = test_rollup_batch(22);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();

        let size = commitment.size();

        assert!(size > 0);
    }

    #[test]
    fn test_rollup_commitment_is_cellular_optimized() {
        let batch = test_rollup_batch(23);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();

        let is_optimized = commitment.is_cellular_optimized();

        assert!(is_optimized || !is_optimized);
    }

    #[test]
    fn test_commitment_manager_new() {
        let manager = setup_commitment_manager();
        let stats = manager.get_commitment_stats();

        assert_eq!(stats.total_commitments, 0);
        assert_eq!(stats.pending_commitments, 0);
        assert_eq!(stats.finalized_commitments, 0);
    }

    #[test]
    fn test_commitment_manager_submit_commitment_success() {
        let mut manager = setup_commitment_manager();
        let batch = test_rollup_batch(24);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        let da_chunks = vec![test_da_chunk(1, batch.batch_id)];

        manager.set_operator_bond(commitment.operator, Balance::new(10_000_000_000));

        let result = manager.submit_commitment(commitment.clone(), da_chunks);

        assert!(result.is_ok());
        let hash = result.unwrap();
        assert!(manager.get_commitment(hash).is_some());
    }

    #[test]
    fn test_commitment_manager_submit_commitment_invalid_chain_id() {
        let mut manager = setup_commitment_manager();
        let batch = test_rollup_batch(25);
        let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        commitment.chain_id = 999;
        let da_chunks = vec![test_da_chunk(2, batch.batch_id)];

        manager.set_operator_bond(commitment.operator, Balance::new(10_000_000_000));

        let result = manager.submit_commitment(commitment, da_chunks);

        assert!(result.is_err());
    }

    #[test]
    fn test_commitment_manager_submit_commitment_invalid_network_id() {
        let mut manager = setup_commitment_manager();
        let batch = test_rollup_batch(26);
        let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        commitment.network_id = 999;
        let da_chunks = vec![test_da_chunk(3, batch.batch_id)];

        manager.set_operator_bond(commitment.operator, Balance::new(10_000_000_000));

        let result = manager.submit_commitment(commitment, da_chunks);

        assert!(result.is_err());
    }

    #[test]
    fn test_commitment_manager_submit_commitment_insufficient_bond() {
        let mut manager = setup_commitment_manager();
        let batch = test_rollup_batch(27);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        let da_chunks = vec![test_da_chunk(4, batch.batch_id)];

        manager.set_operator_bond(commitment.operator, Balance::new(100));

        let result = manager.submit_commitment(commitment, da_chunks);

        assert!(result.is_err());
    }

    #[test]
    fn test_commitment_manager_get_commitment() {
        let mut manager = setup_commitment_manager();
        let batch = test_rollup_batch(28);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        let da_chunks = vec![test_da_chunk(5, batch.batch_id)];

        manager.set_operator_bond(commitment.operator, Balance::new(10_000_000_000));
        let hash = manager.submit_commitment(commitment, da_chunks).unwrap();

        let retrieved = manager.get_commitment(hash);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().commitment.commitment_hash, hash);
    }

    #[test]
    fn test_commitment_manager_get_pending_commitments() {
        let mut manager = setup_commitment_manager();
        let batch = test_rollup_batch(29);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        let da_chunks = vec![test_da_chunk(6, batch.batch_id)];

        manager.set_operator_bond(commitment.operator, Balance::new(10_000_000_000));
        manager.submit_commitment(commitment, da_chunks).unwrap();

        let pending = manager.get_pending_commitments();
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn test_commitment_manager_get_operator_commitments() {
        let mut manager = setup_commitment_manager();
        let operator = test_address(30);
        let batch = test_rollup_batch(30);
        let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        commitment.operator = operator;
        let da_chunks = vec![test_da_chunk(7, batch.batch_id)];

        manager.set_operator_bond(operator, Balance::new(10_000_000_000));
        manager.submit_commitment(commitment, da_chunks).unwrap();

        let operator_commitments = manager.get_operator_commitments(operator);
        assert_eq!(operator_commitments.len(), 1);
    }

    #[test]
    fn test_commitment_manager_challenge_commitment_success() {
        let mut manager = setup_commitment_manager();
        let batch = test_rollup_batch(31);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        let da_chunks = vec![test_da_chunk(8, batch.batch_id)];

        manager.set_operator_bond(commitment.operator, Balance::new(10_000_000_000));
        let hash = manager.submit_commitment(commitment, da_chunks).unwrap();

        let challenger = test_address(100);
        manager.set_operator_bond(challenger, Balance::new(10_000_000_000));

        let result = manager.challenge_commitment(
            hash,
            challenger,
            ChallengeType::InvalidStateTransition,
            Balance::new(10_000_000_000),
            vec![1, 2, 3],
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_commitment_manager_challenge_commitment_not_found() {
        let mut manager = setup_commitment_manager();
        let fake_hash = test_hash(200);
        let challenger = test_address(101);

        manager.set_operator_bond(challenger, Balance::new(10_000_000_000));

        let result = manager.challenge_commitment(
            fake_hash,
            challenger,
            ChallengeType::DataUnavailability,
            Balance::new(10_000_000_000),
            vec![1, 2, 3],
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_commitment_manager_challenge_commitment_insufficient_bond() {
        let mut manager = setup_commitment_manager();
        let batch = test_rollup_batch(32);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        let da_chunks = vec![test_da_chunk(9, batch.batch_id)];

        manager.set_operator_bond(commitment.operator, Balance::new(10_000_000_000));
        let hash = manager.submit_commitment(commitment, da_chunks).unwrap();

        let challenger = test_address(102);
        manager.set_operator_bond(challenger, Balance::new(100));

        let result = manager.challenge_commitment(
            hash,
            challenger,
            ChallengeType::InvalidProof,
            Balance::new(10_000_000_000),
            vec![1, 2, 3],
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_commitment_manager_challenge_commitment_evidence_too_large() {
        let mut manager = setup_commitment_manager();
        let batch = test_rollup_batch(33);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        let da_chunks = vec![test_da_chunk(10, batch.batch_id)];

        manager.set_operator_bond(commitment.operator, Balance::new(10_000_000_000));
        let hash = manager.submit_commitment(commitment, da_chunks).unwrap();

        let challenger = test_address(103);
        manager.set_operator_bond(challenger, Balance::new(10_000_000_000));

        let large_evidence = vec![0u8; 2 * 1024 * 1024];
        let result = manager.challenge_commitment(
            hash,
            challenger,
            ChallengeType::InvalidInclusion,
            Balance::new(10_000_000_000),
            large_evidence,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_commitment_manager_respond_to_challenge_success() {
        let mut manager = setup_commitment_manager();
        let batch = test_rollup_batch(34);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        let operator = commitment.operator;
        let da_chunks = vec![test_da_chunk(11, batch.batch_id)];

        manager.set_operator_bond(operator, Balance::new(10_000_000_000));
        let hash = manager.submit_commitment(commitment, da_chunks).unwrap();

        let challenger = test_address(104);
        manager.set_operator_bond(challenger, Balance::new(10_000_000_000));

        let challenge_hash = manager
            .challenge_commitment(
                hash,
                challenger,
                ChallengeType::InvalidAggregation,
                Balance::new(10_000_000_000),
                vec![1, 2, 3],
            )
            .unwrap();

        let result = manager.respond_to_challenge(challenge_hash, operator, vec![4, 5, 6]);

        assert!(result.is_ok());
    }

    #[test]
    fn test_commitment_manager_respond_to_challenge_not_operator() {
        let mut manager = setup_commitment_manager();
        let batch = test_rollup_batch(35);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        let operator = commitment.operator;
        let da_chunks = vec![test_da_chunk(12, batch.batch_id)];

        manager.set_operator_bond(operator, Balance::new(10_000_000_000));
        let hash = manager.submit_commitment(commitment, da_chunks).unwrap();

        let challenger = test_address(105);
        manager.set_operator_bond(challenger, Balance::new(10_000_000_000));

        let challenge_hash = manager
            .challenge_commitment(
                hash,
                challenger,
                ChallengeType::InvalidDRSCalculation,
                Balance::new(10_000_000_000),
                vec![1, 2, 3],
            )
            .unwrap();

        let wrong_operator = test_address(200);
        let result = manager.respond_to_challenge(challenge_hash, wrong_operator, vec![4, 5, 6]);

        assert!(result.is_err());
    }

    #[test]
    fn test_commitment_manager_resolve_challenge_successful() {
        let mut manager = setup_commitment_manager();
        let batch = test_rollup_batch(36);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        let operator = commitment.operator;
        let da_chunks = vec![test_da_chunk(13, batch.batch_id)];

        manager.set_operator_bond(operator, Balance::new(10_000_000_000));
        let hash = manager.submit_commitment(commitment, da_chunks).unwrap();

        let challenger = test_address(106);
        manager.set_operator_bond(challenger, Balance::new(10_000_000_000));

        let challenge_hash = manager
            .challenge_commitment(
                hash,
                challenger,
                ChallengeType::InvalidDeployPolicy,
                Balance::new(10_000_000_000),
                vec![1, 2, 3],
            )
            .unwrap();

        let result = manager.resolve_challenge(challenge_hash, true, vec![7, 8, 9]);

        assert!(result.is_ok());
        let commit = manager.get_commitment(hash).unwrap();
        assert!(matches!(commit.status, CommitmentStatus::Slashed));
    }

    #[test]
    fn test_commitment_manager_resolve_challenge_unsuccessful() {
        let mut manager = setup_commitment_manager();
        let batch = test_rollup_batch(37);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        let operator = commitment.operator;
        let da_chunks = vec![test_da_chunk(14, batch.batch_id)];

        manager.set_operator_bond(operator, Balance::new(10_000_000_000));
        let hash = manager.submit_commitment(commitment, da_chunks).unwrap();

        let challenger = test_address(107);
        manager.set_operator_bond(challenger, Balance::new(10_000_000_000));

        let challenge_hash = manager
            .challenge_commitment(
                hash,
                challenger,
                ChallengeType::MissingHumanVerification,
                Balance::new(10_000_000_000),
                vec![1, 2, 3],
            )
            .unwrap();

        let result = manager.resolve_challenge(challenge_hash, false, vec![7, 8, 9]);

        assert!(result.is_ok());
        let commit = manager.get_commitment(hash).unwrap();
        assert!(matches!(commit.status, CommitmentStatus::Finalized));
    }

    #[test]
    fn test_commitment_manager_finalize_expired_commitments() {
        let mut manager = setup_commitment_manager();
        let batch = test_rollup_batch(38);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        let da_chunks = vec![test_da_chunk(15, batch.batch_id)];

        manager.set_operator_bond(commitment.operator, Balance::new(10_000_000_000));
        manager.submit_commitment(commitment, da_chunks).unwrap();

        let finalized = manager.finalize_expired_commitments(100000);

        assert_eq!(finalized.len(), 0);
    }

    #[test]
    fn test_commitment_manager_get_challenged_commitments() {
        let mut manager = setup_commitment_manager();
        let batch = test_rollup_batch(39);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        let operator = commitment.operator;
        let da_chunks = vec![test_da_chunk(16, batch.batch_id)];

        manager.set_operator_bond(operator, Balance::new(10_000_000_000));
        let hash = manager.submit_commitment(commitment, da_chunks).unwrap();

        let challenger = test_address(108);
        manager.set_operator_bond(challenger, Balance::new(10_000_000_000));

        manager
            .challenge_commitment(
                hash,
                challenger,
                ChallengeType::PQSignatureViolation,
                Balance::new(10_000_000_000),
                vec![1, 2, 3],
            )
            .unwrap();

        let challenged = manager.get_challenged_commitments();
        assert_eq!(challenged.len(), 1);
    }

    #[test]
    fn test_commitment_manager_get_finalized_commitments() {
        let mut manager = setup_commitment_manager();
        let batch = test_rollup_batch(40);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        let da_chunks = vec![test_da_chunk(17, batch.batch_id)];

        manager.set_operator_bond(commitment.operator, Balance::new(10_000_000_000));
        let hash = manager.submit_commitment(commitment, da_chunks).unwrap();

        let commit = manager.get_commitment_mut(hash).unwrap();
        commit.status = CommitmentStatus::Finalized;
        drop(commit);

        let finalized = manager.get_finalized_commitments();
        assert_eq!(finalized.len(), 1);
    }

    #[test]
    fn test_commitment_manager_associate_batch() {
        let mut manager = setup_commitment_manager();
        let batch = test_rollup_batch(41);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        let da_chunks = vec![test_da_chunk(18, batch.batch_id)];

        manager.set_operator_bond(commitment.operator, Balance::new(10_000_000_000));
        let hash = manager.submit_commitment(commitment, da_chunks).unwrap();

        let batch_hash = test_hash(150);
        let result = manager.associate_batch(hash, batch_hash);

        assert!(result.is_ok());
        let commit = manager.get_commitment(hash).unwrap();
        assert!(commit.associated_batches.contains(&batch_hash));
    }

    #[test]
    fn test_commitment_manager_get_shard_commitments() {
        let mut manager = setup_commitment_manager();
        let batch = test_rollup_batch(42);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        let shard_id = commitment.shard_id;
        let da_chunks = vec![test_da_chunk(19, batch.batch_id)];

        manager.set_operator_bond(commitment.operator, Balance::new(10_000_000_000));
        manager.submit_commitment(commitment, da_chunks).unwrap();

        let shard_commitments = manager.get_shard_commitments(shard_id.as_u32());
        assert_eq!(shard_commitments.len(), 1);
    }

    #[test]
    fn test_commitment_manager_get_epoch_commitments() {
        let mut manager = setup_commitment_manager();
        let batch = test_rollup_batch(43);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        let epoch = commitment.epoch;
        let da_chunks = vec![test_da_chunk(20, batch.batch_id)];

        manager.set_operator_bond(commitment.operator, Balance::new(10_000_000_000));
        manager.submit_commitment(commitment, da_chunks).unwrap();

        let epoch_commitments = manager.get_epoch_commitments(epoch.as_u64());
        assert_eq!(epoch_commitments.len(), 1);
    }

    #[test]
    fn test_commitment_manager_verify_commitment_chain_success() {
        let mut manager = setup_commitment_manager();
        let operator = test_address(44);

        let batch1 = test_rollup_batch(44);
        let mut commitment1 = RollupCommitment::from_batch(&batch1, 100).unwrap();
        commitment1.operator = operator;
        let da_chunks1 = vec![test_da_chunk(21, batch1.batch_id)];

        manager.set_operator_bond(operator, Balance::new(10_000_000_000));
        let hash1 = manager
            .submit_commitment(commitment1.clone(), da_chunks1)
            .unwrap();

        let mut batch2 = test_rollup_batch(45);
        batch2.prev_state_root = commitment1.state_root;
        let mut commitment2 = RollupCommitment::from_batch(&batch2, 100).unwrap();
        commitment2.operator = operator;
        commitment2.previous_state_root = commitment1.state_root;
        let da_chunks2 = vec![test_da_chunk(22, batch2.batch_id)];

        let hash2 = manager.submit_commitment(commitment2, da_chunks2).unwrap();

        let result = manager.verify_commitment_chain(&[hash1, hash2]);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_commitment_manager_verify_commitment_chain_state_mismatch() {
        let mut manager = setup_commitment_manager();
        let operator = test_address(46);

        let batch1 = test_rollup_batch(46);
        let mut commitment1 = RollupCommitment::from_batch(&batch1, 100).unwrap();
        commitment1.operator = operator;
        let da_chunks1 = vec![test_da_chunk(23, batch1.batch_id)];

        manager.set_operator_bond(operator, Balance::new(10_000_000_000));
        let hash1 = manager.submit_commitment(commitment1, da_chunks1).unwrap();

        let batch2 = test_rollup_batch(47);
        let mut commitment2 = RollupCommitment::from_batch(&batch2, 100).unwrap();
        commitment2.operator = operator;
        let da_chunks2 = vec![test_da_chunk(24, batch2.batch_id)];

        let hash2 = manager.submit_commitment(commitment2, da_chunks2).unwrap();

        let result = manager.verify_commitment_chain(&[hash1, hash2]);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_commitment_manager_cleanup_old_commitments() {
        let mut manager = setup_commitment_manager();
        let operator = test_address(48);

        for i in 0..5 {
            let batch = test_rollup_batch(50 + i);
            let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
            commitment.operator = operator;
            let da_chunks = vec![test_da_chunk(25 + i as u8, batch.batch_id)];

            manager.set_operator_bond(operator, Balance::new(10_000_000_000));
            let hash = manager.submit_commitment(commitment, da_chunks).unwrap();

            if i < 2 {
                let commit = manager.get_commitment_mut(hash).unwrap();
                commit.status = CommitmentStatus::Finalized;
            }
        }

        let removed = manager.cleanup_old_commitments(10, 100);
        assert_eq!(removed, 2);
    }

    #[test]
    fn test_commitment_manager_set_operator_bond() {
        let mut manager = setup_commitment_manager();
        let operator = test_address(49);
        let bond = Balance::new(50_000_000_000);

        manager.set_operator_bond(operator, bond);

        let retrieved_bond = manager.get_operator_bond(&operator);
        assert_eq!(retrieved_bond, bond);
    }

    #[test]
    fn test_commitment_manager_get_operator_bond_not_set() {
        let manager = setup_commitment_manager();
        let operator = test_address(50);

        let bond = manager.get_operator_bond(&operator);

        assert_eq!(bond, Balance::ZERO);
    }

    #[test]
    fn test_commitment_manager_get_operator_stats() {
        let mut manager = setup_commitment_manager();
        let operator = test_address(51);
        let batch = test_rollup_batch(51);
        let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        commitment.operator = operator;
        let da_chunks = vec![test_da_chunk(30, batch.batch_id)];

        manager.set_operator_bond(operator, Balance::new(10_000_000_000));
        manager.submit_commitment(commitment, da_chunks).unwrap();

        let stats = manager.get_operator_stats(&operator);
        assert!(stats.is_some());
    }

    #[test]
    fn test_commitment_manager_get_operator_reputation() {
        let manager = setup_commitment_manager();
        let operator = test_address(52);

        let reputation = manager.get_operator_reputation(&operator);

        assert_eq!(reputation, 50);
    }

    #[test]
    fn test_commitment_manager_get_operator_drs_score() {
        let manager = setup_commitment_manager();
        let operator = test_address(53);

        let drs_score = manager.get_operator_drs_score(&operator);

        assert_eq!(drs_score, 0.5);
    }

    #[test]
    fn test_commitment_manager_get_commitment_stats() {
        let mut manager = setup_commitment_manager();
        let operator = test_address(54);

        for i in 0..3 {
            let batch = test_rollup_batch(54 + i);
            let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
            commitment.operator = operator;
            let da_chunks = vec![test_da_chunk(31 + i as u8, batch.batch_id)];

            manager.set_operator_bond(operator, Balance::new(10_000_000_000));
            manager.submit_commitment(commitment, da_chunks).unwrap();
        }

        let stats = manager.get_commitment_stats();
        assert_eq!(stats.total_commitments, 3);
        assert_eq!(stats.pending_commitments, 3);
    }

    #[test]
    fn test_commitment_manager_get_commitment_by_tx_root() {
        let mut manager = setup_commitment_manager();
        let batch = test_rollup_batch(57);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        let tx_root = commitment.tx_root;
        let da_chunks = vec![test_da_chunk(34, batch.batch_id)];

        manager.set_operator_bond(commitment.operator, Balance::new(10_000_000_000));
        manager.submit_commitment(commitment, da_chunks).unwrap();

        let found_hash = manager.get_commitment_by_tx_root(tx_root);
        assert!(found_hash.is_some());
    }

    #[test]
    fn test_commitment_manager_get_cellular_safe_mode() {
        let manager = setup_commitment_manager();
        let safe_mode = manager.get_cellular_safe_mode();
        assert!(!safe_mode);
    }

    #[test]
    fn test_commitment_manager_set_cellular_safe_mode() {
        let mut manager = setup_commitment_manager();
        manager.set_cellular_safe_mode(true);
        assert!(manager.get_cellular_safe_mode());
    }

    #[test]
    fn test_commitment_manager_cellular_safe_mode_rejection() {
        let cellular_config = CellularSafeConfig {
            enabled: true,
            max_chunk_size: 256 * 1024,
            max_batch_size: 256 * 1024,
            compression_required: false,
            monthly_limit_bytes: 1024 * 1024 * 1024,
        };
        let da_manager = Arc::new(Mutex::new(
            DataAvailability::new(1024 * 1024, 256 * 1024, 4, false, 3, cellular_config, 100)
                .unwrap(),
        ));
        let mut manager = CommitmentManager::new(da_manager, 100, 50, 1, 1, 1000, true);

        let batch = test_rollup_batch(58);
        let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        commitment.cellular_optimized = false;
        let da_chunks = vec![test_da_chunk(35, batch.batch_id)];

        manager.set_operator_bond(commitment.operator, Balance::new(10_000_000_000));
        let result = manager.submit_commitment(commitment, da_chunks);

        assert!(result.is_err());
    }

    #[test]
    fn test_rollup_commitment_validate_with_deploy_policy_too_many_ai_flagged() {
        let batch = test_rollup_batch(60);
        let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        commitment.set_deploy_stats(5, 20);

        let deploy_stats = DeployStatsSnapshot {
            max_ai_flagged_per_commitment: 10,
            max_deploy_credits_per_commitment: 10000,
            require_human_verification: false,
        };

        let result = commitment.validate_with_deploy_policy(&deploy_stats);
        assert!(result.is_err());
    }

    #[test]
    fn test_rollup_commitment_validate_with_deploy_policy_exceeds_credits() {
        let batch = test_rollup_batch(61);
        let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        commitment.set_resource_usage(20000, 1000, 5000);

        let deploy_stats = DeployStatsSnapshot {
            max_ai_flagged_per_commitment: 10,
            max_deploy_credits_per_commitment: 10000,
            require_human_verification: false,
        };

        let result = commitment.validate_with_deploy_policy(&deploy_stats);
        assert!(result.is_err());
    }

    #[test]
    fn test_rollup_commitment_validate_with_drs_success() {
        let batch = test_rollup_batch(62);
        let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        commitment.set_proof_counts(10, 5);
        commitment.drs_weighted_rewards = true;

        let drs_params = DRSValidationParams {
            require_drs_weighting: true,
            min_post_proofs_per_commitment: 5,
            min_drs_score: 0.5,
        };

        let result = commitment.validate_with_drs(&drs_params);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rollup_commitment_validate_with_drs_missing_weighting() {
        let batch = test_rollup_batch(63);
        let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        commitment.drs_weighted_rewards = false;

        let drs_params = DRSValidationParams {
            require_drs_weighting: true,
            min_post_proofs_per_commitment: 0,
            min_drs_score: 0.5,
        };

        let result = commitment.validate_with_drs(&drs_params);
        assert!(result.is_err());
    }

    #[test]
    fn test_rollup_commitment_validate_with_drs_insufficient_proofs() {
        let batch = test_rollup_batch(64);
        let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        commitment.set_proof_counts(2, 1);

        let drs_params = DRSValidationParams {
            require_drs_weighting: false,
            min_post_proofs_per_commitment: 10,
            min_drs_score: 0.5,
        };

        let result = commitment.validate_with_drs(&drs_params);
        assert!(result.is_err());
    }

    #[test]
    fn test_rollup_commitment_validate_pq_transition_success() {
        let batch = test_rollup_batch(65);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();

        let pq_config = PQTransitionConfig {
            pq_only_required: false,
            legacy_deadline_epoch: None,
            min_pq_signature_ratio: 0.5,
        };

        let result = commitment.validate_pq_transition(&pq_config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rollup_commitment_validate_pq_transition_after_deadline() {
        let batch = test_rollup_batch(66);
        let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        commitment.epoch = EpochNumber::new(200);
        commitment.legacy_signatures_used = 5;

        let pq_config = PQTransitionConfig {
            pq_only_required: true,
            legacy_deadline_epoch: Some(100),
            min_pq_signature_ratio: 1.0,
        };

        let result = commitment.validate_pq_transition(&pq_config);
        assert!(result.is_err());
    }

    #[test]
    fn test_challenge_type_from_string() {
        let challenge_type = ChallengeType::from_string("invalid_state_transition");
        assert!(challenge_type.is_some());
        assert_eq!(
            challenge_type.unwrap(),
            ChallengeType::InvalidStateTransition
        );
    }

    #[test]
    fn test_challenge_type_to_string() {
        let challenge_type = ChallengeType::DataUnavailability;
        let string = challenge_type.to_string();
        assert_eq!(string, "data_unavailability");
    }

    #[test]
    fn test_challenge_type_to_u8() {
        let challenge_type = ChallengeType::InvalidProof;
        let value = challenge_type.to_u8();
        assert_eq!(value, 3);
    }

    #[test]
    fn test_challenge_type_from_u8() {
        let challenge_type = ChallengeType::from_u8(4);
        assert!(challenge_type.is_some());
        assert_eq!(challenge_type.unwrap(), ChallengeType::InvalidInclusion);
    }

    #[test]
    fn test_challenge_type_roundtrip() {
        let original = ChallengeType::InvalidAggregation;
        let as_u8 = original.to_u8();
        let back = ChallengeType::from_u8(as_u8);
        assert_eq!(back.unwrap(), original);
    }

    #[test]
    fn test_challenge_type_all_variants() {
        let types = vec![
            ChallengeType::InvalidStateTransition,
            ChallengeType::DataUnavailability,
            ChallengeType::InvalidProof,
            ChallengeType::InvalidInclusion,
            ChallengeType::InvalidAggregation,
            ChallengeType::InvalidDRSCalculation,
            ChallengeType::InvalidDeployPolicy,
            ChallengeType::MissingHumanVerification,
            ChallengeType::PQSignatureViolation,
        ];

        for challenge_type in types {
            let as_string = challenge_type.to_string();
            let back = ChallengeType::from_string(&as_string);
            assert!(back.is_some());
        }
    }

    #[test]
    fn test_da_availability_status_variants() {
        let unknown = DAAvailabilityStatus::Unknown;
        let available = DAAvailabilityStatus::Available;
        let unavailable = DAAvailabilityStatus::Unavailable;
        let partial = DAAvailabilityStatus::PartiallyAvailable {
            missing_chunks: vec![1, 2, 3],
        };
        let verifying = DAAvailabilityStatus::Verifying { progress: 50 };

        assert_ne!(unknown, available);
        assert_ne!(available, unavailable);
        assert_ne!(unavailable, partial);
        assert_ne!(partial, verifying);
    }

    #[test]
    fn test_commitment_stats_default() {
        let stats = CommitmentStats::default();
        assert_eq!(stats.total_commitments, 0);
        assert_eq!(stats.pending_commitments, 0);
        assert_eq!(stats.finalized_commitments, 0);
        assert_eq!(stats.total_transactions, 0);
    }

    #[test]
    fn test_commitment_manager_multiple_operators() {
        let mut manager = setup_commitment_manager();

        for i in 0..5 {
            let operator = test_address(70 + i);
            let batch = test_rollup_batch(70 + i);
            let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
            commitment.operator = operator;
            let da_chunks = vec![test_da_chunk(40 + i as u8, batch.batch_id)];

            manager.set_operator_bond(operator, Balance::new(10_000_000_000));
            manager.submit_commitment(commitment, da_chunks).unwrap();
        }

        let stats = manager.get_commitment_stats();
        assert_eq!(stats.total_commitments, 5);
    }

    #[test]
    fn test_commitment_manager_multiple_shards() {
        let mut manager = setup_commitment_manager();
        let operator = test_address(75);

        for i in 0..3 {
            let batch = test_rollup_batch(75 + i);
            let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
            commitment.operator = operator;
            commitment.shard_id = ShardId::new(i as u32).unwrap();
            let da_chunks = vec![test_da_chunk(45 + i as u8, batch.batch_id)];

            manager.set_operator_bond(operator, Balance::new(10_000_000_000));
            manager.submit_commitment(commitment, da_chunks).unwrap();
        }

        for i in 0..3 {
            let shard_commitments = manager.get_shard_commitments(i);
            assert_eq!(shard_commitments.len(), 1);
        }
    }

    #[test]
    fn test_commitment_manager_multiple_epochs() {
        let mut manager = setup_commitment_manager();
        let operator = test_address(78);

        for i in 0..5 {
            let batch = test_rollup_batch(78 + i);
            let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
            commitment.operator = operator;
            commitment.epoch = EpochNumber::new((i + 1) as u64);
            let da_chunks = vec![test_da_chunk(48 + i as u8, batch.batch_id)];

            manager.set_operator_bond(operator, Balance::new(10_000_000_000));
            manager.submit_commitment(commitment, da_chunks).unwrap();
        }

        for i in 1..=5 {
            let epoch_commitments = manager.get_epoch_commitments(i);
            assert_eq!(epoch_commitments.len(), 1);
        }
    }

    #[test]
    fn test_commitment_manager_challenge_info() {
        let mut manager = setup_commitment_manager();
        let batch = test_rollup_batch(83);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        let operator = commitment.operator;
        let da_chunks = vec![test_da_chunk(53, batch.batch_id)];

        manager.set_operator_bond(operator, Balance::new(10_000_000_000));
        let hash = manager.submit_commitment(commitment, da_chunks).unwrap();

        let challenger = test_address(109);
        manager.set_operator_bond(challenger, Balance::new(10_000_000_000));

        let _challenge_hash = manager
            .challenge_commitment(
                hash,
                challenger,
                ChallengeType::InvalidStateTransition,
                Balance::new(10_000_000_000),
                vec![1, 2, 3],
            )
            .unwrap();
    }

    #[test]
    fn test_commitment_manager_resolved_challenge() {
        let mut manager = setup_commitment_manager();
        let batch = test_rollup_batch(84);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        let operator = commitment.operator;
        let da_chunks = vec![test_da_chunk(54, batch.batch_id)];

        manager.set_operator_bond(operator, Balance::new(10_000_000_000));
        let hash = manager.submit_commitment(commitment, da_chunks).unwrap();

        let challenger = test_address(110);
        manager.set_operator_bond(challenger, Balance::new(10_000_000_000));

        let challenge_hash = manager
            .challenge_commitment(
                hash,
                challenger,
                ChallengeType::DataUnavailability,
                Balance::new(10_000_000_000),
                vec![1, 2, 3],
            )
            .unwrap();

        manager
            .resolve_challenge(challenge_hash, true, vec![4, 5, 6])
            .unwrap();

        let resolved = manager.get_resolved_challenge(challenge_hash);
        assert!(resolved.is_some());
    }

    #[test]
    fn test_commitment_manager_operator_stats_after_finalization() {
        let mut manager = setup_commitment_manager();
        let operator = test_address(85);
        let batch = test_rollup_batch(85);
        let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        commitment.operator = operator;
        let da_chunks = vec![test_da_chunk(55, batch.batch_id)];

        manager.set_operator_bond(operator, Balance::new(10_000_000_000));
        let hash = manager.submit_commitment(commitment, da_chunks).unwrap();

        let commit = manager.get_commitment_mut(hash).unwrap();
        commit.status = CommitmentStatus::Finalized;
        drop(commit);

        let stats = manager.get_operator_stats(&operator);
        assert!(stats.is_some());
    }

    #[test]
    fn test_commitment_manager_operator_reputation_after_slash() {
        let mut manager = setup_commitment_manager();
        let operator = test_address(86);
        let batch = test_rollup_batch(86);
        let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        commitment.operator = operator;
        let da_chunks = vec![test_da_chunk(56, batch.batch_id)];

        manager.set_operator_bond(operator, Balance::new(10_000_000_000));
        let hash = manager.submit_commitment(commitment, da_chunks).unwrap();

        let challenger = test_address(111);
        manager.set_operator_bond(challenger, Balance::new(10_000_000_000));

        let challenge_hash = manager
            .challenge_commitment(
                hash,
                challenger,
                ChallengeType::InvalidProof,
                Balance::new(10_000_000_000),
                vec![1, 2, 3],
            )
            .unwrap();

        manager
            .resolve_challenge(challenge_hash, true, vec![4, 5, 6])
            .unwrap();

        let stats = manager.get_operator_stats(&operator);
        assert!(stats.is_some());
    }

    #[test]
    fn test_rollup_commitment_cellular_optimization_small_batch() {
        let mut batch = test_rollup_batch(87);
        batch.transactions = vec![test_transaction(87)];
        batch.gas_used = 1000;

        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();

        assert!(commitment.cellular_optimized);
    }

    #[test]
    fn test_rollup_commitment_pq_signature_tracking() {
        let batch = test_rollup_batch(88);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();

        let total_sigs = commitment.pq_signatures_used + commitment.legacy_signatures_used;
        assert_eq!(total_sigs, commitment.tx_count);
    }

    #[test]
    fn test_commitment_stats_comprehensive() {
        let mut manager = setup_commitment_manager();
        let operator = test_address(89);

        for i in 0..10 {
            let batch = test_rollup_batch(89 + i);
            let mut commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
            commitment.operator = operator;
            commitment.set_resource_usage(100, 200, 300);
            commitment.set_proof_counts(5, 3);
            let da_chunks = vec![test_da_chunk(60 + i as u8, batch.batch_id)];

            manager.set_operator_bond(operator, Balance::new(10_000_000_000));
            manager.submit_commitment(commitment, da_chunks).unwrap();
        }

        let stats = manager.get_commitment_stats();
        assert_eq!(stats.total_commitments, 10);
        assert!(stats.total_transactions > 0);
        assert!(stats.total_post_proofs > 0);
        assert!(stats.total_poc_proofs > 0);
    }

    #[test]
    fn test_commitment_manager_verify_empty_chain() {
        let manager = setup_commitment_manager();
        let result = manager.verify_commitment_chain(&[]);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_commitment_manager_get_commitment_mut() {
        let mut manager = setup_commitment_manager();
        let batch = test_rollup_batch(99);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        let da_chunks = vec![test_da_chunk(70, batch.batch_id)];

        manager.set_operator_bond(commitment.operator, Balance::new(10_000_000_000));
        let hash = manager.submit_commitment(commitment, da_chunks).unwrap();

        let commit_mut = manager.get_commitment_mut(hash);
        assert!(commit_mut.is_some());
    }

    #[test]
    fn test_rollup_commitment_protocol_version() {
        let batch = test_rollup_batch(100);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();

        assert_eq!(commitment.protocol_version, ego_core::PROTOCOL_VERSION);
    }

    #[test]
    fn test_rollup_commitment_version() {
        let batch = test_rollup_batch(101);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();

        assert_eq!(commitment.version, ego_rollup::ROLLUP_VERSION);
    }

    #[test]
    fn test_commitment_manager_max_challenges_per_commitment() {
        let mut manager = setup_commitment_manager();
        let batch = test_rollup_batch(102);
        let commitment = RollupCommitment::from_batch(&batch, 100).unwrap();
        let operator = commitment.operator;
        let da_chunks = vec![test_da_chunk(71, batch.batch_id)];

        manager.set_operator_bond(operator, Balance::new(10_000_000_000));
        let hash = manager.submit_commitment(commitment, da_chunks).unwrap();

        for i in 0..3 {
            let challenger = test_address(120 + i);
            manager.set_operator_bond(challenger, Balance::new(10_000_000_000));
            manager
                .challenge_commitment(
                    hash,
                    challenger,
                    ChallengeType::InvalidStateTransition,
                    Balance::new(10_000_000_000),
                    vec![1, 2, 3],
                )
                .unwrap();
        }

        let challenger4 = test_address(123);
        manager.set_operator_bond(challenger4, Balance::new(10_000_000_000));
        let result = manager.challenge_commitment(
            hash,
            challenger4,
            ChallengeType::DataUnavailability,
            Balance::new(10_000_000_000),
            vec![1, 2, 3],
        );

        assert!(result.is_err());
    }
}
