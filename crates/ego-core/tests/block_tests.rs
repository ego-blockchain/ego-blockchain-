#[cfg(test)]
mod block_tests {
    use ego_core::block::*;
    use ego_core::crypto::{KeyPair, MerkleTree};
    use ego_core::transaction::TransactionPublicKeys;
    use ego_core::{
        Address, AlgorithmId, Balance, BlockHeight, DualSignature, EpochNumber, Hash, PublicKey,
        ShardId, StateManager, Timestamp, Transaction, TransactionPayload, TransactionResult,
    };
    use std::collections::HashMap;

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

    fn test_keypair() -> KeyPair {
        KeyPair::generate()
    }

    fn test_transaction(seed: u8) -> Transaction {
        let keypair = test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());

        Transaction {
            from,
            nonce: seed as u64,
            shard_id: ShardId::new(0).unwrap(),
            chain_id: 1,
            payload: TransactionPayload::Transfer {
                to: test_address(seed + 1),
                amount: Balance::new(1000),
                memo: None,
                stealth_mode: false,
            },
            pob_burn_credits: 100,
            signature: DualSignature::new(None, None),
            timestamp: Timestamp::now(),
            hash: test_hash(seed),
            public_keys: TransactionPublicKeys {
                dilithium_pk: keypair.dilithium_public_key(),
                ed25519_pk: None,
                mlkem_pk: None,
            },
            slice_id: None,
            protocol_version: 1,
            required_algorithms: vec![],
            ru_limit: 10000,
            ru_estimate: 5000,
            priority_hint: 0,
        }
    }

    fn test_rollup_commitment(seed: u8) -> RollupCommitment {
        let keypair = test_keypair();
        let operator = Address::from_public_key(&keypair.dilithium_public_key());

        RollupCommitment {
            rollup_id: format!("rollup_{}", seed),
            state_root: test_hash(seed),
            previous_state_root: test_hash(seed + 1),
            tx_root: test_hash(seed + 2),
            proofs_root: test_hash(seed + 3),
            da_root: test_hash(seed + 4),
            tx_count: 100,
            block_range: (1000, 1100),
            operator_signature: DualSignature::new(None, None),
            operator,
            timestamp: Timestamp::now(),
            proof_data: vec![1, 2, 3, 4],
            fraud_proof_window: 1000,
            min_validity_proof: vec![5, 6, 7, 8],
            epoch: 10,
        }
    }

    #[test]
    fn test_new_block() {
        let height = BlockHeight::new(1);
        let previous_hash = test_hash(1);
        let shard_id = ShardId::new(0).unwrap();
        let epoch = EpochNumber::new(1);
        let proposer = test_address(1);
        let transactions = vec![test_transaction(1), test_transaction(2)];
        let rollup_commitments = vec![test_rollup_commitment(1)];

        let block = Block::new(
            height,
            previous_hash,
            shard_id,
            epoch,
            proposer,
            transactions.clone(),
            rollup_commitments.clone(),
            1,
            1,
        );

        assert_eq!(block.header.core.height, height);
        assert_eq!(block.header.core.previous_hash, previous_hash);
        assert_eq!(block.header.core.shard_id, shard_id);
        assert_eq!(block.header.core.epoch, epoch);
        assert_eq!(block.header.core.proposer, proposer);
        assert_eq!(block.body.transactions.len(), 2);
        assert_eq!(block.body.rollup_commitments.len(), 1);
        assert_eq!(block.header.core.tx_count, 2);
        assert_eq!(block.header.metadata.rollup_commits, 1);
    }

    #[test]
    fn test_genesis_block() {
        let genesis_height = BlockHeight::GENESIS;
        let proposer = test_address(1);

        let block = Block::new(
            genesis_height,
            Hash::ZERO,
            ShardId::new(0).unwrap(),
            EpochNumber::new(0),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        assert!(block.is_genesis());
        assert_eq!(block.header.core.height, BlockHeight::GENESIS);
        assert_eq!(block.header.core.previous_hash, Hash::ZERO);
    }

    #[test]
    fn test_block_hash_computation() {
        let proposer = test_address(1);
        let block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let computed_hash = block.compute_hash();
        assert_eq!(block.hash, computed_hash);
        assert_ne!(computed_hash, Hash::ZERO);
    }

    #[test]
    fn test_transactions_root_computation() {
        let proposer = test_address(1);
        let transactions = vec![
            test_transaction(1),
            test_transaction(2),
            test_transaction(3),
        ];

        let block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            transactions,
            vec![],
            1,
            1,
        );

        assert_ne!(block.header.core.transactions_root, Hash::ZERO);
    }

    #[test]
    fn test_empty_transactions_root() {
        let proposer = test_address(1);
        let block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        assert_eq!(block.header.core.transactions_root, Hash::ZERO);
    }

    #[test]
    fn test_block_sign_and_verify() {
        let keypair = test_keypair();
        let proposer = Address::from_public_key(&keypair.dilithium_public_key());

        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let sign_result = block.sign(&keypair, false);
        assert!(sign_result.is_ok());

        let dilithium_pk = keypair.dilithium_public_key();
        let verify_result = block.verify_signature(&dilithium_pk, None);
        assert!(verify_result.is_ok());
        assert!(verify_result.unwrap());
    }

    #[test]
    fn test_block_sign_with_wrong_proposer() {
        let keypair = test_keypair();
        let wrong_proposer = test_address(99);

        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            wrong_proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let sign_result = block.sign(&keypair, false);
        assert!(sign_result.is_err());
    }

    #[test]
    fn test_validate_structure_valid() {
        let keypair = test_keypair();
        let proposer = Address::from_public_key(&keypair.dilithium_public_key());

        let mut tx1 = Transaction::new(
            proposer,
            1,
            TransactionPayload::Transfer {
                to: test_address(2),
                amount: Balance::new(1000),
                memo: None,
                stealth_mode: false,
            },
            ShardId::new(0).unwrap(),
            None,
            1,
        );
        tx1.sign(&keypair, false).unwrap();

        let mut tx2 = Transaction::new(
            proposer,
            2,
            TransactionPayload::Transfer {
                to: test_address(3),
                amount: Balance::new(2000),
                memo: None,
                stealth_mode: false,
            },
            ShardId::new(0).unwrap(),
            None,
            1,
        );
        tx2.sign(&keypair, false).unwrap();

        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![tx1, tx2],
            vec![],
            1,
            1,
        );

        block.sign(&keypair, false).unwrap();

        let result = block.validate_structure();
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_structure_tx_count_mismatch() {
        let keypair = test_keypair();
        let proposer = Address::from_public_key(&keypair.dilithium_public_key());

        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![test_transaction(1)],
            vec![],
            1,
            1,
        );

        block.header.core.tx_count = 999;

        let result = block.validate_structure();
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_structure_tx_root_mismatch() {
        let keypair = test_keypair();
        let proposer = Address::from_public_key(&keypair.dilithium_public_key());

        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![test_transaction(1)],
            vec![],
            1,
            1,
        );

        block.header.core.transactions_root = test_hash(99);

        let result = block.validate_structure();
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_structure_hash_mismatch() {
        let keypair = test_keypair();
        let proposer = Address::from_public_key(&keypair.dilithium_public_key());

        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        block.hash = test_hash(99);

        let result = block.validate_structure();
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_structure_too_many_transactions() {
        let proposer = test_address(1);
        let mut transactions = Vec::new();
        for i in 0..MAX_TRANSACTIONS_PER_BLOCK + 1 {
            transactions.push(test_transaction((i % 255) as u8));
        }

        let block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            transactions,
            vec![],
            1,
            1,
        );

        let result = block.validate_structure();
        assert!(result.is_err());
    }

    #[test]
    fn test_pq_signature_count() {
        let proposer = test_address(1);
        let block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let count = &block.header.core.pq_signature_count;
        assert_eq!(count.dilithium_sigs, 0);
        assert_eq!(count.ed25519_sigs, 0);
        assert_eq!(count.hybrid_sigs, 0);
        assert_eq!(count.slh_dsa_sigs, 0);
    }

    #[test]
    fn test_pq_signature_count_default() {
        let count = PQSignatureCount::default();
        assert_eq!(count.dilithium_sigs, 0);
        assert_eq!(count.ed25519_sigs, 0);
        assert_eq!(count.hybrid_sigs, 0);
        assert_eq!(count.slh_dsa_sigs, 0);
    }

    #[test]
    fn test_block_size() {
        let proposer = test_address(1);
        let transactions = vec![test_transaction(1), test_transaction(2)];

        let block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            transactions,
            vec![],
            1,
            1,
        );

        let size = block.size();
        assert!(size > 0);
    }

    #[test]
    fn test_block_summary() {
        let proposer = test_address(1);
        let transactions = vec![test_transaction(1)];

        let block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            transactions,
            vec![],
            1,
            1,
        );

        let summary = block.summary();
        assert!(summary.contains("Block"));
        assert!(summary.contains("Height: 1"));
        assert!(summary.contains("TXs: 1"));
    }

    #[test]
    fn test_add_transaction_results() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![test_transaction(1)],
            vec![],
            1,
            1,
        );

        let results = vec![TransactionResult {
            tx_hash: test_hash(1),
            success: true,
            ru_used: 1000,
            events: vec![],
            error: None,
            storage_used: 0,
            state_changes: vec![],
            cross_shard_receipts: vec![],
            pq_verification_result: None,
            proof_verifications: vec![],
        }];

        block.add_transaction_results(results);
        assert_eq!(block.body.transaction_results.len(), 1);
    }

    #[test]
    fn test_add_cross_shard_receipts() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let receipt = CrossShardReceipt {
            from_shard: ShardId::new(0).unwrap(),
            to_shard: ShardId::new(1).unwrap(),
            nonce: 1,
            payload: vec![1, 2, 3],
            source_tx_hash: test_hash(1),
            timestamp: Timestamp::now(),
            receipt_hash: test_hash(2),
            deadline_epoch: 100,
            merkle_proof: vec![test_hash(3), test_hash(4)],
        };

        block.add_cross_shard_receipts(vec![receipt]);
        assert_eq!(block.body.cross_shard_receipts.len(), 1);
        assert_eq!(block.header.metadata.cross_shard_receipts, 1);
    }

    #[test]
    fn test_add_proof_events() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let proof_event = ProofEvent {
            proof_type: ProofEventType::PoSt,
            prover: test_address(1),
            challenge_hash: test_hash(1),
            proof_data_hash: test_hash(2),
            location_id: "loc_001".to_string(),
            slice_id: Some("slice_001".to_string()),
            timestamp: Timestamp::now(),
            verified: true,
            latency_ms: 500,
            witness_data: None,
            batch_proof: false,
            cellular_optimized: true,
            evidence_cid: None,
        };

        block.add_proof_events(vec![proof_event]);
        assert_eq!(block.body.proof_events.len(), 1);
    }

    #[test]
    fn test_add_drs_events() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let drs_event = DRSEvent {
            node_id: test_address(1),
            epoch: 10,
            score: 95000,
            multiplier: 1000,
            components: DRSComponents {
                uptime_score: 10000,
                post_pass_rate: 9500,
                post_latency_score: 9000,
                poc_quality_score: 9200,
                serve_ratio: 9800,
                density_penalty: 500,
            },
            timestamp: Timestamp::now(),
            evidence_root: test_hash(1),
            weights_version: 1,
            params_digest: test_hash(2),
        };

        block.add_drs_events(vec![drs_event]);
        assert_eq!(block.body.drs_events.len(), 1);
        assert_eq!(block.header.metadata.drs_events, 1);
    }

    #[test]
    fn test_add_deploy_events() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let deploy_event = DeployEvent {
            deployer: test_address(1),
            contract_address: Some(test_address(2)),
            deploy_type: DeployType::Contract { code_size_kb: 50 },
            credits_used: 1000,
            free_deploy_used: false,
            bond_amount: Some(Balance::new(5000)),
            timestamp: Timestamp::now(),
            code_hash: Some(test_hash(1)),
        };

        block.add_deploy_events(vec![deploy_event]);
        assert_eq!(block.body.deploy_events.len(), 1);
        assert_eq!(block.header.metadata.deploy_events, 1);
    }

    #[test]
    fn test_add_pq_transition_events() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let pq_event = PQTransitionEvent {
            event_type: PQTransitionEventType::HybridModeEnabled,
            affected_accounts: vec![test_address(1), test_address(2)],
            new_algorithms: vec![AlgorithmId::MlDsa2.as_u16()],
            epoch: 10,
            timestamp: Timestamp::now(),
        };

        block.add_pq_transition_events(vec![pq_event]);
        assert_eq!(block.body.pq_transition_events.len(), 1);
    }

    #[test]
    fn test_add_density_events() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let density_event = DensityEvent {
            node_id: test_address(1),
            h3_cell: "8928308280fffff".to_string(),
            device_count: 25,
            density_multiplier: 950,
            epoch: 10,
            timestamp: Timestamp::now(),
            evidence_root: test_hash(1),
        };

        block.add_density_events(vec![density_event]);
        assert_eq!(block.body.density_events.len(), 1);
        assert_eq!(block.header.metadata.density_events, 1);
    }

    #[test]
    fn test_add_fraud_proofs() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let fraud_proof = FraudProof {
            claim_hash: test_hash(1),
            proof_data: vec![1, 2, 3, 4],
            challenge_period_epochs: 100,
            fraud_type: FraudType::InvalidStateTransition,
            challenger: test_address(2),
            timestamp: Timestamp::now(),
        };

        block.add_fraud_proofs(vec![fraud_proof]);
        assert_eq!(block.body.fraud_proofs.len(), 1);
        assert_eq!(block.header.metadata.fraud_proofs, 1);
    }

    #[test]
    fn test_set_state_root() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let state_root = test_hash(10);
        block.set_state_root(state_root);
        assert_eq!(block.header.core.state_root, state_root);
    }

    #[test]
    fn test_set_receipts_root() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let receipts_root = test_hash(11);
        block.set_receipts_root(receipts_root);
        assert_eq!(block.header.core.receipts_root, receipts_root);
    }

    #[test]
    fn test_set_events_root_post() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let events_root = test_hash(12);
        block.set_events_root_post(events_root);
        assert_eq!(block.header.core.events_root_post, events_root);
    }

    #[test]
    fn test_set_events_root_poc() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let events_root = test_hash(13);
        block.set_events_root_poc(events_root);
        assert_eq!(block.header.core.events_root_poc, events_root);
    }

    #[test]
    fn test_set_rollup_root() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let rollup_root = test_hash(14);
        block.set_rollup_root(rollup_root);
        assert_eq!(block.header.core.rollup_root, rollup_root);
    }

    #[test]
    fn test_set_da_root() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let da_root = test_hash(15);
        block.set_da_root(da_root);
        assert_eq!(block.header.core.da_root, da_root);
    }

    #[test]
    fn test_compute_events_root_post_empty() {
        let proposer = test_address(1);
        let block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let root = block.compute_events_root_post();
        assert_eq!(root, Hash::ZERO);
    }

    #[test]
    fn test_compute_events_root_post_with_events() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let proof_event = ProofEvent {
            proof_type: ProofEventType::PoSt,
            prover: test_address(1),
            challenge_hash: test_hash(1),
            proof_data_hash: test_hash(2),
            location_id: "loc_001".to_string(),
            slice_id: None,
            timestamp: Timestamp::now(),
            verified: true,
            latency_ms: 100,
            witness_data: None,
            batch_proof: false,
            cellular_optimized: false,
            evidence_cid: None,
        };

        block.add_proof_events(vec![proof_event]);

        let root = block.compute_events_root_post();
        assert_ne!(root, Hash::ZERO);
    }

    #[test]
    fn test_compute_events_root_poc_empty() {
        let proposer = test_address(1);
        let block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let root = block.compute_events_root_poc();
        assert_eq!(root, Hash::ZERO);
    }

    #[test]
    fn test_compute_events_root_poc_with_events() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let proof_event = ProofEvent {
            proof_type: ProofEventType::PoC,
            prover: test_address(1),
            challenge_hash: test_hash(1),
            proof_data_hash: test_hash(2),
            location_id: "loc_001".to_string(),
            slice_id: None,
            timestamp: Timestamp::now(),
            verified: true,
            latency_ms: 100,
            witness_data: None,
            batch_proof: false,
            cellular_optimized: false,
            evidence_cid: None,
        };

        block.add_proof_events(vec![proof_event]);

        let root = block.compute_events_root_poc();
        assert_ne!(root, Hash::ZERO);
    }

    #[test]
    fn test_compute_receipts_root_empty() {
        let proposer = test_address(1);
        let block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let root = block.compute_receipts_root();
        assert_eq!(root, Hash::ZERO);
    }

    #[test]
    fn test_compute_receipts_root_with_receipts() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let receipt = CrossShardReceipt {
            from_shard: ShardId::new(0).unwrap(),
            to_shard: ShardId::new(1).unwrap(),
            nonce: 1,
            payload: vec![1, 2, 3],
            source_tx_hash: test_hash(1),
            timestamp: Timestamp::now(),
            receipt_hash: test_hash(2),
            deadline_epoch: 100,
            merkle_proof: vec![],
        };

        block.add_cross_shard_receipts(vec![receipt]);

        let root = block.compute_receipts_root();
        assert_ne!(root, Hash::ZERO);
    }

    #[test]
    fn test_compute_rollup_root_empty() {
        let proposer = test_address(1);
        let block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let root = block.compute_rollup_root();
        assert_eq!(root, Hash::ZERO);
    }

    #[test]
    fn test_compute_rollup_root_with_commitments() {
        let proposer = test_address(1);
        let block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![test_rollup_commitment(1)],
            1,
            1,
        );

        let root = block.compute_rollup_root();
        assert_ne!(root, Hash::ZERO);
    }

    #[test]
    fn test_finalize_roots() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![test_rollup_commitment(1)],
            1,
            1,
        );

        let proof_event = ProofEvent {
            proof_type: ProofEventType::PoSt,
            prover: test_address(1),
            challenge_hash: test_hash(1),
            proof_data_hash: test_hash(2),
            location_id: "loc_001".to_string(),
            slice_id: None,
            timestamp: Timestamp::now(),
            verified: true,
            latency_ms: 100,
            witness_data: None,
            batch_proof: false,
            cellular_optimized: false,
            evidence_cid: None,
        };

        block.add_proof_events(vec![proof_event]);

        block.finalize_roots();

        assert_ne!(block.header.core.events_root_post, Hash::ZERO);
        assert_ne!(block.header.core.rollup_root, Hash::ZERO);
    }

    #[test]
    fn test_is_pq_compliant() {
        let proposer = test_address(1);
        let block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        assert!(block.header.qc.pq_compliant);
    }

    #[test]
    fn test_get_algorithm_usage_stats() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        block.add_transaction_results(vec![]);

        let stats = block.get_algorithm_usage_stats();
        assert!(stats.contains_key(&AlgorithmId::MlDsa2.as_u16()));
        assert!(stats.contains_key(&AlgorithmId::Ed25519.as_u16()));
    }

    #[test]
    fn test_validate_quorum_cert_empty() {
        let proposer = test_address(1);
        let block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let result = block.validate_quorum_cert();
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_quorum_cert_voting_power_mismatch() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let validator_sig = ValidatorSignature {
            validator: test_address(2),
            signature: DualSignature::new(None, None),
            voting_power: 1000,
            algorithm_used: vec![AlgorithmId::MlDsa2.as_u16()],
            timestamp: Timestamp::now(),
        };

        block.header.qc.signatures.push(validator_sig);
        block.header.qc.voting_power = 9999;

        let result = block.validate_quorum_cert();
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_quorum_cert_block_hash_mismatch() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        block.header.qc.block_hash = test_hash(99);

        let validator_sig = ValidatorSignature {
            validator: test_address(2),
            signature: DualSignature::new(None, None),
            voting_power: 1000,
            algorithm_used: vec![AlgorithmId::MlDsa2.as_u16()],
            timestamp: Timestamp::now(),
        };

        block.header.qc.signatures.push(validator_sig);
        block.header.qc.voting_power = 1000;

        let result = block.validate_quorum_cert();
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_pq_compliance() {
        let proposer = test_address(1);
        let block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let result = block.validate_pq_compliance();
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_pq_compliance_consensus_not_compliant() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        block.header.qc.pq_compliant = false;

        let result = block.validate_pq_compliance();
        assert!(result.is_err());
    }

    #[test]
    fn test_add_validator_signature() {
        let keypair = test_keypair();
        let proposer = Address::from_public_key(&keypair.dilithium_public_key());

        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let validator = test_address(10);
        let signature = keypair.sign_hybrid(&[1, 2, 3], false);
        let voting_power = 5000;
        let algorithm_used = vec![AlgorithmId::MlDsa2.as_u16()];

        let result =
            block.add_validator_signature(validator, signature, voting_power, algorithm_used);
        assert!(result.is_ok());
        assert_eq!(block.header.qc.signatures.len(), 1);
        assert_eq!(block.header.qc.voting_power, 5000);
    }

    #[test]
    fn test_add_validator_signature_duplicate() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let keypair = test_keypair();
        let validator = test_address(10);
        let signature = keypair.sign_hybrid(&[1, 2, 3], false);
        let algorithm_used = vec![AlgorithmId::MlDsa2.as_u16()];

        block
            .add_validator_signature(validator, signature.clone(), 5000, algorithm_used.clone())
            .unwrap();

        let result = block.add_validator_signature(validator, signature, 5000, algorithm_used);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_multiple_validator_signatures() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let keypair = test_keypair();
        for i in 0..5 {
            let validator = test_address(10 + i);
            let signature = keypair.sign_hybrid(&[i, i + 1, i + 2], false);
            let algorithm_used = vec![AlgorithmId::MlDsa2.as_u16()];
            block
                .add_validator_signature(validator, signature, 1000, algorithm_used)
                .unwrap();
        }

        assert_eq!(block.header.qc.signatures.len(), 5);
        assert_eq!(block.header.qc.voting_power, 5000);
    }

    #[test]
    fn test_verify_quorum() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let keypair = test_keypair();
        let powers = vec![1000, 2000, 1500, 3000, 2500];

        for (i, power) in powers.iter().enumerate() {
            let validator = test_address(10 + i as u8);
            let signature = keypair.sign_hybrid(&[i as u8], false);
            let algorithm_used = vec![AlgorithmId::MlDsa2.as_u16()];
            block
                .add_validator_signature(validator, signature, *power, algorithm_used)
                .unwrap();
        }

        let total_stake = 10000;
        let quorum_threshold = 6667;

        let result = block.verify_quorum(total_stake, quorum_threshold);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_quorum_insufficient() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let keypair = test_keypair();
        for i in 0..3 {
            let validator = test_address(10 + i);
            let signature = keypair.sign_hybrid(&[i], false);
            let algorithm_used = vec![AlgorithmId::MlDsa2.as_u16()];
            block
                .add_validator_signature(validator, signature, 1000, algorithm_used)
                .unwrap();
        }

        let total_stake = 10000;
        let quorum_threshold = 6667;

        let result = block.verify_quorum(total_stake, quorum_threshold);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_verify_quorum_empty_signatures() {
        let proposer = test_address(1);
        let block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let result = block.verify_quorum(10000, 6667);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_get_proposer_rewards() {
        let proposer = test_address(1);
        let mut tx1 = test_transaction(1);
        tx1.pob_burn_credits = 1000;
        let mut tx2 = test_transaction(2);
        tx2.pob_burn_credits = 500;

        let block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![tx1, tx2],
            vec![],
            1,
            1,
        );

        let rewards = block.get_proposer_rewards();
        assert!(rewards.as_u128() > 1_000_000_000);
    }

    #[test]
    fn test_get_validator_rewards() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let keypair = test_keypair();
        for i in 0..3 {
            let validator = test_address(10 + i);
            let signature = keypair.sign_hybrid(&[i, i + 1], false);
            let algorithm_used = vec![AlgorithmId::MlDsa2.as_u16()];
            block
                .add_validator_signature(validator, signature, 1000, algorithm_used)
                .unwrap();
        }

        let total_reward_pool = Balance::new(3_000_000_000);
        let rewards = block.get_validator_rewards(total_reward_pool);

        assert_eq!(rewards.len(), 3);
        for (_, reward) in &rewards {
            assert_eq!(reward.as_u128(), 1_000_000_000);
        }
    }

    #[test]
    fn test_get_validator_rewards_empty() {
        let proposer = test_address(1);
        let block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let total_reward_pool = Balance::new(1_000_000_000);
        let rewards = block.get_validator_rewards(total_reward_pool);

        assert_eq!(rewards.len(), 0);
    }

    #[test]
    fn test_extract_proof_events_by_type() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let post_event = ProofEvent {
            proof_type: ProofEventType::PoSt,
            prover: test_address(1),
            challenge_hash: test_hash(1),
            proof_data_hash: test_hash(2),
            location_id: "loc_001".to_string(),
            slice_id: None,
            timestamp: Timestamp::now(),
            verified: true,
            latency_ms: 100,
            witness_data: None,
            batch_proof: false,
            cellular_optimized: false,
            evidence_cid: None,
        };

        let poc_event = ProofEvent {
            proof_type: ProofEventType::PoC,
            prover: test_address(2),
            challenge_hash: test_hash(3),
            proof_data_hash: test_hash(4),
            location_id: "loc_002".to_string(),
            slice_id: None,
            timestamp: Timestamp::now(),
            verified: true,
            latency_ms: 200,
            witness_data: None,
            batch_proof: false,
            cellular_optimized: false,
            evidence_cid: None,
        };

        block.add_proof_events(vec![post_event, poc_event]);

        let post_events = block.extract_proof_events_by_type(ProofEventType::PoSt);
        assert_eq!(post_events.len(), 1);

        let poc_events = block.extract_proof_events_by_type(ProofEventType::PoC);
        assert_eq!(poc_events.len(), 1);
    }

    #[test]
    fn test_extract_drs_events_for_epoch() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let drs_event1 = DRSEvent {
            node_id: test_address(1),
            epoch: 10,
            score: 95000,
            multiplier: 1000,
            components: DRSComponents {
                uptime_score: 10000,
                post_pass_rate: 9500,
                post_latency_score: 9000,
                poc_quality_score: 9200,
                serve_ratio: 9800,
                density_penalty: 500,
            },
            timestamp: Timestamp::now(),
            evidence_root: test_hash(1),
            weights_version: 1,
            params_digest: test_hash(2),
        };

        let drs_event2 = DRSEvent {
            node_id: test_address(2),
            epoch: 11,
            score: 92000,
            multiplier: 1000,
            components: DRSComponents {
                uptime_score: 9800,
                post_pass_rate: 9200,
                post_latency_score: 9100,
                poc_quality_score: 9000,
                serve_ratio: 9500,
                density_penalty: 400,
            },
            timestamp: Timestamp::now(),
            evidence_root: test_hash(3),
            weights_version: 1,
            params_digest: test_hash(4),
        };

        block.add_drs_events(vec![drs_event1, drs_event2]);

        let epoch_10_events = block.extract_drs_events_for_epoch(10);
        assert_eq!(epoch_10_events.len(), 1);

        let epoch_11_events = block.extract_drs_events_for_epoch(11);
        assert_eq!(epoch_11_events.len(), 1);

        let epoch_12_events = block.extract_drs_events_for_epoch(12);
        assert_eq!(epoch_12_events.len(), 0);
    }

    #[test]
    fn test_extract_density_penalties() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let density_event1 = DensityEvent {
            node_id: test_address(1),
            h3_cell: "8928308280fffff".to_string(),
            device_count: 25,
            density_multiplier: 950,
            epoch: 10,
            timestamp: Timestamp::now(),
            evidence_root: test_hash(1),
        };

        let density_event2 = DensityEvent {
            node_id: test_address(2),
            h3_cell: "8928308281fffff".to_string(),
            device_count: 15,
            density_multiplier: 980,
            epoch: 10,
            timestamp: Timestamp::now(),
            evidence_root: test_hash(2),
        };

        block.add_density_events(vec![density_event1, density_event2]);

        let penalties = block.extract_density_penalties();
        assert_eq!(penalties.len(), 2);
        assert_eq!(penalties.get(&test_address(1)), Some(&950));
        assert_eq!(penalties.get(&test_address(2)), Some(&980));
    }

    #[test]
    fn test_contains_fraud_proofs() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        assert!(!block.contains_fraud_proofs());

        let fraud_proof = FraudProof {
            claim_hash: test_hash(1),
            proof_data: vec![1, 2, 3, 4],
            challenge_period_epochs: 100,
            fraud_type: FraudType::InvalidStateTransition,
            challenger: test_address(2),
            timestamp: Timestamp::now(),
        };

        block.add_fraud_proofs(vec![fraud_proof]);
        assert!(block.contains_fraud_proofs());
    }

    #[test]
    fn test_get_fraud_proofs_by_type() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let fraud_proof1 = FraudProof {
            claim_hash: test_hash(1),
            proof_data: vec![1, 2, 3],
            challenge_period_epochs: 100,
            fraud_type: FraudType::InvalidStateTransition,
            challenger: test_address(2),
            timestamp: Timestamp::now(),
        };

        let fraud_proof2 = FraudProof {
            claim_hash: test_hash(2),
            proof_data: vec![4, 5, 6],
            challenge_period_epochs: 100,
            fraud_type: FraudType::DataUnavailability,
            challenger: test_address(3),
            timestamp: Timestamp::now(),
        };

        block.add_fraud_proofs(vec![fraud_proof1, fraud_proof2]);

        let state_transition_proofs =
            block.get_fraud_proofs_by_type(FraudType::InvalidStateTransition);
        assert_eq!(state_transition_proofs.len(), 1);

        let data_unavail_proofs = block.get_fraud_proofs_by_type(FraudType::DataUnavailability);
        assert_eq!(data_unavail_proofs.len(), 1);
    }

    #[test]
    fn test_verify_rollup_commitments() {
        let proposer = test_address(1);
        let block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![test_rollup_commitment(1)],
            1,
            1,
        );

        let result = block.verify_rollup_commitments();
        assert!(result.is_ok());
        let results = result.unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0]);
    }

    #[test]
    fn test_verify_rollup_commitments_invalid() {
        let proposer = test_address(1);
        let mut invalid_commitment = test_rollup_commitment(1);
        invalid_commitment.tx_count = 0;

        let block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![invalid_commitment],
            1,
            1,
        );

        let result = block.verify_rollup_commitments();
        assert!(result.is_ok());
        let results = result.unwrap();
        assert_eq!(results.len(), 1);
        assert!(!results[0]);
    }

    #[test]
    fn test_get_cross_shard_receipts_for_shard() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let receipt1 = CrossShardReceipt {
            from_shard: ShardId::new(0).unwrap(),
            to_shard: ShardId::new(1).unwrap(),
            nonce: 1,
            payload: vec![1, 2, 3],
            source_tx_hash: test_hash(1),
            timestamp: Timestamp::now(),
            receipt_hash: test_hash(2),
            deadline_epoch: 100,
            merkle_proof: vec![],
        };

        let receipt2 = CrossShardReceipt {
            from_shard: ShardId::new(0).unwrap(),
            to_shard: ShardId::new(2).unwrap(),
            nonce: 2,
            payload: vec![4, 5, 6],
            source_tx_hash: test_hash(3),
            timestamp: Timestamp::now(),
            receipt_hash: test_hash(4),
            deadline_epoch: 100,
            merkle_proof: vec![],
        };

        block.add_cross_shard_receipts(vec![receipt1, receipt2]);

        let shard_1_receipts = block.get_cross_shard_receipts_for_shard(ShardId::new(1).unwrap());
        assert_eq!(shard_1_receipts.len(), 1);

        let shard_2_receipts = block.get_cross_shard_receipts_for_shard(ShardId::new(2).unwrap());
        assert_eq!(shard_2_receipts.len(), 1);

        let shard_3_receipts = block.get_cross_shard_receipts_for_shard(ShardId::new(3).unwrap());
        assert_eq!(shard_3_receipts.len(), 0);
    }

    #[test]
    fn test_estimate_storage_cost() {
        let proposer = test_address(1);
        let block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![test_transaction(1)],
            vec![],
            1,
            1,
        );

        let cost = block.estimate_storage_cost();
        assert!(cost > 0);
    }

    #[test]
    fn test_estimate_storage_cost_with_events() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let proof_event = ProofEvent {
            proof_type: ProofEventType::PoSt,
            prover: test_address(1),
            challenge_hash: test_hash(1),
            proof_data_hash: test_hash(2),
            location_id: "loc_001".to_string(),
            slice_id: None,
            timestamp: Timestamp::now(),
            verified: true,
            latency_ms: 100,
            witness_data: None,
            batch_proof: false,
            cellular_optimized: false,
            evidence_cid: None,
        };

        block.add_proof_events(vec![proof_event]);

        let cost = block.estimate_storage_cost();
        assert!(cost > 0);
    }

    #[test]
    fn test_is_epoch_boundary() {
        let proposer = test_address(1);

        let block1 = Block::new(
            BlockHeight::new(100),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        assert!(block1.is_epoch_boundary(100));
        assert!(block1.is_epoch_boundary(50));

        let block2 = Block::new(
            BlockHeight::new(99),
            test_hash(2),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        assert!(!block2.is_epoch_boundary(100));
    }

    #[test]
    fn test_get_cellular_efficiency_score() {
        let proposer = test_address(1);
        let block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let score = block.get_cellular_efficiency_score();
        assert!(score >= 0.0 && score <= 100.0);
    }

    #[test]
    fn test_get_pq_adoption_rate() {
        let proposer = test_address(1);
        let block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let rate = block.get_pq_adoption_rate();
        assert!(rate >= 0.0 && rate <= 100.0);
    }

    #[test]
    fn test_block_builder_basic() {
        let height = BlockHeight::new(1);
        let previous_hash = test_hash(1);
        let shard_id = ShardId::new(0).unwrap();
        let epoch = EpochNumber::new(1);
        let proposer = test_address(1);

        let builder = BlockBuilder::new(height, previous_hash, shard_id, epoch, proposer, 1, 1);
        let block = builder.build();

        assert_eq!(block.header.core.height, height);
        assert_eq!(block.header.core.previous_hash, previous_hash);
        assert_eq!(block.header.core.shard_id, shard_id);
        assert_eq!(block.header.core.epoch, epoch);
        assert_eq!(block.header.core.proposer, proposer);
    }

    #[test]
    fn test_block_builder_add_transaction() {
        let height = BlockHeight::new(1);
        let proposer = test_address(1);

        let tx = test_transaction(1);
        let block = BlockBuilder::new(
            height,
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            1,
            1,
        )
        .add_transaction(tx)
        .build();

        assert_eq!(block.body.transactions.len(), 1);
    }

    #[test]
    fn test_block_builder_add_transactions() {
        let height = BlockHeight::new(1);
        let proposer = test_address(1);

        let txs = vec![
            test_transaction(1),
            test_transaction(2),
            test_transaction(3),
        ];
        let block = BlockBuilder::new(
            height,
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            1,
            1,
        )
        .add_transactions(txs)
        .build();

        assert_eq!(block.body.transactions.len(), 3);
    }

    #[test]
    fn test_block_builder_add_rollup_commitment() {
        let height = BlockHeight::new(1);
        let proposer = test_address(1);

        let commitment = test_rollup_commitment(1);
        let block = BlockBuilder::new(
            height,
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            1,
            1,
        )
        .add_rollup_commitment(commitment)
        .build();

        assert_eq!(block.body.rollup_commitments.len(), 1);
    }

    #[test]
    fn test_block_builder_build_and_sign() {
        let keypair = test_keypair();
        let proposer = Address::from_public_key(&keypair.dilithium_public_key());

        let result = BlockBuilder::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            1,
            1,
        )
        .build_and_sign(&keypair, false);

        assert!(result.is_ok());
        let block = result.unwrap();
        assert!(block.header.core.signature.dilithium_sig.is_some());
    }

    #[test]
    fn test_block_builder_chaining() {
        let keypair = test_keypair();
        let proposer = Address::from_public_key(&keypair.dilithium_public_key());

        let tx1 = test_transaction(1);
        let tx2 = test_transaction(2);
        let commitment = test_rollup_commitment(1);

        let result = BlockBuilder::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            1,
            1,
        )
        .add_transaction(tx1)
        .add_transaction(tx2)
        .add_rollup_commitment(commitment)
        .build_and_sign(&keypair, false);

        assert!(result.is_ok());
        let block = result.unwrap();
        assert_eq!(block.body.transactions.len(), 2);
        assert_eq!(block.body.rollup_commitments.len(), 1);
    }

    #[test]
    fn test_pq_transition_event_type_hybrid_mode() {
        let event = PQTransitionEvent {
            event_type: PQTransitionEventType::HybridModeEnabled,
            affected_accounts: vec![test_address(1)],
            new_algorithms: vec![AlgorithmId::MlDsa2.as_u16()],
            epoch: 10,
            timestamp: Timestamp::now(),
        };

        assert!(matches!(
            event.event_type,
            PQTransitionEventType::HybridModeEnabled
        ));
    }

    #[test]
    fn test_pq_transition_event_type_pq_required() {
        let event = PQTransitionEvent {
            event_type: PQTransitionEventType::PQRequiredOnTopic {
                topic: "consensus".to_string(),
            },
            affected_accounts: vec![],
            new_algorithms: vec![],
            epoch: 10,
            timestamp: Timestamp::now(),
        };

        match &event.event_type {
            PQTransitionEventType::PQRequiredOnTopic { topic } => {
                assert_eq!(topic, "consensus");
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_pq_transition_event_type_pq_only() {
        let event = PQTransitionEvent {
            event_type: PQTransitionEventType::PQOnlyModeEnabled,
            affected_accounts: vec![],
            new_algorithms: vec![],
            epoch: 10,
            timestamp: Timestamp::now(),
        };

        assert!(matches!(
            event.event_type,
            PQTransitionEventType::PQOnlyModeEnabled
        ));
    }

    #[test]
    fn test_pq_transition_event_type_legacy_disabled() {
        let event = PQTransitionEvent {
            event_type: PQTransitionEventType::LegacyAlgorithmDisabled {
                algorithm: AlgorithmId::Ed25519.as_u16(),
            },
            affected_accounts: vec![],
            new_algorithms: vec![],
            epoch: 10,
            timestamp: Timestamp::now(),
        };

        match &event.event_type {
            PQTransitionEventType::LegacyAlgorithmDisabled { algorithm } => {
                assert_eq!(*algorithm, AlgorithmId::Ed25519.as_u16());
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_proof_event_types() {
        assert!(matches!(ProofEventType::PoSt, ProofEventType::PoSt));
        assert!(matches!(ProofEventType::PoRep, ProofEventType::PoRep));
        assert!(matches!(ProofEventType::PoC, ProofEventType::PoC));
    }

    #[test]
    fn test_deploy_type_contract() {
        let deploy = DeployType::Contract { code_size_kb: 100 };
        match deploy {
            DeployType::Contract { code_size_kb } => {
                assert_eq!(code_size_kb, 100);
            }
            _ => panic!("Wrong deploy type"),
        }
    }

    #[test]
    fn test_deploy_type_storage_deal() {
        let deploy = DeployType::StorageDeal { data_size_gb: 50 };
        match deploy {
            DeployType::StorageDeal { data_size_gb } => {
                assert_eq!(data_size_gb, 50);
            }
            _ => panic!("Wrong deploy type"),
        }
    }

    #[test]
    fn test_deploy_type_rollup_state() {
        let deploy = DeployType::RollupState { state_size_kb: 200 };
        match deploy {
            DeployType::RollupState { state_size_kb } => {
                assert_eq!(state_size_kb, 200);
            }
            _ => panic!("Wrong deploy type"),
        }
    }

    #[test]
    fn test_fraud_types() {
        let types = vec![
            FraudType::InvalidStateTransition,
            FraudType::DataUnavailability,
            FraudType::InvalidProof,
            FraudType::DoubleSigning,
            FraudType::InvalidTriadPlacement,
            FraudType::InvalidInclusion,
            FraudType::InvalidAggregation,
        ];

        assert_eq!(types.len(), 7);
    }

    #[test]
    fn test_witness_data() {
        let witness = WitnessData {
            rsrp: -80,
            rsrq: -10,
            sinr: 15,
            timing_advance: 5,
            gps_coords: Some((40712345, -74006789)),
            witnesses: vec![test_address(1), test_address(2)],
            h3_cell: "8928308280fffff".to_string(),
            confidence_score: 95000,
        };

        assert_eq!(witness.rsrp, -80);
        assert_eq!(witness.witnesses.len(), 2);
    }

    #[test]
    fn test_drs_components() {
        let components = DRSComponents {
            uptime_score: 10000,
            post_pass_rate: 9500,
            post_latency_score: 9000,
            poc_quality_score: 9200,
            serve_ratio: 9800,
            density_penalty: 500,
        };

        assert_eq!(components.uptime_score, 10000);
        assert_eq!(components.density_penalty, 500);
    }

    #[test]
    fn test_resource_pricing() {
        let pricing = ResourcePricing {
            bytes_cost: 100,
            ru_cost: 10,
            pob_floor: 1000,
            pq_signature_cost: 50,
            cellular_premium: 25,
        };

        assert_eq!(pricing.bytes_cost, 100);
        assert_eq!(pricing.pq_signature_cost, 50);
    }

    #[test]
    fn test_block_metadata_equality() {
        let metadata1 = BlockMetadata {
            protocol_version: 1,
            block_size: 1000,
            cross_shard_receipts: 5,
            rollup_commits: 2,
            poc_events: 10,
            post_events: 8,
            resource_pricing: ResourcePricing {
                bytes_cost: 100,
                ru_cost: 10,
                pob_floor: 1000,
                pq_signature_cost: 50,
                cellular_premium: 25,
            },
            pq_transition_data: PQTransitionData {
                transition_phase: 1,
                pq_required_topics: vec![],
                legacy_support_end_epoch: None,
                algorithm_usage_stats: HashMap::new(),
            },
            cellular_stats: CellularStats {
                cellular_safe_txs: 100,
                wifi_only_txs: 50,
                throttled_operations: 5,
                avg_cellular_cost_per_tx: 0.5,
                total_data_bytes_cellular: 10000,
                total_data_bytes_wifi: 5000,
            },
            density_events: 3,
            drs_events: 4,
            deploy_events: 2,
            fraud_proofs: 1,
        };

        let metadata2 = BlockMetadata {
            protocol_version: 1,
            block_size: 1000,
            cross_shard_receipts: 5,
            rollup_commits: 2,
            poc_events: 10,
            post_events: 8,
            resource_pricing: ResourcePricing {
                bytes_cost: 200,
                ru_cost: 20,
                pob_floor: 2000,
                pq_signature_cost: 100,
                cellular_premium: 50,
            },
            pq_transition_data: PQTransitionData {
                transition_phase: 2,
                pq_required_topics: vec!["test".to_string()],
                legacy_support_end_epoch: Some(1000),
                algorithm_usage_stats: HashMap::new(),
            },
            cellular_stats: CellularStats {
                cellular_safe_txs: 100,
                wifi_only_txs: 50,
                throttled_operations: 5,
                avg_cellular_cost_per_tx: 1.0,
                total_data_bytes_cellular: 20000,
                total_data_bytes_wifi: 10000,
            },
            density_events: 6,
            drs_events: 8,
            deploy_events: 4,
            fraud_proofs: 2,
        };

        assert_eq!(metadata1, metadata2);
    }

    #[test]
    fn test_cellular_stats_equality() {
        let stats1 = CellularStats {
            cellular_safe_txs: 100,
            wifi_only_txs: 50,
            throttled_operations: 5,
            avg_cellular_cost_per_tx: 0.5,
            total_data_bytes_cellular: 10000,
            total_data_bytes_wifi: 5000,
        };

        let stats2 = CellularStats {
            cellular_safe_txs: 100,
            wifi_only_txs: 50,
            throttled_operations: 5,
            avg_cellular_cost_per_tx: 1.0,
            total_data_bytes_cellular: 20000,
            total_data_bytes_wifi: 10000,
        };

        assert_eq!(stats1, stats2);
    }

    #[test]
    fn test_network_stats_equality() {
        let stats1 = NetworkStats {
            active_devices: 1000,
            bandwidth_utilization: 75000000,
            avg_latency_ms: 50,
            active_slices: 10,
            storage_utilization: 5000000000,
            pq_adoption_rate: 0.85,
            cellular_node_count: 500,
        };

        let stats2 = NetworkStats {
            active_devices: 1000,
            bandwidth_utilization: 75000000,
            avg_latency_ms: 50,
            active_slices: 10,
            storage_utilization: 5000000000,
            pq_adoption_rate: 0.90,
            cellular_node_count: 600,
        };

        assert_eq!(stats1, stats2);
    }

    #[test]
    fn test_quorum_cert_structure() {
        let qc = QuorumCert {
            view: 1,
            height: BlockHeight::new(100),
            block_hash: test_hash(1),
            signatures: vec![],
            aggregated_signature: None,
            voting_power: 0,
            timestamp: Timestamp::now(),
            pq_compliant: true,
            validator_set_id: 1,
            round: 1,
            bitmap: vec![],
            signatures_root: Hash::ZERO,
        };

        assert_eq!(qc.view, 1);
        assert_eq!(qc.height, BlockHeight::new(100));
        assert!(qc.pq_compliant);
    }

    #[test]
    fn test_validator_signature_structure() {
        let keypair = test_keypair();
        let validator_sig = ValidatorSignature {
            validator: test_address(1),
            signature: keypair.sign_hybrid(&[1, 2, 3], false),
            voting_power: 1000,
            algorithm_used: vec![AlgorithmId::MlDsa2.as_u16()],
            timestamp: Timestamp::now(),
        };

        assert_eq!(validator_sig.voting_power, 1000);
        assert_eq!(validator_sig.algorithm_used.len(), 1);
    }

    #[test]
    fn test_block_header_core_structure() {
        let core = BlockHeaderCore {
            height: BlockHeight::new(1),
            previous_hash: test_hash(1),
            transactions_root: test_hash(2),
            state_root: test_hash(3),
            receipts_root: test_hash(4),
            events_root_post: test_hash(5),
            events_root_poc: test_hash(6),
            rollup_root: test_hash(7),
            da_root: test_hash(8),
            timestamp: Timestamp::now(),
            shard_id: ShardId::new(0).unwrap(),
            epoch: EpochNumber::new(1),
            proposer: test_address(1),
            signature: DualSignature::new(None, None),
            tx_count: 10,
            compute_used: 5000,
            storage_used: 10000,
            protocol_version: 1,
            chain_id: 1,
            network_id: 1,
            pq_signature_count: PQSignatureCount::default(),
            vrf_output: [0u8; 32],
            vrf_proof: None,
        };

        assert_eq!(core.height, BlockHeight::new(1));
        assert_eq!(core.tx_count, 10);
    }

    #[test]
    fn test_rollup_commitment_structure() {
        let commitment = test_rollup_commitment(1);
        assert_eq!(commitment.tx_count, 100);
        assert_eq!(commitment.block_range, (1000, 1100));
        assert_eq!(commitment.fraud_proof_window, 1000);
    }

    #[test]
    fn test_cross_shard_receipt_structure() {
        let receipt = CrossShardReceipt {
            from_shard: ShardId::new(0).unwrap(),
            to_shard: ShardId::new(1).unwrap(),
            nonce: 1,
            payload: vec![1, 2, 3, 4, 5],
            source_tx_hash: test_hash(1),
            timestamp: Timestamp::now(),
            receipt_hash: test_hash(2),
            deadline_epoch: 100,
            merkle_proof: vec![test_hash(3), test_hash(4)],
        };

        assert_eq!(receipt.from_shard, ShardId::new(0).unwrap());
        assert_eq!(receipt.to_shard, ShardId::new(1).unwrap());
        assert_eq!(receipt.payload.len(), 5);
        assert_eq!(receipt.merkle_proof.len(), 2);
    }

    #[test]
    fn test_proof_event_with_witness() {
        let witness = WitnessData {
            rsrp: -75,
            rsrq: -8,
            sinr: 18,
            timing_advance: 3,
            gps_coords: Some((40712345, -74006789)),
            witnesses: vec![test_address(1)],
            h3_cell: "8928308280fffff".to_string(),
            confidence_score: 98000,
        };

        let proof_event = ProofEvent {
            proof_type: ProofEventType::PoC,
            prover: test_address(1),
            challenge_hash: test_hash(1),
            proof_data_hash: test_hash(2),
            location_id: "loc_001".to_string(),
            slice_id: Some("slice_001".to_string()),
            timestamp: Timestamp::now(),
            verified: true,
            latency_ms: 150,
            witness_data: Some(witness),
            batch_proof: false,
            cellular_optimized: true,
            evidence_cid: Some("QmTest123".to_string()),
        };

        assert!(proof_event.witness_data.is_some());
        assert!(proof_event.cellular_optimized);
        assert!(proof_event.evidence_cid.is_some());
    }

    #[test]
    fn test_complex_block_lifecycle() {
        let keypair = test_keypair();
        let proposer = Address::from_public_key(&keypair.dilithium_public_key());

        let mut tx1 = Transaction::new(
            proposer,
            1,
            TransactionPayload::Transfer {
                to: test_address(2),
                amount: Balance::new(1000),
                memo: None,
                stealth_mode: false,
            },
            ShardId::new(0).unwrap(),
            None,
            1,
        );
        tx1.sign(&keypair, false).unwrap();

        let mut tx2 = Transaction::new(
            proposer,
            2,
            TransactionPayload::Transfer {
                to: test_address(3),
                amount: Balance::new(2000),
                memo: None,
                stealth_mode: false,
            },
            ShardId::new(0).unwrap(),
            None,
            1,
        );
        tx2.sign(&keypair, false).unwrap();

        let mut block = BlockBuilder::new(
            BlockHeight::new(100),
            test_hash(99),
            ShardId::new(0).unwrap(),
            EpochNumber::new(10),
            proposer,
            1,
            1,
        )
        .add_transaction(tx1)
        .add_transaction(tx2)
        .add_rollup_commitment(test_rollup_commitment(1))
        .build();

        block.sign(&keypair, false).unwrap();

        let proof_event = ProofEvent {
            proof_type: ProofEventType::PoSt,
            prover: test_address(1),
            challenge_hash: test_hash(1),
            proof_data_hash: test_hash(2),
            location_id: "loc_001".to_string(),
            slice_id: None,
            timestamp: Timestamp::now(),
            verified: true,
            latency_ms: 100,
            witness_data: None,
            batch_proof: false,
            cellular_optimized: false,
            evidence_cid: None,
        };

        block.add_proof_events(vec![proof_event]);

        let drs_event = DRSEvent {
            node_id: test_address(1),
            epoch: 10,
            score: 95000,
            multiplier: 1000,
            components: DRSComponents {
                uptime_score: 10000,
                post_pass_rate: 9500,
                post_latency_score: 9000,
                poc_quality_score: 9200,
                serve_ratio: 9800,
                density_penalty: 500,
            },
            timestamp: Timestamp::now(),
            evidence_root: test_hash(1),
            weights_version: 1,
            params_digest: test_hash(2),
        };

        block.add_drs_events(vec![drs_event]);

        block.finalize_roots();

        let validation = block.validate_structure();
        assert!(validation.is_ok());

        assert_eq!(block.body.transactions.len(), 2);
        assert_eq!(block.body.rollup_commitments.len(), 1);
        assert_eq!(block.body.proof_events.len(), 1);
        assert_eq!(block.body.drs_events.len(), 1);
        assert_ne!(block.header.core.events_root_post, Hash::ZERO);
    }

    #[test]
    fn test_block_with_all_event_types() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let proof_event = ProofEvent {
            proof_type: ProofEventType::PoSt,
            prover: test_address(1),
            challenge_hash: test_hash(1),
            proof_data_hash: test_hash(2),
            location_id: "loc_001".to_string(),
            slice_id: None,
            timestamp: Timestamp::now(),
            verified: true,
            latency_ms: 100,
            witness_data: None,
            batch_proof: false,
            cellular_optimized: false,
            evidence_cid: None,
        };
        block.add_proof_events(vec![proof_event]);

        let drs_event = DRSEvent {
            node_id: test_address(1),
            epoch: 10,
            score: 95000,
            multiplier: 1000,
            components: DRSComponents {
                uptime_score: 10000,
                post_pass_rate: 9500,
                post_latency_score: 9000,
                poc_quality_score: 9200,
                serve_ratio: 9800,
                density_penalty: 500,
            },
            timestamp: Timestamp::now(),
            evidence_root: test_hash(1),
            weights_version: 1,
            params_digest: test_hash(2),
        };
        block.add_drs_events(vec![drs_event]);

        let deploy_event = DeployEvent {
            deployer: test_address(1),
            contract_address: Some(test_address(2)),
            deploy_type: DeployType::Contract { code_size_kb: 50 },
            credits_used: 1000,
            free_deploy_used: false,
            bond_amount: Some(Balance::new(5000)),
            timestamp: Timestamp::now(),
            code_hash: Some(test_hash(1)),
        };
        block.add_deploy_events(vec![deploy_event]);

        let density_event = DensityEvent {
            node_id: test_address(1),
            h3_cell: "8928308280fffff".to_string(),
            device_count: 25,
            density_multiplier: 950,
            epoch: 10,
            timestamp: Timestamp::now(),
            evidence_root: test_hash(1),
        };
        block.add_density_events(vec![density_event]);

        let fraud_proof = FraudProof {
            claim_hash: test_hash(1),
            proof_data: vec![1, 2, 3, 4],
            challenge_period_epochs: 100,
            fraud_type: FraudType::InvalidStateTransition,
            challenger: test_address(2),
            timestamp: Timestamp::now(),
        };
        block.add_fraud_proofs(vec![fraud_proof]);

        let pq_event = PQTransitionEvent {
            event_type: PQTransitionEventType::HybridModeEnabled,
            affected_accounts: vec![test_address(1)],
            new_algorithms: vec![AlgorithmId::MlDsa2.as_u16()],
            epoch: 10,
            timestamp: Timestamp::now(),
        };
        block.add_pq_transition_events(vec![pq_event]);

        assert_eq!(block.body.proof_events.len(), 1);
        assert_eq!(block.body.drs_events.len(), 1);
        assert_eq!(block.body.deploy_events.len(), 1);
        assert_eq!(block.body.density_events.len(), 1);
        assert_eq!(block.body.fraud_proofs.len(), 1);
        assert_eq!(block.body.pq_transition_events.len(), 1);
    }

    #[test]
    fn test_block_hash_consistency() {
        let proposer = test_address(1);
        let block1 = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![test_transaction(1)],
            vec![],
            1,
            1,
        );

        let hash1 = block1.compute_hash();
        let hash2 = block1.compute_hash();
        assert_eq!(hash1, hash2);

        let block2 = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![test_transaction(2)],
            vec![],
            1,
            1,
        );

        assert_ne!(block1.hash, block2.hash);
    }

    #[test]
    fn test_multiple_validator_signatures_voting_power() {
        let proposer = test_address(1);
        let mut block = Block::new(
            BlockHeight::new(1),
            test_hash(1),
            ShardId::new(0).unwrap(),
            EpochNumber::new(1),
            proposer,
            vec![],
            vec![],
            1,
            1,
        );

        let keypair = test_keypair();
        let powers = vec![1000, 2000, 1500, 3000, 2500];
        let expected_total: u64 = powers.iter().sum();

        for (i, power) in powers.iter().enumerate() {
            let validator = test_address(10 + i as u8);
            let signature = keypair.sign_hybrid(&[i as u8], false);
            let algorithm_used = vec![AlgorithmId::MlDsa2.as_u16()];
            block
                .add_validator_signature(validator, signature, *power, algorithm_used)
                .unwrap();
        }

        assert_eq!(block.header.qc.voting_power, expected_total);
        assert_eq!(block.header.qc.signatures.len(), 5);
    }
}
