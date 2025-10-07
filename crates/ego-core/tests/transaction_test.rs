#[cfg(test)]
mod transaction_tests {
    use ego_core::{
        crypto::KeyPair, transaction::*, Account, AccountType, Address, AlgorithmId, Balance, Hash,
        PublicKey, ShardId, SliceId, Timestamp,
    };
    use std::collections::HashMap;

    const TEST_CHAIN_ID: u32 = 1;

    fn create_test_keypair() -> KeyPair {
        KeyPair::generate()
    }

    fn create_test_account(address: Address, balance: Balance) -> Account {
        let keypair = create_test_keypair();
        let mut account = Account {
            address,
            balance,
            nonce: 0,
            storage_used: 0,
            storage_quota: 10_000_000_000,
            storage_credits: 1_000_000,
            deploy_credits: 100,
            free_deploys_remaining: 3,
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
        };
        account.address = Address::from_public_key(&keypair.dilithium_public_key());
        account
    }

    #[test]
    fn test_transaction_creation() {
        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let to = Address::new([1u8; 20]);
        let payload = TransactionPayload::Transfer {
            to,
            amount: Balance::from(1000u64),
            memo: Some("Test transfer".to_string()),
            stealth_mode: false,
        };
        let tx = Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
        assert_eq!(tx.from, from);
        assert_eq!(tx.nonce, 1);
        assert_eq!(tx.shard_id, ShardId::from_u32(0));
    }

    #[test]
    fn test_transaction_signing_and_verification() {
        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let to = Address::new([2u8; 20]);
        let payload = TransactionPayload::Transfer {
            to,
            amount: Balance::from(5000u64),
            memo: None,
            stealth_mode: false,
        };
        let mut tx = Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
        tx.sign(&keypair, false).expect("Signing failed");
        let is_valid = tx.verify_signature().expect("Verification failed");
        assert!(is_valid, "Signature should be valid");
    }

    #[test]
    fn test_transaction_signing_transition_mode() {
        let keypair = KeyPair::generate();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let payload = TransactionPayload::Transfer {
            to: Address::new([1u8; 20]),
            amount: Balance::from(100u64),
            memo: None,
            stealth_mode: false,
        };
        let mut tx = Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
        tx.sign(&keypair, true).expect("Signing failed");
        tx.public_keys.ed25519_pk = Some(keypair.ed25519_public_key());
        assert!(
            tx.signature.ed25519_sig.is_some(),
            "Ed25519 signature should be present in transition mode"
        );
        assert!(
            tx.signature.dilithium_sig.is_some(),
            "Dilithium signature should be present in transition mode"
        );
        let mut account = create_test_account(from, Balance::from(10_000u64));
        account.dilithium_pk = keypair.dilithium_public_key().key_data.clone();
        account.mlkem_pk = keypair.kyber_public_key().key_data.clone();
        account.ed25519_pk = Some(keypair.ed25519_public_key().key_data.clone());
        account.pq_transition_info = Some(ego_core::account::PQTransitionInfo {
            transition_started_epoch: 0,
            pq_only_mode: false,
            ed25519_disabled_epoch: None,
            supported_algorithms: vec![
                ego_core::AlgorithmId::MlDsa2.as_u16(),
                ego_core::AlgorithmId::Ed25519.as_u16(),
                ego_core::AlgorithmId::MlKem768.as_u16(),
            ],
        });
        let validation_result = tx.validate_against_account(&account);
        assert!(
            validation_result.is_ok(),
            "Validation failed: {:?}",
            validation_result.err()
        );
    }

    #[test]
    fn test_transaction_nonce_validation() {
        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let to = Address::new([4u8; 20]);
        let mut account = create_test_account(from, Balance::from(10000u64));
        account.nonce = 5;
        account.dilithium_pk = keypair.dilithium_public_key().key_data.clone();
        account.mlkem_pk = keypair.kyber_public_key().key_data.clone();
        let payload = TransactionPayload::Transfer {
            to,
            amount: Balance::from(1000u64),
            memo: None,
            stealth_mode: false,
        };
        let mut tx = Transaction::new(
            from,
            10,
            payload.clone(),
            ShardId::from_u32(0),
            None,
            TEST_CHAIN_ID,
        );
        tx.sign(&keypair, false).unwrap();
        let result = tx.validate_against_account(&account);
        assert!(result.is_err(), "Should fail with wrong nonce");
        let mut tx = Transaction::new(from, 6, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
        tx.sign(&keypair, false).unwrap();
        let result = tx.validate_against_account(&account);
        assert!(result.is_ok(), "Should succeed with correct nonce");
    }

    #[test]
    fn test_transaction_balance_validation() {
        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let to = Address::new([5u8; 20]);
        let account = create_test_account(from, Balance::from(1000u64));
        let payload = TransactionPayload::Transfer {
            to,
            amount: Balance::from(2000u64),
            memo: None,
            stealth_mode: false,
        };
        let mut tx = Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
        tx.sign(&keypair, false).unwrap();
        let result = tx.validate_against_account(&account);
        assert!(result.is_err(), "Should fail with insufficient balance");
    }

    #[test]
    fn test_store_data_transaction() {
        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let triad_placement = TriadPlacement {
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
            group_id: "group-123".to_string(),
            placement_epoch: 100,
            diversity_score: 0.85,
        };
        let payload = TransactionPayload::StoreData {
            chunk_id: Hash::new([6u8; 32]),
            data_size: 1024 * 1024,
            duration_epochs: 100,
            data_hash: Hash::new([7u8; 32]),
            slice_id: SliceId::new("personal".to_string()),
            storage_credits: 1000,
            replication_factor: 3,
            triad_placement,
            erasure_coding: ErasureCodingParams {
                k: 10,
                m: 4,
                codec: ErasureCodec::ReedSolomon,
            },
            encryption_envelope: None,
        };
        let mut tx = Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
        tx.sign(&keypair, false).unwrap();
        let triad = tx.extract_triad_placement();
        assert!(triad.is_some());
        assert_eq!(triad.unwrap().diversity_score, 0.85);
        let chunk_ids = tx.get_affected_chunk_ids();
        assert_eq!(chunk_ids.len(), 1);
    }

    #[test]
    fn test_triad_diversity_validation() {
        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let bad_triad = TriadPlacement {
            primary: NodeLocation {
                node_id: Address::new([20u8; 20]),
                h3_cell: "8928308280fffff".to_string(),
                shard_id: 0,
                region: "us-west".to_string(),
                lat_lon: Some((37.7749, -122.4194)),
            },
            replica_a: NodeLocation {
                node_id: Address::new([21u8; 20]),
                h3_cell: "8928308280aaaaa".to_string(),
                shard_id: 0,
                region: "us-west".to_string(),
                lat_lon: Some((37.7849, -122.4094)),
            },
            replica_b: NodeLocation {
                node_id: Address::new([22u8; 20]),
                h3_cell: "8928308280bbbbb".to_string(),
                shard_id: 0,
                region: "us-west".to_string(),
                lat_lon: Some((37.7649, -122.4294)),
            },
            group_id: "group-bad".to_string(),
            placement_epoch: 100,
            diversity_score: 0.3,
        };
        let payload = TransactionPayload::StoreData {
            chunk_id: Hash::new([8u8; 32]),
            data_size: 1024,
            duration_epochs: 10,
            data_hash: Hash::new([9u8; 32]),
            slice_id: SliceId::new("test".to_string()),
            storage_credits: 100,
            replication_factor: 3,
            triad_placement: bad_triad,
            erasure_coding: ErasureCodingParams {
                k: 5,
                m: 2,
                codec: ErasureCodec::ReedSolomon,
            },
            encryption_envelope: None,
        };
        let mut tx = Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
        tx.sign(&keypair, false).unwrap();
        let result = tx.validate_triad_diversity(100.0);
        assert!(result.is_err(), "Should fail diversity check");
    }

    #[test]
    fn test_post_challenge_and_response() {
        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let challenged_node = Address::new([30u8; 20]);
        let challenge_payload = TransactionPayload::PoStChallenge {
            challenged_node,
            chunk_ids: vec![
                Hash::new([40u8; 32]),
                Hash::new([41u8; 32]),
                Hash::new([42u8; 32]),
            ],
            challenge_seed: [99u8; 32],
            vrf_proof: vec![1, 2, 3, 4],
            deadline_block: 1000,
            epoch: 10,
        };
        let mut challenge_tx = Transaction::new(
            from,
            1,
            challenge_payload,
            ShardId::from_u32(0),
            None,
            TEST_CHAIN_ID,
        );
        challenge_tx.sign(&keypair, false).unwrap();
        assert_eq!(challenge_tx.get_priority(), 200);
        assert!(challenge_tx.is_proof_transaction());
        let response_payload = TransactionPayload::PoStResponse {
            challenge_hash: Hash::new([50u8; 32]),
            proofs: vec![
                PoStProof {
                    chunk_id: Hash::new([40u8; 32]),
                    merkle_proof: vec![Hash::new([60u8; 32])],
                    challenge_response: vec![5, 6, 7, 8],
                    timestamp: Timestamp::now(),
                    latency_ms: 150,
                },
                PoStProof {
                    chunk_id: Hash::new([41u8; 32]),
                    merkle_proof: vec![Hash::new([61u8; 32])],
                    challenge_response: vec![9, 10, 11, 12],
                    timestamp: Timestamp::now(),
                    latency_ms: 200,
                },
            ],
            batch_merkle_root: Hash::new([70u8; 32]),
            latency_ms: vec![150, 200],
        };
        let mut response_tx = Transaction::new(
            challenged_node,
            1,
            response_payload,
            ShardId::from_u32(0),
            None,
            TEST_CHAIN_ID,
        );
        let responder_keypair = create_test_keypair();
        response_tx.from = Address::from_public_key(&responder_keypair.dilithium_public_key());
        response_tx.sign(&responder_keypair, false).unwrap();
        let result = response_tx.validate_proof_latency(300);
        assert!(result.is_ok());
        let result = response_tx.validate_proof_latency(100);
        assert!(result.is_err());
    }

    #[test]
    fn test_stake_and_delegate() {
        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let validator_pk = PublicKey::new(AlgorithmId::MlDsa2, vec![88u8; 1312]);
        let mut account = create_test_account(from, Balance::from(100_000u64));
        account.dilithium_pk = keypair.dilithium_public_key().key_data.clone();
        account.mlkem_pk = keypair.kyber_public_key().key_data.clone();
        let stake_payload = TransactionPayload::Stake {
            amount: Balance::from(50_000u64),
            validator_pubkey: validator_pk.clone(),
            lock_duration_epochs: 100,
            commission_rate: Some(500),
        };
        let mut stake_tx = Transaction::new(
            from,
            1,
            stake_payload,
            ShardId::from_u32(0),
            None,
            TEST_CHAIN_ID,
        );
        stake_tx.sign(&keypair, false).unwrap();
        let result = stake_tx.validate_against_account(&account);
        assert!(result.is_ok());
        account.nonce = 1;
        let delegate_payload = TransactionPayload::Delegate {
            amount: Balance::from(30_000u64),
            validator_pubkey: validator_pk,
        };
        let mut delegate_tx = Transaction::new(
            from,
            2,
            delegate_payload,
            ShardId::from_u32(0),
            None,
            TEST_CHAIN_ID,
        );
        delegate_tx.sign(&keypair, false).unwrap();
        let result = delegate_tx.validate_against_account(&account);
        assert!(result.is_ok());
    }

    #[test]
    fn test_claim_rewards() {
        let keypair = create_test_keypair();
        let node_id = Address::from_public_key(&keypair.dilithium_public_key());
        let reward_claim = RewardClaim {
            storage_rewards: Balance::from(1000u64),
            consensus_rewards: Balance::from(2000u64),
            coverage_rewards: Balance::from(500u64),
            retrieval_fees: Balance::from(300u64),
            total: Balance::from(3800u64),
        };
        let payload = TransactionPayload::ClaimRewards {
            node_id,
            epoch: 50,
            reward_buckets: reward_claim,
            drs_score: 0.95,
            drs_multiplier: 1.2,
            evidence_hash: Hash::new([80u8; 32]),
        };
        let mut tx = Transaction::new(
            node_id,
            1,
            payload,
            ShardId::from_u32(0),
            None,
            TEST_CHAIN_ID,
        );
        tx.sign(&keypair, false).unwrap();
        assert_eq!(tx.get_priority(), 90);
        assert!(tx.is_reward_transaction());
    }

    #[test]
    fn test_cross_shard_transaction() {
        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let payload = TransactionPayload::CrossShard {
            target_shard: ShardId::from_u32(1),
            message: vec![1, 2, 3, 4, 5],
            response_hash: Some(Hash::new([90u8; 32])),
            deadline_epoch: 200,
            nonce: 123,
        };
        let mut tx = Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
        tx.sign(&keypair, false).unwrap();
        assert_eq!(tx.get_priority(), 160);
    }

    #[test]
    fn test_rollup_commit() {
        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let payload = TransactionPayload::RollupCommit {
            rollup_id: "rollup-1".to_string(),
            state_root: Hash::new([100u8; 32]),
            tx_root: Hash::new([101u8; 32]),
            proofs_root: Hash::new([102u8; 32]),
            da_root: Hash::new([103u8; 32]),
            tx_count: 1000,
            block_range: (1000, 1100),
            epoch: 25,
            min_validity_proof: vec![11, 12, 13],
            fraud_proofs: vec![],
            operator_signature: vec![14, 15, 16],
        };
        let mut tx = Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
        tx.sign(&keypair, false).unwrap();
        assert_eq!(tx.get_priority(), 140);
        assert!(tx.requires_dilithium());
    }

    #[test]
    fn test_deploy_contract() {
        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let mut account = create_test_account(from, Balance::from(10_000u64));
        account.dilithium_pk = keypair.dilithium_public_key().key_data.clone();
        account.mlkem_pk = keypair.kyber_public_key().key_data.clone();
        account.free_deploys_remaining = 1;
        let payload = TransactionPayload::DeployContract {
            contract_code_hash: Hash::new([110u8; 32]),
            constructor_args: vec![1, 2, 3],
            deploy_credits: 0,
            use_free_quota: true,
            storage_refs: vec![],
        };
        let mut tx = Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
        tx.sign(&keypair, false).unwrap();
        let result = tx.validate_against_account(&account);
        assert!(result.is_ok());
        let ru = tx.estimate_resource_units();
        assert!(ru >= 5000);
    }

    #[test]
    fn test_dao_proposal_and_vote() {
        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let mut params = HashMap::new();
        params.insert("storage_split".to_string(), vec![50u8]);
        params.insert("consensus_split".to_string(), vec![30u8]);
        params.insert("coverage_split".to_string(), vec![20u8]);
        let proposal_payload = TransactionPayload::DAOProposal {
            proposal_type: DAOProposalType::UpdateRewardSplit,
            title: "Adjust reward distribution".to_string(),
            params,
            voting_period_epochs: 10,
            execution_delay_epochs: 2,
        };
        let mut proposal_tx = Transaction::new(
            from,
            1,
            proposal_payload,
            ShardId::from_u32(0),
            None,
            TEST_CHAIN_ID,
        );
        proposal_tx.sign(&keypair, false).unwrap();
        let proposal_hash = Hash::new([120u8; 32]);
        let vote_payload = TransactionPayload::DAOVote {
            proposal_id: proposal_hash,
            vote: true,
            voting_power: Balance::from(10_000u64),
        };
        let mut vote_tx = Transaction::new(
            from,
            2,
            vote_payload,
            ShardId::from_u32(0),
            None,
            TEST_CHAIN_ID,
        );
        vote_tx.sign(&keypair, false).unwrap();
        assert_eq!(proposal_tx.get_priority(), 20);
        assert_eq!(vote_tx.get_priority(), 20);
    }

    #[test]
    fn test_update_drs() {
        let keypair = create_test_keypair();
        let node_id = Address::from_public_key(&keypair.dilithium_public_key());
        let payload = TransactionPayload::UpdateDRS {
            node_id,
            epoch: 100,
            uptime_score: 0.98,
            post_latency_score: 0.95,
            post_pass_rate: 0.99,
            poc_quality_score: 0.92,
            serve_ratio: 0.88,
            density_penalty: 0.05,
            final_multiplier: 1.15,
            metrics_hash: Hash::new([130u8; 32]),
        };
        let mut tx = Transaction::new(
            node_id,
            1,
            payload,
            ShardId::from_u32(0),
            None,
            TEST_CHAIN_ID,
        );
        tx.sign(&keypair, false).unwrap();
        let drs_info = tx.extract_drs_update();
        assert!(drs_info.is_some());
        let info = drs_info.unwrap();
        assert_eq!(info.uptime_score, 0.98);
        assert_eq!(info.final_multiplier, 1.15);
        assert!(tx.requires_dilithium());
    }

    #[test]
    fn test_transaction_builder() {
        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let to = Address::new([140u8; 20]);
        let payload = TransactionPayload::Transfer {
            to,
            amount: Balance::from(5000u64),
            memo: Some("Builder test".to_string()),
            stealth_mode: false,
        };
        let tx = TransactionBuilder::new(from, 1, ShardId::from_u32(0), TEST_CHAIN_ID)
            .payload(payload)
            .ru_limit(2_000_000)
            .priority_hint(50)
            .build_and_sign(&keypair, false)
            .expect("Failed to build transaction");
        assert_eq!(tx.from, from);
        assert_eq!(tx.nonce, 1);
        assert_eq!(tx.ru_limit, 2_000_000);
        assert_eq!(tx.priority_hint, 50);
        assert!(tx.verify_signature().unwrap());
    }

    #[test]
    fn test_transaction_size() {
        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let to = Address::new([150u8; 20]);
        let payload = TransactionPayload::Transfer {
            to,
            amount: Balance::from(1000u64),
            memo: None,
            stealth_mode: false,
        };
        let mut tx = Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
        tx.sign(&keypair, false).unwrap();
        let size = tx.size();
        assert!(size > 0, "Transaction size should be greater than 0");
        assert!(size < 10_000, "Transaction size should be reasonable");
    }

    #[test]
    fn test_pq_transition() {
        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let payload = TransactionPayload::PQTransition {
            new_algorithms: vec![AlgorithmId::MlDsa2.as_u16(), AlgorithmId::MlKem768.as_u16()],
            disable_legacy: false,
            transition_epoch: 1000,
            migration_period_epochs: 100,
        };
        let mut tx = Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
        tx.sign(&keypair, false).unwrap();
        assert_eq!(tx.get_priority(), 230);
        assert!(tx.requires_dilithium());
    }

    #[test]
    fn test_system_operation() {
        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let payload = TransactionPayload::SystemOperation {
            operation_id: "epoch-anchor-1000".to_string(),
            data: vec![1, 2, 3, 4],
            auth_level: 5,
            epoch_anchor: true,
            requires_quorum: true,
        };
        let mut tx = Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
        tx.sign(&keypair, false).unwrap();
        assert_eq!(tx.get_priority(), 255);
        assert!(tx.requires_dilithium());
        assert!(tx.requires_slh_dsa());
        let ru = tx.estimate_resource_units();
        assert!(ru >= 20_000);
    }

    #[test]
    fn test_transaction_categories() {
        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let store_payload = TransactionPayload::BuyStorageCredits {
            amount: Balance::from(1000u64),
            credits_byte_months: 10_000_000,
            burn_proof: Hash::new([160u8; 32]),
        };
        let mut store_tx = Transaction::new(
            from,
            1,
            store_payload,
            ShardId::from_u32(0),
            None,
            TEST_CHAIN_ID,
        );
        store_tx.sign(&keypair, false).unwrap();
        assert!(store_tx.is_storage_transaction());
        let proof_payload = TransactionPayload::SubmitProofBatch {
            proof_type: ProofType::PoSt,
            proofs: vec![],
            batch_merkle_root: Hash::new([170u8; 32]),
            epoch: 50,
            rollup_id: None,
        };
        let mut proof_tx = Transaction::new(
            from,
            2,
            proof_payload,
            ShardId::from_u32(0),
            None,
            TEST_CHAIN_ID,
        );
        proof_tx.sign(&keypair, false).unwrap();
        assert!(proof_tx.is_proof_transaction());
        let reward_payload = TransactionPayload::PayRetrievalFee {
            provider: Address::new([180u8; 20]),
            chunk_ids: vec![Hash::new([190u8; 32])],
            bytes_served: 1_000_000,
            rate_per_gb: Balance::from(100u64),
            session_proof: vec![1, 2, 3],
        };
        let mut reward_tx = Transaction::new(
            from,
            3,
            reward_payload,
            ShardId::from_u32(0),
            None,
            TEST_CHAIN_ID,
        );
        reward_tx.sign(&keypair, false).unwrap();
        assert!(reward_tx.is_reward_transaction());
    }

    #[test]
    fn test_invalid_signature_address_mismatch() {
        let keypair1 = create_test_keypair();
        let keypair2 = create_test_keypair();
        let from = Address::from_public_key(&keypair1.dilithium_public_key());
        let to = Address::new([200u8; 20]);
        let payload = TransactionPayload::Transfer {
            to,
            amount: Balance::from(1000u64),
            memo: None,
            stealth_mode: false,
        };
        let mut tx = Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
        let result = tx.sign(&keypair2, false);
        assert!(
            result.is_err(),
            "Should fail when address doesn't match keypair"
        );
    }

    #[test]
    fn test_future_timestamp_validation() {
        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let to = Address::new([210u8; 20]);
        let account = create_test_account(from, Balance::from(10_000u64));
        let payload = TransactionPayload::Transfer {
            to,
            amount: Balance::from(1000u64),
            memo: None,
            stealth_mode: false,
        };
        let mut tx = Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
        tx.timestamp = Timestamp::from_millis(Timestamp::now().as_millis() + 360_000);
        tx.sign(&keypair, false).unwrap();
        let result = tx.validate_against_account(&account);
        assert!(result.is_err(), "Should fail with future timestamp");
    }

    #[test]
    fn test_slice_authorization() {
        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let to = Address::new([220u8; 20]);
        let mut account = create_test_account(from, Balance::from(10_000u64));
        account.dilithium_pk = keypair.dilithium_public_key().key_data.clone();
        account.mlkem_pk = keypair.kyber_public_key().key_data.clone();
        account.authorized_slices = vec![
            SliceId::new("personal".to_string()),
            SliceId::new("work".to_string()),
        ];
        let payload = TransactionPayload::Transfer {
            to,
            amount: Balance::from(100u64),
            memo: None,
            stealth_mode: false,
        };
        let mut tx = Transaction::new(
            from,
            1,
            payload.clone(),
            ShardId::from_u32(0),
            Some(SliceId::new("private".to_string())),
            TEST_CHAIN_ID,
        );
        tx.sign(&keypair, false).unwrap();
        let result = tx.validate_against_account(&account);
        assert!(result.is_err(), "Should fail with unauthorized slice");
        let mut tx = Transaction::new(
            from,
            1,
            payload,
            ShardId::from_u32(0),
            Some(SliceId::new("personal".to_string())),
            TEST_CHAIN_ID,
        );
        tx.sign(&keypair, false).unwrap();
        let result = tx.validate_against_account(&account);
        assert!(result.is_ok(), "Should succeed with authorized slice");
    }

    #[test]
    fn test_storage_quota_validation() {
        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let mut account = create_test_account(from, Balance::from(100_000u64));
        account.storage_quota = 1_000_000;
        account.storage_used = 500_000;
        let triad = create_test_triad_placement();
        let payload = TransactionPayload::StoreData {
            chunk_id: Hash::new([230u8; 32]),
            data_size: 1_000_000,
            duration_epochs: 10,
            data_hash: Hash::new([231u8; 32]),
            slice_id: SliceId::new("test".to_string()),
            storage_credits: 100,
            replication_factor: 3,
            triad_placement: triad,
            erasure_coding: ErasureCodingParams {
                k: 5,
                m: 2,
                codec: ErasureCodec::ReedSolomon,
            },
            encryption_envelope: None,
        };
        let mut tx = Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
        tx.sign(&keypair, false).unwrap();
        let result = tx.validate_against_account(&account);
        assert!(result.is_err(), "Should fail when exceeding storage quota");
    }

    #[test]
    fn test_storage_credits_validation() {
        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let mut account = create_test_account(from, Balance::from(100_000u64));
        account.storage_credits = 50;
        let triad = create_test_triad_placement();
        let payload = TransactionPayload::StoreData {
            chunk_id: Hash::new([240u8; 32]),
            data_size: 1024,
            duration_epochs: 10,
            data_hash: Hash::new([241u8; 32]),
            slice_id: SliceId::new("test".to_string()),
            storage_credits: 100,
            replication_factor: 3,
            triad_placement: triad,
            erasure_coding: ErasureCodingParams {
                k: 5,
                m: 2,
                codec: ErasureCodec::ReedSolomon,
            },
            encryption_envelope: None,
        };
        let mut tx = Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
        tx.sign(&keypair, false).unwrap();
        let result = tx.validate_against_account(&account);
        assert!(
            result.is_err(),
            "Should fail with insufficient storage credits"
        );
    }

    #[test]
    fn test_deploy_credits_validation() {
        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let mut account = create_test_account(from, Balance::from(100_000u64));
        account.deploy_credits = 10;
        account.free_deploys_remaining = 0;
        let payload = TransactionPayload::DeployContract {
            contract_code_hash: Hash::new([250u8; 32]),
            constructor_args: vec![],
            deploy_credits: 20,
            use_free_quota: false,
            storage_refs: vec![],
        };
        let mut tx = Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
        tx.sign(&keypair, false).unwrap();
        let result = tx.validate_against_account(&account);
        assert!(
            result.is_err(),
            "Should fail with insufficient deploy credits"
        );
    }

    #[test]
    fn test_encryption_envelope() {
        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let envelope = EncryptionEnvelope {
            kyber_ciphertexts: vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]],
            recipient_addresses: vec![Address::new([10u8; 20]), Address::new([11u8; 20])],
            nonce24: [99u8; 24],
            auth_tag: vec![88, 77, 66],
        };
        let triad = create_test_triad_placement();
        let payload = TransactionPayload::StoreData {
            chunk_id: Hash::new([26u8; 32]),
            data_size: 1024,
            duration_epochs: 10,
            data_hash: Hash::new([27u8; 32]),
            slice_id: SliceId::new("encrypted".to_string()),
            storage_credits: 100,
            replication_factor: 3,
            triad_placement: triad,
            erasure_coding: ErasureCodingParams {
                k: 5,
                m: 2,
                codec: ErasureCodec::ReedSolomon,
            },
            encryption_envelope: Some(envelope),
        };
        let mut tx = Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
        tx.sign(&keypair, false).unwrap();
        if let TransactionPayload::StoreData {
            encryption_envelope,
            ..
        } = &tx.payload
        {
            assert!(encryption_envelope.is_some());
            let env = encryption_envelope.as_ref().unwrap();
            assert_eq!(env.kyber_ciphertexts.len(), 2);
            assert_eq!(env.recipient_addresses.len(), 2);
        } else {
            panic!("Wrong payload type");
        }
    }

    #[test]
    fn test_fraud_challenge_lifecycle() {
        let keypair = create_test_keypair();
        let challenger = Address::from_public_key(&keypair.dilithium_public_key());
        let mut account = create_test_account(challenger, Balance::from(100_000u64));
        account.dilithium_pk = keypair.dilithium_public_key().key_data.clone();
        account.mlkem_pk = keypair.kyber_public_key().key_data.clone();
        let challenge_payload = TransactionPayload::ChallengeFraud {
            rollup_id: "rollup-1".to_string(),
            commit_hash: Hash::new([28u8; 32]),
            fraud_type: FraudType::InvalidStateTransition,
            proof_data: vec![1, 2, 3, 4, 5],
            challenger,
            challenge_bond: Balance::from(10_000u64),
        };
        let mut challenge_tx = Transaction::new(
            challenger,
            1,
            challenge_payload,
            ShardId::from_u32(0),
            None,
            TEST_CHAIN_ID,
        );
        challenge_tx.sign(&keypair, false).unwrap();
        let result = challenge_tx.validate_against_account(&account);
        assert!(result.is_ok(), "Should succeed with sufficient bond");
        account.nonce = 1;
        let resolve_payload = TransactionPayload::ResolveFraudChallenge {
            challenge_id: Hash::new([29u8; 32]),
            resolution: FraudResolution::ChallengeValid,
            evidence: vec![6, 7, 8, 9],
            slashing_amount: Some(Balance::from(5000u64)),
        };
        let mut resolve_tx = Transaction::new(
            challenger,
            2,
            resolve_payload,
            ShardId::from_u32(0),
            None,
            TEST_CHAIN_ID,
        );
        resolve_tx.sign(&keypair, false).unwrap();
        assert_eq!(resolve_tx.get_priority(), 125);
    }

    #[test]
    fn test_poc_witness_report() {
        let keypair = create_test_keypair();
        let prover = Address::from_public_key(&keypair.dilithium_public_key());
        let witness_reports = vec![
            WitnessReport {
                witness_id: Address::new([30u8; 20]),
                signal_strength_dbm: -75,
                timing_advance: 100,
                snr_db: 15.5,
                path_loss_db: 85.2,
                witness_signature: vec![1, 2, 3],
                timestamp: Timestamp::now(),
            },
            WitnessReport {
                witness_id: Address::new([31u8; 20]),
                signal_strength_dbm: -80,
                timing_advance: 120,
                snr_db: 12.3,
                path_loss_db: 90.1,
                witness_signature: vec![4, 5, 6],
                timestamp: Timestamp::now(),
            },
        ];
        let signal_quality = SignalQuality {
            rsrp_dbm: -70,
            rsrq_db: -10.5,
            sinr_db: 18.2,
            cell_id: 12345,
            confidence_score: 0.92,
        };
        let payload = TransactionPayload::PoCWitnessReport {
            prover,
            location_h3: "8928308280fffff".to_string(),
            witness_reports,
            signal_quality,
            multi_witness_proof: vec![7, 8, 9],
            timestamp_proof: vec![10, 11, 12],
        };
        let mut tx = Transaction::new(
            prover,
            1,
            payload,
            ShardId::from_u32(0),
            None,
            TEST_CHAIN_ID,
        );
        tx.sign(&keypair, false).unwrap();
        assert_eq!(tx.get_priority(), 180);
        assert!(tx.is_proof_transaction());
        let ru = tx.estimate_resource_units();
        assert!(ru >= 2200);
    }

    #[test]
    fn test_update_account() {
        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let mut metadata_updates = HashMap::new();
        metadata_updates.insert("email".to_string(), Some("user@example.com".to_string()));
        metadata_updates.insert("name".to_string(), Some("Alice".to_string()));
        let updates = AccountUpdates {
            storage_quota: Some(20_000_000_000),
            add_slices: vec![
                SliceId::new("work".to_string()),
                SliceId::new("private".to_string()),
            ],
            remove_slices: vec![],
            device_capabilities: None,
            metadata_updates,
            dilithium_pk: None,
            mlkem_pk: None,
            ed25519_pk: None,
            x25519_pk: None,
            peer_id: Some("QmAbCdEf123456".to_string()),
            pq_transition: None,
        };
        let payload = TransactionPayload::UpdateAccount {
            account_address: from,
            updates,
        };
        let mut tx = Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
        tx.sign(&keypair, false).unwrap();
        let ru = tx.estimate_resource_units();
        assert_eq!(ru, 700);
    }

    #[test]
    fn test_slice_operations() {
        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let mut params = HashMap::new();
        params.insert("capacity".to_string(), "1000000".to_string());
        params.insert("priority".to_string(), "high".to_string());
        let payload = TransactionPayload::SliceOperation {
            operation: SliceOperationType::Create,
            slice_id: SliceId::new("new-slice".to_string()),
            params,
        };
        let mut tx = Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
        tx.sign(&keypair, false).unwrap();
        let ru = tx.estimate_resource_units();
        assert_eq!(ru, 2100);
    }

    #[test]
    fn test_validator_only_operations() {
        let keypair = create_test_keypair();
        let from = Address::from_public_key(&keypair.dilithium_public_key());
        let mut non_validator_account = create_test_account(from, Balance::from(100_000u64));
        non_validator_account.account_type = AccountType::EOA;
        let payload = TransactionPayload::SystemOperation {
            operation_id: "epoch-1000".to_string(),
            data: vec![1, 2, 3],
            auth_level: 5,
            epoch_anchor: true,
            requires_quorum: true,
        };
        let mut tx = Transaction::new(from, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
        tx.sign(&keypair, false).unwrap();
        let result = tx.validate_against_account(&non_validator_account);
        assert!(
            result.is_err(),
            "Non-validators cannot submit epoch anchors"
        );
    }

    #[test]
    fn test_claim_rewards_validation() {
        let keypair1 = create_test_keypair();
        let keypair2 = create_test_keypair();
        let node1 = Address::from_public_key(&keypair1.dilithium_public_key());
        let node2 = Address::from_public_key(&keypair2.dilithium_public_key());
        let account = create_test_account(node1, Balance::from(10_000u64));
        let reward_claim = RewardClaim {
            storage_rewards: Balance::from(500u64),
            consensus_rewards: Balance::from(300u64),
            coverage_rewards: Balance::from(200u64),
            retrieval_fees: Balance::from(100u64),
            total: Balance::from(1100u64),
        };
        let payload = TransactionPayload::ClaimRewards {
            node_id: node2,
            epoch: 50,
            reward_buckets: reward_claim,
            drs_score: 0.9,
            drs_multiplier: 1.1,
            evidence_hash: Hash::new([32u8; 32]),
        };
        let mut tx = Transaction::new(node1, 1, payload, ShardId::from_u32(0), None, TEST_CHAIN_ID);
        tx.sign(&keypair1, false).unwrap();
        let result = tx.validate_against_account(&account);
        assert!(result.is_err(), "Cannot claim rewards for another node");
    }

    #[test]
    fn test_transaction_result_structure() {
        let tx_result = TransactionResult {
            tx_hash: Hash::new([33u8; 32]),
            success: true,
            error: None,
            ru_used: 1500,
            storage_used: 1024,
            state_changes: vec![StateChange {
                account: Address::new([34u8; 20]),
                change_type: StateChangeType::BalanceUpdate,
                previous_value: Some(vec![0, 0, 0, 100]),
                new_value: vec![0, 0, 0, 90],
            }],
            events: vec![TransactionEvent {
                event_type: "Transfer".to_string(),
                data: "Transferred 10 tokens".to_string(),
                block_height: 1000,
                tx_index: 5,
            }],
            cross_shard_receipts: vec![],
            pq_verification_result: Some(PQVerificationResult {
                dilithium_verified: true,
                ed25519_verified: None,
                algorithms_used: vec![AlgorithmId::MlDsa2.as_u16()],
                transition_compliant: true,
            }),
            proof_verifications: vec![],
        };
        assert!(tx_result.success);
        assert_eq!(tx_result.state_changes.len(), 1);
        assert_eq!(tx_result.events.len(), 1);
        assert!(tx_result.pq_verification_result.is_some());
    }

    fn create_test_triad_placement() -> TriadPlacement {
        TriadPlacement {
            primary: NodeLocation {
                node_id: Address::new([100u8; 20]),
                h3_cell: "8928308280fffff".to_string(),
                shard_id: 0,
                region: "us-west".to_string(),
                lat_lon: Some((37.7749, -122.4194)),
            },
            replica_a: NodeLocation {
                node_id: Address::new([101u8; 20]),
                h3_cell: "8928308280aaaaa".to_string(),
                shard_id: 0,
                region: "us-east".to_string(),
                lat_lon: Some((40.7128, -74.0060)),
            },
            replica_b: NodeLocation {
                node_id: Address::new([102u8; 20]),
                h3_cell: "8928308280bbbbb".to_string(),
                shard_id: 0,
                region: "eu-west".to_string(),
                lat_lon: Some((51.5074, -0.1278)),
            },
            group_id: "test-group".to_string(),
            placement_epoch: 100,
            diversity_score: 0.9,
        }
    }
}

#[cfg(test)]
mod transaction_integration_tests {
    use ego_core::{
        crypto::KeyPair, transaction::*, Account, AccountType, Address, Balance, Hash, ShardId,
        SliceId, Timestamp,
    };
    use std::collections::HashMap;

    const TEST_CHAIN_ID: u32 = 1;

    #[test]
    fn test_full_transaction_lifecycle() {
        let sender_keypair = KeyPair::generate();
        let sender_addr = Address::from_public_key(&sender_keypair.dilithium_public_key());
        let mut sender_account = Account {
            address: sender_addr,
            balance: Balance::from(100_000u64),
            nonce: 0,
            storage_used: 0,
            storage_quota: 10_000_000,
            storage_credits: 10_000,
            deploy_credits: 50,
            free_deploys_remaining: 3,
            account_type: AccountType::EOA,
            dilithium_pk: sender_keypair.dilithium_public_key().key_data.clone(),
            mlkem_pk: sender_keypair.kyber_public_key().key_data.clone(),
            ed25519_pk: None,
            x25519_pk: None,
            slh_dsa_pk: None,
            authorized_slices: vec![SliceId::new("personal".to_string())],
            metadata: HashMap::new(),
            device_capabilities: None,
            peer_id: None,
            pq_transition_info: Some(ego_core::account::PQTransitionInfo {
                transition_started_epoch: 300,
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
        };
        let recipient_addr = Address::new([99u8; 20]);
        let payload = TransactionPayload::Transfer {
            to: recipient_addr,
            amount: Balance::from(5_000u64),
            memo: Some("Integration test".to_string()),
            stealth_mode: false,
        };
        let tx = TransactionBuilder::new(sender_addr, 1, ShardId::from_u32(0), TEST_CHAIN_ID)
            .payload(payload)
            .ru_limit(1_000_000)
            .priority_hint(10)
            .build_and_sign(&sender_keypair, false)
            .expect("Failed to build transaction");
        assert!(tx.verify_signature().unwrap());
        assert!(tx.validate_against_account(&sender_account).is_ok());
        sender_account.nonce += 1;
        sender_account.balance = Balance::from(94_990u64);
        assert_eq!(sender_account.nonce, 1);
        assert_eq!(sender_account.balance, Balance::from(94_990u64));
    }

    #[test]
    fn test_multi_transaction_sequence() {
        let keypair = KeyPair::generate();
        let addr = Address::from_public_key(&keypair.dilithium_public_key());
        let mut account = Account {
            address: addr,
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
        };
        let transactions = vec![
            TransactionPayload::BuyStorageCredits {
                amount: Balance::from(10_000u64),
                credits_byte_months: 100_000,
                burn_proof: Hash::new([1u8; 32]),
            },
            TransactionPayload::Transfer {
                to: Address::new([2u8; 20]),
                amount: Balance::from(50_000u64),
                memo: None,
                stealth_mode: false,
            },
            TransactionPayload::Delegate {
                amount: Balance::from(100_000u64),
                validator_pubkey: keypair.dilithium_public_key(),
            },
        ];
        for (i, payload) in transactions.into_iter().enumerate() {
            let nonce = (i as u64) + 1;
            let mut tx = Transaction::new(
                addr,
                nonce,
                payload,
                ShardId::from_u32(0),
                None,
                TEST_CHAIN_ID,
            );
            tx.sign(&keypair, false).expect("Signing failed");
            assert!(tx.verify_signature().unwrap());
            assert!(
                tx.validate_against_account(&account).is_ok(),
                "Transaction {} should validate against account",
                i + 1
            );
            account.nonce = nonce;
            match &tx.payload {
                TransactionPayload::BuyStorageCredits {
                    amount,
                    credits_byte_months,
                    ..
                } => {
                    account.balance = Balance::from(account.balance.as_u128() - amount.as_u128());
                    account.storage_credits += credits_byte_months;
                }
                TransactionPayload::Transfer { amount, .. }
                | TransactionPayload::Delegate { amount, .. } => {
                    account.balance = Balance::from(account.balance.as_u128() - amount.as_u128());
                }
                _ => {}
            }
        }
        assert_eq!(account.nonce, 3);
        assert_eq!(account.balance, Balance::from(840_000u64));
    }
}
