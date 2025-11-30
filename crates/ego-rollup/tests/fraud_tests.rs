#[cfg(test)]
mod fraud_tests {
    use ego_core::{
        Address, Balance, Hash, ShardId, Timestamp, Transaction, TransactionPayload,
        crypto::KeyPair,
    };
    use ego_rollup::fraud::{
        AccountStateProof, ChallengeResponse, ChallengeStatus, DRSComponentsEvidence, DRSEvidence,
        DRSPenaltiesEvidence, DeployEvidence, DeployViolationType, FraudEvidence,
        FraudEvidenceType, FraudProof, FraudProofBuilder, FraudProofVerifier, ResolutionType,
        RollupCommitment, RollupFraudType, RollupTransaction, SamplingRequest, TimeoutEvidence,
    };
    use std::collections::HashMap;

    fn generate_keypair() -> KeyPair {
        KeyPair::generate()
    }

    fn create_signed_test_commitment(operator_keypair: &KeyPair) -> RollupCommitment {
        let operator = Address::from_public_key(&operator_keypair.dilithium_public_key());
        let mut commitment = RollupCommitment {
            rollup_id: "test_rollup".to_string(),
            state_root: Hash::new([1u8; 32]),
            previous_state_root: Hash::new([2u8; 32]),
            tx_root: Hash::new([3u8; 32]),
            proofs_root: Hash::new([4u8; 32]),
            da_root: Hash::new([5u8; 32]),
            tx_count: 10,
            block_range: (1, 10),
            operator,
            timestamp: Timestamp::now(),
            epoch: 1,
            shard_id: ShardId::new(0).unwrap(),
            commitment_hash: Hash::new([0u8; 32]),
            operator_signature: Vec::new(),
            operator_dilithium_pk: operator_keypair.dilithium_public_key().key_data.clone(),
        };
        let hash = commitment.compute_hash();
        commitment.commitment_hash = hash;
        let sig = operator_keypair.sign_dilithium(hash.as_bytes());
        commitment.operator_signature = sig.signature_data;
        commitment
    }

    fn create_test_transaction() -> RollupTransaction {
        let inner = Transaction::new(
            Address::from_public_key(&generate_keypair().dilithium_public_key()),
            1,
            TransactionPayload::Transfer {
                to: Address::new([1u8; 20]),
                amount: Balance::new(1000),
                memo: None,
                stealth_mode: false,
            },
            ShardId::new(0).unwrap(),
            None,
            1,
        );
        RollupTransaction {
            inner,
            rollup_id: "test_rollup".to_string(),
            batch_index: 0,
            inclusion_proof: vec![],
        }
    }

    fn create_account_state_proof() -> AccountStateProof {
        AccountStateProof {
            address: Address::new([0xAA; 20]),
            balance: Balance::new(1_000_000),
            nonce: 5,
            storage_quota: 1000,
            merkle_proof: vec![Hash::new([0xBB; 32])],
            account_type: "user".to_string(),
        }
    }

    #[test]
    fn test_fraud_proof_creation_and_signing() {
        let challenger_keypair = generate_keypair();
        let operator_keypair = generate_keypair();
        let commitment = create_signed_test_commitment(&operator_keypair);

        let mut proof = FraudProof::new(
            Address::from_public_key(&challenger_keypair.dilithium_public_key()),
            commitment.compute_hash(),
            RollupFraudType::InvalidInclusion,
            FraudEvidence {
                commitment,
                evidence_type: FraudEvidenceType::InvalidInclusion {
                    inclusion_proof: vec![Hash::new([0xAA; 32])],
                    merkle_root: Hash::new([0xAB; 32]),
                    invalid_reason: "tx not included".to_string(),
                    transaction_index: 0,
                    claimed_transaction: create_test_transaction(),
                },
                proof_data: vec![],
                witness_data: None,
                reference_commitments: vec![],
                auxiliary_data: HashMap::new(),
                state_proof: None,
                drs_evidence: None,
                deploy_evidence: None,
            },
            0.95,
            100_000,
            100,
            ShardId::new(0).unwrap(),
        );

        proof.sign(&challenger_keypair).unwrap();
        assert!(proof.verify_signature().unwrap());
    }

    #[test]
    fn test_fraud_proof_validation_state_transition() {
        let challenger_keypair = generate_keypair();
        let operator_keypair = generate_keypair();
        let commitment = create_signed_test_commitment(&operator_keypair);

        let mut proof = FraudProof::new(
            Address::from_public_key(&challenger_keypair.dilithium_public_key()),
            commitment.compute_hash(),
            RollupFraudType::InvalidStateTransition,
            FraudEvidence {
                commitment: commitment.clone(),
                evidence_type: FraudEvidenceType::StateTransition {
                    pre_state: Hash::new([0x20; 32]),
                    post_state: Hash::new([0x21; 32]),
                    expected_post_state: Hash::new([0x22; 32]),
                    execution_trace: vec![],
                    transaction_batch: vec![create_test_transaction()],
                    intermediate_states: vec![Hash::new([0x20; 32]), Hash::new([0x21; 32])],
                    account_proofs: vec![create_account_state_proof()],
                },
                proof_data: vec![],
                witness_data: None,
                reference_commitments: vec![],
                auxiliary_data: HashMap::new(),
                state_proof: None,
                drs_evidence: None,
                deploy_evidence: None,
            },
            0.95,
            100_000,
            100,
            ShardId::new(0).unwrap(),
        );

        proof.sign(&challenger_keypair).unwrap();
        proof.validate().unwrap();
    }

    #[test]
    fn test_challenge_lifecycle() {
        let challenger_keypair = generate_keypair();
        let operator_keypair = generate_keypair();
        let commitment = create_signed_test_commitment(&operator_keypair);

        let mut proof = FraudProof::new(
            Address::from_public_key(&challenger_keypair.dilithium_public_key()),
            commitment.compute_hash(),
            RollupFraudType::InvalidStateTransition,
            FraudEvidence {
                commitment: commitment.clone(),
                evidence_type: FraudEvidenceType::StateTransition {
                    pre_state: Hash::new([0x40; 32]),
                    post_state: Hash::new([0x41; 32]),
                    expected_post_state: Hash::new([0x42; 32]),
                    execution_trace: vec![],
                    transaction_batch: vec![create_test_transaction()],
                    intermediate_states: vec![],
                    account_proofs: vec![create_account_state_proof()],
                },
                proof_data: vec![],
                witness_data: None,
                reference_commitments: vec![],
                auxiliary_data: HashMap::new(),
                state_proof: None,
                drs_evidence: None,
                deploy_evidence: None,
            },
            0.95,
            100_000,
            100,
            ShardId::new(0).unwrap(),
        );

        proof.sign(&challenger_keypair).unwrap();

        let verifier = FraudProofVerifier::new(0.9, 24);
        let challenge = verifier.create_challenge(&proof).unwrap();
        assert_eq!(challenge.status, ChallengeStatus::Pending);

        let mut response = ChallengeResponse::new(
            commitment.operator,
            b"counter evidence".to_vec(),
            vec![Hash::new([0xAA; 32])],
        );
        response = response.with_state_recomputation(ego_rollup::fraud::StateRecomputationProof {
            initial_state: Hash::new([0x40; 32]),
            final_state: Hash::new([0x41; 32]),
            transaction_hashes: vec![create_test_transaction().hash()],
            intermediate_roots: vec![Hash::new([0x40; 32]), Hash::new([0x41; 32])],
            execution_logs: vec![],
        });
        response.sign(&operator_keypair).unwrap();

        verifier
            .respond_to_challenge(challenge.challenge_id, response)
            .unwrap();

        let updated = verifier.get_challenge(&challenge.challenge_id).unwrap();
        assert_eq!(updated.status, ChallengeStatus::Responded);

        let resolver = Address::new([0x60; 20]);
        let resolution = verifier
            .resolve_challenge(challenge.challenge_id, resolver, 1)
            .unwrap();

        assert_eq!(resolution.resolution_type, ResolutionType::ChallengeValid);
        assert_eq!(resolution.slashed_party, Some(commitment.operator));
    }

    #[test]
    fn test_fraud_proof_builder() {
        let keypair = generate_keypair();
        let operator_keypair = generate_keypair();
        let commitment = create_signed_test_commitment(&operator_keypair);
        let challenger = Address::from_public_key(&keypair.dilithium_public_key());

        let builder =
            FraudProofBuilder::new(challenger, commitment, RollupFraudType::InvalidInclusion)
                .confidence(0.92)
                .challenge_bond(180_000)
                .deadline_epoch(100)
                .evidence_type(FraudEvidenceType::InvalidInclusion {
                    inclusion_proof: vec![Hash::new([0x80; 32])],
                    merkle_root: Hash::new([0x81; 32]),
                    invalid_reason: "tx not in rollup".to_string(),
                    transaction_index: 5,
                    claimed_transaction: create_test_transaction(),
                });

        let proof = builder.build_and_sign(&keypair).unwrap();
        assert_eq!(proof.fraud_type, RollupFraudType::InvalidInclusion);
        assert_eq!(proof.confidence, 0.92);
        assert!(proof.verify_signature().unwrap());
    }

    #[test]
    fn test_severity_and_priority_scoring() {
        let keypair = generate_keypair();
        let operator_keypair = generate_keypair();
        let commitment = create_signed_test_commitment(&operator_keypair);

        let mut proof = FraudProof::new(
            Address::from_public_key(&keypair.dilithium_public_key()),
            commitment.compute_hash(),
            RollupFraudType::InvalidEpochAnchor,
            FraudEvidence {
                commitment: commitment.clone(),
                evidence_type: FraudEvidenceType::DeployViolation {
                    deployer: Address::new([0xA0; 20]),
                    deploy_id: Hash::new([0xA1; 32]),
                    violation_type: DeployViolationType::QuotaExceeded,
                    policy_snapshot: b"policy".to_vec(),
                },
                proof_data: vec![],
                witness_data: None,
                reference_commitments: vec![],
                auxiliary_data: HashMap::new(),
                state_proof: None,
                drs_evidence: None,
                deploy_evidence: None,
            },
            0.85,
            140_000,
            100,
            ShardId::new(0).unwrap(),
        );

        proof.sign(&keypair).unwrap();

        assert_eq!(proof.severity_score(), 10 + (0.85 * 5.0) as u32);
        assert_eq!(
            proof.priority,
            255u8.saturating_add((0.85 * 10.0) as u8).min(255)
        );
    }

    #[test]
    fn test_statistics_tracking() {
        let keypair = generate_keypair();
        let operator_keypair = generate_keypair();
        let commitment = create_signed_test_commitment(&operator_keypair);

        let mut proof = FraudProof::new(
            Address::from_public_key(&keypair.dilithium_public_key()),
            commitment.compute_hash(),
            RollupFraudType::DuplicateTransaction,
            FraudEvidence {
                commitment: commitment.clone(),
                evidence_type: FraudEvidenceType::StateTransition {
                    pre_state: Hash::new([0xC0; 32]),
                    post_state: Hash::new([0xC1; 32]),
                    expected_post_state: Hash::new([0xC2; 32]),
                    execution_trace: vec![],
                    transaction_batch: vec![create_test_transaction()],
                    intermediate_states: vec![],
                    account_proofs: vec![create_account_state_proof()],
                },
                proof_data: vec![],
                witness_data: None,
                reference_commitments: vec![],
                auxiliary_data: HashMap::new(),
                state_proof: None,
                drs_evidence: None,
                deploy_evidence: None,
            },
            0.9,
            10_000,
            100,
            ShardId::new(0).unwrap(),
        );

        proof.sign(&keypair).unwrap();

        let verifier = FraudProofVerifier::new(0.8, 24);
        assert!(verifier.verify_fraud_proof(&proof).unwrap());

        let stats = verifier.get_fraud_statistics();
        assert_eq!(stats.total_challenges, 1);
        assert_eq!(
            stats
                .fraud_types
                .get(&RollupFraudType::DuplicateTransaction),
            Some(&1)
        );
        assert!(stats.avg_confidence > 0.0);
    }

    #[test]
    fn test_data_unavailability_fraud() {
        let keypair = generate_keypair();
        let operator_keypair = generate_keypair();
        let commitment = create_signed_test_commitment(&operator_keypair);

        let fraud = FraudProof::new(
            Address::from_public_key(&keypair.dilithium_public_key()),
            commitment.compute_hash(),
            RollupFraudType::DataUnavailable,
            FraudEvidence {
                commitment,
                evidence_type: FraudEvidenceType::DataUnavailability {
                    missing_chunks: vec![0, 1, 2],
                    sample_proofs: vec![],
                    timeout_evidence: vec![TimeoutEvidence {
                        chunk_id: 0,
                        request_timestamp: Timestamp::now(),
                        timeout_timestamp: Timestamp::now().add_millis(50_000),
                        operator: Address::new([0xD0; 20]),
                        retry_count: 3,
                        last_error: "timeout".to_string(),
                    }],
                    sampling_requests: vec![SamplingRequest {
                        request_id: Hash::new([0xE0; 32]),
                        chunk_indices: vec![0, 1, 2],
                        timestamp: Timestamp::now(),
                        requester: Address::from_public_key(&keypair.dilithium_public_key()),
                        response_received: false,
                        response_time_ms: None,
                    }],
                    total_chunks: 10,
                    da_commitment: Hash::new([0xF0; 32]),
                },
                proof_data: vec![],
                witness_data: None,
                reference_commitments: vec![],
                auxiliary_data: HashMap::new(),
                state_proof: None,
                drs_evidence: None,
                deploy_evidence: None,
            },
            0.9,
            150_000,
            100,
            ShardId::new(0).unwrap(),
        );

        fraud.validate().unwrap();
    }

    #[test]
    fn test_deploy_violation_fraud() {
        let keypair = generate_keypair();
        let operator_keypair = generate_keypair();
        let commitment = create_signed_test_commitment(&operator_keypair);

        let fraud = FraudProof::new(
            Address::from_public_key(&keypair.dilithium_public_key()),
            commitment.compute_hash(),
            RollupFraudType::DeployPolicyViolation,
            FraudEvidence {
                commitment,
                evidence_type: FraudEvidenceType::DeployViolation {
                    deployer: Address::new([0xE0; 20]),
                    deploy_id: Hash::new([0xE1; 32]),
                    violation_type: DeployViolationType::QuotaExceeded,
                    policy_snapshot: b"quota=100".to_vec(),
                },
                proof_data: vec![],
                witness_data: None,
                reference_commitments: vec![],
                auxiliary_data: HashMap::new(),
                state_proof: None,
                drs_evidence: Some(DRSEvidence {
                    node_id: Address::new([0xE0; 20]),
                    epoch: 1,
                    components: DRSComponentsEvidence {
                        uptime: 0.9,
                        post_pass: 0.8,
                        inv_latency: 0.7,
                        poc_quality: 0.6,
                        serve_ratio: 0.5,
                    },
                    penalties: DRSPenaltiesEvidence {
                        failed_post: 2,
                        replay_or_incoherence: 1,
                        equivocation: 0,
                        total_penalty: 0.1,
                    },
                    claimed_multiplier: 1.2,
                    actual_multiplier: 0.9,
                }),
                deploy_evidence: Some(DeployEvidence {
                    deployer: Address::new([0xE0; 20]),
                    deploy_id: Hash::new([0xE1; 32]),
                    deploy_record: b"record".to_vec(),
                    quota_snapshot: b"100".to_vec(),
                    credits_snapshot: b"500".to_vec(),
                }),
            },
            0.85,
            140_000,
            100,
            ShardId::new(0).unwrap(),
        );

        fraud.validate().unwrap();
    }

    #[test]
    fn test_cross_shard_fraud() {
        let keypair = generate_keypair();
        let operator_keypair = generate_keypair();
        let commitment = create_signed_test_commitment(&operator_keypair);

        let fraud = FraudProof::new(
            Address::from_public_key(&keypair.dilithium_public_key()),
            commitment.compute_hash(),
            RollupFraudType::InvalidCrossShardReceipt,
            FraudEvidence {
                commitment,
                evidence_type: FraudEvidenceType::CrossShardInvalid {
                    receipt_hash: Hash::new([0xF1; 32]),
                    source_shard: 0,
                    target_shard: 1,
                    merkle_proof: vec![Hash::new([0xF2; 32])],
                    invalid_reason: "receipt not anchored".to_string(),
                    receipt_nonce: 12345,
                },
                proof_data: vec![],
                witness_data: None,
                reference_commitments: vec![],
                auxiliary_data: HashMap::new(),
                state_proof: None,
                drs_evidence: None,
                deploy_evidence: None,
            },
            0.87,
            170_000,
            100,
            ShardId::new(0).unwrap(),
        );

        fraud.validate().unwrap();
    }

    #[test]
    fn test_execution_error_fraud() {
        let keypair = generate_keypair();
        let operator_keypair = generate_keypair();
        let commitment = create_signed_test_commitment(&operator_keypair);

        let fraud = FraudProof::new(
            Address::from_public_key(&keypair.dilithium_public_key()),
            commitment.compute_hash(),
            RollupFraudType::InvalidExecution,
            FraudEvidence {
                commitment,
                evidence_type: FraudEvidenceType::ExecutionError {
                    expected_result: b"ok".to_vec(),
                    actual_result: b"fail".to_vec(),
                    error_trace: "RU exceeded".to_string(),
                    transaction: create_test_transaction(),
                    pre_state_proof: vec![Hash::new([0x12; 32])],
                    ru_consumed: 400,
                    ru_limit: 500,
                },
                proof_data: vec![],
                witness_data: None,
                reference_commitments: vec![],
                auxiliary_data: HashMap::new(),
                state_proof: None,
                drs_evidence: None,
                deploy_evidence: None,
            },
            0.92,
            180_000,
            100,
            ShardId::new(0).unwrap(),
        );

        fraud.validate().unwrap();
    }

    #[test]
    fn test_drs_manipulation_fraud() {
        let keypair = generate_keypair();
        let operator_keypair = generate_keypair();
        let commitment = create_signed_test_commitment(&operator_keypair);

        let fraud = FraudProof::new(
            Address::from_public_key(&keypair.dilithium_public_key()),
            commitment.compute_hash(),
            RollupFraudType::InvalidDRSScore,
            FraudEvidence {
                commitment,
                evidence_type: FraudEvidenceType::DRSManipulation {
                    node_id: Address::new([0x13; 20]),
                    claimed_score: 0.95,
                    actual_score: 0.6,
                    evidence_bundle_hash: Hash::new([0x14; 32]),
                    manipulation_type: ego_rollup::fraud::DRSManipulationType::FakeUptime,
                },
                proof_data: vec![],
                witness_data: None,
                reference_commitments: vec![],
                auxiliary_data: HashMap::new(),
                state_proof: None,
                drs_evidence: Some(DRSEvidence {
                    node_id: Address::new([0x13; 20]),
                    epoch: 1,
                    components: DRSComponentsEvidence {
                        uptime: 0.6,
                        post_pass: 0.7,
                        inv_latency: 0.8,
                        poc_quality: 0.9,
                        serve_ratio: 0.5,
                    },
                    penalties: DRSPenaltiesEvidence {
                        failed_post: 0,
                        replay_or_incoherence: 0,
                        equivocation: 0,
                        total_penalty: 0.0,
                    },
                    claimed_multiplier: 1.5,
                    actual_multiplier: 1.0,
                }),
                deploy_evidence: None,
            },
            0.88,
            160_000,
            100,
            ShardId::new(0).unwrap(),
        );

        fraud.validate().unwrap();
    }

    #[test]
    fn test_proof_aggregation_fraud() {
        let keypair = generate_keypair();
        let operator_keypair = generate_keypair();
        let commitment = create_signed_test_commitment(&operator_keypair);

        let fraud = FraudProof::new(
            Address::from_public_key(&keypair.dilithium_public_key()),
            commitment.compute_hash(),
            RollupFraudType::InvalidProofAggregation,
            FraudEvidence {
                commitment,
                evidence_type: FraudEvidenceType::ProofAggregation {
                    claimed_proof_root: Hash::new([0x11; 32]),
                    actual_proofs: vec![b"proof1".to_vec(), b"proof2".to_vec()],
                    recomputed_root: Hash::new([0x12; 32]),
                    invalid_indices: vec![0],
                    proof_type: ego_rollup::fraud::ProofAggregationType::PoSt,
                },
                proof_data: vec![],
                witness_data: None,
                reference_commitments: vec![],
                auxiliary_data: HashMap::new(),
                state_proof: None,
                drs_evidence: None,
                deploy_evidence: None,
            },
            0.9,
            160_000,
            100,
            ShardId::new(0).unwrap(),
        );

        fraud.validate().unwrap();
    }

    #[test]
    fn test_fraud_proof_batch_verification() {
        let keypair = generate_keypair();
        let operator_keypair = generate_keypair();
        let commitment = create_signed_test_commitment(&operator_keypair);
        let tx = create_test_transaction();

        let mut proof1 = FraudProof::new(
            Address::from_public_key(&keypair.dilithium_public_key()),
            commitment.compute_hash(),
            RollupFraudType::InvalidInclusion,
            FraudEvidence {
                commitment: commitment.clone(),
                evidence_type: FraudEvidenceType::InvalidInclusion {
                    inclusion_proof: vec![Hash::new([0x16; 32])],
                    merkle_root: Hash::new([0x17; 32]),
                    invalid_reason: "not included".to_string(),
                    transaction_index: 0,
                    claimed_transaction: tx.clone(),
                },
                proof_data: vec![],
                witness_data: None,
                reference_commitments: vec![],
                auxiliary_data: HashMap::new(),
                state_proof: None,
                drs_evidence: None,
                deploy_evidence: None,
            },
            0.9,
            100_000,
            100,
            ShardId::new(0).unwrap(),
        );

        let mut proof2 = FraudProof::new(
            Address::from_public_key(&keypair.dilithium_public_key()),
            commitment.compute_hash(),
            RollupFraudType::DataUnavailable,
            FraudEvidence {
                commitment,
                evidence_type: FraudEvidenceType::DataUnavailability {
                    missing_chunks: vec![0],
                    sample_proofs: vec![],
                    timeout_evidence: vec![TimeoutEvidence {
                        chunk_id: 0,
                        request_timestamp: Timestamp::now(),
                        timeout_timestamp: Timestamp::now().add_millis(40_000),
                        operator: Address::new([0x18; 20]),
                        retry_count: 2,
                        last_error: "no response".to_string(),
                    }],
                    sampling_requests: vec![SamplingRequest {
                        request_id: Hash::new([0x19; 32]),
                        chunk_indices: vec![0],
                        timestamp: Timestamp::now(),
                        requester: Address::from_public_key(&keypair.dilithium_public_key()),
                        response_received: false,
                        response_time_ms: None,
                    }],
                    total_chunks: 5,
                    da_commitment: Hash::new([0x1A; 32]),
                },
                proof_data: vec![],
                witness_data: None,
                reference_commitments: vec![],
                auxiliary_data: HashMap::new(),
                state_proof: None,
                drs_evidence: None,
                deploy_evidence: None,
            },
            0.85,
            120_000,
            100,
            ShardId::new(0).unwrap(),
        );

        proof1.sign(&keypair).unwrap();
        proof2.sign(&keypair).unwrap();

        let verifier = FraudProofVerifier::new(0.8, 24);
        let results =
            ego_rollup::fraud::verify_fraud_proof_batch(&verifier, &[proof1, proof2]).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0]);
        assert!(results[1]);
    }

    #[test]
    fn test_false_challenge_penalty() {
        let challenger_keypair = generate_keypair();
        let operator_keypair = generate_keypair();
        let commitment = create_signed_test_commitment(&operator_keypair);
        let verifier = FraudProofVerifier::new(0.8, 24);

        let mut proof = FraudProof::new(
            Address::from_public_key(&challenger_keypair.dilithium_public_key()),
            commitment.compute_hash(),
            RollupFraudType::InvalidStateTransition,
            FraudEvidence {
                commitment: commitment.clone(),
                evidence_type: FraudEvidenceType::StateTransition {
                    pre_state: Hash::new([0x30; 32]),
                    post_state: Hash::new([0x31; 32]),
                    expected_post_state: Hash::new([0x32; 32]),
                    execution_trace: vec![],
                    transaction_batch: vec![create_test_transaction()],
                    intermediate_states: vec![],
                    account_proofs: vec![create_account_state_proof()],
                },
                proof_data: vec![],
                witness_data: None,
                reference_commitments: vec![],
                auxiliary_data: HashMap::new(),
                state_proof: None,
                drs_evidence: None,
                deploy_evidence: None,
            },
            0.95,
            100_000,
            10,
            ShardId::new(0).unwrap(),
        );
        proof.sign(&challenger_keypair).unwrap();

        let challenge = verifier.create_challenge(&proof).unwrap();

        let mut response = ChallengeResponse::new(
            commitment.operator,
            vec![1u8; 100],
            vec![Hash::new([0xCC; 32])],
        );
        response.sign(&operator_keypair).unwrap();

        verifier
            .respond_to_challenge(challenge.challenge_id, response)
            .unwrap();

        let resolver = Address::new([0x99; 20]);
        let resolution = verifier
            .resolve_challenge(challenge.challenge_id, resolver, 1)
            .unwrap();

        assert_eq!(resolution.resolution_type, ResolutionType::ChallengeInvalid);
        assert_eq!(
            resolution.slashed_party,
            Some(Address::from_public_key(
                &challenger_keypair.dilithium_public_key()
            ))
        );
    }

    #[test]
    fn test_prune_old_challenges() {
        let verifier = FraudProofVerifier::new(0.8, 24);
        assert_eq!(verifier.prune_old_challenges(10), 0);
    }

    #[test]
    fn test_fraud_proof_confidence_rejection() {
        let keypair = generate_keypair();
        let operator_keypair = generate_keypair();
        let commitment = create_signed_test_commitment(&operator_keypair);

        let proof = FraudProof::new(
            Address::from_public_key(&keypair.dilithium_public_key()),
            commitment.compute_hash(),
            RollupFraudType::InvalidStateTransition,
            FraudEvidence {
                commitment,
                evidence_type: FraudEvidenceType::StateTransition {
                    pre_state: Hash::new([0x10; 32]),
                    post_state: Hash::new([0x11; 32]),
                    expected_post_state: Hash::new([0x12; 32]),
                    execution_trace: vec![],
                    transaction_batch: vec![create_test_transaction()],
                    intermediate_states: vec![],
                    account_proofs: vec![create_account_state_proof()],
                },
                proof_data: vec![],
                witness_data: None,
                reference_commitments: vec![],
                auxiliary_data: HashMap::new(),
                state_proof: None,
                drs_evidence: None,
                deploy_evidence: None,
            },
            0.6,
            100_000,
            100,
            ShardId::new(0).unwrap(),
        );

        assert!(proof.validate().is_err());
    }

    #[test]
    fn test_challenge_response_signature_verification() {
        let keypair = generate_keypair();
        let response = ChallengeResponse::new(
            Address::from_public_key(&keypair.dilithium_public_key()),
            b"evidence".to_vec(),
            vec![Hash::new([0xDD; 32])],
        );
        let mut signed_response = response;
        signed_response.sign(&keypair).unwrap();
        assert!(signed_response.verify_signature().unwrap());
    }
}
