mod proof_rollup_tests {
    use ego_core::{Address, Hash, Timestamp, crypto::KeyPair};
    use ego_rollup::proof_rollup::{
        BeaconAnnouncement, CoherenceStats, EvidenceBundle, EvidenceBundleType, MinValidityProof,
        PoCEvidence, PoRepProof, PoStEvidence, ProofRollupCommit, ProofRollupOperator, ProverStats,
        RollupConfig, ThresholdParams, WindowPoStProof, WitnessReport,
    };
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_submit_poc_evidence() {
        let config = RollupConfig::default();
        let rollup_id = [1u8; 16];
        let region_id = 1;
        let keypair = KeyPair::generate();
        let operator_addr = Address::from_public_key(&keypair.public_key());
        let operator =
            ProofRollupOperator::new(config, rollup_id, region_id, operator_addr, keypair).unwrap();

        let beacon = BeaconAnnouncement {
            device_id: [2u8; 32],
            node_addr: operator_addr,
            location_hash: Hash::random(),
            signal_strength_dbm: -80,
            frequency_mhz: 3500,
            h3_cell: 0x8a2a1072b59ffff,
            timestamp: Timestamp::now(),
            dilithium_pk: vec![],
            dilithium_sig: vec![],
            drs_score: 0.9,
            density_penalty_applied: 0.0,
        };

        let witness = WitnessReport {
            witness_id: [3u8; 32],
            witness_addr: operator_addr,
            beacon_id: [2u8; 32],
            rsrp_dbm: -90,
            rsrq_db: -10,
            sinr_db: 15,
            timing_advance: 12,
            distance_meters: 500,
            gnss_lat: 500000000,
            gnss_lon: 1000000000,
            h3_cell: 0x8a2a1072b59ffff,
            timestamp: Timestamp::now(),
            dilithium_pk: vec![],
            dilithium_sig: vec![],
            drs_score: 0.85,
        };

        let evidence = PoCEvidence {
            beacon_announcements: vec![beacon],
            witness_reports: vec![witness],
            coherence_stats: CoherenceStats {
                total_beacons: 0,
                total_witnesses: 0,
                valid_reports: 0,
                invalid_reports: 0,
                coherence_score: 0.0,
                path_loss_rmse: 0.0,
                diversity_score: 0.0,
                avg_drs_multiplier: 0.0,
                density_penalties_applied: 0,
            },
            thresholds_used: ThresholdParams {
                min_witnesses: 0,
                max_distance_meters: 0,
                min_signal_strength_dbm: 0,
                max_path_loss_rmse: 0.0,
                min_drs_score: 0.0,
            },
            density_events: vec![],
            timestamp: Timestamp::now(),
            human_verified: false,
            ai_pattern_detected: false,
        };

        let res = operator.submit_poc_evidence(evidence).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_submit_post_evidence() {
        let config = RollupConfig::default();
        let rollup_id = [1u8; 16];
        let region_id = 1;
        let keypair = KeyPair::generate();
        let operator_addr = Address::from_public_key(&keypair.public_key());
        let operator =
            ProofRollupOperator::new(config, rollup_id, region_id, operator_addr, keypair).unwrap();

        let proof = WindowPoStProof {
            partition_id: 1,
            challenge_seed: [0u8; 32],
            proof_bytes: vec![1, 2, 3, 4],
            replica_ids: vec![[4u8; 32]],
            sector_count: 10,
            challenged_sectors: vec![1, 2],
            dilithium_pk: vec![],
            dilithium_sig: vec![],
            node_addr: operator_addr,
            latency_ms: 120,
            drs_multiplier: 0.92,
        };

        let evidence = PoStEvidence {
            partition_indices: vec![1],
            window_post_proofs: vec![proof],
            partition_maps: HashMap::new(),
            prover_stats: ProverStats {
                total_sectors: 100,
                proven_sectors: 95,
                failed_proofs: 5,
                avg_proof_time_ms: 100,
                pass_ratio: 0.95,
                sla_compliance_rate: 0.98,
            },
            timestamp: Timestamp::now(),
            human_verified: false,
            ai_pattern_detected: false,
            node_drs_scores: HashMap::new(),
        };

        let res = operator.submit_post_evidence(evidence).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_submit_porep_proof() {
        let config = RollupConfig::default();
        let rollup_id = [1u8; 16];
        let region_id = 1;
        let keypair = KeyPair::generate();
        let operator_addr = Address::from_public_key(&keypair.public_key());
        let operator =
            ProofRollupOperator::new(config, rollup_id, region_id, operator_addr, keypair).unwrap();

        let proof = PoRepProof {
            sector_id: [5u8; 32],
            proof_bytes: vec![5, 6, 7, 8],
            comm_r: [0u8; 32],
            comm_d: [0u8; 32],
            replica_id: [6u8; 32],
            porep_params_v: 1,
            dilithium_pk: vec![],
            dilithium_sig: vec![],
            node_addr: operator_addr,
            seal_time_ms: 5000,
            drs_score: 0.88,
        };

        let res = operator.submit_porep_proof(proof).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_aggregate_and_commit_empty() {
        let config = RollupConfig::default();
        let rollup_id = [1u8; 16];
        let region_id = 1;
        let keypair = KeyPair::generate();
        let operator_addr = Address::from_public_key(&keypair.public_key());
        let operator =
            ProofRollupOperator::new(config, rollup_id, region_id, operator_addr, keypair).unwrap();

        let res = operator.aggregate_and_commit(false).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_evidence_bundle_count_proofs() {
        let mut bundle = EvidenceBundle {
            bundle_id: Hash::random(),
            bundle_type: EvidenceBundleType::Combined,
            poc_evidence: vec![],
            post_evidence: vec![],
            porep_proofs: vec![],
            compressed_data: vec![],
            original_size: 0,
            compression_ratio: 1.0,
            cid: String::new(),
            created_at: Timestamp::now(),
            human_verified_count: 0,
            ai_flagged_count: 0,
            drs_quality_weighted: 1.0,
            deploy_credits_consumed: 0,
            cellular_optimized: false,
        };

        assert_eq!(bundle.count_proofs(), 0);

        let beacon = BeaconAnnouncement {
            device_id: [2u8; 32],
            node_addr: Address::random(),
            location_hash: Hash::random(),
            signal_strength_dbm: -80,
            frequency_mhz: 3500,
            h3_cell: 0x8a2a1072b59ffff,
            timestamp: Timestamp::now(),
            dilithium_pk: vec![],
            dilithium_sig: vec![],
            drs_score: 0.9,
            density_penalty_applied: 0.0,
        };

        let witness = WitnessReport {
            witness_id: [3u8; 32],
            witness_addr: Address::random(),
            beacon_id: [2u8; 32],
            rsrp_dbm: -90,
            rsrq_db: -10,
            sinr_db: 15,
            timing_advance: 12,
            distance_meters: 500,
            gnss_lat: 500000000,
            gnss_lon: 1000000000,
            h3_cell: 0x8a2a1072b59ffff,
            timestamp: Timestamp::now(),
            dilithium_pk: vec![],
            dilithium_sig: vec![],
            drs_score: 0.85,
        };

        bundle.poc_evidence.push(PoCEvidence {
            beacon_announcements: vec![beacon],
            witness_reports: vec![witness],
            coherence_stats: CoherenceStats {
                total_beacons: 1,
                total_witnesses: 1,
                valid_reports: 1,
                invalid_reports: 0,
                coherence_score: 0.95,
                path_loss_rmse: 2.5,
                diversity_score: 0.9,
                avg_drs_multiplier: 0.875,
                density_penalties_applied: 0,
            },
            thresholds_used: ThresholdParams {
                min_witnesses: 1,
                max_distance_meters: 1000,
                min_signal_strength_dbm: -100,
                max_path_loss_rmse: 5.0,
                min_drs_score: 0.3,
            },
            density_events: vec![],
            timestamp: Timestamp::now(),
            human_verified: false,
            ai_pattern_detected: false,
        });

        assert_eq!(bundle.count_proofs(), 2);
    }

    #[tokio::test]
    async fn test_commitment_integrity_score() {
        let commitment = ProofRollupCommit {
            rollup_id: [0u8; 16],
            region_id: 1,
            epoch: 100,
            window_id: 1,
            proofs_root: Hash::random(),
            da_root: Hash::random(),
            count_proofs: 10,
            blob_bytes: 1024,
            min_validity_proof: MinValidityProof::InclusionOnly,
            operator_addr: Address::random(),
            operator_sig: ego_core::DualSignature::new(None, None),
            chain_id: 1,
            network_id: 1,
            created_at: Timestamp::now(),
            commitment_hash: Hash::random(),
            human_verified_count: 2,
            ai_flagged_count: 1,
            drs_weighted_quality: 0.85,
            cellular_friendly: true,
        };

        let score = commitment.integrity_score();
        assert!(score > 0.8 && score < 1.0);
    }
}
