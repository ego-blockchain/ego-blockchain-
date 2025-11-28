#[cfg(test)]
mod da_tests {
    use ego_core::{Address, BlockHeight, Hash, ShardId, Timestamp};
    use ego_rollup::da::{
        CellularSafeConfig, ChallengeStatus, ChallengeType, DAChunk, DACommitment, DataAvailability,
    };
    use ego_rollup::error::RollupResult;

    fn create_test_da() -> DataAvailability {
        let cellular_config = CellularSafeConfig {
            enabled: true,
            max_chunk_size: 256 * 1024,
            max_batch_size: 100,
            compression_required: true,
            monthly_limit_bytes: 50 * 1024 * 1024 * 1024,
        };
        DataAvailability::new(128, 64, 65536, true, 6, cellular_config, 8000).unwrap()
    }

    #[test]
    fn test_da_creation() {
        let da = create_test_da();
        let rs = da.get_rs_params();
        assert_eq!(rs.k, 128);
        assert_eq!(rs.m, 64);
        assert_eq!(rs.n, 192);
        assert_eq!(da.redundancy_factor(), 192.0 / 128.0);
        assert!(da.is_compression_enabled());
    }

    #[test]
    fn test_da_invalid_params() {
        let cellular_config = CellularSafeConfig::default();
        let result = DataAvailability::new(0, 64, 65536, true, 6, cellular_config, 8000);
        assert!(result.is_err());
    }

    #[test]
    fn test_da_chunk_integrity() {
        let data = vec![1u8; 100];
        let chunk = DAChunk {
            chunk_id: 0,
            commitment_hash: Hash::new([0u8; 32]),
            data: data.clone(),
            is_parity: false,
            chunk_hash: ego_core::crypto::hash_data(&data),
            timestamp: Timestamp::now(),
            provider: Some(Address::new([0u8; 20])),
            replica_count: 1,
            access_count: 0,
            shard_id: ShardId::new(0).unwrap(),
            epoch: 1,
        };
        assert!(chunk.verify_integrity());
    }

    #[test]
    fn test_da_commitment_compression_ratio() {
        let commitment = DACommitment {
            commitment_hash: Hash::new([0u8; 32]),
            data_root: Hash::new([0u8; 32]),
            chunk_count: 192,
            original_size: 1000,
            compressed_size: 700,
            rs_params: ego_rollup::da::RSParams {
                k: 128,
                m: 64,
                n: 192,
            },
            timestamp: Timestamp::now(),
            epoch: 1,
            block_height: BlockHeight(1),
            rollup_id: "test".to_string(),
            operator: Address::new([0u8; 20]),
            shard_id: ShardId::new(0).unwrap(),
            proof_batch_hash: Hash::new([0u8; 32]),
            cellular_safe_verified: true,
        };
        assert!((commitment.compression_ratio() - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn test_encode_decode_data() {
        let cellular_config = CellularSafeConfig {
            enabled: false,
            ..CellularSafeConfig::default()
        };
        let chunk_size = 16;
        let da = DataAvailability::new(2, 1, chunk_size, false, 0, cellular_config, 1000).unwrap();

        let data: Vec<u8> = (0..32).collect();
        let commitment_hash = Hash::new([1u8; 32]);

        let chunks = da
            .encode_data(
                commitment_hash,
                data.clone(),
                "test_rollup".to_string(),
                Address::new([0u8; 20]),
                1,
                BlockHeight(1),
                ShardId::new(0).unwrap(),
                Hash::new([0u8; 32]),
            )
            .unwrap();

        assert_eq!(chunks.len(), 3);
        let sampled = da.sample_chunks(commitment_hash, vec![0, 1]).unwrap();
        let decoded = da.decode_data(commitment_hash, sampled).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_da_proof_generation_and_verification() {
        let da = create_test_da();
        let data = b"test data".repeat(1000);
        let commitment_hash = Hash::new([2u8; 32]);
        let _ = da
            .encode_data(
                commitment_hash,
                data.to_vec(),
                "test_rollup".to_string(),
                Address::new([0u8; 20]),
                1,
                BlockHeight(1),
                ShardId::new(0).unwrap(),
                Hash::new([0u8; 32]),
            )
            .unwrap();

        let proof = da
            .generate_da_proof(
                commitment_hash,
                vec![0, 10, 20],
                Address::new([0u8; 20]),
                vec![],
                1,
            )
            .unwrap();

        let verified = da.verify_da_proof(&proof).unwrap();
        assert!(verified);
    }

    #[test]
    fn test_unavailability_proof_creation() {
        let da = create_test_da();
        let commitment_hash = Hash::new([3u8; 32]);
        let proof = da
            .create_unavailability_proof(
                commitment_hash,
                vec![0, 1, 2],
                Address::new([0u8; 20]),
                ego_core::Balance::new(1_000_000_000_000_000),
                vec![],
            )
            .unwrap();

        assert_eq!(proof.missing_chunks.len(), 3);
        assert!(proof.validate().is_ok());
        assert!(proof.is_critical());
    }

    #[test]
    fn test_challenge_lifecycle() {
        let da = create_test_da();
        let commitment_hash = Hash::new([4u8; 32]);
        let _ = da
            .encode_data(
                commitment_hash,
                b"sample".repeat(2000).to_vec(),
                "test_rollup".to_string(),
                Address::new([0u8; 20]),
                1,
                BlockHeight(1),
                ShardId::new(0).unwrap(),
                Hash::new([0u8; 32]),
            )
            .unwrap();

        let challenge = da
            .create_challenge(
                commitment_hash,
                Address::new([0u8; 20]),
                ChallengeType::Availability,
                10,
                100,
                ego_core::Balance::new(100_000_000_000_000_000),
            )
            .unwrap();

        assert_eq!(challenge.status, ChallengeStatus::Pending);
        assert!(da.get_challenge(&challenge.challenge_id).is_some());

        let proof = da
            .generate_da_proof(
                commitment_hash,
                challenge.sample_indices.clone(),
                Address::new([0u8; 20]),
                vec![],
                1,
            )
            .unwrap();

        let status = da.resolve_challenge(challenge.challenge_id, proof).unwrap();
        assert_eq!(status, ChallengeStatus::Resolved);
    }

    #[test]
    fn test_da_window_management() {
        let da = create_test_da();
        let window = da.create_window(0, 100, 10, ShardId::new(0).unwrap());
        assert_eq!(window.start_epoch, 0);
        assert_eq!(window.end_epoch, 100);
        assert!(!window.finalized);

        da.add_commitment_to_window(0, Hash::new([5u8; 32]));
        let active = da.get_active_window(50).unwrap();
        assert_eq!(active.commitments.len(), 1);

        da.finalize_window(0).unwrap();
        let finalized = da.get_active_window(50).unwrap();
        assert!(finalized.finalized);
    }

    #[test]
    fn test_sampling_request_and_response() {
        let da = create_test_da();
        let commitment_hash = Hash::new([6u8; 32]);
        let _ = da
            .encode_data(
                commitment_hash,
                b"sample data".repeat(500).to_vec(),
                "test_rollup".to_string(),
                Address::new([0u8; 20]),
                1,
                BlockHeight(1),
                ShardId::new(0).unwrap(),
                Hash::new([0u8; 32]),
            )
            .unwrap();

        let request = da
            .create_sampling_request(
                commitment_hash,
                5,
                [7u8; 32],
                Address::new([0u8; 20]),
                1000,
                ShardId::new(0).unwrap(),
                1,
            )
            .unwrap();

        let response = da
            .respond_to_sampling(&request, Address::new([0u8; 20]), vec![])
            .unwrap();
        assert_eq!(response.chunks.len(), 5);
        assert!(response.latency_within_sla);
        assert!(response.validate(5).is_ok());
    }

    #[test]
    fn test_pruning_old_data() {
        let da = create_test_da();
        let commitment_hash = Hash::new([8u8; 32]);
        let _ = da
            .encode_data(
                commitment_hash,
                b"test".repeat(1000).to_vec(),
                "test_rollup".to_string(),
                Address::new([0u8; 20]),
                1,
                BlockHeight(1),
                ShardId::new(0).unwrap(),
                Hash::new([0u8; 32]),
            )
            .unwrap();

        assert_eq!(da.count_active_commitments(), 1);

        da.prune_old_data(10);
        assert_eq!(da.count_active_commitments(), 0);
    }

    #[test]
    fn test_cellular_safe_validation() {
        let da = create_test_da();
        let commitment_hash = Hash::new([9u8; 32]);
        let _ = da
            .encode_data(
                commitment_hash,
                b"x".repeat(5000).to_vec(),
                "test_rollup".to_string(),
                Address::new([0u8; 20]),
                1,
                BlockHeight(1),
                ShardId::new(0).unwrap(),
                Hash::new([0u8; 32]),
            )
            .unwrap();

        let valid = da.validate_cellular_safe(commitment_hash).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_storage_stats() {
        let da = create_test_da();
        let stats = da.get_storage_stats();
        assert_eq!(stats.total_commitments, 0);
        assert_eq!(stats.total_chunks, 0);
        assert_eq!(stats.redundancy_factor, 192.0 / 128.0);
    }
}
