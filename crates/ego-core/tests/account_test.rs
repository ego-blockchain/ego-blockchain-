#[cfg(test)]
mod account_tests {
    use ego_core::account::*;
    use ego_core::{Address, AlgorithmId, Balance, Hash, PublicKey, SliceId, Timestamp};
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

    fn test_public_key(seed: u8) -> PublicKey {
        let data = vec![seed; 1312];
        PublicKey::new(AlgorithmId::MlDsa2, data)
    }

    #[test]
    fn test_new_eoa_account() {
        let address = test_address(1);
        let dilithium_pk = vec![1u8; 1312];
        let mlkem_pk = vec![2u8; 1184];

        let account = Account::new_eoa(address, dilithium_pk.clone(), mlkem_pk.clone());

        assert_eq!(account.address, address);
        assert_eq!(account.balance, Balance::ZERO);
        assert_eq!(account.nonce, 0);
        assert_eq!(account.dilithium_pk, dilithium_pk);
        assert_eq!(account.mlkem_pk, mlkem_pk);
        assert_eq!(account.storage_quota, 1024 * 1024);
        assert_eq!(account.storage_used, 0);
        assert!(matches!(account.account_type, AccountType::EOA));
        assert!(matches!(account.hot_set_mode, HotSetMode::LightClient));
        assert!(account.validator_info.is_none());
        assert!(account.storage_provider_info.is_none());
    }

    #[test]
    fn test_new_validator_account() {
        let address = test_address(2);
        let validator_pubkey = test_public_key(3);
        let commission_rate = 1000; // 10%
        let initial_stake = Balance::new(1_000_000_000);
        let dilithium_pk = vec![4u8; 1312];
        let mlkem_pk = vec![5u8; 1184];

        let result = Account::new_validator(
            address,
            validator_pubkey.clone(),
            commission_rate,
            initial_stake,
            dilithium_pk.clone(),
            mlkem_pk.clone(),
        );

        assert!(result.is_ok());
        let account = result.unwrap();

        assert_eq!(account.address, address);
        assert_eq!(account.dilithium_pk, dilithium_pk);
        assert!(account.validator_info.is_some());

        let validator_info = account.validator_info.as_ref().unwrap();
        assert_eq!(validator_info.validator_pubkey, validator_pubkey);
        assert_eq!(validator_info.commission_rate, commission_rate);
        assert!(validator_info.is_active);

        let staking_info = account.staking_info.as_ref().unwrap();
        assert_eq!(staking_info.staked_amount, initial_stake);
        assert_eq!(staking_info.delegated_stake, Balance::ZERO);

        assert!(matches!(account.hot_set_mode, HotSetMode::Validator));
        assert!(account.pruning_config.is_some());
    }

    #[test]
    fn test_validator_commission_rate_validation() {
        let address = test_address(3);
        let validator_pubkey = test_public_key(4);
        let invalid_commission_rate = 10001;
        let initial_stake = Balance::new(1_000_000_000);
        let dilithium_pk = vec![5u8; 1312];
        let mlkem_pk = vec![6u8; 1184];

        let result = Account::new_validator(
            address,
            validator_pubkey,
            invalid_commission_rate,
            initial_stake,
            dilithium_pk,
            mlkem_pk,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_new_storage_provider_account() {
        let address = test_address(4);
        let provider_id = "provider_001".to_string();
        let region = "us-west-1".to_string();
        let storage_capacity = 1_000_000_000_000;
        let dilithium_pk = vec![7u8; 1312];
        let mlkem_pk = vec![8u8; 1184];
        let peer_id = "QmTest123".to_string();

        let account = Account::new_storage_provider(
            address,
            provider_id.clone(),
            region.clone(),
            storage_capacity,
            dilithium_pk.clone(),
            mlkem_pk.clone(),
            peer_id.clone(),
        );

        assert_eq!(account.address, address);
        assert!(account.storage_provider_info.is_some());

        let provider_info = account.storage_provider_info.as_ref().unwrap();
        assert_eq!(provider_info.storage_capacity, storage_capacity);
        assert_eq!(provider_info.storage_allocated, 0);
        assert_eq!(provider_info.health_score, 100000);
        assert!(provider_info.active_sectors.is_empty());

        assert_eq!(account.peer_id, Some(peer_id));
        assert!(matches!(account.hot_set_mode, HotSetMode::StorageProvider));
        assert!(account.archival_config.is_some());
    }

    #[test]
    fn test_new_hybrid_node() {
        let address = test_address(5);
        let roles = vec![NodeRole::Validator, NodeRole::StorageProvider];
        let storage_capacity = 500_000_000_000;
        let dilithium_pk = vec![9u8; 1312];
        let mlkem_pk = vec![10u8; 1184];
        let peer_id = "QmHybrid456".to_string();

        let account = Account::new_hybrid_node(
            address,
            roles.clone(),
            storage_capacity,
            dilithium_pk,
            mlkem_pk,
            peer_id,
        );

        assert!(matches!(account.account_type, AccountType::Hybrid { .. }));
        assert!(matches!(account.hot_set_mode, HotSetMode::FullNode));
        assert!(account.pruning_config.is_some());
        assert!(account.archival_config.is_some());
        assert!(account.storage_provider_info.is_some());
    }

    #[test]
    fn test_new_device_account() {
        let address = test_address(6);
        let device_id = "device_iot_001".to_string();
        let capabilities = DeviceCapabilities {
            bandwidth_capacity: 100_000_000,
            storage_capacity: 10_000_000_000,
            supported_slices: vec![],
            coverage_area: Some("h3cell123".to_string()),
            hardware_specs: HashMap::new(),
            last_poc: None,
            post_stats: PostStats::default(),
            cellular_safe: true,
            max_bandwidth_cellular: 50_000_000,
            monthly_data_limit_gb: 100,
            cost_awareness: CostAwareness::default(),
        };
        let dilithium_pk = vec![11u8; 1312];
        let mlkem_pk = vec![12u8; 1184];
        let peer_id = "QmDevice789".to_string();

        let account = Account::new_device(
            address,
            device_id,
            capabilities.clone(),
            dilithium_pk,
            mlkem_pk,
            peer_id,
        );

        assert!(matches!(account.account_type, AccountType::Device { .. }));
        assert!(account.device_capabilities.is_some());
        assert_eq!(
            account
                .device_capabilities
                .as_ref()
                .unwrap()
                .bandwidth_capacity,
            capabilities.bandwidth_capacity
        );
    }

    #[test]
    fn test_balance_operations() {
        let address = test_address(7);
        let dilithium_pk = vec![13u8; 1312];
        let mlkem_pk = vec![14u8; 1184];
        let mut account = Account::new_eoa(address, dilithium_pk, mlkem_pk);

        let amount = Balance::new(1000);
        account.credit(amount);
        assert_eq!(account.balance, amount);

        assert!(account.can_spend(Balance::new(500)));
        assert!(account.can_spend(Balance::new(1000)));
        assert!(!account.can_spend(Balance::new(1001)));

        let debit_amount = Balance::new(300);
        let result = account.debit(debit_amount);
        assert!(result.is_ok());
        assert_eq!(account.balance, Balance::new(700));

        let large_amount = Balance::new(10000);
        let result = account.debit(large_amount);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_management() {
        let address = test_address(8);
        let dilithium_pk = vec![15u8; 1312];
        let mlkem_pk = vec![16u8; 1184];
        let mut account = Account::new_eoa(address, dilithium_pk, mlkem_pk);

        assert_eq!(account.nonce, 0);

        account.increment_nonce();
        assert_eq!(account.nonce, 1);

        account.increment_nonce();
        assert_eq!(account.nonce, 2);

        assert_eq!(account.get_shard_nonce(0), 0);
        account.increment_shard_nonce(0);
        assert_eq!(account.get_shard_nonce(0), 1);

        account.increment_shard_nonce(1);
        assert_eq!(account.get_shard_nonce(1), 1);
        assert_eq!(account.get_shard_nonce(0), 1);
    }

    #[test]
    fn test_storage_management() {
        let address = test_address(9);
        let dilithium_pk = vec![17u8; 1312];
        let mlkem_pk = vec![18u8; 1184];
        let mut account = Account::new_eoa(address, dilithium_pk, mlkem_pk);

        assert_eq!(account.storage_used, 0);
        assert_eq!(account.storage_quota, 1024 * 1024);

        assert!(account.can_store(1024));
        assert!(account.can_store(1024 * 1024));
        assert!(!account.can_store(1024 * 1024 + 1));

        let result = account.update_storage_usage(1024);
        assert!(result.is_ok());
        assert_eq!(account.storage_used, 1024);

        let result = account.update_storage_usage(account.storage_quota);
        assert!(result.is_err());
    }

    #[test]
    fn test_storage_credits() {
        let address = test_address(10);
        let dilithium_pk = vec![19u8; 1312];
        let mlkem_pk = vec![20u8; 1184];
        let mut account = Account::new_eoa(address, dilithium_pk, mlkem_pk);

        assert_eq!(account.storage_credits, 0);

        account.add_storage_credits(1000);
        assert_eq!(account.storage_credits, 1000);

        let result = account.use_storage_credits(500);
        assert!(result.is_ok());
        assert_eq!(account.storage_credits, 500);

        let result = account.use_storage_credits(1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_deploy_credits() {
        let address = test_address(11);
        let dilithium_pk = vec![21u8; 1312];
        let mlkem_pk = vec![22u8; 1184];
        let mut account = Account::new_eoa(address, dilithium_pk, mlkem_pk);

        assert_eq!(account.deploy_credits, 0);
        assert_eq!(account.free_deploys_remaining, 0);

        account.free_deploys_remaining = 5;
        assert!(account.can_deploy_free());
        let result = account.use_free_deploy();
        assert!(result.is_ok());
        assert_eq!(account.free_deploys_remaining, 4);

        account.deploy_credits = 1000;
        assert!(account.can_use_deploy_credits(500));
        let result = account.use_deploy_credits(500);
        assert!(result.is_ok());
        assert_eq!(account.deploy_credits, 500);
    }

    #[test]
    fn test_slice_authorization() {
        let address = test_address(12);
        let dilithium_pk = vec![23u8; 1312];
        let mlkem_pk = vec![24u8; 1184];
        let mut account = Account::new_eoa(address, dilithium_pk, mlkem_pk);

        let slice_id = SliceId::new("slice_001".to_string());

        assert!(!account.is_authorized_for_slice(&slice_id));

        account.authorize_slice(slice_id.clone());
        assert!(account.is_authorized_for_slice(&slice_id));

        account.authorize_slice(slice_id.clone());
        assert_eq!(account.authorized_slices.len(), 1);
    }

    #[test]
    fn test_drs_score_update() {
        let address = test_address(13);
        let dilithium_pk = vec![25u8; 1312];
        let mlkem_pk = vec![26u8; 1184];
        let mut account = Account::new_eoa(address, dilithium_pk, mlkem_pk);

        assert!(account.last_drs_score.is_none());
        assert!(account.last_drs_epoch.is_none());

        account.update_drs_score(0.85, 100);
        assert_eq!(account.last_drs_score, Some(850));
        assert_eq!(account.last_drs_epoch, Some(100));
    }

    #[test]
    fn test_pq_transition() {
        let address = test_address(14);
        let dilithium_pk = vec![27u8; 1312];
        let mlkem_pk = vec![28u8; 1184];
        let mut account = Account::new_eoa(address, dilithium_pk, mlkem_pk);

        assert!(!account.is_pq_only_mode());
        assert!(account.supports_algorithm(AlgorithmId::MlDsa2.as_u16()));
        assert!(account.supports_algorithm(AlgorithmId::Ed25519.as_u16()));

        account.enable_pq_only_mode(1000);
        assert!(account.is_pq_only_mode());
        assert!(account.supports_algorithm(AlgorithmId::MlDsa2.as_u16()));
        assert!(!account.supports_algorithm(AlgorithmId::Ed25519.as_u16()));
    }

    #[test]
    fn test_add_sector() {
        let address = test_address(15);
        let provider_id = "provider_002".to_string();
        let region = "eu-west-1".to_string();
        let storage_capacity = 1_000_000_000;
        let dilithium_pk = vec![29u8; 1312];
        let mlkem_pk = vec![30u8; 1184];
        let peer_id = "QmProvider".to_string();

        let mut account = Account::new_storage_provider(
            address,
            provider_id,
            region,
            storage_capacity,
            dilithium_pk,
            mlkem_pk,
            peer_id,
        );

        let sector = SectorInfo {
            sector_id: test_hash(1),
            size_bytes: 1000000,
            data_type: DataType::UserData,
            sealed_at: Timestamp::now(),
            expires_at: Timestamp::now(),
            replica_id: test_hash(2),
            comm_d: test_hash(3),
            comm_r: test_hash(4),
            triad: TriadInfo {
                group_id: "group_001".to_string(),
                role: TriadRole::Primary,
                primary: test_address(20),
                replica_a: test_address(21),
                replica_b: test_address(22),
                placement_epoch: 100,
            },
            params_version: 1,
            post_frequency: 3600,
            last_post_epoch: 100,
            miss_count: 0,
            integrity_verified: true,
        };

        let result = account.add_sector(sector.clone());
        assert!(result.is_ok());

        let provider_info = account.storage_provider_info.as_ref().unwrap();
        assert_eq!(provider_info.active_sectors.len(), 1);
        assert_eq!(provider_info.storage_allocated, 1000000);
        assert_eq!(provider_info.postrep_stats.sectors_sealed, 1);
    }

    #[test]
    fn test_add_sector_exceeds_capacity() {
        let address = test_address(16);
        let provider_id = "provider_003".to_string();
        let region = "ap-south-1".to_string();
        let storage_capacity = 100000;
        let dilithium_pk = vec![31u8; 1312];
        let mlkem_pk = vec![32u8; 1184];
        let peer_id = "QmSmall".to_string();

        let mut account = Account::new_storage_provider(
            address,
            provider_id,
            region,
            storage_capacity,
            dilithium_pk,
            mlkem_pk,
            peer_id,
        );

        let large_sector = SectorInfo {
            sector_id: test_hash(5),
            size_bytes: 200000,
            data_type: DataType::UserData,
            sealed_at: Timestamp::now(),
            expires_at: Timestamp::now(),
            replica_id: test_hash(6),
            comm_d: test_hash(7),
            comm_r: test_hash(8),
            triad: TriadInfo {
                group_id: "group_002".to_string(),
                role: TriadRole::Primary,
                primary: test_address(23),
                replica_a: test_address(24),
                replica_b: test_address(25),
                placement_epoch: 200,
            },
            params_version: 1,
            post_frequency: 3600,
            last_post_epoch: 200,
            miss_count: 0,
            integrity_verified: true,
        };

        let result = account.add_sector(large_sector);
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_sector() {
        let address = test_address(17);
        let provider_id = "provider_004".to_string();
        let region = "us-east-1".to_string();
        let storage_capacity = 1_000_000_000;
        let dilithium_pk = vec![33u8; 1312];
        let mlkem_pk = vec![34u8; 1184];
        let peer_id = "QmRemove".to_string();

        let mut account = Account::new_storage_provider(
            address,
            provider_id,
            region,
            storage_capacity,
            dilithium_pk,
            mlkem_pk,
            peer_id,
        );

        let sector_id = test_hash(9);
        let sector = SectorInfo {
            sector_id,
            size_bytes: 500000,
            data_type: DataType::BlockBodies,
            sealed_at: Timestamp::now(),
            expires_at: Timestamp::now(),
            replica_id: test_hash(10),
            comm_d: test_hash(11),
            comm_r: test_hash(12),
            triad: TriadInfo {
                group_id: "group_003".to_string(),
                role: TriadRole::ReplicaA,
                primary: test_address(26),
                replica_a: test_address(27),
                replica_b: test_address(28),
                placement_epoch: 300,
            },
            params_version: 1,
            post_frequency: 3600,
            last_post_epoch: 300,
            miss_count: 0,
            integrity_verified: true,
        };

        account.add_sector(sector).unwrap();
        assert_eq!(
            account
                .storage_provider_info
                .as_ref()
                .unwrap()
                .active_sectors
                .len(),
            1
        );

        let result = account.remove_sector(&sector_id);
        assert!(result.is_ok());
        assert_eq!(
            account
                .storage_provider_info
                .as_ref()
                .unwrap()
                .active_sectors
                .len(),
            0
        );
        assert_eq!(
            account
                .storage_provider_info
                .as_ref()
                .unwrap()
                .storage_allocated,
            0
        );
    }

    #[test]
    fn test_record_post_proof() {
        let address = test_address(18);
        let provider_id = "provider_005".to_string();
        let region = "ca-central-1".to_string();
        let storage_capacity = 1_000_000_000;
        let dilithium_pk = vec![35u8; 1312];
        let mlkem_pk = vec![36u8; 1184];
        let peer_id = "QmPost".to_string();

        let mut account = Account::new_storage_provider(
            address,
            provider_id,
            region,
            storage_capacity,
            dilithium_pk,
            mlkem_pk,
            peer_id,
        );

        account.record_post_proof(true, 1500, 100);
        let provider_info = account.storage_provider_info.as_ref().unwrap();
        assert_eq!(provider_info.postrep_stats.post_proofs_submitted, 1);
        assert_eq!(provider_info.postrep_stats.challenges_answered, 1);
        assert_eq!(provider_info.postrep_stats.challenges_missed, 0);
        assert_eq!(provider_info.postrep_stats.consecutive_misses, 0);

        account.record_post_proof(false, 3000, 101);
        let provider_info = account.storage_provider_info.as_ref().unwrap();
        assert_eq!(provider_info.postrep_stats.post_proofs_submitted, 2);
        assert_eq!(provider_info.postrep_stats.challenges_answered, 1);
        assert_eq!(provider_info.postrep_stats.challenges_missed, 1);
        assert_eq!(provider_info.postrep_stats.consecutive_misses, 1);
    }

    #[test]
    fn test_health_score_calculation() {
        let address = test_address(19);
        let provider_id = "provider_006".to_string();
        let region = "sa-east-1".to_string();
        let storage_capacity = 1_000_000_000;
        let dilithium_pk = vec![37u8; 1312];
        let mlkem_pk = vec![38u8; 1184];
        let peer_id = "QmHealth".to_string();

        let mut account = Account::new_storage_provider(
            address,
            provider_id,
            region,
            storage_capacity,
            dilithium_pk,
            mlkem_pk,
            peer_id,
        );

        let initial_score = account.calculate_health_score();
        assert_eq!(initial_score, 100000);

        for _ in 0..10 {
            account.record_post_proof(true, 1000, 100);
        }

        let good_score = account.calculate_health_score();
        assert!(good_score >= 90000);

        for _ in 0..5 {
            account.record_post_proof(false, 3000, 101);
        }

        let degraded_score = account.calculate_health_score();
        assert!(degraded_score < good_score);
    }

    #[test]
    fn test_mark_sector_faulty() {
        let address = test_address(20);
        let provider_id = "provider_007".to_string();
        let region = "me-south-1".to_string();
        let storage_capacity = 1_000_000_000;
        let dilithium_pk = vec![39u8; 1312];
        let mlkem_pk = vec![40u8; 1184];
        let peer_id = "QmFaulty".to_string();

        let mut account = Account::new_storage_provider(
            address,
            provider_id,
            region,
            storage_capacity,
            dilithium_pk,
            mlkem_pk,
            peer_id,
        );

        let sector_id = test_hash(13);
        let sector = SectorInfo {
            sector_id,
            size_bytes: 100000,
            data_type: DataType::ContractCode,
            sealed_at: Timestamp::now(),
            expires_at: Timestamp::now(),
            replica_id: test_hash(14),
            comm_d: test_hash(15),
            comm_r: test_hash(16),
            triad: TriadInfo {
                group_id: "group_004".to_string(),
                role: TriadRole::ReplicaB,
                primary: test_address(29),
                replica_a: test_address(30),
                replica_b: test_address(31),
                placement_epoch: 400,
            },
            params_version: 1,
            post_frequency: 3600,
            last_post_epoch: 400,
            miss_count: 0,
            integrity_verified: true,
        };

        account.add_sector(sector).unwrap();

        let result = account.mark_sector_faulty(&sector_id);
        assert!(result.is_ok());

        let provider_info = account.storage_provider_info.as_ref().unwrap();
        assert_eq!(provider_info.postrep_stats.sectors_faulty, 1);

        let faulty_sector = account.get_sector(&sector_id).unwrap();
        assert!(!faulty_sector.integrity_verified);
        assert_eq!(faulty_sector.miss_count, 1);
    }

    #[test]
    fn test_promote_replica() {
        let address = test_address(21);
        let provider_id = "provider_008".to_string();
        let region = "af-south-1".to_string();
        let storage_capacity = 1_000_000_000;
        let dilithium_pk = vec![41u8; 1312];
        let mlkem_pk = vec![42u8; 1184];
        let peer_id = "QmPromote".to_string();

        let mut account = Account::new_storage_provider(
            address,
            provider_id,
            region,
            storage_capacity,
            dilithium_pk,
            mlkem_pk,
            peer_id,
        );

        let sector_id = test_hash(17);
        let sector = SectorInfo {
            sector_id,
            size_bytes: 200000,
            data_type: DataType::StateSnapshot,
            sealed_at: Timestamp::now(),
            expires_at: Timestamp::now(),
            replica_id: test_hash(18),
            comm_d: test_hash(19),
            comm_r: test_hash(20),
            triad: TriadInfo {
                group_id: "group_005".to_string(),
                role: TriadRole::ReplicaA,
                primary: test_address(32),
                replica_a: test_address(33),
                replica_b: test_address(34),
                placement_epoch: 500,
            },
            params_version: 1,
            post_frequency: 3600,
            last_post_epoch: 500,
            miss_count: 0,
            integrity_verified: true,
        };

        account.add_sector(sector).unwrap();

        let result = account.promote_replica(&sector_id, TriadRole::Primary);
        assert!(result.is_ok());

        let promoted_sector = account.get_sector(&sector_id).unwrap();
        assert_eq!(promoted_sector.triad.role, TriadRole::Primary);

        let provider_info = account.storage_provider_info.as_ref().unwrap();
        assert_eq!(provider_info.postrep_stats.promotions, 1);
    }

    #[test]
    fn test_record_repair() {
        let address = test_address(22);
        let provider_id = "provider_009".to_string();
        let region = "ap-northeast-1".to_string();
        let storage_capacity = 1_000_000_000;
        let dilithium_pk = vec![43u8; 1312];
        let mlkem_pk = vec![44u8; 1184];
        let peer_id = "QmRepair".to_string();

        let mut account = Account::new_storage_provider(
            address,
            provider_id,
            region,
            storage_capacity,
            dilithium_pk,
            mlkem_pk,
            peer_id,
        );

        let sector_id = test_hash(21);
        let sector = SectorInfo {
            sector_id,
            size_bytes: 150000,
            data_type: DataType::DABlob,
            sealed_at: Timestamp::now(),
            expires_at: Timestamp::now(),
            replica_id: test_hash(22),
            comm_d: test_hash(23),
            comm_r: test_hash(24),
            triad: TriadInfo {
                group_id: "group_006".to_string(),
                role: TriadRole::Primary,
                primary: test_address(35),
                replica_a: test_address(36),
                replica_b: test_address(37),
                placement_epoch: 600,
            },
            params_version: 1,
            post_frequency: 3600,
            last_post_epoch: 600,
            miss_count: 3,
            integrity_verified: false,
        };

        account.add_sector(sector.clone()).unwrap();

        account.mark_sector_faulty(&sector_id).unwrap();

        let result = account.record_repair(&sector_id);
        assert!(result.is_ok());

        let repaired_sector = account.get_sector(&sector_id).unwrap();
        assert!(repaired_sector.integrity_verified);
        assert_eq!(repaired_sector.miss_count, 0);

        let provider_info = account.storage_provider_info.as_ref().unwrap();
        assert_eq!(provider_info.postrep_stats.repairs_completed, 1);
        assert_eq!(provider_info.postrep_stats.sectors_faulty, 0);
    }

    #[test]
    fn test_provider_earnings() {
        let address = test_address(23);
        let provider_id = "provider_010".to_string();
        let region = "eu-north-1".to_string();
        let storage_capacity = 1_000_000_000;
        let dilithium_pk = vec![45u8; 1312];
        let mlkem_pk = vec![46u8; 1184];
        let peer_id = "QmEarnings".to_string();

        let mut account = Account::new_storage_provider(
            address,
            provider_id,
            region,
            storage_capacity,
            dilithium_pk,
            mlkem_pk,
            peer_id,
        );

        let storage_reward = Balance::new(1000);
        let retrieval_fee = Balance::new(500);
        let post_reward = Balance::new(250);

        let result = account.add_provider_earnings(storage_reward, retrieval_fee, post_reward);
        assert!(result.is_ok());

        let provider_info = account.storage_provider_info.as_ref().unwrap();
        assert_eq!(provider_info.earnings.storage_rewards, storage_reward);
        assert_eq!(provider_info.earnings.retrieval_fees, retrieval_fee);
        assert_eq!(provider_info.earnings.post_rewards, post_reward);
        assert_eq!(provider_info.earnings.total_earned, Balance::new(1750));
        assert_eq!(provider_info.earnings.pending_payouts, Balance::new(1750));
    }

    #[test]
    fn test_process_provider_payout() {
        let address = test_address(24);
        let provider_id = "provider_011".to_string();
        let region = "us-west-2".to_string();
        let storage_capacity = 1_000_000_000;
        let dilithium_pk = vec![47u8; 1312];
        let mlkem_pk = vec![48u8; 1184];
        let peer_id = "QmPayout".to_string();

        let mut account = Account::new_storage_provider(
            address,
            provider_id,
            region,
            storage_capacity,
            dilithium_pk,
            mlkem_pk,
            peer_id,
        );

        account
            .add_provider_earnings(Balance::new(2000), Balance::new(1000), Balance::new(500))
            .unwrap();

        let initial_balance = account.balance;
        let payout_amount = Balance::new(2000);

        let result = account.process_provider_payout(payout_amount);
        assert!(result.is_ok());

        assert_eq!(
            account.balance,
            initial_balance.saturating_add(payout_amount)
        );

        let provider_info = account.storage_provider_info.as_ref().unwrap();
        assert_eq!(provider_info.earnings.pending_payouts, Balance::new(1500));
    }

    #[test]
    fn test_process_provider_payout_insufficient() {
        let address = test_address(25);
        let provider_id = "provider_012".to_string();
        let region = "ap-southeast-1".to_string();
        let storage_capacity = 1_000_000_000;
        let dilithium_pk = vec![49u8; 1312];
        let mlkem_pk = vec![50u8; 1184];
        let peer_id = "QmInsufficient".to_string();

        let mut account = Account::new_storage_provider(
            address,
            provider_id,
            region,
            storage_capacity,
            dilithium_pk,
            mlkem_pk,
            peer_id,
        );

        let result = account.process_provider_payout(Balance::new(1000));
        assert!(result.is_err());
    }

    #[test]
    fn test_lock_unlock_collateral() {
        let address = test_address(26);
        let provider_id = "provider_013".to_string();
        let region = "eu-central-1".to_string();
        let storage_capacity = 1_000_000_000;
        let dilithium_pk = vec![51u8; 1312];
        let mlkem_pk = vec![52u8; 1184];
        let peer_id = "QmCollateral".to_string();

        let mut account = Account::new_storage_provider(
            address,
            provider_id,
            region,
            storage_capacity,
            dilithium_pk,
            mlkem_pk,
            peer_id,
        );

        account.credit(Balance::new(10000));

        let lock_amount = Balance::new(5000);
        let result = account.lock_provider_collateral(lock_amount);
        assert!(result.is_ok());

        assert_eq!(account.balance, Balance::new(5000));
        let provider_info = account.storage_provider_info.as_ref().unwrap();
        assert_eq!(provider_info.collateral_locked, lock_amount);

        let unlock_amount = Balance::new(2000);
        let result = account.unlock_provider_collateral(unlock_amount);
        assert!(result.is_ok());

        assert_eq!(account.balance, Balance::new(7000));
        let provider_info = account.storage_provider_info.as_ref().unwrap();
        assert_eq!(provider_info.collateral_locked, Balance::new(3000));
    }

    #[test]
    fn test_slash_provider() {
        let address = test_address(27);
        let provider_id = "provider_014".to_string();
        let region = "sa-east-1".to_string();
        let storage_capacity = 1_000_000_000;
        let dilithium_pk = vec![53u8; 1312];
        let mlkem_pk = vec![54u8; 1184];
        let peer_id = "QmSlash".to_string();

        let mut account = Account::new_storage_provider(
            address,
            provider_id,
            region,
            storage_capacity,
            dilithium_pk,
            mlkem_pk,
            peer_id,
        );

        account.credit(Balance::new(10000));
        account
            .lock_provider_collateral(Balance::new(8000))
            .unwrap();

        let slash_amount = Balance::new(2000);
        let reason = "Multiple POST failures".to_string();
        let evidence_hash = test_hash(25);
        let slash_type = SlashingType::PostMiss;

        let result = account.slash_provider(
            slash_amount,
            reason.clone(),
            evidence_hash,
            slash_type.clone(),
        );
        assert!(result.is_ok());

        let provider_info = account.storage_provider_info.as_ref().unwrap();
        assert_eq!(provider_info.collateral_locked, Balance::new(6000));
        assert_eq!(provider_info.earnings.total_slashed, slash_amount);
        assert_eq!(provider_info.slashing_history.len(), 1);

        let slashing_event = &provider_info.slashing_history[0];
        assert_eq!(slashing_event.amount, slash_amount);
        assert_eq!(slashing_event.reason, reason);
        assert_eq!(slashing_event.evidence_hash, evidence_hash);
        assert_eq!(slashing_event.event_type, slash_type);
    }

    #[test]
    fn test_get_sectors_by_data_type() {
        let address = test_address(28);
        let provider_id = "provider_015".to_string();
        let region = "ap-south-1".to_string();
        let storage_capacity = 1_000_000_000;
        let dilithium_pk = vec![55u8; 1312];
        let mlkem_pk = vec![56u8; 1184];
        let peer_id = "QmDataType".to_string();

        let mut account = Account::new_storage_provider(
            address,
            provider_id,
            region,
            storage_capacity,
            dilithium_pk,
            mlkem_pk,
            peer_id,
        );

        let sector1 = SectorInfo {
            sector_id: test_hash(26),
            size_bytes: 100000,
            data_type: DataType::UserData,
            sealed_at: Timestamp::now(),
            expires_at: Timestamp::now(),
            replica_id: test_hash(27),
            comm_d: test_hash(28),
            comm_r: test_hash(29),
            triad: TriadInfo {
                group_id: "group_007".to_string(),
                role: TriadRole::Primary,
                primary: test_address(38),
                replica_a: test_address(39),
                replica_b: test_address(40),
                placement_epoch: 700,
            },
            params_version: 1,
            post_frequency: 3600,
            last_post_epoch: 700,
            miss_count: 0,
            integrity_verified: true,
        };

        let sector2 = SectorInfo {
            sector_id: test_hash(30),
            size_bytes: 150000,
            data_type: DataType::ContractCode,
            sealed_at: Timestamp::now(),
            expires_at: Timestamp::now(),
            replica_id: test_hash(31),
            comm_d: test_hash(32),
            comm_r: test_hash(33),
            triad: TriadInfo {
                group_id: "group_008".to_string(),
                role: TriadRole::ReplicaA,
                primary: test_address(41),
                replica_a: test_address(42),
                replica_b: test_address(43),
                placement_epoch: 800,
            },
            params_version: 1,
            post_frequency: 3600,
            last_post_epoch: 800,
            miss_count: 0,
            integrity_verified: true,
        };

        let sector3 = SectorInfo {
            sector_id: test_hash(34),
            size_bytes: 200000,
            data_type: DataType::UserData,
            sealed_at: Timestamp::now(),
            expires_at: Timestamp::now(),
            replica_id: test_hash(35),
            comm_d: test_hash(36),
            comm_r: test_hash(37),
            triad: TriadInfo {
                group_id: "group_009".to_string(),
                role: TriadRole::ReplicaB,
                primary: test_address(44),
                replica_a: test_address(45),
                replica_b: test_address(46),
                placement_epoch: 900,
            },
            params_version: 1,
            post_frequency: 3600,
            last_post_epoch: 900,
            miss_count: 0,
            integrity_verified: true,
        };

        account.add_sector(sector1).unwrap();
        account.add_sector(sector2).unwrap();
        account.add_sector(sector3).unwrap();

        let user_data_sectors = account.get_sectors_by_data_type(DataType::UserData);
        assert_eq!(user_data_sectors.len(), 2);

        let contract_sectors = account.get_sectors_by_data_type(DataType::ContractCode);
        assert_eq!(contract_sectors.len(), 1);
    }

    #[test]
    fn test_get_faulty_sectors() {
        let address = test_address(29);
        let provider_id = "provider_016".to_string();
        let region = "us-east-2".to_string();
        let storage_capacity = 1_000_000_000;
        let dilithium_pk = vec![57u8; 1312];
        let mlkem_pk = vec![58u8; 1184];
        let peer_id = "QmFaultyQuery".to_string();

        let mut account = Account::new_storage_provider(
            address,
            provider_id,
            region,
            storage_capacity,
            dilithium_pk,
            mlkem_pk,
            peer_id,
        );

        let good_sector = SectorInfo {
            sector_id: test_hash(38),
            size_bytes: 100000,
            data_type: DataType::ProofEvidence,
            sealed_at: Timestamp::now(),
            expires_at: Timestamp::now(),
            replica_id: test_hash(39),
            comm_d: test_hash(40),
            comm_r: test_hash(41),
            triad: TriadInfo {
                group_id: "group_010".to_string(),
                role: TriadRole::Primary,
                primary: test_address(47),
                replica_a: test_address(48),
                replica_b: test_address(49),
                placement_epoch: 1000,
            },
            params_version: 1,
            post_frequency: 3600,
            last_post_epoch: 1000,
            miss_count: 0,
            integrity_verified: true,
        };

        let faulty_sector = SectorInfo {
            sector_id: test_hash(42),
            size_bytes: 150000,
            data_type: DataType::RollupBatch,
            sealed_at: Timestamp::now(),
            expires_at: Timestamp::now(),
            replica_id: test_hash(43),
            comm_d: test_hash(44),
            comm_r: test_hash(45),
            triad: TriadInfo {
                group_id: "group_011".to_string(),
                role: TriadRole::ReplicaA,
                primary: test_address(50),
                replica_a: test_address(51),
                replica_b: test_address(52),
                placement_epoch: 1100,
            },
            params_version: 1,
            post_frequency: 3600,
            last_post_epoch: 1100,
            miss_count: 5,
            integrity_verified: false,
        };

        account.add_sector(good_sector).unwrap();
        account.add_sector(faulty_sector).unwrap();

        let faulty = account.get_faulty_sectors();
        assert_eq!(faulty.len(), 1);
        assert_eq!(faulty[0].sector_id, test_hash(42));
    }

    #[test]
    fn test_pruning_config() {
        let address = test_address(30);
        let validator_pubkey = test_public_key(5);
        let commission_rate = 500;
        let initial_stake = Balance::new(5_000_000_000);
        let dilithium_pk = vec![59u8; 1312];
        let mlkem_pk = vec![60u8; 1184];

        let account = Account::new_validator(
            address,
            validator_pubkey,
            commission_rate,
            initial_stake,
            dilithium_pk,
            mlkem_pk,
        )
        .unwrap();

        assert!(account.pruning_config.is_some());
        let pruning_config = account.pruning_config.as_ref().unwrap();
        assert!(pruning_config.enabled);
        assert_eq!(pruning_config.keep_epochs, 100);
        assert!(pruning_config.keep_headers_forever);

        assert!(account.should_prune_epoch(10));
        assert!(!account.should_prune_epoch(11));
        assert!(account.should_prune_epoch(1000));
        assert!(account.should_create_snapshot(1000));

        let prunable_epoch = account.get_prunable_epoch(200);
        assert_eq!(prunable_epoch, Some(100));
    }

    #[test]
    fn test_hot_set_mode() {
        let address = test_address(31);
        let dilithium_pk = vec![61u8; 1312];
        let mlkem_pk = vec![62u8; 1184];

        let eoa = Account::new_eoa(address, dilithium_pk.clone(), mlkem_pk.clone());
        assert!(matches!(eoa.hot_set_mode, HotSetMode::LightClient));

        let validator = Account::new_validator(
            test_address(32),
            test_public_key(6),
            1000,
            Balance::new(1_000_000_000),
            dilithium_pk.clone(),
            mlkem_pk.clone(),
        )
        .unwrap();
        assert!(matches!(validator.hot_set_mode, HotSetMode::Validator));

        let provider = Account::new_storage_provider(
            test_address(33),
            "provider_017".to_string(),
            "region".to_string(),
            1_000_000_000,
            dilithium_pk.clone(),
            mlkem_pk.clone(),
            "peer".to_string(),
        );
        assert!(matches!(provider.hot_set_mode, HotSetMode::StorageProvider));

        let hybrid = Account::new_hybrid_node(
            test_address(34),
            vec![NodeRole::Validator, NodeRole::StorageProvider],
            1_000_000_000,
            dilithium_pk,
            mlkem_pk,
            "peer".to_string(),
        );
        assert!(matches!(hybrid.hot_set_mode, HotSetMode::FullNode));
    }

    #[test]
    fn test_requires_hot_set_data() {
        let address = test_address(35);
        let validator_pubkey = test_public_key(7);
        let commission_rate = 800;
        let initial_stake = Balance::new(2_000_000_000);
        let dilithium_pk = vec![63u8; 1312];
        let mlkem_pk = vec![64u8; 1184];

        let validator = Account::new_validator(
            address,
            validator_pubkey,
            commission_rate,
            initial_stake,
            dilithium_pk,
            mlkem_pk,
        )
        .unwrap();

        assert!(validator.requires_hot_set_data("headers"));
        assert!(validator.requires_hot_set_data("qcs"));
        assert!(validator.requires_hot_set_data("state_db"));
        assert!(validator.requires_hot_set_data("recent_bodies"));
        assert!(validator.requires_hot_set_data("mempool"));
        assert!(!validator.requires_hot_set_data("old_bodies"));
    }

    #[test]
    fn test_can_fetch_on_demand() {
        let address = test_address(36);
        let validator_pubkey = test_public_key(8);
        let commission_rate = 600;
        let initial_stake = Balance::new(3_000_000_000);
        let dilithium_pk = vec![65u8; 1312];
        let mlkem_pk = vec![66u8; 1184];

        let validator = Account::new_validator(
            address,
            validator_pubkey,
            commission_rate,
            initial_stake,
            dilithium_pk,
            mlkem_pk,
        )
        .unwrap();

        assert!(validator.can_fetch_on_demand());
    }

    #[test]
    fn test_cellular_safe_mode() {
        let address = test_address(37);
        let device_id = "device_cellular_001".to_string();
        let capabilities = DeviceCapabilities {
            bandwidth_capacity: 50_000_000,
            storage_capacity: 5_000_000_000,
            supported_slices: vec![],
            coverage_area: Some("h3cell456".to_string()),
            hardware_specs: HashMap::new(),
            last_poc: None,
            post_stats: PostStats::default(),
            cellular_safe: true,
            max_bandwidth_cellular: 25_000_000,
            monthly_data_limit_gb: 50,
            cost_awareness: CostAwareness::default(),
        };
        let dilithium_pk = vec![67u8; 1312];
        let mlkem_pk = vec![68u8; 1184];
        let peer_id = "QmCellular".to_string();

        let account = Account::new_device(
            address,
            device_id,
            capabilities.clone(),
            dilithium_pk,
            mlkem_pk,
            peer_id,
        );

        assert!(account.is_cellular_safe());
        assert!(account.should_use_wifi_only("heavy_compute"));
        assert!(account.should_use_wifi_only("large_storage"));
        assert!(account.should_use_wifi_only("bulk_sync"));
        assert!(!account.should_use_wifi_only("normal_operation"));

        assert!(account.within_data_limits(4));
        assert!(!account.within_data_limits(10));
    }

    #[test]
    fn test_account_type_checks() {
        let address = test_address(38);
        let dilithium_pk = vec![69u8; 1312];
        let mlkem_pk = vec![70u8; 1184];

        let eoa = Account::new_eoa(address, dilithium_pk.clone(), mlkem_pk.clone());
        assert!(!eoa.is_validator());
        assert!(!eoa.is_storage_provider());
        assert!(!eoa.is_device());

        let validator = Account::new_validator(
            test_address(39),
            test_public_key(9),
            1200,
            Balance::new(4_000_000_000),
            dilithium_pk.clone(),
            mlkem_pk.clone(),
        )
        .unwrap();
        assert!(validator.is_validator());
        assert!(!validator.is_storage_provider());
        assert!(!validator.is_device());

        let provider = Account::new_storage_provider(
            test_address(40),
            "provider_018".to_string(),
            "region".to_string(),
            1_000_000_000,
            dilithium_pk.clone(),
            mlkem_pk.clone(),
            "peer".to_string(),
        );
        assert!(!provider.is_validator());
        assert!(provider.is_storage_provider());
        assert!(!provider.is_device());

        let device = Account::new_device(
            test_address(41),
            "device_002".to_string(),
            DeviceCapabilities {
                bandwidth_capacity: 100_000_000,
                storage_capacity: 10_000_000_000,
                supported_slices: vec![],
                coverage_area: None,
                hardware_specs: HashMap::new(),
                last_poc: None,
                post_stats: PostStats::default(),
                cellular_safe: false,
                max_bandwidth_cellular: 50_000_000,
                monthly_data_limit_gb: 100,
                cost_awareness: CostAwareness::default(),
            },
            dilithium_pk.clone(),
            mlkem_pk.clone(),
            "peer".to_string(),
        );
        assert!(!device.is_validator());
        assert!(!device.is_storage_provider());
        assert!(device.is_device());

        let hybrid = Account::new_hybrid_node(
            test_address(42),
            vec![NodeRole::Validator, NodeRole::StorageProvider],
            1_000_000_000,
            dilithium_pk,
            mlkem_pk,
            "peer".to_string(),
        );
        assert!(hybrid.is_validator());
        assert!(hybrid.is_storage_provider());
        assert!(!hybrid.is_device());
    }

    #[test]
    fn test_get_validator_pubkey() {
        let address = test_address(43);
        let validator_pubkey = test_public_key(10);
        let commission_rate = 900;
        let initial_stake = Balance::new(6_000_000_000);
        let dilithium_pk = vec![71u8; 1312];
        let mlkem_pk = vec![72u8; 1184];

        let validator = Account::new_validator(
            address,
            validator_pubkey.clone(),
            commission_rate,
            initial_stake,
            dilithium_pk.clone(),
            mlkem_pk.clone(),
        )
        .unwrap();

        let retrieved_pubkey = validator.get_validator_pubkey();
        assert!(retrieved_pubkey.is_some());
        assert_eq!(retrieved_pubkey.unwrap(), validator_pubkey);

        let eoa = Account::new_eoa(test_address(44), dilithium_pk, mlkem_pk);
        assert!(eoa.get_validator_pubkey().is_none());
    }

    #[test]
    fn test_account_summary() {
        let address = test_address(45);
        let dilithium_pk = vec![73u8; 1312];
        let mlkem_pk = vec![74u8; 1184];
        let mut account = Account::new_eoa(address, dilithium_pk, mlkem_pk);

        account.credit(Balance::new(5000));
        account.increment_nonce();
        account.update_storage_usage(512).unwrap();
        account.update_drs_score(0.92, 150);

        let summary = account.summary();

        assert!(summary.contains("EOA"));
        assert!(summary.contains("5000") || summary.contains("Balance"));
        assert!(summary.contains("Nonce: 1"));
        assert!(summary.contains("0.92") || summary.contains("DRS"));
        assert!(summary.contains("PQ: Hybrid") || summary.contains("Hybrid"));
    }

    #[test]
    fn test_per_shard_nonces() {
        let address = test_address(46);
        let dilithium_pk = vec![75u8; 1312];
        let mlkem_pk = vec![76u8; 1184];
        let mut account = Account::new_eoa(address, dilithium_pk, mlkem_pk);

        for shard_id in 0..5 {
            assert_eq!(account.get_shard_nonce(shard_id), 0);
            account.increment_shard_nonce(shard_id);
            assert_eq!(account.get_shard_nonce(shard_id), 1);
        }

        account.increment_shard_nonce(2);
        account.increment_shard_nonce(2);
        assert_eq!(account.get_shard_nonce(2), 3);
        assert_eq!(account.get_shard_nonce(1), 1);
    }

    #[test]
    fn test_post_rep_stats_default() {
        let stats = PostRepStats::default();
        assert_eq!(stats.porep_proofs_submitted, 0);
        assert_eq!(stats.post_proofs_submitted, 0);
        assert_eq!(stats.post_pass_rate, 100.0);
        assert_eq!(stats.avg_post_latency_ms, 0);
        assert_eq!(stats.challenges_answered, 0);
        assert_eq!(stats.challenges_missed, 0);
        assert_eq!(stats.consecutive_misses, 0);
        assert_eq!(stats.sectors_sealed, 0);
        assert_eq!(stats.sectors_faulty, 0);
        assert_eq!(stats.repairs_completed, 0);
        assert_eq!(stats.promotions, 0);
    }

    #[test]
    fn test_provider_earnings_default() {
        let earnings = ProviderEarnings::default();
        assert_eq!(earnings.storage_rewards, Balance::ZERO);
        assert_eq!(earnings.retrieval_fees, Balance::ZERO);
        assert_eq!(earnings.post_rewards, Balance::ZERO);
        assert_eq!(earnings.total_earned, Balance::ZERO);
        assert_eq!(earnings.total_slashed, Balance::ZERO);
        assert_eq!(earnings.pending_payouts, Balance::ZERO);
    }

    #[test]
    fn test_cost_awareness_default() {
        let cost = CostAwareness::default();
        assert!(cost.cellular_safe_mode);
        assert_eq!(cost.max_monthly_cost_usd, 50.0);
        assert_eq!(cost.current_month_usage_gb, 0);
        assert_eq!(cost.cellular_throttle_threshold_gb, 5);
        assert!(cost
            .wifi_only_operations
            .contains(&"heavy_compute".to_string()));
        assert!(cost
            .wifi_only_operations
            .contains(&"large_storage".to_string()));
        assert!(cost.wifi_only_operations.contains(&"bulk_sync".to_string()));
    }

    #[test]
    fn test_archival_config() {
        let address = test_address(47);
        let provider_id = "provider_019".to_string();
        let region = "global".to_string();
        let storage_capacity = 10_000_000_000_000;
        let dilithium_pk = vec![77u8; 1312];
        let mlkem_pk = vec![78u8; 1184];
        let peer_id = "QmArchival".to_string();

        let account = Account::new_storage_provider(
            address,
            provider_id,
            region,
            storage_capacity,
            dilithium_pk,
            mlkem_pk,
            peer_id,
        );

        assert!(account.archival_config.is_some());
        let archival = account.archival_config.as_ref().unwrap();
        assert!(archival.store_old_bodies);
        assert!(archival.store_contract_blobs);
        assert!(archival.store_state_snapshots);
        assert!(archival.store_da_blobs);
        assert!(archival.store_proof_evidence);
        assert!(archival.store_user_data);
        assert_eq!(archival.replication_factor, 3);
        assert_eq!(archival.erasure_coding_params, Some((64, 32)));
    }

    #[test]
    fn test_multiple_slashing_events() {
        let address = test_address(48);
        let provider_id = "provider_020".to_string();
        let region = "multi-region".to_string();
        let storage_capacity = 2_000_000_000;
        let dilithium_pk = vec![79u8; 1312];
        let mlkem_pk = vec![80u8; 1184];
        let peer_id = "QmMultiSlash".to_string();

        let mut account = Account::new_storage_provider(
            address,
            provider_id,
            region,
            storage_capacity,
            dilithium_pk,
            mlkem_pk,
            peer_id,
        );

        account.credit(Balance::new(20000));
        account
            .lock_provider_collateral(Balance::new(15000))
            .unwrap();

        let slashes = vec![
            (Balance::new(1000), "POST miss", SlashingType::PostMiss),
            (
                Balance::new(2000),
                "Invalid POST",
                SlashingType::PostInvalid,
            ),
            (Balance::new(500), "PoC fraud", SlashingType::PoCFraud),
        ];

        for (amount, reason, slash_type) in slashes {
            let result =
                account.slash_provider(amount, reason.to_string(), test_hash(50), slash_type);
            assert!(result.is_ok());
        }

        let provider_info = account.storage_provider_info.as_ref().unwrap();
        assert_eq!(provider_info.slashing_history.len(), 3);
        assert_eq!(provider_info.earnings.total_slashed, Balance::new(3500));
        assert_eq!(provider_info.collateral_locked, Balance::new(11500));
    }

    #[test]
    fn test_health_score_with_high_latency() {
        let address = test_address(49);
        let provider_id = "provider_021".to_string();
        let region = "latency-test".to_string();
        let storage_capacity = 1_000_000_000;
        let dilithium_pk = vec![81u8; 1312];
        let mlkem_pk = vec![82u8; 1184];
        let peer_id = "QmLatency".to_string();

        let mut account = Account::new_storage_provider(
            address,
            provider_id,
            region,
            storage_capacity,
            dilithium_pk,
            mlkem_pk,
            peer_id,
        );

        for _ in 0..10 {
            account.record_post_proof(true, 5000, 100);
        }

        let health_score = account.calculate_health_score();
        assert!(health_score < 100000);
    }

    #[test]
    fn test_consecutive_misses_impact() {
        let address = test_address(50);
        let provider_id = "provider_022".to_string();
        let region = "miss-test".to_string();
        let storage_capacity = 1_000_000_000;
        let dilithium_pk = vec![83u8; 1312];
        let mlkem_pk = vec![84u8; 1184];
        let peer_id = "QmMisses".to_string();

        let mut account = Account::new_storage_provider(
            address,
            provider_id,
            region,
            storage_capacity,
            dilithium_pk,
            mlkem_pk,
            peer_id,
        );

        for _ in 0..5 {
            account.record_post_proof(false, 0, 100);
        }

        let provider_info = account.storage_provider_info.as_ref().unwrap();
        assert_eq!(provider_info.postrep_stats.consecutive_misses, 5);

        let health_score = account.calculate_health_score();
        assert!(health_score < 60000);

        account.record_post_proof(true, 1000, 101);
        let provider_info = account.storage_provider_info.as_ref().unwrap();
        assert_eq!(provider_info.postrep_stats.consecutive_misses, 0);
    }

    #[test]
    fn test_pass_rate_calculation() {
        let address = test_address(51);
        let provider_id = "provider_023".to_string();
        let region = "pass-rate-test".to_string();
        let storage_capacity = 1_000_000_000;
        let dilithium_pk = vec![85u8; 1312];
        let mlkem_pk = vec![86u8; 1184];
        let peer_id = "QmPassRate".to_string();

        let mut account = Account::new_storage_provider(
            address,
            provider_id,
            region,
            storage_capacity,
            dilithium_pk,
            mlkem_pk,
            peer_id,
        );

        for _ in 0..7 {
            account.record_post_proof(true, 1000, 100);
        }
        for _ in 0..3 {
            account.record_post_proof(false, 0, 100);
        }

        let provider_info = account.storage_provider_info.as_ref().unwrap();
        assert!((provider_info.postrep_stats.post_pass_rate - 70.0).abs() < 0.1);
    }

    #[test]
    fn test_average_latency_calculation() {
        let address = test_address(52);
        let provider_id = "provider_024".to_string();
        let region = "avg-latency-test".to_string();
        let storage_capacity = 1_000_000_000;
        let dilithium_pk = vec![87u8; 1312];
        let mlkem_pk = vec![88u8; 1184];
        let peer_id = "QmAvgLatency".to_string();

        let mut account = Account::new_storage_provider(
            address,
            provider_id,
            region,
            storage_capacity,
            dilithium_pk,
            mlkem_pk,
            peer_id,
        );

        let latencies = vec![1000, 1500, 2000, 1200, 1800];
        for latency in latencies {
            account.record_post_proof(true, latency, 100);
        }

        let provider_info = account.storage_provider_info.as_ref().unwrap();
        let avg_latency = provider_info.postrep_stats.avg_post_latency_ms;

        assert!(avg_latency >= 1400 && avg_latency <= 1600);
    }

    #[test]
    fn test_validator_hot_set_config() {
        let address = test_address(53);
        let validator_pubkey = test_public_key(11);
        let commission_rate = 750;
        let initial_stake = Balance::new(7_000_000_000);
        let dilithium_pk = vec![89u8; 1312];
        let mlkem_pk = vec![90u8; 1184];

        let validator = Account::new_validator(
            address,
            validator_pubkey,
            commission_rate,
            initial_stake,
            dilithium_pk,
            mlkem_pk,
        )
        .unwrap();

        let validator_info = validator.validator_info.as_ref().unwrap();
        let hot_set_config = &validator_info.hot_set_config;

        assert!(hot_set_config.keep_headers_forever);
        assert!(hot_set_config.keep_qcs_forever);
        assert_eq!(hot_set_config.keep_recent_bodies_epochs, 100);
        assert!(hot_set_config.keep_state_db);
        assert!(hot_set_config.mempool_enabled);
        assert!(hot_set_config.fetch_on_demand_enabled);
    }

    #[test]
    fn test_staking_info() {
        let address = test_address(54);
        let validator_pubkey = test_public_key(12);
        let commission_rate = 1500;
        let initial_stake = Balance::new(10_000_000_000);
        let dilithium_pk = vec![91u8; 1312];
        let mlkem_pk = vec![92u8; 1184];

        let validator = Account::new_validator(
            address,
            validator_pubkey,
            commission_rate,
            initial_stake,
            dilithium_pk,
            mlkem_pk,
        )
        .unwrap();

        let staking_info = validator.staking_info.as_ref().unwrap();
        assert_eq!(staking_info.staked_amount, initial_stake);
        assert_eq!(staking_info.delegated_stake, Balance::ZERO);
        assert_eq!(staking_info.rewards_earned, Balance::ZERO);
        assert!(staking_info.slashing_events.is_empty());

        let performance = &staking_info.performance;
        assert_eq!(performance.blocks_validated, 0);
        assert_eq!(performance.uptime_percentage, 100000);
        assert_eq!(performance.attestation_accuracy, 100000);
        assert_eq!(performance.last_active_epoch, 0);
        assert_eq!(performance.penalties, 0);
    }

    #[test]
    fn test_triad_roles() {
        let primary_role = TriadRole::Primary;
        let replica_a_role = TriadRole::ReplicaA;
        let replica_b_role = TriadRole::ReplicaB;

        assert_eq!(primary_role, TriadRole::Primary);
        assert_ne!(primary_role, replica_a_role);
        assert_ne!(replica_a_role, replica_b_role);
    }

    #[test]
    fn test_data_types() {
        let data_types = vec![
            DataType::BlockBodies,
            DataType::ContractCode,
            DataType::StateSnapshot,
            DataType::DABlob,
            DataType::ProofEvidence,
            DataType::UserData,
            DataType::RollupBatch,
        ];

        for (i, dt1) in data_types.iter().enumerate() {
            for (j, dt2) in data_types.iter().enumerate() {
                if i == j {
                    assert_eq!(dt1, dt2);
                } else {
                    assert_ne!(dt1, dt2);
                }
            }
        }
    }

    #[test]
    fn test_slashing_types() {
        let slashing_types = vec![
            SlashingType::PostMiss,
            SlashingType::PostInvalid,
            SlashingType::PoCFraud,
            SlashingType::Equivocation,
            SlashingType::DataUnavailability,
        ];

        for (i, st1) in slashing_types.iter().enumerate() {
            for (j, st2) in slashing_types.iter().enumerate() {
                if i == j {
                    assert_eq!(st1, st2);
                } else {
                    assert_ne!(st1, st2);
                }
            }
        }
    }

    #[test]
    fn test_balance_overflow_protection() {
        let address = test_address(55);
        let dilithium_pk = vec![93u8; 1312];
        let mlkem_pk = vec![94u8; 1184];
        let mut account = Account::new_eoa(address, dilithium_pk, mlkem_pk);

        account.credit(Balance::new(u128::MAX - 1000));

        account.credit(Balance::new(2000));

        assert_eq!(account.balance, Balance::new(u128::MAX));
    }

    #[test]
    fn test_nonce_overflow_protection() {
        let address = test_address(56);
        let dilithium_pk = vec![95u8; 1312];
        let mlkem_pk = vec![96u8; 1184];
        let mut account = Account::new_eoa(address, dilithium_pk, mlkem_pk);

        account.nonce = u64::MAX - 1;

        account.increment_nonce();
        assert_eq!(account.nonce, u64::MAX);

        account.increment_nonce();
        assert_eq!(account.nonce, u64::MAX);
    }

    #[test]
    fn test_empty_provider_operations() {
        let address = test_address(57);
        let dilithium_pk = vec![97u8; 1312];
        let mlkem_pk = vec![98u8; 1184];
        let mut account = Account::new_eoa(address, dilithium_pk, mlkem_pk);

        let result = account.add_sector(SectorInfo {
            sector_id: test_hash(46),
            size_bytes: 100000,
            data_type: DataType::UserData,
            sealed_at: Timestamp::now(),
            expires_at: Timestamp::now(),
            replica_id: test_hash(47),
            comm_d: test_hash(48),
            comm_r: test_hash(49),
            triad: TriadInfo {
                group_id: "test".to_string(),
                role: TriadRole::Primary,
                primary: test_address(60),
                replica_a: test_address(61),
                replica_b: test_address(62),
                placement_epoch: 1000,
            },
            params_version: 1,
            post_frequency: 3600,
            last_post_epoch: 1000,
            miss_count: 0,
            integrity_verified: true,
        });
        assert!(result.is_err());

        let result = account.remove_sector(&test_hash(1));
        assert!(result.is_err());

        let result = account.mark_sector_faulty(&test_hash(1));
        assert!(result.is_err());

        let result =
            account.add_provider_earnings(Balance::new(100), Balance::new(50), Balance::new(25));
        assert!(result.is_err());
    }

    #[test]
    fn test_post_stats_partial_eq() {
        let stats1 = PostStats {
            proofs_submitted: 10,
            success_rate: 95000,
            last_proof: Some(Timestamp::now()),
            challenges_responded: 8,
            integrity_score: 95,
            proof_frequency_hz: 0.5,
            batch_enabled: true,
        };

        let stats2 = PostStats {
            proofs_submitted: 10,
            success_rate: 95000,
            last_proof: Some(Timestamp::now()),
            challenges_responded: 8,
            integrity_score: 95,
            proof_frequency_hz: 0.6,
            batch_enabled: false,
        };

        assert_eq!(stats1, stats2);
    }

    #[test]
    fn test_sector_with_all_roles() {
        let address = test_address(58);
        let provider_id = "provider_roles".to_string();
        let region = "test-region".to_string();
        let storage_capacity = 3_000_000_000;
        let dilithium_pk = vec![99u8; 1312];
        let mlkem_pk = vec![100u8; 1184];
        let peer_id = "QmRoles".to_string();

        let mut account = Account::new_storage_provider(
            address,
            provider_id,
            region,
            storage_capacity,
            dilithium_pk,
            mlkem_pk,
            peer_id,
        );

        let roles = vec![TriadRole::Primary, TriadRole::ReplicaA, TriadRole::ReplicaB];

        for (i, role) in roles.iter().enumerate() {
            let sector = SectorInfo {
                sector_id: test_hash(50 + i as u8),
                size_bytes: 100000,
                data_type: DataType::UserData,
                sealed_at: Timestamp::now(),
                expires_at: Timestamp::now(),
                replica_id: test_hash(60 + i as u8),
                comm_d: test_hash(70 + i as u8),
                comm_r: test_hash(80 + i as u8),
                triad: TriadInfo {
                    group_id: format!("group_{}", i),
                    role: role.clone(),
                    primary: test_address(63),
                    replica_a: test_address(64),
                    replica_b: test_address(65),
                    placement_epoch: 1000 + i as u64,
                },
                params_version: 1,
                post_frequency: 3600,
                last_post_epoch: 1000 + i as u64,
                miss_count: 0,
                integrity_verified: true,
            };
            account.add_sector(sector).unwrap();
        }

        let provider_info = account.storage_provider_info.as_ref().unwrap();
        assert_eq!(provider_info.active_sectors.len(), 3);
    }

    #[test]
    fn test_hybrid_node_with_single_role() {
        let address = test_address(59);
        let roles = vec![NodeRole::Gateway];
        let storage_capacity = 500_000_000;
        let dilithium_pk = vec![101u8; 1312];
        let mlkem_pk = vec![102u8; 1184];
        let peer_id = "QmGateway".to_string();

        let account = Account::new_hybrid_node(
            address,
            roles,
            storage_capacity,
            dilithium_pk,
            mlkem_pk,
            peer_id,
        );

        assert!(account.validator_info.is_none());
        assert!(account.storage_provider_info.is_none());
        assert!(account.pruning_config.is_none());
        assert!(account.archival_config.is_none());
    }

    #[test]
    fn test_pq_transition_info() {
        let address = test_address(60);
        let dilithium_pk = vec![103u8; 1312];
        let mlkem_pk = vec![104u8; 1184];
        let account = Account::new_eoa(address, dilithium_pk, mlkem_pk);

        let pq_info = account.pq_transition_info.as_ref().unwrap();
        assert_eq!(pq_info.transition_started_epoch, 0);
        assert!(!pq_info.pq_only_mode);
        assert!(pq_info.ed25519_disabled_epoch.is_none());
        assert!(pq_info
            .supported_algorithms
            .contains(&AlgorithmId::MlDsa2.as_u16()));
        assert!(pq_info
            .supported_algorithms
            .contains(&AlgorithmId::Ed25519.as_u16()));
        assert!(pq_info
            .supported_algorithms
            .contains(&AlgorithmId::MlKem768.as_u16()));
    }

    #[test]
    fn test_metadata_operations() {
        let address = test_address(61);
        let dilithium_pk = vec![105u8; 1312];
        let mlkem_pk = vec![106u8; 1184];
        let mut account = Account::new_eoa(address, dilithium_pk, mlkem_pk);

        account
            .metadata
            .insert("key1".to_string(), "value1".to_string());
        account
            .metadata
            .insert("key2".to_string(), "value2".to_string());

        assert_eq!(account.metadata.len(), 2);
        assert_eq!(account.metadata.get("key1"), Some(&"value1".to_string()));

        account
            .metadata
            .insert("key1".to_string(), "new_value".to_string());
        assert_eq!(account.metadata.get("key1"), Some(&"new_value".to_string()));

        account.metadata.remove("key2");
        assert_eq!(account.metadata.len(), 1);
    }

    #[test]
    fn test_complex_scenario_provider_lifecycle() {
        let address = test_address(62);
        let provider_id = "provider_lifecycle".to_string();
        let region = "lifecycle-region".to_string();
        let storage_capacity = 5_000_000_000;
        let dilithium_pk = vec![107u8; 1312];
        let mlkem_pk = vec![108u8; 1184];
        let peer_id = "QmLifecycle".to_string();

        let mut account = Account::new_storage_provider(
            address,
            provider_id,
            region,
            storage_capacity,
            dilithium_pk,
            mlkem_pk,
            peer_id,
        );

        account.credit(Balance::new(100000));
        account
            .lock_provider_collateral(Balance::new(50000))
            .unwrap();

        for i in 0..5 {
            let sector = SectorInfo {
                sector_id: test_hash(90 + i),
                size_bytes: 500_000_000,
                data_type: DataType::UserData,
                sealed_at: Timestamp::now(),
                expires_at: Timestamp::now(),
                replica_id: test_hash(100 + i),
                comm_d: test_hash(110 + i),
                comm_r: test_hash(120 + i),
                triad: TriadInfo {
                    group_id: format!("lifecycle_group_{}", i),
                    role: TriadRole::Primary,
                    primary: test_address(70 + i),
                    replica_a: test_address(80 + i),
                    replica_b: test_address(90 + i),
                    placement_epoch: 2000 + i as u64,
                },
                params_version: 1,
                post_frequency: 3600,
                last_post_epoch: 2000 + i as u64,
                miss_count: 0,
                integrity_verified: true,
            };
            account.add_sector(sector).unwrap();
        }

        for _ in 0..20 {
            account.record_post_proof(true, 1200, 2100);
        }

        let faulty_sector_id = test_hash(91);
        account.mark_sector_faulty(&faulty_sector_id).unwrap();
        account.record_repair(&faulty_sector_id).unwrap();

        account
            .add_provider_earnings(Balance::new(10000), Balance::new(5000), Balance::new(2000))
            .unwrap();

        account.process_provider_payout(Balance::new(8000)).unwrap();

        account
            .slash_provider(
                Balance::new(3000),
                "Minor violation".to_string(),
                test_hash(150),
                SlashingType::PostMiss,
            )
            .unwrap();

        let provider_info = account.storage_provider_info.as_ref().unwrap();
        assert_eq!(provider_info.active_sectors.len(), 5);
        assert_eq!(provider_info.postrep_stats.sectors_sealed, 5);
        assert_eq!(provider_info.postrep_stats.repairs_completed, 1);
        assert_eq!(provider_info.slashing_history.len(), 1);
        assert!(provider_info.health_score > 80000);

        assert_eq!(account.balance, Balance::new(58000));
    }
}
