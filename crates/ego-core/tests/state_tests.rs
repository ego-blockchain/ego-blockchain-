#[cfg(test)]
mod state_tests {
    use ego_core::state::*;
    use ego_core::transaction::CrossShardReceipt;
    use ego_core::transaction::TransactionPublicKeys;
    use ego_core::Transaction;
    use ego_core::TransactionPayload;
    use ego_core::{
        Account, AccountType, Address, AlgorithmId, Balance, BlockHeight, Hash, PublicKey, ShardId,
        Timestamp,
    };

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

    fn create_test_storage_entry(seed: u8, owner: Address) -> StorageEntry {
        StorageEntry {
            chunk_id: test_hash(seed),
            data_hash: test_hash(seed + 1),
            size: 1000000,
            data_type: StorageDataType::UserData {
                app_id: format!("app_{}", seed),
            },
            created_at: Timestamp::now(),
            expires_at: BlockHeight::new(10000),
            last_audit_epoch: 0,
            triad: TriadInfo {
                group_id: format!("group_{}", seed),
                primary: TriadMember {
                    node_id: test_address(seed),
                    sector_id: test_hash(seed + 10),
                    replica_id: test_hash(seed + 11),
                    h3_cell: format!("h3cell_{}", seed),
                    region: "us-west-1".to_string(),
                    shard_id: 0,
                    role: TriadRole::Primary,
                    health_score: 100000,
                    consecutive_misses: 0,
                },
                replica_a: TriadMember {
                    node_id: test_address(seed + 1),
                    sector_id: test_hash(seed + 12),
                    replica_id: test_hash(seed + 13),
                    h3_cell: format!("h3cell_{}", seed + 1),
                    region: "us-east-1".to_string(),
                    shard_id: 0,
                    role: TriadRole::ReplicaA,
                    health_score: 100000,
                    consecutive_misses: 0,
                },
                replica_b: TriadMember {
                    node_id: test_address(seed + 2),
                    sector_id: test_hash(seed + 14),
                    replica_id: test_hash(seed + 15),
                    h3_cell: format!("h3cell_{}", seed + 2),
                    region: "eu-west-1".to_string(),
                    shard_id: 0,
                    role: TriadRole::ReplicaB,
                    health_score: 100000,
                    consecutive_misses: 0,
                },
                placement_epoch: 100,
                diversity_score: 0.85,
                last_health_check: 100,
            },
            porep_commitment: test_hash(seed + 20),
            porep_params_version: 1,
            post_schedule: PostSchedule {
                windows_per_day: 48,
                challenges_per_window: 24,
                sla_ms: 2000,
                next_window: 101,
                last_window: 100,
            },
            post_stats: PostStats {
                total_challenges: 0,
                passed_challenges: 0,
                failed_challenges: 0,
                avg_latency_ms: 0,
                pass_rate: 100.0,
                last_proof_epoch: 0,
            },
            erasure_coding: Some(ego_core::state::ErasureCodingParams {
                k: 64,
                m: 32,
                codec: ego_core::state::ErasureCodec::ReedSolomon,
                chunk_size: 16384,
            }),
            encryption_envelope: None,
            owner,
            authorized_readers: Vec::new(),
            storage_credits_locked: 1000,
            total_paid: Balance::new(1000),
            slice_id: Some("test_slice".to_string()),
            integrity_verified: true,
            last_verified_epoch: 100,
            verification_failures: 0,
        }
    }

    fn create_test_validator_info(address: Address, pubkey: PublicKey) -> ValidatorInfo {
        ValidatorInfo {
            address,
            public_key: pubkey,
            total_stake: Balance::new(1_000_000_000_000),
            own_stake: Balance::new(500_000_000_000),
            delegated_stake: Balance::new(500_000_000_000),
            commission_rate: 1000,
            status: ValidatorStatus::Active,
            joined_epoch: 0,
            last_active_epoch: 100,
            performance: ValidatorPerformance {
                blocks_proposed: 100,
                blocks_missed: 5,
                attestations_made: 200,
                attestations_missed: 10,
                equivocations: 0,
                uptime_score: 95.0,
                attestation_accuracy: 95.0,
            },
            drs_score: 0.95,
            drs_multiplier: 1.1,
            last_drs_update: 100,
            puc_coefficient: 1.05,
            peer_degree: 50,
            relay_bytes: 1000000,
            iot_sessions: 100,
            shard_demand_score: 80,
            jail_info: None,
            slashing_history: Vec::new(),
            hot_set_config: ValidatorHotSetConfig {
                keep_headers_forever: true,
                keep_qcs_forever: true,
                keep_recent_bodies_epochs: 100,
                keep_state_db: true,
                mempool_enabled: true,
                fetch_on_demand_enabled: true,
            },
        }
    }

    fn create_test_slice_config(slice_id: String, owner: Address) -> SliceConfig {
        SliceConfig {
            slice_id,
            slice_type: SliceType::EMbb,
            owner,
            authorized_devices: Vec::new(),
            authorized_contracts: Vec::new(),
            bandwidth_allocation: 100_000_000,
            latency_target_ms: 50,
            reliability_target: 99,
            priority: 5,
            max_devices: 1000,
            storage_quota: 1_000_000_000,
            compute_quota: 1_000_000,
            status: SliceStatus::Active,
            current_devices: 0,
            current_storage_used: 0,
            current_bandwidth_used: 0,
            created_at: Timestamp::now(),
            updated_at: Timestamp::now(),
            expires_at: None,
            billing_account: owner,
            credits_remaining: Balance::new(1_000_000),
        }
    }

    #[test]
    fn test_state_manager_creation() {
        let state = StateManager::new(1, 1);
        assert_eq!(state.get_chain_id(), 1);
        assert_eq!(state.get_network_id(), 1);
        assert_eq!(state.get_block_height(), BlockHeight::GENESIS);
        assert_eq!(state.get_state_root(), Hash::ZERO);
    }

    #[test]
    fn test_state_manager_with_pruning_config() {
        let config = PruningConfig {
            enabled: true,
            keep_epochs: 50,
            prune_interval_epochs: 5,
            keep_headers_forever: true,
            keep_state_snapshots: true,
            snapshot_interval_epochs: 500,
            prune_old_bodies: true,
            prune_old_receipts: true,
            prune_old_events: true,
            prune_expired_storage: true,
        };

        let _state = StateManager::new(1, 1).with_pruning_config(config.clone());
    }

    #[test]
    fn test_account_operations() {
        let state = StateManager::new(1, 1);
        let address = test_address(1);

        assert!(!state.account_exists(&address));

        let result = state.create_account(address, AccountType::EOA);
        assert!(result.is_ok());
        assert!(state.account_exists(&address));

        let account = state.get_account(&address);
        assert!(account.is_some());
        let account = account.unwrap();
        assert_eq!(account.address, address);
        assert_eq!(account.balance, Balance::ZERO);
    }

    #[test]
    fn test_create_duplicate_account() {
        let state = StateManager::new(1, 1);
        let address = test_address(2);

        state.create_account(address, AccountType::EOA).unwrap();
        let result = state.create_account(address, AccountType::EOA);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_and_get_account() {
        let state = StateManager::new(1, 1);
        let address = test_address(3);
        let mut account = Account::new_eoa(address, vec![1u8; 1312], vec![2u8; 1184]);
        account.credit(Balance::new(5000));

        state.set_account(account.clone());
        let retrieved = state.get_account(&address).unwrap();
        assert_eq!(retrieved.balance, Balance::new(5000));
    }

    #[test]
    fn test_storage_entry_registration() {
        let state = StateManager::new(1, 1);
        let owner = test_address(4);

        state
            .create_account(
                test_address(1),
                AccountType::StorageProvider {
                    provider_id: "provider_1".to_string(),
                    region: "us-west-1".to_string(),
                },
            )
            .unwrap();
        state
            .create_account(
                test_address(2),
                AccountType::StorageProvider {
                    provider_id: "provider_2".to_string(),
                    region: "us-east-1".to_string(),
                },
            )
            .unwrap();
        state
            .create_account(
                test_address(3),
                AccountType::StorageProvider {
                    provider_id: "provider_3".to_string(),
                    region: "eu-west-1".to_string(),
                },
            )
            .unwrap();

        let entry = create_test_storage_entry(1, owner);
        let result = state.register_storage_entry(entry.clone());
        assert!(result.is_ok());

        let retrieved = state.get_storage_entry(&entry.chunk_id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().chunk_id, entry.chunk_id);
    }

    #[test]
    fn test_storage_entry_duplicate() {
        let state = StateManager::new(1, 1);
        let owner = test_address(5);

        for i in 0..3 {
            let node_addr = test_address(2 + i);
            state
                .create_account(
                    node_addr,
                    AccountType::StorageProvider {
                        provider_id: format!("provider_{}", i),
                        region: "us-west-1".to_string(),
                    },
                )
                .unwrap();
        }

        let entry = create_test_storage_entry(2, owner);
        state.register_storage_entry(entry.clone()).unwrap();
        let result = state.register_storage_entry(entry);
        assert!(result.is_err());
    }

    #[test]
    fn test_storage_entry_low_diversity() {
        let state = StateManager::new(1, 1);
        let owner = test_address(6);

        for i in 0..3 {
            let node_addr = test_address(30 + i);
            state
                .create_account(
                    node_addr,
                    AccountType::StorageProvider {
                        provider_id: format!("provider_{}", i),
                        region: "us-west-1".to_string(),
                    },
                )
                .unwrap();
        }

        let mut entry = create_test_storage_entry(3, owner);
        entry.triad.diversity_score = 0.3;
        let result = state.register_storage_entry(entry);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_post_result_success() {
        let state = StateManager::new(1, 1);
        let owner = test_address(7);
        let node_id = test_address(40);

        state
            .create_account(
                node_id,
                AccountType::StorageProvider {
                    provider_id: "provider_001".to_string(),
                    region: "us-west-1".to_string(),
                },
            )
            .unwrap();

        for i in 0..3 {
            let node_addr = test_address(4 + i);
            state
                .create_account(
                    node_addr,
                    AccountType::StorageProvider {
                        provider_id: format!("provider_{}", i),
                        region: "us-west-1".to_string(),
                    },
                )
                .unwrap();
        }

        let mut entry = create_test_storage_entry(4, owner);
        entry.triad.primary.node_id = node_id;
        let chunk_id = entry.chunk_id;
        state.register_storage_entry(entry).unwrap();

        let result = state.update_post_result(&chunk_id, &node_id, true, 1500, 200);
        assert!(result.is_ok());

        let updated_entry = state.get_storage_entry(&chunk_id).unwrap();
        assert_eq!(updated_entry.post_stats.total_challenges, 1);
        assert_eq!(updated_entry.post_stats.passed_challenges, 1);
        assert!(updated_entry.integrity_verified);
    }

    #[test]
    fn test_update_post_result_failure() {
        let state = StateManager::new(1, 1);
        let owner = test_address(8);
        let node_id = test_address(50);

        state
            .create_account(
                node_id,
                AccountType::StorageProvider {
                    provider_id: "provider_002".to_string(),
                    region: "us-west-1".to_string(),
                },
            )
            .unwrap();

        for i in 0..3 {
            let node_addr = test_address(5 + i);
            state
                .create_account(
                    node_addr,
                    AccountType::StorageProvider {
                        provider_id: format!("provider_{}", i),
                        region: "us-west-1".to_string(),
                    },
                )
                .unwrap();
        }

        let mut entry = create_test_storage_entry(5, owner);
        entry.triad.primary.node_id = node_id;
        let chunk_id = entry.chunk_id;
        state.register_storage_entry(entry).unwrap();

        let result = state.update_post_result(&chunk_id, &node_id, false, 3000, 200);
        assert!(result.is_ok());

        let updated_entry = state.get_storage_entry(&chunk_id).unwrap();
        assert_eq!(updated_entry.post_stats.total_challenges, 1);
        assert_eq!(updated_entry.post_stats.failed_challenges, 1);
        assert_eq!(updated_entry.verification_failures, 1);
    }

    #[test]
    fn test_get_chunks_by_data_type() {
        let state = StateManager::new(1, 1);
        let owner = test_address(9);

        for seed in 6..=8 {
            for offset in 0..3 {
                let node_addr = test_address(seed + offset);
                if !state.account_exists(&node_addr) {
                    state
                        .create_account(
                            node_addr,
                            AccountType::StorageProvider {
                                provider_id: format!("provider_{}_{}", seed, offset),
                                region: "us-west-1".to_string(),
                            },
                        )
                        .unwrap();
                }
            }
        }

        let mut entry1 = create_test_storage_entry(6, owner);
        entry1.data_type = StorageDataType::UserData {
            app_id: "app1".to_string(),
        };
        state.register_storage_entry(entry1).unwrap();

        let mut entry2 = create_test_storage_entry(7, owner);
        entry2.data_type = StorageDataType::ContractCode {
            code_hash: test_hash(100),
        };
        state.register_storage_entry(entry2).unwrap();

        let mut entry3 = create_test_storage_entry(8, owner);
        entry3.data_type = StorageDataType::UserData {
            app_id: "app2".to_string(),
        };
        state.register_storage_entry(entry3).unwrap();

        let user_data_chunks = state.get_chunks_by_data_type(StorageDataType::UserData {
            app_id: "app1".to_string(),
        });
        assert_eq!(user_data_chunks.len(), 1);
    }

    #[test]
    fn test_prune_expired_storage() {
        let state = StateManager::new(1, 1);
        let owner = test_address(10);

        for seed in 9..=10 {
            for offset in 0..3 {
                let node_addr = test_address(seed + offset);
                if !state.account_exists(&node_addr) {
                    state
                        .create_account(
                            node_addr,
                            AccountType::StorageProvider {
                                provider_id: format!("provider_{}_{}", seed, offset),
                                region: "us-west-1".to_string(),
                            },
                        )
                        .unwrap();
                }
            }
        }

        let mut entry1 = create_test_storage_entry(9, owner);
        entry1.expires_at = BlockHeight::new(100);
        state.register_storage_entry(entry1).unwrap();

        let mut entry2 = create_test_storage_entry(10, owner);
        entry2.expires_at = BlockHeight::new(200);
        state.register_storage_entry(entry2).unwrap();

        let pruned = state.prune_expired_storage(BlockHeight::new(150)).unwrap();
        assert_eq!(pruned.len(), 1);
    }

    #[test]
    fn test_register_validator() {
        let state = StateManager::new(1, 1);
        let address = test_address(11);
        let pubkey = test_public_key(1);

        let validator_info = create_test_validator_info(address, pubkey);
        let result = state.register_validator(validator_info.clone());
        assert!(result.is_ok());

        let retrieved = state.get_validator(&address);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().address, address);
    }

    #[test]
    fn test_register_validator_insufficient_stake() {
        let state = StateManager::new(1, 1);
        let address = test_address(12);
        let pubkey = test_public_key(2);

        let mut validator_info = create_test_validator_info(address, pubkey);
        validator_info.total_stake = Balance::new(1000);
        let result = state.register_validator(validator_info);
        assert!(result.is_err());
    }

    #[test]
    fn test_register_validator_high_commission() {
        let state = StateManager::new(1, 1);
        let address = test_address(13);
        let pubkey = test_public_key(3);

        let mut validator_info = create_test_validator_info(address, pubkey);
        validator_info.commission_rate = 10001;
        let result = state.register_validator(validator_info);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_validator_metrics() {
        let state = StateManager::new(1, 1);
        let address = test_address(14);
        let pubkey = test_public_key(4);

        let validator_info = create_test_validator_info(address, pubkey);
        state.register_validator(validator_info).unwrap();

        let result = state.update_validator_metrics(&address, 95, 100, 5000000, 200, 85, 1.1);
        assert!(result.is_ok());

        let updated = state.get_validator(&address).unwrap();
        assert_eq!(updated.performance.uptime_score, 95.0);
        assert_eq!(updated.peer_degree, 100);
        assert_eq!(updated.relay_bytes, 5000000);
        assert_eq!(updated.iot_sessions, 200);
        assert_eq!(updated.shard_demand_score, 85);
    }

    #[test]
    fn test_update_validator_drs() {
        let state = StateManager::new(1, 1);
        let address = test_address(15);
        let pubkey = test_public_key(5);

        let validator_info = create_test_validator_info(address, pubkey);
        state.register_validator(validator_info).unwrap();

        let result = state.update_validator_drs(&address, 0.92, 1.15, 500);
        assert!(result.is_ok());

        let updated = state.get_validator(&address).unwrap();
        assert_eq!(updated.drs_score, 0.92);
        assert_eq!(updated.drs_multiplier, 1.15);
        assert_eq!(updated.last_drs_update, 500);
    }

    #[test]
    fn test_jail_validator() {
        let state = StateManager::new(1, 1);
        let address = test_address(16);
        let pubkey = test_public_key(6);

        let validator_info = create_test_validator_info(address, pubkey);
        state.register_validator(validator_info).unwrap();

        let slash_amount = Balance::new(100_000_000_000);
        let result = state.jail_validator(
            &address,
            JailReason::ExcessiveMisses { consecutive: 10 },
            100,
            slash_amount,
        );
        assert!(result.is_ok());

        let updated = state.get_validator(&address).unwrap();
        assert_eq!(updated.status, ValidatorStatus::Jailed);
        assert!(updated.jail_info.is_some());
        assert_eq!(
            updated.jail_info.as_ref().unwrap().slashed_amount,
            slash_amount
        );
    }

    #[test]
    fn test_get_active_validators() {
        let state = StateManager::new(1, 1);

        for i in 0..5 {
            let address = test_address(20 + i);
            let pubkey = test_public_key(10 + i);
            let validator_info = create_test_validator_info(address, pubkey);
            state.register_validator(validator_info).unwrap();
        }

        let address_jail = test_address(25);
        let pubkey_jail = test_public_key(15);
        let validator_info = create_test_validator_info(address_jail, pubkey_jail);
        state.register_validator(validator_info).unwrap();
        state
            .jail_validator(&address_jail, JailReason::Slashing, 100, Balance::new(1000))
            .unwrap();

        let active = state.get_active_validators();
        assert_eq!(active.len(), 5);
    }

    #[test]
    fn test_get_total_staked() {
        let state = StateManager::new(1, 1);

        for i in 0..3 {
            let address = test_address(30 + i);
            let pubkey = test_public_key(20 + i);
            let validator_info = create_test_validator_info(address, pubkey);
            state.register_validator(validator_info).unwrap();
        }

        let total = state.get_total_staked();
        assert!(total.as_u128() > 0);
    }

    #[test]
    fn test_create_slice() {
        let state = StateManager::new(1, 1);
        let owner = test_address(17);

        state.create_account(owner, AccountType::EOA).unwrap();

        let slice_config = create_test_slice_config("slice_001".to_string(), owner);
        let result = state.create_slice(slice_config.clone());
        assert!(result.is_ok());

        let retrieved = state.get_slice("slice_001");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().owner, owner);
    }

    #[test]
    fn test_create_duplicate_slice() {
        let state = StateManager::new(1, 1);
        let owner = test_address(18);

        state.create_account(owner, AccountType::EOA).unwrap();

        let slice_config = create_test_slice_config("slice_002".to_string(), owner);
        state.create_slice(slice_config.clone()).unwrap();
        let result = state.create_slice(slice_config);
        assert!(result.is_err());
    }

    #[test]
    fn test_authorize_device_for_slice() {
        let state = StateManager::new(1, 1);
        let owner = test_address(19);
        let device = test_address(80);

        state.create_account(owner, AccountType::EOA).unwrap();
        state
            .create_account(
                device,
                AccountType::Device {
                    device_id: "device_001".to_string(),
                    geohash: Some("h3cell".to_string()),
                },
            )
            .unwrap();

        let slice_config = create_test_slice_config("slice_003".to_string(), owner);
        state.create_slice(slice_config).unwrap();

        let result = state.authorize_device_for_slice("slice_003", device);
        assert!(result.is_ok());

        let updated_slice = state.get_slice("slice_003").unwrap();
        assert!(updated_slice.authorized_devices.contains(&device));
        assert_eq!(updated_slice.current_devices, 1);
    }

    #[test]
    fn test_authorize_device_exceeds_limit() {
        let state = StateManager::new(1, 1);
        let owner = test_address(21);

        state.create_account(owner, AccountType::EOA).unwrap();

        let mut slice_config = create_test_slice_config("slice_004".to_string(), owner);
        slice_config.max_devices = 1;
        state.create_slice(slice_config).unwrap();

        let device1 = test_address(81);
        let device2 = test_address(82);
        state.create_account(device1, AccountType::EOA).unwrap();
        state.create_account(device2, AccountType::EOA).unwrap();

        state
            .authorize_device_for_slice("slice_004", device1)
            .unwrap();
        let result = state.authorize_device_for_slice("slice_004", device2);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_slice_usage() {
        let state = StateManager::new(1, 1);
        let owner = test_address(22);

        state.create_account(owner, AccountType::EOA).unwrap();

        let slice_config = create_test_slice_config("slice_005".to_string(), owner);
        state.create_slice(slice_config).unwrap();

        let result = state.update_slice_usage("slice_005", 100000, 50000);
        assert!(result.is_ok());

        let updated = state.get_slice("slice_005").unwrap();
        assert_eq!(updated.current_storage_used, 100000);
        assert_eq!(updated.current_bandwidth_used, 50000);
    }

    #[test]
    fn test_update_slice_usage_exceeds_quota() {
        let state = StateManager::new(1, 1);
        let owner = test_address(23);

        state.create_account(owner, AccountType::EOA).unwrap();

        let mut slice_config = create_test_slice_config("slice_006".to_string(), owner);
        slice_config.storage_quota = 1000;
        state.create_slice(slice_config).unwrap();

        let result = state.update_slice_usage("slice_006", 2000, 0);
        assert!(result.is_ok());

        let updated = state.get_slice("slice_006").unwrap();
        assert_eq!(updated.status, SliceStatus::QuotaExceeded);
    }

    #[test]
    fn test_cross_shard_state_init() {
        let state = StateManager::new(1, 1);
        let shard_id = ShardId::new(5).unwrap();

        let result = state.init_cross_shard_state(shard_id);
        assert!(result.is_ok());

        let cross_shard = state.get_cross_shard_state(&shard_id);
        assert!(cross_shard.is_some());
        assert_eq!(cross_shard.unwrap().shard_id, shard_id);
    }

    #[test]
    fn test_add_cross_shard_receipt() {
        let state = StateManager::new(1, 1);
        let src_shard = ShardId::new(0).unwrap();
        let dst_shard = ShardId::new(1).unwrap();

        state.init_cross_shard_state(src_shard).unwrap();
        state.init_cross_shard_state(dst_shard).unwrap();

        let receipt = ego_core::transaction::CrossShardReceipt {
            src_shard,
            dst_shard,
            src_block_hash: test_hash(1),
            tx_id: test_hash(2),
            payload: vec![1, 2, 3, 4],
            nonce: 1,
            deadline_epoch: 1000,
            merkle_proof: Vec::new(),
        };

        let result = state.add_cross_shard_receipt(receipt);
        assert!(result.is_ok());
    }

    #[test]
    fn test_add_cross_shard_receipt_duplicate_nonce() {
        let state = StateManager::new(1, 1);
        let src_shard = ShardId::new(0).unwrap();
        let dst_shard = ShardId::new(1).unwrap();

        state.init_cross_shard_state(src_shard).unwrap();
        state.init_cross_shard_state(dst_shard).unwrap();

        let receipt = ego_core::transaction::CrossShardReceipt {
            src_shard,
            dst_shard,
            src_block_hash: test_hash(1),
            tx_id: test_hash(2),
            payload: vec![1, 2, 3, 4],
            nonce: 1,
            deadline_epoch: 1000,
            merkle_proof: Vec::new(),
        };

        state.add_cross_shard_receipt(receipt.clone()).unwrap();

        state.process_cross_shard_receipt(&receipt.tx_id).unwrap();

        let result = state.add_cross_shard_receipt(receipt);
        assert!(result.is_err());
    }

    #[test]
    fn test_process_cross_shard_receipt() {
        let state = StateManager::new(1, 1);
        let src_shard = ShardId::new(0).unwrap();
        let dst_shard = ShardId::new(1).unwrap();

        state.init_cross_shard_state(src_shard).unwrap();
        state.init_cross_shard_state(dst_shard).unwrap();

        let receipt = ego_core::transaction::CrossShardReceipt {
            src_shard,
            dst_shard,
            src_block_hash: test_hash(1),
            tx_id: test_hash(3),
            payload: vec![1, 2, 3, 4],
            nonce: 2,
            deadline_epoch: 1000,
            merkle_proof: Vec::new(),
        };

        state.add_cross_shard_receipt(receipt.clone()).unwrap();

        let result = state.process_cross_shard_receipt(&receipt.tx_id);
        assert!(result.is_ok());
        assert!(result.unwrap().success);
    }

    #[test]
    fn test_prune_expired_receipts() {
        let state = StateManager::new(1, 1);
        let src_shard = ShardId::new(0).unwrap();
        let dst_shard = ShardId::new(1).unwrap();

        state.init_cross_shard_state(src_shard).unwrap();
        state.init_cross_shard_state(dst_shard).unwrap();

        let receipt1 = ego_core::transaction::CrossShardReceipt {
            src_shard,
            dst_shard,
            src_block_hash: test_hash(1),
            tx_id: test_hash(4),
            payload: vec![1, 2, 3],
            nonce: 3,
            deadline_epoch: 100,
            merkle_proof: Vec::new(),
        };

        let receipt2 = ego_core::transaction::CrossShardReceipt {
            src_shard,
            dst_shard,
            src_block_hash: test_hash(2),
            tx_id: test_hash(5),
            payload: vec![4, 5, 6],
            nonce: 4,
            deadline_epoch: 200,
            merkle_proof: Vec::new(),
        };

        state.add_cross_shard_receipt(receipt1).unwrap();
        state.add_cross_shard_receipt(receipt2).unwrap();

        let expired = state.prune_expired_receipts(150);
        assert_eq!(expired.len(), 1);
    }

    #[test]
    fn test_compute_state_root() {
        let state = StateManager::new(1, 1);
        let address1 = test_address(24);
        let address2 = test_address(25);

        state.create_account(address1, AccountType::EOA).unwrap();
        state.create_account(address2, AccountType::EOA).unwrap();

        let root = state.compute_state_root();
        assert_ne!(root, Hash::ZERO);
    }

    #[test]
    fn test_compute_storage_root() {
        let state = StateManager::new(1, 1);
        let owner = test_address(26);

        for i in 0..3 {
            let node_addr = test_address(11 + i);
            state
                .create_account(
                    node_addr,
                    AccountType::StorageProvider {
                        provider_id: format!("provider_{}", i),
                        region: "us-west-1".to_string(),
                    },
                )
                .unwrap();
        }

        let entry = create_test_storage_entry(11, owner);
        state.register_storage_entry(entry).unwrap();

        let root = state.compute_storage_root();
        assert_ne!(root, Hash::ZERO);
    }

    #[test]
    fn test_update_all_roots() {
        let state = StateManager::new(1, 1);
        let address = test_address(27);

        state.create_account(address, AccountType::EOA).unwrap();
        state.update_all_roots();

        let state_root = state.get_state_root();
        assert_ne!(state_root, Hash::ZERO);
    }

    #[test]
    fn test_set_and_get_roots() {
        let state = StateManager::new(1, 1);
        let test_root = test_hash(50);

        state.set_tx_root(test_root);
        assert_eq!(state.get_tx_root(), test_root);

        state.set_receipts_root(test_root);
        assert_eq!(state.get_receipts_root(), test_root);

        state.set_events_root_post(test_root);
        assert_eq!(state.get_events_root_post(), test_root);

        state.set_events_root_poc(test_root);
        assert_eq!(state.get_events_root_poc(), test_root);

        state.set_rollup_root(test_root);
        assert_eq!(state.get_rollup_root(), test_root);

        state.set_da_root(test_root);
        assert_eq!(state.get_da_root(), test_root);
    }

    #[test]
    fn test_block_height_operations() {
        let mut state = StateManager::new(1, 1);

        assert_eq!(state.get_block_height(), BlockHeight::GENESIS);

        state.set_block_height(BlockHeight::new(100));
        assert_eq!(state.get_block_height(), BlockHeight::new(100));

        state.increment_block_height();
        assert_eq!(state.get_block_height(), BlockHeight::new(101));
    }

    #[test]
    fn test_get_current_epoch() {
        let mut state = StateManager::new(1, 1);

        state.set_block_height(BlockHeight::new(12000));
        assert_eq!(state.get_current_epoch(), 1);

        state.set_block_height(BlockHeight::new(24000));
        assert_eq!(state.get_current_epoch(), 2);

        state.set_block_height(BlockHeight::new(36500));
        assert_eq!(state.get_current_epoch(), 3);
    }

    #[test]
    fn test_get_stats() {
        let state = StateManager::new(1, 1);

        for i in 0..5 {
            let address = test_address(40 + i);
            state.create_account(address, AccountType::EOA).unwrap();
        }

        let stats = state.get_stats();
        assert_eq!(stats.total_accounts, 5);
        assert_eq!(stats.eoa_accounts, 5);
    }

    #[test]
    fn test_should_prune() {
        let config = PruningConfig {
            enabled: true,
            keep_epochs: 100,
            prune_interval_epochs: 10,
            keep_headers_forever: true,
            keep_state_snapshots: true,
            snapshot_interval_epochs: 1000,
            prune_old_bodies: true,
            prune_old_receipts: true,
            prune_old_events: true,
            prune_expired_storage: true,
        };

        let mut state = StateManager::new(1, 1).with_pruning_config(config);

        state.set_block_height(BlockHeight::new(120000));
        assert!(state.should_prune());

        state.set_block_height(BlockHeight::new(120001));
        assert!(state.should_prune());
    }

    #[test]
    fn test_should_create_snapshot() {
        let config = PruningConfig {
            enabled: true,
            keep_epochs: 100,
            prune_interval_epochs: 10,
            keep_headers_forever: true,
            keep_state_snapshots: true,
            snapshot_interval_epochs: 1000,
            prune_old_bodies: true,
            prune_old_receipts: true,
            prune_old_events: true,
            prune_expired_storage: true,
        };

        let mut state = StateManager::new(1, 1).with_pruning_config(config);

        state.set_block_height(BlockHeight::new(12_000_000));
        assert!(state.should_create_snapshot());

        state.set_block_height(BlockHeight::new(12_000_001));
        assert!(state.should_create_snapshot());
    }

    #[test]
    fn test_prune_old_data() {
        let config = PruningConfig {
            enabled: true,
            keep_epochs: 100,
            prune_interval_epochs: 10,
            keep_headers_forever: true,
            keep_state_snapshots: true,
            snapshot_interval_epochs: 1000,
            prune_old_bodies: true,
            prune_old_receipts: true,
            prune_old_events: true,
            prune_expired_storage: true,
        };

        let mut state = StateManager::new(1, 1).with_pruning_config(config);
        let owner = test_address(28);

        for i in 0..3 {
            let node_addr = test_address(12 + i);
            state
                .create_account(
                    node_addr,
                    AccountType::StorageProvider {
                        provider_id: format!("provider_{}", i),
                        region: "us-west-1".to_string(),
                    },
                )
                .unwrap();
        }

        let mut entry = create_test_storage_entry(12, owner);
        entry.expires_at = BlockHeight::new(50);
        state.register_storage_entry(entry).unwrap();

        state.set_block_height(BlockHeight::new(100));

        let report = state.prune_old_data(200).unwrap();
        assert!(report.storage_entries_pruned > 0);
    }

    #[test]
    fn test_create_state_snapshot() {
        let mut state = StateManager::new(1, 1);
        let address = test_address(29);

        state.create_account(address, AccountType::EOA).unwrap();
        state.set_block_height(BlockHeight::new(12000));
        state.update_all_roots();

        let snapshot = state.create_state_snapshot().unwrap();
        assert_eq!(snapshot.epoch, 1);
        assert_eq!(snapshot.block_height, BlockHeight::new(12000));
        assert_eq!(snapshot.total_accounts, 1);
    }

    #[test]
    fn test_get_accounts_by_type() {
        let state = StateManager::new(1, 1);

        for i in 0..3 {
            let address = test_address(50 + i);
            state.create_account(address, AccountType::EOA).unwrap();
        }

        for i in 0..2 {
            let address = test_address(60 + i);
            state
                .create_account(
                    address,
                    AccountType::Device {
                        device_id: format!("device_{}", i),
                        geohash: None,
                    },
                )
                .unwrap();
        }

        let eoa_accounts = state.get_accounts_by_type(AccountType::EOA);
        assert_eq!(eoa_accounts.len(), 3);

        let device_accounts = state.get_accounts_by_type(AccountType::Device {
            device_id: "".to_string(),
            geohash: None,
        });
        assert_eq!(device_accounts.len(), 2);
    }

    #[test]
    fn test_get_storage_providers() {
        let state = StateManager::new(1, 1);

        for i in 0..4 {
            let address = test_address(70 + i);
            state
                .create_account(
                    address,
                    AccountType::StorageProvider {
                        provider_id: format!("provider_{}", i),
                        region: "us-west-1".to_string(),
                    },
                )
                .unwrap();
        }

        let providers = state.get_storage_providers();
        assert_eq!(providers.len(), 4);
    }

    #[test]
    fn test_get_validators_by_status() {
        let state = StateManager::new(1, 1);

        for i in 0..3 {
            let address = test_address(80 + i);
            let pubkey = test_public_key(30 + i);
            let validator_info = create_test_validator_info(address, pubkey);
            state.register_validator(validator_info).unwrap();
        }

        let address_jail = test_address(82);
        state
            .jail_validator(
                &address_jail,
                JailReason::Downtime { epochs_missed: 10 },
                100,
                Balance::new(1000),
            )
            .unwrap();

        let active = state.get_validators_by_status(ValidatorStatus::Active);
        assert_eq!(active.len(), 2);

        let jailed = state.get_validators_by_status(ValidatorStatus::Jailed);
        assert_eq!(jailed.len(), 1);
    }

    #[test]
    fn test_get_top_validators_by_stake() {
        let state = StateManager::new(1, 1);

        for i in 0..5 {
            let address = test_address(90 + i);
            let pubkey = test_public_key(40 + i);
            let mut validator_info = create_test_validator_info(address, pubkey);
            validator_info.total_stake = Balance::new(1_000_000_000_000 * (i as u128 + 1));
            state.register_validator(validator_info).unwrap();
        }

        let top_validators = state.get_top_validators_by_stake(3);
        assert_eq!(top_validators.len(), 3);
        assert!(top_validators[0].total_stake >= top_validators[1].total_stake);
        assert!(top_validators[1].total_stake >= top_validators[2].total_stake);
    }

    #[test]
    fn test_get_sectors_by_node() {
        let state = StateManager::new(1, 1);
        let owner = test_address(95);
        let node_id = test_address(110);

        for i in 0..3 {
            let node_addr = test_address(110 + i);
            state
                .create_account(
                    node_addr,
                    AccountType::StorageProvider {
                        provider_id: format!("provider_{}", i),
                        region: "us-west-1".to_string(),
                    },
                )
                .unwrap();
        }

        for i in 0..3 {
            let node_addr = test_address(13 + i);
            state
                .create_account(
                    node_addr,
                    AccountType::StorageProvider {
                        provider_id: format!("provider_{}", i),
                        region: "us-west-1".to_string(),
                    },
                )
                .unwrap();
        }

        let mut entry1 = create_test_storage_entry(13, owner);
        entry1.triad.primary.node_id = node_id;
        state.register_storage_entry(entry1).unwrap();

        for i in 0..3 {
            let node_addr = test_address(14 + i);
            if !state.account_exists(&node_addr) {
                state
                    .create_account(
                        node_addr,
                        AccountType::StorageProvider {
                            provider_id: format!("provider_14_{}", i),
                            region: "us-west-1".to_string(),
                        },
                    )
                    .unwrap();
            }
        }

        let mut entry2 = create_test_storage_entry(14, owner);
        entry2.triad.replica_a.node_id = node_id;
        state.register_storage_entry(entry2).unwrap();

        let sectors = state.get_sectors_by_node(&node_id);
        assert_eq!(sectors.len(), 2);
    }

    #[test]
    fn test_get_failing_sectors() {
        let state = StateManager::new(1, 1);
        let owner = test_address(96);

        for seed in 15..=16 {
            for i in 0..3 {
                let node_addr = test_address(seed + i);
                if !state.account_exists(&node_addr) {
                    state
                        .create_account(
                            node_addr,
                            AccountType::StorageProvider {
                                provider_id: format!("provider_{}_{}", seed, i),
                                region: "us-west-1".to_string(),
                            },
                        )
                        .unwrap();
                }
            }
        }

        let mut entry1 = create_test_storage_entry(15, owner);
        entry1.verification_failures = 5;
        state.register_storage_entry(entry1).unwrap();

        let mut entry2 = create_test_storage_entry(16, owner);
        entry2.verification_failures = 1;
        state.register_storage_entry(entry2).unwrap();

        let failing = state.get_failing_sectors(3);
        assert_eq!(failing.len(), 1);
    }

    #[test]
    fn test_get_slices_by_owner() {
        let state = StateManager::new(1, 1);
        let owner1 = test_address(97);
        let owner2 = test_address(98);

        state.create_account(owner1, AccountType::EOA).unwrap();
        state.create_account(owner2, AccountType::EOA).unwrap();

        let slice1 = create_test_slice_config("slice_owner1_1".to_string(), owner1);
        let slice2 = create_test_slice_config("slice_owner1_2".to_string(), owner1);
        let slice3 = create_test_slice_config("slice_owner2_1".to_string(), owner2);

        state.create_slice(slice1).unwrap();
        state.create_slice(slice2).unwrap();
        state.create_slice(slice3).unwrap();

        let slices_owner1 = state.get_slices_by_owner(&owner1);
        assert_eq!(slices_owner1.len(), 2);

        let slices_owner2 = state.get_slices_by_owner(&owner2);
        assert_eq!(slices_owner2.len(), 1);
    }

    #[test]
    fn test_get_pending_receipts_for_shard() {
        let state = StateManager::new(1, 1);
        let src_shard = ShardId::new(0).unwrap();
        let dst_shard1 = ShardId::new(1).unwrap();
        let dst_shard2 = ShardId::new(2).unwrap();

        state.init_cross_shard_state(src_shard).unwrap();
        state.init_cross_shard_state(dst_shard1).unwrap();
        state.init_cross_shard_state(dst_shard2).unwrap();

        let receipt1 = ego_core::transaction::CrossShardReceipt {
            src_shard,
            dst_shard: dst_shard1,
            src_block_hash: test_hash(1),
            tx_id: test_hash(10),
            payload: vec![1, 2, 3],
            nonce: 10,
            deadline_epoch: 1000,
            merkle_proof: Vec::new(),
        };

        let receipt2 = ego_core::transaction::CrossShardReceipt {
            src_shard,
            dst_shard: dst_shard1,
            src_block_hash: test_hash(2),
            tx_id: test_hash(11),
            payload: vec![4, 5, 6],
            nonce: 11,
            deadline_epoch: 1000,
            merkle_proof: Vec::new(),
        };

        let receipt3 = ego_core::transaction::CrossShardReceipt {
            src_shard,
            dst_shard: dst_shard2,
            src_block_hash: test_hash(3),
            tx_id: test_hash(12),
            payload: vec![7, 8, 9],
            nonce: 12,
            deadline_epoch: 1000,
            merkle_proof: Vec::new(),
        };

        state.add_cross_shard_receipt(receipt1).unwrap();
        state.add_cross_shard_receipt(receipt2).unwrap();
        state.add_cross_shard_receipt(receipt3).unwrap();

        let pending_shard1 = state.get_pending_receipts_for_shard(&dst_shard1);
        assert_eq!(pending_shard1.len(), 2);

        let pending_shard2 = state.get_pending_receipts_for_shard(&dst_shard2);
        assert_eq!(pending_shard2.len(), 1);
    }

    #[test]
    fn test_validate_state_transition() {
        let state = StateManager::new(1, 1);
        let root1 = test_hash(60);
        let root2 = test_hash(61);

        let result = state.validate_state_transition(root1, root2);
        assert!(result.is_ok());
        assert!(result.unwrap());

        let result_same = state.validate_state_transition(root1, root1);
        assert!(result_same.is_ok());
    }

    #[test]
    fn test_verify_triad_health() {
        let state = StateManager::new(1, 1);
        let owner = test_address(99);

        for i in 0..3 {
            let node_addr = test_address(17 + i);
            state
                .create_account(
                    node_addr,
                    AccountType::StorageProvider {
                        provider_id: format!("provider_{}", i),
                        region: "us-west-1".to_string(),
                    },
                )
                .unwrap();
        }

        let entry = create_test_storage_entry(17, owner);
        let chunk_id = entry.chunk_id;
        state.register_storage_entry(entry).unwrap();

        let report = state.verify_triad_health(&chunk_id).unwrap();
        assert!(report.primary_healthy);
        assert!(report.replica_a_healthy);
        assert!(report.replica_b_healthy);
        assert_eq!(report.healthy_replicas, 3);
        assert!(!report.needs_repair);
        assert!(!report.needs_promotion);
    }

    #[test]
    fn test_verify_triad_health_failing() {
        let state = StateManager::new(1, 1);
        let owner = test_address(100);

        for i in 0..3 {
            let node_addr = test_address(18 + i);
            state
                .create_account(
                    node_addr,
                    AccountType::StorageProvider {
                        provider_id: format!("provider_{}", i),
                        region: "us-west-1".to_string(),
                    },
                )
                .unwrap();
        }

        let mut entry = create_test_storage_entry(18, owner);
        entry.triad.primary.health_score = 30000;
        entry.triad.primary.consecutive_misses = 5;
        let chunk_id = entry.chunk_id;
        state.register_storage_entry(entry).unwrap();

        let report = state.verify_triad_health(&chunk_id).unwrap();
        assert!(!report.primary_healthy);
        assert!(report.replica_a_healthy);
        assert!(report.replica_b_healthy);
        assert_eq!(report.healthy_replicas, 2);
        assert!(!report.needs_repair);
        assert!(report.needs_promotion);
    }

    #[test]
    fn test_storage_data_type_variants() {
        let old_bodies = StorageDataType::OldBlockBodies {
            start_height: 0,
            end_height: 1000,
        };
        let state_snapshot = StorageDataType::StateSnapshot { epoch: 100 };
        let contract_code = StorageDataType::ContractCode {
            code_hash: test_hash(1),
        };
        let contract_state = StorageDataType::ContractState {
            contract_addr: test_address(1),
            epoch: 100,
        };
        let rollup_batch = StorageDataType::RollupBatch {
            rollup_id: "rollup1".to_string(),
            batch_id: 1,
        };
        let da_blob = StorageDataType::DABlob { epoch: 100 };
        let post_evidence = StorageDataType::PoStEvidence {
            epoch: 100,
            node_id: test_address(1),
        };
        let poc_evidence = StorageDataType::PoCEvidence {
            epoch: 100,
            region_id: "region1".to_string(),
        };
        let porep_evidence = StorageDataType::PoRepEvidence {
            sector_id: test_hash(1),
        };
        let user_data = StorageDataType::UserData {
            app_id: "app1".to_string(),
        };
        let file_storage = StorageDataType::FileStorage {
            filename: "file.txt".to_string(),
            mime_type: "text/plain".to_string(),
        };
        let video_content = StorageDataType::VideoContent {
            video_id: "video1".to_string(),
        };
        let telemetry = StorageDataType::TelemetryData {
            device_id: "device1".to_string(),
            period: "2024-01".to_string(),
        };
        let custom = StorageDataType::Custom {
            label: "custom".to_string(),
        };

        assert!(matches!(old_bodies, StorageDataType::OldBlockBodies { .. }));
        assert!(matches!(
            state_snapshot,
            StorageDataType::StateSnapshot { .. }
        ));
        assert!(matches!(
            contract_code,
            StorageDataType::ContractCode { .. }
        ));
        assert!(matches!(
            contract_state,
            StorageDataType::ContractState { .. }
        ));
        assert!(matches!(rollup_batch, StorageDataType::RollupBatch { .. }));
        assert!(matches!(da_blob, StorageDataType::DABlob { .. }));
        assert!(matches!(
            post_evidence,
            StorageDataType::PoStEvidence { .. }
        ));
        assert!(matches!(poc_evidence, StorageDataType::PoCEvidence { .. }));
        assert!(matches!(
            porep_evidence,
            StorageDataType::PoRepEvidence { .. }
        ));
        assert!(matches!(user_data, StorageDataType::UserData { .. }));
        assert!(matches!(file_storage, StorageDataType::FileStorage { .. }));
        assert!(matches!(
            video_content,
            StorageDataType::VideoContent { .. }
        ));
        assert!(matches!(telemetry, StorageDataType::TelemetryData { .. }));
        assert!(matches!(custom, StorageDataType::Custom { .. }));
    }

    #[test]
    fn test_erasure_codec_variants() {
        let reed_solomon = ego_core::state::ErasureCodec::ReedSolomon;
        let ldpc = ego_core::state::ErasureCodec::LDPC;
        let fountain = ego_core::state::ErasureCodec::Fountain;

        assert_eq!(reed_solomon, ego_core::state::ErasureCodec::ReedSolomon);
        assert_eq!(ldpc, ego_core::state::ErasureCodec::LDPC);
        assert_eq!(fountain, ego_core::state::ErasureCodec::Fountain);
        assert_ne!(reed_solomon, ldpc);
    }

    #[test]
    fn test_validator_status_variants() {
        let active = ValidatorStatus::Active;
        let inactive = ValidatorStatus::Inactive;
        let jailed = ValidatorStatus::Jailed;
        let unbonding = ValidatorStatus::Unbonding {
            release_epoch: 1000,
        };
        let slashed = ValidatorStatus::Slashed;

        assert_eq!(active, ValidatorStatus::Active);
        assert_eq!(inactive, ValidatorStatus::Inactive);
        assert_eq!(jailed, ValidatorStatus::Jailed);
        assert!(matches!(unbonding, ValidatorStatus::Unbonding { .. }));
        assert_eq!(slashed, ValidatorStatus::Slashed);
    }

    #[test]
    fn test_jail_reason_variants() {
        let excessive_misses = JailReason::ExcessiveMisses { consecutive: 10 };
        let equivocation = JailReason::Equivocation;
        let invalid_proof = JailReason::InvalidProof;
        let downtime = JailReason::Downtime { epochs_missed: 100 };
        let slashing = JailReason::Slashing;

        assert!(matches!(
            excessive_misses,
            JailReason::ExcessiveMisses { .. }
        ));
        assert_eq!(equivocation, JailReason::Equivocation);
        assert_eq!(invalid_proof, JailReason::InvalidProof);
        assert!(matches!(downtime, JailReason::Downtime { .. }));
        assert_eq!(slashing, JailReason::Slashing);
    }

    #[test]
    fn test_slashing_type_variants() {
        let post_miss = SlashingType::PostMiss;
        let post_invalid = SlashingType::PostInvalid;
        let poc_fraud = SlashingType::PoCFraud;
        let equivocation = SlashingType::Equivocation;
        let data_unavailability = SlashingType::DataUnavailability;
        let contract_violation = SlashingType::ContractViolation;

        assert_eq!(post_miss, SlashingType::PostMiss);
        assert_eq!(post_invalid, SlashingType::PostInvalid);
        assert_eq!(poc_fraud, SlashingType::PoCFraud);
        assert_eq!(equivocation, SlashingType::Equivocation);
        assert_eq!(data_unavailability, SlashingType::DataUnavailability);
        assert_eq!(contract_violation, SlashingType::ContractViolation);
    }

    #[test]
    fn test_slice_type_variants() {
        let embb = SliceType::EMbb;
        let urllc = SliceType::Urllc;
        let mmtc = SliceType::MMtc;
        let custom = SliceType::Custom {
            name: "custom".to_string(),
            parameters: vec![1, 2, 3],
        };

        assert_eq!(embb, SliceType::EMbb);
        assert_eq!(urllc, SliceType::Urllc);
        assert_eq!(mmtc, SliceType::MMtc);
        assert!(matches!(custom, SliceType::Custom { .. }));
    }

    #[test]
    fn test_slice_status_variants() {
        let active = SliceStatus::Active;
        let paused = SliceStatus::Paused;
        let maintenance = SliceStatus::Maintenance;
        let inactive = SliceStatus::Inactive;
        let quota_exceeded = SliceStatus::QuotaExceeded;
        let credits_exhausted = SliceStatus::CreditsExhausted;

        assert_eq!(active, SliceStatus::Active);
        assert_eq!(paused, SliceStatus::Paused);
        assert_eq!(maintenance, SliceStatus::Maintenance);
        assert_eq!(inactive, SliceStatus::Inactive);
        assert_eq!(quota_exceeded, SliceStatus::QuotaExceeded);
        assert_eq!(credits_exhausted, SliceStatus::CreditsExhausted);
    }

    #[test]
    fn test_cross_shard_sync_status_variants() {
        let synced = CrossShardSyncStatus::Synced;
        let syncing = CrossShardSyncStatus::Syncing {
            progress_percent: 50,
        };
        let stale = CrossShardSyncStatus::Stale { epochs_behind: 10 };
        let disconnected = CrossShardSyncStatus::Disconnected;

        assert_eq!(synced, CrossShardSyncStatus::Synced);
        assert!(matches!(syncing, CrossShardSyncStatus::Syncing { .. }));
        assert!(matches!(stale, CrossShardSyncStatus::Stale { .. }));
        assert_eq!(disconnected, CrossShardSyncStatus::Disconnected);
    }

    #[test]
    fn test_receipt_status_variants() {
        let pending = ReceiptStatus::Pending;
        let transmitted = ReceiptStatus::Transmitted;
        let acknowledged = ReceiptStatus::Acknowledged;
        let applied = ReceiptStatus::Applied;
        let expired = ReceiptStatus::Expired;
        let failed = ReceiptStatus::Failed {
            reason: "error".to_string(),
        };

        assert_eq!(pending, ReceiptStatus::Pending);
        assert_eq!(transmitted, ReceiptStatus::Transmitted);
        assert_eq!(acknowledged, ReceiptStatus::Acknowledged);
        assert_eq!(applied, ReceiptStatus::Applied);
        assert_eq!(expired, ReceiptStatus::Expired);
        assert!(matches!(failed, ReceiptStatus::Failed { .. }));
    }

    #[test]
    fn test_pruning_config_default() {
        let config = PruningConfig::default();
        assert!(config.enabled);
        assert_eq!(config.keep_epochs, DEFAULT_PRUNING_EPOCHS);
        assert_eq!(config.snapshot_interval_epochs, DEFAULT_SNAPSHOT_INTERVAL);
        assert!(config.keep_headers_forever);
        assert!(config.keep_state_snapshots);
        assert!(config.prune_old_bodies);
        assert!(config.prune_old_receipts);
        assert!(config.prune_old_events);
        assert!(config.prune_expired_storage);
    }

    #[test]
    fn test_pruning_report_default() {
        let report = PruningReport::default();
        assert_eq!(report.storage_entries_pruned, 0);
        assert_eq!(report.receipts_pruned, 0);
        assert_eq!(report.accounts_pruned, 0);
        assert_eq!(report.validators_pruned, 0);
        assert_eq!(report.bytes_reclaimed, 0);
    }

    #[test]
    fn test_state_stats_default() {
        let stats = StateStats::default();
        assert_eq!(stats.total_accounts, 0);
        assert_eq!(stats.eoa_accounts, 0);
        assert_eq!(stats.device_accounts, 0);
        assert_eq!(stats.validator_accounts, 0);
        assert_eq!(stats.storage_provider_accounts, 0);
        assert_eq!(stats.contract_accounts, 0);
        assert_eq!(stats.total_balance, Balance::ZERO);
        assert_eq!(stats.storage_entries, 0);
        assert_eq!(stats.total_storage_bytes, 0);
        assert_eq!(stats.active_validators, 0);
        assert_eq!(stats.jailed_validators, 0);
        assert_eq!(stats.total_staked, Balance::ZERO);
        assert_eq!(stats.active_slices, 0);
        assert_eq!(stats.pending_cross_shard_receipts, 0);
    }

    #[test]
    fn test_triad_role_equality() {
        let primary1 = TriadRole::Primary;
        let primary2 = TriadRole::Primary;
        let replica_a = TriadRole::ReplicaA;
        let replica_b = TriadRole::ReplicaB;

        assert_eq!(primary1, primary2);
        assert_ne!(primary1, replica_a);
        assert_ne!(replica_a, replica_b);
    }

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_PRUNING_EPOCHS, 100);
        assert_eq!(DEFAULT_SNAPSHOT_INTERVAL, 1000);
        assert_eq!(MAX_CROSS_SHARD_RECEIPTS, 10000);
        assert_eq!(RECEIPT_DEADLINE_EPOCHS, 100);
        assert_eq!(MIN_VALIDATOR_STAKE, 100_000_000_000);
        assert_eq!(MIN_STORAGE_COLLATERAL, 10_000_000_000);
    }

    #[test]
    fn test_multiple_post_updates() {
        let state = StateManager::new(1, 1);
        let owner = test_address(101);
        let node_id = test_address(150);

        state
            .create_account(
                node_id,
                AccountType::StorageProvider {
                    provider_id: "provider_multi".to_string(),
                    region: "us-west-1".to_string(),
                },
            )
            .unwrap();

        for i in 0..3 {
            let node_addr = test_address(19 + i);
            state
                .create_account(
                    node_addr,
                    AccountType::StorageProvider {
                        provider_id: format!("provider_{}", i),
                        region: "us-west-1".to_string(),
                    },
                )
                .unwrap();
        }

        let mut entry = create_test_storage_entry(19, owner);
        entry.triad.primary.node_id = node_id;
        let chunk_id = entry.chunk_id;
        state.register_storage_entry(entry).unwrap();

        for i in 0..10 {
            let success = i % 3 != 0;
            let latency = if success { 1500 } else { 3000 };
            state
                .update_post_result(&chunk_id, &node_id, success, latency, 100 + i)
                .unwrap();
        }

        let updated_entry = state.get_storage_entry(&chunk_id).unwrap();
        assert_eq!(updated_entry.post_stats.total_challenges, 10);
        assert!(updated_entry.post_stats.pass_rate < 100.0);
        assert!(updated_entry.post_stats.pass_rate > 0.0);
    }

    #[test]
    fn test_stats_updates_with_mixed_accounts() {
        let state = StateManager::new(1, 1);

        state
            .create_account(test_address(160), AccountType::EOA)
            .unwrap();
        state
            .create_account(test_address(161), AccountType::EOA)
            .unwrap();

        state
            .create_account(
                test_address(162),
                AccountType::Device {
                    device_id: "device1".to_string(),
                    geohash: None,
                },
            )
            .unwrap();

        state
            .create_account(
                test_address(163),
                AccountType::StorageProvider {
                    provider_id: "provider1".to_string(),
                    region: "us-west-1".to_string(),
                },
            )
            .unwrap();

        let stats = state.get_stats();

        assert_eq!(stats.total_accounts, 4);
        assert_eq!(stats.eoa_accounts, 2);
        assert_eq!(stats.device_accounts, 1);
        assert_eq!(stats.storage_provider_accounts, 1);
    }

    #[test]
    fn test_cross_shard_receipt_max_limit() {
        let state = StateManager::new(1, 1);
        let src_shard = ShardId::new(0).unwrap();
        let dst_shard = ShardId::new(1).unwrap();

        state.init_cross_shard_state(src_shard).unwrap();
        state.init_cross_shard_state(dst_shard).unwrap();

        for i in 0..MAX_CROSS_SHARD_RECEIPTS {
            let mut tx_hash_bytes = [0u8; 32];
            let i_bytes = i.to_le_bytes();
            tx_hash_bytes[..i_bytes.len()].copy_from_slice(&i_bytes);

            let receipt = ego_core::transaction::CrossShardReceipt {
                src_shard,
                dst_shard,
                src_block_hash: test_hash((i % 256) as u8),
                tx_id: Hash::new(tx_hash_bytes),
                payload: vec![1, 2, 3],
                nonce: i as u64,
                deadline_epoch: 10000,
                merkle_proof: Vec::new(),
            };
            state.add_cross_shard_receipt(receipt).unwrap();
        }

        let one_more = ego_core::transaction::CrossShardReceipt {
            src_shard,
            dst_shard,
            src_block_hash: test_hash(255),
            tx_id: test_hash(255),
            payload: vec![1, 2, 3],
            nonce: MAX_CROSS_SHARD_RECEIPTS as u64,
            deadline_epoch: 10000,
            merkle_proof: Vec::new(),
        };

        let result = state.add_cross_shard_receipt(one_more);
        assert!(result.is_err());
    }

    #[test]
    fn test_validator_performance_updates() {
        let state = StateManager::new(1, 1);
        let address = test_address(164);
        let pubkey = test_public_key(50);

        let mut validator_info = create_test_validator_info(address, pubkey);
        validator_info.performance.blocks_proposed = 0;
        validator_info.performance.blocks_missed = 0;
        state.register_validator(validator_info).unwrap();

        state
            .update_validator_metrics(&address, 98, 150, 10000000, 500, 95, 1.2)
            .unwrap();

        let updated = state.get_validator(&address).unwrap();
        assert_eq!(updated.performance.uptime_score, 98.0);
        assert_eq!(updated.puc_coefficient, 1.2);
    }

    #[test]
    fn test_slice_lifecycle() {
        let state = StateManager::new(1, 1);
        let owner = test_address(165);

        state.create_account(owner, AccountType::EOA).unwrap();

        let slice_config = create_test_slice_config("slice_lifecycle".to_string(), owner);
        state.create_slice(slice_config).unwrap();

        let device1 = test_address(170);
        let device2 = test_address(171);
        state.create_account(device1, AccountType::EOA).unwrap();
        state.create_account(device2, AccountType::EOA).unwrap();

        state
            .authorize_device_for_slice("slice_lifecycle", device1)
            .unwrap();
        state
            .authorize_device_for_slice("slice_lifecycle", device2)
            .unwrap();

        state
            .update_slice_usage("slice_lifecycle", 500000, 100000)
            .unwrap();

        let slice = state.get_slice("slice_lifecycle").unwrap();
        assert_eq!(slice.current_devices, 2);
        assert_eq!(slice.current_storage_used, 500000);
        assert_eq!(slice.current_bandwidth_used, 100000);
        assert!(slice.authorized_devices.contains(&device1));
        assert!(slice.authorized_devices.contains(&device2));
    }

    #[test]
    fn test_storage_entry_full_lifecycle() {
        let state = StateManager::new(1, 1);
        let owner = test_address(166);
        let node_id = test_address(175);

        state
            .create_account(
                node_id,
                AccountType::StorageProvider {
                    provider_id: "provider_lifecycle".to_string(),
                    region: "us-west-1".to_string(),
                },
            )
            .unwrap();

        state
            .create_account(
                test_address(176),
                AccountType::StorageProvider {
                    provider_id: "provider2".to_string(),
                    region: "us-east-1".to_string(),
                },
            )
            .unwrap();

        state
            .create_account(
                test_address(177),
                AccountType::StorageProvider {
                    provider_id: "provider3".to_string(),
                    region: "eu-west-1".to_string(),
                },
            )
            .unwrap();

        let mut entry = create_test_storage_entry(20, owner);
        entry.triad.primary.node_id = node_id;
        entry.triad.replica_a.node_id = test_address(176);
        entry.triad.replica_b.node_id = test_address(177);
        let chunk_id = entry.chunk_id;
        state.register_storage_entry(entry).unwrap();

        state
            .update_post_result(&chunk_id, &node_id, true, 1500, 200)
            .unwrap();
        state
            .update_post_result(&chunk_id, &node_id, true, 1600, 201)
            .unwrap();
        state
            .update_post_result(&chunk_id, &node_id, false, 3000, 202)
            .unwrap();

        let final_entry = state.get_storage_entry(&chunk_id).unwrap();
        assert_eq!(final_entry.post_stats.total_challenges, 3);
        assert_eq!(final_entry.post_stats.passed_challenges, 2);
        assert_eq!(final_entry.post_stats.failed_challenges, 1);
    }

    #[test]
    fn test_validator_jail_and_release() {
        let state = StateManager::new(1, 1);
        let address = test_address(167);
        let pubkey = test_public_key(51);

        let validator_info = create_test_validator_info(address, pubkey);
        state.register_validator(validator_info).unwrap();

        state
            .jail_validator(
                &address,
                JailReason::ExcessiveMisses { consecutive: 5 },
                50,
                Balance::new(50_000_000_000),
            )
            .unwrap();

        let jailed = state.get_validator(&address).unwrap();
        assert_eq!(jailed.status, ValidatorStatus::Jailed);
        assert!(jailed.jail_info.is_some());

        let jail_info = jailed.jail_info.as_ref().unwrap();
        assert!(matches!(
            jail_info.reason,
            JailReason::ExcessiveMisses { .. }
        ));
        assert_eq!(jail_info.slashed_amount, Balance::new(50_000_000_000));
    }

    #[test]
    fn test_complex_cross_shard_scenario() {
        let state = StateManager::new(1, 1);
        let shard0 = ShardId::new(0).unwrap();
        let shard1 = ShardId::new(1).unwrap();
        let shard2 = ShardId::new(2).unwrap();

        state.init_cross_shard_state(shard0).unwrap();
        state.init_cross_shard_state(shard1).unwrap();
        state.init_cross_shard_state(shard2).unwrap();

        let receipt1 = CrossShardReceipt {
            src_shard: shard0,
            dst_shard: shard1,
            src_block_hash: test_hash(1),
            tx_id: test_hash(20),
            payload: vec![1, 2, 3],
            nonce: 100,
            deadline_epoch: 1000,
            merkle_proof: Vec::new(),
        };

        let receipt2 = CrossShardReceipt {
            src_shard: shard1,
            dst_shard: shard2,
            src_block_hash: test_hash(2),
            tx_id: test_hash(21),
            payload: vec![4, 5, 6],
            nonce: 101,
            deadline_epoch: 1000,
            merkle_proof: Vec::new(),
        };

        state.add_cross_shard_receipt(receipt1.clone()).unwrap();
        state.add_cross_shard_receipt(receipt2.clone()).unwrap();

        let result1 = state.process_cross_shard_receipt(&receipt1.tx_id);
        assert!(result1.is_ok());

        let result2 = state.process_cross_shard_receipt(&receipt2.tx_id);
        assert!(result2.is_ok());
    }

    #[test]
    fn test_state_manager_concurrent_account_access() {
        let state = StateManager::new(1, 1);

        for i in 0..10 {
            let address = test_address(180 + i);
            state.create_account(address, AccountType::EOA).unwrap();
        }

        for i in 0..10 {
            let address = test_address(180 + i);
            let account = state.get_account(&address);
            assert!(account.is_some());
        }
    }

    #[test]
    fn test_get_cross_shard_state() {
        let state = StateManager::new(1, 1);
        let shard_id = ShardId::new(5).unwrap();

        state.init_cross_shard_state(shard_id).unwrap();

        let cross_shard = state.get_cross_shard_state(&shard_id);
        assert!(cross_shard.is_some());

        let cs_state = cross_shard.unwrap();
        assert_eq!(cs_state.shard_id, shard_id);
        assert_eq!(cs_state.sync_status, CrossShardSyncStatus::Synced);
    }

    #[test]
    fn test_stats_with_validators() {
        let state = StateManager::new(1, 1);

        for i in 0..5 {
            let address = test_address(190 + i);
            let pubkey = test_public_key(60 + i);
            let validator_info = create_test_validator_info(address, pubkey);
            state.register_validator(validator_info).unwrap();
        }

        state
            .jail_validator(
                &test_address(191),
                JailReason::Slashing,
                100,
                Balance::new(1000),
            )
            .unwrap();

        let stats = state.get_stats();

        assert_eq!(stats.active_validators, 4);
        assert_eq!(stats.jailed_validators, 1);
        assert!(stats.total_staked.as_u128() > 0);
    }

    #[test]
    fn test_erasure_coding_params() {
        let params = ErasureCodingParams {
            k: 64,
            m: 32,
            codec: ErasureCodec::ReedSolomon,
            chunk_size: 16384,
        };

        assert_eq!(params.k, 64);
        assert_eq!(params.m, 32);
        assert_eq!(params.codec, ErasureCodec::ReedSolomon);
        assert_eq!(params.chunk_size, 16384);
    }

    #[test]
    fn test_post_schedule() {
        let schedule = PostSchedule {
            windows_per_day: 48,
            challenges_per_window: 24,
            sla_ms: 2000,
            next_window: 101,
            last_window: 100,
        };

        assert_eq!(schedule.windows_per_day, 48);
        assert_eq!(schedule.challenges_per_window, 24);
        assert_eq!(schedule.sla_ms, 2000);
        assert_eq!(schedule.next_window, 101);
        assert_eq!(schedule.last_window, 100);
    }

    #[test]
    fn test_post_stats_calculation() {
        let mut stats = PostStats {
            total_challenges: 100,
            passed_challenges: 85,
            failed_challenges: 15,
            avg_latency_ms: 1500,
            pass_rate: 85.0,
            last_proof_epoch: 200,
        };

        stats.total_challenges += 10;
        stats.passed_challenges += 8;
        stats.failed_challenges += 2;
        stats.pass_rate = (stats.passed_challenges as f64 / stats.total_challenges as f64) * 100.0;

        assert_eq!(stats.total_challenges, 110);
        assert!((stats.pass_rate - 84.54).abs() < 0.1);
    }

    #[test]
    fn test_validator_hot_set_config() {
        let config = ValidatorHotSetConfig {
            keep_headers_forever: true,
            keep_qcs_forever: true,
            keep_recent_bodies_epochs: 100,
            keep_state_db: true,
            mempool_enabled: true,
            fetch_on_demand_enabled: true,
        };

        assert!(config.keep_headers_forever);
        assert!(config.keep_qcs_forever);
        assert_eq!(config.keep_recent_bodies_epochs, 100);
        assert!(config.keep_state_db);
        assert!(config.mempool_enabled);
        assert!(config.fetch_on_demand_enabled);
    }

    #[test]
    fn test_encryption_metadata() {
        let metadata = EncryptionMetadata {
            algorithm: "XChaCha20-Poly1305".to_string(),
            key_refs: vec![test_hash(1), test_hash(2)],
            nonce: vec![0u8; 24],
        };

        assert_eq!(metadata.algorithm, "XChaCha20-Poly1305");
        assert_eq!(metadata.key_refs.len(), 2);
        assert_eq!(metadata.nonce.len(), 24);
    }

    #[test]
    fn test_triad_member_health() {
        let member = TriadMember {
            node_id: test_address(200),
            sector_id: test_hash(30),
            replica_id: test_hash(31),
            h3_cell: "h3cell_test".to_string(),
            region: "us-west-1".to_string(),
            shard_id: 0,
            role: TriadRole::Primary,
            health_score: 95000,
            consecutive_misses: 0,
        };

        assert_eq!(member.health_score, 95000);
        assert_eq!(member.consecutive_misses, 0);
        assert_eq!(member.role, TriadRole::Primary);
    }

    #[test]
    fn test_validator_performance() {
        let performance = ValidatorPerformance {
            blocks_proposed: 1000,
            blocks_missed: 50,
            attestations_made: 2000,
            attestations_missed: 100,
            equivocations: 0,
            uptime_score: 95.0,
            attestation_accuracy: 95.0,
        };

        let success_rate = (performance.blocks_proposed as f64)
            / ((performance.blocks_proposed + performance.blocks_missed) as f64)
            * 100.0;

        assert!((success_rate - 95.24).abs() < 0.1);
        assert_eq!(performance.equivocations, 0);
    }

    #[test]
    fn test_slashing_event() {
        let event = SlashingEvent {
            timestamp: Timestamp::now(),
            epoch: 100,
            amount: Balance::new(1_000_000_000),
            reason: "POST failure".to_string(),
            evidence_hash: test_hash(40),
            event_type: SlashingType::PostMiss,
        };

        assert_eq!(event.epoch, 100);
        assert_eq!(event.amount, Balance::new(1_000_000_000));
        assert_eq!(event.event_type, SlashingType::PostMiss);
    }

    #[test]
    fn test_state_snapshot_creation() {
        let mut state = StateManager::new(1, 1);

        state
            .create_account(test_address(201), AccountType::EOA)
            .unwrap();
        state
            .create_account(test_address(202), AccountType::EOA)
            .unwrap();

        let address = test_address(203);
        let pubkey = test_public_key(70);
        let validator_info = create_test_validator_info(address, pubkey);
        state.register_validator(validator_info).unwrap();

        state.set_block_height(BlockHeight::new(12000));
        state.update_all_roots();

        let snapshot = state.create_state_snapshot().unwrap();

        assert_eq!(snapshot.epoch, 1);
        assert_eq!(snapshot.block_height, BlockHeight::new(12000));
        assert_eq!(snapshot.total_accounts, 2);
        assert_eq!(snapshot.total_validators, 1);
    }

    #[test]
    fn test_receipt_status_transitions() {
        let pending = ReceiptStatus::Pending;
        let transmitted = ReceiptStatus::Transmitted;
        let acknowledged = ReceiptStatus::Acknowledged;
        let applied = ReceiptStatus::Applied;

        assert_eq!(pending, ReceiptStatus::Pending);
        assert_eq!(transmitted, ReceiptStatus::Transmitted);
        assert_eq!(acknowledged, ReceiptStatus::Acknowledged);
        assert_eq!(applied, ReceiptStatus::Applied);
    }

    #[test]
    fn test_triad_info_diversity() {
        let triad = TriadInfo {
            group_id: "group_diversity".to_string(),
            primary: TriadMember {
                node_id: test_address(210),
                sector_id: test_hash(50),
                replica_id: test_hash(51),
                h3_cell: "h3_us_west".to_string(),
                region: "us-west-1".to_string(),
                shard_id: 0,
                role: TriadRole::Primary,
                health_score: 100000,
                consecutive_misses: 0,
            },
            replica_a: TriadMember {
                node_id: test_address(211),
                sector_id: test_hash(52),
                replica_id: test_hash(53),
                h3_cell: "h3_us_east".to_string(),
                region: "us-east-1".to_string(),
                shard_id: 0,
                role: TriadRole::ReplicaA,
                health_score: 100000,
                consecutive_misses: 0,
            },
            replica_b: TriadMember {
                node_id: test_address(212),
                sector_id: test_hash(54),
                replica_id: test_hash(55),
                h3_cell: "h3_eu_west".to_string(),
                region: "eu-west-1".to_string(),
                shard_id: 0,
                role: TriadRole::ReplicaB,
                health_score: 100000,
                consecutive_misses: 0,
            },
            placement_epoch: 100,
            diversity_score: 0.95,
            last_health_check: 100,
        };

        assert_eq!(triad.diversity_score, 0.95);
        assert_ne!(triad.primary.region, triad.replica_a.region);
        assert_ne!(triad.replica_a.region, triad.replica_b.region);
    }

    #[test]
    fn test_storage_entry_encryption() {
        let state = StateManager::new(1, 1);
        let owner = test_address(213);

        for i in 0..3 {
            let node_addr = test_address(21 + i);
            state
                .create_account(
                    node_addr,
                    AccountType::StorageProvider {
                        provider_id: format!("provider_{}", i),
                        region: "us-west-1".to_string(),
                    },
                )
                .unwrap();
        }

        let mut entry = create_test_storage_entry(21, owner);
        entry.encryption_envelope = Some(EncryptionMetadata {
            algorithm: "XChaCha20-Poly1305".to_string(),
            key_refs: vec![test_hash(60), test_hash(61)],
            nonce: vec![0u8; 24],
        });

        state.register_storage_entry(entry.clone()).unwrap();

        let retrieved = state.get_storage_entry(&entry.chunk_id).unwrap();
        assert!(retrieved.encryption_envelope.is_some());
        assert_eq!(
            retrieved.encryption_envelope.as_ref().unwrap().algorithm,
            "XChaCha20-Poly1305"
        );
    }
}
