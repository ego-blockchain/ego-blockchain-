mod state_tests {
    use ego_core::{
        AccountType, Address, Balance, Hash, ShardId,
        crypto::KeyPair,
        transaction::{Transaction, TransactionPayload},
    };
    use ego_rollup::{
        state::{
            CellularStatsState, DeployQuotaRecord, PQTransitionState, ProofHistoryRecord,
            RewardBuckets, RollupState, StorageDealRecord, TriadPlacementRecord,
        },
        types::RollupTransaction,
    };

    fn mock_address(id: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[0] = id;
        Address::new(bytes)
    }

    #[tokio::test]
    async fn test_rollup_state_new() {
        let state = RollupState::new(1, 2);
        assert_eq!(state.get_chain_id(), 1);
        assert_eq!(state.get_network_id(), 2);
        assert_eq!(state.get_epoch(), 0);
        assert_eq!(state.account_count(), 0);
    }

    #[tokio::test]
    async fn test_create_account_via_transaction() {
        let creator_keypair = KeyPair::generate();
        let creator = Address::from_public_key(&creator_keypair.public_key());
        let new_addr = mock_address(2);

        let mut state = RollupState::from_genesis(
            vec![(
                creator,
                Balance::new(1_000_000_000_000_000_000),
                AccountType::EOA,
            )],
            ShardId::new(0).unwrap(),
            1,
            1,
        );

        let tx = Transaction::new(
            creator,
            1,
            TransactionPayload::CreateAccount {
                account_address: new_addr,
                account_type: AccountType::EOA,
                initial_balance: Balance::new(100_000_000_000_000_000),
                dilithium_pk: vec![1u8; 1312],
                mlkem_pk: vec![2u8; 1184],
                ed25519_pk: None,
            },
            ShardId::new(0).unwrap(),
            None,
            1,
        );
        let mut signed_tx = tx;
        signed_tx.sign(&creator_keypair, false).unwrap();
        let rollup_tx = RollupTransaction::new(signed_tx, 1, 0);

        let result = state.execute_transaction(&rollup_tx).await.unwrap();
        assert!(result.success);
        assert_eq!(
            state.get_balance(new_addr),
            Balance::new(100_000_000_000_000_000)
        );
        assert!(state.get_account(&new_addr).is_ok());
    }

    #[tokio::test]
    async fn test_transfer_balance_via_transaction() {
        let from_keypair = KeyPair::generate();
        let from = Address::from_public_key(&from_keypair.public_key());
        let to = mock_address(2);

        let mut state = RollupState::from_genesis(
            vec![(from, Balance::new(1000), AccountType::EOA)],
            ShardId::new(0).unwrap(),
            1,
            1,
        );

        let tx = Transaction::new(
            from,
            1,
            TransactionPayload::Transfer {
                to,
                amount: Balance::new(500),
                stealth_mode: false,
                memo: None,
            },
            ShardId::new(0).unwrap(),
            None,
            1,
        );
        let mut signed_tx = tx;
        signed_tx.sign(&from_keypair, false).unwrap();
        let rollup_tx = RollupTransaction::new(signed_tx, 1, 0);

        let result = state.execute_transaction(&rollup_tx).await.unwrap();
        assert!(result.success);
        assert_eq!(state.get_balance(from), Balance::new(500));
        assert_eq!(state.get_balance(to), Balance::new(500));
    }

    #[tokio::test]
    async fn test_buy_storage_credits_via_transaction() {
        let buyer_keypair = KeyPair::generate();
        let buyer = Address::from_public_key(&buyer_keypair.public_key());

        let mut state = RollupState::from_genesis(
            vec![(buyer, Balance::new(1_000_000_000), AccountType::EOA)],
            ShardId::new(0).unwrap(),
            1,
            1,
        );

        let tx = Transaction::new(
            buyer,
            1,
            TransactionPayload::BuyStorageCredits {
                amount: Balance::new(100_000_000),
                credits_byte_months: 1000,
                burn_proof: Hash::ZERO,
            },
            ShardId::new(0).unwrap(),
            None,
            1,
        );
        let mut signed_tx = tx;
        signed_tx.sign(&buyer_keypair, false).unwrap();
        let rollup_tx = RollupTransaction::new(signed_tx, 1, 0);

        let result = state.execute_transaction(&rollup_tx).await.unwrap();
        assert!(result.success);
        let buyer_acc = state.get_account(&buyer).unwrap();
        assert_eq!(buyer_acc.storage_credits, 1000);
    }

    #[tokio::test]
    async fn test_compute_state_root() {
        let addr1 = mock_address(1);
        let addr2 = mock_address(2);

        let state = RollupState::from_genesis(
            vec![
                (addr1, Balance::new(1000), AccountType::EOA),
                (addr2, Balance::new(2000), AccountType::EOA),
            ],
            ShardId::new(0).unwrap(),
            1,
            1,
        );

        let root1 = state.compute_state_root();
        assert_ne!(root1, Hash::ZERO);
    }

    #[test]
    fn test_proof_history_record() {
        let record = ProofHistoryRecord::new();
        assert_eq!(record.post_pass_rate, 100.0);
        assert_eq!(record.consecutive_misses, 0);
    }

    #[test]
    fn test_pq_transition_state() {
        let state = PQTransitionState::new();
        assert_eq!(state.current_phase, 1);
        assert!(state.pq_required_topics.contains(&"consensus".to_string()));
    }

    #[test]
    fn test_cellular_stats_state() {
        let stats = CellularStatsState::new();
        assert_eq!(stats.total_cellular_bytes, 0);
        assert_eq!(stats.throttled_operations, 0);
    }

    #[test]
    fn test_deploy_quota_record() {
        let record = DeployQuotaRecord {
            free_deploys_used: 5,
            deploy_credits_used: 1000,
            epoch_reset: 100,
        };
        assert_eq!(record.free_deploys_used, 5);
    }

    #[test]
    fn test_triad_placement_record() {
        let record = TriadPlacementRecord {
            primary: mock_address(1),
            replica_a: mock_address(2),
            replica_b: mock_address(3),
            group_id: "test-group".to_string(),
            placement_epoch: 42,
            diversity_score: 0.88,
        };
        assert_eq!(record.placement_epoch, 42);
        assert_eq!(record.diversity_score, 0.88);
    }

    #[test]
    fn test_storage_deal_record() {
        let triad = TriadPlacementRecord {
            primary: mock_address(1),
            replica_a: mock_address(2),
            replica_b: mock_address(3),
            group_id: "deal-1".to_string(),
            placement_epoch: 10,
            diversity_score: 0.9,
        };
        let deal = StorageDealRecord {
            client: mock_address(5),
            triad,
            data_size: 1024 * 1024,
            duration_epochs: 100,
            start_epoch: 10,
            end_epoch: 110,
            credits_locked: 5000,
            replication_factor: 3,
        };
        assert_eq!(deal.end_epoch, 110);
    }

    #[test]
    fn test_reward_buckets() {
        let buckets = RewardBuckets {
            storage: Balance::new(100),
            consensus: Balance::new(200),
            coverage: Balance::new(150),
            retrieval: Balance::new(50),
        };
        let total = buckets.storage + buckets.consensus + buckets.coverage + buckets.retrieval;
        assert_eq!(total, Balance::new(500));
    }

    #[test]
    fn test_state_snapshot() {
        let state = RollupState::new(3, 4);
        let snapshot = state.create_snapshot();
        assert_eq!(snapshot.chain_id, 3);
        assert_eq!(snapshot.network_id, 4);
        assert_eq!(snapshot.account_count, 0);
        assert_eq!(snapshot.epoch, 0);
    }
}
