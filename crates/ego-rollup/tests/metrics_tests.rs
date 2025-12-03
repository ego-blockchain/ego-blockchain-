#[cfg(test)]
mod metrics_tests {
    use ego_core::{
        Address, Balance, Block, BlockBody, BlockHeader, BlockHeight, DualSignature, EpochNumber,
        Hash, QuorumCert, ShardId, Timestamp,
    };
    use ego_rollup::metrics::*;
    use std::collections::HashMap;

    fn create_test_address(id: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[0] = id;
        Address::new(bytes)
    }

    fn create_test_block(height: u64, shard_id: ShardId, tx_count: u32) -> Block {
        Block {
            hash: Hash::ZERO,
            header: BlockHeader {
                core: ego_core::BlockHeaderCore {
                    height: BlockHeight::new(height),
                    shard_id,
                    epoch: EpochNumber::new(0),
                    timestamp: Timestamp::now(),
                    tx_count,
                    pq_signature_count: ego_core::PQSignatureCount {
                        dilithium_sigs: 5,
                        ed25519_sigs: 3,
                        hybrid_sigs: 2,
                        slh_dsa_sigs: 1,
                    },
                    previous_hash: Hash::ZERO,
                    state_root: Hash::ZERO,
                    transactions_root: Hash::ZERO,
                    receipts_root: Hash::ZERO,
                    events_root_post: Hash::ZERO,
                    events_root_poc: Hash::ZERO,
                    proposer: Address::random(),
                    compute_used: 0,
                    da_root: Hash::ZERO,
                    chain_id: 1,
                    rollup_root: Hash::ZERO,
                    signature: DualSignature {
                        ed25519_sig: None,
                        dilithium_sig: None,
                        protocol_version: 1,
                    },
                    storage_used: 0,
                    protocol_version: 1,
                    network_id: 1,
                    vrf_output: [0u8; 32],
                    vrf_proof: None,
                },
                metadata: ego_core::BlockMetadata {
                    cellular_stats: ego_core::CellularStats {
                        cellular_safe_txs: 10,
                        wifi_only_txs: 5,
                        throttled_operations: 2,
                        total_data_bytes_cellular: 1024 * 1024 * 1024,
                        total_data_bytes_wifi: 2 * 1024 * 1024 * 1024,
                        avg_cellular_cost_per_tx: 0.001,
                    },
                    block_size: 1000,
                    cross_shard_receipts: 0,
                    rollup_commits: 0,
                    poc_events: 0,
                    post_events: 0,
                    drs_events: 0,
                    fraud_proofs: 0,
                    density_events: 0,
                    deploy_events: 0,
                    protocol_version: 1,
                    resource_pricing: ego_core::ResourcePricing {
                        bytes_cost: 1,
                        ru_cost: 1,
                        pob_floor: 1000,
                        pq_signature_cost: 100,
                        cellular_premium: 1,
                    },
                    pq_transition_data: ego_core::PQTransitionData {
                        transition_phase: 1,
                        pq_required_topics: vec![],
                        legacy_support_end_epoch: Some(1000),
                        algorithm_usage_stats: HashMap::new(),
                    },
                },
                qc: QuorumCert {
                    height: BlockHeight::new(height),
                    view: 0,
                    block_hash: Hash::ZERO,
                    signatures: vec![],
                    aggregated_signature: None,
                    voting_power: 0,
                    timestamp: Timestamp::now(),
                    pq_compliant: false,
                    round: 0,
                    bitmap: vec![],
                    signatures_root: Hash::ZERO,
                    validator_set_id: 0,
                },
            },
            body: BlockBody {
                transactions: vec![],
                cross_shard_receipts: vec![],
                rollup_commitments: vec![],
                proof_events: vec![],
                drs_events: vec![],
                fraud_proofs: vec![],
                density_events: vec![],
                deploy_events: vec![],
                pq_transition_events: vec![],
                transaction_results: vec![],
            },
        }
    }

    #[test]
    fn test_network_metrics_initialization() {
        let metrics = NetworkMetrics::default();
        assert_eq!(metrics.total_blocks, 0);
        assert_eq!(metrics.total_transactions, 0);
        assert_eq!(metrics.active_validators, 0);
        assert_eq!(metrics.total_staked, Balance::ZERO);
        assert_eq!(metrics.total_shards, 1);
        assert_eq!(metrics.pq_adoption_rate, 0.0);
    }

    #[test]
    fn test_network_metrics_timestamp() {
        let mut metrics = NetworkMetrics::default();
        let initial_timestamp = metrics.last_updated;
        std::thread::sleep(std::time::Duration::from_millis(10));
        metrics.update_timestamp();
        assert!(metrics.last_updated > initial_timestamp);
    }

    #[test]
    fn test_storage_utilization_calculation() {
        let mut metrics = NetworkMetrics::default();
        metrics.total_storage_capacity_gb = 1000;
        metrics.total_storage_used_gb = 750;
        assert_eq!(metrics.storage_utilization_percent(), 75.0);

        metrics.total_storage_capacity_gb = 0;
        assert_eq!(metrics.storage_utilization_percent(), 0.0);
    }

    #[test]
    fn test_fraud_proof_accuracy() {
        let mut metrics = NetworkMetrics::default();
        metrics.fraud_proofs_submitted = 100;
        metrics.fraud_proofs_valid = 95;
        assert_eq!(metrics.fraud_proof_accuracy(), 95.0);

        metrics.fraud_proofs_submitted = 0;
        assert_eq!(metrics.fraud_proof_accuracy(), 0.0);
    }

    #[test]
    fn test_deploy_acceptance_rate() {
        let mut metrics = NetworkMetrics::default();
        metrics.deploy_requests_total = 100;
        metrics.deploy_requests_accepted = 80;
        assert_eq!(metrics.deploy_acceptance_rate(), 80.0);

        metrics.deploy_requests_total = 0;
        assert_eq!(metrics.deploy_acceptance_rate(), 0.0);
    }

    #[test]
    fn test_metrics_collector_creation() {
        let collector = MetricsCollector::new();
        let snapshot = collector.get_snapshot();
        assert_eq!(snapshot.network.total_blocks, 0);
        assert_eq!(snapshot.validators.len(), 0);
        assert_eq!(snapshot.storage_providers.len(), 0);
    }

    #[test]
    fn test_record_block() {
        let collector = MetricsCollector::new();
        let block = create_test_block(1, ShardId::new(0).unwrap(), 10);

        collector.record_block(&block).unwrap();

        let snapshot = collector.get_snapshot();
        assert_eq!(snapshot.network.total_blocks, 1);
        assert_eq!(snapshot.network.total_transactions, 10);
    }

    #[test]
    fn test_record_multiple_blocks() {
        let collector = MetricsCollector::new();

        for i in 1..=5 {
            let block = create_test_block(i, ShardId::new(0).unwrap(), 10);
            collector.record_block(&block).unwrap();
        }

        let snapshot = collector.get_snapshot();
        assert_eq!(snapshot.network.total_blocks, 5);
        assert_eq!(snapshot.network.total_transactions, 50);
    }

    #[test]
    fn test_shard_metrics_tracking() {
        let collector = MetricsCollector::new();
        let shard_id = ShardId::new(0).unwrap();
        let block = create_test_block(1, shard_id, 15);

        collector.record_block(&block).unwrap();

        let snapshot = collector.get_snapshot();
        assert_eq!(snapshot.shards.len(), 1);
        assert_eq!(snapshot.shards[0].shard_id, shard_id);
        assert_eq!(snapshot.shards[0].total_transactions, 15);
    }

    #[test]
    fn test_pq_crypto_metrics_from_block() {
        let collector = MetricsCollector::new();
        let block = create_test_block(1, ShardId::new(0).unwrap(), 10);

        collector.record_block(&block).unwrap();

        let snapshot = collector.get_snapshot();
        assert_eq!(snapshot.pq_crypto.total_dilithium_signatures, 5);
        assert_eq!(snapshot.pq_crypto.total_ed25519_signatures, 3);
        assert_eq!(snapshot.pq_crypto.total_hybrid_signatures, 2);
    }

    #[test]
    fn test_cellular_metrics_from_block() {
        let collector = MetricsCollector::new();
        let block = create_test_block(1, ShardId::new(0).unwrap(), 10);

        collector.record_block(&block).unwrap();

        let snapshot = collector.get_snapshot();
        assert_eq!(snapshot.cellular.cellular_safe_transactions, 10);
        assert_eq!(snapshot.cellular.wifi_only_transactions, 5);
        assert_eq!(snapshot.cellular.throttled_operations, 2);
    }

    #[test]
    fn test_deploy_metrics_initialization() {
        let metrics = DeployMetrics::default();
        assert_eq!(metrics.total_deploys, 0);
        assert_eq!(metrics.successful_deploys, 0);
        assert_eq!(metrics.rejected_deploys, 0);
        assert_eq!(metrics.bonds_collected, Balance::ZERO);
    }

    #[test]
    fn test_record_deploy_decision_accepted() {
        let collector = MetricsCollector::new();

        collector
            .record_deploy_decision(true, true, 0, 100, 5000, None)
            .unwrap();

        let snapshot = collector.get_snapshot();
        assert_eq!(snapshot.deploy.successful_deploys, 1);
        assert_eq!(snapshot.deploy.free_quota_deploys, 1);
        assert_eq!(snapshot.network.deploy_requests_accepted, 1);
    }

    #[test]
    fn test_record_deploy_decision_with_credits() {
        let collector = MetricsCollector::new();

        collector
            .record_deploy_decision(true, false, 1000, 200, 8000, None)
            .unwrap();

        let snapshot = collector.get_snapshot();
        assert_eq!(snapshot.deploy.credits_deploys, 1);
        assert_eq!(snapshot.deploy.total_credits_used, 1000);
        assert_eq!(snapshot.network.credits_consumed_total, 1000);
    }

    #[test]
    fn test_record_deploy_decision_rejected() {
        let collector = MetricsCollector::new();

        collector
            .record_deploy_decision(false, false, 0, 150, 6000, Some("spam detected"))
            .unwrap();

        let snapshot = collector.get_snapshot();
        assert_eq!(snapshot.deploy.rejected_deploys, 1);
        assert_eq!(snapshot.deploy.spam_rejected, 1);
        assert_eq!(snapshot.network.deploy_requests_rejected, 1);
    }

    #[test]
    fn test_record_deploy_ai_pattern() {
        let collector = MetricsCollector::new();

        collector
            .record_deploy_decision(false, false, 0, 100, 5000, Some("AI pattern detected"))
            .unwrap();

        let snapshot = collector.get_snapshot();
        assert_eq!(snapshot.deploy.ai_pattern_detected, 1);
    }

    #[test]
    fn test_record_deploy_duplicate() {
        let collector = MetricsCollector::new();

        collector
            .record_deploy_decision(false, false, 0, 100, 5000, Some("Duplicate contract"))
            .unwrap();

        let snapshot = collector.get_snapshot();
        assert_eq!(snapshot.deploy.duplicate_contracts_rejected, 1);
    }

    #[test]
    fn test_record_deploy_bond_collected() {
        let collector = MetricsCollector::new();
        let bond_amount = Balance::new(1000000);

        collector
            .record_deploy_bond_event(true, bond_amount)
            .unwrap();

        let snapshot = collector.get_snapshot();
        assert_eq!(snapshot.deploy.bonds_collected, bond_amount);
        assert_eq!(snapshot.network.deploy_bonds_collected, bond_amount);
    }

    #[test]
    fn test_record_deploy_bond_slashed() {
        let collector = MetricsCollector::new();
        let bond_amount = Balance::new(500000);

        collector
            .record_deploy_bond_event(false, bond_amount)
            .unwrap();

        let snapshot = collector.get_snapshot();
        assert_eq!(snapshot.deploy.bonds_slashed, bond_amount);
        assert_eq!(snapshot.network.deploy_bonds_slashed, bond_amount);
    }

    #[test]
    fn test_record_deploy_pob_burn() {
        let collector = MetricsCollector::new();

        collector.record_deploy_pob_burn(5000).unwrap();
        collector.record_deploy_pob_burn(3000).unwrap();

        let snapshot = collector.get_snapshot();
        assert_eq!(snapshot.deploy.total_pob_burned, 8000);
        assert_eq!(snapshot.network.pob_burns_total, 8000);
    }

    #[test]
    fn test_record_deploy_verification() {
        let collector = MetricsCollector::new();

        collector.record_deploy_verification(true, false).unwrap();
        collector.record_deploy_verification(false, true).unwrap();
        collector.record_deploy_verification(true, false).unwrap();

        let snapshot = collector.get_snapshot();
        assert_eq!(snapshot.deploy.human_verified, 2);
        assert_eq!(snapshot.deploy.ai_pattern_detected, 1);
    }

    #[test]
    fn test_calculate_deploy_health_score_high() {
        let mut deploy = DeployMetrics::default();
        deploy.total_deploys = 100;
        deploy.successful_deploys = 95;
        deploy.rejected_deploys = 5;
        deploy.ai_pattern_detected = 2;
        deploy.human_verified = 85;

        let score = calculate_deploy_health_score(&deploy);
        assert!(score > 80.0 && score <= 100.0);
    }

    #[test]
    fn test_record_proof_submission_post() {
        let collector = MetricsCollector::new();

        collector
            .record_proof_submission(ProofType::PoSt, 5000, true, false)
            .unwrap();

        let snapshot = collector.get_snapshot();
        assert_eq!(snapshot.proofs.len(), 1);
        assert_eq!(snapshot.proofs[0].total_submitted, 1);
        assert_eq!(snapshot.proofs[0].total_verified, 1);
        assert_eq!(snapshot.proofs[0].success_rate, 100.0);
    }

    #[test]
    fn test_record_proof_submission_failed() {
        let collector = MetricsCollector::new();

        collector
            .record_proof_submission(ProofType::PoRep, 12000, false, true)
            .unwrap();

        let snapshot = collector.get_snapshot();
        assert_eq!(snapshot.proofs[0].total_failed, 1);
        assert_eq!(snapshot.proofs[0].cellular_optimized_count, 1);
    }

    #[test]
    fn test_record_proof_submission_sla_compliance() {
        let collector = MetricsCollector::new();

        collector
            .record_proof_submission(ProofType::PoSt, 7000, true, false)
            .unwrap();
        collector
            .record_proof_submission(ProofType::PoSt, 9000, true, false)
            .unwrap();

        let snapshot = collector.get_snapshot();
        let proof = &snapshot.proofs[0];
        assert_eq!(proof.total_submitted, 2);
        assert!(proof.sla_compliance_rate > 0.0);
    }

    #[test]
    fn test_performance_tracker_basic() {
        let mut tracker = PerformanceTracker::new(100);

        tracker.start_timing("operation1");
        std::thread::sleep(std::time::Duration::from_millis(10));
        tracker.end_timing("operation1");

        let avg = tracker.avg_time("operation1").unwrap();
        assert!(avg.as_millis() >= 10);
    }

    #[test]
    fn test_performance_tracker_multiple_operations() {
        let mut tracker = PerformanceTracker::new(100);

        for _ in 0..5 {
            tracker.start_timing("fast_op");
            std::thread::sleep(std::time::Duration::from_millis(5));
            tracker.end_timing("fast_op");
        }

        let avg = tracker.avg_time("fast_op").unwrap();
        assert!(avg.as_millis() >= 5);
    }

    #[test]
    fn test_performance_tracker_percentiles() {
        let mut tracker = PerformanceTracker::new(100);

        for i in 1..=10 {
            tracker.record_duration("test_op", std::time::Duration::from_millis(i * 10));
        }

        let p50 = tracker.percentile_time("test_op", 50.0).unwrap();
        let p95 = tracker.percentile_time("test_op", 95.0).unwrap();

        assert!(p50.as_millis() > 0);
        assert!(p95.as_millis() > p50.as_millis());
    }

    #[test]
    fn test_performance_tracker_min_max() {
        let mut tracker = PerformanceTracker::new(100);

        tracker.record_duration("test", std::time::Duration::from_millis(10));
        tracker.record_duration("test", std::time::Duration::from_millis(50));
        tracker.record_duration("test", std::time::Duration::from_millis(30));

        let min = tracker.min_time("test").unwrap();
        let max = tracker.max_time("test").unwrap();

        assert_eq!(min.as_millis(), 10);
        assert_eq!(max.as_millis(), 50);
    }

    #[test]
    fn test_performance_tracker_summary() {
        let mut tracker = PerformanceTracker::new(100);

        tracker.record_duration("op1", std::time::Duration::from_millis(100));
        tracker.record_duration("op1", std::time::Duration::from_millis(200));

        let summary = tracker.summary();
        assert!(summary.contains_key("op1"));
        assert_eq!(summary.get("op1").unwrap().count, 2);
    }

    #[test]
    fn test_system_alerts_creation() {
        let mut alerts = SystemAlerts::new();

        let id = alerts.create_alert(
            AlertType::HighLatency,
            AlertSeverity::Warning,
            "Test alert".to_string(),
        );

        assert_eq!(alerts.active_alerts.len(), 1);
        assert_eq!(alerts.alert_history.len(), 1);
        assert!(!id.is_empty());
    }

    #[test]
    fn test_system_alerts_resolution() {
        let mut alerts = SystemAlerts::new();

        let id = alerts.create_alert(
            AlertType::PostProofFailure,
            AlertSeverity::Error,
            "PoSt failure".to_string(),
        );

        assert!(alerts.resolve_alert(&id));
        assert_eq!(alerts.active_alerts.len(), 0);
        assert!(alerts.alert_history[0].resolved);
    }

    #[test]
    fn test_system_alerts_with_metadata() {
        let mut alerts = SystemAlerts::new();
        let mut metadata = HashMap::new();
        metadata.insert("validator".to_string(), "addr123".to_string());

        let _id = alerts.create_alert_with_metadata(
            AlertType::ValidatorMissedBlocks,
            AlertSeverity::Warning,
            "Validator missed blocks".to_string(),
            metadata.clone(),
        );

        assert_eq!(alerts.active_alerts[0].metadata, metadata);
    }

    #[test]
    fn test_alerts_by_severity() {
        let mut alerts = SystemAlerts::new();

        alerts.create_alert(
            AlertType::HighLatency,
            AlertSeverity::Warning,
            "Warning 1".to_string(),
        );
        alerts.create_alert(
            AlertType::SystemOverload,
            AlertSeverity::Critical,
            "Critical 1".to_string(),
        );
        alerts.create_alert(
            AlertType::PostProofFailure,
            AlertSeverity::Warning,
            "Warning 2".to_string(),
        );

        let warnings = alerts.get_alerts_by_severity(AlertSeverity::Warning);
        let criticals = alerts.get_alerts_by_severity(AlertSeverity::Critical);

        assert_eq!(warnings.len(), 2);
        assert_eq!(criticals.len(), 1);
    }

    #[test]
    fn test_alerts_by_type() {
        let mut alerts = SystemAlerts::new();

        alerts.create_alert(
            AlertType::PostProofFailure,
            AlertSeverity::Error,
            "Failure 1".to_string(),
        );
        alerts.create_alert(
            AlertType::HighLatency,
            AlertSeverity::Warning,
            "Latency".to_string(),
        );
        alerts.create_alert(
            AlertType::PostProofFailure,
            AlertSeverity::Critical,
            "Failure 2".to_string(),
        );

        let post_failures = alerts.get_alerts_by_type(AlertType::PostProofFailure);

        assert_eq!(post_failures.len(), 2);
    }

    #[test]
    fn test_alert_stats() {
        let mut alerts = SystemAlerts::new();

        let id1 = alerts.create_alert(
            AlertType::HighLatency,
            AlertSeverity::Warning,
            "Alert 1".to_string(),
        );
        alerts.create_alert(
            AlertType::SystemOverload,
            AlertSeverity::Critical,
            "Alert 2".to_string(),
        );
        alerts.resolve_alert(&id1);

        let stats = alerts.get_alert_stats();

        assert_eq!(stats.total_alerts, 2);
        assert_eq!(stats.active_alerts, 1);
        assert_eq!(stats.resolved_alerts, 1);
        assert_eq!(stats.warning_alerts, 1);
        assert_eq!(stats.critical_alerts, 1);
    }

    #[test]
    fn test_calculate_network_health_score() {
        let snapshot = MetricsSnapshot {
            timestamp: NetworkMetrics::current_timestamp(),
            network: NetworkMetrics::default(),
            shards: vec![],
            validators: vec![],
            storage_providers: vec![],
            devices: vec![],
            proofs: vec![],
            drs_scores: vec![],
            rollups: vec![],
            pq_crypto: PQCryptoMetrics::default(),
            cellular: CellularMetrics::default(),
            epoch: EpochMetrics {
                epoch: 0,
                start_time: NetworkMetrics::current_timestamp(),
                end_time: None,
                blocks_produced: 0,
                transactions_processed: 0,
                total_ru_consumed: 0,
                validators_active: 0,
                storage_providers_active: 0,
                rewards_distributed: Balance::ZERO,
                slashing_penalties: Balance::ZERO,
                post_challenges_issued: 0,
                post_responses_received: 0,
                poc_events: 0,
                drs_updates: 0,
                cross_shard_receipts: 0,
                rollup_commits: 0,
                fraud_proofs: 0,
                epoch_finalized: false,
                deploys_submitted: 0,
                deploys_accepted: 0,
                deploys_rejected: 0,
            },
            performance: HashMap::new(),
            deploy: DeployMetrics::default(),
        };

        let score = calculate_network_health_score(&snapshot);
        assert!(score >= 0.0 && score <= 100.0);
    }

    #[test]
    fn test_calculate_cellular_efficiency() {
        let mut cellular = CellularMetrics::default();
        cellular.cellular_safe_transactions = 800;
        cellular.wifi_only_transactions = 200;
        cellular.total_cellular_data_gb = 10;

        let efficiency = calculate_cellular_efficiency(&cellular);
        assert!(efficiency > 0.0 && efficiency <= 100.0);
    }

    #[test]
    fn test_calculate_drs_aggregate_score() {
        let drs_metrics = vec![
            DRSMetrics {
                node_address: create_test_address(1),
                current_score: 0.85,
                current_multiplier: 1.1,
                uptime_score: 0.95,
                post_pass_rate: 0.98,
                post_latency_score: 0.90,
                poc_quality_score: 0.88,
                serve_ratio: 0.85,
                density_penalty: 0.1,
                last_update_epoch: 0,
                rewards_multiplier_applied: 10,
                score_history: vec![],
            },
            DRSMetrics {
                node_address: create_test_address(2),
                current_score: 0.75,
                current_multiplier: 1.0,
                uptime_score: 0.85,
                post_pass_rate: 0.92,
                post_latency_score: 0.80,
                poc_quality_score: 0.78,
                serve_ratio: 0.75,
                density_penalty: 0.15,
                last_update_epoch: 0,
                rewards_multiplier_applied: 8,
                score_history: vec![],
            },
        ];

        let aggregate = calculate_drs_aggregate_score(&drs_metrics);
        assert_eq!(aggregate, 0.8);
    }

    #[test]
    fn test_metrics_export_import() {
        let collector = MetricsCollector::new();
        collector
            .record_deploy_decision(true, true, 0, 100, 5000, None)
            .unwrap();

        let json = collector.export_metrics_json().unwrap();
        assert!(!json.is_empty());

        let new_collector = MetricsCollector::new();
        new_collector.import_metrics_json(&json).unwrap();

        let snapshot = new_collector.get_snapshot();
        assert_eq!(snapshot.deploy.successful_deploys, 1);
    }

    #[test]
    fn test_metrics_reset() {
        let collector = MetricsCollector::new();
        collector
            .record_deploy_decision(true, false, 1000, 100, 5000, None)
            .unwrap();

        collector.reset_metrics();

        let snapshot = collector.get_snapshot();
        assert_eq!(snapshot.deploy.total_deploys, 0);
        assert_eq!(snapshot.network.total_blocks, 0);
    }
}
