#[cfg(test)]
mod drs_tests {
    use ego_core::drs::*;
    use ego_core::{Account, Address, Balance, Hash, PublicKey, Timestamp};
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

    fn create_test_evidence(node_id: Address, epoch: u64) -> EvidenceBundle {
        EvidenceBundle {
            node_id,
            epoch,
            uptime_slots_seen: 900,
            uptime_slots_expected: 1000,
            post_challenges: 100,
            post_passes: 95,
            post_latency_sum_ms: 150000,
            post_latency_count: 95,
            poc_events: vec![],
            serve_bytes_ok: 1000000,
            serve_bytes_requested: 1100000,
            failed_post_count: 0,
            replay_or_incoherence_count: 0,
            equivocation_count: 0,
            density_data: None,
        }
    }

    fn create_test_poc_event(seed: u8) -> PoCEventData {
        PoCEventData {
            event_id: test_hash(seed),
            q_after_ldm: 0.9,
            witness_confidence: 0.95,
            h3_cell: format!("cell_{}", seed),
            timestamp: Timestamp::now(),
        }
    }

    #[test]
    fn test_drs_config_default() {
        let config = DRSConfig::default();

        assert_eq!(config.w_uptime, 0.20);
        assert_eq!(config.w_post_pass, 0.40);
        assert_eq!(config.w_inv_latency, 0.10);
        assert_eq!(config.w_poc, 0.20);
        assert_eq!(config.w_serve, 0.10);

        let weight_sum = config.w_uptime
            + config.w_post_pass
            + config.w_inv_latency
            + config.w_poc
            + config.w_serve;
        assert!((weight_sum - 1.0).abs() < 0.01);

        assert_eq!(config.a1_failed_post, 0.10);
        assert_eq!(config.a2_replay_incoherence, 0.20);
        assert_eq!(config.a3_equivocation, 0.40);
        assert_eq!(config.p_max, 0.5);

        assert_eq!(config.sla_ms, 600_000);
        assert_eq!(config.smoothing_alpha, 0.3);
        assert_eq!(config.multiplier_slope_beta, 0.6);
        assert_eq!(config.m_min, 0.7);
        assert_eq!(config.m_max, 1.3);
    }

    #[test]
    fn test_validate_drs_params_valid() {
        let config = DRSConfig::default();
        let result = validate_drs_params(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_drs_params_invalid_weights() {
        let mut config = DRSConfig::default();
        config.w_uptime = 0.5;
        config.w_post_pass = 0.5;
        config.w_inv_latency = 0.5;

        let result = validate_drs_params(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_drs_params_invalid_multiplier_range() {
        let mut config = DRSConfig::default();
        config.m_min = 1.5;
        config.m_max = 1.0;

        let result = validate_drs_params(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_drs_params_invalid_smoothing_alpha() {
        let mut config = DRSConfig::default();
        config.smoothing_alpha = 1.5;

        let result = validate_drs_params(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_drs_params_invalid_p_max() {
        let mut config = DRSConfig::default();
        config.p_max = 1.5;

        let result = validate_drs_params(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_drs_params_invalid_band_thresholds() {
        let mut config = DRSConfig::default();
        config.high_band_threshold = 0.5;
        config.mid_band_threshold = 0.8;

        let result = validate_drs_params(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_drs_manager_creation() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        assert_eq!(manager.get_current_epoch(), 0);
        assert_eq!(manager.get_weights_version(), DEFAULT_WEIGHTS_VERSION);
    }

    #[test]
    fn test_calculate_drs_score_basic() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(1);
        let evidence = create_test_evidence(node_id, 100);

        let result = manager.calculate_drs_score(evidence);
        assert!(result.is_ok());

        let score = result.unwrap();
        assert_eq!(score.node_id, node_id);
        assert_eq!(score.epoch, 100);
        assert!(score.score_raw >= 0.0 && score.score_raw <= 1.0);
        assert!(score.score_smoothed >= 0.0 && score.score_smoothed <= 1.0);
        assert!(score.multiplier >= 0.7 && score.multiplier <= 1.3);
    }

    #[test]
    fn test_calculate_components_perfect_score() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(2);
        let evidence = EvidenceBundle {
            node_id,
            epoch: 100,
            uptime_slots_seen: 1000,
            uptime_slots_expected: 1000,
            post_challenges: 100,
            post_passes: 100,
            post_latency_sum_ms: 100000,
            post_latency_count: 100,
            poc_events: vec![],
            serve_bytes_ok: 1000000,
            serve_bytes_requested: 1000000,
            failed_post_count: 0,
            replay_or_incoherence_count: 0,
            equivocation_count: 0,
            density_data: None,
        };

        let result = manager.calculate_drs_score(evidence);
        assert!(result.is_ok());

        let score = result.unwrap();
        assert_eq!(score.components.uptime, 1.0);
        assert_eq!(score.components.post_pass, 1.0);
        assert_eq!(score.components.serve_ratio, 1.0);
    }

    #[test]
    fn test_calculate_components_with_poc_events() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(3);
        let mut evidence = create_test_evidence(node_id, 100);
        evidence.poc_events = vec![
            create_test_poc_event(1),
            create_test_poc_event(2),
            create_test_poc_event(3),
        ];

        let result = manager.calculate_drs_score(evidence);
        assert!(result.is_ok());

        let score = result.unwrap();
        assert!(score.components.poc_quality > 0.0);
        assert!(score.components.poc_quality <= 1.0);
    }

    #[test]
    fn test_calculate_penalties_no_penalties() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(4);
        let evidence = create_test_evidence(node_id, 100);

        let result = manager.calculate_drs_score(evidence);
        assert!(result.is_ok());

        let score = result.unwrap();
        assert_eq!(score.penalties.failed_post, 0);
        assert_eq!(score.penalties.replay_or_incoherence, 0);
        assert_eq!(score.penalties.equivocation, 0);
        assert_eq!(score.penalties.total_penalty, 0.0);
    }

    #[test]
    fn test_calculate_penalties_with_violations() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config.clone());

        let node_id = test_address(5);
        let mut evidence = create_test_evidence(node_id, 100);
        evidence.failed_post_count = 5;
        evidence.replay_or_incoherence_count = 2;
        evidence.equivocation_count = 1;

        let result = manager.calculate_drs_score(evidence);
        assert!(result.is_ok());

        let score = result.unwrap();
        assert_eq!(score.penalties.failed_post, 5);
        assert_eq!(score.penalties.replay_or_incoherence, 2);
        assert_eq!(score.penalties.equivocation, 1);
        assert!(score.penalties.total_penalty > 0.0);

        let expected_penalty = (config.a1_failed_post * 5.0
            + config.a2_replay_incoherence * 2.0
            + config.a3_equivocation * 1.0)
            .min(config.p_max);
        assert!((score.penalties.total_penalty - expected_penalty).abs() < 0.001);
    }

    #[test]
    fn test_penalty_cap_at_p_max() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config.clone());

        let node_id = test_address(6);
        let mut evidence = create_test_evidence(node_id, 100);
        evidence.failed_post_count = 100;
        evidence.replay_or_incoherence_count = 100;
        evidence.equivocation_count = 100;

        let result = manager.calculate_drs_score(evidence);
        assert!(result.is_ok());

        let score = result.unwrap();
        assert!(score.penalties.total_penalty <= config.p_max);
    }

    #[test]
    fn test_smoothing_first_score() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(7);
        let evidence = create_test_evidence(node_id, 100);

        let result = manager.calculate_drs_score(evidence);
        assert!(result.is_ok());

        let score = result.unwrap();
        assert_eq!(score.score_raw, score.score_smoothed);
    }

    #[test]
    fn test_smoothing_subsequent_scores() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(8);
        let evidence1 = create_test_evidence(node_id, 100);
        manager.calculate_drs_score(evidence1).unwrap();

        let mut evidence2 = create_test_evidence(node_id, 101);
        evidence2.post_passes = 50;

        let result = manager.calculate_drs_score(evidence2);
        assert!(result.is_ok());

        let score2 = result.unwrap();
        assert_ne!(score2.score_raw, score2.score_smoothed);
    }

    #[test]
    fn test_calculate_multiplier() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config.clone());

        let node_id = test_address(9);
        let evidence = create_test_evidence(node_id, 100);

        let result = manager.calculate_drs_score(evidence);
        assert!(result.is_ok());

        let score = result.unwrap();
        assert!(score.multiplier >= config.m_min);
        assert!(score.multiplier <= config.m_max);

        let expected_multiplier =
            BASELINE_MULTIPLIER + config.multiplier_slope_beta * (score.score_smoothed - 0.5);
        let expected_clamped = expected_multiplier.clamp(config.m_min, config.m_max);
        assert!((score.multiplier - expected_clamped).abs() < 0.001);
    }

    #[test]
    fn test_determine_quota_band_high() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(10);
        let evidence = EvidenceBundle {
            node_id,
            epoch: 100,
            uptime_slots_seen: 1000,
            uptime_slots_expected: 1000,
            post_challenges: 100,
            post_passes: 100,
            post_latency_sum_ms: 10000,
            post_latency_count: 100,
            poc_events: vec![PoCEventData {
                event_id: test_hash(1),
                q_after_ldm: 0.95,
                witness_confidence: 1.0,
                h3_cell: "cell_1".to_string(),
                timestamp: Timestamp::now(),
            }],
            serve_bytes_ok: 1000000,
            serve_bytes_requested: 1000000,
            failed_post_count: 0,
            replay_or_incoherence_count: 0,
            equivocation_count: 0,
            density_data: None,
        };

        let result = manager.calculate_drs_score(evidence);
        assert!(result.is_ok());

        let score = result.unwrap();
        assert_eq!(score.quota_band, QuotaBand::High);
    }

    #[test]
    fn test_determine_quota_band_mid() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(11);
        let evidence = EvidenceBundle {
            node_id,
            epoch: 100,
            uptime_slots_seen: 700,
            uptime_slots_expected: 1000,
            post_challenges: 100,
            post_passes: 70,
            post_latency_sum_ms: 200000,
            post_latency_count: 70,
            poc_events: vec![],
            serve_bytes_ok: 700000,
            serve_bytes_requested: 1000000,
            failed_post_count: 0,
            replay_or_incoherence_count: 0,
            equivocation_count: 0,
            density_data: None,
        };

        let result = manager.calculate_drs_score(evidence);
        assert!(result.is_ok());

        let score = result.unwrap();
        assert_eq!(score.quota_band, QuotaBand::Mid);
    }

    #[test]
    fn test_determine_quota_band_low() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(12);
        let evidence = EvidenceBundle {
            node_id,
            epoch: 100,
            uptime_slots_seen: 400,
            uptime_slots_expected: 1000,
            post_challenges: 100,
            post_passes: 40,
            post_latency_sum_ms: 300000,
            post_latency_count: 40,
            poc_events: vec![],
            serve_bytes_ok: 400000,
            serve_bytes_requested: 1000000,
            failed_post_count: 5,
            replay_or_incoherence_count: 2,
            equivocation_count: 0,
            density_data: None,
        };

        let result = manager.calculate_drs_score(evidence);
        assert!(result.is_ok());

        let score = result.unwrap();
        assert_eq!(score.quota_band, QuotaBand::Low);
    }

    #[test]
    fn test_get_node_score() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(13);
        let evidence = create_test_evidence(node_id, 100);

        manager.calculate_drs_score(evidence).unwrap();

        let retrieved = manager.get_node_score(&node_id);
        assert!(retrieved.is_some());

        let score = retrieved.unwrap();
        assert_eq!(score.node_id, node_id);
        assert_eq!(score.epoch, 100);
    }

    #[test]
    fn test_get_node_multiplier() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(14);
        let evidence = create_test_evidence(node_id, 100);

        manager.calculate_drs_score(evidence).unwrap();

        let multiplier = manager.get_node_multiplier(&node_id);
        assert!(multiplier >= 0.7 && multiplier <= 1.3);
    }

    #[test]
    fn test_get_node_multiplier_default() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(15);
        let multiplier = manager.get_node_multiplier(&node_id);
        assert_eq!(multiplier, BASELINE_MULTIPLIER);
    }

    #[test]
    fn test_historical_scores() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(16);

        for epoch in 100..110 {
            let evidence = create_test_evidence(node_id, epoch);
            manager.calculate_drs_score(evidence).unwrap();
        }

        let history = manager.get_historical_scores(&node_id);
        assert_eq!(history.len(), 10);

        for (i, score) in history.iter().enumerate() {
            assert_eq!(score.epoch, 100 + i as u64);
        }
    }

    #[test]
    fn test_historical_scores_window_limit() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(17);

        for epoch in 100..120 {
            let evidence = create_test_evidence(node_id, epoch);
            manager.calculate_drs_score(evidence).unwrap();
        }

        let history = manager.get_historical_scores(&node_id);
        assert!(history.len() <= SMOOTHING_WINDOW_EPOCHS);
    }

    #[test]
    fn test_calculate_location_density_multiplier_single_device() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let density_data = DensityData {
            h3_cell: "cell_test".to_string(),
            device_count: 1,
            dwell_time_pct: 0.5,
            witnesses: vec![test_address(20)],
            vertical_separation_m: None,
        };

        let ldm = manager.calculate_location_density_multiplier(&density_data);
        assert_eq!(ldm, 1.0);
    }

    #[test]
    fn test_calculate_location_density_multiplier_multiple_devices() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config.clone());

        let density_data = DensityData {
            h3_cell: "cell_test".to_string(),
            device_count: 5,
            dwell_time_pct: 0.5,
            witnesses: vec![
                test_address(20),
                test_address(21),
                test_address(22),
                test_address(23),
                test_address(24),
            ],
            vertical_separation_m: None,
        };

        let ldm = manager.calculate_location_density_multiplier(&density_data);
        assert!(ldm < 1.0);
        assert!(ldm >= config.density_min_multiplier);

        let expected_penalty = config.density_penalty_rate * 4.0;
        let expected_ldm = (1.0_f64 - expected_penalty).max(config.density_min_multiplier);
        assert!((ldm - expected_ldm).abs() < 0.001);
    }

    #[test]
    fn test_calculate_location_density_multiplier_low_dwell_time() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let density_data = DensityData {
            h3_cell: "cell_test".to_string(),
            device_count: 5,
            dwell_time_pct: 0.05,
            witnesses: vec![],
            vertical_separation_m: None,
        };

        let ldm = manager.calculate_location_density_multiplier(&density_data);
        assert_eq!(ldm, 1.0);
    }

    #[test]
    fn test_apply_density_penalty() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let base_score = 0.9;

        let density_data = DensityData {
            h3_cell: "cell_test".to_string(),
            device_count: 3,
            dwell_time_pct: 0.6,
            witnesses: vec![test_address(30), test_address(31), test_address(32)],
            vertical_separation_m: Some(10.0),
        };

        let adjusted_score = manager.apply_density_penalty(base_score, Some(&density_data));
        assert!(adjusted_score < base_score);
    }

    #[test]
    fn test_apply_density_penalty_none() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let base_score = 0.9;
        let adjusted_score = manager.apply_density_penalty(base_score, None);
        assert_eq!(adjusted_score, base_score);
    }

    #[test]
    fn test_finalize_epoch_empty() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let result = manager.finalize_epoch(100);
        assert!(result.is_ok());

        let stats = result.unwrap();
        assert_eq!(stats.epoch, 100);
        assert_eq!(stats.total_nodes, 0);
        assert_eq!(stats.avg_score, 0.0);
    }

    #[test]
    fn test_finalize_epoch_with_scores() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        for i in 0..10 {
            let node_id = test_address(i);
            let evidence = create_test_evidence(node_id, 100);
            manager.calculate_drs_score(evidence).unwrap();
        }

        let result = manager.finalize_epoch(100);
        assert!(result.is_ok());

        let stats = result.unwrap();
        assert_eq!(stats.epoch, 100);
        assert_eq!(stats.total_nodes, 10);
        assert!(stats.avg_score > 0.0);
        assert!(stats.median_score > 0.0);
        assert!(stats.std_dev >= 0.0);
        assert_eq!(stats.score_distribution.len(), 10);
    }

    #[test]
    fn test_finalize_epoch_top_performers() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        for i in 0..20 {
            let node_id = test_address(i);
            let mut evidence = create_test_evidence(node_id, 100);
            evidence.post_passes = 90 + i as u64 / 2;
            manager.calculate_drs_score(evidence).unwrap();
        }

        let result = manager.finalize_epoch(100);
        assert!(result.is_ok());

        let stats = result.unwrap();
        assert!(!stats.top_performers.is_empty());
        assert!(stats.top_performers.len() <= (stats.total_nodes as f64 * 0.1).max(1.0) as usize);
    }

    #[test]
    fn test_finalize_epoch_penalized_nodes() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        for i in 0..10 {
            let node_id = test_address(i);
            let mut evidence = create_test_evidence(node_id, 100);
            if i < 3 {
                evidence.failed_post_count = 5;
            }
            manager.calculate_drs_score(evidence).unwrap();
        }

        let result = manager.finalize_epoch(100);
        assert!(result.is_ok());

        let stats = result.unwrap();
        assert_eq!(stats.penalized_nodes.len(), 3);
    }

    #[test]
    fn test_apply_reward_multiplier() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(40);
        let evidence = create_test_evidence(node_id, 100);
        manager.calculate_drs_score(evidence).unwrap();

        let base_storage = Balance::new(1000);
        let base_consensus = Balance::new(500);
        let base_coverage = Balance::new(250);

        let result = manager.apply_reward_multiplier(
            &node_id,
            base_storage,
            base_consensus,
            base_coverage,
            100,
        );
        assert!(result.is_ok());

        let distribution = result.unwrap();
        assert_eq!(distribution.node_id, node_id);
        assert_eq!(distribution.epoch, 100);
        assert_eq!(distribution.base_storage_reward, base_storage);
        assert_eq!(distribution.base_consensus_reward, base_consensus);
        assert_eq!(distribution.base_coverage_reward, base_coverage);
        assert!(distribution.drs_multiplier > 0.0);
    }

    #[test]
    fn test_apply_reward_multiplier_high_score() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(41);
        let evidence = EvidenceBundle {
            node_id,
            epoch: 100,
            uptime_slots_seen: 1000,
            uptime_slots_expected: 1000,
            post_challenges: 100,
            post_passes: 100,
            post_latency_sum_ms: 50000,
            post_latency_count: 100,
            poc_events: vec![],
            serve_bytes_ok: 1000000,
            serve_bytes_requested: 1000000,
            failed_post_count: 0,
            replay_or_incoherence_count: 0,
            equivocation_count: 0,
            density_data: None,
        };
        manager.calculate_drs_score(evidence).unwrap();

        let base_reward = Balance::new(1000);
        let result = manager.apply_reward_multiplier(
            &node_id,
            base_reward,
            Balance::ZERO,
            Balance::ZERO,
            100,
        );
        assert!(result.is_ok());

        let distribution = result.unwrap();
        assert!(distribution.final_storage_reward >= base_reward);
    }

    #[test]
    fn test_get_quota_allocation_high_band() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(42);
        let evidence = EvidenceBundle {
            node_id,
            epoch: 100,
            uptime_slots_seen: 1000,
            uptime_slots_expected: 1000,
            post_challenges: 100,
            post_passes: 100,
            post_latency_sum_ms: 10000,
            post_latency_count: 100,
            poc_events: vec![PoCEventData {
                event_id: test_hash(1),
                q_after_ldm: 0.95,
                witness_confidence: 1.0,
                h3_cell: "cell_1".to_string(),
                timestamp: Timestamp::now(),
            }],
            serve_bytes_ok: 1000000,
            serve_bytes_requested: 1000000,
            failed_post_count: 0,
            replay_or_incoherence_count: 0,
            equivocation_count: 0,
            density_data: None,
        };
        manager.calculate_drs_score(evidence).unwrap();

        let allocation = manager.get_quota_allocation(&node_id);
        assert_eq!(allocation.node_id, node_id);
        assert_eq!(allocation.quota_band, QuotaBand::High);
        assert_eq!(allocation.ru_limit, 10_000_000);
        assert_eq!(allocation.proof_batch_size, 500);
        assert_eq!(allocation.audit_frequency, 100);
        assert_eq!(allocation.publish_rate_limit, 1000);
    }

    #[test]
    fn test_get_quota_allocation_mid_band() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(43);
        let evidence = EvidenceBundle {
            node_id,
            epoch: 100,
            uptime_slots_seen: 700,
            uptime_slots_expected: 1000,
            post_challenges: 100,
            post_passes: 70,
            post_latency_sum_ms: 200000,
            post_latency_count: 70,
            poc_events: vec![],
            serve_bytes_ok: 700000,
            serve_bytes_requested: 1000000,
            failed_post_count: 0,
            replay_or_incoherence_count: 0,
            equivocation_count: 0,
            density_data: None,
        };
        manager.calculate_drs_score(evidence).unwrap();

        let allocation = manager.get_quota_allocation(&node_id);
        assert_eq!(allocation.quota_band, QuotaBand::Mid);
        assert_eq!(allocation.ru_limit, 5_000_000);
        assert_eq!(allocation.proof_batch_size, 250);
    }

    #[test]
    fn test_get_quota_allocation_low_band() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(44);
        let evidence = EvidenceBundle {
            node_id,
            epoch: 100,
            uptime_slots_seen: 400,
            uptime_slots_expected: 1000,
            post_challenges: 100,
            post_passes: 40,
            post_latency_sum_ms: 300000,
            post_latency_count: 40,
            poc_events: vec![],
            serve_bytes_ok: 400000,
            serve_bytes_requested: 1000000,
            failed_post_count: 5,
            replay_or_incoherence_count: 2,
            equivocation_count: 0,
            density_data: None,
        };
        manager.calculate_drs_score(evidence).unwrap();

        let allocation = manager.get_quota_allocation(&node_id);
        assert_eq!(allocation.quota_band, QuotaBand::Low);
        assert_eq!(allocation.ru_limit, 2_000_000);
        assert_eq!(allocation.proof_batch_size, 100);
    }

    #[test]
    fn test_get_quota_allocation_default() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(45);
        let allocation = manager.get_quota_allocation(&node_id);
        assert_eq!(allocation.quota_band, QuotaBand::Low);
    }

    #[test]
    fn test_qualifies_for_operation() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(46);
        let evidence = create_test_evidence(node_id, 100);
        manager.calculate_drs_score(evidence).unwrap();

        let qualifies_low = manager.qualifies_for_operation(&node_id, 0.5);
        assert!(qualifies_low);

        let qualifies_high = manager.qualifies_for_operation(&node_id, 0.99);
        assert!(!qualifies_high);
    }

    #[test]
    fn test_qualifies_for_operation_no_score() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(47);
        let qualifies = manager.qualifies_for_operation(&node_id, 0.5);
        assert!(!qualifies);
    }

    #[test]
    fn test_update_config() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let initial_version = manager.get_weights_version();
        let initial_digest = manager.get_params_digest();

        let mut new_config = DRSConfig::default();
        new_config.w_uptime = 0.25;
        new_config.w_post_pass = 0.35;

        let result = manager.update_config(new_config.clone());
        assert!(result.is_ok());

        let updated_config = manager.get_config();
        assert_eq!(updated_config.w_uptime, 0.25);
        assert_eq!(updated_config.w_post_pass, 0.35);

        let new_version = manager.get_weights_version();
        assert_eq!(new_version, initial_version + 1);

        let new_digest = manager.get_params_digest();
        assert_ne!(new_digest, initial_digest);
    }

    #[test]
    fn test_update_config_invalid() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let mut invalid_config = DRSConfig::default();
        invalid_config.w_uptime = 0.8;
        invalid_config.w_post_pass = 0.8;

        let result = manager.update_config(invalid_config);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_epoch_stats() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        for i in 0..5 {
            let node_id = test_address(i);
            let evidence = create_test_evidence(node_id, 100);
            manager.calculate_drs_score(evidence).unwrap();
        }

        manager.finalize_epoch(100).unwrap();

        let stats = manager.get_epoch_stats(100);
        assert!(stats.is_some());

        let stats = stats.unwrap();
        assert_eq!(stats.epoch, 100);
        assert_eq!(stats.total_nodes, 5);
    }

    #[test]
    fn test_get_epoch_stats_nonexistent() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let stats = manager.get_epoch_stats(999);
        assert!(stats.is_none());
    }

    #[test]
    fn test_get_all_nodes_in_epoch() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        for i in 0..5 {
            let node_id = test_address(i);
            let evidence = create_test_evidence(node_id, 100);
            manager.calculate_drs_score(evidence).unwrap();
        }

        for i in 10..15 {
            let node_id = test_address(i);
            let evidence = create_test_evidence(node_id, 101);
            manager.calculate_drs_score(evidence).unwrap();
        }

        let nodes_epoch_100 = manager.get_all_nodes_in_epoch(100);
        assert_eq!(nodes_epoch_100.len(), 5);

        let nodes_epoch_101 = manager.get_all_nodes_in_epoch(101);
        assert_eq!(nodes_epoch_101.len(), 5);
    }

    #[test]
    fn test_get_nodes_by_quota_band() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        for i in 0..3 {
            let node_id = test_address(i);
            let evidence = EvidenceBundle {
                node_id,
                epoch: 100,
                uptime_slots_seen: 1000,
                uptime_slots_expected: 1000,
                post_challenges: 100,
                post_passes: 100,
                post_latency_sum_ms: 10000,
                post_latency_count: 100,
                poc_events: vec![PoCEventData {
                    event_id: test_hash(i),
                    q_after_ldm: 0.95,
                    witness_confidence: 1.0,
                    h3_cell: format!("cell_{}", i),
                    timestamp: Timestamp::now(),
                }],
                serve_bytes_ok: 1000000,
                serve_bytes_requested: 1000000,
                failed_post_count: 0,
                replay_or_incoherence_count: 0,
                equivocation_count: 0,
                density_data: None,
            };
            manager.calculate_drs_score(evidence).unwrap();
        }

        for i in 10..13 {
            let node_id = test_address(i);
            let evidence = EvidenceBundle {
                node_id,
                epoch: 100,
                uptime_slots_seen: 400,
                uptime_slots_expected: 1000,
                post_challenges: 100,
                post_passes: 40,
                post_latency_sum_ms: 300000,
                post_latency_count: 40,
                poc_events: vec![],
                serve_bytes_ok: 400000,
                serve_bytes_requested: 1000000,
                failed_post_count: 5,
                replay_or_incoherence_count: 0,
                equivocation_count: 0,
                density_data: None,
            };
            manager.calculate_drs_score(evidence).unwrap();
        }

        let high_band_nodes = manager.get_nodes_by_quota_band(QuotaBand::High);
        assert_eq!(high_band_nodes.len(), 3);

        let low_band_nodes = manager.get_nodes_by_quota_band(QuotaBand::Low);
        assert_eq!(low_band_nodes.len(), 3);
    }

    #[test]
    fn test_get_nodes_requiring_audit() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        for i in 0..10 {
            let node_id = test_address(i);
            let mut evidence = create_test_evidence(node_id, 100);
            if i < 3 {
                evidence.post_passes = 30;
                evidence.failed_post_count = 10;
            }
            manager.calculate_drs_score(evidence).unwrap();
        }

        let nodes_requiring_audit = manager.get_nodes_requiring_audit(0.7);
        assert!(nodes_requiring_audit.len() >= 3);
    }

    #[test]
    fn test_calculate_aggregate_stats() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        for i in 0..10 {
            let node_id = test_address(i);
            let evidence = create_test_evidence(node_id, 100);
            manager.calculate_drs_score(evidence).unwrap();
        }

        let result = manager.calculate_aggregate_stats(100);
        assert!(result.is_ok());

        let stats = result.unwrap();
        assert_eq!(stats.epoch, 100);
        assert_eq!(stats.total_nodes, 10);
        assert!(stats.avg_uptime > 0.0);
        assert!(stats.avg_post_pass > 0.0);
        assert!(stats.avg_poc_quality >= 0.0);
        assert!(stats.avg_serve_ratio > 0.0);
    }

    #[test]
    fn test_calculate_aggregate_stats_empty() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let result = manager.calculate_aggregate_stats(100);
        assert!(result.is_ok());

        let stats = result.unwrap();
        assert_eq!(stats.total_nodes, 0);
    }

    #[test]
    fn test_get_evidence_bundle() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(50);
        let evidence = create_test_evidence(node_id, 100);
        let score = manager.calculate_drs_score(evidence.clone()).unwrap();

        let retrieved = manager.get_evidence_bundle(&score.evidence_root);
        assert!(retrieved.is_some());

        let retrieved_evidence = retrieved.unwrap();
        assert_eq!(retrieved_evidence.node_id, node_id);
        assert_eq!(retrieved_evidence.epoch, 100);
    }

    #[test]
    fn test_get_evidence_bundle_nonexistent() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let fake_hash = test_hash(99);
        let retrieved = manager.get_evidence_bundle(&fake_hash);
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_prune_old_data() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        for epoch in 100..120 {
            for i in 0..5 {
                let node_id = test_address(i);
                let evidence = create_test_evidence(node_id, epoch);
                manager.calculate_drs_score(evidence).unwrap();
            }
            manager.finalize_epoch(epoch).unwrap();
        }

        let pruned = manager.prune_old_data(10, 120);
        assert!(pruned > 0);

        let old_stats = manager.get_epoch_stats(100);
        assert!(old_stats.is_none());

        let recent_stats = manager.get_epoch_stats(115);
        assert!(recent_stats.is_some());
    }

    #[test]
    fn test_export_scores_for_epoch() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        for i in 0..5 {
            let node_id = test_address(i);
            let evidence = create_test_evidence(node_id, 100);
            manager.calculate_drs_score(evidence).unwrap();
        }

        let exported = manager.export_scores_for_epoch(100);
        assert_eq!(exported.len(), 5);

        for (_node_id, score, multiplier) in exported {
            assert!(score >= 0.0 && score <= 1.0);
            assert!(multiplier >= 0.7 && multiplier <= 1.3);
        }
    }

    #[test]
    fn test_import_score() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config.clone());

        let node_id = test_address(60);
        let evidence = create_test_evidence(node_id, 100);
        let score = manager.calculate_drs_score(evidence).unwrap();

        let new_manager = DRSManager::new(config);
        let result = new_manager.import_score(score.clone());
        assert!(result.is_ok());

        let retrieved = new_manager.get_node_score(&node_id);
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_import_score_digest_mismatch() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(61);
        let evidence = create_test_evidence(node_id, 100);
        let mut score = manager.calculate_drs_score(evidence).unwrap();

        score.params_digest = test_hash(99);

        let result = manager.import_score(score);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_score_consistency() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(62);
        for epoch in 100..110 {
            let evidence = create_test_evidence(node_id, epoch);
            manager.calculate_drs_score(evidence).unwrap();
        }

        let epochs: Vec<u64> = (100..110).collect();
        let is_consistent = manager.validate_score_consistency(&node_id, &epochs);
        assert!(is_consistent);
    }

    #[test]
    fn test_validate_score_consistency_inconsistent() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(63);
        for epoch in 100..110 {
            let mut evidence = create_test_evidence(node_id, epoch);
            if epoch == 105 {
                evidence.post_passes = 10;
                evidence.uptime_slots_seen = 100;
                evidence.failed_post_count = 50;
            }
            manager.calculate_drs_score(evidence).unwrap();
        }

        let epochs: Vec<u64> = (100..110).collect();
        let is_consistent = manager.validate_score_consistency(&node_id, &epochs);
        assert!(!is_consistent);
    }

    #[test]
    fn test_detect_anomalies_equivocation() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(64);
        let mut evidence = create_test_evidence(node_id, 100);
        evidence.equivocation_count = 5;
        manager.calculate_drs_score(evidence).unwrap();

        let anomalies = manager.detect_anomalies(&node_id);
        assert!(!anomalies.is_empty());
        assert!(anomalies
            .iter()
            .any(|a| a.anomaly_type == AnomalyType::Equivocation));
    }

    #[test]
    fn test_detect_anomalies_low_post_pass() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(65);
        let mut evidence = create_test_evidence(node_id, 100);
        evidence.post_passes = 30;
        manager.calculate_drs_score(evidence).unwrap();

        let anomalies = manager.detect_anomalies(&node_id);
        assert!(!anomalies.is_empty());
        assert!(anomalies
            .iter()
            .any(|a| a.anomaly_type == AnomalyType::LowPostPass));
    }

    #[test]
    fn test_detect_anomalies_low_uptime() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(66);
        let mut evidence = create_test_evidence(node_id, 100);
        evidence.uptime_slots_seen = 600;
        manager.calculate_drs_score(evidence).unwrap();

        let anomalies = manager.detect_anomalies(&node_id);
        assert!(!anomalies.is_empty());
        assert!(anomalies
            .iter()
            .any(|a| a.anomaly_type == AnomalyType::LowUptime));
    }

    #[test]
    fn test_detect_anomalies_replay_attack() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(67);
        let mut evidence = create_test_evidence(node_id, 100);
        evidence.replay_or_incoherence_count = 10;
        manager.calculate_drs_score(evidence).unwrap();

        let anomalies = manager.detect_anomalies(&node_id);
        assert!(!anomalies.is_empty());
        assert!(anomalies
            .iter()
            .any(|a| a.anomaly_type == AnomalyType::ReplayAttack));
    }

    #[test]
    fn test_detect_anomalies_none() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(68);
        let evidence = EvidenceBundle {
            node_id,
            epoch: 100,
            uptime_slots_seen: 1000,
            uptime_slots_expected: 1000,
            post_challenges: 100,
            post_passes: 100,
            post_latency_sum_ms: 50000,
            post_latency_count: 100,
            poc_events: vec![],
            serve_bytes_ok: 1000000,
            serve_bytes_requested: 1000000,
            failed_post_count: 0,
            replay_or_incoherence_count: 0,
            equivocation_count: 0,
            density_data: None,
        };
        manager.calculate_drs_score(evidence).unwrap();

        let anomalies = manager.detect_anomalies(&node_id);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn test_generate_performance_report() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(69);
        for epoch in 100..110 {
            let evidence = create_test_evidence(node_id, epoch);
            manager.calculate_drs_score(evidence).unwrap();
        }

        let report = manager.generate_performance_report(&node_id, 10);
        assert_eq!(report.node_id, node_id);
        assert_eq!(report.epochs_analyzed, 10);
        assert!(report.avg_score > 0.0);
        assert!(report.avg_multiplier > 0.0);
    }

    #[test]
    fn test_generate_performance_report_no_history() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(70);
        let report = manager.generate_performance_report(&node_id, 10);
        assert_eq!(report.epochs_analyzed, 0);
        assert_eq!(report.avg_score, 0.0);
    }

    #[test]
    fn test_generate_performance_report_trends() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(71);
        for epoch in 100..110 {
            let mut evidence = create_test_evidence(node_id, epoch);
            evidence.post_passes = 80 + epoch - 100;
            manager.calculate_drs_score(evidence).unwrap();
        }

        let report = manager.generate_performance_report(&node_id, 10);
        assert!(report.score_trend != 0.0);
    }

    #[test]
    fn test_create_evidence_bundle_from_account() {
        let address = test_address(72);
        let provider_id = "provider_test".to_string();
        let region = "test_region".to_string();
        let storage_capacity = 1_000_000_000;
        let dilithium_pk = vec![1u8; 1312];
        let mlkem_pk = vec![2u8; 1184];
        let peer_id = "QmTest".to_string();

        let account = Account::new_storage_provider(
            address,
            provider_id,
            region,
            storage_capacity,
            dilithium_pk,
            mlkem_pk,
            peer_id,
        );

        let poc_events = vec![create_test_poc_event(1)];
        let evidence = create_evidence_bundle_from_account(&account, 100, poc_events, None);

        assert_eq!(evidence.node_id, address);
        assert_eq!(evidence.epoch, 100);
        assert!(evidence.uptime_slots_expected > 0);
    }

    #[test]
    fn test_apply_drs_to_rewards() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let mut node_rewards = Vec::new();
        for i in 0..5 {
            let node_id = test_address(i);
            let evidence = create_test_evidence(node_id, 100);
            manager.calculate_drs_score(evidence).unwrap();

            node_rewards.push((
                node_id,
                Balance::new(1000),
                Balance::new(500),
                Balance::new(250),
            ));
        }

        let result = apply_drs_to_rewards(&manager, node_rewards, 100);
        assert!(result.is_ok());

        let distributions = result.unwrap();
        assert_eq!(distributions.len(), 5);

        for distribution in distributions {
            assert!(distribution.total_reward > Balance::ZERO);
        }
    }

    #[test]
    fn test_calculate_epoch_drs_scores() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let mut evidence_bundles = Vec::new();
        for i in 0..5 {
            let node_id = test_address(i);
            let evidence = create_test_evidence(node_id, 100);
            evidence_bundles.push(evidence);
        }

        let result = calculate_epoch_drs_scores(&manager, evidence_bundles);
        assert!(result.is_ok());

        let scores = result.unwrap();
        assert_eq!(scores.len(), 5);
    }

    #[test]
    fn test_calculate_bucket_rewards() {
        let total_emission = Balance::new(10000);
        let (storage, consensus, coverage) =
            calculate_bucket_rewards(total_emission, 0.5, 0.3, 0.2);

        assert_eq!(storage, Balance::new(5000));
        assert_eq!(consensus, Balance::new(3000));
        assert_eq!(coverage, Balance::new(2000));
    }

    #[test]
    fn test_distribute_rewards_with_drs() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let mut nodes = Vec::new();
        let mut base_shares = Vec::new();

        for i in 0..5 {
            let node_id = test_address(i);
            let evidence = create_test_evidence(node_id, 100);
            manager.calculate_drs_score(evidence).unwrap();

            nodes.push(node_id);
            base_shares.push((node_id, 0.2, 0.2, 0.2));
        }

        let result = distribute_rewards_with_drs(
            &manager,
            nodes,
            Balance::new(5000),
            Balance::new(3000),
            Balance::new(2000),
            100,
            &base_shares,
        );

        assert!(result.is_ok());
        let distributions = result.unwrap();
        assert_eq!(distributions.len(), 5);

        let total_distributed: u128 = distributions.iter().map(|d| d.total_reward.as_u128()).sum();
        assert!(total_distributed <= 10000);
    }

    #[test]
    fn test_apply_density_to_poc_quality() {
        let base_q = 0.9;
        let adjusted = apply_density_to_poc_quality(base_q, 1, 0.5, 0.10, 0.40);
        assert_eq!(adjusted, base_q);

        let adjusted_multiple = apply_density_to_poc_quality(base_q, 5, 0.5, 0.10, 0.40);
        assert!(adjusted_multiple < base_q);

        let adjusted_low_dwell = apply_density_to_poc_quality(base_q, 5, 0.05, 0.10, 0.40);
        assert_eq!(adjusted_low_dwell, base_q);
    }

    #[test]
    fn test_quota_band_equality() {
        assert_eq!(QuotaBand::High, QuotaBand::High);
        assert_ne!(QuotaBand::High, QuotaBand::Mid);
        assert_ne!(QuotaBand::Mid, QuotaBand::Low);
    }

    #[test]
    fn test_quota_band_default() {
        let band = QuotaBand::default();
        assert_eq!(band, QuotaBand::Low);
    }

    #[test]
    fn test_anomaly_type_equality() {
        assert_eq!(AnomalyType::Equivocation, AnomalyType::Equivocation);
        assert_ne!(AnomalyType::Equivocation, AnomalyType::LowPostPass);
    }

    #[test]
    fn test_severity_levels() {
        assert_eq!(Severity::Critical, Severity::Critical);
        assert_ne!(Severity::Critical, Severity::High);
        assert_ne!(Severity::High, Severity::Medium);
        assert_ne!(Severity::Medium, Severity::Low);
    }

    #[test]
    fn test_aggregate_stats_default() {
        let stats = AggregateStats::default();
        assert_eq!(stats.total_nodes, 0);
        assert_eq!(stats.avg_post_pass, 0.0);
    }

    #[test]
    fn test_performance_report_default() {
        let report = PerformanceReport::default();
        assert_eq!(report.epochs_analyzed, 0);
        assert_eq!(report.avg_score, 0.0);
        assert_eq!(report.current_quota_band, QuotaBand::Low);
    }

    #[test]
    fn test_evidence_bundle_serialization() {
        let node_id = test_address(80);
        let evidence = create_test_evidence(node_id, 100);

        let config = bincode::config::standard();
        let encoded = bincode::encode_to_vec(&evidence, config);
        assert!(encoded.is_ok());

        let decoded: Result<EvidenceBundle, _> =
            bincode::decode_from_slice(&encoded.unwrap(), config).map(|(e, _)| e);
        assert!(decoded.is_ok());

        let decoded_evidence = decoded.unwrap();
        assert_eq!(decoded_evidence.node_id, node_id);
        assert_eq!(decoded_evidence.epoch, 100);
    }

    #[test]
    fn test_drs_score_serialization() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(81);
        let evidence = create_test_evidence(node_id, 100);
        let score = manager.calculate_drs_score(evidence).unwrap();

        let bincode_config = bincode::config::standard();
        let encoded = bincode::encode_to_vec(&score, bincode_config);
        assert!(encoded.is_ok());

        let decoded: Result<DRSScore, _> =
            bincode::decode_from_slice(&encoded.unwrap(), bincode_config).map(|(s, _)| s);
        assert!(decoded.is_ok());

        let decoded_score = decoded.unwrap();
        assert_eq!(decoded_score.node_id, node_id);
        assert_eq!(decoded_score.epoch, 100);
    }

    #[test]
    fn test_drs_config_serialization() {
        let config = DRSConfig::default();

        let bincode_config = bincode::config::standard();
        let encoded = bincode::encode_to_vec(&config, bincode_config);
        assert!(encoded.is_ok());

        let decoded: Result<DRSConfig, _> =
            bincode::decode_from_slice(&encoded.unwrap(), bincode_config).map(|(c, _)| c);
        assert!(decoded.is_ok());

        let decoded_config = decoded.unwrap();
        assert_eq!(decoded_config.w_uptime, config.w_uptime);
        assert_eq!(decoded_config.w_post_pass, config.w_post_pass);
    }

    #[test]
    fn test_multiple_epochs_progression() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(82);

        for epoch in 100..110 {
            let evidence = create_test_evidence(node_id, epoch);
            manager.calculate_drs_score(evidence).unwrap();
            manager.finalize_epoch(epoch).unwrap();
        }

        assert_eq!(manager.get_current_epoch(), 110);

        for epoch in 100..110 {
            let stats = manager.get_epoch_stats(epoch);
            assert!(stats.is_some());
        }
    }

    #[test]
    fn test_concurrent_score_calculations() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        for i in 0..100 {
            let node_id = test_address(i);
            let evidence = create_test_evidence(node_id, 100);
            let result = manager.calculate_drs_score(evidence);
            assert!(result.is_ok());
        }

        let all_nodes = manager.get_all_nodes_in_epoch(100);
        assert_eq!(all_nodes.len(), 100);
    }

    #[test]
    fn test_score_bounds_enforcement() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(83);
        let evidence = create_test_evidence(node_id, 100);
        let score = manager.calculate_drs_score(evidence).unwrap();

        assert!(score.score_raw >= MIN_SCORE);
        assert!(score.score_raw <= MAX_SCORE);
        assert!(score.score_smoothed >= MIN_SCORE);
        assert!(score.score_smoothed <= MAX_SCORE);
    }

    #[test]
    fn test_multiplier_bounds_enforcement() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config.clone());

        let node_id = test_address(84);
        let evidence = create_test_evidence(node_id, 100);
        let score = manager.calculate_drs_score(evidence).unwrap();

        assert!(score.multiplier >= config.m_min);
        assert!(score.multiplier <= config.m_max);
    }

    #[test]
    fn test_zero_challenges_handling() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(85);
        let mut evidence = create_test_evidence(node_id, 100);
        evidence.post_challenges = 0;
        evidence.post_passes = 0;

        let result = manager.calculate_drs_score(evidence);
        assert!(result.is_ok());

        let score = result.unwrap();
        assert_eq!(score.components.post_pass, 0.0);
    }

    #[test]
    fn test_zero_uptime_slots_handling() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(86);
        let mut evidence = create_test_evidence(node_id, 100);
        evidence.uptime_slots_expected = 0;
        evidence.uptime_slots_seen = 0;

        let result = manager.calculate_drs_score(evidence);
        assert!(result.is_ok());

        let score = result.unwrap();
        assert_eq!(score.components.uptime, 0.0);
    }

    #[test]
    fn test_zero_serve_bytes_handling() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(87);
        let mut evidence = create_test_evidence(node_id, 100);
        evidence.serve_bytes_requested = 0;
        evidence.serve_bytes_ok = 0;

        let result = manager.calculate_drs_score(evidence);
        assert!(result.is_ok());

        let score = result.unwrap();
        assert_eq!(score.components.serve_ratio, 0.0);
    }

    #[test]
    fn test_latency_above_sla() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(88);
        let mut evidence = create_test_evidence(node_id, 100);
        evidence.post_latency_sum_ms = 100_000_000;
        evidence.post_latency_count = 100;

        let result = manager.calculate_drs_score(evidence);
        assert!(result.is_ok());

        let score = result.unwrap();
        assert!(score.components.inv_latency < 0.5);
    }

    #[test]
    fn test_perfect_latency() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(89);
        let mut evidence = create_test_evidence(node_id, 100);
        evidence.post_latency_sum_ms = 0;
        evidence.post_latency_count = 100;

        let result = manager.calculate_drs_score(evidence);
        assert!(result.is_ok());

        let score = result.unwrap();
        assert_eq!(score.components.inv_latency, 1.0);
    }

    #[test]
    fn test_poc_events_empty() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(90);
        let mut evidence = create_test_evidence(node_id, 100);
        evidence.poc_events = vec![];

        let result = manager.calculate_drs_score(evidence);
        assert!(result.is_ok());

        let score = result.unwrap();
        assert_eq!(score.components.poc_quality, 0.0);
    }

    #[test]
    fn test_poc_events_weighted_average() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(91);
        let mut evidence = create_test_evidence(node_id, 100);
        evidence.poc_events = vec![
            PoCEventData {
                event_id: test_hash(1),
                q_after_ldm: 1.0,
                witness_confidence: 1.0,
                h3_cell: "cell_1".to_string(),
                timestamp: Timestamp::now(),
            },
            PoCEventData {
                event_id: test_hash(2),
                q_after_ldm: 0.5,
                witness_confidence: 0.5,
                h3_cell: "cell_2".to_string(),
                timestamp: Timestamp::now(),
            },
        ];

        let result = manager.calculate_drs_score(evidence);
        assert!(result.is_ok());

        let score = result.unwrap();
        assert!(score.components.poc_quality > 0.5);
        assert!(score.components.poc_quality < 1.0);
    }

    #[test]
    fn test_density_data_with_vertical_separation() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config.clone());

        let density_data = DensityData {
            h3_cell: "cell_test".to_string(),
            device_count: 4,
            dwell_time_pct: 0.8,
            witnesses: vec![test_address(1), test_address(2), test_address(3)],
            vertical_separation_m: Some(50.0),
        };

        let ldm = manager.calculate_location_density_multiplier(&density_data);
        assert!(ldm < 1.0);
        assert!(ldm >= config.density_min_multiplier);
    }

    #[test]
    fn test_epoch_stats_distribution() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        for i in 0..100 {
            let node_id = test_address(i);
            let mut evidence = create_test_evidence(node_id, 100);
            evidence.post_passes = 50 + i as u64;
            manager.calculate_drs_score(evidence).unwrap();
        }

        let stats = manager.finalize_epoch(100).unwrap();
        assert_eq!(stats.score_distribution.len(), 10);

        let total_in_buckets: u32 = stats
            .score_distribution
            .iter()
            .map(|(_, count)| count)
            .sum();
        assert_eq!(total_in_buckets, 100);
    }

    #[test]
    fn test_median_calculation_even_count() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        for i in 0..10 {
            let node_id = test_address(i);
            let evidence = create_test_evidence(node_id, 100);
            manager.calculate_drs_score(evidence).unwrap();
        }

        let stats = manager.finalize_epoch(100).unwrap();
        assert!(stats.median_score > 0.0);
        assert!(stats.median_score <= 1.0);
    }

    #[test]
    fn test_median_calculation_odd_count() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        for i in 0..11 {
            let node_id = test_address(i);
            let evidence = create_test_evidence(node_id, 100);
            manager.calculate_drs_score(evidence).unwrap();
        }

        let stats = manager.finalize_epoch(100).unwrap();
        assert!(stats.median_score > 0.0);
        assert!(stats.median_score <= 1.0);
    }

    #[test]
    fn test_standard_deviation_calculation() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        for i in 0..20 {
            let node_id = test_address(i);
            let mut evidence = create_test_evidence(node_id, 100);
            evidence.post_passes = 70 + (i % 10) as u64;
            manager.calculate_drs_score(evidence).unwrap();
        }

        let stats = manager.finalize_epoch(100).unwrap();
        assert!(stats.std_dev >= 0.0);
    }

    #[test]
    fn test_top_performers_percentage() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        for i in 0..50 {
            let node_id = test_address(i);
            let evidence = create_test_evidence(node_id, 100);
            manager.calculate_drs_score(evidence).unwrap();
        }

        let stats = manager.finalize_epoch(100).unwrap();
        let expected_top_count = (50_f64 * 0.1).max(1.0) as usize;
        assert_eq!(stats.top_performers.len(), expected_top_count);
    }

    #[test]
    fn test_penalized_nodes_filtering() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        for i in 0..20 {
            let node_id = test_address(i);
            let mut evidence = create_test_evidence(node_id, 100);
            if i < 5 {
                evidence.failed_post_count = 3;
            }
            if i >= 5 && i < 10 {
                evidence.replay_or_incoherence_count = 2;
            }
            manager.calculate_drs_score(evidence).unwrap();
        }

        let stats = manager.finalize_epoch(100).unwrap();
        assert_eq!(stats.penalized_nodes.len(), 10);
    }

    #[test]
    fn test_density_events_generation() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        for i in 0..5 {
            let node_id = test_address(i);
            let mut evidence = create_test_evidence(node_id, 100);
            evidence.density_data = Some(DensityData {
                h3_cell: format!("cell_{}", i),
                device_count: 3,
                dwell_time_pct: 0.5,
                witnesses: vec![test_address(10), test_address(11)],
                vertical_separation_m: None,
            });
            manager.calculate_drs_score(evidence).unwrap();
        }

        let stats = manager.finalize_epoch(100).unwrap();
        assert_eq!(stats.density_events.len(), 5);
    }

    #[test]
    fn test_density_events_filtering_single_device() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        for i in 0..5 {
            let node_id = test_address(i);
            let mut evidence = create_test_evidence(node_id, 100);
            evidence.density_data = Some(DensityData {
                h3_cell: format!("cell_{}", i),
                device_count: 1,
                dwell_time_pct: 0.5,
                witnesses: vec![],
                vertical_separation_m: None,
            });
            manager.calculate_drs_score(evidence).unwrap();
        }

        let stats = manager.finalize_epoch(100).unwrap();
        assert_eq!(stats.density_events.len(), 0);
    }

    #[test]
    fn test_reward_distribution_calculation() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(95);
        let evidence = create_test_evidence(node_id, 100);
        manager.calculate_drs_score(evidence).unwrap();

        let base_storage = Balance::new(1000);
        let base_consensus = Balance::new(500);
        let base_coverage = Balance::new(250);

        let result = manager.apply_reward_multiplier(
            &node_id,
            base_storage,
            base_consensus,
            base_coverage,
            100,
        );
        assert!(result.is_ok());

        let distribution = result.unwrap();
        let total = distribution
            .final_storage_reward
            .checked_add(distribution.final_consensus_reward)
            .and_then(|sum| sum.checked_add(distribution.final_coverage_reward))
            .unwrap();

        assert_eq!(distribution.total_reward, total);
    }

    #[test]
    fn test_reward_distribution_zero_base() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(96);
        let evidence = create_test_evidence(node_id, 100);
        manager.calculate_drs_score(evidence).unwrap();

        let result = manager.apply_reward_multiplier(
            &node_id,
            Balance::ZERO,
            Balance::ZERO,
            Balance::ZERO,
            100,
        );
        assert!(result.is_ok());

        let distribution = result.unwrap();
        assert_eq!(distribution.total_reward, Balance::ZERO);
    }

    #[test]
    fn test_config_weight_normalization() {
        let config = DRSConfig::default();

        let sum = config.w_uptime
            + config.w_post_pass
            + config.w_inv_latency
            + config.w_poc
            + config.w_serve;

        assert!((sum - 1.0).abs() < EPSILON);
    }

    #[test]
    fn test_smoothing_alpha_bounds() {
        let config = DRSConfig::default();
        assert!(config.smoothing_alpha >= 0.0);
        assert!(config.smoothing_alpha <= 1.0);
    }

    #[test]
    fn test_penalty_coefficients_positive() {
        let config = DRSConfig::default();
        assert!(config.a1_failed_post >= 0.0);
        assert!(config.a2_replay_incoherence >= 0.0);
        assert!(config.a3_equivocation >= 0.0);
    }

    #[test]
    fn test_multiplier_range_valid() {
        let config = DRSConfig::default();
        assert!(config.m_min > 0.0);
        assert!(config.m_max > config.m_min);
        assert!(config.m_min <= BASELINE_MULTIPLIER);
        assert!(config.m_max >= BASELINE_MULTIPLIER);
    }

    #[test]
    fn test_density_penalty_bounds() {
        let config = DRSConfig::default();
        assert!(config.density_penalty_rate >= 0.0);
        assert!(config.density_penalty_rate <= 1.0);
        assert!(config.density_min_multiplier >= 0.0);
        assert!(config.density_min_multiplier <= 1.0);
    }

    #[test]
    fn test_band_threshold_ordering() {
        let config = DRSConfig::default();
        assert!(config.high_band_threshold > config.mid_band_threshold);
        assert!(config.mid_band_threshold > 0.0);
        assert!(config.high_band_threshold <= 1.0);
    }

    #[test]
    fn test_audit_recompute_score_matching() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(97);
        let evidence = create_test_evidence(node_id, 100);
        let score = manager.calculate_drs_score(evidence.clone()).unwrap();

        let result = manager.audit_recompute_score(&evidence, &score);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_audit_recompute_score_mismatch() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(98);
        let evidence = create_test_evidence(node_id, 100);
        let mut score = manager.calculate_drs_score(evidence.clone()).unwrap();

        score.score_smoothed = 0.5;

        let result = manager.audit_recompute_score(&evidence, &score);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_constants_valid() {
        assert_eq!(MAX_SCORE, 1.0);
        assert_eq!(MIN_SCORE, 0.0);
        assert_eq!(BASELINE_MULTIPLIER, 1.0);
        assert!(SMOOTHING_WINDOW_EPOCHS > 0);
        assert!(EPSILON > 0.0);
    }

    #[test]
    fn test_address_default() {
        let addr = Address::default();
        assert_eq!(addr.as_bytes(), &[0u8; 20]);
    }

    #[test]
    fn test_distribute_rewards_equal_shares() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let mut nodes = Vec::new();
        let mut base_shares = Vec::new();

        for i in 0..5 {
            let node_id = test_address(i);
            let evidence = create_test_evidence(node_id, 100);
            manager.calculate_drs_score(evidence).unwrap();

            nodes.push(node_id);
            base_shares.push((node_id, 0.2, 0.2, 0.2));
        }

        let result = distribute_rewards_with_drs(
            &manager,
            nodes,
            Balance::new(10000),
            Balance::new(6000),
            Balance::new(4000),
            100,
            &base_shares,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_distribute_rewards_unequal_shares() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let mut nodes = Vec::new();
        let mut base_shares = Vec::new();

        let shares = vec![0.5, 0.3, 0.2];
        for (i, &share) in shares.iter().enumerate() {
            let node_id = test_address(i as u8);
            let evidence = create_test_evidence(node_id, 100);
            manager.calculate_drs_score(evidence).unwrap();

            nodes.push(node_id);
            base_shares.push((node_id, share, share, share));
        }

        let result = distribute_rewards_with_drs(
            &manager,
            nodes,
            Balance::new(10000),
            Balance::new(6000),
            Balance::new(4000),
            100,
            &base_shares,
        );

        assert!(result.is_ok());
        let distributions = result.unwrap();
        assert_eq!(distributions.len(), 3);
    }

    #[test]
    fn test_score_components_bounds() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(99);
        let evidence = create_test_evidence(node_id, 100);
        let score = manager.calculate_drs_score(evidence).unwrap();

        assert!(score.components.uptime >= 0.0 && score.components.uptime <= 1.0);
        assert!(score.components.post_pass >= 0.0 && score.components.post_pass <= 1.0);
        assert!(score.components.inv_latency >= 0.0 && score.components.inv_latency <= 1.0);
        assert!(score.components.poc_quality >= 0.0 && score.components.poc_quality <= 1.0);
        assert!(score.components.serve_ratio >= 0.0 && score.components.serve_ratio <= 1.0);
    }

    #[test]
    fn test_weights_version_increment() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config.clone());

        let initial_version = manager.get_weights_version();

        manager.update_config(config).unwrap();
        let new_version = manager.get_weights_version();

        assert_eq!(new_version, initial_version + 1);
    }

    #[test]
    fn test_evidence_hash_deterministic() {
        let config = DRSConfig::default();
        let manager = DRSManager::new(config);

        let node_id = test_address(100);
        let evidence = create_test_evidence(node_id, 100);

        let score1 = manager.calculate_drs_score(evidence.clone()).unwrap();
        let score2 = manager.calculate_drs_score(evidence).unwrap();

        assert_eq!(score1.evidence_root, score2.evidence_root);
    }
}
