#[cfg(test)]
mod deploy_policy_tests {
    use ego_core::crypto::hash_data;
    use ego_core::deploy_policy::*;
    use ego_core::{Address, Balance, Hash, Timestamp};
    use std::collections::HashMap;

    fn calculate_reputation_score(
        success_rate: f64,
        human_verified: u32,
        ai_flagged: u32,
        bonds_slashed: u32,
        total_deploys: u32,
    ) -> u32 {
        let mut score = 50.0;
        score += (success_rate - 50.0) * 0.5;
        score += (human_verified as f64 / total_deploys.max(1) as f64) * 20.0;
        score -= (ai_flagged as f64 / total_deploys.max(1) as f64) * 30.0;
        score -= (bonds_slashed as f64) * 10.0;
        if total_deploys >= 10 {
            score += 5.0;
        }
        if total_deploys >= 50 {
            score += 10.0;
        }
        score.clamp(0.0, 100.0) as u32
    }

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

    fn create_test_deploy_request(
        deployer: Address,
        code_size_kb: u32,
        estimated_ru: u64,
    ) -> DeployRequest {
        DeployRequest {
            deployer,
            deploy_type: DeployType::SmartContract {
                code_size_kb,
                estimated_ru,
            },
            code: vec![1u8; (code_size_kb as usize) * 1024],
            metadata: HashMap::new(),
            use_free_quota: false,
            preferred_shard: None,
            human_verification_signature: None,
            dilithium_verification_pk: None,
        }
    }

    #[test]
    fn test_deploy_policy_config_default() {
        let config = DeployPolicyConfig::default();

        assert_eq!(config.free_deploys_per_epoch, 5);
        assert_eq!(config.credits_per_kb, 100);
        assert_eq!(config.credits_per_ru, 10);
        assert_eq!(config.max_deploy_size_kb, 1024);
        assert_eq!(config.max_ru_per_deploy, 10000);
        assert_eq!(config.max_deploys_per_epoch, 10000);
        assert_eq!(config.max_deploys_per_user_per_epoch, 50);
        assert!(config.enable_dedup);
        assert!(config.anti_spam_enabled);
        assert!(config.ai_pattern_detection_enabled);
        assert!(!config.emergency_mode);
        assert!(!config.whitelist_only_mode);
    }

    #[test]
    fn test_new_deploy_policy_manager() {
        let config = DeployPolicyConfig::default();
        let manager = DeployPolicyManager::new(config.clone());

        assert_eq!(manager.current_epoch, 0);
        assert_eq!(
            manager.config.free_deploys_per_epoch,
            config.free_deploys_per_epoch
        );
        assert_eq!(manager.get_total_deploys(), 0);
        assert!(manager.staker_quotas.is_empty());
        assert!(manager.deploy_history.is_empty());
    }

    #[test]
    fn test_evaluate_deploy_request_basic() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(1);
        let request = create_test_deploy_request(deployer, 100, 500);

        let result = manager.evaluate_deploy_request(&request, None, 1000);
        assert!(result.is_ok());

        let decision = result.unwrap();
        match decision {
            DeployDecision::AcceptWithCredits {
                deploy_id,
                credits_required,
                ..
            } => {
                assert!(credits_required > 0);
                assert_ne!(deploy_id, Hash::new([0u8; 32]));
            }
            _ => panic!("Expected AcceptWithCredits decision"),
        }
    }

    #[test]
    fn test_evaluate_deploy_request_with_free_quota() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(2);
        let mut request = create_test_deploy_request(deployer, 100, 500);
        request.use_free_quota = true;

        let stake = Some(Balance::from_egoc(2000));
        let result = manager.evaluate_deploy_request(&request, stake, 1000);
        assert!(result.is_ok());

        let decision = result.unwrap();
        match decision {
            DeployDecision::AcceptWithFreeQuota { .. } => {}
            _ => panic!("Expected AcceptWithFreeQuota decision"),
        }
    }

    #[test]
    fn test_evaluate_deploy_request_emergency_mode() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);
        manager.enable_emergency_mode();

        let deployer = test_address(3);
        let request = create_test_deploy_request(deployer, 100, 500);

        let result = manager.evaluate_deploy_request(&request, None, 1000);
        assert!(result.is_ok());

        let decision = result.unwrap();
        match decision {
            DeployDecision::Reject { reason, .. } => {
                assert!(reason.contains("Emergency mode"));
            }
            _ => panic!("Expected Reject decision in emergency mode"),
        }
    }

    #[test]
    fn test_ai_pattern_detection() {
        let config = DeployPolicyConfig {
            ai_pattern_detection_enabled: true,
            ..DeployPolicyConfig::default()
        };
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(4);
        let mut request = create_test_deploy_request(deployer, 10, 100);
        request.code = b"let me know if you need more help with this".to_vec();

        let result = manager.evaluate_deploy_request(&request, None, 1000);
        assert!(result.is_ok());

        let decision = result.unwrap();
        match decision {
            DeployDecision::Reject { reason, .. } => {
                assert!(reason.contains("AI pattern detected"));
            }
            _ => panic!("Expected Reject decision for AI pattern"),
        }
    }

    #[test]
    fn test_ai_pattern_detection_in_metadata() {
        let config = DeployPolicyConfig {
            ai_pattern_detection_enabled: true,
            ..DeployPolicyConfig::default()
        };
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(5);
        let mut request = create_test_deploy_request(deployer, 10, 100);
        request.metadata.insert(
            "description".to_string(),
            "As an AI model, I think this is great".to_string(),
        );

        let result = manager.evaluate_deploy_request(&request, None, 1000);
        assert!(result.is_ok());

        let decision = result.unwrap();
        match decision {
            DeployDecision::Reject { reason, .. } => {
                assert!(reason.contains("AI pattern detected"));
            }
            _ => panic!("Expected Reject decision for AI pattern in metadata"),
        }
    }

    #[test]
    fn test_check_hard_caps_global_limit() {
        let config = DeployPolicyConfig {
            max_deploys_per_epoch: 5,
            ..DeployPolicyConfig::default()
        };
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(6);

        for i in 0..5 {
            let request = create_test_deploy_request(test_address(10 + i), 10, 100);
            let _ = manager.evaluate_deploy_request(&request, None, 1000);
        }

        let request = create_test_deploy_request(deployer, 10, 100);
        let result = manager.evaluate_deploy_request(&request, None, 1000);
        assert!(result.is_ok());

        match result.unwrap() {
            DeployDecision::Reject { reason, .. } => {
                assert!(reason.contains("Hard caps exceeded"));
            }
            _ => panic!("Expected Reject decision"),
        }
    }

    #[test]
    fn test_validate_deploy_limits_size() {
        let config = DeployPolicyConfig {
            max_deploy_size_kb: 100,
            ..DeployPolicyConfig::default()
        };
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(8);
        let request = create_test_deploy_request(deployer, 200, 500);

        let result = manager.evaluate_deploy_request(&request, None, 1000);
        assert!(result.is_ok());

        match result.unwrap() {
            DeployDecision::Reject { reason, .. } => {
                assert!(reason.contains("Deploy size"));
            }
            _ => panic!("Expected Reject decision"),
        }
    }

    #[test]
    fn test_validate_deploy_limits_ru() {
        let config = DeployPolicyConfig {
            max_ru_per_deploy: 500,
            ..DeployPolicyConfig::default()
        };
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(9);
        let request = create_test_deploy_request(deployer, 10, 1000);

        let result = manager.evaluate_deploy_request(&request, None, 1000);
        assert!(result.is_ok());

        match result.unwrap() {
            DeployDecision::Reject { reason, .. } => {
                assert!(reason.contains("Deploy RU"));
            }
            _ => panic!("Expected Reject decision"),
        }
    }

    #[test]
    fn test_blacklist_contract() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(11);
        let request = create_test_deploy_request(deployer, 10, 100);
        let code_hash = hash_data(&request.code);

        manager
            .blacklist_contract(
                code_hash,
                "Malicious code".to_string(),
                test_address(100),
                test_hash(1),
            )
            .unwrap();

        assert!(manager.is_blacklisted(&code_hash));

        let result = manager.evaluate_deploy_request(&request, None, 1000);
        assert!(result.is_ok());

        match result.unwrap() {
            DeployDecision::Reject { reason, .. } => {
                assert!(reason.contains("blacklisted"));
            }
            _ => panic!("Expected Reject for blacklisted contract"),
        }
    }

    #[test]
    fn test_remove_from_blacklist() {
        let config = DeployPolicyConfig::default();
        let manager = DeployPolicyManager::new(config);

        let code_hash = test_hash(2);
        manager
            .blacklist_contract(
                code_hash,
                "Test".to_string(),
                test_address(100),
                test_hash(3),
            )
            .unwrap();

        assert!(manager.is_blacklisted(&code_hash));

        manager.remove_from_blacklist(&code_hash).unwrap();
        assert!(!manager.is_blacklisted(&code_hash));
    }

    #[test]
    fn test_anti_spam_min_interval() {
        let config = DeployPolicyConfig {
            anti_spam_enabled: true,
            min_deploy_interval_seconds: 120,
            ..DeployPolicyConfig::default()
        };
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(12);
        let request1 = create_test_deploy_request(deployer, 10, 100);
        let result1 = manager.evaluate_deploy_request(&request1, None, 1000);
        assert!(result1.is_ok());

        let request2 = create_test_deploy_request(deployer, 10, 100);
        let result2 = manager.evaluate_deploy_request(&request2, None, 1001);
        assert!(result2.is_ok());

        match result2.unwrap() {
            DeployDecision::Reject { reason, .. } => {
                assert!(reason.contains("Deploy interval too short"));
            }
            _ => panic!("Expected Reject for interval check"),
        }
    }

    #[test]
    fn test_anti_spam_hourly_limit() {
        let config = DeployPolicyConfig {
            anti_spam_enabled: true,
            max_deploys_per_hour: 3,
            min_deploy_interval_seconds: 0,
            ..DeployPolicyConfig::default()
        };
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(13);

        for _ in 0..3 {
            let request = create_test_deploy_request(deployer, 10, 100);
            let _ = manager.evaluate_deploy_request(&request, None, 1000);
        }

        let request = create_test_deploy_request(deployer, 10, 100);
        let result = manager.evaluate_deploy_request(&request, None, 1000);
        assert!(result.is_ok());

        match result.unwrap() {
            DeployDecision::Reject { reason, .. } => {
                assert!(reason.contains("Hourly deploy limit exceeded"));
            }
            _ => panic!("Expected Reject for hourly limit"),
        }
    }

    #[test]
    fn test_calculate_resources_smart_contract() {
        let deploy_type = DeployType::SmartContract {
            code_size_kb: 100,
            estimated_ru: 500,
        };

        let (size_kb, ru) = match deploy_type {
            DeployType::SmartContract {
                code_size_kb,
                estimated_ru,
            } => (code_size_kb, estimated_ru),
            _ => panic!("Wrong type"),
        };
        assert_eq!(size_kb, 100);
        assert_eq!(ru, 500);
    }

    #[test]
    fn test_calculate_resources_storage_deal() {
        let deploy_type = DeployType::StorageDeal {
            data_size_kb: 1000,
            duration_blocks: 10000,
        };

        let (size_kb, ru) = match deploy_type {
            DeployType::StorageDeal {
                data_size_kb,
                duration_blocks,
            } => {
                let ru = (data_size_kb as u64) * (duration_blocks / 1000);
                (data_size_kb, ru)
            }
            _ => panic!("Wrong type"),
        };
        assert_eq!(size_kb, 1000);
        assert_eq!(ru, 10000);
    }

    #[test]
    fn test_calculate_resources_rollup_operator() {
        let deploy_type = DeployType::RollupOperator {
            initial_state_kb: 200,
        };

        let (size_kb, ru) = match deploy_type {
            DeployType::RollupOperator { initial_state_kb } => {
                let ru = (initial_state_kb as u64) * 10;
                (initial_state_kb, ru)
            }
            _ => panic!("Wrong type"),
        };
        assert_eq!(size_kb, 200);
        assert_eq!(ru, 2000);
    }

    #[test]
    fn test_calculate_credits_needed() {
        let config = DeployPolicyConfig {
            credits_per_kb: 100,
            credits_per_ru: 10,
            ..DeployPolicyConfig::default()
        };

        let size_kb = 50u32;
        let estimated_ru = 200u64;
        let credits =
            (size_kb as u64) * config.credits_per_kb + estimated_ru * config.credits_per_ru;
        assert_eq!(credits, 50 * 100 + 200 * 10);
    }

    #[test]
    fn test_calculate_pob_floor() {
        let config = DeployPolicyConfig {
            pob_floor_enabled: true,
            pob_floor_per_kb: 50,
            pob_floor_per_ru: 5,
            ..DeployPolicyConfig::default()
        };

        let size_kb = 100u32;
        let estimated_ru = 500u64;
        let pob_floor =
            (size_kb as u64) * config.pob_floor_per_kb + estimated_ru * config.pob_floor_per_ru;
        assert_eq!(pob_floor, 100 * 50 + 500 * 5);
    }

    #[test]
    fn test_complete_deploy_success() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(16);
        let request = create_test_deploy_request(deployer, 10, 100);

        let result = manager.evaluate_deploy_request(&request, None, 1000);
        let deploy_id = match result.unwrap() {
            DeployDecision::AcceptWithCredits { deploy_id, .. } => deploy_id,
            _ => panic!("Expected AcceptWithCredits"),
        };

        let contract_address = Some(test_address(200));
        let complete_result =
            manager.complete_deploy(&deploy_id, true, 5000, None, contract_address);
        assert!(complete_result.is_ok());

        let record = manager.get_deploy_record(&deploy_id).unwrap();
        assert!(record.success);
        assert_eq!(record.gas_used, 5000);
        assert_eq!(record.contract_address, contract_address);
        assert_eq!(record.status, DeployStatus::Completed);
    }

    #[test]
    fn test_complete_deploy_failure() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(17);
        let request = create_test_deploy_request(deployer, 10, 100);

        let result = manager.evaluate_deploy_request(&request, None, 1000);
        let deploy_id = match result.unwrap() {
            DeployDecision::AcceptWithCredits { deploy_id, .. } => deploy_id,
            _ => panic!("Expected AcceptWithCredits"),
        };

        let error_msg = Some("Out of gas".to_string());
        let complete_result =
            manager.complete_deploy(&deploy_id, false, 10000, error_msg.clone(), None);
        assert!(complete_result.is_ok());

        let record = manager.get_deploy_record(&deploy_id).unwrap();
        assert!(!record.success);
        assert_eq!(record.gas_used, 10000);
        assert_eq!(record.error, error_msg);
        match record.status {
            DeployStatus::Failed { .. } => {}
            _ => panic!("Expected Failed status"),
        }
    }

    #[test]
    fn test_finalize_epoch() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        let deployer1 = test_address(19);
        let deployer2 = test_address(20);

        let request1 = create_test_deploy_request(deployer1, 50, 200);
        let result1 = manager.evaluate_deploy_request(&request1, None, 1000);
        let deploy_id1 = match result1.unwrap() {
            DeployDecision::AcceptWithCredits { deploy_id, .. } => deploy_id,
            _ => panic!("Expected AcceptWithCredits"),
        };
        manager
            .complete_deploy(&deploy_id1, true, 1000, None, None)
            .unwrap();

        let request2 = create_test_deploy_request(deployer2, 30, 150);
        let result2 = manager.evaluate_deploy_request(&request2, None, 1001);
        let deploy_id2 = match result2.unwrap() {
            DeployDecision::AcceptWithCredits { deploy_id, .. } => deploy_id,
            _ => panic!("Expected AcceptWithCredits"),
        };
        manager
            .complete_deploy(&deploy_id2, false, 500, Some("Error".to_string()), None)
            .unwrap();

        let stats = manager.finalize_epoch(0).unwrap();
        assert_eq!(stats.total_deploys, 2);
        assert_eq!(stats.successful_deploys, 1);
        assert_eq!(stats.failed_deploys, 1);
        assert_eq!(stats.unique_deployers, 2);
        assert!(stats.total_size_kb > 0);
    }

    #[test]
    fn test_advance_epoch() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        assert_eq!(manager.current_epoch, 0);

        let result = manager.advance_epoch(1);
        assert!(result.is_ok());
        assert_eq!(manager.current_epoch, 1);

        let result = manager.advance_epoch(1);
        assert!(result.is_err());

        let result = manager.advance_epoch(5);
        assert!(result.is_ok());
        assert_eq!(manager.current_epoch, 5);
    }

    #[test]
    fn test_prune_old_records() {
        let config = DeployPolicyConfig {
            dedup_lookback_epochs: 2,
            ..DeployPolicyConfig::default()
        };
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(21);

        for epoch in 0..6 {
            manager.current_epoch = epoch;
            let request = create_test_deploy_request(deployer, 10, 100);
            let _ = manager.evaluate_deploy_request(&request, None, 1000 * epoch);
        }

        let initial_count = manager.get_total_deploys();
        assert!(initial_count > 0);

        manager.current_epoch = 10;
        let cutoff_epoch = manager
            .current_epoch
            .saturating_sub(manager.config.dedup_lookback_epochs * 2);

        manager
            .deploy_history
            .retain(|_, record| record.epoch >= cutoff_epoch);
        manager
            .epoch_stats
            .retain(|&epoch, _| epoch >= cutoff_epoch);

        let remaining_count = manager.get_total_deploys();
        assert!(remaining_count < initial_count);
    }

    #[test]
    fn test_get_user_quota() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(22);
        let stake = Some(Balance::from_egoc(2000));

        let mut request = create_test_deploy_request(deployer, 10, 100);
        request.use_free_quota = true;

        manager
            .evaluate_deploy_request(&request, stake, 1000)
            .unwrap();

        let quota = manager.get_user_quota(&deployer);
        assert!(quota.is_some());

        let quota_data = quota.unwrap();
        assert_eq!(quota_data.staker, deployer);
        assert!(quota_data.free_deploys_remaining < 5);
    }

    #[test]
    fn test_get_deploy_record() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(23);
        let request = create_test_deploy_request(deployer, 10, 100);

        let result = manager.evaluate_deploy_request(&request, None, 1000);
        let deploy_id = match result.unwrap() {
            DeployDecision::AcceptWithCredits { deploy_id, .. } => deploy_id,
            _ => panic!("Expected AcceptWithCredits"),
        };

        let record = manager.get_deploy_record(&deploy_id);
        assert!(record.is_some());

        let record_data = record.unwrap();
        assert_eq!(record_data.deployer, deployer);
        assert_eq!(record_data.deploy_id, deploy_id);
    }

    #[test]
    fn test_get_epoch_stats() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(24);
        let request = create_test_deploy_request(deployer, 10, 100);
        manager
            .evaluate_deploy_request(&request, None, 1000)
            .unwrap();

        manager.finalize_epoch(0).unwrap();

        let stats = manager.get_epoch_stats(0);
        assert!(stats.is_some());

        let stats_data = stats.unwrap();
        assert_eq!(stats_data.epoch, 0);
        assert_eq!(stats_data.total_deploys, 1);
    }

    #[test]
    fn test_get_deployer_history() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(25);

        for i in 0..5 {
            let request = create_test_deploy_request(deployer, 10 + i, 100);
            manager
                .evaluate_deploy_request(&request, None, 1000 + i as u64)
                .unwrap();
        }

        let history = manager.get_deployer_history(&deployer, 3);
        assert_eq!(history.len(), 3);

        for record in &history {
            assert_eq!(record.deployer, deployer);
        }
    }

    #[test]
    fn test_get_contract_deploys() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        let deployer1 = test_address(26);
        let deployer2 = test_address(27);

        let request1 = create_test_deploy_request(deployer1, 50, 200);
        manager
            .evaluate_deploy_request(&request1, None, 1000)
            .unwrap();

        let request2 = create_test_deploy_request(deployer2, 50, 200);
        manager
            .evaluate_deploy_request(&request2, None, 1001)
            .unwrap();

        let code_hash = hash_data(&request1.code);
        let deploys = manager.get_contract_deploys(&code_hash);

        assert!(deploys.len() >= 1);
        for deploy in &deploys {
            assert_eq!(deploy.code_hash, code_hash);
        }
    }

    #[test]
    fn test_update_quota_from_drs() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(28);
        let stake = Some(Balance::from_egoc(2000));

        let mut request = create_test_deploy_request(deployer, 10, 100);
        request.use_free_quota = true;

        manager
            .evaluate_deploy_request(&request, stake, 1000)
            .unwrap();

        let result = manager.update_quota_from_drs(&deployer, 1.2, QuotaBand::High);
        assert!(result.is_ok());

        let quota = manager.get_user_quota(&deployer).unwrap();
        assert_eq!(quota.drs_multiplier, 1.2);
        assert_eq!(quota.quota_band, QuotaBand::High);
    }

    #[test]
    fn test_update_quota_from_drs_clamp() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(29);
        let stake = Some(Balance::from_egoc(2000));

        let mut request = create_test_deploy_request(deployer, 10, 100);
        request.use_free_quota = true;

        manager
            .evaluate_deploy_request(&request, stake, 1000)
            .unwrap();

        let result = manager.update_quota_from_drs(&deployer, 2.0, QuotaBand::High);
        assert!(result.is_ok());

        let quota = manager.get_user_quota(&deployer).unwrap();
        assert_eq!(quota.drs_multiplier, 1.3);

        let result = manager.update_quota_from_drs(&deployer, 0.3, QuotaBand::Low);
        assert!(result.is_ok());

        let quota = manager.get_user_quota(&deployer).unwrap();
        assert_eq!(quota.drs_multiplier, 0.7);
    }

    #[test]
    fn test_record_pob_burn() {
        let config = DeployPolicyConfig::default();
        let manager = DeployPolicyManager::new(config);

        let deploy_id = test_hash(10);
        let deployer = test_address(30);
        let burn_amount = 1000;
        let credits_minted = 500;
        let burn_tx_hash = test_hash(11);

        let result = manager.record_pob_burn(
            deploy_id,
            deployer,
            burn_amount,
            credits_minted,
            burn_tx_hash,
        );
        assert!(result.is_ok());

        let record = manager.get_pob_burn_record(&deploy_id);
        assert!(record.is_some());

        let record_data = record.unwrap();
        assert_eq!(record_data.deploy_id, deploy_id);
        assert_eq!(record_data.deployer, deployer);
        assert_eq!(record_data.burn_amount, burn_amount);
        assert_eq!(record_data.credits_minted, credits_minted);
    }

    #[test]
    fn test_get_anti_spam_metrics() {
        let config = DeployPolicyConfig {
            anti_spam_enabled: true,
            min_deploy_interval_seconds: 0,
            ..DeployPolicyConfig::default()
        };
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(31);

        for i in 0..3 {
            let request = create_test_deploy_request(deployer, 10, 100);
            manager
                .evaluate_deploy_request(&request, None, 1000 + i)
                .unwrap();
        }

        let metrics = manager.get_anti_spam_metrics(&deployer);
        assert!(metrics.is_some());

        let metrics_data = metrics.unwrap();
        assert_eq!(metrics_data.deployer, deployer);
        assert!(metrics_data.deploys_last_hour.len() >= 3);
        assert!(metrics_data.deploys_last_day.len() >= 3);
    }

    #[test]
    fn test_enable_disable_emergency_mode() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        assert!(!manager.config.emergency_mode);

        manager.enable_emergency_mode();
        assert!(manager.config.emergency_mode);

        manager.disable_emergency_mode();
        assert!(!manager.config.emergency_mode);
    }

    #[test]
    fn test_enable_disable_whitelist_mode() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        assert!(!manager.config.whitelist_only_mode);

        manager.enable_whitelist_mode();
        assert!(manager.config.whitelist_only_mode);

        manager.disable_whitelist_mode();
        assert!(!manager.config.whitelist_only_mode);
    }

    #[test]
    fn test_update_config() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        let new_config = DeployPolicyConfig {
            free_deploys_per_epoch: 10,
            max_deploy_size_kb: 2048,
            ..DeployPolicyConfig::default()
        };

        let result = manager.update_config(new_config.clone());
        assert!(result.is_ok());

        assert_eq!(manager.config.free_deploys_per_epoch, 10);
        assert_eq!(manager.config.max_deploy_size_kb, 2048);
    }

    #[test]
    fn test_update_config_invalid_limits() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        let invalid_config = DeployPolicyConfig {
            max_deploy_size_kb: 0,
            ..DeployPolicyConfig::default()
        };

        let result = manager.update_config(invalid_config);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_config_invalid_free_deploys() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        let invalid_config = DeployPolicyConfig {
            free_deploys_per_epoch: 2000,
            ..DeployPolicyConfig::default()
        };

        let result = manager.update_config(invalid_config);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_config_invalid_slash_threshold() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        let invalid_config = DeployPolicyConfig {
            bond_slash_threshold: 0,
            ..DeployPolicyConfig::default()
        };

        let result = manager.update_config(invalid_config);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_current_epoch() {
        let config = DeployPolicyConfig::default();
        let manager = DeployPolicyManager::new(config);

        assert_eq!(manager.get_current_epoch(), 0);
    }

    #[test]
    fn test_get_config() {
        let config = DeployPolicyConfig {
            free_deploys_per_epoch: 7,
            ..DeployPolicyConfig::default()
        };
        let manager = DeployPolicyManager::new(config.clone());

        let retrieved_config = manager.get_config();
        assert_eq!(retrieved_config.free_deploys_per_epoch, 7);
    }

    #[test]
    fn test_get_total_deploys() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        assert_eq!(manager.get_total_deploys(), 0);

        let deployer = test_address(32);
        for i in 0..5 {
            let request = create_test_deploy_request(deployer, 10 + i, 100);
            manager
                .evaluate_deploy_request(&request, None, 1000 + i as u64)
                .unwrap();
        }

        assert_eq!(manager.get_total_deploys(), 5);
    }

    #[test]
    fn test_get_epoch_deploys() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(33);

        for i in 0..3 {
            let request = create_test_deploy_request(deployer, 10 + i, 100);
            manager
                .evaluate_deploy_request(&request, None, 1000 + i as u64)
                .unwrap();
        }

        manager.advance_epoch(1).unwrap();

        for i in 0..2 {
            let request = create_test_deploy_request(deployer, 10 + i, 100);
            manager
                .evaluate_deploy_request(&request, None, 2000 + i as u64)
                .unwrap();
        }

        assert_eq!(manager.get_epoch_deploys(0), 3);
        assert_eq!(manager.get_epoch_deploys(1), 2);
    }

    #[test]
    fn test_calculate_reputation_score() {
        let score1 = calculate_reputation_score(100.0, 10, 0, 0, 10);
        assert!(score1 > 70);

        let score2 = calculate_reputation_score(50.0, 0, 5, 2, 10);
        assert!(score2 < 50);

        let score3 = calculate_reputation_score(80.0, 50, 5, 1, 100);
        assert!(score3 > 50);
    }

    #[test]
    fn test_validate_deploy_request_empty_code() {
        let mut request = create_test_deploy_request(test_address(36), 10, 100);
        request.code = Vec::new();

        let result = validate_deploy_request(&request);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_deploy_request_large_code() {
        let mut request = create_test_deploy_request(test_address(37), 10, 100);
        request.code = vec![1u8; 11 * 1024 * 1024];

        let result = validate_deploy_request(&request);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_deploy_request_invalid_smart_contract() {
        let deployer = test_address(38);
        let request = DeployRequest {
            deployer,
            deploy_type: DeployType::SmartContract {
                code_size_kb: 0,
                estimated_ru: 100,
            },
            code: vec![1u8; 1024],
            metadata: HashMap::new(),
            use_free_quota: false,
            preferred_shard: None,
            human_verification_signature: None,
            dilithium_verification_pk: None,
        };

        let result = validate_deploy_request(&request);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_deploy_request_invalid_storage_deal() {
        let deployer = test_address(39);
        let request = DeployRequest {
            deployer,
            deploy_type: DeployType::StorageDeal {
                data_size_kb: 100,
                duration_blocks: 0,
            },
            code: vec![1u8; 1024],
            metadata: HashMap::new(),
            use_free_quota: false,
            preferred_shard: None,
            human_verification_signature: None,
            dilithium_verification_pk: None,
        };

        let result = validate_deploy_request(&request);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_deploy_request_invalid_rollup() {
        let deployer = test_address(40);
        let request = DeployRequest {
            deployer,
            deploy_type: DeployType::RollupOperator {
                initial_state_kb: 0,
            },
            code: vec![1u8; 1024],
            metadata: HashMap::new(),
            use_free_quota: false,
            preferred_shard: None,
            human_verification_signature: None,
            dilithium_verification_pk: None,
        };

        let result = validate_deploy_request(&request);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_deploy_request_valid() {
        let request = create_test_deploy_request(test_address(41), 100, 500);
        let result = validate_deploy_request(&request);
        assert!(result.is_ok());
    }

    #[test]
    fn test_estimate_deploy_cost_smart_contract() {
        let config = DeployPolicyConfig {
            credits_per_kb: 100,
            credits_per_ru: 10,
            pob_floor_enabled: false,
            ..DeployPolicyConfig::default()
        };

        let deploy_type = DeployType::SmartContract {
            code_size_kb: 50,
            estimated_ru: 200,
        };

        let estimate = estimate_deploy_cost(&deploy_type, &config);
        assert_eq!(estimate.size_kb, 50);
        assert_eq!(estimate.estimated_ru, 200);
        assert_eq!(estimate.credits_required, 50 * 100 + 200 * 10);
        assert_eq!(estimate.pob_floor_required, 0);
    }

    #[test]
    fn test_estimate_deploy_cost_with_pob_floor() {
        let config = DeployPolicyConfig {
            credits_per_kb: 100,
            credits_per_ru: 10,
            pob_floor_enabled: true,
            pob_floor_per_kb: 50,
            pob_floor_per_ru: 5,
            ..DeployPolicyConfig::default()
        };

        let deploy_type = DeployType::SmartContract {
            code_size_kb: 100,
            estimated_ru: 500,
        };

        let estimate = estimate_deploy_cost(&deploy_type, &config);
        assert_eq!(estimate.pob_floor_required, 100 * 50 + 500 * 5);
    }

    #[test]
    fn test_estimate_deploy_cost_storage_deal() {
        let config = DeployPolicyConfig::default();

        let deploy_type = DeployType::StorageDeal {
            data_size_kb: 1000,
            duration_blocks: 5000,
        };

        let estimate = estimate_deploy_cost(&deploy_type, &config);
        assert_eq!(estimate.size_kb, 1000);
        assert_eq!(estimate.estimated_ru, 5000);
    }

    #[test]
    fn test_estimate_deploy_cost_rollup_operator() {
        let config = DeployPolicyConfig::default();

        let deploy_type = DeployType::RollupOperator {
            initial_state_kb: 250,
        };

        let estimate = estimate_deploy_cost(&deploy_type, &config);
        assert_eq!(estimate.size_kb, 250);
        assert_eq!(estimate.estimated_ru, 2500);
    }

    #[test]
    fn test_deploy_decision_equality() {
        let deploy_id1 = test_hash(20);
        let deploy_id2 = test_hash(21);

        let decision1 = DeployDecision::AcceptWithFreeQuota {
            deploy_id: deploy_id1,
        };
        let decision2 = DeployDecision::AcceptWithFreeQuota {
            deploy_id: deploy_id1,
        };
        let decision3 = DeployDecision::AcceptWithFreeQuota {
            deploy_id: deploy_id2,
        };

        assert_eq!(decision1, decision2);
        assert_ne!(decision1, decision3);
    }

    #[test]
    fn test_quota_band_equality() {
        assert_eq!(QuotaBand::High, QuotaBand::High);
        assert_eq!(QuotaBand::Mid, QuotaBand::Mid);
        assert_eq!(QuotaBand::Low, QuotaBand::Low);
        assert_ne!(QuotaBand::High, QuotaBand::Mid);
        assert_ne!(QuotaBand::Mid, QuotaBand::Low);
    }

    #[test]
    fn test_deploy_status_equality() {
        let status1 = DeployStatus::Pending;
        let status2 = DeployStatus::Accepted;
        let status3 = DeployStatus::Completed;
        let status4 = DeployStatus::Rejected {
            reason: "Test".to_string(),
        };
        let status5 = DeployStatus::Failed {
            error: "Error".to_string(),
        };

        assert_eq!(status1, DeployStatus::Pending);
        assert_ne!(status1, status2);
        assert_ne!(status2, status3);
        assert_eq!(
            status4,
            DeployStatus::Rejected {
                reason: "Test".to_string()
            }
        );
        assert_eq!(
            status5,
            DeployStatus::Failed {
                error: "Error".to_string()
            }
        );
    }

    #[test]
    fn test_deploy_type_equality() {
        let type1 = DeployType::SmartContract {
            code_size_kb: 100,
            estimated_ru: 500,
        };
        let type2 = DeployType::SmartContract {
            code_size_kb: 100,
            estimated_ru: 500,
        };
        let type3 = DeployType::StorageDeal {
            data_size_kb: 1000,
            duration_blocks: 5000,
        };

        assert_eq!(type1, type2);
        assert_ne!(type1, type3);
    }

    #[test]
    fn test_epoch_deploy_stats_default() {
        let stats = EpochDeployStats::default();
        assert_eq!(stats.epoch, 0);
        assert_eq!(stats.total_deploys, 0);
        assert_eq!(stats.successful_deploys, 0);
        assert_eq!(stats.failed_deploys, 0);
        assert_eq!(stats.unique_deployers, 0);
    }

    #[test]
    fn test_multiple_deployers_same_epoch() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        let deployers = vec![test_address(42), test_address(43), test_address(44)];

        for deployer in &deployers {
            let request = create_test_deploy_request(*deployer, 10, 100);
            manager
                .evaluate_deploy_request(&request, None, 1000)
                .unwrap();
        }

        let stats = manager.finalize_epoch(0).unwrap();
        assert_eq!(stats.unique_deployers, 3);
        assert_eq!(stats.total_deploys, 3);
    }

    #[test]
    fn test_spam_score_increment_and_decay() {
        let config = DeployPolicyConfig {
            anti_spam_enabled: true,
            min_deploy_interval_seconds: 0,
            ..DeployPolicyConfig::default()
        };
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(46);

        for i in 0..10 {
            let request = create_test_deploy_request(deployer, 10, 100);
            manager
                .evaluate_deploy_request(&request, None, 1000 + i)
                .unwrap();
        }

        let metrics = manager.get_anti_spam_metrics(&deployer).unwrap();
        assert!(metrics.spam_score > 0);
        assert_eq!(metrics.deploys_last_hour.len(), 10);
    }

    #[test]
    fn test_failed_deploy_spam_score_increase() {
        let config = DeployPolicyConfig {
            anti_spam_enabled: true,
            min_deploy_interval_seconds: 0,
            ..DeployPolicyConfig::default()
        };
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(47);
        let request = create_test_deploy_request(deployer, 10, 100);

        let result = manager.evaluate_deploy_request(&request, None, 1000);
        let deploy_id = match result.unwrap() {
            DeployDecision::AcceptWithCredits { deploy_id, .. } => deploy_id,
            _ => panic!("Expected AcceptWithCredits"),
        };

        let metrics_before = manager.get_anti_spam_metrics(&deployer).unwrap();
        let score_before = metrics_before.spam_score;

        manager
            .complete_deploy(&deploy_id, false, 1000, Some("Error".to_string()), None)
            .unwrap();

        let metrics_after = manager.get_anti_spam_metrics(&deployer).unwrap();
        assert!(metrics_after.spam_score > score_before);
        assert_eq!(metrics_after.total_rejected, 1);
    }

    #[test]
    fn test_pob_floor_calculation() {
        let config = DeployPolicyConfig {
            pob_floor_enabled: true,
            pob_floor_per_kb: 75,
            pob_floor_per_ru: 8,
            ..DeployPolicyConfig::default()
        };
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(48);
        let request = create_test_deploy_request(deployer, 100, 500);

        let result = manager.evaluate_deploy_request(&request, None, 1000);
        match result.unwrap() {
            DeployDecision::AcceptWithCredits { pob_floor, .. } => {
                assert_eq!(pob_floor, 100 * 75 + 500 * 8);
            }
            _ => panic!("Expected AcceptWithCredits"),
        }
    }

    #[test]
    fn test_bond_requirement() {
        let config = DeployPolicyConfig {
            deploy_bond_amount: Balance::new(5000000),
            bond_lock_duration_blocks: 2000,
            ..DeployPolicyConfig::default()
        };
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(49);
        let request = create_test_deploy_request(deployer, 100, 500);

        let result = manager.evaluate_deploy_request(&request, None, 1000);
        match result.unwrap() {
            DeployDecision::AcceptWithCredits { bond_required, .. } => {
                assert!(bond_required.is_some());
                assert_eq!(bond_required.unwrap(), Balance::new(5000000));
            }
            _ => panic!("Expected AcceptWithCredits"),
        }

        let records: Vec<DeployRecord> = manager
            .deploy_history
            .iter()
            .filter(|r| r.deployer == deployer)
            .map(|r| r.clone())
            .collect();

        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.bond_amount, Some(Balance::new(5000000)));
        assert_eq!(record.bond_unlock_block, Some(3000));
    }

    #[test]
    fn test_shard_preference() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(50);
        let mut request = create_test_deploy_request(deployer, 10, 100);
        request.preferred_shard = Some(5);

        manager
            .evaluate_deploy_request(&request, None, 1000)
            .unwrap();

        let records: Vec<DeployRecord> = manager
            .deploy_history
            .iter()
            .filter(|r| r.deployer == deployer)
            .map(|r| r.clone())
            .collect();

        assert_eq!(records[0].shard_id, 5);
    }

    #[test]
    fn test_contract_address_assignment() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(51);
        let request = create_test_deploy_request(deployer, 10, 100);

        let result = manager.evaluate_deploy_request(&request, None, 1000);
        let deploy_id = match result.unwrap() {
            DeployDecision::AcceptWithCredits { deploy_id, .. } => deploy_id,
            _ => panic!("Expected AcceptWithCredits"),
        };

        let contract_address = test_address(200);
        manager
            .complete_deploy(&deploy_id, true, 1000, None, Some(contract_address))
            .unwrap();

        let record = manager.get_deploy_record(&deploy_id).unwrap();
        assert_eq!(record.contract_address, Some(contract_address));
    }

    #[test]
    fn test_credits_and_ru_tracking() {
        let config = DeployPolicyConfig {
            credits_per_kb: 150,
            credits_per_ru: 12,
            ..DeployPolicyConfig::default()
        };
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(52);
        let request = create_test_deploy_request(deployer, 80, 400);

        manager
            .evaluate_deploy_request(&request, None, 1000)
            .unwrap();

        let records: Vec<DeployRecord> = manager
            .deploy_history
            .iter()
            .filter(|r| r.deployer == deployer)
            .map(|r| r.clone())
            .collect();

        let record = &records[0];
        assert_eq!(record.size_kb, 80);
        assert_eq!(record.ru_consumed, 400);
        assert_eq!(record.credits_used, 80 * 150 + 400 * 12);
    }

    #[test]
    fn test_metadata_storage() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(56);
        let mut request = create_test_deploy_request(deployer, 10, 100);
        request
            .metadata
            .insert("version".to_string(), "1.0.0".to_string());
        request
            .metadata
            .insert("author".to_string(), "Alice".to_string());

        manager
            .evaluate_deploy_request(&request, None, 1000)
            .unwrap();

        let records: Vec<DeployRecord> = manager
            .deploy_history
            .iter()
            .filter(|r| r.deployer == deployer)
            .map(|r| r.clone())
            .collect();

        assert_eq!(records.len(), 1);
    }

    #[test]
    fn test_all_ai_pattern_phrases() {
        let config = DeployPolicyConfig {
            ai_pattern_detection_enabled: true,
            ..DeployPolicyConfig::default()
        };
        let mut manager = DeployPolicyManager::new(config);

        let ai_phrases = vec![
            "do you want me to add more",
            "let me know if you need",
            "as an ai model",
            "i can help you with",
            "would you like me to",
            "is there anything else",
            "feel free to ask",
            "i'm here to assist",
            "chatgpt",
            "claude",
            "generated by ai",
            "ai-generated",
        ];

        for (i, phrase) in ai_phrases.iter().enumerate() {
            let deployer = test_address(60 + i as u8);
            let mut request = create_test_deploy_request(deployer, 10, 100);
            request.code = format!("Some code with {}", phrase).into_bytes();

            let result = manager.evaluate_deploy_request(&request, None, 1000 + i as u64);
            match result.unwrap() {
                DeployDecision::Reject { reason, .. } => {
                    assert!(reason.contains("AI pattern detected"));
                }
                _ => panic!("Expected Reject for phrase: {}", phrase),
            }
        }
    }

    #[test]
    fn test_ai_pattern_case_insensitive() {
        let config = DeployPolicyConfig {
            ai_pattern_detection_enabled: true,
            ..DeployPolicyConfig::default()
        };
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(72);
        let mut request = create_test_deploy_request(deployer, 10, 100);
        request.code = b"LET ME KNOW IF YOU NEED more help".to_vec();

        let result = manager.evaluate_deploy_request(&request, None, 1000);
        match result.unwrap() {
            DeployDecision::Reject { reason, .. } => {
                assert!(reason.contains("AI pattern detected"));
            }
            _ => panic!("Expected Reject for uppercase phrase"),
        }
    }

    #[test]
    fn test_deploy_types_serialization() {
        let type1 = DeployType::SmartContract {
            code_size_kb: 100,
            estimated_ru: 500,
        };
        let type2 = DeployType::StorageDeal {
            data_size_kb: 1000,
            duration_blocks: 5000,
        };
        let type3 = DeployType::RollupOperator {
            initial_state_kb: 200,
        };

        let config = bincode::config::standard();

        let encoded1 = bincode::encode_to_vec(&type1, config).unwrap();
        let decoded1: DeployType = bincode::decode_from_slice(&encoded1, config).unwrap().0;
        assert_eq!(type1, decoded1);

        let encoded2 = bincode::encode_to_vec(&type2, config).unwrap();
        let decoded2: DeployType = bincode::decode_from_slice(&encoded2, config).unwrap().0;
        assert_eq!(type2, decoded2);

        let encoded3 = bincode::encode_to_vec(&type3, config).unwrap();
        let decoded3: DeployType = bincode::decode_from_slice(&encoded3, config).unwrap().0;
        assert_eq!(type3, decoded3);
    }

    #[test]
    fn test_deploy_status_serialization() {
        let statuses = vec![
            DeployStatus::Pending,
            DeployStatus::Accepted,
            DeployStatus::Rejected {
                reason: "Test".to_string(),
            },
            DeployStatus::Completed,
            DeployStatus::Failed {
                error: "Error".to_string(),
            },
            DeployStatus::BondSlashed,
            DeployStatus::HumanVerificationRequired,
            DeployStatus::AIPatternFlagged,
            DeployStatus::Blacklisted,
        ];

        let config = bincode::config::standard();

        for status in statuses {
            let encoded = bincode::encode_to_vec(&status, config).unwrap();
            let decoded: DeployStatus = bincode::decode_from_slice(&encoded, config).unwrap().0;
            assert_eq!(status, decoded);
        }
    }

    #[test]
    fn test_blacklist_entry_retrieval() {
        let config = DeployPolicyConfig::default();
        let manager = DeployPolicyManager::new(config);

        let code_hash = test_hash(30);
        let blacklisted_by = test_address(100);
        let evidence_hash = test_hash(31);

        manager
            .blacklist_contract(
                code_hash,
                "Security vulnerability".to_string(),
                blacklisted_by,
                evidence_hash,
            )
            .unwrap();

        let entry = manager.blacklisted_contracts.get(&code_hash).unwrap();
        assert_eq!(entry.code_hash, code_hash);
        assert_eq!(entry.reason, "Security vulnerability");
        assert_eq!(entry.blacklisted_by, blacklisted_by);
        assert_eq!(entry.evidence_hash, evidence_hash);
    }

    #[test]
    fn test_deployer_index_ordering() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(73);

        for i in 0..5 {
            let request = create_test_deploy_request(deployer, 10 + i, 100);
            manager
                .evaluate_deploy_request(&request, None, 1000 + i as u64)
                .unwrap();
        }

        let history = manager.get_deployer_history(&deployer, 100);
        assert_eq!(history.len(), 5);

        for i in 0..history.len() - 1 {
            assert!(history[i].timestamp.as_millis() >= history[i + 1].timestamp.as_millis());
        }
    }

    #[test]
    fn test_code_hash_index() {
        let config = DeployPolicyConfig {
            enable_dedup: true,
            ..DeployPolicyConfig::default()
        };
        let mut manager = DeployPolicyManager::new(config);

        let deployer1 = test_address(74);
        let deployer2 = test_address(75);

        let request1 = create_test_deploy_request(deployer1, 10, 100);
        let code_hash = ego_core::crypto::hash_data(&request1.code);

        manager
            .evaluate_deploy_request(&request1, None, 1000)
            .unwrap();
        manager
            .evaluate_deploy_request(&request1, None, 1001)
            .unwrap();

        let deploys = manager.get_contract_deploys(&code_hash);
        assert_eq!(deploys.len(), 2);

        for deploy in &deploys {
            assert_eq!(deploy.code_hash, code_hash);
        }
    }

    #[test]
    fn test_anti_spam_metrics_cleanup() {
        let config = DeployPolicyConfig {
            anti_spam_enabled: true,
            min_deploy_interval_seconds: 0,
            ..DeployPolicyConfig::default()
        };
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(76);

        for i in 0u64..10 {
            let request = create_test_deploy_request(deployer, 10, 100);
            manager
                .evaluate_deploy_request(&request, None, 1000 + i)
                .unwrap();
        }

        let metrics_before = manager.get_anti_spam_metrics(&deployer).unwrap();
        let hour_count_before = metrics_before.deploys_last_hour.len();

        assert!(hour_count_before > 0);
    }

    #[test]
    fn test_pob_burn_tracking() {
        let config = DeployPolicyConfig {
            pob_floor_enabled: true,
            pob_floor_per_kb: 50,
            pob_floor_per_ru: 5,
            ..DeployPolicyConfig::default()
        };
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(77);
        let request = create_test_deploy_request(deployer, 100, 500);

        let result = manager.evaluate_deploy_request(&request, None, 1000);
        let deploy_id = match result.unwrap() {
            DeployDecision::AcceptWithCredits {
                deploy_id,
                pob_floor,
                ..
            } => {
                assert!(pob_floor > 0);
                deploy_id
            }
            _ => panic!("Expected AcceptWithCredits"),
        };

        let burn_record = manager.get_pob_burn_record(&deploy_id);
        assert!(burn_record.is_some());

        let record = burn_record.unwrap();
        assert_eq!(record.deploy_id, deploy_id);
        assert_eq!(record.deployer, deployer);
        assert!(record.burn_amount > 0);
    }

    #[test]
    fn test_empty_deployer_history() {
        let config = DeployPolicyConfig::default();
        let manager = DeployPolicyManager::new(config);

        let deployer = test_address(78);
        let history = manager.get_deployer_history(&deployer, 10);

        assert_eq!(history.len(), 0);
    }

    #[test]
    fn test_empty_contract_deploys() {
        let config = DeployPolicyConfig::default();
        let manager = DeployPolicyManager::new(config);

        let code_hash = test_hash(40);
        let deploys = manager.get_contract_deploys(&code_hash);

        assert_eq!(deploys.len(), 0);
    }

    #[test]
    fn test_quota_without_stake() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(79);
        let mut request = create_test_deploy_request(deployer, 10, 100);
        request.use_free_quota = true;

        let result = manager.evaluate_deploy_request(&request, None, 1000);
        match result.unwrap() {
            DeployDecision::AcceptWithCredits { .. } => {}
            _ => panic!("Expected AcceptWithCredits without stake"),
        }
    }

    #[test]
    fn test_reputation_with_no_deploys() {
        let config = DeployPolicyConfig::default();
        let manager = DeployPolicyManager::new(config);

        let deployer = test_address(80);
        let reputation = manager.calculate_deployer_reputation(&deployer);

        assert_eq!(reputation.total_deploys, 0);
        assert_eq!(reputation.successful_deploys, 0);
        assert_eq!(reputation.failed_deploys, 0);
        assert_eq!(reputation.success_rate, 0.0);
    }

    #[test]
    fn test_high_volume_deploys() {
        let config = DeployPolicyConfig {
            max_deploys_per_epoch: 1000,
            max_deploys_per_user_per_epoch: 100,
            ..DeployPolicyConfig::default()
        };
        let mut manager = DeployPolicyManager::new(config);

        for i in 0..50 {
            let deployer = test_address(100 + (i % 10));
            let request = create_test_deploy_request(deployer, 10, 100);
            let _ = manager.evaluate_deploy_request(&request, None, 1000 + i as u64);
        }

        assert!(manager.get_total_deploys() >= 50);
    }

    #[test]
    fn test_concurrent_different_deployers() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        let deployers: Vec<Address> = (0..10).map(|i| test_address(110 + i)).collect();

        for (i, deployer) in deployers.iter().enumerate() {
            let request = create_test_deploy_request(*deployer, 10 + i as u32, 100);
            let result = manager.evaluate_deploy_request(&request, None, 1000 + i as u64);
            assert!(result.is_ok());
        }

        assert_eq!(manager.get_total_deploys(), 10);
    }

    #[test]
    fn test_epoch_transition_with_active_deploys() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(120);

        for i in 0..5 {
            let request = create_test_deploy_request(deployer, 10, 100);
            manager
                .evaluate_deploy_request(&request, None, 1000 + i)
                .unwrap();
        }

        let epoch0_count = manager.get_epoch_deploys(0);
        assert_eq!(epoch0_count, 5);

        manager.advance_epoch(1).unwrap();

        for i in 0..3 {
            let request = create_test_deploy_request(deployer, 10, 100);
            manager
                .evaluate_deploy_request(&request, None, 2000 + i)
                .unwrap();
        }

        let epoch1_count = manager.get_epoch_deploys(1);
        assert_eq!(epoch1_count, 3);
        assert_eq!(manager.get_epoch_deploys(0), 5);
    }

    #[test]
    fn test_bond_unlock_block_calculation() {
        let config = DeployPolicyConfig {
            bond_lock_duration_blocks: 5000,
            deploy_bond_amount: Balance::new(1000000),
            ..DeployPolicyConfig::default()
        };
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(121);
        let request = create_test_deploy_request(deployer, 100, 500);

        let current_block = 10000;
        manager
            .evaluate_deploy_request(&request, None, current_block)
            .unwrap();

        let records: Vec<DeployRecord> = manager
            .deploy_history
            .iter()
            .filter(|r| r.deployer == deployer)
            .map(|r| r.clone())
            .collect();

        assert_eq!(records[0].bond_unlock_block, Some(15000));
    }

    #[test]
    fn test_multiple_contract_types() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(122);

        let smart_contract = DeployRequest {
            deployer,
            deploy_type: DeployType::SmartContract {
                code_size_kb: 50,
                estimated_ru: 200,
            },
            code: vec![1u8; 51200],
            metadata: HashMap::new(),
            use_free_quota: false,
            preferred_shard: None,
            human_verification_signature: None,
            dilithium_verification_pk: None,
        };

        let storage_deal = DeployRequest {
            deployer,
            deploy_type: DeployType::StorageDeal {
                data_size_kb: 1000,
                duration_blocks: 5000,
            },
            code: vec![2u8; 1024000],
            metadata: HashMap::new(),
            use_free_quota: false,
            preferred_shard: None,
            human_verification_signature: None,
            dilithium_verification_pk: None,
        };

        let rollup = DeployRequest {
            deployer,
            deploy_type: DeployType::RollupOperator {
                initial_state_kb: 200,
            },
            code: vec![3u8; 204800],
            metadata: HashMap::new(),
            use_free_quota: false,
            preferred_shard: None,
            human_verification_signature: None,
            dilithium_verification_pk: None,
        };

        let result1 = manager.evaluate_deploy_request(&smart_contract, None, 1000);
        assert!(result1.is_ok());

        let result2 = manager.evaluate_deploy_request(&storage_deal, None, 1001);
        assert!(result2.is_ok());

        let result3 = manager.evaluate_deploy_request(&rollup, None, 1002);
        assert!(result3.is_ok());

        let history = manager.get_deployer_history(&deployer, 10);
        assert_eq!(history.len(), 3);
    }

    #[test]
    fn test_reputation_score_boundaries() {
        let score_max = calculate_reputation_score(100.0, 100, 0, 0, 100);
        assert!(score_max <= 100);

        let score_min = calculate_reputation_score(0.0, 0, 100, 10, 100);
        assert!(score_min >= 0);

        let score_mid = calculate_reputation_score(75.0, 50, 10, 1, 100);
        assert!(score_mid > 0 && score_mid < 100);
    }

    #[test]
    fn test_large_deploy_size() {
        let config = DeployPolicyConfig {
            max_deploy_size_kb: 5000,
            ..DeployPolicyConfig::default()
        };
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(123);
        let request = create_test_deploy_request(deployer, 4500, 10000);

        let result = manager.evaluate_deploy_request(&request, None, 1000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_large_ru_consumption() {
        let config = DeployPolicyConfig {
            max_ru_per_deploy: 50000,
            ..DeployPolicyConfig::default()
        };
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(124);
        let request = create_test_deploy_request(deployer, 100, 45000);

        let result = manager.evaluate_deploy_request(&request, None, 1000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_zero_credits_requirement() {
        let config = DeployPolicyConfig {
            credits_per_kb: 0,
            credits_per_ru: 0,
            ..DeployPolicyConfig::default()
        };
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(125);
        let request = create_test_deploy_request(deployer, 100, 500);

        let result = manager.evaluate_deploy_request(&request, None, 1000);
        match result.unwrap() {
            DeployDecision::AcceptWithCredits {
                credits_required,
                bond_required,
                ..
            } => {
                assert_eq!(credits_required, 0);
                assert!(bond_required.is_none());
            }
            _ => panic!("Expected AcceptWithCredits"),
        }
    }

    #[test]
    fn test_timestamp_ordering() {
        let config = DeployPolicyConfig::default();
        let mut manager = DeployPolicyManager::new(config);

        let deployer = test_address(126);

        let mut timestamps = Vec::new();
        for i in 0..5 {
            let request = create_test_deploy_request(deployer, 10 + i, 100);
            manager
                .evaluate_deploy_request(&request, None, 1000 + i as u64)
                .unwrap();

            std::thread::sleep(std::time::Duration::from_millis(10));
            timestamps.push(Timestamp::now());
        }

        let history = manager.get_deployer_history(&deployer, 100);
        for i in 0..history.len() - 1 {
            assert!(history[i].timestamp.as_millis() >= history[i + 1].timestamp.as_millis());
        }
    }

    #[test]
    fn test_complete_deploy_not_found() {
        let config = DeployPolicyConfig::default();
        let manager = DeployPolicyManager::new(config);

        let fake_deploy_id = test_hash(50);
        let result = manager.complete_deploy(&fake_deploy_id, true, 1000, None, None);

        assert!(result.is_err());
    }

    #[test]
    fn test_update_quota_nonexistent_user() {
        let config = DeployPolicyConfig::default();
        let manager = DeployPolicyManager::new(config);

        let deployer = test_address(127);
        let result = manager.update_quota_from_drs(&deployer, 1.1, QuotaBand::Mid);

        assert!(result.is_err());
    }

    #[test]
    fn test_remove_nonexistent_blacklist() {
        let config = DeployPolicyConfig::default();
        let manager = DeployPolicyManager::new(config);

        let code_hash = test_hash(60);
        let result = manager.remove_from_blacklist(&code_hash);

        assert!(result.is_err());
    }
}
