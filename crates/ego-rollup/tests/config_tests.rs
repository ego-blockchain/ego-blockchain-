#[cfg(test)]
mod config_tests {
    use ego_core::{Address, Balance, ShardId};
    use ego_rollup::config::RollupConfig;
    use std::path::PathBuf;

    fn make_valid_config() -> RollupConfig {
        let mut config = RollupConfig::default();
        config.operator.attestation_required = false;
        config
    }

    #[test]
    fn test_default_config_valid() {
        let config = make_valid_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_chain_id() {
        let mut config = make_valid_config();
        config.chain_id = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_invalid_network_id() {
        let mut config = make_valid_config();
        config.network_id = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_empty_rollup_id() {
        let mut config = make_valid_config();
        config.rollup_id = "".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_zero_protocol_version() {
        let mut config = make_valid_config();
        config.protocol_version = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_da_config_invalid_k_m_n() {
        let mut config = make_valid_config();
        config.da.k = 100;
        config.da.m = 50;
        config.da.n = 140;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_da_config_valid_k_m_n() {
        let mut config = make_valid_config();
        config.da.k = 128;
        config.da.m = 64;
        config.da.n = 192;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_operator_bond_too_low() {
        let mut config = make_valid_config();
        config.operator.bond_amount = Balance::new(1_000_000);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_operator_valid_keys() {
        let mut config = make_valid_config();
        config.operator.dilithium_pk = vec![1u8; 1312];
        config.operator.mlkem_pk = vec![2u8; 1184];
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_fraud_proof_confidence_out_of_range() {
        let mut config = make_valid_config();
        config.fraud_proofs.min_confidence = 1.1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_5g_config_valid() {
        let mut config = make_valid_config();
        config.five_g.enabled = true;
        config.five_g.latency_target_ms = 5;
        config.five_g.bandwidth_mbps = 100;
        config.five_g.cellular_safe_mode = true;
        config.five_g.max_cellular_data_gb_per_month = 10;
        config.five_g.spectrum_config.bandwidth_mhz = 10;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_security_pq_only_mode_requires_dilithium() {
        let mut config = make_valid_config();
        config.security.pq_only_mode = true;
        config.security.require_dilithium = false;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_storage_config_valid() {
        let mut config = make_valid_config();
        config.storage.data_dir = PathBuf::from("/tmp/rollup");
        config.storage.max_storage_gb = 10;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_sharding_config_valid() {
        let mut config = make_valid_config();
        config.sharding.enabled = true;
        config.sharding.num_shards = 2;
        config.sharding.shard_ids = vec![ShardId::new(0).unwrap(), ShardId::new(1).unwrap()];
        config.sharding.cross_shard_enabled = true;
        config.sharding.cross_shard_receipt_timeout_blocks = 100;
        config.sharding.enable_global_finality = true;
        config.sharding.finality_committee_size = 64;
        config.sharding.max_cross_shard_receipts_per_epoch = 1000;
        config.sharding.receipt_deadline_epochs = 100;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_proofs_config_valid() {
        let mut config = make_valid_config();
        config.proofs.post_enabled = true;
        config.proofs.porep_enabled = true;
        config.proofs.poc_enabled = false;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_drs_weights_sum_to_one() {
        let mut config = make_valid_config();
        config.drs.w_uptime = 0.2;
        config.drs.w_post_pass = 0.4;
        config.drs.w_inv_latency = 0.1;
        config.drs.w_poc = 0.2;
        config.drs.w_serve = 0.1;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_economics_bucket_percentages_sum_to_100() {
        let mut config = make_valid_config();
        config.economics.storage_bucket_percentage = 4000;
        config.economics.consensus_bucket_percentage = 3000;
        config.economics.coverage_bucket_percentage = 2000;
        config.economics.dao_bucket_percentage = 1000;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_cellular_config_valid() {
        let mut config = make_valid_config();
        config.cellular.enabled = true;
        config.cellular.safe_mode_default = true;
        config.cellular.max_monthly_usage_gb = 10;
        config.cellular.throttle_threshold_gb = 8;
        config.cellular.proof_rate_hz = 0.5;
        config.cellular.proof_batch_size = 100;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_deploy_policy_valid() {
        let mut config = make_valid_config();
        config.deploy_policy.enabled = true;
        config.deploy_policy.credits_per_kb = 100;
        config.deploy_policy.credits_per_ru = 10;
        config.deploy_policy.max_deploy_size_kb = 1024;
        config.deploy_policy.max_ru_per_deploy = 10000;
        config.deploy_policy.max_deploys_per_epoch = 1000;
        config.deploy_policy.bond_slash_threshold = 1;
        config.deploy_policy.code_hash_cache_size = 1000;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_device_config_valid() {
        let mut config = make_valid_config();
        config.device.ego_device_only = true;
        config.device.hardware_requirements.min_ram_gb = 4;
        config.device.hardware_requirements.min_storage_gb = 64;
        config.device.provisioning.periodic_re_attestation_enabled = true;
        config.device.provisioning.re_attestation_interval_blocks = 1000;
        config.device.lifecycle.firmware_signing_threshold = 2;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_create_test_config() {
        let config = RollupConfig::create_test_config();
        assert_eq!(config.chain_id, 99);
        assert_eq!(config.sharding.num_shards, 2);
        assert!(!config.storage.enable_pruning);
    }

    #[test]
    fn test_create_production_config() {
        let config = RollupConfig::create_production_config();
        assert!(config.security.pq_only_mode);
        assert!(config.proofs.poc_enabled);
        assert!(config.deploy_policy.human_verification_required);
    }

    #[test]
    fn test_create_5g_optimized_config() {
        let config = RollupConfig::create_5g_optimized_config();
        assert!(config.five_g.enabled);
        assert!(config.five_g.urllc_enabled);
        assert!(config.cellular.safe_mode_default);
    }

    #[test]
    fn test_create_ego_device_config() {
        let config = RollupConfig::create_ego_device_config();
        assert!(config.device.ego_device_only);
        assert!(config.security.enable_tpm);
        assert!(config.security.enable_secure_boot);
    }

    #[test]
    fn test_is_5g_optimized() {
        let mut config = make_valid_config();
        config.five_g.enabled = true;
        config.five_g.slice_id = Some("slice-1".to_string());
        assert!(config.is_5g_optimized());
    }

    #[test]
    fn test_is_cellular_safe() {
        let mut config = make_valid_config();
        config.five_g.enabled = true;
        config.five_g.cellular_safe_mode = true;
        assert!(config.is_cellular_safe());
    }

    #[test]
    fn test_estimate_monthly_cellular_usage_mb() {
        let config = make_valid_config();
        let usage = config.estimate_monthly_cellular_usage_mb();
        assert!(usage > 0);
    }

    #[test]
    fn test_detect_ai_filler() {
        let config = make_valid_config();
        let filler = "as an ai model, I can help you";
        assert!(config.detect_ai_filler(filler));
    }

    #[test]
    fn test_get_gossip_topics_sharding() {
        let mut config = make_valid_config();
        config.sharding.enabled = true;
        config.sharding.shard_ids = vec![ShardId::new(0).unwrap()];
        let topics = config.get_gossip_topics();
        assert!(topics.contains(&"ego/shard/0/tx".to_string()));
    }

    #[test]
    fn test_get_drs_weights() {
        let config = make_valid_config();
        let weights = config.get_drs_weights();
        assert_eq!(weights.get("uptime").copied(), Some(0.2));
        assert_eq!(weights.get("post_pass").copied(), Some(0.4));
    }

    #[test]
    fn test_get_emission_bucket_percentages() {
        let config = make_valid_config();
        let buckets = config.get_emission_bucket_percentages();
        assert_eq!(buckets.get("storage").copied(), Some(4000));
        assert_eq!(buckets.get("consensus").copied(), Some(3000));
    }

    #[test]
    fn test_calculate_deploy_credits_needed() {
        let config = make_valid_config();
        let credits = config.calculate_deploy_credits_needed(10, 100);
        assert_eq!(credits, 10 * 100 + 100 * 10);
    }

    #[test]
    fn test_optimize_for_5g() {
        let mut config = make_valid_config();
        config.five_g.enabled = true;
        config.optimize_for_5g();
        assert!(config.operator.max_batch_size <= 500);
        assert!(config.operator.batch_timeout_secs <= 10);
    }

    #[test]
    fn test_optimize_for_cellular() {
        let mut config = make_valid_config();
        config.cellular.safe_mode_default = true;
        config.optimize_for_cellular();
        assert!(config.operator.max_batch_size <= 250);
        assert!(config.operator.compression_level == 9);
    }

    #[test]
    fn test_to_shard_config() {
        let config = make_valid_config();
        let shard_id = ShardId::new(0).unwrap();
        let shard_config = config.to_shard_config(shard_id);
        assert_eq!(shard_config.shard_id, shard_id);
        assert_eq!(shard_config.committee_size, 64);
    }

    #[test]
    fn test_to_shard_storage_config() {
        let config = make_valid_config();
        let storage_config = config.to_shard_storage_config();
        assert_eq!(
            storage_config.max_storage_per_node,
            100 * 1024 * 1024 * 1024
        );
        assert_eq!(storage_config.erasure_coding.data_chunks, 128);
    }

    #[test]
    fn test_to_pob_config() {
        let config = make_valid_config();
        let pob_config = config.to_pob_config();
        assert_eq!(pob_config.storage_credit_price, 1000);
        assert_eq!(pob_config.deploy_credit_price, 500);
    }

    #[test]
    fn test_to_shard_drs_config() {
        let config = make_valid_config();
        let drs_config = config.to_shard_drs_config();
        assert_eq!(drs_config.weight_uptime, 0.2);
        assert_eq!(drs_config.weight_post_pass, 0.4);
    }

    #[test]
    fn test_to_cellular_safe_config() {
        let config = make_valid_config();
        let cellular_config = config.to_cellular_safe_config();
        assert_eq!(cellular_config.max_monthly_data_gb, 5);
        assert!(cellular_config.enabled);
    }

    #[test]
    fn test_to_pq_transition_config() {
        let config = make_valid_config();
        let pq_config = config.to_pq_transition_config();
        assert_eq!(pq_config.pq_only_required, false);
        assert!(!pq_config.supported_algorithms.is_empty());
    }

    #[test]
    fn test_to_deploy_policy_manager_config() {
        let config = make_valid_config();
        let deploy_config = config.to_deploy_policy_manager_config();
        assert_eq!(deploy_config.free_deploys_per_epoch, 5);
        assert_eq!(deploy_config.credits_per_kb, 100);
    }

    #[test]
    fn test_to_drs_config() {
        let config = make_valid_config();
        let drs_config = config.to_drs_config();
        assert_eq!(drs_config.w_uptime, 0.2);
        assert_eq!(drs_config.m_min, 0.7);
    }

    #[test]
    fn test_to_state_pruning_config() {
        let config = make_valid_config();
        let pruning_config = config.to_state_pruning_config();
        assert!(pruning_config.enabled);
        assert_eq!(pruning_config.keep_epochs, 100);
    }

    #[test]
    fn test_get_supported_algorithms() {
        let config = make_valid_config();
        let algs = config.get_supported_algorithms();
        assert!(!algs.is_empty());
    }

    #[test]
    fn test_get_required_algorithms() {
        let config = make_valid_config();
        let algs = config.get_required_algorithms();
        assert!(!algs.is_empty());
    }

    #[test]
    fn test_get_post_sla_duration() {
        let config = make_valid_config();
        let duration = config.get_post_sla_duration();
        assert_eq!(duration.as_millis(), 8000);
    }

    #[test]
    fn test_get_porep_sector_size_bytes() {
        let config = make_valid_config();
        let size = config.get_porep_sector_size_bytes();
        assert_eq!(size, 32 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_get_operator_address() {
        let config = make_valid_config();
        let address = config.get_operator_address();
        assert_eq!(address, Address::new([0u8; 20]));
    }

    #[test]
    fn test_get_operator_bond() {
        let config = make_valid_config();
        let bond = config.get_operator_bond();
        assert_eq!(bond, Balance::new(1_000_000_000_000_000_000));
    }
}
