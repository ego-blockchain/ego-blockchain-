use crate::error::{RollupError, RollupResult};
use ego_core::Address;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollupConfig {
    pub chain_id: u64,
    pub l1_contract: Address,
    pub operator: OperatorConfig,
    pub da: DAConfig,
    pub fraud_proofs: FraudProofConfig,
    pub network: NetworkConfig,
    pub performance: PerformanceConfig,
    pub five_g: FiveGConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorConfig {
    pub address: Address,
    pub bond_amount: u64,
    pub max_batch_size: u32,
    pub batch_timeout_secs: u64,
    pub commit_frequency_secs: u64,
    pub auto_batch: bool,
    pub l1_gas_price: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DAConfig {
    pub k: usize,
    pub m: usize,
    pub n: usize,
    pub chunk_size: usize,
    pub sample_size: usize,
    pub enable_compression: bool,
    pub compression_level: i32,
    pub storage_duration: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudProofConfig {
    pub challenge_period: u64,
    pub response_window: u64,
    pub min_confidence: f64,
    pub max_age_hours: u64,
    pub min_failure_rate: f64,
    pub enable_snark_aggregation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub listen_port: u16,
    pub bootstrap_peers: Vec<String>,
    pub max_peers: u32,
    pub connection_timeout: Duration,
    pub enable_mdns: bool,
    pub gossip: GossipConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipConfig {
    pub heartbeat_interval: Duration,
    pub max_message_size: usize,
    pub duplicate_cache_time: Duration,
    pub validation_mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub worker_threads: usize,
    pub batch_parallelism: usize,
    pub state_cache_size: usize,
    pub tx_pool_size: usize,
    pub enable_metrics: bool,
    pub metrics_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiveGConfig {
    pub enabled: bool,
    pub slice_id: Option<String>,
    pub qos_class: u8,
    pub latency_target_ms: u32,
    pub bandwidth_mbps: u32,
    pub enable_edge_computing: bool,
    pub edge_nodes: Vec<String>,
}

impl Default for RollupConfig {
    fn default() -> Self {
        Self {
            chain_id: 1,
            l1_contract: Address::new([0u8; 20]),
            operator: OperatorConfig::default(),
            da: DAConfig::default(),
            fraud_proofs: FraudProofConfig::default(),
            network: NetworkConfig::default(),
            performance: PerformanceConfig::default(),
            five_g: FiveGConfig::default(),
        }
    }
}

impl Default for OperatorConfig {
    fn default() -> Self {
        Self {
            address: Address::new([0u8; 20]),
            bond_amount: 1_000_000,
            max_batch_size: 1000,
            batch_timeout_secs: 30,
            commit_frequency_secs: 300,
            auto_batch: true,
            l1_gas_price: 20_000_000_000,
        }
    }
}

impl Default for DAConfig {
    fn default() -> Self {
        Self {
            k: 128,
            m: 64,
            n: 192,
            chunk_size: 65536,
            sample_size: 16,
            enable_compression: true,
            compression_level: 6,
            storage_duration: 7200,
        }
    }
}

impl Default for FraudProofConfig {
    fn default() -> Self {
        Self {
            challenge_period: 1000,
            response_window: 100,
            min_confidence: 0.8,
            max_age_hours: 24,
            min_failure_rate: 0.6,
            enable_snark_aggregation: false,
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_port: 9100,
            bootstrap_peers: vec![],
            max_peers: 50,
            connection_timeout: Duration::from_secs(30),
            enable_mdns: true,
            gossip: GossipConfig::default(),
        }
    }
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval: Duration::from_secs(10),
            max_message_size: 2 * 1024 * 1024,
            duplicate_cache_time: Duration::from_secs(120),
            validation_mode: "strict".to_string(),
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            worker_threads: num_cpus::get(),
            batch_parallelism: 4,
            state_cache_size: 10000,
            tx_pool_size: 50000,
            enable_metrics: true,
            metrics_port: 9090,
        }
    }
}

impl Default for FiveGConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            slice_id: None,
            qos_class: 1,
            latency_target_ms: 10,
            bandwidth_mbps: 100,
            enable_edge_computing: false,
            edge_nodes: vec![],
        }
    }
}

impl RollupConfig {
    pub fn validate(&self) -> RollupResult<()> {
        if self.da.k + self.da.m != self.da.n {
            return Err(RollupError::ConfigError(
                "DA parameters: k + m must equal n".to_string(),
            ));
        }

        if self.da.k == 0 || self.da.m == 0 {
            return Err(RollupError::ConfigError(
                "DA parameters: k and m must be > 0".to_string(),
            ));
        }

        if self.da.sample_size > self.da.k {
            return Err(RollupError::ConfigError(
                "DA sample size cannot exceed k".to_string(),
            ));
        }

        if self.operator.bond_amount < 100_000 {
            return Err(RollupError::ConfigError(
                "Operator bond must be at least 100K EGOC".to_string(),
            ));
        }

        if self.operator.max_batch_size == 0 {
            return Err(RollupError::ConfigError(
                "Max batch size must be > 0".to_string(),
            ));
        }

        if self.fraud_proofs.min_confidence < 0.5 || self.fraud_proofs.min_confidence > 1.0 {
            return Err(RollupError::ConfigError(
                "Fraud proof confidence must be between 0.5 and 1.0".to_string(),
            ));
        }

        if self.fraud_proofs.challenge_period < 100 {
            return Err(RollupError::ConfigError(
                "Challenge period must be at least 100 blocks".to_string(),
            ));
        }

        if self.five_g.enabled {
            if self.five_g.latency_target_ms == 0 {
                return Err(RollupError::ConfigError(
                    "5G latency target must be > 0".to_string(),
                ));
            }

            if self.five_g.bandwidth_mbps == 0 {
                return Err(RollupError::ConfigError(
                    "5G bandwidth allocation must be > 0".to_string(),
                ));
            }
        }

        Ok(())
    }

    pub fn from_file(path: &str) -> RollupResult<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| RollupError::ConfigError(format!("Failed to read config file: {}", e)))?;

        let config: Self = toml::from_str(&content)
            .map_err(|e| RollupError::ConfigError(format!("Failed to parse config: {}", e)))?;

        config.validate()?;
        Ok(config)
    }

    pub fn to_file(&self, path: &str) -> RollupResult<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| RollupError::ConfigError(format!("Failed to serialize config: {}", e)))?;

        std::fs::write(path, content)
            .map_err(|e| RollupError::ConfigError(format!("Failed to write config file: {}", e)))?;

        Ok(())
    }

    pub fn is_5g_optimized(&self) -> bool {
        self.five_g.enabled && self.five_g.slice_id.is_some()
    }

    pub fn target_latency(&self) -> Duration {
        if self.five_g.enabled {
            Duration::from_millis(self.five_g.latency_target_ms as u64)
        } else {
            Duration::from_millis(250)
        }
    }

    pub fn da_redundancy_factor(&self) -> f64 {
        self.da.n as f64 / self.da.k as f64
    }

    pub fn expected_chunk_serve_time(&self) -> Duration {
        if self.five_g.enabled {
            Duration::from_millis(300)
        } else {
            Duration::from_millis(1000)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_validation() {
        let config = RollupConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_da_params_validation() {
        let mut config = RollupConfig::default();
        config.da.k = 100;
        config.da.m = 50;
        config.da.n = 140;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_5g_optimization_detection() {
        let mut config = RollupConfig::default();
        assert!(!config.is_5g_optimized());

        config.five_g.enabled = true;
        config.five_g.slice_id = Some("slice-1".to_string());
        assert!(config.is_5g_optimized());
    }

    #[test]
    fn test_da_redundancy_calculation() {
        let config = RollupConfig::default();
        let redundancy = config.da_redundancy_factor();
        assert_eq!(redundancy, 192.0 / 128.0);
    }

    #[test]
    fn test_target_latency() {
        let mut config = RollupConfig::default();
        assert_eq!(config.target_latency(), Duration::from_millis(250));

        config.five_g.enabled = true;
        config.five_g.latency_target_ms = 10;
        assert_eq!(config.target_latency(), Duration::from_millis(10));
    }
}
