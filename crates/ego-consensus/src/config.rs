use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoCConsensusConfig {
    pub beacon_config: BeaconConfig,
    pub witness_config: WitnessConfig,
    pub aggregator_config: AggregatorConfig,
    pub validation_config: ValidationConfig,
    pub network_config: NetworkConfig,
    pub drs_config: DRSConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconConfig {
    pub beacon_interval_ms: u64,
    pub tx_window_ms: u64,
    pub max_tx_power_dbm: i16,
    pub authorized_frequencies: Vec<u32>,
    pub use_side_channel: bool,
    pub co_beacon_method: CoBeaconMethod,
    pub cellular_safe_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessConfig {
    pub scan_rate_hz: f32,
    pub batch_interval_seconds: u64,
    pub max_reports_per_batch: usize,
    pub enable_compression: bool,
    pub rate_limit_per_hour: u32,
    pub dedup_window_minutes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatorConfig {
    pub coverage_h3_resolution: u8,
    pub min_witnesses: usize,
    pub max_witnesses: usize,
    pub witness_collection_window_ms: u64,
    pub compression_threshold_bytes: usize,
    pub daily_anchor_interval_hours: u64,
    pub co_beacon_min_fraction: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationConfig {
    pub rf_validation: RFValidationConfig,
    pub geo_validation: GeoValidationConfig,
    pub time_validation: TimeValidationConfig,
    pub fraud_detection_sensitivity: f32,
    pub strict_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RFValidationConfig {
    pub min_rsrp_dbm: i16,
    pub max_rsrp_dbm: i16,
    pub min_rsrq_db: i16,
    pub max_rsrq_db: i16,
    pub min_sinr_db: i16,
    pub max_sinr_db: i16,
    pub max_timing_advance: u32,
    pub enable_path_loss_validation: bool,
    pub path_loss_tolerance_db: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoValidationConfig {
    pub max_distance_km: f32,
    pub min_distance_m: f32,
    pub gps_accuracy_threshold_m: f32,
    pub enable_h3_validation: bool,
    pub h3_resolution: u8,
    pub neighbor_ring_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeValidationConfig {
    pub max_clock_drift_ms: u64,
    pub beacon_timeout_ms: u64,
    pub witness_window_ms: u64,
    pub enable_ntp_sync: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub topics: TopicConfig,
    pub peer_limits: PeerLimits,
    pub rate_limits: RateLimits,
    pub optimization: NetworkOptimization,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopicConfig {
    pub topic_prefix: String,
    pub role_gated_topics: bool,
    pub subscription_timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerLimits {
    pub max_beacon_peers: usize,
    pub max_witness_peers: usize,
    pub max_aggregator_peers: usize,
    pub connection_timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimits {
    pub beacon_announcements_per_hour: u32,
    pub witness_reports_per_hour: u32,
    pub aggregator_bundles_per_hour: u32,
    pub burst_allowance: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkOptimization {
    pub prefer_wired_for_bundles: bool,
    pub cellular_for_meta_events_only: bool,
    pub adaptive_rate_limiting: bool,
    pub off_peak_batching: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DRSConfig {
    pub update_interval_epochs: u64,
    pub min_participation_score: f64,
    pub fraud_penalty_multiplier: f64,
    pub honest_reward_multiplier: f64,
    pub enable_auto_slashing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CoBeaconMethod {
    BLE,
    WiFi,
    SideChannel,
    Embedded,
}

impl Default for PoCConsensusConfig {
    fn default() -> Self {
        Self {
            beacon_config: BeaconConfig::default(),
            witness_config: WitnessConfig::default(),
            aggregator_config: AggregatorConfig::default(),
            validation_config: ValidationConfig::default(),
            network_config: NetworkConfig::default(),
            drs_config: DRSConfig::default(),
        }
    }
}

impl Default for BeaconConfig {
    fn default() -> Self {
        Self {
            beacon_interval_ms: 30_000,
            tx_window_ms: 5_000,
            max_tx_power_dbm: 23,
            authorized_frequencies: vec![3500, 3600, 3700],
            use_side_channel: true,
            co_beacon_method: CoBeaconMethod::BLE,
            cellular_safe_mode: true,
        }
    }
}

impl Default for WitnessConfig {
    fn default() -> Self {
        Self {
            scan_rate_hz: 0.75,
            batch_interval_seconds: 8,
            max_reports_per_batch: 10,
            enable_compression: true,
            rate_limit_per_hour: 120,
            dedup_window_minutes: 5,
        }
    }
}

impl Default for AggregatorConfig {
    fn default() -> Self {
        Self {
            coverage_h3_resolution: 9,
            min_witnesses: 3,
            max_witnesses: 14,
            witness_collection_window_ms: 10_000,
            compression_threshold_bytes: 1024,
            daily_anchor_interval_hours: 24,
            co_beacon_min_fraction: 0.5,
        }
    }
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            rf_validation: RFValidationConfig::default(),
            geo_validation: GeoValidationConfig::default(),
            time_validation: TimeValidationConfig::default(),
            fraud_detection_sensitivity: 0.8,
            strict_mode: false,
        }
    }
}

impl Default for RFValidationConfig {
    fn default() -> Self {
        Self {
            min_rsrp_dbm: -140,
            max_rsrp_dbm: -44,
            min_rsrq_db: -19,
            max_rsrq_db: -3,
            min_sinr_db: -20,
            max_sinr_db: 30,
            max_timing_advance: 1282,
            enable_path_loss_validation: true,
            path_loss_tolerance_db: 10.0,
        }
    }
}

impl Default for GeoValidationConfig {
    fn default() -> Self {
        Self {
            max_distance_km: 50.0,
            min_distance_m: 100.0,
            gps_accuracy_threshold_m: 10.0,
            enable_h3_validation: true,
            h3_resolution: 9,
            neighbor_ring_count: 2,
        }
    }
}

impl Default for TimeValidationConfig {
    fn default() -> Self {
        Self {
            max_clock_drift_ms: 5_000,
            beacon_timeout_ms: 30_000,
            witness_window_ms: 10_000,
            enable_ntp_sync: true,
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            topics: TopicConfig::default(),
            peer_limits: PeerLimits::default(),
            rate_limits: RateLimits::default(),
            optimization: NetworkOptimization::default(),
        }
    }
}

impl Default for TopicConfig {
    fn default() -> Self {
        Self {
            topic_prefix: "ego/poc".to_string(),
            role_gated_topics: true,
            subscription_timeout_ms: 30_000,
        }
    }
}

impl Default for PeerLimits {
    fn default() -> Self {
        Self {
            max_beacon_peers: 50,
            max_witness_peers: 100,
            max_aggregator_peers: 20,
            connection_timeout_ms: 30_000,
        }
    }
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            beacon_announcements_per_hour: 120,
            witness_reports_per_hour: 120,
            aggregator_bundles_per_hour: 60,
            burst_allowance: 10,
        }
    }
}

impl Default for NetworkOptimization {
    fn default() -> Self {
        Self {
            prefer_wired_for_bundles: true,
            cellular_for_meta_events_only: true,
            adaptive_rate_limiting: true,
            off_peak_batching: true,
        }
    }
}

impl Default for DRSConfig {
    fn default() -> Self {
        Self {
            update_interval_epochs: 1,
            min_participation_score: 0.7,
            fraud_penalty_multiplier: 2.0,
            honest_reward_multiplier: 1.1,
            enable_auto_slashing: true,
        }
    }
}
