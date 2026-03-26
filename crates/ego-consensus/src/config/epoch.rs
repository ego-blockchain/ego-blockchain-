use ego_core::{Hash, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochConfig {

    pub config_by_epoch: BTreeMap<u64, ThresholdConfig>,

    pub latest_block_hash: Option<Hash>,

    pub last_updated: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {

    pub epoch: u64,

    pub quality_thresholds: QualityThresholds,

    pub drs_thresholds: DRSThresholds,

    pub consensus_thresholds: ConsensusThresholds,

    pub fraud_thresholds: FraudThresholds,

    pub config_block_hash: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityThresholds {

    pub min_quality_score: f64,

    pub min_nonce_binding_fraction: f64,

    pub max_path_loss_rmse: f64,

    pub min_coherence_score: f64,

    pub max_fraud_likelihood: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DRSThresholds {

    pub min_participation_score: f64,

    pub high_quota_threshold: f64,

    pub low_quota_threshold: f64,

    pub min_beacon_authorization: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusThresholds {

    pub min_consensus_threshold: f64,

    pub drs_vote_multiplier: f64,

    pub min_witness_count: usize,

    pub max_validation_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudThresholds {

    pub detection_sensitivity: f64,

    pub slashing_confidence_threshold: f64,

    pub co_beacon_min_fraction: f64,

    pub timing_fingerprint_match_threshold: f64,

    pub relay_probability_threshold: f64,
}

impl EpochConfig {

    pub fn new() -> Self {
        let mut config_by_epoch = BTreeMap::new();

        config_by_epoch.insert(0, ThresholdConfig::default());

        Self {
            config_by_epoch,
            latest_block_hash: None,
            last_updated: Timestamp::now(),
        }
    }

    pub fn get_config(&self, epoch: u64) -> &ThresholdConfig {

        if let Some(config) = self.config_by_epoch.get(&epoch) {
            return config;
        }

        self.config_by_epoch
            .range(..=epoch)
            .next_back()
            .map(|(_, config)| config)
            .unwrap_or_else(|| {

                self.config_by_epoch.get(&0).expect("Default config missing")
            })
    }

    pub fn update_epoch_config(&mut self, config: ThresholdConfig) {
        self.config_by_epoch.insert(config.epoch, config);
        self.last_updated = Timestamp::now();
    }

    pub fn update_block_hash(&mut self, block_hash: Hash) {
        self.latest_block_hash = Some(block_hash);
        self.last_updated = Timestamp::now();
    }

    pub fn get_current_config(&self) -> &ThresholdConfig {
        let current_epoch = Timestamp::now().as_secs() / 3600;
        self.get_config(current_epoch)
    }

    pub fn is_valid_for_block(&self, block_hash: &Hash) -> bool {
        self.latest_block_hash.as_ref() == Some(block_hash)
    }

    pub fn cleanup_old_configs(&mut self) {
        let current_epoch = Timestamp::now().as_secs() / 3600;
        let cutoff_epoch = current_epoch.saturating_sub(100);

        self.config_by_epoch = self.config_by_epoch.split_off(&cutoff_epoch);
    }
}

impl Default for EpochConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self {
            epoch: 0,
            quality_thresholds: QualityThresholds::default(),
            drs_thresholds: DRSThresholds::default(),
            consensus_thresholds: ConsensusThresholds::default(),
            fraud_thresholds: FraudThresholds::default(),
            config_block_hash: Hash::new([0u8; 32]),
        }
    }
}

impl Default for QualityThresholds {
    fn default() -> Self {
        Self {
            min_quality_score: 0.5,
            min_nonce_binding_fraction: 0.6,
            max_path_loss_rmse: 10.0,
            min_coherence_score: 0.5,
            max_fraud_likelihood: 0.8,
        }
    }
}

impl Default for DRSThresholds {
    fn default() -> Self {
        Self {
            min_participation_score: 0.5,
            high_quota_threshold: 0.8,
            low_quota_threshold: 0.5,
            min_beacon_authorization: 0.7,
        }
    }
}

impl Default for ConsensusThresholds {
    fn default() -> Self {
        Self {
            min_consensus_threshold: 0.67,
            drs_vote_multiplier: 0.6,
            min_witness_count: 3,
            max_validation_time_ms: 30_000,
        }
    }
}

impl Default for FraudThresholds {
    fn default() -> Self {
        Self {
            detection_sensitivity: 0.8,
            slashing_confidence_threshold: 0.8,
            co_beacon_min_fraction: 0.5,
            timing_fingerprint_match_threshold: 0.8,
            relay_probability_threshold: 0.7,
        }
    }
}

pub trait EpochConfigProvider {

    fn get_epoch_config(&self) -> &EpochConfig;

    fn get_thresholds_for_epoch(&self, epoch: u64) -> &ThresholdConfig {
        self.get_epoch_config().get_config(epoch)
    }

    fn get_current_thresholds(&self) -> &ThresholdConfig {
        self.get_epoch_config().get_current_config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_config_creation() {
        let config = EpochConfig::new();
        assert!(config.config_by_epoch.contains_key(&0));

        let default_config = config.get_config(0);
        assert_eq!(default_config.quality_thresholds.min_quality_score, 0.5);
        assert_eq!(default_config.drs_thresholds.min_participation_score, 0.5);
    }

    #[test]
    fn test_epoch_config_fallback() {
        let mut config = EpochConfig::new();

        let fallback = config.get_config(100);
        assert_eq!(fallback.epoch, 0);

        let mut epoch_50_config = ThresholdConfig::default();
        epoch_50_config.epoch = 50;
        epoch_50_config.quality_thresholds.min_quality_score = 0.7;
        config.update_epoch_config(epoch_50_config);

        let fallback_50 = config.get_config(75);
        assert_eq!(fallback_50.epoch, 50);
        assert_eq!(fallback_50.quality_thresholds.min_quality_score, 0.7);
    }

    #[test]
    fn test_threshold_defaults() {
        let quality = QualityThresholds::default();
        assert_eq!(quality.min_quality_score, 0.5);
        assert_eq!(quality.min_nonce_binding_fraction, 0.6);
        assert_eq!(quality.max_path_loss_rmse, 10.0);

        let drs = DRSThresholds::default();
        assert_eq!(drs.min_participation_score, 0.5);
        assert_eq!(drs.high_quota_threshold, 0.8);

        let consensus = ConsensusThresholds::default();
        assert_eq!(consensus.min_consensus_threshold, 0.67);
        assert_eq!(consensus.min_witness_count, 3);
    }

    #[test]
    fn test_config_cleanup() {
        let mut config = EpochConfig::new();

        for epoch in 1..=110 {
            let mut epoch_config = ThresholdConfig::default();
            epoch_config.epoch = epoch;
            config.update_epoch_config(epoch_config);
        }

        assert_eq!(config.config_by_epoch.len(), 111);

        config.cleanup_old_configs();

        assert!(config.config_by_epoch.len() <= 101);

        assert!(config.config_by_epoch.contains_key(&110));
    }

    #[test]
    fn test_block_hash_validation() {
        let mut config = EpochConfig::new();
        let block_hash = Hash::new([1u8; 32]);

        assert!(!config.is_valid_for_block(&block_hash));

        config.update_block_hash(block_hash);
        assert!(config.is_valid_for_block(&block_hash));
    }
}
