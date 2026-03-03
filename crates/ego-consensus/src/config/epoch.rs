use ego_core::{Hash, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Epoch-based configuration that allows dynamic threshold updates
/// Whitepaper: Governance-driven parameter adjustments per epoch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochConfig {
    /// Configuration history keyed by epoch number
    pub config_by_epoch: BTreeMap<u64, ThresholdConfig>,
    /// Hash of the latest finalized block for validation
    pub latest_block_hash: Option<Hash>,
    /// When this config was last updated
    pub last_updated: Timestamp,
}

/// Threshold configuration for a specific epoch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// Epoch number this config applies to
    pub epoch: u64,

    /// Quality thresholds for PoC validation
    pub quality_thresholds: QualityThresholds,

    /// DRS (Decentralized Reputation System) thresholds
    pub drs_thresholds: DRSThresholds,

    /// Consensus validation thresholds
    pub consensus_thresholds: ConsensusThresholds,

    /// Fraud detection sensitivity settings
    pub fraud_thresholds: FraudThresholds,

    /// Block hash this config was derived from
    pub config_block_hash: Hash,
}

/// Quality score thresholds for PoC bundle validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityThresholds {
    /// Minimum quality score for PoC bundle acceptance (whitepaper: q_min)
    pub min_quality_score: f64,

    /// Minimum nonce binding fraction required
    pub min_nonce_binding_fraction: f64,

    /// Maximum path loss RMSE allowed
    pub max_path_loss_rmse: f64,

    /// Minimum coherence score for bundle acceptance
    pub min_coherence_score: f64,

    /// Maximum fraud likelihood threshold
    pub max_fraud_likelihood: f64,
}

/// DRS-related threshold configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DRSThresholds {
    /// Minimum DRS score to participate (whitepaper: 0.5)
    pub min_participation_score: f64,

    /// High quota threshold for premium participants
    pub high_quota_threshold: f64,

    /// Low quota threshold for restricted participants
    pub low_quota_threshold: f64,

    /// Minimum DRS score for beacon authorization
    pub min_beacon_authorization: f64,
}

/// Consensus validation thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusThresholds {
    /// Minimum consensus threshold for event validation
    pub min_consensus_threshold: f64,

    /// DRS score multiplier for vote weighting
    pub drs_vote_multiplier: f64,

    /// Minimum witness count for valid consensus
    pub min_witness_count: usize,

    /// Maximum validation time in milliseconds
    pub max_validation_time_ms: u64,
}

/// Fraud detection sensitivity configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudThresholds {
    /// General fraud detection sensitivity
    pub detection_sensitivity: f64,

    /// Confidence threshold for slashing actions
    pub slashing_confidence_threshold: f64,

    /// Co-beacon minimum fraction for validation
    pub co_beacon_min_fraction: f64,

    /// Timing analysis thresholds
    pub timing_fingerprint_match_threshold: f64,

    /// Relay probability threshold for fraud detection
    pub relay_probability_threshold: f64,
}

impl EpochConfig {
    /// Create new epoch configuration
    pub fn new() -> Self {
        let mut config_by_epoch = BTreeMap::new();

        // Insert default configuration for epoch 0
        config_by_epoch.insert(0, ThresholdConfig::default());

        Self {
            config_by_epoch,
            latest_block_hash: None,
            last_updated: Timestamp::now(),
        }
    }

    /// Get configuration for a specific epoch
    /// Falls back to the latest available config if epoch not found
    pub fn get_config(&self, epoch: u64) -> &ThresholdConfig {
        // Try to find exact epoch
        if let Some(config) = self.config_by_epoch.get(&epoch) {
            return config;
        }

        // Fall back to latest config <= epoch
        self.config_by_epoch
            .range(..=epoch)
            .next_back()
            .map(|(_, config)| config)
            .unwrap_or_else(|| {
                // If no config found, return epoch 0 default
                self.config_by_epoch.get(&0).expect("Default config missing")
            })
    }

    /// Update configuration for a specific epoch
    pub fn update_epoch_config(&mut self, config: ThresholdConfig) {
        self.config_by_epoch.insert(config.epoch, config);
        self.last_updated = Timestamp::now();
    }

    /// Update latest finalized block hash
    pub fn update_block_hash(&mut self, block_hash: Hash) {
        self.latest_block_hash = Some(block_hash);
        self.last_updated = Timestamp::now();
    }

    /// Get current epoch configuration based on timestamp
    pub fn get_current_config(&self) -> &ThresholdConfig {
        let current_epoch = Timestamp::now().as_secs() / 3600; // 1-hour epochs
        self.get_config(current_epoch)
    }

    /// Validate if configuration is up-to-date with consensus
    pub fn is_valid_for_block(&self, block_hash: &Hash) -> bool {
        self.latest_block_hash.as_ref() == Some(block_hash)
    }

    /// Clean up old epoch configurations (keep last 100 epochs)
    pub fn cleanup_old_configs(&mut self) {
        let current_epoch = Timestamp::now().as_secs() / 3600;
        let cutoff_epoch = current_epoch.saturating_sub(100);

        // Keep configurations from cutoff_epoch onwards
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
            min_quality_score: 0.5,              // Whitepaper q_min
            min_nonce_binding_fraction: 0.6,     // 60% binding required
            max_path_loss_rmse: 10.0,            // dB RMSE threshold
            min_coherence_score: 0.5,            // Coherence threshold
            max_fraud_likelihood: 0.8,           // Fraud detection threshold
        }
    }
}

impl Default for DRSThresholds {
    fn default() -> Self {
        Self {
            min_participation_score: 0.5,        // Whitepaper minimum DRS
            high_quota_threshold: 0.8,           // High performance nodes
            low_quota_threshold: 0.5,            // Minimum viable nodes
            min_beacon_authorization: 0.7,       // Beacon authorization threshold
        }
    }
}

impl Default for ConsensusThresholds {
    fn default() -> Self {
        Self {
            min_consensus_threshold: 0.67,       // 2/3 majority
            drs_vote_multiplier: 0.6,            // DRS weighting factor
            min_witness_count: 3,                // Minimum witnesses
            max_validation_time_ms: 30_000,      // 30 second timeout
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

/// Helper trait for accessing epoch-based thresholds
pub trait EpochConfigProvider {
    /// Get the epoch configuration for the current context
    fn get_epoch_config(&self) -> &EpochConfig;

    /// Get thresholds for a specific epoch
    fn get_thresholds_for_epoch(&self, epoch: u64) -> &ThresholdConfig {
        self.get_epoch_config().get_config(epoch)
    }

    /// Get current thresholds based on current time
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

        // Request config for epoch 100 (doesn't exist)
        let fallback = config.get_config(100);
        assert_eq!(fallback.epoch, 0); // Should fallback to epoch 0

        // Add config for epoch 50
        let mut epoch_50_config = ThresholdConfig::default();
        epoch_50_config.epoch = 50;
        epoch_50_config.quality_thresholds.min_quality_score = 0.7;
        config.update_epoch_config(epoch_50_config);

        // Request config for epoch 75 should fallback to epoch 50
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

        // Add configs for epochs 1-110
        for epoch in 1..=110 {
            let mut epoch_config = ThresholdConfig::default();
            epoch_config.epoch = epoch;
            config.update_epoch_config(epoch_config);
        }

        assert_eq!(config.config_by_epoch.len(), 111); // 0-110

        config.cleanup_old_configs();

        // Should keep only recent configs (current_epoch - 100 to current_epoch)
        assert!(config.config_by_epoch.len() <= 101);

        // Should still have recent epochs
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