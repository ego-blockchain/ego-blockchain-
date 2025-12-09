use crate::aggregator::PoCEvent;
use crate::config::ValidationConfig;
use crate::error::PoCResult;
use ego_core::{Address, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use tokio::sync::RwLock;
use tracing::debug;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    pub validation_config: ValidationConfig,
    pub min_consensus_threshold: f64,
    pub max_validation_time_ms: u64,
    pub fraud_detection_enabled: bool,
    pub batch_validation_size: usize,
}

pub struct ConsensusEngine {
    config: ConsensusConfig,
    validators: Vec<Address>,
    pending_events: RwLock<VecDeque<PoCEvent>>,
    validated_events: RwLock<HashMap<ego_core::Hash, ValidationResult>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub event_hash: ego_core::Hash,
    pub is_valid: bool,
    pub confidence: f64,
    pub validator_votes: HashMap<Address, bool>,
    pub fraud_indicators: Vec<String>,
    pub timestamp: Timestamp,
}

impl ConsensusEngine {
    pub fn new(config: ConsensusConfig, validators: Vec<Address>) -> Self {
        Self {
            config,
            validators,
            pending_events: RwLock::new(VecDeque::new()),
            validated_events: RwLock::new(HashMap::new()),
        }
    }

    pub async fn submit_event(&self, event: PoCEvent) -> PoCResult<()> {
        let mut pending = self.pending_events.write().await;
        pending.push_back(event);
        Ok(())
    }

    pub async fn validate_events(&self) -> PoCResult<Vec<ValidationResult>> {
        let mut pending = self.pending_events.write().await;
        let mut results = Vec::new();

        while let Some(event) = pending.pop_front() {
            let result = self.validate_single_event(&event).await?;
            results.push(result.clone());

            let mut validated = self.validated_events.write().await;
            validated.insert(event.beacon_hash, result);
        }

        Ok(results)
    }

    async fn validate_single_event(&self, event: &PoCEvent) -> PoCResult<ValidationResult> {
        debug!("Validating PoC event for beacon {}", event.beacon_hash);

        let mut validator_votes = HashMap::new();
        let mut fraud_indicators = Vec::new();

        for validator in &self.validators {
            let vote = self.deterministic_validator_vote(event, validator).await;
            validator_votes.insert(*validator, vote);
        }

        let positive_votes = validator_votes.values().filter(|&&v| v).count();
        let total_votes = validator_votes.len();
        let confidence = positive_votes as f64 / total_votes as f64;

        let is_valid = confidence >= self.config.min_consensus_threshold;

        if !is_valid {
            fraud_indicators.push("Low consensus threshold".to_string());
        }

        if event.quality_score < 0.5 {
            fraud_indicators.push("Low quality score".to_string());
        }

        Ok(ValidationResult {
            event_hash: event.beacon_hash,
            is_valid,
            confidence,
            validator_votes,
            fraud_indicators,
            timestamp: Timestamp::now(),
        })
    }

    async fn deterministic_validator_vote(&self, event: &PoCEvent, _validator: &Address) -> bool {
        let mut score = 1.0;

        if event.quality_score < 0.6 {
            score *= 0.5;
        }

        if event.witness_hashes.is_empty() {
            score *= 0.1;
        } else if event.witness_hashes.len() < 3 {
            score *= 0.7;
        }

        if event.region.is_empty() {
            score *= 0.8;
        }

        let current_epoch = Timestamp::now().as_secs() / 3600;
        if event.epoch + 24 < current_epoch {
            score *= 0.3;
        }

        score > 0.7
    }
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            validation_config: ValidationConfig::default(),
            min_consensus_threshold: 0.67,
            max_validation_time_ms: 30_000,
            fraud_detection_enabled: true,
            batch_validation_size: 100,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::{Hash, Address, Timestamp, Signature};

    #[test]
    fn test_consensus_engine_creation() {
        let event = PoCEvent {
            beacon_hash: Hash::new([1u8; 32]),
            witness_hashes: vec![Hash::new([4u8; 32]), Hash::new([5u8; 32])],
            agg_digest: Hash::new([6u8; 32]),
            quality_score: 0.85,
            region: "872834".to_string(),
            epoch: 100,
            cid_hint: None,
            timestamp: Timestamp::now(),
            aggregator_signature: Signature::ed25519([0u8; 64]),
            path_loss_rmse: 8.5,
            diversity_score: 0.9,
            nonce_binding_fraction: 0.75,
            ldm_penalty: 0.0,
        };

        assert_eq!(event.quality_score, 0.85);
        assert_eq!(event.witness_hashes.len(), 2);
    }

    #[tokio::test]
    async fn test_deterministic_scoring() {
        let config = ConsensusConfig::default();
        let validators = vec![Address::new([1u8; 20])];
        let engine = ConsensusEngine::new(config, validators);

        let event = PoCEvent {
            beacon_hash: Hash::new([1u8; 32]),
            witness_hashes: vec![
                Hash::new([2u8; 32]),
                Hash::new([3u8; 32]),
                Hash::new([4u8; 32]),
            ],
            agg_digest: Hash::new([5u8; 32]),
            quality_score: 0.8,
            region: "test_region".to_string(),
            epoch: Timestamp::now().as_secs() / 3600,
            cid_hint: None,
            timestamp: Timestamp::now(),
            aggregator_signature: Signature::ed25519([0u8; 64]),
            path_loss_rmse: 9.0,
            diversity_score: 0.85,
            nonce_binding_fraction: 0.70,
            ldm_penalty: 0.05,
        };

        let result1 = engine.validate_single_event(&event).await.unwrap();
        let result2 = engine.validate_single_event(&event).await.unwrap();

        assert_eq!(result1.is_valid, result2.is_valid);
        assert_eq!(result1.confidence, result2.confidence);
    }

    #[tokio::test]
    async fn test_event_submission() {
        let config = ConsensusConfig::default();
        let validators = vec![Address::new([1u8; 20]), Address::new([2u8; 20])];
        let engine = ConsensusEngine::new(config, validators);

        let event = PoCEvent {
            beacon_hash: Hash::new([10u8; 32]),
            witness_hashes: vec![Hash::new([11u8; 32])],
            agg_digest: Hash::new([12u8; 32]),
            quality_score: 0.75,
            region: "872835".to_string(),
            epoch: Timestamp::now().as_secs() / 3600,
            cid_hint: Some("QmTest123".to_string()),
            timestamp: Timestamp::now(),
            aggregator_signature: Signature::ed25519([1u8; 64]),
            path_loss_rmse: 7.5,
            diversity_score: 0.80,
            nonce_binding_fraction: 0.65,
            ldm_penalty: 0.10,
        };

        assert!(engine.submit_event(event).await.is_ok());
        
        let results = engine.validate_events().await.unwrap();
        assert_eq!(results.len(), 1);
    }
}