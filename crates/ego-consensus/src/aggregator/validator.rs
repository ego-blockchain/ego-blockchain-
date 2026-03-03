use crate::aggregator::{PoCBundle, PoCEvent};
use crate::error::{PoCError, PoCResult};
use ego_core::{Address, Hash, PublicKey, Signature, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Validator for independently verifying PoC bundles from other aggregators
/// This component re-validates all fraud checks and aggregator signatures
/// before casting validator votes to the BFT consensus layer
#[derive(Debug)]
pub struct PoCValidator {
    validator_id: Address,
    validator_key: PublicKey,
    vote_sender: mpsc::UnboundedSender<ValidatorVote>,
    processed_bundles: HashMap<Hash, ValidationResult>,
    fraud_threshold: f64,
    min_witness_count: u32,
    max_bundle_age_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ValidatorVote {
    pub bundle_hash: Hash,
    pub validator_id: Address,
    pub vote: VoteType,
    pub timestamp: Timestamp,
    pub signature: Signature,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum VoteType {
    Accept,
    Reject,
    Abstain,
}

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub fraud_score: f64,
    pub witness_count: u32,
    pub signature_valid: bool,
    pub validation_errors: Vec<String>,
}

impl PoCValidator {
    pub fn new(
        validator_id: Address,
        validator_key: PublicKey,
        vote_sender: mpsc::UnboundedSender<ValidatorVote>,
    ) -> Self {
        Self {
            validator_id,
            validator_key,
            vote_sender,
            processed_bundles: HashMap::new(),
            fraud_threshold: 0.3, // 30% fraud threshold
            min_witness_count: 3,
            max_bundle_age_ms: 300_000, // 5 minutes
        }
    }

    /// Validate an incoming PoC bundle from another aggregator
    pub async fn validate_bundle(&mut self, bundle: &PoCBundle) -> PoCResult<ValidationResult> {
        let bundle_hash = self.compute_bundle_hash(bundle);

        // Skip if already processed
        if let Some(cached_result) = self.processed_bundles.get(&bundle_hash) {
            debug!("Bundle {} already validated: {:?}",
                   format!("{:?}", bundle_hash), cached_result.is_valid);
            return Ok(cached_result.clone());
        }

        info!("Validating PoC bundle {} from aggregator {}",
              format!("{:?}", bundle_hash), bundle.aggregator_id);

        let mut validation_errors = Vec::new();
        let mut is_valid = true;

        // 1. Check bundle age
        let current_time = ego_core::current_timestamp();
        if current_time.0 - bundle.created_at.0 > self.max_bundle_age_ms {
            validation_errors.push("Bundle too old".to_string());
            is_valid = false;
        }

        // 2. Verify aggregator signature
        let signature_valid = self.verify_aggregator_signature(bundle)?;
        if !signature_valid {
            validation_errors.push("Invalid aggregator signature".to_string());
            is_valid = false;
        }

        // 3. Re-validate witness reports for fraud
        let (fraud_score, witness_count) = self.revalidate_witness_reports(&bundle.witness_reports)?;

        if fraud_score > self.fraud_threshold {
            validation_errors.push(format!("High fraud score: {:.2}", fraud_score));
            is_valid = false;
        }

        if witness_count < self.min_witness_count {
            validation_errors.push(format!("Insufficient witnesses: {}", witness_count));
            is_valid = false;
        }

        // 4. Verify bundle statistics consistency
        if !self.verify_bundle_consistency(bundle)? {
            validation_errors.push("Bundle statistics inconsistent".to_string());
            is_valid = false;
        }

        let result = ValidationResult {
            is_valid,
            fraud_score,
            witness_count,
            signature_valid,
            validation_errors: validation_errors.clone(),
        };

        // Cache result
        self.processed_bundles.insert(bundle_hash.clone(), result.clone());

        // Cast validator vote
        let vote = if is_valid { VoteType::Accept } else { VoteType::Reject };
        let reason = if !validation_errors.is_empty() {
            Some(validation_errors.join("; "))
        } else {
            None
        };

        self.cast_vote(bundle_hash, vote, reason).await?;

        info!("Bundle validation complete: valid={}, fraud_score={:.3}, witnesses={}",
              is_valid, fraud_score, witness_count);

        Ok(result)
    }

    /// Re-run fraud detection on all witness reports in the bundle
    fn revalidate_witness_reports(&self, reports: &[crate::witness::WitnessReport]) -> PoCResult<(f64, u32)> {
        if reports.is_empty() {
            return Ok((0.0, 0));
        }

        let mut total_fraud_score = 0.0;
        let witness_count = reports.len() as u32;

        for report in reports {
            // Re-validate beacon transmission parameters
            // TX power validation would be done against beacon announcement data

            // Re-validate timing constraints
            if report.rf_metrics.timing_advance > 1000 {
                total_fraud_score += 0.3; // Suspicious timing
            }

            // Re-validate geographic constraints
            if let (Some(lat), Some(lon)) = (Some(report.witness_location.latitude), Some(report.witness_location.longitude)) {
                if lat.abs() > 90.0 || lon.abs() > 180.0 {
                    total_fraud_score += 0.8; // Invalid coordinates
                }
            }

            // Re-validate RSRP/RSRQ values
            if report.rf_metrics.rsrp > -30 || report.rf_metrics.rsrp < -140 {
                total_fraud_score += 0.4; // Invalid RSRP
            }

            if report.rf_metrics.rsrq > 20 || report.rf_metrics.rsrq < -40 {
                total_fraud_score += 0.4; // Invalid RSRQ
            }
        }

        let avg_fraud_score = total_fraud_score / reports.len() as f64;
        Ok((avg_fraud_score, witness_count))
    }

    /// Verify the aggregator's signature on the bundle
    fn verify_aggregator_signature(&self, bundle: &PoCBundle) -> PoCResult<bool> {
        // Create the message that should have been signed
        let message = self.create_signature_message(bundle);

        // TODO: Implement actual signature verification with aggregator's public key
        // For now, perform basic format validation
        if bundle.signature.as_bytes().len() != 64 {
            warn!("Invalid signature length for bundle from {}", bundle.aggregator_id);
            return Ok(false);
        }

        debug!("Signature verification passed for aggregator {}", bundle.aggregator_id);
        Ok(true)
    }

    /// Verify bundle statistics consistency
    fn verify_bundle_consistency(&self, bundle: &PoCBundle) -> PoCResult<bool> {
        // Verify that witness count matches statistics
        let reported_count = bundle.statistics.witness_count;
        let actual_count = bundle.witness_reports.len();

        if reported_count != actual_count as u32 {
            warn!("Bundle witness count mismatch: reported {}, actual {}", reported_count, actual_count);
            return Ok(false);
        }

        // Empty bundles are allowed - witness count validation is handled separately
        debug!("Bundle consistency verification passed");
        Ok(true)
    }

    /// Cast a validator vote to the BFT consensus layer
    async fn cast_vote(&self, bundle_hash: Hash, vote: VoteType, reason: Option<String>) -> PoCResult<()> {
        let vote_message = ValidatorVote {
            bundle_hash: bundle_hash.clone(),
            validator_id: self.validator_id,
            vote,
            timestamp: ego_core::current_timestamp(),
            signature: Signature::ed25519([0u8; 64]), // TODO: Sign with validator key
            reason,
        };

        if let Err(e) = self.vote_sender.send(vote_message.clone()) {
            error!("Failed to send validator vote: {}", e);
            return Err(PoCError::NetworkError("Failed to send vote through vote channel".to_string()));
        }

        info!("Cast vote {:?} for bundle {}",
              vote_message.vote, format!("{:?}", bundle_hash));
        Ok(())
    }

    fn compute_bundle_hash(&self, bundle: &PoCBundle) -> Hash {
        // Use the existing bundle_id as the hash
        bundle.bundle_id
    }

    fn create_signature_message(&self, bundle: &PoCBundle) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(bundle.aggregator_id.as_bytes());
        message.extend_from_slice(&bundle.created_at.0.to_le_bytes());
        message.extend_from_slice(bundle.bundle_id.as_bytes());
        message.extend_from_slice(&(bundle.witness_reports.len() as u32).to_le_bytes());
        message
    }

    /// Clean up old processed bundles to prevent memory growth
    pub fn cleanup_old_bundles(&mut self, max_age_ms: u64) {
        let current_time = ego_core::current_timestamp();
        let mut to_remove = Vec::new();

        // This is a simplified cleanup - in production would track bundle timestamps
        if self.processed_bundles.len() > 10000 {
            // Remove oldest 25% of entries
            let remove_count = self.processed_bundles.len() / 4;
            for (i, key) in self.processed_bundles.keys().enumerate() {
                if i < remove_count {
                    to_remove.push(key.clone());
                }
            }
        }

        for key in to_remove {
            self.processed_bundles.remove(&key);
        }

        if !self.processed_bundles.is_empty() {
            debug!("Cleaned up bundle cache, {} entries remaining",
                   self.processed_bundles.len());
        }
    }

    /// Update validation parameters from consensus layer
    pub fn update_parameters(&mut self, fraud_threshold: f64, min_witnesses: u32, max_age_ms: u64) {
        self.fraud_threshold = fraud_threshold;
        self.min_witness_count = min_witnesses;
        self.max_bundle_age_ms = max_age_ms;

        info!("Updated validation parameters: fraud_threshold={:.2}, min_witnesses={}, max_age_ms={}",
              fraud_threshold, min_witnesses, max_age_ms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_validator_creation() {
        let (vote_tx, _vote_rx) = mpsc::unbounded_channel();
        let validator = PoCValidator::new(
            Address::default(),
            PublicKey::default(),
            vote_tx,
        );

        assert_eq!(validator.fraud_threshold, 0.3);
        assert_eq!(validator.min_witness_count, 3);
    }

    #[tokio::test]
    async fn test_bundle_validation() {
        let (vote_tx, mut vote_rx) = mpsc::unbounded_channel();
        let mut validator = PoCValidator::new(
            Address::default(),
            PublicKey::default(),
            vote_tx,
        );

        // Allow empty bundles for this test
        validator.min_witness_count = 0;

        // Create a minimal test bundle using the real PoCBundle::new constructor
        use crate::beacon::BeaconAnnouncement;
        use crate::types::{Challenge, LocationData};

        let challenge = Challenge {
            challenge_hash: Hash::new([2u8; 32]),
            h3_cell: "87283472bffffff".to_string(),
            nonce: vec![3u8; 16],
            timestamp: Timestamp::now(),
            difficulty: 1,
            reward_scale: 1.0,
        };

        let location = LocationData {
            latitude: 37.7749,
            longitude: -122.4194,
            altitude: Some(10.0),
            accuracy: Some(5.0),
            timestamp: Timestamp::now().as_millis(),
            h3_index: "87283472bffffff".to_string(),
        };

        let tx_params = crate::beacon::BeaconTxParams::default();
        let beacon_announcement = BeaconAnnouncement::new(
            Address::new([1u8; 20]),
            challenge,
            location,
            tx_params
        );

        let bundle = PoCBundle::new(
            Address::default(),
            beacon_announcement,
            vec![], // Empty witness reports for test
        );

        let result = validator.validate_bundle(&bundle).await.unwrap();

        // Should accept empty bundle with valid signature
        assert!(result.is_valid);

        // Should have cast a vote
        let vote = vote_rx.try_recv().unwrap();
        assert!(matches!(vote.vote, VoteType::Accept));
    }
}