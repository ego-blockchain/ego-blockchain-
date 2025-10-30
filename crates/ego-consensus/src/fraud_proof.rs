use crate::beacon::BeaconAnnouncement;
use crate::error::{PoCError, PoCResult};
use crate::types::*;
use crate::witness::WitnessReport;
use ego_core::{Address, Hash, KeyPair, PublicKey, Signature, Timestamp};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct FraudProof {
    pub proof_id: Hash,
    pub challenger: Address,
    pub accused: Address,
    pub fraud_type: FraudType,
    pub evidence: FraudEvidence,
    pub confidence: f64,
    pub minimal_witness_set: Vec<WitnessReport>,
    pub model_checks: Vec<ModelCheck>,
    pub challenge_reward: u64,
    pub collateral_required: u64,
    pub timestamp: Timestamp,
    pub signature: Signature,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct FraudEvidence {
    pub poc_event_hash: Hash,
    pub bundle_hash: Option<Hash>,
    pub evidence_data: EvidenceData,
    pub calculations: Vec<FraudCalculation>,
    pub reference_data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum EvidenceData {
    LocationSpoof {
        claimed_location: LocationData,
        actual_location: Option<LocationData>,
        movement_analysis: MovementAnalysis,
    },

    InvalidGeometry {
        beacon_location: LocationData,
        witness_locations: Vec<LocationData>,
        rf_measurements: Vec<RFMetrics>,
        path_loss_analysis: PathLossAnalysis,
    },

    ReplayAttack {
        original_transmission: BeaconAnnouncement,
        replayed_transmission: BeaconAnnouncement,
        timing_analysis: TimingAnalysis,
    },

    ClusteredFarm {
        suspected_locations: Vec<LocationData>,
        clustering_analysis: ClusteringAnalysis,
        density_metrics: DensityMetrics,
    },

    RelayAttack {
        beacon_announcement: BeaconAnnouncement,
        witness_reports: Vec<WitnessReport>,
        latency_analysis: LatencyAnalysis,
    },

    InvalidSignature {
        claimed_signature: Signature,
        public_key: PublicKey,
        message: Vec<u8>,
        verification_result: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct MovementAnalysis {
    pub max_speed_kmh: f32,
    pub impossible_movements: Vec<ImpossibleMovement>,
    pub teleportation_events: u32,
    pub movement_consistency_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ImpossibleMovement {
    pub from_location: LocationData,
    pub to_location: LocationData,
    pub time_delta_ms: u64,
    pub distance_km: f32,
    pub required_speed_kmh: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PathLossAnalysis {
    pub expected_path_losses: Vec<f32>,
    pub actual_rsrp_values: Vec<i16>,
    pub path_loss_errors: Vec<f32>,
    pub max_error_db: f32,
    pub geometry_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct TimingAnalysis {
    pub original_timestamp: u64,
    pub replay_timestamp: u64,
    pub time_delta_ms: i64,
    pub nonce_reuse_detected: bool,
    pub timing_fingerprint_match: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ClusteringAnalysis {
    pub cluster_centers: Vec<LocationData>,
    pub cluster_radii: Vec<f32>,
    pub nodes_per_cluster: Vec<u32>,
    pub clustering_coefficient: f64,
    pub suspicious_cluster_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DensityMetrics {
    pub nodes_per_km2: f32,
    pub expected_density: f32,
    pub density_ratio: f32,
    pub hotspot_count: u32,
    pub coverage_overlap_percentage: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct LatencyAnalysis {
    pub expected_propagation_delays: Vec<u32>,
    pub actual_timing_advances: Vec<u32>,
    pub latency_anomalies: Vec<LatencyAnomaly>,
    pub relay_probability: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct LatencyAnomaly {
    pub witness_id: Address,
    pub expected_delay_ns: u32,
    pub actual_delay_ns: u32,
    pub anomaly_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ModelCheck {
    pub check_type: ModelCheckType,
    pub input_parameters: Vec<f64>,
    pub expected_result: f64,
    pub actual_result: f64,
    pub deviation_percentage: f32,
    pub pass: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum ModelCheckType {
    FreeSpacePathLoss,
    OkumuraHata,
    TimingAdvanceConsistency,
    SignalPropagationDelay,
    BeamformingGain,
    InterferenceAnalysis,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct FraudCalculation {
    pub calculation_type: String,
    pub formula: String,
    pub inputs: Vec<(String, f64)>,
    pub result: f64,
    pub unit: String,
    pub description: String,
}

impl PartialEq for FraudProof {
    fn eq(&self, other: &Self) -> bool {
        self.proof_id == other.proof_id
            && self.challenger == other.challenger
            && self.accused == other.accused
            && self.fraud_type == other.fraud_type
    }
}

impl Eq for FraudProof {}

impl PartialEq for FraudEvidence {
    fn eq(&self, other: &Self) -> bool {
        self.poc_event_hash == other.poc_event_hash && self.bundle_hash == other.bundle_hash
    }
}

impl Eq for FraudEvidence {}

impl PartialEq for EvidenceData {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                EvidenceData::LocationSpoof {
                    claimed_location: c1,
                    ..
                },
                EvidenceData::LocationSpoof {
                    claimed_location: c2,
                    ..
                },
            ) => c1 == c2,
            (
                EvidenceData::InvalidGeometry {
                    beacon_location: b1,
                    ..
                },
                EvidenceData::InvalidGeometry {
                    beacon_location: b2,
                    ..
                },
            ) => b1 == b2,
            _ => false,
        }
    }
}

impl Eq for EvidenceData {}

impl PartialEq for MovementAnalysis {
    fn eq(&self, other: &Self) -> bool {
        (self.max_speed_kmh - other.max_speed_kmh).abs() < f32::EPSILON
            && self.teleportation_events == other.teleportation_events
    }
}

impl Eq for MovementAnalysis {}

impl PartialEq for ImpossibleMovement {
    fn eq(&self, other: &Self) -> bool {
        self.from_location == other.from_location
            && self.to_location == other.to_location
            && self.time_delta_ms == other.time_delta_ms
    }
}

impl Eq for ImpossibleMovement {}

impl PartialEq for PathLossAnalysis {
    fn eq(&self, other: &Self) -> bool {
        (self.max_error_db - other.max_error_db).abs() < f32::EPSILON
            && (self.geometry_score - other.geometry_score).abs() < f64::EPSILON
    }
}

impl Eq for PathLossAnalysis {}

impl PartialEq for TimingAnalysis {
    fn eq(&self, other: &Self) -> bool {
        self.original_timestamp == other.original_timestamp
            && self.replay_timestamp == other.replay_timestamp
            && self.time_delta_ms == other.time_delta_ms
            && self.nonce_reuse_detected == other.nonce_reuse_detected
    }
}

impl Eq for TimingAnalysis {}

impl PartialEq for ClusteringAnalysis {
    fn eq(&self, other: &Self) -> bool {
        self.cluster_centers == other.cluster_centers
            && self.nodes_per_cluster == other.nodes_per_cluster
            && self.suspicious_cluster_count == other.suspicious_cluster_count
    }
}

impl Eq for ClusteringAnalysis {}

impl PartialEq for DensityMetrics {
    fn eq(&self, other: &Self) -> bool {
        (self.nodes_per_km2 - other.nodes_per_km2).abs() < f32::EPSILON
            && (self.expected_density - other.expected_density).abs() < f32::EPSILON
            && self.hotspot_count == other.hotspot_count
    }
}

impl Eq for DensityMetrics {}

impl PartialEq for LatencyAnalysis {
    fn eq(&self, other: &Self) -> bool {
        self.expected_propagation_delays == other.expected_propagation_delays
            && self.actual_timing_advances == other.actual_timing_advances
            && (self.relay_probability - other.relay_probability).abs() < f64::EPSILON
    }
}

impl Eq for LatencyAnalysis {}

impl PartialEq for LatencyAnomaly {
    fn eq(&self, other: &Self) -> bool {
        self.witness_id == other.witness_id
            && self.expected_delay_ns == other.expected_delay_ns
            && self.actual_delay_ns == other.actual_delay_ns
    }
}

impl Eq for LatencyAnomaly {}

impl PartialEq for ModelCheck {
    fn eq(&self, other: &Self) -> bool {
        self.check_type == other.check_type
            && (self.expected_result - other.expected_result).abs() < f64::EPSILON
            && (self.actual_result - other.actual_result).abs() < f64::EPSILON
            && self.pass == other.pass
    }
}

impl Eq for ModelCheck {}

impl PartialEq for ModelCheckType {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (ModelCheckType::FreeSpacePathLoss, ModelCheckType::FreeSpacePathLoss) => true,
            (ModelCheckType::OkumuraHata, ModelCheckType::OkumuraHata) => true,
            (
                ModelCheckType::TimingAdvanceConsistency,
                ModelCheckType::TimingAdvanceConsistency,
            ) => true,
            (ModelCheckType::SignalPropagationDelay, ModelCheckType::SignalPropagationDelay) => {
                true
            }
            (ModelCheckType::BeamformingGain, ModelCheckType::BeamformingGain) => true,
            (ModelCheckType::InterferenceAnalysis, ModelCheckType::InterferenceAnalysis) => true,
            _ => false,
        }
    }
}

impl Eq for ModelCheckType {}

impl PartialEq for FraudCalculation {
    fn eq(&self, other: &Self) -> bool {
        self.calculation_type == other.calculation_type
            && self.formula == other.formula
            && (self.result - other.result).abs() < f64::EPSILON
    }
}

impl Eq for FraudCalculation {}

impl FraudProof {
    pub fn new(
        challenger: Address,
        accused: Address,
        fraud_type: FraudType,
        evidence: FraudEvidence,
        confidence: f64,
    ) -> Self {
        let timestamp = Timestamp::now();
        let proof_id = Self::compute_proof_id(challenger, accused, &fraud_type, timestamp);

        let collateral_required = Self::calculate_collateral_requirement(&fraud_type, confidence);
        let challenge_reward = collateral_required / 2;

        Self {
            proof_id,
            challenger,
            accused,
            fraud_type,
            evidence,
            confidence,
            minimal_witness_set: Vec::new(),
            model_checks: Vec::new(),
            challenge_reward,
            collateral_required,
            timestamp,
            signature: Signature::ed25519([0u8; 64]),
            public_key: PublicKey::ed25519([0u8; 32]),
        }
    }

    pub fn sign(&mut self, keypair: &KeyPair) -> PoCResult<()> {
        self.public_key = keypair.public_key();

        let expected_challenger = Address::from_public_key(&self.public_key);
        if expected_challenger != self.challenger {
            return Err(PoCError::SignatureVerificationFailed(
                "Challenger address does not match signing key".to_string(),
            ));
        }

        let signing_data = self.create_signing_data()?;
        self.signature = keypair.sign(&signing_data);

        Ok(())
    }

    pub fn verify_signature(&self) -> PoCResult<bool> {
        let expected_challenger = Address::from_public_key(&self.public_key);
        if expected_challenger != self.challenger {
            return Ok(false);
        }

        let signing_data = self.create_signing_data()?;

        match ego_core::verify_signature(&self.public_key, &signing_data, &self.signature) {
            Ok(valid) => Ok(valid),
            Err(e) => Err(PoCError::SignatureVerificationFailed(format!(
                "Fraud proof signature verification failed: {}",
                e
            ))),
        }
    }

    pub fn validate(&self) -> PoCResult<()> {
        if self.confidence < 0.0 || self.confidence > 1.0 {
            return Err(PoCError::ValidationFailed(
                "Confidence must be between 0.0 and 1.0".to_string(),
            ));
        }

        if self.confidence < 0.7 {
            return Err(PoCError::ValidationFailed(
                "Confidence too low for fraud proof submission".to_string(),
            ));
        }

        self.validate_evidence()?;
        self.validate_model_checks()?;

        if self.challenger == self.accused {
            return Err(PoCError::ValidationFailed(
                "Challenger cannot be the same as accused".to_string(),
            ));
        }

        Ok(())
    }

    fn validate_evidence(&self) -> PoCResult<()> {
        match &self.evidence.evidence_data {
            EvidenceData::LocationSpoof {
                movement_analysis, ..
            } => {
                if movement_analysis.max_speed_kmh > 1000.0 {
                    return Err(PoCError::ValidationFailed(
                        "Unrealistic maximum speed in movement analysis".to_string(),
                    ));
                }
            }
            EvidenceData::InvalidGeometry {
                path_loss_analysis, ..
            } => {
                if path_loss_analysis.max_error_db < 0.0 {
                    return Err(PoCError::ValidationFailed(
                        "Invalid path loss error value".to_string(),
                    ));
                }
            }
            EvidenceData::ReplayAttack {
                timing_analysis, ..
            } => {
                if !timing_analysis.nonce_reuse_detected
                    && timing_analysis.timing_fingerprint_match < 0.8
                {
                    return Err(PoCError::ValidationFailed(
                        "Insufficient evidence for replay attack".to_string(),
                    ));
                }
            }
            EvidenceData::ClusteredFarm {
                clustering_analysis,
                ..
            } => {
                if clustering_analysis.suspicious_cluster_count == 0 {
                    return Err(PoCError::ValidationFailed(
                        "No suspicious clusters detected".to_string(),
                    ));
                }
            }
            EvidenceData::RelayAttack {
                latency_analysis, ..
            } => {
                if latency_analysis.relay_probability < 0.7 {
                    return Err(PoCError::ValidationFailed(
                        "Insufficient probability for relay attack".to_string(),
                    ));
                }
            }
            EvidenceData::InvalidSignature {
                verification_result,
                ..
            } => {
                if *verification_result {
                    return Err(PoCError::ValidationFailed(
                        "Signature is actually valid".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    fn validate_model_checks(&self) -> PoCResult<()> {
        if self.model_checks.is_empty() {
            return Err(PoCError::ValidationFailed(
                "At least one model check is required".to_string(),
            ));
        }

        let failed_checks = self.model_checks.iter().filter(|check| !check.pass).count();

        if failed_checks == 0 {
            return Err(PoCError::ValidationFailed(
                "No model checks failed - insufficient evidence for fraud".to_string(),
            ));
        }

        let failure_rate = failed_checks as f64 / self.model_checks.len() as f64;
        let required_failure_rate = if self.confidence > 0.9 { 0.8 } else { 0.5 };

        if failure_rate < required_failure_rate {
            return Err(PoCError::ValidationFailed(format!(
                "Insufficient model check failures: {:.1}% failed, need {:.1}%",
                failure_rate * 100.0,
                required_failure_rate * 100.0
            )));
        }

        Ok(())
    }

    pub fn add_model_check(&mut self, check: ModelCheck) {
        self.model_checks.push(check);
    }

    pub fn add_minimal_witness(&mut self, witness: WitnessReport) {
        if !self
            .minimal_witness_set
            .iter()
            .any(|w| w.witness_id == witness.witness_id)
        {
            self.minimal_witness_set.push(witness);
        }
    }

    fn calculate_collateral_requirement(fraud_type: &FraudType, confidence: f64) -> u64 {
        let base_collateral = match fraud_type {
            FraudType::InvalidGeometry => 1000,
            FraudType::ReplayAttack => 1500,
            FraudType::LocationSpoof => 2000,
            FraudType::ClusteredFarm => 5000,
            FraudType::RelayAttack => 1200,
            FraudType::InvalidSignature => 800,
            FraudType::TimeWindowViolation => 500,
            FraudType::DensityManipulation => 3000,
        };

        let confidence_multiplier = 2.0 - confidence;
        (base_collateral as f64 * confidence_multiplier) as u64
    }

    fn create_signing_data(&self) -> PoCResult<Vec<u8>> {
        let mut data = Vec::new();

        data.extend_from_slice(self.proof_id.as_bytes());
        data.extend_from_slice(self.challenger.as_bytes());
        data.extend_from_slice(self.accused.as_bytes());
        data.extend_from_slice(&self.timestamp.as_millis().to_le_bytes());
        data.extend_from_slice(&self.confidence.to_le_bytes());

        let config = bincode::config::standard();
        let evidence_bytes = bincode::encode_to_vec(&self.evidence, config)
            .map_err(|e| PoCError::SerializationError(e.to_string()))?;
        let evidence_hash = ego_core::crypto::hash_data(&evidence_bytes);
        data.extend_from_slice(evidence_hash.as_bytes());

        Ok(data)
    }

    fn compute_proof_id(
        challenger: Address,
        accused: Address,
        fraud_type: &FraudType,
        timestamp: Timestamp,
    ) -> Hash {
        use ego_core::crypto::hash_multiple;

        let fraud_type_bytes = format!("{:?}", fraud_type).into_bytes();

        hash_multiple(&[
            challenger.as_bytes(),
            accused.as_bytes(),
            &fraud_type_bytes,
            &timestamp.as_millis().to_le_bytes(),
        ])
    }
}

pub struct FraudProofValidator {
    min_confidence: f64,
    max_age_hours: u64,
    min_failure_rate: f64,
}

impl FraudProofValidator {
    pub fn new(min_confidence: f64, max_age_hours: u64, min_failure_rate: f64) -> Self {
        Self {
            min_confidence,
            max_age_hours,
            min_failure_rate,
        }
    }

    pub fn validate_for_consensus(&self, proof: &FraudProof) -> PoCResult<bool> {
        proof.validate()?;

        if proof.confidence < self.min_confidence {
            return Ok(false);
        }

        let age_hours = (Timestamp::now().as_millis() - proof.timestamp.as_millis()) / 3_600_000;
        if age_hours > self.max_age_hours {
            return Ok(false);
        }

        let failed_checks = proof
            .model_checks
            .iter()
            .filter(|check| !check.pass)
            .count();

        let failure_rate = if proof.model_checks.is_empty() {
            0.0
        } else {
            failed_checks as f64 / proof.model_checks.len() as f64
        };

        if failure_rate < self.min_failure_rate {
            return Ok(false);
        }

        Ok(true)
    }

    pub fn execute_fraud_proof(&self, proof: &FraudProof) -> PoCResult<FraudProofResult> {
        if !self.validate_for_consensus(proof)? {
            return Ok(FraudProofResult {
                success: false,
                slash_amount: 0,
                challenger_reward: 0,
                reason: "Fraud proof validation failed".to_string(),
            });
        }

        let base_slash = proof.collateral_required;
        let confidence_multiplier = proof.confidence;
        let severity_multiplier = match proof.fraud_type {
            FraudType::ClusteredFarm | FraudType::DensityManipulation => 2.0,
            FraudType::LocationSpoof | FraudType::ReplayAttack => 1.5,
            _ => 1.0,
        };

        let slash_amount = (base_slash as f64 * confidence_multiplier * severity_multiplier) as u64;
        let challenger_reward = slash_amount / 2;

        Ok(FraudProofResult {
            success: true,
            slash_amount,
            challenger_reward,
            reason: format!("Fraud proven: {:?}", proof.fraud_type),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudProofResult {
    pub success: bool,
    pub slash_amount: u64,
    pub challenger_reward: u64,
    pub reason: String,
}

impl Default for FraudProofValidator {
    fn default() -> Self {
        Self::new(0.8, 24, 0.6)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::KeyPair;

    fn create_test_fraud_proof() -> FraudProof {
        let evidence = FraudEvidence {
            poc_event_hash: Hash::new([1u8; 32]),
            bundle_hash: Some(Hash::new([2u8; 32])),
            evidence_data: EvidenceData::InvalidGeometry {
                beacon_location: LocationData {
                    latitude: 37.7749,
                    longitude: -122.4194,
                    altitude: Some(10.0),
                    accuracy: Some(5.0),
                    timestamp: Timestamp::now().as_millis(),
                    h3_index: "87283472bffffff".to_string(),
                },
                witness_locations: vec![],
                rf_measurements: vec![],
                path_loss_analysis: PathLossAnalysis {
                    expected_path_losses: vec![80.0],
                    actual_rsrp_values: vec![-50],
                    path_loss_errors: vec![30.0],
                    max_error_db: 30.0,
                    geometry_score: 0.3,
                },
            },
            calculations: vec![],
            reference_data: None,
        };

        FraudProof::new(
            Address::new([1u8; 20]),
            Address::new([2u8; 20]),
            FraudType::InvalidGeometry,
            evidence,
            0.85,
        )
    }

    #[test]
    fn test_fraud_proof_creation() {
        let proof = create_test_fraud_proof();
        assert_eq!(proof.fraud_type, FraudType::InvalidGeometry);
        assert_eq!(proof.confidence, 0.85);
        assert!(proof.collateral_required > 0);
    }

    #[test]
    fn test_fraud_proof_signing() {
        let keypair = KeyPair::generate();
        let challenger = Address::from_public_key(&keypair.public_key());

        let evidence = FraudEvidence {
            poc_event_hash: Hash::new([1u8; 32]),
            bundle_hash: None,
            evidence_data: EvidenceData::InvalidSignature {
                claimed_signature: Signature::ed25519([0u8; 64]),
                public_key: PublicKey::ed25519([0u8; 32]),
                message: vec![1, 2, 3],
                verification_result: false,
            },
            calculations: vec![],
            reference_data: None,
        };

        let mut proof = FraudProof::new(
            challenger,
            Address::new([2u8; 20]),
            FraudType::InvalidSignature,
            evidence,
            0.9,
        );

        assert!(proof.sign(&keypair).is_ok());
        assert!(proof.verify_signature().unwrap());
    }

    #[test]
    fn test_fraud_proof_validation() {
        let mut proof = create_test_fraud_proof();

        proof.add_model_check(ModelCheck {
            check_type: ModelCheckType::FreeSpacePathLoss,
            input_parameters: vec![1.0, 3.5],
            expected_result: 80.0,
            actual_result: 50.0,
            deviation_percentage: 37.5,
            pass: false,
        });

        assert!(proof.validate().is_ok());
    }

    #[test]
    fn test_fraud_proof_validator() {
        let validator = FraudProofValidator::default();
        let mut proof = create_test_fraud_proof();

        proof.add_model_check(ModelCheck {
            check_type: ModelCheckType::FreeSpacePathLoss,
            input_parameters: vec![1.0, 3.5],
            expected_result: 80.0,
            actual_result: 50.0,
            deviation_percentage: 37.5,
            pass: false,
        });

        assert!(validator.validate_for_consensus(&proof).unwrap());

        let result = validator.execute_fraud_proof(&proof).unwrap();
        assert!(result.success);
        assert!(result.slash_amount > 0);
        assert!(result.challenger_reward > 0);
    }

    #[test]
    fn test_collateral_calculation() {
        let collateral =
            FraudProof::calculate_collateral_requirement(&FraudType::ClusteredFarm, 0.9);
        assert!(collateral > 0);

        let high_conf =
            FraudProof::calculate_collateral_requirement(&FraudType::InvalidGeometry, 0.95);
        let low_conf =
            FraudProof::calculate_collateral_requirement(&FraudType::InvalidGeometry, 0.75);
        assert!(high_conf < low_conf);
    }
}
