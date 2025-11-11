use crate::beacon::BeaconAnnouncement;
use crate::error::{PoCError, PoCResult};
use crate::types::*;
use crate::witness::WitnessReport;
use ego_core::{Address, Hash, KeyPair, PublicKey, Signature, Timestamp};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PoCBundle {
    pub bundle_id: Hash,
    pub aggregator_id: Address,
    pub beacon_event: BeaconEventData,
    pub witness_reports: Vec<WitnessReport>,
    pub statistics: BundleStatistics,
    pub coherence_analysis: CoherenceAnalysis,
    pub coverage_quality: CoverageQuality,
    pub compression_info: Option<CompressionInfo>,
    pub created_at: Timestamp,
    pub signature: Signature,
    pub public_key: PublicKey,
    pub cid_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct BeaconEventData {
    pub beacon_announcement: BeaconAnnouncement,
    pub beacon_hash: Hash,
    pub h3_cell: String,
    pub challenge_hash: Hash,
    pub transmission_time: Timestamp,
    pub estimated_coverage_radius_km: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct BundleStatistics {
    pub witness_count: u32,
    pub valid_witnesses: u32,
    pub invalid_witnesses: u32,
    pub avg_rsrp_dbm: f32,
    pub max_distance_km: f32,
    pub min_distance_km: f32,
    pub geographic_spread_km2: f32,
    pub time_window_ms: u64,
    pub duplicate_reports: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct CoherenceAnalysis {
    pub overall_coherence_score: f64,
    pub geometry_coherence: f64,
    pub timing_coherence: f64,
    pub signal_coherence: f64,
    pub clustering_detected: bool,
    pub suspicious_patterns: Vec<SuspiciousPattern>,
    pub fraud_likelihood: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct SuspiciousPattern {
    pub pattern_type: PatternType,
    pub confidence: f64,
    pub affected_witnesses: Vec<Address>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum PatternType {
    ImpossibleGeometry,
    SignalTooStrong,
    SignalTooWeak,
    TimingAnomalies,
    ClusteredWitnesses,
    RepeatedNonces,
    SuspiciousMovement,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PoCEvent {
    pub beacon_hash: Hash,
    pub witness_hashes: Vec<Hash>,
    pub agg_digest: Hash,
    pub quality_score: f64,
    pub region: String,
    pub epoch: u64,
    pub cid_hint: Option<String>,
    pub timestamp: Timestamp,
    pub aggregator_signature: Signature,
}

impl PoCBundle {
    pub fn new(
        aggregator_id: Address,
        beacon_announcement: BeaconAnnouncement,
        witness_reports: Vec<WitnessReport>,
    ) -> Self {
        let beacon_hash = Hash::new({
            let sig_bytes = beacon_announcement.signature.as_bytes();
            let mut hash_bytes = [0u8; 32];
            let len = sig_bytes.len().min(32);
            hash_bytes[..len].copy_from_slice(&sig_bytes[..len]);
            hash_bytes
        });
        let created_at = Timestamp::now();

        let beacon_event = BeaconEventData {
            h3_cell: beacon_announcement.location.h3_index.clone(),
            challenge_hash: beacon_announcement.challenge.challenge_hash,
            transmission_time: beacon_announcement.timestamp,
            estimated_coverage_radius_km: beacon_announcement.estimated_coverage_radius_km(),
            beacon_announcement: beacon_announcement.clone(),
            beacon_hash,
        };

        let statistics = Self::calculate_statistics(&witness_reports, &beacon_announcement);
        let coherence_analysis = Self::analyze_coherence(&witness_reports, &beacon_announcement);
        let coverage_quality =
            Self::assess_coverage_quality(&witness_reports, &beacon_announcement);

        let bundle_id =
            Self::compute_bundle_id(aggregator_id, beacon_hash, &witness_reports, created_at);

        Self {
            bundle_id,
            aggregator_id,
            beacon_event,
            witness_reports,
            statistics,
            coherence_analysis,
            coverage_quality,
            compression_info: None,
            created_at,
            signature: Signature::ed25519([0u8; 64]),
            public_key: PublicKey::ed25519([0u8; 32]),
            cid_hint: None,
        }
    }

    pub fn sign(&mut self, keypair: &KeyPair) -> PoCResult<()> {
        self.public_key = keypair.public_key();

        let expected_id = Address::from_public_key(&self.public_key);
        if expected_id != self.aggregator_id {
            return Err(PoCError::BundleCreationFailed(
                "Aggregator ID does not match signing key".to_string(),
            ));
        }

        let signing_data = self.create_signing_data()?;
        self.signature = keypair.sign(&signing_data);

        Ok(())
    }

    pub fn verify_signature(&self) -> PoCResult<bool> {
        let expected_id = Address::from_public_key(&self.public_key);
        if expected_id != self.aggregator_id {
            return Ok(false);
        }

        let signing_data = self.create_signing_data()?;

        match ego_core::verify_signature(&self.public_key, &signing_data, &self.signature) {
            Ok(valid) => Ok(valid),
            Err(e) => Err(PoCError::SignatureVerificationFailed(format!(
                "Bundle signature verification failed: {}",
                e
            ))),
        }
    }

    pub fn validate(&self) -> PoCResult<()> {
        if self.witness_reports.len() < crate::POC_MIN_WITNESSES {
            return Err(PoCError::InsufficientWitnesses {
                got: self.witness_reports.len(),
                min: crate::POC_MIN_WITNESSES,
            });
        }

        if self.witness_reports.len() > crate::POC_MAX_WITNESSES {
            return Err(PoCError::ExcessiveWitnesses {
                got: self.witness_reports.len(),
                max: crate::POC_MAX_WITNESSES,
            });
        }

        for report in &self.witness_reports {
            report.validate()?;

            if report.beacon_id != self.beacon_event.beacon_announcement.beacon_id {
                return Err(PoCError::ValidationFailed(
                    "Witness report does not match beacon".to_string(),
                ));
            }
        }

        if self.coherence_analysis.overall_coherence_score < 0.5 {
            return Err(PoCError::ValidationFailed(format!(
                "Low coherence score: {}",
                self.coherence_analysis.overall_coherence_score
            )));
        }

        if self.coherence_analysis.fraud_likelihood > 0.8 {
            return Err(PoCError::FraudDetected {
                fraud_type: crate::FraudType::InvalidGeometry,
                details: format!(
                    "High fraud likelihood: {}",
                    self.coherence_analysis.fraud_likelihood
                ),
            });
        }

        Ok(())
    }

    pub fn compress(&mut self) -> PoCResult<()> {
        if self.compression_info.is_some() {
            return Ok(());
        }

        let config = bincode::config::standard();
        let original_data = bincode::encode_to_vec(&*self, config)
            .map_err(|e| PoCError::CompressionError(format!("Encoding failed: {}", e)))?;

        let compressed_data = lz4::block::compress(
            &original_data,
            Some(lz4::block::CompressionMode::HIGHCOMPRESSION(12)),
            true,
        )
        .map_err(|e| PoCError::CompressionError(format!("LZ4 compression failed: {}", e)))?;

        let compression_ratio = compressed_data.len() as f32 / original_data.len() as f32;

        self.compression_info = Some(CompressionInfo {
            algorithm: CompressionAlgorithm::LZ4,
            original_size: original_data.len() as u32,
            compressed_size: compressed_data.len() as u32,
            compression_ratio,
        });

        Ok(())
    }

    pub fn create_poc_event(&self, epoch: u64) -> PoCEvent {
        let witness_hashes = self
            .witness_reports
            .iter()
            .map(|report| report.report_id)
            .collect();

        let agg_digest = self.compute_aggregation_digest();

        PoCEvent {
            beacon_hash: self.beacon_event.beacon_hash,
            witness_hashes,
            agg_digest,
            quality_score: self.coverage_quality.quality_score,
            region: self.beacon_event.h3_cell.clone(),
            epoch,
            cid_hint: self.cid_hint.clone(),
            timestamp: self.created_at,
            aggregator_signature: self.signature.clone(),
        }
    }

    fn calculate_statistics(
        witness_reports: &[WitnessReport],
        beacon_announcement: &BeaconAnnouncement,
    ) -> BundleStatistics {
        let witness_count = witness_reports.len() as u32;
        let valid_witnesses = witness_reports
            .iter()
            .filter(|r| r.detect_potential_fraud().is_none())
            .count() as u32;
        let invalid_witnesses = witness_count - valid_witnesses;

        let avg_rsrp_dbm = if witness_count > 0 {
            witness_reports
                .iter()
                .map(|r| r.rf_metrics.rsrp as f32)
                .sum::<f32>()
                / witness_count as f32
        } else {
            0.0
        };

        let distances: Vec<f32> = witness_reports
            .iter()
            .filter_map(|report| {
                Some(Self::calculate_distance(
                    &report.witness_location,
                    &beacon_announcement.location,
                ))
            })
            .collect();

        let (max_distance_km, min_distance_km) = if !distances.is_empty() {
            (
                *distances
                    .iter()
                    .max_by(|a, b| a.partial_cmp(b).unwrap())
                    .unwrap(),
                *distances
                    .iter()
                    .min_by(|a, b| a.partial_cmp(b).unwrap())
                    .unwrap(),
            )
        } else {
            (0.0, 0.0)
        };

        let geographic_spread_km2 = if distances.len() >= 3 {
            std::f32::consts::PI * max_distance_km.powi(2)
        } else {
            0.0
        };

        BundleStatistics {
            witness_count,
            valid_witnesses,
            invalid_witnesses,
            avg_rsrp_dbm,
            max_distance_km,
            min_distance_km,
            geographic_spread_km2,
            time_window_ms: 30_000,
            duplicate_reports: 0,
        }
    }

    fn analyze_coherence(
        witness_reports: &[WitnessReport],
        beacon_announcement: &BeaconAnnouncement,
    ) -> CoherenceAnalysis {
        let mut suspicious_patterns = Vec::new();

        let geometry_coherence = Self::analyze_geometry_coherence(
            witness_reports,
            beacon_announcement,
            &mut suspicious_patterns,
        );

        let timing_coherence = Self::analyze_timing_coherence(
            witness_reports,
            beacon_announcement,
            &mut suspicious_patterns,
        );

        let signal_coherence =
            Self::analyze_signal_coherence(witness_reports, &mut suspicious_patterns);

        let overall_coherence_score =
            geometry_coherence * 0.4 + timing_coherence * 0.3 + signal_coherence * 0.3;

        let clustering_detected = Self::detect_clustering(witness_reports);
        if clustering_detected {
            suspicious_patterns.push(SuspiciousPattern {
                pattern_type: PatternType::ClusteredWitnesses,
                confidence: 0.8,
                affected_witnesses: witness_reports.iter().map(|r| r.witness_id).collect(),
                description: "Witnesses appear to be clustered together".to_string(),
            });
        }

        let fraud_likelihood = 1.0 - overall_coherence_score;

        CoherenceAnalysis {
            overall_coherence_score,
            geometry_coherence,
            timing_coherence,
            signal_coherence,
            clustering_detected,
            suspicious_patterns,
            fraud_likelihood,
        }
    }

    fn analyze_geometry_coherence(
        witness_reports: &[WitnessReport],
        beacon_announcement: &BeaconAnnouncement,
        suspicious_patterns: &mut Vec<SuspiciousPattern>,
    ) -> f64 {
        let mut coherence_scores = Vec::new();
        let beacon_location = &beacon_announcement.location;

        for report in witness_reports {
            let distance_km = Self::calculate_distance(&report.witness_location, beacon_location);

            let frequency_ghz = report.rf_metrics.frequency as f64 / 1_000_000.0;
            let expected_path_loss =
                20.0 * distance_km.log10() as f64 + 20.0 * frequency_ghz.log10() + 32.44;
            let expected_rsrp = 23.0 - expected_path_loss;

            let actual_rsrp = report.rf_metrics.rsrp as f64;
            let rsrp_error = (expected_rsrp - actual_rsrp).abs();

            let score = if rsrp_error <= 15.0 {
                1.0 - (rsrp_error / 15.0).min(1.0)
            } else {
                0.0
            };

            coherence_scores.push(score);

            if rsrp_error > 25.0 {
                let pattern_type = if actual_rsrp > expected_rsrp {
                    PatternType::SignalTooStrong
                } else {
                    PatternType::SignalTooWeak
                };

                suspicious_patterns.push(SuspiciousPattern {
                    pattern_type,
                    confidence: (rsrp_error / 30.0).min(1.0),
                    affected_witnesses: vec![report.witness_id],
                    description: format!(
                        "RSRP {} dBm inconsistent with distance {} km",
                        actual_rsrp, distance_km
                    ),
                });
            }
        }

        if coherence_scores.is_empty() {
            0.0
        } else {
            coherence_scores.iter().sum::<f64>() / coherence_scores.len() as f64
        }
    }

    fn analyze_timing_coherence(
        witness_reports: &[WitnessReport],
        beacon_announcement: &BeaconAnnouncement,
        suspicious_patterns: &mut Vec<SuspiciousPattern>,
    ) -> f64 {
        let beacon_tx_time = beacon_announcement.timestamp.as_millis();
        let mut coherence_scores = Vec::new();

        for report in witness_reports {
            let rx_time = report.time_sync.rx_timestamp_ms;
            let time_delta = (rx_time as i64 - beacon_tx_time as i64).abs();

            let score = if time_delta <= 1000 {
                1.0 - (time_delta as f64 / 1000.0)
            } else {
                0.0
            };

            coherence_scores.push(score);

            if time_delta > 5000 {
                suspicious_patterns.push(SuspiciousPattern {
                    pattern_type: PatternType::TimingAnomalies,
                    confidence: 0.9,
                    affected_witnesses: vec![report.witness_id],
                    description: format!("Time delta {} ms is suspicious", time_delta),
                });
            }
        }

        if coherence_scores.is_empty() {
            0.0
        } else {
            coherence_scores.iter().sum::<f64>() / coherence_scores.len() as f64
        }
    }

    fn analyze_signal_coherence(
        witness_reports: &[WitnessReport],
        _suspicious_patterns: &mut Vec<SuspiciousPattern>,
    ) -> f64 {
        if witness_reports.len() < 2 {
            return 1.0;
        }

        let mut rsrp_values: Vec<i16> = witness_reports.iter().map(|r| r.rf_metrics.rsrp).collect();

        rsrp_values.sort_unstable();

        let mean = rsrp_values.iter().map(|&x| x as f64).sum::<f64>() / rsrp_values.len() as f64;
        let variance = rsrp_values
            .iter()
            .map(|&x| (x as f64 - mean).powi(2))
            .sum::<f64>()
            / rsrp_values.len() as f64;
        let std_dev = variance.sqrt();

        let coherence = 1.0 - (std_dev / 20.0).min(1.0);

        coherence
    }

    fn detect_clustering(witness_reports: &[WitnessReport]) -> bool {
        if witness_reports.len() < 3 {
            return false;
        }

        let mut close_pairs = 0;
        let total_pairs = witness_reports.len() * (witness_reports.len() - 1) / 2;

        for i in 0..witness_reports.len() {
            for j in i + 1..witness_reports.len() {
                let distance = Self::calculate_distance(
                    &witness_reports[i].witness_location,
                    &witness_reports[j].witness_location,
                );

                if distance < 0.1 {
                    close_pairs += 1;
                }
            }
        }

        (close_pairs as f32 / total_pairs as f32) > 0.5
    }

    fn assess_coverage_quality(
        witness_reports: &[WitnessReport],
        beacon_announcement: &BeaconAnnouncement,
    ) -> CoverageQuality {
        let witness_count = witness_reports.len() as u32;

        let avg_rsrp = if witness_count > 0 {
            witness_reports
                .iter()
                .map(|r| r.rf_metrics.rsrp as f32)
                .sum::<f32>()
                / witness_count as f32
        } else {
            -100.0
        };

        let distances: Vec<f32> = witness_reports
            .iter()
            .map(|report| {
                Self::calculate_distance(&report.witness_location, &beacon_announcement.location)
            })
            .collect();

        let coverage_radius_km = if !distances.is_empty() {
            *distances
                .iter()
                .max_by(|a, b| a.partial_cmp(b).unwrap())
                .unwrap()
        } else {
            0.0
        };

        let interference_level = witness_reports
            .iter()
            .map(|r| (r.rf_metrics.sinr as f32).max(0.0) / 30.0)
            .sum::<f32>()
            / witness_count.max(1) as f32;

        let witness_score = (witness_count as f32 / 10.0).min(1.0);
        let signal_score = ((-avg_rsrp + 140.0) / 96.0).clamp(0.0, 1.0);
        let coverage_score = (coverage_radius_km / 20.0).min(1.0);
        let interference_score = 1.0 - interference_level;

        let quality_score = (witness_score * 0.4
            + signal_score * 0.3
            + coverage_score * 0.2
            + interference_score * 0.1) as f64;

        let density_penalty = if witness_count > 10 {
            0.9 - (witness_count as f64 - 10.0) * 0.02
        } else {
            1.0
        }
        .max(0.5);

        CoverageQuality {
            witness_count,
            avg_rsrp,
            coverage_radius_km,
            interference_level,
            quality_score: quality_score * density_penalty,
            density_penalty: 1.0 - density_penalty,
        }
    }

    fn calculate_distance(loc1: &LocationData, loc2: &LocationData) -> f32 {
        let lat1 = loc1.latitude.to_radians();
        let lat2 = loc2.latitude.to_radians();
        let delta_lat = (loc2.latitude - loc1.latitude).to_radians();
        let delta_lon = (loc2.longitude - loc1.longitude).to_radians();

        let a = (delta_lat / 2.0).sin().powi(2)
            + lat1.cos() * lat2.cos() * (delta_lon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

        6371.0 * c as f32
    }

    fn create_signing_data(&self) -> PoCResult<Vec<u8>> {
        let mut data = Vec::new();

        data.extend_from_slice(self.bundle_id.as_bytes());
        data.extend_from_slice(self.aggregator_id.as_bytes());
        data.extend_from_slice(self.beacon_event.beacon_hash.as_bytes());
        data.extend_from_slice(&self.created_at.as_millis().to_le_bytes());
        data.extend_from_slice(&self.witness_reports.len().to_le_bytes());

        for report in &self.witness_reports {
            data.extend_from_slice(report.report_id.as_bytes());
        }

        data.extend_from_slice(&self.coverage_quality.quality_score.to_le_bytes());
        data.extend_from_slice(
            &self
                .coherence_analysis
                .overall_coherence_score
                .to_le_bytes(),
        );

        Ok(data)
    }

    fn compute_bundle_id(
        aggregator_id: Address,
        beacon_hash: Hash,
        witness_reports: &[WitnessReport],
        timestamp: Timestamp,
    ) -> Hash {
        use ego_core::crypto::hash_multiple;

        let timestamp_bytes = timestamp.as_millis().to_le_bytes();
        let beacon_hash_bytes = beacon_hash.as_bytes();

        let mut hash_inputs = vec![
            aggregator_id.as_bytes(),
            &beacon_hash_bytes[..20],
            &timestamp_bytes,
        ];

        for report in witness_reports {
            let report_id_bytes = report.report_id.as_bytes();
            hash_inputs.push(&report_id_bytes[..20]);
        }

        hash_multiple(&hash_inputs)
    }

    fn compute_aggregation_digest(&self) -> Hash {
        use ego_core::crypto::hash_multiple;

        hash_multiple(&[
            &self.bundle_id.as_bytes()[..20],
            &self.beacon_event.beacon_hash.as_bytes()[..20],
            &self
                .coherence_analysis
                .overall_coherence_score
                .to_le_bytes(),
            &self.coverage_quality.quality_score.to_le_bytes(),
        ])
    }
}

impl PartialEq for BundleStatistics {
    fn eq(&self, other: &Self) -> bool {
        self.witness_count == other.witness_count
            && self.valid_witnesses == other.valid_witnesses
            && (self.avg_rsrp_dbm - other.avg_rsrp_dbm).abs() < f32::EPSILON
    }
}

impl Eq for BundleStatistics {}

impl PartialEq for CoherenceAnalysis {
    fn eq(&self, other: &Self) -> bool {
        (self.overall_coherence_score - other.overall_coherence_score).abs() < f64::EPSILON
            && (self.fraud_likelihood - other.fraud_likelihood).abs() < f64::EPSILON
            && self.clustering_detected == other.clustering_detected
    }
}

impl Eq for CoherenceAnalysis {}

impl PartialEq for PoCBundle {
    fn eq(&self, other: &Self) -> bool {
        self.bundle_id == other.bundle_id
            && self.aggregator_id == other.aggregator_id
            && self.beacon_event.beacon_hash == other.beacon_event.beacon_hash
    }
}

impl Eq for PoCBundle {}

impl PartialEq for PoCEvent {
    fn eq(&self, other: &Self) -> bool {
        self.beacon_hash == other.beacon_hash
            && self.witness_hashes == other.witness_hashes
            && (self.quality_score - other.quality_score).abs() < f64::EPSILON
            && self.region == other.region
            && self.epoch == other.epoch
    }
}

impl Eq for PoCEvent {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::announcement::BeaconTxParams;
    use ego_core::KeyPair;

    fn create_test_bundle() -> PoCBundle {
        let beacon_announcement = create_test_beacon_announcement();
        let witness_reports = vec![create_test_witness_report()];

        PoCBundle::new(
            Address::new([1u8; 20]),
            beacon_announcement,
            witness_reports,
        )
    }

    fn create_test_beacon_announcement() -> BeaconAnnouncement {
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

        let tx_params = BeaconTxParams::default();

        BeaconAnnouncement::new(Address::new([1u8; 20]), challenge, location, tx_params)
    }

    fn create_test_witness_report() -> WitnessReport {
        use crate::witness::WitnessReport;

        let rf_metrics = RFMetrics {
            rsrp: -85,
            rsrq: -10,
            sinr: 15,
            timing_advance: 100,
            pci: 1,
            beam_index: Some(0),
            frequency: 3500,
            rx_timestamp: Timestamp::now().as_millis(),
        };

        let witness_location = LocationData {
            latitude: 37.7849,
            longitude: -122.4094,
            altitude: Some(10.0),
            accuracy: Some(5.0),
            timestamp: Timestamp::now().as_millis(),
            h3_index: "87283472bffffff".to_string(),
        };

        WitnessReport::new(
            Address::new([2u8; 20]),
            Address::new([1u8; 20]),
            Hash::new([3u8; 32]),
            rf_metrics,
            witness_location,
            None,
        )
    }

    #[test]
    fn test_poc_bundle_creation() {
        let bundle = create_test_bundle();
        assert_eq!(bundle.witness_reports.len(), 1);
        assert!(bundle.coverage_quality.quality_score > 0.0);
        assert!(bundle.coherence_analysis.overall_coherence_score >= 0.0);
    }

    #[test]
    fn test_bundle_signing() {
        let keypair = KeyPair::generate();
        let aggregator_id = Address::from_public_key(&keypair.public_key());

        let beacon_announcement = create_test_beacon_announcement();
        let witness_reports = vec![create_test_witness_report()];

        let mut bundle = PoCBundle::new(aggregator_id, beacon_announcement, witness_reports);

        assert!(bundle.sign(&keypair).is_ok());
        assert!(bundle.verify_signature().unwrap());
    }

    #[test]
    fn test_bundle_compression() {
        let mut bundle = create_test_bundle();

        assert!(bundle.compress().is_ok());
        assert!(bundle.compression_info.is_some());

        let compression_info = bundle.compression_info.unwrap();
        assert!(compression_info.compressed_size <= compression_info.original_size);
    }

    #[test]
    fn test_poc_event_creation() {
        let bundle = create_test_bundle();
        let event = bundle.create_poc_event(100);

        assert_eq!(event.beacon_hash, bundle.beacon_event.beacon_hash);
        assert_eq!(event.witness_hashes.len(), 1);
        assert_eq!(event.epoch, 100);
    }

    #[test]
    fn test_coherence_analysis() {
        let bundle = create_test_bundle();

        assert!(bundle.coherence_analysis.overall_coherence_score >= 0.0);
        assert!(bundle.coherence_analysis.overall_coherence_score <= 1.0);
        assert!(bundle.coherence_analysis.fraud_likelihood <= 1.0);
    }
}
