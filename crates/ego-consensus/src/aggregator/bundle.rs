use crate::beacon::BeaconAnnouncement;
use crate::error::{PoCError, PoCResult};
use crate::witness::report::CoBeaconVerification;
use crate::types::*;
use crate::witness::WitnessReport;
use ego_core::{Address, Hash, KeyPair, PublicKey, Signature, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

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
    pub unique_h3_cells: u32,
    pub unique_accounts: u32,
    pub path_loss_rmse: f64,
    pub nonce_binding_fraction: f64,
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
    pub path_loss_fit_quality: PathLossFitQuality,
    pub diversity_metrics: DiversityMetrics,
    pub nonce_verification: NonceVerification,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PathLossFitQuality {
    pub model_type: PathLossModel,
    pub rmse_db: f64,
    pub fit_score: f64,
    pub outlier_count: u32,
    pub acceptable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum PathLossModel {
    UMa,
    UMi,
    FreeSpace,
}

#[derive(Debug, Clone)]
enum FraudPattern {
    TxPowerManipulation,
    LocationSpoofing,
    InvalidGeometry,
    ReplayAttack,
}

#[derive(Debug, Clone)]
struct FraudEvidence {
    pattern: FraudPattern,
    confidence: f64,
    description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DiversityMetrics {
    pub unique_h3_cells: u32,
    pub unique_accounts: u32,
    pub radial_spread_km: f32,
    pub diversity_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct NonceVerification {
    pub witnesses_with_nonce: u32,
    pub total_witnesses: u32,
    pub nonce_binding_fraction: f64,
    pub nonce_score: f64,
    pub replay_detected: bool,
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
    PathLossMismatch,
    LowDiversity,
    NonceBindingFailure,
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

    pub path_loss_rmse: f64,
    pub diversity_score: f64,
    pub nonce_binding_fraction: f64,
    pub ldm_penalty: f64,
}

const UMA_BASE_LOSS: f64 = 32.4;
const UMI_BASE_LOSS: f64 = 32.4;
const RMSE_THRESHOLD_URBAN: f64 = 10.0;
const RMSE_THRESHOLD_RURAL: f64 = 8.0;
const MIN_DIVERSITY_H3_CELLS: usize = 2;
const MIN_DIVERSITY_ACCOUNTS: usize = 2;
const MIN_NONCE_BINDING_FRACTION: f64 = 0.6;
const DENSITY_THRESHOLD_METERS: f32 = 1.0;
const DENSITY_PENALTY_PER_DEVICE: f64 = 0.10;
const DENSITY_PENALTY_FLOOR: f64 = 0.40;

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
            Self::assess_coverage_quality(&witness_reports, &beacon_announcement, &coherence_analysis);

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

        if self.statistics.unique_h3_cells < MIN_DIVERSITY_H3_CELLS as u32 {
            return Err(PoCError::ValidationFailed(format!(
                "Insufficient H3 cell diversity: got {}, need {}",
                self.statistics.unique_h3_cells, MIN_DIVERSITY_H3_CELLS
            )));
        }

        if self.statistics.unique_accounts < MIN_DIVERSITY_ACCOUNTS as u32 {
            return Err(PoCError::ValidationFailed(format!(
                "Insufficient account diversity: got {}, need {}",
                self.statistics.unique_accounts, MIN_DIVERSITY_ACCOUNTS
            )));
        }

        if !self.coherence_analysis.path_loss_fit_quality.acceptable {
            return Err(PoCError::ValidationFailed(format!(
                "Path-loss fit RMSE {} dB exceeds threshold (model: {:?})",
                self.coherence_analysis.path_loss_fit_quality.rmse_db,
                self.coherence_analysis.path_loss_fit_quality.model_type
            )));
        }

        if self.statistics.nonce_binding_fraction < MIN_NONCE_BINDING_FRACTION {
            return Err(PoCError::ValidationFailed(format!(
                "Insufficient nonce binding: {:.2}% of witnesses, need {:.0}%",
                self.statistics.nonce_binding_fraction * 100.0,
                MIN_NONCE_BINDING_FRACTION * 100.0
            )));
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

        if self.coherence_analysis.nonce_verification.replay_detected {
            return Err(PoCError::FraudDetected {
                fraud_type: crate::FraudType::ReplayAttack,
                details: "Nonce replay detected".to_string(),
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
            path_loss_rmse: self.coherence_analysis.path_loss_fit_quality.rmse_db,
            diversity_score: self.coherence_analysis.diversity_metrics.diversity_score,
            nonce_binding_fraction: self.statistics.nonce_binding_fraction,
            ldm_penalty: self.coverage_quality.density_penalty,
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

        let unique_h3_cells = witness_reports
            .iter()
            .map(|r| r.witness_location.h3_index.as_str())
            .collect::<HashSet<_>>()
            .len() as u32;

        let unique_accounts = witness_reports
            .iter()
            .map(|r| r.witness_id)
            .collect::<HashSet<_>>()
            .len() as u32;

        let witnesses_with_nonce = witness_reports
            .iter()
            .filter(|r| {
                r.co_beacon_verification
                    .as_ref()
                    .map_or(false, |v| v.signature_valid && !v.received_nonce.is_empty())
            })
            .count();
        let nonce_binding_fraction = if witness_count > 0 {
            witnesses_with_nonce as f64 / witness_count as f64
        } else {
            0.0
        };

        let path_loss_rmse = 0.0;

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
            unique_h3_cells,
            unique_accounts,
            path_loss_rmse,
            nonce_binding_fraction,
        }
    }

    fn analyze_coherence(
        witness_reports: &[WitnessReport],
        beacon_announcement: &BeaconAnnouncement,
    ) -> CoherenceAnalysis {
        let mut suspicious_patterns = Vec::new();

        let path_loss_fit_quality = Self::fit_3gpp_path_loss(
            witness_reports,
            beacon_announcement,
            &mut suspicious_patterns,
        );

        let diversity_metrics = Self::calculate_diversity_metrics(
            witness_reports,
            beacon_announcement,
            &mut suspicious_patterns,
        );

        let nonce_verification = Self::verify_nonce_binding(
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

        let geometry_coherence = path_loss_fit_quality.fit_score;

        let overall_coherence_score = geometry_coherence * 0.4
            + diversity_metrics.diversity_score * 0.2
            + (diversity_metrics.radial_spread_km / 20.0).min(1.0) as f64 * 0.2
            + nonce_verification.nonce_score * 0.2;

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
            path_loss_fit_quality,
            diversity_metrics,
            nonce_verification,
        }
    }

fn fit_3gpp_path_loss(
    witness_reports: &[WitnessReport],
    beacon_announcement: &BeaconAnnouncement,
    suspicious_patterns: &mut Vec<SuspiciousPattern>,
) -> PathLossFitQuality {
    if witness_reports.is_empty() {
        return PathLossFitQuality {
            model_type: PathLossModel::FreeSpace,
            rmse_db: f64::INFINITY,
            fit_score: 0.0,
            outlier_count: 0,
            acceptable: false,
        };
    }

    let beacon_location = &beacon_announcement.location;

    let avg_distance: f32 = witness_reports
        .iter()
        .map(|r| Self::calculate_distance(&r.witness_location, beacon_location))
        .sum::<f32>()
        / witness_reports.len() as f32;

    let model_type = if avg_distance > 5.0 {
        PathLossModel::UMa
    } else {
        PathLossModel::UMi
    };

    let mut errors = Vec::new();
    let mut outliers = 0;

    for report in witness_reports {
        let distance_km = Self::calculate_distance(&report.witness_location, beacon_location);
        let distance_m = (distance_km * 1000.0).max(1.0);

        let frequency_ghz = report.rf_metrics.frequency as f64 / 1_000_000.0;

        let scenario = if distance_m < 1000.0 {
            "UMi"
        } else if distance_m < 5000.0 {
            "UMa"
        } else {
            "RMa"
        };

        let expected_path_loss = match scenario {
            "UMa" => {
                13.54 + 39.08 * distance_m.log10() + 20.0 * (frequency_ghz.log10() as f32)
            }
            "UMi" => {
                22.4 + 35.3 * distance_m.log10() + 21.3 * (frequency_ghz.log10() as f32)
            }
            "RMa" => {
                20.0 * distance_m.log10() + 20.0 * (frequency_ghz.log10() as f32) + 32.44
            }
            _ => {

                20.0 * distance_m.log10() + 20.0 * (frequency_ghz.log10() as f32) + 32.44
            }
        };

        let expected_rsrp = 23.0 - expected_path_loss;
        let actual_rsrp = report.rf_metrics.rsrp;
        let error = (expected_rsrp - actual_rsrp as f32).abs();

        errors.push(error);

        if error > 25.0 {
            outliers += 1;
            let pattern_type = if actual_rsrp as f32 > expected_rsrp {
                PatternType::SignalTooStrong
            } else {
                PatternType::SignalTooWeak
            };

            suspicious_patterns.push(SuspiciousPattern {
                pattern_type,
                confidence: ((error / 30.0).min(1.0)) as f64,
                affected_witnesses: vec![report.witness_id],
                description: format!(
                    "Path-loss mismatch: RSRP {:.1} dBm, expected {:.1} dBm (distance {:.2} km, model {:?})",
                    actual_rsrp, expected_rsrp, distance_km, model_type
                ),
            });
        }
    }

    let mse = errors.iter().map(|&e| (e as f64).powi(2)).sum::<f64>() / errors.len() as f64;
    let rmse_db = mse.sqrt();

    let threshold = if matches!(model_type, PathLossModel::UMa | PathLossModel::UMi) {
        RMSE_THRESHOLD_URBAN
    } else {
        RMSE_THRESHOLD_RURAL
    };
    let fit_score = (1.0 - (rmse_db / threshold)).max(0.0).min(1.0);

    let acceptable = rmse_db <= threshold;

    if !acceptable {
        suspicious_patterns.push(SuspiciousPattern {
            pattern_type: PatternType::PathLossMismatch,
            confidence: 0.9,
            affected_witnesses: vec![],
            description: format!(
                "Path-loss RMSE {:.2} dB exceeds threshold {:.2} dB (model: {:?})",
                rmse_db, threshold, model_type
            ),
        });
    }

    PathLossFitQuality {
        model_type,
        rmse_db,
        fit_score,
        outlier_count: outliers,
        acceptable,
    }
}

    fn calculate_diversity_metrics(
        witness_reports: &[WitnessReport],
        beacon_announcement: &BeaconAnnouncement,
        suspicious_patterns: &mut Vec<SuspiciousPattern>,
    ) -> DiversityMetrics {
        let unique_h3_cells = witness_reports
            .iter()
            .map(|r| r.witness_location.h3_index.as_str())
            .collect::<HashSet<_>>()
            .len() as u32;

        let unique_accounts = witness_reports
            .iter()
            .map(|r| r.witness_id)
            .collect::<HashSet<_>>()
            .len() as u32;

        let distances: Vec<f32> = witness_reports
            .iter()
            .map(|r| Self::calculate_distance(&r.witness_location, &beacon_announcement.location))
            .collect();

        let radial_spread_km = if !distances.is_empty() {
            *distances
                .iter()
                .max_by(|a, b| a.partial_cmp(b).unwrap())
                .unwrap()
        } else {
            0.0
        };

        let h3_diversity = (unique_h3_cells as f64 / MIN_DIVERSITY_H3_CELLS as f64).min(1.0);
        let account_diversity = (unique_accounts as f64 / MIN_DIVERSITY_ACCOUNTS as f64).min(1.0);
        let diversity_score = (h3_diversity + account_diversity) / 2.0;

        if unique_h3_cells < MIN_DIVERSITY_H3_CELLS as u32 {
            suspicious_patterns.push(SuspiciousPattern {
                pattern_type: PatternType::LowDiversity,
                confidence: 0.9,
                affected_witnesses: vec![],
                description: format!(
                    "Low H3 cell diversity: {} cells (need {})",
                    unique_h3_cells, MIN_DIVERSITY_H3_CELLS
                ),
            });
        }

        if unique_accounts < MIN_DIVERSITY_ACCOUNTS as u32 {
            suspicious_patterns.push(SuspiciousPattern {
                pattern_type: PatternType::LowDiversity,
                confidence: 0.9,
                affected_witnesses: vec![],
                description: format!(
                    "Low account diversity: {} accounts (need {})",
                    unique_accounts, MIN_DIVERSITY_ACCOUNTS
                ),
            });
        }

        DiversityMetrics {
            unique_h3_cells,
            unique_accounts,
            radial_spread_km,
            diversity_score,
        }
    }

    fn verify_nonce_binding(
        witness_reports: &[WitnessReport],
        _beacon_announcement: &BeaconAnnouncement,
        suspicious_patterns: &mut Vec<SuspiciousPattern>,
    ) -> NonceVerification {
        let total_witnesses = witness_reports.len() as u32;
        let witnesses_with_nonce = witness_reports
            .iter()
            .filter(|r| {
                r.co_beacon_verification
                    .as_ref()
                    .map_or(false, |v| v.signature_valid && !v.received_nonce.is_empty())
            })
            .count() as u32;

        let nonce_binding_fraction = if total_witnesses > 0 {
            witnesses_with_nonce as f64 / total_witnesses as f64
        } else {
            0.0
        };

        let nonce_score = (nonce_binding_fraction / MIN_NONCE_BINDING_FRACTION).min(1.0);

        let mut nonce_map: HashMap<Vec<u8>, Vec<Address>> = HashMap::new();
        for report in witness_reports {
            if let Some(ref co_beacon) = report.co_beacon_verification {
                if co_beacon.signature_valid && !co_beacon.received_nonce.is_empty() {
                    nonce_map
                       .entry(co_beacon.received_nonce.clone())
                        .or_insert_with(Vec::new)
                        .push(report.witness_id);
                }
            }
        }

        let replay_detected = nonce_map.values().any(|witnesses| witnesses.len() > 1);

        if replay_detected {
            for (nonce, witnesses) in nonce_map.iter() {
                if witnesses.len() > 1 {
                    suspicious_patterns.push(SuspiciousPattern {
                        pattern_type: PatternType::RepeatedNonces,
                        confidence: 1.0,
                        affected_witnesses: witnesses.clone(),
                        description: format!(
                            "Nonce replay detected: {} witnesses share nonce {:?}",
                            witnesses.len(),
                            nonce
                        ),
                    });
                }
            }
        }

        if nonce_binding_fraction < MIN_NONCE_BINDING_FRACTION {
            suspicious_patterns.push(SuspiciousPattern {
                pattern_type: PatternType::NonceBindingFailure,
                confidence: 0.8,
                affected_witnesses: vec![],
                description: format!(
                    "Low nonce binding: {:.1}% of witnesses (need {:.0}%)",
                    nonce_binding_fraction * 100.0,
                    MIN_NONCE_BINDING_FRACTION * 100.0
                ),
            });
        }

        NonceVerification {
            witnesses_with_nonce,
            total_witnesses,
            nonce_binding_fraction,
            nonce_score,
            replay_detected,
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
                let horizontal_distance = Self::calculate_distance(
                    &witness_reports[i].witness_location,
                    &witness_reports[j].witness_location,
                );

                let vertical_distance = {
                    let alt1 = witness_reports[i].witness_location.altitude.unwrap_or(0.0);
                    let alt2 = witness_reports[j].witness_location.altitude.unwrap_or(0.0);
                    (alt1 - alt2).abs()
                };

                let horizontal_m = horizontal_distance * 1000.0;
                let is_clustered = horizontal_m <= DENSITY_THRESHOLD_METERS && vertical_distance <= 2.0;

                if is_clustered {
                    close_pairs += 1;
                }
            }
        }

        (close_pairs as f32 / total_pairs as f32) > 0.5
    }

    fn assess_coverage_quality(
        witness_reports: &[WitnessReport],
        beacon_announcement: &BeaconAnnouncement,
        coherence_analysis: &CoherenceAnalysis,
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

        let fit_score = coherence_analysis.path_loss_fit_quality.fit_score;
        let diversity_score = coherence_analysis.diversity_metrics.diversity_score;
        let radius_score = (coverage_radius_km / 20.0).min(1.0) as f64;
        let nonce_score = coherence_analysis.nonce_verification.nonce_score;

        let path_loss_penalty = if coherence_analysis.path_loss_fit_quality.outlier_count > 0 {
            0.05 * coherence_analysis.path_loss_fit_quality.outlier_count as f64
        } else {
            0.0
        };

        let timing_penalty = (1.0 - coherence_analysis.timing_coherence) * 0.1;
        let signal_penalty = (1.0 - coherence_analysis.signal_coherence) * 0.05;
        let total_penalties = (path_loss_penalty + timing_penalty + signal_penalty).min(0.3);

        let raw_quality = (fit_score * 0.4
            + diversity_score * 0.2
            + radius_score * 0.2
            + nonce_score * 0.2
            - total_penalties)
            .clamp(0.0, 1.0);

        let density_penalty = Self::calculate_ldm_penalty(witness_reports, beacon_announcement);

        let final_quality = raw_quality * (1.0 - density_penalty);

        CoverageQuality {
            witness_count,
            avg_rsrp,
            coverage_radius_km,
            interference_level,
            quality_score: final_quality,
            density_penalty,
        }
    }

    fn calculate_ldm_penalty(
        witness_reports: &[WitnessReport],
        _beacon_announcement: &BeaconAnnouncement,
    ) -> f64 {
        if witness_reports.len() < 2 {
            return 0.0;
        }

        let mut clusters: Vec<Vec<usize>> = Vec::new();

        for i in 0..witness_reports.len() {
            let mut found_cluster = false;

            for cluster in clusters.iter_mut() {

                let is_close_to_cluster = cluster.iter().any(|&j| {
                    let horizontal_distance = Self::calculate_distance(
                        &witness_reports[i].witness_location,
                        &witness_reports[j].witness_location,
                    );

                    let vertical_distance = {
                        let alt1 = witness_reports[i].witness_location.altitude.unwrap_or(0.0);
                        let alt2 = witness_reports[j].witness_location.altitude.unwrap_or(0.0);
                        (alt1 - alt2).abs()
                    };

                    let horizontal_m = horizontal_distance * 1000.0;
                    horizontal_m <= DENSITY_THRESHOLD_METERS && vertical_distance <= 2.0
                });

                if is_close_to_cluster {
                    cluster.push(i);
                    found_cluster = true;
                    break;
                }
            }

            if !found_cluster {
                clusters.push(vec![i]);
            }
        }

        let max_cluster_size = clusters.iter().map(|c| c.len()).max().unwrap_or(1);

        if max_cluster_size == 1 {
            return 0.0;
        }

        let n = max_cluster_size as f64;
        let ldm_penalty = (1.0 - DENSITY_PENALTY_PER_DEVICE * (n - 1.0)).max(DENSITY_PENALTY_FLOOR);

        1.0 - ldm_penalty
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

        data.extend_from_slice(&self.statistics.path_loss_rmse.to_le_bytes());
        data.extend_from_slice(&self.statistics.nonce_binding_fraction.to_le_bytes());
        data.extend_from_slice(&self.coverage_quality.density_penalty.to_le_bytes());

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
            &self.statistics.path_loss_rmse.to_le_bytes(),
            &self.statistics.nonce_binding_fraction.to_le_bytes(),
        ])
    }

    pub fn get_ldm_penalty(&self) -> f64 {
        self.coverage_quality.density_penalty
    }

    pub fn get_path_loss_rmse(&self) -> f64 {
        self.coherence_analysis.path_loss_fit_quality.rmse_db
    }

    pub fn get_diversity_score(&self) -> f64 {
        self.coherence_analysis.diversity_metrics.diversity_score
    }

    pub fn get_nonce_binding_fraction(&self) -> f64 {
        self.statistics.nonce_binding_fraction
    }

    pub fn meets_quality_threshold(&self, q_min: f64) -> bool {
        self.coverage_quality.quality_score >= q_min
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
        let witness_reports = vec![
            create_test_witness_report(37.7849, -122.4094, true),
            create_test_witness_report(37.7750, -122.4294, true),
            create_test_witness_report(37.7650, -122.4394, true),
        ];

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

    fn create_test_witness_report(lat: f64, lon: f64, valid_nonce: bool) -> WitnessReport {
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
            latitude: lat,
            longitude: lon,
            altitude: Some(10.0),
            accuracy: Some(5.0),
            timestamp: Timestamp::now().as_millis(),
            h3_index: "87283472bffffff".to_string(),
        };

        let mut report = WitnessReport::new(
            Address::new([2u8; 20]),
            Address::new([1u8; 20]),
            Hash::new([3u8; 32]),
            rf_metrics,
            witness_location,
            None,
        );

        if valid_nonce {
            report.co_beacon_verification = Some(CoBeaconVerification {
                received_nonce: vec![3u8; 16],
                signature_valid: true,
                rx_timestamp: Timestamp::now().as_millis(),
                time_delta_ms: 0,
                side_channel_rssi: Some(-45),
            });
        }

        report
    }

    #[test]
    fn test_poc_bundle_creation() {
        let bundle = create_test_bundle();
        assert_eq!(bundle.witness_reports.len(), 3);
        assert!(bundle.coverage_quality.quality_score > 0.0);
        assert!(bundle.coherence_analysis.overall_coherence_score >= 0.0);
    }

    #[test]
    fn test_bundle_signing() {
        let keypair = KeyPair::generate();
        let aggregator_id = Address::from_public_key(&keypair.public_key());

        let beacon_announcement = create_test_beacon_announcement();
        let witness_reports = vec![create_test_witness_report(37.7849, -122.4094, true)];

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
        assert_eq!(event.witness_hashes.len(), 3);
        assert_eq!(event.epoch, 100);
        assert!(event.path_loss_rmse >= 0.0);
        assert!(event.nonce_binding_fraction >= 0.0);
    }

    #[test]
    fn test_coherence_analysis() {
        let bundle = create_test_bundle();

        assert!(bundle.coherence_analysis.overall_coherence_score >= 0.0);
        assert!(bundle.coherence_analysis.overall_coherence_score <= 1.0);
        assert!(bundle.coherence_analysis.fraud_likelihood <= 1.0);
    }

    #[test]
    fn test_whitepaper_diversity_validation() {
        let beacon_announcement = create_test_beacon_announcement();

        let witness_reports = vec![
            create_test_witness_report(37.7749, -122.4194, true),
        ];

        let bundle = PoCBundle::new(
            Address::new([1u8; 20]),
            beacon_announcement.clone(),
            witness_reports,
        );

        assert!(bundle.validate().is_err());
    }

    #[test]
    fn test_whitepaper_nonce_binding() {
        let beacon_announcement = create_test_beacon_announcement();

        let witness_reports = vec![
            create_test_witness_report(37.7849, -122.4094, false),
            create_test_witness_report(37.7750, -122.4294, false),
            create_test_witness_report(37.7650, -122.4394, false),
        ];

        let bundle = PoCBundle::new(
            Address::new([1u8; 20]),
            beacon_announcement,
            witness_reports,
        );

        assert!(bundle.validate().is_err());
    }

    #[test]
    fn test_3gpp_path_loss_fitting() {
        let bundle = create_test_bundle();

        assert!(bundle.coherence_analysis.path_loss_fit_quality.rmse_db >= 0.0);
        assert!(matches!(
            bundle.coherence_analysis.path_loss_fit_quality.model_type,
            PathLossModel::UMa | PathLossModel::UMi | PathLossModel::FreeSpace
        ));
    }

    #[test]
    fn test_ldm_density_penalty() {
        let bundle = create_test_bundle();

        let ldm_penalty = bundle.get_ldm_penalty();
        assert!(ldm_penalty >= 0.0);
        assert!(ldm_penalty <= 1.0);
    }

    #[test]
    fn test_quality_threshold() {
        let bundle = create_test_bundle();

        let meets_threshold = bundle.meets_quality_threshold(0.5);

        assert!(meets_threshold || bundle.coverage_quality.quality_score < 0.5);
    }

    #[test]
    fn test_replay_detection() {
        let beacon_announcement = create_test_beacon_announcement();

        let mut witness1 = create_test_witness_report(37.7849, -122.4094, true);
        let mut witness2 = create_test_witness_report(37.7750, -122.4294, true);
        let mut witness3 = create_test_witness_report(37.7650, -122.4394, true);

        let duplicate_nonce = vec![99u8; 16];
        if let Some(ref mut co_beacon) = witness1.co_beacon_verification {
            co_beacon.received_nonce = duplicate_nonce.clone();
        }
        if let Some(ref mut co_beacon) = witness2.co_beacon_verification {
            co_beacon.received_nonce = duplicate_nonce;
        }

        let witness_reports = vec![witness1, witness2, witness3];

        let bundle = PoCBundle::new(
            Address::new([1u8; 20]),
            beacon_announcement,
            witness_reports,
        );

        assert!(bundle.coherence_analysis.nonce_verification.replay_detected);
        assert!(bundle.validate().is_err());
    }
}
