use crate::beacon::BeaconAnnouncement;
use crate::config::epoch::{EpochConfig, EpochConfigProvider};
use crate::error::PoCResult;
use crate::types::*;
use crate::witness::WitnessReport;
use ego_core::Address;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// Whitepaper constants
pub const MIN_DIVERSITY_H3_CELLS: usize = 2;
pub const MIN_DIVERSITY_ACCOUNTS: usize = 2;
pub const MIN_NONCE_BINDING_FRACTION: f64 = 0.6; // 60%
pub const RMSE_THRESHOLD_UMA: f64 = 10.0; // dB
pub const RMSE_THRESHOLD_UMI: f64 = 10.0; // dB
pub const RMSE_THRESHOLD_RURAL: f64 = 8.0; // dB
pub const DENSITY_THRESHOLD_METERS: f32 = 1.0; // Horizontal co-location
pub const DENSITY_THRESHOLD_VERTICAL: f32 = 2.0; // Vertical co-location
pub const DENSITY_PENALTY_PER_DEVICE: f64 = 0.10; // -10% per extra device
pub const DENSITY_PENALTY_FLOOR: f64 = 0.40; // Floor at 40%
pub const MIN_QUALITY_SCORE: f64 = 0.5; // Default q_min

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub diversity_check: DiversityCheck,
    pub path_loss_check: PathLossCheck,
    pub nonce_check: NonceCheck,
    pub quality_score: f64,
    pub ldm_penalty: f64,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiversityCheck {
    pub unique_h3_cells: usize,
    pub unique_accounts: usize,
    pub min_h3_cells_met: bool,
    pub min_accounts_met: bool,
    pub diversity_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathLossCheck {
    pub model_type: PathLossModel,
    pub rmse_db: f64,
    pub threshold_db: f64,
    pub fit_score: f64,
    pub outlier_count: usize,
    pub acceptable: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PathLossModel {
    UMa,       // Urban Macro
    UMi,       // Urban Micro
    Rural,     // Rural/Suburban
    FreeSpace, // Fallback
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceCheck {
    pub witnesses_with_valid_nonce: usize,
    pub total_witnesses: usize,
    pub binding_fraction: f64,
    pub min_fraction_met: bool,
    pub replay_detected: bool,
    pub nonce_score: f64,
}

/// Whitepaper: Verify witness diversity (≥2 H3 cells and ≥2 accounts)
pub fn verify_witness_diversity(
    witness_reports: &[WitnessReport],
) -> PoCResult<DiversityCheck> {
    let unique_h3_cells: HashSet<&str> = witness_reports
        .iter()
        .map(|r| r.witness_location.h3_index.as_str())
        .collect();

    let unique_accounts: HashSet<Address> = witness_reports
        .iter()
        .map(|r| r.witness_id)
        .collect();

    let unique_h3_count = unique_h3_cells.len();
    let unique_account_count = unique_accounts.len();

    let min_h3_cells_met = unique_h3_count >= MIN_DIVERSITY_H3_CELLS;
    let min_accounts_met = unique_account_count >= MIN_DIVERSITY_ACCOUNTS;

    // Diversity score: normalize to [0, 1]
    let h3_diversity = (unique_h3_count as f64 / MIN_DIVERSITY_H3_CELLS as f64).min(1.0);
    let account_diversity = (unique_account_count as f64 / MIN_DIVERSITY_ACCOUNTS as f64).min(1.0);
    let diversity_score = (h3_diversity + account_diversity) / 2.0;

    Ok(DiversityCheck {
        unique_h3_cells: unique_h3_count,
        unique_accounts: unique_account_count,
        min_h3_cells_met,
        min_accounts_met,
        diversity_score,
    })
}

fn calculate_haversine_distance(loc1: &LocationData, loc2: &LocationData) -> f32 {
    let lat1 = loc1.latitude.to_radians();
    let lat2 = loc2.latitude.to_radians();
    let delta_lat = (loc2.latitude - loc1.latitude).to_radians();
    let delta_lon = (loc2.longitude - loc1.longitude).to_radians();

    let a = (delta_lat / 2.0).sin().powi(2)
        + lat1.cos() * lat2.cos() * (delta_lon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

    6371.0 * c as f32 // Earth radius in km
}

fn calculate_path_loss_error(
    beacon_announcement: &BeaconAnnouncement,
    witness_report: &WitnessReport,
) -> f32 {
    let beacon_location = &beacon_announcement.location;
    let witness_location = &witness_report.witness_location;
    
    // FIXED: Use local function instead of ego_core::geo
    let distance_km = calculate_haversine_distance(witness_location, beacon_location);
    let distance_m = (distance_km * 1000.0).max(1.0) as f32;

    let frequency_ghz = witness_report.rf_metrics.frequency as f64 / 1_000_000.0;
    let tx_power_dbm = beacon_announcement.tx_params.tx_power_dbm as f32;

    let scenario = if distance_m < 1000.0 {
        "UMi"
    } else if distance_m < 5000.0 {
        "UMa"
    } else {
        "RMa"
    };

    let path_loss = match scenario {
        "UMa" => {
            13.54 + 39.08 * distance_m.log10() + 20.0 * (frequency_ghz.log10() as f32)
        }
        "UMi" => {
            22.4 + 35.3 * distance_m.log10() + 21.3 * (frequency_ghz.log10() as f32)
        }
        "RMa" => {
            20.0 + 30.0 * distance_m.log10() + 20.0 * (frequency_ghz.log10() as f32)
        }
        _ => {
            20.0 * distance_m.log10() + 20.0 * (frequency_ghz.log10() as f32) + 32.44
        }
    };

    let expected_rsrp = tx_power_dbm - path_loss;
    let actual_rsrp = witness_report.rf_metrics.rsrp;
    let error = (expected_rsrp - actual_rsrp as f32).abs();
    
    error
}

/// Whitepaper: Calculate path-loss RMSE across all witnesses
pub fn calculate_path_loss_rmse(
    beacon_announcement: &BeaconAnnouncement,
    witness_reports: &[WitnessReport],
) -> f32 {
    if witness_reports.is_empty() {
        return 0.0;
    }

    let mut squared_errors = Vec::new();

    for report in witness_reports {
        let error = calculate_path_loss_error(beacon_announcement, report);
        squared_errors.push(error * error);
    }

    let mse = squared_errors.iter().map(|&e| e as f64).sum::<f64>() / squared_errors.len() as f64;
    mse.sqrt() as f32
}

/// Whitepaper: Verify 3GPP path-loss fitting
pub fn verify_3gpp_path_loss(
    witness_reports: &[WitnessReport],
    beacon_announcement: &BeaconAnnouncement,
) -> PoCResult<PathLossCheck> {
    if witness_reports.is_empty() {
        return Ok(PathLossCheck {
            model_type: PathLossModel::FreeSpace,
            rmse_db: f64::INFINITY,
            threshold_db: RMSE_THRESHOLD_UMI,
            fit_score: 0.0,
            outlier_count: 0,
            acceptable: false,
        });
    }

    // Determine model type based on average distance
    let beacon_location = &beacon_announcement.location;
    let avg_distance: f32 = witness_reports
        .iter()
        .map(|r| {
            calculate_haversine_distance(&r.witness_location, beacon_location)
        })
        .sum::<f32>()
        / witness_reports.len() as f32;

    let model_type = if avg_distance > 5.0 {
        PathLossModel::UMa
    } else if avg_distance > 1.0 {
        PathLossModel::UMi
    } else {
        PathLossModel::Rural
    };

    let threshold_db = match model_type {
        PathLossModel::UMa => RMSE_THRESHOLD_UMA,
        PathLossModel::UMi => RMSE_THRESHOLD_UMI,
        _ => RMSE_THRESHOLD_RURAL,
    };

    let rmse = calculate_path_loss_rmse(beacon_announcement, witness_reports) as f64;
    let fit_score = (1.0 - (rmse / threshold_db)).max(0.0).min(1.0);
    let acceptable = rmse <= threshold_db;

    // Count outliers (errors > 25 dB)
    let outlier_count = witness_reports
        .iter()
        .filter(|r| {
            let error = calculate_path_loss_error(beacon_announcement, r);
            error > 25.0
        })
        .count();

    Ok(PathLossCheck {
        model_type,
        rmse_db: rmse,
        threshold_db,
        fit_score,
        outlier_count,
        acceptable,
    })
}

/// Whitepaper: Co-beacon nonce binding verification with custom threshold
pub fn verify_nonce_binding_with_threshold(
    witness_reports: &[WitnessReport],
    min_binding_fraction: f64,
) -> PoCResult<NonceCheck> {
    let total_witnesses = witness_reports.len();

    let witnesses_with_valid_nonce = witness_reports
        .iter()
        .filter(|r| {
            r.co_beacon_verification
                .as_ref()
                .map_or(false, |v| v.signature_valid && !v.received_nonce.is_empty())
        })
        .count();

    let binding_fraction = if total_witnesses > 0 {
        witnesses_with_valid_nonce as f64 / total_witnesses as f64
    } else {
        0.0
    };

    let min_fraction_met = binding_fraction >= min_binding_fraction;

    // Detect replay attacks: check for duplicate nonces
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

    let replay_detected = nonce_map.values().any(|addresses| addresses.len() > 1);

    // Nonce score: normalize to [0, 1]
    let nonce_score = (binding_fraction / min_binding_fraction).min(1.0);

    Ok(NonceCheck {
        witnesses_with_valid_nonce,
        total_witnesses,
        binding_fraction,
        min_fraction_met,
        replay_detected,
        nonce_score,
    })
}

/// Whitepaper: Co-beacon nonce binding verification (legacy version)
pub fn verify_nonce_binding(witness_reports: &[WitnessReport]) -> PoCResult<NonceCheck> {
    verify_nonce_binding_with_threshold(witness_reports, MIN_NONCE_BINDING_FRACTION)
}

/// Whitepaper: Deterministic quality score calculation
/// q = 0.4·fit + 0.2·diversity + 0.2·radius + 0.2·nonce − penalties
pub fn calculate_deterministic_quality_score(
    path_loss_check: &PathLossCheck,
    diversity_check: &DiversityCheck,
    nonce_check: &NonceCheck,
    max_radius_km: f32,
    penalties: f64,
) -> f64 {
    let fit_score = path_loss_check.fit_score;
    let diversity_score = diversity_check.diversity_score;
    let radius_score = (max_radius_km / 20.0).min(1.0) as f64;
    let nonce_score = nonce_check.nonce_score;

    let raw_quality = fit_score * 0.4
        + diversity_score * 0.2
        + radius_score * 0.2
        + nonce_score * 0.2
        - penalties.min(0.3);

    raw_quality.clamp(0.0, 1.0)
}

/// Whitepaper: LDM density penalty calculation
/// For n devices in ~1m² (time-weighted): LDM = max(1 − 0.10·(n−1), 0.40)
pub fn apply_density_penalty(witness_reports: &[WitnessReport]) -> f64 {
    if witness_reports.len() < 2 {
        return 0.0;
    }

    let mut clusters: Vec<Vec<usize>> = Vec::new();

    for i in 0..witness_reports.len() {
        let mut found_cluster = false;

        for cluster in clusters.iter_mut() {
            let is_close_to_cluster = cluster.iter().any(|&j| {
                let horizontal_distance = calculate_haversine_distance(
                    &witness_reports[i].witness_location,
                    &witness_reports[j].witness_location,
                );

                let vertical_distance = {
                    let alt1 = witness_reports[i].witness_location.altitude.unwrap_or(0.0);
                    let alt2 = witness_reports[j].witness_location.altitude.unwrap_or(0.0);
                    (alt1 - alt2).abs()
                };

                let horizontal_m = horizontal_distance * 1000.0;
                horizontal_m <= DENSITY_THRESHOLD_METERS && vertical_distance <= DENSITY_THRESHOLD_VERTICAL
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
    let ldm = (1.0 - DENSITY_PENALTY_PER_DEVICE * (n - 1.0)).max(DENSITY_PENALTY_FLOOR);

    1.0 - ldm
}

/// Complete validation check per whitepaper with epoch-aware thresholds
pub fn validate_poc_bundle_with_epoch_config(
    witness_reports: &[WitnessReport],
    beacon_announcement: &BeaconAnnouncement,
    epoch_config: &EpochConfig,
    epoch: u64,
) -> PoCResult<ValidationResult> {
    let thresholds = epoch_config.get_config(epoch);
    validate_poc_bundle_impl(
        witness_reports,
        beacon_announcement,
        thresholds.quality_thresholds.min_quality_score,
        Some(thresholds),
    )
}

/// Complete validation check per whitepaper
/// DEPRECATED: Use validate_poc_bundle_with_epoch_config for new code
pub fn validate_poc_bundle(
    witness_reports: &[WitnessReport],
    beacon_announcement: &BeaconAnnouncement,
    quality_threshold: f64,
) -> PoCResult<ValidationResult> {
    validate_poc_bundle_impl(witness_reports, beacon_announcement, quality_threshold, None)
}

/// Internal implementation with optional epoch config
fn validate_poc_bundle_impl(
    witness_reports: &[WitnessReport],
    beacon_announcement: &BeaconAnnouncement,
    quality_threshold: f64,
    epoch_config: Option<&crate::config::epoch::ThresholdConfig>,
) -> PoCResult<ValidationResult> {
    let mut errors = Vec::new();

    let diversity_check = verify_witness_diversity(witness_reports)?;
    if !diversity_check.min_h3_cells_met {
        errors.push(format!(
            "Insufficient H3 cell diversity: {} cells (need {})",
            diversity_check.unique_h3_cells, MIN_DIVERSITY_H3_CELLS
        ));
    }
    if !diversity_check.min_accounts_met {
        errors.push(format!(
            "Insufficient account diversity: {} accounts (need {})",
            diversity_check.unique_accounts, MIN_DIVERSITY_ACCOUNTS
        ));
    }

    let path_loss_check = verify_3gpp_path_loss(witness_reports, beacon_announcement)?;
    if !path_loss_check.acceptable {
        errors.push(format!(
            "Path-loss RMSE {:.2} dB exceeds threshold {:.2} dB (model: {:?})",
            path_loss_check.rmse_db, path_loss_check.threshold_db, path_loss_check.model_type
        ));
    }

    // Use epoch-based nonce binding threshold if available
    let min_nonce_binding = epoch_config
        .map(|cfg| cfg.quality_thresholds.min_nonce_binding_fraction)
        .unwrap_or(MIN_NONCE_BINDING_FRACTION);

    let nonce_check = verify_nonce_binding_with_threshold(witness_reports, min_nonce_binding)?;
    if !nonce_check.min_fraction_met {
        errors.push(format!(
            "Insufficient nonce binding: {:.1}% of witnesses (need {:.0}%)",
            nonce_check.binding_fraction * 100.0,
            min_nonce_binding * 100.0
        ));
    }
    if nonce_check.replay_detected {
        errors.push("Nonce replay detected".to_string());
    }

    let beacon_location = &beacon_announcement.location;
    let max_radius_km = witness_reports
        .iter()
        .map(|r| calculate_haversine_distance(&r.witness_location, beacon_location))
        .max_by(|a, b| a.partial_cmp(b).unwrap())
        .unwrap_or(0.0);

    let path_loss_penalty = if path_loss_check.outlier_count > 0 {
        0.05 * path_loss_check.outlier_count as f64
    } else {
        0.0
    };
    let total_penalties = path_loss_penalty.min(0.3);

    let quality_score = calculate_deterministic_quality_score(
        &path_loss_check,
        &diversity_check,
        &nonce_check,
        max_radius_km,
        total_penalties,
    );

    let ldm_penalty = apply_density_penalty(witness_reports);
    let final_quality = quality_score * (1.0 - ldm_penalty);

    if final_quality < quality_threshold {
        errors.push(format!(
            "Quality score {:.3} below threshold {:.3}",
            final_quality, quality_threshold
        ));
    }

    let valid = errors.is_empty();

    Ok(ValidationResult {
        valid,
        diversity_check,
        path_loss_check,
        nonce_check,
        quality_score: final_quality,
        ldm_penalty,
        errors,
    })
}


#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::{Hash, KeyPair, Timestamp};
    use crate::witness::report::{CoBeaconVerification, TimeSyncData}; // Remove ReportMetadata

    fn create_test_witness(lat: f64, lon: f64, valid_nonce: bool) -> WitnessReport {
        let keypair = KeyPair::generate();
        let witness_id = ego_core::Address::from_public_key(&keypair.public_key());
        
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
            h3_index: format!("8728347{}ffffff", (lat * 100.0) as i32 % 10),
        };
    
        let beacon_location = LocationData {
            latitude: 37.7749,
            longitude: -122.4194,
            altitude: Some(10.0),
            accuracy: Some(5.0),
            timestamp: Timestamp::now().as_millis(),
            h3_index: "87283472bffffff".to_string(),
        };
    
        let time_sync = TimeSyncData {
            rx_timestamp_ms: Timestamp::now().as_millis(),
            tx_timestamp_ms: Timestamp::now().as_millis(),
            time_of_flight_ns: 0,
            clock_offset_ms: 0,
            gps_timestamp: Some(Timestamp::now().as_millis()),
            ntp_synced: true,  // ADDED
        };
    
        let mut report = WitnessReport {
            witness_id,
            beacon_id: Address::new([1u8; 20]),
            report_id: Hash::new([2u8; 32]),
            challenge_hash: Hash::new([3u8; 32]),
            witness_location,
            beacon_location: Some(beacon_location),
            rf_metrics,
            timestamp: Timestamp::now(),
            time_sync,
            signature: keypair.sign(b"test"),
            public_key: keypair.public_key(),
            co_beacon_verification: None,
            metadata: Vec::new(),  // CHANGED
            slice_context: None,
        };
    
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
    fn test_diversity_check_sufficient() {
        let witnesses = vec![
            create_test_witness(37.7749, -122.4194, true),
            create_test_witness(37.7849, -122.4094, true),
            create_test_witness(37.7649, -122.4294, true),
        ];

        let result = verify_witness_diversity(&witnesses).unwrap();
        assert!(result.min_h3_cells_met);
        assert!(result.min_accounts_met);
        assert!(result.diversity_score > 0.0);
    }

    #[test]
    fn test_diversity_check_insufficient_cells() {
        let witnesses = vec![
            create_test_witness(37.7749, -122.4194, true),
        ];

        let result = verify_witness_diversity(&witnesses).unwrap();
        assert!(!result.min_h3_cells_met);
        assert_eq!(result.unique_h3_cells, 1);
    }

    #[test]
    fn test_path_loss_fitting() {
        use crate::beacon::{BeaconAnnouncement, announcement::BeaconTxParams};
        use crate::types::Challenge;

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

        let beacon = BeaconAnnouncement::new(
            Address::new([1u8; 20]),
            challenge,
            location,
            BeaconTxParams::default(),
        );

        let witnesses = vec![
            create_test_witness(37.7849, -122.4094, true),
            create_test_witness(37.7750, -122.4294, true),
        ];

        let result = verify_3gpp_path_loss(&witnesses, &beacon).unwrap();
        assert!(result.rmse_db >= 0.0);
        assert!(matches!(
            result.model_type,
            PathLossModel::UMa | PathLossModel::UMi | PathLossModel::Rural
        ));
    }


#[test]
fn test_nonce_binding_sufficient() {
    let mut witness1 = create_test_witness(37.7749, -122.4194, true);
    let mut witness2 = create_test_witness(37.7849, -122.4094, true);
    let mut witness3 = create_test_witness(37.7649, -122.4294, true);

    // Give each witness a UNIQUE nonce
    if let Some(ref mut co_beacon) = witness1.co_beacon_verification {
        co_beacon.received_nonce = vec![1u8; 16];
    }
    if let Some(ref mut co_beacon) = witness2.co_beacon_verification {
        co_beacon.received_nonce = vec![2u8; 16];
    }
    if let Some(ref mut co_beacon) = witness3.co_beacon_verification {
        co_beacon.received_nonce = vec![3u8; 16];
    }

    let witnesses = vec![witness1, witness2, witness3];

    let result = verify_nonce_binding(&witnesses).unwrap();
    assert!(result.min_fraction_met);
    assert_eq!(result.binding_fraction, 1.0);
    assert!(!result.replay_detected); // Now should pass
}

    #[test]
    fn test_nonce_binding_insufficient() {
        let witnesses = vec![
            create_test_witness(37.7749, -122.4194, false),
            create_test_witness(37.7849, -122.4094, false),
            create_test_witness(37.7649, -122.4294, true),
        ];

        let result = verify_nonce_binding(&witnesses).unwrap();
        assert!(!result.min_fraction_met);
        assert_eq!(result.binding_fraction, 1.0 / 3.0);
    }

    #[test]
    fn test_nonce_replay_detection() {
        let mut witness1 = create_test_witness(37.7749, -122.4194, true);
        let mut witness2 = create_test_witness(37.7849, -122.4094, true);

        // Set same nonce (replay)
        let duplicate_nonce = vec![99u8; 16];
        if let Some(ref mut co_beacon) = witness1.co_beacon_verification {
            co_beacon.received_nonce = duplicate_nonce.clone();
        }
        if let Some(ref mut co_beacon) = witness2.co_beacon_verification {
            co_beacon.received_nonce = duplicate_nonce;
        }

        let witnesses = vec![witness1, witness2];
        let result = verify_nonce_binding(&witnesses).unwrap();
        assert!(result.replay_detected);
    }

    #[test]
    fn test_quality_score_calculation() {
        let path_loss_check = PathLossCheck {
            model_type: PathLossModel::UMi,
            rmse_db: 8.0,
            threshold_db: 10.0,
            fit_score: 0.8,
            outlier_count: 0,
            acceptable: true,
        };

        let diversity_check = DiversityCheck {
            unique_h3_cells: 3,
            unique_accounts: 3,
            min_h3_cells_met: true,
            min_accounts_met: true,
            diversity_score: 1.0,
        };

        let nonce_check = NonceCheck {
            witnesses_with_valid_nonce: 3,
            total_witnesses: 3,
            binding_fraction: 1.0,
            min_fraction_met: true,
            replay_detected: false,
            nonce_score: 1.0,
        };

        let quality = calculate_deterministic_quality_score(
            &path_loss_check,
            &diversity_check,
            &nonce_check,
            10.0,
            0.0,
        );

        assert!((quality - 0.82).abs() < 0.01);
    }

    #[test]
    fn test_density_penalty_no_clustering() {
        let witnesses = vec![
            create_test_witness(37.7749, -122.4194, true),
            create_test_witness(37.7849, -122.4094, true),
        ];

        let penalty = apply_density_penalty(&witnesses);
        assert_eq!(penalty, 0.0);
    }

    #[test]
    fn test_density_penalty_clustering() {
        let witnesses = vec![
            create_test_witness(37.7749, -122.4194, true),
            create_test_witness(37.7749, -122.4194, true),
            create_test_witness(37.7749, -122.4194, true),
        ];

        let penalty = apply_density_penalty(&witnesses);
        assert!((penalty - 0.20).abs() < 0.01);
    }

    #[test]
    fn test_complete_validation() {
        use crate::beacon::{BeaconAnnouncement, announcement::BeaconTxParams};
        use crate::types::Challenge;

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

        let beacon = BeaconAnnouncement::new(
            Address::new([1u8; 20]),
            challenge,
            location,
            BeaconTxParams::default(),
        );

        let witnesses = vec![
            create_test_witness(37.7849, -122.4094, true),
            create_test_witness(37.7750, -122.4294, true),
            create_test_witness(37.7650, -122.4394, true),
        ];

        let result = validate_poc_bundle(&witnesses, &beacon, MIN_QUALITY_SCORE).unwrap();
        
        if !result.valid {
            println!("Validation errors: {:?}", result.errors);
        }
    }
}