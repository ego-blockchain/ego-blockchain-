use crate::types::*;
use ego_core::Timestamp;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    pub error_type: ValidationErrorType,
    pub message: String,
    pub field: Option<String>,
    pub severity: ValidationSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationErrorType {
    InvalidRFMetrics,
    InvalidLocation,
    InvalidTiming,
    InsufficientWitnesses,
    FraudDetected,
    SignatureInvalid,
    GeometryInconsistent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

pub type ValidationResult = Result<(), ValidationError>;

pub struct PoCValidator {
    config: ValidationConfig,
}

impl PoCValidator {
    pub fn new(config: ValidationConfig) -> Self {
        Self { config }
    }

    pub fn validate_rf_metrics(&self, metrics: &RFMetrics) -> ValidationResult {
        if metrics.rsrp < self.config.rf_validation.min_rsrp_dbm
            || metrics.rsrp > self.config.rf_validation.max_rsrp_dbm
        {
            return Err(ValidationError {
                error_type: ValidationErrorType::InvalidRFMetrics,
                message: format!("RSRP {} dBm out of valid range", metrics.rsrp),
                field: Some("rsrp".to_string()),
                severity: ValidationSeverity::Error,
            });
        }

        if metrics.rsrq < self.config.rf_validation.min_rsrq_db
            || metrics.rsrq > self.config.rf_validation.max_rsrq_db
        {
            return Err(ValidationError {
                error_type: ValidationErrorType::InvalidRFMetrics,
                message: format!("RSRQ {} dB out of valid range", metrics.rsrq),
                field: Some("rsrq".to_string()),
                severity: ValidationSeverity::Error,
            });
        }

        if metrics.sinr < self.config.rf_validation.min_sinr_db
            || metrics.sinr > self.config.rf_validation.max_sinr_db
        {
            return Err(ValidationError {
                error_type: ValidationErrorType::InvalidRFMetrics,
                message: format!("SINR {} dB out of valid range", metrics.sinr),
                field: Some("sinr".to_string()),
                severity: ValidationSeverity::Error,
            });
        }

        Ok(())
    }

    pub fn validate_location(&self, location: &LocationData) -> ValidationResult {
        if location.latitude < -90.0 || location.latitude > 90.0 {
            return Err(ValidationError {
                error_type: ValidationErrorType::InvalidLocation,
                message: format!("Invalid latitude: {}", location.latitude),
                field: Some("latitude".to_string()),
                severity: ValidationSeverity::Error,
            });
        }

        if location.longitude < -180.0 || location.longitude > 180.0 {
            return Err(ValidationError {
                error_type: ValidationErrorType::InvalidLocation,
                message: format!("Invalid longitude: {}", location.longitude),
                field: Some("longitude".to_string()),
                severity: ValidationSeverity::Error,
            });
        }

        if let Some(accuracy) = location.accuracy {
            if accuracy > self.config.geo_validation.gps_accuracy_threshold_m {
                return Err(ValidationError {
                    error_type: ValidationErrorType::InvalidLocation,
                    message: format!("GPS accuracy {} m exceeds threshold", accuracy),
                    field: Some("accuracy".to_string()),
                    severity: ValidationSeverity::Warning,
                });
            }
        }

        Ok(())
    }

    pub fn validate_timing(&self, timestamp: Timestamp) -> ValidationResult {
        let now = Timestamp::now();
        let diff = (timestamp.as_millis() as i64 - now.as_millis() as i64).abs() as u64;

        if diff > self.config.time_validation.max_clock_drift_ms {
            return Err(ValidationError {
                error_type: ValidationErrorType::InvalidTiming,
                message: format!("Timestamp drift {} ms exceeds limit", diff),
                field: Some("timestamp".to_string()),
                severity: ValidationSeverity::Error,
            });
        }

        Ok(())
    }

    pub fn validate_geometry_coherence(
        &self,
        beacon_location: &LocationData,
        witness_location: &LocationData,
        rf_metrics: &RFMetrics,
        tx_power_dbm: i16,
    ) -> ValidationResult {
        let distance_km = self.calculate_distance(beacon_location, witness_location);
        let frequency_ghz = rf_metrics.frequency as f64 / 1_000_000.0;

        let path_loss = if distance_km < 0.01 {
            20.0 * distance_km.log10() + 20.0 * (frequency_ghz as f32).log10() + 32.44
        } else {
            let fc = (frequency_ghz * 1000.0) as f32;
            let d3d = (distance_km * 1000.0) as f32;
            let h_bs = 25.0_f32;
            let h_ut = 1.5_f32;

            let pl_los = 28.0 + 22.0 * d3d.log10() + 20.0 * fc.log10();
            let pl_nlos = 13.54 + 39.08 * d3d.log10() + 20.0 * fc.log10() - 0.6 * (h_ut - 1.5);

            pl_los.max(pl_nlos)
        };

        let expected_rsrp = tx_power_dbm as f32 - path_loss;
        let actual_rsrp = rf_metrics.rsrp as f32;
        let error = (expected_rsrp - actual_rsrp).abs();

        if error > self.config.rf_validation.path_loss_tolerance_db {
            return Err(ValidationError {
                error_type: ValidationErrorType::GeometryInconsistent,
                message: format!(
                    "Path loss error {} dB exceeds tolerance for distance {} km",
                    error, distance_km
                ),
                field: Some("geometry".to_string()),
                severity: ValidationSeverity::Error,
            });
        }

        Ok(())
    }

    fn calculate_distance(&self, loc1: &LocationData, loc2: &LocationData) -> f32 {
        let lat1 = loc1.latitude.to_radians();
        let lat2 = loc2.latitude.to_radians();
        let delta_lat = (loc2.latitude - loc1.latitude).to_radians();
        let delta_lon = (loc2.longitude - loc1.longitude).to_radians();

        let a = (delta_lat / 2.0).sin().powi(2)
            + lat1.cos() * lat2.cos() * (delta_lon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

        6371.0 * c as f32
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rf_validation() {
        let validator = PoCValidator::new(ValidationConfig::default());

        let valid_metrics = RFMetrics {
            rsrp: -85,
            rsrq: -10,
            sinr: 15,
            timing_advance: 100,
            pci: 1,
            beam_index: Some(0),
            frequency: 3500,
            rx_timestamp: Timestamp::now().as_millis(),
        };

        assert!(validator.validate_rf_metrics(&valid_metrics).is_ok());

        let invalid_metrics = RFMetrics {
            rsrp: -200,
            rsrq: -10,
            sinr: 15,
            timing_advance: 100,
            pci: 1,
            beam_index: Some(0),
            frequency: 3500,
            rx_timestamp: Timestamp::now().as_millis(),
        };

        assert!(validator.validate_rf_metrics(&invalid_metrics).is_err());
    }

    #[test]
    fn test_location_validation() {
        let validator = PoCValidator::new(ValidationConfig::default());

        let valid_location = LocationData {
            latitude: 37.7749,
            longitude: -122.4194,
            altitude: Some(10.0),
            accuracy: Some(5.0),
            timestamp: Timestamp::now().as_millis(),
            h3_index: "872834720ffffff".to_string(),
        };

        assert!(validator.validate_location(&valid_location).is_ok());

        let invalid_location = LocationData {
            latitude: 91.0,
            longitude: -122.4194,
            altitude: Some(10.0),
            accuracy: Some(5.0),
            timestamp: Timestamp::now().as_millis(),
            h3_index: "872834720ffffff".to_string(),
        };

        assert!(validator.validate_location(&invalid_location).is_err());
    }

    #[test]
    fn test_geometry_coherence_validation() {
        let validator = PoCValidator::new(ValidationConfig::default());

        let beacon_location = LocationData {
            latitude: 37.7749,
            longitude: -122.4194,
            altitude: Some(10.0),
            accuracy: Some(5.0),
            timestamp: Timestamp::now().as_millis(),
            h3_index: "872834720ffffff".to_string(),
        };

        let witness_location = LocationData {
            latitude: 37.7849,
            longitude: -122.4094,
            altitude: Some(10.0),
            accuracy: Some(5.0),
            timestamp: Timestamp::now().as_millis(),
            h3_index: "872834720ffffff".to_string(),
        };

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

        assert!(
            validator
                .validate_geometry_coherence(&beacon_location, &witness_location, &rf_metrics, 23)
                .is_ok()
        );
    }
}
