use crate::error::{PoCError, PoCResult};
use crate::types::*;
use ego_core::{Address, Hash, Timestamp};
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
            h3_resolution: 7,
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
            rsrp: -200, // Invalid
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
            h3_index: "87283472bffffff".to_string(),
        };

        assert!(validator.validate_location(&valid_location).is_ok());

        let invalid_location = LocationData {
            latitude: 91.0,
            longitude: -122.4194,
            altitude: Some(10.0),
            accuracy: Some(5.0),
            timestamp: Timestamp::now().as_millis(),
            h3_index: "87283472bffffff".to_string(),
        };

        assert!(validator.validate_location(&invalid_location).is_err());
    }
}
