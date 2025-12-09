use crate::error::{PoCError, PoCResult};
use crate::types::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RFValidator {
    pub min_rsrp_dbm: i16,
    pub max_rsrp_dbm: i16,
    pub min_rsrq_db: i16,
    pub max_rsrq_db: i16,
    pub min_sinr_db: i16,
    pub max_sinr_db: i16,
    pub max_timing_advance: u32,
}

impl RFValidator {
    pub fn new() -> Self {
        Self {
            min_rsrp_dbm: -140,
            max_rsrp_dbm: -44,
            min_rsrq_db: -19,
            max_rsrq_db: -3,
            min_sinr_db: -20,
            max_sinr_db: 30,
            max_timing_advance: 1282,
        }
    }

    pub fn validate_rf_metrics(&self, metrics: &RFMetrics) -> PoCResult<()> {
        if metrics.rsrp < self.min_rsrp_dbm || metrics.rsrp > self.max_rsrp_dbm {
            return Err(PoCError::InvalidRFMetrics(format!(
                "RSRP {} dBm out of range [{}, {}]",
                metrics.rsrp, self.min_rsrp_dbm, self.max_rsrp_dbm
            )));
        }

        if metrics.rsrq < self.min_rsrq_db || metrics.rsrq > self.max_rsrq_db {
            return Err(PoCError::InvalidRFMetrics(format!(
                "RSRQ {} dB out of range [{}, {}]",
                metrics.rsrq, self.min_rsrq_db, self.max_rsrq_db
            )));
        }

        if metrics.sinr < self.min_sinr_db || metrics.sinr > self.max_sinr_db {
            return Err(PoCError::InvalidRFMetrics(format!(
                "SINR {} dB out of range [{}, {}]",
                metrics.sinr, self.min_sinr_db, self.max_sinr_db
            )));
        }

        if metrics.timing_advance > self.max_timing_advance {
            return Err(PoCError::InvalidRFMetrics(format!(
                "Timing advance {} exceeds maximum {}",
                metrics.timing_advance, self.max_timing_advance
            )));
        }

        Ok(())
    }

    pub fn validate_path_loss(
        &self,
        distance_km: f32,
        frequency_ghz: f32,
        tx_power_dbm: i16,
        rx_power_dbm: i16,
        tolerance_db: f32,
    ) -> PoCResult<()> {
        let expected_path_loss = calculate_free_space_path_loss(distance_km, frequency_ghz);
        let expected_rx_power = tx_power_dbm as f32 - expected_path_loss;
        let actual_rx_power = rx_power_dbm as f32;

        let error = (expected_rx_power - actual_rx_power).abs();

        if error > tolerance_db {
            return Err(PoCError::PathLossValidationFailed {
                expected_db: expected_rx_power,
                actual_db: actual_rx_power,
            });
        }

        Ok(())
    }
}

impl Default for RFValidator {
    fn default() -> Self {
        Self::new()
    }
}

pub fn calculate_free_space_path_loss(distance_km: f32, frequency_ghz: f32) -> f32 {
    20.0 * distance_km.log10() + 20.0 * frequency_ghz.log10() + 32.44
}

pub fn calculate_timing_advance_distance(timing_advance: u32) -> f32 {
    (timing_advance as f32 * 78.0) / 1000.0
}

pub fn estimate_received_power(tx_power_dbm: i16, distance_km: f32, frequency_ghz: f32) -> f32 {
    let path_loss = calculate_free_space_path_loss(distance_km, frequency_ghz);
    tx_power_dbm as f32 - path_loss
}

pub fn validate_rf_geometry(
    beacon_location: &LocationData,
    witness_location: &LocationData,
    rf_metrics: &RFMetrics,
    tx_power_dbm: i16,
) -> PoCResult<()> {
    let distance_km = calculate_distance(beacon_location, witness_location);
    let frequency_ghz = rf_metrics.frequency as f32 / 1_000_000.0;

    let validator = RFValidator::new();
    validator.validate_path_loss(
        distance_km,
        frequency_ghz,
        tx_power_dbm,
        rf_metrics.rsrp,
        20.0,
    )?;

    let expected_ta_distance = calculate_timing_advance_distance(rf_metrics.timing_advance);
    let ta_error = (distance_km - expected_ta_distance).abs();

    if ta_error > 5.0 {
        return Err(PoCError::DistanceValidationFailed {
            distance_km: expected_ta_distance,
            max_km: distance_km + 5.0,
        });
    }

    Ok(())
}

fn calculate_distance(loc1: &LocationData, loc2: &LocationData) -> f32 {
    let lat1 = loc1.latitude.to_radians();
    let lat2 = loc2.latitude.to_radians();
    let delta_lat = (loc2.latitude - loc1.latitude).to_radians();
    let delta_lon = (loc2.longitude - loc1.longitude).to_radians();

    let a =
        (delta_lat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (delta_lon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

    6371.0 * c as f32
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rf_metrics_validation() {
        let validator = RFValidator::new();

        let valid_metrics = RFMetrics {
            rsrp: -85,
            rsrq: -10,
            sinr: 15,
            timing_advance: 100,
            pci: 1,
            beam_index: Some(0),
            frequency: 3500,
            rx_timestamp: ego_core::Timestamp::now().as_millis(),
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
            rx_timestamp: ego_core::Timestamp::now().as_millis(),
        };

        assert!(validator.validate_rf_metrics(&invalid_metrics).is_err());
    }

    #[test]
    fn test_path_loss_calculation() {
        // Free-space path loss at 1km, 3.5 GHz
        let path_loss = calculate_free_space_path_loss(1.0, 3.5);
        
        // FSPL = 20*log10(1) + 20*log10(3.5) + 32.44 ≈ 43.3 dB
        println!("Free-space path loss: {} dB", path_loss);
        assert!(path_loss > 40.0 && path_loss < 50.0);
        
        // Verify it increases with distance
        let path_loss_10km = calculate_free_space_path_loss(10.0, 3.5);
        assert!(path_loss_10km > path_loss);
    }

    #[test]
    fn test_timing_advance_distance() {
        let distance = calculate_timing_advance_distance(100);
        assert!((distance - 7.8).abs() < 0.1);
    }
}