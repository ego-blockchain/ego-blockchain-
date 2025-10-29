use crate::beacon::BeaconAnnouncement;
use crate::error::{PoCError, PoCResult};
use crate::types::*;
use ego_core::{Address, Hash, KeyPair, PublicKey, Signature, Timestamp, verify_signature};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct WitnessReport {
    pub report_id: Hash,

    pub witness_id: Address,

    pub beacon_id: Address,

    pub challenge_hash: Hash,

    pub rf_metrics: RFMetrics,

    pub witness_location: LocationData,

    pub beacon_location: Option<LocationData>,

    pub co_beacon_verification: Option<CoBeaconVerification>,

    pub time_sync: TimeSyncData,

    pub slice_context: Option<SliceContext>,

    pub timestamp: Timestamp,

    pub signature: Signature,

    pub public_key: PublicKey,

    pub metadata: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct CoBeaconVerification {
    pub received_nonce: Vec<u8>,

    pub signature_valid: bool,

    pub rx_timestamp: u64,

    pub time_delta_ms: i32,

    pub side_channel_rssi: Option<i16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct TimeSyncData {
    pub rx_timestamp_ms: u64,

    pub tx_timestamp_ms: u64,

    pub time_of_flight_ns: u32,

    pub clock_offset_ms: i32,

    pub gps_timestamp: Option<u64>,

    pub ntp_synced: bool,
}

impl WitnessReport {
    pub fn new(
        witness_id: Address,
        beacon_id: Address,
        challenge_hash: Hash,
        rf_metrics: RFMetrics,
        witness_location: LocationData,
        beacon_announcement: Option<&BeaconAnnouncement>,
    ) -> Self {
        let timestamp = Timestamp::now();

        let beacon_location = beacon_announcement.map(|ann| ann.location.clone());

        let time_sync = TimeSyncData {
            rx_timestamp_ms: rf_metrics.rx_timestamp,
            tx_timestamp_ms: beacon_announcement
                .map(|ann| ann.timestamp.as_millis())
                .unwrap_or(timestamp.as_millis()),
            time_of_flight_ns: Self::estimate_time_of_flight(&witness_location, &beacon_location),
            clock_offset_ms: 0,
            gps_timestamp: Some(witness_location.timestamp),
            ntp_synced: true,
        };

        let report_data = Self::compute_report_hash(
            witness_id,
            beacon_id,
            challenge_hash,
            &rf_metrics,
            timestamp,
        );

        Self {
            report_id: report_data,
            witness_id,
            beacon_id,
            challenge_hash,
            rf_metrics,
            witness_location,
            beacon_location,
            co_beacon_verification: None,
            time_sync,
            slice_context: None,
            timestamp,
            signature: Signature::ed25519([0u8; 64]),
            public_key: PublicKey::ed25519([0u8; 32]),
            metadata: Vec::new(),
        }
    }

    pub fn sign(&mut self, keypair: &KeyPair) -> PoCResult<()> {
        self.public_key = keypair.public_key();

        let expected_id = Address::from_public_key(&self.public_key);
        if expected_id != self.witness_id {
            return Err(PoCError::InvalidWitnessReport(
                "Witness ID does not match signing key".to_string(),
            ));
        }

        let signing_data = self.create_signing_data()?;
        self.signature = keypair.sign(&signing_data);

        self.report_id = Self::compute_report_hash(
            self.witness_id,
            self.beacon_id,
            self.challenge_hash,
            &self.rf_metrics,
            self.timestamp,
        );

        Ok(())
    }

    pub fn verify_signature(&self) -> PoCResult<bool> {
        let expected_id = Address::from_public_key(&self.public_key);
        if expected_id != self.witness_id {
            return Ok(false);
        }

        let signing_data = self.create_signing_data()?;

        match verify_signature(&self.public_key, &signing_data, &self.signature) {
            Ok(valid) => Ok(valid),
            Err(e) => Err(PoCError::SignatureVerificationFailed(format!(
                "Signature verification failed: {}",
                e
            ))),
        }
    }

    pub fn validate(&self) -> PoCResult<()> {
        let now = Timestamp::now();
        if self.timestamp.as_millis() > now.as_millis() + 60_000 {
            return Err(PoCError::TimeWindowViolation(
                "Report timestamp too far in future".to_string(),
            ));
        }

        self.validate_rf_metrics()?;

        self.validate_location()?;

        self.validate_time_sync()?;

        if let Some(ref beacon_location) = self.beacon_location {
            self.validate_distance(beacon_location)?;
        }

        Ok(())
    }

    fn validate_rf_metrics(&self) -> PoCResult<()> {
        let metrics = &self.rf_metrics;

        if metrics.rsrp < crate::MIN_RSRP_DBM || metrics.rsrp > crate::MAX_RSRP_DBM {
            return Err(PoCError::InvalidRFMetrics(format!(
                "RSRP out of range: {} dBm",
                metrics.rsrp
            )));
        }

        if metrics.rsrq < crate::MIN_RSRQ_DB || metrics.rsrq > crate::MAX_RSRQ_DB {
            return Err(PoCError::InvalidRFMetrics(format!(
                "RSRQ out of range: {} dB",
                metrics.rsrq
            )));
        }

        if metrics.sinr < crate::MIN_SINR_DB || metrics.sinr > crate::MAX_SINR_DB {
            return Err(PoCError::InvalidRFMetrics(format!(
                "SINR out of range: {} dB",
                metrics.sinr
            )));
        }

        if metrics.timing_advance > crate::MAX_TIMING_ADVANCE {
            return Err(PoCError::InvalidRFMetrics(format!(
                "Timing advance out of range: {}",
                metrics.timing_advance
            )));
        }

        Ok(())
    }

    fn validate_location(&self) -> PoCResult<()> {
        let location = &self.witness_location;

        if location.latitude < -90.0 || location.latitude > 90.0 {
            return Err(PoCError::InvalidLocation(format!(
                "Invalid latitude: {}",
                location.latitude
            )));
        }

        if location.longitude < -180.0 || location.longitude > 180.0 {
            return Err(PoCError::InvalidLocation(format!(
                "Invalid longitude: {}",
                location.longitude
            )));
        }

        if let Some(accuracy) = location.accuracy {
            if accuracy > 100.0 {
                return Err(PoCError::InvalidLocation(format!(
                    "GPS accuracy too low: {} meters",
                    accuracy
                )));
            }
        }

        Ok(())
    }

    fn validate_time_sync(&self) -> PoCResult<()> {
        let sync = &self.time_sync;

        if sync.time_of_flight_ns > 1_000_000_000 {
            return Err(PoCError::TimingValidationFailed(
                "Time of flight too large".to_string(),
            ));
        }

        if sync.clock_offset_ms.abs() > 10_000 {
            return Err(PoCError::TimingValidationFailed(format!(
                "Clock offset too large: {} ms",
                sync.clock_offset_ms
            )));
        }

        let time_delta = (sync.rx_timestamp_ms as i64) - (sync.tx_timestamp_ms as i64);
        if time_delta.abs() > 60_000 {
            return Err(PoCError::TimingValidationFailed(
                "TX/RX timestamp difference too large".to_string(),
            ));
        }

        Ok(())
    }

    fn validate_distance(&self, beacon_location: &LocationData) -> PoCResult<()> {
        let distance_km = Self::calculate_distance(&self.witness_location, beacon_location);

        if distance_km > 50.0 {
            return Err(PoCError::DistanceValidationFailed {
                distance_km,
                max_km: 50.0,
            });
        }

        if distance_km < 0.1 {
            return Err(PoCError::DistanceValidationFailed {
                distance_km,
                max_km: 0.1,
            });
        }

        self.validate_path_loss(distance_km)?;

        Ok(())
    }

    fn validate_path_loss(&self, distance_km: f32) -> PoCResult<()> {
        let frequency_ghz = self.rf_metrics.frequency as f32 / 1_000_000.0;

        let expected_path_loss = 20.0 * distance_km.log10() + 20.0 * frequency_ghz.log10() + 32.44;

        let tx_power = 23.0;
        let expected_rsrp = tx_power - expected_path_loss;

        let actual_rsrp = self.rf_metrics.rsrp as f32;
        let path_loss_error = (expected_rsrp - actual_rsrp).abs();

        if path_loss_error > 20.0 {
            return Err(PoCError::PathLossValidationFailed {
                expected_db: expected_rsrp,
                actual_db: actual_rsrp,
            });
        }

        Ok(())
    }

    fn create_signing_data(&self) -> PoCResult<Vec<u8>> {
        let mut data = Vec::new();

        data.extend_from_slice(self.witness_id.as_bytes());
        data.extend_from_slice(self.beacon_id.as_bytes());
        data.extend_from_slice(self.challenge_hash.as_bytes());
        data.extend_from_slice(&self.timestamp.as_millis().to_le_bytes());

        data.extend_from_slice(&self.rf_metrics.rsrp.to_le_bytes());
        data.extend_from_slice(&self.rf_metrics.rsrq.to_le_bytes());
        data.extend_from_slice(&self.rf_metrics.sinr.to_le_bytes());
        data.extend_from_slice(&self.rf_metrics.timing_advance.to_le_bytes());

        data.extend_from_slice(&self.witness_location.latitude.to_le_bytes());
        data.extend_from_slice(&self.witness_location.longitude.to_le_bytes());

        data.extend_from_slice(&self.time_sync.rx_timestamp_ms.to_le_bytes());
        data.extend_from_slice(&self.time_sync.tx_timestamp_ms.to_le_bytes());

        Ok(data)
    }

    fn compute_report_hash(
        witness_id: Address,
        beacon_id: Address,
        challenge_hash: Hash,
        rf_metrics: &RFMetrics,
        timestamp: Timestamp,
    ) -> Hash {
        use ego_core::crypto::hash_multiple;

        hash_multiple(&[
            witness_id.as_bytes(),
            beacon_id.as_bytes(),
            challenge_hash.as_bytes(),
            &rf_metrics.rx_timestamp.to_le_bytes(),
            &timestamp.as_millis().to_le_bytes(),
        ])
    }

    fn estimate_time_of_flight(
        witness_location: &LocationData,
        beacon_location: &Option<LocationData>,
    ) -> u32 {
        if let Some(beacon_loc) = beacon_location {
            let distance_km = Self::calculate_distance(witness_location, beacon_loc);
            let distance_m = distance_km * 1000.0;
            let time_of_flight_us = distance_m / 299.792458;
            (time_of_flight_us * 1000.0) as u32
        } else {
            0
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

    pub fn add_co_beacon_verification(&mut self, verification: CoBeaconVerification) {
        self.co_beacon_verification = Some(verification);
    }

    pub fn set_slice_context(&mut self, slice_context: SliceContext) {
        self.slice_context = Some(slice_context);
    }

    pub fn calculate_quality_score(&self) -> f64 {
        let rsrp_score = ((self.rf_metrics.rsrp as f32 + 140.0) / 96.0).clamp(0.0, 1.0);
        let rsrq_score = ((self.rf_metrics.rsrq as f32 + 19.0) / 16.0).clamp(0.0, 1.0);
        let sinr_score = ((self.rf_metrics.sinr as f32 + 20.0) / 50.0).clamp(0.0, 1.0);

        let quality = (rsrp_score * 0.4 + rsrq_score * 0.3 + sinr_score * 0.3) as f64;

        let distance_penalty = if self.rf_metrics.timing_advance > 500 {
            0.8
        } else {
            1.0
        };

        quality * distance_penalty
    }

    pub fn detect_potential_fraud(&self) -> Option<crate::FraudType> {
        if let Some(ref beacon_location) = self.beacon_location {
            let distance_km = Self::calculate_distance(&self.witness_location, beacon_location);

            if distance_km > 10.0 && self.rf_metrics.rsrp > -50 {
                return Some(crate::FraudType::InvalidGeometry);
            }

            if distance_km < 1.0 && self.rf_metrics.rsrp < -120 {
                return Some(crate::FraudType::InvalidGeometry);
            }
        }

        if self.time_sync.clock_offset_ms.abs() > 5000 {
            return Some(crate::FraudType::RelayAttack);
        }

        if let Some(accuracy) = self.witness_location.accuracy {
            if accuracy > 50.0 {
                return Some(crate::FraudType::LocationSpoof);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::KeyPair;

    fn create_test_witness_report() -> WitnessReport {
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
            latitude: 37.7749,
            longitude: -122.4194,
            altitude: Some(10.0),
            accuracy: Some(5.0),
            timestamp: Timestamp::now().as_millis(),
            h3_index: "87283472bffffff".to_string(),
        };

        WitnessReport::new(
            Address::new([1u8; 20]),
            Address::new([2u8; 20]),
            Hash::new([3u8; 32]),
            rf_metrics,
            witness_location,
            None,
        )
    }

    #[test]
    fn test_witness_report_creation() {
        let report = create_test_witness_report();
        assert_eq!(report.rf_metrics.rsrp, -85);
        assert!(report.calculate_quality_score() > 0.0);
    }

    #[test]
    fn test_witness_report_signing() {
        let keypair = KeyPair::generate();
        let witness_id = Address::from_public_key(&keypair.public_key());

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
            latitude: 37.7749,
            longitude: -122.4194,
            altitude: Some(10.0),
            accuracy: Some(5.0),
            timestamp: Timestamp::now().as_millis(),
            h3_index: "87283472bffffff".to_string(),
        };

        let mut report = WitnessReport::new(
            witness_id,
            Address::new([2u8; 20]),
            Hash::new([3u8; 32]),
            rf_metrics,
            witness_location,
            None,
        );

        assert!(report.sign(&keypair).is_ok());
        assert!(report.verify_signature().unwrap());
    }

    #[test]
    fn test_report_validation() {
        let report = create_test_witness_report();
        assert!(report.validate().is_ok());
    }

    #[test]
    fn test_distance_calculation() {
        let loc1 = LocationData {
            latitude: 37.7749,
            longitude: -122.4194,
            altitude: None,
            accuracy: None,
            timestamp: 0,
            h3_index: String::new(),
        };

        let loc2 = LocationData {
            latitude: 37.7849,
            longitude: -122.4094,
            altitude: None,
            accuracy: None,
            timestamp: 0,
            h3_index: String::new(),
        };

        let distance = WitnessReport::calculate_distance(&loc1, &loc2);
        assert!(distance > 0.0);
        assert!(distance < 2.0);
    }

    #[test]
    fn test_quality_score_calculation() {
        let report = create_test_witness_report();
        let score = report.calculate_quality_score();
        assert!(score >= 0.0);
        assert!(score <= 1.0);
    }

    #[test]
    fn test_fraud_detection() {
        let mut report = create_test_witness_report();

        report.rf_metrics.rsrp = -45;
        report.beacon_location = Some(LocationData {
            latitude: 38.0,
            longitude: -123.0,
            altitude: None,
            accuracy: None,
            timestamp: 0,
            h3_index: String::new(),
        });

        let fraud_type = report.detect_potential_fraud();
        assert!(fraud_type.is_some());
        assert_eq!(fraud_type.unwrap(), crate::FraudType::InvalidGeometry);
    }
}
