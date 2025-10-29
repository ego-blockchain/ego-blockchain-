use crate::error::{PoCError, PoCResult};
use crate::types::*;
use ego_core::{Address, KeyPair, PublicKey, Signature, Timestamp};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct BeaconAnnouncement {
    pub beacon_id: Address,
    pub challenge: Challenge,
    pub nonce: Vec<u8>,
    pub location: LocationData,
    pub tx_params: BeaconTxParams,
    pub co_beacon: Option<CoBeaconInfo>,
    pub timestamp: Timestamp,
    pub signature: Signature,
    pub public_key: PublicKey,
    pub slice_context: Option<SliceContext>,
    pub time_window: TimeWindow,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct BeaconTxParams {
    pub frequency: u32,
    pub tx_power_dbm: i16,
    pub pci: u16,
    pub beam_config: Option<BeamConfig>,
    pub duration_ms: u32,
    pub mcs: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct BeamConfig {
    pub beam_index: u8,
    pub beam_width: f32,
    pub beam_direction: f32,
    pub polarization: Polarization,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum Polarization {
    Horizontal,
    Vertical,
    Circular,
    Dual,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct CoBeaconInfo {
    pub method: CoBeaconMethod,
    pub side_channel_nonce: Vec<u8>,
    pub side_channel_signature: Signature,
    pub metadata: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum CoBeaconMethod {
    BLE {
        service_uuid: String,
        characteristic_uuid: String,
        tx_power_dbm: i8,
    },
    WiFi {
        ssid: String,
        channel: u8,
        beacon_interval_ms: u16,
    },
    SideChannel {
        protocol: String,
        parameters: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct TimeWindow {
    pub start_time: Timestamp,
    pub end_time: Timestamp,
    pub duration_ms: u64,
}

impl BeaconAnnouncement {
    pub fn new(
        beacon_id: Address,
        challenge: Challenge,
        location: LocationData,
        tx_params: BeaconTxParams,
    ) -> Self {
        let nonce = Self::generate_nonce(&challenge);
        let timestamp = Timestamp::now();
        let time_window = TimeWindow {
            start_time: timestamp,
            end_time: Timestamp::from_millis(timestamp.as_millis() + 30_000),
            duration_ms: 30_000,
        };

        Self {
            beacon_id,
            challenge,
            nonce,
            location,
            tx_params,
            co_beacon: None,
            timestamp,
            signature: Signature::ed25519([0u8; 64]),
            public_key: PublicKey::ed25519([0u8; 32]),
            slice_context: None,
            time_window,
        }
    }

    pub fn sign(&mut self, keypair: &KeyPair) -> PoCResult<()> {
        self.public_key = keypair.public_key();

        let expected_id = Address::from_public_key(&self.public_key);
        if expected_id != self.beacon_id {
            return Err(PoCError::InvalidBeacon(
                "Beacon ID does not match signing key".to_string(),
            ));
        }

        let signing_data = self.create_signing_data()?;
        self.signature = keypair.sign(&signing_data);

        Ok(())
    }

    pub fn verify_signature(&self) -> PoCResult<bool> {
        let expected_id = Address::from_public_key(&self.public_key);
        if expected_id != self.beacon_id {
            return Ok(false);
        }

        let signing_data = self.create_signing_data()?;

        match ego_core::verify_signature(&self.public_key, &signing_data, &self.signature) {
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
                "Announcement timestamp too far in future".to_string(),
            ));
        }

        if self.time_window.start_time > self.time_window.end_time {
            return Err(PoCError::ValidationFailed(
                "Invalid time window: start > end".to_string(),
            ));
        }

        if now > self.time_window.end_time {
            return Err(PoCError::TimeWindowViolation(
                "Transmission window has expired".to_string(),
            ));
        }

        self.validate_location()?;
        self.validate_rf_params()?;
        self.validate_nonce()?;

        Ok(())
    }

    fn validate_location(&self) -> PoCResult<()> {
        let lat = self.location.latitude;
        let lon = self.location.longitude;

        if lat < -90.0 || lat > 90.0 {
            return Err(PoCError::InvalidLocation(format!(
                "Invalid latitude: {}",
                lat
            )));
        }

        if lon < -180.0 || lon > 180.0 {
            return Err(PoCError::InvalidLocation(format!(
                "Invalid longitude: {}",
                lon
            )));
        }

        if !self.location.h3_index.is_empty() {
            if self.location.h3_index.len() < 8 || self.location.h3_index.len() > 15 {
                return Err(PoCError::H3Error(format!(
                    "Invalid H3 index length: {}",
                    self.location.h3_index
                )));
            }
        }

        Ok(())
    }

    fn validate_rf_params(&self) -> PoCResult<()> {
        if self.tx_params.tx_power_dbm < -50 || self.tx_params.tx_power_dbm > 50 {
            return Err(PoCError::InvalidRFMetrics(format!(
                "Invalid TX power: {} dBm",
                self.tx_params.tx_power_dbm
            )));
        }

        if self.tx_params.frequency == 0 {
            return Err(PoCError::InvalidRFMetrics(
                "Invalid frequency: 0".to_string(),
            ));
        }

        if self.tx_params.duration_ms == 0 || self.tx_params.duration_ms > 30_000 {
            return Err(PoCError::InvalidRFMetrics(format!(
                "Invalid duration: {} ms",
                self.tx_params.duration_ms
            )));
        }

        Ok(())
    }

    fn validate_nonce(&self) -> PoCResult<()> {
        if self.nonce.is_empty() {
            return Err(PoCError::InvalidBeacon("Empty nonce".to_string()));
        }

        let expected_nonce = Self::generate_nonce(&self.challenge);
        if self.nonce != expected_nonce {
            return Err(PoCError::InvalidBeacon(
                "Nonce does not match challenge".to_string(),
            ));
        }

        Ok(())
    }

    fn create_signing_data(&self) -> PoCResult<Vec<u8>> {
        let mut data = Vec::new();

        data.extend_from_slice(self.beacon_id.as_bytes());
        data.extend_from_slice(self.challenge.challenge_hash.as_bytes());
        data.extend_from_slice(&self.nonce);
        data.extend_from_slice(&self.timestamp.as_millis().to_le_bytes());

        data.extend_from_slice(&self.location.latitude.to_le_bytes());
        data.extend_from_slice(&self.location.longitude.to_le_bytes());

        data.extend_from_slice(&self.tx_params.frequency.to_le_bytes());
        data.extend_from_slice(&self.tx_params.tx_power_dbm.to_le_bytes());
        data.extend_from_slice(&self.tx_params.pci.to_le_bytes());

        Ok(data)
    }

    fn generate_nonce(challenge: &Challenge) -> Vec<u8> {
        use ego_core::crypto::hash_multiple;

        let hash = hash_multiple(&[
            challenge.challenge_hash.as_bytes(),
            &challenge.nonce,
            &challenge.timestamp.as_millis().to_le_bytes(),
        ]);

        hash.as_bytes()[..16].to_vec()
    }

    pub fn is_in_transmission_window(&self) -> bool {
        let now = Timestamp::now();
        now >= self.time_window.start_time && now <= self.time_window.end_time
    }

    pub fn add_co_beacon(&mut self, co_beacon: CoBeaconInfo) {
        self.co_beacon = Some(co_beacon);
    }

    pub fn set_slice_context(&mut self, slice_context: SliceContext) {
        self.slice_context = Some(slice_context);
    }

    pub fn estimated_coverage_radius_km(&self) -> f32 {
        let tx_power = self.tx_params.tx_power_dbm as f32;
        let frequency_ghz = self.tx_params.frequency as f32 / 1000.0;

        let path_loss_at_1km = 32.4 + 20.0 * frequency_ghz.log10();
        let max_path_loss = tx_power + 174.0 - (-100.0);

        let range_km = 10.0_f32.powf((max_path_loss - path_loss_at_1km) / 20.0);
        range_km.min(50.0)
    }
}

impl PartialEq for BeaconAnnouncement {
    fn eq(&self, other: &Self) -> bool {
        self.beacon_id == other.beacon_id
            && self.challenge == other.challenge
            && self.nonce == other.nonce
            && self.location == other.location
    }
}

impl Eq for BeaconAnnouncement {}

impl PartialEq for BeaconTxParams {
    fn eq(&self, other: &Self) -> bool {
        self.frequency == other.frequency
            && self.tx_power_dbm == other.tx_power_dbm
            && self.pci == other.pci
            && self.duration_ms == other.duration_ms
            && self.mcs == other.mcs
    }
}

impl Eq for BeaconTxParams {}

impl PartialEq for BeamConfig {
    fn eq(&self, other: &Self) -> bool {
        self.beam_index == other.beam_index
            && (self.beam_width - other.beam_width).abs() < f32::EPSILON
            && (self.beam_direction - other.beam_direction).abs() < f32::EPSILON
            && self.polarization == other.polarization
    }
}

impl Eq for BeamConfig {}

impl PartialEq for CoBeaconInfo {
    fn eq(&self, other: &Self) -> bool {
        self.method == other.method
            && self.side_channel_nonce == other.side_channel_nonce
            && self.side_channel_signature == other.side_channel_signature
            && self.metadata == other.metadata
    }
}

impl Eq for CoBeaconInfo {}

impl PartialEq for CoBeaconMethod {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                CoBeaconMethod::BLE {
                    service_uuid: s1,
                    characteristic_uuid: c1,
                    tx_power_dbm: p1,
                },
                CoBeaconMethod::BLE {
                    service_uuid: s2,
                    characteristic_uuid: c2,
                    tx_power_dbm: p2,
                },
            ) => s1 == s2 && c1 == c2 && p1 == p2,
            (
                CoBeaconMethod::WiFi {
                    ssid: s1,
                    channel: c1,
                    beacon_interval_ms: b1,
                },
                CoBeaconMethod::WiFi {
                    ssid: s2,
                    channel: c2,
                    beacon_interval_ms: b2,
                },
            ) => s1 == s2 && c1 == c2 && b1 == b2,
            (
                CoBeaconMethod::SideChannel {
                    protocol: p1,
                    parameters: params1,
                },
                CoBeaconMethod::SideChannel {
                    protocol: p2,
                    parameters: params2,
                },
            ) => p1 == p2 && params1 == params2,
            _ => false,
        }
    }
}

impl Eq for CoBeaconMethod {}

impl PartialEq for TimeWindow {
    fn eq(&self, other: &Self) -> bool {
        self.start_time == other.start_time
            && self.end_time == other.end_time
            && self.duration_ms == other.duration_ms
    }
}

impl Eq for TimeWindow {}

impl PartialEq for Polarization {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Polarization::Horizontal, Polarization::Horizontal) => true,
            (Polarization::Vertical, Polarization::Vertical) => true,
            (Polarization::Circular, Polarization::Circular) => true,
            (Polarization::Dual, Polarization::Dual) => true,
            _ => false,
        }
    }
}

impl Eq for Polarization {}

impl Default for BeaconTxParams {
    fn default() -> Self {
        Self {
            frequency: 3500,
            tx_power_dbm: 23,
            pci: 1,
            beam_config: None,
            duration_ms: 1000,
            mcs: Some(16),
        }
    }
}

impl Default for BeamConfig {
    fn default() -> Self {
        Self {
            beam_index: 0,
            beam_width: 120.0,
            beam_direction: 0.0,
            polarization: Polarization::Vertical,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::KeyPair;

    #[test]
    fn test_beacon_announcement_creation() {
        let beacon_id = Address::new([1u8; 20]);
        let challenge = Challenge {
            challenge_hash: ego_core::Hash::new([2u8; 32]),
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

        let announcement = BeaconAnnouncement::new(beacon_id, challenge, location, tx_params);

        assert_eq!(announcement.beacon_id, beacon_id);
        assert!(!announcement.nonce.is_empty());
        assert!(announcement.is_in_transmission_window());
    }

    #[test]
    fn test_beacon_announcement_signing() {
        let keypair = KeyPair::generate();
        let beacon_id = Address::from_public_key(&keypair.public_key());

        let challenge = Challenge {
            challenge_hash: ego_core::Hash::new([2u8; 32]),
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
        let mut announcement = BeaconAnnouncement::new(beacon_id, challenge, location, tx_params);

        assert!(announcement.sign(&keypair).is_ok());
        assert!(announcement.verify_signature().unwrap());
    }

    #[test]
    fn test_coverage_radius_estimation() {
        let announcement = BeaconAnnouncement::new(
            Address::new([1u8; 20]),
            Challenge {
                challenge_hash: ego_core::Hash::new([2u8; 32]),
                h3_cell: "87283472bffffff".to_string(),
                nonce: vec![3u8; 16],
                timestamp: Timestamp::now(),
                difficulty: 1,
                reward_scale: 1.0,
            },
            LocationData {
                latitude: 37.7749,
                longitude: -122.4194,
                altitude: Some(10.0),
                accuracy: Some(5.0),
                timestamp: Timestamp::now().as_millis(),
                h3_index: "87283472bffffff".to_string(),
            },
            BeaconTxParams::default(),
        );

        let radius = announcement.estimated_coverage_radius_km();
        assert!(radius > 0.0);
        assert!(radius <= 50.0);
    }
}
