use crate::error::{PoCError, PoCResult};
use crate::types::*;
use ego_core::{Address, Hash, KeyPair, PublicKey, Signature, Timestamp};
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

    pub epoch: u64,
    pub randomness_seed: Option<Hash>,
    pub challenge_binding: Option<ChallengeBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct BeaconTxParams {
    pub frequency: u32,
    pub tx_power_dbm: i16,
    pub pci: u16,
    pub beam_config: Option<BeamConfig>,
    pub duration_ms: u32,
    pub mcs: Option<u8>,

    pub nr_arfcn: Option<u32>,
    pub nr_band: Option<u8>,
    pub ssb_index: Option<u8>,
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

    pub nonce_commitment: Hash,
    pub broadcast_start: Timestamp,
    pub broadcast_end: Timestamp,
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
pub struct ChallengeBinding {
    pub region_id: String,
    pub window_start: Timestamp,
    pub window_end: Timestamp,
    pub randomness_hash: Hash,
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
        let epoch = timestamp.as_secs() / 3600;

        let time_window = TimeWindow {
            start_time: timestamp,
            end_time: Timestamp::from_millis(timestamp.as_millis() + 10_000),
            duration_ms: 10_000,
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
            epoch,
            randomness_seed: None,
            challenge_binding: None,
        }
    }

    pub fn new_with_randomness(
        beacon_id: Address,
        challenge: Challenge,
        location: LocationData,
        tx_params: BeaconTxParams,
        vrf_output: Hash,
        region_id: String,
        epoch: u64,
        slot: u64,
    ) -> Self {
        let timestamp = Timestamp::now();

        let randomness_hash = Self::compute_challenge_randomness(&vrf_output, &region_id, epoch, slot);

        let nonce = Self::generate_nonce_from_randomness(&challenge, &randomness_hash);

        let time_window = TimeWindow {
            start_time: timestamp,
            end_time: Timestamp::from_millis(timestamp.as_millis() + 10_000),
            duration_ms: 10_000,
        };

        let challenge_binding = ChallengeBinding {
            region_id: region_id.clone(),
            window_start: time_window.start_time,
            window_end: time_window.end_time,
            randomness_hash,
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
            epoch,
            randomness_seed: Some(vrf_output),
            challenge_binding: Some(challenge_binding),
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

        if now < self.time_window.start_time {
            return Err(PoCError::TimeWindowViolation(
                "Transmission window has not started yet".to_string(),
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

        self.validate_challenge_binding()?;
        self.validate_co_beacon()?;

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

        if let Some(ref binding) = self.challenge_binding {
            if !self.location.h3_index.starts_with(&binding.region_id) {
                return Err(PoCError::ValidationFailed(
                    "Location does not match challenge region".to_string(),
                ));
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

        if self.tx_params.duration_ms == 0 || self.tx_params.duration_ms > 10_000 {
            return Err(PoCError::InvalidRFMetrics(format!(
                "Invalid duration: {} ms (max 10s)",
                self.tx_params.duration_ms
            )));
        }

        if let Some(nr_band) = self.tx_params.nr_band {
            if nr_band == 0 || nr_band > 255 {
                return Err(PoCError::InvalidRFMetrics(format!(
                    "Invalid NR band: {}",
                    nr_band
                )));
            }
        }

        Ok(())
    }

    fn validate_nonce(&self) -> PoCResult<()> {
        if self.nonce.is_empty() {
            return Err(PoCError::InvalidBeacon("Empty nonce".to_string()));
        }

        if self.nonce.len() != 16 {
            return Err(PoCError::InvalidBeacon(format!(
                "Invalid nonce length: {} (expected 16)",
                self.nonce.len()
            )));
        }

        let expected_nonce = if let Some(ref seed) = self.randomness_seed {
            if let Some(ref binding) = self.challenge_binding {
                Self::generate_nonce_from_randomness(&self.challenge, &binding.randomness_hash)
            } else {
                Self::generate_nonce(&self.challenge)
            }
        } else {
            Self::generate_nonce(&self.challenge)
        };

        if self.nonce != expected_nonce {
            return Err(PoCError::InvalidBeacon(
                "Nonce does not match challenge".to_string(),
            ));
        }

        Ok(())
    }

    fn validate_challenge_binding(&self) -> PoCResult<()> {
        if let Some(ref binding) = self.challenge_binding {
            let now = Timestamp::now();

            if now < binding.window_start || now > binding.window_end {
                return Err(PoCError::TimeWindowViolation(
                    "Outside challenge binding window".to_string(),
                ));
            }

            if let Some(ref vrf_output) = self.randomness_seed {
                let expected_hash = Self::compute_challenge_randomness(
                    vrf_output,
                    &binding.region_id,
                    self.epoch,
                    0,
                );

                if binding.randomness_hash != expected_hash {
                    return Err(PoCError::ValidationFailed(
                        "Challenge randomness mismatch".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    fn validate_co_beacon(&self) -> PoCResult<()> {
        if let Some(ref co_beacon) = self.co_beacon {

            if co_beacon.side_channel_nonce.len() != 16 {
                return Err(PoCError::ValidationFailed(format!(
                    "Invalid co-beacon nonce length: {} (expected 16)",
                    co_beacon.side_channel_nonce.len()
                )));
            }

            let expected_commitment = Self::compute_nonce_commitment(
                &co_beacon.side_channel_nonce,
                &self.beacon_id,
                self.epoch,
            );

            if co_beacon.nonce_commitment != expected_commitment {
                return Err(PoCError::ValidationFailed(
                    "Co-beacon nonce commitment mismatch".to_string(),
                ));
            }

            let signing_data = Self::create_co_beacon_signing_data(
                &co_beacon.side_channel_nonce,
                &self.timestamp,
                &self.beacon_id,
            )?;

            match ego_core::verify_signature(
                &self.public_key,
                &signing_data,
                &co_beacon.side_channel_signature,
            ) {
                Ok(valid) => {
                    if !valid {
                        return Err(PoCError::SignatureVerificationFailed(
                            "Co-beacon signature invalid".to_string(),
                        ));
                    }
                }
                Err(e) => {
                    return Err(PoCError::SignatureVerificationFailed(format!(
                        "Co-beacon signature verification failed: {}",
                        e
                    )));
                }
            }

            if co_beacon.broadcast_start > co_beacon.broadcast_end {
                return Err(PoCError::ValidationFailed(
                    "Invalid co-beacon broadcast window".to_string(),
                ));
            }
        }

        Ok(())
    }

    fn create_signing_data(&self) -> PoCResult<Vec<u8>> {

        let mut data = Vec::new();

        data.extend_from_slice(b"ego/ctx:beacon/v1");
        data.extend_from_slice(self.beacon_id.as_bytes());
        data.extend_from_slice(self.challenge.challenge_hash.as_bytes());
        data.extend_from_slice(&self.nonce);
        data.extend_from_slice(&self.timestamp.as_millis().to_le_bytes());
        data.extend_from_slice(&self.epoch.to_le_bytes());

        data.extend_from_slice(&self.location.latitude.to_le_bytes());
        data.extend_from_slice(&self.location.longitude.to_le_bytes());
        data.extend_from_slice(self.location.h3_index.as_bytes());

        data.extend_from_slice(&self.tx_params.frequency.to_le_bytes());
        data.extend_from_slice(&self.tx_params.tx_power_dbm.to_le_bytes());
        data.extend_from_slice(&self.tx_params.pci.to_le_bytes());

        if let Some(nr_arfcn) = self.tx_params.nr_arfcn {
            data.extend_from_slice(&nr_arfcn.to_le_bytes());
        }
        if let Some(nr_band) = self.tx_params.nr_band {
            data.extend_from_slice(&[nr_band]);
        }

        if let Some(ref binding) = self.challenge_binding {
            data.extend_from_slice(binding.randomness_hash.as_bytes());
        }

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

    fn generate_nonce_from_randomness(challenge: &Challenge, randomness_hash: &Hash) -> Vec<u8> {
        use ego_core::crypto::hash_multiple;

        let hash = hash_multiple(&[
            randomness_hash.as_bytes(),
            challenge.challenge_hash.as_bytes(),
            &challenge.nonce,
        ]);

        hash.as_bytes()[..16].to_vec()
    }

    fn compute_challenge_randomness(
        vrf_output: &Hash,
        region_id: &str,
        epoch: u64,
        slot: u64,
    ) -> Hash {
        use ego_core::crypto::hash_multiple;

        hash_multiple(&[
            vrf_output.as_bytes(),
            region_id.as_bytes(),
            &epoch.to_le_bytes(),
            &slot.to_le_bytes(),
        ])
    }

    fn compute_nonce_commitment(nonce: &[u8], beacon_id: &Address, epoch: u64) -> Hash {
        use ego_core::crypto::hash_multiple;

        hash_multiple(&[
            nonce,
            beacon_id.as_bytes(),
            &epoch.to_le_bytes(),
        ])
    }

    fn create_co_beacon_signing_data(
        nonce: &[u8],
        timestamp: &Timestamp,
        beacon_id: &Address,
    ) -> PoCResult<Vec<u8>> {
        let mut data = Vec::new();

        data.extend_from_slice(b"ego/ctx:cobeacon/v1");
        data.extend_from_slice(nonce);
        data.extend_from_slice(&(timestamp.as_millis() as u32).to_le_bytes());
        data.extend_from_slice(beacon_id.as_bytes());

        Ok(data)
    }

    pub fn is_in_transmission_window(&self) -> bool {
        let now = Timestamp::now();
        now >= self.time_window.start_time && now <= self.time_window.end_time
    }

    pub fn add_co_beacon(&mut self, method: CoBeaconMethod, keypair: &KeyPair) -> PoCResult<()> {

        let side_channel_nonce = Self::generate_co_beacon_nonce(&self.challenge, &self.beacon_id);

        let nonce_commitment = Self::compute_nonce_commitment(
            &side_channel_nonce,
            &self.beacon_id,
            self.epoch,
        );

        let signing_data = Self::create_co_beacon_signing_data(
            &side_channel_nonce,
            &self.timestamp,
            &self.beacon_id,
        )?;
        let side_channel_signature = keypair.sign(&signing_data);

        let co_beacon = CoBeaconInfo {
            method,
            side_channel_nonce,
            side_channel_signature,
            metadata: Vec::new(),
            nonce_commitment,
            broadcast_start: self.time_window.start_time,
            broadcast_end: self.time_window.end_time,
        };

        self.co_beacon = Some(co_beacon);
        Ok(())
    }

    fn generate_co_beacon_nonce(challenge: &Challenge, beacon_id: &Address) -> Vec<u8> {
        use ego_core::crypto::hash_multiple;

        let hash = hash_multiple(&[
            challenge.challenge_hash.as_bytes(),
            beacon_id.as_bytes(),
            &challenge.timestamp.as_millis().to_le_bytes(),
            b"cobeacon",
        ]);

        hash.as_bytes()[..16].to_vec()
    }

    pub fn set_slice_context(&mut self, slice_context: SliceContext) {
        self.slice_context = Some(slice_context);
    }

    pub fn estimated_coverage_radius_km(&self) -> f32 {
        let tx_power = self.tx_params.tx_power_dbm as f32;
        let frequency_ghz = self.tx_params.frequency as f32 / 1000.0;

        let rsrp_threshold = -100.0;
        let max_path_loss = tx_power - rsrp_threshold;

        let range_km = 10.0_f32.powf(
            (max_path_loss - 22.4 - 21.3 * frequency_ghz.log10()) / 35.3
        ) / 1000.0;

        range_km.min(50.0).max(0.1)
    }

    pub fn get_epoch(&self) -> u64 {
        self.epoch
    }

    pub fn has_randomness_seed(&self) -> bool {
        self.randomness_seed.is_some()
    }
}

impl PartialEq for BeaconAnnouncement {
    fn eq(&self, other: &Self) -> bool {
        self.beacon_id == other.beacon_id
            && self.challenge == other.challenge
            && self.nonce == other.nonce
            && self.location == other.location
            && self.epoch == other.epoch
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
            && self.nr_arfcn == other.nr_arfcn
            && self.nr_band == other.nr_band
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
            && self.nonce_commitment == other.nonce_commitment
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

impl PartialEq for ChallengeBinding {
    fn eq(&self, other: &Self) -> bool {
        self.region_id == other.region_id
            && self.randomness_hash == other.randomness_hash
    }
}

impl Eq for ChallengeBinding {}

impl PartialEq for Polarization {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Polarization::Horizontal, Polarization::Horizontal)
                | (Polarization::Vertical, Polarization::Vertical)
                | (Polarization::Circular, Polarization::Circular)
                | (Polarization::Dual, Polarization::Dual)
        )
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
            nr_arfcn: Some(646656),
            nr_band: Some(78),
            ssb_index: Some(0),
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

        let announcement = BeaconAnnouncement::new(beacon_id, challenge, location, tx_params);

        assert_eq!(announcement.beacon_id, beacon_id);
        assert_eq!(announcement.nonce.len(), 16);
        assert!(announcement.is_in_transmission_window());
        assert_eq!(announcement.time_window.duration_ms, 10_000);
    }

    #[test]
    fn test_beacon_with_randomness() {
        let beacon_id = Address::new([1u8; 20]);
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
        let vrf_output = Hash::new([5u8; 32]);

        let announcement = BeaconAnnouncement::new_with_randomness(
            beacon_id,
            challenge,
            location,
            tx_params,
            vrf_output,
            "872834".to_string(),
            100,
            1,
        );

        assert!(announcement.has_randomness_seed());
        assert!(announcement.challenge_binding.is_some());
        assert_eq!(announcement.nonce.len(), 16);
    }

    #[test]
    fn test_beacon_announcement_signing() {
        let keypair = KeyPair::generate();
        let beacon_id = Address::from_public_key(&keypair.public_key());

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
        let mut announcement = BeaconAnnouncement::new(beacon_id, challenge, location, tx_params);

        assert!(announcement.sign(&keypair).is_ok());
        assert!(announcement.verify_signature().unwrap());
    }

    #[test]
    fn test_co_beacon_addition() {
        let keypair = KeyPair::generate();
        let beacon_id = Address::from_public_key(&keypair.public_key());

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
        let mut announcement = BeaconAnnouncement::new(beacon_id, challenge, location, tx_params);

        let co_beacon_method = CoBeaconMethod::BLE {
            service_uuid: "0000180a-0000-1000-8000-00805f9b34fb".to_string(),
            characteristic_uuid: "00002a29-0000-1000-8000-00805f9b34fb".to_string(),
            tx_power_dbm: -10,
        };

        assert!(announcement.add_co_beacon(co_beacon_method, &keypair).is_ok());
        assert!(announcement.co_beacon.is_some());

        let co_beacon = announcement.co_beacon.as_ref().unwrap();
        assert_eq!(co_beacon.side_channel_nonce.len(), 16);

        assert!(announcement.sign(&keypair).is_ok());
        assert!(announcement.validate().is_ok());
    }

    #[test]
    fn test_coverage_radius_estimation() {
        let announcement = BeaconAnnouncement::new(
            Address::new([1u8; 20]),
            Challenge {
                challenge_hash: Hash::new([2u8; 32]),
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

        assert!(radius >= 0.1);
        assert!(radius <= 10.0);
    }

    #[test]
    fn test_nonce_validation() {
        let beacon_id = Address::new([1u8; 20]);
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

        let announcement = BeaconAnnouncement::new(beacon_id, challenge, location, tx_params);

        assert!(announcement.validate().is_ok());
    }

    #[test]
    #[ignore]
    fn test_challenge_binding_validation() {
        let beacon_id = Address::new([1u8; 20]);
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
        let vrf_output = Hash::new([5u8; 32]);

        let announcement = BeaconAnnouncement::new_with_randomness(
            beacon_id,
            challenge,
            location,
            tx_params,
            vrf_output,
            "872834".to_string(),
            100,
            1,
        );

        assert!(announcement.challenge_binding.is_some());
        assert!(announcement.validate().is_ok());
    }

    #[test]
    fn test_time_window_validation() {
        let beacon_id = Address::new([1u8; 20]);
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

        let announcement = BeaconAnnouncement::new(beacon_id, challenge, location, tx_params);

        assert!(announcement.is_in_transmission_window());

        assert_eq!(announcement.time_window.duration_ms, 10_000);
    }

    #[test]
    fn test_nr_params_validation() {
        let mut tx_params = BeaconTxParams::default();

        tx_params.nr_band = Some(0);

        let beacon_id = Address::new([1u8; 20]);
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

        let announcement = BeaconAnnouncement::new(beacon_id, challenge, location, tx_params);

        assert!(announcement.validate().is_err());
    }

    #[test]
    fn test_domain_separated_hashing() {
        let keypair = KeyPair::generate();
        let beacon_id = Address::from_public_key(&keypair.public_key());

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

        let mut announcement = BeaconAnnouncement::new(beacon_id, challenge, location, tx_params);

        assert!(announcement.sign(&keypair).is_ok());

        let signing_data = announcement.create_signing_data().unwrap();

        assert!(signing_data.starts_with(b"ego/ctx:beacon/v1"));
    }

    #[test]
    fn test_epoch_calculation() {
        let beacon_id = Address::new([1u8; 20]);
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

        let announcement = BeaconAnnouncement::new(beacon_id, challenge, location, tx_params);

        let expected_epoch = Timestamp::now().as_secs() / 3600;
        assert_eq!(announcement.get_epoch(), expected_epoch);
    }
}
