use super::{Beacon, BeaconAnnouncement, BeaconMetrics, BeaconStatus};
use crate::config::BeaconConfig;
use crate::error::{PoCError, PoCResult};
use crate::types::*;
use ego_core::{Address, Hash, KeyPair, PublicKey, Timestamp};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

pub struct BeaconNode {
    config: BeaconConfig,

    keypair: Arc<KeyPair>,

    address: Address,

    location: Arc<RwLock<Option<LocationData>>>,

    h3_cell: Arc<RwLock<Option<String>>>,

    authorized_frequencies: Vec<u32>,

    authorized_slices: Vec<String>,

    status: Arc<RwLock<BeaconStatus>>,

    metrics: Arc<RwLock<BeaconMetrics>>,

    tx_logs: Arc<RwLock<Vec<BeaconTxLog>>>,

    rate_limiter: Arc<RwLock<RateLimiter>>,

    challenge_receiver: Option<mpsc::UnboundedReceiver<Challenge>>,

    announcement_sender: Option<mpsc::UnboundedSender<BeaconAnnouncement>>,

    drs_score: Arc<RwLock<Option<f64>>>,
}

#[derive(Debug, Clone)]
struct RateLimiter {
    announcements_per_hour: u32,
    current_hour_count: u32,
    last_reset: Timestamp,
    burst_allowance: u32,
    burst_used: u32,
}

impl BeaconNode {
    pub fn new(
        config: BeaconConfig,
        keypair: KeyPair,
        location: LocationData,
        authorized_frequencies: Vec<u32>,
    ) -> Self {
        let address = Address::from_public_key(&keypair.public_key());

        let mut status = BeaconStatus {
            beacon_id: address,
            is_active: false,
            last_transmission: None,
            success_rate: 0.0,
            avg_witnesses_per_beacon: 0.0,
            cellular_safe_mode: config.cellular_safe_mode,
            authorized_frequencies: authorized_frequencies.clone(),
            current_h3_cell: Some(location.h3_index.clone()),
            drs_score: None,
        };

        let h3_cell = Some(location.h3_index.clone());

        Self {
            config,
            keypair: Arc::new(keypair),
            address,
            location: Arc::new(RwLock::new(Some(location))),
            h3_cell: Arc::new(RwLock::new(h3_cell)),
            authorized_frequencies,
            authorized_slices: Vec::new(),
            status: Arc::new(RwLock::new(status)),
            metrics: Arc::new(RwLock::new(BeaconMetrics::default())),
            tx_logs: Arc::new(RwLock::new(Vec::new())),
            rate_limiter: Arc::new(RwLock::new(RateLimiter::new(120, 10))),
            challenge_receiver: None,
            announcement_sender: None,
            drs_score: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn start(&mut self) -> PoCResult<()> {
        info!("Starting beacon node {}", self.address);

        self.validate_config()?;

        let (challenge_sender, challenge_receiver) = mpsc::unbounded_channel();
        let (announcement_sender, announcement_receiver) = mpsc::unbounded_channel();

        self.challenge_receiver = Some(challenge_receiver);
        self.announcement_sender = Some(announcement_sender);

        {
            let mut status = self.status.write().unwrap();
            status.is_active = true;
        }

        info!("✅ Beacon node {} started successfully", self.address);
        Ok(())
    }

    pub async fn stop(&mut self) -> PoCResult<()> {
        info!("Stopping beacon node {}", self.address);

        {
            let mut status = self.status.write().unwrap();
            status.is_active = false;
        }

        self.challenge_receiver = None;
        self.announcement_sender = None;

        info!("✅ Beacon node {} stopped", self.address);
        Ok(())
    }

    /// Update node location
    pub fn update_location(&mut self, location: LocationData) -> PoCResult<()> {
        {
            let mut current_location = self.location.write().unwrap();
            *current_location = Some(location.clone());
        }

        {
            let mut h3_cell = self.h3_cell.write().unwrap();
            *h3_cell = Some(location.h3_index.clone());
        }

        {
            let mut status = self.status.write().unwrap();
            status.current_h3_cell = Some(location.h3_index);
        }

        info!("Updated beacon location for node {}", self.address);
        Ok(())
    }

    pub fn authorize_slice(&mut self, slice_id: String) -> PoCResult<()> {
        if !self.authorized_slices.contains(&slice_id) {
            self.authorized_slices.push(slice_id.clone());
            info!("Authorized slice {} for beacon {}", slice_id, self.address);
        }
        Ok(())
    }

    pub fn update_drs_score(&mut self, score: f64) {
        {
            let mut drs_score = self.drs_score.write().unwrap();
            *drs_score = Some(score);
        }

        {
            let mut status = self.status.write().unwrap();
            status.drs_score = Some(score);
        }

        debug!("Updated DRS score to {} for beacon {}", score, self.address);
    }

    pub fn get_status(&self) -> BeaconStatus {
        self.status.read().unwrap().clone()
    }

    pub fn get_metrics(&self) -> BeaconMetrics {
        self.metrics.read().unwrap().clone()
    }

    pub async fn process_challenge(&mut self, challenge: Challenge) -> PoCResult<()> {
        debug!(
            "Processing challenge {} for beacon {}",
            challenge.challenge_hash, self.address
        );

        if !self.check_rate_limit()? {
            return Err(PoCError::RateLimitExceeded {
                operation: "beacon_announcement".to_string(),
                limit: 120,
            });
        }

        if let Some(score) = self.drs_score.read().unwrap().as_ref() {
            if *score < 0.7 {
                return Err(PoCError::InsufficientDRSScore {
                    score: *score,
                    threshold: 0.7,
                });
            }
        }

        let current_cell = self.h3_cell.read().unwrap().clone();
        if current_cell != Some(challenge.h3_cell.clone()) {
            debug!("Skipping challenge - not in target H3 cell");
            return Ok(());
        }

        let announcement = self.prepare_announcement(challenge).await?;

        announcement.validate()?;

        let tx_log = self.transmit_beacon(&announcement).await?;

        {
            let mut logs = self.tx_logs.write().unwrap();
            logs.push(tx_log);
            if logs.len() > 100 {
                logs.remove(0);
            }
        }

        self.update_metrics_after_transmission(true);

        if let Some(ref sender) = self.announcement_sender {
            if let Err(e) = sender.send(announcement) {
                warn!("Failed to publish beacon announcement: {}", e);
            }
        }

        info!(
            "✅ Successfully processed challenge for beacon {}",
            self.address
        );
        Ok(())
    }

    fn validate_config(&self) -> PoCResult<()> {
        if self.authorized_frequencies.is_empty() {
            return Err(PoCError::ConfigError(
                "No authorized frequencies configured".to_string(),
            ));
        }

        if self.config.max_tx_power_dbm < -10 || self.config.max_tx_power_dbm > 50 {
            return Err(PoCError::ConfigError(
                "Invalid maximum transmission power".to_string(),
            ));
        }

        if self.config.beacon_interval_ms < 10_000 {
            return Err(PoCError::CellularSafetyViolation(
                "Beacon interval too short for cellular safety".to_string(),
            ));
        }

        Ok(())
    }

    fn check_rate_limit(&self) -> PoCResult<bool> {
        let mut limiter = self.rate_limiter.write().unwrap();

        let now = Timestamp::now();

        if now.as_millis() - limiter.last_reset.as_millis() > 3_600_000 {
            limiter.current_hour_count = 0;
            limiter.burst_used = 0;
            limiter.last_reset = now;
        }

        if limiter.burst_used < limiter.burst_allowance {
            limiter.burst_used += 1;
            return Ok(true);
        }

        if limiter.current_hour_count >= limiter.announcements_per_hour {
            return Ok(false);
        }

        limiter.current_hour_count += 1;
        Ok(true)
    }

    fn update_metrics_after_transmission(&self, success: bool) {
        let mut metrics = self.metrics.write().unwrap();
        metrics.total_transmissions += 1;

        if success {
            metrics.successful_transmissions += 1;
        }

        metrics.last_updated = Timestamp::now();

        let mut status = self.status.write().unwrap();
        status.success_rate =
            (metrics.successful_transmissions as f64) / (metrics.total_transmissions as f64);
        status.last_transmission = Some(Timestamp::now());
    }
}

impl Beacon for BeaconNode {
    fn beacon_id(&self) -> Address {
        self.address
    }

    fn is_authorized(&self) -> bool {
        !self.authorized_frequencies.is_empty() && self.status.read().unwrap().is_active
    }

    fn h3_cell(&self) -> Option<String> {
        self.h3_cell.read().unwrap().clone()
    }

    fn authorized_frequencies(&self) -> Vec<u32> {
        self.authorized_frequencies.clone()
    }

    async fn prepare_announcement(
        &mut self,
        challenge: Challenge,
    ) -> PoCResult<BeaconAnnouncement> {
        let location = self
            .location
            .read()
            .unwrap()
            .clone()
            .ok_or_else(|| PoCError::InvalidLocation("No location set".to_string()))?;

        let frequency = self.authorized_frequencies.get(0).copied().unwrap_or(3500);

        let tx_params = super::announcement::BeaconTxParams {
            frequency,
            tx_power_dbm: self.config.max_tx_power_dbm.min(23),
            pci: 1,
            beam_config: None,
            duration_ms: 1000,
            mcs: Some(16),
        };

        let mut announcement =
            BeaconAnnouncement::new(self.address, challenge, location, tx_params);

        if self.config.use_side_channel {
            let co_beacon = super::announcement::CoBeaconInfo {
                method: super::announcement::CoBeaconMethod::BLE {
                    service_uuid: "6E400001-B5A3-F393-E0A9-E50E24DCCA9E".to_string(),
                    characteristic_uuid: "6E400002-B5A3-F393-E0A9-E50E24DCCA9E".to_string(),
                    tx_power_dbm: 0,
                },
                side_channel_nonce: announcement.nonce.clone(),
                side_channel_signature: self.keypair.sign(&announcement.nonce),
                metadata: Vec::new(),
            };
            announcement.add_co_beacon(co_beacon);
        }

        announcement.sign(&self.keypair)?;

        Ok(announcement)
    }

    async fn transmit_beacon(
        &mut self,
        announcement: &BeaconAnnouncement,
    ) -> PoCResult<BeaconTxLog> {
        let tx_log = BeaconTxLog {
            tx_timestamp: Timestamp::now().as_millis(),
            tx_power_dbm: announcement.tx_params.tx_power_dbm,
            frequency: announcement.tx_params.frequency,
            pci: announcement.tx_params.pci,
            beam_pattern: None,
            duration_ms: announcement.tx_params.duration_ms,
        };

        info!(
            "🔊 Beacon {} transmitted on {} MHz at {} dBm",
            self.address, announcement.tx_params.frequency, announcement.tx_params.tx_power_dbm
        );

        Ok(tx_log)
    }

    fn get_tx_log(&self) -> Option<BeaconTxLog> {
        self.tx_logs.read().unwrap().last().cloned()
    }

    fn is_cellular_safe(&self) -> bool {
        self.config.cellular_safe_mode
    }
}

impl RateLimiter {
    fn new(announcements_per_hour: u32, burst_allowance: u32) -> Self {
        Self {
            announcements_per_hour,
            current_hour_count: 0,
            last_reset: Timestamp::now(),
            burst_allowance,
            burst_used: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::KeyPair;

    fn create_test_beacon() -> BeaconNode {
        let keypair = KeyPair::generate();
        let location = LocationData {
            latitude: 37.7749,
            longitude: -122.4194,
            altitude: Some(10.0),
            accuracy: Some(5.0),
            timestamp: Timestamp::now().as_millis(),
            h3_index: "87283472bffffff".to_string(),
        };

        BeaconNode::new(
            BeaconConfig::default(),
            keypair,
            location,
            vec![3500, 3600, 3700],
        )
    }

    #[tokio::test]
    async fn test_beacon_node_creation() {
        let beacon = create_test_beacon();
        assert!(beacon.is_authorized());
        assert_eq!(beacon.authorized_frequencies().len(), 3);
    }

    #[tokio::test]
    async fn test_beacon_start_stop() {
        let mut beacon = create_test_beacon();

        assert!(beacon.start().await.is_ok());
        assert!(beacon.get_status().is_active);

        assert!(beacon.stop().await.is_ok());
        assert!(!beacon.get_status().is_active);
    }

    #[tokio::test]
    async fn test_challenge_processing() {
        let mut beacon = create_test_beacon();
        beacon.start().await.unwrap();

        let challenge = Challenge {
            challenge_hash: Hash::new([1u8; 32]),
            h3_cell: "87283472bffffff".to_string(),
            nonce: vec![2u8; 16],
            timestamp: Timestamp::now(),
            difficulty: 1,
            reward_scale: 1.0,
        };

        assert!(beacon.process_challenge(challenge).await.is_ok());

        let metrics = beacon.get_metrics();
        assert_eq!(metrics.total_transmissions, 1);
        assert_eq!(metrics.successful_transmissions, 1);
    }

    #[test]
    fn test_rate_limiting() {
        let beacon = create_test_beacon();

        assert!(beacon.check_rate_limit().unwrap());

        for _ in 0..9 {
            assert!(beacon.check_rate_limit().unwrap());
        }
    }
}
