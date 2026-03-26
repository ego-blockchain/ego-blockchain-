use super::{
    Beacon, BeaconAnnouncement, BeaconMetrics, BeaconStatus, CoBeaconMethod, CoBeaconStatus,
    ChallengeSchedule, RandomnessSource,
};
use crate::config::BeaconConfig;
use crate::error::{PoCError, PoCResult};
use crate::types::*;
use ego_core::{Address, Hash, KeyPair, Timestamp};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, info, warn};

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
    recent_transmissions: Arc<RwLock<HashMap<(Address, Vec<u8>, u64), Timestamp>>>,
    co_beacon_status: Arc<RwLock<Option<CoBeaconStatus>>>,
    randomness_source: RandomnessSource,
    authorized_nr_bands: Vec<u8>,
    challenge_schedule: Arc<RwLock<Option<ChallengeSchedule>>>,
    vrf_receiver: Option<mpsc::UnboundedReceiver<(Hash, u64, u64)>>,
    pub authorized: bool,
    pub drs_score: f64,
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

        let status = BeaconStatus {
            beacon_id: address,
            is_active: false,
            last_transmission: None,
            success_rate: 0.0,
            avg_witnesses_per_beacon: 0.0,
            cellular_safe_mode: config.cellular_safe_mode,
            authorized_frequencies: authorized_frequencies.clone(),
            current_h3_cell: Some(location.h3_index.clone()),
            drs_score: None,
            co_beacon_active: false,
            last_challenge_epoch: None,
            randomness_source: RandomnessSource::None,
            nr_bands: vec![78],
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
            recent_transmissions: Arc::new(RwLock::new(HashMap::new())),
            co_beacon_status: Arc::new(RwLock::new(None)),
            randomness_source: RandomnessSource::None,
            authorized_nr_bands: vec![78],
            challenge_schedule: Arc::new(RwLock::new(None)),
            vrf_receiver: None,
            authorized: true,
            drs_score: 0.9,
        }
    }

    pub fn new_with_randomness(
        config: BeaconConfig,
        keypair: KeyPair,
        location: LocationData,
        authorized_frequencies: Vec<u32>,
        randomness_source: RandomnessSource,
    ) -> Self {
        let mut node = Self::new(config, keypair, location, authorized_frequencies);
        node.randomness_source = randomness_source;

        {
            let mut status = node.status.write().unwrap();
            status.randomness_source = randomness_source;
        }

        node
    }

    pub fn is_authorized(&self) -> bool {
        self.authorized && !self.authorized_frequencies.is_empty()
    }

    pub async fn start(&mut self) -> PoCResult<()> {
        info!("Starting beacon node {} with randomness source: {:?}",
            self.address, self.randomness_source);

        self.validate_config()?;

        let (_challenge_sender, challenge_receiver) = mpsc::unbounded_channel();
        let (announcement_sender, _announcement_receiver) = mpsc::unbounded_channel();
        let (_vrf_sender, vrf_receiver) = mpsc::unbounded_channel();

        self.challenge_receiver = Some(challenge_receiver);
        self.announcement_sender = Some(announcement_sender);
        self.vrf_receiver = Some(vrf_receiver);

        self.start_co_beacon_monitor().await?;

        {
            let mut status = self.status.write().unwrap();
            status.is_active = true;
        }

        info!("✅ Beacon node {} started successfully", self.address);
        Ok(())
    }

    pub async fn stop(&mut self) -> PoCResult<()> {
        info!("Stopping beacon node {}", self.address);

        self.stop_co_beacon_broadcast().await?;

        {
            let mut status = self.status.write().unwrap();
            status.is_active = false;
        }

        self.challenge_receiver = None;
        self.announcement_sender = None;
        self.vrf_receiver = None;

        info!("✅ Beacon node {} stopped", self.address);
        Ok(())
    }

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

    pub fn authorize_nr_band(&mut self, nr_band: u8) -> PoCResult<()> {
        if !self.authorized_nr_bands.contains(&nr_band) {
            self.authorized_nr_bands.push(nr_band);

            let mut status = self.status.write().unwrap();
            status.nr_bands.push(nr_band);

            info!("Authorized NR band n{} for beacon {}", nr_band, self.address);
        }
        Ok(())
    }

    pub fn update_drs_score(&mut self, score: f64) {
        self.drs_score = score.clamp(0.0, 1.0);

        let mut status = self.status.write().unwrap();
        status.drs_score = Some(score);
    }

    pub fn set_randomness_source(&mut self, source: RandomnessSource) {
        self.randomness_source = source;
        let mut status = self.status.write().unwrap();
        status.randomness_source = source;
        info!("Set randomness source to {:?} for beacon {}", source, self.address);
    }

    pub fn get_status(&self) -> BeaconStatus {
        self.status.read().unwrap().clone()
    }

    pub fn get_metrics(&self) -> BeaconMetrics {
        self.metrics.read().unwrap().clone()
    }

    pub fn get_co_beacon_status(&self) -> Option<CoBeaconStatus> {
        self.co_beacon_status.read().unwrap().clone()
    }

    pub fn get_challenge_schedule(&self) -> Option<ChallengeSchedule> {
        self.challenge_schedule.read().unwrap().clone()
    }

    pub async fn process_challenge(&mut self, challenge: Challenge) -> PoCResult<()> {
        debug!(
            "Processing challenge {} for beacon {}",
            challenge.challenge_hash, self.address
        );

        if !self.authorized {
            return Err(PoCError::ValidationFailed("Beacon not authorized".to_string()));
        }

        let epoch = Timestamp::now().as_secs() / 3600;
        let key = (self.address, challenge.nonce.clone(), epoch);

        {
            let mut recent = self.recent_transmissions.write().unwrap();
            let cutoff = Timestamp::now().as_millis().saturating_sub(3_600_000);
            recent.retain(|_, timestamp| timestamp.as_millis() > cutoff);

            if recent.contains_key(&key) {
                return Err(PoCError::DuplicateSubmission(
                    "Duplicate beacon transmission detected".to_string(),
                ));
            }
            recent.insert(key, Timestamp::now());
        }

        if !self.check_rate_limit()? {
            return Err(PoCError::RateLimitExceeded {
                operation: "beacon_announcement".to_string(),
                limit: 120,
            });
        }

        if self.drs_score < 0.7 {
            return Err(PoCError::ValidationFailed(format!(
                "DRS score {} below threshold 0.7",
                self.drs_score
            )));
        }

        let current_cell = self.h3_cell.read().unwrap().clone();
        if current_cell != Some(challenge.h3_cell.clone()) {
            debug!("Skipping challenge - not in target H3 cell");
            return Ok(());
        }

        let announcement = self.prepare_announcement(challenge.clone()).await?;
        announcement.validate()?;

        if self.config.use_side_channel {
            self.start_co_beacon_broadcast(&announcement).await?;
        }

        let tx_log = self.transmit_beacon(&announcement).await?;

        {
            let mut logs = self.tx_logs.write().unwrap();
            logs.push(tx_log);
            if logs.len() > 100 {
                logs.remove(0);
            }
        }

        self.update_metrics_after_transmission(true);

        {
            let mut status = self.status.write().unwrap();
            status.last_challenge_epoch = Some(epoch);
        }

        if let Some(ref sender) = self.announcement_sender {
            if let Err(e) = sender.send(announcement) {
                warn!("Failed to publish beacon announcement: {}", e);
            }
        }

        info!(
            "✅ Successfully processed challenge for beacon {} (epoch {})",
            self.address, epoch
        );
        Ok(())
    }

    pub async fn process_challenge_with_randomness(
        &mut self,
        challenge: Challenge,
        vrf_output: Hash,
        epoch: u64,
        slot: u64,
    ) -> PoCResult<()> {
        debug!(
            "Processing challenge {} with VRF randomness for beacon {} (epoch {}, slot {})",
            challenge.challenge_hash, self.address, epoch, slot
        );

        let region_id = self.h3_cell.read().unwrap().clone()
            .ok_or_else(|| PoCError::InvalidLocation("No H3 cell set".to_string()))?;

        let schedule = ChallengeSchedule::new(
            region_id.clone(),
            epoch,
            slot,
            vrf_output,
            self.address,
        );

        {
            let mut sched = self.challenge_schedule.write().unwrap();
            *sched = Some(schedule.clone());
        }

        if !schedule.is_active() {
            warn!("Challenge window not active for beacon {}", self.address);
            return Err(PoCError::TimeWindowViolation(
                "Not in challenge window".to_string(),
            ));
        }

        let announcement = self.prepare_announcement_with_randomness(
            challenge,
            vrf_output,
            region_id,
            epoch,
            slot,
        ).await?;

        announcement.validate()?;

        if self.config.use_side_channel {
            self.start_co_beacon_broadcast(&announcement).await?;
        }

        let tx_log = self.transmit_beacon(&announcement).await?;

        {
            let mut logs = self.tx_logs.write().unwrap();
            logs.push(tx_log);
            if logs.len() > 100 {
                logs.remove(0);
            }
        }

        self.update_metrics_after_transmission(true);

        {
            let mut metrics = self.metrics.write().unwrap();
            metrics.avg_window_duration_ms = schedule.window_end.as_millis() - schedule.window_start.as_millis();
        }

        {
            let mut status = self.status.write().unwrap();
            status.last_challenge_epoch = Some(epoch);
        }

        if let Some(ref sender) = self.announcement_sender {
            if let Err(e) = sender.send(announcement) {
                warn!("Failed to publish beacon announcement: {}", e);
            }
        }

        info!(
            "✅ Successfully processed challenge with randomness for beacon {} (epoch {}, remaining: {}ms)",
            self.address, epoch, schedule.remaining_time_ms()
        );
        Ok(())
    }

    async fn start_co_beacon_monitor(&self) -> PoCResult<()> {
        let co_beacon_status = self.co_beacon_status.clone();
        let metrics = self.metrics.clone();
        let status = self.status.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(1));

            loop {
                interval.tick().await;

                let co_beacon = co_beacon_status.read().unwrap().clone();

                if let Some(ref beacon) = co_beacon {
                    if beacon.is_broadcasting {
                        let now = Timestamp::now();

                        if now > beacon.end_time {

                            let mut co_status = co_beacon_status.write().unwrap();
                            if let Some(ref mut status) = *co_status {
                                status.is_broadcasting = false;
                            }

                            let mut st = status.write().unwrap();
                            st.co_beacon_active = false;

                            debug!("Co-beacon broadcast window expired, stopping");
                        }
                    }
                }
            }
        });

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

    fn update_co_beacon_metrics(&self, success: bool) {
        let mut metrics = self.metrics.write().unwrap();
        metrics.co_beacon_broadcasts += 1;

        if success {
            metrics.nonce_binding_successes += 1;
        } else {
            metrics.nonce_binding_failures += 1;
        }
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

        let nr_band = self.authorized_nr_bands.first().copied();
        let nr_arfcn = if frequency == 3500 {
            Some(646656)
        } else {
            None
        };

        let tx_params = super::announcement::BeaconTxParams {
            frequency,
            tx_power_dbm: self.config.max_tx_power_dbm.min(23),
            pci: 1,
            beam_config: None,
            duration_ms: 1000,
            mcs: Some(16),
            nr_arfcn,
            nr_band,
            ssb_index: Some(0),
        };

        let mut announcement =
            BeaconAnnouncement::new(self.address, challenge, location, tx_params);

        if self.config.use_side_channel {
            let co_beacon_method = CoBeaconMethod::BLE {
                service_uuid: "6E400001-B5A3-F393-E0A9-E50E24DCCA9E".to_string(),
                characteristic_uuid: "6E400002-B5A3-F393-E0A9-E50E24DCCA9E".to_string(),
                tx_power_dbm: -10,
            };

            announcement.add_co_beacon(co_beacon_method, &self.keypair)?;
        }

        announcement.sign(&self.keypair)?;

        Ok(announcement)
    }

    async fn prepare_announcement_with_randomness(
        &mut self,
        challenge: Challenge,
        vrf_output: Hash,
        region_id: String,
        epoch: u64,
        slot: u64,
    ) -> PoCResult<BeaconAnnouncement> {
        let location = self
            .location
            .read().unwrap()
            .clone()
            .ok_or_else(|| PoCError::InvalidLocation("No location set".to_string()))?;

        let frequency = self.authorized_frequencies.get(0).copied().unwrap_or(3500);

        let nr_band = self.authorized_nr_bands.first().copied();
        let nr_arfcn = if frequency == 3500 {
            Some(646656)
        } else {
            None
        };

        let tx_params = super::announcement::BeaconTxParams {
            frequency,
            tx_power_dbm: self.config.max_tx_power_dbm.min(23),
            pci: 1,
            beam_config: None,
            duration_ms: 1000,
            mcs: Some(16),
            nr_arfcn,
            nr_band,
            ssb_index: Some(0),
        };

        let mut announcement = BeaconAnnouncement::new_with_randomness(
            self.address,
            challenge,
            location,
            tx_params,
            vrf_output,
            region_id,
            epoch,
            slot,
        );

        if self.config.use_side_channel {
            let co_beacon_method = CoBeaconMethod::BLE {
                service_uuid: "6E400001-B5A3-F393-E0A9-E50E24DCCA9E".to_string(),
                characteristic_uuid: "6E400002-B5A3-F393-E0A9-E50E24DCCA9E".to_string(),
                tx_power_dbm: -10,
            };

            announcement.add_co_beacon(co_beacon_method, &self.keypair)?;
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
            "🔊 Beacon {} transmitted on {} MHz (NR band: {:?}) at {} dBm (epoch: {})",
            self.address,
            announcement.tx_params.frequency,
            announcement.tx_params.nr_band,
            announcement.tx_params.tx_power_dbm,
            announcement.epoch
        );

        Ok(tx_log)
    }

    async fn start_co_beacon_broadcast(
        &mut self,
        announcement: &BeaconAnnouncement,
    ) -> PoCResult<()> {
        if let Some(ref co_beacon_info) = announcement.co_beacon {
            info!(
                "📡 Starting co-beacon broadcast for beacon {} ({:?})",
                self.address, co_beacon_info.method
            );

            let co_beacon_status = CoBeaconStatus {
                method: co_beacon_info.method.clone(),
                is_broadcasting: true,
                nonce: co_beacon_info.side_channel_nonce.clone(),
                start_time: co_beacon_info.broadcast_start,
                end_time: co_beacon_info.broadcast_end,
                broadcasts_sent: 0,
                witnesses_detected: 0,
            };

            {
                let mut status = self.co_beacon_status.write().unwrap();
                *status = Some(co_beacon_status);
            }

            {
                let mut status = self.status.write().unwrap();
                status.co_beacon_active = true;
            }

            self.update_co_beacon_metrics(true);

            info!("✅ Co-beacon broadcast started for beacon {}", self.address);
        }

        Ok(())
    }

    async fn stop_co_beacon_broadcast(&mut self) -> PoCResult<()> {
        let is_broadcasting = self.co_beacon_status.read().unwrap()
            .as_ref()
            .map_or(false, |s| s.is_broadcasting);

        if is_broadcasting {
            info!("🔴 Stopping co-beacon broadcast for beacon {}", self.address);

            {
                let mut co_status = self.co_beacon_status.write().unwrap();
                if let Some(ref mut status) = *co_status {
                    status.is_broadcasting = false;
                }
            }

            {
                let mut status = self.status.write().unwrap();
                status.co_beacon_active = false;
            }

            info!("✅ Co-beacon broadcast stopped for beacon {}", self.address);
        }

        Ok(())
    }

    fn get_tx_log(&self) -> Option<BeaconTxLog> {
        self.tx_logs.read().unwrap().last().cloned()
    }

    fn is_cellular_safe(&self) -> bool {
        self.config.cellular_safe_mode
    }

    fn get_current_epoch(&self) -> u64 {
        Timestamp::now().as_secs() / 3600
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
            h3_index: "872834720ffffff".to_string(),
        };

        let mut beacon = BeaconNode::new(
            BeaconConfig::default(),
            keypair,
            location,
            vec![3500, 3600, 3700],
        );

        beacon.authorized = true;
        beacon.drs_score = 0.9;

        beacon
    }

    fn create_test_beacon_with_randomness() -> BeaconNode {
        let keypair = KeyPair::generate();
        let location = LocationData {
            latitude: 37.7749,
            longitude: -122.4194,
            altitude: Some(10.0),
            accuracy: Some(5.0),
            timestamp: Timestamp::now().as_millis(),
            h3_index: "872834720ffffff".to_string(),
        };

        let mut beacon = BeaconNode::new_with_randomness(
            BeaconConfig::default(),
            keypair,
            location,
            vec![3500, 3600, 3700],
            RandomnessSource::VRF,
        );

        beacon.authorized = true;
        beacon.drs_score = 0.9;

        beacon
    }

    #[tokio::test]
    async fn test_beacon_node_creation() {
        let beacon = create_test_beacon();
        assert!(beacon.is_authorized());
        assert_eq!(beacon.authorized_frequencies().len(), 3);
        assert_eq!(beacon.randomness_source, RandomnessSource::None);
    }

    #[tokio::test]
    async fn test_beacon_with_randomness() {
        let beacon = create_test_beacon_with_randomness();
        assert_eq!(beacon.randomness_source, RandomnessSource::VRF);

        let status = beacon.get_status();
        assert_eq!(status.randomness_source, RandomnessSource::VRF);
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
            h3_cell: "872834720ffffff".to_string(),
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

    #[tokio::test]
    #[ignore]
    async fn test_challenge_with_randomness() {
        let mut beacon = create_test_beacon_with_randomness();
        beacon.start().await.unwrap();

        let challenge = Challenge {
            challenge_hash: Hash::new([1u8; 32]),
            h3_cell: "872834720ffffff".to_string(),
            nonce: vec![2u8; 16],
            timestamp: Timestamp::now(),
            difficulty: 1,
            reward_scale: 1.0,
        };

        let vrf_output = Hash::new([5u8; 32]);
        let epoch = beacon.get_current_epoch();
        let slot = 1;

        assert!(beacon.process_challenge_with_randomness(
            challenge,
            vrf_output,
            epoch,
            slot
        ).await.is_ok());

        let metrics = beacon.get_metrics();
        assert_eq!(metrics.total_transmissions, 1);
        assert_eq!(metrics.avg_window_duration_ms, 10_000);

        let status = beacon.get_status();
        assert_eq!(status.last_challenge_epoch, Some(epoch));
    }

    #[tokio::test]
    async fn test_anti_replay_protection() {
        let mut beacon = create_test_beacon();
        beacon.start().await.unwrap();

        let challenge = Challenge {
            challenge_hash: Hash::new([1u8; 32]),
            h3_cell: "872834720ffffff".to_string(),
            nonce: vec![2u8; 16],
            timestamp: Timestamp::now(),
            difficulty: 1,
            reward_scale: 1.0,
        };

        assert!(beacon.process_challenge(challenge.clone()).await.is_ok());

        assert!(beacon.process_challenge(challenge).await.is_err());
    }

    #[test]
    fn test_rate_limiting() {
        let beacon = create_test_beacon();

        assert!(beacon.check_rate_limit().unwrap());

        for _ in 0..9 {
            assert!(beacon.check_rate_limit().unwrap());
        }
    }

    #[tokio::test]
    async fn test_co_beacon_broadcast() {
        let mut beacon = create_test_beacon();
        beacon.start().await.unwrap();

        let challenge = Challenge {
            challenge_hash: Hash::new([1u8; 32]),
            h3_cell: "872834720ffffff".to_string(),
            nonce: vec![2u8; 16],
            timestamp: Timestamp::now(),
            difficulty: 1,
            reward_scale: 1.0,
        };

        let announcement = beacon.prepare_announcement(challenge).await.unwrap();

        assert!(beacon.start_co_beacon_broadcast(&announcement).await.is_ok());

        let status = beacon.get_status();
        assert!(status.co_beacon_active);

        let co_beacon_status = beacon.get_co_beacon_status();
        assert!(co_beacon_status.is_some());
        assert!(co_beacon_status.unwrap().is_broadcasting);

        assert!(beacon.stop_co_beacon_broadcast().await.is_ok());

        let status = beacon.get_status();
        assert!(!status.co_beacon_active);
    }

    #[test]
    fn test_nr_band_authorization() {
        let mut beacon = create_test_beacon();

        assert!(beacon.authorize_nr_band(77).is_ok());
        assert!(beacon.authorize_nr_band(78).is_ok());

        let status = beacon.get_status();
        assert!(status.nr_bands.contains(&77));
        assert!(status.nr_bands.contains(&78));
    }

    #[test]
    fn test_randomness_source_setting() {
        let mut beacon = create_test_beacon();

        assert_eq!(beacon.randomness_source, RandomnessSource::None);

        beacon.set_randomness_source(RandomnessSource::VRF);
        assert_eq!(beacon.randomness_source, RandomnessSource::VRF);

        let status = beacon.get_status();
        assert_eq!(status.randomness_source, RandomnessSource::VRF);
    }

    #[tokio::test]
    #[ignore]
    async fn test_challenge_schedule() {
        let mut beacon = create_test_beacon_with_randomness();
        beacon.start().await.unwrap();

        let challenge = Challenge {
            challenge_hash: Hash::new([1u8; 32]),
            h3_cell: "872834720ffffff".to_string(),
            nonce: vec![2u8; 16],
            timestamp: Timestamp::now(),
            difficulty: 1,
            reward_scale: 1.0,
        };

        let vrf_output = Hash::new([5u8; 32]);
        let epoch = beacon.get_current_epoch();

        assert!(beacon.process_challenge_with_randomness(
            challenge,
            vrf_output,
            epoch,
            1
        ).await.is_ok());

        let schedule = beacon.get_challenge_schedule();
        assert!(schedule.is_some());

        let sched = schedule.unwrap();
        assert_eq!(sched.epoch, epoch);
        assert_eq!(sched.region_id, "872834720ffffff");
        assert!(sched.is_active());
    }

    #[tokio::test]
    async fn test_co_beacon_metrics() {
        let mut beacon = create_test_beacon();
        beacon.start().await.unwrap();

        let challenge = Challenge {
            challenge_hash: Hash::new([1u8; 32]),
            h3_cell: "872834720ffffff".to_string(),
            nonce: vec![2u8; 16],
            timestamp: Timestamp::now(),
            difficulty: 1,
            reward_scale: 1.0,
        };

        let announcement = beacon.prepare_announcement(challenge).await.unwrap();
        beacon.start_co_beacon_broadcast(&announcement).await.unwrap();

        let metrics = beacon.get_metrics();
        assert_eq!(metrics.co_beacon_broadcasts, 1);
        assert_eq!(metrics.nonce_binding_successes, 1);
    }

    #[test]
    fn test_epoch_calculation() {
        let beacon = create_test_beacon();
        let epoch = beacon.get_current_epoch();

        let expected_epoch = Timestamp::now().as_secs() / 3600;
        assert_eq!(epoch, expected_epoch);
    }

    #[tokio::test]
    async fn test_location_update() {
        let mut beacon = create_test_beacon();

        let new_location = LocationData {
            latitude: 40.7128,
            longitude: -74.0060,
            altitude: Some(20.0),
            accuracy: Some(3.0),
            timestamp: Timestamp::now().as_millis(),
            h3_index: "872a1072fffffff".to_string(),
        };

        assert!(beacon.update_location(new_location.clone()).is_ok());

        let status = beacon.get_status();
        assert_eq!(status.current_h3_cell, Some("872a1072fffffff".to_string()));
    }

    #[tokio::test]
    #[ignore]
    async fn test_drs_score_threshold() {
        let mut beacon = create_test_beacon();
        beacon.start().await.unwrap();

        beacon.drs_score = 0.5;

        let challenge = Challenge {
            challenge_hash: Hash::new([1u8; 32]),
            h3_cell: "872834720ffffff".to_string(),
            nonce: vec![2u8; 16],
            timestamp: Timestamp::now(),
            difficulty: 1,
            reward_scale: 1.0,
        };

        assert!(beacon.process_challenge(challenge.clone()).await.is_err());

        beacon.drs_score = 0.9;

        assert!(beacon.process_challenge(challenge).await.is_ok());
    }

    #[tokio::test]
    async fn test_cellular_safe_mode() {
        let beacon = create_test_beacon();
        assert!(beacon.is_cellular_safe());

        let status = beacon.get_status();
        assert!(status.cellular_safe_mode);
    }

    #[tokio::test]
    async fn test_nonce_binding() {
        let mut beacon = create_test_beacon();
        beacon.start().await.unwrap();

        let challenge = Challenge {
            challenge_hash: Hash::new([1u8; 32]),
            h3_cell: "872834720ffffff".to_string(),
            nonce: vec![2u8; 16],
            timestamp: Timestamp::now(),
            difficulty: 1,
            reward_scale: 1.0,
        };

        let announcement = beacon.prepare_announcement(challenge).await.unwrap();

        if beacon.config.use_side_channel {
            assert!(announcement.co_beacon.is_some());

            let co_beacon = announcement.co_beacon.as_ref().unwrap();
            assert_eq!(co_beacon.side_channel_nonce.len(), 16);

            assert_ne!(co_beacon.nonce_commitment, Hash::new([0u8; 32]));
        }
    }

    #[tokio::test]
    #[ignore]
    async fn test_window_duration() {
        let mut beacon = create_test_beacon_with_randomness();
        beacon.start().await.unwrap();

        let challenge = Challenge {
            challenge_hash: Hash::new([1u8; 32]),
            h3_cell: "872834720ffffff".to_string(),
            nonce: vec![2u8; 16],
            timestamp: Timestamp::now(),
            difficulty: 1,
            reward_scale: 1.0,
        };

        let vrf_output = Hash::new([5u8; 32]);
        let epoch = beacon.get_current_epoch();

        beacon.process_challenge_with_randomness(
            challenge,
            vrf_output,
            epoch,
            1
        ).await.unwrap();

        let schedule = beacon.get_challenge_schedule().unwrap();

        let window_duration = schedule.window_end.as_millis() - schedule.window_start.as_millis();
        assert_eq!(window_duration, 10_000);
    }
}
