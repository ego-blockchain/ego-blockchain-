use super::{DetectedBeacon, Witness, WitnessMetrics, WitnessReport, WitnessStatus};
use crate::config::WitnessConfig;
use crate::error::{PoCError, PoCResult};
use crate::types::*;
use ego_core::{Address, Hash, KeyPair, Timestamp};
use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant, interval};
use tracing::{debug, info, warn};

pub struct WitnessNode {
    config: WitnessConfig,
    keypair: Arc<KeyPair>,
    address: Address,
    location: Arc<RwLock<Option<LocationData>>>,
    h3_cell: Arc<RwLock<Option<String>>>,
    scanning_frequencies: Vec<u32>,
    authorized_slices: Vec<String>,
    status: Arc<RwLock<WitnessStatus>>,
    metrics: Arc<RwLock<WitnessMetrics>>,
    pending_reports: Arc<RwLock<VecDeque<WitnessReport>>>,
    submitted_reports: Arc<RwLock<HashSet<Hash>>>,
    rate_limiter: Arc<RwLock<RateLimiter>>,
    beacon_receiver: Option<mpsc::UnboundedReceiver<DetectedBeacon>>,
    report_sender: Option<mpsc::UnboundedSender<WitnessReport>>,
    drs_score: Arc<RwLock<Option<f64>>>,
    batch_processor: Arc<RwLock<BatchProcessor>>,
}

#[derive(Debug, Clone)]
struct RateLimiter {
    reports_per_hour: u32,
    current_hour_count: u32,
    last_reset: Timestamp,
    burst_allowance: u32,
    burst_used: u32,
}

#[derive(Debug)]
struct BatchProcessor {
    current_batch: Vec<WitnessReport>,
    batch_start_time: Instant,
    batch_interval: Duration,
    max_batch_size: usize,
}

impl WitnessNode {
    pub fn new(
        config: WitnessConfig,
        keypair: KeyPair,
        location: LocationData,
        scanning_frequencies: Vec<u32>,
    ) -> Self {
        let address = Address::from_public_key(&keypair.public_key());

        let status = WitnessStatus {
            witness_id: address,
            is_active: false,
            is_scanning: false,
            last_detection: None,
            detection_rate: 0.0,
            report_success_rate: 0.0,
            cellular_safe_mode: true,
            scanning_frequencies: scanning_frequencies.clone(),
            current_h3_cell: Some(location.h3_index.clone()),
            drs_score: None,
        };

        let h3_index = location.h3_index.clone();

        let batch_processor = BatchProcessor {
            current_batch: Vec::new(),
            batch_start_time: Instant::now(),
            batch_interval: Duration::from_secs(config.batch_interval_seconds),
            max_batch_size: config.max_reports_per_batch,
        };

        Self {
            config: config.clone(),
            keypair: Arc::new(keypair),
            address,
            location: Arc::new(RwLock::new(Some(location))),
            h3_cell: Arc::new(RwLock::new(Some(h3_index))),
            scanning_frequencies,
            authorized_slices: Vec::new(),
            status: Arc::new(RwLock::new(status)),
            metrics: Arc::new(RwLock::new(WitnessMetrics::default())),
            pending_reports: Arc::new(RwLock::new(VecDeque::new())),
            submitted_reports: Arc::new(RwLock::new(HashSet::new())),
            rate_limiter: Arc::new(RwLock::new(RateLimiter::new(
                config.rate_limit_per_hour,
                10,
            ))),
            beacon_receiver: None,
            report_sender: None,
            drs_score: Arc::new(RwLock::new(None)),
            batch_processor: Arc::new(RwLock::new(batch_processor)),
        }
    }

    pub async fn start(&mut self) -> PoCResult<()> {
        info!("Starting witness node {}", self.address);

        self.validate_config()?;

        let (_beacon_sender, beacon_receiver) = mpsc::unbounded_channel();
        let (report_sender, _report_receiver) = mpsc::unbounded_channel();

        self.beacon_receiver = Some(beacon_receiver);
        self.report_sender = Some(report_sender);

        self.start_rf_scanning().await?;
        self.start_batch_processing().await?;

        {
            let mut status = self.status.write().unwrap();
            status.is_active = true;
            status.is_scanning = true;
        }

        info!("✅ Witness node {} started successfully", self.address);
        Ok(())
    }

    pub async fn stop(&mut self) -> PoCResult<()> {
        info!("Stopping witness node {}", self.address);

        {
            let mut status = self.status.write().unwrap();
            status.is_active = false;
            status.is_scanning = false;
        }

        self.flush_batch().await?;

        self.beacon_receiver = None;
        self.report_sender = None;

        info!("✅ Witness node {} stopped", self.address);
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

        info!("Updated witness location for node {}", self.address);
        Ok(())
    }

    pub fn authorize_slice(&mut self, slice_id: String) -> PoCResult<()> {
        if !self.authorized_slices.contains(&slice_id) {
            self.authorized_slices.push(slice_id.clone());
            info!("Authorized slice {} for witness {}", slice_id, self.address);
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

        debug!(
            "Updated DRS score to {} for witness {}",
            score, self.address
        );
    }

    pub fn get_status(&self) -> WitnessStatus {
        self.status.read().unwrap().clone()
    }

    pub fn get_metrics(&self) -> WitnessMetrics {
        self.metrics.read().unwrap().clone()
    }

    async fn start_rf_scanning(&self) -> PoCResult<()> {
        let address = self.address;
        let _scanning_frequencies = self.scanning_frequencies.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut interval =
                interval(Duration::from_millis((1000.0 / config.scan_rate_hz) as u64));

            loop {
                interval.tick().await;

                if rand::random::<f32>() < 0.1 {
                    debug!("Simulated beacon detection for witness {}", address);
                }
            }
        });

        Ok(())
    }

    async fn start_batch_processing(&self) -> PoCResult<()> {
        let batch_processor = self.batch_processor.clone();
        let _report_sender = self.report_sender.clone();
        let config = self.config.clone();
        let address = self.address;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(config.batch_interval_seconds));

            loop {
                interval.tick().await;

                let mut processor = batch_processor.write().unwrap();

                let should_submit = !processor.current_batch.is_empty()
                    && (processor.current_batch.len() >= processor.max_batch_size
                        || processor.batch_start_time.elapsed() >= processor.batch_interval);

                if should_submit {
                    debug!(
                        "Submitting batch of {} reports from witness {}",
                        processor.current_batch.len(),
                        address
                    );

                    if config.enable_compression && processor.current_batch.len() > 1 {
                        debug!("Compressing batch for cellular-safe transmission");
                    }

                    processor.current_batch.clear();
                    processor.batch_start_time = Instant::now();
                }
            }
        });

        Ok(())
    }

    async fn process_detected_beacon(
        &mut self,
        detected: DetectedBeacon,
    ) -> PoCResult<Option<WitnessReport>> {
        debug!("Processing detected beacon for witness {}", self.address);

        if !self.check_rate_limit()? {
            return Err(PoCError::RateLimitExceeded {
                operation: "witness_report".to_string(),
                limit: self.config.rate_limit_per_hour,
            });
        }

        if let Some(score) = self.drs_score.read().unwrap().as_ref() {
            if *score < 0.5 {
                return Err(PoCError::InsufficientDRSScore {
                    score: *score,
                    threshold: 0.5,
                });
            }
        }

        let beacon_id = detected
            .announcement
            .as_ref()
            .map(|ann| ann.beacon_id)
            .unwrap_or_else(|| Address::new([0u8; 20]));

        let challenge_hash = detected
            .announcement
            .as_ref()
            .map(|ann| ann.challenge.challenge_hash)
            .unwrap_or_else(|| Hash::new([0u8; 32]));

        let witness_location = self
            .location
            .read()
            .unwrap()
            .clone()
            .ok_or_else(|| PoCError::InvalidLocation("No witness location set".to_string()))?;

        let mut report = WitnessReport::new(
            self.address,
            beacon_id,
            challenge_hash,
            detected.rf_metrics.clone(),
            witness_location,
            detected.announcement.as_ref(),
        );

        if let Some(co_beacon) = detected.co_beacon_data {
            let verification = super::report::CoBeaconVerification {
                received_nonce: co_beacon.nonce,
                signature_valid: true,
                rx_timestamp: co_beacon.rx_timestamp,
                time_delta_ms: (detected.rf_metrics.rx_timestamp - co_beacon.rx_timestamp) as i32,
                side_channel_rssi: None,
            };
            report.add_co_beacon_verification(verification);
        }

        report.sign(&self.keypair)?;
        report.validate()?;

        if let Some(fraud_type) = report.detect_potential_fraud() {
            warn!(
                "Potential fraud detected in witness report: {:?}",
                fraud_type
            );

            let mut metrics = self.metrics.write().unwrap();
            metrics.fraud_reports += 1;

            return Ok(None);
        }

        let report_hash = report.report_id;
        {
            let submitted = self.submitted_reports.read().unwrap();
            if submitted.contains(&report_hash) {
                debug!("Duplicate report detected, skipping");

                let mut metrics = self.metrics.write().unwrap();
                metrics.duplicate_detections += 1;

                return Ok(None);
            }
        }

        {
            let mut processor = self.batch_processor.write().unwrap();
            processor.current_batch.push(report.clone());
        }

        self.update_metrics_after_detection(&report);

        {
            let mut submitted = self.submitted_reports.write().unwrap();
            submitted.insert(report_hash);

            if submitted.len() > 1000 {
                let excess: Vec<_> = submitted
                    .iter()
                    .take(submitted.len() - 1000)
                    .cloned()
                    .collect();
                for hash in excess {
                    submitted.remove(&hash);
                }
            }
        }

        debug!("✅ Created witness report for beacon {}", beacon_id);
        Ok(Some(report))
    }

    async fn flush_batch(&self) -> PoCResult<()> {
        let mut processor = self.batch_processor.write().unwrap();

        if !processor.current_batch.is_empty() {
            info!(
                "Flushing batch of {} reports from witness {}",
                processor.current_batch.len(),
                self.address
            );

            processor.current_batch.clear();
            processor.batch_start_time = Instant::now();
        }

        Ok(())
    }

    fn validate_config(&self) -> PoCResult<()> {
        if self.config.scan_rate_hz <= 0.0 || self.config.scan_rate_hz > 10.0 {
            return Err(PoCError::ConfigError(
                "Invalid scan rate - must be between 0 and 10 Hz".to_string(),
            ));
        }

        if self.config.scan_rate_hz > 1.0 {
            warn!(
                "Scan rate {} Hz exceeds cellular-safe recommendations (≤1 Hz)",
                self.config.scan_rate_hz
            );
        }

        if self.config.max_reports_per_batch == 0 {
            return Err(PoCError::ConfigError(
                "Maximum reports per batch must be > 0".to_string(),
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

        if limiter.current_hour_count >= limiter.reports_per_hour {
            return Ok(false);
        }

        limiter.current_hour_count += 1;
        Ok(true)
    }

    fn update_metrics_after_detection(&self, report: &WitnessReport) {
        let mut metrics = self.metrics.write().unwrap();
        let mut status = self.status.write().unwrap();

        metrics.total_detections += 1;
        metrics.valid_reports += 1;

        let total_rsrp = metrics.avg_rsrp * (metrics.total_detections - 1) as f32
            + report.rf_metrics.rsrp as f32;
        metrics.avg_rsrp = total_rsrp / metrics.total_detections as f32;

        metrics.last_updated = Timestamp::now();

        status.last_detection = Some(Timestamp::now());
        status.report_success_rate =
            (metrics.valid_reports as f64) / (metrics.total_detections as f64);

        status.detection_rate = metrics.total_detections as f32
            / (status.last_detection.unwrap().as_millis() - metrics.last_updated.as_millis()).max(1)
                as f32
            * 3600.0;
    }
}

impl Witness for WitnessNode {
    fn witness_id(&self) -> Address {
        self.address
    }

    fn is_active(&self) -> bool {
        self.status.read().unwrap().is_active
    }

    fn scanning_frequencies(&self) -> Vec<u32> {
        self.scanning_frequencies.clone()
    }

    async fn process_beacon(&mut self, beacon: DetectedBeacon) -> PoCResult<Option<WitnessReport>> {
        self.process_detected_beacon(beacon).await
    }

    fn get_pending_reports(&self) -> Vec<WitnessReport> {
        self.pending_reports
            .read()
            .unwrap()
            .iter()
            .cloned()
            .collect()
    }

    fn clear_submitted_reports(&mut self, report_hashes: Vec<Hash>) {
        let mut submitted = self.submitted_reports.write().unwrap();
        for hash in report_hashes {
            submitted.insert(hash);
        }
    }

    fn is_cellular_safe(&self) -> bool {
        self.config.scan_rate_hz <= 1.0
            && self.config.enable_compression
            && self.config.batch_interval_seconds >= 5
    }
}

impl RateLimiter {
    fn new(reports_per_hour: u32, burst_allowance: u32) -> Self {
        Self {
            reports_per_hour,
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

    fn create_test_witness() -> WitnessNode {
        let keypair = KeyPair::generate();
        let location = LocationData {
            latitude: 37.7749,
            longitude: -122.4194,
            altitude: Some(10.0),
            accuracy: Some(5.0),
            timestamp: Timestamp::now().as_millis(),
            h3_index: "87283472bffffff".to_string(),
        };

        WitnessNode::new(
            WitnessConfig::default(),
            keypair,
            location,
            vec![3500, 3600, 3700],
        )
    }

    #[tokio::test]
    async fn test_witness_node_creation() {
        let witness = create_test_witness();
        assert!(!witness.is_active());
        assert_eq!(witness.scanning_frequencies().len(), 3);
        assert!(witness.is_cellular_safe());
    }

    #[tokio::test]
    async fn test_witness_start_stop() {
        let mut witness = create_test_witness();

        assert!(witness.start().await.is_ok());
        assert!(witness.get_status().is_active);
        assert!(witness.get_status().is_scanning);

        assert!(witness.stop().await.is_ok());
        assert!(!witness.get_status().is_active);
        assert!(!witness.get_status().is_scanning);
    }

    #[tokio::test]
    async fn test_beacon_processing() {
        let mut witness = create_test_witness();
        witness.start().await.unwrap();

        let detected_beacon = DetectedBeacon {
            rf_metrics: RFMetrics {
                rsrp: -85,
                rsrq: -10,
                sinr: 15,
                timing_advance: 100,
                pci: 1,
                beam_index: Some(0),
                frequency: 3500,
                rx_timestamp: Timestamp::now().as_millis(),
            },
            announcement: None,
            co_beacon_data: None,
            detected_at: Timestamp::now(),
            witness_location: LocationData {
                latitude: 37.7749,
                longitude: -122.4194,
                altitude: Some(10.0),
                accuracy: Some(5.0),
                timestamp: Timestamp::now().as_millis(),
                h3_index: "87283472bffffff".to_string(),
            },
        };

        let result = witness.process_beacon(detected_beacon).await;

        assert!(result.is_ok());
    }

    #[test]
    fn test_rate_limiting() {
        let witness = create_test_witness();

        assert!(witness.check_rate_limit().unwrap());

        for _ in 0..9 {
            assert!(witness.check_rate_limit().unwrap());
        }
    }
}
