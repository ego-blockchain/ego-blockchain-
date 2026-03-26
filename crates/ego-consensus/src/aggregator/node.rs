use super::{
    Aggregator, AggregatorMetrics, AggregatorStatus, DailyEvidenceRoot, DensityEvent,
    PoCBundle, PoCEvent, PoCFraudEvidence, PoCFraudType, WitnessSet,
};
use crate::bridge::{BftBridge, create_aggregator_bridge};
use crate::witness::bridge::register_global_aggregator;
use super::validation::{validate_poc_bundle, validate_poc_bundle_with_epoch_config, MIN_QUALITY_SCORE};
use crate::config::epoch::{EpochConfig, EpochConfigProvider};
use super::dos_limits::{
    RateLimiter, RateLimitConfig, DRSQuotaManager, CellularSafeMode,
};
use crate::beacon::BeaconAnnouncement;
use crate::config::AggregatorConfig;
use crate::error::{PoCError, PoCResult};
use crate::witness::WitnessReport;
use ego_core::{Address, Hash, KeyPair, Timestamp};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

pub struct AggregatorNode {
    config: AggregatorConfig,
    keypair: Arc<KeyPair>,
    address: Address,
    coverage_region: Vec<String>,
    active_witness_sets: Arc<RwLock<HashMap<Hash, WitnessSet>>>,
    pending_bundles: Arc<RwLock<VecDeque<PoCBundle>>>,
    daily_bundles: Arc<RwLock<HashMap<String, Vec<PoCBundle>>>>,
    status: Arc<RwLock<AggregatorStatus>>,
    metrics: Arc<RwLock<AggregatorMetrics>>,
    beacon_receiver: Option<mpsc::UnboundedReceiver<BeaconAnnouncement>>,
    witness_receiver: Option<mpsc::UnboundedReceiver<WitnessReport>>,
    event_sender: Option<mpsc::UnboundedSender<PoCEvent>>,
    fraud_sender: Option<mpsc::UnboundedSender<PoCFraudEvidence>>,
    density_event_sender: Option<mpsc::UnboundedSender<DensityEvent>>,
    daily_anchor_sender: Option<mpsc::UnboundedSender<DailyEvidenceRoot>>,
    rate_limiter: Arc<RateLimiter>,
    drs_quota_manager: Arc<DRSQuotaManager>,
    cellular_safe_mode_manager: Arc<CellularSafeMode>,
    compression_enabled: bool,
    compression_threshold: usize,
    cellular_safe_mode: bool,
    quality_threshold: f64,
    epoch_config: Arc<RwLock<EpochConfig>>,
}

impl AggregatorNode {
    pub fn new(config: AggregatorConfig, keypair: KeyPair, coverage_region: Vec<String>) -> Self {
        let address = Address::from_public_key(&keypair.public_key());

        let status = AggregatorStatus {
            aggregator_id: address,
            is_active: false,
            coverage_region: coverage_region.clone(),
            processed_beacons: 0,
            processed_witnesses: 0,
            created_bundles: 0,
            submitted_events: 0,
            fraud_detections: 0,
            last_bundle_time: None,
            last_anchor_time: None,
        };

        let rate_limit_config = RateLimitConfig {
            cellular_safe_mode: false,
            ..Default::default()
        };

        Self {
            config: config.clone(),
            keypair: Arc::new(keypair),
            address,
            coverage_region,
            active_witness_sets: Arc::new(RwLock::new(HashMap::new())),
            pending_bundles: Arc::new(RwLock::new(VecDeque::new())),
            daily_bundles: Arc::new(RwLock::new(HashMap::new())),
            status: Arc::new(RwLock::new(status)),
            metrics: Arc::new(RwLock::new(AggregatorMetrics::default())),
            beacon_receiver: None,
            witness_receiver: None,
            event_sender: None,
            fraud_sender: None,
            density_event_sender: None,
            daily_anchor_sender: None,
            rate_limiter: Arc::new(RateLimiter::new(rate_limit_config)),
            drs_quota_manager: Arc::new(DRSQuotaManager::new()),
            cellular_safe_mode_manager: Arc::new(CellularSafeMode::new()),
            compression_enabled: config.compression_threshold_bytes > 0,
            compression_threshold: config.compression_threshold_bytes,
            cellular_safe_mode: false,
            quality_threshold: MIN_QUALITY_SCORE,
            epoch_config: Arc::new(RwLock::new(EpochConfig::new())),
        }
    }

    pub async fn start(&mut self) -> PoCResult<()> {
        info!(
            "Starting aggregator node {} for regions: {:?}",
            self.address, self.coverage_region
        );

        self.validate_config()?;

        let (_beacon_sender, beacon_receiver) = mpsc::unbounded_channel();
        let (_witness_sender, witness_receiver) = mpsc::unbounded_channel::<WitnessReport>();
        let (fraud_sender, _fraud_receiver) = mpsc::unbounded_channel();

        let erlang_endpoint = format!("{}:{}",
            self.config.erlang_bridge_host.as_deref().unwrap_or("localhost"),
            self.config.erlang_bridge_port.unwrap_or(25010)
        );
        let (event_sender, density_event_sender, daily_anchor_sender) =
            create_aggregator_bridge(erlang_endpoint.clone());

        info!("🔗 BFT bridge connected to Erlang consensus layer at {}", erlang_endpoint);

        let (witness_sender, witness_receiver) = mpsc::unbounded_channel();

        register_global_aggregator(self.coverage_region.clone(), witness_sender);
        info!("📍 Registered aggregator for regions: {:?}", self.coverage_region);

        self.beacon_receiver = Some(beacon_receiver);
        self.witness_receiver = Some(witness_receiver);
        self.event_sender = Some(event_sender);
        self.fraud_sender = Some(fraud_sender);
        self.density_event_sender = Some(density_event_sender);
        self.daily_anchor_sender = Some(daily_anchor_sender);

        self.start_witness_set_processor().await?;
        self.start_bundle_creator().await?;
        self.start_daily_anchor_generator().await?;
        self.start_density_monitor().await?;
        self.start_cleanup_task().await?;

        {
            let mut status = self.status.write().unwrap();
            status.is_active = true;
        }

        info!("✅ Aggregator node {} started successfully", self.address);
        Ok(())
    }

    pub async fn stop(&mut self) -> PoCResult<()> {
        info!("Stopping aggregator node {}", self.address);

        self.process_all_witness_sets().await?;
        self.submit_pending_bundles().await?;

        self.flush_buffered_data().await?;

        {
            let mut status = self.status.write().unwrap();
            status.is_active = false;
        }

        self.beacon_receiver = None;
        self.witness_receiver = None;
        self.event_sender = None;
        self.fraud_sender = None;
        self.density_event_sender = None;
        self.daily_anchor_sender = None;

        info!("✅ Aggregator node {} stopped", self.address);
        Ok(())
    }

    pub fn get_status(&self) -> AggregatorStatus {
        self.status.read().unwrap().clone()
    }

    pub fn get_metrics(&self) -> AggregatorMetrics {
        self.metrics.read().unwrap().clone()
    }

    pub fn set_cellular_safe_mode(&mut self, enabled: bool) {
        self.cellular_safe_mode = enabled;
        self.cellular_safe_mode_manager.set_enabled(enabled);

        let mut metrics = self.metrics.write().unwrap();
        metrics.cellular_safe_mode_active = enabled;

        if enabled {
            info!("📱 Cellular safe mode enabled for aggregator {}", self.address);
        } else {
            info!("📡 Cellular safe mode disabled for aggregator {}", self.address);
        }
    }

    pub fn set_quality_threshold(&mut self, threshold: f64) {
        self.quality_threshold = threshold.clamp(0.0, 1.0);
        info!(
            "Quality threshold set to {:.2} for aggregator {}",
            self.quality_threshold, self.address
        );
    }

    pub fn update_node_drs_score(&self, node_id: Address, drs_score: f64) {
        self.drs_quota_manager.update_quota(node_id, drs_score);
        debug!("Updated DRS quota for node {} (score: {:.2})", node_id, drs_score);
    }

    pub fn get_rate_limit_stats(&self) -> super::dos_limits::RateLimitStats {
        self.rate_limiter.get_stats()
    }

    pub fn get_cellular_stats(&self) -> super::dos_limits::CellularStats {
        self.cellular_safe_mode_manager.get_stats()
    }

    async fn start_witness_set_processor(&self) -> PoCResult<()> {
        let active_sets = self.active_witness_sets.clone();
        let config = self.config.clone();
        let address = self.address;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(5));

            loop {
                interval.tick().await;

                let mut sets_to_remove = Vec::new();

                {
                    let mut sets = active_sets.write().unwrap();

                    for (beacon_hash, witness_set) in sets.iter_mut() {
                        if witness_set.is_expired() {
                            debug!(
                                "Witness collection window expired for beacon {} (aggregator {})",
                                beacon_hash, address
                            );

                            if witness_set.witness_count() >= config.min_witnesses {
                                witness_set.is_complete = true;
                                sets_to_remove.push(*beacon_hash);
                            } else {
                                warn!(
                                    "Insufficient witnesses for beacon {} - got {}, need {}",
                                    beacon_hash,
                                    witness_set.witness_count(),
                                    config.min_witnesses
                                );
                                sets_to_remove.push(*beacon_hash);
                            }
                        }
                    }

                    for beacon_hash in &sets_to_remove {
                        sets.remove(beacon_hash);
                    }
                }
            }
        });

        Ok(())
    }

    async fn start_bundle_creator(&self) -> PoCResult<()> {
        let active_sets = self.active_witness_sets.clone();
        let pending_bundles = self.pending_bundles.clone();
        let keypair = self.keypair.clone();
        let address = self.address;
        let compression_enabled = self.compression_enabled;
        let compression_threshold = self.compression_threshold;
        let fraud_sender = self.fraud_sender.clone();
        let metrics = self.metrics.clone();
        let quality_threshold = self.quality_threshold;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10));

            loop {
                interval.tick().await;

                let completed_sets: Vec<(Hash, WitnessSet)> = {
                    let sets = active_sets.read().unwrap();
                    sets.iter()
                        .filter(|(_, set)| set.is_complete)
                        .map(|(hash, set)| (*hash, set.clone()))
                        .collect()
                };

                for (beacon_hash, witness_set) in completed_sets {
                    debug!(
                        "Creating PoC bundle for beacon {} with {} witnesses (aggregator {})",
                        beacon_hash,
                        witness_set.witness_count(),
                        address
                    );

                    let mut bundle = PoCBundle::new(
                        address,
                        witness_set.beacon_announcement.clone(),
                        witness_set.witness_reports.clone(),
                    );

                    if let Err(e) = bundle.sign(&keypair) {
                        error!("Failed to sign PoC bundle: {}", e);
                        continue;
                    }

                    match bundle.validate() {
                        Ok(_) => {

                            if !bundle.meets_quality_threshold(quality_threshold) {
                                warn!(
                                    "Bundle quality {:.3} below threshold {:.3}, rejecting",
                                    bundle.coverage_quality.quality_score,
                                    quality_threshold
                                );

                                let mut m = metrics.write().unwrap();
                                m.coherence_check_failures += 1;
                                continue;
                            }

                            {
                                let mut m = metrics.write().unwrap();

                                let n = m.bundles_created as f64;
                                m.avg_path_loss_rmse = (m.avg_path_loss_rmse * n + bundle.get_path_loss_rmse()) / (n + 1.0);
                                m.avg_diversity_score = (m.avg_diversity_score * n + bundle.get_diversity_score()) / (n + 1.0);
                                m.avg_nonce_binding_fraction = (m.avg_nonce_binding_fraction * n + bundle.get_nonce_binding_fraction()) / (n + 1.0);

                                if bundle.get_ldm_penalty() > 0.0 {
                                    m.density_penalties_applied += 1;
                                }
                            }

                            info!(
                                "✅ Bundle validated - RMSE: {:.2} dB, diversity: {:.2}, nonce: {:.2}, LDM penalty: {:.2}",
                                bundle.get_path_loss_rmse(),
                                bundle.get_diversity_score(),
                                bundle.get_nonce_binding_fraction(),
                                bundle.get_ldm_penalty()
                            );
                        }
                        Err(e) => {
                            warn!("Bundle validation failed: {}", e);

                            if let Some(ref sender) = fraud_sender {
                                let fraud_type = Self::classify_validation_error(&e);
                                let evidence = PoCFraudEvidence::new(
                                    fraud_type,
                                    beacon_hash,
                                    bundle.bundle_id,
                                    address,
                                    witness_set.epoch,
                                    vec![],
                                    address,
                                );

                                if let Err(send_err) = sender.send(evidence) {
                                    error!("Failed to emit fraud evidence: {}", send_err);
                                }
                            }

                            let mut m = metrics.write().unwrap();
                            if e.to_string().contains("Path-loss") {
                                m.path_loss_fit_failures += 1;
                            }
                            if e.to_string().contains("nonce") {
                                m.nonce_binding_failures += 1;
                            }
                            m.coherence_check_failures += 1;

                            continue;
                        }
                    }

                    if compression_enabled && bundle.witness_reports.len() > compression_threshold {
                        if let Err(e) = bundle.compress() {
                            warn!("Bundle compression failed: {}", e);
                        }
                    }

                    {
                        let mut pending = pending_bundles.write().unwrap();
                        pending.push_back(bundle);
                    }

                    {
                        let mut sets = active_sets.write().unwrap();
                        sets.remove(&beacon_hash);
                    }
                }
            }
        });

        Ok(())
    }

    async fn start_daily_anchor_generator(&self) -> PoCResult<()> {
        let daily_bundles = self.daily_bundles.clone();
        let status = self.status.clone();
        let config = self.config.clone();
        let address = self.address;
        let keypair = self.keypair.clone();
        let daily_anchor_sender = self.daily_anchor_sender.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(
                config.daily_anchor_interval_hours * 3600,
            ));

            loop {
                interval.tick().await;

                let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
                let epoch = Timestamp::now().as_secs() / 3600;

                let bundles = {
                    let daily = daily_bundles.read().unwrap();
                    daily.get(&today).cloned().unwrap_or_default()
                };

                if !bundles.is_empty() {
                    info!(
                        "Generating daily evidence root for {} with {} bundles (aggregator {})",
                        today,
                        bundles.len(),
                        address
                    );

                    let bundle_hashes: Vec<Vec<u8>> =
                        bundles.iter().map(|b| b.bundle_id.to_vec()).collect();

                    let merkle_tree = ego_core::crypto::MerkleTree::build(bundle_hashes);
                    let evidence_root = merkle_tree.root_hash().unwrap_or(Hash::new([0u8; 32]));

                    let mut daily_root = DailyEvidenceRoot::new(
                        evidence_root,
                        bundles.len() as u32,
                        today.clone(),
                        epoch,
                        address,
                    );

                    if let Err(e) = daily_root.sign(&keypair) {
                        error!("Failed to sign daily evidence root: {}", e);
                        continue;
                    }

                    if let Some(ref sender) = daily_anchor_sender {
                        if let Err(e) = sender.send(daily_root.clone()) {
                            error!("Failed to send daily anchor: {}", e);
                        } else {
                            info!(
                                "✅ Daily evidence root for {}: {} (aggregator {})",
                                today, evidence_root, address
                            );
                        }
                    }

                    {
                        let mut status = status.write().unwrap();
                        status.last_anchor_time = Some(Timestamp::now());
                    }
                }
            }
        });

        Ok(())
    }

    async fn start_density_monitor(&self) -> PoCResult<()> {
        let daily_bundles = self.daily_bundles.clone();
        let density_event_sender = self.density_event_sender.clone();
        let address = self.address;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(3600));

            loop {
                interval.tick().await;

                let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
                let epoch = Timestamp::now().as_secs() / 3600;

                let bundles = {
                    let daily = daily_bundles.read().unwrap();
                    daily.get(&today).cloned().unwrap_or_default()
                };

                if bundles.is_empty() {
                    continue;
                }

                let mut h3_device_counts: HashMap<String, Vec<Address>> = HashMap::new();

                for bundle in &bundles {
                    let h3_cell = bundle.beacon_event.h3_cell.clone();

                    if bundle.get_ldm_penalty() > 0.1 {

                        for report in &bundle.witness_reports {
                            h3_device_counts
                                .entry(h3_cell.clone())
                                .or_insert_with(Vec::new)
                                .push(report.witness_id);
                        }
                    }
                }

                for (h3_cell, devices) in h3_device_counts {
                    let device_count = devices.len() as u32;

                    if device_count > 1 {

                        let ldm = (1.0 - 0.10 * (device_count as f64 - 1.0)).max(0.40);

                        let device_hashes: Vec<Vec<u8>> = devices
                            .iter()
                            .map(|addr| addr.as_bytes().to_vec())
                            .collect();
                        let merkle_tree = ego_core::crypto::MerkleTree::build(device_hashes);
                        let evidence_root = merkle_tree.root_hash().unwrap_or(Hash::new([0u8; 32]));

                        for device_id in devices {
                            let density_event = DensityEvent::new(
                                device_id,
                                h3_cell.clone(),
                                device_count,
                                ldm,
                                evidence_root,
                                epoch,
                            );

                            if let Some(ref sender) = density_event_sender {
                                if let Err(e) = sender.send(density_event) {
                                    error!("Failed to send density event: {}", e);
                                } else {
                                    debug!(
                                        "Emitted DensityEvent for {} devices in cell {} (LDM: {:.2})",
                                        device_count, h3_cell, ldm
                                    );
                                }
                            }
                        }
                    }
                }
            }
        });

        Ok(())
    }

    async fn start_cleanup_task(&self) -> PoCResult<()> {
        let rate_limiter = self.rate_limiter.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(300));

            loop {
                interval.tick().await;
                rate_limiter.cleanup_old_buckets(600);
                debug!("Cleaned up old rate limit buckets");
            }
        });

        Ok(())
    }

    async fn flush_buffered_data(&self) -> PoCResult<()> {
        let buffered = self.cellular_safe_mode_manager.get_buffered_data();

        if buffered.is_empty() {
            return Ok(());
        }

        info!("Flushing {} buffered items over Wi-Fi", buffered.len());

        let total_bytes: usize = buffered.iter().map(|d| d.len()).sum();

        self.cellular_safe_mode_manager.record_wifi_usage(total_bytes, buffered.len());

        info!("✅ Flushed {} bytes in {} items over Wi-Fi", total_bytes, buffered.len());

        Ok(())
    }

    async fn process_all_witness_sets(&mut self) -> PoCResult<()> {
        let witness_sets: Vec<(Hash, WitnessSet)> = {
            let mut sets = self.active_witness_sets.write().unwrap();
            let collected: Vec<_> = sets.drain().collect();
            collected
        };

        for (beacon_hash, witness_set) in witness_sets {
            if witness_set.witness_count() >= self.config.min_witnesses {
                if let Ok(Some(bundle)) = self.create_poc_bundle(beacon_hash).await {
                    let mut pending = self.pending_bundles.write().unwrap();
                    pending.push_back(bundle);
                }
            }
        }

        Ok(())
    }

    async fn submit_pending_bundles(&mut self) -> PoCResult<()> {
        let bundles: Vec<PoCBundle> = {
            let mut pending = self.pending_bundles.write().unwrap();
            pending.drain(..).collect()
        };

        for bundle in bundles {
            let event = bundle.create_poc_event(self.get_current_epoch_impl());
            self.submit_poc_event(event).await?;
        }

        Ok(())
    }

    fn validate_config(&self) -> PoCResult<()> {
        if self.coverage_region.is_empty() {
            return Err(PoCError::ConfigError(
                "No coverage region specified".to_string(),
            ));
        }

        if self.config.min_witnesses == 0 {
            return Err(PoCError::ConfigError(
                "Minimum witnesses must be > 0".to_string(),
            ));
        }

        if self.config.max_witnesses < self.config.min_witnesses {
            return Err(PoCError::ConfigError(
                "Maximum witnesses must be >= minimum witnesses".to_string(),
            ));
        }

        if self.config.witness_collection_window_ms < 10_000 {
            return Err(PoCError::ConfigError(
                "Witness collection window too short".to_string(),
            ));
        }

        Ok(())
    }

    fn get_current_epoch_impl(&self) -> u64 {
        Timestamp::now().as_secs() / 3600
    }

    fn update_metrics_after_beacon(&self) {
        let mut metrics = self.metrics.write().unwrap();
        let mut status = self.status.write().unwrap();

        metrics.total_beacon_announcements += 1;
        status.processed_beacons += 1;

        metrics.last_updated = Timestamp::now();
    }

    fn update_metrics_after_witness(&self, valid: bool) {
        let mut metrics = self.metrics.write().unwrap();
        let mut status = self.status.write().unwrap();

        metrics.total_witness_reports += 1;
        status.processed_witnesses += 1;

        if valid {
            metrics.valid_witness_sets += 1;
        } else {
            metrics.invalid_witness_sets += 1;
        }

        metrics.last_updated = Timestamp::now();
    }

    fn update_metrics_after_bundle(&self, bundle: &PoCBundle) {
        let mut metrics = self.metrics.write().unwrap();
        let mut status = self.status.write().unwrap();

        metrics.bundles_created += 1;
        status.created_bundles += 1;
        status.last_bundle_time = Some(Timestamp::now());

        let total_witnesses = metrics.avg_witnesses_per_beacon
            * (metrics.bundles_created - 1) as f32
            + bundle.witness_reports.len() as f32;
        metrics.avg_witnesses_per_beacon = total_witnesses / metrics.bundles_created as f32;

        if let Some(ref compression_info) = bundle.compression_info {
            let total_ratio = metrics.compression_ratio * (metrics.bundles_created - 1) as f32
                + compression_info.compression_ratio;
            metrics.compression_ratio = total_ratio / metrics.bundles_created as f32;
        }

        let n = metrics.bundles_created as f64;
        metrics.avg_path_loss_rmse = (metrics.avg_path_loss_rmse * (n - 1.0) + bundle.get_path_loss_rmse()) / n;
        metrics.avg_diversity_score = (metrics.avg_diversity_score * (n - 1.0) + bundle.get_diversity_score()) / n;
        metrics.avg_nonce_binding_fraction = (metrics.avg_nonce_binding_fraction * (n - 1.0) + bundle.get_nonce_binding_fraction()) / n;

        if bundle.get_ldm_penalty() > 0.0 {
            metrics.density_penalties_applied += 1;
        }

        metrics.last_updated = Timestamp::now();
    }

    fn classify_validation_error(error: &PoCError) -> PoCFraudType {
        let error_str = error.to_string();

        if error_str.contains("Path-loss") || error_str.contains("RMSE") {
            PoCFraudType::PathLossMismatch
        } else if error_str.contains("diversity") || error_str.contains("H3 cell") || error_str.contains("account") {
            PoCFraudType::InsufficientDiversity
        } else if error_str.contains("nonce") || error_str.contains("binding") {
            PoCFraudType::NonceBindingFailure
        } else if error_str.contains("replay") || error_str.contains("duplicate") {
            PoCFraudType::ReplayAttack
        } else if error_str.contains("geometry") || error_str.contains("coherence") {
            PoCFraudType::InvalidGeometry
        } else {
            PoCFraudType::InvalidWitnessSet
        }
    }
}

impl Aggregator for AggregatorNode {
    fn aggregator_id(&self) -> Address {
        self.address
    }

    fn is_active(&self) -> bool {
        self.status.read().unwrap().is_active
    }

    fn coverage_region(&self) -> Vec<String> {
        self.coverage_region.clone()
    }

    async fn process_beacon_announcement(
        &mut self,
        announcement: BeaconAnnouncement,
    ) -> PoCResult<()> {
        debug!(
            "Processing beacon announcement from {} (aggregator {})",
            announcement.beacon_id, self.address
        );

        let announcement_size = std::mem::size_of_val(&announcement);
        if !self.rate_limiter.check_rate_limit(announcement.beacon_id, announcement_size) {
            let mut metrics = self.metrics.write().unwrap();
            metrics.dos_rate_limit_hits += 1;
            warn!("Rate limit exceeded for beacon {}", announcement.beacon_id);
            return Err(PoCError::NetworkError("Rate limit exceeded".to_string()));
        }

        if !self
            .coverage_region
            .contains(&announcement.location.h3_index)
        {
            debug!("Beacon not in coverage region, skipping");
            return Ok(());
        }

        announcement.validate()?;

        let beacon_hash = Hash::new({
            let sig_bytes = announcement.signature.as_bytes();
            let mut hash_bytes = [0u8; 32];
            let len = sig_bytes.len().min(32);
            hash_bytes[..len].copy_from_slice(&sig_bytes[..len]);
            hash_bytes
        });
        let witness_set = WitnessSet::new(
            announcement,
            self.config.witness_collection_window_ms,
            Timestamp::now().as_millis(),
        );

        {
            let mut sets = self.active_witness_sets.write().unwrap();
            sets.insert(beacon_hash, witness_set);
        }

        self.update_metrics_after_beacon();

        info!(
            "✅ Started witness collection for beacon {} (aggregator {})",
            beacon_hash, self.address
        );
        Ok(())
    }

    async fn process_witness_report(&mut self, report: WitnessReport) -> PoCResult<()> {
        debug!(
            "Processing witness report from {} for beacon {} (aggregator {})",
            report.witness_id, report.beacon_id, self.address
        );

        let report_size = std::mem::size_of_val(&report);
        if !self.rate_limiter.check_rate_limit(report.witness_id, report_size) {
            let mut metrics = self.metrics.write().unwrap();
            metrics.dos_rate_limit_hits += 1;
            warn!("Rate limit exceeded for witness {}", report.witness_id);
            return Err(PoCError::NetworkError("Rate limit exceeded".to_string()));
        }

        if !self.drs_quota_manager.can_publish(report.witness_id) {
            warn!("Witness {} failed DRS quota check", report.witness_id);
            return Err(PoCError::NetworkError("Quota exceeded".to_string()));
        }

        report.validate()?;

        let beacon_hash = {
            let sets = self.active_witness_sets.read().unwrap();
            sets.iter()
                .find(|(_, set)| set.beacon_announcement.beacon_id == report.beacon_id)
                .map(|(hash, _)| *hash)
        };

        let beacon_hash = match beacon_hash {
            Some(hash) => hash,
            None => {
                debug!("No matching beacon found for witness report");
                return Ok(());
            }
        };

        let mut valid = false;
        {
            let mut sets = self.active_witness_sets.write().unwrap();
            if let Some(witness_set) = sets.get_mut(&beacon_hash) {
                valid = witness_set.add_witness_report(report.clone());

                if valid {
                    debug!(
                        "Added witness report to set, now has {} witnesses",
                        witness_set.witness_count()
                    );

                    if witness_set.witness_count() >= self.config.max_witnesses {
                        witness_set.is_complete = true;
                        info!(
                            "Witness set for beacon {} complete with {} witnesses",
                            beacon_hash,
                            witness_set.witness_count()
                        );
                    }
                } else {
                    debug!("Witness report was rejected (duplicate or invalid)");
                }
            }
        }

        self.update_metrics_after_witness(valid);

        if valid {
            info!(
                "✅ Added witness report from {} for beacon {} (aggregator {})",
                report.witness_id, report.beacon_id, self.address
            );
        }

        Ok(())
    }

    async fn create_poc_bundle(&mut self, beacon_hash: Hash) -> PoCResult<Option<PoCBundle>> {
        debug!(
            "Creating PoC bundle for beacon {} (aggregator {})",
            beacon_hash, self.address
        );

        let witness_set = {
            let sets = self.active_witness_sets.read().unwrap();
            sets.get(&beacon_hash).cloned()
        };

        let witness_set = match witness_set {
            Some(set) => set,
            None => {
                warn!("Witness set not found for beacon {}", beacon_hash);
                return Ok(None);
            }
        };

        if witness_set.witness_count() < self.config.min_witnesses {
            return Err(PoCError::InsufficientWitnesses {
                got: witness_set.witness_count(),
                min: self.config.min_witnesses,
            });
        }

        let current_epoch = self.get_current_epoch();
        let epoch_config = self.get_epoch_config_guard();
        let validation_result = validate_poc_bundle_with_epoch_config(
            &witness_set.witness_reports,
            &witness_set.beacon_announcement,
            &epoch_config,
            current_epoch,
        )?;
        drop(epoch_config);

        if !validation_result.valid {
            warn!(
                "Bundle validation failed: {}",
                validation_result.errors.join("; ")
            );

            let mut metrics = self.metrics.write().unwrap();
            for error in &validation_result.errors {
                if error.contains("Path-loss") {
                    metrics.path_loss_fit_failures += 1;
                } else if error.contains("nonce") {
                    metrics.nonce_binding_failures += 1;
                }
            }
            metrics.coherence_check_failures += 1;

            return Err(PoCError::ValidationFailed(
                validation_result.errors.join("; ")
            ));
        }

        let mut bundle = PoCBundle::new(
            self.address,
            witness_set.beacon_announcement.clone(),
            witness_set.witness_reports.clone(),
        );

        bundle.sign(&self.keypair)?;
        bundle.validate()?;

        if !bundle.meets_quality_threshold(self.quality_threshold) {
            return Err(PoCError::ValidationFailed(format!(
                "Bundle quality {:.3} below threshold {:.3}",
                bundle.coverage_quality.quality_score, self.quality_threshold
            )));
        }

        let bundle_size = std::mem::size_of_val(&bundle);
        if !self.rate_limiter.check_bundle_size(bundle_size) {
            warn!("Bundle size {} exceeds limit", bundle_size);
            return Err(PoCError::ValidationFailed("Bundle too large".to_string()));
        }

        if self.compression_enabled && bundle.witness_reports.len() > self.compression_threshold {
            bundle.compress()?;
        }

        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        {
            let mut daily = self.daily_bundles.write().unwrap();
            daily
                .entry(today)
                .or_insert_with(Vec::new)
                .push(bundle.clone());
        }

        self.update_metrics_after_bundle(&bundle);

        info!(
            "✅ Created PoC bundle {} for beacon {} with {} witnesses (aggregator {})",
            bundle.bundle_id,
            beacon_hash,
            bundle.witness_reports.len(),
            self.address
        );

        Ok(Some(bundle))
    }

    async fn submit_poc_event(&mut self, event: PoCEvent) -> PoCResult<()> {
        debug!(
            "Submitting PoC event for beacon {} to shard (aggregator {})",
            event.beacon_hash, self.address
        );

        let event_size = std::mem::size_of_val(&event);
        if !self.cellular_safe_mode_manager.can_send_over_cellular(event_size) {
            debug!("Buffering PoC event for Wi-Fi upload (size: {} bytes)", event_size);

            let event_bytes = bincode::encode_to_vec(&event, bincode::config::standard())
                .map_err(|e| PoCError::NetworkError(format!("Serialization failed: {}", e)))?;

            self.cellular_safe_mode_manager.buffer_for_wifi(event_bytes);

            info!(
                "📱 Buffered PoC event for beacon {} ({} bytes) - waiting for Wi-Fi",
                event.beacon_hash, event_size
            );

            return Ok(());
        }

        if self.cellular_safe_mode_manager.is_enabled() {
            self.cellular_safe_mode_manager.record_cellular_usage(event_size);
        }

        if let Some(ref sender) = self.event_sender {
            sender
                .send(event.clone())
                .map_err(|e| PoCError::NetworkError(format!("Failed to send PoC event: {}", e)))?;
        }

        {
            let mut metrics = self.metrics.write().unwrap();
            let mut status = self.status.write().unwrap();

            metrics.events_submitted += 1;
            status.submitted_events += 1;
            metrics.last_updated = Timestamp::now();
        }

        info!(
            "✅ Submitted PoC event for beacon {} with quality {:.3}, RMSE {:.2} dB, diversity {:.2}, nonce {:.2}% (aggregator {})",
            event.beacon_hash,
            event.quality_score,
            event.path_loss_rmse,
            event.diversity_score,
            event.nonce_binding_fraction * 100.0,
            self.address
        );

        Ok(())
    }

    async fn generate_daily_anchor(&mut self) -> PoCResult<Hash> {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let epoch = self.get_current_epoch();

        let bundles = {
            let daily = self.daily_bundles.read().unwrap();
            daily.get(&today).cloned().unwrap_or_default()
        };

        if bundles.is_empty() {
            return Ok(Hash::new([0u8; 32]));
        }

        let bundle_hashes: Vec<Vec<u8>> = bundles.iter().map(|b| b.bundle_id.to_vec()).collect();

        let merkle_tree = ego_core::crypto::MerkleTree::build(bundle_hashes);
        let evidence_root = merkle_tree.root_hash().unwrap_or(Hash::new([0u8; 32]));

        let mut daily_root = DailyEvidenceRoot::new(
            evidence_root,
            bundles.len() as u32,
            today.clone(),
            epoch,
            self.address,
        );

        daily_root.sign(&self.keypair)?;

        if let Some(ref sender) = self.daily_anchor_sender {
            sender.send(daily_root).map_err(|e| {
                PoCError::NetworkError(format!("Failed to send daily anchor: {}", e))
            })?;
        }

        {
            let mut status = self.status.write().unwrap();
            status.last_anchor_time = Some(Timestamp::now());
        }

        info!(
            "Generated daily evidence root for {}: {} with {} bundles (aggregator {})",
            today,
            evidence_root,
            bundles.len(),
            self.address
        );

        Ok(evidence_root)
    }
}

impl EpochConfigProvider for AggregatorNode {
    fn get_epoch_config(&self) -> &EpochConfig {

        unimplemented!("Use get_epoch_config_guard() method instead")
    }
}

impl AggregatorNode {

    pub fn get_epoch_config_guard(&self) -> std::sync::RwLockReadGuard<'_, EpochConfig> {
        self.epoch_config.read().unwrap()
    }

    /// Update epoch configuration
    pub fn update_epoch_config(&self, epoch_config: EpochConfig) {
        *self.epoch_config.write().unwrap() = epoch_config;
    }

    /// Get current epoch number based on timestamp
    pub fn get_current_epoch(&self) -> u64 {
        Timestamp::now().as_secs() / 3600 // 1-hour epochs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::KeyPair;

    fn create_test_aggregator() -> AggregatorNode {
        let keypair = KeyPair::generate();
        let coverage_region = vec!["87283472bffffff".to_string()];

        AggregatorNode::new(AggregatorConfig::default(), keypair, coverage_region)
    }

    #[tokio::test]
    async fn test_aggregator_creation() {
        let aggregator = create_test_aggregator();
        assert!(!aggregator.is_active());
        assert_eq!(aggregator.coverage_region().len(), 1);
        assert_eq!(aggregator.quality_threshold, MIN_QUALITY_SCORE);
    }

    #[tokio::test]
    async fn test_aggregator_start_stop() {
        let mut aggregator = create_test_aggregator();

        assert!(aggregator.start().await.is_ok());
        assert!(aggregator.get_status().is_active);

        assert!(aggregator.stop().await.is_ok());
        assert!(!aggregator.get_status().is_active);
    }

    #[test]
    fn test_configuration_validation() {
        let mut aggregator = create_test_aggregator();

        assert!(aggregator.validate_config().is_ok());

        aggregator.config.min_witnesses = 0;
        assert!(aggregator.validate_config().is_err());
    }

    #[test]
    fn test_cellular_safe_mode() {
        let mut aggregator = create_test_aggregator();

        assert!(!aggregator.cellular_safe_mode);
        assert!(!aggregator.cellular_safe_mode_manager.is_enabled());

        aggregator.set_cellular_safe_mode(true);
        assert!(aggregator.cellular_safe_mode);
        assert!(aggregator.cellular_safe_mode_manager.is_enabled());
        assert!(aggregator.get_metrics().cellular_safe_mode_active);

        aggregator.set_cellular_safe_mode(false);
        assert!(!aggregator.cellular_safe_mode);
        assert!(!aggregator.cellular_safe_mode_manager.is_enabled());
        assert!(!aggregator.get_metrics().cellular_safe_mode_active);
    }

    #[test]
    fn test_quality_threshold() {
        let mut aggregator = create_test_aggregator();

        aggregator.set_quality_threshold(0.7);
        assert_eq!(aggregator.quality_threshold, 0.7);

        // Test clamping
        aggregator.set_quality_threshold(1.5);
        assert_eq!(aggregator.quality_threshold, 1.0);

        aggregator.set_quality_threshold(-0.5);
        assert_eq!(aggregator.quality_threshold, 0.0);
    }

    #[test]
    fn test_drs_quota_management() {
        let aggregator = create_test_aggregator();
        let node = Address::new([1u8; 20]);

        // Update quota
        aggregator.update_node_drs_score(node, 0.9);

        // Check quota was updated
        let quota = aggregator.drs_quota_manager.get_quota(node);
        assert!(quota.is_some());
        let quota = quota.unwrap();
        assert_eq!(quota.drs_score, 0.9);
        assert_eq!(quota.quota_band, crate::aggregator::dos_limits::QuotaBand::High);
    }

    #[test]
    fn test_rate_limiter_integration() {
        let aggregator = create_test_aggregator();
        let peer = Address::new([1u8; 20]);

        // Check initial state
        let stats = aggregator.get_rate_limit_stats();
        assert_eq!(stats.total_messages, 0);

        // Simulate rate limiting
        for _ in 0..10 {
            aggregator.rate_limiter.check_rate_limit(peer, 1000);
        }

        let stats = aggregator.get_rate_limit_stats();
        assert!(stats.total_messages > 0);
    }

    #[test]
    fn test_cellular_stats() {
        let aggregator = create_test_aggregator();

        // Record usage
        aggregator.cellular_safe_mode_manager.record_cellular_usage(1000);
        aggregator.cellular_safe_mode_manager.record_wifi_usage(50_000, 5);

        let stats = aggregator.get_cellular_stats();
        assert_eq!(stats.cellular_bytes_used, 1_000);
        assert_eq!(stats.wifi_bytes_used, 50_000);
        assert_eq!(stats.bundles_uploaded_over_wifi, 5);
    }

    #[test]
    fn test_classify_validation_error() {
        use crate::FraudType;

        let error1 = PoCError::ValidationFailed("Path-loss RMSE exceeds threshold".to_string());
        assert!(matches!(
            AggregatorNode::classify_validation_error(&error1),
            PoCFraudType::PathLossMismatch
        ));

        let error2 = PoCError::ValidationFailed("Insufficient H3 cell diversity".to_string());
        assert!(matches!(
            AggregatorNode::classify_validation_error(&error2),
            PoCFraudType::InsufficientDiversity
        ));

        let error3 = PoCError::ValidationFailed("Insufficient nonce binding".to_string());
        assert!(matches!(
            AggregatorNode::classify_validation_error(&error3),
            PoCFraudType::NonceBindingFailure
        ));

        let error4 = PoCError::FraudDetected {
            fraud_type: FraudType::ReplayAttack,
            details: "Nonce replay detected".to_string(),
        };
        assert!(matches!(
            AggregatorNode::classify_validation_error(&error4),
            PoCFraudType::ReplayAttack
        ));
    }

    #[test]
    fn test_whitepaper_metrics_initialization() {
        let aggregator = create_test_aggregator();
        let metrics = aggregator.get_metrics();

        assert_eq!(metrics.path_loss_fit_failures, 0);
        assert_eq!(metrics.nonce_binding_failures, 0);
        assert_eq!(metrics.density_penalties_applied, 0);
        assert_eq!(metrics.dos_rate_limit_hits, 0);
        assert_eq!(metrics.avg_path_loss_rmse, 0.0);
        assert_eq!(metrics.avg_diversity_score, 0.0);
        assert_eq!(metrics.avg_nonce_binding_fraction, 0.0);
        assert!(!metrics.cellular_safe_mode_active);
    }
}
