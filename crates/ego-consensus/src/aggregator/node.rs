use super::{Aggregator, AggregatorMetrics, AggregatorStatus, PoCBundle, PoCEvent, WitnessSet};
use crate::beacon::BeaconAnnouncement;
use crate::config::AggregatorConfig;
use crate::error::{PoCError, PoCResult};
use crate::witness::WitnessReport;
use ego_core::{Address, Hash, KeyPair, Timestamp};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tokio::time::{Duration, interval};
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
    compression_enabled: bool,
    compression_threshold: usize,
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
            compression_enabled: config.compression_threshold_bytes > 0,
            compression_threshold: config.compression_threshold_bytes,
        }
    }

    pub async fn start(&mut self) -> PoCResult<()> {
        info!(
            "Starting aggregator node {} for regions: {:?}",
            self.address, self.coverage_region
        );

        self.validate_config()?;

        let (_beacon_sender, beacon_receiver) = mpsc::unbounded_channel();
        let (_witness_sender, witness_receiver) = mpsc::unbounded_channel();
        let (event_sender, _event_receiver) = mpsc::unbounded_channel();

        self.beacon_receiver = Some(beacon_receiver);
        self.witness_receiver = Some(witness_receiver);
        self.event_sender = Some(event_sender);

        self.start_witness_set_processor().await?;
        self.start_bundle_creator().await?;
        self.start_daily_anchor_generator().await?;

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

        {
            let mut status = self.status.write().unwrap();
            status.is_active = false;
        }

        self.beacon_receiver = None;
        self.witness_receiver = None;
        self.event_sender = None;

        info!("✅ Aggregator node {} stopped", self.address);
        Ok(())
    }

    pub fn get_status(&self) -> AggregatorStatus {
        self.status.read().unwrap().clone()
    }

    pub fn get_metrics(&self) -> AggregatorMetrics {
        self.metrics.read().unwrap().clone()
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

                    if let Err(e) = bundle.validate() {
                        warn!("Bundle validation failed: {}", e);
                        continue;
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

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(
                config.daily_anchor_interval_hours * 3600,
            ));

            loop {
                interval.tick().await;

                let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

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

                    info!(
                        "Daily evidence root for {}: {} (aggregator {})",
                        today, evidence_root, address
                    );

                    {
                        let mut status = status.write().unwrap();
                        status.last_anchor_time = Some(Timestamp::now());
                    }
                }
            }
        });

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
            let event = bundle.create_poc_event(self.get_current_epoch());
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

    fn get_current_epoch(&self) -> u64 {
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

        metrics.last_updated = Timestamp::now();
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

        let mut bundle = PoCBundle::new(
            self.address,
            witness_set.beacon_announcement.clone(),
            witness_set.witness_reports.clone(),
        );

        bundle.sign(&self.keypair)?;
        bundle.validate()?;

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
            "✅ Submitted PoC event for beacon {} with quality score {:.3} (aggregator {})",
            event.beacon_hash, event.quality_score, self.address
        );

        Ok(())
    }

    async fn generate_daily_anchor(&mut self) -> PoCResult<Hash> {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

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
}
