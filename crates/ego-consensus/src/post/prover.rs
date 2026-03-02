use super::{
    PartitionProof, PoStEvent, PoStMetrics, PoStProof, PoStProvider, PoStResult, PoStWindow,
    WindowSchedule,
};
use crate::error::{PoCError, PoCResult};
use ego_core::{Address, Hash, KeyPair, Timestamp};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use tokio::time::{Duration, interval};
use tracing::{debug, info, warn};

pub struct PoStProver {
    keypair: Arc<KeyPair>,
    address: Address,
    total_sectors: u32,
    windows_per_day: u32,
    active_windows: Arc<RwLock<HashMap<u64, PoStWindow>>>,
    completed_proofs: Arc<RwLock<VecDeque<PoStProof>>>,
    proving_metrics: Arc<RwLock<PoStMetrics>>,
    sector_partitions: HashMap<u64, Vec<u64>>,
    gpu_available: bool,
}

impl PoStProver {
    pub fn new(
        keypair: KeyPair,
        total_sectors: u32,
        windows_per_day: u32,
        gpu_available: bool,
    ) -> Self {
        let address = Address::from_public_key(&keypair.public_key());
        let sector_partitions = Self::create_sector_partitions(total_sectors, windows_per_day);

        Self {
            keypair: Arc::new(keypair),
            address,
            total_sectors,
            windows_per_day,
            active_windows: Arc::new(RwLock::new(HashMap::new())),
            completed_proofs: Arc::new(RwLock::new(VecDeque::new())),
            proving_metrics: Arc::new(RwLock::new(PoStMetrics::default())),
            sector_partitions,
            gpu_available,
        }
    }

    pub async fn start(&mut self) -> PoCResult<()> {
        info!(
            "Starting PoSt prover {} with {} sectors across {} windows/day",
            self.address, self.total_sectors, self.windows_per_day
        );

        self.start_window_scheduler().await?;
        self.start_proving_engine().await?;
        self.start_metrics_collector().await?;

        info!("✅ PoSt prover {} started successfully", self.address);
        Ok(())
    }

    pub async fn stop(&mut self) -> PoCResult<()> {
        info!("Stopping PoSt prover {}", self.address);

        self.complete_active_windows().await?;

        info!("✅ PoSt prover {} stopped", self.address);
        Ok(())
    }

    async fn start_window_scheduler(&self) -> PoCResult<()> {
        let active_windows = self.active_windows.clone();
        let address = self.address;
        let total_sectors = self.total_sectors;
        let windows_per_day = self.windows_per_day;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(1800));

            loop {
                interval.tick().await;

                let current_epoch = Timestamp::now().as_secs() / 3600;
                let schedule = WindowSchedule::generate_deterministic_schedule(
                    address,
                    current_epoch,
                    total_sectors,
                    windows_per_day,
                );

                for window in schedule.assigned_windows {
                    if window.is_active() {
                        debug!(
                            "Scheduling PoSt window {} for epoch {} (prover {})",
                            window.window_id, window.epoch, address
                        );

                        let mut windows = active_windows.write().unwrap();
                        windows.insert(window.window_id, window);
                    }
                }

                let expired_windows: Vec<u64> = {
                    let windows = active_windows.read().unwrap();
                    windows
                        .iter()
                        .filter(|(_, window)| window.is_expired())
                        .map(|(window_id, _)| *window_id)
                        .collect()
                };

                for window_id in expired_windows {
                    debug!("Window {} expired (prover {})", window_id, address);
                    let mut windows = active_windows.write().unwrap();
                    windows.remove(&window_id);
                }
            }
        });

        Ok(())
    }

    async fn start_proving_engine(&self) -> PoCResult<()> {
        let active_windows = self.active_windows.clone();
        let completed_proofs = self.completed_proofs.clone();
        let proving_metrics = self.proving_metrics.clone();
        let sector_partitions = self.sector_partitions.clone();
        let address = self.address;
        let gpu_available = self.gpu_available;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(300));

            loop {
                interval.tick().await;

                let windows_to_prove: Vec<PoStWindow> = {
                    let windows = active_windows.read().unwrap();
                    windows
                        .values()
                        .filter(|window| window.is_active() && window.submitted_proofs.is_empty())
                        .cloned()
                        .collect()
                };

                for window in windows_to_prove {
                    debug!(
                        "Generating PoSt proof for window {} (prover {})",
                        window.window_id, address
                    );

                    let start_time = Timestamp::now();

                    match Self::generate_window_proof(&window, &sector_partitions, gpu_available)
                        .await
                    {
                        Ok(proof) => {
                            let latency_ms = Timestamp::now().as_millis() - start_time.as_millis();

                            {
                                let mut proofs = completed_proofs.write().unwrap();
                                proofs.push_back(proof);

                                if proofs.len() > 100 {
                                    proofs.pop_front();
                                }
                            }

                            {
                                let mut metrics = proving_metrics.write().unwrap();
                                metrics.windows_proven += 1;
                                metrics.avg_latency_ms = (metrics.avg_latency_ms
                                    * (metrics.windows_proven - 1) as f64
                                    + latency_ms as f64)
                                    / metrics.windows_proven as f64;
                                metrics.last_updated = Timestamp::now();
                            }

                            {
                                let mut windows = active_windows.write().unwrap();
                                if let Some(window) = windows.get_mut(&window.window_id) {
                                    window.submitted_proofs.push(Hash::new([1u8; 32]));
                                }
                            }

                            info!(
                                "✅ Generated PoSt proof for window {} in {} ms (prover {})",
                                window.window_id, latency_ms, address
                            );
                        }
                        Err(e) => {
                            warn!(
                                "Failed to generate PoSt proof for window {}: {}",
                                window.window_id, e
                            );

                            let mut metrics = proving_metrics.write().unwrap();
                            metrics.windows_missed += 1;
                            metrics.last_updated = Timestamp::now();
                        }
                    }
                }
            }
        });

        Ok(())
    }

    async fn start_metrics_collector(&self) -> PoCResult<()> {
        let proving_metrics = self.proving_metrics.clone();
        let completed_proofs = self.completed_proofs.clone();
        let address = self.address;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(300));

            loop {
                interval.tick().await;

                let latencies: Vec<u64> = {
                    let proofs = completed_proofs.read().unwrap();
                    proofs.iter().map(|_| 5000u64).collect()
                };

                if !latencies.is_empty() {
                    let mut sorted_latencies = latencies.clone();
                    sorted_latencies.sort_unstable();

                    let p50_idx = sorted_latencies.len() / 2;
                    let p95_idx = (sorted_latencies.len() as f64 * 0.95) as usize;

                    let p50 = sorted_latencies.get(p50_idx).copied().unwrap_or(0);
                    let p95 = sorted_latencies.get(p95_idx).copied().unwrap_or(0);

                    let mut metrics = proving_metrics.write().unwrap();
                    metrics.p50_latency_ms = p50;
                    metrics.p95_latency_ms = p95;
                    metrics.last_updated = Timestamp::now();

                    debug!(
                        "Updated PoSt metrics: P50={}ms, P95={}ms (prover {})",
                        p50, p95, address
                    );
                }
            }
        });

        Ok(())
    }

    async fn generate_window_proof(
        window: &PoStWindow,
        sector_partitions: &HashMap<u64, Vec<u64>>,
        gpu_available: bool,
    ) -> PoCResult<PoStProof> {
        let mut partition_proofs = Vec::new();

        for &partition_id in &window.required_partitions {
            if let Some(sector_ids) = sector_partitions.get(&partition_id) {
                let challenges =
                    window.generate_partition_challenges(partition_id, sector_ids.len() as u32);
                let responses =
                    Self::compute_partition_responses(sector_ids, &challenges, gpu_available)
                        .await?;

                let partition_proof = PartitionProof {
                    partition_id,
                    sector_ids: sector_ids.clone(),
                    challenges,
                    responses,
                };

                partition_proofs.push(partition_proof);
            }
        }

        let proof = PoStProof::new(
            Address::new([0u8; 20]),
            window.epoch,
            window.window_id,
            partition_proofs,
            window.challenge_seed,
        );

        Ok(proof)
    }

    async fn compute_partition_responses(
        sector_ids: &[u64],
        challenges: &[u64],
        gpu_available: bool,
    ) -> PoCResult<Vec<[u8; 32]>> {
        let mut responses = Vec::new();

        for &challenge in challenges {
            let response = Self::compute_challenge_response(sector_ids, challenge).await?;
            responses.push(response);
        }

        let proving_delay = if gpu_available {
            challenges.len() as u64 * 10
        } else {
            challenges.len() as u64 * 50
        };

        tokio::time::sleep(Duration::from_millis(proving_delay.min(5000))).await;

        Ok(responses)
    }

    // FIX: collect temporaries before building the &[u8] slice —
    // to_le_bytes() returns [u8; N] which is a temporary; we must keep
    // the owned arrays alive for the duration of the hash_multiple call.
    async fn compute_challenge_response(sector_ids: &[u64], challenge: u64) -> PoCResult<[u8; 32]> {
        use ego_core::crypto::hash_multiple;

        let challenge_bytes = challenge.to_le_bytes();
        let sector_bytes: Vec<[u8; 8]> = sector_ids.iter().map(|s| s.to_le_bytes()).collect();

        let mut inputs: Vec<&[u8]> = vec![challenge_bytes.as_slice()];
        for b in &sector_bytes {
            inputs.push(b.as_slice());
        }

        let response_hash = hash_multiple(&inputs);
        let bytes = response_hash.as_bytes();
        bytes[..32].try_into().map_err(|_| {
            PoCError::InternalError("Hash slice conversion failed".to_string())
        })
    }

    fn create_sector_partitions(
        total_sectors: u32,
        windows_per_day: u32,
    ) -> HashMap<u64, Vec<u64>> {
        let mut partitions = HashMap::new();
        let base = total_sectors / windows_per_day;
        let remainder = total_sectors % windows_per_day;
        let mut sector_cursor = 0u32;

        for partition_idx in 0..windows_per_day {
            // Distribute remainder sectors one each to the first `remainder` partitions
            let count = base + if partition_idx < remainder { 1 } else { 0 };
            let sector_ids: Vec<u64> = (sector_cursor..sector_cursor + count).map(|i| i as u64).collect();
            partitions.insert(partition_idx as u64, sector_ids);
            sector_cursor += count;
        }

        partitions
    }

    async fn complete_active_windows(&mut self) -> PoCResult<()> {
        let active_windows: Vec<PoStWindow> = {
            let mut windows = self.active_windows.write().unwrap();
            windows.drain().map(|(_, window)| window).collect()
        };

        for window in active_windows {
            if window.is_active() && window.submitted_proofs.is_empty() {
                warn!(
                    "Window {} was active but no proof submitted during shutdown",
                    window.window_id
                );

                let mut metrics = self.proving_metrics.write().unwrap();
                metrics.windows_missed += 1;
            }
        }

        Ok(())
    }
}

impl PoStProvider for PoStProver {
    fn provider_id(&self) -> Address {
        self.address
    }

    async fn generate_post_proof(&self, window: &PoStWindow) -> PoCResult<PoStProof> {
        debug!(
            "Generating PoSt proof for window {} (prover {})",
            window.window_id, self.address
        );

        if window.is_expired() {
            return Err(PoCError::TimeWindowViolation(
                "PoSt window expired".to_string(),
            ));
        }

        Self::generate_window_proof(window, &self.sector_partitions, self.gpu_available).await
    }

    async fn verify_post_proof(&self, proof: &PoStProof) -> PoCResult<bool> {
        debug!(
            "Verifying PoSt proof for window {} (prover {})",
            proof.window_id, self.address
        );

        proof.validate()?;

        let verification_time = if self.gpu_available { 1000 } else { 3000 };
        tokio::time::sleep(Duration::from_millis(verification_time)).await;

        for partition in &proof.partitions {
            if !self
                .verify_partition_proof(partition, &proof.challenge_seed)
                .await?
            {
                return Ok(false);
            }
        }

        Ok(true)
    }

    async fn get_window_assignment(&self, epoch: u64) -> PoCResult<WindowSchedule> {
        let schedule = WindowSchedule::generate_deterministic_schedule(
            self.address,
            epoch,
            self.total_sectors,
            self.windows_per_day,
        );

        Ok(schedule)
    }

    fn get_proving_metrics(&self) -> PoStMetrics {
        self.proving_metrics.read().unwrap().clone()
    }
}

impl PoStProver {
    async fn verify_partition_proof(
        &self,
        partition: &PartitionProof,
        _challenge_seed: &Hash,
    ) -> PoCResult<bool> {
        if partition.challenges.len() != partition.responses.len() {
            return Ok(false);
        }

        for (i, &challenge) in partition.challenges.iter().enumerate() {
            let expected_response =
                Self::compute_challenge_response(&partition.sector_ids, challenge).await?;
            if expected_response != partition.responses[i] {
                return Ok(false);
            }
        }

        Ok(true)
    }

    pub async fn handle_missed_window(&mut self, window_id: u64) -> PoCResult<()> {
        warn!(
            "Handling missed PoSt window {} (prover {})",
            window_id, self.address
        );

        {
            let mut metrics = self.proving_metrics.write().unwrap();
            metrics.windows_missed += 1;
            metrics.last_updated = Timestamp::now();
        }

        {
            let mut windows = self.active_windows.write().unwrap();
            windows.remove(&window_id);
        }

        Ok(())
    }

    pub async fn submit_post_event(
        &self,
        window: &PoStWindow,
        result: PoStResult,
        latency_ms: u64,
    ) -> PoCResult<PoStEvent> {
        let challenges_root = self.compute_challenges_root(window);
        let proof_hash = Hash::new([window.window_id as u8; 32]);

        let event = PoStEvent::new(
            self.address,
            window.epoch,
            window.window_id,
            window.required_partitions.clone(),
            challenges_root,
            proof_hash,
            result,
            latency_ms,
        );

        info!(
            "✅ Submitted PoSt event for window {} with latency {}ms (prover {})",
            window.window_id, latency_ms, self.address
        );

        Ok(event)
    }

    // FIX: same temporaries pattern — collect partition_id bytes before slicing.
    fn compute_challenges_root(&self, window: &PoStWindow) -> Hash {
        use ego_core::crypto::hash_multiple;

        let partition_bytes: Vec<[u8; 8]> = window
            .required_partitions
            .iter()
            .map(|p| p.to_le_bytes())
            .collect();

        let mut inputs: Vec<&[u8]> = vec![window.challenge_seed.as_bytes()];
        for b in &partition_bytes {
            inputs.push(b.as_slice());
        }

        hash_multiple(&inputs)
    }

    pub fn get_sector_utilization(&self) -> f64 {
        let active_sectors = self
            .sector_partitions
            .values()
            .map(|v| v.len())
            .sum::<usize>();
        active_sectors as f64 / self.total_sectors as f64
    }

    pub fn get_window_coverage(&self, epoch: u64) -> f64 {
        let schedule = WindowSchedule::generate_deterministic_schedule(
            self.address,
            epoch,
            self.total_sectors,
            self.windows_per_day,
        );

        let covered_partitions: usize = schedule
            .assigned_windows
            .iter()
            .map(|w| w.required_partitions.len())
            .sum();

        covered_partitions as f64 / self.total_sectors as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::KeyPair;

    #[tokio::test]
    async fn test_post_prover_creation() {
        let keypair = KeyPair::generate();
        let prover = PoStProver::new(keypair, 1000, 48, true);

        assert_eq!(prover.total_sectors, 1000);
        assert_eq!(prover.windows_per_day, 48);
        assert!(prover.gpu_available);
    }

    #[tokio::test]
    async fn test_window_assignment() {
        let keypair = KeyPair::generate();
        let prover = PoStProver::new(keypair, 1000, 48, true);

        let schedule = prover.get_window_assignment(100).await.unwrap();
        assert_eq!(schedule.assigned_windows.len(), 48);
        assert_eq!(schedule.epoch, 100);
    }

    #[tokio::test]
    async fn test_partition_proof_verification() {
        let keypair = KeyPair::generate();
        let prover = PoStProver::new(keypair, 1000, 48, true);

        let partition = PartitionProof {
            partition_id: 1,
            sector_ids: vec![1, 2, 3],
            challenges: vec![100, 200],
            responses: vec![
                PoStProver::compute_challenge_response(&[1, 2, 3], 100)
                    .await
                    .unwrap(),
                PoStProver::compute_challenge_response(&[1, 2, 3], 200)
                    .await
                    .unwrap(),
            ],
        };

        let is_valid = prover
            .verify_partition_proof(&partition, &Hash::new([1u8; 32]))
            .await
            .unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_sector_partitioning() {
        let partitions = PoStProver::create_sector_partitions(1000, 48);
        assert_eq!(partitions.len(), 48);

        let total_sectors: usize = partitions.values().map(|v| v.len()).sum();
        assert_eq!(total_sectors, 1000);
    }
}