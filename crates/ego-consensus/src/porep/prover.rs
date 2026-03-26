use super::{
    PoRepChallenge, PoRepEvent, PoRepFraudEvidence, PoRepFraudType, PoRepProof, PoRepProvider,
    SealingJob, SealingStatus, SectorCommitment,
    persistence::{PoRepPersistence, PoRepRestoredState},
};
use crate::error::{PoCError, PoCResult};
use ego_core::{
    Address, Hash, Timestamp,
    block::{ProofEvent, ProofEventType},
    crypto::{KeyPair, hash_data, hash_multiple},
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tokio::time::{Duration, interval};
use tracing::{debug, info, warn, error};

pub struct PoRepProver {
    keypair: Arc<KeyPair>,
    address: Address,
    sector_size: u64,
    sealing_queue: Arc<RwLock<VecDeque<SealingJob>>>,
    active_sectors: Arc<RwLock<HashMap<u64, SectorState>>>,
    commitments: Arc<RwLock<HashMap<u64, SectorCommitment>>>,
    submitted_proofs: Arc<RwLock<HashSet<Hash>>>,
    proving_params: ProvingParams,
    gpu_available: bool,
    nvme_path: String,
    proof_event_sender: Option<mpsc::UnboundedSender<ProofEvent>>,
    fraud_event_sender: Option<mpsc::UnboundedSender<PoRepFraudEvidence>>,
    persistence: Arc<PoRepPersistence>,
}

#[derive(Debug, Clone)]
pub struct SectorState {
    pub sector_id: u64,
    pub replica_id: Hash,
    pub comm_d: Hash,
    pub comm_r: Hash,
    pub sealed_path: String,
    pub cache_path: String,
    pub deal_ids: Vec<Hash>,
    pub created_at: Timestamp,
    pub proof_count: u32,
    pub last_challenged_at: Option<Timestamp>,
}

#[derive(Debug, Clone)]
pub struct ProvingParams {
    pub porep_id: [u8; 32],
    pub sector_size: u64,
    pub partitions: u32,
    pub challenge_count: u32,
    pub params_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealingMetrics {
    pub sealing_queue_len: u32,
    pub sectors_active: u32,
    pub sectors_committed: u32,
    pub gpu_available: bool,
    pub proofs_submitted: u32,
    pub last_updated: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverConfig {
    pub sector_size: u64,
    pub gpu_available: bool,
    pub nvme_path: String,
    pub max_parallel_sealing: u32,
    pub challenge_window_ms: u64,
    pub params_version: u32,
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self {
            sector_size: 32 * 1024 * 1024 * 1024,
            gpu_available: false,
            nvme_path: "/tmp/ego-sectors".to_string(),
            max_parallel_sealing: 1,
            challenge_window_ms: 300_000,
            params_version: 1,
        }
    }
}

impl PoRepProver {
    pub fn new(keypair: KeyPair, config: ProverConfig) -> Self {
        let address = Address::from_public_key(&keypair.public_key());

        let partitions = (config.sector_size / (1024 * 1024 * 32)).max(1) as u32;

        let proving_params = ProvingParams {
            porep_id: Self::compute_porep_id(config.sector_size, config.params_version),
            sector_size: config.sector_size,
            partitions,
            challenge_count: 176,
            params_version: config.params_version,
        };

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let thread_id = std::thread::current().id();
        let unique_id = format!("porep_test_{}_{:?}", timestamp, thread_id);
        let temp_dir = std::env::temp_dir().join(unique_id);
        let temp_persistence = PoRepPersistence::new(&temp_dir, address)
            .unwrap_or_else(|e| panic!("Failed to create temporary persistence: {}", e));

        Self {
            keypair: Arc::new(keypair),
            address,
            sector_size: config.sector_size,
            sealing_queue: Arc::new(RwLock::new(VecDeque::new())),
            active_sectors: Arc::new(RwLock::new(HashMap::new())),
            commitments: Arc::new(RwLock::new(HashMap::new())),
            submitted_proofs: Arc::new(RwLock::new(HashSet::new())),
            proving_params,
            gpu_available: config.gpu_available,
            nvme_path: config.nvme_path,
            proof_event_sender: None,
            fraud_event_sender: None,
            persistence: Arc::new(temp_persistence),
        }
    }

    pub fn new_with_persistence<P: AsRef<Path>>(
        keypair: KeyPair,
        config: ProverConfig,
        db_path: P
    ) -> PoCResult<Self> {
        let address = Address::from_public_key(&keypair.public_key());

        let partitions = (config.sector_size / (1024 * 1024 * 32)).max(1) as u32;

        let proving_params = ProvingParams {
            porep_id: Self::compute_porep_id(config.sector_size, config.params_version),
            sector_size: config.sector_size,
            partitions,
            challenge_count: 176,
            params_version: config.params_version,
        };

        let persistence = PoRepPersistence::new(db_path, address)?;

        let restored_state = persistence.restore_state()?;

        info!("🔄 Restored PoRep state: {} sectors, {} jobs, {} commitments",
              restored_state.active_sectors.len(),
              restored_state.sealing_queue.len(),
              restored_state.commitments.len());

        let prover = Self {
            keypair: Arc::new(keypair),
            address,
            sector_size: config.sector_size,
            sealing_queue: Arc::new(RwLock::new(restored_state.sealing_queue)),
            active_sectors: Arc::new(RwLock::new(restored_state.active_sectors)),
            commitments: Arc::new(RwLock::new(restored_state.commitments)),
            submitted_proofs: Arc::new(RwLock::new(restored_state.submitted_proofs)),
            proving_params,
            gpu_available: config.gpu_available,
            nvme_path: config.nvme_path,
            proof_event_sender: None,
            fraud_event_sender: None,
            persistence: Arc::new(persistence),
        };

        info!("✅ PoRepProver initialized with persistent storage");
        Ok(prover)
    }

    pub fn with_proof_event_sender(mut self, sender: mpsc::UnboundedSender<ProofEvent>) -> Self {
        self.proof_event_sender = Some(sender);
        self
    }

    pub fn with_fraud_event_sender(
        mut self,
        sender: mpsc::UnboundedSender<PoRepFraudEvidence>,
    ) -> Self {
        self.fraud_event_sender = Some(sender);
        self
    }

    pub async fn start(&mut self) -> PoCResult<()> {
        info!(
            "Starting PoRep prover {} sector_size={} gpu={}",
            self.address, self.sector_size, self.gpu_available
        );

        self.validate_storage_setup()?;
        self.start_sealing_processor().await?;
        self.start_commitment_watchdog().await?;

        info!("PoRep prover {} started", self.address);
        Ok(())
    }

    pub async fn stop(&mut self) -> PoCResult<()> {
        info!("Stopping PoRep prover {}", self.address);
        self.drain_sealing_queue().await?;
        info!("PoRep prover {} stopped", self.address);
        Ok(())
    }

    async fn start_sealing_processor(&self) -> PoCResult<()> {
        let sealing_queue = self.sealing_queue.clone();
        let active_sectors = self.active_sectors.clone();
        let commitments = self.commitments.clone();
        let proving_params = self.proving_params.clone();
        let address = self.address;
        let gpu_available = self.gpu_available;
        let keypair = self.keypair.clone();

        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(10));

            loop {
                tick.tick().await;

                let next_job = {
                    let mut queue = sealing_queue.write().unwrap();
                    queue.pop_front()
                };

                if let Some(mut job) = next_job {
                    debug!(
                        "Processing sealing job {} sector={} prover={}",
                        job.job_id, job.sector_id, address
                    );

                    match Self::process_sealing_job(
                        &mut job,
                        &proving_params,
                        gpu_available,
                        &active_sectors,
                        &commitments,
                        &keypair,
                    )
                    .await
                    {
                        Ok(_) => {
                            info!(
                                "Sealed sector={} prover={} time_ms={}",
                                job.sector_id,
                                address,
                                job.total_sealing_time_ms()
                            );
                        }
                        Err(e) => {
                            warn!("Sealing job {} failed: {}", job.job_id, e);
                            job.status = SealingStatus::Failed;
                        }
                    }
                }
            }
        });

        Ok(())
    }

    async fn start_commitment_watchdog(&self) -> PoCResult<()> {
        let commitments = self.commitments.clone();
        let active_sectors = self.active_sectors.clone();
        let address = self.address;

        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(3600));

            loop {
                tick.tick().await;

                let expired: Vec<u64> = {
                    let comms = commitments.read().unwrap();
                    comms
                        .iter()
                        .filter(|(_, c)| c.is_expired())
                        .map(|(id, _)| *id)
                        .collect()
                };

                for sector_id in expired {
                    warn!("Sector {} commitment expired prover={}", sector_id, address);
                    commitments.write().unwrap().remove(&sector_id);
                    active_sectors.write().unwrap().remove(&sector_id);
                }
            }
        });

        Ok(())
    }

    async fn process_sealing_job(
        job: &mut SealingJob,
        params: &ProvingParams,
        gpu_available: bool,
        active_sectors: &Arc<RwLock<HashMap<u64, SectorState>>>,
        commitments: &Arc<RwLock<HashMap<u64, SectorCommitment>>>,
        keypair: &Arc<KeyPair>,
    ) -> PoCResult<()> {
        let start_time = Timestamp::now();

        job.advance_status(SealingStatus::PreCommit1, 0);
        let pc1_ms = Self::run_pc1(params.sector_size, gpu_available).await?;
        job.advance_status(SealingStatus::PreCommit2, pc1_ms);

        let pc2_ms = Self::run_pc2(params.sector_size, gpu_available).await?;
        job.advance_status(SealingStatus::WaitingForSeed, pc2_ms);

        tokio::time::sleep(Duration::from_millis(100)).await;

        job.advance_status(SealingStatus::Commit1, 0);
        let c1_ms = Self::run_c1(params.sector_size, gpu_available).await?;
        job.advance_status(SealingStatus::Commit2, c1_ms);

        let c2_ms = Self::run_c2(params.sector_size, gpu_available).await?;
        job.advance_status(SealingStatus::Completed, c2_ms);

        let prover_addr = Address::from_public_key(&keypair.public_key());
        let replica_id = Self::derive_replica_id(&prover_addr, job.sector_id, &job.data_cid);
        let comm_d = Self::compute_comm_d(&job.data_cid);
        let comm_r = Self::compute_comm_r(&comm_d, &replica_id);

        let state = SectorState {
            sector_id: job.sector_id,
            replica_id,
            comm_d,
            comm_r,
            sealed_path: format!("{}/sealed/sector-{}", "/sealed", job.sector_id),
            cache_path: format!("{}/cache/sector-{}", "/cache", job.sector_id),
            deal_ids: vec![],
            created_at: start_time,
            proof_count: 0,
            last_challenged_at: None,
        };

        {
            active_sectors
                .write()
                .unwrap()
                .insert(job.sector_id, state.clone());
        }

        let commitment = SectorCommitment {
            sector_id: job.sector_id,
            prover_id: prover_addr,
            comm_d,
            comm_r,
            replica_id,
            sector_size: params.sector_size,
            params_version: params.params_version,
            registered_at: start_time,
            deal_ids: vec![],
            expiry: Timestamp::from_millis(start_time.as_millis() + 180 * 24 * 3600 * 1000),
        };

        {
            commitments
                .write()
                .unwrap()
                .insert(job.sector_id, commitment);
        }

        Ok(())
    }

    fn derive_replica_id(prover_id: &Address, sector_id: u64, data_cid: &Hash) -> Hash {
        hash_multiple(&[
            prover_id.as_bytes(),
            &sector_id.to_le_bytes(),
            data_cid.as_bytes(),
            b"ego/porep/replica-id/v1",
        ])
    }

    fn compute_comm_d(data_cid: &Hash) -> Hash {
        hash_data(data_cid.as_bytes())
    }

    fn compute_comm_r(comm_d: &Hash, replica_id: &Hash) -> Hash {
        hash_multiple(&[
            comm_d.as_bytes(),
            replica_id.as_bytes(),
            b"ego/porep/comm-r/v1",
        ])
    }

    fn compute_porep_id(sector_size: u64, params_version: u32) -> [u8; 32] {
        let h = hash_multiple(&[
            &sector_size.to_le_bytes(),
            &params_version.to_le_bytes(),
            b"ego/porep/params-id/v1",
        ]);
        let mut result = [0u8; 32];
        result.copy_from_slice(h.as_bytes());
        result
    }

    async fn run_pc1(sector_size: u64, gpu: bool) -> PoCResult<u64> {
        let base_ms = match sector_size {
            s if s == 32 * 1024 * 1024 * 1024 => 3_600_000u64,
            s if s == 64 * 1024 * 1024 * 1024 => 7_200_000u64,
            s => (s / (1024 * 1024)) * 1000,
        };
        let duration = if gpu {
            (base_ms as f64 * 0.3) as u64
        } else {
            base_ms
        };
        tokio::time::sleep(Duration::from_millis(duration.min(50))).await;
        Ok(duration)
    }

    async fn run_pc2(sector_size: u64, gpu: bool) -> PoCResult<u64> {
        let base_ms = match sector_size {
            s if s == 32 * 1024 * 1024 * 1024 => 1_800_000u64,
            s if s == 64 * 1024 * 1024 * 1024 => 3_600_000u64,
            s => (s / (1024 * 1024)) * 500,
        };
        let duration = if gpu {
            (base_ms as f64 * 0.2) as u64
        } else {
            base_ms
        };
        tokio::time::sleep(Duration::from_millis(duration.min(30))).await;
        Ok(duration)
    }

    async fn run_c1(sector_size: u64, _gpu: bool) -> PoCResult<u64> {
        let duration = (sector_size / (1024 * 1024)) * 10;
        tokio::time::sleep(Duration::from_millis(duration.min(20))).await;
        Ok(duration)
    }

    async fn run_c2(sector_size: u64, gpu: bool) -> PoCResult<u64> {
        let base_ms = match sector_size {
            s if s == 32 * 1024 * 1024 * 1024 => 1_200_000u64,
            s if s == 64 * 1024 * 1024 * 1024 => 2_400_000u64,
            s => (s / (1024 * 1024)) * 300,
        };
        let duration = if gpu {
            (base_ms as f64 * 0.25) as u64
        } else {
            base_ms
        };
        tokio::time::sleep(Duration::from_millis(duration.min(30))).await;
        Ok(duration)
    }

    async fn compute_proof_for_sector(
        &self,
        state: &SectorState,
        challenges: &[u64],
    ) -> PoCResult<Vec<u8>> {
        let mut proof_elements: Vec<u8> = Vec::new();

        for &challenge in challenges {
            let element = self.compute_challenge_response(state, challenge).await?;
            proof_elements.extend_from_slice(&element);
        }

        Ok(proof_elements)
    }

    async fn compute_challenge_response(
        &self,
        state: &SectorState,
        challenge: u64,
    ) -> PoCResult<[u8; 32]> {
        let leaf_index = challenge % self.proving_params.sector_size.max(1);

        let response = hash_multiple(&[
            state.replica_id.as_bytes(),
            &challenge.to_le_bytes(),
            &leaf_index.to_le_bytes(),
            state.comm_r.as_bytes(),
            self.proving_params.porep_id.as_slice(),
        ]);

        let delay_ms = if self.gpu_available { 5 } else { 20 };
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;

        let mut result = [0u8; 32];
        result.copy_from_slice(response.as_bytes());
        Ok(result)
    }

    async fn verify_proof_data_internal(
        &self,
        proof_data: &[u8],
        state: &SectorState,
    ) -> PoCResult<bool> {
        let expected_len = self.proving_params.challenge_count as usize * 32;
        if proof_data.len() != expected_len {
            return Ok(false);
        }

        let expected_comm_r = Self::compute_comm_r(&state.comm_d, &state.replica_id);
        if expected_comm_r != state.comm_r {
            return Ok(false);
        }

        let chunk_size = 32;
        for (i, chunk) in proof_data.chunks(chunk_size).enumerate() {
            if chunk.len() < 32 {
                return Ok(false);
            }
            let challenge = i as u64;
            let expected = hash_multiple(&[
                state.replica_id.as_bytes(),
                &challenge.to_le_bytes(),
                &(challenge % self.proving_params.sector_size.max(1)).to_le_bytes(),
                state.comm_r.as_bytes(),
                self.proving_params.porep_id.as_slice(),
            ]);
            if chunk != expected.as_bytes() {
                return Ok(false);
            }
        }

        Ok(true)
    }

    pub fn register_deal_ids(&mut self, sector_id: u64, deal_ids: Vec<Hash>) -> PoCResult<()> {
        let mut sectors = self.active_sectors.write().unwrap();
        let state = sectors
            .get_mut(&sector_id)
            .ok_or_else(|| PoCError::ValidationFailed(format!("Sector {} not found", sector_id)))?;
        state.deal_ids = deal_ids.clone();

        let mut comms = self.commitments.write().unwrap();
        if let Some(comm) = comms.get_mut(&sector_id) {
            comm.deal_ids = deal_ids;
        }

        drop(sectors);
        drop(comms);

        self.persist_sector_state(sector_id)?;
        self.persist_commitment(sector_id)?;

        debug!("💾 Persisted deal IDs update for sector {}", sector_id);
        Ok(())
    }

    pub fn get_sector_commitment(&self, sector_id: u64) -> Option<SectorCommitment> {
        self.commitments.read().unwrap().get(&sector_id).cloned()
    }

    pub fn get_all_commitments(&self) -> Vec<SectorCommitment> {
        self.commitments.read().unwrap().values().cloned().collect()
    }

    pub fn build_porep_event(&self, sector_id: u64, deal_ids: Vec<Hash>) -> PoCResult<PoRepEvent> {
        let state = {
            let sectors = self.active_sectors.read().unwrap();
            sectors.get(&sector_id).cloned()
        };

        let state = state
            .ok_or_else(|| PoCError::ValidationFailed(format!("Sector {} not found", sector_id)))?;

        let _proof_data: Vec<u8> = Vec::new();
        let proof_hash = hash_multiple(&[
            state.replica_id.as_bytes(),
            state.comm_r.as_bytes(),
            &sector_id.to_le_bytes(),
        ]);

        let mut event = PoRepEvent::new(
            deal_ids,
            sector_id,
            self.address,
            state.replica_id,
            state.comm_d,
            state.comm_r,
            self.proving_params.params_version,
            proof_hash,
        );

        event.sign_with_keypair(&self.keypair);
        Ok(event)
    }

    pub fn generate_fraud_evidence(
        &self,
        sector_id: u64,
        fraud_type: PoRepFraudType,
        challenger: Address,
    ) -> PoCResult<PoRepFraudEvidence> {
        let state = {
            let sectors = self.active_sectors.read().unwrap();
            sectors.get(&sector_id).cloned()
        };

        let prover_id = self.address;
        let evidence_hash = hash_multiple(&[
            &sector_id.to_le_bytes(),
            prover_id.as_bytes(),
            challenger.as_bytes(),
            &Timestamp::now().as_millis().to_le_bytes(),
        ]);

        Ok(PoRepFraudEvidence {
            sector_id,
            prover_id,
            fraud_type,
            evidence_hash,
            detected_at: Timestamp::now(),
            challenger,
        })
    }

    pub fn emit_proof_event(
        &self,
        sector_id: u64,
        verified: bool,
        latency_ms: u32,
        evidence_cid: Option<String>,
    ) {
        if let Some(ref sender) = self.proof_event_sender {
            let state = {
                let sectors = self.active_sectors.read().unwrap();
                sectors.get(&sector_id).cloned()
            };

            if let Some(state) = state {
                let proof_hash = hash_multiple(&[
                    state.replica_id.as_bytes(),
                    state.comm_r.as_bytes(),
                    &sector_id.to_le_bytes(),
                ]);

                let event = ProofEvent {
                    proof_type: ProofEventType::PoRep,
                    prover: self.address,
                    challenge_hash: state.replica_id,
                    proof_data_hash: proof_hash,
                    location_id: sector_id.to_string(),
                    slice_id: None,
                    timestamp: Timestamp::now(),
                    verified,
                    latency_ms,
                    witness_data: None,
                    batch_proof: false,
                    cellular_optimized: false,
                    evidence_cid,
                };

                let _ = sender.send(event);
            }
        }
    }

    pub fn get_sealing_metrics(&self) -> SealingMetrics {
        let queue_len = self.sealing_queue.read().unwrap().len();
        let sectors_active = self.active_sectors.read().unwrap().len();
        let sectors_committed = self.commitments.read().unwrap().len();
        let proofs_submitted = self.submitted_proofs.read().unwrap().len();

        SealingMetrics {
            sealing_queue_len: queue_len as u32,
            sectors_active: sectors_active as u32,
            sectors_committed: sectors_committed as u32,
            gpu_available: self.gpu_available,
            proofs_submitted: proofs_submitted as u32,
            last_updated: Timestamp::now(),
        }
    }

    fn validate_storage_setup(&self) -> PoCResult<()> {
        if self.sector_size == 0 {
            return Err(PoCError::ConfigError("Invalid sector size".to_string()));
        }
        if self.nvme_path.is_empty() {
            return Err(PoCError::ConfigError(
                "NVMe storage path not configured".to_string(),
            ));
        }
        if !self.gpu_available {
            warn!(
                "GPU not available for prover {}, sealing will be slower",
                self.address
            );
        }
        Ok(())
    }

    async fn drain_sealing_queue(&mut self) -> PoCResult<()> {
        let pending: Vec<SealingJob> = {
            let mut queue = self.sealing_queue.write().unwrap();
            queue.drain(..).collect()
        };

        for mut job in pending {
            if !job.is_terminal() {
                job.status = SealingStatus::Failed;
                warn!(
                    "Marked sealing job {} as failed during shutdown",
                    job.job_id
                );
            }
        }

        Ok(())
    }
}

impl PoRepProvider for PoRepProver {
    fn provider_id(&self) -> Address {
        self.address
    }

    async fn seal_sector(&mut self, sector_id: u64, data: Vec<u8>) -> PoCResult<PoRepProof> {
        debug!(
            "Sealing sector={} bytes={} prover={}",
            sector_id,
            data.len(),
            self.address
        );

        if sector_id == 0 {
            return Err(PoCError::ValidationFailed("Invalid sector ID".to_string()));
        }

        let data_cid = hash_data(&data);
        let job = SealingJob::new(sector_id, data_cid);
        let _job_id = job.job_id;

        {
            let mut queue = self.sealing_queue.write().unwrap();
            queue.push_back(job);
        }

        let mut wait_ms = 0u64;
        let timeout_ms = 60_000u64;

        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            wait_ms += 100;

            let done = {
                let sectors = self.active_sectors.read().unwrap();
                sectors.contains_key(&sector_id)
            };

            if done {
                break;
            }

            if wait_ms >= timeout_ms {
                return Err(PoCError::ValidationFailed(
                    "Sealing job timed out".to_string(),
                ));
            }
        }

        let state = {
            let sectors = self.active_sectors.read().unwrap();
            sectors.get(&sector_id).cloned()
        };

        let state = state.ok_or_else(|| {
            PoCError::ValidationFailed("Sector not found after sealing".to_string())
        })?;

        let challenges: Vec<u64> = (0..self.proving_params.challenge_count as u64).collect();
        let proof_data = self.compute_proof_for_sector(&state, &challenges).await?;

        let proof = PoRepProof::new(
            sector_id,
            state.replica_id,
            state.comm_d,
            state.comm_r,
            proof_data,
            self.proving_params.params_version,
            self.address,
        );

        let proof_hash = proof.compute_proof_hash();
        {
            let mut submitted = self.submitted_proofs.write().unwrap();
            submitted.insert(proof_hash);
        }

        if let Err(e) = self.persist_sector_state(sector_id) {
            warn!("Failed to persist sector state after sealing {}: {}", sector_id, e);
        }

        {
            let mut sectors = self.active_sectors.write().unwrap();
            if let Some(sector_state) = sectors.get_mut(&sector_id) {
                sector_state.proof_count += 1;
                sector_state.last_challenged_at = Some(Timestamp::now());
            }
        }

        if let Err(e) = self.persist_sector_state(sector_id) {
            warn!("Failed to persist sector state after proof count update {}: {}", sector_id, e);
        }

        self.emit_proof_event(sector_id, true, 0, None);

        info!("✅ Sealed sector={} prover={} (proof count incremented)", sector_id, self.address);
        Ok(proof)
    }

    async fn generate_porep_proof(&self, challenge: PoRepChallenge) -> PoCResult<PoRepProof> {
        debug!(
            "Generating PoRep proof sector={} prover={}",
            challenge.sector_id, self.address
        );

        if challenge.is_expired() {
            return Err(PoCError::TimeWindowViolation(
                "PoRep challenge expired".to_string(),
            ));
        }

        let state = {
            let sectors = self.active_sectors.read().unwrap();
            sectors.get(&challenge.sector_id).cloned()
        };

        let state = state.ok_or_else(|| {
            PoCError::ValidationFailed("Sector not found for PoRep challenge".to_string())
        })?;

        if state.replica_id != challenge.replica_id {
            return Err(PoCError::ValidationFailed(
                "Replica ID mismatch".to_string(),
            ));
        }

        let challenges = challenge.generate_deterministic_challenges();
        let start_ms = Timestamp::now().as_millis();
        let proof_data = self.compute_proof_for_sector(&state, &challenges).await?;
        let latency_ms = (Timestamp::now().as_millis() - start_ms) as u32;

        let proof = PoRepProof::new(
            challenge.sector_id,
            challenge.replica_id,
            state.comm_d,
            state.comm_r,
            proof_data,
            self.proving_params.params_version,
            self.address,
        );

        let proof_hash = proof.compute_proof_hash();

        let is_replay = {
            let submitted = self.submitted_proofs.read().unwrap();
            submitted.contains(&proof_hash)
        };

        if is_replay {
            return Err(PoCError::ValidationFailed(
                "Duplicate proof submission".to_string(),
            ));
        }

        {
            let mut submitted = self.submitted_proofs.write().unwrap();
            submitted.insert(proof_hash);
        }

        {
            let mut sectors = self.active_sectors.write().unwrap();
            if let Some(s) = sectors.get_mut(&challenge.sector_id) {
                s.proof_count += 1;
                s.last_challenged_at = Some(Timestamp::now());
            }
        }

        self.emit_proof_event(challenge.sector_id, true, latency_ms, None);

        info!(
            "Generated PoRep proof sector={} prover={}",
            challenge.sector_id, self.address
        );
        Ok(proof)
    }

    async fn verify_porep_proof(&self, proof: &PoRepProof) -> PoCResult<bool> {
        debug!(
            "Verifying PoRep proof sector={} prover={}",
            proof.sector_id, self.address
        );

        proof.validate()?;

        let state = {
            let sectors = self.active_sectors.read().unwrap();
            sectors.get(&proof.sector_id).cloned()
        };

        let state = match state {
            Some(s) => s,
            None => return Ok(false),
        };

        if state.replica_id != proof.replica_id {
            return Ok(false);
        }

        if state.comm_d != proof.comm_d || state.comm_r != proof.comm_r {
            return Ok(false);
        }

        if proof.prover_id != self.address {
            return Ok(false);
        }

        self.verify_proof_data_internal(&proof.proof_data, &state)
            .await
    }

    fn get_sealing_queue_length(&self) -> usize {
        self.sealing_queue.read().unwrap().len()
    }

    fn get_active_sectors(&self) -> Vec<u64> {
        self.active_sectors
            .read()
            .unwrap()
            .keys()
            .cloned()
            .collect()
    }
}

impl PoRepProver {

    fn persist_sector_state(&self, sector_id: u64) -> PoCResult<()> {
        let sectors = self.active_sectors.read().unwrap();
        if let Some(sector_state) = sectors.get(&sector_id) {
            if let Err(e) = self.persistence.save_sector_state(sector_state) {
                error!("Failed to persist sector state {}: {}", sector_id, e);
                return Err(e);
            }
        }
        Ok(())
    }

    fn persist_commitment(&self, sector_id: u64) -> PoCResult<()> {
        let commitments = self.commitments.read().unwrap();
        if let Some(commitment) = commitments.get(&sector_id) {
            if let Err(e) = self.persistence.save_commitment(sector_id, commitment) {
                error!("Failed to persist commitment for sector {}: {}", sector_id, e);
                return Err(e);
            }
        }
        Ok(())
    }

    pub fn start_periodic_backup(&self) -> mpsc::UnboundedSender<()> {
        let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel();

        let active_sectors = Arc::clone(&self.active_sectors);
        let sealing_queue = Arc::clone(&self.sealing_queue);
        let commitments = Arc::clone(&self.commitments);
        let submitted_proofs = Arc::clone(&self.submitted_proofs);
        let persistence = Arc::clone(&self.persistence);

        tokio::spawn(async move {
            let mut backup_interval = interval(Duration::from_secs(300));
            loop {
                tokio::select! {
                    _ = backup_interval.tick() => {
                        info!("🔄 Starting periodic PoRep state backup...");

                        let sectors_snapshot = active_sectors.read().unwrap().clone();
                        let queue_snapshot = sealing_queue.read().unwrap().clone();
                        let commitments_snapshot = commitments.read().unwrap().clone();
                        let proofs_snapshot = submitted_proofs.read().unwrap().clone();

                        if let Err(e) = persistence.backup_state(
                            &sectors_snapshot,
                            &queue_snapshot,
                            &commitments_snapshot,
                            &proofs_snapshot,
                        ) {
                            error!("Periodic backup failed: {}", e);
                        } else {
                            debug!("✅ Periodic backup completed successfully");
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("📁 Shutting down periodic backup task");
                        break;
                    }
                }
            }
        });

        shutdown_tx
    }

    pub fn backup_current_state(&self) -> PoCResult<()> {
        info!("💾 Performing immediate state backup...");

        let sectors_snapshot = self.active_sectors.read().unwrap().clone();
        let queue_snapshot = self.sealing_queue.read().unwrap().clone();
        let commitments_snapshot = self.commitments.read().unwrap().clone();
        let proofs_snapshot = self.submitted_proofs.read().unwrap().clone();

        self.persistence.backup_state(
            &sectors_snapshot,
            &queue_snapshot,
            &commitments_snapshot,
            &proofs_snapshot,
        )?;

        info!("✅ Immediate backup completed");
        Ok(())
    }

    pub fn cleanup_old_sectors(&self, retention_days: u64) -> PoCResult<u32> {
        let retention_ms = retention_days * 24 * 60 * 60 * 1000;
        let cutoff_time = Timestamp::from_millis(Timestamp::now().as_millis().saturating_sub(retention_ms));
        self.persistence.cleanup_completed_sectors(cutoff_time)
    }

    pub fn get_persistence_stats(&self) -> PoCResult<super::persistence::PoRepStorageStats> {
        self.persistence.get_stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::crypto::KeyPair;

    fn make_prover(gpu: bool) -> PoRepProver {
        let keypair = KeyPair::generate();
        let config = ProverConfig {
            sector_size: 512 * 1024 * 1024,
            gpu_available: gpu,
            nvme_path: "/tmp/nvme-test".to_string(),
            max_parallel_sealing: 1,
            challenge_window_ms: 300_000,
            params_version: 1,
        };
        PoRepProver::new(keypair, config)
    }

    #[test]
    fn test_prover_creation() {
        let prover = make_prover(false);
        assert_eq!(prover.sector_size, 512 * 1024 * 1024);
        assert!(!prover.gpu_available);
        assert_eq!(prover.get_sealing_queue_length(), 0);
        assert!(prover.get_active_sectors().is_empty());
    }

    #[test]
    fn test_prover_creation_with_gpu() {
        let prover = make_prover(true);
        assert!(prover.gpu_available);
    }

    #[test]
    fn test_validate_storage_setup_empty_nvme_path() {
        let keypair = KeyPair::generate();
        let config = ProverConfig {
            nvme_path: "".to_string(),
            ..ProverConfig::default()
        };
        let prover = PoRepProver::new(keypair, config);
        assert!(prover.validate_storage_setup().is_err());
    }

    #[test]
    fn test_validate_storage_setup_zero_sector_size() {
        let keypair = KeyPair::generate();
        let config = ProverConfig {
            sector_size: 0,
            nvme_path: "/tmp/nvme".to_string(),
            ..ProverConfig::default()
        };
        let prover = PoRepProver::new(keypair, config);
        assert!(prover.validate_storage_setup().is_err());
    }

    #[test]
    fn test_derive_replica_id_deterministic() {
        let addr = Address::new([1u8; 20]);
        let data_cid = Hash::new([2u8; 32]);
        let r1 = PoRepProver::derive_replica_id(&addr, 1, &data_cid);
        let r2 = PoRepProver::derive_replica_id(&addr, 1, &data_cid);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_derive_replica_id_unique_per_prover() {
        let addr1 = Address::new([1u8; 20]);
        let addr2 = Address::new([2u8; 20]);
        let data_cid = Hash::new([3u8; 32]);
        let r1 = PoRepProver::derive_replica_id(&addr1, 1, &data_cid);
        let r2 = PoRepProver::derive_replica_id(&addr2, 1, &data_cid);
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_derive_replica_id_unique_per_sector() {
        let addr = Address::new([1u8; 20]);
        let data_cid = Hash::new([2u8; 32]);
        let r1 = PoRepProver::derive_replica_id(&addr, 1, &data_cid);
        let r2 = PoRepProver::derive_replica_id(&addr, 2, &data_cid);
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_compute_comm_d_deterministic() {
        let cid = Hash::new([5u8; 32]);
        assert_eq!(
            PoRepProver::compute_comm_d(&cid),
            PoRepProver::compute_comm_d(&cid)
        );
    }

    #[test]
    fn test_compute_comm_r_depends_on_both() {
        let comm_d = Hash::new([1u8; 32]);
        let r1 = Hash::new([2u8; 32]);
        let r2 = Hash::new([3u8; 32]);
        assert_ne!(
            PoRepProver::compute_comm_r(&comm_d, &r1),
            PoRepProver::compute_comm_r(&comm_d, &r2)
        );
    }

    #[tokio::test]
    async fn test_run_pc1_faster_with_gpu() {
        let cpu_ms = PoRepProver::run_pc1(512 * 1024 * 1024, false)
            .await
            .unwrap();
        let gpu_ms = PoRepProver::run_pc1(512 * 1024 * 1024, true).await.unwrap();
        assert!(gpu_ms < cpu_ms);
    }

    #[tokio::test]
    async fn test_run_pc2_faster_with_gpu() {
        let cpu_ms = PoRepProver::run_pc2(512 * 1024 * 1024, false)
            .await
            .unwrap();
        let gpu_ms = PoRepProver::run_pc2(512 * 1024 * 1024, true).await.unwrap();
        assert!(gpu_ms < cpu_ms);
    }

    #[tokio::test]
    async fn test_challenge_response_deterministic() {
        let prover = make_prover(false);
        let state = SectorState {
            sector_id: 1,
            replica_id: Hash::new([1u8; 32]),
            comm_d: Hash::new([2u8; 32]),
            comm_r: Hash::new([3u8; 32]),
            sealed_path: "/sealed/sector-1".to_string(),
            cache_path: "/cache/sector-1".to_string(),
            deal_ids: vec![],
            created_at: Timestamp::now(),
            proof_count: 0,
            last_challenged_at: None,
        };
        let r1 = prover.compute_challenge_response(&state, 42).await.unwrap();
        let r2 = prover.compute_challenge_response(&state, 42).await.unwrap();
        assert_eq!(r1, r2);
    }

    #[tokio::test]
    async fn test_challenge_response_different_challenges() {
        let prover = make_prover(false);
        let state = SectorState {
            sector_id: 1,
            replica_id: Hash::new([1u8; 32]),
            comm_d: Hash::new([2u8; 32]),
            comm_r: Hash::new([3u8; 32]),
            sealed_path: "/sealed/sector-1".to_string(),
            cache_path: "/cache/sector-1".to_string(),
            deal_ids: vec![],
            created_at: Timestamp::now(),
            proof_count: 0,
            last_challenged_at: None,
        };
        let r1 = prover.compute_challenge_response(&state, 1).await.unwrap();
        let r2 = prover.compute_challenge_response(&state, 2).await.unwrap();
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_sealing_metrics_initial() {
        let prover = make_prover(false);
        let m = prover.get_sealing_metrics();
        assert_eq!(m.sealing_queue_len, 0);
        assert_eq!(m.sectors_active, 0);
        assert_eq!(m.sectors_committed, 0);
        assert_eq!(m.proofs_submitted, 0);
    }

    #[test]
    fn test_get_sector_commitment_none() {
        let prover = make_prover(false);
        assert!(prover.get_sector_commitment(99).is_none());
    }

    #[test]
    fn test_register_deal_ids_unknown_sector() {
        let mut prover = make_prover(false);
        let result = prover.register_deal_ids(999, vec![Hash::new([1u8; 32])]);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_fraud_evidence() {
        let prover = make_prover(false);
        let challenger = Address::new([9u8; 20]);
        let evidence = prover
            .generate_fraud_evidence(1, PoRepFraudType::InvalidProofData, challenger)
            .unwrap();
        assert_eq!(evidence.sector_id, 1);
        assert_eq!(evidence.prover_id, prover.address);
        assert_eq!(evidence.challenger, challenger);
    }

    #[test]
    fn test_proof_event_sender_wired() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let prover = make_prover(false).with_proof_event_sender(tx);
        assert!(prover.proof_event_sender.is_some());
    }

    #[tokio::test]
    async fn test_verify_proof_unknown_sector_returns_false() {
        let prover = make_prover(false);
        let proof = PoRepProof::new(
            999,
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            Hash::new([3u8; 32]),
            vec![0u8; 32],
            1,
            prover.address,
        );
        let result = prover.verify_porep_proof(&proof).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_generate_proof_expired_challenge() {
        let prover = make_prover(false);
        let expired_challenge = PoRepChallenge {
            sector_id: 1,
            replica_id: Hash::new([1u8; 32]),
            challenge_seed: Hash::new([2u8; 32]),
            challenge_count: 176,
            deadline: Timestamp::from_millis(0),
        };
        let result = prover.generate_porep_proof(expired_challenge).await;
        assert!(result.is_err());
    }
}
