use super::{PoRepChallenge, PoRepProof, PoRepProvider, SealingJob, SealingStatus};
use crate::error::{PoCError, PoCResult};
use ego_core::{Address, Hash, KeyPair, Timestamp};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use tokio::time::{Duration, interval};
use tracing::{debug, info, warn};

pub struct PoRepProver {
    keypair: Arc<KeyPair>,
    address: Address,
    sector_size: u64,
    sealing_queue: Arc<RwLock<VecDeque<SealingJob>>>,
    active_sectors: Arc<RwLock<HashMap<u64, SectorInfo>>>,
    proving_params: ProvingParams,
    gpu_available: bool,
    nvme_path: String,
}

#[derive(Debug, Clone)]
pub struct SectorInfo {
    pub sector_id: u64,
    pub replica_id: Hash,
    pub comm_d: Hash,
    pub comm_r: Hash,
    pub sealed_path: String,
    pub cache_path: String,
    pub deal_ids: Vec<Hash>,
    pub created_at: Timestamp,
}

#[derive(Debug, Clone)]
pub struct ProvingParams {
    pub porep_id: [u8; 32],
    pub sector_size: u64,
    pub partitions: u32,
    pub challenge_count: u32,
    pub params_version: u32,
}

impl PoRepProver {
    pub fn new(
        keypair: KeyPair,
        sector_size: u64,
        gpu_available: bool,
        nvme_path: String,
    ) -> Self {
        let address = Address::from_public_key(&keypair.public_key());

        let proving_params = ProvingParams {
            porep_id: [0u8; 32],
            sector_size,
            partitions: (sector_size / (1024 * 1024 * 32)) as u32,
            challenge_count: 176,
            params_version: 1,
        };

        Self {
            keypair: Arc::new(keypair),
            address,
            sector_size,
            sealing_queue: Arc::new(RwLock::new(VecDeque::new())),
            active_sectors: Arc::new(RwLock::new(HashMap::new())),
            proving_params,
            gpu_available,
            nvme_path,
        }
    }

    pub async fn start(&mut self) -> PoCResult<()> {
        info!("Starting PoRep prover {} with {} byte sectors",
              self.address, self.sector_size);

        self.validate_storage_setup()?;
        self.start_sealing_processor().await?;

        info!("✅ PoRep prover {} started successfully", self.address);
        Ok(())
    }

    pub async fn stop(&mut self) -> PoCResult<()> {
        info!("Stopping PoRep prover {}", self.address);

        self.complete_pending_sealing().await?;

        info!("✅ PoRep prover {} stopped", self.address);
        Ok(())
    }

    async fn start_sealing_processor(&self) -> PoCResult<()> {
        let sealing_queue = self.sealing_queue.clone();
        let active_sectors = self.active_sectors.clone();
        let proving_params = self.proving_params.clone();
        let address = self.address;
        let gpu_available = self.gpu_available;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10));

            loop {
                interval.tick().await;

                let next_job = {
                    let mut queue = sealing_queue.write().unwrap();
                    queue.pop_front()
                };

                if let Some(mut job) = next_job {
                    debug!("Processing sealing job {} for sector {} (prover {})",
                           job.job_id, job.sector_id, address);

                    if let Err(e) = Self::process_sealing_job(
                        &mut job,
                        &proving_params,
                        gpu_available,
                        &active_sectors,
                    ).await {
                        warn!("Sealing job {} failed: {}", job.job_id, e);
                        job.status = SealingStatus::Failed;
                    }
                }
            }
        });

        Ok(())
    }

    async fn process_sealing_job(
        job: &mut SealingJob,
        params: &ProvingParams,
        gpu_available: bool,
        active_sectors: &Arc<RwLock<HashMap<u64, SectorInfo>>>,
    ) -> PoCResult<()> {
        let start_time = Timestamp::now();

        job.advance_status(SealingStatus::PreCommit1, 0);
        let pc1_duration = Self::simulate_pc1(params.sector_size, gpu_available).await?;
        job.advance_status(SealingStatus::PreCommit2, pc1_duration);

        let pc2_duration = Self::simulate_pc2(params.sector_size, gpu_available).await?;
        job.advance_status(SealingStatus::WaitingForSeed, pc2_duration);

        tokio::time::sleep(Duration::from_secs(1)).await;

        job.advance_status(SealingStatus::Commit1, 0);
        let c1_duration = Self::simulate_c1(params.sector_size, gpu_available).await?;
        job.advance_status(SealingStatus::Commit2, c1_duration);

        let c2_duration = Self::simulate_c2(params.sector_size, gpu_available).await?;
        job.advance_status(SealingStatus::Completed, c2_duration);

        let replica_id = Hash::new([job.sector_id as u8; 32]);
        let comm_d = Self::compute_comm_d(&job.data_cid);
        let comm_r = Self::compute_comm_r(&comm_d, &replica_id);

        let sector_info = SectorInfo {
            sector_id: job.sector_id,
            replica_id,
            comm_d,
            comm_r,
            sealed_path: format!("/sealed/sector-{}", job.sector_id),
            cache_path: format!("/cache/sector-{}", job.sector_id),
            deal_ids: vec![],
            created_at: start_time,
        };

        {
            let mut sectors = active_sectors.write().unwrap();
            sectors.insert(job.sector_id, sector_info);
        }

        Ok(())
    }

    async fn simulate_pc1(sector_size: u64, gpu_available: bool) -> PoCResult<u64> {
        let base_time_ms = match sector_size {
            32 * 1024 * 1024 * 1024 => 3600000,
            64 * 1024 * 1024 * 1024 => 7200000,
            _ => (sector_size / (1024 * 1024)) * 1000,
        };

        let multiplier = if gpu_available { 0.3 } else { 1.0 };
        let duration = (base_time_ms as f64 * multiplier) as u64;

        tokio::time::sleep(Duration::from_millis(duration.min(1000))).await;
        Ok(duration)
    }

    async fn simulate_pc2(sector_size: u64, gpu_available: bool) -> PoCResult<u64> {
        let base_time_ms = match sector_size {
            32 * 1024 * 1024 * 1024 => 1800000,
            64 * 1024 * 1024 * 1024 => 3600000,
            _ => (sector_size / (1024 * 1024)) * 500,
        };

        let multiplier = if gpu_available { 0.2 } else { 1.0 };
        let duration = (base_time_ms as f64 * multiplier) as u64;

        tokio::time::sleep(Duration::from_millis(duration.min(500))).await;
        Ok(duration)
    }

    async fn simulate_c1(sector_size: u64, _gpu_available: bool) -> PoCResult<u64> {
        let duration_ms = (sector_size / (1024 * 1024)) * 10;
        tokio::time::sleep(Duration::from_millis(duration_ms.min(100))).await;
        Ok(duration_ms)
    }

    async fn simulate_c2(sector_size: u64, gpu_available: bool) -> PoCResult<u64> {
        let base_time_ms = match sector_size {
            32 * 1024 * 1024 * 1024 => 1200000,
            64 * 1024 * 1024 * 1024 => 2400000,
            _ => (sector_size / (1024 * 1024)) * 300,
        };

        let multiplier = if gpu_available { 0.25 } else { 1.0 };
        let duration = (base_time_ms as f64 * multiplier) as u64;

        tokio::time::sleep(Duration::from_millis(duration.min(300))).await;
        Ok(duration)
    }

    fn compute_comm_d(data_cid: &Hash) -> Hash {
        use ego_core::crypto::hash_data;
        hash_data(data_cid.as_bytes())
    }

    fn compute_comm_r(comm_d: &Hash, replica_id: &Hash) -> Hash {
        use ego_core::crypto::hash_multiple;
        hash_multiple(&[comm_d.as_bytes(), replica_id.as_bytes()])
    }

    async fn complete_pending_sealing(&mut self) -> PoCResult<()> {
        let pending_jobs: Vec<SealingJob> = {
            let mut queue = self.sealing_queue.write().unwrap();
            queue.drain(..).collect()
        };

        for mut job in pending_jobs {
            if job.status != SealingStatus::Completed && job.status != SealingStatus::Failed {
                job.status = SealingStatus::Failed;
                warn!("Marked sealing job {} as failed during shutdown", job.job_id);
            }
        }

        Ok(())
    }

    fn validate_storage_setup(&self) -> PoCResult<()> {
        if self.sector_size == 0 {
            return Err(PoCError::ConfigError(
                "Invalid sector size".to_string(),
            ));
        }

        if self.nvme_path.is_empty() {
            return Err(PoCError::ConfigError(
                "NVMe storage path not configured".to_string(),
            ));
        }

        Ok(())
    }

    pub fn get_sealing_metrics(&self) -> SealingMetrics {
        let queue = self.sealing_queue.read().unwrap();
        let sectors = self.active_sectors.read().unwrap();

        SealingMetrics {
            sealing_queue_len: queue.len() as u32,
            sectors_active: sectors.len() as u32,
            gpu_available: self.gpu_available,
            last_updated: Timestamp::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealingMetrics {
    pub sealing_queue_len: u32,
    pub sectors_active: u32,
    pub gpu_available: bool,
    pub last_updated: Timestamp,
}

impl PoRepProvider for PoRepProver {
    fn provider_id(&self) -> Address {
        self.address
    }

    async fn seal_sector(&mut self, sector_id: u64, data: Vec<u8>) -> PoCResult<PoRepProof> {
        debug!("Sealing sector {} with {} bytes (prover {})",
               sector_id, data.len(), self.address);

        let data_cid = ego_core::crypto::hash_data(&data);
        let mut job = SealingJob::new(sector_id, data_cid);

        {
            let mut queue = self.sealing_queue.write().unwrap();
            queue.push_back(job.clone());
        }

        let mut attempts = 0;
        while attempts < 100 && job.status != SealingStatus::Completed && job.status != SealingStatus::Failed {
            tokio::time::sleep(Duration::from_millis(100)).await;
            attempts += 1;

            let queue = self.sealing_queue.read().unwrap();
            if let Some(updated_job) = queue.iter().find(|j| j.job_id == job.job_id) {
                job = updated_job.clone();
            }
        }

        if job.status != SealingStatus::Completed {
            return Err(PoCError::ValidationFailed(
                "Sealing job did not complete".to_string(),
            ));
        }

        let sector_info = {
            let sectors = self.active_sectors.read().unwrap();
            sectors.get(&sector_id).cloned()
        };

        if let Some(info) = sector_info {
            let proof_data = self.generate_porep_proof_data(&info).await?;

            let proof = PoRepProof::new(
                sector_id,
                info.replica_id,
                info.comm_d,
                info.comm_r,
                proof_data,
                self.proving_params.params_version,
                self.address,
            );

            info!("✅ Sealed sector {} (prover {})", sector_id, self.address);
            Ok(proof)
        } else {
            Err(PoCError::ValidationFailed(
                "Sector not found after sealing".to_string(),
            ))
        }
    }

    async fn generate_porep_proof(&self, challenge: PoRepChallenge) -> PoCResult<PoRepProof> {
        debug!("Generating PoRep proof for sector {} (prover {})",
               challenge.sector_id, self.address);

        if challenge.is_expired() {
            return Err(PoCError::TimeWindowViolation(
                "PoRep challenge expired".to_string(),
            ));
        }

        let sector_info = {
            let sectors = self.active_sectors.read().unwrap();
            sectors.get(&challenge.sector_id).cloned()
        };

        let sector_info = sector_info.ok_or_else(|| {
            PoCError::ValidationFailed("Sector not found for PoRep challenge".to_string())
        })?;

        if sector_info.replica_id != challenge.replica_id {
            return Err(PoCError::ValidationFailed(
                "Replica ID mismatch".to_string(),
            ));
        }

        let challenges = challenge.generate_deterministic_challenges();
        let proof_data = self.compute_porep_proof(&sector_info, &challenges).await?;

        let proof = PoRepProof::new(
            challenge.sector_id,
            challenge.replica_id,
            sector_info.comm_d,
            sector_info.comm_r,
            proof_data,
            self.proving_params.params_version,
            self.address,
        );

        info!("✅ Generated PoRep proof for sector {} (prover {})",
              challenge.sector_id, self.address);
        Ok(proof)
    }

    async fn verify_porep_proof(&self, proof: &PoRepProof) -> PoCResult<bool> {
        debug!("Verifying PoRep proof for sector {} (prover {})",
               proof.sector_id, self.address);

        proof.validate()?;

        let sector_info = {
            let sectors = self.active_sectors.read().unwrap();
            sectors.get(&proof.sector_id).cloned()
        };

        if let Some(info) = sector_info {
            if info.replica_id != proof.replica_id {
                return Ok(false);
            }

            if info.comm_d != proof.comm_d || info.comm_r != proof.comm_r {
                return Ok(false);
            }

            let is_valid = self.verify_proof_data(&proof.proof_data, &info).await?;
            Ok(is_valid)
        } else {
            Ok(false)
        }
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

    async fn generate_porep_proof_data(&self, sector_info: &SectorInfo) -> PoCResult<Vec<u8>> {
        let proof_size = match self.sector_size {
            32 * 1024 * 1024 * 1024 => 192,
            64 * 1024 * 1024 * 1024 => 384,
            _ => 96,
        };

        let mut proof_data = vec![0u8; proof_size];

        for (i, byte) in proof_data.iter_mut().enumerate() {
            *byte = ((sector_info.sector_id as usize + i) % 256) as u8;
        }

        let proving_time = if self.gpu_available { 5000 } else { 15000 };
        tokio::time::sleep(Duration::from_millis(proving_time)).await;

        Ok(proof_data)
    }

    async fn compute_porep_proof(&self, sector_info: &SectorInfo, challenges: &[u64]) -> PoCResult<Vec<u8>> {
        let mut proof_elements = Vec::new();

        for &challenge in challenges {
            let element = self.compute_challenge_response(sector_info, challenge).await?;
            proof_elements.extend_from_slice(&element);
        }

        Ok(proof_elements)
    }

    async fn compute_challenge_response(&self, sector_info: &SectorInfo, challenge: u64) -> PoCResult<[u8; 32]> {
        use ego_core::crypto::hash_multiple;

        let response = hash_multiple(&[
            sector_info.replica_id.as_bytes(),
            &challenge.to_le_bytes(),
            sector_info.comm_r.as_bytes(),
        ]);

        let proving_delay = if self.gpu_available { 10 } else { 50 };
        tokio::time::sleep(Duration::from_millis(proving_delay)).await;

        Ok(response.as_bytes().try_into().unwrap())
    }

    async fn verify_proof_data(&self, proof_data: &[u8], sector_info: &SectorInfo) -> PoCResult<bool> {
        if proof_data.len() != self.proving_params.challenge_count as usize * 32 {
            return Ok(false);
        }

        let verification_time = if self.gpu_available { 1000 } else { 3000 };
        tokio::time::sleep(Duration::from_millis(verification_time)).await;

        let expected_size = match self.sector_size {
            32 * 1024 * 1024 * 1024 => 192,
            64 * 1024 * 1024 * 1024 => 384,
            _ => 96,
        };

        if proof_data.len() < expected_size {
            return Ok(false);
        }

        for (i, &byte) in proof_data.iter().take(expected_size).enumerate() {
            let expected = ((sector_info.sector_id as usize + i) % 256) as u8;
            if byte != expected {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn validate_storage_setup(&self) -> PoCResult<()> {
        if !std::path::Path::new(&self.nvme_path).exists() {
            warn!("NVMe path {} does not exist, using simulation mode", self.nvme_path);
        }

        if !self.gpu_available {
            warn!("GPU not available, sealing will be slower");
        }

        Ok(())
    }
}

impl PoRepProvider for PoRepProver {
    fn provider_id(&self) -> Address {
        self.address
    }

    async fn seal_sector(&mut self, sector_id: u64, data: Vec<u8>) -> PoCResult<PoRepProof> {
        self.seal_sector(sector_id, data).await
    }

    async fn generate_porep_proof(&self, challenge: PoRepChallenge) -> PoCResult<PoRepProof> {
        self.generate_porep_proof(challenge).await
    }

    async fn verify_porep_proof(&self, proof: &PoRepProof) -> PoCResult<bool> {
        self.verify_porep_proof(proof).await
    }

    fn get_sealing_queue_length(&self) -> usize {
        self.get_sealing_queue_length()
    }

    fn get_active_sectors(&self) -> Vec<u64> {
        self.get_active_sectors()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::KeyPair;

    #[tokio::test]
    async fn test_porep_prover_creation() {
        let keypair = KeyPair::generate();
        let prover = PoRepProver::new(
            keypair,
            32 * 1024 * 1024 * 1024,
            true,
            "/tmp/nvme".to_string(),
        );

        assert_eq!(prover.sector_size, 32 * 1024 * 1024 * 1024);
        assert!(prover.gpu_available);
    }

    #[tokio::test]
    async fn test_sealing_simulation() {
        let duration = PoRepProver::simulate_pc1(32 * 1024 * 1024 * 1024, true).await.unwrap();
        assert!(duration > 0);

        let duration_gpu = PoRepProver::simulate_pc1(32 * 1024 * 1024 * 1024, true).await.unwrap();
        let duration_cpu = PoRepProver::simulate_pc1(32 * 1024 * 1024 * 1024, false).await.unwrap();
        assert!(duration_gpu < duration_cpu);
    }

    #[tokio::test]
    async fn test_porep_challenge_response() {
        let keypair = KeyPair::generate();
        let prover = PoRepProver::new(
            keypair,
            32 * 1024 * 1024 * 1024,
            true,
            "/tmp/nvme".to_string(),
        );

        let sector_info = SectorInfo {
            sector_id: 1,
            replica_id: Hash::new([1u8; 32]),
            comm_d: Hash::new([2u8; 32]),
            comm_r: Hash::new([3u8; 32]),
            sealed_path: "/sealed/sector-1".to_string(),
            cache_path: "/cache/sector-1".to_string(),
            deal_ids: vec![],
            created_at: Timestamp::now(),
        };

        let response = prover.compute_challenge_response(&sector_info, 12345).await.unwrap();
        assert_eq!(response.len(), 32);

        let response2 = prover.compute_challenge_response(&sector_info, 12345).await.unwrap();
        assert_eq!(response, response2);
    }
}
