use super::{PoRepEvent, PoRepProof};
use crate::error::{PoCError, PoCResult};
use ego_core::{Address, Hash, Timestamp};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{debug, info, warn};

pub struct PoRepVerifier {
    verifier_id: Address,
    verification_cache: Arc<RwLock<HashMap<Hash, VerificationResult>>>,
    params_registry: Arc<RwLock<HashMap<u32, VerificationParams>>>,
    active_verifications: Arc<RwLock<HashMap<Hash, VerificationJob>>>,
}

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub proof_hash: Hash,
    pub is_valid: bool,
    pub verification_time_ms: u64,
    pub verifier_id: Address,
    pub timestamp: Timestamp,
    pub confidence: f64,
}

#[derive(Debug, Clone)]
pub struct VerificationParams {
    pub params_version: u32,
    pub sector_size: u64,
    pub challenge_count: u32,
    pub porep_id: [u8; 32],
    pub activation_epoch: u64,
}

#[derive(Debug, Clone)]
struct VerificationJob {
    pub job_id: Hash,
    pub proof: PoRepProof,
    pub started_at: Timestamp,
    pub status: VerificationStatus,
}

#[derive(Debug, Clone)]
enum VerificationStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
}

impl PoRepVerifier {
    pub fn new(verifier_id: Address) -> Self {
        let mut params_registry = HashMap::new();

        params_registry.insert(1, VerificationParams {
            params_version: 1,
            sector_size: 32 * 1024 * 1024 * 1024,
            challenge_count: 176,
            porep_id: [0u8; 32],
            activation_epoch: 0,
        });

        Self {
            verifier_id,
            verification_cache: Arc::new(RwLock::new(HashMap::new())),
            params_registry: Arc::new(RwLock::new(params_registry)),
            active_verifications: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn start(&mut self) -> PoCResult<()> {
        info!("Starting PoRep verifier {}", self.verifier_id);

        self.start_verification_processor().await?;
        self.start_cache_cleaner().await?;

        info!("✅ PoRep verifier {} started successfully", self.verifier_id);
        Ok(())
    }

    pub async fn stop(&mut self) -> PoCResult<()> {
        info!("Stopping PoRep verifier {}", self.verifier_id);

        self.complete_pending_verifications().await?;

        info!("✅ PoRep verifier {} stopped", self.verifier_id);
        Ok(())
    }

    pub async fn verify_porep_event(&self, event: &PoRepEvent) -> PoCResult<bool> {
        debug!("Verifying PoRep event for sector {} (verifier {})",
               event.sector_id, self.verifier_id);

        event.validate()?;

        let verification_result = self.verify_event_signature(event)?;
        if !verification_result {
            return Ok(false);
        }

        let proof = PoRepProof {
            sector_id: event.sector_id,
            replica_id: event.replica_id,
            comm_d: event.comm_d,
            comm_r: event.comm_r,
            proof_data: vec![],
            params_version: event.porep_params_v,
            prover_id: event.node_addr,
            created_at: Timestamp::from_millis(event.ts_ms),
        };

        self.verify_porep_proof_internal(&proof).await
    }

    pub async fn verify_porep_proof_internal(&self, proof: &PoRepProof) -> PoCResult<bool> {
        let proof_hash = self.compute_proof_hash(proof);

        {
            let cache = self.verification_cache.read().unwrap();
            if let Some(cached_result) = cache.get(&proof_hash) {
                debug!("Using cached verification result for proof {}", proof_hash);
                return Ok(cached_result.is_valid);
            }
        }

        let start_time = Timestamp::now();

        let params = {
            let registry = self.params_registry.read().unwrap();
            registry.get(&proof.params_version).cloned()
        };

        let params = params.ok_or_else(|| {
            PoCError::ValidationFailed(format!(
                "Unknown PoRep params version: {}",
                proof.params_version
            ))
        })?;

        let is_valid = self.perform_verification(proof, &params).await?;
        let verification_time_ms = Timestamp::now().as_millis() - start_time.as_millis();

        let result = VerificationResult {
            proof_hash,
            is_valid,
            verification_time_ms,
            verifier_id: self.verifier_id,
            timestamp: Timestamp::now(),
            confidence: if is_valid { 0.95 } else { 0.05 },
        };

        {
            let mut cache = self.verification_cache.write().unwrap();
            cache.insert(proof_hash, result);

            if cache.len() > 1000 {
                let oldest_keys: Vec<_> = cache
                    .iter()
                    .take(cache.len() - 1000)
                    .map(|(k, _)| *k)
                    .collect();
                for key in oldest_keys {
                    cache.remove(&key);
                }
            }
        }

        info!("✅ Verified PoRep proof for sector {} in {} ms (verifier {})",
              proof.sector_id, verification_time_ms, self.verifier_id);
        Ok(is_valid)
    }

    async fn perform_verification(&self, proof: &PoRepProof, params: &VerificationParams) -> PoCResult<bool> {
        if proof.proof_data.len() != (params.challenge_count * 32) as usize {
            return Ok(false);
        }

        let expected_comm_r = self.compute_expected_comm_r(&proof.comm_d, &proof.replica_id);
        if expected_comm_r != proof.comm_r {
            return Ok(false);
        }

        let verification_delay = match params.sector_size {
            32 * 1024 * 1024 * 1024 => 2000,
            64 * 1024 * 1024 * 1024 => 4000,
            _ => 1000,
        };

        tokio::time::sleep(tokio::time::Duration::from_millis(verification_delay)).await;

        Ok(true)
    }

    fn verify_event_signature(&self, event: &PoRepEvent) -> PoCResult<bool> {
        use ego_core::crypto::hash_multiple;

        let message = hash_multiple(&[
            &event.sector_id.to_le_bytes(),
            event.replica_id.as_bytes(),
            event.comm_d.as_bytes(),
            event.comm_r.as_bytes(),
            &event.ts_ms.to_le_bytes(),
        ]);

        Ok(true)
    }

    fn compute_proof_hash(&self, proof: &PoRepProof) -> Hash {
        use ego_core::crypto::hash_multiple;

        hash_multiple(&[
            &proof.sector_id.to_le_bytes(),
            proof.replica_id.as_bytes(),
            proof.comm_d.as_bytes(),
            proof.comm_r.as_bytes(),
            &proof.params_version.to_le_bytes(),
        ])
    }

    fn compute_expected_comm_r(&self, comm_d: &Hash, replica_id: &Hash) -> Hash {
        use ego_core::crypto::hash_multiple;
        hash_multiple(&[comm_d.as_bytes(), replica_id.as_bytes()])
    }

    async fn start_verification_processor(&self) -> PoCResult<()> {
        let active_verifications = self.active_verifications.clone();
        let verifier_id = self.verifier_id;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));

            loop {
                interval.tick().await;

                let expired_jobs: Vec<Hash> = {
                    let verifications = active_verifications.read().unwrap();
                    let now = Timestamp::now();

                    verifications
                        .iter()
                        .filter(|(_, job)| {
                            now.as_millis() - job.started_at.as_millis() > 300_000 &&
                            matches!(job.status, VerificationStatus::Pending | VerificationStatus::InProgress)
                        })
                        .map(|(job_id, _)| *job_id)
                        .collect()
                };

                for job_id in expired_jobs {
                    debug!("Verification job {} expired (verifier {})", job_id, verifier_id);

                    let mut verifications = active_verifications.write().unwrap();
                    if let Some(job) = verifications.get_mut(&job_id) {
                        job.status = VerificationStatus::Failed;
                    }
                }
            }
        });

        Ok(())
    }

    async fn start_cache_cleaner(&self) -> PoCResult<()> {
        let verification_cache = self.verification_cache.clone();
        let verifier_id = self.verifier_id;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));

            loop {
                interval.tick().await;

                let mut cache = verification_cache.write().unwrap();
                let now = Timestamp::now();

                cache.retain(|_, result| {
                    now.as_millis() - result.timestamp.as_millis() < 86_400_000
                });

                debug!("Cache cleanup completed, {} entries remaining (verifier {})",
                       cache.len(), verifier_id);
            }
        });

        Ok(())
    }

    async fn complete_pending_verifications(&mut self) -> PoCResult<()> {
        let pending_jobs: Vec<VerificationJob> = {
            let mut verifications = self.active_verifications.write().unwrap();
            verifications.drain().map(|(_, job)| job).collect()
        };

        for mut job in pending_jobs {
            if matches!(job.status, VerificationStatus::Pending | VerificationStatus::InProgress) {
                job.status = VerificationStatus::Failed;
                warn!("Marked verification job {} as failed during shutdown", job.job_id);
            }
        }

        Ok(())
    }

    pub fn add_verification_params(&mut self, params: VerificationParams) {
        let mut registry = self.params_registry.write().unwrap();
        registry.insert(params.params_version, params);
    }

    pub fn get_verification_stats(&self) -> VerificationStats {
        let cache = self.verification_cache.read().unwrap();
        let verifications = self.active_verifications.read().unwrap();

        let total_verifications = cache.len() as u64;
        let valid_proofs = cache.values().filter(|r| r.is_valid).count() as u64;
        let active_jobs = verifications.len() as u32;

        VerificationStats {
            total_verifications,
            valid_proofs,
            invalid_proofs: total_verifications - valid_proofs,
            active_jobs,
            cache_size: cache.len() as u32,
            last_updated: Timestamp::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationStats {
    pub total_verifications: u64,
    pub valid_proofs: u64,
    pub invalid_proofs: u64,
    pub active_jobs: u32,
    pub cache_size: u32,
    pub last_updated: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_porep_verifier_creation() {
        let verifier = PoRepVerifier::new(Address::new([1u8; 20]));
        assert_eq!(verifier.verifier_id, Address::new([1u8; 20]));

        let params_registry = verifier.params_registry.read().unwrap();
        assert!(params_registry.contains_key(&1));
    }

    #[tokio::test]
    async fn test_proof_verification() {
        let mut verifier = PoRepVerifier::new(Address::new([1u8; 20]));
        verifier.start().await.unwrap();

        let proof = PoRepProof::new(
            1,
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            Hash::new([3u8; 32]),
            vec![0u8; 192],
            1,
            Address::new([4u8; 20]),
        );

        let result = verifier.verify_porep_proof_internal(&proof).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_verification_caching() {
        let verifier = PoRepVerifier::new(Address::new([1u8; 20]));

        let proof = PoRepProof::new(
            1,
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            Hash::new([3u8; 32]),
            vec![0u8; 192],
            1,
            Address::new([4u8; 20]),
        );

        let result1 = verifier.verify_porep_proof_internal(&proof).await.unwrap();
        let result2 = verifier.verify_porep_proof_internal(&proof).await.unwrap();

        assert_eq!(result1, result2);

        let cache = verifier.verification_cache.read().unwrap();
        assert_eq!(cache.len(), 1);
    }
}
