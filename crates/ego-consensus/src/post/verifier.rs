use super::{PartitionProof, PoStEvent, PoStMetrics, PoStProof, PoStResult, PoStWindow};
use crate::error::{PoCError, PoCResult};
use ego_core::{Address, Hash, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{debug, info, warn};

pub struct PoStVerifier {
    verifier_id: Address,
    verification_cache: Arc<RwLock<HashMap<Hash, VerificationResult>>>,
    params_registry: Arc<RwLock<HashMap<u32, VerificationParams>>>,
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
    pub activation_epoch: u64,
}

impl PoStVerifier {
    pub fn new(verifier_id: Address) -> Self {
        let mut params_registry = HashMap::new();
        params_registry.insert(1, VerificationParams {
            params_version: 1,
            sector_size: 32 * 1024 * 1024 * 1024,
            challenge_count: 2,
            activation_epoch: 0,
        });

        Self {
            verifier_id,
            verification_cache: Arc::new(RwLock::new(HashMap::new())),
            params_registry: Arc::new(RwLock::new(params_registry)),
        }
    }

    pub async fn start(&mut self) -> PoCResult<()> {
        info!("Starting PoSt verifier {}", self.verifier_id);
        self.start_cache_cleaner().await?;
        info!("✅ PoSt verifier {} started", self.verifier_id);
        Ok(())
    }

    pub async fn verify_post_event(&self, event: &PoStEvent) -> PoCResult<bool> {
        debug!("Verifying PoSt event for window {} (verifier {})",
               event.window_id, self.verifier_id);

        event.validate()?;

        match &event.result {
            PoStResult::Pass => self.verify_successful_post(event).await,
            PoStResult::Miss => {

                debug!("PoSt miss recorded for window {} node {}",
                       event.window_id, event.node_addr);
                Ok(true)
            }
            PoStResult::Fault => self.verify_faulted_post(event).await,
        }
    }

    async fn verify_successful_post(&self, event: &PoStEvent) -> PoCResult<bool> {
        if event.proof_hash == Hash::new([0u8; 32]) {
            return Ok(false);
        }

        if event.partition_ids.is_empty() {
            return Ok(false);
        }

        if event.latency_ms > 3_600_000 {
            warn!("PoSt proof latency implausibly high: {} ms", event.latency_ms);
            return Ok(false);
        }

        Ok(true)
    }

    async fn verify_faulted_post(&self, event: &PoStEvent) -> PoCResult<bool> {

        debug!("PoSt fault recorded for window {} node {}",
               event.window_id, event.node_addr);
        Ok(true)
    }

    pub async fn verify_post_proof(&self, proof: &PoStProof) -> PoCResult<bool> {
        debug!("Verifying PoSt proof for window {} (verifier {})",
               proof.window_id, self.verifier_id);

        proof.validate()?;

        let proof_hash = self.compute_proof_hash(proof);

        {
            let cache = self.verification_cache.read().unwrap();
            if let Some(cached) = cache.get(&proof_hash) {
                return Ok(cached.is_valid);
            }
        }

        let start_time = Timestamp::now();
        let is_valid = self.perform_proof_verification(proof).await?;
        let verification_time_ms = Timestamp::now().as_millis() - start_time.as_millis();

        {
            let mut cache = self.verification_cache.write().unwrap();
            cache.insert(proof_hash, VerificationResult {
                proof_hash,
                is_valid,
                verification_time_ms,
                verifier_id: self.verifier_id,
                timestamp: Timestamp::now(),
                confidence: if is_valid { 0.95 } else { 0.05 },
            });

            if cache.len() > 1000 {
                let oldest: Vec<_> = cache.iter()
                    .take(cache.len() - 1000)
                    .map(|(k, _)| *k)
                    .collect();
                for k in oldest { cache.remove(&k); }
            }
        }

        info!("✅ Verified PoSt proof for window {} in {} ms (verifier {})",
              proof.window_id, verification_time_ms, self.verifier_id);
        Ok(is_valid)
    }

    async fn perform_proof_verification(&self, proof: &PoStProof) -> PoCResult<bool> {
        for partition in &proof.partitions {
            if !self.verify_partition_proof(partition, &proof.challenge_seed).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn verify_partition_proof(
        &self,
        partition: &PartitionProof,
        _challenge_seed: &Hash,
    ) -> PoCResult<bool> {
        if partition.challenges.len() != partition.responses.len() {
            return Ok(false);
        }

        for (i, &challenge) in partition.challenges.iter().enumerate() {
            let expected = Self::compute_challenge_response(&partition.sector_ids, challenge).await?;
            if expected != partition.responses[i] {
                return Ok(false);
            }
        }

        Ok(true)
    }

    async fn compute_challenge_response(sector_ids: &[u64], challenge: u64) -> PoCResult<[u8; 32]> {
        use ego_core::crypto::hash_multiple;

        let challenge_bytes = challenge.to_le_bytes();
        let sector_bytes: Vec<[u8; 8]> = sector_ids.iter().map(|s| s.to_le_bytes()).collect();

        let mut inputs: Vec<&[u8]> = vec![&challenge_bytes];
        for b in &sector_bytes {
            inputs.push(b.as_slice());
        }

        let response_hash = hash_multiple(&inputs);
        let bytes: &[u8] = response_hash.as_bytes();
        bytes[..32].try_into().map_err(|_| {
            PoCError::InternalError("Hash slice conversion failed".to_string())
        })
    }

    fn compute_proof_hash(&self, proof: &PoStProof) -> Hash {
        use ego_core::crypto::hash_multiple;
        hash_multiple(&[
            proof.prover_id.as_bytes(),
            &proof.epoch.to_le_bytes(),
            &proof.window_id.to_le_bytes(),
            proof.challenge_seed.as_bytes(),
        ])
    }

    async fn start_cache_cleaner(&self) -> PoCResult<()> {
        let cache = self.verification_cache.clone();
        let verifier_id = self.verifier_id;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                let mut cache_lock = cache.write().unwrap();
                let now = Timestamp::now();
                cache_lock.retain(|_, result| {
                    now.as_millis() - result.timestamp.as_millis() < 86_400_000
                });
                debug!("Cache cleanup done, {} entries remain (verifier {})",
                       cache_lock.len(), verifier_id);
            }
        });

        Ok(())
    }

    pub fn get_verification_stats(&self) -> VerificationStats {
        let cache = self.verification_cache.read().unwrap();
        let total = cache.len() as u64;
        let valid = cache.values().filter(|r| r.is_valid).count() as u64;

        VerificationStats {
            total_verifications: total,
            valid_proofs: valid,
            invalid_proofs: total - valid,
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
    pub cache_size: u32,
    pub last_updated: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::post::{PartitionProof, PoStProof};
    use ego_core::{Address, Hash};

    #[tokio::test]
    async fn test_post_verifier_creation() {
        let verifier = PoStVerifier::new(Address::new([1u8; 20]));
        assert_eq!(verifier.verifier_id, Address::new([1u8; 20]));
    }

    #[tokio::test]
    async fn test_proof_verification() {
        let verifier = PoStVerifier::new(Address::new([1u8; 20]));

        let sector_ids = vec![1u64, 2u64];
        let challenges = vec![100u64, 200u64];
        let responses = vec![
            PoStVerifier::compute_challenge_response(&sector_ids, 100).await.unwrap(),
            PoStVerifier::compute_challenge_response(&sector_ids, 200).await.unwrap(),
        ];

        let proof = PoStProof::new(
            Address::new([2u8; 20]),
            5,
            1,
            vec![PartitionProof { partition_id: 0, sector_ids, challenges, responses }],
            Hash::new([9u8; 32]),
        );

        let result = verifier.verify_post_proof(&proof).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_verification_caching() {
        let verifier = PoStVerifier::new(Address::new([1u8; 20]));

        let proof = PoStProof::new(
            Address::new([2u8; 20]),
            5,
            1,
            vec![PartitionProof {
                partition_id: 0,
                sector_ids: vec![1],
                challenges: vec![42],
                responses: vec![
                    PoStVerifier::compute_challenge_response(&[1], 42).await.unwrap(),
                ],
            }],
            Hash::new([9u8; 32]),
        );

        let r1 = verifier.verify_post_proof(&proof).await.unwrap();
        let r2 = verifier.verify_post_proof(&proof).await.unwrap();
        assert_eq!(r1, r2);

        let cache = verifier.verification_cache.read().unwrap();
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test]
    async fn test_post_event_verification() {
        let verifier = PoStVerifier::new(Address::new([1u8; 20]));

        let event = crate::post::PoStEvent::new(
            Address::new([2u8; 20]),
            10,
            3,
            vec![0, 1],
            Hash::new([5u8; 32]),
            Hash::new([6u8; 32]),
            PoStResult::Pass,
            3_000,
        );

        let result = verifier.verify_post_event(&event).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_miss_event_verification() {
        let verifier = PoStVerifier::new(Address::new([1u8; 20]));

        let event = crate::post::PoStEvent::new(
            Address::new([2u8; 20]),
            10,
            3,
            vec![0, 1],
            Hash::new([5u8; 32]),
            Hash::new([0u8; 32]),
            PoStResult::Miss,
            0,
        );

        let result = verifier.verify_post_event(&event).await.unwrap();
        assert!(result);
    }
}
