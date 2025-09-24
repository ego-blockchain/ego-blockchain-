use super::{PoStEvent, PoStProof, PoStResult, WindowSchedule};
use crate::error::{PoCError, PoCResult};
use ego_core::{Address, Hash, Timestamp};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{debug, info, warn};

pub struct PoStVerifier {
    verifier_id: Address,
    verification_cache: Arc<RwLock<HashMap<Hash, PostVerificationResult>>>,
    window_assignments: Arc<RwLock<HashMap<Address, WindowSchedule>>>,
    verification_params: VerificationParams,
}

#[derive(Debug, Clone)]
pub struct PostVerificationResult {
    pub proof_hash: Hash,
    pub is_valid: bool,
    pub verification_time_ms: u64,
    pub verifier_id: Address,
    pub timestamp: Timestamp,
    pub partition_results: Vec<PartitionVerificationResult>,
}

#[derive(Debug, Clone)]
pub struct PartitionVerificationResult {
    pub partition_id: u64,
    pub challenges_verified: u32,
    pub responses_valid: u32,
    pub is_valid: bool,
}

#[derive(Debug, Clone)]
pub struct VerificationParams {
    pub max_verification_time_ms: u64,
    pub challenge_sampling_rate: f64,
    pub partition_failure_threshold: f64,
    pub cache_ttl_hours: u64,
}

impl PoStVerifier {
    pub fn new(verifier_id: Address) -> Self {
        let verification_params = VerificationParams {
            max_verification_time_ms: 30_000,
            challenge_sampling_rate: 0.1,
            partition_failure_threshold: 0.05,
            cache_ttl_hours: 24,
        };

        Self {
            verifier_id,
            verification_cache: Arc::new(RwLock::new(HashMap::new())),
            window_assignments: Arc::new(RwLock::new(HashMap::new())),
            verification_params,
        }
    }

    pub async fn start(&mut self) -> PoCResult<()> {
        info!("Starting PoSt verifier {}", self.verifier_id);

        self.start_cache_maintenance().await?;
        self.start_window_tracking().await?;

        info!("✅ PoSt verifier {} started successfully", self.verifier_id);
        Ok(())
    }

    pub async fn stop(&mut self) -> PoCResult<()> {
        info!("Stopping PoSt verifier {}", self.verifier_id);
        info!("✅ PoSt verifier {} stopped", self.verifier_id);
        Ok(())
    }

    pub async fn verify_post_event(&self, event: &PoStEvent) -> PoCResult<bool> {
        debug!(
            "Verifying PoSt event for node {} window {} (verifier {})",
            event.node_addr, event.window_id, self.verifier_id
        );

        event.validate()?;

        let verification_start = Timestamp::now();

        let proof_hash = self.compute_event_proof_hash(event);

        {
            let cache = self.verification_cache.read().unwrap();
            if let Some(cached_result) = cache.get(&proof_hash) {
                debug!("Using cached PoSt verification result");
                return Ok(cached_result.is_valid);
            }
        }

        let is_valid = match &event.result {
            PoStResult::Success => self.verify_successful_post(event).await?,
            PoStResult::PartialFailure { failed_partitions } => {
                self.verify_partial_failure(event, failed_partitions)
                    .await?
            }
            PoStResult::TotalFailure => self.verify_total_failure(event).await?,
            PoStResult::Timeout => self.verify_timeout(event).await?,
        };

        let verification_time_ms = Timestamp::now().as_millis() - verification_start.as_millis();

        let verification_result = PostVerificationResult {
            proof_hash,
            is_valid,
            verification_time_ms,
            verifier_id: self.verifier_id,
            timestamp: Timestamp::now(),
            partition_results: vec![],
        };

        {
            let mut cache = self.verification_cache.write().unwrap();
            cache.insert(proof_hash, verification_result);
        }

        info!(
            "✅ Verified PoSt event for window {} in {}ms: {} (verifier {})",
            event.window_id, verification_time_ms, is_valid, self.verifier_id
        );

        Ok(is_valid)
    }

    pub async fn verify_post_proof(&self, proof: &PoStProof) -> PoCResult<bool> {
        debug!(
            "Verifying PoSt proof for window {} (verifier {})",
            proof.window_id, self.verifier_id
        );

        proof.validate()?;

        let verification_start = Timestamp::now();
        let mut partition_results = Vec::new();

        for partition in &proof.partitions {
            let partition_result = self
                .verify_partition(partition, &proof.challenge_seed)
                .await?;
            partition_results.push(partition_result.clone());

            if !partition_result.is_valid {
                warn!("Partition {} verification failed", partition.partition_id);
            }
        }

        let failed_partitions = partition_results.iter().filter(|r| !r.is_valid).count();
        let total_partitions = partition_results.len();
        let failure_rate = failed_partitions as f64 / total_partitions as f64;

        let is_valid = failure_rate <= self.verification_params.partition_failure_threshold;

        let verification_time_ms = Timestamp::now().as_millis() - verification_start.as_millis();

        if verification_time_ms > self.verification_params.max_verification_time_ms {
            warn!(
                "PoSt verification took too long: {}ms",
                verification_time_ms
            );
            return Ok(false);
        }

        info!(
            "✅ Verified PoSt proof for window {} in {}ms: {} (verifier {})",
            proof.window_id, verification_time_ms, is_valid, self.verifier_id
        );

        Ok(is_valid)
    }

    async fn verify_successful_post(&self, event: &PoStEvent) -> PoCResult<bool> {
        if event.latency_ms > 1800_000 {
            return Ok(false);
        }

        if event.partitions_covered.is_empty() {
            return Ok(false);
        }

        let expected_schedule = self
            .get_expected_window_schedule(event.node_addr, event.epoch)
            .await?;
        let expected_window = expected_schedule
            .assigned_windows
            .iter()
            .find(|w| w.window_id == event.window_id);

        if let Some(window) = expected_window {
            let required_partitions: std::collections::HashSet<u64> =
                window.required_partitions.iter().cloned().collect();
            let covered_partitions: std::collections::HashSet<u64> =
                event.partitions_covered.iter().cloned().collect();

            Ok(required_partitions.is_subset(&covered_partitions))
        } else {
            Ok(false)
        }
    }

    async fn verify_partial_failure(
        &self,
        event: &PoStEvent,
        failed_partitions: &[u64],
    ) -> PoCResult<bool> {
        if failed_partitions.is_empty() {
            return Ok(false);
        }

        let total_partitions = event.partitions_covered.len() + failed_partitions.len();
        let failure_rate = failed_partitions.len() as f64 / total_partitions as f64;

        Ok(
            failure_rate <= self.verification_params.partition_failure_threshold
                && failure_rate > 0.0,
        )
    }

    async fn verify_total_failure(&self, _event: &PoStEvent) -> PoCResult<bool> {
        Ok(true)
    }

    async fn verify_timeout(&self, event: &PoStEvent) -> PoCResult<bool> {
        Ok(event.latency_ms >= 1800_000)
    }

    async fn verify_partition(
        &self,
        partition: &super::PartitionProof,
        challenge_seed: &Hash,
    ) -> PoCResult<PartitionVerificationResult> {
        let challenges_to_verify = (partition.challenges.len() as f64
            * self.verification_params.challenge_sampling_rate)
            .max(1.0) as usize;
        let mut verified_challenges = 0;
        let mut valid_responses = 0;

        for i in 0..challenges_to_verify {
            let challenge_idx = i % partition.challenges.len();
            let challenge = partition.challenges[challenge_idx];
            let response = partition.responses[challenge_idx];

            let expected_response = self
                .compute_expected_response(&partition.sector_ids, challenge)
                .await?;

            verified_challenges += 1;
            if expected_response == response {
                valid_responses += 1;
            }
        }

        let success_rate = valid_responses as f64 / verified_challenges as f64;
        let is_valid = success_rate >= 0.9;

        Ok(PartitionVerificationResult {
            partition_id: partition.partition_id,
            challenges_verified: verified_challenges as u32,
            responses_valid: valid_responses as u32,
            is_valid,
        })
    }

    async fn compute_expected_response(
        &self,
        sector_ids: &[u64],
        challenge: u64,
    ) -> PoCResult<[u8; 32]> {
        use ego_core::crypto::hash_multiple;

        let mut inputs = vec![&challenge.to_le_bytes()];
        for &sector_id in sector_ids {
            inputs.push(&sector_id.to_le_bytes());
        }

        let response_hash = hash_multiple(&inputs);
        Ok(response_hash.as_bytes().try_into().unwrap())
    }

    async fn get_expected_window_schedule(
        &self,
        node_addr: Address,
        epoch: u64,
    ) -> PoCResult<WindowSchedule> {
        {
            let assignments = self.window_assignments.read().unwrap();
            if let Some(schedule) = assignments.get(&node_addr) {
                if schedule.epoch == epoch {
                    return Ok(schedule.clone());
                }
            }
        }

        let schedule = WindowSchedule::generate_deterministic_schedule(node_addr, epoch, 1000, 48);

        {
            let mut assignments = self.window_assignments.write().unwrap();
            assignments.insert(node_addr, schedule.clone());
        }

        Ok(schedule)
    }

    fn compute_event_proof_hash(&self, event: &PoStEvent) -> Hash {
        use ego_core::crypto::hash_multiple;

        hash_multiple(&[
            event.node_addr.as_bytes(),
            &event.epoch.to_le_bytes(),
            &event.window_id.to_le_bytes(),
            event.challenges_root.as_bytes(),
            event.post_agg_proof_hash.as_bytes(),
        ])
    }

    async fn start_cache_maintenance(&self) -> PoCResult<()> {
        let verification_cache = self.verification_cache.clone();
        let cache_ttl_hours = self.verification_params.cache_ttl_hours;
        let verifier_id = self.verifier_id;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));

            loop {
                interval.tick().await;

                let mut cache = verification_cache.write().unwrap();
                let now = Timestamp::now();
                let ttl_ms = cache_ttl_hours * 3_600_000;

                cache.retain(|_, result| now.as_millis() - result.timestamp.as_millis() < ttl_ms);

                debug!(
                    "Cache maintenance completed, {} entries remaining (verifier {})",
                    cache.len(),
                    verifier_id
                );
            }
        });

        Ok(())
    }

    async fn start_window_tracking(&self) -> PoCResult<()> {
        let window_assignments = self.window_assignments.clone();
        let verifier_id = self.verifier_id;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));

            loop {
                interval.tick().await;

                let mut assignments = window_assignments.write().unwrap();
                let current_epoch = Timestamp::now().as_secs() / 3600;

                assignments
                    .retain(|_, schedule| schedule.epoch >= current_epoch.saturating_sub(24));

                debug!(
                    "Window tracking updated, {} node schedules active (verifier {})",
                    assignments.len(),
                    verifier_id
                );
            }
        });

        Ok(())
    }

    pub fn get_verification_stats(&self) -> PostVerificationStats {
        let cache = self.verification_cache.read().unwrap();

        let total_verifications = cache.len() as u64;
        let valid_proofs = cache.values().filter(|r| r.is_valid).count() as u64;
        let avg_verification_time = if total_verifications > 0 {
            cache.values().map(|r| r.verification_time_ms).sum::<u64>() / total_verifications
        } else {
            0
        };

        PostVerificationStats {
            total_verifications,
            valid_proofs,
            invalid_proofs: total_verifications - valid_proofs,
            avg_verification_time_ms: avg_verification_time,
            cache_size: cache.len() as u32,
            last_updated: Timestamp::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostVerificationStats {
    pub total_verifications: u64,
    pub valid_proofs: u64,
    pub invalid_proofs: u64,
    pub avg_verification_time_ms: u64,
    pub cache_size: u32,
    pub last_updated: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_post_verifier_creation() {
        let verifier = PoStVerifier::new(Address::new([1u8; 20]));
        assert_eq!(verifier.verifier_id, Address::new([1u8; 20]));
        assert_eq!(
            verifier.verification_params.max_verification_time_ms,
            30_000
        );
    }

    #[tokio::test]
    async fn test_post_event_verification() {
        let mut verifier = PoStVerifier::new(Address::new([1u8; 20]));
        verifier.start().await.unwrap();

        let event = PoStEvent::new(
            Address::new([2u8; 20]),
            100,
            1,
            vec![1, 2, 3],
            Hash::new([3u8; 32]),
            Hash::new([4u8; 32]),
            PoStResult::Success,
            5000,
        );

        let result = verifier.verify_post_event(&event).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verification_caching() {
        let verifier = PoStVerifier::new(Address::new([1u8; 20]));

        let event = PoStEvent::new(
            Address::new([2u8; 20]),
            100,
            1,
            vec![1, 2, 3],
            Hash::new([3u8; 32]),
            Hash::new([4u8; 32]),
            PoStResult::Success,
            5000,
        );

        let result1 = verifier.verify_post_event(&event).await.unwrap();
        let result2 = verifier.verify_post_event(&event).await.unwrap();

        assert_eq!(result1, result2);

        let cache = verifier.verification_cache.read().unwrap();
        assert_eq!(cache.len(), 1);
    }
}
