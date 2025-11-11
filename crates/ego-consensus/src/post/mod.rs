use crate::error::PoCResult;
use ego_core::{Address, Hash, Signature, Timestamp};
use serde::{Deserialize, Serialize};
use std::future::Future;

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PoStEvent {
    pub node_addr: Address,
    pub epoch: u64,
    pub window_id: u64,
    pub partitions_covered: Vec<u64>,
    pub challenges_root: Hash,
    pub post_agg_proof_hash: Hash,
    pub result: PoStResult,
    pub latency_ms: u64,
    pub alg_sig_id: u8,
    pub node_sig: Signature,
    pub cid_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PoStProof {
    pub prover_id: Address,
    pub epoch: u64,
    pub window_id: u64,
    pub partitions: Vec<PartitionProof>,
    pub challenge_seed: Hash,
    pub proof_data: Vec<u8>,
    pub created_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PartitionProof {
    pub partition_id: u64,
    pub sector_ids: Vec<u64>,
    pub challenges: Vec<u64>,
    pub responses: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum PoStResult {
    Success,
    PartialFailure { failed_partitions: Vec<u64> },
    TotalFailure,
    Timeout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoStWindow {
    pub window_id: u64,
    pub epoch: u64,
    pub start_time: Timestamp,
    pub end_time: Timestamp,
    pub challenge_seed: Hash,
    pub required_partitions: Vec<u64>,
    pub submitted_proofs: Vec<Hash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowSchedule {
    pub node_addr: Address,
    pub epoch: u64,
    pub assigned_windows: Vec<PoStWindow>,
    pub windows_per_day: u32,
    pub partition_size: u32,
}

pub trait PoStProvider: Send + Sync {
    fn provider_id(&self) -> Address;

    fn generate_post_proof(
        &self,
        window: &PoStWindow,
    ) -> impl Future<Output = PoCResult<PoStProof>> + Send;

    fn verify_post_proof(&self, proof: &PoStProof) -> impl Future<Output = PoCResult<bool>> + Send;

    fn get_window_assignment(
        &self,
        epoch: u64,
    ) -> impl Future<Output = PoCResult<WindowSchedule>> + Send;

    fn get_proving_metrics(&self) -> PoStMetrics;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoStMetrics {
    pub windows_proven: u64,
    pub windows_missed: u64,
    pub avg_latency_ms: f64,
    pub p50_latency_ms: u64,
    pub p95_latency_ms: u64,
    pub partition_failures: u32,
    pub last_updated: Timestamp,
}

impl PoStEvent {
    pub fn new(
        node_addr: Address,
        epoch: u64,
        window_id: u64,
        partitions_covered: Vec<u64>,
        challenges_root: Hash,
        post_agg_proof_hash: Hash,
        result: PoStResult,
        latency_ms: u64,
    ) -> Self {
        Self {
            node_addr,
            epoch,
            window_id,
            partitions_covered,
            challenges_root,
            post_agg_proof_hash,
            result,
            latency_ms,
            alg_sig_id: 1,
            node_sig: Signature::ed25519([0u8; 64]),
            cid_hint: None,
        }
    }

    pub fn validate(&self) -> PoCResult<()> {
        if self.partitions_covered.is_empty() {
            return Err(crate::error::PoCError::ValidationFailed(
                "PoSt event must cover at least one partition".to_string(),
            ));
        }

        if self.window_id == 0 {
            return Err(crate::error::PoCError::ValidationFailed(
                "Invalid window ID".to_string(),
            ));
        }

        if self.latency_ms > 1800_000 {
            return Err(crate::error::PoCError::ValidationFailed(
                "PoSt latency exceeds maximum allowed time".to_string(),
            ));
        }

        Ok(())
    }
}

impl PoStProof {
    pub fn new(
        prover_id: Address,
        epoch: u64,
        window_id: u64,
        partitions: Vec<PartitionProof>,
        challenge_seed: Hash,
    ) -> Self {
        let proof_data = Self::aggregate_partition_proofs(&partitions);

        Self {
            prover_id,
            epoch,
            window_id,
            partitions,
            challenge_seed,
            proof_data,
            created_at: Timestamp::now(),
        }
    }

    pub fn validate(&self) -> PoCResult<()> {
        if self.partitions.is_empty() {
            return Err(crate::error::PoCError::ValidationFailed(
                "PoSt proof must have at least one partition".to_string(),
            ));
        }

        for partition in &self.partitions {
            if partition.sector_ids.is_empty() {
                return Err(crate::error::PoCError::ValidationFailed(
                    "Partition must have at least one sector".to_string(),
                ));
            }

            if partition.challenges.len() != partition.responses.len() {
                return Err(crate::error::PoCError::ValidationFailed(
                    "Challenge/response count mismatch".to_string(),
                ));
            }
        }

        Ok(())
    }

    fn aggregate_partition_proofs(partitions: &[PartitionProof]) -> Vec<u8> {
        let mut aggregated = Vec::new();

        for partition in partitions {
            aggregated.extend_from_slice(&partition.partition_id.to_le_bytes());

            for response in &partition.responses {
                aggregated.extend_from_slice(response);
            }
        }

        aggregated
    }
}

impl PoStWindow {
    pub fn new(
        window_id: u64,
        epoch: u64,
        duration_ms: u64,
        required_partitions: Vec<u64>,
    ) -> Self {
        let start_time = Timestamp::now();
        let end_time = Timestamp::from_millis(start_time.as_millis() + duration_ms);

        let challenge_seed = Self::generate_window_challenge_seed(epoch, window_id);

        Self {
            window_id,
            epoch,
            start_time,
            end_time,
            challenge_seed,
            required_partitions,
            submitted_proofs: Vec::new(),
        }
    }

    pub fn is_active(&self) -> bool {
        let now = Timestamp::now();
        now >= self.start_time && now <= self.end_time
    }

    pub fn is_expired(&self) -> bool {
        Timestamp::now() > self.end_time
    }

    pub fn generate_partition_challenges(&self, partition_id: u64, sector_count: u32) -> Vec<u64> {
        use ego_core::crypto::hash_data;

        let mut challenges = Vec::new();
        let challenges_per_sector: u32 = 10;

        for sector_idx in 0..sector_count {
            for challenge_idx in 0..challenges_per_sector {
                let mut data = Vec::new();
                data.extend_from_slice(self.challenge_seed.as_bytes());
                data.extend_from_slice(&partition_id.to_le_bytes());
                data.extend_from_slice(&sector_idx.to_le_bytes());
                data.extend_from_slice(&challenge_idx.to_le_bytes());

                let challenge_hash = hash_data(&data);

                let challenge_bytes = challenge_hash.as_bytes();
                let challenge_value = u64::from_le_bytes([
                    challenge_bytes[0],
                    challenge_bytes[1],
                    challenge_bytes[2],
                    challenge_bytes[3],
                    challenge_bytes[4],
                    challenge_bytes[5],
                    challenge_bytes[6],
                    challenge_bytes[7],
                ]);

                challenges.push(challenge_value);
            }
        }

        challenges
    }

    fn generate_window_challenge_seed(epoch: u64, window_id: u64) -> Hash {
        use ego_core::crypto::hash_data;

        let mut data = Vec::new();
        data.extend_from_slice(&epoch.to_le_bytes());
        data.extend_from_slice(&window_id.to_le_bytes());
        data.extend_from_slice(b"post_challenge_seed");

        hash_data(&data)
    }
}

impl WindowSchedule {
    pub fn generate_deterministic_schedule(
        node_addr: Address,
        epoch: u64,
        total_sectors: u32,
        windows_per_day: u32,
    ) -> Self {
        let partition_size = total_sectors / windows_per_day;
        let mut assigned_windows = Vec::new();

        for window_idx in 0..windows_per_day {
            let window_id = Self::compute_window_id(node_addr, epoch, window_idx);
            let start_partition = window_idx * partition_size;
            let end_partition = ((window_idx + 1) * partition_size).min(total_sectors);

            let required_partitions: Vec<u64> =
                (start_partition..end_partition).map(|i| i as u64).collect();

            let window = PoStWindow::new(window_id, epoch, 1800_000, required_partitions);

            assigned_windows.push(window);
        }

        Self {
            node_addr,
            epoch,
            assigned_windows,
            windows_per_day,
            partition_size,
        }
    }

    fn compute_window_id(node_addr: Address, epoch: u64, window_idx: u32) -> u64 {
        use ego_core::crypto::hash_data;

        let mut data = Vec::new();
        data.extend_from_slice(node_addr.as_bytes());
        data.extend_from_slice(&epoch.to_le_bytes());
        data.extend_from_slice(&window_idx.to_le_bytes());

        let window_hash = hash_data(&data);

        let hash_bytes = window_hash.as_bytes();
        u64::from_le_bytes([
            hash_bytes[0],
            hash_bytes[1],
            hash_bytes[2],
            hash_bytes[3],
            hash_bytes[4],
            hash_bytes[5],
            hash_bytes[6],
            hash_bytes[7],
        ])
    }
}

impl PartialEq for PoStEvent {
    fn eq(&self, other: &Self) -> bool {
        self.node_addr == other.node_addr
            && self.epoch == other.epoch
            && self.window_id == other.window_id
    }
}

impl Eq for PoStEvent {}

impl PartialEq for PoStProof {
    fn eq(&self, other: &Self) -> bool {
        self.prover_id == other.prover_id
            && self.epoch == other.epoch
            && self.window_id == other.window_id
            && self.challenge_seed == other.challenge_seed
    }
}

impl Eq for PoStProof {}

impl PartialEq for PoStResult {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (PoStResult::Success, PoStResult::Success) => true,
            (PoStResult::TotalFailure, PoStResult::TotalFailure) => true,
            (PoStResult::Timeout, PoStResult::Timeout) => true,
            (
                PoStResult::PartialFailure {
                    failed_partitions: f1,
                },
                PoStResult::PartialFailure {
                    failed_partitions: f2,
                },
            ) => f1 == f2,
            _ => false,
        }
    }
}

impl Eq for PoStResult {}

impl Default for PoStMetrics {
    fn default() -> Self {
        Self {
            windows_proven: 0,
            windows_missed: 0,
            avg_latency_ms: 0.0,
            p50_latency_ms: 0,
            p95_latency_ms: 0,
            partition_failures: 0,
            last_updated: Timestamp::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_post_event_creation() {
        let event = PoStEvent::new(
            Address::new([1u8; 20]),
            100,
            1,
            vec![1, 2, 3],
            Hash::new([2u8; 32]),
            Hash::new([3u8; 32]),
            PoStResult::Success,
            5000,
        );

        assert_eq!(event.epoch, 100);
        assert_eq!(event.partitions_covered.len(), 3);
        assert!(event.validate().is_ok());
    }

    #[test]
    fn test_window_schedule_generation() {
        let schedule =
            WindowSchedule::generate_deterministic_schedule(Address::new([1u8; 20]), 100, 1000, 48);

        assert_eq!(schedule.assigned_windows.len(), 48);
        assert_eq!(schedule.windows_per_day, 48);

        let schedule2 =
            WindowSchedule::generate_deterministic_schedule(Address::new([1u8; 20]), 100, 1000, 48);

        assert_eq!(
            schedule.assigned_windows.len(),
            schedule2.assigned_windows.len()
        );
    }

    #[test]
    fn test_post_window_challenges() {
        let window = PoStWindow::new(1, 100, 1800_000, vec![1, 2, 3]);

        let challenges1 = window.generate_partition_challenges(1, 10);
        let challenges2 = window.generate_partition_challenges(1, 10);

        assert_eq!(challenges1, challenges2);
        assert_eq!(challenges1.len(), 100);
    }

    #[test]
    fn test_post_proof_validation() {
        let partitions = vec![PartitionProof {
            partition_id: 1,
            sector_ids: vec![1, 2, 3],
            challenges: vec![100, 200, 300],
            responses: vec![[1u8; 32], [2u8; 32], [3u8; 32]],
        }];

        let proof = PoStProof::new(
            Address::new([1u8; 20]),
            100,
            1,
            partitions,
            Hash::new([1u8; 32]),
        );

        assert!(proof.validate().is_ok());
        assert_eq!(proof.partitions.len(), 1);
        assert!(!proof.proof_data.is_empty());
    }
}
