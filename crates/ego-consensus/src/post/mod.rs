pub mod prover;
pub mod verifier;

pub use prover::PoStProver;
pub use verifier::PoStVerifier;

use crate::error::{PoCError, PoCResult};
use ego_core::{Address, Hash, KeyPair, Signature, Timestamp};
use ego_core::crypto::hash_multiple;
use serde::{Deserialize, Serialize};
use std::future::Future;

// ─── PoSt result ─────────────────────────────────────────────────────────────

/// Outcome of a single WindowPoSt window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum PoStResult {
    /// Proof submitted on time and verified
    Pass,
    /// Window deadline missed — no proof submitted
    Miss,
    /// Proof submitted but failed verification
    Fault,
}

// ─── PoSt event (on-chain record) ────────────────────────────────────────────

/// Emitted once per WindowPoSt window per node.
/// Consumed by the DRS scorer and the slashing engine.
#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PoStEvent {
    pub event_id: Hash,
    pub node_addr: Address,
    pub epoch: u64,
    pub window_id: u64,
    /// Partition IDs proven in this window
    pub partition_ids: Vec<u64>,
    /// Merkle root of the challenge set
    pub challenges_root: Hash,
    /// Hash of the proof submitted (or zero-hash on Miss)
    pub proof_hash: Hash,
    pub result: PoStResult,
    /// Proof submission latency in ms (0 on Miss/Fault)
    pub latency_ms: u64,
    /// Optional IPFS CID for proof archival
    pub cid_hint: Option<String>,
    /// Algorithm ID: 1 = Ed25519 placeholder, 2 = Dilithium-2
    pub alg_sig_id: u8,
    pub node_sig: Signature,
    pub ts_ms: u64,
}

impl PoStEvent {
    pub fn new(
        node_addr: Address,
        epoch: u64,
        window_id: u64,
        partition_ids: Vec<u64>,
        challenges_root: Hash,
        proof_hash: Hash,
        result: PoStResult,
        latency_ms: u64,
    ) -> Self {
        let event_id = Self::compute_event_id(node_addr, epoch, window_id, &result);

        Self {
            event_id,
            node_addr,
            epoch,
            window_id,
            partition_ids,
            challenges_root,
            proof_hash,
            result,
            latency_ms,
            cid_hint: None,
            alg_sig_id: 1,
            node_sig: Signature::ed25519([0u8; 64]),
            ts_ms: Timestamp::now().as_millis(),
        }
    }

    pub fn sign(&mut self, keypair: &KeyPair) -> PoCResult<()> {
        let msg = self.signing_bytes();
        self.node_sig = keypair.sign(&msg);
        Ok(())
    }

    pub fn validate(&self) -> PoCResult<()> {
        let now = Timestamp::now().as_millis();
        if self.ts_ms > now + 60_000 {
            return Err(PoCError::TimeWindowViolation(
                "PoSt event timestamp too far in future".to_string(),
            ));
        }
        if self.partition_ids.is_empty() {
            return Err(PoCError::ValidationFailed(
                "PoSt event must cover at least one partition".to_string(),
            ));
        }
        Ok(())
    }

    pub fn is_pass(&self) -> bool {
        self.result == PoStResult::Pass
    }

    pub fn is_miss(&self) -> bool {
        self.result == PoStResult::Miss
    }

    pub fn is_fault(&self) -> bool {
        self.result == PoStResult::Fault
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = b"ego/post/event/v1:".to_vec();
        buf.extend_from_slice(self.event_id.as_bytes());
        buf.extend_from_slice(self.node_addr.as_bytes());
        buf.extend_from_slice(&self.epoch.to_le_bytes());
        buf.extend_from_slice(&self.window_id.to_le_bytes());
        buf.extend_from_slice(self.challenges_root.as_bytes());
        buf.extend_from_slice(&self.ts_ms.to_le_bytes());
        buf
    }

    fn compute_event_id(
        node_addr: Address,
        epoch: u64,
        window_id: u64,
        result: &PoStResult,
    ) -> Hash {
        let result_byte = match result {
            PoStResult::Pass => 1u8,
            PoStResult::Miss => 2u8,
            PoStResult::Fault => 3u8,
        };
        hash_multiple(&[
            node_addr.as_bytes(),
            &epoch.to_le_bytes(),
            &window_id.to_le_bytes(),
            &[result_byte],
            &Timestamp::now().as_millis().to_le_bytes(),
        ])
    }
}

// ─── WindowPoSt window ───────────────────────────────────────────────────────

/// A single assigned proving window for a storage node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoStWindow {
    pub window_id: u64,
    pub epoch: u64,
    /// Partitions (sector groups) that must be proven in this window
    pub required_partitions: Vec<u64>,
    /// VRF-derived challenge seed: R_e = H(vrf_output || deal_id || epoch)
    pub challenge_seed: Hash,
    pub open_at_ms: u64,
    pub close_at_ms: u64,
    /// Proof hashes submitted for this window
    pub submitted_proofs: Vec<Hash>,
}

impl PoStWindow {
    pub fn new(
        window_id: u64,
        epoch: u64,
        required_partitions: Vec<u64>,
        challenge_seed: Hash,
        open_at_ms: u64,
        duration_ms: u64,
    ) -> Self {
        Self {
            window_id,
            epoch,
            required_partitions,
            challenge_seed,
            open_at_ms,
            close_at_ms: open_at_ms + duration_ms,
            submitted_proofs: Vec::new(),
        }
    }

    pub fn is_active(&self) -> bool {
        let now = Timestamp::now().as_millis();
        now >= self.open_at_ms && now < self.close_at_ms
    }

    pub fn is_expired(&self) -> bool {
        Timestamp::now().as_millis() >= self.close_at_ms
    }

    pub fn remaining_ms(&self) -> u64 {
        self.close_at_ms
            .saturating_sub(Timestamp::now().as_millis())
    }

    pub fn is_proven(&self) -> bool {
        !self.submitted_proofs.is_empty()
    }

    /// Derive partition-specific challenge indices from the window seed.
    /// challenge_i = H(challenge_seed || partition_id || i) mod sector_count
    pub fn generate_partition_challenges(
        &self,
        partition_id: u64,
        sector_count: u32,
    ) -> Vec<u64> {
        const CHALLENGES_PER_PARTITION: u32 = 2;

        (0..CHALLENGES_PER_PARTITION)
            .map(|i| {
                let h = hash_multiple(&[
                    self.challenge_seed.as_bytes(),
                    &partition_id.to_le_bytes(),
                    &i.to_le_bytes(),
                ]);
                let bytes = h.as_bytes();
                let raw = u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                raw % sector_count as u64
            })
            .collect()
    }
}

// ─── Window schedule ─────────────────────────────────────────────────────────

/// Full set of windows assigned to one node for one epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowSchedule {
    pub node_addr: Address,
    pub epoch: u64,
    pub assigned_windows: Vec<PoStWindow>,
    pub generated_at: Timestamp,
}

impl WindowSchedule {
    /// Deterministic schedule derived from node address, epoch, and sector count.
    /// Each node gets `windows_per_day` windows spread evenly across the epoch.
    pub fn generate_deterministic_schedule(
        node_addr: Address,
        epoch: u64,
        total_sectors: u32,
        windows_per_day: u32,
    ) -> Self {
        let epoch_start_ms = epoch * 3_600_000;
        let window_duration_ms = 3_600_000 / windows_per_day as u64;
        let base = total_sectors / windows_per_day;
        let remainder = total_sectors % windows_per_day;

        let mut windows = Vec::with_capacity(windows_per_day as usize);
        let mut sector_cursor = 0u32;

        for idx in 0..windows_per_day {
            let challenge_seed = hash_multiple(&[
                node_addr.as_bytes(),
                &epoch.to_le_bytes(),
                &idx.to_le_bytes(),
                b"ego/post/window/v1",
            ]);

            // Distribute remainder one-per-window to first `remainder` windows
            let count = base + if idx < remainder { 1 } else { 0 };
            let partitions: Vec<u64> = (sector_cursor..sector_cursor + count).map(|s| s as u64).collect();
            sector_cursor += count;

            let open_at_ms = epoch_start_ms + idx as u64 * window_duration_ms;

            let window = PoStWindow::new(
                idx as u64,
                epoch,
                partitions,
                challenge_seed,
                open_at_ms,
                window_duration_ms,
            );

            windows.push(window);
        }

        Self {
            node_addr,
            epoch,
            assigned_windows: windows,
            generated_at: Timestamp::now(),
        }
    }
}

// ─── Partition proof ─────────────────────────────────────────────────────────

/// Proof for one partition within a WindowPoSt window.
#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PartitionProof {
    pub partition_id: u64,
    pub sector_ids: Vec<u64>,
    pub challenges: Vec<u64>,
    pub responses: Vec<[u8; 32]>,
}

impl PartitionProof {
    pub fn validate(&self) -> PoCResult<()> {
        if self.challenges.len() != self.responses.len() {
            return Err(PoCError::ValidationFailed(
                "Challenge/response count mismatch in partition proof".to_string(),
            ));
        }
        if self.sector_ids.is_empty() {
            return Err(PoCError::ValidationFailed(
                "Partition proof has no sector IDs".to_string(),
            ));
        }
        Ok(())
    }
}

// ─── PoSt proof ──────────────────────────────────────────────────────────────

/// Aggregated proof for a full WindowPoSt window.
#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PoStProof {
    pub proof_id: Hash,
    pub prover_id: Address,
    pub epoch: u64,
    pub window_id: u64,
    pub partitions: Vec<PartitionProof>,
    pub challenge_seed: Hash,
    pub created_at: Timestamp,
    pub signature: Signature,
}

impl PoStProof {
    pub fn new(
        prover_id: Address,
        epoch: u64,
        window_id: u64,
        partitions: Vec<PartitionProof>,
        challenge_seed: Hash,
    ) -> Self {
        let proof_id = hash_multiple(&[
            prover_id.as_bytes(),
            &epoch.to_le_bytes(),
            &window_id.to_le_bytes(),
            challenge_seed.as_bytes(),
        ]);

        Self {
            proof_id,
            prover_id,
            epoch,
            window_id,
            partitions,
            challenge_seed,
            created_at: Timestamp::now(),
            signature: Signature::ed25519([0u8; 64]),
        }
    }

    pub fn sign(&mut self, keypair: &KeyPair) -> PoCResult<()> {
        let msg = self.signing_bytes();
        self.signature = keypair.sign(&msg);
        Ok(())
    }

    pub fn validate(&self) -> PoCResult<()> {
        if self.partitions.is_empty() {
            return Err(PoCError::ValidationFailed(
                "PoSt proof has no partitions".to_string(),
            ));
        }
        for p in &self.partitions {
            p.validate()?;
        }
        Ok(())
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = b"ego/post/proof/v1:".to_vec();
        buf.extend_from_slice(self.proof_id.as_bytes());
        buf.extend_from_slice(self.prover_id.as_bytes());
        buf.extend_from_slice(&self.epoch.to_le_bytes());
        buf.extend_from_slice(&self.window_id.to_le_bytes());
        buf
    }
}

// ─── Metrics ─────────────────────────────────────────────────────────────────

/// Accumulated PoSt proving metrics — fed into DRS scorer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoStMetrics {
    pub windows_proven: u64,
    pub windows_missed: u64,
    pub windows_faulted: u64,
    /// Rolling average latency
    pub avg_latency_ms: f64,
    /// P50 latency (updated periodically)
    pub p50_latency_ms: u64,
    /// P95 latency
    pub p95_latency_ms: u64,
    /// Pass rate = proven / (proven + missed + faulted)
    pub pass_rate: f64,
    pub last_updated: Timestamp,
}

impl PoStMetrics {
    pub fn update_pass_rate(&mut self) {
        let total = self.windows_proven + self.windows_missed + self.windows_faulted;
        self.pass_rate = if total == 0 {
            0.0
        } else {
            self.windows_proven as f64 / total as f64
        };
    }
}

impl Default for PoStMetrics {
    fn default() -> Self {
        Self {
            windows_proven: 0,
            windows_missed: 0,
            windows_faulted: 0,
            avg_latency_ms: 0.0,
            p50_latency_ms: 0,
            p95_latency_ms: 0,
            pass_rate: 0.0,
            last_updated: Timestamp::now(),
        }
    }
}

// ─── Provider trait ──────────────────────────────────────────────────────────

pub trait PoStProvider: Send + Sync {
    fn provider_id(&self) -> Address;

    fn generate_post_proof(
        &self,
        window: &PoStWindow,
    ) -> impl Future<Output = PoCResult<PoStProof>> + Send;

    fn verify_post_proof(
        &self,
        proof: &PoStProof,
    ) -> impl Future<Output = PoCResult<bool>> + Send;

    fn get_window_assignment(
        &self,
        epoch: u64,
    ) -> impl Future<Output = PoCResult<WindowSchedule>> + Send;

    fn get_proving_metrics(&self) -> PoStMetrics;
}

// ─── Triad health ─────────────────────────────────────────────────────────────

/// RF=3 replica set health — all three nodes must be healthy for a deal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriadHealth {
    pub deal_id: Hash,
    pub nodes: [Address; 3],
    pub node_pass_rates: [f64; 3],
    pub node_miss_counts: [u32; 3],
    pub is_healthy: bool,
    pub faulty_node: Option<Address>,
    pub last_updated: Timestamp,
}

impl TriadHealth {
    pub fn new(deal_id: Hash, nodes: [Address; 3]) -> Self {
        Self {
            deal_id,
            nodes,
            node_pass_rates: [1.0; 3],
            node_miss_counts: [0; 3],
            is_healthy: true,
            faulty_node: None,
            last_updated: Timestamp::now(),
        }
    }

    /// Update health after a PoSt event from one of the triad members.
    pub fn record_post_event(&mut self, node_addr: Address, result: &PoStResult) {
        for (i, &node) in self.nodes.iter().enumerate() {
            if node == node_addr {
                match result {
                    PoStResult::Pass => {
                        // Exponential moving average
                        self.node_pass_rates[i] =
                            self.node_pass_rates[i] * 0.9 + 0.1;
                    }
                    PoStResult::Miss | PoStResult::Fault => {
                        self.node_miss_counts[i] += 1;
                        self.node_pass_rates[i] = self.node_pass_rates[i] * 0.9;
                        if self.node_pass_rates[i] < 0.5 {
                            self.is_healthy = false;
                            self.faulty_node = Some(node_addr);
                        }
                    }
                }
                break;
            }
        }
        self.last_updated = Timestamp::now();
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_post_event_creation_and_validation() {
        let event = PoStEvent::new(
            Address::new([1u8; 20]),
            10,
            3,
            vec![0, 1, 2],
            Hash::new([5u8; 32]),
            Hash::new([6u8; 32]),
            PoStResult::Pass,
            3_500,
        );

        assert!(event.validate().is_ok());
        assert!(event.is_pass());
        assert!(!event.is_miss());
        assert_eq!(event.latency_ms, 3_500);
    }

    #[test]
    fn test_window_schedule_generation() {
        let node = Address::new([2u8; 20]);
        let schedule = WindowSchedule::generate_deterministic_schedule(node, 100, 1000, 48);

        assert_eq!(schedule.assigned_windows.len(), 48);
        assert_eq!(schedule.epoch, 100);

        // All windows should cover distinct partitions summing to 1000
        let total: usize = schedule
            .assigned_windows
            .iter()
            .map(|w| w.required_partitions.len())
            .sum();
        assert_eq!(total, 1000);
    }

    #[test]
    fn test_partition_challenges_deterministic() {
        let window = PoStWindow::new(
            0, 1, vec![0, 1], Hash::new([9u8; 32]), 0, 3_600_000,
        );

        let c1 = window.generate_partition_challenges(0, 100);
        let c2 = window.generate_partition_challenges(0, 100);
        assert_eq!(c1, c2, "Challenges must be deterministic");

        let c3 = window.generate_partition_challenges(1, 100);
        assert_ne!(c1, c3, "Different partitions should yield different challenges");
    }

    #[test]
    fn test_post_proof_validation() {
        let proof = PoStProof::new(
            Address::new([1u8; 20]),
            5,
            2,
            vec![PartitionProof {
                partition_id: 0,
                sector_ids: vec![1, 2],
                challenges: vec![10],
                responses: vec![[0u8; 32]],
            }],
            Hash::new([7u8; 32]),
        );

        assert!(proof.validate().is_ok());
    }

    #[test]
    fn test_triad_health_tracking() {
        let deal_id = Hash::new([1u8; 32]);
        let nodes = [
            Address::new([1u8; 20]),
            Address::new([2u8; 20]),
            Address::new([3u8; 20]),
        ];

        let mut health = TriadHealth::new(deal_id, nodes);
        assert!(health.is_healthy);

        // Record many misses for node 0
        for _ in 0..20 {
            health.record_post_event(nodes[0], &PoStResult::Miss);
        }

        assert!(!health.is_healthy);
        assert_eq!(health.faulty_node, Some(nodes[0]));
    }

    #[test]
    fn test_post_metrics_pass_rate() {
        let mut metrics = PoStMetrics::default();
        metrics.windows_proven = 90;
        metrics.windows_missed = 10;
        metrics.update_pass_rate();
        assert!((metrics.pass_rate - 0.9).abs() < 0.001);
    }
}