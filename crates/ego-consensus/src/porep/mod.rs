use crate::error::PoCResult;
use ego_core::{Address, Hash, Signature, Timestamp};
use serde::{Deserialize, Serialize};
use std::future::Future;

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PoRepEvent {
    pub deal_id: Vec<Hash>,
    pub sector_id: u64,
    pub node_addr: Address,
    pub replica_id: Hash,
    pub comm_d: Hash,
    pub comm_r: Hash,
    pub porep_params_v: u32,
    pub proof_hash: Hash,
    pub cid_hint: Option<String>,
    pub alg_sig_id: u8,
    pub node_sig: Signature,
    pub ts_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PoRepProof {
    pub sector_id: u64,
    pub replica_id: Hash,
    pub comm_d: Hash,
    pub comm_r: Hash,
    pub proof_data: Vec<u8>,
    pub params_version: u32,
    pub prover_id: Address,
    pub created_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoRepChallenge {
    pub sector_id: u64,
    pub replica_id: Hash,
    pub challenge_seed: Hash,
    pub challenge_count: u32,
    pub deadline: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealingJob {
    pub job_id: Hash,
    pub sector_id: u64,
    pub data_cid: Hash,
    pub status: SealingStatus,
    pub pc1_duration_ms: u64,
    pub pc2_duration_ms: u64,
    pub c1_duration_ms: u64,
    pub c2_duration_ms: u64,
    pub created_at: Timestamp,
    pub completed_at: Option<Timestamp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SealingStatus {
    Queued,
    PreCommit1,
    PreCommit2,
    WaitingForSeed,
    Commit1,
    Commit2,
    Completed,
    Failed,
}

pub trait PoRepProvider: Send + Sync {
    fn provider_id(&self) -> Address;

    fn seal_sector(
        &mut self,
        sector_id: u64,
        data: Vec<u8>,
    ) -> impl Future<Output = PoCResult<PoRepProof>> + Send;

    fn generate_porep_proof(
        &self,
        challenge: PoRepChallenge,
    ) -> impl Future<Output = PoCResult<PoRepProof>> + Send;

    fn verify_porep_proof(
        &self,
        proof: &PoRepProof,
    ) -> impl Future<Output = PoCResult<bool>> + Send;

    fn get_sealing_queue_length(&self) -> usize;

    fn get_active_sectors(&self) -> Vec<u64>;
}

impl PoRepEvent {
    pub fn new(
        deal_ids: Vec<Hash>,
        sector_id: u64,
        node_addr: Address,
        replica_id: Hash,
        comm_d: Hash,
        comm_r: Hash,
        porep_params_v: u32,
        proof_hash: Hash,
    ) -> Self {
        Self {
            deal_id: deal_ids,
            sector_id,
            node_addr,
            replica_id,
            comm_d,
            comm_r,
            porep_params_v,
            proof_hash,
            cid_hint: None,
            alg_sig_id: 1,
            node_sig: Signature::new([0u8; 64]),
            ts_ms: Timestamp::now().as_millis(),
        }
    }

    pub fn validate(&self) -> PoCResult<()> {
        if self.deal_id.is_empty() {
            return Err(crate::error::PoCError::ValidationFailed(
                "PoRep event must have at least one deal".to_string(),
            ));
        }

        if self.sector_id == 0 {
            return Err(crate::error::PoCError::ValidationFailed(
                "Invalid sector ID".to_string(),
            ));
        }

        let now = Timestamp::now().as_millis();
        if self.ts_ms > now + 60_000 {
            return Err(crate::error::PoCError::TimeWindowViolation(
                "PoRep event timestamp too far in future".to_string(),
            ));
        }

        Ok(())
    }
}

impl PoRepProof {
    pub fn new(
        sector_id: u64,
        replica_id: Hash,
        comm_d: Hash,
        comm_r: Hash,
        proof_data: Vec<u8>,
        params_version: u32,
        prover_id: Address,
    ) -> Self {
        Self {
            sector_id,
            replica_id,
            comm_d,
            comm_r,
            proof_data,
            params_version,
            prover_id,
            created_at: Timestamp::now(),
        }
    }

    pub fn validate(&self) -> PoCResult<()> {
        if self.proof_data.is_empty() {
            return Err(crate::error::PoCError::ValidationFailed(
                "PoRep proof data cannot be empty".to_string(),
            ));
        }

        if self.sector_id == 0 {
            return Err(crate::error::PoCError::ValidationFailed(
                "Invalid sector ID in PoRep proof".to_string(),
            ));
        }

        Ok(())
    }
}

impl PoRepChallenge {
    pub fn new(sector_id: u64, replica_id: Hash, challenge_seed: Hash) -> Self {
        let deadline = Timestamp::from_millis(Timestamp::now().as_millis() + 300_000);

        Self {
            sector_id,
            replica_id,
            challenge_seed,
            challenge_count: 176,
            deadline,
        }
    }

    pub fn is_expired(&self) -> bool {
        Timestamp::now() > self.deadline
    }

    pub fn generate_deterministic_challenges(&self) -> Vec<u64> {
        use ego_core::crypto::hash_multiple;

        let mut challenges = Vec::new();

        for i in 0..self.challenge_count {
            let challenge_hash = hash_multiple(&[
                self.challenge_seed.as_bytes(),
                self.replica_id.as_bytes(),
                &i.to_le_bytes(),
            ]);

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

        challenges
    }
}

impl SealingJob {
    pub fn new(sector_id: u64, data_cid: Hash) -> Self {
        let job_id = Self::compute_job_id(sector_id, data_cid);

        Self {
            job_id,
            sector_id,
            data_cid,
            status: SealingStatus::Queued,
            pc1_duration_ms: 0,
            pc2_duration_ms: 0,
            c1_duration_ms: 0,
            c2_duration_ms: 0,
            created_at: Timestamp::now(),
            completed_at: None,
        }
    }

    pub fn advance_status(&mut self, new_status: SealingStatus, duration_ms: u64) {
        match (&self.status, &new_status) {
            (SealingStatus::Queued, SealingStatus::PreCommit1) => {
                self.status = new_status;
            }
            (SealingStatus::PreCommit1, SealingStatus::PreCommit2) => {
                self.pc1_duration_ms = duration_ms;
                self.status = new_status;
            }
            (SealingStatus::PreCommit2, SealingStatus::WaitingForSeed) => {
                self.pc2_duration_ms = duration_ms;
                self.status = new_status;
            }
            (SealingStatus::WaitingForSeed, SealingStatus::Commit1) => {
                self.status = new_status;
            }
            (SealingStatus::Commit1, SealingStatus::Commit2) => {
                self.c1_duration_ms = duration_ms;
                self.status = new_status;
            }
            (SealingStatus::Commit2, SealingStatus::Completed) => {
                self.c2_duration_ms = duration_ms;
                self.status = new_status;
                self.completed_at = Some(Timestamp::now());
            }
            _ => {
                self.status = SealingStatus::Failed;
            }
        }
    }

    pub fn total_sealing_time_ms(&self) -> u64 {
        self.pc1_duration_ms + self.pc2_duration_ms + self.c1_duration_ms + self.c2_duration_ms
    }

    fn compute_job_id(sector_id: u64, data_cid: Hash) -> Hash {
        use ego_core::crypto::hash_multiple;

        hash_multiple(&[
            &sector_id.to_le_bytes(),
            data_cid.as_bytes(),
            &Timestamp::now().as_millis().to_le_bytes(),
        ])
    }
}

impl PartialEq for PoRepEvent {
    fn eq(&self, other: &Self) -> bool {
        self.sector_id == other.sector_id
            && self.node_addr == other.node_addr
            && self.replica_id == other.replica_id
    }
}

impl Eq for PoRepEvent {}

impl PartialEq for PoRepProof {
    fn eq(&self, other: &Self) -> bool {
        self.sector_id == other.sector_id
            && self.replica_id == other.replica_id
            && self.comm_d == other.comm_d
            && self.comm_r == other.comm_r
    }
}

impl Eq for PoRepProof {}

impl PartialEq for SealingStatus {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (SealingStatus::Queued, SealingStatus::Queued) => true,
            (SealingStatus::PreCommit1, SealingStatus::PreCommit1) => true,
            (SealingStatus::PreCommit2, SealingStatus::PreCommit2) => true,
            (SealingStatus::WaitingForSeed, SealingStatus::WaitingForSeed) => true,
            (SealingStatus::Commit1, SealingStatus::Commit1) => true,
            (SealingStatus::Commit2, SealingStatus::Commit2) => true,
            (SealingStatus::Completed, SealingStatus::Completed) => true,
            (SealingStatus::Failed, SealingStatus::Failed) => true,
            _ => false,
        }
    }
}

impl Eq for SealingStatus {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_porep_event_creation() {
        let deal_ids = vec![Hash::new([1u8; 32])];
        let event = PoRepEvent::new(
            deal_ids,
            1,
            Address::new([2u8; 20]),
            Hash::new([3u8; 32]),
            Hash::new([4u8; 32]),
            Hash::new([5u8; 32]),
            1,
            Hash::new([6u8; 32]),
        );

        assert_eq!(event.sector_id, 1);
        assert_eq!(event.deal_id.len(), 1);
        assert!(event.validate().is_ok());
    }

    #[test]
    fn test_porep_challenge_generation() {
        let challenge = PoRepChallenge::new(1, Hash::new([1u8; 32]), Hash::new([2u8; 32]));

        let challenges = challenge.generate_deterministic_challenges();
        assert_eq!(challenges.len(), 176);

        let challenges2 = challenge.generate_deterministic_challenges();
        assert_eq!(challenges, challenges2);
    }

    #[test]
    fn test_sealing_job_progression() {
        let mut job = SealingJob::new(1, Hash::new([1u8; 32]));
        assert_eq!(job.status, SealingStatus::Queued);

        job.advance_status(SealingStatus::PreCommit1, 0);
        assert_eq!(job.status, SealingStatus::PreCommit1);

        job.advance_status(SealingStatus::PreCommit2, 5000);
        assert_eq!(job.status, SealingStatus::PreCommit2);
        assert_eq!(job.pc1_duration_ms, 5000);

        job.advance_status(SealingStatus::Completed, 3000);
        assert_eq!(job.status, SealingStatus::Completed);
        assert!(job.completed_at.is_some());
    }
}
