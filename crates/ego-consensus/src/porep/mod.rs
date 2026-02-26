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

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct SectorCommitment {
    pub sector_id: u64,
    pub prover_id: Address,
    pub comm_d: Hash,
    pub comm_r: Hash,
    pub replica_id: Hash,
    pub sector_size: u64,
    pub params_version: u32,
    pub registered_at: Timestamp,
    pub deal_ids: Vec<Hash>,
    pub expiry: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoRepFraudEvidence {
    pub sector_id: u64,
    pub prover_id: Address,
    pub fraud_type: PoRepFraudType,
    pub evidence_hash: Hash,
    pub detected_at: Timestamp,
    pub challenger: Address,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PoRepFraudType {
    InvalidCommitment,
    ReplicaSharing,
    InvalidProofData,
    CommitmentMismatch,
    ExpiredSector,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoRepVerdict {
    pub sector_id: u64,
    pub prover_id: Address,
    pub valid: bool,
    pub proof_hash: Hash,
    pub fraud_evidence: Option<PoRepFraudEvidence>,
    pub verdict_at: Timestamp,
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
            node_sig: Signature::ed25519([0u8; 64]),
            ts_ms: Timestamp::now().as_millis(),
        }
    }

    pub fn with_signature(mut self, sig: Signature, alg_sig_id: u8) -> Self {
        self.node_sig = sig;
        self.alg_sig_id = alg_sig_id;
        self
    }

    pub fn with_cid_hint(mut self, cid: String) -> Self {
        self.cid_hint = Some(cid);
        self
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

    pub fn compute_signing_message(&self) -> Hash {
        use ego_core::crypto::hash_multiple;
        hash_multiple(&[
            &self.sector_id.to_le_bytes(),
            self.replica_id.as_bytes(),
            self.comm_d.as_bytes(),
            self.comm_r.as_bytes(),
            &self.ts_ms.to_le_bytes(),
        ])
    }

    pub fn sign_with_keypair(&mut self, keypair: &ego_core::crypto::KeyPair) {
        let message = self.compute_signing_message();
        let sig = keypair.sign(message.as_bytes());
        self.node_sig = sig;
        self.alg_sig_id = 1;
    }

    pub fn to_sector_commitment(&self, sector_size: u64, expiry_ms: u64) -> SectorCommitment {
        SectorCommitment {
            sector_id: self.sector_id,
            prover_id: self.node_addr,
            comm_d: self.comm_d,
            comm_r: self.comm_r,
            replica_id: self.replica_id,
            sector_size,
            params_version: self.porep_params_v,
            registered_at: Timestamp::from_millis(self.ts_ms),
            deal_ids: self.deal_id.clone(),
            expiry: Timestamp::from_millis(self.ts_ms + expiry_ms),
        }
    }

    pub fn to_block_proof_event(
        &self,
        verified: bool,
        latency_ms: u32,
    ) -> ego_core::block::ProofEvent {
        use ego_core::block::{ProofEvent, ProofEventType};
        ProofEvent {
            proof_type: ProofEventType::PoRep,
            prover: self.node_addr,
            challenge_hash: self.replica_id,
            proof_data_hash: self.proof_hash,
            location_id: self.sector_id.to_string(),
            slice_id: None,
            timestamp: Timestamp::from_millis(self.ts_ms),
            verified,
            latency_ms,
            witness_data: None,
            batch_proof: false,
            cellular_optimized: false,
            evidence_cid: self.cid_hint.clone(),
        }
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

    pub fn compute_proof_hash(&self) -> Hash {
        use ego_core::crypto::hash_multiple;
        hash_multiple(&[
            &self.sector_id.to_le_bytes(),
            self.replica_id.as_bytes(),
            self.comm_d.as_bytes(),
            self.comm_r.as_bytes(),
            &self.proof_data,
        ])
    }

    pub fn matches_commitment(&self, commitment: &SectorCommitment) -> bool {
        self.sector_id == commitment.sector_id
            && self.prover_id == commitment.prover_id
            && self.comm_d == commitment.comm_d
            && self.comm_r == commitment.comm_r
            && self.replica_id == commitment.replica_id
    }

    pub fn to_porep_event(&self, deal_ids: Vec<Hash>) -> PoRepEvent {
        PoRepEvent::new(
            deal_ids,
            self.sector_id,
            self.prover_id,
            self.replica_id,
            self.comm_d,
            self.comm_r,
            self.params_version,
            self.compute_proof_hash(),
        )
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

    pub fn from_finalized_block(
        sector_id: u64,
        replica_id: Hash,
        block_hash: Hash,
        block_vrf_output: [u8; 32],
    ) -> Self {
        use ego_core::crypto::hash_multiple;
        let challenge_seed = hash_multiple(&[
            block_hash.as_bytes(),
            &block_vrf_output,
            &sector_id.to_le_bytes(),
            replica_id.as_bytes(),
        ]);
        Self::new(sector_id, replica_id, challenge_seed)
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

    pub fn to_challenge_hash(&self) -> Hash {
        use ego_core::crypto::hash_multiple;
        hash_multiple(&[
            &self.sector_id.to_le_bytes(),
            self.replica_id.as_bytes(),
            self.challenge_seed.as_bytes(),
            &self.challenge_count.to_le_bytes(),
        ])
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

    pub fn is_complete(&self) -> bool {
        matches!(self.status, SealingStatus::Completed)
    }

    pub fn is_failed(&self) -> bool {
        matches!(self.status, SealingStatus::Failed)
    }

    pub fn is_terminal(&self) -> bool {
        self.is_complete() || self.is_failed()
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

impl SectorCommitment {
    pub fn is_expired(&self) -> bool {
        Timestamp::now() > self.expiry
    }

    pub fn compute_commitment_hash(&self) -> Hash {
        use ego_core::crypto::hash_multiple;
        hash_multiple(&[
            &self.sector_id.to_le_bytes(),
            self.prover_id.as_bytes(),
            self.comm_d.as_bytes(),
            self.comm_r.as_bytes(),
            self.replica_id.as_bytes(),
        ])
    }

    pub fn to_account_sector_info(
        &self,
        data_type: ego_core::account::DataType,
        triad: ego_core::account::TriadInfo,
    ) -> ego_core::account::SectorInfo {
        ego_core::account::SectorInfo {
            sector_id: self.compute_commitment_hash(),
            size_bytes: self.sector_size,
            data_type,
            sealed_at: self.registered_at,
            expires_at: self.expiry,
            replica_id: self.replica_id,
            comm_d: self.comm_d,
            comm_r: self.comm_r,
            triad,
            params_version: self.params_version,
            post_frequency: 3600,
            last_post_epoch: 0,
            miss_count: 0,
            integrity_verified: true,
        }
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

pub mod prover;
pub mod verifier;

pub use prover::PoRepProver;
pub use verifier::PoRepVerifier;

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
    fn test_porep_event_validation_no_deals() {
        let event = PoRepEvent::new(
            vec![],
            1,
            Address::new([2u8; 20]),
            Hash::new([3u8; 32]),
            Hash::new([4u8; 32]),
            Hash::new([5u8; 32]),
            1,
            Hash::new([6u8; 32]),
        );
        assert!(event.validate().is_err());
    }

    #[test]
    fn test_porep_event_validation_zero_sector() {
        let event = PoRepEvent::new(
            vec![Hash::new([1u8; 32])],
            0,
            Address::new([2u8; 20]),
            Hash::new([3u8; 32]),
            Hash::new([4u8; 32]),
            Hash::new([5u8; 32]),
            1,
            Hash::new([6u8; 32]),
        );
        assert!(event.validate().is_err());
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
    fn test_porep_challenge_different_seeds() {
        let c1 = PoRepChallenge::new(1, Hash::new([1u8; 32]), Hash::new([2u8; 32]));
        let c2 = PoRepChallenge::new(1, Hash::new([1u8; 32]), Hash::new([3u8; 32]));

        let ch1 = c1.generate_deterministic_challenges();
        let ch2 = c2.generate_deterministic_challenges();
        assert_ne!(ch1, ch2);
    }

    #[test]
    fn test_porep_challenge_from_block() {
        let challenge = PoRepChallenge::from_finalized_block(
            1,
            Hash::new([1u8; 32]),
            Hash::new([10u8; 32]),
            [0u8; 32],
        );
        assert_eq!(challenge.sector_id, 1);
        assert_eq!(challenge.challenge_count, 176);
        assert!(!challenge.is_expired());
    }

    #[test]
    fn test_sealing_job_progression() {
        let mut job = SealingJob::new(1, Hash::new([1u8; 32]));
        assert_eq!(job.status, SealingStatus::Queued);

        job.advance_status(SealingStatus::PreCommit1, 0);
        assert_eq!(job.status, SealingStatus::PreCommit1);

        job.advance_status(SealingStatus::PreCommit2, 5000);
        assert_eq!(job.status, SealingStatus::PreCommit2);

        job.advance_status(SealingStatus::WaitingForSeed, 1000);
        assert_eq!(job.status, SealingStatus::WaitingForSeed);

        job.advance_status(SealingStatus::Commit1, 2000);
        assert_eq!(job.status, SealingStatus::Commit1);

        job.advance_status(SealingStatus::Commit2, 3000);
        assert_eq!(job.status, SealingStatus::Commit2);

        job.advance_status(SealingStatus::Completed, 1000);
        assert_eq!(job.status, SealingStatus::Completed);
        assert!(job.completed_at.is_some());
        assert!(job.is_complete());
        assert!(job.is_terminal());
        assert_eq!(job.total_sealing_time_ms(), 5000 + 1000 + 3000 + 1000);
    }

    #[test]
    fn test_sealing_job_invalid_transition_fails() {
        let mut job = SealingJob::new(1, Hash::new([1u8; 32]));
        job.advance_status(SealingStatus::Commit2, 0);
        assert_eq!(job.status, SealingStatus::Failed);
        assert!(job.is_failed());
    }

    #[test]
    fn test_sector_commitment_expiry() {
        let comm = SectorCommitment {
            sector_id: 1,
            prover_id: Address::new([1u8; 20]),
            comm_d: Hash::new([2u8; 32]),
            comm_r: Hash::new([3u8; 32]),
            replica_id: Hash::new([4u8; 32]),
            sector_size: 32 * 1024 * 1024 * 1024,
            params_version: 1,
            registered_at: Timestamp::now(),
            deal_ids: vec![],
            expiry: Timestamp::from_millis(Timestamp::now().as_millis() + 10_000),
        };
        assert!(!comm.is_expired());
    }

    #[test]
    fn test_proof_matches_commitment() {
        let prover_id = Address::new([1u8; 20]);
        let comm_d = Hash::new([2u8; 32]);
        let comm_r = Hash::new([3u8; 32]);
        let replica_id = Hash::new([4u8; 32]);

        let proof = PoRepProof::new(1, replica_id, comm_d, comm_r, vec![0u8; 96], 1, prover_id);

        let comm = SectorCommitment {
            sector_id: 1,
            prover_id,
            comm_d,
            comm_r,
            replica_id,
            sector_size: 32 * 1024 * 1024 * 1024,
            params_version: 1,
            registered_at: Timestamp::now(),
            deal_ids: vec![],
            expiry: Timestamp::from_millis(Timestamp::now().as_millis() + 10_000),
        };

        assert!(proof.matches_commitment(&comm));
    }

    #[test]
    fn test_proof_compute_hash_deterministic() {
        let proof = PoRepProof::new(
            1,
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            Hash::new([3u8; 32]),
            vec![0u8; 96],
            1,
            Address::new([4u8; 20]),
        );
        let h1 = proof.compute_proof_hash();
        let h2 = proof.compute_proof_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_event_to_block_proof_event() {
        let event = PoRepEvent::new(
            vec![Hash::new([1u8; 32])],
            1,
            Address::new([2u8; 20]),
            Hash::new([3u8; 32]),
            Hash::new([4u8; 32]),
            Hash::new([5u8; 32]),
            1,
            Hash::new([6u8; 32]),
        );
        let block_event = event.to_block_proof_event(true, 250);
        use ego_core::block::ProofEventType;
        assert!(matches!(block_event.proof_type, ProofEventType::PoRep));
        assert!(block_event.verified);
        assert_eq!(block_event.latency_ms, 250);
    }
}
