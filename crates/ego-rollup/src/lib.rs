pub mod batch;
pub mod commitment;
pub mod config;
pub mod da;
pub mod error;
pub mod fraud;
pub mod metrics;
pub mod operator;
pub mod proof_rollup;
pub mod state;
pub mod tx_rollup;
pub mod types;
pub mod verifier;

pub use batch::{BatchBuilder, BatchProcessor, RollupBatch};
pub use commitment::{CommitmentManager, RollupCommit, RollupCommitment};
pub use config::RollupConfig;
pub use da::{DAChunk, DAProof, DAUnavailabilityProof, DataAvailability};
pub use error::{RollupError, RollupResult};
pub use fraud::{FraudProof, FraudProofVerifier, InvalidInclusionProof};
pub use metrics::RollupMetrics;
pub use operator::{OperatorNode, RollupOperator};
pub use proof_rollup::{
    BeaconAnnouncement, CoherenceStats, EvidenceBundle, EvidenceBundleType,
    MinValidityProof as ProofMinValidityProof, PartitionInfo, PoCEvidence,
    PoRepProof, PoStEvidence, ProofRollupCommit, ProofRollupMetrics,
    ProofRollupOperator, ProverStats, ThresholdParams, WitnessReport,
    WindowPoStProof,
};
pub use state::{RollupState, StateDelta, StateTransition};
pub use tx_rollup::{
    ChallengeStatus as TxChallengeStatus, ChallengeType, TxRollupBatch,
    TxRollupChallenge, TxRollupCommit, TxRollupMetrics, TxRollupOperator,
    MinValidityProof as TxMinValidityProof,
};
pub use types::*;
pub use verifier::{RollupVerifier, VerificationResult};

use ego_core::{Address, Hash, Timestamp};
use serde::{Deserialize, Serialize};

pub const ROLLUP_VERSION: u32 = 1;

pub const DEFAULT_CHALLENGE_PERIOD: u64 = 1000;

pub const DEFAULT_DA_K: usize = 128;
pub const DEFAULT_DA_M: usize = 64;
pub const DEFAULT_DA_N: usize = 192;

pub const DEFAULT_CHUNK_SIZE: usize = 65536;

pub const DEFAULT_SAMPLE_SIZE: usize = 16;

pub const DEFAULT_RESPONSE_WINDOW: u64 = 100;

pub const DEFAULT_MIN_BOND: u64 = 1000000;

pub const DEFAULT_DA_SLASH: u64 = 100000;
pub const DEFAULT_INVALID_SLASH: u64 = 500000;

pub const DEFAULT_MAX_COMMIT_FREQUENCY: u32 = 60;

pub const DEFAULT_MAX_COMMIT_SIZE: u32 = 10000;

#[async_trait::async_trait]
pub trait RollupSystem: Send + Sync {
    async fn submit_batch(&mut self, batch: RollupBatch) -> RollupResult<Hash>;

    async fn post_commitment(&mut self, commitment: RollupCommitment) -> RollupResult<Hash>;

    async fn challenge_commitment(&mut self, proof: FraudProof) -> RollupResult<Hash>;

    async fn sample_da(
        &self,
        commitment_hash: Hash,
        sample_indices: Vec<usize>,
    ) -> RollupResult<Vec<DAChunk>>;

    async fn get_state(&self, commitment_hash: Hash) -> RollupResult<RollupState>;

    fn get_metrics(&self) -> RollupMetrics;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RollupEvent {
    BatchSubmitted {
        batch_hash: Hash,
        operator: Address,
        tx_count: u32,
        timestamp: Timestamp,
    },
    CommitmentPosted {
        commitment_hash: Hash,
        operator: Address,
        state_root: Hash,
        tx_root: Hash,
        block_range: (u64, u64),
        timestamp: Timestamp,
    },
    ChallengeSubmitted {
        challenge_hash: Hash,
        challenger: Address,
        commitment_hash: Hash,
        fraud_type: String,
        timestamp: Timestamp,
    },
    CommitmentFinalized {
        commitment_hash: Hash,
        finalized_at: Timestamp,
    },
    OperatorSlashed {
        operator: Address,
        amount: u64,
        reason: String,
        timestamp: Timestamp,
    },
    DAUnavailable {
        commitment_hash: Hash,
        missing_chunks: Vec<usize>,
        timestamp: Timestamp,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollupParams {
    pub rollup_version: u32,
    pub challenge_period: u64,
    pub da_params: DAParams,
    pub chunk_size: usize,
    pub sample_size: usize,
    pub response_window: u64,
    pub min_bond: u64,
    pub slashing_schedule: SlashingSchedule,
    pub commit_frequency: u32,
    pub max_commit_size: u32,
    pub rewards_split: RewardsSplit,
    pub admission_policy: AdmissionPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DAParams {
    pub k: usize,
    pub m: usize,
    pub n: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingSchedule {
    pub da_unavailable: u64,
    pub invalid_inclusion: u64,
    pub timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardsSplit {
    pub operator_percentage: u8,
    pub challenger_percentage: u8,
    pub protocol_percentage: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionPolicy {
    pub min_attestation_version: u32,
    pub required_capabilities: Vec<String>,
    pub min_stake: u64,
}

impl Default for RollupParams {
    fn default() -> Self {
        Self {
            rollup_version: ROLLUP_VERSION,
            challenge_period: DEFAULT_CHALLENGE_PERIOD,
            da_params: DAParams {
                k: DEFAULT_DA_K,
                m: DEFAULT_DA_M,
                n: DEFAULT_DA_N,
            },
            chunk_size: DEFAULT_CHUNK_SIZE,
            sample_size: DEFAULT_SAMPLE_SIZE,
            response_window: DEFAULT_RESPONSE_WINDOW,
            min_bond: DEFAULT_MIN_BOND,
            slashing_schedule: SlashingSchedule {
                da_unavailable: DEFAULT_DA_SLASH,
                invalid_inclusion: DEFAULT_INVALID_SLASH,
                timeout: DEFAULT_DA_SLASH / 2,
            },
            commit_frequency: DEFAULT_MAX_COMMIT_FREQUENCY,
            max_commit_size: DEFAULT_MAX_COMMIT_SIZE,
            rewards_split: RewardsSplit {
                operator_percentage: 70,
                challenger_percentage: 20,
                protocol_percentage: 10,
            },
            admission_policy: AdmissionPolicy {
                min_attestation_version: 1,
                required_capabilities: vec![
                    "5g_slicing".to_string(),
                    "proof_verification".to_string(),
                ],
                min_stake: DEFAULT_MIN_BOND,
            },
        }
    }
}

pub trait RollupGovernance {
    fn update_params(&mut self, params: RollupParams) -> RollupResult<()>;

    fn get_params(&self) -> RollupParams;

    fn propose_change(&mut self, proposal: ParamProposal) -> RollupResult<Hash>;

    fn vote(&mut self, proposal_hash: Hash, vote: bool) -> RollupResult<()>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamProposal {
    pub proposal_id: Hash,
    pub proposer: Address,
    pub new_params: RollupParams,
    pub rationale: String,
    pub voting_deadline: Timestamp,
    pub votes_for: u64,
    pub votes_against: u64,
    pub executed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rollup_params_default() {
        let params = RollupParams::default();
        assert_eq!(params.rollup_version, ROLLUP_VERSION);
        assert_eq!(params.da_params.k, DEFAULT_DA_K);
        assert_eq!(params.da_params.m, DEFAULT_DA_M);
        assert_eq!(params.da_params.n, DEFAULT_DA_N);
        assert_eq!(params.chunk_size, DEFAULT_CHUNK_SIZE);
        assert_eq!(params.sample_size, DEFAULT_SAMPLE_SIZE);
    }

    #[test]
    fn test_da_params_consistency() {
        let params = RollupParams::default();
        assert_eq!(params.da_params.k + params.da_params.m, params.da_params.n);
    }

    #[test]
    fn test_rewards_split_totals_100() {
        let params = RollupParams::default();
        let total = params.rewards_split.operator_percentage
            + params.rewards_split.challenger_percentage
            + params.rewards_split.protocol_percentage;
        assert_eq!(total, 100);
    }
}
