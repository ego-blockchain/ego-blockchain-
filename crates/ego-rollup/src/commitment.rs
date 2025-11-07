use crate::da::{DAChunk, DataAvailability};
use crate::error::{RollupError, RollupResult};
use crate::operator::RollupBatch;
use crate::types::{ChallengeStatus, CommitmentStatus};
use ego_core::{Address, DualSignature, EpochNumber, Hash, PROTOCOL_VERSION, PublicKey, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const DOMAIN_TAG_COMMITMENT: &[u8] = b"ego/rollup/commitment/v1";

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct RollupCommitment {
    pub commitment_hash: Hash,
    pub operator: Address,
    pub rollup_id: String,
    pub state_root: Hash,
    pub previous_state_root: Hash,
    pub tx_root: Hash,
    pub da_root: Hash,
    pub proofs_root: Hash,
    pub tx_count: u32,
    pub block_range: (u64, u64),
    pub l1_block_number: u64,
    pub timestamp: Timestamp,
    pub operator_signature: DualSignature,
    pub proof_data: Vec<u8>,
    pub da_chunks: Vec<u32>,
    pub gas_used: u64,
    pub version: u32,
    pub protocol_version: u32,
    pub chain_id: u32,
    pub network_id: u32,
    pub epoch: EpochNumber,
    pub fraud_proof_window: u64,
    pub min_validity_proof: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollupCommit {
    pub commitment: RollupCommitment,
    pub status: CommitmentStatus,
    pub challenge_deadline: Option<Timestamp>,
    pub finalization_time: Option<Timestamp>,
    pub associated_batches: Vec<Hash>,
    pub da_availability: DAAvailabilityStatus,
    pub verification_count: u32,
    pub last_verified: Option<Timestamp>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DAAvailabilityStatus {
    Unknown,
    Available,
    PartiallyAvailable { missing_chunks: Vec<u32> },
    Unavailable,
}

pub struct CommitmentManager {
    commitments: HashMap<Hash, RollupCommit>,
    operator_commitments: HashMap<Address, Vec<Hash>>,
    pending_challenges: HashMap<Hash, ChallengeInfo>,
    da_manager: DataAvailability,
    challenge_period_blocks: u64,
    response_window_blocks: u64,
    chain_id: u32,
    network_id: u32,
    fraud_proof_window: u64,
}

#[derive(Debug, Clone)]
struct ChallengeInfo {
    challenger: Address,
    challenge_hash: Hash,
    challenge_type: ChallengeType,
    submitted_at: Timestamp,
    deadline: Timestamp,
    bond_amount: u64,
    evidence: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChallengeType {
    InvalidStateTransition,
    DataUnavailability,
    InvalidProof,
    InvalidInclusion,
    InvalidAggregation,
}

impl RollupCommitment {
    pub fn new(
        operator: Address,
        rollup_id: String,
        batch: &RollupBatch,
        da_root: Hash,
        proofs_root: Hash,
        l1_block_number: u64,
        fraud_proof_window: u64,
    ) -> Self {
        let tx_root = batch.tx_root;
        let commitment_hash = Self::compute_commitment_hash(
            &operator,
            &batch.prev_state_root,
            &batch.new_state_root,
            &tx_root,
            &da_root,
            l1_block_number,
            batch.chain_id,
            batch.network_id,
            batch.epoch,
        );

        Self {
            commitment_hash,
            operator,
            rollup_id,
            state_root: batch.new_state_root,
            previous_state_root: batch.prev_state_root,
            tx_root,
            da_root,
            proofs_root,
            tx_count: batch.transactions.len() as u32,
            block_range: (batch.l1_block_number, batch.l1_block_number),
            l1_block_number,
            timestamp: batch.timestamp,
            operator_signature: DualSignature::new(None, None),
            proof_data: Vec::new(),
            da_chunks: Vec::new(),
            gas_used: batch.gas_used,
            version: crate::ROLLUP_VERSION,
            protocol_version: PROTOCOL_VERSION,
            chain_id: batch.chain_id,
            network_id: batch.network_id,
            epoch: batch.epoch,
            fraud_proof_window,
            min_validity_proof: Vec::new(),
        }
    }

    pub fn from_batch(batch: &RollupBatch, fraud_proof_window: u64) -> RollupResult<Self> {
        let da_root = Hash::ZERO;
        let proofs_root = Hash::ZERO;

        Ok(Self::new(
            batch.operator,
            format!("rollup_{}", batch.shard_id.as_u32()),
            batch,
            da_root,
            proofs_root,
            batch.l1_block_number,
            fraud_proof_window,
        ))
    }

    pub fn sign(&mut self, keypair: &ego_core::crypto::KeyPair) -> RollupResult<()> {
        let expected_operator = Address::from_public_key(&keypair.dilithium_public_key());
        if expected_operator != self.operator {
            return Err(RollupError::InvalidCommitment(
                "Operator address does not match signing key".to_string(),
            ));
        }

        let signing_data = self.create_signing_data()?;
        self.operator_signature = keypair.sign_hybrid(&signing_data, false);
        self.commitment_hash = self.compute_hash();
        Ok(())
    }

    pub fn verify_signature(&self, operator_dilithium_pk: &PublicKey) -> RollupResult<bool> {
        let expected_operator = Address::from_public_key(operator_dilithium_pk);
        if expected_operator != self.operator {
            return Ok(false);
        }

        let signing_data = self.create_signing_data()?;

        if let Some(ref dilithium_sig) = self.operator_signature.dilithium_sig {
            ego_core::crypto::verify_signature(operator_dilithium_pk, &signing_data, dilithium_sig)
                .map_err(|e| RollupError::VerificationFailed(e.to_string()))
        } else {
            Ok(false)
        }
    }

    pub fn validate(&self) -> RollupResult<()> {
        if self.tx_count == 0 {
            return Err(RollupError::InvalidCommitment(
                "Commitment must contain at least one transaction".to_string(),
            ));
        }

        if self.block_range.0 > self.block_range.1 {
            return Err(RollupError::InvalidCommitment(
                "Invalid block range".to_string(),
            ));
        }

        if self.state_root == Hash::ZERO {
            return Err(RollupError::InvalidCommitment(
                "State root cannot be zero".to_string(),
            ));
        }

        if self.version != crate::ROLLUP_VERSION {
            return Err(RollupError::InvalidCommitment(format!(
                "Unsupported rollup version: expected {}, got {}",
                crate::ROLLUP_VERSION,
                self.version
            )));
        }

        if self.protocol_version != PROTOCOL_VERSION {
            return Err(RollupError::InvalidCommitment(format!(
                "Protocol version mismatch: expected {}, got {}",
                PROTOCOL_VERSION, self.protocol_version
            )));
        }

        if self.fraud_proof_window == 0 {
            return Err(RollupError::InvalidCommitment(
                "Fraud proof window must be greater than zero".to_string(),
            ));
        }

        Ok(())
    }

    pub fn is_reproducible(&self, other: &Self) -> bool {
        self.state_root == other.state_root
            && self.tx_root == other.tx_root
            && self.da_root == other.da_root
            && self.proofs_root == other.proofs_root
            && self.tx_count == other.tx_count
            && self.block_range == other.block_range
            && self.chain_id == other.chain_id
            && self.network_id == other.network_id
    }

    pub fn compute_hash(&self) -> Hash {
        Self::compute_commitment_hash(
            &self.operator,
            &self.previous_state_root,
            &self.state_root,
            &self.tx_root,
            &self.da_root,
            self.l1_block_number,
            self.chain_id,
            self.network_id,
            self.epoch,
        )
    }

    fn create_signing_data(&self) -> RollupResult<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(DOMAIN_TAG_COMMITMENT);
        data.extend_from_slice(self.operator.as_bytes());
        data.extend_from_slice(self.rollup_id.as_bytes());
        data.extend_from_slice(self.state_root.as_bytes());
        data.extend_from_slice(self.previous_state_root.as_bytes());
        data.extend_from_slice(self.tx_root.as_bytes());
        data.extend_from_slice(self.da_root.as_bytes());
        data.extend_from_slice(self.proofs_root.as_bytes());
        data.extend_from_slice(&self.tx_count.to_le_bytes());
        data.extend_from_slice(&self.block_range.0.to_le_bytes());
        data.extend_from_slice(&self.block_range.1.to_le_bytes());
        data.extend_from_slice(&self.l1_block_number.to_le_bytes());
        data.extend_from_slice(&self.timestamp.as_millis().to_le_bytes());
        data.extend_from_slice(&self.gas_used.to_le_bytes());
        data.extend_from_slice(&self.version.to_le_bytes());
        data.extend_from_slice(&self.protocol_version.to_le_bytes());
        data.extend_from_slice(&self.chain_id.to_le_bytes());
        data.extend_from_slice(&self.network_id.to_le_bytes());
        data.extend_from_slice(&self.epoch.as_u64().to_le_bytes());
        data.extend_from_slice(&self.fraud_proof_window.to_le_bytes());

        Ok(ego_core::crypto::blake2s_hash(&data))
    }

    fn compute_commitment_hash(
        operator: &Address,
        prev_state_root: &Hash,
        state_root: &Hash,
        tx_root: &Hash,
        da_root: &Hash,
        l1_block_number: u64,
        chain_id: u32,
        network_id: u32,
        epoch: EpochNumber,
    ) -> Hash {
        ego_core::crypto::hash_multiple(&[
            DOMAIN_TAG_COMMITMENT,
            operator.as_bytes(),
            prev_state_root.as_bytes(),
            state_root.as_bytes(),
            tx_root.as_bytes(),
            da_root.as_bytes(),
            &l1_block_number.to_le_bytes(),
            &chain_id.to_le_bytes(),
            &network_id.to_le_bytes(),
            &epoch.as_u64().to_le_bytes(),
        ])
    }

    pub fn size(&self) -> usize {
        let config = bincode::config::standard();
        bincode::encode_to_vec(self, config)
            .map(|data| data.len())
            .unwrap_or(0)
    }

    pub fn is_cellular_optimized(&self) -> bool {
        self.size() <= 512 * 1024 && self.tx_count <= 500
    }

    pub fn set_da_root(&mut self, da_root: Hash) {
        self.da_root = da_root;
        self.commitment_hash = self.compute_hash();
    }

    pub fn set_proofs_root(&mut self, proofs_root: Hash) {
        self.proofs_root = proofs_root;
        self.commitment_hash = self.compute_hash();
    }

    pub fn add_proof_data(&mut self, proof_data: Vec<u8>) {
        self.proof_data = proof_data;
    }

    pub fn add_validity_proof(&mut self, validity_proof: Vec<u8>) {
        self.min_validity_proof = validity_proof;
    }
}

impl CommitmentManager {
    pub fn new(
        da_manager: DataAvailability,
        challenge_period_blocks: u64,
        response_window_blocks: u64,
        chain_id: u32,
        network_id: u32,
        fraud_proof_window: u64,
    ) -> Self {
        Self {
            commitments: HashMap::new(),
            operator_commitments: HashMap::new(),
            pending_challenges: HashMap::new(),
            da_manager,
            challenge_period_blocks,
            response_window_blocks,
            chain_id,
            network_id,
            fraud_proof_window,
        }
    }

    pub fn submit_commitment(
        &mut self,
        mut commitment: RollupCommitment,
        da_chunks: Vec<DAChunk>,
    ) -> RollupResult<Hash> {
        commitment.validate()?;

        if commitment.chain_id != self.chain_id {
            return Err(RollupError::InvalidCommitment(format!(
                "Chain ID mismatch: expected {}, got {}",
                self.chain_id, commitment.chain_id
            )));
        }

        if commitment.network_id != self.network_id {
            return Err(RollupError::InvalidCommitment(format!(
                "Network ID mismatch: expected {}, got {}",
                self.network_id, commitment.network_id
            )));
        }

        let chunk_ids: Vec<u32> = da_chunks.iter().map(|c| c.chunk_id).collect();
        commitment.da_chunks = chunk_ids;

        let challenge_deadline = Timestamp::from_millis(
            commitment.timestamp.as_millis() + (self.challenge_period_blocks * 12000),
        );

        let commit = RollupCommit {
            commitment: commitment.clone(),
            status: CommitmentStatus::Pending,
            challenge_deadline: Some(challenge_deadline),
            finalization_time: None,
            associated_batches: Vec::new(),
            da_availability: DAAvailabilityStatus::Unknown,
            verification_count: 0,
            last_verified: None,
        };

        let commitment_hash = commitment.commitment_hash;

        self.commitments.insert(commitment_hash, commit);

        self.operator_commitments
            .entry(commitment.operator)
            .or_insert_with(Vec::new)
            .push(commitment_hash);

        Ok(commitment_hash)
    }

    pub fn challenge_commitment(
        &mut self,
        commitment_hash: Hash,
        challenger: Address,
        challenge_type: ChallengeType,
        bond_amount: u64,
        evidence: Vec<u8>,
    ) -> RollupResult<Hash> {
        let commit = self
            .commitments
            .get_mut(&commitment_hash)
            .ok_or_else(|| RollupError::InvalidCommitment("Commitment not found".to_string()))?;

        match &commit.status {
            CommitmentStatus::Pending => {}
            CommitmentStatus::Finalized => {
                return Err(RollupError::ChallengePeriodExpired);
            }
            CommitmentStatus::Challenged(_) => {
                return Err(RollupError::InvalidCommitment(
                    "Commitment already challenged".to_string(),
                ));
            }
            CommitmentStatus::Slashed => {
                return Err(RollupError::InvalidCommitment(
                    "Commitment already slashed".to_string(),
                ));
            }
        }

        if let Some(deadline) = commit.challenge_deadline {
            if Timestamp::now() > deadline {
                return Err(RollupError::ChallengePeriodExpired);
            }
        }

        let mut data = Vec::new();
        data.extend_from_slice(challenger.as_bytes());
        data.extend_from_slice(commitment_hash.as_bytes());
        data.extend_from_slice(&Timestamp::now().as_millis().to_le_bytes());
        let challenge_hash = ego_core::crypto::hash_data(&data);

        let response_deadline = Timestamp::from_millis(
            Timestamp::now().as_millis() + (self.response_window_blocks * 12000),
        );

        let challenge_info = ChallengeInfo {
            challenger,
            challenge_hash,
            challenge_type: challenge_type.clone(),
            submitted_at: Timestamp::now(),
            deadline: response_deadline,
            bond_amount,
            evidence,
        };

        commit.status = CommitmentStatus::Challenged(ChallengeStatus::Pending {
            challenger,
            challenge_hash,
            deadline: response_deadline,
        });

        self.pending_challenges
            .insert(challenge_hash, challenge_info);

        Ok(challenge_hash)
    }

    pub fn resolve_challenge(
        &mut self,
        challenge_hash: Hash,
        successful: bool,
    ) -> RollupResult<()> {
        let _challenge_info = self
            .pending_challenges
            .remove(&challenge_hash)
            .ok_or_else(|| RollupError::FraudProof("Challenge not found".to_string()))?;

        let mut commitment_hash = None;
        for (hash, commit) in &mut self.commitments {
            if let CommitmentStatus::Challenged(ChallengeStatus::Pending {
                challenge_hash: ch,
                ..
            }) = &commit.status
            {
                if *ch == challenge_hash {
                    commitment_hash = Some(*hash);
                    break;
                }
            }
        }

        let commitment_hash = commitment_hash.ok_or_else(|| {
            RollupError::FraudProof("Associated commitment not found".to_string())
        })?;

        let commit = self.commitments.get_mut(&commitment_hash).unwrap();

        if successful {
            commit.status = CommitmentStatus::Slashed;
        } else {
            commit.status = CommitmentStatus::Finalized;
            commit.finalization_time = Some(Timestamp::now());
        }

        Ok(())
    }

    pub fn finalize_expired_commitments(&mut self, _current_block: u64) -> Vec<Hash> {
        let mut finalized = Vec::new();
        let current_time = Timestamp::now();

        for (hash, commit) in &mut self.commitments {
            if let CommitmentStatus::Pending = commit.status {
                if let Some(deadline) = commit.challenge_deadline {
                    if current_time > deadline {
                        commit.status = CommitmentStatus::Finalized;
                        commit.finalization_time = Some(current_time);
                        finalized.push(*hash);
                    }
                }
            }
        }

        finalized
    }

    pub fn get_commitment(&self, hash: Hash) -> Option<&RollupCommit> {
        self.commitments.get(&hash)
    }

    pub fn get_commitment_mut(&mut self, hash: Hash) -> Option<&mut RollupCommit> {
        self.commitments.get_mut(&hash)
    }

    pub fn get_operator_commitments(&self, operator: Address) -> Vec<Hash> {
        self.operator_commitments
            .get(&operator)
            .cloned()
            .unwrap_or_default()
    }

    pub fn get_pending_commitments(&self) -> Vec<Hash> {
        self.commitments
            .iter()
            .filter(|(_, commit)| matches!(commit.status, CommitmentStatus::Pending))
            .map(|(hash, _)| *hash)
            .collect()
    }

    pub fn get_challenged_commitments(&self) -> Vec<Hash> {
        self.commitments
            .iter()
            .filter(|(_, commit)| matches!(commit.status, CommitmentStatus::Challenged(_)))
            .map(|(hash, _)| *hash)
            .collect()
    }

    pub fn get_finalized_commitments(&self) -> Vec<Hash> {
        self.commitments
            .iter()
            .filter(|(_, commit)| matches!(commit.status, CommitmentStatus::Finalized))
            .map(|(hash, _)| *hash)
            .collect()
    }

    pub fn verify_da_availability(
        &mut self,
        commitment_hash: Hash,
        sample_size: usize,
    ) -> RollupResult<bool> {
        let commit = self
            .commitments
            .get_mut(&commitment_hash)
            .ok_or_else(|| RollupError::DataAvailability("Commitment not found".to_string()))?;

        let chunk_count = commit.commitment.da_chunks.len();
        if chunk_count == 0 {
            commit.da_availability = DAAvailabilityStatus::Unavailable;
            return Ok(false);
        }

        let sample_indices: Vec<u32> = (0..sample_size.min(chunk_count))
            .map(|i| commit.commitment.da_chunks[i])
            .collect();

        match self
            .da_manager
            .sample_chunks(commitment_hash, sample_indices.clone())
        {
            Ok(chunks) => {
                if chunks.len() == sample_indices.len() {
                    commit.da_availability = DAAvailabilityStatus::Available;
                    commit.verification_count += 1;
                    commit.last_verified = Some(Timestamp::now());
                    Ok(true)
                } else {
                    let missing: Vec<u32> = sample_indices
                        .into_iter()
                        .filter(|&idx| !chunks.iter().any(|c| c.chunk_id == idx))
                        .collect();

                    commit.da_availability = DAAvailabilityStatus::PartiallyAvailable {
                        missing_chunks: missing,
                    };
                    commit.verification_count += 1;
                    commit.last_verified = Some(Timestamp::now());
                    Ok(false)
                }
            }
            Err(_) => {
                commit.da_availability = DAAvailabilityStatus::Unavailable;
                commit.verification_count += 1;
                commit.last_verified = Some(Timestamp::now());
                Ok(false)
            }
        }
    }

    pub fn get_commitment_stats(&self) -> CommitmentStats {
        let mut stats = CommitmentStats::default();

        for commit in self.commitments.values() {
            stats.total_commitments += 1;

            match &commit.status {
                CommitmentStatus::Pending => stats.pending_commitments += 1,
                CommitmentStatus::Challenged(_) => stats.challenged_commitments += 1,
                CommitmentStatus::Finalized => stats.finalized_commitments += 1,
                CommitmentStatus::Slashed => stats.slashed_commitments += 1,
            }

            match &commit.da_availability {
                DAAvailabilityStatus::Available => stats.available_da += 1,
                DAAvailabilityStatus::PartiallyAvailable { .. } => {
                    stats.partially_available_da += 1
                }
                DAAvailabilityStatus::Unavailable => stats.unavailable_da += 1,
                DAAvailabilityStatus::Unknown => stats.unknown_da += 1,
            }

            stats.total_transactions += commit.commitment.tx_count as u64;
            stats.total_gas_used += commit.commitment.gas_used;
        }

        stats
    }

    pub fn associate_batch(&mut self, commitment_hash: Hash, batch_hash: Hash) -> RollupResult<()> {
        let commit = self
            .commitments
            .get_mut(&commitment_hash)
            .ok_or_else(|| RollupError::InvalidCommitment("Commitment not found".to_string()))?;

        if !commit.associated_batches.contains(&batch_hash) {
            commit.associated_batches.push(batch_hash);
        }

        Ok(())
    }

    pub fn get_challenge_info(&self, challenge_hash: Hash) -> Option<&ChallengeInfo> {
        self.pending_challenges.get(&challenge_hash)
    }

    pub fn cleanup_old_commitments(&mut self, retention_epochs: u64, current_epoch: u64) -> usize {
        let cutoff_epoch = current_epoch.saturating_sub(retention_epochs);
        let mut removed = 0;

        self.commitments.retain(|hash, commit| {
            let should_keep = commit.commitment.epoch.as_u64() >= cutoff_epoch
                || !matches!(
                    commit.status,
                    CommitmentStatus::Finalized | CommitmentStatus::Slashed
                );

            if !should_keep {
                self.operator_commitments
                    .get_mut(&commit.commitment.operator)
                    .map(|hashes| hashes.retain(|h| h != hash));
                removed += 1;
            }

            should_keep
        });

        removed
    }

    pub fn verify_commitment_chain(&self, commitment_hashes: &[Hash]) -> RollupResult<bool> {
        if commitment_hashes.is_empty() {
            return Ok(true);
        }

        for i in 1..commitment_hashes.len() {
            let prev_commit = self
                .get_commitment(commitment_hashes[i - 1])
                .ok_or_else(|| {
                    RollupError::InvalidCommitment("Previous commitment not found".to_string())
                })?;

            let curr_commit = self.get_commitment(commitment_hashes[i]).ok_or_else(|| {
                RollupError::InvalidCommitment("Current commitment not found".to_string())
            })?;

            if curr_commit.commitment.previous_state_root != prev_commit.commitment.state_root {
                return Ok(false);
            }

            if curr_commit.commitment.block_range.0 < prev_commit.commitment.block_range.1 {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CommitmentStats {
    pub total_commitments: u64,
    pub pending_commitments: u64,
    pub challenged_commitments: u64,
    pub finalized_commitments: u64,
    pub slashed_commitments: u64,
    pub available_da: u64,
    pub partially_available_da: u64,
    pub unavailable_da: u64,
    pub unknown_da: u64,
    pub total_transactions: u64,
    pub total_gas_used: u64,
}

impl ChallengeType {
    pub fn from_string(s: &str) -> Option<Self> {
        match s {
            "invalid_state_transition" => Some(ChallengeType::InvalidStateTransition),
            "data_unavailability" => Some(ChallengeType::DataUnavailability),
            "invalid_proof" => Some(ChallengeType::InvalidProof),
            "invalid_inclusion" => Some(ChallengeType::InvalidInclusion),
            "invalid_aggregation" => Some(ChallengeType::InvalidAggregation),
            _ => None,
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            ChallengeType::InvalidStateTransition => "invalid_state_transition".to_string(),
            ChallengeType::DataUnavailability => "data_unavailability".to_string(),
            ChallengeType::InvalidProof => "invalid_proof".to_string(),
            ChallengeType::InvalidInclusion => "invalid_inclusion".to_string(),
            ChallengeType::InvalidAggregation => "invalid_aggregation".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::RollupBatch;
    use crate::da::DataAvailability;
    use ego_core::{Balance, EpochNumber, ShardId, Transaction, TransactionPayload};

    fn create_test_batch() -> RollupBatch {
        let operator = Address::new([1u8; 20]);
        let inner_tx = Transaction::new(
            Address::new([2u8; 20]),
            1,
            TransactionPayload::Transfer {
                to: Address::new([3u8; 20]),
                amount: Balance::from_egoc(100),
                memo: None,
                stealth_mode: false,
            },
            ShardId::new(0).unwrap(),
            None,
            1,
        );
        let rollup_tx = crate::types::RollupTransaction::new(inner_tx, 1, 1000);

        RollupBatch::new(
            operator,
            vec![rollup_tx],
            1000,
            Hash::ZERO,
            1,
            1,
            EpochNumber::new(0),
            ShardId::new(0).unwrap(),
        )
    }

    #[test]
    fn test_commitment_creation() {
        let batch = create_test_batch();
        let operator = Address::new([1u8; 20]);
        let commitment = RollupCommitment::new(
            operator,
            "test-rollup".to_string(),
            &batch,
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            1000,
            1000,
        );

        assert_eq!(commitment.operator, operator);
        assert_eq!(commitment.rollup_id, "test-rollup");
        assert_eq!(commitment.tx_count, 1);
        assert!(commitment.validate().is_ok());
    }

    #[test]
    fn test_commitment_signing() {
        let batch = create_test_batch();
        let keypair = ego_core::crypto::KeyPair::generate();
        let operator = Address::from_public_key(&keypair.dilithium_public_key());

        let mut commitment = RollupCommitment::new(
            operator,
            "test-rollup".to_string(),
            &batch,
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            1000,
            1000,
        );

        assert!(commitment.sign(&keypair).is_ok());
        assert!(
            commitment
                .verify_signature(&keypair.dilithium_public_key())
                .unwrap()
        );
    }

    #[test]
    fn test_commitment_manager() {
        let da = DataAvailability::new(4, 2, 1024, false, 6).unwrap();
        let mut manager = CommitmentManager::new(da, 1000, 100, 1, 1, 1000);

        let batch = create_test_batch();
        let commitment = RollupCommitment::new(
            Address::new([1u8; 20]),
            "test-rollup".to_string(),
            &batch,
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            1000,
            1000,
        );

        let hash = manager.submit_commitment(commitment, vec![]).unwrap();
        assert!(manager.get_commitment(hash).is_some());

        let stats = manager.get_commitment_stats();
        assert_eq!(stats.total_commitments, 1);
        assert_eq!(stats.pending_commitments, 1);
    }

    #[test]
    fn test_commitment_reproducibility() {
        let batch = create_test_batch();
        let operator = Address::new([1u8; 20]);

        let commitment1 = RollupCommitment::new(
            operator,
            "test-rollup".to_string(),
            &batch,
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            1000,
            1000,
        );

        let commitment2 = RollupCommitment::new(
            operator,
            "test-rollup".to_string(),
            &batch,
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            1000,
            1000,
        );

        assert!(commitment1.is_reproducible(&commitment2));
    }

    #[test]
    fn test_challenge_commitment() {
        let da = DataAvailability::new(4, 2, 1024, false, 6).unwrap();
        let mut manager = CommitmentManager::new(da, 1000, 100, 1, 1, 1000);

        let batch = create_test_batch();
        let commitment = RollupCommitment::new(
            Address::new([1u8; 20]),
            "test-rollup".to_string(),
            &batch,
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            1000,
            1000,
        );

        let hash = manager.submit_commitment(commitment, vec![]).unwrap();

        let challenge_result = manager.challenge_commitment(
            hash,
            Address::new([2u8; 20]),
            ChallengeType::InvalidStateTransition,
            1000,
            vec![],
        );

        assert!(challenge_result.is_ok());
    }

    #[test]
    fn test_commitment_validation() {
        let batch = create_test_batch();
        let mut commitment = RollupCommitment::new(
            Address::new([1u8; 20]),
            "test-rollup".to_string(),
            &batch,
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            1000,
            1000,
        );

        assert!(commitment.validate().is_ok());

        commitment.tx_count = 0;
        assert!(commitment.validate().is_err());
    }

    #[test]
    fn test_cellular_optimization_detection() {
        let batch = create_test_batch();
        let commitment = RollupCommitment::new(
            Address::new([1u8; 20]),
            "test-rollup".to_string(),
            &batch,
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            1000,
            1000,
        );

        assert!(commitment.is_cellular_optimized());
    }
}
