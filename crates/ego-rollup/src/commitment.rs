use crate::batch::RollupBatch;
use crate::da::{DAChunk, DataAvailability};
use crate::error::{RollupError, RollupResult};
use crate::types::{ChallengeStatus, CommitmentStatus};
use ego_core::{Address, Hash, KeyPair, PublicKey, Signature, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    pub operator_signature: Signature,
    pub proof_data: Vec<u8>,
    pub da_chunks: Vec<u32>,
    pub gas_used: u64,
    pub version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollupCommit {
    pub commitment: RollupCommitment,
    pub status: CommitmentStatus,
    pub challenge_deadline: Option<Timestamp>,
    pub finalization_time: Option<Timestamp>,
    pub associated_batches: Vec<Hash>,
    pub da_availability: DAAvailabilityStatus,
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
}

#[derive(Debug, Clone)]
struct ChallengeInfo {
    challenger: Address,
    challenge_hash: Hash,
    challenge_type: String,
    submitted_at: Timestamp,
    deadline: Timestamp,
    bond_amount: u64,
}

impl RollupCommitment {
    pub fn new(
        operator: Address,
        rollup_id: String,
        batch: &RollupBatch,
        da_root: Hash,
        proofs_root: Hash,
        l1_block_number: u64,
    ) -> Self {
        let tx_root = Self::compute_tx_root(&batch.transactions);
        let commitment_hash = Self::compute_commitment_hash(
            &operator,
            &batch.prev_state_root,
            &batch.post_state_root,
            &tx_root,
            &da_root,
            batch.l1_block_number,
        );

        Self {
            commitment_hash,
            operator,
            rollup_id,
            state_root: batch.post_state_root,
            previous_state_root: batch.prev_state_root,
            tx_root,
            da_root,
            proofs_root,
            tx_count: batch.transactions.len() as u32,
            block_range: (batch.l1_block_number, batch.l1_block_number),
            l1_block_number,
            timestamp: Timestamp::now(),
            operator_signature: Signature::new([0u8; 64]),
            proof_data: Vec::new(),
            da_chunks: Vec::new(),
            gas_used: batch.gas_used,
            version: crate::ROLLUP_VERSION,
        }
    }

    pub fn sign(&mut self, keypair: &KeyPair) -> RollupResult<()> {
        let expected_operator = Address::from_public_key(&keypair.public_key());
        if expected_operator != self.operator {
            return Err(RollupError::InvalidCommitment(
                "Operator address does not match signing key".to_string(),
            ));
        }

        let signing_data = self.create_signing_data()?;
        self.operator_signature = keypair.sign(&signing_data);
        Ok(())
    }

    pub fn verify_signature(&self, public_key: &PublicKey) -> RollupResult<bool> {
        let expected_operator = Address::from_public_key(public_key);
        if expected_operator != self.operator {
            return Ok(false);
        }

        let signing_data = self.create_signing_data()?;
        ego_core::verify_signature(public_key, &signing_data, &self.operator_signature)
            .map_err(|e| RollupError::VerificationFailed(e.to_string()))
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

        if self.da_root == Hash::ZERO {
            return Err(RollupError::InvalidCommitment(
                "DA root cannot be zero".to_string(),
            ));
        }

        if self.version != crate::ROLLUP_VERSION {
            return Err(RollupError::InvalidCommitment(format!(
                "Unsupported rollup version: expected {}, got {}",
                crate::ROLLUP_VERSION,
                self.version
            )));
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
    }

    fn create_signing_data(&self) -> RollupResult<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(self.commitment_hash.as_bytes());
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
        Ok(data)
    }

    fn compute_commitment_hash(
        operator: &Address,
        prev_state_root: &Hash,
        state_root: &Hash,
        tx_root: &Hash,
        da_root: &Hash,
        l1_block_number: u64,
    ) -> Hash {
        use ego_core::crypto::hash_multiple;

        hash_multiple(&[
            operator.as_bytes(),
            prev_state_root.as_bytes(),
            state_root.as_bytes(),
            tx_root.as_bytes(),
            da_root.as_bytes(),
            &l1_block_number.to_le_bytes(),
        ])
    }

    fn compute_tx_root(transactions: &[crate::types::RollupTransaction]) -> Hash {
        if transactions.is_empty() {
            return Hash::ZERO;
        }

        let tx_hashes: Vec<Vec<u8>> = transactions.iter().map(|tx| tx.hash().to_vec()).collect();

        let merkle_tree = ego_core::crypto::MerkleTree::build(tx_hashes);
        merkle_tree.root_hash().unwrap_or(Hash::ZERO)
    }

    pub fn size(&self) -> usize {
        let config = bincode::config::standard();
        bincode::encode_to_vec(self, config)
            .map(|data| data.len())
            .unwrap_or(0)
    }
}

impl CommitmentManager {
    pub fn new(
        da_manager: DataAvailability,
        challenge_period_blocks: u64,
        response_window_blocks: u64,
    ) -> Self {
        Self {
            commitments: HashMap::new(),
            operator_commitments: HashMap::new(),
            pending_challenges: HashMap::new(),
            da_manager,
            challenge_period_blocks,
            response_window_blocks,
        }
    }

    pub fn submit_commitment(
        &mut self,
        mut commitment: RollupCommitment,
        da_chunks: Vec<DAChunk>,
    ) -> RollupResult<Hash> {
        commitment.validate()?;

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
            da_availability: DAAvailabilityStatus::Available,
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
        challenge_type: String,
        bond_amount: u64,
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

        let challenge_hash = Hash::new(rand::random());
        let response_deadline = Timestamp::from_millis(
            Timestamp::now().as_millis() + (self.response_window_blocks * 12000),
        );

        let _challenge_info = ChallengeInfo {
            challenger,
            challenge_hash,
            challenge_type: challenge_type.clone(),
            submitted_at: Timestamp::now(),
            deadline: response_deadline,
            bond_amount,
        };

        commit.status = CommitmentStatus::Challenged(ChallengeStatus::Pending {
            challenger,
            challenge_hash,
            deadline: response_deadline,
        });

        self.pending_challenges
            .insert(challenge_hash, _challenge_info);

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
            .map(|_| rand::random::<u32>() % chunk_count as u32)
            .collect();

        match self
            .da_manager
            .sample_chunks(commitment_hash, sample_indices.clone())
        {
            Ok(chunks) => {
                if chunks.len() == sample_indices.len() {
                    commit.da_availability = DAAvailabilityStatus::Available;
                    Ok(true)
                } else {
                    let missing: Vec<u32> = sample_indices
                        .into_iter()
                        .filter(|&idx| !chunks.iter().any(|c| c.chunk_id == idx))
                        .collect();

                    commit.da_availability = DAAvailabilityStatus::PartiallyAvailable {
                        missing_chunks: missing,
                    };
                    Ok(false)
                }
            }
            Err(_) => {
                commit.da_availability = DAAvailabilityStatus::Unavailable;
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
        }

        stats
    }
}

#[derive(Debug, Default)]
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::RollupBatch;
    use crate::da::DataAvailability;
    use ego_core::{Balance, KeyPair, ShardId, Transaction, TransactionPayload};

    fn create_test_batch() -> RollupBatch {
        let operator = Address::new([1u8; 20]);
        let inner_tx = Transaction::new(
            Address::new([2u8; 20]),
            1,
            TransactionPayload::Transfer {
                to: Address::new([3u8; 20]),
                amount: Balance::from_egoc(100),
                memo: None,
            },
            ShardId::new(0).unwrap(),
            None,
        );
        let rollup_tx = crate::types::RollupTransaction::new(inner_tx, 1, 1000);

        RollupBatch::new(operator, vec![rollup_tx], 1000, Hash::ZERO)
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
        );

        assert_eq!(commitment.operator, operator);
        assert_eq!(commitment.rollup_id, "test-rollup");
        assert_eq!(commitment.tx_count, 1);
        assert!(commitment.validate().is_ok());
    }

    #[test]
    fn test_commitment_signing() {
        let batch = create_test_batch();
        let keypair = KeyPair::generate();
        let operator = Address::from_public_key(&keypair.public_key());

        let mut commitment = RollupCommitment::new(
            operator,
            "test-rollup".to_string(),
            &batch,
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            1000,
        );

        assert!(commitment.sign(&keypair).is_ok());
        assert!(commitment.verify_signature(&keypair.public_key()).unwrap());
    }

    #[test]
    fn test_commitment_manager() {
        let da = DataAvailability::new(4, 2, 1024, false, 6).unwrap();
        let mut manager = CommitmentManager::new(da, 1000, 100);

        let batch = create_test_batch();
        let commitment = RollupCommitment::new(
            Address::new([1u8; 20]),
            "test-rollup".to_string(),
            &batch,
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            1000,
        );

        let hash = manager.submit_commitment(commitment, vec![]).unwrap();
        assert!(manager.get_commitment(hash).is_some());

        let stats = manager.get_commitment_stats();
        assert_eq!(stats.total_commitments, 1);
        assert_eq!(stats.pending_commitments, 1);
    }

    #[test]
    fn test_challenge_flow() {
        let da = DataAvailability::new(4, 2, 1024, false, 6).unwrap();
        let mut manager = CommitmentManager::new(da, 1000, 100);

        let batch = create_test_batch();
        let commitment = RollupCommitment::new(
            Address::new([1u8; 20]),
            "test-rollup".to_string(),
            &batch,
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            1000,
        );

        let commitment_hash = manager.submit_commitment(commitment, vec![]).unwrap();

        let challenger = Address::new([2u8; 20]);
        let challenge_hash = manager
            .challenge_commitment(commitment_hash, challenger, "fraud".to_string(), 10000)
            .unwrap();

        assert!(manager.resolve_challenge(challenge_hash, false).is_ok());

        let commit = manager.get_commitment(commitment_hash).unwrap();
        assert!(matches!(commit.status, CommitmentStatus::Finalized));
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
        );

        let commitment2 = RollupCommitment::new(
            operator,
            "test-rollup".to_string(),
            &batch,
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            1000,
        );

        assert!(commitment1.is_reproducible(&commitment2));
    }
}
