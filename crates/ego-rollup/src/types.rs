use ego_core::{Address, Hash, Signature, Timestamp, Transaction};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct RollupTransaction {
    pub inner: Transaction,
    pub rollup_nonce: u64,
    pub l1_block_number: u64,
    pub inclusion_proof: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct RollupBlock {
    pub block_number: u64,
    pub parent_hash: Hash,
    pub state_root: Hash,
    pub transactions_root: Hash,
    pub timestamp: Timestamp,
    pub transactions: Vec<RollupTransaction>,
    pub operator: Address,
    pub signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct RollupExecutionResult {
    pub tx_hash: Hash,
    pub success: bool,
    pub gas_used: u64,
    pub state_changes: Vec<StateChange>,
    pub events: Vec<RollupEvent>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct StateChange {
    pub address: Address,
    pub key: Vec<u8>,
    pub old_value: Option<Vec<u8>>,
    pub new_value: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct RollupEvent {
    pub address: Address,
    pub topics: Vec<Hash>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChallengeStatus {
    None,
    Pending {
        challenger: Address,
        challenge_hash: Hash,
        deadline: Timestamp,
    },
    Resolved {
        successful: bool,
        resolved_at: Timestamp,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CommitmentStatus {
    Pending,
    Challenged(ChallengeStatus),
    Finalized,
    Slashed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorInfo {
    pub address: Address,
    pub bond_amount: u64,
    pub is_active: bool,
    pub last_commit: Option<Timestamp>,
    pub total_commits: u64,
    pub successful_challenges: u64,
    pub failed_challenges: u64,
    pub slash_count: u64,
    pub reputation_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct LightClientProof {
    pub commitment_hash: Hash,
    pub state_root: Hash,
    pub inclusion_proof: Vec<Hash>,
    pub da_proof: Vec<u8>,
    pub block_header: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct WithdrawalRequest {
    pub request_id: Hash,
    pub user: Address,
    pub amount: u64,
    pub asset: Address,
    pub l1_recipient: Address,
    pub rollup_block: u64,
    pub inclusion_proof: Vec<Hash>,
    pub status: WithdrawalStatus,
    pub created_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub enum WithdrawalStatus {
    Pending,
    Challenged,
    ReadyToFinalize,
    Finalized,
    Cancelled,
}

impl RollupTransaction {
    pub fn new(inner: Transaction, rollup_nonce: u64, l1_block_number: u64) -> Self {
        Self {
            inner,
            rollup_nonce,
            l1_block_number,
            inclusion_proof: None,
        }
    }

    pub fn hash(&self) -> Hash {
        let config = bincode::config::standard();
        let data = bincode::encode_to_vec(self, config).unwrap_or_default();
        ego_core::crypto::hash_data(&data)
    }

    pub fn size(&self) -> usize {
        let config = bincode::config::standard();
        bincode::encode_to_vec(self, config)
            .map(|data| data.len())
            .unwrap_or(0)
    }
}

impl RollupBlock {
    pub fn new(
        block_number: u64,
        parent_hash: Hash,
        transactions: Vec<RollupTransaction>,
        operator: Address,
    ) -> Self {
        let transactions_root = Self::compute_transactions_root(&transactions);

        Self {
            block_number,
            parent_hash,
            state_root: Hash::ZERO,
            transactions_root,
            timestamp: Timestamp::now(),
            transactions,
            operator,
            signature: Signature::ed25519([0u8; 64]),
        }
    }

    pub fn hash(&self) -> Hash {
        let config = bincode::config::standard();
        let mut block_copy = self.clone();
        block_copy.signature = Signature::ed25519([0u8; 64]);

        let data = bincode::encode_to_vec(&block_copy, config).unwrap_or_default();
        ego_core::crypto::hash_data(&data)
    }

    pub fn sign(&mut self, keypair: &ego_core::KeyPair) -> Result<(), ego_core::EgoError> {
        let hash = self.hash();
        self.signature = keypair.sign(hash.as_bytes());
        Ok(())
    }

    pub fn verify_signature(
        &self,
        public_key: &ego_core::PublicKey,
    ) -> Result<bool, ego_core::EgoError> {
        let hash = self.hash();
        ego_core::verify_signature(public_key, hash.as_bytes(), &self.signature)
    }

    fn compute_transactions_root(transactions: &[RollupTransaction]) -> Hash {
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

impl Default for OperatorInfo {
    fn default() -> Self {
        Self {
            address: Address::new([0u8; 20]),
            bond_amount: 0,
            is_active: false,
            last_commit: None,
            total_commits: 0,
            successful_challenges: 0,
            failed_challenges: 0,
            slash_count: 0,
            reputation_score: 1.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::{Balance, KeyPair, ShardId, Transaction, TransactionPayload};

    #[test]
    fn test_rollup_transaction_creation() {
        let inner_tx = Transaction::new(
            Address::new([1u8; 20]),
            1,
            TransactionPayload::Transfer {
                to: Address::new([2u8; 20]),
                amount: Balance::from_egoc(100),
                memo: None,
                stealth_mode: false,
            },
            ShardId::new(0).unwrap(),
            None,
            1, // chain_id
        );

        let rollup_tx = RollupTransaction::new(inner_tx, 1, 1000);
        assert_eq!(rollup_tx.rollup_nonce, 1);
        assert_eq!(rollup_tx.l1_block_number, 1000);
        assert!(rollup_tx.inclusion_proof.is_none());
    }

    #[test]
    fn test_rollup_block_creation() {
        let transactions = vec![];
        let operator = Address::new([1u8; 20]);
        let parent_hash = Hash::new([0u8; 32]);

        let block = RollupBlock::new(1, parent_hash, transactions, operator);
        assert_eq!(block.block_number, 1);
        assert_eq!(block.parent_hash, parent_hash);
        assert_eq!(block.operator, operator);
        assert_eq!(block.transactions.len(), 0);
    }

    #[test]
    fn test_rollup_block_signing() {
        let keypair = KeyPair::generate();
        let operator = Address::from_public_key(&keypair.public_key());
        let mut block = RollupBlock::new(1, Hash::ZERO, vec![], operator);

        assert!(block.sign(&keypair).is_ok());
        assert!(block.verify_signature(&keypair.public_key()).unwrap());
    }

    #[test]
    fn test_challenge_status() {
        let status = ChallengeStatus::None;
        assert_eq!(status, ChallengeStatus::None);

        let pending = ChallengeStatus::Pending {
            challenger: Address::new([1u8; 20]),
            challenge_hash: Hash::new([1u8; 32]),
            deadline: Timestamp::now(),
        };

        match pending {
            ChallengeStatus::Pending { .. } => (),
            _ => panic!("Expected pending status"),
        }
    }
}
