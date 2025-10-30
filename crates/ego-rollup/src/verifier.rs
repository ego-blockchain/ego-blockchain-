use crate::commitment::RollupCommitment;
use crate::da::DataAvailability;
use crate::error::{RollupError, RollupResult};
use crate::fraud::{FraudProof, FraudProofVerifier};
use crate::state::RollupState;
use crate::types::RollupTransaction;
use ego_core::{Address, Hash, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub struct RollupVerifier {
    fraud_verifier: FraudProofVerifier,
    da_manager: DataAvailability,
    trusted_operators: HashMap<Address, OperatorTrust>,
    verification_cache: HashMap<Hash, VerificationResult>,
    max_cache_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorTrust {
    pub address: Address,
    pub trust_score: f64,
    pub successful_commits: u64,
    pub challenged_commits: u64,
    pub slashed_commits: u64,
    pub last_activity: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub commitment_hash: Hash,
    pub is_valid: bool,
    pub confidence: f64,
    pub verification_time: Timestamp,
    pub issues: Vec<VerificationIssue>,
    pub da_availability: f64,
    pub fraud_proofs: Vec<Hash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationIssue {
    pub issue_type: IssueType,
    pub severity: IssueSeverity,
    pub description: String,
    pub evidence: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IssueType {
    InvalidSignature,
    StateRootMismatch,
    TransactionRootMismatch,
    DAUnavailable,
    InvalidTransactionInclusion,
    ExecutionError,
    TimestampError,
    OperatorMisbehavior,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum IssueSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl RollupVerifier {
    pub fn new(
        fraud_verifier: FraudProofVerifier,
        da_manager: DataAvailability,
        max_cache_size: usize,
    ) -> Self {
        Self {
            fraud_verifier,
            da_manager,
            trusted_operators: HashMap::new(),
            verification_cache: HashMap::new(),
            max_cache_size,
        }
    }

    pub async fn verify_commitment(
        &mut self,
        commitment: &RollupCommitment,
        state: &RollupState,
        transactions: &[RollupTransaction],
    ) -> RollupResult<VerificationResult> {
        if let Some(cached_result) = self.verification_cache.get(&commitment.commitment_hash) {
            return Ok(cached_result.clone());
        }

        let mut issues = Vec::new();
        let mut confidence = 1.0;

        if let Err(e) = commitment.validate() {
            issues.push(VerificationIssue {
                issue_type: IssueType::InvalidSignature,
                severity: IssueSeverity::Critical,
                description: format!("Commitment validation failed: {}", e),
                evidence: None,
            });
            confidence = 0.0;
        }

        if let Some(operator_trust) = self.trusted_operators.get(&commitment.operator) {
            if let Err(_) = self.verify_operator_signature(commitment, operator_trust) {
                issues.push(VerificationIssue {
                    issue_type: IssueType::InvalidSignature,
                    severity: IssueSeverity::High,
                    description: "Invalid operator signature".to_string(),
                    evidence: None,
                });
                confidence *= 0.5;
            }
        } else {
            issues.push(VerificationIssue {
                issue_type: IssueType::OperatorMisbehavior,
                severity: IssueSeverity::Medium,
                description: "Unknown operator".to_string(),
                evidence: None,
            });
            confidence *= 0.8;
        }

        let expected_state_root = state.get_state_root();
        if commitment.previous_state_root != expected_state_root {
            issues.push(VerificationIssue {
                issue_type: IssueType::StateRootMismatch,
                severity: IssueSeverity::High,
                description: "Previous state root mismatch".to_string(),
                evidence: Some(expected_state_root.to_vec()),
            });
            confidence *= 0.3;
        }

        let computed_tx_root = self.compute_transaction_root(transactions);
        if commitment.tx_root != computed_tx_root {
            issues.push(VerificationIssue {
                issue_type: IssueType::TransactionRootMismatch,
                severity: IssueSeverity::High,
                description: "Transaction root mismatch".to_string(),
                evidence: Some(computed_tx_root.to_vec()),
            });
            confidence *= 0.2;
        }

        if commitment.tx_count != transactions.len() as u32 {
            issues.push(VerificationIssue {
                issue_type: IssueType::InvalidTransactionInclusion,
                severity: IssueSeverity::Medium,
                description: "Transaction count mismatch".to_string(),
                evidence: None,
            });
            confidence *= 0.7;
        }

        let da_availability = self.verify_data_availability(commitment).await?;
        if da_availability < 0.9 {
            issues.push(VerificationIssue {
                issue_type: IssueType::DAUnavailable,
                severity: if da_availability < 0.5 {
                    IssueSeverity::Critical
                } else {
                    IssueSeverity::High
                },
                description: format!("Low data availability: {:.1}%", da_availability * 100.0),
                evidence: None,
            });
            confidence *= da_availability;
        }

        if let Err(issue) = self.verify_timestamp(commitment) {
            issues.push(issue);
            confidence *= 0.9;
        }

        if let Some(execution_issues) = self.verify_execution(commitment, transactions).await? {
            issues.extend(execution_issues);
            confidence *= 0.6;
        }

        let result = VerificationResult {
            commitment_hash: commitment.commitment_hash,
            is_valid: confidence > 0.7,
            confidence,
            verification_time: Timestamp::now(),
            issues,
            da_availability,
            fraud_proofs: vec![],
        };

        self.cache_result(result.clone());

        Ok(result)
    }

    pub fn verify_fraud_proof(&self, proof: &FraudProof) -> RollupResult<bool> {
        self.fraud_verifier.verify_fraud_proof(proof)
    }

    pub fn execute_fraud_proof(
        &self,
        proof: &FraudProof,
    ) -> RollupResult<crate::fraud::FraudProofResult> {
        self.fraud_verifier.execute_fraud_proof(proof)
    }

    pub fn update_operator_trust(&mut self, operator: Address, trust: OperatorTrust) {
        self.trusted_operators.insert(operator, trust);
    }

    pub fn get_operator_trust(&self, operator: Address) -> Option<&OperatorTrust> {
        self.trusted_operators.get(&operator)
    }

    async fn verify_data_availability(&self, commitment: &RollupCommitment) -> RollupResult<f64> {
        if commitment.da_chunks.is_empty() {
            return Ok(0.0);
        }

        let sample_size = (commitment.da_chunks.len() / 4).max(1).min(16);
        let mut available_count = 0;

        for &chunk_id in commitment.da_chunks.iter().take(sample_size) {
            if chunk_id % 3 != 0 {
                available_count += 1;
            }
        }

        Ok(available_count as f64 / sample_size as f64)
    }

    fn verify_operator_signature(
        &self,
        commitment: &RollupCommitment,
        _operator_trust: &OperatorTrust,
    ) -> RollupResult<()> {
        if commitment
            .operator_signature
            .as_bytes()
            .iter()
            .all(|&b| b == 0)
        {
            return Err(RollupError::VerificationFailed(
                "Empty signature".to_string(),
            ));
        }
        Ok(())
    }

    fn compute_transaction_root(&self, transactions: &[RollupTransaction]) -> Hash {
        if transactions.is_empty() {
            return Hash::ZERO;
        }

        let tx_hashes: Vec<Vec<u8>> = transactions.iter().map(|tx| tx.hash().to_vec()).collect();

        let merkle_tree = ego_core::crypto::MerkleTree::build(tx_hashes);
        merkle_tree.root_hash().unwrap_or(Hash::ZERO)
    }

    fn verify_timestamp(&self, commitment: &RollupCommitment) -> Result<(), VerificationIssue> {
        let now = Timestamp::now();
        let commitment_time = commitment.timestamp;

        if commitment_time.as_millis() > now.as_millis() + 300_000 {
            return Err(VerificationIssue {
                issue_type: IssueType::TimestampError,
                severity: IssueSeverity::Medium,
                description: "Commitment timestamp too far in future".to_string(),
                evidence: None,
            });
        }

        if now.as_millis() > commitment_time.as_millis() + 86_400_000 {
            // 24 hours
            return Err(VerificationIssue {
                issue_type: IssueType::TimestampError,
                severity: IssueSeverity::Low,
                description: "Commitment timestamp too old".to_string(),
                evidence: None,
            });
        }

        Ok(())
    }

    async fn verify_execution(
        &self,
        _commitment: &RollupCommitment,
        _transactions: &[RollupTransaction],
    ) -> RollupResult<Option<Vec<VerificationIssue>>> {
        Ok(None)
    }

    fn cache_result(&mut self, result: VerificationResult) {
        if self.verification_cache.len() >= self.max_cache_size {
            if let Some(oldest_key) = self
                .verification_cache
                .iter()
                .min_by_key(|(_, v)| v.verification_time)
                .map(|(k, _)| *k)
            {
                self.verification_cache.remove(&oldest_key);
            }
        }

        self.verification_cache
            .insert(result.commitment_hash, result);
    }

    pub fn get_verification_stats(&self) -> VerificationStats {
        let mut stats = VerificationStats::default();

        for result in self.verification_cache.values() {
            stats.total_verifications += 1;

            if result.is_valid {
                stats.valid_commitments += 1;
            } else {
                stats.invalid_commitments += 1;
            }

            stats.average_confidence += result.confidence;
            stats.average_da_availability += result.da_availability;

            for issue in &result.issues {
                match issue.severity {
                    IssueSeverity::Critical => stats.critical_issues += 1,
                    IssueSeverity::High => stats.high_issues += 1,
                    IssueSeverity::Medium => stats.medium_issues += 1,
                    IssueSeverity::Low => stats.low_issues += 1,
                }
            }
        }

        if stats.total_verifications > 0 {
            stats.average_confidence /= stats.total_verifications as f64;
            stats.average_da_availability /= stats.total_verifications as f64;
        }

        stats.trusted_operators = self.trusted_operators.len() as u64;
        stats.cache_size = self.verification_cache.len() as u64;

        stats
    }

    pub fn clear_cache(&mut self) {
        self.verification_cache.clear();
    }

    pub fn cleanup_cache(&mut self, max_age_hours: u64) {
        let cutoff = Timestamp::now().as_millis() - (max_age_hours * 3600 * 1000);

        self.verification_cache
            .retain(|_, result| result.verification_time.as_millis() > cutoff);
    }
}

#[derive(Debug, Default)]
pub struct VerificationStats {
    pub total_verifications: u64,
    pub valid_commitments: u64,
    pub invalid_commitments: u64,
    pub average_confidence: f64,
    pub average_da_availability: f64,
    pub critical_issues: u64,
    pub high_issues: u64,
    pub medium_issues: u64,
    pub low_issues: u64,
    pub trusted_operators: u64,
    pub cache_size: u64,
}

impl OperatorTrust {
    pub fn new(address: Address) -> Self {
        Self {
            address,
            trust_score: 1.0,
            successful_commits: 0,
            challenged_commits: 0,
            slashed_commits: 0,
            last_activity: Timestamp::now(),
        }
    }

    pub fn update_successful_commit(&mut self) {
        self.successful_commits += 1;
        self.last_activity = Timestamp::now();
        self.recalculate_trust_score();
    }

    pub fn update_challenged_commit(&mut self) {
        self.challenged_commits += 1;
        self.last_activity = Timestamp::now();
        self.recalculate_trust_score();
    }

    pub fn update_slashed_commit(&mut self) {
        self.slashed_commits += 1;
        self.last_activity = Timestamp::now();
        self.recalculate_trust_score();
    }

    fn recalculate_trust_score(&mut self) {
        let total_commits =
            self.successful_commits + self.challenged_commits + self.slashed_commits;

        if total_commits == 0 {
            self.trust_score = 1.0;
            return;
        }

        let success_rate = self.successful_commits as f64 / total_commits as f64;
        let challenge_penalty = (self.challenged_commits as f64 / total_commits as f64) * 0.3;
        let slash_penalty = (self.slashed_commits as f64 / total_commits as f64) * 0.8;

        self.trust_score = (success_rate - challenge_penalty - slash_penalty)
            .max(0.0)
            .min(1.0);
    }

    pub fn is_trusted(&self) -> bool {
        self.trust_score > 0.7
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::da::DataAvailability;
    use crate::fraud::FraudProofVerifier;
    use ego_core::{Balance, KeyPair, ShardId, Transaction, TransactionPayload};

    fn create_test_verifier() -> RollupVerifier {
        let fraud_verifier = FraudProofVerifier::default();
        let da_manager = DataAvailability::new(4, 2, 1024, false, 6).unwrap();
        RollupVerifier::new(fraud_verifier, da_manager, 100)
    }

    fn create_test_commitment() -> RollupCommitment {
        RollupCommitment {
            commitment_hash: Hash::new([1u8; 32]),
            operator: Address::new([1u8; 20]),
            rollup_id: "test-rollup".to_string(),
            state_root: Hash::new([2u8; 32]),
            previous_state_root: Hash::new([3u8; 32]),
            tx_root: Hash::new([4u8; 32]),
            da_root: Hash::new([5u8; 32]),
            proofs_root: Hash::new([6u8; 32]),
            tx_count: 1,
            block_range: (1000, 1000),
            l1_block_number: 1000,
            timestamp: Timestamp::now(),
            operator_signature: ego_core::Signature::ed25519([0u8; 64]),
            proof_data: vec![],
            da_chunks: vec![0, 1, 2, 3],
            gas_used: 21000,
            version: 1,
        }
    }

    fn create_test_transaction() -> RollupTransaction {
        let inner = Transaction::new(
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
            1,
        );

        crate::types::RollupTransaction::new(inner, 1, 1000)
    }

    #[tokio::test]
    async fn test_verifier_creation() {
        let verifier = create_test_verifier();
        let stats = verifier.get_verification_stats();
        assert_eq!(stats.total_verifications, 0);
        assert_eq!(stats.trusted_operators, 0);
    }

    #[tokio::test]
    async fn test_commitment_verification() {
        let mut verifier = create_test_verifier();
        let commitment = create_test_commitment();
        let state = RollupState::new();
        let transactions = vec![create_test_transaction()];

        let result = verifier
            .verify_commitment(&commitment, &state, &transactions)
            .await
            .unwrap();

        assert!(!result.issues.is_empty());
        assert!(result.confidence < 1.0);
    }

    #[test]
    fn test_operator_trust() {
        let mut trust = OperatorTrust::new(Address::new([1u8; 20]));
        assert_eq!(trust.trust_score, 1.0);
        assert!(trust.is_trusted());

        trust.update_successful_commit();
        assert!(trust.is_trusted());

        trust.update_slashed_commit();
        assert!(trust.trust_score < 1.0);
    }

    #[test]
    fn test_verification_issue_severity() {
        let critical = VerificationIssue {
            issue_type: IssueType::InvalidSignature,
            severity: IssueSeverity::Critical,
            description: "Test".to_string(),
            evidence: None,
        };

        let low = VerificationIssue {
            issue_type: IssueType::TimestampError,
            severity: IssueSeverity::Low,
            description: "Test".to_string(),
            evidence: None,
        };

        assert!(critical.severity > low.severity);
    }

    #[tokio::test]
    async fn test_verification_caching() {
        let mut verifier = create_test_verifier();
        let commitment = create_test_commitment();
        let state = RollupState::new();
        let transactions = vec![create_test_transaction()];

        let result1 = verifier
            .verify_commitment(&commitment, &state, &transactions)
            .await
            .unwrap();

        let result2 = verifier
            .verify_commitment(&commitment, &state, &transactions)
            .await
            .unwrap();

        assert_eq!(result1.commitment_hash, result2.commitment_hash);
        assert_eq!(result1.confidence, result2.confidence);

        let stats = verifier.get_verification_stats();
        assert_eq!(stats.cache_size, 1);
    }

    #[test]
    fn test_cache_cleanup() {
        let mut verifier = create_test_verifier();

        let result = VerificationResult {
            commitment_hash: Hash::new([1u8; 32]),
            is_valid: true,
            confidence: 1.0,
            verification_time: Timestamp::from_millis(0),
            issues: vec![],
            da_availability: 1.0,
            fraud_proofs: vec![],
        };

        verifier.cache_result(result);
        assert_eq!(verifier.verification_cache.len(), 1);

        verifier.cleanup_cache(1);
        assert_eq!(verifier.verification_cache.len(), 0);
    }

    #[test]
    fn test_transaction_root_computation() {
        let verifier = create_test_verifier();
        let transactions = vec![create_test_transaction()];

        let root1 = verifier.compute_transaction_root(&transactions);
        let root2 = verifier.compute_transaction_root(&transactions);

        assert_eq!(root1, root2);

        let empty_root = verifier.compute_transaction_root(&[]);
        assert_eq!(empty_root, Hash::ZERO);
    }
}
