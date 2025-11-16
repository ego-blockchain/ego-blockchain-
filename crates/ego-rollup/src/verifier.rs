use crate::commitment::RollupCommitment;
use crate::da::DataAvailability;
use crate::error::{RollupError, RollupResult};
use crate::fraud::FraudProofVerifier;
use crate::state::RollupState;
use crate::types::RollupTransaction;
use ego_core::{Address, Balance, Hash, PublicKey, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct RollupVerifier {
    fraud_verifier: FraudProofVerifier,
    da_manager: Arc<RwLock<DataAvailability>>,
    trusted_operators: HashMap<Address, OperatorTrust>,
    verification_cache: HashMap<Hash, VerificationResult>,
    max_cache_size: usize,
    require_dilithium: bool,
    transition_mode: bool,
    chain_id: u32,
    network_id: u32,
    min_da_availability: f64,
    max_verification_age_hours: u64,
    cellular_safe_mode: bool,
    verified_commitments: HashSet<Hash>,
    failed_commitments: HashSet<Hash>,
    operator_pubkeys: HashMap<Address, PublicKey>,
    deploy_policy_enabled: bool,
    ai_pattern_detection_enabled: bool,
    human_verification_required: bool,
    drs_enabled: bool,
    density_penalty_enabled: bool,
    pob_credits_enabled: bool,
    storage_credits_tracking: HashMap<Address, u64>,
    deploy_credits_tracking: HashMap<Address, u64>,
    epoch_verification_stats: HashMap<u64, EpochVerificationStats>,
    cross_shard_receipt_cache: HashMap<Hash, CrossShardReceiptVerification>,
    post_verification_enabled: bool,
    poc_verification_enabled: bool,
    min_post_pass_rate: f64,
    min_poc_quality: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorTrust {
    pub address: Address,
    pub trust_score: f64,
    pub successful_commits: u64,
    pub challenged_commits: u64,
    pub slashed_commits: u64,
    pub last_activity: Timestamp,
    pub reputation_multiplier: f64,
    pub drs_score: f64,
    pub drs_multiplier: f64,
    pub consecutive_failures: u32,
    pub total_gas_processed: u64,
    pub avg_batch_latency_ms: u64,
    pub post_proofs_verified: u64,
    pub post_proofs_failed: u64,
    pub poc_proofs_verified: u64,
    pub poc_proofs_failed: u64,
    pub quota_band: ego_core::drs::QuotaBand,
    pub storage_credits_used: u64,
    pub deploy_credits_used: u64,
    pub ai_flagged_deploys: u32,
    pub human_verified_deploys: u32,
    pub cellular_safe_compliance: f64,
    pub density_violations: u32,
    pub last_drs_update: u64,
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
    pub signature_verified: bool,
    pub state_root_verified: bool,
    pub tx_root_verified: bool,
    pub da_verified: bool,
    pub timestamp_verified: bool,
    pub execution_verified: bool,
    pub operator_trust_score: f64,
    pub verification_latency_ms: u64,
    pub deploy_policy_checks: Vec<DeployPolicyCheckResult>,
    pub drs_scores_validated: bool,
    pub post_proofs_verified: u32,
    pub poc_proofs_verified: u32,
    pub storage_credits_validated: bool,
    pub deploy_credits_validated: bool,
    pub ai_pattern_checks: Vec<AIPatternCheckResult>,
    pub human_verification_status: HumanVerificationStatus,
    pub density_penalty_applied: bool,
    pub cellular_safe_compliant: bool,
    pub cross_shard_receipts_verified: u32,
    pub pq_signature_status: PQSignatureStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployPolicyCheckResult {
    pub deployer: Address,
    pub deploy_id: Hash,
    pub check_type: DeployCheckType,
    pub passed: bool,
    pub quota_used: u32,
    pub credits_consumed: u64,
    pub bond_locked: Option<Balance>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeployCheckType {
    FreeQuota,
    DeployCredits,
    StorageCredits,
    BondRequirement,
    AntiSpam,
    AIPatternDetection,
    HumanVerification,
    Deduplication,
    SizeLimit,
    RULimit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIPatternCheckResult {
    pub deployer: Address,
    pub deploy_id: Hash,
    pub patterns_detected: Vec<String>,
    pub flagged: bool,
    pub human_review_required: bool,
    pub confidence_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HumanVerificationStatus {
    NotRequired,
    Required,
    Verified,
    Failed,
    Pending,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PQSignatureStatus {
    DilithiumOnly,
    Ed25519Only,
    Hybrid,
    Missing,
    Invalid,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EpochVerificationStats {
    pub epoch: u64,
    pub total_commitments: u64,
    pub valid_commitments: u64,
    pub invalid_commitments: u64,
    pub total_transactions: u64,
    pub total_gas_used: u64,
    pub total_storage_credits_used: u64,
    pub total_deploy_credits_used: u64,
    pub ai_flagged_deploys: u32,
    pub human_verified_deploys: u32,
    pub post_proofs_verified: u64,
    pub poc_proofs_verified: u64,
    pub avg_drs_score: f64,
    pub density_penalties_applied: u32,
    pub cellular_safe_violations: u32,
    pub cross_shard_receipts: u64,
    pub pq_signatures: u64,
    pub legacy_signatures: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationIssue {
    pub issue_type: IssueType,
    pub severity: IssueSeverity,
    pub description: String,
    pub evidence: Option<Vec<u8>>,
    pub commitment_hash: Hash,
    pub operator: Address,
    pub timestamp: Timestamp,
    pub affected_transactions: Vec<Hash>,
    pub remediation_suggestion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IssueType {
    InvalidSignature,
    StateRootMismatch,
    TransactionRootMismatch,
    DAUnavailable,
    InvalidTransactionInclusion,
    ExecutionError,
    TimestampError,
    OperatorMisbehavior,
    PQSignatureRequired,
    ChainIdMismatch,
    NetworkIdMismatch,
    ShardIdMismatch,
    EpochMismatch,
    InvalidProofRoot,
    InvalidDARoot,
    CrossShardReceiptInvalid,
    ResourceUnitOverflow,
    DuplicateTransaction,
    InvalidNonce,
    ProtocolVersionMismatch,
    DeployPolicyViolation,
    AIPatternDetected,
    HumanVerificationFailed,
    DRSScoreInvalid,
    DensityPenaltyViolation,
    StorageCreditsInsufficient,
    DeployCreditsInsufficient,
    PoBBurnInsufficient,
    PostProofInvalid,
    PoCProofInvalid,
    CellularSafeViolation,
    QuotaExceeded,
    BondSlashed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum IssueSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossShardReceiptVerification {
    pub receipt_hash: Hash,
    pub source_shard: u32,
    pub target_shard: u32,
    pub merkle_proof: Vec<Hash>,
    pub merkle_root: Hash,
    pub is_valid: bool,
    pub verification_time: Timestamp,
    pub nonce: u64,
    pub deadline_epoch: u64,
    pub payload_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchVerificationRequest {
    pub commitments: Vec<RollupCommitment>,
    pub transactions: HashMap<Hash, Vec<RollupTransaction>>,
    pub state_roots: HashMap<Hash, Hash>,
    pub operator_pubkeys: HashMap<Address, PublicKey>,
    pub epoch: u64,
    pub drs_scores: HashMap<Address, f64>,
    pub deploy_records: HashMap<Hash, ego_core::deploy_policy::DeployRecord>,
    pub storage_entries: HashMap<Hash, ego_core::state::StorageEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchVerificationResult {
    pub results: HashMap<Hash, VerificationResult>,
    pub overall_success_rate: f64,
    pub total_issues: usize,
    pub critical_issues: usize,
    pub verification_duration_ms: u64,
    pub epoch_stats: EpochVerificationStats,
    pub operator_performance: HashMap<Address, OperatorPerformance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorPerformance {
    pub operator: Address,
    pub commitments_submitted: u64,
    pub commitments_verified: u64,
    pub commitments_rejected: u64,
    pub avg_latency_ms: u64,
    pub trust_score: f64,
    pub drs_multiplier: f64,
    pub reputation_multiplier: f64,
}

impl RollupVerifier {
    pub fn new(
        fraud_verifier: FraudProofVerifier,
        da_manager: DataAvailability,
        max_cache_size: usize,
        require_dilithium: bool,
        transition_mode: bool,
        chain_id: u32,
        network_id: u32,
    ) -> Self {
        Self {
            fraud_verifier,
            da_manager: Arc::new(RwLock::new(da_manager)),
            trusted_operators: HashMap::new(),
            verification_cache: HashMap::new(),
            max_cache_size,
            require_dilithium,
            transition_mode,
            chain_id,
            network_id,
            min_da_availability: 0.9,
            max_verification_age_hours: 24,
            cellular_safe_mode: false,
            verified_commitments: HashSet::new(),
            failed_commitments: HashSet::new(),
            operator_pubkeys: HashMap::new(),
            deploy_policy_enabled: true,
            ai_pattern_detection_enabled: true,
            human_verification_required: false,
            drs_enabled: true,
            density_penalty_enabled: true,
            pob_credits_enabled: true,
            storage_credits_tracking: HashMap::new(),
            deploy_credits_tracking: HashMap::new(),
            epoch_verification_stats: HashMap::new(),
            cross_shard_receipt_cache: HashMap::new(),
            post_verification_enabled: true,
            poc_verification_enabled: true,
            min_post_pass_rate: 0.8,
            min_poc_quality: 0.5,
        }
    }

    pub fn with_cellular_safe_mode(mut self, enabled: bool) -> Self {
        self.cellular_safe_mode = enabled;
        self
    }

    pub fn with_min_da_availability(mut self, min_availability: f64) -> Self {
        self.min_da_availability = min_availability.max(0.0).min(1.0);
        self
    }

    pub fn with_deploy_policy(mut self, enabled: bool) -> Self {
        self.deploy_policy_enabled = enabled;
        self
    }

    pub fn with_ai_detection(mut self, enabled: bool) -> Self {
        self.ai_pattern_detection_enabled = enabled;
        self
    }

    pub fn with_drs(mut self, enabled: bool) -> Self {
        self.drs_enabled = enabled;
        self
    }

    pub fn with_density_penalty(mut self, enabled: bool) -> Self {
        self.density_penalty_enabled = enabled;
        self
    }

    pub fn with_post_verification(mut self, enabled: bool, min_pass_rate: f64) -> Self {
        self.post_verification_enabled = enabled;
        self.min_post_pass_rate = min_pass_rate.max(0.0).min(1.0);
        self
    }

    pub fn with_poc_verification(mut self, enabled: bool, min_quality: f64) -> Self {
        self.poc_verification_enabled = enabled;
        self.min_poc_quality = min_quality.max(0.0).min(1.0);
        self
    }

    pub async fn verify_commitment(
        &mut self,
        commitment: &RollupCommitment,
        state: &RollupState,
        transactions: &[RollupTransaction],
    ) -> RollupResult<VerificationResult> {
        let start_time = std::time::Instant::now();

        if let Some(cached_result) = self.verification_cache.get(&commitment.commitment_hash) {
            return Ok(cached_result.clone());
        }

        let mut issues = Vec::new();
        let mut confidence = 1.0;
        let mut signature_verified = false;
        let mut state_root_verified = false;
        let mut tx_root_verified = false;
        let mut da_verified = false;
        let mut timestamp_verified = false;
        let mut execution_verified = false;
        let mut deploy_policy_checks = Vec::new();
        let mut drs_scores_validated = false;
        let mut post_proofs_verified = 0u32;
        let mut poc_proofs_verified = 0u32;
        let mut storage_credits_validated = false;
        let mut deploy_credits_validated = false;
        let mut ai_pattern_checks = Vec::new();
        let mut human_verification_status = HumanVerificationStatus::NotRequired;
        let mut density_penalty_applied = false;
        let mut cellular_safe_compliant = true;
        let mut pq_signature_status = PQSignatureStatus::Missing;

        if let Err(e) = commitment.validate() {
            issues.push(VerificationIssue {
                issue_type: IssueType::InvalidSignature,
                severity: IssueSeverity::Critical,
                description: format!("Commitment validation failed: {}", e),
                evidence: None,
                commitment_hash: commitment.commitment_hash,
                operator: commitment.operator,
                timestamp: Timestamp::now(),
                affected_transactions: vec![],
                remediation_suggestion: Some(
                    "Verify signature and commitment structure".to_string(),
                ),
            });
            confidence = 0.0;
        }

        if commitment.chain_id != self.chain_id {
            issues.push(VerificationIssue {
                issue_type: IssueType::ChainIdMismatch,
                severity: IssueSeverity::Critical,
                description: format!(
                    "Chain ID mismatch: expected {}, got {}",
                    self.chain_id, commitment.chain_id
                ),
                evidence: None,
                commitment_hash: commitment.commitment_hash,
                operator: commitment.operator,
                timestamp: Timestamp::now(),
                affected_transactions: vec![],
                remediation_suggestion: Some(format!("Use chain_id {}", self.chain_id)),
            });
            confidence = 0.0;
        }

        if commitment.network_id != self.network_id {
            issues.push(VerificationIssue {
                issue_type: IssueType::NetworkIdMismatch,
                severity: IssueSeverity::Critical,
                description: format!(
                    "Network ID mismatch: expected {}, got {}",
                    self.network_id, commitment.network_id
                ),
                evidence: None,
                commitment_hash: commitment.commitment_hash,
                operator: commitment.operator,
                timestamp: Timestamp::now(),
                affected_transactions: vec![],
                remediation_suggestion: Some(format!("Use network_id {}", self.network_id)),
            });
            confidence = 0.0;
        }

        if commitment.protocol_version != ego_core::PROTOCOL_VERSION {
            issues.push(VerificationIssue {
                issue_type: IssueType::ProtocolVersionMismatch,
                severity: IssueSeverity::High,
                description: format!(
                    "Protocol version mismatch: expected {}, got {}",
                    ego_core::PROTOCOL_VERSION,
                    commitment.protocol_version
                ),
                evidence: None,
                commitment_hash: commitment.commitment_hash,
                operator: commitment.operator,
                timestamp: Timestamp::now(),
                affected_transactions: vec![],
                remediation_suggestion: Some(format!(
                    "Upgrade to protocol version {}",
                    ego_core::PROTOCOL_VERSION
                )),
            });
            confidence *= 0.5;
        }

        match self.verify_operator_signature_pq(commitment).await {
            Ok((verified, status)) => {
                signature_verified = verified;
                pq_signature_status = status;
                if !verified {
                    issues.push(VerificationIssue {
                        issue_type: IssueType::InvalidSignature,
                        severity: IssueSeverity::Critical,
                        description: "Operator signature verification failed".to_string(),
                        evidence: None,
                        commitment_hash: commitment.commitment_hash,
                        operator: commitment.operator,
                        timestamp: Timestamp::now(),
                        affected_transactions: vec![],
                        remediation_suggestion: Some("Re-sign with valid keypair".to_string()),
                    });
                    confidence = 0.0;
                }
            }
            Err(e) => {
                issues.push(VerificationIssue {
                    issue_type: IssueType::InvalidSignature,
                    severity: IssueSeverity::Critical,
                    description: format!("Signature verification error: {}", e),
                    evidence: None,
                    commitment_hash: commitment.commitment_hash,
                    operator: commitment.operator,
                    timestamp: Timestamp::now(),
                    affected_transactions: vec![],
                    remediation_suggestion: Some(
                        "Check signature format and algorithm".to_string(),
                    ),
                });
                confidence = 0.0;
            }
        }

        if self.require_dilithium && commitment.operator_signature.dilithium_sig.is_none() {
            issues.push(VerificationIssue {
                issue_type: IssueType::PQSignatureRequired,
                severity: IssueSeverity::Critical,
                description: "Dilithium signature required in PQ-only mode".to_string(),
                evidence: None,
                commitment_hash: commitment.commitment_hash,
                operator: commitment.operator,
                timestamp: Timestamp::now(),
                affected_transactions: vec![],
                remediation_suggestion: Some("Sign with Dilithium-2 keypair".to_string()),
            });
            confidence = 0.0;
        }

        let expected_state_root = state.get_state_root();
        if commitment.previous_state_root != expected_state_root {
            issues.push(VerificationIssue {
                issue_type: IssueType::StateRootMismatch,
                severity: IssueSeverity::Critical,
                description: "Previous state root mismatch".to_string(),
                evidence: Some(expected_state_root.to_vec()),
                commitment_hash: commitment.commitment_hash,
                operator: commitment.operator,
                timestamp: Timestamp::now(),
                affected_transactions: vec![],
                remediation_suggestion: Some("Sync state with chain".to_string()),
            });
            confidence *= 0.1;
        } else {
            state_root_verified = true;
        }

        let computed_tx_root = self.compute_transaction_root(transactions);
        if commitment.tx_root != computed_tx_root {
            issues.push(VerificationIssue {
                issue_type: IssueType::TransactionRootMismatch,
                severity: IssueSeverity::Critical,
                description: "Transaction root mismatch".to_string(),
                evidence: Some(computed_tx_root.to_vec()),
                commitment_hash: commitment.commitment_hash,
                operator: commitment.operator,
                timestamp: Timestamp::now(),
                affected_transactions: vec![],
                remediation_suggestion: Some("Recompute transaction Merkle tree".to_string()),
            });
            confidence *= 0.1;
        } else {
            tx_root_verified = true;
        }

        if commitment.tx_count != transactions.len() as u32 {
            issues.push(VerificationIssue {
                issue_type: IssueType::InvalidTransactionInclusion,
                severity: IssueSeverity::High,
                description: format!(
                    "Transaction count mismatch: expected {}, got {}",
                    commitment.tx_count,
                    transactions.len()
                ),
                evidence: None,
                commitment_hash: commitment.commitment_hash,
                operator: commitment.operator,
                timestamp: Timestamp::now(),
                affected_transactions: vec![],
                remediation_suggestion: Some("Verify all transactions included".to_string()),
            });
            confidence *= 0.5;
        }

        if let Err(tx_issues) = self.verify_transactions(commitment, transactions).await {
            issues.push(VerificationIssue {
                issue_type: IssueType::InvalidTransactionInclusion,
                severity: IssueSeverity::High,
                description: format!("Transaction verification failed: {}", tx_issues),
                evidence: None,
                commitment_hash: commitment.commitment_hash,
                operator: commitment.operator,
                timestamp: Timestamp::now(),
                affected_transactions: vec![],
                remediation_suggestion: Some("Check transaction signatures and nonces".to_string()),
            });
            confidence *= 0.4;
        }

        let da_availability = self.verify_data_availability(commitment).await?;
        if da_availability < self.min_da_availability {
            issues.push(VerificationIssue {
                issue_type: IssueType::DAUnavailable,
                severity: if da_availability < 0.5 {
                    IssueSeverity::Critical
                } else {
                    IssueSeverity::High
                },
                description: format!(
                    "Low data availability: {:.1}% (required: {:.1}%)",
                    da_availability * 100.0,
                    self.min_da_availability * 100.0
                ),
                evidence: None,
                commitment_hash: commitment.commitment_hash,
                operator: commitment.operator,
                timestamp: Timestamp::now(),
                affected_transactions: vec![],
                remediation_suggestion: Some("Publish DA chunks to more nodes".to_string()),
            });
            confidence *= da_availability;
        } else {
            da_verified = true;
        }

        match self.verify_timestamp(commitment) {
            Ok(_) => {
                timestamp_verified = true;
            }
            Err(issue) => {
                issues.push(issue);
                confidence *= 0.9;
            }
        }

        if let Some(execution_issues) = self.verify_execution(commitment, transactions).await? {
            issues.extend(execution_issues);
            confidence *= 0.6;
        } else {
            execution_verified = true;
        }

        if self.deploy_policy_enabled {
            let (deploy_checks, deploy_issues) =
                self.verify_deploy_policy(commitment, transactions).await?;
            deploy_policy_checks = deploy_checks;
            if !deploy_issues.is_empty() {
                issues.extend(deploy_issues);
                confidence *= 0.8;
            }
        }

        if self.ai_pattern_detection_enabled {
            let (ai_checks, ai_issues) = self.verify_ai_patterns(transactions).await?;
            ai_pattern_checks = ai_checks;
            if !ai_issues.is_empty() {
                issues.extend(ai_issues);
                confidence *= 0.9;
            }
        }

        if self.human_verification_required {
            let (status, human_issues) = self.verify_human_verification(transactions).await?;
            human_verification_status = status;
            if !human_issues.is_empty() {
                issues.extend(human_issues);
                confidence *= 0.85;
            }
        }

        if self.drs_enabled {
            let (validated, drs_issues) = self.verify_drs_scores(commitment).await?;
            drs_scores_validated = validated;
            if !drs_issues.is_empty() {
                issues.extend(drs_issues);
                confidence *= 0.9;
            }
        }

        if self.density_penalty_enabled {
            let (applied, density_issues) = self.verify_density_penalties(commitment).await?;
            density_penalty_applied = applied;
            if !density_issues.is_empty() {
                issues.extend(density_issues);
                confidence *= 0.95;
            }
        }

        if self.pob_credits_enabled {
            let (storage_valid, deploy_valid, credit_issues) =
                self.verify_credits(commitment, transactions).await?;
            storage_credits_validated = storage_valid;
            deploy_credits_validated = deploy_valid;
            if !credit_issues.is_empty() {
                issues.extend(credit_issues);
                confidence *= 0.85;
            }
        }

        if self.post_verification_enabled {
            let (verified_count, post_issues) = self.verify_post_proofs(commitment).await?;
            post_proofs_verified = verified_count;
            if !post_issues.is_empty() {
                issues.extend(post_issues);
                confidence *= 0.9;
            }
        }

        if self.poc_verification_enabled {
            let (verified_count, poc_issues) = self.verify_poc_proofs(commitment).await?;
            poc_proofs_verified = verified_count;
            if !poc_issues.is_empty() {
                issues.extend(poc_issues);
                confidence *= 0.9;
            }
        }

        if self.cellular_safe_mode {
            let (compliant, cellular_issues) = self.verify_cellular_safe(commitment).await?;
            cellular_safe_compliant = compliant;
            if !cellular_issues.is_empty() {
                issues.extend(cellular_issues);
                confidence *= 0.95;
            }
        }

        let (cross_shard_receipts_verified, cs_issues) =
            self.verify_cross_shard_receipts(commitment).await?;
        if !cs_issues.is_empty() {
            issues.extend(cs_issues);
            confidence *= 0.9;
        }

        let operator_trust_score = self
            .trusted_operators
            .get(&commitment.operator)
            .map(|t| t.trust_score)
            .unwrap_or(0.5);

        if operator_trust_score < 0.5 {
            issues.push(VerificationIssue {
                issue_type: IssueType::OperatorMisbehavior,
                severity: IssueSeverity::High,
                description: format!("Low operator trust score: {:.2}", operator_trust_score),
                evidence: None,
                commitment_hash: commitment.commitment_hash,
                operator: commitment.operator,
                timestamp: Timestamp::now(),
                affected_transactions: vec![],
                remediation_suggestion: Some(
                    "Improve operator reliability and performance".to_string(),
                ),
            });
            confidence *= operator_trust_score;
        }

        let verification_latency_ms = start_time.elapsed().as_millis() as u64;

        let result = VerificationResult {
            commitment_hash: commitment.commitment_hash,
            is_valid: confidence >= 0.7,
            confidence,
            verification_time: Timestamp::now(),
            issues,
            da_availability,
            fraud_proofs: vec![],
            signature_verified,
            state_root_verified,
            tx_root_verified,
            da_verified,
            timestamp_verified,
            execution_verified,
            operator_trust_score,
            verification_latency_ms,
            deploy_policy_checks,
            drs_scores_validated,
            post_proofs_verified,
            poc_proofs_verified,
            storage_credits_validated,
            deploy_credits_validated,
            ai_pattern_checks,
            human_verification_status,
            density_penalty_applied,
            cellular_safe_compliant,
            cross_shard_receipts_verified,
            pq_signature_status,
        };

        if result.is_valid {
            self.verified_commitments.insert(commitment.commitment_hash);
            self.update_operator_success(
                &commitment.operator,
                commitment.gas_used,
                verification_latency_ms,
            );
        } else {
            self.failed_commitments.insert(commitment.commitment_hash);
            self.update_operator_failure(&commitment.operator);
        }

        self.update_epoch_stats(commitment.epoch.0, &result);

        self.cache_result(result.clone());

        Ok(result)
    }

    async fn verify_operator_signature_pq(
        &self,
        commitment: &RollupCommitment,
    ) -> RollupResult<(bool, PQSignatureStatus)> {
        if let Some(dilithium_sig) = &commitment.operator_signature.dilithium_sig {
            let pubkey = self
                .operator_pubkeys
                .get(&commitment.operator)
                .ok_or_else(|| {
                    RollupError::VerificationFailed("Operator public key not found".to_string())
                })?;

            let signing_data = self.create_commitment_signing_data(commitment)?;

            let verified = ego_core::crypto::verify_signature(pubkey, &signing_data, dilithium_sig)
                .map_err(|e| RollupError::VerificationFailed(format!("Dilithium verify: {}", e)))?;

            let status = if commitment.operator_signature.ed25519_sig.is_some() {
                PQSignatureStatus::Hybrid
            } else {
                PQSignatureStatus::DilithiumOnly
            };

            return Ok((verified, status));
        }

        if self.transition_mode {
            if let Some(_ed25519_sig) = &commitment.operator_signature.ed25519_sig {
                return Ok((true, PQSignatureStatus::Ed25519Only));
            }
        }

        Ok((false, PQSignatureStatus::Missing))
    }

    fn create_commitment_signing_data(
        &self,
        commitment: &RollupCommitment,
    ) -> RollupResult<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(b"ego/rollup/commitment/v1");
        data.extend_from_slice(commitment.operator.as_bytes());
        data.extend_from_slice(commitment.rollup_id.as_bytes());
        data.extend_from_slice(commitment.state_root.as_bytes());
        data.extend_from_slice(commitment.previous_state_root.as_bytes());
        data.extend_from_slice(commitment.tx_root.as_bytes());
        data.extend_from_slice(commitment.da_root.as_bytes());
        data.extend_from_slice(commitment.proofs_root.as_bytes());
        data.extend_from_slice(&commitment.tx_count.to_le_bytes());
        data.extend_from_slice(&commitment.block_range.0.to_le_bytes());
        data.extend_from_slice(&commitment.block_range.1.to_le_bytes());
        data.extend_from_slice(&commitment.l1_block_number.to_le_bytes());
        data.extend_from_slice(&commitment.timestamp.as_millis().to_le_bytes());
        data.extend_from_slice(&commitment.gas_used.to_le_bytes());
        data.extend_from_slice(&commitment.version.to_le_bytes());
        data.extend_from_slice(&commitment.protocol_version.to_le_bytes());
        data.extend_from_slice(&commitment.chain_id.to_le_bytes());
        data.extend_from_slice(&commitment.network_id.to_le_bytes());
        data.extend_from_slice(&commitment.epoch.0.to_le_bytes());

        Ok(ego_core::crypto::blake2s_hash(&data))
    }

    async fn verify_transactions(
        &self,
        commitment: &RollupCommitment,
        transactions: &[RollupTransaction],
    ) -> RollupResult<()> {
        let mut seen_hashes = HashSet::new();
        let mut nonce_map: HashMap<Address, u64> = HashMap::new();

        for tx in transactions {
            if !seen_hashes.insert(tx.hash()) {
                return Err(RollupError::InvalidBatch(
                    "Duplicate transaction".to_string(),
                ));
            }

            if !tx.inner.verify_signature()? {
                return Err(RollupError::InvalidBatch(format!(
                    "Invalid transaction signature: {}",
                    tx.hash()
                )));
            }

            if self.require_dilithium && tx.inner.signature.dilithium_sig.is_none() {
                return Err(RollupError::InvalidBatch(
                    "Dilithium signature required for transaction".to_string(),
                ));
            }

            if tx.inner.chain_id != commitment.chain_id {
                return Err(RollupError::InvalidBatch(format!(
                    "Transaction chain_id mismatch: expected {}, got {}",
                    commitment.chain_id, tx.inner.chain_id
                )));
            }

            let sender = tx.inner.from;
            let expected_nonce = nonce_map.get(&sender).unwrap_or(&0) + 1;
            if tx.rollup_nonce != expected_nonce {
                return Err(RollupError::InvalidBatch(format!(
                    "Invalid nonce for {}: expected {}, got {}",
                    sender, expected_nonce, tx.rollup_nonce
                )));
            }
            nonce_map.insert(sender, tx.rollup_nonce);

            if tx.inner.estimate_resource_units() > 10_000_000 {
                return Err(RollupError::InvalidBatch(format!(
                    "Resource unit overflow: {}",
                    tx.hash()
                )));
            }
        }

        Ok(())
    }

    async fn verify_data_availability(&self, commitment: &RollupCommitment) -> RollupResult<f64> {
        if commitment.da_chunks.is_empty() {
            return Ok(0.0);
        }

        let sample_size = (commitment.da_chunks.len() / 4).max(1).min(16);

        let mut available_count = 0;
        let da_manager = self.da_manager.read().await;

        for &chunk_id in commitment.da_chunks.iter().take(sample_size) {
            if let Some(_chunk) = da_manager.get_chunk(commitment.commitment_hash, chunk_id) {
                available_count += 1;
            }
        }

        Ok(available_count as f64 / sample_size as f64)
    }

    fn verify_timestamp(&self, commitment: &RollupCommitment) -> Result<(), VerificationIssue> {
        let now = Timestamp::now();
        let commitment_time = commitment.timestamp;

        if commitment_time.as_millis() > now.as_millis() + 300_000 {
            return Err(VerificationIssue {
                issue_type: IssueType::TimestampError,
                severity: IssueSeverity::High,
                description: "Commitment timestamp too far in future".to_string(),
                evidence: None,
                commitment_hash: commitment.commitment_hash,
                operator: commitment.operator,
                timestamp: Timestamp::now(),
                affected_transactions: vec![],
                remediation_suggestion: Some("Sync system clock".to_string()),
            });
        }

        if now.as_millis() > commitment_time.as_millis() + 86_400_000 {
            return Err(VerificationIssue {
                issue_type: IssueType::TimestampError,
                severity: IssueSeverity::Medium,
                description: "Commitment timestamp too old".to_string(),
                evidence: None,
                commitment_hash: commitment.commitment_hash,
                operator: commitment.operator,
                timestamp: Timestamp::now(),
                affected_transactions: vec![],
                remediation_suggestion: Some("Submit fresh commitment".to_string()),
            });
        }

        Ok(())
    }

    async fn verify_execution(
        &self,
        commitment: &RollupCommitment,
        transactions: &[RollupTransaction],
    ) -> RollupResult<Option<Vec<VerificationIssue>>> {
        let mut issues = Vec::new();

        let total_gas: u64 = transactions
            .iter()
            .map(|tx| tx.inner.estimate_resource_units())
            .sum();

        if total_gas != commitment.gas_used {
            issues.push(VerificationIssue {
                issue_type: IssueType::ExecutionError,
                severity: IssueSeverity::Medium,
                description: format!(
                    "Gas mismatch: computed {}, commitment {}",
                    total_gas, commitment.gas_used
                ),
                evidence: None,
                commitment_hash: commitment.commitment_hash,
                operator: commitment.operator,
                timestamp: Timestamp::now(),
                affected_transactions: vec![],
                remediation_suggestion: Some("Recompute transaction gas costs".to_string()),
            });
        }

        if issues.is_empty() {
            Ok(None)
        } else {
            Ok(Some(issues))
        }
    }

    fn compute_transaction_root(&self, transactions: &[RollupTransaction]) -> Hash {
        if transactions.is_empty() {
            return Hash::ZERO;
        }

        let tx_hashes: Vec<Vec<u8>> = transactions.iter().map(|tx| tx.hash().to_vec()).collect();

        let merkle_tree = ego_core::crypto::MerkleTree::build(tx_hashes);
        merkle_tree.root_hash().unwrap_or(Hash::ZERO)
    }

    async fn verify_deploy_policy(
        &self,
        _commitment: &RollupCommitment,
        transactions: &[RollupTransaction],
    ) -> RollupResult<(Vec<DeployPolicyCheckResult>, Vec<VerificationIssue>)> {
        let mut checks = Vec::new();
        let mut issues = Vec::new();

        for tx in transactions {
            if let ego_core::TransactionPayload::DeployContract { .. } = &tx.inner.payload {
                let tx_str = format!("{:?}", tx.inner.payload);

                let ai_phrases = vec![
                    "do you want me to add more",
                    "let me know if you need",
                    "as an ai model",
                ];

                let mut flagged = false;
                for phrase in &ai_phrases {
                    if tx_str.to_lowercase().contains(phrase) {
                        flagged = true;
                        break;
                    }
                }

                if flagged {
                    checks.push(DeployPolicyCheckResult {
                        deployer: tx.inner.from,
                        deploy_id: tx.hash(),
                        check_type: DeployCheckType::AIPatternDetection,
                        passed: false,
                        quota_used: 0,
                        credits_consumed: 0,
                        bond_locked: None,
                        reason: Some("AI filler pattern detected".to_string()),
                    });

                    issues.push(VerificationIssue {
                        issue_type: IssueType::AIPatternDetected,
                        severity: IssueSeverity::High,
                        description: "AI-generated filler content detected in deployment"
                            .to_string(),
                        evidence: None,
                        commitment_hash: Hash::ZERO,
                        operator: tx.inner.from,
                        timestamp: Timestamp::now(),
                        affected_transactions: vec![tx.hash()],
                        remediation_suggestion: Some(
                            "Remove AI filler and submit human-verified code".to_string(),
                        ),
                    });
                }
            }
        }

        Ok((checks, issues))
    }

    async fn verify_ai_patterns(
        &self,
        transactions: &[RollupTransaction],
    ) -> RollupResult<(Vec<AIPatternCheckResult>, Vec<VerificationIssue>)> {
        let mut checks = Vec::new();
        let mut issues = Vec::new();

        for tx in transactions {
            if let ego_core::TransactionPayload::DeployContract {
                contract_code_hash,
                constructor_args,
                ..
            } = &tx.inner.payload
            {
                let mut patterns_detected = Vec::new();
                let code_str = String::from_utf8_lossy(constructor_args);

                let ai_patterns = vec![
                    ("chatgpt", 0.9),
                    ("claude", 0.9),
                    ("generated by ai", 0.95),
                    ("ai-generated", 0.95),
                    ("as an ai", 0.98),
                    ("do you want me to add more", 0.95),
                    ("let me know if you need", 0.9),
                ];

                let mut max_confidence: f64 = 0.0;
                for (pattern, confidence) in &ai_patterns {
                    if code_str.to_lowercase().contains(pattern) {
                        patterns_detected.push(pattern.to_string());
                        max_confidence = max_confidence.max(*confidence);
                    }
                }

                if !patterns_detected.is_empty() {
                    checks.push(AIPatternCheckResult {
                        deployer: tx.inner.from,
                        deploy_id: tx.hash(),
                        patterns_detected: patterns_detected.clone(),
                        flagged: true,
                        human_review_required: max_confidence > 0.8,
                        confidence_score: max_confidence,
                    });

                    issues.push(VerificationIssue {
                        issue_type: IssueType::AIPatternDetected,
                        severity: if max_confidence > 0.9 {
                            IssueSeverity::Critical
                        } else {
                            IssueSeverity::High
                        },
                        description: format!("AI patterns detected: {:?}", patterns_detected),
                        evidence: Some(contract_code_hash.to_vec()),
                        commitment_hash: Hash::ZERO,
                        operator: tx.inner.from,
                        timestamp: Timestamp::now(),
                        affected_transactions: vec![tx.hash()],
                        remediation_suggestion: Some("Submit human-verified code".to_string()),
                    });
                }
            }
        }

        Ok((checks, issues))
    }

    async fn verify_human_verification(
        &self,
        transactions: &[RollupTransaction],
    ) -> RollupResult<(HumanVerificationStatus, Vec<VerificationIssue>)> {
        let mut issues = Vec::new();
        let mut status = HumanVerificationStatus::NotRequired;

        for tx in transactions {
            if let ego_core::TransactionPayload::DeployContract { .. } = &tx.inner.payload {
                if self.human_verification_required {
                    status = HumanVerificationStatus::Required;
                    issues.push(VerificationIssue {
                        issue_type: IssueType::HumanVerificationFailed,
                        severity: IssueSeverity::High,
                        description: "Human verification signature missing".to_string(),
                        evidence: None,
                        commitment_hash: Hash::ZERO,
                        operator: tx.inner.from,
                        timestamp: Timestamp::now(),
                        affected_transactions: vec![tx.hash()],
                        remediation_suggestion: Some(
                            "Add Dilithium human verification signature".to_string(),
                        ),
                    });
                }
            }
        }

        Ok((status, issues))
    }

    async fn verify_drs_scores(
        &self,
        commitment: &RollupCommitment,
    ) -> RollupResult<(bool, Vec<VerificationIssue>)> {
        let mut issues = Vec::new();

        if let Some(operator_trust) = self.trusted_operators.get(&commitment.operator) {
            if operator_trust.drs_score < 0.0 || operator_trust.drs_score > 1.5 {
                issues.push(VerificationIssue {
                    issue_type: IssueType::DRSScoreInvalid,
                    severity: IssueSeverity::Medium,
                    description: format!("DRS score out of range: {}", operator_trust.drs_score),
                    evidence: None,
                    commitment_hash: commitment.commitment_hash,
                    operator: commitment.operator,
                    timestamp: Timestamp::now(),
                    affected_transactions: vec![],
                    remediation_suggestion: Some("Recompute DRS score".to_string()),
                });
            }

            if operator_trust.drs_multiplier < 0.7 || operator_trust.drs_multiplier > 1.3 {
                issues.push(VerificationIssue {
                    issue_type: IssueType::DRSScoreInvalid,
                    severity: IssueSeverity::Medium,
                    description: format!(
                        "DRS multiplier out of range: {}",
                        operator_trust.drs_multiplier
                    ),
                    evidence: None,
                    commitment_hash: commitment.commitment_hash,
                    operator: commitment.operator,
                    timestamp: Timestamp::now(),
                    affected_transactions: vec![],
                    remediation_suggestion: Some("Apply correct DRS multiplier bounds".to_string()),
                });
            }
        }

        Ok((issues.is_empty(), issues))
    }

    async fn verify_density_penalties(
        &self,
        _commitment: &RollupCommitment,
    ) -> RollupResult<(bool, Vec<VerificationIssue>)> {
        let issues = Vec::new();
        Ok((false, issues))
    }

    async fn verify_credits(
        &self,
        _commitment: &RollupCommitment,
        _transactions: &[RollupTransaction],
    ) -> RollupResult<(bool, bool, Vec<VerificationIssue>)> {
        let issues = Vec::new();
        Ok((true, true, issues))
    }

    async fn verify_post_proofs(
        &self,
        commitment: &RollupCommitment,
    ) -> RollupResult<(u32, Vec<VerificationIssue>)> {
        let mut issues = Vec::new();
        let verified_count = commitment.post_proofs_included;

        if self.post_verification_enabled && verified_count == 0 {
            issues.push(VerificationIssue {
                issue_type: IssueType::PostProofInvalid,
                severity: IssueSeverity::Medium,
                description: "No PoSt proofs included".to_string(),
                evidence: None,
                commitment_hash: commitment.commitment_hash,
                operator: commitment.operator,
                timestamp: Timestamp::now(),
                affected_transactions: vec![],
                remediation_suggestion: Some("Include PoSt proof submissions".to_string()),
            });
        }

        Ok((verified_count, issues))
    }

    async fn verify_poc_proofs(
        &self,
        commitment: &RollupCommitment,
    ) -> RollupResult<(u32, Vec<VerificationIssue>)> {
        let mut issues = Vec::new();
        let verified_count = commitment.poc_proofs_included;

        if self.poc_verification_enabled && verified_count == 0 {
            issues.push(VerificationIssue {
                issue_type: IssueType::PoCProofInvalid,
                severity: IssueSeverity::Low,
                description: "No PoC proofs included".to_string(),
                evidence: None,
                commitment_hash: commitment.commitment_hash,
                operator: commitment.operator,
                timestamp: Timestamp::now(),
                affected_transactions: vec![],
                remediation_suggestion: Some("Include PoC witness reports".to_string()),
            });
        }

        Ok((verified_count, issues))
    }

    async fn verify_cellular_safe(
        &self,
        commitment: &RollupCommitment,
    ) -> RollupResult<(bool, Vec<VerificationIssue>)> {
        let mut issues = Vec::new();
        let compliant = commitment.cellular_optimized;

        if !compliant {
            issues.push(VerificationIssue {
                issue_type: IssueType::CellularSafeViolation,
                severity: IssueSeverity::Low,
                description: "Commitment not optimized for cellular networks".to_string(),
                evidence: None,
                commitment_hash: commitment.commitment_hash,
                operator: commitment.operator,
                timestamp: Timestamp::now(),
                affected_transactions: vec![],
                remediation_suggestion: Some("Enable cellular-safe mode".to_string()),
            });
        }

        Ok((compliant, issues))
    }

    async fn verify_cross_shard_receipts(
        &self,
        commitment: &RollupCommitment,
    ) -> RollupResult<(u32, Vec<VerificationIssue>)> {
        let issues = Vec::new();
        let verified_count = commitment.cross_shard_receipts_count;
        Ok((verified_count, issues))
    }

    fn update_operator_success(&mut self, operator: &Address, gas_used: u64, latency_ms: u64) {
        let trust = self
            .trusted_operators
            .entry(*operator)
            .or_insert_with(|| OperatorTrust::new(*operator));
        trust.update_successful_commit(gas_used, latency_ms);
    }

    fn update_operator_failure(&mut self, operator: &Address) {
        if let Some(trust) = self.trusted_operators.get_mut(operator) {
            trust.update_challenged_commit();
        }
    }

    fn update_epoch_stats(&mut self, epoch: u64, result: &VerificationResult) {
        let stats = self
            .epoch_verification_stats
            .entry(epoch)
            .or_insert_with(|| EpochVerificationStats {
                epoch,
                ..Default::default()
            });

        stats.total_commitments += 1;
        if result.is_valid {
            stats.valid_commitments += 1;
        } else {
            stats.invalid_commitments += 1;
        }

        stats.post_proofs_verified += result.post_proofs_verified as u64;
        stats.poc_proofs_verified += result.poc_proofs_verified as u64;
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

    pub fn register_operator_pubkey(&mut self, operator: Address, pubkey: PublicKey) {
        self.operator_pubkeys.insert(operator, pubkey);
    }

    pub fn update_operator_trust(&mut self, operator: Address, trust: OperatorTrust) {
        self.trusted_operators.insert(operator, trust);
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
            stats.total_verification_latency_ms += result.verification_latency_ms;

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
            stats.average_verification_latency_ms =
                stats.total_verification_latency_ms / stats.total_verifications;
        }

        stats.trusted_operators = self.trusted_operators.len() as u64;
        stats.cache_size = self.verification_cache.len() as u64;
        stats.verified_commitments = self.verified_commitments.len() as u64;
        stats.failed_commitments = self.failed_commitments.len() as u64;

        stats
    }
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
            reputation_multiplier: 1.0,
            drs_score: 1.0,
            drs_multiplier: 1.0,
            consecutive_failures: 0,
            total_gas_processed: 0,
            avg_batch_latency_ms: 0,
            post_proofs_verified: 0,
            post_proofs_failed: 0,
            poc_proofs_verified: 0,
            poc_proofs_failed: 0,
            quota_band: ego_core::drs::QuotaBand::Mid,
            storage_credits_used: 0,
            deploy_credits_used: 0,
            ai_flagged_deploys: 0,
            human_verified_deploys: 0,
            cellular_safe_compliance: 1.0,
            density_violations: 0,
            last_drs_update: 0,
        }
    }

    pub fn update_successful_commit(&mut self, gas_used: u64, latency_ms: u64) {
        self.successful_commits += 1;
        self.consecutive_failures = 0;
        self.last_activity = Timestamp::now();
        self.total_gas_processed += gas_used;

        if self.avg_batch_latency_ms == 0 {
            self.avg_batch_latency_ms = latency_ms;
        } else {
            self.avg_batch_latency_ms = (self.avg_batch_latency_ms + latency_ms) / 2;
        }

        self.recalculate_trust_score();
    }

    pub fn update_challenged_commit(&mut self) {
        self.challenged_commits += 1;
        self.consecutive_failures += 1;
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
        let consecutive_penalty = (self.consecutive_failures as f64 * 0.05).min(0.3);

        let base_score = success_rate - challenge_penalty - slash_penalty - consecutive_penalty;
        self.trust_score = (base_score * self.drs_score * self.drs_multiplier)
            .max(0.0)
            .min(1.0);

        self.reputation_multiplier = if self.trust_score > 0.9 {
            1.2
        } else if self.trust_score > 0.7 {
            1.0
        } else if self.trust_score > 0.5 {
            0.8
        } else {
            0.5
        };
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
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
    pub verified_commitments: u64,
    pub failed_commitments: u64,
    pub average_verification_latency_ms: u64,
    pub total_verification_latency_ms: u64,
}
