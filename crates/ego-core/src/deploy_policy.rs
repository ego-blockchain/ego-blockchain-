use crate::{Address, Balance, EgoError, EgoResult, Hash, Timestamp};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct DeployPolicyManager {
    pub current_epoch: u64,
    pub config: DeployPolicyConfig,
    pub staker_quotas: Arc<DashMap<Address, StakerQuota>>,
    pub deploy_history: Arc<DashMap<Hash, DeployRecord>>,
    pub epoch_stats: Arc<DashMap<u64, EpochDeployStats>>,
    pub blacklisted_contracts: Arc<DashMap<Hash, BlacklistEntry>>,
    pub code_hash_index: Arc<DashMap<Hash, Vec<Hash>>>,
    pub deployer_index: Arc<DashMap<Address, VecDeque<Hash>>>,
    pub anti_spam_tracker: Arc<DashMap<Address, AntiSpamMetrics>>,
    pub pob_burn_tracker: Arc<DashMap<Hash, PoBBurnRecord>>,
    pub failed_deploys_tracker: Arc<DashMap<(Address, u64), u32>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployPolicyConfig {
    pub free_deploys_per_epoch: u32,
    pub min_stake_for_quota: Balance,

    pub credits_per_kb: u64,
    pub credits_per_ru: u64,
    pub max_deploy_size_kb: u32,
    pub max_ru_per_deploy: u64,

    pub deploy_bond_amount: Balance,
    pub bond_lock_duration_blocks: u64,
    pub bond_slash_threshold: u32,

    pub max_deploys_per_epoch: u32,
    pub max_deploys_per_user_per_epoch: u32,
    pub max_total_size_per_epoch_gb: u32,

    pub enable_dedup: bool,
    pub dedup_lookback_epochs: u64,

    pub pob_floor_enabled: bool,
    pub pob_floor_per_kb: u64,
    pub pob_floor_per_ru: u64,

    pub anti_spam_enabled: bool,
    pub max_deploys_per_hour: u32,
    pub max_deploys_per_day: u32,
    pub min_deploy_interval_seconds: u64,

    pub human_verification_required: bool,
    pub ai_pattern_detection_enabled: bool,

    pub emergency_mode: bool,
    pub whitelist_only_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakerQuota {
    pub staker: Address,
    pub stake_amount: Balance,
    pub free_deploys_remaining: u32,
    pub deploys_used_this_epoch: u32,
    pub epoch: u64,
    pub last_updated: Timestamp,
    pub quota_band: QuotaBand,
    pub drs_multiplier: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuotaBand {
    High,
    Mid,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployRecord {
    pub deploy_id: Hash,
    pub deployer: Address,
    pub deploy_type: DeployType,
    pub code_hash: Hash,
    pub size_kb: u32,
    pub ru_consumed: u64,
    pub credits_used: u64,
    pub free_deploy_used: bool,
    pub bond_amount: Option<Balance>,
    pub bond_unlock_block: Option<u64>,
    pub status: DeployStatus,
    pub epoch: u64,
    pub timestamp: Timestamp,
    pub gas_used: u64,
    pub success: bool,
    pub error: Option<String>,
    pub pob_burn_amount: u64,
    pub human_verified: bool,
    pub ai_pattern_detected: bool,
    pub verification_signature: Option<Vec<u8>>,
    pub shard_id: u32,
    pub contract_address: Option<Address>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum DeployType {
    SmartContract {
        code_size_kb: u32,
        estimated_ru: u64,
    },
    StorageDeal {
        data_size_kb: u32,
        duration_blocks: u64,
    },
    RollupOperator {
        initial_state_kb: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum DeployStatus {
    Pending,
    Accepted,
    Rejected { reason: String },
    Completed,
    Failed { error: String },
    BondSlashed,
    HumanVerificationRequired,
    AIPatternFlagged,
    Blacklisted,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EpochDeployStats {
    pub epoch: u64,
    pub total_deploys: u32,
    pub successful_deploys: u32,
    pub failed_deploys: u32,
    pub total_size_kb: u64,
    pub total_ru_consumed: u64,
    pub free_deploys_used: u32,
    pub credits_consumed: u64,
    pub bonds_collected: Balance,
    pub bonds_slashed: Balance,
    pub unique_deployers: u32,
    pub duplicate_contracts: u32,
    pub pob_burns_total: u64,
    pub human_verified_deploys: u32,
    pub ai_flagged_deploys: u32,
    pub rejected_spam: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployRequest {
    pub deployer: Address,
    pub deploy_type: DeployType,
    pub code: Vec<u8>,
    pub metadata: HashMap<String, String>,
    pub use_free_quota: bool,
    pub preferred_shard: Option<u32>,
    pub human_verification_signature: Option<Vec<u8>>,
    pub dilithium_verification_pk: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DeployRequested {
    pub deployer: Address,
    pub deploy_id: Hash,
    pub deploy_type: DeployType,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DeployAccepted {
    pub deploy_id: Hash,
    pub deployer: Address,
    pub credits_used: u64,
    pub free_quota_used: bool,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DeployRejected {
    pub deploy_id: Hash,
    pub deployer: Address,
    pub reason: String,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlacklistEntry {
    pub code_hash: Hash,
    pub reason: String,
    pub blacklisted_at: Timestamp,
    pub blacklisted_by: Address,
    pub evidence_hash: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiSpamMetrics {
    pub deployer: Address,
    pub deploys_last_hour: VecDeque<Timestamp>,
    pub deploys_last_day: VecDeque<Timestamp>,
    pub last_deploy_timestamp: Timestamp,
    pub spam_score: u32,
    pub total_rejected: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoBBurnRecord {
    pub deploy_id: Hash,
    pub deployer: Address,
    pub burn_amount: u64,
    pub credits_minted: u64,
    pub timestamp: Timestamp,
    pub burn_tx_hash: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIPatternDetection {
    pub suspicious_phrases: Vec<String>,
    pub detection_enabled: bool,
    pub auto_reject: bool,
}

impl Default for DeployPolicyConfig {
    fn default() -> Self {
        Self {
            free_deploys_per_epoch: 5,
            min_stake_for_quota: Balance::from_egoc(1000),
            credits_per_kb: 100,
            credits_per_ru: 10,
            max_deploy_size_kb: 1024,
            max_ru_per_deploy: 10000,
            deploy_bond_amount: Balance::new(1000000),
            bond_lock_duration_blocks: 1000,
            bond_slash_threshold: 3,
            max_deploys_per_epoch: 10000,
            max_deploys_per_user_per_epoch: 50,
            max_total_size_per_epoch_gb: 100,
            enable_dedup: true,
            dedup_lookback_epochs: 10,
            pob_floor_enabled: false,
            pob_floor_per_kb: 50,
            pob_floor_per_ru: 5,
            anti_spam_enabled: true,
            max_deploys_per_hour: 10,
            max_deploys_per_day: 50,
            min_deploy_interval_seconds: 60,
            human_verification_required: false,
            ai_pattern_detection_enabled: true,
            emergency_mode: false,
            whitelist_only_mode: false,
        }
    }
}

impl DeployPolicyManager {
    pub fn new(config: DeployPolicyConfig) -> Self {
        Self {
            current_epoch: 0,
            config,
            staker_quotas: Arc::new(DashMap::new()),
            deploy_history: Arc::new(DashMap::new()),
            epoch_stats: Arc::new(DashMap::new()),
            blacklisted_contracts: Arc::new(DashMap::new()),
            code_hash_index: Arc::new(DashMap::new()),
            deployer_index: Arc::new(DashMap::new()),
            anti_spam_tracker: Arc::new(DashMap::new()),
            pob_burn_tracker: Arc::new(DashMap::new()),
            failed_deploys_tracker: Arc::new(DashMap::new()),
        }
    }

    pub fn evaluate_deploy_request(
        &mut self,
        request: &DeployRequest,
        staker_stake: Option<Balance>,
        current_block: u64,
    ) -> EgoResult<DeployDecision> {
        if self.config.emergency_mode {
            let deploy_id = self.generate_deploy_id(request);
            let decision = DeployDecision::Reject {
                deploy_id,
                reason: "Emergency mode: all deployments suspended".to_string(),
            };
            self.record_deploy_request(request, &decision, current_block, staker_stake);
            return Ok(decision);
        }

        let deploy_id = self.generate_deploy_id(request);

        if self.config.ai_pattern_detection_enabled {
            if let Err(e) = self.detect_ai_patterns(request) {
                let decision = DeployDecision::Reject {
                    deploy_id,
                    reason: format!("AI pattern detected: {}", e),
                };
                self.record_deploy_request(request, &decision, current_block, staker_stake);
                return Ok(decision);
            }
        }

        if self.config.human_verification_required {
            if let Err(e) = self.verify_human_signature(request) {
                let decision = DeployDecision::Reject {
                    deploy_id,
                    reason: format!("Human verification failed: {}", e),
                };
                self.record_deploy_request(request, &decision, current_block, staker_stake);
                return Ok(decision);
            }
        }

        if self.config.anti_spam_enabled {
            if let Err(e) = self.check_anti_spam(&request.deployer) {
                let decision = DeployDecision::Reject {
                    deploy_id,
                    reason: format!("Anti-spam check failed: {}", e),
                };
                self.record_deploy_request(request, &decision, current_block, staker_stake);
                self.update_anti_spam_metrics(&request.deployer);
                return Ok(decision);
            }
        }

        if let Err(e) = self.validate_deploy_limits(&request.deploy_type) {
            let decision = DeployDecision::Reject {
                deploy_id,
                reason: format!("Deploy limits exceeded: {}", e),
            };
            self.record_deploy_request(request, &decision, current_block, staker_stake);
            return Ok(decision);
        }

        if let Err(e) = self.check_hard_caps(&request.deployer, &request.deploy_type) {
            let decision = DeployDecision::Reject {
                deploy_id,
                reason: format!("Hard caps exceeded: {}", e),
            };
            self.record_deploy_request(request, &decision, current_block, staker_stake);
            return Ok(decision);
        }

        let code_hash = crate::crypto::hash_data(&request.code);

        if self.config.enable_dedup {
            if self.blacklisted_contracts.contains_key(&code_hash) {
                let decision = DeployDecision::Reject {
                    deploy_id,
                    reason: "Contract code is blacklisted".to_string(),
                };
                self.record_deploy_request(request, &decision, current_block, staker_stake);
                self.update_anti_spam_metrics(&request.deployer);
                return Ok(decision);
            }

            if let Err(e) = self.check_duplicate_contract(&code_hash) {
                let decision = DeployDecision::Reject {
                    deploy_id,
                    reason: format!("Duplicate contract: {}", e),
                };
                self.record_deploy_request(request, &decision, current_block, staker_stake);
                self.update_anti_spam_metrics(&request.deployer);
                return Ok(decision);
            }
        }

        let (size_kb, estimated_ru) = self.calculate_resources(&request.deploy_type);
        let credits_needed = self.calculate_credits_needed(size_kb, estimated_ru);

        let pob_floor = if self.config.pob_floor_enabled {
            self.calculate_pob_floor(size_kb, estimated_ru)
        } else {
            0
        };

        let can_use_free_quota =
            request.use_free_quota && self.can_use_free_quota(&request.deployer, staker_stake)?;

        let decision = if can_use_free_quota {
            DeployDecision::AcceptWithFreeQuota { deploy_id }
        } else {
            let bond_required = if credits_needed > 0 || pob_floor > 0 {
                Some(self.config.deploy_bond_amount)
            } else {
                None
            };

            DeployDecision::AcceptWithCredits {
                deploy_id,
                credits_required: credits_needed,
                bond_required,
                pob_floor,
            }
        };

        self.record_deploy_request(request, &decision, current_block, staker_stake);

        if self.config.anti_spam_enabled {
            self.update_anti_spam_metrics(&request.deployer);
        }

        Ok(decision)
    }

    fn detect_ai_patterns(&self, request: &DeployRequest) -> EgoResult<()> {
        let code_str = String::from_utf8_lossy(&request.code);

        let ai_filler_phrases = vec![
            "do you want me to add more",
            "let me know if you need",
            "as an ai model",
            "i can help you with",
            "would you like me to",
            "is there anything else",
            "feel free to ask",
            "i'm here to assist",
            "chatgpt",
            "claude",
            "generated by ai",
            "ai-generated",
        ];

        for phrase in &ai_filler_phrases {
            if code_str.to_lowercase().contains(phrase) {
                return Err(EgoError::InvalidTransaction(format!(
                    "AI filler phrase detected: '{}'",
                    phrase
                )));
            }
        }

        if let Some(desc) = request.metadata.get("description") {
            for phrase in &ai_filler_phrases {
                if desc.to_lowercase().contains(phrase) {
                    return Err(EgoError::InvalidTransaction(format!(
                        "AI filler phrase detected in description: '{}'",
                        phrase
                    )));
                }
            }
        }

        Ok(())
    }

    fn verify_human_signature(&self, request: &DeployRequest) -> EgoResult<()> {
        if request.human_verification_signature.is_none()
            || request.dilithium_verification_pk.is_none()
        {
            return Err(EgoError::InvalidTransaction(
                "Missing human verification signature or public key".to_string(),
            ));
        }

        let signature_bytes = request.human_verification_signature.as_ref().unwrap();
        let pk_bytes = request.dilithium_verification_pk.as_ref().unwrap();

        let verification_data = self.create_verification_data(request);

        let public_key = crate::PublicKey::dilithium2(pk_bytes.clone());
        let signature = crate::Signature::dilithium2(signature_bytes.clone());

        let verified =
            crate::crypto::verify_signature(&public_key, &verification_data, &signature)?;

        if !verified {
            return Err(EgoError::InvalidTransaction(
                "Human verification signature invalid".to_string(),
            ));
        }

        Ok(())
    }

    fn create_verification_data(&self, request: &DeployRequest) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"ego/human-verify/v1");
        data.extend_from_slice(request.deployer.as_bytes());
        data.extend_from_slice(&crate::crypto::hash_data(&request.code).to_vec());
        data.extend_from_slice(&self.current_epoch.to_le_bytes());
        crate::crypto::blake2s_hash(&data)
    }

    fn check_anti_spam(&self, deployer: &Address) -> EgoResult<()> {
        let now = Timestamp::now();

        if let Some(metrics) = self.anti_spam_tracker.get(deployer) {
            if let Some(last_deploy) = metrics.deploys_last_hour.back() {
                let elapsed_seconds =
                    now.as_millis().saturating_sub(last_deploy.as_millis()) / 1000;

                if elapsed_seconds < self.config.min_deploy_interval_seconds {
                    return Err(EgoError::InvalidTransaction(format!(
                        "Deploy interval too short: wait {} more seconds",
                        self.config.min_deploy_interval_seconds - elapsed_seconds
                    )));
                }
            }

            let hour_ago = Timestamp::from_millis(now.as_millis().saturating_sub(3600 * 1000));
            let deploys_last_hour = metrics
                .deploys_last_hour
                .iter()
                .filter(|t| t.as_millis() >= hour_ago.as_millis())
                .count();

            if deploys_last_hour >= self.config.max_deploys_per_hour as usize {
                return Err(EgoError::InvalidTransaction(format!(
                    "Hourly deploy limit exceeded: {} deploys in last hour",
                    deploys_last_hour
                )));
            }

            let day_ago = Timestamp::from_millis(now.as_millis().saturating_sub(86400 * 1000));
            let deploys_last_day = metrics
                .deploys_last_day
                .iter()
                .filter(|t| t.as_millis() >= day_ago.as_millis())
                .count();

            if deploys_last_day >= self.config.max_deploys_per_day as usize {
                return Err(EgoError::InvalidTransaction(format!(
                    "Daily deploy limit exceeded: {} deploys in last day",
                    deploys_last_day
                )));
            }

            if metrics.spam_score > 100 {
                return Err(EgoError::InvalidTransaction(
                    "Spam score too high, account temporarily restricted".to_string(),
                ));
            }
        }

        Ok(())
    }

    fn update_anti_spam_metrics(&self, deployer: &Address) {
        let now = Timestamp::now();

        let mut metrics =
            self.anti_spam_tracker
                .entry(*deployer)
                .or_insert_with(|| AntiSpamMetrics {
                    deployer: *deployer,
                    deploys_last_hour: VecDeque::new(),
                    deploys_last_day: VecDeque::new(),
                    last_deploy_timestamp: now,
                    spam_score: 0,
                    total_rejected: 0,
                });

        metrics.deploys_last_hour.push_back(now);
        metrics.deploys_last_day.push_back(now);
        metrics.last_deploy_timestamp = now;

        let hour_ago = Timestamp::from_millis(now.as_millis().saturating_sub(3600 * 1000));
        while let Some(front) = metrics.deploys_last_hour.front() {
            if front.as_millis() < hour_ago.as_millis() {
                metrics.deploys_last_hour.pop_front();
            } else {
                break;
            }
        }

        let day_ago = Timestamp::from_millis(now.as_millis().saturating_sub(86400 * 1000));
        while let Some(front) = metrics.deploys_last_day.front() {
            if front.as_millis() < day_ago.as_millis() {
                metrics.deploys_last_day.pop_front();
            } else {
                break;
            }
        }

        if metrics.deploys_last_hour.len() > 5 {
            metrics.spam_score = metrics.spam_score.saturating_add(10);
        }

        if metrics.spam_score > 0 {
            metrics.spam_score = metrics.spam_score.saturating_sub(1);
        }
    }

    fn check_hard_caps(&self, deployer: &Address, deploy_type: &DeployType) -> EgoResult<()> {
        let current_stats = self
            .epoch_stats
            .get(&self.current_epoch)
            .map(|entry| entry.clone())
            .unwrap_or_default();

        if current_stats.total_deploys >= self.config.max_deploys_per_epoch {
            return Err(EgoError::ResourceLimitExceeded {
                resource: "Global deploys per epoch".to_string(),
            });
        }

        let mut user_deploys = 0u32;
        for entry in self.deploy_history.iter() {
            if entry.deployer == *deployer && entry.epoch == self.current_epoch {
                user_deploys += 1;
            }
        }

        if user_deploys >= self.config.max_deploys_per_user_per_epoch {
            return Err(EgoError::ResourceLimitExceeded {
                resource: format!("Deploys per user per epoch ({})", user_deploys),
            });
        }

        let (size_kb, _) = self.calculate_resources(deploy_type);
        let total_size_gb = current_stats.total_size_kb / (1024 * 1024);

        if total_size_gb + (size_kb as u64) / (1024 * 1024)
            > self.config.max_total_size_per_epoch_gb as u64
        {
            return Err(EgoError::ResourceLimitExceeded {
                resource: "Total size per epoch".to_string(),
            });
        }

        Ok(())
    }

    fn validate_deploy_limits(&self, deploy_type: &DeployType) -> EgoResult<()> {
        let (size_kb, estimated_ru) = self.calculate_resources(deploy_type);

        if size_kb > self.config.max_deploy_size_kb {
            return Err(EgoError::InvalidTransaction(format!(
                "Deploy size {} KB exceeds limit {} KB",
                size_kb, self.config.max_deploy_size_kb
            )));
        }

        if estimated_ru > self.config.max_ru_per_deploy {
            return Err(EgoError::InvalidTransaction(format!(
                "Deploy RU {} exceeds limit {}",
                estimated_ru, self.config.max_ru_per_deploy
            )));
        }

        Ok(())
    }

    fn check_duplicate_contract(&self, code_hash: &Hash) -> EgoResult<()> {
        let cutoff_epoch = self
            .current_epoch
            .saturating_sub(self.config.dedup_lookback_epochs);

        if let Some(deploy_ids) = self.code_hash_index.get(code_hash) {
            for deploy_id in deploy_ids.iter() {
                if let Some(record) = self.deploy_history.get(deploy_id) {
                    if record.epoch >= cutoff_epoch && record.success {
                        return Err(EgoError::InvalidTransaction(
                            "Duplicate contract deployment detected".to_string(),
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    fn can_use_free_quota(&self, deployer: &Address, stake: Option<Balance>) -> EgoResult<bool> {
        let stake_amount = stake.unwrap_or(Balance::ZERO);
        if stake_amount < self.config.min_stake_for_quota {
            return Ok(false);
        }

        if let Some(quota) = self.staker_quotas.get(deployer) {
            if quota.epoch == self.current_epoch {
                Ok(quota.free_deploys_remaining > 0)
            } else {
                Ok(self.config.free_deploys_per_epoch > 0)
            }
        } else {
            Ok(self.config.free_deploys_per_epoch > 0)
        }
    }

    fn calculate_resources(&self, deploy_type: &DeployType) -> (u32, u64) {
        match deploy_type {
            DeployType::SmartContract {
                code_size_kb,
                estimated_ru,
            } => (*code_size_kb, *estimated_ru),
            DeployType::StorageDeal {
                data_size_kb,
                duration_blocks,
            } => {
                let ru = (*data_size_kb as u64) * (*duration_blocks / 1000);
                (*data_size_kb, ru)
            }
            DeployType::RollupOperator { initial_state_kb } => {
                let ru = (*initial_state_kb as u64) * 10;
                (*initial_state_kb, ru)
            }
        }
    }

    fn calculate_credits_needed(&self, size_kb: u32, estimated_ru: u64) -> u64 {
        let size_credits = (size_kb as u64) * self.config.credits_per_kb;
        let ru_credits = estimated_ru * self.config.credits_per_ru;
        size_credits + ru_credits
    }

    fn calculate_pob_floor(&self, size_kb: u32, estimated_ru: u64) -> u64 {
        let size_floor = (size_kb as u64) * self.config.pob_floor_per_kb;
        let ru_floor = estimated_ru * self.config.pob_floor_per_ru;
        size_floor + ru_floor
    }

    fn generate_deploy_id(&self, request: &DeployRequest) -> Hash {
        let config = bincode::config::standard();
        let data = bincode::encode_to_vec(
            &(
                &request.deployer,
                &request.deploy_type,
                &crate::crypto::hash_data(&request.code),
                Timestamp::now(),
            ),
            config,
        )
        .unwrap_or_default();

        crate::crypto::hash_data(&data)
    }

    fn record_deploy_request(
        &self,
        request: &DeployRequest,
        decision: &DeployDecision,
        current_block: u64,
        stake: Option<Balance>,
    ) {
        let deploy_id = match decision {
            DeployDecision::AcceptWithFreeQuota { deploy_id } => *deploy_id,
            DeployDecision::AcceptWithCredits { deploy_id, .. } => *deploy_id,
            DeployDecision::Reject { deploy_id, .. } => *deploy_id,
        };

        let (size_kb, ru_consumed) = self.calculate_resources(&request.deploy_type);
        let code_hash = crate::crypto::hash_data(&request.code);

        let (status, credits_used, free_deploy_used, bond_amount, bond_unlock_block, pob_burn) =
            match decision {
                DeployDecision::AcceptWithFreeQuota { .. } => {
                    (DeployStatus::Accepted, 0, true, None, None, 0)
                }
                DeployDecision::AcceptWithCredits {
                    credits_required,
                    bond_required,
                    pob_floor,
                    ..
                } => {
                    let unlock_block = bond_required
                        .map(|_| current_block + self.config.bond_lock_duration_blocks);
                    (
                        DeployStatus::Accepted,
                        *credits_required,
                        false,
                        *bond_required,
                        unlock_block,
                        *pob_floor,
                    )
                }
                DeployDecision::Reject { reason, .. } => (
                    DeployStatus::Rejected {
                        reason: reason.clone(),
                    },
                    0,
                    false,
                    None,
                    None,
                    0,
                ),
            };

        let ai_pattern_detected = self.detect_ai_patterns(request).is_err();
        let human_verified = request.human_verification_signature.is_some()
            && self.verify_human_signature(request).is_ok();

        let is_accepted = matches!(status, DeployStatus::Accepted);

        let record = DeployRecord {
            deploy_id,
            deployer: request.deployer,
            deploy_type: request.deploy_type.clone(),
            code_hash,
            size_kb,
            ru_consumed,
            credits_used,
            free_deploy_used,
            bond_amount,
            bond_unlock_block,
            status: status.clone(),
            epoch: self.current_epoch,
            timestamp: Timestamp::now(),
            gas_used: 0,
            success: is_accepted,
            error: match decision {
                DeployDecision::Reject { reason, .. } => Some(reason.clone()),
                _ => None,
            },
            pob_burn_amount: pob_burn,
            human_verified,
            ai_pattern_detected,
            verification_signature: request.human_verification_signature.clone(),
            shard_id: request.preferred_shard.unwrap_or(0),
            contract_address: None,
        };

        self.deploy_history.insert(deploy_id, record);

        self.deployer_index
            .entry(request.deployer)
            .or_insert_with(VecDeque::new)
            .push_back(deploy_id);

        self.code_hash_index
            .entry(code_hash)
            .or_insert_with(Vec::new)
            .push(deploy_id);

        let mut stats = self
            .epoch_stats
            .entry(self.current_epoch)
            .or_insert_with(|| EpochDeployStats {
                epoch: self.current_epoch,
                ..Default::default()
            });

        stats.total_deploys += 1;
        stats.total_size_kb += size_kb as u64;
        stats.total_ru_consumed += ru_consumed;

        if is_accepted {
            if free_deploy_used {
                stats.free_deploys_used += 1;

                let stake_amount = stake.unwrap_or(Balance::ZERO);
                if let Some(mut quota) = self.staker_quotas.get_mut(&request.deployer) {
                    if quota.epoch < self.current_epoch {
                        quota.free_deploys_remaining = self.config.free_deploys_per_epoch;
                        quota.deploys_used_this_epoch = 0;
                        quota.epoch = self.current_epoch;
                        quota.stake_amount = stake_amount;
                    }
                    quota.free_deploys_remaining = quota.free_deploys_remaining.saturating_sub(1);
                    quota.deploys_used_this_epoch += 1;
                    quota.last_updated = Timestamp::now();
                } else {
                    self.staker_quotas.insert(
                        request.deployer,
                        StakerQuota {
                            staker: request.deployer,
                            stake_amount,
                            free_deploys_remaining: self
                                .config
                                .free_deploys_per_epoch
                                .saturating_sub(1),
                            deploys_used_this_epoch: 1,
                            epoch: self.current_epoch,
                            last_updated: Timestamp::now(),
                            quota_band: QuotaBand::Mid,
                            drs_multiplier: 1.0,
                        },
                    );
                }
            }
            stats.credits_consumed += credits_used;
            if let Some(bond) = bond_amount {
                stats.bonds_collected = stats
                    .bonds_collected
                    .checked_add(bond)
                    .unwrap_or(stats.bonds_collected);
            }
        } else if matches!(status, DeployStatus::Rejected { .. }) {
            stats.rejected_spam += 1;
        }

        if pob_burn > 0 {
            let burn_record = PoBBurnRecord {
                deploy_id,
                deployer: request.deployer,
                burn_amount: pob_burn,
                credits_minted: credits_used,
                timestamp: Timestamp::now(),
                burn_tx_hash: deploy_id,
            };
            self.pob_burn_tracker.insert(deploy_id, burn_record);
        }
    }

    pub fn complete_deploy(
        &self,
        deploy_id: &Hash,
        success: bool,
        gas_used: u64,
        error: Option<String>,
        contract_address: Option<Address>,
    ) -> EgoResult<()> {
        let mut record =
            self.deploy_history
                .get_mut(deploy_id)
                .ok_or(EgoError::InvalidTransaction(
                    "Deploy record not found".to_string(),
                ))?;

        let deployer = record.deployer;
        let epoch = record.epoch;

        let should_slash = if !success {
            let key = (deployer, epoch);
            let mut failed_count = self.failed_deploys_tracker.entry(key).or_insert(0);
            *failed_count += 1;
            let count = *failed_count;
            drop(failed_count);
            count >= self.config.bond_slash_threshold
        } else {
            false
        };

        record.success = success;
        record.gas_used = gas_used;
        record.error = error.clone();
        record.contract_address = contract_address;

        if success {
            record.status = DeployStatus::Completed;
        } else if should_slash {
            record.status = DeployStatus::BondSlashed;
        } else {
            record.status = DeployStatus::Failed {
                error: error.unwrap_or_else(|| "Unknown error".to_string()),
            };
        }

        drop(record);

        if !success && self.config.anti_spam_enabled {
            if let Some(mut metrics) = self.anti_spam_tracker.get_mut(&deployer) {
                metrics.total_rejected += 1;
                metrics.spam_score = metrics.spam_score.saturating_add(20);
            }
        }

        Ok(())
    }

    pub fn finalize_epoch(&self, epoch: u64) -> EgoResult<EpochDeployStats> {
        let mut stats = self
            .epoch_stats
            .get(&epoch)
            .map(|entry| entry.clone())
            .unwrap_or_else(|| EpochDeployStats {
                epoch,
                ..Default::default()
            });

        let mut deployers = HashSet::new();
        let mut code_hashes = HashSet::new();
        let mut duplicate_contracts = 0;
        let mut successful_deploys = 0;
        let mut failed_deploys = 0;
        let mut bonds_slashed_total = Balance::ZERO;
        let mut human_verified_deploys = 0;
        let mut ai_flagged_deploys = 0;

        for entry in self.deploy_history.iter() {
            if entry.epoch != epoch {
                continue;
            }

            deployers.insert(entry.deployer);

            if !code_hashes.insert(entry.code_hash) {
                duplicate_contracts += 1;
            }

            if entry.success {
                successful_deploys += 1;
            } else {
                failed_deploys += 1;
            }

            if matches!(entry.status, DeployStatus::BondSlashed) {
                if let Some(bond) = entry.bond_amount {
                    bonds_slashed_total = bonds_slashed_total
                        .checked_add(bond)
                        .unwrap_or(bonds_slashed_total);
                }
            }

            if entry.human_verified {
                human_verified_deploys += 1;
            }

            if entry.ai_pattern_detected {
                ai_flagged_deploys += 1;
            }
        }

        stats.unique_deployers = deployers.len() as u32;
        stats.duplicate_contracts = duplicate_contracts;
        stats.successful_deploys = successful_deploys;
        stats.failed_deploys = failed_deploys;
        stats.bonds_slashed = bonds_slashed_total;
        stats.human_verified_deploys = human_verified_deploys;
        stats.ai_flagged_deploys = ai_flagged_deploys;

        self.epoch_stats.insert(epoch, stats.clone());

        Ok(stats)
    }

    pub fn advance_epoch(&mut self, new_epoch: u64) -> EgoResult<()> {
        if new_epoch <= self.current_epoch {
            return Err(EgoError::InvalidTransaction(
                "New epoch must be greater than current epoch".to_string(),
            ));
        }

        let _stats = self.finalize_epoch(self.current_epoch)?;

        self.current_epoch = new_epoch;

        for mut quota in self.staker_quotas.iter_mut() {
            if quota.epoch < new_epoch {
                quota.epoch = new_epoch;
                quota.free_deploys_remaining = self.config.free_deploys_per_epoch;
                quota.deploys_used_this_epoch = 0;
                quota.last_updated = Timestamp::now();
            }
        }

        self.prune_old_records()?;

        Ok(())
    }

    fn prune_old_records(&self) -> EgoResult<()> {
        let cutoff_epoch = self
            .current_epoch
            .saturating_sub(self.config.dedup_lookback_epochs * 2);

        self.deploy_history
            .retain(|_, record| record.epoch >= cutoff_epoch);

        self.epoch_stats.retain(|&epoch, _| epoch >= cutoff_epoch);

        self.failed_deploys_tracker
            .retain(|(_, epoch), _| *epoch >= cutoff_epoch);

        for mut entry in self.deployer_index.iter_mut() {
            let queue = entry.value_mut();
            queue.retain(|deploy_id| {
                self.deploy_history
                    .get(deploy_id)
                    .map(|r| r.epoch >= cutoff_epoch)
                    .unwrap_or(false)
            });
        }

        for mut entry in self.code_hash_index.iter_mut() {
            let vec = entry.value_mut();
            vec.retain(|deploy_id| {
                self.deploy_history
                    .get(deploy_id)
                    .map(|r| r.epoch >= cutoff_epoch)
                    .unwrap_or(false)
            });
        }

        self.pob_burn_tracker.retain(|_, record| {
            let two_epochs_ago = Timestamp::from_millis(
                Timestamp::now()
                    .as_millis()
                    .saturating_sub(2 * 20 * 60 * 12000),
            );
            record.timestamp.as_millis() >= two_epochs_ago.as_millis()
        });

        for mut entry in self.anti_spam_tracker.iter_mut() {
            let metrics = entry.value_mut();
            if metrics.spam_score > 0 {
                metrics.spam_score = metrics.spam_score.saturating_sub(5);
            }
        }

        Ok(())
    }

    pub fn blacklist_contract(
        &self,
        code_hash: Hash,
        reason: String,
        blacklisted_by: Address,
        evidence_hash: Hash,
    ) -> EgoResult<()> {
        let entry = BlacklistEntry {
            code_hash,
            reason,
            blacklisted_at: Timestamp::now(),
            blacklisted_by,
            evidence_hash,
        };

        self.blacklisted_contracts.insert(code_hash, entry);

        Ok(())
    }

    pub fn remove_from_blacklist(&self, code_hash: &Hash) -> EgoResult<()> {
        self.blacklisted_contracts
            .remove(code_hash)
            .ok_or(EgoError::InvalidTransaction(
                "Contract not in blacklist".to_string(),
            ))?;

        Ok(())
    }

    pub fn is_blacklisted(&self, code_hash: &Hash) -> bool {
        self.blacklisted_contracts.contains_key(code_hash)
    }

    pub fn get_user_quota(&self, user: &Address) -> Option<StakerQuota> {
        self.staker_quotas.get(user).map(|entry| entry.clone())
    }

    pub fn get_deploy_record(&self, deploy_id: &Hash) -> Option<DeployRecord> {
        self.deploy_history.get(deploy_id).map(|r| r.clone())
    }

    pub fn get_epoch_stats(&self, epoch: u64) -> Option<EpochDeployStats> {
        self.epoch_stats.get(&epoch).map(|s| s.clone())
    }

    pub fn get_deployer_history(&self, deployer: &Address, limit: usize) -> Vec<DeployRecord> {
        if let Some(deploy_ids) = self.deployer_index.get(deployer) {
            deploy_ids
                .iter()
                .rev()
                .take(limit)
                .filter_map(|id| self.deploy_history.get(id).map(|r| r.clone()))
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn get_contract_deploys(&self, code_hash: &Hash) -> Vec<DeployRecord> {
        if let Some(deploy_ids) = self.code_hash_index.get(code_hash) {
            deploy_ids
                .iter()
                .filter_map(|id| self.deploy_history.get(id).map(|r| r.clone()))
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn update_quota_from_drs(
        &self,
        staker: &Address,
        drs_multiplier: f64,
        quota_band: QuotaBand,
    ) -> EgoResult<()> {
        let mut quota = self
            .staker_quotas
            .get_mut(staker)
            .ok_or(EgoError::AccountNotFound {
                account_id: staker.to_string(),
            })?;

        quota.drs_multiplier = drs_multiplier.clamp(0.7, 1.3);
        quota.quota_band = quota_band;

        let base_quota = self.config.free_deploys_per_epoch;
        let adjusted_quota = ((base_quota as f64) * quota.drs_multiplier).round() as u32;

        if quota.epoch == self.current_epoch {
            let remaining_ratio = quota.free_deploys_remaining as f64 / base_quota.max(1) as f64;
            quota.free_deploys_remaining = (adjusted_quota as f64 * remaining_ratio).round() as u32;
        } else {
            quota.free_deploys_remaining = adjusted_quota;
        }

        quota.last_updated = Timestamp::now();

        Ok(())
    }

    pub fn record_pob_burn(
        &self,
        deploy_id: Hash,
        deployer: Address,
        burn_amount: u64,
        credits_minted: u64,
        burn_tx_hash: Hash,
    ) -> EgoResult<()> {
        let burn_record = PoBBurnRecord {
            deploy_id,
            deployer,
            burn_amount,
            credits_minted,
            timestamp: Timestamp::now(),
            burn_tx_hash,
        };

        self.pob_burn_tracker.insert(deploy_id, burn_record);

        Ok(())
    }

    pub fn get_pob_burn_record(&self, deploy_id: &Hash) -> Option<PoBBurnRecord> {
        self.pob_burn_tracker.get(deploy_id).map(|r| r.clone())
    }

    pub fn get_anti_spam_metrics(&self, deployer: &Address) -> Option<AntiSpamMetrics> {
        self.anti_spam_tracker.get(deployer).map(|m| m.clone())
    }

    pub fn enable_emergency_mode(&mut self) {
        self.config.emergency_mode = true;
    }

    pub fn disable_emergency_mode(&mut self) {
        self.config.emergency_mode = false;
    }

    pub fn enable_whitelist_mode(&mut self) {
        self.config.whitelist_only_mode = true;
    }

    pub fn disable_whitelist_mode(&mut self) {
        self.config.whitelist_only_mode = false;
    }

    pub fn update_config(&mut self, new_config: DeployPolicyConfig) -> EgoResult<()> {
        if new_config.max_deploy_size_kb == 0 || new_config.max_ru_per_deploy == 0 {
            return Err(EgoError::InvalidTransaction(
                "Invalid config: limits cannot be zero".to_string(),
            ));
        }

        if new_config.free_deploys_per_epoch > 1000 {
            return Err(EgoError::InvalidTransaction(
                "Free deploys per epoch too high".to_string(),
            ));
        }

        if new_config.bond_slash_threshold == 0 {
            return Err(EgoError::InvalidTransaction(
                "Bond slash threshold cannot be zero".to_string(),
            ));
        }

        self.config = new_config;

        Ok(())
    }

    pub fn get_current_epoch(&self) -> u64 {
        self.current_epoch
    }

    pub fn get_config(&self) -> &DeployPolicyConfig {
        &self.config
    }

    pub fn get_total_deploys(&self) -> usize {
        self.deploy_history.len()
    }

    pub fn get_epoch_deploys(&self, epoch: u64) -> usize {
        if let Some(stats) = self.epoch_stats.get(&epoch) {
            stats.total_deploys as usize
        } else {
            self.deploy_history
                .iter()
                .filter(|entry| entry.epoch == epoch)
                .count()
        }
    }

    pub fn get_successful_deploys(&self, epoch: u64) -> usize {
        if let Some(stats) = self.epoch_stats.get(&epoch) {
            stats.successful_deploys as usize
        } else {
            self.deploy_history
                .iter()
                .filter(|entry| entry.epoch == epoch && entry.success)
                .count()
        }
    }

    pub fn calculate_deployer_reputation(&self, deployer: &Address) -> DeployerReputation {
        let mut total_deploys = 0u32;
        let mut successful_deploys = 0u32;
        let mut human_verified_count = 0u32;
        let mut ai_flagged_count = 0u32;
        let mut total_credits_used = 0u64;
        let mut total_pob_burned = 0u64;
        let mut bonds_slashed = 0u32;
        let mut last_deploy: Option<Timestamp> = None;

        if let Some(deploy_ids) = self.deployer_index.get(deployer) {
            for deploy_id in deploy_ids.iter() {
                if let Some(record) = self.deploy_history.get(deploy_id) {
                    total_deploys += 1;

                    if record.success {
                        successful_deploys += 1;
                    }

                    if record.human_verified {
                        human_verified_count += 1;
                    }

                    if record.ai_pattern_detected {
                        ai_flagged_count += 1;
                    }

                    total_credits_used += record.credits_used;
                    total_pob_burned += record.pob_burn_amount;

                    if matches!(record.status, DeployStatus::BondSlashed) {
                        bonds_slashed += 1;
                    }

                    if last_deploy.is_none()
                        || record.timestamp.as_millis() > last_deploy.unwrap().as_millis()
                    {
                        last_deploy = Some(record.timestamp);
                    }
                }
            }
        }

        let failed_deploys = total_deploys.saturating_sub(successful_deploys);
        let success_rate = if total_deploys > 0 {
            (successful_deploys as f64 / total_deploys as f64) * 100.0
        } else {
            0.0
        };

        let reputation_score = calculate_reputation_score(
            success_rate,
            human_verified_count,
            ai_flagged_count,
            bonds_slashed,
            total_deploys,
        );

        let spam_metrics = self.get_anti_spam_metrics(deployer);

        DeployerReputation {
            deployer: *deployer,
            total_deploys,
            successful_deploys,
            failed_deploys,
            success_rate,
            human_verified_count,
            ai_flagged_count,
            total_credits_used,
            total_pob_burned,
            bonds_slashed,
            reputation_score,
            spam_score: spam_metrics.map(|m| m.spam_score).unwrap_or(0),
            last_deploy,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum DeployDecision {
    AcceptWithFreeQuota {
        deploy_id: Hash,
    },
    AcceptWithCredits {
        deploy_id: Hash,
        credits_required: u64,
        bond_required: Option<Balance>,
        pob_floor: u64,
    },
    Reject {
        deploy_id: Hash,
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployerReputation {
    pub deployer: Address,
    pub total_deploys: u32,
    pub successful_deploys: u32,
    pub failed_deploys: u32,
    pub success_rate: f64,
    pub human_verified_count: u32,
    pub ai_flagged_count: u32,
    pub total_credits_used: u64,
    pub total_pob_burned: u64,
    pub bonds_slashed: u32,
    pub reputation_score: u32,
    pub spam_score: u32,
    pub last_deploy: Option<Timestamp>,
}

fn calculate_reputation_score(
    success_rate: f64,
    human_verified: u32,
    ai_flagged: u32,
    bonds_slashed: u32,
    total_deploys: u32,
) -> u32 {
    let mut score = 50.0;

    score += (success_rate - 50.0) * 0.5;

    score += (human_verified as f64 / total_deploys.max(1) as f64) * 20.0;

    score -= (ai_flagged as f64 / total_deploys.max(1) as f64) * 30.0;

    score -= (bonds_slashed as f64) * 10.0;

    if total_deploys >= 10 {
        score += 5.0;
    }
    if total_deploys >= 50 {
        score += 10.0;
    }

    score.clamp(0.0, 100.0) as u32
}

pub fn validate_deploy_request(request: &DeployRequest) -> EgoResult<()> {
    if request.code.is_empty() {
        return Err(EgoError::InvalidTransaction(
            "Deploy code cannot be empty".to_string(),
        ));
    }

    if request.code.len() > 10 * 1024 * 1024 {
        return Err(EgoError::InvalidTransaction(
            "Deploy code exceeds maximum size".to_string(),
        ));
    }

    match &request.deploy_type {
        DeployType::SmartContract {
            code_size_kb,
            estimated_ru,
        } => {
            if *code_size_kb == 0 || *estimated_ru == 0 {
                return Err(EgoError::InvalidTransaction(
                    "Invalid deploy parameters".to_string(),
                ));
            }
        }
        DeployType::StorageDeal {
            data_size_kb,
            duration_blocks,
        } => {
            if *data_size_kb == 0 || *duration_blocks == 0 {
                return Err(EgoError::InvalidTransaction(
                    "Invalid storage deal parameters".to_string(),
                ));
            }
        }
        DeployType::RollupOperator { initial_state_kb } => {
            if *initial_state_kb == 0 {
                return Err(EgoError::InvalidTransaction(
                    "Invalid rollup parameters".to_string(),
                ));
            }
        }
    }

    Ok(())
}

pub fn estimate_deploy_cost(
    deploy_type: &DeployType,
    config: &DeployPolicyConfig,
) -> DeployCostEstimate {
    let (size_kb, estimated_ru) = match deploy_type {
        DeployType::SmartContract {
            code_size_kb,
            estimated_ru,
        } => (*code_size_kb, *estimated_ru),
        DeployType::StorageDeal {
            data_size_kb,
            duration_blocks,
        } => {
            let ru = (*data_size_kb as u64) * (*duration_blocks / 1000);
            (*data_size_kb, ru)
        }
        DeployType::RollupOperator { initial_state_kb } => {
            let ru = (*initial_state_kb as u64) * 10;
            (*initial_state_kb, ru)
        }
    };

    let credits = (size_kb as u64) * config.credits_per_kb + estimated_ru * config.credits_per_ru;

    let pob_floor = if config.pob_floor_enabled {
        (size_kb as u64) * config.pob_floor_per_kb + estimated_ru * config.pob_floor_per_ru
    } else {
        0
    };

    let bond = config.deploy_bond_amount;

    DeployCostEstimate {
        size_kb,
        estimated_ru,
        credits_required: credits,
        pob_floor_required: pob_floor,
        bond_required: bond,
        total_cost_estimate: Balance::new(credits as u128 + pob_floor as u128),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployCostEstimate {
    pub size_kb: u32,
    pub estimated_ru: u64,
    pub credits_required: u64,
    pub pob_floor_required: u64,
    pub bond_required: Balance,
    pub total_cost_estimate: Balance,
}
