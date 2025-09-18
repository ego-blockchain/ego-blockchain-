use crate::{Address, Balance, EgoError, EgoResult, Hash, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployPolicyManager {
    pub current_epoch: u64,
    pub config: DeployPolicyConfig,
    pub staker_quotas: HashMap<Address, StakerQuota>,
    pub deploy_history: HashMap<Hash, DeployRecord>,
    pub epoch_stats: HashMap<u64, EpochDeployStats>,
    pub blacklisted_contracts: HashSet<Hash>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakerQuota {
    pub staker: Address,
    pub stake_amount: Balance,
    pub free_deploys_remaining: u32,
    pub deploys_used_this_epoch: u32,
    pub epoch: u64,
    pub last_updated: Timestamp,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployRequest {
    pub deployer: Address,
    pub deploy_type: DeployType,
    pub code: Vec<u8>,
    pub metadata: HashMap<String, String>,
    pub use_free_quota: bool,
    pub preferred_shard: Option<u32>,
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
        }
    }
}

impl DeployPolicyManager {
    pub fn new(config: DeployPolicyConfig) -> Self {
        Self {
            current_epoch: 0,
            config,
            staker_quotas: HashMap::new(),
            deploy_history: HashMap::new(),
            epoch_stats: HashMap::new(),
            blacklisted_contracts: HashSet::new(),
        }
    }

    pub fn evaluate_deploy_request(
        &mut self,
        request: &DeployRequest,
        staker_stake: Option<Balance>,
        current_block: u64,
    ) -> EgoResult<DeployDecision> {
        let deploy_id = self.generate_deploy_id(request);

        self.check_hard_caps(&request.deployer, &request.deploy_type)?;

        self.validate_deploy_limits(&request.deploy_type)?;

        if self.config.enable_dedup {
            let code_hash = crate::crypto::hash_data(&request.code);
            self.check_duplicate_contract(&code_hash)?;
        }

        let (size_kb, estimated_ru) = self.calculate_resources(&request.deploy_type);
        let credits_needed = self.calculate_credits_needed(size_kb, estimated_ru);

        let can_use_free_quota =
            request.use_free_quota && self.can_use_free_quota(&request.deployer, staker_stake)?;

        let decision = if can_use_free_quota {
            DeployDecision::AcceptWithFreeQuota { deploy_id }
        } else {
            let bond_required = if credits_needed > 0 {
                Some(self.config.deploy_bond_amount)
            } else {
                None
            };

            DeployDecision::AcceptWithCredits {
                deploy_id,
                credits_required: credits_needed,
                bond_required,
            }
        };

        self.record_deploy_request(request, &decision, current_block);

        Ok(decision)
    }

    fn check_hard_caps(&self, deployer: &Address, deploy_type: &DeployType) -> EgoResult<()> {
        let current_stats = self
            .epoch_stats
            .get(&self.current_epoch)
            .cloned()
            .unwrap_or_default();

        if current_stats.total_deploys >= self.config.max_deploys_per_epoch {
            return Err(EgoError::ResourceLimitExceeded {
                resource: "Global deploys per epoch".to_string(),
            });
        }

        let user_deploys = self
            .deploy_history
            .values()
            .filter(|record| record.deployer == *deployer && record.epoch == self.current_epoch)
            .count() as u32;

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

        let is_duplicate = self.deploy_history.values().any(|record| {
            record.code_hash == *code_hash
                && record.epoch >= cutoff_epoch
                && record.status == DeployStatus::Completed
        });

        if is_duplicate {
            return Err(EgoError::InvalidTransaction(
                "Duplicate contract deployment detected".to_string(),
            ));
        }

        Ok(())
    }

    fn can_use_free_quota(
        &mut self,
        deployer: &Address,
        stake: Option<Balance>,
    ) -> EgoResult<bool> {
        let stake_amount = stake.unwrap_or(Balance::ZERO);
        if stake_amount < self.config.min_stake_for_quota {
            return Ok(false);
        }

        let quota = self
            .staker_quotas
            .entry(*deployer)
            .or_insert_with(|| StakerQuota {
                staker: *deployer,
                stake_amount,
                free_deploys_remaining: self.config.free_deploys_per_epoch,
                deploys_used_this_epoch: 0,
                epoch: self.current_epoch,
                last_updated: Timestamp::now(),
            });

        if quota.epoch < self.current_epoch {
            quota.free_deploys_remaining = self.config.free_deploys_per_epoch;
            quota.deploys_used_this_epoch = 0;
            quota.epoch = self.current_epoch;
        }

        Ok(quota.free_deploys_remaining > 0)
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

    fn generate_deploy_id(&self, request: &DeployRequest) -> Hash {
        let config = bincode::config::standard();
        let data = bincode::encode_to_vec(
            &(
                &request.deployer,
                &request.deploy_type,
                &request.code,
                Timestamp::now(),
            ),
            config,
        )
        .unwrap_or_default();

        crate::crypto::hash_data(&data)
    }

    fn record_deploy_request(
        &mut self,
        request: &DeployRequest,
        decision: &DeployDecision,
        current_block: u64,
    ) {
        let deploy_id = match decision {
            DeployDecision::AcceptWithFreeQuota { deploy_id } => *deploy_id,
            DeployDecision::AcceptWithCredits { deploy_id, .. } => *deploy_id,
            DeployDecision::Reject { deploy_id, .. } => *deploy_id,
        };

        let (size_kb, ru_consumed) = self.calculate_resources(&request.deploy_type);
        let code_hash = crate::crypto::hash_data(&request.code);

        let (status, credits_used, free_deploy_used, bond_amount, bond_unlock_block) =
            match decision {
                DeployDecision::AcceptWithFreeQuota { .. } => {
                    (DeployStatus::Accepted, 0, true, None, None)
                }
                DeployDecision::AcceptWithCredits {
                    credits_required,
                    bond_required,
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
                ),
            };

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
            status,
            epoch: self.current_epoch,
            timestamp: Timestamp::now(),
            gas_used: 0,
            success: matches!(
                decision,
                DeployDecision::AcceptWithFreeQuota { .. }
                    | DeployDecision::AcceptWithCredits { .. }
            ),
            error: match decision {
                DeployDecision::Reject { reason, .. } => Some(reason.clone()),
                _ => None,
            },
        };

        self.deploy_history.insert(deploy_id, record);

        if free_deploy_used {
            if let Some(quota) = self.staker_quotas.get_mut(&request.deployer) {
                quota.free_deploys_remaining = quota.free_deploys_remaining.saturating_sub(1);
                quota.deploys_used_this_epoch += 1;
                quota.last_updated = Timestamp::now();
            }
        }
    }

    pub fn complete_deploy(
        &mut self,
        deploy_id: &Hash,
        success: bool,
        gas_used: u64,
        error: Option<String>,
    ) -> EgoResult<()> {
        let (deployer, epoch) = {
            let record = self
                .deploy_history
                .get(deploy_id)
                .ok_or(EgoError::InvalidTransaction(
                    "Deploy record not found".to_string(),
                ))?;
            (record.deployer, record.epoch)
        };

        let should_slash = if !success {
            let failed_deploys = self
                .deploy_history
                .values()
                .filter(|r| r.deployer == deployer && r.epoch == epoch && !r.success)
                .count() as u32;
            failed_deploys >= self.config.bond_slash_threshold
        } else {
            false
        };

        let record = self.deploy_history.get_mut(deploy_id).unwrap();
        record.success = success;
        record.gas_used = gas_used;
        record.error = error.clone();
        record.status = if success {
            DeployStatus::Completed
        } else if should_slash {
            DeployStatus::BondSlashed
        } else {
            DeployStatus::Failed {
                error: error.unwrap_or_else(|| "Unknown error".to_string()),
            }
        };

        Ok(())
    }

    pub fn finalize_epoch(&mut self, epoch: u64) -> EgoResult<EpochDeployStats> {
        let records: Vec<&DeployRecord> = self
            .deploy_history
            .values()
            .filter(|record| record.epoch == epoch)
            .collect();

        let total_deploys = records.len() as u32;
        let successful_deploys = records.iter().filter(|r| r.success).count() as u32;
        let failed_deploys = total_deploys - successful_deploys;

        let total_size_kb = records.iter().map(|r| r.size_kb as u64).sum();
        let total_ru_consumed = records.iter().map(|r| r.ru_consumed).sum();
        let free_deploys_used = records.iter().filter(|r| r.free_deploy_used).count() as u32;
        let credits_consumed = records.iter().map(|r| r.credits_used).sum();

        let bonds_collected = records
            .iter()
            .filter_map(|r| r.bond_amount)
            .fold(Balance::ZERO, |acc, bond| {
                acc.checked_add(bond).unwrap_or(acc)
            });

        let bonds_slashed = records
            .iter()
            .filter(|r| matches!(r.status, DeployStatus::BondSlashed))
            .filter_map(|r| r.bond_amount)
            .fold(Balance::ZERO, |acc, bond| {
                acc.checked_add(bond).unwrap_or(acc)
            });

        let unique_deployers = records
            .iter()
            .map(|r| r.deployer)
            .collect::<std::collections::HashSet<_>>()
            .len() as u32;

        let mut code_hashes = std::collections::HashSet::new();
        let mut duplicate_contracts = 0;
        for record in &records {
            if !code_hashes.insert(record.code_hash) {
                duplicate_contracts += 1;
            }
        }

        let stats = EpochDeployStats {
            epoch,
            total_deploys,
            successful_deploys,
            failed_deploys,
            total_size_kb,
            total_ru_consumed,
            free_deploys_used,
            credits_consumed,
            bonds_collected,
            bonds_slashed,
            unique_deployers,
            duplicate_contracts,
        };

        self.epoch_stats.insert(epoch, stats.clone());
        self.current_epoch = epoch + 1;

        Ok(stats)
    }

    pub fn get_user_quota(&self, user: &Address) -> Option<&StakerQuota> {
        self.staker_quotas.get(user)
    }

    pub fn get_deploy_record(&self, deploy_id: &Hash) -> Option<&DeployRecord> {
        self.deploy_history.get(deploy_id)
    }

    pub fn get_epoch_stats(&self, epoch: u64) -> Option<&EpochDeployStats> {
        self.epoch_stats.get(&epoch)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeployDecision {
    AcceptWithFreeQuota {
        deploy_id: Hash,
    },
    AcceptWithCredits {
        deploy_id: Hash,
        credits_required: u64,
        bond_required: Option<Balance>,
    },
    Reject {
        deploy_id: Hash,
        reason: String,
    },
}
