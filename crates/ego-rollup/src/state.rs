use crate::error::{RollupError, RollupResult};
use crate::types::RollupTransaction;
use ego_core::{
    Account, AccountType, Address, Balance, Hash, PublicKey, ShardId, SliceId, Timestamp,
    Transaction, TransactionPayload, TransactionResult,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const MAX_CROSS_SHARD_PENDING: usize = 100000;
const MAX_STATE_HISTORY_EPOCHS: u64 = 1000;
const CROSS_SHARD_DEADLINE_EPOCHS: u64 = 100;

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum RollupStateChange {
    BalanceUpdate {
        address: Address,
        old_balance: Balance,
        new_balance: Balance,
    },
    NonceUpdate {
        address: Address,
        old_nonce: u64,
        new_nonce: u64,
    },
    ContractDeployed {
        address: Address,
        code_hash: Hash,
        deployer: Address,
    },
    Staked {
        address: Address,
        amount: Balance,
        validator: Address,
    },
    Unstaked {
        address: Address,
        amount: Balance,
    },
    Burned {
        address: Address,
        amount: Balance,
        reason: BurnReason,
    },
    CrossShardInitiated {
        from: Address,
        target_shard: u32,
        receipt_hash: Hash,
        nonce: u64,
    },
    StorageUpdate {
        address: Address,
        key: Vec<u8>,
        old_value: Option<Vec<u8>>,
        new_value: Vec<u8>,
    },
    StorageCreditsAdded {
        address: Address,
        credits: u64,
        burn_amount: Balance,
    },
    DeployCreditsAdded {
        address: Address,
        credits: u64,
        burn_amount: Balance,
    },
    DRSScoreUpdated {
        address: Address,
        old_score: Option<u64>,
        new_score: u64,
        epoch: u64,
    },
    TriadPlacementUpdated {
        chunk_id: Hash,
        old_placement: Option<TriadPlacementRecord>,
        new_placement: TriadPlacementRecord,
    },
    ProofSubmitted {
        node: Address,
        proof_type: ProofType,
        chunk_id: Hash,
        verified: bool,
        latency_ms: u32,
    },
    RewardsClaimed {
        node: Address,
        epoch: u64,
        total_amount: Balance,
        buckets: RewardBuckets,
    },
    PQTransition {
        address: Address,
        old_phase: u8,
        new_phase: u8,
        algorithms_enabled: Vec<u16>,
    },
    AccountCreated {
        address: Address,
        account_type: AccountType,
        initial_balance: Balance,
    },
    ValidatorMetricsUpdated {
        validator: Address,
        epoch: u64,
        uptime_percent: u8,
        puc_coefficient: f64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum BurnReason {
    StorageCredits,
    DeployCredits,
    PoB,
    Slashing,
    FeeMarket,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode,
)]
pub enum ProofType {
    PoSt,
    PoRep,
    PoC,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct TriadPlacementRecord {
    pub primary: Address,
    pub replica_a: Address,
    pub replica_b: Address,
    pub group_id: String,
    pub placement_epoch: u64,
    pub diversity_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct RewardBuckets {
    pub storage: Balance,
    pub consensus: Balance,
    pub coverage: Balance,
    pub retrieval: Balance,
}

#[derive(Debug, Clone)]
pub struct RollupState {
    accounts: HashMap<Address, Account>,
    storage: HashMap<Address, HashMap<Vec<u8>, Vec<u8>>>,
    nonces: HashMap<Address, u64>,
    block_height: u64,
    state_root: Hash,
    total_supply: Balance,
    contract_code: HashMap<Address, Vec<u8>>,
    cross_shard_pending: HashMap<Hash, CrossShardPending>,
    epoch: u64,
    shard_id: ShardId,
    triad_placements: HashMap<Hash, TriadPlacementRecord>,
    drs_scores: HashMap<Address, DRSScoreRecord>,
    proof_history: HashMap<Address, ProofHistoryRecord>,
    reward_claims: HashMap<Address, HashMap<u64, Balance>>,
    validator_metrics: HashMap<Address, ValidatorMetricsRecord>,
    pq_transition_state: PQTransitionState,
    cellular_stats: CellularStatsState,
    deploy_quotas: HashMap<Address, DeployQuotaRecord>,
    storage_deals: HashMap<Hash, StorageDealRecord>,
    chain_id: u32,
    network_id: u32,
    protocol_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct StateTransition {
    pub from_state: Hash,
    pub to_state: Hash,
    pub transaction_hash: Hash,
    pub changes: Vec<RollupStateChange>,
    pub gas_used: u64,
    pub epoch: u64,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateDelta {
    pub account_changes: HashMap<Address, AccountDelta>,
    pub storage_changes: HashMap<Address, HashMap<Vec<u8>, StorageChange>>,
    pub nonce_changes: HashMap<Address, u64>,
    pub contract_changes: HashMap<Address, ContractChange>,
    pub cross_shard_changes: Vec<CrossShardChange>,
    pub triad_changes: HashMap<Hash, TriadPlacementRecord>,
    pub drs_changes: HashMap<Address, DRSScoreRecord>,
    pub proof_changes: HashMap<Address, ProofHistoryDelta>,
    pub reward_changes: HashMap<Address, Balance>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct AccountDelta {
    pub old_balance: Option<Balance>,
    pub new_balance: Balance,
    pub old_nonce: u64,
    pub new_nonce: u64,
    pub created: bool,
    pub storage_credits_delta: i64,
    pub deploy_credits_delta: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct StorageChange {
    pub old_value: Option<Vec<u8>>,
    pub new_value: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ContractChange {
    pub deployed: bool,
    pub code: Vec<u8>,
    pub storage_root: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct CrossShardChange {
    pub receipt_hash: Hash,
    pub source_shard: u32,
    pub target_shard: u32,
    pub status: CrossShardStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub enum CrossShardStatus {
    Pending,
    Confirmed,
    Failed,
    Expired,
}

#[derive(Debug, Clone)]
pub struct CrossShardPending {
    pub receipt_hash: Hash,
    pub source_shard: ShardId,
    pub target_shard: ShardId,
    pub payload: Vec<u8>,
    pub timestamp: Timestamp,
    pub deadline_epoch: u64,
    pub nonce: u64,
    pub source_tx_hash: Hash,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DRSScoreRecord {
    pub score: u64,
    pub multiplier: u64,
    pub epoch: u64,
    pub components: DRSComponents,
    pub evidence_root: Hash,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DRSComponents {
    pub uptime_score: u64,
    pub post_pass_rate: u64,
    pub post_latency_score: u64,
    pub poc_quality_score: u64,
    pub serve_ratio: u64,
    pub density_penalty: u64,
}

#[derive(Debug, Clone)]
pub struct ProofHistoryRecord {
    pub post_proofs_submitted: u64,
    pub porep_proofs_submitted: u64,
    pub poc_proofs_submitted: u64,
    pub post_pass_rate: f64,
    pub avg_latency_ms: u32,
    pub consecutive_misses: u32,
    pub last_proof_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProofHistoryDelta {
    pub proofs_added: u64,
    pub pass_rate_change: f64,
    pub latency_change: i32,
}

#[derive(Debug, Clone)]
pub struct ValidatorMetricsRecord {
    pub uptime_percent: u8,
    pub peer_degree: u16,
    pub relay_bytes: u64,
    pub iot_sessions: u32,
    pub shard_demand_score: u16,
    pub puc_coefficient: f64,
    pub last_update_epoch: u64,
}

#[derive(Debug, Clone)]
pub struct PQTransitionState {
    pub current_phase: u8,
    pub pq_required_topics: Vec<String>,
    pub legacy_support_end_epoch: Option<u64>,
    pub algorithm_usage_stats: HashMap<u16, u64>,
    pub transition_start_epoch: u64,
}

#[derive(Debug, Clone)]
pub struct CellularStatsState {
    pub total_cellular_bytes: u64,
    pub total_wifi_bytes: u64,
    pub cellular_safe_txs: u64,
    pub wifi_only_txs: u64,
    pub throttled_operations: u64,
}

#[derive(Debug, Clone)]
pub struct DeployQuotaRecord {
    pub free_deploys_used: u32,
    pub deploy_credits_used: u64,
    pub epoch_reset: u64,
}

#[derive(Debug, Clone)]
pub struct StorageDealRecord {
    pub client: Address,
    pub triad: TriadPlacementRecord,
    pub data_size: u64,
    pub duration_epochs: u64,
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub credits_locked: u64,
    pub replication_factor: u8,
}

#[derive(Debug, Clone)]
pub struct StateCheckpoint {
    accounts: HashMap<Address, Account>,
    storage: HashMap<Address, HashMap<Vec<u8>, Vec<u8>>>,
    nonces: HashMap<Address, u64>,
    block_height: u64,
    state_root: Hash,
    total_supply: Balance,
    contract_code: HashMap<Address, Vec<u8>>,
    cross_shard_pending: HashMap<Hash, CrossShardPending>,
    epoch: u64,
    triad_placements: HashMap<Hash, TriadPlacementRecord>,
    drs_scores: HashMap<Address, DRSScoreRecord>,
    proof_history: HashMap<Address, ProofHistoryRecord>,
    reward_claims: HashMap<Address, HashMap<u64, Balance>>,
    validator_metrics: HashMap<Address, ValidatorMetricsRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub state_root: Hash,
    pub block_height: u64,
    pub epoch: u64,
    pub account_count: usize,
    pub total_supply: Balance,
    pub timestamp: Timestamp,
    pub shard_id: u32,
    pub pending_cross_shard: usize,
    pub contract_count: usize,
    pub total_storage_size: usize,
    pub chain_id: u32,
    pub network_id: u32,
}

impl RollupState {
    pub fn new(chain_id: u32, network_id: u32) -> Self {
        Self {
            accounts: HashMap::new(),
            storage: HashMap::new(),
            nonces: HashMap::new(),
            block_height: 0,
            state_root: Hash::ZERO,
            total_supply: Balance::ZERO,
            contract_code: HashMap::new(),
            cross_shard_pending: HashMap::new(),
            epoch: 0,
            shard_id: ShardId::new(0).unwrap(),
            triad_placements: HashMap::new(),
            drs_scores: HashMap::new(),
            proof_history: HashMap::new(),
            reward_claims: HashMap::new(),
            validator_metrics: HashMap::new(),
            pq_transition_state: PQTransitionState::new(),
            cellular_stats: CellularStatsState::new(),
            deploy_quotas: HashMap::new(),
            storage_deals: HashMap::new(),
            chain_id,
            network_id,
            protocol_version: ego_core::PROTOCOL_VERSION,
        }
    }

    pub fn with_shard_id(shard_id: ShardId, chain_id: u32, network_id: u32) -> Self {
        Self {
            accounts: HashMap::new(),
            storage: HashMap::new(),
            nonces: HashMap::new(),
            block_height: 0,
            state_root: Hash::ZERO,
            total_supply: Balance::ZERO,
            contract_code: HashMap::new(),
            cross_shard_pending: HashMap::new(),
            epoch: 0,
            shard_id,
            triad_placements: HashMap::new(),
            drs_scores: HashMap::new(),
            proof_history: HashMap::new(),
            reward_claims: HashMap::new(),
            validator_metrics: HashMap::new(),
            pq_transition_state: PQTransitionState::new(),
            cellular_stats: CellularStatsState::new(),
            deploy_quotas: HashMap::new(),
            storage_deals: HashMap::new(),
            chain_id,
            network_id,
            protocol_version: ego_core::PROTOCOL_VERSION,
        }
    }

    pub fn from_genesis(
        genesis_accounts: Vec<(Address, Balance, AccountType)>,
        shard_id: ShardId,
        chain_id: u32,
        network_id: u32,
    ) -> Self {
        let mut state = Self::with_shard_id(shard_id, chain_id, network_id);

        for (address, balance, account_type) in genesis_accounts {
            let mut account = match account_type {
                AccountType::EOA => Account::new_eoa(address, vec![0u8; 1312], vec![0u8; 1184]),
                AccountType::Validator {
                    validator_pubkey,
                    commission_rate,
                    ..
                } => Account::new_validator(
                    address,
                    validator_pubkey,
                    commission_rate,
                    balance,
                    vec![0u8; 1312],
                    vec![0u8; 1184],
                )
                .unwrap_or_else(|_| Account::new_eoa(address, vec![0u8; 1312], vec![0u8; 1184])),
                _ => Account::new_eoa(address, vec![0u8; 1312], vec![0u8; 1184]),
            };

            account.credit(balance);
            state.accounts.insert(address, account);
            state.total_supply = state
                .total_supply
                .checked_add(balance)
                .unwrap_or(Balance::new(u128::MAX));
        }

        state.state_root = state.compute_state_root();
        state
    }

    pub async fn execute_transaction(
        &mut self,
        tx: &RollupTransaction,
    ) -> RollupResult<TransactionResult> {
        if !tx.inner.verify_signature()? {
            return Ok(TransactionResult {
                tx_hash: tx.hash(),
                success: false,
                error: Some("Invalid signature".to_string()),
                ru_used: 0,
                storage_used: 0,
                state_changes: vec![],
                events: vec![],
                cross_shard_receipts: vec![],
                pq_verification_result: None,
                proof_verifications: vec![],
            });
        }

        let current_nonce = self.get_nonce(tx.inner.from);
        if tx.rollup_nonce != current_nonce + 1 {
            return Ok(TransactionResult {
                tx_hash: tx.hash(),
                success: false,
                error: Some(format!(
                    "Invalid nonce: expected {}, got {}",
                    current_nonce + 1,
                    tx.rollup_nonce
                )),
                ru_used: 0,
                storage_used: 0,
                state_changes: vec![],
                events: vec![],
                cross_shard_receipts: vec![],
                pq_verification_result: None,
                proof_verifications: vec![],
            });
        }

        if tx.inner.chain_id != self.chain_id {
            return Ok(TransactionResult {
                tx_hash: tx.hash(),
                success: false,
                error: Some(format!(
                    "Chain ID mismatch: expected {}, got {}",
                    self.chain_id, tx.inner.chain_id
                )),
                ru_used: 0,
                storage_used: 0,
                state_changes: vec![],
                events: vec![],
                cross_shard_receipts: vec![],
                pq_verification_result: None,
                proof_verifications: vec![],
            });
        }

        let result = self.execute_inner_transaction(&tx.inner).await?;

        if result.success {
            self.increment_nonce(tx.inner.from);
        }

        self.state_root = self.compute_state_root();

        Ok(result)
    }

    async fn execute_inner_transaction(
        &mut self,
        tx: &Transaction,
    ) -> RollupResult<TransactionResult> {
        match &tx.payload {
            TransactionPayload::Transfer {
                to,
                amount,
                stealth_mode,
                ..
            } => self.execute_transfer(tx.from, *to, *amount, *stealth_mode, tx.hash),
            TransactionPayload::CreateAccount {
                account_address,
                account_type,
                initial_balance,
                dilithium_pk,
                mlkem_pk,
                ed25519_pk,
            } => self.execute_create_account(
                tx.from,
                *account_address,
                account_type.clone(),
                *initial_balance,
                dilithium_pk.clone(),
                mlkem_pk.clone(),
                ed25519_pk.clone(),
                tx.hash,
            ),
            TransactionPayload::StoreData {
                chunk_id,
                data_size,
                duration_epochs,
                triad_placement,
                storage_credits,
                replication_factor,
                ..
            } => self.execute_store_data(
                tx.from,
                *chunk_id,
                *data_size,
                *duration_epochs,
                triad_placement.clone(),
                *storage_credits,
                *replication_factor,
                tx.hash,
            ),
            TransactionPayload::UpdateTriadPlacement {
                chunk_id,
                new_placement,
                reason,
                ..
            } => self.execute_update_triad_placement(
                *chunk_id,
                new_placement.clone(),
                reason.clone(),
                tx.hash,
            ),
            TransactionPayload::SubmitProofBatch {
                proof_type,
                proofs,
                epoch,
                ..
            } => self.execute_submit_proof_batch(
                tx.from,
                proof_type.clone(),
                proofs.clone(),
                *epoch,
                tx.hash,
            ),
            TransactionPayload::PoStResponse {
                proofs, latency_ms, ..
            } => self.execute_post_response(tx.from, proofs.clone(), latency_ms.clone(), tx.hash),
            TransactionPayload::ClaimRewards {
                node_id,
                epoch,
                reward_buckets,
                drs_multiplier,
                ..
            } => self.execute_claim_rewards(
                *node_id,
                *epoch,
                reward_buckets.clone(),
                *drs_multiplier,
                tx.hash,
            ),
            TransactionPayload::BuyStorageCredits {
                amount,
                credits_byte_months,
                ..
            } => self.execute_buy_storage_credits(tx.from, *amount, *credits_byte_months, tx.hash),
            TransactionPayload::BuyDeployCredits {
                amount, credits, ..
            } => self.execute_buy_deploy_credits(tx.from, *amount, *credits, tx.hash),
            TransactionPayload::DeployContract {
                contract_code_hash,
                constructor_args,
                deploy_credits,
                use_free_quota,
                ..
            } => self.execute_deploy_contract(
                tx.from,
                contract_code_hash.to_vec(),
                constructor_args.clone(),
                *deploy_credits,
                *use_free_quota,
                tx.hash,
            ),
            TransactionPayload::ExecuteContract {
                contract_address,
                method,
                args,
                value,
            } => self.execute_call_contract(
                tx.from,
                *contract_address,
                method.clone(),
                args.clone(),
                *value,
                tx.hash,
            ),
            TransactionPayload::Stake {
                amount,
                validator_pubkey,
                ..
            } => self.execute_stake(tx.from, *amount, validator_pubkey.clone(), tx.hash),
            TransactionPayload::Unstake { amount, .. } => {
                self.execute_unstake(tx.from, *amount, tx.hash)
            }
            TransactionPayload::CrossShard {
                target_shard,
                message,
                nonce,
                ..
            } => self.execute_cross_shard(
                tx.from,
                target_shard.as_u32(),
                message.clone(),
                *nonce,
                tx.hash,
            ),
            TransactionPayload::UpdateDRS {
                node_id,
                epoch,
                uptime_score,
                post_latency_score,
                post_pass_rate,
                poc_quality_score,
                serve_ratio,
                density_penalty,
                final_multiplier,
                metrics_hash,
            } => self.execute_update_drs(
                *node_id,
                *epoch,
                *uptime_score,
                *post_latency_score,
                *post_pass_rate,
                *poc_quality_score,
                *serve_ratio,
                *density_penalty,
                *final_multiplier,
                *metrics_hash,
                tx.hash,
            ),
            TransactionPayload::UpdateValidatorMetrics {
                validator,
                epoch,
                uptime_percent,
                peer_degree,
                relay_bytes,
                iot_sessions,
                shard_demand_score,
                puc_coefficient,
            } => self.execute_update_validator_metrics(
                *validator,
                *epoch,
                *uptime_percent,
                *peer_degree,
                *relay_bytes,
                *iot_sessions,
                *shard_demand_score,
                *puc_coefficient,
                tx.hash,
            ),
            TransactionPayload::PQTransition {
                new_algorithms,
                disable_legacy,
                transition_epoch,
                ..
            } => self.execute_pq_transition(
                tx.from,
                new_algorithms.clone(),
                *disable_legacy,
                *transition_epoch,
                tx.hash,
            ),
            _ => Ok(TransactionResult {
                tx_hash: tx.hash,
                success: false,
                error: Some("Unsupported transaction type".to_string()),
                ru_used: 0,
                storage_used: 0,
                state_changes: vec![],
                events: vec![],
                cross_shard_receipts: vec![],
                pq_verification_result: None,
                proof_verifications: vec![],
            }),
        }
    }

    fn execute_transfer(
        &mut self,
        from: Address,
        to: Address,
        amount: Balance,
        stealth_mode: bool,
        tx_hash: Hash,
    ) -> RollupResult<TransactionResult> {
        let mut from_account = self.get_or_create_account(from);
        let mut to_account = self.get_or_create_account(to);

        let old_from_balance = from_account.balance;

        if !from_account.can_spend(amount) {
            return Ok(TransactionResult {
                tx_hash,
                success: false,
                error: Some("Insufficient balance".to_string()),
                ru_used: if stealth_mode { 30000 } else { 21000 },
                storage_used: 0,
                state_changes: vec![],
                events: vec![],
                cross_shard_receipts: vec![],
                pq_verification_result: None,
                proof_verifications: vec![],
            });
        }

        from_account
            .debit(amount)
            .map_err(|e| RollupError::StateError(e.to_string()))?;
        to_account.credit(amount);

        self.accounts.insert(from, from_account.clone());
        self.accounts.insert(to, to_account);

        let state_change = ego_core::StateChange {
            account: from,
            change_type: ego_core::StateChangeType::BalanceUpdate,
            previous_value: Some(old_from_balance.as_u128().to_le_bytes().to_vec()),
            new_value: from_account.balance.as_u128().to_le_bytes().to_vec(),
        };

        Ok(TransactionResult {
            tx_hash,
            success: true,
            error: None,
            ru_used: if stealth_mode { 30000 } else { 21000 },
            storage_used: 0,
            state_changes: vec![state_change],
            events: vec![],
            cross_shard_receipts: vec![],
            pq_verification_result: None,
            proof_verifications: vec![],
        })
    }

    fn execute_create_account(
        &mut self,
        creator: Address,
        account_address: Address,
        account_type: AccountType,
        initial_balance: Balance,
        dilithium_pk: Vec<u8>,
        mlkem_pk: Vec<u8>,
        ed25519_pk: Option<Vec<u8>>,
        tx_hash: Hash,
    ) -> RollupResult<TransactionResult> {
        if self.accounts.contains_key(&account_address) {
            return Ok(TransactionResult {
                tx_hash,
                success: false,
                error: Some("Account already exists".to_string()),
                ru_used: 10000,
                storage_used: 0,
                state_changes: vec![],
                events: vec![],
                cross_shard_receipts: vec![],
                pq_verification_result: None,
                proof_verifications: vec![],
            });
        }

        let mut creator_account = self.get_or_create_account(creator);
        if !creator_account.can_spend(initial_balance) {
            return Ok(TransactionResult {
                tx_hash,
                success: false,
                error: Some("Insufficient balance for account creation".to_string()),
                ru_used: 10000,
                storage_used: 0,
                state_changes: vec![],
                events: vec![],
                cross_shard_receipts: vec![],
                pq_verification_result: None,
                proof_verifications: vec![],
            });
        }

        creator_account
            .debit(initial_balance)
            .map_err(|e| RollupError::StateError(e.to_string()))?;
        self.accounts.insert(creator, creator_account);

        let mut new_account = Account::new_eoa(account_address, dilithium_pk, mlkem_pk);
        new_account.ed25519_pk = ed25519_pk;
        new_account.credit(initial_balance);
        new_account.account_type = account_type;

        self.accounts.insert(account_address, new_account);

        let state_change = ego_core::StateChange {
            account: account_address,
            change_type: ego_core::StateChangeType::AccountCreation,
            previous_value: None,
            new_value: initial_balance.as_u128().to_le_bytes().to_vec(),
        };

        Ok(TransactionResult {
            tx_hash,
            success: true,
            error: None,
            ru_used: 50000,
            storage_used: 1000,
            state_changes: vec![state_change],
            events: vec![],
            cross_shard_receipts: vec![],
            pq_verification_result: None,
            proof_verifications: vec![],
        })
    }

    fn execute_store_data(
        &mut self,
        from: Address,
        chunk_id: Hash,
        data_size: u64,
        duration_epochs: u64,
        triad_placement: ego_core::TriadPlacement,
        storage_credits: u64,
        replication_factor: u8,
        tx_hash: Hash,
    ) -> RollupResult<TransactionResult> {
        let mut account = self.get_or_create_account(from);

        if account.storage_credits < storage_credits {
            return Ok(TransactionResult {
                tx_hash,
                success: false,
                error: Some("Insufficient storage credits".to_string()),
                ru_used: 20000,
                storage_used: 0,
                state_changes: vec![],
                events: vec![],
                cross_shard_receipts: vec![],
                pq_verification_result: None,
                proof_verifications: vec![],
            });
        }

        account
            .use_storage_credits(storage_credits)
            .map_err(|e| RollupError::StateError(e.to_string()))?;
        self.accounts.insert(from, account);

        let triad_record = TriadPlacementRecord {
            primary: triad_placement.primary.node_id,
            replica_a: triad_placement.replica_a.node_id,
            replica_b: triad_placement.replica_b.node_id,
            group_id: triad_placement.group_id.clone(),
            placement_epoch: self.epoch,
            diversity_score: triad_placement.diversity_score,
        };

        self.triad_placements.insert(chunk_id, triad_record);

        let deal = StorageDealRecord {
            client: from,
            triad: self.triad_placements[&chunk_id].clone(),
            data_size,
            duration_epochs,
            start_epoch: self.epoch,
            end_epoch: self.epoch + duration_epochs,
            credits_locked: storage_credits,
            replication_factor,
        };

        self.storage_deals.insert(chunk_id, deal);

        let state_change = ego_core::StateChange {
            account: from,
            change_type: ego_core::StateChangeType::StorageUpdate,
            previous_value: None,
            new_value: chunk_id.as_bytes().to_vec(),
        };

        Ok(TransactionResult {
            tx_hash,
            success: true,
            error: None,
            ru_used: 80000 + (data_size / 1024) * replication_factor as u64,
            storage_used: data_size,
            state_changes: vec![state_change],
            events: vec![],
            cross_shard_receipts: vec![],
            pq_verification_result: None,
            proof_verifications: vec![],
        })
    }

    fn execute_update_triad_placement(
        &mut self,
        chunk_id: Hash,
        new_placement: ego_core::TriadPlacement,
        _reason: ego_core::PlacementUpdateReason,
        tx_hash: Hash,
    ) -> RollupResult<TransactionResult> {
        let old_placement = self.triad_placements.get(&chunk_id).cloned();

        let new_record = TriadPlacementRecord {
            primary: new_placement.primary.node_id,
            replica_a: new_placement.replica_a.node_id,
            replica_b: new_placement.replica_b.node_id,
            group_id: new_placement.group_id.clone(),
            placement_epoch: self.epoch,
            diversity_score: new_placement.diversity_score,
        };

        self.triad_placements.insert(chunk_id, new_record);

        if let Some(deal) = self.storage_deals.get_mut(&chunk_id) {
            deal.triad = self.triad_placements[&chunk_id].clone();
        }

        let state_change = ego_core::StateChange {
            account: Address::new([0u8; 20]),
            change_type: ego_core::StateChangeType::StorageUpdate,
            previous_value: old_placement.map(|p| {
                bincode::encode_to_vec(&p, bincode::config::standard()).unwrap_or_default()
            }),
            new_value: bincode::encode_to_vec(
                &self.triad_placements[&chunk_id],
                bincode::config::standard(),
            )
            .unwrap_or_default(),
        };

        Ok(TransactionResult {
            tx_hash,
            success: true,
            error: None,
            ru_used: 60000,
            storage_used: 0,
            state_changes: vec![state_change],
            events: vec![],
            cross_shard_receipts: vec![],
            pq_verification_result: None,
            proof_verifications: vec![],
        })
    }

    fn execute_submit_proof_batch(
        &mut self,
        from: Address,
        proof_type: ego_core::ProofType,
        proofs: Vec<ego_core::ProofSubmission>,
        epoch: u64,
        tx_hash: Hash,
    ) -> RollupResult<TransactionResult> {
        let mut proof_history = self
            .proof_history
            .get(&from)
            .cloned()
            .unwrap_or_else(|| ProofHistoryRecord::new());

        let total_proofs = proofs.len() as u64;
        let mut verified_count = 0u64;
        let mut total_latency = 0u32;

        for proof in &proofs {
            if proof.latency_ms <= 8000 {
                verified_count += 1;
            }
            total_latency += proof.latency_ms;
        }

        let avg_latency = if total_proofs > 0 {
            total_latency / total_proofs as u32
        } else {
            0
        };

        match proof_type {
            ego_core::ProofType::PoSt => {
                proof_history.post_proofs_submitted += total_proofs;
                proof_history.post_pass_rate = if proof_history.post_proofs_submitted > 0 {
                    (verified_count as f64 / proof_history.post_proofs_submitted as f64) * 100.0
                } else {
                    0.0
                };
            }
            ego_core::ProofType::PoRep => {
                proof_history.porep_proofs_submitted += total_proofs;
            }
            ego_core::ProofType::PoC => {
                proof_history.poc_proofs_submitted += total_proofs;
            }
        }

        proof_history.avg_latency_ms = avg_latency;
        proof_history.last_proof_epoch = epoch;

        if verified_count < total_proofs {
            proof_history.consecutive_misses += 1;
        } else {
            proof_history.consecutive_misses = 0;
        }

        self.proof_history.insert(from, proof_history);

        let state_change = ego_core::StateChange {
            account: from,
            change_type: ego_core::StateChangeType::StorageUpdate,
            previous_value: None,
            new_value: epoch.to_le_bytes().to_vec(),
        };

        Ok(TransactionResult {
            tx_hash,
            success: true,
            error: None,
            ru_used: 50000 + (total_proofs * 5000),
            storage_used: 0,
            state_changes: vec![state_change],
            events: vec![],
            cross_shard_receipts: vec![],
            pq_verification_result: None,
            proof_verifications: vec![],
        })
    }

    fn execute_post_response(
        &mut self,
        from: Address,
        proofs: Vec<ego_core::PoStProof>,
        latency_ms: Vec<u32>,
        tx_hash: Hash,
    ) -> RollupResult<TransactionResult> {
        let mut proof_history = self
            .proof_history
            .get(&from)
            .cloned()
            .unwrap_or_else(|| ProofHistoryRecord::new());

        let total_proofs = proofs.len() as u64;
        let verified_count = proofs.len() as u64;

        let avg_latency = if !latency_ms.is_empty() {
            latency_ms.iter().sum::<u32>() / latency_ms.len() as u32
        } else {
            0
        };

        proof_history.post_proofs_submitted += total_proofs;
        proof_history.post_pass_rate = if proof_history.post_proofs_submitted > 0 {
            (verified_count as f64 / proof_history.post_proofs_submitted as f64) * 100.0
        } else {
            100.0
        };
        proof_history.avg_latency_ms = avg_latency;
        proof_history.last_proof_epoch = self.epoch;
        proof_history.consecutive_misses = 0;

        self.proof_history.insert(from, proof_history);

        let mut account = self.get_or_create_account(from);
        account.record_post_proof(true, avg_latency, self.epoch);
        self.accounts.insert(from, account);

        let state_change = ego_core::StateChange {
            account: from,
            change_type: ego_core::StateChangeType::StorageUpdate,
            previous_value: None,
            new_value: self.epoch.to_le_bytes().to_vec(),
        };

        Ok(TransactionResult {
            tx_hash,
            success: true,
            error: None,
            ru_used: 60000 + (total_proofs * 8000),
            storage_used: 0,
            state_changes: vec![state_change],
            events: vec![],
            cross_shard_receipts: vec![],
            pq_verification_result: None,
            proof_verifications: vec![],
        })
    }

    fn execute_claim_rewards(
        &mut self,
        node_id: Address,
        epoch: u64,
        reward_buckets: ego_core::RewardClaim,
        drs_multiplier: f64,
        tx_hash: Hash,
    ) -> RollupResult<TransactionResult> {
        if epoch > self.epoch {
            return Ok(TransactionResult {
                tx_hash,
                success: false,
                error: Some("Cannot claim rewards for future epochs".to_string()),
                ru_used: 10000,
                storage_used: 0,
                state_changes: vec![],
                events: vec![],
                cross_shard_receipts: vec![],
                pq_verification_result: None,
                proof_verifications: vec![],
            });
        }

        let already_claimed = self
            .reward_claims
            .get(&node_id)
            .map(|claims| claims.contains_key(&epoch))
            .unwrap_or(false);

        if already_claimed {
            return Ok(TransactionResult {
                tx_hash,
                success: false,
                error: Some("Rewards already claimed for this epoch".to_string()),
                ru_used: 10000,
                storage_used: 0,
                state_changes: vec![],
                events: vec![],
                cross_shard_receipts: vec![],
                pq_verification_result: None,
                proof_verifications: vec![],
            });
        }

        let total_reward = reward_buckets.total;
        let adjusted_reward = Balance::new(
            ((total_reward.as_u128() as f64 * drs_multiplier) as u128).min(total_reward.as_u128()),
        );

        let mut account = self.get_or_create_account(node_id);
        account.credit(adjusted_reward);
        self.accounts.insert(node_id, account);

        self.reward_claims
            .entry(node_id)
            .or_insert_with(HashMap::new)
            .insert(epoch, adjusted_reward);

        let state_change = ego_core::StateChange {
            account: node_id,
            change_type: ego_core::StateChangeType::RewardDistribution,
            previous_value: None,
            new_value: adjusted_reward.as_u128().to_le_bytes().to_vec(),
        };

        Ok(TransactionResult {
            tx_hash,
            success: true,
            error: None,
            ru_used: 40000,
            storage_used: 0,
            state_changes: vec![state_change],
            events: vec![],
            cross_shard_receipts: vec![],
            pq_verification_result: None,
            proof_verifications: vec![],
        })
    }

    fn execute_buy_storage_credits(
        &mut self,
        from: Address,
        amount: Balance,
        credits: u64,
        tx_hash: Hash,
    ) -> RollupResult<TransactionResult> {
        let mut account = self.get_or_create_account(from);

        if !account.can_spend(amount) {
            return Ok(TransactionResult {
                tx_hash,
                success: false,
                error: Some("Insufficient balance".to_string()),
                ru_used: 15000,
                storage_used: 0,
                state_changes: vec![],
                events: vec![],
                cross_shard_receipts: vec![],
                pq_verification_result: None,
                proof_verifications: vec![],
            });
        }

        account
            .debit(amount)
            .map_err(|e| RollupError::StateError(e.to_string()))?;
        account.add_storage_credits(credits);
        self.accounts.insert(from, account);

        self.total_supply = self.total_supply.saturating_sub(amount);

        let state_change = ego_core::StateChange {
            account: from,
            change_type: ego_core::StateChangeType::StorageCreditsUpdate,
            previous_value: None,
            new_value: credits.to_le_bytes().to_vec(),
        };

        Ok(TransactionResult {
            tx_hash,
            success: true,
            error: None,
            ru_used: 25000,
            storage_used: 0,
            state_changes: vec![state_change],
            events: vec![],
            cross_shard_receipts: vec![],
            pq_verification_result: None,
            proof_verifications: vec![],
        })
    }

    fn execute_buy_deploy_credits(
        &mut self,
        from: Address,
        amount: Balance,
        credits: u64,
        tx_hash: Hash,
    ) -> RollupResult<TransactionResult> {
        let mut account = self.get_or_create_account(from);

        if !account.can_spend(amount) {
            return Ok(TransactionResult {
                tx_hash,
                success: false,
                error: Some("Insufficient balance".to_string()),
                ru_used: 15000,
                storage_used: 0,
                state_changes: vec![],
                events: vec![],
                cross_shard_receipts: vec![],
                pq_verification_result: None,
                proof_verifications: vec![],
            });
        }

        account
            .debit(amount)
            .map_err(|e| RollupError::StateError(e.to_string()))?;
        account.deploy_credits = account.deploy_credits.saturating_add(credits);
        self.accounts.insert(from, account);

        self.total_supply = self.total_supply.saturating_sub(amount);

        let state_change = ego_core::StateChange {
            account: from,
            change_type: ego_core::StateChangeType::DeployCreditsUpdate,
            previous_value: None,
            new_value: credits.to_le_bytes().to_vec(),
        };

        Ok(TransactionResult {
            tx_hash,
            success: true,
            error: None,
            ru_used: 25000,
            storage_used: 0,
            state_changes: vec![state_change],
            events: vec![],
            cross_shard_receipts: vec![],
            pq_verification_result: None,
            proof_verifications: vec![],
        })
    }

    fn execute_deploy_contract(
        &mut self,
        from: Address,
        code: Vec<u8>,
        _constructor_args: Vec<u8>,
        deploy_credits: u64,
        use_free_quota: bool,
        tx_hash: Hash,
    ) -> RollupResult<TransactionResult> {
        let mut account = self.get_or_create_account(from);

        if use_free_quota {
            if !account.can_deploy_free() {
                return Ok(TransactionResult {
                    tx_hash,
                    success: false,
                    error: Some("No free deploys remaining".to_string()),
                    ru_used: 10000,
                    storage_used: 0,
                    state_changes: vec![],
                    events: vec![],
                    cross_shard_receipts: vec![],
                    pq_verification_result: None,
                    proof_verifications: vec![],
                });
            }
            account
                .use_free_deploy()
                .map_err(|e| RollupError::StateError(e.to_string()))?;
        } else {
            if !account.can_use_deploy_credits(deploy_credits) {
                return Ok(TransactionResult {
                    tx_hash,
                    success: false,
                    error: Some("Insufficient deploy credits".to_string()),
                    ru_used: 10000,
                    storage_used: 0,
                    state_changes: vec![],
                    events: vec![],
                    cross_shard_receipts: vec![],
                    pq_verification_result: None,
                    proof_verifications: vec![],
                });
            }
            account
                .use_deploy_credits(deploy_credits)
                .map_err(|e| RollupError::StateError(e.to_string()))?;
        }

        self.accounts.insert(from, account);

        let contract_address = self.compute_contract_address(from, self.get_nonce(from));
        let contract_account = Account::new_eoa(contract_address, vec![0u8; 1312], vec![0u8; 1184]);
        self.accounts.insert(contract_address, contract_account);
        self.contract_code.insert(contract_address, code.clone());

        let storage_used = code.len() as u64;
        let code_hash = ego_core::crypto::hash_data(&code);

        let state_change = ego_core::StateChange {
            account: contract_address,
            change_type: ego_core::StateChangeType::AccountCreation,
            previous_value: None,
            new_value: code_hash.as_bytes().to_vec(),
        };

        Ok(TransactionResult {
            tx_hash,
            success: true,
            error: None,
            ru_used: 100000 + (code.len() as u64 * 200),
            storage_used,
            state_changes: vec![state_change],
            events: vec![],
            cross_shard_receipts: vec![],
            pq_verification_result: None,
            proof_verifications: vec![],
        })
    }

    fn execute_call_contract(
        &mut self,
        from: Address,
        contract: Address,
        _method: String,
        _args: Vec<u8>,
        value: Balance,
        tx_hash: Hash,
    ) -> RollupResult<TransactionResult> {
        if !self.contract_code.contains_key(&contract) {
            return Ok(TransactionResult {
                tx_hash,
                success: false,
                error: Some("Contract not found".to_string()),
                ru_used: 10000,
                storage_used: 0,
                state_changes: vec![],
                events: vec![],
                cross_shard_receipts: vec![],
                pq_verification_result: None,
                proof_verifications: vec![],
            });
        }

        let mut state_changes = vec![];

        if value > Balance::ZERO {
            let mut from_account = self.get_or_create_account(from);
            let mut contract_account = self.get_or_create_account(contract);

            let old_from_balance = from_account.balance;

            if !from_account.can_spend(value) {
                return Ok(TransactionResult {
                    tx_hash,
                    success: false,
                    error: Some("Insufficient balance".to_string()),
                    ru_used: 25000,
                    storage_used: 0,
                    state_changes: vec![],
                    events: vec![],
                    cross_shard_receipts: vec![],
                    pq_verification_result: None,
                    proof_verifications: vec![],
                });
            }

            from_account
                .debit(value)
                .map_err(|e| RollupError::StateError(e.to_string()))?;
            contract_account.credit(value);

            self.accounts.insert(from, from_account.clone());
            self.accounts.insert(contract, contract_account);

            state_changes.push(ego_core::StateChange {
                account: from,
                change_type: ego_core::StateChangeType::BalanceUpdate,
                previous_value: Some(old_from_balance.as_u128().to_le_bytes().to_vec()),
                new_value: from_account.balance.as_u128().to_le_bytes().to_vec(),
            });
        }

        Ok(TransactionResult {
            tx_hash,
            success: true,
            error: None,
            ru_used: 50000,
            storage_used: 0,
            state_changes,
            events: vec![],
            cross_shard_receipts: vec![],
            pq_verification_result: None,
            proof_verifications: vec![],
        })
    }

    fn execute_stake(
        &mut self,
        from: Address,
        amount: Balance,
        _validator_pubkey: PublicKey,
        tx_hash: Hash,
    ) -> RollupResult<TransactionResult> {
        let mut account = self.get_or_create_account(from);
        let old_balance = account.balance;

        if !account.can_spend(amount) {
            return Ok(TransactionResult {
                tx_hash,
                success: false,
                error: Some("Insufficient balance for staking".to_string()),
                ru_used: 30000,
                storage_used: 0,
                state_changes: vec![],
                events: vec![],
                cross_shard_receipts: vec![],
                pq_verification_result: None,
                proof_verifications: vec![],
            });
        }

        account
            .debit(amount)
            .map_err(|e| RollupError::StateError(e.to_string()))?;
        self.accounts.insert(from, account.clone());

        let state_change = ego_core::StateChange {
            account: from,
            change_type: ego_core::StateChangeType::BalanceUpdate,
            previous_value: Some(old_balance.as_u128().to_le_bytes().to_vec()),
            new_value: account.balance.as_u128().to_le_bytes().to_vec(),
        };

        Ok(TransactionResult {
            tx_hash,
            success: true,
            error: None,
            ru_used: 40000,
            storage_used: 0,
            state_changes: vec![state_change],
            events: vec![],
            cross_shard_receipts: vec![],
            pq_verification_result: None,
            proof_verifications: vec![],
        })
    }

    fn execute_unstake(
        &mut self,
        from: Address,
        amount: Balance,
        tx_hash: Hash,
    ) -> RollupResult<TransactionResult> {
        let mut account = self.get_or_create_account(from);
        let old_balance = account.balance;
        account.credit(amount);
        self.accounts.insert(from, account.clone());

        let state_change = ego_core::StateChange {
            account: from,
            change_type: ego_core::StateChangeType::BalanceUpdate,
            previous_value: Some(old_balance.as_u128().to_le_bytes().to_vec()),
            new_value: account.balance.as_u128().to_le_bytes().to_vec(),
        };

        Ok(TransactionResult {
            tx_hash,
            success: true,
            error: None,
            ru_used: 35000,
            storage_used: 0,
            state_changes: vec![state_change],
            events: vec![],
            cross_shard_receipts: vec![],
            pq_verification_result: None,
            proof_verifications: vec![],
        })
    }

    fn execute_cross_shard(
        &mut self,
        from: Address,
        target_shard: u32,
        message: Vec<u8>,
        nonce: u64,
        tx_hash: Hash,
    ) -> RollupResult<TransactionResult> {
        let target_shard_id =
            ShardId::new(target_shard).map_err(|e| RollupError::StateError(e.to_string()))?;

        let receipt_hash = ego_core::crypto::hash_multiple(&[
            tx_hash.as_bytes(),
            &target_shard.to_le_bytes(),
            &nonce.to_le_bytes(),
            &message,
        ]);

        if self.cross_shard_pending.len() >= MAX_CROSS_SHARD_PENDING {
            return Ok(TransactionResult {
                tx_hash,
                success: false,
                error: Some("Cross-shard queue full".to_string()),
                ru_used: 10000,
                storage_used: 0,
                state_changes: vec![],
                events: vec![],
                cross_shard_receipts: vec![],
                pq_verification_result: None,
                proof_verifications: vec![],
            });
        }

        let pending = CrossShardPending {
            receipt_hash,
            source_shard: self.shard_id,
            target_shard: target_shard_id,
            payload: message.clone(),
            timestamp: Timestamp::now(),
            deadline_epoch: self.epoch + CROSS_SHARD_DEADLINE_EPOCHS,
            nonce,
            source_tx_hash: tx_hash,
        };

        self.cross_shard_pending.insert(receipt_hash, pending);

        let state_change = ego_core::StateChange {
            account: from,
            change_type: ego_core::StateChangeType::StorageUpdate,
            previous_value: None,
            new_value: receipt_hash.as_bytes().to_vec(),
        };

        Ok(TransactionResult {
            tx_hash,
            success: true,
            error: None,
            ru_used: 60000,
            storage_used: 0,
            state_changes: vec![state_change],
            events: vec![],
            cross_shard_receipts: vec![ego_core::transaction::CrossShardReceipt {
                src_shard: self.shard_id,
                dst_shard: target_shard_id,
                src_block_hash: Hash::ZERO,
                tx_id: tx_hash,
                payload: message,
                nonce,
                deadline_epoch: self.epoch + CROSS_SHARD_DEADLINE_EPOCHS,
                merkle_proof: vec![],
            }],
            pq_verification_result: None,
            proof_verifications: vec![],
        })
    }

    fn execute_update_drs(
        &mut self,
        node_id: Address,
        epoch: u64,
        uptime_score: f64,
        post_latency_score: f64,
        post_pass_rate: f64,
        poc_quality_score: f64,
        serve_ratio: f64,
        density_penalty: f64,
        final_multiplier: f64,
        metrics_hash: Hash,
        tx_hash: Hash,
    ) -> RollupResult<TransactionResult> {
        let score = (final_multiplier * 100000.0) as u64;
        let multiplier = ((final_multiplier * 1000.0) as u64).clamp(700, 1300);

        let components = DRSComponents {
            uptime_score: (uptime_score * 100000.0) as u64,
            post_pass_rate: (post_pass_rate * 100000.0) as u64,
            post_latency_score: (post_latency_score * 100000.0) as u64,
            poc_quality_score: (poc_quality_score * 100000.0) as u64,
            serve_ratio: (serve_ratio * 100000.0) as u64,
            density_penalty: (density_penalty * 100000.0) as u64,
        };

        let record = DRSScoreRecord {
            score,
            multiplier,
            epoch,
            components,
            evidence_root: metrics_hash,
        };

        self.drs_scores.insert(node_id, record);

        let mut account = self.get_or_create_account(node_id);
        account.update_drs_score(final_multiplier, epoch);
        self.accounts.insert(node_id, account);

        let state_change = ego_core::StateChange {
            account: node_id,
            change_type: ego_core::StateChangeType::DRSScoreUpdate,
            previous_value: None,
            new_value: score.to_le_bytes().to_vec(),
        };

        Ok(TransactionResult {
            tx_hash,
            success: true,
            error: None,
            ru_used: 45000,
            storage_used: 0,
            state_changes: vec![state_change],
            events: vec![],
            cross_shard_receipts: vec![],
            pq_verification_result: None,
            proof_verifications: vec![],
        })
    }

    fn execute_update_validator_metrics(
        &mut self,
        validator: Address,
        epoch: u64,
        uptime_percent: u8,
        peer_degree: u16,
        relay_bytes: u64,
        iot_sessions: u32,
        shard_demand_score: u16,
        puc_coefficient: f64,
        tx_hash: Hash,
    ) -> RollupResult<TransactionResult> {
        let metrics = ValidatorMetricsRecord {
            uptime_percent,
            peer_degree,
            relay_bytes,
            iot_sessions,
            shard_demand_score,
            puc_coefficient,
            last_update_epoch: epoch,
        };

        self.validator_metrics.insert(validator, metrics);

        let state_change = ego_core::StateChange {
            account: validator,
            change_type: ego_core::StateChangeType::ValidatorUpdate,
            previous_value: None,
            new_value: epoch.to_le_bytes().to_vec(),
        };

        Ok(TransactionResult {
            tx_hash,
            success: true,
            error: None,
            ru_used: 35000,
            storage_used: 0,
            state_changes: vec![state_change],
            events: vec![],
            cross_shard_receipts: vec![],
            pq_verification_result: None,
            proof_verifications: vec![],
        })
    }

    fn execute_pq_transition(
        &mut self,
        _from: Address,
        new_algorithms: Vec<u16>,
        disable_legacy: bool,
        transition_epoch: u64,
        tx_hash: Hash,
    ) -> RollupResult<TransactionResult> {
        if disable_legacy {
            self.pq_transition_state.current_phase = 3;
            self.pq_transition_state.legacy_support_end_epoch = Some(transition_epoch);
        } else {
            self.pq_transition_state.current_phase = 2;
        }

        for &alg_id in &new_algorithms {
            *self
                .pq_transition_state
                .algorithm_usage_stats
                .entry(alg_id)
                .or_insert(0) += 1;
        }

        let state_change = ego_core::StateChange {
            account: Address::new([0u8; 20]),
            change_type: ego_core::StateChangeType::PQTransitionUpdate,
            previous_value: None,
            new_value: self
                .pq_transition_state
                .current_phase
                .to_le_bytes()
                .to_vec(),
        };

        Ok(TransactionResult {
            tx_hash,
            success: true,
            error: None,
            ru_used: 50000,
            storage_used: 0,
            state_changes: vec![state_change],
            events: vec![],
            cross_shard_receipts: vec![],
            pq_verification_result: None,
            proof_verifications: vec![],
        })
    }

    pub fn get_account(&self, address: &Address) -> RollupResult<Account> {
        self.accounts
            .get(address)
            .cloned()
            .ok_or_else(|| RollupError::StateError("Account not found".to_string()))
    }

    pub fn get_or_create_account(&mut self, address: Address) -> Account {
        self.accounts.get(&address).cloned().unwrap_or_else(|| {
            let account = Account::new_eoa(address, vec![0u8; 1312], vec![0u8; 1184]);
            self.accounts.insert(address, account.clone());
            account
        })
    }

    pub fn get_balance(&self, address: Address) -> Balance {
        self.accounts
            .get(&address)
            .map(|acc| acc.balance)
            .unwrap_or(Balance::ZERO)
    }

    pub fn get_nonce(&self, address: Address) -> u64 {
        self.nonces.get(&address).copied().unwrap_or(0)
    }

    pub fn increment_nonce(&mut self, address: Address) {
        let current = self.get_nonce(address);
        self.nonces.insert(address, current + 1);
    }

    pub fn set_storage(&mut self, address: Address, key: Vec<u8>, value: Vec<u8>) {
        self.storage
            .entry(address)
            .or_insert_with(HashMap::new)
            .insert(key, value);
    }

    pub fn get_storage(&self, address: Address, key: &[u8]) -> Option<Vec<u8>> {
        self.storage.get(&address)?.get(key).cloned()
    }

    pub fn get_contract_code(&self, address: Address) -> Option<Vec<u8>> {
        self.contract_code.get(&address).cloned()
    }

    pub fn compute_state_root(&self) -> Hash {
        let mut data = Vec::new();

        let mut sorted_accounts: Vec<_> = self.accounts.iter().collect();
        sorted_accounts.sort_by_key(|(addr, _)| addr.as_bytes());

        for (address, account) in sorted_accounts {
            data.extend_from_slice(address.as_bytes());
            data.extend_from_slice(&account.balance.as_u128().to_le_bytes());
            data.extend_from_slice(&account.nonce.to_le_bytes());
            data.extend_from_slice(&account.storage_credits.to_le_bytes());
            data.extend_from_slice(&account.deploy_credits.to_le_bytes());
        }

        let mut sorted_nonces: Vec<_> = self.nonces.iter().collect();
        sorted_nonces.sort_by_key(|(addr, _)| addr.as_bytes());

        for (address, nonce) in sorted_nonces {
            data.extend_from_slice(address.as_bytes());
            data.extend_from_slice(&nonce.to_le_bytes());
        }

        let mut sorted_storage: Vec<_> = self.storage.iter().collect();
        sorted_storage.sort_by_key(|(addr, _)| addr.as_bytes());

        for (address, storage_map) in sorted_storage {
            data.extend_from_slice(address.as_bytes());

            let mut sorted_storage_entries: Vec<_> = storage_map.iter().collect();
            sorted_storage_entries.sort_by_key(|(key, _)| *key);

            for (key, value) in sorted_storage_entries {
                data.extend_from_slice(key);
                data.extend_from_slice(value);
            }
        }

        let mut sorted_contracts: Vec<_> = self.contract_code.iter().collect();
        sorted_contracts.sort_by_key(|(addr, _)| addr.as_bytes());

        for (address, code) in sorted_contracts {
            data.extend_from_slice(address.as_bytes());
            data.extend_from_slice(&ego_core::crypto::hash_data(code).to_vec());
        }

        let mut sorted_triads: Vec<_> = self.triad_placements.iter().collect();
        sorted_triads.sort_by_key(|(hash, _)| hash.as_bytes());

        for (chunk_id, triad) in sorted_triads {
            data.extend_from_slice(chunk_id.as_bytes());
            data.extend_from_slice(triad.primary.as_bytes());
            data.extend_from_slice(triad.replica_a.as_bytes());
            data.extend_from_slice(triad.replica_b.as_bytes());
        }

        data.extend_from_slice(&self.epoch.to_le_bytes());
        data.extend_from_slice(&self.shard_id.as_u32().to_le_bytes());
        data.extend_from_slice(&self.chain_id.to_le_bytes());
        data.extend_from_slice(&self.network_id.to_le_bytes());
        data.extend_from_slice(&self.protocol_version.to_le_bytes());

        ego_core::crypto::hash_data(&data)
    }

    pub fn create_state_delta(&self, old_state: &RollupState) -> StateDelta {
        let mut account_changes = HashMap::new();
        let mut storage_changes = HashMap::new();
        let mut nonce_changes = HashMap::new();
        let mut contract_changes = HashMap::new();
        let mut cross_shard_changes = Vec::new();
        let mut triad_changes = HashMap::new();
        let mut drs_changes = HashMap::new();
        let mut proof_changes = HashMap::new();
        let mut reward_changes = HashMap::new();

        for (address, account) in &self.accounts {
            if let Some(old_account) = old_state.accounts.get(address) {
                if account.balance != old_account.balance
                    || account.nonce != old_account.nonce
                    || account.storage_credits != old_account.storage_credits
                    || account.deploy_credits != old_account.deploy_credits
                {
                    account_changes.insert(
                        *address,
                        AccountDelta {
                            old_balance: Some(old_account.balance),
                            new_balance: account.balance,
                            old_nonce: old_account.nonce,
                            new_nonce: account.nonce,
                            created: false,
                            storage_credits_delta: account.storage_credits as i64
                                - old_account.storage_credits as i64,
                            deploy_credits_delta: account.deploy_credits as i64
                                - old_account.deploy_credits as i64,
                        },
                    );
                }
            } else {
                account_changes.insert(
                    *address,
                    AccountDelta {
                        old_balance: None,
                        new_balance: account.balance,
                        old_nonce: 0,
                        new_nonce: account.nonce,
                        created: true,
                        storage_credits_delta: account.storage_credits as i64,
                        deploy_credits_delta: account.deploy_credits as i64,
                    },
                );
            }
        }

        for (address, storage_map) in &self.storage {
            let old_storage = old_state.storage.get(address);
            let mut address_storage_changes = HashMap::new();

            for (key, value) in storage_map {
                let old_value = old_storage.and_then(|s| s.get(key));
                if old_value.map(|v| v != value).unwrap_or(true) {
                    address_storage_changes.insert(
                        key.clone(),
                        StorageChange {
                            old_value: old_value.cloned(),
                            new_value: value.clone(),
                        },
                    );
                }
            }

            if !address_storage_changes.is_empty() {
                storage_changes.insert(*address, address_storage_changes);
            }
        }

        for (address, nonce) in &self.nonces {
            let old_nonce = old_state.get_nonce(*address);
            if *nonce != old_nonce {
                nonce_changes.insert(*address, *nonce);
            }
        }

        for (address, code) in &self.contract_code {
            if !old_state.contract_code.contains_key(address) {
                let storage_root = self.compute_contract_storage_root(*address);
                contract_changes.insert(
                    *address,
                    ContractChange {
                        deployed: true,
                        code: code.clone(),
                        storage_root,
                    },
                );
            }
        }

        for (receipt_hash, pending) in &self.cross_shard_pending {
            if !old_state.cross_shard_pending.contains_key(receipt_hash) {
                cross_shard_changes.push(CrossShardChange {
                    receipt_hash: *receipt_hash,
                    source_shard: pending.source_shard.as_u32(),
                    target_shard: pending.target_shard.as_u32(),
                    status: CrossShardStatus::Pending,
                });
            }
        }

        for (chunk_id, triad) in &self.triad_placements {
            if old_state.triad_placements.get(chunk_id) != Some(triad) {
                triad_changes.insert(*chunk_id, triad.clone());
            }
        }

        for (address, record) in &self.drs_scores {
            if old_state.drs_scores.get(address) != Some(record) {
                drs_changes.insert(*address, record.clone());
            }
        }

        StateDelta {
            account_changes,
            storage_changes,
            nonce_changes,
            contract_changes,
            cross_shard_changes,
            triad_changes,
            drs_changes,
            proof_changes,
            reward_changes,
        }
    }

    pub fn apply_state_delta(&mut self, delta: &StateDelta) -> RollupResult<()> {
        for (address, account_delta) in &delta.account_changes {
            if account_delta.created {
                let mut account = Account::new_eoa(*address, vec![0u8; 1312], vec![0u8; 1184]);
                account.balance = account_delta.new_balance;
                account.nonce = account_delta.new_nonce;
                self.accounts.insert(*address, account);
            } else if let Some(account) = self.accounts.get_mut(address) {
                account.balance = account_delta.new_balance;
                account.nonce = account_delta.new_nonce;
            }
        }

        for (address, storage_changes_map) in &delta.storage_changes {
            let storage_map = self.storage.entry(*address).or_insert_with(HashMap::new);
            for (key, storage_change) in storage_changes_map {
                storage_map.insert(key.clone(), storage_change.new_value.clone());
            }
        }

        for (address, nonce) in &delta.nonce_changes {
            self.nonces.insert(*address, *nonce);
        }

        for (address, contract_change) in &delta.contract_changes {
            if contract_change.deployed {
                self.contract_code
                    .insert(*address, contract_change.code.clone());
            }
        }

        for (chunk_id, triad) in &delta.triad_changes {
            self.triad_placements.insert(*chunk_id, triad.clone());
        }

        for (address, record) in &delta.drs_changes {
            self.drs_scores.insert(*address, record.clone());
        }

        self.state_root = self.compute_state_root();

        Ok(())
    }

    pub fn get_state_root(&self) -> Hash {
        self.state_root
    }

    pub fn set_state_root(&mut self, state_root: Hash) {
        self.state_root = state_root;
    }

    pub fn get_block_height(&self) -> u64 {
        self.block_height
    }

    pub fn increment_block_height(&mut self) {
        self.block_height += 1;
    }

    pub fn get_total_supply(&self) -> Balance {
        self.total_supply
    }

    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    pub fn get_epoch(&self) -> u64 {
        self.epoch
    }

    pub fn advance_epoch(&mut self) {
        self.epoch += 1;
        self.cleanup_expired_cross_shard();
        self.reset_epoch_quotas();
    }

    pub fn get_shard_id(&self) -> ShardId {
        self.shard_id
    }

    pub fn get_chain_id(&self) -> u32 {
        self.chain_id
    }

    pub fn get_network_id(&self) -> u32 {
        self.network_id
    }

    pub fn validate_state_transition(&self, transition: &StateTransition) -> RollupResult<bool> {
        if transition.from_state != self.state_root {
            return Ok(false);
        }

        if transition.changes.is_empty() {
            return Ok(false);
        }

        if transition.epoch < self.epoch {
            return Ok(false);
        }

        Ok(true)
    }

    pub fn checkpoint(&self) -> StateCheckpoint {
        StateCheckpoint {
            accounts: self.accounts.clone(),
            storage: self.storage.clone(),
            nonces: self.nonces.clone(),
            block_height: self.block_height,
            state_root: self.state_root,
            total_supply: self.total_supply,
            contract_code: self.contract_code.clone(),
            cross_shard_pending: self.cross_shard_pending.clone(),
            epoch: self.epoch,
            triad_placements: self.triad_placements.clone(),
            drs_scores: self.drs_scores.clone(),
            proof_history: self.proof_history.clone(),
            reward_claims: self.reward_claims.clone(),
            validator_metrics: self.validator_metrics.clone(),
        }
    }

    pub fn restore_checkpoint(&mut self, checkpoint: StateCheckpoint) {
        self.accounts = checkpoint.accounts;
        self.storage = checkpoint.storage;
        self.nonces = checkpoint.nonces;
        self.block_height = checkpoint.block_height;
        self.state_root = checkpoint.state_root;
        self.total_supply = checkpoint.total_supply;
        self.contract_code = checkpoint.contract_code;
        self.cross_shard_pending = checkpoint.cross_shard_pending;
        self.epoch = checkpoint.epoch;
        self.triad_placements = checkpoint.triad_placements;
        self.drs_scores = checkpoint.drs_scores;
        self.proof_history = checkpoint.proof_history;
        self.reward_claims = checkpoint.reward_claims;
        self.validator_metrics = checkpoint.validator_metrics;
    }

    pub fn create_snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            state_root: self.state_root,
            block_height: self.block_height,
            epoch: self.epoch,
            account_count: self.accounts.len(),
            total_supply: self.total_supply,
            timestamp: Timestamp::now(),
            shard_id: self.shard_id.as_u32(),
            pending_cross_shard: self.cross_shard_pending.len(),
            contract_count: self.contract_code.len(),
            total_storage_size: self.total_storage_size(),
            chain_id: self.chain_id,
            network_id: self.network_id,
        }
    }

    pub fn confirm_cross_shard_receipt(&mut self, receipt_hash: Hash) -> RollupResult<()> {
        if self.cross_shard_pending.remove(&receipt_hash).is_some() {
            Ok(())
        } else {
            Err(RollupError::StateError(
                "Cross-shard receipt not found".to_string(),
            ))
        }
    }

    fn cleanup_expired_cross_shard(&mut self) {
        let current_epoch = self.epoch;
        self.cross_shard_pending
            .retain(|_, pending| pending.deadline_epoch >= current_epoch);
    }

    fn reset_epoch_quotas(&mut self) {
        self.deploy_quotas.clear();
    }

    fn compute_contract_address(&self, deployer: Address, nonce: u64) -> Address {
        let mut data = Vec::new();
        data.extend_from_slice(deployer.as_bytes());
        data.extend_from_slice(&nonce.to_le_bytes());
        data.extend_from_slice(b"contract");
        data.extend_from_slice(&self.chain_id.to_le_bytes());

        let hash = ego_core::crypto::hash_data(&data);
        let mut addr_bytes = [0u8; 20];
        addr_bytes.copy_from_slice(&hash.as_bytes()[0..20]);
        Address::new(addr_bytes)
    }

    fn compute_contract_storage_root(&self, contract: Address) -> Hash {
        if let Some(storage_map) = self.storage.get(&contract) {
            let mut data = Vec::new();
            let mut sorted_entries: Vec<_> = storage_map.iter().collect();
            sorted_entries.sort_by_key(|(k, _)| *k);

            for (key, value) in sorted_entries {
                data.extend_from_slice(key);
                data.extend_from_slice(value);
            }

            ego_core::crypto::hash_data(&data)
        } else {
            Hash::ZERO
        }
    }

    pub fn get_cross_shard_pending(&self, receipt_hash: &Hash) -> Option<&CrossShardPending> {
        self.cross_shard_pending.get(receipt_hash)
    }

    pub fn pending_cross_shard_count(&self) -> usize {
        self.cross_shard_pending.len()
    }

    pub fn contract_count(&self) -> usize {
        self.contract_code.len()
    }

    pub fn is_contract(&self, address: Address) -> bool {
        self.contract_code.contains_key(&address)
    }

    pub fn total_storage_size(&self) -> usize {
        self.storage
            .values()
            .map(|m| m.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>())
            .sum()
    }

    pub fn get_drs_score(&self, address: &Address) -> Option<&DRSScoreRecord> {
        self.drs_scores.get(address)
    }

    pub fn get_proof_history(&self, address: &Address) -> Option<&ProofHistoryRecord> {
        self.proof_history.get(address)
    }

    pub fn get_validator_metrics(&self, address: &Address) -> Option<&ValidatorMetricsRecord> {
        self.validator_metrics.get(address)
    }

    pub fn get_triad_placement(&self, chunk_id: &Hash) -> Option<&TriadPlacementRecord> {
        self.triad_placements.get(chunk_id)
    }

    pub fn get_storage_deal(&self, chunk_id: &Hash) -> Option<&StorageDealRecord> {
        self.storage_deals.get(chunk_id)
    }

    pub fn get_pq_transition_state(&self) -> &PQTransitionState {
        &self.pq_transition_state
    }

    pub fn get_cellular_stats(&self) -> &CellularStatsState {
        &self.cellular_stats
    }
}

impl Default for RollupState {
    fn default() -> Self {
        Self::new(1, 1)
    }
}

impl StateTransition {
    pub fn new(
        from_state: Hash,
        to_state: Hash,
        transaction_hash: Hash,
        changes: Vec<RollupStateChange>,
        gas_used: u64,
        epoch: u64,
    ) -> Self {
        Self {
            from_state,
            to_state,
            transaction_hash,
            changes,
            gas_used,
            epoch,
            timestamp: Timestamp::now(),
        }
    }

    pub fn hash(&self) -> Hash {
        let config = bincode::config::standard();
        let encoded = bincode::encode_to_vec(self, config).unwrap_or_default();
        ego_core::crypto::hash_data(&encoded)
    }
}

impl StateDelta {
    pub fn new() -> Self {
        Self {
            account_changes: HashMap::new(),
            storage_changes: HashMap::new(),
            nonce_changes: HashMap::new(),
            contract_changes: HashMap::new(),
            cross_shard_changes: Vec::new(),
            triad_changes: HashMap::new(),
            drs_changes: HashMap::new(),
            proof_changes: HashMap::new(),
            reward_changes: HashMap::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.account_changes.is_empty()
            && self.storage_changes.is_empty()
            && self.nonce_changes.is_empty()
            && self.contract_changes.is_empty()
            && self.cross_shard_changes.is_empty()
            && self.triad_changes.is_empty()
            && self.drs_changes.is_empty()
            && self.proof_changes.is_empty()
            && self.reward_changes.is_empty()
    }

    pub fn merge(&mut self, other: StateDelta) {
        self.account_changes.extend(other.account_changes);
        for (addr, changes) in other.storage_changes {
            self.storage_changes
                .entry(addr)
                .or_insert_with(HashMap::new)
                .extend(changes);
        }
        self.nonce_changes.extend(other.nonce_changes);
        self.contract_changes.extend(other.contract_changes);
        self.cross_shard_changes.extend(other.cross_shard_changes);
        self.triad_changes.extend(other.triad_changes);
        self.drs_changes.extend(other.drs_changes);
        self.proof_changes.extend(other.proof_changes);
        self.reward_changes.extend(other.reward_changes);
    }
}

impl Default for StateDelta {
    fn default() -> Self {
        Self::new()
    }
}

impl ProofHistoryRecord {
    pub fn new() -> Self {
        Self {
            post_proofs_submitted: 0,
            porep_proofs_submitted: 0,
            poc_proofs_submitted: 0,
            post_pass_rate: 100.0,
            avg_latency_ms: 0,
            consecutive_misses: 0,
            last_proof_epoch: 0,
        }
    }
}

impl PQTransitionState {
    pub fn new() -> Self {
        Self {
            current_phase: 1,
            pq_required_topics: vec!["consensus".to_string()],
            legacy_support_end_epoch: None,
            algorithm_usage_stats: HashMap::new(),
            transition_start_epoch: 0,
        }
    }
}

impl CellularStatsState {
    pub fn new() -> Self {
        Self {
            total_cellular_bytes: 0,
            total_wifi_bytes: 0,
            cellular_safe_txs: 0,
            wifi_only_txs: 0,
            throttled_operations: 0,
        }
    }
}
