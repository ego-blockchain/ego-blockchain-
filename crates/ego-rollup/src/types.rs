use ego_core::{Address, Balance, DualSignature, Hash, ShardId, Timestamp, Transaction};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct RollupTransaction {
    pub inner: Transaction,
    pub rollup_nonce: u64,
    pub l1_block_number: u64,
    pub inclusion_proof: Option<Vec<u8>>,
    pub cross_shard_receipt: Option<CrossShardReceipt>,
    pub ru_limit: u64,
    pub ru_estimate: u64,
    pub pob_burn_credits: u64,
    pub priority_hint: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct CrossShardReceipt {
    pub receipt_hash: Hash,
    pub src_shard: ShardId,
    pub dst_shard: ShardId,
    pub src_block_hash: Hash,
    pub tx_id: Hash,
    pub payload: CrossShardPayload,
    pub nonce: u64,
    pub deadline_epoch: u64,
    pub merkle_proof: Vec<Hash>,
    pub status: CrossShardStatus,
    pub created_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum CrossShardPayload {
    Transfer {
        from: Address,
        to: Address,
        amount: Balance,
        asset: Address,
    },
    ContractCall {
        from: Address,
        contract: Address,
        data: Vec<u8>,
        value: Balance,
    },
    Message {
        from: Address,
        to: Address,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub enum CrossShardStatus {
    Pending,
    Committed,
    Verified,
    Failed,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct RollupBlock {
    pub block_number: u64,
    pub parent_hash: Hash,
    pub state_root: Hash,
    pub transactions_root: Hash,
    pub receipts_root: Hash,
    pub events_root_post: Hash,
    pub events_root_poc: Hash,
    pub rollup_root: Hash,
    pub da_root: Hash,
    pub timestamp: Timestamp,
    pub transactions: Vec<RollupTransaction>,
    pub operator: Address,
    pub signature: DualSignature,
    pub chain_id: u32,
    pub network_id: u32,
    pub shard_id: ShardId,
    pub epoch: u64,
    pub protocol_version: u32,
    pub gas_used: u64,
    pub gas_limit: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct RollupExecutionResult {
    pub tx_hash: Hash,
    pub success: bool,
    pub ru_used: u64,
    pub state_changes: Vec<StateChange>,
    pub events: Vec<RollupEvent>,
    pub error: Option<String>,
    pub gas_refund: u64,
    pub logs_bloom: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum StateChange {
    BalanceUpdate {
        address: Address,
        old_balance: Balance,
        new_balance: Balance,
    },
    ContractDeployed {
        address: Address,
        code_hash: Hash,
    },
    Staked {
        address: Address,
        amount: Balance,
    },
    Unstaked {
        address: Address,
        amount: Balance,
    },
    Burned {
        address: Address,
        amount: Balance,
    },
    CrossShardInitiated {
        from: Address,
        target_shard: u32,
        receipt_hash: Hash,
    },
    StorageUpdate {
        address: Address,
        key: Vec<u8>,
        old_value: Option<Vec<u8>>,
        new_value: Vec<u8>,
    },
    NonceUpdate {
        address: Address,
        old_nonce: u64,
        new_nonce: u64,
    },
    CodeUpdate {
        address: Address,
        code_hash: Hash,
    },
    AccountCreation {
        address: Address,
    },
    AccountDeletion {
        address: Address,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub enum StateChangeType {
    StorageUpdate,
    BalanceUpdate,
    NonceUpdate,
    CodeUpdate,
    AccountCreation,
    AccountDeletion,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct RollupEvent {
    pub address: Address,
    pub topics: Vec<Hash>,
    pub data: Vec<u8>,
    pub event_type: EventType,
    pub tx_hash: Hash,
    pub block_number: u64,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub enum EventType {
    Transfer,
    Approval,
    Deposit,
    Withdrawal,
    ContractDeployed,
    ContractCalled,
    CrossShardMessage,
    ProofSubmitted,
    ChallengeCreated,
    ChallengeResolved,
    DRSScoreUpdated,
    PoCBeaconEmitted,
    PoCWitnessReported,
    PoStProofSubmitted,
    PoRepProofSubmitted,
    StorageDealCreated,
    Custom(String),
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
    pub drs_score: f64,
    pub avg_latency_ms: u64,
    pub total_ru_processed: u64,
    pub cellular_safe_batches: u64,
    pub five_g_optimized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct LightClientProof {
    pub commitment_hash: Hash,
    pub state_root: Hash,
    pub inclusion_proof: Vec<Hash>,
    pub da_proof: Vec<u8>,
    pub block_header: Vec<u8>,
    pub qc_proof: Option<QCProof>,
    pub epoch: u64,
    pub shard_id: ShardId,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct QCProof {
    pub validator_set_id: u64,
    pub round: u64,
    pub bitmap: Vec<u8>,
    pub sigs_root: Hash,
    pub alg_sig_id: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct WithdrawalRequest {
    pub request_id: Hash,
    pub user: Address,
    pub amount: Balance,
    pub asset: Address,
    pub l1_recipient: Address,
    pub rollup_block: u64,
    pub inclusion_proof: Vec<Hash>,
    pub status: WithdrawalStatus,
    pub created_at: Timestamp,
    pub finalized_at: Option<Timestamp>,
    pub challenge_period: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub enum WithdrawalStatus {
    Pending,
    Challenged,
    ReadyToFinalize,
    Finalized,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DRSScoreEvent {
    pub node_id: Address,
    pub period: u64,
    pub score_f32: f32,
    pub evidence_root: Hash,
    pub weights_version: u16,
    pub signature: DualSignature,
    pub timestamp: Timestamp,
    pub inputs: DRSInputs,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DRSInputs {
    pub post_pass_ratio: f32,
    pub post_latency_ms: u64,
    pub poc_quality: f32,
    pub serve_ratio: f32,
    pub uptime_ratio: f32,
    pub penalties: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PoCEvent {
    pub beacon_hash: Hash,
    pub witness_hashes: Vec<Hash>,
    pub agg_digest: Hash,
    pub poc_quality_fp16: u16,
    pub region_id: u32,
    pub epoch: u64,
    pub cid_hint: Option<String>,
    pub aggregator_sig: DualSignature,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PoCBeacon {
    pub beacon_id: Hash,
    pub node_addr: Address,
    pub h3_cell: u64,
    pub arfcn: u32,
    pub bandwidth: u16,
    pub tx_power_dbm: i8,
    pub time_ms: u64,
    pub challenge_nonce: [u8; 16],
    pub signature: DualSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PoCWitness {
    pub beacon_id: Hash,
    pub witness_addr: Address,
    pub time_ms: u64,
    pub gnss: GNSSLocation,
    pub rsrp_dbm: i8,
    pub rsrq_db: i8,
    pub sinr_db: i8,
    pub timing_advance: Option<u16>,
    pub arfcn: u32,
    pub pci: u16,
    pub co_beacon_nonce: Option<[u8; 16]>,
    pub device_fingerprint: [u8; 16],
    pub signature: DualSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct GNSSLocation {
    pub lat_i32: i32,
    pub lon_i32: i32,
    pub alt_i16: i16,
    pub dop_u16: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PoStEvent {
    pub node_addr: Address,
    pub epoch: u64,
    pub window_id: u64,
    pub partitions_covered: Vec<u32>,
    pub challenges_root: Hash,
    pub post_agg_proof_hash: Hash,
    pub result: PoStResult,
    pub latency_ms: u64,
    pub alg_sig_id: u8,
    pub node_sig: DualSignature,
    pub cid_hint: Option<String>,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub enum PoStResult {
    Pass,
    Partial { failed_partitions: Vec<u32> },
    Miss,
    Fault,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PoRepEvent {
    pub deal_id: Vec<Hash>,
    pub sector_id: Hash,
    pub node_addr: Address,
    pub replica_id: Hash,
    pub comm_d: Hash,
    pub comm_r: Hash,
    pub porep_params_v: u32,
    pub proof_hash: Hash,
    pub cid_hint: Option<String>,
    pub alg_sig_id: u8,
    pub node_sig: DualSignature,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct StorageDeal {
    pub deal_id: Hash,
    pub client_addr: Address,
    pub size_bytes: u64,
    pub duration_epochs: u64,
    pub price_rate: u64,
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub triad: [TriadMember; 3],
    pub escrow: Balance,
    pub params_hash: Hash,
    pub status: StorageDealStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct TriadMember {
    pub node_addr: Address,
    pub sector_ids: Vec<Hash>,
    pub role: TriadRole,
    pub health: TriadHealth,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub enum TriadRole {
    Primary,
    ReplicaA,
    ReplicaB,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct TriadHealth {
    pub pass_ratio: f32,
    pub consecutive_misses: u32,
    pub last_seen_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub enum StorageDealStatus {
    Pending,
    Active,
    Expired,
    Terminated,
    Slashed,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DeployPolicy {
    pub free_staker_quota: u32,
    pub pob_deploy_credits_per_kb: u64,
    pub deploy_bond: Balance,
    pub max_deploys_per_epoch: u32,
    pub dedup_window_epochs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DeployRequest {
    pub deployer: Address,
    pub code_hash: Hash,
    pub code_size_bytes: u64,
    pub ru_estimate: u64,
    pub pob_credits_burned: u64,
    pub bond_amount: Balance,
    pub epoch: u64,
    pub signature: DualSignature,
    pub status: DeployStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub enum DeployStatus {
    Requested,
    Accepted,
    Rejected { reason: String },
    Deployed { contract_addr: Address },
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct RepairEvent {
    pub deal_id: Hash,
    pub old_replica_id: Hash,
    pub new_node_addr: Address,
    pub new_replica_id: Hash,
    pub source_replica_id: Hash,
    pub comm_r_new: Hash,
    pub porep_proof_hash: Hash,
    pub reason: RepairReason,
    pub node_sig: DualSignature,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub enum RepairReason {
    NodeOffline,
    ConsecutiveMisses,
    FailedAudit,
    PromotionToPrimary,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DensityEvent {
    pub node_id: Address,
    pub h3_cell: u64,
    pub device_count: u32,
    pub ldm: f32,
    pub evidence_root: Hash,
    pub epoch: u64,
    pub timestamp: Timestamp,
}

impl RollupTransaction {
    pub fn new(inner: Transaction, rollup_nonce: u64, l1_block_number: u64) -> Self {
        let ru_estimate = inner.estimate_resource_units();

        Self {
            inner,
            rollup_nonce,
            l1_block_number,
            inclusion_proof: None,
            cross_shard_receipt: None,
            ru_limit: ru_estimate + 10000,
            ru_estimate,
            pob_burn_credits: 0,
            priority_hint: 0,
        }
    }

    pub fn with_cross_shard_receipt(mut self, receipt: CrossShardReceipt) -> Self {
        self.cross_shard_receipt = Some(receipt);
        self
    }

    pub fn with_ru_limit(mut self, ru_limit: u64) -> Self {
        self.ru_limit = ru_limit;
        self
    }

    pub fn with_pob_credits(mut self, pob_burn_credits: u64) -> Self {
        self.pob_burn_credits = pob_burn_credits;
        self
    }

    pub fn with_priority(mut self, priority_hint: u8) -> Self {
        self.priority_hint = priority_hint;
        self
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

    pub fn is_cross_shard(&self) -> bool {
        self.cross_shard_receipt.is_some()
    }

    pub fn requires_pob_credits(&self) -> bool {
        self.pob_burn_credits > 0
    }

    pub fn verify_ru_limit(&self) -> bool {
        self.ru_estimate <= self.ru_limit
    }

    pub fn is_cellular_safe(&self) -> bool {
        self.size() <= 10 * 1024
    }
}

impl CrossShardReceipt {
    pub fn new(
        src_shard: ShardId,
        dst_shard: ShardId,
        src_block_hash: Hash,
        tx_id: Hash,
        payload: CrossShardPayload,
        nonce: u64,
        deadline_epoch: u64,
    ) -> Self {
        let receipt_hash = Self::compute_receipt_hash(
            src_shard,
            dst_shard,
            src_block_hash,
            tx_id,
            &payload,
            nonce,
        );

        Self {
            receipt_hash,
            src_shard,
            dst_shard,
            src_block_hash,
            tx_id,
            payload,
            nonce,
            deadline_epoch,
            merkle_proof: Vec::new(),
            status: CrossShardStatus::Pending,
            created_at: Timestamp::now(),
        }
    }

    fn compute_receipt_hash(
        src_shard: ShardId,
        dst_shard: ShardId,
        src_block_hash: Hash,
        tx_id: Hash,
        payload: &CrossShardPayload,
        nonce: u64,
    ) -> Hash {
        let config = bincode::config::standard();
        let payload_bytes = bincode::encode_to_vec(payload, config).unwrap_or_default();

        ego_core::crypto::hash_multiple(&[
            b"ego/cross-shard/v1",
            &src_shard.as_u32().to_le_bytes(),
            &dst_shard.as_u32().to_le_bytes(),
            src_block_hash.as_bytes(),
            tx_id.as_bytes(),
            &payload_bytes,
            &nonce.to_le_bytes(),
        ])
    }

    pub fn verify(&self) -> bool {
        let computed_hash = Self::compute_receipt_hash(
            self.src_shard,
            self.dst_shard,
            self.src_block_hash,
            self.tx_id,
            &self.payload,
            self.nonce,
        );

        computed_hash == self.receipt_hash
    }

    pub fn is_expired(&self, current_epoch: u64) -> bool {
        current_epoch > self.deadline_epoch
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
        chain_id: u32,
        network_id: u32,
        shard_id: ShardId,
        epoch: u64,
    ) -> Self {
        let transactions_root = Self::compute_transactions_root(&transactions);

        Self {
            block_number,
            parent_hash,
            state_root: Hash::ZERO,
            transactions_root,
            receipts_root: Hash::ZERO,
            events_root_post: Hash::ZERO,
            events_root_poc: Hash::ZERO,
            rollup_root: Hash::ZERO,
            da_root: Hash::ZERO,
            timestamp: Timestamp::now(),
            transactions,
            operator,
            signature: DualSignature::new(None, None),
            chain_id,
            network_id,
            shard_id,
            epoch,
            protocol_version: ego_core::PROTOCOL_VERSION,
            gas_used: 0,
            gas_limit: 10_000_000,
        }
    }

    pub fn hash(&self) -> Hash {
        let config = bincode::config::standard();
        let mut block_copy = self.clone();
        block_copy.signature = DualSignature::new(None, None);

        let data = bincode::encode_to_vec(&block_copy, config).unwrap_or_default();
        ego_core::crypto::hash_data(&data)
    }

    pub fn sign(&mut self, keypair: &ego_core::crypto::KeyPair) -> Result<(), ego_core::EgoError> {
        let hash = self.hash();
        self.signature = keypair.sign_hybrid(hash.as_bytes(), false);
        Ok(())
    }

    pub fn verify_signature(
        &self,
        public_key: &ego_core::PublicKey,
    ) -> Result<bool, ego_core::EgoError> {
        let hash = self.hash();

        if let Some(ref dilithium_sig) = self.signature.dilithium_sig {
            return ego_core::crypto::verify_signature(public_key, hash.as_bytes(), dilithium_sig);
        }

        if let Some(ref ed25519_sig) = self.signature.ed25519_sig {
            return Ok(ed25519_sig.signature_data.len() == 64);
        }

        Ok(false)
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

    pub fn is_cellular_safe(&self) -> bool {
        self.size() <= 512 * 1024 && self.transactions.len() <= 500
    }

    pub fn is_5g_optimized(&self) -> bool {
        self.size() <= 1024 * 1024 && self.transactions.len() <= 1000
    }

    pub fn compute_receipts_root(&self, receipts: &[RollupExecutionResult]) -> Hash {
        if receipts.is_empty() {
            return Hash::ZERO;
        }

        let config = bincode::config::standard();
        let receipt_hashes: Vec<Vec<u8>> = receipts
            .iter()
            .filter_map(|r| bincode::encode_to_vec(r, config).ok())
            .collect();

        let merkle_tree = ego_core::crypto::MerkleTree::build(receipt_hashes);
        merkle_tree.root_hash().unwrap_or(Hash::ZERO)
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
            drs_score: 1.0,
            avg_latency_ms: 0,
            total_ru_processed: 0,
            cellular_safe_batches: 0,
            five_g_optimized: false,
        }
    }
}

impl OperatorInfo {
    pub fn update_stats(&mut self, commits: u64, latency_ms: u64, ru_processed: u64) {
        self.total_commits += commits;
        self.total_ru_processed += ru_processed;

        if self.avg_latency_ms == 0 {
            self.avg_latency_ms = latency_ms;
        } else {
            self.avg_latency_ms = (self.avg_latency_ms + latency_ms) / 2;
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.is_active && self.reputation_score > 0.7 && self.slash_count < 3
    }
}

impl DRSScoreEvent {
    pub fn new(node_id: Address, period: u64, inputs: DRSInputs, weights_version: u16) -> Self {
        let score = Self::calculate_score(&inputs);
        let evidence_root = Self::compute_evidence_root(&inputs);

        Self {
            node_id,
            period,
            score_f32: score,
            evidence_root,
            weights_version,
            signature: DualSignature::new(None, None),
            timestamp: Timestamp::now(),
            inputs,
        }
    }

    fn calculate_score(inputs: &DRSInputs) -> f32 {
        let post_weight = 0.3;
        let poc_weight = 0.3;
        let serve_weight = 0.2;
        let uptime_weight = 0.2;

        let post_score =
            inputs.post_pass_ratio * (1.0 - (inputs.post_latency_ms as f32 / 1000.0).min(0.5));
        let poc_score = inputs.poc_quality;
        let serve_score = inputs.serve_ratio;
        let uptime_score = inputs.uptime_ratio;

        let base_score = post_weight * post_score
            + poc_weight * poc_score
            + serve_weight * serve_score
            + uptime_weight * uptime_score;

        let penalty = inputs.penalties as f32 * 0.05;

        (base_score - penalty).max(0.0).min(1.5)
    }

    fn compute_evidence_root(inputs: &DRSInputs) -> Hash {
        let config = bincode::config::standard();
        let data = bincode::encode_to_vec(inputs, config).unwrap_or_default();
        ego_core::crypto::hash_data(&data)
    }

    pub fn sign(&mut self, keypair: &ego_core::crypto::KeyPair) -> Result<(), ego_core::EgoError> {
        let signing_data = self.create_signing_data();
        self.signature = keypair.sign_hybrid(&signing_data, false);
        Ok(())
    }

    fn create_signing_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"ego/drs/v1");
        data.extend_from_slice(self.node_id.as_bytes());
        data.extend_from_slice(&self.period.to_le_bytes());
        data.extend_from_slice(&self.score_f32.to_le_bytes());
        data.extend_from_slice(self.evidence_root.as_bytes());
        data.extend_from_slice(&self.weights_version.to_le_bytes());
        ego_core::crypto::blake2s_hash(&data)
    }
}

impl PoCEvent {
    pub fn new(
        beacon_hash: Hash,
        witness_hashes: Vec<Hash>,
        poc_quality_fp16: u16,
        region_id: u32,
        epoch: u64,
    ) -> Self {
        let agg_digest = Self::compute_aggregate_digest(&beacon_hash, &witness_hashes);

        Self {
            beacon_hash,
            witness_hashes,
            agg_digest,
            poc_quality_fp16,
            region_id,
            epoch,
            cid_hint: None,
            aggregator_sig: DualSignature::new(None, None),
            timestamp: Timestamp::now(),
        }
    }

    fn compute_aggregate_digest(beacon_hash: &Hash, witness_hashes: &[Hash]) -> Hash {
        let mut data = beacon_hash.to_vec();
        for witness_hash in witness_hashes {
            data.extend_from_slice(witness_hash.as_bytes());
        }
        ego_core::crypto::hash_data(&data)
    }

    pub fn quality_score(&self) -> f32 {
        let fp16_value = self.poc_quality_fp16 as f32;
        fp16_value / 65535.0
    }
}

impl PoStEvent {
    pub fn new(
        node_addr: Address,
        epoch: u64,
        window_id: u64,
        partitions_covered: Vec<u32>,
        challenges_root: Hash,
        post_agg_proof_hash: Hash,
        result: PoStResult,
        latency_ms: u64,
    ) -> Self {
        Self {
            node_addr,
            epoch,
            window_id,
            partitions_covered,
            challenges_root,
            post_agg_proof_hash,
            result,
            latency_ms,
            alg_sig_id: 1,
            node_sig: DualSignature::new(None, None),
            cid_hint: None,
            timestamp: Timestamp::now(),
        }
    }

    pub fn is_successful(&self) -> bool {
        matches!(self.result, PoStResult::Pass)
    }

    pub fn is_partial(&self) -> bool {
        matches!(self.result, PoStResult::Partial { .. })
    }
}

impl PoRepEvent {
    pub fn new(
        deal_id: Vec<Hash>,
        sector_id: Hash,
        node_addr: Address,
        replica_id: Hash,
        comm_d: Hash,
        comm_r: Hash,
        porep_params_v: u32,
        proof_hash: Hash,
    ) -> Self {
        Self {
            deal_id,
            sector_id,
            node_addr,
            replica_id,
            comm_d,
            comm_r,
            porep_params_v,
            proof_hash,
            cid_hint: None,
            alg_sig_id: 1,
            node_sig: DualSignature::new(None, None),
            timestamp: Timestamp::now(),
        }
    }
}

impl StorageDeal {
    pub fn new(
        client_addr: Address,
        size_bytes: u64,
        duration_epochs: u64,
        price_rate: u64,
        start_epoch: u64,
        triad: [TriadMember; 3],
    ) -> Self {
        let deal_id = Self::compute_deal_id(client_addr, size_bytes, start_epoch);
        let end_epoch = start_epoch + duration_epochs;
        let escrow = Balance::from_uegoc((price_rate * duration_epochs) as u128);

        Self {
            deal_id,
            client_addr,
            size_bytes,
            duration_epochs,
            price_rate,
            start_epoch,
            end_epoch,
            triad,
            escrow,
            params_hash: Hash::ZERO,
            status: StorageDealStatus::Pending,
        }
    }

    fn compute_deal_id(client_addr: Address, size_bytes: u64, start_epoch: u64) -> Hash {
        ego_core::crypto::hash_multiple(&[
            b"ego/storage-deal/v1",
            client_addr.as_bytes(),
            &size_bytes.to_le_bytes(),
            &start_epoch.to_le_bytes(),
            &Timestamp::now().as_millis().to_le_bytes(),
        ])
    }

    pub fn is_active(&self, current_epoch: u64) -> bool {
        self.status == StorageDealStatus::Active
            && current_epoch >= self.start_epoch
            && current_epoch < self.end_epoch
    }
}

impl WithdrawalRequest {
    pub fn new(
        user: Address,
        amount: Balance,
        asset: Address,
        l1_recipient: Address,
        rollup_block: u64,
        challenge_period: u64,
    ) -> Self {
        let request_id = Self::compute_request_id(user, amount, rollup_block);

        Self {
            request_id,
            user,
            amount,
            asset,
            l1_recipient,
            rollup_block,
            inclusion_proof: Vec::new(),
            status: WithdrawalStatus::Pending,
            created_at: Timestamp::now(),
            finalized_at: None,
            challenge_period,
        }
    }

    fn compute_request_id(user: Address, amount: Balance, rollup_block: u64) -> Hash {
        ego_core::crypto::hash_multiple(&[
            b"ego/withdrawal/v1",
            user.as_bytes(),
            &amount.to_uegoc().to_le_bytes(),
            &rollup_block.to_le_bytes(),
        ])
    }

    pub fn can_finalize(&self, current_block: u64) -> bool {
        self.status == WithdrawalStatus::ReadyToFinalize
            && current_block >= self.rollup_block + self.challenge_period
    }
}

impl DeployPolicy {
    pub fn default() -> Self {
        Self {
            free_staker_quota: 5,
            pob_deploy_credits_per_kb: 1000,
            deploy_bond: Balance::from_egoc(1),
            max_deploys_per_epoch: 100,
            dedup_window_epochs: 10,
        }
    }

    pub fn calculate_credits_needed(&self, code_size_bytes: u64) -> u64 {
        let kb = (code_size_bytes + 1023) / 1024;
        kb * self.pob_deploy_credits_per_kb
    }
}
