use ego_core::{
    Account, Address, AlgorithmId, Balance, BlockHeight, DualSignature, EgoError, EgoResult, Hash,
    PublicKey, ShardId, Timestamp, Transaction, TransactionPayload,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub const DOMAIN_TAG_ROLLUP_COMMIT: &[u8] = b"ego/proof-rollup/commit/v1";
pub const DOMAIN_TAG_POC_BEACON: &[u8] = b"ego/poc/beacon/v1";
pub const DOMAIN_TAG_POC_WITNESS: &[u8] = b"ego/poc/witness/v1";
pub const DOMAIN_TAG_POST_PROOF: &[u8] = b"ego/post/proof/v1";
pub const DOMAIN_TAG_POREP_PROOF: &[u8] = b"ego/porep/proof/v1";
pub const DOMAIN_TAG_EVIDENCE_BUNDLE: &[u8] = b"ego/evidence/bundle/v1";
pub const DOMAIN_TAG_AI_VERIFICATION: &[u8] = b"ego/ai-verify/v1";

pub const MAX_BUNDLE_SIZE_CELLULAR: usize = 512 * 1024;
pub const MAX_BUNDLE_SIZE_WIFI: usize = 10 * 1024 * 1024;
pub const DEFAULT_ANCHOR_WINDOW_HOURS: u64 = 24;
pub const COMPRESSION_LEVEL_CELLULAR: i32 = 6;
pub const COMPRESSION_LEVEL_WIFI: i32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ProofRollupCommit {
    pub rollup_id: [u8; 16],
    pub region_id: u32,
    pub epoch: u64,
    pub window_id: u32,
    pub proofs_root: Hash,
    pub da_root: Hash,
    pub count_proofs: u32,
    pub blob_bytes: u64,
    pub min_validity_proof: MinValidityProof,
    pub operator_addr: Address,
    pub operator_sig: DualSignature,
    pub chain_id: u32,
    pub network_id: u32,
    pub created_at: Timestamp,
    pub commitment_hash: Hash,
    pub human_verified_count: u32,
    pub ai_flagged_count: u32,
    pub drs_weighted_quality: f64,
    pub cellular_friendly: bool,
}

#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, bincode::Encode, bincode::Decode, PartialEq, Eq,
)]
pub enum MinValidityProof {
    None = 0,
    InclusionOnly = 1,
    StateWitness = 2,
    CircuitProof = 3,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PoCEvidence {
    pub beacon_announcements: Vec<BeaconAnnouncement>,
    pub witness_reports: Vec<WitnessReport>,
    pub coherence_stats: CoherenceStats,
    pub thresholds_used: ThresholdParams,
    pub density_events: Vec<DensityEventData>,
    pub timestamp: Timestamp,
    pub human_verified: bool,
    pub ai_pattern_detected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct BeaconAnnouncement {
    pub device_id: [u8; 32],
    pub node_addr: Address,
    pub location_hash: Hash,
    pub signal_strength_dbm: i16,
    pub frequency_mhz: u32,
    pub h3_cell: u64,
    pub timestamp: Timestamp,
    pub dilithium_pk: Vec<u8>,
    pub dilithium_sig: Vec<u8>,
    pub drs_score: f64,
    pub density_penalty_applied: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct WitnessReport {
    pub witness_id: [u8; 32],
    pub witness_addr: Address,
    pub beacon_id: [u8; 32],
    pub rsrp_dbm: i16,
    pub rsrq_db: i16,
    pub sinr_db: i16,
    pub timing_advance: u16,
    pub distance_meters: u32,
    pub gnss_lat: i32,
    pub gnss_lon: i32,
    pub h3_cell: u64,
    pub timestamp: Timestamp,
    pub dilithium_pk: Vec<u8>,
    pub dilithium_sig: Vec<u8>,
    pub drs_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct CoherenceStats {
    pub total_beacons: u32,
    pub total_witnesses: u32,
    pub valid_reports: u32,
    pub invalid_reports: u32,
    pub coherence_score: f64,
    pub path_loss_rmse: f64,
    pub diversity_score: f64,
    pub avg_drs_multiplier: f64,
    pub density_penalties_applied: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ThresholdParams {
    pub min_witnesses: u32,
    pub max_distance_meters: u32,
    pub min_signal_strength_dbm: i16,
    pub max_path_loss_rmse: f64,
    pub min_drs_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DensityEventData {
    pub node_id: Address,
    pub h3_cell: u64,
    pub device_count: u32,
    pub density_multiplier: f64,
    pub dwell_time_pct: f64,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PoStEvidence {
    pub partition_indices: Vec<u32>,
    pub window_post_proofs: Vec<WindowPoStProof>,
    pub partition_maps: HashMap<u32, PartitionInfo>,
    pub prover_stats: ProverStats,
    pub timestamp: Timestamp,
    pub human_verified: bool,
    pub ai_pattern_detected: bool,
    pub node_drs_scores: HashMap<Address, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct WindowPoStProof {
    pub partition_id: u32,
    pub challenge_seed: [u8; 32],
    pub proof_bytes: Vec<u8>,
    pub replica_ids: Vec<[u8; 32]>,
    pub sector_count: u32,
    pub challenged_sectors: Vec<u32>,
    pub dilithium_pk: Vec<u8>,
    pub dilithium_sig: Vec<u8>,
    pub node_addr: Address,
    pub latency_ms: u32,
    pub drs_multiplier: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PartitionInfo {
    pub partition_id: u32,
    pub sector_count: u32,
    pub proven_sectors: u32,
    pub deadline: Timestamp,
    pub sla_met: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ProverStats {
    pub total_sectors: u64,
    pub proven_sectors: u64,
    pub failed_proofs: u64,
    pub avg_proof_time_ms: u64,
    pub pass_ratio: f64,
    pub sla_compliance_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct EvidenceBundle {
    pub bundle_id: Hash,
    pub bundle_type: EvidenceBundleType,
    pub poc_evidence: Vec<PoCEvidence>,
    pub post_evidence: Vec<PoStEvidence>,
    pub porep_proofs: Vec<PoRepProof>,
    pub compressed_data: Vec<u8>,
    pub original_size: u64,
    pub compression_ratio: f64,
    pub cid: String,
    pub created_at: Timestamp,
    pub human_verified_count: u32,
    pub ai_flagged_count: u32,
    pub drs_quality_weighted: f64,
    pub deploy_credits_consumed: u64,
    pub cellular_optimized: bool,
}

#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, bincode::Encode, bincode::Decode, PartialEq, Eq,
)]
pub enum EvidenceBundleType {
    PoC,
    PoSt,
    PoRep,
    Combined,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PoRepProof {
    pub sector_id: [u8; 32],
    pub proof_bytes: Vec<u8>,
    pub comm_r: [u8; 32],
    pub comm_d: [u8; 32],
    pub replica_id: [u8; 32],
    pub porep_params_v: u32,
    pub dilithium_pk: Vec<u8>,
    pub dilithium_sig: Vec<u8>,
    pub node_addr: Address,
    pub seal_time_ms: u64,
    pub drs_score: f64,
}

pub struct ProofRollupOperator {
    config: RollupConfig,
    rollup_id: [u8; 16],
    region_id: u32,
    operator_addr: Address,
    keypair: Arc<ego_core::crypto::KeyPair>,
    pending_poc: Arc<RwLock<Vec<PoCEvidence>>>,
    pending_post: Arc<RwLock<Vec<PoStEvidence>>>,
    pending_porep: Arc<RwLock<Vec<PoRepProof>>>,
    evidence_bundles: Arc<RwLock<HashMap<Hash, EvidenceBundle>>>,
    da_manager: Arc<RwLock<DataAvailability>>,
    commitments: Arc<RwLock<HashMap<Hash, ProofRollupCommit>>>,
    metrics: Arc<RwLock<ProofRollupMetrics>>,
    current_epoch: Arc<RwLock<u64>>,
    current_window: Arc<RwLock<u32>>,
    anchor_window_hours: u64,
    cellular_safe_mode: bool,
    ai_pattern_detector: Arc<RwLock<AIPatternDetector>>,
    drs_integration: Arc<RwLock<DRSIntegration>>,
    deploy_policy_enforcer: Arc<RwLock<DeployPolicyEnforcer>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProofRollupMetrics {
    pub poc_events_received: u64,
    pub post_events_received: u64,
    pub porep_events_received: u64,
    pub evidence_bundles_created: u64,
    pub commitments_posted: u64,
    pub total_proofs_aggregated: u64,
    pub total_blob_bytes: u64,
    pub avg_bundle_size: u64,
    pub dilithium_signatures_verified: u64,
    pub signature_verification_failures: u64,
    pub compression_ratio: f64,
    pub cellular_data_used_mb: u64,
    pub wifi_data_used_mb: u64,
    pub beacon_count: u64,
    pub witness_count: u64,
    pub partition_count: u64,
    pub sector_proven_count: u64,
    pub human_verified_proofs: u64,
    pub ai_flagged_proofs: u64,
    pub drs_penalties_applied: u64,
    pub density_penalties_applied: u64,
    pub deploy_credits_consumed_total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollupConfig {
    pub rollup_id: String,
    pub chain_id: u32,
    pub network_id: u32,
    pub da: DaConfig,
    pub five_g: FiveGConfig,
    pub ai_verification: AIVerificationConfig,
    pub drs_integration: DRSIntegrationConfig,
    pub deploy_policy: DeployPolicyConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaConfig {
    pub k: u16,
    pub m: u16,
    pub chunk_size: usize,
    pub enable_compression: bool,
    pub compression_level_wifi: i32,
    pub compression_level_cellular: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiveGConfig {
    pub cellular_safe_mode: bool,
    pub max_bundle_size_cellular: usize,
    pub max_bundle_size_wifi: usize,
    pub batch_delay_cellular_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIVerificationConfig {
    pub enabled: bool,
    pub require_human_verification: bool,
    pub auto_reject_ai_patterns: bool,
    pub suspicious_phrases: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DRSIntegrationConfig {
    pub enabled: bool,
    pub min_drs_score: f64,
    pub apply_drs_weights: bool,
    pub density_penalty_rate: f64,
    pub density_min_multiplier: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployPolicyConfig {
    pub enabled: bool,
    pub credits_per_kb_evidence: u64,
    pub credits_per_proof: u64,
    pub require_quota: bool,
}

impl Default for RollupConfig {
    fn default() -> Self {
        Self {
            rollup_id: "ego-rollup-1".to_string(),
            chain_id: 1,
            network_id: 1,
            da: DaConfig {
                k: 64,
                m: 32,
                chunk_size: 32768,
                enable_compression: true,
                compression_level_wifi: COMPRESSION_LEVEL_WIFI,
                compression_level_cellular: COMPRESSION_LEVEL_CELLULAR,
            },
            five_g: FiveGConfig {
                cellular_safe_mode: true,
                max_bundle_size_cellular: MAX_BUNDLE_SIZE_CELLULAR,
                max_bundle_size_wifi: MAX_BUNDLE_SIZE_WIFI,
                batch_delay_cellular_ms: 5000,
            },
            ai_verification: AIVerificationConfig {
                enabled: true,
                require_human_verification: false,
                auto_reject_ai_patterns: true,
                suspicious_phrases: vec![
                    "do you want me to add more".to_string(),
                    "let me know if you need".to_string(),
                    "as an ai model".to_string(),
                    "i can help you with".to_string(),
                    "would you like me to".to_string(),
                    "is there anything else".to_string(),
                    "chatgpt".to_string(),
                    "claude".to_string(),
                    "generated by ai".to_string(),
                ],
            },
            drs_integration: DRSIntegrationConfig {
                enabled: true,
                min_drs_score: 0.3,
                apply_drs_weights: true,
                density_penalty_rate: 0.10,
                density_min_multiplier: 0.40,
            },
            deploy_policy: DeployPolicyConfig {
                enabled: true,
                credits_per_kb_evidence: 50,
                credits_per_proof: 10,
                require_quota: false,
            },
        }
    }
}

pub struct DataAvailability {
    k: usize,
    m: usize,
    chunk_size: usize,
    enable_compression: bool,
    compression_level_wifi: i32,
    compression_level_cellular: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DAChunk {
    pub chunk_id: u32,
    pub chunk_hash: Hash,
    pub data: Vec<u8>,
    pub parity: bool,
    pub rollup_id: String,
    pub operator: Address,
    pub epoch: u64,
}

pub struct AIPatternDetector {
    enabled: bool,
    suspicious_phrases: Vec<String>,
    require_human_verification: bool,
    auto_reject: bool,
}

pub struct DRSIntegration {
    enabled: bool,
    min_drs_score: f64,
    apply_weights: bool,
    density_penalty_rate: f64,
    density_min_multiplier: f64,
}

pub struct DeployPolicyEnforcer {
    enabled: bool,
    credits_per_kb: u64,
    credits_per_proof: u64,
    require_quota: bool,
}

impl DataAvailability {
    pub fn new(
        k: usize,
        m: usize,
        chunk_size: usize,
        enable_compression: bool,
        compression_level_wifi: i32,
        compression_level_cellular: i32,
    ) -> EgoResult<Self> {
        Ok(Self {
            k,
            m,
            chunk_size,
            enable_compression,
            compression_level_wifi,
            compression_level_cellular,
        })
    }

    pub fn encode_data(
        &mut self,
        bundle_id: Hash,
        data: Vec<u8>,
        rollup_id: String,
        operator: Address,
        epoch: u64,
    ) -> EgoResult<Vec<DAChunk>> {
        let mut chunks = Vec::new();
        let chunk_count = (data.len() + self.chunk_size - 1) / self.chunk_size;

        for i in 0..chunk_count {
            let start = i * self.chunk_size;
            let end = std::cmp::min(start + self.chunk_size, data.len());
            let chunk_data = data[start..end].to_vec();

            let chunk_hash = ego_core::crypto::hash_data(&chunk_data);

            chunks.push(DAChunk {
                chunk_id: i as u32,
                chunk_hash,
                data: chunk_data,
                parity: false,
                rollup_id: rollup_id.clone(),
                operator,
                epoch,
            });
        }

        for i in 0..self.m {
            let parity_data = self.generate_parity_chunk(i, &chunks);
            let chunk_hash = ego_core::crypto::hash_data(&parity_data);

            chunks.push(DAChunk {
                chunk_id: (chunk_count + i) as u32,
                chunk_hash,
                data: parity_data,
                parity: true,
                rollup_id: rollup_id.clone(),
                operator,
                epoch,
            });
        }

        Ok(chunks)
    }

    fn generate_parity_chunk(&self, parity_index: usize, data_chunks: &[DAChunk]) -> Vec<u8> {
        let max_len = data_chunks.iter().map(|c| c.data.len()).max().unwrap_or(0);
        let mut parity = vec![0u8; max_len];

        for chunk in data_chunks {
            for (i, &byte) in chunk.data.iter().enumerate() {
                parity[i] ^= byte;
            }
        }

        parity
    }
}

impl AIPatternDetector {
    pub fn new(config: &AIVerificationConfig) -> Self {
        Self {
            enabled: config.enabled,
            suspicious_phrases: config.suspicious_phrases.clone(),
            require_human_verification: config.require_human_verification,
            auto_reject: config.auto_reject_ai_patterns,
        }
    }

    pub fn detect_patterns(&self, data: &[u8]) -> EgoResult<bool> {
        if !self.enabled {
            return Ok(false);
        }

        let text = String::from_utf8_lossy(data).to_lowercase();

        for phrase in &self.suspicious_phrases {
            if text.contains(&phrase.to_lowercase()) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    pub fn verify_human_signature(
        &self,
        signature: &[u8],
        data: &[u8],
        pk: &[u8],
    ) -> EgoResult<bool> {
        if signature.is_empty() || pk.is_empty() {
            return Ok(false);
        }

        let data_hash = ego_core::crypto::blake2s_hash(data);
        ego_core::crypto::verify_dilithium_signature(pk, &data_hash, signature)
    }
}

impl DRSIntegration {
    pub fn new(config: &DRSIntegrationConfig) -> Self {
        Self {
            enabled: config.enabled,
            min_drs_score: config.min_drs_score,
            apply_weights: config.apply_drs_weights,
            density_penalty_rate: config.density_penalty_rate,
            density_min_multiplier: config.density_min_multiplier,
        }
    }

    pub fn validate_drs_score(&self, score: f64) -> bool {
        if !self.enabled {
            return true;
        }
        score >= self.min_drs_score
    }

    pub fn calculate_density_multiplier(&self, device_count: u32, dwell_time_pct: f64) -> f64 {
        if device_count <= 1 || dwell_time_pct < 0.10 {
            return 1.0;
        }

        let penalty = self.density_penalty_rate * (device_count - 1) as f64;
        (1.0 - penalty).max(self.density_min_multiplier)
    }

    pub fn apply_quality_weight(&self, base_quality: f64, drs_multiplier: f64) -> f64 {
        if !self.apply_weights {
            return base_quality;
        }
        base_quality * drs_multiplier
    }
}

impl DeployPolicyEnforcer {
    pub fn new(config: &DeployPolicyConfig) -> Self {
        Self {
            enabled: config.enabled,
            credits_per_kb: config.credits_per_kb_evidence,
            credits_per_proof: config.credits_per_proof,
            require_quota: config.require_quota,
        }
    }

    pub fn calculate_credits_needed(&self, evidence_size_kb: u64, proof_count: u32) -> u64 {
        if !self.enabled {
            return 0;
        }
        evidence_size_kb * self.credits_per_kb + (proof_count as u64) * self.credits_per_proof
    }
}

impl ProofRollupOperator {
    pub fn new(
        config: RollupConfig,
        rollup_id: [u8; 16],
        region_id: u32,
        operator_addr: Address,
        keypair: ego_core::crypto::KeyPair,
    ) -> EgoResult<Self> {
        let da_manager = DataAvailability::new(
            config.da.k as usize,
            config.da.m as usize,
            config.da.chunk_size,
            config.da.enable_compression,
            config.da.compression_level_wifi,
            config.da.compression_level_cellular,
        )?;

        let cellular_safe_mode = config.five_g.cellular_safe_mode;

        let ai_pattern_detector = AIPatternDetector::new(&config.ai_verification);
        let drs_integration = DRSIntegration::new(&config.drs_integration);
        let deploy_policy_enforcer = DeployPolicyEnforcer::new(&config.deploy_policy);

        Ok(Self {
            config,
            rollup_id,
            region_id,
            operator_addr,
            keypair: Arc::new(keypair),
            pending_poc: Arc::new(RwLock::new(Vec::new())),
            pending_post: Arc::new(RwLock::new(Vec::new())),
            pending_porep: Arc::new(RwLock::new(Vec::new())),
            evidence_bundles: Arc::new(RwLock::new(HashMap::new())),
            da_manager: Arc::new(RwLock::new(da_manager)),
            commitments: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(ProofRollupMetrics::default())),
            current_epoch: Arc::new(RwLock::new(0)),
            current_window: Arc::new(RwLock::new(0)),
            anchor_window_hours: DEFAULT_ANCHOR_WINDOW_HOURS,
            cellular_safe_mode,
            ai_pattern_detector: Arc::new(RwLock::new(ai_pattern_detector)),
            drs_integration: Arc::new(RwLock::new(drs_integration)),
            deploy_policy_enforcer: Arc::new(RwLock::new(deploy_policy_enforcer)),
        })
    }

    pub async fn submit_poc_evidence(&self, mut evidence: PoCEvidence) -> EgoResult<Hash> {
        let verify_start = std::time::Instant::now();

        let ai_detector = self.ai_pattern_detector.read().await;
        let config_bytes = bincode::encode_to_vec(&evidence, bincode::config::standard())
            .map_err(|e| EgoError::SerializationError(e.to_string()))?;

        let ai_detected = ai_detector.detect_patterns(&config_bytes)?;
        evidence.ai_pattern_detected = ai_detected;

        if ai_detected && ai_detector.auto_reject {
            return Err(EgoError::InvalidTransaction(
                "AI pattern detected in PoC evidence".to_string(),
            ));
        }
        drop(ai_detector);

        self.verify_poc_signatures(&evidence).await?;

        let drs_integration = self.drs_integration.read().await;
        for beacon in &evidence.beacon_announcements {
            if !drs_integration.validate_drs_score(beacon.drs_score) {
                return Err(EgoError::InvalidTransaction(format!(
                    "Beacon DRS score {} below minimum",
                    beacon.drs_score
                )));
            }
        }
        drop(drs_integration);

        let evidence_hash = self.compute_evidence_hash(&evidence);

        {
            let mut pending = self.pending_poc.write().await;
            pending.push(evidence.clone());
        }

        {
            let mut metrics = self.metrics.write().await;
            metrics.poc_events_received += 1;
            metrics.beacon_count += evidence.beacon_announcements.len() as u64;
            metrics.witness_count += evidence.witness_reports.len() as u64;
            metrics.dilithium_signatures_verified +=
                (evidence.beacon_announcements.len() + evidence.witness_reports.len()) as u64;

            if evidence.human_verified {
                metrics.human_verified_proofs += 1;
            }
            if evidence.ai_pattern_detected {
                metrics.ai_flagged_proofs += 1;
            }
            metrics.density_penalties_applied += evidence.density_events.len() as u64;
        }

        Ok(evidence_hash)
    }

    pub async fn submit_post_evidence(&self, mut evidence: PoStEvidence) -> EgoResult<Hash> {
        let verify_start = std::time::Instant::now();

        let ai_detector = self.ai_pattern_detector.read().await;
        let config_bytes = bincode::encode_to_vec(&evidence, bincode::config::standard())
            .map_err(|e| EgoError::SerializationError(e.to_string()))?;

        let ai_detected = ai_detector.detect_patterns(&config_bytes)?;
        evidence.ai_pattern_detected = ai_detected;

        if ai_detected && ai_detector.auto_reject {
            return Err(EgoError::InvalidTransaction(
                "AI pattern detected in PoSt evidence".to_string(),
            ));
        }
        drop(ai_detector);

        self.verify_post_signatures(&evidence).await?;

        let drs_integration = self.drs_integration.read().await;
        for (_addr, score) in &evidence.node_drs_scores {
            if !drs_integration.validate_drs_score(*score) {
                return Err(EgoError::InvalidTransaction(format!(
                    "Node DRS score {} below minimum",
                    score
                )));
            }
        }
        drop(drs_integration);

        let evidence_hash = self.compute_evidence_hash(&evidence);

        {
            let mut pending = self.pending_post.write().await;
            pending.push(evidence.clone());
        }

        {
            let mut metrics = self.metrics.write().await;
            metrics.post_events_received += 1;
            metrics.partition_count += evidence.partition_indices.len() as u64;
            metrics.sector_proven_count += evidence.prover_stats.proven_sectors;
            metrics.dilithium_signatures_verified += evidence.window_post_proofs.len() as u64;

            if evidence.human_verified {
                metrics.human_verified_proofs += 1;
            }
            if evidence.ai_pattern_detected {
                metrics.ai_flagged_proofs += 1;
            }
        }

        Ok(evidence_hash)
    }

    pub async fn submit_porep_proof(&self, proof: PoRepProof) -> EgoResult<Hash> {
        let verify_start = std::time::Instant::now();

        self.verify_porep_signature(&proof).await?;

        let drs_integration = self.drs_integration.read().await;
        if !drs_integration.validate_drs_score(proof.drs_score) {
            return Err(EgoError::InvalidTransaction(format!(
                "PoRep DRS score {} below minimum",
                proof.drs_score
            )));
        }
        drop(drs_integration);

        let proof_hash = ego_core::crypto::hash_data(&proof.sector_id);

        {
            let mut pending = self.pending_porep.write().await;
            pending.push(proof);
        }

        {
            let mut metrics = self.metrics.write().await;
            metrics.porep_events_received += 1;
            metrics.dilithium_signatures_verified += 1;
        }

        Ok(proof_hash)
    }

    pub async fn aggregate_and_commit(&self, is_cellular: bool) -> EgoResult<Hash> {
        let epoch = *self.current_epoch.read().await;
        let window_id = *self.current_window.read().await;

        let poc_evidence = {
            let mut pending = self.pending_poc.write().await;
            std::mem::take(&mut *pending)
        };

        let post_evidence = {
            let mut pending = self.pending_post.write().await;
            std::mem::take(&mut *pending)
        };

        let porep_proofs = {
            let mut pending = self.pending_porep.write().await;
            std::mem::take(&mut *pending)
        };

        if poc_evidence.is_empty() && post_evidence.is_empty() && porep_proofs.is_empty() {
            return Err(EgoError::InvalidTransaction(
                "No evidence to aggregate".to_string(),
            ));
        }

        let bundle = self
            .create_evidence_bundle(poc_evidence, post_evidence, porep_proofs, is_cellular)
            .await?;

        let bundle_size_bytes = bundle.compressed_data.len() as u64;

        let max_size = if is_cellular {
            self.config.five_g.max_bundle_size_cellular
        } else {
            self.config.five_g.max_bundle_size_wifi
        };

        if bundle_size_bytes > max_size as u64 {
            return Err(EgoError::InvalidTransaction(format!(
                "Bundle size {} exceeds limit {}",
                bundle_size_bytes, max_size
            )));
        }

        let deploy_enforcer = self.deploy_policy_enforcer.read().await;
        let credits_needed = deploy_enforcer
            .calculate_credits_needed(bundle_size_bytes / 1024, bundle.count_proofs());
        drop(deploy_enforcer);

        let proofs_root = bundle.bundle_id;
        let da_chunks = self.create_da_chunks(&bundle, is_cellular).await?;
        let da_root = self.compute_da_root(&da_chunks);

        let drs_integration = self.drs_integration.read().await;
        let drs_weighted_quality = self.calculate_drs_weighted_quality(&bundle, &drs_integration);
        drop(drs_integration);

        let mut commitment = ProofRollupCommit {
            rollup_id: self.rollup_id,
            region_id: self.region_id,
            epoch,
            window_id,
            proofs_root,
            da_root,
            count_proofs: bundle.count_proofs(),
            blob_bytes: bundle_size_bytes,
            min_validity_proof: MinValidityProof::InclusionOnly,
            operator_addr: self.operator_addr,
            operator_sig: DualSignature::new(None, None),
            chain_id: self.config.chain_id,
            network_id: self.config.network_id,
            created_at: Timestamp::now(),
            commitment_hash: Hash::ZERO,
            human_verified_count: bundle.human_verified_count,
            ai_flagged_count: bundle.ai_flagged_count,
            drs_weighted_quality,
            cellular_friendly: bundle.cellular_optimized,
        };

        self.sign_commitment(&mut commitment)?;

        let commitment_hash = self.compute_commitment_hash(&commitment);
        commitment.commitment_hash = commitment_hash;

        {
            let mut bundles = self.evidence_bundles.write().await;
            bundles.insert(bundle.bundle_id, bundle.clone());
        }

        {
            let mut commits = self.commitments.write().await;
            commits.insert(commitment_hash, commitment);
        }

        {
            let mut metrics = self.metrics.write().await;
            metrics.evidence_bundles_created += 1;
            metrics.commitments_posted += 1;
            metrics.total_proofs_aggregated += bundle.count_proofs() as u64;
            metrics.total_blob_bytes += bundle_size_bytes;
            metrics.deploy_credits_consumed_total += credits_needed;

            if metrics.evidence_bundles_created > 0 {
                metrics.avg_bundle_size =
                    metrics.total_blob_bytes / metrics.evidence_bundles_created;
            }

            metrics.compression_ratio = bundle.compression_ratio;

            if is_cellular {
                metrics.cellular_data_used_mb += bundle_size_bytes / (1024 * 1024);
            } else {
                metrics.wifi_data_used_mb += bundle_size_bytes / (1024 * 1024);
            }
        }

        Ok(commitment_hash)
    }

    fn calculate_drs_weighted_quality(&self, bundle: &EvidenceBundle, drs: &DRSIntegration) -> f64 {
        if !drs.enabled || !drs.apply_weights {
            return 1.0;
        }

        let mut total_weight = 0.0;
        let mut weighted_sum = 0.0;

        for poc in &bundle.poc_evidence {
            for beacon in &poc.beacon_announcements {
                let quality = poc.coherence_stats.coherence_score;
                let weighted_quality = drs.apply_quality_weight(quality, beacon.drs_score);
                weighted_sum += weighted_quality;
                total_weight += 1.0;
            }
        }

        for post in &bundle.post_evidence {
            for proof in &post.window_post_proofs {
                let quality = post.prover_stats.pass_ratio;
                let weighted_quality = drs.apply_quality_weight(quality, proof.drs_multiplier);
                weighted_sum += weighted_quality;
                total_weight += 1.0;
            }
        }

        if total_weight > 0.0 {
            weighted_sum / total_weight
        } else {
            1.0
        }
    }

    async fn create_evidence_bundle(
        &self,
        poc_evidence: Vec<PoCEvidence>,
        post_evidence: Vec<PoStEvidence>,
        porep_proofs: Vec<PoRepProof>,
        is_cellular: bool,
    ) -> EgoResult<EvidenceBundle> {
        let bundle_type = if !poc_evidence.is_empty() && !post_evidence.is_empty() {
            EvidenceBundleType::Combined
        } else if !poc_evidence.is_empty() {
            EvidenceBundleType::PoC
        } else if !post_evidence.is_empty() {
            EvidenceBundleType::PoSt
        } else {
            EvidenceBundleType::PoRep
        };

        let config = bincode::config::standard();
        let mut data = Vec::new();

        if !poc_evidence.is_empty() {
            let poc_data = bincode::encode_to_vec(&poc_evidence, config)
                .map_err(|e| EgoError::SerializationError(e.to_string()))?;
            data.extend_from_slice(&poc_data);
        }

        if !post_evidence.is_empty() {
            let post_data = bincode::encode_to_vec(&post_evidence, config)
                .map_err(|e| EgoError::SerializationError(e.to_string()))?;
            data.extend_from_slice(&post_data);
        }

        if !porep_proofs.is_empty() {
            let porep_data = bincode::encode_to_vec(&porep_proofs, config)
                .map_err(|e| EgoError::SerializationError(e.to_string()))?;
            data.extend_from_slice(&porep_data);
        }

        let original_size = data.len() as u64;

        let compression_level = if is_cellular {
            self.config.da.compression_level_cellular
        } else {
            self.config.da.compression_level_wifi
        };

        let compressed_data = zstd::bulk::compress(&data, compression_level)
            .map_err(|e| EgoError::CryptoError(format!("Compression failed: {}", e)))?;

        let compressed_size = compressed_data.len() as u64;
        let compression_ratio = if compressed_size > 0 {
            original_size as f64 / compressed_size as f64
        } else {
            1.0
        };

        let bundle_id = ego_core::crypto::hash_data(&compressed_data);
        let cid = format!("bafy{}", hex::encode(&bundle_id.as_bytes()[..16]));

        let mut human_verified_count = 0;
        let mut ai_flagged_count = 0;

        for poc in &poc_evidence {
            if poc.human_verified {
                human_verified_count += 1;
            }
            if poc.ai_pattern_detected {
                ai_flagged_count += 1;
            }
        }

        for post in &post_evidence {
            if post.human_verified {
                human_verified_count += 1;
            }
            if post.ai_pattern_detected {
                ai_flagged_count += 1;
            }
        }

        let deploy_enforcer = self.deploy_policy_enforcer.read().await;
        let deploy_credits_consumed = deploy_enforcer.calculate_credits_needed(
            compressed_size / 1024,
            (poc_evidence.len() + post_evidence.len() + porep_proofs.len()) as u32,
        );
        drop(deploy_enforcer);

        let drs_integration = self.drs_integration.read().await;
        let mut drs_quality_weighted = 0.0;
        let mut weight_count = 0.0;

        for poc in &poc_evidence {
            for beacon in &poc.beacon_announcements {
                drs_quality_weighted += beacon.drs_score;
                weight_count += 1.0;
            }
        }

        for post in &post_evidence {
            for proof in &post.window_post_proofs {
                drs_quality_weighted += proof.drs_multiplier;
                weight_count += 1.0;
            }
        }

        if weight_count > 0.0 {
            drs_quality_weighted /= weight_count;
        }
        drop(drs_integration);

        Ok(EvidenceBundle {
            bundle_id,
            bundle_type,
            poc_evidence,
            post_evidence,
            porep_proofs,
            compressed_data,
            original_size,
            compression_ratio,
            cid,
            created_at: Timestamp::now(),
            human_verified_count,
            ai_flagged_count,
            drs_quality_weighted,
            deploy_credits_consumed,
            cellular_optimized: is_cellular,
        })
    }

    async fn create_da_chunks(
        &self,
        bundle: &EvidenceBundle,
        is_cellular: bool,
    ) -> EgoResult<Vec<DAChunk>> {
        let epoch = *self.current_epoch.read().await;

        let mut da_manager = self.da_manager.write().await;
        da_manager.encode_data(
            bundle.bundle_id,
            bundle.compressed_data.clone(),
            self.config.rollup_id.clone(),
            self.operator_addr,
            epoch,
        )
    }

    fn compute_da_root(&self, chunks: &[DAChunk]) -> Hash {
        let chunk_hashes: Vec<Vec<u8>> = chunks
            .iter()
            .map(|chunk| chunk.chunk_hash.to_vec())
            .collect();

        if chunk_hashes.is_empty() {
            return Hash::ZERO;
        }

        let merkle_tree = ego_core::crypto::MerkleTree::build(chunk_hashes);
        merkle_tree.root_hash().unwrap_or(Hash::ZERO)
    }

    fn compute_evidence_hash<T: Serialize + bincode::Encode>(&self, evidence: &T) -> Hash {
        let config = bincode::config::standard();
        let data = bincode::encode_to_vec(evidence, config).unwrap_or_default();
        ego_core::crypto::hash_data(&data)
    }

    fn compute_commitment_hash(&self, commitment: &ProofRollupCommit) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(DOMAIN_TAG_ROLLUP_COMMIT);
        data.extend_from_slice(&commitment.rollup_id);
        data.extend_from_slice(&commitment.region_id.to_le_bytes());
        data.extend_from_slice(&commitment.epoch.to_le_bytes());
        data.extend_from_slice(&commitment.window_id.to_le_bytes());
        data.extend_from_slice(commitment.proofs_root.as_bytes());
        data.extend_from_slice(commitment.da_root.as_bytes());
        data.extend_from_slice(&commitment.count_proofs.to_le_bytes());
        data.extend_from_slice(&commitment.blob_bytes.to_le_bytes());
        data.extend_from_slice(&commitment.chain_id.to_le_bytes());
        data.extend_from_slice(&commitment.network_id.to_le_bytes());
        data.extend_from_slice(&commitment.human_verified_count.to_le_bytes());
        data.extend_from_slice(&commitment.ai_flagged_count.to_le_bytes());

        ego_core::crypto::hash_data(&data)
    }

    fn sign_commitment(&self, commitment: &mut ProofRollupCommit) -> EgoResult<()> {
        let signing_data = self.create_commitment_signing_data(commitment)?;
        let sig = self.keypair.sign_hybrid(&signing_data, false);
        commitment.operator_sig = sig;
        Ok(())
    }

    fn create_commitment_signing_data(&self, commitment: &ProofRollupCommit) -> EgoResult<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(DOMAIN_TAG_ROLLUP_COMMIT);
        data.extend_from_slice(&commitment.rollup_id);
        data.extend_from_slice(&commitment.region_id.to_le_bytes());
        data.extend_from_slice(&commitment.epoch.to_le_bytes());
        data.extend_from_slice(&commitment.window_id.to_le_bytes());
        data.extend_from_slice(commitment.proofs_root.as_bytes());
        data.extend_from_slice(commitment.da_root.as_bytes());
        data.extend_from_slice(&commitment.count_proofs.to_le_bytes());
        data.extend_from_slice(&commitment.blob_bytes.to_le_bytes());
        data.extend_from_slice(&commitment.created_at.as_millis().to_le_bytes());
        data.extend_from_slice(&commitment.human_verified_count.to_le_bytes());
        data.extend_from_slice(&commitment.ai_flagged_count.to_le_bytes());

        Ok(ego_core::crypto::blake2s_hash(&data))
    }

    async fn verify_poc_signatures(&self, evidence: &PoCEvidence) -> EgoResult<()> {
        let mut verified = 0;
        let mut failed = 0;

        for beacon in &evidence.beacon_announcements {
            match self.verify_beacon_signature(beacon).await {
                Ok(_) => verified += 1,
                Err(_) => {
                    failed += 1;
                }
            }
        }

        for witness in &evidence.witness_reports {
            match self.verify_witness_signature(witness).await {
                Ok(_) => verified += 1,
                Err(_) => {
                    failed += 1;
                }
            }
        }

        if failed > 0 {
            let mut metrics = self.metrics.write().await;
            metrics.signature_verification_failures += failed as u64;
        }

        if verified == 0 {
            return Err(EgoError::InvalidTransaction(
                "No valid signatures in PoC evidence".to_string(),
            ));
        }

        Ok(())
    }

    async fn verify_beacon_signature(&self, beacon: &BeaconAnnouncement) -> EgoResult<()> {
        if beacon.dilithium_pk.is_empty() || beacon.dilithium_sig.is_empty() {
            return Err(EgoError::InvalidTransaction(
                "Missing beacon signature".to_string(),
            ));
        }

        let mut signing_data = Vec::new();
        signing_data.extend_from_slice(DOMAIN_TAG_POC_BEACON);
        signing_data.extend_from_slice(&beacon.device_id);
        signing_data.extend_from_slice(beacon.node_addr.as_bytes());
        signing_data.extend_from_slice(beacon.location_hash.as_bytes());
        signing_data.extend_from_slice(&beacon.signal_strength_dbm.to_le_bytes());
        signing_data.extend_from_slice(&beacon.frequency_mhz.to_le_bytes());
        signing_data.extend_from_slice(&beacon.h3_cell.to_le_bytes());
        signing_data.extend_from_slice(&beacon.timestamp.as_millis().to_le_bytes());

        let data_hash = ego_core::crypto::blake2s_hash(&signing_data);

        ego_core::crypto::verify_dilithium_signature(
            &beacon.dilithium_pk,
            &data_hash,
            &beacon.dilithium_sig,
        )
        .map_err(|e| EgoError::InvalidTransaction(format!("Beacon signature invalid: {}", e)))
        .and_then(|valid| {
            if valid {
                Ok(())
            } else {
                Err(EgoError::InvalidTransaction(
                    "Beacon signature verification failed".to_string(),
                ))
            }
        })
    }

    async fn verify_witness_signature(&self, witness: &WitnessReport) -> EgoResult<()> {
        if witness.dilithium_pk.is_empty() || witness.dilithium_sig.is_empty() {
            return Err(EgoError::InvalidTransaction(
                "Missing witness signature".to_string(),
            ));
        }

        let mut signing_data = Vec::new();
        signing_data.extend_from_slice(DOMAIN_TAG_POC_WITNESS);
        signing_data.extend_from_slice(&witness.witness_id);
        signing_data.extend_from_slice(witness.witness_addr.as_bytes());
        signing_data.extend_from_slice(&witness.beacon_id);
        signing_data.extend_from_slice(&witness.rsrp_dbm.to_le_bytes());
        signing_data.extend_from_slice(&witness.rsrq_db.to_le_bytes());
        signing_data.extend_from_slice(&witness.sinr_db.to_le_bytes());
        signing_data.extend_from_slice(&witness.timing_advance.to_le_bytes());
        signing_data.extend_from_slice(&witness.distance_meters.to_le_bytes());
        signing_data.extend_from_slice(&witness.gnss_lat.to_le_bytes());
        signing_data.extend_from_slice(&witness.gnss_lon.to_le_bytes());
        signing_data.extend_from_slice(&witness.h3_cell.to_le_bytes());
        signing_data.extend_from_slice(&witness.timestamp.as_millis().to_le_bytes());

        let data_hash = ego_core::crypto::blake2s_hash(&signing_data);

        ego_core::crypto::verify_dilithium_signature(
            &witness.dilithium_pk,
            &data_hash,
            &witness.dilithium_sig,
        )
        .map_err(|e| EgoError::InvalidTransaction(format!("Witness signature invalid: {}", e)))
        .and_then(|valid| {
            if valid {
                Ok(())
            } else {
                Err(EgoError::InvalidTransaction(
                    "Witness signature verification failed".to_string(),
                ))
            }
        })
    }

    async fn verify_post_signatures(&self, evidence: &PoStEvidence) -> EgoResult<()> {
        let mut verified = 0;
        let mut failed = 0;

        for proof in &evidence.window_post_proofs {
            match self.verify_post_proof_signature(proof).await {
                Ok(_) => verified += 1,
                Err(_) => {
                    failed += 1;
                }
            }
        }

        if failed > 0 {
            let mut metrics = self.metrics.write().await;
            metrics.signature_verification_failures += failed as u64;
        }

        if verified == 0 {
            return Err(EgoError::InvalidTransaction(
                "No valid signatures in PoSt evidence".to_string(),
            ));
        }

        Ok(())
    }

    async fn verify_post_proof_signature(&self, proof: &WindowPoStProof) -> EgoResult<()> {
        if proof.dilithium_pk.is_empty() || proof.dilithium_sig.is_empty() {
            return Err(EgoError::InvalidTransaction(
                "Missing PoSt signature".to_string(),
            ));
        }

        let mut signing_data = Vec::new();
        signing_data.extend_from_slice(DOMAIN_TAG_POST_PROOF);
        signing_data.extend_from_slice(&proof.partition_id.to_le_bytes());
        signing_data.extend_from_slice(&proof.challenge_seed);
        signing_data.extend_from_slice(&ego_core::crypto::hash_data(&proof.proof_bytes).to_vec());
        signing_data.extend_from_slice(proof.node_addr.as_bytes());

        for replica_id in &proof.replica_ids {
            signing_data.extend_from_slice(replica_id);
        }

        let data_hash = ego_core::crypto::blake2s_hash(&signing_data);

        ego_core::crypto::verify_dilithium_signature(
            &proof.dilithium_pk,
            &data_hash,
            &proof.dilithium_sig,
        )
        .map_err(|e| EgoError::InvalidTransaction(format!("PoSt signature invalid: {}", e)))
        .and_then(|valid| {
            if valid {
                Ok(())
            } else {
                Err(EgoError::InvalidTransaction(
                    "PoSt signature verification failed".to_string(),
                ))
            }
        })
    }

    async fn verify_porep_signature(&self, proof: &PoRepProof) -> EgoResult<()> {
        if proof.dilithium_pk.is_empty() || proof.dilithium_sig.is_empty() {
            return Err(EgoError::InvalidTransaction(
                "Missing PoRep signature".to_string(),
            ));
        }

        let mut signing_data = Vec::new();
        signing_data.extend_from_slice(DOMAIN_TAG_POREP_PROOF);
        signing_data.extend_from_slice(&proof.sector_id);
        signing_data.extend_from_slice(&proof.comm_r);
        signing_data.extend_from_slice(&proof.comm_d);
        signing_data.extend_from_slice(&proof.replica_id);
        signing_data.extend_from_slice(&proof.porep_params_v.to_le_bytes());
        signing_data.extend_from_slice(proof.node_addr.as_bytes());

        let data_hash = ego_core::crypto::blake2s_hash(&signing_data);

        ego_core::crypto::verify_dilithium_signature(
            &proof.dilithium_pk,
            &data_hash,
            &proof.dilithium_sig,
        )
        .map_err(|e| EgoError::InvalidTransaction(format!("PoRep signature invalid: {}", e)))
        .and_then(|valid| {
            if valid {
                Ok(())
            } else {
                Err(EgoError::InvalidTransaction(
                    "PoRep signature verification failed".to_string(),
                ))
            }
        })
    }

    pub async fn get_metrics(&self) -> ProofRollupMetrics {
        self.metrics.read().await.clone()
    }

    pub async fn get_commitment(&self, hash: Hash) -> Option<ProofRollupCommit> {
        let commits = self.commitments.read().await;
        commits.get(&hash).cloned()
    }

    pub async fn get_evidence_bundle(&self, hash: Hash) -> Option<EvidenceBundle> {
        let bundles = self.evidence_bundles.read().await;
        bundles.get(&hash).cloned()
    }

    pub async fn advance_epoch(&self) {
        let mut epoch = self.current_epoch.write().await;
        *epoch += 1;
    }

    pub async fn advance_window(&self) {
        let mut window = self.current_window.write().await;
        *window += 1;
    }

    pub async fn prune_old_evidence(&self, retention_epochs: u64) -> EgoResult<usize> {
        let current_epoch = *self.current_epoch.read().await;
        let cutoff_epoch = current_epoch.saturating_sub(retention_epochs);

        let mut bundles = self.evidence_bundles.write().await;
        let before_count = bundles.len();

        bundles.retain(|_, bundle| bundle.created_at.as_millis() > cutoff_epoch * 3_600_000);

        let pruned = before_count - bundles.len();

        Ok(pruned)
    }

    pub async fn create_rollup_transaction(
        &self,
        commitment: &ProofRollupCommit,
        from: Address,
        nonce: u64,
        shard_id: ShardId,
        chain_id: u32,
    ) -> EgoResult<Transaction> {
        let payload = TransactionPayload::RollupCommit {
            rollup_id: hex::encode(commitment.rollup_id),
            state_root: commitment.proofs_root,
            tx_root: commitment.da_root,
            proofs_root: commitment.proofs_root,
            da_root: commitment.da_root,
            tx_count: commitment.count_proofs,
            block_range: (commitment.epoch, commitment.epoch),
            epoch: commitment.epoch,
            min_validity_proof: vec![],
            fraud_proofs: vec![],
            operator_signature: vec![],
        };

        let mut tx = Transaction::new(from, nonce, payload, shard_id, None, chain_id);

        tx.sign(&self.keypair, false)?;

        Ok(tx)
    }

    pub fn verify_commitment_signature(&self, commitment: &ProofRollupCommit) -> EgoResult<bool> {
        let signing_data = self.create_commitment_signing_data(commitment)?;

        let dilithium_pk = self.keypair.dilithium_public_key();

        if let Some(ref dilithium_sig) = commitment.operator_sig.dilithium_sig {
            ego_core::crypto::verify_signature(&dilithium_pk, &signing_data, dilithium_sig)
        } else {
            Ok(false)
        }
    }
}

impl EvidenceBundle {
    pub fn count_proofs(&self) -> u32 {
        let mut count = 0;

        for poc in &self.poc_evidence {
            count += poc.beacon_announcements.len() as u32;
            count += poc.witness_reports.len() as u32;
        }

        for post in &self.post_evidence {
            count += post.window_post_proofs.len() as u32;
        }

        count += self.porep_proofs.len() as u32;

        count
    }

    pub fn is_cellular_safe(&self) -> bool {
        self.cellular_optimized && self.compressed_data.len() <= MAX_BUNDLE_SIZE_CELLULAR
    }

    pub fn verify_bundle_hash(&self) -> bool {
        let computed_hash = ego_core::crypto::hash_data(&self.compressed_data);
        computed_hash == self.bundle_id
    }

    pub fn decompress(&self) -> EgoResult<Vec<u8>> {
        zstd::bulk::decompress(&self.compressed_data, self.original_size as usize)
            .map_err(|e| EgoError::CryptoError(format!("Decompression failed: {}", e)))
    }

    pub fn quality_score(&self) -> f64 {
        if self.ai_flagged_count > 0 && self.human_verified_count == 0 {
            return 0.5;
        }

        let mut base_score = self.drs_quality_weighted;

        if self.human_verified_count > 0 {
            base_score *= 1.1;
        }

        if self.ai_flagged_count > 0 {
            let penalty = (self.ai_flagged_count as f64 / self.count_proofs() as f64) * 0.3;
            base_score *= (1.0 - penalty);
        }

        base_score.clamp(0.0, 1.0)
    }
}

impl ProofRollupCommit {
    pub fn verify_signature(&self, operator_pk: &PublicKey) -> EgoResult<bool> {
        let mut data = Vec::new();
        data.extend_from_slice(DOMAIN_TAG_ROLLUP_COMMIT);
        data.extend_from_slice(&self.rollup_id);
        data.extend_from_slice(&self.region_id.to_le_bytes());
        data.extend_from_slice(&self.epoch.to_le_bytes());
        data.extend_from_slice(&self.window_id.to_le_bytes());
        data.extend_from_slice(self.proofs_root.as_bytes());
        data.extend_from_slice(self.da_root.as_bytes());
        data.extend_from_slice(&self.count_proofs.to_le_bytes());
        data.extend_from_slice(&self.blob_bytes.to_le_bytes());
        data.extend_from_slice(&self.created_at.as_millis().to_le_bytes());
        data.extend_from_slice(&self.human_verified_count.to_le_bytes());
        data.extend_from_slice(&self.ai_flagged_count.to_le_bytes());

        let data_hash = ego_core::crypto::blake2s_hash(&data);

        if let Some(ref dilithium_sig) = self.operator_sig.dilithium_sig {
            ego_core::crypto::verify_signature(operator_pk, &data_hash, dilithium_sig)
        } else {
            Ok(false)
        }
    }

    pub fn is_valid(&self) -> bool {
        self.count_proofs > 0
            && self.blob_bytes > 0
            && self.proofs_root != Hash::ZERO
            && self.da_root != Hash::ZERO
    }

    pub fn summary(&self) -> String {
        format!(
            "RollupCommit epoch={} window={} proofs={} size={}KB region={} human_verified={} ai_flagged={} drs_quality={:.3} cellular={}",
            self.epoch,
            self.window_id,
            self.count_proofs,
            self.blob_bytes / 1024,
            self.region_id,
            self.human_verified_count,
            self.ai_flagged_count,
            self.drs_weighted_quality,
            self.cellular_friendly
        )
    }

    pub fn integrity_score(&self) -> f64 {
        let mut score = self.drs_weighted_quality;

        if self.human_verified_count > 0 {
            let verification_ratio = self.human_verified_count as f64 / self.count_proofs as f64;
            score += verification_ratio * 0.2;
        }

        if self.ai_flagged_count > 0 {
            let flag_ratio = self.ai_flagged_count as f64 / self.count_proofs as f64;
            score -= flag_ratio * 0.3;
        }

        score.clamp(0.0, 1.0)
    }
}
