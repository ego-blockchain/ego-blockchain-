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
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct BeaconAnnouncement {
    pub device_id: [u8; 32],
    pub location_hash: Hash,
    pub signal_strength_dbm: i16,
    pub frequency_mhz: u32,
    pub h3_cell: u64,
    pub timestamp: Timestamp,
    pub dilithium_pk: Vec<u8>,
    pub dilithium_sig: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct WitnessReport {
    pub witness_id: [u8; 32],
    pub beacon_id: [u8; 32],
    pub rsrp_dbm: i16,
    pub rsrq_db: i16,
    pub sinr_db: i16,
    pub timing_advance: u16,
    pub distance_meters: u32,
    pub gnss_lat: i32,
    pub gnss_lon: i32,
    pub timestamp: Timestamp,
    pub dilithium_pk: Vec<u8>,
    pub dilithium_sig: Vec<u8>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ThresholdParams {
    pub min_witnesses: u32,
    pub max_distance_meters: u32,
    pub min_signal_strength_dbm: i16,
    pub max_path_loss_rmse: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PoStEvidence {
    pub partition_indices: Vec<u32>,
    pub window_post_proofs: Vec<WindowPoStProof>,
    pub partition_maps: HashMap<u32, PartitionInfo>,
    pub prover_stats: ProverStats,
    pub timestamp: Timestamp,
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
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PartitionInfo {
    pub partition_id: u32,
    pub sector_count: u32,
    pub proven_sectors: u32,
    pub deadline: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ProverStats {
    pub total_sectors: u64,
    pub proven_sectors: u64,
    pub failed_proofs: u64,
    pub avg_proof_time_ms: u64,
    pub pass_ratio: f64,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollupConfig {
    pub rollup_id: String,
    pub chain_id: u32,
    pub network_id: u32,
    pub da: DaConfig,
    pub five_g: FiveGConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaConfig {
    pub k: u16,
    pub m: u16,
    pub chunk_size: usize,
    pub enable_compression: bool,
    pub compression_level: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiveGConfig {
    pub cellular_safe_mode: bool,
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
                compression_level: 3,
            },
            five_g: FiveGConfig {
                cellular_safe_mode: true,
            },
        }
    }
}

pub struct DataAvailability {
    k: usize,
    m: usize,
    chunk_size: usize,
    enable_compression: bool,
    compression_level: i32,
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

impl DataAvailability {
    pub fn new(
        k: usize,
        m: usize,
        chunk_size: usize,
        enable_compression: bool,
        compression_level: i32,
    ) -> EgoResult<Self> {
        Ok(Self {
            k,
            m,
            chunk_size,
            enable_compression,
            compression_level,
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
            config.da.compression_level,
        )?;

        let cellular_safe_mode = config.five_g.cellular_safe_mode;

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
            anchor_window_hours: 24,
            cellular_safe_mode,
        })
    }

    pub async fn submit_poc_evidence(&self, evidence: PoCEvidence) -> EgoResult<Hash> {
        let verify_start = std::time::Instant::now();

        self.verify_poc_signatures(&evidence).await?;

        let verification_time = verify_start.elapsed().as_millis() as u64;

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
        }

        Ok(evidence_hash)
    }

    pub async fn submit_post_evidence(&self, evidence: PoStEvidence) -> EgoResult<Hash> {
        let verify_start = std::time::Instant::now();

        self.verify_post_signatures(&evidence).await?;

        let verification_time = verify_start.elapsed().as_millis() as u64;

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
        }

        Ok(evidence_hash)
    }

    pub async fn submit_porep_proof(&self, proof: PoRepProof) -> EgoResult<Hash> {
        let verify_start = std::time::Instant::now();

        self.verify_porep_signature(&proof).await?;

        let verification_time = verify_start.elapsed().as_millis() as u64;

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
            .create_evidence_bundle(poc_evidence, post_evidence, porep_proofs)
            .await?;

        let bundle_size_bytes = bundle.compressed_data.len() as u64;

        if self.cellular_safe_mode && is_cellular && bundle_size_bytes > 512 * 1024 {
            return Err(EgoError::InvalidTransaction(
                "Bundle too large for cellular upload".to_string(),
            ));
        }

        let proofs_root = bundle.bundle_id;

        let da_chunks = self.create_da_chunks(&bundle).await?;

        let da_root = self.compute_da_root(&da_chunks);

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

    async fn create_evidence_bundle(
        &self,
        poc_evidence: Vec<PoCEvidence>,
        post_evidence: Vec<PoStEvidence>,
        porep_proofs: Vec<PoRepProof>,
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

        let compressed_data = zstd::bulk::compress(&data, self.config.da.compression_level)
            .map_err(|e| EgoError::CryptoError(format!("Compression failed: {}", e)))?;

        let compressed_size = compressed_data.len() as u64;
        let compression_ratio = if compressed_size > 0 {
            original_size as f64 / compressed_size as f64
        } else {
            1.0
        };

        let bundle_id = ego_core::crypto::hash_data(&compressed_data);

        let cid = format!("bafy{}", hex::encode(&bundle_id.as_bytes()[..16]));

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
        })
    }

    async fn create_da_chunks(&self, bundle: &EvidenceBundle) -> EgoResult<Vec<DAChunk>> {
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
        signing_data.extend_from_slice(&witness.beacon_id);
        signing_data.extend_from_slice(&witness.rsrp_dbm.to_le_bytes());
        signing_data.extend_from_slice(&witness.rsrq_db.to_le_bytes());
        signing_data.extend_from_slice(&witness.sinr_db.to_le_bytes());
        signing_data.extend_from_slice(&witness.timing_advance.to_le_bytes());
        signing_data.extend_from_slice(&witness.distance_meters.to_le_bytes());
        signing_data.extend_from_slice(&witness.gnss_lat.to_le_bytes());
        signing_data.extend_from_slice(&witness.gnss_lon.to_le_bytes());
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
        self.compressed_data.len() <= 512 * 1024
    }

    pub fn verify_bundle_hash(&self) -> bool {
        let computed_hash = ego_core::crypto::hash_data(&self.compressed_data);
        computed_hash == self.bundle_id
    }

    pub fn decompress(&self) -> EgoResult<Vec<u8>> {
        zstd::bulk::decompress(&self.compressed_data, self.original_size as usize)
            .map_err(|e| EgoError::CryptoError(format!("Decompression failed: {}", e)))
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
            "RollupCommit epoch={} window={} proofs={} size={}KB region={}",
            self.epoch,
            self.window_id,
            self.count_proofs,
            self.blob_bytes / 1024,
            self.region_id
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::crypto::KeyPair;

    fn create_test_config() -> RollupConfig {
        RollupConfig::default()
    }

    #[tokio::test]
    async fn test_proof_rollup_creation() {
        let config = create_test_config();
        let rollup_id = [1u8; 16];
        let region_id = 1;
        let keypair = KeyPair::generate();
        let operator_addr = Address::from_public_key(&keypair.dilithium_public_key());

        let operator =
            ProofRollupOperator::new(config, rollup_id, region_id, operator_addr, keypair).unwrap();

        assert_eq!(operator.rollup_id, rollup_id);
        assert_eq!(operator.region_id, region_id);
    }

    #[tokio::test]
    async fn test_poc_evidence_submission() {
        let config = create_test_config();
        let rollup_id = [1u8; 16];
        let keypair = KeyPair::generate();
        let operator_addr = Address::from_public_key(&keypair.dilithium_public_key());

        let operator =
            ProofRollupOperator::new(config, rollup_id, 1, operator_addr, keypair).unwrap();

        let poc_evidence = PoCEvidence {
            beacon_announcements: vec![],
            witness_reports: vec![],
            coherence_stats: CoherenceStats {
                total_beacons: 10,
                total_witnesses: 20,
                valid_reports: 18,
                invalid_reports: 2,
                coherence_score: 0.9,
                path_loss_rmse: 5.2,
                diversity_score: 0.85,
            },
            thresholds_used: ThresholdParams {
                min_witnesses: 3,
                max_distance_meters: 1000,
                min_signal_strength_dbm: -100,
                max_path_loss_rmse: 8.0,
            },
            timestamp: Timestamp::now(),
        };

        let hash = operator.submit_poc_evidence(poc_evidence).await.unwrap();
        assert_ne!(hash, Hash::ZERO);

        let metrics = operator.get_metrics().await;
        assert_eq!(metrics.poc_events_received, 1);
    }

    #[tokio::test]
    async fn test_evidence_bundle_cellular_safe() {
        let bundle = EvidenceBundle {
            bundle_id: Hash::ZERO,
            bundle_type: EvidenceBundleType::Combined,
            poc_evidence: vec![],
            post_evidence: vec![],
            porep_proofs: vec![],
            compressed_data: vec![0u8; 256 * 1024],
            original_size: 512 * 1024,
            compression_ratio: 2.0,
            cid: "test".to_string(),
            created_at: Timestamp::now(),
        };

        assert!(bundle.is_cellular_safe());
    }

    #[tokio::test]
    async fn test_commitment_signature() {
        let config = create_test_config();
        let rollup_id = [1u8; 16];
        let keypair = KeyPair::generate();
        let operator_addr = Address::from_public_key(&keypair.dilithium_public_key());

        let operator =
            ProofRollupOperator::new(config, rollup_id, 1, operator_addr, keypair).unwrap();

        let mut commitment = ProofRollupCommit {
            rollup_id,
            region_id: 1,
            epoch: 100,
            window_id: 5,
            proofs_root: Hash::ZERO,
            da_root: Hash::ZERO,
            count_proofs: 10,
            blob_bytes: 1024,
            min_validity_proof: MinValidityProof::InclusionOnly,
            operator_addr,
            operator_sig: DualSignature::new(None, None),
            chain_id: 1,
            network_id: 1,
            created_at: Timestamp::now(),
            commitment_hash: Hash::ZERO,
        };

        operator.sign_commitment(&mut commitment).unwrap();

        let valid = operator.verify_commitment_signature(&commitment).unwrap();
        assert!(valid);
    }
}
