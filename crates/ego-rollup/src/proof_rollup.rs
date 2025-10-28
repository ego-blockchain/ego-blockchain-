use crate::commitment::RollupCommitment;
use crate::config::RollupConfig;
use crate::da::{DAChunk, DataAvailability};
use crate::error::{RollupError, RollupResult};
use crate::metrics::RollupMetrics;
use ego_core::{Address, Hash, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// ProofRollup: Aggregates PoC/PoSt/PoRep events and evidence bundles
/// Posts roots and minimal validity to shards with Dilithium-2 signatures
#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ProofRollupCommit {
    pub rollup_id: [u8; 16],
    pub region_id: u32,
    pub epoch: u64,
    pub window_id: u32,
    
    /// Merkle root over PoC/PoSt/PoRep events
    pub proofs_root: Hash,
    
    /// Erasure-coded blob manifest root
    pub da_root: Hash,
    
    pub count_proofs: u32,
    pub blob_bytes: u64,
    
    /// Minimal validity proof type
    pub min_validity_proof: MinValidityProof,
    
    /// Post-quantum signature (Dilithium-2)
    pub alg_sig_id: u16,  // ML-DSA-2 algorithm ID
    pub operator_addr: [u8; 20],
    pub operator_sig: Vec<u8>,
    
    pub created_at: Timestamp,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub enum MinValidityProof {
    None = 0,
    InclusionOnly = 1,
    StateWitness = 2,
    CircuitProof = 3,
}

/// PoC (Proof of Coverage) evidence
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
    pub signal_strength: i16,
    pub frequency_mhz: u32,
    pub timestamp: Timestamp,
    pub dilithium_sig: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct WitnessReport {
    pub witness_id: [u8; 32],
    pub beacon_id: [u8; 32],
    pub signal_strength: i16,
    pub distance_meters: u32,
    pub timestamp: Timestamp,
    pub dilithium_sig: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct CoherenceStats {
    pub total_beacons: u32,
    pub total_witnesses: u32,
    pub valid_reports: u32,
    pub invalid_reports: u32,
    pub coherence_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ThresholdParams {
    pub min_witnesses: u32,
    pub max_distance_meters: u32,
    pub min_signal_strength: i16,
}

/// PoSt (Proof of Spacetime) evidence
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
}

/// Evidence bundle (off-chain, content-addressed)
#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct EvidenceBundle {
    pub bundle_id: Hash,
    pub bundle_type: EvidenceBundleType,
    pub poc_evidence: Option<PoCEvidence>,
    pub post_evidence: Option<PoStEvidence>,
    pub porep_proofs: Vec<PoRepProof>,
    
    /// CBOR/protobuf, zstd-compressed
    pub compressed_data: Vec<u8>,
    pub original_size: u64,
    pub compression_ratio: f64,
    
    /// Content-addressed identifier (CID)
    pub cid: String,
    pub created_at: Timestamp,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, bincode::Encode, bincode::Decode, PartialEq, Eq)]
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
    pub dilithium_sig: Vec<u8>,
}

/// ProofRollup operator
pub struct ProofRollupOperator {
    config: RollupConfig,
    rollup_id: [u8; 16],
    region_id: u32,
    operator_addr: Address,
    
    /// Evidence aggregation
    pending_poc: Arc<RwLock<Vec<PoCEvidence>>>,
    pending_post: Arc<RwLock<Vec<PoStEvidence>>>,
    pending_porep: Arc<RwLock<Vec<PoRepProof>>>,
    
    /// Evidence bundles indexed by hash
    evidence_bundles: Arc<RwLock<HashMap<Hash, EvidenceBundle>>>,
    
    /// DA manager for erasure coding
    da_manager: Arc<RwLock<DataAvailability>>,
    
    /// Posted commitments
    commitments: Arc<RwLock<HashMap<Hash, ProofRollupCommit>>>,
    
    metrics: Arc<RwLock<ProofRollupMetrics>>,
    
    /// Current epoch and window
    current_epoch: Arc<RwLock<u64>>,
    current_window: Arc<RwLock<u32>>,
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
}

impl ProofRollupOperator {
    pub fn new(
        config: RollupConfig,
        rollup_id: [u8; 16],
        region_id: u32,
        operator_addr: Address,
    ) -> RollupResult<Self> {
        let da_manager = DataAvailability::new(
            config.da.k,
            config.da.m,
            config.da.chunk_size,
            config.da.enable_compression,
            config.da.compression_level,
        )?;
        
        Ok(Self {
            config,
            rollup_id,
            region_id,
            operator_addr,
            pending_poc: Arc::new(RwLock::new(Vec::new())),
            pending_post: Arc::new(RwLock::new(Vec::new())),
            pending_porep: Arc::new(RwLock::new(Vec::new())),
            evidence_bundles: Arc::new(RwLock::new(HashMap::new())),
            da_manager: Arc::new(RwLock::new(da_manager)),
            commitments: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(ProofRollupMetrics::default())),
            current_epoch: Arc::new(RwLock::new(0)),
            current_window: Arc::new(RwLock::new(0)),
        })
    }
    
    /// Submit PoC evidence from Ego device
    pub async fn submit_poc_evidence(&self, evidence: PoCEvidence) -> RollupResult<Hash> {
        // Verify all Dilithium signatures in beacon announcements and witness reports
        self.verify_poc_signatures(&evidence).await?;
        
        let evidence_hash = self.compute_evidence_hash(&evidence);
        
        {
            let mut pending = self.pending_poc.write().await;
            pending.push(evidence);
        }
        
        {
            let mut metrics = self.metrics.write().await;
            metrics.poc_events_received += 1;
        }
        
        info!("Received PoC evidence: {}", evidence_hash);
        Ok(evidence_hash)
    }
    
    /// Submit PoSt evidence from storage provider
    pub async fn submit_post_evidence(&self, evidence: PoStEvidence) -> RollupResult<Hash> {
        // Verify Dilithium signatures in WindowPoSt proofs
        self.verify_post_signatures(&evidence).await?;
        
        let evidence_hash = self.compute_evidence_hash(&evidence);
        
        {
            let mut pending = self.pending_post.write().await;
            pending.push(evidence);
        }
        
        {
            let mut metrics = self.metrics.write().await;
            metrics.post_events_received += 1;
        }
        
        info!("Received PoSt evidence: {}", evidence_hash);
        Ok(evidence_hash)
    }
    
    /// Submit PoRep proof
    pub async fn submit_porep_proof(&self, proof: PoRepProof) -> RollupResult<Hash> {
        // Verify Dilithium signature
        self.verify_dilithium_signature(&proof.dilithium_sig, &proof.sector_id).await?;
        
        let proof_hash = Hash::from_bytes(&proof.sector_id);
        
        {
            let mut pending = self.pending_porep.write().await;
            pending.push(proof);
        }
        
        {
            let mut metrics = self.metrics.write().await;
            metrics.porep_events_received += 1;
        }
        
        info!("Received PoRep proof: {}", proof_hash);
        Ok(proof_hash)
    }
    
    /// Aggregate pending evidence into a bundle and post commitment
    pub async fn aggregate_and_commit(&self) -> RollupResult<Hash> {
        let epoch = *self.current_epoch.read().await;
        let window_id = *self.current_window.read().await;
        
        // Collect all pending evidence
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
            return Err(RollupError::InvalidBatch("No evidence to aggregate".to_string()));
        }
        
        // Create evidence bundle
        let bundle = self.create_evidence_bundle(
            poc_evidence,
            post_evidence,
            porep_proofs,
        ).await?;
        
        // Compute proofs root (Merkle root over all evidence)
        let proofs_root = bundle.bundle_id;
        
        // Create DA chunks for the bundle
        let da_chunks = self.create_da_chunks(&bundle).await?;
        
        // Compute DA root
        let da_root = self.compute_da_root(&da_chunks);
        
        // Create commitment
        let commitment = ProofRollupCommit {
            rollup_id: self.rollup_id,
            region_id: self.region_id,
            epoch,
            window_id,
            proofs_root,
            da_root,
            count_proofs: bundle.count_proofs(),
            blob_bytes: bundle.compressed_data.len() as u64,
            min_validity_proof: MinValidityProof::InclusionOnly,
            alg_sig_id: 2, // ML-DSA-2 (Dilithium-2)
            operator_addr: self.operator_addr.as_bytes().try_into().unwrap_or([0u8; 20]),
            operator_sig: Vec::new(), // TODO: Sign with Dilithium-2
            created_at: Timestamp::now(),
        };
        
        let commitment_hash = self.compute_commitment_hash(&commitment);
        
        // Store bundle and commitment
        {
            let mut bundles = self.evidence_bundles.write().await;
            bundles.insert(bundle.bundle_id, bundle);
        }
        
        {
            let mut commits = self.commitments.write().await;
            commits.insert(commitment_hash, commitment);
        }
        
        {
            let mut metrics = self.metrics.write().await;
            metrics.evidence_bundles_created += 1;
            metrics.commitments_posted += 1;
            metrics.total_proofs_aggregated += 1;
        }
        
        info!("Posted ProofRollup commitment: {} (epoch={}, window={})", 
              commitment_hash, epoch, window_id);
        
        Ok(commitment_hash)
    }
    
    async fn create_evidence_bundle(
        &self,
        poc_evidence: Vec<PoCEvidence>,
        post_evidence: Vec<PoStEvidence>,
        porep_proofs: Vec<PoRepProof>,
    ) -> RollupResult<EvidenceBundle> {
        let bundle_type = if !poc_evidence.is_empty() && !post_evidence.is_empty() {
            EvidenceBundleType::Combined
        } else if !poc_evidence.is_empty() {
            EvidenceBundleType::PoC
        } else if !post_evidence.is_empty() {
            EvidenceBundleType::PoSt
        } else {
            EvidenceBundleType::PoRep
        };
        
        // Serialize evidence to CBOR/bincode
        let config = bincode::config::standard();
        let mut data = Vec::new();
        
        if !poc_evidence.is_empty() {
            let poc_data = bincode::encode_to_vec(&poc_evidence, config)
                .map_err(|e| RollupError::SerializationError(e.to_string()))?;
            data.extend_from_slice(&poc_data);
        }
        
        if !post_evidence.is_empty() {
            let post_data = bincode::encode_to_vec(&post_evidence, config)
                .map_err(|e| RollupError::SerializationError(e.to_string()))?;
            data.extend_from_slice(&post_data);
        }
        
        if !porep_proofs.is_empty() {
            let porep_data = bincode::encode_to_vec(&porep_proofs, config)
                .map_err(|e| RollupError::SerializationError(e.to_string()))?;
            data.extend_from_slice(&porep_data);
        }
        
        let original_size = data.len() as u64;
        
        // Compress with zstd
        let compressed_data = zstd::bulk::compress(&data, self.config.da.compression_level as i32)
            .map_err(|e| RollupError::CompressionError(e.to_string()))?;
        
        let compression_ratio = original_size as f64 / compressed_data.len() as f64;
        
        // Compute bundle ID (hash of compressed data)
        let bundle_id = ego_core::crypto::hash_data(&compressed_data);
        
        // Generate CID (content identifier)
        let cid = format!("bafy{}", hex::encode(&bundle_id.as_bytes()[..16]));
        
        Ok(EvidenceBundle {
            bundle_id,
            bundle_type,
            poc_evidence: if !poc_evidence.is_empty() { Some(poc_evidence[0].clone()) } else { None },
            post_evidence: if !post_evidence.is_empty() { Some(post_evidence[0].clone()) } else { None },
            porep_proofs,
            compressed_data,
            original_size,
            compression_ratio,
            cid,
            created_at: Timestamp::now(),
        })
    }
    
    async fn create_da_chunks(&self, bundle: &EvidenceBundle) -> RollupResult<Vec<DAChunk>> {
        let mut da_manager = self.da_manager.write().await;
        da_manager.encode_data(bundle.bundle_id, bundle.compressed_data.clone())
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
    
    fn compute_evidence_hash<T: Serialize>(&self, evidence: &T) -> Hash {
        let config = bincode::config::standard();
        let data = bincode::encode_to_vec(evidence, config).unwrap_or_default();
        ego_core::crypto::hash_data(&data)
    }
    
    fn compute_commitment_hash(&self, commitment: &ProofRollupCommit) -> Hash {
        let config = bincode::config::standard();
        let data = bincode::encode_to_vec(commitment, config).unwrap_or_default();
        ego_core::crypto::hash_data(&data)
    }
    
    async fn verify_poc_signatures(&self, evidence: &PoCEvidence) -> RollupResult<()> {
        // TODO: Implement Dilithium-2 signature verification
        // For now, accept all signatures
        debug!("Verifying PoC Dilithium signatures for {} beacons", evidence.beacon_announcements.len());
        Ok(())
    }
    
    async fn verify_post_signatures(&self, evidence: &PoStEvidence) -> RollupResult<()> {
        // TODO: Implement Dilithium-2 signature verification
        debug!("Verifying PoSt Dilithium signatures for {} proofs", evidence.window_post_proofs.len());
        Ok(())
    }
    
    async fn verify_dilithium_signature(&self, _sig: &[u8], _data: &[u8]) -> RollupResult<()> {
        // TODO: Implement Dilithium-2 signature verification
        Ok(())
    }
    
    pub async fn get_metrics(&self) -> ProofRollupMetrics {
        self.metrics.read().await.clone()
    }
    
    pub async fn advance_epoch(&self) {
        let mut epoch = self.current_epoch.write().await;
        *epoch += 1;
        info!("Advanced to epoch {}", *epoch);
    }
    
    pub async fn advance_window(&self) {
        let mut window = self.current_window.write().await;
        *window += 1;
        info!("Advanced to window {}", *window);
    }
}

impl EvidenceBundle {
    fn count_proofs(&self) -> u32 {
        let mut count = 0;
        
        if let Some(poc) = &self.poc_evidence {
            count += poc.beacon_announcements.len() as u32;
            count += poc.witness_reports.len() as u32;
        }
        
        if let Some(post) = &self.post_evidence {
            count += post.window_post_proofs.len() as u32;
        }
        
        count += self.porep_proofs.len() as u32;
        
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::KeyPair;
    
    fn create_test_config() -> RollupConfig {
        RollupConfig::default()
    }
    
    #[tokio::test]
    async fn test_proof_rollup_creation() {
        let config = create_test_config();
        let rollup_id = [1u8; 16];
        let region_id = 1;
        let keypair = KeyPair::generate();
        let operator_addr = Address::from_public_key(&keypair.public_key());
        
        let operator = ProofRollupOperator::new(config, rollup_id, region_id, operator_addr).unwrap();
        assert_eq!(operator.rollup_id, rollup_id);
        assert_eq!(operator.region_id, region_id);
    }
    
    #[tokio::test]
    async fn test_poc_evidence_submission() {
        let config = create_test_config();
        let rollup_id = [1u8; 16];
        let keypair = KeyPair::generate();
        let operator_addr = Address::from_public_key(&keypair.public_key());
        
        let operator = ProofRollupOperator::new(config, rollup_id, 1, operator_addr).unwrap();
        
        let poc_evidence = PoCEvidence {
            beacon_announcements: vec![],
            witness_reports: vec![],
            coherence_stats: CoherenceStats {
                total_beacons: 10,
                total_witnesses: 20,
                valid_reports: 18,
                invalid_reports: 2,
                coherence_score: 0.9,
            },
            thresholds_used: ThresholdParams {
                min_witnesses: 3,
                max_distance_meters: 1000,
                min_signal_strength: -100,
            },
            timestamp: Timestamp::now(),
        };
        
        let hash = operator.submit_poc_evidence(poc_evidence).await.unwrap();
        assert_ne!(hash, Hash::ZERO);
        
        let metrics = operator.get_metrics().await;
        assert_eq!(metrics.poc_events_received, 1);
    }
}
