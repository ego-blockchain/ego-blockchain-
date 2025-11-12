use crate::error::{RollupError, RollupResult};
use ego_core::{Address, Balance, Hash, Timestamp, BlockHeight, ShardId};
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DAChunk {
    pub chunk_id: u32,
    pub commitment_hash: Hash,
    pub data: Vec<u8>,
    pub is_parity: bool,
    pub chunk_hash: Hash,
    pub timestamp: Timestamp,
    pub provider: Option<Address>,
    pub replica_count: u8,
    pub access_count: u64,
    pub shard_id: ShardId,
    pub epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DAProof {
    pub commitment_hash: Hash,
    pub chunk_indices: Vec<u32>,
    pub chunk_hashes: Vec<Hash>,
    pub merkle_proof: Vec<Hash>,
    pub root_hash: Hash,
    pub proof_timestamp: Timestamp,
    pub prover: Address,
    pub signature: Vec<u8>,
    pub alg_sig_id: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DAUnavailabilityProof {
    pub commitment_hash: Hash,
    pub missing_chunks: Vec<u32>,
    pub sample_indices: Vec<u32>,
    pub failed_requests: Vec<FailedRequest>,
    pub timestamp: Timestamp,
    pub challenger: Address,
    pub challenge_bond: Balance,
    pub expected_providers: Vec<Address>,
    pub evidence_root: Hash,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct FailedRequest {
    pub chunk_id: u32,
    pub operator: Address,
    pub request_time: Timestamp,
    pub timeout_time: Timestamp,
    pub error: String,
    pub retry_count: u32,
    pub last_attempt: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DACommitment {
    pub commitment_hash: Hash,
    pub data_root: Hash,
    pub chunk_count: u32,
    pub original_size: usize,
    pub compressed_size: usize,
    pub rs_params: RSParams,
    pub timestamp: Timestamp,
    pub epoch: u64,
    pub block_height: BlockHeight,
    pub rollup_id: String,
    pub operator: Address,
    pub shard_id: ShardId,
    pub proof_batch_hash: Hash,
    pub cellular_safe_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DASamplingRequest {
    pub commitment_hash: Hash,
    pub sample_size: u32,
    pub random_seed: [u8; 32],
    pub requester: Address,
    pub deadline_epoch: u64,
    pub shard_id: ShardId,
    pub priority: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DASamplingResponse {
    pub request_hash: Hash,
    pub chunks: Vec<DAChunk>,
    pub proof: DAProof,
    pub responder: Address,
    pub response_time_ms: u32,
    pub latency_within_sla: bool,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DAWindow {
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub commitments: Vec<Hash>,
    pub challenge_period: u64,
    pub active_challenges: HashMap<Hash, Vec<Address>>,
    pub finalized: bool,
    pub shard_id: ShardId,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DAChallenge {
    pub challenge_id: Hash,
    pub commitment_hash: Hash,
    pub challenger: Address,
    pub challenge_type: ChallengeType,
    pub sample_indices: Vec<u32>,
    pub timestamp: Timestamp,
    pub deadline_epoch: u64,
    pub bond: Balance,
    pub status: ChallengeStatus,
    pub response_hash: Option<Hash>,
    pub slash_amount: Option<Balance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum ChallengeType {
    Availability,
    Integrity,
    Performance,
    Fraud,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum ChallengeStatus {
    Pending,
    Responding,
    Resolved,
    Failed,
    Slashed,
    Expired,
}

#[derive(Debug, Clone)]
pub struct DataAvailability {
    rs_params: RSParams,
    chunk_size: usize,
    compression_enabled: bool,
    compression_level: i32,
    stored_chunks: Arc<Mutex<HashMap<Hash, HashMap<u32, DAChunk>>>>,
    chunk_providers: Arc<Mutex<HashMap<u32, Vec<Address>>>>,
    commitments: Arc<Mutex<HashMap<Hash, DACommitment>>>,
    active_challenges: Arc<Mutex<HashMap<Hash, DAChallenge>>>,
    windows: Arc<Mutex<VecDeque<DAWindow>>>,
    sample_cache: Arc<Mutex<HashMap<Hash, Vec<DAChunk>>>>,
    verified_proofs: Arc<Mutex<HashSet<Hash>>>,
    provider_performance: Arc<Mutex<HashMap<Address, ProviderMetrics>>>,
    cellular_safe_config: CellularSafeConfig,
    sla_ms: u32,
    max_windows: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct RSParams {
    pub k: usize,
    pub m: usize,
    pub n: usize,
}

#[derive(Debug, Clone)]
pub struct CellularSafeConfig {
    pub enabled: bool,
    pub max_chunk_size: usize,
    pub max_batch_size: usize,
    pub compression_required: bool,
    pub monthly_limit_bytes: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ProviderMetrics {
    pub chunks_served: u64,
    pub chunks_failed: u64,
    pub avg_response_time_ms: u32,
    pub last_activity: Timestamp,
    pub reputation_score: f64,
    pub total_bandwidth_served: u64,
}

impl Default for CellularSafeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_chunk_size: 1024 * 256,
            max_batch_size: 100,
            compression_required: true,
            monthly_limit_bytes: 50 * 1024 * 1024 * 1024,
        }
    }
}

impl DataAvailability {
    pub fn new(
        k: usize,
        m: usize,
        chunk_size: usize,
        compression_enabled: bool,
        compression_level: i32,
        cellular_safe_config: CellularSafeConfig,
        sla_ms: u32,
    ) -> RollupResult<Self> {
        if k == 0 || m == 0 {
            return Err(RollupError::DataAvailability(
                "k and m must be greater than 0".to_string(),
            ));
        }

        if chunk_size == 0 {
            return Err(RollupError::DataAvailability(
                "chunk_size must be greater than 0".to_string(),
            ));
        }

        let n = k + m;
        let rs_params = RSParams { k, m, n };

        Ok(Self {
            rs_params,
            chunk_size,
            compression_enabled,
            compression_level,
            stored_chunks: Arc::new(Mutex::new(HashMap::new())),
            chunk_providers: Arc::new(Mutex::new(HashMap::new())),
            commitments: Arc::new(Mutex::new(HashMap::new())),
            active_challenges: Arc::new(Mutex::new(HashMap::new())),
            windows: Arc::new(Mutex::new(VecDeque::new())),
            sample_cache: Arc::new(Mutex::new(HashMap::new())),
            verified_proofs: Arc::new(Mutex::new(HashSet::new())),
            provider_performance: Arc::new(Mutex::new(HashMap::new())),
            cellular_safe_config,
            sla_ms,
            max_windows: 1000,
        })
    }

    pub fn encode_data(
        &self,
        commitment_hash: Hash,
        data: Vec<u8>,
        rollup_id: String,
        operator: Address,
        epoch: u64,
        block_height: BlockHeight,
        shard_id: ShardId,
        proof_batch_hash: Hash,
    ) -> RollupResult<Vec<DAChunk>> {
        let original_size = data.len();

        if self.cellular_safe_config.enabled {
            self.validate_cellular_constraints(original_size)?;
        }

        let processed_data = if self.compression_enabled {
            zstd::encode_all(&data[..], self.compression_level)
                .map_err(|e| RollupError::DataAvailability(format!("Compression failed: {}", e)))?
        } else {
            data
        };

        let compressed_size = processed_data.len();
        let mut padded_data = processed_data;
        let chunk_data_size = self.chunk_size;
        let total_data_chunks = (padded_data.len() + chunk_data_size - 1) / chunk_data_size;
        let required_size = total_data_chunks * chunk_data_size;

        if padded_data.len() < required_size {
            padded_data.resize(required_size, 0);
        }

        let mut data_chunks = Vec::new();
        for chunk_data in padded_data.chunks(chunk_data_size) {
            data_chunks.push(chunk_data.to_vec());
        }

        while data_chunks.len() < self.rs_params.k {
            data_chunks.push(vec![0u8; chunk_data_size]);
        }
        data_chunks.truncate(self.rs_params.k);

        let rs = ReedSolomon::new(self.rs_params.k, self.rs_params.m)
            .map_err(|e| RollupError::DataAvailability(format!("RS creation failed: {}", e)))?;

        let mut all_chunks = data_chunks.clone();
        all_chunks.resize(self.rs_params.n, vec![0u8; chunk_data_size]);

        rs.encode(&mut all_chunks)
            .map_err(|e| RollupError::DataAvailability(format!("RS encoding failed: {}", e)))?;

        let mut da_chunks = Vec::new();
        let timestamp = Timestamp::now();

        for (i, chunk_data) in all_chunks.iter().enumerate() {
            let is_parity = i >= self.rs_params.k;
            let chunk_hash = ego_core::crypto::hash_data(chunk_data);

            let da_chunk = DAChunk {
                chunk_id: i as u32,
                commitment_hash,
                data: chunk_data.clone(),
                is_parity,
                chunk_hash,
                timestamp,
                provider: Some(operator),
                replica_count: 1,
                access_count: 0,
                shard_id,
                epoch,
            };

            da_chunks.push(da_chunk);
        }

        let mut stored_chunks = self.stored_chunks.lock().unwrap();
        stored_chunks.insert(
            commitment_hash,
            da_chunks
                .iter()
                .map(|chunk| (chunk.chunk_id, chunk.clone()))
                .collect(),
        );
        drop(stored_chunks);

        let all_hashes: Vec<Vec<u8>> = da_chunks.iter().map(|c| c.chunk_hash.to_vec()).collect();
        let merkle_tree = ego_core::crypto::MerkleTree::build(all_hashes);
        let data_root = merkle_tree
            .root_hash()
            .unwrap_or_else(|| Hash::new([0u8; 32]));

        let cellular_safe_verified = if self.cellular_safe_config.enabled {
            self.verify_cellular_safe_commitment(original_size, compressed_size)
        } else {
            true
        };

        let commitment = DACommitment {
            commitment_hash,
            data_root,
            chunk_count: da_chunks.len() as u32,
            original_size,
            compressed_size,
            rs_params: self.rs_params.clone(),
            timestamp,
            epoch,
            block_height,
            rollup_id,
            operator,
            shard_id,
            proof_batch_hash,
            cellular_safe_verified,
        };

        let mut commitments = self.commitments.lock().unwrap();
        commitments.insert(commitment_hash, commitment);
        drop(commitments);

        self.update_provider_metrics(operator, da_chunks.len() as u64, 0);

        Ok(da_chunks)
    }

    pub fn decode_data(
        &self,
        commitment_hash: Hash,
        available_chunks: Vec<DAChunk>,
    ) -> RollupResult<Vec<u8>> {
        if available_chunks.len() < self.rs_params.k {
            return Err(RollupError::DataAvailability(format!(
                "Insufficient chunks for decoding: need {}, have {}",
                self.rs_params.k,
                available_chunks.len()
            )));
        }

        for chunk in &available_chunks {
            if chunk.commitment_hash != commitment_hash {
                return Err(RollupError::DataAvailability(
                    "Chunk commitment hash mismatch".to_string(),
                ));
            }

            let computed_hash = ego_core::crypto::hash_data(&chunk.data);
            if computed_hash != chunk.chunk_hash {
                return Err(RollupError::DataAvailability(format!(
                    "Chunk {} integrity check failed",
                    chunk.chunk_id
                )));
            }
        }

        let mut sorted_chunks = available_chunks;
        sorted_chunks.sort_by_key(|chunk| chunk.chunk_id);

        let chunk_size = sorted_chunks[0].data.len();
        let mut reconstruction_data: Vec<Option<Vec<u8>>> = vec![None; self.rs_params.n];

        for chunk in &sorted_chunks {
            let idx = chunk.chunk_id as usize;
            if idx < self.rs_params.n {
                reconstruction_data[idx] = Some(chunk.data.clone());
            }
        }

        let rs = ReedSolomon::new(self.rs_params.k, self.rs_params.m)
            .map_err(|e| RollupError::DataAvailability(format!("RS creation failed: {}", e)))?;

        rs.reconstruct(&mut reconstruction_data).map_err(|e| {
            RollupError::DataAvailability(format!("RS reconstruction failed: {}", e))
        })?;

        let mut decoded_data = Vec::new();
        for i in 0..self.rs_params.k {
            if let Some(chunk_data) = &reconstruction_data[i] {
                decoded_data.extend_from_slice(chunk_data);
            }
        }

        let final_data = if self.compression_enabled {
            zstd::decode_all(&decoded_data[..]).map_err(|e| {
                RollupError::DataAvailability(format!("Decompression failed: {}", e))
            })?
        } else {
            decoded_data
        };

        Ok(final_data)
    }

    pub fn sample_chunks(
        &self,
        commitment_hash: Hash,
        sample_indices: Vec<u32>,
    ) -> RollupResult<Vec<DAChunk>> {
        let mut stored_chunks = self.stored_chunks.lock().unwrap();
        let chunks = stored_chunks
            .get_mut(&commitment_hash)
            .ok_or_else(|| RollupError::DataAvailability("Commitment not found".to_string()))?;

        let mut sampled_chunks = Vec::new();
        for &index in &sample_indices {
            if let Some(chunk) = chunks.get_mut(&index) {
                chunk.access_count += 1;
                sampled_chunks.push(chunk.clone());
            } else {
                return Err(RollupError::DataAvailability(format!(
                    "Chunk {} not available for sampling",
                    index
                )));
            }
        }
        drop(stored_chunks);

        let mut sample_cache = self.sample_cache.lock().unwrap();
        sample_cache.insert(commitment_hash, sampled_chunks.clone());
        drop(sample_cache);

        Ok(sampled_chunks)
    }

    pub fn generate_da_proof(
        &self,
        commitment_hash: Hash,
        chunk_indices: Vec<u32>,
        prover: Address,
        signature: Vec<u8>,
        alg_sig_id: u16,
    ) -> RollupResult<DAProof> {
        let stored_chunks = self.stored_chunks.lock().unwrap();
        let chunks = stored_chunks
            .get(&commitment_hash)
            .ok_or_else(|| RollupError::DataAvailability("Commitment not found".to_string()))?;

        let mut chunk_hashes = Vec::new();
        for &index in &chunk_indices {
            if let Some(chunk) = chunks.get(&index) {
                chunk_hashes.push(chunk.chunk_hash);
            } else {
                return Err(RollupError::DataAvailability(format!(
                    "Chunk {} not found",
                    index
                )));
            }
        }

        let all_hashes: Vec<Vec<u8>> = chunks
            .values()
            .map(|chunk| chunk.chunk_hash.to_vec())
            .collect();

        let merkle_tree = ego_core::crypto::MerkleTree::build(all_hashes);
        let root_hash = merkle_tree.root_hash().ok_or_else(|| {
            RollupError::DataAvailability("Failed to compute Merkle root".to_string())
        })?;

        let merkle_proof = Vec::new();

        Ok(DAProof {
            commitment_hash,
            chunk_indices,
            chunk_hashes,
            merkle_proof,
            root_hash,
            proof_timestamp: Timestamp::now(),
            prover,
            signature,
            alg_sig_id,
        })
    }

    pub fn verify_da_proof(&self, proof: &DAProof) -> RollupResult<bool> {
        if proof.chunk_indices.len() != proof.chunk_hashes.len() {
            return Ok(false);
        }

        let stored_chunks = self.stored_chunks.lock().unwrap();
        if let Some(chunks) = stored_chunks.get(&proof.commitment_hash) {
            for (&index, &expected_hash) in
                proof.chunk_indices.iter().zip(proof.chunk_hashes.iter())
            {
                if let Some(chunk) = chunks.get(&index) {
                    if chunk.chunk_hash != expected_hash {
                        return Ok(false);
                    }
                } else {
                    return Ok(false);
                }
            }

            let all_hashes: Vec<Vec<u8>> = chunks.values().map(|c| c.chunk_hash.to_vec()).collect();
            let merkle_tree = ego_core::crypto::MerkleTree::build(all_hashes);
            let computed_root = merkle_tree.root_hash().ok_or_else(|| {
                RollupError::DataAvailability("Failed to compute Merkle root".to_string())
            })?;

            if computed_root != proof.root_hash {
                return Ok(false);
            }

            let proof_hash = ego_core::crypto::hash_data(
                &bincode::encode_to_vec(proof, bincode::config::standard()).map_err(|e| {
                    RollupError::DataAvailability(format!("Proof encoding failed: {}", e))
                })?,
            );

            let mut verified_proofs = self.verified_proofs.lock().unwrap();
            verified_proofs.insert(proof_hash);
            drop(verified_proofs);

            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn create_unavailability_proof(
        &self,
        commitment_hash: Hash,
        sample_indices: Vec<u32>,
        challenger: Address,
        challenge_bond: Balance,
        signature: Vec<u8>,
    ) -> RollupResult<DAUnavailabilityProof> {
        let mut missing_chunks = Vec::new();
        let mut failed_requests = Vec::new();
        let mut expected_providers = Vec::new();

        let stored_chunks = self.stored_chunks.lock().unwrap();
        let chunk_providers = self.chunk_providers.lock().unwrap();

        if let Some(chunks) = stored_chunks.get(&commitment_hash) {
            for &index in &sample_indices {
                if !chunks.contains_key(&index) {
                    missing_chunks.push(index);

                    if let Some(providers) = chunk_providers.get(&index) {
                        expected_providers.extend(providers.clone());

                        for provider in providers {
                            failed_requests.push(FailedRequest {
                                chunk_id: index,
                                operator: *provider,
                                request_time: Timestamp::now(),
                                timeout_time: Timestamp::now(),
                                error: "Chunk not available".to_string(),
                                retry_count: 3,
                                last_attempt: Timestamp::now(),
                            });
                        }
                    } else {
                        failed_requests.push(FailedRequest {
                            chunk_id: index,
                            operator: Address::new([0u8; 20]),
                            request_time: Timestamp::now(),
                            timeout_time: Timestamp::now(),
                            error: "No provider registered".to_string(),
                            retry_count: 0,
                            last_attempt: Timestamp::now(),
                        });
                    }
                }
            }
        } else {
            missing_chunks = sample_indices.clone();

            for &index in &sample_indices {
                failed_requests.push(FailedRequest {
                    chunk_id: index,
                    operator: Address::new([0u8; 20]),
                    request_time: Timestamp::now(),
                    timeout_time: Timestamp::now(),
                    error: "Commitment not found".to_string(),
                    retry_count: 0,
                    last_attempt: Timestamp::now(),
                });
            }
        }

        drop(stored_chunks);
        drop(chunk_providers);

        if missing_chunks.is_empty() {
            return Err(RollupError::DataAvailability(
                "All chunks are available - cannot create unavailability proof".to_string(),
            ));
        }

        let evidence_data = bincode::encode_to_vec(
            &(&missing_chunks, &failed_requests),
            bincode::config::standard(),
        )
        .map_err(|e| RollupError::DataAvailability(format!("Evidence encoding failed: {}", e)))?;

        let evidence_root = ego_core::crypto::hash_data(&evidence_data);

        Ok(DAUnavailabilityProof {
            commitment_hash,
            missing_chunks,
            sample_indices,
            failed_requests,
            timestamp: Timestamp::now(),
            challenger,
            challenge_bond,
            expected_providers,
            evidence_root,
            signature,
        })
    }

    pub fn register_chunk_provider(&self, chunk_id: u32, provider: Address) {
        let mut chunk_providers = self.chunk_providers.lock().unwrap();
        chunk_providers
            .entry(chunk_id)
            .or_insert_with(Vec::new)
            .push(provider);
    }

    pub fn get_chunk_providers(&self, chunk_id: u32) -> Vec<Address> {
        let chunk_providers = self.chunk_providers.lock().unwrap();
        chunk_providers
            .get(&chunk_id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn calculate_storage_size(&self, data_size: usize) -> usize {
        let compressed_size = if self.compression_enabled {
            (data_size as f64 * 0.7) as usize
        } else {
            data_size
        };

        let chunks_needed = (compressed_size + self.chunk_size - 1) / self.chunk_size;
        let padded_size = chunks_needed * self.chunk_size;

        padded_size * self.rs_params.n / self.rs_params.k
    }

    pub fn redundancy_factor(&self) -> f64 {
        self.rs_params.n as f64 / self.rs_params.k as f64
    }

    pub fn can_recover(&self, available_chunk_count: usize) -> bool {
        available_chunk_count >= self.rs_params.k
    }

    pub fn create_sampling_request(
        &self,
        commitment_hash: Hash,
        sample_size: u32,
        random_seed: [u8; 32],
        requester: Address,
        deadline_epoch: u64,
        shard_id: ShardId,
        priority: u8,
    ) -> RollupResult<DASamplingRequest> {
        let commitments = self.commitments.lock().unwrap();
        if !commitments.contains_key(&commitment_hash) {
            return Err(RollupError::DataAvailability(
                "Commitment not found".to_string(),
            ));
        }
        drop(commitments);

        Ok(DASamplingRequest {
            commitment_hash,
            sample_size,
            random_seed,
            requester,
            deadline_epoch,
            shard_id,
            priority,
        })
    }

    pub fn respond_to_sampling(
        &self,
        request: &DASamplingRequest,
        responder: Address,
        signature: Vec<u8>,
    ) -> RollupResult<DASamplingResponse> {
        let start_time = std::time::Instant::now();

        let sample_indices = self.generate_sample_indices(
            request.commitment_hash,
            request.sample_size,
            &request.random_seed,
        )?;

        let chunks = self.sample_chunks(request.commitment_hash, sample_indices.clone())?;

        let proof = self.generate_da_proof(
            request.commitment_hash,
            sample_indices,
            responder,
            signature.clone(),
            1,
        )?;

        let response_time_ms = start_time.elapsed().as_millis() as u32;
        let latency_within_sla = response_time_ms <= self.sla_ms;

        let request_hash = ego_core::crypto::hash_data(
            &bincode::encode_to_vec(request, bincode::config::standard()).map_err(|e| {
                RollupError::DataAvailability(format!("Request encoding failed: {}", e))
            })?,
        );

        self.update_provider_metrics(responder, chunks.len() as u64, response_time_ms);

        Ok(DASamplingResponse {
            request_hash,
            chunks,
            proof,
            responder,
            response_time_ms,
            latency_within_sla,
            signature,
        })
    }

    fn generate_sample_indices(
        &self,
        commitment_hash: Hash,
        sample_size: u32,
        random_seed: &[u8; 32],
    ) -> RollupResult<Vec<u32>> {
        let commitments = self.commitments.lock().unwrap();
        let commitment = commitments
            .get(&commitment_hash)
            .ok_or_else(|| RollupError::DataAvailability("Commitment not found".to_string()))?;

        let chunk_count = commitment.chunk_count;
        drop(commitments);

        if sample_size > chunk_count {
            return Err(RollupError::DataAvailability(
                "Sample size exceeds chunk count".to_string(),
            ));
        }

        let mut indices = Vec::new();
        let mut seed_data = random_seed.to_vec();
        seed_data.extend_from_slice(commitment_hash.as_bytes());

        for i in 0..sample_size {
            seed_data.extend_from_slice(&i.to_le_bytes());
            let hash = ego_core::crypto::hash_data(&seed_data);
            let index = u32::from_le_bytes([
                hash.as_bytes()[0],
                hash.as_bytes()[1],
                hash.as_bytes()[2],
                hash.as_bytes()[3],
            ]) % chunk_count;

            if !indices.contains(&index) {
                indices.push(index);
            }
        }

        Ok(indices)
    }

    pub fn create_challenge(
        &self,
        commitment_hash: Hash,
        challenger: Address,
        challenge_type: ChallengeType,
        sample_size: u32,
        deadline_epoch: u64,
        bond: Balance,
    ) -> RollupResult<DAChallenge> {
        let commitments = self.commitments.lock().unwrap();
        if !commitments.contains_key(&commitment_hash) {
            return Err(RollupError::DataAvailability(
                "Commitment not found".to_string(),
            ));
        }
        drop(commitments);

        let mut random_seed = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut random_seed);

        let sample_indices =
            self.generate_sample_indices(commitment_hash, sample_size, &random_seed)?;

        let challenge_data = bincode::encode_to_vec(
            &(
                commitment_hash,
                challenger,
                &sample_indices,
                Timestamp::now(),
            ),
            bincode::config::standard(),
        )
        .map_err(|e| RollupError::DataAvailability(format!("Encoding failed: {}", e)))?;

        let challenge_id = ego_core::crypto::hash_data(&challenge_data);

        let challenge = DAChallenge {
            challenge_id,
            commitment_hash,
            challenger,
            challenge_type,
            sample_indices,
            timestamp: Timestamp::now(),
            deadline_epoch,
            bond,
            status: ChallengeStatus::Pending,
            response_hash: None,
            slash_amount: None,
        };

        let mut active_challenges = self.active_challenges.lock().unwrap();
        active_challenges.insert(challenge_id, challenge.clone());
        drop(active_challenges);

        Ok(challenge)
    }

    pub fn resolve_challenge(
        &self,
        challenge_id: Hash,
        proof: DAProof,
    ) -> RollupResult<ChallengeStatus> {
        let mut active_challenges = self.active_challenges.lock().unwrap();
        let challenge = active_challenges
            .get(&challenge_id)
            .ok_or_else(|| RollupError::DataAvailability("Challenge not found".to_string()))?;

        if challenge.status != ChallengeStatus::Pending
            && challenge.status != ChallengeStatus::Responding
        {
            return Err(RollupError::DataAvailability(
                "Challenge already resolved".to_string(),
            ));
        }
        drop(active_challenges);

        let verified = self.verify_da_proof(&proof)?;

        let mut active_challenges = self.active_challenges.lock().unwrap();
        let challenge = active_challenges
            .get_mut(&challenge_id)
            .ok_or_else(|| RollupError::DataAvailability("Challenge not found".to_string()))?;

        challenge.status = ChallengeStatus::Responding;

        let proof_hash = ego_core::crypto::hash_data(
            &bincode::encode_to_vec(&proof, bincode::config::standard())
                .map_err(|e| RollupError::DataAvailability(format!("Encoding failed: {}", e)))?,
        );
        challenge.response_hash = Some(proof_hash);

        if verified {
            challenge.status = ChallengeStatus::Resolved;
            Ok(ChallengeStatus::Resolved)
        } else {
            challenge.status = ChallengeStatus::Failed;
            Ok(ChallengeStatus::Failed)
        }
    }

    pub fn slash_on_unavailability(
        &self,
        challenge_id: Hash,
    ) -> RollupResult<(Address, Balance)> {
        let mut active_challenges = self.active_challenges.lock().unwrap();
        let challenge = active_challenges
            .get_mut(&challenge_id)
            .ok_or_else(|| RollupError::DataAvailability("Challenge not found".to_string()))?;

        if challenge.status != ChallengeStatus::Failed {
            return Err(RollupError::DataAvailability(
                "Challenge not in failed state".to_string(),
            ));
        }

        let commitment_hash = challenge.commitment_hash;
        drop(active_challenges);

        let commitments = self.commitments.lock().unwrap();
        let commitment = commitments
            .get(&commitment_hash)
            .ok_or_else(|| RollupError::DataAvailability("Commitment not found".to_string()))?;

        let operator = commitment.operator;
        drop(commitments);

        let mut active_challenges = self.active_challenges.lock().unwrap();
        let challenge = active_challenges.get_mut(&challenge_id).unwrap();

        let slash_amount = challenge
            .bond
            .checked_mul(2u128.into())
            .unwrap_or(challenge.bond);

        challenge.status = ChallengeStatus::Slashed;
        challenge.slash_amount = Some(slash_amount);

        Ok((operator, slash_amount))
    }

    pub fn create_window(
        &self,
        start_epoch: u64,
        end_epoch: u64,
        challenge_period: u64,
        shard_id: ShardId,
    ) -> DAWindow {
        let window = DAWindow {
            start_epoch,
            end_epoch,
            commitments: Vec::new(),
            challenge_period,
            active_challenges: HashMap::new(),
            finalized: false,
            shard_id,
        };

        let mut windows = self.windows.lock().unwrap();
        windows.push_back(window.clone());

        while windows.len() > self.max_windows {
            windows.pop_front();
        }
        drop(windows);

        window
    }

    pub fn add_commitment_to_window(&self, window_index: usize, commitment_hash: Hash) {
        let mut windows = self.windows.lock().unwrap();
        if let Some(window) = windows.get_mut(window_index) {
            window.commitments.push(commitment_hash);
        }
    }

    pub fn finalize_window(&self, window_index: usize) -> RollupResult<()> {
        let mut windows = self.windows.lock().unwrap();
        if let Some(window) = windows.get_mut(window_index) {
            window.finalized = true;
            Ok(())
        } else {
            Err(RollupError::DataAvailability(
                "Window not found".to_string(),
            ))
        }
    }

    pub fn get_active_window(&self, current_epoch: u64) -> Option<DAWindow> {
        let windows = self.windows.lock().unwrap();
        windows
            .iter()
            .find(|w| current_epoch >= w.start_epoch && current_epoch <= w.end_epoch)
            .cloned()
    }

    pub fn get_commitment(&self, commitment_hash: Hash) -> Option<DACommitment> {
        let commitments = self.commitments.lock().unwrap();
        commitments.get(&commitment_hash).cloned()
    }

    pub fn get_chunk(&self, commitment_hash: Hash, chunk_id: u32) -> Option<DAChunk> {
        let stored_chunks = self.stored_chunks.lock().unwrap();
        stored_chunks
            .get(&commitment_hash)
            .and_then(|chunks| chunks.get(&chunk_id))
            .cloned()
    }

    pub fn prune_old_data(&self, cutoff_epoch: u64) -> usize {
        let mut pruned_count = 0;

        let mut commitments = self.commitments.lock().unwrap();
        let expired_commitments: Vec<Hash> = commitments
            .iter()
            .filter(|(_, c)| c.epoch < cutoff_epoch)
            .map(|(h, _)| *h)
            .collect();

        let mut stored_chunks = self.stored_chunks.lock().unwrap();
        for commitment_hash in expired_commitments {
            if stored_chunks.remove(&commitment_hash).is_some() {
                pruned_count += 1;
            }
            commitments.remove(&commitment_hash);

            let mut sample_cache = self.sample_cache.lock().unwrap();
            sample_cache.remove(&commitment_hash);
            drop(sample_cache);
        }
        drop(stored_chunks);
        drop(commitments);

        let mut windows = self.windows.lock().unwrap();
        windows.retain(|w| w.end_epoch >= cutoff_epoch);
        drop(windows);

        let mut active_challenges = self.active_challenges.lock().unwrap();
        let expired_challenges: Vec<Hash> = active_challenges
            .iter()
            .filter(|(_, c)| c.deadline_epoch < cutoff_epoch)
            .map(|(h, _)| *h)
            .collect();

        for challenge_id in expired_challenges {
            active_challenges.remove(&challenge_id);
        }
        drop(active_challenges);

        pruned_count
    }

    pub fn get_storage_stats(&self) -> DAStorageStats {
        let commitments = self.commitments.lock().unwrap();
        let stored_chunks = self.stored_chunks.lock().unwrap();
        let active_challenges = self.active_challenges.lock().unwrap();
        let verified_proofs = self.verified_proofs.lock().unwrap();

        let total_commitments = commitments.len();
        let total_chunks: usize = stored_chunks.values().map(|c| c.len()).sum();

        let total_data_size: usize = stored_chunks
            .values()
            .flat_map(|chunks| chunks.values())
            .map(|chunk| chunk.data.len())
            .sum();

        let total_original_size: usize = commitments.values().map(|c| c.original_size).sum();

        let total_compressed_size: usize = commitments.values().map(|c| c.compressed_size).sum();

        let active_challenges_count = active_challenges.len();

        let verified_proofs_count = verified_proofs.len();

        DAStorageStats {
            total_commitments,
            total_chunks,
            total_data_size,
            total_original_size,
            total_compressed_size,
            active_challenges: active_challenges_count,
            verified_proofs: verified_proofs_count,
            compression_ratio: if total_original_size > 0 {
                total_compressed_size as f64 / total_original_size as f64
            } else {
                1.0
            },
            redundancy_factor: self.redundancy_factor(),
        }
    }

    pub fn estimate_bandwidth_cost(&self, commitment_hash: Hash) -> RollupResult<u64> {
        let commitments = self.commitments.lock().unwrap();
        let commitment = commitments
            .get(&commitment_hash)
            .ok_or_else(|| RollupError::DataAvailability("Commitment not found".to_string()))?;

        let chunk_count = commitment.chunk_count as u64;
        let avg_chunk_size = self.chunk_size as u64;
        let total_bandwidth = chunk_count * avg_chunk_size;

        let upload_cost = total_bandwidth;
        let download_cost = total_bandwidth * 2 / 3;
        let sampling_cost = (chunk_count / 10) * avg_chunk_size;

        Ok(upload_cost + download_cost + sampling_cost)
    }

    pub fn validate_cellular_safe(&self, commitment_hash: Hash) -> RollupResult<bool> {
        if !self.cellular_safe_config.enabled {
            return Ok(true);
        }

        let bandwidth_cost = self.estimate_bandwidth_cost(commitment_hash)?;
        let cellular_limit = self.cellular_safe_config.monthly_limit_bytes / 30;

        Ok(bandwidth_cost <= cellular_limit)
    }

    fn validate_cellular_constraints(&self, data_size: usize) -> RollupResult<()> {
        if !self.cellular_safe_config.enabled {
            return Ok(());
        }

        if data_size > self.cellular_safe_config.max_chunk_size * self.cellular_safe_config.max_batch_size {
            return Err(RollupError::DataAvailability(
                "Data size exceeds cellular-safe limits".to_string(),
            ));
        }

        if self.cellular_safe_config.compression_required && !self.compression_enabled {
            return Err(RollupError::DataAvailability(
                "Compression required for cellular-safe mode".to_string(),
            ));
        }

        Ok(())
    }

    fn verify_cellular_safe_commitment(&self, original_size: usize, compressed_size: usize) -> bool {
        if !self.cellular_safe_config.enabled {
            return true;
        }

        let compression_ratio = compressed_size as f64 / original_size as f64;
        compression_ratio <= 0.8 && compressed_size <= self.cellular_safe_config.max_chunk_size * self.cellular_safe_config.max_batch_size
    }

    fn update_provider_metrics(&self, provider: Address, chunks_served: u64, response_time_ms: u32) {
        let mut provider_performance = self.provider_performance.lock().unwrap();
        let metrics = provider_performance.entry(provider).or_insert_with(ProviderMetrics::default);

        metrics.chunks_served += chunks_served;
        metrics.last_activity = Timestamp::now();
        metrics.total_bandwidth_served += chunks_served * self.chunk_size as u64;

        if response_time_ms > 0 {
            let total_responses = metrics.chunks_served;
            metrics.avg_response_time_ms =
                ((metrics.avg_response_time_ms as u64 * (total_responses - chunks_served) + response_time_ms as u64 * chunks_served) / total_responses) as u32;
        }

        let success_rate = metrics.chunks_served as f64 / (metrics.chunks_served + metrics.chunks_failed).max(1) as f64;
        let latency_score = if metrics.avg_response_time_ms <= self.sla_ms {
            1.0
        } else {
            self.sla_ms as f64 / metrics.avg_response_time_ms as f64
        };

        metrics.reputation_score = (success_rate * 0.7 + latency_score * 0.3).clamp(0.0, 1.0);
    }

    pub fn get_provider_metrics(&self, provider: &Address) -> Option<ProviderMetrics> {
        let provider_performance = self.provider_performance.lock().unwrap();
        provider_performance.get(provider).cloned()
    }

    pub fn get_top_providers(&self, limit: usize) -> Vec<(Address, ProviderMetrics)> {
        let provider_performance = self.provider_performance.lock().unwrap();
        let mut providers: Vec<(Address, ProviderMetrics)> = provider_performance
            .iter()
            .map(|(addr, metrics)| (*addr, metrics.clone()))
            .collect();

        providers.sort_by(|a, b| b.1.reputation_score.partial_cmp(&a.1.reputation_score).unwrap());
        providers.truncate(limit);
        providers
    }

    pub fn expire_challenges(&self, current_epoch: u64) -> Vec<Hash> {
        let mut active_challenges = self.active_challenges.lock().unwrap();
        let mut expired = Vec::new();

        for (challenge_id, challenge) in active_challenges.iter_mut() {
            if challenge.deadline_epoch < current_epoch && challenge.status == ChallengeStatus::Pending {
                challenge.status = ChallengeStatus::Expired;
                expired.push(*challenge_id);
            }
        }

        expired
    }

    pub fn get_challenge(&self, challenge_id: &Hash) -> Option<DAChallenge> {
        let active_challenges = self.active_challenges.lock().unwrap();
        active_challenges.get(challenge_id).cloned()
    }

    pub fn get_challenges_for_commitment(&self, commitment_hash: Hash) -> Vec<DAChallenge> {
        let active_challenges = self.active_challenges.lock().unwrap();
        active_challenges
            .values()
            .filter(|c| c.commitment_hash == commitment_hash)
            .cloned()
            .collect()
    }

    pub fn validate_commitment_integrity(&self, commitment_hash: Hash) -> RollupResult<bool> {
        let commitments = self.commitments.lock().unwrap();
        let commitment = commitments
            .get(&commitment_hash)
            .ok_or_else(|| RollupError::DataAvailability("Commitment not found".to_string()))?;

        let stored_chunks = self.stored_chunks.lock().unwrap();
        let chunks = stored_chunks
            .get(&commitment_hash)
            .ok_or_else(|| RollupError::DataAvailability("Chunks not found".to_string()))?;

        for chunk in chunks.values() {
            let computed_hash = ego_core::crypto::hash_data(&chunk.data);
            if computed_hash != chunk.chunk_hash {
                return Ok(false);
            }
        }

        let all_hashes: Vec<Vec<u8>> = chunks.values().map(|c| c.chunk_hash.to_vec()).collect();
        let merkle_tree = ego_core::crypto::MerkleTree::build(all_hashes);
        let computed_root = merkle_tree.root_hash().ok_or_else(|| {
            RollupError::DataAvailability("Failed to compute Merkle root".to_string())
        })?;

        Ok(computed_root == commitment.data_root)
    }

    pub fn get_commitments_by_epoch(&self, epoch: u64) -> Vec<DACommitment> {
        let commitments = self.commitments.lock().unwrap();
        commitments
            .values()
            .filter(|c| c.epoch == epoch)
            .cloned()
            .collect()
    }

    pub fn get_commitments_by_shard(&self, shard_id: ShardId) -> Vec<DACommitment> {
        let commitments = self.commitments.lock().unwrap();
        commitments
            .values()
            .filter(|c| c.shard_id == shard_id)
            .cloned()
            .collect()
    }

    pub fn get_commitments_by_operator(&self, operator: Address) -> Vec<DACommitment> {
        let commitments = self.commitments.lock().unwrap();
        commitments
            .values()
            .filter(|c| c.operator == operator)
            .cloned()
            .collect()
    }

    pub fn record_chunk_failure(&self, provider: Address, chunk_id: u32) {
        let mut provider_performance = self.provider_performance.lock().unwrap();
        let metrics = provider_performance.entry(provider).or_insert_with(ProviderMetrics::default);
        metrics.chunks_failed += 1;

        let success_rate = metrics.chunks_served as f64 / (metrics.chunks_served + metrics.chunks_failed).max(1) as f64;
        let latency_score = if metrics.avg_response_time_ms <= self.sla_ms {
            1.0
        } else {
            self.sla_ms as f64 / metrics.avg_response_time_ms as f64
        };

        metrics.reputation_score = (success_rate * 0.7 + latency_score * 0.3).clamp(0.0, 1.0);
    }

    pub fn get_window_by_epoch(&self, epoch: u64) -> Option<DAWindow> {
        let windows = self.windows.lock().unwrap();
        windows
            .iter()
            .find(|w| epoch >= w.start_epoch && epoch <= w.end_epoch)
            .cloned()
    }

    pub fn count_active_commitments(&self) -> usize {
        let commitments = self.commitments.lock().unwrap();
        commitments.len()
    }

    pub fn count_active_challenges(&self) -> usize {
        let active_challenges = self.active_challenges.lock().unwrap();
        active_challenges
            .values()
            .filter(|c| c.status == ChallengeStatus::Pending || c.status == ChallengeStatus::Responding)
            .count()
    }

    pub fn get_sla_ms(&self) -> u32 {
        self.sla_ms
    }

    pub fn get_rs_params(&self) -> RSParams {
        self.rs_params.clone()
    }

    pub fn is_compression_enabled(&self) -> bool {
        self.compression_enabled
    }

    pub fn get_cellular_safe_config(&self) -> CellularSafeConfig {
        self.cellular_safe_config.clone()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DAStorageStats {
    pub total_commitments: usize,
    pub total_chunks: usize,
    pub total_data_size: usize,
    pub total_original_size: usize,
    pub total_compressed_size: usize,
    pub active_challenges: usize,
    pub verified_proofs: usize,
    pub compression_ratio: f64,
    pub redundancy_factor: f64,
}

impl DAChunk {
    pub fn verify_integrity(&self) -> bool {
        let computed_hash = ego_core::crypto::hash_data(&self.data);
        computed_hash == self.chunk_hash
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }

    pub fn is_available(&self) -> bool {
        self.provider.is_some() && self.replica_count > 0
    }

    pub fn age_seconds(&self) -> u64 {
        let now = Timestamp::now();
        (now.as_millis().saturating_sub(self.timestamp.as_millis())) / 1000
    }
}

impl DAUnavailabilityProof {
    pub fn validate(&self) -> RollupResult<()> {
        if self.missing_chunks.is_empty() {
            return Err(RollupError::DataAvailability(
                "No missing chunks in unavailability proof".to_string(),
            ));
        }

        if self.sample_indices.is_empty() {
            return Err(RollupError::DataAvailability(
                "No sample indices in unavailability proof".to_string(),
            ));
        }

        for &missing in &self.missing_chunks {
            if !self.sample_indices.contains(&missing) {
                return Err(RollupError::DataAvailability(
                    "Missing chunk not in sample indices".to_string(),
                ));
            }
        }

        if self.challenge_bond.as_u128() == 0 {
            return Err(RollupError::DataAvailability(
                "Challenge bond cannot be zero".to_string(),
            ));
        }

        Ok(())
    }

    pub fn missing_percentage(&self) -> f64 {
        if self.sample_indices.is_empty() {
            return 0.0;
        }

        self.missing_chunks.len() as f64 / self.sample_indices.len() as f64 * 100.0
    }

    pub fn is_critical(&self) -> bool {
        self.missing_percentage() > 30.0
    }
}

impl DACommitment {
    pub fn compression_ratio(&self) -> f64 {
        if self.original_size == 0 {
            return 1.0;
        }
        self.compressed_size as f64 / self.original_size as f64
    }

    pub fn storage_efficiency(&self) -> f64 {
        if self.original_size == 0 {
            return 0.0;
        }
        let actual_storage = self.chunk_count as usize * 1024;
        actual_storage as f64 / self.original_size as f64
    }

    pub fn age_seconds(&self) -> u64 {
        let now = Timestamp::now();
        (now.as_millis().saturating_sub(self.timestamp.as_millis())) / 1000
    }
}

impl DASamplingRequest {
    pub fn hash(&self) -> Hash {
        let config = bincode::config::standard();
        let encoded = bincode::encode_to_vec(self, config).unwrap_or_default();
        ego_core::crypto::hash_data(&encoded)
    }
}

impl DASamplingResponse {
    pub fn validate(&self, expected_sample_size: u32) -> RollupResult<()> {
        if self.chunks.len() != expected_sample_size as usize {
            return Err(RollupError::DataAvailability(
                "Sample size mismatch".to_string(),
            ));
        }

        if self.chunks.len() != self.proof.chunk_indices.len() {
            return Err(RollupError::DataAvailability(
                "Chunk count and proof indices mismatch".to_string(),
            ));
        }

        for chunk in &self.chunks {
            if !chunk.verify_integrity() {
                return Err(RollupError::DataAvailability(
                    "Chunk integrity check failed".to_string(),
                ));
            }
        }

        Ok(())
    }

    pub fn is_within_sla(&self, sla_ms: u32) -> bool {
        self.response_time_ms <= sla_ms
    }
}

impl DAChallenge {
    pub fn is_expired(&self, current_epoch: u64) -> bool {
        current_epoch > self.deadline_epoch
    }

    pub fn can_slash(&self, current_epoch: u64) -> bool {
        self.status == ChallengeStatus::Failed
            || (self.is_expired(current_epoch) && self.status == ChallengeStatus::Pending)
    }

    pub fn age_seconds(&self) -> u64 {
        let now = Timestamp::now();
        (now.as_millis().saturating_sub(self.timestamp.as_millis())) / 1000
    }
}

impl DAWindow {
    pub fn is_active(&self, current_epoch: u64) -> bool {
        current_epoch >= self.start_epoch && current_epoch <= self.end_epoch
    }

    pub fn in_challenge_period(&self, current_epoch: u64) -> bool {
        current_epoch <= self.end_epoch + self.challenge_period
    }

    pub fn add_challenge(&mut self, commitment_hash: Hash, challenger: Address) {
        self.active_challenges
            .entry(commitment_hash)
            .or_insert_with(Vec::new)
            .push(challenger);
    }

    pub fn commitment_count(&self) -> usize {
        self.commitments.len()
    }

    pub fn can_finalize(&self, current_epoch: u64) -> bool {
        !self.finalized && current_epoch > self.end_epoch + self.challenge_period
    }
}
