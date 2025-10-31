use crate::error::{RollupError, RollupResult};
use ego_core::{Address, Hash, Timestamp};
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use zstd;

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
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DAUnavailabilityProof {
    pub commitment_hash: Hash,
    pub missing_chunks: Vec<u32>,
    pub sample_indices: Vec<u32>,
    pub failed_requests: Vec<FailedRequest>,
    pub timestamp: Timestamp,
    pub challenger: Address,
    pub challenge_bond: u64,
    pub expected_providers: Vec<Address>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct FailedRequest {
    pub chunk_id: u32,
    pub operator: Address,
    pub request_time: Timestamp,
    pub timeout_time: Timestamp,
    pub error: String,
    pub retry_count: u32,
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
    pub rollup_id: String,
    pub operator: Address,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DASamplingRequest {
    pub commitment_hash: Hash,
    pub sample_size: u32,
    pub random_seed: [u8; 32],
    pub requester: Address,
    pub deadline_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DASamplingResponse {
    pub request_hash: Hash,
    pub chunks: Vec<DAChunk>,
    pub proof: DAProof,
    pub responder: Address,
    pub response_time_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DAWindow {
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub commitments: Vec<Hash>,
    pub challenge_period: u64,
    pub active_challenges: HashMap<Hash, Vec<Address>>,
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
    pub bond: u64,
    pub status: ChallengeStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum ChallengeType {
    Availability,
    Integrity,
    Performance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum ChallengeStatus {
    Pending,
    Responding,
    Resolved,
    Failed,
    Slashed,
}

#[derive(Debug, Clone)]
pub struct DataAvailability {
    rs_params: RSParams,
    chunk_size: usize,
    compression_enabled: bool,
    compression_level: i32,
    stored_chunks: HashMap<Hash, HashMap<u32, DAChunk>>,
    chunk_providers: HashMap<u32, Vec<Address>>,
    commitments: HashMap<Hash, DACommitment>,
    active_challenges: HashMap<Hash, DAChallenge>,
    windows: Vec<DAWindow>,
    sample_cache: HashMap<Hash, Vec<DAChunk>>,
    verified_proofs: HashSet<Hash>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct RSParams {
    pub k: usize,
    pub m: usize,
    pub n: usize,
}

impl DataAvailability {
    pub fn new(
        k: usize,
        m: usize,
        chunk_size: usize,
        compression_enabled: bool,
        compression_level: i32,
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
            stored_chunks: HashMap::new(),
            chunk_providers: HashMap::new(),
            commitments: HashMap::new(),
            active_challenges: HashMap::new(),
            windows: Vec::new(),
            sample_cache: HashMap::new(),
            verified_proofs: HashSet::new(),
        })
    }

    pub fn encode_data(
        &mut self,
        commitment_hash: Hash,
        data: Vec<u8>,
        rollup_id: String,
        operator: Address,
        epoch: u64,
    ) -> RollupResult<Vec<DAChunk>> {
        let original_size = data.len();

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
            };

            da_chunks.push(da_chunk);
        }

        self.stored_chunks.insert(
            commitment_hash,
            da_chunks
                .iter()
                .map(|chunk| (chunk.chunk_id, chunk.clone()))
                .collect(),
        );

        let all_hashes: Vec<Vec<u8>> = da_chunks.iter().map(|c| c.chunk_hash.to_vec()).collect();
        let merkle_tree = ego_core::crypto::MerkleTree::build(all_hashes);
        let data_root = merkle_tree
            .root_hash()
            .unwrap_or_else(|| Hash::new([0u8; 32]));

        let commitment = DACommitment {
            commitment_hash,
            data_root,
            chunk_count: da_chunks.len() as u32,
            original_size,
            compressed_size,
            rs_params: self.rs_params.clone(),
            timestamp,
            epoch,
            rollup_id,
            operator,
        };

        self.commitments.insert(commitment_hash, commitment);

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
        &mut self,
        commitment_hash: Hash,
        sample_indices: Vec<u32>,
    ) -> RollupResult<Vec<DAChunk>> {
        let chunks = self
            .stored_chunks
            .get(&commitment_hash)
            .ok_or_else(|| RollupError::DataAvailability("Commitment not found".to_string()))?;

        let mut sampled_chunks = Vec::new();
        for &index in &sample_indices {
            if let Some(mut chunk) = chunks.get(&index).cloned() {
                chunk.access_count += 1;
                sampled_chunks.push(chunk);
            } else {
                return Err(RollupError::DataAvailability(format!(
                    "Chunk {} not available for sampling",
                    index
                )));
            }
        }

        self.sample_cache
            .insert(commitment_hash, sampled_chunks.clone());

        Ok(sampled_chunks)
    }

    pub fn generate_da_proof(
        &self,
        commitment_hash: Hash,
        chunk_indices: Vec<u32>,
        prover: Address,
    ) -> RollupResult<DAProof> {
        let chunks = self
            .stored_chunks
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
        })
    }

    pub fn verify_da_proof(&mut self, proof: &DAProof) -> RollupResult<bool> {
        if proof.chunk_indices.len() != proof.chunk_hashes.len() {
            return Ok(false);
        }

        if let Some(chunks) = self.stored_chunks.get(&proof.commitment_hash) {
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
        challenge_bond: u64,
    ) -> RollupResult<DAUnavailabilityProof> {
        let mut missing_chunks = Vec::new();
        let mut failed_requests = Vec::new();
        let mut expected_providers = Vec::new();

        if let Some(chunks) = self.stored_chunks.get(&commitment_hash) {
            for &index in &sample_indices {
                if !chunks.contains_key(&index) {
                    missing_chunks.push(index);

                    if let Some(providers) = self.chunk_providers.get(&index) {
                        expected_providers.extend(providers.clone());

                        for provider in providers {
                            failed_requests.push(FailedRequest {
                                chunk_id: index,
                                operator: *provider,
                                request_time: Timestamp::now(),
                                timeout_time: Timestamp::now(),
                                error: "Chunk not available".to_string(),
                                retry_count: 3,
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
                });
            }
        }

        if missing_chunks.is_empty() {
            return Err(RollupError::DataAvailability(
                "All chunks are available - cannot create unavailability proof".to_string(),
            ));
        }

        Ok(DAUnavailabilityProof {
            commitment_hash,
            missing_chunks,
            sample_indices,
            failed_requests,
            timestamp: Timestamp::now(),
            challenger,
            challenge_bond,
            expected_providers,
        })
    }

    pub fn register_chunk_provider(&mut self, chunk_id: u32, provider: Address) {
        self.chunk_providers
            .entry(chunk_id)
            .or_insert_with(Vec::new)
            .push(provider);
    }

    pub fn get_chunk_providers(&self, chunk_id: u32) -> Vec<Address> {
        self.chunk_providers
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
    ) -> RollupResult<DASamplingRequest> {
        if !self.commitments.contains_key(&commitment_hash) {
            return Err(RollupError::DataAvailability(
                "Commitment not found".to_string(),
            ));
        }

        Ok(DASamplingRequest {
            commitment_hash,
            sample_size,
            random_seed,
            requester,
            deadline_epoch,
        })
    }

    pub fn respond_to_sampling(
        &mut self,
        request: &DASamplingRequest,
        responder: Address,
    ) -> RollupResult<DASamplingResponse> {
        let start_time = std::time::Instant::now();

        let sample_indices = self.generate_sample_indices(
            request.commitment_hash,
            request.sample_size,
            &request.random_seed,
        )?;

        let chunks = self.sample_chunks(request.commitment_hash, sample_indices.clone())?;

        let proof = self.generate_da_proof(request.commitment_hash, sample_indices, responder)?;

        let response_time_ms = start_time.elapsed().as_millis() as u32;

        let request_hash = ego_core::crypto::hash_data(
            &bincode::encode_to_vec(request, bincode::config::standard()).map_err(|e| {
                RollupError::DataAvailability(format!("Request encoding failed: {}", e))
            })?,
        );

        Ok(DASamplingResponse {
            request_hash,
            chunks,
            proof,
            responder,
            response_time_ms,
        })
    }

    fn generate_sample_indices(
        &self,
        commitment_hash: Hash,
        sample_size: u32,
        random_seed: &[u8; 32],
    ) -> RollupResult<Vec<u32>> {
        let commitment = self
            .commitments
            .get(&commitment_hash)
            .ok_or_else(|| RollupError::DataAvailability("Commitment not found".to_string()))?;

        let chunk_count = commitment.chunk_count;

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
        &mut self,
        commitment_hash: Hash,
        challenger: Address,
        challenge_type: ChallengeType,
        sample_size: u32,
        deadline_epoch: u64,
        bond: u64,
    ) -> RollupResult<DAChallenge> {
        if !self.commitments.contains_key(&commitment_hash) {
            return Err(RollupError::DataAvailability(
                "Commitment not found".to_string(),
            ));
        }

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
        };

        self.active_challenges
            .insert(challenge_id, challenge.clone());

        Ok(challenge)
    }

    pub fn resolve_challenge(
        &mut self,
        challenge_id: Hash,
        proof: DAProof,
    ) -> RollupResult<ChallengeStatus> {
        let challenge = self
            .active_challenges
            .get(&challenge_id)
            .ok_or_else(|| RollupError::DataAvailability("Challenge not found".to_string()))?;

        if challenge.status != ChallengeStatus::Pending
            && challenge.status != ChallengeStatus::Responding
        {
            return Err(RollupError::DataAvailability(
                "Challenge already resolved".to_string(),
            ));
        }

        let verified = self.verify_da_proof(&proof)?;

        let challenge = self
            .active_challenges
            .get_mut(&challenge_id)
            .ok_or_else(|| RollupError::DataAvailability("Challenge not found".to_string()))?;

        challenge.status = ChallengeStatus::Responding;

        if verified {
            challenge.status = ChallengeStatus::Resolved;
            Ok(ChallengeStatus::Resolved)
        } else {
            challenge.status = ChallengeStatus::Failed;
            Ok(ChallengeStatus::Failed)
        }
    }

    pub fn slash_on_unavailability(&mut self, challenge_id: Hash) -> RollupResult<(Address, u64)> {
        let challenge = self
            .active_challenges
            .get_mut(&challenge_id)
            .ok_or_else(|| RollupError::DataAvailability("Challenge not found".to_string()))?;

        if challenge.status != ChallengeStatus::Failed {
            return Err(RollupError::DataAvailability(
                "Challenge not in failed state".to_string(),
            ));
        }

        let commitment = self
            .commitments
            .get(&challenge.commitment_hash)
            .ok_or_else(|| RollupError::DataAvailability("Commitment not found".to_string()))?;

        let operator = commitment.operator;
        let slash_amount = challenge.bond * 2;

        challenge.status = ChallengeStatus::Slashed;

        Ok((operator, slash_amount))
    }

    pub fn create_window(
        &mut self,
        start_epoch: u64,
        end_epoch: u64,
        challenge_period: u64,
    ) -> DAWindow {
        let window = DAWindow {
            start_epoch,
            end_epoch,
            commitments: Vec::new(),
            challenge_period,
            active_challenges: HashMap::new(),
        };

        self.windows.push(window.clone());
        window
    }

    pub fn add_commitment_to_window(&mut self, window_index: usize, commitment_hash: Hash) {
        if let Some(window) = self.windows.get_mut(window_index) {
            window.commitments.push(commitment_hash);
        }
    }

    pub fn get_active_window(&self, current_epoch: u64) -> Option<&DAWindow> {
        self.windows
            .iter()
            .find(|w| current_epoch >= w.start_epoch && current_epoch <= w.end_epoch)
    }

    pub fn get_commitment(&self, commitment_hash: Hash) -> Option<&DACommitment> {
        self.commitments.get(&commitment_hash)
    }

    pub fn get_chunk(&self, commitment_hash: Hash, chunk_id: u32) -> Option<&DAChunk> {
        self.stored_chunks
            .get(&commitment_hash)
            .and_then(|chunks| chunks.get(&chunk_id))
    }

    pub fn prune_old_data(&mut self, cutoff_epoch: u64) -> usize {
        let mut pruned_count = 0;

        let expired_commitments: Vec<Hash> = self
            .commitments
            .iter()
            .filter(|(_, c)| c.epoch < cutoff_epoch)
            .map(|(h, _)| *h)
            .collect();

        for commitment_hash in expired_commitments {
            if self.stored_chunks.remove(&commitment_hash).is_some() {
                pruned_count += 1;
            }
            self.commitments.remove(&commitment_hash);
            self.sample_cache.remove(&commitment_hash);
        }

        self.windows.retain(|w| w.end_epoch >= cutoff_epoch);

        let expired_challenges: Vec<Hash> = self
            .active_challenges
            .iter()
            .filter(|(_, c)| c.deadline_epoch < cutoff_epoch)
            .map(|(h, _)| *h)
            .collect();

        for challenge_id in expired_challenges {
            self.active_challenges.remove(&challenge_id);
        }

        pruned_count
    }

    pub fn get_storage_stats(&self) -> DAStorageStats {
        let total_commitments = self.commitments.len();
        let total_chunks: usize = self.stored_chunks.values().map(|c| c.len()).sum();

        let total_data_size: usize = self
            .stored_chunks
            .values()
            .flat_map(|chunks| chunks.values())
            .map(|chunk| chunk.data.len())
            .sum();

        let total_original_size: usize = self.commitments.values().map(|c| c.original_size).sum();

        let total_compressed_size: usize =
            self.commitments.values().map(|c| c.compressed_size).sum();

        let active_challenges = self.active_challenges.len();

        let verified_proofs = self.verified_proofs.len();

        DAStorageStats {
            total_commitments,
            total_chunks,
            total_data_size,
            total_original_size,
            total_compressed_size,
            active_challenges,
            verified_proofs,
            compression_ratio: if total_original_size > 0 {
                total_compressed_size as f64 / total_original_size as f64
            } else {
                1.0
            },
            redundancy_factor: self.redundancy_factor(),
        }
    }

    pub fn estimate_bandwidth_cost(&self, commitment_hash: Hash) -> RollupResult<u64> {
        let commitment = self
            .commitments
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
        let commitment = self
            .commitments
            .get(&commitment_hash)
            .ok_or_else(|| RollupError::DataAvailability("Commitment not found".to_string()))?;

        let bandwidth_cost = self.estimate_bandwidth_cost(commitment_hash)?;
        let cellular_limit = 1024 * 1024 * 100;

        Ok(bandwidth_cost <= cellular_limit)
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

        if self.challenge_bond == 0 {
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
}
