use crate::error::{RollupError, RollupResult};
use ego_core::{Address, Hash, Timestamp};
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zstd;

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DAChunk {
    pub chunk_id: u32,
    pub commitment_hash: Hash,
    pub data: Vec<u8>,
    pub is_parity: bool,
    pub chunk_hash: Hash,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DAProof {
    pub commitment_hash: Hash,
    pub chunk_indices: Vec<u32>,
    pub chunk_hashes: Vec<Hash>,
    pub merkle_proof: Vec<Hash>,
    pub root_hash: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DAUnavailabilityProof {
    pub commitment_hash: Hash,
    pub missing_chunks: Vec<u32>,
    pub sample_indices: Vec<u32>,
    pub failed_requests: Vec<FailedRequest>,
    pub timestamp: Timestamp,
    pub challenger: Address,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct FailedRequest {
    pub chunk_id: u32,
    pub operator: Address,
    pub request_time: Timestamp,
    pub timeout_time: Timestamp,
    pub error: String,
}

#[derive(Debug, Clone)]
pub struct DataAvailability {
    rs_params: RSParams,
    chunk_size: usize,
    compression_enabled: bool,
    compression_level: i32,
    stored_chunks: HashMap<Hash, HashMap<u32, DAChunk>>,
    chunk_providers: HashMap<u32, Vec<Address>>,
}

#[derive(Debug, Clone)]
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

        let n = k + m;
        let rs_params = RSParams { k, m, n };

        Ok(Self {
            rs_params,
            chunk_size,
            compression_enabled,
            compression_level,
            stored_chunks: HashMap::new(),
            chunk_providers: HashMap::new(),
        })
    }

    pub fn encode_data(
        &mut self,
        commitment_hash: Hash,
        data: Vec<u8>,
    ) -> RollupResult<Vec<DAChunk>> {
        let processed_data = if self.compression_enabled {
            zstd::encode_all(&data[..], self.compression_level)
                .map_err(|e| RollupError::DataAvailability(format!("Compression failed: {}", e)))?
        } else {
            data
        };

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
        let chunks = self
            .stored_chunks
            .get(&commitment_hash)
            .ok_or_else(|| RollupError::DataAvailability("Commitment not found".to_string()))?;

        let mut sampled_chunks = Vec::new();
        for &index in &sample_indices {
            if let Some(chunk) = chunks.get(&index) {
                sampled_chunks.push(chunk.clone());
            } else {
                return Err(RollupError::DataAvailability(format!(
                    "Chunk {} not available for sampling",
                    index
                )));
            }
        }

        Ok(sampled_chunks)
    }

    pub fn generate_da_proof(
        &self,
        commitment_hash: Hash,
        chunk_indices: Vec<u32>,
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
        })
    }

    pub fn verify_da_proof(&self, proof: &DAProof) -> RollupResult<bool> {
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
    ) -> RollupResult<DAUnavailabilityProof> {
        let mut missing_chunks = Vec::new();
        let mut failed_requests = Vec::new();

        if let Some(chunks) = self.stored_chunks.get(&commitment_hash) {
            for &index in &sample_indices {
                if !chunks.contains_key(&index) {
                    missing_chunks.push(index);

                    failed_requests.push(FailedRequest {
                        chunk_id: index,
                        operator: Address::new([0u8; 20]),
                        request_time: Timestamp::now(),
                        timeout_time: Timestamp::now(),
                        error: "Chunk not available".to_string(),
                    });
                }
            }
        } else {
            missing_chunks = sample_indices.clone();
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
}

impl DAChunk {
    pub fn verify_integrity(&self) -> bool {
        let computed_hash = ego_core::crypto::hash_data(&self.data);
        computed_hash == self.chunk_hash
    }

    pub fn size(&self) -> usize {
        self.data.len()
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

        Ok(())
    }

    pub fn missing_percentage(&self) -> f64 {
        if self.sample_indices.is_empty() {
            return 0.0;
        }

        self.missing_chunks.len() as f64 / self.sample_indices.len() as f64 * 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_da_creation() {
        let da = DataAvailability::new(4, 2, 1024, false, 6).unwrap();
        assert_eq!(da.rs_params.k, 4);
        assert_eq!(da.rs_params.m, 2);
        assert_eq!(da.rs_params.n, 6);
        assert_eq!(da.redundancy_factor(), 1.5);
    }

    #[test]
    fn test_encode_decode() {
        let mut da = DataAvailability::new(4, 2, 256, false, 6).unwrap();
        let test_data = b"Hello, World! This is test data for DA encoding.".to_vec();
        let commitment_hash = Hash::new([1u8; 32]);

        let chunks = da.encode_data(commitment_hash, test_data.clone()).unwrap();
        assert_eq!(chunks.len(), 6);
        assert_eq!(chunks.iter().filter(|c| !c.is_parity).count(), 4);
        assert_eq!(chunks.iter().filter(|c| c.is_parity).count(), 2);

        let decoded = da
            .decode_data(commitment_hash, chunks[..4].to_vec())
            .unwrap();
        assert!(decoded.starts_with(&test_data));
    }

    #[test]
    fn test_chunk_sampling() {
        let mut da = DataAvailability::new(4, 2, 256, false, 6).unwrap();
        let test_data = b"Test data for sampling".to_vec();
        let commitment_hash = Hash::new([1u8; 32]);

        da.encode_data(commitment_hash, test_data).unwrap();

        let sample_indices = vec![0, 2, 4];
        let sampled = da.sample_chunks(commitment_hash, sample_indices).unwrap();
        assert_eq!(sampled.len(), 3);
    }

    #[test]
    fn test_unavailability_proof() {
        let da = DataAvailability::new(4, 2, 256, false, 6).unwrap();
        let commitment_hash = Hash::new([1u8; 32]);
        let challenger = Address::new([1u8; 20]);

        let proof = da
            .create_unavailability_proof(commitment_hash, vec![0, 1, 2, 3], challenger)
            .unwrap();

        assert_eq!(proof.missing_chunks.len(), 4);
        assert!(proof.validate().is_ok());
        assert_eq!(proof.missing_percentage(), 100.0);
    }

    #[test]
    fn test_chunk_integrity() {
        let chunk = DAChunk {
            chunk_id: 0,
            commitment_hash: Hash::new([1u8; 32]),
            data: vec![1, 2, 3, 4],
            is_parity: false,
            chunk_hash: ego_core::crypto::hash_data(&[1, 2, 3, 4]),
            timestamp: Timestamp::now(),
        };

        assert!(chunk.verify_integrity());
    }

    #[test]
    fn test_recovery_capability() {
        let da = DataAvailability::new(4, 2, 256, false, 6).unwrap();

        assert!(da.can_recover(4));
        assert!(da.can_recover(5));
        assert!(!da.can_recover(3));
    }

    #[test]
    fn test_storage_calculation() {
        let da = DataAvailability::new(4, 2, 1024, false, 6).unwrap();
        let data_size = 2048;
        let storage_size = da.calculate_storage_size(data_size);

        assert!(storage_size > data_size);
        assert_eq!(storage_size, 3072);
    }
}
