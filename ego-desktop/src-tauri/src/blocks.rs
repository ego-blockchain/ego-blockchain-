use crate::ledger::storage_dir;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::io::{Read, Write};

pub const BLOCK_SIZE: usize = 256 * 1024;

/// Blake3 hash over all block CIDs in order — used as the on-chain storage commitment.
/// Anyone with the manifest can recompute this and verify it matches the chain record.
pub fn compute_commitment(blocks: &[BlockEntry]) -> String {
    let mut hasher = blake3::Hasher::new();
    for b in blocks {
        hasher.update(b.block_cid.as_bytes());
    }
    format!("egocmt1{}", hasher.finalize().to_hex())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEntry {
    pub block_cid: String,
    pub nonce_hex: String,
    pub size: u64,
    /// PoRep replica commitment: blake3(POREP_TAG || enc_bytes || prover_addr || block_cid).
    /// Binds the encrypted content to a specific prover — different nodes produce different
    /// comm_r for the same data, so you can't fake storage by fetching on demand.
    #[serde(default)]
    pub comm_r: String,
}

/// Compute the per-block replica commitment.
/// `enc_bytes`   = the encrypted block as stored on disk.
/// `prover_addr` = the storing node's address (makes it replica-unique).
/// `block_cid`   = the block's content CID (prevents cross-block substitution).
pub fn compute_block_comm_r(enc_bytes: &[u8], prover_addr: &str, block_cid: &str) -> String {
    let mut h = blake3::Hasher::new();
    h.update(crate::proof::POREP_TAG);
    h.update(enc_bytes);
    h.update(prover_addr.as_bytes());
    h.update(block_cid.as_bytes());
    hex::encode(h.finalize().as_bytes())
}

/// Aggregate all per-block comm_r values into a single file-level PoRep commitment.
/// Stored in `StoredFile.comm_r` and registered with the relay so peers can slash-verify.
pub fn compute_porep_root(blocks: &[BlockEntry]) -> String {
    let mut h = blake3::Hasher::new();
    for b in blocks {
        h.update(b.comm_r.as_bytes());
    }
    format!("egoporep1{}", h.finalize().to_hex())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifest {

    pub manifest_cid: String,
    pub file_name: String,
    pub total_size: u64,
    pub blocks: Vec<BlockEntry>,
}

pub fn manifest_path(manifest_cid: &str) -> PathBuf {
    let short = &manifest_cid[manifest_cid.len().saturating_sub(16)..];
    storage_dir().join(format!("{}.mfd", short))
}

pub fn block_path(block_cid: &str) -> PathBuf {
    let short = &block_cid[block_cid.len().saturating_sub(16)..];
    storage_dir().join(format!("{}.blk", short))
}

pub fn save_manifest(manifest: &FileManifest) -> Result<PathBuf, String> {
    let path = manifest_path(&manifest.manifest_cid);
    let json = serde_json::to_string(manifest).map_err(|e| e.to_string())?;
    std::fs::write(&path, json.as_bytes()).map_err(|e| e.to_string())?;
    Ok(path)
}

pub fn load_manifest(manifest_cid: &str) -> Result<FileManifest, String> {
    let path = manifest_path(manifest_cid);
    let data = std::fs::read_to_string(&path)
        .map_err(|e| format!("Read manifest {}: {e}", &manifest_cid[..16.min(manifest_cid.len())]))?;
    serde_json::from_str(&data)
        .map_err(|e| format!("Parse manifest: {e}"))
}

pub fn save_block(block_cid: &str, enc_bytes: &[u8]) -> Result<PathBuf, String> {
    let path = block_path(block_cid);
    std::fs::write(&path, enc_bytes).map_err(|e| e.to_string())?;
    Ok(path)
}

pub fn load_block(block_cid: &str) -> Result<Vec<u8>, String> {
    std::fs::read(block_path(block_cid))
        .map_err(|e| format!("Read block {}: {e}", &block_cid[..16.min(block_cid.len())]))
}

pub fn have_block(block_cid: &str) -> bool {
    block_path(block_cid).exists()
}

pub fn missing_blocks(manifest: &FileManifest) -> Vec<String> {
    manifest
        .blocks
        .iter()
        .filter(|b| !have_block(&b.block_cid))
        .map(|b| b.block_cid.clone())
        .collect()
}

pub fn have_all_blocks(manifest: &FileManifest) -> bool {
    manifest.blocks.iter().all(|b| have_block(&b.block_cid))
}

pub fn blocks_received_count(manifest: &FileManifest) -> u32 {
    manifest.blocks.iter().filter(|b| have_block(&b.block_cid)).count() as u32
}

pub fn split_into_blocks(
    plaintext: &[u8],
    file_name: &str,
    key_bytes: &[u8; 32],
) -> Result<(FileManifest, Vec<(String, Vec<u8>)>), String> {
    let mut block_entries: Vec<BlockEntry> = Vec::new();
    let mut blocks_data:   Vec<(String, Vec<u8>)> = Vec::new();

    for chunk in plaintext.chunks(BLOCK_SIZE) {

        let hash      = ego_core::hash_data(chunk);
        let block_cid = format!("egoblk1{}", hash.to_hex());

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let cipher    = Aes256Gcm::new_from_slice(key_bytes)
            .map_err(|e| format!("Key init: {e}"))?;
        let nonce     = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher
            .encrypt(nonce, chunk)
            .map_err(|e| format!("Encrypt block: {e}"))?;

        block_entries.push(BlockEntry {
            block_cid: block_cid.clone(),
            nonce_hex: hex::encode(nonce_bytes),
            size:      chunk.len() as u64,
            comm_r:    String::new(),  // filled in by store_file after encryption
        });
        blocks_data.push((block_cid, encrypted));
    }

    let content       = serde_json::json!({
        "file_name":  file_name,
        "total_size": plaintext.len() as u64,
        "blocks":     &block_entries,
    });
    let content_bytes = serde_json::to_vec(&content).map_err(|e| e.to_string())?;
    let mfd_hash      = ego_core::hash_data(&content_bytes);
    let manifest_cid  = format!("egomfd1{}", mfd_hash.to_hex());

    let manifest = FileManifest {
        manifest_cid,
        file_name:  file_name.to_string(),
        total_size: plaintext.len() as u64,
        blocks:     block_entries,
    };

    Ok((manifest, blocks_data))
}

pub fn reassemble_blocks(
    manifest:  &FileManifest,
    key_bytes: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let mut plaintext = Vec::with_capacity(manifest.total_size as usize);

    for entry in &manifest.blocks {
        let enc_bytes   = load_block(&entry.block_cid)?;
        let nonce_bytes = hex::decode(&entry.nonce_hex)
            .map_err(|e| format!("Decode nonce: {e}"))?;
        let cipher      = Aes256Gcm::new_from_slice(key_bytes)
            .map_err(|e| format!("Key init: {e}"))?;
        let nonce       = Nonce::from_slice(&nonce_bytes);
        let plain       = cipher
            .decrypt(nonce, enc_bytes.as_ref())
            .map_err(|e| format!("Decrypt block {}: {e}", &entry.block_cid[..16.min(entry.block_cid.len())]))?;

        plaintext.extend_from_slice(&plain);
    }

    Ok(plaintext)
}

/// Stream a file from disk, encrypt it chunk-by-chunk, and save blocks locally.
/// This prevents memory panics when uploading multi-gigabyte files.
pub fn stream_into_blocks(
    in_path:   &Path,
    file_name: &str,
    key_bytes: &[u8; 32],
) -> Result<FileManifest, String> {
    let mut file = std::fs::File::open(in_path).map_err(|e| format!("Open failed: {}", e))?;
    let file_size = file.metadata().map_err(|e| e.to_string())?.len();

    let mut block_entries: Vec<BlockEntry> = Vec::new();
    let mut buffer = vec![0u8; BLOCK_SIZE];

    loop {
        let bytes_read = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if bytes_read == 0 { break; }
        let chunk = &buffer[..bytes_read];

        let hash      = ego_core::hash_data(chunk);
        let block_cid = format!("egoblk1{}", hash.to_hex());

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let cipher    = Aes256Gcm::new_from_slice(key_bytes).map_err(|e| e.to_string())?;
        let nonce     = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher.encrypt(nonce, chunk).map_err(|e| e.to_string())?;

        save_block(&block_cid, &encrypted)?;

        block_entries.push(BlockEntry {
            block_cid,
            nonce_hex: hex::encode(nonce_bytes),
            size:      chunk.len() as u64,
            comm_r:    String::new(),
        });
    }

    let content = serde_json::json!({
        "file_name":  file_name,
        "total_size": file_size,
        "blocks":     &block_entries,
    });
    
    let content_bytes = serde_json::to_vec(&content).map_err(|e| e.to_string())?;
    let mfd_hash      = ego_core::hash_data(&content_bytes);
    let manifest_cid  = format!("egomfd1{}", mfd_hash.to_hex());

    let manifest = FileManifest {
        manifest_cid,
        file_name:  file_name.to_string(),
        total_size: file_size,
        blocks:     block_entries,
    };

    save_manifest(&manifest)?;
    Ok(manifest)
}

/// Stream reassembled blocks directly to the disk to prevent OOM
/// crashes when handling multi-gigabyte files.
pub fn reassemble_blocks_to_file(
    manifest:  &FileManifest,
    key_bytes: &[u8; 32],
    out_path:  &Path,
) -> Result<(), String> {
    let mut out_file = std::fs::File::create(out_path)
        .map_err(|e| format!("Failed to create output file: {}", e))?;

    for entry in &manifest.blocks {
        let enc_bytes   = load_block(&entry.block_cid)?;
        let nonce_bytes = hex::decode(&entry.nonce_hex)
            .map_err(|e| format!("Decode nonce: {e}"))?;
        let cipher      = Aes256Gcm::new_from_slice(key_bytes)
            .map_err(|e| format!("Key init: {e}"))?;
        let nonce       = Nonce::from_slice(&nonce_bytes);
        let plain       = cipher
            .decrypt(nonce, enc_bytes.as_ref())
            .map_err(|e| format!("Decrypt block {}: {}", &entry.block_cid[..16.min(entry.block_cid.len())], e))?;

        out_file.write_all(&plain).map_err(|e| format!("Disk write error: {}", e))?;
    }

    Ok(())
}
