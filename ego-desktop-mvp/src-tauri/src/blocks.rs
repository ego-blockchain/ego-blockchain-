//! IPFS-style content-addressed block storage.
//!
//! Files are split into 256 KB plaintext chunks.  Each chunk is:
//!  1. Hashed with BLAKE2 → block CID (`egoblk1{hex}`)  — content-addressed
//!  2. Encrypted with AES-256-GCM (same file key, unique random nonce per block)
//!  3. Stored as `{storage_dir}/{last16_of_cid}.blk`
//!
//! A manifest (`egomfd1{hex}`) records the ordered list of blocks and is
//! stored as `{storage_dir}/{last16_of_manifest_cid}.mfd`.
//!
//! Every block fits inside a DHT record (256 KB raw < our 4 MB limit).
//! The manifest is tiny (~100 B + 100 B/block).
//!
//! Share bundle format (same egoshare1 envelope, new CID prefix):
//!   `egoshare1:{manifest_cid}:{key_hex64}:{base64_name}:{from_addr}`
//!   where `key_hex64` = hex of the 32-byte AES key (no global nonce).

use crate::ledger::storage_dir;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Plaintext block size: 256 KB.
pub const BLOCK_SIZE: usize = 256 * 1024;

// ── Types ─────────────────────────────────────────────────────────────────────

/// One block's metadata as stored in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEntry {
    /// `egoblk1{BLAKE2(plaintext_chunk)}` — content-addressed.
    pub block_cid: String,
    /// Hex-encoded 12-byte AES-GCM nonce, unique to this block.
    pub nonce_hex: String,
    /// Plaintext byte count (≤ BLOCK_SIZE).
    pub size: u64,
}

/// The manifest describing all blocks of a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifest {
    /// `egomfd1{BLAKE2(stable_content)}` — deterministic CID.
    pub manifest_cid: String,
    pub file_name: String,
    pub total_size: u64,
    pub blocks: Vec<BlockEntry>,
}

// ── Path helpers ──────────────────────────────────────────────────────────────

pub fn manifest_path(manifest_cid: &str) -> PathBuf {
    let short = &manifest_cid[manifest_cid.len().saturating_sub(16)..];
    storage_dir().join(format!("{}.mfd", short))
}

pub fn block_path(block_cid: &str) -> PathBuf {
    let short = &block_cid[block_cid.len().saturating_sub(16)..];
    storage_dir().join(format!("{}.blk", short))
}

// ── Persistence ───────────────────────────────────────────────────────────────

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

// ── Split ─────────────────────────────────────────────────────────────────────

/// Split `plaintext` into 256 KB blocks, encrypt each with `key_bytes`
/// (unique random nonce per block), and return
/// `(manifest, Vec<(block_cid, encrypted_bytes)>)`.
pub fn split_into_blocks(
    plaintext: &[u8],
    file_name: &str,
    key_bytes: &[u8; 32],
) -> Result<(FileManifest, Vec<(String, Vec<u8>)>), String> {
    let mut block_entries: Vec<BlockEntry> = Vec::new();
    let mut blocks_data:   Vec<(String, Vec<u8>)> = Vec::new();

    for chunk in plaintext.chunks(BLOCK_SIZE) {
        // Content-addressed: CID = BLAKE2 of plaintext chunk
        let hash      = ego_core::hash_data(chunk);
        let block_cid = format!("egoblk1{}", hash.to_hex());

        // Unique random 12-byte nonce per block
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
        });
        blocks_data.push((block_cid, encrypted));
    }

    // Manifest CID = BLAKE2 of the stable block-list JSON (deterministic)
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

// ── Reassemble ────────────────────────────────────────────────────────────────

/// Decrypt and concatenate all blocks from disk in order.
/// `key_bytes` is the 32-byte AES key stored in `StoredFile.key_nonce_hex`.
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
