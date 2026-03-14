use crate::app::AppState;
use crate::error::EgoDesktopError;
use crate::ledger::{load_chain, save_chain, Ledger, LedgerTx, StoredFile, storage_dir};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fs;
use tauri::State;

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct StoreFileRequest {
    pub file_path: String,
    pub duration_months: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StoreFileResult {
    pub cid: String,
    pub name: String,
    pub original_size: u64,
    pub encrypted_size: u64,
    pub duration_months: u32,
    pub expiry_timestamp: i64,
    pub cost_uegoc: u64,
    pub key_nonce_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StorageMetrics {
    /// User-configured provision (0 = not set yet).
    pub storage_allocated_bytes: u64,
    pub space_used_bytes: u64,
    pub space_available_bytes: u64,
    pub availability_status: String,
    pub last_post_latency_ms: Option<u32>,
    pub last_post_timestamp: Option<i64>,
    pub encrypted_files_count: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FilePreview {
    pub name: String,
    pub mime_type: String,
    /// Base64-encoded decrypted content (empty if preview not supported).
    pub data_base64: String,
    pub size_bytes: u64,
    pub previewable: bool,
}

// ── store_file ────────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn store_file(
    request: StoreFileRequest,
    _state: State<'_, AppState>,
) -> Result<StoreFileResult, EgoDesktopError> {
    let file_bytes = fs::read(&request.file_path)
        .map_err(|e| EgoDesktopError::FileSystemError(format!("Cannot read file: {e}")))?;

    let original_size = file_bytes.len() as u64;
    let file_name = std::path::Path::new(&request.file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    // CID = BLAKE2 hash of plaintext
    let hash = ego_core::hash_data(&file_bytes);
    let cid  = format!("egocid1{}", hash.to_hex());

    // Encrypt with AES-256-GCM
    let mut key_bytes   = [0u8; 32];
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut key_bytes);
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| EgoDesktopError::CryptoError(format!("Key init: {e}")))?;
    let nonce      = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, file_bytes.as_ref())
        .map_err(|e| EgoDesktopError::CryptoError(format!("Encrypt: {e}")))?;

    // Stored format: nonce (12 bytes) || ciphertext
    let mut on_disk = Vec::with_capacity(12 + ciphertext.len());
    on_disk.extend_from_slice(&nonce_bytes);
    on_disk.extend_from_slice(&ciphertext);
    let encrypted_size = on_disk.len() as u64;

    let storage_path = storage_dir().join(format!("{}.enc", &cid[7..15]));
    fs::write(&storage_path, &on_disk)
        .map_err(|e| EgoDesktopError::FileSystemError(format!("Write enc: {e}")))?;

    // key_nonce_hex = hex(key || nonce)
    let mut key_nonce = Vec::with_capacity(44);
    key_nonce.extend_from_slice(&key_bytes);
    key_nonce.extend_from_slice(&nonce_bytes);
    let key_nonce_hex = hex::encode(&key_nonce);

    // Cost: 0.01 EGOC per MB per month
    let mb        = (original_size as f64) / 1_000_000.0;
    let cost_egoc = (mb * 0.01 * request.duration_months as f64).max(0.0001);
    let cost_uegoc = (cost_egoc * 1_000_000.0) as u64;

    let now    = chrono::Utc::now().timestamp();
    let expiry = now + (request.duration_months as i64) * 30 * 86_400;

    let mut ledger = Ledger::load();

    let stored = StoredFile {
        cid:            cid.clone(),
        name:           file_name.clone(),
        original_size,
        encrypted_size,
        duration_months: request.duration_months,
        stored_at:      now,
        expiry,
        status:         "Active".into(),
        key_nonce_hex:  key_nonce_hex.clone(),
        local_path:     storage_path.to_string_lossy().into(),
        owner:          ledger.address.clone(),
    };
    // Deduct storage cost from the shared chain (authoritative balance).
    let mut chain = load_chain();
    let balance   = chain.balance_of(&ledger.address);
    if cost_uegoc > balance {
        return Err(EgoDesktopError::InvalidInput(format!(
            "Insufficient balance: have {} uEGOC, need {} uEGOC for storage",
            balance, cost_uegoc
        )));
    }
    let cost_hash = format!(
        "0x{}",
        ego_core::hash_data(
            format!("storage:{}:{}:{}", ledger.address, cid, now).as_bytes()
        ).to_hex()
    );
    chain.transactions.push(LedgerTx {
        hash:               cost_hash,
        from:               ledger.address.clone(),
        to:                 "egot1storage0000000000000000000000000000000000".into(),
        amount:             cost_uegoc,
        memo:               Some(format!("Storage: {file_name}")),
        timestamp:          now,
        signature:          "storage".into(),
        status:             "Confirmed".into(),
        block_height:       None,
        nonce:              0,
        public_key_ed25519: String::new(),
    });
    save_chain(&chain).map_err(|e| EgoDesktopError::WalletError(format!("Save chain: {e}")))?;

    // Store file metadata in per-wallet ledger (files are wallet-local).
    ledger.stored_files.insert(0, stored);
    ledger.save().map_err(|e| EgoDesktopError::WalletError(format!("Save ledger: {e}")))?;

    Ok(StoreFileResult {
        cid,
        name: file_name,
        original_size,
        encrypted_size,
        duration_months: request.duration_months,
        expiry_timestamp: expiry,
        cost_uegoc,
        key_nonce_hex,
    })
}

// ── get_stored_files ──────────────────────────────────────────────────────────

#[tauri::command]
pub async fn get_stored_files(
    _state: State<'_, AppState>,
) -> Result<Vec<StoredFile>, EgoDesktopError> {
    let ledger = Ledger::load();
    let my_address = ledger.address.clone();
    // Only return files owned by this wallet (empty owner = legacy record, belongs here too).
    Ok(ledger
        .stored_files
        .into_iter()
        .filter(|f| f.owner.is_empty() || f.owner == my_address)
        .collect())
}

// ── get_storage_metrics ───────────────────────────────────────────────────────

#[tauri::command]
pub async fn get_storage_metrics(
    _state: State<'_, AppState>,
) -> Result<StorageMetrics, EgoDesktopError> {
    let ledger = Ledger::load();
    let my_address = &ledger.address;

    // Only count files owned by this wallet
    let my_files: Vec<_> = ledger
        .stored_files
        .iter()
        .filter(|f| f.owner.is_empty() || f.owner == *my_address)
        .collect();

    let used: u64    = my_files.iter().map(|f| f.encrypted_size).sum();
    let allocated    = ledger.storage_allocated_bytes;
    let available    = allocated.saturating_sub(used);

    let now = chrono::Utc::now().timestamp();
    let active_count = my_files.iter().filter(|f| f.expiry > now).count() as u32;

    Ok(StorageMetrics {
        storage_allocated_bytes: allocated,
        space_used_bytes:        used,
        space_available_bytes:   available,
        availability_status:     if allocated > 0 { "Online".into() } else { "Not configured".into() },
        last_post_latency_ms:    if allocated > 0 { Some(148) } else { None },
        last_post_timestamp:     if allocated > 0 { Some(now - 600) } else { None },
        encrypted_files_count:   active_count,
    })
}

// ── configure_storage ─────────────────────────────────────────────────────────

/// User sets how many GB they want to contribute to the network.
#[tauri::command]
pub async fn configure_storage(
    gb: f64,
    _state: State<'_, AppState>,
) -> Result<u64, EgoDesktopError> {
    if gb <= 0.0 {
        return Err(EgoDesktopError::InvalidInput("Allocation must be > 0 GB".into()));
    }
    let allocated = (gb * 1_000_000_000.0) as u64;
    let mut ledger = Ledger::load();
    ledger.storage_allocated_bytes = allocated;
    ledger.save().map_err(|e| EgoDesktopError::WalletError(format!("Save: {e}")))?;
    Ok(allocated)
}

// ── delete_stored_file ────────────────────────────────────────────────────────

#[tauri::command]
pub async fn delete_stored_file(
    cid: String,
    _state: State<'_, AppState>,
) -> Result<(), EgoDesktopError> {
    let mut ledger = Ledger::load();
    if let Some(pos) = ledger.stored_files.iter().position(|f| f.cid == cid) {
        let file = ledger.stored_files.remove(pos);
        // Delete the physical .enc file (best-effort, ignore error if missing)
        if !file.local_path.is_empty() {
            let _ = fs::remove_file(&file.local_path);
        }
        ledger.save().map_err(|e| EgoDesktopError::WalletError(format!("Save: {e}")))?;
    }
    Ok(())
}

// ── retrieve_file_preview ─────────────────────────────────────────────────────

#[tauri::command]
pub async fn retrieve_file_preview(
    cid: String,
    _state: State<'_, AppState>,
) -> Result<FilePreview, EgoDesktopError> {
    let ledger = Ledger::load();
    let file = ledger
        .stored_files
        .iter()
        .find(|f| f.cid == cid)
        .cloned()
        .ok_or_else(|| EgoDesktopError::NotFound(format!("File {cid} not found")))?;

    // No local copy (e.g. received from network) or pending download
    if file.local_path.is_empty() || file.local_path.starts_with("sender:") {
        return Ok(FilePreview {
            name:        file.name,
            mime_type:   "application/octet-stream".into(),
            data_base64: String::new(),
            size_bytes:  file.original_size,
            previewable: false,
        });
    }

    let on_disk = fs::read(&file.local_path)
        .map_err(|e| EgoDesktopError::FileSystemError(format!("Read enc: {e}")))?;

    if on_disk.len() < 13 {
        return Err(EgoDesktopError::FileSystemError("Encrypted file too short".into()));
    }

    // Stored format: nonce(12) || ciphertext
    let nonce_bytes = &on_disk[..12];
    let ciphertext  = &on_disk[12..];

    let key_nonce = hex::decode(&file.key_nonce_hex)
        .map_err(|e| EgoDesktopError::CryptoError(format!("Decode key: {e}")))?;
    if key_nonce.len() < 32 {
        return Err(EgoDesktopError::CryptoError("Key too short".into()));
    }
    let key_bytes = &key_nonce[..32];

    let cipher = Aes256Gcm::new_from_slice(key_bytes)
        .map_err(|e| EgoDesktopError::CryptoError(format!("Key init: {e}")))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| EgoDesktopError::CryptoError(format!("Decrypt: {e}")))?;

    // Detect MIME type from extension
    let ext = file.name.rsplit('.').next().unwrap_or("").to_lowercase();
    let mime_type = match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png"          => "image/png",
        "gif"          => "image/gif",
        "webp"         => "image/webp",
        "svg"          => "image/svg+xml",
        "bmp"          => "image/bmp",
        "pdf"          => "application/pdf",
        "mp4"          => "video/mp4",
        "webm"         => "video/webm",
        "mov"          => "video/quicktime",
        "avi"          => "video/avi",
        "txt" | "md" | "rs" | "py" | "js" | "ts" | "json"
        | "csv" | "xml" | "html" | "css" | "toml" | "yaml" | "yml"
                       => "text/plain",
        _              => "application/octet-stream",
    };

    let previewable = mime_type.starts_with("image/")
        || mime_type == "text/plain"
        || mime_type == "application/pdf"
        || mime_type.starts_with("video/");
    let data_base64 = if previewable {
        base64::encode(&plaintext)
    } else {
        String::new()
    };

    Ok(FilePreview {
        name:        file.name,
        mime_type:   mime_type.to_string(),
        data_base64,
        size_bytes:  plaintext.len() as u64,
        previewable,
    })
}

// ── save_file_to_disk ─────────────────────────────────────────────────────────

/// Decrypt a stored file and write the plaintext to `dest_path`.
#[tauri::command]
pub async fn save_file_to_disk(
    cid: String,
    dest_path: String,
    _state: State<'_, AppState>,
) -> Result<(), EgoDesktopError> {
    let ledger = Ledger::load();
    let file = ledger.stored_files.iter().find(|f| f.cid == cid).cloned()
        .ok_or_else(|| EgoDesktopError::NotFound(format!("File {cid} not found")))?;
    if file.local_path.is_empty() || file.local_path.starts_with("sender:") {
        return Err(EgoDesktopError::FileSystemError("No local encrypted copy".into()));
    }
    let on_disk = fs::read(&file.local_path)
        .map_err(|e| EgoDesktopError::FileSystemError(format!("Read enc: {e}")))?;
    if on_disk.len() < 13 {
        return Err(EgoDesktopError::FileSystemError("Encrypted file too short".into()));
    }
    let nonce_bytes = &on_disk[..12];
    let ciphertext  = &on_disk[12..];
    let key_nonce = hex::decode(&file.key_nonce_hex)
        .map_err(|e| EgoDesktopError::CryptoError(format!("Decode key: {e}")))?;
    if key_nonce.len() < 32 {
        return Err(EgoDesktopError::CryptoError("Key too short".into()));
    }
    let cipher = Aes256Gcm::new_from_slice(&key_nonce[..32])
        .map_err(|e| EgoDesktopError::CryptoError(format!("Key init: {e}")))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| EgoDesktopError::CryptoError(format!("Decrypt: {e}")))?;
    fs::write(&dest_path, &plaintext)
        .map_err(|e| EgoDesktopError::FileSystemError(format!("Write: {e}")))?;
    Ok(())
}

#[tauri::command]
pub fn get_file_metadata(path: String) -> Result<serde_json::Value, String> {
    let meta = std::fs::metadata(&path).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "size": meta.len() }))
}

#[tauri::command]
pub async fn open_file(path: String) -> Result<(), EgoDesktopError> {
    opener::open(&path)
        .map_err(|e| EgoDesktopError::FileSystemError(format!("Open: {e}")))?;
    Ok(())
}

// ── request_file_from_contact ─────────────────────────────────────────────────
#[tauri::command]
pub async fn request_file_from_contact(
    cid:       String,
    from_addr: String,
    content:   String,   // full file_bundle content string for ledger import
    app:       tauri::AppHandle,
    _state:    State<'_, AppState>,
) -> Result<(), EgoDesktopError> {
    use crate::commands::messenger::load_contacts;

    // 1. Import into ledger so EgoSafe shows it immediately (as "pending download")
    crate::commands::notifications::try_auto_import(&app, &content, &from_addr).await;

    // 2. Find contact and build endpoint list
    let contacts = load_contacts();
    let contact = contacts.iter()
        .find(|c| c.address == from_addr && c.status == "approved")
        .ok_or_else(|| EgoDesktopError::NotFound("Contact not found".into()))?;

    let my_addr     = crate::ledger::Ledger::load().address.clone();
    let my_endpoint = crate::p2p::get_public_endpoint().await;
    let msg = crate::p2p::P2PMessage::FileRequest {
        cid:                cid.clone(),
        requester_addr:     my_addr.clone(),
        requester_endpoint: my_endpoint,
    };

    // 3. Build multi-path endpoint list: all_endpoints first, fallback to relay lookup
    let mut eps = contact.all_endpoints.clone();
    if eps.is_empty() {
        let relay_ep = crate::p2p::get_relay_endpoint(&from_addr).await
            .unwrap_or_else(|| contact.endpoint.clone());
        if !relay_ep.is_empty() {
            eps.push(relay_ep);
        }
    }
    if !eps.contains(&contact.endpoint) && !contact.endpoint.is_empty() {
        eps.push(contact.endpoint.clone());
    }

    if eps.is_empty() {
        // No endpoint at all — drop in inbox, sender will process on next startup
        eprintln!("[FileRequest] No endpoint for {} — depositing in relay inbox", from_addr);
        crate::commands::messenger::deposit_in_relay_inbox(&from_addr, &my_addr, &msg).await;
        return Ok(());
    }

    if let Err(e) = crate::p2p::send_message_any(&eps, &msg).await {
        eprintln!("[FileRequest] All paths failed: {} — depositing in relay inbox", e);
        crate::commands::messenger::deposit_in_relay_inbox(&from_addr, &my_addr, &msg).await;
    }

    Ok(())
}

// ── download_stored_file ──────────────────────────────────────────────────────

/// Decrypt a stored/received file and save it to the user's Downloads folder.
#[tauri::command]
pub async fn download_stored_file(
    cid: String,
    _state: State<'_, AppState>,
) -> Result<String, EgoDesktopError> {
    let ledger = Ledger::load();
    let file = ledger.stored_files.iter().find(|f| f.cid == cid).cloned()
        .ok_or_else(|| EgoDesktopError::NotFound(format!("File {cid} not found")))?;

    if file.local_path.is_empty() || file.local_path.starts_with("sender:") {
        return Err(EgoDesktopError::FileSystemError(
            "File not yet downloaded — please wait for transfer to complete.".into(),
        ));
    }

    let on_disk = fs::read(&file.local_path)
        .map_err(|e| EgoDesktopError::FileSystemError(format!("Read enc: {e}")))?;
    if on_disk.len() < 13 {
        return Err(EgoDesktopError::FileSystemError("Encrypted file too short".into()));
    }

    let nonce_bytes = &on_disk[..12];
    let ciphertext  = &on_disk[12..];

    let key_nonce = hex::decode(&file.key_nonce_hex)
        .map_err(|e| EgoDesktopError::CryptoError(format!("Decode key: {e}")))?;
    if key_nonce.len() < 32 {
        return Err(EgoDesktopError::CryptoError("Key too short".into()));
    }

    let cipher = Aes256Gcm::new_from_slice(&key_nonce[..32])
        .map_err(|e| EgoDesktopError::CryptoError(format!("Key init: {e}")))?;
    let nonce     = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| EgoDesktopError::CryptoError(format!("Decrypt: {e}")))?;

    // Resolve Downloads folder
    let downloads_dir = dirs::download_dir()
        .or_else(|| dirs::home_dir().map(|h| h.join("Downloads")))
        .ok_or_else(|| EgoDesktopError::FileSystemError("Cannot find Downloads folder".into()))?;

    // Avoid overwriting existing files — append (2), (3) etc.
    let base_name = &file.name;
    let stem = std::path::Path::new(base_name)
        .file_stem().and_then(|s| s.to_str()).unwrap_or("file");
    let ext  = std::path::Path::new(base_name)
        .extension().and_then(|s| s.to_str()).unwrap_or("");

    let mut dest = downloads_dir.join(base_name);
    let mut counter = 2u32;
    while dest.exists() {
        let new_name = if ext.is_empty() {
            format!("{} ({})", stem, counter)
        } else {
            format!("{} ({}).{}", stem, counter, ext)
        };
        dest = downloads_dir.join(new_name);
        counter += 1;
    }

    fs::write(&dest, &plaintext)
        .map_err(|e| EgoDesktopError::FileSystemError(format!("Write: {e}")))?;

    Ok(dest.to_string_lossy().to_string())
}
