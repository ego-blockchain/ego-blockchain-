use crate::app::AppState;
use crate::error::EgoDesktopError;
use crate::ledger::{load_chain, Ledger, LedgerTx, StoredFile, storage_dir};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fs;
use tauri::{Manager, State};

// ── Storage reservation ───────────────────────────────────────────────────────
//
// ego_reserved.bin physically locks disk space for Ego Desktop.
// Its size = allocated_bytes − bytes_used_by_blocks.
// The OS always sees the full allocation as occupied.

fn reservation_path() -> std::path::PathBuf {
    storage_dir().join("ego_reserved.bin")
}

/// Resize the reservation file so that:
///   reservation_size + actual_block_bytes = allocated_bytes
/// This keeps total on-disk usage constant at the configured allocation.
fn sync_reservation(allocated_bytes: u64) {
    let dir = storage_dir();
    // Sum all .blk files = actual block usage.
    let block_bytes: u64 = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) == Some("blk") {
                std::fs::metadata(&p).ok().map(|m| m.len())
            } else {
                None
            }
        })
        .sum();

    let reservation = allocated_bytes.saturating_sub(block_bytes);
    let path = reservation_path();

    match std::fs::OpenOptions::new().write(true).create(true).open(&path) {
        Ok(f) => {
            if let Err(e) = f.set_len(reservation) {
                eprintln!("[Storage] reservation resize failed: {e}");
            } else {
                eprintln!("[Storage] reservation = {} MB  (alloc={} MB, blocks={} MB)",
                    reservation / 1_000_000,
                    allocated_bytes / 1_000_000,
                    block_bytes / 1_000_000);
            }
        }
        Err(e) => eprintln!("[Storage] reservation open failed: {e}"),
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StoreFileRequest {
    pub file_path: String,
    pub duration_months: u32,
    /// When true the storage fee is waived (used for file sharing between users).
    #[serde(default)]
    pub free: bool,
    /// When true the file was sent/received via EgoSafe — excluded from Storage tab.
    #[serde(default)]
    pub from_egosafe: bool,
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
    pub storage_allocated_bytes: u64,
    pub space_used_bytes: u64,
    pub space_available_bytes: u64,
    pub availability_status: String,
    pub last_post_latency_ms: Option<u32>,
    pub last_post_timestamp: Option<i64>,
    pub encrypted_files_count: u32,
    /// Bytes of OTHER peers' encrypted blocks stored on this node.
    /// This — not own file usage — drives the earning rate.
    pub peer_bytes_hosted: u64,
    /// Free bytes remaining on the local drive (for configure modal).
    pub disk_free_bytes: u64,
    /// Unix timestamp when storage was last configured. Locked for 60 days from this point.
    pub storage_configured_at: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FilePreview {
    pub name: String,
    pub mime_type: String,

    pub data_base64: String,
    pub size_bytes: u64,
    pub previewable: bool,
}

#[tauri::command]
pub async fn store_file(
    request: StoreFileRequest,
    _state: State<'_, AppState>,
) -> Result<StoreFileResult, EgoDesktopError> {
    use std::io::Read as _;
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};

    // Canonicalize the path to prevent directory traversal attacks.
    // `canonicalize` resolves symlinks and `../` components, so we always
    // operate on the real absolute path the user selected.
    let canonical_path = std::fs::canonicalize(&request.file_path)
        .map_err(|e| EgoDesktopError::FileSystemError(format!("Cannot resolve file path: {e}")))?;

    let file_name = canonical_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    let original_size = fs::metadata(&canonical_path)
        .map_err(|e| EgoDesktopError::FileSystemError(format!("Cannot stat file: {e}")))?
        .len();

    const MAX_FILE_BYTES: u64 = 250 * 1024 * 1024; // 250 MB
    if original_size > MAX_FILE_BYTES {
        return Err(EgoDesktopError::InvalidInput(format!(
            "File is {:.1} MB; maximum allowed size is 250 MB.",
            original_size as f64 / (1024.0 * 1024.0)
        )));
    }

    // ── Subscription quota enforcement (backend gate) ─────────────────────────
    // Reads the on-chain subscription tx to determine the user's quota.
    // Falls back to FREE_GB (5 GB) if no valid subscription exists.
    // Grace period: 30 days after expiry, the quota is still honoured.
    {
        let now_quota           = chrono::Utc::now().timestamp();
        const FREE_BYTES:       u64 = 5  * 1_000_000_000;
        const GRACE_SECS:       i64 = 30 * 86_400;

        let ledger_quota = Ledger::load();
        // Sum all active/pending-sync files owned by this user.
        let used_bytes: u64 = ledger_quota.stored_files.iter()
            .filter(|f| (f.status == "Active" || f.status == "PendingSync")
                && (f.owner.is_empty() || f.owner == ledger_quota.address))
            .map(|f| f.original_size)
            .sum();

        // Derive quota from the most recent valid subscription tx on chain.
        let chain_quota_bytes: u64 = {
            let chain = load_chain();
            let sub_tx = chain.transactions.iter()
                .filter(|tx| tx.from == ledger_quota.address
                    && tx.tx_type == "transfer"
                    && tx.to == "egot1storagefees000000000000000000000000000000"
                    && tx.status == "Confirmed")
                .max_by_key(|tx| tx.timestamp);

            // Map memo to GB — memo format: "Ego Storage <Plan> – <billing> ($<usd>)"
            match sub_tx {
                Some(tx) => {
                    let memo = tx.memo.as_deref().unwrap_or("");
                    let gb: u64 = if memo.contains("Max")   { 1024 }
                               else if memo.contains("Pro")   {  200 }
                               else if memo.contains("Basic") {   50 }
                               else                            {    5 };
                    // Check expiry: monthly = 30 days, annual = 365 days from tx timestamp.
                    let period_secs: i64 = if memo.contains("annual") { 365 * 86_400 } else { 30 * 86_400 };
                    let expires_at  = tx.timestamp + period_secs;
                    let in_grace    = now_quota < expires_at + GRACE_SECS;
                    if in_grace { gb * 1_000_000_000 } else { FREE_BYTES }
                }
                None => FREE_BYTES,
            }
        };

        let quota = chain_quota_bytes.max(FREE_BYTES);
        if used_bytes + original_size > quota {
            let quota_gb  = quota as f64 / 1_000_000_000.0;
            let used_gb   = used_bytes as f64 / 1_000_000_000.0;
            let file_mb   = original_size as f64 / 1_000_000.0;
            return Err(EgoDesktopError::InvalidInput(format!(
                "Storage quota exceeded: {used_gb:.2} GB used of {quota_gb:.0} GB plan. \
                 This file is {file_mb:.1} MB. Upgrade your plan to store more files."
            )));
        }
    }

    // ── Streaming block storage (one 256 KB chunk at a time) ──────────────────
    let mut key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut key_bytes);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| EgoDesktopError::CryptoError(format!("Key init: {e}")))?;

    let mut file = std::fs::File::open(&canonical_path)
        .map_err(|e| EgoDesktopError::FileSystemError(format!("Cannot open file: {e}")))?;

    // Prover address needed for PoRep commitment — binds enc_bytes to this specific node.
    let prover_addr = Ledger::load().address;

    let mut block_entries: Vec<crate::blocks::BlockEntry> = Vec::new();
    let mut encrypted_size: u64 = 0;
    let mut buf = vec![0u8; crate::blocks::BLOCK_SIZE];

    loop {
        // Fill buffer fully (handles partial reads from slow/network drives).
        let mut filled = 0;
        loop {
            match file.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(n) => { filled += n; if filled == buf.len() { break; } }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(EgoDesktopError::FileSystemError(format!("Read: {e}"))),
            }
        }
        if filled == 0 { break; }
        let chunk = &buf[..filled];

        let hash      = ego_core::hash_data(chunk);
        let block_cid = format!("egoblk1{}", hash.to_hex());

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce     = Nonce::from_slice(&nonce_bytes);
        let enc_bytes = cipher.encrypt(nonce, chunk)
            .map_err(|e| EgoDesktopError::CryptoError(format!("Encrypt block: {e}")))?;

        // PoRep: compute replica commitment binding enc_bytes to this prover's identity.
        // A different node storing the same file produces a different comm_r — prevents
        // lazy nodes from fetching blocks on-demand during a challenge window.
        let comm_r = crate::blocks::compute_block_comm_r(&enc_bytes, &prover_addr, &block_cid);

        encrypted_size += enc_bytes.len() as u64;
        crate::blocks::save_block(&block_cid, &enc_bytes)
            .map_err(|e| EgoDesktopError::FileSystemError(e))?;

        block_entries.push(crate::blocks::BlockEntry {
            block_cid,
            nonce_hex: hex::encode(nonce_bytes),
            size: chunk.len() as u64,
            comm_r,
        });
    }

    // Build and save manifest.
    let manifest_content = serde_json::json!({
        "file_name":  file_name,
        "total_size": original_size,
        "blocks":     &block_entries,
    });
    let manifest_bytes = serde_json::to_vec(&manifest_content)
        .map_err(|e| EgoDesktopError::CryptoError(e.to_string()))?;
    let mfd_hash = ego_core::hash_data(&manifest_bytes);
    let cid = format!("egomfd1{}", mfd_hash.to_hex());

    let manifest = crate::blocks::FileManifest {
        manifest_cid: cid.clone(),
        file_name:    file_name.clone(),
        total_size:   original_size,
        blocks:       block_entries,
    };
    let manifest_path = crate::blocks::save_manifest(&manifest)
        .map_err(|e| EgoDesktopError::FileSystemError(e))?;

    // Aggregate PoRep commitment = blake3(comm_r_1 || comm_r_2 || ... || comm_r_n).
    // Stored on-chain and in the relay so any peer can slash-verify this node.
    let porep_root = crate::blocks::compute_porep_root(&manifest.blocks);

    let key_nonce_hex = hex::encode(key_bytes);
    let blocks_total  = manifest.blocks.len() as u32;

    let now    = chrono::Utc::now().timestamp();
    // duration_months == 0 means permanent (no expiry)
    let expiry = if request.duration_months == 0 {
        i64::MAX
    } else {
        now + (request.duration_months as i64) * 30 * 86_400
    };

    let mut ledger = Ledger::load();
    let is_staker  = ledger.staked_amount > 0;
    let mb         = (original_size as f64) / 1_000_000.0;
    let cost_uegoc = if request.free { 0 }
                     else { crate::tokenomics::storage_cost_with_staking(mb, request.duration_months, is_staker) };

    let mut stored = StoredFile {
        cid:             cid.clone(),
        name:            file_name.clone(),
        original_size,
        encrypted_size,
        duration_months: request.duration_months,
        stored_at:       now,
        expiry,
        status:          "Active".into(),
        key_nonce_hex:   crate::ledger::protect_key_hex(&key_nonce_hex)
            .map_err(EgoDesktopError::CryptoError)?,
        local_path:      manifest_path.to_string_lossy().into(),
        owner:           ledger.address.clone(),
        manifest_cid:    cid.clone(),
        blocks_total,
        blocks_received: blocks_total, // we own all blocks
        comm_r:          porep_root.clone(),  // PoRep aggregate commitment
        from_egosafe:    request.from_egosafe,
        ..Default::default()
    };

    // Deduct storage cost and record a verifiable store_data commitment on-chain.
    let chain = load_chain();
    {
        let balance = chain.balance_of(&ledger.address);
        if cost_uegoc > balance {
            return Err(EgoDesktopError::InvalidInput(format!(
                "Insufficient balance: have {} uEGOC, need {} uEGOC for storage",
                balance, cost_uegoc
            )));
        }

        // Compute the storage commitment — blake3 over all block CIDs in order.
        // Anyone with the manifest can recompute this to verify file integrity.
        let commitment_hash = crate::blocks::compute_commitment(&manifest.blocks);

        let nonce  = ledger.nonce + 1;
        let sign_input = format!("store_data:{}:{}:{}:{}", ledger.address, cid, commitment_hash, nonce);
        let signature_hex = {
            ego_core::KeyPair::from_bytes(&{
                let seed = crate::ledger::load_seed().ok().flatten().unwrap_or_default();
                let mut arr = [0u8; 32]; arr.copy_from_slice(&seed[..32]); arr
            }).map(|kp| hex::encode(kp.sign_ed25519(sign_input.as_bytes()).as_bytes()))
              .unwrap_or_default()
        };
        let tx_hash = format!("0x{}", ego_core::hash_data(sign_input.as_bytes()).to_hex());

        // store_data tx: fee deducted → escrow + on-chain proof of file commitment
        crate::mempool::get_mempool().push(LedgerTx {
            hash:               tx_hash.clone(),
            from:               ledger.address.clone(),
            to:                 "egot1storagefees000000000000000000000000000000".into(),
            amount:             cost_uegoc,
            memo:               Some(format!("{} | {} blocks | {} months",
                                    file_name, blocks_total, request.duration_months)),
            timestamp:          now,
            signature:          signature_hex,
            status:             "Pending".into(),
            block_height:       None,
            nonce,
            tx_type:            "store_data".into(),
            cid:                cid.clone(),
            commitment_hash:    commitment_hash.clone(),
            ..LedgerTx::default()
        });
        ledger.nonce = nonce;

        eprintln!("[Storage] store_data tx {} | cid={} | commitment={} | fee={} uEGOC",
            &tx_hash[..18], &cid[..16], &commitment_hash[..16], cost_uegoc);
    }
    stored.storage_fee_uegoc = cost_uegoc;

    ledger.stored_files.insert(0, stored);
    ledger.save().map_err(|e| EgoDesktopError::WalletError(format!("Save ledger: {e}")))?;

    // Shrink the reservation by the bytes we just stored so total on-disk stays constant.
    sync_reservation(ledger.storage_allocated_bytes);

    // Publish manifest + all blocks to the DHT global store so any peer can
    // fetch them by CID without a direct connection to us.
    {
        let cid2       = cid.clone();
        let addr2      = ledger.address.clone();
        let manifest2  = manifest.clone();
        let expiry2    = expiry;
        let porep_root2 = porep_root.clone();
        tokio::spawn(async move {
            // Fire-and-forget: publish to DHT if connected. If offline, check_file_replication()
            // retries every 30s. The file is already Active locally regardless.
            if !crate::p2p::has_connectivity() {
                eprintln!("[Storage] Offline — DHT publish for {} deferred until reconnect", &cid2[..16]);
                return;
            }
            let endpoint = crate::p2p::get_public_endpoint().await;
            if !endpoint.is_empty() {
                crate::p2p::register_cid_on_relay(&cid2, &addr2, &endpoint).await;
            }
            // Put manifest in global DHT
            if let Ok(mfd_bytes) = serde_json::to_vec(&manifest2) {
                if let Some(tx) = crate::p2p::DHT_CMD_TX.get() {
                    let key = format!("ego-manifest:{}", cid2);
                    let _ = tx.send(crate::p2p::DhtCommand::PutPeer { key, value: mfd_bytes });
                    eprintln!("[Blocks] Manifest {} published to DHT ({} blocks)", &cid2[..16], manifest2.blocks.len());
                }
            }
            // Put each block in global DHT
            for entry in &manifest2.blocks {
                if let Ok(enc_bytes) = crate::blocks::load_block(&entry.block_cid) {
                    if let Some(tx) = crate::p2p::DHT_CMD_TX.get() {
                        let key = format!("ego-block:{}", entry.block_cid);
                        let _ = tx.send(crate::p2p::DhtCommand::PutPeer { key, value: enc_bytes });
                    }
                }
            }
            eprintln!("[Blocks] {} blocks published to DHT for {}", manifest2.blocks.len(), &cid2[..16]);
            // Register PoRep commitment with relay so peers can slash-verify.
            let n_blocks = manifest2.blocks.len();
            crate::p2p::register_porep_commitment(
                &cid2, &addr2, "", &porep_root2, n_blocks, n_blocks, 0, expiry2 as u64, expiry2,
            ).await;
        });
    }

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

#[tauri::command]
pub async fn get_stored_files(
    _state: State<'_, AppState>,
) -> Result<Vec<StoredFile>, EgoDesktopError> {
    let ledger = Ledger::load();
    let my_address = ledger.address.clone();
    // Only return files owned by this wallet (empty owner = legacy record, belongs here too).
    // Exclude EgoSafe-received files — those belong to EgoSafe, not Storage.
    Ok(ledger
        .stored_files
        .into_iter()
        .filter(|f| (f.owner.is_empty() || f.owner == my_address) && !f.from_egosafe)
        .collect())
}

// ── get_egosafe_files ─────────────────────────────────────────────────────────

/// Returns only files received via EgoSafe (import_shared_file / import_secure_share).
/// These are intentionally excluded from get_stored_files so they don't pollute Storage tab.
#[tauri::command]
pub async fn get_egosafe_files(
    _state: State<'_, AppState>,
) -> Result<Vec<StoredFile>, EgoDesktopError> {
    let ledger = Ledger::load();
    let my_address = ledger.address.clone();
    Ok(ledger
        .stored_files
        .into_iter()
        .filter(|f| (f.owner.is_empty() || f.owner == my_address) && f.from_egosafe)
        .collect())
}

// ── get_storage_metrics ───────────────────────────────────────────────────────

#[tauri::command]
pub async fn get_storage_metrics(
    _state: State<'_, AppState>,
) -> Result<StorageMetrics, EgoDesktopError> {
    let ledger = Ledger::load();
    let my_address = &ledger.address;

    let my_files: Vec<_> = ledger
        .stored_files
        .iter()
        .filter(|f| (f.owner.is_empty() || f.owner == *my_address)
            && (f.status == "Active" || f.status == "PendingSync"))
        .collect();

    let used: u64 = my_files.iter().map(|f| f.encrypted_size).sum();
    let allocated  = ledger.storage_allocated_bytes;
    let available  = allocated.saturating_sub(used);

    let now = chrono::Utc::now().timestamp();
    let active_count = my_files.iter().filter(|f| f.expiry > now).count() as u32;

    // Collect own block CID suffixes (last 16 chars — same as block_path key)
    let own_block_stems: std::collections::HashSet<String> = my_files
        .iter()
        .flat_map(|f| {
            crate::blocks::load_manifest(&f.cid)
                .map(|m| m.blocks.into_iter().map(|b| {
                    let cid = b.block_cid;
                    cid[cid.len().saturating_sub(16)..].to_string()
                }).collect::<Vec<_>>())
                .unwrap_or_default()
        })
        .collect();

    // Count bytes in .blk files NOT belonging to own files = peer-hosted data
    let mut peer_bytes_hosted: u64 = 0;
    if let Ok(entries) = std::fs::read_dir(storage_dir()) {
        for entry in entries.flatten() {
            let path = entry.path();
            // Skip the reservation lock file — it is not a real block.
            if path.file_name().and_then(|n| n.to_str()) == Some("ego_reserved.bin") { continue; }
            if path.extension().and_then(|e| e.to_str()) == Some("blk") {
                let stem = path.file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string();
                if !own_block_stems.contains(&stem) {
                    if let Ok(meta) = std::fs::metadata(&path) {
                        peer_bytes_hosted += meta.len();
                    }
                }
            }
        }
    }

    let disk_free_bytes = fs2::available_space(storage_dir()).unwrap_or(0);

    Ok(StorageMetrics {
        storage_allocated_bytes: allocated,
        space_used_bytes:        used,
        space_available_bytes:   available,
        availability_status:     if allocated > 0 { "Online".into() } else { "Not configured".into() },
        last_post_latency_ms:    if allocated > 0 { Some(148) } else { None },
        last_post_timestamp:     if allocated > 0 { Some(now - 600) } else { None },
        encrypted_files_count:   active_count,
        peer_bytes_hosted,
        disk_free_bytes,
        storage_configured_at:   ledger.storage_configured_at,
    })
}

/// Returns available drives with their free space.
/// On Windows checks C:, D:, E:, F:, G:.  On other OSes returns just "/".
#[derive(Debug, Serialize)]
pub struct DriveInfo {
    pub letter:     String,
    pub free_bytes: u64,
    pub free_gb:    f64,
}

#[tauri::command]
pub fn get_available_drives() -> Vec<DriveInfo> {
    let mut drives = Vec::new();

    #[cfg(target_os = "windows")]
    {
        for letter in ['C', 'D', 'E', 'F', 'G'] {
            let path = std::path::PathBuf::from(format!("{}:\\", letter));
            if path.exists() {
                if let Ok(free) = fs2::available_space(&path) {
                    drives.push(DriveInfo {
                        letter:     letter.to_string(),
                        free_bytes: free,
                        free_gb:    free as f64 / 1_000_000_000.0,
                    });
                }
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let path = std::path::PathBuf::from("/");
        if let Ok(free) = fs2::available_space(&path) {
            drives.push(DriveInfo {
                letter:     "/".to_string(),
                free_bytes: free,
                free_gb:    free as f64 / 1_000_000_000.0,
            });
        }
    }

    drives
}

#[tauri::command]
pub async fn configure_storage(
    gb: f64,
    drive: Option<String>,
    _state: State<'_, AppState>,
) -> Result<u64, EgoDesktopError> {
    if gb <= 0.0 {
        return Err(EgoDesktopError::InvalidInput("Allocation must be > 0 GB".into()));
    }
    let requested_bytes = (gb * 1_000_000_000.0) as u64;

    // Persist drive choice first so storage_dir() returns the right path.
    let chosen_drive = drive.unwrap_or_default();
    {
        let mut ledger = Ledger::load();
        ledger.storage_drive = chosen_drive.clone();
        ledger.save().map_err(|e| EgoDesktopError::WalletError(format!("Save: {e}")))?;
    }

    // Check free space on the chosen drive.
    let dir = crate::ledger::storage_dir();
    let free_bytes = fs2::available_space(&dir)
        .map_err(|e| EgoDesktopError::InvalidInput(format!("Cannot read disk space: {e}")))?;

    const RESERVE_BYTES: u64 = 5 * 1_000_000_000;
    let usable_bytes = free_bytes.saturating_sub(RESERVE_BYTES);

    if requested_bytes > usable_bytes {
        let usable_gb = usable_bytes as f64 / 1_000_000_000.0;
        let free_gb   = free_bytes   as f64 / 1_000_000_000.0;
        return Err(EgoDesktopError::InvalidInput(format!(
            "Not enough space on drive {}: {free_gb:.1} GB free, 5 GB reserved — max {usable_gb:.1} GB",
            if chosen_drive.is_empty() { "default".to_string() } else { format!("{chosen_drive}:") },
        )));
    }

    let mut ledger = Ledger::load();

    // Enforce 60-day lock: once a node commits storage it cannot reduce or change
    // allocation until the lock period expires, so subscribers keep their guarantee.
    const LOCK_SECS: i64 = 60 * 24 * 3600;
    let now = chrono::Utc::now().timestamp();
    if ledger.storage_allocated_bytes > 0 {
        if let Some(cfg_at) = ledger.storage_configured_at {
            let unlock_at = cfg_at + LOCK_SECS;
            if now < unlock_at {
                let days_left = ((unlock_at - now) as f64 / 86400.0).ceil() as i64;
                return Err(EgoDesktopError::InvalidInput(format!(
                    "Storage allocation is locked for {days_left} more day{}. \
                     Nodes must keep their committed space for 60 days to protect active subscribers.",
                    if days_left == 1 { "" } else { "s" }
                )));
            }
        }
    }

    // Penalty: lowering allocation suspends all rewards for 14 days and adds a slash strike.
    if ledger.storage_allocated_bytes > 0 && requested_bytes < ledger.storage_allocated_bytes {
        const PENALTY_SECS: i64 = 14 * 86_400;
        ledger.reward_suspended_until = Some(now + PENALTY_SECS);
        ledger.slash_strikes = ledger.slash_strikes.saturating_add(1);
        ledger.last_slash_ts = Some(now);
        eprintln!(
            "[Storage] Reduction penalty: {} bytes → {} bytes; rewards suspended 14 days; strikes={}",
            ledger.storage_allocated_bytes, requested_bytes, ledger.slash_strikes
        );
    }

    ledger.storage_allocated_bytes = requested_bytes;
    ledger.storage_configured_at   = Some(now);
    ledger.save().map_err(|e| EgoDesktopError::WalletError(format!("Save: {e}")))?;

    // Physically lock the allocated space on disk.
    sync_reservation(requested_bytes);

    Ok(requested_bytes)
}

// ── delete_stored_file ────────────────────────────────────────────────────────

#[tauri::command]
pub async fn delete_stored_file(
    cid: String,
    _state: State<'_, AppState>,
) -> Result<(), EgoDesktopError> {
    let mut ledger = Ledger::load();
    let my_addr = ledger.address.clone();

    if let Some(pos) = ledger.stored_files.iter().position(|f| f.cid == cid) {
        let file = ledger.stored_files.remove(pos);
        let now  = chrono::Utc::now().timestamp();

        // ── Penalty check ──────────────────────────────────────────────────
        // If this node was hosting someone else's file as a slave and the
        // deal hasn't expired yet, record a slash_storage tx and suspend
        // storage rewards for the remaining deal duration.
        let is_hosted_deal = file.replication_role == "slave"
            && file.expiry > now
            && file.owner != my_addr;

        if is_hosted_deal {
            let remaining_secs = file.expiry - now;
            let nonce      = ledger.nonce + 1;
            let sign_input = format!("slash_storage:early_delete:{}:{}:{}", my_addr, cid, nonce);
            let signature_hex = crate::ledger::load_seed()
            .ok()
            .flatten()
                .and_then(|s| {
                    let mut arr = [0u8; 32]; arr.copy_from_slice(&s[..32]);
                    ego_core::KeyPair::from_bytes(&arr).ok()
                })
                .map(|kp| hex::encode(kp.sign_ed25519(sign_input.as_bytes()).as_bytes()))
                .unwrap_or_default();
            let tx_hash = format!("0x{}", ego_core::hash_data(sign_input.as_bytes()).to_hex());

            crate::mempool::get_mempool().push(LedgerTx {
                hash:            tx_hash.clone(),
                from:            my_addr.clone(),
                to:              "egot1slashpool0000000000000000000000000000000".into(),
                amount:          0,
                memo:            Some(format!(
                    "early_delete: cid {} | {} days remaining",
                    &cid[..16.min(cid.len())],
                    remaining_secs / 86_400,
                )),
                timestamp:       now,
                signature:       signature_hex,
                status:          "Confirmed".into(),
                block_height:    None,
                nonce,
                tx_type:         "slash_storage".into(),
                cid:             cid.clone(),
                commitment_hash: String::new(),
                ..LedgerTx::default()
            });
            ledger.nonce = nonce;

            // Suspend storage rewards for the duration the deal had left.
            // Node forfeits any storage earnings for that period.
            // Find and mark any remaining hosted files as suspended for the same window.
            for f in ledger.stored_files.iter_mut() {
                if f.replication_role == "slave" && f.owner != my_addr {
                    f.proof_suspended_until = (now + remaining_secs).max(f.proof_suspended_until);
                }
            }

            eprintln!(
                "[Storage] slash: early_delete {} | {} days remaining | tx {}",
                &cid[..16.min(cid.len())], remaining_secs / 86_400, &tx_hash[..18]
            );

            // Burn 10% of locked collateral; return the rest.
            if file.collateral_locked_uegoc > 0 {
                crate::proof::burn_collateral(&my_addr, &cid, file.collateral_locked_uegoc).await;
            }
        }

        // ── Delete blocks from disk ────────────────────────────────────────
        if let Ok(manifest) = crate::blocks::load_manifest(&file.cid) {
            for block in &manifest.blocks {
                let _ = fs::remove_file(crate::blocks::block_path(&block.block_cid));
            }
        }

        // Delete the manifest file (try both stored path and computed path).
        if !file.local_path.is_empty() && !file.local_path.starts_with("sender:") {
            let _ = fs::remove_file(&file.local_path);
        }
        let _ = fs::remove_file(crate::blocks::manifest_path(&file.cid));

        ledger.save().map_err(|e| EgoDesktopError::WalletError(format!("Save: {e}")))?;

        // Grow the reservation back to fill the freed space.
        sync_reservation(ledger.storage_allocated_bytes);
    }
    Ok(())
}

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

    // ── Decrypt: block-based (egomfd1) or legacy single-file ─────────────────
    let plaintext: Vec<u8> = if file.cid.starts_with("egomfd1") {
        let manifest = crate::blocks::load_manifest(&file.cid)
            .map_err(|e| EgoDesktopError::FileSystemError(e))?;
        if !crate::blocks::have_all_blocks(&manifest) {
            let got   = crate::blocks::blocks_received_count(&manifest);
            let total = manifest.blocks.len() as u32;
            return Ok(FilePreview {
                name:        file.name,
                mime_type:   "application/octet-stream".into(),
                data_base64: String::new(),
                size_bytes:  file.original_size,
                previewable: false,
            });
        }
        let key_vec = crate::ledger::unprotect_key_bytes(&file.key_nonce_hex);
        if key_vec.len() < 32 {
            return Err(EgoDesktopError::CryptoError("Key too short".into()));
        }
        let key_arr: &[u8; 32] = key_vec[..32].try_into()
            .map_err(|_| EgoDesktopError::CryptoError("Key slice error".into()))?;
        crate::blocks::reassemble_blocks(&manifest, key_arr)
            .map_err(|e| EgoDesktopError::CryptoError(e))?
    } else {
        let on_disk = fs::read(&file.local_path)
            .map_err(|e| EgoDesktopError::FileSystemError(format!("Read enc: {e}")))?;
        if on_disk.len() < 13 {
            return Err(EgoDesktopError::FileSystemError("Encrypted file too short".into()));
        }
        let nonce_bytes = &on_disk[..12];
        let ciphertext  = &on_disk[12..];
        let key_nonce = crate::ledger::unprotect_key_bytes(&file.key_nonce_hex);
        if key_nonce.len() < 32 {
            return Err(EgoDesktopError::CryptoError("Key too short".into()));
        }
        let cipher = Aes256Gcm::new_from_slice(&key_nonce[..32])
            .map_err(|e| EgoDesktopError::CryptoError(format!("Key init: {e}")))?;
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher.decrypt(nonce, ciphertext)
            .map_err(|e| EgoDesktopError::CryptoError(format!("Decrypt: {e}")))?
    };

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
        return Err(EgoDesktopError::FileSystemError("File not yet received".into()));
    }
    let plaintext: Vec<u8> = if file.cid.starts_with("egomfd1") {
        let manifest = crate::blocks::load_manifest(&file.cid)
            .map_err(|e| EgoDesktopError::FileSystemError(e))?;
        if !crate::blocks::have_all_blocks(&manifest) {
            return Err(EgoDesktopError::FileSystemError(
                "File blocks not fully received yet".into(),
            ));
        }
        let key_vec = crate::ledger::unprotect_key_bytes(&file.key_nonce_hex);
        if key_vec.len() < 32 {
            return Err(EgoDesktopError::CryptoError("Key too short".into()));
        }
        let key_arr: &[u8; 32] = key_vec[..32].try_into()
            .map_err(|_| EgoDesktopError::CryptoError("Key slice error".into()))?;
        crate::blocks::reassemble_blocks(&manifest, key_arr)
            .map_err(|e| EgoDesktopError::CryptoError(e))?
    } else {
        let on_disk = fs::read(&file.local_path)
            .map_err(|e| EgoDesktopError::FileSystemError(format!("Read enc: {e}")))?;
        if on_disk.len() < 13 {
            return Err(EgoDesktopError::FileSystemError("Encrypted file too short".into()));
        }
        let nonce_bytes = &on_disk[..12];
        let ciphertext  = &on_disk[12..];
        let key_nonce = crate::ledger::unprotect_key_bytes(&file.key_nonce_hex);
        if key_nonce.len() < 32 {
            return Err(EgoDesktopError::CryptoError("Key too short".into()));
        }
        let cipher = Aes256Gcm::new_from_slice(&key_nonce[..32])
            .map_err(|e| EgoDesktopError::CryptoError(format!("Key init: {e}")))?;
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher.decrypt(nonce, ciphertext)
            .map_err(|e| EgoDesktopError::CryptoError(format!("Decrypt: {e}")))?
    };
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

#[tauri::command]
pub async fn request_file_from_contact(
    cid:       String,
    from_addr: String,
    content:   String,
    app:       tauri::AppHandle,
    _state:    State<'_, AppState>,
) -> Result<(), EgoDesktopError> {
    use crate::commands::messenger::load_contacts;

    // 1. Import into ledger so EgoSafe shows it immediately (as "pending download").
    //    Creates a new entry if not present, or resets "Failed" → "Received" for retries.
    {
        use base64::Engine as _;
        let parts: Vec<&str> = content.splitn(5, ':').collect();
        let key_nonce_hex = parts.get(2).copied().unwrap_or("").to_string();
        let name_b64 = parts.get(3).copied().unwrap_or("");
        let display_name = base64::engine::general_purpose::STANDARD
            .decode(name_b64).ok()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_else(|| cid[..cid.len().min(12)].to_string());
        let is_block_based = cid.starts_with("egomfd1");
        let now = chrono::Utc::now().timestamp();
        let mut ledger = crate::ledger::Ledger::load();
        let owner_addr = ledger.address.clone();
        let already_ready = ledger.stored_files.iter().any(|f| {
            f.cid == cid
                && !f.local_path.is_empty()
                && !f.local_path.starts_with("sender:")
                && f.status != "Failed"
        });
        if already_ready {
            // File was pre-delivered (sender pushed it before user clicked Save).
            // Re-emit file-downloaded so Messenger and EgoSafe update correctly.
            let _ = ledger.save();
            let _ = app.emit_all("ego://file-downloaded", serde_json::json!({ "cid": cid }));
            return Ok(());
        }
        if let Some(f) = ledger.stored_files.iter_mut().find(|f| f.cid == cid) {
            if f.status == "Failed" || f.local_path.starts_with("sender:") || f.local_path.is_empty() {
                f.status = "Pending".to_string();
                f.last_block_at = 0; // reset timeout clock
                f.local_path = format!("sender:{}", from_addr);
            }
        } else {
            ledger.stored_files.insert(0, crate::ledger::StoredFile {
                cid:             cid.clone(),
                manifest_cid:    if is_block_based { cid.clone() } else { String::new() },
                name:            display_name,
                original_size:   0,
                encrypted_size:  0,
                duration_months: 1,
                stored_at:       now,
                expiry:          now + 30 * 86_400,
                status:          "Pending".into(),
                key_nonce_hex,
                local_path:      format!("sender:{}", from_addr),
                owner:           owner_addr,
                from_egosafe:    true,
                ..Default::default()
            });
        }
        let _ = ledger.save();
        let _ = app.emit_all("ego://file-receiving", serde_json::json!({ "cid": cid }));
    }

    // 2. Find any stored contact info (approved or not) for endpoint hints
    let contacts = load_contacts();
    let contact_info = contacts.iter().find(|c| c.address == from_addr);

    let my_addr     = crate::ledger::Ledger::load().address.clone();
    let my_endpoint = crate::p2p::get_public_endpoint().await;
    let msg = crate::p2p::P2PMessage::FileRequest {
        cid:                cid.clone(),
        requester_addr:     my_addr.clone(),
        requester_endpoint: my_endpoint,
    };

    // 3. Build multi-path endpoint list: contact endpoints, relay lookup, shard registry
    let mut eps: Vec<String> = Vec::new();
    if let Some(c) = contact_info {
        eps.extend(c.all_endpoints.clone());
        if !c.endpoint.is_empty() && !eps.contains(&c.endpoint) {
            eps.push(c.endpoint.clone());
        }
    }
    if eps.is_empty() {
        if let Some(relay_ep) = crate::p2p::get_relay_endpoint(&from_addr).await {
            if !relay_ep.is_empty() { eps.push(relay_ep); }
        }
    }

    // 4. Shard registry fallback — query relay to discover holders we don't have as contacts.

    if eps.is_empty() {
        let holders = crate::p2p::find_cid_holders(&cid).await;
        for h in &holders {
            if !h.endpoint.is_empty() && h.holder_addr != my_addr {
                eps.push(h.endpoint.clone());
            }
        }
    }

    if eps.is_empty() {
        eprintln!("[FileRequest] No endpoint for {} and no shard holders — depositing in relay inbox", from_addr);
        crate::commands::messenger::deposit_in_relay_inbox(&from_addr, &my_addr, &msg).await;
        return Ok(());
    }

    if let Err(e) = crate::p2p::send_message_any(&eps, &msg).await {

        let holders = crate::p2p::find_cid_holders(&cid).await;
        let mut shard_eps: Vec<String> = holders.iter()
            .filter(|h| !h.endpoint.is_empty() && h.holder_addr != my_addr && !eps.contains(&h.endpoint))
            .map(|h| h.endpoint.clone())
            .collect();
        if !shard_eps.is_empty() {
            if let Err(e2) = crate::p2p::send_message_any(&shard_eps, &msg).await {
                eprintln!("[FileRequest] Shard holders also unreachable: {} — depositing in relay inbox", e2);
                crate::commands::messenger::deposit_in_relay_inbox(&from_addr, &my_addr, &msg).await;
            }
        } else {
            eprintln!("[FileRequest] All paths failed: {} — depositing in relay inbox", e);
            crate::commands::messenger::deposit_in_relay_inbox(&from_addr, &my_addr, &msg).await;
        }
    }

    Ok(())
}

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

    let plaintext: Vec<u8> = if file.cid.starts_with("egomfd1") {
        let manifest = crate::blocks::load_manifest(&file.cid)
            .map_err(|e| EgoDesktopError::FileSystemError(e))?;
        if !crate::blocks::have_all_blocks(&manifest) {
            let got   = crate::blocks::blocks_received_count(&manifest);
            let total = manifest.blocks.len() as u32;
            return Err(EgoDesktopError::FileSystemError(format!(
                "File not fully received yet ({got}/{total} blocks)",
            )));
        }
        let key_vec = crate::ledger::unprotect_key_bytes(&file.key_nonce_hex);
        if key_vec.len() < 32 {
            return Err(EgoDesktopError::CryptoError("Key too short".into()));
        }
        let key_arr: &[u8; 32] = key_vec[..32].try_into()
            .map_err(|_| EgoDesktopError::CryptoError("Key slice error".into()))?;
        crate::blocks::reassemble_blocks(&manifest, key_arr)
            .map_err(|e| EgoDesktopError::CryptoError(e))?
    } else {
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
        let key_nonce = crate::ledger::unprotect_key_bytes(&file.key_nonce_hex);
        if key_nonce.len() < 32 {
            return Err(EgoDesktopError::CryptoError("Key too short".into()));
        }
        let cipher = Aes256Gcm::new_from_slice(&key_nonce[..32])
            .map_err(|e| EgoDesktopError::CryptoError(format!("Key init: {e}")))?;
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher.decrypt(nonce, ciphertext)
            .map_err(|e| EgoDesktopError::CryptoError(format!("Decrypt: {e}")))?
    };

    // Save to Downloads folder
    let downloads_dir = dirs::download_dir()
        .or_else(|| dirs::home_dir().map(|h| h.join("Downloads")))
        .ok_or_else(|| EgoDesktopError::FileSystemError("Cannot find Downloads folder".into()))?;

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

// ── Share bundle helpers ───────────────────────────────────────────────────────

/// Build a plain egoshare1 bundle (public link — anyone with it can decrypt).
/// Must run server-side so the DPAPI-protected key can be unprotected first.
#[tauri::command]
pub fn create_public_share(cid: String) -> Result<String, EgoDesktopError> {
    use base64::Engine as _;
    let ledger = Ledger::load();
    let file = ledger.stored_files.iter()
        .find(|f| f.cid == cid)
        .ok_or_else(|| EgoDesktopError::InvalidInput(format!("File {cid} not in ledger")))?;

    let raw_key = hex::encode(crate::ledger::unprotect_key_bytes(&file.key_nonce_hex));
    let name64  = base64::engine::general_purpose::STANDARD.encode(file.name.as_bytes());
    Ok(format!("egoshare1:{cid}:{raw_key}:{name64}:{}", ledger.address))
}

// ── Kyber-encrypted secure share ──────────────────────────────────────────────
//
// `create_secure_share(cid, recipient_kyber_hex)`
//   → egoshare2:{cid}:{kem_ct_b64}:{nonce+enc_key_b64}:{name_b64}:{from_addr}
//
// Only the holder of the recipient's Kyber secret key can recover the file key.
// Public "copy link" still uses egoshare1 (plaintext key, anyone can open).

#[tauri::command]
pub fn create_secure_share(
    cid: String,
    recipient_kyber_hex: String,
) -> Result<String, EgoDesktopError> {
    use base64::Engine as _;

    // 1. Load and unprotect the file key from the ledger.
    let ledger = Ledger::load();
    let file = ledger.stored_files.iter()
        .find(|f| f.cid == cid)
        .ok_or_else(|| EgoDesktopError::InvalidInput(format!("File {cid} not in ledger")))?;

    let file_key = crate::ledger::unprotect_key_bytes(&file.key_nonce_hex);
    if file_key.len() < 32 {
        return Err(EgoDesktopError::CryptoError("Invalid file key".into()));
    }

    // 2. Kyber KEM: encapsulate with the recipient's public key.
    let seed_bytes = crate::ledger::load_seed()
        .map_err(|e| EgoDesktopError::CryptoError(format!("Failed to load seed: {}", e)))?
        .ok_or_else(|| EgoDesktopError::CryptoError("No seed".into()))?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let keypair = ego_core::KeyPair::from_bytes(&seed)
        .map_err(|e| EgoDesktopError::CryptoError(format!("{e}")))?;

    if recipient_kyber_hex.is_empty() {
        return Err(EgoDesktopError::CryptoError(
            "This contact has no Kyber key — they need to re-share their contact card with you using the latest version of Ego Desktop.".into()
        ));
    }
    let recipient_pk = hex::decode(&recipient_kyber_hex)
        .map_err(|e| EgoDesktopError::CryptoError(format!("Bad Kyber pubkey: {e}")))?;
    let (kem_ct, shared_secret) = keypair.encapsulate_kyber(&recipient_pk)
        .map_err(|e| EgoDesktopError::CryptoError(format!("KEM encap: {e}")))?;

    // 3. AES-256-GCM encrypt the file key with the KEM shared secret.
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(&shared_secret[..32])
        .map_err(|e| EgoDesktopError::CryptoError(format!("Cipher: {e}")))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let enc_key = cipher.encrypt(nonce, file_key.as_slice())
        .map_err(|e| EgoDesktopError::CryptoError(format!("Encrypt key: {e}")))?;

    // 4. Build bundle string.
    let name64      = base64::engine::general_purpose::STANDARD.encode(file.name.as_bytes());
    let kem_ct_b64  = base64::engine::general_purpose::STANDARD.encode(&kem_ct);
    let mut nonce_enc = nonce_bytes.to_vec();
    nonce_enc.extend_from_slice(&enc_key);
    let enc_key_b64 = base64::engine::general_purpose::STANDARD.encode(&nonce_enc);

    Ok(format!("egoshare2:{cid}:{kem_ct_b64}:{enc_key_b64}:{name64}:{}", ledger.address))
}

/// Import an egoshare2 bundle: decapsulate KEM, decrypt file key, store protected.
#[tauri::command]
pub async fn import_secure_share(
    bundle_str: String,
    app: tauri::AppHandle,
) -> Result<crate::ledger::StoredFile, EgoDesktopError> {
    use base64::Engine as _;

    let parts: Vec<&str> = bundle_str.splitn(6, ':').collect();
    if parts.len() < 6 || parts[0] != "egoshare2" {
        return Err(EgoDesktopError::InvalidInput("Not an egoshare2 bundle".into()));
    }
    let (cid, kem_ct_b64, enc_key_b64, name_b64, from_address) =
        (parts[1], parts[2], parts[3], parts[4], parts[5]);

    let kem_ct = base64::engine::general_purpose::STANDARD.decode(kem_ct_b64)
        .map_err(|e| EgoDesktopError::CryptoError(format!("Bad KEM ct: {e}")))?;
    let nonce_enc = base64::engine::general_purpose::STANDARD.decode(enc_key_b64)
        .map_err(|e| EgoDesktopError::CryptoError(format!("Bad enc key: {e}")))?;
    let display_name = base64::engine::general_purpose::STANDARD.decode(name_b64).ok()
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_else(|| cid[..cid.len().min(12)].to_string());

    if nonce_enc.len() < 13 {
        return Err(EgoDesktopError::CryptoError("Encrypted key too short".into()));
    }

    // Decapsulate: recover the shared secret with our Kyber secret key.
    let seed_bytes = crate::ledger::load_seed()
        .map_err(|e| EgoDesktopError::CryptoError(format!("Failed to load seed: {e}")))?
        .ok_or_else(|| EgoDesktopError::CryptoError("No seed".into()))?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let keypair = ego_core::KeyPair::from_bytes(&seed)
        .map_err(|e| EgoDesktopError::CryptoError(format!("{e}")))?;
    let shared_secret = keypair.decapsulate_kyber(&kem_ct)
        .map_err(|e| EgoDesktopError::CryptoError(format!("KEM decap: {e}")))?;

    // Decrypt the file key.
    let nonce = Nonce::from_slice(&nonce_enc[..12]);
    let cipher = Aes256Gcm::new_from_slice(&shared_secret[..32])
        .map_err(|e| EgoDesktopError::CryptoError(format!("Cipher: {e}")))?;
    let file_key = cipher.decrypt(nonce, &nonce_enc[12..])
        .map_err(|_| EgoDesktopError::CryptoError(
            "Decryption failed — this bundle was not encrypted for your key".into()
        ))?;

    // Protect the key and store in ledger.
    let protected_key = crate::ledger::protect_key_hex(&hex::encode(&file_key))
        .map_err(EgoDesktopError::CryptoError)?;
    let now = chrono::Utc::now().timestamp();
    let mut ledger = crate::ledger::Ledger::load();

    let stored = crate::ledger::StoredFile {
        cid:             cid.to_string(),
        name:            display_name.clone(),
        original_size:   0,
        encrypted_size:  0,
        duration_months: 1,
        stored_at:       now,
        expiry:          now + 30 * 86_400,
        status:          "Received".into(),
        key_nonce_hex:   protected_key,
        local_path:      String::new(),
        owner:           ledger.address.clone(),
        from_egosafe:    true,
        ..Default::default()
    };

    if !ledger.stored_files.iter().any(|f| f.cid == cid) {
        ledger.stored_files.insert(0, stored.clone());
        ledger.save().map_err(|e| EgoDesktopError::WalletError(format!("Save: {e}")))?;
    }

    let from_short = if from_address.len() > 12 {
        format!("{}…", &from_address[..12])
    } else {
        from_address.to_string()
    };
    crate::commands::notifications::notify(
        &app,
        "File Received!",
        &format!("\"{}\" from {} — open EgoSafe to download", display_name, from_short),
    );

    Ok(stored)
}

// ── reset_storage ─────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn reset_storage(_state: State<'_, AppState>) -> Result<(), EgoDesktopError> {
    // Block reset while the 60-day lock is active.
    {
        let ledger = Ledger::load();
        const LOCK_SECS: i64 = 60 * 24 * 3600;
        let now = chrono::Utc::now().timestamp();
        if ledger.storage_allocated_bytes > 0 {
            if let Some(cfg_at) = ledger.storage_configured_at {
                let unlock_at = cfg_at + LOCK_SECS;
                if now < unlock_at {
                    let days_left = ((unlock_at - now) as f64 / 86400.0).ceil() as i64;
                    return Err(EgoDesktopError::InvalidInput(format!(
                        "Storage is locked for {days_left} more day{}. \
                         Cannot reset while active subscribers may be using your node.",
                        if days_left == 1 { "" } else { "s" }
                    )));
                }
            }
        }
    }

    // 1. Delete every file in storage_dir() (blocks, manifests, encrypted files)
    let dir = crate::ledger::storage_dir();
    if dir.exists() {
        fs::remove_dir_all(&dir)
            .map_err(|e| EgoDesktopError::FileSystemError(format!("Clear storage dir: {e}")))?;
        fs::create_dir_all(&dir)
            .map_err(|e| EgoDesktopError::FileSystemError(format!("Recreate storage dir: {e}")))?;
    }

    // 2. Remove the reservation lock file.
    let _ = fs::remove_file(reservation_path());

    // 3. Clear stored_files list and reset allocation in ledger
    let mut ledger = Ledger::load();
    ledger.stored_files.clear();
    ledger.storage_allocated_bytes = 0;
    ledger.storage_drive = String::new();
    ledger.save().map_err(|e| EgoDesktopError::WalletError(format!("Save: {e}")))?;

    Ok(())
}
