use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

pub static TX_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

static LEDGER_IO_MUTEX: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
fn ledger_io_mutex() -> &'static std::sync::Mutex<()> {
    LEDGER_IO_MUTEX.get_or_init(|| std::sync::Mutex::new(()))
}

static REGISTRY_IO_MUTEX: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
fn registry_io_mutex() -> &'static std::sync::Mutex<()> {
    REGISTRY_IO_MUTEX.get_or_init(|| std::sync::Mutex::new(()))
}

pub fn base_data_dir() -> PathBuf {
    let dir = if let Ok(v) = std::env::var("EGO_DATA_DIR") {
        PathBuf::from(v)
    } else {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("EgoDesktop")
    };
    let _ = fs::create_dir_all(&dir);
    dir
}

pub fn wallet_dir(wallet_id: &str) -> PathBuf {
    let dir = base_data_dir().join(wallet_id);
    let _ = fs::create_dir_all(&dir);
    dir
}

pub fn registry_path() -> PathBuf {
    base_data_dir().join("wallets.json")
}

pub fn get_active_wallet_id() -> String {
    let id = load_registry().active_id;
    if id.trim().is_empty() { "wallet_0".to_string() } else { id }
}

pub fn data_dir() -> PathBuf {
    wallet_dir(&get_active_wallet_id())
}

pub fn storage_dir() -> PathBuf {
    // If the user chose a specific drive (e.g. "D"), store under
    // {drive}:\EgoDesktop\{wallet_id}\storage  — wallet-scoped, less exposed.
    // Otherwise fall back to the default data_dir()/storage.
    let ledger = Ledger::load();
    let drive = ledger.storage_drive.trim().to_uppercase();
    let base = if !drive.is_empty() && drive.len() == 1 {
        #[cfg(target_os = "windows")]
        let p = PathBuf::from(format!(
            "{}:\\EgoDesktop\\{}\\storage",
            drive,
            get_active_wallet_id()
        ));
        #[cfg(not(target_os = "windows"))]
        let p = data_dir().join("storage");
        p
    } else {
        data_dir().join("storage")
    };
    let _ = fs::create_dir_all(&base);
    base
}


pub fn seed_path() -> PathBuf {
    data_dir().join("wallet.seed")
}

#[cfg(not(windows))]
const SEED_KEYRING_SENTINEL: &[u8] = b"ego-keyring-seed-v1";
#[cfg(not(windows))]
const PROTECTED_KEY_PREFIX: &str = "seedprot:";
#[cfg(not(windows))]
const LEGACY_KEYRING_PREFIX: &str = "keyring:";

#[cfg(not(windows))]
fn seed_keyring_entry() -> Result<keyring::Entry, keyring::Error> {
    keyring::Entry::new("ego-desktop", "wallet-seed")
}

#[cfg(not(windows))]
fn seed_wrap_key(seed: &[u8]) -> Option<[u8; 32]> {
    if seed.len() != 32 {
        return None;
    }
    let mut input = b"ego/protected-key-wrap/v1".to_vec();
    input.extend_from_slice(seed);
    let hash = ego_core::hash_data(&input);
    let mut key = [0u8; 32];
    key.copy_from_slice(hash.as_bytes());
    Some(key)
}

#[cfg(not(windows))]
fn encrypt_seed_wrapped_blob(key: &[u8; 32], plaintext: &[u8]) -> Option<String> {
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
    use base64::Engine as _;

    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce_bytes), plaintext).ok()?;
    let mut blob = nonce_bytes.to_vec();
    blob.extend(ciphertext);
    Some(format!(
        "{}{}",
        PROTECTED_KEY_PREFIX,
        base64::engine::general_purpose::STANDARD.encode(blob),
    ))
}

#[cfg(not(windows))]
fn decrypt_seed_wrapped_blob(seed: &[u8], encoded: &str) -> Option<Vec<u8>> {
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
    use base64::Engine as _;

    let key = seed_wrap_key(seed)?;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    if blob.len() < 28 {
        return None;
    }
    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
    cipher.decrypt(Nonce::from_slice(nonce_bytes), ciphertext).ok()
}

/// Load the wallet seed, decrypting it with OS DPAPI if it was previously protected.
pub fn load_seed() -> Result<Option<Vec<u8>>, String> {
    let path = seed_path();
    if !path.exists() {
        return Ok(None);
    }

    #[cfg(not(windows))]
    {
        let raw = fs::read(&path).map_err(|e| format!("Failed to read seed file: {}", e))?;
        if raw == SEED_KEYRING_SENTINEL || raw == b"ego-keyring-protected" {
            use base64::Engine as _;

            let entry = seed_keyring_entry().map_err(|e| format!("Keyring init error: {}", e))?;
            let pw = match entry.get_password() {
                Ok(p) => p,
                Err(keyring::Error::NoEntry) => return Ok(None),
                Err(e) => {
                    let err_str = e.to_string();
                    if err_str.contains("User canceled") || err_str.contains("Access control") {
                        return Err(format!(
                            "macOS Keychain Access Denied: {}. This happens because the app signature changed or is not notarized.\n\n\
                        FIX: Open 'Keychain Access.app', search for 'ego-desktop', delete the entry named 'ego-desktop', then run 'rm -rf ~/Library/Application\\ Support/EgoDesktop' in Terminal and restart.",
                            err_str
                        ));
                    }
                    return Err(format!("Keyring read error: {}", err_str));
                }
            };
            let bytes = base64::engine::general_purpose::STANDARD.decode(pw).unwrap_or_default();
            if bytes.len() != 32 {
                return Err(format!(
                    "Decrypted seed has invalid length ({} bytes). Local data is out of sync with Keychain.\n\n\
                    FIX: Delete the 'ego-desktop' keychain entry and run 'rm -rf ~/Library/Application\\ Support/EgoDesktop' in Terminal, then restart and re-import your phrase.",
                    bytes.len()
                ));
            }
            return Ok(Some(bytes));
        }
        if raw.len() != 32 {
            return Err("Raw seed has invalid length".into());
        }
        return Ok(Some(raw));
    }

    #[cfg(windows)]
    {
    let raw = fs::read(&path).map_err(|e| format!("Failed to read seed file: {}", e))?;
    let bytes = crate::utils::os_unprotect(&raw);
    if bytes.is_empty() {
        return Err("DPAPI decryption failed".into());
    }
    if bytes.len() != 32 {
        return Err("Decrypted seed has invalid length".into());
    }
    Ok(Some(bytes))
    }
}

/// Save the wallet seed, encrypting it with OS DPAPI before writing.
pub fn save_seed(seed: &[u8]) -> std::io::Result<()> {
    #[cfg(not(windows))]
    {
        use base64::Engine as _;

        let entry = seed_keyring_entry()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("keyring init: {e}")))?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(seed);
        entry
            .set_password(&encoded)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("keyring store: {e}")))?;
        return crate::utils::atomic_write(&seed_path(), SEED_KEYRING_SENTINEL);
    }

    #[cfg(windows)]
    {
    let protected = crate::utils::os_protect(seed);
    crate::utils::atomic_write(&seed_path(), &protected)
    }
}

/// Encode a raw AES key (as hex) for at-rest storage using OS DPAPI.
/// Stored format: `"prot:{base64_of_dpapi_blob}"`.
/// On non-Windows, wraps the key with a seed-derived AEAD key.
pub fn protect_key_hex(raw_hex: &str) -> Result<String, String> {
    match hex::decode(raw_hex) {
        Ok(bytes) => {
            #[cfg(not(windows))]
            {
                if let Ok(Some(seed)) = load_seed() {
                    if let Some(encoded) = seed_wrap_key(&seed)
                        .and_then(|key| encrypt_seed_wrapped_blob(&key, &bytes))
                    {
                        return Ok(encoded);
                    }
                }

                use base64::Engine as _;

                let id = ego_core::hash_data(&bytes).to_hex();
                let entry = keyring::Entry::new("ego-desktop", &format!("protected-key-{id}"))
                    .map_err(|e| format!("keyring init: {e}"))?;
                let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
                entry
                    .set_password(&encoded)
                    .map_err(|e| format!("keyring store: {e}"))?;
                return Ok(format!("{}{}", LEGACY_KEYRING_PREFIX, id));
            }

            #[cfg(windows)]
            {
            let blob = crate::utils::os_protect(&bytes);
            use base64::Engine as _;
            Ok(format!("prot:{}", base64::engine::general_purpose::STANDARD.encode(&blob)))
            }
        }
        Err(_) => Err("invalid protected key hex".into()),
    }
}

/// Decode a stored key back to raw bytes.
/// Handles both the `"prot:{base64}"` format written by `protect_key_hex`
/// and legacy plaintext hex (for wallets created before this change).
pub fn unprotect_key_bytes(stored: &str) -> Vec<u8> {
    #[cfg(not(windows))]
    {
        if let Some(encoded) = stored.strip_prefix(PROTECTED_KEY_PREFIX) {
            if let Ok(Some(seed)) = load_seed() {
                if let Some(bytes) = decrypt_seed_wrapped_blob(&seed, encoded) {
                    return bytes;
                }
            }
            return Vec::new();
        }

        if let Some(id) = stored.strip_prefix(LEGACY_KEYRING_PREFIX) {
            use base64::Engine as _;

            if let Ok(entry) = keyring::Entry::new("ego-desktop", &format!("protected-key-{id}")) {
                if let Ok(pw) = entry.get_password() {
                    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(pw) {
                        return bytes;
                    }
                }
            }
            return Vec::new();
        }
    }

    if let Some(b64) = stored.strip_prefix("prot:") {
        use base64::Engine as _;
        if let Ok(blob) = base64::engine::general_purpose::STANDARD.decode(b64) {
            return crate::utils::os_unprotect(&blob);
        }
    }
    // Legacy: plain hex — still works for old ledger.json files
    hex::decode(stored).unwrap_or_default()
}

pub fn ledger_path() -> PathBuf {
    data_dir().join("ledger.json")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletEntry {
    pub id: String,
    pub name: String,

    pub address: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletRegistry {
    pub active_id: String,
    pub wallets: Vec<WalletEntry>,
}

impl Default for WalletRegistry {
    fn default() -> Self {
        Self {
            active_id: "wallet_0".to_string(),
            wallets: Vec::new(),
        }
    }
}

pub fn load_registry() -> WalletRegistry {
    let _guard = registry_io_mutex().lock().unwrap_or_else(|e| e.into_inner());
    let path = registry_path();
    if !path.exists() {
        return WalletRegistry::default();
    }
    for attempt in 0..10 {
        match fs::read_to_string(&path) {
            Ok(data) => {
                if data.is_empty() {
                    if attempt < 9 {
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        continue;
                    }
                    return WalletRegistry::default();
                }
                match serde_json::from_str::<WalletRegistry>(&data) {
                    Ok(reg) => return reg,
                    Err(e) => {
                        if attempt < 9 {
                            std::thread::sleep(std::time::Duration::from_millis(50));
                            continue;
                        }
                        eprintln!("[Registry] WARN: load failed after retries ({}); refusing to overwrite with defaults", e);
                        return WalletRegistry::default();
                    }
                }
            }
            Err(e) => {
                if attempt < 9 {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    continue;
                }
                eprintln!("[Registry] WARN: read failed after retries ({}); refusing to overwrite with defaults", e);
                return WalletRegistry::default();
            }
        }
    }
    WalletRegistry::default()
}

pub fn save_registry(registry: &WalletRegistry) -> Result<(), String> {
    let _guard = registry_io_mutex().lock().unwrap_or_else(|e| e.into_inner());
    let data = serde_json::to_string_pretty(registry).map_err(|e| e.to_string())?;
    crate::utils::atomic_write(&registry_path(), data.as_bytes()).map_err(|e| e.to_string())
}

pub fn next_wallet_id(registry: &WalletRegistry) -> String {
    let max_n = registry
        .wallets
        .iter()
        .filter_map(|w| w.id.strip_prefix("wallet_").and_then(|n| n.parse::<u32>().ok()))
        .max()
        .unwrap_or(0);
    if registry.wallets.is_empty() {
        "wallet_0".to_string()
    } else {
        format!("wallet_{}", max_n + 1)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LedgerTx {
    pub hash: String,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub memo: Option<String>,
    pub timestamp: i64,

    pub signature: String,
    pub status: String,
    pub block_height: Option<u64>,
    #[serde(default)]
    pub nonce: u64,

    #[serde(default)]
    pub public_key_ed25519: String,

    #[serde(default)]
    pub dilithium_pubkey: String,

    #[serde(default)]
    pub dilithium_signature: String,

    #[serde(default = "default_tx_type")]
    pub tx_type: String,

    #[serde(default)]
    pub fee_uegoc: u64,

    #[serde(default)]
    pub priority_fee_uegoc: u64,

    #[serde(default)]
    pub wasm_code: String,

    #[serde(default)]
    pub contract_addr: String,

    #[serde(default)]
    pub entrypoint: String,

    #[serde(default)]
    pub call_args: String,

    /// For tx_type="store_data" and "retrieve_file": the file's content-addressed CID.
    #[serde(default)]
    pub cid: String,

    /// Blake3 merkle commitment over all block CIDs — proves the file existed at this height.
    #[serde(default)]
    pub commitment_hash: String,

    /// EGO-712: 1 = v1 (legacy, no chain_id/memo in sign bytes), 2 = v2 (chain_id + memo committed).
    #[serde(default)]
    pub tx_version: u8,

    /// Chain identifier committed into the v2 signature (1 = testnet, 2 = mainnet).
    #[serde(default)]
    pub chain_id: u8,

    /// Human-readable summary derived from the exact fields that were signed.
    /// Generated by the backend — cannot be faked by the UI layer.
    #[serde(default)]
    pub signed_summary: String,

    #[serde(default)]
    pub is_private: bool,

    #[serde(default)]
    pub compliance_proof: String,
}

fn default_tx_type() -> String { "transfer".to_string() }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LedgerBlock {
    pub height: u64,
    pub hash: String,
    pub prev_hash: String,
    pub timestamp: i64,
    pub miner: String,
    pub tx_count: u32,
    pub size_bytes: u64,
    pub reward: u64,

    #[serde(default)]
    pub coinbase_tx: Option<String>,

    #[serde(default)]
    pub vote_count: u32,

    #[serde(default)]
    pub tx_merkle_root: String,

    #[serde(default)]
    pub poc_ticket: String,

    #[serde(default)]
    pub poc_slot: u64,

    /// Blake3 Merkle root of all (address, new_balance) pairs modified in this block,
    /// sorted lexicographically by address.  Commits the account-state delta so any
    /// tampering with the balance DB is detectable without replaying all transactions.
    /// Empty string = legacy block (pre-state-root upgrade); never falsifies the hash.
    #[serde(default)]
    pub state_root: String,

    #[serde(default)]
    pub base_fee_uegoc: u64,

    #[serde(default)]
    pub agg_bls_sig: String,

    #[serde(default)]
    pub bls_pubkeys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StoredFile {
    pub cid: String,
    pub name: String,
    pub original_size: u64,
    pub encrypted_size: u64,
    pub duration_months: u32,
    pub stored_at: i64,
    pub expiry: i64,
    pub status: String,
    pub key_nonce_hex: String,
    pub local_path: String,
    #[serde(default)]
    pub owner: String,

    #[serde(default)]
    pub comm_d: String,

    #[serde(default)]
    pub comm_r: String,

    #[serde(default)]
    pub sector_id: u64,

    #[serde(default)]
    pub n_real_leaves: usize,

    #[serde(default)]
    pub n_padded_leaves: usize,

    #[serde(default)]
    pub post_status: String,

    #[serde(default)]
    pub last_proved: Option<i64>,

    #[serde(default)]
    pub manifest_cid: String,

    #[serde(default)]
    pub blocks_total: u32,

    #[serde(default)]
    pub blocks_received: u32,

    /// Unix timestamp of the last block received (or manifest arrival).
    /// Used to detect stalled transfers: if no progress for 10 min → "Failed".
    /// Reset to 0 on retry.
    #[serde(default)]
    pub last_block_at: i64,

    #[serde(default)]
    pub replica_peers: Vec<String>,

    /// Total fee paid by the uploader for this file (uEGOC).
    /// Split equally among storage providers (master + slaves) as they confirm.
    #[serde(default)]
    pub storage_fee_uegoc: u64,

    /// "master" = this node is responsible for re-replicating when a slave drops.
    /// "slave"  = this node holds a replica; watches master liveness.
    /// ""       = role not yet assigned (legacy / in-flight).
    #[serde(default)]
    pub replication_role: String,

    /// Address of the current master node (set on slave nodes).
    #[serde(default)]
    pub replica_master: String,

    /// Unix timestamp of last confirmed heartbeat from master (slave nodes only).
    #[serde(default)]
    pub master_last_seen: i64,

    /// Collateral locked by this node when it accepted a hosting deal (slave role).
    /// Returned when deal expires in good standing; burned on slash or early delete.
    #[serde(default)]
    pub collateral_locked_uegoc: u64,

    /// Unix timestamp when the file first dropped below MIN_REPLICAS.
    /// 0 = fully replicated (or not yet observed under-replicated).
    /// Used to enforce repair deadlines: warn after 1h, critical after 24h.
    #[serde(default)]
    pub under_replicated_since: i64,

    /// Consecutive PoSt challenges this file has failed.
    /// Resets to 0 on a successful proof.
    #[serde(default)]
    pub proof_strikes: u32,

    /// Unix timestamp until which storage rewards for this file are withheld.
    /// 0 = not suspended.  Set on strike ≥ 2.
    #[serde(default)]
    pub proof_suspended_until: i64,

    /// true = this file was received via EgoSafe share (egoshare1/egoshare2 bundle).
    /// false (default) = file the user explicitly uploaded through the Storage tab.
    /// Used to filter Storage tab so EgoSafe-received files don't appear there.
    #[serde(default)]
    pub from_egosafe: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Ledger {
    pub address: String,
    #[serde(default)]
    pub mainnet_address: String,
    pub balance_uegoc: u64,
    #[serde(default)]
    pub balance_uegusd: u64,
    pub nonce: u64,
    #[serde(default, skip_serializing)]
    pub transactions: Vec<LedgerTx>,
    #[serde(default, skip_serializing)]
    pub blocks: Vec<LedgerBlock>,
    pub stored_files: Vec<StoredFile>,
    #[serde(default)]
    pub storage_allocated_bytes: u64,
    #[serde(default)]
    pub security_pin_hash: String,
    #[serde(default)]
    pub security_pin_salt: String,
    #[serde(default)]
    pub staked_amount: u64,
    #[serde(default)]
    pub staked_at: Option<i64>,
    #[serde(default)]
    pub stake_lock_days: u32,
    #[serde(default)]
    pub unstake_at: Option<i64>,

    /// Drive letter chosen by the user for the storage folder, e.g. "C" or "D".
    /// Empty string = use default data_dir() (same drive as the rest of the app).
    #[serde(default)]
    pub storage_drive: String,

    #[serde(default)]
    pub registered_name: String,

    #[serde(default)]
    pub registered_email: String,

    #[serde(default)]
    pub total_burned_uegoc: u64,

    #[serde(default)]
    pub slash_strikes: u32,

    #[serde(default)]
    pub last_slash_ts: Option<i64>,

    #[serde(default)]
    pub slash_banned: bool,

    #[serde(default)]
    pub presale_records: Vec<PresaleIouRecord>,

    /// Random hex token included in contact bundles. Requests using an old
    /// token are auto-dropped. Rotate with `revoke_contact_bundle`.
    #[serde(default)]
    pub bundle_token: String,

    /// Unix timestamp (seconds) when storage allocation was last configured.
    /// Nodes are locked from changing their allocation for 60 days after this.
    #[serde(default)]
    pub storage_configured_at: Option<i64>,

    /// If set, all storage/consensus/coverage rewards are suspended until this timestamp.
    /// Applied when a node lowers its committed storage allocation after the 60-day lock expires.
    #[serde(default)]
    pub reward_suspended_until: Option<i64>,

    /// TX hash of the most recent stake submission that has NOT yet been confirmed on-chain.
    /// Used at startup to reconcile ledger.staked_amount against the actual chain state:
    /// if this hash has no confirmed block_height in chain_db, the local stake state is
    /// cleared so the node doesn't claim validator status for an unconfirmed stake.
    #[serde(default)]
    pub pending_stake_tx_hash: String,

    /// Unix timestamp when the user first deployed a hosted site.
    /// 0 = never deployed. Trial is valid for 7 days from this timestamp.
    #[serde(default)]
    pub hosting_trial_started_at: i64,

    #[serde(default)]
    pub compute_enabled: bool,

    #[serde(default)]
    pub compute_allocated_cores: u32,

    #[serde(default)]
    pub compute_allocated_ram_gb: u32,

    #[serde(default)]
    pub compute_earnings_uegoc: u64,

    #[serde(default)]
    pub compute_jobs_completed: u64,

    #[serde(default)]
    pub compute_price_per_gpu_hour_uegoc: u64,

    #[serde(default)]
    pub compute_price_per_core_hour_uegoc: u64,

    #[serde(default)]
    pub compute_locked_cores: u32,

    #[serde(default)]
    pub compute_locked_ram_gb: u32,

    #[serde(default)]
    pub compute_reservation_earnings_uegoc: u64,

    #[serde(default)]
    pub storage_deal_earnings_uegoc: u64,
}

/// One pre-sale IOU record — stored locally and included in Genesis Block on mainnet launch.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct PresaleIouRecord {
    pub id: String,
    pub mainnet_address: String,
    pub egoc_amount: f64,
    pub usd_value: f64,
    pub pay_symbol: String,
    pub pay_amount: f64,
    pub deposit_address: String,
    pub timestamp: i64,
    /// "pending_payment" → "confirmed" (updated by bridge relayer)
    pub status: String,
}

impl Ledger {
    pub fn load() -> Self {
        let _guard = ledger_io_mutex().lock().unwrap_or_else(|e| e.into_inner());
        let path = ledger_path();
        if !path.exists() {
            return Self::default();
        }
        for attempt in 0..10 {
            match fs::read_to_string(&path) {
                Ok(data) => {
                    if data.is_empty() {
                        if attempt < 9 {
                            std::thread::sleep(std::time::Duration::from_millis(50));
                            continue;
                        }
                        return Self::default();
                    }
                    match serde_json::from_str::<Self>(&data) {
                        Ok(ledger) => return ledger,
                        Err(e) => {
                            if attempt < 9 {
                                std::thread::sleep(std::time::Duration::from_millis(50));
                                continue;
                            }
                            eprintln!("[Ledger] WARN: load failed after retries ({}); refusing to overwrite with defaults", e);
                            return Self::default();
                        }
                    }
                }
                Err(e) => {
                    if attempt < 9 {
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        continue;
                    }
                    eprintln!("[Ledger] WARN: read failed after retries ({}); refusing to overwrite with defaults", e);
                    return Self::default();
                }
            }
        }
        Self::default()
    }

    pub fn save(&self) -> Result<(), String> {
        let _guard = ledger_io_mutex().lock().unwrap_or_else(|e| e.into_inner());
        if self.address.is_empty() && self.registered_email.is_empty()
            && self.transactions.is_empty() && self.blocks.is_empty()
        {
            if ledger_path().exists() {
                eprintln!("[Ledger] BLOCKED save of empty/default Ledger over existing file — race protection");
                return Ok(());
            }
        }
        let data = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        crate::utils::atomic_write(&ledger_path(), data.as_bytes()).map_err(|e| e.to_string())
    }

    pub fn mine_block(&mut self, tx_hash: &str, miner: &str) {
        let prev_hash = self
            .blocks
            .last()
            .map(|b| b.hash.clone())
            .unwrap_or_else(|| GENESIS_HASH.into());

        let height = self.blocks.len() as u64;
        let timestamp = self.blocks.last()
            .map(|b| b.timestamp + 1)
            .unwrap_or(GENESIS_TS);

        let block_data = format!("{prev_hash}{tx_hash}{height}{timestamp}");
        let hash = ego_core::hash_data(block_data.as_bytes()).to_hex();

        for tx in self.transactions.iter_mut() {
            if tx.hash == tx_hash && tx.status == "Pending" {
                tx.status = "Confirmed".to_string();
                tx.block_height = Some(height);

                self.total_burned_uegoc = self.total_burned_uegoc.saturating_add(tx.fee_uegoc);
            }
        }

        let tx_fee = self.transactions.iter()
            .find(|t| t.hash == tx_hash)
            .map(|t| t.fee_uegoc)
            .unwrap_or(0);
        let reward = crate::tokenomics::compute_block_reward(height, tx_fee, &prev_hash);
        self.blocks.push(LedgerBlock {
            height,
            hash,
            prev_hash,
            timestamp,
            miner: miner.to_string(),
            tx_count: 1,
            size_bytes: 512,
            reward,
            coinbase_tx: None,
            vote_count: 0,
            tx_merkle_root: String::new(),
            poc_ticket: String::new(),
            poc_slot: 0,
            state_root: String::new(),
            base_fee_uegoc: 1_000,
            agg_bls_sig: String::new(),
            bls_pubkeys: Vec::new(),
        });
    }

    pub fn format_balance(&self) -> String {
        let egoc = self.balance_uegoc as f64 / 1_000_000.0;
        format!("{:.2} EGOC", egoc)
    }
}

const FAUCET_ADDRESS: &str = "egot1faucet000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SharedChain {
    pub blocks: Vec<LedgerBlock>,
    pub transactions: Vec<LedgerTx>,
}

pub fn chain_path() -> PathBuf {
    base_data_dir().join("chain.json")
}

pub fn contracts_dir() -> PathBuf {
    let dir = base_data_dir().join("contracts");
    let _ = fs::create_dir_all(&dir);
    dir
}

pub const GENESIS_HASH: &str  = "ego00000000000000000000000000000000000000000000000000000000genesis2";
pub const GENESIS_MINER: &str = "egot1genesis0000000000000000000000000000000000";
pub const GENESIS_TS: i64     = 1_744_588_800;

pub fn genesis_block() -> LedgerBlock {
    LedgerBlock {
        height:     0,
        hash:       GENESIS_HASH.into(),
        prev_hash:  "0000000000000000000000000000000000000000000000000000000000000000".into(),
        timestamp:  GENESIS_TS,
        miner:      GENESIS_MINER.into(),
        tx_count:   0,
        size_bytes: 0,
        reward:     0,
        coinbase_tx: None,
        vote_count: 0,
        tx_merkle_root: String::new(),
        poc_ticket: String::new(),
        poc_slot: 0,
        state_root: String::new(),
        base_fee_uegoc: 1_000,
        agg_bls_sig: String::new(),
        bls_pubkeys: Vec::new(),
    }
}

pub fn load_chain() -> SharedChain {
    crate::chain_db::load_shared_chain()
}

/// Persist any blocks (and their transactions) that are in `chain` but not yet in chain_db.
/// Idempotent: blocks already in the DB are skipped.
pub fn save_chain(chain: &SharedChain) -> Result<(), String> {
    for block in &chain.blocks {
        if block.height == 0 { continue; } // genesis is seeded by chain_db init
        if crate::chain_db::get_block_by_height(block.height).is_some() { continue; }
        let block_txs: Vec<LedgerTx> = chain
            .transactions
            .iter()
            .filter(|tx| tx.block_height == Some(block.height))
            .cloned()
            .collect();
        crate::chain_db::append_peer_block(block, &block_txs);
    }
    Ok(())
}

impl SharedChain {

    pub fn balance_of(&self, address: &str) -> u64 {
        crate::chain_db::balance_of(address)
    }

    pub fn mine_block(&mut self, tx_hash: &str, miner: &str) {
        let prev_hash = self
            .blocks
            .last()
            .map(|b| b.hash.clone())
            .unwrap_or_else(|| GENESIS_HASH.into());

        let height = self.blocks.len() as u64;
        let timestamp = self.blocks.last()
            .map(|b| b.timestamp + 1)
            .unwrap_or(GENESIS_TS);

        let block_data = format!("{prev_hash}{tx_hash}{height}{timestamp}");
        let hash = ego_core::hash_data(block_data.as_bytes()).to_hex();

        for tx in self.transactions.iter_mut() {
            if tx.hash == tx_hash && tx.status != "Confirmed" {
                tx.status = "Confirmed".to_string();
                tx.block_height = Some(height);
            }
        }

        self.blocks.push(LedgerBlock {
            height,
            hash,
            prev_hash,
            timestamp,
            miner: miner.to_string(),
            tx_count: 1,
            size_bytes: 512,
            reward: 0,
            coinbase_tx: None,
            vote_count: 0,
            tx_merkle_root: String::new(),
            poc_ticket: String::new(),
            poc_slot: 0,
            state_root: String::new(),
            base_fee_uegoc: 1_000,
            agg_bls_sig: String::new(),
            bls_pubkeys: Vec::new(),
        });
    }

    pub fn mine_batch(&mut self, txs: &[LedgerTx], miner: &str) -> LedgerBlock {
        let prev_hash  = self.blocks.last()
            .map(|b| b.hash.clone())
            .unwrap_or_else(|| GENESIS_HASH.into());
        let height    = self.blocks.len() as u64;
        let timestamp = self.blocks.last()
            .map(|b| b.timestamp + 1)
            .unwrap_or(GENESIS_TS);

        let tx_root: String = txs.iter().map(|t| t.hash.as_str()).collect::<Vec<_>>().join(":");
        let block_data = format!("{prev_hash}:{tx_root}:{height}:{timestamp}");
        let hash = ego_core::hash_data(block_data.as_bytes()).to_hex();

        let era          = height / crate::tokenomics::HALVING_INTERVAL;
        let tx_fees_sum: u64 = txs.iter().map(|t| t.fee_uegoc).sum();
        let block_reward = crate::tokenomics::compute_block_reward(height, tx_fees_sum, &prev_hash);
        let cb_nonce     = self.last_nonce(miner) + 1;
        let cb_data      = format!("coinbase:{miner}:{height}:{block_reward}:{timestamp}");
        let cb_hash      = ego_core::hash_data(cb_data.as_bytes()).to_hex();
        self.transactions.push(LedgerTx {
            hash:               cb_hash.clone(),
            from:               FAUCET_ADDRESS.into(),
            to:                 miner.into(),
            amount:             block_reward,
            memo:               Some(format!("batch reward height={height} txs={} era={era}", txs.len())),
            timestamp,
            status:             "Confirmed".to_string(),
            nonce:              cb_nonce,
            block_height:       Some(height),
            ..LedgerTx::default()
        });

        let tx_count = txs.len() as u32;
        for tx in txs {

            if let Some(existing) = self.transactions.iter_mut().find(|t| t.hash == tx.hash) {
                existing.status       = "Confirmed".to_string();
                existing.block_height = Some(height);
            } else {
                let mut confirmed     = tx.clone();
                confirmed.status      = "Confirmed".to_string();
                confirmed.block_height = Some(height);
                self.transactions.push(confirmed);
            }
        }

        let block = LedgerBlock {
            height,
            hash,
            prev_hash,
            timestamp,
            miner:      miner.to_string(),
            tx_count:   tx_count + 1,
            size_bytes: txs.iter().map(|t| t.hash.len() as u64 + 512).sum(),
            reward:     block_reward,
            coinbase_tx: Some(cb_hash),
            vote_count: 0,
            tx_merkle_root: String::new(),
            poc_ticket: String::new(),
            poc_slot: 0,
            state_root: String::new(),
            base_fee_uegoc: 1_000,
            agg_bls_sig: String::new(),
            bls_pubkeys: Vec::new(),
        };
        self.blocks.push(block.clone());
        block
    }

    pub fn last_nonce(&self, address: &str) -> u64 {
        self.transactions.iter()
            .filter(|t| t.from == address)
            .map(|t| t.nonce)
            .max()
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PocEvent {
    pub id: u64,
    pub timestamp: i64,
    pub quality: String,
    pub peers: u32,
    pub reward_uegoc: u64,
    pub h3_cell: Option<String>,
}

pub fn poc_events_path() -> PathBuf {
    data_dir().join("poc_events.json")
}

pub fn load_poc_events() -> Vec<PocEvent> {
    let path = poc_events_path();
    if let Ok(data) = fs::read_to_string(&path) {
        if let Ok(events) = serde_json::from_str::<Vec<PocEvent>>(&data) {
            return events;
        }
    }
    Vec::new()
}

pub fn save_poc_events(events: &[PocEvent]) -> Result<(), String> {
    let data = serde_json::to_string_pretty(events).map_err(|e| e.to_string())?;
    crate::utils::atomic_write(&poc_events_path(), data.as_bytes()).map_err(|e| e.to_string())
}

pub fn poc_signing_bytes(address: &str, quality: &str, peers: u32, h3_cell: &str, timestamp: i64) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"ego/poc/v1:");
    v.extend_from_slice(address.as_bytes());
    v.extend_from_slice(b":");
    v.extend_from_slice(quality.as_bytes());
    v.extend_from_slice(b":");
    v.extend_from_slice(&peers.to_le_bytes());
    v.extend_from_slice(b":");
    v.extend_from_slice(h3_cell.as_bytes());
    v.extend_from_slice(b":");
    v.extend_from_slice(&timestamp.to_le_bytes());
    v
}

use std::sync::Mutex;
use once_cell::sync::OnceCell;
use std::collections::HashMap;

static NONCE_STORE: OnceCell<Mutex<HashMap<String, u64>>> = OnceCell::new();

fn nonce_store() -> std::sync::MutexGuard<'static, HashMap<String, u64>> {
    NONCE_STORE.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap()
}

/// Record a confirmed nonce for a sender.  Called after a TX is written to chain.
pub fn record_confirmed_nonce(address: &str, nonce: u64) {
    let mut store = nonce_store();
    let entry = store.entry(address.to_string()).or_insert(0);
    if nonce > *entry { *entry = nonce; }
}

/// Returns the highest confirmed nonce for an address (0 = never sent).
pub fn last_confirmed_nonce(address: &str) -> u64 {
    *nonce_store().get(address).unwrap_or(&0)
}

/// Unconditionally set the confirmed nonce for an address to `nonce`.
/// Unlike `record_confirmed_nonce`, this can lower the value — used by reorg rollback.
pub fn set_confirmed_nonce(address: &str, nonce: u64) {
    nonce_store().insert(address.to_string(), nonce);
}

// ── Validator stake tracker ────────────────────────────────────────────────────
// Populated from confirmed stake/unstake TXs in write_block_batch.
// Used by p2p to gate validator registration (minimum stake required).

static STAKE_STORE: OnceCell<Mutex<HashMap<String, u64>>> = OnceCell::new();

fn stake_store() -> std::sync::MutexGuard<'static, HashMap<String, u64>> {
    STAKE_STORE.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap()
}

pub fn record_validator_stake(addr: &str, amount: u64, is_stake: bool) {
    if addr.is_empty() { return; }
    let mut store = stake_store();
    let cur = store.entry(addr.to_string()).or_insert(0);
    if is_stake { *cur = cur.saturating_add(amount); }
    else        { *cur = cur.saturating_sub(amount); }
}

pub fn get_validator_stake(addr: &str) -> u64 {
    *stake_store().get(addr).unwrap_or(&0)
}

/// Sum of all active stake across all known validators.
pub fn total_network_stake() -> u64 {
    let total: u64 = stake_store().values().sum();
    // Minimum 1 EGOC to prevent divide-by-zero during testnet bootstrap
    if total == 0 { 1_000_000 } else { total }
}

/// Number of addresses with non-zero stake (each is a potential validator).
pub fn active_validator_count() -> usize {
    let count = stake_store().values().filter(|&&s| s > 0).count();
    let known = crate::p2p::get_known_validators_snapshot().len();
    let effective = known.max(count);
    if effective < 2 { 2 } else { effective }
}

/// Reduce a validator's coverage score by a fixed penalty for missing their
/// proposal slot (Item 16: offline proposer deterrent).
/// The deduction is small (50 points) — proportional, not slashing.
/// It reduces their DRS weight so they win fewer future proposal lotteries.
pub fn penalise_missed_proposal(addr: &str) {
    const MISSED_PROPOSAL_PENALTY: u64 = 50;
    let current = crate::poc::get_peer_score(addr);
    let new_score = current.saturating_sub(MISSED_PROPOSAL_PENALTY);
    crate::poc::record_peer_score(addr, new_score.max(1));
    eprintln!(
        "[Ledger] Missed-proposal penalty: {} coverage score {} → {}",
        &addr[..addr.len().min(16)], current, new_score.max(1)
    );
}

/// Reconcile the local ledger's staked_amount against the confirmed chain state.
///
/// The stake_coins command updates ledger.staked_amount optimistically (before the TX
/// is confirmed) for a responsive UI.  If the node restarts before the TX is mined —
/// or if the TX was rejected — staked_amount stays set but no actual stake exists on-chain.
///
/// This function is called once at startup.  It checks `pending_stake_tx_hash`:
/// - If empty: nothing to reconcile (either no stake, or it was already confirmed).
/// - If set and the TX is found confirmed in chain_db: promote to confirmed (clear hash).
/// - If set but not found in chain_db within a generous grace window: revert the stake.
pub fn reconcile_stake_state() {
    let mut ledger = Ledger::load();

    if ledger.staked_amount > 0
        && ledger.pending_stake_tx_hash.is_empty()
        && ledger.staked_at.is_none()
    {
        eprintln!("[Staking] Clearing phantom stake ({} uEGOC) — no TX hash and no staked_at timestamp",
            ledger.staked_amount);
        ledger.staked_amount   = 0;
        ledger.stake_lock_days = 0;
        ledger.unstake_at      = None;
        let _ = ledger.save();
        return;
    }

    if ledger.pending_stake_tx_hash.is_empty() {
        return;
    }
    // Check whether the TX has been confirmed in chain_db.
    let tx_opt = crate::chain_db::get_tx_by_hash(&ledger.pending_stake_tx_hash);
    let is_confirmed = tx_opt
        .as_ref()
        .and_then(|tx| tx.block_height)
        .is_some();

    if is_confirmed {
        // Stake TX mined: clear the pending marker, keep staked_amount.
        ledger.pending_stake_tx_hash = String::new();
        let _ = ledger.save();
        eprintln!("[Staking] Stake TX confirmed on-chain — ledger state promoted.");
    } else {
        // TX not confirmed.  Give a grace window of 5 minutes (300s) from staked_at
        // before reverting; the TX may still be in flight from a very recent submission.
        let now = chrono::Utc::now().timestamp();
        let staked_at = ledger.staked_at.unwrap_or(0);
        let grace_secs: i64 = 300;
        if now - staked_at > grace_secs {
            eprintln!(
                "[Staking] Stake TX {} not found on-chain after {} seconds — reverting local state.",
                &ledger.pending_stake_tx_hash[..ledger.pending_stake_tx_hash.len().min(16)],
                now - staked_at,
            );
            ledger.staked_amount         = 0;
            ledger.staked_at             = None;
            ledger.stake_lock_days       = 0;
            ledger.unstake_at            = None;
            ledger.pending_stake_tx_hash = String::new();
            let _ = ledger.save();
        } else {
            eprintln!("[Staking] Stake TX pending — within grace window, keeping local state.");
        }
    }
}

pub fn verify_incoming_tx(tx: &LedgerTx) -> Result<(), String> {
    verify_incoming_tx_with_miner(tx, "")
}

pub fn is_protocol_system_tx(tx: &LedgerTx) -> bool {
    if tx.tx_type == "faucet" && tx.from == crate::chain_db::NODE_POOL_ADDR {
        return true;
    }
    tx.from == crate::chain_db::NODE_POOL_ADDR
        && tx.signature == "coinbase"
        && matches!(tx.tx_type.as_str(), "reward" | "coinbase" | "fee_distribution" | "post_reward")
}

pub fn is_reserved_system_source(addr: &str) -> bool {
    addr.is_empty()
        || addr == crate::chain_db::NODE_POOL_ADDR
        || addr == crate::chain_db::STAKING_POOL_ADDR
        || addr == crate::chain_db::FAUCET_ADDR_FULL
        || addr.starts_with("egot1faucet")
        || addr.starts_with("egot1genesis")
        || addr.starts_with("egot1staking")
        || addr.starts_with("egot1system")
        || addr.starts_with("egot1coverage")
        || addr.starts_with("egot1nodereward")
        || addr.starts_with("egot1collateral")
        || addr.starts_with("egot1slashpool")
        || addr.starts_with("egot1storagefees")
        || addr.starts_with("egot1burn")
        || addr.starts_with("egot1nodepool")
        || addr.starts_with("egot1rewards")
}

fn expected_standard_tx_hash(tx: &LedgerTx) -> String {
    let msg = if tx.tx_version >= 2 {
        tx_signing_bytes_v2(
            &tx.from,
            &tx.to,
            tx.amount,
            tx.nonce,
            tx.timestamp,
            tx.chain_id,
            tx.memo.as_deref().unwrap_or(""),
        )
    } else {
        tx_signing_bytes(&tx.from, &tx.to, tx.amount, tx.nonce, tx.timestamp)
    };
    format!("0x{}", ego_core::hash_data(&msg).to_hex())
}

fn tx_hash_must_match_standard_signing(tx: &LedgerTx) -> bool {
    matches!(
        tx.tx_type.as_str(),
        "transfer" | "stake" | "unstake" | "governance" | "cluster_escrow" | "storage_escrow" | "hosting_plan"
    )
}

pub fn verify_confirmed_tx_sig(tx: &LedgerTx) -> Result<(), String> {
    if is_protocol_system_tx(tx) {
        return Ok(());
    }
    if tx.public_key_ed25519.is_empty() || tx.signature.is_empty() {
        return Err(format!("confirmed tx {} missing Ed25519 pubkey/signature", tx.hash));
    }
    let pk_bytes = hex::decode(&tx.public_key_ed25519)
        .map_err(|_| "invalid pubkey hex".to_string())?;
    let sig_bytes = hex::decode(&tx.signature)
        .map_err(|_| "invalid signature hex".to_string())?;
    let pk_arr: [u8; 32] = pk_bytes.try_into()
        .map_err(|_| "pubkey must be 32 bytes".to_string())?;
    let sig_arr: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| "signature must be 64 bytes".to_string())?;
    use ed25519_dalek::{Signature as DalekSig, VerifyingKey, Verifier};
    let vk  = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| format!("invalid pubkey: {e}"))?;
    let sig = DalekSig::from_bytes(&sig_arr);
    let msg = if tx.tx_version >= 2 {
        tx_signing_bytes_v2(&tx.from, &tx.to, tx.amount, tx.nonce, tx.timestamp,
            tx.chain_id, tx.memo.as_deref().unwrap_or(""))
    } else {
        tx_signing_bytes(&tx.from, &tx.to, tx.amount, tx.nonce, tx.timestamp)
    };
    vk.verify(&msg, &sig).map_err(|_| "Ed25519 signature invalid".to_string())?;
    if tx_hash_must_match_standard_signing(tx) {
        let expected_hash = expected_standard_tx_hash(tx);
        if tx.hash != expected_hash {
            return Err(format!(
                "tx hash mismatch: claimed {} expected {}",
                tx.hash, expected_hash
            ));
        }
    }
    Ok(())
}

/// Full verification. When `block_miner` is non-empty, system-address transactions
/// are only accepted if they are crediting the miner (protocol rewards to self).
/// This closes the free-mint exploit where any node crafts `from=faucet → to=self`.
pub fn verify_incoming_tx_with_miner(tx: &LedgerTx, block_miner: &str) -> Result<(), String> {
    let _ = block_miner;

    let dilithium_disabled = crate::chain_db::is_feature_disabled(
        crate::chain_db::FEATURE_DILITHIUM_DISABLED,
    );
    let dilithium_required = crate::chain_db::is_feature_enabled(
        crate::chain_db::FEATURE_DILITHIUM_REQUIRED,
    );

    if is_reserved_system_source(&tx.from) {
        if tx.tx_type == "faucet" && tx.from == crate::chain_db::NODE_POOL_ADDR {
            return Ok(());
        }
        return Err(format!(
            "system-source tx {} from {} requires block-context protocol validation",
            tx.hash, tx.from
        ));
    }

    // ── Equivocation proof: fee/nonce/dilithium exempted, Ed25519 required ──
    // These txs are submitted by validator nodes to record slash evidence on-chain.
    // They must carry a valid Ed25519 sig from the detector (from = detector address),
    // but are exempt from fee payment and nonce sequencing so evidence is never blocked.
    if tx.tx_type == "equivocation_proof" {
        if tx.public_key_ed25519.is_empty() || tx.signature.is_empty() {
            return Err("equivocation_proof tx missing Ed25519 pubkey/sig".to_string());
        }
        let pk_bytes = hex::decode(&tx.public_key_ed25519)
            .map_err(|_| "equivocation_proof: invalid pubkey hex".to_string())?;
        let sig_bytes = hex::decode(&tx.signature)
            .map_err(|_| "equivocation_proof: invalid sig hex".to_string())?;
        let pk_arr: [u8; 32] = pk_bytes.try_into()
            .map_err(|_| "equivocation_proof: pubkey must be 32 bytes".to_string())?;
        let sig_arr: [u8; 64] = sig_bytes.try_into()
            .map_err(|_| "equivocation_proof: sig must be 64 bytes".to_string())?;
        use ed25519_dalek::{Signature as DalekSig, VerifyingKey, Verifier};
        let vk  = VerifyingKey::from_bytes(&pk_arr)
            .map_err(|e| format!("equivocation_proof: invalid pubkey: {e}"))?;
        let sig = DalekSig::from_bytes(&sig_arr);
        // The signed payload is the tx hash (blake3 of proof_payload computed by submitter).
        vk.verify(tx.hash.as_bytes(), &sig)
            .map_err(|_| "equivocation_proof: Ed25519 sig invalid".to_string())?;
        return Ok(());
    }

    // ── Privacy Compliance (AML Protection) ──────────────────────────────
    // Shielded transactions are allowed for standard users, but to prevent
    // illegal activities, large transfers (> 50k EGOC) must be transparent
    // unless they carry a cryptographic compliance proof.
    if tx.is_private && tx.amount > 50_000 * 1_000_000 {
        if tx.compliance_proof.is_empty() {
            return Err(format!(
                "Large private transfer rejected: {} uEGOC exceeds privacy threshold. \
                Please use a transparent transaction for amounts over 50,000 EGOC.",
                tx.amount
            ));
        }
    }

    // ── Fee floor ─────────────────────────────────────────────────────────
    // Reject zero-fee transactions from accounts that haven't staked.
    // Stakers (≥ MIN_STAKE_FREE_TX_UEGOC) get free transactions as a reward
    // for securing the network. Everyone else must pay the minimum fee.
    // This prevents mempool spam: flooding with free txs now costs real money.
    if tx.fee_uegoc < crate::tokenomics::FEE_FLOOR_UEGOC {
        return Err(format!(
            "tx from {} rejected: fee {} uEGOC below absolute floor {} uEGOC. Zero-fee transactions are disabled to prevent network spam.",
            tx.from, tx.fee_uegoc,
            crate::tokenomics::FEE_FLOOR_UEGOC,
        ));
    }

    let last = last_confirmed_nonce(&tx.from);
    if tx.nonce <= last {
        return Err(format!(
            "replay: nonce {} <= last confirmed {} for {}",
            tx.nonce, last, tx.from
        ));
    }

    // ── Balance check ─────────────────────────────────────────────────────────
    // Without this, write_block_batch's i128 delta clamps negative to 0, which
    // credits the recipient while the sender's balance bottoms out at 0 — net
    // supply inflation.  We reject here so the TX never enters a confirmed block.
    // Stake/unstake TXs are exempt: the staking contract handles those flows.
    let is_staking_tx = tx.tx_type == "stake" || tx.tx_type == "unstake";
    if !is_staking_tx {
        let confirmed_balance = crate::chain_db::balance_of(&tx.from);
        let required = tx.amount.saturating_add(tx.fee_uegoc);
        if confirmed_balance < required {
            return Err(format!(
                "insufficient balance: {} has {} uEGOC, needs {} ({} amount + {} fee)",
                tx.from, confirmed_balance, required, tx.amount, tx.fee_uegoc,
            ));
        }
    } else if tx.tx_type == "stake" {
        // FIX: Staking TXs must still prove they hold the required balance before entering the mempool!
        let confirmed_balance = crate::chain_db::balance_of(&tx.from);
        let required = tx.amount.saturating_add(tx.fee_uegoc);
        if confirmed_balance < required {
            return Err(format!("insufficient balance for staking: needs {}", required));
        }
    }

    if tx.public_key_ed25519.is_empty() || tx.signature.is_empty() {
        return Err(format!("missing signature or pubkey in TX from {}", tx.from));
    }

    let hrp = if tx.chain_id == 1 { "egot" } else { "ego" };
    
    if !dilithium_disabled && !tx.dilithium_pubkey.is_empty() {
        let dil_pk = hex::decode(&tx.dilithium_pubkey).unwrap_or_default();
        let expected_addr = ego_core::EgoAddress::from_dilithium_pk(&dil_pk, tx.chain_id as u32, ego_core::AddressType::EOA)
            .to_bech32(hrp).unwrap_or_default();
        if tx.from != expected_addr {
            return Err(format!("Spoofing detected: TX from {} does not match dilithium pubkey", tx.from));
        }
    } else {
        let ed_pk = hex::decode(&tx.public_key_ed25519).unwrap_or_default();
        if ed_pk.len() != 32 {
            return Err(format!("Spoofing detected: invalid Ed25519 pubkey length"));
        }
    }

    let pk_bytes = hex::decode(&tx.public_key_ed25519)
        .map_err(|_| "invalid pubkey hex".to_string())?;
    let sig_bytes = hex::decode(&tx.signature)
        .map_err(|_| "invalid signature hex".to_string())?;

    let pk_arr: [u8; 32] = pk_bytes.try_into()
        .map_err(|_| "pubkey must be 32 bytes".to_string())?;
    let sig_arr: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| "signature must be 64 bytes".to_string())?;

    use ed25519_dalek::{Signature as DalekSig, VerifyingKey, Verifier};
    let vk  = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| format!("invalid pubkey: {e}"))?;
    let sig = DalekSig::from_bytes(&sig_arr);

    let msg = if tx.tx_version >= 2 {
        tx_signing_bytes_v2(
            &tx.from, &tx.to, tx.amount, tx.nonce, tx.timestamp,
            tx.chain_id, tx.memo.as_deref().unwrap_or(""),
        )
    } else {
        tx_signing_bytes(&tx.from, &tx.to, tx.amount, tx.nonce, tx.timestamp)
    };
    vk.verify(&msg, &sig)
        .map_err(|_| format!("Ed25519 signature verification failed for TX from {}", tx.from))?;

    if tx_hash_must_match_standard_signing(tx) {
        let expected_hash = expected_standard_tx_hash(tx);
        if tx.hash != expected_hash {
            return Err(format!(
                "tx hash mismatch: claimed {} expected {}",
                tx.hash, expected_hash
            ));
        }
    }

    // ── ML-DSA-44 verification (governance-controlled) ────────────────────
    // Three states, set by on-chain validator governance votes:
    //
    //  1. Default (no vote): verify Dilithium if present, skip if absent.
    //     Allows old wallets (Ed25519-only) to coexist with new hybrid wallets.
    //
    //  2. FEATURE_DILITHIUM_REQUIRED enabled: ALL txs must carry Dilithium.
    //     Enforced once the network has fully migrated.
    //
    //  3. FEATURE_DILITHIUM_DISABLED enabled: skip Dilithium entirely.
    //     Emergency switch if a vulnerability is found in ML-DSA-44.
    //     Validators vote → passes threshold → activates at specified block height.

    if dilithium_required && (tx.dilithium_pubkey.is_empty() || tx.dilithium_signature.is_empty()) {
        return Err(format!(
            "TX from {} rejected: ML-DSA-44 signature required by network governance",
            tx.from
        ));
    }

    if !dilithium_disabled && !tx.dilithium_pubkey.is_empty() && !tx.dilithium_signature.is_empty() {
        let dil_pk  = hex::decode(&tx.dilithium_pubkey)
            .map_err(|_| "invalid dilithium pubkey hex".to_string())?;
        let dil_sig = hex::decode(&tx.dilithium_signature)
            .map_err(|_| "invalid dilithium signature hex".to_string())?;
        let pk  = ego_core::PublicKey::dilithium2(dil_pk);
        let sig = ego_core::Signature::dilithium2(dil_sig);
        let valid = ego_core::verify_signature(&pk, &msg, &sig)
            .map_err(|e| format!("ML-DSA-44 error for TX from {}: {}", tx.from, e))?;
        if !valid {
            return Err(format!("ML-DSA-44 signature invalid for TX from {}", tx.from));
        }
    }

    Ok(())
}

pub fn tx_signing_bytes(from: &str, to: &str, amount: u64, nonce: u64, timestamp: i64) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"ego/tx/v1:");
    v.extend_from_slice(from.as_bytes());
    v.extend_from_slice(b":");
    v.extend_from_slice(to.as_bytes());
    v.extend_from_slice(b":");
    v.extend_from_slice(&amount.to_le_bytes());
    v.extend_from_slice(b":");
    v.extend_from_slice(&nonce.to_le_bytes());
    v.extend_from_slice(b":");
    v.extend_from_slice(&timestamp.to_le_bytes());
    v
}

/// EGO-712 v2 signing bytes — commits chain_id and memo so they cannot be
/// misrepresented between the display layer and the signed payload.
///
/// Format: `ego/tx/v2:<chain_id_u8>:<from>:<to>:<amount_le8>:<nonce_le8>:<ts_le8>:<memo_len_le4><memo>`
pub fn tx_signing_bytes_v2(
    from: &str, to: &str, amount: u64, nonce: u64, timestamp: i64,
    chain_id: u8, memo: &str,
) -> Vec<u8> {
    let memo = &memo[..memo.len().min(256)]; // cap at 256 chars
    let mut v = Vec::new();
    v.extend_from_slice(b"ego/tx/v2:");
    v.push(chain_id);
    v.push(b':');
    v.extend_from_slice(from.as_bytes());
    v.push(b':');
    v.extend_from_slice(to.as_bytes());
    v.push(b':');
    v.extend_from_slice(&amount.to_le_bytes());
    v.push(b':');
    v.extend_from_slice(&nonce.to_le_bytes());
    v.push(b':');
    v.extend_from_slice(&timestamp.to_le_bytes());
    v.push(b':');
    v.extend_from_slice(&(memo.len() as u32).to_le_bytes());
    v.extend_from_slice(memo.as_bytes());
    v
}

/// Generate a human-readable summary from the exact fields committed in the
/// v2 signature.  Because this is derived from the same inputs as
/// `tx_signing_bytes_v2`, the UI cannot display a different summary than
/// what was actually signed.
pub fn tx_human_summary(
    from: &str, to: &str, amount_uegoc: u64, memo: &str,
    chain_id: u8, nonce: u64, fee_uegoc: u64,
) -> String {
    let network = if chain_id == 1 { "Testnet" } else { "Mainnet" };
    format!(
        "Transfer {:.6} EGOC\n  From:    {}\n  To:      {}\n  Memo:    {}\n  Fee:     {:.6} EGOC\n  Nonce:   {}\n  Network: {} (chain_id={})",
        amount_uegoc as f64 / 1_000_000.0,
        from, to,
        if memo.is_empty() { "(none)" } else { memo },
        fee_uegoc as f64 / 1_000_000.0,
        nonce,
        network, chain_id,
    )
}
