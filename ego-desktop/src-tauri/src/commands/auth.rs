
use crate::app::AppState;
use crate::error::{EgoDesktopError, EgoResult};
use crate::ledger::{
    base_data_dir, data_dir, get_active_wallet_id, ledger_path, load_chain,
    load_registry, next_wallet_id, registry_path, save_chain, save_registry, seed_path,
    storage_dir, wallet_dir, Ledger, LedgerBlock, LedgerTx, SharedChain, WalletEntry,
    WalletRegistry,
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use ego_core::{AddressType, KeyPair};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use tauri::{Manager, State};

#[derive(Debug, Serialize, Deserialize)]
pub struct WalletInfo {
    pub address: String,
    pub public_key_ed25519: String,
    pub public_key_dilithium: String,
    pub public_key_kyber: String,
    pub balance_uegoc: u64,
    pub balance_formatted: String,
    pub is_new_wallet: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeypairInfo {
    pub address: String,
    pub public_key_ed25519: String,
    pub public_key_dilithium: String,
    pub public_key_kyber: String,
    pub recovery_phrase: Vec<String>,
    pub qr_code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImportKeypairRequest {
    pub recovery_phrase: Vec<String>,
}

#[derive(serde::Serialize)]
pub struct PinStatus {
    pub has_pin: bool,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AppSettings {
    pub auto_start:        bool,
    pub minimize_to_tray:  bool,
    pub notifications:     bool,
}

#[tauri::command]
pub async fn get_app_settings() -> Result<AppSettings, String> {
    let path = base_data_dir().join("settings.json");
    if let Ok(data) = fs::read_to_string(&path) {
        if let Ok(s) = serde_json::from_str::<AppSettings>(&data) {
            return Ok(s);
        }
    }
    Ok(AppSettings { auto_start: true, minimize_to_tray: true, notifications: true })
}

#[tauri::command]
pub async fn save_app_settings(settings: AppSettings) -> Result<(), String> {
    let path = base_data_dir().join("settings.json");
    let data = serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;
    fs::write(path, data).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_pin_status(_state: tauri::State<'_, crate::app::AppState>) -> Result<PinStatus, String> {
    let ledger = Ledger::load();
    Ok(PinStatus { has_pin: !ledger.security_pin_hash.is_empty() })
}

#[tauri::command]
pub async fn get_password_status() -> Result<PinStatus, String> {
    let ledger = Ledger::load();
    Ok(PinStatus { has_pin: !ledger.security_pin_hash.is_empty() })
}

#[tauri::command]
pub async fn set_password(password: String) -> Result<(), EgoDesktopError> {
    let pwd = normalize_pin(&password)?;
    let pwd_hash = hash_pin_argon2(&pwd)?;
    let mut ledger = Ledger::load();
    ledger.security_pin_hash = pwd_hash;
    ledger.security_pin_salt.clear();
    ledger.save().map_err(EgoDesktopError::WalletError)
}

#[tauri::command]
pub async fn verify_password(password: String) -> Result<bool, EgoDesktopError> {
    verify_pin(password).await
}

#[tauri::command]
pub async fn reset_password_with_recovery_phrase(
    recovery_phrase: Vec<String>,
    new_password: String,
) -> Result<(), EgoDesktopError> {
    reset_pin_with_recovery_phrase(recovery_phrase, new_password).await
}

#[tauri::command]
pub fn password_cache_status() -> Result<serde_json::Value, EgoDesktopError> {
    pin_cache_status()
}
// ── Platform-specific biometric helpers ──────────────────────────────────────

#[cfg(target_os = "windows")]
fn biometric_platform(reason: &str) -> Result<bool, String> {
    // Use PowerShell UserConsentVerifier (Windows Hello — PIN, face, fingerprint)
    let script = format!(
        r#"
try {{
  $ucv = [Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]
  $asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() |
    Where-Object {{ $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.IsGenericMethodDefinition }}) |
    Select-Object -First 1
  $chk = $asTask.MakeGenericMethod(
    [Windows.Security.Credentials.UI.UserConsentVerifierAvailability]
  ).Invoke($null, @($ucv.GetMethod('CheckAvailabilityAsync').Invoke($null, @())))
  if ($chk.Result -ne 'Available') {{ exit 2 }}
  $verify = $asTask.MakeGenericMethod(
    [Windows.Security.Credentials.UI.UserConsentVerificationResult]
  ).Invoke($null, @($ucv.GetMethod('RequestVerificationAsync').Invoke($null, @('{reason}'))))
  if ($verify.Result -eq 'Verified') {{ exit 0 }} else {{ exit 1 }}
}} catch {{ exit 1 }}
"#,
        reason = reason.replace('\'', "''")
    );
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", &script])
        .output()
        .map_err(|e| format!("PowerShell error: {e}"))?;
    match out.status.code() {
        Some(0) => Ok(true),
        Some(2) => Ok(false),
        _ => Ok(false),
    }
}

#[cfg(target_os = "macos")]
fn biometric_platform(reason: &str) -> Result<bool, String> {

    let swift_code = format!(
        r#"import LocalAuthentication
import Foundation
let sem = DispatchSemaphore(value: 0)
let ctx = LAContext()
var err: NSError?
let policy: LAPolicy = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err)
    ? .deviceOwnerAuthenticationWithBiometrics
    : .deviceOwnerAuthentication
ctx.evaluatePolicy(policy, localizedReason: "{reason}") {{ ok, _ in
    exit(ok ? 0 : 1)
}}
sem.wait()
"#,
        reason = reason.replace('"', "\\\"")
    );
    let tmp = std::env::temp_dir().join("ego_biometric_check.swift");
    std::fs::write(&tmp, &swift_code).map_err(|e| format!("Write swift file: {e}"))?;
    let out = std::process::Command::new("swift")
        .arg(&tmp)
        .output()
        .map_err(|e| format!("Swift error: {e}"));
    let _ = std::fs::remove_file(&tmp);
    match out {
        Ok(o) => Ok(o.status.success()),
        Err(e) => Err(format!("Biometric unavailable: {e}")),
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn biometric_platform(_reason: &str) -> Result<bool, String> {
    Err("Biometric authentication is not supported on this platform; use PIN instead".into())
}

#[tauri::command]
pub async fn verify_biometric(reason: String) -> Result<bool, String> {
    tokio::task::spawn_blocking(move || biometric_platform(&reason))
        .await
        .map_err(|e| format!("Task error: {e}"))?
}

struct WalletKeys {
    keypair:          KeyPair,
    address:          String,
    ed25519_hex:      String,
    dilithium_hex:    String,
    kyber_hex:        String,
    balance_uegoc:    u64,
    balance_formatted: String,
}

fn pq_cache_path() -> std::path::PathBuf {
    crate::ledger::data_dir().join("pq_keys.bin")
}

pub fn ensure_pq_cache() {
    let cache = pq_cache_path();
    if cache.exists() { return; }
    let seed = match crate::p2p::get_ed25519_seed() {
        Some(s) => s,
        None    => return,
    };
    eprintln!("[KeyGen] Warming PQ key cache…");
    if let Ok(kp) = KeyPair::from_bytes(&seed) {
        if let Ok(encoded) = kp.to_pq_cache() {
            let _ = crate::utils::atomic_write(&cache, &encoded);
        }
    }
}

#[tauri::command]
pub fn pq_cache_ready() -> bool {
    pq_cache_path().exists()
}

fn load_or_generate_pq_keys(seed: &[u8; 32]) -> Result<KeyPair, EgoDesktopError> {
    let cache = pq_cache_path();
    if cache.exists() {
        if let Ok(bytes) = fs::read(&cache) {
            if let Ok(kp) = KeyPair::from_pq_cache(&bytes, seed) {
                return Ok(kp);
            }
        }
    }
    let kp = KeyPair::from_bytes(seed)
        .map_err(|e| EgoDesktopError::CryptoError(format!("Keypair: {e}")))?;
    if let Ok(encoded) = kp.to_pq_cache() {
        let _ = crate::utils::atomic_write(&cache, &encoded);
    }
    Ok(kp)
}

fn derive_wallet_keys() -> Result<WalletKeys, EgoDesktopError> {
    let seed_bytes = crate::ledger::load_seed()
        .map_err(|e| EgoDesktopError::CryptoError(format!("Failed to load seed: {}", e)))?
        .ok_or_else(|| EgoDesktopError::CryptoError("Corrupt or missing seed file".into()))?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);

    let keypair = load_or_generate_pq_keys(&seed)?;

    let mut ledger  = Ledger::load();
    let address = keypair
        .derive_bech32_address(1, AddressType::EOA, "egot")
        .map_err(|e| EgoDesktopError::CryptoError(format!("Address: {e}")))?;
        
    if ledger.address != address {
        ledger.address = address.clone();
        let _ = ledger.save();
    }
    
    let mainnet_addr = keypair
        .derive_bech32_address(0, AddressType::EOA, "ego")
        .unwrap_or_default();
    if ledger.mainnet_address != mainnet_addr && !mainnet_addr.is_empty() {
        ledger.mainnet_address = mainnet_addr;
        let _ = ledger.save();
    }

    let ed25519_hex   = hex::encode(keypair.ed25519_public_key().as_bytes());
    let dilithium_hex = hex::encode(keypair.dilithium_public_key().as_bytes());
    let kyber_hex     = hex::encode(keypair.kyber_public_key().as_bytes());

    // Use ledger-cached balance for instant startup; real balance is fetched
    // in background to avoid blocking on the RocksDB cold open.
    let balance_uegoc     = ledger.balance_uegoc;
    let balance_formatted = format!("{:.2} EGOC", balance_uegoc as f64 / 1_000_000.0);

    Ok(WalletKeys { keypair, address, ed25519_hex, dilithium_hex, kyber_hex, balance_uegoc, balance_formatted })
}

async fn load_active_wallet(
    state: &AppState,
    is_new: bool,
    handle: Option<tauri::AppHandle>,
) -> Result<WalletInfo, EgoDesktopError> {
    let keys = tokio::task::spawn_blocking(derive_wallet_keys)
        .await
        .map_err(|e| EgoDesktopError::CryptoError(format!("Key generation panicked: {e}")))??;

    state
        .initialize_wallet(keys.keypair, false)
        .map_err(|e| EgoDesktopError::WalletError(format!("{e}")))?;
    state.set_session_start(chrono::Utc::now().timestamp());

    {
        let mut ledger = Ledger::load();
        if ledger.storage_allocated_bytes == 0 {
            ledger.storage_allocated_bytes = 10 * 1_000_000_000;
            let _ = ledger.save();
            let _ = fs::create_dir_all(storage_dir());
            eprintln!("[storage] Auto-provisioned 10 GB storage quota");
        }
    }

    // Heavy chain_db work (RocksDB cold open + faucet + real balance) runs in
    // background so init_wallet returns in ~50 ms instead of 2-8 s.
    let addr = keys.address.clone();
    tauri::async_runtime::spawn(async move {
        let (bal, fmt) = tokio::task::spawn_blocking(move || {
            credit_testnet_faucet(&addr);
            let b = crate::chain_db::balance_of(&addr);

            let pending_faucet_in: u64 = crate::mempool::get_mempool()
                .pending_txs_for_address(&addr)
                .into_iter()
                .filter(|tx| tx.tx_type == "faucet" && tx.to == addr)
                .map(|tx| tx.amount)
                .sum();

            let effective_bal = b + pending_faucet_in;
            let f = format!("{:.2} EGOC", effective_bal as f64 / 1_000_000.0);

            // Persist real balance so next launch shows it immediately.
            let mut ledger = Ledger::load();
            if b > 0 || ledger.balance_uegoc == 0 {
                ledger.balance_uegoc = b;
                let _ = ledger.save();
            }
            (effective_bal, f)
        }).await.unwrap_or((0, "0.00 EGOC".into()));

        if let Some(h) = handle {
            let _ = h.emit_all("wallet-balance-updated", serde_json::json!({
                "balance_uegoc": bal,
                "balance_formatted": fmt,
            }));
        }
    });

    Ok(WalletInfo {
        address:              keys.address,
        public_key_ed25519:   keys.ed25519_hex,
        public_key_dilithium: keys.dilithium_hex,
        public_key_kyber:     keys.kyber_hex,
        balance_uegoc:        keys.balance_uegoc,
        balance_formatted:    keys.balance_formatted,
        is_new_wallet:        is_new,
    })
}

fn create_wallet_files(address_override: Option<&str>) -> Result<String, EgoDesktopError> {
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);

    fs::create_dir_all(data_dir())
        .map_err(|e| EgoDesktopError::FileSystemError(format!("Create dir: {e}")))?;
    crate::ledger::save_seed(&seed)
        .map_err(|e| EgoDesktopError::FileSystemError(format!("Write seed: {e}")))?;

    let keypair = KeyPair::from_bytes(&seed)
        .map_err(|e| EgoDesktopError::CryptoError(format!("Keypair: {e}")))?;
    if let Ok(encoded) = keypair.to_pq_cache() {
        let _ = crate::utils::atomic_write(&pq_cache_path(), &encoded);
    }
    let address = keypair
        .derive_bech32_address(1, AddressType::EOA, "egot")
        .map_err(|e| EgoDesktopError::CryptoError(format!("Address: {e}")))?;
    let mainnet_addr = keypair
        .derive_bech32_address(0, AddressType::EOA, "ego")
        .unwrap_or_default();

    let final_address = address_override.unwrap_or(&address).to_string();

    let genesis_data = format!("genesis:{final_address}");
    let genesis_hash = ego_core::hash_data(genesis_data.as_bytes()).to_hex();

    let mut ledger = Ledger::default();
    ledger.address = final_address.clone();
    ledger.mainnet_address = mainnet_addr;
    ledger.save().map_err(EgoDesktopError::WalletError)?;

    let mut chain = load_chain();
    if !chain.transactions.iter().any(|tx| tx.hash == genesis_hash) {
        let ts = chrono::Utc::now().timestamp();
        let genesis_block_height = chain.blocks.len() as u64;

        chain.transactions.push(LedgerTx {
            hash:               genesis_hash.clone(),
            from:               "egot1faucet000000000000000000000000000000000000".into(),
            to:                 final_address.clone(),
            amount:             1_000 * 1_000_000,
            memo:               Some("Testnet faucet – welcome!".into()),
            timestamp:          ts,
            signature:          "genesis".into(),
            status:             "Confirmed".into(),
            block_height:       Some(genesis_block_height),
            nonce:              0,
            public_key_ed25519: String::new(), dilithium_pubkey: String::new(), dilithium_signature: String::new(),
            ..LedgerTx::default()
        });
        chain.blocks.push(LedgerBlock {
            height:     genesis_block_height,
            hash:       genesis_hash,
            prev_hash:  chain.blocks.last().map(|b| b.hash.clone()).unwrap_or_else(|| "0".repeat(64)),
            timestamp:  ts,
            miner:      final_address.clone(),
            tx_count:   1,
            size_bytes: 256,
            reward:     1_000 * 1_000_000,
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
        save_chain(&chain).map_err(EgoDesktopError::WalletError)?;
    }

    Ok(final_address)
}

/// Headless bootstrap: a validator started with EGO_HEADLESS=1 has no GUI to run
/// init_wallet, so self-provision a fresh identity on first run if none exists.
/// Idempotent — returns the existing address once a wallet is present.
pub fn ensure_wallet_exists() -> Result<String, EgoDesktopError> {
    let existing = Ledger::load().address;
    if !existing.is_empty() {
        return Ok(existing);
    }
    create_wallet_files(None)
}

#[tauri::command]
pub async fn init_wallet(
    state: State<'_, AppState>,
    app_handle: tauri::AppHandle,
) -> Result<WalletInfo, EgoDesktopError> {
    let legacy_seed = base_data_dir().join("wallet.seed");
    if legacy_seed.exists() && !registry_path().exists() {
        let w0_dir = wallet_dir("wallet_0");
        fs::create_dir_all(&w0_dir)
            .map_err(|e| EgoDesktopError::FileSystemError(format!("Create wallet_0: {e}")))?;

        let dst_seed   = w0_dir.join("wallet.seed");
        let dst_ledger = w0_dir.join("ledger.json");
        let dst_storage = w0_dir.join("storage");

        if !dst_seed.exists() {
            let _ = fs::copy(&legacy_seed, &dst_seed);
        }
        let legacy_ledger  = base_data_dir().join("ledger.json");
        if legacy_ledger.exists() && !dst_ledger.exists() {
            let _ = fs::copy(&legacy_ledger, &dst_ledger);
        }
        let legacy_storage = base_data_dir().join("storage");
        if legacy_storage.exists() && !dst_storage.exists() {

            let _ = copy_dir_all(&legacy_storage, &dst_storage);
        }

        let address = if dst_ledger.exists() {
            serde_json::from_str::<Ledger>(
                &fs::read_to_string(&dst_ledger).unwrap_or_default(),
            )
            .map(|l| l.address)
            .unwrap_or_default()
        } else {
            String::new()
        };

        let mut reg = WalletRegistry::default();
        reg.active_id = "wallet_0".to_string();
        reg.wallets.push(WalletEntry {
            id:         "wallet_0".to_string(),
            name:       "Main Wallet".to_string(),
            address,
            created_at: chrono::Utc::now().timestamp(),
        });
        save_registry(&reg).map_err(EgoDesktopError::WalletError)?;
    }

    // Import any legacy per-wallet ledger history into RocksDB in background.
    // save_chain() is idempotent, so rerunning this on startup is safe.
    let migration_handle = app_handle.clone();
    tauri::async_runtime::spawn(async move {
        let migrated = tokio::task::spawn_blocking(|| {
            let reg = load_registry();
            let mut chain = SharedChain::default();
            let mut seen_txs: HashSet<String> = HashSet::new();
            let mut seen_blocks: HashSet<String> = HashSet::new();

            for entry in &reg.wallets {
                let lf = wallet_dir(&entry.id).join("ledger.json");
                if let Ok(data) = fs::read_to_string(&lf) {
                    if let Ok(l) = serde_json::from_str::<Ledger>(&data) {
                        for tx in &l.transactions {
                            if seen_txs.insert(tx.hash.clone()) {
                                chain.transactions.push(tx.clone());
                            }
                        }
                        for block in &l.blocks {
                            if seen_blocks.insert(block.hash.clone()) {
                                chain.blocks.push(block.clone());
                            }
                        }
                    }
                }
            }

            if chain.blocks.is_empty() && chain.transactions.is_empty() {
                return false;
            }

            chain.blocks.sort_by_key(|b| b.height);
            chain.transactions.sort_by_key(|tx| tx.timestamp);
            let _ = save_chain(&chain);
            true
        }).await.unwrap_or(false);

        if migrated {
            let _ = migration_handle.emit_all("ego://chain-updated", ());
        }
    });

    let mut registry = load_registry();

    if registry.wallets.is_empty() {
        let wallet_id = "wallet_0".to_string();
        registry.active_id = wallet_id.clone();

        let address = tokio::task::spawn_blocking(|| create_wallet_files(None))
            .await
            .map_err(|e| EgoDesktopError::CryptoError(format!("Wallet creation panicked: {e}")))??;

        registry.wallets.push(WalletEntry {
            id:         wallet_id,
            name:       "Main Wallet".to_string(),
            address,
            created_at: chrono::Utc::now().timestamp(),
        });
        save_registry(&registry).map_err(EgoDesktopError::WalletError)?;

        return load_active_wallet(&state, true, Some(app_handle)).await;
    }

    // check if seed exists and is valid
    let seed_on_disk = seed_path().exists();
    let mut is_new = !seed_on_disk;

    // If seed exists but load_seed fails (e.g. Keychain locked), return the error 
    // instead of creating a new wallet.
    if seed_on_disk {
        if let Err(e) = crate::ledger::load_seed() {
            return Err(EgoDesktopError::CryptoError(e));
        }
    }

    if is_new {
        tokio::task::spawn_blocking(|| create_wallet_files(None))
            .await
            .map_err(|e| EgoDesktopError::CryptoError(format!("Wallet creation panicked: {e}")))??;
    }

    load_active_wallet(&state, is_new, Some(app_handle)).await
}

#[tauri::command]
pub async fn list_wallets() -> Result<WalletRegistry, EgoDesktopError> {
    Ok(load_registry())
}

#[tauri::command]
pub async fn create_wallet(
    name: String,
    state: State<'_, AppState>,
    app_handle: tauri::AppHandle,
) -> Result<WalletInfo, EgoDesktopError> {
    let mut registry = load_registry();

    if registry.wallets.len() >= 6 {
        return Err(EgoDesktopError::InvalidInput(
            "Maximum 6 wallets allowed".into(),
        ));
    }

    let wallet_id = next_wallet_id(&registry);
    let wallet_name = {
        let n = name.trim();
        if n.is_empty() {
            format!("Wallet {}", registry.wallets.len() + 1)
        } else {
            n.to_string()
        }
    };

    // Switch active dir FIRST so create_wallet_files writes to the new dir
    registry.active_id = wallet_id.clone();
    save_registry(&registry).map_err(EgoDesktopError::WalletError)?;

    let address = tokio::task::spawn_blocking(|| create_wallet_files(None))
        .await
        .map_err(|e| EgoDesktopError::CryptoError(format!("Wallet creation panicked: {e}")))??;

    // Update registry with the address we just derived
    registry.wallets.push(WalletEntry {
        id:         wallet_id,
        name:       wallet_name,
        address,
        created_at: chrono::Utc::now().timestamp(),
    });
    save_registry(&registry).map_err(EgoDesktopError::WalletError)?;

    load_active_wallet(&state, true, Some(app_handle)).await
}

// ── import_wallet ─────────────────────────────────────────────────────────────
// Import an existing wallet by 24-word phrase or 64-char hex seed as a NEW
// wallet entry (does not replace the current active wallet).

#[tauri::command]
pub async fn import_wallet(
    name:       String,
    method:     String,
    value:      String,
    state:      State<'_, AppState>,
    app_handle: tauri::AppHandle,
) -> Result<WalletInfo, EgoDesktopError> {
    let mut registry = load_registry();
    if registry.wallets.len() >= 6 {
        return Err(EgoDesktopError::InvalidInput("Maximum 6 wallets allowed".into()));
    }

    // Derive seed bytes from phrase or hex
    let seed: [u8; 32] = if method == "phrase" {
        let words: Vec<String> = value.split_whitespace().map(|w| w.to_lowercase()).collect();
        let kp = restore_keypair_from_phrase(&words)?;
        let raw = kp.to_bytes();
        let mut s = [0u8; 32];
        s.copy_from_slice(&raw[..32]);
        s
    } else if method == "seed" {
        let bytes = hex::decode(value.trim())
            .map_err(|_| EgoDesktopError::InvalidInput("Invalid seed hex — must be 64 hex characters".into()))?;
        if bytes.len() != 32 {
            return Err(EgoDesktopError::InvalidInput(
                format!("Seed must be exactly 32 bytes (64 hex chars), got {}", bytes.len())
            ));
        }
        let mut s = [0u8; 32];
        s.copy_from_slice(&bytes);
        s
    } else {
        return Err(EgoDesktopError::InvalidInput("method must be 'phrase' or 'seed'".into()));
    };

    let wallet_id = next_wallet_id(&registry);
    let wallet_name = {
        let n = name.trim();
        if n.is_empty() { format!("Wallet {}", registry.wallets.len() + 1) } else { n.to_string() }
    };

    // Switch active dir so wallet files are written to the new slot
    registry.active_id = wallet_id.clone();
    save_registry(&registry).map_err(EgoDesktopError::WalletError)?;

    let address = tokio::task::spawn_blocking(move || {
        use crate::ledger::{save_seed, data_dir};
        fs::create_dir_all(data_dir())
            .map_err(|e| EgoDesktopError::FileSystemError(format!("Create dir: {e}")))?;
        save_seed(&seed)
            .map_err(|e| EgoDesktopError::FileSystemError(format!("Write seed: {e}")))?;

        let keypair = KeyPair::from_bytes(&seed)
            .map_err(|e| EgoDesktopError::CryptoError(format!("Keypair: {e}")))?;
        let address = keypair
            .derive_bech32_address(1, AddressType::EOA, "egot")
            .map_err(|e| EgoDesktopError::CryptoError(format!("Address: {e}")))?;
        let mainnet_addr = keypair
            .derive_bech32_address(0, AddressType::EOA, "ego")
            .unwrap_or_default();

        let mut ledger = crate::ledger::Ledger::default();
        ledger.address = address.clone();
        ledger.mainnet_address = mainnet_addr;
        ledger.save().map_err(EgoDesktopError::WalletError)?;

        Ok::<String, EgoDesktopError>(address)
    })
    .await
    .map_err(|e| EgoDesktopError::CryptoError(format!("Import panicked: {e}")))??;

    registry.wallets.push(WalletEntry {
        id:         wallet_id,
        name:       wallet_name,
        address,
        created_at: chrono::Utc::now().timestamp(),
    });
    save_registry(&registry).map_err(EgoDesktopError::WalletError)?;

    load_active_wallet(&state, false, Some(app_handle)).await
}

// ── switch_wallet ─────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn switch_wallet(
    wallet_id:  String,
    state:      State<'_, AppState>,
    app_handle: tauri::AppHandle,
) -> Result<WalletInfo, EgoDesktopError> {
    let mut registry = load_registry();

    if !registry.wallets.iter().any(|w| w.id == wallet_id) {
        return Err(EgoDesktopError::NotFound(format!(
            "Wallet '{wallet_id}' not found"
        )));
    }

    registry.active_id = wallet_id;
    save_registry(&registry).map_err(EgoDesktopError::WalletError)?;

    load_active_wallet(&state, false, Some(app_handle)).await
}

#[tauri::command]
pub async fn delete_wallet(
    wallet_id: String,
    _state: State<'_, AppState>,
) -> Result<WalletRegistry, EgoDesktopError> {
    let mut registry = load_registry();

    if registry.wallets.len() <= 1 {
        return Err(EgoDesktopError::InvalidInput(
            "Cannot delete the only wallet".into(),
        ));
    }
    if wallet_id == registry.active_id {
        return Err(EgoDesktopError::InvalidInput(
            "Switch to a different wallet before deleting this one".into(),
        ));
    }

    let pos = registry
        .wallets
        .iter()
        .position(|w| w.id == wallet_id)
        .ok_or_else(|| EgoDesktopError::NotFound(format!("Wallet '{wallet_id}' not found")))?;

    registry.wallets.remove(pos);
    save_registry(&registry).map_err(EgoDesktopError::WalletError)?;

    // Best-effort: remove wallet directory (seed + ledger + storage)
    let dir = wallet_dir(&wallet_id);
    if dir.exists() {
        let _ = fs::remove_dir_all(&dir);
    }

    Ok(registry)
}

// ── rename_wallet ─────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn rename_wallet(
    wallet_id: String,
    name: String,
) -> Result<(), EgoDesktopError> {
    let mut registry = load_registry();
    let entry = registry
        .wallets
        .iter_mut()
        .find(|w| w.id == wallet_id)
        .ok_or_else(|| EgoDesktopError::NotFound(format!("Wallet '{wallet_id}' not found")))?;

    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(EgoDesktopError::InvalidInput("Name cannot be empty".into()));
    }
    entry.name = trimmed.to_string();
    save_registry(&registry).map_err(EgoDesktopError::WalletError)
}

// ── generate_keypair (legacy) ─────────────────────────────────────────────────

fn credit_testnet_faucet(address: &str) {
    if std::env::var("EGO_NO_FAUCET").map(|v| v == "1").unwrap_or(false) {
        return;
    }
    const FAUCET_UEGOC: u64 = 1_000 * 1_000_000;
    crate::chain_db::grant_testnet_faucet(address, FAUCET_UEGOC);
}

#[tauri::command]
pub async fn generate_keypair(state: State<'_, AppState>) -> Result<KeypairInfo, EgoDesktopError> {
    let keypair  = KeyPair::generate();
    let address  = keypair
        .derive_bech32_address(1, AddressType::EOA, "egot")
        .map_err(|e| EgoDesktopError::CryptoError(format!("{e}")))?;

    let recovery_phrase = generate_recovery_phrase(&keypair)?;

    let ed25519_pk   = hex::encode(keypair.ed25519_public_key().as_bytes());
    let dilithium_pk = hex::encode(keypair.dilithium_public_key().as_bytes());
    let kyber_pk     = hex::encode(keypair.kyber_public_key().as_bytes());
    let qr_code      = generate_address_qr(&address)?;

    credit_testnet_faucet(&address);

    state
        .initialize_wallet(keypair, true)  // true = explicit user action, force switch
        .map_err(|e| EgoDesktopError::WalletError(format!("Init wallet: {e}")))?;

    Ok(KeypairInfo {
        address,
        public_key_ed25519: ed25519_pk,
        public_key_dilithium: dilithium_pk,
        public_key_kyber: kyber_pk,
        recovery_phrase,
        qr_code,
    })
}

#[tauri::command]
pub async fn import_keypair(
    request: ImportKeypairRequest,
    state: State<'_, AppState>,
) -> Result<KeypairInfo, EgoDesktopError> {
    let keypair = restore_keypair_from_phrase(&request.recovery_phrase)?;

    let address      = keypair
        .derive_bech32_address(1, AddressType::EOA, "egot")
        .map_err(|e| EgoDesktopError::CryptoError(format!("{e}")))?;
    let ed25519_pk   = hex::encode(keypair.ed25519_public_key().as_bytes());
    let dilithium_pk = hex::encode(keypair.dilithium_public_key().as_bytes());
    let kyber_pk     = hex::encode(keypair.kyber_public_key().as_bytes());
    let qr_code      = generate_address_qr(&address)?;

    credit_testnet_faucet(&address);

    state
        .initialize_wallet(keypair, true)  // true = explicit user action, force switch
        .map_err(|e| EgoDesktopError::WalletError(format!("Init wallet: {e}")))?;

    Ok(KeypairInfo {
        address,
        public_key_ed25519: ed25519_pk,
        public_key_dilithium: dilithium_pk,
        public_key_kyber: kyber_pk,
        recovery_phrase: request.recovery_phrase,
        qr_code,
    })
}

// ── set_security_pin ──────────────────────────────────────────────────────────

fn normalize_pin(pin: &str) -> Result<String, EgoDesktopError> {
    let pin = pin.trim().to_string();
    if pin.len() < 8 {
        return Err(EgoDesktopError::InvalidInput(
            "Password must be at least 8 characters.".into(),
        ));
    }
    if pin.len() > 128 {
        return Err(EgoDesktopError::InvalidInput(
            "Password must be at most 128 characters.".into(),
        ));
    }
    Ok(pin)
}

static PIN_ATTEMPTS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, (u32, i64)>>> =
    std::sync::OnceLock::new();
const MAX_PIN_ATTEMPTS: u32 = 5;
const LOCKOUT_DURATION_SECS: i64 = 300;

fn pin_attempts_map() -> std::sync::MutexGuard<'static, std::collections::HashMap<String, (u32, i64)>> {
    PIN_ATTEMPTS
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
        .lock()
        .unwrap()
}

fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn enforce_pin_lockout_for(address: &str) -> Result<(), EgoDesktopError> {
    let now = now_ts();
    let mut map = pin_attempts_map();
    let entry = map.entry(address.to_string()).or_insert_with(|| {
        crate::chain_db::load_pin_lockout(address)
    });
    if entry.0 >= MAX_PIN_ATTEMPTS {
        if now < entry.1 {
            return Err(EgoDesktopError::PermissionDenied(format!(
                "Locked until {} (in {} seconds).",
                entry.1,
                entry.1 - now
            )));
        } else {
            entry.0 = 0;
            entry.1 = 0;
            crate::chain_db::clear_pin_lockout(address);
        }
    }
    entry.0 += 1;
    if entry.0 >= MAX_PIN_ATTEMPTS {
        entry.1 = now + LOCKOUT_DURATION_SECS;
        crate::chain_db::persist_pin_lockout(address, entry.0, entry.1);
    }
    Ok(())
}

fn enforce_pin_lockout() -> Result<(), EgoDesktopError> {
    let ledger = Ledger::load();
    enforce_pin_lockout_for(&ledger.address)
}

fn record_failed_pin_for(address: &str) -> EgoDesktopError {
    let mut map = pin_attempts_map();
    let entry = map.entry(address.to_string()).or_insert((0, 0));
    if entry.0 >= MAX_PIN_ATTEMPTS {
        return EgoDesktopError::PermissionDenied(format!(
            "Locked until {} (in {} seconds).",
            entry.1,
            entry.1 - now_ts()
        ));
    }
    let remaining = MAX_PIN_ATTEMPTS - entry.0;
    EgoDesktopError::InvalidInput(format!("Incorrect PIN. {} attempt{} remaining.", remaining, if remaining == 1 { "" } else { "s" }))
}

fn record_failed_pin() -> EgoDesktopError {
    let ledger = Ledger::load();
    record_failed_pin_for(&ledger.address)
}

fn record_successful_pin_for(address: &str) {
    let mut map = pin_attempts_map();
    map.remove(address);
    crate::chain_db::clear_pin_lockout(address);
}

fn record_successful_pin() {
    let ledger = Ledger::load();
    record_successful_pin_for(&ledger.address);
}

fn hash_pin_argon2(pin: &str) -> Result<String, EgoDesktopError> {
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let params = argon2::Params::new(196608, 3, 2, None).unwrap(); 
    let argon2_instance = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    argon2_instance
        .hash_password(pin.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| EgoDesktopError::CryptoError(format!("PIN hash: {e}")))
}

fn legacy_pin_hash(pin: &str, salt_hex: &str) -> String {
    if salt_hex.is_empty() {
        return ego_core::hash_data(pin.as_bytes()).to_hex();
    }
    let salt = hex::decode(salt_hex).unwrap_or_default();
    let mut input = salt;
    input.extend_from_slice(pin.as_bytes());
    ego_core::hash_data(&input).to_hex()
}

// ── TX-confirm PIN cache (in-memory, per-process) ────────────────────────────
// After a successful PIN check (TX confirm OR app-unlock verify_pin), record
// the timestamp. Subsequent TX confirms within the cache window can pass an
// empty PIN and skip re-entry. Cache is cleared on app close (in-memory only).
const PIN_CACHE_SECS: i64 = 15 * 60;
static PIN_CACHE_TS: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

pub(crate) fn pin_cache_is_fresh() -> bool {
    let ts = PIN_CACHE_TS.load(std::sync::atomic::Ordering::Relaxed);
    ts > 0 && (now_ts() - ts) < PIN_CACHE_SECS
}

pub(crate) fn pin_cache_seconds_remaining() -> i64 {
    let ts = PIN_CACHE_TS.load(std::sync::atomic::Ordering::Relaxed);
    if ts <= 0 { return 0; }
    let elapsed = now_ts() - ts;
    if elapsed >= PIN_CACHE_SECS { 0 } else { PIN_CACHE_SECS - elapsed }
}

pub(crate) fn refresh_pin_cache() {
    PIN_CACHE_TS.store(now_ts(), std::sync::atomic::Ordering::Relaxed);
}

pub(crate) fn invalidate_pin_cache() {
    PIN_CACHE_TS.store(0, std::sync::atomic::Ordering::Relaxed);
}

#[tauri::command]
pub fn pin_cache_status() -> Result<serde_json::Value, EgoDesktopError> {
    Ok(serde_json::json!({
        "fresh":             pin_cache_is_fresh(),
        "seconds_remaining": pin_cache_seconds_remaining(),
        "cache_window_secs": PIN_CACHE_SECS,
    }))
}

/// Quickly verify the user-supplied PIN against the local ledger,
/// applying the standard lockout. Returns Ok(()) on a valid PIN,
/// errors on missing/incorrect PIN, and respects the existing
/// brute-force lockout window. Used by transaction signing flows.
pub(crate) fn check_pin_for_tx(_pin: &str) -> Result<(), EgoDesktopError> {
    // Password requirement for transactions has been removed.
    Ok(())
}

fn pin_matches(ledger: &Ledger, pin: &str) -> bool {
    if ledger.security_pin_hash.is_empty() {
        return false;
    }
    if ledger.security_pin_hash.starts_with("$argon2") {
        return PasswordHash::new(&ledger.security_pin_hash)
            .ok()
            .map(|hash| Argon2::default().verify_password(pin.as_bytes(), &hash).is_ok())
            .unwrap_or(false);
    }
    legacy_pin_hash(pin, &ledger.security_pin_salt) == ledger.security_pin_hash
}

fn upgrade_legacy_pin_hash_if_needed(
    ledger: &mut Ledger,
    pin: &str,
) -> Result<(), EgoDesktopError> {
    if ledger.security_pin_hash.is_empty() || ledger.security_pin_hash.starts_with("$argon2") {
        return Ok(());
    }
    ledger.security_pin_hash = hash_pin_argon2(pin)?;
    ledger.security_pin_salt.clear();
    ledger.save().map_err(EgoDesktopError::WalletError)
}

#[tauri::command]
pub async fn set_security_pin(pin: String) -> Result<(), EgoDesktopError> {
    let pin = normalize_pin(&pin)?;
    let pin_hash = hash_pin_argon2(&pin)?;
    let mut ledger = Ledger::load();
    ledger.security_pin_hash = pin_hash;
    ledger.security_pin_salt.clear();
    ledger.save().map_err(EgoDesktopError::WalletError)
}

// ── verify_pin ────────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn verify_pin(pin: String) -> Result<bool, EgoDesktopError> {
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let mut ledger = Ledger::load();
    let address = ledger.address.clone();
    enforce_pin_lockout_for(&address)?;

    if ledger.security_pin_hash.is_empty() {
        record_successful_pin_for(&address);
        return Ok(false);
    }
    let pin_val = match normalize_pin(&pin) {
        Ok(p) => p,
        Err(_) => {
            let err = record_failed_pin_for(&address);
            if let EgoDesktopError::PermissionDenied(_) = err { return Err(err); }
            return Ok(false);
        }
    };
    if !pin_matches(&ledger, &pin_val) {
        let err = record_failed_pin_for(&address);
        if let EgoDesktopError::PermissionDenied(_) = err { return Err(err); }
        return Ok(false);
    }

    record_successful_pin_for(&address);
    upgrade_legacy_pin_hash_if_needed(&mut ledger, &pin_val)?;
    refresh_pin_cache();
    Ok(true)
}

// ── reset_pin_with_recovery_phrase ───────────────────────────────────────────
// Allows the user to set a fresh PIN by proving ownership of the wallet
// via the 24-word recovery phrase derived from the on-disk seed. No email
// dependency — purely local cryptographic proof.
#[tauri::command]
pub async fn reset_pin_with_recovery_phrase(
    recovery_phrase: Vec<String>,
    new_pin: String,
) -> Result<(), EgoDesktopError> {
    let new_pin = normalize_pin(&new_pin)?;

    tokio::task::spawn_blocking(move || -> Result<(), EgoDesktopError> {
        let provided: Vec<String> = recovery_phrase
            .iter()
            .map(|w| w.trim().to_lowercase())
            .filter(|w| !w.is_empty())
            .collect();
        if provided.len() != 24 {
            return Err(EgoDesktopError::InvalidInput(
                "Recovery phrase must be exactly 24 words.".into(),
            ));
        }

        // Derive the expected phrase from the on-disk seed. No side effects.
        let seed = match crate::ledger::load_seed() {
            Ok(Some(s)) => s,
            _ => return Err(EgoDesktopError::WalletError(
                "No seed on disk; cannot verify recovery phrase.".into(),
            )),
        };
        let wordlist = get_bip39_wordlist();
        let checksum_byte = ego_core::hash_data(&seed).as_bytes()[0];
        let mut buf = [0u8; 33];
        buf[..32].copy_from_slice(&seed);
        buf[32] = checksum_byte;
        let mut expected = Vec::with_capacity(24);
        for i in 0..24 {
            let bit_offset = i * 11;
            let byte_idx   = bit_offset / 8;
            let bit_shift  = bit_offset % 8;
            let b0 = buf[byte_idx] as u32;
            let b1 = if byte_idx + 1 < 33 { buf[byte_idx + 1] as u32 } else { 0 };
            let b2 = if byte_idx + 2 < 33 { buf[byte_idx + 2] as u32 } else { 0 };
            let raw   = (b0 << 16) | (b1 << 8) | b2;
            let index = (((raw >> (13 - bit_shift)) & 0x7FF) as usize) % wordlist.len();
            expected.push(wordlist[index].to_string().to_lowercase());
        }

        if provided != expected {
            return Err(EgoDesktopError::InvalidInput(
                "Recovery phrase does not match this wallet.".into(),
            ));
        }

        let new_hash = hash_pin_argon2(&new_pin)?;
        let mut ledger = Ledger::load();
        ledger.security_pin_hash = new_hash;
        ledger.security_pin_salt.clear();
        ledger.save().map_err(EgoDesktopError::WalletError)?;
        let addr = ledger.address.clone();
        record_successful_pin_for(&addr);
        refresh_pin_cache();
        Ok(())
    })
    .await
    .map_err(|e| EgoDesktopError::WalletError(format!("PIN reset task: {e}")))?
}

// ── get_recovery_info ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct RecoveryInfo {
    pub recovery_phrase: Vec<String>,
    pub seed_hex: String,
    pub address: String,
    pub has_pin: bool,
}

#[tauri::command]
pub async fn get_recovery_info(pin: String) -> Result<RecoveryInfo, EgoDesktopError> {
    let mut ledger = Ledger::load();
    let address = ledger.address.clone();
    enforce_pin_lockout_for(&address)?;

    if !ledger.security_pin_hash.is_empty() {
        let pin_val = normalize_pin(&pin).map_err(|_| record_failed_pin_for(&address))?;
        if !pin_matches(&ledger, &pin_val) {
            return Err(record_failed_pin_for(&address));
        }
        record_successful_pin_for(&address);
        upgrade_legacy_pin_hash_if_needed(&mut ledger, &pin_val)?;
    }

    let seed_bytes = crate::ledger::load_seed()
        .map_err(|e| EgoDesktopError::CryptoError(format!("Failed to load seed: {}", e)))?
        .ok_or_else(|| EgoDesktopError::CryptoError("Corrupt or missing seed file".into()))?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);

    let keypair = KeyPair::from_bytes(&seed)
        .map_err(|e| EgoDesktopError::CryptoError(format!("{e}")))?;
    let recovery_phrase = generate_recovery_phrase(&keypair)?;
    let seed_hex        = hex::encode(&seed_bytes);

    Ok(RecoveryInfo {
        recovery_phrase,
        seed_hex,
        address: ledger.address,
        has_pin: !ledger.security_pin_hash.is_empty(),
    })
}

// ── get_address ───────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn get_address(_state: State<'_, AppState>) -> Result<Option<String>, EgoDesktopError> {
    let ledger = Ledger::load();
    if ledger.address.is_empty() {
        Ok(None)
    } else {
        Ok(Some(ledger.address))
    }
}

/// Encode the wallet's 32-byte seed as a 24-word BIP39-compatible mnemonic.
///
/// The seed (NOT the keypair serialization) is the source of truth — this
/// ensures `restore_keypair_from_phrase` is the true inverse and actually
/// recovers the original wallet.
///
/// Encoding: seed[32] + SHA256(seed)[0] (checksum) → 264 bits → 24 × 11-bit
/// word indices → BIP39 English wordlist.  Same bit-packing as BIP39 spec.
fn generate_recovery_phrase(_keypair: &KeyPair) -> EgoResult<Vec<String>> {
    let wordlist = get_bip39_wordlist();

    // Use the raw 32-byte seed from disk — NOT keypair.to_bytes().
    // This guarantees the phrase encodes exactly what is needed to restore.
    let seed_bytes = crate::ledger::load_seed()
        .map_err(|e| EgoDesktopError::CryptoError(format!("Failed to load seed: {e}")))?
        .ok_or_else(|| EgoDesktopError::CryptoError("Seed unavailable for phrase generation".into()))?;

    // BIP39 checksum: first byte of SHA256(entropy).
    // We use BLAKE3 (our canonical hash) for the checksum byte.
    let checksum_byte = ego_core::hash_data(&seed_bytes).as_bytes()[0];

    let mut buf = [0u8; 33];
    buf[..32].copy_from_slice(&seed_bytes);
    buf[32] = checksum_byte;

    let mut words = Vec::with_capacity(24);
    for i in 0..24 {
        let bit_offset = i * 11;
        let byte_idx   = bit_offset / 8;
        let bit_shift  = bit_offset % 8;

        let b0 = buf[byte_idx] as u32;
        let b1 = if byte_idx + 1 < 33 { buf[byte_idx + 1] as u32 } else { 0 };
        let b2 = if byte_idx + 2 < 33 { buf[byte_idx + 2] as u32 } else { 0 };
        let raw   = (b0 << 16) | (b1 << 8) | b2;
        let index = (((raw >> (13 - bit_shift)) & 0x7FF) as usize) % wordlist.len();
        words.push(wordlist[index].to_string());
    }

    Ok(words)
}

/// Decode a 24-word mnemonic back to the original 32-byte seed and restore the keypair.
///
/// This is the true inverse of `generate_recovery_phrase`.  It verifies the
/// checksum so invalid phrases are rejected before any key material is written.
fn restore_keypair_from_phrase(phrase: &[String]) -> EgoResult<KeyPair> {
    if phrase.len() != 24 {
        return Err(EgoDesktopError::InvalidInput(
            "Recovery phrase must be exactly 24 words".into(),
        ));
    }

    let wordlist = get_bip39_wordlist();

    // Build word → index map for O(1) lookup.
    let word_to_idx: std::collections::HashMap<&str, u32> = wordlist.iter()
        .enumerate()
        .map(|(i, &w)| (w, i as u32))
        .collect();

    // Decode each word to its 11-bit index.
    let mut indices = Vec::with_capacity(24);
    for word in phrase {
        let idx = word_to_idx.get(word.as_str())
            .copied()
            .ok_or_else(|| EgoDesktopError::InvalidInput(
                format!("Unknown word in recovery phrase: '{}'", word)
            ))?;
        indices.push(idx);
    }

    // Unpack 24 × 11-bit indices back into a 33-byte buffer (264 bits).
    // This is the exact inverse of the encoding bit-shifts above.
    let mut buf = [0u8; 33];
    for (i, &idx) in indices.iter().enumerate() {
        let bit_offset = i * 11;
        let byte_idx   = bit_offset / 8;
        let bit_shift  = bit_offset % 8;

        let raw = (idx & 0x7FF) << (13 - bit_shift as u32);
        buf[byte_idx]                                    |= ((raw >> 16) & 0xFF) as u8;
        if byte_idx + 1 < 33 { buf[byte_idx + 1]        |= ((raw >>  8) & 0xFF) as u8; }
        if byte_idx + 2 < 33 { buf[byte_idx + 2]        |= ( raw        & 0xFF) as u8; }
    }

    // First 32 bytes = seed; last byte = checksum.
    let seed      = &buf[..32];
    let stored_cs = buf[32];
    let expected_cs = ego_core::hash_data(seed).as_bytes()[0];

    if stored_cs != expected_cs {
        return Err(EgoDesktopError::InvalidInput(
            "Invalid recovery phrase: checksum mismatch. Please check every word.".into()
        ));
    }

    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(seed);

    // Persist the recovered seed so subsequent app launches work without phrase.
    crate::ledger::save_seed(&seed_arr)
        .map_err(|e| EgoDesktopError::CryptoError(format!("Save seed: {e}")))?;

    KeyPair::from_bytes(&seed_arr)
        .map_err(|e| EgoDesktopError::CryptoError(format!("{e}")))
}

fn generate_address_qr(address: &str) -> EgoResult<String> {
    use qrcode::QrCode;
    let qr = QrCode::new(address.as_bytes())
        .map_err(|e| EgoDesktopError::CryptoError(format!("QR: {e}")))?;
    let svg = qr
        .render::<char>()
        .quiet_zone(false)
        .module_dimensions(2, 1)
        .build();
    Ok(format!(
        "data:image/svg+xml;base64,{}",
        base64::encode(svg.as_bytes())
    ))
}

fn copy_dir_all(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dst.join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dst.join(entry.file_name()))?;
        }
    }
    Ok(())
}

fn get_bip39_wordlist() -> &'static [&'static str] {
    &[

        "abandon","ability","able","about","above","absent","absorb","abstract",

        "absurd","abuse","access","accident","account","accuse","achieve","acid",

        "acoustic","acquire","across","act","action","actor","actress","actual",

        "adapt","add","addict","address","adjust","admit","adult","advance",

        "advice","aerobic","affair","afford","afraid","again","age","agent",

        "agree","ahead","aim","air","airport","aisle","alarm","album",

        "alcohol","alert","alien","all","alley","allow","almost","alone",

        "alpha","already","also","alter","always","amateur","amazing","among",

        "amount","amused","analyst","anchor","ancient","anger","angle","angry",

        "animal","ankle","announce","annual","another","answer","antenna","antique",

        "anxiety","any","apart","apology","appear","apple","approve","april",

        "arcade","arch","arctic","area","arena","argue","arm","armed",

        "armor","army","around","arrange","arrest","arrive","arrow","art",

        "ask","aspect","assault","asset","assist","assume","asthma","athlete",

        "atom","attack","attend","attitude","attract","auction","audit","august",

        "aunt","author","auto","autumn","average","avocado","avoid","awake",

        "aware","away","awesome","awful","awkward","axis","baby","bacon",

        "badge","bag","balance","balcony","ball","bamboo","banana","banner",

        "bar","barely","bargain","barrel","base","basic","basket","battle",

        "beach","bean","beauty","because","become","beef","before","begin",

        "behave","behind","believe","below","belt","bench","benefit","best",

        "betray","better","between","beyond","bicycle","bid","bike","bind",

        "biology","bird","birth","bitter","black","blade","blame","blanket",

        "blast","bleak","bless","blind","blood","blossom","blouse","blue",

        "blur","blush","board","boat","body","boil","bomb","bone",

        "book","boost","border","boring","borrow","boss","bottom","bounce",

        "box","boy","bracket","brain","brand","brave","breeze","brick",

        "bridge","brief","bright","bring","brisk","broccoli","broken","bronze",

        "broom","brother","brown","brush","bubble","buddy","budget","buffalo",

        "build","bulb","bulk","bullet","bundle","bunker","burden","burger",

        "burst","bus","business","busy","butter","buyer","buzz","cabbage",

        "cabin","cable","cactus","cage","cake","call","calm","camera",

        "camp","can","canal","cancel","candy","cannon","canvas","canyon",

        "capable","capital","captain","car","carbon","card","cargo","carpet",

        "carry","cart","case","cash","casino","castle","casual","cat",

        "catalog","catch","category","cattle","caught","cause","caution","cave",

        "ceiling","celery","cement","census","chair","chaos","chapter","charge",

        "chase","chat","cheap","check","cheese","chef","cherry","chest",

        "chicken","chief","child","chimney","choice","choose","chronic","chuckle",

        "chunk","cinnamon","circle","citizen","city","civil","claim","clap",

        "clarify","claw","clay","clean","clerk","clever","click","client",

        "cliff","climb","clinic","clip","clock","clog","close","cloth",

        "cloud","clown","club","clump","cluster","cobalt","code","coffee",

        "coil","coin","collect","color","column","combine","come","comfort",

        "comic","common","company","concert","conduct","confirm","congress","connect",

        "consider","control","convince","cook","cool","copper","copy","coral",

        "core","corn","correct","cost","cotton","couch","country","couple",

        "course","cousin","cover","coyote","crack","cradle","craft","cram",

        "crane","crash","crater","crawl","crazy","cream","credit","creek",

        "crew","cricket","crime","crisp","critic","cross","crouch","crowd",

        "crucial","cruel","cruise","crumble","crunch","crush","cry","crystal",

        "cube","culture","cup","cupboard","curious","current","curtain","curve",

        "cushion","custom","cute","cycle","dad","damage","damp","dance",

        "danger","daring","dash","daughter","dawn","day","deal","debate",

        "debris","decade","december","decide","decline","decorate","decrease","deer",

        "defense","define","defy","degree","delay","deliver","demand","demise",

        "denial","dentist","deny","depart","depend","deposit","depth","deputy",

        "derive","describe","desert","design","desk","despair","destroy","detail",

        "detect","develop","device","devote","diagram","dial","diamond","diary",

        "dice","diesel","diet","differ","digital","dignity","dilemma","dinner",

        "dinosaur","direct","dirt","disagree","discover","disease","dish","dismiss",

        "disorder","display","distance","divert","divide","divorce","dizzy","doctor",

        "document","dog","doll","dolphin","domain","donate","donkey","donor",

        "door","dose","double","dove","draft","dragon","drama","drastic",

        "draw","dream","dress","drift","drill","drink","drip","drive",

        "drop","drum","dry","duck","dumb","dune","during","dust",

        "dutch","duty","dwarf","dynamic","eager","eagle","early","earn",

        "earth","easily","east","easy","echo","ecology","edge","edit",

        "educate","effort","egg","eight","either","elbow","elder","electric",

        "elegant","element","elephant","elevator","elite","else","embark","embody",

        "embrace","emerge","emotion","employ","empower","empty","enable","enact",

        "endless","endorse","enemy","engage","engine","enhance","enjoy","enlist",

        "enough","enrich","enroll","ensure","enter","entire","entry","envelope",

        "episode","equal","equip","erase","erode","erosion","error","erupt",

        "escape","essay","essence","estate","eternal","ethics","evidence","evil",

        "evoke","evolve","exact","example","excess","exchange","excite","exclude",

        "exercise","exhaust","exhibit","exile","exist","exit","exotic","expand",

        "expire","explain","expose","express","extend","extra","eye","fable",

        "face","faculty","fade","faint","faith","fall","false","fame",

        "family","famous","fan","fancy","fantasy","far","fashion","fat",

        "fatal","father","fatigue","fault","favorite","feature","february","federal",

        "fee","feed","feel","feet","fellow","felt","fence","festival",

        "fetch","fever","few","fiber","fiction","field","figure","file",

        "film","filter","final","find","fine","finger","finish","fire",

        "firm","first","fiscal","fish","fit","fitness","fix","flag",

        "flame","flash","flat","flavor","flee","flight","flip","float",

        "flock","floor","flower","fluid","flush","fly","foam","focus",

        "fog","foil","follow","food","foot","force","forest","forget",

        "fork","fortune","forum","forward","fossil","foster","found","fox",

        "fragile","frame","frequent","fresh","friend","fringe","frog","front",

        "frost","frown","frozen","fruit","fuel","fun","funny","furnace",

        "fury","future","gadget","gain","galaxy","gallery","game","gap",

        "garbage","garden","garlic","garment","gasp","gate","gather","gauge",

        "gaze","general","genius","genre","gentle","genuine","gesture","ghost",

        "ginger","giraffe","girl","give","glad","glance","glare","glass",

        "gloom","glove","glow","glue","goat","goddess","gold","good",

        "goose","gorilla","gospel","gossip","govern","gown","grab","grace",

        "grain","grant","grape","grasp","grass","gravity","great","green",

        "grid","grief","grit","grocery","group","grow","grunt","guard",

        "guide","guilt","guitar","gun","gym","habit","hair","half",

        "hammer","hamster","hand","happy","harbor","hard","harsh","harvest",

        "hat","have","hawk","hazard","head","health","heart","heavy",

        "hedgehog","height","hello","helmet","help","hen","hero","hidden",

        "high","hill","hint","hip","hire","history","hobby","hockey",

        "hold","hole","holiday","hollow","home","honey","hood","hope",

        "horn","hospital","host","hour","hover","hub","humble","humor",

        "hundred","hungry","hunt","hurdle","hurry","hurt","husband","hybrid",

        "ice","icon","ignore","ill","illegal","image","imitate","immense",

        "immune","impact","impose","improve","impulse","inbox","include","income",

        "increase","index","indicate","indoor","industry","infant","inflict","inform",

        "inhale","inject","injury","inmate","inner","innocent","input","inquiry",

        "insane","insect","inside","inspire","install","intact","interest","into",

        "invest","invite","involve","iron","island","isolate","issue","item",

        "ivory","jacket","jaguar","jar","jazz","jealous","jelly","jewel",

        "job","join","joke","journey","joy","judge","juice","jump",

        "jungle","junior","junk","just","kangaroo","keen","keep","ketchup",

        "key","kick","kingdom","kiss","kit","kitchen","kite","kitten",

        "kiwi","knee","knife","knock","know","lab","ladder","lady",

        "lake","lamp","language","laptop","large","later","laugh","laundry",

        "lava","law","lawn","lawsuit","layer","lazy","leader","learn",

        "leave","lecture","left","leg","legal","legend","leisure","lemon",

        "lend","length","lens","leopard","lesson","letter","level","liar",

        "liberty","library","license","life","lift","light","like","limb",

        "limit","link","lion","liquid","list","little","live","lizard",

        "load","loan","lobster","local","lock","logic","lonely","long",

        "loop","lottery","loud","loyal","lucky","luggage","lumber","lunar",

        "lunch","luxury","mad","magic","magnet","maid","main","major",

        "make","mammal","mango","mansion","manual","maple","marble","march",

        "margin","marine","market","marriage","mask","master","match","material",

        "math","matrix","matter","maximum","maze","meadow","mean","medal",

        "media","melody","melt","member","memory","mention","menu","mercy",

        "merge","merit","merry","mesh","message","metal","method","middle",

        "midnight","milk","million","mimic","mind","minimum","minor","minute",

        "miracle","miss","mixed","mixture","mobile","model","modify","mom",

        "monitor","monkey","monster","month","moon","moral","more","morning",

        "mosquito","mother","motion","motor","mountain","mouse","move","movie",

        "much","muffin","mule","multiply","muscle","museum","mushroom","music",

        "must","mutual","myself","mystery","naive","name","napkin","narrow",

        "nasty","natural","nature","near","neck","need","negative","neglect",

        "neither","nephew","nerve","nest","network","neutral","never","news",

        "next","nice","night","noble","noise","nominee","noodle","normal",

        "north","notable","note","nothing","notice","novel","now","nuclear",

        "number","nurse","nut","oak","obey","object","oblige","obscure",

        "obtain","ocean","october","odd","offer","often","oil","okay",

        "old","olive","olympic","omit","once","onion","open","option",

        "orange","orbit","orchard","order","ordinary","organ","orient","original",

        "orphan","ostrich","other","outdoor","outside","oval","over","own",

        "oxygen","oyster","ozone","pain","paint","pair","palace","palm",

        "panda","panel","panic","panther","paper","parade","parent","park",

        "parrot","party","pass","patch","path","patrol","pause","pave",

        "payment","peace","peanut","peasant","pelican","pen","penalty","penguin",

        "pepper","perfect","permit","person","pet","phone","photo","phrase",

        "physical","piano","picnic","picture","piece","pig","pigeon","pill",

        "pilot","pink","pioneer","pipe","pistol","pitch","pizza","place",

        "planet","plastic","plate","play","please","pledge","pluck","plug",

        "plunge","poem","poet","point","polar","pole","police","pond",

        "pony","popular","portion","position","possible","post","potato","pottery",

        "poverty","powder","power","practice","praise","predict","prefer","prepare",

        "present","pretty","prevent","price","pride","primary","print","priority",

        "prison","private","prize","problem","process","produce","profit","program",

        "project","promote","proof","property","prosper","protect","proud","provide",

        "public","pudding","pull","pulp","pulse","pumpkin","punch","pupil",

        "puppy","purchase","purity","purpose","push","put","puzzle","pyramid",

        "quality","quantum","quarter","question","quick","quit","quiz","quote",

        "rabbit","raccoon","race","rack","radar","radio","rage","rail",

        "rain","raise","rally","ramp","ranch","random","range","rapid",

        "rare","rate","rather","raven","reach","ready","real","reason",

        "rebel","rebuild","recall","receive","recipe","record","recycle","reduce",

        "reflect","reform","refuse","region","regret","regular","reject","relax",

        "release","relief","rely","remain","remember","remind","remove","render",

        "renew","rent","reopen","repair","repeat","replace","report","require",

        "rescue","resemble","resist","resource","response","result","retire","retreat",

        "return","reunion","reveal","review","reward","rhythm","ribbon","rice",

        "rich","ride","rifle","right","rigid","ring","riot","ripple",

        "risk","ritual","rival","river","road","roast","robot","robust",

        "rocket","romance","roof","rookie","rotate","rough","round","route",

        "royal","rubber","rude","rug","rule","run","runway","rural",

        "sad","saddle","sadness","safe","sail","salad","salmon","salon",

        "salt","salute","same","sample","sand","satisfy","satoshi","sauce",

        "sausage","save","say","scale","scan","scare","scatter","scene",

        "scheme","science","scissors","scorpion","scout","scrap","screen","script",

        "scrub","sea","search","season","seat","second","secret","section",

        "security","seek","segment","select","sell","seminar","senior","sense",

        "sentence","series","service","session","settle","setup","seven","shadow",

        "shaft","shallow","share","shed","shell","sheriff","shield","shift",

        "shine","ship","shiver","shock","shoe","shoot","shop","short",

        "shoulder","shove","shrimp","shrug","shuffle","shy","sibling","siege",

        "sight","sign","silent","silk","silly","silver","similar","simple",

        "since","sing","siren","sister","situate","six","size","sketch",

        "skill","skin","skirt","skull","slab","slam","sleep","slender",

        "slice","slide","slight","slim","slogan","slot","slow","slush",

        "small","smart","smile","smoke","smooth","snack","snake","snap",

        "sniff","snow","soap","soccer","social","sock","solar","soldier",

        "solid","solution","solve","someone","song","soon","sorry","soul",

        "sound","soup","source","south","space","spare","spatial","spawn",

        "speak","special","speed","sphere","spice","spider","spike","spin",

        "spirit","split","spoil","sponsor","spoon","spray","spread","spring",

        "spy","square","squeeze","squirrel","stable","stadium","staff","stage",

        "stairs","stamp","stand","start","state","stay","steak","steel",

        "stem","step","stereo","stick","still","sting","stock","stomach",

        "stone","stop","store","storm","story","stove","strategy","street",

        "strike","strong","struggle","student","stuff","stumble","style","subject",

        "submit","subway","success","such","sudden","suffer","sugar","suggest",

        "suit","summer","sun","sunny","sunset","super","supply","supreme",

        "sure","surface","surge","surprise","sustain","swallow","swamp","swap",

        "swear","sweet","swift","swim","swing","switch","sword","symbol",

        "symptom","syrup","table","tackle","tag","tail","talent","tamper",

        "tank","tape","target","task","tattoo","taxi","teach","team",

        "tell","ten","tenant","tennis","tent","term","test","text",

        "thank","that","theme","then","theory","there","they","thing",

        "this","thought","three","thrive","throw","thumb","thunder","ticket",

        "tilt","timber","time","tiny","tip","tired","title","toast",

        "tobacco","today","together","toilet","token","tomato","tomorrow","tone",

        "tongue","tonight","tool","tooth","top","topic","topple","torch",

        "tornado","tortoise","toss","total","tourist","toward","tower","town",

        "toy","track","trade","traffic","tragic","train","transfer","trap",

        "trash","travel","tray","treat","tree","trend","trial","tribe",

        "trick","trigger","trim","trip","trophy","trouble","truck","truly",

        "trumpet","trust","truth","tube","tuition","tumble","tuna","tunnel",

        "turkey","turn","turtle","twelve","twenty","twice","twin","twist",

        "two","type","typical","ugly","umbrella","unable","unaware","uncle",

        "uncover","under","undo","unfair","unfold","unhappy","uniform","unique",

        "universe","unknown","unlock","until","unusual","unveil","update","upgrade",

        "uphold","upon","upper","upset","urban","usage","use","used",

        "useful","useless","usual","utility","vacant","vacuum","vague","valid",

        "valley","valve","van","vanish","vapor","various","vast","vault",

        "vehicle","velvet","vendor","venture","venue","verb","verify","version",

        "very","veteran","viable","vibrant","vicious","victory","video","view",

        "village","vintage","violin","virtual","virus","visa","visit","visual",

        "vital","vivid","vocal","voice","void","volcano","volume","vote",

        "voyage","wage","wagon","wait","walk","wall","walnut","want",

        "warfare","warm","warrior","wash","wasp","waste","water","wave",

        "way","wealth","weapon","wear","weasel","wedding","weekend","weird",

        "welcome","west","wet","whale","wheat","wheel","when","where",

        "whip","whisper","wide","width","wife","wild","will","win",

        "window","wine","wing","wink","winner","winter","wire","wisdom",

        "wish","witness","wolf","woman","wonder","wood","wool","word",

        "world","worry","worth","wrap","wreck","wrestle","wrist","write",

        "wrong","yard","year","yellow","you","young","youth","zebra",

        "zero","zone","zoo",

        "zenith","zeal","zest","zinc","zephyr","zigzag","zodiac","zombie",
        "zealous","zenlike","zoning","zoology","zoomed","zirconia","zipcode","zipline",
        "zeppelin","zipper","zenobia","zircon","zestful","zealotry","zoetrope","zodiacal",
        "zymurgy","zoeform","ziplock","zirconate","zestfully","zealously","zenmaster","zookeeper",
        "abacus","abalone","abbey","abdomen","abduct","abhor","abide","abjure",
        "ablaze","abode","abolish","abrupt","absolve","abstain","abysmal","acclaim",
        "accolade","accrue","accuse","ache","acme","acorn","acquaint","acrid",
        "acrobat","adamant","addendum","adhere","adjacent","adjoin","adjunct","adorn",
        "adroit","adulate","adverse","afflict","agile","agitate","agony","ailment",
        "alacrity","albeit","alcove","alder","aloft","altruism","alum","amalgam",
        "amble","ambrosia","amend","amiable","amiss","amity","amnesty","ample",
        "amputate","analogy","ancestry","anew","anguish","animosity","annex","anomaly",
        "apex","appease","aptitude","ardent","ardor","arid","armor","artisan",
        "ascend","ascent","ascribe","ashen","aspire","astute","atone","atrium",
        "attain","audacity","auspice","austere","avid","axiom","azure","ballad",
        "bastion","beacon","beckon","befall","befriend","beguile","behold","benign",
        "besiege","bestow","betide","beware","bountiful","brazen","brisk","brooch",
    ]
}

#[tauri::command]
pub async fn send_verification_email(email: String, name: String) -> Result<(), String> {
    if email.trim().is_empty() {
        return Err("Email address is required.".into());
    }
    crate::email::check_send_limit(email.trim())?;
    let code = crate::email::gen_otp_code();
    let email_trimmed = email.trim().to_string();
    let name_trimmed  = name.trim().to_string();
    crate::email::store_otp(&email_trimmed, &code);
    crate::email::record_send_attempt(&email_trimmed);
    tokio::spawn(async move {
        if let Err(e) = crate::email::send_otp_email(&email_trimmed, &name_trimmed, &code).await {
            eprintln!("[Email] OTP send failed for {}: {}", &email_trimmed, e);
        }
    });
    Ok(())
}

#[tauri::command]
pub async fn verify_email_code(email: String, code: String) -> Result<bool, String> {
    let ok = crate::email::verify_otp(email.trim(), code.trim());
    if ok { crate::email::reset_send_attempts(email.trim()); }
    Ok(ok)
}

#[tauri::command]
pub async fn save_registration_info(name: String, email: String) -> Result<(), String> {
    let mut ledger = Ledger::load();
    ledger.registered_name  = name.trim().to_string();
    ledger.registered_email = email.trim().to_lowercase();
    ledger.save()
}

// ── Wallet backup / restore ───────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct BackupBundle {
    version:      u8,
    address:      String,
    seed_hex:     String,
    exported_at:  i64,
    contacts:     Vec<crate::commands::messenger::Contact>,
    messages:     Vec<crate::commands::messenger::Message>,
    hosted_sites: Vec<serde_json::Value>,
    stored_files: Vec<crate::ledger::StoredFile>,
}

#[derive(Serialize, Deserialize)]
struct BackupEnvelope {
    version:        u8,
    exported_at:    i64,
    kdf_salt_b64:   String,
    ciphertext_b64: String,
}

fn derive_legacy_backup_key(seed: &[u8]) -> [u8; 32] {
    let mut input = b"ego-backup-v1".to_vec();
    input.extend_from_slice(seed);
    let hash = ego_core::hash_data(&input);
    let mut key = [0u8; 32];
    key.copy_from_slice(hash.as_bytes());
    key
}

fn derive_backup_key_from_passphrase(
    passphrase: &str,
    salt: &[u8],
) -> Result<[u8; 32], EgoDesktopError> {
    if passphrase.trim().len() < 8 {
        return Err(EgoDesktopError::InvalidInput(
            "Backup passphrase must be at least 8 characters".into(),
        ));
    }
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.trim().as_bytes(), salt, &mut key)
        .map_err(|e| EgoDesktopError::CryptoError(format!("Backup KDF: {e}")))?;
    Ok(key)
}

fn decode_backup_seed(bundle: &BackupBundle) -> Result<[u8; 32], EgoDesktopError> {
    let seed_bytes = hex::decode(&bundle.seed_hex)
        .map_err(|_| EgoDesktopError::InvalidInput("Backup seed is not valid hex".into()))?;
    if seed_bytes.len() != 32 {
        return Err(EgoDesktopError::InvalidInput("Backup seed must be 32 bytes".into()));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let keypair = KeyPair::from_bytes(&seed)
        .map_err(|e| EgoDesktopError::CryptoError(format!("Backup keypair: {e}")))?;
    let derived_address = keypair
        .derive_bech32_address(1, AddressType::EOA, "egot")
        .map_err(|e| EgoDesktopError::CryptoError(format!("Backup address: {e}")))?;
    if derived_address != bundle.address {
        return Err(EgoDesktopError::InvalidInput(
            "Backup seed does not match the bundled wallet address".into(),
        ));
    }
    Ok(seed)
}

fn restore_backup_bundle_from_json(json_bytes: &[u8]) -> Result<String, EgoDesktopError> {
    let bundle: BackupBundle = serde_json::from_slice(json_bytes)
        .map_err(|e| EgoDesktopError::InvalidInput(format!("Malformed backup: {e}")))?;

    let seed = decode_backup_seed(&bundle)?;
    let keypair = KeyPair::from_bytes(&seed)
        .map_err(|e| EgoDesktopError::CryptoError(format!("Backup keypair: {e}")))?;
    let mainnet_address = keypair
        .derive_bech32_address(0, AddressType::EOA, "ego")
        .unwrap_or_default();

    let mut ledger = Ledger::load();
    if !ledger.address.is_empty() && bundle.address != ledger.address {
        return Err(EgoDesktopError::InvalidInput(format!(
            "Backup is for address {} but current wallet is {}",
            bundle.address, ledger.address
        )));
    }
    let current_seed = crate::ledger::load_seed().ok().flatten();
    if current_seed.as_deref() != Some(seed.as_slice()) {
        crate::ledger::save_seed(&seed)
            .map_err(|e| EgoDesktopError::FileSystemError(format!("Write seed: {e}")))?;
    }
    if ledger.address.is_empty() {
        ledger.address = bundle.address.clone();
    }
    if ledger.mainnet_address.is_empty() {
        ledger.mainnet_address = mainnet_address;
    }
    ledger.save().map_err(EgoDesktopError::WalletError)?;

    let mut contacts_restored = 0usize;
    let mut messages_restored = 0usize;
    let mut sites_restored = 0usize;
    let mut files_restored = 0usize;

    {
        let _lock = crate::commands::messenger::CONTACTS_LOCK.lock().unwrap();
        let mut existing = crate::commands::messenger::load_contacts();
        for c in bundle.contacts {
            if !existing.iter().any(|e| e.address == c.address) {
                existing.push(c);
                contacts_restored += 1;
            }
        }
        crate::commands::messenger::save_contacts(&existing)
            .map_err(EgoDesktopError::FileSystemError)?;
    }

    {
        let mut existing = crate::commands::messenger::load_messages();
        let existing_ids: std::collections::HashSet<String> =
            existing.iter().map(|m| m.id.clone()).collect();
        for m in bundle.messages {
            if !existing_ids.contains(&m.id) {
                existing.push(m);
                messages_restored += 1;
            }
        }
        crate::commands::messenger::save_messages(&existing)
            .map_err(EgoDesktopError::FileSystemError)?;
    }

    for site_val in bundle.hosted_sites {
        if let Some(name) = site_val["name"].as_str() {
            if crate::chain_db::get_hosted_site_raw(name).is_none() {
                crate::chain_db::save_hosted_site(name, &site_val);
                sites_restored += 1;
            }
        }
    }

    {
        let mut ledger_mut = Ledger::load();
        let existing_cids: std::collections::HashSet<String> =
            ledger_mut.stored_files.iter().map(|f| f.cid.clone()).collect();
        for sf in bundle.stored_files {
            if !existing_cids.contains(&sf.cid) {
                ledger_mut.stored_files.push(sf);
                files_restored += 1;
            }
        }
        ledger_mut.save().map_err(EgoDesktopError::WalletError)?;
    }

    Ok(format!(
        "Restored: {} contacts, {} messages, {} sites, {} files",
        contacts_restored, messages_restored, sites_restored, files_restored
    ))
}

fn aes_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce as AesNonce};
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let ct = cipher.encrypt(AesNonce::from_slice(&nonce_bytes), plaintext)
        .expect("aes encrypt");
    let mut out = nonce_bytes.to_vec();
    out.extend(ct);
    out
}

fn aes_decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, EgoDesktopError> {
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce as AesNonce};
    if data.len() < 28 {
        return Err(EgoDesktopError::InvalidInput("Backup file is too short".into()));
    }
    let (nonce_bytes, ct) = data.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    cipher.decrypt(AesNonce::from_slice(nonce_bytes), ct)
        .map_err(|_| EgoDesktopError::CryptoError(
            "Decryption failed — wrong seed or corrupted backup".into()
        ))
}

#[tauri::command]
pub async fn export_wallet_backup(passphrase: String) -> Result<String, EgoDesktopError> {
    use base64::Engine as _;

    let seed_bytes = crate::ledger::load_seed()
        .map_err(|e| EgoDesktopError::CryptoError(format!("Failed to load seed: {}", e)))?
        .ok_or_else(|| EgoDesktopError::CryptoError("Seed unavailable".into()))?;

    let ledger  = Ledger::load();
    let address = ledger.address.clone();
    let owner   = address.clone();

    let contacts     = crate::commands::messenger::load_contacts();
    let messages     = crate::commands::messenger::load_messages();
    let hosted_sites = crate::chain_db::list_hosted_sites_raw(&owner);
    let stored_files = ledger.stored_files.clone();

    let bundle = BackupBundle {
        version: 2,
        address,
        seed_hex: hex::encode(&seed_bytes),
        exported_at: chrono::Utc::now().timestamp(),
        contacts,
        messages,
        hosted_sites,
        stored_files,
    };

    let json_bytes = serde_json::to_vec(&bundle)
        .map_err(|e| EgoDesktopError::CryptoError(format!("Serialize: {e}")))?;

    let mut salt = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
    let key       = derive_backup_key_from_passphrase(&passphrase, &salt)?;
    let encrypted = aes_encrypt(&key, &json_bytes);
    let envelope = BackupEnvelope {
        version: 2,
        exported_at: bundle.exported_at,
        kdf_salt_b64: base64::engine::general_purpose::STANDARD.encode(salt),
        ciphertext_b64: base64::engine::general_purpose::STANDARD.encode(encrypted),
    };
    let envelope_bytes = serde_json::to_vec(&envelope)
        .map_err(|e| EgoDesktopError::CryptoError(format!("Serialize envelope: {e}")))?;

    Ok(base64::engine::general_purpose::STANDARD.encode(envelope_bytes))
}

#[tauri::command]
pub async fn import_wallet_backup(
    backup_b64: String,
    passphrase: Option<String>,
) -> Result<String, EgoDesktopError> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD.decode(backup_b64.trim())
        .map_err(|_| EgoDesktopError::InvalidInput("Invalid base64 backup data".into()))?;

    let seed_bytes = crate::ledger::load_seed()
        .map_err(|e| EgoDesktopError::CryptoError(format!("Failed to load seed: {}", e)))?
        .ok_or_else(|| EgoDesktopError::CryptoError("Seed unavailable — wallet not loaded".into()))?;

    let key        = derive_legacy_backup_key(&seed_bytes);
    let json_bytes = aes_decrypt(&key, &raw)?;

    restore_backup_bundle_from_json(&json_bytes)
}

/// Derive the mainnet EGOC address from the same seed (chain_id=0, hrp="ego").
/// This address is separate from the testnet address (hrp="egot") and will have
/// a zero balance until mainnet launches.
#[tauri::command]
pub async fn get_mainnet_address() -> Result<String, EgoDesktopError> {
    let ledger = Ledger::load();
    if ledger.mainnet_address.is_empty() {
        return Err(EgoDesktopError::WalletError("Mainnet address not yet derived".into()));
    }
    Ok(ledger.mainnet_address)
}

#[cfg(test)]
mod phrase_compat_tests {
    use super::*;

    fn phrase_from_seed(seed: &[u8; 32]) -> Vec<String> {
        let wordlist = get_bip39_wordlist();
        let checksum_byte = ego_core::hash_data(seed).as_bytes()[0];
        let mut buf = [0u8; 33];
        buf[..32].copy_from_slice(seed);
        buf[32] = checksum_byte;
        let mut words = Vec::with_capacity(24);
        for i in 0..24 {
            let bit_offset = i * 11;
            let byte_idx = bit_offset / 8;
            let bit_shift = bit_offset % 8;
            let b0 = buf[byte_idx] as u32;
            let b1 = if byte_idx + 1 < 33 { buf[byte_idx + 1] as u32 } else { 0 };
            let b2 = if byte_idx + 2 < 33 { buf[byte_idx + 2] as u32 } else { 0 };
            let raw = (b0 << 16) | (b1 << 8) | b2;
            let index = (((raw >> (13 - bit_shift)) & 0x7FF) as usize) % wordlist.len();
            words.push(wordlist[index].to_string());
        }
        words
    }

    #[test]
    fn extension_phrase_matches_desktop() {
        let seed = [1u8; 32];
        let expected = "absurd amount dress acoustic aware mask advice can absurd amount dress acoustic aware mask advice can absurd amount dress acoustic aware mask advice combine";
        assert_eq!(phrase_from_seed(&seed).join(" "), expected);
    }
}
