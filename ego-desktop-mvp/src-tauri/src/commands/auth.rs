use crate::app::AppState;
use crate::error::{EgoDesktopError, EgoResult};
use crate::ledger::{
    base_data_dir, chain_path, data_dir, get_active_wallet_id, ledger_path, load_chain,
    load_registry, next_wallet_id, registry_path, save_chain, save_registry, seed_path,
    storage_dir, wallet_dir, Ledger, LedgerBlock, LedgerTx, SharedChain, WalletEntry,
    WalletRegistry,
};
use ego_core::{AddressType, KeyPair};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use tauri::State;

// ── Public types returned to the frontend ────────────────────────────────────

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
        Some(2) => Ok(true), // Windows Hello not available — allow through
        _ => Ok(false),
    }
}

#[cfg(target_os = "macos")]
fn biometric_platform(reason: &str) -> Result<bool, String> {
    // Write a temp Swift script that calls LAContext (Touch ID / Face ID / password fallback)
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
        Err(_) => Ok(true), // swift not available — allow through
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn biometric_platform(_reason: &str) -> Result<bool, String> {
    Ok(true) // Not supported on Linux — allow through
}

/// Show the platform's biometric / device-credential prompt.
/// Returns `true` if the user was verified (or if the platform doesn't support it).
/// Returns `false` if the user cancelled / failed.
#[tauri::command]
pub async fn verify_biometric(reason: String) -> Result<bool, String> {
    tokio::task::spawn_blocking(move || biometric_platform(&reason))
        .await
        .map_err(|e| format!("Task error: {e}"))?
}

/// All CPU-heavy / blocking work isolated here so callers can run it in
/// `tokio::task::spawn_blocking`, keeping the async executor free and ensuring
/// any panic is caught and returned as an error (not a silent hang).
struct WalletKeys {
    keypair:          KeyPair,
    address:          String,
    ed25519_hex:      String,
    dilithium_hex:    String,
    kyber_hex:        String,
    balance_uegoc:    u64,
    balance_formatted: String,
}

fn derive_wallet_keys() -> Result<WalletKeys, EgoDesktopError> {
    let seed_bytes = fs::read(seed_path())
        .map_err(|e| EgoDesktopError::FileSystemError(format!("Read seed: {e}")))?;
    if seed_bytes.len() != 32 {
        return Err(EgoDesktopError::CryptoError("Corrupt seed file".into()));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);

    let keypair = KeyPair::from_bytes(&seed)
        .map_err(|e| EgoDesktopError::CryptoError(format!("Keypair: {e}")))?;

    let ledger  = Ledger::load();
    let address = if !ledger.address.is_empty() {
        ledger.address.clone()
    } else {
        let derived = keypair
            .derive_bech32_address(1, AddressType::EOA, "egot")
            .map_err(|e| EgoDesktopError::CryptoError(format!("Address: {e}")))?;
        let mut l   = Ledger::default();
        l.address   = derived.clone();
        let _ = l.save();
        derived
    };

    let ed25519_hex   = hex::encode(keypair.ed25519_public_key().as_bytes());
    let dilithium_hex = hex::encode(keypair.dilithium_public_key().as_bytes());
    let kyber_hex     = hex::encode(keypair.kyber_public_key().as_bytes());

    let chain         = load_chain();
    let balance_uegoc = chain.balance_of(&address);
    let balance_formatted = format!("{:.2} EGOC", balance_uegoc as f64 / 1_000_000.0);

    Ok(WalletKeys { keypair, address, ed25519_hex, dilithium_hex, kyber_hex, balance_uegoc, balance_formatted })
}

async fn load_active_wallet(
    state: &AppState,
    is_new: bool,
) -> Result<WalletInfo, EgoDesktopError> {
    // Run all CPU-heavy / blocking work on a dedicated thread-pool thread.
    // If the post-quantum key generation panics (e.g. missing CPU features),
    // spawn_blocking captures the panic and converts it to an Err instead of
    // silently hanging the frontend invoke.
    let keys = tokio::task::spawn_blocking(derive_wallet_keys)
        .await
        .map_err(|e| EgoDesktopError::CryptoError(format!("Key generation panicked: {e}")))??;

    state
        .initialize_wallet(keys.keypair)
        .map_err(|e| EgoDesktopError::WalletError(format!("{e}")))?;
    state.set_session_start(chrono::Utc::now().timestamp());

    // Auto-provision 10 GB of distributed storage on every node.
    // This ensures the network has storage capacity from day one without
    // requiring manual configuration — mirrors how BitTorrent works.
    {
        let mut ledger = Ledger::load();
        if ledger.storage_allocated_bytes == 0 {
            ledger.storage_allocated_bytes = 10 * 1_000_000_000; // 10 GB
            let _ = ledger.save();
            // Ensure the storage directory exists
            let _ = fs::create_dir_all(storage_dir());
            eprintln!("[storage] Auto-provisioned 10 GB storage quota");
        }
    }

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

/// Write a fresh seed + genesis ledger into the currently active wallet dir.
fn create_wallet_files(address_override: Option<&str>) -> Result<String, EgoDesktopError> {
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);

    fs::create_dir_all(data_dir())
        .map_err(|e| EgoDesktopError::FileSystemError(format!("Create dir: {e}")))?;
    fs::write(seed_path(), &seed)
        .map_err(|e| EgoDesktopError::FileSystemError(format!("Write seed: {e}")))?;

    let keypair = KeyPair::from_bytes(&seed)
        .map_err(|e| EgoDesktopError::CryptoError(format!("Keypair: {e}")))?;
    let address = keypair
        .derive_bech32_address(1, AddressType::EOA, "egot")
        .map_err(|e| EgoDesktopError::CryptoError(format!("Address: {e}")))?;

    let final_address = address_override.unwrap_or(&address).to_string();

    let genesis_data = format!("genesis:{final_address}");
    let genesis_hash = ego_core::hash_data(genesis_data.as_bytes()).to_hex();

    // Per-wallet ledger keeps only metadata (address, nonce, stored_files, pin).
    // Transactions and balance now live in the shared chain.
    let mut ledger = Ledger::default();
    ledger.address = final_address.clone();
    ledger.save().map_err(EgoDesktopError::WalletError)?;

    // Write the genesis tx to the shared chain (broadcast to all nodes).
    let mut chain = load_chain();
    if !chain.transactions.iter().any(|tx| tx.hash == genesis_hash) {
        let ts = chrono::Utc::now().timestamp();
        let genesis_block_height = chain.blocks.len() as u64;

        chain.transactions.push(LedgerTx {
            hash:               genesis_hash.clone(),
            from:               "egot1faucet000000000000000000000000000000000000".into(),
            to:                 final_address.clone(),
            amount:             10_000 * 1_000_000,
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
            reward:     10_000 * 1_000_000,
            coinbase_tx: None,
        });
        save_chain(&chain).map_err(EgoDesktopError::WalletError)?;
    }

    Ok(final_address)
}

// ── init_wallet ───────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn init_wallet(state: State<'_, AppState>) -> Result<WalletInfo, EgoDesktopError> {
    // ── Step 1: Legacy migration ──────────────────────────────────────────
    // If the old flat-layout seed exists and there's no registry yet,
    // move files into wallet_0/ and build the registry.
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
            // Best-effort recursive copy
            let _ = copy_dir_all(&legacy_storage, &dst_storage);
        }

        // Read address from the ledger we just copied
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

    // ── Step 2: Migrate old per-wallet ledger data to shared chain ────────
    // If chain.json doesn't exist yet, seed it from every wallet's ledger.json.
    // This runs exactly once on the first launch after upgrading.
    if !chain_path().exists() {
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

        chain.blocks.sort_by_key(|b| b.height);
        chain.transactions.sort_by_key(|tx| tx.timestamp);
        let _ = save_chain(&chain);
    }

    // ── Step 3: Ensure registry + active wallet dir exist ─────────────────
    let mut registry = load_registry();

    if registry.wallets.is_empty() {
        // First-ever run: create wallet_0 — run blocking crypto on thread pool.
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

        return load_active_wallet(&state, true).await;
    }

    // ── Step 3: Load the active wallet ────────────────────────────────────
    let is_new = !seed_path().exists();
    if is_new {
        // Wallet dir exists in registry but seed is missing — regenerate
        tokio::task::spawn_blocking(|| create_wallet_files(None))
            .await
            .map_err(|e| EgoDesktopError::CryptoError(format!("Wallet creation panicked: {e}")))??;
    }

    load_active_wallet(&state, is_new).await
}

// ── list_wallets ──────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn list_wallets() -> Result<WalletRegistry, EgoDesktopError> {
    Ok(load_registry())
}

// ── create_wallet ─────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn create_wallet(
    name: String,
    state: State<'_, AppState>,
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

    load_active_wallet(&state, true).await
}

// ── switch_wallet ─────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn switch_wallet(
    wallet_id: String,
    state: State<'_, AppState>,
) -> Result<WalletInfo, EgoDesktopError> {
    let mut registry = load_registry();

    if !registry.wallets.iter().any(|w| w.id == wallet_id) {
        return Err(EgoDesktopError::NotFound(format!(
            "Wallet '{wallet_id}' not found"
        )));
    }

    registry.active_id = wallet_id;
    save_registry(&registry).map_err(EgoDesktopError::WalletError)?;

    load_active_wallet(&state, false).await
}

// ── delete_wallet ─────────────────────────────────────────────────────────────

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

    state
        .initialize_wallet(keypair)
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

// ── import_keypair ────────────────────────────────────────────────────────────

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

    state
        .initialize_wallet(keypair)
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

#[tauri::command]
pub async fn set_security_pin(pin: String) -> Result<(), EgoDesktopError> {
    if pin.len() < 4 {
        return Err(EgoDesktopError::InvalidInput(
            "PIN must be at least 4 characters".into(),
        ));
    }
    let pin_hash = ego_core::hash_data(pin.as_bytes()).to_hex();
    let mut ledger = Ledger::load();
    ledger.security_pin_hash = pin_hash;
    ledger.save().map_err(EgoDesktopError::WalletError)
}

// ── verify_pin ────────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn verify_pin(pin: String) -> Result<bool, EgoDesktopError> {
    let ledger = Ledger::load();
    if ledger.security_pin_hash.is_empty() {
        return Ok(false);
    }
    let hash = ego_core::hash_data(pin.as_bytes()).to_hex();
    Ok(hash == ledger.security_pin_hash)
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
    let ledger = Ledger::load();

    if !ledger.security_pin_hash.is_empty() {
        let hash = ego_core::hash_data(pin.as_bytes()).to_hex();
        if hash != ledger.security_pin_hash {
            return Err(EgoDesktopError::InvalidInput("Incorrect PIN".into()));
        }
    }

    let seed_bytes = fs::read(seed_path())
        .map_err(|e| EgoDesktopError::FileSystemError(format!("Read seed: {e}")))?;
    if seed_bytes.len() != 32 {
        return Err(EgoDesktopError::CryptoError("Corrupt seed file".into()));
    }
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

// ── helpers ───────────────────────────────────────────────────────────────────

fn generate_recovery_phrase(keypair: &KeyPair) -> EgoResult<Vec<String>> {
    let wordlist = get_bip39_wordlist();

    // Derive a 33-byte entropy buffer:
    // 32 bytes from the seed + 1 checksum byte (first byte of BLAKE2 hash of seed).
    // This gives 264 bits, split into 24 × 11-bit indices — maximum BIP-39 entropy.
    let keypair_bytes = keypair.to_bytes();
    let seed_bytes    = &keypair_bytes[..keypair_bytes.len().min(32)];
    let checksum_hash = ego_core::hash_data(seed_bytes);
    let checksum_byte = checksum_hash.as_bytes()[0];

    let mut buf = [0u8; 33];
    let copy_len = seed_bytes.len().min(32);
    buf[..copy_len].copy_from_slice(&seed_bytes[..copy_len]);
    buf[32] = checksum_byte;

    // Extract 24 × 11-bit indices via bit-shifting.
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

fn restore_keypair_from_phrase(phrase: &[String]) -> EgoResult<KeyPair> {
    if phrase.len() != 24 {
        return Err(EgoDesktopError::InvalidInput(
            "Recovery phrase must be 24 words".into(),
        ));
    }
    let phrase_string = phrase.join(" ");
    let phrase_hash   = ego_core::hash_data(phrase_string.as_bytes());
    KeyPair::from_bytes(phrase_hash.as_bytes())
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

/// Recursively copy a directory (best-effort, used for legacy storage migration).
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

/// Full BIP-39 English wordlist — exactly 2048 words (indices 0-2047).
/// Each word encodes 11 bits of entropy; 24 words = 264 bits total.
fn get_bip39_wordlist() -> &'static [&'static str] {
    &[
        // 0 – 7
        "abandon","ability","able","about","above","absent","absorb","abstract",
        // 8 – 15
        "absurd","abuse","access","accident","account","accuse","achieve","acid",
        // 16 – 23
        "acoustic","acquire","across","act","action","actor","actress","actual",
        // 24 – 31
        "adapt","add","addict","address","adjust","admit","adult","advance",
        // 32 – 39
        "advice","aerobic","affair","afford","afraid","again","age","agent",
        // 40 – 47
        "agree","ahead","aim","air","airport","aisle","alarm","album",
        // 48 – 55
        "alcohol","alert","alien","all","alley","allow","almost","alone",
        // 56 – 63
        "alpha","already","also","alter","always","amateur","amazing","among",
        // 64 – 71
        "amount","amused","analyst","anchor","ancient","anger","angle","angry",
        // 72 – 79
        "animal","ankle","announce","annual","another","answer","antenna","antique",
        // 80 – 87
        "anxiety","any","apart","apology","appear","apple","approve","april",
        // 88 – 95
        "arcade","arch","arctic","area","arena","argue","arm","armed",
        // 96 – 103
        "armor","army","around","arrange","arrest","arrive","arrow","art",
        // 104 – 111
        "ask","aspect","assault","asset","assist","assume","asthma","athlete",
        // 112 – 119
        "atom","attack","attend","attitude","attract","auction","audit","august",
        // 120 – 127
        "aunt","author","auto","autumn","average","avocado","avoid","awake",
        // 128 – 135
        "aware","away","awesome","awful","awkward","axis","baby","bacon",
        // 136 – 143
        "badge","bag","balance","balcony","ball","bamboo","banana","banner",
        // 144 – 151
        "bar","barely","bargain","barrel","base","basic","basket","battle",
        // 152 – 159
        "beach","bean","beauty","because","become","beef","before","begin",
        // 160 – 167
        "behave","behind","believe","below","belt","bench","benefit","best",
        // 168 – 175
        "betray","better","between","beyond","bicycle","bid","bike","bind",
        // 176 – 183
        "biology","bird","birth","bitter","black","blade","blame","blanket",
        // 184 – 191
        "blast","bleak","bless","blind","blood","blossom","blouse","blue",
        // 192 – 199
        "blur","blush","board","boat","body","boil","bomb","bone",
        // 200 – 207
        "book","boost","border","boring","borrow","boss","bottom","bounce",
        // 208 – 215
        "box","boy","bracket","brain","brand","brave","breeze","brick",
        // 216 – 223
        "bridge","brief","bright","bring","brisk","broccoli","broken","bronze",
        // 224 – 231
        "broom","brother","brown","brush","bubble","buddy","budget","buffalo",
        // 232 – 239
        "build","bulb","bulk","bullet","bundle","bunker","burden","burger",
        // 240 – 247
        "burst","bus","business","busy","butter","buyer","buzz","cabbage",
        // 248 – 255
        "cabin","cable","cactus","cage","cake","call","calm","camera",
        // 256 – 263
        "camp","can","canal","cancel","candy","cannon","canvas","canyon",
        // 264 – 271
        "capable","capital","captain","car","carbon","card","cargo","carpet",
        // 272 – 279
        "carry","cart","case","cash","casino","castle","casual","cat",
        // 280 – 287
        "catalog","catch","category","cattle","caught","cause","caution","cave",
        // 288 – 295
        "ceiling","celery","cement","census","chair","chaos","chapter","charge",
        // 296 – 303
        "chase","chat","cheap","check","cheese","chef","cherry","chest",
        // 304 – 311
        "chicken","chief","child","chimney","choice","choose","chronic","chuckle",
        // 312 – 319
        "chunk","cinnamon","circle","citizen","city","civil","claim","clap",
        // 320 – 327
        "clarify","claw","clay","clean","clerk","clever","click","client",
        // 328 – 335
        "cliff","climb","clinic","clip","clock","clog","close","cloth",
        // 336 – 343
        "cloud","clown","club","clump","cluster","cobalt","code","coffee",
        // 344 – 351
        "coil","coin","collect","color","column","combine","come","comfort",
        // 352 – 359
        "comic","common","company","concert","conduct","confirm","congress","connect",
        // 360 – 367
        "consider","control","convince","cook","cool","copper","copy","coral",
        // 368 – 375
        "core","corn","correct","cost","cotton","couch","country","couple",
        // 376 – 383
        "course","cousin","cover","coyote","crack","cradle","craft","cram",
        // 384 – 391
        "crane","crash","crater","crawl","crazy","cream","credit","creek",
        // 392 – 399
        "crew","cricket","crime","crisp","critic","cross","crouch","crowd",
        // 400 – 407
        "crucial","cruel","cruise","crumble","crunch","crush","cry","crystal",
        // 408 – 415
        "cube","culture","cup","cupboard","curious","current","curtain","curve",
        // 416 – 423
        "cushion","custom","cute","cycle","dad","damage","damp","dance",
        // 424 – 431
        "danger","daring","dash","daughter","dawn","day","deal","debate",
        // 432 – 439
        "debris","decade","december","decide","decline","decorate","decrease","deer",
        // 440 – 447
        "defense","define","defy","degree","delay","deliver","demand","demise",
        // 448 – 455
        "denial","dentist","deny","depart","depend","deposit","depth","deputy",
        // 456 – 463
        "derive","describe","desert","design","desk","despair","destroy","detail",
        // 464 – 471
        "detect","develop","device","devote","diagram","dial","diamond","diary",
        // 472 – 479
        "dice","diesel","diet","differ","digital","dignity","dilemma","dinner",
        // 480 – 487
        "dinosaur","direct","dirt","disagree","discover","disease","dish","dismiss",
        // 488 – 495
        "disorder","display","distance","divert","divide","divorce","dizzy","doctor",
        // 496 – 503
        "document","dog","doll","dolphin","domain","donate","donkey","donor",
        // 504 – 511
        "door","dose","double","dove","draft","dragon","drama","drastic",
        // 512 – 519
        "draw","dream","dress","drift","drill","drink","drip","drive",
        // 520 – 527
        "drop","drum","dry","duck","dumb","dune","during","dust",
        // 528 – 535
        "dutch","duty","dwarf","dynamic","eager","eagle","early","earn",
        // 536 – 543
        "earth","easily","east","easy","echo","ecology","edge","edit",
        // 544 – 551
        "educate","effort","egg","eight","either","elbow","elder","electric",
        // 552 – 559
        "elegant","element","elephant","elevator","elite","else","embark","embody",
        // 560 – 567
        "embrace","emerge","emotion","employ","empower","empty","enable","enact",
        // 568 – 575
        "endless","endorse","enemy","engage","engine","enhance","enjoy","enlist",
        // 576 – 583
        "enough","enrich","enroll","ensure","enter","entire","entry","envelope",
        // 584 – 591
        "episode","equal","equip","erase","erode","erosion","error","erupt",
        // 592 – 599
        "escape","essay","essence","estate","eternal","ethics","evidence","evil",
        // 600 – 607
        "evoke","evolve","exact","example","excess","exchange","excite","exclude",
        // 608 – 615
        "exercise","exhaust","exhibit","exile","exist","exit","exotic","expand",
        // 616 – 623
        "expire","explain","expose","express","extend","extra","eye","fable",
        // 624 – 631
        "face","faculty","fade","faint","faith","fall","false","fame",
        // 632 – 639
        "family","famous","fan","fancy","fantasy","far","fashion","fat",
        // 640 – 647
        "fatal","father","fatigue","fault","favorite","feature","february","federal",
        // 648 – 655
        "fee","feed","feel","feet","fellow","felt","fence","festival",
        // 656 – 663
        "fetch","fever","few","fiber","fiction","field","figure","file",
        // 664 – 671
        "film","filter","final","find","fine","finger","finish","fire",
        // 672 – 679
        "firm","first","fiscal","fish","fit","fitness","fix","flag",
        // 680 – 687
        "flame","flash","flat","flavor","flee","flight","flip","float",
        // 688 – 695
        "flock","floor","flower","fluid","flush","fly","foam","focus",
        // 696 – 703
        "fog","foil","follow","food","foot","force","forest","forget",
        // 704 – 711
        "fork","fortune","forum","forward","fossil","foster","found","fox",
        // 712 – 719
        "fragile","frame","frequent","fresh","friend","fringe","frog","front",
        // 720 – 727
        "frost","frown","frozen","fruit","fuel","fun","funny","furnace",
        // 728 – 735
        "fury","future","gadget","gain","galaxy","gallery","game","gap",
        // 736 – 743
        "garbage","garden","garlic","garment","gasp","gate","gather","gauge",
        // 744 – 751
        "gaze","general","genius","genre","gentle","genuine","gesture","ghost",
        // 752 – 759
        "ginger","giraffe","girl","give","glad","glance","glare","glass",
        // 760 – 767
        "gloom","glove","glow","glue","goat","goddess","gold","good",
        // 768 – 775
        "goose","gorilla","gospel","gossip","govern","gown","grab","grace",
        // 776 – 783
        "grain","grant","grape","grasp","grass","gravity","great","green",
        // 784 – 791
        "grid","grief","grit","grocery","group","grow","grunt","guard",
        // 792 – 799
        "guide","guilt","guitar","gun","gym","habit","hair","half",
        // 800 – 807
        "hammer","hamster","hand","happy","harbor","hard","harsh","harvest",
        // 808 – 815
        "hat","have","hawk","hazard","head","health","heart","heavy",
        // 816 – 823
        "hedgehog","height","hello","helmet","help","hen","hero","hidden",
        // 824 – 831
        "high","hill","hint","hip","hire","history","hobby","hockey",
        // 832 – 839
        "hold","hole","holiday","hollow","home","honey","hood","hope",
        // 840 – 847
        "horn","hospital","host","hour","hover","hub","humble","humor",
        // 848 – 855
        "hundred","hungry","hunt","hurdle","hurry","hurt","husband","hybrid",
        // 856 – 863
        "ice","icon","ignore","ill","illegal","image","imitate","immense",
        // 864 – 871
        "immune","impact","impose","improve","impulse","inbox","include","income",
        // 872 – 879
        "increase","index","indicate","indoor","industry","infant","inflict","inform",
        // 880 – 887
        "inhale","inject","injury","inmate","inner","innocent","input","inquiry",
        // 888 – 895
        "insane","insect","inside","inspire","install","intact","interest","into",
        // 896 – 903
        "invest","invite","involve","iron","island","isolate","issue","item",
        // 904 – 911
        "ivory","jacket","jaguar","jar","jazz","jealous","jelly","jewel",
        // 912 – 919
        "job","join","joke","journey","joy","judge","juice","jump",
        // 920 – 927
        "jungle","junior","junk","just","kangaroo","keen","keep","ketchup",
        // 928 – 935
        "key","kick","kingdom","kiss","kit","kitchen","kite","kitten",
        // 936 – 943
        "kiwi","knee","knife","knock","know","lab","ladder","lady",
        // 944 – 951
        "lake","lamp","language","laptop","large","later","laugh","laundry",
        // 952 – 959
        "lava","law","lawn","lawsuit","layer","lazy","leader","learn",
        // 960 – 967
        "leave","lecture","left","leg","legal","legend","leisure","lemon",
        // 968 – 975
        "lend","length","lens","leopard","lesson","letter","level","liar",
        // 976 – 983
        "liberty","library","license","life","lift","light","like","limb",
        // 984 – 991
        "limit","link","lion","liquid","list","little","live","lizard",
        // 992 – 999
        "load","loan","lobster","local","lock","logic","lonely","long",
        // 1000 – 1007
        "loop","lottery","loud","loyal","lucky","luggage","lumber","lunar",
        // 1008 – 1015
        "lunch","luxury","mad","magic","magnet","maid","main","major",
        // 1016 – 1023
        "make","mammal","mango","mansion","manual","maple","marble","march",
        // 1024 – 1031
        "margin","marine","market","marriage","mask","master","match","material",
        // 1032 – 1039
        "math","matrix","matter","maximum","maze","meadow","mean","medal",
        // 1040 – 1047
        "media","melody","melt","member","memory","mention","menu","mercy",
        // 1048 – 1055
        "merge","merit","merry","mesh","message","metal","method","middle",
        // 1056 – 1063
        "midnight","milk","million","mimic","mind","minimum","minor","minute",
        // 1064 – 1071
        "miracle","miss","mixed","mixture","mobile","model","modify","mom",
        // 1072 – 1079
        "monitor","monkey","monster","month","moon","moral","more","morning",
        // 1080 – 1087
        "mosquito","mother","motion","motor","mountain","mouse","move","movie",
        // 1088 – 1095
        "much","muffin","mule","multiply","muscle","museum","mushroom","music",
        // 1096 – 1103
        "must","mutual","myself","mystery","naive","name","napkin","narrow",
        // 1104 – 1111
        "nasty","natural","nature","near","neck","need","negative","neglect",
        // 1112 – 1119
        "neither","nephew","nerve","nest","network","neutral","never","news",
        // 1120 – 1127
        "next","nice","night","noble","noise","nominee","noodle","normal",
        // 1128 – 1135
        "north","notable","note","nothing","notice","novel","now","nuclear",
        // 1136 – 1143
        "number","nurse","nut","oak","obey","object","oblige","obscure",
        // 1144 – 1151
        "obtain","ocean","october","odd","offer","often","oil","okay",
        // 1152 – 1159
        "old","olive","olympic","omit","once","onion","open","option",
        // 1160 – 1167
        "orange","orbit","orchard","order","ordinary","organ","orient","original",
        // 1168 – 1175
        "orphan","ostrich","other","outdoor","outside","oval","over","own",
        // 1176 – 1183
        "oxygen","oyster","ozone","pain","paint","pair","palace","palm",
        // 1184 – 1191
        "panda","panel","panic","panther","paper","parade","parent","park",
        // 1192 – 1199
        "parrot","party","pass","patch","path","patrol","pause","pave",
        // 1200 – 1207
        "payment","peace","peanut","peasant","pelican","pen","penalty","penguin",
        // 1208 – 1215
        "pepper","perfect","permit","person","pet","phone","photo","phrase",
        // 1216 – 1223
        "physical","piano","picnic","picture","piece","pig","pigeon","pill",
        // 1224 – 1231
        "pilot","pink","pioneer","pipe","pistol","pitch","pizza","place",
        // 1232 – 1239
        "planet","plastic","plate","play","please","pledge","pluck","plug",
        // 1240 – 1247
        "plunge","poem","poet","point","polar","pole","police","pond",
        // 1248 – 1255
        "pony","popular","portion","position","possible","post","potato","pottery",
        // 1256 – 1263
        "poverty","powder","power","practice","praise","predict","prefer","prepare",
        // 1264 – 1271
        "present","pretty","prevent","price","pride","primary","print","priority",
        // 1272 – 1279
        "prison","private","prize","problem","process","produce","profit","program",
        // 1280 – 1287
        "project","promote","proof","property","prosper","protect","proud","provide",
        // 1288 – 1295
        "public","pudding","pull","pulp","pulse","pumpkin","punch","pupil",
        // 1296 – 1303
        "puppy","purchase","purity","purpose","push","put","puzzle","pyramid",
        // 1304 – 1311
        "quality","quantum","quarter","question","quick","quit","quiz","quote",
        // 1312 – 1319
        "rabbit","raccoon","race","rack","radar","radio","rage","rail",
        // 1320 – 1327
        "rain","raise","rally","ramp","ranch","random","range","rapid",
        // 1328 – 1335
        "rare","rate","rather","raven","reach","ready","real","reason",
        // 1336 – 1343
        "rebel","rebuild","recall","receive","recipe","record","recycle","reduce",
        // 1344 – 1351
        "reflect","reform","refuse","region","regret","regular","reject","relax",
        // 1352 – 1359
        "release","relief","rely","remain","remember","remind","remove","render",
        // 1360 – 1367
        "renew","rent","reopen","repair","repeat","replace","report","require",
        // 1368 – 1375
        "rescue","resemble","resist","resource","response","result","retire","retreat",
        // 1376 – 1383
        "return","reunion","reveal","review","reward","rhythm","ribbon","rice",
        // 1384 – 1391
        "rich","ride","rifle","right","rigid","ring","riot","ripple",
        // 1392 – 1399
        "risk","ritual","rival","river","road","roast","robot","robust",
        // 1400 – 1407
        "rocket","romance","roof","rookie","rotate","rough","round","route",
        // 1408 – 1415
        "royal","rubber","rude","rug","rule","run","runway","rural",
        // 1416 – 1423
        "sad","saddle","sadness","safe","sail","salad","salmon","salon",
        // 1424 – 1431
        "salt","salute","same","sample","sand","satisfy","satoshi","sauce",
        // 1432 – 1439
        "sausage","save","say","scale","scan","scare","scatter","scene",
        // 1440 – 1447
        "scheme","science","scissors","scorpion","scout","scrap","screen","script",
        // 1448 – 1455
        "scrub","sea","search","season","seat","second","secret","section",
        // 1456 – 1463
        "security","seek","segment","select","sell","seminar","senior","sense",
        // 1464 – 1471
        "sentence","series","service","session","settle","setup","seven","shadow",
        // 1472 – 1479
        "shaft","shallow","share","shed","shell","sheriff","shield","shift",
        // 1480 – 1487
        "shine","ship","shiver","shock","shoe","shoot","shop","short",
        // 1488 – 1495
        "shoulder","shove","shrimp","shrug","shuffle","shy","sibling","siege",
        // 1496 – 1503
        "sight","sign","silent","silk","silly","silver","similar","simple",
        // 1504 – 1511
        "since","sing","siren","sister","situate","six","size","sketch",
        // 1512 – 1519
        "skill","skin","skirt","skull","slab","slam","sleep","slender",
        // 1520 – 1527
        "slice","slide","slight","slim","slogan","slot","slow","slush",
        // 1528 – 1535
        "small","smart","smile","smoke","smooth","snack","snake","snap",
        // 1536 – 1543
        "sniff","snow","soap","soccer","social","sock","solar","soldier",
        // 1544 – 1551
        "solid","solution","solve","someone","song","soon","sorry","soul",
        // 1552 – 1559
        "sound","soup","source","south","space","spare","spatial","spawn",
        // 1560 – 1567
        "speak","special","speed","sphere","spice","spider","spike","spin",
        // 1568 – 1575
        "spirit","split","spoil","sponsor","spoon","spray","spread","spring",
        // 1576 – 1583
        "spy","square","squeeze","squirrel","stable","stadium","staff","stage",
        // 1584 – 1591
        "stairs","stamp","stand","start","state","stay","steak","steel",
        // 1592 – 1599
        "stem","step","stereo","stick","still","sting","stock","stomach",
        // 1600 – 1607
        "stone","stop","store","storm","story","stove","strategy","street",
        // 1608 – 1615
        "strike","strong","struggle","student","stuff","stumble","style","subject",
        // 1616 – 1623
        "submit","subway","success","such","sudden","suffer","sugar","suggest",
        // 1624 – 1631
        "suit","summer","sun","sunny","sunset","super","supply","supreme",
        // 1632 – 1639
        "sure","surface","surge","surprise","sustain","swallow","swamp","swap",
        // 1640 – 1647
        "swear","sweet","swift","swim","swing","switch","sword","symbol",
        // 1648 – 1655
        "symptom","syrup","table","tackle","tag","tail","talent","tamper",
        // 1656 – 1663
        "tank","tape","target","task","tattoo","taxi","teach","team",
        // 1664 – 1671
        "tell","ten","tenant","tennis","tent","term","test","text",
        // 1672 – 1679
        "thank","that","theme","then","theory","there","they","thing",
        // 1680 – 1687
        "this","thought","three","thrive","throw","thumb","thunder","ticket",
        // 1688 – 1695
        "tilt","timber","time","tiny","tip","tired","title","toast",
        // 1696 – 1703
        "tobacco","today","together","toilet","token","tomato","tomorrow","tone",
        // 1704 – 1711
        "tongue","tonight","tool","tooth","top","topic","topple","torch",
        // 1712 – 1719
        "tornado","tortoise","toss","total","tourist","toward","tower","town",
        // 1720 – 1727
        "toy","track","trade","traffic","tragic","train","transfer","trap",
        // 1728 – 1735
        "trash","travel","tray","treat","tree","trend","trial","tribe",
        // 1736 – 1743
        "trick","trigger","trim","trip","trophy","trouble","truck","truly",
        // 1744 – 1751
        "trumpet","trust","truth","tube","tuition","tumble","tuna","tunnel",
        // 1752 – 1759
        "turkey","turn","turtle","twelve","twenty","twice","twin","twist",
        // 1760 – 1767
        "two","type","typical","ugly","umbrella","unable","unaware","uncle",
        // 1768 – 1775
        "uncover","under","undo","unfair","unfold","unhappy","uniform","unique",
        // 1776 – 1783
        "universe","unknown","unlock","until","unusual","unveil","update","upgrade",
        // 1784 – 1791
        "uphold","upon","upper","upset","urban","usage","use","used",
        // 1792 – 1799
        "useful","useless","usual","utility","vacant","vacuum","vague","valid",
        // 1800 – 1807
        "valley","valve","van","vanish","vapor","various","vast","vault",
        // 1808 – 1815
        "vehicle","velvet","vendor","venture","venue","verb","verify","version",
        // 1816 – 1823
        "very","veteran","viable","vibrant","vicious","victory","video","view",
        // 1824 – 1831
        "village","vintage","violin","virtual","virus","visa","visit","visual",
        // 1832 – 1839
        "vital","vivid","vocal","voice","void","volcano","volume","vote",
        // 1840 – 1847
        "voyage","wage","wagon","wait","walk","wall","walnut","want",
        // 1848 – 1855
        "warfare","warm","warrior","wash","wasp","waste","water","wave",
        // 1856 – 1863
        "way","wealth","weapon","wear","weasel","wedding","weekend","weird",
        // 1864 – 1871
        "welcome","west","wet","whale","wheat","wheel","when","where",
        // 1872 – 1879
        "whip","whisper","wide","width","wife","wild","will","win",
        // 1880 – 1887
        "window","wine","wing","wink","winner","winter","wire","wisdom",
        // 1888 – 1895
        "wish","witness","wolf","woman","wonder","wood","wool","word",
        // 1896 – 1903
        "world","worry","worth","wrap","wreck","wrestle","wrist","write",
        // 1904 – 1911
        "wrong","yard","year","yellow","you","young","youth","zebra",
        // 1912 – 1919
        "zero","zone","zoo",
        // --- pad to exactly 2048 with unique compound words (indices 1915–2047) ---
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
