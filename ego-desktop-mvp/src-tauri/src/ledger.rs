use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

// ── Directory helpers ─────────────────────────────────────────────────────────

/// Top-level EgoDesktop directory (not wallet-specific).
pub fn base_data_dir() -> PathBuf {
    let dir = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("EgoDesktop");
    let _ = fs::create_dir_all(&dir);
    dir
}

/// Per-wallet directory: base / wallet_id.
pub fn wallet_dir(wallet_id: &str) -> PathBuf {
    let dir = base_data_dir().join(wallet_id);
    let _ = fs::create_dir_all(&dir);
    dir
}

pub fn registry_path() -> PathBuf {
    base_data_dir().join("wallets.json")
}

/// Returns the current active wallet ID, defaulting to "wallet_0".
pub fn get_active_wallet_id() -> String {
    let id = load_registry().active_id;
    if id.trim().is_empty() { "wallet_0".to_string() } else { id }
}

/// Returns the data directory for the currently active wallet.
/// This makes ALL other path helpers (seed_path, ledger_path, storage_dir)
/// automatically scope to the right wallet.
pub fn data_dir() -> PathBuf {
    wallet_dir(&get_active_wallet_id())
}

pub fn storage_dir() -> PathBuf {
    let dir = data_dir().join("storage");
    let _ = fs::create_dir_all(&dir);
    dir
}

pub fn seed_path() -> PathBuf {
    data_dir().join("wallet.seed")
}

pub fn ledger_path() -> PathBuf {
    data_dir().join("ledger.json")
}

// ── Wallet registry ───────────────────────────────────────────────────────────

/// Metadata for one wallet, stored in wallets.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletEntry {
    pub id: String,
    pub name: String,
    /// Bech32 address — cached here so the switcher UI doesn't need to load every ledger.
    pub address: String,
    pub created_at: i64,
}

/// The wallets.json registry — one per installation.
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
    let path = registry_path();
    if let Ok(data) = fs::read_to_string(&path) {
        if let Ok(reg) = serde_json::from_str::<WalletRegistry>(&data) {
            return reg;
        }
    }
    WalletRegistry::default()
}

pub fn save_registry(registry: &WalletRegistry) -> Result<(), String> {
    let data = serde_json::to_string_pretty(registry).map_err(|e| e.to_string())?;
    fs::write(registry_path(), data).map_err(|e| e.to_string())
}

/// Returns the next wallet id string (e.g. "wallet_3" after "wallet_0","wallet_2").
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

// ── Ledger structs ────────────────────────────────────────────────────────────

/// A single signed transaction in the local ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerTx {
    pub hash: String,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub memo: Option<String>,
    pub timestamp: i64,
    /// Hex-encoded Ed25519 signature over canonical tx bytes.
    pub signature: String,
    pub status: String,
    pub block_height: Option<u64>,
    #[serde(default)]
    pub nonce: u64,
    /// Hex-encoded Ed25519 public key of the sender — required for relay-side verification.
    #[serde(default)]
    pub public_key_ed25519: String,
}

/// A local "block" produced whenever a transaction is confirmed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerBlock {
    pub height: u64,
    pub hash: String,
    pub prev_hash: String,
    pub timestamp: i64,
    pub miner: String,
    pub tx_count: u32,
    pub size_bytes: u64,
    pub reward: u64,
}

/// Metadata for an encrypted file stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredFile {
    pub cid: String,
    pub name: String,
    pub original_size: u64,
    pub encrypted_size: u64,
    pub duration_months: u32,
    pub stored_at: i64,
    pub expiry: i64,
    pub status: String, // "Active" | "Expired" | "Received"
    pub key_nonce_hex: String,
    pub local_path: String,
    #[serde(default)]
    pub owner: String,
}

/// The complete local wallet state, persisted to JSON.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Ledger {
    pub address: String,
    pub balance_uegoc: u64,
    pub nonce: u64,
    pub transactions: Vec<LedgerTx>,
    pub blocks: Vec<LedgerBlock>,
    pub stored_files: Vec<StoredFile>,
    #[serde(default)]
    pub storage_allocated_bytes: u64,
    #[serde(default)]
    pub security_pin_hash: String,
    #[serde(default)]
    pub staked_amount: u64,
    #[serde(default)]
    pub staked_at: Option<i64>,
    #[serde(default)]
    pub stake_lock_days: u32,
    #[serde(default)]
    pub unstake_at: Option<i64>,
}

impl Ledger {
    pub fn load() -> Self {
        let path = ledger_path();
        if let Ok(data) = fs::read_to_string(&path) {
            if let Ok(ledger) = serde_json::from_str::<Self>(&data) {
                return ledger;
            }
        }
        Self::default()
    }

    pub fn save(&self) -> Result<(), String> {
        let data = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(ledger_path(), data).map_err(|e| e.to_string())
    }

    pub fn mine_block(&mut self, tx_hash: &str, miner: &str) {
        let prev_hash = self
            .blocks
            .last()
            .map(|b| b.hash.clone())
            .unwrap_or_else(|| "0".repeat(64));

        let height = self.blocks.len() as u64;
        let timestamp = chrono::Utc::now().timestamp();

        let block_data = format!("{prev_hash}{tx_hash}{height}{timestamp}");
        let hash = ego_core::hash_data(block_data.as_bytes()).to_hex();

        for tx in self.transactions.iter_mut() {
            if tx.hash == tx_hash && tx.status == "Pending" {
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
            reward: 50_000_000,
        });
    }

    pub fn format_balance(&self) -> String {
        let egoc = self.balance_uegoc as f64 / 1_000_000.0;
        format!("{:.2} EGOC", egoc)
    }
}

// ── Shared chain (P2P broadcast ledger) ──────────────────────────────────────

/// The single shared blockchain — lives at `EgoDesktop/chain.json`.
/// Every local wallet reads from and writes to this file, simulating the
/// "broadcast to all nodes" step in a real P2P network.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SharedChain {
    pub blocks: Vec<LedgerBlock>,
    pub transactions: Vec<LedgerTx>,
}

pub fn chain_path() -> PathBuf {
    base_data_dir().join("chain.json")
}

pub fn load_chain() -> SharedChain {
    let path = chain_path();
    if let Ok(data) = fs::read_to_string(&path) {
        if let Ok(chain) = serde_json::from_str::<SharedChain>(&data) {
            return chain;
        }
    }
    SharedChain::default()
}

pub fn save_chain(chain: &SharedChain) -> Result<(), String> {
    let data = serde_json::to_string_pretty(chain).map_err(|e| e.to_string())?;
    fs::write(chain_path(), data).map_err(|e| e.to_string())
}

impl SharedChain {
    /// Compute the confirmed balance of an address from the chain.
    /// balance = Σ incoming confirmed txs − Σ outgoing confirmed txs
    pub fn balance_of(&self, address: &str) -> u64 {
        let incoming: u64 = self
            .transactions
            .iter()
            .filter(|tx| tx.to.trim() == address.trim() && tx.status == "Confirmed")
            .map(|tx| tx.amount)
            .sum();
        let outgoing: u64 = self
            .transactions
            .iter()
            .filter(|tx| tx.from.trim() == address.trim() && tx.status == "Confirmed")
            .map(|tx| tx.amount)
            .sum();
        incoming.saturating_sub(outgoing)
    }

    /// Mine a new block on the shared chain, confirming the given tx and
    /// "broadcasting" the result to all wallets that read chain.json.
    pub fn mine_block(&mut self, tx_hash: &str, miner: &str) {
        let prev_hash = self
            .blocks
            .last()
            .map(|b| b.hash.clone())
            .unwrap_or_else(|| "0".repeat(64));

        let height = self.blocks.len() as u64;
        let timestamp = chrono::Utc::now().timestamp();

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
            reward: 50_000_000,
        });
    }
}

// ── PoC Event log ─────────────────────────────────────────────────────────────

/// A single Proof-of-Coverage beacon event, persisted to poc_events.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PocEvent {
    pub id: u64,
    pub timestamp: i64,
    pub quality: String,   // "Excellent" | "Good" | "Fair" | "Poor"
    pub peers: u32,        // witness count
    pub reward_uegoc: u64, // per-event reward (22_222 ≈ 0.022 EGOC)
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
    fs::write(poc_events_path(), data).map_err(|e| e.to_string())
}

// ── Canonical signing helpers ─────────────────────────────────────────────────

/// Canonical bytes to sign for a PoC coverage event (must match relay exactly).
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

/// Canonical bytes to sign for a transaction.
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
