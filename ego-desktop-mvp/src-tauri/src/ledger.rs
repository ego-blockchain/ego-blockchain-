use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

// ── Directory helpers ─────────────────────────────────────────────────────────

/// Top-level EgoDesktop directory (not wallet-specific).
/// Override with `EGO_DATA_DIR` env var for multi-instance testing.
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
    crate::utils::atomic_write(&registry_path(), data.as_bytes()).map_err(|e| e.to_string())
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
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
    /// Hex-encoded Dilithium2 public key (1312 bytes = 2624 hex chars).
    /// Derives the egot1 address — proves quantum-safe ownership of the from address.
    #[serde(default)]
    pub dilithium_pubkey: String,
    /// Hex-encoded Dilithium2 detached signature (2420 bytes = 4840 hex chars).
    /// Signs the same canonical bytes as `signature` — quantum-safe proof of intent.
    #[serde(default)]
    pub dilithium_signature: String,
    /// TX type: "transfer" | "deploy" | "call"
    #[serde(default = "default_tx_type")]
    pub tx_type: String,
    /// Base fee paid in uEGOC. 100% burned (removed from supply permanently).
    #[serde(default)]
    pub fee_uegoc: u64,
    /// Priority (tip) fee in uEGOC — goes to the miner, not burned.
    /// Higher tip = earlier inclusion in next block (EIP-1559-style ordering).
    #[serde(default)]
    pub priority_fee_uegoc: u64,
    /// For deploy TXs: hex-encoded WASM bytecode
    #[serde(default)]
    pub wasm_code: String,
    /// For call TXs: target contract address (hex)
    #[serde(default)]
    pub contract_addr: String,
    /// For call TXs: entrypoint name
    #[serde(default)]
    pub entrypoint: String,
    /// For deploy/call TXs: ABI-encoded arguments (hex)
    #[serde(default)]
    pub call_args: String,
}

fn default_tx_type() -> String { "transfer".to_string() }

/// A local "block" produced whenever a transaction is confirmed.
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
    /// Coinbase TX hash — miner self-issues their block reward.
    #[serde(default)]
    pub coinbase_tx: Option<String>,
    /// Number of BFT validator votes this block collected.
    /// Fork choice: higher vote count wins when two blocks compete at the same height.
    #[serde(default)]
    pub vote_count: u32,
    /// Blake3 Merkle root of all TX hashes in this block.
    /// Light clients use this to verify TX inclusion without downloading full blocks.
    #[serde(default)]
    pub tx_merkle_root: String,
    /// Proof of Coverage VRF ticket — blake3(ed25519_sign(slot_seed)).
    /// Proves the miner won the slot lottery for this block.
    /// Empty on legacy blocks (accepted during transition).
    #[serde(default)]
    pub poc_ticket: String,
    /// Slot number this block was mined in (now_ms / BATCH_INTERVAL_MS).
    #[serde(default)]
    pub poc_slot: u64,
}

/// Metadata for an encrypted file stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
    // ── PoRep commitment fields (set at store_file time) ──────────────────────
    /// Merkle root of the encrypted file (hex). Empty for pre-PoRep files.
    #[serde(default)]
    pub comm_d: String,
    /// H(comm_d ‖ replica_id ‖ "ego/porep/v1") (hex).
    #[serde(default)]
    pub comm_r: String,
    /// Monotonically-increasing sector ID within this wallet.
    #[serde(default)]
    pub sector_id: u64,
    /// Number of real (non-padding) 1 KB leaves in the Merkle tree.
    #[serde(default)]
    pub n_real_leaves: usize,
    /// Next-power-of-two leaf count used by the tree builder.
    #[serde(default)]
    pub n_padded_leaves: usize,
    /// PoST status: "" | "registered" | "challenged" | "proved" | "faulted"
    #[serde(default)]
    pub post_status: String,
    /// Unix timestamp of the most recent successful PoST proof.
    #[serde(default)]
    pub last_proved: Option<i64>,
    // ── Block-storage fields (IPFS-style, set for egomfd1 files) ─────────────
    /// Manifest CID (`egomfd1…`). Empty for legacy single-blob files.
    #[serde(default)]
    pub manifest_cid: String,
    /// Total 256 KB blocks in this file's manifest.  0 = legacy.
    #[serde(default)]
    pub blocks_total: u32,
    /// How many blocks have been downloaded to disk so far.
    #[serde(default)]
    pub blocks_received: u32,
    /// Addresses of peers that have confirmed pinning this file (replication tracking).
    /// Populated when a PinAck { accepted: true } is received for this CID.
    #[serde(default)]
    pub replica_peers: Vec<String>,
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
    /// Registered user name (set during onboarding).
    #[serde(default)]
    pub registered_name: String,
    /// Registered email (set during onboarding, used for TX confirmations).
    #[serde(default)]
    pub registered_email: String,
    /// Total uEGOC burned as tx fees by this wallet (lifetime).
    #[serde(default)]
    pub total_burned_uegoc: u64,
    /// Validator slash strike count (0 = clean). Resets after 30 clean days.
    #[serde(default)]
    pub slash_strikes: u32,
    /// Unix timestamp of last slash event (for 30-day reset window).
    #[serde(default)]
    pub last_slash_ts: Option<i64>,
    /// Whether this validator has been permanently banned via slashing.
    #[serde(default)]
    pub slash_banned: bool,
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
        crate::utils::atomic_write(&ledger_path(), data.as_bytes()).map_err(|e| e.to_string())
    }

    pub fn mine_block(&mut self, tx_hash: &str, miner: &str) {
        let prev_hash = self
            .blocks
            .last()
            .map(|b| b.hash.clone())
            .unwrap_or_else(|| GENESIS_HASH.into());

        let height = self.blocks.len() as u64;
        let timestamp = chrono::Utc::now().timestamp();

        let block_data = format!("{prev_hash}{tx_hash}{height}{timestamp}");
        let hash = ego_core::hash_data(block_data.as_bytes()).to_hex();

        // Burn any fees from transactions being confirmed in this block
        for tx in self.transactions.iter_mut() {
            if tx.hash == tx_hash && tx.status == "Pending" {
                tx.status = "Confirmed".to_string();
                tx.block_height = Some(height);
                // Accumulate burned fees (100% of tx fee is destroyed)
                self.total_burned_uegoc = self.total_burned_uegoc.saturating_add(tx.fee_uegoc);
            }
        }

        let reward = crate::tokenomics::block_reward_at(height);
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
        });
    }

    pub fn format_balance(&self) -> String {
        let egoc = self.balance_uegoc as f64 / 1_000_000.0;
        format!("{:.2} EGOC", egoc)
    }
}

const INITIAL_BLOCK_REWARD_UEGOC: u64 = 50_000_000;
const HALVING_INTERVAL:           u64 = 2_100_000;
const FAUCET_ADDRESS: &str            = "egot1faucet000000000000000000000000000000000000";

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

/// Directory where contract WASM code and state are stored.
pub fn contracts_dir() -> PathBuf {
    let dir = base_data_dir().join("contracts");
    let _ = fs::create_dir_all(&dir);
    dir
}

pub const GENESIS_HASH: &str  = "ego00000000000000000000000000000000000000000000000000000000genesis1";
pub const GENESIS_MINER: &str = "ego1genesis000000000000000000000000000000000000";
pub const GENESIS_TS: i64     = 1_741_910_400; // 2026-03-14 00:00:00 UTC

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
    }
}

pub fn load_chain() -> SharedChain {
    crate::chain_db::load_shared_chain()
}

/// No-op: chain is now persisted by chain_db (SQLite WAL).
/// Kept for backward-compat call sites that still call save_chain().
pub fn save_chain(_chain: &SharedChain) -> Result<(), String> {
    // Chain is persisted directly by chain_db::mine_batch_db().
    // This stub exists so existing callers compile without changes.
    Ok(())
}

impl SharedChain {
    /// Compute the confirmed balance of an address from the chain.
    /// balance = Σ incoming confirmed txs − Σ outgoing confirmed txs
    pub fn balance_of(&self, address: &str) -> u64 {
        crate::chain_db::balance_of(address)
    }

    /// Mine a new block on the shared chain, confirming the given tx and
    /// "broadcasting" the result to all wallets that read chain.json.
    pub fn mine_block(&mut self, tx_hash: &str, miner: &str) {
        let prev_hash = self
            .blocks
            .last()
            .map(|b| b.hash.clone())
            .unwrap_or_else(|| GENESIS_HASH.into());

        let height = self.blocks.len() as u64;
        let timestamp = chrono::Utc::now().timestamp();

        // Coinbase TX — miner self-issues the block reward (halving schedule)
        let era = height / HALVING_INTERVAL;
        let block_reward = INITIAL_BLOCK_REWARD_UEGOC >> era.min(63);
        let cb_nonce = self.last_nonce(miner) + 1;
        let cb_data = format!("coinbase:{miner}:{height}:{block_reward}:{timestamp}");
        let cb_hash = ego_core::hash_data(cb_data.as_bytes()).to_hex();
        let coinbase = LedgerTx {
            hash:                cb_hash.clone(),
            from:                FAUCET_ADDRESS.into(),
            to:                  miner.into(),
            amount:              block_reward,
            memo:                Some(format!("block reward height={height} era={era}")),
            timestamp,
            signature:           String::new(),
            status:              "Confirmed".to_string(),
            nonce:               cb_nonce,
            block_height:        Some(height),
            public_key_ed25519:  String::new(),
            dilithium_pubkey:    String::new(),
            dilithium_signature: String::new(),
            ..LedgerTx::default()
        };
        self.transactions.push(coinbase);

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
            tx_count: 2, // coinbase + user tx
            size_bytes: 512,
            reward: block_reward,
            coinbase_tx: Some(cb_hash),
            vote_count: 0,
            tx_merkle_root: String::new(),
            poc_ticket: String::new(),
            poc_slot: 0,
        });
    }

    /// Mine one block containing an entire batch of transactions.
    ///
    /// This is the high-throughput path used by the mempool batch loop.
    /// Instead of one block per TX (legacy path), we pack up to 2,000 TXs
    /// into a single block → one disk write per batch → ~100k TPS.
    pub fn mine_batch(&mut self, txs: &[LedgerTx], miner: &str) -> LedgerBlock {
        let prev_hash  = self.blocks.last()
            .map(|b| b.hash.clone())
            .unwrap_or_else(|| GENESIS_HASH.into());
        let height    = self.blocks.len() as u64;
        let timestamp = chrono::Utc::now().timestamp();

        // Block hash = H(prev_hash ‖ all_tx_hashes ‖ height ‖ ts)
        let tx_root: String = txs.iter().map(|t| t.hash.as_str()).collect::<Vec<_>>().join(":");
        let block_data = format!("{prev_hash}:{tx_root}:{height}:{timestamp}");
        let hash = ego_core::hash_data(block_data.as_bytes()).to_hex();

        // Coinbase TX — halving-aware block reward
        let era          = height / HALVING_INTERVAL;
        let block_reward = INITIAL_BLOCK_REWARD_UEGOC >> era.min(63);
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

        // Confirm all TXs in this batch
        let tx_count = txs.len() as u32;
        for tx in txs {
            // If already in chain (re-broadcast), upgrade status; otherwise insert.
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
            tx_count:   tx_count + 1, // +1 for coinbase
            size_bytes: txs.iter().map(|t| t.hash.len() as u64 + 512).sum(),
            reward:     block_reward,
            coinbase_tx: Some(cb_hash),
            vote_count: 0,
            tx_merkle_root: String::new(),
            poc_ticket: String::new(),
            poc_slot: 0,
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
    crate::utils::atomic_write(&poc_events_path(), data.as_bytes()).map_err(|e| e.to_string())
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

// ── Per-address nonce store ───────────────────────────────────────────────────
// Tracks the highest confirmed nonce seen per sender address.
// Incoming TXs with nonce ≤ last_nonce are replays and are rejected.

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

// ── Validator stake tracker ────────────────────────────────────────────────────
// Populated from confirmed stake/unstake TXs in write_block_batch.
// Used by p2p to gate validator registration (minimum stake required).

static STAKE_STORE: OnceCell<Mutex<HashMap<String, u64>>> = OnceCell::new();

fn stake_store() -> std::sync::MutexGuard<'static, HashMap<String, u64>> {
    STAKE_STORE.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap()
}

/// Record a staking or unstaking TX being confirmed.
/// `is_stake=true` adds to staked balance; `false` subtracts.
pub fn record_validator_stake(addr: &str, amount: u64, is_stake: bool) {
    if addr.is_empty() { return; }
    let mut store = stake_store();
    let cur = store.entry(addr.to_string()).or_insert(0);
    if is_stake { *cur = cur.saturating_add(amount); }
    else        { *cur = cur.saturating_sub(amount); }
}

/// Returns the tracked staked balance (uEGOC) for an address.
pub fn get_validator_stake(addr: &str) -> u64 {
    *stake_store().get(addr).unwrap_or(&0)
}

// ── Incoming TX validation ────────────────────────────────────────────────────

/// Validate an incoming peer transaction.
///
/// Checks (in order):
///   1. System / faucet TXs are accepted without a signature.
///   2. Nonce must be strictly greater than the last confirmed nonce for `from`
///      (prevents replay attacks).
///   3. Ed25519 signature over canonical tx bytes must verify against the
///      sender's public key embedded in the TX.
///
/// Returns `Ok(())` on success, `Err(reason)` on rejection.
pub fn verify_incoming_tx(tx: &LedgerTx) -> Result<(), String> {
    const SYSTEM_ADDRS: &[&str] = &[
        "egot1faucet000000000000000000000000000000000000",
        "ego1genesis000000000000000000000000000000000000",
        "egot1staking00000000000000000000000000000000000",
        "egot1system000000000000000000000000000000000000",
        "egot1coverage0000000000000000000000000000000000",
        "egot1nodereward000000000000000000000000000000000",
    ];

    // System / coinbase TXs have no signature — always accept.
    if SYSTEM_ADDRS.iter().any(|a| *a == tx.from) || tx.from.is_empty() {
        return Ok(());
    }

    // 1. Nonce replay check.
    let last = last_confirmed_nonce(&tx.from);
    if tx.nonce <= last {
        return Err(format!(
            "replay: nonce {} <= last confirmed {} for {}",
            tx.nonce, last, tx.from
        ));
    }

    // 2. Ed25519 signature check.
    if tx.public_key_ed25519.is_empty() || tx.signature.is_empty() {
        return Err(format!("missing signature or pubkey in TX from {}", tx.from));
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

    let msg = tx_signing_bytes(&tx.from, &tx.to, tx.amount, tx.nonce, tx.timestamp);
    vk.verify(&msg, &sig)
        .map_err(|_| format!("signature verification failed for TX from {}", tx.from))?;

    Ok(())
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
