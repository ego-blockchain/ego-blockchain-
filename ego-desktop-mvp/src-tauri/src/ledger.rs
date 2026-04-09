use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

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

/// Load the wallet seed, decrypting it with OS DPAPI if it was previously protected.
pub fn load_seed() -> Option<Vec<u8>> {
    let raw = fs::read(seed_path()).ok()?;
    let bytes = crate::utils::os_unprotect(&raw);
    if bytes.len() == 32 { Some(bytes) } else { None }
}

/// Save the wallet seed, encrypting it with OS DPAPI before writing.
pub fn save_seed(seed: &[u8]) -> std::io::Result<()> {
    let protected = crate::utils::os_protect(seed);
    crate::utils::atomic_write(&seed_path(), &protected)
}

/// Encode a raw AES key (as hex) for at-rest storage using OS DPAPI.
/// Stored format: `"prot:{base64_of_dpapi_blob}"`.
/// On non-Windows, returns the plain hex unchanged (os_protect is a passthrough).
pub fn protect_key_hex(raw_hex: &str) -> String {
    match hex::decode(raw_hex) {
        Ok(bytes) => {
            let blob = crate::utils::os_protect(&bytes);
            use base64::Engine as _;
            format!("prot:{}", base64::engine::general_purpose::STANDARD.encode(&blob))
        }
        Err(_) => raw_hex.to_string(),
    }
}

/// Decode a stored key back to raw bytes.
/// Handles both the `"prot:{base64}"` format written by `protect_key_hex`
/// and legacy plaintext hex (for wallets created before this change).
pub fn unprotect_key_bytes(stored: &str) -> Vec<u8> {
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

        for tx in self.transactions.iter_mut() {
            if tx.hash == tx_hash && tx.status == "Pending" {
                tx.status = "Confirmed".to_string();
                tx.block_height = Some(height);

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

pub const GENESIS_HASH: &str  = "ego00000000000000000000000000000000000000000000000000000000genesis1";
pub const GENESIS_MINER: &str = "ego1genesis000000000000000000000000000000000000";
pub const GENESIS_TS: i64     = 1_741_910_400;

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
            reward: 0,
            coinbase_tx: None,
            vote_count: 0,
            tx_merkle_root: String::new(),
            poc_ticket: String::new(),
            poc_slot: 0,
        });
    }

    pub fn mine_batch(&mut self, txs: &[LedgerTx], miner: &str) -> LedgerBlock {
        let prev_hash  = self.blocks.last()
            .map(|b| b.hash.clone())
            .unwrap_or_else(|| GENESIS_HASH.into());
        let height    = self.blocks.len() as u64;
        let timestamp = chrono::Utc::now().timestamp();

        let tx_root: String = txs.iter().map(|t| t.hash.as_str()).collect::<Vec<_>>().join(":");
        let block_data = format!("{prev_hash}:{tx_root}:{height}:{timestamp}");
        let hash = ego_core::hash_data(block_data.as_bytes()).to_hex();

        let block_reward = crate::tokenomics::block_reward_at(height);
        let era          = height / crate::tokenomics::HALVING_INTERVAL;
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
    stake_store().values().sum()
}

/// Number of addresses with non-zero stake (each is a potential validator).
pub fn active_validator_count() -> usize {
    stake_store().values().filter(|&&s| s > 0).count()
}

pub fn verify_incoming_tx(tx: &LedgerTx) -> Result<(), String> {
    verify_incoming_tx_with_miner(tx, "")
}

/// Full verification. When `block_miner` is non-empty, system-address transactions
/// are only accepted if they are crediting the miner (protocol rewards to self).
/// This closes the free-mint exploit where any node crafts `from=faucet → to=self`.
pub fn verify_incoming_tx_with_miner(tx: &LedgerTx, block_miner: &str) -> Result<(), String> {
    const SYSTEM_ADDRS: &[&str] = &[
        "egot1faucet000000000000000000000000000000000000",
        "ego1genesis000000000000000000000000000000000000",
        "egot1staking00000000000000000000000000000000000",
        "egot1system000000000000000000000000000000000000",
        "egot1coverage0000000000000000000000000000000000",
        "egot1nodereward000000000000000000000000000000000",
        "egot1collateral000000000000000000000000000000",
        "egot1slashpool0000000000000000000000000000000",
        "egot1storagefees000000000000000000000000000000",
        "egot1burn0000000000000000000000000000000000000",
    ];

    if tx.from.is_empty() {
        return Ok(());
    }

    if SYSTEM_ADDRS.iter().any(|a| *a == tx.from) {
        // System-to-system is always fine (e.g. staking contract returning funds).
        if SYSTEM_ADDRS.iter().any(|a| *a == tx.to) {
            return Ok(());
        }
        // System → user: only accept if the recipient is the block miner (protocol reward).
        if !block_miner.is_empty() && tx.to != block_miner {
            return Err(format!(
                "system tx from {} to {} rejected — recipient is not block miner {}",
                tx.from, tx.to, block_miner
            ));
        }
        return Ok(());
    }

    // ── Fee floor ─────────────────────────────────────────────────────────
    // Reject zero-fee transactions from accounts that haven't staked.
    // Stakers (≥ MIN_STAKE_FREE_TX_UEGOC) get free transactions as a reward
    // for securing the network. Everyone else must pay the minimum fee.
    // This prevents mempool spam: flooding with free txs now costs real money.
    let staked = get_validator_stake(&tx.from);
    if staked < crate::tokenomics::MIN_STAKE_FREE_TX_UEGOC
        && tx.fee_uegoc < crate::tokenomics::FEE_FLOOR_UEGOC
    {
        return Err(format!(
            "tx from {} rejected: fee {} uEGOC below floor {} uEGOC (stake {} to send free)",
            tx.from, tx.fee_uegoc,
            crate::tokenomics::FEE_FLOOR_UEGOC,
            crate::tokenomics::MIN_STAKE_FREE_TX_UEGOC,
        ));
    }

    let last = last_confirmed_nonce(&tx.from);
    if tx.nonce <= last {
        return Err(format!(
            "replay: nonce {} <= last confirmed {} for {}",
            tx.nonce, last, tx.from
        ));
    }

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
    let dilithium_disabled = crate::chain_db::is_feature_disabled(
        crate::chain_db::FEATURE_DILITHIUM_DISABLED,
    );
    let dilithium_required = crate::chain_db::is_feature_enabled(
        crate::chain_db::FEATURE_DILITHIUM_REQUIRED,
    );

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
