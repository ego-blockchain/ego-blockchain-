use crate::error::EgoResult;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::sync::OnceLock;
use ego_core::{Address, KeyPair};
use std::collections::HashMap;

static GLOBAL_APP_STATE: OnceLock<Arc<AppState>> = OnceLock::new();

pub fn global_app_state() -> Arc<AppState> {
    GLOBAL_APP_STATE.get_or_init(|| Arc::new(AppState::new())).clone()
}

pub fn init_global_app_state(state: Arc<AppState>) {
    let _ = GLOBAL_APP_STATE.set(state);
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PeerInfo {
    pub address:   String,
    pub name:      String,
    #[serde(skip_serializing)] // Privacy: Never expose raw IPs/Endpoints to the UI
    pub endpoint:  String,
    pub last_seen: i64,
    #[serde(default)]
    pub city:    Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub lat: Option<f64>,
    #[serde(default)]
    pub lon: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct AppState {
    pub keypair: Arc<Mutex<Option<KeyPair>>>,
    pub wallet_address: Arc<Mutex<Option<Address>>>,
    pub is_initialized: Arc<Mutex<bool>>,
    pub settings: Arc<Mutex<AppSettings>>,
    pub cache: Arc<Mutex<AppCache>>,

    pub session_started: Arc<Mutex<i64>>,

    pub last_earnings_credit: Arc<Mutex<i64>>,

    /// Running total of confirmed reward TXs — updated only when a new credit is issued,
    /// avoiding an O(n) full-chain scan on every 30-second poll.
    pub cached_total_earned: Arc<Mutex<u64>>,

    pub peers: Arc<Mutex<HashMap<String, PeerInfo>>>,

    pub upnp_status: Arc<Mutex<Option<Result<(), String>>>>,

    pub public_endpoint: Arc<Mutex<String>>,

    pub pending_chat_address: Arc<Mutex<Option<String>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub auto_start: bool,
    pub minimize_to_tray: bool,
    pub notifications_enabled: bool,
    pub theme: String,
    pub language: String,
    pub storage_path: String,
    pub testnet_mode: bool,
    pub coverage_simulation: bool,
}

#[derive(Debug, Clone)]
pub struct AppCache {
    pub balance: Option<u64>,
    pub transaction_history: Vec<TransactionInfo>,
    pub coverage_status: Option<CoverageStatus>,
    pub storage_metrics: Option<StorageMetrics>,
    pub earnings_data: Option<EarningsData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionInfo {
    pub hash: String,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub memo: Option<String>,
    pub timestamp: i64,
    pub status: TransactionStatus,
    pub block_height: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionStatus {
    Pending,
    Confirmed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageStatus {
    pub location: Option<Location>,
    pub coverage_synced_count: u32,
    pub last_coverage_event: Option<i64>,
    pub is_online: bool,
    pub network_quality: NetworkQuality,

    #[serde(default)]
    pub vpn_detected: bool,

    #[serde(default)]
    pub vpn_reason: String,

    #[serde(default)]
    pub machine_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub latitude: f64,
    pub longitude: f64,
    pub accuracy: Option<f64>,
    pub altitude: Option<f64>,
    pub city: Option<String>,
    pub region: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkQuality {
    Excellent,
    Good,
    Fair,
    Poor,
    Offline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageMetrics {
    pub space_used_bytes: u64,
    pub space_available_bytes: u64,
    pub availability_status: AvailabilityStatus,
    pub last_post_pass: Option<PostProof>,
    pub encrypted_files_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AvailabilityStatus {
    Online,
    Offline,
    Syncing,
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostProof {
    pub timestamp: i64,
    pub latency_ms: u32,
    pub sector_count: u32,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EarningsData {
    pub daily_rewards: u64,
    pub epoch_rewards: u64,
    pub total_earned: u64,
    pub drs_multiplier: f64,
    pub reward_breakdown: RewardBreakdown,
    pub pending_rewards: u64,

    pub session_started: i64,

    pub coverage_online: bool,

    /// Unix timestamp until which rewards are suspended due to a storage reduction penalty.
    /// None = no penalty active.
    pub reward_suspended_until: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardBreakdown {
    pub storage_rewards: u64,
    pub consensus_rewards: u64,
    pub coverage_rewards: u64,
    pub retrieval_rewards: u64,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            auto_start: true,
            minimize_to_tray: true,
            notifications_enabled: true,
            theme: "dark".to_string(),
            language: "en".to_string(),
            storage_path: dirs::data_local_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("EgoDesktop")
                .to_string_lossy()
                .to_string(),
            testnet_mode: true,
            coverage_simulation: true,
        }
    }
}

impl Default for AppCache {
    fn default() -> Self {
        Self {
            balance: None,
            transaction_history: Vec::new(),
            coverage_status: None,
            storage_metrics: None,
            earnings_data: None,
        }
    }
}

impl AppState {
    pub fn new() -> Self {
        Self {
            keypair: Arc::new(Mutex::new(None)),
            wallet_address: Arc::new(Mutex::new(None)),
            is_initialized: Arc::new(Mutex::new(false)),
            settings: Arc::new(Mutex::new(AppSettings::default())),
            cache: Arc::new(Mutex::new(AppCache::default())),
            session_started: Arc::new(Mutex::new(0)),
            last_earnings_credit: Arc::new(Mutex::new(0)),
            cached_total_earned:  Arc::new(Mutex::new(0)),
            peers: Arc::new(Mutex::new(HashMap::new())),
            upnp_status: Arc::new(Mutex::new(None)),
            public_endpoint: Arc::new(Mutex::new(String::new())),
            pending_chat_address: Arc::new(Mutex::new(None)),
        }
    }

    pub fn set_upnp_status(&self, result: Result<(), String>) {
        *self.upnp_status.lock().unwrap() = Some(result);
    }

    pub fn set_public_endpoint(&self, endpoint: String) {
        *self.public_endpoint.lock().unwrap() = endpoint;
    }

    pub fn get_upnp_status(&self) -> Option<Result<(), String>> {
        self.upnp_status.lock().unwrap().clone()
    }

    pub fn get_public_endpoint(&self) -> String {
        self.public_endpoint.lock().unwrap().clone()
    }

    pub fn upsert_peer(&self, info: PeerInfo) {
        let mut peers = self.peers.lock().unwrap();
        peers.insert(info.address.clone(), info);
    }

    pub fn get_active_peers(&self, window_secs: i64) -> Vec<PeerInfo> {
        let peers  = self.peers.lock().unwrap();
        let cutoff = chrono::Utc::now().timestamp() - window_secs;
        peers.values()
            .filter(|p| p.last_seen >= cutoff)
            .cloned()
            .collect()
    }

    pub fn cleanup_stale_peers(
        &self,
        active_addresses: &std::collections::HashSet<String>,
        p2p_cutoff: i64,
    ) {
        let mut peers = self.peers.lock().unwrap();
        peers.retain(|addr, p| {
            active_addresses.contains(addr) || p.last_seen >= p2p_cutoff
        });
    }

    pub fn set_session_start(&self, ts: i64) {
        *self.session_started.lock().unwrap() = ts;
        *self.last_earnings_credit.lock().unwrap() = ts;
    }

    pub fn get_session_started(&self) -> i64 {
        *self.session_started.lock().unwrap()
    }

    pub fn get_last_earnings_credit(&self) -> i64 {
        *self.last_earnings_credit.lock().unwrap()
    }

    pub fn set_last_earnings_credit(&self, ts: i64) {
        *self.last_earnings_credit.lock().unwrap() = ts;
    }

    pub fn get_cached_total_earned(&self) -> u64 {
        *self.cached_total_earned.lock().unwrap()
    }

    pub fn add_to_cached_total_earned(&self, amount: u64) {
        let mut v = self.cached_total_earned.lock().unwrap();
        *v = v.saturating_add(amount);
    }

    pub fn set_cached_total_earned(&self, amount: u64) {
        *self.cached_total_earned.lock().unwrap() = amount;
    }

    /// Initialize the in-memory wallet state.
    ///
    /// `force` must be `true` when the caller intentionally switches keypairs
    /// (e.g., `import_keypair` or wallet-slot switching).  Plain loading
    /// (`load_active_wallet`) passes `false` so it silently skips reinit if a
    /// different wallet is already live — preventing a race where two concurrent
    /// Tauri calls could swap the keypair mid-session.
    pub fn initialize_wallet(&self, keypair: KeyPair, force: bool) -> EgoResult<Address> {
        let address = Address::from_public_key(&keypair.ed25519_public_key());

        let mut kp_guard   = self.keypair.lock().unwrap();
        let mut addr_guard = self.wallet_address.lock().unwrap();
        let mut init_guard = self.is_initialized.lock().unwrap();

        if *init_guard && !force {
            // Already initialized with a different keypair — do not overwrite.
            // Return the currently active address so callers can detect the mismatch.
            return Ok(addr_guard.unwrap_or(address));
        }

        *kp_guard   = Some(keypair);
        *addr_guard = Some(address);
        *init_guard = true;

        Ok(address)
    }

    pub fn is_initialized(&self) -> bool {
        *self.is_initialized.lock().unwrap()
    }

    pub fn get_address(&self) -> Option<Address> {
        *self.wallet_address.lock().unwrap()
    }

    pub fn get_keypair(&self) -> Option<KeyPair> {
        self.keypair.lock().unwrap().clone()
    }

    pub fn update_balance(&self, new_balance: u64) {
        self.cache.lock().unwrap().balance = Some(new_balance);
    }

    pub fn add_transaction(&self, transaction: TransactionInfo) {
        let mut cache = self.cache.lock().unwrap();
        cache.transaction_history.insert(0, transaction);

        if cache.transaction_history.len() > 100 {
            cache.transaction_history.truncate(100);
        }
    }

    pub fn update_coverage_status(&self, status: CoverageStatus) {
        self.cache.lock().unwrap().coverage_status = Some(status);
    }

    pub fn update_storage_metrics(&self, metrics: StorageMetrics) {
        self.cache.lock().unwrap().storage_metrics = Some(metrics);
    }

    pub fn update_earnings_data(&self, earnings: EarningsData) {
        self.cache.lock().unwrap().earnings_data = Some(earnings);
    }
}
