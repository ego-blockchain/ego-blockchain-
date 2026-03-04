use crate::error::EgoResult;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use ego_core::{Address, KeyPair};
use std::collections::HashMap;

/// Info about an active peer node seen via P2P PeerAnnounce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub address:   String,
    pub name:      String,
    pub endpoint:  String,
    pub last_seen: i64,
}

#[derive(Debug, Clone)]
pub struct AppState {
    pub keypair: Arc<Mutex<Option<KeyPair>>>,
    pub wallet_address: Arc<Mutex<Option<Address>>>,
    pub is_initialized: Arc<Mutex<bool>>,
    pub settings: Arc<Mutex<AppSettings>>,
    pub cache: Arc<Mutex<AppCache>>,
    /// Unix timestamp when the current session started (init_wallet was called).
    pub session_started: Arc<Mutex<i64>>,
    /// Unix timestamp of the last time we credited accumulated earnings to the ledger.
    pub last_earnings_credit: Arc<Mutex<i64>>,
    /// Live peers seen via PeerAnnounce P2P messages.
    pub active_peers: Arc<Mutex<Vec<PeerInfo>>>,
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
    /// True when a VPN, proxy, or datacenter IP is detected.
    /// Coverage rewards are suppressed while this is true.
    #[serde(default)]
    pub vpn_detected: bool,
    /// Reason string shown in the UI when vpn_detected is true.
    #[serde(default)]
    pub vpn_reason: String,
    /// Stable hardware identifier for this machine.
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
    /// When this node session started (unix timestamp). Frontend uses this
    /// to seed the live per-second earnings counter.
    pub session_started: i64,
    /// Whether coverage (PoC beacon) is active this session.
    pub coverage_online: bool,
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
            active_peers: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Insert or update a peer (keyed by address).
    pub fn upsert_peer(&self, peer: PeerInfo) {
        let mut peers = self.active_peers.lock().unwrap();
        if let Some(existing) = peers.iter_mut().find(|p| p.address == peer.address) {
            *existing = peer;
        } else {
            peers.push(peer);
        }
    }

    /// Return peers seen within `max_age_secs` seconds.
    pub fn get_active_peers(&self, max_age_secs: i64) -> Vec<PeerInfo> {
        let now   = chrono::Utc::now().timestamp();
        let peers = self.active_peers.lock().unwrap();
        peers.iter()
            .filter(|p| now - p.last_seen <= max_age_secs)
            .cloned()
            .collect()
    }

    /// Record the session start time and reset the earnings credit clock.
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

    pub fn initialize_wallet(&self, keypair: KeyPair) -> EgoResult<Address> {
        let address = Address::from_public_key(&keypair.ed25519_public_key());

        *self.keypair.lock().unwrap() = Some(keypair);
        *self.wallet_address.lock().unwrap() = Some(address);
        *self.is_initialized.lock().unwrap() = true;

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

        // Keep only the last 100 transactions in memory
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