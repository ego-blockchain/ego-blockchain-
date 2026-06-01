use crate::error::EgoDesktopError;
use crate::ledger::{load_registry, wallet_dir, Ledger, LedgerBlock, LedgerTx};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;

#[derive(Debug, Serialize, Deserialize)]
pub struct FileEvent {
    pub cid: String,
    pub owner: String,
    pub event_type: String,
    pub original_size: u64,
    pub encrypted_size: u64,
    pub timestamp: i64,
    pub expiry: i64,
    pub status: String,
}

const SHIELD_THRESHOLD_UEGOC: u64 = 50_000 * 1_000_000;

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkStats {
    pub latest_block: u64,
    pub total_transactions: usize,
    pub total_files_stored: usize,

    pub node_count: u32,
    pub network: String,
}

#[tauri::command]
pub async fn get_network_stats() -> Result<NetworkStats, EgoDesktopError> {
    let result = tokio::task::spawn_blocking(|| {
        let registry = load_registry();
        let (latest_height, _) = crate::chain_db::latest_block_info();
        let node_count = registry
            .wallets
            .iter()
            .filter(|w| !w.address.is_empty())
            .count() as u32;
        let mut seen_cids: HashSet<String> = HashSet::new();
        for entry in &registry.wallets {
            let path = wallet_dir(&entry.id).join("ledger.json");
            if let Ok(data) = fs::read_to_string(&path) {
                if let Ok(l) = serde_json::from_str::<Ledger>(&data) {
                    for f in &l.stored_files {
                        seen_cids.insert(f.cid.clone());
                    }
                }
            }
        }
        Ok(NetworkStats {
            latest_block: latest_height,
            total_transactions: crate::chain_db::tx_count() as usize,
            total_files_stored: seen_cids.len(),
            node_count: node_count.max(1),
            network: "Ego Testnet".into(),
        })
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?;
    result
}

#[derive(Debug, Serialize, Deserialize)]
pub struct P2pStatus {

    pub upnp: String,
    pub upnp_error: Option<String>,
    pub public_endpoint: String,
    pub p2p_port: u16,

    pub relay_circuit_ready: bool,
    pub relay_server_active: bool,

    pub community_relays: Vec<String>,

    pub storage_quota_bytes: u64,

    pub storage_used_bytes: u64,
}

#[tauri::command]
pub async fn get_p2p_status(state: tauri::State<'_, crate::app::AppState>) -> Result<P2pStatus, EgoDesktopError> {
    let (upnp, upnp_error) = match state.get_upnp_status() {
        None => ("pending".into(), None),
        Some(Ok(())) => ("ok".into(), None),
        Some(Err(e)) => ("failed".into(), Some(e)),
    };
    let public_endpoint   = state.get_public_endpoint();
    let relay_circuit     = crate::p2p::RELAY_CIRCUIT_READY.load(std::sync::atomic::Ordering::Relaxed);
    let relay_server      = crate::p2p::relay_mode_active();
    let community_relays  = crate::p2p::get_discovered_relay_nodes();

    let (quota, used) = tokio::task::spawn_blocking(|| {
        let ledger = crate::ledger::Ledger::load();
        let used: u64 = ledger.stored_files.iter().map(|f| f.encrypted_size).sum();
        (ledger.storage_allocated_bytes, used)
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?;

    Ok(P2pStatus {
        upnp,
        upnp_error,
        public_endpoint,
        p2p_port:             crate::p2p::P2P_PORT,
        relay_circuit_ready:  relay_circuit,
        relay_server_active:  relay_server,
        community_relays,
        storage_quota_bytes:  quota,
        storage_used_bytes:   used,
    })
}

#[tauri::command]
pub async fn get_blocks(offset: Option<u32>, limit: Option<u32>) -> Result<Vec<LedgerBlock>, EgoDesktopError> {
    let off = offset.unwrap_or(0) as usize;
    let lim = limit.unwrap_or(25) as usize;
    tokio::task::spawn_blocking(move || crate::chain_db::paged_blocks(off, lim))
        .await
        .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))
}

#[tauri::command]
pub async fn get_all_transactions(offset: Option<u32>, limit: Option<u32>) -> Result<Vec<LedgerTx>, EgoDesktopError> {
    let off = offset.unwrap_or(0) as usize;
    let lim = limit.unwrap_or(25) as usize;
    let mut txs = tokio::task::spawn_blocking(move || crate::chain_db::paged_transactions(off, lim))
        .await
        .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?;

    for tx in txs.iter_mut() {
        if tx.is_private || tx.amount >= SHIELD_THRESHOLD_UEGOC || tx.from == "Shielded" || tx.to == "Shielded" {
            tx.from = "Shielded".to_string();
            tx.to   = "Shielded".to_string();
            tx.memo = Some("Privacy Protected".to_string());
        }
    }
    Ok(txs)
}

#[tauri::command]
pub async fn get_block_info(height: u64) -> Result<LedgerBlock, EgoDesktopError> {
    tokio::task::spawn_blocking(move || {
        crate::chain_db::get_block_by_height(height)
            .ok_or_else(|| EgoDesktopError::NotFound(format!("Block #{height} not found")))
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

#[tauri::command]
pub async fn get_transaction_info(hash: String) -> Result<LedgerTx, EgoDesktopError> {
    let mut tx = tokio::task::spawn_blocking(move || {
        crate::chain_db::get_tx_by_hash(&hash)
            .ok_or_else(|| EgoDesktopError::NotFound(format!("TX {hash} not found")))
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))??;

    if tx.is_private || tx.amount >= SHIELD_THRESHOLD_UEGOC || tx.from == "Shielded" || tx.to == "Shielded" {
        tx.from = "Shielded".to_string();
        tx.to   = "Shielded".to_string();
        tx.memo = Some("Privacy Protected".to_string());
    }
    Ok(tx)
}

#[tauri::command]
pub async fn get_file_events() -> Result<Vec<FileEvent>, EgoDesktopError> {
    tokio::task::spawn_blocking(|| {
        let registry = load_registry();
        let mut seen: HashSet<String> = HashSet::new();
        let mut events: Vec<FileEvent> = Vec::new();

        for entry in &registry.wallets {
            let path = wallet_dir(&entry.id).join("ledger.json");
            let ledger: Ledger = match fs::read_to_string(&path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
            {
                Some(l) => l,
                None    => continue,
            };

            let owner = ledger.address.clone();
            for f in &ledger.stored_files {
                let key = format!("{}:{}", f.cid, owner);
                if seen.insert(key) {
                    events.push(FileEvent {
                        cid:            f.cid.clone(),
                        owner:          if f.owner.is_empty() { owner.clone() } else { f.owner.clone() },
                        event_type:     if f.status == "Received" { "Received".into() } else { "Stored".into() },
                        original_size:  f.original_size,
                        encrypted_size: f.encrypted_size,
                        timestamp:      f.stored_at,
                        expiry:         f.expiry,
                        status:         f.status.clone(),
                    });
                }
            }
        }

        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok::<_, EgoDesktopError>(events)
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}


#[derive(Debug, Serialize, Deserialize)]
pub struct EgocPrice {
    pub price_usd: f64,
    pub source: String,
}

#[tauri::command]
pub async fn get_egoc_price_usd() -> EgocPrice {
    crate::p2p::fetch_and_cache_egoc_price().await;
    let price = crate::p2p::get_egoc_price_usd();
    let source = if price > 0.0 { "market".into() } else { "estimated".into() };
    EgocPrice { price_usd: price, source }
}

#[tauri::command]
pub async fn get_base_fee() -> u64 {
    tokio::task::spawn_blocking(crate::chain_db::get_current_base_fee)
        .await
        .unwrap_or(0)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkCapacity {
    pub total_allocated_gb: f64,
    pub total_available_gb: f64,
    pub node_count: usize,
    pub fill_ratio: f64,
}

#[tauri::command]
pub async fn get_network_capacity() -> NetworkCapacity {
    let (total_alloc, total_avail, node_count) = crate::p2p::get_network_capacity();
    let fill_ratio = if total_alloc > 0.0 {
        ((total_alloc - total_avail) / total_alloc).clamp(0.0, 1.0)
    } else {
        0.0
    };
    NetworkCapacity { total_allocated_gb: total_alloc, total_available_gb: total_avail, node_count, fill_ratio }
}

#[tauri::command]
pub async fn get_state_stats() -> crate::chain_db::StateStats {
    tokio::task::spawn_blocking(crate::chain_db::get_state_stats)
        .await
        .unwrap_or(crate::chain_db::StateStats {
            total_accounts: 0,
            total_supply_uegoc: 0,
            db_size_estimate_mb: 0.0,
        })
}

#[derive(serde::Serialize)]
pub struct SupplyInfo {
    pub total_supply_uegoc: u64,
    pub circulating_uegoc: u64,
    pub remaining_mintable_uegoc: u64,
    pub current_block_reward_uegoc: u64,
}

#[tauri::command]
pub async fn get_supply_info() -> SupplyInfo {
    tokio::task::spawn_blocking(|| {
        let (height, _) = crate::chain_db::latest_block_info();
        SupplyInfo {
            total_supply_uegoc: crate::tokenomics::TOTAL_SUPPLY_UEGOC,
            circulating_uegoc: crate::chain_db::get_total_circulating_supply(),
            remaining_mintable_uegoc: crate::chain_db::remaining_mintable(),
            current_block_reward_uegoc: crate::chain_db::block_reward_at_height(height),
        }
    })
    .await
    .unwrap_or(SupplyInfo {
        total_supply_uegoc: crate::tokenomics::TOTAL_SUPPLY_UEGOC,
        circulating_uegoc: 0,
        remaining_mintable_uegoc: 0,
        current_block_reward_uegoc: 0,
    })
}

#[tauri::command]
pub async fn set_log_level(level: String) -> Result<String, String> {
    std::env::set_var("EGO_LOG", &level);
    Ok(format!("Log level hint set to {} (takes effect on restart)", level))
}
