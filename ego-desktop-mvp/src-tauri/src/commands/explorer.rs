use crate::error::EgoDesktopError;
use crate::ledger::{load_chain, load_registry, wallet_dir, Ledger, LedgerBlock, LedgerTx};
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
}

#[derive(Debug, Serialize, Deserialize)]
pub struct P2pStatus {

    pub upnp: String,
    pub upnp_error: Option<String>,
    pub public_endpoint: String,
    pub p2p_port: u16,

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
    let ledger = crate::ledger::Ledger::load();
    let used: u64 = ledger.stored_files.iter().map(|f| f.encrypted_size).sum();
    Ok(P2pStatus {
        upnp,
        upnp_error,
        public_endpoint:      state.get_public_endpoint(),
        p2p_port:             crate::p2p::P2P_PORT,
        relay_server_active:  crate::p2p::relay_mode_active(),
        community_relays:     crate::p2p::get_discovered_relay_nodes(),
        storage_quota_bytes:  ledger.storage_allocated_bytes,
        storage_used_bytes:   used,
    })
}

#[tauri::command]
pub async fn get_blocks(offset: Option<u32>, limit: Option<u32>) -> Result<Vec<LedgerBlock>, EgoDesktopError> {
    Ok(crate::chain_db::paged_blocks(
        offset.unwrap_or(0) as usize,
        limit.unwrap_or(25) as usize,
    ))
}

#[tauri::command]
pub async fn get_all_transactions(offset: Option<u32>, limit: Option<u32>) -> Result<Vec<LedgerTx>, EgoDesktopError> {
    Ok(crate::chain_db::paged_transactions(
        offset.unwrap_or(0) as usize,
        limit.unwrap_or(25) as usize,
    ))
}

#[tauri::command]
pub async fn get_block_info(height: u64) -> Result<LedgerBlock, EgoDesktopError> {
    load_chain()
        .blocks
        .into_iter()
        .find(|b| b.height == height)
        .ok_or_else(|| EgoDesktopError::NotFound(format!("Block #{height} not found")))
}

#[tauri::command]
pub async fn get_transaction_info(hash: String) -> Result<LedgerTx, EgoDesktopError> {
    load_chain()
        .transactions
        .into_iter()
        .find(|tx| tx.hash == hash)
        .ok_or_else(|| EgoDesktopError::NotFound(format!("TX {hash} not found")))
}

/// Returns all file storage/sharing events across all wallets, newest first.
/// Names and keys are never included — only the public CID hash is exposed.
#[tauri::command]
pub async fn get_file_events() -> Result<Vec<FileEvent>, EgoDesktopError> {
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
    Ok(events)
}
