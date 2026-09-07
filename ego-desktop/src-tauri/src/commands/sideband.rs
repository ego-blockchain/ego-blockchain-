use serde::Serialize;

#[derive(Serialize)]
pub struct SidebandTransportInfo {
    pub name: String,
    pub can_send: bool,
}

#[derive(Serialize)]
pub struct SidebandStatus {
    pub enabled: bool,
    pub online: bool,
    pub transports: Vec<SidebandTransportInfo>,
    pub spool_root: String,
    pub inbox_frames: usize,
    pub outbox_frames: usize,
    pub max_age_hours: i64,
}

/// What the offline transaction path is doing, if anything.
///
/// `online` matters more than it looks: transactions are only handed to a
/// sideband transport when gossip has nowhere to go, so a user with working
/// internet will see a configured transport sitting idle, which is correct.
#[tauri::command]
pub fn sideband_status() -> SidebandStatus {
    let transports: Vec<SidebandTransportInfo> = crate::sideband::transports()
        .into_iter()
        .map(|(name, can_send)| SidebandTransportInfo { name, can_send })
        .collect();

    let (inbox_frames, outbox_frames) = crate::sideband_spool::queue_depths();

    SidebandStatus {
        enabled: !transports.is_empty(),
        online: crate::p2p::has_connectivity(),
        transports,
        spool_root: crate::sideband_spool::spool_root()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        inbox_frames,
        outbox_frames,
        max_age_hours: crate::mempool::MAX_SIDEBAND_TX_AGE_SECS / 3600,
    }
}

/// Push a pending transaction onto the sideband by hand.
///
/// The send path already does this automatically when the node is offline.
/// This exists for the case where a user knows their connection is censored
/// rather than absent, so gossip appears to work but nothing arrives.
#[tauri::command]
pub async fn sideband_queue_tx(tx_hash: String) -> Result<String, String> {
    if !crate::sideband::has_transport() {
        return Err("No offline transport is configured. Start with EGO_SIDEBAND_SPOOL=1.".into());
    }

    let hash = tx_hash.clone();
    let tx = tokio::task::spawn_blocking(move || {
        let me = crate::ledger::Ledger::load().address;
        crate::mempool::get_mempool()
            .pending_txs_for_address(&me)
            .into_iter()
            .find(|t| t.hash == hash)
    })
    .await
    .map_err(|e| e.to_string())?
    .ok_or_else(|| format!("Transaction {tx_hash} is not pending from this wallet"))?;

    let msg = crate::p2p::P2PMessage::TxBroadcast {
        tx,
        block: crate::ledger::LedgerBlock::default(),
    };
    let data = serde_json::to_vec(&msg).map_err(|e| e.to_string())?;
    let id = {
        let mut h: u32 = 0x811c_9dc5;
        for b in tx_hash.bytes() {
            h ^= b as u32;
            h = h.wrapping_mul(0x0100_0193);
        }
        h
    };

    let sent = tokio::task::spawn_blocking(move || crate::sideband::broadcast(&data, id))
        .await
        .map_err(|e| e.to_string())?;

    if sent == 0 {
        return Err("Every configured transport is receive-only.".into());
    }
    Ok(format!("Queued for {sent} offline transport(s)."))
}
