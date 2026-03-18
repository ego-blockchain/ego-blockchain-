use crate::app::AppState;
use crate::error::EgoDesktopError;
use crate::ledger::{load_chain, save_chain, tx_signing_bytes, Ledger, LedgerTx};
use serde::{Deserialize, Serialize};
use tauri::State;

#[derive(Debug, Serialize, Deserialize)]
pub struct Balance {
    pub egoc:      u64,
    pub uegoc:     u64,
    pub formatted: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendTransactionRequest {
    pub to_address: String,
    pub amount:     u64, // in uEGOC
    pub memo:       Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionResponse {
    pub hash:         String,
    pub success:      bool,
    pub message:      String,
    pub block_height: Option<u64>,
    /// How many peers the broadcast reached (0 = saved locally only)
    pub peers_reached: usize,
}

// ── get_balance ───────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn get_balance(_state: State<'_, AppState>) -> Result<Balance, EgoDesktopError> {
    let ledger  = Ledger::load();
    let my_addr = ledger.address.clone();

    if my_addr.is_empty() {
        return Ok(Balance { egoc: 0, uegoc: 0, formatted: "0.00 EGOC".into() });
    }

    let chain = load_chain();
    let uegoc = chain.balance_of(&my_addr);
    let egoc  = uegoc / 1_000_000;

    Ok(Balance {
        egoc,
        uegoc,
        formatted: format!("{:.2} EGOC", uegoc as f64 / 1_000_000.0),
    })
}

// ── send_transaction ──────────────────────────────────────────────────────────

#[tauri::command]
pub async fn send_transaction(
    request: SendTransactionRequest,
    state:   State<'_, AppState>,
) -> Result<TransactionResponse, EgoDesktopError> {
    let mut ledger = Ledger::load();
    let from = ledger.address.clone();

    if from.is_empty() {
        return Err(EgoDesktopError::WalletError(
            "Wallet not initialized – call init_wallet first".into(),
        ));
    }

    // ── 1. Validate ───────────────────────────────────────────────────────
    let mut chain   = load_chain();
    let balance     = chain.balance_of(&from);

    if request.amount == 0 {
        return Err(EgoDesktopError::InvalidInput("Amount must be > 0".into()));
    }
    if request.amount > balance {
        return Err(EgoDesktopError::InvalidInput(format!(
            "Insufficient balance: have {} uEGOC, need {}",
            balance, request.amount
        )));
    }

    // ── 2. Sign ───────────────────────────────────────────────────────────
    let nonce      = ledger.nonce + 1;
    let ts         = chrono::Utc::now().timestamp();
    let sign_bytes = tx_signing_bytes(&from, &request.to_address, request.amount, nonce, ts);

    let signature_hex = if let Some(kp) = state.get_keypair() {
        hex::encode(kp.sign_ed25519(&sign_bytes).as_bytes())
    } else {
        return Err(EgoDesktopError::WalletError(
            "Wallet not initialized – call init_wallet first".into(),
        ));
    };

    let tx_hash = format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex());

    // ── 3. Add as Pending ─────────────────────────────────────────────────
    chain.transactions.push(LedgerTx {
        hash:         tx_hash.clone(),
        from:         from.clone(),
        to:           request.to_address.clone(),
        amount:       request.amount,
        memo:         request.memo.clone(),
        timestamp:    ts,
        signature:    signature_hex,
        status:       "Pending".into(),
        block_height: None,
        nonce,
        ..LedgerTx::default()
    });

    // ── 4. Mine block → Confirmed ─────────────────────────────────────────
    chain.mine_block(&tx_hash, &from);

    let block_height = chain
        .transactions
        .iter()
        .find(|t| t.hash == tx_hash)
        .and_then(|t| t.block_height);

    // ── 5. Save locally ───────────────────────────────────────────────────
    save_chain(&chain)
        .map_err(|e| EgoDesktopError::WalletError(format!("Save chain: {e}")))?;

    ledger.nonce = nonce;
    let _ = ledger.save();

    // ── 6. Broadcast to peers — with live endpoint refresh ────────────────
    //
    // KEY FIX: contacts may have stale LAN endpoints stored from before the
    // relay fix. Before broadcasting, we check AppState for a fresher endpoint
    // for the same peer (populated by recent PeerAnnounce messages over P2P).
    // If we have a newer relay-circuit endpoint, we use that instead.
    let tx_b  = chain.transactions.iter().find(|t| t.hash == tx_hash).cloned();
    let blk_b = chain.blocks.last().cloned();

    let peers_reached = if let (Some(tx_b), Some(blk_b)) = (tx_b, blk_b) {
        let contacts = crate::commands::messenger::load_contacts();
        let active_peers = state.get_active_peers(600); // 10-min window

        // Build a map: wallet_address → freshest known endpoint
        // Priority: live PeerAnnounce endpoint > stored contact endpoint
        let fresh_endpoints: std::collections::HashMap<String, String> = {
            let mut map = std::collections::HashMap::new();
            // Start with stored contact endpoints as baseline
            for c in contacts.iter().filter(|c| c.status == "approved" && !c.endpoint.is_empty()) {
                map.insert(c.address.clone(), c.endpoint.clone());
            }
            // Override with live P2P-announced endpoints if newer
            // (relay circuit addresses are always preferred over LAN IPs)
            for peer in &active_peers {
                if !peer.endpoint.is_empty() {
                    let is_relay = peer.endpoint.contains("/p2p-circuit");
                    let existing_is_relay = map.get(&peer.address)
                        .map(|e| e.contains("/p2p-circuit"))
                        .unwrap_or(false);
                    // Prefer relay address, or any live address over stored stale one
                    if is_relay || !existing_is_relay {
                        map.insert(peer.address.clone(), peer.endpoint.clone());
                    }
                }
            }
            map
        };

        let mut send_tasks = vec![];
        for (_addr, endpoint) in fresh_endpoints {
            let tx_clone  = tx_b.clone();
            let blk_clone = blk_b.clone();
            let ep        = endpoint.clone();
            send_tasks.push(tokio::spawn(async move {
                crate::p2p::send_message(
                    &ep,
                    &crate::p2p::P2PMessage::TxBroadcast {
                        tx:    tx_clone,
                        block: blk_clone,
                    },
                ).await
            }));
        }

        // Wait for all sends (with a 10s timeout) and count successes
        let results = futures::future::join_all(send_tasks).await;
        results.iter().filter(|r| {
            matches!(r, Ok(Ok(())))
        }).count()
    } else {
        0
    };

    let message = if peers_reached > 0 {
        format!("Transaction confirmed and broadcast to {} peer(s)", peers_reached)
    } else {
        "Transaction confirmed locally. No peers reachable — will sync when peers reconnect.".into()
    };

    Ok(TransactionResponse {
        hash: tx_hash,
        success: true,
        message,
        block_height,
        peers_reached,
    })
}

// ── sync_chain ────────────────────────────────────────────────────────────────
//
// Pull the full chain from all known peers and merge.
// Called automatically on startup (from main.rs) and can be triggered manually
// from the frontend via a "Sync" button.

#[tauri::command]
pub async fn sync_chain(state: State<'_, AppState>) -> Result<String, EgoDesktopError> {
    let my_endpoint = crate::p2p::get_public_endpoint().await;
    let msg = crate::p2p::P2PMessage::ChainSyncRequest {
        requester_endpoint: my_endpoint.clone(),
    };

    let contacts    = crate::commands::messenger::load_contacts();
    let active_peers = state.get_active_peers(600);

    // Same endpoint-refresh logic as send_transaction
    let mut endpoints: std::collections::HashSet<String> = std::collections::HashSet::new();
    for c in contacts.iter().filter(|c| !c.endpoint.is_empty()) {
        endpoints.insert(c.endpoint.clone());
    }
    for p in &active_peers {
        if !p.endpoint.is_empty() {
            // Prefer relay endpoints
            if p.endpoint.contains("/p2p-circuit") {
                endpoints.retain(|e| {
                    // Remove any non-relay endpoint for the same peer ID
                    let peer_id = p.endpoint.split("/p2p/").last().unwrap_or("");
                    !e.contains(peer_id) || e.contains("/p2p-circuit")
                });
                endpoints.insert(p.endpoint.clone());
            } else {
                endpoints.insert(p.endpoint.clone());
            }
        }
    }

    if endpoints.is_empty() {
        return Ok("No peers to sync from.".into());
    }

    let mut tasks = vec![];
    for endpoint in endpoints {
        let msg_clone = msg.clone();
        tasks.push(tokio::spawn(async move {
            crate::p2p::send_message(&endpoint, &msg_clone).await
        }));
    }

    let results  = futures::future::join_all(tasks).await;
    let reached  = results.iter().filter(|r| matches!(r, Ok(Ok(())))).count();
    let total    = results.len();

    Ok(format!("Sync requested from {}/{} peers. Chain will update shortly.", reached, total))
}


// ── get_transaction_history ───────────────────────────────────────────────────

#[tauri::command]
pub async fn get_transaction_history(
    _state: State<'_, AppState>,
) -> Result<Vec<LedgerTx>, EgoDesktopError> {
    let ledger  = Ledger::load();
    let my_addr = ledger.address.clone();

    if my_addr.is_empty() {
        return Ok(vec![]);
    }

    let chain = load_chain();
    let mut txs: Vec<LedgerTx> = chain
        .transactions
        .into_iter()
        .filter(|tx| {
            tx.to.trim()   == my_addr.trim()
            || tx.from.trim() == my_addr.trim()
        })
        .collect();

    txs.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    Ok(txs)
}