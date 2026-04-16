use crate::app::AppState;
use crate::error::EgoDesktopError;
use crate::ledger::{load_chain, tx_signing_bytes, tx_signing_bytes_v2, tx_human_summary, Ledger, LedgerTx};
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
    pub amount:     u64,
    pub memo:       Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionResponse {
    pub hash:           String,
    pub success:        bool,
    pub message:        String,
    pub block_height:   Option<u64>,
    pub peers_reached:  usize,
    pub signed_summary: Option<String>,
}

#[tauri::command]
pub async fn get_balance(_state: State<'_, AppState>) -> Result<Balance, EgoDesktopError> {
    let ledger  = Ledger::load();
    let my_addr = ledger.address.clone();

    if my_addr.is_empty() {
        return Ok(Balance { egoc: 0, uegoc: 0, formatted: "0.00 EGOC".into() });
    }

    let chain = load_chain();
    let confirmed = chain.balance_of(&my_addr);

    let pending_out: u64 = crate::mempool::get_mempool()
        .peek_all()
        .into_iter()
        .filter(|tx| tx.from.trim() == my_addr.trim())
        .map(|tx| tx.amount.saturating_add(tx.fee_uegoc))
        .sum();

    let uegoc = confirmed.saturating_sub(pending_out);
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

    let mut chain   = load_chain();
    let balance     = chain.balance_of(&from);

    if request.to_address.trim() == from.trim() {
        return Err(EgoDesktopError::InvalidInput("Cannot send to your own address".into()));
    }
    if request.amount == 0 {
        return Err(EgoDesktopError::InvalidInput("Amount must be > 0".into()));
    }
    if request.amount > balance {
        return Err(EgoDesktopError::InvalidInput(format!(
            "Insufficient balance: have {} uEGOC, need {}",
            balance, request.amount
        )));
    }

    let nonce      = ledger.nonce + 1;
    let ts         = chrono::Utc::now().timestamp();
    let memo_str   = request.memo.as_deref().unwrap_or("");
    const CHAIN_ID: u8 = 1; // testnet
    let sign_bytes = tx_signing_bytes_v2(
        &from, &request.to_address, request.amount, nonce, ts, CHAIN_ID, memo_str,
    );

    // Hybrid signing: Ed25519 (classical) + ML-DSA-44 (post-quantum).
    // Both signatures must verify — attacker needs to break BOTH schemes.
    let (signature_hex, dilithium_pubkey_hex, dilithium_sig_hex) =
        if let Some(kp) = state.get_keypair() {
            let ed_sig  = hex::encode(kp.sign_ed25519(&sign_bytes).as_bytes());
            let dil_sig = hex::encode(kp.sign_dilithium(&sign_bytes).as_bytes());
            let dil_pk  = hex::encode(kp.dilithium_public_key().key_data);
            (ed_sig, dil_pk, dil_sig)
        } else {
            return Err(EgoDesktopError::WalletError(
                "Wallet not initialized – call init_wallet first".into(),
            ));
        };

    let tx_hash = format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex());
    let summary = tx_human_summary(
        &from, &request.to_address, request.amount, memo_str, CHAIN_ID, nonce, 0,
    );

    let pending_tx = LedgerTx {
        hash:                tx_hash.clone(),
        from:                from.clone(),
        to:                  request.to_address.clone(),
        amount:              request.amount,
        memo:                request.memo.clone(),
        timestamp:           ts,
        signature:           signature_hex,
        dilithium_pubkey:    dilithium_pubkey_hex,
        dilithium_signature: dilithium_sig_hex,
        status:              "Pending".into(),
        block_height:        None,
        nonce,
        tx_version:          2,
        chain_id:            CHAIN_ID,
        signed_summary:      summary.clone(),
        ..LedgerTx::default()
    };
    crate::commands::tx_pending::add(&pending_tx);
    crate::mempool::get_mempool().push(pending_tx.clone());

    let gossip_tx = pending_tx.clone();
    tokio::spawn(async move { crate::p2p::broadcast_pending_tx(gossip_tx).await; });

    ledger.nonce = nonce;
    let _ = ledger.save();

    Ok(TransactionResponse {
        hash:           tx_hash,
        success:        true,
        message:        "Transaction queued — confirms within the next batch window".into(),
        block_height:   None,
        peers_reached:  0,
        signed_summary: Some(summary),
    })
}

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

    let confirmed_hashes: std::collections::HashSet<String> =
        txs.iter().map(|t| t.hash.clone()).collect();

    let pending: Vec<LedgerTx> = crate::mempool::get_mempool()
        .peek_all()
        .into_iter()
        .filter(|tx| {
            !confirmed_hashes.contains(&tx.hash)
            && (tx.to.trim() == my_addr.trim() || tx.from.trim() == my_addr.trim())
        })
        .collect();

    txs.extend(pending);
    txs.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    Ok(txs)
}
