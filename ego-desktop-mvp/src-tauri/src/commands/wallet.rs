use crate::app::AppState;
use crate::error::EgoDesktopError;
use crate::ledger::{load_chain, save_chain, tx_signing_bytes, Ledger, LedgerBlock, LedgerTx};
use serde::{Deserialize, Serialize};
use tauri::State;

#[derive(Debug, Serialize, Deserialize)]
pub struct Balance {
    pub egoc: u64,
    pub uegoc: u64,
    pub formatted: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendTransactionRequest {
    pub to_address: String,
    pub amount: u64, // in uEGOC
    pub memo: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionResponse {
    pub hash: String,
    pub success: bool,
    pub message: String,
    pub block_height: Option<u64>,
}

// ── get_balance ───────────────────────────────────────────────────────────────
//
// Balance is derived entirely from the shared chain:
//   balance = Σ confirmed incoming txs − Σ confirmed outgoing txs
//
// This mirrors how Bitcoin nodes compute a wallet's balance by replaying the
// chain — no per-wallet "balance" field that can get out of sync.

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
//
// P2P flow:
//   [Wallet A] → add tx to shared chain (Pending)
//             → mine block (Confirmed)
//             → save chain.json  ← "broadcast to all nodes"
//             → [Wallet B] reads chain.json → balance updated automatically

#[tauri::command]
pub async fn send_transaction(
    request: SendTransactionRequest,
    state: State<'_, AppState>,
) -> Result<TransactionResponse, EgoDesktopError> {
    let mut ledger = Ledger::load();
    let from = ledger.address.clone();

    if from.is_empty() {
        return Err(EgoDesktopError::WalletError(
            "Wallet not initialized – call init_wallet first".into(),
        ));
    }

    // ── 1. Validate balance from shared chain ─────────────────────────────
    let chain   = load_chain();
    let balance = chain.balance_of(&from);

    if request.amount == 0 {
        return Err(EgoDesktopError::InvalidInput("Amount must be > 0".into()));
    }
    if request.amount > balance {
        return Err(EgoDesktopError::InvalidInput(format!(
            "Insufficient balance: have {} uEGOC, need {}",
            balance, request.amount
        )));
    }

    // ── 2. Sign the transaction ───────────────────────────────────────────
    let nonce      = ledger.nonce + 1;
    let ts         = chrono::Utc::now().timestamp();
    let sign_bytes = tx_signing_bytes(&from, &request.to_address, request.amount, nonce, ts);

    let (signature_hex, pubkey_hex, dil_sig_hex, dil_pubkey_hex) = if let Some(kp) = state.get_keypair() {
        let ed_sig  = kp.sign_ed25519(&sign_bytes);
        let dil_sig = kp.sign_dilithium(&sign_bytes);
        let ed_pk   = hex::encode(kp.ed25519_public_key().as_bytes());
        let dil_pk  = hex::encode(&kp.dilithium_public_key().key_data);
        (hex::encode(ed_sig.as_bytes()), ed_pk,
         hex::encode(&dil_sig.signature_data), dil_pk)
    } else {
        return Err(EgoDesktopError::WalletError(
            "Wallet not initialized – call init_wallet first".into(),
        ));
    };

    let tx_hash = format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex());

    let tx = LedgerTx {
        hash:                tx_hash.clone(),
        from:                from.clone(),
        to:                  request.to_address.clone(),
        amount:              request.amount,
        memo:                request.memo.clone(),
        timestamp:           ts,
        signature:           signature_hex,
        status:              "Pending".into(),
        block_height:        None,
        nonce,
        public_key_ed25519:  pubkey_hex,
        dilithium_pubkey:    dil_pubkey_hex,
        dilithium_signature: dil_sig_hex,
        ..LedgerTx::default()
    };

    // ── 3. Route to mempool (batch loop will mine + broadcast) ───────────
    // The TX is confirmed inside the next batch window (≤ BATCH_INTERVAL_MS).
    // This decouples signing from disk I/O — enabling 100k TPS throughput.
    crate::mempool::get_mempool().push(tx);

    // ── 4. Persist updated nonce in per-wallet ledger ─────────────────────
    ledger.nonce = nonce;
    let _ = ledger.save();

    Ok(TransactionResponse {
        hash:         tx_hash,
        success:      true,
        message:      "Transaction queued — confirms within the next batch window".into(),
        block_height: None, // assigned by batch loop
    })
}

// ── prepare_transaction ───────────────────────────────────────────────────────
// Builds and signs a tx+block but does NOT save anything.
// Returns JSON strings so the frontend can POST them to the relay for email confirmation.

#[derive(Debug, Serialize)]
pub struct PreparedTransaction {
    pub tx_json:    String,
    pub block_json: String,
    pub tx_hash:    String,
    pub amount:     u64,
    pub from:       String,
    pub to:         String,
}

#[tauri::command]
pub async fn prepare_transaction(
    request: SendTransactionRequest,
    state: State<'_, AppState>,
) -> Result<PreparedTransaction, EgoDesktopError> {
    let mut ledger = Ledger::load();
    let from = ledger.address.clone();
    if from.is_empty() {
        return Err(EgoDesktopError::WalletError("Wallet not initialized".into()));
    }
    let mut chain = load_chain();
    let balance   = chain.balance_of(&from);
    if request.amount == 0 {
        return Err(EgoDesktopError::InvalidInput("Amount must be > 0".into()));
    }
    if request.amount > balance {
        return Err(EgoDesktopError::InvalidInput(format!(
            "Insufficient balance: have {} uEGOC, need {}", balance, request.amount
        )));
    }
    let nonce      = ledger.nonce + 1;
    let ts         = chrono::Utc::now().timestamp();
    let sign_bytes = tx_signing_bytes(&from, &request.to_address, request.amount, nonce, ts);
    let (signature_hex, pubkey_hex, dil_sig_hex, dil_pubkey_hex) = if let Some(kp) = state.get_keypair() {
        let ed_sig  = kp.sign_ed25519(&sign_bytes);
        let dil_sig = kp.sign_dilithium(&sign_bytes);
        let ed_pk   = hex::encode(kp.ed25519_public_key().as_bytes());
        let dil_pk  = hex::encode(&kp.dilithium_public_key().key_data);
        (hex::encode(ed_sig.as_bytes()), ed_pk,
         hex::encode(&dil_sig.signature_data), dil_pk)
    } else {
        return Err(EgoDesktopError::WalletError("Wallet not initialized".into()));
    };
    let tx_hash = format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex());
    let tx = LedgerTx {
        hash: tx_hash.clone(), from: from.clone(), to: request.to_address.clone(),
        amount: request.amount, memo: request.memo.clone(), timestamp: ts,
        signature: signature_hex, status: "Pending".into(),
        block_height: None, nonce, public_key_ed25519: pubkey_hex,
        dilithium_pubkey: dil_pubkey_hex, dilithium_signature: dil_sig_hex,
        ..LedgerTx::default()
    };
    chain.transactions.push(tx.clone());
    chain.mine_block(&tx_hash, &from);
    let block = chain.blocks.last().cloned().ok_or_else(||
        EgoDesktopError::WalletError("Block not created".into())
    )?;
    // Serialize the confirmed tx (after mine_block set status="Confirmed"),
    // not the original `tx` variable which still has status="Pending".
    let confirmed_tx = chain.transactions.iter().find(|t| t.hash == tx_hash).cloned()
        .ok_or_else(|| EgoDesktopError::WalletError("Tx not found after mining".into()))?;
    // DO NOT save — just return JSON for relay submission
    let tx_json    = serde_json::to_string(&confirmed_tx).map_err(|e| EgoDesktopError::WalletError(e.to_string()))?;
    let block_json = serde_json::to_string(&block).map_err(|e| EgoDesktopError::WalletError(e.to_string()))?;
    Ok(PreparedTransaction { tx_json, block_json, tx_hash, amount: request.amount, from, to: request.to_address })
}

// ── commit_transaction ────────────────────────────────────────────────────────
// Called after user confirms via email. Saves tx+block locally and broadcasts.

#[tauri::command]
pub async fn commit_transaction(
    tx_json: String,
    block_json: String,
) -> Result<TransactionResponse, EgoDesktopError> {
    let mut tx: LedgerTx = serde_json::from_str(&tx_json)
        .map_err(|e| EgoDesktopError::WalletError(format!("Invalid tx JSON: {e}")))?;
    let block: LedgerBlock = serde_json::from_str(&block_json)
        .map_err(|e| EgoDesktopError::WalletError(format!("Invalid block JSON: {e}")))?;
    // Always confirm — the tx is being committed by the user, so it's confirmed.
    tx.status = "Confirmed".to_string();
    if tx.block_height.is_none() { tx.block_height = Some(block.height); }
    let mut chain = load_chain();
    if let Some(existing) = chain.transactions.iter_mut().find(|t| t.hash == tx.hash) {
        // Upgrade status if previously saved as Pending.
        existing.status = "Confirmed".to_string();
        existing.block_height = tx.block_height;
    } else {
        chain.transactions.push(tx.clone());
        chain.blocks.push(block.clone());
        chain.blocks.sort_by_key(|b| b.height);
    }
    save_chain(&chain).map_err(|e| EgoDesktopError::WalletError(format!("Save: {e}")))?;
    let mut ledger = Ledger::load();
    if tx.nonce > ledger.nonce { ledger.nonce = tx.nonce; let _ = ledger.save(); }
    let block_height = tx.block_height;
    let tx_hash = tx.hash.clone();
    let tx2 = tx.clone(); let blk2 = block.clone();
    let tx3 = tx.clone(); let blk3 = block.clone();
    tokio::spawn(async move { crate::p2p::push_tx_to_relay(&tx2, &blk2).await; });
    tokio::spawn(async move { crate::p2p::broadcast_tx(tx3, blk3).await; });
    Ok(TransactionResponse {
        hash: tx_hash, success: true,
        message: "Transaction confirmed and broadcast".into(), block_height,
    })
}

// ── get_transaction_history ───────────────────────────────────────────────────
//
// Returns all chain txs that involve this wallet address (sent or received).
// Because the chain is shared, incoming txs from ANY other local wallet appear
// here automatically — no per-wallet scanning or credit step needed.

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

// ── query_remote_node ─────────────────────────────────────────────────────────
//
// Queries a headless ego-node's HTTP RPC and returns its identity + balance.
// This lets desktop wallet holders monitor server nodes they operate.

#[derive(Debug, Serialize, Deserialize)]
pub struct RemoteNodeInfo {
    pub address:        String,
    pub public_key_hex: String,
    pub peer_id:        String,
    pub payout_address: Option<String>,
    pub balance_uegoc:  u64,
    pub balance_egoc:   u64,
    pub formatted:      String,
    pub block_height:   u64,
    pub rpc_url:        String,
}

#[tauri::command]
pub async fn query_remote_node(
    rpc_url: String,
    _state: State<'_, AppState>,
) -> Result<RemoteNodeInfo, EgoDesktopError> {
    let url = rpc_url.trim_end_matches('/').to_string();

    // Fetch identity (address, keys, balance)
    let identity_url = format!("{}/node/identity", url);
    let identity_resp = reqwest::get(&identity_url)
        .await
        .map_err(|e| EgoDesktopError::NetworkError(format!("Cannot reach node: {e}")))?;
    if !identity_resp.status().is_success() {
        return Err(EgoDesktopError::NetworkError(format!(
            "Node returned HTTP {}",
            identity_resp.status()
        )));
    }
    let identity: serde_json::Value = identity_resp
        .json()
        .await
        .map_err(|e| EgoDesktopError::NetworkError(format!("Invalid response: {e}")))?;

    // Fetch block height from /health
    let health_url = format!("{}/health", url);
    let block_height: u64 = if let Ok(hr) = reqwest::get(&health_url).await {
        hr.json::<serde_json::Value>().await
            .ok()
            .and_then(|v| v["block_height"].as_u64())
            .unwrap_or(0)
    } else { 0 };

    let balance_uegoc = identity["balance_uegoc"].as_u64().unwrap_or(0);
    let balance_egoc  = identity["balance_egoc"].as_u64().unwrap_or(0);

    Ok(RemoteNodeInfo {
        address:        identity["address"].as_str().unwrap_or("").to_string(),
        public_key_hex: identity["public_key_hex"].as_str().unwrap_or("").to_string(),
        peer_id:        identity["peer_id"].as_str().unwrap_or("").to_string(),
        payout_address: identity["payout_address"].as_str().map(|s| s.to_string()),
        balance_uegoc,
        balance_egoc,
        formatted: format!("{:.2} EGOC", balance_uegoc as f64 / 1_000_000.0),
        block_height,
        rpc_url: url,
    })
}
