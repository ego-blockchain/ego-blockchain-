use crate::app::AppState;
use crate::error::EgoDesktopError;
use crate::ledger::{load_chain, save_chain, tx_signing_bytes, Ledger, LedgerTx};
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

    // ── 2. Sign the transaction ───────────────────────────────────────────
    let nonce      = ledger.nonce + 1;
    let ts         = chrono::Utc::now().timestamp();
    let sign_bytes = tx_signing_bytes(&from, &request.to_address, request.amount, nonce, ts);

    let signature_hex = if let Some(kp) = state.get_keypair() {
        let sig = kp.sign_ed25519(&sign_bytes);
        hex::encode(sig.as_bytes())
    } else {
        return Err(EgoDesktopError::WalletError(
            "Wallet not initialized – call init_wallet first".into(),
        ));
    };

    let tx_hash = format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex());

    // ── 3. Add tx to the shared chain as "Pending" ────────────────────────
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
    });

    // ── 4. Mine a block → confirms the tx ────────────────────────────────
    chain.mine_block(&tx_hash, &from);

    let block_height = chain
        .transactions
        .iter()
        .find(|t| t.hash == tx_hash)
        .and_then(|t| t.block_height);

    // ── 5. Save chain locally ─────────────────────────────────────────────
    save_chain(&chain)
        .map_err(|e| EgoDesktopError::WalletError(format!("Save chain: {e}")))?;

    // ── 6. Broadcast to all P2P peers (fire-and-forget) ───────────────────
    // Pushes the confirmed tx+block to every machine that has us as a contact
    // so their chain.json, balance, and explorer update in real-time.
    if let (Some(tx_b), Some(blk_b)) = (
        chain.transactions.iter().find(|t| t.hash == tx_hash).cloned(),
        chain.blocks.last().cloned(),
    ) {
        tokio::spawn(async move {
            crate::p2p::broadcast_tx(tx_b, blk_b).await;
        });
    }

    // ── 7. Persist updated nonce in per-wallet ledger ─────────────────────
    ledger.nonce = nonce;
    let _ = ledger.save();

    Ok(TransactionResponse {
        hash: tx_hash,
        success: true,
        message: "Transaction confirmed and broadcast to all nodes".into(),
        block_height,
    })
}

// ── reset_chain ──────────────────────────────────────────────────────────────

/// Wipe all blocks and transactions from chain.json (keeps wallets and keys).
/// Useful for testing — all balances will reset to zero.
#[tauri::command]
pub async fn reset_chain() -> Result<(), EgoDesktopError> {
    let empty = crate::ledger::SharedChain::default();
    save_chain(&empty).map_err(|e| EgoDesktopError::FileSystemError(e))
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
