use crate::app::AppState;
use crate::error::EgoDesktopError;
use crate::ledger::{load_chain, save_chain, tx_signing_bytes, tx_signing_bytes_v2, tx_human_summary, Ledger, LedgerBlock, LedgerTx};
use once_cell::sync::Lazy;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tauri::Manager;
use std::sync::Mutex;
use tauri::State;
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Key, Nonce};
use crate::ledger::PresaleIouRecord;

const SHIELD_THRESHOLD_UEGOC: u64 = 50_000 * 1_000_000;

static PENDING_TXS: Lazy<Mutex<HashMap<String, (LedgerTx, i64)>>> =
    Lazy::new(|| {
        let map: HashMap<String, (LedgerTx, i64)> = crate::chain_db::load_pending_otptxs()
            .into_iter()
            .map(|(id, tx, exp)| (id, (tx, exp)))
            .collect();
        Mutex::new(map)
    });


fn validate_ego_address(addr: &str) -> Result<(), EgoDesktopError> {
    let addr = addr.trim();
    if addr.is_empty() {
        return Err(EgoDesktopError::InvalidInput("Recipient address is empty".into()));
    }
    if addr.len() > 100 {
        return Err(EgoDesktopError::InvalidInput(
            "Address too long (max 100 characters)".into(),
        ));
    }
    // Accept egot1… (user EOA) and egot1staking…/egot1rewards…/egot1faucet… (system)
    if !addr.starts_with("egot1") && !addr.starts_with("ego1") {
        return Err(EgoDesktopError::InvalidInput(
            "Invalid address: must start with 'egot1' (testnet) or 'ego1' (mainnet)".into(),
        ));
    }
    // bech32 charset: a-z 0-9, no uppercase, no special characters
    if !addr.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err(EgoDesktopError::InvalidInput(
            "Invalid address: contains non-bech32 characters".into(),
        ));
    }
    Ok(())
}

// Tracks (attempt_count, expiry_ts) — entries expire 1 hour after first attempt.
static TX_ATTEMPTS: Lazy<Mutex<HashMap<String, (u32, i64)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

const MAX_PENDING_TXS: usize = 1_000;

#[derive(Debug, Serialize, Deserialize)]
pub struct Balance {
    pub egoc: u64,
    pub uegoc: u64,
    pub formatted: String,
    pub egusd: u64,
    pub uegusd: u64,
    pub pending_out_uegoc: u64,
    pub pending_in_uegoc: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendTransactionRequest {
    pub to_address: String,
    pub amount: u64,
    pub memo: Option<String>,
    pub is_private: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionResponse {
    pub hash: String,
    pub success: bool,
    pub message: String,
    pub block_height: Option<u64>,
    /// EGO-712: human-readable summary of what was actually signed.
    pub signed_summary: Option<String>,
}

#[tauri::command]
pub async fn get_balance(_state: State<'_, AppState>) -> Result<Balance, EgoDesktopError> {
    tokio::task::spawn_blocking(|| {
        let ledger  = Ledger::load();
        let my_addr = ledger.address.clone();

        if my_addr.is_empty() {
            return Ok(Balance { egoc: 0, uegoc: 0, formatted: "0.00 EGOC".into(), egusd: 0, uegusd: 0, pending_out_uegoc: 0, pending_in_uegoc: 0 });
        }

        let confirmed = crate::chain_db::balance_of(&my_addr);
        let pending_out: u64 = crate::mempool::get_mempool()
            .peek_all()
            .into_iter()
            .filter(|tx| tx.from.trim() == my_addr.trim())
            .map(|tx| tx.amount.saturating_add(tx.fee_uegoc))
            .sum();

        let pending_faucet_in: u64 = crate::mempool::get_mempool()
            .peek_all()
            .into_iter()
            .filter(|tx| tx.tx_type == "faucet" && tx.to.trim() == my_addr.trim())
            .map(|tx| tx.amount)
            .sum();

        let uegoc = confirmed.saturating_add(pending_faucet_in);
        let egoc  = uegoc / 1_000_000;

        let uegusd = ledger.balance_uegusd;
        let egusd  = uegusd / 1_000_000;

        Ok(Balance {
            egoc,
            uegoc,
            formatted: format!("{:.2} EGOC", uegoc as f64 / 1_000_000.0),
            egusd,
            uegusd,
            pending_out_uegoc: pending_out,
            pending_in_uegoc: pending_faucet_in,
        })
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
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
    let _guard = crate::ledger::TX_MUTEX.lock().await;
    let mut ledger = Ledger::load();
    let from = ledger.address.clone();

    if from.is_empty() {
        return Err(EgoDesktopError::WalletError(
            "Wallet not initialized – call init_wallet first".into(),
        ));
    }

    let confirmed_bal = crate::chain_db::balance_of(&from);
    let pending_out: u64 = crate::mempool::get_mempool()
        .peek_all()
        .into_iter()
        .filter(|tx| tx.from.trim() == from.trim())
        .map(|tx| tx.amount.saturating_add(tx.fee_uegoc))
        .sum();
    let balance = confirmed_bal.saturating_sub(pending_out);

    if request.amount == 0 {
        return Err(EgoDesktopError::InvalidInput("Amount must be > 0".into()));
    }
    validate_ego_address(&request.to_address)?;
    if request.to_address.trim() == from.trim() {
        return Err(EgoDesktopError::InvalidInput("Cannot send to your own address".into()));
    }
    if let Some(ref memo) = request.memo {
        if memo.len() > 256 {
            return Err(EgoDesktopError::InvalidInput("Memo too long (max 256 chars)".into()));
        }
    }
    let is_staker = ledger.staked_amount > 0;
    let fee = crate::tokenomics::fee_for_tx_with_staking("transfer", is_staker);
    let total_needed = request.amount.saturating_add(fee);
    if total_needed > balance {
        return Err(EgoDesktopError::InvalidInput(format!(
            "Insufficient balance: have {} uEGOC, need {} (amount {} + fee {}{})",
            balance, total_needed, request.amount, fee,
            if is_staker { " — staker rate" } else { "" }
        )));
    }

    let confirmed_nonce = crate::ledger::last_confirmed_nonce(&from);
    let nonce      = ledger.nonce.max(confirmed_nonce) + 1;
    let ts         = chrono::Utc::now().timestamp();
    let memo_str   = request.memo.as_deref().unwrap_or("");
    const CHAIN_ID: u8 = 1; // testnet
    let sign_bytes = tx_signing_bytes_v2(
        &from, &request.to_address, request.amount, nonce, ts, CHAIN_ID, memo_str,
    );

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

    let tx_hash     = format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex());
    let summary     = tx_human_summary(
        &from, &request.to_address, request.amount, memo_str, CHAIN_ID, nonce, fee,
    );

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
        fee_uegoc:           fee,
        tx_version:          2,
        chain_id:            CHAIN_ID,
        is_private:          request.is_private.unwrap_or(false) || request.amount >= SHIELD_THRESHOLD_UEGOC,
        signed_summary:      summary.clone(),
        ..LedgerTx::default()
    };

    eprintln!("[TX] {:.12} Pending — {:.16} → {:.16} {} uEGOC nonce={}",
        tx.hash, from, request.to_address, request.amount, nonce);
    crate::mempool::get_mempool().push(tx.clone());
    crate::commands::tx_pending::add(&tx);

    ledger.nonce = nonce;
    let _ = ledger.save();

    {
        let tx_gossip = tx.clone();
        tauri::async_runtime::spawn(async move {
            crate::p2p::broadcast_pending_tx(tx_gossip).await;
        });
    }

    {
        let to_email = ledger.registered_email.clone();
        if !to_email.is_empty() {
            let amount_egoc = format!("{:.6} EGOC", request.amount as f64 / 1_000_000.0);
            crate::email::send_tx_confirmation_when_mined(
                to_email, amount_egoc, request.to_address.clone(), tx_hash.clone(),
            );
        }
    }

    Ok(TransactionResponse {
        hash:           tx_hash,
        success:        true,
        message:        "Transaction queued — confirms within the next batch window".into(),
        block_height:   None,
        signed_summary: Some(summary),
    })
}

#[tauri::command]
pub async fn send_transaction_with_pin(
    request: SendTransactionRequest,
    pin: String,
    state: State<'_, AppState>,
) -> Result<TransactionResponse, EgoDesktopError> {
    let pin_trimmed = pin.trim().to_string();
    tokio::task::spawn_blocking(move || {
        crate::commands::auth::check_pin_for_tx(&pin_trimmed)
    })
    .await
    .map_err(|e| EgoDesktopError::WalletError(format!("PIN check task: {e}")))??;

    send_transaction(request, state).await
}

#[tauri::command]
pub async fn send_transaction_with_password(
    request: SendTransactionRequest,
    password: String,
    state: State<'_, AppState>,
) -> Result<TransactionResponse, EgoDesktopError> {
    send_transaction_with_pin(request, password, state).await
}

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
    let _guard = crate::ledger::TX_MUTEX.lock().await;
    let mut ledger = Ledger::load();
    let from = ledger.address.clone();
    if from.is_empty() {
        return Err(EgoDesktopError::WalletError("Wallet not initialized".into()));
    }
    let mut chain = load_chain();
    let confirmed_bal = chain.balance_of(&from);
    let pending_out: u64 = crate::mempool::get_mempool()
        .peek_all()
        .into_iter()
        .filter(|tx| tx.from.trim() == from.trim())
        .map(|tx| tx.amount.saturating_add(tx.fee_uegoc))
        .sum();
    let balance = confirmed_bal.saturating_sub(pending_out);
    if request.amount == 0 {
        return Err(EgoDesktopError::InvalidInput("Amount must be > 0".into()));
    }
    validate_ego_address(&request.to_address)?;
    if request.to_address.trim() == from.trim() {
        return Err(EgoDesktopError::InvalidInput("Cannot send to your own address".into()));
    }
    if let Some(ref memo) = request.memo {
        if memo.len() > 256 {
            return Err(EgoDesktopError::InvalidInput("Memo too long (max 256 chars)".into()));
        }
    }
    if request.amount > balance {
        return Err(EgoDesktopError::InvalidInput(format!(
            "Insufficient balance: have {} uEGOC, need {}", balance, request.amount
        )));
    }
    let is_staker  = ledger.staked_amount > 0;
    let fee        = crate::tokenomics::fee_for_tx_with_staking("transfer", is_staker);
    let confirmed_nonce_legacy = crate::ledger::last_confirmed_nonce(&from);
    let nonce      = ledger.nonce.max(confirmed_nonce_legacy) + 1;
    let ts         = chrono::Utc::now().timestamp();
    let memo_str   = request.memo.as_deref().unwrap_or("");
    const CHAIN_ID: u8 = 1; 
    let sign_bytes = tx_signing_bytes_v2(
        &from, &request.to_address, request.amount, nonce, ts, CHAIN_ID, memo_str,
    );
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
    let summary = tx_human_summary(
        &from, &request.to_address, request.amount, memo_str, CHAIN_ID, nonce, fee,
    );
    let tx = LedgerTx {
        hash: tx_hash.clone(), from: from.clone(), to: request.to_address.clone(),
        amount: request.amount, memo: request.memo.clone(), timestamp: ts,
        signature: signature_hex, status: "Pending".into(),
        block_height: None, nonce, public_key_ed25519: pubkey_hex,
        dilithium_pubkey: dil_pubkey_hex, dilithium_signature: dil_sig_hex,
        fee_uegoc: fee,
        tx_version: 2,
        chain_id: CHAIN_ID,
        is_private: request.is_private.unwrap_or(false) || request.amount >= SHIELD_THRESHOLD_UEGOC,
        signed_summary: summary.clone(),
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
// Called after user confirms via email. Verifies signatures before persisting.

#[tauri::command]
pub async fn commit_transaction(
    tx_json: String,
    block_json: String,
) -> Result<TransactionResponse, EgoDesktopError> {
    let _guard = crate::ledger::TX_MUTEX.lock().await;
    let mut tx: LedgerTx = serde_json::from_str(&tx_json)
        .map_err(|e| EgoDesktopError::WalletError(format!("Invalid tx JSON: {e}")))?;
    let block: LedgerBlock = serde_json::from_str(&block_json)
        .map_err(|e| EgoDesktopError::WalletError(format!("Invalid block JSON: {e}")))?;

    if block.height == 0 {
        return Err(EgoDesktopError::WalletError("Cannot commit a non-genesis transaction into block 0".into()));
    }

    if tx.block_height.is_some() && tx.block_height != Some(block.height) {
        return Err(EgoDesktopError::WalletError("Transaction block height does not match supplied block".into()));
    }

    let expected_hash = {
        let sign_bytes = if tx.tx_version >= 2 {
            tx_signing_bytes_v2(
                &tx.from,
                &tx.to,
                tx.amount,
                tx.nonce,
                tx.timestamp,
                tx.chain_id,
                tx.memo.as_deref().unwrap_or(""),
            )
        } else {
            tx_signing_bytes(&tx.from, &tx.to, tx.amount, tx.nonce, tx.timestamp)
        };
        format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex())
    };
    if tx.hash != expected_hash {
        return Err(EgoDesktopError::WalletError("Tx hash does not match signed content".into()));
    }

    crate::ledger::verify_confirmed_tx_sig(&tx)
        .map_err(EgoDesktopError::WalletError)?;

    tx.status = "Confirmed".to_string();
    tx.block_height = Some(block.height);

    if !crate::chain_db::verify_block_hash(&block, &[tx.clone()]) {
        return Err(EgoDesktopError::WalletError("Block hash does not match supplied transaction".into()));
    }

    let (tip_height, tip_hash) = crate::chain_db::latest_block_info();
    if block.height != tip_height.saturating_add(1) || block.prev_hash != tip_hash {
        return Err(EgoDesktopError::WalletError(format!(
            "Block is stale or out of sequence: expected height {} on top of {}",
            tip_height.saturating_add(1),
            tip_hash,
        )));
    }

    if block.tx_count != 1 {
        return Err(EgoDesktopError::WalletError("Email-confirm commit expects exactly one transaction in the block".into()));
    }

    let mut chain = load_chain();
    if let Some(existing) = chain.transactions.iter_mut().find(|t| t.hash == tx.hash) {

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
    let tx3 = tx.clone(); let blk3 = block.clone();
    tokio::spawn(async move { crate::p2p::broadcast_tx(tx3, blk3).await; });

    let tx4 = tx.clone();
    let blk4 = block.clone();
    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        let body = serde_json::json!({ "block": blk4, "transactions": [tx4] });
        crate::p2p::oracle_post_pub(&client, "/chain/submit", &body).await;
    });
    let summary = tx.signed_summary.clone();
    Ok(TransactionResponse {
        hash: tx_hash, success: true,
        message: "Transaction confirmed and broadcast".into(), block_height,
        signed_summary: Some(summary),
    })
}

#[tauri::command]
pub async fn get_transaction_history(
    _state: State<'_, AppState>,
) -> Result<Vec<LedgerTx>, EgoDesktopError> {
    tokio::task::spawn_blocking(|| {
        let ledger  = Ledger::load();
        let my_addr = ledger.address.clone();

        if my_addr.is_empty() {
            return Ok(vec![]);
        }

        let txs: Vec<LedgerTx> = crate::chain_db::get_tx_history_for_addr(&my_addr);
        
        let tip_height = crate::chain_db::latest_block_info().0;
        let finalized_h = crate::chain_db::finalized_height();
        let mut confirmed_hashes = std::collections::HashSet::new();
        let mut final_txs = Vec::with_capacity(txs.len());

        for mut tx in txs.into_iter() {
            // Filter out system spam to prevent burying real user transfers
            let is_spammy = tx.from == crate::chain_db::NODE_POOL_ADDR 
                && matches!(tx.tx_type.as_str(), "reward" | "coinbase" | "fee_distribution" | "post_reward");
            if is_spammy {
                continue;
            }

            if tx.is_private || tx.amount >= SHIELD_THRESHOLD_UEGOC || tx.from == "Shielded" || tx.to == "Shielded" {
                let i_am_sender   = tx.from == my_addr;
                let i_am_receiver = tx.to   == my_addr;
                if i_am_sender && !i_am_receiver {
                    tx.to = "Shielded".to_string();
                } else if i_am_receiver && !i_am_sender {
                    tx.from = "Shielded".to_string();
                } else {
                    tx.from = "Shielded".to_string();
                    tx.to   = "Shielded".to_string();
                }
                tx.memo = Some("Privacy Protected".to_string());
            }

            confirmed_hashes.insert(tx.hash.clone());
            let is_receiver = tx.to == my_addr && tx.from != my_addr;
            let is_faucet = tx.tx_type == "faucet";
            let mut is_fully_confirmed = false;

            if let Some(h) = tx.block_height {
                if h <= finalized_h || h == 0 {
                    tx.status = "Confirmed".into();
                    is_fully_confirmed = true;
                } else {
                    // In a block that hasn't reached quorum finality yet (or a
                    // QC-less bootstrap block): show real pipeline progress —
                    // 2/3 = included, waiting on the finality marker. With BFT
                    // this window is typically well under a second.
                    let confs = tip_height.saturating_sub(h) + 1;
                    if confs >= 3 {
                        tx.status = "Confirmed".into();
                        is_fully_confirmed = true;
                    } else {
                        tx.status = format!("Confirming ({}/3)", confs.min(2));
                    }
                }
            } else {
                // Signed and broadcast, waiting for the network to include it in
                // a block. Sitting here means consensus isn't producing blocks
                // (e.g. no quorum) — exactly the signal users should see.
                tx.status = "Confirming (0/3)".into();
            }

            if is_receiver && !is_faucet && !is_fully_confirmed {
                continue; // Hide from receiver until fully confirmed
            }

            final_txs.push(tx);
        }

        let now = chrono::Utc::now().timestamp();
        let pool_txs = crate::mempool::get_mempool().pending_txs_for_address(&my_addr);
        let file_txs = crate::commands::tx_pending::get_all();

        for mut tx in pool_txs.into_iter().chain(file_txs.into_iter()) {
            if (tx.from == my_addr || tx.to == my_addr) && !confirmed_hashes.contains(&tx.hash) {
                let is_receiver = tx.to == my_addr && tx.from != my_addr;
                
                if tx.is_private || tx.amount >= SHIELD_THRESHOLD_UEGOC {
                    if tx.from == my_addr && tx.to != my_addr {
                        tx.to = "Shielded".to_string();
                    } else if tx.to == my_addr && tx.from != my_addr {
                        tx.from = "Shielded".to_string();
                    } else {
                        tx.from = "Shielded".to_string();
                        tx.to   = "Shielded".to_string();
                    }
                    tx.memo = Some("Privacy Protected".to_string());
                }

                let is_faucet = tx.tx_type == "faucet";
                if is_receiver && !is_faucet {
                    continue; // Hide unconfirmed inbound transfers from the receiver's UI
                }

                confirmed_hashes.insert(tx.hash.clone());
                if now - tx.timestamp >= 1800 { // 30 mins
                    tx.status = "Failed".into();
                } else {
                    tx.status = "Confirming (0/3)".into();
                }
                tx.block_height = None;
                final_txs.push(tx);
            }
        }

        final_txs.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        final_txs.truncate(500);
        Ok(final_txs)
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

// ── fetch_swap_rates ──────────────────────────────────────────────────────────

fn binance_sym_to_cg_id(sym: &str) -> Option<&'static str> {
    match sym {
        "BTCUSDT"   => Some("bitcoin"),
        "ETHUSDT"   => Some("ethereum"),
        "BNBUSDT"   => Some("binancecoin"),
        "SOLUSDT"   => Some("solana"),
        "ADAUSDT"   => Some("cardano"),
        "XRPUSDT"   => Some("ripple"),
        "TRXUSDT"   => Some("tron"),
        "LTCUSDT"   => Some("litecoin"),
        "DOGEUSDT"  => Some("dogecoin"),
        "MATICUSDT" => Some("matic-network"),
        "AVAXUSDT"  => Some("avalanche-2"),
        "ARBUSDT"   => Some("arbitrum"),
        "OPUSDT"    => Some("optimism"),
        "DOTUSDT"   => Some("polkadot"),
        "LINKUSDT"  => Some("chainlink"),
        "SHIBUSDT"  => Some("shiba-inu"),
        _ => None,
    }
}

/// Fetch live USD prices using Binance public API (free, 1200 req/min, no key).
/// Falls back to CoinGecko if Binance fails. Returns HashMap keyed by CoinGecko ID.
#[tauri::command]
pub async fn fetch_swap_rates() -> Result<std::collections::HashMap<String, f64>, EgoDesktopError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    // Try Binance first (high rate limits, no API key)
    let binance_symbols = r#"["BTCUSDT","ETHUSDT","BNBUSDT","SOLUSDT","ADAUSDT","XRPUSDT","TRXUSDT","LTCUSDT","DOGEUSDT","MATICUSDT","AVAXUSDT","ARBUSDT","OPUSDT","DOTUSDT","LINKUSDT","SHIBUSDT"]"#;
    let binance_url = format!("https://api.binance.com/api/v3/ticker/price?symbols={}", binance_symbols);

    if let Ok(resp) = client.get(&binance_url).send().await {
        if let Ok(json) = resp.json::<serde_json::Value>().await {
            if let Some(arr) = json.as_array() {
                let mut rates = std::collections::HashMap::new();
                for item in arr {
                    if let (Some(sym), Some(price_str)) = (item["symbol"].as_str(), item["price"].as_str()) {
                        if let (Some(id), Ok(price)) = (binance_sym_to_cg_id(sym), price_str.parse::<f64>()) {
                            rates.insert(id.to_string(), price);
                        }
                    }
                }
                if !rates.is_empty() {
                    rates.insert("tether".into(), 1.0);
                    rates.insert("usd-coin".into(), 1.0);
                    return Ok(rates);
                }
            }
        }
    }

    // Fallback: CoinGecko
    let cg_url = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,ethereum,binancecoin,cardano,solana,ripple,tron,polkadot,chainlink,shiba-inu,tether,usd-coin,litecoin,dogecoin,matic-network,avalanche-2,arbitrum,optimism&vs_currencies=usd";
    let json: serde_json::Value = client.get(cg_url).send().await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?
        .json().await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?;

    let mut rates = std::collections::HashMap::new();
    for (id, data) in json.as_object().into_iter().flatten() {
        if let Some(price) = data["usd"].as_f64() {
            rates.insert(id.clone(), price);
        }
    }
    Ok(rates)
}

// ── query_remote_node ─────────────────────────────────────────────────────────
//
// Queries a headless ego-node's HTTP RPC and returns its identity + balance.

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
    #[serde(skip_serializing)] // Privacy: Mask internal RPC routing from frontend
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

// ── request_tx_code ───────────────────────────────────────────────────────────
//
/// Return the email stored in the local ledger, masked for display.
/// e.g. "abc***@domain.com". Returns empty string if no email is set.
#[derive(serde::Serialize)]
pub struct TxFeeInfo {
    pub fee_uegoc: u64,
    pub fee_usd:   f64,
}

#[tauri::command]
pub fn get_tx_fee(tx_type: Option<String>) -> TxFeeInfo {
    let ledger    = Ledger::load();
    let is_staker = ledger.staked_amount > 0;
    let fee_uegoc = crate::tokenomics::fee_for_tx_with_staking(
        tx_type.as_deref().unwrap_or("transfer"),
        is_staker,
    );
    let price   = crate::p2p::get_egoc_price_usd().max(1e-9);
    let fee_usd = (fee_uegoc as f64 / 1_000_000.0) * price;
    TxFeeInfo { fee_uegoc, fee_usd }
}

#[tauri::command]
pub fn clear_pending_transactions() {
    crate::commands::tx_pending::clear();
    crate::mempool::get_mempool().clear();
    // Also purge Pending-status entries from the legacy JSON ledger so
    // they stop appearing in the transaction list after a chain reset.
    let mut chain = crate::ledger::load_chain();
    let before = chain.transactions.len();
    chain.transactions.retain(|tx| tx.status != "Pending");
    if chain.transactions.len() != before {
        let _ = crate::ledger::save_chain(&chain);
    }
}

#[tauri::command]
pub fn get_account_email() -> String {
    let email = Ledger::load().registered_email;
    if email.is_empty() { return String::new(); }
    if let Some(at) = email.find('@') {
        let visible = email[..at.min(3)].to_string();
        format!("{}***{}", visible, &email[at..])
    } else {
        "***".to_string()
    }
}

// Step 1 of email 2FA: validate + sign the tx, store it pending, email a code.
// Returns { tx_id, masked_email } — frontend shows the code-entry modal.

#[derive(Debug, Serialize)]
pub struct TxCodeRequest {
    pub tx_id:        String,
    pub masked_email: String,
}

#[tauri::command]
pub async fn request_tx_code(
    request: SendTransactionRequest,
    state: State<'_, AppState>,
) -> Result<TxCodeRequest, EgoDesktopError> {
    let _guard = crate::ledger::TX_MUTEX.lock().await;
    validate_ego_address(&request.to_address)?;
    if let Some(ref memo) = request.memo {
        if memo.len() > 256 {
            return Err(EgoDesktopError::InvalidInput("Memo too long (max 256 chars)".into()));
        }
    }

    let kp = match state.get_keypair() {
        Some(k) => k,
        None    => return Err(EgoDesktopError::WalletError("Wallet not initialized".into())),
    };

    let to_address = request.to_address.clone();
    let amount     = request.amount;
    let memo_opt   = request.memo.clone();

    let (tx_id, masked_email, email_bg, code_bg, amount_bg, recipient_bg) =
        tokio::task::spawn_blocking(move || -> Result<(String, String, String, String, String, String), EgoDesktopError> {
            const CHAIN_ID_2FA: u8 = 1;

            let ledger = Ledger::load();
            let from   = ledger.address.clone();
            let email  = ledger.registered_email.clone();

            if from.is_empty() {
                return Err(EgoDesktopError::WalletError("Wallet not initialized".into()));
            }
            if to_address.trim() == from.trim() {
                return Err(EgoDesktopError::InvalidInput("Cannot send to your own address".into()));
            }
            if email.is_empty() {
                return Err(EgoDesktopError::InvalidInput(
                    "No email on file. Set an email in Settings to use 2FA.".into(),
                ));
            }
            if amount == 0 {
                return Err(EgoDesktopError::InvalidInput("Amount must be > 0".into()));
            }

            let confirmed_bal = crate::chain_db::balance_of(&from);
            let pending_out: u64 = crate::mempool::get_mempool()
                .peek_all()
                .into_iter()
                .filter(|tx| tx.from.trim() == from.trim())
                .map(|tx| tx.amount.saturating_add(tx.fee_uegoc))
                .sum();
            let balance      = confirmed_bal.saturating_sub(pending_out);
            let is_staker    = ledger.staked_amount > 0;
            let fee          = crate::tokenomics::fee_for_tx_with_staking("transfer", is_staker);
            let total_needed = amount.saturating_add(fee);
            if total_needed > balance {
                return Err(EgoDesktopError::InvalidInput(format!(
                    "Insufficient balance: have {} uEGOC, need {} (amount {} + fee {})",
                    balance, total_needed, amount, fee
                )));
            }

            let confirmed_nonce = crate::ledger::last_confirmed_nonce(&from);
            let ts = chrono::Utc::now().timestamp();
            let pending_max_nonce: u64 = {
                let map = PENDING_TXS.lock().unwrap_or_else(|e| e.into_inner());
                map.values()
                    .filter(|(pending_tx, exp)| pending_tx.from == from && *exp > ts)
                    .map(|(pending_tx, _)| pending_tx.nonce)
                    .max()
                    .unwrap_or(0)
            };
            let memo_str = memo_opt.as_deref().unwrap_or("");
            let nonce = ledger.nonce.max(confirmed_nonce).max(pending_max_nonce) + 1;
            if pending_max_nonce > 0 && nonce <= pending_max_nonce {
                return Err(EgoDesktopError::InvalidInput(
                    "Too many pending transactions. Please wait for some to confirm first.".into(),
                ));
            }
            let sign_bytes = tx_signing_bytes_v2(
                &from, &to_address, amount, nonce, ts, CHAIN_ID_2FA, memo_str,
            );

            let hrp = if CHAIN_ID_2FA == 1 { "egot" } else { "ego" };
            let ed_sig      = kp.sign_ed25519(&sign_bytes);
            let dil_sig     = kp.sign_dilithium(&sign_bytes);
            let sig_hex     = hex::encode(ed_sig.as_bytes());
            let pk_hex      = hex::encode(kp.ed25519_public_key().as_bytes());
            let dil_sig_raw = hex::encode(&dil_sig.signature_data);
            let dil_pk_raw  = hex::encode(&kp.dilithium_public_key().key_data);

            let dil_bytes    = hex::decode(&dil_pk_raw).unwrap_or_default();
            let dil_expected = ego_core::EgoAddress::from_dilithium_pk(
                &dil_bytes, CHAIN_ID_2FA as u32, ego_core::AddressType::EOA,
            ).to_bech32(hrp).unwrap_or_default();
            let (dil_pk_hex, dil_sig_hex) = if dil_expected == from {
                (dil_pk_raw, dil_sig_raw)
            } else {
                (String::new(), String::new())
            };

            let tx_hash = format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex());
            let summary = tx_human_summary(
                &from, &to_address, amount, memo_str, CHAIN_ID_2FA, nonce, fee,
            );
            let tx = LedgerTx {
                hash:                tx_hash.clone(),
                from:                from.clone(),
                to:                  to_address.clone(),
                amount,
                memo:                memo_opt.clone(),
                timestamp:           ts,
                signature:           sig_hex,
                status:              "Pending".into(),
                block_height:        None,
                nonce,
                public_key_ed25519:  pk_hex,
                dilithium_pubkey:    dil_pk_hex,
                dilithium_signature: dil_sig_hex,
                fee_uegoc:           fee,
                tx_version:          2,
                chain_id:            CHAIN_ID_2FA,
                is_private:          request.is_private.unwrap_or(false) || amount >= SHIELD_THRESHOLD_UEGOC,
                signed_summary:      summary,
                ..LedgerTx::default()
            };

            crate::email::check_send_limit(&email).map_err(EgoDesktopError::InvalidInput)?;

            let code   = crate::email::gen_otp_code();
            let tx_id  = tx_hash.clone();
            let expiry = ts + 600;

            crate::email::store_otp(&format!("tx:{}", tx_id), &code);
            {
                let mut map = PENDING_TXS.lock().unwrap_or_else(|e| e.into_inner());
                map.retain(|_, (_, exp)| *exp > ts);
                if map.len() >= MAX_PENDING_TXS {
                    return Err(EgoDesktopError::InvalidInput(
                        "Too many pending transactions. Please wait and try again.".into(),
                    ));
                }
                crate::chain_db::persist_pending_otptx(&tx_id, &tx, expiry);
                map.insert(tx_id.clone(), (tx, expiry));
            }
            crate::email::record_send_attempt(&email);

            let masked = if let Some(at) = email.find('@') {
                let local  = &email[..at];
                let domain = &email[at..];
                if local.len() > 3 {
                    format!("{}***{}", &local[..2], domain)
                } else {
                    format!("{}***{}", &local[..1], domain)
                }
            } else {
                "***".to_string()
            };

            let amount_str = format!("{:.6} EGOC", amount as f64 / 1_000_000.0);
            Ok((tx_id, masked, email, code, amount_str, to_address))
        }).await.map_err(|e| EgoDesktopError::WalletError(format!("TX code task: {e}")))??;

    tokio::spawn(async move {
        if let Err(e) = crate::email::send_tx_code_email(&email_bg, &code_bg, &amount_bg, &recipient_bg).await {
            eprintln!("[Email] TX code send failed for {}: {}", &email_bg, e);
        }
    });

    Ok(TxCodeRequest { tx_id, masked_email })
}

#[tauri::command]
pub async fn confirm_tx_code(
    tx_id: String,
    code:  String,
) -> Result<TransactionResponse, EgoDesktopError> {
    let _guard = crate::ledger::TX_MUTEX.lock().await;
    let code_trimmed = code.trim().to_string();

    let tx_id_for_block = tx_id.clone();
    let tx = tokio::task::spawn_blocking(move || -> Result<LedgerTx, EgoDesktopError> {
        let valid = crate::email::verify_otp(&format!("tx:{}", tx_id_for_block), &code_trimmed);
        if !valid {
            let now_ts = chrono::Utc::now().timestamp();
            let attempts = {
                let mut map = TX_ATTEMPTS.lock().unwrap_or_else(|e| e.into_inner());
                map.retain(|_, (_, exp)| *exp > now_ts);
                let entry = map.entry(tx_id_for_block.clone()).or_insert((0, now_ts + 3_600));
                entry.0 += 1;
                entry.0
            };
            if attempts >= 3 {
                PENDING_TXS.lock().unwrap_or_else(|e| e.into_inner()).remove(&tx_id_for_block);
                crate::chain_db::remove_pending_otptx(&tx_id_for_block);
                TX_ATTEMPTS.lock().unwrap_or_else(|e| e.into_inner()).remove(&tx_id_for_block);
                return Err(EgoDesktopError::InvalidInput(
                    "Too many failed attempts. Transaction has been cancelled.".into(),
                ));
            }
            return Err(EgoDesktopError::InvalidInput(format!(
                "Incorrect code. {} attempt{} remaining.",
                3 - attempts,
                if 3 - attempts == 1 { "" } else { "s" }
            )));
        }

        TX_ATTEMPTS.lock().unwrap_or_else(|e| e.into_inner()).remove(&tx_id_for_block);
        let email = Ledger::load().registered_email;
        if !email.is_empty() { crate::email::reset_send_attempts(&email); }

        let tx = {
            let mut map = PENDING_TXS.lock().unwrap_or_else(|e| e.into_inner());
            let now = chrono::Utc::now().timestamp();
            match map.remove(&tx_id_for_block) {
                Some((tx, exp)) if exp > now => {
                    crate::chain_db::remove_pending_otptx(&tx_id_for_block);
                    tx
                }
                Some(_) => {
                    crate::chain_db::remove_pending_otptx(&tx_id_for_block);
                    return Err(EgoDesktopError::InvalidInput(
                        "Transaction request expired. Please start over.".into(),
                    ));
                }
                None => return Err(EgoDesktopError::InvalidInput(
                    "Transaction not found. It may have already been submitted or expired.".into(),
                )),
            }
        };

        let mut ledger = Ledger::load();
        if tx.nonce > ledger.nonce {
            ledger.nonce = tx.nonce;
            let _ = ledger.save();
        }

        Ok(tx)
    }).await.map_err(|e| EgoDesktopError::WalletError(format!("TX confirm task: {e}")))??;

    let tx_hash = tx.hash.clone();
    let to_addr = tx.to.clone();
    let amount  = tx.amount;
    let from_addr = tx.from.clone();

    let bal_before = crate::chain_db::balance_of(&from_addr);
    eprintln!("[TX] confirm_tx_code: pushing {:.12} to mempool — addr={:.16} bal_before={} nonce={}",
        tx.hash, from_addr, bal_before, tx.nonce);
    crate::mempool::get_mempool().push(tx.clone());
    eprintln!("[TX] confirm_tx_code: mempool push done — {:.12}", tx.hash);
    crate::commands::tx_pending::add(&tx);

    let to_email = Ledger::load().registered_email;
    if !to_email.is_empty() {
        let amount_str = format!("{:.6} EGOC", tx.amount as f64 / 1_000_000.0);
        crate::email::send_tx_confirmation_when_mined(
            to_email, amount_str, tx.to.clone(), tx.hash.clone(),
        );
    }

    let tx_broadcast = tx.clone();
    tauri::async_runtime::spawn(async move {
        crate::p2p::broadcast_pending_tx(tx_broadcast).await;
    });

    let summary = tx.signed_summary.clone();
    Ok(TransactionResponse {
        hash:           tx_hash,
        success:        true,
        message:        format!("Transaction to {} for {:.6} EGOC queued", &to_addr[..12.min(to_addr.len())], amount as f64 / 1_000_000.0),
        block_height:   None,
        signed_summary: Some(summary),
    })
}

// ── ChangeNow real swap integration ───────────────────────────────────────────

// The ChangeNow key is NOT in this binary. It lives on the payments proxy
// (services/presale-proxy), which owns the symbol→network mapping too, so
// adding a coin is a server deploy rather than a new app release.

#[derive(Debug, Serialize, Deserialize)]
pub struct CnEstimate {
    pub to_amount:       f64,
    pub min_amount:      f64,
    pub network_fee:     f64,   // in destination currency
    pub network_fee_usd: f64,
}

/// Get estimated output amount from ChangeNow for an external↔external pair.
#[tauri::command]
pub async fn changenow_estimate(
    from_symbol: String,
    to_symbol:   String,
    from_amount: f64,
) -> Result<CnEstimate, EgoDesktopError> {
    let url = format!(
        "{}/swap/estimate?from={}&to={}&amount={}",
        payments_proxy_base(),
        url_escape(&from_symbol.to_lowercase()),
        url_escape(&to_symbol.to_lowercase()),
        from_amount,
    );

    let est: serde_json::Value = proxy_client()
        .get(&url)
        .send().await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?
        .json().await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?;

    if let Some(err) = proxy_error(&est) {
        return Err(err);
    }

    let to_amount = est["to_amount"].as_f64()
        .ok_or_else(|| EgoDesktopError::NetworkError("Invalid response from swap service".into()))?;

    Ok(CnEstimate {
        to_amount,
        min_amount:      est["min_amount"].as_f64().unwrap_or(0.0),
        network_fee:     est["network_fee"].as_f64().unwrap_or(0.0),
        network_fee_usd: est["network_fee_usd"].as_f64().unwrap_or(0.0),
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CnExchange {
    pub id:               String,
    pub deposit_address:  String,
    pub deposit_extra_id: Option<String>,
    pub to_amount:        f64,
}

/// Create a real ChangeNow exchange. Returns the deposit address the user must send to.
#[tauri::command]
pub async fn changenow_create_exchange(
    from_symbol: String,
    to_symbol:   String,
    from_amount: f64,
    to_address:  String,
) -> Result<CnExchange, EgoDesktopError> {
    let body = serde_json::json!({
        "from":       from_symbol.to_lowercase(),
        "to":         to_symbol.to_lowercase(),
        "amount":     from_amount,
        "to_address": to_address,
    });

    let resp: serde_json::Value = proxy_client()
        .post(format!("{}/swap/create", payments_proxy_base()))
        .json(&body)
        .send().await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?
        .json().await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?;

    if let Some(err) = proxy_error(&resp) {
        return Err(err);
    }

    Ok(CnExchange {
        id:               resp["id"].as_str().unwrap_or("").to_string(),
        deposit_address:  resp["deposit_address"].as_str().unwrap_or("").to_string(),
        deposit_extra_id: resp["deposit_extra_id"].as_str().map(|s| s.to_string()),
        to_amount:        resp["to_amount"].as_f64().unwrap_or(0.0),
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CnStatus {
    pub status:    String,
    pub to_amount: Option<f64>,
    pub hash_out:  Option<String>,
}

/// Poll the status of a ChangeNow exchange by ID.
#[tauri::command]
pub async fn changenow_get_status(
    exchange_id: String,
) -> Result<CnStatus, EgoDesktopError> {
    let url = format!(
        "{}/swap/status/{}",
        payments_proxy_base(),
        url_escape(&exchange_id),
    );
    let resp: serde_json::Value = proxy_client()
        .get(&url)
        .send().await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?
        .json().await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?;

    if let Some(err) = proxy_error(&resp) {
        return Err(err);
    }

    Ok(CnStatus {
        status:    resp["status"].as_str().unwrap_or("unknown").to_string(),
        to_amount: resp["to_amount"].as_f64(),
        hash_out:  resp["hash_out"].as_str().map(|s| s.to_string()),
    })
}

// ── Pre-sale IOU system ────────────────────────────────────────────────────────
// No tokens exist yet. Buyers receive an encrypted IOU wallet file as proof of
// purchase. All allocations are written into the Ego Chain Genesis Block when
// mainnet launches.

/// Last price fetched from the proxy. Only ever written by
/// `get_presale_config`; the local paths below read it so an IOU is never
/// written at a price the buyer was not shown.
static PRESALE_PRICE_USD: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn cached_presale_price() -> Option<f64> {
    let bits = PRESALE_PRICE_USD.load(std::sync::atomic::Ordering::Relaxed);
    if bits == 0 { return None; }
    let p = f64::from_bits(bits);
    if p.is_finite() && p > 0.0 { Some(p) } else { None }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PresaleConfig {
    pub price_usd:    f64,
    pub launch_usd:   f64,
    pub discount_pct: i64,
    pub tier_label:   String,
    pub tier_index:   u32,
    pub tier_count:   u32,
}

/// Fetch the live pre-sale price. This is the ONLY source — the UI quotes it
/// and the IOU is written from it, so they cannot disagree.
///
/// Deliberately has no hardcoded fallback: if the price is unknown, the UI
/// disables buying rather than guessing. Quoting a stale price at a buyer is
/// how the previous 4x under-allocation happened.
#[tauri::command]
pub async fn get_presale_config() -> Result<PresaleConfig, EgoDesktopError> {
    let resp = proxy_client()
        .get(format!("{}/presale/config", payments_proxy_base()))
        .send().await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?;

    let json: serde_json::Value = resp.json().await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?;

    if let Some(err) = proxy_error(&json) {
        return Err(err);
    }

    let price_usd = json["price_usd"].as_f64().unwrap_or(0.0);
    if !(price_usd.is_finite() && price_usd > 0.0) {
        return Err(EgoDesktopError::NetworkError(
            "Pre-sale price unavailable — please try again shortly".into(),
        ));
    }
    PRESALE_PRICE_USD.store(price_usd.to_bits(), std::sync::atomic::Ordering::Relaxed);

    Ok(PresaleConfig {
        price_usd,
        launch_usd:   json["launch_usd"].as_f64().unwrap_or(0.0),
        discount_pct: json["discount_pct"].as_i64().unwrap_or(0),
        tier_label:   json["tier_label"].as_str().unwrap_or("").to_string(),
        tier_index:   json["tier_index"].as_u64().unwrap_or(0) as u32,
        tier_count:   json["tier_count"].as_u64().unwrap_or(1) as u32,
    })
}

/// Price for the local (crypto-deposit) IOU paths. Errors rather than assuming
/// a value — an IOU written at the wrong price is a debt to the buyer.
fn presale_price_or_err() -> Result<f64, EgoDesktopError> {
    cached_presale_price().ok_or_else(|| EgoDesktopError::NetworkError(
        "Pre-sale price not loaded yet — open the Pre-Sale panel and try again".into(),
    ))
}

/// Returns the Ego team's treasury address for the given payment coin.
/// Funds sent here go directly to the presale treasury wallet.
fn presale_deposit_addr(pay_symbol: &str) -> String {
    match pay_symbol {
        "BTC"  => "bc1qaqx0xf9sv0ktmtcxlzzh7t7kf59nwu8c0vlqhg",
        "ETH"  => "0xD4f2B1fA44668B806290A4c3CB758ABb7EF35C64",
        "USDT" => "0xD4f2B1fA44668B806290A4c3CB758ABb7EF35C64",
        "USDC" => "0xD4f2B1fA44668B806290A4c3CB758ABb7EF35C64",
        "BNB"  => "0xD4f2B1fA44668B806290A4c3CB758ABb7EF35C64",
        "ADA"  => "addr1qyp35j52jw8tmg85wvll3p5krsgkpttxa65kxav4mc56g73fmcra587acj9n8zsqm8u55zvumpff3mrkt9865jswu4gql452dd",
        "SOL"  => "9PZzHQYohiR9fTKTJXUaRYKv6doM4NQPJZKcrVvTJbbW",
        "TRX"  => "TSZnnQGN8idN6vEU66NX1ek1AtwmHbYLRx",
        _      => "— contact support@egoblockchain.com —",
    }.to_string()
}

/// Create an encrypted IOU file (Ethereum-style) for a pre-sale purchase.
/// Returns the IOU as a JSON string ready for the user to download and keep.
/// The plaintext allocation data is only readable by the buyer (password-protected).
#[tauri::command]
pub async fn presale_create_iou(
    pay_symbol:    String,
    pay_amount:    f64,
    pay_usd_price: f64,
    password:      String,
) -> Result<String, EgoDesktopError> {
    let ledger = Ledger::load();
    if ledger.mainnet_address.is_empty() {
        return Err(EgoDesktopError::WalletError(
            "Wallet not initialised — mainnet address missing".into(),
        ));
    }
    if password.trim().is_empty() {
        return Err(EgoDesktopError::WalletError("Password cannot be empty".into()));
    }

    let presale_price = presale_price_or_err()?;
    let usd_value   = pay_amount * pay_usd_price;
    let egoc_amount = usd_value / presale_price;
    let deposit_addr = presale_deposit_addr(&pay_symbol);
    let id  = uuid::Uuid::new_v4().to_string();
    let ts  = chrono::Utc::now().timestamp();

    // ── Plaintext record (encrypted inside the IOU file) ─────────────────────
    let plain = serde_json::json!({
        "id":                id,
        "mainnet_address":   ledger.mainnet_address,
        "testnet_address":   ledger.address,
        "egoc_amount":       egoc_amount,
        "usd_value":         usd_value,
        "price_per_egoc":    presale_price,
        "pay_coin":          pay_symbol,
        "pay_amount":        pay_amount,
        "deposit_address":   deposit_addr,
        "timestamp":         ts,
        "round":             "Seed Round",
    });
    let plain_bytes = serde_json::to_vec(&plain)
        .map_err(|e| EgoDesktopError::WalletError(e.to_string()))?;

    // ── Key derivation: BLAKE3(password_bytes ‖ salt) → 32-byte key ──────────
    let mut salt        = [0u8; 32];
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);

    let kdf_input: Vec<u8> = password.as_bytes().iter().chain(&salt).copied().collect();
    let derived   = blake3::hash(&kdf_input);

    let key    = Key::<Aes256Gcm>::from_slice(derived.as_bytes());
    let cipher = Aes256Gcm::new(key);
    let nonce  = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plain_bytes.as_slice())
        .map_err(|e| EgoDesktopError::CryptoError(e.to_string()))?;

    // ── Outer IOU file (public metadata + encrypted seed) ────────────────────
    let iou = serde_json::json!({
        "version":     1,
        "id":          id,
        "ego_presale": true,
        "network":     "ego-mainnet",
        "issued_at":   ts,
        "round":       "Seed Round",
        "payment": {
            "coin":            pay_symbol,
            "deposit_address": deposit_addr,
            "amount":          pay_amount
        },
        "allocation": {
            "egoc_amount":        egoc_amount,
            "usd_value":          usd_value,
            "price_per_egoc_usd": presale_price
        },
        "genesis_note": "This allocation will be credited in the Ego Chain Genesis Block upon mainnet launch. Keep this file and your password — they are your proof of purchase.",
        "crypto": {
            "cipher":     "aes-256-gcm",
            "kdf":        "blake3",
            "salt":       hex::encode(&salt),
            "nonce":      hex::encode(&nonce_bytes),
            "ciphertext": hex::encode(&ciphertext)
        }
    });

    // ── Persist record locally ────────────────────────────────────────────────
    let record = PresaleIouRecord {
        id:              id.clone(),
        mainnet_address: ledger.mainnet_address.clone(),
        egoc_amount,
        usd_value,
        pay_symbol,
        pay_amount,
        deposit_address: deposit_addr,
        timestamp:       ts,
        status:          "pending_payment".into(),
    };
    let mut ledger2 = Ledger::load();
    ledger2.presale_records.push(record);
    let _ = ledger2.save();

    serde_json::to_string_pretty(&iou)
        .map_err(|e| EgoDesktopError::WalletError(e.to_string()))
}

#[derive(Debug, Serialize)]
pub struct ReservationConnectInfo {
    pub reservation_id: String,
    pub status: String,
    pub provider_ip: String,
    pub ssh_command: String,
    pub note: String,
    pub how_to_verify: String,
}

#[tauri::command]
pub async fn get_reservation_connect_info(
    reservation_id: String,
) -> Result<ReservationConnectInfo, EgoDesktopError> {
    let res = tokio::task::spawn_blocking(move || {
        crate::chain_db::get_compute_reservation(&reservation_id)
    })
    .await
    .map_err(|e| EgoDesktopError::WalletError(e.to_string()))?
    .ok_or_else(|| EgoDesktopError::InvalidInput("Reservation not found".into()))?;

    let provider_addr = res.provider_address.clone();

    // Try to resolve the endpoint from the compute node registry first
    let endpoint = if let Some(node) = tokio::task::spawn_blocking({
        let addr = provider_addr.clone();
        move || crate::chain_db::get_compute_node(&addr)
    }).await.map_err(|e| EgoDesktopError::WalletError(e.to_string()))? {
        node.endpoint
    } else {
        // Fallback to general P2P registry or DHT lookup if compute-specific record was pruned
        crate::p2p::get_relay_endpoint(&provider_addr).await
            .ok_or_else(|| EgoDesktopError::InvalidInput("Provider node info not found. The node may be offline.".into()))?
    };

    let ip = endpoint.split('/').nth(2).unwrap_or("127.0.0.1");

    let is_relay = ip.contains("egoblockchain.com");
    let how_to = if is_relay {
        "The provider is behind a firewall/NAT. Direct SSH is blocked. They must enable Port Forwarding (Port 22) or use a direct IP to allow standard SSH clients to connect.".to_string()
    } else {
        "1. Click 'Launch SSH Terminal'. 2. If you see 'Permission denied', click the 'SSH Key' button in the Compute tab, copy your key, and send it to the provider so they can authorize your computer.".to_string()
    };

    Ok(ReservationConnectInfo {
        reservation_id: res.reservation_id,
        status: res.status,
        provider_ip: ip.to_string(),
        // Return a simple destination. The open_ssh_terminal command adds the 
        // identity, security, and hardware report flags automatically.
        ssh_command: format!("ssh root@{}", ip),
        note: if is_relay { "⚠ Warning: Connecting to Relay. Direct access to provider is likely blocked." } else { "Note: The provider must have Port 22 open." }.to_string(),
        how_to_verify: how_to,
    })
}

#[tauri::command]
pub async fn terminate_reservation_early(
    reservation_id: String,
    app:            tauri::AppHandle,
) -> Result<(), EgoDesktopError> {
    let my_addr = crate::ledger::Ledger::load().address;
    let mut res = crate::chain_db::get_compute_reservation(&reservation_id)
        .ok_or_else(|| EgoDesktopError::NotFound("Reservation not found".into()))?;

    if res.buyer_address != my_addr {
        return Err(EgoDesktopError::PermissionDenied("Not your reservation".into()));
    }
    if res.status != "active" {
        return Err(EgoDesktopError::InvalidInput(format!("Cannot terminate {} reservation", res.status)));
    }

    let penalty = res.period_rate_uegoc.min(res.escrow_remaining);
    let refund = res.escrow_remaining.saturating_sub(penalty);
    let ts = chrono::Utc::now().timestamp();

    // Pay penalty to provider
    if penalty > 0 {
        // crate::chain_db::internal_balance_transfer(crate::chain_db::RESERVATION_ESCROW_ADDR, &res.provider_address, penalty);
        
        let memo = format!("early_termination_penalty:{}", reservation_id);
        let sign_bytes = crate::ledger::tx_signing_bytes_v2(crate::chain_db::RESERVATION_ESCROW_ADDR, &res.provider_address, penalty, 0, ts, 1, &memo);
        let hash = format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex());
        let _ = crate::mempool::get_mempool().push(crate::ledger::LedgerTx {
            hash,
            from:      crate::chain_db::RESERVATION_ESCROW_ADDR.to_string(),
            to:        res.provider_address.clone(),
            amount:    penalty,
            memo:      Some(memo),
            timestamp: ts,
            signature: "system".to_string(),
            status:    "Pending".into(),
            nonce:     0,
            tx_type:   "early_termination_penalty".to_string(),
            tx_version: 2,
            chain_id:   1,
            ..crate::ledger::LedgerTx::default()
        });
    }

    // Refund remainder to buyer
    if refund > 0 {
        // crate::chain_db::internal_balance_transfer(crate::chain_db::RESERVATION_ESCROW_ADDR, &my_addr, refund);
        
        let memo = format!("early_termination_refund:{}", reservation_id);
        let sign_bytes = crate::ledger::tx_signing_bytes_v2(crate::chain_db::RESERVATION_ESCROW_ADDR, &my_addr, refund, 0, ts, 1, &memo);
        let hash = format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex());
        let _ = crate::mempool::get_mempool().push(crate::ledger::LedgerTx {
            hash,
            from:      crate::chain_db::RESERVATION_ESCROW_ADDR.to_string(),
            to:        my_addr.clone(),
            amount:    refund,
            memo:      Some(memo),
            timestamp: ts,
            signature: "system".to_string(),
            status:    "Pending".into(),
            nonce:     0,
            tx_type:   "early_termination_refund".to_string(),
            tx_version: 2,
            chain_id:   1,
            ..crate::ledger::LedgerTx::default()
        });
    }

    res.status = "terminated".to_string();
    res.escrow_remaining = 0;
    crate::chain_db::upsert_compute_reservation(&res);

    if let Some(mut node) = crate::chain_db::get_compute_node(&res.provider_address) {
        node.locked_cores = node.locked_cores.saturating_sub(res.cpu_cores);
        node.locked_ram_gb = node.locked_ram_gb.saturating_sub(res.ram_gb);
        crate::chain_db::upsert_compute_node(&node);
    }

    let msg = crate::p2p::P2PMessage::ReservationTerminated {
        reservation_id: reservation_id.clone(),
        by: my_addr.clone(),
        reason: "early_termination".to_string(),
    };
    crate::p2p::broadcast_compute_msg(msg).await;

    let _ = app.emit_all("ego://reservation-terminated", serde_json::json!({
        "reservation_id": reservation_id,
        "by":             my_addr.clone(),
        "reason":         "early_termination",
        "perspective":    "buyer",
    }));

    Ok(())
}

/// Verify + decrypt an IOU file with the buyer's password.
#[tauri::command]
pub async fn presale_verify_iou(
    iou_json: String,
    password: String,
) -> Result<serde_json::Value, EgoDesktopError> {
    let iou: serde_json::Value = serde_json::from_str(&iou_json)
        .map_err(|e| EgoDesktopError::WalletError(format!("Invalid IOU file: {e}")))?;

    let crypto = &iou["crypto"];
    let salt   = hex::decode(crypto["salt"].as_str().unwrap_or(""))
        .map_err(|_| EgoDesktopError::CryptoError("Bad salt".into()))?;
    let nonce_bytes = hex::decode(crypto["nonce"].as_str().unwrap_or(""))
        .map_err(|_| EgoDesktopError::CryptoError("Bad nonce".into()))?;
    let ciphertext = hex::decode(crypto["ciphertext"].as_str().unwrap_or(""))
        .map_err(|_| EgoDesktopError::CryptoError("Bad ciphertext".into()))?;

    let kdf_input: Vec<u8> = password.as_bytes().iter().chain(&salt[..]).copied().collect();
    let derived = blake3::hash(&kdf_input);

    let key    = Key::<Aes256Gcm>::from_slice(derived.as_bytes());
    let cipher = Aes256Gcm::new(key);
    let nonce  = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_slice())
        .map_err(|_| EgoDesktopError::CryptoError("Wrong password or corrupted IOU file".into()))?;

    serde_json::from_slice(&plaintext)
        .map_err(|e| EgoDesktopError::WalletError(format!("Corrupted record: {e}")))
}

/// List all pre-sale IOU records for this wallet.
#[tauri::command]
pub async fn presale_list_iou() -> Result<Vec<PresaleIouRecord>, EgoDesktopError> {
    Ok(Ledger::load().presale_records)
}

/// Get pre-sale pricing info.
#[tauri::command]
pub async fn presale_info() -> Result<serde_json::Value, EgoDesktopError> {
    Ok(serde_json::json!({
        "egoc_price_usd": cached_presale_price().unwrap_or(0.0),
        "round":          1,
        "round_name":     "Seed Round",
        "market_price":   2.45,
        "discount_pct":   18,
    }))
}


/// Base URL of the Ego payment proxy (`services/presale-proxy`).
///
/// Payment provider secrets live there and never in this binary. `option_env!`
/// substitutes its value into the compiled artifact at build time, so anything
/// passed to it ships to every user and can be recovered with `strings` — fine
/// for a public URL, never for a key.
fn payments_proxy_base() -> String {
    if let Ok(u) = std::env::var("EGO_PAYMENTS_PROXY") {
        if !u.trim().is_empty() { return u.trim().trim_end_matches('/').to_string(); }
    }
    if let Some(u) = option_env!("EGO_PAYMENTS_PROXY") {
        if !u.trim().is_empty() { return u.trim().trim_end_matches('/').to_string(); }
    }
    "https://pay.egoblockchain.com".to_string()
}

/// Percent-encode a value going into a URL path or query. These are coin
/// symbols and provider IDs, but they reach us from the frontend, so they get
/// escaped rather than trusted.
fn url_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn proxy_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .unwrap_or_default()
}

/// Surface the proxy's own `{"error": "..."}` shape as a real error instead of
/// letting it fall through and be read as a successful empty response.
fn proxy_error(json: &serde_json::Value) -> Option<EgoDesktopError> {
    json["error"].as_str().map(|e| EgoDesktopError::NetworkError(e.to_string()))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RampSession {
    pub url:      String,
    pub provider: String,
    /// Where the bought crypto will land. Shown to the user before they leave
    /// the app so a wrong-chain purchase is caught before money moves.
    pub address:  String,
}

/// Open a fiat buy/sell session for one of the wallet's own external assets.
///
/// The destination is resolved here from the wallet's derived addresses rather
/// than taken from the frontend — the address a ramp delivers to should never
/// be something the UI can be talked into supplying.
#[tauri::command]
pub async fn create_ramp_session(
    side:   String,
    symbol: String,
    amount: Option<f64>,
    fiat:   Option<String>,
) -> Result<RampSession, EgoDesktopError> {
    let side = if side.eq_ignore_ascii_case("sell") { "sell" } else { "buy" };
    let symbol_uc = symbol.to_uppercase();

    // Match on `asset` — the only field that means the same thing for native
    // coins and ERC-20 stablecoins alike.
    let addresses = crate::commands::multichain::get_external_addresses()?;
    let entry = addresses.iter()
        .find(|a| a.asset.eq_ignore_ascii_case(&symbol_uc))
        .ok_or_else(|| EgoDesktopError::InvalidInput(
            format!("{symbol_uc} has no receive address in this wallet")
        ))?;

    if side == "buy" && entry.address.trim().is_empty() {
        return Err(EgoDesktopError::WalletError(
            format!("No {symbol_uc} address derived yet — open the Wallet page once and retry")
        ));
    }

    // Pin the settlement network explicitly. USDT exists on several chains and
    // a provider defaulting to the wrong one would deliver funds to an address
    // this wallet cannot spend from.
    let network = ramp_network_for(&entry.asset, &entry.symbol);

    let resp = proxy_client()
        .post(format!("{}/ramp/session", payments_proxy_base()))
        .json(&serde_json::json!({
            "side":    side,
            "asset":   symbol_uc,
            "network": network,
            "address": entry.address,
            "amount":  amount,
            "fiat":    fiat.unwrap_or_else(|| "USD".into()),
        }))
        .send().await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?;

    let json: serde_json::Value = resp.json().await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?;

    if let Some(err) = proxy_error(&json) {
        return Err(err);
    }

    let url = json["url"].as_str().unwrap_or("").to_string();
    if url.is_empty() {
        return Err(EgoDesktopError::NetworkError("No checkout URL returned".into()));
    }

    Ok(RampSession {
        url,
        provider: json["provider"].as_str().unwrap_or("").to_string(),
        address:  entry.address.clone(),
    })
}

/// Settlement network a ramp should deliver on, per asset.
fn ramp_network_for(asset: &str, settles_on: &str) -> String {
    match asset.to_uppercase().as_str() {
        "BTC"  => "mainnet".to_string(),
        "ETH"  => "ethereum".to_string(),
        "BNB"  => "bsc".to_string(),
        "SOL"  => "solana".to_string(),
        "ADA"  => "cardano".to_string(),
        "XRP"  => "ripple".to_string(),
        "TRX"  => "tron".to_string(),
        "LTC"  => "litecoin".to_string(),
        "DOGE" => "dogecoin".to_string(),
        // ERC-20s carry the chain they settle on, not their own symbol.
        _ => match settles_on.to_uppercase().as_str() {
            "ETH" => "ethereum".to_string(),
            "BNB" => "bsc".to_string(),
            "TRX" => "tron".to_string(),
            "SOL" => "solana".to_string(),
            other => other.to_lowercase(),
        },
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StripeSession {
    pub session_id:   String,
    pub checkout_url: String,
    pub egoc_amount:  f64,
    pub usd_amount:   f64,
}


#[tauri::command]
pub async fn presale_stripe_checkout(
    egoc_amount: f64,
    usd_amount:  f64,
) -> Result<StripeSession, EgoDesktopError> {
    // The proxy prices the order itself from usd_amount — it deliberately
    // ignores any client-supplied EGOC figure, so a tampered client can't pay
    // $10 and claim an arbitrary allocation. We send usd_amount only.
    let resp = proxy_client()
        .post(format!("{}/presale/checkout", payments_proxy_base()))
        .json(&serde_json::json!({ "usd_amount": usd_amount }))
        .send()
        .await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?;

    let json: serde_json::Value = resp.json().await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?;

    if let Some(err) = proxy_error(&json) {
        return Err(err);
    }

    let session_id   = json["session_id"].as_str().unwrap_or("").to_string();
    let checkout_url = json["checkout_url"].as_str().unwrap_or("").to_string();

    if session_id.is_empty() || checkout_url.is_empty() {
        return Err(EgoDesktopError::NetworkError("No checkout URL returned".into()));
    }

    // Trust the server's arithmetic over the caller's.
    let egoc_amount = json["egoc_amount"].as_f64().unwrap_or(egoc_amount);
    let usd_amount  = json["usd_amount"].as_f64().unwrap_or(usd_amount);

    // The caller opens `checkout_url` — WalletPage does it via the Tauri shell
    // API. Opening it here too launched the browser twice for one click.
    Ok(StripeSession { session_id, checkout_url, egoc_amount, usd_amount })
}


#[derive(Debug, Serialize, Deserialize)]
pub struct StripeVerifyResult {
    pub paid: bool,
    pub status: String,
    pub amount_total_cents: i64,
}

#[tauri::command]
pub async fn presale_stripe_verify(session_id: String) -> Result<StripeVerifyResult, EgoDesktopError> {
    let url = format!(
        "{}/presale/verify/{}",
        payments_proxy_base(),
        url_escape(&session_id),
    );
    let resp = proxy_client()
        .get(&url)
        .send()
        .await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?;

    let json: serde_json::Value = resp.json().await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?;

    if let Some(err) = proxy_error(&json) {
        return Err(err);
    }

    // The proxy already resolves Stripe's `payment_status` / `status` pair into
    // the boolean the frontend checks.
    Ok(StripeVerifyResult {
        paid:               json["paid"].as_bool().unwrap_or(false),
        status:             json["status"].as_str().unwrap_or("").to_string(),
        amount_total_cents: json["amount_total"].as_i64().unwrap_or(0),
    })
}


#[tauri::command]
pub async fn presale_stripe_create_iou(
    session_id:  String,
    egoc_amount: f64,
    usd_amount:  f64,
    password:    String,
) -> Result<String, EgoDesktopError> {
    let ledger = Ledger::load();
    if password.trim().is_empty() {
        return Err(EgoDesktopError::WalletError("Password cannot be empty".into()));
    }
    if !(egoc_amount.is_finite() && egoc_amount > 0.0) {
        return Err(EgoDesktopError::InvalidInput("Invalid EGOC amount for this purchase".into()));
    }

    // Record the price this buyer actually got — derived from what Stripe
    // collected and the allocation the server computed, so the IOU can never
    // claim a rate that differs from the transaction behind it.
    let presale_price = usd_amount / egoc_amount;

    let id  = uuid::Uuid::new_v4().to_string();
    let ts  = chrono::Utc::now().timestamp();

    let plain = serde_json::json!({
        "id":              id,
        "mainnet_address": ledger.mainnet_address,
        "testnet_address": ledger.address,
        "egoc_amount":     egoc_amount,
        "usd_value":       usd_amount,
        "price_per_egoc":  presale_price,
        "pay_method":      "stripe",
        "stripe_session":  session_id,
        "timestamp":       ts,
        "round":           "Seed Round",
    });
    let plain_bytes = serde_json::to_vec(&plain)
        .map_err(|e| EgoDesktopError::WalletError(e.to_string()))?;

    let mut salt        = [0u8; 32];
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);

    let kdf_input: Vec<u8> = password.as_bytes().iter().chain(&salt).copied().collect();
    let derived   = blake3::hash(&kdf_input);
    let key    = Key::<Aes256Gcm>::from_slice(derived.as_bytes());
    let cipher = Aes256Gcm::new(key);
    let nonce  = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plain_bytes.as_slice())
        .map_err(|e| EgoDesktopError::CryptoError(e.to_string()))?;

    let iou = serde_json::json!({
        "version":     1,
        "id":          id,
        "ego_presale": true,
        "network":     "ego-mainnet",
        "issued_at":   ts,
        "round":       "Seed Round",
        "payment": {
            "method":         "stripe",
            "stripe_session": session_id,
            "status":         "paid"
        },
        "allocation": {
            "egoc_amount":        egoc_amount,
            "usd_value":          usd_amount,
            "price_per_egoc_usd": presale_price
        },
        "genesis_note": "This allocation will be credited in the Ego Chain Genesis Block upon mainnet launch. Keep this file and your password — they are your proof of purchase.",
        "crypto": {
            "cipher":     "aes-256-gcm",
            "kdf":        "blake3",
            "salt":       hex::encode(&salt),
            "nonce":      hex::encode(&nonce_bytes),
            "ciphertext": hex::encode(&ciphertext)
        }
    });

    let record = PresaleIouRecord {
        id:              id.clone(),
        mainnet_address: ledger.mainnet_address.clone(),
        egoc_amount,
        usd_value:       usd_amount,
        pay_symbol:      "USD".into(),
        pay_amount:      usd_amount,
        deposit_address: format!("stripe:{session_id}"),
        timestamp:       ts,
        status:          "paid".into(),
    };
    let mut ledger2 = Ledger::load();
    ledger2.presale_records.push(record);
    let _ = ledger2.save();

    serde_json::to_string_pretty(&iou)
        .map_err(|e| EgoDesktopError::WalletError(e.to_string()))
}
