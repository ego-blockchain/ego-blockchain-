use crate::app::AppState;
use crate::error::EgoDesktopError;
use crate::ledger::{load_chain, save_chain, tx_signing_bytes, Ledger, LedgerBlock, LedgerTx};
use once_cell::sync::Lazy;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use tauri::State;

// ── Pending TX 2FA store ──────────────────────────────────────────────────────
// tx_id → (LedgerTx, expires_unix_ts)

static PENDING_TXS: Lazy<Mutex<HashMap<String, (LedgerTx, i64)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

// tx_id → failed attempt count
static TX_ATTEMPTS: Lazy<Mutex<HashMap<String, u32>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

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
        fee_uegoc:           fee,
        ..LedgerTx::default()
    };

    // ── 3. Route to mempool (batch loop will mine + broadcast) ───────────
    // The TX is confirmed inside the next batch window (≤ BATCH_INTERVAL_MS).
    // This decouples signing from disk I/O — enabling 100k TPS throughput.
    crate::mempool::get_mempool().push(tx);

    // ── 4. Persist updated nonce in per-wallet ledger ─────────────────────
    ledger.nonce = nonce;
    let _ = ledger.save();

    // ── 5. Send email confirmation (fire-and-forget) ─────────────────────
    {
        let to_email = ledger.registered_email.clone();
        let amount_egoc = format!("{:.6} EGOC", request.amount as f64 / 1_000_000.0);
        let recipient = request.to_address.clone();
        let hash_copy = tx_hash.clone();
        if !to_email.is_empty() {
            tauri::async_runtime::spawn(async move {
                if let Err(e) = crate::email::send_tx_confirmation(
                    &to_email, &amount_egoc, &recipient, &hash_copy,
                ).await {
                    eprintln!("[Email] TX confirmation failed: {e}");
                }
            });
        }
    }

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
    let tx3 = tx.clone(); let blk3 = block.clone();
    tokio::spawn(async move { crate::p2p::broadcast_tx(tx3, blk3).await; });
    // Forward tx + block to Oracle node so the public explorer can show them.
    let tx4 = tx.clone();
    let blk4 = block.clone();
    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        if let Ok(body) = serde_json::to_value(&tx4) {
            crate::p2p::oracle_post_pub(&client, "/tx/broadcast", &body).await;
        }
        if let Ok(body) = serde_json::to_value(&blk4) {
            crate::p2p::oracle_post_pub(&client, "/block/broadcast", &body).await;
        }
    });
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

// ── fetch_swap_rates ──────────────────────────────────────────────────────────

/// Fetch live USD prices for swap assets from CoinGecko (no API key needed).
#[tauri::command]
pub async fn fetch_swap_rates() -> Result<std::collections::HashMap<String, f64>, EgoDesktopError> {
    let url = "https://api.coingecko.com/api/v3/simple/price\
        ?ids=bitcoin,ethereum,binancecoin,cardano,solana,ripple,tron,polkadot,chainlink,shiba-inu,tether,usd-coin\
        &vs_currencies=usd";
    let json: serde_json::Value = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default()
        .get(url)
        .send()
        .await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?
        .json()
        .await
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

// ── request_tx_code ───────────────────────────────────────────────────────────
//
/// Return the email stored in the local ledger, masked for display.
/// e.g. "abc***@domain.com". Returns empty string if no email is set.
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
    let ledger  = Ledger::load();
    let from    = ledger.address.clone();
    let email   = ledger.registered_email.clone();

    if from.is_empty() {
        return Err(EgoDesktopError::WalletError("Wallet not initialized".into()));
    }
    if email.is_empty() {
        return Err(EgoDesktopError::InvalidInput(
            "No email on file. Set an email in Settings to use 2FA.".into(),
        ));
    }

    // Validate balance
    let chain   = load_chain();
    let balance = chain.balance_of(&from);
    if request.amount == 0 {
        return Err(EgoDesktopError::InvalidInput("Amount must be > 0".into()));
    }
    let is_staker2   = ledger.staked_amount > 0;
    let fee          = crate::tokenomics::fee_for_tx_with_staking("transfer", is_staker2);
    let total_needed = request.amount.saturating_add(fee);
    if total_needed > balance {
        return Err(EgoDesktopError::InvalidInput(format!(
            "Insufficient balance: have {} uEGOC, need {} (amount {} + fee {})",
            balance, total_needed, request.amount, fee
        )));
    }

    // Build + sign the transaction (same as send_transaction)
    let nonce      = ledger.nonce + 1;
    let ts         = chrono::Utc::now().timestamp();
    let sign_bytes = tx_signing_bytes(&from, &request.to_address, request.amount, nonce, ts);

    let (sig_hex, pk_hex, dil_sig_hex, dil_pk_hex) = if let Some(kp) = state.get_keypair() {
        let ed_sig  = kp.sign_ed25519(&sign_bytes);
        let dil_sig = kp.sign_dilithium(&sign_bytes);
        (
            hex::encode(ed_sig.as_bytes()),
            hex::encode(kp.ed25519_public_key().as_bytes()),
            hex::encode(&dil_sig.signature_data),
            hex::encode(&kp.dilithium_public_key().key_data),
        )
    } else {
        return Err(EgoDesktopError::WalletError("Wallet not initialized".into()));
    };

    let tx_hash = format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex());
    let tx = LedgerTx {
        hash:                tx_hash.clone(),
        from:                from.clone(),
        to:                  request.to_address.clone(),
        amount:              request.amount,
        memo:                request.memo.clone(),
        timestamp:           ts,
        signature:           sig_hex,
        status:              "Pending".into(),
        block_height:        None,
        nonce,
        public_key_ed25519:  pk_hex,
        dilithium_pubkey:    dil_pk_hex,
        dilithium_signature: dil_sig_hex,
        fee_uegoc:           fee,
        ..LedgerTx::default()
    };

    // Check send limit before generating / storing anything
    crate::email::check_send_limit(&email)
        .map_err(|e| EgoDesktopError::InvalidInput(e))?;

    // Generate 4-digit + 2-letter code and store OTP + pending tx (10 min expiry)
    let code  = crate::email::gen_otp_code();
    let tx_id = tx_hash.clone();
    let expiry = ts + 600;

    crate::email::store_otp(&format!("tx:{}", tx_id), &code);
    {
        let mut map = PENDING_TXS.lock().unwrap();
        map.retain(|_, (_, exp)| *exp > ts);
        map.insert(tx_id.clone(), (tx.clone(), expiry));
    }

    // Email the code
    let amount_str = format!("{:.6} EGOC", request.amount as f64 / 1_000_000.0);
    crate::email::send_tx_code_email(&email, &code, &amount_str, &request.to_address)
        .await
        .map_err(|e| EgoDesktopError::NetworkError(format!("Failed to send code: {e}")))?;

    // Only count the attempt after confirmed delivery
    crate::email::record_send_attempt(&email);

    // Mask the email for display: abc***@domain.com
    let masked = if let Some(at) = email.find('@') {
        let local = &email[..at];
        let domain = &email[at..];
        if local.len() > 3 {
            format!("{}***{}", &local[..2], domain)
        } else {
            format!("{}***{}", &local[..1], domain)
        }
    } else {
        "***".to_string()
    };

    Ok(TxCodeRequest { tx_id, masked_email: masked })
}

// ── confirm_tx_code ───────────────────────────────────────────────────────────
//
// Step 2 of email 2FA: verify the code and execute the pending transaction.

#[tauri::command]
pub async fn confirm_tx_code(
    tx_id:  String,
    code:   String,
) -> Result<TransactionResponse, EgoDesktopError> {
    // Verify OTP — cancel transaction after 3 failed attempts
    let valid = crate::email::verify_otp(&format!("tx:{}", tx_id), code.trim());
    if !valid {
        let attempts = {
            let mut map = TX_ATTEMPTS.lock().unwrap();
            let count = map.entry(tx_id.clone()).or_insert(0);
            *count += 1;
            *count
        };
        if attempts >= 3 {
            // Cancel: remove pending tx and reset attempt counter
            PENDING_TXS.lock().unwrap().remove(&tx_id);
            TX_ATTEMPTS.lock().unwrap().remove(&tx_id);
            return Err(EgoDesktopError::InvalidInput(
                "Too many failed attempts. Transaction has been cancelled.".into(),
            ));
        }
        return Err(EgoDesktopError::InvalidInput(
            format!("Incorrect code. {} attempt{} remaining.",
                3 - attempts,
                if 3 - attempts == 1 { "" } else { "s" }
            ),
        ));
    }
    // Clear attempt counter on success and reset email send limit
    TX_ATTEMPTS.lock().unwrap().remove(&tx_id);
    let email = crate::ledger::Ledger::load().registered_email;
    if !email.is_empty() { crate::email::reset_send_attempts(&email); }

    // Retrieve the pending tx
    let tx = {
        let mut map = PENDING_TXS.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        match map.remove(&tx_id) {
            Some((tx, exp)) if exp > now => tx,
            Some(_) => return Err(EgoDesktopError::InvalidInput(
                "Transaction request expired. Please start over.".into(),
            )),
            None => return Err(EgoDesktopError::InvalidInput(
                "Transaction not found. It may have already been submitted or expired.".into(),
            )),
        }
    };

    // Persist nonce update
    let mut ledger = Ledger::load();
    if tx.nonce > ledger.nonce {
        ledger.nonce = tx.nonce;
        let _ = ledger.save();
    }

    // Push to mempool (batch loop mines + broadcasts)
    crate::mempool::get_mempool().push(tx.clone());

    // Fire confirmation email (non-blocking)
    let to_email = ledger.registered_email.clone();
    if !to_email.is_empty() {
        let amount_str = format!("{:.6} EGOC", tx.amount as f64 / 1_000_000.0);
        let recipient  = tx.to.clone();
        let hash_copy  = tx.hash.clone();
        tauri::async_runtime::spawn(async move {
            if let Err(e) = crate::email::send_tx_confirmation(
                &to_email, &amount_str, &recipient, &hash_copy,
            ).await {
                eprintln!("[Email] TX receipt failed: {e}");
            }
        });
    }

    Ok(TransactionResponse {
        hash:         tx.hash,
        success:      true,
        message:      "Transaction confirmed and queued".into(),
        block_height: None,
    })
}
