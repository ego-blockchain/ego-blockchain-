use crate::app::AppState;
use crate::error::EgoDesktopError;
use crate::ledger::{load_chain, save_chain, tx_signing_bytes, tx_signing_bytes_v2, tx_human_summary, Ledger, LedgerBlock, LedgerTx};
use once_cell::sync::Lazy;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use tauri::State;
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Key, Nonce};
use crate::ledger::PresaleIouRecord;

static PENDING_TXS: Lazy<Mutex<HashMap<String, (LedgerTx, i64)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Validate an Ego bech32 address.
///
/// Rules:
/// - Must start with `egot1` (testnet EOA) or one of the known system prefixes.
/// - Must not be empty or exceed 100 characters (prevents DoS / garbage-in).
/// - Must be ASCII alphanumeric only (bech32 charset).
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
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendTransactionRequest {
    pub to_address: String,
    pub amount: u64,
    pub memo: Option<String>,
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
    let ledger  = Ledger::load();
    let my_addr = ledger.address.clone();

    if my_addr.is_empty() {
        return Ok(Balance { egoc: 0, uegoc: 0, formatted: "0.00 EGOC".into(), egusd: 0, uegusd: 0 });
    }

    // Direct O(1) RocksDB CF_BALANCES lookup — no need to deserialise 500 blocks.
    let uegoc = crate::chain_db::balance_of(&my_addr);
    let egoc  = uegoc / 1_000_000;

    let uegusd = ledger.balance_uegusd;
    let egusd  = uegusd / 1_000_000;

    Ok(Balance {
        egoc,
        uegoc,
        formatted: format!("{:.2} EGOC", uegoc as f64 / 1_000_000.0),
        egusd,
        uegusd,
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

    let chain   = load_chain();
    let balance = chain.balance_of(&from);

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

    let nonce      = ledger.nonce + 1;
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
        signed_summary:      summary.clone(),
        ..LedgerTx::default()
    };

    crate::mempool::get_mempool().push(tx.clone());
    crate::commands::tx_pending::add(&tx);

    ledger.nonce = nonce;
    let _ = ledger.save();

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
        hash:           tx_hash,
        success:        true,
        message:        "Transaction queued — confirms within the next batch window".into(),
        block_height:   None,
        signed_summary: Some(summary),
    })
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
        signed_summary: None,
    })
}

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
    txs.truncate(500); // Cap at 500 most-recent — prevents OOM with millions of TXs
    Ok(txs)
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
    validate_ego_address(&request.to_address)?;
    if request.to_address.trim() == from.trim() {
        return Err(EgoDesktopError::InvalidInput("Cannot send to your own address".into()));
    }
    if let Some(ref memo) = request.memo {
        if memo.len() > 256 {
            return Err(EgoDesktopError::InvalidInput("Memo too long (max 256 chars)".into()));
        }
    }
    if email.is_empty() {
        return Err(EgoDesktopError::InvalidInput(
            "No email on file. Set an email in Settings to use 2FA.".into(),
        ));
    }

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

    crate::email::check_send_limit(&email)
        .map_err(|e| EgoDesktopError::InvalidInput(e))?;

    let code  = crate::email::gen_otp_code();
    let tx_id = tx_hash.clone();
    let expiry = ts + 600;

    crate::email::store_otp(&format!("tx:{}", tx_id), &code);
    {
        let mut map = PENDING_TXS.lock().unwrap();
        map.retain(|_, (_, exp)| *exp > ts); // prune expired
        if map.len() >= MAX_PENDING_TXS {
            return Err(EgoDesktopError::InvalidInput(
                "Too many pending transactions. Please wait and try again.".into(),
            ));
        }
        map.insert(tx_id.clone(), (tx.clone(), expiry));
    }

    let amount_str = format!("{:.6} EGOC", request.amount as f64 / 1_000_000.0);
    crate::email::send_tx_code_email(&email, &code, &amount_str, &request.to_address)
        .await
        .map_err(|e| EgoDesktopError::NetworkError(format!("Failed to send code: {e}")))?;

    crate::email::record_send_attempt(&email);

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

#[tauri::command]
pub async fn confirm_tx_code(
    tx_id:  String,
    code:   String,
) -> Result<TransactionResponse, EgoDesktopError> {

    let valid = crate::email::verify_otp(&format!("tx:{}", tx_id), code.trim());
    if !valid {
        let now_ts = chrono::Utc::now().timestamp();
        let attempts = {
            let mut map = TX_ATTEMPTS.lock().unwrap();
            // Purge expired attempt records to keep map bounded.
            map.retain(|_, (_, exp)| *exp > now_ts);
            let entry = map.entry(tx_id.clone()).or_insert((0, now_ts + 3_600));
            entry.0 += 1;
            entry.0
        };
        if attempts >= 3 {
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

    TX_ATTEMPTS.lock().unwrap().remove(&tx_id);
    let email = crate::ledger::Ledger::load().registered_email;
    if !email.is_empty() { crate::email::reset_send_attempts(&email); }

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

    let mut ledger = Ledger::load();
    if tx.nonce > ledger.nonce {
        ledger.nonce = tx.nonce;
        let _ = ledger.save();
    }

    crate::mempool::get_mempool().push(tx.clone());

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
        hash:           tx.hash,
        success:        true,
        message:        "Transaction confirmed and queued".into(),
        block_height:   None,
        signed_summary: None,
    })
}

// ── ChangeNow real swap integration ───────────────────────────────────────────

// Key is injected at compile time via: set CHANGENOW_API_KEY=<key> && cargo build
// Never hardcode the real key here — this file is open source.
const CHANGENOW_KEY: &str = match option_env!("CHANGENOW_API_KEY") {
    Some(k) => k,
    None    => "",
};
const CHANGENOW_BASE: &str = "https://api.changenow.io/v2";

fn changenow_key() -> Result<&'static str, EgoDesktopError> {
    if CHANGENOW_KEY.is_empty() {
        return Err(EgoDesktopError::NetworkError(
            "Swap service not available in this build. Set CHANGENOW_API_KEY at compile time.".into(),
        ));
    }
    Ok(CHANGENOW_KEY)
}

/// Map a coin symbol to its ChangeNow network string.
fn cn_network(sym: &str) -> &'static str {
    match sym {
        "BTC"  => "btc",
        "ETH"  => "eth",
        "BNB"  => "bsc",
        "SOL"  => "sol",
        "XRP"  => "xrp",
        "ADA"  => "ada",
        "TRX"  => "trx",
        "DOT"  => "dot",
        "LINK" => "eth",
        "SHIB" => "eth",
        "USDT" => "eth",
        "USDC" => "eth",
        _      => "eth",
    }
}

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
    let cn_key = changenow_key()?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build().unwrap_or_default();

    let from_cur     = from_symbol.to_lowercase();
    let to_cur       = to_symbol.to_lowercase();
    let from_network = cn_network(&from_symbol);
    let to_network   = cn_network(&to_symbol);

    // Fetch min-amount and estimate in parallel
    let min_url = format!(
        "{CHANGENOW_BASE}/exchange/min-amount?fromCurrency={from_cur}&toCurrency={to_cur}&fromNetwork={from_network}&toNetwork={to_network}&flow=standard"
    );
    let est_url = format!(
        "{CHANGENOW_BASE}/exchange/estimated-amount?fromCurrency={from_cur}&toCurrency={to_cur}&fromAmount={from_amount}&fromNetwork={from_network}&toNetwork={to_network}&flow=standard&type=direct"
    );

    let (min_result, est_result) = tokio::join!(
        async {
            let r = client.get(&min_url).header("x-changenow-api-key", cn_key).send().await.ok()?;
            let v: serde_json::Value = r.json().await.ok()?;
            v["minAmount"].as_f64()
        },
        client.get(&est_url).header("x-changenow-api-key", cn_key).send(),
    );

    let min_amount = min_result.unwrap_or(0.0);

    let est: serde_json::Value = est_result
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?
        .json().await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?;

    if let Some(err) = est["error"].as_str() {
        return Err(EgoDesktopError::NetworkError(
            est["message"].as_str().unwrap_or(err).to_string()
        ));
    }

    let to_amount       = est["toAmount"].as_f64()
        .ok_or_else(|| EgoDesktopError::NetworkError("Invalid response from ChangeNow".into()))?;
    let network_fee     = est["networkFee"].as_f64().unwrap_or(0.0);
    let network_fee_usd = est["networkFeeUSD"].as_f64().unwrap_or(0.0);

    Ok(CnEstimate { to_amount, min_amount, network_fee, network_fee_usd })
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
    let cn_key = changenow_key()?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build().unwrap_or_default();

    let body = serde_json::json!({
        "fromCurrency":  from_symbol.to_lowercase(),
        "toCurrency":    to_symbol.to_lowercase(),
        "fromAmount":    from_amount.to_string(),
        "toAddress":     to_address,
        "fromNetwork":   cn_network(&from_symbol),
        "toNetwork":     cn_network(&to_symbol),
        "flow":          "standard",
        "type":          "direct",
    });

    let resp: serde_json::Value = client
        .post(&format!("{CHANGENOW_BASE}/exchange"))
        .header("x-changenow-api-key", cn_key)
        .header("Content-Type", "application/json")
        .json(&body)
        .send().await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?
        .json().await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?;

    if let Some(err) = resp["error"].as_str() {
        return Err(EgoDesktopError::NetworkError(
            resp["message"].as_str().unwrap_or(err).to_string()
        ));
    }

    Ok(CnExchange {
        id:               resp["id"].as_str().unwrap_or("").to_string(),
        deposit_address:  resp["payinAddress"].as_str().unwrap_or("").to_string(),
        deposit_extra_id: resp["payinExtraId"].as_str().map(|s| s.to_string()),
        to_amount:        resp["toAmount"].as_f64().unwrap_or(0.0),
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
    let cn_key = changenow_key()?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build().unwrap_or_default();

    let resp: serde_json::Value = client
        .get(&format!("{CHANGENOW_BASE}/exchange/{exchange_id}"))
        .header("x-changenow-api-key", cn_key)
        .send().await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?
        .json().await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?;

    Ok(CnStatus {
        status:    resp["status"].as_str().unwrap_or("unknown").to_string(),
        to_amount: resp["amountTo"].as_f64(),
        hash_out:  resp["payoutHash"].as_str().map(|s| s.to_string()),
    })
}

// ── Pre-sale IOU system ────────────────────────────────────────────────────────
// No tokens exist yet. Buyers receive an encrypted IOU wallet file as proof of
// purchase. All allocations are written into the Ego Chain Genesis Block when
// mainnet launches.

const PRESALE_EGOC_USD: f64 = 2.00; // seed-round price ($2.45 market → 18% off)

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

    let usd_value   = pay_amount * pay_usd_price;
    let egoc_amount = usd_value / PRESALE_EGOC_USD;
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
        "price_per_egoc":    PRESALE_EGOC_USD,
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
            "price_per_egoc_usd": PRESALE_EGOC_USD
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
        "egoc_price_usd": PRESALE_EGOC_USD,
        "round":          1,
        "round_name":     "Seed Round",
        "market_price":   2.45,
        "discount_pct":   18,
    }))
}

// ── Stripe card / Apple Pay payments ──────────────────────────────────────────
// The app calls a proxy on your server — Stripe secret key never enters the binary.
// Deploy services/presale-proxy/ to any Node.js host and set PRESALE_API_URL.
const PRESALE_API_URL: &str = match option_env!("PRESALE_API_URL") {
    Some(u) => u,
    None    => "http://localhost:3031/presale",
};

#[derive(Debug, Serialize, Deserialize)]
pub struct StripeSession {
    pub session_id:   String,
    pub checkout_url: String,
    pub egoc_amount:  f64,
    pub usd_amount:   f64,
}

/// Create a Stripe Checkout Session via the presale proxy.
/// The proxy holds the Stripe secret key — never the app.
#[tauri::command]
pub async fn presale_stripe_checkout(
    egoc_amount: f64,
    usd_amount:  f64,
) -> Result<StripeSession, EgoDesktopError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build().unwrap_or_default();

    let resp = client
        .post(format!("{PRESALE_API_URL}/checkout"))
        .json(&serde_json::json!({ "egoc_amount": egoc_amount, "usd_amount": usd_amount }))
        .send()
        .await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?;

    let json: serde_json::Value = resp.json().await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?;

    if let Some(err) = json["error"].as_str() {
        return Err(EgoDesktopError::NetworkError(format!("Presale API: {err}")));
    }

    let session_id   = json["session_id"].as_str().unwrap_or("").to_string();
    let checkout_url = json["checkout_url"].as_str().unwrap_or("").to_string();

    if session_id.is_empty() || checkout_url.is_empty() {
        return Err(EgoDesktopError::NetworkError("No checkout URL returned from presale API".into()));
    }

    Ok(StripeSession { session_id, checkout_url, egoc_amount, usd_amount })
}

/// Verify a Stripe Checkout Session via the presale proxy.
#[tauri::command]
pub async fn presale_stripe_verify(session_id: String) -> Result<serde_json::Value, EgoDesktopError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build().unwrap_or_default();

    let resp = client
        .get(format!("{PRESALE_API_URL}/verify/{session_id}"))
        .send()
        .await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?;

    let json: serde_json::Value = resp.json().await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?;

    if let Some(err) = json["error"].as_str() {
        return Err(EgoDesktopError::NetworkError(format!("Presale API: {err}")));
    }

    Ok(json)
}

/// After a verified Stripe payment, create the encrypted IOU file.
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

    let id  = uuid::Uuid::new_v4().to_string();
    let ts  = chrono::Utc::now().timestamp();

    let plain = serde_json::json!({
        "id":              id,
        "mainnet_address": ledger.mainnet_address,
        "testnet_address": ledger.address,
        "egoc_amount":     egoc_amount,
        "usd_value":       usd_amount,
        "price_per_egoc":  PRESALE_EGOC_USD,
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
            "price_per_egoc_usd": PRESALE_EGOC_USD
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
