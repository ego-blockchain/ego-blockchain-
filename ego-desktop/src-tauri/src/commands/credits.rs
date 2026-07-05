use crate::app::AppState;
use crate::error::EgoDesktopError;
use crate::ledger::{tx_signing_bytes_v2, Ledger, LedgerTx};
use serde::Serialize;
use tauri::State;

const CHAIN_ID: u8 = 1;

#[derive(Serialize)]
pub struct CreditsBalance {
    pub credits: u64,
    pub usd_value: f64,
    pub egoc_price_usd: f64,
}

#[derive(Serialize)]
pub struct CreditsTxResponse {
    pub hash: String,
    pub credits: u64,
    pub message: String,
}

fn build_signed_tx(
    state: &State<'_, AppState>,
    ledger: &mut Ledger,
    to: &str,
    amount: u64,
    memo: String,
    tx_type: &str,
    fee: u64,
) -> Result<LedgerTx, EgoDesktopError> {
    let from = ledger.address.clone();
    let confirmed_nonce = crate::ledger::last_confirmed_nonce(&from);
    let nonce = ledger.nonce.max(confirmed_nonce) + 1;
    let ts = chrono::Utc::now().timestamp();
    let sign_bytes = tx_signing_bytes_v2(&from, to, amount, nonce, ts, CHAIN_ID, &memo);

    let Some(kp) = state.get_keypair() else {
        return Err(EgoDesktopError::WalletError(
            "Wallet not initialized – call init_wallet first".into(),
        ));
    };
    let ed_sig = kp.sign_ed25519(&sign_bytes);
    let dil_sig = kp.sign_dilithium(&sign_bytes);

    let tx = LedgerTx {
        hash: format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex()),
        from,
        to: to.to_string(),
        amount,
        memo: Some(memo),
        timestamp: ts,
        signature: hex::encode(ed_sig.as_bytes()),
        status: "Pending".into(),
        block_height: None,
        nonce,
        public_key_ed25519: hex::encode(kp.ed25519_public_key().as_bytes()),
        dilithium_pubkey: hex::encode(&kp.dilithium_public_key().key_data),
        dilithium_signature: hex::encode(&dil_sig.signature_data),
        fee_uegoc: fee,
        tx_version: 2,
        chain_id: CHAIN_ID,
        tx_type: tx_type.to_string(),
        ..LedgerTx::default()
    };
    ledger.nonce = nonce;
    Ok(tx)
}

async fn queue_tx(tx: LedgerTx, ledger: Ledger) {
    crate::mempool::get_mempool().push(tx.clone());
    crate::commands::tx_pending::add(&tx);
    let _ = ledger.save();
    tauri::async_runtime::spawn(async move {
        crate::p2p::broadcast_pending_tx(tx).await;
    });
}

#[tauri::command]
pub async fn get_credits_balance() -> Result<CreditsBalance, EgoDesktopError> {
    let (credits, price) = tokio::task::spawn_blocking(|| {
        let addr = Ledger::load().address;
        (
            crate::chain_db::credits_balance(&addr),
            crate::p2p::get_egoc_price_usd(),
        )
    })
    .await
    .map_err(|e| EgoDesktopError::WalletError(e.to_string()))?;
    Ok(CreditsBalance {
        credits,
        usd_value: credits as f64 * crate::chain_db::MICRO_USD_PER_CREDIT as f64 / 1_000_000.0,
        egoc_price_usd: price,
    })
}

#[tauri::command]
pub async fn mint_credits(
    amount_uegoc: u64,
    state: State<'_, AppState>,
) -> Result<CreditsTxResponse, EgoDesktopError> {
    if amount_uegoc == 0 {
        return Err(EgoDesktopError::InvalidInput("Amount must be > 0".into()));
    }
    let _guard = crate::ledger::TX_MUTEX.lock().await;
    let mut ledger = Ledger::load();
    if ledger.address.is_empty() {
        return Err(EgoDesktopError::WalletError(
            "Wallet not initialized – call init_wallet first".into(),
        ));
    }

    let is_staker = ledger.staked_amount > 0;
    let fee = crate::tokenomics::fee_for_tx_with_staking("transfer", is_staker);
    let balance = crate::chain_db::balance_of(&ledger.address);
    if amount_uegoc.saturating_add(fee) > balance {
        return Err(EgoDesktopError::InvalidInput(format!(
            "Insufficient balance: have {} uEGOC, need {} + {} fee",
            balance, amount_uegoc, fee
        )));
    }

    let price_micro = (crate::p2p::get_egoc_price_usd() * 1_000_000.0) as u64;
    if price_micro == 0 {
        return Err(EgoDesktopError::WalletError("No EGOC price available".into()));
    }
    let credits = crate::chain_db::credits_mint_amount(amount_uegoc, price_micro);
    if credits == 0 {
        return Err(EgoDesktopError::InvalidInput(
            "Amount too small to mint a single credit".into(),
        ));
    }

    let memo = format!("credits_mint:{}", price_micro);
    let tx = build_signed_tx(
        &state,
        &mut ledger,
        crate::chain_db::CREDITS_BURN_ADDR,
        amount_uegoc,
        memo,
        "credits_mint",
        fee,
    )?;
    let hash = tx.hash.clone();
    eprintln!(
        "[Credits] Mint queued — burn {} uEGOC @ {}µ$ → {} credits ({})",
        amount_uegoc, price_micro, credits, hash
    );
    queue_tx(tx, ledger).await;
    Ok(CreditsTxResponse {
        hash,
        credits,
        message: format!(
            "Burning {:.6} EGOC for {} credits (${:.2}) — confirms next block",
            amount_uegoc as f64 / 1_000_000.0,
            credits,
            credits as f64 / 100.0
        ),
    })
}

#[tauri::command]
pub async fn pay_credits(
    to_address: String,
    credits: u64,
    state: State<'_, AppState>,
) -> Result<CreditsTxResponse, EgoDesktopError> {
    if credits == 0 {
        return Err(EgoDesktopError::InvalidInput("Credits must be > 0".into()));
    }
    let to = to_address.trim().to_string();
    if !to.starts_with("egot1") || to.len() < 20 {
        return Err(EgoDesktopError::InvalidInput("Invalid recipient address".into()));
    }
    let _guard = crate::ledger::TX_MUTEX.lock().await;
    let mut ledger = Ledger::load();
    if ledger.address.is_empty() {
        return Err(EgoDesktopError::WalletError(
            "Wallet not initialized – call init_wallet first".into(),
        ));
    }
    if to == ledger.address {
        return Err(EgoDesktopError::InvalidInput("Cannot pay yourself".into()));
    }
    let have = crate::chain_db::credits_balance(&ledger.address);
    if have < credits {
        return Err(EgoDesktopError::InvalidInput(format!(
            "Insufficient credits: have {}, need {}",
            have, credits
        )));
    }
    let is_staker = ledger.staked_amount > 0;
    let fee = crate::tokenomics::fee_for_tx_with_staking("transfer", is_staker);
    if fee > crate::chain_db::balance_of(&ledger.address) {
        return Err(EgoDesktopError::InvalidInput(
            "Insufficient EGOC for the network fee".into(),
        ));
    }

    let memo = format!("credits_pay:{}", credits);
    let tx = build_signed_tx(&state, &mut ledger, &to, 0, memo, "credits_pay", fee)?;
    let hash = tx.hash.clone();
    eprintln!("[Credits] Pay queued — {} credits → {} ({})", credits, to, hash);
    queue_tx(tx, ledger).await;
    Ok(CreditsTxResponse {
        hash,
        credits,
        message: format!(
            "Paying {} credits (${:.2}) to {} — confirms next block",
            credits,
            credits as f64 / 100.0,
            to
        ),
    })
}
