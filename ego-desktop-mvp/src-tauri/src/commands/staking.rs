use crate::app::AppState;
use crate::error::EgoDesktopError;
use crate::ledger::{load_chain, save_chain, tx_signing_bytes, Ledger, LedgerTx};
use serde::{Deserialize, Serialize};
use tauri::State;

const STAKING_ADDR: &str = "egot1staking000000000000000000000000000000000";

#[derive(Debug, Serialize, Deserialize)]
pub struct StakingInfo {
    pub staked_amount:    u64,
    pub lock_period_days: u32,
    pub apr:              f64,
    pub pending_rewards:  u64,
    pub unlock_date:      Option<i64>,
    pub staked_at:        Option<i64>,
    pub is_locked:        bool,
}

#[tauri::command]
pub async fn get_staking_info() -> Result<StakingInfo, EgoDesktopError> {
    let ledger = Ledger::load();
    let now    = chrono::Utc::now().timestamp();
    let is_locked = ledger.staked_amount > 0
        && ledger.unstake_at.map(|u| u > now).unwrap_or(false);
    Ok(StakingInfo {
        staked_amount:    ledger.staked_amount,
        lock_period_days: ledger.stake_lock_days,
        apr:              12.5,
        pending_rewards:  0,
        unlock_date:      ledger.unstake_at,
        staked_at:        ledger.staked_at,
        is_locked,
    })
}

#[tauri::command]
pub async fn stake_coins(
    amount_uegoc: u64,
    lock_days:    u32,
    state:        State<'_, AppState>,
) -> Result<(), EgoDesktopError> {
    if amount_uegoc == 0 {
        return Err(EgoDesktopError::InvalidInput("Amount must be > 0".into()));
    }
    if lock_days == 0 {
        return Err(EgoDesktopError::InvalidInput("Lock period must be > 0 days".into()));
    }

    let mut ledger = Ledger::load();
    let from = ledger.address.clone();
    if from.is_empty() {
        return Err(EgoDesktopError::WalletError("Wallet not initialized".into()));
    }
    if ledger.staked_amount > 0 {
        return Err(EgoDesktopError::InvalidInput(
            "Already have an active stake. Unstake first.".into(),
        ));
    }

    let mut chain   = load_chain();
    let balance     = chain.balance_of(&from);
    if amount_uegoc > balance {
        return Err(EgoDesktopError::InvalidInput(format!(
            "Insufficient balance: have {} uEGOC, need {}",
            balance, amount_uegoc
        )));
    }

    let nonce      = ledger.nonce + 1;
    let ts         = chrono::Utc::now().timestamp();
    let sign_bytes = tx_signing_bytes(&from, STAKING_ADDR, amount_uegoc, nonce, ts);
    let sig_hex    = if let Some(kp) = state.get_keypair() {
        hex::encode(kp.sign_ed25519(&sign_bytes).as_bytes())
    } else {
        return Err(EgoDesktopError::WalletError("Wallet not initialized".into()));
    };
    let tx_hash = format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex());

    chain.transactions.push(LedgerTx {
        hash:         tx_hash.clone(),
        from:         from.clone(),
        to:           STAKING_ADDR.to_string(),
        amount:       amount_uegoc,
        memo:         Some(format!("Stake {} days", lock_days)),
        timestamp:    ts,
        signature:    sig_hex,
        status:       "Pending".into(),
        block_height: None,
        nonce,
    });
    chain.mine_block(&tx_hash, &from);
    save_chain(&chain).map_err(|e| EgoDesktopError::WalletError(format!("Save chain: {e}")))?;

    if let (Some(tx_b), Some(blk_b)) = (
        chain.transactions.iter().find(|t| t.hash == tx_hash).cloned(),
        chain.blocks.last().cloned(),
    ) {
        let tx2  = tx_b.clone();
        let blk2 = blk_b.clone();
        tokio::spawn(async move { crate::p2p::push_tx_to_relay(&tx2, &blk2).await; });
        tokio::spawn(async move { crate::p2p::broadcast_tx(tx_b, blk_b).await; });
    }

    ledger.staked_amount    = amount_uegoc;
    ledger.staked_at        = Some(ts);
    ledger.stake_lock_days  = lock_days;
    ledger.unstake_at       = Some(ts + (lock_days as i64 * 24 * 3600));
    ledger.nonce            = nonce;
    ledger.save().map_err(EgoDesktopError::FileSystemError)?;

    Ok(())
}

#[tauri::command]
pub async fn unstake_coins(state: State<'_, AppState>) -> Result<(), EgoDesktopError> {
    let mut ledger = Ledger::load();
    let from = ledger.address.clone();
    if from.is_empty() {
        return Err(EgoDesktopError::WalletError("Wallet not initialized".into()));
    }
    if ledger.staked_amount == 0 {
        return Err(EgoDesktopError::InvalidInput("No active stake found.".into()));
    }

    let now = chrono::Utc::now().timestamp();
    if let Some(unlock_at) = ledger.unstake_at {
        if now < unlock_at {
            let days_left = ((unlock_at - now) / 86400) + 1;
            return Err(EgoDesktopError::InvalidInput(format!(
                "Stake is still locked. {} day(s) remaining.", days_left
            )));
        }
    }

    let amount   = ledger.staked_amount;
    let mut chain = load_chain();
    let nonce    = ledger.nonce + 1;
    let ts       = now;
    let sign_bytes = tx_signing_bytes(STAKING_ADDR, &from, amount, nonce, ts);
    let tx_hash  = format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex());

    chain.transactions.push(LedgerTx {
        hash:         tx_hash.clone(),
        from:         STAKING_ADDR.to_string(),
        to:           from.clone(),
        amount,
        memo:         Some("Unstake return".to_string()),
        timestamp:    ts,
        signature:    "staking_system".to_string(),
        status:       "Pending".into(),
        block_height: None,
        nonce,
    });
    chain.mine_block(&tx_hash, &from);
    save_chain(&chain).map_err(|e| EgoDesktopError::WalletError(format!("Save chain: {e}")))?;

    if let (Some(tx_b), Some(blk_b)) = (
        chain.transactions.iter().find(|t| t.hash == tx_hash).cloned(),
        chain.blocks.last().cloned(),
    ) {
        let tx2  = tx_b.clone();
        let blk2 = blk_b.clone();
        tokio::spawn(async move { crate::p2p::push_tx_to_relay(&tx2, &blk2).await; });
        tokio::spawn(async move { crate::p2p::broadcast_tx(tx_b, blk_b).await; });
    }

    ledger.staked_amount   = 0;
    ledger.staked_at       = None;
    ledger.stake_lock_days = 0;
    ledger.unstake_at      = None;
    ledger.nonce           = nonce;
    ledger.save().map_err(EgoDesktopError::FileSystemError)?;

    Ok(())
}
