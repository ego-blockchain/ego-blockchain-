use crate::app::AppState;
use crate::error::EgoDesktopError;
use crate::ledger::{load_chain, tx_signing_bytes, Ledger, LedgerTx};
use crate::tokenomics::{STAKING_APR_BPS, staking_pool_remaining_uegoc};
use serde::{Deserialize, Serialize};
use tauri::State;

const STAKING_ADDR: &str = "egot1staking000000000000000000000000000000000";

/// Returns effective APR in basis points including lock-period bonus.
/// Matches the LOCK_OPTIONS bonuses shown in the frontend.
///   30 days  →  0 bp bonus → 12.50%
///   90 days  → +200 bp     → 14.50%
///  180 days  → +500 bp     → 17.50%
///  365 days  → +1000 bp    → 22.50%
fn effective_apr_bps(lock_days: u32) -> u64 {
    let bonus: u64 = match lock_days {
        d if d >= 365 => 1_000,
        d if d >= 180 =>   500,
        d if d >=  90 =>   200,
        _             =>     0,
    };
    STAKING_APR_BPS + bonus
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StakingInfo {
    pub staked_amount:     u64,
    pub lock_period_days:  u32,
    pub apr:               f64,
    pub pending_rewards:   u64,
    pub unlock_date:       Option<i64>,
    pub staked_at:         Option<i64>,
    pub is_locked:         bool,
    pub projected_interest: u64,
    pub early_unstake_fee:  u64,
}

#[tauri::command]
pub async fn get_staking_info() -> Result<StakingInfo, EgoDesktopError> {
    let ledger = Ledger::load();
    let now    = chrono::Utc::now().timestamp();
    let is_locked = ledger.staked_amount > 0
        && ledger.unstake_at.map(|u| u > now).unwrap_or(false);

    let staked_since_secs = ledger.staked_at
        .map(|t| (now - t).max(0) as u64)
        .unwrap_or(0);

    let apr_bps = effective_apr_bps(ledger.stake_lock_days);

    let pending_rewards = if ledger.staked_amount > 0 && staked_since_secs > 0 {
        let chain = load_chain();
        let pool_left = staking_pool_remaining_uegoc(&chain);
        if pool_left > 0 {
            (ledger.staked_amount as u128
                * apr_bps as u128
                * staked_since_secs as u128
                / (10_000 * 31_536_000)) as u64
        } else {
            0
        }
    } else {
        0
    };

    let projected_interest = if ledger.staked_amount > 0 && ledger.stake_lock_days > 0 {
        (ledger.staked_amount as u128
            * apr_bps as u128
            * ledger.stake_lock_days as u128
            / (10_000 * 365)) as u64
    } else {
        0
    };
    let early_unstake_fee = ledger.staked_amount / 10;

    Ok(StakingInfo {
        staked_amount:     ledger.staked_amount,
        lock_period_days:  ledger.stake_lock_days,
        apr:               apr_bps as f64 / 100.0,
        pending_rewards,
        unlock_date:       ledger.unstake_at,
        staked_at:         ledger.staked_at,
        is_locked,
        projected_interest,
        early_unstake_fee,
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
    if lock_days > 1825 {
        // 5 years maximum — prevents u64 overflow in reward calculations.
        return Err(EgoDesktopError::InvalidInput(
            "Lock period too long (max 1825 days / 5 years)".into(),
        ));
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

    let chain   = load_chain();
    let balance = chain.balance_of(&from);
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

    crate::mempool::get_mempool().push(LedgerTx {
        hash:               tx_hash.clone(),
        from:               from.clone(),
        to:                 STAKING_ADDR.to_string(),
        amount:             amount_uegoc,
        memo:               Some("stake".to_string()),
        timestamp:          ts,
        signature:          sig_hex,
        status:             "Pending".into(),
        block_height:       None,
        nonce,
        public_key_ed25519: String::new(), dilithium_pubkey: String::new(), dilithium_signature: String::new(),
        ..LedgerTx::default()
    });

    ledger.staked_amount    = amount_uegoc;
    ledger.staked_at        = Some(ts);
    ledger.stake_lock_days  = lock_days;
    ledger.unstake_at       = Some(ts + (lock_days as i64 * 24 * 3600));
    ledger.nonce            = nonce;
    ledger.save().map_err(EgoDesktopError::FileSystemError)?;

    // The on-chain stake TX (already pushed above) is the source of truth for
    // the relay's DRS computation — no separate stake registry call needed.

    Ok(())
}

#[tauri::command]
pub async fn unstake_coins(early: bool, state: State<'_, AppState>) -> Result<(), EgoDesktopError> {
    let mut ledger = Ledger::load();
    let from = ledger.address.clone();
    if from.is_empty() {
        return Err(EgoDesktopError::WalletError("Wallet not initialized".into()));
    }
    if ledger.staked_amount == 0 {
        return Err(EgoDesktopError::InvalidInput("No active stake found.".into()));
    }

    let now = chrono::Utc::now().timestamp();
    let is_locked = ledger.unstake_at.map(|u| now < u).unwrap_or(false);

    if is_locked && !early {
        let days_left = ledger.unstake_at
            .map(|u| ((u - now) / 86400) + 1)
            .unwrap_or(1);
        return Err(EgoDesktopError::InvalidInput(format!(
            "Stake is still locked. {} day(s) remaining.", days_left
        )));
    }

    let staked_amount = ledger.staked_amount;
    let ts            = now;

    // Accrue rewards up to now (same formula as get_staking_info).
    let staked_since_secs = ledger.staked_at.map(|t| (now - t).max(0) as u64).unwrap_or(0);
    let apr_bps = effective_apr_bps(ledger.stake_lock_days);
    let accrued_rewards: u64 = {
        let chain     = load_chain();
        let pool_left = staking_pool_remaining_uegoc(&chain);
        if pool_left > 0 && staked_since_secs > 0 {
            let raw = (staked_amount as u128
                * apr_bps as u128
                * staked_since_secs as u128
                / (10_000 * 31_536_000)) as u64;
            raw.min(pool_left)
        } else { 0 }
    };

    if is_locked && early {
        // Early unstake: charge 10% fee on principal only; rewards still paid in full.
        let fee           = staked_amount / 10;
        let return_amount = (staked_amount - fee) + accrued_rewards;
        let kp = match state.get_keypair() {
            Some(k) => k,
            None    => return Err(EgoDesktopError::WalletError("Wallet not initialized".into())),
        };

        // Unstake signal tx: user → staking contract, memo="unstake" (source of truth for relay)
        let unstake_nonce      = ledger.nonce + 1;
        let unstake_sign_bytes = tx_signing_bytes(&from, STAKING_ADDR, staked_amount, unstake_nonce, ts);
        let unstake_sig_hex    = hex::encode(kp.sign_ed25519(&unstake_sign_bytes).as_bytes());
        let unstake_hash       = format!("0x{}", ego_core::hash_data(&unstake_sign_bytes).to_hex());

        crate::mempool::get_mempool().push(LedgerTx {
            hash:               unstake_hash.clone(),
            from:               from.clone(),
            to:                 STAKING_ADDR.to_string(),
            amount:             staked_amount,
            memo:               Some("unstake".to_string()),
            timestamp:          ts,
            signature:          unstake_sig_hex,
            status:             "Pending".into(),
            block_height:       None,
            nonce:              unstake_nonce,
            public_key_ed25519: String::new(), dilithium_pubkey: String::new(), dilithium_signature: String::new(),
            ..LedgerTx::default()
        });

        // Fee tx: user → staking contract (10% penalty)
        let fee_nonce      = unstake_nonce + 1;
        let fee_sign_bytes = tx_signing_bytes(&from, STAKING_ADDR, fee, fee_nonce, ts);
        let fee_sig_hex    = hex::encode(kp.sign_ed25519(&fee_sign_bytes).as_bytes());
        let fee_hash       = format!("0x{}", ego_core::hash_data(&fee_sign_bytes).to_hex());

        crate::mempool::get_mempool().push(LedgerTx {
            hash:               fee_hash.clone(),
            from:               from.clone(),
            to:                 STAKING_ADDR.to_string(),
            amount:             fee,
            memo:               Some("Early unstake fee".to_string()),
            timestamp:          ts,
            signature:          fee_sig_hex,
            status:             "Pending".into(),
            block_height:       None,
            nonce:              fee_nonce,
            public_key_ed25519: String::new(), dilithium_pubkey: String::new(), dilithium_signature: String::new(),
            ..LedgerTx::default()
        });

        // Return tx: staking contract → user (90% returned)
        let ret_nonce      = fee_nonce + 1;
        let ret_sign_bytes = tx_signing_bytes(STAKING_ADDR, &from, return_amount, ret_nonce, ts);
        let ret_hash       = format!("0x{}", ego_core::hash_data(&ret_sign_bytes).to_hex());

        crate::mempool::get_mempool().push(LedgerTx {
            hash:               ret_hash.clone(),
            from:               STAKING_ADDR.to_string(),
            to:                 from.clone(),
            amount:             return_amount,
            memo:               Some(format!("Early unstake return (+{} uEGOC rewards)", accrued_rewards)),
            timestamp:          ts,
            signature:          "staking_system".to_string(),
            status:             "Pending".into(),
            block_height:       None,
            nonce:              ret_nonce,
            public_key_ed25519: String::new(), dilithium_pubkey: String::new(), dilithium_signature: String::new(),
            ..LedgerTx::default()
        });

        ledger.staked_amount   = 0;
        ledger.staked_at       = None;
        ledger.stake_lock_days = 0;
        ledger.unstake_at      = None;
        ledger.nonce           = ledger.nonce + 3;
        ledger.save().map_err(EgoDesktopError::FileSystemError)?;
        // On-chain unstake TX (memo="unstake") is the source of truth for the relay.
    } else {
        // Normal unstake (lock expired): return full amount
        let kp = match state.get_keypair() {
            Some(k) => k,
            None    => return Err(EgoDesktopError::WalletError("Wallet not initialized".into())),
        };

        // Unstake signal tx: user → staking contract, memo="unstake" (source of truth for relay)
        let unstake_nonce      = ledger.nonce + 1;
        let unstake_sign_bytes = tx_signing_bytes(&from, STAKING_ADDR, staked_amount, unstake_nonce, ts);
        let unstake_sig_hex    = hex::encode(kp.sign_ed25519(&unstake_sign_bytes).as_bytes());
        let unstake_hash       = format!("0x{}", ego_core::hash_data(&unstake_sign_bytes).to_hex());

        crate::mempool::get_mempool().push(LedgerTx {
            hash:               unstake_hash.clone(),
            from:               from.clone(),
            to:                 STAKING_ADDR.to_string(),
            amount:             staked_amount,
            memo:               Some("unstake".to_string()),
            timestamp:          ts,
            signature:          unstake_sig_hex,
            status:             "Pending".into(),
            block_height:       None,
            nonce:              unstake_nonce,
            public_key_ed25519: String::new(), dilithium_pubkey: String::new(), dilithium_signature: String::new(),
            ..LedgerTx::default()
        });

        // Return tx: staking contract → user (principal + accrued rewards)
        let total_return   = staked_amount + accrued_rewards;
        let ret_nonce      = unstake_nonce + 1;
        let ret_sign_bytes = tx_signing_bytes(STAKING_ADDR, &from, total_return, ret_nonce, ts);
        let ret_hash       = format!("0x{}", ego_core::hash_data(&ret_sign_bytes).to_hex());

        crate::mempool::get_mempool().push(LedgerTx {
            hash:               ret_hash.clone(),
            from:               STAKING_ADDR.to_string(),
            to:                 from.clone(),
            amount:             total_return,
            memo:               Some(format!("Unstake return (+{} uEGOC rewards)", accrued_rewards)),
            timestamp:          ts,
            signature:          "staking_system".to_string(),
            status:             "Pending".into(),
            block_height:       None,
            nonce:              ret_nonce,
            public_key_ed25519: String::new(), dilithium_pubkey: String::new(), dilithium_signature: String::new(),
            ..LedgerTx::default()
        });
        ledger.staked_amount   = 0;
        ledger.staked_at       = None;
        ledger.stake_lock_days = 0;
        ledger.unstake_at      = None;
        ledger.nonce           = unstake_nonce + 1;
        ledger.save().map_err(EgoDesktopError::FileSystemError)?;
        // On-chain unstake TX (memo="unstake") is the source of truth for the relay.
    }

    Ok(())
}
