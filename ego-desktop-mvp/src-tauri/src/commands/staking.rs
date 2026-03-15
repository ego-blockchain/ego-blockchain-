use crate::app::AppState;
use crate::error::EgoDesktopError;
use crate::ledger::{load_chain, save_chain, tx_signing_bytes, Ledger, LedgerTx};
use serde::{Deserialize, Serialize};
use tauri::State;

const STAKING_ADDR: &str = "egot1staking000000000000000000000000000000000";

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
    let projected_interest = if ledger.staked_amount > 0 {
        ledger.staked_amount * 125 * (ledger.stake_lock_days as u64) / (1000 * 365)
    } else {
        0
    };
    let early_unstake_fee = ledger.staked_amount / 10;

    Ok(StakingInfo {
        staked_amount:     ledger.staked_amount,
        lock_period_days:  ledger.stake_lock_days,
        apr:               12.5,
        pending_rewards:   0,
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
    let mut chain     = load_chain();
    let ts            = now;

    if is_locked && early {
        // Early unstake: charge 10% fee
        let fee           = staked_amount / 10;
        let return_amount = staked_amount - fee;
        let kp = match state.get_keypair() {
            Some(k) => k,
            None    => return Err(EgoDesktopError::WalletError("Wallet not initialized".into())),
        };

        // Unstake signal tx: user → staking contract, memo="unstake" (source of truth for relay)
        let unstake_nonce      = ledger.nonce + 1;
        let unstake_sign_bytes = tx_signing_bytes(&from, STAKING_ADDR, staked_amount, unstake_nonce, ts);
        let unstake_sig_hex    = hex::encode(kp.sign_ed25519(&unstake_sign_bytes).as_bytes());
        let unstake_hash       = format!("0x{}", ego_core::hash_data(&unstake_sign_bytes).to_hex());

        chain.transactions.push(LedgerTx {
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

        chain.transactions.push(LedgerTx {
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

        chain.transactions.push(LedgerTx {
            hash:               ret_hash.clone(),
            from:               STAKING_ADDR.to_string(),
            to:                 from.clone(),
            amount:             return_amount,
            memo:               Some("Early unstake return".to_string()),
            timestamp:          ts,
            signature:          "staking_system".to_string(),
            status:             "Pending".into(),
            block_height:       None,
            nonce:              ret_nonce,
            public_key_ed25519: String::new(), dilithium_pubkey: String::new(), dilithium_signature: String::new(),
            ..LedgerTx::default()
        });
        chain.mine_block(&ret_hash, &from);
        save_chain(&chain).map_err(|e| EgoDesktopError::WalletError(format!("Save chain: {e}")))?;

        if let (Some(unstake_tx), Some(fee_tx), Some(ret_tx), Some(blk)) = (
            chain.transactions.iter().find(|t| t.hash == unstake_hash).cloned(),
            chain.transactions.iter().find(|t| t.hash == fee_hash).cloned(),
            chain.transactions.iter().find(|t| t.hash == ret_hash).cloned(),
            chain.blocks.last().cloned(),
        ) {
            let unstake_tx2 = unstake_tx.clone();
            let fee_tx2     = fee_tx.clone();
            let ret_tx2     = ret_tx.clone();
            let blk_a = blk.clone(); let blk_b = blk.clone();
            let blk_c = blk.clone(); let blk_d = blk.clone();
            let blk_e = blk.clone(); let blk_f = blk;
            tokio::spawn(async move { crate::p2p::push_tx_to_relay(&unstake_tx, &blk_a).await; });
            tokio::spawn(async move { crate::p2p::broadcast_tx(unstake_tx2, blk_b).await; });
            tokio::spawn(async move { crate::p2p::push_tx_to_relay(&fee_tx,    &blk_c).await; });
            tokio::spawn(async move { crate::p2p::broadcast_tx(fee_tx2, blk_d).await; });
            tokio::spawn(async move { crate::p2p::push_tx_to_relay(&ret_tx,    &blk_e).await; });
            tokio::spawn(async move { crate::p2p::broadcast_tx(ret_tx2, blk_f).await; });
        }

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

        chain.transactions.push(LedgerTx {
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

        // Return tx: staking contract → user
        let ret_nonce      = unstake_nonce + 1;
        let ret_sign_bytes = tx_signing_bytes(STAKING_ADDR, &from, staked_amount, ret_nonce, ts);
        let ret_hash       = format!("0x{}", ego_core::hash_data(&ret_sign_bytes).to_hex());

        chain.transactions.push(LedgerTx {
            hash:               ret_hash.clone(),
            from:               STAKING_ADDR.to_string(),
            to:                 from.clone(),
            amount:             staked_amount,
            memo:               Some("Unstake return".to_string()),
            timestamp:          ts,
            signature:          "staking_system".to_string(),
            status:             "Pending".into(),
            block_height:       None,
            nonce:              ret_nonce,
            public_key_ed25519: String::new(), dilithium_pubkey: String::new(), dilithium_signature: String::new(),
            ..LedgerTx::default()
        });
        chain.mine_block(&ret_hash, &from);
        save_chain(&chain).map_err(|e| EgoDesktopError::WalletError(format!("Save chain: {e}")))?;

        if let (Some(unstake_tx), Some(ret_tx), Some(blk)) = (
            chain.transactions.iter().find(|t| t.hash == unstake_hash).cloned(),
            chain.transactions.iter().find(|t| t.hash == ret_hash).cloned(),
            chain.blocks.last().cloned(),
        ) {
            let unstake_tx2 = unstake_tx.clone();
            let ret_tx2     = ret_tx.clone();
            let blk_a = blk.clone(); let blk_b = blk.clone();
            let blk_c = blk.clone(); let blk_d = blk;
            tokio::spawn(async move { crate::p2p::push_tx_to_relay(&unstake_tx, &blk_a).await; });
            tokio::spawn(async move { crate::p2p::broadcast_tx(unstake_tx2, blk_b).await; });
            tokio::spawn(async move { crate::p2p::push_tx_to_relay(&ret_tx,    &blk_c).await; });
            tokio::spawn(async move { crate::p2p::broadcast_tx(ret_tx2, blk_d).await; });
        }

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
