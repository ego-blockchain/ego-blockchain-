use crate::app::AppState;
use crate::error::EgoDesktopError;
use crate::ledger::{load_chain, tx_signing_bytes_v2, Ledger, LedgerTx};
use crate::tokenomics::{staking_pool_remaining_uegoc, effective_apr_bps};
use serde::{Deserialize, Serialize};
use tauri::State;

const STAKING_ADDR: &str = "egot1staking000000000000000000000000000000000";
const STAKING_CHAIN_ID: u8 = 1;

/// Maximum share of total network stake any single validator may hold (5%).
/// Prevents stake concentration attacks — an attacker controlling >33% of
/// stake could halt the chain; >67% could corrupt it.
const MAX_STAKE_FRACTION: f64 = 0.05;

/// Minimum number of validators before the concentration cap is enforced.
/// Below this floor we want MORE validators to join, not fewer — so we
/// skip the cap entirely to allow the network to bootstrap.
const MIN_VALIDATORS_BEFORE_CAP: usize = 3;

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
    tokio::task::spawn_blocking(|| {
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

        Ok::<_, EgoDesktopError>(StakingInfo {
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
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
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
    let fee_uegoc = crate::tokenomics::fee_for_tx_with_staking("stake", false);
    let total_needed = amount_uegoc.saturating_add(fee_uegoc);
    if total_needed > balance {
        return Err(EgoDesktopError::InvalidInput(format!(
            "Insufficient balance: have {} uEGOC, need {} (stake {} + fee {})",
            balance, total_needed, amount_uegoc, fee_uegoc
        )));
    }

    // ── Per-validator stake concentration cap ─────────────────────────────
    // Once the network has MIN_VALIDATORS_BEFORE_CAP active stakers, no
    // single validator may hold more than MAX_STAKE_FRACTION of total stake.
    // This means an attacker always needs to compromise many independent
    // parties to reach the 33% halt threshold.
    {
        let active_count = crate::ledger::active_validator_count();
        if active_count >= MIN_VALIDATORS_BEFORE_CAP {
            let total_staked = crate::ledger::total_network_stake();
            let existing_stake = crate::ledger::get_validator_stake(&from);
            // What the network total will be after this stake is added.
            let new_network_total = total_staked
                .saturating_add(amount_uegoc)
                .saturating_sub(existing_stake); // don't double-count own existing stake
            let new_this_stake = existing_stake.saturating_add(amount_uegoc);
            let max_allowed = (new_network_total as f64 * MAX_STAKE_FRACTION) as u64;
            if new_this_stake > max_allowed {
                return Err(EgoDesktopError::InvalidInput(format!(
                    "Stake would exceed the per-validator cap of {}% of total network stake. \
                     Your stake: {:.4} EGOC → max allowed: {:.4} EGOC \
                     ({}% of {:.2} EGOC total). \
                     This limit prevents any single validator from controlling \
                     enough stake to attack the network.",
                    (MAX_STAKE_FRACTION * 100.0) as u32,
                    new_this_stake as f64 / 1_000_000.0,
                    max_allowed as f64 / 1_000_000.0,
                    (MAX_STAKE_FRACTION * 100.0) as u32,
                    new_network_total as f64 / 1_000_000.0,
                )));
            }
        }
    }

    let nonce      = ledger.nonce + 1;
    let ts         = chrono::Utc::now().timestamp();
    let memo       = format!("stake:{lock_days}");
    let sign_bytes = tx_signing_bytes_v2(
        &from,
        STAKING_ADDR,
        amount_uegoc,
        nonce,
        ts,
        STAKING_CHAIN_ID,
        &memo,
    );
    let (sig_hex, pubkey_hex, dil_sig_hex, dil_pubkey_hex) = if let Some(kp) = state.get_keypair() {
        let ed_sig = kp.sign_ed25519(&sign_bytes);
        let dil_sig = kp.sign_dilithium(&sign_bytes);
        (
            hex::encode(ed_sig.as_bytes()),
            hex::encode(kp.ed25519_public_key().as_bytes()),
            hex::encode(&dil_sig.signature_data),
            hex::encode(kp.dilithium_public_key().key_data),
        )
    } else {
        return Err(EgoDesktopError::WalletError("Wallet not initialized".into()));
    };
    let tx_hash = format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex());

    crate::mempool::get_mempool().push(LedgerTx {
        hash:               tx_hash.clone(),
        from:               from.clone(),
        to:                 STAKING_ADDR.to_string(),
        amount:             amount_uegoc,
        memo:               Some(memo),
        timestamp:          ts,
        signature:          sig_hex,
        status:             "Pending".into(),
        block_height:       None,
        nonce,
        public_key_ed25519: pubkey_hex,
        dilithium_pubkey:   dil_pubkey_hex,
        dilithium_signature: dil_sig_hex,
        tx_type:            "stake".to_string(),
        fee_uegoc,
        tx_version:         2,
        chain_id:           STAKING_CHAIN_ID,
        ..LedgerTx::default()
    });

    ledger.staked_amount         = amount_uegoc;
    ledger.staked_at             = Some(ts);
    ledger.stake_lock_days       = lock_days;
    ledger.unstake_at            = Some(ts + (lock_days as i64 * 24 * 3600));
    ledger.nonce                 = nonce;
    // Record the TX hash so startup reconciliation can verify it was actually mined.
    ledger.pending_stake_tx_hash = tx_hash.clone();
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

    let memo = if is_locked && early { "unstake:early" } else { "unstake" }.to_string();
    let fee_uegoc = crate::tokenomics::fee_for_tx_with_staking("unstake", true);
    let kp = match state.get_keypair() {
        Some(k) => k,
        None    => return Err(EgoDesktopError::WalletError("Wallet not initialized".into())),
    };

    let unstake_nonce = ledger.nonce + 1;
    let sign_bytes = tx_signing_bytes_v2(
        &from,
        STAKING_ADDR,
        staked_amount,
        unstake_nonce,
        ts,
        STAKING_CHAIN_ID,
        &memo,
    );
    let ed_sig = kp.sign_ed25519(&sign_bytes);
    let dil_sig = kp.sign_dilithium(&sign_bytes);
    let unstake_hash = format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex());

    crate::mempool::get_mempool().push(LedgerTx {
        hash:                unstake_hash,
        from:                from.clone(),
        to:                  STAKING_ADDR.to_string(),
        amount:              staked_amount,
        memo:                Some(memo),
        timestamp:           ts,
        signature:           hex::encode(ed_sig.as_bytes()),
        status:              "Pending".into(),
        block_height:        None,
        nonce:               unstake_nonce,
        public_key_ed25519:  hex::encode(kp.ed25519_public_key().as_bytes()),
        dilithium_pubkey:    hex::encode(kp.dilithium_public_key().key_data),
        dilithium_signature: hex::encode(&dil_sig.signature_data),
        tx_type:             "unstake".to_string(),
        fee_uegoc,
        tx_version:          2,
        chain_id:            STAKING_CHAIN_ID,
        ..LedgerTx::default()
    });

    // Both principal AND accrued APR reward are settled deterministically at
    // block-commit, derived from on-chain data (see chain_db: unstake_credit_amount
    // for principal, staking_reward_for_unstake for the APR reward paid from
    // STAKING_POOL_ADDR). The "unstake" signal tx above is the only tx we emit;
    // the credits are protocol-derived, so there is no self-asserted reward tx
    // and no mint surface. `accrued_rewards` here is only for the optimistic UI
    // estimate — the authoritative figure is recomputed on-chain.
    let _ = accrued_rewards;
    ledger.staked_amount         = 0;
    ledger.staked_at             = None;
    ledger.stake_lock_days       = 0;
    ledger.unstake_at            = None;
    ledger.pending_stake_tx_hash = String::new();
    ledger.nonce                 = unstake_nonce;
    ledger.save().map_err(EgoDesktopError::FileSystemError)?;
    Ok(())
}

// ── Consensus health ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ConsensusHealth {
    pub active_validators:       usize,
    pub min_validators_required: usize,
    pub is_bft_ready:            bool,
    pub total_staked_uegoc:      u64,
    pub max_stake_fraction_pct:  u32,
    pub my_stake_uegoc:          u64,
    pub my_stake_pct:            f64,
}

#[tauri::command]
pub async fn get_consensus_health() -> Result<ConsensusHealth, EgoDesktopError> {
    tokio::task::spawn_blocking(|| {
        let ledger   = crate::ledger::Ledger::load();
        let active   = crate::ledger::active_validator_count();
        let total    = crate::ledger::total_network_stake();
        let my_stake = crate::ledger::get_validator_stake(&ledger.address);
        let my_pct   = if total > 0 { my_stake as f64 / total as f64 * 100.0 } else { 0.0 };

        Ok::<_, EgoDesktopError>(ConsensusHealth {
            active_validators:       active,
            min_validators_required: crate::mempool::min_validators_for_finality(),
            is_bft_ready:            active >= crate::mempool::min_validators_for_finality(),
            total_staked_uegoc:      total,
            max_stake_fraction_pct:  (MAX_STAKE_FRACTION * 100.0) as u32,
            my_stake_uegoc:          my_stake,
            my_stake_pct:            my_pct,
        })
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}
