use crate::app::{AppState, EarningsData, RewardBreakdown};
use crate::error::EgoDesktopError;
use crate::ledger::{load_chain, poc_signing_bytes, Ledger, LedgerTx};
use serde::{Deserialize, Serialize};
use tauri::State;

use crate::tokenomics::{
    storage_reward_uegoc, consensus_daily_uegoc, coverage_daily_uegoc,
    retrieval_reward_uegoc, node_reward_scale,
};

#[tauri::command]
pub async fn get_earnings_data(
    state: State<'_, AppState>,
) -> Result<EarningsData, EgoDesktopError> {
    let now = chrono::Utc::now().timestamp();
    let ledger = Ledger::load();

    // ── Reward rates ─────────────────────────────────────────────────────────

    // Only count bytes from files that are actively passing PoSt challenges.
    // Files with proof_suspended_until > now are withheld from the reward base.
    let provable_bytes: u64 = ledger.stored_files.iter()
        .filter(|f| {
            f.status == "Active"
                && (f.owner.is_empty() || f.owner == ledger.address)
                && f.proof_suspended_until <= now
                && !f.local_path.is_empty()
                && !f.local_path.starts_with("sender:")
        })
        .map(|f| f.encrypted_size)
        .sum();
    // Use the smaller of: allocated capacity vs. sum of bytes we can actually prove.
    // This prevents claiming rewards for space you declare but don't fill.
    let allocated_gb = (ledger.storage_allocated_bytes as f64 / 1_000_000_000.0)
        .min(provable_bytes as f64 / 1_000_000_000.0 + 0.001);

    // Scale all node-pool rewards by the depletion factor (full until 80% used, tapers to 0).
    let chain = load_chain();
    let scale = node_reward_scale(&chain);

    // If the node lowered its allocation it receives a 14-day reward suspension.
    let reward_suspended = ledger.reward_suspended_until
        .map(|until| now < until)
        .unwrap_or(false);

    let daily_storage  = if reward_suspended { 0 } else { (storage_reward_uegoc(allocated_gb) as f64 * scale) as u64 };
    let consensus_rate = if reward_suspended { 0 } else { (consensus_daily_uegoc() as f64 * scale) as u64 };
    let retrieval_rate = if reward_suspended { 0 } else { (retrieval_reward_uegoc(1.0) as f64 * scale) as u64 };

    // Coverage reward is only earned while the node is online.
    let coverage_online = state
        .cache
        .lock()
        .unwrap()
        .coverage_status
        .as_ref()
        .map(|s| s.is_online)
        .unwrap_or(true); // default true when coverage hasn't been checked yet

    let coverage_rate = if reward_suspended || !coverage_online { 0 }
                        else { (coverage_daily_uegoc() as f64 * scale) as u64 };

    let daily_total_base = daily_storage
        .saturating_add(consensus_rate)
        .saturating_add(coverage_rate)
        .saturating_add(retrieval_rate);

    // ── DRS multiplier ────────────────────────────────────────────────────────
    // Fetch live DRS score from relay (0–100). Multiplier: 0.5 at score 0, 1.5 at score 100.
    // Falls back to 1.0 (neutral) if the relay is unreachable so rewards still accrue.
    let drs_score: f64 = {
        let address = ledger.address.clone();
        if address.is_empty() {
            50.0 // no wallet yet → neutral
        } else {
            let url = format!("{}/poc/score/{}", crate::p2p::ORACLE_RPC, address);
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .ok()
                .and_then(|c| {
                    // block_in_place is safe here because get_earnings_data runs on a Tokio thread
                    tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(async {
                            c.get(&url).send().await.ok()?.json::<PocScoreResult>().await.ok()
                        })
                    })
                })
                .map(|r| r.drs_score.clamp(0.0, 100.0))
                .unwrap_or(50.0) // relay down → neutral (1.0×)
        }
    };
    let drs_multiplier = 0.5 + (drs_score / 100.0); // 0.5× … 1.5×
    let daily_total = (daily_total_base as f64 * drs_multiplier) as u64;

    // Minimum 1-hour gap between reward credits. Earnings page may be polled every
    // few seconds — without this gate every poll would push a tx and create a block.
    const MIN_CREDIT_INTERVAL_SECS: i64 = 3_600;

    let last_credit = state.get_last_earnings_credit();
    if last_credit == 0 {
        // First call — prime the total_earned cache from chain history once,
        // then initialise the clock (no credit issued yet).
        let historical: u64 = crate::chain_db::get_tx_history_for_addr(&ledger.address)
            .into_iter()
            .filter(|tx| tx.from.starts_with("egot1rewards") && tx.status == "Confirmed")
            .map(|tx| tx.amount)
            .sum();
        state.set_cached_total_earned(historical);
        state.set_last_earnings_credit(now);
    } else if (now - last_credit) >= MIN_CREDIT_INTERVAL_SECS {
        let elapsed_secs = (now - last_credit) as f64;
        let credit = (daily_total as f64 * elapsed_secs / 86_400.0) as u64;

        // Credit at least 1 EGOC (1_000_000 uEGOC) at a time.
        if credit >= 1_000_000 {
            let reward_hash = format!(
                "0x{}",
                ego_core::hash_data(
                    format!("reward:{}:{}", ledger.address, now).as_bytes()
                ).to_hex()
            );
            if crate::chain_db::get_tx_by_hash(&reward_hash).is_none() {
                crate::mempool::get_mempool().push(LedgerTx {
                    hash:                reward_hash,
                    from:                "egot1rewards00000000000000000000000000000000000".into(),
                    to:                  ledger.address.clone(),
                    amount:              credit,
                    memo:                Some("Block & storage rewards".into()),
                    timestamp:           now,
                    signature:           "rewards".into(),
                    status:              "Pending".into(),
                    nonce:               0,
                    tx_type:             "reward".into(),
                    public_key_ed25519:  String::new(),
                    dilithium_pubkey:    String::new(),
                    dilithium_signature: String::new(),
                    ..LedgerTx::default()
                });
                // Update cache so we don't rescan the full chain on next poll.
                state.add_to_cached_total_earned(credit);
            }
        }
        // Advance the clock only after attempting a credit — not on every poll.
        state.set_last_earnings_credit(now);
    }

    let total_earned: u64 = state.get_cached_total_earned();
    let pending      = daily_storage / 24;

    let session_started = state.get_session_started();

    let earnings = EarningsData {
        daily_rewards:  daily_total,
        epoch_rewards:  daily_total.saturating_mul(7),
        total_earned,
        drs_multiplier,
        reward_breakdown: RewardBreakdown {
            storage_rewards:   daily_storage,
            consensus_rewards: consensus_rate,
            coverage_rewards:  coverage_rate,
            retrieval_rewards: retrieval_rate,
        },
        pending_rewards: pending,
        session_started,
        coverage_online,
        reward_suspended_until: ledger.reward_suspended_until,
    };

    state.update_earnings_data(earnings.clone());
    Ok(earnings)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PocEventResult {
    pub success:      bool,
    pub message:      String,
    pub reward_uegoc: u64,
    pub drs_score:    Option<f64>,
}

#[tauri::command]
pub async fn submit_poc_event(
    quality:  String,
    peers:    u32,
    h3_cell:  Option<String>,
    state:    State<'_, AppState>,
) -> Result<PocEventResult, EgoDesktopError> {
    let ledger = Ledger::load();
    let address = ledger.address.clone();
    if address.is_empty() {
        return Err(EgoDesktopError::WalletError("Wallet not initialized".into()));
    }

    // Sign the event
    let timestamp = chrono::Utc::now().timestamp();
    let h3 = h3_cell.as_deref().unwrap_or("");
    let signing_bytes = poc_signing_bytes(&address, &quality, peers, h3, timestamp);

    let (signature_hex, pubkey_hex) = if let Some(kp) = state.get_keypair() {
        let sig = kp.sign_ed25519(&signing_bytes);
        let pk  = hex::encode(kp.ed25519_public_key().as_bytes());
        (hex::encode(sig.as_bytes()), pk)
    } else {
        return Err(EgoDesktopError::WalletError("Wallet not initialized".into()));
    };

    // POST to relay
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| EgoDesktopError::WalletError(e.to_string()))?;

    #[derive(Serialize)]
    struct PocReq<'a> {
        address:    &'a str,
        quality:    &'a str,
        peers:      u32,
        h3_cell:    Option<&'a str>,
        timestamp:  i64,
        signature:  &'a str,
        public_key: &'a str,
    }

    let payload = PocReq {
        address:    &address,
        quality:    &quality,
        peers,
        h3_cell:    h3_cell.as_deref(),
        timestamp,
        signature:  &signature_hex,
        public_key: &pubkey_hex,
    };

    let url = format!("{}/poc/event", crate::p2p::ORACLE_RPC);
    match client.post(&url).json(&payload).send().await {
        Ok(resp) => {
            #[derive(Deserialize)]
            struct RelayResp { success: bool, message: String }
            let status = resp.status();
            match resp.json::<RelayResp>().await {
                Ok(r) => {
                    // Parse reward from message "PoC event accepted, reward: 22222 uEGOC (DRS updated)"
                    let reward_uegoc = r.message.split_whitespace()
                        .find_map(|w| w.parse::<u64>().ok())
                        .unwrap_or(0);
                    Ok(PocEventResult {
                        success: r.success,
                        message: r.message,
                        reward_uegoc,
                        drs_score: None,
                    })
                }
                Err(_) => Ok(PocEventResult {
                    success: status.is_success(),
                    message: format!("Relay responded with {}", status),
                    reward_uegoc: 0,
                    drs_score: None,
                }),
            }
        }
        Err(e) => Ok(PocEventResult {
            success: false,
            message: format!("Relay unreachable: {}", e),
            reward_uegoc: 0,
            drs_score: None,
        }),
    }
}

// ── get_poc_score ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct PocScoreResult {
    pub drs_score:      f64,
    pub events_24h:     u32,
    pub total_events:   u64,
    pub last_event:     Option<i64>,
    pub is_validator:   bool,
    pub validator_rank: Option<usize>,
}

#[tauri::command]
pub async fn get_poc_score(
    state: State<'_, AppState>,
) -> Result<PocScoreResult, EgoDesktopError> {
    let address = Ledger::load().address;
    if address.is_empty() {
        return Ok(PocScoreResult {
            drs_score: 0.0, events_24h: 0, total_events: 0,
            last_event: None, is_validator: false, validator_rank: None,
        });
    }
    let _ = state;
    let url = format!("{}/poc/score/{}", crate::p2p::ORACLE_RPC, address);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .map_err(|e| EgoDesktopError::WalletError(e.to_string()))?;
    match client.get(&url).send().await {
        Ok(resp) => {
            resp.json::<PocScoreResult>().await.map_err(|e| {
                EgoDesktopError::WalletError(format!("Parse error: {e}"))
            })
        }
        Err(e) => Ok(PocScoreResult {
            drs_score: 0.0, events_24h: 0, total_events: 0,
            last_event: None, is_validator: false,
            validator_rank: None,
        }),
    }
}
