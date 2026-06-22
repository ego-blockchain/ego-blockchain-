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

    // All blocking I/O in one spawn_blocking call.
    let (ledger, scale) = tokio::task::spawn_blocking(move || {
        let ledger = Ledger::load();
        let chain  = load_chain();
        let scale  = node_reward_scale(&chain);
        (ledger, scale)
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?;

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
    let allocated_gb = (ledger.storage_allocated_bytes as f64 / 1_000_000_000.0)
        .min(provable_bytes as f64 / 1_000_000_000.0 + 0.001);

    let reward_suspended = ledger.reward_suspended_until
        .map(|until| now < until)
        .unwrap_or(false);

    let daily_storage  = if reward_suspended { 0 } else { (storage_reward_uegoc(allocated_gb) as f64 * scale) as u64 };
    let consensus_rate = if reward_suspended { 0 } else { (consensus_daily_uegoc() as f64 * scale) as u64 };
    let retrieval_rate = if reward_suspended { 0 } else { (retrieval_reward_uegoc(1.0) as f64 * scale) as u64 };

    let coverage_online = state
        .cache
        .lock()
        .unwrap()
        .coverage_status
        .as_ref()
        .map(|s| s.is_online)
        .unwrap_or(true);

    let coverage_rate = if reward_suspended || !coverage_online { 0 }
                        else { (coverage_daily_uegoc() as f64 * scale) as u64 };

    let daily_total_base = daily_storage
        .saturating_add(consensus_rate)
        .saturating_add(coverage_rate)
        .saturating_add(retrieval_rate);

    let drs_score: f64 = if ledger.address.is_empty() {
        50.0
    } else {
        crate::poc::get_peer_score(&ledger.address) as f64
    };
    let drs_multiplier = 0.5 + (drs_score / 100.0);
    let daily_total = (daily_total_base as f64 * drs_multiplier) as u64;

    const MIN_CREDIT_INTERVAL_SECS: i64 = 3_600;

    let last_credit = state.get_last_earnings_credit();
    if last_credit == 0 {
        let address = ledger.address.clone();
        let historical: u64 = tokio::task::spawn_blocking(move || {
            crate::chain_db::get_tx_history_for_addr(&address)
                .into_iter()
                .filter(|tx| {
                    (tx.from == crate::chain_db::NODE_POOL_ADDR
                        || tx.from.starts_with("egot1rewards"))
                        && tx.status == "Confirmed"
                        && (tx.tx_type == "reward" || tx.tx_type == "coinbase")
                })
                .map(|tx| tx.amount)
                .sum::<u64>()
        })
        .await
        .unwrap_or(0);
        state.set_cached_total_earned(historical);
        state.set_last_earnings_credit(now);
    } else if (now - last_credit) >= MIN_CREDIT_INTERVAL_SECS {
        let elapsed_secs = (now - last_credit) as f64;
        let credit = (daily_total as f64 * elapsed_secs / 86_400.0) as u64;

        if credit >= 1_000_000 {
            let reward_hash = format!(
                "0x{}",
                ego_core::hash_data(
                    format!("reward:{}:{}", ledger.address, now).as_bytes()
                ).to_hex()
            );
            let hash_check = reward_hash.clone();
            let already_exists = tokio::task::spawn_blocking(move || {
                crate::chain_db::get_tx_by_hash(&hash_check).is_some()
            })
            .await
            .unwrap_or(false);

            if !already_exists {
                crate::mempool::get_mempool().push(LedgerTx {
                    hash:                reward_hash,
                    from:                crate::chain_db::NODE_POOL_ADDR.into(),
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
                state.add_to_cached_total_earned(credit);
            }
        }
        state.set_last_earnings_credit(now);
    }

    // Lifetime earnings: accumulate confirmed reward/coinbase credits for blocks above our
    // watermark into a PERSISTED total, so it survives app restarts and chain pruning (the
    // local chain only keeps recent blocks). This is the "report" figure the user sees.
    let addr = ledger.address.clone();
    let watermark = ledger.lifetime_counted_height;
    let (newly_earned, new_watermark) = tokio::task::spawn_blocking(move || {
        let mut sum: u64 = 0;
        let mut maxh = watermark;
        for tx in crate::chain_db::get_tx_history_for_addr(&addr) {
            let h = tx.block_height.unwrap_or(0);
            if h > watermark
                && tx.status == "Confirmed"
                && (tx.tx_type == "reward" || tx.tx_type == "coinbase")
                && (tx.from == crate::chain_db::NODE_POOL_ADDR || tx.from.starts_with("egot1rewards"))
            {
                sum = sum.saturating_add(tx.amount);
                if h > maxh { maxh = h; }
            }
        }
        (sum, maxh)
    })
    .await
    .unwrap_or((0, watermark));

    let total_earned = if newly_earned > 0 || new_watermark > watermark {
        tokio::task::spawn_blocking(move || {
            let mut l = Ledger::load();
            l.lifetime_earned_uegoc = l.lifetime_earned_uegoc.saturating_add(newly_earned);
            if new_watermark > l.lifetime_counted_height {
                l.lifetime_counted_height = new_watermark;
            }
            let _ = l.save();
            l.lifetime_earned_uegoc
        })
        .await
        .unwrap_or(ledger.lifetime_earned_uegoc)
    } else {
        ledger.lifetime_earned_uegoc
    };

    let pending         = daily_storage / 24;
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

    // 1. Gossip the event robustly across the P2P mesh
    let msg = crate::p2p::P2PMessage::PocEventBroadcast {
        address:   address.clone(),
        quality:   quality.clone(),
        peers,
        timestamp,
        signature: signature_hex.clone(),
    };
    if let Ok(data) = serde_json::to_vec(&msg) {
        crate::p2p::publish_gossip("ego-poc-v1", data).await;
    }

    // 2. Dispatch HTTP fallback asynchronously across multiple oracle nodes
    if let Ok(body) = serde_json::to_value(&payload) {
        tokio::spawn(async move {
            crate::p2p::oracle_post_pub(&client, "/poc/event", &body).await;
        });
    }

    // Calculate expected reward natively (since we don't wait for synchronous HTTP response)
    let expected_reward = 11_111 + (peers as u64 * 1_500).min(33_333);

    Ok(PocEventResult {
        success:      true,
        message:      "PoC event gossiped to network".to_string(),
        reward_uegoc: expected_reward,
        drs_score:    None,
    })
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
    let score = crate::poc::get_peer_score(&address) as f64;
    Ok(PocScoreResult {
        drs_score: score, events_24h: 0, total_events: 0,
        last_event: None, is_validator: crate::ledger::get_validator_stake(&address) > 0,
        validator_rank: None,
    })
}
