use crate::app::{AppState, EarningsData, RewardBreakdown};
use crate::error::EgoDesktopError;
use crate::ledger::{load_chain, poc_signing_bytes, save_chain, Ledger, LedgerTx};
use serde::{Deserialize, Serialize};
use tauri::State;

/// Storage reward rate: 0.5 EGOC per GB per day = 500_000 uEGOC per GB per day.
const STORAGE_RATE_UEGOC_PER_GB_DAY: f64 = 500_000.0;

/// Fixed testnet reward buckets (per day, in uEGOC).
const CONSENSUS_DAILY: u64 = 10_000_000; //  10 EGOC/day — block validation
const RETRIEVAL_DAILY: u64 =  2_000_000; //   2 EGOC/day — retrieval fees
const COVERAGE_DAILY:  u64 =  8_000_000; //   8 EGOC/day — PoC beacon (only when online)

#[tauri::command]
pub async fn get_earnings_data(
    state: State<'_, AppState>,
) -> Result<EarningsData, EgoDesktopError> {
    let now = chrono::Utc::now().timestamp();
    let mut ledger = Ledger::load();

    // ── Reward rates ─────────────────────────────────────────────────────────

    let allocated_gb = ledger.storage_allocated_bytes as f64 / 1_000_000_000.0;
    let daily_storage = (allocated_gb * STORAGE_RATE_UEGOC_PER_GB_DAY) as u64;

    // Coverage reward is only earned while the node is online.
    let coverage_online = state
        .cache
        .lock()
        .unwrap()
        .coverage_status
        .as_ref()
        .map(|s| s.is_online)
        .unwrap_or(true); // default true when coverage hasn't been checked yet

    let daily_coverage = if coverage_online { COVERAGE_DAILY } else { 0 };

    let daily_total = daily_storage
        .saturating_add(CONSENSUS_DAILY)
        .saturating_add(daily_coverage)
        .saturating_add(RETRIEVAL_DAILY);

    // ── Credit elapsed earnings to the real ledger balance ───────────────────
    // This makes the balance actually grow while the app is open.
    // Time the app is closed does NOT earn (last_earnings_credit resets on
    // init_wallet → set_session_start).

    let last_credit = state.get_last_earnings_credit();
    if last_credit > 0 && now > last_credit {
        let elapsed_secs = (now - last_credit) as f64;
        let credit = (daily_total as f64 * elapsed_secs / 86_400.0) as u64;
        // Only write to chain when at least 1000 uEGOC (0.001 EGOC) has accrued
        // to avoid spamming the chain with sub-second micro-rewards.
        if credit >= 1_000 {
            let mut chain = load_chain();
            let reward_hash = format!(
                "0x{}",
                ego_core::hash_data(
                    format!("reward:{}:{}", ledger.address, now).as_bytes()
                ).to_hex()
            );
            if !chain.transactions.iter().any(|t| t.hash == reward_hash) {
                chain.transactions.push(LedgerTx {
                    hash:               reward_hash,
                    from:               "egot1rewards00000000000000000000000000000000000".into(),
                    to:                 ledger.address.clone(),
                    amount:             credit,
                    memo:               Some("Block & storage rewards".into()),
                    timestamp:          now,
                    signature:          "rewards".into(),
                    status:             "Confirmed".into(),
                    block_height:       None,
                    nonce:              0,
                    public_key_ed25519: String::new(), dilithium_pubkey: String::new(), dilithium_signature: String::new(),
                    ..LedgerTx::default()
                });
                let _ = save_chain(&chain);
            }
        }
    }
    state.set_last_earnings_credit(now);

    // ── Derived stats ─────────────────────────────────────────────────────────

    // total_earned = all rewards credited to this address from the rewards faucet
    let chain = load_chain();
    let total_earned: u64 = chain
        .transactions
        .iter()
        .filter(|tx| {
            tx.to.trim() == ledger.address.trim()
                && tx.from.starts_with("egot1rewards")
                && tx.status == "Confirmed"
        })
        .map(|tx| tx.amount)
        .sum();
    let pending      = daily_storage / 24; // ~1 hour of storage reward

    let session_started = state.get_session_started();

    let earnings = EarningsData {
        daily_rewards:  daily_total,
        epoch_rewards:  daily_total.saturating_mul(7), // 7-day epoch
        total_earned,
        drs_multiplier: 1.5,
        reward_breakdown: RewardBreakdown {
            storage_rewards:   daily_storage,
            consensus_rewards: CONSENSUS_DAILY,
            coverage_rewards:  daily_coverage,
            retrieval_rewards: RETRIEVAL_DAILY,
        },
        pending_rewards: pending,
        session_started,
        coverage_online,
    };

    state.update_earnings_data(earnings.clone());
    Ok(earnings)
}

// ── submit_poc_event ──────────────────────────────────────────────────────────
//
// Signs a Proof of Coverage event with the wallet's Ed25519 key and submits
// it to the relay. The relay verifies the signature, records the event, updates
// the DRS score for this address, and emits a coverage reward transaction.
//
// Called from the frontend EarningsPage whenever a PoC beacon fires.

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

    let url = format!("{}/poc/event", crate::p2p::RELAY_HTTP_API);
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
    let _ = state; // AppState not needed for HTTP fetch
    let url = format!("{}/poc/score/{}", crate::p2p::RELAY_HTTP_API, address);
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
