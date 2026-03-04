use crate::app::{AppState, EarningsData, RewardBreakdown};
use crate::error::EgoDesktopError;
use crate::ledger::{load_chain, save_chain, Ledger, LedgerTx};
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
                    hash:         reward_hash,
                    from:         "egot1rewards00000000000000000000000000000000000".into(),
                    to:           ledger.address.clone(),
                    amount:       credit,
                    memo:         Some("Block & storage rewards".into()),
                    timestamp:    now,
                    signature:    "rewards".into(),
                    status:       "Confirmed".into(),
                    block_height: None,
                    nonce:        0,
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
