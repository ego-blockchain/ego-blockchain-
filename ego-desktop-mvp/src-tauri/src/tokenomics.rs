pub const UEGOC_PER_EGOC: u64 = 1_000_000;

pub const TOTAL_SUPPLY_EGOC:  u64 = 1_000_000_000;
pub const TOTAL_SUPPLY_UEGOC: u64 = TOTAL_SUPPLY_EGOC * UEGOC_PER_EGOC;

pub const BLOCK_EMISSION_EGOC:  u64 = 210_000_000;
pub const BLOCK_EMISSION_UEGOC: u64 = BLOCK_EMISSION_EGOC * UEGOC_PER_EGOC;

pub const NODE_POOL_EGOC:  u64 = 300_000_000;
pub const NODE_POOL_UEGOC: u64 = NODE_POOL_EGOC * UEGOC_PER_EGOC;

pub const STAKING_POOL_EGOC:  u64 = 140_000_000;
pub const STAKING_POOL_UEGOC: u64 = STAKING_POOL_EGOC * UEGOC_PER_EGOC;

pub const ECOSYSTEM_EGOC: u64 = 200_000_000;

pub const FOUNDATION_EGOC: u64 = 150_000_000;

// Block reward halving — designed for a 120-year emission schedule.
//
// At 0.1 s/block there are 315,360,000 blocks/year.
// We want ~30 halvings over 120 years → one halving every ~4 years.
// 4 years × 315,360,000 blocks/year ≈ 1,261,440,000 blocks per era.
//
// Initial reward is sized so that era-0 emits exactly half the block pool
// (the geometric series 1 + 1/2 + 1/4 + … sums to 2, so era-0 = pool/2):
//   era-0 total = 210,000,000 / 2 = 105,000,000 EGOC
//   per-block   = 105,000,000 EGOC / 1,261,440,000 blocks ≈ 0.0832 EGOC = 83,220 uEGOC
pub const INITIAL_BLOCK_REWARD_UEGOC: u64 = 83_220;

// 4-year halving — one era every ~1.26 billion blocks.
pub const HALVING_INTERVAL: u64 = 1_261_440_000;

pub const SLOT_INTERVAL_MS: u64 = 100;

pub const TARGET_BLOCK_SECS: f64 = 0.1;

pub fn block_reward_at(height: u64) -> u64 {
    // Cap at era 63 so the shift never overflows; reward is negligible by then.
    let era = (height / HALVING_INTERVAL).min(63);
    INITIAL_BLOCK_REWARD_UEGOC >> era
}

// ── Node reward targets (USD) ─────────────────────────────────────────────────
//
// Node rewards are defined in USD and converted to EGOC at the live price.
// This keeps real income stable for operators whether EGOC is $0.001 or $1,000,
// while naturally adjusting how many EGOC are emitted from the node pool.
//
// USD targets are competitive with market rates but not so high that a rising
// EGOC price depletes the node pool quickly:
//   Storage : $0.002 / GB / day  → $0.06/GB/month  (below Filecoin ~$0.30)
//   Consensus: $0.20  / node / day → ~$73/year per validator
//   Coverage : $0.15  / node / day → ~$55/year per coverage node
//   Retrieval: $0.003 / GB served  → incentivises fast serving
//
// The EGOC reward is always clamped: at least FEE_FLOOR_UEGOC (never zero),
// at most NODE_REWARD_CEILING_UEGOC (prevents pool drain if price crashes).
pub const STORAGE_REWARD_USD_PER_GB_DAY:  f64 = 0.002;
pub const CONSENSUS_REWARD_USD_PER_DAY:   f64 = 0.20;
pub const COVERAGE_REWARD_USD_PER_DAY:    f64 = 0.15;
pub const RETRIEVAL_REWARD_USD_PER_GB:    f64 = 0.003;

// Hard ceiling per reward event — prevents pool exhaustion if EGOC price collapses
// to near zero (e.g. at $0.000001 the USD target would require trillions of EGOC).
pub const NODE_REWARD_CEILING_UEGOC: u64 = 50 * UEGOC_PER_EGOC; // 50 EGOC per event max

/// Convert a USD reward target to uEGOC at the live price,
/// clamped to [FEE_FLOOR_UEGOC, NODE_REWARD_CEILING_UEGOC].
pub fn reward_usd_to_uegoc(target_usd: f64) -> u64 {
    let price = crate::p2p::get_egoc_price_usd().max(1e-9);
    let uegoc = (target_usd / price * UEGOC_PER_EGOC as f64).round() as u64;
    uegoc.clamp(FEE_FLOOR_UEGOC, NODE_REWARD_CEILING_UEGOC)
}

/// Storage hosting reward for `gb` GB of peer data stored for one day.
pub fn storage_reward_uegoc(gb: f64) -> u64 {
    reward_usd_to_uegoc(STORAGE_REWARD_USD_PER_GB_DAY * gb)
}

/// Daily consensus-node reward.
pub fn consensus_daily_uegoc() -> u64 {
    reward_usd_to_uegoc(CONSENSUS_REWARD_USD_PER_DAY)
}

/// Daily coverage-node reward.
pub fn coverage_daily_uegoc() -> u64 {
    reward_usd_to_uegoc(COVERAGE_REWARD_USD_PER_DAY)
}

/// Retrieval reward for serving `gb` GB to a requester.
pub fn retrieval_reward_uegoc(gb: f64) -> u64 {
    reward_usd_to_uegoc(RETRIEVAL_REWARD_USD_PER_GB * gb)
}

pub const STAKING_APR_BPS: u64 = 1_250;

pub const MIN_STAKE_FREE_TX_UEGOC: u64 = UEGOC_PER_EGOC;

pub const MIN_STAKE_PROGRAM_UEGOC: u64 = 1_000 * UEGOC_PER_EGOC;

pub fn node_pool_paid_uegoc(chain: &crate::ledger::SharedChain) -> u64 {
    chain.transactions.iter()
        .filter(|t| t.from.starts_with("egot1rewards") && t.status == "Confirmed")
        .map(|t| t.amount)
        .sum()
}

pub fn node_pool_remaining_uegoc(chain: &crate::ledger::SharedChain) -> u64 {
    NODE_POOL_UEGOC.saturating_sub(node_pool_paid_uegoc(chain))
}

pub fn node_reward_scale(chain: &crate::ledger::SharedChain) -> f64 {
    let remaining = node_pool_remaining_uegoc(chain);
    if remaining == 0 { return 0.0; }
    let pct = remaining as f64 / NODE_POOL_UEGOC as f64;
    if pct >= 0.20 { 1.0 } else { pct / 0.20 }
}

pub fn staking_pool_paid_uegoc(chain: &crate::ledger::SharedChain) -> u64 {
    chain.transactions.iter()
        .filter(|t| t.from.starts_with("egot1staking") && t.status == "Confirmed")
        .map(|t| t.amount)
        .sum()
}

pub fn staking_pool_remaining_uegoc(chain: &crate::ledger::SharedChain) -> u64 {
    STAKING_POOL_UEGOC.saturating_sub(staking_pool_paid_uegoc(chain))
}

pub fn foundation_vested_egoc(now_secs: i64) -> u64 {
    const GENESIS_TS: i64   = 1_741_910_400;
    const VEST_SECS:  i64   = 4 * 365 * 86_400;
    let elapsed = (now_secs - GENESIS_TS).max(0);
    let vested_frac = (elapsed as f64 / VEST_SECS as f64).min(1.0);
    (FOUNDATION_EGOC as f64 * vested_frac) as u64
}

// Storage pricing — cheapest in the market:
//   Google Drive ~$0.020/GB/mo, iCloud ~$0.015/GB/mo,
//   AWS S3 ~$0.023/GB/mo, Azure ~$0.018/GB/mo,
//   Backblaze B2 ~$0.006/GB/mo, Wasabi ~$0.0069/GB/mo
//   Ego target: $0.005/GB/mo = $0.000005/MB/mo  (beats all of them)
pub const STORAGE_USD_PER_MB_MONTH: f64 = 0.000_005;

// ── Transaction fee model ─────────────────────────────────────────────────────
//
// Base fees are fixed in EGOC so they always look small to the user.
// When EGOC price rises the USD cost could exceed $0.80, so we cap it:
//   fee = min(base_uegoc, USD_MAX / price)
//
// Examples at various prices (transfer base = 0.5 EGOC):
//   $0.001 /EGOC →  0.5 EGOC = $0.0005  (cheap, fixed EGOC)
//   $1.00  /EGOC →  0.5 EGOC = $0.50    (normal range)
//   $2.00  /EGOC →  0.4 EGOC = $0.80    (USD cap kicks in)
//   $10.00 /EGOC →  0.08 EGOC = $0.80   (USD cap, fewer EGOC)

pub const TRANSFER_FEE_UEGOC: u64 = 500_000;   // 0.5 EGOC
pub const CALL_FEE_BASE_UEGOC: u64 = 600_000;  // 0.6 EGOC
pub const DEPLOY_FEE_BASE_UEGOC: u64 = 800_000; // 0.8 EGOC

pub const FEE_USD_MAX: f64 = 0.80; // never charge more than $0.80 when price is high

pub const FEE_FLOOR_UEGOC: u64 = 10;
pub const FEE_CEILING_UEGOC: u64 = 5_000_000; // kept for legacy references
pub const MIN_TX_FEE_UEGOC: u64 = 10;
pub const STANDARD_TX_FEE_UEGOC: u64 = 10_000;
pub const DEPLOY_FEE_UEGOC:      u64 = 100_000;
pub const CALL_FEE_UEGOC:        u64 = 50_000;

pub fn usd_to_uegoc(target_usd: f64, egoc_price_usd: f64) -> u64 {
    let price = egoc_price_usd.max(1e-9);
    let fee_uegoc = (target_usd / price * 1_000_000.0).round() as u64;
    fee_uegoc.max(FEE_FLOOR_UEGOC)
}

pub fn fee_for_tx_with_staking(tx_type: &str, is_staker: bool) -> u64 {
    let price = crate::p2p::get_egoc_price_usd().max(1e-9);
    let base_uegoc = match tx_type {
        "deploy" => DEPLOY_FEE_BASE_UEGOC,
        "call"   => CALL_FEE_BASE_UEGOC,
        _        => TRANSFER_FEE_UEGOC,
    };
    // Cap at $0.80 USD when EGOC price is high
    let usd_cap_uegoc = (FEE_USD_MAX / price * 1_000_000.0) as u64;
    let base = base_uegoc.min(usd_cap_uegoc).max(FEE_FLOOR_UEGOC);
    if is_staker { (base / 10).max(FEE_FLOOR_UEGOC) } else { base }
}

pub fn fee_for_tx_type(tx_type: &str) -> u64 {
    fee_for_tx_with_staking(tx_type, false)
}

pub fn storage_cost_with_staking(size_mb: f64, months: u32, is_staker: bool) -> u64 {
    if is_staker { return 0; }
    let egoc_price = crate::p2p::get_egoc_price_usd();

    let target_usd = if months == 0 {
        // Permanent storage: equivalent to 10 years at 50% discount
        // = size_mb × rate × 120 months × 0.50
        STORAGE_USD_PER_MB_MONTH * size_mb * 120.0 * 0.50
    } else {
        STORAGE_USD_PER_MB_MONTH * size_mb * months as f64
    };
    // No USD floor — let FEE_FLOOR_UEGOC handle dust prevention
    usd_to_uegoc(target_usd.max(0.0), egoc_price)
}

pub fn deploy_fee_with_staking(is_staker: bool) -> u64 {
    if is_staker { 0 } else { fee_for_tx_with_staking("deploy", false) }
}

pub const EGUSD_USDT_RATIO: f64 = 1.0;

pub const SLASH_RESET_DAYS: u64 = 30;

pub const SLASH_LOCK_DAYS: u64 = 7;

pub const SLASH_BURN_BPS: u64 = 1_000;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SlashOutcome {
    Warning,
    EjectAndLock { lock_days: u64 },
    PermanentBan { burn_bps: u64 },
}

pub fn slash_outcome(strikes: u32) -> SlashOutcome {
    match strikes {
        0 => SlashOutcome::Warning,
        1 => SlashOutcome::EjectAndLock { lock_days: SLASH_LOCK_DAYS },
        _ => SlashOutcome::PermanentBan { burn_bps: SLASH_BURN_BPS },
    }
}
