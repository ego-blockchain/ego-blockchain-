//! Ego Blockchain — single source of truth for all supply and reward constants.
//!
//! Total supply breakdown (1,000,000,000 EGOC):
//! ┌─────────────────────────────┬───────────────┬──────┐
//! │ Allocation                  │ EGOC          │  %   │
//! ├─────────────────────────────┼───────────────┼──────┤
//! │ Block mining emission       │ 210,000,000   │  21% │
//! │ Node operation rewards pool │ 300,000,000   │  30% │
//! │ Staking rewards pool        │ 140,000,000   │  14% │
//! │ Ecosystem / grants (DAO)    │ 200,000,000   │  20% │
//! │ Foundation / team (4yr vest)│ 150,000,000   │  15% │
//! └─────────────────────────────┴───────────────┴──────┘
//!
//! Block emission math:
//!   INITIAL_BLOCK_REWARD × 2 × HALVING_INTERVAL
//!   = 50 EGOC × 2 × 2,100,000 = 210,000,000 EGOC  ✓
//!
//! Era duration:
//!   126,000,000 blocks × SLOT_INTERVAL_MS (100ms) ÷ 86,400,000 = ~145 days (~5 months)

// ── Precision ─────────────────────────────────────────────────────────────────

pub const UEGOC_PER_EGOC: u64 = 1_000_000;

// ── Supply allocation ─────────────────────────────────────────────────────────

pub const TOTAL_SUPPLY_EGOC:  u64 = 1_000_000_000;
pub const TOTAL_SUPPLY_UEGOC: u64 = TOTAL_SUPPLY_EGOC * UEGOC_PER_EGOC;

/// Max EGOC ever mintable via block rewards (geometric series sum).
pub const BLOCK_EMISSION_EGOC:  u64 = 210_000_000;
pub const BLOCK_EMISSION_UEGOC: u64 = BLOCK_EMISSION_EGOC * UEGOC_PER_EGOC;

/// Funds daily storage / coverage / consensus / retrieval payouts.
pub const NODE_POOL_EGOC:  u64 = 300_000_000;
pub const NODE_POOL_UEGOC: u64 = NODE_POOL_EGOC * UEGOC_PER_EGOC;

/// Funds staking APR interest payments.
pub const STAKING_POOL_EGOC:  u64 = 140_000_000;
pub const STAKING_POOL_UEGOC: u64 = STAKING_POOL_EGOC * UEGOC_PER_EGOC;

/// DAO-controlled grants / ecosystem fund (not circulating at launch).
pub const ECOSYSTEM_EGOC: u64 = 200_000_000;

/// Foundation / team allocation, 4-year linear vesting (not circulating at launch).
pub const FOUNDATION_EGOC: u64 = 150_000_000;

// ── Block reward schedule ─────────────────────────────────────────────────────

/// Initial block reward in uEGOC.
/// Scaled for 100 ms blocks: 50 EGOC × (100ms / 6000ms) ≈ 0.8333 EGOC/block
/// Total emission check: 833_334 × 2 × 126_000_000 = 210,000,168,000,000 uEGOC ≈ 210M EGOC ✓
pub const INITIAL_BLOCK_REWARD_UEGOC: u64 = 833_334;

/// Number of blocks between halvings.
/// At SLOT_INTERVAL_MS = 100 ms/block → 10 blocks/s → 864,000 blocks/day
/// → era = 126,000,000 blocks ≈ 145.8 days  (same calendar duration as before)
pub const HALVING_INTERVAL: u64 = 126_000_000;

/// Micro-slot interval in milliseconds — one block every 100 ms = 10 blocks/second.
pub const SLOT_INTERVAL_MS: u64 = 100;

/// Kept for staking/tokenomics math that thinks in "seconds per block".
/// At 100 ms/block this equals 0.1.
pub const TARGET_BLOCK_SECS: f64 = 0.1;

/// Reward for block `height` (in uEGOC). Halves every HALVING_INTERVAL blocks.
pub fn block_reward_at(height: u64) -> u64 {
    let era = (height / HALVING_INTERVAL).min(63);
    INITIAL_BLOCK_REWARD_UEGOC >> era
}

// ── Daily node reward rates (drawn from NODE_POOL) ────────────────────────────

/// Storage reward: 0.5 EGOC per GB per day.
pub const STORAGE_RATE_UEGOC_PER_GB_DAY: f64 = 500_000.0;

/// Validator / consensus reward per active node per day.
pub const CONSENSUS_DAILY_UEGOC: u64 = 10 * UEGOC_PER_EGOC; // 10 EGOC

/// Proof-of-Coverage beacon reward per online node per day.
pub const COVERAGE_DAILY_UEGOC: u64 = 8 * UEGOC_PER_EGOC; // 8 EGOC

/// Retrieval fee reward per node per day.
pub const RETRIEVAL_DAILY_UEGOC: u64 = 2 * UEGOC_PER_EGOC; // 2 EGOC

// ── Staking ───────────────────────────────────────────────────────────────────

/// Annual percentage rate for staking, in basis points (12.5% = 1250 bps).
pub const STAKING_APR_BPS: u64 = 1_250;

/// Minimum stake to qualify for free smart-contract execution (EGO-5).
pub const MIN_STAKE_FREE_TX_UEGOC: u64 = UEGOC_PER_EGOC; // 1 EGOC

/// Minimum stake to participate in the staking rewards program.
pub const MIN_STAKE_PROGRAM_UEGOC: u64 = 1_000 * UEGOC_PER_EGOC; // 1,000 EGOC

// ── Pool exhaustion helpers ────────────────────────────────────────────────────

/// How much of the node rewards pool has been paid out so far.
/// Scans confirmed reward transactions from the network chain.
pub fn node_pool_paid_uegoc(chain: &crate::ledger::SharedChain) -> u64 {
    chain.transactions.iter()
        .filter(|t| t.from.starts_with("egot1rewards") && t.status == "Confirmed")
        .map(|t| t.amount)
        .sum()
}

/// Remaining node rewards pool (uEGOC). Returns 0 when pool is exhausted.
pub fn node_pool_remaining_uegoc(chain: &crate::ledger::SharedChain) -> u64 {
    NODE_POOL_UEGOC.saturating_sub(node_pool_paid_uegoc(chain))
}

/// Scale factor (0.0–1.0) to apply to daily node rewards.
/// Full rate until pool drops below 20%; then linearly tapers to 0.
pub fn node_reward_scale(chain: &crate::ledger::SharedChain) -> f64 {
    let remaining = node_pool_remaining_uegoc(chain);
    if remaining == 0 { return 0.0; }
    let pct = remaining as f64 / NODE_POOL_UEGOC as f64;
    if pct >= 0.20 { 1.0 } else { pct / 0.20 }
}

/// How much of the staking rewards pool has been paid out so far.
pub fn staking_pool_paid_uegoc(chain: &crate::ledger::SharedChain) -> u64 {
    chain.transactions.iter()
        .filter(|t| t.from.starts_with("egot1staking") && t.status == "Confirmed")
        .map(|t| t.amount)
        .sum()
}

/// Remaining staking rewards pool (uEGOC).
pub fn staking_pool_remaining_uegoc(chain: &crate::ledger::SharedChain) -> u64 {
    STAKING_POOL_UEGOC.saturating_sub(staking_pool_paid_uegoc(chain))
}

// ── Foundation vesting ────────────────────────────────────────────────────────

/// Foundation tokens that have vested by `now` (unix seconds).
/// Linear vesting: 0 at genesis (2026-03-14), 100% after 4 years.
pub fn foundation_vested_egoc(now_secs: i64) -> u64 {
    const GENESIS_TS: i64   = 1_741_910_400; // 2026-03-14 00:00 UTC
    const VEST_SECS:  i64   = 4 * 365 * 86_400;
    let elapsed = (now_secs - GENESIS_TS).max(0);
    let vested_frac = (elapsed as f64 / VEST_SECS as f64).min(1.0);
    (FOUNDATION_EGOC as f64 * vested_frac) as u64
}

// ── Dynamic Fee Pricing (USD-pegged, 100% burned — deflationary) ───────────────
//
// Fee targets are expressed in USD cents so they stay affordable regardless of
// EGOC price.  The runtime converts to uEGOC using the live EGOC/USD rate fetched
// from the oracle.  Hard floors and ceilings prevent extreme edge cases.
//
// Target (non-staker):
//   Transfer  : $0.003  (0.3¢)
//   Call      : $0.004  (0.4¢)
//   Deploy    : $0.006  (0.6¢)
//   Storage   : $0.001 per MB per month
//
// Staker: 90% discount on transfers/calls/deploys (pays ~0.03¢ — enough to deter
// spam but nearly free as a staking reward).
// Storage & deploy: completely free for stakers.

/// USD target for a standard transfer (~$0.30).
pub const TRANSFER_TARGET_USD: f64 = 0.30;
/// USD target for a contract call (~$0.40).
pub const CALL_TARGET_USD:     f64 = 0.40;
/// USD target for a contract deploy (~$0.60).
pub const DEPLOY_TARGET_USD:   f64 = 0.60;
/// USD rate for storage: $0.20 per GB per month = $0.0002 per MB per month.
pub const STORAGE_USD_PER_MB_MONTH: f64 = 0.0002;

/// Hard floor in uEGOC — never charge less than this (anti-dust).
pub const FEE_FLOOR_UEGOC: u64 = 10;
/// Hard ceiling in uEGOC — never charge more than 5 EGOC even if EGOC = $0.000001.
pub const FEE_CEILING_UEGOC: u64 = 5_000_000;
/// Minimum accepted fee (spam guard for mempool).
pub const MIN_TX_FEE_UEGOC: u64 = 10;

// Legacy constants kept for backward compatibility with callers that haven't
// been updated yet.  Will be removed once all call sites use dynamic pricing.
pub const STANDARD_TX_FEE_UEGOC: u64 = 10_000;
pub const DEPLOY_FEE_UEGOC:      u64 = 100_000;
pub const CALL_FEE_UEGOC:        u64 = 50_000;

/// Convert a USD target amount to uEGOC using the live EGOC price.
/// Always clamps to [FEE_FLOOR_UEGOC, FEE_CEILING_UEGOC].
pub fn usd_to_uegoc(target_usd: f64, egoc_price_usd: f64) -> u64 {
    let price = egoc_price_usd.max(1e-9); // prevent division by zero
    let fee_egoc  = target_usd / price;
    let fee_uegoc = (fee_egoc * 1_000_000.0).round() as u64;
    fee_uegoc.clamp(FEE_FLOOR_UEGOC, FEE_CEILING_UEGOC)
}

/// Returns the fee in uEGOC for the given tx type, priced dynamically in USD.
/// Stakers pay 10% of the base fee (minimum FEE_FLOOR_UEGOC).
pub fn fee_for_tx_with_staking(tx_type: &str, is_staker: bool) -> u64 {
    let egoc_price = crate::p2p::get_egoc_price_usd();
    let target_usd = match tx_type {
        "deploy" => DEPLOY_TARGET_USD,
        "call"   => CALL_TARGET_USD,
        _        => TRANSFER_TARGET_USD,
    };
    let base = usd_to_uegoc(target_usd, egoc_price);
    if is_staker { (base / 10).max(FEE_FLOOR_UEGOC) } else { base }
}

/// Legacy wrapper — returns full (non-staker) fee.  Prefer fee_for_tx_with_staking.
pub fn fee_for_tx_type(tx_type: &str) -> u64 {
    fee_for_tx_with_staking(tx_type, false)
}

/// Storage cost in uEGOC for `size_mb` MB stored for `months` months.
/// Free for stakers, USD-pegged for everyone else.
pub fn storage_cost_with_staking(size_mb: f64, months: u32, is_staker: bool) -> u64 {
    if is_staker { return 0; }
    let egoc_price = crate::p2p::get_egoc_price_usd();
    // Minimum storage charge = $0.20 (same as transfer floor) regardless of file size
    let target_usd = (STORAGE_USD_PER_MB_MONTH * size_mb * months as f64).max(0.20);
    usd_to_uegoc(target_usd, egoc_price)
}

/// Smart contract deploy fee: free for stakers, dynamically priced otherwise.
pub fn deploy_fee_with_staking(is_staker: bool) -> u64 {
    if is_staker { 0 } else { fee_for_tx_with_staking("deploy", false) }
}

// ── EGUSD Stablecoin ──────────────────────────────────────────────────────────
//
// EGUSD is pegged 1:1 to USDT.
// Minting: only when USDT is deposited into the Ego Bridge contract.
// Burning: EGUSD is burned when USDT is withdrawn from the bridge.
// Invariant: circulating_EGUSD ≤ USDT_locked_in_bridge at all times.

pub const EGUSD_USDT_RATIO: f64 = 1.0; // 1 EGUSD = 1 USDT, always

// ── Slashing Rules ────────────────────────────────────────────────────────────
//
// Validators that misbehave (double-sign, invalid block, >15 min downtime)
// receive strikes. Strikes reset after 30 clean days.
//
//   Strike 1 → Warning: logged on-chain, no stake impact.
//   Strike 2 → Ejected: removed from validator set, stake locked 7 days.
//   Strike 3 → Permanent ban: ejected + 10% of stake burned.

/// Days after which strike history clears (clean record resets counter).
pub const SLASH_RESET_DAYS: u64 = 30;

/// Stake lock duration (days) after Strike 2.
pub const SLASH_LOCK_DAYS: u64 = 7;

/// Percentage of stake burned on Strike 3, in basis points (1 000 = 10%).
pub const SLASH_BURN_BPS: u64 = 1_000;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SlashOutcome {
    Warning,
    EjectAndLock { lock_days: u64 },
    PermanentBan { burn_bps: u64 },
}

/// Compute slash outcome from the validator's current strike count (0 = clean).
pub fn slash_outcome(strikes: u32) -> SlashOutcome {
    match strikes {
        0 => SlashOutcome::Warning,
        1 => SlashOutcome::EjectAndLock { lock_days: SLASH_LOCK_DAYS },
        _ => SlashOutcome::PermanentBan { burn_bps: SLASH_BURN_BPS },
    }
}

// ── Genesis Allocation ────────────────────────────────────────────────────────
// TODO: to be defined before mainnet launch.
