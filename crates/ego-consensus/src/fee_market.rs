//! Ego Blockchain Fee Model
//!
//! ## Design Philosophy: Feeless UX
//!
//! Ego is feeless for end users. This is a core design goal, not an afterthought.
//! Validators earn from block emission rewards (EGO-1 §9 / DRS scoring), NOT from
//! transaction fees.
//!
//! ## Fee Rules
//!
//! | Transaction type      | Staker (≥1 EGOC staked) | Non-staker        |
//! |-----------------------|-------------------------|-------------------|
//! | Wallet → wallet       | FREE                    | FREE              |
//! | Smart contract call   | FREE (up to RU allowance)| Proof-of-Burn (PoB) |
//! | Contract deploy       | FREE (up to RU allowance)| Proof-of-Burn (PoB) |
//!
//! ## Spam Prevention
//!
//! Even though transfers are free, every transaction consumes RU (Resource Units).
//! Each account has a per-block RU allowance based on their staked balance.
//! Accounts with no staking must burn a tiny amount of EGOC (Proof-of-Burn Credits)
//! to unlock RU capacity.
//!
//! ## Proof-of-Burn Credits (PoBC)
//!
//! A non-staker can burn EGOC to obtain PoB Credits:
//!   1 uEGOC burned = 10,000 RU capacity
//! This is a one-time burn, not a per-transaction fee. Credits persist until used.
//!
//! ## RU Allowance for Stakers
//!
//! Stakers receive a per-block RU allowance proportional to their stake:
//!   allowance = BASE_STAKER_RU + (staked_uegoc / 1_000_000) * RU_PER_EGOC_STAKED
//! This ensures stakers can always transact freely while preventing abuse.

use serde::{Deserialize, Serialize};

// ── RU Constants ──────────────────────────────────────────────────────────────

pub const MAX_RU_PER_BLOCK:    u64 = 10_000_000;
pub const TARGET_RU_PER_BLOCK: u64 = 5_000_000;

/// Base RU allowance per block for any staker (even 1 uEGOC staked).
pub const BASE_STAKER_RU:      u64 = 500_000;   // 500k RU free per block

/// Extra RU per 1 EGOC staked, per block.
pub const RU_PER_EGOC_STAKED:  u64 = 10_000;    // 10k extra RU per EGOC staked

/// RU gained per 1 uEGOC burned (Proof-of-Burn).
pub const RU_PER_UEGOC_BURNED: u64 = 10_000;    // 10k RU per uEGOC burned

/// Minimum stake (uEGOC) to qualify as a staker and get free transactions.
pub const MIN_STAKE_FOR_FREE_TX: u64 = 1_000_000; // 1 EGOC

// ── Transaction Classification ────────────────────────────────────────────────

/// Whether a transaction is a simple transfer or a contract interaction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TxKind {
    /// Wallet-to-wallet EGOC transfer. Always free.
    Transfer,
    /// Smart contract call or deployment. Free for stakers; PoB for others.
    ContractCall,
    /// Contract deployment. Free for stakers; PoB for others.
    ContractDeploy,
}

/// Fee decision for a transaction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FeeDecision {
    /// Transaction is free — caller is a staker with sufficient RU allowance.
    Free,
    /// Transaction is free — it's a wallet-to-wallet transfer.
    FreeTransfer,
    /// Transaction requires Proof-of-Burn credits. `pob_required` is in uEGOC.
    RequiresPoB { ru_needed: u64, pob_credits_required: u64 },
    /// Transaction rejected — non-staker has no PoB credits and hasn't burned enough.
    Rejected { reason: String },
}

/// Per-account fee state tracked by the mempool.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountFeeState {
    /// How much EGOC (in uEGOC) this account has staked.
    pub staked_uegoc: u64,
    /// Accumulated Proof-of-Burn RU credits (from burning EGOC).
    pub pob_ru_credits: u64,
    /// RU consumed this block (reset each block).
    pub ru_used_this_block: u64,
}

impl AccountFeeState {
    pub fn new(staked_uegoc: u64) -> Self {
        Self { staked_uegoc, pob_ru_credits: 0, ru_used_this_block: 0 }
    }

    /// Whether this account qualifies as a staker (≥1 EGOC staked).
    pub fn is_staker(&self) -> bool {
        self.staked_uegoc >= MIN_STAKE_FOR_FREE_TX
    }

    /// Per-block free RU allowance for this account.
    pub fn free_ru_allowance(&self) -> u64 {
        if !self.is_staker() { return 0; }
        let egoc = self.staked_uegoc / 1_000_000; // convert uEGOC → EGOC
        BASE_STAKER_RU + egoc.saturating_mul(RU_PER_EGOC_STAKED)
    }

    /// Remaining free RU this block.
    pub fn remaining_free_ru(&self) -> u64 {
        self.free_ru_allowance().saturating_sub(self.ru_used_this_block)
    }

    /// Burn uEGOC to gain RU credits.
    pub fn burn_for_credits(&mut self, uegoc_to_burn: u64) -> u64 {
        let credits = uegoc_to_burn.saturating_mul(RU_PER_UEGOC_BURNED);
        self.pob_ru_credits = self.pob_ru_credits.saturating_add(credits);
        credits
    }

    /// Reset per-block counters (called at block start).
    pub fn reset_block(&mut self) {
        self.ru_used_this_block = 0;
    }
}

// ── Fee Engine ────────────────────────────────────────────────────────────────

/// The Ego fee engine. Decides whether a transaction is free, needs PoB, or is rejected.
pub struct FeeEngine;

impl FeeEngine {
    /// Evaluate a transaction and return the fee decision.
    pub fn evaluate(
        account: &AccountFeeState,
        kind: TxKind,
        ru_needed: u64,
    ) -> FeeDecision {
        // Rule 1: wallet-to-wallet transfers are ALWAYS free
        if kind == TxKind::Transfer {
            return FeeDecision::FreeTransfer;
        }

        // Rule 2: stakers with remaining allowance pay nothing
        if account.is_staker() {
            if account.remaining_free_ru() >= ru_needed {
                return FeeDecision::Free;
            }
            // Staker but over their block allowance — needs PoB for the excess
            let excess = ru_needed.saturating_sub(account.remaining_free_ru());
            if account.pob_ru_credits >= excess {
                return FeeDecision::Free; // covered by their burn credits
            }
            let shortfall = excess.saturating_sub(account.pob_ru_credits);
            // How much uEGOC to burn to cover shortfall?
            let pob_required = shortfall.div_ceil(RU_PER_UEGOC_BURNED);
            return FeeDecision::RequiresPoB { ru_needed, pob_credits_required: pob_required };
        }

        // Rule 3: non-stakers need PoB credits for contract calls
        if account.pob_ru_credits >= ru_needed {
            return FeeDecision::Free; // they have pre-bought credits
        }
        let shortfall = ru_needed.saturating_sub(account.pob_ru_credits);
        let pob_required = shortfall.div_ceil(RU_PER_UEGOC_BURNED);
        FeeDecision::RequiresPoB { ru_needed, pob_credits_required: pob_required }
    }

    /// Apply a fee decision — consume RU from the account.
    pub fn apply(account: &mut AccountFeeState, kind: &TxKind, ru_used: u64) {
        if *kind == TxKind::Transfer {
            // Free transfers don't consume RU allowance
            return;
        }
        let free_remaining = account.remaining_free_ru();
        if ru_used <= free_remaining {
            account.ru_used_this_block += ru_used;
        } else {
            account.ru_used_this_block += free_remaining;
            let from_credits = ru_used.saturating_sub(free_remaining);
            account.pob_ru_credits = account.pob_ru_credits.saturating_sub(from_credits);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_always_free() {
        let account = AccountFeeState::new(0); // no stake, no credits
        let decision = FeeEngine::evaluate(&account, TxKind::Transfer, 50_000);
        assert_eq!(decision, FeeDecision::FreeTransfer);
    }

    #[test]
    fn staker_contract_call_free() {
        let account = AccountFeeState::new(5_000_000); // 5 EGOC staked
        let allowance = account.free_ru_allowance();
        assert!(allowance >= 500_000);
        let decision = FeeEngine::evaluate(&account, TxKind::ContractCall, 100_000);
        assert_eq!(decision, FeeDecision::Free);
    }

    #[test]
    fn non_staker_contract_call_needs_pob() {
        let account = AccountFeeState::new(0); // no stake
        let decision = FeeEngine::evaluate(&account, TxKind::ContractCall, 50_000);
        match decision {
            FeeDecision::RequiresPoB { ru_needed, pob_credits_required } => {
                assert_eq!(ru_needed, 50_000);
                assert!(pob_credits_required > 0);
            }
            _ => panic!("expected RequiresPoB"),
        }
    }

    #[test]
    fn pob_credits_cover_contract_call() {
        let mut account = AccountFeeState::new(0);
        account.burn_for_credits(10); // burn 10 uEGOC → 100,000 RU credits
        let decision = FeeEngine::evaluate(&account, TxKind::ContractCall, 50_000);
        assert_eq!(decision, FeeDecision::Free);
    }

    #[test]
    fn staker_ru_allowance_scales_with_stake() {
        let small = AccountFeeState::new(1_000_000);   // 1 EGOC
        let large = AccountFeeState::new(100_000_000); // 100 EGOC
        assert!(large.free_ru_allowance() > small.free_ru_allowance());
    }
}
