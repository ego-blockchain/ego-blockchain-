use serde::{Deserialize, Serialize};

pub const MAX_RU_PER_BLOCK:    u64 = 10_000_000;
pub const TARGET_RU_PER_BLOCK: u64 = 5_000_000;

pub const BASE_STAKER_RU:      u64 = 500_000;

pub const RU_PER_EGOC_STAKED:  u64 = 10_000;

pub const RU_PER_UEGOC_BURNED: u64 = 10_000;

pub const MIN_STAKE_FOR_FREE_TX: u64 = 1_000_000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TxKind {

    Transfer,

    ContractCall,

    ContractDeploy,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FeeDecision {

    Free,

    FreeTransfer,

    RequiresPoB { ru_needed: u64, pob_credits_required: u64 },

    Rejected { reason: String },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountFeeState {

    pub staked_uegoc: u64,

    pub pob_ru_credits: u64,

    pub ru_used_this_block: u64,
}

impl AccountFeeState {
    pub fn new(staked_uegoc: u64) -> Self {
        Self { staked_uegoc, pob_ru_credits: 0, ru_used_this_block: 0 }
    }

    pub fn is_staker(&self) -> bool {
        self.staked_uegoc >= MIN_STAKE_FOR_FREE_TX
    }

    pub fn free_ru_allowance(&self) -> u64 {
        if !self.is_staker() { return 0; }
        let egoc = self.staked_uegoc / 1_000_000;
        BASE_STAKER_RU + egoc.saturating_mul(RU_PER_EGOC_STAKED)
    }

    pub fn remaining_free_ru(&self) -> u64 {
        self.free_ru_allowance().saturating_sub(self.ru_used_this_block)
    }

    pub fn burn_for_credits(&mut self, uegoc_to_burn: u64) -> u64 {
        let credits = uegoc_to_burn.saturating_mul(RU_PER_UEGOC_BURNED);
        self.pob_ru_credits = self.pob_ru_credits.saturating_add(credits);
        credits
    }

    pub fn reset_block(&mut self) {
        self.ru_used_this_block = 0;
    }
}

pub struct FeeEngine;

impl FeeEngine {

    pub fn evaluate(
        account: &AccountFeeState,
        kind: TxKind,
        ru_needed: u64,
    ) -> FeeDecision {

        if kind == TxKind::Transfer {
            return FeeDecision::FreeTransfer;
        }

        if account.is_staker() {
            if account.remaining_free_ru() >= ru_needed {
                return FeeDecision::Free;
            }

            let excess = ru_needed.saturating_sub(account.remaining_free_ru());
            if account.pob_ru_credits >= excess {
                return FeeDecision::Free;
            }
            let shortfall = excess.saturating_sub(account.pob_ru_credits);

            let pob_required = shortfall.div_ceil(RU_PER_UEGOC_BURNED);
            return FeeDecision::RequiresPoB { ru_needed, pob_credits_required: pob_required };
        }

        if account.pob_ru_credits >= ru_needed {
            return FeeDecision::Free;
        }
        let shortfall = ru_needed.saturating_sub(account.pob_ru_credits);
        let pob_required = shortfall.div_ceil(RU_PER_UEGOC_BURNED);
        FeeDecision::RequiresPoB { ru_needed, pob_credits_required: pob_required }
    }

    pub fn apply(account: &mut AccountFeeState, kind: &TxKind, ru_used: u64) {
        if *kind == TxKind::Transfer {

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
        let account = AccountFeeState::new(0);
        let decision = FeeEngine::evaluate(&account, TxKind::Transfer, 50_000);
        assert_eq!(decision, FeeDecision::FreeTransfer);
    }

    #[test]
    fn staker_contract_call_free() {
        let account = AccountFeeState::new(5_000_000);
        let allowance = account.free_ru_allowance();
        assert!(allowance >= 500_000);
        let decision = FeeEngine::evaluate(&account, TxKind::ContractCall, 100_000);
        assert_eq!(decision, FeeDecision::Free);
    }

    #[test]
    fn non_staker_contract_call_needs_pob() {
        let account = AccountFeeState::new(0);
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
        account.burn_for_credits(10);
        let decision = FeeEngine::evaluate(&account, TxKind::ContractCall, 50_000);
        assert_eq!(decision, FeeDecision::Free);
    }

    #[test]
    fn staker_ru_allowance_scales_with_stake() {
        let small = AccountFeeState::new(1_000_000);
        let large = AccountFeeState::new(100_000_000);
        assert!(large.free_ru_allowance() > small.free_ru_allowance());
    }
}
