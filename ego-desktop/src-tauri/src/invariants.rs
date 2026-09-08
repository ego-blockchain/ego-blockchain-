//! Properties that must hold after every block, checked while the block is
//! being written, and an alarm when one does not.
//!
//! # Why this exists rather than more tests
//!
//! A test finds a bug somebody thought to look for. An invariant finds a bug
//! nobody thought of, because it states what must be true of *every* block and
//! is checked against all of them, including the ones an attacker writes. The
//! shielded pool shipped with a hole that let a one-EGOC deposit be withdrawn
//! as ten thousand. It passed every test in the suite. It could not have
//! passed `OutstandingNotes`, which counts unspent notes at each denomination
//! and would have gone negative the first time a withdrawal claimed a size
//! nobody had deposited.
//!
//! # Why clamps are alarms
//!
//! Balance application ends in `.max(0)` and `saturating_sub`, so an
//! accounting error does not corrupt the database; it quietly disappears. That
//! is right for durability and wrong for diagnosis, because the evidence goes
//! with it. Every clamp that would have fired is reported here first.
//!
//! # What happens on a violation
//!
//! By default it is logged at error level and recorded, and the block is still
//! written. That is deliberate. A false positive that halts a validator is its
//! own outage, and a node that stops has no way to tell anyone why. With
//! `EGO_INVARIANTS=strict` the process panics instead, which is what tests and
//! testnet validators should run, because there the loud failure is the point.

use serde::{Deserialize, Serialize};
use std::sync::Mutex;

/// How many recent violations are kept for inspection.
const KEEP: usize = 64;

/// Coins created and destroyed by one block, accumulated as the block's
/// balance changes are computed.
///
/// Every branch that credits without debiting must record a mint, and every
/// branch that debits without crediting must record a burn. The sum of all
/// balance changes then has to equal mints minus burns, which is checked in
/// `check_block`. A new transaction type that moves value and forgets to say
/// so here fails that check on its first block, which is the point: the
/// accounting cannot be extended silently.
#[derive(Debug, Default, Clone)]
pub struct SupplyLedger {
    minted_uegoc: u128,
    burned_uegoc: u128,
}

impl SupplyLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Value credited to somebody with no source account debited.
    pub fn mint(&mut self, uegoc: u64) {
        self.minted_uegoc = self.minted_uegoc.saturating_add(uegoc as u128);
    }

    /// Value debited from somebody and credited to nobody.
    pub fn burn(&mut self, uegoc: u64) {
        self.burned_uegoc = self.burned_uegoc.saturating_add(uegoc as u128);
    }

    pub fn minted(&self) -> u128 {
        self.minted_uegoc
    }

    pub fn burned(&self) -> u128 {
        self.burned_uegoc
    }

    /// What the sum of every balance change in the block must come to.
    pub fn expected_net(&self) -> i128 {
        self.minted_uegoc as i128 - self.burned_uegoc as i128
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Violation {
    /// The block's balance changes do not add up to what it claims to have
    /// minted and burned. Any inflation bug in balance application lands here.
    SupplyDrift {
        height: u64,
        expected_net: i128,
        actual_net: i128,
        minted: u128,
        burned: u128,
    },
    /// An account was about to go below zero and was clamped. The clamp keeps
    /// the database consistent and destroys the evidence, so it is reported.
    NegativeBalance {
        height: u64,
        address: String,
        current: u64,
        delta: i128,
    },
    /// The shielded pool's own balance and the pool address's on-chain balance
    /// disagree. They move together on every deposit and every withdrawal, so
    /// a gap means one of the two paths ran without the other.
    ShieldedPoolMismatch {
        height: u64,
        recorded_uegoc: u64,
        on_chain_uegoc: u64,
    },
    /// More notes of some size have been withdrawn than were ever deposited at
    /// that size, or the counts no longer add up to the pool's balance. This is
    /// the one that catches a withdrawal claiming a value nobody paid in.
    OutstandingNotes {
        height: u64,
        detail: String,
    },
}

impl Violation {
    pub fn height(&self) -> u64 {
        match self {
            Violation::SupplyDrift { height, .. }
            | Violation::NegativeBalance { height, .. }
            | Violation::ShieldedPoolMismatch { height, .. }
            | Violation::OutstandingNotes { height, .. } => *height,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Violation::SupplyDrift { height, expected_net, actual_net, minted, burned } => format!(
                "block #{height}: balance changes sum to {actual_net} uEGOC but the block minted {minted} and burned {burned}, which is {expected_net}"
            ),
            Violation::NegativeBalance { height, address, current, delta } => format!(
                "block #{height}: {address} holds {current} uEGOC and the block applies {delta}, which would go below zero"
            ),
            Violation::ShieldedPoolMismatch { height, recorded_uegoc, on_chain_uegoc } => format!(
                "block #{height}: the shielded pool records {recorded_uegoc} uEGOC but its address holds {on_chain_uegoc}"
            ),
            Violation::OutstandingNotes { height, detail } => format!(
                "block #{height}: shielded note counts are impossible: {detail}"
            ),
        }
    }
}

fn log() -> &'static Mutex<Vec<Violation>> {
    static LOG: std::sync::OnceLock<Mutex<Vec<Violation>>> = std::sync::OnceLock::new();
    LOG.get_or_init(|| Mutex::new(Vec::new()))
}

/// Whether a violation should stop the process rather than be recorded.
///
/// Off by default: a false positive that halts a validator is an outage, and a
/// node that has stopped cannot report why it stopped. Tests and testnet
/// validators should turn it on, because there a loud failure is worth more
/// than an available node.
pub fn strict() -> bool {
    matches!(std::env::var("EGO_INVARIANTS").as_deref(), Ok("strict"))
}

/// Record a violation. Never called on a healthy chain.
pub fn report(v: Violation) {
    let text = v.describe();
    tracing::error!("[Invariant] {text}");
    eprintln!("[Invariant] VIOLATED — {text}");
    {
        let mut l = log().lock().unwrap_or_else(|e| e.into_inner());
        l.push(v);
        let excess = l.len().saturating_sub(KEEP);
        if excess > 0 {
            l.drain(0..excess);
        }
    }
    if strict() {
        panic!("invariant violated: {text}");
    }
}

/// Recent violations, newest last. Empty on a healthy chain.
pub fn violations() -> Vec<Violation> {
    log().lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Forget what has been recorded. For tests, which share this process.
pub fn clear() {
    log().lock().unwrap_or_else(|e| e.into_inner()).clear();
}

// Detection is kept separate from reaction throughout. The `*_violation`
// functions are pure and decide whether something is wrong; the `check_*`
// wrappers decide what to do about it. That split is what lets the tests
// below exercise the detection without tripping strict mode, so the whole
// suite can be run with `EGO_INVARIANTS=strict` and stay clean.

/// Whether a block's balance changes add up to what it minted and burned.
pub fn supply_violation(
    height: u64,
    supply: &SupplyLedger,
    deltas: &std::collections::HashMap<String, i128>,
) -> Option<Violation> {
    let actual_net: i128 = deltas.values().sum();
    let expected_net = supply.expected_net();
    if actual_net == expected_net {
        return None;
    }
    Some(Violation::SupplyDrift {
        height,
        expected_net,
        actual_net,
        minted: supply.minted(),
        burned: supply.burned(),
    })
}

/// Whether one account's change would take it below zero.
pub fn balance_violation(height: u64, address: &str, current: u64, delta: i128) -> Option<Violation> {
    if current as i128 + delta >= 0 {
        return None;
    }
    Some(Violation::NegativeBalance {
        height,
        address: address.to_string(),
        current,
        delta,
    })
}

/// The whole-block check: every balance change in `deltas` must be accounted
/// for by what `supply` says the block minted and burned.
pub fn check_supply(height: u64, supply: &SupplyLedger, deltas: &std::collections::HashMap<String, i128>) {
    if let Some(v) = supply_violation(height, supply, deltas) {
        report(v);
    }
}

/// One account's balance change, before the clamp hides it.
pub fn check_balance(height: u64, address: &str, current: u64, delta: i128) {
    if let Some(v) = balance_violation(height, address, current, delta) {
        report(v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    /// These tests share one process-wide violation log.
    static GUARD: StdMutex<()> = StdMutex::new(());

    fn deltas(pairs: &[(&str, i128)]) -> HashMap<String, i128> {
        pairs.iter().map(|(a, d)| (a.to_string(), *d)).collect()
    }

    #[test]
    fn a_plain_transfer_balances_to_the_fee_it_burned() {
        let mut supply = SupplyLedger::new();
        supply.burn(1_000);
        assert!(supply_violation(1, &supply, &deltas(&[("alice", -101_000), ("bob", 100_000)])).is_none());
    }

    #[test]
    fn a_coinbase_balances_to_what_it_minted() {
        let mut supply = SupplyLedger::new();
        supply.mint(50_000);
        assert!(supply_violation(2, &supply, &deltas(&[("miner", 50_000)])).is_none());
    }

    /// Coins credited to somebody with nothing debited and no mint recorded.
    /// This is the shape of every inflation bug in balance application.
    #[test]
    fn value_appearing_from_nowhere_is_caught() {
        let supply = SupplyLedger::new();
        let v = supply_violation(3, &supply, &deltas(&[("thief", 1_000_000)]));
        assert!(matches!(
            v,
            Some(Violation::SupplyDrift { actual_net: 1_000_000, expected_net: 0, .. })
        ));
    }

    /// The other direction: value destroyed without anybody burning it.
    #[test]
    fn value_vanishing_is_caught_too() {
        let supply = SupplyLedger::new();
        assert!(supply_violation(4, &supply, &deltas(&[("nobody", -5)])).is_some());
    }

    #[test]
    fn a_transfer_that_credits_more_than_it_debits_is_caught() {
        let mut supply = SupplyLedger::new();
        supply.burn(1_000);
        // Recipient credited twice what the sender paid.
        let v = supply_violation(5, &supply, &deltas(&[("alice", -101_000), ("bob", 200_000)]));
        assert!(v.is_some());
    }

    #[test]
    fn a_clamp_is_detected_before_it_hides_the_error() {
        assert!(balance_violation(6, "alice", 10, -11).is_some());
        assert!(balance_violation(6, "bob", 10, -10).is_none(), "exactly zero is fine");
        assert!(balance_violation(6, "carol", 10, 5).is_none());
    }

    /// A mint and a burn in the same block cancel where they should.
    #[test]
    fn a_block_that_both_mints_and_burns_is_accounted_for() {
        let mut supply = SupplyLedger::new();
        supply.mint(50_000);
        supply.burn(1_000);
        assert!(supply_violation(
            7,
            &supply,
            &deltas(&[("miner", 50_000), ("alice", -101_000), ("bob", 100_000)])
        )
        .is_none());
    }

    #[test]
    fn the_log_keeps_the_most_recent_and_forgets_the_rest() {
        // `report` panics under strict mode by design, and that is what the
        // suite is run with in CI, so this exercises the log only when it can.
        if strict() {
            return;
        }
        let _g = GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        for i in 0..(KEEP + 10) {
            report(Violation::NegativeBalance {
                height: i as u64,
                address: "alice".into(),
                current: 0,
                delta: -1,
            });
        }
        let v = violations();
        assert_eq!(v.len(), KEEP);
        assert_eq!(v.last().unwrap().height(), (KEEP + 9) as u64);
        clear();
    }

    #[test]
    fn strict_mode_follows_the_environment_and_nothing_else() {
        let asked_for = matches!(std::env::var("EGO_INVARIANTS").as_deref(), Ok("strict"));
        assert_eq!(strict(), asked_for);
    }

    #[test]
    fn every_violation_says_what_happened() {
        for v in [
            Violation::SupplyDrift { height: 1, expected_net: 0, actual_net: 5, minted: 0, burned: 0 },
            Violation::NegativeBalance { height: 2, address: "a".into(), current: 0, delta: -1 },
            Violation::ShieldedPoolMismatch { height: 3, recorded_uegoc: 1, on_chain_uegoc: 2 },
            Violation::OutstandingNotes { height: 4, detail: "x".into() },
        ] {
            let d = v.describe();
            assert!(d.contains(&format!("#{}", v.height())), "{d}");
            assert!(d.len() > 20, "{d}");
        }
    }
}
