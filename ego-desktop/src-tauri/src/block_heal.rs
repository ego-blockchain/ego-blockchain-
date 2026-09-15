use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// How long a height is given to arrive complete before the node stops waiting for it.
/// A peer on a slow link, or one that is still writing the block it just finalized, needs
/// a few seconds. A peer that cannot serve the block at all will not become able to.
pub const GRACE_SECS: i64 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    KeepAsking,
    RedoHeight,
    SkipWithSnapshot,
}

#[derive(Clone, Copy, Debug)]
pub struct Short {
    pub first_seen: i64,
    pub tries: u32,
    pub best_got: u32,
    pub claimed: u32,
}

static SHORT: OnceLock<Mutex<HashMap<u64, Short>>> = OnceLock::new();

fn short() -> std::sync::MutexGuard<'static, HashMap<u64, Short>> {
    SHORT.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap_or_else(|e| e.into_inner())
}

pub fn note_short_serve(height: u64, got: u32, claimed: u32, now: i64) -> Short {
    let mut map = short();
    let e = map.entry(height).or_insert(Short { first_seen: now, tries: 0, best_got: 0, claimed });
    e.tries = e.tries.saturating_add(1);
    e.best_got = e.best_got.max(got);
    e.claimed = claimed;
    *e
}

pub fn clear(height: u64) {
    short().remove(&height);
}

pub fn forget_below(height: u64) {
    short().retain(|h, _| *h >= height);
}

pub fn pending() -> Vec<(u64, Short)> {
    short().iter().map(|(h, s)| (*h, *s)).collect()
}

pub fn waited_out(s: &Short, now: i64) -> bool {
    now.saturating_sub(s.first_seen) >= GRACE_SECS
}

/// What to do about a height nobody will serve in full.
///
/// Redoing a height the network has already moved past is a fork, so that case takes a
/// snapshot instead: the node skips over the block it cannot read and rejoins the chain
/// everyone else has. Only the frontier, the one height nothing is built on yet, may be
/// thrown away and produced again.
pub fn verdict(
    height: u64,
    local_tip: u64,
    network_tip: u64,
    can_propose: bool,
    s: &Short,
    now: i64,
) -> Verdict {
    if !waited_out(s, now) {
        return Verdict::KeepAsking;
    }
    if network_tip > height {
        return Verdict::SkipWithSnapshot;
    }
    if can_propose && height == local_tip.saturating_add(1) {
        return Verdict::RedoHeight;
    }
    Verdict::SkipWithSnapshot
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(first_seen: i64) -> Short {
        Short { first_seen, tries: 3, best_got: 6, claimed: 7 }
    }

    #[test]
    fn a_height_is_given_seconds_before_anything_is_thrown_away() {
        let st = s(1_000);
        assert_eq!(verdict(5, 4, 5, true, &st, 1_000), Verdict::KeepAsking);
        assert_eq!(verdict(5, 4, 5, true, &st, 1_000 + GRACE_SECS - 1), Verdict::KeepAsking);
    }

    #[test]
    fn the_frontier_is_redone_once_the_wait_is_over() {
        let st = s(1_000);
        assert_eq!(
            verdict(5, 4, 5, true, &st, 1_000 + GRACE_SECS),
            Verdict::RedoHeight,
            "nothing is built on height 5 yet, so producing it again forks nothing",
        );
    }

    #[test]
    fn a_height_the_network_has_moved_past_is_never_redone() {
        let st = s(1_000);
        assert_eq!(
            verdict(5, 4, 9, true, &st, 1_000 + 600),
            Verdict::SkipWithSnapshot,
            "four blocks are already built on height 5; producing a different one is a fork",
        );
    }

    #[test]
    fn a_hole_in_the_middle_is_filled_by_snapshot_not_by_redoing_it() {
        let st = s(1_000);
        assert_eq!(verdict(5, 8, 8, true, &st, 1_000 + 600), Verdict::SkipWithSnapshot);
    }

    #[test]
    fn a_node_that_cannot_propose_takes_a_snapshot_instead_of_redoing_the_height() {
        let st = s(1_000);
        assert_eq!(
            verdict(5, 4, 5, false, &st, 1_000 + GRACE_SECS),
            Verdict::SkipWithSnapshot,
            "a follower producing no replacement would clear the tracking and ask for the              same unservable block again, for ever",
        );
    }

    #[test]
    fn tries_accumulate_and_the_first_sighting_is_what_the_clock_runs_from() {
        clear(41);
        let a = note_short_serve(41, 6, 7, 500);
        let b = note_short_serve(41, 4, 7, 507);
        assert_eq!(a.first_seen, 500);
        assert_eq!(b.first_seen, 500, "a later short serve does not restart the wait");
        assert_eq!(b.tries, 2);
        assert_eq!(b.best_got, 6, "the fullest any peer managed, not the last one");
        clear(41);
    }

    #[test]
    fn a_healed_height_stops_being_tracked() {
        clear(77);
        note_short_serve(77, 6, 7, 100);
        assert!(pending().iter().any(|(h, _)| *h == 77));
        clear(77);
        assert!(!pending().iter().any(|(h, _)| *h == 77));
    }

    #[test]
    fn heights_the_chain_has_passed_are_forgotten() {
        clear(10);
        clear(20);
        note_short_serve(10, 1, 2, 0);
        note_short_serve(20, 1, 2, 0);
        forget_below(15);
        assert!(!pending().iter().any(|(h, _)| *h == 10));
        assert!(pending().iter().any(|(h, _)| *h == 20));
        clear(20);
    }
}
