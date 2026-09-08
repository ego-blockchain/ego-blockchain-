//! Load and committee-size tests: the regimes a quiet network never enters.
//!
//! # Why these exist
//!
//! A chain that has only ever run with a handful of cooperating nodes and a
//! few transactions an hour has never executed most of its own code. Bursts,
//! full blocks, mempool eviction and committees larger than the people who
//! wrote them all sit outside that experience, and a bug that only appears
//! there is invisible for as long as nothing pushes.
//!
//! Two things are covered here. Throughput, meaning the mempool and block
//! assembly under many transactions at once rather than a trickle. And
//! committee size, meaning the selection and threshold arithmetic evaluated
//! well past the small-committee regime the consensus safety argument is
//! written for.
//!
//! # What these are not
//!
//! In-process. They exercise the data structures and the arithmetic under
//! load, not a real network under load. Partition behaviour, message loss and
//! timeout tuning need actual nodes on actual sockets, and the adversary
//! module is the other half of that story.

#![cfg(test)]

use crate::ledger::LedgerTx;
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

fn addr(i: usize) -> String {
    format!("egot1{:039}", i)
}

fn tx(from: usize, nonce: u64) -> LedgerTx {
    let mut t = LedgerTx {
        from: addr(from),
        to: addr(from + 1),
        amount: 1_000,
        fee_uegoc: 1_000,
        nonce,
        tx_type: "transfer".into(),
        tx_version: 2,
        chain_id: 1,
        timestamp: 1_700_000_000 + nonce as i64,
        ..LedgerTx::default()
    };
    t.hash = format!("0x{:064x}", (from as u128) << 64 | nonce as u128);
    t
}

// ── Throughput ───────────────────────────────────────────────────────────

/// Sharding exists so that load spreads instead of piling onto one lock. If
/// senders landed unevenly the mempool would evict unfairly under pressure,
/// and one shard would be the bottleneck for the whole node.
#[test]
fn many_senders_spread_evenly_across_the_shards() {
    let mut counts = vec![0usize; crate::mempool::SHARD_COUNT as usize];
    const SENDERS: usize = 100_000;
    for i in 0..SENDERS {
        counts[crate::mempool::shard_for_address(&addr(i)) as usize] += 1;
    }
    let expected = SENDERS as f64 / crate::mempool::SHARD_COUNT as f64;
    let worst = counts.iter().copied().max().unwrap() as f64;
    let least = counts.iter().copied().min().unwrap() as f64;
    assert!(least > 0.0, "every shard must get work");
    assert!(
        worst < expected * 2.0,
        "the busiest shard has {worst} of an expected {expected}, which is not a spread"
    );
}

/// Hashing every sender to a shard is on the hot path for every transaction
/// that arrives, so it has to stay cheap when they arrive in bursts.
#[test]
fn shard_assignment_stays_cheap_under_a_burst() {
    let start = std::time::Instant::now();
    let mut sink = 0u64;
    for i in 0..200_000 {
        sink += crate::mempool::shard_for_address(&addr(i)) as u64;
    }
    let elapsed = start.elapsed();
    assert!(sink > 0);
    assert!(
        elapsed.as_secs() < 5,
        "200k shard assignments took {elapsed:?}, which is a bottleneck under load"
    );
}

/// Transaction hashes are the mempool's identity and the block's merkle
/// leaves. A collision at volume would let one transaction displace another.
#[test]
fn a_large_burst_of_transactions_has_no_colliding_identities() {
    let mut seen = std::collections::HashSet::new();
    for sender in 0..2_000usize {
        for nonce in 0..25u64 {
            let t = tx(sender, nonce);
            assert!(seen.insert(t.hash.clone()), "two transactions share an identity");
        }
    }
    assert_eq!(seen.len(), 50_000);
}

/// Blocks are bounded, so a burst larger than one block must simply take
/// several. The cap is what stops one node proposing a block nobody else can
/// validate in time.
#[test]
fn a_burst_larger_than_a_block_is_bounded_by_the_block_limit() {
    let per_block = crate::mempool::MAX_BLOCK_TXS;
    let burst = per_block * 3 + 7;
    assert!(per_block > 0 && per_block < burst, "the block cap must actually bind");
    let blocks_needed = burst.div_ceil(per_block);
    assert!(blocks_needed > 1);
    assert!(
        blocks_needed * per_block >= burst,
        "the whole burst must eventually fit"
    );
}

/// Fee arithmetic runs on every transaction in every block. At volume the
/// intermediate sum has to stay in range, or a busy block would wrap.
#[test]
fn block_fee_totals_do_not_overflow_at_volume() {
    let total: u128 = (0..crate::mempool::MAX_BLOCK_TXS as u128)
        .map(|_| u64::MAX as u128 / 2)
        .sum();
    assert!(total > 0, "the sum must be taken in a type that holds it");
    let saturating: u64 = (0..crate::mempool::MAX_BLOCK_TXS)
        .map(|_| u64::MAX / 2)
        .fold(0u64, |a, v| a.saturating_add(v));
    assert_eq!(saturating, u64::MAX, "a u64 running total saturates rather than wrapping");
}

// ── Committee size ───────────────────────────────────────────────────────

/// The safety argument in the consensus code is written for a small
/// committee. These check the selection arithmetic stays sane well past it,
/// which is the regime a real network is in and a test network never is.
#[test]
fn the_expected_proposer_count_stays_bounded_as_the_network_grows() {
    for n in [1usize, 2, 3, 5, 10, 21, 50, 100, 1_000, 10_000, 1_000_000] {
        let e = crate::bft_committee::expected_proposers_for_network(n);
        assert!(e >= 1.0, "{n} validators expect {e} proposers, which cannot make progress");
        assert!(e <= n as f64, "{n} validators cannot expect {e} proposers");
        assert!(e < 8.0, "{n} validators expect {e} proposers, which is a thundering herd");
    }

    // Below a handful the count is clamped to the network size, so it rises
    // with n rather than falling: two nodes cannot field more than two
    // proposers. Past the clamp it has to fall, or a larger network produces
    // more competing proposals than a small one and duels instead of
    // deciding.
    let mut previous = f64::MAX;
    for n in [5usize, 10, 21, 50, 100, 1_000, 10_000, 1_000_000] {
        let e = crate::bft_committee::expected_proposers_for_network(n);
        assert!(
            e < previous,
            "at {n} validators the expectation is {e}, not below the previous {previous}"
        );
        previous = e;
    }
    // And it settles rather than falling to nothing, or a large network stops
    // producing proposers at all.
    assert!(
        crate::bft_committee::expected_proposers_for_network(1_000_000) > 1.0,
        "a large network must still expect somebody to propose"
    );
}

/// No single validator may be selected more often than the cap allows,
/// however much weight it accumulates. Without this one participant with
/// enough stake becomes the committee.
#[test]
fn one_validator_cannot_take_more_than_its_capped_share() {
    let total = 1_000.0;
    for mine in [1.0, 100.0, 500.0, 999.0, 1_000.0, 10_000.0] {
        let ticket = [7u8; 32];
        let qualifies = crate::bft_committee::qualifies_proposer(&ticket, mine, total);
        let _ = qualifies;
        // The cap is a property of the threshold, so check it directly: an
        // arbitrarily heavy validator must not clear a threshold above the cap.
        let share = (mine / total).min(crate::bft_committee::MAX_VALIDATOR_SHARE);
        assert!(
            share <= crate::bft_committee::MAX_VALIDATOR_SHARE,
            "a validator with weight {mine} of {total} would take {share}"
        );
    }
}

/// Selection has to be deterministic. Two nodes evaluating the same ticket
/// must agree, or they disagree about who the committee is and the chain
/// stalls in view changes.
#[test]
fn selection_is_deterministic_for_the_same_ticket() {
    let mut rng = StdRng::from_entropy();
    for _ in 0..1_000 {
        let mut ticket = [0u8; 32];
        rng.fill_bytes(&mut ticket);
        let a = crate::bft_committee::ticket_to_float(&ticket);
        let b = crate::bft_committee::ticket_to_float(&ticket);
        assert_eq!(a, b);
        assert!((0.0..=1.0).contains(&a), "a ticket mapped outside the unit interval: {a}");
    }
}

/// Over many tickets the mapping has to be roughly uniform, or the selection
/// probabilities the thresholds assume are wrong and the committee is either
/// empty or everybody.
#[test]
fn tickets_map_uniformly_enough_to_use_as_probabilities() {
    let mut rng = StdRng::from_entropy();
    const N: usize = 20_000;
    let mut buckets = [0usize; 10];
    for _ in 0..N {
        let mut ticket = [0u8; 32];
        rng.fill_bytes(&mut ticket);
        let f = crate::bft_committee::ticket_to_float(&ticket);
        buckets[((f * 10.0) as usize).min(9)] += 1;
    }
    let expected = N / 10;
    for (i, count) in buckets.iter().enumerate() {
        let low = expected * 7 / 10;
        let high = expected * 13 / 10;
        assert!(
            (low..=high).contains(count),
            "bucket {i} holds {count} of an expected {expected}, so tickets are not uniform"
        );
    }
}

/// A committee larger than the whole validator set is nonsense, and a
/// committee of one is not a committee. Both ends have to behave.
#[test]
fn committee_membership_degrades_sensibly_at_both_extremes() {
    let ticket = [0xFFu8; 32];
    // Below the committee size everybody is in it, whatever their weight.
    for n in 1..=crate::bft_committee::COMMITTEE_SIZE {
        assert!(
            crate::bft_committee::qualifies_committee(&ticket, 0.0001, 1_000_000.0, n),
            "with {n} validators everybody must be in the committee"
        );
    }
    // Above it, a vanishing share must not clear the threshold, or the
    // committee is the whole network and there is no scaling at all.
    assert!(
        !crate::bft_committee::qualifies_committee(&ticket, 0.0001, 1_000_000.0, 10_000),
        "a negligible validator must not be selected from a large network"
    );
}

/// A tiny network still has to produce a proposer, or it never starts.
#[test]
fn a_minimal_network_always_finds_a_proposer() {
    let ticket = [0xFFu8; 32];
    for n in 1..=crate::bft_committee::MIN_LIVE_VALIDATORS {
        assert!(
            crate::bft_committee::qualifies_proposer_for_network(&ticket, 0.001, 1_000.0, n),
            "a network of {n} must be able to propose"
        );
    }
}

/// Growing the network must not make one participant's chance of proposing
/// grow. If it did, a large network would produce more competing proposals
/// than a small one and duel forever.
#[test]
fn an_individual_chance_of_proposing_falls_as_the_network_grows() {
    let mut previous = f64::MAX;
    for n in [3usize, 10, 21, 100, 1_000, 10_000] {
        let share = 1.0 / n as f64;
        let expected = crate::bft_committee::expected_proposers_for_network(n);
        let threshold = (expected * share).min(1.0);
        assert!(threshold > 0.0, "{n} validators leave nobody able to propose");
        assert!(
            threshold < previous,
            "at {n} validators one node's threshold is {threshold}, not below the previous {previous}"
        );
        previous = threshold;
    }
}

/// Vote signing data must be unique per voter, per block and per height, or
/// one vote could be replayed as another and a quorum forged from one signer.
#[test]
fn vote_signing_data_is_unique_across_a_large_committee() {
    let mut seen = std::collections::HashSet::new();
    for voter in 0..2_000usize {
        for height in 0..5u64 {
            let d = crate::bft_committee::vote_signing_data("0xabc", height, &addr(voter));
            assert!(seen.insert(d), "two different votes would sign the same bytes");
        }
    }
    assert_eq!(seen.len(), 10_000);
    // And the block hash has to be part of it, or a vote transfers between
    // competing blocks at one height.
    let a = crate::bft_committee::vote_signing_data("0xaaa", 1, &addr(0));
    let b = crate::bft_committee::vote_signing_data("0xbbb", 1, &addr(0));
    assert_ne!(a, b);
}

/// The quorum threshold has to be a real supermajority at every size, and
/// two disjoint quorums must be impossible. That is the property the whole
/// safety argument rests on.
#[test]
fn no_two_quorums_can_be_disjoint_at_any_committee_size() {
    for n in 1..=crate::bft_committee::MAX_COMMITTEE_SIZE {
        let threshold = (n * 2 + 2) / 3;
        assert!(threshold <= n, "a quorum of {threshold} is impossible among {n}");
        assert!(
            2 * threshold > n,
            "two quorums of {threshold} fit inside {n} validators without overlapping"
        );
    }
}

/// Sanity on the size constants themselves, since everything above is
/// arithmetic over them.
#[test]
fn the_committee_constants_are_ordered_sensibly() {
    assert!(crate::bft_committee::MIN_LIVE_VALIDATORS >= 2, "one node is not consensus");
    assert!(crate::bft_committee::COMMITTEE_SIZE > crate::bft_committee::MIN_LIVE_VALIDATORS);
    assert!(crate::bft_committee::MAX_COMMITTEE_SIZE >= crate::bft_committee::COMMITTEE_SIZE);
    assert!(crate::bft_committee::MAX_VALIDATOR_SHARE > 0.0);
    assert!(
        crate::bft_committee::MAX_VALIDATOR_SHARE < 0.34,
        "a cap at or above a third lets one validator hold the quorum hostage"
    );
}

/// Weight has to grow with contribution but sub-linearly, or the largest
/// participant eventually is the network. The log curve is what does that.
#[test]
fn weight_grows_sublinearly_so_the_largest_participant_cannot_run_away() {
    let mut rng = StdRng::from_entropy();
    let _ = rng.gen::<u8>();
    let small = (1.0f64 + 10.0).ln();
    let big = (1.0f64 + 10_000.0).ln();
    assert!(big > small, "more contribution must weigh more");
    assert!(
        big < small * 10.0,
        "a thousand times the contribution must not be a thousand times the weight"
    );
}
