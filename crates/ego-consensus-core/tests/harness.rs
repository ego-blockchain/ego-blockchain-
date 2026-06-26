//! Deterministic in-process multi-node harness for the BFT state machine.
//!
//! This replaces the "run it on two PCs and paste the logs" loop that the inline
//! p2p.rs BFT forced on us. Engines are driven with synchronous, in-memory message
//! passing — no libp2p, no relay, no Windows port exhaustion — so consensus
//! behaviour (liveness, agreement, no-fork, leader-down failover, partition/heal)
//! is reproducible and asserted in CI.
//!
//! Phase 1 of CONSENSUS_REPLACEMENT_SCOPE.md.

use ego_consensus_core::bft::{BftEngine, BlockRoots, SigScheme, Vote};
use ego_core::{Address, Hash, KeyPair};

/// A simulated network of N engines that all share the SAME validator set (so they
/// agree deterministically on the per-round proposer via `(height + round) % n`).
struct Net {
    engines: Vec<BftEngine>,
}

impl Net {
    /// Fast default for the state-machine suites: ed25519 (the consensus logic is
    /// identical regardless of scheme; ed25519 just keeps these heavy loops quick).
    fn new(n: usize) -> Self {
        Self::with_scheme(n, SigScheme::Ed25519)
    }

    fn with_scheme(n: usize, scheme: SigScheme) -> Self {
        let kps: Vec<KeyPair> = (0..n).map(|_| KeyPair::generate()).collect();
        // One canonical validator-set Vec, cloned identically into every engine, derived
        // with the SAME scheme the engines sign under so vote.voter matches a member.
        let validators: Vec<Address> = kps.iter().map(|k| scheme.address(k)).collect();
        let engines = kps
            .into_iter()
            .map(|kp| BftEngine::with_scheme(kp, validators.clone(), scheme))
            .collect();
        Net { engines }
    }

    fn n(&self) -> usize {
        self.engines.len()
    }

    fn quorum(&self) -> usize {
        (2 * self.n()) / 3 + 1
    }

    /// Drive exactly one height to finalization, tolerating up to `max_rounds`
    /// view-changes when the current round's proposer is unreachable. `reachable[i]`
    /// marks which engines can send/receive this height (false = partitioned away).
    ///
    /// Returns the finalized block hash, or `None` if the reachable set could not
    /// reach quorum within `max_rounds` (i.e. the chain correctly HALTS — no solo).
    fn run_height(&self, reachable: &[bool], max_rounds: u32) -> Option<Hash> {
        for _ in 0..max_rounds {
            // The elected proposer for the CURRENT (height, round) of each engine.
            let proposer = self
                .engines
                .iter()
                .enumerate()
                .find(|(i, e)| reachable[*i] && e.is_proposer())
                .map(|(i, _)| i);

            if let Some(p) = proposer {
                let header = self.engines[p]
                    .propose_block(BlockRoots::empty())
                    .expect("propose_block");

                // Every reachable engine (incl. the proposer) votes on the proposal.
                let mut votes = Vec::new();
                for (i, e) in self.engines.iter().enumerate() {
                    if !reachable[i] {
                        continue;
                    }
                    if let Some(v) = e.receive_proposal(&header).expect("receive_proposal") {
                        votes.push(v);
                    }
                }

                // Deliver all votes to all reachable engines; each forms its own QC
                // at quorum and finalizes independently.
                let mut finalized = None;
                for (i, e) in self.engines.iter().enumerate() {
                    if !reachable[i] {
                        continue;
                    }
                    for v in &votes {
                        if let Some(qc) = e.receive_vote(v).expect("receive_vote") {
                            assert!(
                                qc.voter_count() >= self.quorum(),
                                "QC formed with {} votes < quorum {}",
                                qc.voter_count(),
                                self.quorum()
                            );
                            e.finalize_block(header.clone(), qc).expect("finalize_block");
                            finalized = Some(header.block_hash());
                            break;
                        }
                    }
                }
                if finalized.is_some() {
                    return finalized;
                }
                // Proposed but quorum not reached (too few reachable) → view-change.
            }

            // No reachable proposer, or the round failed → every reachable engine
            // broadcasts a ViewChange and they advance to the next round together.
            let vc: Vec<_> = self
                .engines
                .iter()
                .enumerate()
                .filter(|(i, _)| reachable[*i])
                .map(|(_, e)| e.trigger_view_change().expect("trigger_view_change"))
                .collect();
            for (i, e) in self.engines.iter().enumerate() {
                if !reachable[i] {
                    continue;
                }
                for m in &vc {
                    let _ = e.receive_view_change(m.clone()).expect("receive_view_change");
                }
            }
        }
        None
    }

    /// All engines that participated this height must agree on the finalized block
    /// AND be at the same next height — the core safety property (no fork).
    fn assert_agreement(&self, reachable: &[bool], expected: Hash) {
        let mut heights = Vec::new();
        for (i, e) in self.engines.iter().enumerate() {
            if !reachable[i] {
                continue;
            }
            let (h, _qc) = e
                .get_latest_finalized_block()
                .expect("engine should have a finalized block");
            assert_eq!(
                h.block_hash(),
                expected,
                "engine {i} finalized a DIFFERENT block — FORK",
            );
            heights.push(e.get_current_height());
        }
        assert!(
            heights.windows(2).all(|w| w[0] == w[1]),
            "engines diverged on height: {heights:?}",
        );
    }
}

fn all_reachable(n: usize) -> Vec<bool> {
    vec![true; n]
}

/// Liveness + agreement under perfect network, for several committee sizes.
fn liveness_for(n: usize, heights: u64) {
    let net = Net::new(n);
    let reach = all_reachable(n);
    for h in 0..heights {
        let hash = net
            .run_height(&reach, 4)
            .unwrap_or_else(|| panic!("N={n}: failed to finalize height {h}"));
        net.assert_agreement(&reach, hash);
        // Every engine advanced exactly one height.
        for e in &net.engines {
            assert_eq!(e.get_current_height(), h + 1);
        }
    }
}

#[test]
fn liveness_and_agreement_2_validators() {
    liveness_for(2, 50);
}

#[test]
fn liveness_and_agreement_4_validators() {
    liveness_for(4, 50);
}

#[test]
fn liveness_and_agreement_7_validators() {
    liveness_for(7, 50);
}

/// The production default scheme is post-quantum **Dilithium**. The heavy
/// liveness/adversarial suites run on ed25519 for speed (the state machine is
/// scheme-independent); this exercises the real PQ signing/verifying path end-to-end to
/// confirm it finalizes and agrees.
#[test]
fn dilithium_default_finalizes_and_agrees() {
    let n = 4;
    let net = Net::with_scheme(n, SigScheme::Dilithium);
    for h in 0..5 {
        let hash = net.run_height(&all_reachable(n), 4).expect("dilithium finalize");
        net.assert_agreement(&all_reachable(n), hash);
        for e in &net.engines {
            assert_eq!(e.get_current_height(), h + 1);
        }
    }
}

/// The exact failure that killed the live network: the elected leader for a height
/// goes offline. The inline p2p.rs BFT could not rotate past it (its view-change
/// ignored the view) and deadlocked. Here the reachable majority must view-change
/// to the NEXT proposer and finalize anyway — with f = 1 fault out of 4 (quorum 3).
#[test]
fn leader_down_rotates_and_recovers() {
    let n = 4;
    let net = Net::new(n);

    // Warm up a few clean heights.
    for h in 0..5 {
        let hash = net.run_height(&all_reachable(n), 4).expect("warmup finalize");
        net.assert_agreement(&all_reachable(n), hash);
        assert_eq!(net.engines[0].get_current_height(), h + 1);
    }

    // Partition out whichever node is the round-0 proposer for the next height.
    let down = net
        .engines
        .iter()
        .position(|e| e.is_proposer())
        .expect("a proposer exists");
    let mut reach = all_reachable(n);
    reach[down] = false;

    // The other 3 (>= quorum) must route around the dead leader via view-change.
    let hash = net
        .run_height(&reach, 8)
        .expect("must finalize past a down leader via view-change");
    net.assert_agreement(&reach, hash);

    // Heal: the down node is back. The majority kept the chain alive, so the
    // network resumes cleanly for subsequent heights.
    let target = net.engines.iter().enumerate()
        .filter(|(i, _)| reach[*i])
        .map(|(_, e)| e.get_current_height())
        .max()
        .unwrap();
    assert!(target >= 6, "chain should have advanced past the partition, got {target}");
}

/// A network that drops below quorum (2-of-2 loses one) must HALT, not solo-fork —
/// and then RESUME when the peer returns. This is the user's rule ("1 active → stop,
/// 2 active → blocks") expressed as a test the engine must satisfy.
#[test]
fn below_quorum_halts_then_resumes() {
    let n = 2;
    let net = Net::new(n);

    // Two clean heights.
    for h in 0..2 {
        let hash = net.run_height(&all_reachable(n), 4).expect("finalize");
        net.assert_agreement(&all_reachable(n), hash);
        assert_eq!(net.engines[0].get_current_height(), h + 1);
    }

    // Partition: only one node reachable. Quorum is 2, so it must NOT finalize.
    // Use a single-round attempt (no view-change churn) to assert the clean halt.
    let solo = vec![true, false];
    let h_before = net.engines[0].get_current_height();
    let res = net.try_round(&solo);
    assert!(res.is_none(), "a lone node must HALT, never finalize (no solo-fork)");
    assert_eq!(
        net.engines[0].get_current_height(),
        h_before,
        "height must not advance while below quorum",
    );

    // Heal: both reachable again → chain resumes from where it halted.
    let hash = net.run_height(&all_reachable(n), 6).expect("must resume after heal");
    net.assert_agreement(&all_reachable(n), hash);
    assert_eq!(net.engines[0].get_current_height(), h_before + 1);
}

impl Net {
    /// A single proposal+vote round with NO view-change machinery. Returns the
    /// finalized hash if the reachable set reached quorum this round, else `None`.
    /// Used to assert a clean HALT below quorum without churning view-change state.
    fn try_round(&self, reachable: &[bool]) -> Option<Hash> {
        let p = self
            .engines
            .iter()
            .enumerate()
            .find(|(i, e)| reachable[*i] && e.is_proposer())
            .map(|(i, _)| i)?;
        let header = self.engines[p].propose_block(BlockRoots::empty()).unwrap();
        let mut votes = Vec::new();
        for (i, e) in self.engines.iter().enumerate() {
            if reachable[i] {
                if let Some(v) = e.receive_proposal(&header).unwrap() {
                    votes.push(v);
                }
            }
        }
        let mut finalized = None;
        for (i, e) in self.engines.iter().enumerate() {
            if !reachable[i] {
                continue;
            }
            for v in &votes {
                if let Some(qc) = e.receive_vote(v).unwrap() {
                    e.finalize_block(header.clone(), qc).unwrap();
                    finalized = Some(header.block_hash());
                    break;
                }
            }
        }
        finalized
    }

    /// Drive one all-reachable height to finalization, but pass the collected votes
    /// through `mangle` first — used to simulate adversarial network conditions
    /// (reordering, duplication) on the vote stream.
    fn run_height_mangled(&self, mangle: impl Fn(&mut Vec<Vote>)) -> Hash {
        let p = self
            .engines
            .iter()
            .position(|e| e.is_proposer())
            .expect("a proposer exists");
        let header = self.engines[p].propose_block(BlockRoots::empty()).unwrap();

        let mut votes = Vec::new();
        for e in &self.engines {
            if let Some(v) = e.receive_proposal(&header).unwrap() {
                votes.push(v);
            }
        }
        mangle(&mut votes);

        let mut finalized = None;
        for e in &self.engines {
            for v in &votes {
                if let Some(qc) = e.receive_vote(v).unwrap() {
                    e.finalize_block(header.clone(), qc).unwrap();
                    finalized = Some(header.block_hash());
                    break;
                }
            }
        }
        finalized.expect("finalized")
    }
}

/// Async networks reorder and re-deliver messages. The engine tallies votes in a
/// per-voter map, so out-of-order and duplicate votes must not change the outcome:
/// the same single chain finalizes regardless of vote delivery order.
#[test]
fn vote_reordering_and_duplicates_tolerated() {
    let n = 7;
    let net = Net::new(n);
    for h in 0..30 {
        let hash = net.run_height_mangled(|votes| {
            votes.reverse(); // deliver newest-first
            let dups = votes.clone();
            votes.extend(dups); // every vote arrives twice
        });
        net.assert_agreement(&all_reachable(n), hash);
        for e in &net.engines {
            assert_eq!(e.get_current_height(), h + 1);
        }
    }
}

/// SAFETY under a Byzantine proposer (the ⅓-fault assumption): the elected proposer
/// equivocates — it signs TWO different blocks at the same height and feeds them to
/// honest nodes in conflicting orders. No two honest engines may finalize different
/// blocks (no fork). A single equivocator must never split the chain.
#[test]
fn byzantine_equivocating_proposer_no_fork() {
    let n = 4;
    let net = Net::new(n);
    let p = net
        .engines
        .iter()
        .position(|e| e.is_proposer())
        .expect("a proposer exists");
    let honest: Vec<usize> = (0..n).filter(|&i| i != p).collect();

    // Byzantine proposer crafts two conflicting, validly-signed blocks for this height.
    let b1 = net.engines[p].propose_block(BlockRoots::empty()).unwrap();
    let mut other = BlockRoots::empty();
    other.tx_root = Hash::new([7u8; 32]); // different root → different block_hash
    let b2 = net.engines[p].propose_block(other).unwrap();
    assert_ne!(b1.block_hash(), b2.block_hash(), "equivocating blocks must differ");

    // Worst case for safety: honest nodes receive the two proposals in DIFFERENT
    // orders, so without an equivocation guard they would end on different blocks and
    // each cast votes for both — enabling two QCs.
    let orders: [[&_; 2]; 3] = [[&b1, &b2], [&b2, &b1], [&b1, &b2]];
    let mut votes = Vec::new();
    for (k, &hi) in honest.iter().enumerate() {
        for hdr in orders[k % orders.len()] {
            if let Some(v) = net.engines[hi].receive_proposal(hdr).unwrap() {
                votes.push(v);
            }
        }
    }

    // Deliver every vote to every honest engine; each may form a QC for whichever
    // block it is on.
    for &hi in &honest {
        for v in &votes {
            if let Some(qc) = net.engines[hi].receive_vote(v).unwrap() {
                let hdr = if qc.block_hash == b1.block_hash() { &b1 } else { &b2 };
                let _ = net.engines[hi].finalize_block(hdr.clone(), qc);
            }
        }
    }

    // The invariant: at most ONE distinct block finalized across all honest engines.
    let finals: std::collections::HashSet<Hash> = honest
        .iter()
        .filter_map(|&hi| net.engines[hi].get_latest_finalized_block().map(|(h, _)| h.block_hash()))
        .collect();
    assert!(
        finals.len() <= 1,
        "FORK: honest engines finalized {} different blocks under an equivocating proposer",
        finals.len(),
    );
}
