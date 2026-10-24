use ego_consensus_core::tendermint::{quorum, skip_threshold, Action, Tendermint, Timeouts, ValueId, VoteKind};
use std::collections::{BTreeMap, HashSet};

const HEIGHT: u64 = 40_000;
const SIZE: usize = 4;
const GIVE_UP_MS: u64 = 20_000;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
}

fn fast() -> Timeouts {
    Timeouts { first_propose_ms: 3_000, propose_ms: 2_000, prevote_ms: 1_000, precommit_ms: 1_000, per_round_ms: 500, cap_ms: 10_000 }
}

fn committee(pool: usize, attempt: u32, seed: u64) -> Vec<usize> {
    let mut ranked: Vec<(u64, usize)> = (0..pool)
        .map(|i| {
            let mut x = seed ^ (attempt as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (i as u64).wrapping_mul(0xC2B2_AE3D_27D4_EB4F);
            x ^= x >> 31;
            x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
            x ^= x >> 29;
            (x, i)
        })
        .collect();
    ranked.sort();
    ranked.into_iter().take(SIZE.min(pool)).map(|(_, i)| i).collect()
}

fn value_of(node: usize, attempt: u32, round: u32) -> ValueId {
    let mut v = [0u8; 32];
    v[0] = 7;
    v[1..9].copy_from_slice(&(node as u64).to_le_bytes());
    v[9..13].copy_from_slice(&attempt.to_le_bytes());
    v[13..17].copy_from_slice(&round.to_le_bytes());
    v
}

#[derive(Clone, Debug)]
enum Body {
    Proposal { round: u32, v: ValueId, pol: Option<u32>, backers: Vec<usize> },
    Vote { kind: VoteKind, round: u32, v: Option<ValueId> },
    GiveUp { lock: Option<(u32, ValueId)> },
    Decided { v: ValueId },
}

#[derive(Clone, Debug)]
struct Msg {
    attempt: u32,
    from: usize,
    body: Body,
    skips: Vec<Vec<(usize, Option<(u32, ValueId)>)>>,
}

struct Node {
    id: usize,
    attempt: u32,
    skips: Vec<Vec<(usize, Option<(u32, ValueId)>)>>,
    engine: Option<Tendermint>,
    members: Vec<usize>,
    entered: u64,
    gave_up: bool,
    give_ups: BTreeMap<usize, Option<(u32, ValueId)>>,
    prevotes_seen: BTreeMap<(u32, ValueId), HashSet<usize>>,
    decided: Option<ValueId>,
    later: Vec<Msg>,
    sent: Vec<Msg>,
}

fn carried(skips: &[Vec<(usize, Option<(u32, ValueId)>)>]) -> Option<ValueId> {
    let mut out = None;
    for cert in skips {
        if let Some((_, v)) = cert.iter().filter_map(|(_, l)| *l).max_by_key(|(r, _)| *r) {
            out = Some(v);
        }
    }
    out
}

struct Sim {
    rng: Rng,
    seed: u64,
    pool: usize,
    now: u64,
    nodes: Vec<Node>,
    online: Vec<bool>,
    queue: Vec<(u64, usize, Msg)>,
    max_delay: u64,
    loss_permille: u64,
    crash_first_decider: bool,
}

impl Sim {
    fn new(pool: usize, seed: u64, max_delay: u64) -> Sim {
        let mut sim = Sim { rng: Rng(seed | 1), seed, pool, now: 0, nodes: Vec::new(), online: vec![true; pool], queue: Vec::new(), max_delay, loss_permille: 0, crash_first_decider: false };
        for id in 0..pool {
            sim.nodes.push(Node {
                id,
                attempt: 0,
                skips: Vec::new(),
                engine: None,
                members: Vec::new(),
                entered: 0,
                gave_up: false,
                give_ups: BTreeMap::new(),
                prevotes_seen: BTreeMap::new(),
                decided: None,
                later: Vec::new(),
                sent: Vec::new(),
            });
        }
        for id in 0..pool {
            let out = sim.enter(id, Vec::new());
            sim.send(id, out);
        }
        sim
    }

    fn enter(&mut self, id: usize, skips: Vec<Vec<(usize, Option<(u32, ValueId)>)>>) -> Vec<Msg> {
        let attempt = skips.len() as u32;
        let members = committee(self.pool, attempt, self.seed);
        let me = members.iter().position(|m| *m == id);
        let mut engine = Tendermint::new(HEIGHT, members.len(), me, fast());
        if let Some(v) = carried(&skips) {
            engine.carry(v);
        }
        let n = &mut self.nodes[id];
        n.attempt = attempt;
        n.skips = skips;
        n.members = members;
        n.entered = self.now;
        n.gave_up = false;
        n.give_ups.clear();
        n.prevotes_seen.clear();
        n.sent.clear();
        let acts = engine.start(self.now);
        n.engine = Some(engine);
        let mut out = self.act(id, acts);
        let replay: Vec<Msg> = std::mem::take(&mut self.nodes[id].later);
        for m in replay {
            out.extend(self.receive(id, m));
        }
        out
    }

    fn act(&mut self, id: usize, actions: Vec<Action>) -> Vec<Msg> {
        let mut out = Vec::new();
        let mut queue: std::collections::VecDeque<Action> = actions.into();
        while let Some(a) = queue.pop_front() {
            let n = &mut self.nodes[id];
            match a {
                Action::Decide { value, .. } => {
                    if n.decided.is_none() {
                        n.decided = Some(value);
                    }
                }
                _ if n.gave_up => {}
                Action::Propose { round, pol_round, value } => {
                    let me = n.engine.as_ref().and_then(|e| e.me()).unwrap();
                    let v = value.unwrap_or_else(|| value_of(id, n.attempt, round));
                    let backers: Vec<usize> = pol_round
                        .and_then(|vr| n.prevotes_seen.get(&(vr, v)))
                        .map(|s| s.iter().copied().collect())
                        .unwrap_or_default();
                    out.push(Msg { attempt: n.attempt, from: id, body: Body::Proposal { round, v, pol: pol_round, backers }, skips: n.skips.clone() });
                    let e = n.engine.as_mut().unwrap();
                    queue.extend(e.on_proposal(self.now, round, me, v, pol_round, true));
                }
                Action::Vote { kind, round, value } => {
                    if kind == VoteKind::Prevote {
                        if let Some(v) = value {
                            n.prevotes_seen.entry((round, v)).or_default().insert(id);
                        }
                    }
                    out.push(Msg { attempt: n.attempt, from: id, body: Body::Vote { kind, round, v: value }, skips: n.skips.clone() });
                }
            }
        }
        out
    }

    fn receive(&mut self, id: usize, m: Msg) -> Vec<Msg> {
        if let Body::Decided { v } = m.body {
            if self.nodes[id].decided.is_none() {
                self.nodes[id].decided = Some(v);
            }
            return Vec::new();
        }
        let mine = self.nodes[id].attempt;
        if self.nodes[id].decided.is_some() || m.attempt < mine {
            return Vec::new();
        }
        if m.attempt > mine {
            if m.skips.len() as u32 == m.attempt {
                let mut out = self.enter(id, m.skips.clone());
                out.extend(self.receive(id, m));
                return out;
            }
            self.nodes[id].later.push(m);
            return Vec::new();
        }
        let now = self.now;
        let n = &mut self.nodes[id];
        let Some(from) = n.members.iter().position(|x| *x == m.from) else { return Vec::new() };
        let acts = match m.body {
            Body::Proposal { round, v, pol, backers } => {
                let e = n.engine.as_mut().unwrap();
                let mut acts = Vec::new();
                if let Some(vr) = pol {
                    for b in &backers {
                        if let Some(j) = n.members.iter().position(|x| x == b) {
                            n.prevotes_seen.entry((vr, v)).or_default().insert(*b);
                            acts.extend(e.on_vote(now, VoteKind::Prevote, vr, j, Some(v)));
                        }
                    }
                }
                acts.extend(e.on_proposal(now, round, from, v, pol, true));
                acts
            }
            Body::Vote { kind, round, v } => {
                if kind == VoteKind::Prevote {
                    if let Some(v) = v {
                        n.prevotes_seen.entry((round, v)).or_default().insert(m.from);
                    }
                }
                n.engine.as_mut().unwrap().on_vote(now, kind, round, from, v)
            }
            Body::GiveUp { lock } => {
                n.give_ups.insert(m.from, lock);
                return self.maybe_advance(id);
            }
            Body::Decided { .. } => return Vec::new(),
        };
        self.act(id, acts)
    }

    fn maybe_advance(&mut self, id: usize) -> Vec<Msg> {
        let n = &self.nodes[id];
        if n.decided.is_some() || n.give_ups.len() < skip_threshold(n.members.len()) {
            return Vec::new();
        }
        let mut skips = n.skips.clone();
        skips.push(n.give_ups.iter().map(|(a, l)| (*a, *l)).collect());
        self.enter(id, skips)
    }

    fn give_up_if_due(&mut self, id: usize) -> Vec<Msg> {
        let now = self.now;
        let n = &mut self.nodes[id];
        let Some(e) = n.engine.as_ref() else { return Vec::new() };
        if n.gave_up || n.decided.is_some() || e.me().is_none() || now.saturating_sub(n.entered) < GIVE_UP_MS * (1 + n.attempt as u64) {
            return Vec::new();
        }
        let lock = e.locked();
        if let Some((r, v)) = lock {
            let backed = n.prevotes_seen.get(&(r, v)).map_or(0, |s| s.len());
            assert!(backed >= quorum(n.members.len()), "a node locks only after seeing a quorum of prevotes");
        }
        n.gave_up = true;
        n.give_ups.insert(id, lock);
        let msg = Msg { attempt: n.attempt, from: id, body: Body::GiveUp { lock }, skips: n.skips.clone() };
        let mut out = vec![msg];
        out.extend(self.maybe_advance(id));
        out
    }

    fn resend(&mut self, id: usize) -> Vec<Msg> {
        let n = &self.nodes[id];
        if let Some(v) = n.decided {
            return vec![Msg { attempt: n.attempt, from: id, body: Body::Decided { v }, skips: Vec::new() }];
        }
        let mut out: Vec<Msg> = n.sent.iter().rev().take(6).cloned().collect();
        for (a, cert) in n.skips.iter().enumerate() {
            for (voter, lock) in cert {
                out.push(Msg { attempt: a as u32, from: *voter, body: Body::GiveUp { lock: *lock }, skips: n.skips[..a].to_vec() });
            }
        }
        out
    }

    fn send(&mut self, from: usize, msgs: Vec<Msg>) {
        if let Some(n) = self.nodes.get_mut(from) {
            for m in &msgs {
                if m.from == from && m.attempt == n.attempt && !matches!(m.body, Body::Decided { .. }) {
                    n.sent.push(m.clone());
                }
            }
        }
        for m in msgs {
            for to in 0..self.pool {
                if to == from || self.rng.below(1000) < self.loss_permille {
                    continue;
                }
                let delay = 50 + self.rng.below(self.max_delay);
                self.queue.push((self.now + delay, to, m.clone()));
            }
        }
    }

    fn step(&mut self, until: u64) {
        while self.now < until {
            self.now += 100;
            let due: Vec<(u64, usize, Msg)> = {
                let (due, keep): (Vec<_>, Vec<_>) = self.queue.drain(..).partition(|(t, _, _)| *t <= self.now);
                self.queue = keep;
                due
            };
            for (_, to, m) in due {
                if !self.online[to] {
                    continue;
                }
                let before = self.decisions().len();
                let out = self.receive(to, m);
                if self.crash_first_decider && before == 0 && self.nodes[to].decided.is_some() {
                    self.online[to] = false;
                    let partner = self.nodes[to].members.iter().copied().find(|m| *m != to && self.online[*m]);
                    if let Some(p) = partner {
                        self.online[p] = false;
                    }
                    continue;
                }
                self.send(to, out);
            }
            for id in 0..self.pool {
                if !self.online[id] {
                    continue;
                }
                let now = self.now;
                let acts = match self.nodes[id].engine.as_mut() {
                    Some(e) => e.tick(now),
                    None => Vec::new(),
                };
                let mut out = self.act(id, acts);
                out.extend(self.give_up_if_due(id));
                if self.now % 2_000 == 0 {
                    let again = self.resend(id);
                    for m in again {
                        for to in 0..self.pool {
                            if to != id && self.rng.below(1000) >= self.loss_permille {
                                let delay = 50 + self.rng.below(self.max_delay);
                                self.queue.push((self.now + delay, to, m.clone()));
                            }
                        }
                    }
                }
                self.send(id, out);
            }
        }
    }

    fn decisions(&self) -> Vec<ValueId> {
        self.nodes.iter().filter_map(|n| n.decided).collect()
    }

    fn assert_one_block(&self) {
        let d = self.decisions();
        if let Some(first) = d.first() {
            assert!(d.iter().all(|v| v == first), "two different blocks were finalized at one height (seed {})", self.seed);
        }
    }
}

#[test]
fn two_offline_members_no_longer_stop_the_chain() {
    let mut finished = 0;
    for seed in 1..=40u64 {
        let mut sim = Sim::new(7, seed, 300);
        let c0 = committee(7, 0, seed);
        sim.online[c0[0]] = false;
        sim.online[c0[1]] = false;
        sim.step(400_000);
        sim.assert_one_block();
        let online_decided = (0..7).filter(|i| sim.online[*i]).all(|i| sim.nodes[i].decided.is_some());
        if online_decided {
            finished += 1;
        }
    }
    assert_eq!(finished, 40, "with five of seven nodes up every online node must finalize the height");
}

#[test]
fn crashes_and_returns_at_random_never_finalize_two_blocks() {
    for seed in 1..=150u64 {
        let mut sim = Sim::new(7, seed, 1_500);
        let mut rng = Rng(seed.wrapping_mul(31) | 1);
        for _ in 0..40 {
            let who = rng.below(7) as usize;
            sim.online[who] = !sim.online[who];
            let up = sim.online.iter().filter(|o| **o).count();
            if up < 3 {
                sim.online[who] = true;
            }
            let span = 2_000 + rng.below(20_000);
            let until = sim.now + span;
            sim.step(until);
            sim.assert_one_block();
        }
        for i in 0..7 {
            sim.online[i] = true;
        }
        sim.step(sim.now + 600_000);
        sim.assert_one_block();
        assert!(sim.nodes.iter().all(|n| n.decided.is_some()), "once everyone is back the height is finalized (seed {seed})");
    }
}

#[test]
fn a_block_finalized_just_before_the_committee_gives_up_is_the_one_kept() {
    for seed in 1..=60u64 {
        let mut sim = Sim::new(6, seed, 4_000);
        sim.step(9_000);
        let c0 = committee(6, 0, seed);
        for m in &c0[2..] {
            sim.online[*m] = false;
        }
        sim.step(300_000);
        for m in &c0[2..] {
            sim.online[*m] = true;
        }
        sim.step(sim.now + 400_000);
        sim.assert_one_block();
        assert!(sim.nodes.iter().all(|n| n.decided.is_some()), "seed {seed}");
    }
}

#[test]
fn lost_commit_votes_and_crashes_never_finalize_two_blocks() {
    let mut finished = 0;
    for seed in 1..=600u64 {
        let mut sim = Sim::new(6, seed, 2_500);
        sim.loss_permille = 600;
        let mut rng = Rng(seed.wrapping_mul(97) | 1);
        let c0 = committee(6, 0, seed);
        sim.step(4_000 + rng.below(6_000));
        let first = c0[rng.below(4) as usize];
        let second = c0[rng.below(4) as usize];
        sim.online[first] = false;
        sim.online[second] = false;
        sim.step(sim.now + 120_000);
        sim.assert_one_block();
        sim.loss_permille = 0;
        sim.online[first] = true;
        sim.online[second] = true;
        sim.step(sim.now + 400_000);
        sim.assert_one_block();
        if sim.nodes.iter().all(|n| n.decided.is_some()) {
            finished += 1;
        }
    }
    assert_eq!(finished, 600, "every height is finalized once the network heals");
}

#[test]
fn a_member_that_finalizes_and_crashes_at_once_is_never_contradicted() {
    let mut forks_possible = 0;
    for seed in 1..=800u64 {
        let mut sim = Sim::new(6, seed, 2_000);
        sim.loss_permille = 450;
        sim.crash_first_decider = true;
        sim.step(150_000);
        sim.assert_one_block();
        sim.loss_permille = 0;
        sim.step(sim.now + 400_000);
        sim.assert_one_block();
        let crashed = (0..6).filter(|i| !sim.online[*i] && sim.nodes[*i].decided.is_some()).count();
        let others = (0..6).filter(|i| sim.online[*i] && sim.nodes[*i].decided.is_some()).count();
        if crashed == 1 && others > 0 {
            forks_possible += 1;
        }
    }
    assert!(forks_possible > 50, "the scenario must actually occur often enough to mean something: {forks_possible}");
}
