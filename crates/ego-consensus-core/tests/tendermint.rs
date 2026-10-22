use ego_consensus_core::tendermint::{Action, Saved, Step, Tendermint, Timeouts, ValueId, VoteKind};
use std::collections::{BTreeMap, HashSet};

#[derive(Clone, Debug)]
enum Msg {
    Proposal { h: u64, r: u32, from: usize, v: ValueId, pol: Option<u32>, backers: Vec<usize> },
    Vote { h: u64, kind: VoteKind, r: u32, from: usize, v: Option<ValueId> },
}

impl Msg {
    fn height(&self) -> u64 {
        match self {
            Msg::Proposal { h, .. } | Msg::Vote { h, .. } => *h,
        }
    }
}

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
    fn chance(&mut self, permille: u64) -> bool {
        self.below(1000) < permille
    }
}

fn make_value(h: u64, r: u32, from: usize, salt: u64) -> ValueId {
    let mut v = [0u8; 32];
    v[..8].copy_from_slice(&h.to_le_bytes());
    v[8..12].copy_from_slice(&r.to_le_bytes());
    v[12..20].copy_from_slice(&(from as u64).to_le_bytes());
    v[20..28].copy_from_slice(&salt.to_le_bytes());
    v[31] = 1;
    v
}

fn author_of(v: &ValueId) -> usize {
    u64::from_le_bytes(v[12..20].try_into().unwrap()) as usize
}

fn fast() -> Timeouts {
    Timeouts {
        first_propose_ms: 3_000,
        propose_ms: 2_000,
        prevote_ms: 1_000,
        precommit_ms: 1_000,
        per_round_ms: 500,
        cap_ms: 10_000,
    }
}

struct Node {
    engine: Tendermint,
    height: u64,
    decided: BTreeMap<u64, ValueId>,
    future: Vec<Msg>,
    wal: Option<Saved>,
    up: bool,
    sent: Vec<Msg>,
    liar: bool,
}

type Filter = Box<dyn Fn(u64, usize, usize, &Msg) -> bool>;

struct Sim {
    members: usize,
    nodes: Vec<Node>,
    now: u64,
    queue: BTreeMap<(u64, u64), (usize, Msg)>,
    seq: u64,
    rng: Rng,
    min_delay: u64,
    max_delay: u64,
    drop_permille: u64,
    cut: HashSet<(usize, usize)>,
    filter: Option<Filter>,
    sync: bool,
    bad_author: Option<usize>,
    salt: u64,
    next_resend: u64,
    timeouts: Timeouts,
}

const START_HEIGHT: u64 = 1_000;

impl Sim {
    fn new(members: usize, observers: usize, seed: u64) -> Self {
        Self::with(members, observers, seed, None)
    }

    fn with(members: usize, observers: usize, seed: u64, bad_author: Option<usize>) -> Self {
        let timeouts = fast();
        let mut nodes = Vec::new();
        for i in 0..members + observers {
            let me = (i < members).then_some(i);
            nodes.push(Node {
                engine: Tendermint::new(START_HEIGHT, members, me, timeouts),
                height: START_HEIGHT,
                decided: BTreeMap::new(),
                future: Vec::new(),
                wal: None,
                up: true,
                sent: Vec::new(),
                liar: false,
            });
        }
        let mut sim = Sim {
            members,
            nodes,
            now: 0,
            queue: BTreeMap::new(),
            seq: 0,
            rng: Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1),
            min_delay: 5,
            max_delay: 80,
            drop_permille: 0,
            cut: HashSet::new(),
            filter: None,
            sync: true,
            bad_author,
            salt: 0,
            next_resend: 2_000,
            timeouts,
        };
        sim.start_all();
        sim
    }

    fn unstarted(members: usize, observers: usize, seed: u64) -> Self {
        let mut sim = Self::with(members, observers, seed, None);
        for n in sim.nodes.iter_mut() {
            n.engine = Tendermint::new(START_HEIGHT, members, n.engine.me(), sim.timeouts);
            n.sent.clear();
            n.wal = None;
        }
        sim.queue.clear();
        sim
    }

    fn start_all(&mut self) {
        for i in 0..self.nodes.len() {
            let now = self.now;
            let acts = self.nodes[i].engine.start(now);
            self.handle(i, acts);
        }
    }

    fn valid(&self, v: &ValueId) -> bool {
        self.bad_author.map_or(true, |b| author_of(v) != b)
    }

    fn me_of(&self, i: usize) -> Option<usize> {
        (i < self.members).then_some(i)
    }

    fn send(&mut self, from: usize, to: usize, m: Msg) {
        if from == to || !self.nodes[to].up || self.cut.contains(&(from, to)) {
            return;
        }
        if let Some(f) = &self.filter {
            if f(self.now, from, to, &m) {
                return;
            }
        }
        if self.rng.chance(self.drop_permille) {
            return;
        }
        let span = self.max_delay.saturating_sub(self.min_delay) + 1;
        let at = self.now + self.min_delay + self.rng.below(span);
        self.seq += 1;
        self.queue.insert((at, self.seq), (to, m));
    }

    fn broadcast(&mut self, from: usize, m: Msg) {
        self.nodes[from].sent.push(m.clone());
        for to in 0..self.nodes.len() {
            self.send(from, to, m.clone());
        }
    }

    fn split_broadcast(&mut self, from: usize, a: Msg, b: Msg) {
        self.nodes[from].sent.push(a.clone());
        self.nodes[from].sent.push(b.clone());
        for to in 0..self.nodes.len() {
            let m = if to % 2 == 0 { a.clone() } else { b.clone() };
            self.send(from, to, m);
        }
    }

    fn handle(&mut self, i: usize, actions: Vec<Action>) {
        let height = self.nodes[i].height;
        let mut pending = actions;
        while !pending.is_empty() {
            if self.nodes[i].height != height {
                return;
            }
            self.nodes[i].wal = Some(self.nodes[i].engine.saved());
            let acts = std::mem::take(&mut pending);
            for a in acts {
                if self.nodes[i].height != height {
                    return;
                }
                match a {
                    Action::Propose { round, pol_round, value } => {
                        self.salt += 1;
                        let v = value.unwrap_or_else(|| make_value(height, round, i, self.salt));
                        let backers = pol_round
                            .map(|vr| self.nodes[i].engine.voters_for(VoteKind::Prevote, vr, Some(v)))
                            .unwrap_or_default();
                        if self.nodes[i].liar {
                            self.salt += 1;
                            let w = make_value(height, round, i, self.salt);
                            let a = Msg::Proposal { h: height, r: round, from: i, v, pol: pol_round, backers: backers.clone() };
                            let b = Msg::Proposal { h: height, r: round, from: i, v: w, pol: pol_round, backers: Vec::new() };
                            self.split_broadcast(i, a, b);
                        } else {
                            self.broadcast(i, Msg::Proposal { h: height, r: round, from: i, v, pol: pol_round, backers });
                        }
                        let ok = self.valid(&v);
                        let now = self.now;
                        let more = self.nodes[i].engine.on_proposal(now, round, i, v, pol_round, ok);
                        pending.extend(more);
                    }
                    Action::Vote { kind, round, value } => {
                        let honest = Msg::Vote { h: height, kind, r: round, from: i, v: value };
                        if self.nodes[i].liar {
                            self.salt += 1;
                            let other = if value.is_some() { None } else { Some(make_value(height, round, i, self.salt)) };
                            let lie = Msg::Vote { h: height, kind, r: round, from: i, v: other };
                            self.split_broadcast(i, honest, lie);
                        } else {
                            self.broadcast(i, honest);
                        }
                    }
                    Action::Decide { value, .. } => {
                        self.nodes[i].decided.insert(height, value);
                        self.advance(i);
                        return;
                    }
                }
            }
        }
    }

    fn advance(&mut self, i: usize) {
        let me = self.me_of(i);
        let h = self.nodes[i].height + 1;
        self.nodes[i].height = h;
        self.nodes[i].engine = Tendermint::new(h, self.members, me, self.timeouts);
        self.nodes[i].wal = None;
        self.nodes[i].sent.clear();
        let acts = self.nodes[i].engine.start(self.now);
        self.handle(i, acts);
        let all = std::mem::take(&mut self.nodes[i].future);
        let (now_msgs, later): (Vec<Msg>, Vec<Msg>) = all.into_iter().partition(|m| m.height() == h);
        self.nodes[i].future = later.into_iter().filter(|m| m.height() > h).collect();
        for m in now_msgs {
            self.deliver(i, m);
        }
    }

    fn deliver(&mut self, i: usize, m: Msg) {
        if !self.nodes[i].up {
            return;
        }
        let h = self.nodes[i].height;
        if m.height() > h {
            if self.nodes[i].future.len() < 4_000 {
                self.nodes[i].future.push(m);
            }
            return;
        }
        if m.height() < h {
            return;
        }
        let now = self.now;
        let acts = match m {
            Msg::Proposal { r, from, v, pol, backers, .. } => {
                let mut acts = Vec::new();
                if let Some(vr) = pol {
                    for b in backers {
                        acts.extend(self.nodes[i].engine.on_vote(now, VoteKind::Prevote, vr, b, Some(v)));
                    }
                }
                let ok = self.valid(&v);
                acts.extend(self.nodes[i].engine.on_proposal(now, r, from, v, pol, ok));
                acts
            }
            Msg::Vote { kind, r, from, v, .. } => self.nodes[i].engine.on_vote(now, kind, r, from, v),
        };
        self.handle(i, acts);
    }

    fn catch_up(&mut self, i: usize) {
        if !self.sync {
            return;
        }
        loop {
            if !self.nodes[i].up {
                return;
            }
            let h = self.nodes[i].height;
            let known = self
                .nodes
                .iter()
                .enumerate()
                .filter(|(j, n)| *j != i && !n.liar)
                .find_map(|(_, n)| n.decided.get(&h).copied());
            let Some(value) = known else { return };
            self.nodes[i].decided.insert(h, value);
            self.advance(i);
        }
    }

    fn resend_all(&mut self) {
        for i in 0..self.nodes.len() {
            self.catch_up(i);
        }
        for i in 0..self.nodes.len() {
            if !self.nodes[i].up {
                continue;
            }
            let msgs = self.nodes[i].sent.clone();
            for m in msgs {
                for to in 0..self.nodes.len() {
                    self.send(i, to, m.clone());
                }
            }
        }
    }

    fn crash(&mut self, i: usize) {
        self.nodes[i].up = false;
    }

    fn restart(&mut self, i: usize) {
        if self.nodes[i].up {
            return;
        }
        let me = self.me_of(i);
        let h = self.nodes[i].height;
        let mut engine = Tendermint::new(h, self.members, me, self.timeouts);
        if let Some(w) = self.nodes[i].wal.clone() {
            engine.restore(&w);
        }
        self.nodes[i].engine = engine;
        self.nodes[i].up = true;
        let acts = self.nodes[i].engine.start(self.now);
        self.handle(i, acts);
    }

    fn run_for(&mut self, ms: u64) {
        let end = self.now + ms;
        let mut guard = 0u64;
        loop {
            guard += 1;
            assert!(guard < 5_000_000, "simulation did not settle");
            let next_msg = self.queue.keys().next().map(|k| k.0);
            let next_timer = self
                .nodes
                .iter()
                .filter(|n| n.up)
                .filter_map(|n| n.engine.next_deadline())
                .min();
            let next = [next_msg, next_timer, Some(self.next_resend)].into_iter().flatten().min().unwrap();
            if next > end {
                self.now = end;
                return;
            }
            self.now = self.now.max(next);
            if next_msg == Some(next) {
                let key = *self.queue.keys().next().unwrap();
                let (to, m) = self.queue.remove(&key).unwrap();
                self.deliver(to, m);
            } else if next_timer == Some(next) {
                for i in 0..self.nodes.len() {
                    let due = self.nodes[i].up && self.nodes[i].engine.next_deadline().map_or(false, |d| d <= self.now);
                    if due {
                        let now = self.now;
                        let acts = self.nodes[i].engine.tick(now);
                        self.handle(i, acts);
                    }
                }
            } else {
                self.resend_all();
                self.next_resend = self.now + 2_000;
            }
        }
    }

    fn assert_agreement(&self) {
        let mut seen: BTreeMap<u64, (usize, ValueId)> = BTreeMap::new();
        for (i, n) in self.nodes.iter().enumerate() {
            if n.liar {
                continue;
            }
            for (h, v) in &n.decided {
                match seen.get(h) {
                    Some((j, w)) => assert_eq!(v, w, "FORK at height {h}: node {i} and node {j} finalized different blocks"),
                    None => {
                        seen.insert(*h, (i, *v));
                    }
                }
            }
        }
    }

    fn min_height(&self) -> u64 {
        self.nodes
            .iter()
            .filter(|n| !n.liar && n.up)
            .map(|n| n.height)
            .min()
            .unwrap_or(START_HEIGHT)
    }

    fn max_decided(&self) -> u64 {
        self.nodes
            .iter()
            .filter(|n| !n.liar)
            .flat_map(|n| n.decided.keys().copied())
            .max()
            .unwrap_or(START_HEIGHT - 1)
    }
}

#[test]
fn three_nodes_make_blocks_and_agree() {
    let mut sim = Sim::new(3, 1, 1);
    sim.run_for(60_000);
    sim.assert_agreement();
    assert!(sim.min_height() >= START_HEIGHT + 20, "three healthy nodes stalled at {}", sim.min_height());
}

#[test]
fn larger_committees_agree_under_delay_and_loss() {
    for n in [4usize, 5, 7] {
        for seed in 1..6u64 {
            let mut sim = Sim::new(n, 2, seed * 31 + n as u64);
            sim.max_delay = 1_500;
            sim.drop_permille = 150;
            sim.run_for(180_000);
            sim.assert_agreement();
            assert!(
                sim.min_height() >= START_HEIGHT + 3,
                "n={n} seed={seed}: stalled at {} under ordinary delay and loss",
                sim.min_height()
            );
        }
    }
}

#[test]
fn one_dead_member_of_four_does_not_stop_the_chain() {
    for dead in 0..4usize {
        let mut sim = Sim::new(4, 1, 7 + dead as u64);
        sim.crash(dead);
        sim.run_for(120_000);
        sim.assert_agreement();
        let alive_min = sim
            .nodes
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != dead)
            .map(|(_, n)| n.height)
            .min()
            .unwrap();
        assert!(alive_min >= START_HEIGHT + 5, "member {dead} down: chain stalled at {alive_min}");
    }
}

#[test]
fn three_nodes_need_all_three_and_resume_when_the_third_returns() {
    let mut sim = Sim::new(3, 1, 11);
    sim.run_for(5_000);
    sim.crash(2);
    let before = sim.max_decided();
    sim.run_for(90_000);
    sim.assert_agreement();
    assert!(
        sim.max_decided() <= before + 1,
        "two of three nodes kept finalizing: {} -> {}",
        before,
        sim.max_decided()
    );
    sim.restart(2);
    sim.run_for(90_000);
    sim.assert_agreement();
    assert!(sim.max_decided() >= before + 5, "the chain did not resume after the third node returned");
}

#[test]
fn no_two_blocks_at_one_height_under_random_faults() {
    for n in [3usize, 4, 5, 7] {
        for seed in 1..25u64 {
            let mut sim = Sim::new(n, 2, seed * 1_009 + n as u64 * 7);
            sim.max_delay = 3_000;
            sim.drop_permille = 250;
            let mut crashed: Option<usize> = None;
            for _ in 0..30 {
                sim.cut.clear();
                for a in 0..sim.nodes.len() {
                    for b in 0..sim.nodes.len() {
                        if a != b && sim.rng.chance(250) {
                            sim.cut.insert((a, b));
                        }
                    }
                }
                if let Some(c) = crashed.take() {
                    sim.restart(c);
                } else if sim.rng.chance(300) {
                    let c = sim.rng.below(n as u64) as usize;
                    sim.crash(c);
                    crashed = Some(c);
                }
                let span = 1_000 + sim.rng.below(6_000);
                sim.run_for(span);
                sim.assert_agreement();
            }
            if let Some(c) = crashed.take() {
                sim.restart(c);
            }
            sim.cut.clear();
            sim.drop_permille = 0;
            sim.max_delay = 200;
            let healed_from = sim.max_decided();
            sim.run_for(120_000);
            sim.assert_agreement();
            assert!(
                sim.max_decided() >= healed_from + 2,
                "n={n} seed={seed}: no progress after the network healed (stuck at {})",
                sim.max_decided()
            );
        }
    }
}

#[test]
fn a_lying_member_cannot_split_a_committee_of_four() {
    for seed in 1..40u64 {
        let mut sim = Sim::new(4, 2, seed * 97);
        let liar = (seed % 4) as usize;
        sim.nodes[liar].liar = true;
        sim.max_delay = 2_000;
        sim.drop_permille = 100;
        sim.run_for(150_000);
        sim.assert_agreement();
        assert!(sim.min_height() >= START_HEIGHT + 2, "seed={seed}: three honest members stalled");
    }
}

#[test]
fn a_lying_member_cannot_split_a_committee_of_seven() {
    for seed in 1..15u64 {
        let mut sim = Sim::new(7, 2, seed * 131);
        sim.nodes[(seed % 7) as usize].liar = true;
        sim.nodes[((seed + 3) % 7) as usize].liar = true;
        sim.max_delay = 2_000;
        sim.drop_permille = 100;
        sim.run_for(150_000);
        sim.assert_agreement();
    }
}

#[test]
fn members_who_lose_each_others_precommits_still_finalize_the_same_block_as_an_observer() {
    let mut sim = Sim::new(4, 1, 5);
    sim.sync = false;
    let observer = 4usize;
    sim.filter = Some(Box::new(move |now, from, to, m| {
        now < 40_000
            && from < 4
            && to < 4
            && matches!(m, Msg::Vote { kind: VoteKind::Precommit, h, .. } if *h == START_HEIGHT)
    }));
    sim.run_for(30_000);
    assert!(
        sim.nodes[observer].decided.contains_key(&START_HEIGHT),
        "the observer saw every precommit and should have finalized"
    );
    for i in 0..4 {
        assert!(!sim.nodes[i].decided.contains_key(&START_HEIGHT), "member {i} could not have seen a quorum yet");
    }
    sim.run_for(60_000);
    sim.assert_agreement();
    let first = sim.nodes[observer].decided[&START_HEIGHT];
    for i in 0..4 {
        assert_eq!(sim.nodes[i].decided.get(&START_HEIGHT), Some(&first), "member {i} finalized another block");
    }
}

fn v(tag: u8) -> ValueId {
    let mut x = [0u8; 32];
    x[0] = tag;
    x
}

#[test]
fn a_restarted_member_keeps_its_lock_and_refuses_a_new_block() {
    let height = 10u64;
    let mut e = Tendermint::new(height, 4, Some(1), fast());
    e.start(0);
    let p0 = e.proposer(0);
    let acts = e.on_proposal(1, 0, p0, v(1), None, true);
    assert!(acts.contains(&Action::Vote { kind: VoteKind::Prevote, round: 0, value: Some(v(1)) }));
    e.on_vote(2, VoteKind::Prevote, 0, 0, Some(v(1)));
    let acts = e.on_vote(3, VoteKind::Prevote, 0, 2, Some(v(1)));
    assert!(acts.contains(&Action::Vote { kind: VoteKind::Precommit, round: 0, value: Some(v(1)) }));
    assert_eq!(e.locked(), Some((0, v(1))));
    let saved = e.saved();

    let mut back = Tendermint::new(height, 4, Some(1), fast());
    back.restore(&saved);
    let acts = back.start(100);
    assert!(acts.iter().all(|a| !matches!(a, Action::Vote { .. })), "a restart must not vote again: {acts:?}");
    let acts = back.on_proposal(101, 0, p0, v(2), None, true);
    assert!(acts.is_empty(), "a second block at the same round must be ignored after a restart: {acts:?}");
    assert_eq!(back.locked(), Some((0, v(1))));

    back.on_vote(200, VoteKind::Prevote, 1, 0, None);
    back.on_vote(201, VoteKind::Prevote, 1, 2, None);
    assert_eq!(back.round(), 1);
    let p1 = back.proposer(1);
    if p1 != 1 {
        let acts = back.on_proposal(202, 1, p1, v(3), None, true);
        assert!(
            acts.contains(&Action::Vote { kind: VoteKind::Prevote, round: 1, value: None }),
            "a member locked on one block must not prevote a different one: {acts:?}"
        );
    }
}

#[test]
fn the_next_proposer_offers_the_block_the_committee_already_backed() {
    let height = 20u64;
    let me = ((height + 1) % 4) as usize;
    let mut e = Tendermint::new(height, 4, Some(me), fast());
    e.start(0);
    let p0 = e.proposer(0);
    e.on_proposal(1, 0, p0, v(7), None, true);
    let others: Vec<usize> = (0..4).filter(|i| *i != me).collect();
    e.on_vote(2, VoteKind::Prevote, 0, others[0], Some(v(7)));
    e.on_vote(3, VoteKind::Prevote, 0, others[1], Some(v(7)));
    assert_eq!(e.valid_value(), Some((0, v(7))));
    e.on_vote(4, VoteKind::Precommit, 0, others[0], None);
    e.on_vote(5, VoteKind::Precommit, 0, others[1], None);
    let acts = e.tick(60_000);
    assert!(
        acts.contains(&Action::Propose { round: 1, pol_round: Some(0), value: Some(v(7)) }),
        "the round-1 proposer must offer the backed block again, got {acts:?}"
    );
}

#[test]
fn an_observer_only_finalizes_on_a_quorum_of_precommits() {
    let mut e = Tendermint::new(5, 4, None, fast());
    assert!(e.start(0).is_empty());
    e.on_proposal(1, 0, e.proposer(0), v(9), None, true);
    e.on_vote(2, VoteKind::Precommit, 0, 0, Some(v(9)));
    let acts = e.on_vote(3, VoteKind::Precommit, 0, 1, Some(v(9)));
    assert!(acts.is_empty());
    let acts = e.on_vote(4, VoteKind::Precommit, 0, 2, Some(v(9)));
    assert_eq!(acts, vec![Action::Decide { round: 0, value: v(9) }]);
    assert_eq!(e.step(), Step::Propose);
}

#[test]
fn blocks_judged_invalid_are_never_finalized() {
    for bad in 0..4usize {
        let mut sim = Sim::with(4, 1, 3 + bad as u64, Some(bad));
        sim.run_for(60_000);
        sim.assert_agreement();
        for n in &sim.nodes {
            for d in n.decided.values() {
                assert_ne!(author_of(d), bad, "a block the committee judged invalid was finalized");
            }
        }
        assert!(sim.min_height() >= START_HEIGHT + 3, "the honest proposers should keep the chain going");
    }
}

#[test]
fn the_split_at_32939_cannot_happen() {
    let mut sim = Sim::unstarted(4, 1, 9);
    sim.sync = false;
    let observer = 4usize;
    assert_eq!(sim.nodes[0].engine.proposer(0), 0);
    assert_eq!(sim.nodes[0].engine.proposer(1), 1);
    let ring = |from: usize, to: usize| matches!((from, to), (2, 0) | (3, 2) | (0, 3) | (0, 1) | (2, 1));
    sim.filter = Some(Box::new(move |_, from, to, m| match m {
        Msg::Proposal { h, r: 0, .. } => *h == START_HEIGHT && to == 1,
        Msg::Vote { h, kind: VoteKind::Precommit, r: 0, v: Some(_), .. } => {
            *h == START_HEIGHT && from < 4 && to < 4 && !ring(from, to)
        }
        _ => false,
    }));
    sim.start_all();
    sim.run_for(2_000);
    let first = *sim.nodes[observer]
        .decided
        .get(&START_HEIGHT)
        .expect("the observer saw three commit votes for the first block");
    for i in 0..4 {
        assert!(!sim.nodes[i].decided.contains_key(&START_HEIGHT), "member {i} saw only two commit votes");
    }
    sim.run_for(120_000);
    sim.assert_agreement();
    for i in 0..4 {
        assert_eq!(
            sim.nodes[i].decided.get(&START_HEIGHT),
            Some(&first),
            "member {i} finalized a different block than the observer"
        );
    }
}
