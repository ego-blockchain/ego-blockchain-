use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

pub type ValueId = [u8; 32];

pub const ROUND_WINDOW: u32 = 64;
pub const VALUES_PER_VOTER: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Step {
    Propose,
    Prevote,
    Precommit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum VoteKind {
    Prevote,
    Precommit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Timer {
    Propose,
    Prevote,
    Precommit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Propose { round: u32, pol_round: Option<u32>, value: Option<ValueId> },
    Vote { kind: VoteKind, round: u32, value: Option<ValueId> },
    Decide { round: u32, value: ValueId },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeouts {
    pub first_propose_ms: u64,
    pub propose_ms: u64,
    pub prevote_ms: u64,
    pub precommit_ms: u64,
    pub per_round_ms: u64,
    pub cap_ms: u64,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            first_propose_ms: 15_000,
            propose_ms: 6_000,
            prevote_ms: 3_000,
            precommit_ms: 3_000,
            per_round_ms: 1_000,
            cap_ms: 60_000,
        }
    }
}

impl Timeouts {
    fn of(&self, timer: Timer, round: u32) -> u64 {
        let base = match timer {
            Timer::Propose if round == 0 => self.first_propose_ms,
            Timer::Propose => self.propose_ms,
            Timer::Prevote => self.prevote_ms,
            Timer::Precommit => self.precommit_ms,
        };
        base.saturating_add(self.per_round_ms.saturating_mul(round as u64))
            .min(self.cap_ms.max(base))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Saved {
    pub height: u64,
    pub round: u32,
    pub step: Step,
    pub locked: Option<(u32, ValueId)>,
    pub valid: Option<(u32, ValueId)>,
    pub sent: Vec<(u32, VoteKind, Option<ValueId>)>,
}

pub fn quorum(n: usize) -> usize {
    2 * n / 3 + 1
}

pub fn skip_threshold(n: usize) -> usize {
    n.saturating_sub(quorum(n)) + 1
}

type Book = BTreeMap<u32, HashMap<usize, Vec<Option<ValueId>>>>;

fn record(book: &mut Book, round: u32, from: usize, value: Option<ValueId>) {
    let list = book.entry(round).or_default().entry(from).or_default();
    if !list.contains(&value) && list.len() < VALUES_PER_VOTER {
        list.push(value);
    }
}

pub struct Tendermint {
    height: u64,
    n: usize,
    me: Option<usize>,
    timeouts: Timeouts,
    round: u32,
    step: Step,
    locked: Option<(u32, ValueId)>,
    valid: Option<(u32, ValueId)>,
    proposals: HashMap<u32, (ValueId, Option<u32>)>,
    validity: HashMap<ValueId, bool>,
    prevotes: Book,
    precommits: Book,
    highest: HashMap<usize, u32>,
    sent: HashMap<(u32, VoteKind), Option<ValueId>>,
    timers: Vec<(Timer, u32, u64)>,
    armed: HashSet<(Timer, u32)>,
    polka_done: HashSet<u32>,
    decision: Option<(u32, ValueId)>,
    started: bool,
    resumed: bool,
}

impl Tendermint {
    pub fn new(height: u64, n: usize, me: Option<usize>, timeouts: Timeouts) -> Self {
        Self {
            height,
            n,
            me: me.filter(|i| *i < n),
            timeouts,
            round: 0,
            step: Step::Propose,
            locked: None,
            valid: None,
            proposals: HashMap::new(),
            validity: HashMap::new(),
            prevotes: BTreeMap::new(),
            precommits: BTreeMap::new(),
            highest: HashMap::new(),
            sent: HashMap::new(),
            timers: Vec::new(),
            armed: HashSet::new(),
            polka_done: HashSet::new(),
            decision: None,
            started: false,
            resumed: false,
        }
    }

    pub fn restore(&mut self, saved: &Saved) {
        if saved.height != self.height || self.started {
            return;
        }
        self.round = saved.round;
        self.step = saved.step;
        self.locked = saved.locked;
        self.valid = saved.valid;
        for (round, kind, value) in &saved.sent {
            self.sent.insert((*round, *kind), *value);
            if let Some(me) = self.me {
                record(self.book_mut(*kind), *round, me, *value);
            }
        }
        self.resumed = true;
    }

    pub fn saved(&self) -> Saved {
        let mut sent: Vec<(u32, VoteKind, Option<ValueId>)> =
            self.sent.iter().map(|((r, k), v)| (*r, *k, *v)).collect();
        sent.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
        Saved {
            height: self.height,
            round: self.round,
            step: self.step,
            locked: self.locked,
            valid: self.valid,
            sent,
        }
    }

    pub fn height(&self) -> u64 {
        self.height
    }

    pub fn round(&self) -> u32 {
        self.round
    }

    pub fn step(&self) -> Step {
        self.step
    }

    pub fn locked(&self) -> Option<(u32, ValueId)> {
        self.locked
    }

    pub fn valid_value(&self) -> Option<(u32, ValueId)> {
        self.valid
    }

    pub fn decision(&self) -> Option<(u32, ValueId)> {
        self.decision
    }

    pub fn size(&self) -> usize {
        self.n
    }

    pub fn me(&self) -> Option<usize> {
        self.me
    }

    pub fn quorum(&self) -> usize {
        quorum(self.n)
    }

    pub fn proposer(&self, round: u32) -> usize {
        if self.n == 0 {
            return 0;
        }
        (self.height.wrapping_add(round as u64) % self.n as u64) as usize
    }

    pub fn next_deadline(&self) -> Option<u64> {
        self.timers.iter().map(|t| t.2).min()
    }

    pub fn votes_for(&self, kind: VoteKind, round: u32, value: Option<ValueId>) -> usize {
        self.count(kind, round, value)
    }

    pub fn voters_for(&self, kind: VoteKind, round: u32, value: Option<ValueId>) -> Vec<usize> {
        let mut out: Vec<usize> = self
            .book(kind)
            .get(&round)
            .map(|m| m.iter().filter(|(_, l)| l.contains(&value)).map(|(w, _)| *w).collect())
            .unwrap_or_default();
        out.sort_unstable();
        out
    }

    pub fn start(&mut self, now: u64) -> Vec<Action> {
        let mut out = Vec::new();
        if self.started {
            return out;
        }
        self.started = true;
        if self.me.is_some() && self.n > 0 {
            match (self.resumed, self.step) {
                (false, _) | (true, Step::Propose) => self.start_round(now, self.round, &mut out),
                (true, Step::Prevote) => self.arm(Timer::Prevote, self.round, now),
                (true, Step::Precommit) => self.arm(Timer::Precommit, self.round, now),
            }
        }
        self.progress(now, &mut out);
        out
    }

    pub fn on_proposal(
        &mut self,
        now: u64,
        round: u32,
        from: usize,
        value: ValueId,
        pol_round: Option<u32>,
        valid: bool,
    ) -> Vec<Action> {
        let mut out = Vec::new();
        let in_window = round <= self.round.saturating_add(ROUND_WINDOW);
        if from < self.n && from == self.proposer(round) && pol_round.map_or(true, |p| p < round) && in_window {
            self.proposals.entry(round).or_insert((value, pol_round));
            self.validity.entry(value).or_insert(valid);
            self.note_round(from, round);
        }
        self.progress(now, &mut out);
        out
    }

    pub fn on_value(&mut self, now: u64, value: ValueId, valid: bool) -> Vec<Action> {
        let mut out = Vec::new();
        self.validity.entry(value).or_insert(valid);
        self.progress(now, &mut out);
        out
    }

    pub fn on_vote(
        &mut self,
        now: u64,
        kind: VoteKind,
        round: u32,
        from: usize,
        value: Option<ValueId>,
    ) -> Vec<Action> {
        let mut out = Vec::new();
        if from < self.n && Some(from) != self.me {
            self.note_round(from, round);
            if round <= self.round.saturating_add(ROUND_WINDOW) {
                record(self.book_mut(kind), round, from, value);
            }
        }
        self.progress(now, &mut out);
        out
    }

    pub fn tick(&mut self, now: u64) -> Vec<Action> {
        let mut out = Vec::new();
        let mut due: Vec<(Timer, u32, u64)> = Vec::new();
        let mut keep: Vec<(Timer, u32, u64)> = Vec::new();
        for t in self.timers.drain(..) {
            if t.2 <= now {
                due.push(t);
            } else {
                keep.push(t);
            }
        }
        self.timers = keep;
        due.sort_by_key(|t| (t.2, t.1));
        for (timer, round, _) in due {
            if self.decision.is_some() {
                break;
            }
            match timer {
                Timer::Propose => {
                    if self.round == round && self.step == Step::Propose {
                        self.cast(VoteKind::Prevote, None, &mut out);
                        self.step = Step::Prevote;
                    }
                }
                Timer::Prevote => {
                    if self.round == round && self.step == Step::Prevote {
                        self.cast(VoteKind::Precommit, None, &mut out);
                        self.step = Step::Precommit;
                    }
                }
                Timer::Precommit => {
                    if self.round == round {
                        self.start_round(now, round.saturating_add(1), &mut out);
                    }
                }
            }
            self.progress(now, &mut out);
        }
        self.progress(now, &mut out);
        out
    }

    fn note_round(&mut self, from: usize, round: u32) {
        let e = self.highest.entry(from).or_insert(round);
        if round > *e {
            *e = round;
        }
    }

    fn book(&self, kind: VoteKind) -> &Book {
        match kind {
            VoteKind::Prevote => &self.prevotes,
            VoteKind::Precommit => &self.precommits,
        }
    }

    fn book_mut(&mut self, kind: VoteKind) -> &mut Book {
        match kind {
            VoteKind::Prevote => &mut self.prevotes,
            VoteKind::Precommit => &mut self.precommits,
        }
    }

    fn count(&self, kind: VoteKind, round: u32, value: Option<ValueId>) -> usize {
        self.book(kind)
            .get(&round)
            .map_or(0, |m| m.values().filter(|l| l.contains(&value)).count())
    }

    fn count_any(&self, kind: VoteKind, round: u32) -> usize {
        self.book(kind).get(&round).map_or(0, |m| m.len())
    }

    fn value_with_quorum(&self, kind: VoteKind, round: u32) -> Option<ValueId> {
        let m = self.book(kind).get(&round)?;
        let mut tally: HashMap<ValueId, usize> = HashMap::new();
        for list in m.values() {
            for v in list.iter().flatten() {
                *tally.entry(*v).or_default() += 1;
            }
        }
        let q = self.quorum();
        tally.into_iter().find(|(_, c)| *c >= q).map(|(v, _)| v)
    }

    fn find_decision(&self) -> Option<(u32, ValueId)> {
        for round in self.precommits.keys() {
            if let Some(v) = self.value_with_quorum(VoteKind::Precommit, *round) {
                if self.validity.get(&v) == Some(&true) {
                    return Some((*round, v));
                }
            }
        }
        None
    }

    fn skip_target(&self) -> Option<u32> {
        let mut rounds: Vec<u32> = self
            .highest
            .iter()
            .filter(|(who, _)| Some(**who) != self.me)
            .map(|(_, r)| *r)
            .collect();
        rounds.sort_unstable_by(|a, b| b.cmp(a));
        let target = *rounds.get(skip_threshold(self.n).saturating_sub(1))?;
        (target > self.round).then_some(target)
    }

    fn arm(&mut self, timer: Timer, round: u32, now: u64) {
        if self.armed.insert((timer, round)) {
            let at = now.saturating_add(self.timeouts.of(timer, round));
            self.timers.push((timer, round, at));
        }
    }

    fn start_round(&mut self, now: u64, round: u32, out: &mut Vec<Action>) {
        self.round = round;
        self.step = Step::Propose;
        if Some(self.proposer(round)) == self.me && !self.sent.contains_key(&(round, VoteKind::Prevote)) {
            out.push(Action::Propose {
                round,
                pol_round: self.valid.map(|(r, _)| r),
                value: self.valid.map(|(_, v)| v),
            });
        }
        self.arm(Timer::Propose, round, now);
    }

    fn cast(&mut self, kind: VoteKind, value: Option<ValueId>, out: &mut Vec<Action>) {
        let Some(me) = self.me else { return };
        let round = self.round;
        if self.sent.contains_key(&(round, kind)) {
            return;
        }
        self.sent.insert((round, kind), value);
        record(self.book_mut(kind), round, me, value);
        out.push(Action::Vote { kind, round, value });
    }

    fn progress(&mut self, now: u64, out: &mut Vec<Action>) {
        loop {
            if self.decision.is_none() {
                if let Some(d) = self.find_decision() {
                    self.decision = Some(d);
                    self.timers.clear();
                    out.push(Action::Decide { round: d.0, value: d.1 });
                }
            }
            if self.decision.is_some() || self.me.is_none() || !self.started || self.n == 0 {
                return;
            }
            if let Some(r) = self.skip_target() {
                self.start_round(now, r, out);
                continue;
            }
            let q = self.quorum();
            let round = self.round;
            if self.step == Step::Propose {
                if let Some((v, pol)) = self.proposals.get(&round).copied() {
                    if let Some(ok) = self.validity.get(&v).copied() {
                        let verdict = match pol {
                            None => Some(ok && self.locked.map_or(true, |(_, lv)| lv == v)),
                            Some(vr) if self.count(VoteKind::Prevote, vr, Some(v)) >= q => {
                                Some(ok && self.locked.map_or(true, |(lr, lv)| lr <= vr || lv == v))
                            }
                            Some(_) => None,
                        };
                        if let Some(accept) = verdict {
                            self.cast(VoteKind::Prevote, accept.then_some(v), out);
                            self.step = Step::Prevote;
                            continue;
                        }
                    }
                }
            }
            if self.step == Step::Prevote && self.count_any(VoteKind::Prevote, round) >= q {
                self.arm(Timer::Prevote, round, now);
            }
            if self.step != Step::Propose && !self.polka_done.contains(&round) {
                if let Some(v) = self.value_with_quorum(VoteKind::Prevote, round) {
                    if self.validity.get(&v) == Some(&true) {
                        self.polka_done.insert(round);
                        if self.step == Step::Prevote {
                            self.locked = Some((round, v));
                            self.cast(VoteKind::Precommit, Some(v), out);
                            self.step = Step::Precommit;
                        }
                        self.valid = Some((round, v));
                        continue;
                    }
                }
            }
            if self.step == Step::Prevote && self.count(VoteKind::Prevote, round, None) >= q {
                self.cast(VoteKind::Precommit, None, out);
                self.step = Step::Precommit;
                continue;
            }
            if self.count_any(VoteKind::Precommit, round) >= q {
                self.arm(Timer::Precommit, round, now);
            }
            return;
        }
    }
}
