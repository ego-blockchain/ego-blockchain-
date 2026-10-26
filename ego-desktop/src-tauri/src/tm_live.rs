use crate::chain_db::{
    attempt_of, compact_skip, extended_attempts_at, quorum_of, skip_threshold_of, tm_proposal_message_at, tm_signature_ok,
    tm_skip_message, tm_skip_message_v2, tm_value_id, tm_vote_message_at, SkipChain, TmCert, TmLock, TmSkipCert, TmSkipVote, TM_CERT_V4, TM_CERT_VERSION, TM_MAX_ATTEMPT, TM_PRECOMMIT, TM_PREVOTE,
};
use crate::ledger::{LedgerBlock, LedgerTx};
use crate::p2p::P2PMessage;
use ego_consensus_core::tendermint::{Action, Saved, Step, Tendermint, Timeouts, ValueId, VoteKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Instant;

const RESEND_MS: u64 = 2_000;
const STATUS_MS: u64 = 15_000;
const FUTURE_HEIGHTS: u64 = 4;
const FUTURE_MAX: usize = 512;
const LATER_MAX: usize = 256;
const WAL_FILE: &str = "consensus_wal.json";
const V2_LOCK_SECS: i64 = 90;
const V2_LOCK_KEEP: u64 = 200;
const GIVE_UP_AFTER_MS: u64 = 30_000;
const GIVE_UP_STEP_MS: u64 = 10_000;
const GIVE_UP_CAP_MS: u64 = 90_000;
const ABSENT_GIVE_UP_MS: u64 = 10_000;
const SILENT_AFTER_MS: u64 = 20_000;
const HEARD_WITHIN_MS: u64 = 60_000;
const ANNOUNCED_WITHIN_SECS: i64 = 100;
const LAST_HEARD_MAX: usize = 1_024;
const SILENT_KEEP_MS: u64 = 600_000;
const SKIPS_RESEND_MS: u64 = 10_000;
const REPLACEMENT_VERSION: &str = "0.3.646";
const LIVE_WITHIN_SECS: i64 = 900;
const LOOKAHEAD: u32 = 6;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Via {
    Both,
    Direct,
    Gossip,
}

type Out = Vec<(P2PMessage, Via)>;
type Payload = (LedgerBlock, Vec<LedgerTx>);

fn mono_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

static LAST_HEARD: Mutex<BTreeMap<String, u64>> = Mutex::new(BTreeMap::new());

fn note_heard(addr: &str, now: u64) {
    let mut g = LAST_HEARD.lock().unwrap_or_else(|e| e.into_inner());
    if g.len() >= LAST_HEARD_MAX && !g.contains_key(addr) {
        g.retain(|_, at| now.saturating_sub(*at) < HEARD_WITHIN_MS);
        if g.len() >= LAST_HEARD_MAX {
            return;
        }
    }
    g.insert(addr.to_string(), now);
}

fn heard_within(addr: &str, now: u64) -> bool {
    LAST_HEARD
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(addr)
        .map_or(false, |at| now.saturating_sub(*at) < HEARD_WITHIN_MS)
}

static SILENT: Mutex<BTreeMap<String, u64>> = Mutex::new(BTreeMap::new());

fn mark_silent(addr: &str, now: u64) -> bool {
    let mut g = SILENT.lock().unwrap_or_else(|e| e.into_inner());
    g.retain(|_, at| now.saturating_sub(*at) < SILENT_KEEP_MS);
    if g.len() >= LAST_HEARD_MAX {
        return false;
    }
    g.insert(addr.to_string(), now).is_none()
}

fn clear_silent(addr: &str) {
    SILENT.lock().unwrap_or_else(|e| e.into_inner()).remove(addr);
}

fn is_silent(addr: &str, now: u64) -> bool {
    SILENT
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(addr)
        .map_or(false, |at| now.saturating_sub(*at) < SILENT_KEEP_MS)
}

fn present_in(members: &[(String, Vec<u8>)], me: &str, silent: impl Fn(&str) -> bool, live: impl Fn(&str) -> bool) -> usize {
    members
        .iter()
        .filter(|(a, _)| a == me || (!silent(a) && live(a)))
        .count()
}

fn give_up_after(attempt: u32) -> u64 {
    GIVE_UP_AFTER_MS
        .saturating_add(GIVE_UP_STEP_MS.saturating_mul(attempt as u64))
        .min(GIVE_UP_CAP_MS)
}

fn code_of(kind: VoteKind) -> u8 {
    match kind {
        VoteKind::Prevote => TM_PREVOTE,
        VoteKind::Precommit => TM_PRECOMMIT,
    }
}

fn kind_of(code: u8) -> Option<VoteKind> {
    match code {
        TM_PREVOTE => Some(VoteKind::Prevote),
        TM_PRECOMMIT => Some(VoteKind::Precommit),
        _ => None,
    }
}

#[derive(Serialize, Deserialize, Default)]
struct Wal {
    #[serde(default)]
    tm: Option<Saved>,
    #[serde(default)]
    tm_parent: String,
    #[serde(default)]
    tm_attempt: u32,
    #[serde(default)]
    tm_skips: Vec<TmSkipCert>,
    #[serde(default)]
    tm_gave_up: Option<TmSkipVote>,
    #[serde(default)]
    tm_lock_pol: Option<TmLock>,
    #[serde(default)]
    tm_lock_block: Option<Payload>,
    #[serde(default)]
    v2: BTreeMap<u64, (String, i64)>,
}

static WAL: Mutex<Option<Wal>> = Mutex::new(None);

fn wal_path() -> std::path::PathBuf {
    crate::ledger::data_dir().join(WAL_FILE)
}

fn wal() -> MutexGuard<'static, Option<Wal>> {
    let mut g = WAL.lock().unwrap_or_else(|e| e.into_inner());
    if g.is_none() {
        let loaded = std::fs::read(wal_path())
            .ok()
            .and_then(|b| serde_json::from_slice::<Wal>(&b).ok())
            .unwrap_or_default();
        *g = Some(loaded);
    }
    g
}

fn wal_store(w: &Wal) {
    match serde_json::to_vec(w) {
        Ok(bytes) => {
            if let Err(e) = crate::utils::atomic_write(&wal_path(), &bytes) {
                eprintln!("[Consensus] could not save the vote record: {e}");
            }
        }
        Err(e) => eprintln!("[Consensus] could not encode the vote record: {e}"),
    }
}

pub fn v2_vote_guarded<T>(height: u64, hash: &str, vote: impl FnOnce() -> Option<T>) -> Option<T> {
    let mut g = wal();
    let w = g.get_or_insert_with(Wal::default);
    let now = chrono::Utc::now().timestamp();
    if let Some((earlier, at)) = w.v2.get(&height) {
        if earlier != hash && now - at < V2_LOCK_SECS {
            eprintln!(
                "[ConsensusV2/LIVE] not voting for #{height} block {:.12}: this node voted for block {:.12} at this height {}s ago",
                hash,
                earlier,
                now - at
            );
            return None;
        }
    }
    let cast = vote();
    if cast.is_some() {
        let keep = w.v2.get(&height).map_or(false, |(earlier, _)| earlier == hash);
        if !keep {
            w.v2.insert(height, (hash.to_string(), now));
        }
        w.v2.retain(|h, _| h.saturating_add(V2_LOCK_KEEP) >= height);
        wal_store(w);
    }
    cast
}

fn signer() -> Option<Arc<ego_core::KeyPair>> {
    static KP: Mutex<Option<([u8; 32], Arc<ego_core::KeyPair>)>> = Mutex::new(None);
    let seed = crate::p2p::get_ed25519_seed()?;
    let mut g = KP.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((s, kp)) = g.as_ref() {
        if *s == seed {
            return Some(kp.clone());
        }
    }
    let kp = Arc::new(ego_core::KeyPair::from_bytes(&seed).ok()?);
    *g = Some((seed, kp.clone()));
    Some(kp)
}

fn sign(kp: &ego_core::KeyPair, msg: &[u8]) -> String {
    crate::chain_db::encode_vote_sig(&kp.sign_dilithium(msg).signature_data)
}

fn short(a: &str) -> &str {
    a.get(..14).unwrap_or(a)
}

struct Waiting {
    round: u32,
    from: usize,
    value: ValueId,
    pol_round: Option<u32>,
}

struct Driver {
    height: u64,
    parent_hash: String,
    parent_ts: i64,
    attempt: u32,
    skips: Vec<TmSkipCert>,
    members: Vec<(String, Vec<u8>)>,
    miners: Vec<String>,
    me: Option<usize>,
    me_addr: String,
    kp: Option<Arc<ego_core::KeyPair>>,
    engine: Tendermint,
    names: HashMap<ValueId, String>,
    payloads: HashMap<ValueId, Payload>,
    proposal_msgs: HashMap<ValueId, P2PMessage>,
    verdicts: HashMap<ValueId, bool>,
    checking: HashSet<ValueId>,
    waiting: Vec<Waiting>,
    sigs: HashMap<(u8, u32, ValueId), BTreeMap<usize, String>>,
    my_votes: BTreeMap<(u32, u8), P2PMessage>,
    my_proposals: BTreeMap<u32, P2PMessage>,
    pending_propose: Option<u32>,
    building: bool,
    decided: Option<(u32, ValueId)>,
    committing: bool,
    gave_up: Option<TmSkipVote>,
    give_ups: BTreeMap<String, TmSkipVote>,
    lock_pol: Option<TmLock>,
    advancing: bool,
    later: Vec<P2PMessage>,
    attempt_started: u64,
    last_resend: u64,
    last_skips_resend: u64,
    last_status: u64,
    last_progress: u64,
    said_cannot_give_up: bool,
    said_no_replacement: bool,
    caught_up: HashMap<u32, u64>,
    heard: HashSet<usize>,
    seen_at_height: HashSet<String>,
    carried: Option<TmLock>,
}

static DRIVER: Mutex<Option<Driver>> = Mutex::new(None);
static FUTURE: Mutex<BTreeMap<u64, Vec<P2PMessage>>> = Mutex::new(BTreeMap::new());
static GROUP: Mutex<Option<(u64, Vec<String>)>> = Mutex::new(None);

fn driver() -> MutexGuard<'static, Option<Driver>> {
    DRIVER.lock().unwrap_or_else(|e| e.into_inner())
}

fn future() -> MutexGuard<'static, BTreeMap<u64, Vec<P2PMessage>>> {
    FUTURE.lock().unwrap_or_else(|e| e.into_inner())
}

fn seat(members: &[(String, Vec<u8>)], me_addr: &str, kp: &Option<Arc<ego_core::KeyPair>>, height: u64) -> Option<usize> {
    let i = members.iter().position(|(a, _)| a == me_addr)?;
    let matches = kp.as_ref().map_or(false, |k| k.dilithium_public_key().key_data == members[i].1);
    if !matches {
        eprintln!("[Consensus] h={height}: this node is on the committee but its signing key is not the one registered on chain, so it only follows");
        return None;
    }
    Some(i)
}

fn able(addr: &str, me: &str) -> bool {
    addr == me || crate::commands::updates::runs_at_least(addr, REPLACEMENT_VERSION, LIVE_WITHIN_SECS)
}

fn present_addr(addr: &str, me: &str, now: u64) -> bool {
    addr == me
        || (!is_silent(addr, now)
            && (heard_within(addr, now) || crate::p2p::validator_announced_within(addr, ANNOUNCED_WITHIN_SECS)))
}

fn replacement_reachable(plan: &[Vec<String>], me: &str) -> bool {
    replacement_reachable_by(plan, |a| able(a, me))
}

fn replacement_reachable_by(plan: &[Vec<String>], ok: impl Fn(&str) -> bool) -> bool {
    for committee in plan {
        let n = committee.len();
        let ready = committee.iter().filter(|a| ok(a)).count();
        if ready >= quorum_of(n) {
            return true;
        }
        if ready < skip_threshold_of(n) {
            return false;
        }
    }
    false
}

fn msg_attempt(msg: &P2PMessage) -> u32 {
    match msg {
        P2PMessage::TmProposal { attempt, .. } | P2PMessage::TmVote { attempt, .. } | P2PMessage::TmSkip { attempt, .. } => *attempt,
        _ => 0,
    }
}

impl Driver {
    fn build(height: u64) -> Option<Driver> {
        let (tip, tip_hash) = crate::chain_db::latest_block_info();
        if tip.saturating_add(1) != height {
            return None;
        }
        let parent_ts = crate::chain_db::get_block_by_height(tip).map(|b| b.timestamp).unwrap_or(0);
        let me_addr = crate::ledger::Ledger::load().address;
        let kp = signer();

        let (resume, skips, gave_up, lock_pol, lock_block) = {
            let g = wal();
            match g.as_ref().filter(|w| w.tm_parent == tip_hash && w.tm.as_ref().map_or(false, |s| s.height == height)) {
                Some(w) => (w.tm.clone(), w.tm_skips.clone(), w.tm_gave_up.clone(), w.tm_lock_pol.clone(), w.tm_lock_block.clone()),
                None => (None, Vec::new(), None, None, None),
            }
        };

        let (skips, chain, resume, gave_up, lock_pol) = match crate::chain_db::skip_chain(height, &skips) {
            Ok(chain) => (skips, chain, resume, gave_up, lock_pol),
            Err(e) => {
                eprintln!("[Consensus] h={height}: the saved replacement committees no longer check out ({e}), starting again from the first");
                (Vec::new(), crate::chain_db::skip_chain(height, &[]).ok()?, None, None, None)
            }
        };
        let attempt = attempt_of(&skips);
        let SkipChain { committee: members, miners, carried } = chain;
        let me = seat(&members, &me_addr, &kp, height);

        let mut engine = Tendermint::new(height, members.len(), me, Timeouts::default());
        let mut restored = None;
        if me.is_some() {
            if let Some(saved) = resume {
                engine.restore(&saved);
                restored = Some(saved);
            }
        }
        let mut names = HashMap::new();
        let mut payloads = HashMap::new();
        if let Some((b, t)) = lock_block {
            let v = tm_value_id(&b.hash);
            names.insert(v, b.hash.clone());
            payloads.insert(v, (b, t));
        }
        if let Some(l) = &carried {
            let v = tm_value_id(&l.value);
            names.insert(v, l.value.clone());
            engine.carry(v);
        }
        eprintln!(
            "[Consensus] h={height}{}: committee {} ({}), quorum {}, this node {}",
            if attempt > 0 { format!(" attempt {attempt}") } else { String::new() },
            members.len(),
            members.iter().map(|(a, _)| short(a)).collect::<Vec<_>>().join(" "),
            quorum_of(members.len()),
            match me {
                Some(i) => format!("is member {i}"),
                None => "follows".to_string(),
            }
        );
        let now = mono_ms();
        let d = Driver {
            height,
            parent_hash: tip_hash,
            parent_ts,
            attempt,
            skips,
            members,
            miners,
            me,
            me_addr,
            kp,
            engine,
            names,
            payloads,
            proposal_msgs: HashMap::new(),
            verdicts: HashMap::new(),
            checking: HashSet::new(),
            waiting: Vec::new(),
            sigs: HashMap::new(),
            my_votes: BTreeMap::new(),
            my_proposals: BTreeMap::new(),
            pending_propose: None,
            building: false,
            decided: None,
            committing: false,
            gave_up: gave_up.filter(|_| me.is_some()),
            give_ups: BTreeMap::new(),
            lock_pol,
            advancing: false,
            later: Vec::new(),
            attempt_started: now,
            last_resend: now,
            last_skips_resend: now,
            last_status: now,
            last_progress: now,
            said_cannot_give_up: false,
            said_no_replacement: false,
            caught_up: HashMap::new(),
            heard: HashSet::new(),
            seen_at_height: HashSet::new(),
            carried: carried.clone(),
        };
        if let Some(saved) = restored {
            eprintln!(
                "[Consensus] h={height}: resuming at round {} after a restart, locked on {}{}",
                saved.round,
                if saved.locked.is_some() { "a block" } else { "nothing" },
                if d.gave_up.is_some() { ", having given up on this committee" } else { "" }
            );
        }
        Some(d)
    }

    fn group(&self) -> Vec<String> {
        let mut g = self.miners.clone();
        g.sort();
        g.dedup();
        g
    }

    fn index_of(&self, addr: &str) -> Option<usize> {
        self.members.iter().position(|(a, _)| a == addr)
    }

    fn persist(&self) {
        if self.me.is_none() {
            return;
        }
        let lock_block = self
            .lock_pol
            .as_ref()
            .and_then(|l| self.payloads.get(&tm_value_id(&l.value)).cloned())
            .or_else(|| self.engine.carried().and_then(|v| self.payloads.get(&v).cloned()));
        let mut g = wal();
        let w = g.get_or_insert_with(Wal::default);
        w.tm = Some(self.engine.saved());
        w.tm_parent = self.parent_hash.clone();
        w.tm_attempt = self.attempt;
        w.tm_skips = self.skips.clone();
        w.tm_gave_up = self.gave_up.clone();
        w.tm_lock_pol = self.lock_pol.clone();
        w.tm_lock_block = lock_block;
        wal_store(w);
    }

    fn vote_message(&self, kind: VoteKind, round: u32, value: Option<ValueId>) -> Option<P2PMessage> {
        let kp = self.kp.as_ref()?;
        let name = value.map(|v| self.names.get(&v).cloned().unwrap_or_else(|| hex::encode(v)));
        let code = code_of(kind);
        let sig = sign(kp, &tm_vote_message_at(self.attempt, code, self.height, round, name.as_deref()));
        Some(P2PMessage::TmVote {
            height: self.height,
            round,
            kind: code,
            value: name,
            voter: self.me_addr.clone(),
            sig,
            attempt: self.attempt,
        })
    }

    fn proposal_message(&self, round: u32, pol_round: Option<u32>, value: ValueId) -> Option<P2PMessage> {
        let kp = self.kp.as_ref()?;
        let (block, txs) = self.payloads.get(&value)?;
        let sig = sign(kp, &tm_proposal_message_at(self.attempt, self.height, round, pol_round, &block.hash));
        let pol_votes = pol_round
            .and_then(|vr| self.sigs.get(&(TM_PREVOTE, vr, value)))
            .map(|m| m.iter().map(|(j, s)| (self.members[*j].0.clone(), s.clone())).collect())
            .unwrap_or_default();
        Some(P2PMessage::TmProposal {
            height: self.height,
            round,
            pol_round,
            block: block.clone(),
            transactions: txs.clone(),
            proposer: self.me_addr.clone(),
            sig,
            pol_votes,
            attempt: self.attempt,
            skips: self.skips.clone(),
        })
    }

    fn pol_for(&self, round: u32, value: ValueId) -> Option<TmLock> {
        let name = self.names.get(&value)?.clone();
        if let Some(l) = &self.lock_pol {
            if l.round == round && l.value == name {
                return Some(l.clone());
            }
        }
        let sigs = self.sigs.get(&(TM_PREVOTE, round, value))?;
        if sigs.len() < quorum_of(self.members.len()) {
            return None;
        }
        Some(TmLock {
            round,
            value: name,
            pol: sigs.iter().map(|(j, s)| (self.members[*j].0.clone(), s.clone())).collect(),
            attempt: compact_skip(self.attempt).then_some(self.attempt),
        })
    }

    fn apply(&mut self, actions: Vec<Action>, now: u64, out: &mut Out) {
        let mut queue: VecDeque<Action> = actions.into();
        let mut persist = false;
        let silent = self.gave_up.is_some();
        while let Some(action) = queue.pop_front() {
            match action {
                Action::Propose { .. } if silent => {}
                Action::Vote { .. } if silent => {}
                Action::Propose { round, pol_round, value } => match value {
                    Some(v) => match (self.me, self.proposal_message(round, pol_round, v)) {
                        (Some(me), Some(msg)) => {
                            match pol_round {
                                Some(r) => eprintln!("[Consensus] h={} round {round}: offering again the block the committee backed in round {r}", self.height),
                                None => eprintln!("[Consensus] h={} attempt {} round {round}: offering the block the previous committee locked on", self.height, self.attempt),
                            }
                            self.my_proposals.insert(round, msg.clone());
                            out.push((msg, Via::Both));
                            queue.extend(self.engine.on_proposal(now, round, me, v, pol_round, true));
                        }
                        _ => eprintln!("[Consensus] h={} round {round}: cannot offer the backed block again, its contents are not here", self.height),
                    },
                    None => self.pending_propose = Some(round),
                },
                Action::Vote { kind, round, value } => {
                    if let Some(msg) = self.vote_message(kind, round, value) {
                        if let (Some(v), Some(me), P2PMessage::TmVote { sig, .. }) = (value, self.me, &msg) {
                            self.sigs.entry((code_of(kind), round, v)).or_default().insert(me, sig.clone());
                        }
                        self.my_votes.insert((round, code_of(kind)), msg.clone());
                        out.push((msg, Via::Both));
                        persist = true;
                    }
                }
                Action::Decide { round, value } => {
                    self.decided = Some((round, value));
                    self.last_progress = now;
                }
            }
        }
        if let Some((lr, lv)) = self.engine.locked() {
            let fresh = self.lock_pol.as_ref().map_or(true, |l| l.round != lr || self.names.get(&lv) != Some(&l.value));
            if fresh {
                if let Some(l) = self.pol_for(lr, lv) {
                    self.lock_pol = Some(l);
                    persist = true;
                }
            }
        }
        if persist {
            self.persist();
        }
    }

    fn rebuild_votes_after_restart(&mut self) {
        if self.gave_up.is_some() {
            return;
        }
        let saved = self.engine.saved();
        for (round, kind, value) in saved.sent {
            if let Some(msg) = self.vote_message(kind, round, value) {
                if let (Some(v), Some(me), P2PMessage::TmVote { sig, .. }) = (value, self.me, &msg) {
                    self.sigs.entry((code_of(kind), round, v)).or_default().insert(me, sig.clone());
                }
                self.my_votes.insert((round, code_of(kind)), msg);
            }
        }
        if let Some(l) = self.lock_pol.clone() {
            let v = tm_value_id(&l.value);
            for (voter, sig) in l.pol {
                if let Some(j) = self.index_of(&voter) {
                    self.sigs.entry((TM_PREVOTE, l.round, v)).or_default().insert(j, sig);
                }
            }
        }
    }

    fn give_up_message(&self, vote: &TmSkipVote) -> P2PMessage {
        let payload = vote.locked.as_ref().and_then(|l| self.payloads.get(&tm_value_id(&l.value)).cloned());
        P2PMessage::TmSkip {
            height: self.height,
            attempt: self.attempt,
            vote: vote.clone(),
            block: payload.as_ref().map(|p| p.0.clone()),
            transactions: payload.map(|p| p.1).unwrap_or_default(),
        }
    }

    fn mark_heard(&mut self, j: usize) {
        self.heard.insert(j);
        if let Some((addr, _)) = self.members.get(j) {
            clear_silent(addr);
            self.seen_at_height.insert(addr.clone());
            note_heard(addr, mono_ms());
        }
    }

    fn present_members(&self, now: u64) -> usize {
        present_in(&self.members, &self.me_addr, |a| is_silent(a, now), |a| {
            heard_within(a, now) || crate::p2p::validator_announced_within(a, ANNOUNCED_WITHIN_SECS)
        })
    }

    fn short_of_quorum(&self, now: u64) -> bool {
        self.present_members(now) < quorum_of(self.members.len())
    }

    fn give_up_due(&self, now: u64) -> bool {
        if self.gave_up.is_some()
            || self.decided.is_some()
            || self.me.is_none()
            || !self.may_move_on()
            || self.height < crate::drs::SKIP_FROM_HEIGHT
        {
            return false;
        }
        let waited = now.saturating_sub(self.attempt_started);
        waited >= give_up_after(self.attempt) || (waited >= ABSENT_GIVE_UP_MS && self.short_of_quorum(now))
    }

    fn maybe_give_up(&mut self, now: u64, plan: Option<&[Vec<String>]>, out: &mut Out) {
        if !self.give_up_due(now) {
            return;
        }
        let Some(plan) = plan else { return };
        let me = self.me_addr.clone();
        if !replacement_reachable_by(plan, |a| able(a, &me) && present_addr(a, &me, now)) {
            if !self.said_no_replacement {
                self.said_no_replacement = true;
                eprintln!(
                    "[Consensus] h={} attempt {}: not giving up yet, none of the next committees has enough members present on {REPLACEMENT_VERSION} or later to finish the block, so this node keeps waiting here instead of using up attempts",
                    self.height, self.attempt
                );
            }
            return;
        }
        let (Some(_), Some(kp)) = (self.me, self.kp.clone()) else { return };
        let locked = match self.engine.locked() {
            None => None,
            Some((r, v)) => match self.pol_for(r, v) {
                Some(l) => Some(l),
                None => {
                    if !self.said_cannot_give_up {
                        self.said_cannot_give_up = true;
                        eprintln!("[Consensus] h={}: this node is locked on a block but no longer holds the votes behind the lock, so it waits instead of giving up", self.height);
                    }
                    return;
                }
            },
        };
        let msg = if compact_skip(self.attempt) {
            let reported = locked.or_else(|| self.carried.clone());
            let msg = tm_skip_message_v2(
                self.height,
                self.attempt,
                reported.as_ref().map(|l| (l.attempt.unwrap_or(self.attempt), l.round, l.value.as_str())),
            );
            (reported, msg)
        } else {
            let msg = tm_skip_message(self.height, self.attempt, locked.as_ref().map(|l| (l.round, l.value.as_str())));
            (locked, msg)
        };
        let (locked, msg) = msg;
        let vote = TmSkipVote { voter: self.me_addr.clone(), locked, sig: sign(&kp, &msg) };
        self.gave_up = Some(vote.clone());
        self.persist();
        let present = self.present_members(now);
        eprintln!(
            "[Consensus] h={} attempt {}: {} after {}s, this node gives up on this committee{}",
            self.height,
            self.attempt,
            if present < quorum_of(self.members.len()) {
                format!("only {present} of {} members are present", self.members.len())
            } else {
                "no block".to_string()
            },
            now.saturating_sub(self.attempt_started) / 1000,
            if vote.locked.is_some() { " and passes on the block it locked on" } else { "" }
        );
        out.push((self.give_up_message(&vote), Via::Both));
        self.give_ups.insert(vote.voter.clone(), vote);
    }

    fn may_move_on(&self) -> bool {
        self.attempt < TM_MAX_ATTEMPT || extended_attempts_at(self.height)
    }

    fn ready_skips(&self) -> Option<Vec<TmSkipCert>> {
        if self.advancing || self.decided.is_some() || !self.may_move_on() {
            return None;
        }
        if self.give_ups.len() < skip_threshold_of(self.members.len()) {
            return None;
        }
        let cert = TmSkipCert { attempt: self.attempt, votes: self.give_ups.values().cloned().collect() };
        if self.attempt.saturating_add(1) > TM_MAX_ATTEMPT {
            return Some(vec![cert]);
        }
        let mut skips = self.skips.clone();
        skips.push(cert);
        Some(skips)
    }

    fn enter(&mut self, skips: Vec<TmSkipCert>, chain: SkipChain, now: u64, out: &mut Out) {
        let attempt = attempt_of(&skips);
        let SkipChain { committee, miners, carried } = chain;
        let me = seat(&committee, &self.me_addr, &self.kp, self.height);
        eprintln!(
            "[Consensus] h={}: committee {} could not finish the block; attempt {attempt} committee {} ({}), quorum {}, this node {}{}",
            self.height,
            attempt.saturating_sub(1),
            committee.len(),
            committee.iter().map(|(a, _)| short(a)).collect::<Vec<_>>().join(" "),
            quorum_of(committee.len()),
            match me {
                Some(i) => format!("is member {i}"),
                None => "follows".to_string(),
            },
            if carried.is_some() { ", and it may only finish the block the last one locked on" } else { "" }
        );
        if now.saturating_sub(self.attempt_started) >= SILENT_AFTER_MS {
            for (addr, _) in &self.members {
                if *addr != self.me_addr && !self.seen_at_height.contains(addr) && mark_silent(addr, now) {
                    eprintln!("[Consensus] h={}: {} sent nothing while on committee {}, so it no longer counts as present", self.height, short(addr), self.attempt);
                }
            }
        }
        self.attempt = attempt;
        self.skips = skips;
        self.carried = carried.clone();
        self.members = committee;
        self.miners = miners;
        self.me = me;
        self.engine = Tendermint::new(self.height, self.members.len(), me, Timeouts::default());
        if let Some(l) = &carried {
            let v = tm_value_id(&l.value);
            self.names.entry(v).or_insert_with(|| l.value.clone());
            self.engine.carry(v);
        }
        self.proposal_msgs.clear();
        self.waiting.clear();
        self.sigs.clear();
        self.my_votes.clear();
        self.my_proposals.clear();
        self.pending_propose = None;
        self.gave_up = None;
        self.give_ups.clear();
        self.lock_pol = None;
        self.advancing = false;
        self.said_cannot_give_up = false;
        self.said_no_replacement = false;
        self.caught_up.clear();
        self.heard.clear();
        self.attempt_started = now;
        self.last_progress = now;
        let acts = self.engine.start(now);
        self.apply(acts, now, out);
        self.persist();
        *GROUP.lock().unwrap_or_else(|e| e.into_inner()) = Some((self.height, self.group()));
    }

    fn catch_up(&mut self, round: u32, now: u64, out: &mut Out) {
        if self.gave_up.is_some() || round >= self.engine.round() {
            return;
        }
        if self.caught_up.get(&round).map_or(false, |at| now.saturating_sub(*at) < RESEND_MS) {
            return;
        }
        self.caught_up.insert(round, now);
        if let Some(m) = self.my_proposals.get(&round) {
            out.push((m.clone(), Via::Both));
        }
        for code in [TM_PREVOTE, TM_PRECOMMIT] {
            if let Some(m) = self.my_votes.get(&(round, code)) {
                out.push((m.clone(), Via::Both));
            }
        }
    }

    fn resend_skips(&mut self, now: u64, out: &mut Out) {
        if self.skips.is_empty() || now.saturating_sub(self.last_skips_resend) < SKIPS_RESEND_MS {
            return;
        }
        self.last_skips_resend = now;
        for cert in &self.skips {
            for vote in &cert.votes {
                let payload = vote.locked.as_ref().and_then(|l| self.payloads.get(&tm_value_id(&l.value)).cloned());
                out.push((
                    P2PMessage::TmSkip {
                        height: self.height,
                        attempt: cert.attempt,
                        vote: vote.clone(),
                        block: payload.as_ref().map(|p| p.0.clone()),
                        transactions: payload.map(|p| p.1).unwrap_or_default(),
                    },
                    Via::Gossip,
                ));
            }
        }
    }

    fn resend(&mut self, now: u64, out: &mut Out) {
        self.resend_skips(now, out);
        if now.saturating_sub(self.last_resend) < RESEND_MS {
            return;
        }
        self.last_resend = now;
        if let Some(vote) = &self.gave_up {
            out.push((self.give_up_message(vote), Via::Both));
        } else {
            let round = self.engine.round();
            if let Some(m) = self.my_proposals.get(&round) {
                out.push((m.clone(), Via::Direct));
            }
            for code in [TM_PREVOTE, TM_PRECOMMIT] {
                if let Some(m) = self.my_votes.get(&(round, code)) {
                    out.push((m.clone(), Via::Both));
                }
            }
            if let Some((lr, lv)) = self.engine.locked() {
                if let Some(m) = self.proposal_msgs.get(&lv) {
                    out.push((m.clone(), Via::Direct));
                }
                if lr != round {
                    if let Some(m) = self.my_votes.get(&(lr, TM_PRECOMMIT)) {
                        out.push((m.clone(), Via::Both));
                    }
                }
            }
        }
        if now.saturating_sub(self.last_status) >= STATUS_MS && self.decided.is_none() {
            self.last_status = now;
            eprintln!("[Consensus] {}", self.status());
        }
    }

    fn status(&self) -> String {
        format!(
            "h={}{} round {} step {:?}, committee {} quorum {}, {}, heard from {} other member(s), {} present, locked {}{}, waiting {}s",
            self.height,
            if self.attempt > 0 { format!(" attempt {}", self.attempt) } else { String::new() },
            self.engine.round(),
            self.engine.step(),
            self.members.len(),
            quorum_of(self.members.len()),
            match self.me {
                Some(i) => format!("member {i}"),
                None => "following".into(),
            },
            self.heard.len(),
            self.present_members(mono_ms()),
            if self.engine.locked().is_some() { "yes" } else { "no" },
            if self.give_ups.is_empty() {
                String::new()
            } else {
                format!(", {} of {} gave up", self.give_ups.len(), skip_threshold_of(self.members.len()))
            },
            mono_ms().saturating_sub(self.last_progress) / 1000
        )
    }
}

pub fn status_line() -> Option<String> {
    driver().as_ref().map(|d| d.status())
}

async fn flush(height: u64, out: Out) {
    if out.is_empty() {
        return;
    }
    let mut direct = Vec::new();
    for (msg, via) in out {
        if via != Via::Direct {
            crate::p2p::shadow_publish(&msg).await;
        }
        if via != Via::Gossip {
            direct.push(msg);
        }
    }
    if direct.is_empty() {
        return;
    }
    let group = GROUP
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .filter(|(h, _)| *h == height)
        .map(|(_, g)| g.clone());
    match group {
        Some(members) => crate::p2p::send_to_members(members, direct).await,
        None => crate::p2p::send_to_group(height, direct).await,
    }
}

pub async fn tick() -> bool {
    let (tip, tip_hash) = crate::chain_db::latest_block_info();
    let next = tip.saturating_add(1);
    let active = tokio::task::spawn_blocking(move || crate::chain_db::tendermint_active(next))
        .await
        .unwrap_or(false);
    if !active {
        let mut g = driver();
        if g.is_some() {
            *g = None;
        }
        return false;
    }
    if !ensure_driver(next, &tip_hash).await {
        return true;
    }
    let now = mono_ms();
    let due = driver().as_ref().and_then(|d| d.give_up_due(now).then_some((d.height, d.attempt)));
    let plan = match due {
        Some((h, a)) => tokio::task::spawn_blocking(move || {
            (a + 1..=a + LOOKAHEAD)
                .filter_map(|k| crate::chain_db::committee_for_attempt(h, k))
                .map(|c| c.into_iter().map(|(x, _)| x).collect::<Vec<String>>())
                .collect::<Vec<Vec<String>>>()
        })
        .await
        .ok(),
        None => None,
    };
    let mut out = Out::new();
    let ready = {
        let mut g = driver();
        let Some(d) = g.as_mut() else { return true };
        let acts = d.engine.tick(now);
        d.apply(acts, now, &mut out);
        d.maybe_give_up(now, plan.as_deref(), &mut out);
        d.resend(now, &mut out);
        d.ready_skips()
    };
    flush(next, out).await;
    if let Some(skips) = ready {
        advance(next, skips).await;
    }
    maybe_propose().await;
    maybe_commit().await;
    true
}

async fn advance(height: u64, skips: Vec<TmSkipCert>) {
    let attempt = attempt_of(&skips);
    {
        let mut g = driver();
        let Some(d) = g.as_mut() else { return };
        if d.height != height || d.attempt >= attempt || d.advancing {
            return;
        }
        d.advancing = true;
    }
    let checked = skips.clone();
    let chain = tokio::task::spawn_blocking(move || crate::chain_db::skip_chain(height, &checked))
        .await
        .unwrap_or_else(|_| Err("committee task panicked".into()));
    let now = mono_ms();
    let mut out = Out::new();
    let replay = {
        let mut g = driver();
        let Some(d) = g.as_mut() else { return };
        if d.height != height {
            return;
        }
        d.advancing = false;
        if d.attempt >= attempt {
            return;
        }
        match chain {
            Ok(chain) => d.enter(skips, chain, now, &mut out),
            Err(e) => {
                eprintln!("[Consensus] h={height}: not moving to committee {attempt}: {e}");
                return;
            }
        }
        let (now_due, keep): (Vec<P2PMessage>, Vec<P2PMessage>) = d.later.drain(..).partition(|m| msg_attempt(m) == attempt);
        d.later = keep.into_iter().filter(|m| msg_attempt(m) > attempt).collect();
        now_due
    };
    flush(height, out).await;
    for msg in replay {
        Box::pin(on_message(msg)).await;
    }
}

async fn ensure_driver(height: u64, tip_hash: &str) -> bool {
    {
        let g = driver();
        if g.as_ref().map_or(false, |d| d.height == height && d.parent_hash == tip_hash) {
            return true;
        }
    }
    let built = tokio::task::spawn_blocking(move || Driver::build(height)).await.ok().flatten();
    let Some(mut d) = built else {
        *driver() = None;
        static SAID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        if SAID.swap(height, std::sync::atomic::Ordering::Relaxed) != height {
            eprintln!("[Consensus] h={height}: no committee could be seated from chain state yet");
        }
        return false;
    };
    let now = mono_ms();
    let mut out = Out::new();
    {
        let mut g = driver();
        if g.as_ref().map_or(false, |x| x.height == height && x.parent_hash == d.parent_hash) {
            return true;
        }
        let acts = d.engine.start(now);
        d.rebuild_votes_after_restart();
        d.apply(acts, now, &mut out);
        *GROUP.lock().unwrap_or_else(|e| e.into_inner()) = Some((height, d.group()));
        *g = Some(d);
    }
    flush(height, out).await;
    let replay: Vec<P2PMessage> = {
        let mut f = future();
        let keep = f.split_off(&height.saturating_add(1));
        let due = f.remove(&height).unwrap_or_default();
        *f = keep;
        due
    };
    for msg in replay {
        Box::pin(on_message(msg)).await;
    }
    true
}

enum Route {
    Now,
    Later,
    Drop,
}

fn route(height: u64) -> Route {
    let next = crate::chain_db::latest_block_info().0.saturating_add(1);
    if height < next || height > next.saturating_add(FUTURE_HEIGHTS) {
        return Route::Drop;
    }
    let ready = driver().as_ref().map_or(false, |d| d.height == height);
    if height == next && ready {
        Route::Now
    } else {
        Route::Later
    }
}

fn hold(height: u64, msg: P2PMessage) {
    let mut f = future();
    let total: usize = f.values().map(|v| v.len()).sum();
    if total < FUTURE_MAX {
        f.entry(height).or_default().push(msg);
    }
}

enum Gate {
    Current,
    Behind,
    Stale,
}

fn gate(d: &mut Driver, attempt: u32, msg: &P2PMessage) -> Gate {
    if attempt < d.attempt {
        Gate::Stale
    } else if attempt > d.attempt {
        if d.later.len() < LATER_MAX {
            d.later.push(msg.clone());
        }
        Gate::Behind
    } else {
        Gate::Current
    }
}

pub async fn on_message(msg: P2PMessage) {
    match msg {
        P2PMessage::TmProposal { height, round, pol_round, block, transactions, proposer, sig, pol_votes, attempt, skips } => {
            on_proposal(height, round, pol_round, block, transactions, proposer, sig, pol_votes, attempt, skips).await
        }
        P2PMessage::TmVote { height, round, kind, value, voter, sig, attempt } => {
            on_vote(height, round, kind, value, voter, sig, attempt).await
        }
        P2PMessage::TmSkip { height, attempt, vote, block, transactions } => {
            on_give_up(height, attempt, vote, block, transactions).await
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
async fn on_proposal(
    height: u64,
    round: u32,
    pol_round: Option<u32>,
    block: LedgerBlock,
    transactions: Vec<LedgerTx>,
    proposer: String,
    sig: String,
    pol_votes: Vec<(String, String)>,
    attempt: u32,
    skips: Vec<TmSkipCert>,
) {
    let full = P2PMessage::TmProposal {
        height,
        round,
        pol_round,
        block: block.clone(),
        transactions: transactions.clone(),
        proposer: proposer.clone(),
        sig: sig.clone(),
        pol_votes: pol_votes.clone(),
        attempt,
        skips: skips.clone(),
    };
    match route(height) {
        Route::Drop => return,
        Route::Later => {
            crate::p2p::note_network_height(height);
            hold(height, full);
            return;
        }
        Route::Now => {}
    }
    crate::p2p::note_network_height(height);
    let behind = {
        let g = driver();
        let Some(d) = g.as_ref() else { return };
        d.height == height && attempt > d.attempt
    };
    if behind {
        if attempt_of(&skips) != attempt {
            return;
        }
        advance(height, skips.clone()).await;
        let caught_up = driver().as_ref().map_or(false, |d| d.height == height && d.attempt == attempt);
        if !caught_up {
            return;
        }
    }
    let now = mono_ms();
    let mut out = Out::new();
    let mut check: Option<(ValueId, LedgerBlock, Vec<LedgerTx>, i64, Vec<String>)> = None;
    {
        let mut g = driver();
        let Some(d) = g.as_mut() else { return };
        if d.height != height || pol_round.map_or(false, |p| p >= round) {
            return;
        }
        match gate(d, attempt, &full) {
            Gate::Current => {}
            _ => return,
        }
        let idx = d.engine.proposer(round);
        let Some((addr, pk)) = d.members.get(idx).cloned() else { return };
        if addr != proposer || block.height != height || block.prev_hash != d.parent_hash {
            return;
        }
        if !tm_signature_ok(&pk, &tm_proposal_message_at(attempt, height, round, pol_round, &block.hash), &sig) {
            eprintln!("[Consensus] h={height} round {round}: proposal from {:.14} does not verify", proposer);
            return;
        }
        d.mark_heard(idx);
        let v = tm_value_id(&block.hash);
        d.names.entry(v).or_insert_with(|| block.hash.clone());
        d.catch_up(round, now, &mut out);
        let mut acts = Vec::new();
        if let Some(vr) = pol_round {
            let msg = tm_vote_message_at(attempt, TM_PREVOTE, height, vr, Some(&block.hash));
            for (voter, s) in &pol_votes {
                let Some(j) = d.index_of(voter) else { continue };
                if tm_signature_ok(&d.members[j].1, &msg, s) {
                    d.sigs.entry((TM_PREVOTE, vr, v)).or_default().insert(j, s.clone());
                    acts.extend(d.engine.on_vote(now, VoteKind::Prevote, vr, j, Some(v)));
                }
            }
        }
        d.proposal_msgs.entry(v).or_insert(full);
        d.payloads.entry(v).or_insert_with(|| (block.clone(), transactions.clone()));
        match d.verdicts.get(&v).copied() {
            Some(ok) => acts.extend(d.engine.on_proposal(now, round, idx, v, pol_round, ok)),
            None => {
                d.waiting.push(Waiting { round, from: idx, value: v, pol_round });
                if d.checking.insert(v) {
                    check = Some((v, block, transactions, d.parent_ts, d.miners.clone()));
                }
            }
        }
        d.apply(acts, now, &mut out);
    }
    flush(height, out).await;
    if let Some((v, b, t, parent_ts, miners)) = check {
        let verdict = tokio::task::spawn_blocking(move || crate::chain_db::validate_tm_block_for(&b, &t, parent_ts, &miners))
            .await
            .unwrap_or_else(|_| Err("validation task panicked".into()));
        settle(height, v, verdict).await;
    }
    maybe_commit().await;
}

async fn settle(height: u64, value: ValueId, verdict: Result<(), String>) {
    let now = mono_ms();
    let mut out = Out::new();
    {
        let mut g = driver();
        let Some(d) = g.as_mut() else { return };
        if d.height != height {
            return;
        }
        let ok = verdict.is_ok();
        if let Err(e) = &verdict {
            eprintln!("[Consensus] h={height}: refusing block {:.12}: {e}", d.names.get(&value).map(|s| s.as_str()).unwrap_or(""));
        }
        d.checking.remove(&value);
        d.verdicts.insert(value, ok);
        let mut acts = Vec::new();
        let waiting: Vec<Waiting> = {
            let (now_ready, rest): (Vec<Waiting>, Vec<Waiting>) = d.waiting.drain(..).partition(|w| w.value == value);
            d.waiting = rest;
            now_ready
        };
        for w in waiting {
            acts.extend(d.engine.on_proposal(now, w.round, w.from, w.value, w.pol_round, ok));
        }
        acts.extend(d.engine.on_value(now, value, ok));
        d.apply(acts, now, &mut out);
    }
    flush(height, out).await;
}

#[allow(clippy::too_many_arguments)]
async fn on_vote(height: u64, round: u32, kind: u8, value: Option<String>, voter: String, sig: String, attempt: u32) {
    let full = P2PMessage::TmVote { height, round, kind, value: value.clone(), voter: voter.clone(), sig: sig.clone(), attempt };
    match route(height) {
        Route::Drop => return,
        Route::Later => {
            hold(height, full);
            return;
        }
        Route::Now => {}
    }
    let Some(k) = kind_of(kind) else { return };
    let now = mono_ms();
    let mut out = Out::new();
    {
        let mut g = driver();
        let Some(d) = g.as_mut() else { return };
        if d.height != height {
            return;
        }
        match gate(d, attempt, &full) {
            Gate::Current => {}
            _ => return,
        }
        let Some(j) = d.index_of(&voter) else { return };
        if Some(j) == d.me {
            return;
        }
        if !tm_signature_ok(&d.members[j].1, &tm_vote_message_at(attempt, kind, height, round, value.as_deref()), &sig) {
            return;
        }
        let v = value.as_deref().map(tm_value_id);
        if let (Some(v), Some(name)) = (v, value.as_ref()) {
            d.names.entry(v).or_insert_with(|| name.clone());
            d.sigs.entry((kind, round, v)).or_default().insert(j, sig);
        }
        d.mark_heard(j);
        d.catch_up(round, now, &mut out);
        let acts = d.engine.on_vote(now, k, round, j, v);
        d.apply(acts, now, &mut out);
    }
    flush(height, out).await;
    maybe_commit().await;
}

async fn on_give_up(height: u64, attempt: u32, vote: TmSkipVote, block: Option<LedgerBlock>, transactions: Vec<LedgerTx>) {
    let full = P2PMessage::TmSkip { height, attempt, vote: vote.clone(), block: block.clone(), transactions: transactions.clone() };
    match route(height) {
        Route::Drop => return,
        Route::Later => {
            hold(height, full);
            return;
        }
        Route::Now => {}
    }
    let backing_attempt = vote.lock_attempt(attempt).filter(|a| *a != attempt);
    let backing = match backing_attempt {
        Some(a) => tokio::task::spawn_blocking(move || crate::chain_db::committee_for_attempt(height, a)).await.ok().flatten(),
        None => None,
    };
    let ready = {
        let mut g = driver();
        let Some(d) = g.as_mut() else { return };
        if d.height != height || d.decided.is_some() {
            return;
        }
        match gate(d, attempt, &full) {
            Gate::Current => {}
            _ => return,
        }
        if d.give_ups.contains_key(&vote.voter) {
            return;
        }
        let earlier = |a: u32| if Some(a) == backing_attempt { backing.clone() } else { None };
        if let Err(e) = vote.verify_with(height, attempt, &d.members, &earlier) {
            eprintln!("[Consensus] h={height}: ignoring a give-up: {e}");
            return;
        }
        if let (Some(l), Some(b)) = (&vote.locked, block) {
            if b.hash == l.value && b.height == height && b.prev_hash == d.parent_hash {
                let v = tm_value_id(&b.hash);
                d.names.entry(v).or_insert_with(|| b.hash.clone());
                d.payloads.entry(v).or_insert((b, transactions));
            }
        }
        eprintln!(
            "[Consensus] h={height} attempt {attempt}: {} gave up on this committee ({} of {} needed)",
            short(&vote.voter),
            d.give_ups.len() + 1,
            skip_threshold_of(d.members.len())
        );
        if let Some(j) = d.index_of(&vote.voter) {
            d.mark_heard(j);
        }
        d.give_ups.insert(vote.voter.clone(), vote);
        d.ready_skips()
    };
    if let Some(skips) = ready {
        advance(height, skips).await;
    }
}

async fn maybe_propose() {
    let job = {
        let mut g = driver();
        let Some(d) = g.as_mut() else { return };
        let Some(round) = d.pending_propose else { return };
        if d.building {
            return;
        }
        if d.gave_up.is_some() || d.engine.round() != round || d.engine.step() != Step::Propose || d.decided.is_some() {
            d.pending_propose = None;
            return;
        }
        let due = round > 0
            || d.attempt > 0
            || crate::mempool::get_mempool().pending_count() > 0
            || crate::clock::now() - d.parent_ts >= crate::mempool::EMPTY_BLOCK_INTERVAL_S as i64;
        if !due || crate::p2p::proposing_suspended() {
            return;
        }
        if !crate::p2p::offline_mode() && !crate::clock::is_trusted() {
            static SAID: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
            let t = chrono::Utc::now().timestamp();
            if t - SAID.swap(t, std::sync::atomic::Ordering::Relaxed) > 600 {
                eprintln!("[Consensus] not proposing: this node has no trusted time yet");
            }
            return;
        }
        d.building = true;
        (d.height, d.attempt, round, d.parent_hash.clone(), d.parent_ts, d.miners.clone())
    };
    let (height, attempt, round, parent_hash, parent_ts, miners) = job;
    let built = crate::p2p::build_live_candidate().await;
    let checked = match built {
        Some((block, txs)) if block.height == height && block.prev_hash == parent_hash => {
            let (b, t) = (block.clone(), txs.clone());
            let verdict = tokio::task::spawn_blocking(move || crate::chain_db::validate_tm_block_for(&b, &t, parent_ts, &miners))
                .await
                .unwrap_or_else(|_| Err("validation task panicked".into()));
            match verdict {
                Ok(()) => Some((block, txs)),
                Err(e) => {
                    eprintln!("[Consensus] h={height} round {round}: the block this node built is not valid: {e}");
                    None
                }
            }
        }
        _ => None,
    };
    let now = mono_ms();
    let mut out = Out::new();
    {
        let mut g = driver();
        let Some(d) = g.as_mut() else { return };
        if d.height != height {
            return;
        }
        d.building = false;
        let Some((block, txs)) = checked else { return };
        let Some(me) = d.me else { return };
        if d.attempt != attempt
            || d.gave_up.is_some()
            || d.pending_propose != Some(round)
            || d.engine.round() != round
            || d.engine.step() != Step::Propose
        {
            return;
        }
        let v = tm_value_id(&block.hash);
        let tx_count = txs.len();
        d.names.insert(v, block.hash.clone());
        d.payloads.insert(v, (block, txs));
        d.verdicts.insert(v, true);
        d.pending_propose = None;
        let Some(msg) = d.proposal_message(round, None, v) else { return };
        eprintln!("[Consensus] h={height} round {round}: proposing block {:.12} with {tx_count} transactions", d.names[&v]);
        d.my_proposals.insert(round, msg.clone());
        d.proposal_msgs.insert(v, msg.clone());
        out.push((msg, Via::Both));
        let acts = d.engine.on_proposal(now, round, me, v, None, true);
        d.apply(acts, now, &mut out);
    }
    flush(height, out).await;
}

async fn maybe_commit() {
    let job = {
        let mut g = driver();
        let Some(d) = g.as_mut() else { return };
        let Some((round, v)) = d.decided else { return };
        if d.committing {
            return;
        }
        let Some((block, txs)) = d.payloads.get(&v).cloned() else {
            return;
        };
        let quorum = quorum_of(d.members.len());
        let Some(votes) = d.sigs.get(&(TM_PRECOMMIT, round, v)) else { return };
        if votes.len() < quorum {
            return;
        }
        let chosen: Vec<(String, String)> = votes
            .iter()
            .take(quorum)
            .map(|(j, s)| (d.members[*j].0.clone(), s.clone()))
            .collect();
        let cert = if d.attempt == 0 {
            TmCert { v: TM_CERT_VERSION, round, votes: chosen, ..TmCert::default() }
        } else {
            TmCert { v: TM_CERT_V4, round, votes: chosen, attempt: d.attempt, skips: d.skips.clone() }
        };
        let mut block = block;
        block.commit_cert = serde_json::to_string(&cert).unwrap_or_default();
        d.committing = true;
        (d.height, d.attempt, round, block, txs, quorum as u32)
    };
    let (height, attempt, round, block, txs, count) = job;
    let (b, t) = (block.clone(), txs.clone());
    let persisted = tokio::task::spawn_blocking(move || crate::chain_db::commit_staged_block(&b, &t, count))
        .await
        .unwrap_or(false);
    if persisted {
        eprintln!(
            "[Consensus] finalized h={height}{} in round {round} with {count} commit votes, block {:.12}",
            if attempt > 0 { format!(" by replacement committee {attempt}") } else { String::new() },
            block.hash
        );
        crate::p2p::LAST_BLOCK_FINALIZED_TS.store(chrono::Utc::now().timestamp(), std::sync::atomic::Ordering::Relaxed);
        crate::clock::note_finalized_block_time(block.timestamp);
        crate::p2p::touch_proposal_timestamp();
        let announce = P2PMessage::TmCommit { block: block.clone(), transactions: txs.clone() };
        tokio::spawn(async move { flush(height, vec![(announce, Via::Both)]).await });
        tokio::spawn(async move { crate::p2p::push_block_to_oracle(&block, &txs).await });
        let mut g = driver();
        if g.as_ref().map_or(false, |d| d.height == height) {
            *g = None;
        }
        future().retain(|h, _| *h > height);
    } else {
        eprintln!("[Consensus] h={height}: the agreed block could not be stored yet; retrying");
        if let Some(d) = driver().as_mut() {
            if d.height == height {
                d.committing = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_db::{tm_proposal_message, tm_vote_message};

    #[test]
    fn a_committee_short_of_present_members_is_left_quickly_and_a_full_one_gets_time() {
        let m = |names: &[&str]| names.iter().map(|n| (n.to_string(), Vec::new())).collect::<Vec<(String, Vec<u8>)>>();
        let committee = m(&["egot1me", "egot1a", "egot1b", "egot1gone"]);
        let live = |a: &str| a != "egot1gone";
        assert_eq!(present_in(&committee, "egot1me", |_| false, live), 3, "three present members can still finish");
        assert_eq!(
            present_in(&committee, "egot1me", |a| a == "egot1b", live),
            2,
            "a member that sent nothing on its last committee no longer counts, even if it still announces"
        );
        assert_eq!(present_in(&committee, "egot1me", |a| a == "egot1me", |_| false), 1, "a node always counts itself");
        assert!(ABSENT_GIVE_UP_MS < give_up_after(0), "an absent committee is left before the normal wait");
        assert!(ABSENT_GIVE_UP_MS < SILENT_AFTER_MS, "members get longer to speak than an absent committee is kept");
    }

    #[test]
    fn a_silent_member_is_forgotten_the_moment_it_speaks_and_marks_expire() {
        let now = 1_000_000;
        assert!(mark_silent("egot1test-silent", now));
        assert!(!mark_silent("egot1test-silent", now + 1), "marking twice reports nothing new");
        assert!(is_silent("egot1test-silent", now + SILENT_KEEP_MS), "staying silent keeps the mark fresh");
        assert!(!is_silent("egot1test-silent", now + 1 + SILENT_KEEP_MS), "a mark expires");
        clear_silent("egot1test-silent");
        assert!(!is_silent("egot1test-silent", now + 1), "speaking clears it");
    }

    #[test]
    fn the_new_messages_travel_under_their_own_names() {
        let vote = P2PMessage::TmVote {
            height: 33_101,
            round: 2,
            kind: TM_PRECOMMIT,
            value: Some("ab".repeat(32)),
            voter: "egot1x".into(),
            sig: "c2ln".into(),
            attempt: 0,
        };
        let json = serde_json::to_value(&vote).unwrap();
        assert_eq!(json["type"], "tm_vote");
        let back: P2PMessage = serde_json::from_value(json).unwrap();
        assert!(matches!(back, P2PMessage::TmVote { round: 2, kind: TM_PRECOMMIT, .. }));

        let proposal = P2PMessage::TmProposal {
            height: 33_101,
            round: 1,
            pol_round: Some(0),
            block: LedgerBlock::default(),
            transactions: vec![],
            proposer: "egot1x".into(),
            sig: "c2ln".into(),
            pol_votes: vec![("egot1y".into(), "c2ln".into())],
            attempt: 0,
            skips: vec![],
        };
        let mut json = serde_json::to_value(&proposal).unwrap();
        assert_eq!(json["type"], "tm_proposal");
        json.as_object_mut().unwrap().remove("pol_votes");
        assert!(matches!(
            serde_json::from_value::<P2PMessage>(json).unwrap(),
            P2PMessage::TmProposal { pol_round: Some(0), .. }
        ));
    }

    #[test]
    fn messages_from_older_nodes_belong_to_the_first_committee() {
        let vote = serde_json::json!({
            "type": "tm_vote", "height": 40_000, "round": 1, "kind": TM_PREVOTE,
            "value": null, "voter": "egot1x", "sig": "c2ln"
        });
        assert!(matches!(serde_json::from_value::<P2PMessage>(vote).unwrap(), P2PMessage::TmVote { attempt: 0, .. }));
        let proposal = serde_json::json!({
            "type": "tm_proposal", "height": 40_000, "round": 0, "pol_round": null,
            "block": LedgerBlock::default(), "transactions": [], "proposer": "egot1x", "sig": "c2ln"
        });
        assert!(matches!(
            serde_json::from_value::<P2PMessage>(proposal).unwrap(),
            P2PMessage::TmProposal { attempt: 0, ref skips, .. } if skips.is_empty()
        ));
    }

    #[test]
    fn a_give_up_travels_with_the_block_it_locked_on() {
        let msg = P2PMessage::TmSkip {
            height: 40_000,
            attempt: 1,
            vote: TmSkipVote {
                voter: "egot1x".into(),
                locked: Some(TmLock { round: 2, value: "ab".repeat(32), pol: vec![("egot1y".into(), "c2ln".into())], attempt: None }),
                sig: "c2ln".into(),
            },
            block: Some(LedgerBlock { height: 40_000, hash: "ab".repeat(32), ..LedgerBlock::default() }),
            transactions: vec![],
        };
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["type"], "tm_skip");
        match serde_json::from_value::<P2PMessage>(json).unwrap() {
            P2PMessage::TmSkip { attempt: 1, vote, block: Some(b), .. } => {
                assert_eq!(vote.locked.unwrap().value, b.hash);
            }
            other => panic!("wrong message: {other:?}"),
        }
    }

    #[test]
    fn every_vote_kind_round_and_choice_signs_different_bytes() {
        let h = "ab".repeat(32);
        let a = tm_vote_message(TM_PREVOTE, 9, 1, Some(&h));
        assert_ne!(a, tm_vote_message(TM_PRECOMMIT, 9, 1, Some(&h)));
        assert_ne!(a, tm_vote_message(TM_PREVOTE, 9, 2, Some(&h)));
        assert_ne!(a, tm_vote_message(TM_PREVOTE, 10, 1, Some(&h)));
        assert_ne!(a, tm_vote_message(TM_PREVOTE, 9, 1, None));
        assert_ne!(tm_proposal_message(9, 1, None, &h), tm_proposal_message(9, 1, Some(0), &h));
    }

    #[test]
    fn vote_kinds_map_both_ways() {
        for k in [VoteKind::Prevote, VoteKind::Precommit] {
            assert_eq!(kind_of(code_of(k)), Some(k));
        }
        assert_eq!(kind_of(0), None);
        assert_eq!(kind_of(9), None);
    }

    #[test]
    fn attempts_are_not_spent_on_committees_whose_members_are_away() {
        let c = |xs: &[&str]| xs.iter().map(|x| x.to_string()).collect::<Vec<String>>();
        let away = ["egot1tc5p", "egot1cczr"];
        let here = |a: &str| !away.contains(&a);
        let plan = vec![
            c(&["egot1me", "egot1tzz8", "egot1tc5p", "egot1cczr"]),
            c(&["egot1me", "egot1y2dm", "egot1tc5p", "egot1cczr"]),
        ];
        assert!(!replacement_reachable_by(&plan, here), "with two of four away in every next committee, giving up only burns attempts");
        let plan = vec![
            c(&["egot1me", "egot1tzz8", "egot1tc5p", "egot1cczr"]),
            c(&["egot1me", "egot1tzz8", "egot1y2dm", "egot1tc5p"]),
        ];
        assert!(replacement_reachable_by(&plan, here), "a committee two steps on with three present is worth moving to");
    }

    #[test]
    fn a_node_gives_up_only_toward_committees_that_can_finish_the_block() {
        let me = "egot1me";
        let c = |xs: &[&str]| xs.iter().map(|x| x.to_string()).collect::<Vec<String>>();
        assert!(!replacement_reachable(&[], me));
        assert!(!replacement_reachable(&[c(&[me, "egot1old1", "egot1old2", "egot1old3"])], me), "one able member cannot give up or finish");
        crate::commands::updates::note_peer_version("egot1new1", REPLACEMENT_VERSION);
        crate::commands::updates::note_peer_version("egot1new2", "0.3.700");
        crate::commands::updates::note_peer_version("egot1stale", "0.3.645");
        assert!(replacement_reachable(&[c(&[me, "egot1new1", "egot1new2", "egot1old1"])], me), "three able members can finish");
        assert!(
            replacement_reachable(&[c(&[me, "egot1new1", "egot1old1", "egot1old2"]), c(&[me, "egot1new1", "egot1new2", "egot1old3"])], me),
            "two able members can pass a committee on to one that finishes"
        );
        assert!(
            !replacement_reachable(&[c(&[me, "egot1stale", "egot1old1", "egot1old2"]), c(&[me, "egot1new1", "egot1new2", "egot1old3"])], me),
            "a committee with one able member is a dead end"
        );
    }

    #[test]
    fn a_finished_block_travels_with_its_certificate() {
        let block = LedgerBlock { height: 40_000, hash: "ab".repeat(32), commit_cert: "{}".into(), ..LedgerBlock::default() };
        let msg = P2PMessage::TmCommit { block, transactions: vec![] };
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["type"], "tm_commit");
        match serde_json::from_value::<P2PMessage>(json).unwrap() {
            P2PMessage::TmCommit { block, .. } => assert_eq!(block.commit_cert, "{}"),
            other => panic!("wrong message: {other:?}"),
        }
    }

    #[test]
    fn later_committees_wait_longer_before_giving_up() {
        assert_eq!(give_up_after(0), GIVE_UP_AFTER_MS);
        assert!(give_up_after(1) > give_up_after(0));
        assert_eq!(give_up_after(TM_MAX_ATTEMPT), GIVE_UP_CAP_MS);
    }
}
