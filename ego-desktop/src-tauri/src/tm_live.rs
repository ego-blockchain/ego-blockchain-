use crate::chain_db::{tm_proposal_message, tm_signature_ok, tm_value_id, tm_vote_message, TmCert, TM_CERT_VERSION, TM_PRECOMMIT, TM_PREVOTE};
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
const WAL_FILE: &str = "consensus_wal.json";
const V2_LOCK_SECS: i64 = 90;
const V2_LOCK_KEEP: u64 = 200;

type Out = Vec<(P2PMessage, bool)>;

fn mono_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
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

fn wal_save_tm(saved: Saved, parent: &str) {
    let mut g = wal();
    let w = g.get_or_insert_with(Wal::default);
    w.tm = Some(saved);
    w.tm_parent = parent.to_string();
    wal_store(w);
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
    members: Vec<(String, Vec<u8>)>,
    me: Option<usize>,
    me_addr: String,
    kp: Option<Arc<ego_core::KeyPair>>,
    engine: Tendermint,
    names: HashMap<ValueId, String>,
    payloads: HashMap<ValueId, (LedgerBlock, Vec<LedgerTx>)>,
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
    last_resend: u64,
    last_status: u64,
    last_progress: u64,
}

static DRIVER: Mutex<Option<Driver>> = Mutex::new(None);
static FUTURE: Mutex<BTreeMap<u64, Vec<P2PMessage>>> = Mutex::new(BTreeMap::new());

fn driver() -> MutexGuard<'static, Option<Driver>> {
    DRIVER.lock().unwrap_or_else(|e| e.into_inner())
}

fn future() -> MutexGuard<'static, BTreeMap<u64, Vec<P2PMessage>>> {
    FUTURE.lock().unwrap_or_else(|e| e.into_inner())
}

impl Driver {
    fn build(height: u64) -> Option<Driver> {
        let (tip, tip_hash) = crate::chain_db::latest_block_info();
        if tip.saturating_add(1) != height {
            return None;
        }
        let members = crate::chain_db::committee_for_height(height, crate::clock::now())?;
        let parent_ts = crate::chain_db::get_block_by_height(tip).map(|b| b.timestamp).unwrap_or(0);
        let me_addr = crate::ledger::Ledger::load().address;
        let kp = signer();
        let mut me = members.iter().position(|(a, _)| *a == me_addr);
        if let Some(i) = me {
            let matches = kp.as_ref().map_or(false, |k| k.dilithium_public_key().key_data == members[i].1);
            if !matches {
                eprintln!("[Consensus] h={height}: this node is on the committee but its signing key is not the one registered on chain, so it only follows");
                me = None;
            }
        }
        let mut engine = Tendermint::new(height, members.len(), me, Timeouts::default());
        let mut restored = None;
        if me.is_some() {
            let g = wal();
            let parent_matches = g.as_ref().map_or(false, |w| w.tm_parent == tip_hash);
            if let Some(saved) = g.as_ref().and_then(|w| w.tm.clone()).filter(|_| parent_matches) {
                if saved.height == height {
                    engine.restore(&saved);
                    restored = Some(saved);
                }
            }
        }
        eprintln!(
            "[Consensus] h={height}: committee {} ({}), quorum {}, this node {}",
            members.len(),
            members.iter().map(|(a, _)| a.get(..14).unwrap_or(a)).collect::<Vec<_>>().join(" "),
            crate::chain_db::quorum_of(members.len()),
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
            members,
            me,
            me_addr,
            kp,
            engine,
            names: HashMap::new(),
            payloads: HashMap::new(),
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
            last_resend: now,
            last_status: now,
            last_progress: now,
        };
        if let Some(saved) = restored {
            eprintln!(
                "[Consensus] h={height}: resuming at round {} after a restart, locked on {}",
                saved.round,
                if saved.locked.is_some() { "a block" } else { "nothing" }
            );
        }
        Some(d)
    }

    fn index_of(&self, addr: &str) -> Option<usize> {
        self.members.iter().position(|(a, _)| a == addr)
    }

    fn vote_message(&self, kind: VoteKind, round: u32, value: Option<ValueId>) -> Option<P2PMessage> {
        let kp = self.kp.as_ref()?;
        let name = value.map(|v| self.names.get(&v).cloned().unwrap_or_else(|| hex::encode(v)));
        let code = code_of(kind);
        let sig = sign(kp, &tm_vote_message(code, self.height, round, name.as_deref()));
        Some(P2PMessage::TmVote {
            height: self.height,
            round,
            kind: code,
            value: name,
            voter: self.me_addr.clone(),
            sig,
        })
    }

    fn proposal_message(&self, round: u32, pol_round: Option<u32>, value: ValueId) -> Option<P2PMessage> {
        let kp = self.kp.as_ref()?;
        let (block, txs) = self.payloads.get(&value)?;
        let sig = sign(kp, &tm_proposal_message(self.height, round, pol_round, &block.hash));
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
        })
    }

    fn apply(&mut self, actions: Vec<Action>, now: u64, out: &mut Out) {
        let mut queue: VecDeque<Action> = actions.into();
        let mut persist = false;
        while let Some(action) = queue.pop_front() {
            match action {
                Action::Propose { round, pol_round, value } => match value {
                    Some(v) => match (self.me, self.proposal_message(round, pol_round, v)) {
                        (Some(me), Some(msg)) => {
                            eprintln!("[Consensus] h={} round {round}: offering again the block the committee backed in round {:?}", self.height, pol_round);
                            self.my_proposals.insert(round, msg.clone());
                            out.push((msg, true));
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
                        out.push((msg, true));
                        persist = true;
                    }
                }
                Action::Decide { round, value } => {
                    self.decided = Some((round, value));
                    self.last_progress = now;
                }
            }
        }
        if persist && self.me.is_some() {
            wal_save_tm(self.engine.saved(), &self.parent_hash);
        }
    }

    fn rebuild_votes_after_restart(&mut self) {
        let saved = self.engine.saved();
        for (round, kind, value) in saved.sent {
            if let Some(msg) = self.vote_message(kind, round, value) {
                if let (Some(v), Some(me), P2PMessage::TmVote { sig, .. }) = (value, self.me, &msg) {
                    self.sigs.entry((code_of(kind), round, v)).or_default().insert(me, sig.clone());
                }
                self.my_votes.insert((round, code_of(kind)), msg);
            }
        }
    }

    fn resend(&mut self, now: u64, out: &mut Out) {
        if now.saturating_sub(self.last_resend) < RESEND_MS {
            return;
        }
        self.last_resend = now;
        let round = self.engine.round();
        if let Some(m) = self.my_proposals.get(&round) {
            out.push((m.clone(), false));
        }
        for code in [TM_PREVOTE, TM_PRECOMMIT] {
            if let Some(m) = self.my_votes.get(&(round, code)) {
                out.push((m.clone(), false));
            }
        }
        if let Some((lr, lv)) = self.engine.locked() {
            if let Some(m) = self.proposal_msgs.get(&lv) {
                out.push((m.clone(), false));
            }
            if lr != round {
                if let Some(m) = self.my_votes.get(&(lr, TM_PRECOMMIT)) {
                    out.push((m.clone(), false));
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
            "h={} round {} step {:?}, committee {} quorum {}, {}, locked {}, waiting {}s",
            self.height,
            self.engine.round(),
            self.engine.step(),
            self.members.len(),
            crate::chain_db::quorum_of(self.members.len()),
            match self.me {
                Some(i) => format!("member {i}"),
                None => "following".into(),
            },
            if self.engine.locked().is_some() { "yes" } else { "no" },
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
    for (msg, gossip) in out {
        if gossip {
            crate::p2p::shadow_publish(&msg).await;
        }
        direct.push(msg);
    }
    crate::p2p::send_to_group(height, direct).await;
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
    let mut out = Out::new();
    {
        let mut g = driver();
        let Some(d) = g.as_mut() else { return true };
        let acts = d.engine.tick(now);
        d.apply(acts, now, &mut out);
        d.resend(now, &mut out);
    }
    flush(next, out).await;
    maybe_propose().await;
    maybe_commit().await;
    true
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

pub async fn on_message(msg: P2PMessage) {
    match msg {
        P2PMessage::TmProposal { height, round, pol_round, block, transactions, proposer, sig, pol_votes } => {
            on_proposal(height, round, pol_round, block, transactions, proposer, sig, pol_votes).await
        }
        P2PMessage::TmVote { height, round, kind, value, voter, sig } => {
            on_vote(height, round, kind, value, voter, sig).await
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
) {
    match route(height) {
        Route::Drop => return,
        Route::Later => {
            crate::p2p::note_network_height(height);
            hold(
                height,
                P2PMessage::TmProposal { height, round, pol_round, block, transactions, proposer, sig, pol_votes },
            );
            return;
        }
        Route::Now => {}
    }
    crate::p2p::note_network_height(height);
    let now = mono_ms();
    let mut out = Out::new();
    let mut check: Option<(ValueId, LedgerBlock, Vec<LedgerTx>, i64)> = None;
    {
        let mut g = driver();
        let Some(d) = g.as_mut() else { return };
        if d.height != height || pol_round.map_or(false, |p| p >= round) {
            return;
        }
        let idx = d.engine.proposer(round);
        let Some((addr, pk)) = d.members.get(idx).cloned() else { return };
        if addr != proposer || block.height != height || block.prev_hash != d.parent_hash {
            return;
        }
        if !tm_signature_ok(&pk, &tm_proposal_message(height, round, pol_round, &block.hash), &sig) {
            eprintln!("[Consensus] h={height} round {round}: proposal from {:.14} does not verify", proposer);
            return;
        }
        let v = tm_value_id(&block.hash);
        d.names.entry(v).or_insert_with(|| block.hash.clone());
        let mut acts = Vec::new();
        if let Some(vr) = pol_round {
            let msg = tm_vote_message(TM_PREVOTE, height, vr, Some(&block.hash));
            for (voter, s) in &pol_votes {
                let Some(j) = d.index_of(voter) else { continue };
                if tm_signature_ok(&d.members[j].1, &msg, s) {
                    d.sigs.entry((TM_PREVOTE, vr, v)).or_default().insert(j, s.clone());
                    acts.extend(d.engine.on_vote(now, VoteKind::Prevote, vr, j, Some(v)));
                }
            }
        }
        let full = P2PMessage::TmProposal {
            height,
            round,
            pol_round,
            block: block.clone(),
            transactions: transactions.clone(),
            proposer: proposer.clone(),
            sig: sig.clone(),
            pol_votes: pol_votes.clone(),
        };
        d.proposal_msgs.entry(v).or_insert(full);
        d.payloads.entry(v).or_insert_with(|| (block.clone(), transactions.clone()));
        match d.verdicts.get(&v).copied() {
            Some(ok) => acts.extend(d.engine.on_proposal(now, round, idx, v, pol_round, ok)),
            None => {
                d.waiting.push(Waiting { round, from: idx, value: v, pol_round });
                if d.checking.insert(v) {
                    check = Some((v, block, transactions, d.parent_ts));
                }
            }
        }
        d.apply(acts, now, &mut out);
    }
    flush(height, out).await;
    if let Some((v, b, t, parent_ts)) = check {
        let verdict = tokio::task::spawn_blocking(move || crate::chain_db::validate_tm_block(&b, &t, parent_ts))
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

async fn on_vote(height: u64, round: u32, kind: u8, value: Option<String>, voter: String, sig: String) {
    match route(height) {
        Route::Drop => return,
        Route::Later => {
            hold(height, P2PMessage::TmVote { height, round, kind, value, voter, sig });
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
        let Some(j) = d.index_of(&voter) else { return };
        if Some(j) == d.me {
            return;
        }
        if !tm_signature_ok(&d.members[j].1, &tm_vote_message(kind, height, round, value.as_deref()), &sig) {
            return;
        }
        let v = value.as_deref().map(tm_value_id);
        if let (Some(v), Some(name)) = (v, value.as_ref()) {
            d.names.entry(v).or_insert_with(|| name.clone());
            d.sigs.entry((kind, round, v)).or_default().insert(j, sig);
        }
        let acts = d.engine.on_vote(now, k, round, j, v);
        d.apply(acts, now, &mut out);
    }
    flush(height, out).await;
    maybe_commit().await;
}

async fn maybe_propose() {
    let job = {
        let mut g = driver();
        let Some(d) = g.as_mut() else { return };
        let Some(round) = d.pending_propose else { return };
        if d.building {
            return;
        }
        if d.engine.round() != round || d.engine.step() != Step::Propose || d.decided.is_some() {
            d.pending_propose = None;
            return;
        }
        let due = round > 0
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
        (d.height, round, d.parent_hash.clone(), d.parent_ts)
    };
    let (height, round, parent_hash, parent_ts) = job;
    let built = crate::p2p::build_live_candidate().await;
    let checked = match built {
        Some((block, txs)) if block.height == height && block.prev_hash == parent_hash => {
            let (b, t) = (block.clone(), txs.clone());
            let verdict = tokio::task::spawn_blocking(move || crate::chain_db::validate_tm_block(&b, &t, parent_ts))
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
        if d.pending_propose != Some(round) || d.engine.round() != round || d.engine.step() != Step::Propose {
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
        out.push((msg, true));
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
        let quorum = crate::chain_db::quorum_of(d.members.len());
        let Some(votes) = d.sigs.get(&(TM_PRECOMMIT, round, v)) else { return };
        if votes.len() < quorum {
            return;
        }
        let chosen: Vec<(String, String)> = votes
            .iter()
            .take(quorum)
            .map(|(j, s)| (d.members[*j].0.clone(), s.clone()))
            .collect();
        let cert = TmCert { v: TM_CERT_VERSION, round, votes: chosen };
        let mut block = block;
        block.commit_cert = serde_json::to_string(&cert).unwrap_or_default();
        d.committing = true;
        (d.height, round, block, txs, quorum as u32)
    };
    let (height, round, block, txs, count) = job;
    let (b, t) = (block.clone(), txs.clone());
    let persisted = tokio::task::spawn_blocking(move || crate::chain_db::commit_staged_block(&b, &t, count))
        .await
        .unwrap_or(false);
    if persisted {
        eprintln!("[Consensus] finalized h={height} in round {round} with {count} commit votes, block {:.12}", block.hash);
        crate::p2p::LAST_BLOCK_FINALIZED_TS.store(chrono::Utc::now().timestamp(), std::sync::atomic::Ordering::Relaxed);
        crate::clock::note_finalized_block_time(block.timestamp);
        crate::p2p::touch_proposal_timestamp();
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

    #[test]
    fn the_new_messages_travel_under_their_own_names() {
        let vote = P2PMessage::TmVote {
            height: 33_101,
            round: 2,
            kind: TM_PRECOMMIT,
            value: Some("ab".repeat(32)),
            voter: "egot1x".into(),
            sig: "c2ln".into(),
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
}
