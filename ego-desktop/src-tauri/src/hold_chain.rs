use crate::dao_chain::Fit;
use crate::drs::Ov;
use crate::ledger::{LedgerBlock, LedgerTx};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const ACTIVATION_HEIGHT: Option<u64> = None;

pub const TX_REQUEST: &str = "hold_request";
pub const TX_VOTE: &str = "hold_vote";
pub const TX_NODE_VOTE: &str = "hold_node_vote";
pub const TX_APPEAL: &str = "hold_appeal";
pub const TX_RETURN: &str = "hold_return";
pub const TX_CERT: &str = "hold_cert";
pub const TX_SETTLE: &str = "hold_settle";
pub const USER_TYPES: [&str; 5] = [TX_REQUEST, TX_VOTE, TX_NODE_VOTE, TX_APPEAL, TX_RETURN];
pub const PHASE_CONFIRM: &str = "confirm";
pub const PHASE_RETURN: &str = "return";

pub const MIN_NODE_POOL: u64 = 64;
pub const REQUEST_FEE_UEGOC: u64 = 10_000_000;
pub const MIN_BOND_UEGOC: u64 = 100_000_000;
pub const SIGN_WINDOW_SECS: i64 = 3_600;
pub const VOTE_SECS: i64 = 72 * 3_600;
pub const CONFIRM_SECS: i64 = 90 * 86_400;
pub const COOLDOWN_SECS: i64 = 30 * 86_400;
pub const FILE_WINDOW_SECS: i64 = 30 * 86_400;
pub const MAX_TXS: usize = 64;
pub const MAX_HELD: usize = 32;
pub const MAX_HOLDS_PER_ADDR: usize = 8;
pub const MAX_LIVE: usize = 256;
pub const MAX_TEXT_BYTES: usize = 2_000;
pub const MAX_BODY_BYTES: usize = 16_384;
pub const MIN_VOTERS: u64 = 3;
pub const MIN_STAKE_PERCENT: u128 = 1;
pub const MIN_NODE_PERCENT: u128 = 5;

const BODY_DOMAIN: &[u8] = b"ego/hold/body/v1:";
const CERT_DOMAIN: &[u8] = b"ego/hold/cert/v1:";
const ID_DOMAIN: &[u8] = b"ego/hold/id/v1:";
const SETTLE_DOMAIN: &[u8] = b"ego/hold/settle/v1:";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestBody {
    pub victim: String,
    pub theft: Vec<String>,
    #[serde(default)]
    pub hops: Vec<String>,
    pub case: String,
    pub bond: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteBody {
    pub id: String,
    pub phase: String,
    pub yes: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppealBody {
    pub id: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdBody {
    pub id: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldBody {
    pub id: String,
    pub amounts: Vec<(String, u64)>,
}

impl HoldBody {
    pub fn message(&self) -> Vec<u8> {
        let mut m = CERT_DOMAIN.to_vec();
        m.extend_from_slice(blake3::hash(&serde_json::to_vec(self).unwrap_or_default()).as_bytes());
        m
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldCert {
    pub body: HoldBody,
    #[serde(default)]
    pub signers: Vec<u32>,
    #[serde(default)]
    pub sig: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hold {
    pub id: String,
    pub requester: String,
    pub request: RequestBody,
    pub created: i64,
    pub height: u64,
    pub keys: Vec<String>,
    #[serde(default)]
    pub amounts: Vec<(String, u64)>,
    #[serde(default)]
    pub held_at: i64,
    #[serde(default)]
    pub stake_total: u64,
    #[serde(default)]
    pub node_total: u64,
    #[serde(default)]
    pub appeals: Vec<(String, String)>,
    #[serde(default)]
    pub return_opened: i64,
    #[serde(default)]
    pub paid: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tally {
    pub stake_yes: u64,
    pub stake_no: u64,
    pub stake_voters: u64,
    pub node_yes: u64,
    pub node_no: u64,
    pub node_voters: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Pass,
    Fail,
    NoQuorum,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Signing,
    Failed,
    Voting,
    Confirmed,
    ReturnVoting,
    Returned,
    Rejected,
    Lapsed,
    Expired,
}

pub fn rule_active(height: u64) -> bool {
    ACTIVATION_HEIGHT.is_some_and(|h| height >= h)
}

pub fn rule_active_at_tip() -> bool {
    rule_active(crate::chain_db::local_chain_height().saturating_add(1))
}

pub fn is_hold_op(tx: &LedgerTx) -> bool {
    USER_TYPES.contains(&tx.tx_type.as_str())
}

pub fn body_hash(call_args: &str) -> String {
    let mut m = BODY_DOMAIN.to_vec();
    m.extend_from_slice(call_args.as_bytes());
    blake3::hash(&m).to_hex().to_string()
}

pub fn memo_for(tx_type: &str, call_args: &str) -> Option<String> {
    if !USER_TYPES.contains(&tx_type) {
        return None;
    }
    let op = tx_type.strip_prefix("hold_")?;
    Some(format!("hold:{op}:{}", body_hash(call_args)))
}

pub fn hold_id(tx_hash: &str) -> String {
    let mut m = ID_DOMAIN.to_vec();
    m.extend_from_slice(tx_hash.as_bytes());
    format!("hold{}", &blake3::hash(&m).to_hex()[..16])
}

fn is_id(s: &str) -> bool {
    s.len() == 20 && s.starts_with("hold") && s[4..].bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_tx_hash(s: &str) -> bool {
    s.len() == 66 && s.starts_with("0x") && s[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

fn valid_addr(s: &str) -> bool {
    (s.starts_with("egot1") || s.starts_with("ego1"))
        && (20..=100).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

pub fn check_request(from: &str, b: &RequestBody) -> Result<(), String> {
    if !valid_addr(&b.victim) {
        return Err("the request names no victim".into());
    }
    if b.theft.is_empty() || b.theft.len() + b.hops.len() > MAX_TXS {
        return Err(format!("a request lists between 1 and {MAX_TXS} transactions"));
    }
    let mut seen = BTreeSet::new();
    if !b.theft.iter().chain(&b.hops).all(|h| is_tx_hash(h) && seen.insert(h.as_str())) {
        return Err("each listed transaction is a distinct transaction hash".into());
    }
    if b.case.trim().is_empty() || b.case.len() > MAX_TEXT_BYTES {
        return Err(format!("the case is between 1 and {MAX_TEXT_BYTES} bytes"));
    }
    if b.bond < MIN_BOND_UEGOC {
        return Err(format!("the bond is at least {} EGOC", MIN_BOND_UEGOC / 1_000_000));
    }
    if from.is_empty() {
        return Err("the request has no sender".into());
    }
    Ok(())
}

pub fn well_formed(tx: &LedgerTx) -> Result<(), String> {
    if !is_hold_op(tx) {
        return Err(format!("{} is not a hold transaction", tx.tx_type));
    }
    if tx.from.is_empty() || tx.to != tx.from || tx.amount != 0 {
        return Err("a hold transaction is a zero-amount transaction to the sender itself".into());
    }
    if tx.call_args.len() > MAX_BODY_BYTES {
        return Err(format!("the body is longer than {MAX_BODY_BYTES} bytes"));
    }
    if tx.memo != memo_for(&tx.tx_type, &tx.call_args) {
        return Err("the memo does not commit to the body".into());
    }
    let unreadable = |e: serde_json::Error| format!("the body is not readable: {e}");
    match tx.tx_type.as_str() {
        TX_REQUEST => {
            if tx.fee_uegoc < REQUEST_FEE_UEGOC {
                return Err(format!("a hold request burns a fee of at least {} EGOC", REQUEST_FEE_UEGOC / 1_000_000));
            }
            check_request(&tx.from, &serde_json::from_str(&tx.call_args).map_err(unreadable)?)
        }
        TX_VOTE | TX_NODE_VOTE => {
            let b: VoteBody = serde_json::from_str(&tx.call_args).map_err(unreadable)?;
            if !is_id(&b.id) || !(b.phase == PHASE_CONFIRM || b.phase == PHASE_RETURN) {
                return Err("the vote names no hold or phase".into());
            }
            Ok(())
        }
        TX_APPEAL => {
            let b: AppealBody = serde_json::from_str(&tx.call_args).map_err(unreadable)?;
            if !is_id(&b.id) || b.text.trim().is_empty() || b.text.len() > MAX_TEXT_BYTES {
                return Err(format!("an appeal names a hold and says why in at most {MAX_TEXT_BYTES} bytes"));
            }
            Ok(())
        }
        _ => {
            let b: IdBody = serde_json::from_str(&tx.call_args).map_err(unreadable)?;
            if !is_id(&b.id) {
                return Err("the request names no hold".into());
            }
            Ok(())
        }
    }
}

fn key(parts: std::fmt::Arguments) -> Vec<u8> {
    format!("hold:{parts}").into_bytes()
}

fn hold_key(id: &str) -> Vec<u8> {
    key(format_args!("r:{id}"))
}

fn addr_key(addr: &str) -> Vec<u8> {
    key(format_args!("a:{addr}"))
}

fn bond_key(addr: &str) -> Vec<u8> {
    key(format_args!("b:{addr}"))
}

fn lock_key(addr: &str) -> Vec<u8> {
    key(format_args!("lock:{addr}"))
}

fn tally_key(id: &str, phase: &str) -> Vec<u8> {
    key(format_args!("t:{id}:{phase}"))
}

fn vote_key(id: &str, phase: &str, kind: &str, voter: &str) -> Vec<u8> {
    key(format_args!("v:{id}:{phase}:{kind}:{voter}"))
}

const LIVE_KEY: &[u8] = b"hold:live";

fn load<T: for<'de> Deserialize<'de>>(ov: &Ov, k: &[u8]) -> Option<T> {
    ov.get(k).and_then(|v| serde_json::from_slice(&v).ok())
}

fn save<T: Serialize>(ov: &mut Ov, k: Vec<u8>, v: &T) {
    ov.put(k, serde_json::to_vec(v).unwrap_or_default());
}

pub fn load_hold(ov: &Ov, id: &str) -> Option<Hold> {
    load(ov, &hold_key(id))
}

pub fn live(ov: &Ov) -> Vec<String> {
    load(ov, LIVE_KEY).unwrap_or_default()
}

pub fn my_vote(ov: &Ov, id: &str, phase: &str, node: bool, voter: &str) -> Option<bool> {
    ov.get(&vote_key(id, phase, if node { "n" } else { "s" }, voter)).map(|v| v.first() == Some(&1))
}

pub fn tally(ov: &Ov, id: &str, phase: &str) -> Tally {
    load(ov, &tally_key(id, phase)).unwrap_or_default()
}

pub fn outcome(t: &Tally, h: &Hold) -> Outcome {
    let stake_cast = t.stake_yes.saturating_add(t.stake_no);
    let node_cast = t.node_yes.saturating_add(t.node_no);
    let stake_quorum = t.stake_voters >= MIN_VOTERS && stake_cast as u128 * 100 >= h.stake_total as u128 * MIN_STAKE_PERCENT;
    let node_quorum = t.node_voters >= MIN_VOTERS && node_cast as u128 * 100 >= h.node_total as u128 * MIN_NODE_PERCENT;
    if !(stake_quorum && node_quorum) {
        return Outcome::NoQuorum;
    }
    let two_thirds = |yes: u64, cast: u64| yes as u128 * 3 >= cast as u128 * 2;
    if two_thirds(t.stake_yes, stake_cast) && two_thirds(t.node_yes, node_cast) {
        Outcome::Pass
    } else {
        Outcome::Fail
    }
}

pub fn vote_end(h: &Hold) -> i64 {
    h.held_at.saturating_add(VOTE_SECS)
}

pub fn phase(ov: &Ov, h: &Hold, now: i64) -> Phase {
    if h.held_at == 0 {
        return if now < h.created.saturating_add(SIGN_WINDOW_SECS) { Phase::Signing } else { Phase::Failed };
    }
    if now < vote_end(h) {
        return Phase::Voting;
    }
    match outcome(&tally(ov, &h.id, PHASE_CONFIRM), h) {
        Outcome::Fail => return Phase::Rejected,
        Outcome::NoQuorum => return Phase::Lapsed,
        Outcome::Pass => {}
    }
    if h.return_opened > 0 {
        if now < h.return_opened.saturating_add(VOTE_SECS) {
            return Phase::ReturnVoting;
        }
        if outcome(&tally(ov, &h.id, PHASE_RETURN), h) == Outcome::Pass {
            return Phase::Returned;
        }
    }
    if now < vote_end(h).saturating_add(CONFIRM_SECS) {
        Phase::Confirmed
    } else {
        Phase::Expired
    }
}

pub fn ended_at(ov: &Ov, h: &Hold) -> i64 {
    match phase(ov, h, i64::MAX) {
        Phase::Failed => h.created.saturating_add(SIGN_WINDOW_SECS),
        Phase::Rejected | Phase::Lapsed => vote_end(h),
        _ => i64::MAX,
    }
}

fn holds_coins(p: Phase, h: &Hold) -> bool {
    matches!(p, Phase::Voting | Phase::Confirmed | Phase::ReturnVoting) || (p == Phase::Returned && !h.paid)
}

fn binds_bond(p: Phase, h: &Hold) -> bool {
    matches!(p, Phase::Signing | Phase::Voting) || (p == Phase::Rejected && !h.paid)
}

pub fn held_on(ov: &Ov, addr: &str, now: i64) -> u64 {
    let ids: Vec<String> = load(ov, &addr_key(addr)).unwrap_or_default();
    ids.iter()
        .filter_map(|id| load_hold(ov, id))
        .filter(|h| holds_coins(phase(ov, h, now), h))
        .map(|h| h.amounts.iter().filter(|(a, _)| a == addr).map(|(_, n)| *n).sum::<u64>())
        .fold(0u64, |acc, n| acc.saturating_add(n))
}

pub fn bond_on(ov: &Ov, addr: &str, now: i64) -> u64 {
    let Some(id) = load::<String>(ov, &bond_key(addr)) else { return 0 };
    let Some(h) = load_hold(ov, &id) else { return 0 };
    if binds_bond(phase(ov, &h, now), &h) {
        h.request.bond
    } else {
        0
    }
}

pub fn locked(ov: &Ov, addr: &str, now: i64) -> u64 {
    held_on(ov, addr, now).saturating_add(bond_on(ov, addr, now))
}

pub fn stake_locked_until(ov: &Ov, addr: &str) -> i64 {
    load(ov, &lock_key(addr)).unwrap_or(0)
}

fn cooling(ov: &Ov, addr: &str, now: i64) -> bool {
    let ids: Vec<String> = load(ov, &addr_key(addr)).unwrap_or_default();
    ids.iter().filter_map(|id| load_hold(ov, id)).any(|h| {
        let end = ended_at(ov, &h);
        end != i64::MAX && h.held_at > 0 && now < end.saturating_add(COOLDOWN_SECS)
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settlement {
    pub from: String,
    pub to: String,
    pub owed: u64,
}

pub fn settlements(ov: &Ov, h: &Hold, now: i64) -> Vec<Settlement> {
    if h.paid {
        return Vec::new();
    }
    match phase(ov, h, now) {
        Phase::Rejected => {
            let target = h.amounts.iter().max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0))).map(|(a, _)| a.clone());
            target
                .map(|to| vec![Settlement { from: h.requester.clone(), to, owed: h.request.bond }])
                .unwrap_or_default()
        }
        Phase::Returned => h
            .amounts
            .iter()
            .map(|(a, n)| Settlement { from: a.clone(), to: h.request.victim.clone(), owed: *n })
            .collect(),
        _ => Vec::new(),
    }
}

pub fn settle_hash(id: &str, index: usize, from: &str, to: &str, amount: u64) -> String {
    let mut m = SETTLE_DOMAIN.to_vec();
    m.extend_from_slice(format!("{id}:{index}:{from}:{to}:{amount}").as_bytes());
    format!("0x{}", blake3::hash(&m).to_hex())
}

pub fn settle_memo(id: &str, index: usize) -> String {
    format!("hold:settle:{id}:{index}")
}

fn settle_parts(tx: &LedgerTx) -> Option<(String, usize)> {
    let rest = tx.memo.as_deref()?.strip_prefix("hold:settle:")?;
    let (id, i) = rest.rsplit_once(':')?;
    Some((id.to_string(), i.parse().ok()?))
}

pub fn is_settle(tx: &LedgerTx) -> bool {
    tx.tx_type == TX_SETTLE
}

pub fn settle_is_well_formed(tx: &LedgerTx) -> bool {
    is_settle(tx)
        && tx.signature == "hold"
        && tx.tx_version == 3
        && tx.nonce == 0
        && tx.fee_uegoc == 0
        && tx.priority_fee_uegoc == 0
        && tx.amount > 0
        && settle_parts(tx).is_some_and(|(id, i)| tx.hash == settle_hash(&id, i, &tx.from, &tx.to, tx.amount))
}

pub fn settle_txs(ov: &Ov, height: u64, now: i64, balance: &dyn Fn(&str) -> u64) -> Vec<LedgerTx> {
    if !rule_active(height) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for id in live(ov) {
        let Some(h) = load_hold(ov, &id) else { continue };
        for (i, s) in settlements(ov, &h, now).into_iter().enumerate() {
            let amount = s.owed.min(balance(&s.from));
            if amount == 0 {
                continue;
            }
            out.push(LedgerTx {
                hash: settle_hash(&id, i, &s.from, &s.to, amount),
                from: s.from,
                to: s.to,
                amount,
                memo: Some(settle_memo(&id, i)),
                timestamp: now,
                status: "Confirmed".into(),
                block_height: Some(height),
                tx_type: TX_SETTLE.into(),
                signature: "hold".into(),
                tx_version: 3,
                chain_id: 1,
                ..LedgerTx::default()
            });
        }
    }
    out
}

pub fn is_cert_tx(tx: &LedgerTx) -> bool {
    tx.tx_type == TX_CERT
        && tx.from.is_empty()
        && tx.to == crate::chain_db::NODE_POOL_ADDR
        && tx.amount == 0
        && tx.signature == "coinbase"
}

pub fn check_amounts(h: &Hold, amounts: &[(String, u64)]) -> Result<(), String> {
    if amounts.is_empty() || amounts.len() > MAX_HELD {
        return Err(format!("a hold covers between 1 and {MAX_HELD} addresses"));
    }
    let mut seen = BTreeSet::new();
    let mut total: u64 = 0;
    for (a, n) in amounts {
        if !valid_addr(a) || a == &h.request.victim || *n == 0 || !seen.insert(a.as_str()) {
            return Err("each held address appears once, is not the victim and holds a positive amount".into());
        }
        total = total.saturating_add(*n);
    }
    let _ = total;
    Ok(())
}

pub fn verify_cert(cert: &HoldCert, keys: &[String]) -> Result<(), String> {
    let quorum = crate::state_cert::quorum(keys.len());
    if keys.is_empty() || cert.signers.len() < quorum {
        return Err(format!("the hold has {} of the {} committee signatures it needs", cert.signers.len(), quorum));
    }
    if cert.signers.windows(2).any(|w| w[0] >= w[1]) || cert.signers.iter().any(|p| *p as usize >= keys.len()) {
        return Err("the hold lists its signers out of order or out of range".into());
    }
    let pks: Vec<Vec<u8>> = cert.signers.iter().filter_map(|p| hex::decode(&keys[*p as usize]).ok()).collect();
    let sig = hex::decode(&cert.sig).map_err(|_| "the hold signature is not hex".to_string())?;
    if pks.len() != cert.signers.len() || !crate::bls_agg::verify_shared_aggregate(&sig, &pks, &cert.body.message()) {
        return Err("the hold signature does not verify".into());
    }
    Ok(())
}

pub fn vote_ok(body: &HoldBody, signer: &str, sig: &str, keys: &[String]) -> bool {
    keys.iter().any(|k| k == signer)
        && match (hex::decode(signer), hex::decode(sig)) {
            (Ok(pk), Ok(s)) => crate::bls_agg::verify_shared(&s, &pk, &body.message()),
            _ => false,
        }
}

pub fn assemble(body: &HoldBody, votes: &[(String, String)], keys: &[String]) -> Option<HoldCert> {
    let mut picked: Vec<(u32, Vec<u8>)> = keys
        .iter()
        .enumerate()
        .filter_map(|(i, k)| {
            let (_, sig) = votes.iter().find(|(s, g)| s == k && vote_ok(body, s, g, keys))?;
            Some((i as u32, hex::decode(sig).ok()?))
        })
        .collect();
    picked.sort_by_key(|(i, _)| *i);
    let sigs: Vec<Vec<u8>> = picked.iter().map(|(_, s)| s.clone()).collect();
    let agg = crate::bls_agg::aggregate_shared(&sigs)?;
    let cert = HoldCert { body: body.clone(), signers: picked.iter().map(|(i, _)| *i).collect(), sig: hex::encode(agg) };
    verify_cert(&cert, keys).ok().map(|_| cert)
}

fn subject(tx: &LedgerTx) -> bool {
    !tx.from.is_empty()
        && !crate::ledger::is_reserved_system_source(&tx.from)
        && tx.signature != "coinbase"
        && !is_settle(tx)
}

pub fn outflow(tx: &LedgerTx) -> u64 {
    if crate::chain_db::is_unstake_tx(tx) || tx.to == tx.from {
        tx.fee_uegoc
    } else {
        tx.amount.saturating_add(tx.fee_uegoc)
    }
}

pub struct Planner {
    height: u64,
    now: i64,
    spent: BTreeMap<String, u64>,
    requests: BTreeSet<String>,
    certs: BTreeSet<String>,
    voters: BTreeSet<String>,
}

impl Planner {
    pub fn new(height: u64, now: i64) -> Self {
        Self { height, now, spent: BTreeMap::new(), requests: BTreeSet::new(), certs: BTreeSet::new(), voters: BTreeSet::new() }
    }

    pub fn fit(&mut self, ov: &Ov, tx: &LedgerTx, balance: &dyn Fn(&str) -> u64) -> Fit {
        let active = rule_active(self.height);
        if is_hold_op(tx) || is_cert_tx(tx) || is_settle(tx) {
            if !active {
                return Fit::Later(format!("theft holds start at block {:?}", ACTIVATION_HEIGHT));
            }
        }
        if !active {
            return Fit::Yes;
        }
        self.judge(ov, tx, balance)
    }

    fn judge(&mut self, ov: &Ov, tx: &LedgerTx, balance: &dyn Fn(&str) -> u64) -> Fit {
        let now = self.now;
        if is_hold_op(tx) {
            if let Err(e) = well_formed(tx) {
                return Fit::Never(e);
            }
            if tx.tx_type == TX_VOTE {
                self.voters.insert(tx.from.clone());
            }
        }
        if is_cert_tx(tx) {
            return match self.check_cert(ov, tx) {
                Ok(()) => Fit::Yes,
                Err(e) => Fit::Never(e),
            };
        }
        if is_settle(tx) {
            return Fit::Yes;
        }
        if crate::chain_db::is_unstake_tx(tx) {
            if self.voters.contains(&tx.from) {
                return Fit::Later("the sender votes on a hold with this stake in this block".into());
            }
            if stake_locked_until(ov, &tx.from) > now {
                return Fit::Later("the stake is locked by a hold vote".into());
            }
        }
        if !subject(tx) {
            return Fit::Yes;
        }
        let mut need = locked(ov, &tx.from, now);
        if tx.tx_type == TX_REQUEST {
            if let Ok(b) = serde_json::from_str::<RequestBody>(&tx.call_args) {
                if !self.requests.insert(tx.from.clone()) || bond_on(ov, &tx.from, now) > 0 {
                    return Fit::Never("the sender already has an open hold request".into());
                }
                need = need.saturating_add(b.bond);
            }
        }
        if need == 0 && !self.requests.contains(&tx.from) {
            return Fit::Yes;
        }
        let spent = self.spent.get(&tx.from).copied().unwrap_or(0).saturating_add(outflow(tx));
        if balance(&tx.from).saturating_sub(spent) < need {
            return Fit::Later("the coins are held by a theft hold or a hold bond".into());
        }
        self.spent.insert(tx.from.clone(), spent);
        Fit::Yes
    }

    fn check_cert(&mut self, ov: &Ov, tx: &LedgerTx) -> Result<(), String> {
        if tx.hash != crate::drs::batch_hash(TX_CERT, self.height, &tx.call_args) {
            return Err("the hold certificate is not bound to this block".into());
        }
        let cert: HoldCert = serde_json::from_str(&tx.call_args).map_err(|e| format!("the hold certificate is unreadable: {e}"))?;
        if !self.certs.insert(cert.body.id.clone()) {
            return Err("one certificate per hold".into());
        }
        let h = load_hold(ov, &cert.body.id).ok_or("the certificate names no hold")?;
        if phase(ov, &h, self.now) != Phase::Signing {
            return Err("the hold is not waiting for its committee".into());
        }
        check_amounts(&h, &cert.body.amounts)?;
        verify_cert(&cert, &h.keys)
    }
}

pub fn validate(ov: &Ov, block: &LedgerBlock, txs: &[LedgerTx], balance: &dyn Fn(&str) -> u64) -> Result<(), String> {
    let active = rule_active(block.height);
    let mut plan = Planner::new(block.height, block.timestamp);
    for tx in txs {
        if !active && (is_hold_op(tx) || is_cert_tx(tx) || is_settle(tx)) {
            return Err(format!("{} {} refused: theft holds are not active at block {}", tx.tx_type, tx.hash, block.height));
        }
        match plan.fit(ov, tx, balance) {
            Fit::Yes => {}
            Fit::Later(e) | Fit::Never(e) => return Err(format!("{} {} refused: {e}", tx.tx_type, tx.hash)),
        }
    }
    if !active {
        return Ok(());
    }
    let settles: Vec<&LedgerTx> = txs.iter().filter(|t| is_settle(t)).collect();
    if settles.is_empty() {
        return Ok(());
    }
    let mut expected: BTreeMap<String, LedgerTx> = BTreeMap::new();
    for tx in settle_txs(ov, block.height, block.timestamp, balance) {
        expected.insert(tx.hash.clone(), tx);
    }
    let mut by_hold: BTreeMap<String, usize> = BTreeMap::new();
    for tx in &settles {
        if !settle_is_well_formed(tx) {
            return Err(format!("hold settlement {} is malformed", tx.hash));
        }
        let e = expected.get(&tx.hash).ok_or_else(|| format!("hold settlement {} is not due", tx.hash))?;
        if e.from != tx.from || e.to != tx.to || e.amount != tx.amount {
            return Err(format!("hold settlement {} does not match what is due", tx.hash));
        }
        let (id, _) = settle_parts(tx).unwrap_or_default();
        *by_hold.entry(id).or_insert(0) += 1;
    }
    for (id, n) in by_hold {
        let due = expected.values().filter(|t| settle_parts(t).is_some_and(|(i, _)| i == id)).count();
        if n != due {
            return Err(format!("hold {id} settles {n} of its {due} payments; all go in one block"));
        }
    }
    Ok(())
}

fn add_live(ov: &mut Ov, id: &str, now: i64) -> Result<(), String> {
    let mut ids = live(ov);
    if ids.len() >= MAX_LIVE {
        ids.retain(|i| {
            load_hold(ov, i).is_some_and(|h| {
                let p = phase(ov, &h, now);
                !matches!(p, Phase::Failed | Phase::Lapsed | Phase::Expired) && !(matches!(p, Phase::Rejected | Phase::Returned) && h.paid)
            })
        });
    }
    if ids.len() >= MAX_LIVE {
        return Err("too many holds are open across the network right now".into());
    }
    ids.push(id.to_string());
    save(ov, LIVE_KEY.to_vec(), &ids);
    Ok(())
}

fn op_request(ov: &mut Ov, block: &LedgerBlock, tx: &LedgerTx) -> Result<(), String> {
    let b: RequestBody = serde_json::from_str(&tx.call_args).map_err(|e| e.to_string())?;
    if crate::drs::node_count(ov) < MIN_NODE_POOL {
        return Err(format!("theft holds need at least {MIN_NODE_POOL} nodes in the pool"));
    }
    if bond_on(ov, &tx.from, block.timestamp) > 0 {
        return Err("the sender already has an open hold request".into());
    }
    let keys = crate::state_cert::draw_answering(ov, block.height);
    if keys.len() < 4 {
        return Err("no committee can be drawn for a hold right now".into());
    }
    let id = hold_id(&tx.hash);
    if load_hold(ov, &id).is_some() {
        return Err("this hold exists".into());
    }
    add_live(ov, &id, block.timestamp)?;
    let h = Hold {
        id: id.clone(),
        requester: tx.from.clone(),
        request: b,
        created: block.timestamp,
        height: block.height,
        keys,
        ..Hold::default()
    };
    save(ov, hold_key(&id), &h);
    save(ov, bond_key(&tx.from), &id);
    Ok(())
}

fn apply_cert(ov: &mut Ov, block: &LedgerBlock, tx: &LedgerTx, staked: u64) -> Result<(), String> {
    let cert: HoldCert = serde_json::from_str(&tx.call_args).map_err(|e| e.to_string())?;
    let mut h = load_hold(ov, &cert.body.id).ok_or("no such hold")?;
    let now = block.timestamp;
    let mut amounts = Vec::new();
    for (a, n) in cert.body.amounts {
        if cooling(ov, &a, now) {
            continue;
        }
        let mut ids: Vec<String> = load(ov, &addr_key(&a)).unwrap_or_default();
        ids.retain(|i| {
            load_hold(ov, i).is_some_and(|o| {
                let end = ended_at(ov, &o);
                end == i64::MAX || now < end.saturating_add(COOLDOWN_SECS)
            })
        });
        if ids.len() >= MAX_HOLDS_PER_ADDR {
            continue;
        }
        ids.push(h.id.clone());
        save(ov, addr_key(&a), &ids);
        amounts.push((a, n));
    }
    h.amounts = amounts;
    h.held_at = now;
    h.stake_total = staked;
    h.node_total = crate::drs::total_weight(ov, crate::drs::period_of(block.height));
    save(ov, hold_key(&h.id), &h);
    Ok(())
}

fn op_vote(ov: &mut Ov, block: &LedgerBlock, tx: &LedgerTx, node: bool) -> Result<(), String> {
    let b: VoteBody = serde_json::from_str(&tx.call_args).map_err(|e| e.to_string())?;
    let h = load_hold(ov, &b.id).ok_or("no such hold")?;
    let now = block.timestamp;
    let p = phase(ov, &h, now);
    let (open, ends) = match b.phase.as_str() {
        PHASE_CONFIRM => (p == Phase::Voting, vote_end(&h)),
        _ => (p == Phase::ReturnVoting, h.return_opened.saturating_add(VOTE_SECS)),
    };
    if !open {
        return Err("that vote is not open".into());
    }
    let kind = if node { "n" } else { "s" };
    let vk = vote_key(&h.id, &b.phase, kind, &tx.from);
    if ov.get(&vk).is_some() {
        return Err("already voted".into());
    }
    let weight = if node {
        let rec = crate::drs::load_rec(ov, &tx.from).ok_or("only a node in the pool casts a node vote")?;
        rec.weight.at(crate::drs::period_of(block.height))
    } else {
        crate::dao_chain::stake_of(ov, &tx.from)
    };
    if weight == 0 {
        return Err("a vote needs weight".into());
    }
    let mut t = tally(ov, &h.id, &b.phase);
    if node {
        t.node_voters += 1;
        if b.yes { t.node_yes = t.node_yes.saturating_add(weight) } else { t.node_no = t.node_no.saturating_add(weight) }
    } else {
        t.stake_voters += 1;
        if b.yes { t.stake_yes = t.stake_yes.saturating_add(weight) } else { t.stake_no = t.stake_no.saturating_add(weight) }
        let until = stake_locked_until(ov, &tx.from).max(ends);
        save(ov, lock_key(&tx.from), &until);
    }
    save(ov, tally_key(&h.id, &b.phase), &t);
    ov.put(vk, vec![u8::from(b.yes)]);
    Ok(())
}

fn op_appeal(ov: &mut Ov, block: &LedgerBlock, tx: &LedgerTx) -> Result<(), String> {
    let b: AppealBody = serde_json::from_str(&tx.call_args).map_err(|e| e.to_string())?;
    let mut h = load_hold(ov, &b.id).ok_or("no such hold")?;
    if !matches!(phase(ov, &h, block.timestamp), Phase::Voting | Phase::Confirmed | Phase::ReturnVoting) {
        return Err("the hold takes no appeals now".into());
    }
    if !h.amounts.iter().any(|(a, _)| a == &tx.from) || h.appeals.iter().any(|(a, _)| a == &tx.from) {
        return Err("each held address appeals once".into());
    }
    h.appeals.push((tx.from.clone(), b.text));
    save(ov, hold_key(&h.id), &h);
    Ok(())
}

fn op_return(ov: &mut Ov, block: &LedgerBlock, tx: &LedgerTx) -> Result<(), String> {
    let b: IdBody = serde_json::from_str(&tx.call_args).map_err(|e| e.to_string())?;
    let mut h = load_hold(ov, &b.id).ok_or("no such hold")?;
    if h.request.victim != tx.from || h.return_opened > 0 || phase(ov, &h, block.timestamp) != Phase::Confirmed {
        return Err("only the victim opens one return vote on a confirmed hold".into());
    }
    h.return_opened = block.timestamp;
    save(ov, hold_key(&h.id), &h);
    Ok(())
}

pub fn apply_op(ov: &mut Ov, block: &LedgerBlock, tx: &LedgerTx) -> Result<(), String> {
    well_formed(tx)?;
    match tx.tx_type.as_str() {
        TX_REQUEST => op_request(ov, block, tx),
        TX_VOTE => op_vote(ov, block, tx, false),
        TX_NODE_VOTE => op_vote(ov, block, tx, true),
        TX_APPEAL => op_appeal(ov, block, tx),
        _ => op_return(ov, block, tx),
    }
}

pub fn apply_block(ov: &mut Ov, block: &LedgerBlock, txs: &[&LedgerTx], staked: u64) {
    if !rule_active(block.height) {
        return;
    }
    apply_effects(ov, block, txs, staked);
}

fn apply_effects(ov: &mut Ov, block: &LedgerBlock, txs: &[&LedgerTx], staked: u64) {
    let mut paid = BTreeSet::new();
    for tx in txs.iter().filter(|t| is_settle(t)) {
        if let Some((id, _)) = settle_parts(tx) {
            paid.insert(id);
        }
    }
    for id in paid {
        if let Some(mut h) = load_hold(ov, &id) {
            h.paid = true;
            save(ov, hold_key(&id), &h);
        }
    }
    for tx in txs.iter().filter(|t| is_cert_tx(t)) {
        if let Err(e) = apply_cert(ov, block, tx, staked) {
            tracing::debug!("[HOLD] certificate {} had no effect: {e}", tx.hash);
        }
    }
    for tx in txs.iter().filter(|t| is_hold_op(t)) {
        if let Err(e) = apply_op(ov, block, tx) {
            tracing::debug!("[HOLD] {} {} had no effect: {e}", tx.tx_type, tx.hash);
        }
    }
}

pub fn admit(tx: &LedgerTx) -> Result<(), String> {
    if is_settle(tx) || is_cert_tx(tx) {
        return Err(format!("{} transactions are made by block producers only", tx.tx_type));
    }
    let active = rule_active_at_tip();
    if is_hold_op(tx) {
        if !active {
            return Err(format!("{} refused: theft holds are not active yet", tx.tx_type));
        }
        well_formed(tx)?;
    }
    if !active || !subject(tx) {
        return Ok(());
    }
    let ov = Ov::new(crate::chain_db::global_db());
    let now = chrono::Utc::now().timestamp();
    if crate::chain_db::is_unstake_tx(tx) && stake_locked_until(&ov, &tx.from) > now {
        return Err("HOLD_LOCKED: your stake is locked by a hold vote".into());
    }
    let mut need = locked(&ov, &tx.from, now);
    if tx.tx_type == TX_REQUEST {
        if bond_on(&ov, &tx.from, now) > 0 {
            return Err("you already have an open hold request".into());
        }
        need = need.saturating_add(serde_json::from_str::<RequestBody>(&tx.call_args).map(|b| b.bond).unwrap_or(0));
    }
    if need > 0 && crate::chain_db::balance_of(&tx.from).saturating_sub(outflow(tx)) < need {
        return Err(format!("HOLD_LOCKED: {} uEGOC of this wallet is held by a theft hold or a hold bond", need));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub height: u64,
    pub pos: u32,
    pub hash: String,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub fee: u64,
    pub unstake: bool,
}

pub fn trace(
    victim: &str,
    theft: &[String],
    hops: &[String],
    events: &[Event],
    now_balance: &dyn Fn(&str) -> u64,
    stops: &dyn Fn(&str) -> bool,
) -> Result<Vec<(String, u64)>, String> {
    let theft_set: BTreeSet<&str> = theft.iter().map(String::as_str).collect();
    let listed: BTreeSet<&str> = theft.iter().chain(hops).map(String::as_str).collect();
    let mut ordered: Vec<&Event> = events.iter().collect();
    ordered.sort_by(|a, b| (a.height, a.pos, &a.hash).cmp(&(b.height, b.pos, &b.hash)));
    ordered.dedup_by(|a, b| a.hash == b.hash);
    for h in &listed {
        if !ordered.iter().any(|e| e.hash == *h) {
            return Err(format!("listed transaction {h} is not in the history"));
        }
    }
    for e in ordered.iter().filter(|e| theft_set.contains(e.hash.as_str())) {
        if e.from != victim {
            return Err(format!("theft transaction {} does not leave the victim", e.hash));
        }
    }
    let first = ordered.iter().position(|e| theft_set.contains(e.hash.as_str())).ok_or("no theft transaction in the history")?;
    let mut tracked: BTreeSet<String> = BTreeSet::new();
    for e in ordered.iter().filter(|e| listed.contains(e.hash.as_str())) {
        if !stops(&e.to) && e.to != victim {
            tracked.insert(e.to.clone());
        }
    }
    let mut balance: BTreeMap<String, i128> = tracked.iter().map(|a| (a.clone(), now_balance(a) as i128)).collect();
    for e in ordered[first..].iter().rev() {
        if let Some(b) = balance.get_mut(&e.to) {
            if !e.unstake {
                *b -= e.amount as i128;
            }
        }
        if let Some(b) = balance.get_mut(&e.from) {
            *b += if e.unstake { e.fee as i128 } else { e.amount as i128 + e.fee as i128 };
        }
        if e.unstake {
            if let Some(b) = balance.get_mut(&e.from) {
                *b -= e.amount as i128;
            }
        }
    }
    let mut traced: BTreeMap<String, u64> = tracked.iter().map(|a| (a.clone(), 0)).collect();
    let mut bal: BTreeMap<String, u64> = balance.into_iter().map(|(a, b)| (a, b.max(0) as u64)).collect();
    for e in &ordered[first..] {
        let is_listed = listed.contains(e.hash.as_str());
        let mut carried: u64 = 0;
        if theft_set.contains(e.hash.as_str()) {
            carried = e.amount;
        } else if let Some(b) = bal.get_mut(&e.from) {
            let out = if e.unstake { e.fee } else { e.amount.saturating_add(e.fee) };
            let t = traced.get(&e.from).copied().unwrap_or(0);
            let new_bal = b.saturating_sub(out);
            let left = if is_listed {
                carried = e.amount.min(t);
                t - carried
            } else {
                let own = b.saturating_sub(t);
                t.saturating_sub(out.saturating_sub(own))
            };
            *b = if e.unstake { new_bal.saturating_add(e.amount) } else { new_bal };
            traced.insert(e.from.clone(), left.min(new_bal));
        }
        if let Some(b) = bal.get_mut(&e.to) {
            if !e.unstake {
                *b = b.saturating_add(e.amount);
            }
            if is_listed && carried > 0 {
                let t = traced.get(&e.to).copied().unwrap_or(0).saturating_add(carried);
                traced.insert(e.to.clone(), t.min(*b));
            }
        }
    }
    let mut out: Vec<(String, u64)> = traced
        .into_iter()
        .map(|(a, t)| {
            let cap = now_balance(&a);
            (a, t.min(cap))
        })
        .filter(|(_, t)| *t > 0)
        .collect();
    out.sort();
    out.truncate(MAX_HELD);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EGOC: u64 = 1_000_000;
    const ALICE: &str = "egot1alice00000000000000000000000000000000000";
    const A: &str = "egot1thiefa0000000000000000000000000000000000";
    const B: &str = "egot1thiefb0000000000000000000000000000000000";
    const EXCHANGE: &str = "egot1exchange00000000000000000000000000000000";
    const REQ: &str = "egot1requester000000000000000000000000000000";
    const V1: &str = "egot1voter10000000000000000000000000000000000";

    fn ev(n: u64, from: &str, to: &str, amount: u64) -> Event {
        Event { height: n, pos: 0, hash: format!("0x{:064x}", n), from: from.into(), to: to.into(), amount, fee: 0, unstake: false }
    }

    fn h(n: u64) -> String {
        format!("0x{:064x}", n)
    }

    #[test]
    fn the_docs_example_traces_to_one_hundred_and_seven_hundred() {
        let events = vec![
            ev(1, "egot1earlier000000000000000000000000000000000", A, 200 * EGOC),
            ev(2, ALICE, A, 1_000 * EGOC),
            ev(3, A, B, 700 * EGOC),
            ev(4, A, EXCHANGE, 400 * EGOC),
        ];
        let now = |a: &str| match a {
            A => 100 * EGOC,
            B => 700 * EGOC,
            _ => 0,
        };
        let got = trace(ALICE, &[h(2)], &[h(3)], &events, &now, &|_| false).unwrap();
        assert_eq!(got, vec![(A.to_string(), 100 * EGOC), (B.to_string(), 700 * EGOC)]);
    }

    #[test]
    fn coins_that_arrive_later_are_never_counted_as_stolen() {
        let events = vec![
            ev(2, ALICE, A, 1_000 * EGOC),
            ev(3, A, EXCHANGE, 1_000 * EGOC),
            ev(4, "egot1payer00000000000000000000000000000000000", A, 500 * EGOC),
        ];
        let now = |a: &str| if a == A { 500 * EGOC } else { 0 };
        assert!(trace(ALICE, &[h(2)], &[], &events, &now, &|_| false).unwrap().is_empty());
    }

    #[test]
    fn a_trail_into_the_shielded_pool_ends_there() {
        let events = vec![ev(2, ALICE, A, 1_000 * EGOC), ev(3, A, "egot1shieldedpool000000000000000000000000000", 600 * EGOC)];
        let now = |a: &str| if a == A { 400 * EGOC } else { 0 };
        let got = trace(ALICE, &[h(2)], &[h(3)], &events, &now, &|a| a.starts_with("egot1shielded")).unwrap();
        assert_eq!(got, vec![(A.to_string(), 400 * EGOC)]);
    }

    #[test]
    fn a_listed_transaction_that_is_missing_stops_the_trace() {
        let events = vec![ev(2, ALICE, A, 1_000 * EGOC)];
        assert!(trace(ALICE, &[h(2)], &[h(9)], &events, &|_| 0, &|_| false).is_err());
        assert!(trace(B, &[h(2)], &[], &events, &|_| 0, &|_| false).is_err(), "a theft leaves the victim");
    }

    fn hold_with(ov: &mut Ov<'static>, held_at: i64) -> Hold {
        let h = Hold {
            id: "hold0123456789abcdef".into(),
            requester: REQ.into(),
            request: RequestBody { victim: ALICE.into(), theft: vec![h(2)], hops: vec![], case: "x".into(), bond: 100 * EGOC },
            created: 1_000,
            height: 10,
            keys: vec!["k".into(); 4],
            amounts: vec![(A.into(), 300 * EGOC), (B.into(), 50 * EGOC)],
            held_at,
            stake_total: 1_000 * EGOC,
            node_total: 1_000,
            ..Hold::default()
        };
        save(ov, hold_key(&h.id), &h);
        save(ov, addr_key(A), &vec![h.id.clone()]);
        save(ov, bond_key(REQ), &h.id);
        save(ov, LIVE_KEY.to_vec(), &vec![h.id.clone()]);
        ov.commit_memory();
        h
    }

    #[test]
    fn a_hold_keeps_only_the_traced_amount_and_lapses_without_quorum() {
        let mut ov = Ov::memory();
        let h = hold_with(&mut ov, 2_000);
        assert_eq!(held_on(&ov, A, 2_001), 300 * EGOC);
        let mut plan = Planner::new(20, 2_001);
        let bal = |a: &str| if a == A { 1_000 * EGOC } else { 0 };
        let mut send = LedgerTx { hash: "0xs".into(), from: A.into(), to: EXCHANGE.into(), amount: 700 * EGOC, tx_type: "transfer".into(), signature: "ab".into(), nonce: 1, ..LedgerTx::default() };
        assert!(matches!(plan.judge(&ov, &send, &bal), Fit::Yes), "coins above the held amount move freely");
        send.hash = "0xs2".into();
        send.amount = 1;
        assert!(matches!(plan.judge(&ov, &send, &bal), Fit::Later(_)), "the held amount stays");
        assert_eq!(phase(&ov, &h, vote_end(&h)), Phase::Lapsed);
        assert_eq!(held_on(&ov, A, vote_end(&h)), 0, "a lapsed hold frees the coins");
        assert_eq!(bond_on(&ov, REQ, vote_end(&h)), 0, "a lapsed hold frees the bond");
        assert!(settlements(&ov, &h, vote_end(&h)).is_empty(), "a lapse pays nobody");
    }

    fn vote(ov: &mut Ov<'static>, h: &Hold, phase_name: &str, t: Tally) {
        save(ov, tally_key(&h.id, phase_name), &t);
        ov.commit_memory();
    }

    #[test]
    fn a_rejected_hold_pays_its_bond_to_the_held_address() {
        let mut ov = Ov::memory();
        let h = hold_with(&mut ov, 2_000);
        vote(&mut ov, &h, PHASE_CONFIRM, Tally { stake_yes: 10, stake_no: 90 * EGOC, stake_voters: 3, node_yes: 1, node_no: 200, node_voters: 3 });
        let end = vote_end(&h);
        assert_eq!(phase(&ov, &h, end), Phase::Rejected);
        let s = settlements(&ov, &h, end);
        assert_eq!(s, vec![Settlement { from: REQ.into(), to: A.into(), owed: 100 * EGOC }]);
        let txs = settle_txs_for_test(&ov, end);
        assert_eq!(txs.len(), 1);
        assert!(settle_is_well_formed(&txs[0]));
    }

    fn settle_txs_for_test(ov: &Ov, now: i64) -> Vec<LedgerTx> {
        let mut out = Vec::new();
        for id in live(ov) {
            let h = load_hold(ov, &id).unwrap();
            for (i, s) in settlements(ov, &h, now).into_iter().enumerate() {
                out.push(LedgerTx {
                    hash: settle_hash(&id, i, &s.from, &s.to, s.owed),
                    from: s.from,
                    to: s.to,
                    amount: s.owed,
                    memo: Some(settle_memo(&id, i)),
                    tx_type: TX_SETTLE.into(),
                    signature: "hold".into(),
                    tx_version: 3,
                    ..LedgerTx::default()
                });
            }
        }
        out
    }

    #[test]
    fn a_confirmed_hold_returns_coins_only_after_its_own_vote() {
        let mut ov = Ov::memory();
        let mut h = hold_with(&mut ov, 2_000);
        let pass = Tally { stake_yes: 900 * EGOC, stake_no: 0, stake_voters: 3, node_yes: 200, node_no: 0, node_voters: 3 };
        vote(&mut ov, &h, PHASE_CONFIRM, pass);
        let end = vote_end(&h);
        assert_eq!(phase(&ov, &h, end), Phase::Confirmed);
        assert_eq!(held_on(&ov, A, end), 300 * EGOC);
        assert!(settlements(&ov, &h, end).is_empty());
        h.return_opened = end + 10;
        save(&mut ov, hold_key(&h.id), &h);
        ov.commit_memory();
        assert_eq!(phase(&ov, &h, end + 11), Phase::ReturnVoting);
        vote(&mut ov, &h, PHASE_RETURN, pass);
        let back = end + 10 + VOTE_SECS;
        assert_eq!(phase(&ov, &h, back), Phase::Returned);
        let s = settlements(&ov, &h, back);
        assert_eq!(s.len(), 2);
        assert!(s.iter().all(|x| x.to == ALICE));
        assert_eq!(phase(&ov, &h, end + CONFIRM_SECS), Phase::Returned);
    }

    #[test]
    fn a_confirmed_hold_expires_after_ninety_days() {
        let mut ov = Ov::memory();
        let h = hold_with(&mut ov, 2_000);
        vote(&mut ov, &h, PHASE_CONFIRM, Tally { stake_yes: 900 * EGOC, stake_no: 0, stake_voters: 3, node_yes: 200, node_no: 0, node_voters: 3 });
        assert_eq!(phase(&ov, &h, vote_end(&h) + CONFIRM_SECS), Phase::Expired);
        assert_eq!(held_on(&ov, A, vote_end(&h) + CONFIRM_SECS), 0);
    }

    #[test]
    fn large_holders_alone_cannot_confirm() {
        let h = Hold { stake_total: 1_000, node_total: 1_000, ..Hold::default() };
        let whales = Tally { stake_yes: 1_000, stake_no: 0, stake_voters: 5, node_yes: 0, node_no: 0, node_voters: 0 };
        assert_eq!(outcome(&whales, &h), Outcome::NoQuorum);
        let split = Tally { stake_yes: 1_000, stake_no: 0, stake_voters: 5, node_yes: 10, node_no: 90, node_voters: 4 };
        assert_eq!(outcome(&split, &h), Outcome::Fail);
    }

    #[test]
    fn the_requester_cannot_spend_the_bond_while_the_hold_runs() {
        let mut ov = Ov::memory();
        hold_with(&mut ov, 0);
        let mut plan = Planner::new(20, 1_500);
        let bal = |a: &str| if a == REQ { 150 * EGOC } else { 0 };
        let tx = LedgerTx { hash: "0xr".into(), from: REQ.into(), to: V1.into(), amount: 60 * EGOC, tx_type: "transfer".into(), signature: "ab".into(), nonce: 1, ..LedgerTx::default() };
        assert!(matches!(plan.judge(&ov, &tx, &bal), Fit::Later(_)));
    }

    #[test]
    fn hold_ops_need_the_memo_that_commits_to_the_body() {
        let body = RequestBody { victim: ALICE.into(), theft: vec![h(2)], hops: vec![], case: "stolen".into(), bond: MIN_BOND_UEGOC };
        let call_args = serde_json::to_string(&body).unwrap();
        let mut tx = LedgerTx {
            from: REQ.into(),
            to: REQ.into(),
            tx_type: TX_REQUEST.into(),
            memo: memo_for(TX_REQUEST, &call_args),
            call_args,
            fee_uegoc: REQUEST_FEE_UEGOC,
            ..LedgerTx::default()
        };
        assert!(well_formed(&tx).is_ok());
        tx.fee_uegoc = 1_000;
        assert!(well_formed(&tx).is_err(), "a request burns its fee");
    }
}
