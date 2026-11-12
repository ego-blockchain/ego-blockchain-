use crate::chain_db::{DaoOptionResult, DaoProposalPublic, DaoProposalResults, DaoTestQuestionPublic, DAO_BASE_KNOWLEDGE_POWER};
use crate::drs::Ov;
use crate::ledger::{LedgerBlock, LedgerTx};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const ACTIVATION_HEIGHT: Option<u64> = Some(65103);
#[cfg(not(test))]
pub const KNOW_TALLY_FROM: Option<u64> = Some(67922);
#[cfg(test)]
pub const KNOW_TALLY_FROM: Option<u64> = Some(1_000);

pub const TX_PROPOSE: &str = "dao_propose";
pub const TX_VOTE: &str = "dao_vote";
pub const TX_KNOW: &str = "dao_know";
pub const TX_REVEAL: &str = "dao_reveal";
pub const TX_WITHDRAW: &str = "dao_withdraw";
pub const TX_KNOW_REVEAL: &str = "dao_know_reveal";
pub const TX_REPORT: &str = "dao_report";
pub const DAO_TYPES: [&str; 7] = [TX_PROPOSE, TX_VOTE, TX_KNOW, TX_REVEAL, TX_WITHDRAW, TX_KNOW_REVEAL, TX_REPORT];
pub const KINDS: [&str; 5] = ["protocol", "resource", "feature", "parameter", "tender"];
pub const KIND_ARBITER_ADD: &str = "arbiter_add";
pub const KIND_ARBITER_REMOVE: &str = "arbiter_remove";
pub const ARBITER_KINDS: [&str; 2] = [KIND_ARBITER_ADD, KIND_ARBITER_REMOVE];
pub const ARBITER_OPTIONS: [&str; 2] = ["Yes", "No"];
pub const ARBITER_MIN_STAKE_UEGOC: u64 = 10_000 * 1_000_000;
pub const MAX_ARBITERS: usize = 100;
pub const ARBITERS_KEY: &[u8] = b"dao:arbiters";
const ARBITER_SETTLE_PER_BLOCK: usize = 64;
pub const OUTCOME_REJECTED: u8 = 0;
pub const OUTCOME_APPLIED: u8 = 1;
pub const OUTCOME_UNCHANGED: u8 = 2;

pub fn arbiter_rules_active(height: u64) -> bool {
    height >= crate::drs::NODE_PAY_V2_FROM_HEIGHT
}

pub fn is_arbiter_kind(kind: &str) -> bool {
    ARBITER_KINDS.contains(&kind)
}

pub const MAX_BODY_BYTES: usize = 16_384;
pub const MAX_TITLE_BYTES: usize = 200;
pub const MAX_DESCRIPTION_BYTES: usize = 4_000;
pub const MAX_OPTIONS: usize = 10;
pub const MAX_OPTION_BYTES: usize = 100;
pub const MAX_QUESTIONS: usize = 10;
pub const MAX_QUESTION_BYTES: usize = 300;
pub const MAX_QUESTION_OPTIONS: usize = 4;
pub const MIN_DAYS: u32 = 1;
pub const MAX_DAYS: u32 = 30;
pub const DEFAULT_DAYS: u32 = 7;
pub const DAY_SECS: i64 = 86_400;
pub const PROPOSALS_PER_WINDOW: usize = 5;
pub const WINDOW_SECS: i64 = 30 * DAY_SECS;
pub const REVEAL_WINDOW_SECS: i64 = 7 * DAY_SECS;
pub const MIN_STAKE_VOTERS: u64 = 3;
pub const MIN_STAKE_PERCENT: u128 = 1;
pub const LIST_LIMIT: usize = 200;
pub const KNOWLEDGE_SCAN_LIMIT: usize = 100_000;
pub const REPORT_SECS: i64 = 30 * DAY_SECS;
pub const MAX_REPORTS: usize = 256;
pub const MIN_REPORTERS: usize = 3;

const BODY_DOMAIN: &[u8] = b"ego/dao/body/v1:";
const ANSWERS_DOMAIN: &[u8] = b"ego/dao/answers/v1:";
const VOTE_ANSWERS_DOMAIN: &[u8] = b"ego/dao/vote-answers/v1:";
const ID_DOMAIN: &[u8] = b"ego/dao/id/v1:";

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Question {
    pub question: String,
    pub options: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProposeBody {
    pub title: String,
    pub description: String,
    pub kind: String,
    pub options: Vec<String>,
    pub duration_days: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub questions: Vec<Question>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub answers_commit: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct VoteBody {
    pub id: String,
    pub option: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct KnowBody {
    pub id: String,
    pub option: u32,
    pub commit: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ReportBody {
    pub target: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub reporter: String,
    pub weight: u64,
    pub at: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RevealBody {
    pub id: String,
    pub salt: String,
    pub answers: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct WithdrawBody {
    pub id: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Proposal {
    pub id: String,
    pub title: String,
    pub description: String,
    pub kind: String,
    pub options: Vec<String>,
    pub creator: String,
    pub created_at: i64,
    pub ends_at: i64,
    pub height: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub questions: Vec<Question>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub answers_commit: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answers: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub withdrawn: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revealed_at: Option<i64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target: String,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct StakeVote {
    pub option: u32,
    pub weight: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct KnowVote {
    pub option: u32,
    pub commit: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answers: Option<Vec<u8>>,
}

pub fn rule_active(height: u64) -> bool {
    ACTIVATION_HEIGHT.is_some_and(|h| height >= h)
}

pub fn rule_active_at_tip() -> bool {
    rule_active(crate::chain_db::local_chain_height().saturating_add(1))
}

pub fn tally_active(height: u64) -> bool {
    KNOW_TALLY_FROM.is_some_and(|h| height >= h)
}

pub fn is_dao_tx(tx: &LedgerTx) -> bool {
    DAO_TYPES.contains(&tx.tx_type.as_str())
}

pub fn body_hash(call_args: &str) -> String {
    let mut m = BODY_DOMAIN.to_vec();
    m.extend_from_slice(call_args.as_bytes());
    blake3::hash(&m).to_hex().to_string()
}

pub fn memo_for(tx_type: &str, call_args: &str) -> Option<String> {
    if !DAO_TYPES.contains(&tx_type) {
        return None;
    }
    let op = tx_type.strip_prefix("dao_")?;
    Some(format!("dao:{op}:{}", body_hash(call_args)))
}

pub fn proposal_id(tx_hash: &str) -> String {
    let mut m = ID_DOMAIN.to_vec();
    m.extend_from_slice(tx_hash.as_bytes());
    format!("dao{}", &blake3::hash(&m).to_hex()[..16])
}

pub fn answers_commit(salt: &str, answers: &[u8]) -> String {
    let mut m = ANSWERS_DOMAIN.to_vec();
    m.extend_from_slice(salt.as_bytes());
    m.push(b':');
    m.extend_from_slice(answers);
    blake3::hash(&m).to_hex().to_string()
}

pub fn vote_commit(id: &str, voter: &str, salt: &str, answers: &[u8]) -> String {
    let mut m = VOTE_ANSWERS_DOMAIN.to_vec();
    for part in [id.as_bytes(), voter.as_bytes(), salt.as_bytes()] {
        m.extend_from_slice(part);
        m.push(b':');
    }
    m.extend_from_slice(answers);
    blake3::hash(&m).to_hex().to_string()
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_id(s: &str) -> bool {
    s.len() == 19 && s.starts_with("dao") && s[3..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn text_ok(s: &str, max: usize) -> bool {
    !s.trim().is_empty() && s.len() <= max
}

pub fn check_propose(b: &ProposeBody) -> Result<(), String> {
    check_propose_at(b, crate::chain_db::local_chain_height().saturating_add(1))
}

fn arbiter_address_ok(a: &str) -> bool {
    a.starts_with("egot1") && (20..=80).contains(&a.len()) && a.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

pub fn check_propose_at(b: &ProposeBody, height: u64) -> Result<(), String> {
    if is_arbiter_kind(&b.kind) && arbiter_rules_active(height) {
        if !arbiter_address_ok(&b.target) {
            return Err("an arbiter proposal names the Ego address it adds or removes".into());
        }
        if b.options.iter().map(String::as_str).ne(ARBITER_OPTIONS.iter().copied()) {
            return Err("an arbiter proposal is voted Yes or No".into());
        }
        if !b.questions.is_empty() {
            return Err("an arbiter proposal is decided by stake alone, with no knowledge test".into());
        }
    } else if !KINDS.contains(&b.kind.as_str()) {
        return Err(format!("unknown type '{}'; use {}", b.kind, KINDS.join(", ")));
    }
    if !text_ok(&b.title, MAX_TITLE_BYTES) {
        return Err(format!("a title is needed, at most {MAX_TITLE_BYTES} bytes"));
    }
    if b.description.len() > MAX_DESCRIPTION_BYTES {
        return Err(format!("the description is longer than {MAX_DESCRIPTION_BYTES} bytes"));
    }
    if b.options.len() < 2 || b.options.len() > MAX_OPTIONS {
        return Err(format!("a proposal needs 2 to {MAX_OPTIONS} options"));
    }
    if b.options.iter().any(|o| !text_ok(o, MAX_OPTION_BYTES)) {
        return Err(format!("every option needs text, at most {MAX_OPTION_BYTES} bytes"));
    }
    if b.duration_days < MIN_DAYS || b.duration_days > MAX_DAYS {
        return Err(format!("voting lasts {MIN_DAYS} to {MAX_DAYS} days"));
    }
    if b.questions.len() > MAX_QUESTIONS {
        return Err(format!("a knowledge test has at most {MAX_QUESTIONS} questions"));
    }
    for (i, q) in b.questions.iter().enumerate() {
        if !text_ok(&q.question, MAX_QUESTION_BYTES) {
            return Err(format!("question {} needs text, at most {MAX_QUESTION_BYTES} bytes", i + 1));
        }
        if q.options.len() < 2 || q.options.len() > MAX_QUESTION_OPTIONS {
            return Err(format!("question {} needs 2 to {MAX_QUESTION_OPTIONS} answers", i + 1));
        }
        if q.options.iter().any(|o| !text_ok(o, MAX_OPTION_BYTES)) {
            return Err(format!("every answer to question {} needs text, at most {MAX_OPTION_BYTES} bytes", i + 1));
        }
    }
    match (b.questions.is_empty(), is_hex64(&b.answers_commit)) {
        (true, _) if !b.answers_commit.is_empty() => Err("a proposal without questions commits to no answers".into()),
        (false, false) => Err("a knowledge test must commit to its answers".into()),
        _ => Ok(()),
    }
}

fn answers_shape_ok(questions: &[Question], answers: &[u8]) -> bool {
    answers.len() == questions.len() && questions.iter().zip(answers).all(|(q, a)| (*a as usize) < q.options.len())
}

pub fn well_formed(tx: &LedgerTx, height: u64) -> Result<(), String> {
    if !is_dao_tx(tx) {
        return Err(format!("{} is not a DAO transaction", tx.tx_type));
    }
    if tx.from.is_empty() || tx.to != tx.from || tx.amount != 0 {
        return Err("a DAO transaction is a zero-amount transaction to the sender itself".into());
    }
    if tx.call_args.len() > MAX_BODY_BYTES {
        return Err(format!("the body is longer than {MAX_BODY_BYTES} bytes"));
    }
    if tx.memo != memo_for(&tx.tx_type, &tx.call_args) {
        return Err("the memo does not commit to the body".into());
    }
    let unreadable = |e: serde_json::Error| format!("the body is not readable: {e}");
    match tx.tx_type.as_str() {
        TX_PROPOSE => check_propose_at(&serde_json::from_str::<ProposeBody>(&tx.call_args).map_err(unreadable)?, height),
        TX_VOTE => {
            let b: VoteBody = serde_json::from_str(&tx.call_args).map_err(unreadable)?;
            if !is_id(&b.id) || b.option as usize >= MAX_OPTIONS {
                return Err("the vote names no proposal or option".into());
            }
            Ok(())
        }
        TX_KNOW => {
            let b: KnowBody = serde_json::from_str(&tx.call_args).map_err(unreadable)?;
            if !is_id(&b.id) || b.option as usize >= MAX_OPTIONS {
                return Err("the vote names no proposal or option".into());
            }
            if !is_hex64(&b.commit) {
                return Err("a knowledge vote commits to its answers".into());
            }
            Ok(())
        }
        TX_REPORT => {
            let b: ReportBody = serde_json::from_str(&tx.call_args).map_err(unreadable)?;
            if b.target.is_empty() || b.target.len() > 128 || b.target == tx.from {
                return Err("a report names someone else".into());
            }
            Ok(())
        }
        TX_REVEAL | TX_KNOW_REVEAL => {
            let b: RevealBody = serde_json::from_str(&tx.call_args).map_err(unreadable)?;
            if !is_id(&b.id) || !is_hex64(&b.salt) || b.answers.is_empty() || b.answers.len() > MAX_QUESTIONS {
                return Err("the reveal names no proposal, salt or answers".into());
            }
            Ok(())
        }
        _ => {
            let b: WithdrawBody = serde_json::from_str(&tx.call_args).map_err(unreadable)?;
            if !is_id(&b.id) {
                return Err("the withdrawal names no proposal".into());
            }
            Ok(())
        }
    }
}

fn key(parts: std::fmt::Arguments) -> Vec<u8> {
    format!("dao:{parts}").into_bytes()
}

fn arbiter_end_key(ends_at: i64, id: &str) -> Vec<u8> {
    key(format_args!("ae:{:020}:{id}", ends_at.max(0) as u64))
}

fn arbiter_outcome_key(id: &str) -> Vec<u8> {
    key(format_args!("ao:{id}"))
}

fn arbiter_end_parts(k: &[u8]) -> Option<(i64, String)> {
    let s = std::str::from_utf8(k.strip_prefix(b"dao:ae:".as_slice())?).ok()?;
    let (ts, id) = s.split_once(':')?;
    Some((ts.parse::<u64>().ok()? as i64, id.to_string()))
}

pub fn arbiter_list(ov: &Ov, height: u64) -> Vec<String> {
    load::<Vec<String>>(ov, ARBITERS_KEY)
        .unwrap_or_else(|| crate::market_chain::arbiters_at(height).iter().map(|a| a.to_string()).collect())
}

pub fn arbiter_outcome(ov: &Ov, id: &str) -> Option<u8> {
    ov.get(&arbiter_outcome_key(id)).and_then(|v| v.first().copied())
}

fn decide_arbiter(ov: &mut Ov, p: &Proposal, network_stake: u64, height: u64) -> u8 {
    if p.withdrawn || p.target.is_empty() || !is_arbiter_kind(&p.kind) {
        return OUTCOME_REJECTED;
    }
    let tallies: Vec<u64> = load(ov, &tally_key(&p.id)).unwrap_or_default();
    let yes = tallies.first().copied().unwrap_or(0);
    let no = tallies.get(1).copied().unwrap_or(0);
    let voters = u64_at(ov, &stake_count_key(&p.id));
    let quorum = voters >= MIN_STAKE_VOTERS
        && (yes as u128 + no as u128) * 100 >= network_stake as u128 * MIN_STAKE_PERCENT;
    if !quorum || yes <= no {
        return OUTCOME_REJECTED;
    }
    let mut list = arbiter_list(ov, height);
    let listed = list.iter().any(|a| *a == p.target);
    if p.kind == KIND_ARBITER_ADD {
        if listed || list.len() >= MAX_ARBITERS || stake_of(ov, &p.target) < ARBITER_MIN_STAKE_UEGOC {
            return OUTCOME_UNCHANGED;
        }
        list.push(p.target.clone());
    } else {
        if !listed || list.len() <= 1 {
            return OUTCOME_UNCHANGED;
        }
        list.retain(|a| *a != p.target);
    }
    save(ov, ARBITERS_KEY.to_vec(), &list);
    OUTCOME_APPLIED
}

fn settle_arbiter_votes(ov: &mut Ov, block: &LedgerBlock, network_stake: u64) {
    let due = ov.committed_keys(b"dao:ae:", ARBITER_SETTLE_PER_BLOCK, |k| {
        arbiter_end_parts(k).map_or(true, |(ts, _)| ts > block.timestamp)
    });
    for k in due {
        let Some((_, id)) = arbiter_end_parts(&k) else { continue };
        ov.del(k);
        let outcome = match load_proposal(ov, &id) {
            Some(p) => decide_arbiter(ov, &p, network_stake, block.height),
            None => OUTCOME_REJECTED,
        };
        ov.put(arbiter_outcome_key(&id), vec![outcome]);
    }
}

fn p_key(id: &str) -> Vec<u8> {
    key(format_args!("p:{id}"))
}

fn idx_key(created_at: i64, id: &str) -> Vec<u8> {
    key(format_args!("i:{:020}:{id}", u64::MAX - created_at.max(0) as u64))
}

fn tally_key(id: &str) -> Vec<u8> {
    key(format_args!("st:{id}"))
}

fn stake_count_key(id: &str) -> Vec<u8> {
    key(format_args!("sc:{id}"))
}

fn stake_vote_key(id: &str, voter: &str) -> Vec<u8> {
    key(format_args!("sv:{id}:{voter}"))
}

fn know_prefix(id: &str) -> Vec<u8> {
    key(format_args!("kv:{id}:"))
}

fn know_vote_key(id: &str, voter: &str) -> Vec<u8> {
    key(format_args!("kv:{id}:{voter}"))
}

fn know_count_key(id: &str) -> Vec<u8> {
    key(format_args!("kc:{id}"))
}

fn know_tally_key(id: &str) -> Vec<u8> {
    key(format_args!("kt:{id}"))
}

fn right_answers(questions: &[Question], key: &[u8], answers: &[u8]) -> u64 {
    if questions.is_empty() || !answers_shape_ok(questions, answers) {
        return 0;
    }
    key.iter().zip(answers).filter(|(a, b)| a == b).count() as u64
}

fn created_key(creator: &str) -> Vec<u8> {
    key(format_args!("pc:{creator}"))
}

fn lock_key(addr: &str) -> Vec<u8> {
    key(format_args!("lock:{addr}"))
}

fn report_key(target: &str) -> Vec<u8> {
    key(format_args!("rt:{target}"))
}

fn load<T: for<'de> Deserialize<'de>>(ov: &Ov, k: &[u8]) -> Option<T> {
    ov.get(k).and_then(|v| serde_json::from_slice(&v).ok())
}

fn save<T: Serialize>(ov: &mut Ov, k: Vec<u8>, v: &T) {
    ov.put(k, serde_json::to_vec(v).unwrap_or_default());
}

fn u64_at(ov: &Ov, k: &[u8]) -> u64 {
    ov.get(k).and_then(|v| v.get(..8).and_then(|b| b.try_into().ok()).map(u64::from_le_bytes)).unwrap_or(0)
}

fn put_u64(ov: &mut Ov, k: Vec<u8>, v: u64) {
    ov.put(k, v.to_le_bytes().to_vec());
}

pub fn load_proposal(ov: &Ov, id: &str) -> Option<Proposal> {
    load(ov, &p_key(id))
}

pub fn know_vote(ov: &Ov, id: &str, voter: &str) -> Option<KnowVote> {
    load(ov, &know_vote_key(id, voter))
}

pub fn stake_of(ov: &Ov, addr: &str) -> u64 {
    u64_at(ov, format!("stake:{addr}").as_bytes())
}

pub fn locked_until(ov: &Ov, addr: &str) -> i64 {
    u64_at(ov, &lock_key(addr)) as i64
}

pub fn created_in_window(ov: &Ov, creator: &str, now: i64) -> Vec<i64> {
    load::<Vec<i64>>(ov, &created_key(creator))
        .unwrap_or_default()
        .into_iter()
        .filter(|t| *t > now - WINDOW_SECS)
        .collect()
}

fn open_proposal(ov: &Ov, id: &str, now: i64) -> Result<Proposal, String> {
    let p = load_proposal(ov, id).ok_or("no such proposal")?;
    if p.withdrawn {
        return Err("the proposal was withdrawn".into());
    }
    if now >= p.ends_at {
        return Err("voting has ended".into());
    }
    Ok(p)
}

pub fn active_reports(ov: &Ov, target: &str, now: i64) -> Vec<Report> {
    load::<Vec<Report>>(ov, &report_key(target))
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.at > now - REPORT_SECS)
        .collect()
}

pub fn banned(reports: &[Report], network_stake: u64) -> bool {
    let weight: u128 = reports.iter().map(|r| r.weight as u128).sum();
    reports.len() >= MIN_REPORTERS && network_stake > 0 && weight * 100 >= network_stake as u128 * MIN_STAKE_PERCENT
}

pub fn ban_status(ov: &Ov, target: &str, viewer: Option<&str>, now: i64, network_stake: u64) -> crate::chain_db::ProposerBanStatus {
    let reports = active_reports(ov, target, now);
    crate::chain_db::ProposerBanStatus {
        target: target.to_string(),
        vote_count: reports.len(),
        threshold: MIN_REPORTERS,
        banned: banned(&reports, network_stake),
        my_vote: viewer.is_some_and(|v| reports.iter().any(|r| r.reporter == v)),
    }
}

fn report(ov: &mut Ov, block: &LedgerBlock, tx: &LedgerTx) -> Result<(), String> {
    let b: ReportBody = serde_json::from_str(&tx.call_args).map_err(|e| e.to_string())?;
    let weight = stake_of(ov, &tx.from);
    if weight == 0 {
        return Err("only staked EGOC can report".into());
    }
    let mut reports = active_reports(ov, &b.target, block.timestamp);
    if reports.iter().any(|r| r.reporter == tx.from) {
        return Err("already reported".into());
    }
    reports.push(Report { reporter: tx.from.clone(), weight, at: block.timestamp });
    if reports.len() > MAX_REPORTS {
        reports.drain(..reports.len() - MAX_REPORTS);
    }
    save(ov, report_key(&b.target), &reports);
    let until = block.timestamp + REPORT_SECS;
    if locked_until(ov, &tx.from) < until {
        put_u64(ov, lock_key(&tx.from), until as u64);
    }
    Ok(())
}

fn propose(ov: &mut Ov, block: &LedgerBlock, tx: &LedgerTx, network_stake: u64) -> Result<(), String> {
    let b: ProposeBody = serde_json::from_str(&tx.call_args).map_err(|e| e.to_string())?;
    let id = proposal_id(&tx.hash);
    if ov.get(&p_key(&id)).is_some() {
        return Err("a proposal with this id exists".into());
    }
    if banned(&active_reports(ov, &tx.from, block.timestamp), network_stake) {
        return Err("the community reported this address; it cannot propose for now".into());
    }
    let mut times = created_in_window(ov, &tx.from, block.timestamp);
    if times.len() >= PROPOSALS_PER_WINDOW {
        return Err(format!("at most {PROPOSALS_PER_WINDOW} proposals in 30 days"));
    }
    times.push(block.timestamp);
    save(ov, created_key(&tx.from), &times);
    let arbiter_vote = is_arbiter_kind(&b.kind) && arbiter_rules_active(block.height);
    let target = if arbiter_vote { b.target.clone() } else { String::new() };
    let p = Proposal {
        id: id.clone(),
        title: b.title,
        description: b.description,
        kind: b.kind,
        options: b.options,
        creator: tx.from.clone(),
        created_at: block.timestamp,
        ends_at: block.timestamp + b.duration_days as i64 * DAY_SECS,
        height: block.height,
        questions: b.questions,
        answers_commit: b.answers_commit,
        answers: None,
        withdrawn: false,
        revealed_at: None,
        target,
    };
    if arbiter_vote {
        ov.put(arbiter_end_key(p.ends_at, &id), Vec::new());
    }
    save(ov, tally_key(&id), &vec![0u64; p.options.len()]);
    ov.put(idx_key(p.created_at, &id), Vec::new());
    save(ov, p_key(&id), &p);
    Ok(())
}

fn stake_vote(ov: &mut Ov, block: &LedgerBlock, tx: &LedgerTx) -> Result<(), String> {
    let b: VoteBody = serde_json::from_str(&tx.call_args).map_err(|e| e.to_string())?;
    let p = open_proposal(ov, &b.id, block.timestamp)?;
    if b.option as usize >= p.options.len() {
        return Err("no such option".into());
    }
    let weight = stake_of(ov, &tx.from);
    if weight == 0 {
        return Err("only staked EGOC votes".into());
    }
    let mut tallies: Vec<u64> = load(ov, &tally_key(&p.id)).unwrap_or_else(|| vec![0; p.options.len()]);
    tallies.resize(p.options.len(), 0);
    match load::<StakeVote>(ov, &stake_vote_key(&p.id, &tx.from)) {
        Some(prev) => {
            if let Some(t) = tallies.get_mut(prev.option as usize) {
                *t = t.saturating_sub(prev.weight);
            }
        }
        None => {
            let n = u64_at(ov, &stake_count_key(&p.id));
            put_u64(ov, stake_count_key(&p.id), n + 1);
        }
    }
    tallies[b.option as usize] = tallies[b.option as usize].saturating_add(weight);
    save(ov, tally_key(&p.id), &tallies);
    save(ov, stake_vote_key(&p.id, &tx.from), &StakeVote { option: b.option, weight });
    if locked_until(ov, &tx.from) < p.ends_at {
        put_u64(ov, lock_key(&tx.from), p.ends_at as u64);
    }
    Ok(())
}

fn knowledge_vote(ov: &mut Ov, block: &LedgerBlock, tx: &LedgerTx) -> Result<(), String> {
    let b: KnowBody = serde_json::from_str(&tx.call_args).map_err(|e| e.to_string())?;
    let p = open_proposal(ov, &b.id, block.timestamp)?;
    if p.questions.is_empty() {
        return Err("the proposal has no knowledge test".into());
    }
    if b.option as usize >= p.options.len() {
        return Err("the vote does not fit the proposal".into());
    }
    if ov.get(&know_vote_key(&p.id, &tx.from)).is_none() {
        let n = u64_at(ov, &know_count_key(&p.id));
        put_u64(ov, know_count_key(&p.id), n + 1);
    }
    save(ov, know_vote_key(&p.id, &tx.from), &KnowVote { option: b.option, commit: b.commit, answers: None });
    Ok(())
}

fn know_reveal(ov: &mut Ov, block: &LedgerBlock, tx: &LedgerTx) -> Result<(), String> {
    let b: RevealBody = serde_json::from_str(&tx.call_args).map_err(|e| e.to_string())?;
    let p = load_proposal(ov, &b.id).ok_or("no such proposal")?;
    let mut v: KnowVote = load(ov, &know_vote_key(&p.id, &tx.from)).ok_or("no knowledge vote to reveal")?;
    if v.answers.is_some() {
        return Err("already revealed".into());
    }
    let closes = match (tally_active(p.height), p.revealed_at) {
        (false, _) => p.ends_at + REVEAL_WINDOW_SECS,
        (true, Some(at)) => at + REVEAL_WINDOW_SECS,
        (true, None) => return Err("voters reveal after the creator has revealed the correct answers".into()),
    };
    if block.timestamp < p.ends_at || block.timestamp >= closes {
        return Err("answers are revealed in the 7 days after the correct answers are out".into());
    }
    if !answers_shape_ok(&p.questions, &b.answers) || vote_commit(&p.id, &tx.from, &b.salt, &b.answers) != v.commit {
        return Err("the answers do not match the vote".into());
    }
    if tally_active(p.height) {
        let key = p.answers.as_deref().unwrap_or_default();
        let mut tally: Vec<u64> = load(ov, &know_tally_key(&p.id)).unwrap_or_default();
        tally.resize(p.options.len(), 0);
        if let Some(slot) = tally.get_mut(v.option as usize) {
            *slot += right_answers(&p.questions, key, &b.answers);
        }
        save(ov, know_tally_key(&p.id), &tally);
    }
    v.answers = Some(b.answers);
    save(ov, know_vote_key(&p.id, &tx.from), &v);
    Ok(())
}

fn reveal(ov: &mut Ov, block: &LedgerBlock, tx: &LedgerTx) -> Result<(), String> {
    let b: RevealBody = serde_json::from_str(&tx.call_args).map_err(|e| e.to_string())?;
    let mut p = load_proposal(ov, &b.id).ok_or("no such proposal")?;
    if p.creator != tx.from {
        return Err("only the creator reveals the answers".into());
    }
    if p.questions.is_empty() || p.answers.is_some() {
        return Err("there is nothing to reveal".into());
    }
    if block.timestamp < p.ends_at || block.timestamp >= p.ends_at + REVEAL_WINDOW_SECS {
        return Err("answers are revealed in the 7 days after voting ends".into());
    }
    if !answers_shape_ok(&p.questions, &b.answers) || answers_commit(&b.salt, &b.answers) != p.answers_commit {
        return Err("the answers do not match the commitment".into());
    }
    p.answers = Some(b.answers);
    if tally_active(p.height) {
        p.revealed_at = Some(block.timestamp);
    }
    save(ov, p_key(&p.id), &p);
    Ok(())
}

fn withdraw(ov: &mut Ov, block: &LedgerBlock, tx: &LedgerTx) -> Result<(), String> {
    let b: WithdrawBody = serde_json::from_str(&tx.call_args).map_err(|e| e.to_string())?;
    let mut p = open_proposal(ov, &b.id, block.timestamp)?;
    if p.creator != tx.from {
        return Err("only the creator withdraws a proposal".into());
    }
    p.withdrawn = true;
    save(ov, p_key(&p.id), &p);
    Ok(())
}

pub fn apply_tx(ov: &mut Ov, block: &LedgerBlock, tx: &LedgerTx, network_stake: u64) -> Result<(), String> {
    well_formed(tx, block.height)?;
    match tx.tx_type.as_str() {
        TX_PROPOSE => propose(ov, block, tx, network_stake),
        TX_VOTE => stake_vote(ov, block, tx),
        TX_KNOW => knowledge_vote(ov, block, tx),
        TX_REVEAL => reveal(ov, block, tx),
        TX_KNOW_REVEAL => know_reveal(ov, block, tx),
        TX_REPORT => report(ov, block, tx),
        _ => withdraw(ov, block, tx),
    }
}

pub fn locks_stake(tx: &LedgerTx) -> bool {
    tx.tx_type == TX_VOTE || tx.tx_type == TX_REPORT
}

pub fn apply_block(ov: &mut Ov, block: &LedgerBlock, txs: &[&LedgerTx], network_stake: u64) {
    if !rule_active(block.height) {
        return;
    }
    for tx in txs.iter().filter(|t| is_dao_tx(t)) {
        if let Err(e) = apply_tx(ov, block, tx, network_stake) {
            tracing::debug!("[DAO] {} {} had no effect: {e}", tx.tx_type, tx.hash);
        }
    }
    if arbiter_rules_active(block.height) {
        settle_arbiter_votes(ov, block, network_stake);
    }
}

pub fn validate(ov: &Ov, block: &LedgerBlock, txs: &[LedgerTx]) -> Result<(), String> {
    let active = rule_active(block.height);
    let mut voters = BTreeSet::new();
    for tx in txs.iter().filter(|t| is_dao_tx(t)) {
        if !active {
            return Err(format!("{} {} refused: DAO transactions are not active at block {}", tx.tx_type, tx.hash, block.height));
        }
        well_formed(tx, block.height).map_err(|e| format!("{} {} rejected: {e}", tx.tx_type, tx.hash))?;
        if locks_stake(tx) {
            voters.insert(tx.from.as_str());
        }
    }
    if !active {
        return Ok(());
    }
    for tx in txs.iter().filter(|t| crate::chain_db::is_unstake_tx(t)) {
        if voters.contains(tx.from.as_str()) {
            return Err(format!("unstake {} refused: {} votes or reports with this stake in the same block", tx.hash, tx.from));
        }
        let until = locked_until(ov, &tx.from);
        if until > block.timestamp {
            return Err(format!("unstake {} refused: {} voted with this stake and it stays locked until {until}", tx.hash, tx.from));
        }
    }
    Ok(())
}

pub enum Fit {
    Yes,
    Later(String),
    Never(String),
}

pub fn proposal_fit(ov: &Ov, tx: &LedgerTx, height: u64, timestamp: i64, unstakers: &BTreeSet<String>) -> Fit {
    if is_dao_tx(tx) {
        if !rule_active(height) {
            return Fit::Later(format!("DAO transactions start at block {:?}", ACTIVATION_HEIGHT));
        }
        if let Err(e) = well_formed(tx, height) {
            return Fit::Never(e);
        }
        if locks_stake(tx) && unstakers.contains(&tx.from) {
            return Fit::Later("the sender unstakes in this block".into());
        }
    }
    if rule_active(height) && crate::chain_db::is_unstake_tx(tx) && locked_until(ov, &tx.from) > timestamp {
        return Fit::Later("the stake is locked by a DAO vote".into());
    }
    Fit::Yes
}

pub fn admit(tx: &LedgerTx) -> Result<(), String> {
    if is_dao_tx(tx) {
        if !rule_active_at_tip() {
            return Err(format!("{} refused: DAO transactions are not active yet", tx.tx_type));
        }
        well_formed(tx, crate::chain_db::local_chain_height().saturating_add(1))?;
    }
    if crate::chain_db::is_unstake_tx(tx) && rule_active_at_tip() {
        let until = locked_until(&Ov::new(crate::chain_db::global_db()), &tx.from);
        if until > chrono::Utc::now().timestamp() {
            return Err(format!("your stake is locked by a DAO vote until {until}"));
        }
    }
    Ok(())
}

pub fn status(p: &Proposal, now: i64) -> &'static str {
    if p.withdrawn {
        "withdrawn"
    } else if now < p.ends_at {
        "active"
    } else {
        "expired"
    }
}

pub fn score(questions: &[Question], key: &[u8], answers: &[u8]) -> f64 {
    if questions.is_empty() || !answers_shape_ok(questions, answers) {
        return 0.0;
    }
    let right = key.iter().zip(answers).filter(|(a, b)| a == b).count();
    right as f64 / questions.len() as f64
}

fn knowledge_votes(ov: &Ov, id: &str) -> Vec<KnowVote> {
    ov.committed_keys(&know_prefix(id), KNOWLEDGE_SCAN_LIMIT, |_| false)
        .into_iter()
        .filter_map(|k| load::<KnowVote>(ov, &k))
        .collect()
}

pub fn to_public(ov: &Ov, p: &Proposal, voter: Option<&str>, now: i64) -> DaoProposalPublic {
    let mine_stake = voter.and_then(|v| load::<StakeVote>(ov, &stake_vote_key(&p.id, v)));
    let mine_know = voter.and_then(|v| load::<KnowVote>(ov, &know_vote_key(&p.id, v)));
    let my_test_score = match (&p.answers, mine_know.as_ref().and_then(|k| k.answers.as_ref())) {
        (Some(key), Some(answers)) => Some(score(&p.questions, key, answers)),
        _ => None,
    };
    DaoProposalPublic {
        id: p.id.clone(),
        title: p.title.clone(),
        description: p.description.clone(),
        proposal_type: p.kind.clone(),
        options: p.options.clone(),
        creator: p.creator.clone(),
        created_at: p.created_at,
        voting_ends_at: p.ends_at,
        status: status(p, now).to_string(),
        has_knowledge_test: !p.questions.is_empty(),
        question_count: p.questions.len(),
        stake_vote_count: u64_at(ov, &stake_count_key(&p.id)) as usize,
        knowledge_vote_count: u64_at(ov, &know_count_key(&p.id)) as usize,
        questions: (!p.questions.is_empty()).then(|| {
            p.questions
                .iter()
                .enumerate()
                .map(|(i, q)| DaoTestQuestionPublic { id: format!("q{i}"), question: q.question.clone(), options: q.options.clone() })
                .collect()
        }),
        my_stake_vote: mine_stake.map(|v| v.option as usize),
        my_knowledge_vote: mine_know.map(|v| v.option as usize),
        my_test_score,
        on_chain: true,
        answers_revealed: p.answers.is_some(),
        target: p.target.clone(),
    }
}

pub fn list(ov: &Ov, filter: Option<&str>, voter: Option<&str>, now: i64) -> Vec<DaoProposalPublic> {
    let prefix = key(format_args!("i:"));
    ov.committed_keys(&prefix, LIST_LIMIT, |_| false)
        .into_iter()
        .filter_map(|k| {
            let id = std::str::from_utf8(&k).ok()?.rsplit(':').next()?.to_string();
            load_proposal(ov, &id)
        })
        .filter(|p| match filter {
            None | Some("all") => true,
            Some(s) => status(p, now) == s,
        })
        .map(|p| to_public(ov, &p, voter, now))
        .collect()
}

pub fn results(ov: &Ov, p: &Proposal, now: i64, network_stake: u64) -> DaoProposalResults {
    let n = p.options.len();
    let mut stake_by_opt: Vec<u64> = load(ov, &tally_key(&p.id)).unwrap_or_else(|| vec![0; n]);
    stake_by_opt.resize(n, 0);
    let total_stake: u64 = stake_by_opt.iter().sum();
    let stake_voters = u64_at(ov, &stake_count_key(&p.id));
    let mut know_by_opt = vec![0f64; n];
    if tally_active(p.height) {
        let tally: Vec<u64> = load(ov, &know_tally_key(&p.id)).unwrap_or_default();
        let per = DAO_BASE_KNOWLEDGE_POWER / p.questions.len().max(1) as f64;
        for (slot, right) in know_by_opt.iter_mut().zip(tally) {
            *slot = right as f64 * per;
        }
    } else if let Some(key) = &p.answers {
        for v in knowledge_votes(ov, &p.id) {
            let (Some(slot), Some(answers)) = (know_by_opt.get_mut(v.option as usize), v.answers.as_ref()) else { continue };
            *slot += score(&p.questions, key, answers) * DAO_BASE_KNOWLEDGE_POWER;
        }
    }
    let total_knowledge: f64 = know_by_opt.iter().sum();
    let options: Vec<DaoOptionResult> = p
        .options
        .iter()
        .enumerate()
        .map(|(i, opt)| {
            let sp = if total_stake > 0 { stake_by_opt[i] as f64 / total_stake as f64 } else { 0.0 };
            let kp = if total_knowledge > 0.0 { know_by_opt[i] / total_knowledge } else { 0.0 };
            let cp = match (total_stake > 0, total_knowledge > 0.0) {
                (true, true) => (sp + kp) / 2.0,
                (true, false) => sp,
                (false, true) => kp,
                (false, false) => 0.0,
            };
            DaoOptionResult { option: opt.clone(), stake_power: sp, knowledge_power: kp, combined_power: cp }
        })
        .collect();
    let winning_option_index = options
        .iter()
        .enumerate()
        .max_by(|(_, a), (_, b)| a.combined_power.partial_cmp(&b.combined_power).unwrap_or(std::cmp::Ordering::Equal))
        .filter(|(_, o)| o.combined_power > 0.0)
        .map(|(i, _)| i);
    let quorum_reached = stake_voters >= MIN_STAKE_VOTERS
        && total_stake as u128 * 100 >= network_stake as u128 * MIN_STAKE_PERCENT;
    DaoProposalResults {
        proposal_id: p.id.clone(),
        title: p.title.clone(),
        options,
        winning_option_index,
        total_stake_voters: stake_voters as usize,
        total_knowledge_voters: u64_at(ov, &know_count_key(&p.id)) as usize,
        total_staked_in_votes: total_stake,
        quorum_reached,
        status: status(p, now).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "egot1alice";
    const BOB: &str = "egot1bob";

    fn block(height: u64, timestamp: i64) -> LedgerBlock {
        LedgerBlock { height, timestamp, ..LedgerBlock::default() }
    }

    fn tx(from: &str, tx_type: &str, body: &impl Serialize, nonce: u64) -> LedgerTx {
        let call_args = serde_json::to_string(body).unwrap();
        LedgerTx {
            hash: format!("0x{}", blake3::hash(format!("{from}{tx_type}{call_args}{nonce}").as_bytes()).to_hex()),
            from: from.into(),
            to: from.into(),
            memo: memo_for(tx_type, &call_args),
            tx_type: tx_type.into(),
            call_args,
            nonce,
            ..LedgerTx::default()
        }
    }

    fn run(ov: &mut Ov, block: &LedgerBlock, tx: &LedgerTx) -> Result<(), String> {
        apply_tx(ov, block, tx, 1_000)
    }

    fn with_stake(ov: &mut Ov, addr: &str, amount: u64) {
        ov.put(format!("stake:{addr}").into_bytes(), amount.to_le_bytes().to_vec());
    }

    fn body(questions: Vec<Question>, commit: String) -> ProposeBody {
        ProposeBody {
            title: "Raise the storage rate".into(),
            description: "Pay hosts more".into(),
            kind: "parameter".into(),
            options: vec!["Yes".into(), "No".into()],
            duration_days: 7,
            questions,
            answers_commit: commit,
            target: String::new(),
        }
    }

    fn quiz() -> Vec<Question> {
        vec![
            Question { question: "Block time?".into(), options: vec!["1 s".into(), "10 s".into()] },
            Question { question: "Ticker?".into(), options: vec!["EGO".into(), "EGOC".into(), "EGOT".into()] },
        ]
    }

    #[test]
    fn memo_binds_the_body_and_only_dao_types() {
        let a = memo_for(TX_VOTE, "{\"id\":\"x\"}").unwrap();
        assert!(a.starts_with("dao:vote:"));
        assert_ne!(a, memo_for(TX_VOTE, "{\"id\":\"y\"}").unwrap());
        assert_eq!(memo_for("transfer", "{}"), None);
        assert!(DAO_TYPES.iter().all(|t| memo_for(t, "").unwrap().len() <= crate::ledger::MAX_MEMO_BYTES));
    }

    #[test]
    fn a_changed_body_is_not_well_formed() {
        let mut t = tx(ALICE, TX_PROPOSE, &body(vec![], String::new()), 1);
        assert!(well_formed(&t, 0).is_ok());
        t.call_args = t.call_args.replace("Yes", "Yep");
        assert!(well_formed(&t, 0).is_err());
        let mut sent = tx(ALICE, TX_PROPOSE, &body(vec![], String::new()), 1);
        sent.to = BOB.into();
        assert!(well_formed(&sent, 0).is_err());
        let mut paid = tx(ALICE, TX_PROPOSE, &body(vec![], String::new()), 1);
        paid.amount = 5;
        assert!(well_formed(&paid, 0).is_err());
    }

    #[test]
    fn a_test_must_commit_to_answers() {
        assert!(check_propose(&body(quiz(), String::new())).is_err());
        assert!(check_propose(&body(vec![], answers_commit(&"a".repeat(64), &[1]))).is_err());
        assert!(check_propose(&body(quiz(), answers_commit(&"a".repeat(64), &[1, 1]))).is_ok());
    }

    #[test]
    fn stake_votes_count_stake_once_and_can_change() {
        let mut ov = Ov::memory();
        with_stake(&mut ov, ALICE, 700);
        with_stake(&mut ov, BOB, 300);
        let b = block(10, 1_000);
        let pt = tx(ALICE, TX_PROPOSE, &body(vec![], String::new()), 1);
        run(&mut ov, &b, &pt).unwrap();
        let id = proposal_id(&pt.hash);
        run(&mut ov, &b, &tx(ALICE, TX_VOTE, &VoteBody { id: id.clone(), option: 0 }, 2)).unwrap();
        run(&mut ov, &b, &tx(BOB, TX_VOTE, &VoteBody { id: id.clone(), option: 1 }, 1)).unwrap();
        run(&mut ov, &b, &tx(ALICE, TX_VOTE, &VoteBody { id: id.clone(), option: 1 }, 3)).unwrap();
        let p = load_proposal(&ov, &id).unwrap();
        let r = results(&ov, &p, 1_001, 1_000);
        assert_eq!(r.total_staked_in_votes, 1_000);
        assert_eq!(r.total_stake_voters, 2);
        assert_eq!(r.winning_option_index, Some(1));
        assert_eq!(locked_until(&ov, ALICE), p.ends_at);
        assert!(run(&mut ov, &b, &tx("egot1nostake", TX_VOTE, &VoteBody { id, option: 0 }, 1)).is_err());
    }

    #[test]
    fn voting_stops_at_the_end_and_after_withdrawal() {
        let mut ov = Ov::memory();
        with_stake(&mut ov, BOB, 10);
        let pt = tx(ALICE, TX_PROPOSE, &body(vec![], String::new()), 1);
        run(&mut ov, &block(10, 1_000), &pt).unwrap();
        let id = proposal_id(&pt.hash);
        let ends = 1_000 + 7 * DAY_SECS;
        assert!(run(&mut ov, &block(11, ends), &tx(BOB, TX_VOTE, &VoteBody { id: id.clone(), option: 0 }, 1)).is_err());
        assert!(run(&mut ov, &block(11, 2_000), &tx(BOB, TX_WITHDRAW, &WithdrawBody { id: id.clone() }, 2)).is_err());
        run(&mut ov, &block(11, 2_000), &tx(ALICE, TX_WITHDRAW, &WithdrawBody { id: id.clone() }, 2)).unwrap();
        assert!(run(&mut ov, &block(12, 2_001), &tx(BOB, TX_VOTE, &VoteBody { id: id.clone(), option: 0 }, 3)).is_err());
        assert_eq!(status(&load_proposal(&ov, &id).unwrap(), 2_001), "withdrawn");
    }

    #[test]
    fn five_proposals_per_thirty_days() {
        let mut ov = Ov::memory();
        for n in 0..PROPOSALS_PER_WINDOW as u64 {
            run(&mut ov, &block(10 + n, 1_000 + n as i64), &tx(ALICE, TX_PROPOSE, &body(vec![], String::new()), n)).unwrap();
        }
        assert!(run(&mut ov, &block(20, 2_000), &tx(ALICE, TX_PROPOSE, &body(vec![], String::new()), 9)).is_err());
        run(&mut ov, &block(21, 1_000 + WINDOW_SECS + 1), &tx(ALICE, TX_PROPOSE, &body(vec![], String::new()), 10)).unwrap();
        ov.commit_memory();
        let listed = list(&ov, None, None, 0);
        assert_eq!(listed.len(), PROPOSALS_PER_WINDOW + 1);
        assert_eq!(listed[0].created_at, 1_000 + WINDOW_SECS + 1);
    }

    #[test]
    fn knowledge_scores_appear_only_after_a_matching_reveal() {
        let mut ov = Ov::memory();
        let salt = "5".repeat(64);
        let key = vec![1u8, 1];
        let pt = tx(ALICE, TX_PROPOSE, &body(quiz(), answers_commit(&salt, &key)), 1);
        run(&mut ov, &block(10, 1_000), &pt).unwrap();
        let id = proposal_id(&pt.hash);
        let bob_salt = "6".repeat(64);
        let bob_commit = vote_commit(&id, BOB, &bob_salt, &[1, 1]);
        let vote = tx(BOB, TX_KNOW, &KnowBody { id: id.clone(), option: 0, commit: bob_commit.clone() }, 1);
        assert!(!vote.call_args.contains("[1,1]"), "the answers are not on the chain during the vote");
        run(&mut ov, &block(11, 1_100), &vote).unwrap();
        let p = load_proposal(&ov, &id).unwrap();
        assert_eq!(to_public(&ov, &p, Some(BOB), 1_200).my_test_score, None);
        let ends = p.ends_at;
        let early = tx(ALICE, TX_REVEAL, &RevealBody { id: id.clone(), salt: salt.clone(), answers: key.clone() }, 2);
        assert!(run(&mut ov, &block(12, ends - 1), &early).is_err());
        let wrong = tx(ALICE, TX_REVEAL, &RevealBody { id: id.clone(), salt: salt.clone(), answers: vec![0, 1] }, 3);
        assert!(run(&mut ov, &block(12, ends), &wrong).is_err());
        let stranger = tx(BOB, TX_REVEAL, &RevealBody { id: id.clone(), salt: salt.clone(), answers: key.clone() }, 3);
        assert!(run(&mut ov, &block(12, ends), &stranger).is_err());
        run(&mut ov, &block(12, ends), &tx(ALICE, TX_REVEAL, &RevealBody { id: id.clone(), salt, answers: key }, 4)).unwrap();
        let p = load_proposal(&ov, &id).unwrap();
        assert_eq!(to_public(&ov, &p, Some(BOB), ends).my_test_score, None, "a vote whose answers are not revealed has no score");
        let copied = tx(BOB, TX_KNOW_REVEAL, &RevealBody { id: id.clone(), salt: bob_salt.clone(), answers: vec![0, 1] }, 5);
        assert!(run(&mut ov, &block(13, ends + 1), &copied).is_err(), "answers that differ from the commitment are refused");
        let other = tx(ALICE, TX_KNOW_REVEAL, &RevealBody { id: id.clone(), salt: bob_salt.clone(), answers: vec![1, 1] }, 5);
        assert!(run(&mut ov, &block(13, ends + 1), &other).is_err(), "nobody reveals another voter's answers");
        run(&mut ov, &block(13, ends + 1), &tx(BOB, TX_KNOW_REVEAL, &RevealBody { id: id.clone(), salt: bob_salt, answers: vec![1, 1] }, 6)).unwrap();
        ov.commit_memory();
        let p = load_proposal(&ov, &id).unwrap();
        assert_eq!(to_public(&ov, &p, Some(BOB), ends).my_test_score, Some(1.0));
        let r = results(&ov, &p, ends, 1);
        assert_eq!(r.total_knowledge_voters, 1);
        assert_eq!(r.winning_option_index, Some(0));
    }

    #[test]
    fn knowledge_results_come_from_a_running_count_after_the_switch() {
        let mut ov = Ov::memory();
        let salt = "5".repeat(64);
        let key = vec![1u8, 1];
        let pt = tx(ALICE, TX_PROPOSE, &body(quiz(), answers_commit(&salt, &key)), 1);
        run(&mut ov, &block(2_000, 1_000), &pt).unwrap();
        let id = proposal_id(&pt.hash);
        let bob_salt = "6".repeat(64);
        let vote = tx(BOB, TX_KNOW, &KnowBody { id: id.clone(), option: 1, commit: vote_commit(&id, BOB, &bob_salt, &[1, 0]) }, 1);
        run(&mut ov, &block(2_001, 1_100), &vote).unwrap();
        let ends = load_proposal(&ov, &id).unwrap().ends_at;
        let bob_reveal = tx(BOB, TX_KNOW_REVEAL, &RevealBody { id: id.clone(), salt: bob_salt.clone(), answers: vec![1, 0] }, 2);
        assert!(run(&mut ov, &block(2_002, ends + 1), &bob_reveal).is_err(), "voters wait for the correct answers");
        let late = ends + REVEAL_WINDOW_SECS - 10;
        run(&mut ov, &block(2_003, late), &tx(ALICE, TX_REVEAL, &RevealBody { id: id.clone(), salt, answers: key }, 2)).unwrap();
        run(&mut ov, &block(2_004, late + 100), &bob_reveal).unwrap();
        ov.commit_memory();
        let p = load_proposal(&ov, &id).unwrap();
        assert_eq!(load::<Vec<u64>>(&ov, &know_tally_key(&id)), Some(vec![0, 1]));
        let r = results(&ov, &p, late + 200, 1);
        assert_eq!(r.winning_option_index, Some(1));
        assert!(r.options[1].knowledge_power > 0.99);
    }

    #[test]
    fn staked_reports_stop_a_proposer_and_expire() {
        let mut ov = Ov::memory();
        let reporters = ["egot1r1", "egot1r2", "egot1r3"];
        for r in reporters {
            with_stake(&mut ov, r, 10);
        }
        let t = block(10, 1_000);
        assert!(run(&mut ov, &t, &tx("egot1free", TX_REPORT, &ReportBody { target: ALICE.into() }, 1)).is_err(), "a wallet without stake cannot report");
        assert!(run(&mut ov, &t, &tx(ALICE, TX_REPORT, &ReportBody { target: ALICE.into() }, 1)).is_err());
        for (i, r) in reporters.iter().enumerate() {
            run(&mut ov, &t, &tx(r, TX_REPORT, &ReportBody { target: ALICE.into() }, i as u64)).unwrap();
        }
        assert!(run(&mut ov, &t, &tx(reporters[0], TX_REPORT, &ReportBody { target: ALICE.into() }, 9)).is_err(), "one report per reporter");
        assert!(banned(&active_reports(&ov, ALICE, 1_000), 3_000), "3 reporters holding 1% of all stake stop a proposer");
        assert!(!banned(&active_reports(&ov, ALICE, 1_000), 3_001), "less than 1% of all stake does not");
        assert!(apply_tx(&mut ov, &t, &tx(ALICE, TX_PROPOSE, &body(vec![], String::new()), 1), 3_000).is_err());
        assert_eq!(locked_until(&ov, reporters[0]), 1_000 + REPORT_SECS);
        let later = block(11, 1_000 + REPORT_SECS);
        apply_tx(&mut ov, &later, &tx(ALICE, TX_PROPOSE, &body(vec![], String::new()), 2), 3_000).unwrap();
        assert_eq!(ban_status(&ov, ALICE, Some(reporters[1]), 1_001, 3_000).my_vote, true);
    }

    #[test]
    fn undo_restores_every_dao_key() {
        let mut ov = Ov::memory();
        with_stake(&mut ov, BOB, 10);
        ov.commit_memory();
        let pt = tx(ALICE, TX_PROPOSE, &body(vec![], String::new()), 1);
        run(&mut ov, &block(10, 1_000), &pt).unwrap();
        run(&mut ov, &block(10, 1_000), &tx(BOB, TX_VOTE, &VoteBody { id: proposal_id(&pt.hash), option: 0 }, 1)).unwrap();
        let undo = ov.undo_record();
        ov.commit_memory();
        assert!(load_proposal(&ov, &proposal_id(&pt.hash)).is_some());
        ov.restore_memory(&undo);
        assert!(load_proposal(&ov, &proposal_id(&pt.hash)).is_none());
        assert_eq!(locked_until(&ov, BOB), 0);
        assert_eq!(stake_of(&ov, BOB), 10);
    }

    #[test]
    fn the_block_refuses_dao_txs_before_activation_and_locked_unstakes_after() {
        let ov = Ov::memory();
        let t = tx(ALICE, TX_PROPOSE, &body(vec![], String::new()), 1);
        if ACTIVATION_HEIGHT.is_none() {
            assert!(validate(&ov, &block(10, 1_000), std::slice::from_ref(&t)).is_err());
        }
        let mut ov = Ov::memory();
        put_u64(&mut ov, lock_key(BOB), 5_000);
        let unstake = LedgerTx { from: BOB.into(), to: crate::chain_db::STAKING_ADDR.into(), tx_type: "unstake".into(), ..LedgerTx::default() };
        if let Some(h) = ACTIVATION_HEIGHT {
            assert!(validate(&ov, &block(h, 4_999), std::slice::from_ref(&unstake)).is_err());
            assert!(validate(&ov, &block(h, 5_000), std::slice::from_ref(&unstake)).is_ok());
        } else {
            assert!(validate(&ov, &block(10, 4_999), std::slice::from_ref(&unstake)).is_ok());
        }
    }
}

#[cfg(test)]
mod arbiter_vote_tests {
    use super::*;

    fn block(height: u64, timestamp: i64) -> LedgerBlock {
        LedgerBlock { height, timestamp, ..LedgerBlock::default() }
    }

    fn proposal(ov: &mut Ov, kind: &str, target: &str, ends_at: i64) -> String {
        let id = "a".repeat(64);
        let p = Proposal {
            id: id.clone(),
            title: "arbiter".into(),
            kind: kind.into(),
            options: vec!["Yes".into(), "No".into()],
            ends_at,
            target: target.into(),
            ..Proposal::default()
        };
        save(ov, p_key(&id), &p);
        ov.put(arbiter_end_key(ends_at, &id), Vec::new());
        id
    }

    fn votes(ov: &mut Ov, id: &str, yes: u64, no: u64, voters: u64) {
        save(ov, tally_key(id), &vec![yes, no]);
        put_u64(ov, stake_count_key(id), voters);
    }

    #[test]
    fn a_passed_vote_adds_a_staked_arbiter_when_it_ends_and_not_before() {
        let h = crate::drs::NODE_PAY_V2_FROM_HEIGHT;
        let mut ov = Ov::memory();
        ov.put(b"stake:egot1newarbiter0000000000".to_vec(), (20_000u64 * 1_000_000).to_le_bytes().to_vec());
        let id = proposal(&mut ov, KIND_ARBITER_ADD, "egot1newarbiter0000000000", 1_000);
        votes(&mut ov, &id, 900, 100, 5);
        ov.commit_memory();
        apply_block(&mut ov, &block(h, 999), &[], 10_000);
        ov.commit_memory();
        assert_eq!(arbiter_outcome(&ov, &id), None, "nothing happens before the vote ends");
        apply_block(&mut ov, &block(h + 1, 1_000), &[], 10_000);
        ov.commit_memory();
        assert_eq!(arbiter_outcome(&ov, &id), Some(OUTCOME_APPLIED));
        let list = arbiter_list(&ov, h);
        assert!(list.contains(&"egot1newarbiter0000000000".to_string()));
        assert!(list.len() >= 2, "the founding arbiter stays until the DAO removes it");
    }

    #[test]
    fn a_vote_without_quorum_or_majority_or_stake_changes_nothing() {
        let h = crate::drs::NODE_PAY_V2_FROM_HEIGHT;
        for (yes, no, voters, staked, want) in [
            (900u64, 100u64, 2u64, true, OUTCOME_REJECTED),
            (100, 900, 5, true, OUTCOME_REJECTED),
            (500, 500, 5, true, OUTCOME_REJECTED),
            (1, 0, 5, true, OUTCOME_REJECTED),
            (900, 100, 5, false, OUTCOME_UNCHANGED),
        ] {
            let mut ov = Ov::memory();
            if staked {
                ov.put(b"stake:egot1candidate000000000".to_vec(), (20_000u64 * 1_000_000).to_le_bytes().to_vec());
            }
            let id = proposal(&mut ov, KIND_ARBITER_ADD, "egot1candidate000000000", 10);
            votes(&mut ov, &id, yes, no, voters);
            ov.commit_memory();
            apply_block(&mut ov, &block(h, 10), &[], 10_000);
            ov.commit_memory();
            assert_eq!(arbiter_outcome(&ov, &id), Some(want), "{yes} {no} {voters} {staked}");
            assert!(!arbiter_list(&ov, h).contains(&"egot1candidate000000000".to_string()));
        }
    }

    #[test]
    fn the_last_arbiter_cannot_be_voted_away() {
        let h = crate::drs::NODE_PAY_V2_FROM_HEIGHT;
        let mut ov = Ov::memory();
        let only = crate::market_chain::arbiters_at(h)[0].to_string();
        let id = proposal(&mut ov, KIND_ARBITER_REMOVE, &only, 10);
        votes(&mut ov, &id, 900, 0, 5);
        ov.commit_memory();
        apply_block(&mut ov, &block(h, 10), &[], 10_000);
        ov.commit_memory();
        assert_eq!(arbiter_outcome(&ov, &id), Some(OUTCOME_UNCHANGED));
        assert_eq!(arbiter_list(&ov, h), vec![only]);
    }

    #[test]
    fn arbiter_proposals_are_refused_before_the_switch_and_must_be_yes_or_no() {
        let h = crate::drs::NODE_PAY_V2_FROM_HEIGHT;
        let mut b = ProposeBody {
            title: "Add an arbiter".into(),
            description: String::new(),
            kind: KIND_ARBITER_ADD.into(),
            options: vec!["Yes".into(), "No".into()],
            duration_days: 7,
            questions: Vec::new(),
            answers_commit: String::new(),
            target: "egot1candidate000000000".into(),
        };
        assert!(check_propose_at(&b, h - 1).is_err(), "old nodes do not know this type, so it waits for the switch");
        assert!(check_propose_at(&b, h).is_ok());
        b.options = vec!["Maybe".into(), "No".into()];
        assert!(check_propose_at(&b, h).is_err());
        b.options = vec!["Yes".into(), "No".into()];
        b.target = "0xabc".into();
        assert!(check_propose_at(&b, h).is_err());
    }
}
