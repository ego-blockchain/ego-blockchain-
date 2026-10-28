use crate::chain_db::{read_u64_le, u64_le, CF_META, NODE_POOL_ADDR};
use crate::ledger::{LedgerBlock, LedgerTx};
use rocksdb::{WriteBatch, DB};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const CHECKIN_FROM_HEIGHT: u64 = 32_000;
pub const DRS_FROM_HEIGHT: u64 = 32_601;
pub const FAST_START_HEIGHT: u64 = 32_350;
const FAST_START_RECOUNT_MAX: u64 = 100_000;

pub fn min_streak(period: u64) -> u32 {
    if period >= period_of(FAST_START_HEIGHT) { 1 } else { MIN_STREAK }
}
pub const EPOCH: u64 = 100;
pub const SHORT_EPOCH: u64 = 20;
pub const SHORT_EPOCH_FROM_HEIGHT: u64 = 40_601;
const SHORT_EPOCH_FIRST: u64 = (SHORT_EPOCH_FROM_HEIGHT - 1) / EPOCH;
const _: () = assert!(SHORT_EPOCH_FROM_HEIGHT % EPOCH == 1);
pub const SHORT_READY_DEADLINE: u64 = 18;
pub const WEIGHT_LEAD: u64 = 50;
pub const COMMITTEE_SIZE: usize = 32;
pub const MIN_COMMITTEE: usize = 3;
pub const BLOCK_COMMITTEE: usize = 4;
pub const WIDE_COMMITTEE: usize = 8;
pub const WIDE_POOL_MIN: usize = 16;
pub const WIDE_COMMITTEE_FROM_HEIGHT: u64 = SHORT_EPOCH_FROM_HEIGHT;
pub const WIDE_LAST_MAKERS_KEEP: usize = 32;
pub const DRAW_V2_FROM_HEIGHT: u64 = 32_640;
pub const READY_V2_EPOCH: u64 = 328;
pub const READY_V3_EPOCH: u64 = 329;
pub const DRAW_V3_FROM_HEIGHT: u64 = 32_851;
pub const LAST_MAKERS_KEEP: usize = 16;
pub const SPLIT_FROM_HEIGHT: u64 = 32_901;
pub const TENDERMINT_FROM_HEIGHT: u64 = 33_101;
pub const SKIP_FROM_HEIGHT: u64 = 39_523;
pub const WIDEN_FROM_HEIGHT: u64 = 42_292;
pub const WIDEN_FROM_ATTEMPT: u32 = 2;
pub const WIDEN_ANCHORED_ATTEMPTS: u32 = 32;
pub const WIDEN_V2_FROM_HEIGHT: u64 = 42_311;
pub const WIDEN_V2_ANCHORED_ATTEMPTS: u32 = 8;
pub const TM_CARRY_FROM_HEIGHT: u64 = 42_397;
const TM_CARRY_EPOCHS: u64 = 16;
const WIDEN_READY_EPOCHS: u64 = 8;
const WIDEN_MAX_OUTSIDERS: usize = 512;
pub const RULE_CHANGES: &[u64] = &[32_801, 32_901, DRAW_V3_FROM_HEIGHT, SPLIT_FROM_HEIGHT];
const KEY_STORAGE_TOTAL: &[u8] = b"n2swt";
const KEY_LAST_MAKERS: &[u8] = b"n2last";

pub fn ready_version(epoch: u64) -> u32 {
    let first = epoch_start(epoch);
    1 + RULE_CHANGES.iter().filter(|h| **h <= first).count() as u32
}
pub const MISS_RULE_FROM_HEIGHT: u64 = 32_750;
pub const MISS_LIMIT: u32 = 2;
pub const MISS_RULE_UNTIL_HEIGHT: u64 = 32_766;

pub fn miss_rule_active(height: u64) -> bool {
    (MISS_RULE_FROM_HEIGHT..MISS_RULE_UNTIL_HEIGHT).contains(&height)
}
pub const ROTA_LEN: usize = 128;
pub const READY_DEADLINE: u64 = 90;
pub const CHECKIN_INTERVAL_SECS: i64 = 12 * 3600;
pub const STREAK_GAP_SECS: i64 = 26 * 3600;
pub const MIN_STREAK: u32 = 4;
pub const UPTIME_CAP: u64 = 60;
pub const STORAGE_POINTS_PER_GB: u64 = 10;
pub const STORAGE_CAP: u64 = 10_000;
pub const COVERAGE_POINTS_PER_WITNESS: u64 = 2;
pub const COVERAGE_CAP_WITNESSES: u64 = 20;
pub const COVERAGE_VALID_SECS: i64 = 8 * 86_400;
pub const COVERAGE_MIN_SPACING_SECS: i64 = 6 * 86_400;
pub const MAX_WITNESSES: usize = 32;
pub const MAX_COVERAGE_PROOFS_PER_BLOCK: usize = 512;
pub const TX_COVERAGE_BATCH: &str = "coverage_batch";
pub const NODE_REWARD_PER_DAY_UEGOC: u64 = 50_000 * 1_000_000;
pub const CHECKIN_HALVING_START_TS: i64 = 1_792_382_606;
pub const CHECKIN_HALVING_SECS: i64 = 1_461 * 86_400;

pub fn node_reward_per_day_at(at: i64) -> u64 {
    let era = at.saturating_sub(CHECKIN_HALVING_START_TS).max(0) / CHECKIN_HALVING_SECS;
    if era >= 64 { 0 } else { NODE_REWARD_PER_DAY_UEGOC >> era }
}
pub const MAX_CHECKINS_PER_BLOCK: usize = 2_048;
pub const MAX_EXPIRIES_PER_BLOCK: usize = 20_000;
pub const ANCHOR_MAX_AGE: u64 = 300;
pub const TREE_LEVELS: u32 = 8;
const TREE_FANOUT_BITS: u32 = 4;
const TREE_FANOUT: u64 = 1 << TREE_FANOUT_BITS;
pub const TX_CHECKIN_BATCH: &str = "checkin_batch";
pub const TX_READY_BATCH: &str = "ready_batch";
pub const TX_TM_READY_BATCH: &str = "tm_ready_batch";
const GB: u64 = 1_000_000_000;
const KEY_COUNT: &[u8] = b"n2count";
const KEY_ELIGIBLE: &[u8] = b"n2elig";
const KEY_MIGRATED: &[u8] = b"n2migrated";

pub fn period_of(height: u64) -> u64 {
    (height + WEIGHT_LEAD) / EPOCH
}

pub fn epoch_of(height: u64) -> u64 {
    if height < SHORT_EPOCH_FROM_HEIGHT {
        height.saturating_sub(1) / EPOCH
    } else {
        SHORT_EPOCH_FIRST + (height - SHORT_EPOCH_FROM_HEIGHT) / SHORT_EPOCH
    }
}

pub fn epoch_start(epoch: u64) -> u64 {
    if epoch < SHORT_EPOCH_FIRST {
        epoch.saturating_mul(EPOCH).saturating_add(1)
    } else {
        (epoch - SHORT_EPOCH_FIRST).saturating_mul(SHORT_EPOCH).saturating_add(SHORT_EPOCH_FROM_HEIGHT)
    }
}

pub fn epoch_offset(height: u64) -> u64 {
    height.saturating_add(1).saturating_sub(epoch_start(epoch_of(height)))
}

pub fn ready_deadline(epoch: u64) -> u64 {
    if epoch < SHORT_EPOCH_FIRST { READY_DEADLINE } else { SHORT_READY_DEADLINE }
}

pub fn ready_open(height: u64) -> bool {
    epoch_offset(height) <= ready_deadline(epoch_of(height))
}

pub fn ends_epoch(height: u64) -> bool {
    epoch_of(height.saturating_add(1)) != epoch_of(height)
}

pub fn committee_size(height: u64, pool: usize) -> usize {
    let wide = height >= WIDE_COMMITTEE_FROM_HEIGHT && pool >= WIDE_POOL_MIN;
    (if wide { WIDE_COMMITTEE } else { BLOCK_COMMITTEE }).min(pool)
}

pub fn last_makers_keep(height: u64) -> usize {
    if height >= WIDE_COMMITTEE_FROM_HEIGHT { WIDE_LAST_MAKERS_KEEP } else { LAST_MAKERS_KEEP }
}

pub fn first_drs_epoch() -> u64 {
    epoch_of(DRS_FROM_HEIGHT)
}

fn rec_key(addr: &str) -> Vec<u8> {
    format!("n2rec:{addr}").into_bytes()
}

fn miss_key(addr: &str) -> Vec<u8> {
    format!("n2miss:{addr}").into_bytes()
}

pub fn missed_turns(ov: &Ov, addr: &str, epoch: u64) -> u32 {
    ov.get(&miss_key(addr))
        .filter(|v| v.len() == 12 && read_u64_le(&v[..8]) == epoch)
        .map(|v| u32::from_le_bytes(v[8..12].try_into().unwrap_or([0; 4])))
        .unwrap_or(0)
}

pub fn record_turns(ov: &mut Ov, height: u64, missed: &[String], miner: &str) {
    if !miss_rule_active(height) {
        return;
    }
    let epoch = epoch_of(height);
    for addr in missed.iter().filter(|a| a.as_str() != miner) {
        let count = missed_turns(ov, addr, epoch).saturating_add(1);
        let mut v = epoch.to_le_bytes().to_vec();
        v.extend_from_slice(&count.to_le_bytes());
        ov.put(miss_key(addr), v);
    }
    if !miner.is_empty() && ov.get(&miss_key(miner)).is_some() {
        ov.del(miss_key(miner));
    }
}

pub fn proposer_order(group: &[String], height: u64) -> Vec<String> {
    let n = group.len();
    (0..n).map(|r| group[(height.wrapping_add(r as u64) % n as u64) as usize].clone()).collect()
}

pub fn skipped_before(group: &[String], height: u64, miner: &str) -> Vec<String> {
    let order = proposer_order(group, height);
    match order.iter().position(|a| a == miner) {
        Some(turn) => order[..turn].to_vec(),
        None => Vec::new(),
    }
}

fn addr_key(idx: u64) -> Vec<u8> {
    format!("n2addr:{idx:016x}").into_bytes()
}

fn tree_key(level: u32, index: u64) -> Vec<u8> {
    format!("n2t:{level:02}:{index:016x}").into_bytes()
}

fn expiry_key(ts: i64, addr: &str) -> Vec<u8> {
    format!("n2x:{:016x}:{addr}", ts.max(0) as u64).into_bytes()
}

fn rota_key(epoch: u64) -> Vec<u8> {
    format!("n2rota:{epoch:020}").into_bytes()
}

fn storage_w_key(addr: &str) -> Vec<u8> {
    format!("n2sw:{addr}").into_bytes()
}

pub fn storage_points(rec: &NodeRec, at: i64) -> u64 {
    if at <= rec.storage_until {
        (rec.storage_bytes / GB).saturating_mul(STORAGE_POINTS_PER_GB).min(STORAGE_CAP)
    } else {
        0
    }
}

pub fn split_pay(budget: u128, base: u128, base_total: u128, storage: u128, storage_total: u128) -> u128 {
    match (base_total > 0, storage_total > 0) {
        (true, true) => budget / 2 * base / base_total + budget / 2 * storage / storage_total,
        (true, false) => budget * base / base_total,
        (false, true) => budget * storage / storage_total,
        (false, false) => 0,
    }
}

fn ready_key(epoch: u64) -> Vec<u8> {
    format!("n2ready:{epoch:020}").into_bytes()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct Versioned {
    pub active: u64,
    pub next: u64,
    pub from: u64,
}

impl Versioned {
    pub fn at(&self, period: u64) -> u64 {
        if period >= self.from { self.next } else { self.active }
    }

    fn roll(&mut self, period: u64) {
        if period >= self.from {
            self.active = self.next;
        }
    }

    pub fn set(&mut self, period: u64, value: u64) {
        self.roll(period);
        self.next = value;
        self.from = period + 1;
    }

    pub fn add(&mut self, period: u64, delta: i128) {
        self.roll(period);
        self.next = (self.next as i128 + delta).clamp(0, u64::MAX as i128) as u64;
        self.from = period + 1;
    }

    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(24);
        v.extend_from_slice(&self.active.to_le_bytes());
        v.extend_from_slice(&self.next.to_le_bytes());
        v.extend_from_slice(&self.from.to_le_bytes());
        v
    }

    fn decode(b: &[u8]) -> Self {
        if b.len() < 24 {
            return Self::default();
        }
        Self { active: read_u64_le(&b[..8]), next: read_u64_le(&b[8..16]), from: read_u64_le(&b[16..24]) }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NodeRec {
    pub idx: u64,
    #[serde(default)]
    pub pop_key: String,
    #[serde(default)]
    pub streak: u32,
    #[serde(default)]
    pub last_checkin: i64,
    #[serde(default)]
    pub storage_bytes: u64,
    #[serde(default)]
    pub storage_until: i64,
    #[serde(default)]
    pub coverage: u32,
    #[serde(default)]
    pub coverage_at: i64,
    #[serde(default)]
    pub served: u64,
    #[serde(default)]
    pub weight: Versioned,
    #[serde(default)]
    pub earned: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Rota {
    pub seed: String,
    pub members: Vec<String>,
}

pub struct Ov<'a> {
    db: Option<&'a DB>,
    base: BTreeMap<Vec<u8>, Vec<u8>>,
    map: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl<'a> Ov<'a> {
    pub fn new(db: &'a DB) -> Self {
        Self { db: Some(db), base: BTreeMap::new(), map: BTreeMap::new() }
    }

    #[cfg(test)]
    pub fn memory() -> Ov<'static> {
        Ov { db: None, base: BTreeMap::new(), map: BTreeMap::new() }
    }

    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        if let Some(v) = self.map.get(key) {
            return v.clone();
        }
        self.committed(key)
    }

    fn committed(&self, key: &[u8]) -> Option<Vec<u8>> {
        match self.db {
            Some(db) => {
                let cf = db.cf_handle(CF_META)?;
                db.get_cf(cf, key).ok().flatten()
            }
            None => self.base.get(key).cloned(),
        }
    }

    pub fn undo_record(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for key in self.map.keys() {
            out.extend_from_slice(&(key.len() as u32).to_le_bytes());
            out.extend_from_slice(key);
            match self.committed(key) {
                Some(v) => {
                    out.push(1);
                    out.extend_from_slice(&(v.len() as u32).to_le_bytes());
                    out.extend_from_slice(&v);
                }
                None => out.push(0),
            }
        }
        out
    }

    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.map.insert(key, Some(value));
    }

    pub fn del(&mut self, key: Vec<u8>) {
        self.map.insert(key, None);
    }

    pub fn committed_keys(&self, prefix: &[u8], limit: usize, stop: impl Fn(&[u8]) -> bool) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        match self.db {
            Some(db) => {
                let Some(cf) = db.cf_handle(CF_META) else { return out };
                for item in db.prefix_iterator_cf(cf, prefix) {
                    let Ok((k, _)) = item else { break };
                    if !k.starts_with(prefix) || out.len() >= limit || stop(&k) {
                        break;
                    }
                    out.push(k.to_vec());
                }
            }
            None => {
                for k in self.base.range(prefix.to_vec()..).map(|(k, _)| k) {
                    if !k.starts_with(prefix) || out.len() >= limit || stop(k) {
                        break;
                    }
                    out.push(k.clone());
                }
            }
        }
        out
    }

    #[cfg(test)]
    pub fn restore_memory(&mut self, undo: &[u8]) {
        for (k, v) in read_undo(undo).expect("a well-formed undo record") {
            match v {
                Some(v) => {
                    self.base.insert(k, v);
                }
                None => {
                    self.base.remove(&k);
                }
            }
        }
    }

    #[cfg(test)]
    pub fn commit_memory(&mut self) {
        for (k, v) in std::mem::take(&mut self.map) {
            match v {
                Some(v) => {
                    self.base.insert(k, v);
                }
                None => {
                    self.base.remove(&k);
                }
            }
        }
    }

    pub fn flush(self, batch: &mut WriteBatch) {
        let Some(db) = self.db else { return };
        let Some(cf) = db.cf_handle(CF_META) else { return };
        for (k, v) in self.map {
            match v {
                Some(v) => batch.put_cf(cf, k, v),
                None => batch.delete_cf(cf, k),
            }
        }
    }
}

pub fn read_undo(bytes: &[u8]) -> Option<Vec<(Vec<u8>, Option<Vec<u8>>)>> {
    fn take<'b>(bytes: &'b [u8], i: &mut usize, n: usize) -> Option<&'b [u8]> {
        let s = bytes.get(*i..i.checked_add(n)?)?;
        *i += n;
        Some(s)
    }
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let kl = u32::from_le_bytes(take(bytes, &mut i, 4)?.try_into().ok()?) as usize;
        let k = take(bytes, &mut i, kl)?.to_vec();
        let v = match take(bytes, &mut i, 1)?[0] {
            1 => {
                let vl = u32::from_le_bytes(take(bytes, &mut i, 4)?.try_into().ok()?) as usize;
                Some(take(bytes, &mut i, vl)?.to_vec())
            }
            0 => None,
            _ => return None,
        };
        out.push((k, v));
    }
    Some(out)
}

impl NodeRec {
    const FIXED: usize = 8 + 4 + 8 + 8 + 8 + 4 + 8 + 8 + 24 + 8;

    pub fn encode(&self) -> Vec<u8> {
        let key = hex::decode(&self.pop_key).unwrap_or_default();
        let mut v = Vec::with_capacity(1 + Self::FIXED + 1 + key.len());
        v.push(1u8);
        v.extend_from_slice(&self.idx.to_le_bytes());
        v.extend_from_slice(&self.streak.to_le_bytes());
        v.extend_from_slice(&self.last_checkin.to_le_bytes());
        v.extend_from_slice(&self.storage_bytes.to_le_bytes());
        v.extend_from_slice(&self.storage_until.to_le_bytes());
        v.extend_from_slice(&self.coverage.to_le_bytes());
        v.extend_from_slice(&self.coverage_at.to_le_bytes());
        v.extend_from_slice(&self.served.to_le_bytes());
        v.extend_from_slice(&self.weight.encode());
        v.extend_from_slice(&self.earned.to_le_bytes());
        v.push(key.len() as u8);
        v.extend_from_slice(&key);
        v
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.first() != Some(&1) || b.len() < 1 + Self::FIXED + 1 {
            return None;
        }
        let mut at = 1usize;
        let mut take = |n: usize| {
            let s = &b[at..at + n];
            at += n;
            s
        };
        let idx = read_u64_le(take(8));
        let streak = u32::from_le_bytes(take(4).try_into().ok()?);
        let last_checkin = read_u64_le(take(8)) as i64;
        let storage_bytes = read_u64_le(take(8));
        let storage_until = read_u64_le(take(8)) as i64;
        let coverage = u32::from_le_bytes(take(4).try_into().ok()?);
        let coverage_at = read_u64_le(take(8)) as i64;
        let served = read_u64_le(take(8));
        let weight = Versioned::decode(take(24));
        let earned = read_u64_le(take(8));
        let klen = take(1)[0] as usize;
        if b.len() < at + klen {
            return None;
        }
        let pop_key = hex::encode(&b[at..at + klen]);
        Some(Self { idx, pop_key, streak, last_checkin, storage_bytes, storage_until, coverage, coverage_at, served, weight, earned })
    }
}

pub fn load_rec(ov: &Ov, addr: &str) -> Option<NodeRec> {
    ov.get(&rec_key(addr)).and_then(|v| NodeRec::decode(&v))
}

fn save_rec(ov: &mut Ov, addr: &str, rec: &NodeRec) {
    ov.put(rec_key(addr), rec.encode());
}

pub fn addr_at(ov: &Ov, idx: u64) -> Option<String> {
    ov.get(&addr_key(idx)).and_then(|v| String::from_utf8(v).ok())
}

pub fn node_count(ov: &Ov) -> u64 {
    ov.get(KEY_COUNT).map(|v| read_u64_le(&v)).unwrap_or(0)
}

fn versioned(ov: &Ov, key: &[u8]) -> Versioned {
    ov.get(key).map(|v| Versioned::decode(&v)).unwrap_or_default()
}

pub fn total_weight(ov: &Ov, period: u64) -> u64 {
    versioned(ov, &tree_key(TREE_LEVELS, 0)).at(period)
}

pub fn eligible_count(ov: &Ov, period: u64) -> u64 {
    versioned(ov, KEY_ELIGIBLE).at(period)
}

fn tree_add(ov: &mut Ov, idx: u64, period: u64, delta: i128) {
    for level in 0..=TREE_LEVELS {
        let key = tree_key(level, idx >> (level * TREE_FANOUT_BITS));
        let mut v = versioned(ov, &key);
        v.add(period, delta);
        ov.put(key, v.encode());
    }
}

pub fn sample(ov: &Ov, period: u64, mut r: u64) -> Option<u64> {
    if r >= total_weight(ov, period) {
        return None;
    }
    let mut index = 0u64;
    for level in (1..=TREE_LEVELS).rev() {
        let mut chosen = None;
        for c in 0..TREE_FANOUT {
            let child = index * TREE_FANOUT + c;
            let w = versioned(ov, &tree_key(level - 1, child)).at(period);
            if r < w {
                chosen = Some(child);
                break;
            }
            r -= w;
        }
        index = chosen?;
    }
    Some(index)
}

fn has_consensus_key(ov: &Ov, addr: &str) -> bool {
    crate::genesis::has_key(addr)
        || ov.get(&crate::chain_db::val_dil_key(addr)).map(|k| !k.is_empty()).unwrap_or(false)
}

pub fn weight_of(rec: &NodeRec, at: i64, keys_ok: bool, period: u64) -> u64 {
    if !keys_ok || rec.pop_key.is_empty() || rec.streak < min_streak(period) || at.saturating_sub(rec.last_checkin) > STREAK_GAP_SECS {
        return 0;
    }
    let uptime = (rec.streak as u64).min(UPTIME_CAP);
    let storage = storage_points(rec, at);
    let coverage = if at <= rec.coverage_at.saturating_add(COVERAGE_VALID_SECS) {
        (rec.coverage as u64).min(COVERAGE_CAP_WITNESSES) * COVERAGE_POINTS_PER_WITNESS
    } else {
        0
    };
    uptime + storage + coverage
}

fn next_drop(rec: &NodeRec, at: i64) -> Option<i64> {
    let mut times = Vec::new();
    if rec.streak > 0 {
        times.push(rec.last_checkin.saturating_add(STREAK_GAP_SECS) + 1);
    }
    if rec.storage_bytes >= GB {
        times.push(rec.storage_until + 1);
    }
    if rec.coverage > 0 {
        times.push(rec.coverage_at.saturating_add(COVERAGE_VALID_SECS) + 1);
    }
    times.into_iter().filter(|t| *t > at).min()
}

fn refresh(ov: &mut Ov, addr: &str, rec: &mut NodeRec, at: i64, period: u64) {
    let keys_ok = has_consensus_key(ov, addr);
    let new_w = weight_of(rec, at, keys_ok, period);
    let old_w = rec.weight.next;
    if new_w != old_w {
        rec.weight.set(period, new_w);
        tree_add(ov, rec.idx, period, new_w as i128 - old_w as i128);
        if (old_w == 0) != (new_w == 0) {
            let mut elig = versioned(ov, KEY_ELIGIBLE);
            elig.add(period, if new_w > 0 { 1 } else { -1 });
            ov.put(KEY_ELIGIBLE.to_vec(), elig.encode());
        }
    }
    if period >= period_of(SPLIT_FROM_HEIGHT) {
        let new_s = if new_w > 0 { storage_points(rec, at).min(new_w) } else { 0 };
        let key = storage_w_key(addr);
        let mut sw = versioned(ov, &key);
        if sw.next != new_s {
            let old_s = sw.next;
            sw.set(period, new_s);
            ov.put(key, sw.encode());
            let mut total = versioned(ov, KEY_STORAGE_TOTAL);
            total.add(period, new_s as i128 - old_s as i128);
            ov.put(KEY_STORAGE_TOTAL.to_vec(), total.encode());
        }
    }
    if let Some(t) = next_drop(rec, at) {
        ov.put(expiry_key(t, addr), Vec::new());
    }
}

fn expiry_parts(key: &[u8]) -> Option<(i64, String)> {
    let s = std::str::from_utf8(key.strip_prefix(b"n2x:".as_slice())?).ok()?;
    let (ts_hex, addr) = s.split_once(':')?;
    Some((u64::from_str_radix(ts_hex, 16).ok()? as i64, addr.to_string()))
}

fn process_expiries(ov: &mut Ov, at: i64, period: u64) {
    let due = ov.committed_keys(b"n2x:", MAX_EXPIRIES_PER_BLOCK, |k| {
        expiry_parts(k).map_or(false, |(ts, _)| ts > at)
    });
    for key in due {
        let Some((_, addr)) = expiry_parts(&key) else { continue };
        ov.del(key);
        if let Some(mut rec) = load_rec(ov, &addr) {
            refresh(ov, &addr, &mut rec, at, period);
            save_rec(ov, &addr, &rec);
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Registration {
    pub hash: String,
    pub addr: String,
    pub pop_key: Option<String>,
}

pub fn registration_pop(tx: &LedgerTx, bls_hex: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(&tx.call_args).ok()?;
    let pop = hex::decode(v.get("bls_pop")?.as_str()?).ok()?;
    let pk = hex::decode(bls_hex).ok()?;
    crate::bls_agg::pop_verify(&pk, &pop).then(|| bls_hex.to_string())
}

fn apply_registrations(ov: &mut Ov, txs: &[&LedgerTx], at: i64, period: u64) {
    let mut regs: Vec<Registration> = txs
        .iter()
        .filter_map(|tx| {
            let (addr, bls_hex) = crate::chain_db::parse_validator_registration(tx)?;
            Some(Registration { hash: tx.hash.clone(), pop_key: registration_pop(tx, &bls_hex), addr })
        })
        .collect();
    regs.sort_by(|a, b| a.hash.cmp(&b.hash));
    for reg in regs {
        let mut rec = match load_rec(ov, &reg.addr) {
            Some(r) => r,
            None => {
                let idx = node_count(ov);
                ov.put(KEY_COUNT.to_vec(), u64_le(idx + 1).to_vec());
                ov.put(addr_key(idx), reg.addr.as_bytes().to_vec());
                NodeRec { idx, ..NodeRec::default() }
            }
        };
        rec.pop_key = reg.pop_key.unwrap_or_default();
        refresh(ov, &reg.addr, &mut rec, at, period);
        save_rec(ov, &reg.addr, &rec);
    }
}

pub fn checkin_message(anchor: u64, anchor_hash: &str) -> Vec<u8> {
    format!("ego/checkin/v1:{anchor}:{anchor_hash}").into_bytes()
}

pub fn ready_message(epoch: u64, seed: &str) -> Vec<u8> {
    format!("ego/ready/v{}:{epoch}:{seed}", ready_version(epoch)).into_bytes()
}

pub fn checkin_due(rec: &NodeRec, at: i64) -> bool {
    rec.last_checkin == 0 || at.saturating_sub(rec.last_checkin) >= CHECKIN_INTERVAL_SECS
}

pub fn encode_members(sorted: &[u64]) -> String {
    use base64::Engine;
    let mut out = Vec::with_capacity(sorted.len() * 3);
    let mut prev = 0u64;
    for (i, &v) in sorted.iter().enumerate() {
        let mut d = if i == 0 { v } else { v - prev };
        prev = v;
        loop {
            let b = (d & 0x7f) as u8;
            d >>= 7;
            if d == 0 {
                out.push(b);
                break;
            }
            out.push(b | 0x80);
        }
    }
    base64::engine::general_purpose::STANDARD.encode(out)
}

pub fn decode_members(s: &str) -> Option<Vec<u64>> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD.decode(s).ok()?;
    let mut out = Vec::new();
    let mut cur = 0u64;
    let mut shift = 0u32;
    let mut prev = 0u64;
    for b in bytes {
        if shift > 63 {
            return None;
        }
        cur |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            let v = if out.is_empty() { cur } else { prev.checked_add(cur)? };
            if !out.is_empty() && cur == 0 {
                return None;
            }
            out.push(v);
            prev = v;
            cur = 0;
            shift = 0;
        } else {
            shift += 7;
        }
    }
    (shift == 0).then_some(out)
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SignedGroup {
    pub anchor: u64,
    pub sig: String,
    pub members: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CheckinBatch {
    pub groups: Vec<SignedGroup>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ReadyBatch {
    pub epoch: u64,
    pub sig: String,
    pub members: String,
}

pub fn batch_tx(kind: &str, height: u64, timestamp: i64, call_args: String) -> LedgerTx {
    LedgerTx {
        hash: batch_hash(kind, height, &call_args),
        from: String::new(),
        to: NODE_POOL_ADDR.to_string(),
        amount: 0,
        timestamp,
        status: "Confirmed".to_string(),
        block_height: Some(height),
        tx_type: kind.to_string(),
        signature: "coinbase".to_string(),
        call_args,
        ..LedgerTx::default()
    }
}

pub fn batch_hash(kind: &str, height: u64, call_args: &str) -> String {
    format!("0x{}", blake3::hash(format!("{kind}:{height}:{call_args}").as_bytes()).to_hex())
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CoverageProof {
    pub prover: u64,
    pub challenge: u64,
    pub witnesses: String,
    pub sig: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CoverageBatch {
    pub proofs: Vec<CoverageProof>,
}

pub fn witness_message(beacon_id: &str) -> Vec<u8> {
    format!("ego/witness/v1:{beacon_id}").into_bytes()
}

pub fn is_batch_tx(tx: &LedgerTx) -> bool {
    (tx.tx_type == TX_CHECKIN_BATCH
        || tx.tx_type == TX_READY_BATCH
        || tx.tx_type == TX_TM_READY_BATCH
        || tx.tx_type == TX_COVERAGE_BATCH
        || tx.tx_type == crate::state_cert::TX_STATE_CERT)
        && tx.from.is_empty()
        && tx.to == NODE_POOL_ADDR
        && tx.amount == 0
        && tx.signature == "coinbase"
}

fn anchor_hash_ok(height: u64, anchor: u64, block_hash_at: &impl Fn(u64) -> Option<String>) -> Result<String, String> {
    if anchor == 0 || anchor % EPOCH != 0 || anchor >= height || height - anchor > ANCHOR_MAX_AGE {
        return Err(format!("check-in anchor {anchor} is not a recent epoch boundary for block {height}"));
    }
    block_hash_at(anchor).ok_or_else(|| format!("check-in anchor {anchor} is not on this chain"))
}

pub fn validate_batches(
    ov: &Ov,
    block: &LedgerBlock,
    txs: &[LedgerTx],
    block_hash_at: impl Fn(u64) -> Option<String>,
) -> Result<(), String> {
    let checkins: Vec<&LedgerTx> = txs.iter().filter(|t| t.tx_type == TX_CHECKIN_BATCH).collect();
    let readies: Vec<&LedgerTx> = txs.iter().filter(|t| t.tx_type == TX_READY_BATCH).collect();
    let coverages: Vec<&LedgerTx> = txs.iter().filter(|t| t.tx_type == TX_COVERAGE_BATCH).collect();
    let tm_readies: Vec<&LedgerTx> = txs.iter().filter(|t| t.tx_type == TX_TM_READY_BATCH).collect();
    if checkins.len() > 1 || readies.len() > 1 || coverages.len() > 1 || tm_readies.len() > 1 {
        return Err(format!("block {} carries more than one batch of a kind", block.height));
    }
    for tx in checkins.iter().chain(readies.iter()).chain(coverages.iter()).chain(tm_readies.iter()) {
        if block.height < CHECKIN_FROM_HEIGHT || !is_batch_tx(tx) || tx.hash != batch_hash(&tx.tx_type, block.height, &tx.call_args) {
            return Err(format!("batch tx {} is not one the rules allow in block {}", tx.hash, block.height));
        }
    }
    if let Some(tx) = checkins.first() {
        let batch: CheckinBatch = serde_json::from_str(&tx.call_args).map_err(|e| format!("check-in batch unreadable: {e}"))?;
        let count = node_count(ov);
        let mut seen: BTreeSet<u64> = BTreeSet::new();
        let mut total = 0usize;
        for g in &batch.groups {
            let members = decode_members(&g.members).ok_or("check-in members unreadable")?;
            if members.is_empty() {
                return Err("an empty check-in group".into());
            }
            total += members.len();
            if total > MAX_CHECKINS_PER_BLOCK {
                return Err(format!("more than {MAX_CHECKINS_PER_BLOCK} check-ins in one block"));
            }
            let hash = anchor_hash_ok(block.height, g.anchor, &block_hash_at)?;
            let mut pks = Vec::with_capacity(members.len());
            for idx in &members {
                if *idx >= count || !seen.insert(*idx) {
                    return Err(format!("check-in for node {idx} is unknown or repeated"));
                }
                let addr = addr_at(ov, *idx).ok_or("check-in for an unindexed node")?;
                let rec = load_rec(ov, &addr).ok_or("check-in for a node with no record")?;
                let pk = hex::decode(&rec.pop_key).ok().filter(|k| k.len() == 48).ok_or_else(|| {
                    format!("{addr} has no proven BLS key")
                })?;
                pks.push(pk);
            }
            let sig = hex::decode(&g.sig).map_err(|_| "check-in signature not hex".to_string())?;
            if !crate::bls_agg::verify_shared_aggregate(&sig, &pks, &checkin_message(g.anchor, &hash)) {
                return Err(format!("check-in group at anchor {} does not verify", g.anchor));
            }
        }
    }
    if let Some(tx) = coverages.first() {
        let batch: CoverageBatch = serde_json::from_str(&tx.call_args).map_err(|e| format!("coverage batch unreadable: {e}"))?;
        if batch.proofs.is_empty() || batch.proofs.len() > MAX_COVERAGE_PROOFS_PER_BLOCK {
            return Err("coverage batch is empty or too large".into());
        }
        let count = node_count(ov);
        let mut provers: BTreeSet<u64> = BTreeSet::new();
        for p in &batch.proofs {
            if p.prover >= count || !provers.insert(p.prover) {
                return Err(format!("coverage proof for node {} is unknown or repeated", p.prover));
            }
            if p.challenge == 0 || p.challenge >= block.height || block.height - p.challenge > ANCHOR_MAX_AGE {
                return Err(format!("coverage proof answers block {}, not a recent one", p.challenge));
            }
            let hash = block_hash_at(p.challenge).ok_or("coverage proof answers a block this chain does not have")?;
            let prover = addr_at(ov, p.prover).ok_or("coverage proof for an unindexed node")?;
            let witnesses = decode_members(&p.witnesses).ok_or("coverage witnesses unreadable")?;
            if witnesses.is_empty() || witnesses.len() > MAX_WITNESSES || witnesses.contains(&p.prover) {
                return Err("coverage proof has no witnesses, too many, or witnesses itself".into());
            }
            let mut pks = Vec::with_capacity(witnesses.len());
            for w in &witnesses {
                let addr = addr_at(ov, *w).ok_or("coverage witness is not indexed")?;
                let rec = load_rec(ov, &addr).ok_or("coverage witness has no record")?;
                pks.push(hex::decode(&rec.pop_key).ok().filter(|k| k.len() == 48).ok_or("coverage witness has no proven BLS key")?);
            }
            let sig = hex::decode(&p.sig).map_err(|_| "coverage signature not hex".to_string())?;
            let beacon = crate::coverage_proof::beacon_id_for(&hash, &prover);
            if !crate::bls_agg::verify_shared_aggregate(&sig, &pks, &witness_message(&beacon)) {
                return Err(format!("coverage proof for {prover} does not verify"));
            }
        }
    }
    if let Some(tx) = readies.first() {
        let batch: ReadyBatch = serde_json::from_str(&tx.call_args).map_err(|e| format!("ready batch unreadable: {e}"))?;
        if batch.epoch != epoch_of(block.height) + 1 || !ready_open(block.height) {
            return Err(format!("ready batch for epoch {} in block {}", batch.epoch, block.height));
        }
        let rota = load_rota(ov, batch.epoch).ok_or("ready batch for an epoch with no rota")?;
        let positions = decode_members(&batch.members).ok_or("ready members unreadable")?;
        if positions.is_empty() {
            return Err("an empty ready batch".into());
        }
        let mut pks = Vec::with_capacity(positions.len());
        for p in &positions {
            let addr = rota.members.get(*p as usize).ok_or("ready position outside the rota")?;
            let rec = load_rec(ov, addr).ok_or("ready from a node with no record")?;
            pks.push(hex::decode(&rec.pop_key).ok().filter(|k| k.len() == 48).ok_or("ready from a node with no proven BLS key")?);
        }
        let sig = hex::decode(&batch.sig).map_err(|_| "ready signature not hex".to_string())?;
        if !crate::bls_agg::verify_shared_aggregate(&sig, &pks, &ready_message(batch.epoch, &rota.seed)) {
            return Err("ready batch does not verify".into());
        }
    }
    if let Some(tx) = tm_readies.first() {
        let batch: ReadyBatch = serde_json::from_str(&tx.call_args).map_err(|e| format!("consensus readiness batch unreadable: {e}"))?;
        if tm_ready_epoch_at(block.height) != Some(batch.epoch) {
            return Err(format!("consensus readiness for epoch {} is not open in block {}", batch.epoch, block.height));
        }
        let rota = load_rota(ov, batch.epoch).ok_or("consensus readiness for an epoch with no rota")?;
        let positions = decode_members(&batch.members).ok_or("consensus readiness members unreadable")?;
        if positions.is_empty() {
            return Err("an empty consensus readiness batch".into());
        }
        let mut pks = Vec::with_capacity(positions.len());
        for p in &positions {
            let addr = rota.members.get(*p as usize).ok_or("consensus readiness position outside the rota")?;
            let rec = load_rec(ov, addr).ok_or("consensus readiness from a node with no record")?;
            pks.push(hex::decode(&rec.pop_key).ok().filter(|k| k.len() == 48).ok_or("consensus readiness from a node with no proven BLS key")?);
        }
        let sig = hex::decode(&batch.sig).map_err(|_| "consensus readiness signature not hex".to_string())?;
        if !crate::bls_agg::verify_shared_aggregate(&sig, &pks, &tm_ready_message(batch.epoch, &rota.seed)) {
            return Err("consensus readiness batch does not verify".into());
        }
    }
    Ok(())
}

pub fn load_rota(ov: &Ov, epoch: u64) -> Option<Rota> {
    ov.get(&rota_key(epoch)).and_then(|v| serde_json::from_slice(&v).ok())
}

pub fn ready_set(ov: &Ov, epoch: u64) -> Vec<u8> {
    ov.get(&ready_key(epoch)).unwrap_or_default()
}

fn bit(bits: &[u8], i: usize) -> bool {
    bits.get(i / 8).map(|b| b & (1 << (i % 8)) != 0).unwrap_or(false)
}

fn set_bit(bits: &mut Vec<u8>, i: usize) {
    if bits.len() <= i / 8 {
        bits.resize(i / 8 + 1, 0);
    }
    bits[i / 8] |= 1 << (i % 8);
}

fn draw_rota(ov: &Ov, period: u64, epoch: u64, seed: &str) -> Vec<String> {
    let total = total_weight(ov, period);
    if total == 0 {
        return Vec::new();
    }
    let cooldown = eligible_count(ov, period) / (2 * COMMITTEE_SIZE as u64);
    let mut picked: Vec<String> = Vec::new();
    let mut set: BTreeSet<String> = BTreeSet::new();
    let mut deferred: Vec<String> = Vec::new();
    let draws = (ROTA_LEN * 8) as u64;
    for j in 0..draws {
        if picked.len() >= ROTA_LEN {
            break;
        }
        let mut h = blake3::Hasher::new();
        h.update(b"ego/rota/v2:");
        h.update(seed.as_bytes());
        h.update(&epoch.to_le_bytes());
        h.update(&j.to_le_bytes());
        let r = (u128::from_le_bytes(h.finalize().as_bytes()[..16].try_into().unwrap()) % total as u128) as u64;
        let Some(idx) = sample(ov, period, r) else { continue };
        let Some(addr) = addr_at(ov, idx) else { continue };
        if !set.insert(addr.clone()) {
            continue;
        }
        let rested = cooldown == 0
            || load_rec(ov, &addr).map_or(true, |rec| rec.served == 0 || rec.served.saturating_sub(1) + cooldown < epoch);
        if rested {
            picked.push(addr);
        } else {
            deferred.push(addr);
        }
    }
    for addr in deferred {
        if picked.len() >= ROTA_LEN {
            break;
        }
        picked.push(addr);
    }
    picked
}

pub struct Applied {
    pub credits: Vec<(String, u64)>,
}

pub fn apply_block(
    ov: &mut Ov,
    block: &LedgerBlock,
    txs: &[&LedgerTx],
    pool_balance: u64,
    rota_seed: &str,
) -> Applied {
    let at = block.timestamp;
    let period = period_of(block.height);
    let mut credits: Vec<(String, u64)> = Vec::new();
    if block.height >= CHECKIN_FROM_HEIGHT {
        process_expiries(ov, at, period);
    }
    apply_registrations(ov, txs, at, period);
    if block.height == FAST_START_HEIGHT || block.height == SPLIT_FROM_HEIGHT {
        recount_all(ov, at, period);
    }
    if block.height < CHECKIN_FROM_HEIGHT {
        return Applied { credits };
    }

    if let Some(tx) = txs.iter().find(|t| t.tx_type == TX_CHECKIN_BATCH) {
        if let Ok(batch) = serde_json::from_str::<CheckinBatch>(&tx.call_args) {
            let total_w = total_weight(ov, period) as u128;
            let split = block.height >= SPLIT_FROM_HEIGHT;
            let storage_total = if split { (versioned(ov, KEY_STORAGE_TOTAL).at(period) as u128).min(total_w) } else { 0 };
            let per_checkin = node_reward_per_day_at(at) as u128 * CHECKIN_INTERVAL_SECS as u128 / 86_400;
            let mut members: Vec<u64> = batch.groups.iter().filter_map(|g| decode_members(&g.members)).flatten().collect();
            members.sort_unstable();
            members.dedup();
            let mut pool_left = pool_balance as u128;
            for idx in members {
                let Some(addr) = addr_at(ov, idx) else { continue };
                let Some(mut rec) = load_rec(ov, &addr) else { continue };
                if !checkin_due(&rec, at) {
                    continue;
                }
                let w = rec.weight.at(period) as u128;
                let pay = if split {
                    let s = (versioned(ov, &storage_w_key(&addr)).at(period) as u128).min(w);
                    split_pay(per_checkin, w - s, total_w - storage_total, s, storage_total).min(pool_left)
                } else if total_w > 0 {
                    (per_checkin * w / total_w).min(pool_left)
                } else {
                    0
                };
                pool_left -= pay;
                rec.streak = if rec.streak > 0 && at.saturating_sub(rec.last_checkin) <= STREAK_GAP_SECS {
                    rec.streak.saturating_add(1)
                } else {
                    1
                };
                rec.last_checkin = at;
                rec.earned = rec.earned.saturating_add(pay as u64);
                refresh(ov, &addr, &mut rec, at, period);
                save_rec(ov, &addr, &rec);
                if pay > 0 {
                    credits.push((addr, pay as u64));
                }
            }
        }
    }

    if let Some(tx) = txs.iter().find(|t| t.tx_type == TX_READY_BATCH) {
        if let Ok(batch) = serde_json::from_str::<ReadyBatch>(&tx.call_args) {
            if let Some(positions) = decode_members(&batch.members) {
                let mut bits = ready_set(ov, batch.epoch);
                for p in positions {
                    set_bit(&mut bits, p as usize);
                }
                ov.put(ready_key(batch.epoch), bits);
            }
        }
    }

    if let Some(tx) = txs.iter().find(|t| t.tx_type == TX_TM_READY_BATCH) {
        if let Ok(batch) = serde_json::from_str::<ReadyBatch>(&tx.call_args) {
            if let Some(positions) = decode_members(&batch.members) {
                let mut bits = tm_ready_set(ov, batch.epoch);
                for p in positions {
                    set_bit(&mut bits, p as usize);
                }
                ov.put(tm_ready_key(batch.epoch), bits);
            }
        }
    }

    if let Some(tx) = txs.iter().find(|t| t.tx_type == TX_COVERAGE_BATCH) {
        if let Ok(batch) = serde_json::from_str::<CoverageBatch>(&tx.call_args) {
            for p in batch.proofs {
                let Some(prover) = addr_at(ov, p.prover) else { continue };
                let live: BTreeSet<u64> = decode_members(&p.witnesses)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|w| *w != p.prover)
                    .filter(|w| addr_at(ov, *w).map_or(false, |a| is_live_in(ov, &a, at, period)))
                    .collect();
                record_coverage(ov, &prover, live.len() as u64, at, block.height);
            }
        }
    }

    if block.height >= DRS_FROM_HEIGHT {
        if let Some(mut rec) = load_rec(ov, &block.miner) {
            rec.served = epoch_of(block.height) + 1;
            save_rec(ov, &block.miner, &rec);
        }
        record_maker(ov, block.height, &block.miner);
    }

    if ends_epoch(block.height) {
        let next_epoch = epoch_of(block.height) + 2;
        if next_epoch >= first_drs_epoch() && ov.get(&rota_key(next_epoch)).is_none() {
            let rota = Rota { seed: rota_seed.to_string(), members: draw_rota(ov, period, next_epoch, rota_seed) };
            if let Ok(v) = serde_json::to_vec(&rota) {
                ov.put(rota_key(next_epoch), v);
            }
        }
    }
    Applied { credits }
}

pub fn record_coverage(ov: &mut Ov, addr: &str, witnesses: u64, at: i64, height: u64) {
    if height < CHECKIN_FROM_HEIGHT {
        return;
    }
    let Some(mut rec) = load_rec(ov, addr) else { return };
    if rec.coverage_at > 0 && at.saturating_sub(rec.coverage_at) < COVERAGE_MIN_SPACING_SECS {
        return;
    }
    rec.coverage = witnesses.min(u32::MAX as u64) as u32;
    rec.coverage_at = at;
    refresh(ov, addr, &mut rec, at, period_of(height));
    save_rec(ov, addr, &rec);
}

pub fn record_storage(ov: &mut Ov, addr: &str, bytes: u64, until: i64, at: i64, height: u64) {
    if height < CHECKIN_FROM_HEIGHT {
        return;
    }
    let Some(mut rec) = load_rec(ov, addr) else { return };
    rec.storage_bytes = bytes;
    rec.storage_until = until;
    refresh(ov, addr, &mut rec, at, period_of(height));
    save_rec(ov, addr, &rec);
}

pub fn coverage_spacing_ok(ov: &Ov, addr: &str, at: i64) -> bool {
    load_rec(ov, addr).map_or(true, |rec| rec.coverage_at == 0 || at.saturating_sub(rec.coverage_at) >= COVERAGE_MIN_SPACING_SECS)
}

pub fn is_live(ov: &Ov, addr: &str, at: i64) -> bool {
    load_rec(ov, addr).map_or(false, |rec| rec.streak >= MIN_STREAK && at.saturating_sub(rec.last_checkin) <= STREAK_GAP_SECS)
}

pub fn is_live_in(ov: &Ov, addr: &str, at: i64, period: u64) -> bool {
    load_rec(ov, addr).map_or(false, |rec| rec.streak >= min_streak(period) && at.saturating_sub(rec.last_checkin) <= STREAK_GAP_SECS)
}

fn recount_all(ov: &mut Ov, at: i64, period: u64) {
    let count = node_count(ov);
    if count > FAST_START_RECOUNT_MAX {
        return;
    }
    for idx in 0..count {
        let Some(addr) = addr_at(ov, idx) else { continue };
        let Some(mut rec) = load_rec(ov, &addr) else { continue };
        refresh(ov, &addr, &mut rec, at, period);
        save_rec(ov, &addr, &rec);
    }
}

#[cfg(test)]
pub fn seed_rota_for_tests(ov: &mut Ov, epoch: u64, members: &[String], ready: &[usize]) {
    ov.put(rota_key(epoch), serde_json::to_vec(&Rota { seed: "s".into(), members: members.to_vec() }).unwrap());
    let mut bits = Vec::new();
    for i in ready {
        set_bit(&mut bits, *i);
    }
    ov.put(ready_key(epoch), bits);
}

#[cfg(test)]
pub fn seed_pop_key_for_tests(ov: &mut Ov, addr: &str, pop: &str) {
    let mut rec = load_rec(ov, addr).unwrap_or_default();
    rec.pop_key = pop.to_string();
    save_rec(ov, addr, &rec);
}

#[cfg(test)]
pub fn seed_weight_for_tests(ov: &mut Ov, addr: &str, weight: u64) {
    let mut rec = load_rec(ov, addr).unwrap_or_default();
    rec.weight.set(0, weight);
    save_rec(ov, addr, &rec);
}

pub fn ready_members(ov: &Ov, height: u64) -> Vec<String> {
    let epoch = epoch_of(height);
    let rota = load_rota(ov, epoch).unwrap_or_default();
    let bits = ready_set(ov, epoch);
    rota.members
        .iter()
        .enumerate()
        .filter(|(i, _)| bit(&bits, *i))
        .map(|(_, a)| a.clone())
        .collect()
}

fn tm_ready_key(epoch: u64) -> Vec<u8> {
    format!("n2tmready:{epoch:020}").into_bytes()
}

pub fn tm_ready_message(epoch: u64, seed: &str) -> Vec<u8> {
    format!("ego/ready/tendermint/v1:{epoch}:{seed}").into_bytes()
}

pub fn tm_ready_set(ov: &Ov, epoch: u64) -> Vec<u8> {
    ov.get(&tm_ready_key(epoch)).unwrap_or_default()
}

pub fn tm_ready_epoch_at(height: u64) -> Option<u64> {
    let next = epoch_of(height) + 1;
    (ready_open(height) && epoch_start(next) >= TENDERMINT_FROM_HEIGHT).then_some(next)
}

fn tm_ready_in(ov: &Ov, epoch: u64) -> Vec<String> {
    let rota = load_rota(ov, epoch).unwrap_or_default();
    let bits = tm_ready_set(ov, epoch);
    rota.members
        .iter()
        .enumerate()
        .filter(|(i, _)| bit(&bits, *i))
        .map(|(_, a)| a.clone())
        .collect()
}

pub fn tm_ready_members(ov: &Ov, height: u64) -> Vec<String> {
    let epoch = epoch_of(height);
    let mut ready = tm_ready_in(ov, epoch);
    if ready.len() >= MIN_COMMITTEE || epoch <= SHORT_EPOCH_FIRST {
        return ready;
    }
    let reach = if height >= TM_CARRY_FROM_HEIGHT { TM_CARRY_EPOCHS } else { 1 };
    for e in (epoch.saturating_sub(reach)..epoch).rev().filter(|e| *e >= SHORT_EPOCH_FIRST) {
        for a in tm_ready_in(ov, e) {
            if !ready.contains(&a) {
                ready.push(a);
            }
        }
        if ready.len() >= MIN_COMMITTEE {
            break;
        }
    }
    ready
}

pub fn tendermint_active(ov: &Ov, height: u64) -> bool {
    height >= TENDERMINT_FROM_HEIGHT && tm_ready_members(ov, height).len() >= MIN_COMMITTEE
}

pub fn draw_pool(ov: &Ov, height: u64) -> Vec<String> {
    if tendermint_active(ov, height) {
        return tm_ready_members(ov, height);
    }
    let epoch = epoch_of(height);
    let ready = ready_members(ov, height);
    let mut pool = if ready.len() >= MIN_COMMITTEE {
        ready
    } else {
        load_rota(ov, epoch).unwrap_or_default().members
    };
    if miss_rule_active(height) {
        let answering: Vec<String> = pool.iter().filter(|a| missed_turns(ov, a, epoch) < MISS_LIMIT).cloned().collect();
        if answering.len() >= MIN_COMMITTEE {
            pool = answering;
        }
    }
    pool
}

pub fn last_makers(ov: &Ov) -> Vec<String> {
    ov.get(KEY_LAST_MAKERS).and_then(|v| serde_json::from_slice(&v).ok()).unwrap_or_default()
}

pub fn record_maker(ov: &mut Ov, height: u64, miner: &str) {
    if height < DRAW_V3_FROM_HEIGHT || miner.is_empty() {
        return;
    }
    let mut list = last_makers(ov);
    list.insert(0, miner.to_string());
    list.truncate(last_makers_keep(height));
    if let Ok(v) = serde_json::to_vec(&list) {
        ov.put(KEY_LAST_MAKERS.to_vec(), v);
    }
}

pub fn maker_cooldown(pool_len: usize) -> usize {
    (pool_len / 2).min(LAST_MAKERS_KEEP)
}

pub fn proposer_of(group: &[String], height: u64, round: u32) -> Option<&String> {
    if group.is_empty() {
        return None;
    }
    group.get((height.wrapping_add(round as u64) % group.len() as u64) as usize)
}

fn draw_hash(seed: &str, height: u64, attempt: i64, pick: usize) -> u128 {
    let mut h = blake3::Hasher::new();
    h.update(b"ego/committee-draw/v3:");
    h.update(seed.as_bytes());
    h.update(&height.to_le_bytes());
    h.update(&attempt.to_le_bytes());
    h.update(&(pick as u64).to_le_bytes());
    u128::from_le_bytes(h.finalize().as_bytes()[..16].try_into().unwrap())
}

fn weighted_pick(candidates: &[(String, u64)], r: u128) -> usize {
    let total: u128 = candidates.iter().map(|(_, w)| *w as u128).sum();
    let mut r = r % total.max(1);
    for (i, (_, w)) in candidates.iter().enumerate() {
        if r < *w as u128 {
            return i;
        }
        r -= *w as u128;
    }
    candidates.len().saturating_sub(1)
}

fn weighted_committee(ov: &Ov, height: u64, attempt: i64, seed: &str, pool: Vec<String>) -> Vec<String> {
    let period = period_of(height);
    let size = committee_size(height, pool.len());
    let mut remaining: Vec<(String, u64)> = pool
        .into_iter()
        .map(|a| {
            let w = load_rec(ov, &a).map_or(0, |r| r.weight.at(period));
            (a, w.max(1))
        })
        .collect();
    let recent: Vec<String> = last_makers(ov).into_iter().take(maker_cooldown(remaining.len())).collect();
    let mut order: Vec<String> = Vec::with_capacity(size);
    for pick in 0..size {
        if remaining.is_empty() {
            break;
        }
        let r = draw_hash(seed, height, attempt, pick);
        let idx = if pick == 0 {
            let rested: Vec<usize> = remaining
                .iter()
                .enumerate()
                .filter(|(_, (a, _))| !recent.contains(a))
                .map(|(i, _)| i)
                .collect();
            if rested.is_empty() {
                weighted_pick(&remaining, r)
            } else {
                let cands: Vec<(String, u64)> = rested.iter().map(|i| remaining[*i].clone()).collect();
                rested[weighted_pick(&cands, r)]
            }
        } else {
            weighted_pick(&remaining, r)
        };
        order.push(remaining.remove(idx).0);
    }
    seat_in_turn(height, order)
}

fn seat_in_turn(height: u64, order: Vec<String>) -> Vec<String> {
    let n = order.len();
    let mut rotated = vec![String::new(); n];
    for (k, a) in order.into_iter().enumerate() {
        rotated[(height as usize).wrapping_add(k) % n] = a;
    }
    rotated
}

pub fn widened(height: u64, attempt: u32) -> bool {
    height >= WIDEN_FROM_HEIGHT && attempt >= WIDEN_FROM_ATTEMPT
}

pub fn anchored_attempts(height: u64) -> u32 {
    if height >= WIDEN_V2_FROM_HEIGHT { WIDEN_V2_ANCHORED_ATTEMPTS } else { WIDEN_ANCHORED_ATTEMPTS }
}

fn anchored(height: u64, attempt: u32) -> bool {
    attempt.saturating_sub(WIDEN_FROM_ATTEMPT) < anchored_attempts(height)
}

pub fn extra_seats(base: usize) -> usize {
    let minority = base.saturating_sub(1) / 2;
    (3 * minority + 1).saturating_sub(base).max(1)
}

fn tolerates_minority(base: usize) -> bool {
    let minority = base.saturating_sub(1) / 2;
    crate::chain_db::quorum_of(base) <= base - minority
}

pub fn extra_seats_at(height: u64, base: usize) -> usize {
    if height >= WIDEN_V2_FROM_HEIGHT && tolerates_minority(base) { 0 } else { extra_seats(base) }
}

fn can_vote(ov: &Ov, addr: &str) -> bool {
    crate::genesis::dilithium_pubkey_for(addr).is_some()
        || ov.get(&crate::chain_db::val_dil_key(addr)).map_or(false, |k| !k.is_empty())
}

fn outsiders(ov: &Ov, height: u64, inside: &[String]) -> Vec<String> {
    let epoch = epoch_of(height);
    let mut seen: BTreeSet<String> = inside.iter().cloned().collect();
    let earlier: Vec<String> = (1..=WIDEN_READY_EPOCHS)
        .filter_map(|back| epoch.checked_sub(back))
        .flat_map(|e| tm_ready_in(ov, e))
        .collect();
    let rota = load_rota(ov, epoch).map(|r| r.members).unwrap_or_default();
    let mut out = Vec::new();
    for a in earlier.into_iter().chain(last_makers(ov)).chain(rota) {
        if out.len() >= WIDEN_MAX_OUTSIDERS {
            break;
        }
        if seen.insert(a.clone()) && can_vote(ov, &a) {
            out.push(a);
        }
    }
    out
}

fn widen_hash(seed: &str, height: u64, attempt: u32, pick: usize) -> u128 {
    let mut h = blake3::Hasher::new();
    h.update(b"ego/committee-widen/v1:");
    h.update(seed.as_bytes());
    h.update(&height.to_le_bytes());
    h.update(&attempt.to_le_bytes());
    h.update(&(pick as u64).to_le_bytes());
    u128::from_le_bytes(h.finalize().as_bytes()[..16].try_into().unwrap())
}

fn draw_from(ov: &Ov, height: u64, attempt: u32, seed: &str, from: Vec<String>, count: usize) -> Vec<String> {
    let period = period_of(height);
    let mut remaining: Vec<(String, u64)> = from
        .into_iter()
        .map(|a| {
            let w = load_rec(ov, &a).map_or(0, |r| r.weight.at(period));
            (a, w.max(1))
        })
        .collect();
    let mut picked = Vec::with_capacity(count);
    for pick in 0..count {
        if remaining.is_empty() {
            break;
        }
        let idx = weighted_pick(&remaining, widen_hash(seed, height, attempt, pick));
        picked.push(remaining.remove(idx).0);
    }
    picked
}

fn widened_committee(ov: &Ov, height: u64, attempt: u32, seed: &str, pool: &[String], base: Vec<String>) -> Vec<String> {
    if anchored(height, attempt) {
        let seats = extra_seats_at(height, base.len());
        if seats == 0 {
            return base;
        }
        let extra = draw_from(ov, height, attempt, seed, outsiders(ov, height, &base), seats);
        if extra.is_empty() {
            return base;
        }
        let mut order = base;
        order.extend(extra);
        return seat_in_turn(height, order);
    }
    let mut everyone = pool.to_vec();
    everyone.extend(outsiders(ov, height, pool));
    let fresh = draw_from(ov, height, attempt, seed, everyone, MIN_COMMITTEE);
    if fresh.len() < MIN_COMMITTEE {
        return base;
    }
    seat_in_turn(height, fresh)
}

pub fn committee(ov: &Ov, height: u64, attempt: i64) -> Vec<String> {
    let epoch = epoch_of(height);
    let rota = load_rota(ov, epoch).unwrap_or_default();
    let pool = draw_pool(ov, height);
    if height >= DRAW_V3_FROM_HEIGHT {
        return weighted_committee(ov, height, attempt, &rota.seed, pool);
    }
    let size = BLOCK_COMMITTEE.min(pool.len());
    if pool.len() <= size {
        return pool;
    }
    if height < DRAW_V2_FROM_HEIGHT && attempt <= 0 {
        return pool[..size].to_vec();
    }
    let mut ranked: Vec<([u8; 32], String)> = pool
        .into_iter()
        .map(|a| {
            let mut h = blake3::Hasher::new();
            if height >= DRAW_V2_FROM_HEIGHT {
                h.update(b"ego/committee-draw/v2:");
                h.update(rota.seed.as_bytes());
                h.update(&height.to_le_bytes());
            } else {
                h.update(b"ego/committee-redraw/v1:");
                h.update(rota.seed.as_bytes());
                h.update(&epoch.to_le_bytes());
            }
            h.update(&attempt.to_le_bytes());
            h.update(a.as_bytes());
            (*h.finalize().as_bytes(), a)
        })
        .collect();
    ranked.sort();
    ranked.into_iter().take(size).map(|(_, a)| a).collect()
}

pub fn skip_committee(ov: &Ov, height: u64, attempt: u32) -> Vec<String> {
    let rota = load_rota(ov, epoch_of(height)).unwrap_or_default();
    let full = draw_pool(ov, height);
    let recent = last_makers(ov);
    let answering: Vec<String> = full.iter().filter(|a| recent.contains(a)).cloned().collect();
    let pool = if answering.len() >= MIN_COMMITTEE { answering } else { full.clone() };
    let base = weighted_committee(ov, height, i64::from(attempt), &rota.seed, pool);
    if !widened(height, attempt) || base.is_empty() {
        return base;
    }
    widened_committee(ov, height, attempt, &rota.seed, &full, base)
}

pub fn rota_position(ov: &Ov, epoch: u64, addr: &str) -> Option<(usize, String)> {
    let rota = load_rota(ov, epoch)?;
    let pos = rota.members.iter().position(|a| a == addr)?;
    Some((pos, rota.seed))
}

pub fn migrate(db: &DB, mut blocks: Vec<(u64, i64, Vec<LedgerTx>)>) {
    let mut ov = Ov::new(db);
    if ov.get(KEY_MIGRATED).is_some() {
        return;
    }
    replay_registrations(&mut ov, &mut blocks);
    ov.put(KEY_MIGRATED.to_vec(), b"1".to_vec());
    let mut batch = WriteBatch::default();
    ov.flush(&mut batch);
    let _ = db.write(batch);
}

fn replay_registrations(ov: &mut Ov, blocks: &mut [(u64, i64, Vec<LedgerTx>)]) {
    blocks.sort_by_key(|(h, _, _)| *h);
    for (height, at, txs) in blocks.iter() {
        let refs: Vec<&LedgerTx> = txs.iter().collect();
        apply_registrations(ov, &refs, *at, period_of(*height));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consent_to_the_new_consensus_is_checked_and_recorded_only_in_its_window() {
        let mut ov = Ov::memory();
        let sks: Vec<_> = (0..4u8).map(|i| crate::bls_agg::derive_bls_key(&[i + 1; 32])).collect();
        let addrs: Vec<String> = (0..4).map(|i| format!("egot1tm{i}")).collect();
        for (i, a) in addrs.iter().enumerate() {
            let pop_key = hex::encode(crate::bls_agg::bls_pubkey(&sks[i]));
            save_rec(&mut ov, a, &NodeRec { idx: i as u64, pop_key, ..NodeRec::default() });
        }
        let e = epoch_of(TENDERMINT_FROM_HEIGHT);
        let rota = Rota { seed: "seed".into(), members: addrs.clone() };
        ov.put(rota_key(e), serde_json::to_vec(&rota).unwrap());
        ov.commit_memory();
        let signed = |signers: &[usize], msg: &dyn Fn(u64) -> Vec<u8>| -> String {
            let sigs: Vec<Vec<u8>> = signers.iter().map(|i| crate::bls_agg::sign_shared(&sks[*i], &msg(e))).collect();
            let ids: Vec<u64> = signers.iter().map(|i| *i as u64).collect();
            let agg = crate::bls_agg::aggregate_shared(&sigs).unwrap();
            serde_json::to_string(&ReadyBatch { epoch: e, sig: hex::encode(agg), members: encode_members(&ids) }).unwrap()
        };
        let good = signed(&[0, 1, 2], &|ep| tm_ready_message(ep, "seed"));
        let old_kind = signed(&[0, 1, 2], &|ep| ready_message(ep, "seed"));
        let ts = 1_900_000_000i64;
        let check = |ov: &Ov, height: u64, args: &str| {
            let tx = batch_tx(TX_TM_READY_BATCH, height, ts, args.to_string());
            validate_batches(ov, &block(height, ts), &[tx], |_| None)
        };
        let open = TENDERMINT_FROM_HEIGHT - EPOCH + 5;
        assert!(check(&ov, open, &good).is_ok(), "{:?}", check(&ov, open, &good));
        assert!(check(&ov, open, &old_kind).is_err(), "a signature on the old ready message is not consent to the new consensus");
        assert!(check(&ov, TENDERMINT_FROM_HEIGHT - EPOCH + READY_DEADLINE + 1, &good).is_err(), "after the window closes");
        assert!(check(&ov, TENDERMINT_FROM_HEIGHT - 2 * EPOCH + 5, &good).is_err(), "before the epoch that leads into the switch");
        let forged = signed(&[0, 1], &|ep| tm_ready_message(ep, "seed")).replace("\"members\":\"", "\"members\":\"x");
        assert!(check(&ov, open, &forged).is_err());
        assert!(!tendermint_active(&ov, TENDERMINT_FROM_HEIGHT));
        let tx = batch_tx(TX_TM_READY_BATCH, open, ts, good);
        let _ = apply_block(&mut ov, &block(open, ts), &[&tx], 0, "seed");
        assert_eq!(tm_ready_members(&ov, TENDERMINT_FROM_HEIGHT), addrs[..3].to_vec());
        assert!(tendermint_active(&ov, TENDERMINT_FROM_HEIGHT));
        assert_eq!(draw_pool(&ov, TENDERMINT_FROM_HEIGHT), addrs[..3].to_vec());
    }

    #[test]
    fn the_new_consensus_runs_only_when_three_nodes_are_ready_under_it() {
        let mut ov = Ov::memory();
        let h = TENDERMINT_FROM_HEIGHT;
        let e = epoch_of(h);
        let rota = Rota { seed: "s".into(), members: (0..5).map(|i| format!("egot1n{i}")).collect() };
        ov.put(rota_key(e), serde_json::to_vec(&rota).unwrap());
        let mut old_ready = Vec::new();
        for i in 0..5 {
            set_bit(&mut old_ready, i);
        }
        ov.put(ready_key(e), old_ready);
        assert!(!tendermint_active(&ov, h), "being ready under the old rules does not count");
        let mut bits = Vec::new();
        set_bit(&mut bits, 0);
        set_bit(&mut bits, 3);
        ov.put(tm_ready_key(e), bits.clone());
        assert!(!tendermint_active(&ov, h), "two nodes on the new rules are not enough");
        assert_eq!(draw_pool(&ov, h).len(), 5, "until then everyone ready keeps making blocks the old way");
        set_bit(&mut bits, 4);
        ov.put(tm_ready_key(e), bits);
        assert!(tendermint_active(&ov, h));
        assert!(!tendermint_active(&ov, h - 1), "the epoch before keeps the old rules");
        assert_eq!(tm_ready_members(&ov, h), vec!["egot1n0", "egot1n3", "egot1n4"]);
        assert_eq!(draw_pool(&ov, h), tm_ready_members(&ov, h), "old nodes are left out of the draw");
        let mut seated = committee(&ov, h, 0);
        seated.sort();
        assert_eq!(seated, vec!["egot1n0", "egot1n3", "egot1n4"], "with three ready nodes the committee is all three");
    }

    #[test]
    fn an_undo_record_puts_every_touched_key_back() {
        let mut ov = Ov::memory();
        ov.put(b"n2a".to_vec(), b"1".to_vec());
        ov.put(b"n2b".to_vec(), b"2".to_vec());
        ov.commit_memory();
        ov.put(b"n2a".to_vec(), b"9".to_vec());
        ov.del(b"n2b".to_vec());
        ov.put(b"n2c".to_vec(), b"3".to_vec());
        let undo = ov.undo_record();
        ov.commit_memory();
        ov.restore_memory(&undo);
        assert_eq!(ov.get(b"n2a"), Some(b"1".to_vec()));
        assert_eq!(ov.get(b"n2b"), Some(b"2".to_vec()));
        assert_eq!(ov.get(b"n2c"), None);
        assert!(read_undo(&undo[..undo.len() - 1]).is_none(), "a cut-off record is refused");
    }

    #[test]
    fn a_weight_set_in_one_period_only_counts_from_the_next() {
        let mut v = Versioned::default();
        v.set(5, 10);
        assert_eq!(v.at(5), 0);
        assert_eq!(v.at(6), 10);
        v.set(5, 12);
        assert_eq!(v.at(5), 0);
        assert_eq!(v.at(6), 12);
        v.add(9, -2);
        assert_eq!(v.at(9), 12);
        assert_eq!(v.at(10), 10);
        assert_eq!(v.at(1_000), 10);
        assert_eq!(Versioned::decode(&v.encode()), v);
    }

    #[test]
    fn node_records_round_trip_in_binary() {
        let rec = NodeRec {
            idx: 9_999_999,
            pop_key: KEY.into(),
            streak: 61,
            last_checkin: 1_900_000_123,
            storage_bytes: 5 * GB,
            storage_until: 1_900_086_400,
            coverage: 7,
            coverage_at: 1_899_999_000,
            served: 341,
            weight: Versioned { active: 3, next: 4, from: 5 },
            earned: 123_456_789,
        };
        assert_eq!(NodeRec::decode(&rec.encode()).unwrap(), rec);
        assert!(NodeRec::decode(&[]).is_none());
        let bare = NodeRec { idx: 1, ..NodeRec::default() };
        assert_eq!(NodeRec::decode(&bare.encode()).unwrap(), bare);
    }

    #[test]
    fn member_lists_round_trip_compactly() {
        let ids: Vec<u64> = vec![0, 1, 5, 127, 128, 70_000, 9_999_999];
        let s = encode_members(&ids);
        assert_eq!(decode_members(&s).unwrap(), ids);
        assert!(decode_members(&encode_members(&[3, 3])).is_none());
        let many: Vec<u64> = (0..2_048u64).map(|i| i * 4_000).collect();
        assert!(encode_members(&many).len() < 2_048 * 4);
    }

    const KEY: &str = "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5";

    fn network(n: usize) -> (Ov<'static>, Vec<String>) {
        let mut ov = Ov::memory();
        let mut addrs = Vec::new();
        for i in 0..n {
            let addr = format!("egot1simnode{i:06}");
            let idx = node_count(&ov);
            ov.put(KEY_COUNT.to_vec(), u64_le(idx + 1).to_vec());
            ov.put(addr_key(idx), addr.as_bytes().to_vec());
            ov.put(crate::chain_db::val_dil_key(&addr), vec![1u8; 8]);
            save_rec(&mut ov, &addr, &NodeRec { idx, pop_key: KEY.into(), ..NodeRec::default() });
            addrs.push(addr);
        }
        ov.commit_memory();
        (ov, addrs)
    }

    fn block(height: u64, ts: i64) -> LedgerBlock {
        LedgerBlock { height, timestamp: ts, miner: "egot1simminer".into(), ..LedgerBlock::default() }
    }

    fn checkins(height: u64, ids: &[u64]) -> LedgerTx {
        let batch = CheckinBatch {
            groups: vec![SignedGroup { anchor: height / EPOCH * EPOCH, sig: "00".into(), members: encode_members(ids) }],
        };
        batch_tx(TX_CHECKIN_BATCH, height, 0, serde_json::to_string(&batch).unwrap())
    }

    fn run(ov: &mut Ov, height: u64, ts: i64, ids: &[u64]) -> Vec<(String, u64)> {
        let tx = checkins(height, ids);
        let b = block(height, ts);
        let out = apply_block(ov, &b, &[&tx], u64::MAX, "seed").credits;
        ov.commit_memory();
        out
    }

    #[test]
    fn from_the_fast_start_one_check_in_is_enough_and_the_first_draw_sees_it() {
        let (mut ov, _) = network(6);
        let all: Vec<u64> = (0..6).collect();
        let t0 = 1_900_000_000i64;
        run(&mut ov, CHECKIN_FROM_HEIGHT, t0, &all);
        assert_eq!(total_weight(&ov, period_of(FAST_START_HEIGHT)), 0, "one check-in earns nothing before the fast start");
        apply_block(&mut ov, &block(FAST_START_HEIGHT, t0 + 3_600), &[], u64::MAX, "seed");
        ov.commit_memory();
        assert_eq!(total_weight(&ov, period_of(FAST_START_HEIGHT) + 1), 6, "the fast start counts everyone who checked in");
        let draw_height = (first_drs_epoch() - 1) * EPOCH;
        assert!(FAST_START_HEIGHT < draw_height && draw_height < DRS_FROM_HEIGHT);
        apply_block(&mut ov, &block(draw_height, t0 + 7_200), &[], u64::MAX, "seed");
        ov.commit_memory();
        let rota = load_rota(&ov, first_drs_epoch()).expect("the first open group is drawn");
        assert_eq!(rota.members.len(), 6, "every node that checked in is in the first draw");
    }

    #[test]
    fn nodes_earn_weight_after_two_days_and_lose_it_when_they_stop() {
        let (mut ov, addrs) = network(40);
        let all: Vec<u64> = (0..40).collect();
        let base = CHECKIN_FROM_HEIGHT;
        let t0 = 1_900_000_000i64;
        for k in 0..MIN_STREAK as u64 {
            run(&mut ov, base + k * EPOCH, t0 + k as i64 * CHECKIN_INTERVAL_SECS, &all);
        }
        let later = base + MIN_STREAK as u64 * EPOCH;
        let period = period_of(later);
        assert_eq!(eligible_count(&ov, period), 40);
        assert_eq!(total_weight(&ov, period), 40 * MIN_STREAK as u64);

        let paid = run(&mut ov, later, t0 + MIN_STREAK as i64 * CHECKIN_INTERVAL_SECS, &all);
        let per_checkin = (node_reward_per_day_at(t0 + MIN_STREAK as i64 * CHECKIN_INTERVAL_SECS) as u128 * CHECKIN_INTERVAL_SECS as u128 / 86_400) as u64;
        let sum: u64 = paid.iter().map(|(_, p)| *p).sum();
        assert_eq!(paid.len(), 40);
        assert!(sum <= per_checkin && sum + 40 >= per_checkin, "{sum} vs budget {per_checkin}");

        let half: Vec<u64> = (0..20).collect();
        let mut h = later + EPOCH;
        let mut ts = t0 + (MIN_STREAK as i64 + 1) * CHECKIN_INTERVAL_SECS;
        for _ in 0..4 {
            run(&mut ov, h, ts, &half);
            h += EPOCH;
            ts += CHECKIN_INTERVAL_SECS;
        }
        let p = period_of(h + EPOCH);
        run(&mut ov, h, ts, &[]);
        assert_eq!(eligible_count(&ov, p), 20);
        assert!(load_rec(&ov, &addrs[30]).unwrap().weight.at(p) == 0);
        assert!(load_rec(&ov, &addrs[3]).unwrap().weight.at(p) > 0);
    }

    #[test]
    fn a_checkin_too_soon_is_not_counted_twice() {
        let (mut ov, addrs) = network(3);
        let t0 = 1_900_000_000i64;
        run(&mut ov, CHECKIN_FROM_HEIGHT, t0, &[0, 1, 2]);
        run(&mut ov, CHECKIN_FROM_HEIGHT + 1, t0 + 60, &[0, 1, 2]);
        assert_eq!(load_rec(&ov, &addrs[0]).unwrap().streak, 1);
        run(&mut ov, CHECKIN_FROM_HEIGHT + 2, t0 + CHECKIN_INTERVAL_SECS, &[0]);
        assert_eq!(load_rec(&ov, &addrs[0]).unwrap().streak, 2);
        assert_eq!(load_rec(&ov, &addrs[1]).unwrap().streak, 1);
    }

    #[test]
    fn sampling_follows_weight_and_never_picks_a_weightless_node() {
        let mut ov = Ov::memory();
        let weights = [0u64, 10, 0, 30, 60];
        for (i, w) in weights.iter().enumerate() {
            tree_add(&mut ov, i as u64, 7, *w as i128);
        }
        ov.commit_memory();
        assert_eq!(total_weight(&ov, 8), 100);
        assert_eq!(total_weight(&ov, 7), 0);
        let mut hits = [0u64; 5];
        for r in 0..100u64 {
            hits[sample(&ov, 8, r).unwrap() as usize] += 1;
        }
        assert_eq!(hits, [0, 10, 0, 30, 60]);
        assert!(sample(&ov, 8, 100).is_none());
        let big = (1u64 << 32) - 1;
        assert_eq!(big >> (TREE_LEVELS * TREE_FANOUT_BITS), 0);
        tree_add(&mut ov, big, 9, 5);
        ov.commit_memory();
        assert_eq!(sample(&ov, 10, 100), Some(big));
    }

    #[test]
    fn the_rota_is_distinct_weighted_and_rests_recent_members() {
        let (mut ov, addrs) = network(400);
        let all: Vec<u64> = (0..400).collect();
        let t0 = 1_900_000_000i64;
        for k in 0..MIN_STREAK as u64 {
            run(&mut ov, CHECKIN_FROM_HEIGHT + k * EPOCH, t0 + k as i64 * CHECKIN_INTERVAL_SECS, &all);
        }
        let period = period_of(CHECKIN_FROM_HEIGHT + MIN_STREAK as u64 * EPOCH);
        let epoch = 500u64;
        let rota = draw_rota(&ov, period, epoch, "mix-a");
        assert_eq!(rota.len(), ROTA_LEN);
        let uniq: BTreeSet<&String> = rota.iter().collect();
        assert_eq!(uniq.len(), ROTA_LEN);
        assert_eq!(rota, draw_rota(&ov, period, epoch, "mix-a"));
        assert_ne!(rota, draw_rota(&ov, period, epoch, "mix-b"));

        for a in &rota[..COMMITTEE_SIZE] {
            let mut rec = load_rec(&ov, a).unwrap();
            rec.served = epoch + 1;
            save_rec(&mut ov, a, &rec);
        }
        ov.commit_memory();
        let next = draw_rota(&ov, period, epoch + 1, "mix-c");
        let rested_first = &next[..ROTA_LEN - COMMITTEE_SIZE];
        assert!(rested_first.iter().all(|a| !rota[..COMMITTEE_SIZE].contains(a)));
        assert!(addrs.len() == 400);
    }

    #[test]
    fn the_committee_is_the_ready_part_of_the_rota_and_rotates_on_redraw() {
        let old_epoch = (DRAW_V2_FROM_HEIGHT - 1) / EPOCH - 1;
        let new_epoch = DRAW_V2_FROM_HEIGHT / EPOCH + 1;
        let mut ov = Ov::memory();
        let members: Vec<String> = (0..ROTA_LEN).map(|i| format!("egot1seat{i:03}")).collect();
        let rota = Rota { seed: "s".into(), members: members.clone() };
        for e in [old_epoch, new_epoch] {
            ov.put(rota_key(e), serde_json::to_vec(&rota).unwrap());
        }
        ov.commit_memory();
        let old_h = old_epoch * EPOCH + 5;
        let new_h = new_epoch * EPOCH + 5;
        assert!(old_h < DRAW_V2_FROM_HEIGHT && new_h >= DRAW_V2_FROM_HEIGHT);
        assert_eq!(committee(&ov, old_h, 0), members[..BLOCK_COMMITTEE].to_vec(), "with nobody ready the first drawn make up the group");
        let mut bits = Vec::new();
        for i in (0..ROTA_LEN).filter(|i| i % 2 == 1) {
            set_bit(&mut bits, i);
        }
        for e in [old_epoch, new_epoch] {
            ov.put(ready_key(e), bits.clone());
        }
        ov.commit_memory();
        let ready: Vec<String> = members.iter().enumerate().filter(|(i, _)| i % 2 == 1).map(|(_, a)| a.clone()).collect();
        assert_eq!(committee(&ov, old_h, 0), ready[..BLOCK_COMMITTEE].to_vec(), "before the new draw, the first attempt takes the first ready nodes");
        assert_eq!(committee(&ov, old_h, 1), committee(&ov, old_h + 1, 1), "before the new draw, every height gets the same redraw");

        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut firsts: BTreeSet<Vec<String>> = BTreeSet::new();
        for k in 0..60u64 {
            let h = new_h + k;
            let c = committee(&ov, h, 0);
            assert_eq!(c, committee(&ov, h, 0), "every node draws the same group");
            assert_eq!(c.len(), BLOCK_COMMITTEE);
            assert!(c.iter().all(|a| ready.contains(a)), "only ready nodes are drawn");
            assert_ne!(c, committee(&ov, h, 1), "a redraw changes the group");
            firsts.insert(c.clone());
            seen.extend(c);
        }
        assert!(firsts.len() > 40, "the first group changes from block to block ({} different in 60)", firsts.len());
        assert!(seen.len() > ready.len() * 3 / 4, "blocks rotate through the ready nodes ({} of {})", seen.len(), ready.len());

        let mut three = Vec::new();
        for i in [3usize, 40, 90] {
            set_bit(&mut three, i);
        }
        ov.put(ready_key(new_epoch), three);
        ov.commit_memory();
        assert_eq!(committee(&ov, new_h, 7), vec![members[3].clone(), members[40].clone(), members[90].clone()], "three ready nodes are enough");
        assert!(committee(&Ov::memory(), new_h, 0).is_empty(), "no founders are added when nobody was drawn");
    }

    #[test]
    fn check_in_pay_halves_every_four_years_and_never_drains_the_pool() {
        let start = CHECKIN_HALVING_START_TS;
        assert_eq!(node_reward_per_day_at(start - 86_400), NODE_REWARD_PER_DAY_UEGOC, "before the clock starts the full pool is paid");
        assert_eq!(node_reward_per_day_at(start), NODE_REWARD_PER_DAY_UEGOC);
        assert_eq!(node_reward_per_day_at(start + CHECKIN_HALVING_SECS - 1), NODE_REWARD_PER_DAY_UEGOC, "the first four years pay what nodes are paid today");
        assert_eq!(node_reward_per_day_at(start + CHECKIN_HALVING_SECS), NODE_REWARD_PER_DAY_UEGOC / 2);
        assert_eq!(node_reward_per_day_at(start + 2 * CHECKIN_HALVING_SECS), NODE_REWARD_PER_DAY_UEGOC / 4);
        assert_eq!(node_reward_per_day_at(start + 70 * CHECKIN_HALVING_SECS), 0);
        let total: u128 = (0..64).map(|e| node_reward_per_day_at(start + e * CHECKIN_HALVING_SECS) as u128 * 1_461).sum();
        assert!(total < crate::tokenomics::NODE_POOL_UEGOC as u128 / 2 + NODE_REWARD_PER_DAY_UEGOC as u128 * 1_461, "{} EGOC over all time", total / 1_000_000);
        assert!(total < crate::tokenomics::NODE_POOL_UEGOC as u128, "check-in pay alone never empties the node pool");
    }

    #[test]
    fn the_turns_skipped_before_a_block_s_maker_are_the_ones_that_count() {
        let g: Vec<String> = ["a", "b", "c", "d"].iter().map(|s| s.to_string()).collect();
        assert_eq!(proposer_order(&g, 8), vec!["a", "b", "c", "d"], "height 8 starts the order at 8 % 4 = 0");
        assert_eq!(proposer_order(&g, 9), vec!["b", "c", "d", "a"]);
        assert!(skipped_before(&g, 9, "b").is_empty(), "the first in line made it, nobody skipped");
        assert_eq!(skipped_before(&g, 9, "d"), vec!["b", "c"]);
        assert!(skipped_before(&g, 9, "z").is_empty(), "a maker outside the group skips nobody");
    }

    #[test]
    fn the_missed_turn_rule_only_ever_applied_between_32750_and_32765() {
        let h = MISS_RULE_FROM_HEIGHT + 1;
        let e = epoch_of(h);
        assert_eq!(e, epoch_of(MISS_RULE_UNTIL_HEIGHT + 20), "the test stays inside one epoch");
        let mut ov = Ov::memory();
        let members: Vec<String> = (0..6).map(|i| format!("egot1n{i}")).collect();
        ov.put(rota_key(e), serde_json::to_vec(&Rota { seed: "s".into(), members: members.clone() }).unwrap());
        let mut bits = Vec::new();
        for i in 0..6 {
            set_bit(&mut bits, i);
        }
        ov.put(ready_key(e), bits);
        ov.commit_memory();
        let silent = members[0].clone();
        record_turns(&mut ov, h, &[silent.clone()], &members[1]);
        record_turns(&mut ov, h + 1, &[silent.clone()], &members[2]);
        ov.commit_memory();
        assert_eq!(missed_turns(&ov, &silent, e), 2);
        for x in h + 2..MISS_RULE_UNTIL_HEIGHT {
            for attempt in 0..3 {
                assert!(!committee(&ov, x, attempt).contains(&silent), "while the rule ran, two misses left a node out");
            }
        }
        assert!(
            (MISS_RULE_UNTIL_HEIGHT..MISS_RULE_UNTIL_HEIGHT + 20).any(|x| committee(&ov, x, 0).contains(&silent)),
            "from 32,766 nobody is left out for missed turns"
        );
        assert_eq!(draw_pool(&ov, MISS_RULE_UNTIL_HEIGHT).len(), 6);
        record_turns(&mut ov, MISS_RULE_UNTIL_HEIGHT, &[members[3].clone()], &members[1]);
        ov.commit_memory();
        assert_eq!(missed_turns(&ov, &members[3], e), 0, "and no new misses are counted");
        let mut old = Ov::memory();
        record_turns(&mut old, MISS_RULE_FROM_HEIGHT - 1, &[silent.clone()], &members[1]);
        old.commit_memory();
        assert_eq!(missed_turns(&old, &silent, epoch_of(MISS_RULE_FROM_HEIGHT - 1)), 0, "nothing is counted before the rule starts");
    }

    fn weighted_network(weights: &[u64]) -> (Ov<'static>, Vec<String>, u64) {
        let e = epoch_of(DRAW_V3_FROM_HEIGHT) + 1;
        let mut ov = Ov::memory();
        let members: Vec<String> = (0..weights.len()).map(|i| format!("egot1w{i}")).collect();
        let all: Vec<usize> = (0..weights.len()).collect();
        seed_rota_for_tests(&mut ov, e, &members, &all);
        for (m, w) in members.iter().zip(weights) {
            seed_weight_for_tests(&mut ov, m, *w);
        }
        ov.commit_memory();
        (ov, members, e * EPOCH + 1)
    }

    fn simulate(ov: &mut Ov, members: &[String], first: u64, blocks: u64) -> Vec<u64> {
        let mut counts = vec![0u64; members.len()];
        let mut recent: Vec<String> = Vec::new();
        for h in first..first + blocks {
            let group = committee(ov, h, 0);
            assert_eq!(group, committee(ov, h, 0), "every node draws the same group");
            assert_eq!(group.len(), BLOCK_COMMITTEE.min(members.len()));
            let mut unique = group.clone();
            unique.sort();
            unique.dedup();
            assert_eq!(unique.len(), group.len(), "a group holds distinct nodes");
            let proposer = proposer_of(&group, h, 0).unwrap().clone();
            assert!(!recent.contains(&proposer), "a node that just made a block waits its turn (h={h}, {proposer}, recent {recent:?})");
            counts[members.iter().position(|m| *m == proposer).unwrap()] += 1;
            recent.insert(0, proposer.clone());
            recent.truncate(maker_cooldown(members.len()));
            record_maker(ov, h, &proposer);
            ov.commit_memory();
        }
        counts
    }

    #[test]
    fn the_best_drs_makes_the_most_blocks_but_everyone_ready_gets_a_turn() {
        let (mut ov, members, first) = weighted_network(&[1_000, 10, 10, 10, 10, 10]);
        let counts = simulate(&mut ov, &members, first, 90);
        assert!(counts[1..].iter().all(|c| counts[0] > *c), "the highest DRS makes the most blocks: {counts:?}");
        assert!(counts.iter().all(|c| *c >= 3), "every ready node makes blocks: {counts:?}");
        assert!(counts[0] <= 90 / (maker_cooldown(6) as u64 + 1) + 1, "the cooldown stops one node from taking every block: {counts:?}");
        assert_eq!(last_makers(&ov).len(), LAST_MAKERS_KEEP);
    }

    #[test]
    fn equal_drs_shares_the_blocks_evenly_and_a_redraw_changes_the_group() {
        let (mut ov, members, first) = weighted_network(&[50, 50, 50, 50, 50, 50]);
        let counts = simulate(&mut ov, &members, first, 99);
        assert!(counts.iter().all(|c| *c >= 10), "equal scores share evenly: {counts:?}");
        let h = first + 50;
        let a0 = committee(&ov, h, 0);
        let a1 = committee(&ov, h, 1);
        assert_ne!(a0, a1, "a stalled attempt draws a different group");
        assert_eq!(proposer_of(&a0, h, 1), Some(&a0[(h as usize + 1) % 4]), "the next round hands the block to the next drawn node");
        let mut before = Ov::memory();
        record_maker(&mut before, DRAW_V3_FROM_HEIGHT - 1, "egot1x");
        before.commit_memory();
        assert!(last_makers(&before).is_empty(), "nothing is recorded before the rule starts");
    }

    #[test]
    fn a_replacement_committee_is_drawn_the_same_everywhere_from_nodes_that_made_blocks_lately() {
        let (mut ov, members, first) = weighted_network(&[50, 50, 50, 50, 50, 50, 50, 50]);
        let h = first + 20;
        for i in 0..LAST_MAKERS_KEEP {
            record_maker(&mut ov, h - 1, &members[i % 5]);
        }
        ov.commit_memory();
        let c1 = skip_committee(&ov, h, 1);
        assert_eq!(c1, skip_committee(&ov, h, 1), "every node draws the same replacement");
        assert_eq!(c1.len(), BLOCK_COMMITTEE);
        assert!(c1.iter().all(|a| members[..5].contains(a)), "only nodes that made blocks lately are drawn: {c1:?}");
        assert!((2..8).any(|a| skip_committee(&ov, h, a) != c1), "later attempts draw other groups");

        let (quiet, members, first) = weighted_network(&[50, 50, 50, 50, 50, 50]);
        let c = skip_committee(&quiet, first + 1, 1);
        assert_eq!(c.len(), BLOCK_COMMITTEE, "with no recent makers the whole pool is drawn from");
        assert!(c.iter().all(|a| members.contains(a)));
    }

    #[test]
    fn short_epochs_follow_the_last_long_one_without_a_gap() {
        let s = SHORT_EPOCH_FROM_HEIGHT;
        let e0 = epoch_of(s);
        assert_eq!(epoch_of(s - 1), e0 - 1);
        assert_eq!(epoch_start(e0 - 1), s - EPOCH);
        assert_eq!((epoch_start(e0), epoch_start(e0 + 1), epoch_start(e0 + 2)), (s, s + SHORT_EPOCH, s + 2 * SHORT_EPOCH));
        assert_eq!((epoch_of(s + SHORT_EPOCH - 1), epoch_of(s + SHORT_EPOCH)), (e0, e0 + 1));
        for h in 33_000..s {
            let e = (h - 1) / EPOCH;
            assert_eq!(epoch_of(h), e, "before the switch nothing moves (h={h})");
            assert_eq!(epoch_offset(h), h - e * EPOCH);
            assert_eq!(ready_open(h), h - e * EPOCH <= READY_DEADLINE);
            assert_eq!(ends_epoch(h), h % EPOCH == 0);
            assert_eq!(epoch_start(e), e * EPOCH + 1);
        }
        for h in s - 3 * EPOCH..s + 10 * SHORT_EPOCH {
            let e = epoch_of(h);
            assert!(epoch_start(e) <= h && h < epoch_start(e + 1), "h={h} sits inside its epoch");
            assert!((1..=epoch_start(e + 1) - epoch_start(e)).contains(&epoch_offset(h)));
            assert_eq!(ends_epoch(h), h + 1 == epoch_start(e + 1));
        }
        assert!(ends_epoch(s - 1) && ends_epoch(s + SHORT_EPOCH - 1) && !ends_epoch(s));
        assert_eq!(tm_ready_epoch_at(s - EPOCH + READY_DEADLINE - 1), Some(e0), "the last long epoch keeps its long window");
        assert_eq!(tm_ready_epoch_at(s - EPOCH + READY_DEADLINE), None);
        assert_eq!(tm_ready_epoch_at(s), Some(e0 + 1));
        assert_eq!(tm_ready_epoch_at(s + SHORT_READY_DEADLINE - 1), Some(e0 + 1));
        assert_eq!(tm_ready_epoch_at(s + SHORT_READY_DEADLINE), None, "a short epoch closes readiness two blocks before it ends");
        assert_eq!(tm_ready_epoch_at(s + SHORT_EPOCH), Some(e0 + 2));
        assert_eq!(ready_version(e0 + 5), ready_version(e0 - 1), "no rule change hides in the new numbering");
    }

    #[test]
    fn every_short_epoch_has_its_rota_drawn_two_epochs_ahead() {
        let (mut ov, _) = network(6);
        let s = SHORT_EPOCH_FROM_HEIGHT;
        let e0 = epoch_of(s);
        let apply = |ov: &mut Ov, h: u64| {
            let _ = apply_block(ov, &block(h, 1_900_000_000 + h as i64), &[], 0, &format!("seed{h}"));
            ov.commit_memory();
        };
        apply(&mut ov, s - EPOCH - 1);
        assert!(load_rota(&ov, e0).is_some(), "the old rule draws the first short epoch");
        apply(&mut ov, s - 1);
        assert!(load_rota(&ov, e0 + 1).is_some(), "and the one after it, from the last long epoch");
        for h in s..s + SHORT_EPOCH - 1 {
            apply(&mut ov, h);
        }
        assert!(load_rota(&ov, e0 + 2).is_none(), "nothing is drawn inside an epoch");
        apply(&mut ov, s + SHORT_EPOCH - 1);
        assert_eq!(load_rota(&ov, e0 + 2).map(|r| r.seed), Some(format!("seed{}", s + SHORT_EPOCH - 1)));
        apply(&mut ov, s + 2 * SHORT_EPOCH - 1);
        assert!(load_rota(&ov, e0 + 3).is_some());
        assert!(load_rota(&ov, e0 + 4).is_none());
    }

    #[test]
    fn committees_widen_to_eight_only_for_a_big_pool_after_the_switch() {
        let s = WIDE_COMMITTEE_FROM_HEIGHT;
        assert_eq!(committee_size(s - 1, 100), BLOCK_COMMITTEE);
        assert_eq!(committee_size(s, WIDE_POOL_MIN - 1), BLOCK_COMMITTEE, "a small network keeps committees of four");
        assert_eq!(committee_size(s, WIDE_POOL_MIN), WIDE_COMMITTEE);
        assert_eq!(committee_size(s, 3), 3, "three nodes still make blocks");
        assert_eq!(crate::chain_db::quorum_of(WIDE_COMMITTEE), 6);
        assert_eq!(crate::chain_db::skip_threshold_of(WIDE_COMMITTEE), 3, "three give-ups move a wide committee on");

        let e = epoch_of(s + 3 * SHORT_EPOCH);
        let h = epoch_start(e) + 1;
        let mut ov = Ov::memory();
        let members: Vec<String> = (0..20).map(|i| format!("egot1wide{i:02}")).collect();
        seed_rota_for_tests(&mut ov, e, &members, &(0..20).collect::<Vec<_>>());
        for m in &members {
            seed_weight_for_tests(&mut ov, m, 50);
        }
        ov.commit_memory();
        let c = committee(&ov, h, 0);
        let mut unique = c.clone();
        unique.sort();
        unique.dedup();
        assert_eq!((c.len(), unique.len()), (WIDE_COMMITTEE, WIDE_COMMITTEE));
        for i in 0..40 {
            record_maker(&mut ov, h, &members[i % 20]);
        }
        ov.commit_memory();
        assert_eq!(last_makers(&ov).len(), WIDE_LAST_MAKERS_KEEP);
        assert_eq!(skip_committee(&ov, h, 1).len(), WIDE_COMMITTEE, "replacements are drawn from the last 32 makers");

        let mut small = Ov::memory();
        seed_rota_for_tests(&mut small, e, &members[..10], &(0..10).collect::<Vec<_>>());
        small.commit_memory();
        assert_eq!(committee(&small, h, 0).len(), BLOCK_COMMITTEE);
    }

    fn stuck_pool_network() -> (Ov<'static>, Vec<String>, Vec<String>, u64) {
        stuck_pool_network_with(10)
    }

    fn stuck_pool_network_with(outside: usize) -> (Ov<'static>, Vec<String>, Vec<String>, u64) {
        widen_network(WIDEN_FROM_HEIGHT, &["egot1pooldead", "egot1poolm", "egot1poolp"], outside)
    }

    fn widen_network(h: u64, pool: &[&str], outside: usize) -> (Ov<'static>, Vec<String>, Vec<String>, u64) {
        let e = epoch_of(h);
        let pool: Vec<String> = pool.iter().map(|s| s.to_string()).collect();
        let others: Vec<String> = (0..outside).map(|i| format!("egot1outside{i}")).collect();
        let mut members = pool.clone();
        members.extend(others.iter().cloned());
        members.push("egot1nokey".into());
        let mut ov = Ov::memory();
        ov.put(rota_key(e), serde_json::to_vec(&Rota { seed: "s".into(), members: members.clone() }).unwrap());
        let mut bits = Vec::new();
        for i in 0..pool.len() {
            set_bit(&mut bits, i);
        }
        ov.put(tm_ready_key(e), bits);
        for m in &members {
            seed_weight_for_tests(&mut ov, m, 50);
            if m != "egot1nokey" {
                ov.put(crate::chain_db::val_dil_key(m), vec![1u8; 8]);
            }
        }
        ov.commit_memory();
        (ov, pool, others, h)
    }

    #[test]
    fn extra_seats_keep_a_minority_of_dead_members_passable() {
        assert_eq!(extra_seats(3), 1);
        assert_eq!(extra_seats(4), 1);
        assert_eq!(extra_seats(5), 2);
        assert_eq!(extra_seats(8), 2);
        for c in 3..=16usize {
            let n = c + extra_seats(c);
            let dead = (c - 1) / 2;
            let q = crate::chain_db::quorum_of(n);
            let t = crate::chain_db::skip_threshold_of(n);
            assert!(t <= c - dead, "with {dead} of {c} away the rest can still pass a widened committee on");
            assert!(q <= n - dead, "with {dead} of {c} away a widened committee can still finish once its new seats answer");
        }
    }

    #[test]
    fn a_stuck_three_node_pool_hands_the_block_to_nodes_outside_it() {
        let (ov, pool, others, h) = stuck_pool_network();
        assert_eq!(draw_pool(&ov, h), pool);
        let mut c1 = skip_committee(&ov, h, 1);
        c1.sort();
        let mut sorted_pool = pool.clone();
        sorted_pool.sort();
        assert_eq!(c1, sorted_pool, "the first redraw still comes from the pool");

        let mut outside_seen = BTreeSet::new();
        for attempt in WIDEN_FROM_ATTEMPT..WIDEN_FROM_ATTEMPT + WIDEN_ANCHORED_ATTEMPTS {
            let c = skip_committee(&ov, h, attempt);
            assert_eq!(c, skip_committee(&ov, h, attempt), "every node draws the same widened committee");
            assert_eq!(c.len(), pool.len() + 1);
            assert!(pool.iter().all(|p| c.contains(p)), "the nodes still answering keep their seats");
            let extra: Vec<&String> = c.iter().filter(|a| !pool.contains(a)).collect();
            assert_eq!(extra.len(), 1);
            assert!(others.contains(extra[0]), "the new seat goes to a node that can sign: {extra:?}");
            outside_seen.insert(extra[0].clone());
        }
        assert!(outside_seen.len() >= others.len() / 2, "attempts keep drawing other outside nodes: {outside_seen:?}");

        let mut fresh_without_dead = false;
        for attempt in WIDEN_FROM_ATTEMPT + WIDEN_ANCHORED_ATTEMPTS..WIDEN_FROM_ATTEMPT + WIDEN_ANCHORED_ATTEMPTS + 40 {
            let c = skip_committee(&ov, h, attempt);
            assert_eq!(c.len(), MIN_COMMITTEE);
            assert!(!c.iter().any(|a| a == "egot1nokey"));
            fresh_without_dead |= !c.contains(&pool[0]) && c.iter().any(|a| others.contains(a));
        }
        assert!(fresh_without_dead, "after the anchored attempts whole new committees are drawn");

        let before = WIDEN_FROM_HEIGHT - 1;
        assert!(!widened(before, 5) && !widened(h, 1) && widened(h, 2));
    }

    #[test]
    fn with_one_pool_member_gone_every_widened_committee_can_be_passed_on_until_one_finishes() {
        let (ov, pool, others, h) = stuck_pool_network();
        let live: BTreeSet<String> = [pool[1].clone(), pool[2].clone(), others[3].clone(), others[7].clone()].into_iter().collect();
        let mut finished_at = None;
        for attempt in WIDEN_FROM_ATTEMPT..WIDEN_FROM_ATTEMPT + WIDEN_ANCHORED_ATTEMPTS {
            let c = skip_committee(&ov, h, attempt);
            let present = c.iter().filter(|a| live.contains(*a)).count();
            assert!(present >= crate::chain_db::skip_threshold_of(c.len()), "attempt {attempt} can be passed on: {c:?}");
            if present >= crate::chain_db::quorum_of(c.len()) {
                finished_at = Some(attempt);
                break;
            }
        }
        assert!(finished_at.is_some(), "an outside node that answers finishes the block");
    }

    #[test]
    fn two_of_three_pool_members_unable_still_end_in_a_committee_of_three_that_answer() {
        let (ov, pool, others, h) = stuck_pool_network_with(2);
        let able: BTreeSet<String> = [pool[1].clone(), others[0].clone(), others[1].clone()].into_iter().collect();
        let mut finished_at = None;
        for attempt in 1..WIDEN_FROM_ATTEMPT + WIDEN_ANCHORED_ATTEMPTS + 200 {
            let c = skip_committee(&ov, h, attempt);
            let answering = c.iter().filter(|a| able.contains(*a)).count();
            if answering >= crate::chain_db::quorum_of(c.len()) {
                finished_at = Some(attempt);
                break;
            }
            assert!(answering >= crate::chain_db::skip_threshold_of(c.len()), "attempt {attempt} can be passed on: {c:?}");
        }
        let at = finished_at.expect("three answering nodes make the block without the two that stopped");
        assert!(at >= WIDEN_FROM_ATTEMPT + WIDEN_ANCHORED_ATTEMPTS, "only whole new committees can leave both out (finished at {at})");
    }

    #[test]
    fn from_the_second_rule_four_seat_committees_get_no_outside_seat_and_fresh_ones_come_sooner() {
        let v1 = WIDEN_V2_FROM_HEIGHT - 1;
        let v2 = WIDEN_V2_FROM_HEIGHT;
        assert_eq!((extra_seats_at(v1, 4), extra_seats_at(v2, 4)), (1, 0), "a seat added to four only makes finishing harder");
        assert_eq!((extra_seats_at(v2, 3), extra_seats_at(v2, 5), extra_seats_at(v2, 8)), (1, 2, 2));
        assert_eq!((anchored_attempts(v1), anchored_attempts(v2)), (WIDEN_ANCHORED_ATTEMPTS, WIDEN_V2_ANCHORED_ATTEMPTS));
        assert!(WIDEN_V2_FROM_HEIGHT > WIDEN_FROM_HEIGHT);

        let (ov, pool, others, h) = widen_network(v2, &["egot1me", "egot1tc5p", "egot1tzz8", "egot1a8x4"], 1);
        let base = skip_committee(&ov, h, 1);
        for attempt in WIDEN_FROM_ATTEMPT..WIDEN_FROM_ATTEMPT + WIDEN_V2_ANCHORED_ATTEMPTS {
            let mut c = skip_committee(&ov, h, attempt);
            c.sort();
            let mut p = pool.clone();
            p.sort();
            assert_eq!(c, p, "a pool of four redraws itself without an outside seat");
        }
        assert_eq!(base.len(), 4);
        let able: BTreeSet<String> = ["egot1me".to_string(), "egot1tc5p".to_string(), others[0].clone()].into_iter().collect();
        let mut finished_at = None;
        for attempt in 1..WIDEN_FROM_ATTEMPT + WIDEN_V2_ANCHORED_ATTEMPTS + 200 {
            let c = skip_committee(&ov, h, attempt);
            let answering = c.iter().filter(|a| able.contains(*a)).count();
            if answering >= crate::chain_db::quorum_of(c.len()) {
                finished_at = Some(attempt);
                break;
            }
            assert!(answering >= crate::chain_db::skip_threshold_of(c.len()), "attempt {attempt} can be passed on: {c:?}");
        }
        let at = finished_at.expect("the three that answer make the block");
        assert!(at < WIDEN_FROM_ATTEMPT + WIDEN_V2_ANCHORED_ATTEMPTS + 60, "fresh committees start after eight anchored attempts (finished at {at})");
    }

    #[test]
    fn a_short_epoch_with_too_few_ready_keeps_the_nodes_ready_one_epoch_before() {
        let mut ov = Ov::memory();
        let e0 = epoch_of(SHORT_EPOCH_FROM_HEIGHT);
        let names = |r: std::ops::Range<usize>| -> Vec<String> { r.map(|i| format!("egot1carry{i}")).collect() };
        let seat = |ov: &mut Ov, e: u64, members: &[String], ready: &[usize]| {
            ov.put(rota_key(e), serde_json::to_vec(&Rota { seed: "s".into(), members: members.to_vec() }).unwrap());
            let mut bits = Vec::new();
            for i in ready {
                set_bit(&mut bits, *i);
            }
            ov.put(tm_ready_key(e), bits);
        };
        seat(&mut ov, e0, &names(0..5), &[0, 1]);
        seat(&mut ov, e0 + 1, &names(0..5), &[0, 1, 2, 3]);
        seat(&mut ov, e0 + 2, &names(0..6), &[5]);
        seat(&mut ov, e0 + 3, &names(0..6), &[1, 2, 5]);
        ov.commit_memory();
        assert_eq!(tm_ready_members(&ov, epoch_start(e0)).len(), 2, "the first short epoch keeps the old rule");
        assert_eq!(tm_ready_members(&ov, epoch_start(e0 + 1)), names(0..4));
        let carried = tm_ready_members(&ov, epoch_start(e0 + 2));
        assert_eq!(carried, vec!["egot1carry5", "egot1carry0", "egot1carry1", "egot1carry2", "egot1carry3"]);
        assert!(tendermint_active(&ov, epoch_start(e0 + 2)), "one thin epoch does not drop back to the old engine");
        assert_eq!(tm_ready_members(&ov, epoch_start(e0 + 3)), vec!["egot1carry1", "egot1carry2", "egot1carry5"], "with three ready, only they are drawn");
    }

    #[test]
    fn from_the_carry_rule_thin_epochs_reach_back_until_three_have_been_ready() {
        let mut ov = Ov::memory();
        let e = epoch_of(TM_CARRY_FROM_HEIGHT);
        let names: Vec<String> = (0..5).map(|i| format!("egot1thin{i}")).collect();
        let seat = |ov: &mut Ov, e: u64, ready: &[usize]| {
            ov.put(rota_key(e), serde_json::to_vec(&Rota { seed: "s".into(), members: names.clone() }).unwrap());
            let mut bits = Vec::new();
            for i in ready {
                set_bit(&mut bits, *i);
            }
            ov.put(tm_ready_key(e), bits);
        };
        seat(&mut ov, e, &[0, 1]);
        seat(&mut ov, e - 1, &[0, 1]);
        seat(&mut ov, e - 2, &[]);
        seat(&mut ov, e - 3, &[0, 2, 3]);
        seat(&mut ov, e - 4, &[4]);
        ov.commit_memory();
        let h = epoch_start(e).max(TM_CARRY_FROM_HEIGHT);
        assert_eq!(tm_ready_members(&ov, h), vec!["egot1thin0", "egot1thin1", "egot1thin2", "egot1thin3"], "it stops at the first epoch that makes three");
        assert!(tendermint_active(&ov, h), "two thin epochs in a row no longer drop back to the old engine");
        assert_eq!(tm_ready_members(&ov, TM_CARRY_FROM_HEIGHT - 1).len(), 2, "before the rule only one epoch back counts");

        let mut empty = Ov::memory();
        empty.put(rota_key(e), serde_json::to_vec(&Rota { seed: "s".into(), members: names.clone() }).unwrap());
        empty.commit_memory();
        assert!(tm_ready_members(&empty, h).is_empty(), "nothing ready anywhere stays nothing");
    }

    #[test]
    fn the_split_pays_each_half_by_its_own_weights_and_leaves_nothing_idle() {
        assert_eq!(split_pay(1000, 10, 40, 0, 2000), 125, "a node without storage shares the uptime half");
        assert_eq!(split_pay(1000, 10, 40, 500, 2000), 250, "a storage node earns from both halves");
        assert_eq!(split_pay(1000, 10, 40, 0, 0), 250, "with no storage anywhere the whole budget goes by uptime");
        assert_eq!(split_pay(1000, 0, 0, 500, 2000), 250, "with no uptime weight anywhere the whole budget goes by storage");
        assert_eq!(split_pay(1000, 0, 0, 0, 0), 0);
    }

    #[test]
    fn the_daily_pool_is_split_between_uptime_and_storage_from_the_activation() {
        let (mut ov, addrs) = network(4);
        let t0 = 1_900_000_000i64;
        for a in &addrs[2..] {
            let mut rec = load_rec(&ov, a).unwrap();
            rec.storage_bytes = 100 * GB;
            rec.storage_until = t0 + 400 * 86_400;
            save_rec(&mut ov, a, &rec);
        }
        ov.commit_memory();
        let all: Vec<u64> = (0..4).collect();
        let step = CHECKIN_INTERVAL_SECS;
        let budget = |ts: i64| node_reward_per_day_at(ts) as u128 * CHECKIN_INTERVAL_SECS as u128 / 86_400;
        let pay_of = |paid: &[(String, u64)], a: &str| paid.iter().find(|(x, _)| x == a).map(|(_, p)| *p as u128).unwrap_or(0);
        run(&mut ov, SPLIT_FROM_HEIGHT - 2 * EPOCH, t0, &all);
        let before = run(&mut ov, SPLIT_FROM_HEIGHT - EPOCH, t0 + step, &all);
        let b0 = budget(t0 + step);
        assert!(pay_of(&before, &addrs[0]) * 50 < b0, "before the split a node without storage gets under 2%: {} of {b0}", pay_of(&before, &addrs[0]));
        run(&mut ov, SPLIT_FROM_HEIGHT, t0 + 2 * step, &all);
        let after = run(&mut ov, SPLIT_FROM_HEIGHT + EPOCH, t0 + 3 * step, &all);
        let b = budget(t0 + 3 * step);
        for a in &addrs[..2] {
            let p = pay_of(&after, a);
            assert!(p + 8 >= b / 8 && p <= b / 8 + 8, "a node without storage gets an eighth: {p} vs {}", b / 8);
        }
        for a in &addrs[2..] {
            let p = pay_of(&after, a);
            assert!(p + 8 >= b * 3 / 8 && p <= b * 3 / 8 + 8, "a storage node gets three eighths: {p} vs {}", b * 3 / 8);
        }
        let total: u128 = after.iter().map(|(_, p)| *p as u128).sum();
        assert!(total <= b && total + 16 >= b, "the whole budget is paid out: {total} vs {b}");
    }

    #[test]
    fn readiness_is_signed_for_the_rules_the_node_runs() {
        assert_eq!(ready_message(READY_V2_EPOCH - 1, "s"), b"ego/ready/v1:327:s".to_vec());
        assert_eq!(ready_message(READY_V2_EPOCH, "s"), b"ego/ready/v2:328:s".to_vec());
        assert_eq!(ready_version(READY_V2_EPOCH - 1), 1);
        assert_eq!(ready_version(READY_V2_EPOCH), 2);
        let v329 = ready_version(READY_V3_EPOCH);
        assert!(v329 >= 4, "every rule change before epoch 329 raises the version: {v329}");
        assert_eq!(ready_message(READY_V3_EPOCH, "s"), format!("ego/ready/v{v329}:329:s").into_bytes());
        let after_split = epoch_of(SPLIT_FROM_HEIGHT) + 1;
        assert!(ready_version(after_split) > ready_version(epoch_of(SPLIT_FROM_HEIGHT.saturating_sub(EPOCH))), "the pool split raises the version for the epoch after it");
        let sk3 = crate::bls_agg::derive_bls_key(&[8u8; 32]);
        for v in 1..v329 {
            let sig = crate::bls_agg::sign_shared(&sk3, format!("ego/ready/v{v}:329:s").as_bytes());
            assert!(!crate::bls_agg::verify_shared(&sig, &crate::bls_agg::bls_pubkey(&sk3), &ready_message(READY_V3_EPOCH, "s")), "a node without every rule change is not drawn from epoch 329");
        }
        let sk = crate::bls_agg::derive_bls_key(&[9u8; 32]);
        let pk = crate::bls_agg::bls_pubkey(&sk);
        let old = crate::bls_agg::sign_shared(&sk, b"ego/ready/v1:328:s");
        assert!(!crate::bls_agg::verify_shared(&old, &pk, &ready_message(READY_V2_EPOCH, "s")), "a node still on the old rules is not counted ready");
    }

    #[test]
    #[ignore]
    fn cost_per_block_at_scale() {
        let n = 100_000usize;
        let t = std::time::Instant::now();
        let (mut ov, _) = network(n);
        eprintln!("setup {n} nodes: {:?}", t.elapsed());
        let t0 = 1_900_000_000i64;
        for k in 0..MIN_STREAK as u64 {
            for chunk in (0..n as u64).collect::<Vec<_>>().chunks(MAX_CHECKINS_PER_BLOCK) {
                run(&mut ov, CHECKIN_FROM_HEIGHT + k * EPOCH, t0 + k as i64 * CHECKIN_INTERVAL_SECS, chunk);
            }
        }
        let ids: Vec<u64> = (0..MAX_CHECKINS_PER_BLOCK as u64).collect();
        let h = CHECKIN_FROM_HEIGHT + MIN_STREAK as u64 * EPOCH;
        let t = std::time::Instant::now();
        run(&mut ov, h, t0 + MIN_STREAK as i64 * CHECKIN_INTERVAL_SECS, &ids);
        eprintln!("one block with {} check-ins: {:?}", ids.len(), t.elapsed());
        let period = period_of(h + EPOCH);
        let t = std::time::Instant::now();
        let rota = draw_rota(&ov, period, 900, "seed");
        eprintln!("rota of {} from {} nodes: {:?}", rota.len(), eligible_count(&ov, period), t.elapsed());
    }

    #[test]
    fn weight_needs_a_proven_key_a_streak_and_a_recent_checkin() {
        let mut rec = NodeRec { idx: 0, pop_key: "ab".into(), streak: MIN_STREAK, last_checkin: 1_000, ..NodeRec::default() };
        assert_eq!(weight_of(&rec, 1_000, true, 0), MIN_STREAK as u64);
        assert_eq!(weight_of(&rec, 1_000, false, 0), 0);
        assert_eq!(weight_of(&rec, 1_000 + STREAK_GAP_SECS + 1, true, 0), 0);
        rec.streak = 500;
        rec.storage_bytes = 3 * GB;
        rec.storage_until = 2_000;
        rec.coverage = 50;
        rec.coverage_at = 1_000;
        assert_eq!(weight_of(&rec, 1_500, true, 0), UPTIME_CAP + 30 + COVERAGE_CAP_WITNESSES * 2);
        assert_eq!(weight_of(&rec, 2_001, true, 0), UPTIME_CAP + COVERAGE_CAP_WITNESSES * 2);
        rec.pop_key.clear();
        assert_eq!(weight_of(&rec, 1_500, true, 0), 0);
    }
}
