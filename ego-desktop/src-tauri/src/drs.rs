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
pub const WEIGHT_LEAD: u64 = 50;
pub const COMMITTEE_SIZE: usize = 32;
pub const MIN_COMMITTEE: usize = 3;
pub const BLOCK_COMMITTEE: usize = 4;
pub const DRAW_V2_FROM_HEIGHT: u64 = 32_640;
pub const READY_V2_EPOCH: u64 = 328;
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
pub const MAX_CHECKINS_PER_BLOCK: usize = 2_048;
pub const MAX_EXPIRIES_PER_BLOCK: usize = 20_000;
pub const ANCHOR_MAX_AGE: u64 = 300;
pub const TREE_LEVELS: u32 = 8;
const TREE_FANOUT_BITS: u32 = 4;
const TREE_FANOUT: u64 = 1 << TREE_FANOUT_BITS;
pub const TX_CHECKIN_BATCH: &str = "checkin_batch";
pub const TX_READY_BATCH: &str = "ready_batch";
const GB: u64 = 1_000_000_000;
const KEY_COUNT: &[u8] = b"n2count";
const KEY_ELIGIBLE: &[u8] = b"n2elig";
const KEY_MIGRATED: &[u8] = b"n2migrated";

pub fn period_of(height: u64) -> u64 {
    (height + WEIGHT_LEAD) / EPOCH
}

pub fn epoch_of(height: u64) -> u64 {
    height.saturating_sub(1) / EPOCH
}

pub fn first_drs_epoch() -> u64 {
    epoch_of(DRS_FROM_HEIGHT)
}

fn rec_key(addr: &str) -> Vec<u8> {
    format!("n2rec:{addr}").into_bytes()
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
    let storage = if at <= rec.storage_until {
        (rec.storage_bytes / GB).saturating_mul(STORAGE_POINTS_PER_GB).min(STORAGE_CAP)
    } else {
        0
    };
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
    let version = if epoch >= READY_V2_EPOCH { 2 } else { 1 };
    format!("ego/ready/v{version}:{epoch}:{seed}").into_bytes()
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
    if checkins.len() > 1 || readies.len() > 1 || coverages.len() > 1 {
        return Err(format!("block {} carries more than one batch of a kind", block.height));
    }
    for tx in checkins.iter().chain(readies.iter()).chain(coverages.iter()) {
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
        let e = epoch_of(block.height);
        let offset = block.height - e * EPOCH;
        if batch.epoch != e + 1 || offset > READY_DEADLINE {
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
    if block.height == FAST_START_HEIGHT {
        recount_all(ov, at, period);
    }
    if block.height < CHECKIN_FROM_HEIGHT {
        return Applied { credits };
    }

    if let Some(tx) = txs.iter().find(|t| t.tx_type == TX_CHECKIN_BATCH) {
        if let Ok(batch) = serde_json::from_str::<CheckinBatch>(&tx.call_args) {
            let total_w = total_weight(ov, period) as u128;
            let per_checkin = NODE_REWARD_PER_DAY_UEGOC as u128 * CHECKIN_INTERVAL_SECS as u128 / 86_400;
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
                let pay = if total_w > 0 { (per_checkin * w / total_w).min(pool_left) } else { 0 };
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
    }

    if block.height % EPOCH == 0 {
        let next_epoch = block.height / EPOCH + 1;
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

pub fn committee(ov: &Ov, height: u64, attempt: i64) -> Vec<String> {
    let epoch = epoch_of(height);
    let rota = load_rota(ov, epoch).unwrap_or_default();
    let bits = ready_set(ov, epoch);
    let ready: Vec<String> = rota
        .members
        .iter()
        .enumerate()
        .filter(|(i, _)| bit(&bits, *i))
        .map(|(_, a)| a.clone())
        .collect();
    let pool = if ready.len() >= MIN_COMMITTEE { ready } else { rota.members };
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
        let per_checkin = (NODE_REWARD_PER_DAY_UEGOC as u128 * CHECKIN_INTERVAL_SECS as u128 / 86_400) as u64;
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
    fn readiness_is_signed_for_the_rules_the_node_runs() {
        assert_eq!(ready_message(READY_V2_EPOCH - 1, "s"), b"ego/ready/v1:327:s".to_vec());
        assert_eq!(ready_message(READY_V2_EPOCH, "s"), b"ego/ready/v2:328:s".to_vec());
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
