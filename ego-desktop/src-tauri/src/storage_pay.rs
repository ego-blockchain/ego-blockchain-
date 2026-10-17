use crate::chain_db::{read_u64_le, u64_le};
use crate::drs::Ov;
use crate::ledger::LedgerTx;
use serde::{Deserialize, Serialize};

pub const HOSTS_PER_FILE: usize = 3;
pub const PAY_CAP_SECS: i64 = 7 * 86_400;
pub const FRESH_SECS: i64 = 3 * 86_400;
pub const SHARE_PERCENT: u128 = 80;
pub const MAX_PLAN_SPANS: usize = 24;
pub const MAX_EXPIRIES_PER_BLOCK: usize = 20_000;

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct PlanSpan {
    pub start: i64,
    pub expires: i64,
    pub bytes: u64,
    pub price_micro: u64,
    pub period: i64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct HostFile {
    last_paid: i64,
    last_proof: i64,
    counted_bytes: u64,
}

impl HostFile {
    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(24);
        v.extend_from_slice(&self.last_paid.to_le_bytes());
        v.extend_from_slice(&self.last_proof.to_le_bytes());
        v.extend_from_slice(&self.counted_bytes.to_le_bytes());
        v
    }

    fn decode(b: &[u8]) -> Self {
        if b.len() < 24 {
            return Self::default();
        }
        Self {
            last_paid: read_u64_le(&b[..8]) as i64,
            last_proof: read_u64_le(&b[8..16]) as i64,
            counted_bytes: read_u64_le(&b[16..24]),
        }
    }
}

fn plan_key(owner: &str) -> Vec<u8> {
    format!("s2plan:{owner}").into_bytes()
}

fn owned_key(owner: &str) -> Vec<u8> {
    format!("s2own:{owner}").into_bytes()
}

fn hosts_key(cid: &str) -> Vec<u8> {
    format!("s2fh:{cid}").into_bytes()
}

fn host_file_key(cid: &str, host: &str) -> Vec<u8> {
    format!("s2fp:{cid}:{host}").into_bytes()
}

fn host_bytes_key(host: &str) -> Vec<u8> {
    format!("s2hb:{host}").into_bytes()
}

fn expiry_key(ts: i64, cid: &str, host: &str) -> Vec<u8> {
    format!("s2x:{:016x}:{cid}|{host}", ts.max(0) as u64).into_bytes()
}

fn spans(ov: &Ov, owner: &str) -> Vec<PlanSpan> {
    ov.get(&plan_key(owner)).and_then(|v| serde_json::from_slice(&v).ok()).unwrap_or_default()
}

pub fn active_plan(ov: &Ov, owner: &str, at: i64) -> Option<PlanSpan> {
    spans(ov, owner).into_iter().find(|s| s.start <= at && at < s.expires)
}

pub fn owned_bytes(ov: &Ov, owner: &str) -> u64 {
    ov.get(&owned_key(owner)).map(|v| read_u64_le(&v)).unwrap_or(0)
}

pub fn host_bytes(ov: &Ov, host: &str) -> u64 {
    ov.get(&host_bytes_key(host)).map(|v| read_u64_le(&v)).unwrap_or(0)
}

fn hosts(ov: &Ov, cid: &str) -> Vec<String> {
    ov.get(&hosts_key(cid)).and_then(|v| serde_json::from_slice(&v).ok()).unwrap_or_default()
}

fn set_host_bytes(ov: &mut Ov, host: &str, bytes: u64, at: i64, height: u64) {
    ov.put(host_bytes_key(host), u64_le(bytes).to_vec());
    crate::drs::record_storage(ov, host, bytes, i64::MAX, at, height);
}

pub fn add_plan(ov: &mut Ov, owner: &str, at: i64, bytes: u64, price_micro: u64, period: i64) {
    if period <= 0 {
        return;
    }
    let mut list: Vec<PlanSpan> = spans(ov, owner).into_iter().filter(|s| s.expires > at).collect();
    let start = list.iter().map(|s| s.expires).max().unwrap_or(at).max(at);
    list.push(PlanSpan { start, expires: start.saturating_add(period), bytes, price_micro, period });
    if list.len() > MAX_PLAN_SPANS {
        let excess = list.len() - MAX_PLAN_SPANS;
        list.drain(..excess);
    }
    if let Ok(v) = serde_json::to_vec(&list) {
        ov.put(plan_key(owner), v);
    }
}

pub fn adjust_owned(ov: &mut Ov, owner: &str, delta: i128) {
    let cur = owned_bytes(ov, owner) as i128;
    ov.put(owned_key(owner), u64_le((cur + delta).clamp(0, u64::MAX as i128) as u64).to_vec());
}

fn expiry_parts(key: &[u8]) -> Option<(i64, String, String)> {
    let s = std::str::from_utf8(key.strip_prefix(b"s2x:".as_slice())?).ok()?;
    let (ts_hex, rest) = s.split_once(':')?;
    let (cid, host) = rest.rsplit_once('|')?;
    Some((u64::from_str_radix(ts_hex, 16).ok()? as i64, cid.to_string(), host.to_string()))
}

pub fn process_expiries(ov: &mut Ov, at: i64, height: u64) {
    let due = ov.committed_keys(b"s2x:", MAX_EXPIRIES_PER_BLOCK, |k| expiry_parts(k).map_or(false, |(ts, _, _)| ts > at));
    for key in due {
        ov.del(key.clone());
        let Some((_, cid, host)) = expiry_parts(&key) else { continue };
        let fkey = host_file_key(&cid, &host);
        let mut hf = ov.get(&fkey).map(|v| HostFile::decode(&v)).unwrap_or_default();
        if hf.counted_bytes == 0 || at.saturating_sub(hf.last_proof) <= FRESH_SECS {
            continue;
        }
        let left = host_bytes(ov, &host).saturating_sub(hf.counted_bytes);
        hf.counted_bytes = 0;
        ov.put(fkey, hf.encode());
        set_host_bytes(ov, &host, left, at, height);
        let mut list = hosts(ov, &cid);
        list.retain(|h| h != &host);
        if let Ok(v) = serde_json::to_vec(&list) {
            ov.put(hosts_key(&cid), v);
        }
    }
}

pub struct ProvenFile {
    pub cid: String,
    pub owner: String,
    pub bytes: u64,
}

pub fn apply_proof(
    ov: &mut Ov,
    host: &str,
    file: &ProvenFile,
    at: i64,
    height: u64,
    price_micro_per_egoc: Option<u64>,
) -> u64 {
    if host == file.owner || file.bytes == 0 {
        return 0;
    }
    let mut list = hosts(ov, &file.cid);
    if !list.iter().any(|h| h == host) {
        if list.len() >= HOSTS_PER_FILE {
            return 0;
        }
        list.push(host.to_string());
        if let Ok(v) = serde_json::to_vec(&list) {
            ov.put(hosts_key(&file.cid), v);
        }
    }
    let fkey = host_file_key(&file.cid, host);
    let mut hf = ov.get(&fkey).map(|v| HostFile::decode(&v)).unwrap_or_default();
    let plan = active_plan(ov, &file.owner, at);
    let denom = owned_bytes(ov, &file.owner).max(plan.map_or(0, |p| p.bytes)).max(1) as u128;
    let mut pay = 0u128;
    if let (Some(plan), Some(price), true) = (plan, price_micro_per_egoc, hf.last_paid > 0) {
        let elapsed = at.saturating_sub(hf.last_paid).clamp(0, PAY_CAP_SECS) as u128;
        let numerator = plan.price_micro as u128 * elapsed * file.bytes as u128 * SHARE_PERCENT * 1_000_000u128;
        let denominator = plan.period.max(1) as u128 * denom * 100 * HOSTS_PER_FILE as u128 * price.max(1) as u128;
        pay = numerator / denominator;
    }
    hf.last_paid = at;
    let counted = match plan {
        Some(p) => ((file.bytes as u128 * p.bytes as u128) / denom).min(file.bytes as u128) as u64,
        None => 0,
    };
    let before = hf.counted_bytes;
    hf.counted_bytes = counted;
    hf.last_proof = at;
    ov.put(fkey, hf.encode());
    if before != counted {
        let total = (host_bytes(ov, host) as i128 - before as i128 + counted as i128).max(0) as u64;
        set_host_bytes(ov, host, total, at, height);
    }
    if counted > 0 {
        ov.put(expiry_key(at.saturating_add(FRESH_SECS) + 1, &file.cid, host), Vec::new());
    }
    pay.min(u64::MAX as u128) as u64
}

pub fn last_proof(ov: &Ov, cid: &str, host: &str) -> i64 {
    ov.get(&host_file_key(cid, host)).map(|v| HostFile::decode(&v).last_proof).unwrap_or(0)
}

pub fn plan_payment(tx: &LedgerTx) -> Option<(u64, u64, i64)> {
    if tx.tx_type != "credits_pay" || tx.to != crate::commands::storage::STORAGE_FEE_SINK {
        return None;
    }
    let (gb, price_micro, period) = crate::commands::storage::egusd_plan_terms(tx.memo.as_deref().unwrap_or(""))?;
    Some((gb.saturating_mul(1_000_000_000), price_micro, period))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(bytes: u64) -> ProvenFile {
        ProvenFile { cid: "egomfd1paidfile".into(), owner: "egot1owner".into(), bytes }
    }

    #[test]
    fn a_host_is_paid_for_the_time_since_its_last_proof_and_only_three_hosts_count() {
        let mut ov = Ov::memory();
        let gb = 1_000_000_000u64;
        add_plan(&mut ov, "egot1owner", 1_000, 100 * gb, 10_000_000, 30 * 86_400);
        adjust_owned(&mut ov, "egot1owner", (50 * gb) as i128);
        ov.commit_memory();
        let f = file(50 * gb);
        let price = Some(10_000u64);
        assert_eq!(apply_proof(&mut ov, "egot1hosta", &f, 2_000, 35_000, price), 0);
        let day = apply_proof(&mut ov, "egot1hosta", &f, 2_000 + 86_400, 35_001, price);
        let expected = 10_000_000u128 * 86_400 * (50 * gb) as u128 * 80 * 1_000_000
            / (30 * 86_400u128 * (100 * gb) as u128 * 100 * 3 * 10_000);
        assert_eq!(day as u128, expected);
        let week = apply_proof(&mut ov, "egot1hosta", &f, 2_000 + 86_400 + 30 * 86_400, 35_002, price);
        assert_eq!(week, 0, "no plan is active a month later");
        for h in ["egot1hostb", "egot1hostc"] {
            apply_proof(&mut ov, h, &f, 3_000, 35_003, price);
        }
        assert_eq!(apply_proof(&mut ov, "egot1hostd", &f, 3_000, 35_003, price), 0);
        assert_eq!(hosts(&ov, &f.cid).len(), 3);
        assert_eq!(apply_proof(&mut ov, "egot1owner", &f, 3_000, 35_003, price), 0);
    }

    #[test]
    fn a_renewal_queues_after_the_current_plan_and_stale_hosts_free_their_slot() {
        let mut ov = Ov::memory();
        add_plan(&mut ov, "egot1owner", 0, 10, 100, 1_000);
        add_plan(&mut ov, "egot1owner", 500, 10, 200, 1_000);
        assert_eq!(active_plan(&ov, "egot1owner", 900).unwrap().price_micro, 100);
        assert_eq!(active_plan(&ov, "egot1owner", 1_500).unwrap().price_micro, 200);
        assert!(active_plan(&ov, "egot1owner", 2_001).is_none());

        let mut ov = Ov::memory();
        add_plan(&mut ov, "egot1owner", 0, 1_000, 100, 100 * 86_400);
        adjust_owned(&mut ov, "egot1owner", 1_000);
        let f = file(1_000);
        for h in ["egot1h1", "egot1h2", "egot1h3"] {
            apply_proof(&mut ov, h, &f, 10, 35_000, Some(1));
        }
        ov.commit_memory();
        assert_eq!(host_bytes(&ov, "egot1h1"), 1_000);
        process_expiries(&mut ov, 10 + FRESH_SECS + 1, 35_100);
        ov.commit_memory();
        assert_eq!(host_bytes(&ov, "egot1h1"), 0);
        assert!(hosts(&ov, &f.cid).is_empty());
        apply_proof(&mut ov, "egot1h4", &f, FRESH_SECS + 100, 35_101, Some(1));
        assert_eq!(hosts(&ov, &f.cid), vec!["egot1h4".to_string()]);
    }
}
