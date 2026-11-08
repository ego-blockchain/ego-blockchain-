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

pub fn process_expiries(ov: &mut Ov, at: i64, height: u64) -> Vec<(String, String)> {
    let mut stale = Vec::new();
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
        stale.push((cid, host));
    }
    stale
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
    ov.del(stale_key(&file.owner, host));
    if let (Some(plan), Some(price), true, false) = (plan, price_micro_per_egoc, hf.last_paid > 0, plan_mode(ov, height)) {
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

pub const PLAN_PAY_FROM_HEIGHT: u64 = 92_500;
pub const PLAN_HOSTS: usize = 3;
pub const TX_STORAGE_CLAIM: &str = "storage_claim";
pub const CLAIM_EVERY_SECS: i64 = 6 * 3600;
pub const CLAIM_PAY_CAP_SECS: i64 = 24 * 3600;
pub const HOST_DROP_SECS: i64 = 3 * 86_400;
pub const MAX_HOST_PLANS: usize = 512;
pub const MAX_OFFER_BYTES: u64 = 1_000_000_000_000_000;
const WAIT_SCAN: usize = 16;
const MIGRATE_MAX_OWNERS: usize = 100_000;
const PLAN_MODE_KEY: &[u8] = b"s3on";

pub fn plan_mode(ov: &Ov, height: u64) -> bool {
    height >= PLAN_PAY_FROM_HEIGHT && ov.get(PLAN_MODE_KEY).is_some()
}

pub fn start_plan_mode(ov: &mut Ov, at: i64) {
    if ov.get(PLAN_MODE_KEY).is_some() {
        return;
    }
    ov.put(PLAN_MODE_KEY.to_vec(), u64_le(at as u64).to_vec());
    migrate_plans(ov, at);
}

pub fn is_storage_claim(tx: &LedgerTx) -> bool {
    tx.tx_type == TX_STORAGE_CLAIM && !tx.from.is_empty() && tx.to == tx.from && tx.amount == 0
}

pub fn claim_memo(offer_bytes: u64) -> String {
    format!("{TX_STORAGE_CLAIM}:{offer_bytes}")
}

pub fn claim_offer(tx: &LedgerTx) -> Option<u64> {
    let v: u64 = tx.memo.as_deref()?.strip_prefix("storage_claim:")?.parse().ok()?;
    (v <= MAX_OFFER_BYTES).then_some(v)
}

fn offer_key(host: &str) -> Vec<u8> {
    format!("s3off:{host}").into_bytes()
}

fn reserved_key(host: &str) -> Vec<u8> {
    format!("s3res:{host}").into_bytes()
}

fn last_claim_key(host: &str) -> Vec<u8> {
    format!("s3lc:{host}").into_bytes()
}

fn plan_hosts_key(owner: &str) -> Vec<u8> {
    format!("s3ph:{owner}").into_bytes()
}

fn plan_size_key(owner: &str) -> Vec<u8> {
    format!("s3ps:{owner}").into_bytes()
}

fn host_plans_key(host: &str) -> Vec<u8> {
    format!("s3hp:{host}").into_bytes()
}

fn paid_key(owner: &str, host: &str) -> Vec<u8> {
    format!("s3pd:{owner}:{host}").into_bytes()
}

fn stale_key(owner: &str, host: &str) -> Vec<u8> {
    format!("s3st:{owner}:{host}").into_bytes()
}

fn queued_key(owner: &str) -> Vec<u8> {
    format!("s3wq:{owner}").into_bytes()
}

fn wait_key(at: i64, owner: &str, slot: u64) -> Vec<u8> {
    format!("s3w:{:016x}:{owner}:{slot}", at.max(0) as u64).into_bytes()
}

fn drop_key(ts: i64, owner: &str, host: &str) -> Vec<u8> {
    format!("s3x:{:016x}:{owner}|{host}", ts.max(0) as u64).into_bytes()
}

fn wait_owner(key: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(key.strip_prefix(b"s3w:".as_slice())?).ok()?;
    let mut parts = s.split(':');
    parts.next()?;
    let owner = parts.next()?;
    parts.next()?;
    (!owner.is_empty()).then(|| owner.to_string())
}

fn drop_parts(key: &[u8]) -> Option<(i64, String, String)> {
    let s = std::str::from_utf8(key.strip_prefix(b"s3x:".as_slice())?).ok()?;
    let (ts_hex, rest) = s.split_once(':')?;
    let (owner, host) = rest.rsplit_once('|')?;
    Some((u64::from_str_radix(ts_hex, 16).ok()? as i64, owner.to_string(), host.to_string()))
}

fn get_u64(ov: &Ov, key: &[u8]) -> u64 {
    ov.get(key).map(|v| read_u64_le(&v)).unwrap_or(0)
}

fn get_list(ov: &Ov, key: &[u8]) -> Vec<String> {
    ov.get(key).and_then(|v| serde_json::from_slice(&v).ok()).unwrap_or_default()
}

fn put_list(ov: &mut Ov, key: Vec<u8>, list: &[String]) {
    if list.is_empty() {
        ov.del(key);
    } else if let Ok(v) = serde_json::to_vec(list) {
        ov.put(key, v);
    }
}

pub fn plan_hosts(ov: &Ov, owner: &str) -> Vec<String> {
    get_list(ov, &plan_hosts_key(owner))
}

pub fn host_plans(ov: &Ov, host: &str) -> Vec<String> {
    get_list(ov, &host_plans_key(host))
}

pub fn offered(ov: &Ov, host: &str) -> u64 {
    get_u64(ov, &offer_key(host))
}

pub fn reserved(ov: &Ov, host: &str) -> u64 {
    get_u64(ov, &reserved_key(host))
}

pub fn last_claim(ov: &Ov, host: &str) -> i64 {
    get_u64(ov, &last_claim_key(host)) as i64
}

pub fn plan_size(ov: &Ov, owner: &str) -> u64 {
    get_u64(ov, &plan_size_key(owner))
}

fn add_reserved(ov: &mut Ov, host: &str, delta: i128) {
    let next = (reserved(ov, host) as i128 + delta).clamp(0, u64::MAX as i128) as u64;
    ov.put(reserved_key(host), u64_le(next).to_vec());
}

fn plan_bytes_now(ov: &Ov, owner: &str, at: i64) -> Option<u64> {
    spans(ov, owner).into_iter().filter(|s| s.expires > at).map(|s| s.bytes).max()
}

pub fn want_hosts(ov: &mut Ov, owner: &str, at: i64) {
    let Some(bytes) = plan_bytes_now(ov, owner, at) else { return };
    let hosts = plan_hosts(ov, owner);
    let old = plan_size(ov, owner);
    if bytes != old {
        for h in &hosts {
            add_reserved(ov, h, bytes as i128 - old as i128);
        }
        ov.put(plan_size_key(owner), u64_le(bytes).to_vec());
    }
    let queued = get_u64(ov, &queued_key(owner));
    let missing = PLAN_HOSTS.saturating_sub(hosts.len() + queued as usize) as u64;
    for slot in queued..queued + missing {
        ov.put(wait_key(at, owner, slot), Vec::new());
    }
    if missing > 0 {
        ov.put(queued_key(owner), u64_le(queued + missing).to_vec());
    }
}

fn unqueue(ov: &mut Ov, owner: &str) {
    let q = get_u64(ov, &queued_key(owner)).saturating_sub(1);
    if q == 0 {
        ov.del(queued_key(owner));
    } else {
        ov.put(queued_key(owner), u64_le(q).to_vec());
    }
}

fn assign(ov: &mut Ov, owner: &str, host: &str, at: i64) {
    let mut hosts = plan_hosts(ov, owner);
    hosts.push(host.to_string());
    put_list(ov, plan_hosts_key(owner), &hosts);
    let mut plans = host_plans(ov, host);
    plans.push(owner.to_string());
    put_list(ov, host_plans_key(host), &plans);
    add_reserved(ov, host, plan_size(ov, owner) as i128);
    ov.put(paid_key(owner, host), u64_le(at as u64).to_vec());
    ov.put(drop_key(at.saturating_add(HOST_DROP_SECS), owner, host), Vec::new());
}

fn release(ov: &mut Ov, owner: &str, host: &str) {
    let mut hosts = plan_hosts(ov, owner);
    hosts.retain(|h| h != host);
    put_list(ov, plan_hosts_key(owner), &hosts);
    let mut plans = host_plans(ov, host);
    plans.retain(|o| o != owner);
    put_list(ov, host_plans_key(host), &plans);
    add_reserved(ov, host, -(plan_size(ov, owner) as i128));
    let paid = get_u64(ov, &paid_key(owner, host)) as i64;
    if paid > 0 {
        ov.del(drop_key(paid.saturating_add(HOST_DROP_SECS), owner, host));
    }
    ov.del(paid_key(owner, host));
    ov.del(stale_key(owner, host));
    if hosts.is_empty() && get_u64(ov, &queued_key(owner)) == 0 {
        ov.del(plan_size_key(owner));
    }
}

pub fn mark_stale(ov: &mut Ov, owner: &str, host: &str, at: i64) {
    if plan_hosts(ov, owner).iter().any(|h| h == host) {
        ov.put(stale_key(owner, host), u64_le(at as u64).to_vec());
    }
}

pub fn is_stale(ov: &Ov, owner: &str, host: &str) -> bool {
    ov.get(&stale_key(owner, host)).is_some()
}

fn fill_waiting(ov: &mut Ov, host: &str, at: i64) {
    if host_plans(ov, host).len() >= MAX_HOST_PLANS {
        return;
    }
    let free = offered(ov, host).saturating_sub(reserved(ov, host));
    for key in ov.committed_keys(b"s3w:", WAIT_SCAN, |_| false) {
        if ov.get(&key).is_none() {
            continue;
        }
        let Some(owner) = wait_owner(&key) else {
            ov.del(key);
            continue;
        };
        let hosts = plan_hosts(ov, &owner);
        if active_plan(ov, &owner, at).is_none() || hosts.len() >= PLAN_HOSTS {
            ov.del(key);
            unqueue(ov, &owner);
            continue;
        }
        if owner == host || hosts.iter().any(|h| h == host) || plan_size(ov, &owner) > free {
            continue;
        }
        assign(ov, &owner, host, at);
        ov.del(key);
        unqueue(ov, &owner);
        return;
    }
}

pub fn apply_claim(ov: &mut Ov, host: &str, offer: u64, at: i64, price_micro_per_egoc: Option<u64>) -> u64 {
    let last = last_claim(ov, host);
    if last > 0 && at.saturating_sub(last) < CLAIM_EVERY_SECS {
        return 0;
    }
    ov.put(last_claim_key(host), u64_le(at as u64).to_vec());
    ov.put(offer_key(host), u64_le(offer.min(MAX_OFFER_BYTES)).to_vec());
    let mut pay = 0u128;
    for owner in host_plans(ov, host) {
        let Some(plan) = active_plan(ov, &owner, at) else {
            release(ov, &owner, host);
            continue;
        };
        let paid = get_u64(ov, &paid_key(&owner, host)) as i64;
        let since = if paid > 0 { paid } else { at };
        let elapsed = at.saturating_sub(since).clamp(0, CLAIM_PAY_CAP_SECS) as u128;
        if let (Some(price), false) = (price_micro_per_egoc, is_stale(ov, &owner, host)) {
            pay += plan.price_micro as u128 * elapsed * SHARE_PERCENT * 1_000_000u128
                / (plan.period.max(1) as u128 * 100 * PLAN_HOSTS as u128 * price.max(1) as u128);
        }
        if paid > 0 {
            ov.del(drop_key(paid.saturating_add(HOST_DROP_SECS), &owner, host));
        }
        ov.put(paid_key(&owner, host), u64_le(at as u64).to_vec());
        ov.put(drop_key(at.saturating_add(HOST_DROP_SECS), &owner, host), Vec::new());
    }
    fill_waiting(ov, host, at);
    pay.min(u64::MAX as u128) as u64
}

pub fn process_plan_drops(ov: &mut Ov, at: i64) {
    let due = ov.committed_keys(b"s3x:", MAX_EXPIRIES_PER_BLOCK, |k| drop_parts(k).map_or(false, |(ts, _, _)| ts > at));
    for key in due {
        if ov.get(&key).is_none() {
            continue;
        }
        ov.del(key.clone());
        let Some((_, owner, host)) = drop_parts(&key) else { continue };
        let paid = get_u64(ov, &paid_key(&owner, &host)) as i64;
        if paid == 0 || paid.saturating_add(HOST_DROP_SECS) > at {
            continue;
        }
        release(ov, &owner, &host);
        want_hosts(ov, &owner, at);
    }
}

pub fn migrate_plans(ov: &mut Ov, at: i64) {
    for key in ov.committed_keys(b"s2plan:", MIGRATE_MAX_OWNERS, |_| false) {
        let Some(owner) = std::str::from_utf8(&key[b"s2plan:".len()..]).ok().map(str::to_string) else { continue };
        want_hosts(ov, &owner, at);
    }
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

#[cfg(test)]
mod plan_pay_tests {
    use super::*;

    const GB: u64 = 1_000_000_000;
    const MONTH: i64 = 30 * 86_400;
    const PRICE: Option<u64> = Some(8_000);

    fn share(elapsed: i64) -> u64 {
        (790_000u128 * elapsed as u128 * 80 * 1_000_000 / (MONTH as u128 * 100 * 3 * 8_000)) as u64
    }

    fn bought(ov: &mut Ov) {
        add_plan(ov, "egot1owner", 0, 50 * GB, 790_000, MONTH);
        ov.commit_memory();
        start_plan_mode(ov, 0);
        ov.commit_memory();
    }

    #[test]
    fn a_bought_plan_is_paid_to_three_computers_whether_or_not_anything_is_stored() {
        let mut ov = Ov::memory();
        bought(&mut ov);
        assert!(plan_mode(&ov, PLAN_PAY_FROM_HEIGHT));
        assert!(!plan_mode(&ov, PLAN_PAY_FROM_HEIGHT - 1));

        assert_eq!(apply_claim(&mut ov, "egot1owner", 500 * GB, 100, PRICE), 0);
        assert_eq!(apply_claim(&mut ov, "egot1small", GB, 100, PRICE), 0);
        for h in ["egot1h1", "egot1h2", "egot1h3", "egot1h4"] {
            assert_eq!(apply_claim(&mut ov, h, 100 * GB, 100, PRICE), 0);
        }
        ov.commit_memory();
        assert_eq!(plan_hosts(&ov, "egot1owner"), vec!["egot1h1", "egot1h2", "egot1h3"], "the owner and a computer without room are passed over");
        assert!(host_plans(&ov, "egot1h4").is_empty());
        assert_eq!(reserved(&ov, "egot1h1"), 50 * GB);

        let t = 100 + CLAIM_EVERY_SECS;
        assert_eq!(apply_claim(&mut ov, "egot1h1", 100 * GB, t - 60, PRICE), 0, "too soon after the last claim");
        assert_eq!(apply_claim(&mut ov, "egot1h1", 100 * GB, t, PRICE), share(CLAIM_EVERY_SECS));
        assert_eq!(apply_claim(&mut ov, "egot1h4", 100 * GB, t, PRICE), 0, "a computer not keeping the plan earns nothing from it");
        let later = t + 5 * 86_400;
        assert_eq!(apply_claim(&mut ov, "egot1h1", 100 * GB, later, PRICE), share(CLAIM_PAY_CAP_SECS), "a long silence pays one day at most");
    }

    #[test]
    fn a_computer_silent_for_three_days_is_replaced() {
        let mut ov = Ov::memory();
        bought(&mut ov);
        for h in ["egot1h1", "egot1h2", "egot1h3"] {
            apply_claim(&mut ov, h, 100 * GB, 100, PRICE);
        }
        ov.commit_memory();
        let t = 100 + 2 * 86_400;
        apply_claim(&mut ov, "egot1h1", 100 * GB, t, PRICE);
        apply_claim(&mut ov, "egot1h2", 100 * GB, t, PRICE);
        ov.commit_memory();
        process_plan_drops(&mut ov, 100 + HOST_DROP_SECS + 1);
        ov.commit_memory();
        assert_eq!(plan_hosts(&ov, "egot1owner"), vec!["egot1h1", "egot1h2"]);
        assert_eq!(reserved(&ov, "egot1h3"), 0);
        apply_claim(&mut ov, "egot1h4", 100 * GB, 100 + HOST_DROP_SECS + 2, PRICE);
        ov.commit_memory();
        assert_eq!(plan_hosts(&ov, "egot1owner"), vec!["egot1h1", "egot1h2", "egot1h4"]);
    }

    #[test]
    fn a_keeper_that_stops_proving_the_owners_files_stops_being_paid_until_it_proves_again() {
        let mut ov = Ov::memory();
        bought(&mut ov);
        apply_claim(&mut ov, "egot1h1", 100 * GB, 100, PRICE);
        ov.commit_memory();
        mark_stale(&mut ov, "egot1owner", "egot1h1", 200);
        mark_stale(&mut ov, "egot1owner", "egot1stranger", 200);
        assert!(!is_stale(&ov, "egot1owner", "egot1stranger"));
        let t = 100 + CLAIM_EVERY_SECS;
        assert_eq!(apply_claim(&mut ov, "egot1h1", 100 * GB, t, PRICE), 0);
        let f = ProvenFile { cid: "egomfd1x".into(), owner: "egot1owner".into(), bytes: GB };
        apply_proof(&mut ov, "egot1h1", &f, t + 10, PLAN_PAY_FROM_HEIGHT, PRICE);
        assert_eq!(apply_claim(&mut ov, "egot1h1", 100 * GB, t + CLAIM_EVERY_SECS, PRICE), share(CLAIM_EVERY_SECS));
    }

    #[test]
    fn once_plan_pay_is_on_a_proof_pays_nothing_by_itself_and_an_ended_plan_frees_the_space() {
        let mut ov = Ov::memory();
        bought(&mut ov);
        adjust_owned(&mut ov, "egot1owner", GB as i128);
        let f = ProvenFile { cid: "egomfd1x".into(), owner: "egot1owner".into(), bytes: GB };
        apply_proof(&mut ov, "egot1h1", &f, 10, PLAN_PAY_FROM_HEIGHT, PRICE);
        assert_eq!(apply_proof(&mut ov, "egot1h1", &f, 10 + 86_400, PLAN_PAY_FROM_HEIGHT, PRICE), 0);

        apply_claim(&mut ov, "egot1h1", 100 * GB, 100, PRICE);
        ov.commit_memory();
        apply_claim(&mut ov, "egot1h1", 100 * GB, MONTH + 10, PRICE);
        ov.commit_memory();
        assert!(host_plans(&ov, "egot1h1").is_empty());
        assert!(plan_hosts(&ov, "egot1owner").is_empty());
        assert_eq!(reserved(&ov, "egot1h1"), 0);
    }

    #[test]
    fn claims_say_how_much_space_is_offered() {
        let tx = LedgerTx { from: "egot1h".into(), to: "egot1h".into(), tx_type: TX_STORAGE_CLAIM.into(), memo: Some(claim_memo(5 * GB)), ..Default::default() };
        assert!(is_storage_claim(&tx));
        assert_eq!(claim_offer(&tx), Some(5 * GB));
        let bad = LedgerTx { memo: Some("storage_claim:lots".into()), ..tx.clone() };
        assert_eq!(claim_offer(&bad), None);
        let to_other = LedgerTx { to: "egot1x".into(), ..tx };
        assert!(!is_storage_claim(&to_other));
    }
}
