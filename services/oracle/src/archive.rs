use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

pub const BUCKET: u64 = 100;
pub const KEEP_RECENT: u64 = 200;
pub const WRITES_PER_PASS: usize = 10;
pub const USERS_MAX: usize = 5_000;
pub const WINDOW_KEEP: u64 = 6_000;

const HEAVY_BLOCK_FIELDS: [&str; 6] = ["commit_cert", "poc_ticket", "randao_reveal", "producer_sig", "agg_bls_sig", "bls_pubkeys"];

#[derive(Default)]
pub struct Archive {
    pub buckets: BTreeSet<u64>,
    pub users: Vec<Value>,
    pub incomplete: BTreeSet<u64>,
    pub hashes: Vec<(u64, u32)>,
    pub addrs: HashMap<String, BTreeSet<u32>>,
}

pub fn hash_prefix(hash: &str) -> Option<u64> {
    let h = hash.strip_prefix("0x").or_else(|| hash.strip_prefix("0X")).unwrap_or(hash);
    u64::from_str_radix(h.get(..16)?, 16).ok()
}

pub fn same_hash(a: &str, b: &str) -> bool {
    let strip = |s: &str| s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s).to_ascii_lowercase();
    !a.is_empty() && strip(a) == strip(b)
}

pub fn is_address(q: &str) -> bool {
    (q.starts_with("egot1") || q.starts_with("ego1")) && q.len() <= 90 && q.bytes().all(|c| c.is_ascii_alphanumeric())
}

impl Archive {
    pub fn index_bucket(&mut self, bucket: u64, v: &Value) {
        let b = bucket as u32;
        for blk in v["blocks"].as_array().into_iter().flatten() {
            if let Some(p) = blk["hash"].as_str().and_then(hash_prefix) {
                self.hashes.push((p, b << 1 | 1));
            }
        }
        for t in v["txs"].as_array().into_iter().flatten() {
            if let Some(p) = t["hash"].as_str().and_then(hash_prefix) {
                self.hashes.push((p, b << 1));
            }
            for k in ["from", "to"] {
                if let Some(a) = t[k].as_str().filter(|a| is_address(a)) {
                    self.addrs.entry(a.to_string()).or_default().insert(b);
                }
            }
        }
    }

    pub fn finish_index(&mut self) {
        self.hashes.sort_unstable();
        self.hashes.dedup();
    }

    pub fn absorb(&mut self, other: Archive) {
        self.buckets.extend(other.buckets.iter().copied());
        for b in &other.buckets {
            self.incomplete.remove(b);
        }
        let users = std::mem::take(&mut self.users);
        self.users = merge_users(&other.users, &users, usize::MAX);
        self.hashes.extend(other.hashes);
        self.finish_index();
        for (a, set) in other.addrs {
            self.addrs.entry(a).or_default().extend(set);
        }
    }

    pub fn find_hash(&self, q: &str) -> (Vec<u64>, Vec<u64>) {
        let Some(p) = hash_prefix(q) else { return (Vec::new(), Vec::new()) };
        let start = self.hashes.partition_point(|(x, _)| *x < p);
        let (mut txs, mut blocks) = (Vec::new(), Vec::new());
        for (_, v) in self.hashes[start..].iter().take_while(|(x, _)| *x == p) {
            let bucket = (*v >> 1) as u64;
            if *v & 1 == 1 { blocks.push(bucket) } else { txs.push(bucket) }
        }
        (txs, blocks)
    }

    pub fn address_buckets(&self, addr: &str) -> Vec<u64> {
        self.addrs.get(addr).map(|s| s.iter().rev().map(|b| *b as u64).collect()).unwrap_or_default()
    }
}

pub fn window_bucket(chain: &crate::ChainState, bucket: u64) -> Option<Value> {
    let range = bucket * BUCKET..(bucket + 1) * BUCKET;
    let blocks: Vec<&Value> = chain.blocks.iter().filter(|b| b["height"].as_u64().map_or(false, |h| range.contains(&h))).collect();
    if blocks.is_empty() {
        return None;
    }
    let txs: Vec<&Value> = chain.transactions.iter().filter(|t| t["block_height"].as_u64().map_or(false, |h| range.contains(&h))).collect();
    let mut v = bucket_json(bucket, &blocks, &txs);
    v["partial"] = json!(true);
    Some(v)
}

pub fn trim_window(chain: &mut crate::ChainState, archived: &BTreeSet<u64>, tip: u64) -> usize {
    let keep_from = tip.saturating_sub(WINDOW_KEEP);
    let gone = |h: u64| h > 0 && h < keep_from && archived.contains(&bucket_of(h));
    let before = chain.blocks.len() + chain.transactions.len();
    chain.blocks.retain(|b| !b["height"].as_u64().map_or(false, gone));
    chain.transactions.retain(|t| !t["block_height"].as_u64().map_or(false, gone));
    before - chain.blocks.len() - chain.transactions.len()
}

pub fn read_bucket(dir: &Path, bucket: u64) -> Option<Value> {
    let data = std::fs::read(dir.join(file_name(bucket))).ok()?;
    serde_json::from_slice::<Value>(&data).ok().filter(|v| v["bucket"].as_u64() == Some(bucket))
}

pub fn archived_from(dir: &Path, have: &BTreeSet<u64>, from: u64, below: u64, limit: usize, key: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for b in have.range(bucket_of(from)..).copied() {
        if b * BUCKET >= below || out.len() >= limit {
            break;
        }
        let Some(v) = read_bucket(dir, b) else { continue };
        let field = if key == "blocks" { "height" } else { "block_height" };
        for x in v[key].as_array().into_iter().flatten() {
            let h = x[field].as_u64().unwrap_or(0);
            if h >= from && h < below && out.len() < limit {
                out.push(x.clone());
            }
        }
    }
    out
}

pub fn window_address_buckets(chain: &crate::ChainState, addr: &str) -> BTreeSet<u64> {
    chain
        .transactions
        .iter()
        .filter(|t| t["from"].as_str() == Some(addr) || t["to"].as_str() == Some(addr))
        .filter_map(|t| t["block_height"].as_u64())
        .map(bucket_of)
        .collect()
}

pub fn dir() -> PathBuf {
    std::env::var("ORACLE_ARCHIVE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| crate::chain_data_path().with_file_name("archive"))
}

pub fn file_name(bucket: u64) -> String {
    format!("b{bucket:07}.json")
}

pub fn parse_name(name: &str) -> Option<u64> {
    let digits = name.strip_prefix('b')?.strip_suffix(".json")?;
    if digits.len() != 7 || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

pub fn bucket_of(height: u64) -> u64 {
    height / BUCKET
}

pub fn slim_block(block: &Value) -> Value {
    let mut b = block.clone();
    if let Some(o) = b.as_object_mut() {
        for k in HEAVY_BLOCK_FIELDS {
            o.remove(k);
        }
    }
    b
}

fn sort_users(users: &mut Vec<Value>) {
    users.sort_by_key(|t| std::cmp::Reverse((t["block_height"].as_u64().unwrap_or(0), t["timestamp"].as_i64().unwrap_or(0))));
    let mut seen = std::collections::HashSet::new();
    users.retain(|t| seen.insert(t["hash"].as_str().unwrap_or("").to_string()));
}

pub fn rescan_dir(archive: &mut Archive, dir: &Path) -> usize {
    let Ok(rd) = std::fs::read_dir(dir) else { return 0 };
    let mut fresh: Vec<u64> = rd
        .filter_map(|e| e.ok())
        .filter_map(|e| parse_name(&e.file_name().to_string_lossy()))
        .filter(|b| !archive.buckets.contains(b))
        .collect();
    fresh.sort_unstable();
    let mut added = 0;
    for b in fresh {
        let Ok(data) = std::fs::read(dir.join(file_name(b))) else { continue };
        let Ok(v) = serde_json::from_slice::<Value>(&data) else { continue };
        if v["bucket"].as_u64() != Some(b) {
            continue;
        }
        if let Some(txs) = v["txs"].as_array() {
            archive.users.extend(txs.iter().filter(|t| crate::is_user_tx(t)).cloned());
        }
        archive.index_bucket(b, &v);
        archive.buckets.insert(b);
        archive.incomplete.remove(&b);
        added += 1;
    }
    if added > 0 {
        sort_users(&mut archive.users);
        archive.finish_index();
    }
    added
}

pub fn bucket_json(bucket: u64, blocks: &[&Value], txs: &[&Value]) -> Value {
    let mut blocks: Vec<Value> = blocks.iter().map(|b| slim_block(b)).collect();
    blocks.sort_by_key(|b| b["height"].as_u64().unwrap_or(0));
    let mut txs: Vec<Value> = txs.iter().map(|t| (*t).clone()).collect();
    txs.sort_by_key(|t| (t["block_height"].as_u64().unwrap_or(0), t["timestamp"].as_i64().unwrap_or(0)));
    json!({
        "bucket": bucket,
        "from": bucket * BUCKET,
        "to": bucket * BUCKET + BUCKET - 1,
        "blocks": blocks,
        "txs": txs,
    })
}

pub fn ready_buckets(chain: &crate::ChainState, have: &BTreeSet<u64>, skip: &BTreeSet<u64>, tip: u64) -> (Vec<Value>, Vec<u64>) {
    let limit = tip.saturating_sub(KEEP_RECENT);
    let settled = tip.saturating_sub(WINDOW_KEEP);
    let mut by_bucket: HashMap<u64, Vec<&Value>> = HashMap::new();
    for b in &chain.blocks {
        let Some(h) = b["height"].as_u64() else { continue };
        let bucket = bucket_of(h);
        let old = (bucket + 1) * BUCKET <= settled;
        if (bucket + 1) * BUCKET > limit || have.contains(&bucket) || (skip.contains(&bucket) && !old) {
            continue;
        }
        by_bucket.entry(bucket).or_default().push(b);
    }
    let mut full: Vec<u64> = by_bucket
        .iter()
        .filter(|(bucket, blocks)| {
            let mut hs: Vec<u64> = blocks.iter().filter_map(|b| b["height"].as_u64()).collect();
            hs.sort_unstable();
            hs.dedup();
            (**bucket + 1) * BUCKET <= settled || (hs.len() as u64 == BUCKET && hs.first() == Some(&(**bucket * BUCKET)))
        })
        .map(|(b, _)| *b)
        .collect();
    full.sort_unstable();
    full.reverse();
    full.truncate(WRITES_PER_PASS);
    if full.is_empty() {
        return (Vec::new(), Vec::new());
    }
    let wanted: BTreeSet<u64> = full.iter().copied().collect();
    let mut txs_by: HashMap<u64, Vec<&Value>> = HashMap::new();
    for t in &chain.transactions {
        let Some(h) = t["block_height"].as_u64() else { continue };
        if wanted.contains(&bucket_of(h)) {
            txs_by.entry(bucket_of(h)).or_default().push(t);
        }
    }
    let mut out = Vec::new();
    let mut short = Vec::new();
    for bucket in full {
        let blocks = &by_bucket[&bucket];
        let txs = txs_by.remove(&bucket).unwrap_or_default();
        let mut per_height: HashMap<u64, u64> = HashMap::new();
        for t in &txs {
            *per_height.entry(t["block_height"].as_u64().unwrap_or(0)).or_insert(0) += 1;
        }
        let complete = blocks.len() as u64 == BUCKET
            && blocks.iter().all(|b| {
                let h = b["height"].as_u64().unwrap_or(0);
                per_height.get(&h).copied().unwrap_or(0) >= b["tx_count"].as_u64().unwrap_or(0)
            });
        if complete {
            out.push(bucket_json(bucket, blocks, &txs));
        } else if (bucket + 1) * BUCKET <= settled {
            let mut v = bucket_json(bucket, blocks, &txs);
            v["partial"] = json!(true);
            out.push(v);
        } else {
            short.push(bucket);
        }
    }
    (out, short)
}

pub fn write_bucket(dir: &Path, v: &Value) -> std::io::Result<()> {
    let bucket = v["bucket"].as_u64().ok_or_else(|| std::io::Error::other("bucket id missing"))?;
    std::fs::create_dir_all(dir)?;
    let path = dir.join(file_name(bucket));
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(v).map_err(std::io::Error::other)?)?;
    std::fs::rename(&tmp, &path)
}

pub fn ranges(buckets: &BTreeSet<u64>) -> Vec<[u64; 2]> {
    let mut out: Vec<[u64; 2]> = Vec::new();
    for &b in buckets {
        match out.last_mut() {
            Some(r) if r[1] + 1 == b => r[1] = b,
            _ => out.push([b, b]),
        }
    }
    out
}

pub fn merge_users(recent: &[Value], archived: &[Value], limit: usize) -> Vec<Value> {
    let mut all: Vec<Value> = recent.iter().chain(archived.iter()).cloned().collect();
    sort_users(&mut all);
    all.truncate(limit);
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(h: u64, txs: u64) -> Value {
        json!({ "height": h, "hash": format!("{h:064x}"), "tx_count": txs, "commit_cert": "x".repeat(50) })
    }

    fn tx(h: u64, n: u64, user: bool) -> Value {
        if user {
            json!({ "hash": format!("u{h}-{n}"), "block_height": h, "timestamp": h as i64, "from": "egot1alice", "to": "egot1bob", "tx_type": "transfer", "signature": "s" })
        } else {
            json!({ "hash": format!("c{h}-{n}"), "block_height": h, "timestamp": h as i64, "from": "", "to": "egot1miner", "tx_type": "coinbase", "signature": "coinbase" })
        }
    }

    fn chain(heights: std::ops::Range<u64>, skip_tx_at: Option<u64>) -> crate::ChainState {
        let blocks = heights.clone().map(|h| block(h, 1)).collect();
        let transactions = heights.filter(|h| Some(*h) != skip_tx_at).map(|h| tx(h, 0, h % 7 == 0)).collect();
        crate::ChainState { blocks, transactions }
    }

    #[test]
    fn names_round_trip_and_reject_junk() {
        assert_eq!(parse_name(&file_name(42)), Some(42));
        assert_eq!(parse_name("b0000042.json.tmp"), None);
        assert_eq!(parse_name("b42.json"), None);
        assert_eq!(parse_name("../b0000042.json"), None);
    }

    #[test]
    fn only_complete_settled_buckets_are_written() {
        let c = chain(0..1_000, Some(550));
        let (ready, short) = ready_buckets(&c, &BTreeSet::new(), &BTreeSet::new(), 999);
        let ids: Vec<u64> = ready.iter().map(|v| v["bucket"].as_u64().unwrap()).collect();
        assert_eq!(ids, vec![6, 4, 3, 2, 1, 0]);
        assert_eq!(short, vec![5]);
        assert!(ready[0]["blocks"][0].get("commit_cert").is_none());
        assert_eq!(ready[0]["blocks"].as_array().unwrap().len(), 100);
        assert_eq!(ready[0]["txs"].as_array().unwrap().len(), 100);
    }

    #[test]
    fn a_recent_bucket_with_a_missing_block_waits() {
        let mut c = chain(0..400, None);
        c.blocks.retain(|b| b["height"].as_u64() != Some(150));
        let (ready, _) = ready_buckets(&c, &BTreeSet::new(), &BTreeSet::new(), 600);
        let ids: Vec<u64> = ready.iter().map(|v| v["bucket"].as_u64().unwrap()).collect();
        assert_eq!(ids, vec![3, 2, 0]);
    }

    #[test]
    fn rescan_picks_up_files_and_user_transfers() {
        let dir = std::env::temp_dir().join(format!("ego-archive-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let c = chain(0..300, None);
        let (ready, _) = ready_buckets(&c, &BTreeSet::new(), &BTreeSet::new(), 10_000);
        for v in &ready {
            write_bucket(&dir, v).unwrap();
        }
        std::fs::write(dir.join("b0000009.json"), b"{\"bucket\":8}").unwrap();
        let mut a = Archive::default();
        assert_eq!(rescan_dir(&mut a, &dir), 3);
        assert_eq!(rescan_dir(&mut a, &dir), 0);
        assert_eq!(a.users.len(), (0..300).filter(|h| h % 7 == 0).count());
        assert_eq!(a.users[0]["block_height"].as_u64(), Some(294));
        assert_eq!(ranges(&a.buckets), vec![[0, 2]]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hashes_and_addresses_lead_back_to_their_bucket() {
        let mut c = chain(0..300, None);
        for (i, b) in c.blocks.iter_mut().enumerate() {
            b["hash"] = json!(format!("{:016x}{}", 0xab00_0000_0000_0000u64 + i as u64, "0".repeat(48)));
        }
        let (ready, _) = ready_buckets(&c, &BTreeSet::new(), &BTreeSet::new(), 10_000);
        let mut a = Archive::default();
        for v in &ready {
            a.index_bucket(v["bucket"].as_u64().unwrap(), v);
        }
        a.finish_index();
        let block_hash = format!("{:016x}{}", 0xab00_0000_0000_0000u64 + 150, "0".repeat(48));
        assert_eq!(a.find_hash(&block_hash), (vec![], vec![1]));
        assert_eq!(a.find_hash("zz"), (vec![], vec![]));
        assert_eq!(a.address_buckets("egot1alice"), vec![2, 1, 0]);
        assert!(a.address_buckets("egot1nobody").is_empty());
        assert!(same_hash("0xABcd", "abcd"));
        assert!(!same_hash("", ""));
        assert!(is_address("egot1alice") && !is_address("egot1a/../x"));
    }

    #[test]
    fn a_window_bucket_is_built_from_live_blocks_and_marked_partial() {
        let c = chain(0..250, None);
        let v = window_bucket(&c, 2).unwrap();
        assert_eq!(v["blocks"].as_array().unwrap().len(), 50);
        assert_eq!(v["partial"], json!(true));
        assert!(window_bucket(&c, 3).is_none());
        assert_eq!(window_address_buckets(&c, "egot1alice").into_iter().collect::<Vec<_>>(), vec![0, 1, 2]);
    }

    #[test]
    fn old_buckets_are_archived_even_with_gaps_and_then_leave_memory() {
        let mut c = chain(0..10_000, Some(1_234));
        c.blocks.retain(|b| b["height"].as_u64() != Some(2_345));
        let tip = 9_999;
        let mut have = BTreeSet::new();
        for _ in 0..20 {
            let (ready, _) = ready_buckets(&c, &have, &BTreeSet::new(), tip);
            if ready.is_empty() {
                break;
            }
            for v in &ready {
                have.insert(v["bucket"].as_u64().unwrap());
                if v["bucket"] == json!(12) || v["bucket"] == json!(23) {
                    assert_eq!(v["partial"], json!(true));
                }
            }
        }
        assert!(have.contains(&12) && have.contains(&23));
        assert!(!have.contains(&97));
        let removed = trim_window(&mut c, &have, tip);
        assert!(removed > 0);
        let lowest = c.blocks.iter().filter_map(|b| b["height"].as_u64()).filter(|h| *h > 0).min().unwrap();
        assert_eq!(lowest, 3_999);
        assert!(c.blocks.iter().any(|b| b["height"].as_u64() == Some(0)));
    }

    #[test]
    fn reading_by_height_continues_from_disk_below_the_window() {
        let dir = std::env::temp_dir().join(format!("ego-archive-from-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let c = chain(0..400, None);
        let (ready, _) = ready_buckets(&c, &BTreeSet::new(), &BTreeSet::new(), 10_000);
        let mut have = BTreeSet::new();
        for v in &ready {
            write_bucket(&dir, v).unwrap();
            have.insert(v["bucket"].as_u64().unwrap());
        }
        let blocks = archived_from(&dir, &have, 150, 300, 500, "blocks");
        assert_eq!(blocks.first().unwrap()["height"], json!(150));
        assert_eq!(blocks.len(), 150);
        assert_eq!(archived_from(&dir, &have, 150, 300, 10, "txs").len(), 10);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn users_merge_newest_first_without_duplicates() {
        let recent = vec![tx(900, 0, true), tx(800, 0, true)];
        let archived = vec![tx(800, 0, true), tx(10, 0, true)];
        let m = merge_users(&recent, &archived, 10);
        let hs: Vec<u64> = m.iter().map(|t| t["block_height"].as_u64().unwrap()).collect();
        assert_eq!(hs, vec![900, 800, 10]);
        assert_eq!(merge_users(&recent, &archived, 2).len(), 2);
    }
}
