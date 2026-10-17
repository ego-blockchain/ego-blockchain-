use crate::drs::Ov;
use crate::ledger::{LedgerBlock, LedgerTx};
use serde::{Deserialize, Serialize};

pub const CHUNK: u64 = 4096;
const LEVELS: usize = 12;
pub const RECENT_MIN_BLOCKS: u64 = 10_000;
pub const RECENT_MIN_SECS: i64 = 14 * 86_400;
pub const HOLDERS_NEEDED: usize = 3;
pub const HOLDER_TARGET: u64 = 16;
pub const MAX_SHARDS: u64 = 65_536;
pub const PROBE_HEIGHTS: usize = 4;
pub const MAX_PROBE_HEIGHTS: usize = 8;
pub const PROBE_CANDIDATES: usize = 8;
pub const FETCH_BATCH: u64 = 16;
pub const VERIFIED_FOR_SECS: i64 = 6 * 3600;
pub const UNDO_KEEP: u64 = 1_000;
const KEY_FRONTIER: &[u8] = b"bhf";
const BROKEN: u64 = u64::MAX;

fn root_key(chunk: u64) -> Vec<u8> {
    format!("bhr:{chunk:012}").into_bytes()
}

pub fn pruned_key(chunk: u64) -> Vec<u8> {
    format!("hpr:{chunk:012}").into_bytes()
}

pub fn undo_key(height: u64) -> Vec<u8> {
    format!("hu:{height:016x}").into_bytes()
}

pub fn chunk_of(height: u64) -> u64 {
    height / CHUNK
}

pub fn chunk_heights(chunk: u64) -> std::ops::Range<u64> {
    chunk * CHUNK..(chunk + 1) * CHUNK
}

pub fn hash_bytes(hash: &str) -> [u8; 32] {
    hex::decode(hash)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .unwrap_or_else(|| *blake3::hash(hash.as_bytes()).as_bytes())
}

fn leaf(hash: &str) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"ego/bh/leaf:");
    h.update(&hash_bytes(hash));
    *h.finalize().as_bytes()
}

fn node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"ego/bh/node:");
    h.update(l);
    h.update(r);
    *h.finalize().as_bytes()
}

struct Frontier {
    chunk: u64,
    count: u64,
    levels: Vec<[u8; 32]>,
}

impl Frontier {
    fn fresh(chunk: u64, count: u64) -> Self {
        Self { chunk, count, levels: vec![[0u8; 32]; LEVELS] }
    }

    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(16 + LEVELS * 32);
        v.extend_from_slice(&self.chunk.to_le_bytes());
        v.extend_from_slice(&self.count.to_le_bytes());
        for l in &self.levels {
            v.extend_from_slice(l);
        }
        v
    }

    fn decode(v: &[u8]) -> Option<Self> {
        if v.len() != 16 + LEVELS * 32 {
            return None;
        }
        let chunk = u64::from_le_bytes(v[0..8].try_into().ok()?);
        let count = u64::from_le_bytes(v[8..16].try_into().ok()?);
        let levels = v[16..].chunks(32).map(|c| <[u8; 32]>::try_from(c).unwrap_or([0u8; 32])).collect();
        Some(Self { chunk, count, levels })
    }
}

pub fn push(ov: &mut Ov, height: u64, hash: &str) {
    let chunk = chunk_of(height);
    let pos = height % CHUNK;
    let broken = |ov: &mut Ov| ov.put(KEY_FRONTIER.to_vec(), Frontier::fresh(chunk, BROKEN).encode());
    let mut f = match ov.get(KEY_FRONTIER).and_then(|v| Frontier::decode(&v)) {
        Some(f) if f.count == BROKEN => {
            if chunk <= f.chunk {
                return;
            }
            if pos != 0 {
                broken(ov);
                return;
            }
            Frontier::fresh(chunk, 0)
        }
        Some(f) => {
            let expected = f.chunk * CHUNK + f.count;
            if height < expected {
                return;
            }
            if height > expected {
                if pos != 0 {
                    broken(ov);
                    return;
                }
                Frontier::fresh(chunk, 0)
            } else {
                f
            }
        }
        None if pos == 0 => Frontier::fresh(chunk, 0),
        None => {
            broken(ov);
            return;
        }
    };
    let mut cur = leaf(hash);
    let mut level = 0usize;
    let mut c = f.count;
    while c & 1 == 1 {
        cur = node(&f.levels[level], &cur);
        c >>= 1;
        level += 1;
    }
    f.count += 1;
    if f.count == CHUNK {
        ov.put(root_key(chunk), cur.to_vec());
        ov.put(KEY_FRONTIER.to_vec(), Frontier::fresh(chunk + 1, 0).encode());
    } else {
        f.levels[level] = cur;
        ov.put(KEY_FRONTIER.to_vec(), f.encode());
    }
}

pub fn chunk_root(ov: &Ov, chunk: u64) -> Option<[u8; 32]> {
    ov.get(&root_key(chunk)).and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
}

pub fn tree_root(hashes: &[String]) -> Option<[u8; 32]> {
    if hashes.len() as u64 != CHUNK {
        return None;
    }
    let mut layer: Vec<[u8; 32]> = hashes.iter().map(|h| leaf(h)).collect();
    while layer.len() > 1 {
        layer = layer.chunks(2).map(|p| node(&p[0], &p[1])).collect();
    }
    layer.first().copied()
}

pub fn path_for(hashes: &[String], pos: u64) -> Option<Vec<String>> {
    if hashes.len() as u64 != CHUNK || pos >= CHUNK {
        return None;
    }
    let mut layer: Vec<[u8; 32]> = hashes.iter().map(|h| leaf(h)).collect();
    let mut idx = pos as usize;
    let mut path = Vec::with_capacity(LEVELS);
    while layer.len() > 1 {
        path.push(hex::encode(layer[idx ^ 1]));
        layer = layer.chunks(2).map(|p| node(&p[0], &p[1])).collect();
        idx >>= 1;
    }
    Some(path)
}

pub fn path_ok(hash: &str, pos: u64, path: &[String], root: &[u8; 32]) -> bool {
    if path.len() != LEVELS || pos >= CHUNK {
        return false;
    }
    let mut cur = leaf(hash);
    let mut idx = pos;
    for sib in path {
        let Some(s) = hex::decode(sib).ok().and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok()) else {
            return false;
        };
        cur = if idx & 1 == 0 { node(&cur, &s) } else { node(&s, &cur) };
        idx >>= 1;
    }
    &cur == root
}

pub fn shard_count(live_nodes: u64) -> u64 {
    let x = live_nodes / HOLDER_TARGET;
    if x < 2 {
        return 1;
    }
    let mut p = 1u64;
    while p * 2 <= x && p * 2 <= MAX_SHARDS {
        p *= 2;
    }
    p
}

pub fn shard_of_chunk(chunk: u64, shards: u64) -> u64 {
    if shards <= 1 { 0 } else { chunk % shards }
}

pub fn home_shard(idx: u64, shards: u64) -> u64 {
    if shards <= 1 { 0 } else { idx % shards }
}

pub fn holders(ov: &Ov, shard: u64, shards: u64, at: i64, rotate: u64, limit: usize, skip: &[String]) -> Vec<String> {
    let count = crate::drs::node_count(ov);
    let step = shards.max(1);
    if shard >= count {
        return Vec::new();
    }
    let per_class = (count - shard + step - 1) / step;
    let start = rotate % per_class;
    let mut out = Vec::new();
    let mut k = 0u64;
    while out.len() < limit && k < per_class.min(10_000) {
        let idx = shard + ((start + k) % per_class) * step;
        k += 1;
        let Some(addr) = crate::drs::addr_at(ov, idx) else { continue };
        if !skip.contains(&addr) && crate::drs::is_live(ov, &addr, at) {
            out.push(addr);
        }
    }
    out
}

pub fn recent_floor(tip: u64, tip_ts: i64, ts_at: impl Fn(u64) -> Option<i64>, contract_height: Option<u64>) -> u64 {
    if tip < crate::drs::DRS_FROM_HEIGHT {
        return 0;
    }
    let by_blocks = tip.saturating_sub(RECENT_MIN_BLOCKS);
    let cutoff = tip_ts.saturating_sub(RECENT_MIN_SECS);
    let old_enough = |h: u64| ts_at(h).map_or(true, |t| t <= cutoff);
    let floor = if old_enough(by_blocks) {
        by_blocks
    } else {
        let (mut lo, mut hi) = (0u64, by_blocks);
        while lo < hi {
            let mid = lo + (hi - lo + 1) / 2;
            if old_enough(mid) { lo = mid } else { hi = mid - 1 }
        }
        lo
    };
    match contract_height {
        Some(c) => floor.min(c),
        None => floor,
    }
}

pub fn prunable(chunk: u64, floor: u64) -> bool {
    (chunk + 1) * CHUNK <= floor
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HistoryPiece {
    pub height: u64,
    pub block: LedgerBlock,
    pub txs: Vec<LedgerTx>,
    #[serde(default)]
    pub path: Vec<String>,
}

pub fn piece_digest(block: &LedgerBlock, txs: &[LedgerTx]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"ego/piece/v1:");
    h.update(&block.height.to_le_bytes());
    h.update(block.hash.as_bytes());
    let mut sorted: Vec<&LedgerTx> = txs.iter().collect();
    sorted.sort_by(|a, b| a.hash.cmp(&b.hash));
    for tx in sorted {
        let mut t = tx.clone();
        t.status.clear();
        t.block_height = Some(block.height);
        let body = serde_json::to_vec(&t).unwrap_or_default();
        h.update(&(body.len() as u64).to_le_bytes());
        h.update(&body);
    }
    *h.finalize().as_bytes()
}

pub fn probe_answer(nonce: &str, holder: &str, digest: &[u8; 32]) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"ego/probe/v1:");
    h.update(nonce.as_bytes());
    h.update(b":");
    h.update(holder.as_bytes());
    h.update(b":");
    h.update(digest);
    h.finalize().to_hex().to_string()
}

pub fn proof_message(nonce: &str, holder: &str, answers: &[String]) -> Vec<u8> {
    format!("ego/history-proof/v1:{nonce}:{holder}:{}", answers.join(",")).into_bytes()
}

pub fn probe_heights(nonce: &str, chunk: u64, n: usize) -> Vec<u64> {
    let mut out: Vec<u64> = Vec::with_capacity(n);
    let mut i = 0u64;
    while out.len() < n && i < 64 {
        let d = blake3::hash(format!("{nonce}:{chunk}:{i}").as_bytes());
        let pos = u64::from_le_bytes(d.as_bytes()[..8].try_into().unwrap()) % CHUNK;
        let h = chunk * CHUNK + pos;
        if h != 0 && !out.contains(&h) {
            out.push(h);
        }
        i += 1;
    }
    out
}

pub fn txs_root_ok(block: &LedgerBlock, txs: &[LedgerTx]) -> bool {
    let hashes: Vec<&str> = txs.iter().map(|t| t.hash.as_str()).collect();
    block.tx_merkle_root == crate::chain_db::compute_merkle_root(&hashes)
        || block.tx_merkle_root == crate::chain_db::sorted_tx_root(txs)
}

pub fn verify_piece(piece: &HistoryPiece, root: &[u8; 32]) -> Result<(), String> {
    let b = &piece.block;
    if b.height != piece.height || piece.height == 0 {
        return Err(format!("piece for height {} carries block {}", piece.height, b.height));
    }
    if !path_ok(&b.hash, piece.height % CHUNK, &piece.path, root) {
        return Err(format!("block {} is not the one this chain recorded at that height", piece.height));
    }
    if !crate::chain_db::verify_block_hash(b, &piece.txs) {
        return Err(format!("block {}'s fields do not hash to its hash", piece.height));
    }
    if piece.txs.len() as u64 != b.tx_count as u64 {
        return Err(format!("{} transactions served for block {} which carries {}", piece.txs.len(), piece.height, b.tx_count));
    }
    let mut seen = std::collections::HashSet::new();
    if !piece.txs.iter().all(|t| seen.insert(t.hash.as_str())) {
        return Err(format!("block {} was served with a transaction twice", piece.height));
    }
    if !txs_root_ok(b, &piece.txs) {
        return Err(format!("the transactions served for block {} do not match its root", piece.height));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hashes(chunk: u64) -> Vec<String> {
        chunk_heights(chunk).map(|h| format!("{:064x}", h * 7 + 1)).collect()
    }

    #[test]
    fn the_running_index_matches_the_whole_chunk_tree() {
        let mut ov = Ov::memory();
        for c in 0..2u64 {
            for (i, h) in hashes(c).iter().enumerate() {
                push(&mut ov, c * CHUNK + i as u64, h);
                ov.commit_memory();
            }
        }
        assert_eq!(chunk_root(&ov, 0), tree_root(&hashes(0)));
        assert_eq!(chunk_root(&ov, 1), tree_root(&hashes(1)));
        assert!(chunk_root(&ov, 0) != chunk_root(&ov, 1));
        let hs = hashes(1);
        let root = chunk_root(&ov, 1).unwrap();
        for pos in [0u64, 1, 2047, 4095] {
            let path = path_for(&hs, pos).unwrap();
            assert!(path_ok(&hs[pos as usize], pos, &path, &root));
            assert!(!path_ok(&hs[pos as usize], pos ^ 1, &path, &root), "a hash proves only its own height");
            assert!(!path_ok(&format!("{:064x}", 9), pos, &path, &root), "another block fails");
        }
    }

    #[test]
    fn a_missing_block_leaves_its_chunk_without_a_root() {
        let mut ov = Ov::memory();
        let hs = hashes(0);
        for (i, h) in hs.iter().enumerate() {
            if i != 100 {
                push(&mut ov, i as u64, h);
                ov.commit_memory();
            }
        }
        assert!(chunk_root(&ov, 0).is_none(), "a chunk with a gap must never get a root");
        for (i, h) in hashes(1).iter().enumerate() {
            push(&mut ov, CHUNK + i as u64, h);
            ov.commit_memory();
        }
        assert_eq!(chunk_root(&ov, 1), tree_root(&hashes(1)), "the next chunk starts clean");
    }

    #[test]
    fn a_block_written_twice_does_not_disturb_the_index() {
        let mut ov = Ov::memory();
        let hs = hashes(0);
        for (i, h) in hs.iter().enumerate() {
            push(&mut ov, i as u64, h);
            if i == 2_000 {
                push(&mut ov, 0, &hs[0]);
                push(&mut ov, 1_500, &hs[1_500]);
            }
            ov.commit_memory();
        }
        assert_eq!(chunk_root(&ov, 0), tree_root(&hs), "rewriting old heights changes nothing");
        let next = hashes(1);
        push(&mut ov, 5, &hs[5]);
        for (i, h) in next.iter().enumerate() {
            push(&mut ov, CHUNK + i as u64, h);
            ov.commit_memory();
        }
        assert_eq!(chunk_root(&ov, 1), tree_root(&next), "a finished chunk hands over cleanly to the next");
    }

    #[test]
    fn shards_grow_with_the_network_and_each_has_many_holders() {
        assert_eq!(shard_count(0), 1);
        assert_eq!(shard_count(31), 1);
        assert_eq!(shard_count(32), 2);
        assert_eq!(shard_count(1_000), 32);
        assert_eq!(shard_count(10_000_000), MAX_SHARDS);
        for n in [32u64, 1_000, 100_000, 10_000_000] {
            assert!(n / shard_count(n) >= HOLDER_TARGET);
        }
    }

    #[test]
    fn doubling_the_shards_only_ever_drops_history() {
        for idx in 0..300u64 {
            for s in [1u64, 2, 4, 64, 1_024] {
                for c in 0..3_000u64 {
                    if shard_of_chunk(c, s * 2) == home_shard(idx, s * 2) {
                        assert_eq!(shard_of_chunk(c, s), home_shard(idx, s));
                    }
                }
            }
        }
    }

    #[test]
    fn the_floor_keeps_two_weeks_and_ten_thousand_blocks() {
        let drs = crate::drs::DRS_FROM_HEIGHT;
        assert_eq!(recent_floor(drs - 1, 0, |_| Some(0), None), 0, "nothing is pruned before committees run");
        let tip = drs + 100_000;
        let ts = |h: u64| Some(h as i64 * 20);
        let tip_ts = tip as i64 * 20;
        let f = recent_floor(tip, tip_ts, ts, None);
        assert_eq!(f, tip - RECENT_MIN_SECS as u64 / 20, "fast blocks keep fourteen days");
        let slow = |h: u64| Some(h as i64 * 1_200);
        let f = recent_floor(tip, tip as i64 * 1_200, slow, None);
        assert_eq!(f, tip - RECENT_MIN_BLOCKS, "slow blocks keep ten thousand");
        assert_eq!(recent_floor(tip, tip as i64 * 1_200, slow, Some(drs)), drs, "unexecuted contracts hold the floor");
        assert!(!prunable(chunk_of(f), f));
        assert!(prunable(chunk_of(f) - 1, f));
    }

    #[test]
    fn probes_sample_heights_the_holder_cannot_guess() {
        let a = probe_heights("n1", 5, PROBE_HEIGHTS);
        let b = probe_heights("n2", 5, PROBE_HEIGHTS);
        assert_eq!(a.len(), PROBE_HEIGHTS);
        assert!(a.iter().all(|h| chunk_of(*h) == 5));
        assert_ne!(a, b);
        assert!(!probe_heights("n", 0, 64).contains(&0));
    }

    #[test]
    fn a_piece_digest_ignores_local_status_but_not_contents() {
        let block = LedgerBlock { height: 9, hash: "0xb".into(), ..Default::default() };
        let tx = LedgerTx { hash: "0x1".into(), amount: 5, status: "Confirmed".into(), ..Default::default() };
        let mut pending = tx.clone();
        pending.status = "Pending".into();
        assert_eq!(piece_digest(&block, &[tx.clone()]), piece_digest(&block, &[pending]));
        let mut forged = tx.clone();
        forged.amount = 6;
        assert_ne!(piece_digest(&block, &[tx]), piece_digest(&block, &[forged]));
    }
}
