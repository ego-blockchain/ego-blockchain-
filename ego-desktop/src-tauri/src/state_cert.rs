use crate::drs::Ov;
use crate::ledger::{LedgerBlock, LedgerTx};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const STATE_CERT_FROM_HEIGHT: u64 = 32_650;
pub const CERT_DRAW_V2_FROM_HEIGHT: u64 = 32_815;
pub const CERT_RETRY_BLOCKS: u64 = 300;
pub const CERT_FALLBACK_BLOCKS: u64 = 2_000;
pub const CERT_COMMITTEE: usize = 128;
pub const CHUNK_ENTRIES: usize = 4096;
pub const DAY_SECS: i64 = 86_400;
pub const TX_STATE_CERT: &str = "state_cert";
pub const TAG_BALANCE: u8 = 1;
pub const TAG_META: u8 = 2;
pub const TAG_CONTRACT: u8 = 3;
pub const STATE_CERT_ANCHORS: &[(u64, &str)] = &[
    (1, "cda691751e0b56e24ef1706b3af4e149c0a51f90c996d47b9fc4b85b7b2c200c"),
    (2, "cffc024048f1b24c2a3dcdb61f9cf763b38ef1f5c5d1548de3b550998ef50785"),
];
const KEY_DAY: &[u8] = b"sc:day";
const KEY_OPEN: &[u8] = b"sc:open";
const KEY_LAST: &[u8] = b"sc:last";

const STATE_META_KEYS: &[&[u8]] = &[b"bhf", b"randao_mix", b"latest_height"];
const STATE_META_PREFIXES: &[&[u8]] = &[
    b"n2",
    b"s2",
    b"bhr:",
    b"ftotal:",
    b"sc:",
    b"shielded:",
    b"market:",
    b"nonce:",
    b"stake:",
    b"stakemeta:",
    b"val_active:",
    b"val_seated:",
    b"val_jailed:",
    b"val_dil:",
    b"val_bls:",
    b"bls_reg:",
    b"faucet_mark:",
    b"credits:",
    b"escrow_rel",
    b"sfile:",
    b"sproof:",
    b"price_rep:",
    b"storage_proven:",
    b"poc_proof:",
];
const NOT_STATE: &[&[u8]] = &[b"n2migrated"];

pub fn is_state_meta(key: &[u8]) -> bool {
    !NOT_STATE.contains(&key) && (STATE_META_KEYS.contains(&key) || STATE_META_PREFIXES.iter().any(|p| key.starts_with(p)))
}

pub fn is_state_contract(key: &[u8]) -> bool {
    !key.starts_with(b"u:")
}

fn cert_key(index: u64) -> Vec<u8> {
    format!("sc:cert:{index:012}").into_bytes()
}

fn u64_of(v: &[u8]) -> u64 {
    v.get(..8).and_then(|b| b.try_into().ok()).map(u64::from_le_bytes).unwrap_or(0)
}

fn feed(h: &mut blake3::Hasher, tag: u8, key: &[u8], value: &[u8]) {
    h.update(&[tag]);
    h.update(&(key.len() as u32).to_le_bytes());
    h.update(key);
    h.update(&(value.len() as u32).to_le_bytes());
    h.update(value);
}

fn chunk_hasher() -> blake3::Hasher {
    let mut h = blake3::Hasher::new();
    h.update(b"ego/state/chunk/v1:");
    h
}

pub fn chunk_hash(entries: &[(u8, Vec<u8>, Vec<u8>)]) -> [u8; 32] {
    let mut h = chunk_hasher();
    for (tag, k, v) in entries {
        feed(&mut h, *tag, k, v);
    }
    *h.finalize().as_bytes()
}

fn node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"ego/state/node/v1:");
    h.update(l);
    h.update(r);
    *h.finalize().as_bytes()
}

fn layer_up(nodes: &[[u8; 32]]) -> Vec<[u8; 32]> {
    nodes.chunks(2).map(|p| if p.len() == 2 { node(&p[0], &p[1]) } else { p[0] }).collect()
}

pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut layer = leaves.to_vec();
    while layer.len() > 1 {
        layer = layer_up(&layer);
    }
    layer[0]
}

pub fn merkle_path(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    let mut path = Vec::new();
    let mut layer = leaves.to_vec();
    let mut i = index;
    while layer.len() > 1 {
        if let Some(s) = layer.get(i ^ 1) {
            path.push(*s);
        }
        layer = layer_up(&layer);
        i /= 2;
    }
    path
}

pub fn merkle_verify(leaf: [u8; 32], index: u64, count: u64, path: &[[u8; 32]], root: &[u8; 32]) -> bool {
    if index >= count {
        return false;
    }
    let mut cur = leaf;
    let (mut i, mut n) = (index, count);
    let mut sibs = path.iter();
    while n > 1 {
        if (i ^ 1) < n {
            let Some(s) = sibs.next() else { return false };
            cur = if i & 1 == 0 { node(&cur, s) } else { node(s, &cur) };
        }
        i /= 2;
        n = (n + 1) / 2;
    }
    sibs.next().is_none() && &cur == root
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ChunkStart {
    pub tag: u8,
    pub key: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Digest {
    pub root: String,
    pub chunks: Vec<String>,
    pub starts: Vec<ChunkStart>,
}

impl Digest {
    pub fn chunk_hashes(&self) -> Vec<[u8; 32]> {
        self.chunks.iter().map(|c| hex32(c).unwrap_or([0u8; 32])).collect()
    }
}

pub fn hex32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok().and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
}

pub struct RootBuilder {
    hasher: blake3::Hasher,
    in_chunk: usize,
    chunks: Vec<[u8; 32]>,
    starts: Vec<ChunkStart>,
}

impl Default for RootBuilder {
    fn default() -> Self {
        Self { hasher: chunk_hasher(), in_chunk: 0, chunks: Vec::new(), starts: Vec::new() }
    }
}

impl RootBuilder {
    pub fn add(&mut self, tag: u8, key: &[u8], value: &[u8]) {
        if self.in_chunk == 0 {
            self.hasher = chunk_hasher();
            self.starts.push(ChunkStart { tag, key: hex::encode(key) });
        }
        feed(&mut self.hasher, tag, key, value);
        self.in_chunk += 1;
        if self.in_chunk == CHUNK_ENTRIES {
            self.chunks.push(*self.hasher.finalize().as_bytes());
            self.in_chunk = 0;
        }
    }

    pub fn finish(mut self) -> Digest {
        if self.in_chunk > 0 {
            self.chunks.push(*self.hasher.finalize().as_bytes());
        }
        Digest {
            root: hex::encode(merkle_root(&self.chunks)),
            chunks: self.chunks.iter().map(hex::encode).collect(),
            starts: self.starts,
        }
    }
}

pub fn chunk_ok(entries: &[(u8, Vec<u8>, Vec<u8>)], index: u64, count: u64, path: &[[u8; 32]], root: &[u8; 32]) -> bool {
    let full = index + 1 < count;
    let size_ok = if full { entries.len() == CHUNK_ENTRIES } else { !entries.is_empty() && entries.len() <= CHUNK_ENTRIES };
    size_ok && merkle_verify(chunk_hash(entries), index, count, path, root)
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CertBody {
    pub index: u64,
    pub height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub state_chunks: u64,
    pub contract_root: String,
    pub contract_chunks: u64,
    pub next: Vec<String>,
}

impl CertBody {
    pub fn message(&self) -> Vec<u8> {
        let mut m = b"ego/state-cert/v1:".to_vec();
        m.extend_from_slice(blake3::hash(&serde_json::to_vec(self).unwrap_or_default()).as_bytes());
        m
    }

    pub fn id(&self) -> [u8; 32] {
        *blake3::hash(&self.message()).as_bytes()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StateCert {
    pub body: CertBody,
    #[serde(default)]
    pub signers: Vec<u32>,
    #[serde(default)]
    pub sig: String,
}

impl StateCert {
    pub fn hash(&self) -> String {
        blake3::hash(&serde_json::to_vec(self).unwrap_or_default()).to_hex().to_string()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OpenCheckpoint {
    pub index: u64,
    pub height: u64,
    pub block_hash: String,
    pub next: Vec<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub first_height: u64,
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

pub fn quorum(n: usize) -> usize {
    n * 2 / 3 + 1
}

pub fn signers_for(prev: Option<&StateCert>, drawn: &[String]) -> Vec<String> {
    match prev {
        Some(c) if !c.body.next.is_empty() => c.body.next.clone(),
        _ => drawn.to_vec(),
    }
}

pub fn vote_ok(body: &CertBody, signer: &str, sig: &str, keys: &[String]) -> bool {
    keys.iter().any(|k| k == signer)
        && match (hex::decode(signer), hex::decode(sig)) {
            (Ok(pk), Ok(s)) => crate::bls_agg::verify_shared(&s, &pk, &body.message()),
            _ => false,
        }
}

pub fn verify_cert(cert: &StateCert, keys: &[String]) -> Result<(), String> {
    if keys.is_empty() {
        return Err(format!("certificate {} has no committee that may sign it", cert.body.index));
    }
    if cert.signers.windows(2).any(|w| w[0] >= w[1]) || cert.signers.iter().any(|p| *p as usize >= keys.len()) {
        return Err(format!("certificate {} lists its signers out of order or out of range", cert.body.index));
    }
    if cert.signers.len() < quorum(keys.len()) {
        return Err(format!("certificate {} has {} of the {} signatures it needs", cert.body.index, cert.signers.len(), quorum(keys.len())));
    }
    let pks: Vec<Vec<u8>> = cert.signers.iter().filter_map(|p| hex::decode(&keys[*p as usize]).ok()).collect();
    let sig = hex::decode(&cert.sig).map_err(|_| "certificate signature is not hex".to_string())?;
    if pks.len() != cert.signers.len() || !crate::bls_agg::verify_shared_aggregate(&sig, &pks, &cert.body.message()) {
        return Err(format!("certificate {} signature does not verify", cert.body.index));
    }
    Ok(())
}

pub fn assemble(body: &CertBody, votes: &[(String, String)], keys: &[String]) -> Option<StateCert> {
    let ok: Vec<&(String, String)> = votes.iter().filter(|(s, g)| vote_ok(body, s, g, keys)).collect();
    let mut picked: Vec<(u32, Vec<u8>)> = keys
        .iter()
        .enumerate()
        .filter_map(|(i, k)| {
            let (_, sig) = ok.iter().find(|(s, _)| s == k)?;
            Some((i as u32, hex::decode(sig).ok()?))
        })
        .collect();
    picked.sort_by_key(|(i, _)| *i);
    let sigs: Vec<Vec<u8>> = picked.iter().map(|(_, s)| s.clone()).collect();
    let agg = crate::bls_agg::aggregate_shared(&sigs)?;
    let cert = StateCert { body: body.clone(), signers: picked.iter().map(|(i, _)| *i).collect(), sig: hex::encode(agg) };
    verify_cert(&cert, keys).ok().map(|_| cert)
}

pub fn is_anchor_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn anchors_with(published: Option<(u64, String)>) -> Vec<(u64, String)> {
    let mut all: Vec<(u64, String)> = STATE_CERT_ANCHORS.iter().map(|(i, h)| (*i, h.to_string())).collect();
    all.extend(published.filter(|(i, h)| *i > 0 && is_anchor_hash(h)));
    all.sort();
    all.dedup();
    all
}

pub fn verify_chain(certs: &[StateCert], anchors: &[(u64, String)]) -> Result<Option<StateCert>, String> {
    let Some(first) = certs.first() else { return Ok(None) };
    let Some((start, _)) = anchors.first() else {
        return Err("no official certificate is known yet; egoblockchain.com names one once the first is final".into());
    };
    if first.body.index != *start {
        return Err(format!("the certificates offered start at {}, not at the official certificate {start}", first.body.index));
    }
    let mut prev: Option<StateCert> = None;
    for cert in certs {
        if anchors.iter().any(|(i, h)| *i == cert.body.index && *h != cert.hash()) {
            return Err(format!("certificate {} is not the official one", cert.body.index));
        }
        let official = anchors.iter().any(|(i, _)| *i == cert.body.index);
        if let Some(p) = &prev {
            if cert.body.index != p.body.index + 1 {
                return Err(format!("certificate {} follows {}", cert.body.index, p.body.index));
            }
            if cert.body.height <= p.body.height {
                return Err(format!("certificate {} does not move the chain forward", cert.body.index));
            }
            if !official {
                verify_cert(cert, &p.body.next)?;
            }
        }
        prev = Some(cert.clone());
    }
    if let Some((i, _)) = anchors.last() {
        if prev.as_ref().map_or(true, |p| p.body.index < *i) {
            return Err(format!("the certificates offered stop before {i}, which is already official"));
        }
    }
    Ok(prev)
}

pub fn load_open(ov: &Ov) -> Option<OpenCheckpoint> {
    ov.get(KEY_OPEN).and_then(|v| serde_json::from_slice(&v).ok())
}

pub fn load_cert(ov: &Ov, index: u64) -> Option<StateCert> {
    ov.get(&cert_key(index)).and_then(|v| serde_json::from_slice(&v).ok())
}

pub fn last_index(ov: &Ov) -> u64 {
    ov.get(KEY_LAST).map(|v| u64_of(&v)).unwrap_or(0)
}

pub fn signers_of(ov: &Ov, index: u64, height: u64) -> Vec<String> {
    let prev = if index > 1 { load_cert(ov, index - 1) } else { None };
    let open = load_open(ov).filter(|o| o.index == index);
    let drawn = open.as_ref().map(|o| o.next.clone()).unwrap_or_default();
    let stuck = open.as_ref().map_or(false, |o| o.first_height > 0 && height >= o.first_height.saturating_add(CERT_FALLBACK_BLOCKS));
    if stuck && !drawn.is_empty() {
        return drawn;
    }
    signers_for(prev.as_ref(), &drawn)
}

pub fn draw_answering(ov: &Ov, height: u64) -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();
    let mut seen = BTreeSet::new();
    for addr in crate::drs::draw_pool(ov, height) {
        if keys.len() >= CERT_COMMITTEE {
            break;
        }
        if let Some(rec) = crate::drs::load_rec(ov, &addr) {
            if !rec.pop_key.is_empty() && seen.insert(rec.pop_key.clone()) {
                keys.push(rec.pop_key);
            }
        }
    }
    keys
}

pub fn draw_next(ov: &Ov, period: u64, seed: &str) -> Vec<String> {
    let total = crate::drs::total_weight(ov, period);
    if total == 0 {
        return Vec::new();
    }
    let mut keys: Vec<String> = Vec::new();
    let mut seen_idx = BTreeSet::new();
    let mut seen_key = BTreeSet::new();
    for j in 0..(CERT_COMMITTEE * 8) as u64 {
        if keys.len() >= CERT_COMMITTEE {
            break;
        }
        let mut h = blake3::Hasher::new();
        h.update(b"ego/state-cert/draw/v1:");
        h.update(seed.as_bytes());
        h.update(&j.to_le_bytes());
        let r = (u128::from_le_bytes(h.finalize().as_bytes()[..16].try_into().unwrap()) % total as u128) as u64;
        let Some(idx) = crate::drs::sample(ov, period, r) else { continue };
        if !seen_idx.insert(idx) {
            continue;
        }
        let Some(rec) = crate::drs::addr_at(ov, idx).and_then(|a| crate::drs::load_rec(ov, &a)) else { continue };
        if !rec.pop_key.is_empty() && seen_key.insert(rec.pop_key.clone()) {
            keys.push(rec.pop_key);
        }
    }
    keys
}

pub fn is_cert_tx(tx: &LedgerTx) -> bool {
    tx.tx_type == TX_STATE_CERT
        && tx.from.is_empty()
        && tx.to == crate::chain_db::NODE_POOL_ADDR
        && tx.amount == 0
        && tx.signature == "coinbase"
}

pub fn validate(ov: &Ov, block: &LedgerBlock, txs: &[LedgerTx]) -> Result<(), String> {
    let certs: Vec<&LedgerTx> = txs.iter().filter(|t| t.tx_type == TX_STATE_CERT).collect();
    let Some(tx) = certs.first() else { return Ok(()) };
    if certs.len() > 1 {
        return Err(format!("block {} carries more than one state certificate", block.height));
    }
    if block.height < STATE_CERT_FROM_HEIGHT
        || !is_cert_tx(tx)
        || tx.hash != crate::drs::batch_hash(TX_STATE_CERT, block.height, &tx.call_args)
    {
        return Err(format!("state certificate {} is not one the rules allow in block {}", tx.hash, block.height));
    }
    let cert: StateCert = serde_json::from_str(&tx.call_args).map_err(|e| format!("state certificate is unreadable: {e}"))?;
    let open = load_open(ov).ok_or_else(|| format!("block {} certifies a checkpoint nobody is waiting on", block.height))?;
    let b = &cert.body;
    if b.index != open.index || b.height != open.height || b.block_hash != open.block_hash || b.next != open.next {
        return Err(format!("state certificate {} does not match the checkpoint at block {}", b.index, open.height));
    }
    verify_cert(&cert, &signers_of(ov, open.index, block.height))
}

pub fn apply_block(ov: &mut Ov, block: &LedgerBlock, txs: &[&LedgerTx], seed: &str) -> bool {
    if block.height < STATE_CERT_FROM_HEIGHT {
        return false;
    }
    if let Some(cert) = txs
        .iter()
        .find(|t| t.tx_type == TX_STATE_CERT)
        .and_then(|t| serde_json::from_str::<StateCert>(&t.call_args).ok())
    {
        let index = cert.body.index;
        ov.put(cert_key(index), serde_json::to_vec(&cert).unwrap_or_default());
        ov.put(KEY_LAST.to_vec(), index.to_le_bytes().to_vec());
        if load_open(ov).map_or(false, |o| o.index == index) {
            ov.del(KEY_OPEN.to_vec());
        }
    }
    let day = (block.timestamp.max(0) / DAY_SECS) as u64;
    let new_day = !ov.get(KEY_DAY).map_or(false, |v| day <= u64_of(&v));
    let v2 = block.height >= CERT_DRAW_V2_FROM_HEIGHT;
    let waiting = load_open(ov);
    let retry = v2
        && waiting.as_ref().map_or(false, |o| {
            block.height == CERT_DRAW_V2_FROM_HEIGHT || block.height >= o.height.saturating_add(CERT_RETRY_BLOCKS)
        });
    if !new_day && !retry {
        return false;
    }
    if new_day {
        ov.put(KEY_DAY.to_vec(), day.to_le_bytes().to_vec());
    }
    let last = last_index(ov);
    let mut next = if v2 { draw_answering(ov, block.height) } else { draw_next(ov, crate::drs::period_of(block.height), seed) };
    if next.is_empty() {
        next = load_cert(ov, last).map(|c| c.body.next).unwrap_or_default();
    }
    let first_height = if v2 {
        waiting
            .filter(|o| o.index == last + 1)
            .map(|o| if o.first_height > 0 { o.first_height } else { o.height })
            .unwrap_or(block.height)
    } else {
        0
    };
    let open = OpenCheckpoint { index: last + 1, height: block.height, block_hash: block.hash.clone(), next, first_height };
    ov.put(KEY_OPEN.to_vec(), serde_json::to_vec(&open).unwrap_or_default());
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(n: usize) -> Vec<(u8, Vec<u8>, Vec<u8>)> {
        (0..n).map(|i| (TAG_BALANCE, format!("k{i:08}").into_bytes(), (i as u64).to_le_bytes().to_vec())).collect()
    }

    #[test]
    fn every_chunk_of_the_state_proves_itself_against_the_root() {
        for n in [1usize, CHUNK_ENTRIES, CHUNK_ENTRIES + 1, CHUNK_ENTRIES * 5 + 7] {
            let all = entries(n);
            let mut b = RootBuilder::default();
            for (t, k, v) in &all {
                b.add(*t, k, v);
            }
            let d = b.finish();
            let root = hex32(&d.root).unwrap();
            let hashes = d.chunk_hashes();
            let count = hashes.len() as u64;
            assert_eq!(count as usize, (n + CHUNK_ENTRIES - 1) / CHUNK_ENTRIES);
            for (i, part) in all.chunks(CHUNK_ENTRIES).enumerate() {
                let path = merkle_path(&hashes, i);
                assert!(chunk_ok(part, i as u64, count, &path, &root), "chunk {i} of {count}");
                assert_eq!(d.starts[i].key, hex::encode(&part[0].1));
                let mut forged = part.to_vec();
                forged[0].2 = b"x".to_vec();
                assert!(!chunk_ok(&forged, i as u64, count, &path, &root), "an altered value is refused");
                if part.len() > 1 {
                    assert!(!chunk_ok(&part[1..], i as u64, count, &path, &root), "a chunk served short is refused");
                }
                if count > 1 {
                    let j = (i as u64 + 1) % count;
                    assert!(!chunk_ok(part, j, count, &path, &root), "a chunk cannot pose as another");
                }
            }
        }
    }

    fn body(index: u64, next: Vec<String>) -> CertBody {
        CertBody { index, height: 100 * index, block_hash: format!("{index:064x}"), state_root: "aa".repeat(32), state_chunks: 3, next, ..CertBody::default() }
    }

    fn bls(seed: u8) -> blst::min_pk::SecretKey {
        crate::bls_agg::derive_bls_key(&[seed; 32])
    }

    fn bls_votes(b: &CertBody, keys: &[blst::min_pk::SecretKey]) -> Vec<(String, String)> {
        keys.iter()
            .map(|k| (hex::encode(crate::bls_agg::bls_pubkey(k)), hex::encode(crate::bls_agg::sign_shared(k, &b.message()))))
            .collect()
    }

    fn keys(s: &[blst::min_pk::SecretKey]) -> Vec<String> {
        s.iter().map(|k| hex::encode(crate::bls_agg::bls_pubkey(k))).collect()
    }

    #[test]
    fn a_new_node_follows_the_certificates_from_the_official_one_to_today() {
        let c1: Vec<blst::min_pk::SecretKey> = (1..7).map(bls).collect();
        let c2: Vec<blst::min_pk::SecretKey> = (10..16).map(bls).collect();
        let c3: Vec<blst::min_pk::SecretKey> = (20..26).map(bls).collect();

        let b1 = body(1, keys(&c2));
        let first = signers_for(None, &keys(&c1));
        assert_eq!(first, keys(&c1), "the first certificate is signed by the committee drawn at its own checkpoint");
        assert!(assemble(&b1, &bls_votes(&b1, &c1[..4]), &first).is_none(), "four of six is not two thirds");
        let cert1 = assemble(&b1, &bls_votes(&b1, &c1[..5]), &first).unwrap();

        let b2 = body(2, keys(&c3));
        let committee2 = signers_for(Some(&cert1), &keys(&c1));
        assert_eq!(committee2, keys(&c2), "after that, each certificate names who signs the next");
        let cert2 = assemble(&b2, &bls_votes(&b2, &c2[..5]), &committee2).unwrap();
        assert!(assemble(&b2, &bls_votes(&b2, &c3), &committee2).is_none(), "the next committee cannot sign early");

        let b3 = body(3, keys(&c3));
        let cert3 = assemble(&b3, &bls_votes(&b3, &c3), &signers_for(Some(&cert2), &[])).unwrap();
        let chain = vec![cert1.clone(), cert2.clone(), cert3.clone()];
        let official = vec![(1, cert1.hash())];
        assert_eq!(verify_chain(&chain, &official).unwrap().unwrap().body.index, 3);

        assert!(verify_chain(&chain, &[]).is_err(), "with nothing official there is nothing to start from");
        assert!(verify_chain(&chain, &[(1, "00".repeat(32))]).is_err(), "a first certificate that is not the official one is refused");
        assert!(verify_chain(&[cert2.clone(), cert3.clone()], &official).is_err(), "the chain must start at the official certificate");

        let attacker: Vec<blst::min_pk::SecretKey> = (40..46).map(bls).collect();
        let mut fake_body = b1.clone();
        fake_body.state_root = "bb".repeat(32);
        fake_body.next = keys(&attacker);
        let fake1 = assemble(&fake_body, &bls_votes(&fake_body, &attacker), &keys(&attacker)).unwrap();
        let fake2 = assemble(&b2, &bls_votes(&b2, &attacker), &keys(&attacker)).unwrap();
        assert!(verify_chain(&[fake1, fake2], &official).is_err(), "a made-up chain that signs itself is refused");

        let mut forged = cert2.clone();
        forged.body.state_root = "bb".repeat(32);
        assert!(verify_chain(&[cert1.clone(), forged], &official).is_err(), "a changed state root breaks the signature");
        let resigned = assemble(&b2, &bls_votes(&b2, &c1), &keys(&c1)).unwrap();
        assert!(verify_chain(&[cert1.clone(), resigned], &official).is_err(), "an old committee cannot sign once it has handed over");

        let later = vec![(2, cert2.hash())];
        assert_eq!(verify_chain(&[cert2.clone(), cert3.clone()], &later).unwrap().unwrap().body.index, 3, "the website may name a newer certificate to start from");
        let both = vec![(1, cert1.hash()), (2, cert2.hash())];
        assert!(verify_chain(&chain, &both).is_ok());
        assert!(verify_chain(&[cert1.clone()], &both).is_err(), "a chain that stops before an official certificate is refused");
        let disagree = vec![(1, cert1.hash()), (2, cert3.hash())];
        assert!(verify_chain(&chain, &disagree).is_err(), "every official certificate on the way must match");
    }

    #[test]
    fn only_well_formed_published_certificates_are_used() {
        let h = "ab".repeat(32);
        let built_in = vec![
            (1u64, "cda691751e0b56e24ef1706b3af4e149c0a51f90c996d47b9fc4b85b7b2c200c".to_string()),
            (2u64, "cffc024048f1b24c2a3dcdb61f9cf763b38ef1f5c5d1548de3b550998ef50785".to_string()),
        ];
        assert_eq!(anchors_with(None), built_in, "this release names checkpoints 1 and 2 itself");
        assert_eq!(anchors_with(Some((4, h.clone()))), vec![built_in[0].clone(), built_in[1].clone(), (4, h.clone())]);
        assert_eq!(anchors_with(Some((1, "cda691751e0b56e24ef1706b3af4e149c0a51f90c996d47b9fc4b85b7b2c200c".into()))), built_in, "the website naming the same one adds nothing");
        assert_eq!(anchors_with(Some((0, h.clone()))), built_in);
        assert_eq!(anchors_with(Some((4, "AB".repeat(32)))), built_in);
        assert_eq!(anchors_with(Some((4, "ab".repeat(31)))), built_in);
        assert!(STATE_CERT_ANCHORS.iter().all(|(_, h)| is_anchor_hash(h)));
    }

    #[test]
    fn a_block_may_carry_only_the_certificate_the_open_checkpoint_asked_for() {
        let c1: Vec<blst::min_pk::SecretKey> = (1..5).map(bls).collect();
        let from = STATE_CERT_FROM_HEIGHT;
        let blk = |h: u64, ts: i64| LedgerBlock { height: h, timestamp: ts, hash: format!("{h:064x}"), ..LedgerBlock::default() };
        let mut ov = Ov::memory();
        apply_block(&mut ov, &blk(from, 10), &[], "s");
        let mut open = load_open(&ov).unwrap();
        open.next = keys(&c1);
        ov.put(KEY_OPEN.to_vec(), serde_json::to_vec(&open).unwrap());
        ov.commit_memory();
        assert_eq!(signers_of(&ov, 1, from + 1), keys(&c1));
        let body = CertBody { index: 1, height: open.height, block_hash: open.block_hash.clone(), state_root: "aa".repeat(32), state_chunks: 2, next: open.next.clone(), ..CertBody::default() };
        let signed = |b: &CertBody| assemble(b, &bls_votes(b, &c1), &keys(&c1)).unwrap();
        let tx_of = |c: &StateCert, h: u64| crate::drs::batch_tx(TX_STATE_CERT, h, 20, serde_json::to_string(c).unwrap());
        let cert = signed(&body);
        let next = blk(from + 1, 20);
        assert!(validate(&ov, &next, &[tx_of(&cert, from + 1)]).is_ok());
        let mut moved = body.clone();
        moved.height += 1;
        assert!(validate(&ov, &next, &[tx_of(&signed(&moved), from + 1)]).is_err(), "a certificate for another block is refused");
        let mut later = body.clone();
        later.index = 2;
        assert!(validate(&ov, &next, &[tx_of(&signed(&later), from + 1)]).is_err(), "a certificate out of turn is refused");
        assert!(validate(&ov, &next, &[tx_of(&cert, from + 1), tx_of(&cert, from + 1)]).is_err());
        let mut tampered = tx_of(&cert, from + 1);
        tampered.hash = "0x00".into();
        assert!(validate(&ov, &next, &[tampered]).is_err());
        assert!(assemble(&body, &bls_votes(&body, &c1[..2]), &keys(&c1)).is_none(), "two of four is not enough");
        let outsiders: Vec<blst::min_pk::SecretKey> = (30..34).map(bls).collect();
        let by_outsiders = assemble(&body, &bls_votes(&body, &outsiders), &keys(&outsiders)).unwrap();
        assert!(validate(&ov, &next, &[tx_of(&by_outsiders, from + 1)]).is_err(), "only the drawn committee can sign");
        let mut forged = cert.clone();
        forged.signers.truncate(2);
        assert!(validate(&ov, &next, &[tx_of(&forged, from + 1)]).is_err(), "too few signatures is refused");
        let early = blk(from - 1, 5);
        assert!(validate(&Ov::memory(), &early, &[tx_of(&cert, from - 1)]).is_err(), "no certificates before the rules start");
        let ctx = tx_of(&cert, from + 1);
        apply_block(&mut ov, &next, &[&ctx], "s");
        ov.commit_memory();
        assert!(validate(&ov, &blk(from + 2, 30), &[tx_of(&cert, from + 2)]).is_err(), "a certificate lands once");
        apply_block(&mut ov, &blk(from + 3, DAY_SECS + 40), &[], "s");
        ov.commit_memory();
        let reopened = load_open(&ov).unwrap();
        assert_eq!((reopened.index, reopened.next.clone()), (2, keys(&c1)), "with nobody to draw, the last committee carries on");
        assert_eq!(signers_of(&ov, 2, from + 4), keys(&c1));
    }

    fn answering_network(ov: &mut Ov, height: u64, ready: &[usize]) -> Vec<String> {
        let epoch = crate::drs::epoch_of(height);
        let members: Vec<String> = (0..6).map(|i| format!("egot1cert{i}")).collect();
        crate::drs::seed_rota_for_tests(ov, epoch, &members, ready);
        let mut pops = Vec::new();
        for (i, m) in members.iter().enumerate() {
            let pop = hex::encode(crate::bls_agg::bls_pubkey(&bls(60 + i as u8)));
            crate::drs::seed_pop_key_for_tests(ov, m, &pop);
            pops.push(pop);
        }
        ov.commit_memory();
        ready.iter().map(|i| pops[*i].clone()).collect()
    }

    #[test]
    fn an_unsigned_checkpoint_is_redrawn_from_the_nodes_that_answer() {
        let blk = |h: u64, ts: i64| LedgerBlock { height: h, timestamp: ts, hash: format!("{h:064x}"), ..LedgerBlock::default() };
        let mut ov = Ov::memory();
        let before = CERT_DRAW_V2_FROM_HEIGHT - 50;
        apply_block(&mut ov, &blk(before, 10), &[], "s");
        ov.commit_memory();
        let old = load_open(&ov).unwrap();
        assert_eq!(old.first_height, 0, "before the new rules a checkpoint is written exactly as before");
        assert!(!serde_json::to_string(&old).unwrap().contains("first_height"));

        let answering = answering_network(&mut ov, CERT_DRAW_V2_FROM_HEIGHT, &[1, 2, 4]);
        assert!(!apply_block(&mut ov, &blk(CERT_DRAW_V2_FROM_HEIGHT - 1, 20), &[], "s"), "same day, still the old rules: nothing moves");
        assert!(apply_block(&mut ov, &blk(CERT_DRAW_V2_FROM_HEIGHT, 30), &[], "s"), "the new rules redraw a waiting checkpoint at once");
        ov.commit_memory();
        let redrawn = load_open(&ov).unwrap();
        assert_eq!((redrawn.index, redrawn.height), (1, CERT_DRAW_V2_FROM_HEIGHT));
        assert_eq!(redrawn.next, answering, "only nodes that are ready and answering are asked to sign");
        assert_eq!(redrawn.first_height, before, "the checkpoint remembers when it first opened");
        assert_eq!(signers_of(&ov, 1, CERT_DRAW_V2_FROM_HEIGHT + 1), answering);

        assert!(!apply_block(&mut ov, &blk(CERT_DRAW_V2_FROM_HEIGHT + CERT_RETRY_BLOCKS - 1, 40), &[], "s"));
        assert!(apply_block(&mut ov, &blk(CERT_DRAW_V2_FROM_HEIGHT + CERT_RETRY_BLOCKS, 50), &[], "s"), "still unsigned after the retry interval: draw again");
        ov.commit_memory();
        assert_eq!(load_open(&ov).unwrap().first_height, before);
    }

    #[test]
    fn a_checkpoint_whose_signers_are_gone_can_be_signed_by_its_own_draw_after_a_long_wait() {
        let mut ov = Ov::memory();
        let gone: Vec<blst::min_pk::SecretKey> = (70..74).map(bls).collect();
        let cert1 = StateCert { body: body(1, keys(&gone)), ..StateCert::default() };
        ov.put(cert_key(1), serde_json::to_vec(&cert1).unwrap());
        ov.put(KEY_LAST.to_vec(), 1u64.to_le_bytes().to_vec());
        let here: Vec<blst::min_pk::SecretKey> = (80..84).map(bls).collect();
        let first = CERT_DRAW_V2_FROM_HEIGHT + 10;
        let open = OpenCheckpoint { index: 2, height: first + 600, block_hash: "ab".repeat(32), next: keys(&here), first_height: first };
        ov.put(KEY_OPEN.to_vec(), serde_json::to_vec(&open).unwrap());
        ov.commit_memory();
        assert_eq!(signers_of(&ov, 2, first + CERT_FALLBACK_BLOCKS - 1), keys(&gone), "until the wait is over the named committee must sign");
        assert_eq!(signers_of(&ov, 2, first + CERT_FALLBACK_BLOCKS), keys(&here), "after it, the checkpoint's own draw may");
    }

    #[test]
    fn a_new_node_trusts_an_official_certificate_even_when_its_signers_changed() {
        let c1: Vec<blst::min_pk::SecretKey> = (1..5).map(bls).collect();
        let c2: Vec<blst::min_pk::SecretKey> = (10..14).map(bls).collect();
        let fresh: Vec<blst::min_pk::SecretKey> = (20..24).map(bls).collect();
        let b1 = body(1, keys(&c2));
        let cert1 = assemble(&b1, &bls_votes(&b1, &c1), &keys(&c1)).unwrap();
        let b2 = body(2, keys(&fresh));
        let by_own_draw = assemble(&b2, &bls_votes(&b2, &fresh), &keys(&fresh)).unwrap();
        assert!(verify_chain(&[cert1.clone(), by_own_draw.clone()], &[(1, cert1.hash())]).is_err(), "without the website naming it, a certificate signed by others is refused");
        let both = vec![(1, cert1.hash()), (2, by_own_draw.hash())];
        assert_eq!(verify_chain(&[cert1, by_own_draw], &both).unwrap().unwrap().body.index, 2, "once it is official it is taken on the website's word");
    }

    #[test]
    fn only_shared_chain_state_is_fingerprinted() {
        for k in [&b"nonce:egot1x"[..], b"n2rec:egot1x", b"shielded:state", b"market:o:1", b"latest_height", b"sc:open", b"bhf", b"escrow_relc:d:a"] {
            assert!(is_state_meta(k), "{}", String::from_utf8_lossy(k));
        }
        for k in [&b"n2migrated"[..], b"pvotes:1", b"faucet_drops:egot1x", b"proof:a:b:1", b"finalized_height", b"tx_count", b"hu:0001", b"hpr:1", b"validator_ed25519:x", b"contract_exec_height", b"pin_lockout"] {
            assert!(!is_state_meta(k), "{}", String::from_utf8_lossy(k));
        }
    }

    #[test]
    fn a_new_day_opens_a_checkpoint_and_a_late_one_moves_it() {
        let mut ov = Ov::memory();
        let blk = |h: u64, ts: i64| LedgerBlock { height: h, timestamp: ts, hash: format!("{h:064x}"), ..LedgerBlock::default() };
        let from = STATE_CERT_FROM_HEIGHT;
        assert!(!apply_block(&mut ov, &blk(from - 1, 0), &[], "s"));
        assert!(apply_block(&mut ov, &blk(from, 10), &[], "s"), "the first block under the rules opens checkpoint 1");
        ov.commit_memory();
        assert_eq!(load_open(&ov).unwrap().index, 1);
        assert!(!apply_block(&mut ov, &blk(from + 1, 20), &[], "s"), "the same day opens nothing");
        assert!(apply_block(&mut ov, &blk(from + 2, DAY_SECS + 5), &[], "s"));
        ov.commit_memory();
        let open = load_open(&ov).unwrap();
        assert_eq!((open.index, open.height), (1, from + 2), "an unsigned checkpoint moves to the newest day");
        let cert = StateCert { body: CertBody { index: 1, height: open.height, block_hash: open.block_hash.clone(), ..CertBody::default() }, ..StateCert::default() };
        let tx = LedgerTx { tx_type: TX_STATE_CERT.into(), call_args: serde_json::to_string(&cert).unwrap(), ..LedgerTx::default() };
        assert!(apply_block(&mut ov, &blk(from + 3, 2 * DAY_SECS), &[&tx], "s"));
        ov.commit_memory();
        assert_eq!(last_index(&ov), 1);
        assert_eq!(load_open(&ov).unwrap().index, 2, "after a certificate lands the next day opens the next one");
    }
}
