use crate::state_cert::{self, Digest, RootBuilder, CHUNK_ENTRIES, TAG_BALANCE, TAG_CONTRACT, TAG_META};
use rocksdb::{IteratorMode, DB};
use serde::{Deserialize, Serialize};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

pub const PART_CHAIN: u8 = 0;
pub const PART_CONTRACTS: u8 = 1;
pub const TIP_BLOCKS: u64 = 320;
const KEEP_DIRS: usize = 3;
const SERVER_SHARE: u8 = 16;
pub type Entry = (u8, Vec<u8>, Vec<u8>);

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoredDigest {
    pub digest: Digest,
    pub offsets: Vec<u64>,
}

fn root_dir() -> PathBuf {
    crate::ledger::base_data_dir().join("state_certs")
}

pub fn dir_for(height: u64) -> PathBuf {
    root_dir().join(format!("{height:012}"))
}

fn names(part: u8) -> (&'static str, &'static str) {
    if part == PART_CHAIN { ("state.bin", "state.json") } else { ("contracts.bin", "contracts.json") }
}

pub fn marker_key(height: u64) -> Vec<u8> {
    format!("scp:{height:012}").into_bytes()
}

fn write_entry(w: &mut impl Write, tag: u8, k: &[u8], v: &[u8]) -> std::io::Result<u64> {
    w.write_all(&[tag])?;
    w.write_all(&(k.len() as u32).to_le_bytes())?;
    w.write_all(k)?;
    w.write_all(&(v.len() as u32).to_le_bytes())?;
    w.write_all(v)?;
    Ok(9 + k.len() as u64 + v.len() as u64)
}

fn read_entry(r: &mut impl Read) -> Option<Entry> {
    let mut tag = [0u8; 1];
    r.read_exact(&mut tag).ok()?;
    let mut len = [0u8; 4];
    r.read_exact(&mut len).ok()?;
    let mut k = vec![0u8; u32::from_le_bytes(len) as usize];
    r.read_exact(&mut k).ok()?;
    r.read_exact(&mut len).ok()?;
    let mut v = vec![0u8; u32::from_le_bytes(len) as usize];
    r.read_exact(&mut v).ok()?;
    Some((tag[0], k, v))
}

pub fn encode_entries(entries: &[Entry]) -> Vec<u8> {
    let mut out = Vec::new();
    for (t, k, v) in entries {
        let _ = write_entry(&mut out, *t, k, v);
    }
    out
}

pub fn decode_entries(bytes: &[u8]) -> Option<Vec<Entry>> {
    let mut r = std::io::Cursor::new(bytes);
    let mut out = Vec::new();
    while (r.position() as usize) < bytes.len() {
        out.push(read_entry(&mut r)?);
    }
    Some(out)
}

pub struct Writer {
    file: BufWriter<std::fs::File>,
    builder: RootBuilder,
    offsets: Vec<u64>,
    pos: u64,
    count: u64,
}

impl Writer {
    pub fn create(path: &std::path::Path) -> std::io::Result<Self> {
        Ok(Self {
            file: BufWriter::new(std::fs::File::create(path)?),
            builder: RootBuilder::default(),
            offsets: Vec::new(),
            pos: 0,
            count: 0,
        })
    }

    pub fn add(&mut self, tag: u8, k: &[u8], v: &[u8]) -> std::io::Result<()> {
        if self.count % CHUNK_ENTRIES as u64 == 0 {
            self.offsets.push(self.pos);
        }
        self.pos += write_entry(&mut self.file, tag, k, v)?;
        self.builder.add(tag, k, v);
        self.count += 1;
        Ok(())
    }

    pub fn finish(mut self) -> std::io::Result<StoredDigest> {
        self.file.flush()?;
        Ok(StoredDigest { digest: self.builder.finish(), offsets: self.offsets })
    }
}

pub trait Source {
    fn scan<'a>(&'a self, cf: &'a rocksdb::ColumnFamily) -> rocksdb::DBIteratorWithThreadMode<'a, DB>;
}

impl Source for DB {
    fn scan<'a>(&'a self, cf: &'a rocksdb::ColumnFamily) -> rocksdb::DBIteratorWithThreadMode<'a, DB> {
        self.iterator_cf(cf, IteratorMode::Start)
    }
}

impl Source for rocksdb::Snapshot<'_> {
    fn scan<'a>(&'a self, cf: &'a rocksdb::ColumnFamily) -> rocksdb::DBIteratorWithThreadMode<'a, DB> {
        self.iterator_cf(cf, IteratorMode::Start)
    }
}

fn stream(db: &'static DB, snap: &rocksdb::Snapshot<'static>, height: u64, part: u8) -> Result<StoredDigest, String> {
    write_part(db, snap, &dir_for(height), part)
}

pub fn write_part(db: &DB, src: &impl Source, dir: &std::path::Path, part: u8) -> Result<StoredDigest, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let (bin, json) = names(part);
    let tmp = dir.join(format!("{bin}.tmp"));
    let mut w = Writer::create(&tmp).map_err(|e| e.to_string())?;
    let mut put = |tag: u8, cf_name: &str, keep: &dyn Fn(&[u8]) -> bool| -> Result<(), String> {
        let cf = db.cf_handle(cf_name).ok_or_else(|| format!("{cf_name} column is missing"))?;
        for item in src.scan(cf) {
            let (k, v) = item.map_err(|e| e.to_string())?;
            if keep(&k) {
                w.add(tag, &k, &v).map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    };
    if part == PART_CHAIN {
        put(TAG_BALANCE, crate::chain_db::CF_BALANCES, &|_| true)?;
        put(TAG_META, crate::chain_db::CF_META, &state_cert::is_state_meta)?;
    } else {
        put(TAG_CONTRACT, crate::chain_db::CF_CONTRACT_STATE, &state_cert::is_state_contract)?;
    }
    let stored = w.finish().map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, dir.join(bin)).map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec(&stored).map_err(|e| e.to_string())?;
    crate::utils::atomic_write(&dir.join(json), &bytes).map_err(|e| e.to_string())?;
    Ok(stored)
}

pub fn on_checkpoint(db: &DB, height: u64) {
    if cfg!(test) {
        return;
    }
    let global = crate::chain_db::global_db();
    if !std::ptr::eq(global, db) {
        return;
    }
    if !serves_state() {
        return;
    }
    if let Some(cf) = global.cf_handle(crate::chain_db::CF_META) {
        let _ = global.put_cf(cf, marker_key(height), b"1");
    }
    capture(global, height, PART_CHAIN);
}

fn serves_state() -> bool {
    let me = crate::ledger::Ledger::load().address;
    if me.is_empty() {
        return false;
    }
    if crate::p2p::history_archive_mode(&me) {
        return true;
    }
    if let (Some(key), Some((open, signers))) = (crate::p2p::my_bls_pubkey(), crate::chain_db::state_cert_open()) {
        if signers.contains(&key) || open.next.contains(&key) {
            return true;
        }
    }
    blake3::hash(me.as_bytes()).as_bytes()[0] % SERVER_SHARE == 0
}

pub fn on_contract_commit(height: u64) {
    if cfg!(test) {
        return;
    }
    let global = crate::chain_db::global_db();
    let marked = global
        .cf_handle(crate::chain_db::CF_META)
        .and_then(|cf| global.get_cf(cf, marker_key(height)).ok().flatten())
        .is_some();
    if marked {
        capture(global, height, PART_CONTRACTS);
    }
}

pub fn capture(db: &'static DB, height: u64, part: u8) {
    let snap: rocksdb::Snapshot<'static> = db.snapshot();
    let started = std::time::Instant::now();
    let spawned = std::thread::Builder::new().name("state-capture".into()).spawn(move || {
        match stream(db, &snap, height, part) {
            Ok(d) => eprintln!(
                "[StateCert] {} at block {height} fingerprinted: {} chunks, root {:.16} ({} ms)",
                if part == PART_CHAIN { "chain state" } else { "contract state" },
                d.digest.chunks.len(),
                d.digest.root,
                started.elapsed().as_millis()
            ),
            Err(e) => eprintln!("[StateCert] could not fingerprint block {height}: {e}"),
        }
        drop(snap);
    });
    if spawned.is_err() {
        eprintln!("[StateCert] could not start the fingerprint of block {height}");
    }
    prune_dirs();
}

pub fn read_digest(height: u64, part: u8) -> Option<StoredDigest> {
    let bytes = std::fs::read(dir_for(height).join(names(part).1)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn digests(height: u64) -> Option<(StoredDigest, StoredDigest)> {
    Some((read_digest(height, PART_CHAIN)?, read_digest(height, PART_CONTRACTS)?))
}

pub fn serve_chunk(height: u64, part: u8, index: u64) -> Option<(Vec<Entry>, Vec<[u8; 32]>)> {
    serve_chunk_in(&dir_for(height), part, index)
}

pub fn read_digest_in(dir: &std::path::Path, part: u8) -> Option<StoredDigest> {
    serde_json::from_slice(&std::fs::read(dir.join(names(part).1)).ok()?).ok()
}

pub fn serve_chunk_in(dir: &std::path::Path, part: u8, index: u64) -> Option<(Vec<Entry>, Vec<[u8; 32]>)> {
    let stored = read_digest_in(dir, part)?;
    let offset = *stored.offsets.get(index as usize)?;
    let mut r = BufReader::new(std::fs::File::open(dir.join(names(part).0)).ok()?);
    r.seek(SeekFrom::Start(offset)).ok()?;
    let mut entries = Vec::with_capacity(CHUNK_ENTRIES);
    while entries.len() < CHUNK_ENTRIES {
        match read_entry(&mut r) {
            Some(e) => entries.push(e),
            None => break,
        }
    }
    let path = state_cert::merkle_path(&stored.digest.chunk_hashes(), index as usize);
    Some((entries, path))
}

fn prune_dirs() {
    let Ok(rd) = std::fs::read_dir(root_dir()) else { return };
    let certified = crate::chain_db::state_cert_last_height();
    let mut heights: Vec<u64> = rd
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str()?.parse::<u64>().ok())
        .filter(|h| Some(*h) != certified)
        .collect();
    heights.sort_unstable();
    while heights.len() > KEEP_DIRS {
        let old = heights.remove(0);
        let _ = std::fs::remove_dir_all(dir_for(old));
    }
}

pub fn staging_dir() -> PathBuf {
    crate::ledger::base_data_dir().join("state_sync_staging")
}

pub fn staged_path(part: u8, index: u64) -> PathBuf {
    staged_path_in(&staging_dir(), part, index)
}

pub fn staged_path_in(dir: &std::path::Path, part: u8, index: u64) -> PathBuf {
    dir.join(format!("{part}-{index:010}.bin"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_served_chunk_is_exactly_what_the_fingerprint_covers() {
        let dir = std::env::temp_dir().join(format!("ego-state-sync-{}-{}", std::process::id(), rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.bin");
        let mut w = Writer::create(&path).unwrap();
        let n = CHUNK_ENTRIES * 2 + 3;
        let all: Vec<Entry> = (0..n).map(|i| (TAG_META, format!("key{i:06}").into_bytes(), vec![i as u8; i % 7])).collect();
        for (t, k, v) in &all {
            w.add(*t, k, v).unwrap();
        }
        let stored = w.finish().unwrap();
        assert_eq!(stored.offsets.len(), 3);
        let root = state_cert::hex32(&stored.digest.root).unwrap();
        let hashes = stored.digest.chunk_hashes();
        let bytes = std::fs::read(&path).unwrap();
        for i in 0..3usize {
            let start = stored.offsets[i] as usize;
            let mut r = std::io::Cursor::new(&bytes[start..]);
            let mut got = Vec::new();
            while got.len() < CHUNK_ENTRIES {
                match read_entry(&mut r) {
                    Some(e) => got.push(e),
                    None => break,
                }
            }
            assert_eq!(got, all[i * CHUNK_ENTRIES..((i + 1) * CHUNK_ENTRIES).min(n)].to_vec());
            assert!(state_cert::chunk_ok(&got, i as u64, 3, &state_cert::merkle_path(&hashes, i), &root));
            assert_eq!(decode_entries(&encode_entries(&got)).unwrap(), got);
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
