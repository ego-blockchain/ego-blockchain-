//! RocksDB-backed chain storage — production-grade, designed for millions of blocks/txs.
//!
//! Column families
//! ───────────────
//!   blocks     key: height (8 B big-endian u64)           value: bincode(LedgerBlock)
//!   txs        key: tx_hash (hex string bytes)            value: bincode(LedgerTx)
//!   block_txs  key: height_be8 ++ tx_hash                value: [] (block→tx index)
//!   addr_txs   key: addr ++ ts_be8 ++ tx_hash            value: i64_le8 signed amount delta
//!   balances   key: address bytes                         value: u64_le8 cached balance
//!   recent_txs key: ts_be8 ++ tx_hash                    value: [] (global recency index)
//!   meta       key: string bytes                          value: raw bytes
//!
//! Balance invariant
//! ─────────────────
//! balances[addr] == Σ confirmed_incoming − Σ confirmed_outgoing at all times.
//! Updated atomically in every WriteBatch that writes transactions.
//!
//! Migration
//! ─────────
//! On first boot (RocksDB dir missing or empty):
//!   1. Import from chain.db (SQLite) if present.
//!   2. Import from chain.json if present.
//!   3. Seed genesis block.

use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, DBCompressionType, Options,
    WriteBatch, DB,
};
use std::sync::{Mutex, OnceLock};

use crate::ledger::{
    base_data_dir, LedgerBlock, LedgerTx, SharedChain, GENESIS_HASH, GENESIS_MINER, GENESIS_TS,
};

// ── Column family names ───────────────────────────────────────────────────────

const CF_BLOCKS:     &str = "blocks";
const CF_TXS:        &str = "txs";
const CF_BLOCK_TXS:  &str = "block_txs";
const CF_ADDR_TXS:   &str = "addr_txs";
const CF_BALANCES:   &str = "balances";
const CF_RECENT_TXS: &str = "recent_txs";
const CF_META:       &str = "meta";

const ALL_CFS: &[&str] = &[
    CF_BLOCKS, CF_TXS, CF_BLOCK_TXS, CF_ADDR_TXS, CF_BALANCES, CF_RECENT_TXS, CF_META,
];

// ── Bincode config ────────────────────────────────────────────────────────────

fn bc() -> impl bincode::config::Config { bincode::config::standard() }

fn encode<T: serde::Serialize>(val: &T) -> Vec<u8> {
    bincode::serde::encode_to_vec(val, bc()).expect("bincode encode")
}

fn decode<T: for<'de> serde::Deserialize<'de>>(bytes: &[u8]) -> Option<T> {
    bincode::serde::decode_from_slice(bytes, bc()).ok().map(|(v, _)| v)
}

// ── Key helpers ───────────────────────────────────────────────────────────────

#[inline] fn height_key(h: u64)  -> [u8; 8] { h.to_be_bytes() }
#[inline] fn ts_key(ts: i64)     -> [u8; 8] { (ts as u64).to_be_bytes() }
#[inline] fn u64_le(v: u64)      -> [u8; 8] { v.to_le_bytes() }
#[inline] fn read_u64_le(b: &[u8]) -> u64   { u64::from_le_bytes(b.try_into().unwrap_or([0u8; 8])) }
#[inline] fn read_i64_le(b: &[u8]) -> i64   { i64::from_le_bytes(b.try_into().unwrap_or([0u8; 8])) }

fn block_txs_key(height: u64, tx_hash: &str) -> Vec<u8> {
    let mut k = height_key(height).to_vec();
    k.extend_from_slice(tx_hash.as_bytes());
    k
}

fn addr_txs_key(addr: &str, ts: i64, tx_hash: &str) -> Vec<u8> {
    let mut k = addr.as_bytes().to_vec();
    k.extend_from_slice(&ts_key(ts));
    k.extend_from_slice(tx_hash.as_bytes());
    k
}

fn recent_txs_key(ts: i64, tx_hash: &str) -> Vec<u8> {
    let mut k = ts_key(ts).to_vec();
    k.extend_from_slice(tx_hash.as_bytes());
    k
}

// ── Meta keys ─────────────────────────────────────────────────────────────────

const META_LATEST_HEIGHT:   &[u8] = b"latest_height";
const META_TX_COUNT:        &[u8] = b"tx_count";
const META_FINALIZED:       &[u8] = b"finalized_height";
const META_MIGRATION_DONE:  &[u8] = b"migration_done";

// ── Global DB handle ──────────────────────────────────────────────────────────

static CHAIN_DB: OnceLock<Mutex<DB>> = OnceLock::new();

pub fn get_db() -> &'static Mutex<DB> {
    CHAIN_DB.get_or_init(|| {
        let db_path = base_data_dir().join("chain_rocksdb");

        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        db_opts.set_write_buffer_size(64 * 1024 * 1024);       // 64 MB memtable
        db_opts.set_max_write_buffer_number(3);
        db_opts.set_max_background_jobs(4);
        db_opts.set_compression_type(DBCompressionType::Lz4);
        db_opts.set_bottommost_compression_type(DBCompressionType::Lz4);

        // Shared 128 MB block cache across all CFs with bloom filters.
        let block_cache = Cache::new_lru_cache(128 * 1024 * 1024);

        let cf_descs: Vec<ColumnFamilyDescriptor> = ALL_CFS.iter().map(|name| {
            let mut cf_opts = Options::default();
            cf_opts.set_compression_type(DBCompressionType::Lz4);

            // Bloom filter + cache on point-get heavy CFs.
            if [CF_BLOCKS, CF_TXS, CF_BALANCES].contains(name) {
                let mut bbo = BlockBasedOptions::default();
                bbo.set_block_cache(&block_cache);
                bbo.set_bloom_filter(10.0, false);
                bbo.set_cache_index_and_filter_blocks(true);
                bbo.set_pin_l0_filter_and_index_blocks_in_cache(true);
                cf_opts.set_block_based_table_factory(&bbo);
            }

            ColumnFamilyDescriptor::new(*name, cf_opts)
        }).collect();

        let db = DB::open_cf_descriptors(&db_opts, &db_path, cf_descs)
            .expect("open RocksDB chain store");

        init_db(&db);
        Mutex::new(db)
    })
}

// ── Initialise / migrate ──────────────────────────────────────────────────────

fn init_db(db: &DB) {
    let meta = db.cf_handle(CF_META).unwrap();

    // Already migrated?
    if db.get_cf(meta, META_MIGRATION_DONE).ok().flatten().is_some() {
        return;
    }

    // 1. Try SQLite chain.db.
    let sqlite_path = base_data_dir().join("chain.db");
    if sqlite_path.exists() {
        if migrate_from_sqlite(db, &sqlite_path) {
            db.put_cf(meta, META_MIGRATION_DONE, b"1").ok();
            eprintln!("[ChainDB] Migrated from SQLite → RocksDB");
            return;
        }
    }

    // 2. Try chain.json.
    let json_path = base_data_dir().join("chain.json");
    if json_path.exists() {
        if migrate_from_json(db, &json_path) {
            db.put_cf(meta, META_MIGRATION_DONE, b"1").ok();
            eprintln!("[ChainDB] Migrated from chain.json → RocksDB");
            return;
        }
    }

    // 3. Seed genesis.
    seed_genesis(db);
    db.put_cf(meta, META_MIGRATION_DONE, b"1").ok();
    eprintln!("[ChainDB] Seeded genesis block");
}

fn seed_genesis(db: &DB) {
    let genesis = LedgerBlock {
        height:     0,
        hash:       GENESIS_HASH.to_string(),
        prev_hash:  "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        miner:      GENESIS_MINER.to_string(),
        timestamp:  GENESIS_TS,
        tx_count:   0,
        size_bytes: 0,
        reward:     0,
        coinbase_tx: None,
    };
    write_block_batch(db, &genesis, &[]);
}

fn migrate_from_sqlite(db: &DB, path: &std::path::Path) -> bool {
    use rusqlite::{Connection, params};
    let conn = match Connection::open(path) {
        Ok(c) => c,
        Err(e) => { eprintln!("[ChainDB] SQLite open failed: {}", e); return false; }
    };

    // Read blocks ordered by height.
    let mut stmt = match conn.prepare(
        "SELECT height,hash,prev_hash,miner,timestamp,tx_count,size_bytes,reward,coinbase_tx \
         FROM blocks ORDER BY height ASC"
    ) {
        Ok(s) => s,
        Err(e) => { eprintln!("[ChainDB] SQLite read failed: {}", e); return false; }
    };
    let blocks: Vec<LedgerBlock> = stmt.query_map([], |r| {
        Ok(LedgerBlock {
            height:     r.get::<_, i64>(0)? as u64,
            hash:       r.get(1)?,
            prev_hash:  r.get(2)?,
            miner:      r.get(3)?,
            timestamp:  r.get::<_, i64>(4)?,
            tx_count:   r.get::<_, i64>(5)? as u32,
            size_bytes: r.get::<_, i64>(6)? as u64,
            reward:     r.get::<_, i64>(7)? as u64,
            coinbase_tx: r.get(8)?,
        })
    }).unwrap().filter_map(|r| r.ok()).collect();

    let mut stmt2 = match conn.prepare(
        "SELECT hash,block_height,from_addr,to_addr,amount,memo,timestamp,\
                signature,status,nonce,pub_key_ed,dil_pubkey,dil_sig,\
                tx_type,wasm_code,contract_addr,entrypoint,call_args \
         FROM transactions ORDER BY timestamp ASC"
    ) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let txs: Vec<LedgerTx> = stmt2.query_map([], |r| {
        Ok(LedgerTx {
            hash:                r.get(0)?,
            block_height:        r.get::<_, Option<i64>>(1)?.map(|h| h as u64),
            from:                r.get(2)?,
            to:                  r.get(3)?,
            amount:              r.get::<_, i64>(4)? as u64,
            memo:                r.get(5)?,
            timestamp:           r.get(6)?,
            signature:           r.get(7)?,
            status:              r.get(8)?,
            nonce:               r.get::<_, i64>(9)? as u64,
            public_key_ed25519:  r.get(10)?,
            dilithium_pubkey:    r.get(11)?,
            dilithium_signature: r.get(12)?,
            tx_type:             r.get(13)?,
            wasm_code:           r.get(14)?,
            contract_addr:       r.get(15)?,
            entrypoint:          r.get(16)?,
            call_args:           r.get(17)?,
            fee_uegoc:           0,
        })
    }).unwrap().filter_map(|r| r.ok()).collect();

    // Group txs by block height.
    let mut by_height: std::collections::HashMap<u64, Vec<LedgerTx>> = Default::default();
    for tx in txs {
        by_height.entry(tx.block_height.unwrap_or(0)).or_default().push(tx);
    }

    for block in &blocks {
        let block_txs = by_height.remove(&block.height).unwrap_or_default();
        write_block_batch(db, block, &block_txs);
    }
    true
}

fn migrate_from_json(db: &DB, path: &std::path::Path) -> bool {
    let data = match std::fs::read_to_string(path) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let chain: SharedChain = match serde_json::from_str(&data) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let mut blocks = chain.blocks.clone();
    blocks.sort_by_key(|b| b.height);

    let mut by_height: std::collections::HashMap<u64, Vec<LedgerTx>> = Default::default();
    for tx in chain.transactions {
        by_height.entry(tx.block_height.unwrap_or(0)).or_default().push(tx);
    }

    for block in &blocks {
        let block_txs = by_height.remove(&block.height).unwrap_or_default();
        write_block_batch(db, block, &block_txs);
    }
    true
}

// ── Core write primitive ──────────────────────────────────────────────────────

const FAUCET_ADDR: &str = "egot1faucet000000000000000000000000000000000";

/// Atomically writes one block + its transactions into all column families.
/// Maintains balance cache and all secondary indices.
/// INSERT-OR-IGNORE semantics: skips existing blocks/txs.
fn write_block_batch(db: &DB, block: &LedgerBlock, txs: &[LedgerTx]) {
    let cf_blocks     = db.cf_handle(CF_BLOCKS).unwrap();
    let cf_txs        = db.cf_handle(CF_TXS).unwrap();
    let cf_block_txs  = db.cf_handle(CF_BLOCK_TXS).unwrap();
    let cf_addr_txs   = db.cf_handle(CF_ADDR_TXS).unwrap();
    let cf_balances   = db.cf_handle(CF_BALANCES).unwrap();
    let cf_recent_txs = db.cf_handle(CF_RECENT_TXS).unwrap();
    let cf_meta       = db.cf_handle(CF_META).unwrap();

    let height_k = height_key(block.height);

    // Skip if block already exists.
    if db.get_cf(cf_blocks, height_k).ok().flatten().is_some() {
        return;
    }

    // Pre-read balances for all addresses involved (read-before-batch).
    let mut balance_delta: std::collections::HashMap<String, i128> = Default::default();
    let mut new_tx_count: u64 = 0;

    let confirmed_txs: Vec<&LedgerTx> = txs.iter()
        .filter(|tx| tx.status == "Confirmed" || tx.status.is_empty())
        .collect();

    for tx in &confirmed_txs {
        // Skip if tx already exists.
        if db.get_cf(cf_txs, tx.hash.as_bytes()).ok().flatten().is_some() {
            continue;
        }
        *balance_delta.entry(tx.to.clone()).or_insert(0) += tx.amount as i128;
        if tx.from != FAUCET_ADDR && !tx.from.is_empty() {
            *balance_delta.entry(tx.from.clone()).or_insert(0) -= tx.amount as i128;
        }
        new_tx_count += 1;
    }

    // Read current balances for affected addresses.
    let mut new_balances: std::collections::HashMap<String, u64> = Default::default();
    for addr in balance_delta.keys() {
        let cur = db.get_cf(cf_balances, addr.as_bytes())
            .ok().flatten()
            .map(|v| read_u64_le(&v))
            .unwrap_or(0);
        new_balances.insert(addr.clone(), cur);
    }
    for (addr, delta) in &balance_delta {
        let cur = *new_balances.get(addr).unwrap_or(&0) as i128;
        new_balances.insert(addr.clone(), (cur + delta).max(0) as u64);
    }

    // Build atomic WriteBatch.
    let mut batch = WriteBatch::default();

    // Block record.
    batch.put_cf(cf_blocks, height_k, encode(block));

    // Transactions + all secondary indices.
    for tx in &confirmed_txs {
        if db.get_cf(cf_txs, tx.hash.as_bytes()).ok().flatten().is_some() {
            continue; // already exists
        }
        batch.put_cf(cf_txs,        tx.hash.as_bytes(), encode(tx));
        batch.put_cf(cf_block_txs,  block_txs_key(block.height, &tx.hash), b"");
        batch.put_cf(cf_recent_txs, recent_txs_key(tx.timestamp, &tx.hash), b"");
        // Per-address history with signed delta.
        let incoming_k = addr_txs_key(&tx.to, tx.timestamp, &tx.hash);
        batch.put_cf(cf_addr_txs, incoming_k, (tx.amount as i64).to_le_bytes());
        if tx.from != FAUCET_ADDR && !tx.from.is_empty() {
            let outgoing_k = addr_txs_key(&tx.from, tx.timestamp, &tx.hash);
            batch.put_cf(cf_addr_txs, outgoing_k, (-(tx.amount as i64)).to_le_bytes());
        }
    }

    // Balance cache.
    for (addr, bal) in &new_balances {
        batch.put_cf(cf_balances, addr.as_bytes(), u64_le(*bal));
    }

    // Meta: latest_height and tx_count.
    let cur_height = db.get_cf(cf_meta, META_LATEST_HEIGHT)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
    if block.height > cur_height {
        batch.put_cf(cf_meta, META_LATEST_HEIGHT, u64_le(block.height));
    }
    let cur_tx_count = db.get_cf(cf_meta, META_TX_COUNT)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
    batch.put_cf(cf_meta, META_TX_COUNT, u64_le(cur_tx_count + new_tx_count));

    db.write(batch).expect("RocksDB write batch");
}

// ── Public read API ───────────────────────────────────────────────────────────

pub fn latest_block_info() -> (u64, String) {
    let db = get_db().lock().unwrap();
    let cf_meta = db.cf_handle(CF_META).unwrap();
    let height = db.get_cf(cf_meta, META_LATEST_HEIGHT)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
    let cf_blocks = db.cf_handle(CF_BLOCKS).unwrap();
    let hash = db.get_cf(cf_blocks, height_key(height))
        .ok().flatten()
        .and_then(|v| decode::<LedgerBlock>(&v))
        .map(|b| b.hash)
        .unwrap_or_else(|| GENESIS_HASH.to_string());
    (height, hash)
}

pub fn block_count() -> u64 {
    let db = get_db().lock().unwrap();
    let cf_meta = db.cf_handle(CF_META).unwrap();
    let height = db.get_cf(cf_meta, META_LATEST_HEIGHT)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
    height + 1
}

pub fn tx_count() -> u64 {
    let db = get_db().lock().unwrap();
    let cf_meta = db.cf_handle(CF_META).unwrap();
    db.get_cf(cf_meta, META_TX_COUNT)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0)
}

/// O(1) balance lookup via cached balances CF.
pub fn balance_of(address: &str) -> u64 {
    let db = get_db().lock().unwrap();
    let cf = db.cf_handle(CF_BALANCES).unwrap();
    db.get_cf(cf, address.as_bytes())
        .ok().flatten()
        .map(|v| read_u64_le(&v))
        .unwrap_or(0)
}

pub fn recent_blocks(limit: usize) -> Vec<LedgerBlock> {
    let db = get_db().lock().unwrap();
    let cf = db.cf_handle(CF_BLOCKS).unwrap();
    let mut iter = db.raw_iterator_cf(cf);
    iter.seek_to_last();
    let mut out = Vec::with_capacity(limit);
    while iter.valid() && out.len() < limit {
        if let Some(v) = iter.value() {
            if let Some(b) = decode::<LedgerBlock>(v) {
                out.push(b);
            }
        }
        iter.prev();
    }
    out
}

pub fn recent_transactions(limit: usize) -> Vec<LedgerTx> {
    let db = get_db().lock().unwrap();
    let cf_recent = db.cf_handle(CF_RECENT_TXS).unwrap();
    let cf_txs    = db.cf_handle(CF_TXS).unwrap();
    let mut iter = db.raw_iterator_cf(cf_recent);
    iter.seek_to_last();
    let mut hashes: Vec<Vec<u8>> = Vec::with_capacity(limit);
    while iter.valid() && hashes.len() < limit {
        if let Some(k) = iter.key() {
            // Key = ts_be8 ++ tx_hash; tx_hash starts at byte 8.
            if k.len() > 8 { hashes.push(k[8..].to_vec()); }
        }
        iter.prev();
    }
    hashes.iter()
        .filter_map(|h| {
            db.get_cf(cf_txs, h).ok().flatten()
                .and_then(|v| decode::<LedgerTx>(&v))
        })
        .collect()
}

/// View of the last 2000 blocks/txs, for legacy callers that use SharedChain.
pub fn load_shared_chain() -> SharedChain {
    SharedChain {
        blocks:       recent_blocks(2000),
        transactions: recent_transactions(2000),
    }
}

// ── Direct lookup helpers (new, additive) ─────────────────────────────────────

pub fn get_block_by_height(height: u64) -> Option<LedgerBlock> {
    let db = get_db().lock().unwrap();
    let cf = db.cf_handle(CF_BLOCKS).unwrap();
    db.get_cf(cf, height_key(height)).ok().flatten()
        .and_then(|v| decode(&v))
}

pub fn get_tx_by_hash(hash: &str) -> Option<LedgerTx> {
    let db = get_db().lock().unwrap();
    let cf = db.cf_handle(CF_TXS).unwrap();
    db.get_cf(cf, hash.as_bytes()).ok().flatten()
        .and_then(|v| decode(&v))
}

/// Full transaction history for an address, ordered by timestamp ascending.
pub fn get_tx_history_for_addr(address: &str) -> Vec<LedgerTx> {
    let db = get_db().lock().unwrap();
    let cf_addr = db.cf_handle(CF_ADDR_TXS).unwrap();
    let cf_txs  = db.cf_handle(CF_TXS).unwrap();

    let prefix = address.as_bytes();
    let iter = db.prefix_iterator_cf(cf_addr, prefix);
    let mut hashes: Vec<Vec<u8>> = Vec::new();

    for item in iter {
        let (k, _) = item.expect("RocksDB iter");
        if !k.starts_with(prefix) { break; }
        // Key = addr ++ ts_be8 ++ tx_hash; tx_hash starts after addr+8.
        let hash_start = prefix.len() + 8;
        if k.len() > hash_start {
            hashes.push(k[hash_start..].to_vec());
        }
    }

    hashes.iter()
        .filter_map(|h| {
            db.get_cf(cf_txs, h).ok().flatten()
                .and_then(|v| decode::<LedgerTx>(&v))
        })
        .collect()
}

// ── Public write API ──────────────────────────────────────────────────────────

/// Mine a new block directly into RocksDB. O(1) per block, no chain.json.
pub fn mine_batch_db(txs: &[LedgerTx], miner: &str) -> LedgerBlock {
    let db = get_db().lock().unwrap();

    let (latest_height, prev_hash) = {
        let cf_meta = db.cf_handle(CF_META).unwrap();
        let h = db.get_cf(cf_meta, META_LATEST_HEIGHT)
            .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
        let cf_blocks = db.cf_handle(CF_BLOCKS).unwrap();
        let hash = db.get_cf(cf_blocks, height_key(h))
            .ok().flatten()
            .and_then(|v| decode::<LedgerBlock>(&v))
            .map(|b| b.hash)
            .unwrap_or_else(|| GENESIS_HASH.to_string());
        (h, hash)
    };

    let height    = latest_height + 1;
    let timestamp = chrono::Utc::now().timestamp();
    let reward    = crate::tokenomics::block_reward_at(height);
    let hash_input = format!("{prev_hash}{height}{miner}{timestamp}");
    let hash = blake3::hash(hash_input.as_bytes()).to_hex().to_string();

    // Stamp block_height on each tx before writing.
    let stamped: Vec<LedgerTx> = txs.iter().map(|tx| {
        let mut t = tx.clone();
        t.block_height = Some(height);
        t.status = "Confirmed".to_string();
        t
    }).collect();

    let block = LedgerBlock {
        height,
        hash,
        prev_hash,
        miner: miner.to_string(),
        timestamp,
        tx_count:   txs.len() as u32,
        size_bytes: txs.len() as u64 * 256,
        reward,
        coinbase_tx: None,
    };

    write_block_batch(&db, &block, &stamped);
    block
}

/// Append a block received from a peer (gossip / sync path).
/// INSERT-OR-IGNORE: silently skips if block or tx already exists.
pub fn append_peer_block(block: &LedgerBlock, txs: &[LedgerTx]) {
    let db = get_db().lock().unwrap();
    write_block_batch(&db, block, txs);
}

// ── BFT finality ──────────────────────────────────────────────────────────────

/// Record the highest finalized block height in meta.
/// In pipelined HotStuff, block N is finalized when block N+2 is committed.
pub fn pipeline_commit(commit_height: u64) {
    if commit_height < 2 { return; }
    let finalized = commit_height - 2;
    let db = get_db().lock().unwrap();
    let cf = db.cf_handle(CF_META).unwrap();
    let cur = db.get_cf(cf, META_FINALIZED)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
    if finalized > cur {
        db.put_cf(cf, META_FINALIZED, u64_le(finalized)).ok();
    }
}

/// Returns the highest finalized block height.
pub fn finalized_height() -> u64 {
    let db = get_db().lock().unwrap();
    let cf = db.cf_handle(CF_META).unwrap();
    db.get_cf(cf, META_FINALIZED)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0)
}

// ── Kept for API compatibility ────────────────────────────────────────────────

/// No-op: DB handle is a global singleton, not caller-managed.
#[allow(dead_code)]
pub fn get_db_handle() -> &'static Mutex<DB> { get_db() }
