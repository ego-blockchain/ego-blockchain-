use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, DBCompressionType, Options,
    WriteBatch, DB,
};
use std::sync::{Mutex, OnceLock};

use crate::ledger::{
    base_data_dir, LedgerBlock, LedgerTx, SharedChain, GENESIS_HASH, GENESIS_MINER, GENESIS_TS,
};

const CF_BLOCKS:     &str = "blocks";
const CF_TXS:        &str = "txs";
const CF_BLOCK_TXS:  &str = "block_txs";
const CF_ADDR_TXS:   &str = "addr_txs";
const CF_BALANCES:   &str = "balances";
const CF_RECENT_TXS: &str = "recent_txs";
const CF_META:       &str = "meta";
const CF_HEADERS:    &str = "headers";    // light block headers — kept longer than full blocks
const CF_GOVERNANCE: &str = "governance"; // on-chain feature flag votes
const CF_DAO:        &str = "dao";        // DAO proposals (stake + knowledge voting)

const ALL_CFS: &[&str] = &[
    CF_BLOCKS, CF_TXS, CF_BLOCK_TXS, CF_ADDR_TXS, CF_BALANCES,
    CF_RECENT_TXS, CF_META, CF_HEADERS, CF_GOVERNANCE, CF_DAO,
];

pub const FEATURE_DILITHIUM_DISABLED: &str = "dilithium_disabled";
/// Enforce ML-DSA-44 on every transaction (migration complete).
pub const FEATURE_DILITHIUM_REQUIRED: &str = "dilithium_required";


const FULL_BLOCK_CAP: u64 = 2_000;

const HEADER_CAP: u64 = 100_000;

const META_PRUNE_BELOW:         &[u8] = b"prune_below";
const META_PRUNE_HEADERS_BELOW: &[u8] = b"prune_headers_below";

fn encode<T: serde::Serialize>(val: &T) -> Vec<u8> {
    serde_json::to_vec(val).expect("json encode")
}

fn decode<T: for<'de> serde::Deserialize<'de>>(bytes: &[u8]) -> Option<T> {
    serde_json::from_slice(bytes).ok()
}

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

const META_LATEST_HEIGHT:   &[u8] = b"latest_height";
const META_TX_COUNT:        &[u8] = b"tx_count";
const META_FINALIZED:       &[u8] = b"finalized_height";
const META_MIGRATION_DONE:  &[u8] = b"migration_done";

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
            if [CF_BLOCKS, CF_TXS, CF_BALANCES, CF_HEADERS].contains(name) {
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

/// Genesis addresses for pre-minted supply pools.
/// These hold the non-circulating allocations defined in tokenomics.rs.
pub const ECOSYSTEM_ADDR:   &str = "egot1ecosystem00000000000000000000000000000000";
pub const FOUNDATION_ADDR:  &str = "egot1foundation00000000000000000000000000000000";
pub const NODE_POOL_ADDR:   &str = "egot1nodepool000000000000000000000000000000000";
pub const STAKING_POOL_ADDR:&str = "egot1stakingpool0000000000000000000000000000000";
pub const FAUCET_ADDR_FULL: &str = "egot1faucet000000000000000000000000000000000000";

fn seed_genesis(db: &DB) {
    use crate::tokenomics::*;

    // ── Genesis allocations ────────────────────────────────────────────────
    // Mint each non-circulating pool directly into the balance cache.
    // These are pre-mined at height 0 — no TXs needed, just balance records.
    let cf_balances = db.cf_handle(CF_BALANCES).unwrap();
    let mut batch = WriteBatch::default();

    let allocs: &[(&str, u64)] = &[
        (ECOSYSTEM_ADDR,    ECOSYSTEM_EGOC  * UEGOC_PER_EGOC),
        (FOUNDATION_ADDR,   FOUNDATION_EGOC * UEGOC_PER_EGOC),
        (NODE_POOL_ADDR,    NODE_POOL_UEGOC),
        (STAKING_POOL_ADDR, STAKING_POOL_UEGOC),
        // Faucet seeded with 10M EGOC for testnet distribution
        (FAUCET_ADDR_FULL,  10_000_000 * UEGOC_PER_EGOC),
    ];
    for (addr, amount) in allocs {
        batch.put_cf(cf_balances, addr.as_bytes(), u64_le(*amount));
    }
    db.write(batch).expect("genesis balance batch");

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
        vote_count: 0,
        tx_merkle_root: String::new(),
        poc_ticket: String::new(),
        poc_slot: 0,
    };
    write_block_batch(db, &genesis, &[]);

    eprintln!("[Genesis] Seeded supply pools: ecosystem={} EGOC, foundation={} EGOC, node_pool={} EGOC, staking_pool={} EGOC, faucet=10M EGOC",
        ECOSYSTEM_EGOC, FOUNDATION_EGOC, NODE_POOL_EGOC, STAKING_POOL_EGOC);
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
            vote_count: 0,
            tx_merkle_root: String::new(),
            poc_ticket: String::new(),
            poc_slot: 0,
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
            priority_fee_uegoc:  0,
            cid:                 String::new(),
            commitment_hash:     String::new(),
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

// ── Checkpoint anchors (long-range attack protection) ─────────────────────────
//
// A long-range attack: attacker obtains old private keys and rewrites history
// from block 0, building a longer chain that appears valid. Without checkpoints
// any chain with valid signatures is accepted, even one forked at genesis.
//
// Defense: hardcode well-known block hashes. Any peer-supplied chain that
// contradicts a checkpoint is rejected outright, even if its signatures are valid.
// Checkpoints are chosen at finalized, widely-gossiped heights.
//
// Add new checkpoints after each major milestone (mainnet launch, hard forks).
// A checkpoint can never be rolled back — that is the guarantee.
pub const CHECKPOINTS: &[(u64, &str)] = &[
    // (height, expected_block_hash)
    // Genesis is always checkpoint 0 — immovable anchor.
    (0, "ego00000000000000000000000000000000000000000000000000000000genesis1"),
    // Add production checkpoints here as the chain grows, e.g.:
    // (100_000, "abc123..."),
    // (500_000, "def456..."),
];

/// Returns Err if `block` contradicts a known checkpoint.
pub fn check_checkpoint(block: &LedgerBlock) -> Result<(), String> {
    for &(cp_height, cp_hash) in CHECKPOINTS {
        if block.height == cp_height && block.hash != cp_hash {
            return Err(format!(
                "checkpoint violation at height {}: expected {} got {}",
                cp_height, cp_hash, block.hash
            ));
        }
    }
    Ok(())
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

    // Checkpoint guard: reject blocks that contradict hardcoded anchors.
    if let Err(e) = check_checkpoint(block) {
        eprintln!("[ChainDB] CHECKPOINT VIOLATION — rejecting block: {}", e);
        return;
    }

    // Fork choice: if a block already exists at this height, only replace it
    // if the incoming block has strictly more validator votes (heavier chain).
    // This is the canonical rule: the block that collects the most BFT votes wins.
    if let Some(existing_bytes) = db.get_cf(cf_blocks, height_k).ok().flatten() {
        let existing_votes = decode::<LedgerBlock>(&existing_bytes)
            .map(|b| b.vote_count)
            .unwrap_or(0);
        if block.vote_count <= existing_votes {
            return; // existing block is at least as well-attested — keep it
        }
        // New block has more votes: fall through and overwrite.
        eprintln!("[ForkChoice] Replacing block #{} ({} votes → {} votes)",
            block.height, existing_votes, block.vote_count);
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
        let is_system_source = tx.from == FAUCET_ADDR
            || tx.from == NODE_POOL_ADDR
            || tx.from.is_empty();
        if !is_system_source {
            let total_out = tx.amount as i128 + tx.fee_uegoc as i128;
            *balance_delta.entry(tx.from.clone()).or_insert(0) -= total_out;
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
        let is_system_source = tx.from == FAUCET_ADDR
            || tx.from == NODE_POOL_ADDR
            || tx.from.is_empty();
        if !is_system_source {
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

    // Write light header to CF_HEADERS (kept for a larger window than full block data).
    let cf_hdrs = db.cf_handle(CF_HEADERS).unwrap();
    let hdr = LightBlockHeader::from(block);
    db.put_cf(cf_hdrs, height_key(block.height), encode(&hdr)).ok();

    // Prune old data to keep disk bounded.
    prune_if_needed(db);

    // Update the in-memory nonce store so replay detection stays current.
    for tx in &confirmed_txs {
        if !tx.from.is_empty() {
            crate::ledger::record_confirmed_nonce(&tx.from, tx.nonce);
        }
    }

    // Update validator stake tracker for staking/unstaking TXs.
    // This is what gates validator registration (minimum stake required).
    const STAKING_ADDR_STR: &str = "egot1staking000000000000000000000000000000000";
    for tx in &confirmed_txs {
        if tx.to == STAKING_ADDR_STR && !tx.from.is_empty() {
            crate::ledger::record_validator_stake(&tx.from, tx.amount, true);
        } else if tx.from == STAKING_ADDR_STR && !tx.to.is_empty() {
            crate::ledger::record_validator_stake(&tx.to, tx.amount, false);
        }
    }
}

// ── Pruning ───────────────────────────────────────────────────────────────────
//
// Desktop wallet = light client.  We keep:
//   • Last FULL_BLOCK_CAP full blocks (CF_BLOCKS + CF_BLOCK_TXS).
//   • Last HEADER_CAP light headers (CF_HEADERS).
//   • All transactions in CF_TXS / CF_ADDR_TXS — user's own history is never pruned.
//
// RocksDB's delete_range_cf is O(log N) — it writes a range tombstone, not N deletes.

fn prune_if_needed(db: &DB) {
    let cf_meta = db.cf_handle(CF_META).unwrap();
    let latest = db.get_cf(cf_meta, META_LATEST_HEIGHT)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);

    // Only prune every 50 blocks to amortise overhead.
    if latest % 50 != 0 { return; }

    // ── Full blocks ────────────────────────────────────────────────────────
    if latest > FULL_BLOCK_CAP {
        let keep_from = latest - FULL_BLOCK_CAP;
        let pruned_below = db.get_cf(cf_meta, META_PRUNE_BELOW)
            .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(1); // skip genesis
        if pruned_below < keep_from {
            let cf_blocks    = db.cf_handle(CF_BLOCKS).unwrap();
            let cf_block_txs = db.cf_handle(CF_BLOCK_TXS).unwrap();
            let mut batch = WriteBatch::default();
            // Range tombstone: delete all keys in [pruned_below, keep_from).
            // CF_BLOCK_TXS keys are height(8) ++ tx_hash, so the height prefix
            // range covers all index entries for those blocks.
            batch.delete_range_cf(cf_blocks,    height_key(pruned_below), height_key(keep_from));
            batch.delete_range_cf(cf_block_txs, height_key(pruned_below), height_key(keep_from));
            batch.put_cf(cf_meta, META_PRUNE_BELOW, u64_le(keep_from));
            let _ = db.write(batch);
            eprintln!("[ChainDB] Pruned full blocks {}..{} (keeping last {})",
                pruned_below, keep_from, FULL_BLOCK_CAP);
        }
    }

    // ── Light headers ──────────────────────────────────────────────────────
    if latest > HEADER_CAP {
        let keep_from = latest - HEADER_CAP;
        let pruned_below = db.get_cf(cf_meta, META_PRUNE_HEADERS_BELOW)
            .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(1);
        if pruned_below < keep_from {
            let cf_hdrs = db.cf_handle(CF_HEADERS).unwrap();
            let mut batch = WriteBatch::default();
            batch.delete_range_cf(cf_hdrs, height_key(pruned_below), height_key(keep_from));
            batch.put_cf(cf_meta, META_PRUNE_HEADERS_BELOW, u64_le(keep_from));
            let _ = db.write(batch);
        }
    }
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

/// Burn tokens from the staking pool (slash penalty — tokens are permanently destroyed).
pub fn burn_from_staking_pool(amount_uegoc: u64) {
    const STAKING_ADDR_STR: &str = "egot1staking000000000000000000000000000000000";
    let db = get_db().lock().unwrap();
    let cf = db.cf_handle(CF_BALANCES).unwrap();
    let cur = db.get_cf(cf, STAKING_ADDR_STR.as_bytes())
        .ok().flatten()
        .map(|v| read_u64_le(&v))
        .unwrap_or(0);
    let new_bal = cur.saturating_sub(amount_uegoc);
    db.put_cf(cf, STAKING_ADDR_STR.as_bytes(), u64_le(new_bal))
        .expect("RocksDB burn_from_staking_pool");
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
    paged_blocks(0, limit)
}

pub fn paged_blocks(offset: usize, limit: usize) -> Vec<LedgerBlock> {
    let db = get_db().lock().unwrap();
    let cf = db.cf_handle(CF_BLOCKS).unwrap();
    let mut iter = db.raw_iterator_cf(cf);
    iter.seek_to_last();
    let mut skipped = 0usize;
    let mut out = Vec::with_capacity(limit);
    while iter.valid() && out.len() < limit {
        if let Some(v) = iter.value() {
            if let Some(b) = decode::<LedgerBlock>(v) {
                if skipped < offset { skipped += 1; }
                else { out.push(b); }
            }
        }
        iter.prev();
    }
    out
}

pub fn recent_transactions(limit: usize) -> Vec<LedgerTx> {
    paged_transactions(0, limit)
}

pub fn paged_transactions(offset: usize, limit: usize) -> Vec<LedgerTx> {
    let db = get_db().lock().unwrap();
    let cf_recent = db.cf_handle(CF_RECENT_TXS).unwrap();
    let cf_txs    = db.cf_handle(CF_TXS).unwrap();
    let mut iter = db.raw_iterator_cf(cf_recent);
    iter.seek_to_last();
    let mut skipped = 0usize;
    let mut hashes: Vec<Vec<u8>> = Vec::with_capacity(limit);
    while iter.valid() && hashes.len() < limit {
        if let Some(k) = iter.key() {
            if k.len() > 8 {
                if skipped < offset { skipped += 1; }
                else { hashes.push(k[8..].to_vec()); }
            }
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
/// Max blocks/txs held in the in-memory SharedChain window.
/// Full history lives in RocksDB; this is just the hot window for the UI.
pub const CHAIN_WINDOW: usize = 500;

pub fn load_shared_chain() -> SharedChain {
    SharedChain {
        blocks:       recent_blocks(CHAIN_WINDOW),
        transactions: recent_transactions(CHAIN_WINDOW),
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

/// Return all transactions confirmed in block `height`, in insertion order.
/// Used by the light-client Merkle proof generator.
pub fn get_txs_for_block(height: u64) -> Vec<LedgerTx> {
    let db           = get_db().lock().unwrap();
    let cf_block_txs = db.cf_handle(CF_BLOCK_TXS).unwrap();
    let cf_txs       = db.cf_handle(CF_TXS).unwrap();
    let prefix       = height_key(height);

    let mut out = Vec::new();
    let iter = db.prefix_iterator_cf(cf_block_txs, prefix);
    for item in iter {
        let Ok((key, _)) = item else { continue };
        if key.len() <= 8 { continue; }
        let tx_hash = std::str::from_utf8(&key[8..]).unwrap_or("");
        if tx_hash.is_empty() { continue; }
        if let Some(tx) = db.get_cf(cf_txs, tx_hash.as_bytes()).ok().flatten()
            .and_then(|v| decode::<LedgerTx>(&v))
        {
            out.push(tx);
        }
    }
    out
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
/// `poc_ticket` is the VRF ticket hex proving the miner won the slot lottery.
/// Pass empty string for genesis / faucet / remote blocks (accepted transitionally).
pub fn mine_batch_db(txs: &[LedgerTx], miner: &str) -> LedgerBlock {
    mine_batch_db_with_ticket(txs, miner, "", 0)
}

pub fn mine_batch_db_with_ticket(txs: &[LedgerTx], miner: &str, poc_ticket: &str, poc_slot: u64) -> LedgerBlock {
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

    // Coinbase transaction: credit the block reward to the miner.
    let coinbase_hash = format!("0x{}", blake3::hash(
        format!("coinbase:{height}:{miner}:{reward}:{timestamp}").as_bytes()
    ).to_hex());
    let coinbase = LedgerTx {
        hash:         coinbase_hash.clone(),
        from:         NODE_POOL_ADDR.to_string(),
        to:           miner.to_string(),
        amount:       reward,
        memo:         Some(format!("Block #{height} reward")),
        timestamp,
        status:       "Confirmed".to_string(),
        block_height: Some(height),
        tx_type:      "reward".to_string(),
        signature:    "coinbase".to_string(),
        ..LedgerTx::default()
    };

    // Stamp block_height on each tx before writing.
    let mut stamped: Vec<LedgerTx> = txs.iter().map(|tx| {
        let mut t = tx.clone();
        t.block_height = Some(height);
        t.status = "Confirmed".to_string();
        t
    }).collect();
    stamped.push(coinbase);

    let tx_hashes: Vec<&str> = stamped.iter().map(|t| t.hash.as_str()).collect();
    let tx_merkle_root = compute_merkle_root(&tx_hashes);

    let block = LedgerBlock {
        height,
        hash,
        prev_hash,
        miner: miner.to_string(),
        timestamp,
        tx_count:   stamped.len() as u32,
        size_bytes: stamped.len() as u64 * 256,
        reward,
        coinbase_tx: Some(coinbase_hash),
        vote_count: 0,
        tx_merkle_root,
        poc_ticket: poc_ticket.to_string(),
        poc_slot,
    };

    write_block_batch(&db, &block, &stamped);
    block
}

/// Append a block received from a peer (gossip / sync path).
/// Fork choice: replaces existing block at the same height only if the new
/// block carries more BFT votes (heavier chain wins).
pub fn append_peer_block(block: &LedgerBlock, txs: &[LedgerTx]) {
    let db = get_db().lock().unwrap();
    write_block_batch(&db, block, txs);
}

/// Same as `append_peer_block` but stamps `vote_count` before writing.
/// Used by the BFT finalization path to record how many votes the block got.
pub fn append_peer_block_with_votes(block: &LedgerBlock, txs: &[LedgerTx], votes: u32) {
    let mut b = block.clone();
    b.vote_count = votes;
    let db = get_db().lock().unwrap();
    write_block_batch(&db, &b, txs);
}

// ── Merkle tree (Blake3) ───────────────────────────────────────────────────────
//
// Standard binary Merkle tree. Leaf = blake3(tx_hash). Internal nodes:
// blake3(left_child_hex ++ right_child_hex). Odd levels: duplicate last leaf.
// This allows any light client to verify TX inclusion with O(log N) hashes.

fn blake3_hex(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

/// Compute the Merkle root of a list of transaction hashes.
/// Returns 64 zero chars for an empty block.
pub fn compute_merkle_root(tx_hashes: &[&str]) -> String {
    if tx_hashes.is_empty() {
        return "0".repeat(64);
    }
    let mut layer: Vec<String> = tx_hashes.iter()
        .map(|h| blake3_hex(h.as_bytes()))
        .collect();
    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            let last = layer.last().unwrap().clone();
            layer.push(last);
        }
        layer = layer.chunks(2)
            .map(|pair| blake3_hex(format!("{}{}", pair[0], pair[1]).as_bytes()))
            .collect();
    }
    layer.into_iter().next().unwrap_or_else(|| "0".repeat(64))
}

/// Merkle inclusion proof: sibling hashes from leaf to root.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MerkleProof {
    /// The transaction hash being proved.
    pub tx_hash: String,
    /// Merkle root stored in the block header.
    pub root:    String,
    /// Sibling hashes, bottom-up (leaf level first).
    pub path:    Vec<String>,
    /// For each sibling: false = sibling is on the right, true = sibling is on the left.
    pub indices: Vec<bool>,
}

/// Generate a Merkle inclusion proof for `target_tx` in a list of TX hashes.
pub fn prove_tx_inclusion(tx_hashes: &[&str], target_tx: &str) -> Option<MerkleProof> {
    if tx_hashes.is_empty() { return None; }
    let mut pos = tx_hashes.iter().position(|h| *h == target_tx)?;
    let root = compute_merkle_root(tx_hashes);

    let mut layer: Vec<String> = tx_hashes.iter()
        .map(|h| blake3_hex(h.as_bytes()))
        .collect();
    let mut path    = Vec::new();
    let mut indices = Vec::new();

    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            let last = layer.last().unwrap().clone();
            layer.push(last);
        }
        let sibling_pos = if pos % 2 == 0 { pos + 1 } else { pos - 1 };
        path.push(layer[sibling_pos].clone());
        indices.push(pos % 2 == 1); // true = we are on the right, sibling is left
        pos /= 2;
        layer = layer.chunks(2)
            .map(|pair| blake3_hex(format!("{}{}", pair[0], pair[1]).as_bytes()))
            .collect();
    }
    Some(MerkleProof { tx_hash: target_tx.to_string(), root, path, indices })
}

/// Verify a Merkle inclusion proof. Returns true if the proof is valid.
pub fn verify_merkle_proof(proof: &MerkleProof) -> bool {
    if proof.path.len() != proof.indices.len() { return false; }
    let mut current = blake3_hex(proof.tx_hash.as_bytes());
    for (sibling, is_right) in proof.path.iter().zip(proof.indices.iter()) {
        current = if *is_right {
            blake3_hex(format!("{}{}", sibling, current).as_bytes())
        } else {
            blake3_hex(format!("{}{}", current, sibling).as_bytes())
        };
    }
    current == proof.root
}

/// Light block header — only what a light client needs to track the chain.
/// No TX data; use `prove_tx_inclusion` for inclusion proofs.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LightBlockHeader {
    pub height:         u64,
    pub hash:           String,
    pub prev_hash:      String,
    pub miner:          String,
    pub timestamp:      i64,
    pub tx_count:       u32,
    pub reward:         u64,
    pub vote_count:     u32,
    pub tx_merkle_root: String,
}

impl From<&LedgerBlock> for LightBlockHeader {
    fn from(b: &LedgerBlock) -> Self {
        LightBlockHeader {
            height:         b.height,
            hash:           b.hash.clone(),
            prev_hash:      b.prev_hash.clone(),
            miner:          b.miner.clone(),
            timestamp:      b.timestamp,
            tx_count:       b.tx_count,
            reward:         b.reward,
            vote_count:     b.vote_count,
            tx_merkle_root: b.tx_merkle_root.clone(),
        }
    }
}

/// Look up a single light header. Available even after the full block is pruned.
pub fn get_light_header(height: u64) -> Option<LightBlockHeader> {
    let db = get_db().lock().unwrap();
    let cf = db.cf_handle(CF_HEADERS).unwrap();
    db.get_cf(cf, height_key(height)).ok().flatten()
        .and_then(|v| decode(&v))
}

/// Fetch block headers from `from_height` up to `limit` (max 10_000).
pub fn get_block_headers(from_height: u64, limit: u32) -> Vec<LightBlockHeader> {
    let db    = get_db().lock().unwrap();
    let cf    = db.cf_handle(CF_BLOCKS).unwrap();
    let limit = (limit as usize).min(10_000);
    let mut out = Vec::with_capacity(limit);
    for h in from_height.. {
        if out.len() >= limit { break; }
        match db.get_cf(cf, height_key(h)).ok().flatten()
            .and_then(|v| decode::<LedgerBlock>(&v))
        {
            Some(b) => out.push(LightBlockHeader::from(&b)),
            None    => break,
        }
    }
    out
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

/// Returns the hash of the current chain tip (latest mined block).
/// Used by the PoC lottery to compute slot seeds.
pub fn get_tip_hash() -> String {
    let db = get_db().lock().unwrap();
    let cf_meta   = db.cf_handle(CF_META).unwrap();
    let cf_blocks = db.cf_handle(CF_BLOCKS).unwrap();
    let h = db.get_cf(cf_meta, META_LATEST_HEIGHT)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
    db.get_cf(cf_blocks, height_key(h))
        .ok().flatten()
        .and_then(|v| decode::<LedgerBlock>(&v))
        .map(|b| b.hash)
        .unwrap_or_else(|| GENESIS_HASH.to_string())
}

// ── RPC helpers ───────────────────────────────────────────────────────────────

/// Return up to `limit` transactions for `address`, newest first.
pub fn get_address_txs(address: &str, limit: usize) -> Vec<LedgerTx> {
    let mut txs = get_tx_history_for_addr(address);
    txs.sort_unstable_by(|a, b| b.timestamp.cmp(&a.timestamp));
    txs.truncate(limit);
    txs
}

/// Return full blocks starting at `from_height`, up to `limit` (max 1_000).
pub fn get_blocks_range(from_height: u64, limit: u32) -> Vec<LedgerBlock> {
    let db    = get_db().lock().unwrap();
    let cf    = db.cf_handle(CF_BLOCKS).unwrap();
    let limit = (limit as usize).min(1_000);
    let mut out = Vec::with_capacity(limit);
    for h in from_height.. {
        if out.len() >= limit { break; }
        match db.get_cf(cf, height_key(h)).ok().flatten()
            .and_then(|v| decode::<LedgerBlock>(&v))
        {
            Some(b) => out.push(b),
            None    => break,
        }
    }
    out
}

#[derive(Debug, serde::Serialize)]
pub struct NetworkStats {
    pub block_count: u64,
    pub tx_count:    u64,
}

/// Lightweight network statistics from meta column family.
pub fn get_network_stats_db() -> NetworkStats {
    let db      = get_db().lock().unwrap();
    let cf_meta = db.cf_handle(CF_META).unwrap();
    let block_count = db.get_cf(cf_meta, META_LATEST_HEIGHT)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
    let tx_count = db.get_cf(cf_meta, META_TX_COUNT)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
    NetworkStats { block_count, tx_count }
}

// ── Kept for API compatibility ────────────────────────────────────────────────

/// No-op: DB handle is a global singleton, not caller-managed.
#[allow(dead_code)]
pub fn get_db_handle() -> &'static Mutex<DB> { get_db() }

// ── On-chain governance ───────────────────────────────────────────────────────
//
// Validators submit governance transactions (tx_type = "governance") to vote on
// enabling or disabling named feature flags. When ⅔+1 stake-weighted validators
// agree, the feature activates at the specified block height.
//
// This allows emergency changes (e.g. disabling a broken crypto primitive) to be
// deployed without a hard fork or code rollout — just validator votes on-chain.

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GovernanceProposal {
    /// The feature being voted on (e.g. FEATURE_DILITHIUM_DISABLED).
    pub feature:     String,
    /// "enable" or "disable".
    pub action:      String,
    /// Block height at which the feature takes effect once approved.
    pub activate_at: u64,
    /// Validator addresses that have voted yes.
    pub votes:       Vec<String>,
    /// True once the proposal passed and is recorded as active.
    pub activated:   bool,
}

fn governance_key(feature: &str, action: &str) -> Vec<u8> {
    format!("{}:{}", action, feature).into_bytes()
}

/// Record one validator vote. Returns the updated proposal so the caller
/// (p2p layer) can check if threshold is now reached.
pub fn record_governance_vote(
    feature:     &str,
    action:      &str,
    activate_at: u64,
    voter:       &str,
) -> GovernanceProposal {
    let db  = get_db().lock().unwrap();
    let cf  = db.cf_handle(CF_GOVERNANCE).unwrap();
    let key = governance_key(feature, action);

    let mut proposal: GovernanceProposal = db.get_cf(cf, &key)
        .ok().flatten()
        .and_then(|v| decode(&v))
        .unwrap_or(GovernanceProposal {
            feature:     feature.to_string(),
            action:      action.to_string(),
            activate_at,
            votes:       Vec::new(),
            activated:   false,
        });

    if !proposal.activated && !proposal.votes.contains(&voter.to_string()) {
        proposal.votes.push(voter.to_string());
        db.put_cf(cf, &key, encode(&proposal)).ok();
    }
    proposal
}

/// Mark a proposal as activated. Called by the p2p layer after threshold reached.
pub fn activate_feature(feature: &str, action: &str) {
    let db  = get_db().lock().unwrap();
    let cf  = db.cf_handle(CF_GOVERNANCE).unwrap();
    let key = governance_key(feature, action);

    if let Some(mut p) = db.get_cf(cf, &key).ok().flatten()
        .and_then(|v| decode::<GovernanceProposal>(&v))
    {
        p.activated = true;
        db.put_cf(cf, &key, encode(&p)).ok();
        eprintln!("[Governance] '{}' {} — activates at block {}", feature, action, p.activate_at);
    }
}

/// Returns true if feature's "disable" vote passed AND current height ≥ activate_at.
pub fn is_feature_disabled(feature: &str) -> bool {
    feature_state(feature, "disable")
}

/// Returns true if feature's "enable" vote passed AND current height ≥ activate_at.
pub fn is_feature_enabled(feature: &str) -> bool {
    feature_state(feature, "enable")
}

fn feature_state(feature: &str, action: &str) -> bool {
    let db  = get_db().lock().unwrap();
    let cf  = db.cf_handle(CF_GOVERNANCE).unwrap();
    let key = governance_key(feature, action);
    let cf_meta = db.cf_handle(CF_META).unwrap();
    let height  = db.get_cf(cf_meta, META_LATEST_HEIGHT)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);

    db.get_cf(cf, &key).ok().flatten()
        .and_then(|v| decode::<GovernanceProposal>(&v))
        .map(|p| p.activated && height >= p.activate_at)
        .unwrap_or(false)
}

/// Return all proposals for display in the UI.
pub fn get_all_governance_proposals() -> Vec<GovernanceProposal> {
    let db = get_db().lock().unwrap();
    let cf = db.cf_handle(CF_GOVERNANCE).unwrap();
    db.iterator_cf(cf, rocksdb::IteratorMode::Start)
        .filter_map(|r| r.ok())
        .filter_map(|(_, v)| decode::<GovernanceProposal>(&v))
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// ── DAO Proposal System ───────────────────────────────────────────────────────
//
// Two-type voting per the Ego whitepaper:
//   Stake power(opt)     = Σ stake_i_for_opt / Σ stake_all
//   Knowledge power(opt) = Σ (score_i × BASE) for_opt / Σ (score_all × BASE)
//   Combined             = (stake_power + knowledge_power) / 2
//
// Proposals are community-submitted; knowledge tests are community-submitted.
// Correct answers are stored server-side only — never sent to the frontend.

pub const DAO_BASE_KNOWLEDGE_POWER: f64 = 10.0;
const DAO_DEFAULT_DURATION_SECS:    i64 = 7 * 24 * 3600; // 7 days

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ── Stored types (server-side, include correct answers) ───────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DaoTestQuestion {
    pub id:            String,
    pub question:      String,
    pub options:       Vec<String>,
    pub correct_index: usize,   // NOT exposed to frontend
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DaoKnowledgeTest {
    pub questions:  Vec<DaoTestQuestion>,
    pub created_by: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DaoStakeVote {
    pub voter:        String,
    pub option_index: usize,
    pub stake_amount: u64,
    pub timestamp:    i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DaoKnowledgeVote {
    pub voter:        String,
    pub option_index: usize,
    pub test_score:   f64,
    pub timestamp:    i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DaoProposal {
    pub id:              String,
    pub title:           String,
    pub description:     String,
    pub proposal_type:   String,
    pub options:         Vec<String>,
    pub creator:         String,
    pub created_at:      i64,
    pub voting_ends_at:  i64,
    pub status:          String,  // "active" | "passed" | "failed" | "expired"
    pub knowledge_test:  Option<DaoKnowledgeTest>,
    pub stake_votes:     std::collections::HashMap<String, DaoStakeVote>,
    pub knowledge_votes: std::collections::HashMap<String, DaoKnowledgeVote>,
}

// ── Frontend-safe types (no correct answers) ──────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DaoTestQuestionPublic {
    pub id:       String,
    pub question: String,
    pub options:  Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DaoProposalPublic {
    pub id:                   String,
    pub title:                String,
    pub description:          String,
    pub proposal_type:        String,
    pub options:              Vec<String>,
    pub creator:              String,
    pub created_at:           i64,
    pub voting_ends_at:       i64,
    pub status:               String,
    pub has_knowledge_test:   bool,
    pub question_count:       usize,
    pub stake_vote_count:     usize,
    pub knowledge_vote_count: usize,
    pub questions:            Option<Vec<DaoTestQuestionPublic>>,
    pub my_stake_vote:        Option<usize>,
    pub my_knowledge_vote:    Option<usize>,
    pub my_test_score:        Option<f64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DaoOptionResult {
    pub option:          String,
    pub stake_power:     f64,
    pub knowledge_power: f64,
    pub combined_power:  f64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DaoProposalResults {
    pub proposal_id:            String,
    pub title:                  String,
    pub options:                Vec<DaoOptionResult>,
    pub winning_option_index:   Option<usize>,
    pub total_stake_voters:     usize,
    pub total_knowledge_voters: usize,
    pub total_staked_in_votes:  u64,
    pub quorum_reached:         bool,
    pub status:                 String,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn dao_key(id: &str) -> Vec<u8> { id.as_bytes().to_vec() }

fn resolved_status(p: &DaoProposal) -> String {
    if p.status == "active" && now_secs() > p.voting_ends_at {
        "expired".to_string()
    } else {
        p.status.clone()
    }
}

fn proposal_to_public(p: &DaoProposal, voter: Option<&str>) -> DaoProposalPublic {
    let questions = p.knowledge_test.as_ref().map(|kt| {
        kt.questions.iter().map(|q| DaoTestQuestionPublic {
            id:       q.id.clone(),
            question: q.question.clone(),
            options:  q.options.clone(),
        }).collect()
    });
    DaoProposalPublic {
        id:                   p.id.clone(),
        title:                p.title.clone(),
        description:          p.description.clone(),
        proposal_type:        p.proposal_type.clone(),
        options:              p.options.clone(),
        creator:              p.creator.clone(),
        created_at:           p.created_at,
        voting_ends_at:       p.voting_ends_at,
        status:               resolved_status(p),
        has_knowledge_test:   p.knowledge_test.is_some(),
        question_count:       p.knowledge_test.as_ref().map(|k| k.questions.len()).unwrap_or(0),
        stake_vote_count:     p.stake_votes.len(),
        knowledge_vote_count: p.knowledge_votes.len(),
        questions,
        my_stake_vote:    voter.and_then(|v| p.stake_votes.get(v).map(|sv| sv.option_index)),
        my_knowledge_vote:voter.and_then(|v| p.knowledge_votes.get(v).map(|kv| kv.option_index)),
        my_test_score:    voter.and_then(|v| p.knowledge_votes.get(v).map(|kv| kv.test_score)),
    }
}

fn grade_answers(kt: &DaoKnowledgeTest, answers: &[usize]) -> Result<f64, String> {
    if answers.len() != kt.questions.len() {
        return Err(format!("Expected {} answers, got {}", kt.questions.len(), answers.len()));
    }
    let correct = kt.questions.iter().zip(answers.iter())
        .filter(|(q, &a)| q.correct_index == a)
        .count();
    Ok(correct as f64 / kt.questions.len() as f64)
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn store_dao_proposal(proposal: DaoProposal) -> Result<(), String> {
    let db = get_db().lock().unwrap();
    let cf = db.cf_handle(CF_DAO).ok_or("CF_DAO missing")?;
    db.put_cf(cf, dao_key(&proposal.id), encode(&proposal))
        .map_err(|e| e.to_string())
}

pub fn get_dao_proposal_public(id: &str, voter: Option<&str>) -> Option<DaoProposalPublic> {
    let db = get_db().lock().unwrap();
    let cf = db.cf_handle(CF_DAO)?;
    let bytes = db.get_cf(cf, dao_key(id)).ok()??;
    let p: DaoProposal = decode(&bytes)?;
    Some(proposal_to_public(&p, voter))
}

pub fn list_dao_proposals(status_filter: Option<&str>, voter: Option<&str>) -> Vec<DaoProposalPublic> {
    let db = get_db().lock().unwrap();
    let cf = match db.cf_handle(CF_DAO) { Some(c) => c, None => return vec![] };
    let now = now_secs();
    db.iterator_cf(cf, rocksdb::IteratorMode::Start)
        .filter_map(|r| r.ok())
        .filter_map(|(_, v)| decode::<DaoProposal>(&v))
        .filter(|p| match status_filter {
            None | Some("all") => true,
            Some("active")  => p.status == "active" && now <= p.voting_ends_at,
            Some("expired") => (p.status == "active" && now > p.voting_ends_at) || p.status == "expired",
            Some(s)         => p.status == s,
        })
        .map(|p| proposal_to_public(&p, voter))
        .collect()
}

pub fn cast_dao_stake_vote(
    proposal_id: &str,
    option_index: usize,
    voter: &str,
    stake_amount: u64,
) -> Result<(), String> {
    let db = get_db().lock().unwrap();
    let cf = db.cf_handle(CF_DAO).ok_or("CF_DAO missing")?;
    let bytes = db.get_cf(cf, dao_key(proposal_id)).map_err(|e| e.to_string())?.ok_or("Proposal not found")?;
    let mut p: DaoProposal = decode(&bytes).ok_or("Decode error")?;
    let now = now_secs();
    if p.status != "active" || now > p.voting_ends_at { return Err("Voting period has ended".into()); }
    if option_index >= p.options.len() { return Err("Invalid option index".into()); }
    if stake_amount == 0 { return Err("You must hold EGOC to cast a stake vote".into()); }
    p.stake_votes.insert(voter.to_string(), DaoStakeVote {
        voter: voter.to_string(), option_index, stake_amount, timestamp: now,
    });
    db.put_cf(cf, dao_key(proposal_id), encode(&p)).map_err(|e| e.to_string())
}

pub fn grade_dao_knowledge_test(proposal_id: &str, answers: &[usize]) -> Result<f64, String> {
    let db = get_db().lock().unwrap();
    let cf = db.cf_handle(CF_DAO).ok_or("CF_DAO missing")?;
    let bytes = db.get_cf(cf, dao_key(proposal_id)).map_err(|e| e.to_string())?.ok_or("Proposal not found")?;
    let p: DaoProposal = decode(&bytes).ok_or("Decode error")?;
    let kt = p.knowledge_test.ok_or("No knowledge test on this proposal")?;
    grade_answers(&kt, answers)
}

pub fn cast_dao_knowledge_vote(
    proposal_id: &str,
    option_index: usize,
    voter: &str,
    answers: &[usize],
) -> Result<f64, String> {
    let db = get_db().lock().unwrap();
    let cf = db.cf_handle(CF_DAO).ok_or("CF_DAO missing")?;
    let bytes = db.get_cf(cf, dao_key(proposal_id)).map_err(|e| e.to_string())?.ok_or("Proposal not found")?;
    let mut p: DaoProposal = decode(&bytes).ok_or("Decode error")?;
    let now = now_secs();
    if p.status != "active" || now > p.voting_ends_at { return Err("Voting period has ended".into()); }
    if option_index >= p.options.len() { return Err("Invalid option index".into()); }
    let kt = p.knowledge_test.as_ref().ok_or("No knowledge test on this proposal")?;
    let score = grade_answers(kt, answers)?;
    p.knowledge_votes.insert(voter.to_string(), DaoKnowledgeVote {
        voter: voter.to_string(), option_index, test_score: score, timestamp: now,
    });
    db.put_cf(cf, dao_key(proposal_id), encode(&p)).map_err(|e| e.to_string())?;
    Ok(score)
}

pub fn get_dao_results(proposal_id: &str) -> Option<DaoProposalResults> {
    let db = get_db().lock().unwrap();
    let cf = db.cf_handle(CF_DAO)?;
    let bytes = db.get_cf(cf, dao_key(proposal_id)).ok()??;
    let p: DaoProposal = decode(&bytes)?;
    let n = p.options.len();

    let total_stake: u64 = p.stake_votes.values().map(|v| v.stake_amount).sum();
    let mut stake_by_opt = vec![0u64; n];
    for v in p.stake_votes.values() {
        if v.option_index < n { stake_by_opt[v.option_index] += v.stake_amount; }
    }

    let total_knowledge: f64 = p.knowledge_votes.values()
        .map(|v| v.test_score * DAO_BASE_KNOWLEDGE_POWER).sum();
    let mut know_by_opt = vec![0f64; n];
    for v in p.knowledge_votes.values() {
        if v.option_index < n { know_by_opt[v.option_index] += v.test_score * DAO_BASE_KNOWLEDGE_POWER; }
    }

    let options: Vec<DaoOptionResult> = p.options.iter().enumerate().map(|(i, opt)| {
        let sp = if total_stake > 0 { stake_by_opt[i] as f64 / total_stake as f64 } else { 0.0 };
        let kp = if total_knowledge > 0.0 { know_by_opt[i] / total_knowledge } else { 0.0 };
        let cp = match (total_stake > 0, total_knowledge > 0.0) {
            (true,  true)  => (sp + kp) / 2.0,
            (true,  false) => sp,
            (false, true)  => kp,
            (false, false) => 0.0,
        };
        DaoOptionResult { option: opt.clone(), stake_power: sp, knowledge_power: kp, combined_power: cp }
    }).collect();

    let winning_option_index = options.iter().enumerate()
        .max_by(|(_, a), (_, b)| a.combined_power.partial_cmp(&b.combined_power)
            .unwrap_or(std::cmp::Ordering::Equal))
        .filter(|(_, o)| o.combined_power > 0.0)
        .map(|(i, _)| i);

    Some(DaoProposalResults {
        proposal_id:            proposal_id.to_string(),
        title:                  p.title.clone(),
        options,
        winning_option_index,
        total_stake_voters:     p.stake_votes.len(),
        total_knowledge_voters: p.knowledge_votes.len(),
        total_staked_in_votes:  total_stake,
        quorum_reached:         p.stake_votes.len() >= 1,
        status:                 resolved_status(&p),
    })
}
