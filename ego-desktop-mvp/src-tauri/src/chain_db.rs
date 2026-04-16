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
const CF_HOSTING:       &str = "hosting";       // Web3 hosted sites (name → HostedSite JSON)
const CF_HOSTING_NODES: &str = "hosting_nodes"; // node_id → HostingNodeRecord JSON

const ALL_CFS: &[&str] = &[
    CF_BLOCKS, CF_TXS, CF_BLOCK_TXS, CF_ADDR_TXS, CF_BALANCES,
    CF_RECENT_TXS, CF_META, CF_HEADERS, CF_GOVERNANCE, CF_DAO,
    CF_HOSTING, CF_HOSTING_NODES,
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
        state_root: String::new(),
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
            state_root: String::new(),
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
            tx_version:          0,
            chain_id:            0,
            signed_summary:      String::new(),
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
    (0, "ego00000000000000000000000000000000000000000000000000000000genesis2"),
    // Production checkpoints added here after each major milestone.
    // Dynamic checkpoints are also stored in RocksDB (see below).
];

/// How often (in blocks) a dynamic checkpoint is automatically written.
/// Every 10,000 blocks (~8.3 hours at 3s/block) the block hash is stored in
/// RocksDB and used to reject any peer-supplied chain that forks before it.
pub const CHECKPOINT_INTERVAL: u64 = 10_000;

const META_CHECKPOINT_PREFIX: &[u8] = b"ckpt:";

fn checkpoint_meta_key(height: u64) -> Vec<u8> {
    let mut k = META_CHECKPOINT_PREFIX.to_vec();
    k.extend_from_slice(&height.to_be_bytes());
    k
}

/// Store a dynamic checkpoint for `block` in RocksDB.
/// Called automatically in write_block_batch every CHECKPOINT_INTERVAL blocks.
fn store_dynamic_checkpoint(db: &DB, block: &LedgerBlock) {
    let cf = match db.cf_handle(CF_META) { Some(c) => c, None => return };
    let key = checkpoint_meta_key(block.height);
    // Only store if not already set (first finalized block at this height wins).
    if db.get_cf(cf, &key).ok().flatten().is_none() {
        let _ = db.put_cf(cf, key, block.hash.as_bytes());
        eprintln!("[Checkpoint] Stored dynamic checkpoint at height {} ({}…)",
            block.height, &block.hash[..16.min(block.hash.len())]);
    }
}

/// Load the dynamic checkpoint hash for `height` from RocksDB.
/// Returns None if no checkpoint has been stored at that height yet.
pub fn get_dynamic_checkpoint(height: u64) -> Option<String> {
    let db = get_db().lock().unwrap();
    let cf = db.cf_handle(CF_META)?;
    db.get_cf(cf, checkpoint_meta_key(height)).ok().flatten()
        .and_then(|b| String::from_utf8(b.to_vec()).ok())
}

/// Returns Err if `block` contradicts a known checkpoint (hardcoded or dynamic).
pub fn check_checkpoint(block: &LedgerBlock) -> Result<(), String> {
    // 1. Hardcoded checkpoints (genesis + post-launch milestones).
    for &(cp_height, cp_hash) in CHECKPOINTS {
        if block.height == cp_height && block.hash != cp_hash {
            return Err(format!(
                "hardcoded checkpoint violation at height {}: expected {} got {}",
                cp_height, cp_hash, block.hash
            ));
        }
    }
    // 2. Dynamic checkpoints stored in RocksDB.
    if block.height > 0 && block.height % CHECKPOINT_INTERVAL == 0 {
        if let Some(stored_hash) = get_dynamic_checkpoint(block.height) {
            if stored_hash != block.hash {
                return Err(format!(
                    "dynamic checkpoint violation at height {}: expected {}… got {}…",
                    block.height,
                    &stored_hash[..16.min(stored_hash.len())],
                    &block.hash[..16.min(block.hash.len())]
                ));
            }
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

        // ── Max supply enforcement ────────────────────────────────────────────
        // When the node pool is the source (coinbase), cap the outgoing amount to
        // the pool's current balance. This prevents any block — local or peer —
        // from inflating supply past the genesis-allocated NODE_POOL_UEGOC.
        let credited_amount = if tx.from == NODE_POOL_ADDR && tx.amount > 0 {
            let pool_bal: u64 = db.get_cf(cf_balances, NODE_POOL_ADDR.as_bytes())
                .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
            // Apply any earlier delta for NODE_POOL_ADDR in this same batch
            let pending_delta = *balance_delta.get(NODE_POOL_ADDR).unwrap_or(&0);
            let effective_pool = (pool_bal as i128 + pending_delta).max(0) as u64;
            let capped = tx.amount.min(effective_pool);
            if capped < tx.amount {
                eprintln!(
                    "[ChainDB] Max supply cap: coinbase {} capped from {} to {} uEGOC (pool={})",
                    &tx.hash[..tx.hash.len().min(12)], tx.amount, capped, effective_pool
                );
            }
            capped
        } else {
            tx.amount
        };

        *balance_delta.entry(tx.to.clone()).or_insert(0) += credited_amount as i128;
        let is_system_source = tx.from == FAUCET_ADDR
            || tx.from == NODE_POOL_ADDR
            || tx.from.is_empty();
        if !is_system_source {
            let total_out = tx.amount as i128 + tx.fee_uegoc as i128;
            *balance_delta.entry(tx.from.clone()).or_insert(0) -= total_out;
        } else if tx.from == NODE_POOL_ADDR {
            // Debit the node pool so it actually decreases — enforces hard supply cap.
            *balance_delta.entry(NODE_POOL_ADDR.to_string()).or_insert(0) -= credited_amount as i128;
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

    // Persist confirmed nonces atomically with the block write so replay
    // protection survives node restarts.  Only non-system senders have nonces.
    for tx in &confirmed_txs {
        let is_system = tx.from == FAUCET_ADDR || tx.from == NODE_POOL_ADDR || tx.from.is_empty();
        if !is_system && tx.nonce > 0 {
            persist_nonce_in_batch(&mut batch, &db, &tx.from, tx.nonce);
        }
    }

    db.write(batch).expect("RocksDB write batch");

    // Write light header to CF_HEADERS (kept for a larger window than full block data).
    let cf_hdrs = db.cf_handle(CF_HEADERS).unwrap();
    let hdr = LightBlockHeader::from(block);
    db.put_cf(cf_hdrs, height_key(block.height), encode(&hdr)).ok();

    // Dynamic checkpoint: every CHECKPOINT_INTERVAL blocks store the hash in CF_META.
    // This protects against long-range attacks on intervals not covered by hardcoded checkpoints.
    if block.height > 0 && block.height % CHECKPOINT_INTERVAL == 0 {
        store_dynamic_checkpoint(db, block);
    }

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

/// Canonical block hash function.  Every field that defines "what this block
/// contains" is committed: prev_hash chains blocks, tx_merkle_root commits to
/// all transactions, poc_ticket commits to the slot winner proof.
///
/// Changing any transaction → merkle root changes → block hash changes →
/// every subsequent block's prev_hash is wrong → the whole chain from that
/// point forward is invalid.  Same domino-effect as Bitcoin's PoW chain.
pub fn block_hash_for(
    prev_hash:       &str,
    height:          u64,
    miner:           &str,
    timestamp:       i64,
    tx_merkle_root:  &str,
    poc_ticket:      &str,
) -> String {
    // v2 format — kept for backwards compatibility with existing blocks.
    let input = format!(
        "ego/block/v2:{prev_hash}:{height}:{miner}:{timestamp}:{tx_merkle_root}:{poc_ticket}"
    );
    blake3::hash(input.as_bytes()).to_hex().to_string()
}

/// v3 block hash — includes the state delta root so any tampering with account
/// balances changes the block hash and breaks every subsequent block's prev_hash.
/// All new blocks are produced with this format.
pub fn block_hash_v3(
    prev_hash:       &str,
    height:          u64,
    miner:           &str,
    timestamp:       i64,
    tx_merkle_root:  &str,
    poc_ticket:      &str,
    state_root:      &str,
) -> String {
    let input = format!(
        "ego/block/v3:{prev_hash}:{height}:{miner}:{timestamp}:{tx_merkle_root}:{poc_ticket}:{state_root}"
    );
    blake3::hash(input.as_bytes()).to_hex().to_string()
}

/// Compute the state delta root from a balance-change map.
/// Sorts entries by address (lexicographic) then hashes each as `"addr:balance_u64_le"`.
/// Returns a 64-char hex string.  Empty map → 64 zeros (empty-state sentinel).
pub fn compute_state_delta_root(balance_delta: &std::collections::HashMap<String, u64>) -> String {
    if balance_delta.is_empty() {
        return "0".repeat(64);
    }
    let mut entries: Vec<(&String, &u64)> = balance_delta.iter().collect();
    entries.sort_by_key(|(addr, _)| addr.as_str());
    let leaf_hashes: Vec<&str>;
    let leaf_strings: Vec<String> = entries.iter()
        .map(|(addr, bal)| {
            let mut leaf = Vec::with_capacity(addr.len() + 9);
            leaf.extend_from_slice(addr.as_bytes());
            leaf.push(b':');
            leaf.extend_from_slice(&bal.to_le_bytes());
            blake3::hash(&leaf).to_hex().to_string()
        })
        .collect();
    let refs: Vec<&str> = leaf_strings.iter().map(|s| s.as_str()).collect();
    compute_merkle_root(&refs)
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
    let tx_fees_sum: u64 = txs.iter().map(|t| t.fee_uegoc).sum();
    let reward    = crate::tokenomics::compute_block_reward(height, tx_fees_sum, &prev_hash);

    // ── 1. Build all transactions first — merkle root must be computed
    //       BEFORE the block hash so the hash commits to tx content.
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

    let mut stamped: Vec<LedgerTx> = txs.iter().map(|tx| {
        let mut t = tx.clone();
        t.block_height = Some(height);
        t.status = "Confirmed".to_string();
        t
    }).collect();
    stamped.push(coinbase);

    let staking_fee = crate::tokenomics::staking_fee_share(tx_fees_sum);
    if staking_fee > 0 {
        let sf_hash = format!("0x{}", blake3::hash(
            format!("stakingfee:{height}:{staking_fee}:{timestamp}").as_bytes()
        ).to_hex());
        stamped.push(LedgerTx {
            hash:         sf_hash,
            from:         NODE_POOL_ADDR.to_string(),
            to:           STAKING_POOL_ADDR.to_string(),
            amount:       staking_fee,
            memo:         Some(format!("Block #{height} staking fee share")),
            timestamp,
            status:       "Confirmed".to_string(),
            block_height: Some(height),
            tx_type:      "fee_distribution".to_string(),
            signature:    "coinbase".to_string(),
            ..LedgerTx::default()
        });
    }

    // ── 2. Merkle root over all txs in this block.
    let tx_hashes: Vec<&str> = stamped.iter().map(|t| t.hash.as_str()).collect();
    let tx_merkle_root = compute_merkle_root(&tx_hashes);

    // ── 3. Compute balance-delta state root BEFORE hashing the block.
    //       This commits the account-state changes so any DB tampering is
    //       detectable: changing a balance changes state_root → changes block hash.
    //
    //       IMPORTANT: accumulate signed i128 deltas first, then apply once per
    //       address.  The naive insert() approach overwrites earlier entries for
    //       the same address when multiple TXs touch it in one block, producing a
    //       state_root that disagrees with what write_block_batch actually commits.
    let balance_delta_for_root = {
        let cf_bal = db.cf_handle(CF_BALANCES).unwrap();
        // Phase 1: accumulate signed deltas — same logic as write_block_batch.
        let mut deltas: std::collections::HashMap<String, i128> = Default::default();
        for tx in &stamped {
            if !tx.to.is_empty() {
                *deltas.entry(tx.to.clone()).or_insert(0) += tx.amount as i128;
            }
            let is_system = tx.from.is_empty()
                || tx.from == NODE_POOL_ADDR
                || tx.from.starts_with("egot1faucet")
                || tx.from.starts_with("egot1genesis");
            if !is_system {
                let out = tx.amount as i128 + tx.fee_uegoc as i128;
                *deltas.entry(tx.from.clone()).or_insert(0) -= out;
            }
        }
        // Phase 2: apply each delta to the current DB balance, clamp to 0.
        let mut result: std::collections::HashMap<String, u64> = Default::default();
        for (addr, delta) in &deltas {
            let old: u64 = db.get_cf(cf_bal, addr.as_bytes())
                .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
            result.insert(addr.clone(), (old as i128 + delta).max(0) as u64);
        }
        result
    };
    let state_root = compute_state_delta_root(&balance_delta_for_root);

    // ── 4. Block hash (v3) commits to prev_hash + tx_merkle_root + poc_ticket + state_root.
    //       Any tampering with transactions OR balances breaks this hash, which
    //       breaks every subsequent block's prev_hash (Bitcoin domino effect).
    let hash = block_hash_v3(&prev_hash, height, miner, timestamp, &tx_merkle_root, poc_ticket, &state_root);

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
        state_root,
    };

    write_block_batch(&db, &block, &stamped);
    block
}

pub fn build_block_proposal(txs: &[LedgerTx], miner: &str, poc_ticket: &str, poc_slot: u64) -> (LedgerBlock, Vec<LedgerTx>) {
    let db = get_db().lock().expect("chain_db lock poisoned");

    let (latest_height, prev_hash) = {
        let cf_meta = db.cf_handle(CF_META).expect("CF_META missing");
        let h = db.get_cf(cf_meta, META_LATEST_HEIGHT)
            .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
        let cf_blocks = db.cf_handle(CF_BLOCKS).expect("CF_BLOCKS missing");
        let hash = db.get_cf(cf_blocks, height_key(h))
            .ok().flatten()
            .and_then(|v| decode::<LedgerBlock>(&v))
            .map(|b| b.hash)
            .unwrap_or_else(|| GENESIS_HASH.to_string());
        (h, hash)
    };

    let height    = latest_height + 1;
    let timestamp = chrono::Utc::now().timestamp();
    let tx_fees_sum: u64 = txs.iter().map(|t| t.fee_uegoc).sum();
    let reward    = crate::tokenomics::compute_block_reward(height, tx_fees_sum, &prev_hash);

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

    let valid_txs: Vec<&LedgerTx> = txs.iter().filter(|tx| {
        if tx.nonce == 0 { return true; }
        let last = crate::ledger::last_confirmed_nonce(&tx.from);
        if tx.nonce <= last {
            eprintln!(
                "[TX] {:.12} Rejected — stale nonce {} <= confirmed {} for {:.16}",
                tx.hash, tx.nonce, last, tx.from
            );
            return false;
        }
        true
    }).collect();

    let mut stamped: Vec<LedgerTx> = valid_txs.iter().map(|tx| {
        let mut t = (*tx).clone();
        t.block_height = Some(height);
        t.status = "Confirmed".to_string();
        t
    }).collect();
    stamped.push(coinbase);

    let staking_fee = crate::tokenomics::staking_fee_share(tx_fees_sum);
    if staking_fee > 0 {
        let sf_hash = format!("0x{}", blake3::hash(
            format!("stakingfee:{height}:{staking_fee}:{timestamp}").as_bytes()
        ).to_hex());
        stamped.push(LedgerTx {
            hash:         sf_hash,
            from:         NODE_POOL_ADDR.to_string(),
            to:           STAKING_POOL_ADDR.to_string(),
            amount:       staking_fee,
            memo:         Some(format!("Block #{height} staking fee share")),
            timestamp,
            status:       "Confirmed".to_string(),
            block_height: Some(height),
            tx_type:      "fee_distribution".to_string(),
            signature:    "coinbase".to_string(),
            ..LedgerTx::default()
        });
    }

    let tx_hashes: Vec<&str> = stamped.iter().map(|t| t.hash.as_str()).collect();
    let tx_merkle_root = compute_merkle_root(&tx_hashes);

    let balance_delta_for_root = {
        let cf_bal = db.cf_handle(CF_BALANCES).expect("CF_BALANCES missing");
        let mut deltas: std::collections::HashMap<String, i128> = Default::default();
        for tx in &stamped {
            if !tx.to.is_empty() {
                *deltas.entry(tx.to.clone()).or_insert(0) += tx.amount as i128;
            }
            let is_system = tx.from.is_empty()
                || tx.from == NODE_POOL_ADDR
                || tx.from.starts_with("egot1faucet")
                || tx.from.starts_with("egot1genesis");
            if !is_system {
                let out = tx.amount as i128 + tx.fee_uegoc as i128;
                *deltas.entry(tx.from.clone()).or_insert(0) -= out;
            }
        }
        let mut result: std::collections::HashMap<String, u64> = Default::default();
        for (addr, delta) in &deltas {
            let old: u64 = db.get_cf(cf_bal, addr.as_bytes())
                .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
            result.insert(addr.clone(), (old as i128 + delta).max(0) as u64);
        }
        result
    };
    let state_root = compute_state_delta_root(&balance_delta_for_root);

    let hash = block_hash_v3(&prev_hash, height, miner, timestamp, &tx_merkle_root, poc_ticket, &state_root);

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
        state_root,
    };

    (block, stamped)
}

pub fn commit_staged_block(block: &LedgerBlock, stamped: &[LedgerTx]) -> bool {
    let db = get_db().lock().expect("chain_db lock poisoned");
    let current_tip = {
        let cf_meta = db.cf_handle(CF_META).expect("CF_META missing");
        db.get_cf(cf_meta, META_LATEST_HEIGHT)
            .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0)
    };
    if block.height != current_tip + 1 {
        eprintln!(
            "[ChainDB] commit_staged_block: block #{} rejected — tip is #{} (already committed or stale)",
            block.height, current_tip
        );
        return false;
    }
    write_block_batch(&db, block, stamped);
    true
}

/// Verify that a block's hash field matches its contents.
/// Accepts v1 (legacy), v2 (tx_merkle_root), and v3 (+ state_root) formats.
/// Returns false if the block was tampered with after production.
pub fn verify_block_hash(block: &LedgerBlock, txs: &[crate::ledger::LedgerTx]) -> bool {
    // Recompute merkle root from the actual txs.
    let tx_hashes: Vec<&str> = txs.iter().map(|t| t.hash.as_str()).collect();
    let expected_merkle = compute_merkle_root(&tx_hashes);

    if !block.tx_merkle_root.is_empty() && block.tx_merkle_root != expected_merkle {
        eprintln!(
            "[ChainDB] Block #{} merkle root mismatch: stored={} computed={}",
            block.height, &block.tx_merkle_root[..8.min(block.tx_merkle_root.len())], &expected_merkle[..8]
        );
        return false;
    }

    // v1 hash (no domain tag, no merkle root) — legacy acceptance.
    let v1_input = format!("{}{}{}{}", block.prev_hash, block.height, block.miner, block.timestamp);
    let v1_hash  = blake3::hash(v1_input.as_bytes()).to_hex().to_string();
    if block.hash == v1_hash { return true; }

    // v2 hash (tx_merkle_root + poc_ticket, no state_root).
    let v2_hash = block_hash_for(
        &block.prev_hash, block.height, &block.miner,
        block.timestamp, &expected_merkle, &block.poc_ticket,
    );
    if block.hash == v2_hash { return true; }

    // v3 hash (+ state_root) — all new blocks use this format.
    if !block.state_root.is_empty() {
        let v3_hash = block_hash_v3(
            &block.prev_hash, block.height, &block.miner,
            block.timestamp, &expected_merkle, &block.poc_ticket,
            &block.state_root,
        );
        if block.hash == v3_hash { return true; }
        eprintln!(
            "[ChainDB] Block #{} v3 hash mismatch: stored={:.8} expected={:.8}",
            block.height, block.hash, v3_hash
        );
        return false;
    }

    eprintln!(
        "[ChainDB] Block #{} hash mismatch: stored={:.8} v2={:.8}",
        block.height, block.hash, v2_hash
    );
    false
}

/// Append a block received from a peer (gossip / sync path).
/// Fork choice: replaces existing block at the same height only if the new
/// block carries more BFT votes (heavier chain wins).
pub fn append_peer_block(block: &LedgerBlock, txs: &[LedgerTx]) {
    let db = get_db().lock().unwrap();
    write_block_batch(&db, block, txs);
}

pub fn truncate_from(height: u64) {
    if height == 0 { return; }
    let db = get_db().lock().unwrap();
    let cf_blocks = db.cf_handle(CF_BLOCKS).unwrap();
    let cf_meta   = db.cf_handle(CF_META).unwrap();
    let tip = db.get_cf(cf_meta, META_LATEST_HEIGHT)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
    if height > tip { return; }
    let mut batch = WriteBatch::default();
    for h in height..=tip {
        batch.delete_cf(cf_blocks, height_key(h));
    }
    let new_tip = height - 1;
    batch.put_cf(cf_meta, META_LATEST_HEIGHT, u64_le(new_tip));
    db.write(batch).expect("truncate write");
    eprintln!("[ChainDB] Reorg: truncated heights {}..={} (new tip: {})", height, tip, new_tip);
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

// ── Startup state restoration ─────────────────────────────────────────────────
//
// NONCE_STORE and STAKE_STORE are in-memory maps populated incrementally as new
// blocks arrive.  On restart they are empty, which would allow replay attacks and
// strip validators of their minimum-stake registration.  Restoring from the full
// TX history in RocksDB at startup fixes both problems in a single O(n) scan.

const STAKING_ADDR_RESTORE: &str = "egot1staking000000000000000000000000000000000";

/// Rebuild the in-memory nonce store and stake store by scanning every confirmed
/// transaction stored in RocksDB.  Call once at startup before accepting any
/// incoming P2P messages or local transactions.
pub fn restore_in_memory_state_from_db() {
    let db = get_db().lock().unwrap();
    let cf_txs = match db.cf_handle(CF_TXS) { Some(c) => c, None => return };

    let iter = db.full_iterator_cf(cf_txs, rocksdb::IteratorMode::Start);
    let mut nonce_max: std::collections::HashMap<String, u64> = Default::default();
    let mut stake_map: std::collections::HashMap<String, u64> = Default::default();

    for item in iter {
        let Ok((_, v)) = item else { continue };
        let tx: LedgerTx = match serde_json::from_slice(&v) { Ok(t) => t, Err(_) => continue };

        // ── Nonce store: track highest confirmed nonce per sender.
        if !tx.from.is_empty() && tx.nonce > 0 {
            let entry = nonce_max.entry(tx.from.clone()).or_insert(0);
            if tx.nonce > *entry { *entry = tx.nonce; }
        }

        // ── Stake store: replay stake/unstake transactions.
        if tx.to == STAKING_ADDR_RESTORE && !tx.from.is_empty() {
            *stake_map.entry(tx.from.clone()).or_insert(0) =
                stake_map.get(&tx.from).unwrap_or(&0).saturating_add(tx.amount);
        } else if tx.from == STAKING_ADDR_RESTORE && !tx.to.is_empty() {
            *stake_map.entry(tx.to.clone()).or_insert(0) =
                stake_map.get(&tx.to).unwrap_or(&0).saturating_sub(tx.amount);
        }
    }

    // Push into ledger stores.
    for (addr, nonce) in nonce_max {
        crate::ledger::record_confirmed_nonce(&addr, nonce);
    }
    for (addr, amount) in stake_map {
        if amount > 0 {
            crate::ledger::record_validator_stake(&addr, amount, true);
        }
    }
    eprintln!("[ChainDB] In-memory nonce + stake stores restored from RocksDB");
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

/// Minimum number of unique stake-voters for quorum.
const DAO_MIN_UNIQUE_VOTERS: usize = 3;
/// Minimum fraction of total network stake that must participate (1%).
const DAO_MIN_STAKE_FRACTION: f64 = 0.01;

/// True if the proposal has met quorum: at least DAO_MIN_UNIQUE_VOTERS distinct
/// addresses voted AND their combined stake ≥ 1% of total network stake.
/// This prevents a single whale or a handful of colluding nodes from unilaterally
/// passing governance decisions on an otherwise quiet network.
fn dao_quorum_reached(p: &DaoProposal, staked_in_votes: u64) -> bool {
    if p.stake_votes.len() < DAO_MIN_UNIQUE_VOTERS {
        return false;
    }
    let total_network = crate::ledger::total_network_stake();
    if total_network == 0 {
        // No validators staked yet (early testnet) — fall back to voter-count only.
        return p.stake_votes.len() >= DAO_MIN_UNIQUE_VOTERS;
    }
    let fraction = staked_in_votes as f64 / total_network as f64;
    fraction >= DAO_MIN_STAKE_FRACTION
}

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
        quorum_reached:         dao_quorum_reached(&p, total_stake),
        status:                 resolved_status(&p),
    })
}

// ── Proposer Ban System ───────────────────────────────────────────────────────

pub const PROPOSER_BAN_THRESHOLD: usize = 10;

fn ban_key(address: &str) -> Vec<u8> {
    let mut k = b"ban:".to_vec();
    k.extend_from_slice(address.as_bytes());
    k
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct ProposerBanRecord {
    pub target:   String,
    pub voters:   std::collections::HashSet<String>,
    pub banned:   bool,
    pub banned_at: Option<i64>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct ProposerBanStatus {
    pub target:     String,
    pub vote_count: usize,
    pub threshold:  usize,
    pub banned:     bool,
    pub my_vote:    bool,
}

/// Cast a removal vote against `target`. Returns updated status.
/// Returns Err if the voter tries to vote against themselves.
pub fn vote_remove_proposer(target: &str, voter: &str) -> Result<ProposerBanStatus, String> {
    if target == voter {
        return Err("You cannot vote to remove yourself".into());
    }
    let db = get_db().lock().unwrap();
    let cf = db.cf_handle(CF_DAO).ok_or("CF_DAO missing")?;
    let key = ban_key(target);

    let mut rec: ProposerBanRecord = db.get_cf(cf, &key)
        .ok().flatten()
        .and_then(|b| decode(&b))
        .unwrap_or_else(|| ProposerBanRecord {
            target:    target.to_string(),
            voters:    std::collections::HashSet::new(),
            banned:    false,
            banned_at: None,
        });

    if rec.voters.contains(voter) {
        return Err("You have already voted to remove this proposer".into());
    }

    rec.voters.insert(voter.to_string());
    if rec.voters.len() >= PROPOSER_BAN_THRESHOLD && !rec.banned {
        rec.banned    = true;
        rec.banned_at = Some(now_secs());
    }

    db.put_cf(cf, &key, encode(&rec)).map_err(|e| e.to_string())?;
    Ok(ProposerBanStatus {
        target:     rec.target,
        vote_count: rec.voters.len(),
        threshold:  PROPOSER_BAN_THRESHOLD,
        banned:     rec.banned,
        my_vote:    true,
    })
}

pub fn get_proposer_ban_status(target: &str, viewer: Option<&str>) -> ProposerBanStatus {
    let db = get_db().lock().unwrap();
    let cf = match db.cf_handle(CF_DAO) { Some(c) => c, None => {
        return ProposerBanStatus { target: target.to_string(), vote_count: 0, threshold: PROPOSER_BAN_THRESHOLD, banned: false, my_vote: false };
    }};
    let rec: Option<ProposerBanRecord> = db.get_cf(cf, ban_key(target))
        .ok().flatten().and_then(|b| decode(&b));
    match rec {
        None => ProposerBanStatus { target: target.to_string(), vote_count: 0, threshold: PROPOSER_BAN_THRESHOLD, banned: false, my_vote: false },
        Some(r) => {
            let my_vote = viewer.map(|v| r.voters.contains(v)).unwrap_or(false);
            ProposerBanStatus { target: r.target, vote_count: r.voters.len(), threshold: PROPOSER_BAN_THRESHOLD, banned: r.banned, my_vote }
        }
    }
}

pub fn is_proposer_banned(address: &str) -> bool {
    let db = get_db().lock().unwrap();
    let cf = match db.cf_handle(CF_DAO) { Some(c) => c, None => return false };
    db.get_cf(cf, ban_key(address))
        .ok().flatten()
        .and_then(|b| decode::<ProposerBanRecord>(&b))
        .map(|r| r.banned)
        .unwrap_or(false)
}

// ── Slashing persistence ───────────────────────────────────────────────────────
// Slashed-validator records survive node restarts via the CF_META column family.

const META_SLASHED: &[u8] = b"slashed_validators";

/// Persist a slashed validator address to RocksDB so the ban survives restarts.
pub fn persist_slashed_validator(addr: &str) {
    let db = get_db().lock().unwrap();
    let cf = match db.cf_handle(CF_META) { Some(c) => c, None => return };
    let mut set: Vec<String> = db.get_cf(cf, META_SLASHED)
        .ok().flatten()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    if !set.contains(&addr.to_string()) {
        set.push(addr.to_string());
        let _ = db.put_cf(cf, META_SLASHED,
            serde_json::to_vec(&set).unwrap_or_default());
    }
}

/// Load the full set of slashed validator addresses from RocksDB.
/// Called once at startup to restore the in-memory set.
pub fn load_slashed_validators() -> Vec<String> {
    let db = get_db().lock().unwrap();
    let cf = match db.cf_handle(CF_META) { Some(c) => c, None => return vec![] };
    db.get_cf(cf, META_SLASHED)
        .ok().flatten()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

// ── Pending-vote persistence (Item 6: BFT votes survive restart) ──────────────

const META_PENDING_VOTES_PREFIX: &[u8] = b"pvotes:";

/// Persist one pending (unfinalized) vote to RocksDB.
/// Key: `pvotes:{block_hash}:{voter_addr}` → empty value (presence = voted).
/// Called immediately after adding the vote to the in-memory map.
pub fn persist_pending_vote(block_hash: &str, voter: &str) {
    let db = get_db().lock().unwrap();
    let cf = match db.cf_handle(CF_META) { Some(c) => c, None => return };
    let key = format!("pvotes:{}:{}", block_hash, voter);
    let _ = db.put_cf(cf, key.as_bytes(), b"1");
}

/// Remove one persisted pending vote (called after the block is finalized
/// or the round is abandoned so stale entries don't accumulate).
pub fn clear_pending_vote(block_hash: &str, voter: &str) {
    let db = get_db().lock().unwrap();
    let cf = match db.cf_handle(CF_META) { Some(c) => c, None => return };
    let key = format!("pvotes:{}:{}", block_hash, voter);
    let _ = db.delete_cf(cf, key.as_bytes());
}

/// Remove ALL pending votes for a given block hash (called when a block
/// reaches quorum and is committed, or when the view times out).
pub fn clear_pending_votes_for_block(block_hash: &str) {
    let db = get_db().lock().unwrap();
    let cf = match db.cf_handle(CF_META) { Some(c) => c, None => return };
    let prefix = format!("pvotes:{}:", block_hash);
    // Collect all matching keys, then delete them.
    let mut keys_to_delete: Vec<Vec<u8>> = Vec::new();
    {
        let iter = db.prefix_iterator_cf(cf, prefix.as_bytes());
        for item in iter {
            if let Ok((k, _)) = item {
                if k.starts_with(prefix.as_bytes()) {
                    keys_to_delete.push(k.to_vec());
                } else {
                    break;
                }
            }
        }
    }
    let mut batch = WriteBatch::default();
    for k in &keys_to_delete {
        batch.delete_cf(cf, k);
    }
    let _ = db.write(batch);
}

// ── Nonce persistence ─────────────────────────────────────────────────────────
// Confirmed sender nonces are written into CF_META so they survive node restarts.
// Without persistence the in-memory NONCE_STORE resets to 0 on restart, making
// replay attacks trivial (resend any past signed TX).

const NONCE_KEY_PREFIX: &[u8] = b"nonce:";

/// Persist a confirmed nonce for an address.
/// Called from write_block_batch (in the same WriteBatch for atomicity).
pub fn persist_nonce_in_batch(batch: &mut WriteBatch, db: &DB, address: &str, nonce: u64) {
    let cf = match db.cf_handle(CF_META) { Some(c) => c, None => return };
    let mut key = NONCE_KEY_PREFIX.to_vec();
    key.extend_from_slice(address.as_bytes());
    // Only advance — never go backwards.
    let existing = db.get_cf(cf, &key).ok().flatten()
        .map(|v| read_u64_le(&v)).unwrap_or(0);
    if nonce > existing {
        batch.put_cf(cf, &key, u64_le(nonce));
    }
}

/// Restore all confirmed nonces from CF_META into the in-memory NONCE_STORE.
/// Must be called once at startup before accepting any transactions.
pub fn restore_nonces_from_db() {
    let db = get_db().lock().unwrap();
    let cf = match db.cf_handle(CF_META) { Some(c) => c, None => return };
    let iter = db.prefix_iterator_cf(cf, NONCE_KEY_PREFIX);
    for item in iter {
        if let Ok((k, v)) = item {
            let key_str = match std::str::from_utf8(&k) { Ok(s) => s, Err(_) => continue };
            if !key_str.starts_with("nonce:") { break; }
            let address = &key_str["nonce:".len()..];
            if address.is_empty() { continue; }
            let nonce = read_u64_le(&v);
            if nonce > 0 {
                crate::ledger::record_confirmed_nonce(address, nonce);
            }
        }
    }
}

/// Restore all pending votes from RocksDB into an in-memory map.
/// Returns `HashMap<block_hash, Vec<voter_addr>>`.
/// Called once at node startup so in-flight consensus rounds survive restarts.
pub fn restore_pending_votes_from_db() -> std::collections::HashMap<String, Vec<String>> {
    let db = get_db().lock().unwrap();
    let cf = match db.cf_handle(CF_META) { Some(c) => c, None => return Default::default() };
    let mut out: std::collections::HashMap<String, Vec<String>> = Default::default();
    let iter = db.prefix_iterator_cf(cf, META_PENDING_VOTES_PREFIX);
    for item in iter {
        if let Ok((k, _)) = item {
            let s = match std::str::from_utf8(&k) { Ok(s) => s, Err(_) => continue };
            if !s.starts_with("pvotes:") { break; }
            // key format: pvotes:{block_hash}:{voter}
            // block_hash itself may contain colons (hex is fine, but be safe)
            let without_prefix = &s["pvotes:".len()..];
            // voter is last 63 chars (bech32 addr), split from the right
            if let Some(colon_pos) = without_prefix.rfind(':') {
                let block_hash = &without_prefix[..colon_pos];
                let voter      = &without_prefix[colon_pos + 1..];
                if !block_hash.is_empty() && !voter.is_empty() {
                    out.entry(block_hash.to_string()).or_default().push(voter.to_string());
                }
            }
        }
    }
    out
}

// ── Web3 Hosting registry ─────────────────────────────────────────────────────

pub fn save_hosted_site(name: &str, data: &serde_json::Value) {
    let db = get_db().lock().unwrap();
    let cf = db.cf_handle(CF_HOSTING).unwrap();
    let _ = db.put_cf(&cf, name.as_bytes(), encode(data));
}

pub fn get_hosted_site_raw(name: &str) -> Option<serde_json::Value> {
    let db = get_db().lock().unwrap();
    let cf = db.cf_handle(CF_HOSTING).unwrap();
    db.get_cf(&cf, name.as_bytes()).ok()?.and_then(|b| decode(&b))
}

pub fn list_hosted_sites_raw(owner: &str) -> Vec<serde_json::Value> {
    let db = get_db().lock().unwrap();
    let cf = db.cf_handle(CF_HOSTING).unwrap();
    db.iterator_cf(&cf, rocksdb::IteratorMode::Start)
        .flatten()
        .filter_map(|(_, v)| decode::<serde_json::Value>(&v))
        .filter(|s| s["owner"].as_str() == Some(owner))
        .collect()
}

pub fn delete_hosted_site(name: &str) {
    let db = get_db().lock().unwrap();
    let cf = db.cf_handle(CF_HOSTING).unwrap();
    let _ = db.delete_cf(&cf, name.as_bytes());
}

// ── Hosting node registry ─────────────────────────────────────────────────────

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct HostingNodeRecord {
    pub node_id:   String,
    pub endpoint:  String,
    pub sites:     Vec<String>,
    pub domains:   Vec<String>,
    pub last_seen: i64,
}

pub fn upsert_hosting_node(record: &HostingNodeRecord) {
    let db = get_db().lock().unwrap();
    let cf = db.cf_handle(CF_HOSTING_NODES).unwrap();
    let _ = db.put_cf(&cf, record.node_id.as_bytes(), encode(record));
}

pub fn get_hosting_node(node_id: &str) -> Option<HostingNodeRecord> {
    let db = get_db().lock().unwrap();
    let cf = db.cf_handle(CF_HOSTING_NODES).unwrap();
    db.get_cf(&cf, node_id.as_bytes()).ok()?.and_then(|b| decode(&b))
}

pub fn list_hosting_nodes() -> Vec<HostingNodeRecord> {
    let db = get_db().lock().unwrap();
    let cf = db.cf_handle(CF_HOSTING_NODES).unwrap();
    db.iterator_cf(&cf, rocksdb::IteratorMode::Start)
        .flatten()
        .filter_map(|(_, v)| decode::<HostingNodeRecord>(&v))
        .collect()
}

pub fn get_nodes_for_domain(domain_or_slug: &str) -> Vec<HostingNodeRecord> {
    let target = domain_or_slug.to_lowercase();
    let cutoff  = chrono::Utc::now().timestamp() - 300;
    list_hosting_nodes()
        .into_iter()
        .filter(|n| n.last_seen >= cutoff)
        .filter(|n| n.sites.contains(&target) || n.domains.contains(&target))
        .collect()
}

pub fn prune_stale_hosting_nodes() {
    let cutoff = chrono::Utc::now().timestamp() - 600;
    let stale: Vec<String> = list_hosting_nodes()
        .into_iter()
        .filter(|n| n.last_seen < cutoff)
        .map(|n| n.node_id)
        .collect();
    let db = get_db().lock().unwrap();
    let cf = db.cf_handle(CF_HOSTING_NODES).unwrap();
    for id in stale {
        let _ = db.delete_cf(&cf, id.as_bytes());
    }
}

