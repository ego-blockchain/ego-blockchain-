//! SQLite-backed chain storage — replaces chain.json for production throughput.
//!
//! Design goals:
//! - O(1) per-block write regardless of chain length (was O(N) with chain.json)
//! - WAL mode: concurrent reads never block the write path
//! - One-time migration: imports existing chain.json on first boot
//! - Backward-compatible: `load_chain()` still returns SharedChain (last 2000 entries)
//! - `mine_batch_db()` is the hot path — no full-chain load, no full-chain save

use rusqlite::{params, Connection};
use std::sync::{Mutex, OnceLock};

use crate::ledger::{
    base_data_dir, LedgerBlock, LedgerTx, SharedChain, GENESIS_HASH, GENESIS_MINER, GENESIS_TS,
};

// ── Global connection ─────────────────────────────────────────────────────────

static CHAIN_DB: OnceLock<Mutex<Connection>> = OnceLock::new();

pub fn get_db() -> &'static Mutex<Connection> {
    CHAIN_DB.get_or_init(|| {
        let path = base_data_dir().join("chain.db");
        let conn = Connection::open(&path).expect("open chain.db");
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA cache_size=-65536;
             PRAGMA temp_store=MEMORY;
             PRAGMA mmap_size=268435456;",
        )
        .expect("chain.db pragma");
        init_schema(&conn);
        migrate_json(&conn);
        Mutex::new(conn)
    })
}

// ── Schema ────────────────────────────────────────────────────────────────────

fn init_schema(conn: &Connection) {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS blocks (
            height       INTEGER PRIMARY KEY,
            hash         TEXT    NOT NULL,
            prev_hash    TEXT    NOT NULL,
            miner        TEXT    NOT NULL DEFAULT '',
            timestamp    INTEGER NOT NULL,
            tx_count     INTEGER NOT NULL DEFAULT 0,
            size_bytes   INTEGER NOT NULL DEFAULT 0,
            reward       INTEGER NOT NULL DEFAULT 0,
            finalized    INTEGER NOT NULL DEFAULT 1,
            coinbase_tx  TEXT
        );
        CREATE TABLE IF NOT EXISTS transactions (
            hash          TEXT    PRIMARY KEY,
            block_height  INTEGER,
            from_addr     TEXT    NOT NULL DEFAULT '',
            to_addr       TEXT    NOT NULL DEFAULT '',
            amount        INTEGER NOT NULL DEFAULT 0,
            memo          TEXT,
            timestamp     INTEGER NOT NULL DEFAULT 0,
            signature     TEXT    NOT NULL DEFAULT '',
            status        TEXT    NOT NULL DEFAULT 'Confirmed',
            nonce         INTEGER NOT NULL DEFAULT 0,
            pub_key_ed    TEXT    NOT NULL DEFAULT '',
            dil_pubkey    TEXT    NOT NULL DEFAULT '',
            dil_sig       TEXT    NOT NULL DEFAULT '',
            tx_type       TEXT    NOT NULL DEFAULT 'transfer',
            wasm_code     TEXT    NOT NULL DEFAULT '',
            contract_addr TEXT    NOT NULL DEFAULT '',
            entrypoint    TEXT    NOT NULL DEFAULT '',
            call_args     TEXT    NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_tx_block ON transactions(block_height);
        CREATE INDEX IF NOT EXISTS idx_tx_from  ON transactions(from_addr);
        CREATE INDEX IF NOT EXISTS idx_tx_to    ON transactions(to_addr);
        CREATE INDEX IF NOT EXISTS idx_blk_ts   ON blocks(timestamp);",
    )
    .expect("chain.db schema");
}

// ── One-time migration from chain.json ───────────────────────────────────────

fn migrate_json(conn: &Connection) {
    // If DB already has blocks, migration was done.
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM blocks", [], |r| r.get(0))
        .unwrap_or(0);
    if count > 0 {
        return;
    }

    let json_path = base_data_dir().join("chain.json");
    if json_path.exists() {
        if let Ok(data) = std::fs::read_to_string(&json_path) {
            if let Ok(chain) = serde_json::from_str::<SharedChain>(&data) {
                eprintln!(
                    "[ChainDB] Migrating chain.json → chain.db ({} blocks, {} txs)…",
                    chain.blocks.len(),
                    chain.transactions.len()
                );
                conn.execute_batch("BEGIN").unwrap();
                for b in &chain.blocks {
                    let _ = conn.execute(
                        "INSERT OR IGNORE INTO blocks \
                         (height,hash,prev_hash,miner,timestamp,tx_count,size_bytes,reward,finalized,coinbase_tx) \
                         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,1,?9)",
                        params![
                            b.height as i64, &b.hash, &b.prev_hash, &b.miner,
                            b.timestamp, b.tx_count as i64, b.size_bytes as i64,
                            b.reward as i64, b.coinbase_tx.as_deref()
                        ],
                    );
                }
                for t in &chain.transactions {
                    let _ = conn.execute(
                        "INSERT OR IGNORE INTO transactions \
                         (hash,block_height,from_addr,to_addr,amount,memo,timestamp,\
                          signature,status,nonce,pub_key_ed,dil_pubkey,dil_sig,\
                          tx_type,wasm_code,contract_addr,entrypoint,call_args) \
                         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
                        params![
                            &t.hash, t.block_height.map(|h| h as i64),
                            &t.from, &t.to, t.amount as i64, t.memo.as_deref(),
                            t.timestamp, &t.signature, &t.status, t.nonce as i64,
                            &t.public_key_ed25519, &t.dilithium_pubkey, &t.dilithium_signature,
                            &t.tx_type, &t.wasm_code, &t.contract_addr,
                            &t.entrypoint, &t.call_args
                        ],
                    );
                }
                conn.execute_batch("COMMIT").unwrap();
                eprintln!("[ChainDB] Migration complete.");
                return;
            }
        }
    }

    // No chain.json — seed genesis block.
    let _ = conn.execute(
        "INSERT OR IGNORE INTO blocks \
         (height,hash,prev_hash,miner,timestamp,tx_count,size_bytes,reward,finalized) \
         VALUES (0,?1,'0000000000000000000000000000000000000000000000000000000000000000',?2,?3,0,0,0,1)",
        params![GENESIS_HASH, GENESIS_MINER, GENESIS_TS],
    );
}

// ── Read helpers ──────────────────────────────────────────────────────────────

/// Latest (height, hash) — O(1) index seek.
pub fn latest_block_info() -> (u64, String) {
    let db = get_db();
    let conn = db.lock().unwrap();
    conn.query_row(
        "SELECT height, hash FROM blocks ORDER BY height DESC LIMIT 1",
        [],
        |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?)),
    )
    .unwrap_or((0, GENESIS_HASH.to_string()))
}

/// Total number of blocks in the chain.
pub fn block_count() -> u64 {
    let db = get_db();
    let conn = db.lock().unwrap();
    conn.query_row("SELECT COUNT(*) FROM blocks", [], |r| r.get::<_, i64>(0))
        .unwrap_or(0) as u64
}

/// Total number of confirmed transactions.
pub fn tx_count() -> u64 {
    let db = get_db();
    let conn = db.lock().unwrap();
    conn.query_row("SELECT COUNT(*) FROM transactions", [], |r| r.get::<_, i64>(0))
        .unwrap_or(0) as u64
}

/// Balance of `address` across ALL confirmed transactions — single SQL query.
pub fn balance_of(address: &str) -> u64 {
    let db = get_db();
    let conn = db.lock().unwrap();
    let incoming: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(amount),0) FROM transactions WHERE to_addr=?1 AND status='Confirmed'",
            [address],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let outgoing: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(amount),0) FROM transactions WHERE from_addr=?1 AND status='Confirmed'",
            [address],
            |r| r.get(0),
        )
        .unwrap_or(0);
    (incoming - outgoing).max(0) as u64
}

/// Load the most recent `limit` blocks (descending height).
pub fn recent_blocks(limit: usize) -> Vec<LedgerBlock> {
    let db = get_db();
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT height,hash,prev_hash,miner,timestamp,tx_count,size_bytes,reward,coinbase_tx \
             FROM blocks ORDER BY height DESC LIMIT ?1",
        )
        .unwrap();
    stmt.query_map([limit as i64], |r| {
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
    })
    .unwrap()
    .filter_map(|r| r.ok())
    .collect()
}

/// Load the most recent `limit` transactions (descending timestamp).
pub fn recent_transactions(limit: usize) -> Vec<LedgerTx> {
    let db = get_db();
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT hash,block_height,from_addr,to_addr,amount,memo,timestamp,\
                    signature,status,nonce,pub_key_ed,dil_pubkey,dil_sig,\
                    tx_type,wasm_code,contract_addr,entrypoint,call_args \
             FROM transactions ORDER BY timestamp DESC LIMIT ?1",
        )
        .unwrap();
    stmt.query_map([limit as i64], |r| {
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
    })
    .unwrap()
    .filter_map(|r| r.ok())
    .collect()
}

/// Build a SharedChain view from the last 2000 blocks/txs (for code that still uses SharedChain).
pub fn load_shared_chain() -> SharedChain {
    SharedChain {
        blocks:       recent_blocks(2000),
        transactions: recent_transactions(2000),
    }
}

// ── Write — hot path ──────────────────────────────────────────────────────────

/// Mine a new block directly into SQLite. O(1) per block, no chain.json.
///
/// This is the high-throughput path: one atomic transaction inserts the block
/// header + all TXs.  No SharedChain is loaded or saved.
pub fn mine_batch_db(txs: &[LedgerTx], miner: &str) -> LedgerBlock {
    let db = get_db();
    let conn = db.lock().unwrap();

    let (latest_height, prev_hash) = {
        conn.query_row(
            "SELECT height, hash FROM blocks ORDER BY height DESC LIMIT 1",
            [],
            |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?)),
        )
        .unwrap_or((0, GENESIS_HASH.to_string()))
    };

    let height    = latest_height + 1;
    let timestamp = chrono::Utc::now().timestamp();
    let reward    = crate::tokenomics::block_reward_at(height);

    // BLAKE3 hash: prev_hash ‖ height ‖ miner ‖ timestamp
    let hash_input = format!("{prev_hash}{height}{miner}{timestamp}");
    let hash = blake3::hash(hash_input.as_bytes()).to_hex().to_string();

    let block = LedgerBlock {
        height,
        hash: hash.clone(),
        prev_hash,
        miner: miner.to_string(),
        timestamp,
        tx_count:   txs.len() as u32,
        size_bytes: txs.len() as u64 * 256,
        reward,
        coinbase_tx: None,
    };

    // Atomic insert: block + all TXs in one transaction
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();

    let _ = conn.execute(
        "INSERT OR REPLACE INTO blocks \
         (height,hash,prev_hash,miner,timestamp,tx_count,size_bytes,reward,finalized) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,1)",
        params![
            height as i64, &block.hash, &block.prev_hash, miner,
            timestamp, block.tx_count as i64, block.size_bytes as i64, reward as i64
        ],
    );

    for tx in txs {
        let _ = conn.execute(
            "INSERT OR IGNORE INTO transactions \
             (hash,block_height,from_addr,to_addr,amount,memo,timestamp,\
              signature,status,nonce,pub_key_ed,dil_pubkey,dil_sig,\
              tx_type,wasm_code,contract_addr,entrypoint,call_args) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'Confirmed',?9,?10,?11,?12,?13,?14,?15,?16,?17)",
            params![
                &tx.hash, height as i64, &tx.from, &tx.to, tx.amount as i64,
                tx.memo.as_deref(), tx.timestamp, &tx.signature, tx.nonce as i64,
                &tx.public_key_ed25519, &tx.dilithium_pubkey, &tx.dilithium_signature,
                &tx.tx_type, &tx.wasm_code, &tx.contract_addr,
                &tx.entrypoint, &tx.call_args
            ],
        );
    }

    conn.execute_batch("COMMIT").unwrap();

    block
}

/// Append a block received from a peer (sync path).
pub fn append_peer_block(block: &LedgerBlock, txs: &[LedgerTx]) {
    let db = get_db();
    let conn = db.lock().unwrap();
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    let _ = conn.execute(
        "INSERT OR IGNORE INTO blocks \
         (height,hash,prev_hash,miner,timestamp,tx_count,size_bytes,reward,finalized,coinbase_tx) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,1,?9)",
        params![
            block.height as i64, &block.hash, &block.prev_hash, &block.miner,
            block.timestamp, block.tx_count as i64, block.size_bytes as i64,
            block.reward as i64, block.coinbase_tx.as_deref()
        ],
    );
    for tx in txs {
        let _ = conn.execute(
            "INSERT OR IGNORE INTO transactions \
             (hash,block_height,from_addr,to_addr,amount,memo,timestamp,\
              signature,status,nonce,pub_key_ed,dil_pubkey,dil_sig,\
              tx_type,wasm_code,contract_addr,entrypoint,call_args) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
            params![
                &tx.hash, block.height as i64, &tx.from, &tx.to, tx.amount as i64,
                tx.memo.as_deref(), tx.timestamp, &tx.signature, &tx.status, tx.nonce as i64,
                &tx.public_key_ed25519, &tx.dilithium_pubkey, &tx.dilithium_signature,
                &tx.tx_type, &tx.wasm_code, &tx.contract_addr,
                &tx.entrypoint, &tx.call_args
            ],
        );
    }
    conn.execute_batch("COMMIT").unwrap();
}

// ── BFT pipeline — mark blocks finalized ─────────────────────────────────────

/// In pipelined HotStuff, block N is finalized when block N+2 is committed.
/// This function marks all blocks up to `commit_height - 2` as finalized.
/// In single-node mode, everything is finalized immediately (finalized=1 at insert).
pub fn pipeline_commit(commit_height: u64) {
    if commit_height < 2 { return; }
    let finalize_up_to = commit_height - 2;
    let db = get_db();
    let conn = db.lock().unwrap();
    let _ = conn.execute(
        "UPDATE blocks SET finalized=1 WHERE height <= ?1 AND finalized=0",
        [finalize_up_to as i64],
    );
}
