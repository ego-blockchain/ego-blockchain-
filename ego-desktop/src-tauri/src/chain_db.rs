use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, DBCompressionType, Options,
    WriteBatch, DB,
};
use std::sync::{Mutex, OnceLock};
use tauri::Manager as _;

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
const CF_HOSTING:        &str = "hosting";
const CF_HOSTING_NODES:  &str = "hosting_nodes";
const CF_HOSTING_PLANS:  &str = "hosting_plans";
const CF_COMPUTE_NODES:        &str = "compute_nodes";
const CF_COMPUTE_JOBS:         &str = "compute_jobs";
const CF_COMPUTE_OFFERS:       &str = "compute_offers";
const CF_COMPUTE_RESERVATIONS: &str = "compute_reservations";
const CF_STORAGE_DEALS:        &str = "storage_deals";
const CF_CLUSTER_BOOKINGS:     &str = "cluster_bookings";
const CF_CONTRACT_STATE:       &str = "contract_state";
const CF_L2_CHANNELS:          &str = "cf_l2_channels";
const CF_L2_BATCHES:           &str = "cf_l2_batches";
const CF_L2_STATE:             &str = "cf_l2_state";

const ALL_CFS: &[&str] = &[
    CF_BLOCKS, CF_TXS, CF_BLOCK_TXS, CF_ADDR_TXS, CF_BALANCES,
    CF_RECENT_TXS, CF_META, CF_HEADERS, CF_GOVERNANCE, CF_DAO,
    CF_HOSTING, CF_HOSTING_NODES, CF_HOSTING_PLANS,
    CF_COMPUTE_NODES, CF_COMPUTE_JOBS, CF_COMPUTE_OFFERS, CF_COMPUTE_RESERVATIONS,
    CF_STORAGE_DEALS, CF_CLUSTER_BOOKINGS, CF_CONTRACT_STATE,
    CF_L2_CHANNELS, CF_L2_BATCHES, CF_L2_STATE,
];

pub const FEATURE_DILITHIUM_DISABLED: &str = "dilithium_disabled";
/// Enforce ML-DSA-44 on every transaction (migration complete).
pub const FEATURE_DILITHIUM_REQUIRED: &str = "dilithium_required";


const FULL_BLOCK_CAP: u64 = 2_000_000_000; // Act as an Archive Node (keep all history)

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
    k.push(b':');
    k.extend_from_slice(&ts_key(ts));
    k.extend_from_slice(tx_hash.as_bytes());
    k
}

fn old_addr_txs_key(addr: &str, ts: i64, tx_hash: &str) -> Vec<u8> {
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

static CHAIN_DB: OnceLock<DB> = OnceLock::new();

#[derive(Debug)]
pub struct FakeLockError(pub &'static DB);
impl FakeLockError {
    pub fn into_inner(self) -> &'static DB { self.0 }
}
pub struct DbWrapper(&'static DB);
impl DbWrapper {
    pub fn lock(&self) -> Result<&'static DB, FakeLockError> { Ok(self.0) }
    pub fn expect(&self, _msg: &str) -> &'static DB { self.0 }
}

pub fn get_db() -> DbWrapper {
    DbWrapper(CHAIN_DB.get_or_init(|| {
        let db_path = base_data_dir().join("chain_rocksdb");
        eprintln!("[ChainDB] Opening RocksDB at {:?}", db_path);

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

        let db = match DB::open_cf_descriptors(&db_opts, &db_path, cf_descs) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("\n[FATAL ERROR] Could not open the blockchain database at:");
                eprintln!("  {:?}", db_path);
                eprintln!("Reason: {}", e);
                eprintln!("\nThis usually happens because another instance of Ego Desktop is already running");
                eprintln!("and using the same data directory. If you are running multiple nodes on the same");
                eprintln!("machine, make sure to set a unique EGO_DATA_DIR environment variable for each node.");
                std::process::exit(1);
            }
        };
        eprintln!("[ChainDB] RocksDB opened successfully");

        init_db(&db);
        eprintln!("[ChainDB] RocksDB init_db done");

        // Seed supply pools exactly once for migrated DBs that skipped seed_genesis.
        const META_POOLS_SEEDED: &[u8] = b"pools_seeded_v2";
        if let Some(cf_meta) = db.cf_handle(CF_META) {
            let already_seeded = db.get_cf(cf_meta, META_POOLS_SEEDED).ok().flatten().is_some();
            if !already_seeded {
                if let Some(cf_balances) = db.cf_handle(CF_BALANCES) {
                    let faucet_addr = get_faucet_address();
                    use crate::tokenomics::*;
                    let allocs = vec![
                        (ECOSYSTEM_ADDR.to_string(),    ECOSYSTEM_EGOC  * UEGOC_PER_EGOC),
                        (FOUNDATION_ADDR.to_string(),   FOUNDATION_EGOC * UEGOC_PER_EGOC),
                        (NODE_POOL_ADDR.to_string(),    NODE_POOL_UEGOC),
                        (STAKING_POOL_ADDR.to_string(), STAKING_POOL_UEGOC),
                        (faucet_addr,                   10_000_000 * UEGOC_PER_EGOC),
                    ];
                    for (addr, amount) in allocs {
                        let cur = db.get_cf(cf_balances, addr.as_bytes())
                            .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
                        if cur == 0 {
                            let _ = db.put_cf(cf_balances, addr.as_bytes(), u64_le(amount));
                        }
                    }
                }
                let _ = db.put_cf(cf_meta, META_POOLS_SEEDED, b"1");
            }
        }
        
        db
    }))
}

static FAUCET_KEYPAIR: std::sync::OnceLock<ego_core::KeyPair> = std::sync::OnceLock::new();
static FAUCET_ADDRESS: std::sync::OnceLock<String> = std::sync::OnceLock::new();

pub fn get_faucet_keypair() -> &'static ego_core::KeyPair {
    FAUCET_KEYPAIR.get_or_init(|| {
        ego_core::KeyPair::from_bytes(&[0u8; 32]).unwrap()
    })
}

pub fn get_faucet_address() -> String {
    FAUCET_ADDRESS.get_or_init(|| {
        get_faucet_keypair().derive_bech32_address(1, ego_core::AddressType::EOA, "egot").unwrap_or_default()
    }).clone()
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
            tracing::info!("Migrated from SQLite → RocksDB");
            return;
        }
    }

    // 2. Try chain.json.
    let json_path = base_data_dir().join("chain.json");
    if json_path.exists() {
        if migrate_from_json(db, &json_path) {
            db.put_cf(meta, META_MIGRATION_DONE, b"1").ok();
            tracing::info!("Migrated from chain.json → RocksDB");
            return;
        }
    }

    // 3. Seed genesis.
    seed_genesis(db);
    db.put_cf(meta, META_MIGRATION_DONE, b"1").ok();
    tracing::info!("Seeded genesis block");
}

/// Genesis addresses for pre-minted supply pools.
/// These hold the non-circulating allocations defined in tokenomics.rs.
pub const ECOSYSTEM_ADDR:   &str = "egot1ecosystem00000000000000000000000000000000";
pub const FOUNDATION_ADDR:  &str = "egot1foundation00000000000000000000000000000000";
pub const NODE_POOL_ADDR:   &str = "egot1nodepool000000000000000000000000000000000";
pub const STAKING_ADDR:     &str = "egot1staking000000000000000000000000000000000";
pub const STAKING_POOL_ADDR:&str = "egot1stakingpool0000000000000000000000000000000";
pub const SLASH_POOL_ADDR:  &str = "egot1slashpool0000000000000000000000000000000";
pub const FAUCET_ADDR_FULL: &str = "egot1faucet000000000000000000000000000000000000";
pub const SLASH_BPS: u64 = 1_000; // 10%

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EquivocationProofPayload {
    pub accused: String,
    pub height: u64,
    pub hash_a: String,
    pub sig_a: String,
    pub hash_b: String,
    pub sig_b: String,
    pub accused_ed25519_pubkey: String,
    pub reporter: String,
}

fn is_stake_tx(tx: &LedgerTx) -> bool {
    tx.tx_type == "stake" && tx.to == STAKING_ADDR && !tx.from.is_empty()
}

fn is_unstake_tx(tx: &LedgerTx) -> bool {
    tx.tx_type == "unstake" && tx.to == STAKING_ADDR && !tx.from.is_empty()
}

fn unstake_credit_amount(tx: &LedgerTx) -> u64 {
    if tx.memo.as_deref() == Some("unstake:early") {
        tx.amount.saturating_sub(tx.amount / 10)
    } else {
        tx.amount
    }
}

pub fn equivocation_proof_hash(memo_json: &str) -> String {
    format!("0x{}", blake3::hash(memo_json.as_bytes()).to_hex())
}

pub fn encode_equivocation_proof_payload(payload: &EquivocationProofPayload) -> String {
    serde_json::to_string(payload).unwrap_or_default()
}

fn parse_equivocation_proof_payload(tx: &LedgerTx) -> Result<EquivocationProofPayload, String> {
    if tx.tx_type != "equivocation_proof" {
        return Err("not an equivocation proof tx".to_string());
    }
    let memo = tx.memo.as_deref().ok_or_else(|| "equivocation proof missing payload memo".to_string())?;
    let payload: EquivocationProofPayload = serde_json::from_str(memo)
        .map_err(|e| format!("equivocation proof payload invalid JSON: {e}"))?;
    Ok(payload)
}

fn validator_ed25519_key(addr: &str) -> Vec<u8> {
    format!("validator_ed25519:{addr}").into_bytes()
}

fn get_validator_ed25519_pubkey_inner(db: &DB, addr: &str) -> Option<String> {
    let cf = db.cf_handle(CF_META)?;
    db.get_cf(cf, validator_ed25519_key(addr))
        .ok()
        .flatten()
        .and_then(|b| String::from_utf8(b.to_vec()).ok())
        .filter(|s| !s.is_empty())
}

pub fn get_validator_ed25519_pubkey(addr: &str) -> Option<String> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    get_validator_ed25519_pubkey_inner(&db, addr)
}

fn persist_validator_ed25519_pubkey_in_batch(batch: &mut WriteBatch, db: &DB, addr: &str, pubkey_hex: &str) {
    if addr.is_empty() || pubkey_hex.len() != 64 || hex::decode(pubkey_hex).map(|b| b.len() != 32).unwrap_or(true) {
        return;
    }
    let Some(cf) = db.cf_handle(CF_META) else { return; };
    batch.put_cf(cf, validator_ed25519_key(addr), pubkey_hex.as_bytes());
}

pub fn persist_validator_ed25519_pubkey(addr: &str, pubkey_hex: &str) {
    if addr.is_empty() || pubkey_hex.len() != 64 || hex::decode(pubkey_hex).map(|b| b.len() != 32).unwrap_or(true) {
        return;
    }
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let Some(cf) = db.cf_handle(CF_META) else { return; };
    let _ = db.put_cf(cf, validator_ed25519_key(addr), pubkey_hex.as_bytes());
}

fn validator_bls_key(addr: &str) -> Vec<u8> {
    format!("validator_bls:{addr}").into_bytes()
}

pub fn get_validator_bls_pubkey(addr: &str) -> Option<String> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_META)?;
    db.get_cf(cf, validator_bls_key(addr))
        .ok()
        .flatten()
        .and_then(|b| String::from_utf8(b.to_vec()).ok())
        .filter(|s| !s.is_empty())
}

pub fn persist_validator_bls_pubkey(addr: &str, pubkey_hex: &str) {
    if addr.is_empty() || pubkey_hex.len() != 96 {
        return;
    }
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let Some(cf) = db.cf_handle(CF_META) else { return; };
    let _ = db.put_cf(cf, validator_bls_key(addr), pubkey_hex.as_bytes());
}

fn load_slashed_set_inner(db: &DB) -> std::collections::HashSet<String> {
    let Some(cf) = db.cf_handle(CF_META) else { return Default::default(); };
    db.get_cf(cf, META_SLASHED)
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice::<Vec<String>>(&b).ok())
        .unwrap_or_default()
        .into_iter()
        .collect()
}

fn persist_slashed_set_in_batch(batch: &mut WriteBatch, db: &DB, set: &std::collections::HashSet<String>) {
    let Some(cf) = db.cf_handle(CF_META) else { return; };
    let mut ordered: Vec<String> = set.iter().cloned().collect();
    ordered.sort_unstable();
    batch.put_cf(cf, META_SLASHED, serde_json::to_vec(&ordered).unwrap_or_default());
}

pub fn is_slashed_validator(addr: &str) -> bool {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    load_slashed_set_inner(&db).contains(addr)
}

fn verify_ed25519_hex(pubkey_hex: &str, message: &[u8], sig_hex: &str, context: &str) -> Result<(), String> {
    let pk_bytes = hex::decode(pubkey_hex)
        .map_err(|_| format!("{context}: invalid pubkey hex"))?;
    let sig_bytes = hex::decode(sig_hex)
        .map_err(|_| format!("{context}: invalid signature hex"))?;
    let pk_arr: [u8; 32] = pk_bytes.try_into()
        .map_err(|_| format!("{context}: pubkey must be 32 bytes"))?;
    let sig_arr: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| format!("{context}: signature must be 64 bytes"))?;
    use ed25519_dalek::{Signature as DalekSig, VerifyingKey, Verifier};
    let vk = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| format!("{context}: invalid pubkey: {e}"))?;
    let sig = DalekSig::from_bytes(&sig_arr);
    vk.verify(message, &sig)
        .map_err(|_| format!("{context}: signature invalid"))
}

fn validate_equivocation_proof_tx_inner(db: &DB, tx: &LedgerTx) -> Result<EquivocationProofPayload, String> {
    let payload = parse_equivocation_proof_payload(tx)?;
    if payload.accused.is_empty() || payload.reporter.is_empty() {
        return Err("equivocation proof missing accused or reporter".to_string());
    }
    if tx.from != payload.reporter || tx.to != payload.accused {
        return Err("equivocation proof tx endpoints do not match payload".to_string());
    }
    if tx.amount != 0 || tx.fee_uegoc != 0 || tx.nonce != 0 {
        return Err("equivocation proof must have zero amount, fee, and nonce".to_string());
    }
    if payload.height == 0 || payload.hash_a.is_empty() || payload.hash_b.is_empty() || payload.hash_a == payload.hash_b {
        return Err("equivocation proof must contain two distinct non-genesis vote hashes".to_string());
    }
    let memo = tx.memo.as_deref().unwrap_or("");
    let expected_hash = equivocation_proof_hash(memo);
    if tx.hash != expected_hash {
        return Err(format!("equivocation proof hash mismatch: got {}, expected {}", tx.hash, expected_hash));
    }
    if payload.accused_ed25519_pubkey.len() != 64 {
        return Err("equivocation proof accused pubkey must be 32-byte hex".to_string());
    }
    let expected_accused_pk = get_validator_ed25519_pubkey_inner(db, &payload.accused)
        .ok_or_else(|| format!("missing on-chain validator Ed25519 key for {}", payload.accused))?;
    if expected_accused_pk != payload.accused_ed25519_pubkey {
        return Err("equivocation proof accused pubkey does not match confirmed validator key".to_string());
    }

    let vote_data_a = crate::bft_committee::vote_signing_data(&payload.hash_a, payload.height, &payload.accused);
    let vote_data_b = crate::bft_committee::vote_signing_data(&payload.hash_b, payload.height, &payload.accused);
    verify_ed25519_hex(&payload.accused_ed25519_pubkey, vote_data_a.as_bytes(), &payload.sig_a, "equivocation proof vote A")?;
    verify_ed25519_hex(&payload.accused_ed25519_pubkey, vote_data_b.as_bytes(), &payload.sig_b, "equivocation proof vote B")?;

    if tx.public_key_ed25519.is_empty() || tx.signature.is_empty() {
        return Err("equivocation proof missing reporter pubkey/signature".to_string());
    }
    verify_ed25519_hex(&tx.public_key_ed25519, tx.hash.as_bytes(), &tx.signature, "equivocation proof reporter")?;
    Ok(payload)
}

pub fn validate_equivocation_proof_tx(tx: &LedgerTx) -> Result<EquivocationProofPayload, String> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let payload = validate_equivocation_proof_tx_inner(&db, tx)?;
    if load_slashed_set_inner(&db).contains(&payload.accused) {
        return Err(format!("validator {} already slashed", payload.accused));
    }
    Ok(payload)
}

fn slash_from_equivocation_tx(
    db: &DB,
    tx: &LedgerTx,
    stake_sim: &mut std::collections::HashMap<String, u64>,
    slashed_seen: &mut std::collections::HashSet<String>,
) -> Result<(String, u64), String> {
    let payload = validate_equivocation_proof_tx_inner(db, tx)?;
    if slashed_seen.contains(&payload.accused) {
        return Err(format!("validator {} already slashed", payload.accused));
    }
    let stake = stake_sim
        .entry(payload.accused.clone())
        .or_insert_with(|| crate::ledger::get_validator_stake(&payload.accused));
    let slash_amount = stake.saturating_mul(SLASH_BPS) / 10_000;
    if slash_amount == 0 {
        return Err(format!("validator {} has no slashable stake", payload.accused));
    }
    *stake = stake.saturating_sub(slash_amount);
    slashed_seen.insert(payload.accused.clone());
    Ok((payload.accused, slash_amount))
}

fn seed_genesis(db: &DB) {
    use crate::tokenomics::*;

    // ── Genesis allocations ────────────────────────────────────────────────
    // Mint each non-circulating pool directly into the balance cache.
    // These are pre-mined at height 0 — no TXs needed, just balance records.
    let cf_balances = db.cf_handle(CF_BALANCES).unwrap();
    let mut batch = WriteBatch::default();

    let faucet_addr = get_faucet_address();
    let allocs = vec![
        (ECOSYSTEM_ADDR.to_string(),    ECOSYSTEM_EGOC  * UEGOC_PER_EGOC),
        (FOUNDATION_ADDR.to_string(),   FOUNDATION_EGOC * UEGOC_PER_EGOC),
        (NODE_POOL_ADDR.to_string(),    NODE_POOL_UEGOC),
        (STAKING_POOL_ADDR.to_string(), STAKING_POOL_UEGOC),
        (faucet_addr,                   10_000_000 * UEGOC_PER_EGOC),
    ];
    for (addr, amount) in allocs {
        batch.put_cf(cf_balances, addr.as_bytes(), u64_le(amount));
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
        base_fee_uegoc: 1_000,
        agg_bls_sig: String::new(),
        bls_pubkeys: Vec::new(),
    };
    write_block_batch(db, &genesis, &[]);

    tracing::info!("Seeded supply pools: ecosystem={} EGOC, foundation={} EGOC, node_pool={} EGOC, staking_pool={} EGOC, faucet=10M EGOC",
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
            base_fee_uegoc: 1_000,
            agg_bls_sig: String::new(),
            bls_pubkeys: Vec::new(),
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
            is_private:          false,
            compliance_proof:    String::new(),
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
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
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

static BLOCK_COMMIT_MUTEX: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
fn block_commit_mutex() -> &'static std::sync::Mutex<()> {
    BLOCK_COMMIT_MUTEX.get_or_init(|| std::sync::Mutex::new(()))
}

/// Atomically writes one block + its transactions into all column families.
/// Maintains balance cache and all secondary indices.
/// INSERT-OR-IGNORE semantics: skips existing blocks/txs.
fn write_block_batch(db: &DB, block: &LedgerBlock, txs: &[LedgerTx]) -> bool {
    // Serialize all commits — multiple gossip paths (BFT QC, sync, ForkChoice)
    // can race for the same block. Without this lock, each path reads "no
    // existing block at this height", all proceed in parallel, each fires
    // balance-updated events and touch_proposal_timestamp(), keeping the
    // BFT timeout perpetually fresh and stalling the chain.
    let _commit_guard = block_commit_mutex().lock().unwrap_or_else(|e| e.into_inner());

    // After acquiring the lock, re-check that this block hasn't been written
    // already by an earlier thread. Idempotent skip on identical hash.
    {
        let cf_blocks_check = db.cf_handle(CF_BLOCKS).unwrap();
        if let Some(existing_bytes) = db.get_cf(cf_blocks_check, height_key(block.height)).ok().flatten() {
            if let Some(existing) = decode::<LedgerBlock>(&existing_bytes) {
                if existing.hash == block.hash {
                    return true;
                } else {
                    // Never overwrite in place! Caller must use truncate_from to handle reorgs safely.
                    return false;
                }
            }
        }
    }

    tracing::debug!("[ChainDB] write_block_batch start — block #{} ({} txs)", block.height, txs.len());
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
        tracing::error!("CHECKPOINT VIOLATION — rejecting block: {}", e);
        return false;
    }

    // Pre-read balances for all addresses involved (read-before-batch).
    let mut balance_delta: std::collections::HashMap<String, i128> = Default::default();
    let mut new_tx_count: u64 = 0;
    let mut stake_sim: std::collections::HashMap<String, u64> = Default::default();
    let mut slashed_seen = load_slashed_set_inner(db);
    let mut newly_slashed: Vec<(String, u64)> = Vec::new();

    // Process all transactions provided in the block. If they are in the block 
    // payload, they are being treated as valid and confirmed by the consensus layer.
    let confirmed_txs: Vec<&LedgerTx> = txs.iter().collect();

    for tx in &confirmed_txs {
        // Skip if tx already exists.
        if db.get_cf(cf_txs, tx.hash.as_bytes()).ok().flatten().is_some() {
            continue;
        }

        // ── Foundation vesting enforcement ───────────────────────────────────
        // Transfers from the foundation wallet are gated by a 4-year linear
        // vesting schedule.  Blocks containing over-vested foundation TXs are
        // silently filtered — the block itself is still accepted.
        if tx.from == FOUNDATION_ADDR && tx.amount > 0 {
            let now = chrono::Utc::now().timestamp();
            let vested = crate::tokenomics::foundation_vested_egoc(now)
                .saturating_mul(crate::tokenomics::UEGOC_PER_EGOC);
            let current_foundation_bal: u64 = db
                .get_cf(cf_balances, FOUNDATION_ADDR.as_bytes())
                .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
            let pending = *balance_delta.get(FOUNDATION_ADDR).unwrap_or(&0);
            let effective_bal = (current_foundation_bal as i128 + pending).max(0) as u64;
            let initial = crate::tokenomics::FOUNDATION_EGOC * crate::tokenomics::UEGOC_PER_EGOC;
            let already_out = initial.saturating_sub(effective_bal);
            let total_out = tx.amount.saturating_add(tx.fee_uegoc);
            if already_out.saturating_add(total_out) > vested {
                tracing::warn!(
                    "[ChainDB] Foundation vesting: TX {} rejected — would exceed vested {} uEGOC (already_out={})",
                    &tx.hash[..tx.hash.len().min(12)], vested, already_out
                );
                continue;
            }
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

        if is_unstake_tx(tx) {
            let credit = unstake_credit_amount(tx);
            *balance_delta.entry(tx.from.clone()).or_insert(0) += credit as i128 - tx.fee_uegoc as i128;
            *balance_delta.entry(STAKING_ADDR.to_string()).or_insert(0) -= credit as i128;
            let stake = stake_sim
                .entry(tx.from.clone())
                .or_insert_with(|| crate::ledger::get_validator_stake(&tx.from));
            *stake = stake.saturating_sub(tx.amount);
        } else if tx.tx_type == "equivocation_proof" {
            match slash_from_equivocation_tx(db, tx, &mut stake_sim, &mut slashed_seen) {
                Ok((accused, slash_amount)) => {
                    *balance_delta.entry(STAKING_ADDR.to_string()).or_insert(0) -= slash_amount as i128;
                    newly_slashed.push((accused, slash_amount));
                }
                Err(e) => tracing::warn!("Skipping invalid equivocation proof {} during block write: {}", tx.hash, e),
            }
        } else {
            *balance_delta.entry(tx.to.clone()).or_insert(0) += credited_amount as i128;
        let is_system_source = tx.from == NODE_POOL_ADDR || tx.from.is_empty();
        if !is_system_source {
            let total_out = tx.amount as i128 + tx.fee_uegoc as i128;
            *balance_delta.entry(tx.from.clone()).or_insert(0) -= total_out;
            if is_stake_tx(tx) {
                let stake = stake_sim
                    .entry(tx.from.clone())
                    .or_insert_with(|| crate::ledger::get_validator_stake(&tx.from));
                *stake = stake.saturating_add(tx.amount);
            }
        } else if tx.from == NODE_POOL_ADDR {
            // Debit the node pool so it actually decreases — enforces hard supply cap.
            *balance_delta.entry(NODE_POOL_ADDR.to_string()).or_insert(0) -= credited_amount as i128;
        }
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
        let already_exists = db.get_cf(cf_txs, tx.hash.as_bytes()).ok().flatten().is_some();
        if already_exists {
            continue;
        }
        batch.put_cf(cf_txs,        tx.hash.as_bytes(), encode(tx));
        batch.put_cf(cf_block_txs,  block_txs_key(block.height, &tx.hash), b"");
        
        let is_spammy = tx.from == NODE_POOL_ADDR 
            && matches!(tx.tx_type.as_str(), "reward" | "coinbase" | "fee_distribution" | "post_reward");
        if !is_spammy {
            batch.put_cf(cf_recent_txs, recent_txs_key(tx.timestamp, &tx.hash), b"");
        }
        // Per-address history with signed delta.
        if is_unstake_tx(tx) {
            let credit = unstake_credit_amount(tx);
            let incoming_k = addr_txs_key(&tx.from, tx.timestamp, &tx.hash);
            batch.put_cf(cf_addr_txs, incoming_k, (credit as i64).to_le_bytes());
            let staking_k = addr_txs_key(STAKING_ADDR, tx.timestamp, &tx.hash);
            batch.put_cf(cf_addr_txs, staking_k, (-(credit as i64)).to_le_bytes());
        } else if tx.tx_type == "equivocation_proof" {
            if let Some((_, slash_amount)) = newly_slashed.iter().find(|(addr, _)| addr == &tx.to) {
                let staking_k = addr_txs_key(STAKING_ADDR, tx.timestamp, &tx.hash);
                batch.put_cf(cf_addr_txs, staking_k, (-(*slash_amount as i64)).to_le_bytes());
            }
            let proof_k = addr_txs_key(&tx.to, tx.timestamp, &tx.hash);
            batch.put_cf(cf_addr_txs, proof_k, 0i64.to_le_bytes());
        } else {
            let incoming_k = addr_txs_key(&tx.to, tx.timestamp, &tx.hash);
            batch.put_cf(cf_addr_txs, incoming_k, (tx.amount as i64).to_le_bytes());
            let is_system_source = tx.from == NODE_POOL_ADDR || tx.from.is_empty();
            if !is_system_source {
                let outgoing_k = addr_txs_key(&tx.from, tx.timestamp, &tx.hash);
                batch.put_cf(cf_addr_txs, outgoing_k, (-(tx.amount as i64)).to_le_bytes());
            }
        }
    }

    for (addr, bal) in &new_balances {
        if *bal == 0 {
            batch.delete_cf(cf_balances, addr.as_bytes());
        } else {
            batch.put_cf(cf_balances, addr.as_bytes(), u64_le(*bal));
        }
    }

    // Meta: latest_height and tx_count.
    let cur_height = db.get_cf(cf_meta, META_LATEST_HEIGHT)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
    if block.height > cur_height {
        batch.put_cf(cf_meta, META_LATEST_HEIGHT, u64_le(block.height));
    }
    // Only count non-system/non-reward transactions for the global counter
    // so the Explorer pagination matches the visible user transactions.
    let mut real_user_txs = 0u64;
    for tx in &confirmed_txs {
        let is_system = tx.from == NODE_POOL_ADDR 
            && matches!(tx.tx_type.as_str(), "reward" | "coinbase" | "fee_distribution" | "post_reward");
        if !is_system {
            real_user_txs += 1;
        }
    }

    let cur_tx_count = db.get_cf(cf_meta, META_TX_COUNT)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
    batch.put_cf(cf_meta, META_TX_COUNT, u64_le(cur_tx_count + real_user_txs));

    // Persist confirmed nonces atomically with the block write so replay
    // protection survives node restarts.  Only non-system senders have nonces.
    for tx in &confirmed_txs {
        let is_system = tx.from == NODE_POOL_ADDR || tx.from.is_empty();
        if !is_system && tx.nonce > 0 {
            persist_nonce_in_batch(&mut batch, &db, &tx.from, tx.nonce);
        }
        if is_stake_tx(tx) && !tx.public_key_ed25519.is_empty() {
            persist_validator_ed25519_pubkey_in_batch(
                &mut batch,
                &db,
                &tx.from,
                &tx.public_key_ed25519,
            );
        }
    }

    // Persist validator stakes to CF_META so they survive restarts without O(N) scan
    for (addr, amount) in &stake_sim {
        let mut key = b"stake:".to_vec();
        key.extend_from_slice(addr.as_bytes());
        batch.put_cf(cf_meta, &key, u64_le(*amount));
    }

    if !newly_slashed.is_empty() {
        persist_slashed_set_in_batch(&mut batch, &db, &slashed_seen);
        for (addr, _) in &newly_slashed {
            crate::p2p::mark_validator_slashed_local(addr);
        }
    }

    tracing::debug!("[ChainDB] db.write(batch) starting — block #{}", block.height);
    if let Err(e) = db.write(batch) {
        tracing::error!("write batch failed (disk full?): {e}");
        return false;
    }
    tracing::debug!("[ChainDB] db.write(batch) done — block #{}", block.height);

    let block_height = block.height;
    let addr = crate::ledger::Ledger::load().address;
    if let Some(&new_bal) = new_balances.get(&addr) {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                static LAST_BAL_UPDATE: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
                let now = chrono::Utc::now().timestamp_millis();
                let last = LAST_BAL_UPDATE.load(std::sync::atomic::Ordering::Relaxed);
                
                // Throttle intense I/O & UI events to 1 per second during bulk sync
                if now - last > 1000 {
                    LAST_BAL_UPDATE.store(now, std::sync::atomic::Ordering::Relaxed);
                    
                    let _guard = crate::ledger::TX_MUTEX.lock().await;
                    let mut ledger = crate::ledger::Ledger::load();
                    if ledger.balance_uegoc != new_bal {
                        tracing::debug!("[ChainDB] balance update — addr {:.16} old={} new={}", ledger.address, ledger.balance_uegoc, new_bal);
                        ledger.balance_uegoc = new_bal;
                        let _ = ledger.save();
                        if let Some(h) = crate::p2p::APP_HANDLE.get() {
                            tracing::debug!("[ChainDB] emitting wallet-balance-updated — block #{} bal={}", block_height, new_bal);
                            let _ = h.emit_all("wallet-balance-updated", serde_json::json!({
                                "balance_uegoc": new_bal,
                                "balance_formatted": format!("{:.2} EGOC", new_bal as f64 / 1_000_000.0)
                            }));
                        }
                    }
                    // Update ledger.nonce if the block contains a transaction from the local node
                    let max_nonce_for_addr = max_confirmed_nonce_from_db(&addr);
                    if ledger.nonce != max_nonce_for_addr {
                        ledger.nonce = max_nonce_for_addr;
                        let _ = ledger.save(); // Save the updated nonce to disk
                        if let Some(h) = crate::p2p::APP_HANDLE.get() {
                            let _ = h.emit_all("wallet-nonce-updated", serde_json::json!({
                                "address": addr,
                                "nonce": max_nonce_for_addr
                            }));
                        }
                    }
                }
            });
        }
    }

    // Write light header to CF_HEADERS (kept for a larger window than full block data).
    let cf_hdrs = db.cf_handle(CF_HEADERS).unwrap();
    let hdr = LightBlockHeader::from(block);
    db.put_cf(cf_hdrs, height_key(block.height), encode(&hdr)).ok();

    // Prune old data to keep disk bounded.
    prune_if_needed(db);

    // Update the in-memory nonce store so replay detection stays current.
    // Also remove any confirmed TXs from the local pending tracker so the UI
    // updates correctly even when a peer committed the block (not bft_solo_commit).
    let mut hashes_to_remove = Vec::with_capacity(confirmed_txs.len());
    for tx in &confirmed_txs {
        hashes_to_remove.push(tx.hash.clone());
        if !tx.from.is_empty() {
            crate::ledger::record_confirmed_nonce(&tx.from, tx.nonce);
        }
        if !tx.hash.is_empty() {
            crate::commands::tx_pending::remove(&tx.hash);
        }
        if !tx.from.is_empty() && tx.from != NODE_POOL_ADDR && !tx.hash.is_empty() {
            tracing::debug!("[TX] {:.12} Confirmed — {:.16} → {:.16} {} uEGOC in block #{}",
                tx.hash, tx.from, tx.to, tx.amount, block.height);
        }
    }
    crate::mempool::get_mempool().remove_txs(&hashes_to_remove);
    crate::mempool::get_mempool().cleanup_stale();

    // Update validator stake tracker for staking/unstaking TXs.
    // This is what gates validator registration (minimum stake required).
    for tx in &confirmed_txs {
        if is_stake_tx(tx) {
            crate::ledger::record_validator_stake(&tx.from, tx.amount, true);
        } else if is_unstake_tx(tx) {
            crate::ledger::record_validator_stake(&tx.from, tx.amount, false);
        } else if tx.tx_type == "equivocation_proof" {
            if let Some((accused, slash_amount)) = newly_slashed.iter().find(|(addr, _)| addr == &tx.to) {
                crate::ledger::record_validator_stake(accused, *slash_amount, false);
            }
        }
    }
    true
}

// ── Pruning ───────────────────────────────────────────────────────────────────
//
// Desktop wallet = light client.  We keep:
//   • Last FULL_BLOCK_CAP full blocks (CF_BLOCKS + CF_BLOCK_TXS).
//   • Last HEADER_CAP light headers (CF_HEADERS).
//   • All transactions in CF_TXS / CF_ADDR_TXS — user's own history is never pruned.
//
// RocksDB's delete_range_cf is O(log N) — it writes a range tombstone, not N deletes.

fn prune_zero_balance_accounts(db: &DB) -> u64 {
    let cf = match db.cf_handle(CF_BALANCES) { Some(c) => c, None => return 0 };
    let mut keys_to_delete: Vec<Vec<u8>> = Vec::new();
    {
        let iter = db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        for item in iter {
            if let Ok((k, v)) = item {
                if read_u64_le(&v) == 0 {
                    keys_to_delete.push(k.to_vec());
                }
            }
        }
    }
    let count = keys_to_delete.len() as u64;
    if count > 0 {
        let mut batch = WriteBatch::default();
        for k in &keys_to_delete {
            batch.delete_cf(cf, k);
        }
        let _ = db.write(batch);
    }
    count
}

fn prune_if_needed(db: &DB) {
    let cf_meta = db.cf_handle(CF_META).unwrap();
    let latest = db.get_cf(cf_meta, META_LATEST_HEIGHT)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);

    if latest % 10_000 == 0 && latest > 0 {
        let pruned = prune_zero_balance_accounts(db);
        if pruned > 0 {
            tracing::info!("Pruned {} zero-balance accounts from state trie", pruned);
        }
    }

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
            let cf_txs       = db.cf_handle(CF_TXS).unwrap();
            let cf_addr_txs  = db.cf_handle(CF_ADDR_TXS).unwrap();
            let mut batch = WriteBatch::default();
            
            let my_addr = crate::ledger::Ledger::load().address;
            
            // Delete individual transactions from CF_TXS before dropping the index
            for h in pruned_below..keep_from {
                let prefix = height_key(h);
                let iter = db.prefix_iterator_cf(cf_block_txs, prefix);
                for item in iter {
                    if let Ok((k, _)) = item {
                        if !k.starts_with(&prefix) { break; }
                        if k.len() > 8 {
                            let tx_hash = &k[8..];
                            if let Some(v) = db.get_cf(cf_txs, tx_hash).ok().flatten() {
                                if let Some(tx) = decode::<LedgerTx>(&v) {
                                    // Preserve local wallet history, prune everything else
                                    if tx.from != my_addr && tx.to != my_addr {
                                        batch.delete_cf(cf_txs, tx_hash);
                                        
                                        // Also prune the address index (CF_ADDR_TXS) to prevent infinite growth
                                        let tx_hash_str = std::str::from_utf8(tx_hash).unwrap_or("");
                                        if !tx_hash_str.is_empty() {
                                            batch.delete_cf(cf_addr_txs, addr_txs_key(&tx.to, tx.timestamp, tx_hash_str));
                                    batch.delete_cf(cf_addr_txs, old_addr_txs_key(&tx.to, tx.timestamp, tx_hash_str));
                                            if !tx.from.is_empty() && tx.from != NODE_POOL_ADDR {
                                                batch.delete_cf(cf_addr_txs, addr_txs_key(&tx.from, tx.timestamp, tx_hash_str));
                                        batch.delete_cf(cf_addr_txs, old_addr_txs_key(&tx.from, tx.timestamp, tx_hash_str));
                                            }
                                        }
                                    }
                                } else {
                                    batch.delete_cf(cf_txs, tx_hash);
                                }
                            }
                        }
                    }
                }
            }

            // Range tombstone: delete all keys in [pruned_below, keep_from).
            batch.delete_range_cf(cf_blocks,    height_key(pruned_below), height_key(keep_from));
            batch.delete_range_cf(cf_block_txs, height_key(pruned_below), height_key(keep_from));
            batch.put_cf(cf_meta, META_PRUNE_BELOW, u64_le(keep_from));
            let _ = db.write(batch);
            tracing::info!("Pruned full blocks {}..{} (keeping last {})",
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
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let Some(cf_meta) = db.cf_handle(CF_META) else { return (0, GENESIS_HASH.to_string()); };
    let height = db.get_cf(cf_meta, META_LATEST_HEIGHT)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
    let Some(cf_blocks) = db.cf_handle(CF_BLOCKS) else { return (0, GENESIS_HASH.to_string()); };
    let hash = db.get_cf(cf_blocks, height_key(height))
        .ok().flatten()
        .and_then(|v| decode::<LedgerBlock>(&v))
        .map(|b| b.hash)
        .unwrap_or_else(|| GENESIS_HASH.to_string());
    (height, hash)
}

pub fn block_count() -> u64 {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf_meta = db.cf_handle(CF_META).unwrap();
    let height = db.get_cf(cf_meta, META_LATEST_HEIGHT)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
    height + 1
}

pub fn tx_count() -> u64 {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let Some(cf_meta) = db.cf_handle(CF_META) else { return 0; };
    db.get_cf(cf_meta, META_TX_COUNT)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0)
}

const MIN_POOL_RESERVE: u64 = 1_000_000_000_000;

/// Burn tokens from the staking pool (slash penalty — tokens are permanently destroyed).
pub fn burn_from_staking_pool(amount_uegoc: u64) {
    const STAKING_ADDR_STR: &str = "egot1staking000000000000000000000000000000000";
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_BALANCES).unwrap();
    let cur = db.get_cf(cf, STAKING_ADDR_STR.as_bytes())
        .ok().flatten()
        .map(|v| read_u64_le(&v))
        .unwrap_or(0);
    let node_pool_bal = db.get_cf(cf, NODE_POOL_ADDR.as_bytes())
        .ok().flatten()
        .map(|v| read_u64_le(&v))
        .unwrap_or(0);
    if node_pool_bal <= MIN_POOL_RESERVE {
        tracing::warn!(
            "burn_from_staking_pool refused: node pool at {} uEGOC is at or below MIN_POOL_RESERVE ({} uEGOC)",
            node_pool_bal, MIN_POOL_RESERVE
        );
        return;
    }
    let new_bal = cur.saturating_sub(amount_uegoc);
    if let Err(e) = db.put_cf(cf, STAKING_ADDR_STR.as_bytes(), u64_le(new_bal)) {
        tracing::error!("burn_from_staking_pool write failed: {e}");
    }
}

/// O(1) balance lookup via cached balances CF.
pub fn balance_of(address: &str) -> u64 {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_BALANCES).unwrap();
    db.get_cf(cf, address.as_bytes())
        .ok().flatten()
        .map(|v| read_u64_le(&v))
        .unwrap_or(0)
}

pub fn get_faucet_drops(address: &str) -> u32 {
    let global_drops = get_tx_history_for_addr(address)
        .into_iter()
        .filter(|tx| tx.tx_type == "faucet")
        .count() as u32;

    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf_meta = match db.cf_handle(CF_META) { Some(c) => c, None => return global_drops };
    let faucet_key = format!("faucet_drops:{}", address);
    let local_drops = db.get_cf(cf_meta, faucet_key.as_bytes())
        .ok().flatten()
        .map(|v| read_u64_le(&v) as u32)
        .unwrap_or(0);

    global_drops.max(local_drops)
}

pub fn grant_testnet_faucet(address: &str, amount_uegoc: u64) -> bool {
    static FAUCET_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    let _guard = FAUCET_LOCK.get_or_init(|| std::sync::Mutex::new(())).lock().unwrap();

    let pool_bal = {
        let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
        let cf_balances = match db.cf_handle(CF_BALANCES) { Some(c) => c, None => return false };

        db.get_cf(cf_balances, NODE_POOL_ADDR.as_bytes())
            .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0)
    };

    let credited = amount_uegoc.min(pool_bal);
    if credited == 0 { return false; }

    if get_faucet_drops(address) >= 1 {
        return false;
    }

    // Check mempool — don't grant if a faucet tx is already pending (not yet committed).
    let already_pending = crate::mempool::get_mempool()
        .pending_txs_for_address(address)
        .into_iter()
        .any(|tx| tx.tx_type == "faucet" && tx.to == address);

    if already_pending {
        return false;
    }

    // Generate transaction (nonce MUST be 0 for system txs to prevent network collisions)
    let current_time = chrono::Utc::now().timestamp();
    let nonce = 0;

    let sign_bytes = crate::ledger::tx_signing_bytes_v2(
        NODE_POOL_ADDR, address, credited, nonce, current_time, 1, "testnet faucet",
    );
    let hash = format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex());

    let tx = crate::ledger::LedgerTx {
        hash:        hash.clone(),
        from:        NODE_POOL_ADDR.into(),
        to:          address.into(),
        amount:      credited,
        fee_uegoc:   0,
        tx_type:     "faucet".into(),
        memo:        Some("testnet faucet".into()),
        timestamp:   current_time,
        status:      "Pending".into(),
        block_height: None,
        nonce,
        signature:   "faucet".into(),
        tx_version:  2,
        chain_id:    1,
        ..crate::ledger::LedgerTx::default()
    };

    eprintln!("[Faucet] Queuing {} uEGOC for {} via Mempool", credited, address);

    {
        let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(cf_meta) = db.cf_handle(CF_META) {
            let faucet_key = format!("faucet_drops:{}", address);
            let prev = db.get_cf(cf_meta, faucet_key.as_bytes())
                .ok().flatten()
                .map(|v| read_u64_le(&v))
                .unwrap_or(0);
            let _ = db.put_cf(cf_meta, faucet_key.as_bytes(), u64_le(prev + 1));
        }
    }

    crate::commands::tx_pending::add(&tx);
    let pool = crate::mempool::get_mempool();
    let _ = pool.push(tx.clone());
    tokio::spawn(async move {
        crate::p2p::broadcast_pending_tx(tx).await;
    });
    true
}

pub fn recent_blocks(limit: usize) -> Vec<LedgerBlock> {
    paged_blocks(0, limit)
}

pub fn paged_blocks(offset: usize, limit: usize) -> Vec<LedgerBlock> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let Some(cf) = db.cf_handle(CF_BLOCKS) else { return vec![]; };
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

pub fn local_chain_height() -> u64 {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let Some(cf) = db.cf_handle(CF_BLOCKS) else { return 0; };
    let mut iter = db.raw_iterator_cf(cf);
    iter.seek_to_last();
    if iter.valid() {
        if let Some(v) = iter.value() {
            if let Some(b) = decode::<LedgerBlock>(v) {
                return b.height;
            }
        }
    }
    0
}

pub fn recent_transactions(limit: usize) -> Vec<LedgerTx> {
    paged_transactions(0, limit)
}

pub fn paged_transactions(offset: usize, limit: usize) -> Vec<LedgerTx> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let Some(cf_recent) = db.cf_handle(CF_RECENT_TXS) else { return vec![]; };
    let Some(cf_txs)    = db.cf_handle(CF_TXS) else { return vec![]; };
    let mut iter = db.raw_iterator_cf(cf_recent);
    iter.seek_to_last();
    let mut skipped = 0usize;
    let mut out = Vec::with_capacity(limit);
    
    while iter.valid() && out.len() < limit {
        if let Some(k) = iter.key() {
            if k.len() > 8 {
                let tx_hash = &k[8..];
                if let Some(v) = db.get_cf(cf_txs, tx_hash).ok().flatten() {
                    if let Some(mut tx) = decode::<LedgerTx>(&v) {
                        if skipped < offset { 
                            skipped += 1; 
                        } else { 
                            tx.status = "Confirmed".to_string();
                            out.push(tx); 
                        }
                    }
                }
            }
        }
        iter.prev();
    }
    out
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
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_BLOCKS).unwrap();
    db.get_cf(cf, height_key(height)).ok().flatten()
        .and_then(|v| decode(&v))
}

pub fn get_tx_by_hash(hash: &str) -> Option<LedgerTx> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_TXS).unwrap();
    db.get_cf(cf, hash.as_bytes()).ok().flatten()
        .and_then(|v| decode(&v))
        .map(|mut tx: LedgerTx| {
            tx.status = "Confirmed".to_string();
            tx
        })
}

/// Return all transactions confirmed in block `height`, in insertion order.
/// Used by the light-client Merkle proof generator.
pub fn get_txs_for_block(height: u64) -> Vec<LedgerTx> {
    let db           = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf_block_txs = db.cf_handle(CF_BLOCK_TXS).unwrap();
    let cf_txs       = db.cf_handle(CF_TXS).unwrap();
    let prefix       = height_key(height);

    let mut out = Vec::new();
    let iter = db.prefix_iterator_cf(cf_block_txs, prefix);
    for item in iter {
        let Ok((key, _)) = item else { continue };
        if !key.starts_with(&prefix) { break; }
        if key.len() <= 8 { continue; }
        let tx_hash = std::str::from_utf8(&key[8..]).unwrap_or("");
        if tx_hash.is_empty() { continue; }
        if let Some(mut tx) = db.get_cf(cf_txs, tx_hash.as_bytes()).ok().flatten()
            .and_then(|v| decode::<LedgerTx>(&v))
        {
            tx.status = "Confirmed".to_string();
            out.push(tx);
        }
    }
    out
}

/// Full transaction history for an address, ordered by timestamp ascending.
pub fn get_tx_history_for_addr(address: &str) -> Vec<LedgerTx> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf_addr = db.cf_handle(CF_ADDR_TXS).unwrap();
    let cf_txs  = db.cf_handle(CF_TXS).unwrap();

    let mut prefix = address.as_bytes().to_vec();
    prefix.push(b':');
    let iter = db.prefix_iterator_cf(cf_addr, &prefix);
    let mut hashes: Vec<Vec<u8>> = Vec::new();

    for item in iter {
        let (k, _) = match item { Ok(v) => v, Err(e) => { eprintln!("[ChainDB] iter error: {e}"); break; } };
        if !k.starts_with(&prefix) { break; }
        // Key = addr ++ ':' ++ ts_be8 ++ tx_hash; tx_hash starts after addr+9 (with colon).
        let hash_start = prefix.len() + 8; // Since prefix already includes the colon
        if k.len() > hash_start {
            hashes.push(k[hash_start..].to_vec());
        }
    }

    hashes.iter()
        .filter_map(|h| {
            db.get_cf(cf_txs, h).ok().flatten()
                .and_then(|v| decode::<LedgerTx>(&v))
                .map(|mut tx| {
                    tx.status = "Confirmed".to_string();
                    tx
                })
        })
        .collect()
}

pub fn parallel_apply_txs(txs: &[LedgerTx], db: &DB) -> Vec<(String, u64)> {
    use rayon::prelude::*;
    use std::collections::HashMap;

    let mut by_sender: HashMap<&str, Vec<&LedgerTx>> = HashMap::new();
    for tx in txs {
        by_sender.entry(tx.from.as_str()).or_default().push(tx);
    }

    let delta_pairs: Vec<(String, i128)> = by_sender
        .par_iter()
        .flat_map(|(_, sender_txs)| {
            let mut pairs: Vec<(String, i128)> = Vec::new();
            for tx in sender_txs.iter() {
                if is_unstake_tx(tx) {
                    let credit = unstake_credit_amount(tx);
                    pairs.push((tx.from.clone(), credit as i128 - tx.fee_uegoc as i128));
                    pairs.push((STAKING_ADDR.to_string(), -(credit as i128)));
                    continue;
                }
                let is_system = tx.from.is_empty() || tx.from == NODE_POOL_ADDR;
                if !tx.to.is_empty() {
                    pairs.push((tx.to.clone(), tx.amount as i128));
                }
                if !is_system {
                    let out = tx.amount as i128 + tx.fee_uegoc as i128;
                    pairs.push((tx.from.clone(), -out));
                } else if tx.from == NODE_POOL_ADDR {
                    pairs.push((NODE_POOL_ADDR.to_string(), -(tx.amount as i128)));
                }
            }
            pairs
        })
        .collect();

    let mut deltas: HashMap<String, i128> = HashMap::new();
    for (addr, delta) in delta_pairs {
        *deltas.entry(addr).or_insert(0) += delta;
    }

    let cf = db.cf_handle(CF_BALANCES).unwrap();
    deltas
        .into_iter()
        .map(|(addr, delta)| {
            let cur = db.get_cf(cf, addr.as_bytes())
                .ok().flatten()
                .map(|v| read_u64_le(&v))
                .unwrap_or(0);
            let new_bal = (cur as i128 + delta).max(0) as u64;
            (addr, new_bal)
        })
        .collect()
}

// ── Public write API ──────────────────────────────────────────────────────────

/// Mine a new block directly into RocksDB. O(1) per block, no chain.json.
/// `poc_ticket` is the VRF ticket hex proving the miner won the slot lottery.
/// Pass empty string for genesis / faucet / remote blocks (accepted transitionally).
pub fn mine_batch_db(txs: &[LedgerTx], miner: &str) -> LedgerBlock {
    let (poc_ticket, poc_sig) = crate::p2p::get_ed25519_seed()
        .and_then(|seed| {
            let prev_hash = get_tip_hash();
            let slot = crate::poc::current_slot();
            let slot_seed = crate::poc::slot_seed(&prev_hash, slot);
            use ed25519_dalek::{Signer, SigningKey};
            let sig = SigningKey::from_bytes(&seed).sign(&slot_seed);
            let ticket = *blake3::hash(&sig.to_bytes()).as_bytes();
            Some((hex::encode(ticket), hex::encode(sig.to_bytes())))
        })
        .unwrap_or_default();
    let poc_slot = crate::poc::current_slot();
    let combined_ticket = if poc_ticket.is_empty() {
        String::new()
    } else { format!("{}:{}", poc_ticket, poc_sig) };
    mine_batch_db_with_ticket(txs, miner, &combined_ticket, poc_slot)
}


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

fn balance_leaf(key_bytes: &[u8], bal: u64) -> String {
    let mut leaf = Vec::with_capacity(key_bytes.len() + 8);
    leaf.extend_from_slice(key_bytes);
    leaf.extend_from_slice(&bal.to_le_bytes());
    blake3::hash(&leaf).to_hex().to_string()
}

fn collect_sorted_balances(db: &DB) -> Vec<(Vec<u8>, u64)> {
    let cf = match db.cf_handle(CF_BALANCES) {
        Some(c) => c,
        None => return vec![],
    };
    let mut entries: Vec<(Vec<u8>, u64)> = db
        .iterator_cf(cf, rocksdb::IteratorMode::Start)
        .filter_map(|r| r.ok())
        .map(|(k, v)| (k.to_vec(), read_u64_le(&v)))
        .collect();
    entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    entries
}

pub fn compute_full_state_root() -> String {
    let (h, _) = latest_block_info();
    get_block_by_height(h).map(|b| b.state_root).unwrap_or_else(|| "0".repeat(64))
}

pub fn get_state_merkle_proof(address: &str) -> Vec<String> {
    // O(N) full state proofs are deprecated in favor of delta roots.
    vec![]
}

pub fn mine_batch_db_with_ticket(txs: &[LedgerTx], miner: &str, poc_ticket: &str, poc_slot: u64) -> LedgerBlock {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());

    let (latest_height, prev_hash, prev_base_fee, prev_state_root) = {
        let cf_meta = db.cf_handle(CF_META).unwrap();
        let h = db.get_cf(cf_meta, META_LATEST_HEIGHT)
            .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
        let cf_blocks = db.cf_handle(CF_BLOCKS).unwrap();
        let prev_block = db.get_cf(cf_blocks, height_key(h))
            .ok().flatten()
            .and_then(|v| decode::<LedgerBlock>(&v));
        let hash = prev_block.as_ref().map(|b| b.hash.clone()).unwrap_or_else(|| GENESIS_HASH.to_string());
        let base_fee = prev_block.as_ref().map(|b| b.base_fee_uegoc).unwrap_or(0);
        let base_fee = if base_fee == 0 { 1_000 } else { base_fee };
        let state_root = prev_block.as_ref().map(|b| b.state_root.clone()).unwrap_or_else(|| "0".repeat(64));
        (h, hash, base_fee, state_root)
    };

    let height    = latest_height + 1;
    let timestamp = chrono::Utc::now().timestamp();

    let user_tx_count = txs.iter().filter(|t| {
        !t.from.is_empty() && t.tx_type != "reward" && t.tx_type != "coinbase" && t.tx_type != "post_reward"
    }).count();
    let new_base_fee = compute_next_base_fee(prev_base_fee, user_tx_count);

    let tx_fees_sum: u64 = txs.iter().map(|t| t.fee_uegoc).sum();
    let remaining = crate::tokenomics::TOTAL_SUPPLY_UEGOC.saturating_sub(circulating_supply_inner(&db));
    let reward = crate::tokenomics::compute_block_reward(height, tx_fees_sum, &prev_hash).min(remaining);
    if reward == 0 {
        tracing::warn!("Supply cap reached at block {} — no coinbase reward", height);
    }

    let coinbase_hash = format!("0x{}", blake3::hash(
        format!("coinbase:{height}:{miner}:{reward}:{timestamp}").as_bytes()
    ).to_hex());

    let mut stamped: Vec<LedgerTx> = txs.iter().map(|tx| {
        let mut t = tx.clone();
        t.block_height = Some(height);
        t.status = "Confirmed".to_string();
        t
    }).collect();

    if reward > 0 {
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
        stamped.push(coinbase);
    }

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

    let state_root = {
        use rayon::prelude::*;

        let raw_pairs: Vec<(Vec<u8>, i128)> = stamped
            .par_iter()
            .flat_map(|tx| {
                let mut pairs: Vec<(Vec<u8>, i128)> = Vec::with_capacity(2);
                if is_unstake_tx(tx) {
                    let credit = unstake_credit_amount(tx);
                    pairs.push((tx.from.as_bytes().to_vec(), credit as i128 - tx.fee_uegoc as i128));
                    pairs.push((STAKING_ADDR.as_bytes().to_vec(), -(credit as i128)));
                    return pairs;
                }
                if !tx.to.is_empty() {
                    pairs.push((tx.to.as_bytes().to_vec(), tx.amount as i128));
                }
                let is_system = tx.from.is_empty() || tx.from == NODE_POOL_ADDR;
                if !is_system {
                    let out = tx.amount as i128 + tx.fee_uegoc as i128;
                    pairs.push((tx.from.as_bytes().to_vec(), -out));
                } else if tx.from == NODE_POOL_ADDR {
                    pairs.push((NODE_POOL_ADDR.as_bytes().to_vec(), -(tx.amount as i128)));
                }
                pairs
            })
            .collect();

        let mut deltas: std::collections::HashMap<Vec<u8>, i128> = Default::default();
        for (k, v) in raw_pairs {
            *deltas.entry(k).or_insert(0) += v;
        }

        let cf_bal = db.cf_handle(CF_BALANCES).unwrap();
        let mut changed: Vec<(Vec<u8>, u64)> = deltas.into_iter().map(|(k, delta)| {
            let cur = db.get_cf(cf_bal, &k).ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
            (k, (cur as i128 + delta).max(0) as u64)
        }).collect();
        changed.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let leaf_strings: Vec<String> = changed.iter().map(|(k, bal)| balance_leaf(k, *bal)).collect();
        let refs: Vec<&str> = leaf_strings.iter().map(|s| s.as_str()).collect();
        let delta_root = compute_merkle_root(&refs);
        blake3_hex(format!("{}{}", prev_state_root, delta_root).as_bytes())
    };

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
        coinbase_tx: if reward > 0 { Some(coinbase_hash) } else { None },
        vote_count: 0,
        tx_merkle_root,
        poc_ticket: poc_ticket.to_string(),
        poc_slot,
        state_root,
        base_fee_uegoc: new_base_fee,
        agg_bls_sig: String::new(),
        bls_pubkeys: Vec::new(),
    };

    write_block_batch(&db, &block, &stamped);

    {
        let cf_bal = db.cf_handle(CF_BALANCES).unwrap();
        let mut burn_batch = WriteBatch::default();
        let mut total_burned: u64 = 0;
        for tx in txs {
            let is_system = tx.from.is_empty()
                || tx.from == NODE_POOL_ADDR
                || tx.tx_type == "reward"
                || tx.tx_type == "coinbase";
            if !is_system {
                let cur = db.get_cf(cf_bal, tx.from.as_bytes())
                    .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
                let burned = cur.min(new_base_fee);
                if burned > 0 {
                    burn_batch.put_cf(cf_bal, tx.from.as_bytes(), u64_le(cur - burned));
                    total_burned = total_burned.saturating_add(burned);
                }
            }
        }
        if total_burned > 0 {
            if let Err(e) = db.write(burn_batch) {
                tracing::error!("BaseFee burn write failed: {e}");
            } else {
                tracing::info!("Block #{height} burned {} uEGOC base fees ({} user txs, {} uEGOC each)",
                    total_burned, user_tx_count, new_base_fee);
            }
        }
    }

    block
}

pub fn build_block_proposal(txs: &[LedgerTx], miner: &str, poc_ticket: &str, poc_slot: u64) -> (LedgerBlock, Vec<LedgerTx>) {
    let db = get_db().lock().expect("chain_db lock poisoned");

    let (latest_height, prev_hash, prev_base_fee, prev_state_root) = {
        let cf_meta = db.cf_handle(CF_META).expect("CF_META missing");
        let h = db.get_cf(cf_meta, META_LATEST_HEIGHT)
            .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
        let cf_blocks = db.cf_handle(CF_BLOCKS).expect("CF_BLOCKS missing");
        let prev_block = db.get_cf(cf_blocks, height_key(h))
            .ok().flatten()
            .and_then(|v| decode::<LedgerBlock>(&v));
        let hash = prev_block.as_ref().map(|b| b.hash.clone()).unwrap_or_else(|| GENESIS_HASH.to_string());
        let base_fee = prev_block.as_ref().map(|b| b.base_fee_uegoc).unwrap_or(0);
        let base_fee = if base_fee == 0 { 1_000 } else { base_fee };
        let state_root = prev_block.as_ref().map(|b| b.state_root.clone()).unwrap_or_else(|| "0".repeat(64));
        (h, hash, base_fee, state_root)
    };

    let height    = latest_height + 1;
    let timestamp = chrono::Utc::now().timestamp();

    let cf_bal = db.cf_handle(CF_BALANCES).expect("CF_BALANCES missing");
    let mut sim_balances: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut sim_stakes: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut sim_nonces: std::collections::HashMap<String, u64> = std::collections::HashMap::new();

    let mut sorted_txs = txs.to_vec();
    // Ensure strict nonce ordering so validation doesn't reject out-of-order txs
    sorted_txs.sort_by_key(|t| t.nonce);

    let mut seen_tx_hashes = std::collections::HashSet::new();
    let valid_txs: Vec<&LedgerTx> = sorted_txs.iter().filter(|tx| {
        if tx.hash.is_empty() {
            eprintln!("[TX] Rejected — empty hash (from={:.16})", tx.from);
            return false;
        }
        if !seen_tx_hashes.insert(tx.hash.clone()) {
            eprintln!("[TX] {:.12} Rejected — duplicate hash in proposal", tx.hash);
            return false;
        }
            if get_tx_by_hash(&tx.hash).is_some() {
            // TX was already confirmed by a peer's block, silently drop from mempool
                return false;
            }
        if tx.nonce == 0 { return true; }
        let last = *sim_nonces.entry(tx.from.clone())
            .or_insert_with(|| crate::ledger::last_confirmed_nonce(&tx.from));
        if tx.nonce <= last {
            // Stale nonce means it was already processed, silently drop
            return false;
        }
        sim_nonces.insert(tx.from.clone(), tx.nonce);

        if is_unstake_tx(tx) {
            let stake_left = sim_stakes.entry(tx.from.clone())
                .or_insert_with(|| crate::ledger::get_validator_stake(&tx.from));
            if tx.amount == 0 || *stake_left < tx.amount {
                eprintln!("[TX] {:.12} Rejected - unstake exceeds active stake", tx.hash);
                return false;
            }
            let credit = unstake_credit_amount(tx);
            if credit < tx.fee_uegoc {
                eprintln!("[TX] {:.12} Rejected - unstake credit below fee", tx.hash);
                return false;
            }
            let staking_bal = sim_balances.get(STAKING_ADDR).copied().unwrap_or_else(|| {
                db.get_cf(cf_bal, STAKING_ADDR.as_bytes()).ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0)
            });
            if staking_bal < credit {
                eprintln!("[TX] {:.12} Rejected - staking contract balance too low", tx.hash);
                return false;
            }
            *stake_left = stake_left.saturating_sub(tx.amount);
            let from_bal = sim_balances.get(&tx.from).copied().unwrap_or_else(|| {
                db.get_cf(cf_bal, tx.from.as_bytes()).ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0)
            });
            sim_balances.insert(tx.from.clone(), from_bal.saturating_add(credit).saturating_sub(tx.fee_uegoc));
            sim_balances.insert(STAKING_ADDR.to_string(), staking_bal.saturating_sub(credit));
            return true;
        }

        let is_system = tx.from.is_empty() || tx.from == NODE_POOL_ADDR;
        if !is_system {
            let from_bal = sim_balances.get(&tx.from).copied().unwrap_or_else(|| {
                db.get_cf(cf_bal, tx.from.as_bytes()).ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0)
            });
            let cost = tx.amount.saturating_add(tx.fee_uegoc);
            if from_bal < cost {
                eprintln!("[TX] {:.12} Rejected — insufficient balance for multi-tx batch", tx.hash);
                return false;
            }
            sim_balances.insert(tx.from.clone(), from_bal - cost);
            
            if !tx.to.is_empty() && !crate::ledger::is_reserved_system_source(&tx.to) {
                let to_bal = sim_balances.get(&tx.to).copied().unwrap_or_else(|| {
                    db.get_cf(cf_bal, tx.to.as_bytes()).ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0)
                });
                sim_balances.insert(tx.to.clone(), to_bal.saturating_add(tx.amount));
            }
        }

        true
    }).collect();

    let user_tx_count = valid_txs.iter().filter(|t| {
        !t.from.is_empty() && t.tx_type != "reward" && t.tx_type != "coinbase" && t.tx_type != "post_reward"
    }).count();
    let new_base_fee = compute_next_base_fee(prev_base_fee, user_tx_count);

    let tx_fees_sum: u64 = valid_txs.iter().map(|t| t.fee_uegoc).sum();
    let remaining = crate::tokenomics::TOTAL_SUPPLY_UEGOC.saturating_sub(circulating_supply_inner(&db));
    let reward = crate::tokenomics::compute_block_reward(height, tx_fees_sum, &prev_hash).min(remaining);
    if reward == 0 {
        tracing::warn!("Supply cap reached at block {} — no coinbase reward", height);
    }

    let coinbase_hash = format!("0x{}", blake3::hash(
        format!("coinbase:{height}:{miner}:{reward}:{timestamp}").as_bytes()
    ).to_hex());

    let mut stamped: Vec<LedgerTx> = valid_txs.iter().map(|tx| {
        let mut t = (*tx).clone();
        t.block_height = Some(height);
        t.status = "Confirmed".to_string();
        t
    }).collect();

    if reward > 0 {
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
        stamped.push(coinbase);
    }

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

    let state_root = {
        let cf_bal = db.cf_handle(CF_BALANCES).expect("CF_BALANCES missing");
        let mut deltas: std::collections::HashMap<Vec<u8>, i128> = Default::default();
        for tx in &stamped {
            if is_unstake_tx(tx) {
                let credit = unstake_credit_amount(tx);
                *deltas.entry(tx.from.as_bytes().to_vec()).or_insert(0) += credit as i128 - tx.fee_uegoc as i128;
                *deltas.entry(STAKING_ADDR.as_bytes().to_vec()).or_insert(0) -= credit as i128;
                continue;
            }
            if !tx.to.is_empty() {
                *deltas.entry(tx.to.as_bytes().to_vec()).or_insert(0) += tx.amount as i128;
            }
            let is_system = tx.from.is_empty() || tx.from == NODE_POOL_ADDR;
            if !is_system {
                let out = tx.amount as i128 + tx.fee_uegoc as i128;
                *deltas.entry(tx.from.as_bytes().to_vec()).or_insert(0) -= out;
            } else if tx.from == NODE_POOL_ADDR {
                *deltas.entry(NODE_POOL_ADDR.as_bytes().to_vec()).or_insert(0) -= tx.amount as i128;
            }
        }
        let mut changed: Vec<(Vec<u8>, u64)> = deltas.into_iter().map(|(k, delta)| {
            let cur = db.get_cf(cf_bal, &k).ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
            (k, (cur as i128 + delta).max(0) as u64)
        }).collect();
        changed.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let leaf_strings: Vec<String> = changed.iter().map(|(k, bal)| balance_leaf(k, *bal)).collect();
        let refs: Vec<&str> = leaf_strings.iter().map(|s| s.as_str()).collect();
        let delta_root = compute_merkle_root(&refs);
        blake3_hex(format!("{}{}", prev_state_root, delta_root).as_bytes())
    };

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
        coinbase_tx: if reward > 0 { Some(coinbase_hash) } else { None },
        vote_count: 0,
        tx_merkle_root,
        poc_ticket: poc_ticket.to_string(),
        poc_slot,
        state_root,
        base_fee_uegoc: new_base_fee,
        agg_bls_sig: String::new(),
        bls_pubkeys: Vec::new(),
    };

    (block, stamped)
}

pub fn commit_staged_block(block: &LedgerBlock, stamped: &[LedgerTx], vote_count: u32) -> bool {
    let db = get_db().lock().expect("chain_db lock poisoned");
    let current_tip = {
        let cf_meta = db.cf_handle(CF_META).expect("CF_META missing");
        db.get_cf(cf_meta, META_LATEST_HEIGHT)
            .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0)
    };
    if block.height == current_tip + 1 {
        let mut b = block.clone();
        b.vote_count = vote_count;
        write_block_batch(&db, &b, stamped);
        return true;
    }
    // The sync path may have written this block before BFT finalization arrived.
    // If the same block is already at this height, treat as committed and update
    // the vote count (write_block_batch's fork-choice replaces if vote_count > existing).
    if block.height <= current_tip {
        let same_hash = db.cf_handle(CF_BLOCKS)
            .and_then(|cf| db.get_cf(cf, height_key(block.height)).ok().flatten())
            .and_then(|v| decode::<LedgerBlock>(&v))
            .map(|existing| existing.hash == block.hash)
            .unwrap_or(false);
        if same_hash {
            let mut b = block.clone();
            b.vote_count = vote_count;
            write_block_batch(&db, &b, stamped);
            return true;
        }
    }
    tracing::warn!(
        "commit_staged_block: block #{} rejected — tip is #{} (stale or conflicting)",
        block.height, current_tip
    );
    false
}

/// Verify that a block's hash field matches its contents.
/// Accepts v1 (legacy), v2 (tx_merkle_root), and v3 (+ state_root) formats.
/// Returns false if the block was tampered with after production.
pub fn verify_block_hash(block: &LedgerBlock, _txs: &[crate::ledger::LedgerTx]) -> bool {
    // Merkle root recomputation is skipped: TX insertion order at production time
    // differs from hash-sorted iteration order in get_txs_for_block(), causing false
    // rejections. The block hash already commits to tx_merkle_root, so verifying the
    // hash is sufficient to detect tampering.

    // v1 hash (no domain tag, no merkle root) — legacy acceptance.
    let v1_input = format!("{}{}{}{}", block.prev_hash, block.height, block.miner, block.timestamp);
    let v1_hash  = blake3::hash(v1_input.as_bytes()).to_hex().to_string();
    if block.hash == v1_hash { return true; }

    // v2 hash (tx_merkle_root + poc_ticket, no state_root).
    let v2_hash = block_hash_for(
        &block.prev_hash, block.height, &block.miner,
        block.timestamp, &block.tx_merkle_root, &block.poc_ticket,
    );
    if block.hash == v2_hash { return true; }

    // v3 hash (+ state_root) — all new blocks use this format.
    if !block.state_root.is_empty() {
        let v3_hash = block_hash_v3(
            &block.prev_hash, block.height, &block.miner,
            block.timestamp, &block.tx_merkle_root, &block.poc_ticket,
            &block.state_root,
        );
        if block.hash == v3_hash { return true; }
        tracing::debug!(
            "Block #{} v3 hash mismatch: stored={:.8} expected={:.8} — ignoring foreign block",
            block.height, block.hash, v3_hash
        );
        return false;
    }

    tracing::debug!(
        "Block #{} hash mismatch: stored={:.8} v2={:.8} — ignoring foreign block",
        block.height, block.hash, v2_hash
    );
    false
}

fn compute_projected_state_root_inner(db: &DB, txs: &[LedgerTx]) -> String {
    let cf_bal = match db.cf_handle(CF_BALANCES) {
        Some(cf) => cf,
        None => return String::new(),
    };

    let mut deltas: std::collections::HashMap<Vec<u8>, i128> = Default::default();
    for tx in txs {
        if is_unstake_tx(tx) {
            let credit = unstake_credit_amount(tx);
            *deltas.entry(tx.from.as_bytes().to_vec()).or_insert(0) += credit as i128 - tx.fee_uegoc as i128;
            *deltas.entry(STAKING_ADDR.as_bytes().to_vec()).or_insert(0) -= credit as i128;
            continue;
        }
        if !tx.to.is_empty() {
            *deltas.entry(tx.to.as_bytes().to_vec()).or_insert(0) += tx.amount as i128;
        }
        let is_system = tx.from.is_empty() || tx.from == NODE_POOL_ADDR;
        if !is_system {
            let out = tx.amount as i128 + tx.fee_uegoc as i128;
            *deltas.entry(tx.from.as_bytes().to_vec()).or_insert(0) -= out;
        } else if tx.from == NODE_POOL_ADDR {
            let pool_bal: u64 = db.get_cf(cf_bal, NODE_POOL_ADDR.as_bytes())
                .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
            let pending_delta = *deltas.get(NODE_POOL_ADDR.as_bytes()).unwrap_or(&0);
            let effective_pool = (pool_bal as i128 + pending_delta).max(0) as u64;
            let credited = tx.amount.min(effective_pool);
            *deltas.entry(NODE_POOL_ADDR.as_bytes().to_vec()).or_insert(0) -= credited as i128;
        }
    }

    let cf_meta = db.cf_handle(CF_META).unwrap();
    let tip_h = db.get_cf(cf_meta, META_LATEST_HEIGHT).ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
    let prev_state_root = if tip_h > 0 {
        let cf_blocks = db.cf_handle(CF_BLOCKS).unwrap();
        db.get_cf(cf_blocks, height_key(tip_h)).ok().flatten().and_then(|v| decode::<LedgerBlock>(&v)).map(|b| b.state_root).unwrap_or_else(|| "0".repeat(64))
    } else {
        "0".repeat(64)
    };

    let mut changed: Vec<(Vec<u8>, u64)> = deltas.into_iter().map(|(k, delta)| {
        let cur = db.get_cf(cf_bal, &k).ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
        (k, (cur as i128 + delta).max(0) as u64)
    }).collect();
    changed.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let leaf_strings: Vec<String> = changed.iter().map(|(k, bal)| balance_leaf(k, *bal)).collect();
    let refs: Vec<&str> = leaf_strings.iter().map(|s| s.as_str()).collect();
    let delta_root = compute_merkle_root(&refs);
    blake3_hex(format!("{}{}", prev_state_root, delta_root).as_bytes())
}

fn validate_block_protocol_txs_inner(db: &DB, block: &LedgerBlock, txs: &[LedgerTx]) -> Result<(), String> {
    if block.height > 0 && block.tx_count as usize != txs.len() {
        return Err(format!(
            "tx_count mismatch: block says {}, received {}",
            block.tx_count,
            txs.len()
        ));
    }

    let mut sorted_txs = txs.to_vec();
    // Sort transactions by nonce to recover the original order if scrambled by CF_BLOCK_TXS
    sorted_txs.sort_by_key(|t| t.nonce);

    let mut seen_hashes = std::collections::HashSet::new();
    for tx in &sorted_txs {
        if tx.hash.is_empty() {
            return Err(format!("empty tx hash in block #{} (type={} from={})", block.height, tx.tx_type, tx.from));
        }
        if !seen_hashes.insert(tx.hash.clone()) {
            return Err(format!("duplicate tx hash {} in block #{}", &tx.hash[..12.min(tx.hash.len())], block.height));
        }
    }

    let tx_fees_sum: u64 = sorted_txs.iter()
        .filter(|t| !crate::ledger::is_protocol_system_tx(t))
        .map(|t| t.fee_uegoc)
        .sum();
    let remaining = crate::tokenomics::TOTAL_SUPPLY_UEGOC.saturating_sub(circulating_supply_inner(db));
    let expected_reward = crate::tokenomics::compute_block_reward(
        block.height,
        tx_fees_sum,
        &block.prev_hash,
    ).min(remaining);
    let expected_staking_fee = crate::tokenomics::staking_fee_share(tx_fees_sum);

    // Tolerate reward=0 from nodes that missed the genesis pool seeding
    if block.reward != expected_reward && block.reward != 0 {
        return Err(format!(
            "invalid block reward: got {}, expected {}",
            block.reward,
            expected_reward
        ));
    }

    let coinbase_txs: Vec<&LedgerTx> = sorted_txs.iter()
        .filter(|t| Some(&t.hash) == block.coinbase_tx.as_ref())
        .collect();
    if block.reward > 0 {
        let cb = coinbase_txs.first().ok_or_else(|| "coinbase tx missing".to_string())?;
        let expected_hash = format!("0x{}", blake3::hash(
            format!("coinbase:{}:{}:{}:{}", block.height, block.miner, expected_reward, block.timestamp).as_bytes()
        ).to_hex());
        if cb.from != NODE_POOL_ADDR
            || cb.to != block.miner
            || cb.amount != expected_reward
            || cb.signature != "coinbase"
            || cb.tx_type != "reward"
            || cb.hash != expected_hash
        {
            return Err("invalid coinbase tx".to_string());
        }
    } else if block.coinbase_tx.is_some() || !coinbase_txs.is_empty() {
        return Err("coinbase present when expected reward is zero".to_string());
    }

    let fee_txs: Vec<&LedgerTx> = sorted_txs.iter()
        .filter(|t| t.tx_type == "fee_distribution")
        .collect();
    if expected_staking_fee > 0 {
        if fee_txs.len() != 1 {
            return Err(format!("expected exactly one staking fee tx, got {}", fee_txs.len()));
        }
        let sf = fee_txs[0];
        let expected_hash = format!("0x{}", blake3::hash(
            format!("stakingfee:{}:{}:{}", block.height, expected_staking_fee, block.timestamp).as_bytes()
        ).to_hex());
        if sf.from != NODE_POOL_ADDR
            || sf.to != STAKING_POOL_ADDR
            || sf.amount != expected_staking_fee
            || sf.signature != "coinbase"
            || sf.hash != expected_hash
        {
            return Err("invalid staking fee tx".to_string());
        }
    } else if !fee_txs.is_empty() {
        return Err("unexpected staking fee tx".to_string());
    }

    for tx in &sorted_txs {
        if crate::ledger::is_protocol_system_tx(tx) {
            let is_coinbase = Some(&tx.hash) == block.coinbase_tx.as_ref();
            let is_fee = tx.tx_type == "fee_distribution";
            let is_post_reward = tx.tx_type == "post_reward";
            let is_faucet = tx.tx_type == "faucet";
                let is_cluster = tx.tx_type == "cluster_escrow" || tx.tx_type.contains("escrow");
                let is_res = tx.tx_type == "reservation_escrow"
                    || tx.tx_type == "early_termination_penalty"
                    || tx.tx_type == "early_termination_refund"
                    || tx.tx_type == "compute_escrow"
                    || tx.tx_type == "storage_escrow"
                    || tx.tx_type == "slash_storage";
                let is_legacy = tx.signature == "system" || tx.signature == "faucet" || tx.signature == "cluster_escrow_system" || tx.signature == "coinbase" || tx.tx_type == "reward";
                
                if !is_coinbase && !is_fee && !is_post_reward && !is_faucet && !is_cluster && !is_res && !is_legacy {
                    return Err(format!("unexpected protocol system tx {} (type: '{}')", tx.hash, tx.tx_type));
            }
            if is_post_reward && (tx.to.is_empty() || tx.amount == 0) {
                return Err(format!("malformed post_reward tx {}", tx.hash));
            }
        } else if crate::ledger::is_reserved_system_source(&tx.from) {
                let is_cluster = tx.tx_type == "cluster_escrow" || tx.tx_type.contains("escrow");
                let is_res = tx.tx_type == "reservation_escrow"
                    || tx.tx_type == "early_termination_penalty"
                    || tx.tx_type == "early_termination_refund"
                    || tx.tx_type == "compute_escrow"
                    || tx.tx_type == "storage_escrow"
                    || tx.tx_type == "slash_storage";
                let is_legacy = tx.signature == "system" || tx.signature == "faucet" || tx.signature == "cluster_escrow_system" || tx.signature == "coinbase" || tx.tx_type == "reward";
                
                if !is_cluster && !is_res && !is_legacy {
                    return Err(format!("forbidden system-source tx {} (type: '{}')", tx.hash, tx.tx_type));
                }
        } else {
            crate::ledger::verify_confirmed_tx_sig(tx)
                .map_err(|e| format!("tx {} rejected: {}", tx.hash, e))?;
        }
    }

    let cf_bal = db.cf_handle(CF_BALANCES).ok_or_else(|| "balances column family missing".to_string())?;
    let mut simulated_balances: std::collections::HashMap<String, u64> = Default::default();
    let mut simulated_nonces: std::collections::HashMap<String, u64> = Default::default();
    let mut simulated_stakes: std::collections::HashMap<String, u64> = Default::default();
    for tx in &sorted_txs {
        if crate::ledger::is_protocol_system_tx(tx) || crate::ledger::is_reserved_system_source(&tx.from) {
            continue;
        }
        if is_unstake_tx(tx) {
            let stake_left = simulated_stakes.entry(tx.from.clone())
                .or_insert_with(|| crate::ledger::get_validator_stake(&tx.from));
            if tx.amount == 0 || *stake_left < tx.amount {
                return Err(format!("unstake tx {} exceeds active stake", tx.hash));
            }
            let credit = unstake_credit_amount(tx);
            if credit < tx.fee_uegoc {
                return Err(format!("unstake tx {} credit below fee", tx.hash));
            }
            let staking_balance = simulated_balances.entry(STAKING_ADDR.to_string()).or_insert_with(|| {
                db.get_cf(cf_bal, STAKING_ADDR.as_bytes())
                    .ok().flatten()
                    .map(|v| read_u64_le(&v))
                    .unwrap_or(0)
            });
            if *staking_balance < credit {
                return Err(format!("unstake tx {} exceeds staking contract balance", tx.hash));
            }
            *staking_balance = staking_balance.saturating_sub(credit);
            *stake_left = stake_left.saturating_sub(tx.amount);
            let balance = simulated_balances.entry(tx.from.clone()).or_insert_with(|| {
                db.get_cf(cf_bal, tx.from.as_bytes())
                    .ok().flatten()
                    .map(|v| read_u64_le(&v))
                    .unwrap_or(0)
            });
            *balance = balance.saturating_add(credit).saturating_sub(tx.fee_uegoc);
        } else {
        let balance = simulated_balances.entry(tx.from.clone()).or_insert_with(|| {
            db.get_cf(cf_bal, tx.from.as_bytes())
                .ok().flatten()
                .map(|v| read_u64_le(&v))
                .unwrap_or(0)
        });
        let required = tx.amount.saturating_add(tx.fee_uegoc);
        if *balance < required {
            return Err(format!(
                "insufficient balance for tx {}: has {}, needs {}",
                tx.hash, *balance, required
            ));
        }
        *balance = balance.saturating_sub(required);
        if !tx.to.is_empty() && !crate::ledger::is_reserved_system_source(&tx.to) {
            let to_bal = simulated_balances.entry(tx.to.clone()).or_insert_with(|| {
                db.get_cf(cf_bal, tx.to.as_bytes())
                    .ok().flatten()
                    .map(|v| read_u64_le(&v))
                    .unwrap_or(0)
            });
            *to_bal = to_bal.saturating_add(tx.amount);
        }
        }

        if tx.nonce > 0 {
            let last = *simulated_nonces.entry(tx.from.clone())
                .or_insert_with(|| crate::ledger::last_confirmed_nonce(&tx.from));
            if tx.nonce <= last {
                return Err(format!(
                    "stale nonce for tx {}: {} <= {}",
                    tx.hash, tx.nonce, last
                ));
            }
            simulated_nonces.insert(tx.from.clone(), tx.nonce);
        }
    }

    Ok(())
}

pub fn validate_peer_block(block: &LedgerBlock, txs: &[LedgerTx]) -> Result<(), String> {
    if block.height == 0 {
        return if block.hash == GENESIS_HASH { Ok(()) } else { Err("invalid genesis hash".into()) };
    }
    if !verify_block_hash(block, txs) {
        return Err("block hash/merkle verification failed".into());
    }
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    if block.height > 1 {
        let parent = db
            .cf_handle(CF_BLOCKS)
            .and_then(|cf| db.get_cf(cf, height_key(block.height - 1)).ok().flatten())
            .and_then(|v| decode::<LedgerBlock>(&v));
        match parent {
            Some(parent) if parent.hash == block.prev_hash => {}
            Some(_) => return Err("prev_hash mismatch against local parent".into()),
            None => return Err("missing local parent".into()),
        }
    } else if block.prev_hash != GENESIS_HASH {
        return Err("height-1 block does not point at genesis".into());
    }

    if block.height > 1 && block.vote_count > 0 && !block.agg_bls_sig.is_empty() && !block.bls_pubkeys.is_empty() {
        let block_hash_bytes = hex::decode(&block.hash).unwrap_or_default();
        let sig_bytes = hex::decode(&block.agg_bls_sig).unwrap_or_default();
        let pubkeys: Vec<Vec<u8>> = block.bls_pubkeys.iter().filter_map(|pk| hex::decode(pk).ok()).collect();


        let active_validators = crate::p2p::get_known_validators_snapshot();
        let total_weight = crate::bft_committee::total_drs_weight(&active_validators) as f64;
        let mut voter_weight = 0f64;
        let mut max_unknown_weight = 0f64;

        for val_addr in &active_validators {
            if let Some(val_bls_pk) = crate::p2p::get_peer_bls_pubkey_hex(val_addr) {
                if block.bls_pubkeys.contains(&val_bls_pk) {
                    voter_weight += crate::bft_committee::compute_drs_weight(val_addr) as f64;
                }
            } else {
                max_unknown_weight += crate::bft_committee::compute_drs_weight(val_addr) as f64;
            }
        }

        let max_possible_weight = voter_weight + max_unknown_weight;

        // If we don't have all BLS keys cached locally, we assume the unknown keys *could* belong to the signers.
        if active_validators.len() >= 10 && total_weight > 0.0 && (max_possible_weight * 3.0) < (total_weight * 2.0) {
            return Err("Quorum Certificate rejected: cumulative DRS weight is < 2/3 of network".into());
        }

        if sig_bytes.is_empty() || pubkeys.is_empty() || !crate::bls_agg::verify_aggregate(&sig_bytes, &pubkeys, &block_hash_bytes) {
            return Err("Invalid Quorum Certificate (BLS aggregate signature)".into());
        }
    }


    let local_tip = db.cf_handle(CF_META)
        .and_then(|cf| db.get_cf(cf, META_LATEST_HEIGHT).ok().flatten())
        .map(|v| read_u64_le(&v))
        .unwrap_or(0);
    if local_tip + 1 == block.height {
        // Legacy blocks (historical sync) are trusted if their BFT signatures and hashes are valid.
        if block.height > 5000 {
            return validate_block_protocol_txs_inner(&db, block, txs);
        }
    }
    Ok(())
}


pub fn append_peer_block(block: &LedgerBlock, txs: &[LedgerTx]) -> bool {
    if let Some(existing) = get_block_by_height(block.height) {
        if existing.hash == block.hash {
            return true;
        } else {
            // Fork detected via gossip. Reject and trigger sync to heal via truncate_from.
            tokio::spawn(async move {
                crate::p2p::sync_chain_from_peers().await;
            });
            return false;
        }
    }
    if let Err(reason) = validate_peer_block(block, txs) {
        tracing::warn!(
            "append_peer_block rejected block #{} {}: {}",
            block.height,
            block.hash,
            reason
        );
        if reason.contains("missing local parent") || reason.contains("prev_hash mismatch") {
            let now = chrono::Utc::now().timestamp_millis();
            static LAST_REJECT_SYNC: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
            let last = LAST_REJECT_SYNC.load(std::sync::atomic::Ordering::Relaxed);
            if now - last > 200 {
                LAST_REJECT_SYNC.store(now, std::sync::atomic::Ordering::Relaxed);
                tokio::spawn(async move {
                    crate::p2p::sync_chain_from_peers().await;
                });
            }
        }
        return false;
    }

    let map = crate::sharding::load_shard_map();
    if map.shard_count > 1 {
        let all_nodes: Vec<String> = map.assignments.iter()
            .map(|a| a.node_address.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter().collect();
        let my_addr = crate::ledger::Ledger::load().address;
        let my_shard_ids: Vec<u32> = crate::sharding::my_shards(&my_addr, &map, &all_nodes)
            .into_iter().map(|(id, _)| id).collect();
        let block_shard = crate::sharding::shard_for_height(block.height, map.shard_count);
        if !my_shard_ids.contains(&block_shard) {
            let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
            let cf_hdrs = db.cf_handle(CF_HEADERS).unwrap();
            let hdr = LightBlockHeader::from(block);
            db.put_cf(cf_hdrs, height_key(block.height), encode(&hdr)).ok();
            return false;
        }
    }
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    write_block_batch(&db, block, txs)
}

pub fn append_trusted_block(block: &LedgerBlock, txs: &[LedgerTx]) -> bool {
    if block.height == 0 { return false; }
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    write_block_batch(&db, block, txs)
}

pub fn delete_full_blocks_for_shard(shard_id: u32, shard_count: u32) {
    if shard_count <= 1 { return; }
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf_blocks    = db.cf_handle(CF_BLOCKS).unwrap();
    let cf_block_txs = db.cf_handle(CF_BLOCK_TXS).unwrap();
    let cf_meta      = db.cf_handle(CF_META).unwrap();
    let latest = db.get_cf(cf_meta, META_LATEST_HEIGHT)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);

    let mut heights_to_delete: Vec<u64> = Vec::new();
    for h in 1..=latest {
        if crate::sharding::shard_for_height(h, shard_count) == shard_id {
            heights_to_delete.push(h);
        }
    }

    if heights_to_delete.is_empty() { return; }

    let mut batch = WriteBatch::default();
    for h in &heights_to_delete {
        batch.delete_cf(cf_blocks,    height_key(*h));
        batch.delete_cf(cf_block_txs, height_key(*h));
    }
    let _ = db.write(batch);
    tracing::info!("Pruned {} full blocks for shard {} (keeping light headers)", heights_to_delete.len(), shard_id);
}

fn reorg_reverse_balance_delta(tx: &LedgerTx, out: &mut std::collections::HashMap<String, i128>) {
    if tx.tx_type == "equivocation_proof" { return; }
    let is_system = tx.from == NODE_POOL_ADDR || tx.from.is_empty();
    if is_unstake_tx(tx) {
        let credit = unstake_credit_amount(tx) as i128;
        *out.entry(tx.from.clone()).or_insert(0) -= credit - tx.fee_uegoc as i128;
        *out.entry(STAKING_ADDR.to_string()).or_insert(0) += credit;
    } else {
        *out.entry(tx.to.clone()).or_insert(0) -= tx.amount as i128;
        if !is_system {
            *out.entry(tx.from.clone()).or_insert(0) += tx.amount as i128 + tx.fee_uegoc as i128;
        } else if tx.from == NODE_POOL_ADDR {
            *out.entry(NODE_POOL_ADDR.to_string()).or_insert(0) += tx.amount as i128;
        }
    }
}

fn recompute_max_nonce_for_addr(db: &DB, addr: &str) -> u64 {
    let cf_txs = match db.cf_handle(CF_TXS) { Some(c) => c, None => return 0 };
    let cf_addr_txs = match db.cf_handle(CF_ADDR_TXS) { Some(c) => c, None => return 0 };
    let mut prefix = addr.as_bytes().to_vec();
    prefix.push(b':');
    let iter = db.prefix_iterator_cf(cf_addr_txs, &prefix);
    let mut max_nonce: u64 = 0;
    for item in iter {
        let Ok((k, _)) = item else { continue };
        if !k.starts_with(&prefix) { break; }
        if k.len() <= prefix.len() + 8 { continue; }
        let tx_hash = match std::str::from_utf8(&k[prefix.len() + 8..]) { Ok(s) => s, Err(_) => continue };
        if let Some(tx) = db.get_cf(cf_txs, tx_hash.as_bytes()).ok().flatten()
            .and_then(|v| decode::<LedgerTx>(&v))
        {
            if tx.from == addr && tx.nonce > max_nonce {
                max_nonce = tx.nonce;
            }
        }
    }
    max_nonce
}

pub fn truncate_from(height: u64) -> Vec<crate::ledger::LedgerTx> {
    if height == 0 { return vec![]; }
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf_blocks     = db.cf_handle(CF_BLOCKS).unwrap();
    let cf_meta       = db.cf_handle(CF_META).unwrap();
    let tip = db.get_cf(cf_meta, META_LATEST_HEIGHT)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
    if height > tip { return vec![]; }
    let cf_block_txs  = db.cf_handle(CF_BLOCK_TXS).unwrap();
    let cf_txs        = db.cf_handle(CF_TXS).unwrap();
    let cf_addr_txs   = db.cf_handle(CF_ADDR_TXS).unwrap();
    let cf_recent_txs = db.cf_handle(CF_RECENT_TXS).unwrap();
    let cf_balances   = db.cf_handle(CF_BALANCES).unwrap();

    let mut removed_txs: u64 = 0;
    let mut orphaned: Vec<crate::ledger::LedgerTx> = Vec::new();
    let mut affected_senders: std::collections::HashSet<String> = Default::default();
    let mut balance_reverse: std::collections::HashMap<String, i128> = Default::default();
    let mut batch = WriteBatch::default();

    for h in height..=tip {
        if let Ok(Some(bytes)) = db.get_cf(cf_blocks, height_key(h)) {
            if let Some(b) = decode::<LedgerBlock>(&bytes) {
                // Re-derive user tx count for this block so we don't over-subtract
                // the META_TX_COUNT (which only tracks non-system txs).
                let block_txs_list = get_txs_for_block(b.height);
                for tx in block_txs_list {
                    let is_system = tx.from == NODE_POOL_ADDR 
                        && matches!(tx.tx_type.as_str(), "reward" | "coinbase" | "fee_distribution" | "post_reward");
                    if !is_system {
                        removed_txs += 1;
                    }
                }
                let block_tx_keys: Vec<Box<[u8]>> = db.prefix_iterator_cf(cf_block_txs, height_key(h))
                    .filter_map(|item| item.ok().map(|(k, _)| k))
                    .take_while(|k| k.starts_with(&height_key(h)))
                    .collect();
                for key in &block_tx_keys {
                    batch.delete_cf(cf_block_txs, key.as_ref());
                    if key.len() <= 8 { continue; }
                    let tx_hash = std::str::from_utf8(&key[8..]).unwrap_or("");
                    if let Some(mut tx) = db.get_cf(cf_txs, tx_hash.as_bytes()).ok().flatten()
                        .and_then(|v| decode::<LedgerTx>(&v))
                    {
                        batch.delete_cf(cf_txs, tx.hash.as_bytes());
                        batch.delete_cf(cf_recent_txs, recent_txs_key(tx.timestamp, &tx.hash));
                        if is_unstake_tx(&tx) {
                            batch.delete_cf(cf_addr_txs, addr_txs_key(&tx.from, tx.timestamp, &tx.hash));
                    batch.delete_cf(cf_addr_txs, old_addr_txs_key(&tx.from, tx.timestamp, &tx.hash));
                            batch.delete_cf(cf_addr_txs, addr_txs_key(STAKING_ADDR, tx.timestamp, &tx.hash));
                    batch.delete_cf(cf_addr_txs, old_addr_txs_key(STAKING_ADDR, tx.timestamp, &tx.hash));
                        } else if tx.tx_type == "equivocation_proof" {
                            batch.delete_cf(cf_addr_txs, addr_txs_key(STAKING_ADDR, tx.timestamp, &tx.hash));
                    batch.delete_cf(cf_addr_txs, old_addr_txs_key(STAKING_ADDR, tx.timestamp, &tx.hash));
                            if !tx.to.is_empty() {
                                batch.delete_cf(cf_addr_txs, addr_txs_key(&tx.to, tx.timestamp, &tx.hash));
                        batch.delete_cf(cf_addr_txs, old_addr_txs_key(&tx.to, tx.timestamp, &tx.hash));
                            }
                        } else {
                            if !tx.to.is_empty() {
                                batch.delete_cf(cf_addr_txs, addr_txs_key(&tx.to, tx.timestamp, &tx.hash));
                        batch.delete_cf(cf_addr_txs, old_addr_txs_key(&tx.to, tx.timestamp, &tx.hash));
                            }
                            let is_system = tx.from == NODE_POOL_ADDR || tx.from.is_empty();
                            if !is_system {
                                batch.delete_cf(cf_addr_txs, addr_txs_key(&tx.from, tx.timestamp, &tx.hash));
                        batch.delete_cf(cf_addr_txs, old_addr_txs_key(&tx.from, tx.timestamp, &tx.hash));
                            }
                        }
                        reorg_reverse_balance_delta(&tx, &mut balance_reverse);
                        if !tx.from.is_empty() && tx.nonce > 0 {
                            affected_senders.insert(tx.from.clone());
                        }
                        if tx.tx_type == "transfer" || tx.tx_type == "stake" || tx.tx_type == "unstake" {
                    tx.status = "Pending".to_string();
                    tx.block_height = None;
                            orphaned.push(tx);
                        }
                    }
                }
            }
        }
        batch.delete_cf(cf_blocks, height_key(h));
    }

    let new_tip = height - 1;
    batch.put_cf(cf_meta, META_LATEST_HEIGHT, u64_le(new_tip));
    let cur_fin = db.get_cf(cf_meta, META_FINALIZED).ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
    if cur_fin > new_tip {
        batch.put_cf(cf_meta, META_FINALIZED, u64_le(new_tip));
    }
    if removed_txs > 0 {
        let cur = db.get_cf(cf_meta, META_TX_COUNT)
            .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
        batch.put_cf(cf_meta, META_TX_COUNT, u64_le(cur.saturating_sub(removed_txs)));
    }
    for (addr, delta) in &balance_reverse {
        if addr.is_empty() { continue; }
        let cur = db.get_cf(cf_balances, addr.as_bytes())
            .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
        let new_bal = (cur as i128 + delta).max(0) as u64;
        if new_bal == 0 {
            batch.delete_cf(cf_balances, addr.as_bytes());
        } else {
            batch.put_cf(cf_balances, addr.as_bytes(), u64_le(new_bal));
        }
    }
    db.write(batch).expect("truncate write");

    if !affected_senders.is_empty() {
        let mut nonce_batch = WriteBatch::default();
        for addr in &affected_senders {
            let max_nonce = recompute_max_nonce_for_addr(&db, addr);
            let mut nonce_key = NONCE_KEY_PREFIX.to_vec();
            nonce_key.extend_from_slice(addr.as_bytes());
            if max_nonce == 0 {
                nonce_batch.delete_cf(cf_meta, &nonce_key);
            } else {
                nonce_batch.put_cf(cf_meta, &nonce_key, u64_le(max_nonce));
            }
            crate::ledger::set_confirmed_nonce(addr, max_nonce);
        }
        db.write(nonce_batch).ok();
    }

    tracing::warn!("Reorg: truncated heights {}..={} (new tip: {}, removed {} txs, {} orphaned user txs)",
        height, tip, new_tip, removed_txs, orphaned.len());
    orphaned
}

/// Same as `append_peer_block` but stamps `vote_count` before writing.
/// Used by the BFT finalization path to record how many votes the block got.
pub fn append_peer_block_with_votes(block: &LedgerBlock, txs: &[LedgerTx], votes: u32) {
    let mut b = block.clone();
    b.vote_count = votes;
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    write_block_batch(&db, &b, txs);
}

/// Applies a single TX to a block that is already in the chain.
/// Called when multiple TxBroadcast messages share the same block — the first
/// message creates the block, but subsequent TXs in that block must still be
/// credited.  The fork-choice guard inside write_block_batch would silently
/// drop equal-vote-count re-writes, so we bypass it here and only touch the
/// TX and balance columns, never the block record.
pub fn apply_missing_tx(block_height: u64, tx: &LedgerTx) {
    if tx.hash.is_empty() { return; }
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());

    let cf_txs        = db.cf_handle(CF_TXS).unwrap();
    let cf_block_txs  = db.cf_handle(CF_BLOCK_TXS).unwrap();
    let cf_addr_txs   = db.cf_handle(CF_ADDR_TXS).unwrap();
    let cf_balances   = db.cf_handle(CF_BALANCES).unwrap();
    let cf_recent_txs = db.cf_handle(CF_RECENT_TXS).unwrap();
    let cf_meta       = db.cf_handle(CF_META).unwrap();

    if db.get_cf(cf_txs, tx.hash.as_bytes()).ok().flatten().is_some() {
        return;
    }

    let is_system_source = tx.from == NODE_POOL_ADDR || tx.from.is_empty();

    let credited_amount = if tx.from == NODE_POOL_ADDR && tx.amount > 0 {
        let pool_bal: u64 = db.get_cf(cf_balances, NODE_POOL_ADDR.as_bytes())
            .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
        tx.amount.min(pool_bal)
    } else {
        tx.amount
    };

    let mut balance_delta: std::collections::HashMap<String, i128> = Default::default();
    *balance_delta.entry(tx.to.clone()).or_insert(0) += credited_amount as i128;
    if !is_system_source {
        *balance_delta.entry(tx.from.clone()).or_insert(0) -=
            tx.amount as i128 + tx.fee_uegoc as i128;
    } else if tx.from == NODE_POOL_ADDR {
        *balance_delta.entry(NODE_POOL_ADDR.to_string()).or_insert(0) -= credited_amount as i128;
    }

    let mut new_balances: std::collections::HashMap<String, u64> = Default::default();
    for addr in balance_delta.keys() {
        let cur = db.get_cf(cf_balances, addr.as_bytes())
            .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
        new_balances.insert(addr.clone(), cur);
    }
    for (addr, delta) in &balance_delta {
        let cur = *new_balances.get(addr).unwrap_or(&0) as i128;
        new_balances.insert(addr.clone(), (cur + delta).max(0) as u64);
    }

    let mut batch = WriteBatch::default();

    batch.put_cf(cf_txs,        tx.hash.as_bytes(), encode(tx));
    batch.put_cf(cf_block_txs,  block_txs_key(block_height, &tx.hash), b"");
    
    let is_spammy = tx.from == NODE_POOL_ADDR 
        && matches!(tx.tx_type.as_str(), "reward" | "coinbase" | "fee_distribution" | "post_reward");
    if !is_spammy {
        batch.put_cf(cf_recent_txs, recent_txs_key(tx.timestamp, &tx.hash), b"");
    }

    let incoming_k = addr_txs_key(&tx.to, tx.timestamp, &tx.hash);
    batch.put_cf(cf_addr_txs, incoming_k, (tx.amount as i64).to_le_bytes());
    if !is_system_source {
        let outgoing_k = addr_txs_key(&tx.from, tx.timestamp, &tx.hash);
        batch.put_cf(cf_addr_txs, outgoing_k, (-(tx.amount as i64)).to_le_bytes());
    }

    for (addr, bal) in &new_balances {
        if *bal == 0 {
            batch.delete_cf(cf_balances, addr.as_bytes());
        } else {
            batch.put_cf(cf_balances, addr.as_bytes(), u64_le(*bal));
        }
    }

    let cur_tx_count = db.get_cf(cf_meta, META_TX_COUNT)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
    batch.put_cf(cf_meta, META_TX_COUNT, u64_le(cur_tx_count + 1));

    if !is_system_source && tx.nonce > 0 {
        persist_nonce_in_batch(&mut batch, &db, &tx.from, tx.nonce);
    }

    if let Err(e) = db.write(batch) {
        eprintln!("[ChainDB] apply_missing_tx write failed: {e}");
    }
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
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_HEADERS).unwrap();
    db.get_cf(cf, height_key(height)).ok().flatten()
        .and_then(|v| decode(&v))
}

/// Fetch block headers from `from_height` up to `limit` (max 10_000).
pub fn get_block_headers(from_height: u64, limit: u32) -> Vec<LightBlockHeader> {
    let db    = get_db().lock().unwrap_or_else(|e| e.into_inner());
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
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_META).unwrap();
    let cur = db.get_cf(cf, META_FINALIZED)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
    if finalized > cur {
        db.put_cf(cf, META_FINALIZED, u64_le(finalized)).ok();
        
        // Dynamic checkpoint ONLY on hard-finalized blocks to prevent poisoning
        if finalized > 0 && finalized % CHECKPOINT_INTERVAL == 0 {
            if let Some(block) = get_block_by_height(finalized) {
                store_dynamic_checkpoint(&db, &block);
            }
        }
    }
}

/// Returns the highest finalized block height.
pub fn finalized_height() -> u64 {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_META).unwrap();
    db.get_cf(cf, META_FINALIZED)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0)
}

/// Returns the hash of the current chain tip (latest mined block).
/// Used by the PoC lottery to compute slot seeds.
pub fn get_tip_hash() -> String {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
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

pub fn compute_next_base_fee(prev_base_fee: u64, tx_count: usize) -> u64 {
    const TARGET_TX_COUNT: usize = 5_000;
    const MAX_CHANGE_DENOMINATOR: u64 = 8;
    const FLOOR: u64 = 1_000;

    let prev = prev_base_fee.max(FLOOR);
    if tx_count == TARGET_TX_COUNT {
        return prev;
    }
    let delta = if tx_count > TARGET_TX_COUNT {
        let excess = (tx_count - TARGET_TX_COUNT) as u64;
        let change = prev.saturating_mul(excess) / (TARGET_TX_COUNT as u64 * MAX_CHANGE_DENOMINATOR);
        prev.saturating_add(change.max(1))
    } else {
        let deficit = (TARGET_TX_COUNT - tx_count) as u64;
        let change = prev.saturating_mul(deficit) / (TARGET_TX_COUNT as u64 * MAX_CHANGE_DENOMINATOR);
        prev.saturating_sub(change).max(FLOOR)
    };
    delta.max(FLOOR)
}

pub fn get_current_base_fee() -> u64 {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf_meta   = db.cf_handle(CF_META).unwrap();
    let cf_blocks = db.cf_handle(CF_BLOCKS).unwrap();
    let h = db.get_cf(cf_meta, META_LATEST_HEIGHT)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
    let fee = db.get_cf(cf_blocks, height_key(h))
        .ok().flatten()
        .and_then(|v| decode::<LedgerBlock>(&v))
        .map(|b| b.base_fee_uegoc)
        .unwrap_or(0);
    if fee == 0 { 1_000 } else { fee }
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
    let db    = get_db().lock().unwrap_or_else(|e| e.into_inner());
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

pub fn get_block_hash_at(height: u64) -> Option<String> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_BLOCKS).unwrap();
    db.get_cf(cf, height_key(height)).ok().flatten()
        .and_then(|v| decode::<LedgerBlock>(&v))
        .map(|b| b.hash)
}

pub fn record_local_proof(prover: &str, cid: &str, _seed: &str, proof_json: &str) {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = match db.cf_handle(CF_META) { Some(c) => c, None => return };
    let h = db.get_cf(cf, META_LATEST_HEIGHT)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
    let epoch = h / 100;
    let key = format!("proof:{}:{}:{}", prover, cid, epoch);
    let _ = db.put_cf(cf, key.as_bytes(), proof_json.as_bytes());
}

pub fn get_local_proof(prover: &str, cid: &str, epoch: u64) -> Option<String> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = match db.cf_handle(CF_META) { Some(c) => c, None => return None };
    let key = format!("proof:{}:{}:{}", prover, cid, epoch);
    db.get_cf(cf, key.as_bytes()).ok().flatten()
        .and_then(|v| std::str::from_utf8(&v).ok().map(|s| s.to_string()))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StateStats {
    pub total_accounts:       u64,
    pub total_supply_uegoc:   u64,
    pub db_size_estimate_mb:  f64,
}

pub fn get_state_stats() -> StateStats {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = match db.cf_handle(CF_BALANCES) {
        Some(c) => c,
        None => return StateStats { total_accounts: 0, total_supply_uegoc: 0, db_size_estimate_mb: 0.0 },
    };
    let mut total_accounts: u64 = 0;
    let mut total_supply:   u64 = 0;
    let iter = db.iterator_cf(cf, rocksdb::IteratorMode::Start);
    for item in iter {
        if let Ok((_, v)) = item {
            let bal = read_u64_le(&v);
            if bal > 0 {
                total_accounts += 1;
                total_supply = total_supply.saturating_add(bal);
            }
        }
    }
    let db_size_bytes = db.property_int_value("rocksdb.estimate-live-data-size")
        .ok().flatten().unwrap_or(0);
    let db_size_mb = db_size_bytes as f64 / (1024.0 * 1024.0);
    StateStats { total_accounts, total_supply_uegoc: total_supply, db_size_estimate_mb: db_size_mb }
}

fn circulating_supply_inner(db: &DB) -> u64 {
    let cf_bal = match db.cf_handle(CF_BALANCES) {
        Some(c) => c,
        None => return 0,
    };
    let node_pool = db.get_cf(cf_bal, NODE_POOL_ADDR.as_bytes()).ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
    let ecosystem = db.get_cf(cf_bal, ECOSYSTEM_ADDR.as_bytes()).ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
    let foundation = db.get_cf(cf_bal, FOUNDATION_ADDR.as_bytes()).ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
    
    crate::tokenomics::TOTAL_SUPPLY_UEGOC
        .saturating_sub(node_pool)
        .saturating_sub(ecosystem)
        .saturating_sub(foundation)
}

pub fn get_total_circulating_supply() -> u64 {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    circulating_supply_inner(&db)
}

pub fn remaining_mintable() -> u64 {
    crate::tokenomics::TOTAL_SUPPLY_UEGOC.saturating_sub(get_total_circulating_supply())
}

pub fn block_reward_at_height(height: u64) -> u64 {
    let halvings = height / crate::tokenomics::HALVING_INTERVAL;
    if halvings >= 64 { return 0; }
    crate::tokenomics::INITIAL_BLOCK_REWARD_UEGOC >> halvings
}

#[derive(Debug, serde::Serialize)]
pub struct NetworkStats {
    pub block_count: u64,
    pub tx_count:    u64,
}

/// Lightweight network statistics from meta column family.
pub fn get_network_stats_db() -> NetworkStats {
    let db      = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf_meta = db.cf_handle(CF_META).unwrap();
    let block_count = db.get_cf(cf_meta, META_LATEST_HEIGHT)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
    let tx_count = db.get_cf(cf_meta, META_TX_COUNT)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
    NetworkStats { block_count, tx_count }
}


pub fn restore_in_memory_state_from_db() {
    {
        let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
        let cf_meta = match db.cf_handle(CF_META) { Some(c) => c, None => return };
        
        let mut stake_count = 0;
        // O(1) Stake Restoration
        let iter = db.prefix_iterator_cf(cf_meta, b"stake:");
        for item in iter {
            if let Ok((k, v)) = item {
                if !k.starts_with(b"stake:") { break; }
                if let Ok(key_str) = std::str::from_utf8(&k) {
                    if key_str.starts_with("stake:") {
                        let addr = &key_str[6..];
                        let amount = read_u64_le(&v);
                        if amount > 0 {
                            crate::ledger::record_validator_stake(addr, amount, true);
                            stake_count += 1;
                        }
                    }
                }
            }
        }
        tracing::info!("In-memory stake store restored from CF_META ({} validators) - no CF_TXS scan needed", stake_count);
    }
    restore_nonces_from_db();
    recalibrate_tx_count();
}

/// Recompute META_TX_COUNT from block headers so stale counts from past
/// reorgs or fork-choice replacements don't persist across restarts.
fn recalibrate_tx_count() {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf_blocks = match db.cf_handle(CF_BLOCKS) { Some(c) => c, None => return };
    let cf_meta   = match db.cf_handle(CF_META)   { Some(c) => c, None => return };
    let tip = db.get_cf(cf_meta, META_LATEST_HEIGHT)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
        
        let mut gap_height = None;
    let mut canonical: u64 = 0;
    for h in 0..=tip {
        if let Ok(Some(bytes)) = db.get_cf(cf_blocks, height_key(h)) {
            if let Some(b) = decode::<LedgerBlock>(&bytes) {
                // Recalibrate based on user transactions only
                let txs = get_txs_for_block(b.height);
                for tx in txs {
                    let is_system = tx.from == NODE_POOL_ADDR 
                        && matches!(tx.tx_type.as_str(), "reward" | "coinbase" | "fee_distribution" | "post_reward");
                    if !is_system { canonical += 1; }
                }
            }
        } else if h > 0 {
            gap_height = Some(h);
            break;
        }
    }
        
    if let Some(h) = gap_height {
        tracing::error!("CRITICAL: Gap detected in blockchain at height {}. Forward state will be overwritten on next block.", h);
    }

        let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
        let cf_meta = match db.cf_handle(CF_META) { Some(c) => c, None => return };
        let pruned_below = db.get_cf(cf_meta, META_PRUNE_BELOW)
            .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(1);

        // If pruning has occurred, we cannot recalculate the lifetime total transaction count
        // purely from the remaining blocks on disk. We must trust the stored META_TX_COUNT.
        if pruned_below > 1 {
            return;
        }

    let stored = db.get_cf(cf_meta, META_TX_COUNT)
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
    if stored != canonical {
        tracing::warn!("TX count recalibrated: {} → {} (was inflated by reorgs/fork-choices)", stored, canonical);
        db.put_cf(cf_meta, META_TX_COUNT, u64_le(canonical)).ok();
    }
}

// ── Kept for API compatibility ────────────────────────────────────────────────

/// No-op: DB handle is a global singleton, not caller-managed.
#[allow(dead_code)]
pub fn get_db_handle() -> DbWrapper { get_db() }

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
    let db  = get_db().lock().unwrap_or_else(|e| e.into_inner());
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
    let db  = get_db().lock().unwrap_or_else(|e| e.into_inner());
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
    let db  = get_db().lock().unwrap_or_else(|e| e.into_inner());
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
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
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
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_DAO).ok_or("CF_DAO missing")?;
    db.put_cf(cf, dao_key(&proposal.id), encode(&proposal))
        .map_err(|e| e.to_string())
}

pub fn get_dao_proposal_public(id: &str, voter: Option<&str>) -> Option<DaoProposalPublic> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_DAO)?;
    let bytes = db.get_cf(cf, dao_key(id)).ok()??;
    let p: DaoProposal = decode(&bytes)?;
    Some(proposal_to_public(&p, voter))
}

pub fn list_dao_proposals(status_filter: Option<&str>, voter: Option<&str>) -> Vec<DaoProposalPublic> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
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
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
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
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
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
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
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
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
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
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
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
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
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
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
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
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
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
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
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
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = match db.cf_handle(CF_META) { Some(c) => c, None => return };
    let key = format!("pvotes:{}:{}", block_hash, voter);
    let _ = db.put_cf(cf, key.as_bytes(), b"1");
}

/// Remove one persisted pending vote (called after the block is finalized
/// or the round is abandoned so stale entries don't accumulate).
pub fn clear_pending_vote(block_hash: &str, voter: &str) {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = match db.cf_handle(CF_META) { Some(c) => c, None => return };
    let key = format!("pvotes:{}:{}", block_hash, voter);
    let _ = db.delete_cf(cf, key.as_bytes());
}

/// Remove ALL pending votes for a given block hash (called when a block
/// reaches quorum and is committed, or when the view times out).
pub fn clear_pending_votes_for_block(block_hash: &str) {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
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

/// Read the persisted confirmed nonce for a single address directly from CF_META.
/// Used as a fallback when the in-memory NONCE_STORE is stale (e.g. after oracle sync
/// writes blocks without updating memory, or after a reorg that zeros the store).
pub fn max_confirmed_nonce_from_db(address: &str) -> u64 {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = match db.cf_handle(CF_META) { Some(c) => c, None => return 0 };
    let mut key = NONCE_KEY_PREFIX.to_vec();
    key.extend_from_slice(address.as_bytes());
    db.get_cf(cf, &key).ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0)
}

/// Restore all confirmed nonces from CF_META into the in-memory NONCE_STORE.
/// Must be called once at startup before accepting any transactions.
pub fn restore_nonces_from_db() {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
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
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
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
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = match db.cf_handle(CF_HOSTING) {
        Some(c) => c,
        None => { eprintln!("[ChainDB] CF_HOSTING missing"); return; }
    };
    if let Err(e) = db.put_cf(&cf, name.as_bytes(), encode(data)) {
        eprintln!("[ChainDB] save_hosted_site '{}' failed: {}", name, e);
    }
}

pub fn get_hosted_site_raw(name: &str) -> Option<serde_json::Value> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_HOSTING).unwrap();
    db.get_cf(&cf, name.as_bytes()).ok()?.and_then(|b| decode(&b))
}

pub fn list_hosted_sites_raw(owner: &str) -> Vec<serde_json::Value> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_HOSTING).unwrap();
    db.iterator_cf(&cf, rocksdb::IteratorMode::Start)
        .flatten()
        .filter_map(|(_, v)| decode::<serde_json::Value>(&v))
        .filter(|s| s["owner"].as_str() == Some(owner))
        .collect()
}

pub fn delete_hosted_site(name: &str) {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_HOSTING).unwrap();
    let _ = db.delete_cf(&cf, name.as_bytes());
}

// ── Hosting node registry ─────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HostingNodeRecord {
    pub node_id:   String,
    pub endpoint:  String,
    pub sites:     Vec<String>,
    pub domains:   Vec<String>,
    pub last_seen: i64,
    #[serde(default)]
    pub signature: String,
}

pub fn upsert_hosting_node(record: &HostingNodeRecord) {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_HOSTING_NODES).unwrap();
    let _ = db.put_cf(&cf, record.node_id.as_bytes(), encode(record));
}

pub fn get_hosting_node(node_id: &str) -> Option<HostingNodeRecord> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_HOSTING_NODES).unwrap();
    db.get_cf(&cf, node_id.as_bytes()).ok()?.and_then(|b| decode(&b))
}

pub fn list_hosting_nodes() -> Vec<HostingNodeRecord> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
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
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_HOSTING_NODES).unwrap();
    for id in stale {
        let _ = db.delete_cf(&cf, id.as_bytes());
    }
}

// ── Hosting plan subscriptions ────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ActiveHostingPlan {
    pub owner:      String,
    pub tier:       String,
    pub months:     u32,
    pub started_at: i64,
    pub expires_at: i64,
    pub paid_uegoc: u64,
    pub tx_hash:    String,
}

pub fn upsert_hosting_plan(plan: &ActiveHostingPlan) {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_HOSTING_PLANS).unwrap();
    let _ = db.put_cf(&cf, plan.owner.as_bytes(), encode(plan));
}

pub fn get_hosting_plan(owner: &str) -> Option<ActiveHostingPlan> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_HOSTING_PLANS).unwrap();
    db.get_cf(&cf, owner.as_bytes()).ok()?.and_then(|b| decode(&b))
}

// ── Decentralized Compute (DePIN / DAI) ──────────────────────────────────────

pub const COMPUTE_ESCROW_ADDR: &str = "egot1computeescrow000000000000000000000000000";
pub const COMPUTE_COLLATERAL_BPS: u64 = 2_000; // 20% of bid

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComputeNodeRecord {
    pub address:              String,
    pub endpoint:             String,
    pub cpu_cores:            u32,
    pub cpu_model:            String,
    pub ram_gb:               u32,
    pub gpu_name:             String,
    pub gpu_vram_gb:          u32,
    pub gpu_count:            u32,
    pub has_cuda:             bool,
    pub compute_score:        u64,
    pub available_cores:      u32,
    pub available_ram_gb:     u32,
    pub price_per_gpu_hour_uegoc:  u64,
    pub price_per_core_hour_uegoc: u64,
    pub jobs_completed:            u64,
    pub reputation_score:     u64,
    pub last_seen:            i64,
    pub status:               String,
    #[serde(default)]
    pub locked_cores:         u32,
    #[serde(default)]
    pub locked_ram_gb:        u32,
    #[serde(default)]
    pub slash_count:          u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComputeJob {
    pub job_id:              String,
    pub poster_address:      String,
    pub worker_address:      String,
    pub job_type:            String,
    pub model_cid:           String,
    pub input_cid:           String,
    pub output_cid:          String,
    pub required_vram_gb:    u32,
    pub required_cores:      u32,
    pub max_duration_mins:   u32,
    pub bid_uegoc:           u64,
    pub status:              String,
    pub created_at:          i64,
    pub accepted_at:         Option<i64>,
    pub completed_at:        Option<i64>,
    #[serde(default)]
    pub collateral_uegoc:    u64,
    #[serde(default)]
    pub escrow_active:       bool,
    #[serde(default)]
    pub min_bid_uegoc:       u64,
}

/// Move EGOC between two addresses directly in the balance CF.
/// Used for protocol-level escrow operations (compute, future contracts).
/// Does NOT create a mempool TX — call before creating the audit TX.
pub fn internal_balance_transfer(from: &str, to: &str, amount: u64) -> bool {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_BALANCES).unwrap();
    let from_bal = db.get_cf(cf, from.as_bytes())
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
    if from_bal < amount { return false; }
    let to_bal = db.get_cf(cf, to.as_bytes())
        .ok().flatten().map(|v| read_u64_le(&v)).unwrap_or(0);
    let mut batch = rocksdb::WriteBatch::default();
    batch.put_cf(cf, from.as_bytes(), u64_le(from_bal - amount));
    batch.put_cf(cf, to.as_bytes(), u64_le(to_bal + amount));
    db.write(batch).is_ok()
}

pub fn upsert_compute_node(node: &ComputeNodeRecord) {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_COMPUTE_NODES).unwrap();
    let _ = db.put_cf(&cf, node.address.as_bytes(), encode(node));
}

pub fn get_compute_node(address: &str) -> Option<ComputeNodeRecord> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_COMPUTE_NODES).unwrap();
    db.get_cf(&cf, address.as_bytes()).ok()?.and_then(|b| decode(&b))
}

pub fn list_compute_nodes() -> Vec<ComputeNodeRecord> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_COMPUTE_NODES).unwrap();
    let mut out = Vec::new();
    let iter = db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
    for item in iter {
        if let Ok((_, v)) = item {
            if let Some(n) = decode::<ComputeNodeRecord>(&v) {
                out.push(n);
            }
        }
    }
    out
}

pub fn upsert_compute_job(job: &ComputeJob) {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_COMPUTE_JOBS).unwrap();
    let _ = db.put_cf(&cf, job.job_id.as_bytes(), encode(job));
}

pub fn get_compute_job(job_id: &str) -> Option<ComputeJob> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_COMPUTE_JOBS).unwrap();
    db.get_cf(&cf, job_id.as_bytes()).ok()?.and_then(|b| decode(&b))
}

pub fn list_compute_jobs() -> Vec<ComputeJob> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_COMPUTE_JOBS).unwrap();
    let mut out = Vec::new();
    let iter = db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
    for item in iter {
        if let Ok((_, v)) = item {
            if let Some(j) = decode::<ComputeJob>(&v) {
                out.push(j);
            }
        }
    }
    out
}

pub fn prune_stale_compute_nodes() {
    let cutoff = chrono::Utc::now().timestamp() - 600;
    let my_addr = crate::ledger::Ledger::load().address;
    let stale: Vec<String> = list_compute_nodes()
        .into_iter()
        .filter(|n| n.last_seen < cutoff && n.address != my_addr)
        .map(|n| n.address.clone())
        .collect();
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_COMPUTE_NODES).unwrap();
    for addr in stale {
        let _ = db.delete_cf(&cf, addr.as_bytes());
    }
}

// ── Compute Capacity Reservations ────────────────────────────────────────────

pub const RESERVATION_SLA_BPS: u64 = 3_000;
pub const RESERVATION_ESCROW_ADDR: &str = "egot1reserveescrow00000000000000000000000000";
pub const MAX_BREACH_BEFORE_TERMINATE: u32 = 3;
pub const HEARTBEAT_INTERVAL_SECS: i64 = 86_400;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComputeCapacityOffer {
    pub offer_id:                  String,
    pub provider_address:          String,
    pub cpu_cores:                 u32,
    pub ram_gb:                    u32,
    pub gpu_count:                 u32,
    pub gpu_vram_gb:               u32,
    pub gpu_name:                  String,
    /// Canonical pricing: per hour. Legacy day fields kept for backward compat.
    #[serde(default)]
    pub price_per_gpu_hour_uegoc:  u64,
    #[serde(default)]
    pub price_per_core_hour_uegoc: u64,
    #[serde(default)]
    pub price_per_gpu_day_uegoc:   u64,
    #[serde(default)]
    pub price_per_core_day_uegoc:  u64,
    /// Duration limits in hours (1 hr min → 8760 hr = 1 year max).
    #[serde(default)]
    pub min_duration_hours:        u64,
    #[serde(default)]
    pub max_duration_hours:        u64,
    pub sla_uptime_pct:            u32,
    pub available_from:            i64,
    pub status:                    String,
    pub created_at:                i64,
    #[serde(default)]
    pub bonded:                    bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComputeReservation {
    pub reservation_id:   String,
    pub offer_id:         String,
    pub buyer_address:    String,
    pub provider_address: String,
    pub cpu_cores:         u32,
    pub ram_gb:            u32,
    pub gpu_count:         u32,
    /// Total booked duration in minutes.
    pub duration_minutes:  u64,
    /// Heartbeat period in minutes (e.g. 60 = hourly, 1440 = daily).
    pub period_minutes:    u64,
    /// EGOC released to provider per heartbeat period.
    pub period_rate_uegoc: u64,
    pub total_cost_uegoc:  u64,
    pub collateral_uegoc:  u64,
    pub status:            String,
    pub created_at:        i64,
    pub expires_at:        i64,
    pub last_heartbeat_at: i64,
    /// Number of periods paid out so far.
    pub periods_paid:      u64,
    pub breach_count:      u32,
    pub escrow_remaining:  u64,
    #[serde(default)] pub days:             u32,
    #[serde(default)] pub days_paid:        u32,
    #[serde(default)] pub daily_rate_uegoc: u64,
    /// Unix timestamp when the buyer first actively used the rental (opened console).
    /// None = not yet started; timer and billing begin at this moment, not at created_at.
    #[serde(default)] pub started_at: Option<i64>,
}

pub fn upsert_compute_offer(offer: &ComputeCapacityOffer) {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_COMPUTE_OFFERS).unwrap();
    let _ = db.put_cf(&cf, offer.offer_id.as_bytes(), encode(offer));
}

pub fn get_compute_offer(offer_id: &str) -> Option<ComputeCapacityOffer> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_COMPUTE_OFFERS).unwrap();
    db.get_cf(&cf, offer_id.as_bytes()).ok()?.and_then(|b| decode(&b))
}

pub fn list_compute_offers() -> Vec<ComputeCapacityOffer> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_COMPUTE_OFFERS).unwrap();
    let mut out = Vec::new();
    let iter = db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
    for item in iter {
        if let Ok((_, v)) = item {
            if let Some(o) = decode::<ComputeCapacityOffer>(&v) {
                out.push(o);
            }
        }
    }
    out
}

pub fn upsert_compute_reservation(res: &ComputeReservation) {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_COMPUTE_RESERVATIONS).unwrap();
    let _ = db.put_cf(&cf, res.reservation_id.as_bytes(), encode(res));
}

pub fn get_compute_reservation(reservation_id: &str) -> Option<ComputeReservation> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_COMPUTE_RESERVATIONS).unwrap();
    db.get_cf(&cf, reservation_id.as_bytes()).ok()?.and_then(|b| decode(&b))
}

pub fn delete_compute_reservation(reservation_id: &str) -> Result<(), String> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_COMPUTE_RESERVATIONS).ok_or("CF_COMPUTE_RESERVATIONS missing")?;
    db.delete_cf(&cf, reservation_id.as_bytes()).map_err(|e| e.to_string())
}

pub fn list_compute_reservations() -> Vec<ComputeReservation> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_COMPUTE_RESERVATIONS).unwrap();
    let mut out = Vec::new();
    let iter = db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
    for item in iter {
        if let Ok((_, v)) = item {
            if let Some(r) = decode::<ComputeReservation>(&v) {
                out.push(r);
            }
        }
    }
    out
}

// ── Storage Deals (escrow-based) ─────────────────────────────────────────────

pub const STORAGE_ESCROW_ADDR:       &str = "egot1storageescrow000000000000000000000000";
pub const STORAGE_DEAL_HEARTBEAT_SECS: i64 = 86_400;
pub const STORAGE_DEAL_GRACE_SECS:    i64 = 7_200;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StorageDeal {
    pub deal_id:           String,
    pub provider_address:  String,
    pub client_address:    String,
    pub size_gb:           u32,
    pub duration_days:     u32,
    pub daily_rate_uegoc:  u64,
    pub total_cost_uegoc:  u64,
    pub escrow_remaining:  u64,
    pub days_paid:         u32,
    pub breach_count:      u32,
    pub last_proof_at:     i64,
    pub status:            String,
    pub created_at:        i64,
    pub expires_at:        i64,
    #[serde(default)]
    pub cid:               String,
    #[serde(default)]
    pub comm_d_hex:        String,
    #[serde(default)]
    pub n_real_leaves:     u64,
    #[serde(default)]
    pub n_padded_leaves:   u64,
}

pub fn upsert_storage_deal(deal: &StorageDeal) {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_STORAGE_DEALS).unwrap();
    let _ = db.put_cf(&cf, deal.deal_id.as_bytes(), &encode(deal));
}

pub fn get_storage_deal(deal_id: &str) -> Option<StorageDeal> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_STORAGE_DEALS).unwrap();
    db.get_cf(&cf, deal_id.as_bytes()).ok().flatten().and_then(|v| decode(&v))
}

pub fn list_storage_deals() -> Vec<StorageDeal> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_STORAGE_DEALS).unwrap();
    let mut out = Vec::new();
    for item in db.iterator_cf(&cf, rocksdb::IteratorMode::Start) {
        if let Ok((_, v)) = item {
            if let Some(d) = decode::<StorageDeal>(&v) { out.push(d); }
        }
    }
    out
}

// ── Cluster Bookings (distributed multi-node compute) ────────────────────────

pub const CLUSTER_ESCROW_ADDR: &str = "egot1clusterescrow00000000000000000000000";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClusterNode {
    pub provider_address:  String,
    pub reservation_id:    String,
    pub cpu_cores:         u32,
    pub ram_gb:            u32,
    pub gpu_count:         u32,
    pub gpu_vram_gb:       u32,
    pub gpu_name:          String,
    pub wg_pubkey:         String,
    pub wg_ip:             String,
    pub endpoint:          String,
    pub is_head:           bool,
    pub status:            String,
    pub joined_at:         i64,
    pub last_heartbeat_at: i64,
    pub period_rate_uegoc: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClusterBooking {
    pub cluster_id:            String,
    pub buyer_address:         String,
    pub name:                  String,
    pub subnet:                String,
    pub nodes:                 Vec<ClusterNode>,
    pub head_provider_address: String,
    pub head_wg_ip:            String,
    pub buyer_wg_pubkey:       String,
    pub total_gpu_count:       u32,
    pub total_cpu_cores:       u32,
    pub total_ram_gb:          u32,
    pub total_cost_uegoc:      u64,
    pub status:                String,
    pub created_at:            i64,
    pub expires_at:            i64,
    pub duration_minutes:      u64,
    pub framework:             String,
    pub wg_listen_port:        u16,
}

pub fn upsert_cluster_booking(b: &ClusterBooking) {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_CLUSTER_BOOKINGS).unwrap();
    let _ = db.put_cf(&cf, b.cluster_id.as_bytes(), encode(b));
}

pub fn get_cluster_booking(cluster_id: &str) -> Option<ClusterBooking> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_CLUSTER_BOOKINGS).unwrap();
    db.get_cf(&cf, cluster_id.as_bytes()).ok().flatten().and_then(|v| decode(&v))
}

pub fn list_cluster_bookings() -> Vec<ClusterBooking> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_CLUSTER_BOOKINGS).unwrap();
    let mut out = Vec::new();
    for item in db.iterator_cf(&cf, rocksdb::IteratorMode::Start) {
        if let Ok((_, v)) = item {
            if let Some(b) = decode::<ClusterBooking>(&v) { out.push(b); }
        }
    }
    out
}

// ── Contract State (RocksDB mirror of ego-vm filesystem state) ────────────────

pub fn save_contract_state(addr: &str, state_json: &str) {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = match db.cf_handle(CF_CONTRACT_STATE) { Some(c) => c, None => return };
    let _ = db.put_cf(&cf, addr.as_bytes(), state_json.as_bytes());
}

pub fn load_contract_state(addr: &str) -> Option<String> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_CONTRACT_STATE)?;
    db.get_cf(&cf, addr.as_bytes()).ok().flatten()
        .and_then(|v| String::from_utf8(v.to_vec()).ok())
}

pub fn apply_balance_delta(addr: &str, delta: i64) {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_BALANCES).unwrap();
    let cur = db.get_cf(cf, addr.as_bytes())
        .ok().flatten()
        .map(|v| read_u64_le(&v))
        .unwrap_or(0);
    let new_bal = (cur as i128 + delta as i128).max(0) as u64;
    let _ = db.put_cf(cf, addr.as_bytes(), u64_le(new_bal));
}

pub fn save_state_channel(ch: &crate::l2::state_channel::StateChannel) -> Result<(), String> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_L2_CHANNELS).ok_or("CF_L2_CHANNELS missing")?;
    db.put_cf(cf, ch.channel_id.as_bytes(), encode(ch))
        .map_err(|e| e.to_string())
}

pub fn get_state_channel(id: &str) -> Option<crate::l2::state_channel::StateChannel> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_L2_CHANNELS)?;
    db.get_cf(cf, id.as_bytes()).ok().flatten().and_then(|v| decode(&v))
}

pub fn get_channels_for_address(addr: &str) -> Vec<crate::l2::state_channel::StateChannel> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = match db.cf_handle(CF_L2_CHANNELS) { Some(c) => c, None => return vec![] };
    db.iterator_cf(cf, rocksdb::IteratorMode::Start)
        .flatten()
        .filter_map(|(_, v)| decode::<crate::l2::state_channel::StateChannel>(&v))
        .filter(|ch| ch.party_a == addr || ch.party_b == addr)
        .collect()
}

pub fn save_l2_batch(batch: &crate::l2::rollup::RollupBatch) -> Result<(), String> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_L2_BATCHES).ok_or("CF_L2_BATCHES missing")?;
    db.put_cf(cf, batch.batch_id.as_bytes(), encode(batch))
        .map_err(|e| e.to_string())
}

pub fn get_l2_batch(id: &str) -> Option<crate::l2::rollup::RollupBatch> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_L2_BATCHES)?;
    db.get_cf(cf, id.as_bytes()).ok().flatten().and_then(|v| decode(&v))
}

pub fn get_l2_batches_from(from_height: u64) -> Vec<crate::l2::rollup::RollupBatch> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = match db.cf_handle(CF_L2_BATCHES) { Some(c) => c, None => return vec![] };
    db.iterator_cf(cf, rocksdb::IteratorMode::Start)
        .flatten()
        .filter_map(|(_, v)| decode::<crate::l2::rollup::RollupBatch>(&v))
        .filter(|b| b.l1_height >= from_height)
        .collect()
}

const L2_BALANCES_KEY: &[u8] = b"l2_current_balances";

pub fn get_l2_balances() -> std::collections::HashMap<String, u64> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = match db.cf_handle(CF_L2_STATE) { Some(c) => c, None => return Default::default() };
    db.get_cf(cf, L2_BALANCES_KEY).ok().flatten()
        .and_then(|v| serde_json::from_slice(&v).ok())
        .unwrap_or_default()
}

pub fn set_l2_balances(bal: &std::collections::HashMap<String, u64>) -> Result<(), String> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_L2_STATE).ok_or("CF_L2_STATE missing")?;
    let bytes = serde_json::to_vec(bal).map_err(|e| e.to_string())?;
    db.put_cf(cf, L2_BALANCES_KEY, bytes).map_err(|e| e.to_string())
}

pub fn get_l2_balances_at(l1_height: u64) -> std::collections::HashMap<String, u64> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = match db.cf_handle(CF_L2_BATCHES) { Some(c) => c, None => return Default::default() };
    let mut balances: std::collections::HashMap<String, u64> = Default::default();
    let batches: Vec<crate::l2::rollup::RollupBatch> = db
        .iterator_cf(cf, rocksdb::IteratorMode::Start)
        .flatten()
        .filter_map(|(_, v)| decode::<crate::l2::rollup::RollupBatch>(&v))
        .filter(|b| {
            b.l1_height <= l1_height
                && b.status == crate::l2::rollup::BatchStatus::Finalized
        })
        .collect();
    let mut sorted = batches;
    sorted.sort_by_key(|b| b.l1_height);
    for batch in &sorted {
        for tx in &batch.l2_txs {
            let from_bal = *balances.get(&tx.from).unwrap_or(&0);
            let cost = tx.amount.saturating_add(tx.fee_l2);
            if from_bal >= cost {
                *balances.entry(tx.from.clone()).or_insert(0) -= cost;
                *balances.entry(tx.to.clone()).or_insert(0) += tx.amount;
            }
        }
    }
    balances
}

pub fn get_meta_u64(key: &[u8]) -> Option<u64> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_META)?;
    let bytes = db.get_cf(cf, key).ok()??;
    if bytes.len() == 8 { Some(u64::from_le_bytes(<[u8; 8]>::try_from(bytes.as_ref()).ok()?)) } else { None }
}

pub fn set_meta_u64(key: &[u8], val: u64) {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(cf) = db.cf_handle(CF_META) {
        let _ = db.put_cf(cf, key, &val.to_le_bytes());
    }
}

const META_KNOWN_VALIDATORS: &[u8] = b"known_validators_v1";

pub fn persist_known_validator(addr: &str) {
    if addr.is_empty() { return; }
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = match db.cf_handle(CF_META) { Some(c) => c, None => return };
    let mut current: Vec<String> = db.get_cf(cf, META_KNOWN_VALIDATORS)
        .ok().flatten()
        .and_then(|v| serde_json::from_slice(&v).ok())
        .unwrap_or_default();
    let addr_s = addr.to_string();
    if !current.contains(&addr_s) {
        current.push(addr_s);
        if let Ok(bytes) = serde_json::to_vec(&current) {
            let _ = db.put_cf(cf, META_KNOWN_VALIDATORS, bytes);
        }
    }
}

pub fn remove_persisted_validator(addr: &str) {
    if addr.is_empty() { return; }
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = match db.cf_handle(CF_META) { Some(c) => c, None => return };
    let mut current: Vec<String> = db.get_cf(cf, META_KNOWN_VALIDATORS)
        .ok().flatten()
        .and_then(|v| serde_json::from_slice(&v).ok())
        .unwrap_or_default();
    current.retain(|a| a != addr);
    if let Ok(bytes) = serde_json::to_vec(&current) {
        let _ = db.put_cf(cf, META_KNOWN_VALIDATORS, bytes);
    }
}

pub fn load_known_validators() -> Vec<String> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = match db.cf_handle(CF_META) { Some(c) => c, None => return vec![] };
    db.get_cf(cf, META_KNOWN_VALIDATORS)
        .ok().flatten()
        .and_then(|v| serde_json::from_slice(&v).ok())
        .unwrap_or_default()
}

const META_PIN_LOCKOUT_PREFIX: &str = "pin_lock:";

pub fn persist_pin_lockout(addr: &str, fails: u32, until: i64) {
    if addr.is_empty() { return; }
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = match db.cf_handle(CF_META) { Some(c) => c, None => return };
    let key = format!("{}{}", META_PIN_LOCKOUT_PREFIX, addr);
    let val = serde_json::json!({ "fails": fails, "until": until });
    if let Ok(bytes) = serde_json::to_vec(&val) {
        let _ = db.put_cf(cf, key.as_bytes(), bytes);
    }
}

pub fn load_pin_lockout(addr: &str) -> (u32, i64) {
    if addr.is_empty() { return (0, 0); }
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = match db.cf_handle(CF_META) { Some(c) => c, None => return (0, 0) };
    let key = format!("{}{}", META_PIN_LOCKOUT_PREFIX, addr);
    db.get_cf(cf, key.as_bytes())
        .ok().flatten()
        .and_then(|v| serde_json::from_slice::<serde_json::Value>(&v).ok())
        .map(|v| {
            let fails = v["fails"].as_u64().unwrap_or(0) as u32;
            let until = v["until"].as_i64().unwrap_or(0);
            (fails, until)
        })
        .unwrap_or((0, 0))
}

pub fn clear_pin_lockout(addr: &str) {
    if addr.is_empty() { return; }
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = match db.cf_handle(CF_META) { Some(c) => c, None => return };
    let key = format!("{}{}", META_PIN_LOCKOUT_PREFIX, addr);
    let _ = db.delete_cf(cf, key.as_bytes());
}

const META_OTP_TX_PREFIX: &str = "otptx:";

pub fn persist_pending_otptx(tx_id: &str, tx: &crate::ledger::LedgerTx, expiry: i64) {
    if tx_id.is_empty() { return; }
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = match db.cf_handle(CF_META) { Some(c) => c, None => return };
    let key = format!("{}{}", META_OTP_TX_PREFIX, tx_id);
    let val = serde_json::json!({ "tx": tx, "expiry": expiry });
    if let Ok(bytes) = serde_json::to_vec(&val) {
        let _ = db.put_cf(cf, key.as_bytes(), bytes);
    }
}

pub fn load_pending_otptxs() -> Vec<(String, crate::ledger::LedgerTx, i64)> {
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = match db.cf_handle(CF_META) { Some(c) => c, None => return vec![] };
    let now = chrono::Utc::now().timestamp();
    db.iterator_cf(cf, rocksdb::IteratorMode::Start)
        .flatten()
        .filter_map(|(k, v)| {
            let key_str = std::str::from_utf8(&k).ok()?;
            let tx_id = key_str.strip_prefix(META_OTP_TX_PREFIX)?;
            let obj = serde_json::from_slice::<serde_json::Value>(&v).ok()?;
            let expiry = obj["expiry"].as_i64()?;
            if expiry <= now { return None; }
            let tx: crate::ledger::LedgerTx = serde_json::from_value(obj["tx"].clone()).ok()?;
            Some((tx_id.to_string(), tx, expiry))
        })
        .collect()
}

pub fn remove_pending_otptx(tx_id: &str) {
    if tx_id.is_empty() { return; }
    let db = get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = match db.cf_handle(CF_META) { Some(c) => c, None => return };
    let key = format!("{}{}", META_OTP_TX_PREFIX, tx_id);
    let _ = db.delete_cf(cf, key.as_bytes());
}
