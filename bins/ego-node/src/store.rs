use ego_core::Account;
use rocksdb::{ColumnFamilyDescriptor, DBCompressionType, IteratorMode, Options, WriteBatch, DB};
use serde_json::Value;
use std::sync::OnceLock;

const BLOCK_CAP: u64 = 10_000;
const TX_CAP:    u64 = 50_000;
const DB_PATH:   &str = "ego-node-chain.db";

const CF_BLOCKS:     &str = "blocks";
const CF_TXS:        &str = "txs";
const CF_TX_INDEX:   &str = "tx_index";
const CF_ACCOUNTS:   &str = "accounts";
const CF_VALIDATORS: &str = "validators";
const CF_META:       &str = "meta";

const REWARD_POOL_KEY: &[u8] = b"\x00__reward_pool__";
const TOTAL_EMISSION_UEGOC_DEFAULT: u64 = 40_000_000 * 1_000_000;

static STORE: OnceLock<DB> = OnceLock::new();

fn store() -> &'static DB {
    STORE.get_or_init(|| {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_compression_type(DBCompressionType::Lz4);

        let cf_descs = vec![
            ColumnFamilyDescriptor::new(CF_BLOCKS, Options::default()),
            ColumnFamilyDescriptor::new(CF_TXS, Options::default()),
            ColumnFamilyDescriptor::new(CF_TX_INDEX, Options::default()),
            ColumnFamilyDescriptor::new(CF_ACCOUNTS, Options::default()),
            ColumnFamilyDescriptor::new(CF_VALIDATORS, Options::default()),
            ColumnFamilyDescriptor::new(CF_META, Options::default()),
        ];

        DB::open_cf_descriptors(&opts, DB_PATH, cf_descs)
            .expect("open ego-node chain store")
    })
}

#[inline]
fn height_key(h: u64) -> [u8; 8] {
    h.to_be_bytes()
}

#[inline]
fn ts_hash_key(ts: i64, hash: &str) -> Vec<u8> {
    let mut k = (ts as u64).to_be_bytes().to_vec();
    k.extend_from_slice(hash.as_bytes());
    k
}

pub fn insert_block(height: u64, body: &Value) {
    let db = store();
    let cf = db.cf_handle(CF_BLOCKS).unwrap();
    let _ = db.put_cf(cf, height_key(height), body.to_string().as_bytes());

    let count = {
        let iter = db.iterator_cf(cf, IteratorMode::Start);
        iter.count() as u64
    };
    if count > BLOCK_CAP {
        let mut batch = WriteBatch::default();
        let to_delete = count - BLOCK_CAP;
        let iter = db.iterator_cf(cf, IteratorMode::Start);
        for (i, item) in iter.enumerate() {
            if i as u64 >= to_delete {
                break;
            }
            if let Ok((k, _)) = item {
                batch.delete_cf(cf, k);
            }
        }
        let _ = db.write(batch);
    }
}

pub fn get_blocks(limit: usize) -> Vec<Value> {
    let db = store();
    let cf = db.cf_handle(CF_BLOCKS).unwrap();
    let iter = db.iterator_cf(cf, IteratorMode::End);
    iter.take(limit)
        .filter_map(|r| r.ok())
        .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
        .collect()
}

pub fn block_exists(height: u64) -> bool {
    let db = store();
    let cf = db.cf_handle(CF_BLOCKS).unwrap();
    db.get_cf(cf, height_key(height)).ok().flatten().is_some()
}

pub fn get_block_by_height(height: u64) -> Option<Value> {
    let db = store();
    let cf = db.cf_handle(CF_BLOCKS).unwrap();
    db.get_cf(cf, height_key(height))
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_slice(&v).ok())
}

pub fn get_blocks_range(from_height: u64, count: u64) -> Vec<Value> {
    let db = store();
    let cf = match db.cf_handle(CF_BLOCKS) {
        Some(cf) => cf,
        None => return vec![],
    };
    let mut result = Vec::new();
    for h in from_height..from_height + count {
        let key = h.to_be_bytes();
        if let Ok(Some(bytes)) = db.get_cf(cf, &key) {
            if let Ok(val) = serde_json::from_slice::<Value>(&bytes) {
                result.push(val);
            }
        }
    }
    result
}

pub fn insert_tx(hash: &str, ts: i64, body: &Value) {
    if hash.is_empty() {
        return;
    }

    let db = store();
    let cf = db.cf_handle(CF_TXS).unwrap();
    let cf_index = db.cf_handle(CF_TX_INDEX).unwrap();
    let key = ts_hash_key(ts, hash);

    let mut batch = WriteBatch::default();
    batch.put_cf(cf, &key, body.to_string().as_bytes());
    batch.put_cf(cf_index, hash.as_bytes(), &key);

    let count = {
        let iter = db.iterator_cf(cf, IteratorMode::Start);
        iter.count() as u64
    };
    if count > TX_CAP {
        let to_delete = count - TX_CAP;
        let iter = db.iterator_cf(cf, IteratorMode::Start);
        for (i, item) in iter.enumerate() {
            if i as u64 >= to_delete {
                break;
            }
            if let Ok((k, _)) = item {
                if k.len() > 8 {
                    batch.delete_cf(cf_index, &k[8..]);
                }
                batch.delete_cf(cf, k);
            }
        }
    }

    let _ = db.write(batch);
}

pub fn get_txs(limit: usize) -> Vec<Value> {
    let db = store();
    let cf = db.cf_handle(CF_TXS).unwrap();
    let iter = db.iterator_cf(cf, IteratorMode::End);
    iter.take(limit)
        .filter_map(|r| r.ok())
        .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
        .collect()
}

pub fn tx_exists(hash: &str) -> bool {
    if hash.is_empty() {
        return false;
    }
    let db = store();
    let cf_index = db.cf_handle(CF_TX_INDEX).unwrap();
    db.get_cf(cf_index, hash.as_bytes()).ok().flatten().is_some()
}

pub fn get_tx_by_hash(hash: &str) -> Option<Value> {
    if hash.is_empty() {
        return None;
    }
    let db = store();
    let cf = db.cf_handle(CF_TXS).unwrap();
    let cf_index = db.cf_handle(CF_TX_INDEX).unwrap();
    let key = db.get_cf(cf_index, hash.as_bytes()).ok().flatten()?;
    db.get_cf(cf, key)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_slice(&v).ok())
}

pub fn save_account(addr: &[u8; 20], account: &Account) {
    let db = store();
    let cf = db.cf_handle(CF_ACCOUNTS).unwrap();
    if let Ok(json) = serde_json::to_vec(account) {
        let _ = db.put_cf(cf, addr as &[u8], json);
    }
}

pub fn save_accounts_batch(accounts: &[(&[u8; 20], &Account)]) {
    if accounts.is_empty() {
        return;
    }
    let db = store();
    let cf = db.cf_handle(CF_ACCOUNTS).unwrap();
    let mut batch = WriteBatch::default();
    for (addr, acct) in accounts {
        if let Ok(json) = serde_json::to_vec(acct) {
            batch.put_cf(cf, addr.as_ref(), json);
        }
    }
    let _ = db.write(batch);
}

pub fn load_account(addr: &[u8; 20]) -> Option<Account> {
    let db = store();
    let cf = db.cf_handle(CF_ACCOUNTS).unwrap();
    db.get_cf(cf, addr as &[u8])
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_slice(&v).ok())
}

pub fn load_all_accounts() -> Vec<Account> {
    let db = store();
    let cf = db.cf_handle(CF_ACCOUNTS).unwrap();
    db.iterator_cf(cf, IteratorMode::Start)
        .filter_map(|r| r.ok())
        .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
        .collect()
}

pub fn save_validator_json(addr: &[u8; 20], info: &Value) {
    let db = store();
    let cf = db.cf_handle(CF_VALIDATORS).unwrap();
    let _ = db.put_cf(cf, addr as &[u8], info.to_string().as_bytes());
}

pub fn load_all_validators() -> Vec<Value> {
    let db = store();
    let cf = db.cf_handle(CF_VALIDATORS).unwrap();
    db.iterator_cf(cf, IteratorMode::Start)
        .filter_map(|r| r.ok())
        .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
        .collect()
}

pub fn save_reward_pool(remaining_uegoc: u64) {
    let db = store();
    let cf = db.cf_handle(CF_VALIDATORS).unwrap();
    let _ = db.put_cf(cf, REWARD_POOL_KEY, remaining_uegoc.to_le_bytes());
}

pub fn load_reward_pool() -> u64 {
    let db = store();
    let cf = match db.cf_handle(CF_VALIDATORS) {
        Some(cf) => cf,
        None => return TOTAL_EMISSION_UEGOC_DEFAULT,
    };
    match db.get_cf(cf, REWARD_POOL_KEY) {
        Ok(Some(ref bytes)) if bytes.len() == 8 => {
            u64::from_le_bytes(bytes.as_slice().try_into().unwrap_or([0; 8]))
        }
        _ => TOTAL_EMISSION_UEGOC_DEFAULT,
    }
}

pub fn save_fork_choice(state: &crate::engine::ForkChoiceState) {
    let db = store();
    if let Some(cf) = db.cf_handle(CF_META) {
        if let Ok(json) = serde_json::to_vec(state) {
            let _ = db.put_cf(cf, b"fork_choice_state", json);
        }
    }
}

pub fn load_fork_choice() -> Option<crate::engine::ForkChoiceState> {
    let db = store();
    let cf = db.cf_handle(CF_META)?;
    db.get_cf(cf, b"fork_choice_state").ok().flatten().and_then(|b| serde_json::from_slice(&b).ok())
}
