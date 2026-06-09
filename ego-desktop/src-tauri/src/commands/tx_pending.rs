use crate::ledger::{data_dir, LedgerTx};
use std::fs;

fn pending_path() -> std::path::PathBuf {
    data_dir().join("tx_pending.json")
}

pub fn get_all() -> Vec<LedgerTx> {
    load()
}

fn load() -> Vec<LedgerTx> {
    fs::read_to_string(pending_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save(txs: &[LedgerTx]) {
    if let Ok(data) = serde_json::to_string(txs) {
        let _ = crate::utils::atomic_write(&pending_path(), data.as_bytes());
    }
}

pub fn add(tx: &LedgerTx) {
    if tx.signature.is_empty() || tx.public_key_ed25519.is_empty() {
        eprintln!("[TxPending] Dropping malformed TX {} — missing signature/pubkey", &tx.hash[..12.min(tx.hash.len())]);
        return;
    }
    let mut txs = load();
    if !txs.iter().any(|t| t.hash == tx.hash) {
        txs.push(tx.clone());
        save(&txs);
    }
}

pub fn remove(hash: &str) {
    let mut txs = load();
    let before = txs.len();
    txs.retain(|t| t.hash != hash);
    if txs.len() != before {
        save(&txs);
    }
}

pub fn clear() {
    save(&[]);
    eprintln!("[TxPending] All pending transactions cleared");
}

pub fn restore_to_mempool() {
    let txs = load();
    if txs.is_empty() { return; }

    let pool = crate::mempool::get_mempool();
    let mut restored = 0usize;
    let mut pruned = 0usize;

    for tx in &txs {
        if tx.signature.is_empty() || tx.public_key_ed25519.is_empty() {
            eprintln!("[TxPending] Pruning malformed TX {} — missing signature/pubkey", &tx.hash[..12.min(tx.hash.len())]);
            remove(&tx.hash);
            pruned += 1;
            continue;
        }

        if crate::chain_db::get_tx_by_hash(&tx.hash).is_some() {
            remove(&tx.hash);
            pruned += 1;
            continue;
        }

        let balance = crate::chain_db::balance_of(&tx.from);
        let amount_plus_fee = tx.amount + tx.fee_uegoc;
        if balance < amount_plus_fee {
            eprintln!("[TxPending] Pruning stale TX {} — sender {} balance {} < required {}",
                &tx.hash[..12.min(tx.hash.len())], &tx.from, balance, amount_plus_fee);
            remove(&tx.hash);
            pruned += 1;
            continue;
        }

        let confirmed_nonce = crate::ledger::last_confirmed_nonce(&tx.from);
        if tx.nonce > 0 && tx.nonce <= confirmed_nonce {
            eprintln!("[TxPending] Pruning stale TX {} — nonce {} already used (confirmed={})",
                &tx.hash[..12.min(tx.hash.len())], tx.nonce, confirmed_nonce);
            remove(&tx.hash);
            pruned += 1;
            continue;
        }

        match pool.push(tx.clone()) {
            Ok(_) => { restored += 1; }
            Err(ref e) if e.contains("too far ahead") => {
                eprintln!("[TxPending] TX {} deferred — nonce {} not yet confirmable (confirmed={}); will retry after oracle sync",
                    &tx.hash[..12.min(tx.hash.len())], tx.nonce, confirmed_nonce);
            }
            Err(e) => {
                eprintln!("[TxPending] Pruning TX {} — push rejected: {}", &tx.hash[..12.min(tx.hash.len())], e);
                remove(&tx.hash);
                pruned += 1;
            }
        }
    }

    if restored > 0 {
        eprintln!("[TxPending] Restored {} pending tx(s) to mempool after restart", restored);
    }
    if pruned > 0 {
        eprintln!("[TxPending] Pruned {} stale tx(s) from previous chain run", pruned);
    }
}
