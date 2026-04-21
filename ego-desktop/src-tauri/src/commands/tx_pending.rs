/// Persistent pending-transaction store.
///
/// When a user submits a transfer it is placed in the in-memory mempool.
/// If the app closes before the batch loop mines the block, the transaction
/// would be silently lost — the sender's balance was already deducted but
/// the coins never arrive.
///
/// This module writes every submitted transaction to
///   %LOCALAPPDATA%/EgoDesktop/wallet_N/tx_pending.json
/// on submit, and removes it only once it is confirmed in RocksDB.
/// On startup, any leftover entries are re-injected into the mempool so
/// the batch loop can mine them on the next cycle.

use crate::ledger::{data_dir, LedgerTx};
use std::fs;

fn pending_path() -> std::path::PathBuf {
    data_dir().join("tx_pending.json")
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

/// Call this immediately after pushing a tx to the mempool.
pub fn add(tx: &LedgerTx) {
    let mut txs = load();
    if !txs.iter().any(|t| t.hash == tx.hash) {
        txs.push(tx.clone());
        save(&txs);
    }
}

/// Call this after a tx is confirmed in a block.
pub fn remove(hash: &str) {
    let mut txs = load();
    let before = txs.len();
    txs.retain(|t| t.hash != hash);
    if txs.len() != before {
        save(&txs);
    }
}

/// On app startup: re-inject any pending txs that are not yet in chain_db
/// back into the mempool so the batch loop can mine them.
pub fn restore_to_mempool() {
    let txs = load();
    if txs.is_empty() { return; }

    let pool = crate::mempool::get_mempool();
    let mut restored = 0usize;

    for tx in &txs {
        // Skip if already confirmed in RocksDB (e.g. arrived via P2P while offline).
        if crate::chain_db::get_tx_by_hash(&tx.hash).is_some() {
            remove(&tx.hash);
            continue;
        }
        pool.push(tx.clone());
        restored += 1;
    }

    if restored > 0 {
        eprintln!("[TxPending] Restored {} pending tx(s) to mempool after restart", restored);
    }
}
