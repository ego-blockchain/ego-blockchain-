//! Rollup / sharding status commands exposed to the frontend.

use crate::error::EgoDesktopError;
use crate::mempool::{get_mempool, BATCH_INTERVAL_MS, BATCH_SIZE, SHARD_COUNT};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct RollupStatus {
    /// Number of active shards.
    pub shard_count: u32,
    /// TXs currently waiting in the mempool.
    pub pending_txs: u64,
    /// TXs submitted to mempool since node start.
    pub submitted_total: u64,
    /// TXs confirmed (drained into blocks) since node start.
    pub confirmed_total: u64,
    /// Flush interval in milliseconds.
    pub batch_interval_ms: u64,
    /// Maximum TXs per batch per shard.
    pub batch_size: u64,
    /// Total blocks on chain.
    pub total_blocks: u64,
    /// Total TXs on chain (including coinbase).
    pub total_txs: u64,
    /// Latest block height.
    pub latest_block_height: u64,
    /// Per-shard pending TX counts.
    pub shard_sizes: Vec<usize>,
    /// Theoretical peak TPS = shard_count × batch_size × (1000 / batch_interval_ms)
    pub theoretical_tps: u64,
    /// Last measured batch TPS (TXs in last block / block interval).
    pub last_batch_tps: u64,
}

#[derive(Debug, Serialize)]
pub struct ShardInfo {
    pub shard_id:    u32,
    pub pending_txs: usize,
    pub total_txs:   u64, // confirmed TXs whose sender maps to this shard
}

#[tauri::command]
pub async fn get_rollup_status() -> Result<RollupStatus, EgoDesktopError> {
    let pool  = get_mempool();
    let chain = crate::ledger::load_chain();

    let latest_height = chain.blocks.last().map(|b| b.height).unwrap_or(0);

    // Estimate last_batch_tps from the most recent block's tx_count
    let last_batch_tps = if let Some(last) = chain.blocks.last() {
        if last.tx_count > 1 {
            // tx_count includes coinbase; subtract 1 for user TXs
            (last.tx_count.saturating_sub(1) as u64 * 1000) / BATCH_INTERVAL_MS
        } else {
            0
        }
    } else {
        0
    };

    let theoretical_tps =
        SHARD_COUNT as u64 * BATCH_SIZE as u64 * 1000 / BATCH_INTERVAL_MS;

    Ok(RollupStatus {
        shard_count:       SHARD_COUNT,
        pending_txs:       pool.pending_count(),
        submitted_total:   pool.submitted_count(),
        confirmed_total:   pool.confirmed_count(),
        batch_interval_ms: BATCH_INTERVAL_MS,
        batch_size:        BATCH_SIZE as u64,
        total_blocks:      chain.blocks.len() as u64,
        total_txs:         chain.transactions.len() as u64,
        latest_block_height: latest_height,
        shard_sizes:       pool.shard_sizes(),
        theoretical_tps,
        last_batch_tps,
    })
}

#[tauri::command]
pub fn get_shard_map_status() -> serde_json::Value {
    crate::sharding::get_shard_status()
}

#[tauri::command]
pub async fn get_shard_stats() -> Result<Vec<ShardInfo>, EgoDesktopError> {
    let pool  = get_mempool();
    let chain = crate::ledger::load_chain();
    let sizes = pool.shard_sizes();

    let stats = (0..SHARD_COUNT)
        .map(|shard_id| {
            // Count confirmed TXs that belong to this shard
            let confirmed = chain.transactions.iter()
                .filter(|tx| {
                    tx.status == "Confirmed"
                    && crate::mempool::shard_for_address(&tx.from) == shard_id
                })
                .count() as u64;

            ShardInfo {
                shard_id,
                pending_txs: sizes[shard_id as usize],
                total_txs:   confirmed,
            }
        })
        .collect();

    Ok(stats)
}
