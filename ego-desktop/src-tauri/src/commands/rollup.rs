use crate::error::EgoDesktopError;
use crate::mempool::{get_mempool, BATCH_INTERVAL_MS, BATCH_SIZE, SHARD_COUNT};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct RollupStatus {

    pub shard_count: u32,

    pub pending_txs: u64,

    pub submitted_total: u64,

    pub confirmed_total: u64,

    pub batch_interval_ms: u64,

    pub batch_size: u64,

    pub total_blocks: u64,

    pub total_txs: u64,

    pub latest_block_height: u64,

    pub shard_sizes: Vec<usize>,

    pub theoretical_tps: u64,

    pub last_batch_tps: u64,
}

#[derive(Debug, Serialize)]
pub struct ShardInfo {
    pub shard_id:    u32,
    pub pending_txs: usize,
    pub total_txs:   u64,
}

#[tauri::command]
pub async fn get_rollup_status() -> Result<RollupStatus, EgoDesktopError> {
    let pool  = get_mempool();
    let chain = crate::ledger::load_chain();

    let latest_height = chain.blocks.last().map(|b| b.height).unwrap_or(0);

    let last_batch_tps = if let Some(last) = chain.blocks.last() {
        if last.tx_count > 1 {
            (last.tx_count.saturating_sub(1) as u64 * 1000) / BATCH_INTERVAL_MS
        } else {
            0
        }
    } else {
        0
    };

    let shard_map     = crate::sharding::load_shard_map();
    let network_shards = shard_map.shard_count.max(1);

    let theoretical_tps = network_shards as u64 * BATCH_SIZE as u64 * 1000 / BATCH_INTERVAL_MS;

    let raw_sizes = pool.shard_sizes();
    let bucket = (SHARD_COUNT as usize).max(1);
    let mut net_sizes = vec![0usize; network_shards as usize];
    for (i, &sz) in raw_sizes.iter().enumerate() {
        let slot = (i * network_shards as usize / bucket).min(network_shards as usize - 1);
        net_sizes[slot] += sz;
    }

    Ok(RollupStatus {
        shard_count:         network_shards,
        pending_txs:         pool.pending_count(),
        submitted_total:     pool.submitted_count(),
        confirmed_total:     pool.confirmed_count(),
        batch_interval_ms:   BATCH_INTERVAL_MS,
        batch_size:          BATCH_SIZE as u64,
        total_blocks:        chain.blocks.len() as u64,
        total_txs:           chain.transactions.len() as u64,
        latest_block_height: latest_height,
        shard_sizes:         net_sizes,
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
