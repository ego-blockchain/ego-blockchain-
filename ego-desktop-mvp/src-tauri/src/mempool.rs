/// Shard-partitioned in-memory transaction pool.
///
/// Architecture:
///   send_transaction → MEMPOOL (shard-partitioned)
///                              ↓ every BATCH_INTERVAL_MS or BATCH_SIZE TXs
///                         batch_loop
///                              ↓
///                    mine_batch (one block for N TXs)
///                              ↓
///                    save_chain (once per batch, not per TX)
///                              ↓
///                    broadcast_batch
///
/// With SHARD_COUNT=16, BATCH_SIZE=2000, BATCH_INTERVAL_MS=50:
///   theoretical peak = 16 × 2000 / 0.05s = 640,000 TPS
///   realistic target  ≈ 100,000 TPS (accounting for I/O and network overhead)

use crate::ledger::LedgerTx;
use once_cell::sync::OnceCell;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};

pub const SHARD_COUNT:       u32  = 16;
pub const BATCH_SIZE:        usize = 2_000;  // TXs per batch per shard
pub const BATCH_INTERVAL_MS: u64  = 50;      // flush every 50 ms

// ── Shard routing ─────────────────────────────────────────────────────────────

/// Deterministically map an address to a shard using FNV-1a over the raw bytes.
/// Same algorithm used in ego-core's `calculate_shard_for_address`.
pub fn shard_for_address(addr: &str) -> u32 {
    let mut h: u32 = 0xcbf29ce4;
    for b in addr.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h % SHARD_COUNT
}

// ── Sharded mempool ───────────────────────────────────────────────────────────

pub struct ShardedMempool {
    shards:        Vec<Mutex<Vec<LedgerTx>>>,
    pending_total: AtomicU64,
    /// Monotonic counter of TXs ever enqueued (for throughput tracking).
    submitted:     AtomicU64,
    /// Monotonic counter of TXs ever confirmed (drained into a batch).
    confirmed:     AtomicU64,
}

impl ShardedMempool {
    fn new() -> Arc<Self> {
        let shards = (0..SHARD_COUNT)
            .map(|_| Mutex::new(Vec::with_capacity(BATCH_SIZE)))
            .collect();
        Arc::new(Self {
            shards,
            pending_total: AtomicU64::new(0),
            submitted:     AtomicU64::new(0),
            confirmed:     AtomicU64::new(0),
        })
    }

    /// Enqueue a single TX into the appropriate shard.
    pub fn push(&self, tx: LedgerTx) {
        let shard = shard_for_address(&tx.from) as usize;
        self.shards[shard].lock().unwrap().push(tx);
        self.pending_total.fetch_add(1, Ordering::Relaxed);
        self.submitted.fetch_add(1, Ordering::Relaxed);
    }

    /// Drain up to BATCH_SIZE TXs from one shard for batch processing.
    pub fn drain_shard(&self, shard_id: u32) -> Vec<LedgerTx> {
        let mut s = self.shards[shard_id as usize].lock().unwrap();
        let n = s.len().min(BATCH_SIZE);
        if n == 0 { return vec![]; }
        let drained: Vec<LedgerTx> = s.drain(..n).collect();
        let count = drained.len() as u64;
        self.pending_total.fetch_sub(count, Ordering::Relaxed);
        self.confirmed.fetch_add(count, Ordering::Relaxed);
        drained
    }

    /// Drain ALL shards and return a flat vec.
    pub fn drain_all(&self) -> Vec<LedgerTx> {
        let mut all = Vec::new();
        for shard_id in 0..SHARD_COUNT {
            all.extend(self.drain_shard(shard_id));
        }
        all
    }

    pub fn pending_count(&self) -> u64 {
        self.pending_total.load(Ordering::Relaxed)
    }

    pub fn submitted_count(&self) -> u64 {
        self.submitted.load(Ordering::Relaxed)
    }

    pub fn confirmed_count(&self) -> u64 {
        self.confirmed.load(Ordering::Relaxed)
    }

    /// Per-shard pending lengths — useful for load-balance monitoring.
    pub fn shard_sizes(&self) -> Vec<usize> {
        self.shards.iter()
            .map(|s| s.lock().unwrap().len())
            .collect()
    }

    /// True when any shard has reached BATCH_SIZE — caller should flush immediately.
    pub fn any_shard_full(&self) -> bool {
        self.shards.iter()
            .any(|s| s.lock().unwrap().len() >= BATCH_SIZE)
    }
}

// ── Global accessor ───────────────────────────────────────────────────────────

static MEMPOOL: OnceCell<Arc<ShardedMempool>> = OnceCell::new();

pub fn get_mempool() -> Arc<ShardedMempool> {
    MEMPOOL.get_or_init(ShardedMempool::new).clone()
}

// ── Batch loop (runs forever as a background task) ────────────────────────────

/// Spawned once from main.rs — drains the mempool on every tick and mines a
/// batch block if there are pending TXs.
pub async fn run_batch_loop() {
    eprintln!("[Rollup] Batch loop started — {} shards, {}ms interval, {} TX/batch",
              SHARD_COUNT, BATCH_INTERVAL_MS, BATCH_SIZE);

    let mut ticker = tokio::time::interval(
        std::time::Duration::from_millis(BATCH_INTERVAL_MS)
    );
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Track unix timestamp of the last mined block to enforce minimum block time.
    let mut last_block_ts: i64 = 0;

    loop {
        ticker.tick().await;

        let pool = get_mempool();

        // Skip tick if nothing is pending and no shard is full.
        if pool.pending_count() == 0 { continue; }

        // Enforce minimum block interval: only mine once per TARGET_BLOCK_SECS.
        let now_ts = chrono::Utc::now().timestamp();
        if now_ts - last_block_ts < crate::tokenomics::TARGET_BLOCK_SECS as i64 {
            continue;
        }

        let txs = pool.drain_all();
        if txs.is_empty() { continue; }

        let ledger = crate::ledger::Ledger::load();
        let miner  = ledger.address.clone();
        if miner.is_empty() { continue; }

        let mut chain = crate::ledger::load_chain();
        let block     = chain.mine_batch(&txs, &miner);

        if let Err(e) = crate::ledger::save_chain(&chain) {
            eprintln!("[Rollup] Save error: {e}");
            continue;
        }

        last_block_ts = now_ts;
        eprintln!("[Rollup] Block #{} — {} TXs confirmed ({} TPS theoretical)",
                  block.height, txs.len(),
                  (txs.len() as u64 * 1000) / BATCH_INTERVAL_MS);

        // Broadcast batch to P2P peers (fire-and-forget)
        tokio::spawn(async move {
            for tx in &txs {
                crate::p2p::broadcast_tx(tx.clone(), block.clone()).await;
            }
        });
    }
}
