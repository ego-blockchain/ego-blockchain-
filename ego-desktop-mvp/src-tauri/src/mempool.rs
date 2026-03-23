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

pub const SHARD_COUNT:       u32   = 16;
/// TXs per shard per 100-ms micro-slot.
/// 625 × 16 shards × 10 slots/s = 100,000 TPS target.
pub const BATCH_SIZE:        usize = 625;
/// Micro-slot interval: one block every 100 ms = 10 blocks/second.
pub const BATCH_INTERVAL_MS: u64   = 100;

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
    /// TXs are sorted by total fee (base + priority) descending so high-tip
    /// transactions are always included first — EIP-1559-style ordering.
    pub fn drain_shard(&self, shard_id: u32) -> Vec<LedgerTx> {
        let mut s = self.shards[shard_id as usize].lock().unwrap();
        if s.is_empty() { return vec![]; }
        // Sort: highest (fee_uegoc + priority_fee_uegoc) first.
        s.sort_unstable_by(|a, b| {
            let fa = a.fee_uegoc + a.priority_fee_uegoc;
            let fb = b.fee_uegoc + b.priority_fee_uegoc;
            fb.cmp(&fa)
        });
        let n = s.len().min(BATCH_SIZE);
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

/// Hot-path batch loop: mines one micro-slot block every 100 ms.
///
/// Uses `chain_db::mine_batch_db()` for O(1) block insertion — no chain.json
/// read/write, no full-chain serialization. Target: 100,000 TPS.
pub async fn run_batch_loop() {
    eprintln!(
        "[Rollup] Micro-slot loop started — {} shards, {}ms slot, {} TX/shard/slot  →  target {}k TPS",
        SHARD_COUNT,
        BATCH_INTERVAL_MS,
        BATCH_SIZE,
        (SHARD_COUNT as usize * BATCH_SIZE * (1000 / BATCH_INTERVAL_MS as usize)) / 1000,
    );

    // Warm up the DB connection (migration runs here if needed).
    let _ = crate::chain_db::get_db();

    let mut ticker = tokio::time::interval(
        std::time::Duration::from_millis(BATCH_INTERVAL_MS)
    );
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;

        let pool = get_mempool();
        if pool.pending_count() == 0 {
            continue;
        }

        let miner = {
            let ledger = crate::ledger::Ledger::load();
            ledger.address.clone()
        };
        if miner.is_empty() {
            continue;
        }

        // ── Proof of Coverage lottery ─────────────────────────────────────
        // Each node signs the slot seed with its Ed25519 key.  Only the node
        // whose ticket falls below the coverage-weighted threshold wins this
        // slot and is allowed to mine.  This makes block production:
        //   • Unpredictable — no node knows in advance if it will win.
        //   • Coverage-weighted — more storage/uptime/relay = higher chance.
        //   • Manipulation-resistant — TX value does not affect who mines;
        //     fees are burned so there's nothing to gain by stuffing blocks.
        let prev_hash = crate::chain_db::get_tip_hash();
        let (poc_ticket, _poc_sig) = match crate::poc::check_slot_winner(&prev_hash) {
            Some(t) => t,
            None    => continue, // didn't win this slot — TXs stay in pool
        };
        let poc_slot = crate::poc::current_slot();

        let txs = pool.drain_all();
        if txs.is_empty() {
            continue;
        }

        // Embed both ticket hash and sig in the block field: "ticket_hex:sig_hex"
        let combined_ticket = format!("{}:{}", poc_ticket, _poc_sig);
        // O(1) block insert — no chain.json load/save
        let block = crate::chain_db::mine_batch_db_with_ticket(&txs, &miner, &combined_ticket, poc_slot);

        eprintln!(
            "[Rollup] Block #{} — {} TXs in {}ms slot  ({} TPS instantaneous)",
            block.height,
            txs.len(),
            BATCH_INTERVAL_MS,
            (txs.len() as u64 * 1000) / BATCH_INTERVAL_MS,
        );

        // BFT pipeline: finalize blocks 2 slots behind the tip
        crate::chain_db::pipeline_commit(block.height);

        // Broadcast batch to P2P peers (fire-and-forget).
        // Stamp "Confirmed" + block_height so receivers' write_block_batch
        // doesn't filter them out (it skips status="Pending").
        let height = block.height;
        let confirmed: Vec<crate::ledger::LedgerTx> = txs.iter().map(|tx| {
            let mut t = tx.clone();
            t.status       = "Confirmed".to_string();
            t.block_height = Some(height);
            t
        }).collect();
        tokio::spawn(async move {
            for tx in &confirmed {
                crate::p2p::broadcast_tx(tx.clone(), block.clone()).await;
            }
        });
    }
}
