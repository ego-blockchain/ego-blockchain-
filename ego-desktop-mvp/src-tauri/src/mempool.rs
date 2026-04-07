use crate::ledger::LedgerTx;
use once_cell::sync::OnceCell;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

pub const SHARD_COUNT: u32   = 16;
pub const BATCH_SIZE:  usize = 625;

/// After the first tx lands, wait this long to collect more before sealing.
pub const BATCH_WINDOW_MS: u64 = 3_000;

/// Kept for PoC slot calculation and rollup stats — represents the effective
/// average block time when the network is active (batch window duration).
pub const BATCH_INTERVAL_MS: u64 = BATCH_WINDOW_MS;

/// If the mempool reaches this many pending txs, seal immediately — don't wait.
pub const TX_THRESHOLD: u64 = 50;

/// Maximum time to hold pending txs before sealing a block (even if under threshold).
pub const MAX_BLOCK_INTERVAL_S: u64 = 30;

/// Minimum gap between reward-only (empty tx) blocks when the network is quiet.
pub const EMPTY_BLOCK_INTERVAL_S: u64 = 60;

pub fn shard_for_address(addr: &str) -> u32 {
    let mut h: u32 = 0xcbf29ce4;
    for b in addr.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h % SHARD_COUNT
}

pub struct ShardedMempool {
    shards:        Vec<Mutex<Vec<LedgerTx>>>,
    pending_total: AtomicU64,
    submitted:     AtomicU64,
    confirmed:     AtomicU64,
    /// Fires whenever a new tx is pushed — wakes the batch loop.
    pub tx_notify: Arc<Notify>,
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
            tx_notify:     Arc::new(Notify::new()),
        })
    }

    pub fn push(&self, tx: LedgerTx) {
        let shard = shard_for_address(&tx.from) as usize;
        self.shards[shard].lock().unwrap().push(tx);
        self.pending_total.fetch_add(1, Ordering::Relaxed);
        self.submitted.fetch_add(1, Ordering::Relaxed);
        self.tx_notify.notify_one();
    }

    pub fn drain_shard(&self, shard_id: u32) -> Vec<LedgerTx> {
        let mut s = self.shards[shard_id as usize].lock().unwrap();
        if s.is_empty() { return vec![]; }

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

    pub fn drain_all(&self) -> Vec<LedgerTx> {
        let mut all = Vec::new();
        for shard_id in 0..SHARD_COUNT {
            all.extend(self.drain_shard(shard_id));
        }
        all
    }

    /// Returns a snapshot of all pending txs without draining — for the explorer.
    pub fn peek_all(&self) -> Vec<LedgerTx> {
        self.shards.iter()
            .flat_map(|s| s.lock().unwrap().clone())
            .collect()
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

    pub fn shard_sizes(&self) -> Vec<usize> {
        self.shards.iter()
            .map(|s| s.lock().unwrap().len())
            .collect()
    }

    pub fn any_shard_full(&self) -> bool {
        self.shards.iter()
            .any(|s| s.lock().unwrap().len() >= BATCH_SIZE)
    }
}

static MEMPOOL: OnceCell<Arc<ShardedMempool>> = OnceCell::new();

pub fn get_mempool() -> Arc<ShardedMempool> {
    MEMPOOL.get_or_init(ShardedMempool::new).clone()
}

// ── Block production helpers ───────────────────────────────────────────────────

fn get_miner_address() -> Option<String> {
    let addr = crate::ledger::Ledger::load().address;
    if addr.is_empty() { None } else { Some(addr) }
}

async fn try_mine(txs: Vec<LedgerTx>, miner: &str) {
    let prev_hash = crate::chain_db::get_tip_hash();
    let (poc_ticket, _poc_sig) = match crate::poc::check_slot_winner(&prev_hash) {
        Some(t) => t,
        None    => return,
    };
    let poc_slot = crate::poc::current_slot();
    let combined_ticket = format!("{}:{}", poc_ticket, _poc_sig);

    let tx_count = txs.len();
    let block = crate::chain_db::mine_batch_db_with_ticket(&txs, miner, &combined_ticket, poc_slot);

    eprintln!(
        "[Mempool] Block #{} sealed — {} user txs + 1 coinbase",
        block.height, tx_count,
    );

    crate::chain_db::pipeline_commit(block.height);

    let height = block.height;
    let confirmed: Vec<LedgerTx> = txs.iter().map(|tx| {
        let mut t = tx.clone();
        t.status       = "Confirmed".to_string();
        t.block_height = Some(height);
        t
    }).collect();

    // Remove confirmed txs from the on-disk pending store so they're not
    // re-injected on next startup.
    for tx in &txs {
        crate::commands::tx_pending::remove(&tx.hash);
    }
    tokio::spawn(async move {
        for tx in &confirmed {
            crate::p2p::broadcast_tx(tx.clone(), block.clone()).await;
        }
    });
}

// ── Reactive batch loop ────────────────────────────────────────────────────────
//
// State machine:
//   Idle          → waiting for first tx (or empty-block timeout)
//   Batching      → first tx arrived; drains after BATCH_WINDOW_MS or TX_THRESHOLD
//   MaxWaitForced → txs pending > MAX_BLOCK_INTERVAL_S — seal regardless of window
//
// Empty blocks (coinbase only) are produced at most every EMPTY_BLOCK_INTERVAL_S
// so the miner still earns rewards during quiet periods without flooding the chain.

pub async fn run_batch_loop() {
    eprintln!(
        "[Mempool] Reactive batch loop started — \
         batch_window={}ms  threshold={}txs  max_wait={}s  empty_min={}s",
        BATCH_WINDOW_MS, TX_THRESHOLD, MAX_BLOCK_INTERVAL_S, EMPTY_BLOCK_INTERVAL_S,
    );

    let _ = crate::chain_db::get_db();

    let pool = get_mempool();

    // When we last sealed a block (for empty-block suppression).
    let mut last_block_at   = Instant::now();
    // When the batch window started (first tx after an idle period).
    let mut batch_started_at: Option<Instant> = None;

    loop {
        let notify  = pool.tx_notify.clone();
        let pending = pool.pending_count();

        // ── Determine how long to sleep before checking again ─────────────────
        let sleep_dur = if pending == 0 {
            // Idle: wake on new tx or when the empty-block timer fires.
            let since_block = last_block_at.elapsed().as_secs();
            let until_empty = EMPTY_BLOCK_INTERVAL_S.saturating_sub(since_block);
            Duration::from_secs(until_empty.max(1))
        } else {
            // Batching: wake at the earlier of batch-window end or max-wait end.
            let batch_remaining = batch_started_at
                .map(|t| {
                    let elapsed = t.elapsed().as_millis() as u64;
                    Duration::from_millis(BATCH_WINDOW_MS.saturating_sub(elapsed))
                })
                .unwrap_or(Duration::from_millis(BATCH_WINDOW_MS));

            let since_block    = last_block_at.elapsed().as_secs();
            let max_remaining  = Duration::from_secs(
                MAX_BLOCK_INTERVAL_S.saturating_sub(since_block).max(1)
            );

            batch_remaining.min(max_remaining)
        };

        // ── Wait for a tx notification OR the computed timeout ─────────────────
        tokio::select! {
            _ = notify.notified() => {
                // New tx pushed. Record when batching started.
                if batch_started_at.is_none() {
                    batch_started_at = Some(Instant::now());
                }
                // If threshold reached, fall through immediately to produce.
                if pool.pending_count() < TX_THRESHOLD {
                    continue; // keep collecting
                }
                eprintln!("[Mempool] TX_THRESHOLD ({}) reached — sealing immediately", TX_THRESHOLD);
            }
            _ = tokio::time::sleep(sleep_dur) => {
                // Timer fired.
            }
        }

        // ── Check if we should produce a block ────────────────────────────────
        let pending = pool.pending_count();
        let since_block = last_block_at.elapsed().as_secs();

        let should_seal = if pending >= TX_THRESHOLD {
            true // threshold
        } else if pending > 0 {
            let batch_age = batch_started_at
                .map(|t| t.elapsed().as_millis() as u64)
                .unwrap_or(0);
            batch_age >= BATCH_WINDOW_MS || since_block >= MAX_BLOCK_INTERVAL_S
        } else {
            // No user txs — only produce a reward block if enough time passed.
            since_block >= EMPTY_BLOCK_INTERVAL_S
        };

        if !should_seal {
            continue;
        }

        let miner = match get_miner_address() {
            Some(a) => a,
            None    => continue,
        };

        let txs = pool.drain_all();
        try_mine(txs, &miner).await;

        last_block_at   = Instant::now();
        batch_started_at = None;
    }
}
