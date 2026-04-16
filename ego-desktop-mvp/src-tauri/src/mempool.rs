use crate::ledger::LedgerTx;
use once_cell::sync::OnceCell;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

pub const SHARD_COUNT: u32   = 256;
pub const BATCH_SIZE:  usize = 625;


pub const MIN_VALIDATORS_FOR_FINALITY: usize = 1;


pub const BATCH_WINDOW_MS: u64 = 3_000;


pub const BATCH_INTERVAL_MS: u64 = BATCH_WINDOW_MS;

pub const TX_THRESHOLD: u64 = 50;

pub const MAX_BLOCK_INTERVAL_S: u64 = 30;


pub const EMPTY_BLOCK_INTERVAL_S: u64 = 60;


pub const MAX_MEMPOOL_SIZE: usize = 500_000;


pub const MAX_TX_AGE_SECS: i64 = 300;

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

    seen_hashes:   Mutex<std::collections::HashSet<String>>,
    pending_total: AtomicU64,
    submitted:     AtomicU64,
    confirmed:     AtomicU64,

    pub tx_notify: Arc<Notify>,
}

impl ShardedMempool {
    fn new() -> Arc<Self> {
        let shards = (0..SHARD_COUNT)
            .map(|_| Mutex::new(Vec::with_capacity(BATCH_SIZE)))
            .collect();
        Arc::new(Self {
            shards,
            seen_hashes:   Mutex::new(std::collections::HashSet::new()),
            pending_total: AtomicU64::new(0),
            submitted:     AtomicU64::new(0),
            confirmed:     AtomicU64::new(0),
            tx_notify:     Arc::new(Notify::new()),
        })
    }


    pub fn push(&self, tx: LedgerTx) {
        // 1. Dedup: reject if the same tx hash is already pending.
        {
            let mut seen = self.seen_hashes.lock().expect("lock poisoned");
            if !seen.insert(tx.hash.clone()) {
                return; // already in mempool
            }
        }

        // 2. Hard cap: if at capacity, evict the cheapest pending tx to free a slot.
        if self.pending_total.load(Ordering::Relaxed) as usize >= MAX_MEMPOOL_SIZE {
            self.evict_one_cheapest();
        }

        let shard = shard_for_address(&tx.from) as usize;
        self.shards[shard].lock().expect("lock poisoned").push(tx);
        self.pending_total.fetch_add(1, Ordering::Relaxed);
        self.submitted.fetch_add(1, Ordering::Relaxed);
        self.tx_notify.notify_one();
    }


    fn evict_one_cheapest(&self) {
        let mut worst_shard = 0usize;
        let mut worst_fee   = u64::MAX;
        let mut worst_idx   = 0usize;
        let mut worst_hash  = String::new();


        for (i, shard) in self.shards.iter().enumerate() {
            let s = shard.lock().expect("lock poisoned");
            for (j, tx) in s.iter().enumerate() {
                let fee = tx.fee_uegoc.saturating_add(tx.priority_fee_uegoc);
                if fee < worst_fee {
                    worst_fee   = fee;
                    worst_shard = i;
                    worst_idx   = j;
                    worst_hash  = tx.hash.clone();
                }
            }
        }

        if worst_hash.is_empty() { return; }

        // Remove from shard (verify slot still holds the same tx to avoid races).
        {
            let mut s = self.shards[worst_shard].lock().expect("lock poisoned");
            if worst_idx < s.len() && s[worst_idx].hash == worst_hash {
                s.remove(worst_idx);
                self.pending_total.fetch_sub(1, Ordering::Relaxed);
            } else {
                // tx moved (concurrent drain) — give up on this eviction
                self.seen_hashes.lock().expect("lock poisoned").remove(&worst_hash);
                return;
            }
        }

        self.seen_hashes.lock().expect("lock poisoned").remove(&worst_hash);
        eprintln!(
            "[Mempool] Evicted lowest-fee tx {} (fee={} uEGOC) — mempool at capacity",
            &worst_hash[..worst_hash.len().min(12)], worst_fee
        );
    }


    pub fn drain_shard(&self, shard_id: u32) -> Vec<LedgerTx> {
        let mut expired_hashes: Vec<String> = Vec::new();

        let drained = {
            let mut s = self.shards[shard_id as usize].lock().expect("lock poisoned");
            if s.is_empty() { return vec![]; }

            // TTL eviction: remove stale txs that have been waiting too long.
            let now = chrono::Utc::now().timestamp();
            s.retain(|tx| {
                let stale = tx.timestamp > 0 && (now - tx.timestamp) >= MAX_TX_AGE_SECS;
                if stale { expired_hashes.push(tx.hash.clone()); }
                !stale
            });
            if !expired_hashes.is_empty() {
                let n = expired_hashes.len() as u64;
                self.pending_total.fetch_sub(n, Ordering::Relaxed);
                eprintln!(
                    "[Mempool] Evicted {} stale txs (>{}s old) from shard {}",
                    n, MAX_TX_AGE_SECS, shard_id
                );
            }

            if s.is_empty() { return vec![]; }

            // Sort by total fee descending (base + priority) to maximise miner revenue.
            s.sort_unstable_by(|a, b| {
                let fa = a.fee_uegoc + a.priority_fee_uegoc;
                let fb = b.fee_uegoc + b.priority_fee_uegoc;
                fb.cmp(&fa)
            });
            let n = s.len().min(BATCH_SIZE);
            let batch: Vec<LedgerTx> = s.drain(..n).collect();
            let count = batch.len() as u64;
            self.pending_total.fetch_sub(count, Ordering::Relaxed);
            self.confirmed.fetch_add(count, Ordering::Relaxed);
            batch
        };

        // Clean up seen_hashes for expired + drained txs (shard lock already released).
        if !expired_hashes.is_empty() || !drained.is_empty() {
            let mut seen = self.seen_hashes.lock().expect("lock poisoned");
            for h in &expired_hashes { seen.remove(h); }
            for tx in &drained        { seen.remove(&tx.hash); }
        }

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
            .flat_map(|s| s.lock().expect("lock poisoned").clone())
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
            .map(|s| s.lock().expect("lock poisoned").len())
            .collect()
    }

    pub fn any_shard_full(&self) -> bool {
        self.shards.iter()
            .any(|s| s.lock().expect("lock poisoned").len() >= BATCH_SIZE)
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
    if !crate::p2p::get_known_validators_snapshot().is_empty() {
        return;
    }

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
        "[Mempool] Solo block #{} sealed — {} user txs + 1 coinbase",
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

pub async fn run_batch_loop() {
    eprintln!(
        "[Mempool] Reactive batch loop started — \
         batch_window={}ms  threshold={}txs  max_wait={}s  empty_min={}s  \
         max_pending={}  tx_ttl={}s",
        BATCH_WINDOW_MS, TX_THRESHOLD, MAX_BLOCK_INTERVAL_S, EMPTY_BLOCK_INTERVAL_S,
        MAX_MEMPOOL_SIZE, MAX_TX_AGE_SECS,
    );

    let _ = crate::chain_db::get_db();

    let pool = get_mempool();

    let mut last_block_at    = Instant::now();
    let mut batch_started_at: Option<Instant> = None;

    loop {
        let notify  = pool.tx_notify.clone();
        let pending = pool.pending_count();

        let sleep_dur = if pending == 0 {
            let since_block = last_block_at.elapsed().as_secs();
            let until_empty = EMPTY_BLOCK_INTERVAL_S.saturating_sub(since_block);
            Duration::from_secs(until_empty.max(1))
        } else {
            let batch_remaining = batch_started_at
                .map(|t| {
                    let elapsed = t.elapsed().as_millis() as u64;
                    Duration::from_millis(BATCH_WINDOW_MS.saturating_sub(elapsed))
                })
                .unwrap_or(Duration::from_millis(BATCH_WINDOW_MS));

            let since_block   = last_block_at.elapsed().as_secs();
            let max_remaining = Duration::from_secs(
                MAX_BLOCK_INTERVAL_S.saturating_sub(since_block).max(1)
            );

            batch_remaining.min(max_remaining)
        };

        tokio::select! {
            _ = notify.notified() => {
                if batch_started_at.is_none() {
                    batch_started_at = Some(Instant::now());
                }
                if pool.pending_count() < TX_THRESHOLD {
                    continue;
                }
                eprintln!("[Mempool] TX_THRESHOLD ({}) reached — sealing immediately", TX_THRESHOLD);
            }
            _ = tokio::time::sleep(sleep_dur) => {}
        }

        let pending     = pool.pending_count();
        let since_block = last_block_at.elapsed().as_secs();

        let should_seal = if pending >= TX_THRESHOLD {
            true
        } else if pending > 0 {
            let batch_age = batch_started_at
                .map(|t| t.elapsed().as_millis() as u64)
                .unwrap_or(0);
            batch_age >= BATCH_WINDOW_MS || since_block >= MAX_BLOCK_INTERVAL_S
        } else {
            since_block >= EMPTY_BLOCK_INTERVAL_S
        };

        if !should_seal { continue; }

        if !crate::p2p::get_known_validators_snapshot().is_empty() {
            last_block_at    = Instant::now();
            batch_started_at = None;
            continue;
        }

        let miner = match get_miner_address() {
            Some(a) => a,
            None    => continue,
        };

        let active_validators = crate::ledger::active_validator_count();
        if active_validators < MIN_VALIDATORS_FOR_FINALITY {
            eprintln!(
                "[Consensus] ⚠ Solo-node mode: {} active validator(s) \
                 (need {} for BFT finality) — block will be accepted locally \
                 but chain is not Byzantine-fault-tolerant yet",
                active_validators, MIN_VALIDATORS_FOR_FINALITY
            );
        }

        let txs = pool.drain_all();
        try_mine(txs, &miner).await;

        last_block_at    = Instant::now();
        batch_started_at = None;
    }
}
