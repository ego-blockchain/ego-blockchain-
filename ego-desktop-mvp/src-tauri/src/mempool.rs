use crate::ledger::LedgerTx;
use once_cell::sync::OnceCell;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};

pub const SHARD_COUNT:       u32   = 16;

pub const BATCH_SIZE:        usize = 625;

pub const BATCH_INTERVAL_MS: u64   = 100;

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

    pub fn push(&self, tx: LedgerTx) {
        let shard = shard_for_address(&tx.from) as usize;
        self.shards[shard].lock().unwrap().push(tx);
        self.pending_total.fetch_add(1, Ordering::Relaxed);
        self.submitted.fetch_add(1, Ordering::Relaxed);
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

pub async fn run_batch_loop() {
    eprintln!(
        "[Rollup] Micro-slot loop started — {} shards, {}ms slot, {} TX/shard/slot  →  target {}k TPS",
        SHARD_COUNT,
        BATCH_INTERVAL_MS,
        BATCH_SIZE,
        (SHARD_COUNT as usize * BATCH_SIZE * (1000 / BATCH_INTERVAL_MS as usize)) / 1000,
    );

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

        let prev_hash = crate::chain_db::get_tip_hash();
        let (poc_ticket, _poc_sig) = match crate::poc::check_slot_winner(&prev_hash) {
            Some(t) => t,
            None    => continue,
        };
        let poc_slot = crate::poc::current_slot();

        let txs = pool.drain_all();
        if txs.is_empty() {
            continue;
        }

        let combined_ticket = format!("{}:{}", poc_ticket, _poc_sig);

        let block = crate::chain_db::mine_batch_db_with_ticket(&txs, &miner, &combined_ticket, poc_slot);

        eprintln!(
            "[Rollup] Block #{} — {} TXs in {}ms slot  ({} TPS instantaneous)",
            block.height,
            txs.len(),
            BATCH_INTERVAL_MS,
            (txs.len() as u64 * 1000) / BATCH_INTERVAL_MS,
        );

        crate::chain_db::pipeline_commit(block.height);

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
