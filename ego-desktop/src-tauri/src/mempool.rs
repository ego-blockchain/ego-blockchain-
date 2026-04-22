use crate::ledger::LedgerTx;
use once_cell::sync::OnceCell;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

pub const SHARD_COUNT: u32   = 256;
pub const BATCH_SIZE:  usize = 10_000;


/// Solo-mine threshold: once this many validators are online the mempool defers
/// block production to BFT propose_block_as_leader() instead of mining solo.
/// Default 1 — disable solo mining as soon as any peer validator exists.
/// Override with EGO_MIN_VALIDATORS env var (e.g. =21 for strict mainnet gate).
pub fn min_validators_for_finality() -> usize {
    std::env::var("EGO_MIN_VALIDATORS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1)
}

pub const MIN_VALIDATORS_FOR_FINALITY: usize = 1;


pub const BATCH_WINDOW_MS: u64 = 1_000;


pub const BATCH_INTERVAL_MS: u64 = BATCH_WINDOW_MS;

pub const TX_THRESHOLD: u64 = 50;

pub const MAX_BLOCK_INTERVAL_S: u64 = 30;


pub const EMPTY_BLOCK_INTERVAL_S: u64 = 60;


pub const MAX_MEMPOOL_SIZE: usize = 2_000_000;


pub const MAX_TX_AGE_SECS: i64 = 300;

pub const MIN_FEE_UEGOC: u64 = 1_000;

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
        let is_system = tx.from.is_empty()
            || tx.tx_type == "reward"
            || tx.tx_type == "coinbase";

        if !is_system {
            let network_size =
                crate::p2p::get_known_validators_snapshot().len() as u32 + 1;
            let total_shards = crate::sharding::compute_shard_count(network_size);
            if total_shards > 1 {
                let mut h: u64 = 0xcbf29ce484222325;
                for b in tx.from.bytes() {
                    h ^= b as u64;
                    h = h.wrapping_mul(0x00000100000001b3);
                }
                let tx_blockchain_shard = (h % total_shards as u64) as u32;
                let my_addr = crate::ledger::Ledger::load().address;
                let map = crate::sharding::load_shard_map();
                let all_nodes: Vec<String> = map
                    .assignments
                    .iter()
                    .map(|a| a.node_address.clone())
                    .collect::<std::collections::HashSet<_>>()
                    .into_iter()
                    .collect();
                let my_shard_ids: Vec<u32> =
                    crate::sharding::my_shards(&my_addr, &map, &all_nodes)
                        .into_iter()
                        .map(|(id, _)| id)
                        .collect();
                if !my_shard_ids.contains(&tx_blockchain_shard) {
                    let shard_id = tx_blockchain_shard;
                    let tx_clone = tx;
                    tokio::spawn(async move {
                        crate::p2p::route_tx_to_shard_master(shard_id, tx_clone).await;
                    });
                    return;
                }
            }
        }

        if !is_system {
            if tx.fee_uegoc < MIN_FEE_UEGOC {
                eprintln!(
                    "[Mempool] Rejected {} — fee {} uEGOC below floor {}",
                    &tx.hash[..12.min(tx.hash.len())], tx.fee_uegoc, MIN_FEE_UEGOC
                );
                return;
            }
            let current_base_fee = crate::chain_db::get_current_base_fee();
            if tx.fee_uegoc < current_base_fee {
                eprintln!(
                    "[Mempool] Rejected {} — fee {} uEGOC below current base fee {}",
                    &tx.hash[..12.min(tx.hash.len())], tx.fee_uegoc, current_base_fee
                );
                return;
            }

            if tx.nonce > 0 {
                let confirmed_nonce = crate::ledger::last_confirmed_nonce(&tx.from);
                if tx.nonce <= confirmed_nonce {
                    eprintln!(
                        "[Mempool] Rejected {} — replay nonce {} <= confirmed {}",
                        &tx.hash[..12.min(tx.hash.len())], tx.nonce, confirmed_nonce
                    );
                    return;
                }
                if tx.nonce > confirmed_nonce + 10 {
                    eprintln!(
                        "[Mempool] Rejected {} — nonce {} too far ahead of confirmed {}",
                        &tx.hash[..12.min(tx.hash.len())], tx.nonce, confirmed_nonce
                    );
                    return;
                }
            }
        }

        {
            let mut seen = self.seen_hashes.lock().expect("lock poisoned");
            if !seen.insert(tx.hash.clone()) {
                return;
            }
        }

        let shard = shard_for_address(&tx.from) as usize;
        let mut s = self.shards[shard].lock().expect("lock poisoned");

        if !is_system {
            let balance = crate::chain_db::balance_of(&tx.from);
            let pending_outflow: u64 = s.iter()
                .filter(|t| t.from == tx.from)
                .map(|t| t.amount.saturating_add(t.fee_uegoc))
                .fold(0u64, |acc, v| acc.saturating_add(v));
            let required = tx.amount.saturating_add(tx.fee_uegoc).saturating_add(pending_outflow);
            if balance < required {
                eprintln!(
                    "[Mempool] Rejected {} — insufficient balance: has {} uEGOC, needs {} (amount {} + fee {} + pending_outflow {})",
                    &tx.hash[..12.min(tx.hash.len())], balance, required,
                    tx.amount, tx.fee_uegoc, pending_outflow
                );
                self.seen_hashes.lock().expect("lock poisoned").remove(&tx.hash);
                return;
            }
        }

        // Localized O(K) eviction instead of O(N) global scan
        let max_per_shard = MAX_MEMPOOL_SIZE / SHARD_COUNT as usize;
        if s.len() >= max_per_shard {
            let mut worst_fee = u64::MAX;
            let mut worst_idx = 0;
            for (j, existing_tx) in s.iter().enumerate() {
                let fee = existing_tx.fee_uegoc.saturating_add(existing_tx.priority_fee_uegoc);
                if fee < worst_fee {
                    worst_fee = fee;
                    worst_idx = j;
                }
            }
            let evicted = s.remove(worst_idx);
            self.seen_hashes.lock().expect("lock poisoned").remove(&evicted.hash);
            self.pending_total.fetch_sub(1, Ordering::Relaxed);
            eprintln!("[Mempool] Evicted lowest-fee tx {} from shard {}", &evicted.hash[..12], shard);
        }

        let tx_hash_for_notify = tx.hash.clone();
        s.push(tx);
        self.pending_total.fetch_add(1, Ordering::Relaxed);
        self.submitted.fetch_add(1, Ordering::Relaxed);
        self.tx_notify.notify_one();
        drop(s);
        crate::rpc::notify_pending_tx(&tx_hash_for_notify);
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
        use rayon::prelude::*;
        (0..SHARD_COUNT)
            .into_par_iter()
            .flat_map(|shard_id| self.drain_shard(shard_id))
            .collect()
    }

    pub fn peek_all(&self) -> Vec<LedgerTx> {
        use rayon::prelude::*;
        self.shards.par_iter()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::LedgerTx;

    fn sys_tx(hash: &str) -> LedgerTx {
        LedgerTx { hash: hash.to_string(), from: String::new(), to: "egot1recv".to_string(),
            amount: 0, fee_uegoc: 0, tx_type: "coinbase".to_string(),
            timestamp: 0, status: "Pending".to_string(), ..LedgerTx::default() }
    }

    #[test]
    fn shard_is_deterministic() {
        assert_eq!(shard_for_address("egot1abc"), shard_for_address("egot1abc"));
        assert!(shard_for_address("egot1abc") < SHARD_COUNT);
    }

    #[test]
    fn duplicate_hash_rejected() {
        let pool = ShardedMempool::new();
        let tx = sys_tx("0xdup");
        pool.push(tx.clone());
        pool.push(tx);
        assert_eq!(pool.pending_count(), 1);
    }

    #[test]
    fn system_tx_bypasses_fee_check() {
        let pool = ShardedMempool::new();
        pool.push(sys_tx("0xcb1"));
        assert_eq!(pool.pending_count(), 1);
    }

    #[test]
    fn drain_empties_pool() {
        let pool = ShardedMempool::new();
        for i in 0..4u64 {
            pool.push(sys_tx(&format!("0xd{i}")));
        }
        let got = pool.drain_all();
        assert_eq!(got.len(), 4);
        assert_eq!(pool.pending_count(), 0);
    }

    #[test]
    fn user_tx_below_fee_floor_rejected() {
        let pool = ShardedMempool::new();
        let tx = LedgerTx {
            hash: "0xlow".to_string(),
            from: "egot1sender0000000000000000000000000000000000".to_string(),
            to: "egot1recv".to_string(),
            amount: 1000,
            fee_uegoc: MIN_FEE_UEGOC - 1,
            nonce: 1,
            tx_type: "transfer".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            status: "Pending".to_string(),
            ..LedgerTx::default()
        };
        pool.push(tx);
        assert_eq!(pool.pending_count(), 0);
    }
}

// ── Block production helpers ───────────────────────────────────────────────────

fn get_miner_address() -> Option<String> {
    let addr = crate::ledger::Ledger::load().address;
    if addr.is_empty() { None } else { Some(addr) }
}

async fn try_mine(txs: Vec<LedgerTx>, miner: &str) -> Vec<LedgerTx> {
    let known = crate::p2p::get_known_validators_snapshot();
    if known.len() >= min_validators_for_finality() {
        return txs;
    }

    let prev_hash = crate::chain_db::get_tip_hash();
    let (poc_ticket, _poc_sig) = match crate::poc::check_slot_winner(&prev_hash) {
        Some(t) => t,
        None    => return txs,
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
    crate::rpc::notify_new_block(&block);

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
    vec![]
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

        let miner = match get_miner_address() {
            Some(a) => a,
            None    => continue,
        };

        let known_count = crate::p2p::get_known_validators_snapshot().len();
        let needed = min_validators_for_finality();
        if known_count >= needed {
            // BFT mode: leave txs in mempool for the BFT proposer to drain.
            last_block_at    = Instant::now();
            batch_started_at = None;
            continue;
        }

        eprintln!(
            "[Consensus] ⚠ Pre-BFT mode: {} known validator(s) \
             (need {} for Byzantine-fault-tolerant finality) — \
             solo mining until quorum is reached",
            known_count, needed
        );

        let txs = pool.drain_all();
        let unprocessed = try_mine(txs, &miner).await;
        for tx in unprocessed {
            pool.push(tx);
        }

        last_block_at    = Instant::now();
        batch_started_at = None;
    }
}
