use ego_core::Transaction;
use std::cmp::Ordering as CmpOrd;
use std::collections::{BinaryHeap, HashMap};
use std::sync::{Mutex, MutexGuard};
use std::sync::atomic::{AtomicU64, Ordering};

pub const SHARD_COUNT: usize = 64;
pub const MAX_TOTAL:   usize = 50_000;

/// Effective fee for ordering: gross fee from ru_limit minus pob subsidy, then
/// priority_hint added as a 0–255 uEGOC bonus so senders can tip the block producer.
///
/// BASE_FEE_PER_RU matches the constant in ego-core's state.rs (10 uEGOC per RU).
const BASE_FEE_PER_RU: u128 = 10;

fn effective_fee(tx: &Transaction) -> u128 {
    let gross = tx.ru_limit as u128 * BASE_FEE_PER_RU;
    let net   = gross.saturating_sub(tx.pob_burn_credits as u128);
    net + tx.priority_hint as u128
}

/// Wrapper so Transaction can live in a max-BinaryHeap ordered by fee then age.
struct HeapEntry {
    fee:       u128,
    /// Timestamp as seconds — smaller = older = higher priority on ties.
    ts_secs:   u64,
    hash_hex:  String,
    tx:        Transaction,
}

impl PartialEq for HeapEntry {
    fn eq(&self, other: &Self) -> bool { self.hash_hex == other.hash_hex }
}
impl Eq for HeapEntry {}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrd> { Some(self.cmp(other)) }
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> CmpOrd {
        // Higher fee wins; on ties, older tx wins (lower ts_secs).
        self.fee.cmp(&other.fee)
            .then_with(|| other.ts_secs.cmp(&self.ts_secs))
    }
}

/// Per-shard state: BinaryHeap for O(log n) insert/pop + HashMap for O(1) remove-by-hash.
struct Shard {
    heap: BinaryHeap<HeapEntry>,
    map:  HashMap<String, ()>,   // tracks which hashes are in the heap
}

impl Shard {
    fn new() -> Self { Self { heap: BinaryHeap::new(), map: HashMap::new() } }
    fn is_empty(&self) -> bool { self.map.is_empty() }
    fn contains(&self, h: &str) -> bool { self.map.contains_key(h) }

    fn push(&mut self, tx: Transaction, hash_hex: String) {
        let fee    = effective_fee(&tx);
        let ts_secs = tx.timestamp.as_secs();
        self.map.insert(hash_hex.clone(), ());
        self.heap.push(HeapEntry { fee, ts_secs, hash_hex, tx });
    }

    /// Pop the highest-priority tx still present in `map`.
    /// Stale entries (removed via `remove_by_hash`) are skipped lazily.
    fn pop_best(&mut self) -> Option<Transaction> {
        loop {
            let entry = self.heap.pop()?;
            if self.map.remove(&entry.hash_hex).is_some() {
                return Some(entry.tx);
            }
            // Entry was already removed — discard and keep popping.
        }
    }

    /// Returns true if the entry existed and was tombstoned.
    fn remove_by_hash(&mut self, hash_hex: &str) -> bool {
        // Mark as removed in O(1); the BinaryHeap entry will be skipped lazily in pop_best.
        self.map.remove(hash_hex).is_some()
    }
}

pub struct ShardedMempool {
    shards: Vec<Mutex<Shard>>,
    total:  AtomicU64,
    /// (sender_bytes, nonce) → tx_hash_hex: prevents two pending txs with the same
    /// (from, nonce), which would cause a silent failure when the second is executed.
    nonce_index: Mutex<HashMap<([u8; 20], u64), String>>,
}

impl ShardedMempool {
    pub fn new() -> Self {
        let shards = (0..SHARD_COUNT)
            .map(|_| Mutex::new(Shard::new()))
            .collect();
        Self {
            shards,
            total: AtomicU64::new(0),
            nonce_index: Mutex::new(HashMap::new()),
        }
    }

    /// FNV-1a shard assignment from the first 16 chars of the tx hash hex.
    fn shard_idx(hash_hex: &str) -> usize {
        let slice = &hash_hex.as_bytes()[..hash_hex.len().min(16)];
        let h = slice.iter().fold(
            0xcbf2_9ce4_8422_2325_u64,
            |acc, &b| acc.wrapping_mul(0x0000_0001_0000_01b3) ^ (b as u64),
        );
        (h as usize) % SHARD_COUNT
    }

    fn lock_shard(&self, hash_hex: &str) -> MutexGuard<Shard> {
        self.shards[Self::shard_idx(hash_hex)].lock().unwrap()
    }

    /// Maximum age of a transaction in seconds before it is rejected on insert.
    /// Prevents replay of old signed transactions after nonce gaps are filled.
    pub const MAX_TX_AGE_SECS: i64 = 3_600; // 1 hour

    /// Insert a transaction.
    ///
    /// Rejected with an error if:
    /// - The tx timestamp is more than 1 hour in the past or more than 30s in the future (`"expired"`)
    /// - The tx hash is already in the pool (`"duplicate"`)
    /// - Another pending tx from the same sender already occupies this nonce (`"nonce conflict"`)
    /// - The pool is full (`"full"`)
    pub fn insert(&self, tx: Transaction) -> Result<(), &'static str> {
        // Reject stale or far-future transactions.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let tx_secs = tx.timestamp.as_secs() as i64;
        let age = now_secs - tx_secs;
        if age > Self::MAX_TX_AGE_SECS || age < -30 {
            return Err("expired");
        }

        let hash_hex  = hex::encode(tx.hash.as_bytes());
        let nonce_key = (*tx.from.as_bytes(), tx.nonce);

        // Lock order: nonce_index → shard (consistent across all methods).
        let mut ni = self.nonce_index.lock().unwrap();
        if let Some(existing) = ni.get(&nonce_key) {
            if existing != &hash_hex {
                return Err("nonce conflict");
            }
            // Same hash — duplicate check below will catch it.
        }
        if self.total.load(Ordering::Relaxed) as usize >= MAX_TOTAL {
            return Err("full");
        }
        let mut s = self.lock_shard(&hash_hex);
        if s.contains(&hash_hex) { return Err("duplicate"); }
        s.push(tx, hash_hex.clone());
        ni.insert(nonce_key, hash_hex);

        self.total.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn contains(&self, hash_hex: &str) -> bool {
        self.lock_shard(hash_hex).contains(hash_hex)
    }

    /// Drain up to `n` transactions, highest effective fee first.
    ///
    /// O(k log n) where k = txs drained — no full sort, just heap pops.
    pub fn drain_n(&self, n: usize) -> Vec<Transaction> {
        let mut out = Vec::with_capacity(n);
        let per_shard = ((n + SHARD_COUNT - 1) / SHARD_COUNT).max(1);

        // Lock order: nonce_index → shard.
        let mut ni = self.nonce_index.lock().unwrap();

        for shard_lock in &self.shards {
            if out.len() >= n { break; }
            let mut s = shard_lock.lock().unwrap();
            if s.is_empty() { continue; }

            let take = per_shard.min(n - out.len());
            for _ in 0..take {
                let Some(tx) = s.pop_best() else { break };
                let nonce_key = (*tx.from.as_bytes(), tx.nonce);
                ni.remove(&nonce_key);
                self.total.fetch_sub(1, Ordering::Relaxed);
                out.push(tx);
            }
        }
        out
    }

    /// Remove a specific tx (e.g. after it was included in a peer block).
    ///
    /// Lock ordering: nonce_index → shard (same as `insert`/`drain_n`).
    pub fn remove(&self, hash_hex: &str) {
        let mut ni = self.nonce_index.lock().unwrap();
        let mut s  = self.lock_shard(hash_hex);
        if s.remove_by_hash(hash_hex) {
            // Reconstruct the nonce_key by scanning ni — O(pending) but `remove` is rare.
            ni.retain(|_, v| v != hash_hex);
            self.total.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn len(&self) -> u64 { self.total.load(Ordering::Relaxed) }

    pub fn is_empty(&self) -> bool { self.len() == 0 }
}

impl Default for ShardedMempool {
    fn default() -> Self { Self::new() }
}
