use crate::ledger::LedgerTx;
use once_cell::sync::OnceCell;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tauri::Manager;

pub const SHARD_COUNT: u32   = 256;
pub const BATCH_SIZE:  usize = 100_000;
pub const MAX_BLOCK_TXS: usize = 500_000;



pub fn min_validators_for_finality() -> usize {
    std::env::var("EGO_MIN_VALIDATORS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(crate::bft_committee::MIN_LIVE_VALIDATORS)
}

pub const MIN_VALIDATORS_FOR_FINALITY: usize = crate::bft_committee::MIN_LIVE_VALIDATORS;

fn allow_pre_bft_solo() -> bool {
    std::env::var("EGO_ALLOW_PRE_BFT_SOLO")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true)
}


pub const BATCH_WINDOW_MS: u64 = 1_000;


pub const BATCH_INTERVAL_MS: u64 = BATCH_WINDOW_MS;

pub const TX_THRESHOLD: u64 = 50;

pub const MAX_BLOCK_INTERVAL_S: u64 = 5;


pub const EMPTY_BLOCK_INTERVAL_S: u64 = 60;


pub const MAX_MEMPOOL_SIZE: usize = 2_000_000;


pub const MAX_TX_AGE_SECS: i64 = 1800;

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

    seen_hashes:   Vec<Mutex<std::collections::HashSet<String>>>,
    pending_total: AtomicU64,
    submitted:     AtomicU64,
    confirmed:     AtomicU64,

    pub tx_notify: Arc<Notify>,
}

impl ShardedMempool {
    fn new() -> Arc<Self> {
        let shards = (0..SHARD_COUNT)
            .map(|_| Mutex::new(Vec::new()))
            .collect();
        let seen_hashes = (0..SHARD_COUNT)
            .map(|_| Mutex::new(std::collections::HashSet::new()))
            .collect();
        Arc::new(Self {
            shards,
            seen_hashes,
            pending_total: AtomicU64::new(0),
            submitted:     AtomicU64::new(0),
            confirmed:     AtomicU64::new(0),
            tx_notify:     Arc::new(Notify::new()),
        })
    }


    pub fn push(&self, tx: LedgerTx) -> Result<(), String> {
        let is_pool_faucet = tx.tx_type == "faucet"
            && tx.from == crate::chain_db::NODE_POOL_ADDR;

        let is_system = tx.from.is_empty()
            || tx.tx_type == "reward"
            || tx.tx_type == "coinbase"
            || tx.tx_type == "faucet"
            || tx.from.starts_with("egot1faucet");

        if is_system && !is_pool_faucet {
            tracing::warn!("Mempool rejected {} - system txs are only valid inside verified blocks", tx.hash);
            return Err("System txs are only valid inside verified blocks".into());
        }

        {
            let shard_idx = shard_for_address(&tx.from) as usize;
            if self.seen_hashes[shard_idx].lock().expect("lock poisoned").contains(&tx.hash) {
                return Ok(());
            }
        }

        if !is_pool_faucet {
            if let Err(reason) = crate::ledger::verify_incoming_tx(&tx) {
                eprintln!("[Mempool] REJECTED {:.12} — {}", tx.hash, reason);
                return Err(reason);
            }
        }

        let balance = if !is_system {
            crate::chain_db::balance_of(&tx.from)
        } else { 0 };

        let active_stake = if !is_system && tx.tx_type == "unstake" && tx.to == crate::chain_db::STAKING_ADDR {
            crate::ledger::get_validator_stake(&tx.from)
        } else { 0 };

        if !is_system {
            let small_network = crate::p2p::known_validator_count() < 4;
            if !small_network {
                let current_height = crate::chain_db::latest_block_info().0;
                let in_grace = crate::sharding::is_in_grace_period(current_height);
                if !in_grace {
                    let tx_shard = crate::sharding::shard_for_address_agreed(&tx.from);
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
                    if !my_shard_ids.contains(&tx_shard) {
                        let shard_id = tx_shard;
                        let tx_clone = tx;
                        tokio::spawn(async move {
                            crate::p2p::route_tx_to_shard_master(shard_id, tx_clone).await;
                        });
                        return Ok(()); // Routed
                    }
                }
            }
        }

        if !is_system {
            if tx.fee_uegoc < MIN_FEE_UEGOC {
                let err = format!("fee {} uEGOC below floor {}", tx.fee_uegoc, MIN_FEE_UEGOC);
                eprintln!("[Mempool] REJECTED {:.12} — {}", &tx.hash[..12.min(tx.hash.len())], err);
                return Err(err);
            }
            let current_base_fee = crate::chain_db::get_current_base_fee();
            if tx.fee_uegoc < current_base_fee {
                let err = format!("fee {} uEGOC below base fee {}", tx.fee_uegoc, current_base_fee);
                eprintln!("[Mempool] REJECTED {:.12} — {}", &tx.hash[..12.min(tx.hash.len())], err);
                return Err(err);
            }

            if tx.nonce > 0 {
                let confirmed_nonce = crate::ledger::last_confirmed_nonce(&tx.from);
                if tx.nonce <= confirmed_nonce {
                    let err = format!("replay nonce {} <= confirmed {}", tx.nonce, confirmed_nonce);
                    eprintln!("[Mempool] REJECTED {:.12} — {}", &tx.hash[..12.min(tx.hash.len())], err);
                    return Err(err);
                }
                if tx.nonce > confirmed_nonce + 10 {
                    let err = format!("nonce {} too far ahead of confirmed {}", tx.nonce, confirmed_nonce);
                    eprintln!("[Mempool] REJECTED {:.12} — {}", &tx.hash[..12.min(tx.hash.len())], err);
                    return Err(err);
                }
            }
        }

        let shard = shard_for_address(&tx.from) as usize;
        {
            let mut seen = self.seen_hashes[shard].lock().expect("lock poisoned");
            if !seen.insert(tx.hash.clone()) {
                return Ok(());
            }
        }

        let mut s = self.shards[shard].lock().expect("lock poisoned");

        if !is_system {
            if tx.tx_type == "unstake" && tx.to == crate::chain_db::STAKING_ADDR {
                let pending_unstake: u64 = s.iter()
                    .filter(|t| t.from == tx.from
                        && t.tx_type == "unstake"
                        && t.to == crate::chain_db::STAKING_ADDR)
                    .map(|t| t.amount)
                    .fold(0u64, |acc, v| acc.saturating_add(v));
                let requested = tx.amount.saturating_add(pending_unstake);
                let credit = if tx.memo.as_deref() == Some("unstake:early") {
                    tx.amount.saturating_sub(tx.amount / 10)
                } else {
                    tx.amount
                };
                if requested == 0 || requested > active_stake || credit < tx.fee_uegoc {
                    tracing::warn!(
                        "Mempool rejected {} - invalid unstake request: active_stake={}, requested={}, credit={}, fee={}",
                        &tx.hash[..12.min(tx.hash.len())], active_stake, requested, credit, tx.fee_uegoc
                    );
                    self.seen_hashes[shard].lock().expect("lock poisoned").remove(&tx.hash);
                    return Err("invalid unstake request".to_string());
                }
            } else {
            let pending_outflow: u64 = s.iter()
                .filter(|t| t.from == tx.from)
                .map(|t| {
                    if t.tx_type == "unstake" && t.to == crate::chain_db::STAKING_ADDR {
                        t.fee_uegoc
                    } else {
                        t.amount.saturating_add(t.fee_uegoc)
                    }
                })
                .fold(0u64, |acc, v| acc.saturating_add(v));
            let required = tx.amount.saturating_add(tx.fee_uegoc).saturating_add(pending_outflow);
            if balance < required {
                let err = format!("insufficient balance: has {} uEGOC, needs {} (amount {} + fee {} + pending_outflow {})",
                    balance, required, tx.amount, tx.fee_uegoc, pending_outflow);
                eprintln!("[Mempool] REJECTED {:.12} — {}", &tx.hash[..12.min(tx.hash.len())], err);
                self.seen_hashes[shard].lock().expect("lock poisoned").remove(&tx.hash);
                return Err(err);
            }
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
            let evicted = s.swap_remove(worst_idx);
            self.seen_hashes[shard].lock().expect("lock poisoned").remove(&evicted.hash);
            self.pending_total.fetch_sub(1, Ordering::Relaxed);
            tracing::info!("Mempool evicted lowest-fee tx {} from shard {}", &evicted.hash[..12], shard);

            let my_addr = crate::ledger::Ledger::load().address;
            if evicted.from == my_addr || evicted.to == my_addr {
                crate::commands::tx_pending::remove(&evicted.hash);
                if let Some(app) = crate::p2p::APP_HANDLE.get() {
                    if evicted.from == my_addr {
                        crate::commands::notifications::notify(
                            app,
                            "Transaction Dropped",
                            &format!("Your transaction of {:.2} EGOC was dropped (fee too low). Please try again with a higher fee.", evicted.amount as f64 / 1_000_000.0)
                        );
                    }
                    let _ = app.emit_all("ego://chain-updated", ());
                }
            }
        }

        let tx_hash_for_notify = tx.hash.clone();
        s.push(tx);
        self.pending_total.fetch_add(1, Ordering::Relaxed);
        self.submitted.fetch_add(1, Ordering::Relaxed);
        self.tx_notify.notify_one();
        drop(s);
        crate::rpc::notify_pending_tx(&tx_hash_for_notify);
        
        Ok(())
    }


    pub fn drain_shard(&self, shard_id: u32) -> Vec<LedgerTx> {
        let mut expired_hashes: Vec<String> = Vec::new();
        let mut my_expired_txs: Vec<LedgerTx> = Vec::new();
        let my_addr = crate::ledger::Ledger::load().address;

        let drained = {
            let mut s = self.shards[shard_id as usize].lock().expect("lock poisoned");
            if s.is_empty() { return vec![]; }

            // TTL eviction: remove stale txs that have been waiting too long.
            let now = chrono::Utc::now().timestamp();
            s.retain(|tx| {
                let stale = tx.timestamp > 0 && (now - tx.timestamp) >= MAX_TX_AGE_SECS;
                if stale { 
                    expired_hashes.push(tx.hash.clone()); 
                    if tx.from == my_addr || tx.to == my_addr { my_expired_txs.push(tx.clone()); }
                }
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
            let mut seen = self.seen_hashes[shard_id as usize].lock().expect("lock poisoned");
            for h in &expired_hashes { seen.remove(h); }
            for tx in &drained        { seen.remove(&tx.hash); }
        }

        for tx in my_expired_txs {
            crate::commands::tx_pending::remove(&tx.hash);
            if let Some(app) = crate::p2p::APP_HANDLE.get() {
                if tx.from == my_addr {
                    crate::commands::notifications::notify(
                        app,
                        "Transaction Failed",
                        &format!("Your transaction of {:.2} EGOC timed out and was cancelled. Please try again.", tx.amount as f64 / 1_000_000.0)
                    );
                }
                let _ = app.emit_all("ego://chain-updated", ());
            }
        }

        drained
    }

    pub fn drain_all(&self) -> Vec<LedgerTx> {
        let current_height = crate::chain_db::latest_block_info().0 + 1;
        let map = crate::sharding::load_shard_map();
        let target_chain_shard = if map.shard_count > 1 {
            Some(crate::sharding::shard_for_height(current_height, map.shard_count))
        } else {
            None
        };

        let mut out = Vec::with_capacity(MAX_BLOCK_TXS.min(BATCH_SIZE * SHARD_COUNT as usize));
        for shard_id in 0..SHARD_COUNT {
            if out.len() >= MAX_BLOCK_TXS { break; }
            let remaining = MAX_BLOCK_TXS - out.len();
            let mut batch = self.drain_shard(shard_id);
            
            if let Some(target) = target_chain_shard {
                let mut kept = Vec::new();
                let mut skipped = Vec::new();
                for tx in batch {
                    if tx.from.is_empty() || crate::sharding::shard_for_address_agreed(&tx.from) == target {
                        kept.push(tx);
                    } else {
                        skipped.push(tx);
                    }
                }
                
                if !skipped.is_empty() {
                    {
                        let mut seen = self.seen_hashes[shard_id as usize].lock().expect("lock poisoned");
                        for tx in &skipped {
                            seen.insert(tx.hash.clone());
                        }
                    }
                    let count = skipped.len() as u64;
                    let mut s = self.shards[shard_id as usize].lock().expect("lock poisoned");
                    for tx in skipped {
                        s.push(tx);
                    }
                    self.pending_total.fetch_add(count, Ordering::Relaxed);
                    self.confirmed.fetch_sub(count, Ordering::Relaxed);
                }
                batch = kept;
            }
            
            if batch.len() > remaining {
                let overflow = batch.split_off(remaining);
                {
                    let mut seen = self.seen_hashes[shard_id as usize].lock().expect("lock poisoned");
                    for tx in &overflow {
                        seen.insert(tx.hash.clone());
                    }
                }
                {
                    let count = overflow.len() as u64;
                    let mut s = self.shards[shard_id as usize].lock().expect("lock poisoned");
                    for tx in overflow {
                        s.push(tx);
                    }
                    self.pending_total.fetch_add(count, Ordering::Relaxed);
                    self.confirmed.fetch_sub(count, Ordering::Relaxed);
                }
            }
            out.extend(batch);
        }
        out
    }

    pub fn peek_all(&self) -> Vec<LedgerTx> {
        use rayon::prelude::*;
        self.shards.par_iter()
            .flat_map(|s| s.lock().expect("lock poisoned").clone())
            .collect()
    }

    pub fn remove_txs(&self, tx_hashes: &[String]) {
        if tx_hashes.is_empty() { return; }
        let hash_set: std::collections::HashSet<&String> = tx_hashes.iter().collect();
        
        for shard_idx in 0..SHARD_COUNT as usize {
            let mut s = self.shards[shard_idx].lock().expect("lock poisoned");
            let before = s.len();
            s.retain(|tx| !hash_set.contains(&tx.hash));
            let removed = before - s.len();
            if removed > 0 {
                self.pending_total.fetch_sub(removed as u64, Ordering::Relaxed);
                self.confirmed.fetch_add(removed as u64, Ordering::Relaxed);
                let mut seen = self.seen_hashes[shard_idx].lock().expect("lock poisoned");
                for h in tx_hashes {
                    seen.remove(h);
                }
            }
        }
    }

    pub fn pending_outflow_for_address(&self, addr: &str) -> u64 {
        let shard = shard_for_address(addr) as usize;
        let s = self.shards[shard].lock().expect("lock poisoned");
        s.iter()
            .filter(|tx| tx.from.trim() == addr.trim())
            .map(|tx| tx.amount.saturating_add(tx.fee_uegoc))
            .sum()
    }

    pub fn pending_txs_for_address(&self, addr: &str) -> Vec<LedgerTx> {
        let mut out = Vec::new();
        // Since `to` address could be in any shard, we scan all shards.
        // But we avoid cloning the entire mempool, only matching txs.
        for shard in &self.shards {
            let s = shard.lock().expect("lock poisoned");
            for tx in s.iter() {
                if tx.from.trim() == addr.trim() || tx.to.trim() == addr.trim() {
                    out.push(tx.clone());
                }
            }
        }
        out
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

    pub fn clear(&self) {
        let mut total: u64 = 0;
        for shard_idx in 0..SHARD_COUNT as usize {
            let mut s = self.shards[shard_idx].lock().expect("lock poisoned");
            total += s.len() as u64;
            s.clear();
            self.seen_hashes[shard_idx].lock().expect("lock poisoned").clear();
        }
        self.pending_total.fetch_sub(total, Ordering::Relaxed);
    }

    pub fn cleanup_stale(&self) {
        let mut hashes_to_remove = Vec::new();
        let my_addr = crate::ledger::Ledger::load().address;
        for shard_idx in 0..SHARD_COUNT as usize {
            let s = self.shards[shard_idx].lock().expect("lock poisoned");
            for tx in s.iter() {
                if tx.nonce > 0 && tx.nonce <= crate::ledger::last_confirmed_nonce(&tx.from) {
                    hashes_to_remove.push(tx.hash.clone());
                    if tx.from == my_addr || tx.to == my_addr {
                        crate::commands::tx_pending::remove(&tx.hash);
                    }
                }
            }
        }
        if !hashes_to_remove.is_empty() {
            self.remove_txs(&hashes_to_remove);
            if let Some(app) = crate::p2p::APP_HANDLE.get() {
                let _ = app.emit_all("ego://chain-updated", ());
            }
        }
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
        let _ = pool.push(tx.clone());
        let _ = pool.push(tx);
        assert_eq!(pool.pending_count(), 1);
    }

    #[test]
    fn system_tx_bypasses_fee_check() {
        let pool = ShardedMempool::new();
        let _ = pool.push(sys_tx("0xcb1"));
        assert_eq!(pool.pending_count(), 1);
    }

    #[test]
    fn drain_empties_pool() {
        let pool = ShardedMempool::new();
        for i in 0..4u64 {
            let _ = pool.push(sys_tx(&format!("0xd{i}")));
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
        let _ = pool.push(tx);
        assert_eq!(pool.pending_count(), 0);
    }
}

// ── Block production helpers ───────────────────────────────────────────────────

fn get_miner_address() -> Option<String> {
    let addr = crate::ledger::Ledger::load().address;
    if addr.is_empty() { None } else { Some(addr) }
}

async fn try_mine(txs: Vec<LedgerTx>, miner: &str) -> Vec<LedgerTx> {
    if !allow_pre_bft_solo() {
        return txs;
    }
    let known_count = crate::p2p::known_validator_count();
    if known_count >= min_validators_for_finality() {
        return txs;
    }
    
    // If we are significantly behind the network, do not attempt to mine.
    // Catch-up sync must take priority to avoid creating orphaned mini-forks.
    let (tip_h, _) = crate::chain_db::latest_block_info();
    let network_view = crate::p2p::current_view();
    // network_view is 0 at absolute start; only silence if the network is actually ahead.
    let last_fin = crate::p2p::LAST_BLOCK_FINALIZED_TS.load(Ordering::Relaxed);
    let stuck_secs = chrono::Utc::now().timestamp() - last_fin;

    if network_view > 0 && tip_h + 10 < network_view && (stuck_secs < 60 || last_fin == 0) {
        return txs;
    }

    let is_alone = known_count <= 1;

    if !is_alone && !crate::commands::consensus::drs_eligible() {
        tracing::debug!("[Mine] DRS < 0.5 — not eligible to mine");
        return txs;
    }

    let prev_hash = crate::chain_db::get_tip_hash();
    let (poc_ticket, _poc_sig) = match crate::poc::check_slot_winner(&prev_hash) {
        Some(t) => t,
        None    => {
            if is_alone {
                (String::new(), String::new())
            } else {
                return txs;
            }
        }
    };
    let poc_slot = crate::poc::current_slot();
    let combined_ticket = if poc_ticket.is_empty() { String::new() } else { format!("{}:{}", poc_ticket, _poc_sig) };

    let oracle_rewards = crate::p2p::fetch_pending_post_rewards().await;
    let post_proof_ids: Vec<String> = oracle_rewards.iter().map(|t| t.hash.clone()).collect();
    let mut all_txs = txs.clone();
    all_txs.extend(oracle_rewards);
    let tx_count = txs.len();
    
    let (block, stamped) = crate::chain_db::build_block_proposal(&all_txs, miner, &combined_ticket, poc_slot);
    
    {
        let mut staged = crate::p2p::staged_block();
        *staged = Some((block.clone(), stamped));
    }
    
    crate::p2p::bft_solo_commit(&block.hash, block.height);
    
    tracing::info!(
        "Solo block #{} sealed — {} user txs + {} PoST rewards + 1 coinbase",
        block.height, tx_count, post_proof_ids.len(),
    );
    if !post_proof_ids.is_empty() {
        tokio::spawn(crate::p2p::notify_post_rewards_claimed(post_proof_ids));
    }
    for tx in &txs {
        crate::commands::tx_pending::remove(&tx.hash);
    }
    vec![]
}

// ── Reactive batch loop ────────────────────────────────────────────────────────

pub async fn run_batch_loop() {
    tracing::info!(
        "Reactive batch loop started — batch_window={}ms threshold={}txs max_wait={}s empty_min={}s max_pending={} tx_ttl={}s",
        BATCH_WINDOW_MS, TX_THRESHOLD, MAX_BLOCK_INTERVAL_S, EMPTY_BLOCK_INTERVAL_S,
        MAX_MEMPOOL_SIZE, MAX_TX_AGE_SECS,
    );

    tokio::task::spawn_blocking(|| { let _ = crate::chain_db::get_db(); }).await.ok();

    let pool = get_mempool();

    let mut last_block_at    = Instant::now();
    let mut batch_started_at: Option<Instant> = None;
    let startup_time         = Instant::now();

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
                tracing::info!("TX_THRESHOLD ({}) reached — sealing immediately", TX_THRESHOLD);
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

        let known_count = crate::p2p::known_validator_count();
        let needed = min_validators_for_finality();
        
        let now_ts = chrono::Utc::now().timestamp();
        let last_fin = crate::p2p::LAST_BLOCK_FINALIZED_TS.load(Ordering::Relaxed);
        let stuck_secs = now_ts - last_fin;

        if known_count >= needed {
            // BFT mode: normally we wait for the proposer.
            // However, if the chain is stuck for > 30s and we have very few validators,
            // fall back to solo mining to keep the network alive.
            if stuck_secs < 30 || known_count > 5 {
                last_block_at    = Instant::now();
                batch_started_at = None;
                continue;
            }
        }
        if !allow_pre_bft_solo() {
            tracing::warn!(
                "BFT quorum not ready: {} known validator(s), need {}; leaving txs in mempool",
                known_count,
                needed
            );
            last_block_at    = Instant::now();
            batch_started_at = None;
            continue;
        }

        // Grace period: allow peers to discover each other via DHT before deciding we are alone
        let is_brand_new = crate::chain_db::latest_block_info().0 < 2;
        let settle_time = if is_brand_new { 60 } else { 15 };
        if known_count <= 1 && startup_time.elapsed().as_secs() < settle_time {
            tokio::time::sleep(Duration::from_secs(2)).await;
            last_block_at    = Instant::now();
            batch_started_at = None;
            continue;
        }

        tracing::warn!(
            "Pre-BFT mode: {} known validator(s) (need {} for Byzantine-fault-tolerant finality) — solo mining until quorum is reached",
            known_count, needed
        );

        let txs = pool.drain_all();
        let unprocessed = try_mine(txs, &miner).await;
        for tx in unprocessed {
            let _ = pool.push(tx);
        }

        last_block_at    = Instant::now();
        batch_started_at = None;
    }
}
