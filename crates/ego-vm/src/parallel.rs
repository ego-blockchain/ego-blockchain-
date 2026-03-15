use crate::executor::Executor;
use crate::error::VmError;
use crate::types::CallResult;
use std::collections::HashSet;

/// A pending transaction to execute.
#[derive(Debug, Clone)]
pub struct PendingTx {
    pub tx_id:         [u8; 32],
    pub contract_addr: String,
    pub caller_addr:   String,
    pub entrypoint:    String,
    pub args:          Vec<u8>,
    pub block_height:  u64,
    pub timestamp:     i64,
    pub fuel:          u64,
}

/// Access set declared by a transaction (used for scheduling).
#[derive(Debug, Clone, Default)]
pub struct AccessSet {
    pub reads:  HashSet<String>,  // "contract_addr:storage_prefix:key"
    pub writes: HashSet<String>,  // same format
}

impl AccessSet {
    pub fn new() -> Self { Self::default() }

    pub fn add_read(&mut self, contract: &str, prefix: &str, key: &str) {
        self.reads.insert(format!("{}:{}:{}", contract, prefix, key));
    }

    pub fn add_write(&mut self, contract: &str, prefix: &str, key: &str) {
        self.writes.insert(format!("{}:{}:{}", contract, prefix, key));
    }

    /// Returns true if this access set conflicts with another.
    /// Conflict = any write-write or read-write overlap.
    pub fn conflicts_with(&self, other: &AccessSet) -> bool {
        // write-write
        if self.writes.intersection(&other.writes).next().is_some() { return true; }
        // read-write (self reads, other writes)
        if self.reads.intersection(&other.writes).next().is_some() { return true; }
        // write-read (self writes, other reads)
        if self.writes.intersection(&other.reads).next().is_some() { return true; }
        false
    }
}

/// Schedule a batch of transactions into non-conflicting groups.
/// Each group can be executed in parallel; groups execute sequentially.
/// Uses a greedy coloring algorithm: O(n^2) but fine for batch sizes <= 512.
pub fn schedule_batch(txs: &[PendingTx], access_sets: &[AccessSet]) -> Vec<Vec<usize>> {
    // access_sets[i] is the access set for txs[i]
    let n = txs.len();
    let mut groups: Vec<Vec<usize>> = Vec::new();
    let mut assigned = vec![false; n];

    while assigned.iter().any(|&a| !a) {
        let mut group = Vec::new();
        let mut group_access = AccessSet::new();

        for i in 0..n {
            if assigned[i] { continue; }
            if !group_access.conflicts_with(&access_sets[i]) {
                group.push(i);
                // merge access sets
                group_access.reads.extend(access_sets[i].reads.iter().cloned());
                group_access.writes.extend(access_sets[i].writes.iter().cloned());
                assigned[i] = true;
            }
        }
        if !group.is_empty() {
            groups.push(group);
        }
    }
    groups
}

/// Result of a batch execution.
#[derive(Debug)]
pub struct BatchResult {
    /// One entry per input tx, in the same order.
    pub results: Vec<Result<CallResult, VmError>>,
    /// Total RU used across all txs.
    pub total_ru: u64,
    /// Number of parallel groups executed.
    pub parallel_groups: usize,
    /// Average group size.
    pub avg_group_size: f64,
}

impl Executor {
    /// Execute a batch of transactions with automatic parallelism.
    /// Transactions that touch different storage slots execute in parallel.
    /// Conflicting transactions execute sequentially.
    pub fn execute_batch(
        &self,
        txs: &[PendingTx],
        access_sets: &[AccessSet],
    ) -> BatchResult {
        use rayon::prelude::*;

        let groups = schedule_batch(txs, access_sets);
        let n = txs.len();
        let mut results: Vec<Option<Result<CallResult, VmError>>> = (0..n).map(|_| None).collect();
        let parallel_groups = groups.len();
        let avg_group_size = if groups.is_empty() { 0.0 } else { n as f64 / groups.len() as f64 };

        for group in &groups {
            // Execute group in parallel
            let group_results: Vec<(usize, Result<CallResult, VmError>)> = group
                .par_iter()
                .map(|&idx| {
                    let tx = &txs[idx];
                    let result = self.call(
                        &tx.contract_addr,
                        &tx.caller_addr,
                        &tx.entrypoint,
                        &tx.args,
                        tx.block_height,
                        tx.timestamp,
                        tx.fuel,
                    );
                    (idx, result)
                })
                .collect();

            for (idx, res) in group_results {
                results[idx] = Some(res);
            }
        }

        let total_ru = results.iter().filter_map(|r| {
            r.as_ref().and_then(|r| r.as_ref().ok().map(|cr| cr.ru_used))
        }).sum();

        BatchResult {
            results: results.into_iter().map(|r| r.unwrap_or(Err(VmError::ExecutionError("not executed".into())))).collect(),
            total_ru,
            parallel_groups,
            avg_group_size,
        }
    }
}
