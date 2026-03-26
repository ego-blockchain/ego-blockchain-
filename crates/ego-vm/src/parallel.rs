use crate::executor::Executor;
use crate::error::VmError;
use crate::types::CallResult;
use std::collections::HashSet;

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

#[derive(Debug, Clone, Default)]
pub struct AccessSet {
    pub reads:  HashSet<String>,
    pub writes: HashSet<String>,
}

impl AccessSet {
    pub fn new() -> Self { Self::default() }

    pub fn add_read(&mut self, contract: &str, prefix: &str, key: &str) {
        self.reads.insert(format!("{}:{}:{}", contract, prefix, key));
    }

    pub fn add_write(&mut self, contract: &str, prefix: &str, key: &str) {
        self.writes.insert(format!("{}:{}:{}", contract, prefix, key));
    }

    pub fn conflicts_with(&self, other: &AccessSet) -> bool {

        if self.writes.intersection(&other.writes).next().is_some() { return true; }

        if self.reads.intersection(&other.writes).next().is_some() { return true; }

        if self.writes.intersection(&other.reads).next().is_some() { return true; }
        false
    }
}

pub fn schedule_batch(txs: &[PendingTx], access_sets: &[AccessSet]) -> Vec<Vec<usize>> {

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

#[derive(Debug)]
pub struct BatchResult {

    pub results: Vec<Result<CallResult, VmError>>,

    pub total_ru: u64,

    pub parallel_groups: usize,

    pub avg_group_size: f64,
}

impl Executor {

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
