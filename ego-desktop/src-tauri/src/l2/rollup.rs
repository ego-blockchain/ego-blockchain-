use serde::{Deserialize, Serialize};

pub const FRAUD_PROOF_WINDOW: u64 = 100;
pub const L2_CHAIN_ID: u64 = 1_399_02;
pub const MAX_L2_BATCH_TXS: usize = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2Tx {
    pub hash: String,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub fee_l2: u64,
    pub nonce: u64,
    pub timestamp: i64,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollupBatch {
    pub batch_id: String,
    pub sequencer: String,
    pub l1_height: u64,
    pub l2_txs: Vec<L2Tx>,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub submitted_at: i64,
    pub status: BatchStatus,
    pub challenge_deadline: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BatchStatus {
    Pending,
    Finalized,
    Challenged,
    Rejected,
}

pub fn l2tx_hash(from: &str, to: &str, amount: u64, nonce: u64, ts: i64) -> String {
    let data = format!("l2tx:{}:{}:{}:{}:{}", from, to, amount, nonce, ts);
    format!("0x{}", blake3::hash(data.as_bytes()).to_hex())
}

pub fn batch_id(sequencer: &str, l1_height: u64, tx_count: usize) -> String {
    let data = format!(
        "l2batch:{}:{}:{}:{}",
        sequencer,
        l1_height,
        tx_count,
        chrono::Utc::now().timestamp_millis()
    );
    format!("egobatch1{}", blake3::hash(data.as_bytes()).to_hex())
}

pub fn compute_l2_state_root(balances: &std::collections::HashMap<String, u64>) -> String {
    let mut entries: Vec<_> = balances.iter().collect();
    entries.sort_by_key(|(k, _)| k.as_str());
    let leaves: Vec<String> = entries
        .iter()
        .map(|(addr, bal)| {
            let leaf = format!("{}:{}", addr, bal);
            blake3::hash(leaf.as_bytes()).to_hex().to_string()
        })
        .collect();
    if leaves.is_empty() {
        return "0".repeat(64);
    }
    let mut level = leaves;
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(level.last().unwrap().clone());
        }
        level = level
            .chunks(2)
            .map(|pair| {
                let combined = format!("{}{}", pair[0], pair[1]);
                blake3::hash(combined.as_bytes()).to_hex().to_string()
            })
            .collect();
    }
    level[0].clone()
}

pub fn execute_l2_batch(
    txs: &[L2Tx],
    mut balances: std::collections::HashMap<String, u64>,
) -> Result<(std::collections::HashMap<String, u64>, String), String> {
    for tx in txs {
        let from_bal = *balances.get(&tx.from).unwrap_or(&0);
        let total_cost = tx.amount.saturating_add(tx.fee_l2);
        if from_bal < total_cost {
            return Err(format!(
                "insufficient L2 balance for {}: has {} needs {}",
                tx.from, from_bal, total_cost
            ));
        }
        *balances.entry(tx.from.clone()).or_insert(0) -= total_cost;
        *balances.entry(tx.to.clone()).or_insert(0) += tx.amount;
    }
    let root = compute_l2_state_root(&balances);
    Ok((balances, root))
}

pub fn verify_batch(
    batch: &RollupBatch,
    pre_balances: std::collections::HashMap<String, u64>,
) -> bool {
    match execute_l2_batch(&batch.l2_txs, pre_balances) {
        Ok((_, computed_root)) => computed_root == batch.post_state_root,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn bals(pairs: &[(&str, u64)]) -> HashMap<String, u64> {
        pairs.iter().map(|(k,v)| (k.to_string(), *v)).collect()
    }
    fn tx(from: &str, to: &str, amt: u64, nonce: u64) -> L2Tx {
        L2Tx { hash: l2tx_hash(from,to,amt,nonce,0), from: from.into(), to: to.into(),
               amount: amt, fee_l2: 100, nonce, timestamp: 0, signature: String::new() }
    }

    #[test]
    fn transfer_moves_balance() {
        let pre = bals(&[("alice", 1_000_000)]);
        let (post, _) = execute_l2_batch(&[tx("alice","bob",100_000,1)], pre).unwrap();
        assert_eq!(*post.get("alice").unwrap(), 899_900);
        assert_eq!(*post.get("bob").unwrap(), 100_000);
    }

    #[test]
    fn overdraft_fails() {
        let pre = bals(&[("alice", 50)]);
        assert!(execute_l2_batch(&[tx("alice","bob",1_000,1)], pre).is_err());
    }

    #[test]
    fn state_root_is_deterministic() {
        let b = bals(&[("alice", 1000), ("bob", 2000)]);
        assert_eq!(compute_l2_state_root(&b), compute_l2_state_root(&b));
        assert_eq!(compute_l2_state_root(&b).len(), 64);
    }

    #[test]
    fn fraud_proof_catches_wrong_root() {
        let pre = bals(&[("alice", 1_000_000)]);
        let txs = vec![tx("alice","bob",500_000,1)];
        let batch = RollupBatch { batch_id: "t".into(), sequencer: "s".into(),
            l1_height: 1, l2_txs: txs, pre_state_root: compute_l2_state_root(&pre),
            post_state_root: "0".repeat(64), submitted_at: 0,
            status: BatchStatus::Pending, challenge_deadline: 101 };
        assert!(!verify_batch(&batch, pre));
    }

    #[test]
    fn valid_batch_passes_fraud_check() {
        let pre = bals(&[("alice", 1_000_000), ("bob", 0)]);
        let txs = vec![tx("alice","bob",100_000,1)];
        let (_, root) = execute_l2_batch(&txs, pre.clone()).unwrap();
        let batch = RollupBatch { batch_id: "t".into(), sequencer: "s".into(),
            l1_height: 1, l2_txs: txs, pre_state_root: compute_l2_state_root(&pre),
            post_state_root: root, submitted_at: 0,
            status: BatchStatus::Pending, challenge_deadline: 101 };
        assert!(verify_batch(&batch, pre));
    }
}
