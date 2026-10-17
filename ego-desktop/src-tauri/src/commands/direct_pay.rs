use crate::ledger::{Ledger, LedgerTx};

pub fn pay_memo(kind: &str, id: &str, period: u64) -> String {
    format!("{kind}:{id}:{period}")
}

fn memo_body(memo: &str) -> &str {
    memo.strip_prefix("credits_pay:")
        .and_then(|m| m.split_once(':').map(|(_, rest)| rest))
        .unwrap_or(memo)
}

pub fn paid_periods(payer: &str, payee: &str, kind: &str, id: &str) -> u64 {
    let prefix = format!("{kind}:{id}:");
    let mut seen: std::collections::BTreeSet<u64> = Default::default();
    let confirmed = crate::chain_db::get_tx_history_for_addr(payee);
    let pending = crate::mempool::get_mempool().peek_all();
    for tx in confirmed.iter().chain(pending.iter()) {
        if tx.from != payer || tx.to != payee {
            continue;
        }
        let Some(memo) = tx.memo.as_deref() else { continue };
        if let Some(n) = memo_body(memo).strip_prefix(&prefix).and_then(|n| n.parse::<u64>().ok()) {
            seen.insert(n);
        }
    }
    seen.len() as u64
}

pub async fn pay(to: &str, amount: u64, egusd: bool, memo: String) -> Result<String, String> {
    if amount == 0 {
        return Err("Nothing to pay".into());
    }
    let kp = crate::app::global_app_state()
        .get_keypair()
        .ok_or("The wallet is locked, so the payment can't be signed")?;
    let _guard = crate::ledger::TX_MUTEX.lock().await;
    let mut ledger = Ledger::load();
    let from = ledger.address.clone();
    if from.is_empty() {
        return Err("No wallet yet".into());
    }
    if from == to {
        return Err("A payment to yourself is not needed".into());
    }
    let fee = crate::tokenomics::fee_for_tx_with_staking("transfer", ledger.staked_amount > 0)
        .max(crate::chain_db::get_current_base_fee());
    let pending_out: u64 = crate::mempool::get_mempool()
        .peek_all()
        .into_iter()
        .filter(|t| t.from == from)
        .map(|t| t.amount.saturating_add(t.fee_uegoc))
        .sum();
    let spendable = crate::chain_db::balance_of(&from).saturating_sub(pending_out);
    if egusd {
        let credits = crate::chain_db::credits_balance(&from);
        if credits < amount {
            return Err(format!(
                "Not enough EGUSD: need {:.2}, have {:.2}",
                amount as f64 / 100.0,
                credits as f64 / 100.0
            ));
        }
        if spendable < fee {
            return Err("Not enough EGOC for the network fee".into());
        }
    } else if spendable < amount.saturating_add(fee) {
        return Err(format!(
            "Not enough EGOC: need {:.6} (with the fee), have {:.6}",
            amount.saturating_add(fee) as f64 / 1_000_000.0,
            spendable as f64 / 1_000_000.0
        ));
    }
    let tx = LedgerTx {
        to: to.to_string(),
        amount: if egusd { 0 } else { amount },
        memo: Some(if egusd { format!("credits_pay:{amount}:{memo}") } else { memo }),
        tx_type: if egusd { "credits_pay".into() } else { String::new() },
        ..LedgerTx::default()
    };
    sign_and_send(tx, &kp, &mut ledger, fee)
}

fn sign_and_send(mut tx: LedgerTx, kp: &ego_core::KeyPair, ledger: &mut Ledger, fee: u64) -> Result<String, String> {
    let nonce = crate::ledger::next_nonce_for(&ledger.address, ledger.nonce);
    tx.from = ledger.address.clone();
    tx.timestamp = chrono::Utc::now().timestamp();
    tx.status = "Pending".into();
    tx.nonce = nonce;
    tx.fee_uegoc = fee;
    tx.chain_id = 1;
    crate::ledger::seal_tx(&mut tx, kp, true);
    crate::mempool::get_mempool().push(tx.clone())?;
    crate::commands::tx_pending::add(&tx);
    ledger.nonce = nonce;
    let _ = ledger.save();
    let gossip = tx.clone();
    tauri::async_runtime::spawn(async move { crate::p2p::broadcast_pending_tx(gossip).await; });
    Ok(tx.hash)
}

pub async fn submit_own(tx: LedgerTx) -> Result<String, String> {
    let kp = crate::app::global_app_state()
        .get_keypair()
        .ok_or("The wallet is locked, so the transaction can't be signed")?;
    let _guard = crate::ledger::TX_MUTEX.lock().await;
    let mut ledger = Ledger::load();
    if ledger.address.is_empty() {
        return Err("No wallet yet".into());
    }
    let fee = crate::tokenomics::fee_for_tx_with_staking("transfer", ledger.staked_amount > 0)
        .max(crate::chain_db::get_current_base_fee());
    if crate::chain_db::balance_of(&ledger.address) < fee {
        return Err("Not enough EGOC for the network fee".into());
    }
    sign_and_send(tx, &kp, &mut ledger, fee)
}

pub fn periods_due(start: i64, now: i64, period_secs: i64, total: u64) -> u64 {
    if period_secs <= 0 {
        return total;
    }
    ((((now - start).max(0)) / period_secs) as u64 + 1).min(total.max(1))
}

pub fn period_amount(total_cost: u64, rate: u64, period: u64, total_periods: u64) -> u64 {
    if period >= total_periods.max(1) {
        total_cost.saturating_sub(rate.saturating_mul(total_periods.max(1) - 1))
    } else {
        rate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn periods_come_due_one_at_a_time_and_stop_at_the_end() {
        assert_eq!(periods_due(1_000, 1_000, 3_600, 5), 1);
        assert_eq!(periods_due(1_000, 4_599, 3_600, 5), 1);
        assert_eq!(periods_due(1_000, 4_600, 3_600, 5), 2);
        assert_eq!(periods_due(1_000, 1_000_000, 3_600, 5), 5);
        assert_eq!(periods_due(1_000, 500, 3_600, 5), 1);
    }

    #[test]
    fn the_last_period_settles_the_exact_total() {
        assert_eq!(period_amount(1_000, 333, 1, 3), 333);
        assert_eq!(period_amount(1_000, 333, 2, 3), 333);
        assert_eq!(period_amount(1_000, 333, 3, 3), 334);
        assert_eq!(period_amount(500, 500, 1, 1), 500);
    }

    #[test]
    fn credits_memos_are_read_through() {
        assert_eq!(memo_body("credits_pay:120:reservation_pay:abc:2"), "reservation_pay:abc:2");
        assert_eq!(memo_body("reservation_pay:abc:1"), "reservation_pay:abc:1");
    }
}
