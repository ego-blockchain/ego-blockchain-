use crate::error::EgoDesktopError;
use crate::l2::rollup::{self, L2Tx, RollupBatch};
use crate::l2::state_channel::{self, StateChannel};

#[tauri::command]
pub async fn open_state_channel(
    with_address: String,
    collateral_uegoc: u64,
) -> Result<String, EgoDesktopError> {
    tokio::task::spawn_blocking(move || {
        let ledger = crate::ledger::Ledger::load();
        if ledger.address.is_empty() {
            return Err(EgoDesktopError::WalletError("wallet not initialized".into()));
        }
        let balance = crate::chain_db::balance_of(&ledger.address);
        if balance < collateral_uegoc {
            return Err(EgoDesktopError::WalletError(format!(
                "insufficient balance: have {} uEGOC, need {}",
                balance, collateral_uegoc
            )));
        }

        let (height, _) = crate::chain_db::latest_block_info();
        let channel = state_channel::open_channel(
            &ledger.address,
            &with_address,
            collateral_uegoc,
            0,
            height,
        );
        let channel_id = channel.channel_id.clone();

        
        crate::chain_db::apply_balance_delta(&ledger.address, -(collateral_uegoc as i64));
        crate::chain_db::save_state_channel(&channel)
            .map_err(|e| EgoDesktopError::DatabaseError(e))?;

        Ok(channel_id)
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

#[tauri::command]
pub async fn get_my_channels() -> Result<Vec<StateChannel>, EgoDesktopError> {
    tokio::task::spawn_blocking(|| {
        let ledger = crate::ledger::Ledger::load();
        Ok(crate::chain_db::get_channels_for_address(&ledger.address))
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

#[tauri::command]
pub async fn close_state_channel(channel_id: String) -> Result<String, EgoDesktopError> {
    tokio::task::spawn_blocking(move || {
        let (height, _) = crate::chain_db::latest_block_info();
        let mut channel = crate::chain_db::get_state_channel(&channel_id)
            .ok_or_else(|| EgoDesktopError::NotFound("channel not found".into()))?;

        state_channel::initiate_close(&mut channel, height);
        crate::chain_db::save_state_channel(&channel)
            .map_err(|e| EgoDesktopError::DatabaseError(e))?;

        Ok(format!(
            "Channel {} closing, dispute window: {} blocks",
            channel_id,
            state_channel::DISPUTE_WINDOW_BLOCKS
        ))
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

#[tauri::command]
pub async fn finalize_state_channel(channel_id: String) -> Result<String, EgoDesktopError> {
    tokio::task::spawn_blocking(move || {
        let (height, _) = crate::chain_db::latest_block_info();
        let mut channel = crate::chain_db::get_state_channel(&channel_id)
            .ok_or_else(|| EgoDesktopError::NotFound("channel not found".into()))?;

        if channel.status != crate::l2::state_channel::ChannelStatus::Closing {
            return Err(EgoDesktopError::InvalidInput(
                "channel is not in Closing state".into(),
            ));
        }
        let deadline = channel.dispute_deadline.unwrap_or(0);
        if height < deadline {
            return Err(EgoDesktopError::InvalidInput(format!(
                "dispute window still open: {} blocks remaining",
                deadline - height
            )));
        }

        let (payout_a, payout_b) = state_channel::finalize_close(&mut channel);
        let party_a = channel.party_a.clone();
        let party_b = channel.party_b.clone();

        crate::chain_db::apply_balance_delta(&party_a, payout_a as i64);
        crate::chain_db::apply_balance_delta(&party_b, payout_b as i64);
        crate::chain_db::save_state_channel(&channel)
            .map_err(|e| EgoDesktopError::DatabaseError(e))?;

        Ok(format!(
            "Settled: {} → {} uEGOC, {} → {} uEGOC",
            party_a, payout_a, party_b, payout_b
        ))
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

#[tauri::command]
pub async fn submit_l2_batch(txs_json: String) -> Result<String, EgoDesktopError> {
    let l2_txs: Vec<L2Tx> = serde_json::from_str(&txs_json)
        .map_err(|e| EgoDesktopError::SerializationError(format!("invalid L2 TX list: {e}")))?;

    if l2_txs.len() > rollup::MAX_L2_BATCH_TXS {
        return Err(EgoDesktopError::InvalidInput(format!(
            "batch too large: {} txs (max {})",
            l2_txs.len(),
            rollup::MAX_L2_BATCH_TXS
        )));
    }

    tokio::task::spawn_blocking(move || {
        let ledger = crate::ledger::Ledger::load();
        let (height, _) = crate::chain_db::latest_block_info();

        let pre_balances = crate::chain_db::get_l2_balances();
        let pre_root = rollup::compute_l2_state_root(&pre_balances);

        let (post_balances, post_root) = rollup::execute_l2_batch(&l2_txs, pre_balances)
            .map_err(|e| EgoDesktopError::InvalidInput(e))?;

        let bid = rollup::batch_id(&ledger.address, height, l2_txs.len());
        let now = chrono::Utc::now().timestamp();

        let batch = RollupBatch {
            batch_id: bid.clone(),
            sequencer: ledger.address.clone(),
            l1_height: height,
            l2_txs,
            pre_state_root: pre_root,
            post_state_root: post_root,
            submitted_at: now,
            status: rollup::BatchStatus::Pending,
            challenge_deadline: height + rollup::FRAUD_PROOF_WINDOW,
        };

        crate::chain_db::save_l2_batch(&batch)
            .map_err(|e| EgoDesktopError::DatabaseError(e))?;
        crate::chain_db::set_l2_balances(&post_balances)
            .map_err(|e| EgoDesktopError::DatabaseError(e))?;

        Ok(bid)
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

#[tauri::command]
pub async fn get_rollup_batches(from_l1_height: u64) -> Result<Vec<RollupBatch>, EgoDesktopError> {
    tokio::task::spawn_blocking(move || Ok(crate::chain_db::get_l2_batches_from(from_l1_height)))
        .await
        .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

#[tauri::command]
pub async fn challenge_rollup_batch(batch_id: String) -> Result<String, EgoDesktopError> {
    tokio::task::spawn_blocking(move || {
        let batch = crate::chain_db::get_l2_batch(&batch_id)
            .ok_or_else(|| EgoDesktopError::NotFound("batch not found".into()))?;

        if batch.status != rollup::BatchStatus::Pending {
            return Err(EgoDesktopError::InvalidInput("batch is not pending".into()));
        }

        let pre_balances = crate::chain_db::get_l2_balances_at(batch.l1_height);
        let is_valid = rollup::verify_batch(&batch, pre_balances);

        if is_valid {
            return Ok("batch verified as valid — challenge rejected".into());
        }

        let mut updated = batch;
        updated.status = rollup::BatchStatus::Rejected;
        crate::chain_db::save_l2_batch(&updated)
            .map_err(|e| EgoDesktopError::DatabaseError(e))?;

        Ok("fraud proof accepted — batch rejected, sequencer slashed".into())
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}
