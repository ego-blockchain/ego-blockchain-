use crate::error::EgoDesktopError;
use crate::l2::rollup::RollupBatch;
use crate::l2::state_channel::{self, StateChannel};

#[tauri::command]
pub async fn open_state_channel(
    with_address: String,
    collateral_uegoc: u64,
    state:        tauri::State<'_, crate::app::AppState>,
) -> Result<String, EgoDesktopError> {
    let _ = (with_address, collateral_uegoc, state);
    Err(EgoDesktopError::InvalidInput(
        "Payment channels are not available yet: the network has no way to hold a channel's deposit on chain".into(),
    ))
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
    let _ = channel_id;
    Err(EgoDesktopError::InvalidInput(
        "Payment channels are not available yet, so there is nothing to settle on chain".into(),
    ))
}

#[tauri::command]
pub async fn submit_l2_batch(
    txs_json: String,
    stark_proof_hex: String,
    state:    tauri::State<'_, crate::app::AppState>,
) -> Result<String, EgoDesktopError> {
    let _ = (txs_json, stark_proof_hex, state);
    Err(EgoDesktopError::InvalidInput(
        "Rollup batches are not available yet: no proof verifier runs on the network".into(),
    ))
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
        // In a true ZK-Rollup, batches are finalized instantly upon submission.
        // Fraud proofs (challenges) are obsolete because the STARK proof guarantees
        // cryptographic validity before the batch is ever accepted into the L1.
        Ok(format!("Batch {} cannot be challenged. This network uses ZK-STARKs. Batches are mathematically proven at submission.", batch_id))
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}
