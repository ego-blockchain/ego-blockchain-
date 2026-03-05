use crate::error::EgoDesktopError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct StakingInfo {
    pub current_stake: u64,
    pub lock_period_days: u32,
    pub estimated_apr: f64,
    pub pending_rewards: u64,
    pub unlock_date: Option<i64>,
    pub is_locked: bool,
}

#[tauri::command]
pub async fn get_staking_info() -> Result<StakingInfo, EgoDesktopError> {
    Ok(StakingInfo {
        current_stake: 10000,
        lock_period_days: 30,
        estimated_apr: 12.5,
        pending_rewards: 250,
        unlock_date: Some(chrono::Utc::now().timestamp() + (30 * 24 * 3600)),
        is_locked: true,
    })
}