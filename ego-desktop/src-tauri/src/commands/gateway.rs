use crate::error::EgoDesktopError;
use crate::gateway::{self, GatewayStatus};

#[tauri::command]
pub async fn gateway_status() -> Result<GatewayStatus, EgoDesktopError> {
    tokio::task::spawn_blocking(gateway::status)
        .await
        .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))
}

