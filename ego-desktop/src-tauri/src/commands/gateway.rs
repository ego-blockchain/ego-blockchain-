use crate::error::EgoDesktopError;
use crate::gateway::{self, GatewayStatus};
use crate::ledger::Ledger;

#[tauri::command]
pub async fn gateway_status() -> Result<GatewayStatus, EgoDesktopError> {
    tokio::task::spawn_blocking(gateway::status)
        .await
        .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))
}

#[tauri::command]
pub async fn set_gateway_enabled(enabled: bool) -> Result<GatewayStatus, EgoDesktopError> {
    tokio::task::spawn_blocking(move || {
        let mut ledger = Ledger::load();
        ledger.gateway_opt_out = !enabled;
        ledger.save().map_err(EgoDesktopError::FileSystemError)?;
        Ok::<_, EgoDesktopError>(gateway::status())
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}
