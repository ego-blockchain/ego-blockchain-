use crate::error::EgoDesktopError;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct PhoneAccess {
    pub needed: bool,
    pub port: u16,
}

#[tauri::command]
pub async fn get_phone_access() -> Result<PhoneAccess, EgoDesktopError> {
    let allowed = tokio::task::spawn_blocking(crate::p2p::phones_allowed).await.unwrap_or(true);
    Ok(PhoneAccess {
        needed: cfg!(target_os = "windows") && crate::gateway::enabled() && !allowed,
        port: crate::gateway::port(),
    })
}

#[tauri::command]
pub async fn allow_phone_access() -> Result<(), EgoDesktopError> {
    tokio::task::spawn_blocking(crate::p2p::allow_phones_elevated)
        .await
        .map_err(|e| EgoDesktopError::InvalidInput(e.to_string()))?
        .map_err(EgoDesktopError::InvalidInput)
}
