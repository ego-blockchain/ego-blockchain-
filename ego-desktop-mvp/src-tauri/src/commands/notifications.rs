use crate::error::EgoDesktopError;
use crate::ledger::{Ledger, StoredFile};
use serde::{Deserialize, Serialize};
use tauri::AppHandle;

/// A bundle produced by "Share File" that can be sent to another user.
#[derive(Debug, Serialize, Deserialize)]
pub struct ShareBundle {
    pub cid: String,
    pub key_nonce_hex: String,
    pub display_name: String,
    pub from_address: String,
}

/// Import a file shared by another user.
/// Creates a ledger entry (status "Received") and triggers a desktop notification.
#[tauri::command]
pub async fn import_shared_file(
    app: AppHandle,
    bundle: ShareBundle,
) -> Result<StoredFile, EgoDesktopError> {
    let now = chrono::Utc::now().timestamp();

    let mut ledger = Ledger::load();

    let stored = StoredFile {
        cid:             bundle.cid.clone(),
        name:            bundle.display_name.clone(),
        original_size:   0,   // unknown until fetched from network
        encrypted_size:  0,
        duration_months: 1,
        stored_at:       now,
        expiry:          now + 30 * 86_400,
        status:          "Received".into(),
        key_nonce_hex:   bundle.key_nonce_hex.clone(),
        local_path:      String::new(), // no local .enc yet
        owner:           ledger.address.clone(), // belongs to this wallet
    };
    // Avoid duplicates
    if !ledger.stored_files.iter().any(|f| f.cid == bundle.cid) {
        ledger.stored_files.insert(0, stored.clone());
        ledger
            .save()
            .map_err(|e| EgoDesktopError::WalletError(format!("Save: {e}")))?;
    }

    // Trigger local desktop notification
    let from_short = if bundle.from_address.len() > 12 {
        format!("{}…", &bundle.from_address[..12])
    } else {
        bundle.from_address.clone()
    };
    let _ = tauri::api::notification::Notification::new(
        &app.config().tauri.bundle.identifier,
    )
    .title("File Received!")
    .body(&format!(
        "\"{}\" shared by {}",
        bundle.display_name, from_short
    ))
    .show();

    Ok(stored)
}
