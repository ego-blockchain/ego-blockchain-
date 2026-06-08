use crate::error::EgoDesktopError;
use crate::ledger::{Ledger, LedgerTx, StoredFile};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

pub fn notify(app: &AppHandle, title: &str, body: &str) {
    let mut n = tauri::api::notification::Notification::new(&app.config().tauri.bundle.identifier)
        .title(title)
        .body(body);
    // Windows: icon comes from the AUMID registry entry set at startup.
    // macOS: icon comes from the app bundle automatically — passing a path here
    //        causes show() to fail silently on macOS.
    // Linux only: set the icon path explicitly.
    #[cfg(target_os = "linux")]
    if let Some(p) = app
        .path_resolver()
        .resource_dir()
        .map(|d| d.join("icons").join("icon.png"))
        .filter(|p| p.exists())
    {
        n = n.icon(p.to_string_lossy().as_ref());
    }
    if let Err(e) = n.show() {
        eprintln!("[notify] {e}");
    }
}

// Removed PowerShell balloon-tip fallback — it doesn't work on Windows 10/11
// (ShowBalloonTip is deprecated and silently ignored).
// Tauri's WinRT notification + AUMID registry registration (main.rs) is the correct path.


#[derive(Debug, Serialize, Deserialize)]
pub struct ShareBundle {
    pub cid: String,
    pub key_nonce_hex: String,
    pub display_name: String,
    pub from_address: String,
}

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
        original_size:   0,
        encrypted_size:  0,
        duration_months: 1,
        stored_at:       now,
        expiry:          now + 30 * 86_400,
        status:          "Received".into(),
        key_nonce_hex:   bundle.key_nonce_hex.clone(),
        local_path:      format!("sender:{}", bundle.from_address),
        owner:           ledger.address.clone(),
        from_egosafe:    true,
        ..Default::default()
    };

    if !ledger.stored_files.iter().any(|f| f.cid == bundle.cid) {
        ledger.stored_files.insert(0, stored.clone());
        ledger
            .save()
            .map_err(|e| EgoDesktopError::WalletError(format!("Save: {e}")))?;
    }

    // Record a retrieve_file tx on-chain so the import is verifiable.
    {
        let now = chrono::Utc::now().timestamp();
        let cid = bundle.cid.clone();
        let recipient_addr = ledger.address.clone();
        let sender_addr = if bundle.from_address.is_empty() {
            "unknown".to_string()
        } else {
            bundle.from_address.clone()
        };
        let nonce = ledger.nonce + 1;
        let sign_input = format!("retrieve_file:{}:{}:{}", recipient_addr, cid, nonce);
        let signature_hex = crate::ledger::load_seed()
            .ok()
            .flatten()
            .and_then(|s| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&s[..32]);
                ego_core::KeyPair::from_bytes(&arr).ok()
            })
            .map(|kp| hex::encode(kp.sign_ed25519(sign_input.as_bytes()).as_bytes()))
            .unwrap_or_default();
        let tx_hash = format!("0x{}", ego_core::hash_data(sign_input.as_bytes()).to_hex());

        crate::mempool::get_mempool().push(LedgerTx {
            hash:            tx_hash.clone(),
            from:            recipient_addr.clone(),
            to:              sender_addr.clone(),
            amount:          0,
            memo:            Some(format!("retrieve_file: {}", bundle.display_name)),
            timestamp:       now,
            signature:       signature_hex,
            status:          "Pending".into(),
            block_height:    None,
            nonce,
            tx_type:         "retrieve_file".into(),
            cid:             cid.clone(),
            commitment_hash: String::new(),
            ..LedgerTx::default()
        });
        ledger.nonce = nonce;

        eprintln!("[Storage] retrieve_file tx {} | cid={} | from={}",
            &tx_hash[..18], &cid[..cid.len().min(16)], &sender_addr[..sender_addr.len().min(16)]);

        // Persist the incremented nonce.
        let _ = ledger.save();
    }

    let from_short = if bundle.from_address.len() > 12 {
        format!("{}…", &bundle.from_address[..12])
    } else {
        bundle.from_address.clone()
    };
    notify(&app, "File Received!", &format!("\"{}\" shared by {}", bundle.display_name, from_short));

    let _ = app.emit_all("ego://file-receiving", serde_json::json!({ "cid": bundle.cid }));

    Ok(stored)
}

pub async fn try_auto_import(app: Option<&AppHandle<tauri::Wry>>, content: &str, from_addr: &str) {
    // egoshare1:{cid}:{key_nonce_hex}:{name_b64}:{from}  — 5 parts
    // egoshare2:{cid}:{kem_ct}:{enc_key}:{name_b64}:{from}  — 6 parts
    let (prefix, cid, key_nonce_hex, name_field) = if content.starts_with("egoshare1:") {
        let parts: Vec<&str> = content.splitn(5, ':').collect();
        if parts.len() < 5 { return; }
        ("egoshare1", parts[1], parts[2].to_string(), parts[3])
    } else if content.starts_with("egoshare2:") {
        let parts: Vec<&str> = content.splitn(6, ':').collect();
        if parts.len() < 6 { return; }
        // key is KEM-encrypted; store empty for now — EgoSafe page decrypts on demand
        ("egoshare2", parts[1], String::new(), parts[4])
    } else {
        return;
    };

    let display_name = STANDARD.decode(name_field).ok()
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_else(|| cid[..cid.len().min(12)].to_string());

    // Notify the frontend that a file bundle arrived — user must click "Save to EgoSafe"
    // to actually import it. Do NOT auto-save here.
    if let Some(h) = app {
        let _ = h.emit_all("ego://file-received", serde_json::json!({
            "cid":           cid,
            "name":          display_name.clone(),
            "key_nonce_hex": key_nonce_hex,
            "from_address":  from_addr,
        }));

        let from_short = if from_addr.len() > 12 {
            format!("{}…", &from_addr[..12])
        } else {
            from_addr.to_string()
        };

        let security = if prefix == "egoshare2" { " (encrypted for you)" } else { "" };
        notify(h, "File Received!", &format!("\"{}\" from {}{}", display_name, from_short, security));
    }
}
