use crate::app::AppState;
use crate::error::EgoDesktopError;
use crate::ledger::{data_dir, Ledger};
use crate::p2p;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fs;
use tauri::{AppHandle, State};

// ── Storage paths ─────────────────────────────────────────────────────────────

fn contacts_path() -> std::path::PathBuf {
    data_dir().join("contacts.json")
}

fn messages_path() -> std::path::PathBuf {
    data_dir().join("messages.json")
}

// ── Types ─────────────────────────────────────────────────────────────────────

/// A paired (or pending) contact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub address:        String,
    pub name:           String,
    pub ed25519_pubkey: String,
    pub kyber_pubkey:   String,
    /// AES-256-GCM key shared between this pair (hex).
    pub shared_key_hex: String,
    /// "pending_out" | "pending_in" | "approved"
    pub status: String,
    pub added_at: i64,
    /// TCP endpoint of the remote peer ("ip:port"). Empty for legacy contacts.
    #[serde(default)]
    pub endpoint: String,
}

/// A single chat message stored locally in plain-text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id:           String,
    pub from:         String,
    pub to:           String,
    pub content:      String,
    /// "text" | "file_bundle" | "decrypt_key"
    pub message_type: String,
    pub timestamp:    i64,
    pub outgoing:     bool,
}

// ── Storage helpers (pub(crate) so p2p.rs can call them) ─────────────────────

pub(crate) fn load_contacts() -> Vec<Contact> {
    let path = contacts_path();
    if let Ok(data) = fs::read_to_string(&path) {
        if let Ok(v) = serde_json::from_str::<Vec<Contact>>(&data) {
            return v;
        }
    }
    Vec::new()
}

pub(crate) fn save_contacts(contacts: &[Contact]) -> Result<(), String> {
    let data = serde_json::to_string_pretty(contacts).map_err(|e| e.to_string())?;
    fs::write(contacts_path(), data).map_err(|e| e.to_string())
}

fn load_messages() -> Vec<Message> {
    let path = messages_path();
    if let Ok(data) = fs::read_to_string(&path) {
        if let Ok(v) = serde_json::from_str::<Vec<Message>>(&data) {
            return v;
        }
    }
    Vec::new()
}

fn save_messages(msgs: &[Message]) -> Result<(), String> {
    let data = serde_json::to_string_pretty(msgs).map_err(|e| e.to_string())?;
    fs::write(messages_path(), data).map_err(|e| e.to_string())
}

// ── Bundle helpers ─────────────────────────────────────────────────────────────
// Format v1 (legacy): egocontact1:{addr}:{ed25519hex}:{kyberhex}:{name_b64}:{shared_key}[:{endpoint_b64}]
// Format v2 (current): egocontact1:{addr}:{ed25519_b64}:{name_b64}:{endpoint_b64}

fn parse_contact_bundle(
    bundle: &str,
) -> Option<(String, String, String, String, String, Option<String>)> {
    let s = bundle.trim().strip_prefix("egocontact1:")?;
    let parts: Vec<&str> = s.splitn(6, ':').collect();

    if parts.len() >= 5 {
        // Legacy v1: addr:ed25519hex:kyberhex:nameb64:sharedkey[:endpointb64]
        let addr        = parts[0].to_string();
        let ed25519_hex = parts[1].to_string();
        let kyber_hex   = parts[2].to_string();
        let name        = STANDARD.decode(parts[3]).ok()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_else(|| "Unknown".to_string());
        let shared_key  = parts[4].to_string();
        let endpoint    = parts.get(5)
            .and_then(|e| STANDARD.decode(e.trim()).ok())
            .and_then(|b| String::from_utf8(b).ok());
        Some((addr, ed25519_hex, kyber_hex, name, shared_key, endpoint))
    } else if parts.len() == 4 {
        // Current v2: addr:ed25519_b64:name_b64:endpoint_b64
        let addr        = parts[0].to_string();
        let ed25519_hex = hex::encode(STANDARD.decode(parts[1]).unwrap_or_default());
        let name        = STANDARD.decode(parts[2]).ok()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_else(|| "Unknown".to_string());
        let endpoint    = STANDARD.decode(parts[3].trim()).ok()
            .and_then(|b| String::from_utf8(b).ok());
        Some((addr, ed25519_hex, String::new(), name, String::new(), endpoint))
    } else {
        None
    }
}

// Format: egomsg1:{from}:{to}:{ts}:{type}:{nonce_hex}:{ct_hex}
fn parse_msg_bundle(
    bundle: &str,
) -> Option<(String, String, i64, String, String, String)> {
    let s = bundle.trim().strip_prefix("egomsg1:")?;
    let parts: Vec<&str> = s.splitn(6, ':').collect();
    if parts.len() != 6 {
        return None;
    }
    let from  = parts[0].to_string();
    let to    = parts[1].to_string();
    let ts    = parts[2].parse::<i64>().ok()?;
    let mtype = parts[3].to_string();
    let nonce = parts[4].to_string();
    let ct    = parts[5].to_string();
    Some((from, to, ts, mtype, nonce, ct))
}

// ── Core receive logic (shared by Tauri command and P2P handler) ──────────────

/// Decrypt an incoming egomsg1 bundle, deduplicate, and persist it.
/// Called both from the `receive_message` Tauri command and from the P2P server.
pub(crate) fn receive_message_inner(bundle: &str) -> Result<Message, String> {
    let (from, to, ts, mtype, nonce_hex, ct_hex) = parse_msg_bundle(bundle)
        .ok_or_else(|| "Invalid message bundle — must start with egomsg1:".to_string())?;

    // ── Replay / clock-skew protection ───────────────────────────────────────
    let now_ts               = chrono::Utc::now().timestamp();
    const MAX_AGE_SECS: i64  = 24 * 60 * 60;
    const MAX_FUTURE_SECS: i64 = 5 * 60;

    if ts > now_ts + MAX_FUTURE_SECS {
        return Err("Message timestamp is more than 5 minutes in the future".into());
    }
    if now_ts - ts > MAX_AGE_SECS {
        return Err("Message is older than 24 hours and has been rejected to prevent replay attacks".into());
    }

    let contacts = load_contacts();
    let contact  = contacts
        .iter()
        .find(|c| c.address == from)
        .ok_or_else(|| "Sender not found in contacts — add them first".to_string())?;

    let key_bytes = hex::decode(&contact.shared_key_hex)
        .map_err(|_| "Invalid shared key".to_string())?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|_| "Bad key length (must be 32 bytes)".to_string())?;

    let nonce_bytes = hex::decode(&nonce_hex)
        .map_err(|_| "Bad nonce".to_string())?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ct_bytes = hex::decode(&ct_hex)
        .map_err(|_| "Bad ciphertext".to_string())?;

    let plaintext = cipher
        .decrypt(nonce, ct_bytes.as_slice())
        .map_err(|_| "Decryption failed — wrong contact or corrupted bundle".to_string())?;

    let content = String::from_utf8(plaintext)
        .map_err(|_| "Decrypted bytes are not valid UTF-8".to_string())?;

    let msg = Message {
        id:           format!("{}-{}", ts, &nonce_hex[..8]),
        from:         from.clone(),
        to,
        content,
        message_type: mtype,
        timestamp:    ts,
        outgoing:     false,
    };

    let mut msgs = load_messages();
    if !msgs.iter().any(|m| m.id == msg.id) {
        msgs.push(msg.clone());
        save_messages(&msgs).map_err(|e| e.to_string())?;
    }

    Ok(msg)
}

// ── Commands ──────────────────────────────────────────────────────────────────

/// Generate a shareable contact card bundle (v2 compact format).
/// Format: egocontact1:{addr}:{ed25519_b64}:{name_b64}:{endpoint_b64}
#[tauri::command]
pub async fn get_my_contact_bundle(
    state: State<'_, AppState>,
    my_name: String,
) -> Result<String, EgoDesktopError> {
    let keypair = state
        .get_keypair()
        .ok_or_else(|| EgoDesktopError::WalletError("Wallet not initialized".into()))?;

    let ledger       = Ledger::load();
    let my_addr      = ledger.address.clone();
    let ed25519_b64  = STANDARD.encode(keypair.ed25519_public_key().as_bytes());
    let name_b64     = STANDARD.encode(my_name.trim().as_bytes());
    // Use public (internet-routable) IP so the card works across different networks.
    // Falls back to LAN IP if offline.
    let public_endpoint = p2p::get_public_endpoint().await;
    let endpoint_b64 = STANDARD.encode(public_endpoint.as_bytes());

    Ok(format!(
        "egocontact1:{}:{}:{}:{}",
        my_addr, ed25519_b64, name_b64, endpoint_b64
    ))
}

/// Import a contact bundle and send a real-time contact request to that peer.
#[tauri::command]
pub async fn import_contact(
    _app: AppHandle,
    state: State<'_, AppState>,
    bundle: String,
    my_name: String,
) -> Result<Contact, EgoDesktopError> {
    let (addr, ed25519, kyber, name, _bundle_key, endpoint_opt) =
        parse_contact_bundle(&bundle).ok_or_else(|| {
            EgoDesktopError::InvalidInput(
                "Invalid contact bundle — must start with egocontact1:".into(),
            )
        })?;

    let ledger  = Ledger::load();
    let my_addr = ledger.address.clone();

    if addr == my_addr {
        return Err(EgoDesktopError::InvalidInput(
            "Cannot add yourself as a contact".into(),
        ));
    }

    let endpoint = endpoint_opt.unwrap_or_default();
    if endpoint.is_empty() {
        return Err(EgoDesktopError::InvalidInput(
            "This contact bundle is from an older version and does not include a network endpoint. \
             Ask the contact to regenerate their card with the latest Ego Desktop."
                .into(),
        ));
    }

    let keypair = state
        .get_keypair()
        .ok_or_else(|| EgoDesktopError::WalletError("Wallet not initialized".into()))?;
    let my_ed25519_hex = hex::encode(keypair.ed25519_public_key().as_bytes());
    let my_kyber_hex   = hex::encode(keypair.kyber_public_key().as_bytes());
    let my_name_trimmed = my_name.trim().to_string();

    let mut contacts = load_contacts();
    if let Some(existing) = contacts.iter().find(|c| c.address == addr) {
        if existing.status == "pending_out" {
            return Err(EgoDesktopError::InvalidInput(
                "A contact request to this address is already pending.".into(),
            ));
        }
        if existing.status == "approved" {
            return Err(EgoDesktopError::InvalidInput(
                "This contact is already in your list.".into(),
            ));
        }
    }

    let mut key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut key_bytes);
    let shared_key_hex = hex::encode(key_bytes);
    let my_endpoint    = p2p::get_public_endpoint().await;

    let request = p2p::P2PMessage::ContactRequest {
        from_addr:       my_addr.clone(),
        from_name:       my_name_trimmed.clone(),
        from_ed25519:    my_ed25519_hex,
        from_kyber:      my_kyber_hex,
        from_shared_key: shared_key_hex.clone(),
        from_endpoint:   my_endpoint,
    };
    p2p::send_message(&endpoint, &request)
        .await
        .map_err(EgoDesktopError::NetworkError)?;

    let contact = Contact {
        address:        addr,
        name,
        ed25519_pubkey: ed25519,
        kyber_pubkey:   kyber,
        shared_key_hex,
        status:         "pending_out".to_string(),
        added_at:       chrono::Utc::now().timestamp(),
        endpoint,
    };
    contacts.push(contact.clone());
    save_contacts(&contacts).map_err(EgoDesktopError::FileSystemError)?;
    Ok(contact)
}

/// Approve an incoming contact request (pending_in).
#[tauri::command]
pub async fn approve_contact_request(
    state: State<'_, AppState>,
    contact_addr: String,
    my_name: String,
) -> Result<Contact, EgoDesktopError> {
    let keypair = state
        .get_keypair()
        .ok_or_else(|| EgoDesktopError::WalletError("Wallet not initialized".into()))?;

    let ledger      = Ledger::load();
    let my_addr     = ledger.address.clone();
    let ed25519_hex = hex::encode(keypair.ed25519_public_key().as_bytes());
    let kyber_hex   = hex::encode(keypair.kyber_public_key().as_bytes());

    let mut contacts = load_contacts();
    let pos = contacts
        .iter()
        .position(|c| c.address == contact_addr && c.status == "pending_in")
        .ok_or_else(|| {
            EgoDesktopError::NotFound("No pending request from this address".into())
        })?;

    let shared_key_hex = contacts[pos].shared_key_hex.clone();
    let peer_endpoint  = contacts[pos].endpoint.clone();
    contacts[pos].status = "approved".to_string();
    let contact = contacts[pos].clone();
    save_contacts(&contacts).map_err(EgoDesktopError::FileSystemError)?;

    if !peer_endpoint.is_empty() {
        let response = p2p::P2PMessage::ContactResponse {
            from_addr:    my_addr,
            from_name:    my_name.trim().to_string(),
            from_ed25519: ed25519_hex,
            from_kyber:   kyber_hex,
            approved:     true,
            shared_key:   shared_key_hex,
        };
        if let Err(e) = p2p::send_message(&peer_endpoint, &response).await {
            eprintln!("[P2P] Could not notify requester of approval: {}", e);
        }
    }

    Ok(contact)
}

/// Decline an incoming contact request (pending_in).
#[tauri::command]
pub async fn decline_contact_request(
    state: State<'_, AppState>,
    contact_addr: String,
    my_name: String,
) -> Result<(), EgoDesktopError> {
    let keypair = state
        .get_keypair()
        .ok_or_else(|| EgoDesktopError::WalletError("Wallet not initialized".into()))?;

    let ledger      = Ledger::load();
    let my_addr     = ledger.address.clone();
    let ed25519_hex = hex::encode(keypair.ed25519_public_key().as_bytes());
    let kyber_hex   = hex::encode(keypair.kyber_public_key().as_bytes());

    let mut contacts = load_contacts();
    let pos = contacts
        .iter()
        .position(|c| c.address == contact_addr && c.status == "pending_in")
        .ok_or_else(|| {
            EgoDesktopError::NotFound("No pending request from this address".into())
        })?;

    let shared_key_hex = contacts[pos].shared_key_hex.clone();
    let peer_endpoint  = contacts[pos].endpoint.clone();
    contacts.remove(pos);
    save_contacts(&contacts).map_err(EgoDesktopError::FileSystemError)?;

    if !peer_endpoint.is_empty() {
        let response = p2p::P2PMessage::ContactResponse {
            from_addr:    my_addr,
            from_name:    my_name.trim().to_string(),
            from_ed25519: ed25519_hex,
            from_kyber:   kyber_hex,
            approved:     false,
            shared_key:   shared_key_hex,
        };
        if let Err(e) = p2p::send_message(&peer_endpoint, &response).await {
            eprintln!("[P2P] Could not send decline notice: {}", e);
        }
    }

    Ok(())
}

/// Return all contacts (approved and pending).
#[tauri::command]
pub async fn get_contacts() -> Result<Vec<Contact>, EgoDesktopError> {
    Ok(load_contacts())
}

/// Encrypt `content` with the contact's shared AES key, persist the outgoing
/// message locally, then deliver the encrypted bundle directly to the contact's
/// TCP endpoint via the P2P server.
#[tauri::command]
pub async fn send_message(
    state: State<'_, AppState>,
    contact_addr: String,
    content: String,
    message_type: String,
) -> Result<(), EgoDesktopError> {
    let ledger   = Ledger::load();
    let my_addr  = ledger.address.clone();
    let contacts = load_contacts();

    let contact = contacts
        .iter()
        .find(|c| c.address == contact_addr && c.status == "approved")
        .ok_or_else(|| EgoDesktopError::NotFound("Contact not found or not approved".into()))?;

    let key_bytes = hex::decode(&contact.shared_key_hex)
        .map_err(|_| EgoDesktopError::CryptoError("Invalid shared key".into()))?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|_| EgoDesktopError::CryptoError("Bad key length (must be 32 bytes)".into()))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(nonce, content.as_bytes())
        .map_err(|e| EgoDesktopError::CryptoError(e.to_string()))?;

    let ts        = chrono::Utc::now().timestamp();
    let nonce_hex = hex::encode(nonce_bytes);
    let ct_hex    = hex::encode(&ct);

    let bundle = format!(
        "egomsg1:{}:{}:{}:{}:{}:{}",
        my_addr, contact_addr, ts, message_type, nonce_hex, ct_hex
    );

    // Persist outgoing message locally (plain-text for display).
    let mut msgs = load_messages();
    msgs.push(Message {
        id:           format!("{}-{}", ts, &nonce_hex[..8]),
        from:         my_addr,
        to:           contact_addr,
        content,
        message_type,
        timestamp:    ts,
        outgoing:     true,
    });
    save_messages(&msgs).map_err(EgoDesktopError::FileSystemError)?;

    // ── Deliver the encrypted bundle directly to the peer via P2P ────────────
    let contact_endpoint = contact.endpoint.clone();
    tokio::spawn(async move {
        if !contact_endpoint.is_empty() {
            let p2p_msg = p2p::P2PMessage::ChatMessage { bundle };
            if let Err(e) = p2p::send_message(&contact_endpoint, &p2p_msg).await {
                eprintln!("[P2P] deliver chat to {}: {}", contact_endpoint, e);
            }
        }
    });

    let _ = &state;
    Ok(())
}

/// Manually decrypt an incoming egomsg1 bundle (kept for backward compat /
/// offline fallback — normally delivery is automatic via the P2P server).
#[tauri::command]
pub async fn receive_message(
    _state: State<'_, AppState>,
    bundle: String,
) -> Result<Message, EgoDesktopError> {
    receive_message_inner(&bundle).map_err(EgoDesktopError::InvalidInput)
}

/// Get the chat history with a specific contact (ordered by time).
#[tauri::command]
pub async fn get_messages(
    contact_addr: String,
) -> Result<Vec<Message>, EgoDesktopError> {
    let ledger  = Ledger::load();
    let my_addr = ledger.address.clone();
    let mut msgs: Vec<Message> = load_messages()
        .into_iter()
        .filter(|m| {
            (m.from == contact_addr && m.to == my_addr)
                || (m.from == my_addr && m.to == contact_addr)
        })
        .collect();
    msgs.sort_by_key(|m| m.timestamp);
    Ok(msgs)
}

/// Wipe all chat messages for the current wallet (keeps contacts and keys).
#[tauri::command]
pub async fn clear_messages() -> Result<(), EgoDesktopError> {
    std::fs::write(messages_path(), "[]")
        .map_err(|e| EgoDesktopError::FileSystemError(e.to_string()))
}

/// Remove a contact (does not delete their messages).
#[tauri::command]
pub async fn delete_contact(
    _state: State<'_, AppState>,
    contact_addr: String,
) -> Result<(), EgoDesktopError> {
    let mut contacts = load_contacts();
    contacts.retain(|c| c.address != contact_addr);
    save_contacts(&contacts).map_err(EgoDesktopError::FileSystemError)?;
    Ok(())
}
