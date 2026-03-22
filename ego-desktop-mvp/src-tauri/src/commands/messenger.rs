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
use tauri::{AppHandle, Manager, State};

// ── Storage paths ─────────────────────────────────────────────────────────────

fn contacts_path() -> std::path::PathBuf { data_dir().join("contacts.json") }
fn messages_path() -> std::path::PathBuf { data_dir().join("messages.json") }

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub address:        String,
    pub name:           String,
    pub ed25519_pubkey: String,
    pub kyber_pubkey:   String,
    pub shared_key_hex: String,
    pub status:         String,
    pub added_at:       i64,
    pub endpoint:       String,
    #[serde(default)]
    pub all_endpoints:  Vec<String>,
    // ── Phase 4: KDF ratchet (forward secrecy) ────────────────────────────────
    /// Hex-encoded 32-byte chain key for outgoing messages; empty = uninitialized.
    #[serde(default)]
    pub ratchet_send_chain: String,
    /// Hex-encoded 32-byte chain key for incoming messages; empty = uninitialized.
    #[serde(default)]
    pub ratchet_recv_chain: String,
    /// Monotonically-increasing send counter (advances each message sent).
    #[serde(default)]
    pub ratchet_send_count: u64,
    /// Highest received sequence number seen so far from this contact.
    #[serde(default)]
    pub ratchet_recv_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id:           String,
    pub from:         String,
    pub to:           String,
    pub content:      String,
    pub message_type: String,
    pub timestamp:    i64,
    pub outgoing:     bool,
}

// ── Storage helpers ───────────────────────────────────────────────────────────

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

// ── Bundle parsers ────────────────────────────────────────────────────────────

fn parse_contact_bundle(
    bundle: &str,
) -> Option<(String, String, String, String, String, Option<String>)> {
    let s = bundle.trim().strip_prefix("egocontact1:")?;
    let parts: Vec<&str> = s.splitn(6, ':').collect();

    if parts.len() >= 5 {
        // Legacy v1: addr:ed25519hex:kyberhex:nameb64:sharedkey[:endpointb64]
        let addr       = parts[0].to_string();
        let ed25519    = parts[1].to_string();
        let kyber      = parts[2].to_string();
        let name       = STANDARD.decode(parts[3]).ok()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_else(|| "Unknown".to_string());
        let shared_key = parts[4].to_string();
        let endpoint   = parts.get(5)
            .and_then(|e| STANDARD.decode(e.trim()).ok())
            .and_then(|b| String::from_utf8(b).ok());
        Some((addr, ed25519, kyber, name, shared_key, endpoint))
    } else if parts.len() == 4 {
        // Current v2: addr:ed25519_b64:name_b64:endpoint_b64
        let addr     = parts[0].to_string();
        let ed25519  = hex::encode(STANDARD.decode(parts[1]).unwrap_or_default());
        let name     = STANDARD.decode(parts[2]).ok()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_else(|| "Unknown".to_string());
        let endpoint = STANDARD.decode(parts[3].trim()).ok()
            .and_then(|b| String::from_utf8(b).ok());
        Some((addr, ed25519, String::new(), name, String::new(), endpoint))
    } else {
        None
    }
}

fn parse_msg_bundle(
    bundle: &str,
) -> Option<(String, String, i64, String, String, String)> {
    let s = bundle.trim().strip_prefix("egomsg1:")?;
    let parts: Vec<&str> = s.splitn(6, ':').collect();
    if parts.len() != 6 { return None; }
    Some((
        parts[0].to_string(),
        parts[1].to_string(),
        parts[2].parse::<i64>().ok()?,
        parts[3].to_string(),
        parts[4].to_string(),
        parts[5].to_string(),
    ))
}
// ── Phase 4: KDF ratchet helpers ──────────────────────────────────────────────
//
// Symmetric KDF chain with per-message key derivation:
//
//   For a contact pair (addr_A, addr_B) sharing `shared_key`:
//     - Lexicographically lower address uses chain-1 for send, chain-2 for recv.
//     - Lexicographically higher address uses chain-2 for send, chain-1 for recv.
//   This ensures A's send chain == B's recv chain (both derive from same root).
//
//   Each message: msg_key = BLAKE3("ego msg key v1", chain); new_chain = BLAKE3("ego chain next v1", chain)
//   Key derivation erases old chain keys → forward secrecy for in-order delivery.

fn init_ratchet_chain(shared_key: &[u8], for_send: bool, my_addr: &str, peer_addr: &str) -> [u8; 32] {
    let lower_is_mine = my_addr < peer_addr;
    // If lower: send=chain-1, recv=chain-2.  If higher: send=chain-2, recv=chain-1.
    let use_chain_1 = lower_is_mine == for_send;
    if use_chain_1 {
        blake3::derive_key("ego ratchet chain-1 v1", shared_key)
    } else {
        blake3::derive_key("ego ratchet chain-2 v1", shared_key)
    }
}

fn ratchet_advance(chain: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let msg_key   = blake3::derive_key("ego msg key v1", chain);
    let new_chain = blake3::derive_key("ego chain next v1", chain);
    (msg_key, new_chain)
}

/// Derive the encryption key for the next outgoing message.
/// Initializes the ratchet chain on first call, then advances it.
/// Returns `(enc_key_bytes, current_send_seq)`.
fn derive_send_key_and_seq(contact: &mut Contact, my_addr: &str) -> Result<([u8; 32], u64), String> {
    let shared_bytes = hex::decode(&contact.shared_key_hex)
        .map_err(|_| "Invalid shared key".to_string())?;

    if contact.ratchet_send_chain.is_empty() {
        let chain = init_ratchet_chain(&shared_bytes, true, my_addr, &contact.address);
        contact.ratchet_send_chain = hex::encode(chain);
    }

    let chain_bytes: [u8; 32] = hex::decode(&contact.ratchet_send_chain)
        .map_err(|_| "Bad send chain".to_string())?
        .try_into()
        .map_err(|_| "Bad send chain length".to_string())?;

    let (msg_key, next_chain) = ratchet_advance(&chain_bytes);
    contact.ratchet_send_chain  = hex::encode(next_chain);
    contact.ratchet_send_count += 1;
    let seq = contact.ratchet_send_count;
    Ok((msg_key, seq))
}

/// Try to decrypt `ct` using the ratchet recv chain with a skip window of up to
/// SKIP_WINDOW steps (handles mild out-of-order delivery).
/// On success, advances the recv chain and updates `contact`.
/// Returns `Some(plaintext)` on success, `None` if all ratchet attempts fail.
fn try_decrypt_ratchet(
    contact:   &mut Contact,
    my_addr:   &str,
    nonce:     &[u8],
    ct:        &[u8],
) -> Option<Vec<u8>> {
    use aes_gcm::aead::Aead;

    let shared_bytes = hex::decode(&contact.shared_key_hex).ok()?;

    if contact.ratchet_recv_chain.is_empty() {
        let chain = init_ratchet_chain(&shared_bytes, false, my_addr, &contact.address);
        contact.ratchet_recv_chain = hex::encode(chain);
    }

    let chain_bytes: [u8; 32] = hex::decode(&contact.ratchet_recv_chain)
        .ok()?.try_into().ok()?;

    const SKIP_WINDOW: u32 = 20;
    let mut chain = chain_bytes;
    for _ in 0..=SKIP_WINDOW {
        let (msg_key, next_chain) = ratchet_advance(&chain);
        let cipher = Aes256Gcm::new_from_slice(&msg_key).ok()?;
        let nonce_obj = Nonce::from_slice(nonce);
        if let Ok(pt) = cipher.decrypt(nonce_obj, ct) {
            contact.ratchet_recv_chain  = hex::encode(next_chain);
            contact.ratchet_recv_count += 1;
            return Some(pt);
        }
        chain = next_chain;
    }
    None
}

// ── resolve_endpoint ──────────────────────────────────────────────────────────
// Falls back to local peer cache (populated by DHT discovery and PeerAnnounce).
// HTTP relay lookup removed — relay decommissioned.
async fn resolve_endpoint(contact_addr: &str, stored_endpoint: &str) -> String {
    // Check local peer cache (populated by PeerAnnounce + DHT)
    let cache = crate::p2p::load_peer_cache();
    if let Some(entry) = cache.iter().find(|p| p.address == contact_addr) {
        if !entry.endpoint.is_empty() {
            let cache_is_better = entry.endpoint.contains("/p2p-circuit")
                || !stored_endpoint.contains("/p2p-circuit");
            if cache_is_better && entry.endpoint != stored_endpoint {
                eprintln!(
                    "[Messenger] Cache: fresher endpoint for {}: {}",
                    contact_addr, entry.endpoint
                );
                let mut contacts = load_contacts();
                if let Some(c) = contacts.iter_mut().find(|c| c.address == contact_addr) {
                    c.endpoint = entry.endpoint.clone();
                    let _ = save_contacts(&contacts);
                }
                return entry.endpoint.clone();
            }
        }
    }

    stored_endpoint.to_string()
}

// ── Core receive logic ────────────────────────────────────────────────────────

/// Returns `(message, is_new)` — `is_new` is false if this message was already stored (duplicate).
/// `seq` is the sender's sequence number (0 = unknown / old client).
pub(crate) fn receive_message_inner(bundle: &str, seq: u64) -> Result<(Message, bool), String> {
    let (from, to, ts, mtype, nonce_hex, ct_hex) = parse_msg_bundle(bundle)
        .ok_or_else(|| "Invalid message bundle — must start with egomsg1:".to_string())?;

    let now_ts               = chrono::Utc::now().timestamp();
    const MAX_AGE_SECS: i64  = 24 * 60 * 60;
    const MAX_FUTURE_SECS: i64 = 5 * 60;

    if ts > now_ts + MAX_FUTURE_SECS {
        return Err("Message timestamp is more than 5 minutes in the future".into());
    }
    if now_ts - ts > MAX_AGE_SECS {
        return Err("Message is older than 24 hours and has been rejected".into());
    }

    let nonce_bytes = hex::decode(&nonce_hex).map_err(|_| "Bad nonce".to_string())?;
    let ct_bytes    = hex::decode(&ct_hex).map_err(|_| "Bad ciphertext".to_string())?;

    // Load my own address for ratchet key direction
    let my_addr = crate::ledger::Ledger::load().address;

    // ── Phase 4: try ratchet decrypt first, then fall back to static key ──────
    let mut contacts = load_contacts();
    let contact_pos = contacts.iter().position(|c| c.address == from)
        .ok_or_else(|| "Sender not found in contacts".to_string())?;

    let (content, ratchet_ok) = {
        let contact = &mut contacts[contact_pos];

        // Attempt ratchet decryption (with skip window for mild reordering)
        if let Some(pt) = try_decrypt_ratchet(contact, &my_addr, &nonce_bytes, &ct_bytes) {
            // Phase 5: track received seq for gap detection
            if seq > 0 && seq > contact.ratchet_recv_count {
                if seq > contact.ratchet_recv_count + 1 {
                    eprintln!(
                        "[Messenger] Seq gap from {}: expected ≤{}, got {}",
                        &from[..from.len().min(12)],
                        contact.ratchet_recv_count + 1,
                        seq
                    );
                }
                contact.ratchet_recv_count = seq;
            }
            let text = String::from_utf8(pt)
                .map_err(|_| "Decrypted bytes are not valid UTF-8".to_string())?;
            (text, true)
        } else {
            // Ratchet failed — fall back to static shared key (old sender or chain diverged)
            let key_bytes = hex::decode(&contact.shared_key_hex)
                .map_err(|_| "Invalid shared key".to_string())?;
            let cipher = Aes256Gcm::new_from_slice(&key_bytes)
                .map_err(|_| "Bad key length".to_string())?;
            let nonce_obj = Nonce::from_slice(&nonce_bytes);
            let pt = cipher.decrypt(nonce_obj, ct_bytes.as_slice())
                .map_err(|_| "Decryption failed (ratchet and static key both failed)".to_string())?;
            let text = String::from_utf8(pt)
                .map_err(|_| "Decrypted bytes are not valid UTF-8".to_string())?;
            (text, false)
        }
    };

    if ratchet_ok {
        // Persist advanced ratchet chain state
        let _ = save_contacts(&contacts);
    }

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
    let is_new = !msgs.iter().any(|m| m.id == msg.id);
    if is_new {
        msgs.push(msg.clone());
        save_messages(&msgs).map_err(|e| e.to_string())?;
    }
    Ok((msg, is_new))
}

// ── Commands ──────────────────────────────────────────────────────────────────

/// Generate a shareable contact card.
/// Always waits for relay circuit so the card contains an address that works
/// cross-internet, not a raw LAN IP.
#[tauri::command]
pub async fn get_my_contact_bundle(
    state: State<'_, AppState>,
    my_name: String,
) -> Result<String, EgoDesktopError> {
    let keypair = state.get_keypair()
        .ok_or_else(|| EgoDesktopError::WalletError("Wallet not initialized".into()))?;

    let ledger      = Ledger::load();
    let my_addr     = ledger.address.clone();
    let ed25519_b64 = STANDARD.encode(keypair.ed25519_public_key().as_bytes());
    let name_b64    = STANDARD.encode(my_name.trim().as_bytes());

    // Return immediately if we already have a relay circuit (the common case —
    // circuit is ready within 3-5 s of startup, well before the user opens
    // the contact card screen). Only block if we genuinely don't have it yet,
    // and cap the wait at 3 s so the UI never freezes for 10+ seconds.
    let current = p2p::get_public_endpoint().await;
    let public_endpoint = if current.contains("/p2p-circuit") {
        current  // already confirmed — return instantly
    } else {
        p2p::wait_for_public_endpoint(3).await  // not yet ready — short wait only
    };
    let endpoint_b64    = STANDARD.encode(public_endpoint.as_bytes());

    Ok(format!(
        "egocontact1:{}:{}:{}:{}",
        my_addr, ed25519_b64, name_b64, endpoint_b64
    ))
}

/// Import a contact bundle and send a contact request.
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
        return Err(EgoDesktopError::InvalidInput("Cannot add yourself as a contact".into()));
    }

    let endpoint = endpoint_opt.unwrap_or_default();
    if endpoint.is_empty() {
        return Err(EgoDesktopError::InvalidInput(
            "This contact bundle is from an older version and does not include a network endpoint. \
             Ask the contact to regenerate their card with the latest Ego Desktop.".into(),
        ));
    }

    let keypair        = state.get_keypair()
        .ok_or_else(|| EgoDesktopError::WalletError("Wallet not initialized".into()))?;
    let my_ed25519_hex = hex::encode(keypair.ed25519_public_key().as_bytes());
    let my_kyber_hex   = hex::encode(keypair.kyber_public_key().as_bytes());

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

    // Use relay circuit if already confirmed, otherwise short wait only.
    let current     = p2p::get_public_endpoint().await;
    let my_endpoint = if current.contains("/p2p-circuit") {
        current
    } else {
        p2p::wait_for_public_endpoint(3).await
    };

    // Save the contact FIRST — so it persists even if P2P delivery fails.
    // The peer will receive the request once they are reachable.
    let contact = Contact {
        address:            addr.clone(),
        name,
        ed25519_pubkey:     ed25519,
        kyber_pubkey:       kyber,
        shared_key_hex:     shared_key_hex.clone(),
        status:             "pending_out".to_string(),
        added_at:           chrono::Utc::now().timestamp(),
        endpoint:           endpoint.clone(),
        all_endpoints:      Vec::new(),
        ratchet_send_chain: String::new(),
        ratchet_recv_chain: String::new(),
        ratchet_send_count: 0,
        ratchet_recv_count: 0,
    };
    contacts.push(contact.clone());
    save_contacts(&contacts).map_err(EgoDesktopError::FileSystemError)?;

    let request = p2p::P2PMessage::ContactRequest {
        from_addr:       my_addr.clone(),
        from_name:       my_name.trim().to_string(),
        from_ed25519:    my_ed25519_hex,
        from_kyber:      my_kyber_hex,
        from_shared_key: shared_key_hex,
        from_endpoint:   my_endpoint,
    };
    if let Err(e) = p2p::send_message(&endpoint, &request).await {
        eprintln!("[Messenger] ContactRequest delivery deferred for {}: {}", addr, e);
        deposit_in_relay_inbox(&addr, &my_addr, &request).await;
    }

    Ok(contact)
}

/// Approve an incoming contact request.
/// FIX: includes our relay circuit endpoint in the approval response so the
/// requester learns our current address even if our contact card is stale.
#[tauri::command]
pub async fn approve_contact_request(
    state: State<'_, AppState>,
    contact_addr: String,
    my_name: String,
) -> Result<Contact, EgoDesktopError> {
    let keypair = state.get_keypair()
        .ok_or_else(|| EgoDesktopError::WalletError("Wallet not initialized".into()))?;

    let ledger      = Ledger::load();
    let my_addr     = ledger.address.clone();
    let ed25519_hex = hex::encode(keypair.ed25519_public_key().as_bytes());
    let kyber_hex   = hex::encode(keypair.kyber_public_key().as_bytes());

    let mut contacts = load_contacts();
    let pos = contacts.iter().position(|c| c.address == contact_addr && c.status == "pending_in")
        .ok_or_else(|| EgoDesktopError::NotFound("No pending request from this address".into()))?;

    let shared_key_hex = contacts[pos].shared_key_hex.clone();
    let peer_endpoint  = contacts[pos].endpoint.clone();
    contacts[pos].status = "approved".to_string();
    let contact = contacts[pos].clone();
    save_contacts(&contacts).map_err(EgoDesktopError::FileSystemError)?;

    let my_endpoint = p2p::get_public_endpoint().await;
    let response = p2p::P2PMessage::ContactResponse {
        from_addr:     my_addr.clone(),
        from_name:     my_name.trim().to_string(),
        from_ed25519:  ed25519_hex,
        from_kyber:    kyber_hex,
        approved:      true,
        shared_key:    shared_key_hex,
        from_endpoint: my_endpoint.clone(),
    };

    if !peer_endpoint.is_empty() {
        let resolved_peer_ep = resolve_endpoint(&contact_addr, &peer_endpoint).await;
        if let Err(e) = p2p::send_message(&resolved_peer_ep, &response).await {
            eprintln!("[P2P] Could not notify requester of approval directly: {}", e);
        }

        if !my_endpoint.is_empty() {
            let registry  = crate::ledger::load_registry();
            let active_id = crate::ledger::get_active_wallet_id();
            let my_name_str = registry.wallets.iter()
                .find(|w| w.id == active_id)
                .map(|w| w.name.clone())
                .unwrap_or_else(|| my_name.trim().to_string());
            let announce = p2p::P2PMessage::PeerAnnounce {
                address:   my_addr.clone(),
                name:      my_name_str,
                endpoint:  my_endpoint.clone(),
                endpoints: vec![my_endpoint.clone()],
                city:      None,
                country:   None,
            };
            if let Err(e) = p2p::send_message(&resolved_peer_ep, &announce).await {
                eprintln!("[P2P] Could not send PeerAnnounce after approval: {}", e);
            }
        }
    }

    // Always deposit to relay mailbox so the requester receives the approval
    // even if they were offline or direct delivery was unreliable.
    deposit_in_relay_inbox(&contact_addr, &my_addr, &response).await;

    Ok(contact)
}

/// Decline an incoming contact request.
#[tauri::command]
pub async fn decline_contact_request(
    state: State<'_, AppState>,
    contact_addr: String,
    my_name: String,
) -> Result<(), EgoDesktopError> {
    let keypair = state.get_keypair()
        .ok_or_else(|| EgoDesktopError::WalletError("Wallet not initialized".into()))?;

    let ledger      = Ledger::load();
    let my_addr     = ledger.address.clone();
    let ed25519_hex = hex::encode(keypair.ed25519_public_key().as_bytes());
    let kyber_hex   = hex::encode(keypair.kyber_public_key().as_bytes());

    let mut contacts = load_contacts();
    let pos = contacts.iter().position(|c| c.address == contact_addr && c.status == "pending_in")
        .ok_or_else(|| EgoDesktopError::NotFound("No pending request from this address".into()))?;

    let shared_key_hex = contacts[pos].shared_key_hex.clone();
    let peer_endpoint  = contacts[pos].endpoint.clone();
    contacts.remove(pos);
    save_contacts(&contacts).map_err(EgoDesktopError::FileSystemError)?;

    if !peer_endpoint.is_empty() {
        let response = p2p::P2PMessage::ContactResponse {
            from_addr:     my_addr,
            from_name:     my_name.trim().to_string(),
            from_ed25519:  ed25519_hex,
            from_kyber:    kyber_hex,
            approved:      false,
            shared_key:    shared_key_hex,
            from_endpoint: String::new(),
        };
        if let Err(e) = p2p::send_message(&peer_endpoint, &response).await {
            eprintln!("[P2P] Could not send decline notice: {}", e);
        }
    }

    Ok(())
}

#[tauri::command]
pub async fn get_contacts() -> Result<Vec<Contact>, EgoDesktopError> {
    Ok(load_contacts())
}

/// Encrypt and deliver a chat message.
/// FIX: resolves the peer's latest endpoint from the relay cache before
/// sending so stale stored endpoints don't cause silent delivery failures.
#[tauri::command]
pub async fn send_message(
    app: AppHandle,
    state: State<'_, AppState>,
    contact_addr: String,
    content: String,
    message_type: String,
) -> Result<(), EgoDesktopError> {
    let ledger   = Ledger::load();
    let my_addr  = ledger.address.clone();

    // ── Phase 4: ratchet — load contacts mutably to advance the send chain ────
    let mut contacts = load_contacts();
    let contact_pos = contacts.iter().position(|c| c.address == contact_addr && c.status == "approved")
        .ok_or_else(|| EgoDesktopError::NotFound("Contact not found or not approved".into()))?;

    // Derive per-message encryption key from KDF chain (advances chain state).
    let (enc_key_bytes, send_seq) = derive_send_key_and_seq(&mut contacts[contact_pos], &my_addr)
        .map_err(EgoDesktopError::CryptoError)?;

    let cipher = Aes256Gcm::new_from_slice(&enc_key_bytes)
        .map_err(|_| EgoDesktopError::CryptoError("Bad key length".into()))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ct = cipher.encrypt(nonce, content.as_bytes())
        .map_err(|e| EgoDesktopError::CryptoError(e.to_string()))?;

    let ts        = chrono::Utc::now().timestamp();
    let nonce_hex = hex::encode(nonce_bytes);
    let ct_hex    = hex::encode(&ct);
    let bundle    = format!(
        "egomsg1:{}:{}:{}:{}:{}:{}",
        my_addr, contact_addr, ts, message_type, nonce_hex, ct_hex
    );

    // Clone endpoint data from contact before saving contacts
    let stored_endpoint = contacts[contact_pos].endpoint.clone();
    let all_endpoints   = contacts[contact_pos].all_endpoints.clone();

    // Persist the advanced ratchet chain state immediately
    save_contacts(&contacts).map_err(EgoDesktopError::FileSystemError)?;

    // Capture before content/message_type are moved into Message
    let is_file_bundle  = message_type == "file_bundle";
    let raw_content     = content.clone();

    let mut msgs = load_messages();
    msgs.push(Message {
        id:           format!("{}-{}", ts, &nonce_hex[..8]),
        from:         my_addr.clone(),
        to:           contact_addr.clone(),
        content,
        message_type,
        timestamp:    ts,
        outgoing:     true,
    });
    save_messages(&msgs).map_err(EgoDesktopError::FileSystemError)?;
    // Notify MessengerPage (open in any tab) so it refreshes immediately.
    let _ = app.emit_all("ego://message-sent", serde_json::json!({ "to": contact_addr }));
    let contact_addr_key = contact_addr.clone();
    tokio::spawn(async move {
        // ── File bundles: proactively push FileData to DHT before anything else ──
        // This guarantees the file is available in the receiver's DHT inbox even
        // if the direct connection or relay is down.  Direct delivery below is
        // then just an optimistic fast-path.
        if is_file_bundle {
            let parts: Vec<&str> = raw_content.splitn(5, ':').collect();
            if parts.len() >= 2 {
                let cid    = parts[1].to_string();
                let ledger = crate::ledger::Ledger::load();
                if let Some(file) = ledger.stored_files.iter().find(|f| f.cid == cid).cloned() {

                    if cid.starts_with("egomfd1") {
                        // ── Block-based: pre-deposit ManifestData in receiver's inbox ──
                        // Blocks are already in the DHT global store (put during store_file).
                        // We just need to deliver the manifest + key so the receiver can
                        // reconstruct the block list and fetch any blocks they're missing.
                        if let Ok(manifest) = crate::blocks::load_manifest(&cid) {
                            if let Ok(manifest_json) = serde_json::to_string(&manifest) {
                                let manifest_msg = p2p::P2PMessage::ManifestData {
                                    manifest_cid:  cid.clone(),
                                    manifest_json,
                                    key_hex64:     file.key_nonce_hex.clone(),
                                    file_name:     file.name.clone(),
                                    from_addr:     my_addr.clone(),
                                };
                                deposit_in_relay_inbox(&contact_addr_key, &my_addr, &manifest_msg).await;
                                eprintln!("[EgoSafe] ManifestData deposited in relay mailbox for {} ({} blocks)",
                                    contact_addr_key, manifest.blocks.len());
                            }
                        }
                    } else if !file.local_path.is_empty() && !file.local_path.starts_with("sender:") {
                        // ── Legacy single-file: pre-deposit FileData in receiver's inbox ──
                        match std::fs::read(&file.local_path) {
                            Ok(enc_bytes) => {
                                use base64::Engine as _;
                                let enc_data_b64 = base64::engine::general_purpose::STANDARD
                                    .encode(&enc_bytes);
                                let file_data = p2p::P2PMessage::FileData {
                                    cid:           cid.clone(),
                                    enc_data_b64,
                                    file_name:     file.name.clone(),
                                    key_nonce_hex: file.key_nonce_hex.clone(),
                                };
                                const RELAY_FILE_LIMIT: usize = 3 * 1024 * 1024;
                                if enc_bytes.len() <= RELAY_FILE_LIMIT {
                                    deposit_in_relay_inbox(&contact_addr_key, &my_addr, &file_data).await;
                                    eprintln!("[EgoSafe] FileData deposited in relay mailbox for {} ({} bytes)", contact_addr_key, enc_bytes.len());
                                } else {
                                    eprintln!("[EgoSafe] File too large for relay mailbox ({} bytes) — relying on direct delivery + FileRequest pull", enc_bytes.len());
                                }
                            }
                            Err(e) => eprintln!("[EgoSafe] Cannot read file for push: {}", e),
                        }
                    }
                }
            }
        }

        // ── Deliver ChatMessage (direct or relay mailbox) ─────────────────────
        if stored_endpoint.is_empty() {
            eprintln!("[Messenger] No endpoint for {} — relay mailbox only", contact_addr_key);
            let p2p_msg = p2p::P2PMessage::ChatMessage { bundle, seq: send_seq };
            deposit_in_relay_inbox(&contact_addr_key, &my_addr, &p2p_msg).await;
            return;
        }
        let endpoint = resolve_endpoint(&contact_addr_key, &stored_endpoint).await;
        let p2p_msg  = p2p::P2PMessage::ChatMessage { bundle, seq: send_seq };
        if let Err(e) = p2p::send_message(&endpoint, &p2p_msg).await {
            eprintln!("[Messenger] deliver to {}: {} — depositing in relay inbox", endpoint, e);
            deposit_in_relay_inbox(&contact_addr_key, &my_addr, &p2p_msg).await;
        }

        // ── Also try direct ManifestData/FileData delivery as a fast-path ────
        if is_file_bundle {
            let parts: Vec<&str> = raw_content.splitn(5, ':').collect();
            if parts.len() >= 2 {
                let cid    = parts[1].to_string();
                let ledger = crate::ledger::Ledger::load();
                if let Some(file) = ledger.stored_files.iter().find(|f| f.cid == cid).cloned() {
                    if cid.starts_with("egomfd1") {
                        if let Ok(manifest) = crate::blocks::load_manifest(&cid) {
                            if let Ok(manifest_json) = serde_json::to_string(&manifest) {
                                let manifest_msg = p2p::P2PMessage::ManifestData {
                                    manifest_cid:  cid.clone(),
                                    manifest_json,
                                    key_hex64:     file.key_nonce_hex.clone(),
                                    file_name:     file.name.clone(),
                                    from_addr:     my_addr.clone(),
                                };
                                if let Ok(()) = p2p::send_message(&endpoint, &manifest_msg).await {
                                    eprintln!("[EgoSafe] ManifestData sent directly to {}", contact_addr_key);
                                }
                            }
                        }
                    } else if !file.local_path.is_empty() && !file.local_path.starts_with("sender:") {
                        if let Ok(enc_bytes) = std::fs::read(&file.local_path) {
                            use base64::Engine as _;
                            let enc_data_b64 = base64::engine::general_purpose::STANDARD.encode(&enc_bytes);
                            let file_data = p2p::P2PMessage::FileData {
                                cid:           cid.clone(),
                                enc_data_b64,
                                file_name:     file.name.clone(),
                                key_nonce_hex: file.key_nonce_hex.clone(),
                            };
                            if let Ok(()) = p2p::send_message(&endpoint, &file_data).await {
                                eprintln!("[EgoSafe] FileData sent directly to {} ({} bytes)", contact_addr_key, enc_bytes.len());
                            }
                        }
                    }
                }
            }
        }
    });

    let _ = &state;
    Ok(())
}

#[tauri::command]
pub async fn receive_message(
    _state: State<'_, AppState>,
    bundle: String,
) -> Result<Message, EgoDesktopError> {
    receive_message_inner(&bundle, 0) // seq=0: called from frontend, no seq context
        .map(|(msg, _)| msg)
        .map_err(EgoDesktopError::InvalidInput)
}

#[tauri::command]
pub async fn get_messages(contact_addr: String) -> Result<Vec<Message>, EgoDesktopError> {
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

#[tauri::command]
pub async fn clear_messages() -> Result<(), EgoDesktopError> {
    std::fs::write(messages_path(), "[]")
        .map_err(|e| EgoDesktopError::FileSystemError(e.to_string()))
}

#[tauri::command]
pub async fn delete_message(message_id: String) -> Result<(), EgoDesktopError> {
    let mut msgs = load_messages();
    msgs.retain(|m| m.id != message_id);
    save_messages(&msgs).map_err(EgoDesktopError::FileSystemError)
}

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

#[tauri::command]
pub async fn rename_contact(
    contact_addr: String,
    new_name: String,
) -> Result<(), EgoDesktopError> {
    let new_name = new_name.trim().to_string();
    if new_name.is_empty() {
        return Err(EgoDesktopError::InvalidInput("Name cannot be empty".into()));
    }
    let mut contacts = load_contacts();
    let contact = contacts.iter_mut().find(|c| c.address == contact_addr)
        .ok_or_else(|| EgoDesktopError::NotFound("Contact not found".into()))?;
    contact.name = new_name;
    save_contacts(&contacts).map_err(EgoDesktopError::FileSystemError)
}

/// Deposit an encrypted P2PMessage blob in the relay HTTP mailbox for offline delivery.
/// The relay stores opaque bytes; it never sees plaintext.
pub async fn deposit_in_relay_inbox(_from_addr: &str, to_addr: &str, msg: &crate::p2p::P2PMessage) {
    match serde_json::to_vec(msg) {
        Ok(bytes) => {
            if crate::relay_inbox::deposit(to_addr, bytes).await {
                eprintln!("[RelayInbox] Deposited message for {}", to_addr);
            } else {
                eprintln!("[RelayInbox] Relay deposit failed for {} — message may be lost", to_addr);
            }
        }
        Err(e) => eprintln!("[RelayInbox] Serialization failed: {}", e),
    }
}

/// Poll the relay HTTP mailbox for messages addressed to `my_addr` and
/// dispatch each one through the normal incoming-message handler.
pub async fn poll_relay_inbox(my_addr: &str, app: &tauri::AppHandle) {
    let entries = crate::relay_inbox::fetch(my_addr).await;
    for (msg_id, bytes) in entries {
        match serde_json::from_slice::<crate::p2p::P2PMessage>(&bytes) {
            Ok(msg) => {
                crate::p2p::handle_incoming(msg, app).await;
                crate::relay_inbox::delete(my_addr, &msg_id).await;
            }
            Err(e) => {
                eprintln!("[RelayInbox] Failed to parse message {}: {}", msg_id, e);
                // Delete malformed messages so they don't clog the inbox
                crate::relay_inbox::delete(my_addr, &msg_id).await;
            }
        }
    }
}

