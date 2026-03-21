//! Relay-side store-and-forward mailbox.
//!
//! Peers POST encrypted message blobs to `/inbox/{hash}` where `hash =
//! blake3(recipient_address)`.  The relay never sees plaintext — it only
//! stores opaque bytes and returns them on GET.  Messages auto-expire after
//! TTL_SECS (7 days).
//!
//! Listening on port 4002 alongside the libp2p relay on port 4001.

use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post},
    Json,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_MSG_SIZE:   usize = 64 * 1024;   // 64 KB per message
const MAX_INBOX_MSGS: usize = 500;          // max queued messages per inbox
const TTL_SECS:       u64   = 7 * 24 * 3600; // 7 days

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
pub struct MailboxEntry {
    pub id:         String,
    pub ciphertext: Vec<u8>,
    pub stored_at:  u64,
}

pub type MailboxStore = Arc<Mutex<HashMap<String, Vec<MailboxEntry>>>>;

pub fn new_store() -> MailboxStore {
    Arc::new(Mutex::new(HashMap::new()))
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router(store: MailboxStore) -> Router {
    Router::new()
        .route("/inbox/{hash}",      post(post_message).get(get_messages))
        .route("/inbox/{hash}/{id}", delete(delete_message))
        .with_state(store)
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn post_message(
    Path(hash):     Path<String>,
    State(store):   State<MailboxStore>,
    body:           Bytes,
) -> StatusCode {
    if body.len() > MAX_MSG_SIZE {
        return StatusCode::PAYLOAD_TOO_LARGE;
    }
    let now = now_secs();
    let id  = blake3::hash(&[body.as_ref(), &now.to_le_bytes()].concat())
        .to_hex()
        .to_string();
    let entry = MailboxEntry { id, ciphertext: body.to_vec(), stored_at: now };

    let mut map = store.lock().unwrap();
    let inbox = map.entry(hash).or_default();
    inbox.retain(|e| now.saturating_sub(e.stored_at) < TTL_SECS);
    if inbox.len() >= MAX_INBOX_MSGS {
        return StatusCode::TOO_MANY_REQUESTS;
    }
    inbox.push(entry);
    StatusCode::CREATED
}

async fn get_messages(
    Path(hash):   Path<String>,
    State(store): State<MailboxStore>,
) -> Json<Vec<MailboxEntry>> {
    let now = now_secs();
    let mut map = store.lock().unwrap();
    let inbox = map.entry(hash).or_default();
    inbox.retain(|e| now.saturating_sub(e.stored_at) < TTL_SECS);
    Json(inbox.clone())
}

async fn delete_message(
    Path((hash, id)): Path<(String, String)>,
    State(store):     State<MailboxStore>,
) -> StatusCode {
    let mut map = store.lock().unwrap();
    if let Some(inbox) = map.get_mut(&hash) {
        inbox.retain(|e| e.id != id);
    }
    StatusCode::NO_CONTENT
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
