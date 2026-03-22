//! Relay-side store-and-forward mailbox backed by RocksDB.
//!
//! Peers POST encrypted message blobs to `/inbox/{hash}` where `hash =
//! blake3(recipient_address)`.  The relay never sees plaintext — it only
//! stores opaque bytes and returns them on GET.  Messages auto-expire after
//! TTL_SECS (7 days) via RocksDB's built-in TTL compaction filter.
//!
//! Listening on port 4002 alongside the libp2p relay on port 4001.
//!
//! Key format:   `{hash}:{id}`
//! Value format: `{8-byte LE stored_at}{ciphertext}`

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};
use rocksdb::{Options, DB};
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const MAX_MSG_SIZE:   usize = 64 * 1024;    // 64 KB per message
const MAX_INBOX_MSGS: usize = 500;           // max queued messages per inbox
const TTL_SECS:       u64   = 7 * 24 * 3600; // 7 days

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
pub struct MailboxEntry {
    pub id:         String,
    pub ciphertext: Vec<u8>,
    pub stored_at:  u64,
}

pub type MailboxStore = Arc<DB>;

pub fn new_store() -> MailboxStore {
    let mut opts = Options::default();
    opts.create_if_missing(true);
    let db = DB::open_with_ttl(&opts, "mailbox.db", Duration::from_secs(TTL_SECS))
        .expect("Failed to open mailbox RocksDB — check write permissions");
    Arc::new(db)
}

// ── Key/value encoding ────────────────────────────────────────────────────────

/// RocksDB key: `{hash}:{id}` (both ASCII-safe hex strings)
fn db_key(hash: &str, id: &str) -> Vec<u8> {
    format!("{}:{}", hash, id).into_bytes()
}

/// RocksDB value: first 8 bytes = stored_at as u64 LE, remainder = ciphertext
fn encode_value(stored_at: u64, ct: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + ct.len());
    v.extend_from_slice(&stored_at.to_le_bytes());
    v.extend_from_slice(ct);
    v
}

fn decode_value(id: &str, raw: &[u8]) -> Option<MailboxEntry> {
    if raw.len() < 8 { return None; }
    let stored_at = u64::from_le_bytes(raw[..8].try_into().ok()?);
    Some(MailboxEntry { id: id.to_string(), ciphertext: raw[8..].to_vec(), stored_at })
}

/// Byte prefix used to scope iteration to one inbox: `{hash}:`
fn inbox_prefix(hash: &str) -> Vec<u8> {
    format!("{}:", hash).into_bytes()
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
    Path(hash):   Path<String>,
    State(store): State<MailboxStore>,
    body:         Bytes,
) -> StatusCode {
    if body.len() > MAX_MSG_SIZE {
        return StatusCode::PAYLOAD_TOO_LARGE;
    }

    let now = now_secs();
    let id  = blake3::hash(&[body.as_ref(), &now.to_le_bytes()].concat())
        .to_hex()
        .to_string();

    // Count existing messages for this inbox before inserting
    let prefix = inbox_prefix(&hash);
    let count = store
        .prefix_iterator(&prefix)
        .take_while(|r| r.as_ref().ok().map(|(k, _)| k.starts_with(&prefix)).unwrap_or(false))
        .count();
    if count >= MAX_INBOX_MSGS {
        return StatusCode::TOO_MANY_REQUESTS;
    }

    let key   = db_key(&hash, &id);
    let value = encode_value(now, &body);
    match store.put(&key, &value) {
        Ok(_)  => StatusCode::CREATED,
        Err(e) => {
            eprintln!("[Mailbox] DB write error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn get_messages(
    Path(hash):   Path<String>,
    State(store): State<MailboxStore>,
) -> Json<Vec<MailboxEntry>> {
    let prefix = inbox_prefix(&hash);
    let now    = now_secs();
    let mut msgs = Vec::new();

    for item in store.prefix_iterator(&prefix) {
        let Ok((key, val)) = item else { continue };
        if !key.starts_with(&prefix) { break; }

        // Extract id from key by stripping the "{hash}:" prefix
        let id = String::from_utf8_lossy(&key[prefix.len()..]).to_string();
        if let Some(entry) = decode_value(&id, &val) {
            // Belt-and-suspenders TTL check alongside RocksDB compaction
            if now.saturating_sub(entry.stored_at) < TTL_SECS {
                msgs.push(entry);
            }
        }
    }

    Json(msgs)
}

async fn delete_message(
    Path((hash, id)): Path<(String, String)>,
    State(store):     State<MailboxStore>,
) -> StatusCode {
    let key = db_key(&hash, &id);
    let _ = store.delete(&key); // idempotent: ignore "not found"
    StatusCode::NO_CONTENT
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
