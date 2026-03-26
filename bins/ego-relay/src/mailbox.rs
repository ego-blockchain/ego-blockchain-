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
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const RATE_WINDOW_SECS: u64 = 3600;
const MAX_POSTS_PER_WINDOW: usize = 20;

const MAX_MSG_SIZE:   usize = 16 * 1024;
const MAX_INBOX_MSGS: usize = 20;
const TTL_SECS:       u64   = 48 * 3600;

#[derive(Clone, Serialize, Deserialize)]
pub struct MailboxEntry {
    pub id:         String,
    pub ciphertext: Vec<u8>,
    pub stored_at:  u64,
}

type RateMap = Arc<Mutex<HashMap<String, (u64, usize)>>>;

pub struct MailboxStore {
    pub db:   Arc<DB>,
    pub rate: RateMap,
}

impl Clone for MailboxStore {
    fn clone(&self) -> Self {
        MailboxStore { db: self.db.clone(), rate: self.rate.clone() }
    }
}

pub fn new_store() -> MailboxStore {
    let mut opts = Options::default();
    opts.create_if_missing(true);
    let db = DB::open_with_ttl(&opts, "mailbox.db", Duration::from_secs(TTL_SECS))
        .expect("Failed to open mailbox RocksDB — check write permissions");
    MailboxStore {
        db:   Arc::new(db),
        rate: Arc::new(Mutex::new(HashMap::new())),
    }
}

fn db_key(hash: &str, id: &str) -> Vec<u8> {
    format!("{}:{}", hash, id).into_bytes()
}

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

fn inbox_prefix(hash: &str) -> Vec<u8> {
    format!("{}:", hash).into_bytes()
}

pub fn router(store: MailboxStore) -> Router {
    Router::new()
        .route("/inbox/{hash}",      post(post_message).get(get_messages))
        .route("/inbox/{hash}/{id}", delete(delete_message))
        .with_state(store)
}

async fn post_message(
    Path(hash):   Path<String>,
    State(store): State<MailboxStore>,
    body:         Bytes,
) -> StatusCode {
    if body.len() > MAX_MSG_SIZE {
        return StatusCode::PAYLOAD_TOO_LARGE;
    }

    let now = now_secs();

    {
        let mut rate = store.rate.lock().unwrap();
        let entry = rate.entry(hash.clone()).or_insert((now, 0));
        if now.saturating_sub(entry.0) > RATE_WINDOW_SECS {
            *entry = (now, 0);
        }
        if entry.1 >= MAX_POSTS_PER_WINDOW {
            return StatusCode::TOO_MANY_REQUESTS;
        }
        entry.1 += 1;
    }

    let id = blake3::hash(&[body.as_ref(), &now.to_le_bytes()].concat())
        .to_hex()
        .to_string();

    let prefix = inbox_prefix(&hash);
    let count = store.db
        .prefix_iterator(&prefix)
        .take_while(|r| r.as_ref().ok().map(|(k, _)| k.starts_with(&prefix)).unwrap_or(false))
        .count();
    if count >= MAX_INBOX_MSGS {
        return StatusCode::TOO_MANY_REQUESTS;
    }

    let key   = db_key(&hash, &id);
    let value = encode_value(now, &body);
    match store.db.put(&key, &value) {
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

    for item in store.db.prefix_iterator(&prefix) {
        let Ok((key, val)) = item else { continue };
        if !key.starts_with(&prefix) { break; }

        let id = String::from_utf8_lossy(&key[prefix.len()..]).to_string();
        if let Some(entry) = decode_value(&id, &val) {
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
    let _ = store.db.delete(&key);
    StatusCode::NO_CONTENT
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
