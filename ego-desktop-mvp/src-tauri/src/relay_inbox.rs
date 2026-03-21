//! Relay HTTP mailbox — store-and-forward for offline messenger delivery.
//!
//! Messages are AES-256-GCM encrypted at the messenger layer before being
//! sent here.  The relay stores opaque blobs indexed by blake3(recipient_addr)
//! so it never learns actual addresses or content.

use serde::{Deserialize, Serialize};

const RELAY_HTTP: &str = "http://EgoRelay.egoblockchain.com:4002";

#[derive(Serialize, Deserialize)]
struct MailboxEntry {
    id:         String,
    ciphertext: Vec<u8>,
    stored_at:  u64,
}

fn recipient_hash(addr: &str) -> String {
    hex::encode(blake3::hash(addr.as_bytes()).as_bytes())
}

/// POST an encrypted message blob to the relay mailbox for `to_addr`.
/// Returns true on success.
pub async fn deposit(to_addr: &str, ciphertext: Vec<u8>) -> bool {
    let hash = recipient_hash(to_addr);
    let url  = format!("{}/inbox/{}", RELAY_HTTP, hash);
    match reqwest::Client::new().post(&url).body(ciphertext).send().await {
        Ok(r)  => r.status().is_success(),
        Err(e) => {
            eprintln!("[RelayInbox] deposit failed: {}", e);
            false
        }
    }
}

/// GET all pending blobs for `my_addr` from the relay mailbox.
/// Returns a list of (message_id, ciphertext) pairs.
pub async fn fetch(my_addr: &str) -> Vec<(String, Vec<u8>)> {
    let hash = recipient_hash(my_addr);
    let url  = format!("{}/inbox/{}", RELAY_HTTP, hash);
    match reqwest::Client::new().get(&url).send().await {
        Ok(r) => {
            match r.json::<Vec<MailboxEntry>>().await {
                Ok(entries) => entries.into_iter().map(|e| (e.id, e.ciphertext)).collect(),
                Err(e) => {
                    eprintln!("[RelayInbox] fetch parse failed: {}", e);
                    vec![]
                }
            }
        }
        Err(e) => {
            eprintln!("[RelayInbox] fetch failed: {}", e);
            vec![]
        }
    }
}

/// DELETE a message from the relay mailbox after successful delivery.
pub async fn delete(my_addr: &str, msg_id: &str) {
    let hash = recipient_hash(my_addr);
    let url  = format!("{}/inbox/{}/{}", RELAY_HTTP, hash, msg_id);
    let _ = reqwest::Client::new().delete(&url).send().await;
}
