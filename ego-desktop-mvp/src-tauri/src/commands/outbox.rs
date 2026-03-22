//! Local sender-side outbox for undelivered P2P messages.
//!
//! When direct delivery of a ChatMessage (or ManifestData) fails — because the
//! peer is temporarily offline or the relay circuit isn't up yet — the message
//! is queued here rather than forwarded to the relay server.
//!
//! The relay is a concierge: it only holds contact-pairing events
//! (ContactRequest / ContactResponse).  All ongoing chat is P2P or outbox-retried.
//!
//! Retry strategy:
//!   - On PeerAnnounce: flush immediately for that address.
//!   - Every 30 s (keep-alive loop): flush entries whose retry_at has passed.
//!   - Exponential back-off: retry_at += 30s × 2^retry_count (cap 6 h).
//!   - Entries older than OUTBOX_TTL_SECS are pruned automatically.

use crate::ledger::data_dir;
use serde::{Deserialize, Serialize};
use std::fs;

const OUTBOX_TTL_SECS: i64 = 7 * 86_400; // 7 days — then give up
const MAX_RETRIES: u32      = 20;          // ~6 h back-off ceiling

fn outbox_path() -> std::path::PathBuf {
    data_dir().join("outbox.json")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxEntry {
    pub to_addr:     String,
    pub endpoint:    String,
    pub msg_json:    String, // JSON-encoded P2PMessage
    pub created_at:  i64,
    pub retry_at:    i64,
    pub retry_count: u32,
}

// ── Persistence ────────────────────────────────────────────────────────────────

fn load_outbox() -> Vec<OutboxEntry> {
    let data  = fs::read_to_string(outbox_path()).unwrap_or_default();
    let mut v: Vec<OutboxEntry> = serde_json::from_str(&data).unwrap_or_default();
    let cutoff = chrono::Utc::now().timestamp() - OUTBOX_TTL_SECS;
    v.retain(|e| e.created_at > cutoff && e.retry_count <= MAX_RETRIES);
    v
}

fn save_outbox(entries: &[OutboxEntry]) {
    if let Ok(data) = serde_json::to_string_pretty(entries) {
        let _ = crate::utils::atomic_write(&outbox_path(), data.as_bytes());
    }
}

// ── Public API ─────────────────────────────────────────────────────────────────

/// Queue a P2P message for retry.  Called when direct delivery failed.
pub fn enqueue(to_addr: &str, endpoint: &str, msg: &crate::p2p::P2PMessage) {
    let Ok(msg_json) = serde_json::to_string(msg) else { return };
    let now = chrono::Utc::now().timestamp();
    let mut entries = load_outbox();
    entries.push(OutboxEntry {
        to_addr:     to_addr.to_string(),
        endpoint:    endpoint.to_string(),
        msg_json,
        created_at:  now,
        retry_at:    now + 30, // first retry in 30 s
        retry_count: 0,
    });
    save_outbox(&entries);
    eprintln!("[Outbox] Queued message for {} (total: {})", to_addr, entries.len());
}

/// Flush all outbox entries for `addr`, using `fresh_endpoint` if available.
/// Called on PeerAnnounce so we deliver immediately when the peer comes online.
pub async fn flush_for(addr: &str, fresh_endpoint: Option<&str>) {
    let mut entries = load_outbox();
    if entries.is_empty() { return; }

    let now = chrono::Utc::now().timestamp();
    let mut to_remove: Vec<usize> = Vec::new();

    for (i, entry) in entries.iter_mut().enumerate() {
        if entry.to_addr != addr { continue; }

        let ep = fresh_endpoint
            .filter(|e| !e.is_empty())
            .unwrap_or(&entry.endpoint);
        if ep.is_empty() { continue; }

        let Ok(msg) = serde_json::from_str::<crate::p2p::P2PMessage>(&entry.msg_json) else {
            to_remove.push(i); // malformed — drop
            continue;
        };

        match crate::p2p::send_message(ep, &msg).await {
            Ok(_) => {
                eprintln!("[Outbox] Delivered queued message to {} (attempt {})",
                    addr, entry.retry_count + 1);
                to_remove.push(i);
            }
            Err(e) => {
                eprintln!("[Outbox] Retry {} failed for {}: {}", entry.retry_count + 1, addr, e);
                entry.retry_count += 1;
                // Exponential back-off, capped at 6 hours
                let delay = (30u64 * (1u64 << entry.retry_count.min(9))) as i64;
                entry.retry_at = now + delay;
            }
        }
    }

    // Remove delivered / malformed entries (reverse order to preserve indices)
    for &i in to_remove.iter().rev() {
        entries.remove(i);
    }
    save_outbox(&entries);
}

/// Flush all outbox entries whose retry_at ≤ now.
/// Called from the 30-second keep-alive loop.
pub async fn flush_pending() {
    let entries = load_outbox();
    if entries.is_empty() { return; }

    let now = chrono::Utc::now().timestamp();
    // Collect unique addresses with due entries
    let addrs: std::collections::HashSet<String> = entries.iter()
        .filter(|e| e.retry_at <= now)
        .map(|e| e.to_addr.clone())
        .collect();

    for addr in addrs {
        flush_for(&addr, None).await;
    }
}

/// How many messages are currently pending for `addr`.
pub fn pending_count(addr: &str) -> usize {
    load_outbox().iter().filter(|e| e.to_addr == addr).count()
}
