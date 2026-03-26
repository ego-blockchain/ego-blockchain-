use crate::ledger::data_dir;
use serde::{Deserialize, Serialize};
use std::fs;

const OUTBOX_TTL_SECS: i64 = 7 * 86_400;
const MAX_RETRIES: u32      = 20;

fn outbox_path() -> std::path::PathBuf {
    data_dir().join("outbox.json")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxEntry {
    pub to_addr:     String,
    pub endpoint:    String,
    pub msg_json:    String,
    pub created_at:  i64,
    pub retry_at:    i64,
    pub retry_count: u32,
}

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

pub fn enqueue(to_addr: &str, endpoint: &str, msg: &crate::p2p::P2PMessage) {
    let Ok(msg_json) = serde_json::to_string(msg) else { return };
    let now = chrono::Utc::now().timestamp();
    let mut entries = load_outbox();
    entries.push(OutboxEntry {
        to_addr:     to_addr.to_string(),
        endpoint:    endpoint.to_string(),
        msg_json,
        created_at:  now,
        retry_at:    now + 30,
        retry_count: 0,
    });
    save_outbox(&entries);
    eprintln!("[Outbox] Queued message for {} (total: {})", to_addr, entries.len());
}

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
            to_remove.push(i);
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

                let delay = (30u64 * (1u64 << entry.retry_count.min(9))) as i64;
                entry.retry_at = now + delay;
            }
        }
    }

    for &i in to_remove.iter().rev() {
        entries.remove(i);
    }
    save_outbox(&entries);
}

pub async fn flush_pending() {
    let entries = load_outbox();
    if entries.is_empty() { return; }

    let now = chrono::Utc::now().timestamp();

    let addrs: std::collections::HashSet<String> = entries.iter()
        .filter(|e| e.retry_at <= now)
        .map(|e| e.to_addr.clone())
        .collect();

    for addr in addrs {

        let fresh_ep = {
            let cache = crate::p2p::load_peer_cache();
            cache.into_iter()
                .find(|p| p.address == addr && !p.endpoint.is_empty())
                .map(|p| p.endpoint)
        };
        flush_for(&addr, fresh_ep.as_deref()).await;
    }
}

pub fn pending_count(addr: &str) -> usize {
    load_outbox().iter().filter(|e| e.to_addr == addr).count()
}
