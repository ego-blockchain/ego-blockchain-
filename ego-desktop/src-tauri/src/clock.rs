//! Network time. A node must not trust its computer's clock: plenty are hours off, set to
//! the wrong time zone, or drifting. Blocks stamped with a wrong time are refused by the
//! rest of the network, so every time that reaches consensus comes from here instead.
//!
//! The offset to real time is measured from the `Date` header of several independent HTTPS
//! servers and the median is kept, so no single server decides it. Each sample is taken at
//! the midpoint of its request, which removes most of the round-trip time from the error.

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

static OFFSET_MS: AtomicI64 = AtomicI64::new(0);
static MEASURED: AtomicBool = AtomicBool::new(false);
static ESTIMATED: AtomicBool = AtomicBool::new(false);
static BLOCK_SAMPLES: std::sync::Mutex<Vec<i64>> = std::sync::Mutex::new(Vec::new());
const BLOCK_SAMPLES_KEEP: usize = 16;
const BLOCK_SAMPLES_MIN: usize = 5;
const RETRY_SECS: u64 = 60;

const SOURCES: &[&str] = &[
    "https://www.egoblockchain.com",
    "https://rpc.egoblockchain.com",
    "https://www.google.com",
    "https://www.cloudflare.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
];

const RESYNC_EVERY_SECS: u64 = 15 * 60;
const MIN_SAMPLES: usize = 2;

/// Milliseconds since the Unix epoch, corrected to network time.
pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis() + OFFSET_MS.load(Ordering::Relaxed)
}

/// Seconds since the Unix epoch, corrected to network time.
pub fn now() -> i64 {
    now_ms().div_euclid(1000)
}

/// How far the computer's clock is behind network time, in milliseconds (negative: ahead).
pub fn offset_ms() -> i64 {
    OFFSET_MS.load(Ordering::Relaxed)
}

pub fn is_measured() -> bool {
    MEASURED.load(Ordering::Relaxed)
}

pub fn is_estimated() -> bool {
    ESTIMATED.load(Ordering::Relaxed)
}

/// Whether this node has any trustworthy idea of the time: measured from the web, or
/// estimated from the blocks the network finalised.
pub fn is_trusted() -> bool {
    is_measured() || is_estimated()
}

/// A block the network agreed on was stamped at `block_ts`. Its makers used their own
/// network time, so the stamps tell a node whose web lookups fail how far its clock is off.
pub fn note_finalized_block_time(block_ts: i64) {
    let sample = block_ts * 1000 + 500 - chrono::Utc::now().timestamp_millis();
    let estimate = {
        let mut s = BLOCK_SAMPLES.lock().unwrap_or_else(|e| e.into_inner());
        s.push(sample);
        if s.len() > BLOCK_SAMPLES_KEEP {
            s.remove(0);
        }
        estimate_from_samples(&s)
    };
    if is_measured() {
        return;
    }
    if let Some(offset) = estimate {
        let before = OFFSET_MS.swap(offset, Ordering::Relaxed);
        if !ESTIMATED.swap(true, Ordering::Relaxed) || (before - offset).abs() > 5_000 {
            eprintln!(
                "[Clock] no web time source answered; following the network's blocks instead, this computer's clock is {:.1}s {}",
                offset.abs() as f64 / 1000.0,
                if offset > 0 { "behind" } else { "ahead" }
            );
        }
    }
}

pub fn estimate_from_samples(samples: &[i64]) -> Option<i64> {
    if samples.len() < BLOCK_SAMPLES_MIN {
        return None;
    }
    median_offset(samples.to_vec())
}

/// The median of `samples`, or `None` if there aren't enough of them to trust.
pub fn median_offset(mut samples: Vec<i64>) -> Option<i64> {
    if samples.len() < MIN_SAMPLES {
        return None;
    }
    samples.sort_unstable();
    let mid = samples.len() / 2;
    Some(if samples.len() % 2 == 0 { (samples[mid - 1] + samples[mid]) / 2 } else { samples[mid] })
}

async fn sample(client: &reqwest::Client, url: &str) -> Option<i64> {
    let sent = chrono::Utc::now().timestamp_millis();
    let resp = client.head(url).send().await.ok()?;
    let received = chrono::Utc::now().timestamp_millis();
    if received - sent > 5_000 {
        return None;
    }
    let date = resp.headers().get(reqwest::header::DATE)?.to_str().ok()?;
    let server_ms = chrono::DateTime::parse_from_rfc2822(date).ok()?.timestamp_millis() + 500;
    Some(server_ms - (sent + received) / 2)
}

pub async fn sync() {
    let Ok(client) = reqwest::Client::builder().timeout(std::time::Duration::from_secs(6)).build() else { return };
    let samples: Vec<i64> = futures::future::join_all(SOURCES.iter().map(|u| sample(&client, u)))
        .await
        .into_iter()
        .flatten()
        .collect();
    let Some(offset) = median_offset(samples) else { return };
    OFFSET_MS.store(offset, Ordering::Relaxed);
    MEASURED.store(true, Ordering::Relaxed);
    if offset.abs() > 5_000 {
        eprintln!(
            "[Clock] This computer's clock is {:.1}s {}; the node uses network time instead.",
            offset.abs() as f64 / 1000.0,
            if offset > 0 { "behind" } else { "ahead" }
        );
    }
}

pub fn start() {
    tauri::async_runtime::spawn(async {
        loop {
            sync().await;
            let wait = if is_measured() { RESYNC_EVERY_SECS } else { RETRY_SECS };
            tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_few_agreed_blocks_are_enough_to_estimate_the_clock() {
        assert_eq!(estimate_from_samples(&[170_000, 171_000, 169_000, 170_500]), None, "four blocks are too few");
        assert_eq!(estimate_from_samples(&[170_000, 171_000, 169_000, 170_500, 9_000_000]), Some(170_500), "one late block does not move the estimate");
    }

    #[test]
    fn one_wrong_source_cannot_move_the_clock() {
        assert_eq!(median_offset(vec![37_558_000, 120, -80, 40, 10]), Some(40));
        assert_eq!(median_offset(vec![100, 300]), Some(200));
        assert_eq!(median_offset(vec![5]), None);
        assert_eq!(median_offset(vec![]), None);
    }
}
