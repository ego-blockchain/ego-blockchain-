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
            tokio::time::sleep(std::time::Duration::from_secs(RESYNC_EVERY_SECS)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_wrong_source_cannot_move_the_clock() {
        assert_eq!(median_offset(vec![37_558_000, 120, -80, 40, 10]), Some(40));
        assert_eq!(median_offset(vec![100, 300]), Some(200));
        assert_eq!(median_offset(vec![5]), None);
        assert_eq!(median_offset(vec![]), None);
    }
}
