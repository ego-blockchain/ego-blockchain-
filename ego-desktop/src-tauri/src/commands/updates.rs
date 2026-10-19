use crate::error::EgoDesktopError;
use serde::{Deserialize, Serialize};

/// Where the latest published version is announced. A small static file served
/// alongside the download page, so cutting a release is a website deploy rather
/// than anything server-side.
const VERSION_MANIFEST_URL: &str = "https://egoblockchain.com/version.json";
const DOWNLOAD_PAGE_URL:    &str = "https://egoblockchain.com/download";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateInfo {
    pub update_available: bool,
    /// Version this build is running.
    pub current: String,
    /// Latest published version, or the current one when the check fails.
    pub latest: String,
    pub download_url: String,
    #[serde(default)]
    pub notes: String,
}

/// Parse "0.3.33" into comparable parts. Anything unparseable sorts as 0 so a
/// malformed manifest can never look newer than a real build.
fn parse_version(v: &str) -> (u32, u32, u32) {
    let clean = v.trim().trim_start_matches(['v', 'V']);
    let mut it = clean.split(['.', '-', '+']).map(|p| p.parse::<u32>().unwrap_or(0));
    (
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
    )
}

fn is_newer(latest: &str, current: &str) -> bool {
    parse_version(latest) > parse_version(current)
}

/// Ask the website whether a newer build has been published.
///
/// Never fails loudly: a node with no connectivity, a website mid-deploy or a
/// malformed manifest all return "no update" rather than an error the user has
/// to dismiss. The check is advisory — it must not interfere with running a
/// node offline.
#[tauri::command]
pub async fn check_for_update() -> Result<UpdateInfo, EgoDesktopError> {
    let current = env!("CARGO_PKG_VERSION").to_string();

    let fallback = UpdateInfo {
        update_available: false,
        current: current.clone(),
        latest: current.clone(),
        download_url: DOWNLOAD_PAGE_URL.to_string(),
        notes: String::new(),
    };

    // An update check is a request to a known host. On a censored connection
    // that is enough to identify the machine as running Ego, so a node told to
    // stay local does not make it.
    if crate::p2p::offline_mode() {
        return Ok(fallback);
    }

    let Some(manifest) = fetch_manifest().await else { return Ok(fallback) };

    let latest = manifest["version"].as_str().unwrap_or("").trim().to_string();
    if latest.is_empty() {
        return Ok(fallback);
    }

    Ok(UpdateInfo {
        update_available: is_newer(&latest, &current),
        current,
        latest,
        download_url: manifest["url"].as_str().unwrap_or(DOWNLOAD_PAGE_URL).to_string(),
        notes: manifest["notes"].as_str().unwrap_or("").to_string(),
    })
}

async fn fetch_manifest() -> Option<serde_json::Value> {
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(8)).build().ok()?;
    let resp = client.get(VERSION_MANIFEST_URL).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    // A missing version.json on an SPA host answers with index.html and a 200,
    // so a failed JSON parse here is the expected shape of "not published yet".
    resp.json().await.ok()
}

const PUBLISHED_CERT_RECHECK_SECS: i64 = 600;
static PUBLISHED_CERT: std::sync::Mutex<(i64, Option<(u64, String)>)> = std::sync::Mutex::new((0, None));

fn published_cert_in(manifest: &serde_json::Value) -> Option<(u64, String)> {
    let index = manifest["state_cert"]["index"].as_u64().filter(|i| *i > 0)?;
    let hash = manifest["state_cert"]["hash"].as_str()?.trim().to_ascii_lowercase();
    crate::state_cert::is_anchor_hash(&hash).then_some((index, hash))
}

pub fn published_state_cert() -> Option<(u64, String)> {
    PUBLISHED_CERT.lock().unwrap_or_else(|e| e.into_inner()).1.clone()
}

pub async fn refresh_published_state_cert() -> Option<(u64, String)> {
    let now = chrono::Utc::now().timestamp();
    {
        let g = PUBLISHED_CERT.lock().unwrap_or_else(|e| e.into_inner());
        if g.0 != 0 && now - g.0 < PUBLISHED_CERT_RECHECK_SECS {
            return g.1.clone();
        }
    }
    let fetched = if crate::p2p::offline_mode() { None } else { fetch_manifest().await.as_ref().and_then(published_cert_in) };
    let mut g = PUBLISHED_CERT.lock().unwrap_or_else(|e| e.into_inner());
    g.0 = now;
    if fetched.is_some() {
        g.1 = fetched;
    }
    g.1.clone()
}

const NOTIFY_MARKER: &str = ".update_notified";
const FIRST_CHECK_SECS: u64 = 90;
const RECHECK_SECS: u64 = 6 * 60 * 60;

fn already_notified(version: &str) -> bool {
    let p = crate::ledger::base_data_dir().join(NOTIFY_MARKER);
    std::fs::read_to_string(p).map(|v| v.trim() == version).unwrap_or(false)
}

fn remember_notified(version: &str) {
    let p = crate::ledger::base_data_dir().join(NOTIFY_MARKER);
    let _ = std::fs::write(p, version);
}

pub fn spawn_update_notifier(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(FIRST_CHECK_SECS)).await;
        loop {
            if let Ok(info) = check_for_update().await {
                if info.update_available && !already_notified(&info.latest) {
                    let body = if info.notes.is_empty() {
                        format!("Version {} is ready to download.", info.latest)
                    } else {
                        info.notes.clone()
                    };
                    crate::commands::notifications::notify(
                        &app,
                        &format!("Ego Desktop {} available", info.latest),
                        &body,
                    );
                    remember_notified(&info.latest);
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(RECHECK_SECS)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newer_versions_are_detected() {
        assert!(is_newer("0.3.34", "0.3.33"));
        assert!(is_newer("0.4.0", "0.3.99"));
        assert!(is_newer("1.0.0", "0.9.9"));
        assert!(is_newer("v0.3.34", "0.3.33"), "a leading v must not break it");
    }

    #[test]
    fn same_or_older_never_prompts() {
        assert!(!is_newer("0.3.33", "0.3.33"));
        assert!(!is_newer("0.3.32", "0.3.33"));
        assert!(!is_newer("0.2.99", "0.3.0"));
    }

    /// 0.3.9 vs 0.3.10 is the case string comparison gets wrong.
    #[test]
    fn compares_numerically_not_alphabetically() {
        assert!(is_newer("0.3.10", "0.3.9"));
        assert!(!is_newer("0.3.9", "0.3.10"));
    }

    #[test]
    fn the_published_certificate_is_read_only_when_well_formed() {
        let h = "ab".repeat(32);
        let ok = serde_json::json!({ "version": "0.3.627", "state_cert": { "index": 1, "hash": h } });
        assert_eq!(published_cert_in(&ok), Some((1, h.clone())));
        let upper = serde_json::json!({ "state_cert": { "index": 3, "hash": h.to_uppercase() } });
        assert_eq!(published_cert_in(&upper), Some((3, h.clone())));
        for bad in [
            serde_json::json!({ "version": "0.3.627" }),
            serde_json::json!({ "state_cert": { "index": 0, "hash": h } }),
            serde_json::json!({ "state_cert": { "index": 1, "hash": "abc" } }),
            serde_json::json!({ "state_cert": { "index": 1, "hash": "zz".repeat(32) } }),
            serde_json::json!({ "state_cert": { "hash": h } }),
        ] {
            assert_eq!(published_cert_in(&bad), None, "{bad}");
        }
    }

    /// A corrupt or HTML manifest must never appear newer than a real build.
    #[test]
    fn garbage_never_looks_like_an_update() {
        assert!(!is_newer("", "0.3.33"));
        assert!(!is_newer("<!doctype html>", "0.3.33"));
        assert!(!is_newer("not.a.version", "0.3.33"));
    }
}
