use crate::app::{AppState, CoverageStatus, Location, NetworkQuality};
use crate::error::EgoDesktopError;
use serde::Deserialize;
use tauri::State;

// ── ip-api.com extended response ──────────────────────────────────────────────
// Endpoint: http://ip-api.com/json?fields=status,lat,lon,city,regionName,country,isp,org,proxy,hosting
// The `proxy` and `hosting` fields are available on the free tier when requested explicitly.

#[derive(Deserialize)]
struct IpApiResponse {
    status: String,
    lat: Option<f64>,
    lon: Option<f64>,
    city: Option<String>,
    #[serde(rename = "regionName")]
    region_name: Option<String>,
    country: Option<String>,
    isp: Option<String>,
    org: Option<String>,
    /// true if ip-api detects a proxy / VPN
    proxy: Option<bool>,
    /// true if the IP belongs to a hosting / datacenter provider
    hosting: Option<bool>,
}

// ── VPN / proxy keyword blocklist ─────────────────────────────────────────────
// Matches against ISP and org fields (lowercased). Covers major VPN providers
// and datacenter ranges commonly used as VPN exit nodes.
const VPN_KEYWORDS: &[&str] = &[
    // Named VPN services
    "nordvpn", "expressvpn", "mullvad", "surfshark", "privatevpn",
    "cyberghost", "ipvanish", "purevpn", "protonvpn", "windscribe",
    "tunnelbear", "hotspot shield", "private internet access", "pia vpn",
    "torguard", "zenmate", "hide.me", "astrill", "ivpn", "ovpn",
    "hidemyass", "hma", "perfect privacy", "strongvpn", "vyprvpn",
    "avast vpn", "avg vpn", "norton vpn", "f-secure vpn", "bitdefender vpn",
    // Generic proxy / anonymiser terms
    "vpn", "proxy", "anonymizer", "anonymiser", "tor exit", "tor relay",
    "socks", "openvpn", "wireguard relay",
    // Datacenter / hosting providers often used as VPN exit nodes
    "datacamp", "m247", "leaseweb", "quadranet", "serverius",
    "choopa", "vultr", "linode", "akamai", "fastly",
    // Note: we intentionally leave out "digitalocean", "aws", "cloudflare",
    // "hetzner" etc. because many legitimate business ISPs use those networks.
    // The ip-api `hosting` flag already catches datacenter IPs more precisely.
];

fn vpn_keyword_match(resp: &IpApiResponse) -> Option<String> {
    let isp_l = resp.isp.as_deref().unwrap_or("").to_lowercase();
    let org_l = resp.org.as_deref().unwrap_or("").to_lowercase();
    for kw in VPN_KEYWORDS {
        if isp_l.contains(kw) || org_l.contains(kw) {
            let matched_in = if isp_l.contains(kw) {
                resp.isp.as_deref().unwrap_or(kw)
            } else {
                resp.org.as_deref().unwrap_or(kw)
            };
            return Some(format!("ISP/Org match: \"{}\"", matched_in));
        }
    }
    None
}

fn detect_vpn(resp: &IpApiResponse) -> Option<String> {
    // 1 – ip-api's own proxy flag
    if resp.proxy.unwrap_or(false) {
        return Some("IP flagged as proxy/VPN by ip-api.com".to_string());
    }
    // 2 – hosting/datacenter flag
    if resp.hosting.unwrap_or(false) {
        return Some(format!(
            "IP belongs to a datacenter/hosting provider (ISP: {})",
            resp.isp.as_deref().unwrap_or("unknown")
        ));
    }
    // 3 – keyword match in ISP / org name
    vpn_keyword_match(resp)
}

// ── Machine fingerprint ───────────────────────────────────────────────────────
// Used to detect multiple wallets/instances on the same physical machine
// attempting to multiply coverage rewards.

fn get_machine_id() -> String {
    // Windows: Windows Machine GUID from registry (unique per installation, survives reboots)
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("reg")
            .args([
                "query",
                r"HKLM\SOFTWARE\Microsoft\Cryptography",
                "/v",
                "MachineGuid",
            ])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                if line.contains("MachineGuid") {
                    if let Some(guid) = line.split_whitespace().last() {
                        return guid.to_string();
                    }
                }
            }
        }
    }

    // Linux: /etc/machine-id (systemd)
    #[cfg(target_os = "linux")]
    {
        if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
            let id = id.trim().to_string();
            if !id.is_empty() {
                return id;
            }
        }
        // Fallback: /var/lib/dbus/machine-id
        if let Ok(id) = std::fs::read_to_string("/var/lib/dbus/machine-id") {
            let id = id.trim().to_string();
            if !id.is_empty() {
                return id;
            }
        }
    }

    // macOS: IOPlatformUUID
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                if line.contains("IOPlatformUUID") {
                    // Line looks like: "IOPlatformUUID" = "XXXXXXXX-XXXX-..."
                    let parts: Vec<&str> = line.splitn(2, '=').collect();
                    if let Some(val) = parts.get(1) {
                        let trimmed = val.trim().trim_matches('"');
                        if !trimmed.is_empty() {
                            return trimmed.to_string();
                        }
                    }
                }
            }
        }
    }

    // Universal fallback: hash of COMPUTERNAME (Windows) or HOSTNAME env var.
    // Not as stable as a proper machine UUID but better than nothing.
    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".to_string());
    let hash_bytes = ego_core::hash_data(hostname.as_bytes());
    hex::encode(&hash_bytes.as_bytes()[..8]) // 16 hex chars
}

// ── PoC event recording ───────────────────────────────────────────────────────

fn quality_str(q: &NetworkQuality) -> &'static str {
    match q {
        NetworkQuality::Excellent => "Excellent",
        NetworkQuality::Good      => "Good",
        NetworkQuality::Fair      => "Fair",
        NetworkQuality::Poor      => "Poor",
        NetworkQuality::Offline   => "Offline",
    }
}

/// Derive a pseudo H3-style cell hex from lat/lon (same formula as frontend).
fn derive_h3_cell(lat: f64, lon: f64) -> String {
    let a = (lat.abs() * 1_000.0).round() as u64;
    let b = (lon.abs() * 1_000.0).round() as u64;
    let n = a.wrapping_mul(180_000).wrapping_add(b) & 0xFFFF_FFFF;
    format!("892{:09x}ff", n % 1_000_000_000)
}

/// Append a PoC event to the wallet's poc_events.json if ≥240 s have elapsed
/// since the last recorded event. Safe to call on every page visit.
fn maybe_record_poc_event(status: &CoverageStatus) {
    let now    = chrono::Utc::now().timestamp();
    let mut events = crate::ledger::load_poc_events();

    let should_record = events.last()
        .map(|e| now - e.timestamp >= 240)
        .unwrap_or(true);

    if !should_record {
        return;
    }

    let quality = quality_str(&status.network_quality);

    // Per-event reward: 8 EGOC/day ÷ 360 events ≈ 22 222 uEGOC
    let reward_uegoc: u64 = match quality {
        "Excellent" => 22_222,
        "Good"      => 18_518,
        "Fair"      => 14_814,
        _           => 11_111,
    };

    // Solo node — no real peers on the network yet.
    let peers: u32 = 0;

    let h3_cell = status.location.as_ref().map(|loc| derive_h3_cell(loc.latitude, loc.longitude));

    let next_id = events.last().map(|e| e.id + 1).unwrap_or(0);

    events.push(crate::ledger::PocEvent {
        id: next_id,
        timestamp: now,
        quality: quality.to_string(),
        peers,
        reward_uegoc,
        h3_cell,
    });

    // Keep at most 200 events on disk
    if events.len() > 200 {
        let drain = events.len() - 200;
        events.drain(0..drain);
    }

    let _ = crate::ledger::save_poc_events(&events);
}

// ── Commands ──────────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn get_coverage_status(
    state: State<'_, AppState>,
) -> Result<CoverageStatus, EgoDesktopError> {
    // Check cache first to avoid hammering ip-api.com on every page visit.
    let cached = {
        let cache = state.cache.lock().unwrap();
        cache.coverage_status.clone()
    };

    let status = if let Some(s) = cached {
        s
    } else {
        let machine_id  = get_machine_id();
        let ledger      = crate::ledger::Ledger::load();
        let node_active = !ledger.address.is_empty();

        let (location, vpn_detected, vpn_reason) = fetch_ip_data().await;
        let is_online = node_active && !vpn_detected;

        let s = CoverageStatus {
            location,
            coverage_synced_count: if is_online { 1 } else { 0 },
            last_coverage_event: if is_online {
                Some(chrono::Utc::now().timestamp())
            } else {
                None
            },
            is_online,
            network_quality: if is_online {
                NetworkQuality::Excellent
            } else {
                NetworkQuality::Offline
            },
            vpn_detected,
            vpn_reason,
            machine_id,
        };

        state.update_coverage_status(s.clone());
        s
    };

    // Record a real PoC event (throttled to one per 240 s) if coverage is up.
    if status.is_online {
        maybe_record_poc_event(&status);
    }

    Ok(status)
}

/// Return stored PoC events for this wallet, newest-first, capped at 100.
#[tauri::command]
pub fn get_poc_events() -> Vec<crate::ledger::PocEvent> {
    let mut events = crate::ledger::load_poc_events();
    events.reverse();
    events.truncate(100);
    events
}

/// Fetch IP geolocation + proxy/hosting flags from ip-api.com (free tier).
/// Returns (location, vpn_detected, reason_string).
async fn fetch_ip_data() -> (Option<Location>, bool, String) {
    let url = "http://ip-api.com/json?fields=status,lat,lon,city,regionName,country,isp,org,proxy,hosting";

    let resp = match reqwest::get(url).await {
        Ok(r)  => r,
        Err(_) => return (None, false, String::new()),
    };

    let data = match resp.json::<IpApiResponse>().await {
        Ok(d)  => d,
        Err(_) => return (None, false, String::new()),
    };

    if data.status != "success" {
        return (None, false, String::new());
    }

    let location = match (data.lat, data.lon) {
        (Some(lat), Some(lon)) => Some(Location {
            latitude:  lat,
            longitude: lon,
            accuracy:  Some(15_000.0), // IP geolocation ~1–15 km
            altitude:  None,
            city:      data.city.clone(),
            region:    data.region_name.clone(),
            country:   data.country.clone(),
        }),
        _ => None,
    };

    let (vpn_detected, vpn_reason) = match detect_vpn(&data) {
        Some(reason) => (true, reason),
        None         => (false, String::new()),
    };

    (location, vpn_detected, vpn_reason)
}


/// Return all peer nodes seen via P2P PeerAnnounce within the last 5 minutes.
#[tauri::command]
pub async fn get_network_peers(
    state: State<'_, AppState>,
) -> Result<Vec<crate::app::PeerInfo>, EgoDesktopError> {
    Ok(state.get_active_peers(300))
}
