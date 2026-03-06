use crate::app::{AppState, CoverageStatus, Location, NetworkQuality};
use crate::error::EgoDesktopError;
use serde::Deserialize;
use tauri::State;

// ── ip-api.com extended response ──────────────────────────────────────────────

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
    proxy: Option<bool>,
    hosting: Option<bool>,
}

// ── VPN / proxy keyword blocklist ─────────────────────────────────────────────

const VPN_KEYWORDS: &[&str] = &[
    "nordvpn", "expressvpn", "mullvad", "surfshark", "privatevpn",
    "cyberghost", "ipvanish", "purevpn", "protonvpn", "windscribe",
    "tunnelbear", "hotspot shield", "private internet access", "pia vpn",
    "torguard", "zenmate", "hide.me", "astrill", "ivpn", "ovpn",
    "hidemyass", "hma", "perfect privacy", "strongvpn", "vyprvpn",
    "avast vpn", "avg vpn", "norton vpn", "f-secure vpn", "bitdefender vpn",
    "vpn", "proxy", "anonymizer", "anonymiser", "tor exit", "tor relay",
    "socks", "openvpn", "wireguard relay",
    "datacamp", "m247", "leaseweb", "quadranet", "serverius",
    "choopa", "vultr", "linode", "akamai", "fastly",
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
    if resp.proxy.unwrap_or(false) {
        return Some("IP flagged as proxy/VPN by ip-api.com".to_string());
    }
    if resp.hosting.unwrap_or(false) {
        return Some(format!(
            "IP belongs to a datacenter/hosting provider (ISP: {})",
            resp.isp.as_deref().unwrap_or("unknown")
        ));
    }
    vpn_keyword_match(resp)
}

// ── Machine fingerprint ───────────────────────────────────────────────────────

fn get_machine_id() -> String {
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("reg")
            .args(["query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"])
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

    #[cfg(target_os = "linux")]
    {
        for path in &["/etc/machine-id", "/var/lib/dbus/machine-id"] {
            if let Ok(id) = std::fs::read_to_string(path) {
                let id = id.trim().to_string();
                if !id.is_empty() { return id; }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                if line.contains("IOPlatformUUID") {
                    let parts: Vec<&str> = line.splitn(2, '=').collect();
                    if let Some(val) = parts.get(1) {
                        let trimmed = val.trim().trim_matches('"');
                        if !trimmed.is_empty() { return trimmed.to_string(); }
                    }
                }
            }
        }
    }

    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".to_string());
    let hash_bytes = ego_core::hash_data(hostname.as_bytes());
    hex::encode(&hash_bytes.as_bytes()[..8])
}

// ── Network quality from peer count ──────────────────────────────────────────

/// Derive network quality from how many live peers we can see.
/// 0 peers = Offline (no P2P neighbours found yet).
/// The thresholds are intentionally low for an early network.
fn quality_from_peers(peer_count: usize, base_online: bool) -> NetworkQuality {
    if !base_online { return NetworkQuality::Offline; }
    match peer_count {
        0           => NetworkQuality::Fair,      // online but isolated
        1..=2       => NetworkQuality::Good,
        3..=4       => NetworkQuality::Good,
        _           => NetworkQuality::Excellent,
    }
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

fn derive_h3_cell(lat: f64, lon: f64) -> String {
    let a = (lat.abs() * 1_000.0).round() as u64;
    let b = (lon.abs() * 1_000.0).round() as u64;
    let n = a.wrapping_mul(180_000).wrapping_add(b) & 0xFFFF_FFFF;
    format!("892{:09x}ff", n % 1_000_000_000)
}

fn maybe_record_poc_event(status: &CoverageStatus) {
    let now    = chrono::Utc::now().timestamp();
    let mut events = crate::ledger::load_poc_events();

    let should_record = events.last()
        .map(|e| now - e.timestamp >= 240)
        .unwrap_or(true);

    if !should_record { return; }

    let quality = quality_str(&status.network_quality);

    let reward_uegoc: u64 = match quality {
        "Excellent" => 22_222,
        "Good"      => 18_518,
        "Fair"      => 14_814,
        _           => 11_111,
    };

    // FIX: use the real peer count from coverage_synced_count
    let peers = status.coverage_synced_count;

    let h3_cell = status.location.as_ref()
        .map(|loc| derive_h3_cell(loc.latitude, loc.longitude));

    let next_id = events.last().map(|e| e.id + 1).unwrap_or(0);

    events.push(crate::ledger::PocEvent {
        id: next_id,
        timestamp: now,
        quality: quality.to_string(),
        peers,
        reward_uegoc,
        h3_cell,
    });

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
    // ── FIX: always fetch live peer count — don't rely on stale cache for this.
    // The cache is only used for the IP geolocation part (expensive HTTP call).
    // Peer count changes every few seconds and must be read fresh every call.

    let machine_id  = get_machine_id();
    let ledger      = crate::ledger::Ledger::load();
    let node_active = !ledger.address.is_empty();

    // ── FIX: read active peers from AppState (populated by P2P PeerAnnounce).
    // active_peers_count uses a 300-second window — same as get_network_peers.
    // "seen in last 5 minutes" is a reasonable definition of "online peer".
    let active_peers = state.get_active_peers(300);
    let peer_count   = active_peers.len();

    // Also count approved contacts whose endpoint we know, as a fallback for
    // peers that haven't sent a PeerAnnounce yet this session.
    let contact_count = {
        let contacts = crate::commands::messenger::load_contacts();
        contacts.iter()
            .filter(|c| c.status == "approved" && !c.endpoint.is_empty())
            .count()
    };

    // Use whichever is larger — live PeerAnnounce beats stale contact list,
    // but the contact list ensures we don't show 0 if the peer hasn't announced yet.
    let visible_peers = peer_count.max(contact_count);

    // IP geolocation: use cache if available (avoid hammering ip-api.com)
    let (location, vpn_detected, vpn_reason) = {
        let cached_loc = {
            let cache = state.cache.lock().unwrap();
            cache.coverage_status.as_ref().map(|s| (
                s.location.clone(),
                s.vpn_detected,
                s.vpn_reason.clone(),
            ))
        };
        if let Some(cached) = cached_loc {
            cached
        } else {
            fetch_ip_data().await
        }
    };

    let is_online = node_active && !vpn_detected;

    // ── FIX: coverage_synced_count = real visible peer count, not hardcoded 1
    let coverage_synced_count = if is_online { visible_peers as u32 } else { 0u32 };

    // ── FIX: network quality derived from actual peer count
    let network_quality = quality_from_peers(visible_peers, is_online);

    let s = CoverageStatus {
        location,
        // How many peer nodes this node can currently see
        coverage_synced_count,
        last_coverage_event: if is_online {
            Some(chrono::Utc::now().timestamp())
        } else {
            None
        },
        is_online,
        network_quality,
        vpn_detected,
        vpn_reason,
        machine_id,
    };

    // Update cache so the IP geolocation part is reused next call
    state.update_coverage_status(s.clone());

    if s.is_online {
        maybe_record_poc_event(&s);
    }

    Ok(s)
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
            accuracy:  Some(15_000.0),
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