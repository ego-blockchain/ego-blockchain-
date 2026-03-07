use crate::app::{AppState, CoverageStatus, Location, NetworkQuality};
use crate::error::EgoDesktopError;
use serde::Deserialize;
use tauri::{Manager, State};

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

fn quality_from_peers(peer_count: usize, base_online: bool) -> NetworkQuality {
    if !base_online { return NetworkQuality::Offline; }
    match peer_count {
        0     => NetworkQuality::Fair,
        1..=2 => NetworkQuality::Good,
        3..=4 => NetworkQuality::Good,
        _     => NetworkQuality::Excellent,
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

    let quality      = quality_str(&status.network_quality);
    let reward_uegoc: u64 = match quality {
        "Excellent" => 22_222,
        "Good"      => 18_518,
        "Fair"      => 14_814,
        _           => 11_111,
    };
    let peers   = status.coverage_synced_count;
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

// ── Background coverage loop ──────────────────────────────────────────────────
//
// Runs forever in its own Tokio task (started from main.rs setup).
// Ticks every 60 seconds regardless of whether the window is visible.
// This is the ONLY place that calls maybe_record_poc_event and probe_peers
// so PoC rewards and peer discovery continue when the app is minimized.
//
// Why 60 s?  PoC events require 240 s between them, so 60 s gives us
// 4 checks per window — enough resolution without hammering the relay.
pub async fn run_background_coverage_loop(app: tauri::AppHandle) {
    // Wait for relay circuit to be confirmed before first probe.
    // This prevents a flood of failed dials on startup.
    tokio::time::sleep(std::time::Duration::from_secs(8)).await;

    // Fetch IP data once — it changes rarely, no need to re-fetch every tick.
    let (location, vpn_detected, vpn_reason) = fetch_ip_data().await;

    // Store in AppState so UI polls can use it without an HTTP call.
    {
        let state = app.state::<AppState>();
        let machine_id  = get_machine_id();
        let ledger      = crate::ledger::Ledger::load();
        let node_active = !ledger.address.is_empty();
        let is_online   = node_active && !vpn_detected;
        let placeholder = CoverageStatus {
            location:              location.clone(),
            coverage_synced_count: 0,
            last_coverage_event:   None,
            is_online,
            network_quality:       if is_online { NetworkQuality::Fair } else { NetworkQuality::Offline },
            vpn_detected,
            vpn_reason:            vpn_reason.clone(),
            machine_id,
        };
        state.update_coverage_status(placeholder);
    }

    loop {
        tick_coverage(&app, &location, vpn_detected, &vpn_reason).await;
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
}

/// One coverage tick: probe peers, count, record PoC event, announce.
async fn tick_coverage(
    app:          &tauri::AppHandle,
    location:     &Option<Location>,
    vpn_detected: bool,
    vpn_reason:   &str,
) {
    let state = app.state::<AppState>();

    let ledger      = crate::ledger::Ledger::load();
    let node_active = !ledger.address.is_empty();
    let machine_id  = get_machine_id();
    let is_online   = node_active && !vpn_detected;

    // ── Step 1: probe known peers from relay directory ─────────────────────
    // Fetches latest endpoints from relay HTTP API and sends each peer a
    // PeerListRequest so they announce back to us. This actively discovers
    // new nodes even if they haven't sent a PeerAnnounce to us yet.
    if is_online {
        probe_peers_from_relay(app).await;
    }

    // ── Step 2: count live peers ───────────────────────────────────────────
    let active_peers = state.get_active_peers(300);
    let peer_count   = active_peers.len();

    let contact_count = {
        let contacts = crate::commands::messenger::load_contacts();
        contacts.iter()
            .filter(|c| c.status == "approved" && !c.endpoint.is_empty())
            .count()
    };
    let visible_peers = peer_count.max(contact_count);

    let coverage_synced_count = if is_online { visible_peers as u32 } else { 0 };
    let network_quality       = quality_from_peers(visible_peers, is_online);

    let status = CoverageStatus {
        location:             location.clone(),
        coverage_synced_count,
        last_coverage_event:  if is_online { Some(chrono::Utc::now().timestamp()) } else { None },
        is_online,
        network_quality,
        vpn_detected,
        vpn_reason:           vpn_reason.to_string(),
        machine_id,
    };

    // ── Step 3: update AppState so UI reads fresh data ─────────────────────
    state.update_coverage_status(status.clone());
    let _ = app.emit_all("ego://coverage-updated", ());

    // ── Step 4: record PoC event (rate-limited to 1 per 240 s internally) ──
    if is_online {
        maybe_record_poc_event(&status);
        eprintln!(
            "[Coverage] tick — peers: {}, quality: {}, PoC eligible",
            visible_peers,
            quality_str(&network_quality)
        );
    }
}

/// Fetch peer list from relay HTTP directory, update AppState, then send
/// PeerListRequest to any peer we don't currently have in active peers.
/// This actively recruits nodes that are online but haven't announced to us yet.
async fn probe_peers_from_relay(app: &tauri::AppHandle) {
    // Pull fresh endpoints from relay directory
    crate::p2p::fetch_peers_from_relay(app).await;

    let state        = app.state::<AppState>();
    let my_endpoint  = crate::p2p::get_public_endpoint().await;
    let active_peers = state.get_active_peers(300);
    let active_eps:  std::collections::HashSet<String> =
        active_peers.iter().map(|p| p.endpoint.clone()).collect();

    // Also load contacts — they might have relay circuit addresses
    let contacts = crate::commands::messenger::load_contacts();

    // Combine relay-directory peers + contacts into a candidate list
    let mut candidates: Vec<String> = Vec::new();

    // From AppState (populated by fetch_peers_from_relay)
    let all_known = state.get_active_peers(86_400); // last 24h, not just 5min
    for p in &all_known {
        if !p.endpoint.is_empty() && p.endpoint != my_endpoint {
            candidates.push(p.endpoint.clone());
        }
    }
    // From contacts
    for c in &contacts {
        if c.status == "approved" && !c.endpoint.is_empty() && c.endpoint != my_endpoint {
            if !candidates.contains(&c.endpoint) {
                candidates.push(c.endpoint.clone());
            }
        }
    }

    // Send PeerListRequest to every candidate not already active.
    // This causes them to reply with PeerListResponse → we learn their
    // current endpoint, and they get our endpoint too via PeerAnnounce.
    let requester_endpoint = my_endpoint.clone();
    for endpoint in candidates {
        if active_eps.contains(&endpoint) { continue; } // already talking
        let ep  = endpoint.clone();
        let req = crate::p2p::P2PMessage::PeerListRequest {
            requester_endpoint: requester_endpoint.clone(),
        };
        tokio::spawn(async move {
            if let Err(e) = crate::p2p::send_message(&ep, &req).await {
                eprintln!("[Coverage] probe {}: {}", ep, e);
            }
        });
    }
}

// ── Commands (called by UI) ───────────────────────────────────────────────────
//
// These now just READ from the AppState cache that the background loop keeps
// fresh. No blocking HTTP calls, no peer counting inline — just a cache read.

#[tauri::command]
pub async fn get_coverage_status(
    state: State<'_, AppState>,
) -> Result<CoverageStatus, EgoDesktopError> {
    // Return what the background loop last computed.
    // If the loop hasn't run yet (first few seconds), compute once inline.
    let cached = {
        let cache = state.cache.lock().unwrap();
        cache.coverage_status.clone()
    };

    if let Some(status) = cached {
        return Ok(status);
    }

    // First-call fallback: background loop hasn't ticked yet.
    // Return a minimal status so the UI isn't blank.
    let ledger     = crate::ledger::Ledger::load();
    let machine_id = get_machine_id();
    Ok(CoverageStatus {
        location:              None,
        coverage_synced_count: 0,
        last_coverage_event:   None,
        is_online:             !ledger.address.is_empty(),
        network_quality:       NetworkQuality::Fair,
        vpn_detected:          false,
        vpn_reason:            String::new(),
        machine_id,
    })
}

#[tauri::command]
pub fn get_poc_events() -> Vec<crate::ledger::PocEvent> {
    let mut events = crate::ledger::load_poc_events();
    events.reverse();
    events.truncate(100);
    events
}

#[tauri::command]
pub async fn get_network_peers(
    state: State<'_, AppState>,
) -> Result<Vec<crate::app::PeerInfo>, EgoDesktopError> {
    Ok(state.get_active_peers(300))
}

// ── IP geolocation (called once on startup, cached) ──────────────────────────

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