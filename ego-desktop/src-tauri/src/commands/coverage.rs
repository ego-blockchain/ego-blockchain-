use crate::app::{AppState, CoverageStatus, Location, NetworkQuality};
use crate::error::EgoDesktopError;
use once_cell::sync::OnceCell;
use serde::Deserialize;
use tauri::{Manager, State};

static MACHINE_ID: OnceCell<String> = OnceCell::new();

fn cached_machine_id() -> String {
    MACHINE_ID.get_or_init(get_machine_id).clone()
}

#[derive(Deserialize)]
struct IpApiResponse {
    status: String,
    /// The public IP address — used to detect network/VPN changes between ticks.
    #[serde(rename = "query")]
    query: Option<String>,
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

const VPN_KEYWORDS: &[&str] = &[
    "nordvpn", "expressvpn", "mullvad", "surfshark", "privatevpn",
    "cyberghost", "ipvanish", "purevpn", "protonvpn", "windscribe",
    "tunnelbear", "hotspot shield", "private internet access", "pia vpn",
    "torguard", "zenmate", "hide.me", "astrill", "ivpn", "ovpn",
    "hidemyass", "hma", "perfect privacy", "strongvpn", "vyprvpn",
    "avast vpn", "avg vpn", "norton vpn", "f-secure vpn", "bitdefender vpn",
    "anonymizer", "anonymiser", "tor exit", "tor relay",
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
    vpn_keyword_match(resp)
}

fn get_machine_id() -> String {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        if let Ok(output) = std::process::Command::new("reg")
            .args(["query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"])
            .creation_flags(CREATE_NO_WINDOW)
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

fn quality_from_peers(peer_count: usize, base_online: bool) -> NetworkQuality {
    if !base_online { return NetworkQuality::Offline; }
    match peer_count {
        0     => NetworkQuality::Fair,
        1..=2 => NetworkQuality::Good,
        3..=4 => NetworkQuality::Good,
        _     => NetworkQuality::Excellent,
    }
}

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
    let peers   = status.coverage_synced_count;
    // Continuous reward: 11,111 base + 1,500 per witnessed peer, cap 44,444 (~22 peers).
    // This makes every additional peer genuinely worth more reward rather than
    // jumping between a few fixed tiers.
    const BASE:       u64 = 11_111;
    const PER_PEER:   u64 = 1_500;
    const MAX_REWARD: u64 = 44_444;
    let reward_uegoc: u64 = (BASE + (peers as u64) * PER_PEER).min(MAX_REWARD);
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
    tokio::time::sleep(std::time::Duration::from_secs(8)).await;

    // Initial IP/VPN fetch.
    let (init_loc, init_vpn, init_reason, init_ip) = fetch_ip_data().await;
    let mut location     = init_loc;
    let mut vpn_detected = init_vpn;
    let mut vpn_reason   = init_reason;
    let mut last_ip      = init_ip;

    // Store initial state in AppState.
    {
        let state = app.state::<AppState>();
        let machine_id  = cached_machine_id();
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

    // Re-check VPN every tick (60 s). Catches enabling/disabling VPN while the app is open.
    let mut tick: u32 = 0;
    loop {
        let recheck = tick > 0;
        if recheck {
            let (new_loc, new_vpn, new_reason, new_ip) = fetch_ip_data().await;

            let ip_changed  = !new_ip.is_empty() && new_ip != last_ip;
            let vpn_changed = new_vpn != vpn_detected;

            if new_loc.is_some() { location = new_loc; }
            vpn_detected = new_vpn;
            vpn_reason   = new_reason;
            if !new_ip.is_empty() { last_ip = new_ip; }

            if ip_changed || vpn_changed {
                eprintln!(
                    "[Coverage] Network change detected — IP changed: {}, VPN: {} ({})",
                    ip_changed, vpn_detected, vpn_reason
                );
                // Emit immediately so the UI updates without waiting for the next tick.
                let _ = app.emit_all("ego://vpn-status-changed", serde_json::json!({
                    "vpn_detected": vpn_detected,
                    "vpn_reason":   &vpn_reason,
                }));
            }
        }

        tick_coverage(&app, &location, vpn_detected, &vpn_reason).await;
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        tick += 1;
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
    let machine_id  = cached_machine_id();
    let is_online   = node_active && !vpn_detected;

    // ── Step 1: probe known peers from relay directory ─────────────────────
    // Fetches latest endpoints from relay HTTP API and sends each peer a
    // PeerListRequest so they announce back to us. This actively discovers
    // new nodes even if they haven't sent a PeerAnnounce to us yet.
    if is_online {
        probe_peers_from_relay(app).await;
    }

    if is_online {
        crate::p2p::broadcast_peer_announce(Some(app)).await;
    }

    let active_peers = state.get_active_peers(600);
    let peer_count   = active_peers.len();

    let coverage_synced_count = if is_online { peer_count as u32 } else { 0 };
    let network_quality       = quality_from_peers(peer_count, is_online);
    let network_quality_str   = quality_str(&network_quality);

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

    state.update_coverage_status(status.clone());
    let _ = app.emit_all("ego://coverage-updated", ());

    if is_online {
        maybe_record_poc_event(&status);
        eprintln!(
            "[Coverage] tick — peers: {}, quality: {}, PoC eligible",
            peer_count,
            network_quality_str
        );
    }
}

async fn probe_peers_from_relay(app: &tauri::AppHandle) {

    crate::p2p::dht_discover_peers().await;

    let state        = app.state::<AppState>();
    let my_endpoint  = crate::p2p::get_public_endpoint().await;
    let active_peers = state.get_active_peers(300);
    let active_eps:  std::collections::HashSet<String> =
        active_peers.iter().map(|p| p.endpoint.clone()).collect();

    let contacts = crate::commands::messenger::load_contacts();

    let mut candidates: Vec<String> = Vec::new();
    for p in &crate::p2p::load_peer_cache() {
        if !p.endpoint.is_empty() && p.endpoint != my_endpoint {
            candidates.push(p.endpoint.clone());
        }
    }
    for c in &contacts {
        if c.status == "approved" && !c.endpoint.is_empty() && c.endpoint != my_endpoint {
            if !candidates.contains(&c.endpoint) {
                candidates.push(c.endpoint.clone());
            }
        }
    }

    // Cap probe concurrency — prevent spawning one task per node at millions-of-nodes scale.
    const MAX_PROBE_CONCURRENT: usize = 32;
    let requester_endpoint = my_endpoint.clone();
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_PROBE_CONCURRENT));

    for endpoint in candidates.into_iter().take(256) {
        if active_eps.contains(&endpoint) { continue; }
        let ep   = endpoint.clone();
        let req  = crate::p2p::P2PMessage::PeerListRequest {
            requester_endpoint: requester_endpoint.clone(),
        };
        let sem2 = sem.clone();
        tokio::spawn(async move {
            let _permit = sem2.acquire().await;
            if let Err(e) = crate::p2p::send_message(&ep, &req).await {
                let msg = e.to_string();
                if !msg.contains("none of the requested protocols") {
                    eprintln!("[Coverage] probe {}: {}", ep, e);
                }
            }
        });
    }
}

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

    let ledger     = crate::ledger::Ledger::load();
    let machine_id = cached_machine_id();
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
    Ok(state.get_active_peers(600))
}

// ── IP geolocation — called on startup and re-checked every 5 min ─────────────

/// Returns (location, vpn_detected, vpn_reason, public_ip).
async fn fetch_ip_data() -> (Option<Location>, bool, String, String) {
    let url = "http://ip-api.com/json?fields=status,query,lat,lon,city,regionName,country,isp,org,proxy,hosting";
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c)  => c,
        Err(_) => return (None, false, String::new(), String::new()),
    };
    let resp = match client.get(url).send().await {
        Ok(r)  => r,
        Err(_) => return (None, false, String::new(), String::new()),
    };
    let data = match resp.json::<IpApiResponse>().await {
        Ok(d)  => d,
        Err(_) => return (None, false, String::new(), String::new()),
    };
    if data.status != "success" {
        return (None, false, String::new(), String::new());
    }
    let public_ip = data.query.clone().unwrap_or_default();
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
    (location, vpn_detected, vpn_reason, public_ip)
}
