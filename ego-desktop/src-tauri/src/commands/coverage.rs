use crate::app::{AppState, CoverageStatus, Location, NetworkQuality};
use crate::error::EgoDesktopError;
use once_cell::sync::OnceCell;
use serde::Deserialize;
use tauri::{Manager, State};

static MACHINE_ID: OnceCell<String> = OnceCell::new();

pub fn get_machine_id_cached() -> String {
    MACHINE_ID.get_or_init(get_machine_id).clone()
}

fn cached_machine_id() -> String {
    get_machine_id_cached()
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

pub const NET_VERIFIED_FOR_SECS: i64 = 24 * 3600;

struct NetCheck {
    blocked: bool,
    reason: String,
    verified_at: i64,
}

static NET_CHECK: std::sync::Mutex<NetCheck> =
    std::sync::Mutex::new(NetCheck { blocked: false, reason: String::new(), verified_at: 0 });

fn record_net_check(blocked: bool, reason: &str) {
    let mut s = NET_CHECK.lock().unwrap_or_else(|e| e.into_inner());
    s.blocked = blocked;
    s.reason = reason.to_string();
    s.verified_at = chrono::Utc::now().timestamp();
}

fn net_block_reason(blocked: bool, reason: &str, verified_at: i64, now: i64) -> Option<String> {
    if verified_at == 0 || now - verified_at > NET_VERIFIED_FOR_SECS {
        return Some("Ego could not check your internet connection".to_string());
    }
    blocked.then(|| if reason.is_empty() { "VPN, proxy or datacenter connection".to_string() } else { reason.to_string() })
}

pub fn earning_block_reason() -> Option<String> {
    if crate::genesis::is_member(&crate::ledger::Ledger::load().address) {
        return None;
    }
    let s = NET_CHECK.lock().unwrap_or_else(|e| e.into_inner());
    net_block_reason(s.blocked, &s.reason, s.verified_at, chrono::Utc::now().timestamp())
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

pub fn derive_h3_cell(lat: f64, lon: f64) -> String {
    let a = (lat.abs() * 1_000.0).round() as u64;
    let b = (lon.abs() * 1_000.0).round() as u64;
    let n = a.wrapping_mul(180_000).wrapping_add(b) & 0xFFFF_FFFF;
    format!("892{:09x}ff", n % 1_000_000_000)
}

async fn submit_coverage_proof(challenge_height: u64, cell: String, records: Vec<crate::poc::PocWitnessRecord>) {
    static LAST_SENT: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
    const MIN_INTERVAL_SECS: i64 = 3_600;
    let now = chrono::Utc::now().timestamp();
    if now - LAST_SENT.load(std::sync::atomic::Ordering::Relaxed) < MIN_INTERVAL_SECS {
        return;
    }
    let me = crate::ledger::Ledger::load().address;
    if me.is_empty() || !crate::chain_db::is_registered_node(&me) {
        return;
    }
    let tip = crate::chain_db::local_chain_height();
    if tip.saturating_add(1) >= crate::chain_db::CHECKIN_FROM_HEIGHT {
        return;
    }
    if tip.saturating_sub(challenge_height) > crate::coverage_proof::CHALLENGE_MAX_AGE * 4 / 5 {
        eprintln!("[PoC] coverage proof not sent: its beacon is already {} blocks old", tip.saturating_sub(challenge_height));
        return;
    }
    let mut machines: std::collections::HashSet<String> = Default::default();
    let mut seen: std::collections::HashSet<String> = Default::default();
    let witnesses: Vec<crate::coverage_proof::CoverageWitness> = records
        .into_iter()
        .filter(|r| r.witness != me && crate::chain_db::is_registered_node(&r.witness))
        .filter(|r| seen.insert(r.witness.clone()))
        .filter(|r| r.machine_id.trim().is_empty() || machines.insert(r.machine_id.clone()))
        .filter_map(|r| {
            let pk = crate::p2p::get_peer_ed25519_pubkey(&r.witness)?;
            Some(crate::coverage_proof::CoverageWitness {
                address: r.witness,
                ed25519_pubkey: hex::encode(pk),
                machine_id: r.machine_id,
                cell: r.cell,
                latency_ms: r.latency_ms,
                rssi_dbm: r.rssi_dbm,
                timestamp: r.timestamp,
                signature: r.signature,
            })
        })
        .take(crate::coverage_proof::MAX_WITNESSES)
        .collect();
    if witnesses.is_empty() {
        return;
    }
    let count = witnesses.len();
    let body = crate::coverage_proof::PocProofBody { challenge_height, cell, witnesses };
    let Ok(call_args) = serde_json::to_string(&body) else { return };
    let tx = crate::ledger::LedgerTx {
        to: me.clone(),
        amount: 0,
        tx_type: crate::coverage_proof::POC_PROOF_TX.to_string(),
        memo: Some("poc_proof".into()),
        call_args,
        ..Default::default()
    };
    match crate::commands::direct_pay::submit_own(tx).await {
        Ok(hash) => {
            LAST_SENT.store(now, std::sync::atomic::Ordering::Relaxed);
            eprintln!("[PoC] coverage proof with {count} witness(es) sent on chain ({:.12})", hash);
        }
        Err(e) => eprintln!("[PoC] coverage proof not sent: {e}"),
    }
}

fn maybe_record_poc_event(status: &CoverageStatus, witnesses: Option<Vec<crate::poc::PocWitnessRecord>>) {
    let now    = chrono::Utc::now().timestamp();
    let mut events = crate::ledger::load_poc_events();

    let should_record = events.last()
        .map(|e| now - e.timestamp >= 240)
        .unwrap_or(true);

    if !should_record { return; }

    let quality = quality_str(&status.network_quality);
    // Witness-backed count when signed receipts arrived for our beacon;
    // otherwise fall back to the legacy reachability estimate so nodes
    // surrounded by old builds keep earning until the network upgrades.
    let (peers, witness_addrs): (u32, Vec<String>) = match witnesses {
        Some(w) if !w.is_empty() => (w.len() as u32, w.into_iter().map(|r| r.witness).collect()),
        _ => (status.coverage_synced_count, Vec::new()),
    };
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
        witnesses: witness_addrs,
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
    let machine_id = tokio::task::spawn_blocking(cached_machine_id)
        .await
        .unwrap_or_default();

    // Publish an immediate placeholder so CoveragePage has something real to
    // render before relay/IP discovery completes. Always show Fair (not Offline)
    // here — the real tick at t+8s will determine the true online/offline state.
    // Showing Offline in the placeholder causes a misleading flash whenever the
    // wallet file hasn't been read yet at the exact moment this runs.
    {
        let state = app.state::<AppState>();
        let placeholder = CoverageStatus {
            location:              None,
            coverage_synced_count: 0,
            last_coverage_event:   None,
            is_online:             true,
            network_quality:       NetworkQuality::Fair,
            vpn_detected:          false,
            vpn_reason:            String::new(),
            machine_id:            machine_id.clone(),
        };
        state.update_coverage_status(placeholder);
    }
    let _ = app.emit_all("ego://coverage-updated", ());

    // Wait for relay circuit before first real probe.
    tokio::time::sleep(std::time::Duration::from_secs(8)).await;

    // Initial IP/VPN fetch.
    let (init_loc, _, _, init_ip) = fetch_ip_data().await;
    let init_gate = tokio::task::spawn_blocking(earning_block_reason).await.unwrap_or(None);
    let init_vpn = init_gate.is_some();
    let init_reason = init_gate.unwrap_or_default();
    let mut location     = init_loc;
    let mut vpn_detected = init_vpn;
    let mut vpn_reason   = init_reason;
    let mut last_ip      = init_ip;

    {
        let state = app.state::<AppState>();
        let node_active = tokio::task::spawn_blocking(|| !crate::ledger::Ledger::load().address.is_empty())
            .await
            .unwrap_or(false);
        let is_online = node_active && !vpn_detected;
        let placeholder = CoverageStatus {
            location:              location.clone(),
            coverage_synced_count: 0,
            last_coverage_event:   None,
            is_online,
            network_quality:       if is_online { NetworkQuality::Fair } else { NetworkQuality::Offline },
            vpn_detected,
            vpn_reason:            vpn_reason.clone(),
            machine_id:            machine_id.clone(),
        };
        state.update_coverage_status(placeholder);
    }
    let _ = app.emit_all("ego://coverage-updated", ());

    // Re-check VPN every tick (60 s). Catches enabling/disabling VPN while the app is open.
    let mut tick: u32 = 0;
    loop {
        let recheck = tick > 0;
        if recheck {
            let (new_loc, _, _, new_ip) = fetch_ip_data().await;
            let gate = tokio::task::spawn_blocking(earning_block_reason).await.unwrap_or(None);
            let new_vpn = gate.is_some();
            let new_reason = gate.unwrap_or_default();

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

    let (node_active, machine_id) = tokio::task::spawn_blocking(|| {
        (!crate::ledger::Ledger::load().address.is_empty(), cached_machine_id())
    }).await.unwrap_or((false, String::new()));
    let is_online = node_active && !vpn_detected;

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
        let now = chrono::Utc::now().timestamp();
        let challenge = crate::poc::beacon_challenge();
        if let Some((_beacon_id, records)) = crate::poc::take_beacon_older_than(now - 30) {
            eprintln!("[PoC] beacon finalized — {} signed witness receipt(s)", records.len());
            if let Some(height) = challenge {
                let cell = status.location.as_ref().map(|l| derive_h3_cell(l.latitude, l.longitude)).unwrap_or_default();
                submit_coverage_proof(height, cell, records.clone()).await;
            }
            maybe_record_poc_event(&status, Some(records));
        }
        let last_event_ts = crate::ledger::load_poc_events().last().map(|e| e.timestamp).unwrap_or(0);
        if crate::poc::current_beacon().is_none() && now - last_event_ts >= 180 {
            if crate::p2p::broadcast_poc_beacon().await.is_none() && now - last_event_ts >= 300 {
                maybe_record_poc_event(&status, None);
            }
        }
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
        // Skip relay-circuit endpoints for coverage probes — coverage measures
        // direct reachability. Relay probes also exhaust relay stream limits.
        if endpoint.contains("/p2p-circuit") { continue; }
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
                    tracing::debug!("[Coverage] probe {}: {}", ep, e);
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

    let (node_active, machine_id) = tokio::task::spawn_blocking(|| {
        (!crate::ledger::Ledger::load().address.is_empty(), cached_machine_id())
    }).await.unwrap_or((false, String::new()));
    Ok(CoverageStatus {
        location:              None,
        coverage_synced_count: 0,
        last_coverage_event:   None,
        is_online:             node_active,
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
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    if let Ok(resp) = client.get("http://ip-api.com/json/?fields=status,message,country,regionName,city,lat,lon,isp,org,proxy,hosting,query").send().await {
        if let Ok(data) = resp.json::<IpApiResponse>().await {
            if data.status == "success" {
                let loc = Location {
                    latitude: data.lat.unwrap_or(0.0),
                    longitude: data.lon.unwrap_or(0.0),
                    accuracy: None,
                    altitude: None,
                    city: data.city.clone(),
                    region: data.region_name.clone(),
                    country: data.country.clone(),
                };
                let vpn_reason = detect_vpn(&data);
                let is_vpn = vpn_reason.is_some() || data.proxy.unwrap_or(false) || data.hosting.unwrap_or(false);
                let reason_str = vpn_reason.unwrap_or_else(|| {
                    if data.proxy.unwrap_or(false) { "Proxy detected".to_string() }
                    else if data.hosting.unwrap_or(false) { "Datacenter/Hosting IP".to_string() }
                    else { String::new() }
                });
                record_net_check(is_vpn, &reason_str);
                return (Some(loc), is_vpn, reason_str, data.query.unwrap_or_default());
            }
        }
    }

    let public_ip = crate::p2p::get_public_endpoint().await;
    (None, false, String::new(), public_ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_earns_only_after_a_clean_recent_connection_check() {
        let now = 1_900_000_000;
        assert!(net_block_reason(false, "", 0, now).is_some(), "never checked is not clean");
        assert!(net_block_reason(false, "", now - NET_VERIFIED_FOR_SECS - 1, now).is_some(), "a check older than a day has expired");
        assert_eq!(net_block_reason(false, "", now - 60, now), None, "a clean check from a minute ago passes");
        assert_eq!(net_block_reason(true, "Proxy detected", now - 60, now).as_deref(), Some("Proxy detected"));
        assert!(net_block_reason(true, "", now - 60, now).is_some());
    }
}
