/// Lightweight TCP-based P2P server for real-time contact requests/responses
/// AND transaction / chain-state synchronisation across machines.
///
/// Each Ego Desktop node listens on P2P_PORT.
///
/// Contact pairing
///   A imports B's bundle → sends ContactRequest to B's endpoint.
///   B fires notification + Tauri event.  B approves → ContactResponse → A.
///
/// Transaction propagation
///   After mining a block locally, the sender calls broadcast_tx().
///   Every approved contact receives a TxBroadcast message and merges the
///   tx into their local chain.json so their balance / explorer update live.
///
/// Startup chain sync
///   On launch, sync_chain_from_peers() fires a ChainSyncRequest to every
///   known contact.  Peers reply with their full chain; we merge any missing
///   blocks / txs.

use crate::commands::messenger::{load_contacts, save_contacts, Contact};
use crate::ledger::{base_data_dir, load_chain, save_chain, LedgerBlock, LedgerTx};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tauri::Manager;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub const P2P_PORT: u16 = 47393;
/// UDP port used for LAN broadcast peer discovery (no contacts needed).
const DISCOVERY_PORT: u16 = 47394;
/// 8 MB cap — large enough for a full chain sync response.
const MAX_MSG_BYTES: usize = 8 * 1024 * 1024;

// ── Persistent peer cache ─────────────────────────────────────────────────────

/// A known remote peer (may or may not be a messenger contact).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEntry {
    pub address:   String,
    pub endpoint:  String,
    pub last_seen: i64,
}

fn peer_cache_path() -> std::path::PathBuf {
    base_data_dir().join("peers.json")
}

pub fn load_peer_cache() -> Vec<PeerEntry> {
    let data = std::fs::read_to_string(peer_cache_path()).unwrap_or_default();
    let mut peers: Vec<PeerEntry> = serde_json::from_str(&data).unwrap_or_default();
    let cutoff = Utc::now().timestamp() - 30 * 86_400; // drop peers silent for 30 days
    peers.retain(|p| p.last_seen >= cutoff);
    peers
}

fn save_peer_cache(peers: &[PeerEntry]) {
    if let Ok(data) = serde_json::to_string_pretty(peers) {
        let _ = std::fs::write(peer_cache_path(), data);
    }
}

/// Add or refresh a peer in the persistent cache (keyed by address).
pub fn upsert_peer_cache(entry: PeerEntry) {
    let mut peers = load_peer_cache();
    if let Some(e) = peers.iter_mut().find(|p| p.address == entry.address) {
        e.endpoint  = entry.endpoint;
        e.last_seen = entry.last_seen;
    } else {
        peers.push(entry);
    }
    save_peer_cache(&peers);
}

// ── UPnP / NAT-traversal ─────────────────────────────────────────────────────

/// Try to add a UPnP (IGD) TCP port-mapping on the user's router so that
/// internet peers can connect to us.  Silently ignored if UPnP is unavailable.
pub async fn upnp_map_port() -> Result<(), String> {
    let local_ip_str = get_local_ip();
    let local_ip: std::net::Ipv4Addr = local_ip_str
        .parse()
        .map_err(|e| format!("UPnP: bad local IP {}: {}", local_ip_str, e))?;
    let local_addr = std::net::SocketAddrV4::new(local_ip, P2P_PORT);

    tokio::task::spawn_blocking(move || {
        let gateway = igd::search_gateway(igd::SearchOptions::default())
            .map_err(|e| format!("UPnP: no gateway found: {}", e))?;

        match gateway.add_port(
            igd::PortMappingProtocol::TCP,
            P2P_PORT,
            local_addr,
            0, // 0 = permanent lease
            "Ego Desktop P2P",
        ) {
            Ok(()) => Ok(()),
            // Already mapped from a previous session — treat as success.
            Err(igd::AddPortError::PortInUse) => Ok(()),
            Err(e) => Err(format!("UPnP: add_port: {}", e)),
        }
    })
    .await
    .map_err(|e| format!("UPnP spawn: {}", e))?
}

// ── Public IP detection ───────────────────────────────────────────────────────

/// Detect our real public (internet-routable) IP via a free HTTP service.
/// Returns `None` if offline or the request fails within 5 seconds.
pub async fn get_public_ip() -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;
    let resp = client
        .get("https://api.ipify.org?format=json")
        .send()
        .await
        .ok()?;
    let json: serde_json::Value = resp.json().await.ok()?;
    json["ip"].as_str().map(|s| s.to_string())
}

/// Best available endpoint for sharing with internet peers.
/// Uses public IP when reachable, falls back to LAN IP.
pub async fn get_public_endpoint() -> String {
    match get_public_ip().await {
        Some(ip) => format!("{}:{}", ip, P2P_PORT),
        None     => get_local_endpoint(),
    }
}

// ── Local IP / endpoint ──────────────────────────────────────────────────────

/// Detect the primary outbound local IP using a UDP "connect" trick (no packet sent).
pub fn get_local_ip() -> String {
    if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
        let _ = sock.connect("8.8.8.8:80");
        if let Ok(addr) = sock.local_addr() {
            let ip = addr.ip().to_string();
            if ip != "0.0.0.0" {
                return ip;
            }
        }
    }
    "127.0.0.1".to_string()
}

/// Returns "ip:47393".
pub fn get_local_endpoint() -> String {
    format!("{}:{}", get_local_ip(), P2P_PORT)
}

// ── Wire protocol ────────────────────────────────────────────────────────────
// 4-byte big-endian length prefix + JSON payload.

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum P2PMessage {
    // ── Contact pairing ──────────────────────────────────────────────────────
    /// Sent by A when A imports B's contact bundle and wants to connect.
    ContactRequest {
        from_addr:       String,
        from_name:       String,
        from_ed25519:    String,
        from_kyber:      String,
        /// Fresh AES key generated by A; both sides will use this for encryption.
        from_shared_key: String,
        /// A's own TCP endpoint ("ip:port") so B can reply directly.
        from_endpoint:   String,
    },
    /// Sent by B back to A after approving or declining A's request.
    ContactResponse {
        from_addr:    String,
        from_name:    String,
        from_ed25519: String,
        from_kyber:   String,
        approved:     bool,
        /// The shared_key originally sent by A — used to match A's pending_out.
        shared_key:   String,
    },

    // ── Peer discovery ───────────────────────────────────────────────────────
    /// Periodic heartbeat so every node knows who is online.
    PeerAnnounce {
        address:  String,
        name:     String,
        endpoint: String,
    },

    // ── Chat ─────────────────────────────────────────────────────────────────
    /// An encrypted egomsg1 bundle delivered directly from sender to recipient.
    ChatMessage {
        bundle: String,
    },

    // ── Chain sync ───────────────────────────────────────────────────────────
    /// Broadcast after mining a block so every peer updates their chain.json.
    TxBroadcast {
        tx:    LedgerTx,
        block: LedgerBlock,
    },
    /// Request a peer to send us their full chain (used on startup).
    ChainSyncRequest {
        /// Our endpoint so the peer can open a new connection to reply.
        requester_endpoint: String,
    },
    /// Full chain state — sent in reply to ChainSyncRequest.
    ChainSyncResponse {
        blocks:       Vec<LedgerBlock>,
        transactions: Vec<LedgerTx>,
    },

    // ── Peer gossip (internet-wide discovery) ────────────────────────────────
    /// Ask a peer to send us their known peer list.
    PeerListRequest {
        requester_endpoint: String,
    },
    /// Reply to PeerListRequest — the sender's full known-peer list.
    PeerListResponse {
        peers: Vec<PeerEntry>,
    },
}

// ── Server ───────────────────────────────────────────────────────────────────

/// On Windows, add a firewall inbound rule for the P2P port so remote peers can connect.
/// Silently ignored on non-Windows or if the rule already exists.
#[cfg(target_os = "windows")]
fn add_firewall_rule(name: &str, port: u16, protocol: &str) {
    let check = std::process::Command::new("netsh")
        .args(["advfirewall", "firewall", "show", "rule", &format!("name={}", name)])
        .output();
    if let Ok(out) = check {
        if out.status.success() && !out.stdout.is_empty() {
            return; // already exists
        }
    }
    let _ = std::process::Command::new("netsh")
        .args([
            "advfirewall", "firewall", "add", "rule",
            &format!("name={}", name),
            "dir=in", "action=allow",
            &format!("protocol={}", protocol),
            &format!("localport={}", port),
            "enable=yes", "profile=any",
        ])
        .output();
}

#[cfg(target_os = "windows")]
fn ensure_firewall_rule() {
    add_firewall_rule(&format!("Ego Desktop P2P port {}", P2P_PORT), P2P_PORT, "TCP");
    add_firewall_rule(&format!("Ego Desktop discovery port {}", DISCOVERY_PORT), DISCOVERY_PORT, "UDP");
}

#[cfg(not(target_os = "windows"))]
fn ensure_firewall_rule() {}

pub async fn start_p2p_server(app: tauri::AppHandle) {
    ensure_firewall_rule();

    // Attempt UPnP port mapping so internet peers can reach us.
    // Runs in the background so it doesn't delay server startup.
    let app_for_upnp = app.clone();
    tokio::spawn(async move {
        let upnp_result = upnp_map_port().await;
        let public_ep = get_public_endpoint().await;
        let state = app_for_upnp.state::<crate::app::AppState>();
        state.set_public_endpoint(public_ep.clone());
        match &upnp_result {
            Ok(()) => {
                eprintln!("[P2P] UPnP: port {} mapped — internet-wide P2P enabled ({})", P2P_PORT, public_ep);
                state.set_upnp_status(Ok(()));
            }
            Err(e) => {
                eprintln!(
                    "[P2P] UPnP unavailable ({}). Internet P2P requires manual port forwarding of TCP {} on your router.",
                    e, P2P_PORT
                );
                state.set_upnp_status(Err(e.clone()));
            }
        }
        let _ = app_for_upnp.emit_all("ego://p2p-status-changed", ());
    });

    let listener = match TcpListener::bind(format!("0.0.0.0:{}", P2P_PORT)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[P2P] Cannot bind port {}: {}", P2P_PORT, e);
            return;
        }
    };
    eprintln!("[P2P] Listening on 0.0.0.0:{}", P2P_PORT);

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                eprintln!("[P2P] Connection from {}", peer_addr);
                let app = app.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, app).await {
                        eprintln!("[P2P] Error: {}", e);
                    }
                });
            }
            Err(e) => eprintln!("[P2P] Accept error: {}", e),
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| e.to_string())?;

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MSG_BYTES {
        return Err(format!("Message too large: {} bytes", len));
    }

    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| e.to_string())?;

    let msg: P2PMessage =
        serde_json::from_slice(&buf).map_err(|e| format!("Parse: {}", e))?;

    handle_message(msg, &app).await;
    Ok(())
}

async fn handle_message(msg: P2PMessage, app: &tauri::AppHandle) {
    match msg {
        // ── Incoming contact request (B receives from A) ──────────────────
        P2PMessage::ContactRequest {
            from_addr,
            from_name,
            from_ed25519,
            from_kyber,
            from_shared_key,
            from_endpoint,
        } => {
            let mut contacts = load_contacts();

            // Ignore duplicates
            if contacts.iter().any(|c| c.address == from_addr) {
                return;
            }

            let contact = Contact {
                address:        from_addr.clone(),
                name:           from_name.clone(),
                ed25519_pubkey: from_ed25519,
                kyber_pubkey:   from_kyber,
                shared_key_hex: from_shared_key,
                status:         "pending_in".to_string(),
                added_at:       Utc::now().timestamp(),
                endpoint:       from_endpoint,
            };
            contacts.push(contact.clone());
            let _ = save_contacts(&contacts);

            // OS notification
            let _ = tauri::api::notification::Notification::new(
                &app.config().tauri.bundle.identifier,
            )
            .title("Contact Request")
            .body(&format!("{} wants to connect with you", from_name))
            .show();

            // Tauri event → frontend reloads contact list in real-time
            let _ = app.emit_all("ego://contact-request", &contact);
        }

        // ── Incoming contact response (A receives from B) ─────────────────
        P2PMessage::ContactResponse {
            from_addr,
            from_name,
            from_ed25519,
            from_kyber,
            approved,
            shared_key,
        } => {
            let mut contacts = load_contacts();

            if approved {
                // Match our pending_out by shared_key and promote to approved.
                if let Some(pending) = contacts
                    .iter_mut()
                    .find(|c| c.status == "pending_out" && c.shared_key_hex == shared_key)
                {
                    pending.address        = from_addr.clone();
                    pending.name           = from_name.clone();
                    pending.ed25519_pubkey = from_ed25519;
                    pending.kyber_pubkey   = from_kyber;
                    pending.status         = "approved".to_string();
                    let contact = pending.clone();
                    let _ = save_contacts(&contacts);

                    let _ = tauri::api::notification::Notification::new(
                        &app.config().tauri.bundle.identifier,
                    )
                    .title("Contact Request Accepted!")
                    .body(&format!("{} accepted your request", from_name))
                    .show();

                    let _ = app.emit_all("ego://contact-approved", &contact);
                }
            } else {
                // Remove our pending_out.
                let before = contacts.len();
                contacts
                    .retain(|c| !(c.status == "pending_out" && c.shared_key_hex == shared_key));
                if contacts.len() < before {
                    let _ = save_contacts(&contacts);

                    let _ = tauri::api::notification::Notification::new(
                        &app.config().tauri.bundle.identifier,
                    )
                    .title("Contact Request Declined")
                    .body("Your contact request was declined.")
                    .show();

                    let _ = app.emit_all("ego://contact-declined", ());
                }
            }
        }

        // ── Peer heartbeat ───────────────────────────────────────────────
        P2PMessage::PeerAnnounce { address, name, endpoint } => {
            let now = Utc::now().timestamp();
            let state = app.state::<crate::app::AppState>();
            state.upsert_peer(crate::app::PeerInfo {
                address:   address.clone(),
                name,
                endpoint:  endpoint.clone(),
                last_seen: now,
            });
            // Persist so we can reconnect after restart
            upsert_peer_cache(PeerEntry { address, endpoint, last_seen: now });
        }

        // ── Incoming chat message ─────────────────────────────────────────
        P2PMessage::ChatMessage { bundle } => {
            match crate::commands::messenger::receive_message_inner(&bundle) {
                Ok(msg) => {
                    // OS notification
                    let preview = if msg.content.len() > 40 {
                        format!("{}…", &msg.content[..40])
                    } else {
                        msg.content.clone()
                    };
                    let _ = tauri::api::notification::Notification::new(
                        &app.config().tauri.bundle.identifier,
                    )
                    .title("New Message")
                    .body(&preview)
                    .show();
                    // Tell frontend to refresh chat
                    let _ = app.emit_all("ego://message-received", &msg);
                }
                Err(e) => {
                    eprintln!("[P2P] Could not decrypt incoming chat message: {}", e);
                }
            }
        }

        // ── Incoming transaction broadcast ────────────────────────────────
        P2PMessage::TxBroadcast { tx, block } => {
            apply_incoming_tx(tx, block, app).await;
        }

        // ── Peer requests our full chain ──────────────────────────────────
        P2PMessage::ChainSyncRequest { requester_endpoint } => {
            let chain = load_chain();
            let response = P2PMessage::ChainSyncResponse {
                blocks:       chain.blocks,
                transactions: chain.transactions,
            };
            tokio::spawn(async move {
                if let Err(e) = send_message(&requester_endpoint, &response).await {
                    eprintln!("[P2P] chain sync reply to {}: {}", requester_endpoint, e);
                }
            });
        }

        // ── Peer sent us their full chain ─────────────────────────────────
        P2PMessage::ChainSyncResponse { blocks, transactions } => {
            merge_remote_chain(blocks, transactions, app).await;
        }

        // ── Peer asks for our known-peer list ─────────────────────────────
        P2PMessage::PeerListRequest { requester_endpoint } => {
            // Build combined list: persistent cache + approved contacts
            let mut known = load_peer_cache();
            for c in load_contacts().iter().filter(|c| !c.endpoint.is_empty()) {
                if !known.iter().any(|p| p.address == c.address) {
                    known.push(PeerEntry {
                        address:   c.address.clone(),
                        endpoint:  c.endpoint.clone(),
                        last_seen: Utc::now().timestamp(),
                    });
                }
            }
            let response = P2PMessage::PeerListResponse { peers: known };
            tokio::spawn(async move {
                if let Err(e) = send_message(&requester_endpoint, &response).await {
                    eprintln!("[P2P] peer list reply to {}: {}", requester_endpoint, e);
                }
            });
        }

        // ── We received a peer list — add new peers to cache ──────────────
        P2PMessage::PeerListResponse { peers } => {
            let my_ep = get_public_endpoint().await;
            for peer in peers {
                if peer.endpoint.is_empty() || peer.endpoint == my_ep {
                    continue;
                }
                let is_new = !load_peer_cache().iter().any(|p| p.address == peer.address);
                upsert_peer_cache(PeerEntry {
                    address:   peer.address.clone(),
                    endpoint:  peer.endpoint.clone(),
                    last_seen: Utc::now().timestamp(),
                });
                // Try to reach brand-new peers right away
                if is_new {
                    let ep  = peer.endpoint.clone();
                    let my  = my_ep.clone();
                    tokio::spawn(async move {
                        let msg = P2PMessage::ChainSyncRequest { requester_endpoint: my };
                        if let Err(e) = send_message(&ep, &msg).await {
                            eprintln!("[P2P] probe new peer {}: {}", ep, e);
                        }
                    });
                }
            }
        }
    }
}

// ── Chain helpers ─────────────────────────────────────────────────────────────

/// Apply a single incoming tx+block to our local chain (skip if already present).
async fn apply_incoming_tx(tx: LedgerTx, block: LedgerBlock, app: &tauri::AppHandle) {
    let mut chain = load_chain();
    if chain.transactions.iter().any(|t| t.hash == tx.hash) {
        return; // already have it
    }
    chain.transactions.push(tx);
    chain.blocks.push(block);
    chain.blocks.sort_by_key(|b| b.height);
    let _ = save_chain(&chain);
    // Tell the frontend to refresh balance / explorer / wallet history
    let _ = app.emit_all("ego://chain-updated", ());
}

/// Merge a peer's full chain into ours, adding any txs/blocks we don't have.
async fn merge_remote_chain(
    blocks:       Vec<LedgerBlock>,
    transactions: Vec<LedgerTx>,
    app: &tauri::AppHandle,
) {
    let mut chain   = load_chain();
    let mut changed = false;

    for tx in transactions {
        if !chain.transactions.iter().any(|t| t.hash == tx.hash) {
            chain.transactions.push(tx);
            changed = true;
        }
    }
    for block in blocks {
        if !chain.blocks.iter().any(|b| b.hash == block.hash) {
            chain.blocks.push(block);
            changed = true;
        }
    }

    if changed {
        chain.blocks.sort_by_key(|b| b.height);
        let _ = save_chain(&chain);
        let _ = app.emit_all("ego://chain-updated", ());
    }
}

// ── Public broadcast / sync helpers ──────────────────────────────────────────

/// After mining a block, call this to push the tx to every known contact peer.
pub async fn broadcast_tx(tx: LedgerTx, block: LedgerBlock) {
    let contacts = load_contacts();
    let msg = P2PMessage::TxBroadcast { tx: tx.clone(), block: block.clone() };

    // Send to all known contacts
    for contact in contacts.iter().filter(|c| !c.endpoint.is_empty()) {
        let endpoint  = contact.endpoint.clone();
        let msg_clone = msg.clone();
        tokio::spawn(async move {
            if let Err(e) = send_message(&endpoint, &msg_clone).await {
                eprintln!("[P2P] broadcast_tx to {}: {}", endpoint, e);
            }
        });
    }

    // Also send directly to recipient if they are a known contact
    let recipient_endpoint = contacts
        .iter()
        .find(|c| c.address == tx.to && !c.endpoint.is_empty())
        .map(|c| c.endpoint.clone());

    if let Some(endpoint) = recipient_endpoint {
        let msg_clone = msg.clone();
        tokio::spawn(async move {
            if let Err(e) = send_message(&endpoint, &msg_clone).await {
                eprintln!("[P2P] broadcast_tx to recipient {}: {}", endpoint, e);
            }
        });
    }
}

/// On startup, ask every known peer (contacts + cache) to send us their latest chain.
pub async fn sync_chain_from_peers() {
    let contacts    = load_contacts();
    let my_endpoint = get_public_endpoint().await;
    let msg = P2PMessage::ChainSyncRequest {
        requester_endpoint: my_endpoint.clone(),
    };

    let mut endpoints: Vec<String> = contacts
        .iter()
        .filter(|c| !c.endpoint.is_empty())
        .map(|c| c.endpoint.clone())
        .collect();
    for p in load_peer_cache() {
        if !p.endpoint.is_empty() && !endpoints.contains(&p.endpoint) && p.endpoint != my_endpoint {
            endpoints.push(p.endpoint);
        }
    }

    for endpoint in endpoints {
        let msg_clone = msg.clone();
        tokio::spawn(async move {
            if let Err(e) = send_message(&endpoint, &msg_clone).await {
                eprintln!("[P2P] sync request to {}: {}", endpoint, e);
            }
        });
    }
}

/// Send a PeerListRequest to every known peer so they share their peer tables.
/// Each response grows our cache, making the network self-expanding.
pub async fn gossip_peer_list() {
    let my_endpoint = get_public_endpoint().await;
    let msg = P2PMessage::PeerListRequest {
        requester_endpoint: my_endpoint.clone(),
    };

    let contacts = load_contacts();
    let mut endpoints: Vec<String> = contacts
        .iter()
        .filter(|c| !c.endpoint.is_empty())
        .map(|c| c.endpoint.clone())
        .collect();
    for p in load_peer_cache() {
        if !p.endpoint.is_empty() && !endpoints.contains(&p.endpoint) && p.endpoint != my_endpoint {
            endpoints.push(p.endpoint);
        }
    }

    for endpoint in endpoints {
        let msg_clone = msg.clone();
        tokio::spawn(async move {
            if let Err(e) = send_message(&endpoint, &msg_clone).await {
                eprintln!("[P2P] peer list request to {}: {}", endpoint, e);
            }
        });
    }
}

/// Broadcast our identity to all known peers so they can see us as "online".
/// Called on startup and every 30 s from the background sync loop.
pub async fn broadcast_peer_announce(app: &tauri::AppHandle) {
    let address = {
        let ledger = crate::ledger::Ledger::load();
        ledger.address.clone()
    };
    if address.is_empty() {
        return; // wallet not yet initialised
    }

    let registry  = crate::ledger::load_registry();
    let active_id = crate::ledger::get_active_wallet_id();
    let name = registry.wallets.iter()
        .find(|w| w.id == active_id)
        .map(|w| w.name.clone())
        .unwrap_or_else(|| "Ego Node".to_string());

    let contacts    = load_contacts();
    let my_endpoint = get_public_endpoint().await;

    // Also record ourselves as a peer locally.
    {
        let state = app.state::<crate::app::AppState>();
        state.upsert_peer(crate::app::PeerInfo {
            address:   address.clone(),
            name:      name.clone(),
            endpoint:  my_endpoint.clone(),
            last_seen: Utc::now().timestamp(),
        });
    }

    let msg = P2PMessage::PeerAnnounce { address, name, endpoint: my_endpoint.clone() };

    // Collect all unique endpoints: contacts + peer cache
    let mut endpoints: Vec<String> = contacts
        .iter()
        .filter(|c| !c.endpoint.is_empty())
        .map(|c| c.endpoint.clone())
        .collect();
    for p in load_peer_cache() {
        if !p.endpoint.is_empty() && !endpoints.contains(&p.endpoint) && p.endpoint != my_endpoint {
            endpoints.push(p.endpoint);
        }
    }

    for endpoint in endpoints {
        let msg_clone = msg.clone();
        tokio::spawn(async move {
            if let Err(e) = send_message(&endpoint, &msg_clone).await {
                eprintln!("[P2P] peer announce to {}: {}", endpoint, e);
            }
        });
    }
}

// ── UDP LAN broadcast discovery ───────────────────────────────────────────────

/// Listen for UDP broadcast peer announcements from other Ego nodes on the LAN.
/// Any node that sends an announce is added to active_peers — no contact pairing needed.
pub async fn start_udp_discovery(app: tauri::AppHandle) {
    use tokio::net::UdpSocket;

    let sock = match UdpSocket::bind(format!("0.0.0.0:{}", DISCOVERY_PORT)).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[P2P] UDP discovery bind failed on port {}: {}", DISCOVERY_PORT, e);
            return;
        }
    };
    if let Err(e) = sock.set_broadcast(true) {
        eprintln!("[P2P] UDP set_broadcast failed: {}", e);
    }
    eprintln!("[P2P] UDP discovery listening on 0.0.0.0:{}", DISCOVERY_PORT);

    let my_ip = get_local_ip();
    let mut buf = vec![0u8; 2048];

    loop {
        let (n, from_addr) = match sock.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => { eprintln!("[P2P] UDP recv error: {}", e); continue; }
        };

        // Skip our own broadcasts
        if from_addr.ip().to_string() == my_ip {
            continue;
        }

        let data = &buf[..n];
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) {
            if let (Some(address), Some(name), Some(endpoint)) = (
                v["address"].as_str(),
                v["name"].as_str(),
                v["endpoint"].as_str(),
            ) {
                let state = app.state::<crate::app::AppState>();
                state.upsert_peer(crate::app::PeerInfo {
                    address:   address.to_string(),
                    name:      name.to_string(),
                    endpoint:  endpoint.to_string(),
                    last_seen: Utc::now().timestamp(),
                });
                let _ = app.emit_all("ego://peer-discovered", ());
            }
        }
    }
}

/// Broadcast our identity on the LAN via UDP so nearby nodes can discover us.
/// Called every 30 s from the background sync loop.
pub async fn broadcast_udp_announce() {
    use tokio::net::UdpSocket;

    let address = {
        let ledger = crate::ledger::Ledger::load();
        ledger.address.clone()
    };
    if address.is_empty() { return; }

    let registry  = crate::ledger::load_registry();
    let active_id = crate::ledger::get_active_wallet_id();
    let name = registry.wallets.iter()
        .find(|w| w.id == active_id)
        .map(|w| w.name.clone())
        .unwrap_or_else(|| "Ego Node".to_string());

    let endpoint = get_local_endpoint();
    let payload  = match serde_json::to_vec(&serde_json::json!({
        "address":  address,
        "name":     name,
        "endpoint": endpoint,
    })) {
        Ok(d) => d,
        Err(_) => return,
    };

    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await {
        let _ = sock.set_broadcast(true);
        // Global broadcast
        let _ = sock.send_to(&payload, format!("255.255.255.255:{}", DISCOVERY_PORT)).await;
        // Subnet-directed broadcast (e.g. 192.168.1.255)
        let ip = get_local_ip();
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() == 4 {
            let subnet_bc = format!("{}.{}.{}.255:{}", parts[0], parts[1], parts[2], DISCOVERY_PORT);
            let _ = sock.send_to(&payload, &subnet_bc).await;
        }
    }
}

// ── Client ───────────────────────────────────────────────────────────────────

/// Send a P2P message to a remote endpoint ("ip:port").
pub async fn send_message(endpoint: &str, msg: &P2PMessage) -> Result<(), String> {
    let data = serde_json::to_vec(msg).map_err(|e| e.to_string())?;
    let len  = data.len() as u32;

    let mut stream = TcpStream::connect(endpoint)
        .await
        .map_err(|e| {
            let hint = if e.raw_os_error() == Some(10061) || e.raw_os_error() == Some(111) {
                // ECONNREFUSED: port open on the internet but firewall/app blocking
                " (Windows Firewall is likely blocking port 47393 — \
                  the recipient should run Ego Desktop as Administrator once to add the firewall rule, \
                  or run: netsh advfirewall firewall add rule name=\"Ego P2P\" dir=in action=allow protocol=TCP localport=47393)"
            } else if e.raw_os_error() == Some(10060) || e.raw_os_error() == Some(110) {
                // ETIMEDOUT: no route / port not forwarded on router
                " (connection timed out — the recipient may need to forward TCP port 47393 on their router)"
            } else {
                ""
            };
            format!("Cannot reach peer at {}: {}{}", endpoint, e, hint)
        })?;

    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.write_all(&data).await.map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;

    Ok(())
}
