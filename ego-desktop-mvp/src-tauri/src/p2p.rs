//! libp2p P2P engine for Ego Desktop.
//! - QUIC + TCP transports
//! - Circuit Relay v2  (cross-NAT fallback)
//! - DCUtR hole punching (upgrades relay → direct)
//! - AutoNAT (detects NAT type)
//! - Identify (address exchange)
//!
//! Kademlia removed — IPFS bootstrap nodes reject non-IPFS peers.

use crate::commands::messenger::{load_contacts, save_contacts, Contact};
use crate::ledger::{base_data_dir, load_chain, save_chain, LedgerBlock, LedgerTx};
use chrono::Utc;
use futures::StreamExt;
use futures::{AsyncReadExt, AsyncWriteExt};
use libp2p::{
    autonat, dcutr, identify, noise, ping, relay,
    request_response::{self, OutboundRequestId, ProtocolSupport},
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, StreamProtocol, SwarmBuilder,
};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{collections::HashMap, io, sync::OnceLock, time::Duration};
use tauri::Manager;
use tokio::sync::{mpsc, oneshot};

pub const P2P_PORT: u16 = 47393;

pub const RELAY_NODES: &[&str] = &[
    "/ip4/40.233.82.42/tcp/4001/p2p/12D3KooWPj6m7jzmVyMh1zWrsoux3YiVs9j2HwsjrFXzDcqAGGz4",
];

const RELAY_HTTP_API: &str = "http://40.233.82.42:8080";

// ─────────────────────────────────────────────────────────────────────────────
// SINGLE SOURCE OF TRUTH FOR RELAY CIRCUIT STATE
//
// This flag is set ONLY from inside the swarm event loop (handle_event) via
// inject_circuit(). It is NEVER set from a spawned task.
//
// wait_for_public_endpoint() polls this flag. When true it calls
// get_public_endpoint() which reads from external_addrs via GetEndpoint cmd.
// external_addrs is also only mutated from inside the swarm loop.
//
// This means all three (RELAY_CIRCUIT_READY, external_addrs, AppState endpoint)
// are always consistent with each other.
// ─────────────────────────────────────────────────────────────────────────────
static RELAY_CIRCUIT_READY: AtomicBool = AtomicBool::new(false);

// ── Wire protocol ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum P2PMessage {
    ContactRequest {
        from_addr:       String,
        from_name:       String,
        from_ed25519:    String,
        from_kyber:      String,
        from_shared_key: String,
        from_endpoint:   String,
    },
    ContactResponse {
        from_addr:    String,
        from_name:    String,
        from_ed25519: String,
        from_kyber:   String,
        approved:     bool,
        shared_key:   String,
    },
    PeerAnnounce {
        address:  String,
        name:     String,
        endpoint: String,
    },
    ChatMessage {
        bundle: String,
    },
    TxBroadcast {
        tx:    LedgerTx,
        block: LedgerBlock,
    },
    ChainSyncRequest {
        requester_endpoint: String,
    },
    ChainSyncResponse {
        blocks:       Vec<LedgerBlock>,
        transactions: Vec<LedgerTx>,
    },
    PeerListRequest {
        requester_endpoint: String,
    },
    PeerListResponse {
        peers: Vec<PeerEntry>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEntry {
    pub address:   String,
    pub endpoint:  String,
    pub last_seen: i64,
}

// ── Request-response codec (4-byte length prefix + JSON) ─────────────────────

#[derive(Debug, Clone, Default)]
struct EgoCodec;
impl request_response::Codec for EgoCodec {
    type Protocol = StreamProtocol;
    type Request  = P2PMessage;
    type Response = ();

    fn read_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _: &'life1 Self::Protocol,
        io: &'life2 mut T,
    ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = io::Result<Self::Request>> + ::core::marker::Send + 'async_trait>>
    where
        T: futures::io::AsyncRead + Unpin + Send + 'async_trait,
        'life0: 'async_trait, 'life1: 'async_trait, 'life2: 'async_trait, Self: 'async_trait,
    {
        Box::pin(async move {
            let mut len_buf = [0u8; 4];
            AsyncReadExt::read_exact(io, &mut len_buf).await?;
            let len = u32::from_be_bytes(len_buf) as usize;
            if len > 8 * 1024 * 1024 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "message too large"));
            }
            let mut buf = vec![0u8; len];
            AsyncReadExt::read_exact(io, &mut buf).await?;
            serde_json::from_slice(&buf)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        })
    }

    fn read_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _: &'life1 Self::Protocol,
        _io: &'life2 mut T,
    ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = io::Result<Self::Response>> + ::core::marker::Send + 'async_trait>>
    where
        T: futures::io::AsyncRead + Unpin + Send + 'async_trait,
        'life0: 'async_trait, 'life1: 'async_trait, 'life2: 'async_trait, Self: 'async_trait,
    { Box::pin(async move { Ok(()) }) }

    fn write_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _: &'life1 Self::Protocol,
        io: &'life2 mut T,
        req: Self::Request,
    ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = io::Result<()>> + ::core::marker::Send + 'async_trait>>
    where
        T: futures::io::AsyncWrite + Unpin + Send + 'async_trait,
        'life0: 'async_trait, 'life1: 'async_trait, 'life2: 'async_trait, Self: 'async_trait,
    {
        Box::pin(async move {
            let data = serde_json::to_vec(&req)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            AsyncWriteExt::write_all(io, &(data.len() as u32).to_be_bytes()).await?;
            AsyncWriteExt::write_all(io, &data).await?;
            AsyncWriteExt::flush(io).await
        })
    }

    fn write_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _: &'life1 Self::Protocol,
        _io: &'life2 mut T,
        _: Self::Response,
    ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = io::Result<()>> + ::core::marker::Send + 'async_trait>>
    where
        T: futures::io::AsyncWrite + Unpin + Send + 'async_trait,
        'life0: 'async_trait, 'life1: 'async_trait, 'life2: 'async_trait, Self: 'async_trait,
    { Box::pin(async move { Ok(()) }) }
}

// ── Network behaviour ─────────────────────────────────────────────────────────

#[derive(NetworkBehaviour)]
struct EgoBehaviour {
    relay_client:     relay::client::Behaviour,
    dcutr:            dcutr::Behaviour,
    identify:         identify::Behaviour,
    request_response: request_response::Behaviour<EgoCodec>,
    autonat:          autonat::Behaviour,
    ping:             ping::Behaviour,
}

// ── Swarm command channel ─────────────────────────────────────────────────────

pub enum SwarmCmd {
    Send {
        peer_addr: Multiaddr,
        msg:       P2PMessage,
        reply:     oneshot::Sender<Result<(), String>>,
    },
    GetEndpoint {
        reply: oneshot::Sender<String>,
    },
}

static SWARM_TX: OnceLock<mpsc::Sender<SwarmCmd>> = OnceLock::new();

// ── Public API ────────────────────────────────────────────────────────────────

pub async fn send_message(endpoint: &str, msg: &P2PMessage) -> Result<(), String> {
    let tx = SWARM_TX.get().ok_or_else(|| "P2P not started".to_string())?;
    let peer_addr: Multiaddr = endpoint
        .parse()
        .map_err(|e| format!("Invalid multiaddr '{}': {}", endpoint, e))?;
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(SwarmCmd::Send { peer_addr, msg: msg.clone(), reply: reply_tx })
        .await
        .map_err(|_| "Swarm channel closed".to_string())?;
    reply_rx.await.map_err(|_| "Swarm dropped reply".to_string())?
}

pub async fn get_public_endpoint() -> String {
    let Some(tx) = SWARM_TX.get() else { return String::new(); };
    let (reply_tx, reply_rx) = oneshot::channel();
    if tx.send(SwarmCmd::GetEndpoint { reply: reply_tx }).await.is_err() {
        return String::new();
    }
    reply_rx.await.unwrap_or_default()
}

/// Wait up to `timeout_secs` for a confirmed relay circuit endpoint.
///
/// RELAY_CIRCUIT_READY is set only from inside the swarm loop when either:
///   (a) NewListenAddr fires with /p2p-circuit, OR
///   (b) ReservationReqAccepted fires and we synthesise the circuit address.
///
/// Both paths update external_addrs before setting the flag, so
/// get_public_endpoint() is guaranteed to return the circuit address
/// the instant the flag is true.
pub async fn wait_for_public_endpoint(timeout_secs: u64) -> String {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if RELAY_CIRCUIT_READY.load(Ordering::Relaxed) {
            let ep = get_public_endpoint().await;
            if ep.contains("/p2p-circuit") {
                return ep;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return get_public_endpoint().await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

pub fn get_local_ip() -> String {
    if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
        let _ = sock.connect("8.8.8.8:80");
        if let Ok(addr) = sock.local_addr() {
            let ip = addr.ip().to_string();
            if ip != "0.0.0.0" { return ip; }
        }
    }
    "127.0.0.1".to_string()
}

pub fn get_local_endpoint() -> String {
    format!("/ip4/{}/tcp/{}", get_local_ip(), P2P_PORT)
}

// No-ops kept for API compatibility
pub async fn start_udp_discovery(_app: tauri::AppHandle) {}
pub async fn broadcast_udp_announce() {}
pub async fn gossip_peer_list() {}

pub async fn broadcast_tx(tx: LedgerTx, block: LedgerBlock) {
    let contacts = load_contacts();
    let msg = P2PMessage::TxBroadcast { tx, block };
    for contact in contacts.iter().filter(|c| c.status == "approved" && !c.endpoint.is_empty()) {
        let endpoint  = contact.endpoint.clone();
        let msg_clone = msg.clone();
        tokio::spawn(async move {
            if let Err(e) = send_message(&endpoint, &msg_clone).await {
                if !e.contains("none of the requested protocols") {
                    eprintln!("[P2P] broadcast_tx to {}: {}", endpoint, e);
                }
            }
        });
    }
}

pub async fn sync_chain_from_peers() {
    let my_endpoint = get_public_endpoint().await;
    let msg = P2PMessage::ChainSyncRequest { requester_endpoint: my_endpoint };
    // Only approved contacts — pending contacts may be on old builds.
    for contact in load_contacts().iter().filter(|c| c.status == "approved" && !c.endpoint.is_empty()) {
        let endpoint  = contact.endpoint.clone();
        let msg_clone = msg.clone();
        tokio::spawn(async move {
            if let Err(e) = send_message(&endpoint, &msg_clone).await {
                if !e.contains("none of the requested protocols") {
                    eprintln!("[P2P] sync request to {}: {}", endpoint, e);
                }
            }
        });
    }
}

pub async fn broadcast_peer_announce(app: &tauri::AppHandle) {
    let address = crate::ledger::Ledger::load().address.clone();
    if address.is_empty() { return; }
    let my_endpoint = get_public_endpoint().await;
    let registry  = crate::ledger::load_registry();
    let active_id = crate::ledger::get_active_wallet_id();
    let name = registry.wallets.iter()
        .find(|w| w.id == active_id)
        .map(|w| w.name.clone())
        .unwrap_or_else(|| "Ego Node".to_string());
    {
        let state = app.state::<crate::app::AppState>();
        state.upsert_peer(crate::app::PeerInfo {
            address:   address.clone(),
            name:      name.clone(),
            endpoint:  my_endpoint.clone(),
            last_seen: Utc::now().timestamp(),
        });
    }
    let msg = P2PMessage::PeerAnnounce { address, name, endpoint: my_endpoint };
    // Send to approved contacts only — pending contacts haven't confirmed
    // protocol compatibility yet.
    for contact in load_contacts().iter().filter(|c| c.status == "approved" && !c.endpoint.is_empty()) {
        let endpoint  = contact.endpoint.clone();
        let msg_clone = msg.clone();
        tokio::spawn(async move {
            if let Err(e) = send_message(&endpoint, &msg_clone).await {
                if !e.contains("none of the requested protocols") {
                    eprintln!("[P2P] peer announce to {}: {}", endpoint, e);
                }
            }
        });
    }
}

// ── Peer cache ────────────────────────────────────────────────────────────────

fn peer_cache_path() -> std::path::PathBuf { base_data_dir().join("peers.json") }

pub fn load_peer_cache() -> Vec<PeerEntry> {
    let data = std::fs::read_to_string(peer_cache_path()).unwrap_or_default();
    let mut peers: Vec<PeerEntry> = serde_json::from_str(&data).unwrap_or_default();
    let cutoff = Utc::now().timestamp() - 30 * 86_400;
    peers.retain(|p| p.last_seen >= cutoff);
    peers
}

fn save_peer_cache(peers: &[PeerEntry]) {
    if let Ok(data) = serde_json::to_string_pretty(peers) {
        let _ = std::fs::write(peer_cache_path(), data);
    }
}

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

// ── Identity ──────────────────────────────────────────────────────────────────

fn load_or_create_identity() -> libp2p::identity::Keypair {
    let path = base_data_dir().join("p2p_identity.bin");
    if let Ok(bytes) = std::fs::read(&path) {
        if let Ok(kp) = libp2p::identity::Keypair::from_protobuf_encoding(&bytes) {
            return kp;
        }
    }
    let kp = libp2p::identity::Keypair::generate_ed25519();
    if let Ok(bytes) = kp.to_protobuf_encoding() {
        let _ = std::fs::write(&path, bytes);
    }
    kp
}

// ── Swarm entry point ─────────────────────────────────────────────────────────

pub async fn start_p2p_server(app: tauri::AppHandle) {
    #[cfg(target_os = "windows")]
    ensure_firewall_rule();

    let identity      = load_or_create_identity();
    let local_peer_id = identity.public().to_peer_id();
    eprintln!("[P2P] Local peer ID: {}", local_peer_id);

    let mut swarm = match build_swarm(identity).await {
        Ok(s)  => s,
        Err(e) => { eprintln!("[P2P] Failed to build swarm: {}", e); return; }
    };

    if let Err(e) = swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{}", P2P_PORT).parse().unwrap()) {
        eprintln!("[P2P] TCP listen: {}", e);
    }
    if let Err(e) = swarm.listen_on(format!("/ip4/0.0.0.0/udp/{}/quic-v1", P2P_PORT).parse().unwrap()) {
        eprintln!("[P2P] QUIC listen: {}", e);
    }

    // relay PeerId → base transport addr (no /p2p/<id> suffix)
    // e.g.  12D3KooWPj6m... → /ip4/40.233.82.42/tcp/4001
    let mut relay_addrs: HashMap<PeerId, Multiaddr> = HashMap::new();
    for relay_str in RELAY_NODES {
        if let Ok(addr) = relay_str.parse::<Multiaddr>() {
            if let Some(pid) = peer_id_from_multiaddr(&addr) {
                relay_addrs.insert(pid, strip_p2p_suffix(&addr));
            }
            eprintln!("[P2P] Dialling relay {}", relay_str);
            let _ = swarm.dial(addr);
        }
    }

    let (tx, mut rx) = mpsc::channel::<SwarmCmd>(64);
    let _ = SWARM_TX.set(tx);

    let mut external_addrs: Vec<Multiaddr> = Vec::new();
    let mut pending_sends:  HashMap<PeerId, Vec<(P2PMessage, oneshot::Sender<Result<(), String>>)>> = HashMap::new();
    let mut in_flight:      HashMap<OutboundRequestId, oneshot::Sender<Result<(), String>>> = HashMap::new();

    // Retry relay connection every 15 s when circuit is not confirmed.
    // Recovers from relay being down at startup — once it comes back up the
    // next tick redials and the circuit establishes automatically.
    let mut relay_retry = tokio::time::interval(Duration::from_secs(15));
    relay_retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    relay_retry.tick().await; // consume the immediate first tick

    loop {
        tokio::select! {
            cmd = rx.recv() => {
                let Some(cmd) = cmd else { break; };
                match cmd {
                    SwarmCmd::Send { peer_addr, msg, reply } => {
                        handle_send(&mut swarm, peer_addr, msg, reply,
                            &mut pending_sends, &mut in_flight);
                    }
                    SwarmCmd::GetEndpoint { reply } => {
                        let ep = best_endpoint(&external_addrs, &local_peer_id);
                        let _ = reply.send(ep);
                    }
                }
            }
            event = swarm.select_next_some() => {
                handle_event(
                    event, &app,
                    &mut external_addrs, &mut pending_sends, &mut in_flight,
                    &mut swarm, &relay_addrs,
                ).await;
            }
            _ = relay_retry.tick() => {
                // Only redial if relay circuit not yet confirmed.
                // Once circuit is live this branch is a cheap no-op.
                if !has_circuit_addr(&external_addrs) {
                    for relay_str in RELAY_NODES {
                        if let Ok(addr) = relay_str.parse::<Multiaddr>() {
                            let already = peer_id_from_multiaddr(&addr)
                                .map(|p| swarm.is_connected(&p))
                                .unwrap_or(false);
                            if !already {
                                eprintln!("[P2P] Relay not connected — redialling {}", relay_str);
                                let _ = swarm.dial(addr);
                            }
                        }
                    }
                }
            }
        }
    }
}

fn strip_p2p_suffix(addr: &Multiaddr) -> Multiaddr {
    use libp2p::multiaddr::Protocol;
    addr.iter().filter(|p| !matches!(p, Protocol::P2p(_))).collect()
}

async fn build_swarm(
    identity: libp2p::identity::Keypair,
) -> Result<libp2p::Swarm<EgoBehaviour>, Box<dyn std::error::Error>> {
    let peer_id = identity.public().to_peer_id();
    let swarm = SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(tcp::Config::default().nodelay(true), noise::Config::new, yamux::Config::default)?
        .with_quic()
        .with_dns()?
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key, relay_client| EgoBehaviour {
            relay_client,
            dcutr:    dcutr::Behaviour::new(peer_id),
            identify: identify::Behaviour::new(
                identify::Config::new("/ego/identify/1.0.0".to_string(), key.public())
                    .with_interval(Duration::from_secs(60)),
            ),
            request_response: request_response::Behaviour::new(
                [(StreamProtocol::new("/ego/msg/1.0.0"), ProtocolSupport::Full)],
                request_response::Config::default()
                    .with_request_timeout(Duration::from_secs(30)),
            ),
            autonat: autonat::Behaviour::new(peer_id, autonat::Config::default()),
            ping:    ping::Behaviour::new(
                ping::Config::new().with_interval(Duration::from_secs(30)),
            ),
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(300)))
        .build();
    Ok(swarm)
}

// ── Send helper ───────────────────────────────────────────────────────────────

fn handle_send(
    swarm:         &mut libp2p::Swarm<EgoBehaviour>,
    peer_addr:     Multiaddr,
    msg:           P2PMessage,
    reply:         oneshot::Sender<Result<(), String>>,
    pending_sends: &mut HashMap<PeerId, Vec<(P2PMessage, oneshot::Sender<Result<(), String>>)>>,
    in_flight:     &mut HashMap<OutboundRequestId, oneshot::Sender<Result<(), String>>>,
) {
    let peer_id = match peer_id_from_multiaddr(&peer_addr) {
        Some(id) => id,
        None => {
            let _ = reply.send(Err(format!("No peer ID in multiaddr: {}", peer_addr)));
            return;
        }
    };
    if swarm.is_connected(&peer_id) {
        let req_id = swarm.behaviour_mut().request_response.send_request(&peer_id, msg);
        in_flight.insert(req_id, reply);
    } else {
        pending_sends.entry(peer_id).or_default().push((msg, reply));
        let _ = swarm.dial(peer_addr);
    }
}

fn peer_id_from_multiaddr(addr: &Multiaddr) -> Option<PeerId> {
    use libp2p::multiaddr::Protocol;
    addr.iter().find_map(|p| {
        if let Protocol::P2p(pid) = p { Some(pid) } else { None }
    })
}

/// Select best reachable endpoint.
///   1. /p2p-circuit   — works behind any NAT
///   2. Public IPv4    — works if port-forwarded
///   3. LAN / loopback — last resort
fn best_endpoint(external_addrs: &[Multiaddr], peer_id: &PeerId) -> String {
    let pid_str = peer_id.to_string();

    if let Some(a) = external_addrs.iter().find(|a| a.to_string().contains("/p2p-circuit")) {
        let s = a.to_string();
        return if s.contains(&pid_str) { s } else { format!("{}/p2p/{}", s, pid_str) };
    }

    let is_public = |a: &Multiaddr| {
        let s = a.to_string();
        !s.starts_with("/ip4/127.")     &&
        !s.starts_with("/ip4/10.")      &&
        !s.starts_with("/ip4/192.168.") &&
        !s.starts_with("/ip4/172.")
    };
    let base = external_addrs.iter().find(|a| is_public(a))
        .or_else(|| external_addrs.first())
        .map(|a| a.to_string())
        .unwrap_or_else(|| format!("/ip4/{}/tcp/{}", get_local_ip(), P2P_PORT));
    if base.contains("/p2p/") { base } else { format!("{}/p2p/{}", base, pid_str) }
}

fn has_circuit_addr(addrs: &[Multiaddr]) -> bool {
    addrs.iter().any(|a| a.to_string().contains("/p2p-circuit"))
}

// Build the full dialable circuit address:
//   /ip4/<relay_ip>/tcp/<port>/p2p/<relay_id>/p2p-circuit/p2p/<our_id>
fn build_circuit_addr(
    relay_base:    &Multiaddr,
    relay_peer_id: &PeerId,
    our_peer_id:   &PeerId,
) -> Option<Multiaddr> {
    format!("{}/p2p/{}/p2p-circuit/p2p/{}", relay_base, relay_peer_id, our_peer_id)
        .parse()
        .ok()
}

// ── Circuit injection (called from multiple event paths) ──────────────────────

/// Add `circuit` to external_addrs and set RELAY_CIRCUIT_READY.
/// MUST only be called from within the swarm event loop so that
/// external_addrs mutations are always single-threaded.
fn inject_circuit(
    circuit:        Multiaddr,
    external_addrs: &mut Vec<Multiaddr>,
    app:            &tauri::AppHandle,
    local_peer_id:  &PeerId,
) {
    if !external_addrs.contains(&circuit) {
        eprintln!("[P2P] ✓ Circuit injected: {}", circuit);
        external_addrs.push(circuit);
    }
    RELAY_CIRCUIT_READY.store(true, Ordering::Relaxed);
    let ep    = best_endpoint(external_addrs, local_peer_id);
    let state = app.state::<crate::app::AppState>();
    state.set_public_endpoint(ep.clone());
    state.set_upnp_status(Ok(()));
    let _ = app.emit_all("ego://p2p-status-changed", ());

    // Register with HTTP relay directory (async, non-blocking)
    let address_str = crate::ledger::Ledger::load().address;
    let registry    = crate::ledger::load_registry();
    let active_id   = crate::ledger::get_active_wallet_id();
    let name = registry.wallets.iter()
        .find(|w| w.id == active_id)
        .map(|w| w.name.clone())
        .unwrap_or_else(|| "Ego Node".to_string());
    let ep_clone  = ep.clone();
    let app_clone = app.clone();
    tokio::spawn(async move {
        register_with_relay(address_str, name, ep_clone).await;
        // Small delay so contacts have time to register too before we announce
        tokio::time::sleep(Duration::from_millis(300)).await;
        broadcast_peer_announce(&app_clone).await;
        eprintln!("[P2P] Re-announced after relay circuit confirmed");
    });
}

// ── Swarm event handler ───────────────────────────────────────────────────────

async fn handle_event(
    event:          SwarmEvent<EgoBehaviourEvent>,
    app:            &tauri::AppHandle,
    external_addrs: &mut Vec<Multiaddr>,
    pending_sends:  &mut HashMap<PeerId, Vec<(P2PMessage, oneshot::Sender<Result<(), String>>)>>,
    in_flight:      &mut HashMap<OutboundRequestId, oneshot::Sender<Result<(), String>>>,
    swarm:          &mut libp2p::Swarm<EgoBehaviour>,
    relay_addrs:    &HashMap<PeerId, Multiaddr>,
) {
    match event {

        // ─── NewListenAddr ────────────────────────────────────────────────────
        // When the relay accepts our reservation it assigns a circuit listen
        // address.  libp2p fires NewListenAddr with that address.
        // This is the PRIMARY confirmation path.
        SwarmEvent::NewListenAddr { address, .. } => {
            let addr_str = address.to_string();
            eprintln!("[P2P] Listening on {}", addr_str);

            if addr_str.contains("/p2p-circuit") {
                let peer_id = *swarm.local_peer_id();
                let pid_str = peer_id.to_string();
                // Ensure /p2p/<our_id> is appended so remote peers can dial us
                let full: Multiaddr = if addr_str.contains(&pid_str) {
                    address.clone()
                } else {
                    format!("{}/p2p/{}", addr_str, pid_str)
                        .parse()
                        .unwrap_or(address.clone())
                };
                eprintln!("[P2P] ✓ Relay circuit LIVE (NewListenAddr): {}", full);
                inject_circuit(full, external_addrs, app, &peer_id);
            }
        }

        // ─── ConnectionEstablished ────────────────────────────────────────────
        // For relays: call swarm.listen_on(circuit_addr) to request a slot,
        // then IMMEDIATELY inject the circuit address optimistically.
        //
        // Why optimistic: the relay almost always accepts, the circuit multiaddr
        // is deterministic, and waiting for ReservationReqAccepted / NewListenAddr
        // is unreliable — the event may arrive after wait_for_public_endpoint
        // has already timed out, or get lost entirely during reconnects.
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            eprintln!("[P2P] Connected to {}", peer_id);

            if let Some(relay_base) = relay_addrs.get(&peer_id) {
                let our_peer_id = *swarm.local_peer_id();
                // Request slot: <relay_base>/p2p/<relay_id>/p2p-circuit
                let circuit_str = format!("{}/p2p/{}/p2p-circuit", relay_base, peer_id);
                match circuit_str.parse::<Multiaddr>() {
                    Ok(circuit_addr) => {
                        eprintln!("[P2P] Reserving relay slot: {}", circuit_str);
                        match swarm.listen_on(circuit_addr) {
                            Ok(_)  => {
                                eprintln!("[P2P] Relay reservation requested ✓");
                                // Optimistically inject the full circuit address
                                // immediately — don't wait for ReservationReqAccepted
                                // or NewListenAddr, which are unreliable on disconnect/
                                // reconnect cycles.
                                if let Some(full_circuit) = build_circuit_addr(
                                    relay_base, &peer_id, &our_peer_id,
                                ) {
                                    inject_circuit(full_circuit, external_addrs, app, &our_peer_id);
                                }
                            }
                            Err(e) => eprintln!("[P2P] Relay listen error: {}", e),
                        }
                    }
                    Err(e) => eprintln!("[P2P] Bad circuit addr '{}': {}", circuit_str, e),
                }
            }

            // Flush queued messages for this peer
            if let Some(pending) = pending_sends.remove(&peer_id) {
                for (msg, reply) in pending {
                    let req_id = swarm.behaviour_mut()
                        .request_response.send_request(&peer_id, msg);
                    in_flight.insert(req_id, reply);
                }
            }
        }

        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            if relay_addrs.contains_key(&peer_id) {
                eprintln!("[P2P] Relay {} disconnected — clearing circuit, redialling", peer_id);
                RELAY_CIRCUIT_READY.store(false, Ordering::Relaxed);
                external_addrs.retain(|a| !a.to_string().contains("/p2p-circuit"));
                for relay_str in RELAY_NODES {
                    if let Ok(addr) = relay_str.parse::<Multiaddr>() {
                        let _ = swarm.dial(addr);
                    }
                }
            }
            if let Some(pending) = pending_sends.remove(&peer_id) {
                for (_, reply) in pending {
                    let _ = reply.send(Err("Connection closed before send".into()));
                }
            }
        }

        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            eprintln!("[P2P] Dial error {:?}: {}", peer_id, error);
            if let Some(pid) = peer_id {
                if let Some(pending) = pending_sends.remove(&pid) {
                    for (_, reply) in pending {
                        let _ = reply.send(Err(format!("Cannot reach peer: {}", error)));
                    }
                }
            }
        }

        // ─── Identify ─────────────────────────────────────────────────────────
        // Learn our own external address as seen by a remote peer.
        // Only update AppState from here if relay circuit isn't live yet.
        SwarmEvent::Behaviour(EgoBehaviourEvent::Identify(
            identify::Event::Received { info, .. },
        )) => {
            let observed = info.observed_addr.clone();
            swarm.add_external_address(observed.clone());
            if !external_addrs.contains(&observed) {
                external_addrs.push(observed.clone());
                eprintln!("[P2P] Observed external address: {}", observed);
            }
            if !RELAY_CIRCUIT_READY.load(Ordering::Relaxed) {
                let peer_id = *swarm.local_peer_id();
                let state   = app.state::<crate::app::AppState>();
                state.set_public_endpoint(best_endpoint(external_addrs, &peer_id));
                let _ = app.emit_all("ego://p2p-status-changed", ());
            }
        }

        // ─── ReservationReqAccepted ───────────────────────────────────────────
        // Belt-and-suspenders path: if NewListenAddr already fired this is a
        // no-op (inject_circuit deduplicates).  If NewListenAddr didn't fire
        // (version quirk), we synthesise the full circuit address ourselves.
        SwarmEvent::Behaviour(EgoBehaviourEvent::RelayClient(
            relay::client::Event::ReservationReqAccepted { relay_peer_id, .. },
        )) => {
            eprintln!("[P2P] ✓ Relay reservation ACCEPTED via {}", relay_peer_id);
            let our_peer_id = *swarm.local_peer_id();
            if let Some(relay_base) = relay_addrs.get(&relay_peer_id) {
                if let Some(circuit) = build_circuit_addr(relay_base, &relay_peer_id, &our_peer_id) {
                    inject_circuit(circuit, external_addrs, app, &our_peer_id);
                }
            }
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::RelayClient(event)) => {
            eprintln!("[P2P] Relay event: {:?}", event);
        }

        // ─── AutoNAT ──────────────────────────────────────────────────────────
        SwarmEvent::Behaviour(EgoBehaviourEvent::Autonat(
            autonat::Event::StatusChanged { new, .. },
        )) => {
            let state = app.state::<crate::app::AppState>();
            match new {
                autonat::NatStatus::Public(addr) => {
                    eprintln!("[P2P] AutoNAT: public at {}", addr);
                    state.set_upnp_status(Ok(()));
                    if !RELAY_CIRCUIT_READY.load(Ordering::Relaxed) {
                        if !external_addrs.contains(&addr) {
                            external_addrs.push(addr.clone());
                        }
                        let peer_id = *swarm.local_peer_id();
                        state.set_public_endpoint(best_endpoint(external_addrs, &peer_id));
                        let _ = app.emit_all("ego://p2p-status-changed", ());
                    }
                }
                autonat::NatStatus::Private => {
                    eprintln!("[P2P] AutoNAT: behind NAT — relay required");
                    state.set_upnp_status(Err("Behind NAT — using relay".into()));
                    let _ = app.emit_all("ego://p2p-status-changed", ());
                }
                autonat::NatStatus::Unknown => {}
            }
        }

        // ─── request-response ─────────────────────────────────────────────────
        SwarmEvent::Behaviour(EgoBehaviourEvent::RequestResponse(
            request_response::Event::Message {
                message: request_response::Message::Request { request, channel, .. }, ..
            },
        )) => {
            let _ = swarm.behaviour_mut().request_response.send_response(channel, ());
            let app = app.clone();
            tokio::spawn(async move { handle_incoming(request, &app).await; });
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::RequestResponse(
            request_response::Event::Message {
                message: request_response::Message::Response { request_id, .. }, ..
            },
        )) => {
            if let Some(reply) = in_flight.remove(&request_id) {
                let _ = reply.send(Ok(()));
            }
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::RequestResponse(
            request_response::Event::OutboundFailure { request_id, error, .. },
        )) => {
            if let Some(reply) = in_flight.remove(&request_id) {
                let _ = reply.send(Err(format!("Network error: {}", error)));
            }
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::Dcutr(event)) => {
            eprintln!("[P2P] DCUtR: {:?}", event);
        }

        _ => {}
    }
}

// ── Incoming message handler ──────────────────────────────────────────────────

async fn handle_incoming(msg: P2PMessage, app: &tauri::AppHandle) {
    match msg {
        P2PMessage::ContactRequest {
            from_addr, from_name, from_ed25519, from_kyber, from_shared_key, from_endpoint,
        } => {
            let mut contacts = load_contacts();
            if let Some(existing) = contacts.iter_mut().find(|c| c.address == from_addr) {
                if !from_endpoint.is_empty() && existing.endpoint != from_endpoint {
                    existing.endpoint = from_endpoint;
                    let _ = save_contacts(&contacts);
                }
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
            let _ = tauri::api::notification::Notification::new(
                &app.config().tauri.bundle.identifier,
            )
            .title("Contact Request")
            .body(&format!("{} wants to connect with you", from_name))
            .show();
            let _ = app.emit_all("ego://contact-request", &contact);
        }

        P2PMessage::ContactResponse {
            from_addr, from_name, from_ed25519, from_kyber, approved, shared_key,
        } => {
            let mut contacts = load_contacts();
            if approved {
                if let Some(p) = contacts.iter_mut()
                    .find(|c| c.status == "pending_out" && c.shared_key_hex == shared_key)
                {
                    p.address        = from_addr.clone();
                    p.name           = from_name.clone();
                    p.ed25519_pubkey = from_ed25519;
                    p.kyber_pubkey   = from_kyber;
                    p.status         = "approved".to_string();
                    let contact = p.clone();
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
                contacts.retain(|c| !(c.status == "pending_out" && c.shared_key_hex == shared_key));
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

        P2PMessage::PeerAnnounce { address, name, endpoint } => {
            if !endpoint.is_empty() {
                let mut contacts = load_contacts();
                if let Some(c) = contacts.iter_mut().find(|c| c.address == address) {
                    let relay_in   = endpoint.contains("/p2p-circuit");
                    let relay_curr = c.endpoint.contains("/p2p-circuit");
                    // relay circuit always wins; raw IP only updates non-relay
                    if (relay_in || !relay_curr) && c.endpoint != endpoint {
                        eprintln!("[P2P] Updated contact {} endpoint → {}", address, endpoint);
                        c.endpoint = endpoint.clone();
                        let _ = save_contacts(&contacts);
                    }
                }
            }
            let state = app.state::<crate::app::AppState>();
            state.upsert_peer(crate::app::PeerInfo {
                address:   address.clone(),
                name,
                endpoint:  endpoint.clone(),
                last_seen: Utc::now().timestamp(),
            });
            upsert_peer_cache(PeerEntry {
                address,
                endpoint,
                last_seen: Utc::now().timestamp(),
            });
        }

        P2PMessage::ChatMessage { bundle } => {
            match crate::commands::messenger::receive_message_inner(&bundle) {
                Ok(msg) => {
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
                    let _ = app.emit_all("ego://message-received", &msg);
                }
                Err(e) => eprintln!("[P2P] Decrypt error: {}", e),
            }
        }

        P2PMessage::TxBroadcast { tx, block } => {
            apply_incoming_tx(tx, block, app).await;
        }

        P2PMessage::ChainSyncRequest { requester_endpoint } => {
            let chain    = load_chain();
            let response = P2PMessage::ChainSyncResponse {
                blocks:       chain.blocks,
                transactions: chain.transactions,
            };
            tokio::spawn(async move {
                if let Err(e) = send_message(&requester_endpoint, &response).await {
                    eprintln!("[P2P] chain sync reply: {}", e);
                }
            });
        }

        P2PMessage::ChainSyncResponse { blocks, transactions } => {
            merge_remote_chain(blocks, transactions, app).await;
        }

        P2PMessage::PeerListRequest { requester_endpoint } => {
            let peers    = load_peer_cache();
            let response = P2PMessage::PeerListResponse { peers };
            tokio::spawn(async move {
                if let Err(e) = send_message(&requester_endpoint, &response).await {
                    eprintln!("[P2P] peer list reply: {}", e);
                }
            });
        }

        P2PMessage::PeerListResponse { peers } => {
            let my_ep = get_public_endpoint().await;
            for peer in peers {
                if peer.endpoint.is_empty() || peer.endpoint == my_ep { continue; }
                upsert_peer_cache(PeerEntry {
                    address:   peer.address,
                    endpoint:  peer.endpoint,
                    last_seen: Utc::now().timestamp(),
                });
            }
        }
    }
}

// ── Chain helpers ─────────────────────────────────────────────────────────────

async fn apply_incoming_tx(tx: LedgerTx, block: LedgerBlock, app: &tauri::AppHandle) {
    let mut chain = load_chain();
    if chain.transactions.iter().any(|t| t.hash == tx.hash) { return; }
    chain.transactions.push(tx);
    chain.blocks.push(block);
    chain.blocks.sort_by_key(|b| b.height);
    let _ = save_chain(&chain);
    let _ = app.emit_all("ego://chain-updated", ());
}

async fn merge_remote_chain(
    blocks: Vec<LedgerBlock>, transactions: Vec<LedgerTx>, app: &tauri::AppHandle,
) {
    let mut chain   = load_chain();
    let mut changed = false;
    for tx in transactions {
        if !chain.transactions.iter().any(|t| t.hash == tx.hash) {
            chain.transactions.push(tx); changed = true;
        }
    }
    for block in blocks {
        if !chain.blocks.iter().any(|b| b.hash == block.hash) {
            chain.blocks.push(block); changed = true;
        }
    }
    if changed {
        chain.blocks.sort_by_key(|b| b.height);
        let _ = save_chain(&chain);
        let _ = app.emit_all("ego://chain-updated", ());
    }
}

// ── Relay HTTP helpers ────────────────────────────────────────────────────────

pub async fn fetch_chain_from_relay(app: &tauri::AppHandle) {
    let url = format!("{}/chain", RELAY_HTTP_API);
    eprintln!("[Relay] Fetching chain from {}", url);
    let resp = match reqwest::get(&url).await {
        Ok(r)  => r,
        Err(e) => { eprintln!("[Relay] fetch_chain HTTP error: {}", e); return; }
    };
    let body = match resp.text().await {
        Ok(b)  => b,
        Err(e) => { eprintln!("[Relay] fetch_chain read error: {}", e); return; }
    };
    let remote: crate::ledger::SharedChain = match serde_json::from_str(&body) {
        Ok(c)  => c,
        Err(e) => { eprintln!("[Relay] fetch_chain parse error: {}", e); return; }
    };
    if remote.blocks.is_empty() && remote.transactions.is_empty() {
        eprintln!("[Relay] Relay chain is empty — nothing to merge");
        return;
    }
    merge_remote_chain(remote.blocks, remote.transactions, app).await;
    eprintln!("[Relay] Chain merged from relay seed node");
}

pub async fn push_tx_to_relay(tx: &crate::ledger::LedgerTx, block: &crate::ledger::LedgerBlock) {
    let client = reqwest::Client::new();
    if let Err(e) = client.post(format!("{}/chain/tx", RELAY_HTTP_API))
        .json(tx).send().await
    {
        eprintln!("[Relay] push tx error: {}", e);
    }
    if let Err(e) = client.post(format!("{}/chain/block", RELAY_HTTP_API))
        .json(block).send().await
    {
        eprintln!("[Relay] push block error: {}", e);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RelayPeerEntry {
    address:   String,
    name:      String,
    endpoint:  String,
    last_seen: i64,
}

pub async fn register_with_relay(address: String, name: String, endpoint: String) {
    if address.is_empty() || endpoint.is_empty() { return; }
    let entry  = RelayPeerEntry { address: address.clone(), name, endpoint: endpoint.clone(), last_seen: 0 };
    let client = reqwest::Client::new();
    match client.post(format!("{}/peers", RELAY_HTTP_API))
        .json(&entry).send().await
    {
        Ok(_)  => eprintln!("[Relay] Registered endpoint: {}", endpoint),
        Err(e) => eprintln!("[Relay] register error: {}", e),
    }
}

pub async fn fetch_peers_from_relay(app: &tauri::AppHandle) {
    let url = format!("{}/peers", RELAY_HTTP_API);
    let resp = match reqwest::get(&url).await {
        Ok(r)  => r,
        Err(e) => { eprintln!("[Relay] fetch_peers error: {}", e); return; }
    };
    let body = match resp.text().await {
        Ok(b)  => b,
        Err(e) => { eprintln!("[Relay] fetch_peers read: {}", e); return; }
    };
    let remote_peers: Vec<RelayPeerEntry> = match serde_json::from_str(&body) {
        Ok(p)  => p,
        Err(e) => { eprintln!("[Relay] fetch_peers parse: {}", e); return; }
    };
    if remote_peers.is_empty() { return; }

    let state = app.state::<crate::app::AppState>();
    let now   = Utc::now().timestamp();
    for p in &remote_peers {
        // Use now, not p.last_seen (which is when they registered with relay,
        // potentially minutes ago).  As long as a peer is in the relay directory
        // they are considered online — AppState::get_active_peers(300) will keep
        // them visible until the NEXT relay fetch fails to include them.
        state.upsert_peer(crate::app::PeerInfo {
            address:   p.address.clone(),
            name:      p.name.clone(),
            endpoint:  p.endpoint.clone(),
            last_seen: now,
        });
        // Also write to the file-based peer cache so resolve_endpoint()
        // (in messenger.rs) can find it without another HTTP round-trip.
        if !p.endpoint.is_empty() {
            upsert_peer_cache(PeerEntry {
                address:   p.address.clone(),
                endpoint:  p.endpoint.clone(),
                last_seen: Utc::now().timestamp(),
            });
        }
    }

    let mut contacts = load_contacts();
    let mut changed  = false;
    for remote in &remote_peers {
        if remote.endpoint.is_empty() { continue; }
        if let Some(c) = contacts.iter_mut().find(|c| c.address == remote.address) {
            let relay_in   = remote.endpoint.contains("/p2p-circuit");
            let relay_curr = c.endpoint.contains("/p2p-circuit");
            if (relay_in || !relay_curr) && c.endpoint != remote.endpoint {
                eprintln!("[Relay] Updated {} endpoint → {}", remote.address, remote.endpoint);
                c.endpoint = remote.endpoint.clone();
                changed = true;
            }
        }
    }
    if changed {
        let _ = save_contacts(&contacts);
        let _ = app.emit_all("ego://peers-updated", ());
    }
    eprintln!("[Relay] Fetched {} peers from relay directory", remote_peers.len());
}

/// Live relay HTTP lookup — returns the peer's current relay circuit endpoint
/// for the given wallet address, or `None` if not found.
/// Called by resolve_endpoint() as a fallback when the local cache is stale.
pub async fn get_relay_endpoint(address: &str) -> Option<String> {
    let resp = reqwest::get(format!("{}/peers", RELAY_HTTP_API)).await.ok()?;
    let body = resp.text().await.ok()?;
    let peers: Vec<RelayPeerEntry> = serde_json::from_str(&body).ok()?;
    peers.into_iter()
        .find(|p| p.address == address && !p.endpoint.is_empty())
        .map(|p| p.endpoint)
}

// ── Windows firewall ──────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn ensure_firewall_rule() {
    for (name, proto, port) in [
        (format!("Ego Desktop P2P TCP {}", P2P_PORT), "TCP", P2P_PORT),
        (format!("Ego Desktop P2P UDP {}", P2P_PORT), "UDP", P2P_PORT),
    ] {
        let check = std::process::Command::new("netsh")
            .args(["advfirewall", "firewall", "show", "rule", &format!("name={}", name)])
            .output();
        if let Ok(out) = check {
            if out.status.success() && !out.stdout.is_empty() { continue; }
        }
        let _ = std::process::Command::new("netsh")
            .args([
                "advfirewall", "firewall", "add", "rule",
                &format!("name={}", name),
                "dir=in", "action=allow",
                &format!("protocol={}", proto),
                &format!("localport={}", port),
                "enable=yes", "profile=any",
            ])
            .output();
    }
}

#[cfg(not(target_os = "windows"))]
fn ensure_firewall_rule() {}