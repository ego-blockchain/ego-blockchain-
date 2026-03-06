//! libp2p P2P engine for Ego Desktop.
//! Replaces raw TCP + UPnP with proper NAT traversal:
//! - QUIC + TCP transports
//! - Circuit Relay v2 (fallback when direct fails)
//! - DCUtR hole punching (upgrades relay → direct)
//! - AutoNAT (detects NAT type, updates UI)
//! - Identify (address exchange)

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
use std::{collections::HashMap, io, sync::OnceLock, time::Duration};
use tauri::Manager;
use tokio::sync::{mpsc, oneshot};

pub const P2P_PORT: u16 = 47393;

/// Public relay nodes (Protocol Labs / IPFS network, support relay v2).
const RELAY_NODES: &[&str] = &[
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
];

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
        'life0: 'async_trait, 'life1: 'async_trait, 'life2: 'async_trait,
        Self: 'async_trait,
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
            serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        })
    }

    fn read_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _: &'life1 Self::Protocol,
        _io: &'life2 mut T,
    ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = io::Result<Self::Response>> + ::core::marker::Send + 'async_trait>>
    where
        T: futures::io::AsyncRead + Unpin + Send + 'async_trait,
        'life0: 'async_trait, 'life1: 'async_trait, 'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { Ok(()) })
    }

    fn write_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _: &'life1 Self::Protocol,
        io: &'life2 mut T,
        req: Self::Request,
    ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = io::Result<()>> + ::core::marker::Send + 'async_trait>>
    where
        T: futures::io::AsyncWrite + Unpin + Send + 'async_trait,
        'life0: 'async_trait, 'life1: 'async_trait, 'life2: 'async_trait,
        Self: 'async_trait,
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
        'life0: 'async_trait, 'life1: 'async_trait, 'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { Ok(()) })
    }
}

// ── Combined network behaviour ────────────────────────────────────────────────

#[derive(NetworkBehaviour)]
struct EgoBehaviour {
    relay_client:     relay::client::Behaviour,
    dcutr:            dcutr::Behaviour,
    identify:         identify::Behaviour,
    request_response: request_response::Behaviour<EgoCodec>,
    autonat:          autonat::Behaviour,
    ping:             ping::Behaviour,
}

// ── Commands: Tauri → swarm ───────────────────────────────────────────────────

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

// ── Public API (same interface as old p2p.rs) ─────────────────────────────────

/// Send a P2P message to a peer. `endpoint` is a libp2p multiaddr string,
/// e.g. `/ip4/1.2.3.4/tcp/47393/p2p/12D3KooW...`
pub async fn send_message(endpoint: &str, msg: &P2PMessage) -> Result<(), String> {
    let tx = SWARM_TX.get().ok_or_else(|| "P2P not started".to_string())?;
    let peer_addr: Multiaddr = endpoint.parse()
        .map_err(|e| format!("Invalid multiaddr '{}': {}", endpoint, e))?;
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(SwarmCmd::Send { peer_addr, msg: msg.clone(), reply: reply_tx })
        .await
        .map_err(|_| "Swarm channel closed".to_string())?;
    reply_rx.await.map_err(|_| "Swarm dropped reply".to_string())?
}

/// Best public endpoint for sharing in contact bundles.
pub async fn get_public_endpoint() -> String {
    let Some(tx) = SWARM_TX.get() else { return String::new(); };
    let (reply_tx, reply_rx) = oneshot::channel();
    if tx.send(SwarmCmd::GetEndpoint { reply: reply_tx }).await.is_err() {
        return String::new();
    }
    reply_rx.await.unwrap_or_default()
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

// No-ops — libp2p handles LAN discovery and peer gossip internally.
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
                eprintln!("[P2P] broadcast_tx to {}: {}", endpoint, e);
            }
        });
    }
}

pub async fn sync_chain_from_peers() {
    let my_endpoint = get_public_endpoint().await;
    let msg = P2PMessage::ChainSyncRequest { requester_endpoint: my_endpoint };
    for contact in load_contacts().iter().filter(|c| !c.endpoint.is_empty()) {
        let endpoint  = contact.endpoint.clone();
        let msg_clone = msg.clone();
        tokio::spawn(async move {
            if let Err(e) = send_message(&endpoint, &msg_clone).await {
                eprintln!("[P2P] sync request to {}: {}", endpoint, e);
            }
        });
    }
}

pub async fn broadcast_peer_announce(app: &tauri::AppHandle) {
    let address = { crate::ledger::Ledger::load().address.clone() };
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
    for contact in load_contacts().iter().filter(|c| !c.endpoint.is_empty()) {
        let endpoint  = contact.endpoint.clone();
        let msg_clone = msg.clone();
        tokio::spawn(async move {
            if let Err(e) = send_message(&endpoint, &msg_clone).await {
                eprintln!("[P2P] peer announce to {}: {}", endpoint, e);
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

// ── Identity (persisted per-device, independent of wallet) ───────────────────

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

    // Listen on TCP and QUIC
    let tcp_addr:  Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", P2P_PORT).parse().unwrap();
    let quic_addr: Multiaddr = format!("/ip4/0.0.0.0/udp/{}/quic-v1", P2P_PORT).parse().unwrap();
    if let Err(e) = swarm.listen_on(tcp_addr)  { eprintln!("[P2P] TCP listen: {}", e); }
    if let Err(e) = swarm.listen_on(quic_addr) { eprintln!("[P2P] QUIC listen: {}", e); }

    // Dial relay nodes so we can reserve a relay slot for inbound connections
    for relay_addr in RELAY_NODES {
        if let Ok(addr) = relay_addr.parse::<Multiaddr>() {
            let _ = swarm.dial(addr);
        }
    }

    let (tx, mut rx) = mpsc::channel::<SwarmCmd>(64);
    let _ = SWARM_TX.set(tx);

    let mut external_addrs: Vec<Multiaddr> = Vec::new();
    let mut pending_sends:  HashMap<PeerId, Vec<(P2PMessage, oneshot::Sender<Result<(), String>>)>> = HashMap::new();
    let mut in_flight:      HashMap<OutboundRequestId, oneshot::Sender<Result<(), String>>> = HashMap::new();

    loop {
        tokio::select! {
            cmd = rx.recv() => {
                let Some(cmd) = cmd else { break; };
                match cmd {
                    SwarmCmd::Send { peer_addr, msg, reply } => {
                        handle_send(&mut swarm, peer_addr, msg, reply, &mut pending_sends, &mut in_flight);
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
                    &mut swarm,
                ).await;
            }
        }
    }
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
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
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
        let _ = swarm.dial(peer_addr);
        pending_sends.entry(peer_id).or_default().push((msg, reply));
    }
}

fn peer_id_from_multiaddr(addr: &Multiaddr) -> Option<PeerId> {
    use libp2p::multiaddr::Protocol;
    addr.iter().find_map(|p| {
        if let Protocol::P2p(peer_id) = p { Some(peer_id) } else { None }
    })
}

fn best_endpoint(external_addrs: &[Multiaddr], peer_id: &PeerId) -> String {
    let is_public = |a: &Multiaddr| {
        let s = a.to_string();
        !s.starts_with("/ip4/127.") &&
        !s.starts_with("/ip4/10.")  &&
        !s.starts_with("/ip4/192.168.") &&
        !s.starts_with("/ip4/172.")
    };
    let base = external_addrs.iter().find(|a| is_public(a))
        .or_else(|| external_addrs.first())
        .map(|a| a.to_string())
        .unwrap_or_else(|| format!("/ip4/{}/tcp/{}", get_local_ip(), P2P_PORT));
    if base.contains("/p2p/") { base } else { format!("{}/p2p/{}", base, peer_id) }
}

// ── Swarm event handler ───────────────────────────────────────────────────────

async fn handle_event(
    event:         SwarmEvent<EgoBehaviourEvent>,
    app:           &tauri::AppHandle,
    external_addrs: &mut Vec<Multiaddr>,
    pending_sends: &mut HashMap<PeerId, Vec<(P2PMessage, oneshot::Sender<Result<(), String>>)>>,
    in_flight:     &mut HashMap<OutboundRequestId, oneshot::Sender<Result<(), String>>>,
    swarm:         &mut libp2p::Swarm<EgoBehaviour>,
) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            eprintln!("[P2P] Listening on {}", address);
        }

        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            eprintln!("[P2P] Connected to {}", peer_id);
            if let Some(pending) = pending_sends.remove(&peer_id) {
                for (msg, reply) in pending {
                    let req_id = swarm.behaviour_mut().request_response.send_request(&peer_id, msg);
                    in_flight.insert(req_id, reply);
                }
            }
        }

        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            if let Some(pending) = pending_sends.remove(&peer_id) {
                for (_, reply) in pending {
                    let _ = reply.send(Err("Connection closed before message could be sent".into()));
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

        // Identify: learn our own external addresses
        SwarmEvent::Behaviour(EgoBehaviourEvent::Identify(identify::Event::Received {
            info, ..
        })) => {
            for addr in &info.listen_addrs {
                if !external_addrs.contains(addr) {
                    external_addrs.push(addr.clone());
                }
            }
            let peer_id = *swarm.local_peer_id();
            let state = app.state::<crate::app::AppState>();
            state.set_public_endpoint(best_endpoint(external_addrs, &peer_id));
            let _ = app.emit_all("ego://p2p-status-changed", ());
        }

        // Request-response: incoming message
        SwarmEvent::Behaviour(EgoBehaviourEvent::RequestResponse(
            request_response::Event::Message {
                message: request_response::Message::Request { request, channel, .. },
                ..
            },
        )) => {
            let _ = swarm.behaviour_mut().request_response.send_response(channel, ());
            let app = app.clone();
            tokio::spawn(async move { handle_incoming(request, &app).await; });
        }

        // Request-response: our send succeeded
        SwarmEvent::Behaviour(EgoBehaviourEvent::RequestResponse(
            request_response::Event::Message {
                message: request_response::Message::Response { request_id, .. },
                ..
            },
        )) => {
            if let Some(reply) = in_flight.remove(&request_id) {
                let _ = reply.send(Ok(()));
            }
        }

        // Request-response: our send failed
        SwarmEvent::Behaviour(EgoBehaviourEvent::RequestResponse(
            request_response::Event::OutboundFailure { request_id, error, .. },
        )) => {
            if let Some(reply) = in_flight.remove(&request_id) {
                let _ = reply.send(Err(format!("Network error: {}", error)));
            }
        }

        // AutoNAT: detected NAT status
        SwarmEvent::Behaviour(EgoBehaviourEvent::Autonat(autonat::Event::StatusChanged {
            new, ..
        })) => {
            let state = app.state::<crate::app::AppState>();
            match new {
                autonat::NatStatus::Public(addr) => {
                    let peer_id = *swarm.local_peer_id();
                    eprintln!("[P2P] AutoNAT: public at {}", addr);
                    state.set_upnp_status(Ok(()));
                    state.set_public_endpoint(format!("{}/p2p/{}", addr, peer_id));
                    let _ = app.emit_all("ego://p2p-status-changed", ());
                }
                autonat::NatStatus::Private => {
                    eprintln!("[P2P] AutoNAT: behind NAT — using relay");
                    state.set_upnp_status(Err("Behind NAT — using relay for connectivity".into()));
                    let _ = app.emit_all("ego://p2p-status-changed", ());
                }
                autonat::NatStatus::Unknown => {}
            }
        }

        // Relay: reservation accepted — relay will forward inbound connections to us
        SwarmEvent::Behaviour(EgoBehaviourEvent::RelayClient(
            relay::client::Event::ReservationReqAccepted { relay_peer_id, .. },
        )) => {
            eprintln!("[P2P] Relay reservation accepted with {}", relay_peer_id);
            let peer_id = *swarm.local_peer_id();
            let state = app.state::<crate::app::AppState>();
            state.set_upnp_status(Ok(()));
            state.set_public_endpoint(best_endpoint(external_addrs, &peer_id));
            let _ = app.emit_all("ego://p2p-status-changed", ());
        }

        // DCUtR: hole punch attempt
        SwarmEvent::Behaviour(EgoBehaviourEvent::Dcutr(event)) => {
            eprintln!("[P2P] DCUtR event: {:?}", event);
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
            if contacts.iter().any(|c| c.address == from_addr) { return; }
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
            let _ = tauri::api::notification::Notification::new(&app.config().tauri.bundle.identifier)
                .title("Contact Request")
                .body(&format!("{} wants to connect with you", from_name))
                .show();
            let _ = app.emit_all("ego://contact-request", &contact);
        }

        P2PMessage::ContactResponse { from_addr, from_name, from_ed25519, from_kyber, approved, shared_key } => {
            let mut contacts = load_contacts();
            if approved {
                if let Some(pending) = contacts.iter_mut()
                    .find(|c| c.status == "pending_out" && c.shared_key_hex == shared_key)
                {
                    pending.address        = from_addr.clone();
                    pending.name           = from_name.clone();
                    pending.ed25519_pubkey = from_ed25519;
                    pending.kyber_pubkey   = from_kyber;
                    pending.status         = "approved".to_string();
                    let contact = pending.clone();
                    let _ = save_contacts(&contacts);
                    let _ = tauri::api::notification::Notification::new(&app.config().tauri.bundle.identifier)
                        .title("Contact Request Accepted!")
                        .body(&format!("{} accepted your request", from_name))
                        .show();
                    let _ = app.emit_all("ego://contact-approved", &contact);
                }
            } else {
                contacts.retain(|c| !(c.status == "pending_out" && c.shared_key_hex == shared_key));
                let _ = save_contacts(&contacts);
                let _ = tauri::api::notification::Notification::new(&app.config().tauri.bundle.identifier)
                    .title("Contact Request Declined")
                    .body("Your contact request was declined.")
                    .show();
                let _ = app.emit_all("ego://contact-declined", ());
            }
        }

        P2PMessage::PeerAnnounce { address, name, endpoint } => {
            let state = app.state::<crate::app::AppState>();
            state.upsert_peer(crate::app::PeerInfo {
                address:   address.clone(),
                name,
                endpoint:  endpoint.clone(),
                last_seen: Utc::now().timestamp(),
            });
            upsert_peer_cache(PeerEntry { address, endpoint, last_seen: Utc::now().timestamp() });
        }

        P2PMessage::ChatMessage { bundle } => {
            match crate::commands::messenger::receive_message_inner(&bundle) {
                Ok(msg) => {
                    let preview = if msg.content.len() > 40 {
                        format!("{}…", &msg.content[..40])
                    } else {
                        msg.content.clone()
                    };
                    let _ = tauri::api::notification::Notification::new(&app.config().tauri.bundle.identifier)
                        .title("New Message").body(&preview).show();
                    let _ = app.emit_all("ego://message-received", &msg);
                }
                Err(e) => eprintln!("[P2P] Decrypt error: {}", e),
            }
        }

        P2PMessage::TxBroadcast { tx, block } => {
            apply_incoming_tx(tx, block, app).await;
        }

        P2PMessage::ChainSyncRequest { requester_endpoint } => {
            let chain = load_chain();
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
            let known = load_peer_cache();
            let response = P2PMessage::PeerListResponse { peers: known };
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
