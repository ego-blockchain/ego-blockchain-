//! Ego Relay Server — libp2p circuit relay v2 + HTTP chain/peer API.
//!
//! HTTP endpoints:
//!   GET  /chain            — full global blockchain
//!   POST /chain/tx         — submit a confirmed transaction
//!   POST /chain/block      — submit a mined block
//!   GET  /peers            — list all known peer endpoints
//!   POST /peers            — register/update your relay circuit address
//!   POST /inbox/:address   — store a message for an offline peer
//!   GET  /inbox/:address   — fetch and clear pending messages (called on startup)
//!   GET  /health           — liveness probe

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use futures::StreamExt;
use libp2p::{
    identify, noise, ping, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, SwarmBuilder,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    sync::{Arc, RwLock},
    time::Duration,
};

// ── Chain data model ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SharedChain {
    blocks:       Vec<LedgerBlock>,
    transactions: Vec<LedgerTx>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerBlock {
    height:     u64,
    hash:       String,
    prev_hash:  String,
    timestamp:  i64,
    miner:      String,
    tx_count:   u32,
    size_bytes: u64,
    reward:     u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerTx {
    hash:         String,
    from:         String,
    to:           String,
    amount:       u64,
    memo:         Option<String>,
    timestamp:    i64,
    signature:    String,
    status:       String,
    block_height: Option<u64>,
    #[serde(default)]
    nonce: u64,
}

// ── Persistent chain storage ──────────────────────────────────────────────────

const CHAIN_PATH: &str = "chain.json";

fn load_chain() -> SharedChain {
    if let Ok(data) = fs::read_to_string(CHAIN_PATH) {
        if let Ok(c) = serde_json::from_str::<SharedChain>(&data) {
            return c;
        }
    }
    SharedChain::default()
}

fn save_chain(chain: &SharedChain) {
    if let Ok(data) = serde_json::to_string_pretty(chain) {
        let _ = fs::write(CHAIN_PATH, data);
    }
}

// ── Peer directory ────────────────────────────────────────────────────────────

const PEERS_PATH: &str = "peers.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PeerEntry {
    address:   String,
    name:      String,
    endpoint:  String,
    last_seen: i64,
    #[serde(default)]
    city:    Option<String>,
    #[serde(default)]
    country: Option<String>,
}

fn load_peers() -> Vec<PeerEntry> {
    if let Ok(data) = fs::read_to_string(PEERS_PATH) {
        if let Ok(p) = serde_json::from_str::<Vec<PeerEntry>>(&data) {
            return p;
        }
    }
    Vec::new()
}

fn save_peers(peers: &[PeerEntry]) {
    if let Ok(data) = serde_json::to_string_pretty(peers) {
        let _ = fs::write(PEERS_PATH, data);
    }
}

// ── Inbox (store-and-forward) ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InboxMessage {
    /// JSON-serialised P2PMessage, base64-encoded
    payload:   String,
    deposited: i64,
    from_addr: String,
}

// ── Shared HTTP state ─────────────────────────────────────────────────────────

type ChainState = Arc<RwLock<SharedChain>>;
type PeersState = Arc<RwLock<Vec<PeerEntry>>>;
type InboxState = Arc<RwLock<HashMap<String, Vec<InboxMessage>>>>;

#[derive(Clone)]
struct AppState {
    chain: ChainState,
    peers: PeersState,
    inbox: InboxState,
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

async fn get_chain(State(s): State<AppState>) -> Json<SharedChain> {
    Json(s.chain.read().unwrap().clone())
}

async fn health() -> &'static str { "ok" }

async fn get_peers(State(s): State<AppState>) -> Json<Vec<PeerEntry>> {
    Json(s.peers.read().unwrap().clone())
}

async fn post_peer(
    State(s): State<AppState>,
    Json(entry): Json<PeerEntry>,
) -> StatusCode {
    if entry.address.is_empty() || entry.endpoint.is_empty() {
        return StatusCode::BAD_REQUEST;
    }
    let mut list = s.peers.write().unwrap();
    let now = chrono::Utc::now().timestamp();
    if let Some(existing) = list.iter_mut().find(|p| p.address == entry.address) {
        existing.endpoint  = entry.endpoint.clone();
        existing.name      = entry.name.clone();
        existing.last_seen = now;
        if entry.city.is_some()    { existing.city    = entry.city.clone(); }
        if entry.country.is_some() { existing.country = entry.country.clone(); }
        println!("[peers] Updated endpoint for {} → {}", entry.address, entry.endpoint);
    } else {
        println!("[peers] New peer {} → {}", entry.address, entry.endpoint);
        list.push(PeerEntry { last_seen: now, ..entry });
    }
    let cutoff = now - 600;
    list.retain(|p| p.last_seen >= cutoff);
    save_peers(&list);
    StatusCode::OK
}

async fn post_tx(
    State(s): State<AppState>,
    Json(tx): Json<LedgerTx>,
) -> StatusCode {
    let mut chain = s.chain.write().unwrap();
    if !chain.transactions.iter().any(|t| t.hash == tx.hash) {
        println!("[chain] New tx {} from {} → {} ({} uEGOC)", tx.hash, tx.from, tx.to, tx.amount);
        chain.transactions.push(tx);
        save_chain(&chain);
    }
    StatusCode::OK
}

async fn post_block(
    State(s): State<AppState>,
    Json(block): Json<LedgerBlock>,
) -> StatusCode {
    let mut chain = s.chain.write().unwrap();
    if !chain.blocks.iter().any(|b| b.hash == block.hash) {
        println!("[chain] New block #{} hash {}", block.height, block.hash);
        chain.blocks.push(block);
        chain.blocks.sort_by_key(|b| b.height);
        save_chain(&chain);
    }
    StatusCode::OK
}

/// POST /inbox/:address — deposit a message for an offline peer.
/// The desktop calls this when direct P2P delivery fails.
async fn post_inbox(
    Path(address): Path<String>,
    State(s): State<AppState>,
    Json(msg): Json<InboxMessage>,
) -> StatusCode {
    if address.is_empty() || msg.payload.is_empty() {
        return StatusCode::BAD_REQUEST;
    }
    let mut map = s.inbox.write().unwrap();
    let bucket = map.entry(address.clone()).or_default();
    // Deduplicate by payload so retries don't stack up
    if !bucket.iter().any(|m| m.payload == msg.payload) {
        println!("[inbox] Stored message for {} from {}", address, msg.from_addr);
        bucket.push(msg);
    }
    StatusCode::OK
}

/// GET /inbox/:address — fetch and clear all pending messages.
/// The desktop calls this on every startup to receive offline messages.
async fn get_inbox(
    Path(address): Path<String>,
    State(s): State<AppState>,
) -> Json<Vec<InboxMessage>> {
    let mut map = s.inbox.write().unwrap();
    let msgs = map.remove(&address).unwrap_or_default();
    if !msgs.is_empty() {
        println!("[inbox] Delivered {} message(s) to {}", msgs.len(), address);
    }
    Json(msgs)
}

// ── libp2p relay behaviour ────────────────────────────────────────────────────

#[derive(NetworkBehaviour)]
struct RelayBehaviour {
    relay:    relay::Behaviour,
    identify: identify::Behaviour,
    ping:     ping::Behaviour,
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let identity = load_or_create_identity();
    let peer_id  = identity.public().to_peer_id();

    let p2p_port = std::env::var("EGO_RELAY_PORT")
        .ok().and_then(|p| p.parse::<u16>().ok()).unwrap_or(4001);
    let http_port = std::env::var("EGO_HTTP_PORT")
        .ok().and_then(|p| p.parse::<u16>().ok()).unwrap_or(8080);

    let state = AppState {
        chain: Arc::new(RwLock::new(load_chain())),
        peers: Arc::new(RwLock::new(load_peers())),
        inbox: Arc::new(RwLock::new(HashMap::new())),
    };
    {
        let c = state.chain.read().unwrap();
        let p = state.peers.read().unwrap();
        println!("[chain] Loaded {} blocks, {} txs from {}", c.blocks.len(), c.transactions.len(), CHAIN_PATH);
        println!("[peers] Loaded {} known peers from {}", p.len(), PEERS_PATH);
    }

    let http_addr = format!("0.0.0.0:{}", http_port);
    let state_clone = state.clone();
    tokio::spawn(async move {
        let app = Router::new()
            .route("/chain",          get(get_chain))
            .route("/chain/tx",       post(post_tx))
            .route("/chain/block",    post(post_block))
            .route("/peers",          get(get_peers).post(post_peer))
            .route("/inbox/:address", get(get_inbox).post(post_inbox))
            .route("/health",         get(health))
            .with_state(state_clone);

        let listener = tokio::net::TcpListener::bind(&http_addr).await
            .expect("HTTP bind failed");
        println!("[http] Listening on {}", http_addr);
        axum::serve(listener, app).await.expect("HTTP server error");
    });

    let mut swarm = SwarmBuilder::with_existing_identity(identity.clone())
        .with_tokio()
        .with_tcp(tcp::Config::default().nodelay(true), noise::Config::new, yamux::Config::default)
        .expect("TCP transport")
        .with_behaviour(|key| RelayBehaviour {
            relay: relay::Behaviour::new(
                peer_id,
                relay::Config {
                    max_reservations:          1024,
                    max_reservations_per_peer: 32,
                    reservation_duration:      Duration::from_secs(3600),
                    max_circuits:              2048,
                    max_circuits_per_peer:     128,
                    max_circuit_duration:      Duration::from_secs(7200),
                    max_circuit_bytes:         0,
                    ..Default::default()
                },
            ),
            identify: identify::Behaviour::new(
                identify::Config::new("/ego/identify/1.0.0".to_string(), key.public())
                    .with_interval(Duration::from_secs(60)),
            ),
            ping: ping::Behaviour::new(
                ping::Config::new().with_interval(Duration::from_secs(30)),
            ),
        })
        .expect("behaviour")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(3600)))
        .build();

    let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", p2p_port).parse().unwrap();
    swarm.listen_on(listen_addr).expect("listen");

    println!("╔═══════════════════════════════════════════╗");
    println!("║       Ego Relay + Chain Seed v0.3.0       ║");
    println!("╚═══════════════════════════════════════════╝");
    println!("Peer ID   : {}", peer_id);
    println!("P2P port  : {}", p2p_port);
    println!("HTTP port : {}", http_port);

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                println!("[relay] Listening on {}", address);
            }
            SwarmEvent::ConnectionEstablished { peer_id: pid, .. } => {
                println!("[relay] Peer connected: {}", pid);
            }
            SwarmEvent::ConnectionClosed { peer_id: pid, .. } => {
                println!("[relay] Peer disconnected: {}", pid);
            }
            SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(
                relay::Event::ReservationReqAccepted { src_peer_id, .. },
            )) => {
                println!("[relay] Reservation accepted for {}", src_peer_id);
            }
            SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(
                relay::Event::CircuitReqAccepted { src_peer_id, dst_peer_id, .. },
            )) => {
                println!("[relay] Circuit: {} -> {}", src_peer_id, dst_peer_id);
            }
            _ => {}
        }
    }
}

fn load_or_create_identity() -> libp2p::identity::Keypair {
    let path = "relay_identity.bin";
    if let Ok(bytes) = fs::read(path) {
        if let Ok(kp) = libp2p::identity::Keypair::from_protobuf_encoding(&bytes) {
            return kp;
        }
    }
    let kp = libp2p::identity::Keypair::generate_ed25519();
    if let Ok(bytes) = kp.to_protobuf_encoding() {
        fs::write(path, bytes).expect("write identity");
    }
    kp
}