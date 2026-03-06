//! Ego Relay Server — libp2p circuit relay v2 + HTTP chain API.
//!
//! Runs two services in parallel:
//!   • libp2p swarm on TCP port 4001 — NAT traversal relay for all peers
//!   • axum HTTP server on TCP port 8080 — global chain seed node
//!
//! The HTTP API is the global source-of-truth for the blockchain.
//! Every Ego Desktop node fetches the chain from here on startup and
//! pushes every new confirmed tx/block back here so no local node can
//! delete or roll back the shared history.

use axum::{
    extract::State,
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
    fs,
    sync::{Arc, RwLock},
    time::Duration,
};

// ── Chain data model ──────────────────────────────────────────────────────────
// Mirrors the structs in ego-desktop's ledger.rs — kept in sync manually.

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

// ── Shared HTTP state ─────────────────────────────────────────────────────────

type ChainState = Arc<RwLock<SharedChain>>;

// ── HTTP handlers ─────────────────────────────────────────────────────────────

/// GET /chain — returns the full chain as JSON.
async fn get_chain(State(state): State<ChainState>) -> Json<SharedChain> {
    let chain = state.read().unwrap().clone();
    Json(chain)
}

/// GET /health — simple liveness probe.
async fn health() -> &'static str {
    "ok"
}

/// POST /chain/tx — accepts a confirmed transaction; deduplicates by hash.
async fn post_tx(
    State(state): State<ChainState>,
    Json(tx): Json<LedgerTx>,
) -> StatusCode {
    let mut chain = state.write().unwrap();
    if !chain.transactions.iter().any(|t| t.hash == tx.hash) {
        println!("[chain] New tx {} from {} → {} ({} uEGOC)", tx.hash, tx.from, tx.to, tx.amount);
        chain.transactions.push(tx);
        save_chain(&chain);
    }
    StatusCode::OK
}

/// POST /chain/block — accepts a mined block; deduplicates by hash.
async fn post_block(
    State(state): State<ChainState>,
    Json(block): Json<LedgerBlock>,
) -> StatusCode {
    let mut chain = state.write().unwrap();
    if !chain.blocks.iter().any(|b| b.hash == block.hash) {
        println!("[chain] New block #{} hash {}", block.height, block.hash);
        chain.blocks.push(block);
        // keep blocks sorted by height
        chain.blocks.sort_by_key(|b| b.height);
        save_chain(&chain);
    }
    StatusCode::OK
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
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(4001);

    let http_port = std::env::var("EGO_HTTP_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8080);

    // ── Load persisted chain ──────────────────────────────────────────────
    let chain_state: ChainState = Arc::new(RwLock::new(load_chain()));
    {
        let c = chain_state.read().unwrap();
        println!("[chain] Loaded {} blocks, {} txs from {}", c.blocks.len(), c.transactions.len(), CHAIN_PATH);
    }

    // ── Start HTTP API in background ──────────────────────────────────────
    let http_state = chain_state.clone();
    let http_addr  = format!("0.0.0.0:{}", http_port);
    tokio::spawn(async move {
        let app = Router::new()
            .route("/chain",       get(get_chain))
            .route("/chain/tx",    post(post_tx))
            .route("/chain/block", post(post_block))
            .route("/health",      get(health))
            .with_state(http_state);

        let listener = tokio::net::TcpListener::bind(&http_addr).await
            .expect("HTTP bind failed");
        println!("[http] Chain API listening on {}", http_addr);
        axum::serve(listener, app).await.expect("HTTP server error");
    });

    // ── Build libp2p swarm ────────────────────────────────────────────────
    let mut swarm = SwarmBuilder::with_existing_identity(identity.clone())
        .with_tokio()
        .with_tcp(tcp::Config::default().nodelay(true), noise::Config::new, yamux::Config::default)
        .expect("TCP transport")
        .with_behaviour(|key| RelayBehaviour {
            relay: relay::Behaviour::new(
                peer_id,
                relay::Config {
                    max_reservations:          1024,
                    max_reservations_per_peer: 8,
                    reservation_duration:      Duration::from_secs(3600),
                    max_circuits:              512,
                    max_circuits_per_peer:     16,
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
    println!("║       Ego Relay + Chain Seed v0.2.0       ║");
    println!("╚═══════════════════════════════════════════╝");
    println!("Peer ID   : {}", peer_id);
    println!("P2P port  : {}", p2p_port);
    println!("HTTP port : {}", http_port);
    println!();
    println!("RELAY_NODES in p2p.rs:");
    println!("  \"/ip4/<PUBLIC_IP>/tcp/{}/p2p/{}\",", p2p_port, peer_id);
    println!();
    println!("RELAY_HTTP_API in p2p.rs:");
    println!("  \"http://<PUBLIC_IP>:{}\",", http_port);
    println!();

    // ── Event loop ────────────────────────────────────────────────────────
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                println!("[relay] Listening on {}", address);
                println!("[relay] Share with peers: {}/p2p/{}", address, peer_id);
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
