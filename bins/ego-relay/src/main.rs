//! Ego Relay — minimal libp2p circuit-relay + DHT bootstrap server.
//!
//! Listens on port 4001 (TCP + QUIC).
//! Saves its keypair to `ego-relay.key` so the peer ID is stable across restarts.
//! Prints the peer ID on startup — copy it into RELAY_NODES in p2p.rs.

use futures::StreamExt;
use libp2p::{
    identify, kad, noise, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId,
};
use std::{fs, path::Path, time::Duration};
use tracing::info;

const LISTEN_PORT: u16 = 4001;
const KEY_FILE: &str   = "ego-relay.key";

// ── Behaviour ────────────────────────────────────────────────────────────────

#[derive(NetworkBehaviour)]
struct RelayBehaviour {
    relay:    relay::Behaviour,
    identify: identify::Behaviour,
    kad:      kad::Behaviour<kad::store::MemoryStore>,
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).init();

    // ── 1. Load or generate a stable keypair ─────────────────────────────────
    let keypair = if Path::new(KEY_FILE).exists() {
        let bytes = fs::read(KEY_FILE)?;
        libp2p::identity::Keypair::from_protobuf_encoding(&bytes)?
    } else {
        let kp = libp2p::identity::Keypair::generate_ed25519();
        fs::write(KEY_FILE, kp.to_protobuf_encoding()?)?;
        kp
    };

    let local_peer_id = PeerId::from(&keypair.public());
    info!("╔══════════════════════════════════════════════════════╗");
    info!("║  Ego Relay started                                   ║");
    info!("║  Peer ID: {:<42} ║", local_peer_id);
    info!("║  Copy the Peer ID above into RELAY_NODES in p2p.rs  ║");
    info!("╚══════════════════════════════════════════════════════╝");

    // ── 2. Build transport + behaviour ───────────────────────────────────────
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| RelayBehaviour {
            relay: relay::Behaviour::new(
                local_peer_id,
                relay::Config {
                    max_reservations:             512,
                    max_reservations_per_peer:     8,
                    reservation_duration:          Duration::from_secs(3600),
                    max_circuits:                  512,
                    max_circuits_per_peer:         8,
                    max_circuit_duration:          Duration::from_secs(3600),
                    max_circuit_bytes:             0,  // unlimited
                    ..Default::default()
                },
            ),
            identify: identify::Behaviour::new(identify::Config::new(
                "/ego/relay/1.0.0".into(),
                key.public(),
            )),
            kad: {
                let mut k = kad::Behaviour::new(
                    local_peer_id,
                    kad::store::MemoryStore::new(local_peer_id),
                );
                k.set_mode(Some(kad::Mode::Server));
                k
            },
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    // ── 3. Listen on TCP 0.0.0.0:4001 ───────────────────────────────────────
    let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", LISTEN_PORT).parse()?;
    swarm.listen_on(listen_addr)?;

    // ── 4. Event loop ────────────────────────────────────────────────────────
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("[Relay] Listening on {}/p2p/{}", address, local_peer_id);
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                info!("[Relay] Peer connected: {}", peer_id);
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                info!("[Relay] Peer disconnected: {} ({:?})", peer_id, cause);
            }
            SwarmEvent::Behaviour(event) => {
                match event {
                    RelayBehaviourEvent::Relay(relay::Event::ReservationReqAccepted { src_peer_id, .. }) => {
                        info!("[Relay] Circuit reservation accepted for {}", src_peer_id);
                    }
                    RelayBehaviourEvent::Relay(relay::Event::CircuitReqAccepted { src_peer_id, .. }) => {
                        info!("[Relay] Circuit opened for {}", src_peer_id);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}
