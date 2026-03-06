//! Ego Relay Server — minimal libp2p circuit relay v2 server.
//! Deploy this on any public VPS. All Ego Desktop peers connect here
//! for NAT traversal and peer discovery without port forwarding.

use futures::StreamExt;
use libp2p::{
    identify, noise, ping, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, SwarmBuilder,
};
use std::{fs, time::Duration};

#[derive(NetworkBehaviour)]
struct RelayBehaviour {
    relay:    relay::Behaviour,
    identify: identify::Behaviour,
    ping:     ping::Behaviour,
}

#[tokio::main]
async fn main() {
    let identity = load_or_create_identity();
    let peer_id  = identity.public().to_peer_id();

    let port = std::env::var("EGO_RELAY_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(4001);

    let mut swarm = SwarmBuilder::with_existing_identity(identity.clone())
        .with_tokio()
        .with_tcp(tcp::Config::default().nodelay(true), noise::Config::new, yamux::Config::default)
        .expect("TCP transport")
        .with_behaviour(|key| RelayBehaviour {
            relay: relay::Behaviour::new(
                peer_id,
                relay::Config {
                    max_reservations:           1024,
                    max_reservations_per_peer:  8,
                    reservation_duration:       Duration::from_secs(3600),
                    max_circuits:               512,
                    max_circuits_per_peer:      16,
                    max_circuit_duration:       Duration::from_secs(7200),
                    max_circuit_bytes:          0, // unlimited
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

    let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", port).parse().unwrap();
    swarm.listen_on(listen_addr).expect("listen");

    println!("╔═══════════════════════════════════════════╗");
    println!("║          Ego Relay Server v0.1.0          ║");
    println!("╚═══════════════════════════════════════════╝");
    println!("Peer ID : {}", peer_id);
    println!("Port    : {}", port);
    println!();
    println!("Add this to RELAY_NODES in p2p.rs once you know the public IP:");
    println!("  \"/ip4/<YOUR_PUBLIC_IP>/tcp/{}/p2p/{}\"", port, peer_id);
    println!();

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
