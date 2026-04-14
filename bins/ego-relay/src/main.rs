mod mailbox;
mod alerts;
mod chain;

use futures::StreamExt;
use libp2p::{
    identify, noise, ping, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId,
};
use std::{fs, path::Path, time::Duration};
use tracing::info;

const LISTEN_PORT: u16      = 4001;
const MAILBOX_PORT: u16     = 4002;
const KEY_FILE: &str        = "ego-relay.key";

#[derive(NetworkBehaviour)]
struct RelayBehaviour {
    relay:    relay::Behaviour,
    identify: identify::Behaviour,
    ping:     ping::Behaviour,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).init();

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
    info!("║  P2P  port: {}                                    ║", LISTEN_PORT);
    info!("║  HTTP port: {}                                    ║", MAILBOX_PORT);
    info!("╚══════════════════════════════════════════════════════╝");

    let store        = mailbox::new_store();
    let alert_store  = alerts::new_alert_store();
    let chain_store  = chain::new_chain_store();
    let http_app     = mailbox::router(store)
        .merge(alerts::alert_router(alert_store))
        .merge(chain::chain_router(chain_store));
    let http_bind  = format!("0.0.0.0:{}", MAILBOX_PORT);
    let http_listener = tokio::net::TcpListener::bind(&http_bind).await?;
    info!("[Mailbox] HTTP listening on {}", http_bind);
    tokio::spawn(async move {
        axum::serve(http_listener, http_app).await.unwrap();
    });

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
                    max_reservations:          1024,
                    max_reservations_per_peer: 4,
                    reservation_duration:      Duration::from_secs(3600),
                    max_circuits:              4096,
                    max_circuits_per_peer:     64,
                    max_circuit_duration:      Duration::from_secs(7200),
                    max_circuit_bytes:         u64::MAX,
                    ..Default::default()
                },
            ),
            identify: identify::Behaviour::new(identify::Config::new(
                "/ego/relay/1.0.0".into(),
                key.public(),
            )),
            ping: ping::Behaviour::new(
                ping::Config::new()
                    .with_interval(Duration::from_secs(30))
                    .with_timeout(Duration::from_secs(20)),
            ),
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(7200)))
        .build();

    let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", LISTEN_PORT).parse()?;
    swarm.listen_on(listen_addr)?;

    let public_addr: Multiaddr =
        format!("/dns4/EgoRelay.egoblockchain.com/tcp/{}", LISTEN_PORT).parse()?;
    swarm.add_external_address(public_addr);

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
            SwarmEvent::Behaviour(event) => match event {
                RelayBehaviourEvent::Relay(
                    relay::Event::ReservationReqAccepted { src_peer_id, .. }
                ) => {
                    info!("[Relay] Reservation accepted for {}", src_peer_id);
                }
                RelayBehaviourEvent::Relay(
                    relay::Event::CircuitReqAccepted { src_peer_id, dst_peer_id, .. }
                ) => {
                    info!("[Relay] Circuit opened: {} → {}", src_peer_id, dst_peer_id);
                }
                RelayBehaviourEvent::Relay(
                    relay::Event::ReservationReqDenied { src_peer_id, status }
                ) => {
                    info!("[Relay] Reservation DENIED for {} — status: {:?}", src_peer_id, status);
                }
                RelayBehaviourEvent::Relay(
                    relay::Event::CircuitReqDenied { src_peer_id, dst_peer_id, status }
                ) => {
                    info!("[Relay] Circuit DENIED: {} → {} — status: {:?}", src_peer_id, dst_peer_id, status);
                }
                _ => {}
            },
            _ => {}
        }
    }
}
