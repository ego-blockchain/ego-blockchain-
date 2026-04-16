mod mailbox;
mod alerts;
mod chain;
mod hosting;
mod dns;

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

    // ── Hosting gateway ───────────────────────────────────────────────────────
    let hosting_cfg   = std::sync::Arc::new(hosting::HostingConfig::from_env());
    let hosting_state = hosting::new_hosting_state(hosting_cfg);

    // API routes merged into the mailbox server
    let http_app = mailbox::router(store)
        .merge(alerts::alert_router(alert_store))
        .merge(chain::chain_router(chain_store))
        .nest("/api/hosting", hosting::api_router(hosting_state.clone()));

    let http_bind  = format!("0.0.0.0:{}", MAILBOX_PORT);
    let http_listener = tokio::net::TcpListener::bind(&http_bind).await?;
    info!("[Mailbox] HTTP listening on {}", http_bind);
    tokio::spawn(async move {
        axum::serve(http_listener, http_app).await.unwrap();
    });

    // ── HTTP gateway (port 80) — serves sites by Host header ─────────────────
    let gw_port: u16 = std::env::var("GATEWAY_HTTP_PORT").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(80);
    let gw_bind = format!("0.0.0.0:{}", gw_port);
    if let Ok(gw_listener) = tokio::net::TcpListener::bind(&gw_bind).await {
        info!("[Gateway] HTTP listening on {} (.eo sites)", gw_bind);
        let gw_app = hosting::gateway_router(hosting_state.clone());
        tokio::spawn(async move {
            axum::serve(gw_listener, gw_app).await.unwrap();
        });
    } else {
        info!("[Gateway] Could not bind port {} — try GATEWAY_HTTP_PORT env var", gw_port);
    }

    // ── HTTPS gateway (port 443) — if TLS certs are provided ─────────────────
    let tls_cert = std::env::var("TLS_CERT_PATH").ok();
    let tls_key  = std::env::var("TLS_KEY_PATH").ok();
    let https_port: u16 = std::env::var("GATEWAY_HTTPS_PORT").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(443);

    if let (Some(cert_path), Some(key_path)) = (tls_cert, tls_key) {
        let cert_pem = std::fs::read_to_string(&cert_path)
            .unwrap_or_else(|_| String::new());
        let key_pem = std::fs::read_to_string(&key_path)
            .unwrap_or_else(|_| String::new());
        if !cert_pem.is_empty() && !key_pem.is_empty() {
            match axum_server::tls_rustls::RustlsConfig::from_pem(
                cert_pem.into_bytes(),
                key_pem.into_bytes(),
            ).await {
                Ok(tls_cfg) => {
                    let https_addr = std::net::SocketAddr::from(([0, 0, 0, 0], https_port));
                    info!("[Gateway] HTTPS listening on {} (.eo sites)", https_addr);
                    let gw_app = hosting::gateway_router(hosting_state.clone());
                    tokio::spawn(async move {
                        axum_server::bind_rustls(https_addr, tls_cfg)
                            .serve(gw_app.into_make_service())
                            .await
                            .unwrap_or_else(|e| tracing::error!("[Gateway] HTTPS error: {}", e));
                    });
                }
                Err(e) => tracing::warn!("[Gateway] TLS config error: {}", e),
            }
        } else {
            tracing::warn!("[Gateway] TLS_CERT_PATH / TLS_KEY_PATH set but files empty — skipping HTTPS");
        }
    } else {
        info!("[Gateway] No TLS certs (set TLS_CERT_PATH + TLS_KEY_PATH for HTTPS)");
    }

    // ── DNS server (port 53) — resolves *.eo to this server ──────────────────
    let relay_ip_str = std::env::var("RELAY_PUBLIC_IP").unwrap_or_else(|_| "127.0.0.1".to_string());
    let dns_upstream = std::env::var("DNS_UPSTREAM").unwrap_or_else(|_| "8.8.8.8:53".to_string());
    let relay_ip: [u8; 4] = relay_ip_str.split('.')
        .map(|p| p.parse::<u8>().unwrap_or(0))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap_or([127, 0, 0, 1]);
    tokio::spawn(async move {
        dns::run_dns_server(relay_ip, &dns_upstream).await;
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
