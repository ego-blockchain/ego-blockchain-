use base64::Engine as _;
use futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{Multiaddr, PeerId, StreamProtocol};
use serde_json::Value;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;

pub const PROTOCOL: StreamProtocol = StreamProtocol::new("/ego/rpc/1");
const MAX_CONNECTIONS: u32 = 512;
const MAX_CONNECTIONS_PER_PEER: u32 = 2;
const MAX_PENDING: u32 = 64;
const MAX_REQUESTS_AT_ONCE: usize = 256;
const IDLE: Duration = Duration::from_secs(60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const NEVER_EXPIRES_SECS: u64 = 64_060_588_800;

static REMOTE: Mutex<Option<HashMap<PeerId, IpAddr>>> = Mutex::new(None);

#[derive(NetworkBehaviour)]
struct Behaviour {
    limits: libp2p::connection_limits::Behaviour,
    stream: libp2p_stream::Behaviour,
}

fn pem_body(pem: &str, label: &str) -> Option<String> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = pem.find(&begin)? + begin.len();
    let stop = start + pem[start..].find(&end)?;
    let body: String = pem[start..stop].split_whitespace().collect();
    (!body.is_empty()).then_some(body)
}

fn block(label: &str, body: &str) -> String {
    let lines: Vec<&str> = body.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap_or_default()).collect();
    format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", lines.join("\n"))
}

fn webrtc_pem(cert_pem: &str, key_pem: &str) -> Option<String> {
    let key = pem_body(key_pem, "PRIVATE KEY")?;
    let cert = pem_body(cert_pem, "CERTIFICATE")?;
    let expires = base64::engine::general_purpose::STANDARD.encode(NEVER_EXPIRES_SECS.to_le_bytes());
    Some(format!("{}\n{}\n{}", block("EXPIRES", &expires), block("PRIVATE_KEY", &key), block("CERTIFICATE", &cert)))
}

fn certificate(cert_pem: &str, key_pem: &str, cert_sha256: &str) -> Result<libp2p_webrtc::tokio::Certificate, String> {
    let pem = webrtc_pem(cert_pem, key_pem).ok_or("the gateway certificate files are damaged")?;
    let cert = libp2p_webrtc::tokio::Certificate::from_pem(&pem).map_err(|e| e.to_string())?;
    if hex::encode(cert.fingerprint().to_multihash().digest()) != cert_sha256 {
        return Err("the WebRTC certificate does not match the gateway certificate".into());
    }
    Ok(cert)
}

fn ip_of(addr: &Multiaddr) -> Option<IpAddr> {
    addr.iter().find_map(|p| match p {
        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    })
}

fn remote(f: impl FnOnce(&mut HashMap<PeerId, IpAddr>)) {
    let mut guard = REMOTE.lock().unwrap_or_else(|e| e.into_inner());
    f(guard.get_or_insert_with(HashMap::new));
}

fn remote_ip(peer: &PeerId) -> Option<IpAddr> {
    REMOTE.lock().unwrap_or_else(|e| e.into_inner()).as_ref().and_then(|m| m.get(peer).copied())
}

async fn reply_to(ip: IpAddr, frame: &[u8]) -> Value {
    let Ok(body) = serde_json::from_slice::<Value>(frame) else {
        return crate::gateway::fail(Value::Null, -32700, "That request isn't valid JSON.");
    };
    let method = body.get("method").and_then(Value::as_str).unwrap_or_default();
    if !crate::gateway::fits(method, frame.len()) {
        let id = body.get("id").cloned().unwrap_or(Value::Null);
        return crate::gateway::fail(id, -32600, "That request is too large for this gateway.");
    }
    match crate::gateway::answer(ip, body).await {
        Ok(reply) | Err(reply) => reply,
    }
}

async fn serve_stream<S>(ip: IpAddr, mut stream: S, limit: Arc<Semaphore>) -> Result<(), String>
where
    S: futures::AsyncRead + futures::AsyncWrite + Unpin,
{
    loop {
        let frame = match tokio::time::timeout(IDLE, crate::p2p::read_frame(&mut stream, crate::gateway::MAX_STORAGE_BODY_BYTES)).await {
            Ok(frame) => frame?,
            Err(_) => return Ok(()),
        };
        let reply = {
            let _permit = limit.acquire().await.map_err(|e| e.to_string())?;
            tokio::time::timeout(REQUEST_TIMEOUT, reply_to(ip, &frame))
                .await
                .unwrap_or_else(|_| crate::gateway::fail(Value::Null, -32603, "The gateway took too long to answer."))
        };
        let data = serde_json::to_vec(&reply).map_err(|e| e.to_string())?;
        crate::p2p::write_frame(&mut stream, &data).await?;
    }
}

async fn accept_loop(mut incoming: libp2p_stream::IncomingStreams) {
    let limit = Arc::new(Semaphore::new(MAX_REQUESTS_AT_ONCE));
    while let Some((peer, stream)) = incoming.next().await {
        let Some(ip) = remote_ip(&peer) else { continue };
        let limit = limit.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_stream(ip, stream, limit).await {
                tracing::debug!("[gateway] WebRTC stream from {peer} ended: {e}");
            }
        });
    }
}

async fn run(cert_pem: &str, key_pem: &str, cert_sha256: &str, port: u16, listening: Option<tokio::sync::oneshot::Sender<Multiaddr>>) -> Result<(), String> {
    let certificate = certificate(cert_pem, key_pem, cert_sha256)?;
    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_other_transport(|key| libp2p_webrtc::tokio::Transport::new(key.clone(), certificate))
        .map_err(|e| e.to_string())?
        .with_behaviour(|_| Behaviour {
            limits: libp2p::connection_limits::Behaviour::new(
                libp2p::connection_limits::ConnectionLimits::default()
                    .with_max_established(Some(MAX_CONNECTIONS))
                    .with_max_established_per_peer(Some(MAX_CONNECTIONS_PER_PEER))
                    .with_max_pending_incoming(Some(MAX_PENDING)),
            ),
            stream: libp2p_stream::Behaviour::new(),
        })
        .map_err(|e| e.to_string())?
        .with_swarm_config(|c| c.with_idle_connection_timeout(IDLE))
        .build();
    let incoming = swarm.behaviour().stream.new_control().accept(PROTOCOL).map_err(|e| e.to_string())?;
    let listen: Multiaddr = format!("/ip4/0.0.0.0/udp/{port}/webrtc-direct").parse().map_err(|e: libp2p::multiaddr::Error| e.to_string())?;
    swarm.listen_on(listen).map_err(|e| e.to_string())?;
    tokio::spawn(accept_loop(incoming));
    let mut listening = listening;
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                eprintln!("[Gateway] browsers can connect over WebRTC at {address}");
                if let Some(tx) = listening.take() {
                    let _ = tx.send(address);
                }
            }
            SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                if let Some(ip) = ip_of(endpoint.get_remote_address()) {
                    remote(|m| {
                        m.insert(peer_id, ip);
                    });
                }
            }
            SwarmEvent::ConnectionClosed { peer_id, num_established: 0, .. } => remote(|m| {
                m.remove(&peer_id);
            }),
            SwarmEvent::ListenerClosed { reason, .. } => {
                return Err(match reason {
                    Ok(()) => "the WebRTC listener closed".to_string(),
                    Err(e) => e.to_string(),
                })
            }
            SwarmEvent::ListenerError { error, .. } => return Err(error.to_string()),
            _ => {}
        }
    }
}

pub async fn serve(cert_pem: String, key_pem: String, cert_sha256: String, port: u16) {
    if let Err(e) = run(&cert_pem, &key_pem, &cert_sha256, port, None).await {
        eprintln!("[Gateway] browsers can't connect over WebRTC on UDP port {port}: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn gateway_style_cert() -> (String, String, String) {
        let cert = rcgen::generate_simple_self_signed(vec!["ego-gateway".to_string()]).unwrap();
        let cert_pem = cert.serialize_pem().unwrap();
        let key_pem = cert.serialize_private_key_pem();
        let der = base64::engine::general_purpose::STANDARD.decode(pem_body(&cert_pem, "CERTIFICATE").unwrap()).unwrap();
        (cert_pem, key_pem, hex::encode(Sha256::digest(&der)))
    }

    #[test]
    fn browsers_pin_the_same_certificate_the_gateway_list_already_publishes() {
        let (cert_pem, key_pem, sha) = gateway_style_cert();
        if let Err(e) = certificate(&cert_pem, &key_pem, &sha) {
            panic!("the HTTPS certificate is reused as is: {e}");
        }
        let (_, _, other) = gateway_style_cert();
        assert!(certificate(&cert_pem, &key_pem, &other).is_err(), "a fingerprint that does not match is refused");
        assert!(certificate("not a certificate", &key_pem, &sha).is_err());
    }

    #[test]
    fn the_caller_is_rate_limited_by_its_address() {
        let addr: Multiaddr = "/ip4/203.0.113.7/udp/40000/webrtc-direct".parse().unwrap();
        assert_eq!(ip_of(&addr), Some("203.0.113.7".parse().unwrap()));
        assert_eq!(ip_of(&"/dns4/example.com/tcp/1".parse().unwrap()), None);
    }

    #[tokio::test]
    async fn bad_and_oversized_requests_get_a_json_rpc_error() {
        let ip: IpAddr = "203.0.113.8".parse().unwrap();
        assert_eq!(reply_to(ip, b"{not json").await["error"]["code"], -32700);
        let big = serde_json::to_vec(&serde_json::json!({ "jsonrpc": "2.0", "id": 4, "method": "gateway.list", "params": { "pad": "x".repeat(70_000) } })).unwrap();
        let reply = reply_to(ip, &big).await;
        assert_eq!((reply["error"]["code"].clone(), reply["id"].clone()), (Value::from(-32600), Value::from(4)));
    }

    #[tokio::test]
    async fn a_libp2p_client_can_call_the_gateway_over_webrtc() {
        let (cert_pem, key_pem, sha) = gateway_style_cert();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move { run(&cert_pem, &key_pem, &sha, 0, Some(tx)).await });
        let listening = tokio::time::timeout(Duration::from_secs(20), rx).await.unwrap().unwrap();
        let port = listening.iter().find_map(|p| if let Protocol::Udp(p) = p { Some(p) } else { None }).unwrap();
        let certhash = listening.iter().find(|p| matches!(p, Protocol::Certhash(_))).unwrap();
        let target: Multiaddr = format!("/ip4/127.0.0.1/udp/{port}/webrtc-direct").parse::<Multiaddr>().unwrap().with(certhash);

        let client_cert = libp2p_webrtc::tokio::Certificate::generate(&mut rand::thread_rng()).unwrap();
        let mut client = libp2p::SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_other_transport(|key| libp2p_webrtc::tokio::Transport::new(key.clone(), client_cert))
            .unwrap()
            .with_behaviour(|_| libp2p_stream::Behaviour::new())
            .unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(IDLE))
            .build();
        let mut control = client.behaviour().new_control();
        client.listen_on("/ip4/127.0.0.1/udp/0/webrtc-direct".parse().unwrap()).unwrap();
        loop {
            if let SwarmEvent::NewListenAddr { .. } = tokio::time::timeout(Duration::from_secs(20), client.select_next_some()).await.unwrap() {
                break;
            }
        }
        client.dial(target).unwrap();
        let server_peer = loop {
            match tokio::time::timeout(Duration::from_secs(20), client.select_next_some()).await.expect("the browser-style dial connects") {
                SwarmEvent::ConnectionEstablished { peer_id, .. } => break peer_id,
                SwarmEvent::OutgoingConnectionError { error, .. } => panic!("dial failed: {error}"),
                _ => {}
            }
        };
        tokio::spawn(async move {
            loop {
                client.select_next_some().await;
            }
        });
        let mut stream = control.open_stream(server_peer, PROTOCOL).await.unwrap();
        let request = serde_json::json!({ "jsonrpc": "2.0", "id": 7, "method": "gateway.list", "params": {} });
        for _ in 0..2 {
            crate::p2p::write_frame(&mut stream, &serde_json::to_vec(&request).unwrap()).await.unwrap();
            let reply: Value = serde_json::from_slice(&crate::p2p::read_frame(&mut stream, 1 << 20).await.unwrap()).unwrap();
            assert_eq!(reply["id"], 7);
            assert!(reply["result"]["gateways"].is_array(), "one stream answers request after request: {reply}");
        }
        server.abort();
    }

    #[tokio::test]
    #[ignore]
    async fn serve_for_an_outside_client() {
        let port: u16 = std::env::var("EGO_WEBRTC_TEST_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(47_499);
        let secs: u64 = std::env::var("EGO_WEBRTC_TEST_SECS").ok().and_then(|p| p.parse().ok()).unwrap_or(300);
        let _ = tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).with_writer(std::io::stderr).try_init();
        let (cert_pem, key_pem, sha) = gateway_style_cert();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let entry = format!("https://127.0.0.1:{port}/rpc {sha}");
        let server = tokio::spawn(async move { run(&cert_pem, &key_pem, &sha, port, Some(tx)).await });
        let listening = tokio::time::timeout(Duration::from_secs(20), rx).await.unwrap().unwrap();
        println!("READY {listening}");
        println!("ENTRY {entry}");
        tokio::time::sleep(Duration::from_secs(secs)).await;
        server.abort();
    }
}
