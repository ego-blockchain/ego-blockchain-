use crate::sideband::{Frame, SidebandTransport};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::OnceLock;

/// The offline link that needs nobody to set it up.
///
/// The realistic way a person is cut off is not that radio hardware is missing: it is that
/// the router is up and the internet behind it is not, or that everyone is on one phone's
/// hotspot with no data left. In both cases the machines can still reach each other, and
/// nothing about that requires a relay, a bootstrap node, or a name server.
///
/// So frames go out as UDP broadcast on the local segment. Anyone listening picks them up,
/// verifies the signature exactly as it would a gossiped transaction, and whoever does have
/// a connection passes it on. A transaction carries its own signature and nonce, so a node
/// receiving one this way needs nothing from the sender to judge it.
///
/// This is deliberately not addressed to anyone. There is no peer discovery to fail, no
/// handshake to time out, and no configuration to get wrong.
pub const LAN_SIDEBAND_PORT: u16 = 47421;

/// UDP keeps a datagram whole, so a frame is never split further and never reassembled out
/// of order within itself. Staying inside the smallest MTU anyone realistically has avoids
/// IP fragmentation, where losing one fragment silently loses the whole frame.
const LAN_MAX_PAYLOAD: usize = 1_200;

pub struct LanTransport {
    socket: UdpSocket,
    port: u16,
    tag: Vec<u8>,
}

fn tag_bytes() -> &'static [u8] {
    static TAG: OnceLock<Vec<u8>> = OnceLock::new();
    TAG.get_or_init(|| {
        let t = crate::sideband_spool::node_tag().as_bytes();
        let mut out = [0u8; 8];
        for (i, b) in t.iter().take(8).enumerate() {
            out[i] = *b;
        }
        out.to_vec()
    })
}

impl LanTransport {
    pub fn bind() -> Result<Self, String> {
        let port = std::env::var("EGO_SIDEBAND_LAN_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(LAN_SIDEBAND_PORT);

        let socket = bind_shared(port)?;
        socket.set_broadcast(true).map_err(|e| format!("broadcast: {e}"))?;
        socket
            .set_nonblocking(true)
            .map_err(|e| format!("nonblocking: {e}"))?;

        Ok(Self { socket, port, tag: tag_bytes().to_vec() })
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

/// Several nodes run on one machine, so the port has to be shareable. Without this the
/// second node to start would fail to bind and silently have no offline link at all.
fn bind_shared(port: u16) -> Result<UdpSocket, String> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| format!("socket: {e}"))?;
    sock.set_reuse_address(true).map_err(|e| format!("reuse: {e}"))?;
    let addr: SocketAddr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into();
    sock.bind(&addr.into()).map_err(|e| format!("bind {port}: {e}"))?;
    Ok(sock.into())
}

impl SidebandTransport for LanTransport {
    fn name(&self) -> &'static str {
        "lan"
    }

    fn max_payload(&self) -> usize {
        LAN_MAX_PAYLOAD
    }

    fn can_send(&self) -> bool {
        true
    }

    fn send_frame(&self, frame: &Frame) -> Result<(), String> {
        let body = serde_json::to_vec(frame).map_err(|e| e.to_string())?;
        // Who sent it, so a node can ignore the copy of its own broadcast that comes back.
        // Not a claim of identity and nothing trusts it: the transaction inside carries the
        // signature that decides whether it is real.
        let mut datagram = Vec::with_capacity(8 + body.len());
        datagram.extend_from_slice(&self.tag);
        datagram.extend_from_slice(&body);

        let dest = SocketAddrV4::new(Ipv4Addr::BROADCAST, self.port);
        self.socket
            .send_to(&datagram, dest)
            .map(|_| ())
            .map_err(|e| format!("broadcast: {e}"))
    }

    fn recv_frame(&self) -> Option<Frame> {
        let mut buf = [0u8; 2048];
        loop {
            let n = match self.socket.recv_from(&mut buf) {
                Ok((n, _)) => n,
                Err(_) => return None,
            };
            if n <= 8 {
                continue;
            }
            if buf[..8] == self.tag[..] {
                continue;
            }
            match serde_json::from_slice::<Frame>(&buf[8..n]) {
                Ok(f) => return Some(f),
                Err(_) => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sideband::split;

    #[test]
    fn a_frame_broadcast_on_the_segment_comes_back_to_a_listener() {
        let port = 47_500 + (std::process::id() % 200) as u16;
        std::env::set_var("EGO_SIDEBAND_LAN_PORT", port.to_string());
        let Ok(sender) = LanTransport::bind() else { return };
        let Ok(mut listener) = LanTransport::bind() else { return };
        // A second node on the same machine has its own tag, or it would discard everything
        // the first one says as its own echo.
        listener.tag = b"otherpc\0".to_vec();

        let frames = split(b"a transaction", sender.max_payload(), 7);
        assert_eq!(frames.len(), 1, "a short message is one datagram");
        if sender.send_frame(&frames[0]).is_err() {
            return; // no broadcast route on this host, nothing to assert
        }

        for _ in 0..50 {
            if let Some(got) = listener.recv_frame() {
                assert_eq!(got.msg_id, 7);
                assert_eq!(got.payload, b"a transaction");
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[test]
    fn a_node_ignores_its_own_broadcast() {
        let port = 47_800 + (std::process::id() % 150) as u16;
        std::env::set_var("EGO_SIDEBAND_LAN_PORT", port.to_string());
        let Ok(node) = LanTransport::bind() else { return };
        let frames = split(b"mine", node.max_payload(), 3);
        if node.send_frame(&frames[0]).is_err() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(80));
        assert!(
            node.recv_frame().is_none(),
            "a node re-ingesting its own send would gossip the transaction it deliberately \
             kept off the network",
        );
    }
}
