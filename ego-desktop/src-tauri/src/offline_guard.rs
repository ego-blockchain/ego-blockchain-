use libp2p::core::transport::PortUse;
use libp2p::core::{ConnectedPoint, Endpoint, Multiaddr};
use libp2p::swarm::{
    dummy, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler,
    THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use libp2p::PeerId;
use std::task::{Context, Poll};

/// Refuses every connection that leaves the local network while offline mode is on.
///
/// This lives in the behaviour rather than at the call sites because libp2p dials
/// on its own account. Kademlia dials peers it learns from identify, AutoNAT
/// probes, DCUtR punches holes, the relay client makes reservations. None of
/// those go through our own send or dial paths, so gating those paths left the
/// node holding live connections to public addresses with EGO_OFFLINE=1 set.
///
/// `handle_pending_outbound_connection` is the hook libp2p's own allow/block list
/// uses. Denying here stops the dial before a packet is sent, which matters:
/// on a monitored connection the SYN alone names the destination.
#[derive(Default)]
pub struct OfflineGuard;

fn addr_is_local(addr: &Multiaddr) -> bool {
    crate::p2p::endpoint_is_local(&addr.to_string())
}

fn deny(what: &str, addr: &Multiaddr) -> ConnectionDenied {
    eprintln!("[Offline] refused {what} {addr}");
    ConnectionDenied::new(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!("offline mode: {addr} is outside the local network"),
    ))
}

impl NetworkBehaviour for OfflineGuard {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = std::convert::Infallible;

    fn handle_pending_outbound_connection(
        &mut self,
        _id: ConnectionId,
        _peer: Option<PeerId>,
        addrs: &[Multiaddr],
        _role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        if !crate::p2p::offline_mode() {
            return Ok(Vec::new());
        }
        // Deny if any candidate address leaves the local network. libp2p tries
        // them in turn, so allowing the set through because one entry is local
        // would still let it fall back to a public one.
        if let Some(bad) = addrs.iter().find(|a| !addr_is_local(a)) {
            return Err(deny("outbound dial to", bad));
        }
        Ok(Vec::new())
    }

    fn handle_established_outbound_connection(
        &mut self,
        _id: ConnectionId,
        _peer: PeerId,
        addr: &Multiaddr,
        _role: Endpoint,
        _port: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if crate::p2p::offline_mode() && !addr_is_local(addr) {
            return Err(deny("outbound connection to", addr));
        }
        Ok(dummy::ConnectionHandler)
    }

    /// Inbound matters as much as outbound. A node that is reachable from the
    /// internet would otherwise still be found and connected to by strangers,
    /// which is the thing offline mode exists to prevent.
    fn handle_established_inbound_connection(
        &mut self,
        _id: ConnectionId,
        _peer: PeerId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        let _ = local;
        if crate::p2p::offline_mode() && !addr_is_local(remote) {
            return Err(deny("inbound connection from", remote));
        }
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, _event: FromSwarm) {}

    fn on_connection_handler_event(
        &mut self,
        _peer: PeerId,
        _id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        // dummy::ConnectionHandler never emits, so this is unreachable.
        let _: std::convert::Infallible = event;
    }

    fn poll(&mut self, _cx: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

#[allow(dead_code)]
fn connected_point_addr(cp: &ConnectedPoint) -> &Multiaddr {
    match cp {
        ConnectedPoint::Dialer { address, .. } => address,
        ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> Multiaddr {
        s.parse().expect("multiaddr")
    }

    #[test]
    fn private_ranges_count_as_local() {
        for s in [
            "/ip4/127.0.0.1/tcp/41001",
            "/ip4/192.168.1.71/tcp/41001",
            "/ip4/10.0.0.4/tcp/41001",
            "/ip4/172.16.0.9/tcp/41001",
            "/ip4/172.31.255.1/tcp/41001",
        ] {
            assert!(addr_is_local(&addr(s)), "{s} should be local");
        }
    }

    #[test]
    fn public_addresses_and_relays_are_not_local() {
        for s in [
            "/ip4/40.233.82.42/tcp/4001",
            "/ip4/50.66.180.231/tcp/47393",
            "/ip4/8.8.8.8/tcp/53",
            "/ip4/172.32.0.1/tcp/41001",
            "/ip4/172.15.0.1/tcp/41001",
        ] {
            assert!(!addr_is_local(&addr(s)), "{s} should not be local");
        }
    }

    #[test]
    fn a_mixed_candidate_set_is_denied_on_the_public_entry() {
        // The failure this guards against: libp2p is handed several addresses for
        // one peer and falls back to the public one when the LAN address fails.
        let mut g = OfflineGuard;
        let addrs = vec![addr("/ip4/192.168.1.71/tcp/41001"), addr("/ip4/40.233.82.42/tcp/4001")];
        if crate::p2p::offline_mode() {
            assert!(g
                .handle_pending_outbound_connection(ConnectionId::new_unchecked(1), None, &addrs, Endpoint::Dialer)
                .is_err());
        }
    }
}
