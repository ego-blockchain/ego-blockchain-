use crate::{P2PError, P2PResult};
use libp2p::{Multiaddr, PeerId};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    pub peer_id: PeerId,
    pub addresses: Vec<Multiaddr>,
    pub discovered_at: u64,
    pub source: DiscoverySource,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DiscoverySource {
    Mdns,
    Kademlia,
    Bootstrap,
    Manual,
}

pub struct DiscoveryManager {
    discovered_peers: Arc<RwLock<HashMap<PeerId, DiscoveredPeer>>>,
    max_peers: usize,
}

impl DiscoveryManager {
    pub fn new(max_peers: usize) -> Self {
        Self {
            discovered_peers: Arc::new(RwLock::new(HashMap::new())),
            max_peers,
        }
    }

    pub async fn add_discovered_peer(
        &self,
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        source: DiscoverySource,
    ) -> P2PResult<()> {
        let mut peers = self.discovered_peers.write().await;

        if peers.len() >= self.max_peers && !peers.contains_key(&peer_id) {
            return Err(P2PError::ResourceLimitExceeded(
                "Maximum discovered peers reached".to_string(),
            ));
        }

        let discovered_peer = DiscoveredPeer {
            peer_id,
            addresses,
            discovered_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            source,
        };

        peers.insert(peer_id, discovered_peer);
        Ok(())
    }

    pub async fn remove_peer(&self, peer_id: &PeerId) {
        let mut peers = self.discovered_peers.write().await;
        peers.remove(peer_id);
    }

    pub async fn get_peer(&self, peer_id: &PeerId) -> Option<DiscoveredPeer> {
        let peers = self.discovered_peers.read().await;
        peers.get(peer_id).cloned()
    }

    pub async fn get_all_peers(&self) -> Vec<DiscoveredPeer> {
        let peers = self.discovered_peers.read().await;
        peers.values().cloned().collect()
    }

    pub async fn get_peers_by_source(&self, source: DiscoverySource) -> Vec<DiscoveredPeer> {
        let peers = self.discovered_peers.read().await;
        peers
            .values()
            .filter(|p| p.source == source)
            .cloned()
            .collect()
    }

    pub async fn get_peer_count(&self) -> usize {
        let peers = self.discovered_peers.read().await;
        peers.len()
    }

    pub async fn clear(&self) {
        let mut peers = self.discovered_peers.write().await;
        peers.clear();
    }

    pub async fn prune_old_peers(&self, max_age_secs: u64) {
        let mut peers = self.discovered_peers.write().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        peers.retain(|_, peer| now.saturating_sub(peer.discovered_at) < max_age_secs);
    }
}
