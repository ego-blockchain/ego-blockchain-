use crate::{ConnectionState, NodeIdentity, P2PError, P2PResult, PeerInfo};
use dashmap::DashMap;
use ego_core::Timestamp;
use libp2p::PeerId;
use std::sync::Arc;
use std::time::Duration;

pub struct PeerManager {
    peers: Arc<DashMap<PeerId, PeerInfo>>,
    max_peers: usize,
    reputation_threshold: f64,
    dilithium_keys: Arc<DashMap<PeerId, Vec<u8>>>,
    attestations: Arc<DashMap<PeerId, Vec<u8>>>,
}

impl PeerManager {
    pub fn new(max_peers: usize) -> Self {
        Self {
            peers: Arc::new(DashMap::new()),
            max_peers,
            reputation_threshold: 0.3,
            dilithium_keys: Arc::new(DashMap::new()),
            attestations: Arc::new(DashMap::new()),
        }
    }

    pub fn with_reputation_threshold(mut self, threshold: f64) -> Self {
        self.reputation_threshold = threshold.clamp(0.0, 1.0);
        self
    }

    pub fn add_peer(&self, peer_id: PeerId) -> P2PResult<()> {
        if self.peers.len() >= self.max_peers {
            return Err(P2PError::ResourceLimitExceeded(
                "Maximum peer limit reached".to_string(),
            ));
        }

        if self.peers.contains_key(&peer_id) {
            return Ok(());
        }

        let peer_info = PeerInfo {
            peer_id,
            identity: None,
            reputation_score: 1.0,
            last_seen: Timestamp::now(),
            connection_state: ConnectionState::Connecting,
            bandwidth_stats: Default::default(),
        };

        self.peers.insert(peer_id, peer_info);
        Ok(())
    }

    pub fn remove_peer(&self, peer_id: &PeerId) -> P2PResult<()> {
        self.peers.remove(peer_id);
        self.dilithium_keys.remove(peer_id);
        self.attestations.remove(peer_id);
        Ok(())
    }

    pub fn get_peer(&self, peer_id: &PeerId) -> Option<PeerInfo> {
        self.peers.get(peer_id).map(|entry| entry.clone())
    }

    pub fn update_connection_state(&self, peer_id: &PeerId, state: ConnectionState) {
        if let Some(mut entry) = self.peers.get_mut(peer_id) {
            entry.connection_state = state;
            entry.last_seen = Timestamp::now();
        }
    }

    pub fn update_identity(&self, peer_id: &PeerId, identity: NodeIdentity) {
        if let Some(mut entry) = self.peers.get_mut(peer_id) {
            entry.identity = Some(identity);
        }
    }

    pub fn set_dilithium_key(&self, peer_id: &PeerId, public_key: Vec<u8>) -> P2PResult<()> {
        if public_key.is_empty() {
            return Err(P2PError::InvalidCapabilities(
                "Dilithium key is empty".to_string(),
            ));
        }
        self.dilithium_keys.insert(*peer_id, public_key);
        Ok(())
    }

    pub fn get_dilithium_key(&self, peer_id: &PeerId) -> Option<Vec<u8>> {
        self.dilithium_keys.get(peer_id).map(|entry| entry.clone())
    }

    pub fn set_attestation(&self, peer_id: &PeerId, attestation: Vec<u8>) -> P2PResult<()> {
        if attestation.is_empty() {
            return Err(P2PError::InvalidAttestation(
                "Attestation is empty".to_string(),
            ));
        }
        self.attestations.insert(*peer_id, attestation);
        Ok(())
    }

    pub fn get_attestation(&self, peer_id: &PeerId) -> Option<Vec<u8>> {
        self.attestations.get(peer_id).map(|entry| entry.clone())
    }

    pub fn verify_peer_attestation(&self, peer_id: &PeerId) -> P2PResult<bool> {
        let attestation = self.get_attestation(peer_id);
        let dilithium_key = self.get_dilithium_key(peer_id);

        match (attestation, dilithium_key) {
            (Some(att), Some(key)) => {
                if att.is_empty() || key.is_empty() {
                    return Ok(false);
                }
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    pub fn update_bandwidth_stats(
        &self,
        peer_id: &PeerId,
        bytes_sent: u64,
        bytes_received: u64,
        messages_sent: u64,
        messages_received: u64,
    ) {
        if let Some(mut entry) = self.peers.get_mut(peer_id) {
            entry.bandwidth_stats.bytes_sent += bytes_sent;
            entry.bandwidth_stats.bytes_received += bytes_received;
            entry.bandwidth_stats.messages_sent += messages_sent;
            entry.bandwidth_stats.messages_received += messages_received;
            entry.bandwidth_stats.last_updated = Some(Timestamp::now());
        }
    }

    pub fn adjust_reputation(&self, peer_id: &PeerId, delta: f64) {
        if let Some(mut entry) = self.peers.get_mut(peer_id) {
            entry.reputation_score = (entry.reputation_score + delta).clamp(0.0, 1.0);
        }
    }

    pub fn get_reputation(&self, peer_id: &PeerId) -> f64 {
        self.peers
            .get(peer_id)
            .map(|entry| entry.reputation_score)
            .unwrap_or(0.0)
    }

    pub fn is_peer_trusted(&self, peer_id: &PeerId) -> bool {
        self.get_reputation(peer_id) >= self.reputation_threshold
    }

    pub fn get_connected_peers(&self) -> Vec<PeerId> {
        self.peers
            .iter()
            .filter(|entry| entry.connection_state == ConnectionState::Connected)
            .map(|entry| entry.peer_id)
            .collect()
    }

    pub fn get_all_peers(&self) -> Vec<PeerInfo> {
        self.peers.iter().map(|entry| entry.clone()).collect()
    }

    pub fn count_connected_peers(&self) -> usize {
        self.peers
            .iter()
            .filter(|entry| entry.connection_state == ConnectionState::Connected)
            .count()
    }

    pub fn prune_inactive_peers(&self, max_idle_duration: Duration) {
        let cutoff_time = Timestamp::now()
            .as_millis()
            .saturating_sub(max_idle_duration.as_millis() as u64);

        let to_remove: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|entry| {
                entry.connection_state != ConnectionState::Connected
                    && entry.last_seen.as_millis() < cutoff_time
            })
            .map(|entry| entry.peer_id)
            .collect();

        for peer_id in to_remove {
            self.peers.remove(&peer_id);
            self.dilithium_keys.remove(&peer_id);
            self.attestations.remove(&peer_id);
        }
    }

    pub fn get_peers_by_shard(&self, shard_id: u32) -> Vec<PeerId> {
        self.peers
            .iter()
            .filter(|entry| {
                if let Some(ref identity) = entry.identity {
                    identity.capabilities.shard_ids.contains(&shard_id)
                } else {
                    false
                }
            })
            .map(|entry| entry.peer_id)
            .collect()
    }

    pub fn get_5g_capable_peers(&self) -> Vec<PeerId> {
        self.peers
            .iter()
            .filter(|entry| {
                if let Some(ref identity) = entry.identity {
                    identity.capabilities.is_5g_capable
                } else {
                    false
                }
            })
            .map(|entry| entry.peer_id)
            .collect()
    }

    pub fn get_peers_with_capability(&self, capability: &str) -> Vec<PeerId> {
        self.peers
            .iter()
            .filter(|entry| {
                if let Some(ref identity) = entry.identity {
                    identity
                        .capabilities
                        .protocols
                        .contains(&capability.to_string())
                } else {
                    false
                }
            })
            .map(|entry| entry.peer_id)
            .collect()
    }

    pub fn ban_peer(&self, peer_id: &PeerId) {
        self.adjust_reputation(peer_id, -1.0);
    }

    pub fn get_banned_peers(&self) -> Vec<PeerId> {
        self.peers
            .iter()
            .filter(|entry| entry.reputation_score <= 0.0)
            .map(|entry| entry.peer_id)
            .collect()
    }

    pub fn is_peer_banned(&self, peer_id: &PeerId) -> bool {
        self.get_reputation(peer_id) <= 0.0
    }
}
