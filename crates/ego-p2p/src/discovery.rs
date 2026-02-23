use crate::{P2PError, P2PResult};
use libp2p::kad::RecordKey;
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
    pub capabilities: Option<Vec<String>>,
    pub attestation: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DiscoverySource {
    Mdns,
    Kademlia,
    Bootstrap,
    Manual,
    DhtProvider,
}

#[derive(Debug, Clone)]
pub struct ProviderRecord {
    pub provider_id: PeerId,
    pub key: Vec<u8>,
    pub record_type: ProviderRecordType,
    pub addresses: Vec<Multiaddr>,
    pub registered_at: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProviderRecordType {
    Evidence,
    DataAvailability,
}

pub struct DiscoveryManager {
    discovered_peers: Arc<RwLock<HashMap<PeerId, DiscoveredPeer>>>,
    provider_records: Arc<RwLock<HashMap<Vec<u8>, Vec<ProviderRecord>>>>,
    max_peers: usize,
    max_providers_per_key: usize,
}

impl DiscoveryManager {
    pub fn new(max_peers: usize) -> Self {
        Self {
            discovered_peers: Arc::new(RwLock::new(HashMap::new())),
            provider_records: Arc::new(RwLock::new(HashMap::new())),
            max_peers,
            max_providers_per_key: 20,
        }
    }

    pub fn with_max_providers(mut self, max: usize) -> Self {
        self.max_providers_per_key = max;
        self
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
            capabilities: None,
            attestation: None,
        };
        peers.insert(peer_id, discovered_peer);
        Ok(())
    }

    pub async fn add_discovered_peer_with_caps(
        &self,
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        source: DiscoverySource,
        capabilities: Vec<String>,
        attestation: Option<Vec<u8>>,
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
            capabilities: Some(capabilities),
            attestation,
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

    pub async fn add_evidence_provider(
        &self,
        cid: Vec<u8>,
        provider_id: PeerId,
        addresses: Vec<Multiaddr>,
    ) -> P2PResult<()> {
        let key = Self::evidence_key(&cid);
        self.add_provider_record(key, provider_id, addresses, ProviderRecordType::Evidence)
            .await
    }

    pub async fn add_da_provider(
        &self,
        blob_id: Vec<u8>,
        chunk_index: u64,
        provider_id: PeerId,
        addresses: Vec<Multiaddr>,
    ) -> P2PResult<()> {
        let key = Self::da_key(&blob_id, chunk_index);
        self.add_provider_record(
            key,
            provider_id,
            addresses,
            ProviderRecordType::DataAvailability,
        )
        .await
    }

    async fn add_provider_record(
        &self,
        key: Vec<u8>,
        provider_id: PeerId,
        addresses: Vec<Multiaddr>,
        record_type: ProviderRecordType,
    ) -> P2PResult<()> {
        let mut providers = self.provider_records.write().await;
        let records = providers.entry(key.clone()).or_insert_with(Vec::new);

        if records.len() >= self.max_providers_per_key {
            records.remove(0);
        }

        let record = ProviderRecord {
            provider_id,
            key,
            record_type,
            addresses,
            registered_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        records.retain(|r| r.provider_id != provider_id);
        records.push(record);

        Ok(())
    }

    pub async fn get_evidence_providers(&self, cid: &[u8]) -> Vec<ProviderRecord> {
        let key = Self::evidence_key(cid);
        self.get_providers_for_key(&key).await
    }

    pub async fn get_da_providers(&self, blob_id: &[u8], chunk_index: u64) -> Vec<ProviderRecord> {
        let key = Self::da_key(blob_id, chunk_index);
        self.get_providers_for_key(&key).await
    }

    async fn get_providers_for_key(&self, key: &[u8]) -> Vec<ProviderRecord> {
        let providers = self.provider_records.read().await;
        providers.get(key).cloned().unwrap_or_default()
    }

    pub async fn remove_provider(&self, key: &[u8], provider_id: &PeerId) {
        let mut providers = self.provider_records.write().await;
        if let Some(records) = providers.get_mut(key) {
            records.retain(|r| &r.provider_id != provider_id);
            if records.is_empty() {
                providers.remove(key);
            }
        }
    }

    pub async fn prune_old_providers(&self, max_age_secs: u64) {
        let mut providers = self.provider_records.write().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        for records in providers.values_mut() {
            records.retain(|r| now.saturating_sub(r.registered_at) < max_age_secs);
        }

        providers.retain(|_, records| !records.is_empty());
    }

    pub async fn get_provider_count(&self) -> usize {
        let providers = self.provider_records.read().await;
        providers.values().map(|v| v.len()).sum()
    }

    pub async fn get_provider_keys_count(&self) -> usize {
        let providers = self.provider_records.read().await;
        providers.len()
    }

    pub fn evidence_key(cid: &[u8]) -> Vec<u8> {
        let mut key = b"/ego/evidence/".to_vec();
        key.extend_from_slice(cid);
        key
    }

    pub fn da_key(blob_id: &[u8], chunk_index: u64) -> Vec<u8> {
        let mut key = b"/ego/da/".to_vec();
        key.extend_from_slice(blob_id);
        key.push(b'/');
        key.extend_from_slice(&chunk_index.to_be_bytes());
        key
    }

    pub fn evidence_record_key(cid: &[u8]) -> RecordKey {
        RecordKey::new(&Self::evidence_key(cid))
    }

    pub fn da_record_key(blob_id: &[u8], chunk_index: u64) -> RecordKey {
        RecordKey::new(&Self::da_key(blob_id, chunk_index))
    }
}
