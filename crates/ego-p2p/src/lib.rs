pub mod behaviour;
pub mod builder;
pub mod codec;
pub mod config;
pub mod discovery;
pub mod error;
pub mod event;
pub mod network;
pub mod peer;
pub mod subscription;
pub mod sync;
pub mod topic;
pub mod types;

pub use behaviour::{
    DaCodec, DaRequest, DaResponse, EgoBehaviour, EvidenceCodec, EvidenceRequest, EvidenceResponse,
};
pub use builder::{
    GossipEnvelope, GossipPayload, HeaderMessage, MessageBuilder, PeerCaps, ReceiptMessage,
    RollupMessage,
};
pub use codec::MessageCodec;
pub use config::NetworkConfig;
pub use discovery::{
    DiscoveredPeer, DiscoveryManager, DiscoverySource, ProviderRecord, ProviderRecordType,
};
pub use error::{P2PError, P2PResult};
pub use event::{EventHandler, NetworkEvent};
pub use network::NetworkManager;
pub use peer::PeerManager;
pub use subscription::SubscriptionManager;
pub use topic::{TopicManager, get_standard_topics};
pub use sync::{SyncManager, SyncMode, SyncProgress};
pub use types::*;

pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;
pub const DA_PROTOCOL_VERSION: &str = "/ego/da/1.0";
pub const EVIDENCE_PROTOCOL_VERSION: &str = "/ego/evidence/1.0";
pub const IDENTIFY_PROTOCOL_VERSION: &str = "/ego/1.0.0";

pub mod metrics {
    use dashmap::DashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    #[derive(Clone)]
    pub struct NetworkMetrics {
        pub connected_peers: Arc<AtomicUsize>,
        pub messages_received: Arc<AtomicU64>,
        pub messages_sent: Arc<AtomicU64>,
        pub messages_dropped: Arc<AtomicU64>,
        pub bytes_received: Arc<AtomicU64>,
        pub bytes_sent: Arc<AtomicU64>,
        pub publish_queue_length: Arc<AtomicUsize>,
        pub topic_peer_counts: Arc<DashMap<String, usize>>,
        pub topic_bandwidth_in: Arc<DashMap<String, u64>>,
        pub topic_bandwidth_out: Arc<DashMap<String, u64>>,
        pub dht_providers_found: Arc<AtomicU64>,
        pub dht_providers_served: Arc<AtomicU64>,
        pub da_requests_received: Arc<AtomicU64>,
        pub da_requests_sent: Arc<AtomicU64>,
        pub da_requests_failed: Arc<AtomicU64>,
        pub evidence_requests_received: Arc<AtomicU64>,
        pub evidence_requests_sent: Arc<AtomicU64>,
        pub evidence_requests_failed: Arc<AtomicU64>,
    }

    impl NetworkMetrics {
        pub fn new() -> Self {
            Self {
                connected_peers: Arc::new(AtomicUsize::new(0)),
                messages_received: Arc::new(AtomicU64::new(0)),
                messages_sent: Arc::new(AtomicU64::new(0)),
                messages_dropped: Arc::new(AtomicU64::new(0)),
                bytes_received: Arc::new(AtomicU64::new(0)),
                bytes_sent: Arc::new(AtomicU64::new(0)),
                publish_queue_length: Arc::new(AtomicUsize::new(0)),
                topic_peer_counts: Arc::new(DashMap::new()),
                topic_bandwidth_in: Arc::new(DashMap::new()),
                topic_bandwidth_out: Arc::new(DashMap::new()),
                dht_providers_found: Arc::new(AtomicU64::new(0)),
                dht_providers_served: Arc::new(AtomicU64::new(0)),
                da_requests_received: Arc::new(AtomicU64::new(0)),
                da_requests_sent: Arc::new(AtomicU64::new(0)),
                da_requests_failed: Arc::new(AtomicU64::new(0)),
                evidence_requests_received: Arc::new(AtomicU64::new(0)),
                evidence_requests_sent: Arc::new(AtomicU64::new(0)),
                evidence_requests_failed: Arc::new(AtomicU64::new(0)),
            }
        }

        pub fn increment_connected_peers(&self) {
            self.connected_peers.fetch_add(1, Ordering::Relaxed);
        }

        pub fn decrement_connected_peers(&self) {
            self.connected_peers.fetch_sub(1, Ordering::Relaxed);
        }

        pub fn set_connected_peers(&self, count: usize) {
            self.connected_peers.store(count, Ordering::Relaxed);
        }

        pub fn get_connected_peers(&self) -> usize {
            self.connected_peers.load(Ordering::Relaxed)
        }

        pub fn increment_messages_received(&self) {
            self.messages_received.fetch_add(1, Ordering::Relaxed);
        }

        pub fn increment_messages_sent(&self) {
            self.messages_sent.fetch_add(1, Ordering::Relaxed);
        }

        pub fn increment_messages_dropped(&self) {
            self.messages_dropped.fetch_add(1, Ordering::Relaxed);
        }

        pub fn add_bytes_received(&self, bytes: u64) {
            self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
        }

        pub fn add_bytes_sent(&self, bytes: u64) {
            self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        }

        pub fn set_publish_queue_length(&self, length: usize) {
            self.publish_queue_length.store(length, Ordering::Relaxed);
        }

        pub fn get_publish_queue_length(&self) -> usize {
            self.publish_queue_length.load(Ordering::Relaxed)
        }

        pub fn set_topic_peer_count(&self, topic: String, count: usize) {
            self.topic_peer_counts.insert(topic, count);
        }

        pub fn add_topic_bandwidth_in(&self, topic: String, bytes: u64) {
            self.topic_bandwidth_in
                .entry(topic)
                .and_modify(|v| *v += bytes)
                .or_insert(bytes);
        }

        pub fn add_topic_bandwidth_out(&self, topic: String, bytes: u64) {
            self.topic_bandwidth_out
                .entry(topic)
                .and_modify(|v| *v += bytes)
                .or_insert(bytes);
        }

        pub fn increment_dht_providers_found(&self) {
            self.dht_providers_found.fetch_add(1, Ordering::Relaxed);
        }

        pub fn increment_dht_providers_served(&self) {
            self.dht_providers_served.fetch_add(1, Ordering::Relaxed);
        }

        pub fn increment_da_requests_received(&self) {
            self.da_requests_received.fetch_add(1, Ordering::Relaxed);
        }

        pub fn increment_da_requests_sent(&self) {
            self.da_requests_sent.fetch_add(1, Ordering::Relaxed);
        }

        pub fn increment_da_requests_failed(&self) {
            self.da_requests_failed.fetch_add(1, Ordering::Relaxed);
        }

        pub fn increment_evidence_requests_received(&self) {
            self.evidence_requests_received
                .fetch_add(1, Ordering::Relaxed);
        }

        pub fn increment_evidence_requests_sent(&self) {
            self.evidence_requests_sent.fetch_add(1, Ordering::Relaxed);
        }

        pub fn increment_evidence_requests_failed(&self) {
            self.evidence_requests_failed
                .fetch_add(1, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> MetricsSnapshot {
            MetricsSnapshot {
                connected_peers: self.get_connected_peers(),
                messages_received: self.messages_received.load(Ordering::Relaxed),
                messages_sent: self.messages_sent.load(Ordering::Relaxed),
                messages_dropped: self.messages_dropped.load(Ordering::Relaxed),
                bytes_received: self.bytes_received.load(Ordering::Relaxed),
                bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
                publish_queue_length: self.get_publish_queue_length(),
                dht_providers_found: self.dht_providers_found.load(Ordering::Relaxed),
                dht_providers_served: self.dht_providers_served.load(Ordering::Relaxed),
                da_requests_received: self.da_requests_received.load(Ordering::Relaxed),
                da_requests_sent: self.da_requests_sent.load(Ordering::Relaxed),
                da_requests_failed: self.da_requests_failed.load(Ordering::Relaxed),
                evidence_requests_received: self.evidence_requests_received.load(Ordering::Relaxed),
                evidence_requests_sent: self.evidence_requests_sent.load(Ordering::Relaxed),
                evidence_requests_failed: self.evidence_requests_failed.load(Ordering::Relaxed),
            }
        }
    }

    impl Default for NetworkMetrics {
        fn default() -> Self {
            Self::new()
        }
    }

    #[derive(Debug, Clone)]
    pub struct MetricsSnapshot {
        pub connected_peers: usize,
        pub messages_received: u64,
        pub messages_sent: u64,
        pub messages_dropped: u64,
        pub bytes_received: u64,
        pub bytes_sent: u64,
        pub publish_queue_length: usize,
        pub dht_providers_found: u64,
        pub dht_providers_served: u64,
        pub da_requests_received: u64,
        pub da_requests_sent: u64,
        pub da_requests_failed: u64,
        pub evidence_requests_received: u64,
        pub evidence_requests_sent: u64,
        pub evidence_requests_failed: u64,
    }
}

pub use metrics::{MetricsSnapshot, NetworkMetrics};
