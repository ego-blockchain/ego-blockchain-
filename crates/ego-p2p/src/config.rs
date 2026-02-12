use libp2p::Multiaddr;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct NetworkConfig {
    pub listen_addresses: Vec<Multiaddr>,
    pub bootstrap_peers: Vec<Multiaddr>,
    pub max_peers: usize,
    pub max_pending_connections: u32,
    pub connection_timeout: Duration,
    pub heartbeat_interval: Duration,
    pub peer_discovery_interval: Duration,
    pub enable_mdns: bool,
    pub enable_autonat: bool,
    pub enable_relay: bool,
    pub enable_dcutr: bool,
    pub gossipsub_heartbeat: Duration,
    pub gossipsub_max_transmit_size: usize,
    pub kademlia_replication_factor: usize,
    pub kademlia_query_timeout: Duration,
    pub idle_connection_timeout: Duration,
    pub max_topics_per_role: usize,
    pub max_message_rate_per_peer: u32,
    pub reputation_decay_interval: Duration,
    pub prune_inactive_peers_interval: Duration,
    pub max_peer_idle_duration: Duration,
    pub da_fetch_timeout: Duration,
    pub evidence_fetch_timeout: Duration,
    pub provider_publication_interval: Duration,
    pub provider_record_ttl: Duration,
    pub enable_metrics: bool,
    pub metrics_port: u16,
    pub grpc_bridge_enabled: bool,
    pub grpc_bridge_path: String,
    pub per_topic_auth_enabled: bool,
    pub backpressure_threshold: usize,
    pub publish_queue_size: usize,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addresses: vec![],
            bootstrap_peers: vec![],
            max_peers: 200,
            max_pending_connections: 50,
            connection_timeout: Duration::from_secs(30),
            heartbeat_interval: Duration::from_secs(10),
            peer_discovery_interval: Duration::from_secs(60),
            enable_mdns: true,
            enable_autonat: true,
            enable_relay: false,
            enable_dcutr: false,
            gossipsub_heartbeat: Duration::from_secs(10),
            gossipsub_max_transmit_size: 2 * 1024 * 1024,
            kademlia_replication_factor: 5,
            kademlia_query_timeout: Duration::from_secs(60),
            idle_connection_timeout: Duration::from_secs(120),
            max_topics_per_role: 20,
            max_message_rate_per_peer: 100,
            reputation_decay_interval: Duration::from_secs(300),
            prune_inactive_peers_interval: Duration::from_secs(600),
            max_peer_idle_duration: Duration::from_secs(1800),
            da_fetch_timeout: Duration::from_secs(30),
            evidence_fetch_timeout: Duration::from_secs(30),
            provider_publication_interval: Duration::from_secs(12 * 60 * 60),
            provider_record_ttl: Duration::from_secs(24 * 60 * 60),
            enable_metrics: true,
            metrics_port: 9090,
            grpc_bridge_enabled: false,
            grpc_bridge_path: "/tmp/ego-p2p.sock".to_string(),
            per_topic_auth_enabled: true,
            backpressure_threshold: 1000,
            publish_queue_size: 10000,
        }
    }
}

impl NetworkConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_listen_addresses(mut self, addresses: Vec<Multiaddr>) -> Self {
        self.listen_addresses = addresses;
        self
    }

    pub fn with_bootstrap_peers(mut self, peers: Vec<Multiaddr>) -> Self {
        self.bootstrap_peers = peers;
        self
    }

    pub fn with_max_peers(mut self, max: usize) -> Self {
        self.max_peers = max;
        self
    }

    pub fn with_mdns(mut self, enable: bool) -> Self {
        self.enable_mdns = enable;
        self
    }

    pub fn with_metrics(mut self, enable: bool, port: u16) -> Self {
        self.enable_metrics = enable;
        self.metrics_port = port;
        self
    }

    pub fn with_grpc_bridge(mut self, enable: bool, path: String) -> Self {
        self.grpc_bridge_enabled = enable;
        self.grpc_bridge_path = path;
        self
    }

    pub fn with_da_timeout(mut self, timeout: Duration) -> Self {
        self.da_fetch_timeout = timeout;
        self
    }

    pub fn with_evidence_timeout(mut self, timeout: Duration) -> Self {
        self.evidence_fetch_timeout = timeout;
        self
    }

    pub fn with_backpressure_threshold(mut self, threshold: usize) -> Self {
        self.backpressure_threshold = threshold;
        self
    }

    pub fn with_publish_queue_size(mut self, size: usize) -> Self {
        self.publish_queue_size = size;
        self
    }

    pub fn with_per_topic_auth(mut self, enable: bool) -> Self {
        self.per_topic_auth_enabled = enable;
        self
    }

    pub fn validator_config() -> Self {
        Self {
            max_peers: 150,
            max_topics_per_role: 25,
            heartbeat_interval: Duration::from_secs(5),
            enable_metrics: true,
            metrics_port: 9091,
            grpc_bridge_enabled: true,
            per_topic_auth_enabled: true,
            backpressure_threshold: 500,
            publish_queue_size: 5000,
            ..Default::default()
        }
    }

    pub fn storage_config() -> Self {
        Self {
            max_peers: 100,
            max_topics_per_role: 15,
            gossipsub_max_transmit_size: 4 * 1024 * 1024,
            enable_metrics: true,
            metrics_port: 9092,
            grpc_bridge_enabled: true,
            provider_publication_interval: Duration::from_secs(6 * 60 * 60),
            backpressure_threshold: 2000,
            publish_queue_size: 20000,
            ..Default::default()
        }
    }

    pub fn gateway_config() -> Self {
        Self {
            max_peers: 500,
            max_topics_per_role: 30,
            enable_relay: true,
            enable_dcutr: true,
            enable_metrics: true,
            metrics_port: 9093,
            grpc_bridge_enabled: true,
            backpressure_threshold: 1500,
            publish_queue_size: 15000,
            ..Default::default()
        }
    }

    pub fn seed_config() -> Self {
        Self {
            max_peers: 1000,
            max_topics_per_role: 50,
            enable_relay: true,
            enable_metrics: true,
            metrics_port: 9094,
            grpc_bridge_enabled: false,
            per_topic_auth_enabled: false,
            backpressure_threshold: 3000,
            publish_queue_size: 30000,
            ..Default::default()
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.max_peers == 0 {
            return Err("max_peers must be greater than 0".to_string());
        }

        if self.backpressure_threshold > self.publish_queue_size {
            return Err("backpressure_threshold cannot exceed publish_queue_size".to_string());
        }

        if self.kademlia_replication_factor == 0 {
            return Err("kademlia_replication_factor must be greater than 0".to_string());
        }

        if self.grpc_bridge_enabled && self.grpc_bridge_path.is_empty() {
            return Err("grpc_bridge_path must be set when grpc_bridge is enabled".to_string());
        }

        Ok(())
    }
}
