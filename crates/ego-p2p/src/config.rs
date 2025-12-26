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

    pub fn validator_config() -> Self {
        Self {
            max_peers: 150,
            max_topics_per_role: 25,
            heartbeat_interval: Duration::from_secs(5),
            ..Default::default()
        }
    }

    pub fn storage_config() -> Self {
        Self {
            max_peers: 100,
            max_topics_per_role: 15,
            gossipsub_max_transmit_size: 4 * 1024 * 1024,
            ..Default::default()
        }
    }

    pub fn gateway_config() -> Self {
        Self {
            max_peers: 500,
            max_topics_per_role: 30,
            enable_relay: true,
            enable_dcutr: true,
            ..Default::default()
        }
    }

    pub fn seed_config() -> Self {
        Self {
            max_peers: 1000,
            max_topics_per_role: 50,
            enable_relay: true,
            ..Default::default()
        }
    }
}
