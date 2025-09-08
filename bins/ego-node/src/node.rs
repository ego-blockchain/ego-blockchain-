use crate::{NodeBehaviour, NodeRole, Placement, ProofEvent, SecureKeystore, ShardConfig};
use libp2p::{
    Multiaddr, PeerId, Swarm, Transport, autonat, core::upgrade::Version, gossipsub, identify, kad,
    mdns, noise, ping, tcp, yamux,
};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

pub struct Node {
    pub peer_id: PeerId,
    pub swarm: Swarm<NodeBehaviour>,
    pub listen_addresses: Vec<Multiaddr>,
    pub bootstrap_peers: Vec<Multiaddr>,
    pub roles: HashSet<NodeRole>,
    pub shard_ids: Vec<u32>,
    pub shard_configs: HashMap<u32, ShardConfig>,
    pub placements: Vec<Placement>,
    pub storage_capacity_bytes: u64,
    pub geohash: Option<String>,
    pub bandwidth_capacity_bps: u64,
    pub slice_id: Option<String>, // 5G network slice identifier
    keystore: SecureKeystore,
    pub max_peers_per_shard: u32,
    pub max_topics_per_role: u32,
    pub recent_proofs: Vec<ProofEvent>,
}

impl Node {
    pub async fn new(roles: Vec<NodeRole>, shard_ids: Vec<u32>) -> anyhow::Result<Self> {
        let keystore = SecureKeystore::new();
        let peer_id = PeerId::from(keystore.keypair().public());

        let transport = tcp::tokio::Transport::default()
            .upgrade(Version::V1)
            .authenticate(noise::Config::new(keystore.keypair())?)
            .multiplex(yamux::Config::default())
            .boxed();

        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(10))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .max_transmit_size(1024 * 1024) // 1MB max message
            .duplicate_cache_time(Duration::from_secs(60))
            .build()
            .map_err(|e| anyhow::anyhow!("Gossipsub config error: {}", e))?;

        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(keystore.keypair().clone()),
            gossipsub_config,
        )
        .map_err(|e| anyhow::anyhow!("Gossipsub creation error: {}", e))?;

        let mut kademlia_config = kad::Config::default();
        kademlia_config.set_query_timeout(Duration::from_secs(60));
        kademlia_config.set_replication_factor(std::num::NonZeroUsize::new(3).unwrap());
        let store = kad::store::MemoryStore::new(peer_id);
        let kademlia = kad::Behaviour::with_config(peer_id, store, kademlia_config);

        let identify = identify::Behaviour::new(identify::Config::new(
            "/ego/1.0.0".to_string(),
            keystore.keypair().public(),
        ));

        let autonat = autonat::Behaviour::new(peer_id, autonat::Config::default());

        let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)?;

        let ping = ping::Behaviour::new(ping::Config::new());

        let behaviour = NodeBehaviour {
            gossipsub,
            kademlia,
            identify,
            autonat,
            mdns,
            ping,
        };

        let swarm_config = libp2p::swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(Duration::from_secs(60));
        let swarm = Swarm::new(transport, behaviour, peer_id, swarm_config);

        let roles_set: HashSet<NodeRole> = roles.into_iter().collect();

        info!(
            "Creating node {} with roles: {:?}, shards: {:?}",
            peer_id, roles_set, shard_ids
        );

        let mut node = Node {
            peer_id,
            swarm,
            keystore,
            listen_addresses: Vec::new(),
            bootstrap_peers: Vec::new(),
            roles: roles_set,
            shard_ids,
            shard_configs: HashMap::new(),
            placements: Vec::new(),
            storage_capacity_bytes: 0,
            geohash: None,
            bandwidth_capacity_bps: 0,
            slice_id: None,
            max_peers_per_shard: 100,
            max_topics_per_role: 20,
            recent_proofs: Vec::new(),
        };

        node.subscribe_to_topics()?;
        Ok(node)
    }

    pub fn subscribe_to_topics(&mut self) -> anyhow::Result<()> {
        for &shard_id in &self.shard_ids {
            if self.has_role(NodeRole::Validator) {
                self.swarm
                    .behaviour_mut()
                    .gossipsub
                    .subscribe(&gossipsub::IdentTopic::new(format!(
                        "ego/shard/{}/tx",
                        shard_id
                    )))?;
                self.swarm
                    .behaviour_mut()
                    .gossipsub
                    .subscribe(&gossipsub::IdentTopic::new(format!(
                        "ego/shard/{}/headers",
                        shard_id
                    )))?;
                self.swarm
                    .behaviour_mut()
                    .gossipsub
                    .subscribe(&gossipsub::IdentTopic::new(format!(
                        "ego/shard/{}/receipts",
                        shard_id
                    )))?;
            }

            if self.has_role(NodeRole::Storage) {
                self.swarm
                    .behaviour_mut()
                    .gossipsub
                    .subscribe(&gossipsub::IdentTopic::new(format!(
                        "ego/shard/{}/proofs",
                        shard_id
                    )))?;
            }
        }

        if self.has_role(NodeRole::Validator) {
            self.swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&gossipsub::IdentTopic::new("ego/finality/commits"))?;
        }

        if self.has_role(NodeRole::Witness) {
            if let Some(ref geohash) = self.geohash {
                self.swarm
                    .behaviour_mut()
                    .gossipsub
                    .subscribe(&gossipsub::IdentTopic::new(format!(
                        "ego/poc/h3/{}",
                        geohash
                    )))?;
            }
        }

        if self.has_role(NodeRole::Storage) {
            self.swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&gossipsub::IdentTopic::new("ego/storage"))?;
            self.swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&gossipsub::IdentTopic::new("ego/storage/placement"))?;
            self.swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&gossipsub::IdentTopic::new("ego/storage/repair"))?;
        }

        info!("Subscribed to topics for roles: {:?}", self.roles);
        Ok(())
    }

    pub fn add_role(&mut self, role: NodeRole) -> anyhow::Result<()> {
        if self.roles.insert(role) {
            info!("Added role: {:?}", role);
            self.subscribe_to_topics()?;
        }
        Ok(())
    }

    pub fn remove_role(&mut self, role: NodeRole) {
        if self.roles.remove(&role) {
            info!("Removed role: {:?}", role);
        }
    }

    pub fn has_role(&self, role: NodeRole) -> bool {
        self.roles.contains(&role)
    }

    pub fn get_roles(&self) -> &HashSet<NodeRole> {
        &self.roles
    }

    pub fn add_shard(&mut self, shard_id: u32, config: ShardConfig) -> anyhow::Result<()> {
        if !self.shard_ids.contains(&shard_id) {
            self.shard_ids.push(shard_id);
            self.shard_configs.insert(shard_id, config);
            info!("Added shard: {}", shard_id);
            self.subscribe_to_topics()?;
        }
        Ok(())
    }

    pub fn remove_shard(&mut self, shard_id: u32) {
        self.shard_ids.retain(|&id| id != shard_id);
        self.shard_configs.remove(&shard_id);
        info!("Removed shard: {}", shard_id);
    }

    pub fn add_placement(&mut self, placement: Placement) {
        info!(
            "Added placement for piece {} in group {:?} as {:?}",
            placement.piece_id, placement.group_id, placement.role
        );
        self.placements.push(placement);
    }

    pub fn promote_replica(
        &mut self,
        group_id: [u8; 16],
        new_primary: String,
    ) -> anyhow::Result<()> {
        for placement in &mut self.placements {
            if placement.group_id == group_id {
                let proof_event = ProofEvent {
                    event_type: "promotion".to_string(),
                    shard_id: None,
                    piece_id: Some(placement.piece_id),
                    group_id: Some(group_id),
                    evidence_digest: vec![],
                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                    peer_id: new_primary.clone(),
                };
                self.emit_proof_event(&proof_event);
                info!("Promoted replica for group {:?}", group_id);
                break;
            }
        }
        Ok(())
    }

    pub fn schedule_repair(&mut self, group_id: [u8; 16]) -> anyhow::Result<()> {
        let proof_event = ProofEvent {
            event_type: "repair".to_string(),
            shard_id: None,
            piece_id: None,
            group_id: Some(group_id),
            evidence_digest: vec![],
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            peer_id: self.peer_id.to_string(),
        };
        self.emit_proof_event(&proof_event);
        info!("Scheduled repair for group {:?}", group_id);
        Ok(())
    }

    pub fn emit_proof_event(&mut self, event: &ProofEvent) {
        debug!("Emitting proof event: {:?}", event.event_type);
        self.recent_proofs.push(event.clone());
        if self.recent_proofs.len() > 100 {
            self.recent_proofs.remove(0);
        }
    }

    pub fn emit_poc_proof(
        &mut self,
        h3_cell: String,
        evidence_digest: Vec<u8>,
    ) -> anyhow::Result<()> {
        let event = ProofEvent {
            event_type: "poc".to_string(),
            shard_id: None,
            piece_id: None,
            group_id: None,
            evidence_digest,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            peer_id: self.peer_id.to_string(),
        };
        self.emit_proof_event(&event);
        let topic = gossipsub::IdentTopic::new(format!("ego/poc/h3/{}", h3_cell));
        let message = format!("{:?}", event).into_bytes();
        let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, message);
        Ok(())
    }

    pub fn emit_post_proof(
        &mut self,
        shard_id: u32,
        piece_id: u32,
        evidence_digest: Vec<u8>,
    ) -> anyhow::Result<()> {
        let event = ProofEvent {
            event_type: "post".to_string(),
            shard_id: Some(shard_id),
            piece_id: Some(piece_id),
            group_id: None,
            evidence_digest,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            peer_id: self.peer_id.to_string(),
        };
        self.emit_proof_event(&event);
        let topic = gossipsub::IdentTopic::new(format!("ego/shard/{}/proofs", shard_id));
        let message = format!("{:?}", event).into_bytes();
        let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, message);
        Ok(())
    }

    pub fn set_geolocation(&mut self, lat: f64, lon: f64, precision: usize) {
        let geohash = format!("geo_{}_{}_p{}", lat, lon, precision);
        self.geohash = Some(geohash.clone());
        info!("Node geohash set to: {}", geohash);
    }

    pub fn set_bandwidth_capacity(&mut self, bps: u64) {
        self.bandwidth_capacity_bps = bps;
        info!("Node bandwidth capacity set to: {} bps", bps);
    }

    pub fn set_storage_capacity(&mut self, bytes: u64) {
        self.storage_capacity_bytes = bytes;
        info!("Node storage capacity set to: {} bytes", bytes);
    }

    pub fn set_slice_configuration(&mut self, slice_id: String) {
        self.slice_id = Some(slice_id.clone());
        info!("Node configured for 5G slice: {}", slice_id);
    }

    pub fn bind_on_chain_identity(&mut self, account_pubkey: Vec<u8>, signature: Vec<u8>) {
        self.keystore
            .bind_on_chain_account_simple(account_pubkey, signature);
        info!("Bound on-chain identity to peer {}", self.peer_id);
    }

    pub fn dht_put_record(
        &mut self,
        key: Vec<u8>,
        value: Vec<u8>,
        shard_id: Option<u32>,
    ) -> anyhow::Result<()> {
        let namespaced_key = match shard_id {
            Some(id) => {
                let mut namespaced = format!("shard-{}/", id).into_bytes();
                namespaced.extend(key);
                namespaced
            }
            None => key,
        };
        let record = kad::Record::new(namespaced_key, value);
        self.swarm
            .behaviour_mut()
            .kademlia
            .put_record(record, kad::Quorum::One)?;
        Ok(())
    }

    pub fn dht_get_record(&mut self, key: Vec<u8>, shard_id: Option<u32>) -> anyhow::Result<()> {
        let namespaced_key = match shard_id {
            Some(id) => {
                let mut namespaced = format!("shard-{}/", id).into_bytes();
                namespaced.extend(key);
                namespaced
            }
            None => key,
        };
        self.swarm
            .behaviour_mut()
            .kademlia
            .get_record(kad::RecordKey::new(&namespaced_key));
        Ok(())
    }

    pub fn add_bootstrap_peer(&mut self, addr: Multiaddr) {
        self.bootstrap_peers.push(addr.clone());
        self.swarm
            .behaviour_mut()
            .kademlia
            .add_address(&self.peer_id, addr.clone());
        info!("Added bootstrap peer: {}", addr);
    }

    pub async fn start_listening(&mut self, port: u16) -> anyhow::Result<()> {
        let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", port).parse()?;
        self.swarm.listen_on(listen_addr.clone())?;
        self.listen_addresses.push(listen_addr);
        Ok(())
    }

    pub fn configure_resource_limits(&mut self, max_peers: u32, max_topics: u32) {
        self.max_peers_per_shard = max_peers;
        self.max_topics_per_role = max_topics;
        info!(
            "Configured resource limits: max_peers={}, max_topics={}",
            max_peers, max_topics
        );
    }

    pub fn is_5g_ready(&self) -> bool {
        self.slice_id.is_some()
            && self.geohash.is_some()
            && self.bandwidth_capacity_bps >= 100_000_000
    }

    pub fn get_capabilities(&self) -> Vec<&'static str> {
        let mut capabilities = Vec::new();

        if self.has_role(NodeRole::Validator) {
            capabilities.extend_from_slice(&[
                "block_validation",
                "consensus_participation",
                "cross_shard_validation",
            ]);
        }
        if self.has_role(NodeRole::Storage) {
            capabilities.extend_from_slice(&[
                "data_storage",
                "proof_of_spacetime",
                "erasure_coding",
            ]);
        }
        if self.has_role(NodeRole::Relay) {
            capabilities.extend_from_slice(&["packet_routing", "network_relay"]);
        }
        if self.has_role(NodeRole::Witness) {
            capabilities.extend_from_slice(&[
                "proof_of_coverage",
                "beacon_reporting",
                "h3_coverage",
            ]);
        }
        if self.has_role(NodeRole::Gateway) {
            capabilities.extend_from_slice(&["api_gateway", "http_interface", "rate_limiting"]);
        }
        if self.has_role(NodeRole::Seed) {
            capabilities.extend_from_slice(&["peer_discovery", "bootstrap_service", "dht_seeding"]);
        }
        if self.has_role(NodeRole::Indexer) {
            capabilities.extend_from_slice(&[
                "data_indexing",
                "search_service",
                "cross_shard_indexing",
            ]);
        }

        capabilities
    }

    pub fn get_summary(&self) -> String {
        format!(
            "Node {} - Roles: {:?}, Shards: {:?}, Geohash: {:?}, Bandwidth: {} bps, Storage: {} bytes, Placements: {}",
            self.peer_id,
            self.roles,
            self.shard_ids,
            self.geohash,
            self.bandwidth_capacity_bps,
            self.storage_capacity_bytes,
            self.placements.len()
        )
    }
}

impl Node {
    pub async fn new_validator(shard_ids: Vec<u32>) -> anyhow::Result<Self> {
        Self::new(vec![NodeRole::Validator], shard_ids).await
    }

    pub async fn new_storage_miner(capacity_bytes: u64, geohash: String) -> anyhow::Result<Self> {
        let mut node = Self::new(vec![NodeRole::Storage, NodeRole::Witness], vec![]).await?;
        node.set_storage_capacity(capacity_bytes);
        node.geohash = Some(geohash);
        Ok(node)
    }

    pub async fn new_5g_edge_gateway(
        slice_id: String,
        lat: f64,
        lon: f64,
        bandwidth_bps: u64,
    ) -> anyhow::Result<Self> {
        let mut node = Self::new(
            vec![NodeRole::Gateway, NodeRole::Witness, NodeRole::Relay],
            vec![],
        )
        .await?;
        node.set_slice_configuration(slice_id);
        node.set_geolocation(lat, lon, 7);
        node.set_bandwidth_capacity(bandwidth_bps);
        Ok(node)
    }

    pub async fn new_full_node(shard_ids: Vec<u32>, storage_capacity: u64) -> anyhow::Result<Self> {
        let mut node = Self::new(
            vec![NodeRole::Validator, NodeRole::Storage, NodeRole::Relay],
            shard_ids,
        )
        .await?;
        node.set_storage_capacity(storage_capacity);
        Ok(node)
    }
}
