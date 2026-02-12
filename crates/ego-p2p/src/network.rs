use crate::{
    NetworkMetrics, P2PError, P2PMessage, P2PResult, behaviour::EgoBehaviour,
    config::NetworkConfig, discovery::DiscoveryManager, peer::PeerManager, topic::TopicManager,
};
use ego_core::{Address, KeyPair, ShardId};
use libp2p::{
    Multiaddr, PeerId, Swarm, Transport, core::upgrade::Version, gossipsub::IdentTopic, identity,
    kad, noise, yamux,
};
use std::collections::VecDeque;
use std::sync::Arc;
use tracing::{debug, info};

pub struct PublishQueue {
    queue: VecDeque<(String, P2PMessage)>,
    max_size: usize,
}

impl PublishQueue {
    pub fn new(max_size: usize) -> Self {
        Self {
            queue: VecDeque::with_capacity(max_size),
            max_size,
        }
    }

    pub fn enqueue(&mut self, topic: String, message: P2PMessage) -> Result<(), ()> {
        if self.queue.len() >= self.max_size {
            return Err(());
        }
        self.queue.push_back((topic, message));
        Ok(())
    }

    pub fn dequeue(&mut self) -> Option<(String, P2PMessage)> {
        self.queue.pop_front()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

pub struct NetworkManager {
    pub swarm: Swarm<EgoBehaviour>,
    pub peer_manager: Arc<PeerManager>,
    pub topic_manager: Arc<TopicManager>,
    pub discovery_manager: Arc<DiscoveryManager>,
    pub config: NetworkConfig,
    pub keypair: KeyPair,
    pub peer_id: PeerId,
    pub address: Address,
    pub shard_ids: Vec<u32>,
    pub started: bool,
    pub metrics: Arc<NetworkMetrics>,
    pub publish_queues: Arc<dashmap::DashMap<String, PublishQueue>>,
}

impl NetworkManager {
    pub async fn new(
        keypair: KeyPair,
        config: NetworkConfig,
        shard_ids: Vec<u32>,
    ) -> P2PResult<Self> {
        config.validate()?;

        let libp2p_keypair = Self::create_libp2p_keypair(&keypair)?;
        let peer_id = PeerId::from_public_key(&libp2p_keypair.public());
        let address = Address::from_public_key(&keypair.ed25519_public_key());

        let transport = libp2p::tcp::tokio::Transport::default()
            .upgrade(Version::V1)
            .authenticate(noise::Config::new(&libp2p_keypair)?)
            .multiplex(yamux::Config::default())
            .timeout(config.connection_timeout)
            .boxed();

        let behaviour = EgoBehaviour::new(&libp2p_keypair, peer_id, config.enable_mdns)?;

        let swarm_config = libp2p::swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(config.idle_connection_timeout)
            .with_notify_handler_buffer_size(std::num::NonZeroUsize::new(32).unwrap())
            .with_per_connection_event_buffer_size(64);

        let swarm = Swarm::new(transport, behaviour, peer_id, swarm_config);

        let peer_manager = Arc::new(PeerManager::new(config.max_peers));
        let topic_manager = Arc::new(TopicManager::new());
        let discovery_manager = Arc::new(DiscoveryManager::new(config.max_peers));
        let metrics = Arc::new(NetworkMetrics::new());
        let publish_queues = Arc::new(dashmap::DashMap::new());

        info!("Network manager created with peer_id: {}", peer_id);

        Ok(Self {
            swarm,
            peer_manager,
            topic_manager,
            discovery_manager,
            config,
            keypair,
            peer_id,
            address,
            shard_ids,
            started: false,
            metrics,
            publish_queues,
        })
    }

    fn create_libp2p_keypair(keypair: &KeyPair) -> P2PResult<identity::Keypair> {
        let ed25519_pk = keypair.ed25519_public_key();
        let ed25519_bytes = ed25519_pk.as_bytes();

        if ed25519_bytes.len() != 32 {
            return Err(P2PError::AuthenticationError(
                "Invalid Ed25519 public key length".to_string(),
            ));
        }

        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&ed25519_bytes[..32]);

        let secret = identity::ed25519::SecretKey::try_from_bytes(secret_bytes)
            .map_err(|e| P2PError::AuthenticationError(format!("Invalid Ed25519 key: {:?}", e)))?;
        let keypair = identity::ed25519::Keypair::from(secret);
        Ok(identity::Keypair::from(keypair))
    }

    pub async fn start(&mut self) -> P2PResult<()> {
        if self.started {
            return Ok(());
        }

        for addr in &self.config.listen_addresses {
            self.swarm.listen_on(addr.clone()).map_err(|e| {
                P2PError::NetworkError(format!("Failed to listen on {}: {}", addr, e))
            })?;
            info!("Listening on: {}", addr);
        }

        self.subscribe_to_topics().await?;

        let bootstrap_peers = self.config.bootstrap_peers.clone();
        for addr in bootstrap_peers {
            self.add_bootstrap_peer(addr).await?;
        }

        self.started = true;
        info!("Network manager started successfully");
        Ok(())
    }

    async fn subscribe_to_topics(&mut self) -> P2PResult<()> {
        let topics = crate::topic::get_standard_topics(&self.shard_ids);

        for (topic_name, shard_id) in topics {
            self.topic_manager
                .register_topic(topic_name.clone(), shard_id)?;

            let topic = IdentTopic::new(topic_name.clone());
            self.swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&topic)
                .map_err(|e| P2PError::TopicError(format!("Subscribe failed: {}", e)))?;

            self.publish_queues.insert(
                topic_name.clone(),
                PublishQueue::new(self.config.publish_queue_size),
            );

            debug!("Subscribed to topic: {}", topic_name);
        }

        info!(
            "Subscribed to {} topics",
            self.topic_manager.get_all_topics().len()
        );
        Ok(())
    }

    pub async fn add_bootstrap_peer(&mut self, addr: Multiaddr) -> P2PResult<()> {
        if let Some(libp2p::multiaddr::Protocol::P2p(peer_id)) = addr.iter().last() {
            self.swarm
                .behaviour_mut()
                .kademlia
                .add_address(&peer_id, addr.clone());

            self.peer_manager.add_peer(peer_id)?;

            let _ = self.swarm.behaviour_mut().kademlia.bootstrap();

            self.swarm.dial(addr.clone()).map_err(|e| {
                P2PError::ConnectionError(format!("Failed to dial {}: {}", addr, e))
            })?;

            info!("Added bootstrap peer and initiated bootstrap: {}", addr);
        }

        Ok(())
    }

    pub async fn publish_message(&mut self, topic: &str, message: P2PMessage) -> P2PResult<()> {
        let encoded = crate::codec::MessageCodec::encode(&message)?;
        let gossip_topic = IdentTopic::new(topic);

        let peer_count = self
            .swarm
            .behaviour()
            .gossipsub
            .mesh_peers(&gossip_topic.hash())
            .count();

        if peer_count == 0 {
            if let Some(mut queue) = self.publish_queues.get_mut(topic) {
                if queue.enqueue(topic.to_string(), message).is_ok() {
                    info!("Message queued for topic {} (no peers)", topic);
                    self.metrics.set_publish_queue_length(queue.len());
                    return Ok(());
                } else {
                    return Err(P2PError::QueueFullError(format!(
                        "Publish queue full for topic {}",
                        topic
                    )));
                }
            }
        }

        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(gossip_topic, encoded.clone())
            .map_err(|e| P2PError::NetworkError(format!("Publish failed: {}", e)))?;

        self.topic_manager.increment_message_count(topic);
        self.metrics.increment_messages_sent();
        self.metrics.add_bytes_sent(encoded.len() as u64);
        self.metrics
            .add_topic_bandwidth_out(topic.to_string(), encoded.len() as u64);

        debug!("Published message to topic: {}", topic);
        Ok(())
    }

    pub async fn process_publish_queues(&mut self) -> P2PResult<()> {
        let topics: Vec<String> = self
            .publish_queues
            .iter()
            .map(|entry| entry.key().clone())
            .collect();

        for topic in topics {
            let gossip_topic = IdentTopic::new(&topic);
            let peer_count = self
                .swarm
                .behaviour()
                .gossipsub
                .mesh_peers(&gossip_topic.hash())
                .count();

            if peer_count > 0 {
                if let Some(mut queue) = self.publish_queues.get_mut(&topic) {
                    while let Some((_, message)) = queue.dequeue() {
                        let encoded = crate::codec::MessageCodec::encode(&message)?;
                        self.swarm
                            .behaviour_mut()
                            .gossipsub
                            .publish(gossip_topic.clone(), encoded.clone())
                            .map_err(|e| {
                                P2PError::NetworkError(format!("Publish failed: {}", e))
                            })?;

                        self.metrics.increment_messages_sent();
                        self.metrics.add_bytes_sent(encoded.len() as u64);
                        info!("Dequeued and published message to topic {}", topic);
                    }
                    self.metrics.set_publish_queue_length(queue.len());
                }
            }
        }

        Ok(())
    }

    pub async fn broadcast_to_shard(
        &mut self,
        shard_id: ShardId,
        message_type: &str,
        message: P2PMessage,
    ) -> P2PResult<()> {
        let topic = TopicManager::build_topic_name("ego", Some(shard_id.as_u32()), message_type);
        self.publish_message(&topic, message).await
    }

    pub async fn start_providing_evidence(&mut self, cid: Vec<u8>) -> P2PResult<()> {
        let key = DiscoveryManager::evidence_record_key(&cid);
        self.swarm
            .behaviour_mut()
            .kademlia
            .start_providing(key)
            .map_err(|e| P2PError::DhtError(format!("Failed to start providing: {:?}", e)))?;
        info!("Started providing evidence for CID: {:?}", cid);
        Ok(())
    }

    pub async fn start_providing_da(
        &mut self,
        blob_id: Vec<u8>,
        chunk_index: u64,
    ) -> P2PResult<()> {
        let key = DiscoveryManager::da_record_key(&blob_id, chunk_index);
        self.swarm
            .behaviour_mut()
            .kademlia
            .start_providing(key)
            .map_err(|e| P2PError::DhtError(format!("Failed to start providing: {:?}", e)))?;
        info!(
            "Started providing DA for blob: {:?}, chunk: {}",
            blob_id, chunk_index
        );
        Ok(())
    }

    pub async fn find_evidence_providers(&mut self, cid: Vec<u8>) -> P2PResult<kad::QueryId> {
        let key = DiscoveryManager::evidence_record_key(&cid);
        let query_id = self.swarm.behaviour_mut().kademlia.get_providers(key);
        Ok(query_id)
    }

    pub async fn find_da_providers(
        &mut self,
        blob_id: Vec<u8>,
        chunk_index: u64,
    ) -> P2PResult<kad::QueryId> {
        let key = DiscoveryManager::da_record_key(&blob_id, chunk_index);
        let query_id = self.swarm.behaviour_mut().kademlia.get_providers(key);
        Ok(query_id)
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn peer_manager(&self) -> Arc<PeerManager> {
        self.peer_manager.clone()
    }

    pub fn topic_manager(&self) -> Arc<TopicManager> {
        self.topic_manager.clone()
    }

    pub fn discovery_manager(&self) -> Arc<DiscoveryManager> {
        self.discovery_manager.clone()
    }

    pub fn metrics(&self) -> Arc<NetworkMetrics> {
        self.metrics.clone()
    }

    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.swarm.connected_peers().copied().collect()
    }

    pub fn is_connected_to_peer(&self, peer_id: &PeerId) -> bool {
        self.swarm.is_connected(peer_id)
    }

    pub fn get_network_stats(&self) -> crate::NetworkStats {
        let connected = self.swarm.connected_peers().count();
        let gossipsub_peers = self.swarm.behaviour().gossipsub.all_peers().count();

        self.metrics.set_connected_peers(connected);

        crate::NetworkStats {
            total_peers: self.peer_manager.get_all_peers().len(),
            connected_peers: connected,
            gossipsub_peers,
            total_messages_sent: self
                .metrics
                .messages_sent
                .load(std::sync::atomic::Ordering::Relaxed),
            total_messages_received: self
                .metrics
                .messages_received
                .load(std::sync::atomic::Ordering::Relaxed),
            total_bytes_sent: self
                .metrics
                .bytes_sent
                .load(std::sync::atomic::Ordering::Relaxed),
            total_bytes_received: self
                .metrics
                .bytes_received
                .load(std::sync::atomic::Ordering::Relaxed),
            active_topics: self.topic_manager.get_all_topics().len(),
            uptime_seconds: 0,
        }
    }

    pub fn get_topic_peer_counts(&self) -> Vec<(String, usize)> {
        let mut counts = Vec::new();
        for topic_info in self.topic_manager.get_all_topics() {
            let topic = IdentTopic::new(&topic_info.name);
            let count = self
                .swarm
                .behaviour()
                .gossipsub
                .mesh_peers(&topic.hash())
                .count();
            self.metrics
                .set_topic_peer_count(topic_info.name.clone(), count);
            counts.push((topic_info.name, count));
        }
        counts
    }
}
