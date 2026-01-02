use crate::{
    P2PError, P2PMessage, P2PResult, behaviour::EgoBehaviour, config::NetworkConfig,
    peer::PeerManager, topic::TopicManager,
};
use ego_core::{Address, KeyPair, ShardId};
use libp2p::{
    Multiaddr, PeerId, Swarm, Transport, core::upgrade::Version, gossipsub::IdentTopic, identity,
    noise, yamux,
};
use std::sync::Arc;
use tracing::{debug, info};

pub struct NetworkManager {
    pub swarm: Swarm<EgoBehaviour>,
    pub peer_manager: Arc<PeerManager>,
    pub topic_manager: Arc<TopicManager>,
    pub config: NetworkConfig,
    pub keypair: KeyPair,
    pub peer_id: PeerId,
    pub address: Address,
    pub shard_ids: Vec<u32>,
    pub started: bool,
}

impl NetworkManager {
    pub async fn new(
        keypair: KeyPair,
        config: NetworkConfig,
        shard_ids: Vec<u32>,
    ) -> P2PResult<Self> {
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

        info!("Network manager created with peer_id: {}", peer_id);

        Ok(Self {
            swarm,
            peer_manager,
            topic_manager,
            config,
            keypair,
            peer_id,
            address,
            shard_ids,
            started: false,
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

            self.swarm.dial(addr.clone()).map_err(|e| {
                P2PError::ConnectionError(format!("Failed to dial {}: {}", addr, e))
            })?;

            info!("Added bootstrap peer: {}", addr);
        }

        Ok(())
    }

    pub async fn publish_message(&mut self, topic: &str, message: P2PMessage) -> P2PResult<()> {
        let encoded = crate::codec::MessageCodec::encode(&message)?;

        let gossip_topic = IdentTopic::new(topic);
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(gossip_topic, encoded)
            .map_err(|e| P2PError::NetworkError(format!("Publish failed: {}", e)))?;

        self.topic_manager.increment_message_count(topic);
        debug!("Published message to topic: {}", topic);
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

    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.swarm.connected_peers().copied().collect()
    }

    pub fn is_connected_to_peer(&self, peer_id: &PeerId) -> bool {
        self.swarm.is_connected(peer_id)
    }

    pub fn get_network_stats(&self) -> crate::NetworkStats {
        crate::NetworkStats {
            total_peers: self.peer_manager.get_all_peers().len(),
            connected_peers: self.peer_manager.count_connected_peers(),
            total_messages_sent: 0,
            total_messages_received: 0,
            total_bytes_sent: 0,
            total_bytes_received: 0,
            active_topics: self.topic_manager.get_all_topics().len(),
            uptime_seconds: 0,
        }
    }
}
