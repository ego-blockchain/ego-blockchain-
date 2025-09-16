use crate::{BandwidthSharingEvent, NetworkEvent, OptimizerEvent};
use crate::{BandwidthSharingManager, DataOptimizer, NetworkManager, NetworkType};
use crate::{NodeBehaviour, NodeRole, Placement, ProofEvent, SecureKeystore, ShardConfig};

use ego_core::{
    Account, AccountType, Address, Balance, Block, BlockHeight, DeviceCapabilities, EgoResult,
    Hash, SliceId, StateManager, Timestamp, Transaction, TransactionResult,
};

use libp2p::{
    Multiaddr, PeerId, Swarm, Transport, autonat, core::upgrade::Version, gossipsub, identify, kad,
    mdns, noise, ping, tcp, yamux,
};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

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
    pub slice_id: Option<String>,
    keystore: SecureKeystore,
    pub max_peers_per_shard: u32,
    pub max_topics_per_role: u32,
    pub recent_proofs: Vec<ProofEvent>,

    pub state_manager: StateManager,

    pub network_manager: NetworkManager,
    pub bandwidth_sharing: BandwidthSharingManager,
    pub data_optimizer: DataOptimizer,

    pub optimization_events: mpsc::UnboundedSender<OptimizationCommand>,
    optimization_receiver: mpsc::UnboundedReceiver<OptimizationCommand>,

    pub node_type: String,
    pub is_bootstrap: bool,
    pub connection_attempts: u32,
    pub last_proof_time: SystemTime,
    pub performance_metrics: PerformanceMetrics,
}

#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    pub uptime_seconds: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub proof_events_generated: u64,
    pub peer_connections_established: u64,
    pub peer_connections_lost: u64,
    pub bandwidth_shared_bytes: u64,
    pub data_compressed_bytes: u64,
    pub network_switches: u64,
    pub cost_savings_usd: f64,
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            uptime_seconds: 0,
            messages_sent: 0,
            messages_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            proof_events_generated: 0,
            peer_connections_established: 0,
            peer_connections_lost: 0,
            bandwidth_shared_bytes: 0,
            data_compressed_bytes: 0,
            network_switches: 0,
            cost_savings_usd: 0.0,
        }
    }
}

#[derive(Debug, Clone)]
pub enum OptimizationCommand {
    EnableBandwidthSharing(u64, u64),
    DisableBandwidthSharing,
    SwitchNetwork(NetworkType),
    OptimizeData(String, String, Vec<u8>, u8),
    ProcessBatches,
    ProcessScheduledOps,
    UpdateNetworkStats(NetworkType, u64),
    ConnectToPeer(Multiaddr),
    UpdateMetrics(String, u64),
}

impl Node {
    pub fn get_public_key(&self) -> ego_core::PublicKey {
        self.keystore.public_key()
    }

    pub fn get_keypair(&self) -> &ego_core::KeyPair {
        self.keystore.keypair()
    }

    pub fn get_address(&self) -> Address {
        Address::from_public_key(&self.keystore.public_key())
    }
}

impl Node {
    pub async fn new(roles: Vec<NodeRole>, shard_ids: Vec<u32>) -> anyhow::Result<Self> {
        let keystore = SecureKeystore::new();
        let peer_id = keystore.peer_id();

        let transport = tcp::tokio::Transport::default()
            .upgrade(Version::V1)
            .authenticate(noise::Config::new(&keystore.libp2p_keypair())?)
            .multiplex(yamux::Config::default())
            .timeout(Duration::from_secs(30))
            .boxed();

        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(10))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .max_transmit_size(2 * 1024 * 1024)
            .duplicate_cache_time(Duration::from_secs(120))
            .message_id_fn(|message| {
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut hasher = DefaultHasher::new();
                message.data.hash(&mut hasher);
                gossipsub::MessageId::from(hasher.finish().to_string().into_bytes())
            })
            .build()
            .map_err(|e| anyhow::anyhow!("Gossipsub config error: {}", e))?;

        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(keystore.libp2p_keypair()),
            gossipsub_config,
        )
        .map_err(|e| anyhow::anyhow!("Gossipsub creation error: {}", e))?;

        let mut kademlia_config = kad::Config::default();
        kademlia_config.set_query_timeout(Duration::from_secs(60));
        kademlia_config.set_replication_factor(std::num::NonZeroUsize::new(5).unwrap());
        kademlia_config.set_parallelism(std::num::NonZeroUsize::new(3).unwrap());
        let store = kad::store::MemoryStore::new(peer_id);
        let kademlia = kad::Behaviour::with_config(peer_id, store, kademlia_config);

        let identify = identify::Behaviour::new(
            identify::Config::new("/ego/1.0.0".to_string(), keystore.libp2p_keypair().public())
                .with_interval(Duration::from_secs(30)),
        );

        let autonat = autonat::Behaviour::new(
            peer_id,
            autonat::Config {
                retry_interval: Duration::from_secs(30),
                refresh_interval: Duration::from_secs(300),
                boot_delay: Duration::from_secs(5),
                throttle_server_period: Duration::from_secs(1),
                ..Default::default()
            },
        );

        let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)?;

        let ping = ping::Behaviour::new(
            ping::Config::new()
                .with_interval(Duration::from_secs(30))
                .with_timeout(Duration::from_secs(10)),
        );

        let behaviour = NodeBehaviour {
            gossipsub,
            kademlia,
            identify,
            autonat,
            mdns,
            ping,
        };

        let swarm_config = libp2p::swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(Duration::from_secs(120))
            .with_notify_handler_buffer_size(std::num::NonZeroUsize::new(32).unwrap())
            .with_per_connection_event_buffer_size(64);

        let swarm = Swarm::new(transport, behaviour, peer_id, swarm_config);

        let roles_set: HashSet<NodeRole> = roles.into_iter().collect();

        let network_manager = NetworkManager::new();
        let bandwidth_sharing = BandwidthSharingManager::new(Default::default());
        let data_optimizer = DataOptimizer::new();
        let state_manager = StateManager::new();

        let (optimization_events, optimization_receiver) = mpsc::unbounded_channel();

        info!(
            "Creating optimized node {} with roles: {:?}, shards: {:?}",
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
            state_manager,
            network_manager,
            bandwidth_sharing,
            data_optimizer,
            optimization_events,
            optimization_receiver,
            node_type: "full".to_string(),
            is_bootstrap: false,
            connection_attempts: 0,
            last_proof_time: SystemTime::now(),
            performance_metrics: PerformanceMetrics::default(),
        };

        node.subscribe_to_topics()?;
        Ok(node)
    }

    pub async fn new_validator(shard_ids: Vec<u32>) -> anyhow::Result<Self> {
        let mut node = Self::new(vec![NodeRole::Validator, NodeRole::Relay], shard_ids).await?;
        node.node_type = "validator".to_string();
        node.max_peers_per_shard = 150;
        node.max_topics_per_role = 25;

        let _ = node.enable_bandwidth_sharing(25, 500);

        let validator_address = Address::from_public_key(&node.keystore.public_key());
        let validator_account = Account::new_validator(
            validator_address,
            node.keystore.public_key(),
            500,
            Balance::from_egoc(1000),
        )?;
        node.state_manager.set_account(validator_account);

        info!("✅ Validator node created with enhanced consensus capabilities");
        Ok(node)
    }

    pub async fn new_storage_miner(capacity_bytes: u64, geohash: String) -> anyhow::Result<Self> {
        let mut node = Self::new(vec![NodeRole::Storage, NodeRole::Witness], vec![]).await?;
        node.node_type = "storage".to_string();
        node.set_storage_capacity(capacity_bytes);
        node.geohash = Some(geohash.clone());
        node.max_peers_per_shard = 100;
        node.max_topics_per_role = 15;

        let _ = node.enable_bandwidth_sharing(50, 1000);

        let device_address = Address::from_public_key(&node.keystore.public_key());
        let capabilities = DeviceCapabilities {
            bandwidth_capacity: node.bandwidth_capacity_bps,
            storage_capacity: capacity_bytes,
            supported_slices: vec![],
            coverage_area: Some(geohash),
            hardware_specs: HashMap::new(),
            last_poc: None,
            post_stats: Default::default(),
        };

        let device_account = Account::new_device(
            device_address,
            format!("storage-{}", node.peer_id),
            capabilities,
        );
        node.state_manager.set_account(device_account);

        info!(
            "✅ Storage miner created with {} GB capacity",
            capacity_bytes / 1_000_000_000
        );
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

        node.node_type = "gateway".to_string();
        node.set_slice_configuration(slice_id.clone());
        node.set_geolocation(lat, lon, 7);
        node.set_bandwidth_capacity(bandwidth_bps);
        node.max_peers_per_shard = 500;
        node.max_topics_per_role = 30;

        let bandwidth_mbps = bandwidth_bps / 1_000_000;
        let sharing_bandwidth = (bandwidth_mbps / 2).max(100);
        let _ = node.enable_bandwidth_sharing(sharing_bandwidth, 3000);

        let gateway_address = Address::from_public_key(&node.keystore.public_key());
        let capabilities = DeviceCapabilities {
            bandwidth_capacity: bandwidth_bps,
            storage_capacity: 10_000_000_000,
            supported_slices: vec![SliceId::new(slice_id.clone())],
            coverage_area: Some(format!("geo_{}_{}_p7", lat, lon)),
            hardware_specs: HashMap::from([
                ("type".to_string(), "5g_gateway".to_string()),
                ("slice".to_string(), slice_id.clone()),
            ]),
            last_poc: None,
            post_stats: Default::default(),
        };

        let gateway_account = Account::new_device(
            gateway_address,
            format!("gateway-{}-{}", slice_id, node.peer_id),
            capabilities,
        );
        node.state_manager.set_account(gateway_account);

        info!(
            "✅ 5G Edge Gateway created with {} Mbps capacity",
            bandwidth_mbps
        );
        Ok(node)
    }

    pub async fn new_full_node(shard_ids: Vec<u32>, storage_capacity: u64) -> anyhow::Result<Self> {
        let mut node = Self::new(
            vec![
                NodeRole::Validator,
                NodeRole::Storage,
                NodeRole::Relay,
                NodeRole::Witness,
            ],
            shard_ids,
        )
        .await?;

        node.node_type = "full".to_string();
        node.set_storage_capacity(storage_capacity);
        node.max_peers_per_shard = 200;
        node.max_topics_per_role = 25;

        let _ = node.enable_bandwidth_sharing(75, 1500);

        let node_address = Address::from_public_key(&node.keystore.public_key());
        let mut full_account = Account::new_user(node_address);
        full_account.storage_quota = storage_capacity;
        full_account.credit(Balance::from_egoc(1000));
        node.state_manager.set_account(full_account);

        info!("✅ Full node created with comprehensive capabilities");
        Ok(node)
    }

    pub async fn new_seed_node() -> anyhow::Result<Self> {
        let mut node = Self::new(vec![NodeRole::Seed, NodeRole::Relay], vec![]).await?;
        node.node_type = "seed".to_string();
        node.is_bootstrap = true;
        node.max_peers_per_shard = 1000;
        node.max_topics_per_role = 50;

        let _ = node.enable_bandwidth_sharing(200, 5000);

        let seed_address = Address::from_public_key(&node.keystore.public_key());
        let mut seed_account = Account::new_user(seed_address);
        seed_account.storage_quota = 50_000_000_000;
        seed_account.credit(Balance::from_egoc(10000));
        node.state_manager.set_account(seed_account);

        info!("✅ Seed node created for network bootstrapping");
        Ok(node)
    }

    pub async fn new_indexer_node(
        shard_ids: Vec<u32>,
        storage_capacity: u64,
    ) -> anyhow::Result<Self> {
        let mut node = Self::new(vec![NodeRole::Indexer, NodeRole::Storage], shard_ids).await?;
        node.node_type = "indexer".to_string();
        node.set_storage_capacity(storage_capacity);
        node.max_peers_per_shard = 150;
        node.max_topics_per_role = 20;

        let _ = node.enable_bandwidth_sharing(40, 800);

        let indexer_address = Address::from_public_key(&node.keystore.public_key());
        let mut indexer_account = Account::new_user(indexer_address);
        indexer_account.storage_quota = storage_capacity;
        indexer_account.credit(Balance::from_egoc(500));
        node.state_manager.set_account(indexer_account);

        info!("✅ Indexer node created with cross-shard indexing capabilities");
        Ok(node)
    }

    pub async fn execute_transaction(&mut self, tx: &Transaction) -> EgoResult<TransactionResult> {
        self.state_manager.execute_transaction(tx)
    }

    pub async fn create_block(
        &mut self,
        transactions: Vec<Transaction>,
        previous_hash: Hash,
        height: BlockHeight,
    ) -> EgoResult<Block> {
        let shard_id = if !self.shard_ids.is_empty() {
            ego_core::ShardId::new(self.shard_ids[0])?
        } else {
            ego_core::ShardId::new(0)?
        };

        let proposer_address = Address::from_public_key(&self.keystore.public_key());

        let block = Block::new(
            height,
            previous_hash,
            shard_id,
            ego_core::EpochNumber::new(height.as_u64() / 1000),
            proposer_address,
            transactions,
            vec![],
        );

        Ok(block)
    }

    pub async fn validate_block(&self, block: &Block) -> EgoResult<bool> {
        block.validate_structure()?;

        if let Some(account) = self.state_manager.get_account(&block.header.proposer) {
            match &account.account_type {
                AccountType::Validator {
                    validator_pubkey, ..
                } => {
                    return block.verify_signature(validator_pubkey);
                }
                _ => {}
            }
        }

        Ok(true)
    }

    pub async fn start_listening(&mut self, port: u16) -> anyhow::Result<()> {
        let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", port).parse()?;
        self.swarm.listen_on(listen_addr.clone())?;
        self.listen_addresses.push(listen_addr.clone());

        info!("🎧 Node listening on {}", listen_addr);
        Ok(())
    }

    pub fn add_bootstrap_peer(&mut self, addr: Multiaddr) {
        if !self.bootstrap_peers.contains(&addr) {
            self.bootstrap_peers.push(addr.clone());
            self.swarm
                .behaviour_mut()
                .kademlia
                .add_address(&self.peer_id, addr.clone());
            info!("🔗 Added bootstrap peer: {}", addr);
        }
    }

    pub async fn connect_to_bootstrap_peers(&mut self) -> anyhow::Result<()> {
        for addr in self.bootstrap_peers.clone() {
            match self.swarm.dial(addr.clone()) {
                Ok(_) => {
                    info!("📞 Dialing bootstrap peer: {}", addr);
                    self.connection_attempts += 1;
                }
                Err(e) => {
                    warn!("❌ Failed to dial bootstrap peer {}: {}", addr, e);
                }
            }
        }
        Ok(())
    }

    pub fn enable_bandwidth_sharing(
        &mut self,
        max_bandwidth_mbps: u64,
        daily_limit_mb: u64,
    ) -> anyhow::Result<()> {
        self.bandwidth_sharing
            .enable_sharing(max_bandwidth_mbps, daily_limit_mb);
        let _ = self
            .optimization_events
            .send(OptimizationCommand::EnableBandwidthSharing(
                max_bandwidth_mbps,
                daily_limit_mb,
            ));

        info!(
            "💰 Bandwidth sharing enabled: {} Mbps, {} MB daily limit",
            max_bandwidth_mbps, daily_limit_mb
        );
        Ok(())
    }

    pub fn disable_bandwidth_sharing(&mut self) -> anyhow::Result<()> {
        self.bandwidth_sharing.disable_sharing();
        let _ = self
            .optimization_events
            .send(OptimizationCommand::DisableBandwidthSharing);
        info!("🚫 Bandwidth sharing disabled");
        Ok(())
    }

    pub fn emit_poc_proof(
        &mut self,
        h3_cell: String,
        evidence_digest: Vec<u8>,
    ) -> anyhow::Result<()> {
        let event = ego_core::ProofEvent {
            proof_type: "poc".to_string(),
            prover: Address::from_public_key(&self.keystore.public_key()),
            challenge_hash: Hash::new(rand::random()),
            proof_data: evidence_digest,
            location_id: h3_cell.clone(),
            slice_id: self.slice_id.clone(),
            timestamp: Timestamp::now(),
            verified: false,
        };

        let node_proof = ProofEvent {
            event_type: "poc".to_string(),
            shard_id: None,
            piece_id: None,
            group_id: None,
            evidence_digest: event.proof_data.clone(),
            timestamp: event.timestamp.as_millis(),
            peer_id: self.peer_id.to_string(),
        };

        self.recent_proofs.push(node_proof);
        self.performance_metrics.proof_events_generated += 1;

        let topic = gossipsub::IdentTopic::new(format!("ego/poc/h3/{}", h3_cell));
        let message = serde_json::to_string(&event)
            .unwrap_or_default()
            .into_bytes();
        let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, message);

        info!("✅ PoC proof emitted for H3 cell: {}", h3_cell);
        Ok(())
    }

    pub fn emit_post_proof(
        &mut self,
        shard_id: u32,
        piece_id: u32,
        evidence_digest: Vec<u8>,
    ) -> anyhow::Result<()> {
        let event = ego_core::ProofEvent {
            proof_type: "post".to_string(),
            prover: Address::from_public_key(&self.keystore.public_key()),
            challenge_hash: Hash::new(rand::random()),
            proof_data: evidence_digest,
            location_id: format!("shard-{}-piece-{}", shard_id, piece_id),
            slice_id: self.slice_id.clone(),
            timestamp: Timestamp::now(),
            verified: false,
        };

        let node_proof = ProofEvent {
            event_type: "post".to_string(),
            shard_id: Some(shard_id),
            piece_id: Some(piece_id),
            group_id: None,
            evidence_digest: event.proof_data.clone(),
            timestamp: event.timestamp.as_millis(),
            peer_id: self.peer_id.to_string(),
        };

        self.recent_proofs.push(node_proof);
        self.performance_metrics.proof_events_generated += 1;

        let topic = gossipsub::IdentTopic::new(format!("ego/shard/{}/proofs", shard_id));
        let message = serde_json::to_string(&event)
            .unwrap_or_default()
            .into_bytes();
        let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, message);

        info!(
            "✅ PoST proof emitted for shard {} piece {}",
            shard_id, piece_id
        );
        Ok(())
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
                self.swarm
                    .behaviour_mut()
                    .gossipsub
                    .subscribe(&gossipsub::IdentTopic::new(format!(
                        "ego/shard/{}/consensus",
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
                self.swarm
                    .behaviour_mut()
                    .gossipsub
                    .subscribe(&gossipsub::IdentTopic::new(format!(
                        "ego/shard/{}/storage",
                        shard_id
                    )))?;
            }

            if self.has_role(NodeRole::Indexer) {
                self.swarm
                    .behaviour_mut()
                    .gossipsub
                    .subscribe(&gossipsub::IdentTopic::new(format!(
                        "ego/shard/{}/index",
                        shard_id
                    )))?;
            }
        }

        if self.has_role(NodeRole::Validator) {
            self.swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&gossipsub::IdentTopic::new("ego/finality/commits"))?;
            self.swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&gossipsub::IdentTopic::new("ego/consensus/global"))?;
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
            self.swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&gossipsub::IdentTopic::new("ego/witness/beacons"))?;
        }

        if self.has_role(NodeRole::Storage) {
            self.swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&gossipsub::IdentTopic::new("ego/storage/global"))?;
            self.swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&gossipsub::IdentTopic::new("ego/storage/placement"))?;
            self.swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&gossipsub::IdentTopic::new("ego/storage/repair"))?;
        }

        if self.has_role(NodeRole::Gateway) {
            self.swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&gossipsub::IdentTopic::new("ego/gateway/requests"))?;
            self.swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&gossipsub::IdentTopic::new("ego/gateway/responses"))?;
        }

        if self.has_role(NodeRole::Relay) {
            self.swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&gossipsub::IdentTopic::new("ego/relay/routing"))?;
        }

        if self.has_role(NodeRole::Seed) {
            self.swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&gossipsub::IdentTopic::new("ego/seed/discovery"))?;
        }

        if self.has_role(NodeRole::Indexer) {
            self.swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&gossipsub::IdentTopic::new("ego/indexer/global"))?;
            self.swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&gossipsub::IdentTopic::new("ego/indexer/queries"))?;
        }

        self.swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&gossipsub::IdentTopic::new("ego/optimization/bandwidth"))?;
        self.swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&gossipsub::IdentTopic::new("ego/optimization/network"))?;

        info!("📡 Subscribed to topics for roles: {:?}", self.roles);
        Ok(())
    }

    pub async fn process_optimization_events(&mut self) -> anyhow::Result<()> {
        while let Ok(event) = self.network_manager.event_receiver.try_recv() {
            match event {
                NetworkEvent::InterfaceChanged(new_type) => {
                    info!("🌐 Network interface changed to: {:?}", new_type);
                    self.performance_metrics.network_switches += 1;
                }
                NetworkEvent::DataThresholdReached(usage_gb) => {
                    warn!("⚠️ Data threshold reached: {:.2} GB", usage_gb);
                    if self
                        .network_manager
                        .interfaces
                        .get(&NetworkType::WiFi)
                        .map_or(false, |i| i.is_available)
                    {
                        let _ = self
                            .optimization_events
                            .send(OptimizationCommand::SwitchNetwork(NetworkType::WiFi));
                    }
                }
                NetworkEvent::CostThresholdReached(cost) => {
                    warn!("💰 Cost threshold reached: ${:.2}", cost);
                }
                _ => {}
            }
        }

        while let Ok(event) = self.bandwidth_sharing.event_receiver.try_recv() {
            match event {
                BandwidthSharingEvent::DeviceConnected(device_id) => {
                    info!("📱 Device connected for bandwidth sharing: {}", device_id);
                }
                BandwidthSharingEvent::EgocEarned(amount) => {
                    debug!("💰 Earned {:.4} EGOC from bandwidth sharing", amount);
                    self.performance_metrics.cost_savings_usd += amount as f64 * 0.1;
                }
                _ => {}
            }
        }

        while let Ok(event) = self.data_optimizer.event_receiver.try_recv() {
            match event {
                OptimizerEvent::BatchReady(batch_id) => {
                    info!("📦 Batch ready for processing: {}", batch_id);
                    let _ = self
                        .optimization_events
                        .send(OptimizationCommand::ProcessBatches);
                }
                OptimizerEvent::CompressionCompleted(op_id, ratio) => {
                    debug!("🗜️ Compression completed for {}: ratio {:.2}", op_id, ratio);
                }
                _ => {}
            }
        }

        while let Ok(command) = self.optimization_receiver.try_recv() {
            match command {
                OptimizationCommand::SwitchNetwork(network_type) => {
                    self.network_manager.current_interface = network_type.clone();
                    info!("🔄 Switched to network: {:?}", network_type);
                }
                OptimizationCommand::ConnectToPeer(addr) => {
                    if let Err(e) = self.swarm.dial(addr.clone()) {
                        warn!("❌ Failed to connect to peer {}: {}", addr, e);
                    } else {
                        info!("📞 Connecting to peer: {}", addr);
                    }
                }
                OptimizationCommand::UpdateMetrics(metric_name, value) => {
                    debug!("📊 Updating metric {}: {}", metric_name, value);
                }
                _ => {}
            }
        }

        Ok(())
    }

    pub fn has_role(&self, role: NodeRole) -> bool {
        self.roles.contains(&role)
    }

    pub fn get_roles(&self) -> &HashSet<NodeRole> {
        &self.roles
    }

    pub fn set_geolocation(&mut self, lat: f64, lon: f64, precision: usize) {
        let geohash = format!("geo_{}_{}_p{}", lat, lon, precision);
        self.geohash = Some(geohash.clone());
        info!("📍 Node geohash set to: {}", geohash);
    }

    pub fn set_bandwidth_capacity(&mut self, bps: u64) {
        self.bandwidth_capacity_bps = bps;
        info!("📶 Node bandwidth capacity set to: {} bps", bps);
    }

    pub fn set_storage_capacity(&mut self, bytes: u64) {
        self.storage_capacity_bytes = bytes;
        info!("💾 Node storage capacity set to: {} bytes", bytes);
    }

    pub fn set_slice_configuration(&mut self, slice_id: String) {
        self.slice_id = Some(slice_id.clone());
        info!("📡 Node configured for 5G slice: {}", slice_id);
    }

    pub fn configure_resource_limits(&mut self, max_peers: u32, max_topics: u32) {
        self.max_peers_per_shard = max_peers;
        self.max_topics_per_role = max_topics;
        info!(
            "⚙️ Configured resource limits: max_peers={}, max_topics={}",
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
                "finality_commitment",
            ]);
        }
        if self.has_role(NodeRole::Storage) {
            capabilities.extend_from_slice(&[
                "data_storage",
                "proof_of_spacetime",
                "erasure_coding",
                "replica_management",
            ]);
        }
        if self.has_role(NodeRole::Relay) {
            capabilities.extend_from_slice(&[
                "packet_routing",
                "network_relay",
                "message_forwarding",
            ]);
        }
        if self.has_role(NodeRole::Witness) {
            capabilities.extend_from_slice(&[
                "proof_of_coverage",
                "beacon_reporting",
                "h3_coverage",
                "location_verification",
            ]);
        }
        if self.has_role(NodeRole::Gateway) {
            capabilities.extend_from_slice(&[
                "api_gateway",
                "http_interface",
                "rate_limiting",
                "request_routing",
            ]);
        }
        if self.has_role(NodeRole::Seed) {
            capabilities.extend_from_slice(&[
                "peer_discovery",
                "bootstrap_service",
                "dht_seeding",
                "network_bootstrapping",
            ]);
        }
        if self.has_role(NodeRole::Indexer) {
            capabilities.extend_from_slice(&[
                "data_indexing",
                "search_service",
                "cross_shard_indexing",
                "query_processing",
            ]);
        }

        capabilities.extend_from_slice(&[
            "bandwidth_sharing",
            "data_optimization",
            "network_switching",
            "cost_optimization",
            "compression",
            "batch_processing",
            "scheduled_operations",
        ]);

        capabilities
    }

    pub fn get_summary(&self) -> String {
        let sharing_stats = self.get_bandwidth_sharing_stats();
        let opt_stats = self.get_optimization_stats();
        let network_summary = self.get_data_usage_summary();
        let connected_peers = self.swarm.connected_peers().count();
        let state_stats = self.state_manager.get_stats();

        format!(
            "Node {} [{}] - Roles: {:?}, Shards: {:?}, Peers: {}, Accounts: {}, Network: {:?}, Sharing: {} active, Data saved: {:.1}MB, Proofs: {}, {}",
            self.peer_id,
            self.node_type,
            self.roles,
            self.shard_ids,
            connected_peers,
            state_stats.total_accounts,
            self.network_manager.current_interface,
            sharing_stats.active_connections,
            opt_stats.total_bandwidth_saved_mb,
            self.performance_metrics.proof_events_generated,
            network_summary
        )
    }

    pub fn get_bandwidth_sharing_stats(&self) -> crate::bandwidth_sharing::BandwidthSharingStats {
        self.bandwidth_sharing.get_sharing_stats()
    }

    pub fn get_optimization_stats(&self) -> crate::data_optimizer::OptimizationStats {
        self.data_optimizer.get_optimization_stats()
    }

    pub fn get_data_usage_summary(&self) -> String {
        self.network_manager.get_data_usage_summary()
    }

    pub fn get_performance_metrics(&self) -> &PerformanceMetrics {
        &self.performance_metrics
    }

    pub fn update_uptime(&mut self) {
        self.performance_metrics.uptime_seconds += 1;
    }

    pub fn record_peer_connection(&mut self) {
        self.performance_metrics.peer_connections_established += 1;
    }

    pub fn record_peer_disconnection(&mut self) {
        self.performance_metrics.peer_connections_lost += 1;
    }

    pub fn update_network_interface_status(
        &mut self,
        interface_type: NetworkType,
        available: bool,
        signal_strength: Option<u8>,
    ) {
        self.network_manager
            .update_interface_status(interface_type, available, signal_strength);
    }

    pub fn is_cost_effective_time(&self) -> bool {
        self.network_manager.is_off_peak_hours()
    }

    pub fn get_account(&self, address: &Address) -> Option<Account> {
        self.state_manager.get_account(address)
    }

    pub fn get_balance(&self, address: &Address) -> Balance {
        self.state_manager
            .get_account(address)
            .map(|acc| acc.balance)
            .unwrap_or(Balance::ZERO)
    }

    pub fn get_state_root(&self) -> Hash {
        self.state_manager.compute_state_root()
    }

    pub fn get_block_height(&self) -> BlockHeight {
        self.state_manager.get_block_height()
    }
}
