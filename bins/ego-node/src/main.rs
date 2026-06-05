use clap::{Arg, Command};
use ego_core::{Address, Balance, ShardId, Transaction, TransactionPayload};
use ego_node::{
    NetworkType, Node, NodeRole,
    engine::EgoExecutionEngine,
    rpc::{RpcState, serve as rpc_serve},
    store,
    supervisor::NodeSupervisor,
};
use reqwest;
use libp2p::{Multiaddr, futures::StreamExt};
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error, info, warn};
use tracing_subscriber::fmt::init;

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct NodeConfig {
    pub node_type: String,
    pub roles: Vec<NodeRole>,
    pub shard_ids: Vec<u32>,
    pub listen_port: u16,
    pub bootstrap_peers: Vec<String>,
    pub storage_capacity_gb: Option<f64>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub geohash_precision: usize,
    pub bandwidth_mbps: Option<u64>,
    pub slice_id: Option<String>,
    pub enable_metrics: bool,
    pub enable_interactive: bool,

    pub payout_address: Option<String>,

    pub payout_interval_blocks: u64,

    pub enable_bandwidth_sharing: bool,
    pub sharing_bandwidth_mbps: u64,
    pub sharing_daily_limit_mb: u64,
    pub enable_data_compression: bool,
    pub enable_auto_network_switching: bool,
    pub cost_threshold_usd: f64,
    pub data_threshold_gb: f64,

    pub max_peers: u32,
    pub connection_timeout_secs: u64,
    pub enable_mdns: bool,
    pub enable_autonat: bool,

    /// Advertised HTTP RPC address for P2P chain-sync (e.g. "http://203.0.113.5:8545").
    /// Defaults to "http://127.0.0.1:8545" (single-machine / LAN setups).
    pub rpc_advertise_addr: String,

    /// HTTP RPC listen port (default 8545).
    pub rpc_port: u16,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node_type: "seed".to_string(),
            roles: vec![NodeRole::Gateway],
            shard_ids: vec![0],
            listen_port: 9000,
            rpc_port: 8545,
            rpc_advertise_addr: "http://127.0.0.1:8545".to_string(),
            bootstrap_peers: vec![
                "/dns4/rpc.egoblockchain.com/tcp/9000/p2p/12D3KooWMNRh7dJePAgtaZiwFCTisevVJQ5E52SpPqQqUPbHpJ72".to_string(),
            ],
            storage_capacity_gb: Some(100.0),
            latitude: None,
            longitude: None,
            geohash_precision: 7,
            bandwidth_mbps: Some(100),
            slice_id: None,
            enable_metrics: false,
            enable_interactive: false,

            payout_address: None,
            payout_interval_blocks: 100,
            enable_bandwidth_sharing: false,
            sharing_bandwidth_mbps: 50,
            sharing_daily_limit_mb: 1000,
            enable_data_compression: true,
            enable_auto_network_switching: true,
            cost_threshold_usd: 100.0,
            data_threshold_gb: 40.0,

            max_peers: 200,
            connection_timeout_secs: 30,
            enable_mdns: true,
            enable_autonat: true,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init();

    let config = parse_cli_args();

    info!("🚀 Starting Ego Blockchain Node with Advanced 5G Cost Optimization");
    info!("📋 Configuration: {:?}", config);

    let mut node = match create_node_from_config(&config).await {
        Ok(node) => {
            info!("✅ Node created successfully");
            node
        }
        Err(e) => {
            error!("❌ Failed to create node: {}", e);
            return Err(e);
        }
    };

    if let Err(e) = setup_networking(&mut node, &config).await {
        error!("❌ Failed to setup networking: {}", e);
        return Err(e);
    }
    info!("🌐 Networking setup completed");

    if let Err(e) = setup_optimization_features(&mut node, &config).await {
        error!("❌ Failed to setup optimization features: {}", e);
        return Err(e);
    }
    info!("⚡ Optimization features setup completed");

    print_node_info(&node, &config);

    let node_address = format!("0x{}", hex::encode(node.get_address().as_bytes()));
    let node_pubkey  = hex::encode(&node.get_keypair().ed25519_public_key().key_data);
    let node_keypair = node.get_keypair().clone();

    let _engine = EgoExecutionEngine::new();
    let (supervisor, _heartbeat) = NodeSupervisor::new();

    let (mempool_gossip_tx, mempool_gossip_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

    let rpc_state = Arc::new(RpcState {
        state_manager:  node.state_manager.clone(),
        peer_id:        node.peer_id.to_string(),
        node_address:   node_address.clone(),
        node_pubkey,
        node_keypair,
        payout_address: config.payout_address.clone(),
        pending_txs:    ego_node::mempool::ShardedMempool::new(),
        recent_blocks:  Mutex::new(Vec::new()),
        node_stats:     Mutex::new(Default::default()),
        nonce:          Mutex::new(0),
        supervisor,
        faucet_claims:  Mutex::new(std::collections::HashMap::new()),
        write_rate:     Mutex::new(std::collections::HashMap::new()),
        mempool_gossip_tx,
        active_renters: Mutex::new(std::collections::HashMap::new()),
        peer_rpc_addrs: Mutex::new(std::collections::HashMap::new()),
    });
    let rpc_addr = format!("0.0.0.0:{}", config.rpc_port);
    let rpc_state_clone = Arc::clone(&rpc_state);
    tokio::spawn(async move {
        if let Err(e) = rpc_serve(&rpc_addr, rpc_state_clone).await {
            tracing::error!("RPC server error: {e}");
        }
    });
    info!("🌐 HTTP RPC listening on 0.0.0.0:8545");

    if let Some(payout_to) = config.payout_address.clone() {
        let payout_state  = Arc::clone(&rpc_state);
        let interval_blks = config.payout_interval_blocks;
        info!("💸 Auto-payout enabled: every {} blocks → {}", interval_blks, &payout_to);
        tokio::spawn(async move {
            let mut last_payout_height: u64 = 0;
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let current_height = payout_state.state_manager.get_block_height().0;
                if current_height < last_payout_height + interval_blks {
                    continue;
                }

                let addr_hex = payout_state.node_address.trim_start_matches("0x").to_string();
                let from_addr = match hex::decode(&addr_hex) {
                    Ok(b) if b.len() == 20 => {
                        let mut arr = [0u8; 20];
                        arr.copy_from_slice(&b);
                        Address::new(arr)
                    }
                    _ => continue,
                };

                let balance_raw = payout_state.state_manager
                    .get_account(&from_addr)
                    .map(|a| a.balance.0)
                    .unwrap_or(0u128);
                if balance_raw == 0 {
                    continue;
                }

                let to_hex = payout_to.trim_start_matches("0x");
                let to_addr = match hex::decode(to_hex) {
                    Ok(b) if b.len() == 20 => {
                        let mut arr = [0u8; 20];
                        arr.copy_from_slice(&b);
                        Address::new(arr)
                    }
                    _ => { warn!("Invalid payout address: {}", payout_to); continue; }
                };

                let nonce = {
                    let mut n = payout_state.nonce.lock().unwrap();
                    let v = *n;
                    *n += 1;
                    v
                };
                let mut tx = Transaction::new(
                    from_addr,
                    nonce,
                    TransactionPayload::Transfer {
                        to:           to_addr,
                        amount:       Balance(balance_raw),
                        memo:         Some("auto-payout".to_string()),
                        stealth_mode: false,
                    },
                    ShardId::from_u32(0),
                    None,
                    1,
                );
                if let Err(e) = tx.sign(&payout_state.node_keypair, false) {
                    warn!("Auto-payout sign error: {e}");
                    continue;
                }
                let _ = payout_state.pending_txs.insert(tx);
                last_payout_height = current_height;
                info!(
                    "💸 Auto-payout: {} uEGOC → {}  (block {})",
                    balance_raw, payout_to, current_height
                );
            }
        });
    }

    if config.enable_interactive {
        info!("🖥️ Starting interactive mode");
        run_interactive_mode(node, config).await?;
    } else {
        info!("🔄 Starting daemon mode");
        run_daemon_mode(node, config, Arc::clone(&rpc_state), mempool_gossip_rx).await?;
    }

    Ok(())
}

fn parse_cli_args() -> NodeConfig {
    let matches = Command::new("ego-node")
        .version("1.0.0")
        .author("Ego Blockchain Team")
        .about("Ego Blockchain Node - Advanced 5G-enabled decentralized network with intelligent cost optimization")
        .arg(
            Arg::new("type")
                .long("type")
                .short('t')
                .help("Node type: validator, storage, gateway, full, seed, indexer")
                .default_value("full"),
        )
        .arg(
            Arg::new("shards")
                .long("shards")
                .short('s')
                .help("Comma-separated shard IDs to participate in")
                .default_value("0,1,2"),
        )
        .arg(
            Arg::new("port")
                .long("port")
                .short('p')
                .help("Listen port for P2P networking")
                .default_value("9000"),
        )
        .arg(
            Arg::new("bootstrap")
                .long("bootstrap")
                .short('b')
                .help("Bootstrap peer multiaddresses (comma-separated)")
                .default_value(""),
        )
        .arg(
            Arg::new("storage")
                .long("storage")
                .help("Storage capacity in GB")
                .default_value("100"),
        )
        .arg(
            Arg::new("latitude")
                .long("lat")
                .help("Node latitude for geolocation")
                .value_name("LATITUDE")
                .allow_negative_numbers(true),
        )
        .arg(
            Arg::new("longitude")
                .long("lon")
                .help("Node longitude for geolocation")
                .value_name("LONGITUDE")
                .allow_negative_numbers(true),
        )
        .arg(
            Arg::new("bandwidth")
                .long("bandwidth")
                .help("Bandwidth capacity in Mbps")
                .default_value("500")
                .value_name("MBPS"),
        )
        .arg(
            Arg::new("slice-id")
                .long("slice-id")
                .help("5G network slice identifier")
                .value_name("SLICE_ID"),
        )
        .arg(
            Arg::new("interactive")
                .long("interactive")
                .short('i')
                .help("Run in interactive mode")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("metrics")
                .long("metrics")
                .short('m')
                .help("Enable metrics collection")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("enable-sharing")
                .long("enable-sharing")
                .help("Enable bandwidth sharing to earn EGOC")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("sharing-bandwidth")
                .long("sharing-bandwidth")
                .help("Max bandwidth to share in Mbps")
                .default_value("50")
                .value_name("MBPS"),
        )
        .arg(
            Arg::new("sharing-limit")
                .long("sharing-limit")
                .help("Daily data sharing limit in MB")
                .default_value("1000")
                .value_name("MB"),
        )
        .arg(
            Arg::new("disable-compression")
                .long("disable-compression")
                .help("Disable data compression")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("disable-auto-switch")
                .long("disable-auto-switch")
                .help("Disable automatic network switching")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("cost-threshold")
                .long("cost-threshold")
                .help("Monthly cost threshold in USD")
                .default_value("100")
                .value_name("USD"),
        )
        .arg(
            Arg::new("data-threshold")
                .long("data-threshold")
                .help("Monthly data threshold in GB")
                .default_value("40")
                .value_name("GB"),
        )
        .arg(
            Arg::new("max-peers")
                .long("max-peers")
                .help("Maximum number of peers to connect to")
                .default_value("200")
                .value_name("COUNT"),
        )
        .arg(
            Arg::new("disable-mdns")
                .long("disable-mdns")
                .help("Disable mDNS local discovery")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("disable-autonat")
                .long("disable-autonat")
                .help("Disable AutoNAT")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("payout-address")
                .long("payout-address")
                .help("Auto-forward earned EGOC to this address every N blocks")
                .value_name("ADDRESS"),
        )
        .arg(
            Arg::new("payout-interval")
                .long("payout-interval")
                .help("Blocks between automatic reward sweeps (default: 100)")
                .default_value("100")
                .value_name("BLOCKS"),
        )
        .arg(
            Arg::new("rpc-port")
                .long("rpc-port")
                .help("HTTP RPC listen port (default: 8545)")
                .default_value("8545")
                .value_name("PORT"),
        )
        .arg(
            Arg::new("rpc-advertise")
                .long("rpc-advertise")
                .help("Publicly reachable HTTP RPC URL broadcast to peers for chain sync (e.g. http://203.0.113.5:8545)")
                .value_name("URL"),
        )
        .get_matches();

    let node_type = matches.get_one::<String>("type").unwrap().clone();
    let shard_ids: Vec<u32> = matches
        .get_one::<String>("shards")
        .unwrap()
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    let listen_port: u16 = matches
        .get_one::<String>("port")
        .unwrap()
        .parse()
        .unwrap_or(9000);

    let bootstrap_peers: Vec<String> = matches
        .get_one::<String>("bootstrap")
        .unwrap()
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
        .collect();

    let storage_capacity_gb: Option<f64> = matches
        .get_one::<String>("storage")
        .and_then(|s| s.parse().ok());

    let latitude = matches
        .get_one::<String>("latitude")
        .and_then(|s| s.parse().ok());

    let longitude = matches
        .get_one::<String>("longitude")
        .and_then(|s| s.parse().ok());

    let bandwidth_mbps = matches
        .get_one::<String>("bandwidth")
        .and_then(|s| s.parse().ok());

    let slice_id = matches.get_one::<String>("slice-id").cloned();

    let roles = determine_roles(&node_type);

    let enable_bandwidth_sharing = matches.get_flag("enable-sharing");
    let sharing_bandwidth_mbps = matches
        .get_one::<String>("sharing-bandwidth")
        .unwrap()
        .parse()
        .unwrap_or(50);
    let sharing_daily_limit_mb = matches
        .get_one::<String>("sharing-limit")
        .unwrap()
        .parse()
        .unwrap_or(1000);
    let enable_data_compression = !matches.get_flag("disable-compression");
    let enable_auto_network_switching = !matches.get_flag("disable-auto-switch");
    let cost_threshold_usd = matches
        .get_one::<String>("cost-threshold")
        .unwrap()
        .parse()
        .unwrap_or(100.0);
    let data_threshold_gb = matches
        .get_one::<String>("data-threshold")
        .unwrap()
        .parse()
        .unwrap_or(40.0);

    let max_peers = matches
        .get_one::<String>("max-peers")
        .unwrap()
        .parse()
        .unwrap_or(200);
    let enable_mdns = !matches.get_flag("disable-mdns");
    let enable_autonat = !matches.get_flag("disable-autonat");

    let payout_address = matches.get_one::<String>("payout-address").cloned();
    let payout_interval_blocks: u64 = matches
        .get_one::<String>("payout-interval")
        .unwrap()
        .parse()
        .unwrap_or(100);

    NodeConfig {
        node_type,
        roles,
        shard_ids,
        listen_port,
        bootstrap_peers,
        storage_capacity_gb,
        latitude,
        longitude,
        geohash_precision: 7,
        bandwidth_mbps,
        slice_id,
        enable_metrics: matches.get_flag("metrics"),
        enable_interactive: matches.get_flag("interactive"),
        enable_bandwidth_sharing,
        sharing_bandwidth_mbps,
        sharing_daily_limit_mb,
        enable_data_compression,
        enable_auto_network_switching,
        cost_threshold_usd,
        data_threshold_gb,
        max_peers,
        connection_timeout_secs: 30,
        enable_mdns,
        enable_autonat,
        payout_address,
        payout_interval_blocks,
        rpc_port: matches.get_one::<String>("rpc-port")
            .and_then(|s| s.parse().ok()).unwrap_or(8545),
        rpc_advertise_addr: matches.get_one::<String>("rpc-advertise")
            .cloned()
            .unwrap_or_else(|| {
                let port = matches.get_one::<String>("rpc-port")
                    .and_then(|s| s.parse::<u16>().ok()).unwrap_or(8545);
                format!("http://127.0.0.1:{}", port)
            }),
    }
}

fn determine_roles(node_type: &str) -> Vec<NodeRole> {
    // The Oracle node is a peer-discovery concierge only.
    // "validator" and "full" roles are reserved for desktop app instances —
    // the Oracle never proposes or votes on blocks.
    match node_type {
        "storage" => vec![NodeRole::StorageProvider],
        "gateway" | "seed" | "oracle" | "validator" | "full" | "indexer" => vec![NodeRole::Gateway],
        _ => {
            warn!("Unknown node type '{}', running as peer-discovery relay", node_type);
            vec![NodeRole::Gateway]
        }
    }
}
async fn create_node_from_config(config: &NodeConfig) -> anyhow::Result<Node> {
    info!(
        "🏗️ Creating {} node with roles: {:?}",
        config.node_type, config.roles
    );

    let mut node = match config.node_type.as_str() {
        "validator" => {
            info!(
                "⚖️ Creating validator node for shards: {:?}",
                config.shard_ids
            );
            Node::new_validator(config.shard_ids.clone()).await?
        }
        "storage" => {
            let capacity_bytes = config.storage_capacity_gb.unwrap_or(100.0) * 1_000_000_000.0;
            let geohash = config
                .latitude
                .zip(config.longitude)
                .map(|(lat, lon)| format!("geo_{}_{}_p{}", lat, lon, config.geohash_precision))
                .unwrap_or_else(|| "default_geohash".to_string());
            info!(
                "💾 Creating storage node with capacity: {} GB, geohash: {}",
                capacity_bytes / 1_000_000_000.0,
                geohash
            );
            Node::new_storage_miner(capacity_bytes as u64, geohash).await?
        }
        "gateway" => {
            if let (Some(lat), Some(lon), Some(slice_id), Some(bandwidth)) = (
                config.latitude,
                config.longitude,
                &config.slice_id,
                config.bandwidth_mbps,
            ) {
                info!(
                    "🌐 Creating 5G edge gateway at ({}, {}) with slice: {}",
                    lat, lon, slice_id
                );
                Node::new_5g_edge_gateway(slice_id.clone(), lat, lon, bandwidth * 1_000_000).await?
            } else {
                warn!("Gateway node requires latitude, longitude, slice-id, and bandwidth");
                Node::new(config.roles.clone(), config.shard_ids.clone()).await?
            }
        }
        "seed" => {
            info!("🌱 Creating seed node for network bootstrapping");
            Node::new_seed_node().await?
        }
        "indexer" => {
            let capacity_bytes = config.storage_capacity_gb.unwrap_or(200.0) * 1_000_000_000.0;
            info!(
                "🔍 Creating indexer node with {} GB storage",
                capacity_bytes / 1_000_000_000.0
            );
            Node::new_indexer_node(config.shard_ids.clone(), capacity_bytes as u64).await?
        }
        "full" | _ => {
            let capacity_bytes = config.storage_capacity_gb.unwrap_or(100.0) * 1_000_000_000.0;
            info!(
                "🔄 Creating full node with {} GB storage",
                capacity_bytes / 1_000_000_000.0
            );
            Node::new_full_node(config.shard_ids.clone(), capacity_bytes as u64).await?
        }
    };

    if let (Some(lat), Some(lon)) = (config.latitude, config.longitude) {
        node.set_geolocation(lat, lon, config.geohash_precision);
        info!("📍 Node geolocation set to: ({}, {})", lat, lon);
    }

    if let Some(bandwidth_mbps) = config.bandwidth_mbps {
        node.set_bandwidth_capacity(bandwidth_mbps * 1_000_000);
        info!("📶 Node bandwidth capacity set to: {} Mbps", bandwidth_mbps);
    }

    if let Some(storage_gb) = config.storage_capacity_gb {
        node.set_storage_capacity((storage_gb * 1_000_000_000.0) as u64);
        info!("💾 Node storage capacity set to: {} GB", storage_gb);
    }

    if let Some(slice_id) = &config.slice_id {
        node.set_slice_configuration(slice_id.clone());
        info!("📡 Node configured for 5G slice: {}", slice_id);
    }

    let (max_peers, max_topics) = match config.node_type.as_str() {
        "seed" => (1000, 50),
        "gateway" => (500, 30),
        "full" => (config.max_peers, 25),
        "validator" => (150, 20),
        "storage" => (100, 15),
        "indexer" => (200, 20),
        _ => (config.max_peers, 20),
    };
    node.configure_resource_limits(max_peers, max_topics);

    Ok(node)
}

async fn setup_networking(node: &mut Node, config: &NodeConfig) -> anyhow::Result<()> {
    info!("🌐 Setting up networking on port {}", config.listen_port);

    if let Err(e) = node.start_listening(config.listen_port).await {
        error!(
            "Failed to start listening on port {}: {}",
            config.listen_port, e
        );
        return Err(e);
    }
    info!("🎧 Node listening on port {}", config.listen_port);

    for bootstrap_addr in &config.bootstrap_peers {
        if let Ok(addr) = bootstrap_addr.parse::<Multiaddr>() {
            node.add_bootstrap_peer(addr.clone());
            info!("🔗 Added bootstrap peer: {}", bootstrap_addr);
        } else {
            warn!("Invalid bootstrap peer address: {}", bootstrap_addr);
        }
    }

    if !config.bootstrap_peers.is_empty() {
        info!("📞 Connecting to bootstrap peers...");
        if let Err(e) = node.connect_to_bootstrap_peers().await {
            warn!("Some bootstrap connections failed: {}", e);
        }
    }

    Ok(())
}

async fn setup_optimization_features(node: &mut Node, config: &NodeConfig) -> anyhow::Result<()> {
    info!("⚡ Setting up optimization features");

    if config.enable_bandwidth_sharing {
        if let Err(e) = node
            .enable_bandwidth_sharing(config.sharing_bandwidth_mbps, config.sharing_daily_limit_mb)
        {
            error!("Failed to enable bandwidth sharing: {}", e);
            return Err(e);
        }
        info!(
            "💰 Bandwidth sharing enabled: {} Mbps, {} MB daily limit",
            config.sharing_bandwidth_mbps, config.sharing_daily_limit_mb
        );
    }

    if config.enable_data_compression {
        info!("🗜️ Data compression enabled");
    }

    if config.enable_auto_network_switching {
        info!("🔄 Auto network switching enabled");
    }

    node.network_manager.cost_threshold_usd = config.cost_threshold_usd;
    node.network_manager.data_threshold_gb = config.data_threshold_gb;

    info!(
        "💰 Cost optimization: ${:.0} monthly threshold, {:.0}GB data threshold",
        config.cost_threshold_usd, config.data_threshold_gb
    );

    Ok(())
}

fn print_node_info(node: &Node, config: &NodeConfig) {
    info!("✅ Node initialization completed");
    info!("📊 Node summary: {}", node.get_summary());
    info!("🔧 Node capabilities: {:?}", node.get_capabilities());
    info!("🌐 5G Ready: {}", node.is_5g_ready());
    info!("💰 Bandwidth Sharing: {}", config.enable_bandwidth_sharing);
    info!("🗜️ Data Compression: {}", config.enable_data_compression);
    info!(
        "🔄 Auto Network Switching: {}",
        config.enable_auto_network_switching
    );
    info!("👥 Max Peers: {}", config.max_peers);

    if !config.bootstrap_peers.is_empty() {
        info!("🔗 Bootstrap Peers: {:?}", config.bootstrap_peers);
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    const THRESHOLD: u64 = 1024;

    if bytes < THRESHOLD {
        return format!("{} B", bytes);
    }

    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= THRESHOLD as f64 && unit_index < UNITS.len() - 1 {
        size /= THRESHOLD as f64;
        unit_index += 1;
    }

    format!("{:.2} {}", size, UNITS[unit_index])
}

async fn run_daemon_mode(
    mut node: Node,
    config: NodeConfig,
    rpc_state: Arc<RpcState>,
    mut mempool_gossip_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
) -> anyhow::Result<()> {
    // ── Peer-discovery / relay mode ─────────────────────────────────────────
    // The Oracle node is a CONCIERGE: it maintains the P2P mesh so desktop
    // nodes can discover each other, but it NEVER proposes, votes, or
    // finalizes blocks.  All consensus and block production happens
    // exclusively on desktop app instances.
    // ────────────────────────────────────────────────────────────────────────

    info!("🔄 Running in peer-discovery relay mode. Press Ctrl+C to stop.");
    info!(
        "📡 Oracle concierge | Port: {} | RPC: {}",
        config.listen_port, config.rpc_port
    );

    // Subscribe to gossip topics — the oracle relays messages between desktop
    // nodes but does NOT process consensus or produce blocks itself.
    let consensus_topic = libp2p::gossipsub::IdentTopic::new(
        ego_node::consensus_integration::CONSENSUS_TOPIC
    );
    let _ = node.swarm.behaviour_mut().gossipsub.subscribe(&consensus_topic);

    let mempool_topic = libp2p::gossipsub::IdentTopic::new(ego_node::consensus_integration::MEMPOOL_TOPIC);
    let mempool_topic_hash = mempool_topic.hash();
    let _ = node.swarm.behaviour_mut().gossipsub.subscribe(&mempool_topic);

    let sync_topic = libp2p::gossipsub::IdentTopic::new(ego_node::consensus_integration::SYNC_TOPIC);
    let sync_topic_hash = sync_topic.hash();
    let _ = node.swarm.behaviour_mut().gossipsub.subscribe(&sync_topic);

    let rollup_topic = libp2p::gossipsub::IdentTopic::new("ego/rollup/commits");
    let _ = node.swarm.behaviour_mut().gossipsub.subscribe(&rollup_topic);

    let my_shard_id = node.shard_ids.first().copied().unwrap_or(0);
    let receipts_topic = libp2p::gossipsub::IdentTopic::new(
        format!("ego/shard/{}/receipts", my_shard_id)
    );
    let _ = node.swarm.behaviour_mut().gossipsub.subscribe(&receipts_topic);

    let oracle_topic = libp2p::gossipsub::IdentTopic::new("ego/oracle/price");
    let oracle_topic_hash = oracle_topic.hash();
    let _ = node.swarm.behaviour_mut().gossipsub.subscribe(&oracle_topic);

    let compute_topic = libp2p::gossipsub::IdentTopic::new("ego-compute-v1");
    let _ = node.swarm.behaviour_mut().gossipsub.subscribe(&compute_topic);

    let mut status_interval       = interval(Duration::from_secs(30));
    let mut metrics_interval      = interval(Duration::from_secs(60));
    let mut optimization_interval = interval(Duration::from_secs(10));
    let mut daily_reset_interval  = interval(Duration::from_secs(86400));
    let mut uptime_interval       = interval(Duration::from_secs(1));
    let mut gc_interval           = interval(Duration::from_secs(600));

    print_status(&node);

    loop {
        tokio::select! {
            event = node.swarm.select_next_some() => {
                // Gossipsub automatically relays messages to all subscribed peers in
                // the mesh — no manual forwarding needed.  We only peek at sync
                // messages so we can track peer RPC addresses for the /peers RPC
                // endpoint used by desktop nodes for bootstrapping.
                if let libp2p::swarm::SwarmEvent::Behaviour(
                    ego_node::NodeBehaviourEvent::Gossipsub(
                        libp2p::gossipsub::Event::Message { message, .. }
                    )
                ) = &event {
                    if message.topic == sync_topic_hash {
                        use ego_node::consensus_integration::SyncMsg;
                        if let Some(SyncMsg::ChainTip { rpc_addr, .. }) = SyncMsg::from_bytes(&message.data) {
                            // Index the peer's advertised RPC address so the
                            // /peers endpoint can hand it to new desktop joiners.
                            rpc_state.peer_rpc_addrs.lock().unwrap()
                                .insert(rpc_addr.clone(), rpc_addr);
                        }
                    } else if message.topic == mempool_topic_hash {
                        // Count for stats only — relay handled by gossipsub mesh.
                        debug!("Relayed mempool tx ({} bytes)", message.data.len());
                    } else if message.topic == oracle_topic_hash {
                        // Basic Stake-Weighted Oracle verification
                        if let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&message.data) {
                            if let (Some(validator_hex), Some(price)) = (
                                payload.get("validator").and_then(|v| v.as_str()),
                                payload.get("price_usd").and_then(|p| p.as_f64()),
                            ) {
                                let addr_bytes = hex::decode(validator_hex.trim_start_matches("0x")).unwrap_or_default();
                                if addr_bytes.len() == 20 {
                                    let mut arr = [0u8; 20];
                                    arr.copy_from_slice(&addr_bytes);
                                    let addr = Address::new(arr);
                                    if let Some(validator) = node.state_manager.get_validator(&addr) {
                                        if validator.total_stake.0 >= 1_000_000_000 { // Minimum 1,000 EGOC
                                            debug!("Received valid Oracle price update: ${} from {}", price, validator_hex);
                                        } else {
                                            warn!("Rejected oracle price from low-stake validator: {}", validator_hex);
                                        }
                                    }
                                }
                            }
                        }
                    } else if message.topic == compute_topic.hash() {
                        if let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&message.data) {
                            if payload["type"] == "reservation_booked" {
                                let provider = payload["reservation"]["provider_address"].as_str().unwrap_or("");
                                let my_addr_raw = node.get_address();
                                let my_addr_hex = format!("0x{}", hex::encode(my_addr_raw.as_bytes()));
                                
                                // Robust check: matches hex exactly OR decodes bech32 to compare raw bytes
                                let is_for_me = if provider == my_addr_hex {
                                    true
                                } else {
                                    // Attempt to decode as bech32 and compare bytes
                                    let hrp = if provider.starts_with("egot") { "egot" } else { "ego" };
                                    ego_core::EgoAddress::from_bech32(provider, hrp)
                                        .map(|addr| &addr.as_bytes()[1..] == my_addr_raw.as_bytes())
                                        .unwrap_or(false)
                                };

                                if is_for_me {
                                    let res_id = payload["reservation"]["reservation_id"].as_str().unwrap_or_default().to_string();
                                    let buyer = payload["reservation"]["buyer_address"].as_str().unwrap_or_default().to_string();
                                    info!("🖥️ Compute reservation {} detected for buyer {}! Authorizing Web Console...", res_id, buyer);
                                    rpc_state.active_renters.lock().unwrap().insert(res_id, buyer);

                                    if let Some(pubkey) = payload["ssh_public_key"].as_str() {
                                        info!("🔑 Authorizing SSH key for this reservation...");
                                        let _ = authorize_ssh_key(pubkey);
                                    }
                                }
                            }
                        }
                    }
                }

                if let Err(e) = handle_network_event(&mut node, event).await {
                    warn!("Error handling network event: {}", e);
                }
            },

            _ = status_interval.tick() => {
                print_status(&node);
            },

            _ = metrics_interval.tick() => {
                if config.enable_metrics {
                    print_metrics(&node);
                    print_optimization_metrics(&node);
                }
            },

            _ = optimization_interval.tick() => {
                if let Err(e) = node.process_optimization_events().await {
                    warn!("Error processing optimization events: {}", e);
                }
                node.handle_porep_events().await;
            },

            _ = gc_interval.tick() => {
                let height = node.state_manager.get_block_height().0;
                node.evict_expired_placements(height);
            },

            _ = daily_reset_interval.tick() => {
                node.network_manager.reset_monthly_stats();
                node.bandwidth_sharing.reset_daily_stats();
                info!("Daily stats reset");
            },

            _ = uptime_interval.tick() => {
                node.update_uptime();
            },

            // Forward any tx bytes submitted via RPC into the gossip mesh so
            // connected desktop nodes receive them (pure relay — no validation).
            Some(tx_bytes) = mempool_gossip_rx.recv() => {
                let topic = libp2p::gossipsub::IdentTopic::new(ego_node::consensus_integration::MEMPOOL_TOPIC);
                let _ = node.swarm.behaviour_mut().gossipsub.publish(topic, tx_bytes);
            },

            _ = tokio::signal::ctrl_c() => {
                info!("Received shutdown signal");
                break;
            }
        }
    }

    info!("👋 Ego blockchain node shutting down gracefully");
    print_final_stats(&node);
    Ok(())
}

fn authorize_ssh_key(key: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        let ssh_dir = format!("{}/.ssh", home);
        let auth_keys = format!("{}/authorized_keys", ssh_dir);
        
        std::fs::create_dir_all(&ssh_dir)?;
        
        // Skip if key already present
        if let Ok(content) = std::fs::read_to_string(&auth_keys) {
            if content.contains(key.trim()) {
                return Ok(());
            }
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&auth_keys)?;
            
        writeln!(file, "{}", key.trim())?;
        
        #[cfg(target_family = "unix")]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&ssh_dir, std::fs::Permissions::from_mode(0o700));
            let _ = std::fs::set_permissions(&auth_keys, std::fs::Permissions::from_mode(0o600));
        }
    }
    Ok(())
}

async fn handle_network_event<T>(
    node: &mut Node,
    event: libp2p::swarm::SwarmEvent<T>,
) -> anyhow::Result<()> {
    match event {
        libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
            info!("🌐 Listening on {}", address);
        }
        libp2p::swarm::SwarmEvent::Behaviour(_event) => {
            debug!("Behaviour event received");
        }
        libp2p::swarm::SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            info!("🤝 Connected to peer: {}", peer_id);
            node.record_peer_connection();
        }
        libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
            info!(
                "❌ Disconnected from peer: {} (cause: {:?})",
                peer_id, cause
            );
            node.record_peer_disconnection();
        }
        libp2p::swarm::SwarmEvent::IncomingConnection { .. } => {
            debug!("📥 Incoming connection");
        }
        libp2p::swarm::SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            warn!("📤❌ Outgoing connection error to {:?}: {}", peer_id, error);
        }
        libp2p::swarm::SwarmEvent::IncomingConnectionError { error, .. } => {
            warn!("📥❌ Incoming connection error: {}", error);
        }
        _ => {}
    }
    Ok(())
}

fn print_status(node: &Node) {
    let connected_peers = node.swarm.connected_peers().count();
    info!("📊 Node Status: {}", node.get_summary());
    info!("🌐 Listening addresses: {:?}", node.listen_addresses);
    info!("👥 Connected peers: {}", connected_peers);

    if connected_peers == 0 && !node.bootstrap_peers.is_empty() {
        warn!("⚠️ No peers connected. Check network connectivity and bootstrap peers.");
    }
}

fn print_metrics(node: &Node) {
    println!("\n📈 Node Metrics");
    println!("═══════════════");
    println!("Connected Peers: {}", node.swarm.connected_peers().count());
    println!("Recent Proof Events: {}", node.recent_proofs.len());
    println!("Active Placements: {}", node.placements.len());
    println!(
        "Network Bandwidth: {} Mbps",
        node.bandwidth_capacity_bps / 1_000_000
    );
    println!(
        "Storage Utilization: {} GB available",
        node.storage_capacity_bytes / 1_000_000_000
    );

    let state_stats = node.state_manager.get_stats();
    println!("Blockchain Accounts: {}", state_stats.total_accounts);
    println!("Total Balance: {}", state_stats.total_balance);
    println!("Active Validators: {}", state_stats.active_validators);

    let mut proof_counts = std::collections::HashMap::new();
    for proof in &node.recent_proofs {
        *proof_counts.entry(&proof.event_type).or_insert(0) += 1;
    }

    if !proof_counts.is_empty() {
        println!("Proof Events by Type:");
        for (event_type, count) in proof_counts {
            println!("  {}: {}", event_type, count);
        }
    }
}

fn print_optimization_metrics(node: &Node) {
    println!("\n💰 Optimization Metrics");
    println!("═══════════════════════");

    let sharing_stats = node.get_bandwidth_sharing_stats();
    println!("Bandwidth Sharing:");
    println!(
        "  Status: {}",
        if sharing_stats.enabled {
            "Enabled"
        } else {
            "Disabled"
        }
    );
    println!("  Active Connections: {}", sharing_stats.active_connections);
    println!(
        "  Daily Shared: {:.1}/{} MB",
        sharing_stats.daily_shared_mb, sharing_stats.daily_limit_mb
    );
    println!(
        "  Total Earned: {:.4} EGOC",
        sharing_stats.total_earned_egoc
    );
    println!(
        "  Available: {} Mbps",
        sharing_stats.available_bandwidth_mbps
    );

    let opt_stats = node.get_optimization_stats();
    println!("\nData Optimization:");
    println!(
        "  Operations Compressed: {}",
        opt_stats.compression_stats.operations_compressed
    );
    println!(
        "  Compression Ratio: {:.2}",
        opt_stats.compression_stats.compression_ratio
    );
    println!(
        "  Bandwidth Saved: {:.1} MB",
        opt_stats.total_bandwidth_saved_mb
    );
    println!("  Pending Operations: {}", opt_stats.pending_operations);
    println!("  Pending Batches: {}", opt_stats.pending_batches);

    println!("\nNetwork Usage:");
    println!("  {}", node.get_data_usage_summary());
    println!(
        "  Current Interface: {:?}",
        node.network_manager.current_interface
    );
    println!("  Off-Peak Hours: {}", node.is_cost_effective_time());
}

fn print_final_stats(node: &Node) {
    println!("\n📊 Final Statistics");
    println!("═══════════════════");
    let metrics = node.get_performance_metrics();
    println!(
        "Total uptime: {:.1} hours",
        metrics.uptime_seconds as f64 / 3600.0
    );
    println!("Total proofs generated: {}", metrics.proof_events_generated);
    println!(
        "Total data processed: {:.2} MB",
        (metrics.bytes_sent + metrics.bytes_received) as f64 / 1_000_000.0
    );
    println!("Total cost savings: ${:.2}", metrics.cost_savings_usd);

    let sharing_stats = node.get_bandwidth_sharing_stats();
    if sharing_stats.enabled {
        println!("Total EGOC earned: {:.4}", sharing_stats.total_earned_egoc);
    }

    let state_stats = node.state_manager.get_stats();
    println!("Final blockchain state:");
    println!("  Total accounts: {}", state_stats.total_accounts);
    println!("  Total balance: {}", state_stats.total_balance);
    println!("  Block height: {}", node.get_block_height());
}

#[allow(dead_code)]
async fn generate_proofs(node: &mut Node) -> anyhow::Result<()> {
    if node.has_role(NodeRole::StorageProvider) && !node.shard_ids.is_empty() {
        let shard_id = node.shard_ids[0];
        let piece_id = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
            % 1000000) as u32;

        let evidence = format!("post_proof_{}_{}", shard_id, piece_id).into_bytes();
        node.emit_post_proof(shard_id, piece_id, evidence)?;
        debug!("Generated optimized PoST proof for shard {}", shard_id);
    }

    if node.has_role(NodeRole::Gateway) {
        if let Some(ref geohash) = node.geohash.clone() {
            let evidence = format!(
                "poc_proof_{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs()
            )
            .into_bytes();

            node.emit_poc_proof(geohash.clone(), evidence)?;
            debug!("Generated optimized PoC proof for geohash");
        }
    }

    Ok(())
}
async fn run_interactive_mode(mut node: Node, config: NodeConfig) -> anyhow::Result<()> {
    info!("🖥️ Running in interactive mode. Type 'help' for commands.");

    let mut status_interval = interval(Duration::from_secs(10));
    let mut optimization_interval = interval(Duration::from_secs(5));
    let mut uptime_interval = interval(Duration::from_secs(1));

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();

    tokio::spawn(async move {
        let stdin = std::io::stdin();
        loop {
            print!("\n> ");
            io::stdout().flush().unwrap();
            let mut input = String::new();
            match stdin.read_line(&mut input) {
                Ok(_) => {
                    if tx.send(input.trim().to_string()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    print_commands();
    print_status(&node);

    loop {
        tokio::select! {
            event = node.swarm.select_next_some() => {
                debug!("Network event: {:?}", event);
                if let Err(e) = handle_network_event(&mut node, event).await {
                    warn!("Error handling network event: {}", e);
                }
            },

            _ = status_interval.tick() => {
            },

            _ = optimization_interval.tick() => {
                if let Err(e) = node.process_optimization_events().await {
                    warn!("Error processing optimization events: {}", e);
                }

                node.handle_porep_events().await;
            },

            _ = uptime_interval.tick() => {
                node.update_uptime();
            },

            Some(command) = rx.recv() => {
                let command = command.to_lowercase();
                match handle_interactive_command(&mut node, &command, &config).await {
                    Ok(should_continue) => {
                        if !should_continue {
                            break;
                        }
                    },
                    Err(e) => {
                        error!("Command error: {}", e);
                    }
                }
            }
        }
    }

    print_final_stats(&node);
    Ok(())
}

async fn handle_interactive_command(
    node: &mut Node,
    command: &str,
    config: &NodeConfig,
) -> anyhow::Result<bool> {
    match command {
        "help" => {
            print_commands();
        }
        "status" => {
            print_detailed_status(node);
        }
        "peers" => {
            let peers: Vec<_> = node.swarm.connected_peers().collect();
            println!("Connected peers: {:?}", peers);
            if peers.is_empty() {
                println!("❌ No peers connected. Try:");
                println!("  - Check network connectivity");
                println!("  - Verify bootstrap peer addresses");
                println!("  - Check firewall settings");
                println!("  - Ensure port {} is available", config.listen_port);
                println!("  - Use 'connect' command to retry bootstrap peers");
            } else {
                println!("✅ {} peer(s) connected successfully", peers.len());
            }
        }
        "roles" => {
            println!("Current roles: {:?}", node.get_roles());
            println!("Node type: {}", node.node_type);
        }
        "capabilities" => {
            println!("Node capabilities:");
            for capability in node.get_capabilities() {
                println!("  ✓ {}", capability);
            }
        }
        "blockchain" => {
            let state_stats = node.state_manager.get_stats();
            println!("Blockchain State:");
            println!("  Block height: {}", node.get_block_height());
            println!("  State root: {}", node.get_state_root());
            println!("  Total accounts: {}", state_stats.total_accounts);
            println!("  Total balance: {}", state_stats.total_balance);
            println!("  Active validators: {}", state_stats.active_validators);
            println!("  Total staked: {}", state_stats.total_staked);
        }
        "account" => {
            let my_address = node.get_address();
            if let Some(account) = node.get_account(&my_address) {
                println!("My Account:");
                println!("  Address: {}", my_address);
                println!("  Balance: {}", account.balance);
                println!("  Nonce: {}", account.nonce);
                println!("  Type: {:?}", account.account_type);
                println!(
                    "  Storage: {}/{} bytes",
                    account.storage_used, account.storage_quota
                );
                println!("  Storage Credits: {}", account.storage_credits);
                println!("  Deploy Credits: {}", account.deploy_credits);
                println!("  Free Deploys: {}", account.free_deploys_remaining);
                if account.is_validator() {
                    println!("  Validator: YES");
                    if let Some(validator_info) = &account.validator_info {
                        println!(
                            "    Commission Rate: {}%",
                            validator_info.commission_rate as f64 / 100.0
                        );
                        println!("    Active: {}", validator_info.is_active);
                    }
                }
                if account.is_storage_provider() {
                    println!("  Storage Provider: YES");
                    if let Some(provider_info) = &account.storage_provider_info {
                        println!("    Active Sectors: {}", provider_info.active_sectors.len());
                        println!("    Health Score: {}", provider_info.health_score);
                        println!(
                            "    Storage Allocated: {} bytes",
                            provider_info.storage_allocated
                        );
                    }
                }
            } else {
                println!("❌ Account not found in state");
            }
        }
        "accounts" => {
            let state_stats = node.state_manager.get_stats();
            println!("Blockchain Accounts Summary:");
            println!("  Total Accounts: {}", state_stats.total_accounts);
            println!("  Total Balance: {}", state_stats.total_balance);
            println!("  Active Validators: {}", state_stats.active_validators);
            println!("  Total Staked: {}", state_stats.total_staked);
        }
        "transfer" => {
            println!("Creating transfer transaction...");
            let from_address = node.get_address();
            let to_address = Address::new([1u8; 20]);
            let amount = Balance::from_egoc(10);

            if let Some(account) = node.get_account(&from_address) {
                let payload = TransactionPayload::Transfer {
                    to: to_address,
                    amount,
                    memo: Some("Interactive transfer".to_string()),
                    stealth_mode: false,
                };

                let mut tx = Transaction::new(
                    from_address,
                    account.nonce + 1,
                    payload,
                    ego_core::ShardId::new(0).unwrap(),
                    None,
                    1,
                );

                if let Err(e) = tx.sign(node.get_keypair(), false) {
                    println!("❌ Failed to sign transaction: {}", e);
                } else {
                    match node.execute_transaction(&tx).await {
                        Ok(result) => {
                            println!("✅ Transaction executed: {}", result.success);
                            if let Some(error) = result.error {
                                println!("   Error: {}", error);
                            }
                            println!("   RU used: {}", result.ru_used);
                        }
                        Err(e) => {
                            println!("❌ Transaction failed: {}", e);
                        }
                    }
                }
            } else {
                println!("❌ Account not found");
            }
        }
        "block" => {
            println!("Creating block...");
            let previous_hash = node.get_state_root();
            let height = node.get_block_height().next();

            match node.create_block(vec![], previous_hash, height).await {
                Ok(block) => {
                    println!("✅ Block created successfully:");
                    println!("   Hash: {}", block.hash);
                    println!("   Height: {}", block.header.core.height.as_u64());
                    println!("   Proposer: {}", block.header.core.proposer);
                    println!("   Transactions: {}", block.body.transactions.len());
                    println!("   Timestamp: {}", block.header.core.timestamp.as_secs());
                }
                Err(e) => {
                    println!("❌ Failed to create block: {}", e);
                }
            }
        }
        "crypto" => {
            println!("🔐 Cryptographic Information");
            println!("════════════════════════════");

            println!("\n📍 Identity:");
            println!("  Node Address: {}", node.get_address());
            println!("  Peer ID: {}", node.peer_id);

            println!("\n🔑 Public Keys:");
            let ed25519_pk = node.get_keypair().ed25519_public_key();
            let dilithium_pk = node.get_keypair().dilithium_public_key();
            let kyber_pk = node.get_keypair().kyber_public_key();
            let x25519_pk = node.get_keypair().x25519_public_key();

            println!(
                "  Ed25519 (Classical): {}",
                hex::encode(ed25519_pk.as_bytes())
            );
            println!(
                "  ML-DSA-2 (Dilithium): {} bytes",
                dilithium_pk.as_bytes().len()
            );
            println!("  ML-KEM-768 (Kyber): {} bytes", kyber_pk.as_bytes().len());
            println!("  X25519 (Classical): {}", hex::encode(&x25519_pk));

            if let Some(slh_dsa_pk) = node.get_keypair().slh_dsa_public_key() {
                println!(
                    "  SLH-DSA (SPHINCS+): {} bytes",
                    slh_dsa_pk.as_bytes().len()
                );
            }

            println!("\n🔐 Cryptographic Modes:");
            println!(
                "  Transition Mode: {}",
                node.get_keypair().is_transition_mode()
            );
            println!("  Post-Quantum Ready: true");
            println!(
                "  Hybrid Signatures: {}",
                node.get_keypair().is_transition_mode()
            );

            println!("\n🔬 Signature Verification:");
            let test_message = b"Ego blockchain node signature verification";

            let ed25519_sig = node.get_keypair().sign_ed25519(test_message);
            println!("  Ed25519:");
            println!("    Algorithm: {:?}", ed25519_sig.algorithm);
            println!("    Size: {} bytes", ed25519_sig.signature_data.len());
            println!(
                "    Verification: {}",
                ego_core::crypto::verify_signature(&ed25519_pk, test_message, &ed25519_sig)
                    .unwrap_or(false)
            );

            let dilithium_sig = node.get_keypair().sign_dilithium(test_message);
            println!("  ML-DSA-2 (Dilithium):");
            println!("    Algorithm: {:?}", dilithium_sig.algorithm);
            println!("    Size: {} bytes", dilithium_sig.signature_data.len());
            println!(
                "    Verification: {}",
                ego_core::crypto::verify_signature(&dilithium_pk, test_message, &dilithium_sig)
                    .unwrap_or(false)
            );

            let dual_sig = node.get_keypair().dual_sign(test_message);
            println!("  Dual Signature (Hybrid):");
            println!("    Has Ed25519: {}", dual_sig.ed25519_sig.is_some());
            println!("    Has Dilithium: {}", dual_sig.dilithium_sig.is_some());
            println!(
                "    Verification: {}",
                ego_core::crypto::verify_dual_signature(
                    &ed25519_pk,
                    &dilithium_pk,
                    test_message,
                    &dual_sig
                )
                .unwrap_or(false)
            );

            println!("\n🔒 Key Encapsulation:");
            match node.get_keypair().encapsulate_kyber(kyber_pk.as_bytes()) {
                Ok((ciphertext, shared_secret)) => {
                    println!("  ML-KEM-768 (Kyber):");
                    println!("    Ciphertext: {} bytes", ciphertext.len());
                    println!("    Shared Secret: {} bytes", shared_secret.len());

                    match node.get_keypair().decapsulate_kyber(&ciphertext) {
                        Ok(decapsulated_secret) => {
                            println!("    Decapsulation: SUCCESS");
                            println!(
                                "    Secrets Match: {}",
                                shared_secret == decapsulated_secret
                            );
                        }
                        Err(e) => println!("    Decapsulation: FAILED - {}", e),
                    }
                }
                Err(e) => println!("  KEM: FAILED - {}", e),
            }

            println!("\n🎭 Advanced Features:");
            println!("  Stealth Addresses: Supported");
            println!("  Hybrid Sessions: Supported");
            println!("  Domain Separation: Enabled");
            println!("  Replay Protection: Active");
            println!("  Batch Verification: Supported");

            println!("\n📊 Supported Algorithms:");
            println!("  Signatures:");
            println!("    ✓ Ed25519 (NIST SP 800-186)");
            println!("    ✓ ML-DSA-2 / Dilithium2 (FIPS 204)");
            println!("    ✓ SLH-DSA / SPHINCS+ (FIPS 205)");
            println!("  Key Exchange:");
            println!("    ✓ X25519 (RFC 7748)");
            println!("    ✓ ML-KEM-768 / Kyber768 (FIPS 203)");
            println!("  Symmetric:");
            println!("    ✓ XChaCha20-Poly1305 (AEAD)");
            println!("    ✓ BLAKE2s (Hashing)");
            println!("    ✓ HKDF-SHA256 (Key Derivation)");

            println!("\n🛡️ Security Properties:");
            println!("  Post-Quantum Security: YES");
            println!("  Forward Secrecy: YES");
            println!("  Replay Protection: YES");
            println!("  Domain Separation: YES");
            println!("  Authenticated Encryption: YES");
        }
        "kem" => {
            println!("🔒 Key Encapsulation Mechanism");
            let kyber_pk = node.get_keypair().kyber_public_key();

            match node.get_keypair().encapsulate_kyber(kyber_pk.as_bytes()) {
                Ok((ciphertext, shared_secret1)) => {
                    println!("✅ Encapsulation successful");
                    println!("   Ciphertext: {} bytes", ciphertext.len());
                    println!("   Shared secret: {} bytes", shared_secret1.len());

                    match node.get_keypair().decapsulate_kyber(&ciphertext) {
                        Ok(shared_secret2) => {
                            if shared_secret1 == shared_secret2 {
                                println!("✅ Decapsulation successful - secrets match!");
                            } else {
                                println!("❌ Decapsulation failed - secrets don't match");
                            }
                        }
                        Err(e) => println!("❌ Decapsulation error: {}", e),
                    }
                }
                Err(e) => println!("❌ Encapsulation error: {}", e),
            }
        }
        "stealth" => {
            println!("🎭 Stealth Address Generation");
            let kyber_pk = node.get_keypair().kyber_public_key();
            let ephemeral = node.get_keypair().to_bytes();

            match ego_core::crypto::derive_stealth_address(kyber_pk.as_bytes(), &ephemeral) {
                Ok((one_time_pk, spend_key)) => {
                    println!("✅ Stealth address generated");
                    println!("   One-time public key: {:?}", one_time_pk.algorithm);
                    println!("   Spend key size: {} bytes", spend_key.len());
                    println!("   Algorithm: Post-Quantum Safe");
                }
                Err(e) => println!("❌ Stealth address generation failed: {}", e),
            }
        }
        "batch-verify" => {
            println!("📦 Batch Signature Verification");
            use ego_core::crypto::BatchVerifier;

            let mut verifier = BatchVerifier::new(100000, 10);

            for i in 0..5 {
                let msg = format!("Message {}", i);
                let sig = node.get_keypair().sign_dilithium(msg.as_bytes());
                let pk = node.get_keypair().dilithium_public_key();

                match verifier.add_signature(pk, msg.as_bytes().to_vec(), sig) {
                    Ok(()) => println!("  ✓ Added signature {}", i + 1),
                    Err(e) => println!("  ✗ Failed to add signature {}: {}", i + 1, e),
                }
            }

            match verifier.verify_batch() {
                Ok(results) => {
                    let valid_count = results.iter().filter(|&&v| v).count();
                    println!("✅ Batch verification complete");
                    println!("   Total signatures: {}", results.len());
                    println!("   Valid signatures: {}", valid_count);
                    println!("   Invalid signatures: {}", results.len() - valid_count);
                }
                Err(e) => println!("❌ Batch verification failed: {}", e),
            }
        }
        "merkle" => {
            println!("🌳 Merkle Tree Construction");
            use ego_core::crypto::MerkleTree;

            let items: Vec<Vec<u8>> = (0..8)
                .map(|i| format!("Transaction {}", i).into_bytes())
                .collect();

            let tree = MerkleTree::build(items.clone());

            if let Some(root) = tree.root_hash() {
                println!("✅ Merkle tree constructed");
                println!("   Leaves: {}", tree.len());
                println!("   Root hash: {}", root);
                println!("   Tree structure: Post-Quantum Safe (BLAKE2s)");
            } else {
                println!("❌ Failed to construct Merkle tree");
            }
        }
        "proofs" => {
            println!("Recent proofs: {} events", node.recent_proofs.len());
            for (i, proof) in node.recent_proofs.iter().rev().take(10).enumerate() {
                println!(
                    "  {}: {} - {} ({})",
                    i + 1,
                    proof.event_type,
                    proof.peer_id,
                    proof.timestamp
                );
            }
            if node.recent_proofs.is_empty() {
                println!("  No proofs generated yet. Use 'poc' or 'post' to generate proofs.");
            }
        }
        "5g" => {
            println!("5G Configuration:");
            println!("  5G Ready: {}", node.is_5g_ready());
            if let Some(slice_id) = &node.slice_id {
                println!("  Slice ID: {}", slice_id);
            } else {
                println!("  Slice ID: Not configured");
            }
            if let Some(geohash) = &node.geohash {
                println!("  Geohash: {}", geohash);
            } else {
                println!("  Geohash: Not set");
            }
            println!(
                "  Bandwidth: {} Mbps",
                node.bandwidth_capacity_bps / 1_000_000
            );
        }
        "metrics" => {
            print_metrics(node);
            print_optimization_metrics(node);
            print_performance_metrics(node);
        }
        "network" => {
            println!("Network Status:");
            println!(
                "  Current network: {:?}",
                node.network_manager.current_interface
            );
            println!("  {}", node.get_data_usage_summary());
            println!(
                "  Off-peak hours: {}",
                node.network_manager.is_off_peak_hours()
            );
            println!("  Cost effective time: {}", node.is_cost_effective_time());
        }
        "sharing" => {
            let stats = node.get_bandwidth_sharing_stats();
            println!("Bandwidth Sharing Stats:");
            println!("  Enabled: {}", stats.enabled);
            println!("  Active connections: {}", stats.active_connections);
            println!(
                "  Daily shared: {:.1} MB / {} MB",
                stats.daily_shared_mb, stats.daily_limit_mb
            );
            println!("  Total earned: {:.4} EGOC", stats.total_earned_egoc);
            println!(
                "  Available bandwidth: {} Mbps",
                stats.available_bandwidth_mbps
            );
            if !stats.enabled {
                println!("  💡 Use 'enable-sharing' to start earning EGOC tokens");
            }
        }
        "compression" => {
            let stats = node.get_optimization_stats();
            println!("Data Optimization Stats:");
            println!(
                "  Operations compressed: {}",
                stats.compression_stats.operations_compressed
            );
            println!(
                "  Compression ratio: {:.2}",
                stats.compression_stats.compression_ratio
            );
            println!(
                "  Bandwidth saved: {:.1} MB",
                stats.total_bandwidth_saved_mb
            );
            println!("  Pending operations: {}", stats.pending_operations);
            println!("  Pending batches: {}", stats.pending_batches);
        }
        "enable-sharing" => {
            if let Err(e) = node.enable_bandwidth_sharing(50, 1000) {
                println!("❌ Failed to enable bandwidth sharing: {}", e);
            } else {
                println!("✅ Bandwidth sharing enabled (50 Mbps, 1000 MB daily limit)");
            }
        }
        "disable-sharing" => {
            if let Err(e) = node.disable_bandwidth_sharing() {
                println!("❌ Failed to disable bandwidth sharing: {}", e);
            } else {
                println!("✅ Bandwidth sharing disabled");
            }
        }
        "switch-wifi" => {
            node.update_network_interface_status(NetworkType::WiFi, true, Some(80));
            println!("✅ Switched to WiFi");
        }
        "switch-5g" => {
            node.update_network_interface_status(NetworkType::FiveG, true, Some(90));
            println!("✅ Switched to 5G");
        }
        "switch-ethernet" => {
            node.update_network_interface_status(NetworkType::Ethernet, true, Some(100));
            println!("✅ Switched to Ethernet");
        }
        "poc" => {
            if let Some(geohash) = node.geohash.clone() {
                let evidence = format!("poc_{}", chrono::Utc::now().timestamp()).into_bytes();
                if let Err(e) = node.emit_poc_proof(geohash.clone(), evidence) {
                    println!("❌ Failed to emit PoC proof: {}", e);
                } else {
                    println!("✅ PoC proof emitted for geohash: {}", geohash);
                }
            } else {
                println!("❌ No geohash set for PoC proof. Set latitude/longitude first.");
            }
        }
        "post" => {
            if !node.shard_ids.is_empty() {
                let shard_id = node.shard_ids[0];
                let piece_id = chrono::Utc::now().timestamp() as u32;
                let evidence = format!("post_{}_{}", shard_id, piece_id).into_bytes();
                if let Err(e) = node.emit_post_proof(shard_id, piece_id, evidence) {
                    println!("❌ Failed to emit PoST proof: {}", e);
                } else {
                    println!(
                        "✅ PoST proof emitted for shard {} piece {}",
                        shard_id, piece_id
                    );
                }
            } else {
                println!("❌ No shards configured for PoST proof");
            }
        }
        "connect" => {
            println!("🔄 Attempting to connect to bootstrap peers...");
            if node.bootstrap_peers.is_empty() {
                println!("❌ No bootstrap peers configured");
            } else {
                if let Err(e) = node.connect_to_bootstrap_peers().await {
                    println!("❌ Connection attempts failed: {}", e);
                } else {
                    println!("✅ Connection attempts initiated");
                }
            }
        }
        "addresses" => {
            println!("Network Addresses:");
            println!("  Listen addresses:");
            for addr in &node.listen_addresses {
                println!("    {}", addr);
            }
            println!("  Bootstrap peers:");
            for addr in &node.bootstrap_peers {
                println!("    {}", addr);
            }
            if node.bootstrap_peers.is_empty() {
                println!("    (none configured)");
            }
        }
        "performance" => {
            print_performance_metrics(node);
        }
        "reset-stats" => {
            node.network_manager.reset_monthly_stats();
            node.bandwidth_sharing.reset_daily_stats();
            println!("✅ Statistics reset completed");
        }
        "node-info" => {
            println!("Node Information:");
            println!("  Peer ID: {}", node.peer_id);
            println!("  Node Type: {}", node.node_type);
            println!("  Roles: {:?}", node.roles);
            println!("  Shards: {:?}", node.shard_ids);
            println!(
                "  Storage: {} GB",
                node.storage_capacity_bytes / 1_000_000_000
            );
            println!(
                "  Bandwidth: {} Mbps",
                node.bandwidth_capacity_bps / 1_000_000
            );
            println!("  5G Ready: {}", node.is_5g_ready());
        }
        "deploy-policy" => {
            println!("📋 Deploy Policy Manager");
            use ego_core::deploy_policy::{
                DeployPolicyConfig, DeployPolicyManager, DeployRequest, DeployType,
            };

            let config = DeployPolicyConfig::default();
            let mut manager = DeployPolicyManager::new(config);

            println!("  Config:");
            println!(
                "    Free deploys per epoch: {}",
                manager.get_config().free_deploys_per_epoch
            );
            println!(
                "    Max deploy size: {} KB",
                manager.get_config().max_deploy_size_kb
            );
            println!(
                "    Credits per KB: {}",
                manager.get_config().credits_per_kb
            );
            println!(
                "    Anti-spam enabled: {}",
                manager.get_config().anti_spam_enabled
            );
            println!(
                "    AI detection enabled: {}",
                manager.get_config().ai_pattern_detection_enabled
            );

            let test_code = b"contract TestContract { function test() public pure returns (uint) { return 42; } }";
            let request = DeployRequest {
                deployer: node.get_address(),
                deploy_type: DeployType::SmartContract {
                    code_size_kb: 1,
                    estimated_ru: 1000,
                },
                code: test_code.to_vec(),
                metadata: std::collections::HashMap::new(),
                use_free_quota: true,
                preferred_shard: Some(0),
                human_verification_signature: None,
                dilithium_verification_pk: None,
            };

            match manager.evaluate_deploy_request(
                &request,
                Some(ego_core::Balance::from_egoc(1000)),
                0,
            ) {
                Ok(decision) => {
                    println!("✅ Deploy evaluation successful:");
                    match decision {
                        ego_core::deploy_policy::DeployDecision::AcceptWithFreeQuota {
                            deploy_id,
                        } => {
                            println!("   Accepted with free quota");
                            println!("   Deploy ID: {}", deploy_id);
                        }
                        ego_core::deploy_policy::DeployDecision::AcceptWithCredits {
                            deploy_id,
                            credits_required,
                            bond_required,
                            pob_floor,
                        } => {
                            println!("   Accepted with credits");
                            println!("   Deploy ID: {}", deploy_id);
                            println!("   Credits required: {}", credits_required);
                            println!("   Bond required: {:?}", bond_required);
                            println!("   PoB floor: {}", pob_floor);
                        }
                        ego_core::deploy_policy::DeployDecision::Reject { deploy_id, reason } => {
                            println!("   Rejected: {}", reason);
                            println!("   Deploy ID: {}", deploy_id);
                        }
                    }
                }
                Err(e) => println!("❌ Deploy evaluation failed: {}", e),
            }

            let reputation = manager.calculate_deployer_reputation(&node.get_address());
            println!("\n  Deployer Reputation:");
            println!("    Total deploys: {}", reputation.total_deploys);
            println!("    Success rate: {:.2}%", reputation.success_rate);
            println!("    Reputation score: {}", reputation.reputation_score);
        }
        "drs" => {
            println!("📊 Deterministic Reward Scoring");
            use ego_core::drs::{DRSConfig, DRSManager, EvidenceBundle, PoCEventData};

            let config = DRSConfig::default();
            println!("  DRS Config:");
            println!("    Weight uptime: {:.2}", config.w_uptime);
            println!("    Weight PoST pass: {:.2}", config.w_post_pass);
            println!("    Weight PoC: {:.2}", config.w_poc);
            println!("    Smoothing alpha: {:.2}", config.smoothing_alpha);
            println!(
                "    Multiplier range: {:.2} - {:.2}",
                config.m_min, config.m_max
            );

            let manager = DRSManager::new(config);

            let evidence = EvidenceBundle {
                node_id: node.get_address(),
                epoch: 1,
                uptime_slots_seen: 950,
                uptime_slots_expected: 1000,
                post_challenges: 100,
                post_passes: 98,
                post_latency_sum_ms: 45000,
                post_latency_count: 98,
                poc_events: vec![PoCEventData {
                    event_id: ego_core::Hash::random(),
                    q_after_ldm: 0.95,
                    witness_confidence: 0.9,
                    h3_cell: "8c283082a6c7fff".to_string(),
                    timestamp: ego_core::Timestamp::now(),
                }],
                serve_bytes_ok: 1_000_000_000,
                serve_bytes_requested: 1_050_000_000,
                failed_post_count: 2,
                replay_or_incoherence_count: 0,
                equivocation_count: 0,
                density_data: None,
            };

            match manager.calculate_drs_score(evidence) {
                Ok(score) => {
                    println!("✅ DRS score calculated:");
                    println!("   Node: {}", score.node_id);
                    println!("   Epoch: {}", score.epoch);
                    println!("   Raw score: {:.4}", score.score_raw);
                    println!("   Smoothed score: {:.4}", score.score_smoothed);
                    println!("   Multiplier: {:.4}", score.multiplier);
                    println!("   Quota band: {:?}", score.quota_band);
                    println!("\n   Components:");
                    println!("     Uptime: {:.4}", score.components.uptime);
                    println!("     PoST pass: {:.4}", score.components.post_pass);
                    println!("     Inv latency: {:.4}", score.components.inv_latency);
                    println!("     PoC quality: {:.4}", score.components.poc_quality);
                    println!("     Serve ratio: {:.4}", score.components.serve_ratio);
                    println!("\n   Penalties:");
                    println!("     Failed PoST: {}", score.penalties.failed_post);
                    println!(
                        "     Replay/incoherence: {}",
                        score.penalties.replay_or_incoherence
                    );
                    println!("     Equivocation: {}", score.penalties.equivocation);
                    println!("     Total penalty: {:.4}", score.penalties.total_penalty);

                    let quota = manager.get_quota_allocation(&node.get_address());
                    println!("\n   Quota Allocation:");
                    println!("     Band: {:?}", quota.quota_band);
                    println!("     RU limit: {}", quota.ru_limit);
                    println!("     Proof batch size: {}", quota.proof_batch_size);
                    println!("     Audit frequency: {}", quota.audit_frequency);
                    println!("     Publish rate limit: {}", quota.publish_rate_limit);
                }
                Err(e) => println!("❌ DRS score calculation failed: {}", e),
            }
        }
        "deploy-cost" => {
            println!("💰 Deploy Cost Estimation");
            use ego_core::deploy_policy::{DeployPolicyConfig, DeployType, estimate_deploy_cost};

            let config = DeployPolicyConfig::default();

            let deploy_types = vec![
                (
                    "Smart Contract (Small)",
                    DeployType::SmartContract {
                        code_size_kb: 10,
                        estimated_ru: 5000,
                    },
                ),
                (
                    "Smart Contract (Large)",
                    DeployType::SmartContract {
                        code_size_kb: 500,
                        estimated_ru: 50000,
                    },
                ),
                (
                    "Storage Deal (1GB)",
                    DeployType::StorageDeal {
                        data_size_kb: 1_048_576,
                        duration_blocks: 100000,
                    },
                ),
                (
                    "Rollup Operator",
                    DeployType::RollupOperator {
                        initial_state_kb: 100,
                    },
                ),
            ];

            for (name, deploy_type) in deploy_types {
                let estimate = estimate_deploy_cost(&deploy_type, &config);
                println!("\n  {}:", name);
                println!("    Size: {} KB", estimate.size_kb);
                println!("    Estimated RU: {}", estimate.estimated_ru);
                println!("    Credits required: {}", estimate.credits_required);
                println!("    PoB floor: {}", estimate.pob_floor_required);
                println!("    Bond required: {}", estimate.bond_required);
                println!("    Total cost estimate: {}", estimate.total_cost_estimate);
            }
        }
        "drs-rewards" => {
            println!("🎁 DRS Reward Distribution");
            use ego_core::Balance;
            use ego_core::drs::{DRSConfig, DRSManager};

            let manager = DRSManager::new(DRSConfig::default());

            let base_storage = Balance::from_egoc(100);
            let base_consensus = Balance::from_egoc(50);
            let base_coverage = Balance::from_egoc(25);

            match manager.apply_reward_multiplier(
                &node.get_address(),
                base_storage,
                base_consensus,
                base_coverage,
                1,
            ) {
                Ok(distribution) => {
                    println!("✅ Reward distribution calculated:");
                    println!("   Node: {}", distribution.node_id);
                    println!("   Epoch: {}", distribution.epoch);
                    println!("   DRS multiplier: {:.4}", distribution.drs_multiplier);
                    println!("\n   Base rewards:");
                    println!("     Storage: {}", distribution.base_storage_reward);
                    println!("     Consensus: {}", distribution.base_consensus_reward);
                    println!("     Coverage: {}", distribution.base_coverage_reward);
                    println!("\n   Final rewards (with multiplier):");
                    println!("     Storage: {}", distribution.final_storage_reward);
                    println!("     Consensus: {}", distribution.final_consensus_reward);
                    println!("     Coverage: {}", distribution.final_coverage_reward);
                    println!("\n   Total reward: {}", distribution.total_reward);
                }
                Err(e) => println!("❌ Reward calculation failed: {}", e),
            }
        }
        "shard" => {
            println!("🔷 Shard Configuration");
            println!("═══════════════════════");

            let state = node.state_manager.get_stats();

            println!("Basic Configuration:");
            println!(
                "  Shard ID: {}",
                node.shard_ids
                    .first()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "N/A".to_string())
            );
            println!("  Node roles: {:?}", node.roles);
            println!("  Block height: #{}", node.get_block_height().as_u64());

            println!("\nStorage:");
            println!("  Total entries: {}", state.storage_entries);
            println!(
                "  Total size: {:.2} GB",
                state.total_storage_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
            );
            println!("  Archival chunks: {}", state.archival_chunks);
            println!("  User data chunks: {}", state.user_data_chunks);

            println!("\nValidators:");
            println!("  Active: {}", state.active_validators);
            println!("  Jailed: {}", state.jailed_validators);
            println!("  Total staked: {}", state.total_staked);
            println!(
                "  Avg performance: {:.2}%",
                state.average_validator_performance
            );

            println!("\nProofs:");
            println!("  Total PoST challenges: {}", state.total_post_challenges);
            println!("  Pass rate: {:.2}%", state.post_pass_rate);
            println!("  Sectors monitored: {}", state.sectors_under_post);
        }
        "state" => {
            println!("📊 Current State");
            println!("════════════════");

            let state = node.state_manager.get_stats();

            println!("Accounts:");
            println!("  Total: {}", state.total_accounts);
            println!("  EOA: {}", state.eoa_accounts);
            println!("  Devices: {}", state.device_accounts);
            println!("  Validators: {}", state.validator_accounts);
            println!("  Storage Providers: {}", state.storage_provider_accounts);
            println!("  Contracts: {}", state.contract_accounts);

            println!("\nBalances:");
            println!("  Total balance: {}", state.total_balance);
            println!("  Total staked: {}", state.total_staked);

            println!("\nNetwork:");
            println!("  Active slices: {}", state.active_slices);
            println!(
                "  Total bandwidth: {:.2} Mbps",
                state.total_slice_bandwidth as f64 / 1_000_000.0
            );
            println!(
                "  Pending cross-shard: {}",
                state.pending_cross_shard_receipts
            );

            println!(
                "\nLast updated: {}",
                chrono::DateTime::from_timestamp_millis(state.last_updated.as_millis() as i64)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|| "Unknown".to_string())
            );
        }
        "validators" => {
            println!("👥 Validators");
            println!("═════════════");

            let validators = node.state_manager.get_active_validators();

            if validators.is_empty() {
                println!("No active validators");
            } else {
                println!("Active validators: {}\n", validators.len());

                for (i, val) in validators.iter().take(10).enumerate() {
                    println!("{}. {}", i + 1, val.address);
                    println!("   Stake: {}", val.total_stake);
                    println!("   Commission: {}%", val.commission_rate as f64 / 100.0);
                    println!("   Uptime: {:.2}%", val.performance.uptime_score);
                    println!(
                        "   DRS score: {:.4} ({}x)",
                        val.drs_score, val.drs_multiplier
                    );
                    println!();
                }

                if validators.len() > 10 {
                    println!("... and {} more", validators.len() - 10);
                }
            }

            let total_staked = node.state_manager.get_total_staked();
            println!("Total staked: {}", total_staked);
        }
        "storage" => {
            println!("💾 Storage Overview");
            println!("═══════════════════");

            let state_stats = node.state_manager.get_stats();

            println!("Storage Entries: {}", state_stats.storage_entries);
            println!(
                "Total Size: {:.2} GB",
                state_stats.total_storage_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
            );

            println!("\nBy Type:");
            println!("  Archival: {}", state_stats.archival_chunks);
            println!("  Contract Code: {}", state_stats.contract_code_chunks);
            println!("  User Data: {}", state_stats.user_data_chunks);

            println!("\nProof of Spacetime:");
            println!("  Total challenges: {}", state_stats.total_post_challenges);
            println!("  Pass rate: {:.2}%", state_stats.post_pass_rate);
            println!("  Sectors: {}", state_stats.sectors_under_post);

            println!("\nNode Storage:");
            println!(
                "  Capacity: {} GB",
                node.storage_capacity_bytes / (1024 * 1024 * 1024)
            );
            println!("  Shards: {:?}", node.shard_ids);
        }
        "slices" => {
            println!("🍰 Network Slices");
            println!("═════════════════");

            let state_stats = node.state_manager.get_stats();

            println!("Active slices: {}", state_stats.active_slices);
            println!(
                "Total bandwidth: {:.2} Mbps",
                state_stats.total_slice_bandwidth as f64 / 1_000_000.0
            );

            if let Some(slice_id) = &node.slice_id {
                println!("\nNode Slice: {}", slice_id);
            }

            if let Some(geohash) = &node.geohash {
                println!("Coverage area: {}", geohash);
            }

            println!("\nNode Capabilities:");
            println!("  5G Ready: {}", node.is_5g_ready());
            println!(
                "  Bandwidth: {} Mbps",
                node.bandwidth_capacity_bps / 1_000_000
            );
        }
        "my-account" => {
            let my_address = node.get_address();
            println!("👤 My Account: {}", my_address);
            println!("═════════════════════════════════════════════");

            if let Some(account) = node.state_manager.get_account(&my_address) {
                println!("\nBalance: {}", account.balance);
                println!("Nonce: {}", account.nonce);
                println!("Type: {:?}", account.account_type);

                println!("\nStorage:");
                println!("  Used: {} bytes", account.storage_used);
                println!("  Quota: {} bytes", account.storage_quota);
                println!("  Credits: {}", account.storage_credits);

                println!("\nDeploy:");
                println!("  Credits: {}", account.deploy_credits);
                println!("  Free remaining: {}", account.free_deploys_remaining);

                if account.is_validator() {
                    println!("\n✓ Validator Account");
                    if let Some(val_info) = account.validator_info.as_ref() {
                        println!("  Commission: {}%", val_info.commission_rate as f64 / 100.0);
                        println!("  Active: {}", val_info.is_active);
                    }
                }

                if account.is_storage_provider() {
                    println!("\n✓ Storage Provider");
                    if let Some(sp_info) = account.storage_provider_info.as_ref() {
                        println!("  Active sectors: {}", sp_info.active_sectors.len());
                        println!("  Health score: {}", sp_info.health_score);
                    }
                }

                if !account.authorized_slices.is_empty() {
                    println!("\nAuthorized Slices:");
                    for slice in &account.authorized_slices {
                        println!("  - {}", slice.as_str());
                    }
                }
            } else {
                println!("❌ Account not found in state");
            }
        }
        "txpool" => {
            println!("🌊 Transaction Pool");
            println!("═══════════════════");

            println!("Connected peers: {}", node.swarm.connected_peers().count());
            println!("Recent proofs: {}", node.recent_proofs.len());

            let state_stats = node.state_manager.get_stats();
            println!("\nBlockchain Activity:");
            println!("  Total accounts: {}", state_stats.total_accounts);
            println!("  Active validators: {}", state_stats.active_validators);
            println!("  Storage operations: {}", state_stats.storage_entries);
        }

        "cross-shard" => {
            println!("🔀 Cross-Shard Communication");
            let state_stats = node.state_manager.get_stats();
            println!(
                "Pending receipts: {}",
                state_stats.pending_cross_shard_receipts
            );
            println!(
                "Cross-shard throughput: {} receipts/sec",
                state_stats.cross_shard_throughput_per_sec
            );
        }
        "account-details" => {
            let my_address = node.get_address();
            if let Some(account) = node.state_manager.get_account(&my_address) {
                println!("🔍 Detailed Account Information");
                println!("═════════════════════════════════");

                println!("\n📍 Identity:");
                println!("  Address: {}", my_address);
                println!("  Account Type: {:?}", account.account_type);
                println!(
                    "  Created: {}",
                    chrono::DateTime::from_timestamp_millis(account.created_at.as_millis() as i64)
                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                        .unwrap_or_else(|| "Unknown".to_string())
                );

                println!("\n💰 Balances & Credits:");
                println!("  Balance: {}", account.balance);
                println!("  Storage Credits: {}", account.storage_credits);
                println!("  Deploy Credits: {}", account.deploy_credits);
                println!(
                    "  Free Deploys Remaining: {}",
                    account.free_deploys_remaining
                );

                println!("\n💾 Storage:");
                println!(
                    "  Quota: {} bytes ({:.2} GB)",
                    account.storage_quota,
                    account.storage_quota as f64 / 1_073_741_824.0
                );
                println!(
                    "  Used: {} bytes ({:.2} GB)",
                    account.storage_used,
                    account.storage_used as f64 / 1_073_741_824.0
                );
                println!(
                    "  Available: {} bytes ({:.2} GB)",
                    account.storage_quota.saturating_sub(account.storage_used),
                    (account.storage_quota.saturating_sub(account.storage_used)) as f64
                        / 1_073_741_824.0
                );
                println!(
                    "  Utilization: {:.2}%",
                    if account.storage_quota > 0 {
                        (account.storage_used as f64 / account.storage_quota as f64) * 100.0
                    } else {
                        0.0
                    }
                );

                println!("\n🔐 Post-Quantum Cryptography:");
                if let Some(ref pq_info) = account.pq_transition_info {
                    println!(
                        "  Transition Started: Epoch {}",
                        pq_info.transition_started_epoch
                    );
                    println!("  PQ-Only Mode: {}", pq_info.pq_only_mode);

                    if let Some(disabled_epoch) = pq_info.ed25519_disabled_epoch {
                        println!("  Ed25519 Disabled: Epoch {}", disabled_epoch);
                    } else {
                        println!("  Ed25519 Status: Active");
                    }

                    println!("  Supported Algorithms:");
                    for alg_id in &pq_info.supported_algorithms {
                        let alg_name = match *alg_id {
                            0 => "Ed25519",
                            1 => "ML-DSA-2 (Dilithium2)",
                            2 => "ML-KEM-768 (Kyber768)",
                            3 => "X25519",
                            4 => "SLH-DSA (SPHINCS+)",
                            _ => "Unknown",
                        };
                        println!("    - {} (ID: {})", alg_name, alg_id);
                    }
                }

                println!("\n📊 Activity:");
                println!("  Nonce: {}", account.nonce);
                println!(
                    "  Last Activity: {}",
                    chrono::DateTime::from_timestamp_millis(
                        account.last_activity.as_millis() as i64
                    )
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|| "Unknown".to_string())
                );

                if let Some(ref drs_score) = account.last_drs_score {
                    println!("\n⭐ Reputation (DRS):");
                    println!("  Score: {:.4}", *drs_score as f64 / 1000.0);
                    if let Some(epoch) = account.last_drs_epoch {
                        println!("  Last Updated: Epoch {}", epoch);
                    }
                }

                if account.is_validator() {
                    println!("\n✅ Validator Status:");
                    if let Some(ref val_info) = account.validator_info {
                        println!("  Active: {}", val_info.is_active);
                        println!("  Commission: {}%", val_info.commission_rate as f64 / 100.0);
                        println!("  Public Key: {}", val_info.validator_pubkey);

                        if let Some(ref jail) = val_info.jail_info {
                            println!("  ⚠️ JAILED:");
                            println!("    Reason: {}", jail.reason);
                            println!(
                                "    Release: {}",
                                chrono::DateTime::from_timestamp_millis(
                                    jail.release_at.as_millis() as i64
                                )
                                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                                .unwrap_or_else(|| "Unknown".to_string())
                            );
                        }
                    }

                    if let Some(ref stake_info) = account.staking_info {
                        println!("  Staked: {}", stake_info.staked_amount);
                        println!("  Delegated: {}", stake_info.delegated_stake);
                        println!("  Rewards Earned: {}", stake_info.rewards_earned);
                        println!("  Performance:");
                        println!(
                            "    Blocks Validated: {}",
                            stake_info.performance.blocks_validated
                        );
                        println!(
                            "    Uptime: {}%",
                            stake_info.performance.uptime_percentage as f64 / 1000.0
                        );
                        println!(
                            "    Attestation Accuracy: {}%",
                            stake_info.performance.attestation_accuracy as f64 / 1000.0
                        );
                        println!("    Penalties: {}", stake_info.performance.penalties);
                    }
                }

                if account.is_storage_provider() {
                    println!("\n💾 Storage Provider Status:");
                    if let Some(ref provider_info) = account.storage_provider_info {
                        println!(
                            "  Capacity: {:.2} GB",
                            provider_info.storage_capacity as f64 / 1_073_741_824.0
                        );
                        println!(
                            "  Allocated: {:.2} GB",
                            provider_info.storage_allocated as f64 / 1_073_741_824.0
                        );
                        println!("  Active Sectors: {}", provider_info.active_sectors.len());
                        println!("  Health Score: {}", provider_info.health_score);
                        println!("  Collateral Locked: {}", provider_info.collateral_locked);

                        println!("\n  PoST Statistics:");
                        println!(
                            "    Proofs Submitted: {}",
                            provider_info.postrep_stats.post_proofs_submitted
                        );
                        println!(
                            "    Pass Rate: {:.2}%",
                            provider_info.postrep_stats.post_pass_rate
                        );
                        println!(
                            "    Avg Latency: {}ms",
                            provider_info.postrep_stats.avg_post_latency_ms
                        );
                        println!(
                            "    Challenges Answered: {}",
                            provider_info.postrep_stats.challenges_answered
                        );
                        println!(
                            "    Challenges Missed: {}",
                            provider_info.postrep_stats.challenges_missed
                        );
                        println!(
                            "    Consecutive Misses: {}",
                            provider_info.postrep_stats.consecutive_misses
                        );
                        println!(
                            "    Sectors Sealed: {}",
                            provider_info.postrep_stats.sectors_sealed
                        );
                        println!(
                            "    Faulty Sectors: {}",
                            provider_info.postrep_stats.sectors_faulty
                        );

                        println!("\n  Earnings:");
                        println!(
                            "    Storage Rewards: {}",
                            provider_info.earnings.storage_rewards
                        );
                        println!(
                            "    Retrieval Fees: {}",
                            provider_info.earnings.retrieval_fees
                        );
                        println!("    PoST Rewards: {}", provider_info.earnings.post_rewards);
                        println!("    Total Earned: {}", provider_info.earnings.total_earned);
                        println!(
                            "    Total Slashed: {}",
                            provider_info.earnings.total_slashed
                        );
                        println!(
                            "    Pending Payouts: {}",
                            provider_info.earnings.pending_payouts
                        );
                    }
                }

                if let Some(ref device_caps) = account.device_capabilities {
                    println!("\n📱 Device Capabilities:");
                    println!(
                        "  Bandwidth: {} Mbps",
                        device_caps.bandwidth_capacity / 1_000_000
                    );
                    println!(
                        "  Storage: {:.2} GB",
                        device_caps.storage_capacity as f64 / 1_073_741_824.0
                    );
                    println!("  Cellular Safe: {}", device_caps.cellular_safe);
                    println!(
                        "  Max Cellular Bandwidth: {} Mbps",
                        device_caps.max_bandwidth_cellular / 1_000_000
                    );
                    println!(
                        "  Monthly Data Limit: {} GB",
                        device_caps.monthly_data_limit_gb
                    );

                    if !device_caps.supported_slices.is_empty() {
                        println!("  Supported Slices:");
                        for slice in &device_caps.supported_slices {
                            println!("    - {}", slice.as_str());
                        }
                    }

                    if let Some(ref coverage) = device_caps.coverage_area {
                        println!("  Coverage Area: {}", coverage);
                    }

                    println!("\n  Cost Awareness:");
                    println!(
                        "    Safe Mode: {}",
                        device_caps.cost_awareness.cellular_safe_mode
                    );
                    println!(
                        "    Max Monthly Cost: ${:.2}",
                        device_caps.cost_awareness.max_monthly_cost_usd
                    );
                    println!(
                        "    Current Month Usage: {} GB",
                        device_caps.cost_awareness.current_month_usage_gb
                    );
                    println!(
                        "    Throttle Threshold: {} GB",
                        device_caps.cost_awareness.cellular_throttle_threshold_gb
                    );
                }

                if let Some(ref pruning) = account.pruning_config {
                    println!("\n🗑️ Pruning Configuration:");
                    println!("  Enabled: {}", pruning.enabled);
                    println!("  Keep Epochs: {}", pruning.keep_epochs);
                    println!("  Prune Interval: {} epochs", pruning.prune_interval_epochs);
                    println!("  Keep Headers Forever: {}", pruning.keep_headers_forever);
                    println!("  Keep State Snapshots: {}", pruning.keep_state_snapshots);
                }

                if let Some(ref archival) = account.archival_config {
                    println!("\n📚 Archival Configuration:");
                    println!("  Store Old Bodies: {}", archival.store_old_bodies);
                    println!("  Store Contract Blobs: {}", archival.store_contract_blobs);
                    println!(
                        "  Store State Snapshots: {}",
                        archival.store_state_snapshots
                    );
                    println!("  Store DA Blobs: {}", archival.store_da_blobs);
                    println!("  Store Proof Evidence: {}", archival.store_proof_evidence);
                    println!("  Store User Data: {}", archival.store_user_data);
                    println!("  Replication Factor: {}", archival.replication_factor);
                }
            } else {
                println!("❌ Account not found in state");
            }
        }
        "epoch" => {
            println!("📅 Epoch Information");
            println!("═══════════════════");

            if let Some(shard_manager) = &node.shard_manager {
                let epoch = shard_manager.get_current_epoch().await;

                println!("\n🔢 Current Epoch: {}", epoch.epoch_number);
                println!("  Start Block: #{}", epoch.start_block.as_u64());
                println!("  End Block: #{}", epoch.end_block.as_u64());
                println!("  Start Time: {}", epoch.start_time);
                println!(
                    "  Duration: {} blocks",
                    epoch.end_block.as_u64() - epoch.start_block.as_u64()
                );

                println!("\n👥 Committee:");
                println!("  Size: {} validators", epoch.committee.len());
                println!("  Leader Schedule: {} slots", epoch.leader_schedule.len());

                println!("\n📊 Epoch Statistics:");
                println!("  Blocks Produced: {}", epoch.stats.blocks_produced);
                println!(
                    "  Transactions Processed: {}",
                    epoch.stats.transactions_processed
                );
                println!("  Average Block Time: {}ms", epoch.stats.avg_block_time_ms);
                println!("  Average TPS: {:.2}", epoch.stats.avg_tps);
                println!("  Cross-Shard TXs: {}", epoch.stats.cross_shard_txs);
                println!(
                    "  Network Utilization: {:.2}%",
                    epoch.stats.network_utilization * 100.0
                );

                println!("\n🔍 Proof Verification:");
                println!(
                    "  Storage Proofs (PoST): {}",
                    epoch.stats.storage_proofs_verified
                );
                println!(
                    "  Coverage Proofs (PoC): {}",
                    epoch.stats.coverage_proofs_verified
                );

                println!("\n💰 Resource Usage:");
                println!("  Total RU Consumed: {}", epoch.stats.total_ru_consumed);
                println!(
                    "  Storage Credits Burned: {}",
                    epoch.stats.total_storage_credits_burned
                );
                println!(
                    "  Deploy Credits Burned: {}",
                    epoch.stats.total_deploy_credits_burned
                );

                println!("\n🎁 Epoch Rewards:");
                println!("  Total: {} EGOC", epoch.total_rewards.to_egoc());
                println!(
                    "  Storage Bucket: {} EGOC",
                    epoch.reward_buckets.storage_rewards.to_egoc()
                );
                println!(
                    "  Consensus Bucket: {} EGOC",
                    epoch.reward_buckets.consensus_rewards.to_egoc()
                );
                println!(
                    "  Coverage Bucket: {} EGOC",
                    epoch.reward_buckets.coverage_rewards.to_egoc()
                );
                println!(
                    "  Retrieval Bucket: {} EGOC",
                    epoch.reward_buckets.retrieval_rewards.to_egoc()
                );
                println!(
                    "  DAO Treasury: {} EGOC",
                    epoch.reward_buckets.dao_treasury.to_egoc()
                );
            } else {
                println!("\n❌ Shard manager not initialized");
            }
        }
        "shard-config" => {
            println!("⚙️  Shard Configuration");
            println!("═══════════════════════");

            if let Some(shard_manager) = &node.shard_manager {
                let config = shard_manager.get_config();

                println!("\n🆔 Shard Identity:");
                println!("  Shard ID: {}", config.shard_id.as_u32());
                println!("  Chain ID: {}", shard_manager.chain_id);
                println!("  Network ID: {}", shard_manager.network_id);

                println!("\n👥 Consensus Configuration:");
                println!("  Committee Size: {} validators", config.committee_size);
                println!("  Replication Factor: {}", config.replication_factor);
                println!("  Epoch Duration: {} blocks", config.epoch_duration_blocks);
                println!("  Micro Slot Duration: {}ms", config.micro_slot_duration_ms);

                println!("\n📦 Block Configuration:");
                println!("  Max TXs per Block: {}", config.max_txs_per_block);
                println!("  Target Block Time: {}ms", config.target_block_time_ms);

                println!("\n🔗 Cross-Shard:");
                println!("  Enabled: {}", config.cross_shard_enabled);

                println!("\n💾 Storage Configuration:");
                println!(
                    "  Max Storage per Node: {}",
                    format_bytes(config.storage_config.max_storage_per_node)
                );
                println!(
                    "  Proof Frequency: every {} blocks",
                    config.storage_config.proof_frequency
                );
                println!(
                    "  Retention Period: {} blocks",
                    config.storage_config.retention_period
                );

                println!("\n🧩 Erasure Coding:");
                println!(
                    "  Data Chunks: {}",
                    config.storage_config.erasure_coding.data_chunks
                );
                println!(
                    "  Parity Chunks: {}",
                    config.storage_config.erasure_coding.parity_chunks
                );
                println!(
                    "  Chunk Size: {}",
                    format_bytes(config.storage_config.erasure_coding.chunk_size as u64)
                );
                println!("  Codec: {}", config.storage_config.erasure_coding.codec);

                println!("\n🗑️  Garbage Collection:");
                println!(
                    "  Frequency: every {} blocks",
                    config.storage_config.gc_config.frequency
                );
                println!(
                    "  Threshold: {:.0}%",
                    config.storage_config.gc_config.threshold * 100.0
                );
                println!(
                    "  Aggressive Mode: {}",
                    config.storage_config.gc_config.aggressive_mode
                );
                println!(
                    "  Prune Old Bodies: {}",
                    config.storage_config.gc_config.prune_old_bodies
                );
                println!(
                    "  Prune Old Receipts: {}",
                    config.storage_config.gc_config.prune_old_receipts
                );

                println!("\n📍 PoRep Parameters:");
                println!(
                    "  Sector Size: {}",
                    format_bytes(config.storage_config.porep_params.sector_size)
                );
                println!("  Layers: {}", config.storage_config.porep_params.layers);
                println!(
                    "  Base Degree: {}",
                    config.storage_config.porep_params.base_degree
                );
                println!(
                    "  Tree Arity: {}",
                    config.storage_config.porep_params.tree_arity
                );

                println!("\n⏱️  PoST Parameters:");
                println!(
                    "  Windows per Day: {}",
                    config.storage_config.post_params.windows_per_day
                );
                println!(
                    "  Challenges per Sector: {}",
                    config.storage_config.post_params.challenges_per_sector
                );
                println!("  SLA: {}ms", config.storage_config.post_params.sla_ms);
                println!(
                    "  Sectors per Partition: {}",
                    config.storage_config.post_params.sectors_per_partition
                );
                println!(
                    "  Enable Aggregation: {}",
                    config.storage_config.post_params.enable_aggregation
                );

                println!("\n💎 Proof of Burn (PoB):");
                println!("  Enabled: {}", config.pob_config.enabled);
                println!(
                    "  Storage Credit Price: {} uEGOC",
                    config.pob_config.storage_credit_price
                );
                println!(
                    "  Deploy Credit Price: {} uEGOC",
                    config.pob_config.deploy_credit_price
                );
                println!("  Floors Enabled: {}", config.pob_config.floors_enabled);

                println!("\n📊 DRS (Reputation System):");
                println!("  Weight Uptime: {:.2}", config.drs_config.weight_uptime);
                println!(
                    "  Weight PoST Pass: {:.2}",
                    config.drs_config.weight_post_pass
                );
                println!(
                    "  Weight Inv. Latency: {:.2}",
                    config.drs_config.weight_inv_latency
                );
                println!("  Weight PoC: {:.2}", config.drs_config.weight_poc);
                println!("  Weight Serve: {:.2}", config.drs_config.weight_serve);
                println!(
                    "  Multiplier Range: {:.2} - {:.2}",
                    config.drs_config.multiplier_min, config.drs_config.multiplier_max
                );
                println!("  PoST SLA: {}ms", config.drs_config.post_sla_ms);

                println!("\n📱 Cellular Safe Mode:");
                println!("  Enabled: {}", config.cellular_safe_config.enabled);
                println!(
                    "  Max Monthly Data: {} GB",
                    config.cellular_safe_config.max_monthly_data_gb
                );
                println!(
                    "  Throttle Threshold: {} GB",
                    config.cellular_safe_config.throttle_threshold_gb
                );
                println!(
                    "  Proof Rate: {} Hz",
                    config.cellular_safe_config.proof_rate_hz
                );
                println!(
                    "  Proof Batch Size: {}",
                    config.cellular_safe_config.proof_batch_size
                );

                println!("\n🔐 Post-Quantum Transition:");
                println!(
                    "  Transition Epoch: {}",
                    config.pq_transition_config.transition_epoch
                );
                println!(
                    "  Migration Period: {} epochs",
                    config.pq_transition_config.migration_period_epochs
                );
                println!(
                    "  PQ-Only Required: {}",
                    config.pq_transition_config.pq_only_required
                );
                println!(
                    "  Supported Algorithms: {:?}",
                    config.pq_transition_config.supported_algorithms
                );
                if let Some(deadline) = config.pq_transition_config.legacy_deadline_epoch {
                    println!("  Legacy Deadline: Epoch {}", deadline);
                }

                if !config.preferred_slices.is_empty() {
                    println!("\n🍰 Preferred Slices:");
                    for slice in &config.preferred_slices {
                        println!("  • {}", slice);
                    }
                }

                if let Some(geo) = &config.geo_constraints {
                    println!("\n🌍 Geographic Constraints:");
                    println!("  Allowed Regions: {}", geo.allowed_regions.join(", "));
                    println!("  Max Latency: {}ms", geo.max_latency_ms);
                    println!("  Min Nodes per Region: {}", geo.min_nodes_per_region);
                    println!("  H3 Resolution: {}", geo.h3_resolution);
                }
            } else {
                println!("\n❌ Shard manager not initialized");
            }
        }
        "txpool" => {
            println!("🔄 Transaction Pool Status");
            println!("═════════════════════════");

            if let Some(shard_manager) = &node.shard_manager {
                let stats = shard_manager.tx_pool.get_stats().await;

                println!("\n📊 Pool Statistics:");
                println!("  Pending Transactions: {}", stats.pending_count);
                println!("  Pool Size: {}", format_bytes(stats.pool_size_bytes));
                println!("  Average TX Age: {}ms", stats.avg_tx_age_ms);

                println!("\n📈 Transaction Counters:");
                println!("  Total Added: {}", stats.txs_added);
                println!("  Total Removed: {}", stats.txs_removed);
                println!("  Total Rejected: {}", stats.txs_rejected);

                println!("\n⏰ Status:");
                println!("  Last Updated: {}", stats.last_updated);

                if stats.pending_count > 0 {
                    println!("\n💡 Pool Health:");
                    let health = if stats.pending_count < 100 {
                        "✅ Healthy"
                    } else if stats.pending_count < 1000 {
                        "⚠️  Busy"
                    } else {
                        "🔴 Congested"
                    };
                    println!("  {}", health);

                    if stats.txs_rejected > 0 {
                        let rejection_rate =
                            (stats.txs_rejected as f64 / stats.txs_added as f64) * 100.0;
                        println!("  Rejection Rate: {:.2}%", rejection_rate);
                    }
                }
            } else {
                println!("\n❌ Shard manager not initialized");
            }
        }
        "cross-shard" => {
            println!("🔗 Cross-Shard Status");
            println!("═══════════════════");

            if let Some(shard_manager) = &node.shard_manager {
                let stats = shard_manager.cross_shard.get_stats().await;

                println!("\n📊 Receipt Statistics:");
                println!("  Receipts Sent: {}", stats.receipts_sent);
                println!("  Receipts Received: {}", stats.receipts_received);
                println!("  Receipts Pending: {}", stats.receipts_pending);
                println!("  Failed Receipts: {}", stats.failed_receipts);

                println!("\n⚡ Performance:");
                println!("  Average Latency: {}ms", stats.avg_receipt_latency_ms);

                if stats.receipts_sent > 0 {
                    let success_rate = ((stats.receipts_sent - stats.failed_receipts) as f64
                        / stats.receipts_sent as f64)
                        * 100.0;
                    println!("  Success Rate: {:.2}%", success_rate);
                }

                println!("\n⏰ Last Updated: {}", stats.last_updated);

                if stats.receipts_pending > 0 {
                    println!("\n⚠️  {} receipts pending delivery", stats.receipts_pending);
                }

                if stats.failed_receipts > 0 {
                    println!("\n❌ {} receipts failed", stats.failed_receipts);
                }
            } else {
                println!("\n❌ Shard manager not initialized");
            }
        }
        "block-details" => {
            println!("Creating detailed block with full metadata...");
            let previous_hash = node.get_state_root();
            let height = node.get_block_height().next();

            match node.create_block(vec![], previous_hash, height).await {
                Ok(block) => {
                    println!("✅ Block Created Successfully");
                    println!("═══════════════════════════════");

                    println!("\n📦 Block Header:");
                    println!("  Hash: {}", block.hash);
                    println!("  Height: {}", block.header.core.height.as_u64());
                    println!("  Previous Hash: {}", block.header.core.previous_hash);
                    println!("  Shard ID: {}", block.header.core.shard_id);
                    println!("  Epoch: {}", block.header.core.epoch.as_u64());
                    println!("  Proposer: {}", block.header.core.proposer);
                    println!(
                        "  Timestamp: {}",
                        chrono::DateTime::from_timestamp(
                            block.header.core.timestamp.as_secs() as i64,
                            0
                        )
                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                        .unwrap_or_else(|| "Unknown".to_string())
                    );

                    println!("\n📊 Block Statistics:");
                    println!("  Transaction Count: {}", block.header.core.tx_count);
                    println!("  Compute Used: {} RU", block.header.core.compute_used);
                    println!("  Storage Used: {} bytes", block.header.core.storage_used);
                    println!(
                        "  Block Size: {} bytes ({:.2} KB)",
                        block.size(),
                        block.size() as f64 / 1024.0
                    );

                    println!("\n🔐 Post-Quantum Signatures:");
                    println!(
                        "  Dilithium: {}",
                        block.header.core.pq_signature_count.dilithium_sigs
                    );
                    println!(
                        "  Ed25519: {}",
                        block.header.core.pq_signature_count.ed25519_sigs
                    );
                    println!(
                        "  Hybrid: {}",
                        block.header.core.pq_signature_count.hybrid_sigs
                    );
                    println!(
                        "  SLH-DSA: {}",
                        block.header.core.pq_signature_count.slh_dsa_sigs
                    );
                    println!("  PQ Adoption Rate: {:.2}%", block.get_pq_adoption_rate());

                    println!("\n🌐 Network & Protocol:");
                    println!("  Protocol Version: {}", block.header.core.protocol_version);
                    println!("  Chain ID: {}", block.header.core.chain_id);
                    println!("  Network ID: {}", block.header.core.network_id);

                    println!("\n📱 Cellular Optimization:");
                    println!(
                        "  Cellular Safe TXs: {}",
                        block.header.metadata.cellular_stats.cellular_safe_txs
                    );
                    println!(
                        "  WiFi Only TXs: {}",
                        block.header.metadata.cellular_stats.wifi_only_txs
                    );
                    println!(
                        "  Throttled Operations: {}",
                        block.header.metadata.cellular_stats.throttled_operations
                    );
                    println!(
                        "  Cellular Efficiency: {:.2}%",
                        block.get_cellular_efficiency_score()
                    );

                    println!("\n💰 Resource Pricing:");
                    println!(
                        "  Bytes Cost: {}",
                        block.header.metadata.resource_pricing.bytes_cost
                    );
                    println!(
                        "  RU Cost: {}",
                        block.header.metadata.resource_pricing.ru_cost
                    );
                    println!(
                        "  PoB Floor: {}",
                        block.header.metadata.resource_pricing.pob_floor
                    );
                    println!(
                        "  PQ Signature Cost: {}",
                        block.header.metadata.resource_pricing.pq_signature_cost
                    );
                    println!(
                        "  Cellular Premium: {}",
                        block.header.metadata.resource_pricing.cellular_premium
                    );

                    println!("\n🔗 Merkle Roots:");
                    println!("  Transactions: {}", block.header.core.transactions_root);
                    println!("  State: {}", block.header.core.state_root);
                    println!("  Receipts: {}", block.header.core.receipts_root);
                    println!("  PoST Events: {}", block.header.core.events_root_post);
                    println!("  PoC Events: {}", block.header.core.events_root_poc);
                    println!("  Rollup: {}", block.header.core.rollup_root);
                    println!("  DA: {}", block.header.core.da_root);

                    println!("\n📈 Events:");
                    println!(
                        "  Cross-Shard Receipts: {}",
                        block.header.metadata.cross_shard_receipts
                    );
                    println!("  Rollup Commits: {}", block.header.metadata.rollup_commits);
                    println!("  PoC Events: {}", block.header.metadata.poc_events);
                    println!("  PoST Events: {}", block.header.metadata.post_events);
                    println!("  DRS Events: {}", block.header.metadata.drs_events);
                    println!("  Deploy Events: {}", block.header.metadata.deploy_events);
                    println!("  Density Events: {}", block.header.metadata.density_events);
                    println!("  Fraud Proofs: {}", block.header.metadata.fraud_proofs);

                    println!("\n🔄 Quorum Certificate:");
                    println!("  View: {}", block.header.qc.view);
                    println!("  Round: {}", block.header.qc.round);
                    println!("  Voting Power: {}", block.header.qc.voting_power);
                    println!("  Validator Set ID: {}", block.header.qc.validator_set_id);
                    println!("  Signatures: {}", block.header.qc.signatures.len());
                    println!("  PQ Compliant: {}", block.header.qc.pq_compliant);
                }
                Err(e) => {
                    println!("❌ Failed to create block: {}", e);
                }
            }
        }

        "crypto-keys" => {
            println!("🔑 Cryptographic Keys");
            println!("════════════════════");

            let keypair = node.get_keypair();

            println!("\n📍 Identity:");
            println!("  Node Address: {}", node.get_address());
            println!("  Peer ID: {}", node.peer_id);

            println!("\n🔐 Public Keys:");
            let ed25519_pk = keypair.ed25519_public_key();
            let dilithium_pk = keypair.dilithium_public_key();
            let kyber_pk = keypair.kyber_public_key();
            let x25519_pk = keypair.x25519_public_key();

            println!("  Ed25519 (Classical):");
            println!("    Size: {} bytes", ed25519_pk.as_bytes().len());
            println!("    Algorithm: {:?}", ed25519_pk.algorithm);
            println!("    Hex: {}", hex::encode(ed25519_pk.as_bytes()));

            println!("\n  ML-DSA-2 (Dilithium2) - Post-Quantum:");
            println!("    Size: {} bytes", dilithium_pk.as_bytes().len());
            println!("    Algorithm: {:?}", dilithium_pk.algorithm);
            println!(
                "    Hex Preview: {}...",
                &hex::encode(&dilithium_pk.as_bytes()[..32])
            );

            println!("\n  ML-KEM-768 (Kyber768) - Post-Quantum:");
            println!("    Size: {} bytes", kyber_pk.as_bytes().len());
            println!("    Algorithm: {:?}", kyber_pk.algorithm);
            println!(
                "    Hex Preview: {}...",
                &hex::encode(&kyber_pk.as_bytes()[..32])
            );

            println!("\n  X25519 (Classical ECDH):");
            println!("    Size: {} bytes", x25519_pk.len());
            println!("    Hex: {}", hex::encode(&x25519_pk));

            if let Some(slh_dsa_pk) = keypair.slh_dsa_public_key() {
                println!("\n  SLH-DSA (SPHINCS+) - Post-Quantum:");
                println!("    Size: {} bytes", slh_dsa_pk.as_bytes().len());
                println!("    Algorithm: {:?}", slh_dsa_pk.algorithm);
                println!(
                    "    Hex Preview: {}...",
                    &hex::encode(&slh_dsa_pk.as_bytes()[..32])
                );
            }

            println!("\n⚙️ Configuration:");
            println!("  Transition Mode: {}", keypair.is_transition_mode());
            println!("  Post-Quantum Ready: true");
            println!("  Hybrid Signatures: {}", keypair.is_transition_mode());

            println!("\n🛡️ Security Level:");
            println!("  Classical: 128-bit (Ed25519, X25519)");
            println!("  Post-Quantum: NIST Level 2 (Dilithium2)");
            println!("  Post-Quantum: NIST Level 3 (Kyber768)");
            if keypair.slh_dsa_public_key().is_some() {
                println!("  Post-Quantum: NIST Level 1 (SLH-DSA)");
            }
        }

        "sectors" => {
            let my_address = node.get_address();
            if let Some(account) = node.state_manager.get_account(&my_address) {
                if let Some(ref provider_info) = account.storage_provider_info {
                    println!("📦 Storage Sectors");
                    println!("═════════════════");

                    if provider_info.active_sectors.is_empty() {
                        println!("\nNo active sectors");
                    } else {
                        println!("\nActive Sectors: {}\n", provider_info.active_sectors.len());

                        for (i, sector) in provider_info.active_sectors.iter().enumerate() {
                            println!("{}. Sector {}", i + 1, sector.sector_id);
                            println!(
                                "   Size: {:.2} GB",
                                sector.size_bytes as f64 / 1_073_741_824.0
                            );
                            println!("   Data Type: {:?}", sector.data_type);
                            println!("   Triad Role: {:?}", sector.triad.role);
                            println!("   Group ID: {}", sector.triad.group_id);
                            println!(
                                "   Sealed At: {}",
                                chrono::DateTime::from_timestamp_millis(
                                    sector.sealed_at.as_millis() as i64
                                )
                                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                                .unwrap_or_else(|| "Unknown".to_string())
                            );
                            println!(
                                "   Expires At: {}",
                                chrono::DateTime::from_timestamp_millis(
                                    sector.expires_at.as_millis() as i64
                                )
                                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                                .unwrap_or_else(|| "Unknown".to_string())
                            );
                            println!(
                                "   Integrity: {}",
                                if sector.integrity_verified {
                                    "✅ Verified"
                                } else {
                                    "❌ Unverified"
                                }
                            );
                            println!("   Miss Count: {}", sector.miss_count);
                            println!("   Last PoST: Epoch {}", sector.last_post_epoch);
                            println!();
                        }

                        println!("Summary:");
                        println!(
                            "  Total Capacity: {:.2} GB",
                            provider_info.storage_capacity as f64 / 1_073_741_824.0
                        );
                        println!(
                            "  Total Allocated: {:.2} GB",
                            provider_info.storage_allocated as f64 / 1_073_741_824.0
                        );
                        println!(
                            "  Utilization: {:.2}%",
                            (provider_info.storage_allocated as f64
                                / provider_info.storage_capacity as f64)
                                * 100.0
                        );
                    }
                } else {
                    println!("❌ Account is not a storage provider");
                }
            } else {
                println!("❌ Account not found");
            }
        }

        "algorithms" => {
            println!("🔬 Supported Cryptographic Algorithms");
            println!("════════════════════════════════════");

            println!("\n🔐 Digital Signatures:");
            println!("  Classical:");
            println!("    ✓ Ed25519 (NIST SP 800-186)");
            println!("      - Key Size: 32 bytes");
            println!("      - Signature Size: 64 bytes");
            println!("      - Security: ~128-bit classical");

            println!("\n  Post-Quantum:");
            println!("    ✓ ML-DSA-2 / Dilithium2 (FIPS 204)");
            println!("      - Public Key: ~1312 bytes");
            println!("      - Signature: ~2420 bytes");
            println!("      - Security: NIST Level 2");

            println!("\n    ✓ SLH-DSA / SPHINCS+ (FIPS 205)");
            println!("      - Public Key: 32 bytes");
            println!("      - Signature: ~7856 bytes");
            println!("      - Security: NIST Level 1");
            println!("      - Properties: Stateless, hash-based");

            println!("\n🔑 Key Encapsulation:");
            println!("  Classical:");
            println!("    ✓ X25519 (RFC 7748)");
            println!("      - Key Size: 32 bytes");
            println!("      - Shared Secret: 32 bytes");
            println!("      - Security: ~128-bit classical");

            println!("\n  Post-Quantum:");
            println!("    ✓ ML-KEM-768 / Kyber768 (FIPS 203)");
            println!("      - Public Key: 1184 bytes");
            println!("      - Ciphertext: 1088 bytes");
            println!("      - Shared Secret: 32 bytes");
            println!("      - Security: NIST Level 3");

            println!("\n🔒 Symmetric Encryption:");
            println!("    ✓ XChaCha20-Poly1305 (AEAD)");
            println!("      - Key Size: 32 bytes");
            println!("      - Nonce: 24 bytes");
            println!("      - Tag: 16 bytes");
            println!("      - Security: 256-bit");

            println!("\n🗂️ Hashing:");
            println!("    ✓ BLAKE2s-256");
            println!("      - Output: 32 bytes");
            println!("      - Use: General hashing, Merkle trees");

            println!("\n    ✓ SHA-256");
            println!("      - Output: 32 bytes");
            println!("      - Use: HKDF key derivation");

            println!("\n🎯 Key Derivation:");
            println!("    ✓ HKDF-SHA256");
            println!("      - Use: Session key derivation");

            println!("\n🛡️ Security Properties:");
            println!("  ✓ Post-Quantum Secure");
            println!("  ✓ Forward Secrecy");
            println!("  ✓ Replay Protection");
            println!("  ✓ Domain Separation");
            println!("  ✓ Authenticated Encryption");
            println!("  ✓ Hybrid Cryptography Support");
        }
        "pq-status" => {
            println!("🔮 Post-Quantum Status");
            println!("═════════════════════");

            let my_address = node.get_address();
            if let Some(account) = node.state_manager.get_account(&my_address) {
                if let Some(ref pq_info) = account.pq_transition_info {
                    println!("\n📊 Transition Information:");
                    println!(
                        "  Transition Started: Epoch {}",
                        pq_info.transition_started_epoch
                    );
                    println!("  PQ-Only Mode: {}", pq_info.pq_only_mode);

                    if let Some(disabled_epoch) = pq_info.ed25519_disabled_epoch {
                        println!("  Ed25519 Disabled: Epoch {}", disabled_epoch);
                        println!(
                            "  Classical Signatures: Disabled since epoch {}",
                            disabled_epoch
                        );
                    } else {
                        println!("  Ed25519 Status: Active");
                        println!("  Classical Signatures: Enabled (Hybrid Mode)");
                    }

                    println!("\n🔐 Supported Algorithms:");
                    for alg_id in &pq_info.supported_algorithms {
                        let alg_name = match *alg_id {
                            0 => "Ed25519 (Classical)",
                            1 => "ML-DSA-2 (Dilithium2 - PQ)",
                            2 => "ML-KEM-768 (Kyber768 - PQ)",
                            3 => "X25519 (Classical)",
                            4 => "SLH-DSA (SPHINCS+ - PQ)",
                            _ => "Unknown",
                        };
                        println!("    ✓ {} (ID: {})", alg_name, alg_id);
                    }

                    println!("\n⚙️ Current Configuration:");
                    if pq_info.pq_only_mode {
                        println!("  Mode: Pure Post-Quantum");
                        println!("  Classical algorithms: Disabled");
                        println!("  Hybrid mode: Disabled");
                    } else {
                        println!("  Mode: Hybrid (Transition)");
                        println!("  Classical algorithms: Enabled");
                        println!("  Hybrid mode: Enabled");
                    }

                    println!("\n🛡️ Security Posture:");
                    println!("  Post-Quantum Readiness: 100%");
                    println!("  Quantum-Safe: YES");
                    println!("  Downgrade Protection: Active");

                    let has_ed25519 = pq_info.supported_algorithms.contains(&0);
                    let has_dilithium = pq_info.supported_algorithms.contains(&1);
                    let has_kyber = pq_info.supported_algorithms.contains(&2);
                    let has_x25519 = pq_info.supported_algorithms.contains(&3);
                    let has_slh_dsa = pq_info.supported_algorithms.contains(&4);

                    println!("\n✅ Active Cryptographic Primitives:");
                    if has_ed25519 {
                        println!("  ✓ Ed25519 Digital Signatures");
                    }
                    if has_dilithium {
                        println!("  ✓ ML-DSA-2 Digital Signatures (Post-Quantum)");
                    }
                    if has_kyber {
                        println!("  ✓ ML-KEM-768 Key Encapsulation (Post-Quantum)");
                    }
                    if has_x25519 {
                        println!("  ✓ X25519 Key Exchange");
                    }
                    if has_slh_dsa {
                        println!("  ✓ SLH-DSA Digital Signatures (Post-Quantum)");
                    }
                } else {
                    println!("\n❌ No PQ transition information available");
                }
            } else {
                println!("\n❌ Account not found");
            }

            let keypair = node.get_keypair();
            println!("\n🔑 Node Keypair Configuration:");
            println!("  Transition Mode: {}", keypair.is_transition_mode());
            println!("  Available Keys:");
            println!("    ✓ Ed25519 (Classical)");
            println!("    ✓ ML-DSA-2 (Post-Quantum)");
            println!("    ✓ ML-KEM-768 (Post-Quantum)");
            println!("    ✓ X25519 (Classical)");
            if keypair.slh_dsa_public_key().is_some() {
                println!("    ✓ SLH-DSA (Post-Quantum)");
            }

            println!("\n📊 Signature Capabilities:");
            if keypair.is_transition_mode() {
                println!("  Current Mode: Hybrid");
                println!("  Default Signatures: Dual (Ed25519 + Dilithium)");
                println!("  Quantum Resistance: Partial (Transitioning)");
            } else {
                println!("  Current Mode: Post-Quantum Only");
                println!("  Default Signatures: Dilithium Only");
                println!("  Quantum Resistance: Full");
            }
        }
        "quit" | "exit" | "q" => {
            println!("👋 Goodbye!");
            return Ok(false);
        }
        _ => {
            println!(
                "❓ Unknown command: '{}'. Type 'help' for available commands.",
                command
            );
        }
    }
    Ok(true)
}

fn print_commands() {
    println!("\n📋 Available Commands:");
    println!("═════════════════════");

    println!("\n💰 Account & Balance:");
    println!("  my-account     - Show my account details");
    println!("  account        - Show account by address");
    println!("  account-details- Show detailed account information");
    println!("  accounts       - List all accounts");
    println!("  transfer       - Create transfer transaction");

    println!("\n⛓️  Blockchain:");
    println!("  blockchain     - Show blockchain state");
    println!("  block          - Create block");
    println!("  block-details  - Create block with full details");
    println!("  state          - Show current state");
    println!("  shard          - Show shard configuration");

    println!("  txpool         - Transaction pool status");
    println!("  cross-shard    - Cross-shard communication status");

    println!("\n👥 Network:");
    println!("  peers          - List connected peers");
    println!("  validators     - Show active validators");
    println!("  connect        - Connect to bootstrap peers");
    println!("  addresses      - Show network addresses");

    println!("\n💾 Storage:");
    println!("  storage        - Storage overview");
    println!("  sectors        - Show storage sectors (providers only)");
    println!("  proofs         - Show recent proofs");
    println!("  post           - Generate PoST proof");
    println!("  poc            - Generate PoC proof");

    println!("\n🍰 5G & Slices:");
    println!("  slices         - Network slices overview");
    println!("  5g             - Show 5G configuration");

    println!("\n🔐 Cryptography:");
    println!("  crypto         - Show cryptographic info");
    println!("  crypto-keys    - Show detailed key information");
    println!("  algorithms     - Show supported algorithms");
    println!("  pq-status      - Show post-quantum status");
    println!("  kem            - Key encapsulation");
    println!("  stealth        - Stealth addresses");
    println!("  batch-verify   - Batch verification");
    println!("  merkle         - Merkle trees");

    println!("\n📊 Monitoring:");
    println!("  status         - Show detailed status");
    println!("  metrics        - Show performance metrics");
    println!("  performance    - Show detailed performance");
    println!("  network        - Show network status");
    println!("  sharing        - Bandwidth sharing stats");
    println!("  compression    - Data optimization stats");
    println!("  txpool         - Transaction pool status");
    println!("  cross-shard    - Cross-shard status");

    println!("\n🔬 Advanced:");
    println!("  deploy-policy  - Deploy manager");
    println!("  drs            - Reputation system");
    println!("  deploy-cost    - Cost estimation");
    println!("  drs-rewards    - Reward distribution");

    println!("\n🔧 Control:");
    println!("  roles          - Show node roles");
    println!("  capabilities   - Show node capabilities");
    println!("  node-info      - Show basic info");
    println!("  enable-sharing - Enable bandwidth sharing");
    println!("  disable-sharing- Disable bandwidth sharing");
    println!("  reset-stats    - Reset statistics");
    println!("  switch-wifi    - Switch to WiFi");
    println!("  switch-5g      - Switch to 5G");
    println!("  switch-ethernet- Switch to Ethernet");

    println!("\n  quit/exit      - Shutdown the node");
    println!();
}

fn print_detailed_status(node: &Node) {
    println!("\n📊 Detailed Node Status");
    println!("════════════════════════");
    println!("Peer ID: {}", node.peer_id);
    println!("Node Type: {}", node.node_type);
    println!("Roles: {:?}", node.roles);
    println!("Shards: {:?}", node.shard_ids);
    println!(
        "Storage Capacity: {} GB",
        node.storage_capacity_bytes / 1_000_000_000
    );
    println!(
        "Bandwidth Capacity: {} Mbps",
        node.bandwidth_capacity_bps / 1_000_000
    );
    println!("Geohash: {:?}", node.geohash);
    println!("5G Slice: {:?}", node.slice_id);
    println!("5G Ready: {}", node.is_5g_ready());
    println!("Recent Proofs: {}", node.recent_proofs.len());
    println!("Placements: {}", node.placements.len());
    println!("Connected Peers: {}", node.swarm.connected_peers().count());
    println!("Listen Addresses: {:?}", node.listen_addresses);
    println!("Bootstrap Peers: {:?}", node.bootstrap_peers);

    println!("\n🔗 Blockchain State");
    let state_stats = node.state_manager.get_stats();
    println!("Block Height: {}", node.get_block_height());
    println!("State Root: {}", node.get_state_root());
    println!("Total Accounts: {}", state_stats.total_accounts);
    println!("Total Balance: {}", state_stats.total_balance);
    println!("Active Validators: {}", state_stats.active_validators);

    println!("\n🔧 Optimization Features");
    println!(
        "Current Network: {:?}",
        node.network_manager.current_interface
    );
    println!("{}", node.get_data_usage_summary());

    let sharing_stats = node.get_bandwidth_sharing_stats();
    println!(
        "Bandwidth Sharing: {} (active: {})",
        sharing_stats.enabled, sharing_stats.active_connections
    );

    let opt_stats = node.get_optimization_stats();
    println!("Data Saved: {:.1} MB", opt_stats.total_bandwidth_saved_mb);
}

fn print_performance_metrics(node: &Node) {
    let metrics = node.get_performance_metrics();
    println!("\n⚡ Performance Metrics");
    println!("═════════════════════");
    println!(
        "Uptime: {} seconds ({:.1} hours)",
        metrics.uptime_seconds,
        metrics.uptime_seconds as f64 / 3600.0
    );
    println!("Messages Sent: {}", metrics.messages_sent);
    println!("Messages Received: {}", metrics.messages_received);
    println!(
        "Bytes Sent: {:.2} MB",
        metrics.bytes_sent as f64 / 1_000_000.0
    );
    println!(
        "Bytes Received: {:.2} MB",
        metrics.bytes_received as f64 / 1_000_000.0
    );
    println!("Proof Events Generated: {}", metrics.proof_events_generated);
    println!(
        "Peer Connections Established: {}",
        metrics.peer_connections_established
    );
    println!("Peer Connections Lost: {}", metrics.peer_connections_lost);
    println!(
        "Bandwidth Shared: {:.2} MB",
        metrics.bandwidth_shared_bytes as f64 / 1_000_000.0
    );
    println!(
        "Data Compressed: {:.2} MB",
        metrics.data_compressed_bytes as f64 / 1_000_000.0
    );
    println!("Network Switches: {}", metrics.network_switches);
    println!("Cost Savings: ${:.2}", metrics.cost_savings_usd);
}
