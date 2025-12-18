use clap::{Arg, Command};
use ego_core::{Address, Balance, Transaction, TransactionPayload};
use ego_node::{NetworkType, Node, NodeRole};
use libp2p::{Multiaddr, futures::StreamExt};
use std::io::{self, Write};
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
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node_type: "full".to_string(),
            roles: vec![NodeRole::Validator, NodeRole::StorageProvider],
            shard_ids: vec![0],
            listen_port: 9000,
            bootstrap_peers: vec![],
            storage_capacity_gb: Some(100.0),
            latitude: None,
            longitude: None,
            geohash_precision: 7,
            bandwidth_mbps: Some(100),
            slice_id: None,
            enable_metrics: false,
            enable_interactive: false,

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

    if config.enable_interactive {
        info!("🖥️ Starting interactive mode");
        run_interactive_mode(node, config).await?;
    } else {
        info!("🔄 Starting daemon mode");
        run_daemon_mode(node, config).await?;
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
    }
}

fn determine_roles(node_type: &str) -> Vec<NodeRole> {
    match node_type {
        "validator" => vec![NodeRole::Validator],
        "storage" => vec![NodeRole::StorageProvider],
        "gateway" => vec![NodeRole::Gateway],
        "seed" => vec![NodeRole::Gateway],
        "indexer" => vec![NodeRole::StorageProvider],
        "full" => vec![NodeRole::Validator, NodeRole::StorageProvider],
        _ => {
            warn!("Unknown node type '{}', defaulting to full node", node_type);
            vec![NodeRole::Validator, NodeRole::StorageProvider]
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
async fn run_daemon_mode(mut node: Node, config: NodeConfig) -> anyhow::Result<()> {
    info!("🔄 Running in daemon mode. Press Ctrl+C to stop.");
    info!(
        "📊 Node Type: {} | Roles: {:?} | Port: {}",
        config.node_type, config.roles, config.listen_port
    );

    let mut status_interval = interval(Duration::from_secs(30));
    let mut metrics_interval = interval(Duration::from_secs(60));
    let mut proof_interval = interval(Duration::from_secs(300));
    let mut optimization_interval = interval(Duration::from_secs(10));
    let mut daily_reset_interval = interval(Duration::from_secs(86400));
    let mut uptime_interval = interval(Duration::from_secs(1));

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
                print_status(&node);
            },

            _ = metrics_interval.tick() => {
                if config.enable_metrics {
                    print_metrics(&node);
                    print_optimization_metrics(&node);
                }
            },

            _ = proof_interval.tick() => {
                if let Err(e) = generate_proofs(&mut node).await {
                    warn!("Error generating proofs: {}", e);
                }
            },

            _ = optimization_interval.tick() => {
                if let Err(e) = node.process_optimization_events().await {
                    warn!("Error processing optimization events: {}", e);
                }
            },

            _ = daily_reset_interval.tick() => {
                node.network_manager.reset_monthly_stats();
                node.bandwidth_sharing.reset_daily_stats();
                info!("🔄 Daily stats reset completed");
            },

            _ = uptime_interval.tick() => {
                node.update_uptime();
            },

            _ = tokio::signal::ctrl_c() => {
                info!("🛑 Received shutdown signal");
                break;
            }
        }
    }

    info!("👋 Ego blockchain node shutting down gracefully");
    print_final_stats(&node);
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
            println!("Creating test transfer transaction...");
            let from_address = node.get_address();
            let to_address = Address::new([1u8; 20]);
            let amount = Balance::from_egoc(10);

            if let Some(account) = node.get_account(&from_address) {
                let payload = TransactionPayload::Transfer {
                    to: to_address,
                    amount,
                    memo: Some("Test transfer".to_string()),
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
            println!("Creating test block...");
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

            println!("\n🔬 Signature Test:");
            let test_message = b"Test signature verification - advanced blockchain node";

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

            println!("\n🔒 Key Encapsulation (KEM):");
            match node.get_keypair().encapsulate_kyber(kyber_pk.as_bytes()) {
                Ok((ciphertext, shared_secret)) => {
                    println!("  ML-KEM-768 (Kyber) Encapsulation:");
                    println!("    Ciphertext Size: {} bytes", ciphertext.len());
                    println!("    Shared Secret Size: {} bytes", shared_secret.len());

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
                Err(e) => println!("  KEM Test: FAILED - {}", e),
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
        "test-kem" => {
            println!("🔒 Testing Key Encapsulation Mechanism...");
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
        "test-stealth" => {
            println!("🎭 Testing Stealth Address Generation...");
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
        "test-batch-verify" => {
            println!("📦 Testing Batch Signature Verification...");
            use ego_core::crypto::BatchVerifier;

            let mut verifier = BatchVerifier::new(100000, 10);
            let test_msg = b"Batch verification test message";

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
        "test-merkle" => {
            println!("🌳 Testing Merkle Tree Construction...");
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
                println!(
                    "  No proofs generated yet. Use 'test-poc' or 'test-post' to generate test proofs."
                );
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
            println!("✅ Switched to WiFi (simulated)");
        }
        "switch-5g" => {
            node.update_network_interface_status(NetworkType::FiveG, true, Some(90));
            println!("✅ Switched to 5G (simulated)");
        }
        "switch-ethernet" => {
            node.update_network_interface_status(NetworkType::Ethernet, true, Some(100));
            println!("✅ Switched to Ethernet (simulated)");
        }
        "test-poc" => {
            if let Some(geohash) = node.geohash.clone() {
                let evidence = format!("test_poc_{}", chrono::Utc::now().timestamp()).into_bytes();
                if let Err(e) = node.emit_poc_proof(geohash.clone(), evidence) {
                    println!("❌ Failed to emit PoC proof: {}", e);
                } else {
                    println!("✅ PoC proof emitted for geohash: {}", geohash);
                }
            } else {
                println!("❌ No geohash set for PoC proof. Set latitude/longitude first.");
            }
        }
        "test-post" => {
            if !node.shard_ids.is_empty() {
                let shard_id = node.shard_ids[0];
                let piece_id = chrono::Utc::now().timestamp() as u32;
                let evidence = format!("test_post_{}_{}", shard_id, piece_id).into_bytes();
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
    println!("  help           - Show this help message");
    println!("  status         - Show detailed node status");
    println!("  peers          - List connected peers");
    println!("  roles          - Show current node roles");
    println!("  capabilities   - Show node capabilities");
    println!("");
    println!("🔗 Blockchain Commands:");
    println!("  blockchain     - Show blockchain state");
    println!("  account        - Show my account details");
    println!("  accounts       - Show all accounts summary");
    println!("  transfer       - Create test transfer transaction");
    println!("  block          - Create test block");
    println!("  crypto         - Show cryptographic information");
    println!("");
    println!("📊 Monitoring Commands:");
    println!("  proofs         - Show recent proof events");
    println!("  5g             - Show 5G configuration status");
    println!("  metrics        - Show performance metrics");
    println!("  network        - Show network status and usage");
    println!("  sharing        - Show bandwidth sharing stats");
    println!("  compression    - Show data compression stats");
    println!("  performance    - Show detailed performance metrics");
    println!("  node-info      - Show basic node information");
    println!("");
    println!("🔧 Control Commands:");
    println!("  enable-sharing - Enable bandwidth sharing");
    println!("  disable-sharing- Disable bandwidth sharing");
    println!("  switch-wifi    - Switch to WiFi (simulated)");
    println!("  switch-5g      - Switch to 5G (simulated)");
    println!("  switch-ethernet- Switch to Ethernet (simulated)");
    println!("  reset-stats    - Reset statistics");
    println!("");
    println!("🧪 Test Commands:");
    println!("  test-poc       - Generate test Proof of Coverage");
    println!("  test-post      - Generate test Proof of Spacetime");
    println!("  connect        - Attempt to connect to bootstrap peers");
    println!("  addresses      - Show listen and bootstrap addresses");
    println!("🔐 Advanced Crypto Commands:");
    println!("  test-kem       - Test Key Encapsulation Mechanism");
    println!("  test-stealth   - Test Stealth Address Generation");
    println!("  test-batch-verify - Test Batch Signature Verification");
    println!("  test-merkle    - Test Merkle Tree Construction");
    println!("");
    println!("  quit/exit      - Shutdown the node");
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
