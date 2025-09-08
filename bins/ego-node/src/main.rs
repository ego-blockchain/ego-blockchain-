use clap::{Arg, Command};
use ego_node::{Node, NodeRole};
use libp2p::{Multiaddr, futures::StreamExt};
use std::io::{self, Write};
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error, info, warn};
use tracing_subscriber::fmt::init;

#[derive(Debug, Clone)]
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
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node_type: "full".to_string(),
            roles: vec![NodeRole::Validator, NodeRole::Storage, NodeRole::Relay],
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
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init();

    let config = parse_cli_args();

    info!("🚀 Starting Ego Blockchain Node");
    info!("Configuration: {:?}", config);

    let mut node = create_node_from_config(&config).await?;

    setup_networking(&mut node, &config).await?;

    info!("✅ Node created successfully: {}", node.get_summary());
    info!("🔧 Node capabilities: {:?}", node.get_capabilities());
    info!("🌐 5G Ready: {}", node.is_5g_ready());

    if config.enable_interactive {
        run_interactive_mode(node, config).await?;
    } else {
        run_daemon_mode(node, config).await?;
    }

    Ok(())
}

fn parse_cli_args() -> NodeConfig {
    let matches = Command::new("ego-node")
        .version("1.0.0")
        .author("Ego Blockchain Team")
        .about("Ego Blockchain Node - 5G-enabled decentralized network")
        .arg(
            Arg::new("type")
                .long("type")
                .short('t')
                .help("Node type: validator, storage, gateway, full, seed")
                .default_value("full"),
        )
        .arg(
            Arg::new("shards")
                .long("shards")
                .short('s')
                .help("Comma-separated shard IDs to participate in")
                .default_value("0,1"),
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
                .default_value("100")
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
    }
}

fn determine_roles(node_type: &str) -> Vec<NodeRole> {
    match node_type {
        "validator" => vec![NodeRole::Validator],
        "storage" => vec![NodeRole::Storage, NodeRole::Witness],
        "gateway" => vec![NodeRole::Gateway, NodeRole::Witness, NodeRole::Relay],
        "seed" => vec![NodeRole::Seed, NodeRole::Relay],
        "indexer" => vec![NodeRole::Indexer, NodeRole::Storage],
        "full" => vec![
            NodeRole::Validator,
            NodeRole::Storage,
            NodeRole::Relay,
            NodeRole::Witness,
        ],
        _ => {
            warn!("Unknown node type '{}', defaulting to full node", node_type);
            vec![NodeRole::Validator, NodeRole::Storage, NodeRole::Relay]
        }
    }
}

async fn create_node_from_config(config: &NodeConfig) -> anyhow::Result<Node> {
    let mut node = match config.node_type.as_str() {
        "validator" => Node::new_validator(config.shard_ids.clone()).await?,
        "storage" => {
            let capacity_bytes = config.storage_capacity_gb.unwrap_or(100.0) * 1_000_000_000.0;
            let geohash = config
                .latitude
                .zip(config.longitude)
                .map(|(lat, lon)| format!("geo_{}_{}_p{}", lat, lon, config.geohash_precision))
                .unwrap_or_else(|| "default_geohash".to_string());
            Node::new_storage_miner(capacity_bytes as u64, geohash).await?
        }
        "gateway" => {
            if let (Some(lat), Some(lon), Some(slice_id), Some(bandwidth)) = (
                config.latitude,
                config.longitude,
                &config.slice_id,
                config.bandwidth_mbps,
            ) {
                Node::new_5g_edge_gateway(slice_id.clone(), lat, lon, bandwidth * 1_000_000).await?
            } else {
                warn!("Gateway node requires latitude, longitude, slice-id, and bandwidth");
                Node::new(config.roles.clone(), config.shard_ids.clone()).await?
            }
        }
        "full" | _ => {
            let capacity_bytes = config.storage_capacity_gb.unwrap_or(100.0) * 1_000_000_000.0;
            Node::new_full_node(config.shard_ids.clone(), capacity_bytes as u64).await?
        }
    };

    if let (Some(lat), Some(lon)) = (config.latitude, config.longitude) {
        node.set_geolocation(lat, lon, config.geohash_precision);
    }

    if let Some(bandwidth_mbps) = config.bandwidth_mbps {
        node.set_bandwidth_capacity(bandwidth_mbps * 1_000_000);
    }

    if let Some(storage_gb) = config.storage_capacity_gb {
        node.set_storage_capacity((storage_gb * 1_000_000_000.0) as u64);
    }

    if let Some(slice_id) = &config.slice_id {
        node.set_slice_configuration(slice_id.clone());
    }

    Ok(node)
}

async fn setup_networking(node: &mut Node, config: &NodeConfig) -> anyhow::Result<()> {
    node.start_listening(config.listen_port).await?;
    info!("🎧 Node listening on port {}", config.listen_port);

    for bootstrap_addr in &config.bootstrap_peers {
        if let Ok(addr) = bootstrap_addr.parse::<Multiaddr>() {
            node.add_bootstrap_peer(addr);
            info!("🔗 Added bootstrap peer: {}", bootstrap_addr);
        } else {
            warn!("Invalid bootstrap peer address: {}", bootstrap_addr);
        }
    }

    let (max_peers, max_topics) = match config.node_type.as_str() {
        "seed" => (1000, 50),
        "gateway" => (500, 30),
        "full" => (200, 25),
        _ => (100, 20),
    };
    node.configure_resource_limits(max_peers, max_topics);

    Ok(())
}

async fn run_daemon_mode(mut node: Node, config: NodeConfig) -> anyhow::Result<()> {
    info!("🔄 Running in daemon mode. Press Ctrl+C to stop.");

    let mut status_interval = interval(Duration::from_secs(30));
    let mut metrics_interval = interval(Duration::from_secs(60));
    let mut proof_interval = interval(Duration::from_secs(300)); // 5 minutes

    loop {
        tokio::select! {
            event = node.swarm.select_next_some() => {
                debug!("Network event: {:?}", event);
                handle_network_event(&mut node, event).await?;
            },
            _ = status_interval.tick() => {
                print_status(&node);
            },
            _ = metrics_interval.tick() => {
                if config.enable_metrics {
                    print_metrics(&node);
                }
            },
            _ = proof_interval.tick() => {
                generate_proofs(&mut node).await?;
            },
            _ = tokio::signal::ctrl_c() => {
                info!("🛑 Received shutdown signal");
                break;
            }
        }
    }

    info!("👋 Ego blockchain node shutting down gracefully");
    Ok(())
}

async fn run_interactive_mode(mut node: Node, _config: NodeConfig) -> anyhow::Result<()> {
    info!("🖥️  Running in interactive mode. Type 'help' for commands.");

    let mut status_interval = interval(Duration::from_secs(10));

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

    loop {
        tokio::select! {
            event = node.swarm.select_next_some() => {
                debug!("Network event: {:?}", event);
                handle_network_event(&mut node, event).await?;
            },
            _ = status_interval.tick() => {
            },
            Some(command) = rx.recv() => {
                let command = command.to_lowercase();

                match handle_interactive_command(&mut node, &command).await {
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

    Ok(())
}

async fn handle_network_event(
    _node: &mut Node,
    event: libp2p::swarm::SwarmEvent<
        <ego_node::NodeBehaviour as libp2p::swarm::NetworkBehaviour>::ToSwarm,
    >,
) -> anyhow::Result<()> {
    match event {
        libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
            info!("🌐 Listening on {}", address);
        }
        libp2p::swarm::SwarmEvent::Behaviour(event) => {
            debug!("Behaviour event: {:?}", event);
        }
        libp2p::swarm::SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            info!("🤝 Connected to peer: {}", peer_id);
        }
        libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
            info!(
                "❌ Disconnected from peer: {} (cause: {:?})",
                peer_id, cause
            );
        }
        _ => {}
    }
    Ok(())
}

async fn handle_interactive_command(node: &mut Node, command: &str) -> anyhow::Result<bool> {
    match command {
        "help" => {
            print_commands();
        }
        "status" => {
            print_detailed_status(node);
        }
        "peers" => {
            println!(
                "Connected peers: {:?}",
                node.swarm.connected_peers().collect::<Vec<_>>()
            );
        }
        "roles" => {
            println!("Current roles: {:?}", node.get_roles());
        }
        "capabilities" => {
            println!("Node capabilities: {:?}", node.get_capabilities());
        }
        "proofs" => {
            println!("Recent proofs: {} events", node.recent_proofs.len());
            for (i, proof) in node.recent_proofs.iter().rev().take(5).enumerate() {
                println!("  {}: {} - {}", i + 1, proof.event_type, proof.peer_id);
            }
        }
        "5g" => {
            println!("5G Ready: {}", node.is_5g_ready());
            if let Some(slice_id) = &node.slice_id {
                println!("Slice ID: {}", slice_id);
            }
        }
        "metrics" => {
            print_metrics(node);
        }
        "test-poc" => {
            if let Some(geohash) = &node.geohash {
                node.emit_poc_proof(geohash.clone(), vec![1, 2, 3, 4])?;
            } else {
                println!("❌ No geohash set for PoC proof");
            }
        }
        "test-post" => {
            if !node.shard_ids.is_empty() {
                let shard_id = node.shard_ids[0];
                node.emit_post_proof(shard_id, 12345, vec![5, 6, 7, 8])?;
            } else {
                println!("❌ No shards configured for PoST proof");
            }
        }
        "quit" | "exit" | "q" => {
            println!("👋 Goodbye!");
            return Ok(false);
        }
        _ => {
            println!(
                "❓ Unknown command: {}. Type 'help' for available commands.",
                command
            );
        }
    }
    Ok(true)
}

fn print_commands() {
    println!("\n📋 Available Commands:");
    println!("  help        - Show this help message");
    println!("  status      - Show detailed node status");
    println!("  peers       - List connected peers");
    println!("  roles       - Show current node roles");
    println!("  capabilities - Show node capabilities");
    println!("  proofs      - Show recent proof events");
    println!("  5g          - Show 5G configuration status");
    println!("  metrics     - Show performance metrics");
    println!("  test-poc    - Generate test Proof of Coverage");
    println!("  test-post   - Generate test Proof of Spacetime");
    println!("  quit/exit   - Shutdown the node");
}

fn print_status(node: &Node) {
    info!("📊 Node Status: {}", node.get_summary());
}

fn print_detailed_status(node: &Node) {
    println!("\n📊 Detailed Node Status");
    println!("════════════════════════");
    println!("Peer ID: {}", node.peer_id);
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

async fn generate_proofs(node: &mut Node) -> anyhow::Result<()> {
    if node.has_role(NodeRole::Storage) && !node.shard_ids.is_empty() {
        let shard_id = node.shard_ids[0];
        let piece_id = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
            % 1000000) as u32;

        let evidence = format!("post_proof_{}", piece_id).into_bytes();
        node.emit_post_proof(shard_id, piece_id, evidence)?;
        debug!("Generated PoST proof for shard {}", shard_id);
    }

    if node.has_role(NodeRole::Witness) {
        if let Some(geohash) = &node.geohash.clone() {
            let evidence = format!(
                "poc_proof_{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs()
            )
            .into_bytes();

            node.emit_poc_proof(geohash.clone(), evidence)?;
            debug!("Generated PoC proof for geohash {}", geohash);
        }
    }

    Ok(())
}
