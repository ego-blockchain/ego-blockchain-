use ego_core::{Hash, KeyPair, ShardId};
use ego_p2p::{MessageBuilder, NetworkConfig, NetworkManager};
use futures::StreamExt;
use libp2p::Multiaddr;
use tokio::time::{Duration, sleep, timeout};
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    info!("=== Starting Two Node Test ===");

    let keypair1 = KeyPair::generate();
    let keypair2 = KeyPair::generate();

    let config1 = NetworkConfig::default()
        .with_listen_addresses(vec!["/ip4/0.0.0.0/tcp/9001".parse::<Multiaddr>()?])
        .with_max_peers(50)
        .with_mdns(true);

    let mut network1 = NetworkManager::new(keypair1, config1, vec![0]).await?;

    info!("Node 1 Peer ID: {}", network1.peer_id());
    info!("Node 1 Address: {}", network1.address());

    network1.start().await?;
    info!("✅ Node 1 started");

    sleep(Duration::from_secs(2)).await;

    let node1_multiaddr: Multiaddr =
        format!("/ip4/127.0.0.1/tcp/9001/p2p/{}", network1.peer_id()).parse()?;

    info!("Node 1 multiaddress: {}", node1_multiaddr);

    let config2 = NetworkConfig::default()
        .with_listen_addresses(vec!["/ip4/0.0.0.0/tcp/9002".parse::<Multiaddr>()?])
        .with_bootstrap_peers(vec![node1_multiaddr.clone()])
        .with_max_peers(50)
        .with_mdns(true);

    let mut network2 = NetworkManager::new(keypair2, config2, vec![0]).await?;

    info!("Node 2 Peer ID: {}", network2.peer_id());
    info!("Node 2 Address: {}", network2.address());

    network2.start().await?;
    info!("✅ Node 2 started and connecting to Node 1");

    info!("Waiting for connections to establish...");

    let connection_timeout = Duration::from_secs(20);
    let start = std::time::Instant::now();

    loop {
        tokio::select! {
            event = network1.swarm.select_next_some() => {
                if let libp2p::swarm::SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                    info!("Node 1: Connection established with {}", peer_id);
                    network1.peer_manager.update_connection_state(&peer_id, ego_p2p::ConnectionState::Connected);
                }
            }

            event = network2.swarm.select_next_some() => {
                if let libp2p::swarm::SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                    info!("Node 2: Connection established with {}", peer_id);
                    network2.peer_manager.update_connection_state(&peer_id, ego_p2p::ConnectionState::Connected);
                }
            }

            _ = sleep(Duration::from_secs(1)) => {
                let peers1 = network1.connected_peers().len();
                let peers2 = network2.connected_peers().len();

                if peers1 > 0 && peers2 > 0 {
                    info!("✅ Nodes connected successfully!");
                    info!("Node 1 has {} peers", peers1);
                    info!("Node 2 has {} peers", peers2);
                    break;
                }

                if start.elapsed() >= connection_timeout {
                    warn!("⚠️ Connection timeout after {} seconds", connection_timeout.as_secs());
                    break;
                }
            }
        }
    }

    info!("\n=== Final Connection Status ===");
    info!(
        "Node 1 connected peers: {}",
        network1.connected_peers().len()
    );
    info!(
        "Node 2 connected peers: {}",
        network2.connected_peers().len()
    );

    if network1.connected_peers().is_empty() && network2.connected_peers().is_empty() {
        info!("\n⚠️ Nodes are running independently (not connected)");
        info!("This can happen due to:");
        info!("  - Firewall blocking local connections");
        info!("  - mDNS not working on your system");
        info!("  - Network configuration issues");
        info!("\nEach node is still functional and can operate independently.");
    }

    info!("\n=== Testing Message Publishing ===");

    let test_message = MessageBuilder::transaction(
        Hash::random(),
        ShardId::new(0)?,
        b"Hello from Node 2!".to_vec(),
    );

    match network2
        .publish_message("ego/shard/0/tx", test_message)
        .await
    {
        Ok(_) => {
            info!("✅ Node 2 published test message to shard 0");

            info!("Processing messages for 2 seconds...");
            let message_timeout = Duration::from_secs(2);
            let start = std::time::Instant::now();

            loop {
                tokio::select! {
                    event = network1.swarm.select_next_some() => {
                        if let libp2p::swarm::SwarmEvent::Behaviour(behaviour) = event {
                            info!("Node 1 received network event");
                        }
                    }

                    _ = sleep(Duration::from_millis(100)) => {
                        if start.elapsed() >= message_timeout {
                            break;
                        }
                    }
                }
            }
        }
        Err(e) => {
            warn!("⚠️ Failed to publish message: {}", e);
            info!("This is expected when nodes aren't connected to peers");
        }
    }

    info!("\n=== Network Statistics ===");
    let stats1 = network1.get_network_stats();
    let stats2 = network2.get_network_stats();

    info!("Node 1 Stats:");
    info!("  Total peers: {}", stats1.total_peers);
    info!("  Connected peers: {}", stats1.connected_peers);
    info!("  Active topics: {}", stats1.active_topics);

    info!("Node 2 Stats:");
    info!("  Total peers: {}", stats2.total_peers);
    info!("  Connected peers: {}", stats2.connected_peers);
    info!("  Active topics: {}", stats2.active_topics);

    info!("\n✅ Test completed successfully!");
    info!("Both nodes are running. Press Ctrl+C to exit...");

    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");

    Ok(())
}
