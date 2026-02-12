use ego_core::{Hash, KeyPair, ShardId};
use ego_p2p::{MessageBuilder, NetworkConfig, NetworkManager};
use futures::StreamExt;
use libp2p::Multiaddr;
use tokio::time::{Duration, sleep};
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let keypair1 = KeyPair::generate();
    let keypair2 = KeyPair::generate();

    let config1 = NetworkConfig::default()
        .with_listen_addresses(vec!["/ip4/0.0.0.0/tcp/9001".parse::<Multiaddr>()?])
        .with_max_peers(50)
        .with_mdns(true)
        .with_metrics(true, 9091)
        .with_backpressure_threshold(100)
        .with_publish_queue_size(1000);

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
        .with_mdns(true)
        .with_metrics(true, 9092)
        .with_backpressure_threshold(100)
        .with_publish_queue_size(1000);

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

    info!("\n=== Testing DHT Provider Records ===");

    let test_cid = b"QmTestCID12345".to_vec();
    let test_blob_id = b"blob123".to_vec();
    let chunk_index = 0u64;

    info!("Node 1: Starting to provide evidence for CID");
    if let Err(e) = network1.start_providing_evidence(test_cid.clone()).await {
        warn!("Failed to start providing evidence: {}", e);
    } else {
        info!("✅ Node 1 is now providing evidence");
    }

    info!("Node 2: Starting to provide DA chunk");
    if let Err(e) = network2
        .start_providing_da(test_blob_id.clone(), chunk_index)
        .await
    {
        warn!("Failed to start providing DA: {}", e);
    } else {
        info!("✅ Node 2 is now providing DA chunk");
    }

    sleep(Duration::from_secs(2)).await;

    info!("\n=== Testing Message Publishing with Queue ===");

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
                        match event {
                            libp2p::swarm::SwarmEvent::Behaviour(_) => {
                                info!("Node 1 received network event");
                            }
                            _ => {}
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

    info!("\n=== Testing Publish Queue (No Peers Scenario) ===");

    let isolated_message = MessageBuilder::block(
        Hash::random(),
        100,
        ShardId::new(0)?,
        b"Isolated block".to_vec(),
    );

    match network1
        .publish_message("ego/shard/0/headers", isolated_message)
        .await
    {
        Ok(_) => {
            info!("✅ Message published or queued");
        }
        Err(e) => {
            info!("Message handling: {}", e);
        }
    }

    info!("\n=== Network Metrics ===");

    let metrics1 = network1.metrics();
    let snapshot1 = metrics1.snapshot();

    info!("Node 1 Metrics:");
    info!("  Connected peers: {}", snapshot1.connected_peers);
    info!("  Messages sent: {}", snapshot1.messages_sent);
    info!("  Messages received: {}", snapshot1.messages_received);
    info!("  Bytes sent: {}", snapshot1.bytes_sent);
    info!("  Bytes received: {}", snapshot1.bytes_received);
    info!("  Messages dropped: {}", snapshot1.messages_dropped);
    info!("  Publish queue length: {}", snapshot1.publish_queue_length);
    info!("  DHT providers found: {}", snapshot1.dht_providers_found);
    info!("  DHT providers served: {}", snapshot1.dht_providers_served);

    let metrics2 = network2.metrics();
    let snapshot2 = metrics2.snapshot();

    info!("Node 2 Metrics:");
    info!("  Connected peers: {}", snapshot2.connected_peers);
    info!("  Messages sent: {}", snapshot2.messages_sent);
    info!("  Messages received: {}", snapshot2.messages_received);
    info!("  Bytes sent: {}", snapshot2.bytes_sent);
    info!("  Bytes received: {}", snapshot2.bytes_received);
    info!("  Messages dropped: {}", snapshot2.messages_dropped);
    info!("  Publish queue length: {}", snapshot2.publish_queue_length);
    info!("  DA requests sent: {}", snapshot2.da_requests_sent);
    info!(
        "  Evidence requests sent: {}",
        snapshot2.evidence_requests_sent
    );

    info!("\n=== Topic Peer Counts ===");
    let topic_counts1 = network1.get_topic_peer_counts();
    info!("Node 1 Topics:");
    for (topic, count) in topic_counts1.iter().take(5) {
        info!("  {}: {} peers", topic, count);
    }

    let topic_counts2 = network2.get_topic_peer_counts();
    info!("Node 2 Topics:");
    for (topic, count) in topic_counts2.iter().take(5) {
        info!("  {}: {} peers", topic, count);
    }

    info!("\n=== Network Statistics ===");
    let stats1 = network1.get_network_stats();
    let stats2 = network2.get_network_stats();

    info!("Node 1 Stats:");
    info!("  Total peers: {}", stats1.total_peers);
    info!("  Connected peers: {}", stats1.connected_peers);
    info!("  Gossipsub peers: {}", stats1.gossipsub_peers);
    info!("  Active topics: {}", stats1.active_topics);
    info!("  Messages sent: {}", stats1.total_messages_sent);
    info!("  Messages received: {}", stats1.total_messages_received);

    info!("Node 2 Stats:");
    info!("  Total peers: {}", stats2.total_peers);
    info!("  Connected peers: {}", stats2.connected_peers);
    info!("  Gossipsub peers: {}", stats2.gossipsub_peers);
    info!("  Active topics: {}", stats2.active_topics);
    info!("  Messages sent: {}", stats2.total_messages_sent);
    info!("  Messages received: {}", stats2.total_messages_received);

    info!("\n=== Testing Provider Discovery ===");

    info!("Node 2: Searching for evidence providers...");
    match network2.find_evidence_providers(test_cid.clone()).await {
        Ok(query_id) => {
            info!("✅ Evidence provider query initiated: {:?}", query_id);
        }
        Err(e) => {
            warn!("Failed to query evidence providers: {}", e);
        }
    }

    info!("Node 1: Searching for DA providers...");
    match network1
        .find_da_providers(test_blob_id.clone(), chunk_index)
        .await
    {
        Ok(query_id) => {
            info!("✅ DA provider query initiated: {:?}", query_id);
        }
        Err(e) => {
            warn!("Failed to query DA providers: {}", e);
        }
    }

    sleep(Duration::from_secs(2)).await;

    info!("\n=== Discovery Manager Stats ===");
    let discovery1 = network1.discovery_manager();
    info!("Node 1 Discovery:");
    info!(
        "  Total discovered peers: {}",
        discovery1.get_peer_count().await
    );
    info!(
        "  Provider keys count: {}",
        discovery1.get_provider_keys_count().await
    );
    info!(
        "  Total provider records: {}",
        discovery1.get_provider_count().await
    );

    let discovery2 = network2.discovery_manager();
    info!("Node 2 Discovery:");
    info!(
        "  Total discovered peers: {}",
        discovery2.get_peer_count().await
    );
    info!(
        "  Provider keys count: {}",
        discovery2.get_provider_keys_count().await
    );
    info!(
        "  Total provider records: {}",
        discovery2.get_provider_count().await
    );

    info!("\n=== Testing Peer Management Features ===");

    let peer_manager1 = network1.peer_manager();
    let peer_manager2 = network2.peer_manager();

    info!("Node 1 Peer Manager:");
    info!("  All peers: {}", peer_manager1.get_all_peers().len());
    info!(
        "  Connected peers: {}",
        peer_manager1.count_connected_peers()
    );
    info!(
        "  Trusted peers: {}",
        peer_manager1
            .get_connected_peers()
            .iter()
            .filter(|p| peer_manager1.is_peer_trusted(p))
            .count()
    );

    info!("Node 2 Peer Manager:");
    info!("  All peers: {}", peer_manager2.get_all_peers().len());
    info!(
        "  Connected peers: {}",
        peer_manager2.count_connected_peers()
    );
    info!(
        "  5G capable peers: {}",
        peer_manager2.get_5g_capable_peers().len()
    );

    if let Some(peer) = network1.connected_peers().first() {
        info!(
            "\nNode 1: Testing peer reputation adjustment for peer {}",
            peer
        );
        let initial_rep = peer_manager1.get_reputation(peer);
        info!("  Initial reputation: {:.2}", initial_rep);

        peer_manager1.adjust_reputation(peer, 0.1);
        let new_rep = peer_manager1.get_reputation(peer);
        info!("  After +0.1 adjustment: {:.2}", new_rep);
    }

    info!("\n=== Testing Message Queue Processing ===");
    info!("Processing any queued messages...");
    if let Err(e) = network1.process_publish_queues().await {
        warn!("Failed to process queues: {}", e);
    } else {
        info!("✅ Queue processing completed");
    }

    if let Err(e) = network2.process_publish_queues().await {
        warn!("Failed to process queues: {}", e);
    } else {
        info!("✅ Queue processing completed");
    }

    info!("\n=== Final Metrics Summary ===");
    let final_snapshot1 = network1.metrics().snapshot();
    let final_snapshot2 = network2.metrics().snapshot();

    info!("Combined Network Activity:");
    info!(
        "  Total messages sent: {}",
        final_snapshot1.messages_sent + final_snapshot2.messages_sent
    );
    info!(
        "  Total messages received: {}",
        final_snapshot1.messages_received + final_snapshot2.messages_received
    );
    info!(
        "  Total bytes sent: {}",
        final_snapshot1.bytes_sent + final_snapshot2.bytes_sent
    );
    info!(
        "  Total bytes received: {}",
        final_snapshot1.bytes_received + final_snapshot2.bytes_received
    );
    info!(
        "  Total providers found: {}",
        final_snapshot1.dht_providers_found + final_snapshot2.dht_providers_found
    );

    info!("Features tested:");
    info!("  ✓ Bootstrap connectivity");
    info!("  ✓ DHT provider records (Evidence & DA)");
    info!("  ✓ Message publishing with queue");
    info!("  ✓ Metrics collection and reporting");
    info!("  ✓ Provider discovery");
    info!("  ✓ Peer management & reputation");
    info!("  ✓ Topic peer counting");
    info!("\nBoth nodes are running. Press Ctrl+C to exit...");

    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");

    Ok(())
}
