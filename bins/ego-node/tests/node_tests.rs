use ego_node::{Node, NodeRole, ProofEvent};
use libp2p::gossipsub::{IdentTopic, TopicHash};

fn topic_hash(name: &str) -> TopicHash {
    IdentTopic::new(name).hash()
}

fn has_topic(node: &Node, name: &str) -> bool {
    node.swarm
        .behaviour()
        .gossipsub
        .topics()
        .any(|t| t == &topic_hash(name))
}

#[tokio::test(flavor = "current_thread")]
async fn test_node_initial_topics_for_roles_and_shards() {
    let node = Node::new(vec![NodeRole::Validator, NodeRole::Storage], vec![1])
        .await
        .expect("node");

    assert!(has_topic(&node, "ego/shard/1/tx"));
    assert!(has_topic(&node, "ego/shard/1/headers"));
    assert!(has_topic(&node, "ego/shard/1/receipts"));

    assert!(has_topic(&node, "ego/shard/1/proofs"));

    assert!(has_topic(&node, "ego/finality/commits"));
    assert!(has_topic(&node, "ego/storage"));
    assert!(has_topic(&node, "ego/storage/placement"));
    assert!(has_topic(&node, "ego/storage/repair"));
}

#[tokio::test(flavor = "current_thread")]
async fn test_witness_topic_after_geolocation() {
    let mut node = Node::new(vec![NodeRole::Witness], vec![])
        .await
        .expect("node");

    node.set_geolocation(1.23, 4.56, 7);
    let geohash = node.geohash.clone().expect("geohash");
    node.subscribe_to_topics().expect("subscribe");

    let topic = format!("ego/poc/h3/{}", geohash);
    assert!(has_topic(&node, &topic));
}

#[tokio::test(flavor = "current_thread")]
async fn test_is_5g_ready_flags() {
    let mut node = Node::new(vec![], vec![]).await.expect("node");

    assert!(!node.is_5g_ready());

    node.set_slice_configuration("slice-a".into());
    node.set_geolocation(0.0, 0.0, 7);
    node.set_bandwidth_capacity(50_000_000);
    assert!(!node.is_5g_ready());

    node.set_bandwidth_capacity(100_000_000);
    assert!(node.is_5g_ready());
}

#[tokio::test(flavor = "current_thread")]
async fn test_add_and_remove_role() {
    let mut node = Node::new(vec![], vec![]).await.expect("node");

    assert!(!node.has_role(NodeRole::Validator));
    node.add_role(NodeRole::Validator).expect("add role");
    assert!(node.has_role(NodeRole::Validator));

    node.remove_role(NodeRole::Validator);
    assert!(!node.has_role(NodeRole::Validator));
}

#[tokio::test(flavor = "current_thread")]
async fn test_emit_proof_event_ring_buffer() {
    let mut node = Node::new(vec![], vec![]).await.expect("node");

    for i in 0..105u64 {
        let pe = ProofEvent {
            event_type: "poc".to_string(),
            shard_id: None,
            piece_id: None,
            group_id: None,
            evidence_digest: vec![],
            timestamp: i,
            peer_id: node.peer_id.to_string(),
        };
        node.emit_proof_event(&pe);
    }

    assert_eq!(node.recent_proofs.len(), 100);
    assert_eq!(node.recent_proofs.last().unwrap().timestamp, 104);
}

#[tokio::test(flavor = "current_thread")]
async fn test_emit_poc_and_post_publish_and_record() {
    let mut node = Node::new(vec![NodeRole::Storage, NodeRole::Witness], vec![7])
        .await
        .expect("node");

    node.emit_poc_proof("h3_test_cell".into(), vec![1, 2, 3])
        .expect("emit poc");
    assert_eq!(node.recent_proofs.last().unwrap().event_type, "poc");

    node.emit_post_proof(7, 42, vec![9, 9, 9])
        .expect("emit post");
    assert_eq!(node.recent_proofs.last().unwrap().event_type, "post");
    assert_eq!(node.recent_proofs.last().unwrap().shard_id, Some(7));
    assert_eq!(node.recent_proofs.last().unwrap().piece_id, Some(42));
}

#[tokio::test(flavor = "current_thread")]
async fn test_resource_limits_config() {
    let mut node = Node::new(vec![], vec![]).await.expect("node");
    node.configure_resource_limits(10, 5);
    assert_eq!(node.max_peers_per_shard, 10);
    assert_eq!(node.max_topics_per_role, 5);
}

#[tokio::test(flavor = "current_thread")]
async fn test_capabilities_by_roles() {
    let node = Node::new(
        vec![
            NodeRole::Validator,
            NodeRole::Storage,
            NodeRole::Relay,
            NodeRole::Witness,
            NodeRole::Gateway,
            NodeRole::Seed,
            NodeRole::Indexer,
        ],
        vec![],
    )
    .await
    .expect("node");

    let caps = node.get_capabilities();
    assert!(caps.contains(&"block_validation"));
    assert!(caps.contains(&"proof_of_spacetime"));
    assert!(caps.contains(&"network_relay"));
    assert!(caps.contains(&"proof_of_coverage"));
    assert!(caps.contains(&"api_gateway"));
    assert!(caps.contains(&"peer_discovery"));
    assert!(caps.contains(&"data_indexing"));
}

#[tokio::test(flavor = "current_thread")]
async fn test_summary_contains_core_fields() {
    let mut node = Node::new(vec![NodeRole::Storage], vec![9])
        .await
        .expect("node");
    node.set_storage_capacity(1234);
    node.set_bandwidth_capacity(5678);
    node.set_geolocation(10.0, 20.0, 6);

    let s = node.get_summary();
    assert!(s.contains("Roles"));
    assert!(s.contains("Shards"));
    assert!(s.contains("Bandwidth: 5678 bps"));
    assert!(s.contains("Storage: 1234 bytes"));
    assert!(s.contains("Placements: 0"));
}

#[tokio::test(flavor = "current_thread")]
async fn test_convenience_constructors() {
    let node_val = Node::new_validator(vec![1, 2]).await.expect("validator");
    assert!(node_val.has_role(NodeRole::Validator));
    assert_eq!(node_val.shard_ids, vec![1, 2]);

    let node_stor = Node::new_storage_miner(10_000, "geo_1.0_2.0_p7".into())
        .await
        .expect("storage miner");
    assert!(node_stor.has_role(NodeRole::Storage));
    assert!(node_stor.has_role(NodeRole::Witness));
    assert_eq!(node_stor.storage_capacity_bytes, 10_000);
    assert_eq!(node_stor.geohash.as_deref(), Some("geo_1.0_2.0_p7"));

    let node_gw = Node::new_5g_edge_gateway("slice-123".into(), 1.0, 2.0, 200_000_000)
        .await
        .expect("5g gw");
    assert!(node_gw.has_role(NodeRole::Gateway));
    assert!(node_gw.has_role(NodeRole::Witness));
    assert!(node_gw.has_role(NodeRole::Relay));
    assert_eq!(node_gw.slice_id.as_deref(), Some("slice-123"));
    assert!(node_gw.geohash.is_some());
    assert!(node_gw.is_5g_ready());

    let node_full = Node::new_full_node(vec![3], 42_000).await.expect("full");
    assert!(node_full.has_role(NodeRole::Validator));
    assert!(node_full.has_role(NodeRole::Storage));
    assert!(node_full.has_role(NodeRole::Relay));
    assert_eq!(node_full.shard_ids, vec![3]);
    assert_eq!(node_full.storage_capacity_bytes, 42_000);
}

#[tokio::test(flavor = "current_thread")]
async fn test_dht_methods_do_not_error() {
    let mut node = Node::new(vec![NodeRole::Validator], vec![99])
        .await
        .expect("node");

    node.dht_put_record(b"key".to_vec(), b"value".to_vec(), Some(99))
        .expect("put namespaced");
    node.dht_put_record(b"k".to_vec(), b"v".to_vec(), None)
        .expect("put global");

    node.dht_get_record(b"key".to_vec(), Some(99))
        .expect("get namespaced");
    node.dht_get_record(b"k".to_vec(), None)
        .expect("get global");
}

#[tokio::test(flavor = "current_thread")]
async fn test_start_listening_records_requested_addr() {
    let mut node = Node::new(vec![], vec![]).await.expect("node");

    node.start_listening(0).await.expect("listen");
    assert!(!node.listen_addresses.is_empty());

    let first = node.listen_addresses[0].to_string();
    assert!(first.starts_with("/ip4/0.0.0.0/tcp/"));
}
