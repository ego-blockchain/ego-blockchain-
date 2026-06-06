pub mod bandwidth_sharing;
pub mod consensus_integration;
pub mod mempool;
pub mod data_optimizer;
pub mod engine;
pub mod keystore;
pub mod network_manager;
pub mod node;
pub mod rpc;
pub mod store;
pub mod supervisor;

pub use bandwidth_sharing::*;
pub use data_optimizer::*;
pub use ego_core::*;
pub use keystore::*;
pub use network_manager::*;
pub use node::*;

use libp2p::{autonat, dcutr, gossipsub, identify, kad, mdns, ping, relay, swarm::NetworkBehaviour};

#[derive(NetworkBehaviour)]
pub struct NodeBehaviour {
    pub relay_client: relay::client::Behaviour,
    pub dcutr: dcutr::Behaviour,
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
    pub autonat: autonat::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub ping: ping::Behaviour,
}

/// Concrete swarm event type for ego-node — avoids generic T in event handlers.
pub type EgoSwarmEvent = libp2p::swarm::SwarmEvent<
    <NodeBehaviour as libp2p::swarm::NetworkBehaviour>::ToSwarm,
>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ReplicaRole {
    Primary,
    ReplicaA,
    ReplicaB,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Placement {
    pub cid: String,
    pub piece_id: u32,
    pub group_id: [u8; 16],
    pub members: [String; 3],
    pub role: ReplicaRole,
    pub lease_expiry: u64,
    pub audit_count: u32,
    pub last_audit: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProofEvent {
    pub event_type: String,
    pub shard_id: Option<u32>,
    pub piece_id: Option<u32>,
    pub group_id: Option<[u8; 16]>,
    pub evidence_digest: Vec<u8>,
    pub timestamp: u64,
    pub peer_id: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ShardConfig {
    pub shard_id: u32,
    pub committee_size: u32,
    pub replication_factor: u8,
}
