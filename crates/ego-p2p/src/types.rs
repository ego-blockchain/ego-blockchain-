use ego_core::{Address, Hash, ShardId, Timestamp};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct NodeIdentity {
    pub peer_id: PeerId,
    pub address: Address,
    pub device_cert: Option<Vec<u8>>,
    pub attestation: Option<Vec<u8>>,
    pub capabilities: NodeCapabilities,
    pub created_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapabilities {
    pub roles: Vec<String>,
    pub shard_ids: Vec<u32>,
    pub supported_protocols: Vec<String>,
    pub max_bandwidth_bps: u64,
    pub storage_capacity_bytes: u64,
    pub is_5g_capable: bool,
    pub slice_ids: Vec<String>,
    pub geohash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2PMessage {
    Transaction(TransactionMessage),
    Block(BlockMessage),
    Proof(ProofMessage),
    Sync(SyncMessage),
    CrossShard(CrossShardMessage),
    Identify(IdentifyMessage),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionMessage {
    pub tx_hash: Hash,
    pub shard_id: ShardId,
    pub payload: Vec<u8>,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockMessage {
    pub block_hash: Hash,
    pub height: u64,
    pub shard_id: ShardId,
    pub payload: Vec<u8>,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMessage {
    pub proof_type: ProofType,
    pub prover: Address,
    pub payload: Vec<u8>,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofType {
    PoSt,
    PoC,
    PoRep,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncMessage {
    pub sync_type: SyncType,
    pub from_height: u64,
    pub to_height: u64,
    pub shard_id: ShardId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncType {
    Headers,
    Blocks,
    State,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossShardMessage {
    pub source_shard: ShardId,
    pub target_shard: ShardId,
    pub receipt_hash: Hash,
    pub payload: Vec<u8>,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentifyMessage {
    pub listen_addrs: Vec<String>,
    pub protocols: Vec<String>,
    pub agent_version: String,
    pub address: Address,
    pub capabilities: NodeCapabilities,
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub identity: Option<NodeIdentity>,
    pub reputation_score: f64,
    pub last_seen: Timestamp,
    pub connection_state: ConnectionState,
    pub bandwidth_stats: BandwidthStats,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Connected,
    Disconnected,
    Connecting,
    Failed,
}

#[derive(Debug, Clone, Default)]
pub struct BandwidthStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub last_updated: Option<Timestamp>,
}

#[derive(Debug, Clone)]
pub struct TopicInfo {
    pub name: String,
    pub shard_id: Option<ShardId>,
    pub subscriber_count: usize,
    pub message_count: u64,
    pub created_at: Timestamp,
}

#[derive(Debug)]
pub struct NetworkStats {
    pub total_peers: usize,
    pub connected_peers: usize,
    pub total_messages_sent: u64,
    pub total_messages_received: u64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub active_topics: usize,
    pub uptime_seconds: u64,
}

pub const PROTOCOL_VERSION: &str = "/ego/1.0.0";
pub const MAX_MESSAGE_SIZE: usize = 2 * 1024 * 1024;
pub const CONNECTION_TIMEOUT_SECS: u64 = 30;
pub const HEARTBEAT_INTERVAL_SECS: u64 = 10;
pub const PEER_DISCOVERY_INTERVAL_SECS: u64 = 60;
