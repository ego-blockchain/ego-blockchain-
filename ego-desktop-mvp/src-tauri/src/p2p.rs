//! libp2p P2P engine for Ego Desktop.
//! - QUIC + TCP transports
//! - Circuit Relay v2  (cross-NAT fallback)
//! - DCUtR hole punching (upgrades relay → direct)
//! - AutoNAT (detects NAT type)
//! - Identify (address exchange)
//!
//! Kademlia removed — IPFS bootstrap nodes reject non-IPFS peers.

use crate::commands::messenger::{load_contacts, save_contacts, Contact};
use crate::ledger::{base_data_dir, load_chain, save_chain, LedgerBlock, LedgerTx};
use chrono::Utc;
use futures::StreamExt;
use futures::{AsyncReadExt, AsyncWriteExt};
use libp2p::{
    autonat, dcutr, gossipsub, identify, kad, noise, ping, relay,
    request_response::{self, OutboundRequestId, ProtocolSupport},
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, StreamProtocol, SwarmBuilder,
};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{collections::HashMap, io, sync::{Mutex, OnceLock}, time::Duration};
use tauri::Manager;
use tokio::sync::{mpsc, oneshot};

/// Gossip publish channel: anything outside the swarm loop calls `publish_gossip()`
/// which queues a (topic, bytes) pair. The swarm loop drains it and calls
/// `swarm.behaviour_mut().gossipsub.publish(...)`.
static GOSSIP_TX: OnceLock<mpsc::UnboundedSender<(String, Vec<u8>)>> = OnceLock::new();

/// DHT command channel: send put/get requests into the swarm loop.
pub static DHT_CMD_TX: OnceLock<mpsc::UnboundedSender<DhtCommand>> = OnceLock::new();

/// Pending mailbox appends: addr → list of msg_hash strings waiting to be merged
/// into the DHT `ego-mailbox:{addr}` list record.
static PENDING_MAILBOX_APPENDS: OnceLock<Mutex<HashMap<String, Vec<String>>>> = OnceLock::new();
fn pending_appends() -> &'static Mutex<HashMap<String, Vec<String>>> {
    PENDING_MAILBOX_APPENDS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Debug)]
pub enum DhtCommand {
    PutPeer { key: String, value: Vec<u8> },
    GetPeers { key: String },
}

pub const P2P_PORT: u16 = 47393;

/// Bootstrap / relay nodes. The first entry is the official Ego seed node.
/// Anyone can run an additional relay — add their multiaddr here in future releases.
/// The network remains functional as long as at least one of these is reachable.
pub const RELAY_NODES: &[&str] = &[
    // Official Ego seed node
    "/dns4/EgoRelay.egoblockchain.com/tcp/4001/p2p/12D3KooWLBwV9rP8iT1iTDrjWRLs2wQQCw9AhVzFbPfRu9iE8Uvz",
    // Community relay 1 — placeholder, replace with real peer when available
    // "/dns4/relay2.egoblockchain.com/tcp/4001/p2p/12D3KooW...",
    // Community relay 2 — placeholder
    // "/dns4/relay3.egoblockchain.com/tcp/4001/p2p/12D3KooW...",
];

/// Oracle RPC endpoint for chain sync.
pub const ORACLE_RPC: &str = "https://rpc.egoblockchain.com";
// ─────────────────────────────────────────────────────────────────────────────
// SINGLE SOURCE OF TRUTH FOR RELAY CIRCUIT STATE
//
// This flag is set ONLY from inside the swarm event loop (handle_event) via
// inject_circuit(). It is NEVER set from a spawned task.
//
// wait_for_public_endpoint() polls this flag. When true it calls
// get_public_endpoint() which reads from external_addrs via GetEndpoint cmd.
// external_addrs is also only mutated from inside the swarm loop.
//
// This means all three (RELAY_CIRCUIT_READY, external_addrs, AppState endpoint)
// are always consistent with each other.
// ─────────────────────────────────────────────────────────────────────────────
static RELAY_CIRCUIT_READY: AtomicBool = AtomicBool::new(false);

/// Set to true when AutoNAT confirms a public IP — this node then acts as a
/// relay server for peers behind NAT (same role as the central EgoRelay server).
static IS_RELAY_SERVER: AtomicBool = AtomicBool::new(false);

pub fn relay_mode_active() -> bool { IS_RELAY_SERVER.load(Ordering::Relaxed) }

/// Pending BFT votes: block_hash → list of voter addresses that have voted.
/// Once >2/3 of KNOWN_VALIDATORS have voted for a hash, the block is finalized.
static PENDING_VOTES: std::sync::OnceLock<std::sync::Mutex<HashMap<String, Vec<String>>>> =
    std::sync::OnceLock::new();

fn pending_votes() -> std::sync::MutexGuard<'static, HashMap<String, Vec<String>>> {
    PENDING_VOTES
        .get_or_init(|| std::sync::Mutex::new(HashMap::new()))
        .lock()
        .unwrap()
}

/// Known active validators (Ego addresses). Populated from PeerAnnounce and BlockVote messages.
/// Used to compute the 2/3 quorum threshold.
static KNOWN_VALIDATORS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
    std::sync::OnceLock::new();

fn known_validators() -> std::sync::MutexGuard<'static, std::collections::HashSet<String>> {
    KNOWN_VALIDATORS
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
        .lock()
        .unwrap()
}

/// Add a validator address to the known set (from PeerAnnounce or vote messages).
pub fn register_known_validator(address: &str) {
    if !address.is_empty() {
        known_validators().insert(address.to_string());
    }
}

/// Compute the minimum votes needed for BFT finality.
/// Bootstrap mode: if < 3 validators known, 1 vote is enough (prevents cold-start deadlock).
fn bft_threshold() -> usize {
    let n = known_validators().len();
    if n < 3 { 1 } else { (n * 2 / 3) + 1 }
}

/// Peer-relay nodes discovered via DataManifest (addr → endpoint).
/// Lets us dial through community relay nodes, not just the central server.
static PEER_RELAY_NODES: std::sync::OnceLock<std::sync::Mutex<HashMap<String, String>>> =
    std::sync::OnceLock::new();

/// Keys of DHT inbox messages already dispatched this session.
/// Prevents re-notifying the user every 30 s when the same DHT record is polled.
static DHT_SEEN_MSGS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
    std::sync::OnceLock::new();

fn dht_seen() -> std::sync::MutexGuard<'static, std::collections::HashSet<String>> {
    DHT_SEEN_MSGS
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
        .lock()
        .unwrap()
}


fn peer_relay_nodes() -> std::sync::MutexGuard<'static, HashMap<String, String>> {
    PEER_RELAY_NODES
        .get_or_init(|| std::sync::Mutex::new(HashMap::new()))
        .lock()
        .unwrap()
}

pub fn get_discovered_relay_nodes() -> Vec<String> {
    peer_relay_nodes().values().cloned().collect()
}

// ── Wire protocol ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum P2PMessage {
    ContactRequest {
        from_addr:       String,
        from_name:       String,
        from_ed25519:    String,
        from_kyber:      String,
        from_shared_key: String,
        from_endpoint:   String,
    },
    ContactResponse {
        from_addr:     String,
        from_name:     String,
        from_ed25519:  String,
        from_kyber:    String,
        approved:      bool,
        shared_key:    String,
        #[serde(default)]
        from_endpoint: String,
    },
    PeerAnnounce {
        address:   String,
        name:      String,
        endpoint:  String,
        #[serde(default)]
        endpoints: Vec<String>,
        #[serde(default)]
        city:    Option<String>,
        #[serde(default)]
        country: Option<String>,
    },
    ChatMessage {
        bundle: String,
    },
    TxBroadcast {
        tx:    LedgerTx,
        block: LedgerBlock,
    },
    ChainSyncRequest {
        requester_endpoint: String,
    },
    ChainSyncResponse {
        blocks:       Vec<LedgerBlock>,
        transactions: Vec<LedgerTx>,
    },
    PeerListRequest {
        requester_endpoint: String,
    },
    PeerListResponse {
        peers: Vec<PeerEntry>,
    },
    FileRequest {
        cid: String,
        requester_addr: String,
        requester_endpoint: String,
    },
    FileData {
        cid: String,
        enc_data_b64: String,
        file_name: String,
        key_nonce_hex: String,   // ← add this field
    },
    FileChunk {
        cid:          String,
        chunk_index:  u32,
        total_chunks: u32,
        data_b64:     String,
        file_name:    String,
    },
    FileChunkComplete {
        cid:       String,
        file_name: String,
        enc_data_b64: String,
    },
    /// Announce what data this node holds and how much space it has.
    /// Sent periodically so peers can discover content locations and relay nodes.
    DataManifest {
        from_addr:    String,
        cids:         Vec<String>,
        available_gb: f64,
        is_relay:     bool,     // true = this node is also a relay server
        endpoint:     String,
    },
    /// Ask a peer to replicate (pin) one of our files on their node.
    PinRequest {
        cid:           String,
        from_addr:     String,
        from_endpoint: String,
    },
    /// Response to a PinRequest.
    PinAck {
        cid:      String,
        accepted: bool,
        reason:   String,
    },
    /// A miner proposes a new block for BFT voting.
    BlockProposal {
        block:        LedgerBlock,
        transactions: Vec<LedgerTx>,
        proposer:     String,
        /// Ed25519 signature over block.hash bytes
        signature:    String,
    },
    /// A validator casts a signed vote on a block proposal.
    BlockVote {
        block_hash: String,
        height:     u64,
        voter:      String,
        /// Ed25519 signature over "{block_hash}:{height}:{voter}"
        signature:  String,
        timestamp:  i64,
    },
    /// A block that has collected >2/3 validator votes — safe to commit.
    BlockFinalized {
        block:        LedgerBlock,
        transactions: Vec<LedgerTx>,
        /// The votes that finalized this block (for audit)
        votes:        Vec<serde_json::Value>,
    },
    /// Broadcast every 60s: "I hold these shards with this role."
    ShardAnnounce {
        from_addr:          String,
        from_endpoint:      String,
        held_shards:        Vec<u32>,
        uptime_secs:        u64,
        network_node_count: u32,
        shard_count:        u32,
    },
    /// Slave promotes itself to master after detecting master is offline.
    MasterPromotion {
        shard_id:      u32,
        new_master:    String,
        new_endpoint:  String,
        former_master: String,
        timestamp:     i64,
    },
    /// Slave asks master to send blocks for a specific shard starting from `from_height`.
    ShardDataRequest {
        shard_id:             u32,
        from_height:          u64,
        requester_address:    String,
        requester_endpoint:   String,
    },
    /// Master replies with blocks + txs for the requested shard.
    ShardDataResponse {
        shard_id:     u32,
        blocks:       Vec<LedgerBlock>,
        transactions: Vec<LedgerTx>,
    },
    /// Route a block-height query to the correct shard holder (Phase 3).
    ShardBlockQuery {
        block_height:       u64,
        requester_address:  String,
        requester_endpoint: String,
    },
    /// Response to ShardBlockQuery.
    ShardBlockResponse {
        block_height: u64,
        blocks:       Vec<LedgerBlock>,
        transactions: Vec<LedgerTx>,
    },
    /// Broadcast when a shard has fewer than REPLICATION_FACTOR live holders.
    ShardVacancyNotice {
        shard_id:        u32,
        current_holders: u32,
    },
    /// A node volunteers to become a slave for an under-replicated shard.
    ShardVolunteer {
        shard_id:           u32,
        volunteer_address:  String,
        volunteer_endpoint: String,
    },
    // ── IPFS-style block transfer ──────────────────────────────────────────────
    /// Request a file manifest by its CID (`egomfd1…`).
    ManifestRequest {
        manifest_cid:       String,
        requester_addr:     String,
        requester_endpoint: String,
    },
    /// Response carrying the full manifest JSON.
    ManifestData {
        manifest_cid:  String,
        manifest_json: String,   // serde_json of blocks::FileManifest
        key_hex64:     String,   // 32-byte AES key as 64-char hex
        file_name:     String,
        from_addr:     String,
    },
    /// Request one 256 KB encrypted block by its CID (`egoblk1…`).
    BlockRequest {
        block_cid:          String,
        manifest_cid:       String,   // context for progress tracking
        requester_addr:     String,
        requester_endpoint: String,
    },
    /// Response carrying one encrypted block.
    BlockData {
        block_cid:    String,
        manifest_cid: String,
        enc_b64:      String,   // base64 of the encrypted 256 KB chunk
        from_addr:    String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEntry {
    pub address:   String,
    pub endpoint:  String,
    pub last_seen: i64,
    #[serde(default)]
    pub city:    Option<String>,
    #[serde(default)]
    pub country: Option<String>,
}

// ── Request-response codec (4-byte length prefix + JSON) ─────────────────────

#[derive(Debug, Clone, Default)]
struct EgoCodec;
impl request_response::Codec for EgoCodec {
    type Protocol = StreamProtocol;
    type Request  = P2PMessage;
    type Response = ();

    fn read_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _: &'life1 Self::Protocol,
        io: &'life2 mut T,
    ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = io::Result<Self::Request>> + ::core::marker::Send + 'async_trait>>
    where
        T: futures::io::AsyncRead + Unpin + Send + 'async_trait,
        'life0: 'async_trait, 'life1: 'async_trait, 'life2: 'async_trait, Self: 'async_trait,
    {
        Box::pin(async move {
            let mut len_buf = [0u8; 4];
            AsyncReadExt::read_exact(io, &mut len_buf).await?;
            let len = u32::from_be_bytes(len_buf) as usize;
            if len > 512 * 1024 * 1024 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "message too large"));
            }
            let mut buf = vec![0u8; len];
            AsyncReadExt::read_exact(io, &mut buf).await?;
            serde_json::from_slice(&buf)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        })
    }

    fn read_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _: &'life1 Self::Protocol,
        io: &'life2 mut T,
    ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = io::Result<Self::Response>> + ::core::marker::Send + 'async_trait>>
    where
        T: futures::io::AsyncRead + Unpin + Send + 'async_trait,
        'life0: 'async_trait, 'life1: 'async_trait, 'life2: 'async_trait, Self: 'async_trait,
    {
        Box::pin(async move {
            // Read ack byte — ignore errors (old peers send nothing)
            let mut buf = [0u8; 1];
            let _ = AsyncReadExt::read_exact(io, &mut buf).await;
            Ok(())
        })
    }

    fn write_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _: &'life1 Self::Protocol,
        io: &'life2 mut T,
        req: Self::Request,
    ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = io::Result<()>> + ::core::marker::Send + 'async_trait>>
    where
        T: futures::io::AsyncWrite + Unpin + Send + 'async_trait,
        'life0: 'async_trait, 'life1: 'async_trait, 'life2: 'async_trait, Self: 'async_trait,
    {
        Box::pin(async move {
            let data = serde_json::to_vec(&req)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            AsyncWriteExt::write_all(io, &(data.len() as u32).to_be_bytes()).await?;
            AsyncWriteExt::write_all(io, &data).await?;
            AsyncWriteExt::flush(io).await
        })
    }

    fn write_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _: &'life1 Self::Protocol,
        io: &'life2 mut T,
        _: Self::Response,
    ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = io::Result<()>> + ::core::marker::Send + 'async_trait>>
    where
        T: futures::io::AsyncWrite + Unpin + Send + 'async_trait,
        'life0: 'async_trait, 'life1: 'async_trait, 'life2: 'async_trait, Self: 'async_trait,
    {
        Box::pin(async move {
            // Write ack byte — ignore errors (remote may have already closed)
            let _ = AsyncWriteExt::write_all(io, &[0u8]).await;
            let _ = AsyncWriteExt::flush(io).await;
            Ok(())
        })
    }
}

// ── Network behaviour ─────────────────────────────────────────────────────────

#[derive(NetworkBehaviour)]
struct EgoBehaviour {
    relay_client:     relay::client::Behaviour,
    /// Server-side relay — active on all nodes but only useful when AutoNAT
    /// reports Public.  Peers that discover us via Identify will see we support
    /// the relay server protocol and can use us as a hop.
    relay_server:     relay::Behaviour,
    dcutr:            dcutr::Behaviour,
    identify:         identify::Behaviour,
    request_response: request_response::Behaviour<EgoCodec>,
    autonat:          autonat::Behaviour,
    ping:             ping::Behaviour,
    /// Gossipsub — pub/sub mesh for chain tx/block propagation.
    /// Peers receive blocks and transactions even without direct contacts.
    gossipsub:        gossipsub::Behaviour,
    /// Kademlia DHT — decentralised peer discovery without the central relay.
    kad:              kad::Behaviour<kad::store::MemoryStore>,
}

// ── Swarm command channel ─────────────────────────────────────────────────────

pub enum SwarmCmd {
    Send {
        peer_addr: Multiaddr,
        msg:       P2PMessage,
        reply:     oneshot::Sender<Result<(), String>>,
    },
    GetEndpoint {
        reply: oneshot::Sender<String>,
    },
    /// Fire-and-forget gossipsub publish. Routed from GOSSIP_TX into the swarm loop.
    GossipPublish {
        topic: String,
        data:  Vec<u8>,
    },
}

static SWARM_TX: OnceLock<mpsc::Sender<SwarmCmd>> = OnceLock::new();

// ── Public API ────────────────────────────────────────────────────────────────

pub async fn send_message(endpoint: &str, msg: &P2PMessage) -> Result<(), String> {
    let tx = SWARM_TX.get().ok_or_else(|| "P2P not started".to_string())?;
    let peer_addr: Multiaddr = endpoint
        .parse()
        .map_err(|e| format!("Invalid multiaddr '{}': {}", endpoint, e))?;
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(SwarmCmd::Send { peer_addr, msg: msg.clone(), reply: reply_tx })
        .await
        .map_err(|_| "Swarm channel closed".to_string())?;
    reply_rx.await.map_err(|_| "Swarm dropped reply".to_string())?
}

/// Try endpoints in order: LAN first, public IP second, relay circuit last.
/// Returns Ok on first success, Err if all fail.
pub async fn send_message_any(endpoints: &[String], msg: &P2PMessage) -> Result<(), String> {
    if endpoints.is_empty() {
        return Err("No endpoints available".to_string());
    }
    // Sort: LAN (0) → public IP (1) → relay circuit (2)
    let mut sorted = endpoints.to_vec();
    sorted.sort_by_key(|ep| {
        if ep.contains("/ip4/192.168.") || ep.contains("/ip4/10.") || ep.contains("/ip4/172.") {
            0usize
        } else if ep.contains("/p2p-circuit") {
            2
        } else {
            1
        }
    });
    let mut last_err = String::new();
    for ep in &sorted {
        match send_message(ep, msg).await {
            Ok(_)  => {
                eprintln!("[P2P] Connected via {}", ep);
                return Ok(());
            }
            Err(e) => {
                eprintln!("[P2P] Failed {}: {}", ep, e);
                last_err = e;
            }
        }
    }
    Err(last_err)
}

pub async fn get_public_endpoint() -> String {
    let Some(tx) = SWARM_TX.get() else { return String::new(); };
    let (reply_tx, reply_rx) = oneshot::channel();
    if tx.send(SwarmCmd::GetEndpoint { reply: reply_tx }).await.is_err() {
        return String::new();
    }
    reply_rx.await.unwrap_or_default()
}

/// Wait up to `timeout_secs` for a confirmed relay circuit endpoint.
///
/// RELAY_CIRCUIT_READY is set only from inside the swarm loop when either:
///   (a) NewListenAddr fires with /p2p-circuit, OR
///   (b) ReservationReqAccepted fires and we synthesise the circuit address.
///
/// Both paths update external_addrs before setting the flag, so
/// get_public_endpoint() is guaranteed to return the circuit address
/// the instant the flag is true.
pub async fn wait_for_public_endpoint(timeout_secs: u64) -> String {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if RELAY_CIRCUIT_READY.load(Ordering::Relaxed) {
            let ep = get_public_endpoint().await;
            if ep.contains("/p2p-circuit") {
                return ep;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return get_public_endpoint().await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

pub fn get_local_ip() -> String {
    if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
        let _ = sock.connect("8.8.8.8:80");
        if let Ok(addr) = sock.local_addr() {
            let ip = addr.ip().to_string();
            if ip != "0.0.0.0" { return ip; }
        }
    }
    "127.0.0.1".to_string()
}

pub fn get_local_endpoint() -> String {
    format!("/ip4/{}/tcp/{}", get_local_ip(), P2P_PORT)
}

// No-ops kept for API compatibility
pub async fn start_udp_discovery(_app: tauri::AppHandle) {}
pub async fn broadcast_udp_announce() {}
pub async fn gossip_peer_list() {}

/// Enqueue a gossipsub publish to the swarm event loop.
/// Fire-and-forget; silently drops if P2P hasn't started yet.
pub async fn publish_gossip(topic: &str, data: Vec<u8>) {
    if let Some(tx) = GOSSIP_TX.get() {
        let _ = tx.send((topic.to_string(), data));
    }
}

pub async fn broadcast_tx(tx: LedgerTx, block: LedgerBlock) {
    // Legacy TxBroadcast for backward compat
    let msg = P2PMessage::TxBroadcast { tx: tx.clone(), block: block.clone() };

    // ── Gossipsub: reaches ALL subscribers, not just known contacts ───────────
    // This is the primary true-P2P broadcast path.
    if let Ok(data) = serde_json::to_vec(&msg) {
        publish_gossip("ego-txs-v1", data).await;
    }

    // BFT proposal: other validators vote before committing
    let my_addr = crate::ledger::Ledger::load().address;
    let proposal_data = block.hash.clone();
    let signature = bft_sign(&proposal_data).unwrap_or_default();
    let proposal = P2PMessage::BlockProposal {
        block:        block.clone(),
        transactions: vec![tx.clone()],
        proposer:     my_addr.clone(),
        signature,
    };
    if let Ok(data) = serde_json::to_vec(&proposal) {
        publish_gossip("ego-proposals-v1", data).await;
    }

    // Register ourselves as a known validator
    register_known_validator(&my_addr);

    // ── Direct P2P to ALL known peers (contacts + peer cache) ────────────────
    // Gossipsub needs the mesh to be formed first (heartbeat latency).
    // Direct request-response is immediate and works even before the mesh
    // is fully established. We deduplicate by endpoint so we don't double-send.
    let mut seen_eps: std::collections::HashSet<String> = Default::default();
    let mut endpoints: Vec<String> = Vec::new();

    let contacts = load_contacts();
    for c in contacts.iter().filter(|c| c.status == "approved" && !c.endpoint.is_empty()) {
        if seen_eps.insert(c.endpoint.clone()) {
            endpoints.push(c.endpoint.clone());
        }
        for ep in &c.all_endpoints {
            if seen_eps.insert(ep.clone()) { endpoints.push(ep.clone()); }
        }
    }
    for p in load_peer_cache().iter().filter(|p| !p.endpoint.is_empty()) {
        if seen_eps.insert(p.endpoint.clone()) {
            endpoints.push(p.endpoint.clone());
        }
    }

    for endpoint in endpoints {
        let msg_clone = msg.clone();
        tokio::spawn(async move {
            if let Err(e) = send_message(&endpoint, &msg_clone).await {
                if !e.contains("none of the requested protocols") {
                    eprintln!("[P2P] broadcast_tx direct to {}: {}", endpoint, e);
                }
            }
        });
    }
}

pub async fn sync_chain_from_peers() {
    let my_endpoint = get_public_endpoint().await;
    let msg = P2PMessage::ChainSyncRequest { requester_endpoint: my_endpoint };
    for contact in load_contacts().iter().filter(|c| c.status == "approved" && !c.endpoint.is_empty()) {
        let endpoint  = contact.endpoint.clone();
        let all_eps   = contact.all_endpoints.clone();
        let msg_clone = msg.clone();
        tokio::spawn(async move {
            let mut eps = if all_eps.is_empty() { vec![endpoint.clone()] } else { all_eps };
            if !eps.contains(&endpoint) { eps.push(endpoint.clone()); }
            if let Err(e) = send_message_any(&eps, &msg_clone).await {
                if !e.contains("none of the requested protocols") {
                    eprintln!("[P2P] sync request to {}: {}", endpoint, e);
                }
            }
        });
    }
}

pub async fn broadcast_peer_announce(app: &tauri::AppHandle) {
    let address = crate::ledger::Ledger::load().address.clone();
    if address.is_empty() { return; }
    let my_endpoint = get_public_endpoint().await;
    let registry  = crate::ledger::load_registry();
    let active_id = crate::ledger::get_active_wallet_id();
    let name = registry.wallets.iter()
        .find(|w| w.id == active_id)
        .map(|w| w.name.clone())
        .unwrap_or_else(|| "Ego Node".to_string());

    // Include our own geolocation so remote peers can display us on their map
    let (my_city, my_country) = {
        let state = app.state::<crate::app::AppState>();
        let cache = state.cache.lock().unwrap();
        if let Some(ref cs) = cache.coverage_status {
            if let Some(ref loc) = cs.location {
                (loc.city.clone(), loc.country.clone())
            } else { (None, None) }
        } else { (None, None) }
    };

    {
        let state = app.state::<crate::app::AppState>();
        state.upsert_peer(crate::app::PeerInfo {
            address:   address.clone(),
            name:      name.clone(),
            endpoint:  my_endpoint.clone(),
            last_seen: Utc::now().timestamp(),
            city:      my_city.clone(),
            country:   my_country.clone(),
        });
    }
    // Collect all local IPs as additional endpoints so peers can try direct connection
    let local_peer_id = {
        let ep = my_endpoint.clone();
        ep.split("/p2p/").last().unwrap_or("").to_string()
    };
    let mut all_endpoints = vec![my_endpoint.clone()];
    if let Ok(ifaces) = local_ip_address::list_afinet_netifas() {
        for (_name, ip) in ifaces {
            if ip.is_ipv4() && !ip.is_loopback() {
                let ep = format!("/ip4/{}/tcp/{}/p2p/{}", ip, P2P_PORT, local_peer_id);
                if !all_endpoints.contains(&ep) {
                    all_endpoints.push(ep);
                }
            }
        }
    }
    let msg = P2PMessage::PeerAnnounce {
        address, name,
        endpoint:  my_endpoint,
        endpoints: all_endpoints,
        city:      my_city,
        country:   my_country,
    };

    // Publish over gossipsub so that peers whose stored endpoint for us is stale
    // (e.g. after a WiFi/LAN change) still learn our new relay circuit address once
    // the gossipsub mesh reforms through the relay.
    if let Ok(data) = serde_json::to_vec(&msg) {
        publish_gossip("ego-peers-v1", data).await;
    }

    // Also send directly to approved contacts — faster delivery when endpoints are fresh.
    for contact in load_contacts().iter().filter(|c| c.status == "approved" && !c.endpoint.is_empty()) {
        let endpoint  = contact.endpoint.clone();
        let msg_clone = msg.clone();
        let all_eps = contact.all_endpoints.clone();
        tokio::spawn(async move {
            let mut eps = if all_eps.is_empty() { vec![endpoint.clone()] } else { all_eps };
            if !eps.contains(&endpoint) { eps.push(endpoint.clone()); }
            if let Err(e) = send_message_any(&eps, &msg_clone).await {
                if !e.contains("none of the requested protocols") {
                    eprintln!("[P2P] peer announce to {}: {}", endpoint, e);
                }
            }
        });
    }
}

/// Broadcast a DataManifest to all approved contacts so they know:
///  - which CIDs we're storing (for content routing)
///  - how much free space we have (so they can pin files to us)
///  - whether we're a relay server (so they can use us as a hop)
pub async fn broadcast_data_manifest() {
    let ledger = crate::ledger::Ledger::load();
    if ledger.address.is_empty() { return; }
    let cids: Vec<String> = ledger.stored_files.iter()
        .filter(|f| !f.local_path.is_empty() && !f.local_path.starts_with("sender:"))
        .map(|f| f.cid.clone())
        .collect();
    let used: u64 = ledger.stored_files.iter().map(|f| f.encrypted_size).sum();
    let capacity  = ledger.storage_allocated_bytes;
    let avail_gb  = if capacity > used {
        (capacity - used) as f64 / 1_000_000_000.0
    } else { 0.0 };
    let endpoint = get_public_endpoint().await;
    let msg = P2PMessage::DataManifest {
        from_addr:    ledger.address,
        cids,
        available_gb: avail_gb,
        is_relay:     IS_RELAY_SERVER.load(Ordering::Relaxed),
        endpoint,
    };
    // Publish to gossipsub so ALL shard subscribers learn about our CIDs
    // (not just contacts we dial directly).
    if let Ok(data) = serde_json::to_vec(&msg) {
        publish_gossip("ego-shards-v1", data).await;
    }

    // Register each CID in the relay's shard CID registry (fire-and-forget).
    // This lets any node discover file holders without having them as a contact.
    {
        let ledger2  = crate::ledger::Ledger::load();
        let endpoint = get_public_endpoint().await;
        let addr     = ledger2.address.clone();
        let cids2: Vec<String> = ledger2.stored_files.iter()
            .filter(|f| !f.local_path.is_empty() && !f.local_path.starts_with("sender:"))
            .map(|f| f.cid.clone())
            .collect();
        if !addr.is_empty() && !endpoint.is_empty() {
            tokio::spawn(async move {
                for cid in &cids2 {
                    register_cid_on_relay(cid, &addr, &endpoint).await;
                }
            });
        }
    }

    for contact in load_contacts().iter().filter(|c| c.status == "approved" && !c.endpoint.is_empty()) {
        let ep      = contact.endpoint.clone();
        let all_eps = contact.all_endpoints.clone();
        let msg2    = msg.clone();
        tokio::spawn(async move {
            let mut eps = if all_eps.is_empty() { vec![ep.clone()] } else { all_eps };
            if !eps.contains(&ep) { eps.push(ep); }
            if let Err(e) = send_message_any(&eps, &msg2).await {
                if !e.contains("none of the requested protocols") {
                    eprintln!("[P2P] DataManifest failed: {}", e);
                }
            }
        });
    }
}

/// Returns Ego addresses of recently-seen peers from the in-memory peer cache.
pub fn get_known_peers() -> Vec<String> {
    load_peer_cache()
        .into_iter()
        .map(|p| p.address)
        .filter(|a| !a.is_empty())
        .collect()
}

pub async fn broadcast_shard_announce() {
    let ledger = crate::ledger::Ledger::load();
    let my_addr = ledger.address.clone();
    if my_addr.is_empty() { return; }
    let endpoint = get_public_endpoint().await;
    let map = crate::sharding::load_shard_map();
    let all_nodes: Vec<String> = map.assignments.iter()
        .map(|a| a.node_address.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter().collect();
    let held: Vec<u32> = crate::sharding::my_shards(&my_addr, &map, &all_nodes)
        .into_iter().map(|(id, _)| id).collect();
    let msg = crate::p2p::P2PMessage::ShardAnnounce {
        from_addr:          my_addr,
        from_endpoint:      endpoint,
        held_shards:        if held.is_empty() { vec![0] } else { held },
        uptime_secs:        0,
        network_node_count: map.network_node_count.max(1),
        shard_count:        map.shard_count.max(1),
    };
    if let Ok(data) = serde_json::to_vec(&msg) {
        publish_gossip("ego-shards-v1", data).await;
    }
}

pub async fn broadcast_master_promotion(shard_id: u32, new_master: &str, new_endpoint: &str, former_master: &str) {
    let msg = crate::p2p::P2PMessage::MasterPromotion {
        shard_id,
        new_master:    new_master.to_string(),
        new_endpoint:  new_endpoint.to_string(),
        former_master: former_master.to_string(),
        timestamp:     chrono::Utc::now().timestamp(),
    };
    if let Ok(data) = serde_json::to_vec(&msg) {
        publish_gossip("ego-shards-v1", data).await;
    }
}

/// Phase 2: master pushes its shard blocks to known slaves so they stay in sync.
/// Only runs when shard_count > 1 (Phase 2+). No-op in Phase 1.
pub async fn push_shard_data_to_slaves() {
    let map = crate::sharding::load_shard_map();
    if map.shard_count <= 1 { return; }

    let my_addr = crate::ledger::Ledger::load().address;
    if my_addr.is_empty() { return; }
    let my_ep = get_public_endpoint().await;

    let all_nodes: Vec<String> = map.assignments.iter()
        .map(|a| a.node_address.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter().collect();

    let chain = load_chain();

    for (shard_id, role) in crate::sharding::my_shards(&my_addr, &map, &all_nodes) {
        if role != crate::sharding::ShardRole::Master { continue; }

        // Find slave endpoints for this shard
        let slave_eps: Vec<String> = map.assignments.iter()
            .filter(|a| a.shard_id == shard_id && a.role == crate::sharding::ShardRole::Slave && !a.node_endpoint.is_empty())
            .map(|a| a.node_endpoint.clone())
            .collect();

        if slave_eps.is_empty() { continue; }

        let (blocks, txs) = crate::sharding::get_shard_blocks(shard_id, 0, &chain, &map);
        if blocks.is_empty() { continue; }

        let response = P2PMessage::ShardDataResponse { shard_id, blocks, transactions: txs };
        let eps_clone = slave_eps.clone();
        tokio::spawn(async move {
            for ep in &eps_clone {
                let _ = send_message_any(&[ep.clone()], &response).await;
            }
        });
    }
}

/// Ask approved contacts to pin files we hold — increases replication factor.
pub async fn request_file_pinning(cids: Vec<String>) {
    if cids.is_empty() { return; }
    let ledger = crate::ledger::Ledger::load();
    if ledger.address.is_empty() { return; }
    let my_ep = get_public_endpoint().await;
    for contact in load_contacts().iter().filter(|c| c.status == "approved" && !c.endpoint.is_empty()) {
        let ep      = contact.endpoint.clone();
        let all_eps = contact.all_endpoints.clone();
        let from    = ledger.address.clone();
        let my_ep2  = my_ep.clone();
        let cids2   = cids.clone();
        tokio::spawn(async move {
            let mut eps = if all_eps.is_empty() { vec![ep.clone()] } else { all_eps };
            if !eps.contains(&ep) { eps.push(ep); }
            for cid in cids2 {
                let msg = P2PMessage::PinRequest {
                    cid,
                    from_addr:     from.clone(),
                    from_endpoint: my_ep2.clone(),
                };
                if let Err(e) = send_message_any(&eps, &msg).await {
                    if !e.contains("none of the requested protocols") {
                        eprintln!("[P2P] PinRequest failed: {}", e);
                    }
                    break; // don't spam if peer unreachable
                }
            }
        });
    }
}

/// Called when AutoNAT confirms public IP — broadcast manifest + peer announce.
async fn announce_as_relay(app: &tauri::AppHandle) {
    // Let all contacts know we're a relay node
    broadcast_data_manifest().await;
    broadcast_peer_announce(app).await;
    eprintln!("[relay-server] Announced as community relay node");
}

// ── Peer cache ────────────────────────────────────────────────────────────────

fn peer_cache_path() -> std::path::PathBuf { base_data_dir().join("peers.json") }

pub fn load_peer_cache() -> Vec<PeerEntry> {
    let data = std::fs::read_to_string(peer_cache_path()).unwrap_or_default();
    let mut peers: Vec<PeerEntry> = serde_json::from_str(&data).unwrap_or_default();
    let cutoff = Utc::now().timestamp() - 30 * 86_400;
    peers.retain(|p| p.last_seen >= cutoff);
    peers
}

fn save_peer_cache(peers: &[PeerEntry]) {
    if let Ok(data) = serde_json::to_string_pretty(peers) {
        let _ = std::fs::write(peer_cache_path(), data);
    }
}

pub fn upsert_peer_cache(entry: PeerEntry) {
    let mut peers = load_peer_cache();
    if let Some(e) = peers.iter_mut().find(|p| p.address == entry.address) {
        e.endpoint  = entry.endpoint;
        e.last_seen = entry.last_seen;
    } else {
        peers.push(entry);
    }
    save_peer_cache(&peers);
}

// ── Identity ──────────────────────────────────────────────────────────────────

fn load_or_create_identity() -> libp2p::identity::Keypair {
    let path = base_data_dir().join("p2p_identity.bin");
    if let Ok(bytes) = std::fs::read(&path) {
        if let Ok(kp) = libp2p::identity::Keypair::from_protobuf_encoding(&bytes) {
            return kp;
        }
    }
    let kp = libp2p::identity::Keypair::generate_ed25519();
    if let Ok(bytes) = kp.to_protobuf_encoding() {
        let _ = std::fs::write(&path, bytes);
    }
    kp
}

// ── Swarm entry point ─────────────────────────────────────────────────────────

pub async fn start_p2p_server(app: tauri::AppHandle) {
    #[cfg(target_os = "windows")]
    ensure_firewall_rule();

    let identity      = load_or_create_identity();
    let local_peer_id = identity.public().to_peer_id();
    eprintln!("[P2P] Local peer ID: {}", local_peer_id);

    let mut swarm = match build_swarm(identity).await {
        Ok(s)  => s,
        Err(e) => { eprintln!("[P2P] Failed to build swarm: {}", e); return; }
    };

    if let Err(e) = swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{}", P2P_PORT).parse().unwrap()) {
        eprintln!("[P2P] TCP listen: {}", e);
    }
    if let Err(e) = swarm.listen_on(format!("/ip4/0.0.0.0/udp/{}/quic-v1", P2P_PORT).parse().unwrap()) {
        eprintln!("[P2P] QUIC listen: {}", e);
    }

    // relay PeerId → base transport addr (no /p2p/<id> suffix)
    // e.g.  12D3KooWPj6m... → /ip4/40.233.82.42/tcp/4001
    let mut relay_addrs: HashMap<PeerId, Multiaddr> = HashMap::new();
    for relay_str in RELAY_NODES {
        if let Ok(addr) = relay_str.parse::<Multiaddr>() {
            if let Some(pid) = peer_id_from_multiaddr(&addr) {
                relay_addrs.insert(pid, strip_p2p_suffix(&addr));
            }
            eprintln!("[P2P] Dialling relay {}", relay_str);
            let _ = swarm.dial(addr);
        }
    }

    // ── Gossipsub subscriptions ───────────────────────────────────────────────
    let tx_topic       = gossipsub::IdentTopic::new("ego-txs-v1");
    let block_topic    = gossipsub::IdentTopic::new("ego-blocks-v1");
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&tx_topic);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&block_topic);

    let proposal_topic = gossipsub::IdentTopic::new("ego-proposals-v1");
    let vote_topic     = gossipsub::IdentTopic::new("ego-votes-v1");
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&proposal_topic);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&vote_topic);

    let shard_topic = gossipsub::IdentTopic::new("ego-shards-v1");
    swarm.behaviour_mut().gossipsub.subscribe(&shard_topic).ok();

    // Peer presence / endpoint updates — critical for surviving network changes.
    // When a peer changes WiFi/LAN their relay circuit address changes; publishing
    // here lets all mesh subscribers learn the new endpoint even if our stored
    // address for them is stale.
    let peers_topic = gossipsub::IdentTopic::new("ego-peers-v1");
    swarm.behaviour_mut().gossipsub.subscribe(&peers_topic).ok();

    // ── Kademlia bootstrap ────────────────────────────────────────────────────
    // Contacts the seeded relay nodes and discovers the rest of the DHT network.
    let _ = swarm.behaviour_mut().kad.bootstrap();

    // ── Gossip channel (fire-and-forget from broadcast_tx etc.) ──────────────
    let (gossip_unbounded_tx, mut gossip_rx) =
        mpsc::unbounded_channel::<(String, Vec<u8>)>();
    let _ = GOSSIP_TX.set(gossip_unbounded_tx);

    // ── DHT command channel ───────────────────────────────────────────────
    let (dht_cmd_tx, mut dht_cmd_rx) = mpsc::unbounded_channel::<DhtCommand>();
    let _ = DHT_CMD_TX.set(dht_cmd_tx);

    let (tx, mut rx) = mpsc::channel::<SwarmCmd>(64);
    let _ = SWARM_TX.set(tx);

    let mut external_addrs:   Vec<Multiaddr> = Vec::new();
    let mut pending_sends:    HashMap<PeerId, Vec<(P2PMessage, oneshot::Sender<Result<(), String>>)>> = HashMap::new();
    let mut in_flight:        HashMap<OutboundRequestId, oneshot::Sender<Result<(), String>>> = HashMap::new();
    let mut circuit_listener: Option<libp2p_core::transport::ListenerId> = None;

    // Retry relay connection every 15 s when circuit is not confirmed.
    let mut relay_retry = tokio::time::interval(Duration::from_secs(15));
    relay_retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    relay_retry.tick().await;

    // Periodic Kademlia random-walk discovery (every 5 minutes).
    let mut kad_discovery = tokio::time::interval(Duration::from_secs(300));
    kad_discovery.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    kad_discovery.tick().await;

    // Periodic DHT inbox poll (every 30 s) so offline-deposited ContactResponses
    // and chat messages are delivered even when the relay circuit was ready before
    // the sender deposited their message.
    let mut dht_inbox_poll = tokio::time::interval(Duration::from_secs(30));
    dht_inbox_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    dht_inbox_poll.tick().await; // skip first immediate tick

    loop {
        tokio::select! {
            // ── Gossip publish (from broadcast_tx / publish_gossip) ───────────
            Some((topic_str, data)) = gossip_rx.recv() => {
                let topic = gossipsub::IdentTopic::new(topic_str.clone());
                match swarm.behaviour_mut().gossipsub.publish(topic, data) {
                    Ok(_) => {}
                    // InsufficientPeers is normal at startup — suppress silently.
                    Err(gossipsub::PublishError::NoPeersSubscribedToTopic) => {}
                    Err(e) => eprintln!("[Gossip] publish '{}': {:?}", topic_str, e),
                }
            }

            // ── SwarmCmd (send / get-endpoint) ────────────────────────────────
            cmd = rx.recv() => {
                let Some(cmd) = cmd else { break; };
                match cmd {
                    SwarmCmd::Send { peer_addr, msg, reply } => {
                        handle_send(&mut swarm, peer_addr, msg, reply,
                            &mut pending_sends, &mut in_flight);
                    }
                    SwarmCmd::GetEndpoint { reply } => {
                        let ep = best_endpoint(&external_addrs, &local_peer_id);
                        let _ = reply.send(ep);
                    }
                    SwarmCmd::GossipPublish { topic, data } => {
                        let t = gossipsub::IdentTopic::new(topic.clone());
                        match swarm.behaviour_mut().gossipsub.publish(t, data) {
                            Ok(_) => {}
                            Err(gossipsub::PublishError::NoPeersSubscribedToTopic) => {}
                            Err(e) => eprintln!("[Gossip] publish '{}': {:?}", topic, e),
                        }
                    }
                }
            }

            // ── Swarm events ──────────────────────────────────────────────────
            event = swarm.select_next_some() => {
                handle_event(
                    event, &app,
                    &mut external_addrs, &mut pending_sends, &mut in_flight,
                    &mut swarm, &relay_addrs,
                    &mut circuit_listener,
                ).await;
            }

            // ── Relay circuit retry ───────────────────────────────────────────
            _ = relay_retry.tick() => {
                if !has_circuit_addr(&external_addrs) {
                    for relay_str in RELAY_NODES {
                        if let Ok(addr) = relay_str.parse::<Multiaddr>() {
                            let already = peer_id_from_multiaddr(&addr)
                                .map(|p| swarm.is_connected(&p))
                                .unwrap_or(false);
                            if !already {
                                eprintln!("[P2P] Relay not connected — redialling {}", relay_str);
                                let _ = swarm.dial(addr);
                            }
                        }
                    }
                }
            }

            // ── DHT commands (put/get peer records) ──────────────────────────
            Some(cmd) = dht_cmd_rx.recv() => {
                match cmd {
                    DhtCommand::PutPeer { key, value } => {
                        let record = kad::Record {
                            key:       kad::RecordKey::new(&key),
                            value,
                            publisher: None,
                            expires:   None,
                        };
                        let _ = swarm.behaviour_mut().kad.put_record(
                            record, kad::Quorum::One
                        );
                    }
                    DhtCommand::GetPeers { key } => {
                        swarm.behaviour_mut().kad.get_record(
                            kad::RecordKey::new(&key)
                        );
                    }
                }
            }

            // ── Kademlia periodic discovery ───────────────────────────────────
            _ = kad_discovery.tick() => {
                let _ = swarm.behaviour_mut().kad.bootstrap();
                // Also query rendezvous key to pick up any new peers
                swarm.behaviour_mut().kad.get_record(kad::RecordKey::new(&"ego-peers-v1"));
            }

            // ── Periodic DHT inbox poll (ContactResponse + offline messages) ──
            _ = dht_inbox_poll.tick() => {
                let addr = crate::ledger::Ledger::load().address;
                if !addr.is_empty() && RELAY_CIRCUIT_READY.load(Ordering::Relaxed) {
                    if let Some(tx) = DHT_CMD_TX.get() {
                        // Poll our mailbox for new messages
                        let mailbox_key = format!("ego-mailbox:{}", addr);
                        let _ = tx.send(DhtCommand::GetPeers { key: mailbox_key });
                        // Re-issue DHT gets for any blocks we're still missing.
                        // The sender may have published them to the DHT global store
                        // since our last attempt.
                        let ledger = crate::ledger::Ledger::load();
                        for file in &ledger.stored_files {
                            if file.cid.starts_with("egomfd1")
                                && file.blocks_total > 0
                                && file.blocks_received < file.blocks_total
                            {
                                if let Ok(manifest) = crate::blocks::load_manifest(&file.cid) {
                                    for block_cid in crate::blocks::missing_blocks(&manifest) {
                                        let _ = tx.send(DhtCommand::GetPeers {
                                            key: format!("ego-block:{}", block_cid),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn strip_p2p_suffix(addr: &Multiaddr) -> Multiaddr {
    use libp2p::multiaddr::Protocol;
    addr.iter().filter(|p| !matches!(p, Protocol::P2p(_))).collect()
}

async fn build_swarm(
    identity: libp2p::identity::Keypair,
) -> Result<libp2p::Swarm<EgoBehaviour>, Box<dyn std::error::Error>> {
    let peer_id = identity.public().to_peer_id();
    let swarm = SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(tcp::Config::default().nodelay(true), noise::Config::new, yamux::Config::default)?
        .with_quic()
        .with_dns()?
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key, relay_client| {
            // ── Gossipsub ─────────────────────────────────────────────────────
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(10))
                .validation_mode(gossipsub::ValidationMode::Permissive)
                .max_transmit_size(512 * 1024) // 512 KB
                .build()
                .expect("gossipsub config");
            let gossipsub_behaviour = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::RandomAuthor,
                gossipsub_config,
            )
            .expect("gossipsub::Behaviour");

            // ── Kademlia DHT ──────────────────────────────────────────────────
            // Increase max_value_bytes from the default 64 KB to 4 MB so that
            // small-to-medium file payloads (images, documents) can be stored
            // in the DHT inbox as a fallback when direct P2P is unavailable.
            let mut kad_store_cfg = kad::store::MemoryStoreConfig::default();
            kad_store_cfg.max_value_bytes = 4 * 1024 * 1024; // 4 MB
            let store = kad::store::MemoryStore::with_config(peer_id, kad_store_cfg);
            let mut kad_behaviour = kad::Behaviour::new(peer_id, store);
            // Seed the routing table with all known relay nodes so we can
            // bootstrap even if we've never connected to any peer before.
            for relay_str in RELAY_NODES {
                if let Ok(addr) = relay_str.parse::<Multiaddr>() {
                    if let Some(relay_pid) = peer_id_from_multiaddr(&addr) {
                        kad_behaviour.add_address(&relay_pid, strip_p2p_suffix(&addr));
                    }
                }
            }
            // Every Ego node participates as a full DHT server so the network
            // can discover peers without the central HTTP relay.
            kad_behaviour.set_mode(Some(kad::Mode::Server));

            EgoBehaviour {
                relay_client,
                // Desktop relay server: runs on every node, becomes useful when
                // AutoNAT reports Public.  Limits are ~1/4 of the central relay's
                // to avoid overloading consumer hardware.
                relay_server: relay::Behaviour::new(
                    peer_id,
                    relay::Config {
                        max_reservations:          128,
                        max_reservations_per_peer: 2,
                        reservation_duration:      Duration::from_secs(3600),
                        max_circuits:              256,
                        max_circuits_per_peer:     8,
                        max_circuit_duration:      Duration::from_secs(7200),
                        max_circuit_bytes:         u64::MAX,
                        ..Default::default()
                    },
                ),
                dcutr:    dcutr::Behaviour::new(peer_id),
                identify: identify::Behaviour::new(
                    identify::Config::new("/ego/identify/1.0.0".to_string(), key.public())
                        .with_interval(Duration::from_secs(60)),
                ),
                request_response: request_response::Behaviour::new(
                    [(StreamProtocol::new("/ego/msg/1.1.0"), ProtocolSupport::Full)],
                    request_response::Config::default()
                        .with_request_timeout(Duration::from_secs(120)),
                ),
                autonat: autonat::Behaviour::new(peer_id, autonat::Config::default()),
                    ping: ping::Behaviour::new(
                        ping::Config::new()
                            .with_interval(Duration::from_secs(15))  // was 30s — halve it
                            .with_timeout(Duration::from_secs(10)),
                    ),
                gossipsub: gossipsub_behaviour,
                kad:       kad_behaviour,
            }
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(86400)))
        .build();
    Ok(swarm)
}

// ── Send helper ───────────────────────────────────────────────────────────────

fn handle_send(
    swarm:         &mut libp2p::Swarm<EgoBehaviour>,
    peer_addr:     Multiaddr,
    msg:           P2PMessage,
    reply:         oneshot::Sender<Result<(), String>>,
    pending_sends: &mut HashMap<PeerId, Vec<(P2PMessage, oneshot::Sender<Result<(), String>>)>>,
    in_flight:     &mut HashMap<OutboundRequestId, oneshot::Sender<Result<(), String>>>,
) {
    let peer_id = match peer_id_from_multiaddr(&peer_addr) {
        Some(id) => id,
        None => {
            let _ = reply.send(Err(format!("No peer ID in multiaddr: {}", peer_addr)));
            return;
        }
    };
    if swarm.is_connected(&peer_id) {
        let req_id = swarm.behaviour_mut().request_response.send_request(&peer_id, msg);
        in_flight.insert(req_id, reply);
    } else {
        pending_sends.entry(peer_id).or_default().push((msg, reply));
        let _ = swarm.dial(peer_addr);
    }
}

fn peer_id_from_multiaddr(addr: &Multiaddr) -> Option<PeerId> {
    use libp2p::multiaddr::Protocol;
    addr.iter().filter_map(|p| {
        if let Protocol::P2p(pid) = p { Some(pid) } else { None }
    }).last()
}

/// Select best reachable endpoint.
///   1. /p2p-circuit   — works behind any NAT
///   2. Public IPv4    — works if port-forwarded
///   3. LAN / loopback — last resort
fn best_endpoint(external_addrs: &[Multiaddr], peer_id: &PeerId) -> String {
    let pid_str = peer_id.to_string();

    if let Some(a) = external_addrs.iter().find(|a| a.to_string().contains("/p2p-circuit")) {
        let s = a.to_string();
        return if s.contains(&pid_str) { s } else { format!("{}/p2p/{}", s, pid_str) };
    }

    let is_public = |a: &Multiaddr| {
        let s = a.to_string();
        !s.starts_with("/ip4/127.")     &&
        !s.starts_with("/ip4/10.")      &&
        !s.starts_with("/ip4/192.168.") &&
        !s.starts_with("/ip4/172.")
    };
    let base = external_addrs.iter().find(|a| is_public(a))
        .or_else(|| external_addrs.first())
        .map(|a| a.to_string())
        .unwrap_or_else(|| format!("/ip4/{}/tcp/{}", get_local_ip(), P2P_PORT));
    if base.contains("/p2p/") { base } else { format!("{}/p2p/{}", base, pid_str) }
}

fn has_circuit_addr(addrs: &[Multiaddr]) -> bool {
    addrs.iter().any(|a| a.to_string().contains("/p2p-circuit"))
}

// Build the full dialable circuit address:
//   /ip4/<relay_ip>/tcp/<port>/p2p/<relay_id>/p2p-circuit/p2p/<our_id>
fn build_circuit_addr(
    relay_base:    &Multiaddr,
    relay_peer_id: &PeerId,
    our_peer_id:   &PeerId,
) -> Option<Multiaddr> {
    format!("{}/p2p/{}/p2p-circuit/p2p/{}", relay_base, relay_peer_id, our_peer_id)
        .parse()
        .ok()
}

// ── Circuit injection (called from multiple event paths) ──────────────────────

/// Add `circuit` to external_addrs and set RELAY_CIRCUIT_READY.
/// MUST only be called from within the swarm event loop so that
/// external_addrs mutations are always single-threaded.
fn inject_circuit(
    circuit:        Multiaddr,
    external_addrs: &mut Vec<Multiaddr>,
    app:            &tauri::AppHandle,
    local_peer_id:  &PeerId,
) {
    if !external_addrs.contains(&circuit) {
        eprintln!("[P2P] ✓ Circuit injected: {}", circuit);
        external_addrs.push(circuit);
    }
    RELAY_CIRCUIT_READY.store(true, Ordering::Relaxed);
    let ep    = best_endpoint(external_addrs, local_peer_id);
    let state = app.state::<crate::app::AppState>();
    state.set_public_endpoint(ep.clone());
    state.set_upnp_status(Ok(()));
    let _ = app.emit_all("ego://p2p-status-changed", ());

    // Announce to contacts + poll DHT inbox after circuit is confirmed
    let app_clone = app.clone();
    tokio::spawn(async move {
        // Small delay so contacts have time to connect too before we announce
        tokio::time::sleep(Duration::from_millis(300)).await;
        broadcast_peer_announce(&app_clone).await;
        eprintln!("[P2P] Re-announced after relay circuit confirmed");

        // Poll DHT inbox for offline messages deposited while we were offline
        let addr = crate::ledger::Ledger::load().address;
        if !addr.is_empty() {
            dht_fetch_inbox(&addr).await;
            eprintln!("[Messenger] DHT inbox polled for {}", &addr[..addr.len().min(20)]);
        }
    });
}

// ── Swarm event handler ───────────────────────────────────────────────────────

async fn handle_event(
    event:            SwarmEvent<EgoBehaviourEvent>,
    app:              &tauri::AppHandle,
    external_addrs:   &mut Vec<Multiaddr>,
    pending_sends:    &mut HashMap<PeerId, Vec<(P2PMessage, oneshot::Sender<Result<(), String>>)>>,
    in_flight:        &mut HashMap<OutboundRequestId, oneshot::Sender<Result<(), String>>>,
    swarm:            &mut libp2p::Swarm<EgoBehaviour>,
    relay_addrs:      &HashMap<PeerId, Multiaddr>,
    circuit_listener: &mut Option<libp2p_core::transport::ListenerId>,
) {
    match event {

        // ─── NewListenAddr ────────────────────────────────────────────────────
        // When the relay accepts our reservation it assigns a circuit listen
        // address.  libp2p fires NewListenAddr with that address.
        // This is the PRIMARY confirmation path.
        SwarmEvent::NewListenAddr { address, .. } => {
            let addr_str = address.to_string();
            eprintln!("[P2P] Listening on {}", addr_str);

            if addr_str.contains("/p2p-circuit") {
                let peer_id = *swarm.local_peer_id();
                let pid_str = peer_id.to_string();
                // Ensure /p2p/<our_id> is appended so remote peers can dial us
                let full: Multiaddr = if addr_str.contains(&pid_str) {
                    address.clone()
                } else {
                    format!("{}/p2p/{}", addr_str, pid_str)
                        .parse()
                        .unwrap_or(address.clone())
                };
                eprintln!("[P2P] ✓ Relay circuit LIVE (NewListenAddr): {}", full);
                inject_circuit(full, external_addrs, app, &peer_id);
            }
        }

        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            eprintln!("[P2P] Connected to {}", peer_id);

            if let Some(relay_base) = relay_addrs.get(&peer_id) {
                let our_peer_id = *swarm.local_peer_id();
                let circuit_str = format!("{}/p2p/{}/p2p-circuit", relay_base, peer_id);
                match circuit_str.parse::<Multiaddr>() {
                    Ok(circuit_addr) => {
                        // Only register a new circuit listener if we don't already have
                        // one active. TCP and QUIC both connect to the relay at startup,
                        // firing ConnectionEstablished twice for the same peer. Without
                        // this guard, two listen_on calls produce two simultaneous
                        // reservation requests — the relay drops one with a WARN and the
                        // surviving reservation ends up on the wrong connection, causing
                        // every subsequent circuit to be denied.
                        if circuit_listener.is_some() {
                            eprintln!("[P2P] Relay already reserved — skipping duplicate ConnectionEstablished for {}", peer_id);
                        } else {
                        eprintln!("[P2P] Reserving relay slot: {}", circuit_str);
                        match swarm.listen_on(circuit_addr) {
                            Ok(lid) => {
                                *circuit_listener = Some(lid);
                                eprintln!("[P2P] Relay reservation requested ✓");
                                if let Some(full_circuit) = build_circuit_addr(
                                    relay_base, &peer_id, &our_peer_id,
                                ) {
                                    inject_circuit(full_circuit, external_addrs, app, &our_peer_id);
                                }
                            }
                            Err(e) => eprintln!("[P2P] Relay listen error: {}", e),
                        }
                        } // end else (circuit_listener.is_none())
                    }
                    Err(e) => eprintln!("[P2P] Bad circuit addr '{}': {}", circuit_str, e),
                }
            }

            // Force identify exchange so remote learns our protocols immediately.
            swarm.behaviour_mut().identify.push(std::iter::once(peer_id));

            // If the relay is already reserved, flush any pending sends to this
            // peer immediately. ReservationReqAccepted fires only once at startup
            // so messages queued after that would otherwise be lost.
            if RELAY_CIRCUIT_READY.load(Ordering::Relaxed) {
                if let Some(pending) = pending_sends.remove(&peer_id) {
                    eprintln!("[P2P] Flushing {} queued message(s) to {} on connect", pending.len(), peer_id);
                    for (msg, reply) in pending {
                        let req_id = swarm.behaviour_mut()
                            .request_response.send_request(&peer_id, msg);
                        in_flight.insert(req_id, reply);
                    }
                }
            }
        }

        SwarmEvent::ConnectionClosed { peer_id, num_established, .. } => {
            if relay_addrs.contains_key(&peer_id) {
                eprintln!("[P2P] Relay {} connection closed ({} remaining)", peer_id, num_established);
                if num_established == 0 {
                    // All connections to relay are gone — clear the circuit.
                    // If we cleared on every ConnectionClosed (even when another
                    // relay connection is still open), we would call remove_listener
                    // prematurely: the Receiver side of the handler's to_listener
                    // channel gets dropped, the handler's Reservation state flips to
                    // None, and the next circuit request is denied with NO_RESERVATION
                    // which the relay logs as UNEXPECTED_MESSAGE.
                    eprintln!("[P2P] All relay connections gone — clearing circuit");
                    RELAY_CIRCUIT_READY.store(false, Ordering::Relaxed);
                    external_addrs.retain(|a| !a.to_string().contains("/p2p-circuit"));
                    if let Some(id) = circuit_listener.take() {
                        swarm.remove_listener(id);
                    }
                }
                // Do NOT dial here — the relay_retry timer (every 15 s) will
                // reconnect. Dialling immediately AND from the timer causes two
                // simultaneous connections to the relay; the relay then has two
                // handlers for our peer ID, routes incoming circuits to the one
                // without a reservation, and denies every circuit.
            }
            if let Some(pending) = pending_sends.remove(&peer_id) {
                for (_, reply) in pending {
                    let _ = reply.send(Err("Connection closed before send".into()));
                }
            }
        }

        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            eprintln!("[P2P] Dial error {:?}: {}", peer_id, error);
            if let Some(pid) = peer_id {
                if let Some(pending) = pending_sends.remove(&pid) {
                    for (_, reply) in pending {
                        let _ = reply.send(Err(format!("Cannot reach peer: {}", error)));
                    }
                }
            }
        }

        // ─── Identify ─────────────────────────────────────────────────────────
        // Learn our own external address as seen by a remote peer.
        // Only update AppState from here if relay circuit isn't live yet.
        SwarmEvent::Behaviour(EgoBehaviourEvent::Identify(
            identify::Event::Received { info, .. },
        )) => {
            let observed = info.observed_addr.clone();
            swarm.add_external_address(observed.clone());
            if !external_addrs.contains(&observed) {
                external_addrs.push(observed.clone());
                eprintln!("[P2P] Observed external address: {}", observed);
            }
            if !RELAY_CIRCUIT_READY.load(Ordering::Relaxed) {
                let peer_id = *swarm.local_peer_id();
                let state   = app.state::<crate::app::AppState>();
                state.set_public_endpoint(best_endpoint(external_addrs, &peer_id));
                let _ = app.emit_all("ego://p2p-status-changed", ());
            }
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::RelayClient(
            relay::client::Event::ReservationReqAccepted { relay_peer_id, .. },
        )) => {
            eprintln!("[P2P] ✓ Relay reservation ACCEPTED via {}", relay_peer_id);
            let our_peer_id = *swarm.local_peer_id();
            if let Some(relay_base) = relay_addrs.get(&relay_peer_id) {
                if let Some(circuit) = build_circuit_addr(relay_base, &relay_peer_id, &our_peer_id) {
                    inject_circuit(circuit, external_addrs, app, &our_peer_id);
                }
            }
            // Reservation confirmed — now safe to dial peers through the relay.
            for (peer_id, pending) in pending_sends.drain() {
                eprintln!("[P2P] Flushing {} queued messages to {} after reservation", pending.len(), peer_id);
                for (msg, reply) in pending {
                    let req_id = swarm.behaviour_mut()
                        .request_response.send_request(&peer_id, msg);
                    in_flight.insert(req_id, reply);
                }
            }
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::RelayClient(event)) => {
            eprintln!("[P2P] Relay event: {:?}", event);
        }

        // ─── Relay server events (this node relaying for others) ──────────
        SwarmEvent::Behaviour(EgoBehaviourEvent::RelayServer(
            relay::Event::ReservationReqAccepted { src_peer_id, .. },
        )) => {
            eprintln!("[relay-server] Reservation accepted for {}", src_peer_id);
        }
        SwarmEvent::Behaviour(EgoBehaviourEvent::RelayServer(
            relay::Event::CircuitReqAccepted { src_peer_id, dst_peer_id, .. },
        )) => {
            eprintln!("[relay-server] Circuit opened: {} → {}", src_peer_id, dst_peer_id);
        }
        SwarmEvent::Behaviour(EgoBehaviourEvent::RelayServer(_)) => {}

        // ─── AutoNAT ──────────────────────────────────────────────────────────
        SwarmEvent::Behaviour(EgoBehaviourEvent::Autonat(
            autonat::Event::StatusChanged { new, .. },
        )) => {
            let state = app.state::<crate::app::AppState>();
            match new {
                autonat::NatStatus::Public(addr) => {
                    eprintln!("[P2P] AutoNAT: public at {}", addr);
                    state.set_upnp_status(Ok(()));
                    if !external_addrs.contains(&addr) {
                        external_addrs.push(addr.clone());
                    }
                    if !RELAY_CIRCUIT_READY.load(Ordering::Relaxed) {
                        let peer_id = *swarm.local_peer_id();
                        state.set_public_endpoint(best_endpoint(external_addrs, &peer_id));
                        let _ = app.emit_all("ego://p2p-status-changed", ());
                    }
                    // Enable relay server mode — this node can now relay for NAT peers.
                    if !IS_RELAY_SERVER.load(Ordering::Relaxed) {
                        IS_RELAY_SERVER.store(true, Ordering::Relaxed);
                        eprintln!("[relay-server] Public IP confirmed — relay server ACTIVE");
                        let _ = app.emit_all("ego://relay-server-enabled", ());
                        let app_clone = app.clone();
                        tokio::spawn(async move { announce_as_relay(&app_clone).await; });
                    }
                }
                autonat::NatStatus::Private => {
                    eprintln!("[P2P] AutoNAT: behind NAT — relay required");
                    state.set_upnp_status(Err("Behind NAT — using relay".into()));
                    let _ = app.emit_all("ego://p2p-status-changed", ());
                }
                autonat::NatStatus::Unknown => {}
            }
        }

        // ─── request-response ─────────────────────────────────────────────────
        SwarmEvent::Behaviour(EgoBehaviourEvent::RequestResponse(
            request_response::Event::Message {
                message: request_response::Message::Request { request, channel, .. }, ..
            },
        )) => {
            let _ = swarm.behaviour_mut().request_response.send_response(channel, ());
            let app = app.clone();
            tokio::spawn(async move { handle_incoming(request, &app).await; });
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::RequestResponse(
            request_response::Event::Message {
                message: request_response::Message::Response { request_id, .. }, ..
            },
        )) => {
            if let Some(reply) = in_flight.remove(&request_id) {
                let _ = reply.send(Ok(()));
            }
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::RequestResponse(
            request_response::Event::OutboundFailure { request_id, error, .. },
        )) => {
            if let Some(reply) = in_flight.remove(&request_id) {
                let _ = reply.send(Err(format!("Network error: {}", error)));
            }
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::Dcutr(event)) => {
            eprintln!("[P2P] DCUtR: {:?}", event);
        }

        // ── Gossipsub: incoming broadcast (tx or block from any peer) ─────────
        SwarmEvent::Behaviour(EgoBehaviourEvent::Gossipsub(
            gossipsub::Event::Message { message, .. },
        )) => {
            let topic = message.topic.to_string();
            if topic == "ego-txs-v1" {
                // TxBroadcast envelope: { type, tx, block }
                if let Ok(P2PMessage::TxBroadcast { tx, block }) =
                    serde_json::from_slice::<P2PMessage>(&message.data)
                {
                    let app2 = app.clone();
                    tokio::spawn(async move { apply_incoming_tx(tx, block, &app2).await; });
                }
            } else if topic == "ego-blocks-v1" {
                match serde_json::from_slice::<P2PMessage>(&message.data) {
                    Ok(P2PMessage::ChainSyncResponse { blocks, transactions }) => {
                        let app2 = app.clone();
                        tokio::spawn(async move { merge_remote_chain(blocks, transactions, &app2).await; });
                    }
                    Ok(P2PMessage::BlockFinalized { block, transactions, .. }) => {
                        let app2 = app.clone();
                        tokio::spawn(async move { merge_remote_chain(vec![block], transactions, &app2).await; });
                    }
                    _ => {}
                }
            } else if topic == "ego-proposals-v1" {
                if let Ok(P2PMessage::BlockProposal { block, transactions, proposer, .. }) =
                    serde_json::from_slice::<P2PMessage>(&message.data)
                {
                    // Register proposer as known validator
                    register_known_validator(&proposer);
                    let app2 = app.clone();
                    tokio::spawn(async move {
                        handle_block_proposal(block, transactions, proposer, &app2).await;
                    });
                }
            } else if topic == "ego-votes-v1" {
                if let Ok(P2PMessage::BlockVote { block_hash, height, voter, signature, timestamp }) =
                    serde_json::from_slice::<P2PMessage>(&message.data)
                {
                    register_known_validator(&voter);
                    let app2 = app.clone();
                    tokio::spawn(async move {
                        handle_block_vote(block_hash, height, voter, signature, timestamp, &app2).await;
                    });
                }
            } else if topic == "ego-peers-v1" {
                // Peer presence / endpoint update broadcast.
                // When a peer changes WiFi/LAN their relay circuit changes; this
                // lets us update the peer cache without a direct connection.
                if let Ok(msg @ P2PMessage::PeerAnnounce { .. }) =
                    serde_json::from_slice::<P2PMessage>(&message.data)
                {
                    let app2 = app.clone();
                    tokio::spawn(async move { handle_incoming(msg, &app2).await; });
                }
            } else if topic == "ego-shards-v1" {
                match serde_json::from_slice::<P2PMessage>(&message.data) {
                    Ok(P2PMessage::ShardAnnounce { from_addr, from_endpoint, held_shards, uptime_secs, network_node_count, shard_count }) => {
                        crate::sharding::handle_shard_announce_update(&from_addr, &from_endpoint, &held_shards, uptime_secs, network_node_count, shard_count);
                    }
                    Ok(P2PMessage::MasterPromotion { shard_id, new_master, new_endpoint, former_master, timestamp }) => {
                        eprintln!("[Sharding] MasterPromotion: shard {} → new master {} (was {})", shard_id, new_master, former_master);
                        let mut map = crate::sharding::load_shard_map();
                        if let Some(old) = map.assignments.iter_mut().find(|a| a.shard_id == shard_id && a.node_address == former_master) {
                            old.role = crate::sharding::ShardRole::Observer;
                        }
                        if let Some(new_m) = map.assignments.iter_mut().find(|a| a.shard_id == shard_id && a.node_address == new_master) {
                            new_m.role = crate::sharding::ShardRole::Master;
                            new_m.node_endpoint = new_endpoint.clone();
                            new_m.last_seen = timestamp;
                        } else {
                            map.assignments.push(crate::sharding::ShardAssignment {
                                shard_id,
                                role: crate::sharding::ShardRole::Master,
                                node_address: new_master.clone(),
                                node_endpoint: new_endpoint.clone(),
                                last_seen: timestamp,
                                uptime_secs: 0,
                            });
                        }
                        let _ = crate::sharding::save_shard_map(&map);
                        // Phase 2: if we are a slave for this shard, fill vacancy by
                        // pulling the shard data from the new master
                        let my_addr = crate::ledger::Ledger::load().address;
                        let my_ep   = get_public_endpoint().await;
                        let updated = crate::sharding::load_shard_map();
                        let all_nodes: Vec<String> = updated.assignments.iter()
                            .map(|a| a.node_address.clone())
                            .collect::<std::collections::HashSet<_>>()
                            .into_iter().collect();
                        let is_slave = crate::sharding::my_shards(&my_addr, &updated, &all_nodes)
                            .iter().any(|(sid, role)| *sid == shard_id && *role == crate::sharding::ShardRole::Slave);
                        if is_slave && !new_endpoint.is_empty() {
                            let my_ep2 = my_ep.clone();
                            let my_a2  = my_addr.clone();
                            let ep2    = new_endpoint.clone();
                            let chain  = load_chain();
                            let from_h = crate::sharding::last_shard_height(shard_id, &chain, &updated);
                            tokio::spawn(async move {
                                let req = P2PMessage::ShardDataRequest {
                                    shard_id,
                                    from_height:        from_h,
                                    requester_address:  my_a2,
                                    requester_endpoint: my_ep2,
                                };
                                let _ = send_message_any(&[ep2], &req).await;
                            });
                        }
                    }
                    _ => {}
                }
            }
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::Gossipsub(
            gossipsub::Event::Subscribed { peer_id: pid, topic },
        )) => {
            eprintln!("[Gossip] {} subscribed to {}", pid, topic);
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::Gossipsub(_)) => {}

        // ── Kademlia: new peer discovered via DHT ─────────────────────────────
        SwarmEvent::Behaviour(EgoBehaviourEvent::Kad(
            kad::Event::RoutingUpdated { peer, addresses, .. },
        )) => {
            eprintln!("[DHT] Routing updated: {} ({} addrs)", peer, addresses.len());
            // Try to connect so gossipsub mesh includes them.
            if let Some(addr) = addresses.iter().next() {
                let full: Multiaddr = format!("{}/p2p/{}", addr, peer)
                    .parse()
                    .unwrap_or_else(|_| addr.clone());
                let _ = swarm.dial(full);
            }
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::Kad(
            kad::Event::OutboundQueryProgressed { result, .. },
        )) => {
            match result {
                kad::QueryResult::Bootstrap(Ok(kad::BootstrapOk { num_remaining, .. })) => {
                    if num_remaining == 0 {
                        eprintln!("[DHT] Bootstrap complete");
                    }
                }
                kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(rec))) => {
                    let key_str = String::from_utf8_lossy(rec.record.key.as_ref()).to_string();

                    if key_str.starts_with("ego-mailbox:") {
                        // Mailbox list: JSON array of msg_hash strings.
                        // On each GetRecord we: (a) merge any pending appends and write
                        // back the enlarged list, then (b) issue a GetRecord for every
                        // ego-inbox:{addr}:{hash} entry so the payload is dispatched.
                        let addr = key_str.trim_start_matches("ego-mailbox:");
                        let mut hashes: Vec<String> = serde_json::from_slice::<Vec<String>>(
                            &rec.record.value
                        ).unwrap_or_default();

                        // Drain pending appends for this address.
                        let pending: Vec<String> = {
                            let mut map = pending_appends().lock().unwrap();
                            map.remove(addr).unwrap_or_default()
                        };
                        if !pending.is_empty() {
                            for h in &pending {
                                if !hashes.contains(h) {
                                    hashes.push(h.clone());
                                }
                            }
                            if let Ok(v) = serde_json::to_vec(&hashes) {
                                let _ = swarm.behaviour_mut().kad.put_record(
                                    kad::Record {
                                        key:       rec.record.key.clone(),
                                        value:     v,
                                        publisher: None,
                                        expires:   None,
                                    },
                                    kad::Quorum::One,
                                );
                                eprintln!("[DHT] Updated mailbox list for {} ({} entries)", addr, hashes.len());
                            }
                        }

                        // Only fetch and dispatch messages when this mailbox belongs to us.
                        // During a deposit (append cycle) we read a *foreign* mailbox to
                        // do the read-modify-write; we must NOT dispatch those messages here
                        // — the actual owner's node will pick them up on their own poll.
                        let my_addr_check = crate::ledger::Ledger::load().address;
                        if addr == my_addr_check {
                            for hash in &hashes {
                                let msg_key = format!("ego-inbox:{}:{}", addr, hash);
                                swarm.behaviour_mut().kad.get_record(kad::RecordKey::new(&msg_key));
                            }
                            if !hashes.is_empty() {
                                eprintln!("[DHT] Polling {} inbox message(s) for {}", hashes.len(), addr);
                            }
                        }
                    } else if key_str.starts_with("ego-inbox:") {
                        // Actual message payload — dispatch to handle_incoming.
                        // Deduplicate: same DHT record is polled every 30 s; only
                        // dispatch each unique key once per session.
                        if dht_seen().insert(key_str.clone()) {
                            if let Ok(msg) = serde_json::from_slice::<P2PMessage>(&rec.record.value) {
                                let app2 = app.clone();
                                tokio::spawn(async move { handle_incoming(msg, &app2).await; });
                                eprintln!("[DHT] Dispatched inbox message from DHT: {}", &key_str[..key_str.len().min(50)]);
                            }
                        } else {
                            eprintln!("[DHT] Skipping already-seen inbox message: {}", &key_str[..key_str.len().min(50)]);
                        }
                    } else if key_str.starts_with("ego-manifest:") {
                        // File manifest from DHT global store — save and process.
                        let manifest_cid = key_str.trim_start_matches("ego-manifest:").to_string();
                        if let Ok(manifest) = serde_json::from_slice::<crate::blocks::FileManifest>(&rec.record.value) {
                            // Save to disk
                            let _ = crate::blocks::save_manifest(&manifest);
                            eprintln!("[DHT] Manifest {} received from DHT ({} blocks)", &manifest_cid[..16.min(manifest_cid.len())], manifest.blocks.len());
                            // Update ledger entry if we're waiting for this file
                            let app2 = app.clone();
                            let mcid = manifest_cid.clone();
                            tokio::spawn(async move {
                                process_received_manifest(&mcid, &app2).await;
                            });
                        }
                    } else if key_str.starts_with("ego-block:") {
                        // Encrypted block from DHT global store — save to disk.
                        let block_cid = key_str.trim_start_matches("ego-block:").to_string();
                        if !crate::blocks::have_block(&block_cid) {
                            let _ = crate::blocks::save_block(&block_cid, &rec.record.value);
                            eprintln!("[DHT] Block {} received from DHT ({} bytes)", &block_cid[..16.min(block_cid.len())], rec.record.value.len());
                            // Check if this completes any pending manifest
                            let app2 = app.clone();
                            tokio::spawn(async move {
                                check_block_completes_manifests(&block_cid, &app2).await;
                            });
                        }
                    } else {
                        // Peer discovery record: { address, endpoint, name, ts }
                        if let Ok(peer_info) = serde_json::from_slice::<serde_json::Value>(&rec.record.value) {
                            let endpoint = peer_info["endpoint"].as_str().unwrap_or("");
                            if !endpoint.is_empty() {
                                if let Ok(addr) = endpoint.parse::<Multiaddr>() {
                                    let _ = swarm.dial(addr);
                                    eprintln!("[DHT] Discovered peer via DHT: {}", endpoint);
                                }
                            }
                        }
                    }
                }
                // Mailbox key not found in DHT yet — write a fresh list if there
                // are pending appends (first message ever deposited for this addr).
                kad::QueryResult::GetRecord(Err(kad::GetRecordError::NotFound { key, .. })) => {
                    let key_str = String::from_utf8_lossy(key.as_ref()).to_string();
                    if key_str.starts_with("ego-mailbox:") {
                        let addr = key_str.trim_start_matches("ego-mailbox:");
                        let pending: Vec<String> = {
                            let mut map = pending_appends().lock().unwrap();
                            map.remove(addr).unwrap_or_default()
                        };
                        if !pending.is_empty() {
                            if let Ok(v) = serde_json::to_vec(&pending) {
                                let _ = swarm.behaviour_mut().kad.put_record(
                                    kad::Record {
                                        key:       kad::RecordKey::new(&key_str),
                                        value:     v,
                                        publisher: None,
                                        expires:   None,
                                    },
                                    kad::Quorum::One,
                                );
                                eprintln!("[DHT] Created new mailbox list for {} ({} entries)", addr, pending.len());
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        SwarmEvent::Behaviour(EgoBehaviourEvent::Kad(_)) => {}

        _ => {}
    }
}

// ── Incoming message handler ──────────────────────────────────────────────────

pub async fn handle_incoming(msg: P2PMessage, app: &tauri::AppHandle) {
    match msg {
        P2PMessage::ContactRequest {
            from_addr, from_name, from_ed25519, from_kyber, from_shared_key, from_endpoint,
        } => {
            let mut contacts = load_contacts();
            if let Some(existing) = contacts.iter_mut().find(|c| c.address == from_addr) {
                if !from_endpoint.is_empty() && existing.endpoint != from_endpoint {
                    existing.endpoint = from_endpoint;
                    let _ = save_contacts(&contacts);
                }
                return;
            }
            let contact = Contact {
                address:        from_addr.clone(),
                name:           from_name.clone(),
                ed25519_pubkey: from_ed25519,
                kyber_pubkey:   from_kyber,
                shared_key_hex: from_shared_key,
                status:         "pending_in".to_string(),
                added_at:       Utc::now().timestamp(),
                endpoint:       from_endpoint,
                all_endpoints:  Vec::new(),
            };
            contacts.push(contact.clone());
            let _ = save_contacts(&contacts);
            let _ = tauri::api::notification::Notification::new(
                &app.config().tauri.bundle.identifier,
            )
            .title("Contact Request")
            .body(&format!("{} wants to connect with you", from_name))
            .show();
            let _ = app.emit_all("ego://contact-request", &contact);
        }

        P2PMessage::FileChunk { .. } => {
            eprintln!("[P2P] FileChunk ignored — 50MB max file size enforced at upload");
        }

        P2PMessage::FileChunkComplete { .. } => {
            eprintln!("[P2P] FileChunkComplete ignored — 50MB max file size enforced at upload");
        }

        // ── Distributed storage: data manifest ───────────────────────────
        P2PMessage::DataManifest { from_addr, cids, available_gb, is_relay, endpoint } => {
            eprintln!("[P2P] DataManifest from {} — {} CIDs, {:.1}GB free, relay={}",
                from_addr, cids.len(), available_gb, is_relay);
            // Track peer relay nodes so we can use them as additional hops
            if is_relay && !endpoint.is_empty() {
                peer_relay_nodes().insert(from_addr.clone(), endpoint.clone());
                eprintln!("[relay-server] Discovered community relay node at {}", endpoint);
            }
            let _ = app.emit_all("ego://data-manifest", serde_json::json!({
                "from_addr":    from_addr,
                "cid_count":    cids.len(),
                "available_gb": available_gb,
                "is_relay":     is_relay,
            }));
        }

        // ── Distributed storage: pin request ────────────────────────────
        P2PMessage::PinRequest { cid, from_addr, from_endpoint } => {
            eprintln!("[P2P] PinRequest for {} from {}", cid, from_addr);
            let ledger    = crate::ledger::Ledger::load();
            let used: u64 = ledger.stored_files.iter().map(|f| f.encrypted_size).sum();
            let capacity  = ledger.storage_allocated_bytes;
            let has_file  = ledger.stored_files.iter()
                .any(|f| f.cid == cid && !f.local_path.is_empty() && !f.local_path.starts_with("sender:"));
            let my_addr   = ledger.address.clone();
            let ep        = from_endpoint.clone();
            if has_file {
                tokio::spawn(async move {
                    let _ = send_message_any(&[ep], &P2PMessage::PinAck {
                        cid, accepted: true, reason: "Already stored".into(),
                    }).await;
                });
            } else if capacity > 0 && used + 10_000_000 < capacity {
                // We have space — pull the file from the requester to pin it
                let my_ep = get_public_endpoint().await;
                let cid2  = cid.clone();
                let ep2   = ep.clone();
                tokio::spawn(async move {
                    let _ = send_message_any(&[ep2.clone()], &P2PMessage::FileRequest {
                        cid: cid2.clone(),
                        requester_addr:     my_addr,
                        requester_endpoint: my_ep,
                    }).await;
                    let _ = send_message_any(&[ep2], &P2PMessage::PinAck {
                        cid: cid2, accepted: true, reason: "Pinning".into(),
                    }).await;
                });
            } else {
                tokio::spawn(async move {
                    let _ = send_message_any(&[ep], &P2PMessage::PinAck {
                        cid, accepted: false, reason: "Insufficient capacity".into(),
                    }).await;
                });
            }
        }

        P2PMessage::PinAck { cid, accepted, reason } => {
            eprintln!("[P2P] PinAck for {} — accepted={} ({})", cid, accepted, reason);
        }

        P2PMessage::ContactResponse {
            from_addr, from_name, from_ed25519, from_kyber, approved, shared_key, from_endpoint,
        } => {
            let mut contacts = load_contacts();
            if approved {
                if let Some(p) = contacts.iter_mut()
                    .find(|c| c.shared_key_hex == shared_key
                           && (c.status == "pending_out" || c.status == "approved"))
                {
                    let already_approved = p.status == "approved";
                    p.address        = from_addr.clone();
                    p.name           = from_name.clone();
                    p.ed25519_pubkey = from_ed25519;
                    p.kyber_pubkey   = from_kyber;
                    p.status         = "approved".to_string();
                    if !from_endpoint.is_empty() {
                        p.endpoint = from_endpoint;
                    }
                    let contact = p.clone();
                    let _ = save_contacts(&contacts);
                    if !already_approved {
                        let _ = tauri::api::notification::Notification::new(
                            &app.config().tauri.bundle.identifier,
                        )
                        .title("Contact Request Accepted!")
                        .body(&format!("{} accepted your request", from_name))
                        .show();
                        let _ = app.emit_all("ego://contact-approved", &contact);
                    }
                }
            } else {
                contacts.retain(|c| !(c.status == "pending_out" && c.shared_key_hex == shared_key));
                let _ = save_contacts(&contacts);
                let _ = tauri::api::notification::Notification::new(
                    &app.config().tauri.bundle.identifier,
                )
                .title("Contact Request Declined")
                .body("Your contact request was declined.")
                .show();
                let _ = app.emit_all("ego://contact-declined", ());
            }
        }

        P2PMessage::PeerAnnounce { address, name, endpoint, endpoints, city, country } => {
            register_known_validator(&address);
            if !endpoint.is_empty() {
                let mut contacts = load_contacts();
                if let Some(c) = contacts.iter_mut().find(|c| c.address == address) {
                    let relay_in   = endpoint.contains("/p2p-circuit");
                    let relay_curr = c.endpoint.contains("/p2p-circuit");
                    if (relay_in || !relay_curr) && c.endpoint != endpoint {
                        eprintln!("[P2P] Updated contact {} endpoint → {}", address, endpoint);
                        c.endpoint = endpoint.clone();
                    }
                    // Store all endpoints for multi-path dialling
                    if !endpoints.is_empty() {
                        c.all_endpoints = endpoints.clone();
                    }
                    let _ = save_contacts(&contacts);
                }
            }
            let state = app.state::<crate::app::AppState>();
            state.upsert_peer(crate::app::PeerInfo {
                address:   address.clone(),
                name,
                endpoint:  endpoint.clone(),
                last_seen: Utc::now().timestamp(),
                city,
                country,
            });
            upsert_peer_cache(PeerEntry {
                address:   address.clone(),
                endpoint:  endpoint.clone(),
                last_seen: Utc::now().timestamp(),
                city:      None,
                country:   None,
            });
            // Chain sync is handled by the dedicated sync_chain_from_peers() loop
            // (runs every 30 s in the keep-alive loop).  Do NOT send a ChainSyncRequest
            // here — PeerAnnounce fires every 60 s per peer, so doing it here was
            // triggering a merge on every tick and inflating the block count.
        }
P2PMessage::ChatMessage { bundle } => {
    match crate::commands::messenger::receive_message_inner(&bundle) {
        Ok((msg, is_new)) => {
            if !is_new {
                // Duplicate delivery (DHT re-poll or multi-path) — skip notification
                return;
            }
            if msg.message_type == "file_bundle" {
                use base64::Engine as _;
                let parts: Vec<&str> = msg.content.splitn(5, ':').collect();
                let file_name = parts.get(3)
                    .and_then(|n| base64::engine::general_purpose::STANDARD.decode(n).ok())
                    .and_then(|b| String::from_utf8(b).ok())
                    .unwrap_or_else(|| "File".to_string());
                // Auto-import into ledger immediately so EgoSafe shows "Received Files"
                // even before the actual FileData arrives from the sender.
                // try_auto_import also shows the "File Received!" notification.
                {
                    let content_clone = msg.content.clone();
                    let from_for_import = msg.from.clone();
                    let app_import = app.clone();
                    tokio::spawn(async move {
                        crate::commands::notifications::try_auto_import(
                            &app_import, &content_clone, &from_for_import,
                        ).await;
                    });
                }
                if parts.len() >= 2 {
                    let cid       = parts[1].to_string();
                    let from_addr = msg.from.clone();
                    let app_clone = app.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        let contacts = load_contacts();
                        let my_ep   = get_public_endpoint().await;
                        let my_addr = crate::ledger::Ledger::load().address;

                        // Choose the right request type based on CID prefix
                        let file_req: P2PMessage = if cid.starts_with("egomfd1") {
                            // Block-based: try DHT manifest first, then ManifestRequest
                            if let Some(tx) = DHT_CMD_TX.get() {
                                let _ = tx.send(DhtCommand::GetPeers {
                                    key: format!("ego-manifest:{}", cid),
                                });
                            }
                            P2PMessage::ManifestRequest {
                                manifest_cid:       cid.clone(),
                                requester_addr:     my_addr.clone(),
                                requester_endpoint: my_ep,
                            }
                        } else {
                            P2PMessage::FileRequest {
                                cid:                cid.clone(),
                                requester_addr:     my_addr.clone(),
                                requester_endpoint: my_ep,
                            }
                        };

                        if let Some(contact) = contacts.iter().find(|c| {
                            c.address == from_addr && !c.endpoint.is_empty()
                        }) {
                            let endpoint = contact.endpoint.clone();
                            if let Err(e) = send_message(&endpoint, &file_req).await {
                                eprintln!("[P2P] Auto file request failed: {} — depositing in sender inbox", e);
                                crate::commands::messenger::deposit_in_relay_inbox(
                                    &from_addr, &my_addr, &file_req,
                                ).await;
                            } else {
                                eprintln!("[P2P] Auto-requested file {} from {}", cid, endpoint);
                            }
                        } else {
                            // Sender not in contacts or no endpoint — go straight to relay inbox
                            eprintln!("[P2P] No direct endpoint for {} — depositing request in relay inbox", from_addr);
                            crate::commands::messenger::deposit_in_relay_inbox(
                                &from_addr, &my_addr, &file_req,
                            ).await;
                        }

                        // ── Timeout watcher: poll every 10s for up to 3 minutes ──
                        let cid_watch = cid.clone();
                        let app_watch = app_clone.clone();
                        tokio::spawn(async move {
                            const POLL_INTERVAL: u64 = 10;
                            const TIMEOUT_SECS:  u64 = 300; // 5 min: enough for 10× DHT polls
                            let mut elapsed = 0u64;
                            loop {
                                tokio::time::sleep(Duration::from_secs(POLL_INTERVAL)).await;
                                elapsed += POLL_INTERVAL;
                                let ledger = crate::ledger::Ledger::load();
                                if let Some(f) = ledger.stored_files.iter().find(|f| f.cid == cid_watch) {
                                    let is_block_complete = f.blocks_total > 0
                                        && f.blocks_received >= f.blocks_total;
                                    let is_legacy_complete = f.status == "Received"
                                        && !f.local_path.is_empty()
                                        && !f.local_path.starts_with("sender:");
                                    if is_block_complete || is_legacy_complete {
                                        eprintln!("[P2P] File {} received OK within {}s", cid_watch, elapsed);
                                        return;
                                    }
                                }
                                if elapsed >= TIMEOUT_SECS {
                                    eprintln!("[P2P] File {} timed out after {}s — marking failed", cid_watch, elapsed);
                                    let mut ledger = crate::ledger::Ledger::load();
                                    if let Some(f) = ledger.stored_files.iter_mut().find(|f| f.cid == cid_watch) {
                                        // Mark failed only if still waiting (no real data yet)
                                        let still_pending = f.local_path.is_empty()
                                            || f.local_path.starts_with("sender:")
                                            || (f.blocks_total > 0 && f.blocks_received < f.blocks_total);
                                        if still_pending {
                                            f.status = "Failed".to_string();
                                            let _ = ledger.save();
                                            let _ = app_watch.emit_all("ego://file-failed", serde_json::json!({
                                                "cid":    cid_watch,
                                                "reason": "File transfer timed out. The sender may be offline."
                                            }));
                                        }
                                    }
                                    return;
                                }
                            }
                        });
                    });
                }
            } else {
                // Only show "New Message" notification for text messages.
                {
                    let state = app.state::<crate::app::AppState>();
                    *state.pending_chat_address.lock().unwrap() = Some(msg.from.clone());
                }
                let preview = if msg.content.len() > 40 {
                    format!("{}…", &msg.content[..40])
                } else {
                    msg.content.clone()
                };
                let _ = tauri::api::notification::Notification::new(
                    &app.config().tauri.bundle.identifier,
                )
                .title("New Message")
                .body(&preview)
                .show();
            }
            let _ = app.emit_all("ego://message-received", &msg);
        }
        Err(e) => eprintln!("[P2P] Decrypt error: {}", e),
    }
}

        P2PMessage::TxBroadcast { tx, block } => {
            apply_incoming_tx(tx, block, app).await;
        }

        P2PMessage::BlockProposal { block, transactions, proposer, .. } => {
            register_known_validator(&proposer);
            handle_block_proposal(block, transactions, proposer, app).await;
        }

        P2PMessage::BlockVote { block_hash, height, voter, signature, timestamp } => {
            register_known_validator(&voter);
            handle_block_vote(block_hash, height, voter, signature, timestamp, app).await;
        }

        P2PMessage::BlockFinalized { block, transactions, .. } => {
            merge_remote_chain(vec![block], transactions, app).await;
        }

        P2PMessage::ChainSyncRequest { requester_endpoint } => {
            let chain    = load_chain();
            let response = P2PMessage::ChainSyncResponse {
                blocks:       chain.blocks,
                transactions: chain.transactions,
            };
            tokio::spawn(async move {
                let eps = vec![requester_endpoint.clone()];
                if let Err(e) = send_message_any(&eps, &response).await {
                    eprintln!("[P2P] chain sync reply: {}", e);
                }
            });
        }

        P2PMessage::ChainSyncResponse { blocks, transactions } => {
            merge_remote_chain(blocks, transactions, app).await;
        }

        // ── Phase 2: shard data replication ──────────────────────────────────
        P2PMessage::ShardDataRequest { shard_id, from_height, requester_address: _, requester_endpoint } => {
            let chain = load_chain();
            let map   = crate::sharding::load_shard_map();
            let (blocks, txs) = crate::sharding::get_shard_blocks(shard_id, from_height, &chain, &map);
            let response = P2PMessage::ShardDataResponse { shard_id, blocks, transactions: txs };
            tokio::spawn(async move {
                if let Err(e) = send_message_any(&[requester_endpoint.clone()], &response).await {
                    eprintln!("[Sharding] shard data reply to {}: {}", requester_endpoint, e);
                }
            });
        }

        P2PMessage::ShardDataResponse { shard_id, blocks, transactions } => {
            eprintln!("[Sharding] received {} blocks for shard {}", blocks.len(), shard_id);
            merge_remote_chain(blocks, transactions, app).await;
        }

        P2PMessage::ShardBlockQuery { block_height, requester_address: _, requester_endpoint } => {
            let chain = load_chain();
            let map   = crate::sharding::load_shard_map();
            let shard_id = crate::sharding::shard_for_height(
                block_height, map.total_blocks.max(1), map.shard_count
            );
            let (blocks, txs) = crate::sharding::get_shard_blocks(shard_id, block_height.saturating_sub(1), &chain, &map);
            let resp = P2PMessage::ShardBlockResponse { block_height, blocks, transactions: txs };
            tokio::spawn(async move {
                let _ = send_message_any(&[requester_endpoint.clone()], &resp).await;
            });
        }

        P2PMessage::ShardBlockResponse { block_height: _, blocks, transactions } => {
            merge_remote_chain(blocks, transactions, app).await;
        }

        P2PMessage::ShardVacancyNotice { shard_id, current_holders } => {
            // Phase 3: if replication factor not met and we can help, volunteer
            if current_holders < crate::sharding::REPLICATION_FACTOR {
                let my_addr = crate::ledger::Ledger::load().address;
                if my_addr.is_empty() { return; }
                let my_ep = get_public_endpoint().await;
                let map   = crate::sharding::load_shard_map();
                if crate::sharding::should_volunteer_for_shard(shard_id, &my_addr, &map) {
                    let volunteer = P2PMessage::ShardVolunteer {
                        shard_id,
                        volunteer_address:  my_addr,
                        volunteer_endpoint: my_ep,
                    };
                    if let Ok(data) = serde_json::to_vec(&volunteer) {
                        publish_gossip("ego-shards-v1", data).await;
                    }
                }
            }
        }

        P2PMessage::ShardVolunteer { shard_id, volunteer_address, volunteer_endpoint } => {
            // Master for this shard: accept the volunteer as a new slave
            let my_addr = crate::ledger::Ledger::load().address;
            if my_addr.is_empty() { return; }
            let map = crate::sharding::load_shard_map();
            let all_nodes: Vec<String> = map.assignments.iter()
                .map(|a| a.node_address.clone())
                .collect::<std::collections::HashSet<_>>()
                .into_iter().collect();
            let is_master = crate::sharding::my_shards(&my_addr, &map, &all_nodes)
                .iter().any(|(sid, role)| *sid == shard_id && *role == crate::sharding::ShardRole::Master);
            if !is_master { return; }

            eprintln!("[Sharding] Volunteer accepted: {} for shard {}", volunteer_address, shard_id);

            // Update shard map
            let mut updated = crate::sharding::load_shard_map();
            updated.assignments.retain(|a| !(a.shard_id == shard_id && a.node_address == volunteer_address));
            updated.assignments.push(crate::sharding::ShardAssignment {
                shard_id,
                role:          crate::sharding::ShardRole::Slave,
                node_address:  volunteer_address.clone(),
                node_endpoint: volunteer_endpoint.clone(),
                last_seen:     chrono::Utc::now().timestamp(),
                uptime_secs:   0,
            });
            let _ = crate::sharding::save_shard_map(&updated);

            // Push shard data to the new volunteer
            let chain      = load_chain();
            let (blocks, txs) = crate::sharding::get_shard_blocks(shard_id, 0, &chain, &updated);
            let resp = P2PMessage::ShardDataResponse { shard_id, blocks, transactions: txs };
            tokio::spawn(async move {
                let _ = send_message_any(&[volunteer_endpoint.clone()], &resp).await;
            });
        }

        P2PMessage::PeerListRequest { requester_endpoint } => {
            let peers    = load_peer_cache();
            let response = P2PMessage::PeerListResponse { peers };
            tokio::spawn(async move {
                let eps = vec![requester_endpoint.clone()];
                if let Err(e) = send_message_any(&eps, &response).await {
                    eprintln!("[P2P] peer list reply: {}", e);
                }
            });
        }

        P2PMessage::PeerListResponse { peers } => {
            let my_ep = get_public_endpoint().await;
            for peer in peers {
                if peer.endpoint.is_empty() || peer.endpoint == my_ep { continue; }
                upsert_peer_cache(PeerEntry {
                    address:   peer.address,
                    endpoint:  peer.endpoint,
                    last_seen: Utc::now().timestamp(),
                    city:      None,
                    country:   None,
                });
            }
        }

P2PMessage::FileRequest { cid, requester_addr, requester_endpoint } => {
    eprintln!("[P2P] FileRequest for {} from {} at {}", cid, requester_addr, requester_endpoint);
    let ledger  = crate::ledger::Ledger::load();
    let my_addr = ledger.address.clone();

    if let Some(file) = ledger.stored_files.iter().find(|f| f.cid == cid).cloned() {
        if file.local_path.is_empty() || file.local_path.starts_with("sender:") {
            eprintln!("[P2P] FileRequest: we don't have the data for {}", cid);
            return;
        }

        // Block-based file: respond with ManifestData so receiver can fetch blocks
        if cid.starts_with("egomfd1") {
            let ep = requester_endpoint.clone();
            let addr = requester_addr.clone();
            let key_hex64 = file.key_nonce_hex.clone();
            let file_name = file.name.clone();
            tokio::spawn(async move {
                match crate::blocks::load_manifest(&cid) {
                    Err(e) => eprintln!("[P2P] ManifestData: load failed: {}", e),
                    Ok(manifest) => {
                        match serde_json::to_string(&manifest) {
                            Err(e) => eprintln!("[P2P] ManifestData: serialize failed: {}", e),
                            Ok(manifest_json) => {
                                let response = P2PMessage::ManifestData {
                                    manifest_cid: cid.clone(),
                                    manifest_json,
                                    key_hex64,
                                    file_name,
                                    from_addr: my_addr.clone(),
                                };
                                let eps = vec![ep.clone()];
                                if let Err(e) = send_message_any(&eps, &response).await {
                                    eprintln!("[P2P] ManifestData direct failed: {} — relay inbox", e);
                                    crate::commands::messenger::deposit_in_relay_inbox(
                                        &addr, &my_addr, &response,
                                    ).await;
                                } else {
                                    eprintln!("[P2P] ManifestData sent for {} ({} blocks)", &cid[..16], manifest.blocks.len());
                                }
                            }
                        }
                    }
                }
            });
            return;
        }

        // Legacy single-file: send FileData
        match std::fs::read(&file.local_path) {
            Err(e) => eprintln!("[P2P] FileRequest: read failed {}: {}", file.local_path, e),
            Ok(enc_bytes) => {
                use base64::Engine as _;
                let key_nonce_hex = file.key_nonce_hex.clone();
                let file_name     = file.name.clone();
                let cid2          = cid.clone();
                let ep            = requester_endpoint.clone();
                let addr          = requester_addr.clone();

                const RELAY_LIMIT: usize = 50 * 1024 * 1024; // 50 MB — relay cap

                tokio::spawn(async move {
                    if enc_bytes.len() > RELAY_LIMIT {
                        eprintln!("[P2P] File too large ({} bytes) — 50 MB max", enc_bytes.len());
                        return;
                    }

                    let enc_data_b64 = base64::engine::general_purpose::STANDARD.encode(&enc_bytes);
                    let response = P2PMessage::FileData {
                        cid:           cid2.clone(),
                        enc_data_b64,
                        file_name,
                        key_nonce_hex,
                    };

                    // Try direct P2P; fall back to DHT relay inbox
                    let eps = vec![ep.clone()];
                    if let Err(e) = send_message_any(&eps, &response).await {
                        eprintln!("[P2P] FileData direct failed: {} — relay inbox", e);
                        crate::commands::messenger::deposit_in_relay_inbox(
                            &addr, &my_addr, &response,
                        ).await;
                    } else {
                        eprintln!("[P2P] FileData sent OK for {}", cid2);
                    }
                });
            }
        }
    } else {
        eprintln!("[P2P] FileRequest: CID {} not found in our ledger", cid);
    }
}

        P2PMessage::ShardAnnounce { from_addr, from_endpoint, held_shards, uptime_secs, network_node_count, shard_count } => {
            crate::sharding::handle_shard_announce_update(&from_addr, &from_endpoint, &held_shards, uptime_secs, network_node_count, shard_count);
        }

        P2PMessage::MasterPromotion { shard_id, new_master, new_endpoint, former_master, timestamp } => {
            eprintln!("[Sharding] MasterPromotion (direct): shard {} → new master {} (was {})", shard_id, new_master, former_master);
            let mut map = crate::sharding::load_shard_map();
            if let Some(old) = map.assignments.iter_mut().find(|a| a.shard_id == shard_id && a.node_address == former_master) {
                old.role = crate::sharding::ShardRole::Observer;
            }
            if let Some(new_m) = map.assignments.iter_mut().find(|a| a.shard_id == shard_id && a.node_address == new_master) {
                new_m.role = crate::sharding::ShardRole::Master;
                new_m.node_endpoint = new_endpoint.clone();
                new_m.last_seen = timestamp;
            } else {
                map.assignments.push(crate::sharding::ShardAssignment {
                    shard_id,
                    role: crate::sharding::ShardRole::Master,
                    node_address: new_master,
                    node_endpoint: new_endpoint,
                    last_seen: timestamp,
                    uptime_secs: 0,
                });
            }
            let _ = crate::sharding::save_shard_map(&map);
        }

P2PMessage::FileData { cid, enc_data_b64, file_name, key_nonce_hex } => {
    use base64::Engine as _;
    eprintln!("[P2P] FileData received for {} ({} chars b64)", cid, enc_data_b64.len());
    match base64::engine::general_purpose::STANDARD.decode(&enc_data_b64) {
        Err(e) => eprintln!("[P2P] FileData decode failed: {}", e),
        Ok(enc_bytes) => {
            let storage  = crate::ledger::storage_dir();
            let short    = &cid[cid.len().saturating_sub(16)..];
            let enc_path = storage.join(format!("{}.enc", short));
            if let Err(e) = std::fs::write(&enc_path, &enc_bytes) {
                eprintln!("[P2P] FileData write failed: {}", e);
                return;
            }
            let mut ledger = crate::ledger::Ledger::load();
            let enc_str    = enc_path.to_string_lossy().to_string();
            if let Some(f) = ledger.stored_files.iter_mut().find(|f| f.cid == cid) {
                f.local_path = enc_str.clone();
                if !key_nonce_hex.is_empty() { f.key_nonce_hex = key_nonce_hex.clone(); }
                if f.name.is_empty() { f.name = file_name.clone(); }
                f.status = "Received".to_string(); // ← add this
            } else {
                // Not yet in ledger (race) — create entry
                let now = chrono::Utc::now().timestamp();
                ledger.stored_files.push(crate::ledger::StoredFile {
                    cid:             cid.clone(),
                    name:            file_name,
                    original_size:   enc_bytes.len() as u64,
                    encrypted_size:  enc_bytes.len() as u64,
                    duration_months: 0,
                    stored_at:       now,
                    expiry:          0,
                    status:          "Received".to_string(),
                    key_nonce_hex,
                    local_path:      enc_str,
                    owner:           String::new(),
                    ..Default::default()
                });
            }
            let _ = ledger.save();
            eprintln!("[P2P] FileData saved for {}", cid);
            let _ = app.emit_all("ego://file-downloaded", serde_json::json!({ "cid": cid }));
        }
    }
}

        // ── Block-based file transfer (IPFS-style) ────────────────────────────

        P2PMessage::ManifestRequest { manifest_cid, requester_addr, requester_endpoint } => {
            eprintln!("[Blocks] ManifestRequest for {} from {}", &manifest_cid[..16.min(manifest_cid.len())], requester_addr);
            let ledger  = crate::ledger::Ledger::load();
            let my_addr = ledger.address.clone();
            if let Some(file) = ledger.stored_files.iter().find(|f| f.cid == manifest_cid).cloned() {
                let ep      = requester_endpoint.clone();
                let addr    = requester_addr.clone();
                tokio::spawn(async move {
                    match crate::blocks::load_manifest(&manifest_cid) {
                        Err(e) => eprintln!("[Blocks] ManifestRequest: load failed: {}", e),
                        Ok(manifest) => {
                            match serde_json::to_string(&manifest) {
                                Err(e) => eprintln!("[Blocks] ManifestRequest: serialize: {}", e),
                                Ok(manifest_json) => {
                                    let response = P2PMessage::ManifestData {
                                        manifest_cid: manifest_cid.clone(),
                                        manifest_json,
                                        key_hex64:   file.key_nonce_hex,
                                        file_name:   file.name,
                                        from_addr:   my_addr.clone(),
                                    };
                                    let eps = vec![ep.clone()];
                                    if let Err(e) = send_message_any(&eps, &response).await {
                                        eprintln!("[Blocks] ManifestData direct failed: {} — inbox", e);
                                        crate::commands::messenger::deposit_in_relay_inbox(&addr, &my_addr, &response).await;
                                    }
                                }
                            }
                        }
                    }
                });
            }
        }

        P2PMessage::ManifestData { manifest_cid, manifest_json, key_hex64, file_name, from_addr } => {
            eprintln!("[Blocks] ManifestData received for {}", &manifest_cid[..16.min(manifest_cid.len())]);
            match serde_json::from_str::<crate::blocks::FileManifest>(&manifest_json) {
                Err(e) => eprintln!("[Blocks] ManifestData parse error: {}", e),
                Ok(manifest) => {
                    // Persist the manifest to disk
                    let _ = crate::blocks::save_manifest(&manifest);
                    let blocks_total = manifest.blocks.len() as u32;
                    // Update ledger entry
                    {
                        let mut ledger = crate::ledger::Ledger::load();
                        let my_addr    = ledger.address.clone();
                        if let Some(f) = ledger.stored_files.iter_mut().find(|f| f.cid == manifest_cid) {
                            f.key_nonce_hex  = key_hex64.clone();
                            f.blocks_total   = blocks_total;
                            f.blocks_received = crate::blocks::blocks_received_count(&manifest);
                            f.manifest_cid   = manifest_cid.clone();
                            if f.name.is_empty() { f.name = file_name.clone(); }
                            let _ = ledger.save();
                        }
                    }
                    // Request each missing block directly from the sender
                    let missing = crate::blocks::missing_blocks(&manifest);
                    eprintln!("[Blocks] Need {}/{} blocks for {}", missing.len(), blocks_total, &manifest_cid[..16.min(manifest_cid.len())]);
                    let my_addr    = crate::ledger::Ledger::load().address;
                    let my_ep      = get_public_endpoint().await;
                    // Try to find sender endpoint
                    let sender_ep = {
                        let contacts = load_contacts();
                        contacts.iter().find(|c| c.address == from_addr)
                            .map(|c| c.endpoint.clone())
                            .unwrap_or_default()
                    };
                    for block_cid in missing {
                        let req = P2PMessage::BlockRequest {
                            block_cid:          block_cid.clone(),
                            manifest_cid:       manifest_cid.clone(),
                            requester_addr:     my_addr.clone(),
                            requester_endpoint: my_ep.clone(),
                        };
                        // 1. Try DHT global store (PutPeer'd by sender on upload)
                        if let Some(tx) = crate::p2p::DHT_CMD_TX.get() {
                            let dht_key = format!("ego-block:{}", block_cid);
                            let _ = tx.send(crate::p2p::DhtCommand::GetPeers { key: dht_key });
                        }
                        // 2. Try direct P2P if we have sender's endpoint
                        if !sender_ep.is_empty() {
                            let ep2  = sender_ep.clone();
                            let req2 = req.clone();
                            tokio::spawn(async move {
                                let _ = send_message_any(&[ep2], &req2).await;
                            });
                        }
                        // 3. ALWAYS deposit BlockRequest in sender's DHT inbox.
                        //    This guarantees delivery even when sender is offline or
                        //    block was uploaded before DHT publishing was added.
                        //    Sender will respond with BlockData via receiver's inbox.
                        {
                            let from2   = from_addr.clone();
                            let myaddr2 = my_addr.clone();
                            let req3    = req.clone();
                            tokio::spawn(async move {
                                crate::commands::messenger::deposit_in_relay_inbox(
                                    &from2, &myaddr2, &req3,
                                ).await;
                                eprintln!("[Blocks] BlockRequest deposited in sender inbox for {}",
                                    &block_cid[..16.min(block_cid.len())]);
                            });
                        }
                    }
                }
            }
        }

        P2PMessage::BlockRequest { block_cid, manifest_cid, requester_addr, requester_endpoint } => {
            eprintln!("[Blocks] BlockRequest for {} from {}", &block_cid[..16.min(block_cid.len())], requester_addr);
            if crate::blocks::have_block(&block_cid) {
                use base64::Engine as _;
                match crate::blocks::load_block(&block_cid) {
                    Err(e) => eprintln!("[Blocks] BlockRequest: load failed: {}", e),
                    Ok(enc_bytes) => {
                        // Also publish to DHT global store so receiver can fetch directly
                        // without depending on the inbox relay completing.
                        if let Some(tx) = DHT_CMD_TX.get() {
                            let dht_key = format!("ego-block:{}", block_cid);
                            let _ = tx.send(DhtCommand::PutPeer { key: dht_key, value: enc_bytes.clone() });
                            eprintln!("[Blocks] Block {} published to DHT global store", &block_cid[..16.min(block_cid.len())]);
                        }
                        let enc_b64    = base64::engine::general_purpose::STANDARD.encode(&enc_bytes);
                        let my_addr    = crate::ledger::Ledger::load().address;
                        let ep         = requester_endpoint.clone();
                        let addr       = requester_addr.clone();
                        let response = P2PMessage::BlockData {
                            block_cid:    block_cid.clone(),
                            manifest_cid: manifest_cid.clone(),
                            enc_b64,
                            from_addr:    my_addr.clone(),
                        };
                        tokio::spawn(async move {
                            if let Err(e) = send_message_any(&[ep.clone()], &response).await {
                                eprintln!("[Blocks] BlockData direct failed: {} — inbox", e);
                                crate::commands::messenger::deposit_in_relay_inbox(&addr, &my_addr, &response).await;
                            } else {
                                eprintln!("[Blocks] BlockData sent: {}", &block_cid[..16.min(block_cid.len())]);
                            }
                        });
                    }
                }
            } else {
                eprintln!("[Blocks] BlockRequest: block {} not found", &block_cid[..16.min(block_cid.len())]);
            }
        }

        P2PMessage::BlockData { block_cid, manifest_cid, enc_b64, from_addr: _ } => {
            use base64::Engine as _;
            eprintln!("[Blocks] BlockData received: {}", &block_cid[..16.min(block_cid.len())]);
            match base64::engine::general_purpose::STANDARD.decode(&enc_b64) {
                Err(e) => eprintln!("[Blocks] BlockData decode failed: {}", e),
                Ok(enc_bytes) => {
                    if !crate::blocks::have_block(&block_cid) {
                        let _ = crate::blocks::save_block(&block_cid, &enc_bytes);
                    }
                    // Update blocks_received counter and emit progress
                    let app2 = app.clone();
                    let mcid = manifest_cid.clone();
                    tokio::spawn(async move {
                        update_ledger_for_block(&mcid, &app2).await;
                    });
                }
            }
        }
    }
}


// ── Block storage helpers ─────────────────────────────────────────────────────

/// Called after saving a new block to disk.  Updates `blocks_received` in the
/// ledger and emits `ego://file-downloaded` when all blocks are present.
async fn update_ledger_for_block(manifest_cid: &str, app: &tauri::AppHandle) {
    let Ok(manifest) = crate::blocks::load_manifest(manifest_cid) else { return; };
    let received = crate::blocks::blocks_received_count(&manifest);
    let total    = manifest.blocks.len() as u32;

    let mut ledger = crate::ledger::Ledger::load();
    if let Some(f) = ledger.stored_files.iter_mut().find(|f| f.cid == manifest_cid) {
        f.blocks_received = received;
        if received >= total {
            f.status     = "Received".to_string();
            f.local_path = crate::blocks::manifest_path(manifest_cid)
                .to_string_lossy().to_string();
        }
        let _ = ledger.save();
    }

    let _ = app.emit_all("ego://block-progress", serde_json::json!({
        "manifest_cid": manifest_cid,
        "blocks_received": received,
        "blocks_total": total,
    }));

    if received >= total {
        eprintln!("[Blocks] All {} blocks received for {}", total, &manifest_cid[..16.min(manifest_cid.len())]);
        let _ = app.emit_all("ego://file-downloaded", serde_json::json!({ "cid": manifest_cid }));
    }
}

/// Called when a manifest arrives (from DHT or ManifestData message).
/// Kicks off requests for any missing blocks.
async fn process_received_manifest(manifest_cid: &str, app: &tauri::AppHandle) {
    let Ok(manifest) = crate::blocks::load_manifest(manifest_cid) else { return; };
    let total    = manifest.blocks.len() as u32;
    let received = crate::blocks::blocks_received_count(&manifest);

    // Update ledger
    {
        let mut ledger = crate::ledger::Ledger::load();
        if let Some(f) = ledger.stored_files.iter_mut().find(|f| f.cid == manifest_cid) {
            f.blocks_total    = total;
            f.blocks_received = received;
            f.manifest_cid    = manifest_cid.to_string();
            let _ = ledger.save();
        }
    }

    // Emit progress
    let _ = app.emit_all("ego://block-progress", serde_json::json!({
        "manifest_cid": manifest_cid,
        "blocks_received": received,
        "blocks_total": total,
    }));

    if received >= total {
        let _ = app.emit_all("ego://file-downloaded", serde_json::json!({ "cid": manifest_cid }));
        return;
    }

    // Get sender address from ledger (local_path = "sender:{addr}")
    let sender_addr = {
        let ledger = crate::ledger::Ledger::load();
        ledger.stored_files.iter()
            .find(|f| f.cid == manifest_cid)
            .and_then(|f| f.local_path.strip_prefix("sender:"))
            .map(|s| s.to_string())
            .unwrap_or_default()
    };
    let my_addr = crate::ledger::Ledger::load().address;
    let my_ep   = get_public_endpoint().await;

    for block_cid in crate::blocks::missing_blocks(&manifest) {
        // 1. DHT global store
        if let Some(tx) = DHT_CMD_TX.get() {
            let _ = tx.send(DhtCommand::GetPeers { key: format!("ego-block:{}", block_cid) });
        }
        // 2. BlockRequest in sender's DHT inbox (works even if sender offline or
        //    block was never published to DHT)
        if !sender_addr.is_empty() {
            let req = P2PMessage::BlockRequest {
                block_cid:          block_cid.clone(),
                manifest_cid:       manifest_cid.to_string(),
                requester_addr:     my_addr.clone(),
                requester_endpoint: my_ep.clone(),
            };
            let sender2 = sender_addr.clone();
            let my2     = my_addr.clone();
            let bcid    = block_cid.clone();
            tokio::spawn(async move {
                crate::commands::messenger::deposit_in_relay_inbox(&sender2, &my2, &req).await;
                eprintln!("[Blocks] BlockRequest→inbox for {}", &bcid[..16.min(bcid.len())]);
            });
        }
    }
}

/// After a block is saved, check if it completes any manifest we're waiting on.
async fn check_block_completes_manifests(block_cid: &str, app: &tauri::AppHandle) {
    let ledger = crate::ledger::Ledger::load();
    for file in &ledger.stored_files {
        if file.cid.starts_with("egomfd1") && file.blocks_received < file.blocks_total {
            if let Ok(manifest) = crate::blocks::load_manifest(&file.cid) {
                let has_this = manifest.blocks.iter().any(|b| b.block_cid == block_cid);
                if has_this {
                    let mcid = file.cid.clone();
                    let app2 = app.clone();
                    tokio::spawn(async move {
                        update_ledger_for_block(&mcid, &app2).await;
                    });
                }
            }
        }
    }
}

// ── Chain helpers ─────────────────────────────────────────────────────────────

/// Validate a block received from a remote peer before accepting it into the local chain.
/// Returns true if the block is structurally valid according to consensus rules.
fn validate_block(block: &crate::ledger::LedgerBlock, chain: &crate::ledger::SharedChain) -> bool {
    // 1. Genesis block is always valid.
    if block.height == 0 {
        return block.hash == crate::ledger::GENESIS_HASH;
    }

    // 2. Must connect to a known previous block.
    let prev_exists = chain.blocks.iter().any(|b| b.hash == block.prev_hash);
    if !prev_exists {
        eprintln!("[Validate] Block #{} rejected: unknown prev_hash {}", block.height, block.prev_hash);
        return false;
    }

    // 3. No duplicate hash — not an error, just skip.
    if chain.blocks.iter().any(|b| b.hash == block.hash) {
        return false;
    }

    // 4. Reward must match halving schedule (or be zero for non-coinbase blocks).
    let expected_reward = crate::tokenomics::block_reward_at(block.height);
    if block.reward != expected_reward && block.reward != 0 {
        eprintln!("[Validate] Block #{} rejected: reward {} != expected {}",
            block.height, block.reward, expected_reward);
        return false;
    }

    // 5. If coinbase_tx is set, verify it exists and pays the right amount to the miner.
    if let Some(ref cb_hash) = block.coinbase_tx {
        let cb_tx = chain.transactions.iter().find(|t| &t.hash == cb_hash);
        match cb_tx {
            Some(tx) => {
                if tx.to != block.miner || tx.amount != expected_reward {
                    eprintln!("[Validate] Block #{} rejected: invalid coinbase tx (to={}, amount={}, miner={}, expected={})",
                        block.height, tx.to, tx.amount, block.miner, expected_reward);
                    return false;
                }
            }
            None => {
                // Coinbase TX may not have arrived yet in this gossip batch — allow if reward=0
                // to avoid rejecting blocks whose coinbase TX arrives alongside the block.
                if block.reward != 0 {
                    eprintln!("[Validate] Block #{} rejected: coinbase TX {} not found",
                        block.height, cb_hash);
                    return false;
                }
            }
        }
    }

    true
}

async fn apply_incoming_tx(tx: LedgerTx, block: LedgerBlock, app: &tauri::AppHandle) {
    if block.height == 0 { return; } // genesis already seeded locally
    // Persist to SQLite — INSERT OR IGNORE deduplicates automatically.
    // save_chain() is a no-op stub; chain_db is the single source of truth.
    crate::chain_db::append_peer_block(&block, &[tx]);
    let _ = app.emit_all("ego://chain-updated", ());
}

/// Execute any Deploy or Call transactions from incoming blocks.
/// Called on every node when new blocks are finalized — this is how
/// contract state stays in sync across the network without a central executor.
fn execute_contract_txs(chain: &crate::ledger::SharedChain, txs: &[crate::ledger::LedgerTx]) {
    let height    = chain.blocks.last().map(|b| b.height).unwrap_or(0);
    let timestamp = chrono::Utc::now().timestamp();
    let contracts_dir = crate::ledger::contracts_dir();

    let exec = match ego_vm::Executor::new(contracts_dir) {
        Ok(e)  => e,
        Err(e) => { eprintln!("[VM] Executor init failed: {}", e); return; }
    };

    for tx in txs {
        match tx.tx_type.as_str() {
            "deploy" => {
                if tx.wasm_code.is_empty() { continue; }
                let wasm_bytes = match hex::decode(&tx.wasm_code) {
                    Ok(b)  => b,
                    Err(_) => continue,
                };
                let init_args = hex::decode(&tx.call_args).unwrap_or_default();
                match exec.deploy(&wasm_bytes, &tx.from, &init_args, height, timestamp,
                                  ego_vm::types::DEFAULT_DEPLOY_FUEL) {
                    Ok(r)  => eprintln!("[VM] Deployed contract {} (RU={})", r.contract_address, r.ru_used),
                    Err(e) => eprintln!("[VM] Deploy failed for tx {}: {}", tx.hash, e),
                }
            }
            "call" => {
                if tx.contract_addr.is_empty() || tx.entrypoint.is_empty() { continue; }
                let call_args = hex::decode(&tx.call_args).unwrap_or_default();
                match exec.call(&tx.contract_addr, &tx.from, &tx.entrypoint,
                                &call_args, height, timestamp,
                                ego_vm::types::DEFAULT_CALL_FUEL) {
                    Ok(r)  => eprintln!("[VM] Called {}.{}() — success={} RU={}",
                                        tx.contract_addr, tx.entrypoint, r.success, r.ru_used),
                    Err(e) => eprintln!("[VM] Call failed for tx {}: {}", tx.hash, e),
                }
            }
            _ => {}
        }
    }
}

async fn merge_remote_chain(
    blocks: Vec<LedgerBlock>, transactions: Vec<LedgerTx>, app: &tauri::AppHandle,
) {
    merge_remote_chain_inner(blocks, transactions, app, false).await;
}

async fn merge_remote_chain_trusted(
    blocks: Vec<LedgerBlock>, transactions: Vec<LedgerTx>, app: &tauri::AppHandle,
) {
    merge_remote_chain_inner(blocks, transactions, app, true).await;
}

async fn merge_remote_chain_inner(
    blocks: Vec<LedgerBlock>, transactions: Vec<LedgerTx>, app: &tauri::AppHandle,
    trusted: bool,
) {
    // chain_db is the single source of truth (SQLite). The JSON ledger is legacy.
    // All incoming blocks/txs go directly into SQLite via append_peer_block.
    // INSERT OR IGNORE handles deduplication; no in-memory dedup needed.
    let mut new_txs: Vec<LedgerTx> = Vec::new();
    let mut new_blocks: Vec<LedgerBlock> = Vec::new();

    // Collect blocks that pass validation (or are from trusted source).
    // validate_block reads from load_chain() which is an in-memory JSON chain.
    // For peer gossip, skip prev_hash validation — SQLite is the real chain;
    // the JSON chain is always empty so prev_hash check always fails for height>0.
    for block in blocks {
        if block.height == 0 { continue; } // genesis seeded locally
        if trusted {
            new_blocks.push(block);
        } else {
            // Only check reward and duplicate; skip prev_hash (JSON chain is empty).
            let expected_reward = crate::tokenomics::block_reward_at(block.height);
            let reward_ok = block.reward == expected_reward || block.reward == 0;
            if reward_ok {
                new_blocks.push(block);
            } else {
                eprintln!("[P2P] Block #{} rejected: reward {} != expected {}",
                    block.height, block.reward, expected_reward);
            }
        }
    }

    for tx in transactions {
        new_txs.push(tx);
    }

    if new_blocks.is_empty() && new_txs.is_empty() { return; }

    // Write to SQLite. Each block with its matching txs.
    for block in &new_blocks {
        let block_txs: Vec<LedgerTx> = new_txs.iter()
            .filter(|tx| tx.block_height == Some(block.height))
            .cloned()
            .collect();
        crate::chain_db::append_peer_block(block, &block_txs);
    }
    // Txs that arrived without a matching block (e.g. staking TXs whose block lives
    // only in the sender's in-memory chain) — mine them locally so balance_of() sees
    // them.  But skip any TX already present in RocksDB to avoid inflating the block
    // count on every sync (was the main driver of the ~155-block explosion).
    let orphan_txs: Vec<LedgerTx> = new_txs.iter()
        .filter(|tx| {
            !new_blocks.iter().any(|b| Some(b.height) == tx.block_height)
                && tx.hash.len() > 0
                && crate::chain_db::get_tx_by_hash(&tx.hash).is_none()
        })
        .cloned()
        .collect();
    if !orphan_txs.is_empty() {
        let miner = new_blocks.first().map(|b| b.miner.as_str()).unwrap_or("remote");
        crate::chain_db::mine_batch_db(&orphan_txs, miner);
    }

    // Build a minimal chain for execute_contract_txs (only needs block height/timestamp).
    let mut chain = load_chain();
    chain.blocks.extend(new_blocks.clone());
    execute_contract_txs(&chain, &new_txs);
    let _ = app.emit_all("ego://chain-updated", ());
}

// ── Oracle RPC chain sync ─────────────────────────────────────────────────────

/// Fetch the canonical chain from the Oracle RPC node and merge it locally.
/// Replaces fetch_chain_from_relay — no HTTP relay required.
/// Push every local block and transaction to the Oracle node so the public
/// explorer stays in sync. Runs on startup and every 30 s. The Oracle node
/// deduplicates by height/hash so this is safe to call repeatedly.
pub async fn oracle_sync_chain() {
    let chain = load_chain();
    if chain.blocks.is_empty() && chain.transactions.is_empty() { return; }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .unwrap_or_default();
    for block in &chain.blocks {
        if let Ok(body) = serde_json::to_value(block) {
            let _ = client.post(format!("{}/block/broadcast", ORACLE_RPC))
                .json(&body).send().await;
        }
    }
    for tx in &chain.transactions {
        if let Ok(body) = serde_json::to_value(tx) {
            let _ = client.post(format!("{}/tx/broadcast", ORACLE_RPC))
                .json(&body).send().await;
        }
    }
    eprintln!("[Oracle] Synced {} blocks, {} txs to Oracle explorer",
        chain.blocks.len(), chain.transactions.len());
}

pub async fn fetch_chain_from_oracle(app: &tauri::AppHandle) {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    // Fetch blocks
    let blocks_url = format!("{}/chain/blocks", ORACLE_RPC);
    let blocks: Vec<crate::ledger::LedgerBlock> = match client.get(&blocks_url).send().await {
        Ok(resp) => resp.json().await.unwrap_or_default(),
        Err(e) => { eprintln!("[Oracle] fetch blocks: {}", e); vec![] }
    };

    // Fetch transactions
    let txs_url = format!("{}/chain/transactions", ORACLE_RPC);
    let transactions: Vec<crate::ledger::LedgerTx> = match client.get(&txs_url).send().await {
        Ok(resp) => resp.json().await.unwrap_or_default(),
        Err(e) => { eprintln!("[Oracle] fetch txs: {}", e); vec![] }
    };

    if blocks.is_empty() && transactions.is_empty() {
        eprintln!("[Oracle] chain empty or unreachable — skipping merge");
        return;
    }

    merge_remote_chain_trusted(blocks, transactions, app).await;
    eprintln!("[Oracle] Chain merged from Oracle RPC (trusted)");
}

// ── BFT voting round ─────────────────────────────────────────────────────────

/// Sign a payload with our Ed25519 key. Returns hex(signature).
fn bft_sign(data: &str) -> Option<String> {
    let seed_bytes = std::fs::read(crate::ledger::seed_path()).ok()
        .filter(|b| b.len() == 32)?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let kp = ego_core::KeyPair::from_bytes(&seed).ok()?;
    let sig = kp.sign_ed25519(data.as_bytes());
    Some(hex::encode(sig.as_bytes()))
}

/// Called when we receive a BlockProposal from a peer.
/// Validate it, then cast and broadcast a signed vote.
async fn handle_block_proposal(
    block: LedgerBlock,
    transactions: Vec<LedgerTx>,
    proposer: String,
    app: &tauri::AppHandle,
) {
    let chain = load_chain();

    // Validate the proposed block
    if !validate_block(&block, &chain) {
        eprintln!("[BFT] Rejected proposal for block #{} from {}", block.height, proposer);
        return;
    }

    // Don't vote twice for the same block_hash
    {
        let my_addr = crate::ledger::Ledger::load().address;
        let votes = pending_votes();
        if let Some(voters) = votes.get(&block.hash) {
            if voters.contains(&my_addr) {
                return; // already voted
            }
        }
    }

    eprintln!("[BFT] Valid proposal block #{} from {} — casting vote", block.height, proposer);

    // Store proposal transactions locally so coinbase check works when finalizing
    {
        let mut chain2 = load_chain();
        let mut changed = false;
        for tx in &transactions {
            if !chain2.transactions.iter().any(|t| t.hash == tx.hash) {
                chain2.transactions.push(tx.clone());
                changed = true;
            }
        }
        if changed { let _ = crate::ledger::save_chain(&chain2); }
    }

    // Cast our vote
    let my_addr = crate::ledger::Ledger::load().address;
    if my_addr.is_empty() { return; }

    let vote_data = format!("{}:{}:{}", block.hash, block.height, my_addr);
    let signature = match bft_sign(&vote_data) {
        Some(s) => s,
        None    => { eprintln!("[BFT] Cannot sign vote — no key"); return; }
    };

    let vote = P2PMessage::BlockVote {
        block_hash: block.hash.clone(),
        height:     block.height,
        voter:      my_addr.clone(),
        signature,
        timestamp:  chrono::Utc::now().timestamp(),
    };

    if let Ok(data) = serde_json::to_vec(&vote) {
        publish_gossip("ego-votes-v1", data).await;
    }

    // Also count our own vote
    handle_block_vote(block.hash, block.height, my_addr, String::new(), chrono::Utc::now().timestamp(), app).await;
}

/// Called when we receive a BlockVote from a peer (or cast our own).
/// Collect votes; finalize the block when >2/3 threshold is reached.
async fn handle_block_vote(
    block_hash: String,
    height:     u64,
    voter:      String,
    _signature: String,
    _timestamp: i64,
    app:        &tauri::AppHandle,
) {
    let threshold = bft_threshold();

    let should_finalize = {
        let mut votes = pending_votes();
        let voters = votes.entry(block_hash.clone()).or_default();
        if !voters.contains(&voter) {
            voters.push(voter.clone());
            eprintln!("[BFT] Vote for block #{} from {} ({}/{} votes)",
                height, voter, voters.len(), threshold);
        }
        voters.len() >= threshold
    };

    if !should_finalize { return; }

    // Already finalized this block? Check chain.
    let chain = load_chain();
    if chain.blocks.iter().any(|b| b.hash == block_hash) {
        return; // already in chain
    }

    eprintln!("[BFT] Block #{} FINALIZED with {} votes (threshold={})",
        height,
        pending_votes().get(&block_hash).map(|v| v.len()).unwrap_or(0),
        threshold);

    // Clean up pending votes for this height
    pending_votes().retain(|_, _| true); // keep for now, or clear by height

    // Find the block in pending transactions (was stored when we saw the proposal)
    // or request it from the relay
    let finalized_chain = load_chain();
    let block = match finalized_chain.blocks.iter().find(|b| b.hash == block_hash) {
        Some(b) => b.clone(),
        None    => {
            // Block not yet known locally — Oracle sync will pick it up on the next tick
            eprintln!("[BFT] Block {} not found locally — will arrive via Oracle sync", block_hash);
            return;
        }
    };

    // Broadcast finalization so all peers learn about it
    let votes_json: Vec<serde_json::Value> = pending_votes()
        .get(&block_hash)
        .map(|voters| voters.iter().map(|v| serde_json::json!({"voter": v})).collect())
        .unwrap_or_default();

    let finalized = P2PMessage::BlockFinalized {
        block:        block.clone(),
        transactions: finalized_chain.transactions.iter()
            .filter(|t| t.block_height == Some(height))
            .cloned()
            .collect(),
        votes:        votes_json,
    };

    if let Ok(data) = serde_json::to_vec(&finalized) {
        publish_gossip("ego-blocks-v1", data).await;
    }

    let _ = app.emit_all("ego://chain-updated", ());
}

/// No-op stub — HTTP relay decommissioned. Gossipsub broadcast is handled by
/// broadcast_tx(); Oracle RPC receives TXs via the /tx/broadcast call in wallet.rs.
pub async fn push_tx_to_relay(_tx: &crate::ledger::LedgerTx, _block: &crate::ledger::LedgerBlock) {}

// ── CID registry (DHT-only after relay decommission) ──────────────────────────

/// After storing a file locally, register it on the DHT so peers can discover
/// the holder and request it directly.
pub async fn register_cid_on_relay(cid: &str, holder_addr: &str, endpoint: &str) {
    dht_register_cid(cid, holder_addr, endpoint).await;
}

/// No-op stub — PoRep commitments are tracked on-chain via deploy TXs.
pub async fn register_porep_commitment(
    _cid: &str, _prover_addr: &str, _comm_d: &str, _comm_r: &str,
    _n_real_leaves: usize, _n_padded_leaves: usize,
    _sector_id: u64, _file_size: u64, _expiry: i64,
) {}

/// No-op stub — PoST challenges will come from Oracle RPC in a future update.
pub async fn fetch_post_challenges(_prover_addr: &str) -> Vec<serde_json::Value> {
    vec![]
}

/// No-op stub — PoST proof submission will target Oracle RPC in a future update.
pub async fn submit_post_proof(_payload: serde_json::Value) -> bool {
    false
}

/// Minimal holder info returned by find_cid_holders.
#[derive(Debug, Clone, Default)]
pub struct CidHolder {
    pub holder_addr: String,
    pub endpoint:    String,
}

/// Query the DHT to find who holds a CID.
pub async fn find_cid_holders(cid: &str) -> Vec<CidHolder> {
    dht_find_cid(cid).await;
    vec![]
}

/// Publish a CID→holder mapping to the DHT so any peer can find who holds a file.
/// Called alongside register_cid_on_relay (dual-write during transition).
pub async fn dht_register_cid(cid: &str, holder_addr: &str, endpoint: &str) {
    let record = serde_json::json!({
        "cid":         cid,
        "holder_addr": holder_addr,
        "endpoint":    endpoint,
        "ts":          chrono::Utc::now().timestamp(),
    });
    let key = format!("ego-cid:{}", cid);
    if let Ok(v) = serde_json::to_vec(&record) {
        if let Some(tx) = DHT_CMD_TX.get() {
            let _ = tx.send(DhtCommand::PutPeer { key, value: v });
        }
    }
}

/// Look up who holds a CID in the DHT.
/// Results come back asynchronously via the GetRecord Kademlia event handler.
pub async fn dht_find_cid(cid: &str) {
    let key = format!("ego-cid:{}", cid);
    if let Some(tx) = DHT_CMD_TX.get() {
        let _ = tx.send(DhtCommand::GetPeers { key });
    }
}

/// Store an offline message in the DHT for a recipient who is not reachable right now.
/// The message will be retrievable when they come online and call dht_fetch_inbox.
pub async fn dht_deposit_message(to_addr: &str, from_addr: &str, msg: &P2PMessage) {
    let payload = match serde_json::to_vec(msg) {
        Ok(v) => v,
        Err(_) => return,
    };
    let msg_hash = hex::encode(ego_core::hash_data(&payload).as_bytes());
    let msg_key  = format!("ego-inbox:{}:{}", to_addr, msg_hash);

    // 1. Store the message itself
    if let Some(tx) = DHT_CMD_TX.get() {
        let _ = tx.send(DhtCommand::PutPeer {
            key:   msg_key.clone(),
            value: payload,
        });
    }

    // 2. Append this msg_hash to the mailbox list via a read-then-write cycle:
    //    queue the hash in PENDING_MAILBOX_APPENDS, then trigger a GetRecord on
    //    the mailbox key.  The GetRecord handler will merge pending hashes and
    //    write back the enlarged list (or create a fresh list if key not found).
    {
        let mut map = pending_appends().lock().unwrap();
        map.entry(to_addr.to_string()).or_default().push(msg_hash.clone());
    }
    let mailbox_key = format!("ego-mailbox:{}", to_addr);
    if let Some(tx) = DHT_CMD_TX.get() {
        let _ = tx.send(DhtCommand::GetPeers { key: mailbox_key });
    }
    let display_len = msg_key.len().min(40);
    eprintln!("[DHT] Queued mailbox append for {} (hash={})", to_addr, &msg_hash[..8.min(msg_hash.len())]);
}

/// Query the DHT for offline messages addressed to our address.
pub async fn dht_fetch_inbox(my_addr: &str) {
    let mailbox_key = format!("ego-mailbox:{}", my_addr);
    if let Some(tx) = DHT_CMD_TX.get() {
        let _ = tx.send(DhtCommand::GetPeers { key: mailbox_key });
    }
}

/// Discover peers via DHT only (HTTP relay decommissioned).
pub async fn fetch_peers_from_relay(_app: &tauri::AppHandle) {
    dht_discover_peers().await;
}

/// Publish our own peer record to the Kademlia DHT so other nodes can find
/// us without querying the central HTTP relay.  Called on startup and every
/// 30 minutes from the keep-alive loop.
pub async fn dht_publish_self(address: &str, endpoint: &str, name: &str) {
    let record_value = serde_json::json!({
        "address":  address,
        "endpoint": endpoint,
        "name":     name,
        "ts":       chrono::Utc::now().timestamp(),
    });
    let value = match serde_json::to_vec(&record_value) {
        Ok(v) => v,
        Err(_) => return,
    };
    // DHT key: "ego-peer:{address}" so anyone can look up a peer by Ego address
    let key = format!("ego-peer:{}", address);
    if let Some(tx) = DHT_CMD_TX.get() {
        let _ = tx.send(DhtCommand::PutPeer { key, value });
    }
}

/// Query the well-known DHT rendezvous key to discover active peers without
/// relying on the central HTTP relay.
pub async fn dht_discover_peers() {
    let key = "ego-peers-v1".to_string();
    if let Some(tx) = DHT_CMD_TX.get() {
        let _ = tx.send(DhtCommand::GetPeers { key });
    }
}

/// Phase 3: publish this node's shard assignments to the DHT.
/// Key: "ego-shard:{shard_id}" → JSON array of holder info.
pub async fn dht_publish_shard_assignments(address: &str, endpoint: &str) {
    let map = crate::sharding::load_shard_map();
    if map.shard_count <= 1 { return; } // Phase 1 no-op

    let all_nodes: Vec<String> = map.assignments.iter()
        .map(|a| a.node_address.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter().collect();

    let held: Vec<u32> = crate::sharding::my_shards(address, &map, &all_nodes)
        .into_iter().map(|(id, _)| id).collect();

    for shard_id in held {
        let key = format!("ego-shard:{}", shard_id);
        let value = serde_json::json!({
            "shard_id":  shard_id,
            "address":   address,
            "endpoint":  endpoint,
            "ts":        chrono::Utc::now().timestamp(),
        });
        if let Ok(v) = serde_json::to_vec(&value) {
            if let Some(tx) = DHT_CMD_TX.get() {
                let _ = tx.send(DhtCommand::PutPeer { key, value: v });
            }
        }
    }
}

/// Phase 3: query the DHT for holders of a specific shard.
pub async fn dht_query_shard_holders(shard_id: u32) {
    let key = format!("ego-shard:{}", shard_id);
    if let Some(tx) = DHT_CMD_TX.get() {
        let _ = tx.send(DhtCommand::GetPeers { key });
    }
}

/// Phase 3: detect under-replicated shards and broadcast vacancy notices.
pub async fn broadcast_vacancy_notices() {
    let map = crate::sharding::load_shard_map();
    if map.shard_count <= 1 { return; }

    let vacant = crate::sharding::detect_vacant_shards(&map);
    for (shard_id, current_holders) in vacant {
        eprintln!("[Sharding] Shard {} under-replicated: {}/{} holders",
            shard_id, current_holders, crate::sharding::REPLICATION_FACTOR);
        let notice = P2PMessage::ShardVacancyNotice { shard_id, current_holders };
        if let Ok(data) = serde_json::to_vec(&notice) {
            publish_gossip("ego-shards-v1", data).await;
        }
    }
}

/// Phase 3: request a specific block from its shard holder (for nodes that
/// pruned the block). Falls back to full chain sync if no holder found.
pub async fn query_block_from_shard(block_height: u64) {
    let map = crate::sharding::load_shard_map();
    if map.shard_count <= 1 { return; }

    let shard_id = crate::sharding::shard_for_height(
        block_height, map.total_blocks.max(1), map.shard_count
    );
    // Find a holder for this shard
    let now = chrono::Utc::now().timestamp();
    let holder_ep = map.assignments.iter()
        .find(|a| a.shard_id == shard_id && !a.node_endpoint.is_empty() && now - a.last_seen < 300)
        .map(|a| a.node_endpoint.clone());

    let my_addr = crate::ledger::Ledger::load().address;
    let my_ep   = get_public_endpoint().await;

    if let Some(ep) = holder_ep {
        let req = P2PMessage::ShardBlockQuery {
            block_height,
            requester_address:  my_addr,
            requester_endpoint: my_ep,
        };
        tokio::spawn(async move {
            let _ = send_message_any(&[ep], &req).await;
        });
    }
}

/// Endpoint lookup — HTTP relay removed; falls back to local peer cache only.
pub async fn get_relay_endpoint(_address: &str) -> Option<String> {
    None
}

// ── Windows firewall ──────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn ensure_firewall_rule() {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    for (name, proto, port) in [
        (format!("Ego Desktop P2P TCP {}", P2P_PORT), "TCP", P2P_PORT),
        (format!("Ego Desktop P2P UDP {}", P2P_PORT), "UDP", P2P_PORT),
    ] {
        let check = std::process::Command::new("netsh")
            .args(["advfirewall", "firewall", "show", "rule", &format!("name={}", name)])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        if let Ok(out) = check {
            if out.status.success() && !out.stdout.is_empty() { continue; }
        }
        let _ = std::process::Command::new("netsh")
            .args([
                "advfirewall", "firewall", "add", "rule",
                &format!("name={}", name),
                "dir=in", "action=allow",
                &format!("protocol={}", proto),
                &format!("localport={}", port),
                "enable=yes", "profile=any",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    }
}

#[cfg(not(target_os = "windows"))]
fn ensure_firewall_rule() {}