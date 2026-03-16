//! Sharded blockchain storage — Phase 1 foundation.
//!
//! Phase 1 (1-9 nodes):  full replication, shard_count = 1, every node holds all data.
//! Phase 2 (10-99 nodes): partial sharding, shard_count = N/3.
//! Phase 3 (100+ nodes): full sharding with master/slave failover.
//!
//! In Phase 1 the shard math runs but always produces shard_count=1, so
//! all existing chain.json storage is untouched.

use crate::ledger::{base_data_dir, load_chain, SharedChain, LedgerBlock, LedgerTx};
use serde::{Deserialize, Serialize};
use std::fs;

pub const REPLICATION_FACTOR: u32 = 3;   // 1 master + 2 slaves
pub const PHASE2_NODE_THRESHOLD: u32 = 10;
pub const PHASE3_NODE_THRESHOLD: u32 = 100;
pub const MASTER_TIMEOUT_SECS: i64 = 120; // 2 minutes

/// Role this node plays for a specific shard.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ShardRole {
    Master,
    Slave,
    Observer,  // holds no data for this shard
}

/// A node's recorded responsibility for a shard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardAssignment {
    pub shard_id:       u32,
    pub role:           ShardRole,
    pub node_address:   String,
    pub node_endpoint:  String,
    /// Unix timestamp when this assignment was last confirmed alive.
    pub last_seen:      i64,
    pub uptime_secs:    u64,
}

/// Global shard map — persisted to shard_map.json.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ShardMap {
    pub network_node_count: u32,
    pub shard_count:        u32,
    pub total_blocks:       u64,
    pub assignments:        Vec<ShardAssignment>,
    pub updated_at:         i64,
}

pub fn shard_map_path() -> std::path::PathBuf {
    base_data_dir().join("shard_map.json")
}

pub fn load_shard_map() -> ShardMap {
    let path = shard_map_path();
    if let Ok(data) = fs::read_to_string(&path) {
        if let Ok(map) = serde_json::from_str::<ShardMap>(&data) {
            return map;
        }
    }
    ShardMap::default()
}

pub fn save_shard_map(map: &ShardMap) -> Result<(), String> {
    let data = serde_json::to_string_pretty(map).map_err(|e| e.to_string())?;
    fs::write(shard_map_path(), data).map_err(|e| e.to_string())
}

/// Number of storage shards for a given network size.
/// Phase 1: always 1. Phase 2+: N/3.
pub fn compute_shard_count(network_node_count: u32) -> u32 {
    if network_node_count < PHASE2_NODE_THRESHOLD {
        return 1;
    }
    (network_node_count / REPLICATION_FACTOR).max(1)
}

/// How many blocks per shard.
pub fn blocks_per_shard(total_blocks: u64, shard_count: u32) -> u64 {
    if shard_count <= 1 { return total_blocks.max(1); }
    (total_blocks / shard_count as u64).max(1)
}

/// Which shard a block height belongs to.
pub fn shard_for_height(height: u64, total_blocks: u64, shard_count: u32) -> u32 {
    if shard_count <= 1 { return 0; }
    let total = total_blocks.max(1);
    ((height * shard_count as u64 / total) as u32).min(shard_count - 1)
}

/// Deterministic consistent-hash assignment: returns up to 3 node addresses
/// responsible for shard_id. Position 0 = Master, 1 = Slave 1, 2 = Slave 2.
/// Same inputs always produce the same ordering on every node — no coordinator needed.
pub fn consistent_hash_assign(shard_id: u32, nodes: &[String]) -> Vec<String> {
    let mut scored: Vec<(u64, &String)> = nodes.iter().map(|addr| {
        // FNV-1a over shard_id bytes ++ addr bytes
        let mut h: u64 = 0xcbf29ce484222325;
        for b in shard_id.to_le_bytes().iter().chain(addr.bytes().collect::<Vec<_>>().iter()) {
            h ^= *b as u64;
            h = h.wrapping_mul(0x00000100000001b3);
        }
        (h, addr)
    }).collect();
    scored.sort_by_key(|(h, _)| *h);
    scored.into_iter().take(REPLICATION_FACTOR as usize).map(|(_, a)| a.clone()).collect()
}

/// Returns which shards this node is responsible for and in what role.
pub fn my_shards(my_address: &str, map: &ShardMap, all_nodes: &[String]) -> Vec<(u32, ShardRole)> {
    let mut result = Vec::new();
    for shard_id in 0..map.shard_count {
        let responsible = consistent_hash_assign(shard_id, all_nodes);
        let role = if responsible.get(0).map(|a| a.as_str()) == Some(my_address) {
            ShardRole::Master
        } else if responsible.get(1).map(|a| a.as_str()) == Some(my_address)
               || responsible.get(2).map(|a| a.as_str()) == Some(my_address) {
            ShardRole::Slave
        } else {
            continue; // Observer — skip
        };
        result.push((shard_id, role));
    }
    // Phase 1: shard_count=1, so every node is either Master or Slave for shard 0.
    // With fewer than 3 nodes, everyone is Master for shard 0.
    if map.shard_count == 1 && result.is_empty() {
        result.push((0, ShardRole::Master));
    }
    result
}

/// True if this node should drop a shard (no longer responsible and not in buffer).
pub fn should_drop_shard(shard_id: u32, my_address: &str, map: &ShardMap, all_nodes: &[String]) -> bool {
    if map.shard_count <= 1 { return false; } // Phase 1: never drop
    let my = my_shards(my_address, map, all_nodes);
    let assigned_ids: Vec<u32> = my.iter().map(|(id, _)| *id).collect();
    if assigned_ids.contains(&shard_id) { return false; }
    // Buffer: keep shard_id ±1 as well
    let next = (shard_id + 1) % map.shard_count;
    let prev = if shard_id == 0 { map.shard_count - 1 } else { shard_id - 1 };
    if assigned_ids.contains(&next) || assigned_ids.contains(&prev) { return false; }
    true
}

/// Called at startup and every 30s from the keep-alive loop.
/// Updates the local ShardMap with current network state.
pub async fn run_shard_startup(my_address: &str, my_endpoint: &str, peer_addresses: &[String], uptime_secs: u64) {
    let chain = load_chain();
    let total_blocks = chain.blocks.len() as u64;
    let network_node_count = (peer_addresses.len() as u32 + 1).max(1); // +1 for self

    let shard_count = compute_shard_count(network_node_count);
    let now = chrono::Utc::now().timestamp();

    let mut map = load_shard_map();
    map.network_node_count = network_node_count;
    map.shard_count = shard_count;
    map.total_blocks = total_blocks;
    map.updated_at = now;

    // Build full node list (self + peers)
    let mut all_nodes: Vec<String> = peer_addresses.to_vec();
    if !all_nodes.contains(&my_address.to_string()) {
        all_nodes.push(my_address.to_string());
    }

    // Upsert this node's shard assignments
    let my_assignments = my_shards(my_address, &map, &all_nodes);
    for (shard_id, role) in my_assignments {
        if let Some(existing) = map.assignments.iter_mut()
            .find(|a| a.shard_id == shard_id && a.node_address == my_address) {
            existing.role = role;
            existing.last_seen = now;
            existing.uptime_secs = uptime_secs;
            existing.node_endpoint = my_endpoint.to_string();
        } else {
            map.assignments.push(ShardAssignment {
                shard_id,
                role,
                node_address:  my_address.to_string(),
                node_endpoint: my_endpoint.to_string(),
                last_seen:     now,
                uptime_secs,
            });
        }
    }

    // Remove stale entries (not seen for 10 minutes)
    map.assignments.retain(|a| now - a.last_seen < 600);

    let _ = save_shard_map(&map);

    eprintln!("[Sharding] Phase {} — {} nodes, {} shards, {} blocks",
        if shard_count == 1 { 1 } else if network_node_count < PHASE3_NODE_THRESHOLD { 2 } else { 3 },
        network_node_count, shard_count, total_blocks);
}

/// Check master health and promote self if master has been offline > 2 minutes.
/// In Phase 1 this is a no-op (shard_count = 1, everyone holds full chain).
pub async fn check_master_health(my_address: &str, my_endpoint: &str, uptime_secs: u64) {
    let map = load_shard_map();
    if map.shard_count <= 1 { return; } // Phase 1: no failover needed

    let now = chrono::Utc::now().timestamp();
    let all_nodes: Vec<String> = map.assignments.iter()
        .map(|a| a.node_address.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter().collect();

    for (shard_id, role) in my_shards(my_address, &map, &all_nodes) {
        if role != ShardRole::Slave { continue; }

        // Find current master for this shard
        let master = map.assignments.iter()
            .find(|a| a.shard_id == shard_id && a.role == ShardRole::Master);

        if let Some(m) = master {
            if now - m.last_seen > MASTER_TIMEOUT_SECS {
                // Check we are the highest-uptime slave (position 1 in ring)
                let responsible = consistent_hash_assign(shard_id, &all_nodes);
                if responsible.get(1).map(|a| a.as_str()) == Some(my_address) {
                    eprintln!("[Sharding] Shard {} master {} offline — promoting self to master",
                        shard_id, &m.node_address);
                    // Broadcast promotion via P2P
                    crate::p2p::broadcast_master_promotion(shard_id, my_address, my_endpoint, &m.node_address).await;
                    // Update local map
                    let mut updated = load_shard_map();
                    if let Some(old) = updated.assignments.iter_mut()
                        .find(|a| a.shard_id == shard_id && a.node_address == m.node_address) {
                        old.role = ShardRole::Observer;
                    }
                    if let Some(me) = updated.assignments.iter_mut()
                        .find(|a| a.shard_id == shard_id && a.node_address == my_address) {
                        me.role = ShardRole::Master;
                        me.last_seen = now;
                        me.uptime_secs = uptime_secs;
                    }
                    let _ = save_shard_map(&updated);
                }
            }
        }
    }
}

/// Update ShardMap when a ShardAnnounce is received from a peer.
pub fn handle_shard_announce_update(
    peer_addr: &str,
    peer_endpoint: &str,
    held_shards: &[u32],
    uptime_secs: u64,
    network_node_count: u32,
    shard_count: u32,
) {
    let now = chrono::Utc::now().timestamp();
    let mut map = load_shard_map();

    // Update network stats if newer info
    if network_node_count > map.network_node_count {
        map.network_node_count = network_node_count;
        map.shard_count = shard_count;
        map.updated_at = now;
    }

    // Remove old entries for this peer
    map.assignments.retain(|a| a.node_address != peer_addr);

    // Build all nodes list for role computation
    let mut all_nodes: Vec<String> = map.assignments.iter()
        .map(|a| a.node_address.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter().collect();
    if !all_nodes.contains(&peer_addr.to_string()) {
        all_nodes.push(peer_addr.to_string());
    }

    for &shard_id in held_shards {
        let responsible = consistent_hash_assign(shard_id, &all_nodes);
        let role = if responsible.get(0).map(|a| a.as_str()) == Some(peer_addr) {
            ShardRole::Master
        } else {
            ShardRole::Slave
        };
        map.assignments.push(ShardAssignment {
            shard_id,
            role,
            node_address:  peer_addr.to_string(),
            node_endpoint: peer_endpoint.to_string(),
            last_seen:     now,
            uptime_secs,
        });
    }

    let _ = save_shard_map(&map);
}

// ── Phase 2 helpers ───────────────────────────────────────────────────────────

/// Returns the blocks and their transactions belonging to `shard_id`,
/// starting from `from_height` (exclusive). In Phase 1 (shard_count=1) returns
/// all blocks above `from_height`.
pub fn get_shard_blocks(
    shard_id:    u32,
    from_height: u64,
    chain:       &SharedChain,
    map:         &ShardMap,
) -> (Vec<LedgerBlock>, Vec<LedgerTx>) {
    let blocks: Vec<LedgerBlock> = chain.blocks.iter()
        .filter(|b| {
            b.height > from_height
            && (map.shard_count <= 1
                || shard_for_height(b.height, map.total_blocks.max(1), map.shard_count) == shard_id)
        })
        .cloned()
        .collect();

    if blocks.is_empty() {
        return (blocks, vec![]);
    }

    let min_h = blocks.iter().map(|b| b.height).min().unwrap_or(0);
    let max_h = blocks.iter().map(|b| b.height).max().unwrap_or(0);

    // Return txs whose confirmed block_height falls within this shard's range.
    let txs: Vec<LedgerTx> = chain.transactions.iter()
        .filter(|t| t.block_height.map(|h| h >= min_h && h <= max_h).unwrap_or(false))
        .cloned()
        .collect();

    (blocks, txs)
}

/// Returns the highest block height we already hold for a given shard.
/// Used by slaves to request only the blocks they're missing.
pub fn last_shard_height(shard_id: u32, chain: &SharedChain, map: &ShardMap) -> u64 {
    chain.blocks.iter()
        .filter(|b| {
            map.shard_count <= 1
            || shard_for_height(b.height, map.total_blocks.max(1), map.shard_count) == shard_id
        })
        .map(|b| b.height)
        .max()
        .unwrap_or(0)
}

/// Returns a JSON summary of the current shard state for the frontend.
pub fn get_shard_status() -> serde_json::Value {
    let map = load_shard_map();
    let phase = if map.shard_count == 1 { 1u32 }
                else if map.network_node_count < PHASE3_NODE_THRESHOLD { 2 }
                else { 3 };
    serde_json::json!({
        "phase":               phase,
        "network_node_count":  map.network_node_count,
        "shard_count":         map.shard_count,
        "total_blocks":        map.total_blocks,
        "replication_factor":  REPLICATION_FACTOR,
        "assignments":         map.assignments,
        "updated_at":          map.updated_at,
    })
}
