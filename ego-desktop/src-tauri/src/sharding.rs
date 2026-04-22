use crate::ledger::{base_data_dir, load_chain, SharedChain, LedgerBlock, LedgerTx};
use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

static AGREED_SHARD_COUNT: AtomicU32 = AtomicU32::new(1);
static REBALANCE_EFFECTIVE_HEIGHT: AtomicU64 = AtomicU64::new(0);

pub const REBALANCE_GRACE_BLOCKS: u64 = 500;

pub fn get_agreed_shard_count() -> u32 {
    AGREED_SHARD_COUNT.load(Ordering::Relaxed)
}

pub fn set_agreed_shard_count(count: u32, effective_at: u64) {
    AGREED_SHARD_COUNT.store(count, Ordering::Relaxed);
    REBALANCE_EFFECTIVE_HEIGHT.store(effective_at, Ordering::Relaxed);
    crate::chain_db::set_meta_u64(b"agreed_shard_count", count as u64);
    crate::chain_db::set_meta_u64(b"shard_effective_height", effective_at);
}

pub fn load_agreed_shard_count_from_db() {
    let count = crate::chain_db::get_meta_u64(b"agreed_shard_count").unwrap_or(1) as u32;
    let height = crate::chain_db::get_meta_u64(b"shard_effective_height").unwrap_or(0);
    AGREED_SHARD_COUNT.store(count.max(1), Ordering::Relaxed);
    REBALANCE_EFFECTIVE_HEIGHT.store(height, Ordering::Relaxed);
}

pub fn is_in_grace_period(current_height: u64) -> bool {
    let eff = REBALANCE_EFFECTIVE_HEIGHT.load(Ordering::Relaxed);
    eff > 0 && current_height < eff + REBALANCE_GRACE_BLOCKS
}

pub fn shard_for_address_agreed(addr: &str) -> u32 {
    let count = get_agreed_shard_count();
    if count <= 1 { return 0; }
    let mut h: u64 = 0xcbf29ce484222325;
    for b in addr.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    (h % count as u64) as u32
}

pub const REPLICATION_FACTOR: u32 = 3;
pub const PHASE2_NODE_THRESHOLD: u32 = 10;
pub const PHASE3_NODE_THRESHOLD: u32 = 100;
pub const MASTER_TIMEOUT_SECS: i64 = 120;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ShardRole {
    Master,
    Slave,
    Observer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardAssignment {
    pub shard_id:       u32,
    pub role:           ShardRole,
    pub node_address:   String,
    pub node_endpoint:  String,

    pub last_seen:      i64,
    pub uptime_secs:    u64,
}

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

pub fn compute_shard_count(network_node_count: u32) -> u32 {
    if network_node_count < PHASE2_NODE_THRESHOLD {
        return 1;
    }
    (network_node_count / REPLICATION_FACTOR).max(1)
}

pub fn blocks_per_shard(total_blocks: u64, shard_count: u32) -> u64 {
    if shard_count <= 1 { return total_blocks.max(1); }
    (total_blocks / shard_count as u64).max(1)
}

pub fn shard_for_height(height: u64, shard_count: u32) -> u32 {
    if shard_count <= 1 { return 0; }
    (height % shard_count as u64) as u32
}

pub fn consistent_hash_assign(shard_id: u32, nodes: &[String]) -> Vec<String> {
    let mut scored: Vec<(u64, &String)> = nodes.iter().map(|addr| {

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
            continue;
        };
        result.push((shard_id, role));
    }

    if map.shard_count == 1 && result.is_empty() {
        result.push((0, ShardRole::Master));
    }
    result
}

pub fn should_drop_shard(shard_id: u32, my_address: &str, map: &ShardMap, all_nodes: &[String]) -> bool {
    if map.shard_count <= 1 { return false; }
    let my = my_shards(my_address, map, all_nodes);
    let assigned_ids: Vec<u32> = my.iter().map(|(id, _)| *id).collect();
    if assigned_ids.contains(&shard_id) { return false; }

    let next = (shard_id + 1) % map.shard_count;
    let prev = if shard_id == 0 { map.shard_count - 1 } else { shard_id - 1 };
    if assigned_ids.contains(&next) || assigned_ids.contains(&prev) { return false; }
    true
}

pub async fn run_shard_startup(my_address: &str, my_endpoint: &str, peer_addresses: &[String], uptime_secs: u64) {
    let chain = load_chain();
    let total_blocks = chain.blocks.len() as u64;
    let network_node_count = (peer_addresses.len() as u32 + 1).max(1);

    let shard_count = compute_shard_count(network_node_count);
    let now = chrono::Utc::now().timestamp();

    let mut map = load_shard_map();
    map.network_node_count = network_node_count;
    map.shard_count = shard_count;
    map.total_blocks = total_blocks;
    map.updated_at = now;

    let mut all_nodes: Vec<String> = peer_addresses.to_vec();
    if !all_nodes.contains(&my_address.to_string()) {
        all_nodes.push(my_address.to_string());
    }

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

    map.assignments.retain(|a| now - a.last_seen < 600);

    let _ = save_shard_map(&map);

    eprintln!("[Sharding] Phase {} — {} nodes, {} shards, {} blocks",
        if shard_count == 1 { 1 } else if network_node_count < PHASE3_NODE_THRESHOLD { 2 } else { 3 },
        network_node_count, shard_count, total_blocks);
}

pub async fn check_master_health(my_address: &str, my_endpoint: &str, uptime_secs: u64) {
    let map = load_shard_map();
    if map.shard_count <= 1 { return; }

    let now = chrono::Utc::now().timestamp();
    let all_nodes: Vec<String> = map.assignments.iter()
        .map(|a| a.node_address.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter().collect();

    for (shard_id, role) in my_shards(my_address, &map, &all_nodes) {
        if role != ShardRole::Slave { continue; }

        let master = map.assignments.iter()
            .find(|a| a.shard_id == shard_id && a.role == ShardRole::Master);

        if let Some(m) = master {
            if now - m.last_seen > MASTER_TIMEOUT_SECS {

                let responsible = consistent_hash_assign(shard_id, &all_nodes);
                if responsible.get(1).map(|a| a.as_str()) == Some(my_address) {
                    eprintln!("[Sharding] Shard {} master {} offline — promoting self to master",
                        shard_id, &m.node_address);

                    crate::p2p::broadcast_master_promotion(shard_id, my_address, my_endpoint, &m.node_address).await;

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

    if network_node_count > map.network_node_count {
        map.network_node_count = network_node_count;
        map.shard_count = shard_count;
        map.updated_at = now;
    }

    map.assignments.retain(|a| a.node_address != peer_addr);

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
                || shard_for_height(b.height, map.shard_count) == shard_id)
        })
        .cloned()
        .collect();

    if blocks.is_empty() {
        return (blocks, vec![]);
    }

    let min_h = blocks.iter().map(|b| b.height).min().unwrap_or(0);
    let max_h = blocks.iter().map(|b| b.height).max().unwrap_or(0);

    let txs: Vec<LedgerTx> = chain.transactions.iter()
        .filter(|t| t.block_height.map(|h| h >= min_h && h <= max_h).unwrap_or(false))
        .cloned()
        .collect();

    (blocks, txs)
}

pub fn last_shard_height(shard_id: u32, chain: &SharedChain, map: &ShardMap) -> u64 {
    chain.blocks.iter()
        .filter(|b| {
            map.shard_count <= 1
            || shard_for_height(b.height, map.shard_count) == shard_id
        })
        .map(|b| b.height)
        .max()
        .unwrap_or(0)
}

pub fn detect_vacant_shards(map: &ShardMap) -> Vec<(u32, u32)> {
    if map.shard_count <= 1 { return vec![]; }
    let now = chrono::Utc::now().timestamp();
    let mut result = Vec::new();
    for shard_id in 0..map.shard_count {
        let live = map.assignments.iter()
            .filter(|a| a.shard_id == shard_id && now - a.last_seen < 300)
            .count() as u32;
        if live < REPLICATION_FACTOR {
            result.push((shard_id, live));
        }
    }
    result
}

pub fn should_volunteer_for_shard(shard_id: u32, my_address: &str, map: &ShardMap) -> bool {
    if map.shard_count <= 1 { return false; }

    if map.assignments.iter().any(|a| a.shard_id == shard_id && a.node_address == my_address) {
        return false;
    }

    let my_count = map.assignments.iter()
        .filter(|a| a.node_address == my_address)
        .count() as u32;

    let avg = (map.shard_count * REPLICATION_FACTOR).max(1) / map.network_node_count.max(1);
    my_count <= avg
}

pub fn prune_observer_shards(my_address: &str) {
    let map = load_shard_map();
    if map.shard_count <= 1 { return; }

    let now = chrono::Utc::now().timestamp();
    let all_nodes: Vec<String> = map.assignments.iter()
        .map(|a| a.node_address.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter().collect();

    let my_shard_ids: Vec<u32> = my_shards(my_address, &map, &all_nodes)
        .into_iter().map(|(id, _)| id).collect();

    for shard_id in 0..map.shard_count {
        if my_shard_ids.contains(&shard_id) { continue; }
        let live_holders = map.assignments.iter()
            .filter(|a| a.shard_id == shard_id && now - a.last_seen < 300)
            .count() as u32;
        if live_holders >= REPLICATION_FACTOR {
            crate::chain_db::delete_full_blocks_for_shard(shard_id, map.shard_count);
        }
    }
}

pub fn get_shard_master(shard_id: u32) -> Option<String> {
    let map = load_shard_map();
    if map.shard_count <= 1 {
        return None;
    }
    let now = chrono::Utc::now().timestamp();
    if let Some(a) = map.assignments.iter().find(|a| {
        a.shard_id == shard_id
            && a.role == ShardRole::Master
            && now - a.last_seen < 300
    }) {
        if !a.node_endpoint.is_empty() {
            return Some(a.node_endpoint.clone());
        }
    }
    let all_nodes: Vec<String> = map
        .assignments
        .iter()
        .map(|a| a.node_address.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    let responsible = consistent_hash_assign(shard_id, &all_nodes);
    if let Some(master_addr) = responsible.first() {
        if let Some(a) = map.assignments.iter().find(|a| &a.node_address == master_addr) {
            if !a.node_endpoint.is_empty() {
                return Some(a.node_endpoint.clone());
            }
        }
    }
    None
}

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
