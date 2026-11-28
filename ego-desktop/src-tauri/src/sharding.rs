use crate::ledger::{base_data_dir, load_chain, SharedChain, LedgerBlock, LedgerTx};
use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

static AGREED_SHARD_COUNT: AtomicU32 = AtomicU32::new(256);
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
    let count = crate::chain_db::get_meta_u64(b"agreed_shard_count").unwrap_or(256) as u32;
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
pub const MAX_SHARDS: u32 = 256;
pub const MAX_HOLDERS_PER_SHARD: usize = 16;
pub const SHARD_MSG_SKEW_SECS: i64 = 600;
const MAX_ENDPOINT_LEN: usize = 256;

pub fn fresh(ts: i64, now: i64) -> bool {
    (ts - now).abs() <= SHARD_MSG_SKEW_SECS
}

pub fn announce_signing_bytes(
    from_addr: &str,
    from_endpoint: &str,
    held_shards: &[u32],
    uptime_secs: u64,
    network_node_count: u32,
    shard_count: u32,
    ts: i64,
) -> Vec<u8> {
    let held: Vec<String> = held_shards.iter().map(|s| s.to_string()).collect();
    format!(
        "ego/shard-announce/v1\n{from_addr}\n{from_endpoint}\n{}\n{uptime_secs}\n{network_node_count}\n{shard_count}\n{ts}",
        held.join(",")
    )
    .into_bytes()
}

pub fn promotion_signing_bytes(shard_id: u32, new_master: &str, new_endpoint: &str, former_master: &str, ts: i64) -> Vec<u8> {
    format!("ego/shard-promotion/v1\n{shard_id}\n{new_master}\n{new_endpoint}\n{former_master}\n{ts}").into_bytes()
}

pub fn sign_as_node(msg: &[u8]) -> Option<(String, String)> {
    let kp = crate::commands::hosting::hosting_keypair()?;
    Some((hex::encode(&kp.ed25519_public_key().as_bytes()[..32]), hex::encode(kp.sign_ed25519(msg).as_bytes())))
}

pub fn signed_by(addr: &str, pubkey_hex: &str, sig_hex: &str, msg: &[u8]) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    let Some(pk) = hex::decode(pubkey_hex).ok().and_then(|v| <[u8; 32]>::try_from(v).ok()) else { return false };
    let Some(sig) = hex::decode(sig_hex).ok().and_then(|v| <[u8; 64]>::try_from(v).ok()) else { return false };
    crate::market_chain::address_of(&pk) == addr
        && VerifyingKey::from_bytes(&pk).map_or(false, |k| k.verify_strict(msg, &Signature::from_bytes(&sig)).is_ok())
}

pub fn limit_holders(map: &mut ShardMap) {
    map.assignments.retain(|a| a.shard_id < MAX_SHARDS);
    map.assignments.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
    let mut per_shard: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
    map.assignments.retain(|a| {
        let n = per_shard.entry(a.shard_id).or_insert(0);
        *n += 1;
        *n <= MAX_HOLDERS_PER_SHARD
    });
}

pub fn apply_promotion(
    map: &mut ShardMap,
    shard_id: u32,
    new_master: &str,
    new_endpoint: &str,
    former_master: &str,
    ts: i64,
    now: i64,
) -> bool {
    if shard_id >= MAX_SHARDS || new_master == former_master || !fresh(ts, now) || new_endpoint.len() > MAX_ENDPOINT_LEN {
        return false;
    }
    if !map.assignments.iter().any(|a| a.shard_id == shard_id && a.node_address == new_master) {
        return false;
    }
    let live = |a: &ShardAssignment| now - a.last_seen <= MASTER_TIMEOUT_SECS;
    if map.assignments.iter().any(|a| a.shard_id == shard_id && a.node_address == former_master && live(a)) {
        return false;
    }
    if map.assignments.iter().any(|a| {
        a.shard_id == shard_id && a.role == ShardRole::Master && a.node_address != former_master && a.node_address != new_master && live(a)
    }) {
        return false;
    }
    for a in map.assignments.iter_mut().filter(|a| a.shard_id == shard_id) {
        if a.node_address == former_master {
            a.role = ShardRole::Observer;
        } else if a.node_address == new_master {
            a.role = ShardRole::Master;
            if !new_endpoint.is_empty() {
                a.node_endpoint = new_endpoint.to_string();
            }
            a.last_seen = a.last_seen.max(ts.min(now));
        }
    }
    true
}

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
    if network_node_count <= 50 { return 1; }
    256
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
    limit_holders(&mut map);

    let _ = save_shard_map(&map);

    tracing::info!("Sharding phase {} — {} nodes, {} shards, {} blocks",
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
            let silence = now - m.last_seen;
            // Require double the base timeout before promoting.  This gives the
            // master time to reconnect and prevents split-brain caused by a
            // brief network partition being mistaken for a dead node.
            if silence > MASTER_TIMEOUT_SECS * 2 {
                let responsible = consistent_hash_assign(shard_id, &all_nodes);
                // Only the first-priority slave (index 1) promotes — deterministic
                // election prevents simultaneous promotions by multiple slaves.
                if responsible.get(1).map(|a| a.as_str()) == Some(my_address) {
                    // Require at least one other live peer to have also seen the
                    // master as absent (last_seen also expired) before promoting.
                    let other_slaves_agree = map.assignments.iter().any(|a| {
                        a.shard_id == shard_id
                            && a.node_address != my_address
                            && a.node_address != m.node_address
                            && now - a.last_seen < 300
                    });
                    if !other_slaves_agree && map.network_node_count > 2 {
                        continue;
                    }

                    tracing::warn!("Shard {} master {} offline {}s — promoting self to master",
                        shard_id, &m.node_address, silence);

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
) {
    if peer_endpoint.len() > MAX_ENDPOINT_LEN {
        return;
    }
    let now = chrono::Utc::now().timestamp();
    let mut map = load_shard_map();
    let held: std::collections::BTreeSet<u32> = held_shards.iter().copied().filter(|s| *s < MAX_SHARDS).collect();

    map.assignments.retain(|a| a.node_address != peer_addr);

    let mut all_nodes: Vec<String> = map.assignments.iter()
        .map(|a| a.node_address.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter().collect();
    if !all_nodes.contains(&peer_addr.to_string()) {
        all_nodes.push(peer_addr.to_string());
    }

    for shard_id in held {
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

    limit_holders(&mut map);
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

#[cfg(test)]
mod node_count_tests {
    use super::*;

    /// The shard count steps from one to two hundred and fifty six in a single move, so the
    /// number fed to it decides everything. Counting every peer a node remembers rather than
    /// the ones present tips a handful of live nodes over the threshold and splits their
    /// transactions two hundred and fifty six ways.
    #[test]
    fn the_threshold_is_a_cliff_so_the_count_has_to_be_the_live_one() {
        assert_eq!(compute_shard_count(4), 1, "four live nodes need no sharding at all");
        assert_eq!(compute_shard_count(50), 1);
        assert_eq!(
            compute_shard_count(51),
            256,
            "one peer past the line and every sender's transactions are split 256 ways",
        );
        assert_eq!(
            compute_shard_count(63),
            256,
            "which is what a month of remembered addresses added up to while four nodes ran",
        );
    }
}

#[cfg(test)]
mod signed_shard_message_tests {
    use super::*;

    fn key(n: u8) -> (ego_core::KeyPair, String, String) {
        let kp = ego_core::KeyPair::from_bytes(&[n; 32]).unwrap();
        let pk: [u8; 32] = kp.ed25519_public_key().as_bytes()[..32].try_into().unwrap();
        (kp, hex::encode(pk), crate::market_chain::address_of(&pk))
    }

    fn holder(shard_id: u32, addr: &str, role: ShardRole, last_seen: i64) -> ShardAssignment {
        ShardAssignment { shard_id, role, node_address: addr.into(), node_endpoint: format!("/ip4/10.0.0.1/tcp/1/{addr}"), last_seen, uptime_secs: 0 }
    }

    #[test]
    fn an_announce_counts_only_when_its_own_address_signed_it() {
        let (kp, pk, addr) = key(7);
        let (_, _, other) = key(8);
        let msg = announce_signing_bytes(&addr, "/ip4/1.2.3.4/tcp/4001", &[1, 2], 0, 5, 256, 1_000);
        let sig = hex::encode(kp.sign_ed25519(&msg).as_bytes());
        assert!(signed_by(&addr, &pk, &sig, &msg));
        assert!(!signed_by(&other, &pk, &sig, &msg), "a key cannot speak for another address");
        let moved = announce_signing_bytes(&addr, "/ip4/6.6.6.6/tcp/4001", &[1, 2], 0, 5, 256, 1_000);
        assert!(!signed_by(&addr, &pk, &sig, &moved), "the endpoint is covered by the signature");
        let more = announce_signing_bytes(&addr, "/ip4/1.2.3.4/tcp/4001", &[1, 2, 3], 0, 5, 256, 1_000);
        assert!(!signed_by(&addr, &pk, &sig, &more), "so are the shards it claims");
        assert!(!signed_by(&addr, "", "", &msg), "an unsigned message from an older node is refused");
    }

    #[test]
    fn a_takeover_is_accepted_only_from_a_known_holder_after_the_master_went_quiet() {
        let now = 10_000;
        let base = ShardMap {
            shard_count: 256,
            assignments: vec![holder(140, "old", ShardRole::Master, now - 500), holder(140, "next", ShardRole::Slave, now - 10)],
            ..Default::default()
        };

        let mut m = base.clone();
        assert!(apply_promotion(&mut m, 140, "next", "/ip4/9.9.9.9/tcp/1", "old", now, now));
        assert_eq!(m.assignments.len(), 2, "a takeover never adds entries");
        assert!(m.assignments.iter().any(|a| a.node_address == "next" && a.role == ShardRole::Master && a.node_endpoint == "/ip4/9.9.9.9/tcp/1"));
        assert!(m.assignments.iter().any(|a| a.node_address == "old" && a.role == ShardRole::Observer));

        let mut m = base.clone();
        assert!(!apply_promotion(&mut m, 140, "stranger", "/ip4/6.6.6.6/tcp/1", "old", now, now), "an address that holds nothing of the shard cannot take it");

        let mut m = base.clone();
        m.assignments[0].last_seen = now - 30;
        assert!(!apply_promotion(&mut m, 140, "next", "/ip4/9.9.9.9/tcp/1", "old", now, now), "a master heard from recently keeps its shard");

        let mut m = base.clone();
        m.assignments.push(holder(140, "third", ShardRole::Master, now - 5));
        assert!(!apply_promotion(&mut m, 140, "next", "/ip4/9.9.9.9/tcp/1", "old", now, now), "nor can it push aside a different live master");

        let mut m = base.clone();
        assert!(!apply_promotion(&mut m, 140, "next", "/ip4/9.9.9.9/tcp/1", "old", now - 3_600, now), "an old takeover message replayed later is refused");
        assert!(!apply_promotion(&mut m, 999, "next", "/ip4/9.9.9.9/tcp/1", "old", now, now));
        assert!(!apply_promotion(&mut m, 140, "next", &"x".repeat(300), "old", now, now));
        assert!(!apply_promotion(&mut m, 140, "old", "/ip4/9.9.9.9/tcp/1", "old", now, now));
    }

    #[test]
    fn the_shard_map_stays_bounded_however_many_holders_announce() {
        let mut m = ShardMap::default();
        for i in 0..100 {
            m.assignments.push(holder(5, &format!("n{i}"), ShardRole::Slave, i));
        }
        m.assignments.push(holder(MAX_SHARDS, "far", ShardRole::Slave, 1_000));
        m.assignments.push(holder(6, "solo", ShardRole::Master, 0));
        limit_holders(&mut m);
        assert_eq!(m.assignments.iter().filter(|a| a.shard_id == 5).count(), MAX_HOLDERS_PER_SHARD);
        assert!(m.assignments.iter().filter(|a| a.shard_id == 5).all(|a| a.last_seen >= 100 - MAX_HOLDERS_PER_SHARD as i64), "the most recently heard holders stay");
        assert!(!m.assignments.iter().any(|a| a.shard_id >= MAX_SHARDS));
        assert!(m.assignments.iter().any(|a| a.node_address == "solo"));
    }

    #[test]
    fn shard_messages_must_be_recent() {
        assert!(fresh(1_000, 1_000));
        assert!(fresh(1_000 - SHARD_MSG_SKEW_SECS, 1_000));
        assert!(!fresh(1_000 - SHARD_MSG_SKEW_SECS - 1, 1_000));
        assert!(!fresh(1_000 + SHARD_MSG_SKEW_SECS + 1, 1_000));
    }
}
