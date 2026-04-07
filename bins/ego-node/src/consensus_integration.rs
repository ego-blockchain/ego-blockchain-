
use ego_core::{Address, Balance, Hash, PublicKey, StateManager, JailReason, hash_data};
use ego_core::state::{
    ValidatorHotSetConfig, ValidatorInfo, ValidatorPerformance, ValidatorStatus,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use tracing::warn;


pub const CONSENSUS_TOPIC: &str = "ego/consensus/v1";


pub const MEMPOOL_TOPIC: &str = "ego/mempool/v1";


pub const SYNC_TOPIC: &str = "ego/sync/v1";


#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SyncMsg {

    ChainTip {
        height:     u64,
        block_hash: String,
        rpc_addr:   String, 
    },
}

impl SyncMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        serde_json::from_slice(data).ok()
    }
}


pub const QUORUM_THRESHOLD: f64 = 0.67;


pub const DRS_STALE_EPOCHS: u64 = 3;


pub const DRS_DECAY_FACTOR: f64 = 0.8;

/// DRS score below which a validator is automatically jailed.
pub const DRS_JAIL_THRESHOLD: f64 = 0.1;

// ── gossip message types ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConsensusMsg {
    Proposal {
        height:     u64,
        block_hash: String,
        proposer:   String,
        block_json: serde_json::Value,
    },

    Vote {
        height:      u64,
        block_hash:  String,
        voter:       String,
        dil_sig_hex: String,
    },
    /// Proposer broadcasts the fully-formed quorum certificate.
    Qc {
        height:           u64,
        block_hash:       String,
        voter_count:      usize,
        total_drs_weight: f64,
    },

    ViewChange {
        height:    u64,
        epoch:     u64,
        new_round: u32,
        voter:     String,
        payload:   serde_json::Value,
    },
}

impl ConsensusMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        serde_json::from_slice(data).ok()
    }
}

/// Result returned by `process_inbound_consensus`.
pub enum ConsensusAction {
    /// Broadcast a signed vote to peers.
    Vote(ConsensusMsg),
    /// A QC with sufficient DRS weight was received — apply this block.
    FinalizeBlock {
        height:     u64,
        block_json: serde_json::Value,
    },
}

/// Cache of blocks received from peer proposals, keyed by (height, block_hash_hex).
/// Entries older than 20 heights behind tip are pruned to bound memory.
pub struct ProposalCache {
    inner: HashMap<(u64, String), serde_json::Value>,
}

impl ProposalCache {
    pub fn new() -> Self { Self { inner: HashMap::new() } }

    pub fn insert(&mut self, height: u64, block_hash: String, block_json: serde_json::Value) {
        self.inner.insert((height, block_hash), block_json);
    }

    pub fn get(&self, height: u64, block_hash: &str) -> Option<&serde_json::Value> {
        self.inner.get(&(height, block_hash.to_string()))
    }

    /// Drop entries more than 20 heights behind `current_height`.
    pub fn prune(&mut self, current_height: u64) {
        self.inner.retain(|(h, _), _| current_height.saturating_sub(*h) <= 20);
    }
}


pub struct VoteCollector {
    /// height → block_hash_hex → list of (voter_hex, drs_weight)
    votes: HashMap<u64, HashMap<String, Vec<(String, f64)>>>,
}

impl VoteCollector {
    pub fn new() -> Self {
        Self { votes: HashMap::new() }
    }

    /// Add a vote, deduplicating by voter address.
    pub fn add_vote(&mut self, height: u64, block_hash: &str, voter: &str, weight: f64) {
        let by_hash = self.votes.entry(height).or_default();
        let voters  = by_hash.entry(block_hash.to_string()).or_default();
        if !voters.iter().any(|(v, _)| v == voter) {
            voters.push((voter.to_string(), weight));
        }
    }

    /// Total DRS weight of votes for a (height, block_hash).
    pub fn total_weight(&self, height: u64, block_hash: &str) -> f64 {
        self.votes
            .get(&height)
            .and_then(|m| m.get(block_hash))
            .map(|v| v.iter().map(|(_, w)| *w).sum())
            .unwrap_or(0.0)
    }

    pub fn voter_count(&self, height: u64, block_hash: &str) -> usize {
        self.votes
            .get(&height)
            .and_then(|m| m.get(block_hash))
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Remove entries more than 20 heights behind current tip.
    pub fn prune(&mut self, current_height: u64) {
        self.votes.retain(|h, _| current_height.saturating_sub(*h) <= 20);
    }
}


pub fn elect_leader(state: &StateManager, height: u64, fallback: &Address) -> Address {
    let validators = state.get_active_validators();
    if validators.is_empty() {
        return *fallback;
    }

    let state_root  = state.get_state_root();
    let mut seed_data = state_root.as_bytes().to_vec();
    seed_data.extend_from_slice(&height.to_le_bytes());
    let seed     = hash_data(&seed_data);
    let seed_u64 = u64::from_le_bytes(
        seed.as_bytes()[..8].try_into().unwrap_or([0u8; 8])
    );

    let total_weight: u64 = validators.iter().map(|v| drs_weight(v.drs_score)).sum();
    if total_weight == 0 {
        return validators[0].address;
    }

    let mut pick = seed_u64 % total_weight;
    for v in &validators {
        let w = drs_weight(v.drs_score);
        if pick < w {
            return v.address;
        }
        pick = pick.saturating_sub(w);
    }
    validators.last().unwrap().address
}


#[inline]
pub fn drs_weight(score: f64) -> u64 {
    (score * 1_000.0) as u64 + 1
}


pub fn total_active_drs_weight(state: &StateManager) -> f64 {
    state.get_active_validators()
        .iter()
        .map(|v| v.drs_score)
        .sum::<f64>()
        .max(1.0)
}


pub fn register_storage_validator(
    state:      &StateManager,
    address:    Address,
    public_key: PublicKey,
    epoch:      u64,
) {
    if let Some(v) = state.get_validator(&address) {
        if matches!(v.status, ValidatorStatus::Active) {
            return; 
        }
    }

    let info = ValidatorInfo {
        address,
        public_key,
        total_stake:       Balance(0),
        own_stake:         Balance(0),
        delegated_stake:   Balance(0),
        commission_rate:   0,
        status:            ValidatorStatus::Active,
        joined_epoch:      epoch,
        last_active_epoch: epoch,
        performance: ValidatorPerformance {
            blocks_proposed:      0,
            blocks_missed:        0,
            attestations_made:    0,
            attestations_missed:  0,
            equivocations:        0,
            uptime_score:         1.0,
            attestation_accuracy: 1.0,
        },
        drs_score:         0.5,
        drs_multiplier:    1.0,
        last_drs_update:   epoch,
        puc_coefficient:   1.0,
        peer_degree:       0,
        relay_bytes:       0,
        iot_sessions:      0,
        shard_demand_score: 0,
        jail_info:         None,
        slashing_history:  Vec::new(),
        hot_set_config: ValidatorHotSetConfig {
            keep_headers_forever:      false,
            keep_qcs_forever:          false,
            keep_recent_bodies_epochs: 10,
            keep_state_db:             true,
            mempool_enabled:           true,
            fetch_on_demand_enabled:   true,
        },
    };

    if let Err(e) = state.register_storage_validator(info) {
        warn!("Failed to register storage validator {address}: {e}");
    } else {
        tracing::info!("✅ Validator registered via PoRep: {address}");
    }
}


pub fn check_equivocation(
    seen:       &Mutex<HashMap<(u64, String), String>>,
    state:      &StateManager,
    height:     u64,
    proposer:   &str,
    block_hash: &str,
) -> bool {
    let mut map = seen.lock().unwrap();
    let key = (height, proposer.to_string());

    match map.get(&key) {
        Some(prev) if prev != block_hash => {
            warn!(
                "⚠️  Equivocation: {proposer} produced two blocks at height {height} \
                 ({} vs {block_hash})",
                prev
            );
            if let Ok(bytes) = hex::decode(proposer.trim_start_matches("0x")) {
                if bytes.len() == 20 {
                    let mut arr = [0u8; 20];
                    arr.copy_from_slice(&bytes);
                    let addr = Address::new(arr);
                    let _ = state.jail_validator(
                        &addr,
                        JailReason::Equivocation,
                        200,
                        Balance(0),
                    );
                }
            }
            true
        }
        None => {
            map.insert(key, block_hash.to_string());
            // Prune entries more than 100 heights old
            map.retain(|(h, _), _| height.saturating_sub(*h) <= 100);
            false
        }
        _ => false,
    }
}


pub fn apply_post_miss_penalties(state: &StateManager, current_epoch: u64) {
    for v in state.get_active_validators() {
        let stale_epochs = current_epoch.saturating_sub(v.last_drs_update);
        if stale_epochs < DRS_STALE_EPOCHS {
            continue;
        }
        let new_score = (v.drs_score * DRS_DECAY_FACTOR.powi(
            (stale_epochs - DRS_STALE_EPOCHS + 1) as i32
        )).max(0.0);

        let _ = state.update_validator_drs(&v.address, new_score, v.drs_multiplier, current_epoch);

        if new_score < DRS_JAIL_THRESHOLD {
            let _ = state.jail_validator(
                &v.address,
                JailReason::Downtime { epochs_missed: stale_epochs },
                100,
                Balance(0),
            );
            tracing::warn!(
                "Validator {} jailed: DRS decayed to {:.3} after {} stale epochs",
                v.address, new_score, stale_epochs
            );
        }
    }
}


pub fn has_quorum(collected_weight: f64, total_weight: f64) -> bool {
    if total_weight <= 1.0 {
        return true; // solo-node / bootstrap mode
    }
    collected_weight / total_weight >= QUORUM_THRESHOLD
}
