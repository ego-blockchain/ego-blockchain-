mod acme;
mod dns;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use once_cell::sync::Lazy;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::Arc,
    time::Duration,
};

const GENESIS_HASH:  &str = "ego00000000000000000000000000000000000000000000000000000000genesis2";
const GENESIS_MINER: &str = "egot1genesis0000000000000000000000000000000000";
const GENESIS_TS:    i64  = 1_744_588_800;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, warn};

// ── BFT quorum-certificate verification ──────────────────────────────────────
// A finalized Ego block carries a BLS12-381 aggregate signature (`agg_bls_sig`)
// over the raw block-hash bytes, signed by the committee validators whose BLS
// public keys are listed in `bls_pubkeys` (DST = EGO-BFT-VOTE-BLS12381-v1).
// Verifying it proves those keys actually signed this exact block — the first
// half of making the oracle an untrusted cache (it can reject forged blocks
// that do not carry a valid quorum certificate, no shared secret needed).
const BLS_DST: &[u8] = b"EGO-BFT-VOTE-BLS12381-v1";

#[derive(PartialEq, Debug)]
enum QcStatus { Valid, Invalid, Absent }

/// Below these thresholds the stake-weighted quorum check is bypassed (matches
/// the node's `stake_quorum_reached`), so a small bootstrap network isn't broken.
const MIN_VALIDATORS_FOR_STAKE_QUORUM: usize = 10;
const MIN_STAKE_FOR_QUORUM_UEGOC: u64 = 10_000_000_000_000; // 10M EGOC

/// Derive an Ego testnet address from an Ed25519 public key — mirrors ego-core
/// `EgoAddress::from_public_key_bytes(pk, 1, EOA).to_bech32("egot")`:
/// blake2s256("ego/addr/v1" || chain_id_u32_le || pubkey)[..20], version byte
/// (0b001<<5)|0, bech32m over the 21-byte payload.
fn ed25519_pubkey_to_address(pk: &[u8]) -> Option<String> {
    use blake2::{Blake2s256, Digest};
    if pk.len() != 32 { return None; }
    let mut h = Blake2s256::new();
    h.update(b"ego/addr/v1");
    h.update(1u32.to_le_bytes());
    h.update(pk);
    let digest = h.finalize();
    let mut payload = [0u8; 21];
    payload[0] = 0b001 << 5; // version 1, AddressType::EOA = 0
    payload[1..].copy_from_slice(&digest[..20]);
    use bech32::ToBase32;
    bech32::encode("egot", payload.to_base32(), bech32::Variant::Bech32m).ok()
}

fn verify_block_qc(block: &Value) -> QcStatus {
    use blst::min_pk::{AggregateSignature, PublicKey, Signature};
    use blst::BLST_ERROR;

    let hash_hex = block["hash"].as_str().unwrap_or("");
    let agg_hex  = block["agg_bls_sig"].as_str().unwrap_or("");
    let pubkeys  = block["bls_pubkeys"].as_array();

    if agg_hex.is_empty() || pubkeys.map(|p| p.is_empty()).unwrap_or(true) {
        return QcStatus::Absent;
    }
    let (Ok(msg), Ok(agg_bytes)) = (hex::decode(hash_hex), hex::decode(agg_hex)) else {
        return QcStatus::Invalid;
    };
    let agg_sig = match Signature::from_bytes(&agg_bytes) {
        Ok(s) => s,
        Err(_) => return QcStatus::Invalid,
    };
    let pks: Vec<PublicKey> = pubkeys.unwrap().iter()
        .filter_map(|v| v.as_str())
        .filter_map(|h| hex::decode(h).ok())
        .filter_map(|b| PublicKey::from_bytes(&b).ok())
        .collect();
    if pks.is_empty() {
        return QcStatus::Invalid;
    }
    let pk_refs: Vec<&PublicKey> = pks.iter().collect();
    let _ = AggregateSignature::aggregate; // (verify path uses fast_aggregate_verify)
    if agg_sig.fast_aggregate_verify(true, &msg, BLS_DST, &pk_refs) == BLST_ERROR::BLST_SUCCESS {
        QcStatus::Valid
    } else {
        QcStatus::Invalid
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostingNodeRecord {
    pub node_id:   String,
    pub endpoint:  String,
    pub sites:     Vec<String>,
    pub domains:   Vec<String>,
    pub last_seen: i64,
}

type HostingNodes = HashMap<String, HostingNodeRecord>;

// ── PoST proof types ───────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostRewardApproval {
    pub proof_id:    String,
    pub prover_addr: String,
    pub cid:         String,
    pub reward_uegoc: u64,
    pub approved_at: i64,
}

const POST_REWARD_WINDOW_SECS: i64 = 1_800;
const POST_NODEPOOL_ADDR: &str = "egot1nodepool00000000000000000000000000000000";
const POST_RATE_LIMIT_CAP: usize = 200_000;

// ── Price types ────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PriceEntry {
    pub usd: f64,
    pub updated_at: i64,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub stale: bool,
}

type PriceMap = HashMap<String, PriceEntry>;

// ── Chain types ────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ChainState {
    pub blocks:       Vec<Value>,
    pub transactions: Vec<Value>,
}

#[derive(Deserialize)]
struct ChainQuery {
    #[serde(rename = "fromHeight")]
    from_height: Option<u64>,
    limit: Option<usize>,
}

const MAX_BLOCKS: usize       = 50_000;
const MAX_TRANSACTIONS: usize = 500_000;


fn normalize_block_schema(block: &mut Value) {
    let obj = match block.as_object_mut() {
        Some(o) => o,
        None => return,
    };
    if !obj.contains_key("coinbase_tx")    { obj.insert("coinbase_tx".into(),    Value::Null); }
    if !obj.contains_key("vote_count")     { obj.insert("vote_count".into(),     json!(0u32)); }
    if !obj.contains_key("tx_merkle_root") { obj.insert("tx_merkle_root".into(), json!("")); }
    if !obj.contains_key("poc_ticket")     { obj.insert("poc_ticket".into(),     json!("")); }
    if !obj.contains_key("poc_slot")       { obj.insert("poc_slot".into(),       json!(0u64)); }
    if !obj.contains_key("state_root")     { obj.insert("state_root".into(),     json!("")); }
    if !obj.contains_key("base_fee_uegoc") { obj.insert("base_fee_uegoc".into(), json!(0u64)); }
    if !obj.contains_key("agg_bls_sig")    { obj.insert("agg_bls_sig".into(),    json!("")); }
    if !obj.contains_key("bls_pubkeys")    { obj.insert("bls_pubkeys".into(),    json!([])); }
    if !obj.contains_key("tx_count")       { obj.insert("tx_count".into(),       json!(0u32)); }
    if !obj.contains_key("size_bytes")     { obj.insert("size_bytes".into(),     json!(0u64)); }
    if !obj.contains_key("reward")         { obj.insert("reward".into(),         json!(0u64)); }
}

impl ChainState {
    fn merge_block(&mut self, mut block: Value) {
        normalize_block_schema(&mut block);
        let height   = block["height"].as_u64().unwrap_or(0);
        let new_hash = block["hash"].as_str().unwrap_or("").to_string();

        if let Some(pos) = self.blocks.iter().position(|b| b["height"].as_u64() == Some(height)) {
            let old_hash = self.blocks[pos]["hash"].as_str().unwrap_or("").to_string();
            self.blocks[pos] = block;
            if !old_hash.is_empty() && old_hash != new_hash {
                self.prune_descendants_of(&old_hash);
            }
        } else {
            self.blocks.push(block);
            if self.blocks.len() > MAX_BLOCKS {
                self.blocks.sort_by_key(|b| b["height"].as_u64().unwrap_or(0));
                self.blocks = self.blocks.split_off(self.blocks.len() - MAX_BLOCKS);
            }
        }
    }

    /// Validating merge: structural sanity + parent linkage. Rejects malformed
    /// blocks and silent history rewrites (a replacement at an existing height
    /// whose prev_hash doesn't match the stored parent). Out-of-order delivery
    /// is tolerated — linkage is only enforced when the parent is already known.
    fn merge_block_checked(&mut self, mut block: Value) -> Result<(), String> {
        normalize_block_schema(&mut block);
        let height   = block["height"].as_u64().ok_or("block missing numeric height")?;
        let new_hash = block["hash"].as_str().unwrap_or("").to_string();
        let prev     = block["prev_hash"].as_str().unwrap_or("").to_string();

        if new_hash.len() < 40 {
            return Err("block hash too short / missing".into());
        }
        let hash_ok = new_hash == GENESIS_HASH
            || new_hash.bytes().all(|c| c.is_ascii_hexdigit());
        if !hash_ok {
            return Err("block hash is not valid hex".into());
        }

        if height == 0 {
            if new_hash != GENESIS_HASH {
                return Err("genesis block hash mismatch".into());
            }
        } else if prev.len() < 40 {
            return Err("non-genesis block missing prev_hash".into());
        }

        // Testnet-wipe recovery: the anti-rewrite checks below correctly refuse to
        // let an unrelated chain silently overwrite history at the same height —
        // but after an intentional wipe (fresh genesis, height counting restarts),
        // every new block's honest prev_hash will conflict with the abandoned old
        // chain's block at that same height FOREVER, since the old data never ages
        // out (MAX_BLOCKS is 50,000; a wipe rarely produces enough new blocks to
        // out-compete it by height). That permanently blinds the explorer.
        // Detection: our stored data has gone stale (no accepted block in a long
        // time — blocks are produced at least every ~60s even when idle) AND this
        // submission doesn't line up with what we're holding. That combination
        // only happens after a deliberate reset, so treat the old chain as dead
        // and start fresh rather than rejecting the live chain forever.
        const STALE_RESET_SECS: i64 = 600;
        if height > 0 {
            let last_seen = self.blocks.iter()
                .filter_map(|b| b["timestamp"].as_i64())
                .max()
                .unwrap_or(0);
            let stale = !self.blocks.is_empty() && Utc::now().timestamp() - last_seen > STALE_RESET_SECS;
            if stale {
                let conflicts = self.blocks.iter().any(|b| {
                    (b["height"].as_u64() == Some(height) && b["hash"].as_str() != Some(new_hash.as_str()))
                        || (b["height"].as_u64() == Some(height - 1) && b["hash"].as_str() != Some(prev.as_str()))
                });
                if conflicts {
                    info!(
                        "Stored chain stale for {}s and block #{} doesn't link to it — treating as a chain reset, clearing stored history",
                        Utc::now().timestamp() - last_seen, height,
                    );
                    self.blocks.clear();
                    self.transactions.clear();
                    self.blocks.push(genesis_chain_state().blocks.remove(0));
                }
            }
        }

        // Parent linkage (best-effort: only when we already hold height-1).
        if height > 0 {
            if let Some(parent) = self.blocks.iter().find(|b| b["height"].as_u64() == Some(height - 1)) {
                if parent["hash"].as_str() != Some(prev.as_str()) {
                    return Err(format!(
                        "prev_hash does not link to known parent at height {}", height - 1
                    ));
                }
            }
        }

        // Reject silent rewrite: a different block already occupies this height
        // whose hash differs and whose parent linkage we can't justify.
        if let Some(existing) = self.blocks.iter().find(|b| b["height"].as_u64() == Some(height)) {
            let old_hash = existing["hash"].as_str().unwrap_or("");
            if !old_hash.is_empty() && old_hash != new_hash {
                // Only allow the replacement if it links to a parent we hold.
                let parent_known = height == 0
                    || self.blocks.iter().any(|b| b["height"].as_u64() == Some(height - 1)
                        && b["hash"].as_str() == Some(prev.as_str()));
                if !parent_known {
                    return Err("refusing to replace existing block with unlinked fork".into());
                }
            }
        }

        // Quorum-certificate check. A block that carries a QC must carry a VALID
        // one — this rejects forged blocks regardless of the submit token. Blocks
        // without a QC (solo/bootstrap) are still accepted unless ORACLE_REQUIRE_QC
        // is set, which enforces a valid QC on every non-genesis block (use once
        // the network reliably produces quorum certificates, to retire the token).
        if height > 0 {
            match verify_block_qc(&block) {
                QcStatus::Invalid => {
                    return Err(format!("block #{} has an invalid quorum certificate", height));
                }
                QcStatus::Absent => {
                    if std::env::var("ORACLE_REQUIRE_QC").map(|v| v == "1").unwrap_or(false) {
                        return Err(format!("block #{} missing required quorum certificate", height));
                    }
                }
                QcStatus::Valid => {
                    // Signers proven; now require they carry ≥⅔ of validator stake
                    // (no-op until the network passes the bootstrap thresholds).
                    self.qc_stake_weight_ok(&block)?;
                    static QC_SEEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
                    if !QC_SEEN.swap(true, std::sync::atomic::Ordering::Relaxed) {
                        info!("Quorum-certificate verification ACTIVE — first valid QC accepted at block #{}", height);
                    }
                }
            }
        }

        self.merge_block(block);
        Ok(())
    }

    fn prune_descendants_of(&mut self, parent_hash: &str) {
        let orphaned: Vec<String> = self.blocks.iter()
            .filter(|b| b["prev_hash"].as_str() == Some(parent_hash))
            .filter_map(|b| b["hash"].as_str().map(String::from))
            .collect();
        self.blocks.retain(|b| b["prev_hash"].as_str() != Some(parent_hash));
        for hash in orphaned {
            self.prune_descendants_of(&hash);
        }
    }

    fn merge_txs(&mut self, txs: Vec<Value>) {
        for tx in txs {
            let hash = tx["hash"].as_str().unwrap_or("").to_string();
            if hash.is_empty() { continue; }
            if !self.transactions.iter().any(|t| t["hash"].as_str() == Some(&hash)) {
                self.transactions.push(tx);
            }
        }
        if self.transactions.len() > MAX_TRANSACTIONS {
            self.transactions = self.transactions.split_off(self.transactions.len() - MAX_TRANSACTIONS);
        }
    }

    /// Replay confirmed stake/unstake transactions into an address→stake map.
    /// Mirrors the node's validator-stake tracker. This is the weight input for
    /// the (upcoming) stake-weighted quorum check — derived purely from the chain
    /// the oracle already holds, no extra trust.
    fn validator_stakes(&self) -> std::collections::HashMap<String, u64> {
        const STAKING_ADDR: &str = "egot1staking000000000000000000000000000000000";
        let mut stakes: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        // Process oldest-first so stake/unstake apply in order.
        let mut txs = self.transactions.clone();
        txs.sort_by_key(|t| t["timestamp"].as_i64().unwrap_or(0));
        for tx in &txs {
            let to = tx["to"].as_str().unwrap_or("");
            if to != STAKING_ADDR { continue; }
            let from = tx["from"].as_str().unwrap_or("");
            if from.is_empty() { continue; }
            let amount = tx["amount"].as_u64().unwrap_or(0);
            match tx["tx_type"].as_str().unwrap_or("") {
                "stake"   => { *stakes.entry(from.to_string()).or_insert(0) += amount; }
                "unstake" => {
                    let e = stakes.entry(from.to_string()).or_insert(0);
                    *e = e.saturating_sub(amount);
                }
                _ => {}
            }
        }
        stakes.retain(|_, &mut v| v > 0);
        stakes
    }

    /// Build the verified address→BLS-pubkey registry from on-chain
    /// `validator_register` txs. Each binding is accepted only if the tx's
    /// Ed25519 pubkey derives `from` AND the bind-signature over the BLS pubkey
    /// is valid — so the oracle trusts no one for the binding.
    fn validator_bls_registry(&self) -> std::collections::HashMap<String, Vec<u8>> {
        use ed25519_dalek::{VerifyingKey, Signature, Verifier};
        let mut reg = std::collections::HashMap::new();
        let mut txs = self.transactions.clone();
        txs.sort_by_key(|t| t["timestamp"].as_i64().unwrap_or(0));
        for tx in &txs {
            if tx["tx_type"].as_str() != Some("validator_register") { continue; }
            let from = tx["from"].as_str().unwrap_or("");
            let ed_hex = tx["public_key_ed25519"].as_str().unwrap_or("");
            let memo = tx["memo"].as_str().unwrap_or("");
            let parts: Vec<&str> = memo.splitn(3, ':').collect();
            if parts.len() != 3 || parts[0] != "valreg" { continue; }
            let Ok(ed_bytes) = hex::decode(ed_hex) else { continue };
            if ed25519_pubkey_to_address(&ed_bytes).as_deref() != Some(from) { continue; }
            let (Ok(bls_bytes), Ok(sig_bytes)) = (hex::decode(parts[1]), hex::decode(parts[2])) else { continue };
            let Ok(ed_arr): Result<[u8; 32], _> = ed_bytes.try_into() else { continue };
            let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.try_into() else { continue };
            let Ok(vk) = VerifyingKey::from_bytes(&ed_arr) else { continue };
            if vk.verify(&bls_bytes, &Signature::from_bytes(&sig_arr)).is_err() { continue; }
            reg.insert(from.to_string(), bls_bytes);
        }
        reg
    }

    /// Stake-weighted quorum gate for a block's QC. Returns Ok(()) if the QC's
    /// BLS signers represent ≥⅔ of total validator stake — or if the network is
    /// still below the bootstrap thresholds (then it's a no-op, matching the node).
    fn qc_stake_weight_ok(&self, block: &Value) -> Result<(), String> {
        let stakes = self.validator_stakes();
        let total_stake: u64 = stakes.values().sum();
        if stakes.len() < MIN_VALIDATORS_FOR_STAKE_QUORUM || total_stake < MIN_STAKE_FOR_QUORUM_UEGOC {
            return Ok(()); // bootstrap phase — weight check not yet enforced
        }
        let registry = self.validator_bls_registry();
        // reverse map: bls pubkey hex → address
        let mut by_bls: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        for (addr, bls) in &registry {
            by_bls.insert(hex::encode(bls), addr.clone());
        }
        let signers = block["bls_pubkeys"].as_array().cloned().unwrap_or_default();
        let mut signer_stake: u64 = 0;
        let mut counted: std::collections::HashSet<String> = std::collections::HashSet::new();
        for pk in signers.iter().filter_map(|v| v.as_str()) {
            if let Some(addr) = by_bls.get(pk) {
                if counted.insert(addr.clone()) {
                    signer_stake += stakes.get(addr).copied().unwrap_or(0);
                }
            }
        }
        if (signer_stake as u128) * 3 < (total_stake as u128) * 2 {
            return Err(format!(
                "QC stake weight {} < ⅔ of {} total", signer_stake, total_stake
            ));
        }
        Ok(())
    }

    fn sorted_blocks(&self) -> Vec<Value> {
        let mut v = self.blocks.clone();
        for block in v.iter_mut() {
            normalize_block_schema(block);
        }
        v.sort_by(|a, b| {
            b["height"].as_u64().unwrap_or(0).cmp(&a["height"].as_u64().unwrap_or(0))
        });
        v
    }

    fn sorted_txs(&self) -> Vec<Value> {
        let mut v = self.transactions.clone();
        v.sort_by(|a, b| {
            b["timestamp"].as_i64().unwrap_or(0).cmp(&a["timestamp"].as_i64().unwrap_or(0))
        });
        v
    }
}

fn chain_data_path() -> std::path::PathBuf {
    std::env::var("ORACLE_DATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/var/lib/ego-oracle/chain.json"))
}

fn genesis_chain_state() -> ChainState {
    let mut g = json!({
        "height":    0,
        "hash":      GENESIS_HASH,
        "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "miner":     GENESIS_MINER,
        "timestamp": GENESIS_TS,
        "tx_count":  0,
        "size_bytes": 0,
        "reward":    0,
    });
    normalize_block_schema(&mut g);
    ChainState {
        blocks: vec![g],
        transactions: vec![],
    }
}

fn load_chain() -> ChainState {
    let path = chain_data_path();
    if let Ok(data) = std::fs::read_to_string(&path) {
        if let Ok(mut state) = serde_json::from_str::<ChainState>(&data) {
            if !state.blocks.iter().any(|b| b["height"].as_u64() == Some(0)) {
                let mut g = genesis_chain_state();
                state.blocks.push(g.blocks.remove(0));
            }
            // Normalize any blocks that were persisted with an older/stripped
            // schema so consumers always see the full LedgerBlock shape.
            for block in state.blocks.iter_mut() {
                normalize_block_schema(block);
            }
            info!("Loaded chain state from disk: {} blocks, {} txs", state.blocks.len(), state.transactions.len());
            return state;
        }
    }
    info!("No persisted chain state found, seeding genesis");
    genesis_chain_state()
}

fn save_chain(chain: &ChainState) {
    let path = chain_data_path();
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            error!("Chain persistence FAILED: cannot create dir {}: {}. \
                    Set ORACLE_DATA to a writable path — the chain will be LOST on restart.",
                   parent.display(), e);
            return;
        }
    }
    match serde_json::to_string(chain) {
        Ok(data) => {
            // Write to a temp file then rename, so a crash mid-write can't corrupt
            // the persisted chain.
            let tmp = path.with_extension("json.tmp");
            if let Err(e) = std::fs::write(&tmp, &data) {
                error!("Chain persistence FAILED: cannot write {}: {}. \
                        Set ORACLE_DATA to a writable path — the chain will be LOST on restart.",
                       tmp.display(), e);
                return;
            }
            if let Err(e) = std::fs::rename(&tmp, &path) {
                error!("Chain persistence FAILED: cannot rename into {}: {}", path.display(), e);
            }
        }
        Err(e) => { error!("Failed to serialize chain state: {}", e); }
    }
}

/// Sibling of the chain file: the trusted fast-sync snapshot. Persisted so an
/// oracle restart never strands joining nodes (no snapshot → fresh nodes can't
/// jump to tip and can't paginate genesis→tip because early blocks are pruned).
fn snapshot_data_path() -> std::path::PathBuf {
    chain_data_path().with_file_name("snapshot.json")
}

fn load_snapshot() -> Option<serde_json::Value> {
    let data = std::fs::read_to_string(snapshot_data_path()).ok()?;
    let v: serde_json::Value = serde_json::from_str(&data).ok()?;
    let h = v.get("height").and_then(|x| x.as_u64()).unwrap_or(0);
    if h == 0 { return None; }
    info!("Loaded fast-sync snapshot from disk at height {}", h);
    Some(v)
}

fn save_snapshot(snap: &serde_json::Value) {
    let path = snapshot_data_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(data) = serde_json::to_string(snap) {
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, &data).is_ok() {
            if let Err(e) = std::fs::rename(&tmp, &path) {
                error!("Snapshot persistence FAILED: cannot rename into {}: {}", path.display(), e);
            }
        }
    }
}

// ── App state ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub prices:         Arc<RwLock<PriceMap>>,
    pub chain:          Arc<RwLock<ChainState>>,
    pub client:         Client,
    pub hosting_nodes:  Arc<RwLock<HostingNodes>>,
    /// Peer rendezvous: dialable node endpoint → last-seen unix ts. Nodes POST
    /// their relayed /p2p-circuit address to /nodes/register and GET /nodes to
    /// discover and dial each other (so two NAT'd nodes behind one relay meet).
    pub ego_nodes:      Arc<RwLock<HashMap<String, i64>>>,
    pub acme:           Arc<acme::AcmeState>,
    pub post_approvals: Arc<RwLock<HashMap<String, PostRewardApproval>>>,
    pub post_rate_limit: Arc<RwLock<HashMap<String, i64>>>,
    /// Shared secret required on chain-mutating endpoints. When `None`, submits
    /// are still accepted but a loud SECURITY warning is logged on every call —
    /// set ORACLE_SUBMIT_TOKEN before any public exposure to enforce auth.
    pub submit_token: Option<String>,
    /// Latest trusted state snapshot (raw JSON from a writer node) for checkpoint
    /// fast-sync. Kept in memory; the writer re-pushes it every ~100 blocks.
    pub snapshot:     Arc<RwLock<Option<serde_json::Value>>>,
    pub blocks_cache: Arc<RwLock<Option<Arc<Vec<Value>>>>>,
    pub txs_cache:    Arc<RwLock<Option<Arc<Vec<Value>>>>>,
    /// Set on every submit; a background task debounces the expensive full-chain
    /// clone+save to disk so it never runs under the request's write lock.
    pub chain_dirty:  Arc<std::sync::atomic::AtomicBool>,
    /// Lock-free chain stats for /health. Updated on submit; read without ever
    /// taking the chain lock, so /health can't starve behind submits or the saver.
    pub stat_blocks:  Arc<std::sync::atomic::AtomicU64>,
    pub stat_txs:     Arc<std::sync::atomic::AtomicU64>,
    pub stat_tip:     Arc<std::sync::atomic::AtomicU64>,
}

const EGOC_USD: f64 = 0.01;
const EGOC_SUPPLY: u64 = 1_000_000_000;
const EGOC_MARKET_CAP: f64 = EGOC_USD * EGOC_SUPPLY as f64;

static BINANCE_SYMBOLS: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("BTC", "BTCUSDT");
    m.insert("ETH", "ETHUSDT");
    m.insert("SOL", "SOLUSDT");
    m.insert("BNB", "BNBUSDT");
    m.insert("MATIC", "MATICUSDT");
    m
});

// ── Price fetching ─────────────────────────────────────────────────────────────

async fn fetch_coingecko(client: &Client) -> anyhow::Result<HashMap<String, f64>> {
    let url = "https://api.coingecko.com/api/v3/simple/price\
               ?ids=ethereum,bitcoin,solana,binancecoin,matic-network\
               &vs_currencies=usd";
    let resp: Value = client.get(url).timeout(Duration::from_secs(10)).send().await?
        .error_for_status()?.json().await?;
    let mut out = HashMap::new();
    for (id, sym) in &[("bitcoin","BTC"),("ethereum","ETH"),("solana","SOL"),("binancecoin","BNB"),("matic-network","MATIC")] {
        if let Some(price) = resp[id]["usd"].as_f64() { out.insert(sym.to_string(), price); }
    }
    Ok(out)
}

async fn fetch_binance(client: &Client) -> anyhow::Result<HashMap<String, f64>> {
    #[derive(Deserialize)]
    struct Ticker { symbol: String, price: String }
    let tickers: Vec<Ticker> = client.get("https://api.binance.com/api/v3/ticker/price")
        .timeout(Duration::from_secs(10)).send().await?.error_for_status()?.json().await?;
    let reverse: HashMap<&str, &str> = BINANCE_SYMBOLS.iter().map(|(s, t)| (*t, *s)).collect();
    let mut out = HashMap::new();
    for t in &tickers {
        if let Some(&sym) = reverse.get(t.symbol.as_str()) {
            if let Ok(price) = t.price.parse::<f64>() { out.insert(sym.to_string(), price); }
        }
    }
    Ok(out)
}

fn average_maps(a: HashMap<String, f64>, b: HashMap<String, f64>) -> HashMap<String, f64> {
    let mut result = HashMap::new();
    let keys: std::collections::HashSet<String> = a.keys().chain(b.keys()).cloned().collect();
    for key in keys {
        let price = match (a.get(&key), b.get(&key)) {
            (Some(&pa), Some(&pb)) => (pa + pb) / 2.0,
            (Some(&pa), None) => pa,
            (None, Some(&pb)) => pb,
            _ => continue,
        };
        result.insert(key, price);
    }
    result
}

async fn refresh_prices(state: AppState) {
    let now = Utc::now().timestamp();
    let (cg_result, bn_result) = (fetch_coingecko(&state.client).await, fetch_binance(&state.client).await);
    let (merged, stale) = match (cg_result, bn_result) {
        (Ok(cg), Ok(bn)) => { info!("Prices from CoinGecko+Binance"); (average_maps(cg, bn), false) }
        (Ok(cg), Err(e)) => { warn!("Binance failed ({})", e); (cg, false) }
        (Err(e), Ok(bn)) => { warn!("CoinGecko failed ({})", e); (bn, false) }
        (Err(e1), Err(e2)) => { error!("Both price sources failed: {} {}", e1, e2); (HashMap::new(), true) }
    };
    let mut prices = state.prices.write().await;
    if stale { for e in prices.values_mut() { e.stale = true; } return; }
    for (sym, usd) in merged { prices.insert(sym, PriceEntry { usd, updated_at: now, stale: false }); }
    prices.insert("EGOC".to_string(), PriceEntry { usd: EGOC_USD, updated_at: now, stale: false });
}

async fn price_refresh_task(state: AppState) {
    loop { refresh_prices(state.clone()).await; tokio::time::sleep(Duration::from_secs(30)).await; }
}

// ── Handlers: prices ──────────────────────────────────────────────────────────

async fn handle_prices(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.prices.read().await.clone())
}

async fn handle_price(State(state): State<AppState>, Path(symbol): Path<String>) -> impl IntoResponse {
    let sym = symbol.to_uppercase();
    let prices = state.prices.read().await;
    if let Some(entry) = prices.get(&sym) {
        (StatusCode::OK, Json(json!({ "symbol": sym, "usd": entry.usd, "updated_at": entry.updated_at, "stale": entry.stale })))
    } else {
        (StatusCode::NOT_FOUND, Json(json!({ "error": format!("symbol '{}' not found", sym) })))
    }
}

async fn handle_egoc(State(state): State<AppState>) -> impl IntoResponse {
    let updated_at = state.prices.read().await.get("EGOC").map(|e| e.updated_at).unwrap_or_else(|| Utc::now().timestamp());
    Json(json!({ "symbol": "EGOC", "usd": EGOC_USD, "market_cap": EGOC_MARKET_CAP, "supply": EGOC_SUPPLY, "updated_at": updated_at }))
}

// ── Handlers: chain ───────────────────────────────────────────────────────────

async fn handle_chain_blocks(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<ChainQuery>
) -> impl IntoResponse {
    let limit = q.limit.unwrap_or(500);

    if q.from_height.is_none() && limit <= 500 {
        let cached = { let c = state.blocks_cache.read().await; c.as_ref().cloned() };
        let arc = match cached {
            Some(a) => a,
            None => {
                let built: Vec<Value> = {
                    let chain = state.chain.read().await;
                    let mut refs: Vec<&Value> = chain.blocks.iter().collect();
                    refs.sort_by_key(|b| b["height"].as_u64().unwrap_or(0));
                    let start = refs.len().saturating_sub(500);
                    refs[start..].iter().map(|b| (*b).clone()).collect()
                };
                let a = Arc::new(built);
                *state.blocks_cache.write().await = Some(a.clone());
                a
            }
        };
        let skip = arc.len().saturating_sub(limit);
        return Json(arc.iter().skip(skip).cloned().collect::<Vec<Value>>());
    }

    let chain = state.chain.read().await;
    let mut refs: Vec<&Value> = match q.from_height {
        Some(from) => chain.blocks.iter()
            .filter(|b| b["height"].as_u64().unwrap_or(0) >= from)
            .collect(),
        None => chain.blocks.iter().collect(),
    };
    refs.sort_by_key(|b| b["height"].as_u64().unwrap_or(0));

    let out: Vec<Value> = if q.from_height.is_some() {
        refs.iter().take(limit).map(|b| (*b).clone()).collect()
    } else {
        let skip = refs.len().saturating_sub(limit);
        refs.iter().skip(skip).map(|b| (*b).clone()).collect()
    };
    Json(out)
}

async fn handle_chain_transactions(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<ChainQuery>
) -> impl IntoResponse {
    let limit = q.limit.unwrap_or(500);

    if q.from_height.is_none() && limit <= 500 {
        let cached = { let c = state.txs_cache.read().await; c.as_ref().cloned() };
        let arc = match cached {
            Some(a) => a,
            None => {
                let built: Vec<Value> = {
                    let chain = state.chain.read().await;
                    let mut refs: Vec<&Value> = chain.transactions.iter().collect();
                    refs.sort_by_key(|t| std::cmp::Reverse(t["block_height"].as_u64().unwrap_or(0)));
                    refs.iter().take(500).map(|t| (*t).clone()).collect()
                };
                let a = Arc::new(built);
                *state.txs_cache.write().await = Some(a.clone());
                a
            }
        };
        return Json(arc.iter().take(limit).cloned().collect::<Vec<Value>>());
    }

    let chain = state.chain.read().await;
    let from = q.from_height.unwrap_or(0);
    let mut refs: Vec<&Value> = chain.transactions.iter()
        .filter(|t| t["block_height"].as_u64().unwrap_or(0) >= from)
        .collect();
    refs.sort_by_key(|t| t["block_height"].as_u64().unwrap_or(0));
    let out: Vec<Value> = refs.iter().take(limit).map(|t| (*t).clone()).collect();
    Json(out)
}

#[derive(Deserialize)]
struct SubmitPayload {
    #[serde(default)]
    block: Option<Value>,
    #[serde(default)]
    blocks: Vec<Value>,
    #[serde(default)]
    transactions: Vec<Value>,
}

/// Constant-time-ish bearer/token check. Accepts the token via either
/// `Authorization: Bearer <token>` or `X-Ego-Submit-Token: <token>`.
fn submit_authorized(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(expected) = state.submit_token.as_deref() else {
        // No token configured — allowed but the startup warning already fired.
        return true;
    };
    let presented = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim_start_matches("Bearer ").trim())
        .filter(|v| !v.is_empty())
        .or_else(|| headers.get("x-ego-submit-token").and_then(|v| v.to_str().ok()));
    match presented {
        Some(tok) => {
            // length-independent comparison to avoid trivial timing leaks
            let a = tok.as_bytes();
            let b = expected.as_bytes();
            let mut diff = (a.len() ^ b.len()) as u8;
            for i in 0..a.len().max(b.len()) {
                diff |= a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0);
            }
            diff == 0
        }
        None => false,
    }
}

async fn handle_chain_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<SubmitPayload>,
) -> impl IntoResponse {
    if !submit_authorized(&state, &headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "invalid or missing submit token" })));
    }

    let mut chain = state.chain.write().await;
    let mut max_h: u64 = 0;

    if let Some(block) = payload.block {
        max_h = max_h.max(block["height"].as_u64().unwrap_or(0));
        if let Err(e) = chain.merge_block_checked(block) {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": e })));
        }
    }
    for block in payload.blocks {
        max_h = max_h.max(block["height"].as_u64().unwrap_or(0));
        if let Err(e) = chain.merge_block_checked(block) {
            // One bad block in a batch shouldn't poison the rest, but log it.
            error!("Oracle: rejected batched block: {}", e);
        }
    }
    chain.merge_txs(payload.transactions);

    let nblocks = chain.blocks.len() as u64;
    let ntxs = chain.transactions.len() as u64;
    drop(chain);
    // Do NOT invalidate the read caches here — a block arrives every few seconds,
    // so per-submit invalidation would keep /chain/blocks rebuilding (50k sort)
    // under the chain lock. A background task refreshes the caches instead.
    // Publish lock-free stats for /health, then flag the debounced saver. Never
    // clone the whole chain under the write lock here, or /health and submits starve.
    use std::sync::atomic::Ordering;
    state.stat_blocks.store(nblocks, Ordering::Relaxed);
    state.stat_txs.store(ntxs, Ordering::Relaxed);
    if max_h > state.stat_tip.load(Ordering::Relaxed) {
        state.stat_tip.store(max_h, Ordering::Relaxed);
    }
    state.chain_dirty.store(true, Ordering::Relaxed);

    (StatusCode::OK, Json(json!({ "ok": true, "blocks": nblocks, "txs": ntxs })))
}

// ── Handlers: hosting node registry ──────────────────────────────────────

async fn handle_hosting_announce(
    State(state): State<AppState>,
    Json(record): Json<HostingNodeRecord>,
) -> impl IntoResponse {
    let mut nodes = state.hosting_nodes.write().await;
    nodes.insert(record.node_id.clone(), record);
    StatusCode::OK
}

async fn handle_hosting_nodes(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> impl IntoResponse {
    let now = Utc::now().timestamp();
    let nodes = state.hosting_nodes.read().await;
    let matching: Vec<&HostingNodeRecord> = nodes.values()
        .filter(|n| n.last_seen > now - 900)
        .filter(|n| n.domains.iter().any(|d| d == &domain) || n.sites.iter().any(|s| s == &domain))
        .collect();
    Json(json!({ "domain": domain, "nodes": matching }))
}

async fn handle_nodes_register(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    if let Some(endpoint) = body["endpoint"].as_str() {
        let ep = endpoint.trim_end_matches('/').to_string();
        // Only relayed circuit addresses are dialable across NATs. Reject direct
        // LAN/loopback endpoints (e.g. 192.168.x / 127.0.0.1) that other nodes on
        // the internet could never reach — registering those just causes failed
        // dials. Override for same-LAN testing via EGO_ORACLE_ALLOW_DIRECT_PEERS.
        let dialable = ep.contains("/p2p-circuit")
            || std::env::var("EGO_ORACLE_ALLOW_DIRECT_PEERS").is_ok();
        if dialable {
            let now = Utc::now().timestamp();
            let mut nodes = state.ego_nodes.write().await;
            if nodes.insert(ep.clone(), now).is_none() {
                info!("[Registry] Ego node registered: {}", ep);
            }
        }
    }
    StatusCode::OK
}

/// Peer rendezvous: return node endpoints seen within the last 10 minutes so
/// nodes can dial each other. This is the read half of /nodes/register — without
/// it the registry is write-only and peers never discover one another.
async fn handle_nodes_list(State(state): State<AppState>) -> impl IntoResponse {
    let now = Utc::now().timestamp();
    let mut nodes = state.ego_nodes.write().await;
    nodes.retain(|_, seen| now - *seen < 600);
    let list: Vec<String> = nodes.keys().cloned().collect();
    Json(json!({ "nodes": list }))
}

// ── Checkpoint fast-sync: trusted state snapshot store/serve ──────────────
async fn handle_snapshot_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    if !submit_authorized(&state, &headers) {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "invalid or missing submit token" })));
    }
    let new_h = payload.get("height").and_then(|v| v.as_u64()).unwrap_or(0);
    if new_h == 0 {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "snapshot missing height" })));
    }
    let mut snap = state.snapshot.write().await;
    let cur_h = snap.as_ref().and_then(|s| s.get("height")).and_then(|v| v.as_u64()).unwrap_or(0);
    if new_h >= cur_h {
        *snap = Some(payload.clone());
        drop(snap);
        let to_save = payload.clone();
        tokio::task::spawn_blocking(move || save_snapshot(&to_save));
    } else {
        drop(snap);
    }

    // Self-heal: fill any holes in the block feed from the trusted snapshot, which
    // carries the full recent window. A dropped /chain/submit no longer leaves a
    // permanent gap that wedges syncing nodes — the next snapshot patches it.
    if let Some(blocks_arr) = payload.get("blocks").and_then(|b| b.as_array()) {
        let mut chain = state.chain.write().await;
        let existing: std::collections::HashSet<u64> =
            chain.blocks.iter().filter_map(|b| b["height"].as_u64()).collect();
        let mut missing: Vec<Value> = blocks_arr.iter()
            .filter(|b| b["height"].as_u64().map(|h| !existing.contains(&h)).unwrap_or(false))
            .cloned()
            .collect();
        let mut filled = 0u32;
        if !missing.is_empty() {
            missing.sort_by_key(|b| b["height"].as_u64().unwrap_or(0)); // parents before children
            for b in missing {
                if chain.merge_block_checked(b).is_ok() { filled += 1; }
            }
        }
        let nblocks = chain.blocks.len() as u64;
        drop(chain);
        if filled > 0 {
            use std::sync::atomic::Ordering;
            state.stat_blocks.store(nblocks, Ordering::Relaxed);
            state.chain_dirty.store(true, Ordering::Relaxed);
            info!("[SelfHeal] snapshot merge filled {} missing block(s) in the oracle feed", filled);
        }
    }

    (StatusCode::OK, Json(json!({ "ok": true, "height": new_h.max(cur_h) })))
}

async fn handle_snapshot_get(State(state): State<AppState>) -> impl IntoResponse {
    let snap = state.snapshot.read().await;
    match snap.as_ref() {
        Some(v) => (StatusCode::OK, Json(v.clone())),
        None    => (StatusCode::NOT_FOUND, Json(json!({ "error": "no snapshot available yet" }))),
    }
}

// ── Handlers: TLS cert automation (Let's Encrypt DNS-01) ─────────────────

#[derive(serde::Deserialize)]
struct CertRequest { domain: String }

// Cert-request abuse guard: each ACME issuance counts against Let's Encrypt
// rate limits, so we cap per-domain re-requests and total issuance volume.
static CERT_RATE: once_cell::sync::Lazy<std::sync::Mutex<std::collections::HashMap<String, i64>>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));
const CERT_DOMAIN_COOLDOWN_SECS: i64 = 3600;     // one issuance per domain per hour
const CERT_GLOBAL_WINDOW_SECS:   i64 = 3600;
const CERT_GLOBAL_MAX_PER_WINDOW: usize = 50;    // total new domains per hour

async fn handle_cert_request(
    State(state): State<AppState>,
    Json(body): Json<CertRequest>,
) -> impl IntoResponse {
    let domain = body.domain.trim().to_lowercase();
    if domain.is_empty() || !domain.contains('.') || domain.len() > 253 {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid domain" })));
    }
    // Basic hostname sanity — block obvious junk before hitting ACME.
    if !domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid domain characters" })));
    }
    {
        let now = Utc::now().timestamp();
        let mut rate = CERT_RATE.lock().unwrap_or_else(|e| e.into_inner());
        rate.retain(|_, &mut t| now - t < CERT_GLOBAL_WINDOW_SECS);
        if let Some(&last) = rate.get(&domain) {
            if now - last < CERT_DOMAIN_COOLDOWN_SECS {
                return (StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({ "error": "cert recently requested for this domain; retry later" })));
            }
        }
        if rate.len() >= CERT_GLOBAL_MAX_PER_WINDOW {
            return (StatusCode::TOO_MANY_REQUESTS,
                Json(json!({ "error": "cert issuance rate limit reached; retry later" })));
        }
        rate.insert(domain.clone(), now);
    }
    state.acme.request(domain.clone()).await;
    (StatusCode::ACCEPTED, Json(json!({ "domain": domain, "status": "pending" })))
}

async fn handle_cert_status(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> impl IntoResponse {
    match state.acme.status(&domain).await {
        Some(status) => (StatusCode::OK, Json(serde_json::to_value(&status).unwrap_or_default())),
        None         => (StatusCode::NOT_FOUND, Json(json!({ "error": "no cert request found" }))),
    }
}

// ── Handlers: PoST proof & rewards ───────────────────────────────────────────

#[derive(Deserialize)]
struct PostProofPayload {
    challenge_id:    String,
    cid:             String,
    prover_addr:     String,
    n_real_leaves:   u64,
    #[allow(dead_code)]
    n_padded_leaves: u64,
    timestamp:       i64,
    signature:       String,
    public_key:      String,
}

async fn handle_post_proof(
    State(state): State<AppState>,
    Json(body): Json<PostProofPayload>,
) -> impl IntoResponse {
    let now = Utc::now().timestamp();

    if body.prover_addr.is_empty() || body.cid.is_empty() || body.signature.is_empty() || body.public_key.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "missing required fields" })));
    }

    if (now - body.timestamp).abs() > 300 {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "timestamp too old or too far in future" })));
    }

    let pk_bytes: [u8; 32] = match hex::decode(&body.public_key)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(b) => b,
        None => return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid public key" }))),
    };
    let sig_bytes: [u8; 64] = match hex::decode(&body.signature)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(b) => b,
        None => return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid signature" }))),
    };

    use ed25519_dalek::{Signature, VerifyingKey, Verifier};
    let vk = match VerifyingKey::from_bytes(&pk_bytes) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid public key" }))),
    };
    let sig = Signature::from_bytes(&sig_bytes);
    let sign_data = format!("{}:{}:{}", body.challenge_id, body.cid, body.timestamp);
    if vk.verify(sign_data.as_bytes(), &sig).is_err() {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "signature verification failed" })));
    }

    let rate_key = format!("{}:{}", body.prover_addr, body.cid);
    {
        let mut rl = state.post_rate_limit.write().await;
        if let Some(&last) = rl.get(&rate_key) {
            if now - last < POST_REWARD_WINDOW_SECS {
                return (StatusCode::TOO_MANY_REQUESTS, Json(json!({
                    "error": format!("already proved — next window in {}s", POST_REWARD_WINDOW_SECS - (now - last))
                })));
            }
        }
        rl.insert(rate_key, now);
        if rl.len() > POST_RATE_LIMIT_CAP {
            if let Some(oldest) = rl.iter().min_by_key(|(_, v)| *v).map(|(k, _)| k.clone()) {
                rl.remove(&oldest);
            }
        }
    }

    let file_bytes = body.n_real_leaves.saturating_mul(1_024);
    let reward_uegoc = ((file_bytes as f64 / 1_000_000_000.0) * 10_416.0).max(1_000.0) as u64;

    let proof_id = format!("0x{}", blake3::hash(
        format!("post_reward:{}:{}:{}", body.prover_addr, body.cid, now).as_bytes()
    ).to_hex());

    let approval = PostRewardApproval {
        proof_id:    proof_id.clone(),
        prover_addr: body.prover_addr.clone(),
        cid:         body.cid.clone(),
        reward_uegoc,
        approved_at: now,
    };

    {
        let mut approvals = state.post_approvals.write().await;
        approvals.insert(proof_id.clone(), approval);
    }

    info!("[PoST] Approved {} uEGOC → {} for CID {}…", reward_uegoc, body.prover_addr, &body.cid[..body.cid.len().min(16)]);
    (StatusCode::OK, Json(json!({ "ok": true, "reward_uegoc": reward_uegoc, "proof_id": proof_id })))
}

async fn handle_post_pending_rewards(State(state): State<AppState>) -> impl IntoResponse {
    let approvals = state.post_approvals.read().await;
    let list: Vec<&PostRewardApproval> = approvals.values().collect();
    Json(json!(list))
}

#[derive(Deserialize)]
struct ClaimedPayload {
    proof_ids: Vec<String>,
}

async fn handle_post_rewards_claimed(
    State(state): State<AppState>,
    Json(body): Json<ClaimedPayload>,
) -> impl IntoResponse {
    let mut approvals = state.post_approvals.write().await;
    let mut removed = 0usize;
    for id in &body.proof_ids {
        if approvals.remove(id).is_some() { removed += 1; }
    }
    info!("[PoST] Cleared {} claimed rewards ({} remaining)", removed, approvals.len());
    (StatusCode::OK, Json(json!({ "ok": true, "removed": removed })))
}

async fn handle_post_challenges(Path(_addr): Path<String>) -> impl IntoResponse {
    Json(json!([]))
}

// ── Handler: health ───────────────────────────────────────────────────────────

async fn handle_health(State(state): State<AppState>) -> impl IntoResponse {
    let prices = state.prices.read().await;
    let last_update = prices.values().map(|e| e.updated_at).max().unwrap_or(0);
    let prices_count = prices.len();
    drop(prices);

    // Fully lock-free: read the atomics, never touch the chain lock — so /health
    // can't stall behind a submit's write lock or the saver's clone.
    use std::sync::atomic::Ordering;
    let tip     = state.stat_tip.load(Ordering::Relaxed);
    let nblocks = state.stat_blocks.load(Ordering::Relaxed);
    let ntxs    = state.stat_txs.load(Ordering::Relaxed);
    Json(json!({
        "status":       "ok",
        "prices_count": prices_count,
        "last_update":  last_update,
        "chain_blocks": nblocks,
        "chain_tip":    tip,
        "block_height": tip,
        "chain_txs":    ntxs,
        "tx_count":     ntxs,
    }))
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ego_oracle=info,tower_http=warn".parse().unwrap()),
        )
        .init();

    let port: u16 = std::env::var("PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(8547);
    info!("Ego Oracle starting on port {}", port);

    let client = Client::builder().user_agent("ego-oracle/1.0").build().expect("failed to build HTTP client");

    let mut initial_prices: PriceMap = HashMap::new();
    initial_prices.insert("EGOC".to_string(), PriceEntry { usd: EGOC_USD, updated_at: Utc::now().timestamp(), stale: false });

    let acme_state = acme::AcmeState::new();

    let loaded_chain = load_chain();
    let init_tip = loaded_chain.blocks.iter().map(|b| b["height"].as_u64().unwrap_or(0)).max().unwrap_or(0);
    let init_blocks = loaded_chain.blocks.len() as u64;
    let init_txs = loaded_chain.transactions.len() as u64;

    let state = AppState {
        prices:          Arc::new(RwLock::new(initial_prices)),
        chain:           Arc::new(RwLock::new(loaded_chain)),
        client,
        hosting_nodes:   Arc::new(RwLock::new(HashMap::new())),
        ego_nodes:       Arc::new(RwLock::new(HashMap::new())),
        acme:            acme_state,
        post_approvals:  Arc::new(RwLock::new(HashMap::new())),
        post_rate_limit: Arc::new(RwLock::new(HashMap::new())),
        submit_token:    std::env::var("ORACLE_SUBMIT_TOKEN").ok().filter(|s| !s.trim().is_empty()),
        snapshot:        Arc::new(RwLock::new(load_snapshot())),
        blocks_cache:    Arc::new(RwLock::new(None)),
        txs_cache:       Arc::new(RwLock::new(None)),
        chain_dirty:     Arc::new(std::sync::atomic::AtomicBool::new(false)),
        stat_blocks:     Arc::new(std::sync::atomic::AtomicU64::new(init_blocks)),
        stat_txs:        Arc::new(std::sync::atomic::AtomicU64::new(init_txs)),
        stat_tip:        Arc::new(std::sync::atomic::AtomicU64::new(init_tip)),
    };
    if state.submit_token.is_none() {
        error!("SECURITY: ORACLE_SUBMIT_TOKEN is not set — /chain/submit is UNAUTHENTICATED. \
                Set this env var (matching EGO_ORACLE_SUBMIT_TOKEN on nodes) before public launch.");
    } else {
        info!("Chain-submit authentication enabled (ORACLE_SUBMIT_TOKEN set)");
    }

    tokio::spawn(price_refresh_task(state.clone()));

    // Background maintenance:
    //  • every 4s — rebuild the read caches (last 500 blocks / 500 txs) from a
    //    brief shared read lock, so /chain/blocks always serves a warm cache and
    //    never sorts 50k blocks under a request.
    //  • every ~16s — if the chain changed, clone+save to disk (the only heavy
    //    lock hold), so persistence never runs under a submit's write lock.
    {
        use std::sync::atomic::Ordering;
        let state = state.clone();
        tokio::spawn(async move {
            let mut tick: u32 = 0;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(4)).await;
                tick = tick.wrapping_add(1);

                let (blocks500, txs500) = {
                    let chain = state.chain.read().await;
                    let mut brefs: Vec<&Value> = chain.blocks.iter().collect();
                    brefs.sort_by_key(|b| b["height"].as_u64().unwrap_or(0));
                    let bstart = brefs.len().saturating_sub(500);
                    let blocks500: Vec<Value> = brefs[bstart..].iter().map(|b| (*b).clone()).collect();

                    let mut trefs: Vec<&Value> = chain.transactions.iter().collect();
                    trefs.sort_by_key(|t| std::cmp::Reverse(t["block_height"].as_u64().unwrap_or(0)));
                    let txs500: Vec<Value> = trefs.iter().take(500).map(|t| (*t).clone()).collect();
                    (blocks500, txs500)
                };
                *state.blocks_cache.write().await = Some(Arc::new(blocks500));
                *state.txs_cache.write().await = Some(Arc::new(txs500));

                if tick % 4 == 0 && state.chain_dirty.swap(false, Ordering::Relaxed) {
                    let snapshot = { state.chain.read().await.clone() };
                    let _ = tokio::task::spawn_blocking(move || save_chain(&snapshot)).await;
                }
            }
        });
    }

    let relay_ip_str = std::env::var("RELAY_PUBLIC_IP").unwrap_or_else(|_| "127.0.0.1".to_string());
    let dns_upstream  = std::env::var("DNS_UPSTREAM").unwrap_or_else(|_| "8.8.8.8:53".to_string());
    let relay_ip: [u8; 4] = relay_ip_str.split('.')
        .map(|p| p.parse::<u8>().unwrap_or(0))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap_or([127, 0, 0, 1]);
    let dns_nodes      = state.hosting_nodes.clone();
    let dns_challenges = state.acme.challenges.clone();
    tokio::spawn(async move {
        dns::run_dns_server(relay_ip, dns_upstream, dns_nodes, dns_challenges).await;
    });

    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);

    let app = Router::new()
        .route("/health",                   get(handle_health))
        // Read-only chain index for the public block explorer. NOT part of consensus —
        // peers reach finality peer-to-peer; writer nodes fire-and-forget finalized blocks
        // here so explorer.html (rpc.egoblockchain.com/chain/blocks) has data to show.
        .route("/chain/blocks",             get(handle_chain_blocks))
        .route("/chain/transactions",       get(handle_chain_transactions))
        .route("/chain/submit",             post(handle_chain_submit))
        .route("/prices",                   get(handle_prices))
        .route("/price/:symbol",            get(handle_price))
        .route("/egoc",                     get(handle_egoc))
        .route("/hosting/announce",         post(handle_hosting_announce))
        .route("/hosting/nodes/:domain",    get(handle_hosting_nodes))
        .route("/nodes/register",           post(handle_nodes_register))
        .route("/nodes",                    get(handle_nodes_list))
        .route("/cert/request",             post(handle_cert_request))
        .route("/cert/status/:domain",      get(handle_cert_status))
        .route("/post/proof",               post(handle_post_proof))
        .route("/post/pending_rewards",     get(handle_post_pending_rewards))
        .route("/post/rewards_claimed",     post(handle_post_rewards_claimed))
        .route("/post/challenges/:addr",    get(handle_post_challenges))
        .layer(cors)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .expect("failed to bind port");

    info!("Listening on http://0.0.0.0:{}", port);
    axum::serve(listener, app).await.expect("server error");
}
