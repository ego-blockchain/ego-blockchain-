use crate::app::{AppState, EarningsData, RewardBreakdown};
use crate::error::EgoDesktopError;
use crate::ledger::{load_chain, poc_signing_bytes, Ledger, LedgerTx};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tauri::State;

use crate::tokenomics::{
    storage_reward_uegoc, consensus_daily_uegoc, coverage_daily_uegoc,
    retrieval_reward_uegoc, node_reward_scale,
};

#[tauri::command]
pub async fn get_earnings_data(
    state: State<'_, AppState>,
) -> Result<EarningsData, EgoDesktopError> {
    compute_earnings(&state).await
}

/// The numbers on the Earnings page. The phone gateway calls this too, so the
/// owner's iPhone shows exactly what this computer shows.
pub async fn compute_earnings(state: &AppState) -> Result<EarningsData, EgoDesktopError> {
    let now = chrono::Utc::now().timestamp();

    // All blocking I/O in one spawn_blocking call.
    let (ledger, scale, plan, storage_pay) = tokio::task::spawn_blocking(move || {
        let ledger = Ledger::load();
        let chain  = load_chain();
        let scale  = node_reward_scale(&chain);
        let plan   = (!ledger.address.is_empty()).then(|| crate::chain_db::plan_hosting(&ledger.address));
        let storage_pay: Vec<(i64, u64)> = if ledger.address.is_empty() {
            Vec::new()
        } else {
            crate::chain_db::reward_entries_for(&ledger.address)
                .into_iter()
                .filter(|r| r.kind == crate::chain_db::REWARD_STORAGE)
                .map(|r| (r.timestamp, r.amount_uegoc))
                .collect()
        };
        (ledger, scale, plan, storage_pay)
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?;

    // Storage pays for peer data actually held, not for capacity offered. A file
    // hosted for someone else carries the uploader's address as its owner, so the
    // node's own files are excluded: storing your own data is not a service to the
    // network and must not earn. Capacity still caps the payout, so a node cannot
    // be paid for more than it pledged.
    let hosted_bytes: u64 = ledger.stored_files.iter()
        .filter(|f| {
            f.status == "Active"
                && !f.owner.is_empty()
                && f.owner != ledger.address
                && f.proof_suspended_until <= now
                && !f.local_path.is_empty()
                && !f.local_path.starts_with("sender:")
        })
        .map(|f| f.encrypted_size)
        .sum();
    let billable_gb = (hosted_bytes as f64 / 1_000_000_000.0)
        .min(ledger.storage_allocated_bytes as f64 / 1_000_000_000.0);

    let storage_plan_pay = plan.as_ref().map_or(false, |p| p.active);
    let daily_storage  = match plan.as_ref().filter(|p| p.active) {
        Some(p) => p.daily_uegoc,
        None => (storage_reward_uegoc(billable_gb) as f64 * scale) as u64,
    };
    let consensus_rate = (consensus_daily_uegoc() as f64 * scale) as u64;
    let retrieval_rate = (retrieval_reward_uegoc(1.0) as f64 * scale) as u64;

    let coverage_online = state
        .cache
        .lock()
        .unwrap()
        .coverage_status
        .as_ref()
        .map(|s| s.is_online)
        .unwrap_or(true);

    let coverage_rate = if !coverage_online { 0 }
                        else { (coverage_daily_uegoc() as f64 * scale) as u64 };

    let daily_total_base = daily_storage
        .saturating_add(consensus_rate)
        .saturating_add(coverage_rate)
        .saturating_add(retrieval_rate);

    let drs_score: f64 = if ledger.address.is_empty() {
        50.0
    } else {
        crate::poc::get_peer_score(&ledger.address) as f64
    };
    let drs_multiplier = 0.5 + (drs_score / 100.0);
    let daily_total = (daily_total_base as f64 * drs_multiplier) as u64;

    const MIN_CREDIT_INTERVAL_SECS: i64 = 3_600;

    let last_credit = state.get_last_earnings_credit();
    if last_credit == 0 {
        let address = ledger.address.clone();
        let historical: u64 = tokio::task::spawn_blocking(move || {
            crate::chain_db::get_tx_history_for_addr(&address)
                .into_iter()
                .filter(|tx| {
                    (tx.from == crate::chain_db::NODE_POOL_ADDR
                        || tx.from.starts_with("egot1rewards"))
                        && tx.status == "Confirmed"
                        && (tx.tx_type == "reward" || tx.tx_type == "coinbase")
                })
                .map(|tx| tx.amount)
                .sum::<u64>()
        })
        .await
        .unwrap_or(0);
        state.set_cached_total_earned(historical);
        state.set_last_earnings_credit(now);
    } else if (now - last_credit) >= MIN_CREDIT_INTERVAL_SECS {
        let elapsed_secs = (now - last_credit) as f64;
        let credit = (daily_total as f64 * elapsed_secs / 86_400.0) as u64;

        if credit >= 1_000_000 {
            let reward_hash = format!(
                "0x{}",
                ego_core::hash_data(
                    format!("reward:{}:{}", ledger.address, now).as_bytes()
                ).to_hex()
            );
            let hash_check = reward_hash.clone();
            let already_exists = tokio::task::spawn_blocking(move || {
                crate::chain_db::get_tx_by_hash(&hash_check).is_some()
            })
            .await
            .unwrap_or(false);

            if !already_exists {
                crate::mempool::get_mempool().push(LedgerTx {
                    hash:                reward_hash,
                    from:                crate::chain_db::NODE_POOL_ADDR.into(),
                    to:                  ledger.address.clone(),
                    amount:              credit,
                    memo:                Some("Block & storage rewards".into()),
                    timestamp:           now,
                    signature:           "rewards".into(),
                    status:              "Pending".into(),
                    nonce:               0,
                    tx_type:             "reward".into(),
                    public_key_ed25519:  String::new(),
                    dilithium_pubkey:    String::new(),
                    dilithium_signature: String::new(),
                    ..LedgerTx::default()
                });
                state.add_to_cached_total_earned(credit);
            }
        }
        state.set_last_earnings_credit(now);
    }

    let addr = ledger.address.clone();
    let watermark = ledger.lifetime_counted_height;
    let (newly_earned, new_watermark) = tokio::task::spawn_blocking(move || {
        let mut sum: u64 = 0;
        let mut maxh = watermark;
        for tx in crate::chain_db::get_tx_history_for_addr(&addr) {
            let h = tx.block_height.unwrap_or(0);
            if h > watermark
                && tx.status == "Confirmed"
                && (tx.tx_type == "reward" || tx.tx_type == "coinbase")
                && (tx.from == crate::chain_db::NODE_POOL_ADDR || tx.from.starts_with("egot1rewards"))
            {
                sum = sum.saturating_add(tx.amount);
                if h > maxh { maxh = h; }
            }
        }
        (sum, maxh)
    })
    .await
    .unwrap_or((0, watermark));

    let total_earned = if newly_earned > 0 || new_watermark > watermark {
        tokio::task::spawn_blocking(move || {
            let mut l = Ledger::load();
            l.lifetime_earned_uegoc = l.lifetime_earned_uegoc.saturating_add(newly_earned);
            if new_watermark > l.lifetime_counted_height {
                l.lifetime_counted_height = new_watermark;
            }
            let _ = l.save();
            l.lifetime_earned_uegoc
        })
        .await
        .unwrap_or(ledger.lifetime_earned_uegoc)
    } else {
        ledger.lifetime_earned_uegoc
    };

    let pending         = daily_storage / 24;
    let session_started = state.get_session_started();

    let earnings = EarningsData {
        daily_rewards:  daily_total,
        epoch_rewards:  daily_total.saturating_mul(7),
        total_earned,
        drs_multiplier,
        storage_plan_pay,
        storage_plans_kept: plan.as_ref().map_or(0, |p| p.plans.len()),
        storage_used_bytes: hosted_bytes,
        storage_reserved_bytes: plan.as_ref().map_or(0, |p| p.reserved_bytes),
        storage_earned_24h_uegoc: storage_pay.iter().filter(|(t, _)| now - t < 86_400).map(|(_, a)| *a).sum(),
        storage_earned_total_uegoc: storage_pay.iter().map(|(_, a)| *a).sum(),
        reward_breakdown: RewardBreakdown {
            storage_rewards:   daily_storage,
            consensus_rewards: consensus_rate,
            coverage_rewards:  coverage_rate,
            retrieval_rewards: retrieval_rate,
        },
        pending_rewards: pending,
        session_started,
        coverage_online,
    };

    state.update_earnings_data(earnings.clone());
    Ok(earnings)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PocEventResult {
    pub success:      bool,
    pub message:      String,
    pub reward_uegoc: u64,
    pub drs_score:    Option<f64>,
}

#[tauri::command]
pub async fn submit_poc_event(
    quality:  String,
    peers:    u32,
    h3_cell:  Option<String>,
    state:    State<'_, AppState>,
) -> Result<PocEventResult, EgoDesktopError> {
    let ledger = Ledger::load();
    let address = ledger.address.clone();
    if address.is_empty() {
        return Err(EgoDesktopError::WalletError("Wallet not initialized".into()));
    }

    // Sign the event
    let timestamp = chrono::Utc::now().timestamp();
    let h3 = h3_cell.as_deref().unwrap_or("");
    let signing_bytes = poc_signing_bytes(&address, &quality, peers, h3, timestamp);

    let (signature_hex, pubkey_hex) = if let Some(kp) = state.get_keypair() {
        let sig = kp.sign_ed25519(&signing_bytes);
        let pk  = hex::encode(kp.ed25519_public_key().as_bytes());
        (hex::encode(sig.as_bytes()), pk)
    } else {
        return Err(EgoDesktopError::WalletError("Wallet not initialized".into()));
    };

    // POST to relay
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| EgoDesktopError::WalletError(e.to_string()))?;

    #[derive(Serialize)]
    struct PocReq<'a> {
        address:    &'a str,
        quality:    &'a str,
        peers:      u32,
        h3_cell:    Option<&'a str>,
        timestamp:  i64,
        signature:  &'a str,
        public_key: &'a str,
    }

    let payload = PocReq {
        address:    &address,
        quality:    &quality,
        peers,
        h3_cell:    h3_cell.as_deref(),
        timestamp,
        signature:  &signature_hex,
        public_key: &pubkey_hex,
    };

    static LAST_POST: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
    if timestamp - LAST_POST.load(std::sync::atomic::Ordering::Relaxed) >= 6 * 3600 {
        LAST_POST.store(timestamp, std::sync::atomic::Ordering::Relaxed);
        if let Ok(body) = serde_json::to_value(&payload) {
            tokio::spawn(async move {
                crate::p2p::oracle_post_pub(&client, "/poc/event", &body).await;
            });
        }
    }

    Ok(PocEventResult {
        success:      true,
        message:      "Coverage noted. It is paid through your node's DRS, not per event".to_string(),
        reward_uegoc: 0,
        drs_score:    None,
    })
}

// ── get_poc_score ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct PocScoreResult {
    pub drs_score:      f64,
    pub events_24h:     u32,
    pub total_events:   u64,
    pub last_event:     Option<i64>,
    pub is_validator:   bool,
    pub validator_rank: Option<usize>,
}

#[tauri::command]
pub async fn get_poc_score(
    state: State<'_, AppState>,
) -> Result<PocScoreResult, EgoDesktopError> {
    let address = Ledger::load().address;
    if address.is_empty() {
        return Ok(PocScoreResult {
            drs_score: 0.0, events_24h: 0, total_events: 0,
            last_event: None, is_validator: false, validator_rank: None,
        });
    }
    let _ = state;
    let score = crate::poc::get_peer_score(&address) as f64;
    Ok(PocScoreResult {
        drs_score: score, events_24h: 0, total_events: 0,
        last_event: None, is_validator: crate::ledger::get_validator_stake(&address) > 0,
        validator_rank: None,
    })
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HostedFile {
    pub cid: String,
    pub owner: String,
    pub bytes: u64,
    pub role: String,
    pub copies: usize,
    pub holding: bool,
    pub recorded: bool,
    pub plan_active: bool,
    pub last_proof: i64,
}

#[derive(Debug, Clone, Serialize, Default, PartialEq)]
pub struct HostedStorage {
    pub files: Vec<HostedFile>,
    pub file_count: usize,
    pub hosted_bytes: u64,
    pub paying_files: usize,
    pub earned_24h_uegoc: u64,
    pub earned_30d_uegoc: u64,
    pub earned_total_uegoc: u64,
    pub registered: bool,
    pub paused_reason: Option<String>,
    pub plan_pay: bool,
    pub plans_kept: usize,
    pub reserved_bytes: u64,
    pub offered_bytes: u64,
    pub last_claim: i64,
    pub daily_uegoc: u64,
}

pub const HOSTED_FILES_SHOWN: usize = 50;

pub struct ChainView<'a> {
    pub recorded: &'a dyn Fn(&str) -> Option<String>,
    pub plan_active: &'a dyn Fn(&str) -> bool,
    pub last_proof: &'a dyn Fn(&str) -> i64,
}

pub fn hosted_storage(
    files: &[crate::ledger::StoredFile],
    me: &str,
    now: i64,
    chain: &ChainView,
    storage_pay: &[(i64, u64)],
) -> HostedStorage {
    let mut plans: HashMap<String, bool> = HashMap::new();
    let mut out: Vec<HostedFile> = files.iter()
        .filter(|f| f.status == "Active" && !f.owner.is_empty() && f.owner != me)
        .map(|f| {
            let holding = (f.blocks_total == 0 || f.blocks_received >= f.blocks_total)
                && !f.local_path.is_empty()
                && !f.local_path.starts_with("sender:");
            let recorded = (chain.recorded)(&f.cid).map_or(false, |owner| owner == f.owner);
            let plan_active = *plans.entry(f.owner.clone()).or_insert_with(|| (chain.plan_active)(&f.owner));
            HostedFile {
                cid: f.cid.clone(),
                owner: f.owner.clone(),
                bytes: if f.encrypted_size > 0 { f.encrypted_size } else { f.original_size },
                role: f.replication_role.clone(),
                copies: if f.replication_role == "master" { 1 + f.replica_peers.len() } else { 0 },
                holding,
                recorded,
                plan_active,
                last_proof: if recorded { (chain.last_proof)(&f.cid) } else { 0 },
            }
        })
        .collect();
    let paying = |h: &HostedFile| h.holding && h.recorded && h.plan_active;
    out.sort_by(|a, b| paying(b).cmp(&paying(a)).then(b.bytes.cmp(&a.bytes)).then(a.cid.cmp(&b.cid)));
    let earned_since = |secs: i64| storage_pay.iter().filter(|(t, _)| now.saturating_sub(*t) <= secs).map(|(_, a)| *a).sum::<u64>();
    let summary = HostedStorage {
        file_count: out.len(),
        hosted_bytes: out.iter().filter(|h| h.holding).map(|h| h.bytes).sum(),
        paying_files: out.iter().filter(|h| paying(h)).count(),
        earned_24h_uegoc: earned_since(86_400),
        earned_30d_uegoc: earned_since(30 * 86_400),
        earned_total_uegoc: storage_pay.iter().map(|(_, a)| *a).sum(),
        ..Default::default()
    };
    out.truncate(HOSTED_FILES_SHOWN);
    HostedStorage { files: out, ..summary }
}

#[tauri::command]
pub async fn get_hosted_storage() -> Result<HostedStorage, EgoDesktopError> {
    tokio::task::spawn_blocking(|| {
        let ledger = Ledger::load();
        let me = ledger.address.clone();
        let now = chrono::Utc::now().timestamp();
        let pay: Vec<(i64, u64)> = if me.is_empty() {
            Vec::new()
        } else {
            crate::chain_db::reward_entries_for(&me)
                .into_iter()
                .filter(|r| r.kind == crate::chain_db::REWARD_STORAGE)
                .map(|r| (r.timestamp, r.amount_uegoc))
                .collect()
        };
        let me2 = me.clone();
        let recorded = |cid: &str| crate::chain_db::recorded_storage_file(cid).map(|r| r.owner);
        let plan_active = move |owner: &str| crate::chain_db::storage_plan_active(owner, now);
        let last_proof = move |cid: &str| crate::chain_db::storage_last_proof(cid, &me2);
        let view = ChainView { recorded: &recorded, plan_active: &plan_active, last_proof: &last_proof };
        let mut out = hosted_storage(&ledger.stored_files, &me, now, &view, &pay);
        out.registered = !me.is_empty() && crate::chain_db::is_registered_node(&me);
        out.paused_reason = crate::commands::coverage::earning_block_reason();
        if !me.is_empty() {
            let hosting = crate::chain_db::plan_hosting(&me);
            out.plan_pay = hosting.active;
            out.plans_kept = hosting.plans.len();
            out.reserved_bytes = hosting.reserved_bytes;
            out.offered_bytes = hosting.offered_bytes;
            out.last_claim = hosting.last_claim;
            out.daily_uegoc = hosting.daily_uegoc;
        }
        out
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))
}

#[cfg(test)]
mod hosted_tests {
    use super::*;
    use crate::ledger::StoredFile;

    fn file(cid: &str, owner: &str, role: &str, path: &str, size: u64) -> StoredFile {
        StoredFile {
            cid: cid.into(),
            owner: owner.into(),
            status: "Active".into(),
            replication_role: role.into(),
            local_path: path.into(),
            encrypted_size: size,
            ..Default::default()
        }
    }

    #[test]
    fn a_kept_file_pays_only_when_held_recorded_by_its_owner_and_covered_by_a_plan() {
        let mut master = file("egomfd1a", "egot1phone", "master", "storage/a.json", 500);
        master.replica_peers = vec!["egot1b".into(), "egot1c".into()];
        let files = vec![
            master,
            file("egomfd1b", "egot1phone", "slave", "storage/b.json", 300),
            file("egomfd1c", "egot1phone", "slave", "sender:egot1master", 200),
            file("egomfd1d", "egot1noplan", "master", "storage/d.json", 100),
            file("egomfd1e", "egot1phone", "master", "storage/e.json", 50),
            file("egomfd1mine", "egot1me", "master", "storage/m.json", 999),
        ];
        let recorded = |cid: &str| match cid {
            "egomfd1a" | "egomfd1b" | "egomfd1c" => Some("egot1phone".to_string()),
            "egomfd1d" => Some("egot1noplan".to_string()),
            "egomfd1e" => Some("egot1someoneelse".to_string()),
            _ => None,
        };
        let plan_active = |owner: &str| owner == "egot1phone";
        let last_proof = |cid: &str| if cid == "egomfd1a" { 1_000 } else { 0 };
        let view = ChainView { recorded: &recorded, plan_active: &plan_active, last_proof: &last_proof };
        let now = 100 * 86_400;
        let pay = vec![(now - 3_600, 7), (now - 2 * 86_400, 11), (now - 40 * 86_400, 13)];
        let h = hosted_storage(&files, "egot1me", now, &view, &pay);

        assert_eq!(h.file_count, 5, "the node's own file is not kept for anyone else");
        assert_eq!(h.paying_files, 2);
        assert_eq!(h.hosted_bytes, 500 + 300 + 100 + 50, "a copy still waiting for its data holds nothing yet");
        assert_eq!(h.files[0].cid, "egomfd1a");
        assert_eq!(h.files[0].copies, 3);
        assert_eq!(h.files[0].last_proof, 1_000);
        assert_eq!(h.files[1].cid, "egomfd1b");
        let waiting = h.files.iter().find(|f| f.cid == "egomfd1c").unwrap();
        assert!(!waiting.holding && waiting.recorded && waiting.plan_active);
        assert!(!h.files.iter().find(|f| f.cid == "egomfd1d").unwrap().plan_active);
        assert!(!h.files.iter().find(|f| f.cid == "egomfd1e").unwrap().recorded, "a record by someone else is not the owner's");
        assert_eq!((h.earned_24h_uegoc, h.earned_30d_uegoc, h.earned_total_uegoc), (7, 18, 31));
    }
}
