use crate::error::EgoDesktopError;
use crate::ledger::Ledger;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct SectorStatus {
    pub cid:           String,
    pub name:          String,
    pub sector_id:     u64,
    pub file_size:     u64,
    pub comm_d:        String,
    pub comm_r:        String,
    pub n_real_leaves: usize,
    pub post_status:   String,
    pub last_proved:   Option<i64>,
    pub stored_at:     i64,
    pub expiry:        i64,
}

#[derive(Debug, Serialize)]
pub struct PostChallengeResult {

    pub challenges_found: usize,

    pub proofs_submitted: usize,

    pub failures: usize,
    pub details: Vec<String>,
}

#[tauri::command]
pub async fn get_porep_status() -> Result<Vec<SectorStatus>, EgoDesktopError> {
    let ledger = Ledger::load();
    let statuses = ledger.stored_files.iter()
        .filter(|f| f.status == "Active" || f.status == "Expired")
        .map(|f| SectorStatus {
            cid:           f.cid.clone(),
            name:          f.name.clone(),
            sector_id:     f.sector_id,
            file_size:     f.encrypted_size,
            comm_d:        f.comm_d.clone(),
            comm_r:        f.comm_r.clone(),
            n_real_leaves: f.n_real_leaves,
            post_status:   if f.post_status.is_empty() {
                               if f.comm_d.is_empty() { "no_commitment".into() }
                               else { "registered".into() }
                           } else { f.post_status.clone() },
            last_proved:   f.last_proved,
            stored_at:     f.stored_at,
            expiry:        f.expiry,
        })
        .collect();
    Ok(statuses)
}

#[tauri::command]
pub async fn respond_to_challenges() -> Result<PostChallengeResult, EgoDesktopError> {
    let ledger     = Ledger::load();
    let prover_addr = ledger.address.clone();
    if prover_addr.is_empty() {
        return Ok(PostChallengeResult {
            challenges_found: 0, proofs_submitted: 0, failures: 0, details: vec![],
        });
    }

    let challenges = crate::p2p::fetch_post_challenges(&prover_addr).await;
    let n_found    = challenges.len();

    let mut submitted = 0usize;
    let mut failures  = 0usize;
    let mut details   = Vec::new();

    for ch in &challenges {
        let challenge_id       = ch["challenge_id"].as_str().unwrap_or("").to_string();
        let cid                = ch["cid"].as_str().unwrap_or("").to_string();
        let seed_hex           = ch["challenge_seed"].as_str().unwrap_or("").to_string();
        let n_real             = ch["n_real_leaves"].as_u64().unwrap_or(0) as usize;
        let n_padded           = ch["n_padded_leaves"].as_u64().unwrap_or(0) as usize;
        let comm_d_hex         = ch["comm_d"].as_str().unwrap_or("").to_string();

        let _challenge_block_hash = ch["challenge_block_hash"].as_str().unwrap_or("").to_string();

        if cid.is_empty() || seed_hex.is_empty() || n_real == 0 {
            failures += 1;
            details.push(format!("Skipped malformed challenge {challenge_id}"));
            continue;
        }

        let file_meta = ledger.stored_files.iter().find(|f| f.cid == cid);
        if let Some(f) = file_meta {
            if f.key_nonce_hex == "public" {
                continue;
            }
        }
        let local_path = match file_meta {
            Some(f) => f.local_path.clone(),
            None => {
                failures += 1;
                details.push(format!("CID {cid} not found locally — sector faulted"));
                continue;
            }
        };

        let seed_bytes = match hex::decode(&seed_hex)
            .ok()
            .and_then(|b| if b.len() == 32 { Some(b) } else { None })
        {
            Some(b) => { let mut arr = [0u8; 32]; arr.copy_from_slice(&b); arr }
            None => {
                failures += 1;
                details.push(format!("Invalid challenge seed for {cid}"));
                continue;
            }
        };

        let proofs = match crate::proof::generate_post_proofs_from_path(
            std::path::Path::new(&local_path), &seed_bytes, n_real
        ) {
            Ok(p)  => p,
            Err(e) => {
                failures += 1;
                details.push(format!("Cannot read {local_path}: {e}"));
                continue;
            }
        };

        let proofs_json: Vec<serde_json::Value> = proofs.iter().map(|p| {
            serde_json::json!({
                "leaf_index": p.leaf_index,
                "leaf":  hex::encode(p.leaf),
                "path":  p.path.iter().map(|h| hex::encode(h)).collect::<Vec<_>>(),
            })
        }).collect();

        let timestamp = chrono::Utc::now().timestamp();

        let sign_bytes = format!("{}:{}:{}", challenge_id, cid, timestamp).into_bytes();
        let (sig_hex, pubkey_hex) = match sign_payload(&sign_bytes) {
            Some(pair) => pair,
            None => {
                failures += 1;
                details.push(format!("Key not available for signing challenge {challenge_id}"));
                continue;
            }
        };

        let payload = serde_json::json!({
            "challenge_id": challenge_id,
            "cid":          cid,
            "prover_addr":  prover_addr,
            "comm_d":       comm_d_hex,
            "n_real_leaves":   n_real,
            "n_padded_leaves": n_padded,
            "proofs":       proofs_json,
            "timestamp":    timestamp,
            "signature":    sig_hex,
            "public_key":   pubkey_hex,
        });

        if crate::p2p::submit_post_proof(payload).await {
            submitted += 1;
            details.push(format!("✓ Proved {}", &cid[..16.min(cid.len())]));
        } else {
            failures += 1;
            details.push(format!("✗ Proof rejected for {}", &cid[..16.min(cid.len())]));
        }

        if failures == 0 || submitted > 0 {
            update_post_status(&cid, "proved", Some(timestamp));
        }
    }

    if submitted > 0 {
        let ledger = Ledger::load();
        if !ledger.address.is_empty() {

            const REWARD_PER_SECTOR_WINDOW: u64 = 10_417;
            let reward_uegoc = REWARD_PER_SECTOR_WINDOW * submitted as u64;
            let ts2 = chrono::Utc::now().timestamp();
            let reward_data = format!("post_reward:{}:{}:{}", ledger.address, submitted, ts2);
            let reward_hash = format!("0x{}", ego_core::hash_data(reward_data.as_bytes()).to_hex());
            let mut chain = crate::ledger::load_chain();

            let pool_addr = "egot1nodepool0000000000000000000000000000000000";
            chain.transactions.push(crate::ledger::LedgerTx {
                hash:      reward_hash,
                from:      pool_addr.into(),
                to:        ledger.address.clone(),
                amount:    reward_uegoc,
                memo:      Some(format!("PoST reward: {} sector(s) proved", submitted)),
                timestamp: ts2,
                signature: "system_post_reward".into(),
                status:    "Confirmed".into(),
                tx_type:   "reward".into(),
                ..crate::ledger::LedgerTx::default()
            });
            if let Err(e) = crate::ledger::save_chain(&chain) {
                eprintln!("[PoST] Failed to record reward TX: {e}");
            } else {
                eprintln!("[PoST] Issued {} uEGOC reward for {} proved sector(s)", reward_uegoc, submitted);
            }
        }
    }

    Ok(PostChallengeResult {
        challenges_found: n_found,
        proofs_submitted: submitted,
        failures,
        details,
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PostScore {
    pub address:        String,
    pub active_sectors: u32,
    pub proved_windows: u64,
    pub fault_count:    u64,
    pub last_proved:    Option<i64>,
}

#[tauri::command]
pub async fn get_post_score() -> Result<PostScore, EgoDesktopError> {
    let ledger = Ledger::load();
    let last_proved = ledger.stored_files.iter()
        .filter_map(|f| f.last_proved)
        .max();
    Ok(PostScore {
        address:        ledger.address,
        active_sectors: ledger.stored_files.iter()
            .filter(|f| f.status == "Active").count() as u32,
        proved_windows: 0,
        fault_count:    0,
        last_proved,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CombinedDrsScore {
    pub address:        String,
    pub combined_score: f64,

    pub poc_events_24h: u32,
    pub poc_total:      u64,

    pub post_sectors:   u32,
    pub post_windows:   u64,
    pub post_faults:    u64,

    pub staked_uegoc:   u64,
    pub validator_rank: Option<usize>,

    pub is_eligible:    bool,
}

#[tauri::command]
pub async fn get_combined_drs() -> Result<CombinedDrsScore, EgoDesktopError> {
    let ledger = Ledger::load();
    let addr   = ledger.address.clone();
    if addr.is_empty() {
        return Ok(CombinedDrsScore::default());
    }
    let staked_uegoc = ledger.staked_amount;
    let post_sectors = ledger.stored_files.iter()
        .filter(|f| f.status == "Active").count() as u32;

    let poc_events = crate::ledger::load_poc_events();
    let now = chrono::Utc::now().timestamp();
    let poc_events_24h = poc_events.iter()
        .filter(|e| now - e.timestamp <= 86_400).count() as u32;
    let poc_total = poc_events.len() as u64;

    let poc_score  = (poc_events_24h as f64 / 360.0_f64).min(1.0);
    let post_score = if post_sectors > 0 { 1.0 } else { 0.0 };
    let combined_score = poc_score * 0.6 + post_score * 0.4;

    Ok(CombinedDrsScore {
        address: addr,
        combined_score,
        poc_events_24h,
        poc_total,
        post_sectors,
        post_windows:   0,
        post_faults:    0,
        staked_uegoc,
        validator_rank: None,
        is_eligible:    combined_score >= 0.5,
    })
}

#[tauri::command]
pub async fn get_tokenomics() -> Result<serde_json::Value, EgoDesktopError> {
    use crate::tokenomics::{
        TOTAL_SUPPLY_EGOC, HALVING_INTERVAL, INITIAL_BLOCK_REWARD_UEGOC, UEGOC_PER_EGOC,
        BLOCK_EMISSION_EGOC, NODE_POOL_EGOC, STAKING_POOL_EGOC, ECOSYSTEM_EGOC, FOUNDATION_EGOC,
        STAKING_APR_BPS, block_reward_at, staking_pool_remaining_uegoc, node_pool_remaining_uegoc,
    };

    let total_blocks = crate::chain_db::block_count();

    let era: u64 = total_blocks / HALVING_INTERVAL;
    let current_reward = block_reward_at(total_blocks) as f64 / UEGOC_PER_EGOC as f64;
    let blocks_to_next = HALVING_INTERVAL - (total_blocks % HALVING_INTERVAL);

    let chain = crate::ledger::load_chain();
    let circulating_uegoc: u64 = chain.blocks.iter()
        .map(|b| b.reward)
        .sum();
    let circulating_egoc = circulating_uegoc / UEGOC_PER_EGOC;
    let circulating_pct  = if TOTAL_SUPPLY_EGOC > 0 {
        ((circulating_egoc as f64 / TOTAL_SUPPLY_EGOC as f64) * 100.0 * 100.0).round() / 100.0
    } else { 0.0 };

    let node_pool_remaining  = node_pool_remaining_uegoc(&chain) / UEGOC_PER_EGOC;
    let staking_pool_remaining = staking_pool_remaining_uegoc(&chain) / UEGOC_PER_EGOC;

    let ledger = crate::ledger::Ledger::load();
    let total_staked_egoc = ledger.staked_amount / UEGOC_PER_EGOC;

    let next_halving_at = (era + 1) * HALVING_INTERVAL;

    let foundation_uegoc  = FOUNDATION_EGOC  * UEGOC_PER_EGOC;
    let emission_uegoc    = BLOCK_EMISSION_EGOC * UEGOC_PER_EGOC;
    let node_pool_uegoc   = NODE_POOL_EGOC   * UEGOC_PER_EGOC;
    let staking_uegoc     = STAKING_POOL_EGOC * UEGOC_PER_EGOC;
    let ecosystem_uegoc   = ECOSYSTEM_EGOC   * UEGOC_PER_EGOC;

    Ok(serde_json::json!({
        "total_supply_egoc":          TOTAL_SUPPLY_EGOC,
        "circulating_egoc":           circulating_egoc,
        "circulating_pct":            circulating_pct,
        "block_rewards_issued_uegoc": circulating_uegoc,

        "emission_pools": {
            "genesis":       { "cap_uegoc": foundation_uegoc,  "pct": 15 },
            "block_rewards": { "cap_uegoc": emission_uegoc,    "pct": 21 },
            "storage":       { "cap_uegoc": node_pool_uegoc,   "pct": 30 },
            "coverage":      { "cap_uegoc": staking_uegoc,     "pct": 14 },
            "ecosystem":     { "cap_uegoc": ecosystem_uegoc,   "pct": 20 },
        },

        "pools": {
            "node_pool_remaining_egoc":    node_pool_remaining,
            "staking_pool_remaining_egoc": staking_pool_remaining,
        },

        "halving": {
            "era":                    era,
            "interval_blocks":        HALVING_INTERVAL,
            "current_reward_egoc":    current_reward,
            "blocks_to_next_halving": blocks_to_next,
            "next_halving_at_block":  next_halving_at,
            "max_block_height":       total_blocks,
        },

        "staking": {
            "apr_pct":           STAKING_APR_BPS as f64 / 100.0,
            "total_staked_egoc": total_staked_egoc,
            "active_stakers":    if ledger.staked_amount > 0 { 1u64 } else { 0u64 }
        },

        "drs": {
            "min_drs_to_mine": 0.5,
            "weights": { "poc": 0.6, "post": 0.4, "stake": 0.0 }
        }
    }))
}

fn sign_payload(data: &[u8]) -> Option<(String, String)> {
    let seed_bytes = crate::ledger::load_seed().ok().flatten()?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let kp  = ego_core::KeyPair::from_bytes(&seed).ok()?;
    let sig = kp.sign_ed25519(data);
    let pk  = hex::encode(kp.ed25519_public_key().as_bytes());
    Some((hex::encode(sig.as_bytes()), pk))
}

fn update_post_status(cid: &str, status: &str, proved_at: Option<i64>) {
    let mut ledger = Ledger::load();
    if let Some(f) = ledger.stored_files.iter_mut().find(|f| f.cid == cid) {
        f.post_status = status.to_string();
        if let Some(ts) = proved_at { f.last_proved = Some(ts); }
    }
    let _ = ledger.save();
}

pub async fn run_post_loop() {
    let interval = std::time::Duration::from_secs(
        crate::proof::POST_WINDOW_SECS as u64
    );
    loop {
        tokio::time::sleep(interval).await;
        match respond_to_challenges().await {
            Ok(r) if r.challenges_found > 0 => {
                eprintln!(
                    "[PoST] {} challenges found, {} proved, {} failed",
                    r.challenges_found, r.proofs_submitted, r.failures
                );
            }
            Ok(_)  => {}
            Err(e) => eprintln!("[PoST] loop error: {e}"),
        }
    }
}
