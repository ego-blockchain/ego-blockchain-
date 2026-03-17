//! Tauri commands for PoRep / PoST consensus.
//!
//! - `get_porep_status`   — list sectors with their commitment + PoST state
//! - `respond_to_challenges` — fetch pending challenges from relay and submit Merkle proofs
//! - `get_post_score`     — fetch DRS score contributed by PoST from relay

use crate::error::EgoDesktopError;
use crate::ledger::Ledger;
use serde::{Deserialize, Serialize};

// ── Response types ────────────────────────────────────────────────────────────

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
    /// Number of challenges found.
    pub challenges_found: usize,
    /// Number of proofs successfully submitted.
    pub proofs_submitted: usize,
    /// Number of proofs that were rejected or errored.
    pub failures: usize,
    pub details: Vec<String>,
}

// ── get_porep_status ──────────────────────────────────────────────────────────

/// Return the PoRep/PoST status of every locally stored file.
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

// ── respond_to_challenges ─────────────────────────────────────────────────────

/// Fetch all pending PoST challenges from the relay and respond with Merkle proofs.
///
/// For each challenge the relay provides: { challenge_id, cid, challenge_seed (hex),
/// n_real_leaves, n_padded_leaves, comm_d (hex) }.
/// The desktop loads the matching .enc file, rebuilds the Merkle tree, and
/// submits 8 proofs back to the relay.  The relay verifies and issues a reward TX.
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
        // challenge_block_hash is the block hash used to derive the challenge seed
        // deterministically — included for auditability; proofs are generated from seed_hex.
        let _challenge_block_hash = ch["challenge_block_hash"].as_str().unwrap_or("").to_string();

        if cid.is_empty() || seed_hex.is_empty() || n_real == 0 {
            failures += 1;
            details.push(format!("Skipped malformed challenge {challenge_id}"));
            continue;
        }

        // Find the locally stored file matching this CID.
        let file_meta = ledger.stored_files.iter().find(|f| f.cid == cid);
        let local_path = match file_meta {
            Some(f) => f.local_path.clone(),
            None => {
                failures += 1;
                details.push(format!("CID {cid} not found locally — sector faulted"));
                continue;
            }
        };

        // Load the encrypted file bytes.
        let enc_bytes = match std::fs::read(&local_path) {
            Ok(b)  => b,
            Err(e) => {
                failures += 1;
                details.push(format!("Cannot read {local_path}: {e}"));
                continue;
            }
        };

        // Parse the 32-byte challenge seed.
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

        // Generate Merkle proofs.
        let proofs = crate::proof::generate_post_proofs(&enc_bytes, &seed_bytes, n_real);

        // Serialize proofs: leaf and path as hex strings for the JSON API.
        let proofs_json: Vec<serde_json::Value> = proofs.iter().map(|p| {
            serde_json::json!({
                "leaf_index": p.leaf_index,
                "leaf":  hex::encode(p.leaf),
                "path":  p.path.iter().map(|h| hex::encode(h)).collect::<Vec<_>>(),
            })
        }).collect();

        let timestamp = chrono::Utc::now().timestamp();
        // Sign challenge_id:cid:timestamp with Ed25519 to prove identity.
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

        // Update post_status + last_proved in the local ledger.
        if failures == 0 || submitted > 0 {
            update_post_status(&cid, "proved", Some(timestamp));
        }
    }

    Ok(PostChallengeResult {
        challenges_found: n_found,
        proofs_submitted: submitted,
        failures,
        details,
    })
}

// ── get_post_score ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct PostScore {
    pub address:        String,
    pub active_sectors: u32,
    pub proved_windows: u64,
    pub fault_count:    u64,
    pub last_proved:    Option<i64>,
}

/// Returns local PoST score derived from ledger (relay decommissioned).
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

// ── get_combined_drs ──────────────────────────────────────────────────────────

/// Full DRS picture: combined score + all three raw signals.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CombinedDrsScore {
    pub address:        String,
    pub combined_score: f64,
    /// PoC events submitted in the last 24 h.
    pub poc_events_24h: u32,
    pub poc_total:      u64,
    /// Active PoST sectors on the relay.
    pub post_sectors:   u32,
    pub post_windows:   u64,
    pub post_faults:    u64,
    /// Local staked amount (uEGOC) — from ledger, not relay.
    pub staked_uegoc:   u64,
    pub validator_rank: Option<usize>,
    /// True when combined_score ≥ 0.5 (PoC + PoST performance). Staking is not required.
    pub is_eligible:    bool,
}

/// Returns combined DRS score derived from local ledger (relay decommissioned).
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

    // PoC events from local ledger
    let poc_events = crate::ledger::load_poc_events();
    let now = chrono::Utc::now().timestamp();
    let poc_events_24h = poc_events.iter()
        .filter(|e| now - e.timestamp <= 86_400).count() as u32;
    let poc_total = poc_events.len() as u64;

    // Simple combined score: PoC weight 0.6, PoST weight 0.4
    let poc_score  = (poc_events_24h as f64 / 360.0_f64).min(1.0); // 360 events/day max
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

// ── get_tokenomics ────────────────────────────────────────────────────────────

/// Returns tokenomics data shaped to match the frontend Tokenomics interface.
#[tauri::command]
pub async fn get_tokenomics() -> Result<serde_json::Value, EgoDesktopError> {
    let chain = crate::ledger::load_chain();
    let total_blocks = chain.blocks.len() as u64;

    const TOTAL_SUPPLY: u64   = 1_000_000_000;
    const HALVING_INTERVAL: u64 = 2_100_000;
    const INITIAL_REWARD: f64   = 50.0;

    let era: u64 = total_blocks / HALVING_INTERVAL;
    let current_reward = INITIAL_REWARD / (2u64.pow(era as u32) as f64);
    let blocks_to_next = HALVING_INTERVAL - (total_blocks % HALVING_INTERVAL);

    // Circulating = sum of all confirmed coinbase rewards
    let circulating_uegoc: u64 = chain.blocks.iter()
        .map(|b| b.reward)
        .sum();
    let circulating_egoc = circulating_uegoc / 1_000_000;
    let circulating_pct  = if TOTAL_SUPPLY > 0 {
        ((circulating_egoc as f64 / TOTAL_SUPPLY as f64) * 100.0 * 100.0).round() / 100.0
    } else { 0.0 };

    // Staking totals from ledger
    let ledger = crate::ledger::Ledger::load();
    let total_staked_egoc = ledger.staked_amount / 1_000_000;

    Ok(serde_json::json!({
        "total_supply_egoc":  TOTAL_SUPPLY,
        "circulating_egoc":   circulating_egoc,
        "circulating_pct":    circulating_pct,
        "halving": {
            "era":                    era,
            "current_reward_egoc":    current_reward,
            "blocks_to_next_halving": blocks_to_next
        },
        "staking": {
            "total_staked_egoc": total_staked_egoc,
            "active_stakers":    if ledger.staked_amount > 0 { 1u64 } else { 0u64 }
        }
    }))
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn sign_payload(data: &[u8]) -> Option<(String, String)> {
    let seed_bytes = std::fs::read(crate::ledger::seed_path()).ok()
        .filter(|b| b.len() == 32)?;
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

// ── background task ───────────────────────────────────────────────────────────

/// Run forever: respond to PoST challenges every POST_WINDOW_SECS seconds.
/// Called from main.rs setup as a background tokio task.
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
            Ok(_)  => {} // nothing pending
            Err(e) => eprintln!("[PoST] loop error: {e}"),
        }
    }
}
