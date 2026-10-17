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
    tokio::task::spawn_blocking(|| {
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
        Ok::<_, EgoDesktopError>(statuses)
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

/// Prove the files this node holds, on-chain.
///
/// The challenge is taken from a recent committed block rather than fetched from anyone:
/// every node derives the same question from the same block hash, so a proof can be checked
/// by whoever receives it and nobody has to be trusted to hand out challenges. The answer
/// goes into a transaction, so what a node has proven becomes chain state that consensus
/// can read, instead of gossip that every receiver discards.
fn node_keypair() -> Option<ego_core::KeyPair> {
    if let Some(kp) = crate::app::global_app_state().get_keypair() {
        return Some(kp);
    }
    let seed = crate::ledger::load_seed().ok().flatten()?;
    let seed: [u8; 32] = seed.get(..32)?.try_into().ok()?;
    ego_core::KeyPair::from_bytes(&seed).ok()
}

fn send_signed(tx: &mut crate::ledger::LedgerTx, kp: &ego_core::KeyPair) -> Result<(), String> {
    crate::ledger::seal_tx(tx, kp, false);
    crate::mempool::get_mempool().push(tx.clone()).map_err(|e| e.to_string())?;
    crate::commands::tx_pending::add(tx);
    let gossip = tx.clone();
    tauri::async_runtime::spawn(async move { crate::p2p::broadcast_pending_tx(gossip).await; });
    Ok(())
}

/// Prove, on chain, the files this node holds for other people.
///
/// The challenge comes from a recent committed block, so every node derives the same
/// question and nobody hands out challenges. A proof only counts toward pay when it matches
/// the owner's on-chain record of the file and carries the challenged pieces, and only a
/// staked host may send proofs without a fee.
#[tauri::command]
pub async fn prove_stored_files() -> Result<PostChallengeResult, EgoDesktopError> {
    let ledger = Ledger::load();
    let prover_addr = ledger.address.clone();
    let empty = |detail: String| PostChallengeResult { challenges_found: 0, proofs_submitted: 0, failures: 0, details: vec![detail] };
    if prover_addr.is_empty() {
        return Ok(empty("No wallet yet".into()));
    }
    if !crate::chain_db::is_registered_node(&prover_addr) {
        return Ok(empty("This node registers itself on the network first; proofs start once it has".into()));
    }
    let tip = crate::chain_db::local_chain_height();
    if tip.saturating_add(1) < crate::chain_db::STORAGE_PAY_FROM_HEIGHT {
        return Ok(empty(format!("Storage pay starts at block {}", crate::chain_db::STORAGE_PAY_FROM_HEIGHT)));
    }
    let challenge_height = tip.saturating_sub(crate::storage_proof::CHALLENGE_MIN_AGE.max(1));
    let Some(block_hash) = crate::chain_db::get_block_hash_at(challenge_height) else {
        return Ok(empty(format!("Block {challenge_height} is not on this node yet")));
    };
    let Some(kp) = node_keypair() else { return Ok(empty("Wallet is locked".into())) };

    let hosted: Vec<_> = ledger.stored_files.iter()
        .filter(|f| f.status == "Active" && !f.owner.is_empty() && f.owner != prover_addr)
        .filter(|f| f.blocks_total == 0 || f.blocks_received >= f.blocks_total)
        .cloned()
        .collect();

    let mut nonce = crate::ledger::next_nonce_for(&prover_addr, ledger.nonce);
    let mut submitted = 0usize;
    let mut failures = 0usize;
    let mut found = 0usize;
    let mut details = Vec::new();

    for f in &hosted {
        let Some(record) = crate::chain_db::recorded_storage_file(&f.cid) else { continue };
        let Ok(manifest) = crate::blocks::load_manifest(&f.cid) else { continue };
        found += 1;
        let (cid, prover, hash) = (f.cid.clone(), prover_addr.clone(), block_hash.clone());
        let body = tokio::task::spawn_blocking(move || {
            crate::storage_proof::manifest_proof(&manifest, &cid, &prover, challenge_height, &hash)
        })
        .await
        .map_err(|e| EgoDesktopError::FileSystemError(e.to_string()))?;
        let body = match body {
            Ok(b) => b,
            Err(e) => {
                failures += 1;
                details.push(format!("{}: {e}", f.name));
                continue;
            }
        };
        if body.comm_d != record.record.comm_d {
            failures += 1;
            details.push(format!("{}: the copy here doesn't match the owner's record", f.name));
            continue;
        }
        let mut tx = crate::ledger::LedgerTx {
            from: prover_addr.clone(),
            to: prover_addr.clone(),
            amount: 0,
            fee_uegoc: 0,
            tx_type: crate::storage_proof::POST_PROOF_TX.to_string(),
            call_args: serde_json::to_string(&body).map_err(|e| EgoDesktopError::SerializationError(e.to_string()))?,
            timestamp: chrono::Utc::now().timestamp(),
            nonce,
            chain_id: 1,
            status: "Pending".to_string(),
            ..Default::default()
        };
        match send_signed(&mut tx, &kp) {
            Ok(()) => {
                nonce += 1;
                submitted += 1;
                update_post_status(&f.cid, "proved", Some(chrono::Utc::now().timestamp()));
                details.push(format!("Proved {}", f.name));
            }
            Err(e) => {
                failures += 1;
                details.push(format!("{}: {e}", f.name));
            }
        }
    }
    if submitted > 0 {
        let _guard = crate::ledger::TX_MUTEX.lock().await;
        let mut l = Ledger::load();
        l.nonce = l.nonce.max(nonce.saturating_sub(1));
        let _ = l.save();
    }

    Ok(PostChallengeResult { challenges_found: found, proofs_submitted: submitted, failures, details })
}

/// Record this node's own files on chain, so the hosts holding them can be paid. Only files
/// covered by a plan bought with EGUSD are recorded: that payment is what funds the hosts.
pub async fn record_my_stored_files() -> usize {
    let ledger = Ledger::load();
    let me = ledger.address.clone();
    if me.is_empty() { return 0; }
    if crate::chain_db::local_chain_height().saturating_add(1) < crate::chain_db::STORAGE_PAY_FROM_HEIGHT { return 0; }
    if !crate::chain_db::egusd_plan_active(&me) { return 0; }
    let Some(kp) = node_keypair() else { return 0 };
    let pending: std::collections::HashSet<String> = crate::mempool::get_mempool()
        .peek_all()
        .into_iter()
        .filter(|t| t.from == me && crate::chain_db::is_storage_file_tx(t))
        .filter_map(|t| serde_json::from_str::<crate::chain_db::StorageFileRecord>(&t.call_args).ok())
        .map(|r| r.cid)
        .collect();
    let mine: Vec<_> = ledger.stored_files.iter()
        .filter(|f| f.status == "Active" && (f.owner.is_empty() || f.owner == me) && f.cid.starts_with("egomfd1"))
        .filter(|f| !pending.contains(&f.cid) && crate::chain_db::recorded_storage_file(&f.cid).is_none())
        .take(20)
        .cloned()
        .collect();
    let fee = crate::tokenomics::fee_for_tx_with_staking("transfer", crate::ledger::get_validator_stake(&me) > 0)
        .max(crate::mempool::MIN_FEE_UEGOC);
    let mut nonce = crate::ledger::next_nonce_for(&me, ledger.nonce);
    let mut sent = 0usize;
    for f in mine {
        let Ok(manifest) = crate::blocks::load_manifest(&f.cid) else { continue };
        let Ok(Ok((comm_d, n_real, n_padded, bytes))) =
            tokio::task::spawn_blocking(move || crate::storage_proof::manifest_commitment(&manifest)).await
        else { continue };
        let record = crate::chain_db::StorageFileRecord { cid: f.cid.clone(), comm_d, n_real_leaves: n_real, n_padded_leaves: n_padded, bytes };
        let Ok(call_args) = serde_json::to_string(&record) else { continue };
        let mut tx = crate::ledger::LedgerTx {
            from: me.clone(),
            to: me.clone(),
            amount: 0,
            fee_uegoc: fee,
            tx_type: crate::chain_db::TX_STORAGE_FILE.to_string(),
            memo: Some("storage_file".into()),
            call_args,
            timestamp: chrono::Utc::now().timestamp(),
            nonce,
            chain_id: 1,
            status: "Pending".to_string(),
            ..Default::default()
        };
        if send_signed(&mut tx, &kp).is_ok() {
            nonce += 1;
            sent += 1;
        }
    }
    if sent > 0 {
        let _guard = crate::ledger::TX_MUTEX.lock().await;
        let mut l = Ledger::load();
        l.nonce = l.nonce.max(nonce.saturating_sub(1));
        let _ = l.save();
    }
    sent
}

/// Remove a deleted file's on-chain record, so it no longer counts against the owner's plan.
pub async fn unrecord_stored_file(cid: &str) {
    let me = Ledger::load().address;
    let Some(rec) = crate::chain_db::recorded_storage_file(cid) else { return };
    if rec.owner != me { return; }
    let Some(kp) = node_keypair() else { return };
    let _guard = crate::ledger::TX_MUTEX.lock().await;
    let mut ledger = Ledger::load();
    let nonce = crate::ledger::next_nonce_for(&me, ledger.nonce);
    let fee = crate::tokenomics::fee_for_tx_with_staking("transfer", crate::ledger::get_validator_stake(&me) > 0)
        .max(crate::mempool::MIN_FEE_UEGOC);
    let mut tx = crate::ledger::LedgerTx {
        from: me.clone(),
        to: me.clone(),
        amount: 0,
        fee_uegoc: fee,
        tx_type: crate::chain_db::TX_STORAGE_FILE.to_string(),
        memo: Some("storage_file:delete".into()),
        call_args: serde_json::to_string(&rec.record).unwrap_or_default(),
        timestamp: chrono::Utc::now().timestamp(),
        nonce,
        chain_id: 1,
        status: "Pending".to_string(),
        ..Default::default()
    };
    if send_signed(&mut tx, &kp).is_ok() {
        ledger.nonce = nonce;
        let _ = ledger.save();
    }
}

/// Validators report the EGOC price they see once per payout epoch; the chain pays storage
/// at the median of those reports.
pub async fn report_price_if_due() {
    let me = Ledger::load().address;
    if me.is_empty() || !crate::chain_db::may_report_price(&me) { return; }
    let next = crate::chain_db::local_chain_height().saturating_add(1);
    if next.saturating_add(crate::chain_db::STORAGE_PAY_EPOCH) < crate::chain_db::STORAGE_PAY_FROM_HEIGHT { return; }
    let epoch = next / crate::chain_db::STORAGE_PAY_EPOCH;
    static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX);
    if LAST.load(std::sync::atomic::Ordering::Relaxed) == epoch { return; }
    let usd = crate::p2p::get_egoc_price_usd();
    if !(usd.is_finite() && usd > 0.0) { return; }
    let micro = (usd * 1_000_000.0).round() as u64;
    let Some(kp) = node_keypair() else { return };
    let _guard = crate::ledger::TX_MUTEX.lock().await;
    let mut ledger = Ledger::load();
    let nonce = crate::ledger::next_nonce_for(&me, ledger.nonce);
    let mut tx = crate::ledger::LedgerTx {
        from: me.clone(),
        to: me.clone(),
        amount: 0,
        fee_uegoc: 0,
        tx_type: crate::chain_db::TX_PRICE_REPORT.to_string(),
        memo: Some(format!("price:{micro}")),
        timestamp: chrono::Utc::now().timestamp(),
        nonce,
        chain_id: 1,
        status: "Pending".to_string(),
        ..Default::default()
    };
    if send_signed(&mut tx, &kp).is_ok() {
        ledger.nonce = nonce;
        let _ = ledger.save();
        LAST.store(epoch, std::sync::atomic::Ordering::Relaxed);
    }
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

        if let Ok(proofs_serialized) = serde_json::to_string(&proofs_json) {
            crate::chain_db::record_local_proof(&prover_addr, &cid, &seed_hex, &proofs_serialized);
        }

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
        eprintln!("[PoST] {} sector proof(s) accepted by oracle — reward TX will arrive via network gossip", submitted);
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
    tokio::task::spawn_blocking(|| {
        let ledger = Ledger::load();
        let last_proved = ledger.stored_files.iter()
            .filter_map(|f| f.last_proved)
            .max();
        Ok::<_, EgoDesktopError>(PostScore {
            address:        ledger.address,
            active_sectors: ledger.stored_files.iter()
                .filter(|f| f.status == "Active").count() as u32,
            proved_windows: 0,
            fault_count:    0,
            last_proved,
        })
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
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

pub fn drs_eligible() -> bool {
    let ledger = Ledger::load();
    if ledger.address.is_empty() { return false; }
    let post_sectors = ledger.stored_files.iter()
        .filter(|f| f.status == "Active").count() as u32;
    let poc_events = crate::ledger::load_poc_events();
    let now = chrono::Utc::now().timestamp();
    let poc_events_24h = poc_events.iter()
        .filter(|e| now - e.timestamp <= 86_400).count() as u32;
    let poc_score  = (poc_events_24h as f64 / 360.0_f64).min(1.0);
    let post_score = if post_sectors > 0 { 1.0 } else { 0.0 };
    (poc_score * 0.6 + post_score * 0.4) >= 0.5
}

#[tauri::command]
pub async fn get_combined_drs() -> Result<CombinedDrsScore, EgoDesktopError> {
    tokio::task::spawn_blocking(|| {
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

        Ok::<_, EgoDesktopError>(CombinedDrsScore {
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
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

#[tauri::command]
pub async fn get_tokenomics() -> Result<serde_json::Value, EgoDesktopError> {
    tokio::task::spawn_blocking(|| {
        use crate::tokenomics::{
            TOTAL_SUPPLY_EGOC, HALVING_INTERVAL, UEGOC_PER_EGOC, BLOCK_EMISSION_EGOC,
            NODE_POOL_EGOC, STAKING_POOL_EGOC, ECOSYSTEM_EGOC, FOUNDATION_EGOC,
            STAKING_APR_BPS, block_reward_at, staking_pool_remaining_uegoc,
            node_pool_remaining_uegoc,
        };

        let total_blocks = crate::chain_db::block_count();
        let era: u64 = total_blocks / HALVING_INTERVAL;
        let current_reward = block_reward_at(total_blocks) as f64 / UEGOC_PER_EGOC as f64;
        let blocks_to_next = HALVING_INTERVAL - (total_blocks % HALVING_INTERVAL);

        let chain = crate::ledger::load_chain();
        let circulating_uegoc: u64 = chain.blocks.iter().map(|b| b.reward).sum();
        let circulating_egoc = circulating_uegoc / UEGOC_PER_EGOC;
        let circulating_pct = if TOTAL_SUPPLY_EGOC > 0 {
            ((circulating_egoc as f64 / TOTAL_SUPPLY_EGOC as f64) * 100.0 * 100.0).round() / 100.0
        } else {
            0.0
        };

        let node_pool_remaining = node_pool_remaining_uegoc(&chain) / UEGOC_PER_EGOC;
        let staking_pool_remaining = staking_pool_remaining_uegoc(&chain) / UEGOC_PER_EGOC;

        let ledger = crate::ledger::Ledger::load();
        let total_staked_egoc = ledger.staked_amount / UEGOC_PER_EGOC;

        let next_halving_at = (era + 1) * HALVING_INTERVAL;
        let foundation_uegoc = FOUNDATION_EGOC * UEGOC_PER_EGOC;
        let emission_uegoc = BLOCK_EMISSION_EGOC * UEGOC_PER_EGOC;
        let node_pool_uegoc = NODE_POOL_EGOC * UEGOC_PER_EGOC;
        let staking_uegoc = STAKING_POOL_EGOC * UEGOC_PER_EGOC;
        let ecosystem_uegoc = ECOSYSTEM_EGOC * UEGOC_PER_EGOC;

        Ok::<_, EgoDesktopError>(serde_json::json!({
            "is_testnet":                 crate::tokenomics::is_testnet(),
            "total_supply_egoc":          TOTAL_SUPPLY_EGOC,
            "circulating_egoc":           circulating_egoc,
            "circulating_pct":            circulating_pct,
            "block_rewards_issued_uegoc": circulating_uegoc,

            "emission_pools": {
                "node_rewards":  { "cap_uegoc": node_pool_uegoc,   "pct": 30 },
                "block_rewards": { "cap_uegoc": emission_uegoc,    "pct": 21 },
                "ecosystem":     { "cap_uegoc": ecosystem_uegoc,   "pct": 20 },
                "foundation":    { "cap_uegoc": foundation_uegoc,  "pct": 15 },
                "staking":       { "cap_uegoc": staking_uegoc,     "pct": 14 },
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
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

fn sign_payload(data: &[u8]) -> Option<(String, String)> {
    if let Some(kp) = crate::app::global_app_state().get_keypair() {
        let sig = kp.sign_ed25519(data);
        let pk = hex::encode(kp.ed25519_public_key().as_bytes());
        return Some((hex::encode(sig.as_bytes()), pk));
    }

    let seed_bytes = crate::ledger::load_seed().ok().flatten()?;
    if seed_bytes.len() < 32 {
        return None;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes[..32]);

    use ed25519_dalek::{Signer, SigningKey};
    let signing_key = SigningKey::from_bytes(&seed);
    let sig = signing_key.sign(data);
    let pk = hex::encode(signing_key.verifying_key().as_bytes());
    Some((hex::encode(sig.to_bytes()), pk))
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChainDrs {
    pub active: bool,
    pub from_height: u64,
    pub checkins_from_height: u64,
    pub height: u64,
    pub epoch: u64,
    pub registered: bool,
    pub uptime_streak: u32,
    pub streak_needed: u32,
    pub my_weight: u64,
    pub total_weight: u64,
    pub nodes: u64,
    pub on_committee: bool,
    pub committee: Vec<String>,
}

#[tauri::command]
pub async fn get_chain_drs() -> Result<ChainDrs, EgoDesktopError> {
    tokio::task::spawn_blocking(|| {
        let addr = Ledger::load().address;
        let height = crate::chain_db::local_chain_height();
        let next = height.saturating_add(1);
        let (my_weight, total_weight, nodes) = crate::chain_db::drs_weight_of(&addr);
        let committee: Vec<String> = if crate::chain_db::drs_active(next) {
            crate::chain_db::committee_for_height(next, crate::clock::now())
                .map(|c| c.into_iter().map(|(a, _)| a).collect())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        ChainDrs {
            active: crate::chain_db::drs_active(next),
            from_height: crate::chain_db::DRS_FROM_HEIGHT,
            checkins_from_height: crate::chain_db::CHECKIN_FROM_HEIGHT,
            height,
            epoch: crate::chain_db::drs_epoch_of(next),
            registered: !addr.is_empty() && crate::chain_db::is_registered_node(&addr),
            uptime_streak: crate::chain_db::uptime_streak(&addr).0,
            streak_needed: crate::chain_db::SEAT_MIN_UPTIME_STREAK,
            my_weight,
            total_weight,
            nodes,
            on_committee: !addr.is_empty() && committee.iter().any(|a| a == &addr),
            committee,
        }
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))
}

#[tauri::command]
pub async fn resync_chain(app: tauri::AppHandle) -> Result<(), EgoDesktopError> {
    crate::chain_db::request_resync().map_err(EgoDesktopError::DatabaseError)?;
    app.restart();
    Ok(())
}
