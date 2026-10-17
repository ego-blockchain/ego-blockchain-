use crate::chain_db::{StorageDeal, STORAGE_DEAL_HEARTBEAT_SECS, STORAGE_DEAL_GRACE_SECS};
use crate::error::EgoDesktopError;
use uuid::Uuid;

const BREACH_THRESHOLD: u32 = 1;

pub async fn pay_due_days(mut deal: StorageDeal) {
    let me = crate::ledger::Ledger::load().address;
    if deal.client_address != me || deal.status != "active" {
        return;
    }
    let total = (deal.duration_days as u64).max(1);
    let due = crate::commands::direct_pay::periods_due(deal.created_at, chrono::Utc::now().timestamp(), 86_400, total);
    let (client, provider, id) = (deal.client_address.clone(), deal.provider_address.clone(), deal.deal_id.clone());
    let on_chain = tokio::task::spawn_blocking(move || {
        crate::commands::direct_pay::paid_periods(&client, &provider, "storage_deal_pay", &id)
    }).await.unwrap_or(0);
    let mut paid = (deal.days_paid as u64).max(on_chain);
    while deal.status == "active" && paid < due && paid < total {
        let day = paid + 1;
        let amount = crate::commands::direct_pay::period_amount(deal.total_cost_uegoc, deal.daily_rate_uegoc, day, total);
        let memo = crate::commands::direct_pay::pay_memo("storage_deal_pay", &deal.deal_id, day);
        match crate::commands::direct_pay::pay(&deal.provider_address, amount, false, memo).await {
            Ok(_) => {
                paid = day;
                deal.days_paid = day as u32;
                deal.escrow_remaining = deal.escrow_remaining.saturating_sub(amount);
                if day >= total {
                    deal.status = "completed".to_string();
                }
                crate::chain_db::upsert_storage_deal(&deal);
            }
            Err(e) => {
                eprintln!("[StorageDeal] could not pay day {day} of {}: {e}", deal.deal_id);
                break;
            }
        }
    }
}

fn passive_breach_tick(deal: &mut StorageDeal) -> bool {
    if deal.status != "active" { return false; }
    let now     = chrono::Utc::now().timestamp();
    let elapsed = now - deal.last_proof_at;
    if elapsed < STORAGE_DEAL_HEARTBEAT_SECS + STORAGE_DEAL_GRACE_SECS { return false; }

    deal.last_proof_at += STORAGE_DEAL_HEARTBEAT_SECS;
    deal.breach_count  += 1;

    if deal.breach_count >= BREACH_THRESHOLD {
        deal.escrow_remaining = 0;
        deal.status = "auto_terminated".to_string();
        eprintln!("[StorageDeal] {} auto-terminated after {} breach(es)", deal.deal_id, deal.breach_count);
    }
    true
}

#[tauri::command]
pub async fn create_storage_deal(
    provider_address: String,
    size_gb:          u32,
    days:             u32,
    daily_rate_uegoc: u64,
    cid: Option<String>,
) -> Result<String, EgoDesktopError> {
    if size_gb == 0 { return Err(EgoDesktopError::InvalidInput("size_gb must be > 0".into())); }
    if days    == 0 { return Err(EgoDesktopError::InvalidInput("days must be > 0".into())); }
    if daily_rate_uegoc == 0 { return Err(EgoDesktopError::InvalidInput("daily_rate must be > 0".into())); }

    let ledger     = crate::ledger::Ledger::load();
    let my_addr    = ledger.address.clone();
    let now        = chrono::Utc::now().timestamp();
    let total_cost = daily_rate_uegoc * days as u64;

    if my_addr == provider_address {
        return Err(EgoDesktopError::InvalidInput("Cannot create a deal with yourself".into()));
    }

    let deal_id = Uuid::new_v4().to_string();
    let first = crate::commands::direct_pay::period_amount(total_cost, daily_rate_uegoc, 1, days as u64);
    crate::commands::direct_pay::pay(
        &provider_address,
        first,
        false,
        crate::commands::direct_pay::pay_memo("storage_deal_pay", &deal_id, 1),
    )
    .await
    .map_err(EgoDesktopError::WalletError)?;

    let cid_str = cid.unwrap_or_default();
    let (comm_d_hex, n_real_leaves, n_padded_leaves) = if !cid_str.is_empty() {
        let file_path = crate::ledger::Ledger::load()
            .stored_files
            .into_iter()
            .find(|f| f.cid == cid_str)
            .map(|f| f.local_path)
            .unwrap_or_default();
        if !file_path.is_empty() {
            let path = std::path::Path::new(&file_path);
            match crate::proof::MerkleTree::build_from_path(path) {
                Ok(tree) => (hex::encode(tree.root), tree.n_real as u64, tree.n_padded as u64),
                Err(_)   => (String::new(), 0, 0),
            }
        } else {
            (String::new(), 0, 0)
        }
    } else {
        (String::new(), 0, 0)
    };

    let deal = StorageDeal {
        deal_id:          deal_id.clone(),
        provider_address: provider_address.clone(),
        client_address:   my_addr.clone(),
        size_gb,
        duration_days:    days,
        daily_rate_uegoc,
        total_cost_uegoc: total_cost,
        escrow_remaining: total_cost.saturating_sub(first),
        days_paid:        1,
        breach_count:     0,
        last_proof_at:    now,
        status:           "active".to_string(),
        created_at:       now,
        expires_at:       now + days as i64 * 86_400,
        cid:            cid_str,
        comm_d_hex,
        n_real_leaves,
        n_padded_leaves,
    };

    // Anchor the deal ON-CHAIN: this tx carries the full record (hash-bound) so it lands
    // in a block's tx_merkle_root and every node materializes the identical StorageDeal
    // from it. The local upsert below is just an optimistic copy for instant UX — the
    // block is the canonical source of truth.
    if let Err(e) = crate::mempool::get_mempool().push(crate::chain_db::storage_deal_tx(&deal)) {
        eprintln!("[StorageDeal] on-chain anchor tx rejected: {e}");
    }
    crate::chain_db::upsert_storage_deal(&deal);

    let msg = crate::p2p::P2PMessage::StorageDealCreated { deal: deal.clone() };
    crate::p2p::broadcast_compute_msg(msg).await;

    Ok(deal.deal_id)
}

#[tauri::command]
pub async fn send_storage_proof(deal_id: String) -> Result<(), EgoDesktopError> {
    let mut ledger = crate::ledger::Ledger::load();
    let my_addr    = ledger.address.clone();
    let now        = chrono::Utc::now().timestamp();

    let mut deal = crate::chain_db::get_storage_deal(&deal_id)
        .ok_or_else(|| EgoDesktopError::NotFound("Deal not found".into()))?;

    if deal.provider_address != my_addr {
        return Err(EgoDesktopError::PermissionDenied("Not your deal".into()));
    }
    if deal.status != "active" {
        return Err(EgoDesktopError::InvalidInput(format!("Deal is {}", deal.status)));
    }

    let elapsed     = now - deal.last_proof_at;
    let missed_days = (elapsed / STORAGE_DEAL_HEARTBEAT_SECS).saturating_sub(1).max(0) as u32;
    if missed_days > 0 {
        deal.breach_count += missed_days;
        if deal.breach_count >= BREACH_THRESHOLD {
            deal.status = "breached".to_string();
            crate::chain_db::upsert_storage_deal(&deal);
            return Err(EgoDesktopError::InvalidInput("Deal terminated: too many missed days".into()));
        }
    }

    if !deal.cid.is_empty() && !deal.comm_d_hex.is_empty() && deal.n_real_leaves > 0 {
        let file_path = ledger.stored_files.iter()
            .find(|f| f.cid == deal.cid)
            .map(|f| f.local_path.clone())
            .unwrap_or_default();

        if file_path.is_empty() || !std::path::Path::new(&file_path).exists() {
            deal.breach_count += 1;
            if deal.breach_count >= BREACH_THRESHOLD {
                deal.status = "breached".to_string();
            }
            crate::chain_db::upsert_storage_deal(&deal);
            return Err(EgoDesktopError::InvalidInput(
                "Storage proof failed: data file not found on disk".into()
            ));
        }

        let window_number = deal.last_proof_at / STORAGE_DEAL_HEARTBEAT_SECS;
        let challenge_seed: [u8; 32] = {
            let mut h = blake3::Hasher::new();
            h.update(deal.deal_id.as_bytes());
            h.update(&window_number.to_le_bytes());
            *h.finalize().as_bytes()
        };

        let n_real_leaves   = deal.n_real_leaves as usize;
        let n_padded_leaves = deal.n_padded_leaves as usize;
        let comm_d_bytes    = hex::decode(&deal.comm_d_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
            .unwrap_or([0u8; 32]);

        let path   = std::path::Path::new(&file_path);
        let proofs = crate::proof::generate_post_proofs_from_path(path, &challenge_seed, n_real_leaves)
            .map_err(|e| EgoDesktopError::InvalidInput(format!("Proof generation failed: {e}")))?;

        if !crate::proof::verify_post_proofs(&proofs, &comm_d_bytes, &challenge_seed, n_real_leaves, n_padded_leaves) {
            deal.breach_count += 1;
            if deal.breach_count >= BREACH_THRESHOLD {
                deal.status = "breached".to_string();
            }
            crate::chain_db::upsert_storage_deal(&deal);
            return Err(EgoDesktopError::InvalidInput(
                "Storage proof failed: Merkle challenge verification rejected".into()
            ));
        }

        eprintln!("[StorageDeal] {} Merkle proof verified (window={}, cid={})", deal_id, window_number, &deal.cid[..16.min(deal.cid.len())]);
    }

    let total = (deal.duration_days as u64).max(1);
    let paid = crate::commands::direct_pay::paid_periods(&deal.client_address, &my_addr, "storage_deal_pay", &deal_id);
    if paid > deal.days_paid as u64 {
        let earned: u64 = (deal.days_paid as u64 + 1..=paid)
            .map(|d| crate::commands::direct_pay::period_amount(deal.total_cost_uegoc, deal.daily_rate_uegoc, d, total))
            .sum();
        ledger.storage_deal_earnings_uegoc += earned;
        ledger.save().map_err(EgoDesktopError::FileSystemError)?;
        deal.escrow_remaining = deal.escrow_remaining.saturating_sub(earned);
        deal.days_paid = paid as u32;
    }

    deal.last_proof_at = now;

    if now >= deal.expires_at && deal.days_paid as u64 >= total {
        deal.status = "completed".to_string();
    }

    crate::chain_db::upsert_storage_deal(&deal);

    let msg = crate::p2p::P2PMessage::StorageDealProof {
        deal_id: deal_id.clone(),
        provider: my_addr,
        timestamp: now,
    };
    crate::p2p::broadcast_compute_msg(msg).await;

    Ok(())
}

#[tauri::command]
pub async fn get_storage_deals() -> Result<Vec<StorageDeal>, EgoDesktopError> {
    let ledger  = crate::ledger::Ledger::load();
    let my_addr = ledger.address.clone();

    let mut deals: Vec<StorageDeal> = crate::chain_db::list_storage_deals()
        .into_iter()
        .filter(|d| d.client_address == my_addr || d.provider_address == my_addr)
        .collect();

    for deal in &mut deals {
        if passive_breach_tick(deal) {
            crate::chain_db::upsert_storage_deal(deal);
        }
    }

    Ok(deals)
}

#[tauri::command]
pub async fn terminate_storage_deal(deal_id: String) -> Result<(), EgoDesktopError> {
    let ledger  = crate::ledger::Ledger::load();
    let my_addr = ledger.address.clone();

    let mut deal = crate::chain_db::get_storage_deal(&deal_id)
        .ok_or_else(|| EgoDesktopError::NotFound("Deal not found".into()))?;

    if deal.client_address != my_addr {
        return Err(EgoDesktopError::PermissionDenied("Only the client can terminate".into()));
    }
    if deal.status != "active" && deal.status != "breached" {
        return Err(EgoDesktopError::InvalidInput(format!("Deal is {}", deal.status)));
    }
    if deal.breach_count < BREACH_THRESHOLD && deal.status != "breached" {
        return Err(EgoDesktopError::InvalidInput(
            format!("Need {} missed day(s) to terminate; currently {}", BREACH_THRESHOLD, deal.breach_count)
        ));
    }

    deal.status           = "terminated".to_string();
    deal.escrow_remaining = 0;
    crate::chain_db::upsert_storage_deal(&deal);

    let msg = crate::p2p::P2PMessage::StorageDealTerminated {
        deal_id: deal_id.clone(),
        by:      "client".to_string(),
    };
    crate::p2p::broadcast_compute_msg(msg).await;

    Ok(())
}
