use crate::chain_db::{
    StorageDeal, STORAGE_ESCROW_ADDR, STORAGE_DEAL_HEARTBEAT_SECS, STORAGE_DEAL_GRACE_SECS,
};
use crate::error::EgoDesktopError;
use crate::ledger::{tx_signing_bytes, LedgerTx};
use uuid::Uuid;

const BREACH_THRESHOLD: u32 = 1;

fn push_system_tx(from: &str, to: &str, amount: u64, memo: &str, nonce: u64) {
    let ts         = chrono::Utc::now().timestamp();
    let sign_bytes = tx_signing_bytes(from, to, amount, nonce, ts);
    let hash       = format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex());
    crate::mempool::get_mempool().push(LedgerTx {
        hash,
        from:      from.to_string(),
        to:        to.to_string(),
        amount,
        memo:      Some(memo.to_string()),
        timestamp: ts,
        signature: "storage_escrow_system".to_string(),
        status:    "Pending".into(),
        nonce,
        tx_type:   "storage_escrow".to_string(),
        ..LedgerTx::default()
    });
}

fn passive_breach_tick(deal: &mut StorageDeal) -> bool {
    if deal.status != "active" { return false; }
    let now     = chrono::Utc::now().timestamp();
    let elapsed = now - deal.last_proof_at;
    if elapsed < STORAGE_DEAL_HEARTBEAT_SECS + STORAGE_DEAL_GRACE_SECS { return false; }

    deal.last_proof_at += STORAGE_DEAL_HEARTBEAT_SECS;
    deal.breach_count  += 1;

    if deal.breach_count >= BREACH_THRESHOLD {
        if deal.escrow_remaining > 0 {
            crate::chain_db::internal_balance_transfer(
                STORAGE_ESCROW_ADDR, &deal.client_address, deal.escrow_remaining,
            );
            push_system_tx(STORAGE_ESCROW_ADDR, &deal.client_address, deal.escrow_remaining,
                &format!("storage_auto_refund:{}", deal.deal_id), 0);
        }
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

    let my_balance = crate::chain_db::balance_of(&my_addr);
    if my_balance < total_cost {
        return Err(EgoDesktopError::WalletError(
            format!("Insufficient balance: need {} uEGOC, have {}", total_cost, my_balance)
        ));
    }

    if !crate::chain_db::internal_balance_transfer(&my_addr, STORAGE_ESCROW_ADDR, total_cost) {
        return Err(EgoDesktopError::WalletError("Failed to lock payment in escrow".into()));
    }
    push_system_tx(&my_addr, STORAGE_ESCROW_ADDR, total_cost,
        &format!("storage_deal_escrow:{}", provider_address), ledger.nonce + 1);

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
        deal_id:          Uuid::new_v4().to_string(),
        provider_address: provider_address.clone(),
        client_address:   my_addr.clone(),
        size_gb,
        duration_days:    days,
        daily_rate_uegoc,
        total_cost_uegoc: total_cost,
        escrow_remaining: total_cost,
        days_paid:        0,
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
    let missed_days = (elapsed / STORAGE_DEAL_HEARTBEAT_SECS).saturating_sub(1) as u32;
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

    let payment = deal.daily_rate_uegoc;
    if deal.escrow_remaining >= payment {
        crate::chain_db::internal_balance_transfer(STORAGE_ESCROW_ADDR, &my_addr, payment);
        push_system_tx(STORAGE_ESCROW_ADDR, &my_addr, payment,
            &format!("storage_daily_payment:{}", deal_id), 0);
        deal.escrow_remaining = deal.escrow_remaining.saturating_sub(payment);
        deal.days_paid += 1;
        ledger.storage_deal_earnings_uegoc += payment;
        ledger.save().map_err(EgoDesktopError::FileSystemError)?;
    }

    deal.last_proof_at = now;

    if deal.days_paid >= deal.duration_days || deal.escrow_remaining == 0 {
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

    if deal.escrow_remaining > 0 {
        crate::chain_db::internal_balance_transfer(STORAGE_ESCROW_ADDR, &my_addr, deal.escrow_remaining);
        push_system_tx(STORAGE_ESCROW_ADDR, &my_addr, deal.escrow_remaining,
            &format!("storage_terminate_refund:{}", deal_id), ledger.nonce + 1);
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
