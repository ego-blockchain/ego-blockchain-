use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use crate::app::AppState;
use crate::chain_db::{
    ComputeCapacityOffer, ComputeJob, ComputeNodeRecord, ComputeReservation,
    COMPUTE_COLLATERAL_BPS, COMPUTE_ESCROW_ADDR,
    HEARTBEAT_INTERVAL_SECS,
    RESERVATION_ESCROW_ADDR, RESERVATION_SLA_BPS,
};

const HEARTBEAT_GRACE_SECS: i64 = 7_200;
const BREACH_THRESHOLD_BONDED:   u32 = 3;
const BREACH_THRESHOLD_UNBONDED: u32 = 1;
use crate::error::EgoDesktopError;
use crate::ledger::{tx_signing_bytes, LedgerTx};
use serde::{Deserialize, Serialize};
use tauri::State;
use uuid::Uuid;

const NODE_POOL_ADDR: &str = crate::chain_db::NODE_POOL_ADDR;
const SLASH_BASE_UEGOC: u64 = 1_000_000; // 1 EGOC minimum slash regardless of bid

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareProfile {
    pub cpu_cores:     u32,
    pub cpu_model:     String,
    pub ram_gb:        u32,
    pub gpu_name:      String,
    pub gpu_vram_gb:   u32,
    pub gpu_count:     u32,
    pub has_cuda:      bool,
    pub compute_score: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeStatus {
    pub enabled:              bool,
    pub hardware:             Option<HardwareProfile>,
    pub allocated_cores:      u32,
    pub allocated_ram_gb:     u32,
    pub locked_cores:              u32,
    pub locked_ram_gb:             u32,
    pub price_per_gpu_hour_uegoc:  u64,
    pub price_per_core_hour_uegoc: u64,
    pub active_jobs:               Vec<ComputeJob>,
    pub pending_jobs:         Vec<ComputeJob>,
    pub my_posted_jobs:       Vec<ComputeJob>,
    pub total_jobs_completed: u64,
    pub earnings_uegoc:       u64,
    pub online_nodes:         u64,
    pub available_jobs:       Vec<ComputeJob>,
    pub address:              String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeEarnings {
    pub total_uegoc:       u64,
    pub jobs_completed:    u64,
    pub avg_per_job_uegoc: u64,
    pub last_24h_uegoc:    u64,
}

fn detect_gpu() -> (String, u32, u32, bool) {
    let output = std::process::Command::new("nvidia-smi")
        .args(["--query-gpu=name,memory.total", "--format=csv,noheader,nounits"])
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut gpu_count = 0u32;
            let mut gpu_name  = String::new();
            let mut vram_mb   = 0u32;
            for line in text.lines() {
                let parts: Vec<&str> = line.split(',').collect();
                if parts.len() >= 2 {
                    gpu_count += 1;
                    if gpu_count == 1 {
                        gpu_name = parts[0].trim().to_string();
                        vram_mb  = parts[1].trim().parse().unwrap_or(0);
                    }
                }
            }
            if gpu_count > 0 {
                return (gpu_name, (vram_mb / 1024).max(1), gpu_count, true);
            }
        }
    }
    ("None".to_string(), 0, 0, false)
}

fn compute_score(cpu_cores: u32, ram_gb: u32, gpu_vram_gb: u32, gpu_count: u32) -> u64 {
    let cpu_score = cpu_cores as u64 * 100;
    let ram_score = ram_gb as u64 * 10;
    let gpu_score = gpu_vram_gb as u64 * 500 * (gpu_count.max(1) as u64);
    cpu_score + ram_score + gpu_score
}

fn collateral_for(bid: u64) -> u64 {
    (bid * COMPUTE_COLLATERAL_BPS / 10_000).max(SLASH_BASE_UEGOC)
}

fn push_system_tx(from: &str, to: &str, amount: u64, memo: &str, nonce: u64) -> String {
    let ts         = chrono::Utc::now().timestamp();
    let sign_bytes = tx_signing_bytes(from, to, amount, nonce, ts);
    let hash       = format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex());
    crate::mempool::get_mempool().push(LedgerTx {
        hash:      hash.clone(),
        from:      from.to_string(),
        to:        to.to_string(),
        amount,
        memo:      Some(memo.to_string()),
        timestamp: ts,
        signature: "compute_escrow_system".to_string(),
        status:    "Pending".into(),
        nonce,
        tx_type:   "compute_escrow".to_string(),
        ..LedgerTx::default()
    });
    hash
}

fn check_and_apply_timeout(job: &mut ComputeJob) -> bool {
    if job.status != "accepted" && job.status != "running" { return false; }
    let now = chrono::Utc::now().timestamp();
    let deadline_secs = job.max_duration_mins as i64 * 60;
    let start = job.accepted_at.unwrap_or(job.created_at);
    if now - start < deadline_secs { return false; }

    job.status       = "timed_out".to_string();
    job.completed_at = Some(now);

    let collateral = job.collateral_uegoc;
    let bid        = job.bid_uegoc;

    if collateral > 0 {
        crate::chain_db::internal_balance_transfer(COMPUTE_ESCROW_ADDR, NODE_POOL_ADDR, collateral);
        push_system_tx(COMPUTE_ESCROW_ADDR, NODE_POOL_ADDR, collateral,
            &format!("compute_slash:{}", job.job_id), 0);
    }
    if bid > 0 {
        crate::chain_db::internal_balance_transfer(COMPUTE_ESCROW_ADDR, &job.poster_address, bid);
        push_system_tx(COMPUTE_ESCROW_ADDR, &job.poster_address, bid,
            &format!("compute_refund:{}", job.job_id), 0);
    }

    job.escrow_active = false;

    if !job.worker_address.is_empty() {
        if let Some(mut node) = crate::chain_db::get_compute_node(&job.worker_address) {
            node.locked_cores  = node.locked_cores.saturating_sub(job.required_cores);
            node.locked_ram_gb = node.locked_ram_gb.saturating_sub(job.required_vram_gb);
            node.slash_count   += 1;
            crate::chain_db::upsert_compute_node(&node);
        }
    }

    eprintln!("[Compute] Job {} timed out — slashed {} uEGOC, refunded {} uEGOC to poster",
        job.job_id, collateral, bid);
    true
}

#[tauri::command]
pub async fn compute_node_heartbeat() {
    let (owner, node_opt, is_enabled, ledger) = tokio::task::spawn_blocking(|| {
        let ledger = crate::ledger::Ledger::load();
        let owner = ledger.address.clone();
        let node = if owner.is_empty() { None } else { crate::chain_db::get_compute_node(&owner) };
        (owner, node, ledger.compute_enabled, ledger)
    }).await.unwrap_or_default();

    if owner.is_empty() {
        tokio::task::spawn_blocking(crate::chain_db::prune_stale_compute_nodes).await.ok();
        return;
    }

    if is_enabled {
        let mut node = if let Some(mut n) = node_opt {
            n.available_cores  = ledger.compute_allocated_cores.saturating_sub(ledger.compute_locked_cores);
            n.available_ram_gb = ledger.compute_allocated_ram_gb.saturating_sub(ledger.compute_locked_ram_gb);
            n.locked_cores     = ledger.compute_locked_cores;
            n.locked_ram_gb    = ledger.compute_locked_ram_gb;
            n
        } else {
            // Reconstruct if pruned or on fresh restart
            if let Ok(hw) = detect_hardware().await {
                crate::chain_db::ComputeNodeRecord {
                    address:              owner.clone(),
                    endpoint:             String::new(),
                    cpu_cores:            hw.cpu_cores,
                    cpu_model:            hw.cpu_model,
                    ram_gb:               hw.ram_gb,
                    gpu_name:             hw.gpu_name,
                    gpu_vram_gb:          hw.gpu_vram_gb,
                    gpu_count:            hw.gpu_count,
                    has_cuda:             hw.has_cuda,
                    compute_score:        hw.compute_score,
                    available_cores:      ledger.compute_allocated_cores.saturating_sub(ledger.compute_locked_cores),
                    available_ram_gb:     ledger.compute_allocated_ram_gb.saturating_sub(ledger.compute_locked_ram_gb),
                    price_per_gpu_hour_uegoc:  ledger.compute_price_per_gpu_hour_uegoc,
                    price_per_core_hour_uegoc: ledger.compute_price_per_core_hour_uegoc,
                    jobs_completed:       ledger.compute_jobs_completed,
                    reputation_score:     ledger.compute_jobs_completed * 10,
                    last_seen:            chrono::Utc::now().timestamp(),
                    status:               "online".to_string(),
                    locked_cores:         ledger.compute_locked_cores,
                    locked_ram_gb:        ledger.compute_locked_ram_gb,
                    slash_count:          0,
                }
            } else {
                return;
            }
        };

        node.last_seen = chrono::Utc::now().timestamp();
        let public_ip = crate::p2p::get_public_endpoint().await;
        if !public_ip.is_empty() {
            node.endpoint = public_ip;
        }
        
        let node_clone = node.clone();
        tokio::task::spawn_blocking(move || crate::chain_db::upsert_compute_node(&node_clone)).await.ok();
        let msg = crate::p2p::P2PMessage::ComputeAnnounce { node };
        crate::p2p::broadcast_compute_msg(msg).await;
        
        // Re-broadcast active open capacity offers
        let owner_clone = owner.clone();
        let my_offers = tokio::task::spawn_blocking(move || {
            crate::chain_db::list_compute_offers().into_iter()
                .filter(|o| o.provider_address == owner_clone && o.status == "open")
                .collect::<Vec<_>>()
        }).await.unwrap_or_default();
        
        for offer in my_offers {
            let msg = crate::p2p::P2PMessage::CapacityOfferBroadcast { offer };
            crate::p2p::broadcast_compute_msg(msg).await;
        }
    }
    
    tokio::task::spawn_blocking(crate::chain_db::prune_stale_compute_nodes).await.ok();
}

#[tauri::command]
pub async fn detect_hardware() -> Result<HardwareProfile, EgoDesktopError> {
    tokio::task::spawn_blocking(|| {
        use sysinfo::System;
        let mut sys = System::new_all();
        sys.refresh_all();

        let cpu_cores = sys.cpus().len() as u32;
        let cpu_model = sys.cpus().first()
            .map(|c| c.brand().to_string())
            .unwrap_or_else(|| "Unknown CPU".to_string());
        let ram_gb = (sys.total_memory() / 1_073_741_824).max(1) as u32;

        let (gpu_name, gpu_vram_gb, gpu_count, has_cuda) = detect_gpu();
        let score = compute_score(cpu_cores, ram_gb, gpu_vram_gb, gpu_count);

        Ok::<_, EgoDesktopError>(HardwareProfile {
            cpu_cores,
            cpu_model,
            ram_gb,
            gpu_name,
            gpu_vram_gb,
            gpu_count,
            has_cuda,
            compute_score: score,
        })
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

#[tauri::command]
pub async fn configure_compute_node(
    enabled: bool,
    allocated_cores: u32,
    allocated_ram_gb: u32,
    price_per_gpu_hour_uegoc: u64,
    price_per_core_hour_uegoc: u64,
) -> Result<(), EgoDesktopError> {
    let mut ledger = crate::ledger::Ledger::load();

    if !enabled && ledger.compute_locked_cores > 0 {
        return Err(EgoDesktopError::InvalidInput(format!(
            "Cannot disable: {} cores and {} GB RAM locked by active jobs. Complete or wait for jobs to finish first.",
            ledger.compute_locked_cores, ledger.compute_locked_ram_gb
        )));
    }

    if allocated_cores < ledger.compute_locked_cores {
        return Err(EgoDesktopError::InvalidInput(format!(
            "Cannot reduce cores below {} — currently locked by active jobs.",
            ledger.compute_locked_cores
        )));
    }
    if allocated_ram_gb < ledger.compute_locked_ram_gb {
        return Err(EgoDesktopError::InvalidInput(format!(
            "Cannot reduce RAM below {} GB — currently locked by active jobs.",
            ledger.compute_locked_ram_gb
        )));
    }

    ledger.compute_enabled                   = enabled;
    ledger.compute_allocated_cores           = allocated_cores;
    ledger.compute_allocated_ram_gb          = allocated_ram_gb;
    ledger.compute_price_per_gpu_hour_uegoc  = price_per_gpu_hour_uegoc;
    ledger.compute_price_per_core_hour_uegoc = price_per_core_hour_uegoc;
    ledger.save().map_err(EgoDesktopError::FileSystemError)?;

    if enabled {
        let hw = detect_hardware().await?;
        let node = ComputeNodeRecord {
            address:              ledger.address.clone(),
            endpoint:             String::new(),
            cpu_cores:            hw.cpu_cores,
            cpu_model:            hw.cpu_model.clone(),
            ram_gb:               hw.ram_gb,
            gpu_name:             hw.gpu_name.clone(),
            gpu_vram_gb:          hw.gpu_vram_gb,
            gpu_count:            hw.gpu_count,
            has_cuda:             hw.has_cuda,
            compute_score:        hw.compute_score,
            available_cores:           allocated_cores,
            available_ram_gb:          allocated_ram_gb,
            price_per_gpu_hour_uegoc,
            price_per_core_hour_uegoc,
            jobs_completed:            ledger.compute_jobs_completed,
            reputation_score:     ledger.compute_jobs_completed * 10,
            last_seen:            chrono::Utc::now().timestamp(),
            status:               "online".to_string(),
            locked_cores:         ledger.compute_locked_cores,
            locked_ram_gb:        ledger.compute_locked_ram_gb,
            slash_count:          0,
        };
        crate::chain_db::upsert_compute_node(&node);

        let msg = crate::p2p::P2PMessage::ComputeAnnounce { node };
        crate::p2p::broadcast_compute_msg(msg).await;
    }

    Ok(())
}

#[tauri::command]
pub async fn get_compute_status() -> Result<ComputeStatus, EgoDesktopError> {
    let (ledger, all_jobs, online_nodes) = tokio::task::spawn_blocking(|| {
        let ledger = crate::ledger::Ledger::load();
        let mut all_jobs = crate::chain_db::list_compute_jobs();
        let now = chrono::Utc::now().timestamp();
        for job in all_jobs.iter_mut() {
            if check_and_apply_timeout(job) {
                crate::chain_db::upsert_compute_job(job);
            }
        }
        let online_nodes = crate::chain_db::list_compute_nodes().iter()
            .filter(|n| now - n.last_seen < 300)
            .count() as u64;
        (ledger, all_jobs, online_nodes)
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?;

    let hw = if ledger.compute_enabled {
        detect_hardware().await.ok()
    } else {
        None
    };

    let my_addr = &ledger.address;

    let locked_c: u32 = all_jobs.iter()
        .filter(|j| j.worker_address == *my_addr && (j.status == "accepted" || j.status == "running"))
        .map(|j| j.required_cores)
        .sum();
    let locked_r: u32 = all_jobs.iter()
        .filter(|j| j.worker_address == *my_addr && (j.status == "accepted" || j.status == "running"))
        .map(|j| j.required_vram_gb)
        .sum();
    if locked_c != ledger.compute_locked_cores || locked_r != ledger.compute_locked_ram_gb {
        tokio::task::spawn_blocking(move || {
            let mut l = crate::ledger::Ledger::load();
            l.compute_locked_cores  = locked_c;
            l.compute_locked_ram_gb = locked_r;
            let _ = l.save();
        }).await.ok();
    }

    let active_jobs: Vec<ComputeJob> = all_jobs.iter()
        .filter(|j| j.worker_address == *my_addr && j.status == "running")
        .cloned().collect();

    let pending_jobs: Vec<ComputeJob> = all_jobs.iter()
        .filter(|j| j.worker_address == *my_addr && j.status == "accepted")
        .cloned().collect();

    let my_posted_jobs: Vec<ComputeJob> = all_jobs.iter()
        .filter(|j| j.poster_address == *my_addr && (j.status == "posted" || j.status == "accepted"))
        .cloned().collect();

    let available_jobs: Vec<ComputeJob> = all_jobs.iter()
        .filter(|j| j.status == "posted" && j.poster_address != *my_addr)
        .cloned().collect();

    Ok(ComputeStatus {
        enabled:                   ledger.compute_enabled,
        hardware:                  hw,
        allocated_cores:           ledger.compute_allocated_cores,
        allocated_ram_gb:          ledger.compute_allocated_ram_gb,
        locked_cores:              locked_c,
        locked_ram_gb:             locked_r,
        price_per_gpu_hour_uegoc:  ledger.compute_price_per_gpu_hour_uegoc,
        price_per_core_hour_uegoc: ledger.compute_price_per_core_hour_uegoc,
        active_jobs,
        pending_jobs,
        my_posted_jobs,
        total_jobs_completed: ledger.compute_jobs_completed,
        earnings_uegoc:       ledger.compute_earnings_uegoc,
        online_nodes,
        available_jobs,
        address:              ledger.address.clone(),
    })
}

#[tauri::command]
pub async fn get_compute_nodes() -> Result<Vec<ComputeNodeRecord>, EgoDesktopError> {
    tokio::task::spawn_blocking(|| {
        let now   = chrono::Utc::now().timestamp();
        let nodes = crate::chain_db::list_compute_nodes()
            .into_iter()
            .filter(|n| now - n.last_seen < 600)
            .collect();
        Ok::<_, EgoDesktopError>(nodes)
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

#[tauri::command]
pub async fn post_compute_job(
    job_type:          String,
    model_cid:         String,
    input_cid:         String,
    required_vram_gb:  u32,
    required_cores:    u32,
    max_duration_mins: u32,
    bid_uegoc:         u64,
    state:             State<'_, AppState>,
) -> Result<String, EgoDesktopError> {
    if bid_uegoc == 0 {
        return Err(EgoDesktopError::InvalidInput("Bid must be > 0".into()));
    }
    if max_duration_mins == 0 {
        return Err(EgoDesktopError::InvalidInput("Duration must be > 0".into()));
    }

    let mut ledger = crate::ledger::Ledger::load();
    let from = ledger.address.clone();

    let chain_balance = crate::chain_db::balance_of(&from);
    if chain_balance < bid_uegoc {
        return Err(EgoDesktopError::InvalidInput(format!(
            "Insufficient balance: have {} uEGOC, bid requires {}",
            chain_balance, bid_uegoc
        )));
    }

    let nonce      = ledger.nonce + 1;
    let ts         = chrono::Utc::now().timestamp();
    let sign_bytes = tx_signing_bytes(&from, COMPUTE_ESCROW_ADDR, bid_uegoc, nonce, ts);
    let sig_hex    = if let Some(kp) = state.get_keypair() {
        hex::encode(kp.sign_ed25519(&sign_bytes).as_bytes())
    } else {
        return Err(EgoDesktopError::WalletError("Wallet not initialized".into()));
    };
    let job_id   = Uuid::new_v4().to_string();
    let lock_hash = format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex());

    crate::mempool::get_mempool().push(LedgerTx {
        hash:               lock_hash.clone(),
        from:               from.clone(),
        to:                 COMPUTE_ESCROW_ADDR.to_string(),
        amount:             bid_uegoc,
        memo:               Some(format!("compute_lock:{}", job_id)),
        timestamp:          ts,
        signature:          sig_hex,
        status:             "Pending".into(),
        block_height:       None,
        nonce,
        tx_type:            "compute_escrow".to_string(),
        ..LedgerTx::default()
    });

    crate::chain_db::internal_balance_transfer(&from, COMPUTE_ESCROW_ADDR, bid_uegoc);

    ledger.nonce = nonce;
    ledger.save().map_err(EgoDesktopError::FileSystemError)?;

    let job = ComputeJob {
        job_id:            job_id.clone(),
        poster_address:    from,
        worker_address:    String::new(),
        job_type,
        model_cid,
        input_cid,
        output_cid:        String::new(),
        required_vram_gb,
        required_cores,
        max_duration_mins,
        bid_uegoc,
        status:            "posted".to_string(),
        created_at:        ts,
        accepted_at:       None,
        completed_at:      None,
        collateral_uegoc:  0,
        escrow_active:     true,
        min_bid_uegoc:     0,
    };

    crate::chain_db::upsert_compute_job(&job);

    let msg = crate::p2p::P2PMessage::ComputeJobPost { job };
    crate::p2p::broadcast_compute_msg(msg).await;

    Ok(job_id)
}

#[tauri::command]
pub async fn cancel_compute_job(
    job_id: String,
    state:  State<'_, AppState>,
) -> Result<(), EgoDesktopError> {
    let mut ledger = crate::ledger::Ledger::load();
    let my_addr    = ledger.address.clone();

    let mut job = crate::chain_db::get_compute_job(&job_id)
        .ok_or_else(|| EgoDesktopError::NotFound("Job not found".into()))?;

    if job.poster_address != my_addr {
        return Err(EgoDesktopError::PermissionDenied("Only the poster can cancel".into()));
    }
    if job.status != "posted" {
        return Err(EgoDesktopError::InvalidInput(
            "Can only cancel jobs that have not been accepted yet".into()
        ));
    }

    if job.escrow_active && job.bid_uegoc > 0 {
        crate::chain_db::internal_balance_transfer(COMPUTE_ESCROW_ADDR, &my_addr, job.bid_uegoc);
        push_system_tx(COMPUTE_ESCROW_ADDR, &my_addr, job.bid_uegoc,
            &format!("compute_cancel_refund:{}", job_id), 0);
    }

    job.status       = "cancelled".to_string();
    job.escrow_active = false;
    job.completed_at  = Some(chrono::Utc::now().timestamp());
    crate::chain_db::upsert_compute_job(&job);

    let msg = crate::p2p::P2PMessage::ComputeJobCancel {
        job_id:         job_id.clone(),
        poster_address: my_addr,
    };
    crate::p2p::broadcast_compute_msg(msg).await;

    Ok(())
}

#[tauri::command]
pub async fn get_compute_jobs() -> Result<Vec<ComputeJob>, EgoDesktopError> {
    tokio::task::spawn_blocking(|| Ok::<_, EgoDesktopError>(crate::chain_db::list_compute_jobs()))
        .await
        .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

fn compute_min_bid(
    required_vram_gb: u32, required_cores: u32, max_duration_mins: u32,
    gpu_vram_gb: u32, price_per_gpu_hour: u64, price_per_core_hour: u64,
) -> u64 {
    let hours_f = max_duration_mins as f64 / 60.0;
    let gpus_needed = if required_vram_gb == 0 || gpu_vram_gb == 0 { 0u64 }
                      else { ((required_vram_gb as f64 / gpu_vram_gb as f64).ceil() as u64).max(1) };
    let gpu_cost  = gpus_needed * price_per_gpu_hour;
    let core_cost = required_cores as u64 * price_per_core_hour;
    ((gpu_cost + core_cost) as f64 * hours_f).ceil() as u64
}

#[tauri::command]
pub async fn accept_compute_job(
    job_id: String,
    state:  State<'_, AppState>,
) -> Result<(), EgoDesktopError> {
    let mut ledger = crate::ledger::Ledger::load();
    let my_addr    = ledger.address.clone();

    let mut job = crate::chain_db::get_compute_job(&job_id)
        .ok_or_else(|| EgoDesktopError::NotFound("Job not found".into()))?;

    if job.status != "posted" {
        return Err(EgoDesktopError::InvalidInput("Job is no longer available".into()));
    }
    if job.poster_address == my_addr {
        return Err(EgoDesktopError::InvalidInput("Cannot accept your own job".into()));
    }
    if !ledger.compute_enabled {
        return Err(EgoDesktopError::InvalidInput("Enable compute node first".into()));
    }

    let free_cores = ledger.compute_allocated_cores.saturating_sub(ledger.compute_locked_cores);
    let free_ram   = ledger.compute_allocated_ram_gb.saturating_sub(ledger.compute_locked_ram_gb);

    if free_cores < job.required_cores {
        return Err(EgoDesktopError::InvalidInput(format!(
            "Not enough free cores: have {}, job needs {}", free_cores, job.required_cores
        )));
    }
    if free_ram < job.required_vram_gb {
        return Err(EgoDesktopError::InvalidInput(format!(
            "Not enough free RAM: have {} GB, job needs {} GB", free_ram, job.required_vram_gb
        )));
    }

    let my_node = crate::chain_db::get_compute_node(&my_addr);
    let (gpu_vram_gb, price_per_gpu_hour, price_per_core_hour) = my_node
        .as_ref()
        .map(|n| (n.gpu_vram_gb, n.price_per_gpu_hour_uegoc, n.price_per_core_hour_uegoc))
        .unwrap_or((0, 0, 0));

    let min_bid = compute_min_bid(
        job.required_vram_gb, job.required_cores, job.max_duration_mins,
        gpu_vram_gb, price_per_gpu_hour, price_per_core_hour,
    );

    if min_bid > 0 && job.bid_uegoc < min_bid {
        return Err(EgoDesktopError::InvalidInput(format!(
            "Bid {} uEGOC is below your minimum price of {} uEGOC for this job",
            job.bid_uegoc, min_bid
        )));
    }

    let collateral = collateral_for(job.bid_uegoc);
    let my_balance = crate::chain_db::balance_of(&my_addr);
    if my_balance < collateral {
        return Err(EgoDesktopError::InvalidInput(format!(
            "Insufficient balance for collateral: need {} uEGOC (20% of bid), have {}",
            collateral, my_balance
        )));
    }

    let nonce      = ledger.nonce + 1;
    let ts         = chrono::Utc::now().timestamp();
    let sign_bytes = tx_signing_bytes(&my_addr, COMPUTE_ESCROW_ADDR, collateral, nonce, ts);
    let sig_hex    = if let Some(kp) = state.get_keypair() {
        hex::encode(kp.sign_ed25519(&sign_bytes).as_bytes())
    } else {
        return Err(EgoDesktopError::WalletError("Wallet not initialized".into()));
    };
    let col_hash = format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex());

    crate::mempool::get_mempool().push(LedgerTx {
        hash:      col_hash.clone(),
        from:      my_addr.clone(),
        to:        COMPUTE_ESCROW_ADDR.to_string(),
        amount:    collateral,
        memo:      Some(format!("compute_collateral:{}", job_id)),
        timestamp: ts,
        signature: sig_hex,
        status:    "Pending".into(),
        nonce,
        tx_type:   "compute_escrow".to_string(),
        ..LedgerTx::default()
    });

    crate::chain_db::internal_balance_transfer(&my_addr, COMPUTE_ESCROW_ADDR, collateral);

    job.status           = "accepted".to_string();
    job.worker_address   = my_addr.clone();
    job.accepted_at      = Some(ts);
    job.collateral_uegoc = collateral;
    job.min_bid_uegoc    = min_bid;
    crate::chain_db::upsert_compute_job(&job);

    ledger.nonce                += 1;
    ledger.compute_locked_cores  += job.required_cores;
    ledger.compute_locked_ram_gb += job.required_vram_gb;
    ledger.save().map_err(EgoDesktopError::FileSystemError)?;

    if let Some(mut node) = crate::chain_db::get_compute_node(&my_addr) {
        node.locked_cores  += job.required_cores;
        node.locked_ram_gb += job.required_vram_gb;
        crate::chain_db::upsert_compute_node(&node);
    }

    let msg = crate::p2p::P2PMessage::ComputeJobAccept {
        job_id:          job_id.clone(),
        worker_address:  my_addr.clone(),
        worker_endpoint: String::new(),
    };
    crate::p2p::broadcast_compute_msg(msg).await;

    let job_id_bg = job_id.clone();
    let addr_bg   = my_addr.clone();
    tokio::spawn(async move {
        run_compute_job_task(job_id_bg, addr_bg).await;
    });

    Ok(())
}

fn decrypt_stored_file(cid: &str) -> Result<Vec<u8>, EgoDesktopError> {
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
    let ledger = crate::ledger::Ledger::load();
    let file   = ledger.stored_files.iter()
        .find(|f| f.cid == cid)
        .ok_or_else(|| EgoDesktopError::NotFound(format!("CID not found locally: {cid}")))?
        .clone();

    if file.local_path.is_empty() || !std::path::Path::new(&file.local_path).exists() {
        return Err(EgoDesktopError::NotFound(format!("File not on disk: {}", file.local_path)));
    }

    let on_disk = std::fs::read(&file.local_path)
        .map_err(|e| EgoDesktopError::FileSystemError(format!("Read: {e}")))?;

    if file.key_nonce_hex == "public" {
        return Ok(on_disk);
    }

    if on_disk.len() < 13 {
        return Err(EgoDesktopError::CryptoError("Encrypted file too short".into()));
    }

    let key_vec = crate::ledger::unprotect_key_bytes(&file.key_nonce_hex);
    if key_vec.len() < 32 {
        return Err(EgoDesktopError::CryptoError("Key too short".into()));
    }

    let cipher  = Aes256Gcm::new_from_slice(&key_vec[..32])
        .map_err(|e| EgoDesktopError::CryptoError(format!("Key init: {e}")))?;
    let nonce   = Nonce::from_slice(&on_disk[..12]);
    let plain   = cipher.decrypt(nonce, &on_disk[12..])
        .map_err(|e| EgoDesktopError::CryptoError(format!("Decrypt: {e}")))?;
    Ok(plain)
}

async fn complete_job_internal(job_id: &str, output_cid: &str, worker_addr: &str) {
    let mut ledger = crate::ledger::Ledger::load();
    let mut job = match crate::chain_db::get_compute_job(job_id) {
        Some(j) => j,
        None    => return,
    };

    let total_release = job.bid_uegoc + job.collateral_uegoc;
    if job.escrow_active && total_release > 0 {
        crate::chain_db::internal_balance_transfer(COMPUTE_ESCROW_ADDR, worker_addr, total_release);
        push_system_tx(COMPUTE_ESCROW_ADDR, worker_addr, job.bid_uegoc,
            &format!("compute_payment:{}", job_id), 0);
        if job.collateral_uegoc > 0 {
            push_system_tx(COMPUTE_ESCROW_ADDR, worker_addr, job.collateral_uegoc,
                &format!("compute_collateral_return:{}", job_id), 0);
        }
    }

    let now = chrono::Utc::now().timestamp();
    job.status       = "completed".to_string();
    job.output_cid   = output_cid.to_string();
    job.completed_at = Some(now);
    job.escrow_active = false;
    crate::chain_db::upsert_compute_job(&job);

    ledger.compute_jobs_completed   += 1;
    ledger.compute_earnings_uegoc   += job.bid_uegoc;
    ledger.compute_locked_cores      = ledger.compute_locked_cores.saturating_sub(job.required_cores);
    ledger.compute_locked_ram_gb     = ledger.compute_locked_ram_gb.saturating_sub(job.required_vram_gb);
    let _ = ledger.save();

    if let Some(mut node) = crate::chain_db::get_compute_node(worker_addr) {
        node.locked_cores   = node.locked_cores.saturating_sub(job.required_cores);
        node.locked_ram_gb  = node.locked_ram_gb.saturating_sub(job.required_vram_gb);
        node.jobs_completed += 1;
        node.reputation_score = node.jobs_completed * 10;
        crate::chain_db::upsert_compute_node(&node);
    }

    let msg = crate::p2p::P2PMessage::ComputeJobComplete {
        job_id:     job_id.to_string(),
        output_cid: output_cid.to_string(),
        worker:     worker_addr.to_string(),
    };
    crate::p2p::broadcast_compute_msg(msg).await;
    eprintln!("[Compute] Job {} completed → output_cid={}", job_id, &output_cid[..output_cid.len().min(20)]);
}

async fn slash_job_internal(job_id: &str, worker_addr: &str, reason: &str) {
    let mut job = match crate::chain_db::get_compute_job(job_id) {
        Some(j) => j,
        None    => return,
    };

    if job.escrow_active && job.collateral_uegoc > 0 {
        push_system_tx(COMPUTE_ESCROW_ADDR, NODE_POOL_ADDR, job.collateral_uegoc,
            &format!("compute_slash:{}", job_id), 0);
    }

    job.status       = "timed_out".to_string();
    job.escrow_active = false;
    job.completed_at  = Some(chrono::Utc::now().timestamp());
    crate::chain_db::upsert_compute_job(&job);

    let mut ledger = crate::ledger::Ledger::load();
    ledger.compute_locked_cores  = ledger.compute_locked_cores.saturating_sub(job.required_cores);
    ledger.compute_locked_ram_gb = ledger.compute_locked_ram_gb.saturating_sub(job.required_vram_gb);
    let _ = ledger.save();

    if let Some(mut node) = crate::chain_db::get_compute_node(worker_addr) {
        node.locked_cores  = node.locked_cores.saturating_sub(job.required_cores);
        node.locked_ram_gb = node.locked_ram_gb.saturating_sub(job.required_vram_gb);
        crate::chain_db::upsert_compute_node(&node);
    }
    eprintln!("[Compute] Job {} slashed — {}", job_id, reason);
}

async fn run_compute_job_task(job_id: String, worker_addr: String) {
    let job = match crate::chain_db::get_compute_job(&job_id) {
        Some(j) => j,
        None    => return,
    };

    let mut running = job.clone();
    running.status = "running".to_string();
    crate::chain_db::upsert_compute_job(&running);

    let timeout_secs = (job.max_duration_mins as u64).max(1) * 60;
    let timeout_dur  = std::time::Duration::from_secs(timeout_secs);

    let model_cid_clone = job.model_cid.clone();
    let input_cid_clone = job.input_cid.clone();
    let job_id_clone    = job_id.clone();
    let worker_clone    = worker_addr.clone();

    let result = tokio::time::timeout(timeout_dur, tokio::task::spawn_blocking(move || {
        execute_wasm_job(&model_cid_clone, &input_cid_clone)
    })).await;

    match result {
        Ok(Ok(Ok(output_cid))) => {
            complete_job_internal(&job_id_clone, &output_cid, &worker_clone).await;
        }
        Ok(Ok(Err(e))) => {
            eprintln!("[Compute] Job {} execution error: {}", job_id_clone, e);
            slash_job_internal(&job_id_clone, &worker_clone, &e).await;
        }
        Ok(Err(e)) => {
            eprintln!("[Compute] Job {} task panic: {}", job_id_clone, e);
            slash_job_internal(&job_id_clone, &worker_clone, "task panic").await;
        }
        Err(_) => {
            eprintln!("[Compute] Job {} timed out after {}s", job_id_clone, timeout_secs);
            slash_job_internal(&job_id_clone, &worker_clone, "timeout").await;
        }
    }
}

fn execute_wasm_job(model_cid: &str, input_cid: &str) -> Result<String, String> {
    let wasm_bytes = decrypt_stored_file(model_cid)
        .map_err(|e| format!("Cannot load model: {e}"))?;

    if wasm_bytes.len() < 4 || &wasm_bytes[..4] != b"\0asm" {
        return Err("model_cid is not valid WASM".into());
    }

    let input_bytes: Vec<u8> = if input_cid.is_empty() {
        Vec::new()
    } else {
        decrypt_stored_file(input_cid).unwrap_or_default()
    };

    let contracts_dir = crate::ledger::contracts_dir();
    let exec = ego_vm::Executor::new(contracts_dir)
        .map_err(|e| format!("VM init: {e}"))?;

    let ts      = chrono::Utc::now().timestamp();
    let deploy  = exec.deploy(&wasm_bytes, "compute_worker", &[], 0, ts,
                              ego_vm::types::DEFAULT_DEPLOY_FUEL)
        .map_err(|e| format!("Deploy: {e}"))?;

    let call = exec.call(&deploy.contract_address, "compute_worker",
                         "run", &input_bytes, 0, ts,
                         ego_vm::types::DEFAULT_CALL_FUEL)
        .map_err(|e| format!("Call: {e}"))?;

    if !call.success {
        return Err(call.error.unwrap_or_else(|| "WASM run() returned failure".into()));
    }

    let hash = blake3::hash(&call.return_val);
    Ok(format!("egocid1{}", hex::encode(hash.as_bytes())))
}

#[tauri::command]
pub async fn complete_compute_job(
    job_id:     String,
    output_cid: String,
) -> Result<(), EgoDesktopError> {
    let mut ledger = crate::ledger::Ledger::load();
    let my_addr    = ledger.address.clone();

    let mut job = crate::chain_db::get_compute_job(&job_id)
        .ok_or_else(|| EgoDesktopError::NotFound("Job not found".into()))?;

    if job.worker_address != my_addr {
        return Err(EgoDesktopError::PermissionDenied("Not your job".into()));
    }
    if job.status != "accepted" && job.status != "running" {
        return Err(EgoDesktopError::InvalidInput(format!("Job is {}", job.status)));
    }

    let total_release = job.bid_uegoc + job.collateral_uegoc;
    if job.escrow_active && total_release > 0 {
        crate::chain_db::internal_balance_transfer(COMPUTE_ESCROW_ADDR, &my_addr, total_release);
        push_system_tx(COMPUTE_ESCROW_ADDR, &my_addr, job.bid_uegoc,
            &format!("compute_payment:{}", job_id), 0);
        if job.collateral_uegoc > 0 {
            push_system_tx(COMPUTE_ESCROW_ADDR, &my_addr, job.collateral_uegoc,
                &format!("compute_collateral_return:{}", job_id), 0);
        }
    }

    let now = chrono::Utc::now().timestamp();
    job.status       = "completed".to_string();
    job.output_cid   = output_cid.clone();
    job.completed_at = Some(now);
    job.escrow_active = false;
    crate::chain_db::upsert_compute_job(&job);

    ledger.compute_jobs_completed   += 1;
    ledger.compute_earnings_uegoc   += job.bid_uegoc;
    ledger.compute_locked_cores      = ledger.compute_locked_cores.saturating_sub(job.required_cores);
    ledger.compute_locked_ram_gb     = ledger.compute_locked_ram_gb.saturating_sub(job.required_vram_gb);
    ledger.save().map_err(EgoDesktopError::FileSystemError)?;

    if let Some(mut node) = crate::chain_db::get_compute_node(&my_addr) {
        node.locked_cores  = node.locked_cores.saturating_sub(job.required_cores);
        node.locked_ram_gb = node.locked_ram_gb.saturating_sub(job.required_vram_gb);
        node.jobs_completed += 1;
        node.reputation_score = node.jobs_completed * 10;
        crate::chain_db::upsert_compute_node(&node);
    }

    let msg = crate::p2p::P2PMessage::ComputeJobComplete {
        job_id,
        output_cid,
        worker: my_addr,
    };
    crate::p2p::broadcast_compute_msg(msg).await;

    Ok(())
}

#[tauri::command]
pub async fn post_capacity_offer(
    cpu_cores:                 u32,
    ram_gb:                    u32,
    gpu_count:                 u32,
    gpu_vram_gb:               u32,
    gpu_name:                  String,
    price_per_gpu_hour_uegoc:  u64,
    price_per_core_hour_uegoc: u64,
    min_duration_hours:        u64,
    max_duration_hours:        u64,
    sla_uptime_pct:            u32,
    bonded:                    bool,
) -> Result<String, EgoDesktopError> {
    let ledger  = crate::ledger::Ledger::load();
    let my_addr = ledger.address.clone();
    let now     = chrono::Utc::now().timestamp();

    if min_duration_hours == 0 || max_duration_hours < min_duration_hours {
        return Err(EgoDesktopError::InvalidInput("min_duration_hours must be >= 1 and <= max_duration_hours".into()));
    }
    if price_per_gpu_hour_uegoc == 0 && price_per_core_hour_uegoc == 0 {
        return Err(EgoDesktopError::InvalidInput("At least one rate must be > 0".into()));
    }

    let offer = ComputeCapacityOffer {
        offer_id:                 Uuid::new_v4().to_string(),
        provider_address:         my_addr.clone(),
        cpu_cores, ram_gb, gpu_count, gpu_vram_gb, gpu_name,
        price_per_gpu_hour_uegoc,
        price_per_core_hour_uegoc,
        price_per_gpu_day_uegoc:  price_per_gpu_hour_uegoc * 24,
        price_per_core_day_uegoc: price_per_core_hour_uegoc * 24,
        min_duration_hours,
        max_duration_hours,
        sla_uptime_pct: sla_uptime_pct.min(100),
        available_from: now,
        status: "open".to_string(),
        created_at: now,
        bonded,
    };

    crate::chain_db::upsert_compute_offer(&offer);
    let msg = crate::p2p::P2PMessage::CapacityOfferBroadcast { offer: offer.clone() };
    crate::p2p::broadcast_compute_msg(msg).await;
    Ok(offer.offer_id)
}

#[tauri::command]
pub async fn cancel_capacity_offer(offer_id: String) -> Result<(), EgoDesktopError> {
    let my_addr = crate::ledger::Ledger::load().address;
    let mut offer = crate::chain_db::get_compute_offer(&offer_id)
        .ok_or_else(|| EgoDesktopError::NotFound("Offer not found".into()))?;
    if offer.provider_address != my_addr {
        return Err(EgoDesktopError::PermissionDenied("Not your offer".into()));
    }
    if offer.status != "open" {
        return Err(EgoDesktopError::InvalidInput("Only open offers can be cancelled".into()));
    }
    offer.status = "cancelled".to_string();
    crate::chain_db::upsert_compute_offer(&offer);
    let msg = crate::p2p::P2PMessage::CapacityOfferCancelled { offer_id };
    crate::p2p::broadcast_compute_msg(msg).await;
    Ok(())
}

#[tauri::command]
pub async fn get_capacity_offers() -> Result<Vec<ComputeCapacityOffer>, EgoDesktopError> {
    tokio::task::spawn_blocking(|| {
        let offers = crate::chain_db::list_compute_offers()
            .into_iter()
            .filter(|o| o.status == "open")
            .collect();
        Ok::<_, EgoDesktopError>(offers)
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

#[tauri::command]
pub async fn book_reservation(
    offer_id:         String,
    duration_minutes: u64,
    state:            State<'_, AppState>,
) -> Result<String, EgoDesktopError> {
    let mut ledger = crate::ledger::Ledger::load();
    let my_addr    = ledger.address.clone();
    let now        = chrono::Utc::now().timestamp();

    let offer = crate::chain_db::get_compute_offer(&offer_id)
        .ok_or_else(|| EgoDesktopError::NotFound("Offer not found".into()))?;

    if offer.status != "open" {
        return Err(EgoDesktopError::InvalidInput("Offer is not open".into()));
    }
    if offer.provider_address == my_addr {
        return Err(EgoDesktopError::InvalidInput("Cannot book your own offer".into()));
    }

    let min_mins = offer.min_duration_hours * 60;
    let max_mins = offer.max_duration_hours * 60;
    if duration_minutes < min_mins || duration_minutes > max_mins {
        return Err(EgoDesktopError::InvalidInput(
            format!("Duration must be between {} and {} minutes", min_mins, max_mins)
        ));
    }

    let hourly_rate = offer.price_per_gpu_hour_uegoc  * offer.gpu_count as u64
                    + offer.price_per_core_hour_uegoc * offer.cpu_cores  as u64;
    let total_cost  = hourly_rate * duration_minutes / 60;

    let period_minutes: u64 = if duration_minutes < 60 {
        duration_minutes
    } else if duration_minutes <= 1_440 {
        60
    } else {
        1_440
    };
    let period_rate = hourly_rate * period_minutes / 60;

    let my_balance = crate::chain_db::balance_of(&my_addr);
    if my_balance < total_cost {
        return Err(EgoDesktopError::WalletError(
            format!("Insufficient balance: need {} uEGOC, have {}", total_cost, my_balance)
        ));
    }

    if !crate::chain_db::internal_balance_transfer(&my_addr, RESERVATION_ESCROW_ADDR, total_cost) {
        return Err(EgoDesktopError::WalletError("Failed to lock buyer payment in escrow".into()));
    }

    let nonce      = ledger.nonce + 1;
    let sign_bytes = tx_signing_bytes(&my_addr, RESERVATION_ESCROW_ADDR, total_cost, nonce, now);
    let kp = state.get_keypair().ok_or_else(|| {
        crate::chain_db::internal_balance_transfer(RESERVATION_ESCROW_ADDR, &my_addr, total_cost);
        EgoDesktopError::WalletError("Wallet not initialized".into())
    })?;
    let sig_hex    = hex::encode(kp.sign_ed25519(&sign_bytes).as_bytes());
    let dil_sig    = kp.sign_dilithium(&sign_bytes);
    let pubkey_hex = hex::encode(kp.ed25519_public_key().as_bytes());
    let dil_pk_hex = hex::encode(&kp.dilithium_public_key().key_data);
    let dil_sig_hex= hex::encode(&dil_sig.signature_data);
    let tx_hash    = format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex());
    crate::mempool::get_mempool().push(LedgerTx {
        hash:                 tx_hash,
        from:                 my_addr.clone(),
        to:                   RESERVATION_ESCROW_ADDR.to_string(),
        amount:               total_cost,
        memo:                 Some(format!("reservation_escrow_buyer:{}", offer_id)),
        timestamp:            now,
        signature:            sig_hex,
        status:               "Pending".into(),
        nonce,
        public_key_ed25519:   pubkey_hex,
        dilithium_pubkey:     dil_pk_hex,
        dilithium_signature:  dil_sig_hex,
        tx_type:              "reservation_escrow".to_string(),
        tx_version:           2,
        chain_id:             1,
        ..LedgerTx::default()
    });
    ledger.nonce = nonce;
    ledger.save().map_err(EgoDesktopError::FileSystemError)?;

    let collateral = if offer.bonded {
        let required = (total_cost * RESERVATION_SLA_BPS / 10_000).max(1_000_000);
        let provider_balance = crate::chain_db::balance_of(&offer.provider_address);
        if provider_balance < required {
            crate::chain_db::internal_balance_transfer(RESERVATION_ESCROW_ADDR, &my_addr, total_cost);
            return Err(EgoDesktopError::InvalidInput(
                format!("Provider cannot meet SLA bond of {} uEGOC (has {})", required, provider_balance)
            ));
        }
        if !crate::chain_db::internal_balance_transfer(&offer.provider_address, RESERVATION_ESCROW_ADDR, required) {
            crate::chain_db::internal_balance_transfer(RESERVATION_ESCROW_ADDR, &my_addr, total_cost);
            return Err(EgoDesktopError::WalletError("Failed to lock provider SLA collateral".into()));
        }
        push_system_tx(&offer.provider_address, RESERVATION_ESCROW_ADDR, required,
            &format!("reservation_escrow_collateral:{}", offer_id), 0);
        required
    } else {
        0
    };

    let reservation = ComputeReservation {
        reservation_id:    Uuid::new_v4().to_string(),
        offer_id:          offer_id.clone(),
        buyer_address:     my_addr.clone(),
        provider_address:  offer.provider_address.clone(),
        cpu_cores:         offer.cpu_cores,
        ram_gb:            offer.ram_gb,
        gpu_count:         offer.gpu_count,
        duration_minutes,
        period_minutes,
        period_rate_uegoc: period_rate,
        total_cost_uegoc:  total_cost,
        collateral_uegoc:  collateral,
        status:            "active".to_string(),
        created_at:        now,
        expires_at:        now + duration_minutes as i64 * 60,
        last_heartbeat_at: now,
        periods_paid:      0,
        breach_count:      0,
        escrow_remaining:  total_cost,
        days:              0,
        days_paid:         0,
        daily_rate_uegoc:  0,
    };

    crate::chain_db::upsert_compute_reservation(&reservation);

    let mut updated_offer = offer.clone();
    updated_offer.status = "booked".to_string();
    crate::chain_db::upsert_compute_offer(&updated_offer);

    if let Some(mut node) = crate::chain_db::get_compute_node(&offer.provider_address) {
        node.locked_cores  += offer.cpu_cores;
        node.locked_ram_gb += offer.ram_gb;
        crate::chain_db::upsert_compute_node(&node);    
    }

    let ssh_pub = get_or_create_ssh_key().await.unwrap_or_default();

    let msg = crate::p2p::P2PMessage::ReservationBooked { 
        reservation: reservation.clone(),
        ssh_public_key: if ssh_pub.is_empty() { None } else { Some(ssh_pub) },
    };
    crate::p2p::broadcast_compute_msg(msg).await;
    Ok(reservation.reservation_id)
}

#[tauri::command]
pub async fn send_reservation_heartbeat(reservation_id: String) -> Result<(), EgoDesktopError> {
    let mut ledger = crate::ledger::Ledger::load();
    let my_addr    = ledger.address.clone();
    let now        = chrono::Utc::now().timestamp();

    let mut res = crate::chain_db::get_compute_reservation(&reservation_id)
        .ok_or_else(|| EgoDesktopError::NotFound("Reservation not found".into()))?;

    if res.provider_address != my_addr {
        return Err(EgoDesktopError::PermissionDenied("Not your reservation".into()));
    }
    if res.status != "active" {
        return Err(EgoDesktopError::InvalidInput(format!("Reservation is {}", res.status)));
    }

    let bonded        = crate::chain_db::get_compute_offer(&res.offer_id).map(|o| o.bonded).unwrap_or(false);
    let threshold     = if bonded { BREACH_THRESHOLD_BONDED } else { BREACH_THRESHOLD_UNBONDED };
    let period_secs   = res.period_minutes as i64 * 60;
    let elapsed       = now - res.last_heartbeat_at;
    let total_periods = res.duration_minutes / res.period_minutes.max(1);
    let missed        = (elapsed / period_secs).saturating_sub(1) as u32;

    if missed > 0 {
        res.breach_count += missed;
        if bonded && res.collateral_uegoc > 0 {
            let slash = (res.collateral_uegoc / total_periods.max(1) * missed as u64)
                .min(res.collateral_uegoc);
            if slash > 0 {
                crate::chain_db::internal_balance_transfer(RESERVATION_ESCROW_ADDR, crate::chain_db::NODE_POOL_ADDR, slash);
                push_system_tx(RESERVATION_ESCROW_ADDR, crate::chain_db::NODE_POOL_ADDR, slash,
                    &format!("reservation_breach_slash:{}", reservation_id), 0);
            }
        }
        if res.breach_count >= threshold {
            res.status = "breached".to_string();
            crate::chain_db::upsert_compute_reservation(&res);
            return Err(EgoDesktopError::InvalidInput("Reservation terminated due to excessive missed periods".into()));
        }
    }

    let payment = res.period_rate_uegoc;
    if res.escrow_remaining >= payment {
        crate::chain_db::internal_balance_transfer(RESERVATION_ESCROW_ADDR, &my_addr, payment);
        push_system_tx(RESERVATION_ESCROW_ADDR, &my_addr, payment,
            &format!("reservation_period_payment:{}", reservation_id), 0);
        res.escrow_remaining = res.escrow_remaining.saturating_sub(payment);
        res.periods_paid += 1;
        ledger.compute_reservation_earnings_uegoc += payment;
        ledger.save().map_err(EgoDesktopError::FileSystemError)?;
    }

    res.last_heartbeat_at = now;

    if res.periods_paid >= total_periods || res.escrow_remaining == 0 {
        res.status = "completed".to_string();
        if res.collateral_uegoc > 0 {
            let slashed   = res.collateral_uegoc / total_periods.max(1) * res.breach_count as u64;
            let remaining = res.collateral_uegoc.saturating_sub(slashed);
            if remaining > 0 {
                crate::chain_db::internal_balance_transfer(RESERVATION_ESCROW_ADDR, &my_addr, remaining);
                push_system_tx(RESERVATION_ESCROW_ADDR, &my_addr, remaining,
                    &format!("reservation_collateral_return:{}", reservation_id), 0);
            }
        }
        if let Some(mut node) = crate::chain_db::get_compute_node(&my_addr) {
            node.locked_cores  = node.locked_cores.saturating_sub(res.cpu_cores);
            node.locked_ram_gb = node.locked_ram_gb.saturating_sub(res.ram_gb);
            crate::chain_db::upsert_compute_node(&node);
        }
    }

    crate::chain_db::upsert_compute_reservation(&res);

    let msg = crate::p2p::P2PMessage::ReservationHeartbeat {
        reservation_id: reservation_id.clone(),
        provider:       my_addr,
        timestamp:      now,
    };
    crate::p2p::broadcast_compute_msg(msg).await;

    Ok(())
}

fn passive_breach_tick(res: &mut ComputeReservation, bonded: bool) -> bool {
    if res.status != "active" { return false; }
    let now          = chrono::Utc::now().timestamp();
    let elapsed      = now - res.last_heartbeat_at;
    let period_secs  = res.period_minutes as i64 * 60;
    let grace_secs   = (period_secs / 4).max(HEARTBEAT_GRACE_SECS);
    if elapsed < period_secs + grace_secs { return false; }

    res.last_heartbeat_at += period_secs;
    res.breach_count      += 1;

    let total_periods = res.duration_minutes / res.period_minutes.max(1);
    if bonded && res.collateral_uegoc > 0 {
        let slash = (res.collateral_uegoc / total_periods.max(1)).min(res.collateral_uegoc);
        if slash > 0 {
            crate::chain_db::internal_balance_transfer(RESERVATION_ESCROW_ADDR, crate::chain_db::NODE_POOL_ADDR, slash);
            push_system_tx(RESERVATION_ESCROW_ADDR, crate::chain_db::NODE_POOL_ADDR, slash,
                &format!("reservation_breach_slash:{}", res.reservation_id), 0);
        }
    }

    let threshold = if bonded { BREACH_THRESHOLD_BONDED } else { BREACH_THRESHOLD_UNBONDED };
    if res.breach_count >= threshold {
        if res.escrow_remaining > 0 {
            crate::chain_db::internal_balance_transfer(RESERVATION_ESCROW_ADDR, &res.buyer_address, res.escrow_remaining);
            push_system_tx(RESERVATION_ESCROW_ADDR, &res.buyer_address, res.escrow_remaining,
                &format!("reservation_auto_refund:{}", res.reservation_id), 0);
        }
        if bonded {
            let slashed   = res.collateral_uegoc / total_periods.max(1) * res.breach_count as u64;
            let remaining = res.collateral_uegoc.saturating_sub(slashed);
            if remaining > 0 {
                crate::chain_db::internal_balance_transfer(RESERVATION_ESCROW_ADDR, &res.buyer_address, remaining);
                push_system_tx(RESERVATION_ESCROW_ADDR, &res.buyer_address, remaining,
                    &format!("reservation_auto_penalty:{}", res.reservation_id), 0);
            }
        }
        res.escrow_remaining = 0;
        res.status = "auto_terminated".to_string();

        if let Some(mut offer) = crate::chain_db::get_compute_offer(&res.offer_id) {
            offer.status = "open".to_string();
            crate::chain_db::upsert_compute_offer(&offer);
        }
        if let Some(mut node) = crate::chain_db::get_compute_node(&res.provider_address) {
            node.locked_cores  = node.locked_cores.saturating_sub(res.cpu_cores);
            node.locked_ram_gb = node.locked_ram_gb.saturating_sub(res.ram_gb);
            crate::chain_db::upsert_compute_node(&node);
        }

        eprintln!("[Compute] Reservation {} auto-terminated ({} breaches, bonded={})",
            res.reservation_id, res.breach_count, bonded);
    }
    true
}

#[tauri::command]
pub async fn get_reservations() -> Result<Vec<ComputeReservation>, EgoDesktopError> {
    tokio::task::spawn_blocking(|| {
        let ledger  = crate::ledger::Ledger::load();
        let my_addr = ledger.address.clone();

        let mut reservations: Vec<ComputeReservation> = crate::chain_db::list_compute_reservations()
            .into_iter()
            .filter(|r| r.buyer_address == my_addr || r.provider_address == my_addr)
            .collect();

        for res in &mut reservations {
            let bonded = crate::chain_db::get_compute_offer(&res.offer_id)
                .map(|o| o.bonded)
                .unwrap_or(false);
            if passive_breach_tick(res, bonded) {
                crate::chain_db::upsert_compute_reservation(res);
            }
        }

        Ok::<_, EgoDesktopError>(reservations)
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

#[tauri::command]
pub async fn terminate_reservation(
    reservation_id: String,
) -> Result<(), EgoDesktopError> {
    let ledger  = crate::ledger::Ledger::load();
    let my_addr = ledger.address.clone();
    let now     = chrono::Utc::now().timestamp();

    let mut res = crate::chain_db::get_compute_reservation(&reservation_id)
        .ok_or_else(|| EgoDesktopError::NotFound("Reservation not found".into()))?;

    if res.buyer_address != my_addr {
        return Err(EgoDesktopError::PermissionDenied("Only the buyer can terminate".into()));
    }
    if res.status != "active" && res.status != "breached" {
        return Err(EgoDesktopError::InvalidInput(format!("Reservation is {}", res.status)));
    }
    let bonded = crate::chain_db::get_compute_offer(&res.offer_id)
        .map(|o| o.bonded)
        .unwrap_or(false);
    let threshold = if bonded { BREACH_THRESHOLD_BONDED } else { BREACH_THRESHOLD_UNBONDED };
    if res.breach_count < threshold && res.status != "breached" {
        return Err(EgoDesktopError::InvalidInput(
            format!("Need {} breach event(s) to terminate; currently {}", threshold, res.breach_count)
        ));
    }

    if res.escrow_remaining > 0 {
        crate::chain_db::internal_balance_transfer(RESERVATION_ESCROW_ADDR, &my_addr, res.escrow_remaining);
        push_system_tx(RESERVATION_ESCROW_ADDR, &my_addr, res.escrow_remaining,
            &format!("reservation_terminate_refund:{}", reservation_id), ledger.nonce + 1);
    }

    if res.collateral_uegoc > 0 {
        crate::chain_db::internal_balance_transfer(RESERVATION_ESCROW_ADDR, &my_addr, res.collateral_uegoc);
        push_system_tx(RESERVATION_ESCROW_ADDR, &my_addr, res.collateral_uegoc,
            &format!("reservation_terminate_penalty:{}", reservation_id), 0);
    }

    res.status           = "terminated".to_string();
    res.escrow_remaining = 0;
    crate::chain_db::upsert_compute_reservation(&res);

    if let Some(mut node) = crate::chain_db::get_compute_node(&res.provider_address) {
        node.locked_cores  = node.locked_cores.saturating_sub(res.cpu_cores);
        node.locked_ram_gb = node.locked_ram_gb.saturating_sub(res.ram_gb);
        crate::chain_db::upsert_compute_node(&node);
    }

    let mut offer = crate::chain_db::get_compute_offer(&res.offer_id)
        .unwrap_or_else(|| ComputeCapacityOffer {
            offer_id: res.offer_id.clone(),
            provider_address: res.provider_address.clone(),
            cpu_cores: res.cpu_cores, ram_gb: res.ram_gb,
            gpu_count: res.gpu_count, gpu_vram_gb: 0, gpu_name: String::new(),
            price_per_gpu_hour_uegoc: 0, price_per_core_hour_uegoc: 0,
            price_per_gpu_day_uegoc: 0, price_per_core_day_uegoc: 0,
            min_duration_hours: 1, max_duration_hours: 8_760,
            sla_uptime_pct: 99,
            available_from: now, status: "booked".to_string(), created_at: now,
            bonded: false,
        });
    offer.status = "open".to_string();
    crate::chain_db::upsert_compute_offer(&offer);

    let msg = crate::p2p::P2PMessage::ReservationTerminated {
        reservation_id: reservation_id.clone(),
        by:     "buyer".to_string(),
        reason: format!("{} breach events", res.breach_count),
    };
    crate::p2p::broadcast_compute_msg(msg).await;

    Ok(())
}

#[tauri::command]
pub async fn get_compute_earnings() -> Result<ComputeEarnings, EgoDesktopError> {
    tokio::task::spawn_blocking(|| {
        let ledger  = crate::ledger::Ledger::load();
        let jobs    = crate::chain_db::list_compute_jobs();
        let now     = chrono::Utc::now().timestamp();
        let day_ago = now - 86_400;

        let last_24h_uegoc: u64 = jobs.iter()
            .filter(|j| {
                j.worker_address == ledger.address
                    && j.status == "completed"
                    && j.completed_at.map(|t| t > day_ago).unwrap_or(false)
            })
            .map(|j| j.bid_uegoc)
            .sum();

        let avg = if ledger.compute_jobs_completed > 0 {
            ledger.compute_earnings_uegoc / ledger.compute_jobs_completed
        } else {
            0
        };

        Ok::<_, EgoDesktopError>(ComputeEarnings {
            total_uegoc:       ledger.compute_earnings_uegoc,
            jobs_completed:    ledger.compute_jobs_completed,
            avg_per_job_uegoc: avg,
            last_24h_uegoc,
        })
    }).await.map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

/// Opens the system's default terminal and executes the SSH command.
/// This allows non-technical users to connect to their rented machine with one click.
#[tauri::command]
pub async fn open_ssh_terminal(ssh_command: String) -> Result<(), EgoDesktopError> {
    // We append a command to show hardware info immediately upon login
    // This script runs on the REMOTE Linux machine.
    let verify_cmd = "echo '--- RENTED HARDWARE REPORT ---'; echo -n 'CPU Cores: '; nproc; echo -n 'RAM: '; awk '/MemTotal/ {print $2/1024/1024}' /proc/meminfo; echo ' GB'; nvidia-smi --query-gpu=name,memory.total --format=csv,noheader; exec bash";
    
    // Check if ssh is actually installed first to give a better error
    let has_ssh = if cfg!(target_os = "windows") {
        std::process::Command::new("where").arg("ssh").output().is_ok()
    } else {
        std::process::Command::new("which").arg("ssh").output().is_ok()
    };

    #[cfg(target_os = "windows")]
    {
        let target = ssh_command.strip_prefix("ssh ").unwrap_or(&ssh_command);
        
        // Escape $ for PowerShell and wrap remote command in escaped double quotes.
        let ps_verify = verify_cmd.replace("$", "`$").replace("\"", "\\\"");
        
        // Detect OpenSSH path: check standard and 32-bit compatibility (Sysnative) paths
        let ssh_exe = if std::path::Path::new("C:\\Windows\\System32\\OpenSSH\\ssh.exe").exists() {
            "C:\\Windows\\System32\\OpenSSH\\ssh.exe"
        } else if std::path::Path::new("C:\\Windows\\Sysnative\\OpenSSH\\ssh.exe").exists() {
            "C:\\Windows\\Sysnative\\OpenSSH\\ssh.exe"
        } else if has_ssh {
            "ssh.exe"
        } else {
                    return Err(EgoDesktopError::NotFound(
                "OpenSSH Client not found. Please install it via: \
                 Settings -> Apps -> Optional Features -> Add 'OpenSSH Client'.".into()
            ));
        };    

        // Automatically ensure the key exists before connecting
        let key_path = ensure_ssh_key_on_disk()?;
        let pub_key = get_or_create_ssh_key().await.unwrap_or_default();
        
        // Use single quotes for the path to handle spaces in Windows usernames reliably in PowerShell
        let identity_flag = format!("-i '{}' -o IdentitiesOnly=yes", 
            key_path.to_string_lossy().replace("'", "''"));

        // Improved PowerShell command: Bypasses host warnings and provides help on failure
        // Using single quotes for verify_cmd to prevent tokenization errors
        let ps_verify_esc = ps_verify.replace("'", "''");
        let ps_cmd = format!(
            "& '{}' -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -o LogLevel=ERROR {} {} -t '{}'; \
             if ($LASTEXITCODE -ne 0) {{ \
                Write-Host \"`n[!] Connection Failed\" -ForegroundColor Red; \
                Write-Host \"If you see 'Permission denied', send your Public Key to the provider:`n\" -ForegroundColor Yellow; \
                Write-Host '{}' -ForegroundColor Cyan; \
                Write-Host \"`n[!] Also check: Is the machine behind a firewall? Is port 22 open?\" -ForegroundColor Gray; \
             }}", 
            ssh_exe, identity_flag, target, ps_verify_esc, pub_key);

        use std::os::windows::process::CommandExt;
                // Use absolute path for PowerShell to avoid "program not found" if PATH is restricted
        let ps_path = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
        let mut cmd = if std::path::Path::new(ps_path).exists() {
            std::process::Command::new(ps_path)
        } else {
            std::process::Command::new("powershell.exe")
        };
        cmd.args(["-NoExit", "-Command", &ps_cmd])
            .creation_flags(0x00000010) // CREATE_NEW_CONSOLE
            .spawn()
            .map_err(|e| EgoDesktopError::FileSystemError(format!("Failed to launch PowerShell: {e}. Try installing 'OpenSSH Client' in Windows Settings.")))?;

    }

    #[cfg(target_os = "macos")]
    {
        let final_ssh_cmd = if ssh_command.starts_with("ssh ") { 
            ssh_command.clone() 
        } else { 
            format!("ssh {}", ssh_command) 
        };

        // Automatically ensure the key exists
        let key_path = ensure_ssh_key_on_disk()?;
        let identity_flag = format!("-i '{}' -o IdentitiesOnly=yes", key_path.to_string_lossy());

        let full_command = format!("{} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR {} -t \"{}\"", 
            final_ssh_cmd, identity_flag, verify_cmd.replace("\"", "\\\""));
        let script = format!("tell application \"Terminal\" to do script \"{}\"", full_command.replace("\\", "\\\\").replace("\"", "\\\""));

        if !has_ssh {
            return Err(EgoDesktopError::NotFound("SSH client not found. Please install OpenSSH.".into()));
        }

        let osa_path = "/usr/bin/osascript";
        let mut cmd = if std::path::Path::new(osa_path).exists() {
            std::process::Command::new(osa_path)
        } else {
            std::process::Command::new("osascript")
        };

        cmd.args(["-e", &script])
            .spawn()
            .map_err(|e| EgoDesktopError::FileSystemError(format!("Failed to launch Terminal via osascript: {e}")))?;
    }

    #[cfg(target_os = "linux")]
    {
        let final_ssh_cmd = if ssh_command.starts_with("ssh ") { 
            ssh_command.clone() 
        } else { 
            format!("ssh {}", ssh_command) 
        };

        if !has_ssh {
            return Err(EgoDesktopError::NotFound("SSH client not found. Please install 'openssh-client' using your package manager.".into()));
        }

        // Automatically ensure the key exists
        let key_path = ensure_ssh_key_on_disk()?;
        let identity_flag = format!("-i '{}' -o IdentitiesOnly=yes", key_path.to_string_lossy());

        let full_command = format!("{} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR {} -t \"{}\"", 
            final_ssh_cmd, identity_flag, verify_cmd.replace("\"", "\\\""));

        // Expanded list of common Linux terminals
        let terminals = [
            "gnome-terminal", "konsole", "xfce4-terminal", "xterm", 
            "alacritty", "kitty", "terminator", "tilix", "urxvt"
        ];
        let mut success = false;
        for term in terminals {
            if std::process::Command::new(term)
                .args(["--", "bash", "-c", &format!("{}; exec bash", full_command)])
                .spawn()
                .is_ok() { success = true; break; }
        }
        if !success { return Err(EgoDesktopError::FileSystemError("No supported terminal found. Please install gnome-terminal or xterm.".into())); }
    }
    Ok(())
}

/// Internal helper to add a public key to the local authorized_keys file.
/// This allows automated SSH access for renters.
pub fn authorize_ssh_key(pub_key: &str) -> Result<(), EgoDesktopError> {
    let pub_key = pub_key.trim();
    if pub_key.is_empty() { return Ok(()); }

    let home = dirs::home_dir()
        .ok_or_else(|| EgoDesktopError::NotFound("Could not find home directory".into()))?;
    let ssh_dir = home.join(".ssh");
    if !ssh_dir.exists() {
        std::fs::create_dir_all(&ssh_dir)
            .map_err(|e| EgoDesktopError::FileSystemError(format!("Failed to create .ssh dir: {e}")))?;
    }

    let auth_keys_path = ssh_dir.join("authorized_keys");
    let mut content = if auth_keys_path.exists() {
        std::fs::read_to_string(&auth_keys_path).unwrap_or_default()
    } else {
        String::new()
    };

    if !content.contains(pub_key) {
        if !content.is_empty() && !content.ends_with('\n') {
            content.push('\n');
        }
        content.push_str(pub_key);
        content.push('\n');
        std::fs::write(&auth_keys_path, content)
            .map_err(|e| EgoDesktopError::FileSystemError(format!("Failed to write authorized_keys: {e}")))?;

        #[cfg(not(target_os = "windows"))]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&auth_keys_path, std::fs::Permissions::from_mode(0o600));
        }
        eprintln!("[SSH] Authorized new key: {}...", &pub_key[..pub_key.len().min(30)]);
    }
    Ok(())
}

/// Internal helper to ensure the identity key exists, or generate it.
fn ensure_ssh_key_on_disk() -> Result<std::path::PathBuf, EgoDesktopError> {
    let home = dirs::home_dir()
        .ok_or_else(|| EgoDesktopError::NotFound("Could not find home directory".into()))?;
    let ssh_dir = home.join(".ssh");
    if !ssh_dir.exists() {
        std::fs::create_dir_all(&ssh_dir)
            .map_err(|e| EgoDesktopError::FileSystemError(format!("Failed to create .ssh dir: {e}")))?;
    }

    let key_path = ssh_dir.join("id_ed25519");
    if !key_path.exists() {
        eprintln!("[SSH] id_ed25519 missing, generating automatically...");
        // Generate a new Ed25519 keypair without a passphrase
        let keygen_exe = if cfg!(target_os = "windows") {
            if std::path::Path::new("C:\\Windows\\System32\\OpenSSH\\ssh-keygen.exe").exists() {
                "C:\\Windows\\System32\\OpenSSH\\ssh-keygen.exe"
            } else if std::path::Path::new("C:\\Windows\\Sysnative\\OpenSSH\\ssh-keygen.exe").exists() {
                "C:\\Windows\\Sysnative\\OpenSSH\\ssh-keygen.exe"
            } else { "ssh-keygen.exe" }
        } else { "ssh-keygen" };

        let mut cmd = std::process::Command::new(keygen_exe);
        cmd.args([
            "-t", "ed25519",
            "-N", "", // empty passphrase
            "-f", &key_path.to_string_lossy(),
            "-C", "ego-compute-key"
        ]);

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
        }

        let output = cmd.output()
            .map_err(|e| EgoDesktopError::FileSystemError(format!("Failed to run ssh-keygen: {e}. Please ensure OpenSSH Client is installed.")))?;
        
        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(EgoDesktopError::FileSystemError(format!("ssh-keygen failed: {err}")));
        }

        // On Unix, ensure the private key has the correct 600 permissions
        #[cfg(not(target_os = "windows"))]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&key_path).map_err(|e| EgoDesktopError::FileSystemError(e.to_string()))?.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(&key_path, perms);
        }
    }
    Ok(key_path)
}

/// Returns the user's public SSH key (Ed25519). 
/// If no key exists, it attempts to generate one automatically without a passphrase.
/// This makes it easy for non-technical users to provide their key to compute providers.
#[tauri::command]
pub async fn get_or_create_ssh_key() -> Result<String, EgoDesktopError> {
    tokio::task::spawn_blocking(|| {
        let key_path = ensure_ssh_key_on_disk()?;
        let pub_path = key_path.with_extension("pub");

        if pub_path.exists() {
            let content = std::fs::read_to_string(&pub_path)
                .map_err(|e| EgoDesktopError::FileSystemError(format!("Failed to read public key: {e}")))?;
            Ok(content.trim().to_string())
        } else {
            // Try to re-derive the public key if .pub is missing but private is there
            let keygen_exe = if cfg!(target_os = "windows") {
                if std::path::Path::new("C:\\Windows\\System32\\OpenSSH\\ssh-keygen.exe").exists() {
                    "C:\\Windows\\System32\\OpenSSH\\ssh-keygen.exe"
                } else if std::path::Path::new("C:\\Windows\\Sysnative\\OpenSSH\\ssh-keygen.exe").exists() {
                    "C:\\Windows\\Sysnative\\OpenSSH\\ssh-keygen.exe"
                } else { "ssh-keygen.exe" }
            } else { "ssh-keygen" };

            let output = std::process::Command::new(keygen_exe)
                .args(["-y", "-f", &key_path.to_string_lossy()])
                .output()
                .map_err(|e| EgoDesktopError::FileSystemError(e.to_string()))?;
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        }
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}
