use crate::app::AppState;
use crate::chain_db::{ClusterBooking, ClusterNode, CLUSTER_ESCROW_ADDR};
use crate::error::EgoDesktopError;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use tauri::State;
use uuid::Uuid;
use hex;

const WG_PORT: u16 = 51820;

fn cluster_subnet(cluster_id: &str) -> String {
    let h = blake3::hash(cluster_id.as_bytes());
    let b = h.as_bytes();
    format!("10.{}.{}", b[0], b[1])
}

fn generate_wg_keypair() -> (String, String) {
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = PublicKey::from(&secret);
    (BASE64.encode(secret.as_bytes()), BASE64.encode(public.as_bytes()))
}

fn wg_key_path(cluster_id: &str, role: &str) -> std::path::PathBuf {
    crate::ledger::base_data_dir().join(format!("cluster_{}_{}.wg", cluster_id, role))
}

fn save_wg_privkey(cluster_id: &str, role: &str, privkey: &str) {
    let _ = std::fs::write(wg_key_path(cluster_id, role), privkey);
}

fn load_wg_privkey(cluster_id: &str, role: &str) -> Option<String> {
    std::fs::read_to_string(wg_key_path(cluster_id, role)).ok()
}

fn get_public_ip() -> String {
    local_ip_address::local_ip()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|_| "0.0.0.0".to_string())
}

fn apply_wg_conf(path: &std::path::Path) -> Result<(), String> {
    let path_str = path.to_string_lossy().to_string();

    #[cfg(target_os = "windows")]
    {
        let r = std::process::Command::new("wireguard")
            .args(["/installtunnelservice", &path_str])
            .output();
        match r {
            Ok(o) if o.status.success() => return Ok(()),
            _ => return Err(format!(
                "Run as Administrator: wireguard.exe /installtunnelservice \"{}\"",
                path_str
            )),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(o) = std::process::Command::new("wg-quick")
            .args(["up", &path_str]).output()
        {
            if o.status.success() { return Ok(()); }
        }
        if let Ok(o) = std::process::Command::new("pkexec")
            .args(["wg-quick", "up", &path_str]).output()
        {
            if o.status.success() { return Ok(()); }
        }
        Err(format!("Run as root: sudo wg-quick up \"{}\"", path_str))
    }
}

fn try_start_ray(is_head: bool, head_ip: &str) -> Result<(), String> {
    let args: Vec<String> = if is_head {
        vec![
            "start".into(), "--head".into(),
            "--port=6379".into(),
            "--object-manager-port=8076".into(),
            "--dashboard-host=0.0.0.0".into(),
        ]
    } else {
        vec!["start".into(), format!("--address={}:6379", head_ip)]
    };

    match std::process::Command::new("ray").args(&args).spawn() {
        Ok(_)  => Ok(()),
        Err(e) => Err(format!(
            "ray not in PATH ({}). Install: pip install 'ray[default]', then run: ray {}",
            e, args.join(" ")
        )),
    }
}

fn write_node_wg_config(booking: &ClusterBooking, my_addr: &str, priv_key: &str)
    -> Result<std::path::PathBuf, String>
{
    let my_node = booking.nodes.iter()
        .find(|n| n.provider_address == my_addr)
        .ok_or_else(|| "node not found in booking".to_string())?;

    let mut cfg = format!(
        "[Interface]\nPrivateKey = {}\nAddress = {}/24\nListenPort = {}\n",
        priv_key, my_node.wg_ip, WG_PORT
    );
    if !booking.buyer_wg_pubkey.is_empty() {
        cfg.push_str(&format!(
            "\n[Peer]\n# buyer\nPublicKey = {}\nAllowedIPs = {}.254/32\nPersistentKeepalive = 25\n",
            booking.buyer_wg_pubkey, booking.subnet
        ));
    }
    for node in &booking.nodes {
        if node.provider_address == my_addr || node.wg_pubkey.is_empty() { continue; }
        let ep = if node.endpoint.is_empty() { format!("{}:{}", node.wg_ip, WG_PORT) } else { node.endpoint.clone() };
        cfg.push_str(&format!(
            "\n[Peer]\n# {}{}\nPublicKey = {}\nAllowedIPs = {}/32\nEndpoint = {}\nPersistentKeepalive = 25\n",
            node.provider_address, if node.is_head { " (head)" } else { "" },
            node.wg_pubkey, node.wg_ip, ep
        ));
    }

    let id_short = &booking.cluster_id[..8.min(booking.cluster_id.len())];
    let conf_path = crate::ledger::base_data_dir().join(format!("wg_cluster_{}.conf", id_short));
    std::fs::write(&conf_path, &cfg).map_err(|e| format!("write config: {}", e))?;
    Ok(conf_path)
}

fn hourly_rate_uegoc(offer: &crate::chain_db::ComputeCapacityOffer) -> u64 {
    offer.price_per_gpu_hour_uegoc * offer.gpu_count as u64
        + offer.price_per_core_hour_uegoc * offer.cpu_cores as u64
}

fn push_system_tx(from: &str, to: &str, amount: u64, memo: &str) {
    use crate::ledger::{tx_signing_bytes, LedgerTx};
    let ts         = chrono::Utc::now().timestamp();
    let sign_bytes = tx_signing_bytes(from, to, amount, 0, ts);
    let hash       = format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex());
    crate::mempool::get_mempool().push(LedgerTx {
        hash,
        from:      from.to_string(),
        to:        to.to_string(),
        amount,
        memo:      Some(memo.to_string()),
        timestamp: ts,
        signature: "cluster_escrow_system".to_string(),
        status:    "Pending".into(),
        nonce:     0,
        tx_type:   "cluster_escrow".to_string(),
        ..LedgerTx::default()
    });
}

#[tauri::command]
pub async fn create_cluster_booking(
    gpu_count:        u32,
    min_gpu_vram_gb:  u32,
    cpu_cores:        u32,
    ram_gb:           u32,
    duration_minutes: u64,
    framework:        String,
    name:             String,
    state:            State<'_, AppState>,
) -> Result<ClusterBooking, EgoDesktopError> {
    let mut ledger = crate::ledger::Ledger::load();
    let my_addr    = ledger.address.clone();
    let now     = chrono::Utc::now().timestamp();

    if duration_minutes == 0 {
        return Err(EgoDesktopError::InvalidInput("duration_minutes must be > 0".into()));
    }
    if gpu_count == 0 && cpu_cores == 0 {
        return Err(EgoDesktopError::InvalidInput("Specify gpu_count or cpu_cores".into()));
    }

    let all_offers = crate::chain_db::list_compute_offers();
    let mut candidates: Vec<_> = all_offers
        .into_iter()
        .filter(|o| {
            o.status == "open"
                && o.provider_address != my_addr
                && o.min_duration_hours * 60 <= duration_minutes
                && duration_minutes <= o.max_duration_hours * 60
                && (gpu_count == 0 || (o.gpu_count > 0 && o.gpu_vram_gb >= min_gpu_vram_gb))
        })
        .collect();

    candidates.sort_by_key(|o| hourly_rate_uegoc(o));

    let mut selected: Vec<crate::chain_db::ComputeCapacityOffer> = Vec::new();
    let mut total_gpus  = 0u32;
    let mut total_cores = 0u32;
    let mut total_ram   = 0u32;

    for offer in candidates {
        if gpu_count > 0 && total_gpus >= gpu_count { break; }
        if gpu_count == 0 && total_cores >= cpu_cores && total_ram >= ram_gb { break; }
        total_gpus  += offer.gpu_count;
        total_cores += offer.cpu_cores;
        total_ram   += offer.ram_gb;
        selected.push(offer);
    }

    if gpu_count > 0 && total_gpus < gpu_count {
        return Err(EgoDesktopError::InvalidInput(
            format!("Only {} GPUs with {}GB+ VRAM available, need {}", total_gpus, min_gpu_vram_gb, gpu_count)
        ));
    }
    if gpu_count == 0 && total_cores < cpu_cores {
        return Err(EgoDesktopError::InvalidInput(
            format!("Only {} cores available, need {}", total_cores, cpu_cores)
        ));
    }

    let cluster_id = Uuid::new_v4().to_string();
    let subnet     = cluster_subnet(&cluster_id);

    let period_minutes: u64 = if duration_minutes <= 60 { duration_minutes }
        else if duration_minutes <= 1_440 { 60 }
        else { 1_440 };

    let mut total_cost = 0u64;
    for offer in &selected {
        total_cost += hourly_rate_uegoc(offer) * duration_minutes / 60;
    }

    let my_balance = crate::chain_db::balance_of(&my_addr);
    if my_balance < total_cost {
        return Err(EgoDesktopError::WalletError(
            format!("Need {} uEGOC, have {}", total_cost, my_balance)
        ));
    }

    if !crate::chain_db::internal_balance_transfer(&my_addr, CLUSTER_ESCROW_ADDR, total_cost) {
        return Err(EgoDesktopError::WalletError("Failed to lock escrow".into()));
    }

    {
        use crate::ledger::{tx_signing_bytes, LedgerTx};
        let nonce      = ledger.nonce + 1;
        let sign_bytes = tx_signing_bytes(&my_addr, CLUSTER_ESCROW_ADDR, total_cost, nonce, now);
        let kp = state.get_keypair().ok_or_else(|| {
            crate::chain_db::internal_balance_transfer(CLUSTER_ESCROW_ADDR, &my_addr, total_cost);
            EgoDesktopError::WalletError("Wallet not initialized".into())
        })?;
        let sig_hex     = hex::encode(kp.sign_ed25519(&sign_bytes).as_bytes());
        let dil_sig     = kp.sign_dilithium(&sign_bytes);
        let pubkey_hex  = hex::encode(kp.ed25519_public_key().as_bytes());
        let dil_pk_hex  = hex::encode(&kp.dilithium_public_key().key_data);
        let dil_sig_hex = hex::encode(&dil_sig.signature_data);
        let tx_hash     = format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex());
        crate::mempool::get_mempool().push(LedgerTx {
            hash:                tx_hash,
            from:                my_addr.clone(),
            to:                  CLUSTER_ESCROW_ADDR.to_string(),
            amount:              total_cost,
            memo:                Some(format!("cluster_escrow:{}", cluster_id)),
            timestamp:           now,
            signature:           sig_hex,
            status:              "Pending".into(),
            nonce,
            public_key_ed25519:  pubkey_hex,
            dilithium_pubkey:    dil_pk_hex,
            dilithium_signature: dil_sig_hex,
            tx_type:             "cluster_escrow".to_string(),
            tx_version:          2,
            chain_id:            1,
            ..LedgerTx::default()
        });
        ledger.nonce = nonce;
        ledger.save().map_err(EgoDesktopError::FileSystemError)?;
    }

    let (buyer_priv, buyer_pub) = generate_wg_keypair();
    save_wg_privkey(&cluster_id, "buyer", &buyer_priv);

    let mut nodes: Vec<ClusterNode> = Vec::new();
    let mut head_provider = String::new();
    let mut head_wg_ip    = String::new();
    let mut best_vram     = 0u32;

    for (i, offer) in selected.iter().enumerate() {
        let ip_idx = (i + 1) as u8;
        let wg_ip  = format!("{}.{}", subnet, ip_idx);
        let is_head = offer.gpu_vram_gb > best_vram || (i == 0 && head_provider.is_empty());
        if is_head {
            best_vram        = offer.gpu_vram_gb;
            head_provider    = offer.provider_address.clone();
            head_wg_ip       = wg_ip.clone();
        }

        let node_hourly = hourly_rate_uegoc(offer);
        let node_cost   = node_hourly * duration_minutes / 60;

        let reservation = crate::chain_db::ComputeReservation {
            reservation_id:    Uuid::new_v4().to_string(),
            offer_id:          offer.offer_id.clone(),
            buyer_address:     my_addr.clone(),
            provider_address:  offer.provider_address.clone(),
            cpu_cores:         offer.cpu_cores,
            ram_gb:            offer.ram_gb,
            gpu_count:         offer.gpu_count,
            duration_minutes,
            period_minutes,
            period_rate_uegoc: node_hourly * period_minutes / 60,
            total_cost_uegoc:  node_cost,
            collateral_uegoc:  0,
            status:            "active".to_string(),
            created_at:        now,
            expires_at:        now + duration_minutes as i64 * 60,
            last_heartbeat_at: now,
            periods_paid:      0,
            breach_count:      0,
            escrow_remaining:  node_cost,
            days:              0,
            days_paid:         0,
            daily_rate_uegoc:  0,
        };
        crate::chain_db::upsert_compute_reservation(&reservation);

        let mut updated_offer = offer.clone();
        updated_offer.status = "booked".to_string();
        crate::chain_db::upsert_compute_offer(&updated_offer);

        nodes.push(ClusterNode {
            provider_address:  offer.provider_address.clone(),
            reservation_id:    reservation.reservation_id,
            cpu_cores:         offer.cpu_cores,
            ram_gb:            offer.ram_gb,
            gpu_count:         offer.gpu_count,
            gpu_vram_gb:       offer.gpu_vram_gb,
            gpu_name:          offer.gpu_name.clone(),
            wg_pubkey:         String::new(),
            wg_ip:             wg_ip.clone(),
            endpoint:          String::new(),
            is_head,
            status:            "pending".to_string(),
            joined_at:         0,
            last_heartbeat_at: now,
            period_rate_uegoc: node_hourly * period_minutes / 60,
        });
    }

    let booking = ClusterBooking {
        cluster_id:            cluster_id.clone(),
        buyer_address:         my_addr.clone(),
        name:                  name.clone(),
        subnet:                subnet.clone(),
        nodes,
        head_provider_address: head_provider,
        head_wg_ip:            head_wg_ip.clone(),
        buyer_wg_pubkey:       buyer_pub,
        total_gpu_count:       total_gpus,
        total_cpu_cores:       total_cores,
        total_ram_gb:          total_ram,
        total_cost_uegoc:      total_cost,
        status:                "forming".to_string(),
        created_at:            now,
        expires_at:            now + duration_minutes as i64 * 60,
        duration_minutes,
        framework:             framework.clone(),
        wg_listen_port:        WG_PORT,
    };

    crate::chain_db::upsert_cluster_booking(&booking);

    let msg = crate::p2p::P2PMessage::ClusterBookingCreated { booking: booking.clone() };
    crate::p2p::broadcast_compute_msg(msg).await;

    Ok(booking)
}

pub async fn auto_join_cluster(cluster_id: String, app: tauri::AppHandle) {
    let my_addr = crate::ledger::Ledger::load().address;
    let mut booking = match crate::chain_db::get_cluster_booking(&cluster_id) {
        Some(b) => b,
        None    => return,
    };

    let is_member = booking.nodes.iter().any(|n| n.provider_address == my_addr);
    if !is_member { return; }

    let already_joined = booking.nodes.iter()
        .find(|n| n.provider_address == my_addr)
        .map(|n| !n.wg_pubkey.is_empty())
        .unwrap_or(false);
    if already_joined { return; }

    let (priv_key, pub_key) = generate_wg_keypair();
    save_wg_privkey(&cluster_id, "provider", &priv_key);
    let endpoint  = format!("{}:{}", get_public_ip(), WG_PORT);
    let now       = chrono::Utc::now().timestamp();
    let mut is_head = false;

    for node in booking.nodes.iter_mut() {
        if node.provider_address == my_addr {
            node.wg_pubkey         = pub_key.clone();
            node.endpoint          = endpoint.clone();
            node.status            = "active".to_string();
            node.joined_at         = now;
            node.last_heartbeat_at = now;
            is_head                = node.is_head;
            break;
        }
    }

    let all_active = booking.nodes.iter().all(|n| n.status == "active");
    if all_active { booking.status = "active".to_string(); }

    crate::chain_db::upsert_cluster_booking(&booking);

    let cluster_name = if booking.name.is_empty() {
        cluster_id[..8.min(cluster_id.len())].to_string()
    } else {
        booking.name.clone()
    };
    let head_ip      = booking.head_wg_ip.clone();
    let framework    = booking.framework.clone();

    let wg_result = write_node_wg_config(&booking, &my_addr, &priv_key)
        .and_then(|p| apply_wg_conf(&p).map(|_| p));

    let ray_result = if framework == "ray" {
        try_start_ray(is_head, &head_ip)
    } else {
        Ok(())
    };

    let body = match (&wg_result, &ray_result) {
        (Ok(_),  Ok(_))  => format!("Joined cluster '{}'. WireGuard and Ray are running.", cluster_name),
        (Ok(_),  Err(e)) => format!("Joined cluster '{}'. WireGuard up. Ray: {}", cluster_name, e),
        (Err(e), _)      => format!("Joined cluster '{}'. WG config saved. Manual step needed: {}", cluster_name, e),
    };
    crate::commands::notifications::notify(&app, "Cluster Node Joined", &body);

    let msg = crate::p2p::P2PMessage::ClusterNodeJoined {
        cluster_id,
        provider_address: my_addr,
        wg_pubkey: pub_key,
        endpoint,
    };
    crate::p2p::broadcast_compute_msg(msg).await;
}

#[tauri::command]
pub async fn get_cluster_bookings() -> Result<Vec<ClusterBooking>, EgoDesktopError> {
    let my_addr = crate::ledger::Ledger::load().address;
    let bookings = crate::chain_db::list_cluster_bookings()
        .into_iter()
        .filter(|b| {
            b.status != "terminated"
                && (b.buyer_address == my_addr
                    || b.nodes.iter().any(|n| n.provider_address == my_addr))
        })
        .collect();
    Ok(bookings)
}

#[tauri::command]
pub async fn terminate_cluster(cluster_id: String) -> Result<(), EgoDesktopError> {
    let my_addr = crate::ledger::Ledger::load().address;
    let mut booking = crate::chain_db::get_cluster_booking(&cluster_id)
        .ok_or_else(|| EgoDesktopError::NotFound("Cluster not found".into()))?;

    if booking.buyer_address != my_addr {
        return Err(EgoDesktopError::PermissionDenied("Not your cluster".into()));
    }
    if booking.status == "terminated" {
        return Err(EgoDesktopError::InvalidInput("Already terminated".into()));
    }

    let now     = chrono::Utc::now().timestamp();
    let elapsed = now - booking.created_at;
    let elapsed_mins = (elapsed / 60) as u64;
    let remaining_mins = booking.duration_minutes.saturating_sub(elapsed_mins);

    for node in &booking.nodes {
        let (total_node_cost, used_cost) =
            if let Some(res) = crate::chain_db::get_compute_reservation(&node.reservation_id) {
                (res.total_cost_uegoc, res.total_cost_uegoc.saturating_sub(res.escrow_remaining))
            } else {
                (0, 0)
            };
        let refund = total_node_cost.saturating_sub(used_cost);
        if refund > 0 {
            crate::chain_db::internal_balance_transfer(CLUSTER_ESCROW_ADDR, &my_addr, refund);
        }

        if let Some(mut res) = crate::chain_db::get_compute_reservation(&node.reservation_id) {
            res.status = "terminated".to_string();
            res.escrow_remaining = 0;
            crate::chain_db::upsert_compute_reservation(&res);
        }
    }

    let _ = remaining_mins;
    booking.status = "terminated".to_string();
    crate::chain_db::upsert_cluster_booking(&booking);

    let msg = crate::p2p::P2PMessage::ClusterTerminated { cluster_id };
    crate::p2p::broadcast_compute_msg(msg).await;
    Ok(())
}

#[tauri::command]
pub async fn get_cluster_wg_config(cluster_id: String) -> Result<String, EgoDesktopError> {
    let my_addr = crate::ledger::Ledger::load().address;
    let booking = crate::chain_db::get_cluster_booking(&cluster_id)
        .ok_or_else(|| EgoDesktopError::NotFound("Cluster not found".into()))?;

    if booking.buyer_address != my_addr {
        return Err(EgoDesktopError::PermissionDenied("Not your cluster".into()));
    }

    let priv_key = load_wg_privkey(&cluster_id, "buyer")
        .unwrap_or_else(|| {
            let (pk, _) = generate_wg_keypair();
            save_wg_privkey(&cluster_id, "buyer", &pk);
            pk
        });

    let buyer_ip = format!("{}.254", booking.subnet);
    let mut cfg = format!(
        "[Interface]\nPrivateKey = {}\nAddress = {}/24\nDNS = 1.1.1.1\n",
        priv_key, buyer_ip
    );

    for node in &booking.nodes {
        if node.wg_pubkey.is_empty() { continue; }
        let allowed = if node.is_head {
            format!("{}.0/24", booking.subnet)
        } else {
            format!("{}/32", node.wg_ip)
        };
        cfg.push_str(&format!(
            "\n[Peer]\n# {}{}\nPublicKey = {}\nAllowedIPs = {}\nEndpoint = {}\nPersistentKeepalive = 25\n",
            node.provider_address,
            if node.is_head { " (head)" } else { "" },
            node.wg_pubkey,
            allowed,
            if node.endpoint.is_empty() {
                format!("{}:{}", node.wg_ip, WG_PORT)
            } else {
                node.endpoint.clone()
            }
        ));
    }

    Ok(cfg)
}

#[tauri::command]
pub async fn get_node_wg_config(cluster_id: String) -> Result<String, EgoDesktopError> {
    let my_addr = crate::ledger::Ledger::load().address;
    let booking = crate::chain_db::get_cluster_booking(&cluster_id)
        .ok_or_else(|| EgoDesktopError::NotFound("Cluster not found".into()))?;

    let my_node = booking.nodes.iter()
        .find(|n| n.provider_address == my_addr)
        .ok_or_else(|| EgoDesktopError::PermissionDenied("Not in this cluster".into()))?;

    let priv_key = load_wg_privkey(&cluster_id, "provider")
        .ok_or_else(|| EgoDesktopError::NotFound("WireGuard key not found — rejoin the cluster".into()))?;

    let mut cfg = format!(
        "[Interface]\nPrivateKey = {}\nAddress = {}/24\nListenPort = {}\n",
        priv_key, my_node.wg_ip, WG_PORT
    );

    if !booking.buyer_wg_pubkey.is_empty() {
        cfg.push_str(&format!(
            "\n[Peer]\n# buyer\nPublicKey = {}\nAllowedIPs = {}.254/32\nPersistentKeepalive = 25\n",
            booking.buyer_wg_pubkey, booking.subnet
        ));
    }

    for node in &booking.nodes {
        if node.provider_address == my_addr || node.wg_pubkey.is_empty() { continue; }
        cfg.push_str(&format!(
            "\n[Peer]\n# {}{}\nPublicKey = {}\nAllowedIPs = {}/32\nEndpoint = {}\nPersistentKeepalive = 25\n",
            node.provider_address,
            if node.is_head { " (head)" } else { "" },
            node.wg_pubkey,
            node.wg_ip,
            if node.endpoint.is_empty() {
                format!("{}:{}", node.wg_ip, WG_PORT)
            } else {
                node.endpoint.clone()
            }
        ));
    }

    Ok(cfg)
}

#[tauri::command]
pub async fn get_cluster_connect_info(cluster_id: String) -> Result<serde_json::Value, EgoDesktopError> {
    let booking = crate::chain_db::get_cluster_booking(&cluster_id)
        .ok_or_else(|| EgoDesktopError::NotFound("Cluster not found".into()))?;

    let head_ip = &booking.head_wg_ip;
    let framework = &booking.framework;

    let connect = match framework.as_str() {
        "ray" => serde_json::json!({
            "type": "ray",
            "head_ip": head_ip,
            "ray_address": format!("ray://{}:10001", head_ip),
            "python_snippet": format!(
                "import ray\nray.init(address=\"ray://{}:10001\")\n\n# Example: run on all GPUs\n@ray.remote(num_gpus=1)\ndef my_gpu_task():\n    import torch\n    return torch.cuda.get_device_name(0)\n\nresult = ray.get([my_gpu_task.remote() for _ in range({})])\nprint(result)",
                head_ip, booking.total_gpu_count
            ),
            "head_bootstrap": format!(
                "# Run on head node ({}):\npip install ray[default]\nray start --head --port=6379 --object-manager-port=8076 --dashboard-host=0.0.0.0",
                head_ip
            ),
            "worker_bootstrap": format!(
                "# Run on each worker node:\npip install ray[default]\nray start --address={}:6379",
                head_ip
            ),
            "ssh_command": format!("ssh root@{}", head_ip),
        }),
        _ => serde_json::json!({
            "type": "ssh",
            "head_ip": head_ip,
            "ssh_command": format!("ssh root@{}", head_ip),
            "note": "Connect to the head node, then run commands across the cluster using mpirun or your preferred scheduler.",
        }),
    };

    Ok(serde_json::json!({
        "cluster_id": cluster_id,
        "status": booking.status,
        "nodes_active": booking.nodes.iter().filter(|n| n.status == "active").count(),
        "nodes_total": booking.nodes.len(),
        "total_gpus": booking.total_gpu_count,
        "total_cores": booking.total_cpu_cores,
        "total_ram_gb": booking.total_ram_gb,
        "subnet": booking.subnet,
        "connect": connect,
    }))
}

#[tauri::command]
pub async fn send_cluster_node_heartbeat(cluster_id: String) -> Result<(), EgoDesktopError> {
    let mut ledger = crate::ledger::Ledger::load();
    let my_addr    = ledger.address.clone();
    let now        = chrono::Utc::now().timestamp();

    let mut booking = crate::chain_db::get_cluster_booking(&cluster_id)
        .ok_or_else(|| EgoDesktopError::NotFound("Cluster not found".into()))?;

    let node_idx = booking.nodes.iter().position(|n| n.provider_address == my_addr)
        .ok_or_else(|| EgoDesktopError::PermissionDenied("Not in this cluster".into()))?;

    let reservation_id = booking.nodes[node_idx].reservation_id.clone();
    let period_rate    = booking.nodes[node_idx].period_rate_uegoc;
    let last_hb        = booking.nodes[node_idx].last_heartbeat_at;

    let mut res = crate::chain_db::get_compute_reservation(&reservation_id)
        .ok_or_else(|| EgoDesktopError::NotFound("Reservation not found".into()))?;

    if res.status != "active" {
        return Err(EgoDesktopError::InvalidInput(format!("Reservation is {}", res.status)));
    }

    let period_secs   = res.period_minutes as i64 * 60;
    let total_periods = res.duration_minutes / res.period_minutes.max(1);
    let elapsed       = now - last_hb;
    let missed        = (elapsed / period_secs).saturating_sub(1) as u32;

    if missed > 0 {
        res.breach_count += missed;
        if res.breach_count >= 3 {
            res.status = "breached".to_string();
            crate::chain_db::upsert_compute_reservation(&res);
            return Err(EgoDesktopError::InvalidInput(
                "Reservation terminated — too many missed periods".into()
            ));
        }
    }

    if res.escrow_remaining >= period_rate {
        crate::chain_db::internal_balance_transfer(CLUSTER_ESCROW_ADDR, &my_addr, period_rate);
        push_system_tx(CLUSTER_ESCROW_ADDR, &my_addr, period_rate,
            &format!("cluster_period_payment:{}:{}", cluster_id, reservation_id));
        res.escrow_remaining  = res.escrow_remaining.saturating_sub(period_rate);
        res.periods_paid     += 1;
        ledger.compute_reservation_earnings_uegoc += period_rate;
        ledger.save().map_err(EgoDesktopError::FileSystemError)?;
    }

    res.last_heartbeat_at = now;
    if res.periods_paid >= total_periods || res.escrow_remaining == 0 {
        res.status = "completed".to_string();
    }
    crate::chain_db::upsert_compute_reservation(&res);

    booking.nodes[node_idx].last_heartbeat_at = now;
    booking.nodes[node_idx].status            = "active".to_string();
    crate::chain_db::upsert_cluster_booking(&booking);

    let msg = crate::p2p::P2PMessage::ClusterNodeHeartbeat {
        cluster_id,
        provider_address: my_addr,
        timestamp: now,
    };
    crate::p2p::broadcast_compute_msg(msg).await;
    Ok(())
}
