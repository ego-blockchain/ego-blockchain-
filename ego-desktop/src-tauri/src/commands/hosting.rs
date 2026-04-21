use crate::error::EgoDesktopError;
use crate::ledger::Ledger;
use serde::{Deserialize, Serialize};
use tauri::Manager;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

static PENDING_SITE_KEYS: OnceLock<Mutex<HashMap<String, [u8; 32]>>> = OnceLock::new();

fn pending_keys() -> std::sync::MutexGuard<'static, HashMap<String, [u8; 32]>> {
    PENDING_SITE_KEYS.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap()
}

pub fn encrypt_site_file(plaintext: &[u8], key: &[u8; 32]) -> Vec<u8> {
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
    use rand::{rngs::OsRng, RngCore};
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut out = nonce_bytes.to_vec();
    out.extend(cipher.encrypt(nonce, plaintext).expect("encrypt"));
    out
}

pub fn decrypt_site_file(data: &[u8], key_hex: &str) -> Option<Vec<u8>> {
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
    if key_hex.is_empty() { return Some(data.to_vec()); }
    let key_bytes = hex::decode(key_hex).ok()?;
    if key_bytes.len() != 32 { return Some(data.to_vec()); }
    if data.len() < 28 { return None; }
    let (nonce_bytes, ct) = data.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).ok()?;
    cipher.decrypt(Nonce::from_slice(nonce_bytes), ct).ok()
}

const HOSTING_FEE_SINK: &str = "egot1feesink0000000000000000000000000000000";
const TRIAL_DAYS: i64 = 7;

#[derive(Debug, Serialize)]
pub struct HostingAccess {
    pub has_access:          bool,
    pub in_trial:            bool,
    pub trial_days_left:     i64,
    pub has_plan:            bool,
    pub plan_tier:           Option<String>,
    pub plan_expires_at:     Option<i64>,
}

pub fn check_hosting_access() -> Result<HostingAccess, EgoDesktopError> {
    let ledger = Ledger::load();
    let owner  = &ledger.address;
    let now    = chrono::Utc::now().timestamp();

    let plan = if owner.is_empty() { None } else {
        crate::chain_db::get_hosting_plan(owner).filter(|p| p.expires_at > now)
    };

    if let Some(ref p) = plan {
        return Ok(HostingAccess {
            has_access:      true,
            in_trial:        false,
            trial_days_left: 0,
            has_plan:        true,
            plan_tier:       Some(p.tier.clone()),
            plan_expires_at: Some(p.expires_at),
        });
    }

    let trial_start = ledger.hosting_trial_started_at;
    if trial_start > 0 {
        let days_left = (TRIAL_DAYS - (now - trial_start) / 86_400).max(0);
        return Ok(HostingAccess {
            has_access:      days_left > 0,
            in_trial:        days_left > 0,
            trial_days_left: days_left,
            has_plan:        false,
            plan_tier:       None,
            plan_expires_at: None,
        });
    }

    Ok(HostingAccess {
        has_access:      true,
        in_trial:        true,
        trial_days_left: TRIAL_DAYS,
        has_plan:        false,
        plan_tier:       None,
        plan_expires_at: None,
    })
}

#[tauri::command]
pub fn get_hosting_access() -> HostingAccess {
    check_hosting_access().unwrap_or(HostingAccess {
        has_access: false, in_trial: false, trial_days_left: 0,
        has_plan: false, plan_tier: None, plan_expires_at: None,
    })
}

#[derive(Debug, Serialize, Clone)]
pub struct HostingPlanOption {
    pub tier:             String,
    pub label:            String,
    pub usd_per_month:    f64,
    pub max_sites:        u32,
    pub max_storage_gb:   f64,
    pub egoc_per_month:   f64,
    pub uegoc_per_month:  u64,
}

fn plan_options() -> Vec<(String, String, f64, u32, f64)> {
    vec![
        ("starter".into(),  "Starter".into(),  3.99,  20,  50.0),
        ("pro".into(),      "Pro".into(),       7.99,  60, 120.0),
        ("business".into(), "Business".into(), 14.99,   0, 500.0),
    ]
}

fn usd_to_uegoc(usd: f64) -> u64 {
    let price = crate::p2p::get_egoc_price_usd().max(0.000001);
    ((usd / price) * 1_000_000.0).ceil() as u64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteFile {
    pub path: String,
    pub cid: String,
    pub mime_type: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostedSite {
    pub name: String,
    pub root_cid: String,
    pub owner: String,
    pub deployed_at: i64,
    pub updated_at: i64,
    pub file_count: usize,
    pub total_size: u64,
    pub local_url: String,
    pub files: Vec<SiteFile>,
    #[serde(default)]
    pub custom_domain: Option<String>,
    #[serde(default)]
    pub site_key_hex: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SiteFileInput {
    pub path: String,
    pub source_path: String,
    pub mime_type: String,
}

#[derive(Debug, Serialize)]
pub struct SiteFileResult {
    pub cid: String,
    pub size: u64,
}

#[derive(Debug, Serialize)]
pub struct DomainAvailability {
    pub available: bool,
    pub taken_by:  Option<String>,
    pub is_yours:  bool,
    pub hosts_ok:  bool,
    pub certs_ok:  bool,
}

#[derive(Debug, Deserialize)]
pub struct FinalizeFileEntry {
    pub path: String,
    pub cid: String,
    pub mime_type: String,
    pub size: u64,
}

pub fn hosting_base_dir() -> std::path::PathBuf {
    let dir = crate::ledger::base_data_dir().join("hosting");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

pub fn site_dir(owner: &str, name: &str) -> std::path::PathBuf {
    let dir = hosting_base_dir().join(owner).join(name);
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn cid_of(data: &[u8]) -> String {
    use blake2::{Blake2s256, Digest};
    let mut h = Blake2s256::new();
    h.update(data);
    format!("egocid1{}", hex::encode(h.finalize()))
}

fn rpc_port() -> u16 {
    std::env::var("EGO_RPC_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(47395)
}

fn local_site_url(name: &str) -> String {
    format!("http://localhost:{}/site/{}", rpc_port(), name)
}

fn sign_hosting_record(node_id: &str, endpoint: &str, last_seen: i64) -> String {
    let sign_msg = format!("ego/hosting/v1:{}:{}:{}", node_id, endpoint, last_seen);
    crate::ledger::load_seed()
        .ok()
        .flatten()
        .and_then(|seed| {
            let arr: [u8; 32] = seed.get(..32)?.try_into().ok()?;
            ego_core::KeyPair::from_bytes(&arr).ok()
        })
        .map(|kp| hex::encode(kp.sign_ed25519(sign_msg.as_bytes()).as_bytes()))
        .unwrap_or_default()
}

fn sanitize_site_relative_path(path: &str) -> Result<std::path::PathBuf, EgoDesktopError> {
    use std::path::{Component, Path, PathBuf};

    let raw = path.trim();
    if raw.is_empty() {
        return Err(EgoDesktopError::InvalidInput("File path cannot be empty".into()));
    }

    let mut clean = PathBuf::new();
    for component in Path::new(raw).components() {
        match component {
            Component::Normal(part) => clean.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(EgoDesktopError::InvalidInput(
                    "Invalid file path: traversal outside site directory is not allowed".into(),
                ));
            }
        }
    }

    if clean.as_os_str().is_empty() {
        return Err(EgoDesktopError::InvalidInput("File path cannot be empty".into()));
    }

    Ok(clean)
}

fn validate_name(name: &str) -> Result<(), EgoDesktopError> {
    if name.is_empty() || name.len() > 63 {
        return Err(EgoDesktopError::InvalidInput("Name must be 1–63 characters".into()));
    }
    if !name.chars().all(|c| c.is_alphanumeric() || c == '-') {
        return Err(EgoDesktopError::InvalidInput(
            "Name may only contain letters, numbers, and hyphens".into(),
        ));
    }
    Ok(())
}

#[tauri::command]
pub fn deploy_site_begin(name: String) -> Result<(), EgoDesktopError> {
    let name = name.trim().to_lowercase();
    validate_name(&name)?;

    let access = check_hosting_access()?;
    if !access.has_access {
        return Err(EgoDesktopError::PermissionDenied(
            "Free trial expired. Subscribe to a hosting plan to continue.".into(),
        ));
    }

    let mut ledger = Ledger::load();
    if ledger.hosting_trial_started_at == 0 {
        ledger.hosting_trial_started_at = chrono::Utc::now().timestamp();
        let _ = ledger.save();
    }
    let owner = ledger.address.clone();

    {
        use rand::{rngs::OsRng, RngCore};
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        pending_keys().insert(name.clone(), key);
    }
    if let Some(raw) = crate::chain_db::get_hosted_site_raw(&name) {
        let existing_owner = raw["owner"].as_str().unwrap_or("").to_string();
        if existing_owner != owner {
            return Err(EgoDesktopError::PermissionDenied(
                format!("Site name '{}' is already registered", name),
            ));
        }
    }
    let _ = site_dir(&owner, &name);
    Ok(())
}

#[tauri::command]
pub fn deploy_site_file(name: String, file: SiteFileInput) -> Result<SiteFileResult, EgoDesktopError> {
    let name  = name.trim().to_lowercase();
    let owner = Ledger::load().address;
    let dir   = site_dir(&owner, &name);

    let content = std::fs::read(&file.source_path)
        .map_err(|e| EgoDesktopError::FileSystemError(format!("Cannot read {}: {}", file.source_path, e)))?;

    let cid  = cid_of(&content);
    let rel_path = sanitize_site_relative_path(&file.path)?;
    let dest = dir.join(&rel_path);
    let dir_canon = dir.canonicalize().unwrap_or_else(|_| dir.clone());
    if !dest.starts_with(&dir_canon) {
        return Err(EgoDesktopError::InvalidInput(
            "Invalid file path: traversal outside site directory is not allowed".into()
        ));
    }
    if let Some(p) = dest.parent() {
        std::fs::create_dir_all(p)
            .map_err(|e| EgoDesktopError::FileSystemError(e.to_string()))?;
    }
    let disk_bytes = {
        let keys = pending_keys();
        if let Some(key) = keys.get(&name) {
            encrypt_site_file(&content, key)
        } else {
            content.clone()
        }
    };
    crate::utils::atomic_write(&dest, &disk_bytes)
        .map_err(|e| EgoDesktopError::FileSystemError(e.to_string()))?;

    let size       = content.len() as u64;
    let now        = chrono::Utc::now().timestamp();
    let local_path = dest.to_string_lossy().to_string();

    let mut ledger = Ledger::load();
    if !ledger.stored_files.iter().any(|sf| sf.cid == cid) {
        ledger.stored_files.push(crate::ledger::StoredFile {
            cid:              cid.clone(),
            name:             format!("{}/{}", name, rel_path.to_string_lossy()),
            original_size:    size,
            encrypted_size:   size,
            duration_months:  12,
            stored_at:        now,
            expiry:           now + 365 * 86_400,
            status:           "Active".to_string(),
            key_nonce_hex:    "public".to_string(),
            local_path,
            owner:            owner.clone(),
            replication_role: "master".to_string(),
            ..Default::default()
        });
    } else if let Some(sf) = ledger.stored_files.iter_mut().find(|sf| sf.cid == cid) {
        sf.local_path        = dest.to_string_lossy().to_string();
        sf.replication_role  = "master".to_string();
        sf.status            = "Active".to_string();
    }
    let _ = ledger.save();

    Ok(SiteFileResult { cid, size })
}

#[tauri::command]
pub async fn finalize_deploy(name: String, files: Vec<FinalizeFileEntry>) -> Result<HostedSite, EgoDesktopError> {
    let name  = name.trim().to_lowercase();
    let owner = Ledger::load().address;
    let now   = chrono::Utc::now().timestamp();

    let total_size: u64 = files.iter().map(|f| f.size).sum();
    let root_cid = files.iter()
        .find(|f| f.path == "/index.html")
        .map(|f| f.cid.clone())
        .or_else(|| files.first().map(|f| f.cid.clone()))
        .unwrap_or_default();

    let deployed_at = crate::chain_db::get_hosted_site_raw(&name)
        .and_then(|r| r["deployed_at"].as_i64())
        .unwrap_or(now);

    let existing_custom_domain = crate::chain_db::get_hosted_site_raw(&name)
        .and_then(|r| r["custom_domain"].as_str().map(|s| s.to_string()));

    let site_files: Vec<SiteFile> = files.into_iter().map(|f| SiteFile {
        path:      f.path,
        cid:       f.cid,
        mime_type: f.mime_type,
        size:      f.size,
    }).collect();

    let site_key_hex = {
        let mut keys = pending_keys();
        keys.remove(&name)
            .map(|k| hex::encode(k))
            .or_else(|| {
                crate::chain_db::get_hosted_site_raw(&name)
                    .and_then(|v| v["site_key_hex"].as_str().map(|s| s.to_string()))
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or_default()
    };

    let site = HostedSite {
        name:          name.clone(),
        root_cid,
        owner:         owner.clone(),
        deployed_at,
        updated_at:    now,
        file_count:    site_files.len(),
        total_size,
        local_url:     local_site_url(&name),
        files:         site_files,
        custom_domain: existing_custom_domain,
        site_key_hex,
    };

    crate::chain_db::save_hosted_site(&name, &serde_json::to_value(&site).unwrap());

    let announce_name   = name.clone();
    let announce_domain = site.custom_domain.clone();
    tokio::spawn(async move {
        announce_self_as_hosting_node(announce_name, announce_domain).await;
    });

    Ok(site)
}

#[tauri::command]
pub async fn deploy_site(name: String, files: Vec<SiteFileInput>) -> Result<HostedSite, EgoDesktopError> {
    let name = name.trim().to_lowercase();
    validate_name(&name)?;
    if files.is_empty() {
        return Err(EgoDesktopError::InvalidInput("No files provided".into()));
    }
    let owner = Ledger::load().address;
    if let Some(raw) = crate::chain_db::get_hosted_site_raw(&name) {
        let existing_owner = raw["owner"].as_str().unwrap_or("").to_string();
        if existing_owner != owner {
            return Err(EgoDesktopError::PermissionDenied(
                format!("Site name '{}' is already registered", name),
            ));
        }
    }
    deploy_site_begin(name.clone())?;
    let mut entries: Vec<FinalizeFileEntry> = Vec::new();
    for f in files {
        let result = deploy_site_file(name.clone(), f.clone())?;
        entries.push(FinalizeFileEntry {
            path:      f.path,
            cid:       result.cid,
            mime_type: f.mime_type,
            size:      result.size,
        });
    }
    finalize_deploy(name, entries).await
}

#[tauri::command]
pub fn get_hosted_sites() -> Vec<HostedSite> {
    let owner = Ledger::load().address;
    crate::chain_db::list_hosted_sites_raw(&owner)
        .into_iter()
        .filter_map(|v| serde_json::from_value::<HostedSite>(v).ok())
        .map(|mut site| { site.local_url = local_site_url(&site.name); site })
        .collect()
}

#[tauri::command]
pub fn undeploy_site(name: String) -> Result<(), EgoDesktopError> {
    let name  = name.trim().to_lowercase();
    let owner = Ledger::load().address;

    if let Some(raw) = crate::chain_db::get_hosted_site_raw(&name) {
        let site_owner = raw["owner"].as_str().unwrap_or("").to_string();
        if site_owner != owner {
            return Err(EgoDesktopError::PermissionDenied("Not your site".into()));
        }
        if let Ok(site) = serde_json::from_value::<HostedSite>(raw) {
            let cids: Vec<String> = site.files.iter().map(|f| f.cid.clone()).collect();
            let mut ledger = Ledger::load();
            ledger.stored_files.retain(|sf| !cids.contains(&sf.cid));
            let _ = ledger.save();
        }
    }

    let _ = std::fs::remove_dir_all(site_dir(&owner, &name));
    crate::chain_db::delete_hosted_site(&name);
    crate::python_host::stop(&name);
    Ok(())
}

async fn announce_self_as_hosting_node(site_name: String, custom_domain: Option<String>) {
    let owner = Ledger::load().address;
    let port  = rpc_port();

    // Discover public IP so oracle DNS returns the correct address.
    let public_ip = discover_public_ip().await.unwrap_or_else(|| "127.0.0.1".to_string());
    let endpoint  = format!("http://{}:{}", public_ip, port);
    eprintln!("[Hosting] Announcing with endpoint: {}", endpoint);

    let mut record = crate::chain_db::get_hosting_node(&owner)
        .unwrap_or_else(|| crate::chain_db::HostingNodeRecord {
            node_id:   owner.clone(),
            endpoint:  endpoint.clone(),
            sites:     vec![],
            domains:   vec![],
            last_seen: 0,
            signature: String::new(),
        });

    record.endpoint  = endpoint;
    record.last_seen = chrono::Utc::now().timestamp();
    if !record.sites.contains(&site_name) {
        record.sites.push(site_name);
    }
    if let Some(d) = custom_domain {
        if !d.is_empty() && !record.domains.contains(&d) {
            record.domains.push(d);
        }
    }
    record.signature = sign_hosting_record(&record.node_id, &record.endpoint, record.last_seen);

    crate::chain_db::upsert_hosting_node(&record);

    // Push directly to all oracle RPCs so DNS resolves immediately.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .unwrap_or_default();
    for oracle in crate::p2p::ORACLE_RPCS {
        let url = format!("{}/hosting/announce", oracle);
        if let Err(e) = client.post(&url).json(&record).send().await {
            eprintln!("[Hosting] Oracle announce to {} failed: {}", oracle, e);
        } else {
            eprintln!("[Hosting] Announced to oracle {}", oracle);
        }
    }

    crate::p2p::gossip_hosting_node(&record);
}

async fn discover_public_ip() -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;
    for url in &["https://api.ipify.org", "https://icanhazip.com", "https://ifconfig.me/ip"] {
        if let Ok(resp) = client.get(*url).send().await {
            if let Ok(text) = resp.text().await {
                let ip = text.trim().to_string();
                if !ip.is_empty() && ip.len() < 50 {
                    return Some(ip);
                }
            }
        }
    }
    None
}

#[tauri::command]
pub async fn hosting_heartbeat() {
    let owner = Ledger::load().address;
    if let Some(mut record) = crate::chain_db::get_hosting_node(&owner) {
        record.last_seen = chrono::Utc::now().timestamp();
        if let Some(ip) = discover_public_ip().await {
            let port = rpc_port();
            record.endpoint = format!("http://{}:{}", ip, port);
        }
        record.signature = sign_hosting_record(&record.node_id, &record.endpoint, record.last_seen);
        crate::chain_db::upsert_hosting_node(&record);
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        for oracle in crate::p2p::ORACLE_RPCS {
            let url = format!("{}/hosting/announce", oracle);
            let _ = client.post(&url).json(&record).send().await;
        }
        crate::p2p::gossip_hosting_node(&record);
    }
    crate::chain_db::prune_stale_hosting_nodes();
}

#[tauri::command]
pub fn get_hosting_nodes(domain: String) -> Vec<crate::chain_db::HostingNodeRecord> {
    let d = domain.trim().to_lowercase();
    crate::chain_db::get_nodes_for_domain(&d)
}

#[tauri::command]
pub fn set_custom_domain(name: String, domain: String) -> Result<(), EgoDesktopError> {
    let name   = name.trim().to_lowercase();
    let domain = domain.trim().to_lowercase().replace("https://", "").replace("http://", "").replace("www.", "");
    let owner  = Ledger::load().address;

    let mut raw = crate::chain_db::get_hosted_site_raw(&name)
        .ok_or_else(|| EgoDesktopError::InvalidInput(format!("Site '{}' not found", name)))?;

    if raw["owner"].as_str().unwrap_or("") != owner {
        return Err(EgoDesktopError::PermissionDenied("Not your site".into()));
    }

    if domain.is_empty() {
        raw["custom_domain"] = serde_json::Value::Null;
    } else {
        raw["custom_domain"] = serde_json::json!(domain);
    }
    crate::chain_db::save_hosted_site(&name, &raw);
    Ok(())
}


#[tauri::command]
pub fn check_domain_available(name: String) -> DomainAvailability {
    let name  = name.trim().to_lowercase();
    let owner = Ledger::load().address;

    match crate::chain_db::get_hosted_site_raw(&name) {
        None => DomainAvailability {
            available: true,
            taken_by:  None,
            is_yours:  false,
            hosts_ok:  crate::tls::hosts_has_entry(&name),
            certs_ok:  crate::tls::certs_exist(),
        },
        Some(raw) => {
            let site_owner = raw["owner"].as_str().unwrap_or("").to_string();
            let is_yours   = site_owner == owner;
            DomainAvailability {
                available: is_yours,
                taken_by:  if is_yours { None } else { Some(site_owner) },
                is_yours,
                hosts_ok:  crate::tls::hosts_has_entry(&name),
                certs_ok:  crate::tls::certs_exist(),
            }
        }
    }
}

#[tauri::command]
pub fn get_hosting_plans() -> Vec<HostingPlanOption> {
    plan_options().into_iter().map(|(tier, label, usd, max_sites, max_storage_gb)| {
        let uegoc = usd_to_uegoc(usd);
        HostingPlanOption {
            tier,
            label,
            usd_per_month: usd,
            max_sites,
            max_storage_gb,
            egoc_per_month: uegoc as f64 / 1_000_000.0,
            uegoc_per_month: uegoc,
        }
    }).collect()
}

#[tauri::command]
pub fn get_my_hosting_plan() -> Option<crate::chain_db::ActiveHostingPlan> {
    let owner = Ledger::load().address;
    if owner.is_empty() { return None; }
    let plan = crate::chain_db::get_hosting_plan(&owner)?;
    let now   = chrono::Utc::now().timestamp();
    if plan.expires_at > now { Some(plan) } else { None }
}

#[tauri::command]
pub async fn purchase_hosting_plan(
    tier:   String,
    months: u32,
    state:  tauri::State<'_, crate::app::AppState>,
) -> Result<crate::chain_db::ActiveHostingPlan, EgoDesktopError> {
    if months == 0 || months > 24 {
        return Err(EgoDesktopError::InvalidInput("months must be 1–24".into()));
    }
    let (_, _, usd_per_month, _, _) = plan_options()
        .into_iter()
        .find(|(t, ..)| t == tier.trim())
        .ok_or_else(|| EgoDesktopError::InvalidInput(format!("Unknown tier: {}", tier)))?;

    let uegoc_per_month = usd_to_uegoc(usd_per_month);
    let total_uegoc     = uegoc_per_month.saturating_mul(months as u64);

    let mut ledger = Ledger::load();
    let owner = ledger.address.clone();
    if owner.is_empty() {
        return Err(EgoDesktopError::WalletError("Wallet not initialized".into()));
    }

    let chain   = crate::ledger::load_chain();
    let balance = chain.balance_of(&owner);
    if balance < total_uegoc {
        let needed_egoc = total_uegoc as f64 / 1_000_000.0;
        let have_egoc   = balance as f64 / 1_000_000.0;
        return Err(EgoDesktopError::InvalidInput(format!(
            "Insufficient balance: need {:.4} EGOC, have {:.4} EGOC",
            needed_egoc, have_egoc
        )));
    }

    let now   = chrono::Utc::now().timestamp();
    let nonce = ledger.nonce + 1;
    let memo  = format!("hosting_plan:{}:{}", tier.trim(), months);
    let sign_bytes = crate::ledger::tx_signing_bytes_v2(
        &owner, HOSTING_FEE_SINK, 0, nonce, now, 1, &memo,
    );

    let (sig_hex, dil_pk, dil_sig) = if let Some(kp) = state.get_keypair() {
        (
            hex::encode(kp.sign_ed25519(&sign_bytes).as_bytes()),
            hex::encode(kp.dilithium_public_key().key_data),
            hex::encode(kp.sign_dilithium(&sign_bytes).as_bytes()),
        )
    } else {
        return Err(EgoDesktopError::WalletError("Wallet not initialized".into()));
    };

    let tx_hash = format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex());

    let pending_tx = crate::ledger::LedgerTx {
        hash:                tx_hash.clone(),
        from:                owner.clone(),
        to:                  HOSTING_FEE_SINK.to_string(),
        amount:              0,
        memo:                Some(memo.clone()),
        timestamp:           now,
        signature:           sig_hex,
        dilithium_pubkey:    dil_pk,
        dilithium_signature: dil_sig,
        status:              "Pending".into(),
        block_height:        None,
        nonce,
        tx_version:          2,
        chain_id:            1,
        fee_uegoc:           total_uegoc,
        tx_type:             "hosting_plan".into(),
        signed_summary:      memo.clone(),
        ..crate::ledger::LedgerTx::default()
    };

    crate::commands::tx_pending::add(&pending_tx);
    crate::mempool::get_mempool().push(pending_tx.clone());
    let gossip_tx = pending_tx.clone();
    tokio::spawn(async move { crate::p2p::broadcast_pending_tx(gossip_tx).await; });

    ledger.nonce = nonce;
    let _ = ledger.save();

    let new_tier = tier.trim().to_string();
    let existing = crate::chain_db::get_hosting_plan(&owner)
        .filter(|p| p.expires_at > now);

    let expires_at = if let Some(ref p) = existing {
        if p.tier == new_tier {
            p.expires_at + (months as i64 * 30 * 86_400)
        } else {
            let remaining_secs = (p.expires_at - now).max(0);
            now + remaining_secs + (months as i64 * 30 * 86_400)
        }
    } else {
        now + (months as i64 * 30 * 86_400)
    };

    let plan = crate::chain_db::ActiveHostingPlan {
        owner:      owner.clone(),
        tier:       new_tier,
        months,
        started_at: now,
        expires_at,
        paid_uegoc: total_uegoc,
        tx_hash:    tx_hash.clone(),
    };
    crate::chain_db::upsert_hosting_plan(&plan);

    Ok(plan)
}

#[tauri::command]
pub fn cancel_hosting_plan() -> Result<(), EgoDesktopError> {
    let owner = Ledger::load().address;
    if owner.is_empty() {
        return Err(EgoDesktopError::WalletError("Wallet not initialized".into()));
    }
    let db = crate::chain_db::get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle("hosting_plans")
        .ok_or_else(|| EgoDesktopError::InvalidInput("Plan store unavailable".into()))?;
    let _ = db.delete_cf(&cf, owner.as_bytes());
    Ok(())
}

#[tauri::command]
pub async fn check_domain_status(domain: String) -> String {
    let domain = domain.trim().to_lowercase()
        .replace("https://", "").replace("http://", "");
    let domain = domain.trim_start_matches("www.");
    if domain.is_empty() { return "pending".to_string(); }

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
    {
        Ok(c)  => c,
        Err(_) => return "pending".to_string(),
    };

    let url = format!("https://dns.google/resolve?name={}&type=NS", domain);
    match client.get(&url).header("Accept", "application/dns-json").send().await {
        Ok(resp) => {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(answers) = json["Answer"].as_array() {
                    let live = answers.iter().any(|a| {
                        a["data"].as_str()
                            .map(|d| d.to_lowercase().contains("egoblockchain.com"))
                            .unwrap_or(false)
                    });
                    if live { return "live".to_string(); }
                }
            }
            "pending".to_string()
        }
        Err(_) => "pending".to_string(),
    }
}

#[tauri::command]
pub fn open_in_browser(url: String) {
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("cmd").args(["/c", "start", "", &url]).spawn();
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(&url).spawn();
    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
}

#[tauri::command]
pub async fn approve_python_site(
    site_name: String,
    app: tauri::AppHandle,
) -> Result<bool, EgoDesktopError> {
    if crate::python_host::is_python_trusted(&site_name) {
        return Ok(true);
    }
    let msg = format!(
        "Site \"{}\" contains Python code (Flask app).\n\n\
         Executing this code gives it full access to your desktop — files, network, and system resources.\n\n\
         Only approve sites you created or fully trust. This cannot be undone without manual revocation.\n\n\
         Allow \"{}\" to run Python?",
        site_name, site_name
    );
    let approved = tauri::api::dialog::blocking::ask(
        app.get_window("main").as_ref(),
        "Python Execution Request",
        &msg,
    );
    if approved {
        crate::python_host::trust_python_site(&site_name);
    }
    Ok(approved)
}

#[tauri::command]
pub fn revoke_python_trust(site_name: String) {
    crate::python_host::revoke_python_trust(&site_name);
}

#[tauri::command]
pub fn setup_eo_certificates() -> Result<String, crate::error::EgoDesktopError> {
    crate::tls::ensure_tls_certs()
        .map_err(|e| crate::error::EgoDesktopError::InvalidInput(e))?;
    crate::tls::install_ca_to_store()
        .map_err(|e| crate::error::EgoDesktopError::InvalidInput(e))?;
    Ok("Ego Local CA installed. .eo domains will work after browser restart.".into())
}
