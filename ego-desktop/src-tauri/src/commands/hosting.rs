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

/// tier, label, dollars a month, site limit, gigabytes.
///
/// Priced to undercut paid shared hosting, which runs ten to thirty dollars a month once
/// the introductory rate lapses. Not priced against Cloudflare Pages or Netlify, which are
/// free and cannot be beaten on price by anybody: against those the argument is that a site
/// here has no single owner who can take it down, which is a different sale.
///
/// The storage each tier includes costs about $0.002 a gigabyte-month to serve, so even the
/// largest keeps over eighty percent. There was room to halve these and there still is.
fn plan_options() -> Vec<(String, String, f64, u32, f64)> {
    vec![
        ("starter".into(),  "Starter".into(),   1.49,  20,  50.0),
        ("pro".into(),      "Pro".into(),       2.99,  60, 120.0),
        ("business".into(), "Business".into(),  5.99,   0, 500.0),
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

const HOSTING_CLOCK_SKEW_SECS: i64 = 600;
const HOSTING_MAX_SITES: usize = 256;
const HOSTING_MAX_DOMAINS: usize = 64;

pub(crate) fn hosting_keypair() -> Option<ego_core::KeyPair> {
    crate::ledger::load_seed().ok().flatten().and_then(|seed| {
        let arr: [u8; 32] = seed.get(..32)?.try_into().ok()?;
        ego_core::KeyPair::from_bytes(&arr).ok()
    })
}

pub fn hosting_signing_bytes(r: &crate::chain_db::HostingNodeRecord) -> Vec<u8> {
    format!(
        "ego/hosting/v2\n{}\n{}\n{}\n{}\n{}",
        r.node_id,
        r.endpoint,
        r.last_seen,
        r.sites.join(","),
        r.domains.join(",")
    )
    .into_bytes()
}

pub fn valid_hosting_domain(d: &str) -> bool {
    if d.is_empty() || d.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = d.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn valid_hosting_site(s: &str) -> bool {
    !s.is_empty() && s.len() <= 63 && !s.contains(',') && !s.contains('\n') && !s.contains('.')
}

fn sign_hosting_record(record: &mut crate::chain_db::HostingNodeRecord, kp: &ego_core::KeyPair) {
    let legacy = format!("ego/hosting/v1:{}:{}:{}", record.node_id, record.endpoint, record.last_seen);
    record.signature = hex::encode(kp.sign_ed25519(legacy.as_bytes()).as_bytes());
    record.pubkey = hex::encode(&kp.ed25519_public_key().as_bytes()[..32]);
    record.signature_v2 = hex::encode(kp.sign_ed25519(&hosting_signing_bytes(record)).as_bytes());
}

pub fn verify_hosting_record(r: &crate::chain_db::HostingNodeRecord, now: i64) -> Result<(), &'static str> {
    use ed25519_dalek::{Signature, VerifyingKey};
    if (r.last_seen - now).abs() > HOSTING_CLOCK_SKEW_SECS {
        return Err("time");
    }
    if r.endpoint.is_empty() || r.endpoint.len() > 200 || r.endpoint.contains('\n') {
        return Err("endpoint");
    }
    if r.sites.len() > HOSTING_MAX_SITES || !r.sites.iter().all(|s| valid_hosting_site(s)) {
        return Err("site");
    }
    if r.domains.len() > HOSTING_MAX_DOMAINS || !r.domains.iter().all(|d| valid_hosting_domain(d)) {
        return Err("domain");
    }
    let pk: [u8; 32] = hex::decode(&r.pubkey).ok().and_then(|v| v.try_into().ok()).ok_or("pubkey")?;
    let sig: [u8; 64] = hex::decode(&r.signature_v2).ok().and_then(|v| v.try_into().ok()).ok_or("sig")?;
    if crate::market_chain::address_of(&pk) != r.node_id {
        return Err("node");
    }
    VerifyingKey::from_bytes(&pk)
        .map_err(|_| "pubkey")?
        .verify_strict(&hosting_signing_bytes(r), &Signature::from_bytes(&sig))
        .map_err(|_| "sig")
}

fn current_hosting_names(owner: &str) -> (Vec<String>, Vec<String>) {
    let mut sites: Vec<String> = Vec::new();
    let mut domains: Vec<String> = Vec::new();
    for raw in crate::chain_db::list_hosted_sites_raw(owner) {
        if let Some(n) = raw["name"].as_str() {
            if valid_hosting_site(n) && !sites.iter().any(|s| s == n) {
                sites.push(n.to_string());
            }
        }
        if let Some(d) = raw["custom_domain"].as_str() {
            if valid_hosting_domain(d) && !domains.iter().any(|x| x == d) {
                domains.push(d.to_string());
            }
        }
    }
    sites.truncate(HOSTING_MAX_SITES);
    domains.truncate(HOSTING_MAX_DOMAINS);
    (sites, domains)
}

pub fn normalize_custom_domain(input: &str) -> String {
    let d = input.trim().to_lowercase();
    let d = d.trim_start_matches("https://").trim_start_matches("http://");
    let d = d.split(['/', '?', '#']).next().unwrap_or("").trim_end_matches('.');
    d.strip_prefix("www.").unwrap_or(d).to_string()
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
            Component::RootDir | Component::Prefix(_) => {}
            Component::ParentDir => {
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

    let name_clone = name.clone();
    let (deployed_at, existing_custom_domain, existing_key_hex) = tokio::task::spawn_blocking(move || {
        let raw = crate::chain_db::get_hosted_site_raw(&name_clone);
        let deployed_at = raw.as_ref().and_then(|r| r["deployed_at"].as_i64()).unwrap_or(now);
        let domain = raw.as_ref().and_then(|r| r["custom_domain"].as_str().map(|s| s.to_string()));
        let key_hex = raw.and_then(|v| v["site_key_hex"].as_str().map(|s| s.to_string()))
            .filter(|s| !s.is_empty());
        (deployed_at, domain, key_hex)
    }).await.map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?;

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
            .or(existing_key_hex)
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

    let site_val = serde_json::to_value(&site).unwrap();
    let name_clone2 = name.clone();
    tokio::task::spawn_blocking(move || crate::chain_db::save_hosted_site(&name_clone2, &site_val))
        .await.map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?;

    tokio::spawn(announce_hosting_record());
    crate::public_sites::wake_now();

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
    tauri::async_runtime::spawn(announce_hosting_record());
    crate::public_sites::wake_now();
    Ok(())
}

async fn announce_hosting_record() {
    let Ok((owner, names, stored)) = tokio::task::spawn_blocking(|| {
        let owner = Ledger::load().address;
        if owner.is_empty() {
            return (owner, (Vec::new(), Vec::new()), None);
        }
        let names = current_hosting_names(&owner);
        let stored = crate::chain_db::get_hosting_node(&owner);
        (owner, names, stored)
    })
    .await
    else {
        return;
    };
    let (sites, domains) = names;
    if sites.is_empty() && domains.is_empty() {
        return;
    }
    let endpoint = match discover_public_ip().await {
        Some(ip) => format!("http://{}:{}", ip, rpc_port()),
        None => match stored {
            Some(s) => s.endpoint,
            None => {
                eprintln!("[Hosting] Could not find this computer's public address; announcing later");
                return;
            }
        },
    };
    let Some(kp) = hosting_keypair() else {
        eprintln!("[Hosting] No wallet key to sign the hosting announcement");
        return;
    };
    let mut record = crate::chain_db::HostingNodeRecord {
        node_id: owner,
        endpoint,
        sites,
        domains,
        last_seen: chrono::Utc::now().timestamp(),
        signature: String::new(),
        pubkey: String::new(),
        signature_v2: String::new(),
    };
    sign_hosting_record(&mut record, &kp);
    let saved = record.clone();
    tokio::task::spawn_blocking(move || crate::chain_db::upsert_hosting_node(&saved)).await.ok();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .unwrap_or_default();
    for oracle in crate::p2p::ORACLE_RPCS {
        let url = format!("{}/hosting/announce", oracle);
        match client.post(&url).json(&record).send().await {
            Err(e) => eprintln!("[Hosting] Announce to {} failed: {}", oracle, e),
            Ok(resp) if !resp.status().is_success() => {
                let status = resp.status();
                eprintln!("[Hosting] {} refused the announcement ({}): {}", oracle, status, resp.text().await.unwrap_or_default());
            }
            Ok(resp) => {
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                for d in body["refused"].as_array().into_iter().flatten().filter_map(|v| v.as_str()) {
                    eprintln!("[Hosting] {} belongs to another Ego address on {}; it will not point here", d, oracle);
                }
            }
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
    announce_hosting_record().await;
    tokio::task::spawn_blocking(crate::chain_db::prune_stale_hosting_nodes).await.ok();
}

#[tauri::command]
pub fn get_hosting_nodes(domain: String) -> Vec<crate::chain_db::HostingNodeRecord> {
    let d = domain.trim().to_lowercase();
    crate::chain_db::get_nodes_for_domain(&d)
}

#[tauri::command]
pub fn set_custom_domain(name: String, domain: String) -> Result<(), EgoDesktopError> {
    let name   = name.trim().to_lowercase();
    let domain = normalize_custom_domain(&domain);
    if !domain.is_empty() && !valid_hosting_domain(&domain) {
        return Err(EgoDesktopError::InvalidInput(
            "That domain can't be served by Ego. Use a plain name like example.com: letters, numbers, hyphens and dots.".into(),
        ));
    }
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
    tauri::async_runtime::spawn(announce_hosting_record());
    crate::public_sites::wake_now();
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
    tier:            String,
    months:          u32,
    pay_with_egusd:  Option<bool>,
    state:           tauri::State<'_, crate::app::AppState>,
) -> Result<crate::chain_db::ActiveHostingPlan, EgoDesktopError> {
    if months == 0 || months > 24 {
        return Err(EgoDesktopError::InvalidInput("months must be 1–24".into()));
    }
    let (_, _, usd_per_month, _, _) = plan_options()
        .into_iter()
        .find(|(t, ..)| t == tier.trim())
        .ok_or_else(|| EgoDesktopError::InvalidInput(format!("Unknown tier: {}", tier)))?;

    let pay_egusd       = pay_with_egusd.unwrap_or(false);
    let uegoc_per_month = usd_to_uegoc(usd_per_month);
    let total_uegoc     = uegoc_per_month.saturating_mul(months as u64);
    // The plan has a dollar price, so in credits it is simply that price. No trip through
    // a coin rate, which means the bill cannot move between quoting it and paying it.
    let total_credits   = crate::chain_db::usd_to_credits(usd_per_month * months as f64);

    let mut ledger = Ledger::load();
    let owner = ledger.address.clone();
    if owner.is_empty() {
        return Err(EgoDesktopError::WalletError("Wallet not initialized".into()));
    }

    if pay_egusd {
        let have = crate::chain_db::credits_balance(&owner);
        if have < total_credits {
            return Err(EgoDesktopError::InvalidInput(format!(
                "Insufficient EGUSD: need ${:.2}, have ${:.2}",
                total_credits as f64 / 100.0,
                have as f64 / 100.0
            )));
        }
    } else {
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
    }

    let now   = chrono::Utc::now().timestamp();
    let nonce = crate::ledger::next_nonce_for(&ledger.address, ledger.nonce);
    let memo  = if pay_egusd {
        format!("credits_pay:{}:hosting:{}:{}", total_credits, tier.trim(), months)
    } else {
        format!("hosting_plan:{}:{}", tier.trim(), months)
    };
    let Some(kp) = state.get_keypair() else {
        return Err(EgoDesktopError::WalletError("Wallet not initialized".into()));
    };

    let mut pending_tx = crate::ledger::LedgerTx {
        from:                owner.clone(),
        to:                  HOSTING_FEE_SINK.to_string(),
        amount:              0,
        memo:                Some(memo.clone()),
        timestamp:           now,
        status:              "Pending".into(),
        block_height:        None,
        nonce,
        chain_id:            1,
        fee_uegoc:           if pay_egusd { 0 } else { total_uegoc },
        tx_type:             if pay_egusd { "credits_pay".into() } else { "hosting_plan".into() },
        signed_summary:      memo.clone(),
        ..crate::ledger::LedgerTx::default()
    };
    crate::ledger::seal_tx(&mut pending_tx, &kp, true);
    let tx_hash = pending_tx.hash.clone();

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
        paid_uegoc: if pay_egusd { 0 } else { total_uegoc },
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
pub fn public_sites_status() -> crate::public_sites::PublicStatus {
    crate::public_sites::status()
}

#[tauri::command]
pub fn public_sites_refresh() {
    crate::public_sites::wake_now();
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
pub fn open_in_browser(url: String) -> Result<(), EgoDesktopError> {
    let url = web_address(&url)?;
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("rundll32.exe").args(["url.dll,FileProtocolHandler", &url]).spawn();
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(&url).spawn();
    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
    Ok(())
}

fn web_address(raw: &str) -> Result<String, EgoDesktopError> {
    let parsed = reqwest::Url::parse(raw.trim())
        .map_err(|_| EgoDesktopError::InvalidInput("That is not a web address.".into()))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(EgoDesktopError::InvalidInput("Only http and https addresses can be opened.".into()));
    }
    Ok(parsed.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_db::HostingNodeRecord;

    fn record(kp: &ego_core::KeyPair, ts: i64, domains: &[&str]) -> HostingNodeRecord {
        let pk: [u8; 32] = kp.ed25519_public_key().as_bytes()[..32].try_into().unwrap();
        let mut r = HostingNodeRecord {
            node_id: crate::market_chain::address_of(&pk),
            endpoint: "http://57.1.2.3:47395".to_string(),
            sites: vec!["myshop-com".to_string()],
            domains: domains.iter().map(|d| d.to_string()).collect(),
            last_seen: ts,
            signature: String::new(),
            pubkey: String::new(),
            signature_v2: String::new(),
        };
        sign_hosting_record(&mut r, kp);
        r
    }

    #[test]
    fn the_signed_text_matches_what_the_oracle_checks() {
        let r = HostingNodeRecord {
            node_id: "egot1abc".into(),
            endpoint: "http://1.2.3.4:5".into(),
            sites: vec!["a".into(), "b".into()],
            domains: vec!["x.com".into(), "y.org".into()],
            last_seen: 7,
            signature: String::new(),
            pubkey: String::new(),
            signature_v2: String::new(),
        };
        assert_eq!(hosting_signing_bytes(&r), b"ego/hosting/v2\negot1abc\nhttp://1.2.3.4:5\n7\na,b\nx.com,y.org".to_vec());
    }

    #[test]
    fn only_the_node_itself_can_sign_its_domains() {
        let kp = ego_core::KeyPair::from_bytes(&[7; 32]).unwrap();
        let now = 1_800_000_000;
        let r = record(&kp, now, &["myshop.com"]);
        assert_eq!(verify_hosting_record(&r, now), Ok(()));
        assert!(!r.signature.is_empty(), "older nodes still get their v1 signature");

        let mut moved = r.clone();
        moved.domains = vec!["bank.com".into()];
        assert_eq!(verify_hosting_record(&moved, now), Err("sig"));

        let other = ego_core::KeyPair::from_bytes(&[8; 32]).unwrap();
        let mut stolen = record(&other, now, &["myshop.com"]);
        stolen.node_id = r.node_id.clone();
        assert_eq!(verify_hosting_record(&stolen, now), Err("node"));

        let mut legacy = r.clone();
        legacy.pubkey.clear();
        legacy.signature_v2.clear();
        assert!(verify_hosting_record(&legacy, now).is_err());

        assert_eq!(verify_hosting_record(&r, now + 3600), Err("time"));
    }

    #[test]
    fn custom_domains_are_cleaned_before_they_are_saved() {
        assert_eq!(normalize_custom_domain(" https://www.MyShop.com/about?x=1 "), "myshop.com");
        assert_eq!(normalize_custom_domain("myshop.com."), "myshop.com");
        assert_eq!(normalize_custom_domain("awww.com"), "awww.com");
        assert_eq!(normalize_custom_domain("shop.www.example.com"), "shop.www.example.com");
        assert!(valid_hosting_domain("myshop.com"));
        for bad in ["myshop", "my shop.com", "shöp.com", "-x.com", "a..b"] {
            assert!(!valid_hosting_domain(bad), "{bad}");
        }
    }
}
