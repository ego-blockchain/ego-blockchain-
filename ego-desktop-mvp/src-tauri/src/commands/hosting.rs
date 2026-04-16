use crate::error::EgoDesktopError;
use crate::ledger::Ledger;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

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
}

#[derive(Debug, Clone, Deserialize)]
pub struct SiteFileInput {
    pub path: String,
    pub content_base64: String,
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
    let owner = Ledger::load().address;
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

    let content = base64::engine::general_purpose::STANDARD
        .decode(&file.content_base64)
        .map_err(|e| EgoDesktopError::InvalidInput(format!("Bad base64 for {}: {}", file.path, e)))?;

    let cid  = cid_of(&content);
    let rel  = file.path.trim_start_matches('/');
    let dest = dir.join(rel);
    if let Some(p) = dest.parent() {
        std::fs::create_dir_all(p)
            .map_err(|e| EgoDesktopError::FileSystemError(e.to_string()))?;
    }
    crate::utils::atomic_write(&dest, &content)
        .map_err(|e| EgoDesktopError::FileSystemError(e.to_string()))?;

    let size       = content.len() as u64;
    let now        = chrono::Utc::now().timestamp();
    let local_path = dest.to_string_lossy().to_string();

    let mut ledger = Ledger::load();
    if !ledger.stored_files.iter().any(|sf| sf.cid == cid) {
        ledger.stored_files.push(crate::ledger::StoredFile {
            cid:              cid.clone(),
            name:             format!("{}/{}", name, rel),
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
        .filter_map(|v| serde_json::from_value(v).ok())
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
    Ok(())
}

async fn announce_self_as_hosting_node(site_name: String, custom_domain: Option<String>) {
    let owner    = Ledger::load().address;
    let port     = rpc_port();
    let endpoint = format!("http://localhost:{}", port);

    let mut record = crate::chain_db::get_hosting_node(&owner)
        .unwrap_or_else(|| crate::chain_db::HostingNodeRecord {
            node_id:   owner.clone(),
            endpoint:  endpoint.clone(),
            sites:     vec![],
            domains:   vec![],
            last_seen: 0,
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

    crate::chain_db::upsert_hosting_node(&record);
    crate::p2p::gossip_hosting_node(&record);
}

#[tauri::command]
pub async fn hosting_heartbeat() {
    let owner = Ledger::load().address;
    if let Some(mut record) = crate::chain_db::get_hosting_node(&owner) {
        record.last_seen = chrono::Utc::now().timestamp();
        crate::chain_db::upsert_hosting_node(&record);
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
pub fn setup_eo_certificates() -> Result<String, crate::error::EgoDesktopError> {
    crate::tls::ensure_tls_certs()
        .map_err(|e| crate::error::EgoDesktopError::InvalidInput(e))?;
    crate::tls::install_ca_to_store()
        .map_err(|e| crate::error::EgoDesktopError::InvalidInput(e))?;
    Ok("Ego Local CA installed. .eo domains will work after browser restart.".into())
}
