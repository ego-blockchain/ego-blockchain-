use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{delete, post},
    Json, Router,
};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, RwLock},
};

// ── Config ─────────────────────────────────────────────────────────────────────

pub struct HostingConfig {
    pub data_dir:   PathBuf,
    pub api_key:    String,
    pub relay_domain: String,
}

impl HostingConfig {
    pub fn from_env() -> Self {
        let data_dir = std::env::var("DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./data"));
        let api_key = std::env::var("RELAY_API_KEY")
            .unwrap_or_else(|_| "changeme".to_string());
        let relay_domain = std::env::var("RELAY_DOMAIN")
            .unwrap_or_else(|_| "ego.egoblockchain.com".to_string());
        Self { data_dir, api_key, relay_domain }
    }

    pub fn sites_dir(&self) -> PathBuf {
        let d = self.data_dir.join("sites");
        let _ = std::fs::create_dir_all(&d);
        d
    }

    pub fn site_dir(&self, name: &str) -> PathBuf {
        let d = self.sites_dir().join(name);
        let _ = std::fs::create_dir_all(&d);
        d
    }

    pub fn registry_path(&self) -> PathBuf {
        self.data_dir.join("site_registry.json")
    }
}

// ── Registry ───────────────────────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct SiteRecord {
    pub owner:         String,
    pub deployed_at:   i64,
    pub updated_at:    i64,
    pub file_count:    usize,
    pub total_size:    u64,
    pub files:         Vec<SiteFileMeta>,
    pub custom_domain: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SiteFileMeta {
    pub path:      String,
    pub mime_type: String,
    pub size:      u64,
}

type Registry      = Arc<RwLock<HashMap<String, SiteRecord>>>;
type DomainMap     = Arc<RwLock<HashMap<String, String>>>;

pub fn load_registry(cfg: &HostingConfig) -> Registry {
    let map = if cfg.registry_path().exists() {
        std::fs::read_to_string(cfg.registry_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    } else {
        HashMap::new()
    };
    Arc::new(RwLock::new(map))
}

fn build_domain_map(registry: &Registry) -> DomainMap {
    let mut map = HashMap::new();
    if let Ok(reg) = registry.read() {
        for (name, record) in reg.iter() {
            if let Some(d) = &record.custom_domain {
                map.insert(d.to_lowercase(), name.clone());
            }
        }
    }
    Arc::new(RwLock::new(map))
}

fn save_registry(registry: &Registry, cfg: &HostingConfig) {
    if let Ok(guard) = registry.read() {
        if let Ok(json) = serde_json::to_string_pretty(&*guard) {
            let _ = std::fs::create_dir_all(&cfg.data_dir);
            let _ = std::fs::write(cfg.registry_path(), json);
        }
    }
}

// ── Shared state ───────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct HostingState {
    pub registry:       Registry,
    pub custom_domains: DomainMap,
    pub cfg:            Arc<HostingConfig>,
}

pub fn new_hosting_state(cfg: Arc<HostingConfig>) -> HostingState {
    let registry       = load_registry(&cfg);
    let custom_domains = build_domain_map(&registry);
    HostingState { registry, custom_domains, cfg }
}

// ── API router (mounted at /api/hosting) ───────────────────────────────────────

pub fn api_router(state: HostingState) -> Router {
    Router::new()
        .route("/deploy/begin",    post(api_deploy_begin))
        .route("/deploy/file",     post(api_deploy_file))
        .route("/deploy/finalize", post(api_deploy_finalize))
        .route("/undeploy/:name",  delete(api_undeploy))
        .route("/domain",          post(api_set_domain))
        .route("/domain/:name",    delete(api_remove_domain))
        .route("/sites",           axum::routing::get(api_list_sites))
        .with_state(state)
}

// ── Gateway router (catch-all, reads Host header) ──────────────────────────────

pub fn gateway_router(state: HostingState) -> Router {
    Router::new()
        .fallback(gateway_handler)
        .with_state(state)
}

// ── API handlers ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct DeployBeginReq {
    name:    String,
    owner:   String,
    api_key: String,
}

async fn api_deploy_begin(
    State(state): State<HostingState>,
    Json(req):    Json<DeployBeginReq>,
) -> StatusCode {
    if req.api_key != state.cfg.api_key { return StatusCode::UNAUTHORIZED; }
    let name = req.name.trim().to_lowercase();
    if !is_valid_name(&name) { return StatusCode::BAD_REQUEST; }

    if let Ok(reg) = state.registry.read() {
        if let Some(existing) = reg.get(&name) {
            if existing.owner != req.owner {
                return StatusCode::CONFLICT;
            }
        }
    }

    let dir = state.cfg.site_dir(&name);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::create_dir_all(&dir);
    StatusCode::OK
}

#[derive(Deserialize)]
struct DeployFileReq {
    name:           String,
    owner:          String,
    api_key:        String,
    path:           String,
    content_base64: String,
    mime_type:      String,
}

async fn api_deploy_file(
    State(state): State<HostingState>,
    Json(req):    Json<DeployFileReq>,
) -> StatusCode {
    if req.api_key != state.cfg.api_key { return StatusCode::UNAUTHORIZED; }
    let name = req.name.trim().to_lowercase();
    let content = match base64::engine::general_purpose::STANDARD.decode(&req.content_base64) {
        Ok(b)  => b,
        Err(_) => return StatusCode::BAD_REQUEST,
    };
    let rel  = req.path.trim_start_matches('/');
    let dest = state.cfg.site_dir(&name).join(rel);
    if let Some(p) = dest.parent() {
        let _ = std::fs::create_dir_all(p);
    }
    match std::fs::write(&dest, &content) {
        Ok(_)  => StatusCode::CREATED,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[derive(Deserialize)]
struct DeployFinalizeReq {
    name:    String,
    owner:   String,
    api_key: String,
    files:   Vec<SiteFileMeta>,
}

#[derive(Serialize)]
struct DeployFinalizeResp {
    url: String,
}

async fn api_deploy_finalize(
    State(state): State<HostingState>,
    Json(req):    Json<DeployFinalizeReq>,
) -> impl IntoResponse {
    if req.api_key != state.cfg.api_key {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"unauthorized"}))).into_response();
    }
    let name = req.name.trim().to_lowercase();
    let now  = chrono::Utc::now().timestamp();
    let total_size: u64 = req.files.iter().map(|f| f.size).sum();

    let deployed_at = state.registry.read().ok()
        .and_then(|r| r.get(&name).map(|s| s.deployed_at))
        .unwrap_or(now);

    let existing_domain = state.registry.read().ok()
        .and_then(|r| r.get(&name).and_then(|s| s.custom_domain.clone()));

    let record = SiteRecord {
        owner:         req.owner.clone(),
        deployed_at,
        updated_at:    now,
        file_count:    req.files.len(),
        total_size,
        files:         req.files,
        custom_domain: existing_domain,
    };

    if let Ok(mut reg) = state.registry.write() {
        reg.insert(name.clone(), record);
    }
    save_registry(&state.registry, &state.cfg);

    let url = format!("http://{}.eo", name); // HTTPS if TLS configured
    tracing::info!("[Hosting] Deployed: {} (owner: {})", name, req.owner);

    (StatusCode::OK, Json(DeployFinalizeResp { url })).into_response()
}

async fn api_undeploy(
    Path(name):   Path<String>,
    State(state): State<HostingState>,
    headers:      HeaderMap,
) -> StatusCode {
    let api_key = headers.get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim_start_matches("Bearer ");
    if api_key != state.cfg.api_key { return StatusCode::UNAUTHORIZED; }

    let name = name.trim().to_lowercase();
    let _ = std::fs::remove_dir_all(state.cfg.site_dir(&name));
    if let Ok(mut reg) = state.registry.write() {
        reg.remove(&name);
    }
    save_registry(&state.registry, &state.cfg);
    StatusCode::NO_CONTENT
}

async fn api_list_sites(State(state): State<HostingState>) -> impl IntoResponse {
    let map = state.registry.read().map(|r| r.clone()).unwrap_or_default();
    Json(map)
}

#[derive(Deserialize)]
struct SetDomainReq {
    name:    String,
    owner:   String,
    api_key: String,
    domain:  String,
}

async fn api_set_domain(
    State(state): State<HostingState>,
    Json(req):    Json<SetDomainReq>,
) -> StatusCode {
    if req.api_key != state.cfg.api_key { return StatusCode::UNAUTHORIZED; }
    let name   = req.name.trim().to_lowercase();
    let domain = req.domain.trim().to_lowercase();
    if domain.is_empty() { return StatusCode::BAD_REQUEST; }

    let owner_ok = state.registry.read()
        .ok()
        .and_then(|r| r.get(&name).map(|s| s.owner == req.owner))
        .unwrap_or(false);
    if !owner_ok { return StatusCode::FORBIDDEN; }

    if let Ok(mut reg) = state.registry.write() {
        if let Some(record) = reg.get_mut(&name) {
            if let Some(old) = record.custom_domain.take() {
                if let Ok(mut dm) = state.custom_domains.write() { dm.remove(&old); }
            }
            record.custom_domain = Some(domain.clone());
        } else {
            return StatusCode::NOT_FOUND;
        }
    }
    if let Ok(mut dm) = state.custom_domains.write() {
        dm.insert(domain, name);
    }
    save_registry(&state.registry, &state.cfg);
    tracing::info!("[Hosting] Custom domain set: {} → {}", req.domain, req.name);
    StatusCode::OK
}

async fn api_remove_domain(
    Path(name):   Path<String>,
    State(state): State<HostingState>,
    headers:      HeaderMap,
) -> StatusCode {
    let api_key = headers.get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim_start_matches("Bearer ");
    if api_key != state.cfg.api_key { return StatusCode::UNAUTHORIZED; }

    let name = name.trim().to_lowercase();
    if let Ok(mut reg) = state.registry.write() {
        if let Some(record) = reg.get_mut(&name) {
            if let Some(old) = record.custom_domain.take() {
                if let Ok(mut dm) = state.custom_domains.write() { dm.remove(&old); }
            }
        }
    }
    save_registry(&state.registry, &state.cfg);
    StatusCode::NO_CONTENT
}

// ── Gateway handler ────────────────────────────────────────────────────────────

async fn gateway_handler(
    State(state): State<HostingState>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let host = headers.get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let host_no_port = host.split(':').next().unwrap_or("");

    let name = state.custom_domains.read().ok()
        .and_then(|dm| dm.get(host_no_port).cloned())
        .unwrap_or_else(|| extract_site_name(host_no_port, &state.cfg.relay_domain));

    if name.is_empty() {
        return (StatusCode::NOT_FOUND, "Unknown host").into_response();
    }

    let reg = state.registry.read().map(|r| r.contains_key(&name)).unwrap_or(false);
    if !reg {
        return (StatusCode::NOT_FOUND, format!("Site '{}' not found on Ego Network", name)).into_response();
    }

    let base = state.cfg.site_dir(&name);
    let path = uri.path().trim_start_matches('/');

    if path.is_empty() {
        let index = base.join("index.html");
        if index.exists() { return serve_file(&index); }
        if let Ok(mut rd) = std::fs::read_dir(&base) {
            if let Some(Ok(e)) = rd.next() { return serve_file(&e.path()); }
        }
        return (StatusCode::NOT_FOUND, "No index.html found").into_response();
    }

    let full = base.join(path);
    if !full.starts_with(&base) {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }
    if full.exists() {
        return serve_file(&full);
    }
    // SPA fallback
    let index = base.join("index.html");
    if index.exists() { return serve_file(&index); }
    (StatusCode::NOT_FOUND, "Not Found").into_response()
}

fn extract_site_name(host: &str, relay_domain: &str) -> String {
    // Primary:  ascasq.ego  → "ascasq"
    // With domain: ascasq.ego.someserver.com → "ascasq"
    // Legacy: ascasq.eo → "ascasq"
    let primary = format!(".{}", relay_domain);
    if let Some(n) = host.strip_suffix(&primary) {
        return n.strip_prefix("www.").unwrap_or(n).to_string();
    }
    let with_domain = format!(".{}.{}", relay_domain, relay_domain);
    if let Some(n) = host.strip_suffix(&with_domain) {
        return n.strip_prefix("www.").unwrap_or(n).to_string();
    }
    if let Some(n) = host.strip_suffix(".eo") {
        return n.strip_prefix("www.").unwrap_or(n).to_string();
    }
    String::new()
}

fn serve_file(path: &std::path::Path) -> Response {
    match std::fs::read(path) {
        Ok(bytes) => {
            let mime = mime_for(path);
            (StatusCode::OK, [(header::CONTENT_TYPE, mime)], bytes).into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, "File not found").into_response(),
    }
}

fn mime_for(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" | "htm" => "text/html; charset=utf-8",
        "css"          => "text/css; charset=utf-8",
        "js" | "mjs"   => "application/javascript; charset=utf-8",
        "json"         => "application/json",
        "png"          => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif"          => "image/gif",
        "svg"          => "image/svg+xml",
        "ico"          => "image/x-icon",
        "webp"         => "image/webp",
        "woff"         => "font/woff",
        "woff2"        => "font/woff2",
        "ttf"          => "font/ttf",
        "wasm"         => "application/wasm",
        "txt"          => "text/plain; charset=utf-8",
        "xml"          => "application/xml",
        "pdf"          => "application/pdf",
        _              => "application/octet-stream",
    }
}

fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.chars().all(|c| c.is_alphanumeric() || c == '-')
}
