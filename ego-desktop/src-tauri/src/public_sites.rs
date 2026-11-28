use axum::{
    http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    Router,
};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

const RENEW_BEFORE_SECS: i64 = 30 * 86_400;
const REQUEST_AGAIN_SECS: i64 = 3_700;
const LOOP_EVERY: Duration = Duration::from_secs(600);
const ROUTER_LEASE_SECS: u32 = 7_200;
const MAX_IN_FLIGHT: usize = 64;
const EGO_NS_SUFFIX: &str = ".egoblockchain.com";
const ROUTER_NAME: &str = "Ego Desktop websites";

pub fn http_port() -> u16 {
    std::env::var("EGO_SITES_HTTP_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(47480)
}

pub fn https_port() -> u16 {
    std::env::var("EGO_SITES_HTTPS_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(47443)
}

fn bind_ip() -> std::net::IpAddr {
    std::env::var("EGO_SITES_BIND").ok().and_then(|v| v.parse().ok()).unwrap_or(std::net::IpAddr::from([0, 0, 0, 0]))
}

#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct DomainStatus {
    pub domain: String,
    pub nameservers: Option<bool>,
    pub certificate: String,
    pub certificate_expires: Option<i64>,
    pub certificate_error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct PublicStatus {
    pub serving: bool,
    pub serving_error: Option<String>,
    pub http_port: u16,
    pub https_port: u16,
    pub router: String,
    pub router_error: Option<String>,
    pub public_ip: Option<String>,
    pub local_ip: Option<String>,
    pub carrier_nat: bool,
    pub nameservers: Vec<String>,
    pub domains: Vec<DomainStatus>,
}

fn status_cell() -> &'static Mutex<PublicStatus> {
    static S: OnceLock<Mutex<PublicStatus>> = OnceLock::new();
    S.get_or_init(|| {
        Mutex::new(PublicStatus {
            http_port: http_port(),
            https_port: https_port(),
            router: "unknown".into(),
            nameservers: vec!["ns1.egoblockchain.com".into(), "ns2.egoblockchain.com".into()],
            ..Default::default()
        })
    })
}

fn update(f: impl FnOnce(&mut PublicStatus)) {
    f(&mut status_cell().lock().unwrap_or_else(|e| e.into_inner()));
}

fn update_domain(domain: &str, f: impl FnOnce(&mut DomainStatus)) {
    update(|s| {
        if let Some(d) = s.domains.iter_mut().find(|d| d.domain == domain) {
            f(d);
        }
    });
}

pub fn status() -> PublicStatus {
    status_cell().lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn sites() -> &'static RwLock<HashMap<String, String>> {
    static S: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();
    S.get_or_init(|| RwLock::new(HashMap::new()))
}

fn certs() -> &'static RwLock<HashMap<String, Arc<rustls::sign::CertifiedKey>>> {
    static C: OnceLock<RwLock<HashMap<String, Arc<rustls::sign::CertifiedKey>>>> = OnceLock::new();
    C.get_or_init(|| RwLock::new(HashMap::new()))
}

fn wake() -> &'static tokio::sync::Notify {
    static W: OnceLock<tokio::sync::Notify> = OnceLock::new();
    W.get_or_init(tokio::sync::Notify::new)
}

pub fn wake_now() {
    wake().notify_one();
}

fn in_flight() -> &'static Mutex<HashSet<String>> {
    static F: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    F.get_or_init(|| Mutex::new(HashSet::new()))
}

fn permits() -> &'static tokio::sync::Semaphore {
    static P: OnceLock<tokio::sync::Semaphore> = OnceLock::new();
    P.get_or_init(|| tokio::sync::Semaphore::new(MAX_IN_FLIGHT))
}

pub fn site_for_host(map: &HashMap<String, String>, host: &str) -> Option<String> {
    map.get(host).or_else(|| map.get(host.strip_prefix("www.")?)).cloned()
}

pub fn host_of(headers: &HeaderMap, uri: &Uri) -> Option<String> {
    let raw = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .or_else(|| uri.host())?;
    let name = match raw.rsplit_once(':') {
        Some((h, port)) if port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => raw,
    };
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    (!name.is_empty() && name.len() <= 253 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'))
        .then_some(name)
}

pub fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            out.push(u8::from_str_radix(s.get(i + 1..i + 3)?, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

pub fn site_path(base: &Path, rel: &str) -> Option<PathBuf> {
    let mut out = base.to_path_buf();
    for seg in rel.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." || seg.contains('\\') || seg.contains(':') || seg.contains('\0') {
            return None;
        }
        out.push(seg);
    }
    Some(out)
}

fn file_to_serve(base: &Path, url_path: &str) -> Option<PathBuf> {
    let decoded = percent_decode(url_path)?;
    let full = site_path(base, &decoded)?;
    if full.is_dir() {
        let index = full.join("index.html");
        return index.is_file().then_some(index);
    }
    if full.is_file() {
        return Some(full);
    }
    if full.extension().is_none() {
        let index = base.join("index.html");
        return index.is_file().then_some(index);
    }
    None
}

fn plain(status: StatusCode, text: &'static str) -> Response {
    (status, [(header::CONTENT_TYPE, "text/plain; charset=utf-8")], text).into_response()
}

async fn serve(method: Method, headers: HeaderMap, uri: Uri) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return plain(StatusCode::METHOD_NOT_ALLOWED, "Only GET and HEAD are served.");
    }
    let Ok(_permit) = permits().try_acquire() else {
        return plain(StatusCode::SERVICE_UNAVAILABLE, "This site is busy. Try again in a moment.");
    };
    let Some(host) = host_of(&headers, &uri) else {
        return plain(StatusCode::BAD_REQUEST, "Missing or invalid host name.");
    };
    let Some(site) = site_for_host(&sites().read().unwrap_or_else(|e| e.into_inner()), &host) else {
        return plain(StatusCode::NOT_FOUND, "No Ego site is published for this name on this computer.");
    };
    let path = uri.path().to_string();
    let range = headers.get(header::RANGE).and_then(|v| v.to_str().ok()).map(str::to_string);
    let served = tokio::task::spawn_blocking(move || {
        if site.starts_with("mirror:") {
            return crate::site_mirror::read(&site, &path).map(Ok);
        }
        let base = crate::rpc::resolve_site_base(&site)?;
        if crate::python_host::is_python_site(&base) {
            return Some(Err(()));
        }
        let file = file_to_serve(&base, &path)?;
        let data = crate::rpc::read_site_file(&file, &site).or_else(|| std::fs::read(&file).ok())?;
        Some(Ok((data, crate::rpc::mime_from_path(&file))))
    })
    .await
    .ok()
    .flatten();
    let mut resp = match served {
        Some(Ok((data, mime))) => crate::rpc::serve_ranged_bytes(data, mime, range.as_deref()),
        Some(Err(())) => plain(
            StatusCode::NOT_IMPLEMENTED,
            "This site runs Python, which Ego Desktop does not serve to the public internet yet.",
        ),
        None => plain(StatusCode::NOT_FOUND, "Not found."),
    };
    let h = resp.headers_mut();
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=60"));
    resp
}

async fn serve_http(method: Method, headers: HeaderMap, uri: Uri) -> Response {
    if let Some(host) = host_of(&headers, &uri) {
        let bare = host.strip_prefix("www.").unwrap_or(&host).to_string();
        if certs().read().unwrap_or_else(|e| e.into_inner()).contains_key(&bare) {
            let target = format!("https://{}{}", host, uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"));
            if let Ok(v) = HeaderValue::from_str(&target) {
                return (StatusCode::MOVED_PERMANENTLY, [(header::LOCATION, v)]).into_response();
            }
        }
    }
    serve(method, headers, uri).await
}

struct SiteCerts;

impl rustls::server::ResolvesServerCert for SiteCerts {
    fn resolve(&self, hello: rustls::server::ClientHello) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let name = hello.server_name()?.to_ascii_lowercase();
        let bare = name.strip_prefix("www.").unwrap_or(&name).to_string();
        certs().read().unwrap_or_else(|e| e.into_inner()).get(&bare).cloned()
    }
}

fn start_listeners() {
    static STARTED: AtomicBool = AtomicBool::new(false);
    if STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    let http_addr = SocketAddr::from((bind_ip(), http_port()));
    let https_addr = SocketAddr::from((bind_ip(), https_port()));
    for addr in [http_addr, https_addr] {
        if let Err(e) = std::net::TcpListener::bind(addr) {
            update(|s| s.serving_error = Some(format!("Port {} on this computer is in use: {e}", addr.port())));
            STARTED.store(false, Ordering::SeqCst);
            return;
        }
    }
    tokio::spawn(async move {
        let app = Router::new().fallback(serve_http);
        if let Err(e) = axum_server::bind(http_addr).serve(app.into_make_service()).await {
            eprintln!("[Sites] HTTP server stopped: {e}");
        }
    });
    tokio::spawn(async move {
        let mut cfg = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SiteCerts));
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(cfg));
        let app = Router::new().fallback(serve);
        if let Err(e) = axum_server::bind_rustls(https_addr, tls).serve(app.into_make_service()).await {
            eprintln!("[Sites] HTTPS server stopped: {e}");
        }
    });
    eprintln!("[Sites] Serving published sites on ports {} and {}", http_addr.port(), https_addr.port());
    update(|s| {
        s.serving = true;
        s.serving_error = None;
    });
}

async fn open_router() {
    let result: Result<(std::net::IpAddr, std::net::Ipv4Addr), String> = async {
        let router = crate::gateway::find_router().await?;
        let local_ip = crate::gateway::local_ipv4_toward(router.addr).await.ok_or("couldn't find this computer's local address")?;
        for (outside, inside) in [(80u16, http_port()), (443u16, https_port())] {
            router
                .add_port(igd_next::PortMappingProtocol::TCP, outside, SocketAddr::from((local_ip, inside)), ROUTER_LEASE_SECS, ROUTER_NAME)
                .await
                .map_err(|e| match e {
                    igd_next::AddPortError::PortInUse => format!("port {outside} on your router already goes to another device"),
                    other => format!("the router refused to open port {outside}: {other}"),
                })?;
        }
        let public = router.get_external_ip().await.map_err(|e| format!("the router didn't give its public address: {e}"))?;
        Ok((public, local_ip))
    }
    .await;
    match result {
        Ok((public, local)) => update(|s| {
            s.router = "open".into();
            s.router_error = None;
            s.local_ip = Some(local.to_string());
            s.public_ip = Some(public.to_string());
            s.carrier_nat = matches!(public, std::net::IpAddr::V4(ip) if !crate::gateway::is_public(&ip));
        }),
        Err(e) => update(|s| {
            s.router = "failed".into();
            s.router_error = Some(e);
        }),
    }
}

fn tls_dir(domain: &str) -> PathBuf {
    crate::ledger::base_data_dir().join("sites-tls").join(domain)
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn cert_info(cert_pem: &str) -> Option<(Vec<Vec<u8>>, i64, Vec<u8>)> {
    let chain = rustls_pemfile::certs(&mut cert_pem.as_bytes()).ok()?;
    let (_, leaf) = x509_parser::parse_x509_certificate(chain.first()?).ok()?;
    let not_after = leaf.validity().not_after.timestamp();
    let spki = leaf.public_key().raw.to_vec();
    Some((chain, not_after, spki))
}

fn certified_key(chain: Vec<Vec<u8>>, key_pem: &str) -> Option<Arc<rustls::sign::CertifiedKey>> {
    let key = rustls_pemfile::pkcs8_private_keys(&mut key_pem.as_bytes()).ok()?.into_iter().next()?;
    let signing = rustls::sign::any_supported_type(&rustls::PrivateKey(key)).ok()?;
    Some(Arc::new(rustls::sign::CertifiedKey::new(chain.into_iter().map(rustls::Certificate).collect(), signing)))
}

fn spki_of(key_pem: &str) -> Option<Vec<u8>> {
    rcgen::KeyPair::from_pem(key_pem).ok().map(|k| k.public_key_der())
}

fn install(domain: &str, cert_pem: &str, key_pem: &str) -> Result<i64, &'static str> {
    let (chain, not_after, cert_spki) = cert_info(cert_pem).ok_or("the certificate could not be read")?;
    if spki_of(key_pem).as_deref() != Some(cert_spki.as_slice()) {
        return Err("the certificate is for a different key");
    }
    let ck = certified_key(chain, key_pem).ok_or("the key could not be loaded")?;
    certs().write().unwrap_or_else(|e| e.into_inner()).insert(domain.to_string(), ck);
    Ok(not_after)
}

fn load_saved(domain: &str) -> Option<i64> {
    let dir = tls_dir(domain);
    let cert = std::fs::read_to_string(dir.join("cert.pem")).ok()?;
    let key = std::fs::read_to_string(dir.join("key.pem")).ok()?;
    install(domain, &cert, &key).ok()
}

fn new_request(domain: &str) -> Result<(String, Vec<u8>), String> {
    let names = vec![domain.to_string(), format!("www.{domain}")];
    let mut params = rcgen::CertificateParams::new(names);
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, domain);
    params.key_pair = Some(rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?);
    let cert = rcgen::Certificate::from_params(params).map_err(|e| e.to_string())?;
    let csr = cert.serialize_request_der().map_err(|e| e.to_string())?;
    Ok((cert.serialize_private_key_pem(), csr))
}

fn pending_request(domain: &str) -> Result<(String, Vec<u8>, i64), String> {
    let dir = tls_dir(domain);
    let key_path = dir.join("key.pending.pem");
    let csr_path = dir.join("request.pending.der");
    if let (Ok(key), Ok(csr), Ok(meta)) = (std::fs::read_to_string(&key_path), std::fs::read(&csr_path), std::fs::metadata(&csr_path)) {
        let at = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        return Ok((key, csr, at));
    }
    let (key, csr) = new_request(domain)?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    crate::utils::atomic_write(&key_path, key.as_bytes()).map_err(|e| e.to_string())?;
    crate::utils::atomic_write(&csr_path, &csr).map_err(|e| e.to_string())?;
    Ok((key, csr, 0))
}

pub fn cert_request_bytes(domain: &str, ts: i64, csr_hex: &str) -> Vec<u8> {
    format!("ego/cert/v1\n{domain}\n{ts}\n{csr_hex}").into_bytes()
}

async fn nameservers_point_here(client: &reqwest::Client, domain: &str) -> Option<bool> {
    let url = format!("https://dns.google/resolve?name={domain}&type=NS");
    let v: serde_json::Value = client.get(&url).header("Accept", "application/dns-json").send().await.ok()?.json().await.ok()?;
    let answers = v["Answer"].as_array().cloned().unwrap_or_default();
    Some(answers.iter().filter_map(|a| a["data"].as_str()).any(|d| d.trim_end_matches('.').to_ascii_lowercase().ends_with(EGO_NS_SUFFIX)))
}

async fn ensure_cert(domain: String) {
    let client = match reqwest::Client::builder().timeout(Duration::from_secs(15)).build() {
        Ok(c) => c,
        Err(_) => return,
    };
    let d = domain.clone();
    if let Some(exp) = tokio::task::spawn_blocking(move || load_saved(&d)).await.ok().flatten() {
        update_domain(&domain, |s| {
            s.certificate = "ready".into();
            s.certificate_expires = Some(exp);
            s.certificate_error = None;
        });
        if exp - now() > RENEW_BEFORE_SECS {
            let ns = nameservers_point_here(&client, &domain).await;
            update_domain(&domain, |s| s.nameservers = ns);
            return;
        }
    }
    let ns = nameservers_point_here(&client, &domain).await;
    update_domain(&domain, |s| s.nameservers = ns);
    if ns != Some(true) {
        return;
    }
    let d = domain.clone();
    let (key_pem, csr, requested_at) = match tokio::task::spawn_blocking(move || pending_request(&d)).await {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => {
            update_domain(&domain, |s| {
                s.certificate = "failed".into();
                s.certificate_error = Some(e);
            });
            return;
        }
        Err(_) => return,
    };
    let Some(kp) = crate::commands::hosting::hosting_keypair() else { return };
    let base = crate::p2p::ORACLE_RPC;
    if now() - requested_at > REQUEST_AGAIN_SECS {
        let ts = now();
        let csr_hex = hex::encode(&csr);
        let pubkey = hex::encode(&kp.ed25519_public_key().as_bytes()[..32]);
        let sig = hex::encode(kp.sign_ed25519(&cert_request_bytes(&domain, ts, &csr_hex)).as_bytes());
        let body = serde_json::json!({ "domain": domain, "csr": csr_hex, "pubkey": pubkey, "sig": sig, "ts": ts });
        match client.post(format!("{base}/cert/request")).json(&body).send().await {
            Ok(resp) if resp.status() == reqwest::StatusCode::FORBIDDEN || resp.status() == reqwest::StatusCode::BAD_REQUEST => {
                let reason = resp.json::<serde_json::Value>().await.ok().and_then(|v| v["error"].as_str().map(str::to_string));
                update_domain(&domain, |s| {
                    s.certificate = "failed".into();
                    s.certificate_error = reason.or(Some("the certificate service refused the request".into()));
                });
                return;
            }
            Ok(_) => {
                let path = tls_dir(&domain).join("request.pending.der");
                let _ = crate::utils::atomic_write(&path, &csr);
            }
            Err(e) => {
                update_domain(&domain, |s| s.certificate_error = Some(format!("could not reach the certificate service: {e}")));
                return;
            }
        }
    }
    update_domain(&domain, |s| {
        if s.certificate != "ready" {
            s.certificate = "requested".into();
        }
    });
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let Ok(resp) = client.get(format!("{base}/cert/status/{domain}")).send().await else { continue };
        let Ok(v) = resp.json::<serde_json::Value>().await else { continue };
        match v["status"].as_str() {
            Some("ready") => {
                let cert_pem = v["cert_pem"].as_str().unwrap_or_default().to_string();
                let (d, k, c) = (domain.clone(), key_pem.clone(), cert_pem.clone());
                let installed = tokio::task::spawn_blocking(move || -> Result<i64, &'static str> {
                    let exp = install(&d, &c, &k)?;
                    let dir = tls_dir(&d);
                    crate::utils::atomic_write(&dir.join("cert.pem"), c.as_bytes()).map_err(|_| "could not save the certificate")?;
                    crate::utils::atomic_write(&dir.join("key.pem"), k.as_bytes()).map_err(|_| "could not save the key")?;
                    let _ = std::fs::remove_file(dir.join("key.pending.pem"));
                    let _ = std::fs::remove_file(dir.join("request.pending.der"));
                    Ok(exp)
                })
                .await;
                match installed {
                    Ok(Ok(exp)) => {
                        eprintln!("[Sites] Certificate installed for {domain}");
                        update_domain(&domain, |s| {
                            s.certificate = "ready".into();
                            s.certificate_expires = Some(exp);
                            s.certificate_error = None;
                        });
                        return;
                    }
                    Ok(Err("the certificate is for a different key")) => continue,
                    Ok(Err(e)) => {
                        update_domain(&domain, |s| s.certificate_error = Some(e.to_string()));
                        return;
                    }
                    Err(_) => return,
                }
            }
            Some("failed") => {
                let reason = v["reason"].as_str().unwrap_or("the certificate could not be issued").to_string();
                update_domain(&domain, |s| {
                    if s.certificate != "ready" {
                        s.certificate = "failed".into();
                    }
                    s.certificate_error = Some(reason);
                });
                return;
            }
            _ => {}
        }
    }
}

fn published_domains() -> HashMap<String, String> {
    let owner = crate::ledger::Ledger::load().address;
    if owner.is_empty() {
        return HashMap::new();
    }
    let mut map = crate::site_mirror::serving_map();
    map.extend(crate::chain_db::list_hosted_sites_raw(&owner).into_iter().filter_map(|raw| {
        let domain = raw["custom_domain"].as_str()?.to_string();
        let name = raw["name"].as_str()?.to_string();
        crate::commands::hosting::valid_hosting_domain(&domain).then_some((domain, name))
    }));
    map
}

static LAST_MIRROR_ANNOUNCE: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
const MIRROR_ANNOUNCE_EVERY_SECS: i64 = 300;

async fn mirror_duties() {
    crate::site_mirror::tick().await;
    let me = tokio::task::spawn_blocking(|| crate::ledger::Ledger::load().address).await.unwrap_or_default();
    if !me.is_empty() {
        crate::site_mirror::push_own_sites(me).await;
    }
    let now = now();
    let last = LAST_MIRROR_ANNOUNCE.load(std::sync::atomic::Ordering::Relaxed);
    if now - last >= MIRROR_ANNOUNCE_EVERY_SECS {
        LAST_MIRROR_ANNOUNCE.store(now, std::sync::atomic::Ordering::Relaxed);
        let mirrors = tokio::task::spawn_blocking(crate::site_mirror::serving_domains).await.unwrap_or_default();
        if !mirrors.is_empty() {
            crate::commands::hosting::announce_hosting_record().await;
        }
    }
}

async fn tick() {
    if crate::chain_db::local_chain_height().saturating_add(1) >= crate::storage_pay::HOSTING_PLAN_FROM_HEIGHT {
        mirror_duties().await;
    }
    let map = tokio::task::spawn_blocking(published_domains).await.unwrap_or_default();
    *sites().write().unwrap_or_else(|e| e.into_inner()) = map.clone();
    update(|s| {
        let keep: Vec<DomainStatus> = map
            .keys()
            .map(|d| {
                s.domains.iter().find(|x| &x.domain == d).cloned().unwrap_or(DomainStatus {
                    domain: d.clone(),
                    certificate: "none".into(),
                    ..Default::default()
                })
            })
            .collect();
        s.domains = keep;
    });
    if map.is_empty() {
        return;
    }
    start_listeners();
    open_router().await;
    for domain in map.into_keys() {
        if in_flight().lock().unwrap_or_else(|e| e.into_inner()).insert(domain.clone()) {
            tokio::spawn(async move {
                ensure_cert(domain.clone()).await;
                in_flight().lock().unwrap_or_else(|e| e.into_inner()).remove(&domain);
            });
        }
    }
}

pub async fn run() {
    loop {
        tick().await;
        tokio::select! {
            _ = tokio::time::sleep(LOOP_EVERY) => {}
            _ = wake().notified() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_cannot_leave_the_site_folder() {
        let base = Path::new("/sites/alice/shop");
        assert_eq!(site_path(base, "/css/app.css"), Some(base.join("css").join("app.css")));
        assert_eq!(site_path(base, "/"), Some(base.to_path_buf()));
        for bad in ["/../secret", "/a/../../b", "/..", "/a\\..\\b", "/C:/Windows", "/a\0b"] {
            assert_eq!(site_path(base, bad), None, "{bad:?}");
        }
        assert_eq!(percent_decode("/my%20file.png").as_deref(), Some("/my file.png"));
        assert_eq!(percent_decode("/%2e%2e/secret").and_then(|p| site_path(base, &p)), None, "encoded dots are caught after decoding");
        assert_eq!(percent_decode("/bad%zz"), None);
    }

    #[test]
    fn a_host_maps_to_its_site_with_or_without_www() {
        let map = HashMap::from([("myshop.com".to_string(), "myshop-com".to_string())]);
        assert_eq!(site_for_host(&map, "myshop.com").as_deref(), Some("myshop-com"));
        assert_eq!(site_for_host(&map, "www.myshop.com").as_deref(), Some("myshop-com"));
        assert_eq!(site_for_host(&map, "evil.net"), None);

        let mut h = HeaderMap::new();
        h.insert(header::HOST, HeaderValue::from_static("WWW.MyShop.com:443"));
        assert_eq!(host_of(&h, &Uri::from_static("/")).as_deref(), Some("www.myshop.com"));
        h.insert(header::HOST, HeaderValue::from_static("bad host"));
        assert_eq!(host_of(&h, &Uri::from_static("/")), None);
        assert_eq!(host_of(&HeaderMap::new(), &Uri::from_static("https://myshop.com/x")).as_deref(), Some("myshop.com"), "HTTP/2 sends the name in the address, not a Host header");
    }

    #[test]
    fn missing_pages_fall_back_to_the_app_and_folders_to_their_index() {
        let dir = std::env::temp_dir().join(format!("ego-public-sites-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("docs")).unwrap();
        std::fs::write(dir.join("index.html"), "home").unwrap();
        std::fs::write(dir.join("docs").join("index.html"), "docs").unwrap();
        std::fs::write(dir.join("logo.png"), "png").unwrap();
        assert_eq!(file_to_serve(&dir, "/"), Some(dir.join("index.html")));
        assert_eq!(file_to_serve(&dir, "/docs/"), Some(dir.join("docs").join("index.html")));
        assert_eq!(file_to_serve(&dir, "/logo.png"), Some(dir.join("logo.png")));
        assert_eq!(file_to_serve(&dir, "/pricing"), Some(dir.join("index.html")), "single-page apps get their index for client routes");
        assert_eq!(file_to_serve(&dir, "/missing.png"), None);
        assert_eq!(file_to_serve(&dir, "/../Windows/win.ini"), None);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_certificate_is_only_installed_with_its_own_key() {
        let (key_pem, _csr) = new_request("example.com").unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["example.com".to_string(), "www.example.com".to_string()]);
        params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        params.key_pair = Some(rcgen::KeyPair::from_pem(&key_pem).unwrap());
        let cert_pem = rcgen::Certificate::from_params(params).unwrap().serialize_pem().unwrap();
        let exp = install("example.com", &cert_pem, &key_pem).expect("matching key installs");
        assert!(exp > now());
        assert!(certs().read().unwrap().contains_key("example.com"));

        let (other_key, _) = new_request("example.com").unwrap();
        assert_eq!(install("example.com", &cert_pem, &other_key), Err("the certificate is for a different key"));
    }

    #[tokio::test]
    async fn a_published_site_is_served_over_https_by_its_name() {
        std::env::set_var("EGO_SITES_BIND", "127.0.0.1");
        std::env::set_var("EGO_SITES_HTTP_PORT", "47981");
        std::env::set_var("EGO_SITES_HTTPS_PORT", "47944");
        let site_dir = crate::commands::hosting::hosting_base_dir().join("egot1tester").join("shop-site");
        std::fs::create_dir_all(site_dir.join("img")).unwrap();
        std::fs::write(site_dir.join("index.html"), "<h1>hello from ego</h1>").unwrap();
        std::fs::write(site_dir.join("img").join("a b.txt"), "spaced").unwrap();
        sites().write().unwrap().insert("shop.test".to_string(), "shop-site".to_string());

        let (key_pem, _) = new_request("shop.test").unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["shop.test".to_string(), "www.shop.test".to_string()]);
        params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        params.key_pair = Some(rcgen::KeyPair::from_pem(&key_pem).unwrap());
        let cert_pem = rcgen::Certificate::from_params(params).unwrap().serialize_pem().unwrap();
        install("shop.test", &cert_pem, &key_pem).unwrap();

        start_listeners();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(status().serving, "{:?}", status().serving_error);

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .resolve("shop.test", SocketAddr::from(([127, 0, 0, 1], 47944)))
            .resolve("www.shop.test", SocketAddr::from(([127, 0, 0, 1], 47944)))
            .resolve("other.test", SocketAddr::from(([127, 0, 0, 1], 47944)))
            .build()
            .unwrap();
        let home = client.get("https://shop.test:47944/").send().await.unwrap();
        assert_eq!(home.status(), 200);
        assert_eq!(home.headers()["x-content-type-options"], "nosniff");
        assert_eq!(home.text().await.unwrap(), "<h1>hello from ego</h1>");
        assert_eq!(client.get("https://www.shop.test:47944/img/a%20b.txt").send().await.unwrap().text().await.unwrap(), "spaced");
        assert_eq!(client.get("https://www.shop.test:47944/checkout").send().await.unwrap().text().await.unwrap(), "<h1>hello from ego</h1>");
        assert_eq!(client.post("https://shop.test:47944/").send().await.unwrap().status(), 405);
        assert!(client.get("https://other.test:47944/").send().await.is_err(), "a name with no certificate gets no TLS handshake");

        let http = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
        let moved = http.get("http://127.0.0.1:47981/about?x=1").header("host", "shop.test").send().await.unwrap();
        assert_eq!(moved.status(), 301);
        assert_eq!(moved.headers()["location"], "https://shop.test/about?x=1");
        let unknown = http.get("http://127.0.0.1:47981/").header("host", "nobody.test").send().await.unwrap();
        assert_eq!(unknown.status(), 404);
        let _ = std::fs::remove_dir_all(site_dir);
    }

    #[test]
    fn the_signed_request_matches_what_the_oracle_checks() {
        assert_eq!(cert_request_bytes("example.com", 7, "3082"), b"ego/cert/v1\nexample.com\n7\n3082".to_vec());
    }
}
