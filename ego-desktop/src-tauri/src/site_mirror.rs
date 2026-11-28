use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;

pub const MAX_FILES: usize = 5_000;
pub const MAX_FILE_BYTES: u64 = 50 * 1024 * 1024;
pub const MAX_SITES_PER_OWNER: usize = 64;
const MAX_PATH: usize = 512;
const FETCH_PER_TICK: usize = 32;
const ASK_AGAIN_SECS: i64 = 600;
const PUSH_EVERY_SECS: i64 = 1_800;
const ANSWERS_PER_MINUTE: u32 = 120;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MirrorFile {
    pub path: String,
    pub cid: String,
    pub mime: String,
    pub size: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SiteManifest {
    pub owner: String,
    pub name: String,
    pub domain: String,
    pub files: Vec<MirrorFile>,
    pub updated_at: i64,
    pub pubkey: String,
    pub signature: String,
}

pub fn signing_bytes(m: &SiteManifest) -> Vec<u8> {
    let mut s = format!("ego/site-manifest/v1\n{}\n{}\n{}\n{}\n", m.owner, m.name, m.domain, m.updated_at);
    for f in &m.files {
        s.push_str(&format!("{}\t{}\t{}\t{}\n", f.path, f.cid, f.mime, f.size));
    }
    s.into_bytes()
}

fn clean_text(s: &str, max: usize) -> bool {
    s.len() <= max && !s.contains('\t') && !s.contains('\n')
}

pub fn well_formed(m: &SiteManifest) -> bool {
    crate::commands::hosting::valid_hosting_domain(&m.domain)
        && !m.name.is_empty()
        && m.name.len() <= 63
        && m.name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !m.files.is_empty()
        && m.files.len() <= MAX_FILES
        && m.files.iter().all(|f| {
            f.path.starts_with('/')
                && clean_text(&f.path, MAX_PATH)
                && !f.path.split('/').any(|seg| seg == "..")
                && f.cid.len() == 71
                && f.cid.starts_with("egocid1")
                && f.cid[7..].bytes().all(|b| b.is_ascii_hexdigit())
                && f.size <= MAX_FILE_BYTES
                && clean_text(&f.mime, 100)
        })
}

pub fn signed_by_owner(m: &SiteManifest) -> bool {
    crate::sharding::signed_by(&m.owner, &m.pubkey, &m.signature, &signing_bytes(m))
}

fn root() -> PathBuf {
    crate::ledger::data_dir().join("mirrors")
}

fn owner_dir(owner: &str) -> Option<PathBuf> {
    owner.bytes().all(|b| b.is_ascii_alphanumeric()).then(|| root().join(owner))
}

fn manifest_path(owner: &str, name: &str) -> Option<PathBuf> {
    Some(owner_dir(owner)?.join(format!("{name}.json")))
}

fn file_path(owner: &str, cid: &str) -> Option<PathBuf> {
    cid.bytes().all(|b| b.is_ascii_alphanumeric()).then_some(())?;
    Some(owner_dir(owner)?.join("files").join(cid))
}

fn load(owner: &str, name: &str) -> Option<SiteManifest> {
    serde_json::from_slice(&std::fs::read(manifest_path(owner, name)?).ok()?).ok()
}

fn owners() -> Vec<String> {
    std::fs::read_dir(root())
        .map(|it| it.flatten().filter(|e| e.path().is_dir()).filter_map(|e| e.file_name().into_string().ok()).collect())
        .unwrap_or_default()
}

fn manifests_of(owner: &str) -> Vec<SiteManifest> {
    let Some(dir) = owner_dir(owner) else { return Vec::new() };
    std::fs::read_dir(dir)
        .map(|it| {
            it.flatten()
                .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
                .filter_map(|e| serde_json::from_slice(&std::fs::read(e.path()).ok()?).ok())
                .collect()
        })
        .unwrap_or_default()
}

fn plan_bytes(owner: &str, now: i64) -> u64 {
    crate::chain_db::hosting_plan_on_chain(owner, now)
        .and_then(|p| crate::storage_pay::hosting_tier(&p.tier))
        .map(|(_, gb)| gb * 1_000_000_000)
        .unwrap_or(0)
}

fn kept_for(owner: &str, me: &str, now: i64) -> bool {
    plan_bytes(owner, now) > 0 && crate::chain_db::hosting_plan_hosts(owner).iter().any(|h| h == me)
}

pub fn fits(incoming: &SiteManifest, existing: &[SiteManifest], allowed_bytes: u64) -> bool {
    let others: Vec<&SiteManifest> = existing.iter().filter(|m| m.name != incoming.name).collect();
    if others.len() + 1 > MAX_SITES_PER_OWNER {
        return false;
    }
    let mut seen: HashSet<&str> = HashSet::new();
    let total: u64 = others
        .iter()
        .flat_map(|m| m.files.iter())
        .chain(incoming.files.iter())
        .filter(|f| seen.insert(f.cid.as_str()))
        .map(|f| f.size)
        .sum();
    total <= allowed_bytes
}

pub fn accept(m: SiteManifest) {
    let me = crate::ledger::Ledger::load().address;
    let now = chrono::Utc::now().timestamp();
    if me.is_empty() || m.owner == me || !well_formed(&m) || !signed_by_owner(&m) || !kept_for(&m.owner, &me, now) {
        return;
    }
    if load(&m.owner, &m.name).is_some_and(|old| old.updated_at >= m.updated_at) {
        return;
    }
    if !fits(&m, &manifests_of(&m.owner), plan_bytes(&m.owner, now)) {
        eprintln!("[Mirror] {} sent more site files than its hosting plan covers; not kept", m.owner);
        return;
    }
    let Some(path) = manifest_path(&m.owner, &m.name) else { return };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir.join("files"));
    }
    if let Ok(bytes) = serde_json::to_vec(&m) {
        if crate::utils::atomic_write(&path, &bytes).is_ok() {
            eprintln!("[Mirror] Keeping a copy of {} ({} files) for {}", m.domain, m.files.len(), m.owner);
        }
    }
}

fn wanted(owner: &str) -> HashSet<String> {
    manifests_of(owner).into_iter().flat_map(|m| m.files.into_iter().map(|f| f.cid)).collect()
}

pub fn store_file(cid: &str, data: &[u8]) -> bool {
    if data.len() as u64 > MAX_FILE_BYTES || crate::commands::hosting::cid_of(data) != cid {
        return false;
    }
    for owner in owners() {
        if !wanted(&owner).contains(cid) {
            continue;
        }
        let Some(path) = file_path(&owner, cid) else { continue };
        if path.exists() {
            return true;
        }
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        return crate::utils::atomic_write(&path, data).is_ok();
    }
    false
}

fn complete(m: &SiteManifest) -> bool {
    m.files.iter().all(|f| file_path(&m.owner, &f.cid).is_some_and(|p| p.exists()))
}

pub fn serving_map() -> HashMap<String, String> {
    let me = crate::ledger::Ledger::load().address;
    let now = chrono::Utc::now().timestamp();
    let mut out = HashMap::new();
    for owner in owners() {
        if !kept_for(&owner, &me, now) {
            continue;
        }
        for m in manifests_of(&owner).into_iter().filter(complete) {
            out.insert(m.domain.clone(), format!("mirror:{}:{}", m.owner, m.name));
        }
    }
    out
}

pub fn serving_domains() -> Vec<String> {
    let mut d: Vec<String> = serving_map().into_keys().collect();
    d.sort();
    d.truncate(64);
    d
}

pub fn lookup<'a>(m: &'a SiteManifest, url_path: &str) -> Option<&'a MirrorFile> {
    let decoded = crate::public_sites::percent_decode(url_path.split('?').next().unwrap_or(""))?;
    let mut p = format!("/{}", decoded.trim_start_matches('/'));
    if p.ends_with('/') {
        p.push_str("index.html");
    }
    let found = m.files.iter().find(|f| f.path == p);
    if found.is_some() {
        return found;
    }
    let last = p.rsplit('/').next().unwrap_or("");
    if last.contains('.') {
        return None;
    }
    m.files
        .iter()
        .find(|f| f.path == format!("{p}/index.html"))
        .or_else(|| m.files.iter().find(|f| f.path == "/index.html"))
}

pub fn read(site: &str, url_path: &str) -> Option<(Vec<u8>, &'static str)> {
    let mut parts = site.strip_prefix("mirror:")?.splitn(2, ':');
    let (owner, name) = (parts.next()?, parts.next()?);
    let m = load(owner, name)?;
    let f = lookup(&m, url_path)?;
    let data = std::fs::read(file_path(owner, &f.cid)?).ok()?;
    Some((data, crate::rpc::mime_from_path(std::path::Path::new(&f.path))))
}

fn asked() -> &'static Mutex<HashMap<String, i64>> {
    static M: std::sync::OnceLock<Mutex<HashMap<String, i64>>> = std::sync::OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
}

fn answered() -> &'static Mutex<HashMap<String, (i64, u32)>> {
    static M: std::sync::OnceLock<Mutex<HashMap<String, (i64, u32)>>> = std::sync::OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
}

fn pushed() -> &'static Mutex<HashMap<String, (i64, i64)>> {
    static M: std::sync::OnceLock<Mutex<HashMap<String, (i64, i64)>>> = std::sync::OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn may_answer(requester: &str, now: i64) -> bool {
    let mut map = answered().lock().unwrap_or_else(|e| e.into_inner());
    let minute = now / 60;
    map.retain(|_, (m, _)| *m == minute);
    let entry = map.entry(requester.to_string()).or_insert((minute, 0));
    entry.1 += 1;
    entry.1 <= ANSWERS_PER_MINUTE
}

pub fn own_file(owner: &str, cid: &str) -> Option<Vec<u8>> {
    for raw in crate::chain_db::list_hosted_sites_raw(owner) {
        let Some(name) = raw["name"].as_str() else { continue };
        let Some(files) = raw["files"].as_array() else { continue };
        let Some(path) = files.iter().find(|f| f["cid"].as_str() == Some(cid)).and_then(|f| f["path"].as_str()) else { continue };
        let disk = crate::commands::hosting::site_dir(owner, name).join(path.trim_start_matches('/'));
        let raw_bytes = std::fs::read(disk).ok()?;
        let key = raw["site_key_hex"].as_str().unwrap_or("");
        let data = crate::commands::hosting::decrypt_site_file(&raw_bytes, key)?;
        return (crate::commands::hosting::cid_of(&data) == cid).then_some(data);
    }
    None
}

pub fn held_file(cid: &str) -> Option<Vec<u8>> {
    for owner in owners() {
        let Some(path) = file_path(&owner, cid) else { continue };
        if let Ok(data) = std::fs::read(path) {
            return Some(data);
        }
    }
    None
}

pub fn own_manifests(owner: &str) -> Vec<SiteManifest> {
    let mut out = Vec::new();
    for raw in crate::chain_db::list_hosted_sites_raw(owner) {
        let Some(domain) = raw["custom_domain"].as_str().filter(|d| crate::commands::hosting::valid_hosting_domain(d)) else { continue };
        let site_name = raw["name"].as_str().unwrap_or("");
        if site_name.is_empty() || crate::python_host::is_python_site(&crate::commands::hosting::site_dir(owner, site_name)) {
            continue;
        }
        let files: Vec<MirrorFile> = raw["files"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|f| {
                Some(MirrorFile {
                    path: f["path"].as_str()?.to_string(),
                    cid: f["cid"].as_str()?.to_string(),
                    mime: f["mime_type"].as_str().unwrap_or("").to_string(),
                    size: f["size"].as_u64().unwrap_or(0),
                })
            })
            .collect();
        let mut m = SiteManifest {
            owner: owner.to_string(),
            name: raw["name"].as_str().unwrap_or("").to_string(),
            domain: domain.to_string(),
            files,
            updated_at: raw["updated_at"].as_i64().unwrap_or(0),
            pubkey: String::new(),
            signature: String::new(),
        };
        if !well_formed(&m) {
            continue;
        }
        let Some((pubkey, signature)) = crate::sharding::sign_as_node(&signing_bytes(&m)) else { continue };
        m.pubkey = pubkey;
        m.signature = signature;
        out.push(m);
    }
    out
}

fn endpoints_of(peers: &[crate::p2p::PeerEntry], addr: &str) -> Vec<String> {
    peers.iter().filter(|p| p.address == addr && !p.endpoint.is_empty()).map(|p| p.endpoint.clone()).collect()
}

async fn send_to(addr: &str, me: &str, eps: Vec<String>, msg: crate::p2p::P2PMessage) {
    if eps.is_empty() || crate::p2p::send_message_any(&eps, &msg).await.is_err() {
        crate::commands::messenger::deposit_in_relay_inbox(me, addr, &msg).await;
    }
}

pub async fn push_own_sites(owner: String) {
    let now = chrono::Utc::now().timestamp();
    let o = owner.clone();
    let Ok((manifests, hosts, peers)) = tokio::task::spawn_blocking(move || {
        (own_manifests(&o), crate::chain_db::hosting_plan_hosts(&o), crate::p2p::load_peer_cache())
    })
    .await
    else {
        return;
    };
    for m in manifests {
        for host in hosts.iter().filter(|h| **h != owner) {
            let key = format!("{host}\n{}", m.name);
            {
                let mut map = pushed().lock().unwrap_or_else(|e| e.into_inner());
                if map.get(&key).is_some_and(|(at, v)| *v == m.updated_at && now - at < PUSH_EVERY_SECS) {
                    continue;
                }
                map.insert(key, (now, m.updated_at));
            }
            let msg = crate::p2p::P2PMessage::SiteManifestPush { manifest: m.clone() };
            send_to(host, &owner, endpoints_of(&peers, host), msg).await;
        }
    }
}

pub async fn tick() {
    let Ok((me, todo, peers)) = tokio::task::spawn_blocking(|| {
        let me = crate::ledger::Ledger::load().address;
        let now = chrono::Utc::now().timestamp();
        let mut todo: Vec<(String, String, Vec<String>)> = Vec::new();
        if me.is_empty() {
            return (me, todo, Vec::new());
        }
        for owner in owners() {
            if !kept_for(&owner, &me, now) {
                if let Some(dir) = owner_dir(&owner) {
                    let _ = std::fs::remove_dir_all(dir);
                    eprintln!("[Mirror] No longer keeping {}'s sites: the plan ended or moved", owner);
                }
                continue;
            }
            let hosts: Vec<String> = crate::chain_db::hosting_plan_hosts(&owner).into_iter().filter(|h| *h != me).collect();
            for m in manifests_of(&owner) {
                for f in &m.files {
                    if todo.len() >= FETCH_PER_TICK {
                        break;
                    }
                    if file_path(&owner, &f.cid).is_some_and(|p| p.exists()) {
                        continue;
                    }
                    let mut map = asked().lock().unwrap_or_else(|e| e.into_inner());
                    if map.get(&f.cid).is_some_and(|at| now - at < ASK_AGAIN_SECS) {
                        continue;
                    }
                    map.insert(f.cid.clone(), now);
                    let mut from = vec![owner.clone()];
                    from.extend(hosts.iter().cloned());
                    todo.push((f.cid.clone(), owner.clone(), from));
                }
            }
        }
        (me, todo, crate::p2p::load_peer_cache())
    })
    .await
    else {
        return;
    };
    if todo.is_empty() {
        return;
    }
    let my_ep = crate::p2p::get_public_endpoint().await;
    for (cid, owner, from) in todo {
        for addr in from {
            let msg = crate::p2p::P2PMessage::SiteFileRequest {
                cid: cid.clone(),
                owner: owner.clone(),
                requester_addr: me.clone(),
                requester_endpoint: my_ep.clone(),
            };
            send_to(&addr, &me, endpoints_of(&peers, &addr), msg).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(files: &[(&str, &str, u64)]) -> SiteManifest {
        SiteManifest {
            owner: "egot1owner".into(),
            name: "shop".into(),
            domain: "example-shop.com".into(),
            files: files
                .iter()
                .map(|(p, c, s)| MirrorFile { path: p.to_string(), cid: c.to_string(), mime: "text/html".into(), size: *s })
                .collect(),
            updated_at: 10,
            ..SiteManifest::default()
        }
    }

    fn cid(n: u8) -> String {
        format!("egocid1{}", hex::encode([n; 32]))
    }

    #[test]
    fn only_a_clean_signed_manifest_is_kept() {
        let (a, b) = (cid(1), cid(2));
        let mut m = manifest(&[("/index.html", &a, 10), ("/app.js", &b, 20)]);
        assert!(well_formed(&m));
        m.files[1].path = "/../../etc/passwd".into();
        assert!(!well_formed(&m), "no path may climb out of the site");
        let mut m = manifest(&[("/index.html", "egocid1short", 10)]);
        assert!(!well_formed(&m));
        m.files[0].cid = a.clone();
        m.files[0].size = MAX_FILE_BYTES + 1;
        assert!(!well_formed(&m));
        let mut m = manifest(&[("/index.html", &a, 10)]);
        m.domain = "localhost".into();
        assert!(!well_formed(&m));

        let kp = ego_core::KeyPair::from_bytes(&[5; 32]).unwrap();
        let pk: [u8; 32] = kp.ed25519_public_key().as_bytes()[..32].try_into().unwrap();
        let mut m = manifest(&[("/index.html", &a, 10)]);
        m.owner = crate::market_chain::address_of(&pk);
        m.pubkey = hex::encode(pk);
        m.signature = hex::encode(kp.sign_ed25519(&signing_bytes(&m)).as_bytes());
        assert!(signed_by_owner(&m));
        let mut swapped = m.clone();
        swapped.files[0].cid = b.clone();
        assert!(!signed_by_owner(&swapped), "a copy holder cannot change what the owner published");
    }

    #[test]
    fn a_plan_covers_only_its_size() {
        let (a, b, c) = (cid(1), cid(2), cid(3));
        let one = manifest(&[("/index.html", &a, 600), ("/x.js", &b, 300)]);
        let mut two = manifest(&[("/index.html", &a, 600), ("/y.js", &c, 50)]);
        two.name = "blog".into();
        assert!(fits(&two, &[one.clone()], 1_000), "a file both sites share counts once");
        assert!(!fits(&two, &[one.clone()], 900));
        assert!(fits(&one, &[one.clone()], 900), "a new version replaces the old one");
    }

    #[test]
    fn paths_map_to_the_published_files() {
        let (a, b, c) = (cid(1), cid(2), cid(3));
        let m = manifest(&[("/index.html", &a, 1), ("/docs/index.html", &b, 1), ("/app.js", &c, 1)]);
        assert_eq!(lookup(&m, "/").map(|f| f.cid.as_str()), Some(a.as_str()));
        assert_eq!(lookup(&m, "/app.js?v=3").map(|f| f.cid.as_str()), Some(c.as_str()));
        assert_eq!(lookup(&m, "/docs/").map(|f| f.cid.as_str()), Some(b.as_str()));
        assert_eq!(lookup(&m, "/docs").map(|f| f.cid.as_str()), Some(b.as_str()));
        assert_eq!(lookup(&m, "/pricing").map(|f| f.cid.as_str()), Some(a.as_str()), "app routes fall back to the start page");
        assert!(lookup(&m, "/missing.png").is_none());
    }
}
