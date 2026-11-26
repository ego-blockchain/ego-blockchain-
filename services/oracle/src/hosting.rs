use ed25519_dalek::{Signature, VerifyingKey};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::HostingNodeRecord;

pub const ONLINE_SECS: i64 = 900;
const CLOCK_SKEW_SECS: i64 = 600;
pub const MAX_RECORDS: usize = 50_000;
const MAX_SITES: usize = 256;
const MAX_DOMAINS: usize = 64;
const MAX_ENDPOINT_LEN: usize = 200;
pub const MAX_BINDINGS: usize = 100_000;
pub const NEW_BINDINGS_PER_IP_PER_DAY: u32 = 20;

pub fn signing_bytes(r: &HostingNodeRecord) -> Vec<u8> {
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

pub fn valid_domain(d: &str) -> bool {
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

fn valid_site(s: &str) -> bool {
    !s.is_empty() && s.len() <= 63 && !s.contains(',') && !s.contains('\n') && !s.contains('.')
}

pub fn verify(r: &HostingNodeRecord, now: i64) -> Result<(), &'static str> {
    if r.last_seen > now + CLOCK_SKEW_SECS || r.last_seen < now - CLOCK_SKEW_SECS {
        return Err("The record's time is off by more than ten minutes.");
    }
    if r.endpoint.is_empty() || r.endpoint.len() > MAX_ENDPOINT_LEN || r.endpoint.contains('\n') {
        return Err("The endpoint is missing or too long.");
    }
    if r.sites.len() > MAX_SITES || !r.sites.iter().all(|s| valid_site(s)) {
        return Err("A site name is not valid.");
    }
    if r.domains.len() > MAX_DOMAINS || !r.domains.iter().all(|d| valid_domain(d)) {
        return Err("A domain is not a valid lowercase domain name.");
    }
    let pk: [u8; 32] = hex::decode(&r.pubkey)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("The record has no public key. Update Ego Desktop.")?;
    let sig: [u8; 64] = hex::decode(&r.signature_v2)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("The record is not signed. Update Ego Desktop.")?;
    if crate::gateways::address_of(&pk) != r.node_id {
        return Err("The public key does not belong to this node.");
    }
    VerifyingKey::from_bytes(&pk)
        .map_err(|_| "The public key is not valid.")?
        .verify_strict(&signing_bytes(r), &Signature::from_bytes(&sig))
        .map_err(|_| "The signature does not match the record.")
}

pub fn registrable(name: &str) -> Option<&str> {
    psl::domain_str(name)
}

pub fn owner_of<'a>(bindings: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    bindings.get(registrable(name)?).map(String::as_str)
}

pub fn serves(record_domains: &[String], name: &str) -> bool {
    record_domains.iter().any(|d| d == name || name.strip_prefix("www.") == Some(d.as_str()))
}

pub fn cert_names(bindings: &HashMap<String, String>, domain: &str, signer: &str) -> Result<Vec<String>, &'static str> {
    if !valid_domain(domain) || domain.starts_with("www.") {
        return Err("Ask for the plain domain, like example.com; www is added for you.");
    }
    if owner_of(bindings, domain) != Some(signer) {
        return Err("This domain belongs to another Ego address, or nobody has claimed it yet.");
    }
    let www = format!("www.{domain}");
    Ok(if valid_domain(&www) { vec![domain.to_string(), www] } else { vec![domain.to_string()] })
}

pub struct Claimed {
    pub domains: Vec<String>,
    pub new_bindings: Vec<String>,
}

pub fn claim(bindings: &HashMap<String, String>, owner: &str, wanted: &[String], new_allowed: u32) -> Claimed {
    let mut owned_now: Option<usize> = None;
    let mut domains = Vec::new();
    let mut new_bindings: Vec<String> = Vec::new();
    for d in wanted {
        let Some(reg) = registrable(d) else { continue };
        match bindings.get(reg) {
            Some(o) if o == owner => domains.push(d.clone()),
            Some(_) => {}
            None => {
                if new_bindings.iter().any(|b| b == reg) {
                    domains.push(d.clone());
                } else if (new_bindings.len() as u32) < new_allowed
                    && *owned_now.get_or_insert_with(|| bindings.values().filter(|o| o.as_str() == owner).count()) + new_bindings.len() < MAX_DOMAINS
                    && bindings.len() + new_bindings.len() < MAX_BINDINGS
                {
                    new_bindings.push(reg.to_string());
                    domains.push(d.clone());
                }
            }
        }
    }
    Claimed { domains, new_bindings }
}

pub fn bindings_path(chain_path: &Path) -> PathBuf {
    std::env::var("ORACLE_HOSTING_DOMAINS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| chain_path.with_file_name("hosting-domains.json"))
}

pub fn load_bindings(path: &Path) -> HashMap<String, String> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_bindings(path: &Path, bindings: &HashMap<String, String>) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(bindings)?)?;
    std::fs::rename(&tmp, path)
}

pub fn prune_stale(records: &mut HashMap<String, HostingNodeRecord>, now: i64) {
    records.retain(|_, r| r.last_seen >= now - ONLINE_SECS);
}

pub fn allow_new_bindings(counts: &mut HashMap<String, (i64, u32)>, ip: &str, now: i64) -> u32 {
    let day = now / 86_400;
    counts.retain(|_, (d, _)| *d == day);
    let used = counts.get(ip).map(|(_, n)| *n).unwrap_or(0);
    NEW_BINDINGS_PER_IP_PER_DAY.saturating_sub(used)
}

pub fn spend_new_bindings(counts: &mut HashMap<String, (i64, u32)>, ip: &str, now: i64, n: u32) {
    if n == 0 {
        return;
    }
    let day = now / 86_400;
    let entry = counts.entry(ip.to_string()).or_insert((day, 0));
    entry.1 += n;
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed(key: &SigningKey, endpoint: &str, ts: i64, domains: &[&str]) -> HostingNodeRecord {
        let pk = key.verifying_key().to_bytes();
        let mut r = HostingNodeRecord {
            node_id: crate::gateways::address_of(&pk),
            endpoint: endpoint.to_string(),
            sites: vec!["mysite".to_string()],
            domains: domains.iter().map(|d| d.to_string()).collect(),
            last_seen: ts,
            pubkey: hex::encode(pk),
            signature_v2: String::new(),
            signature: String::new(),
        };
        r.signature_v2 = hex::encode(key.sign(&signing_bytes(&r)).to_bytes());
        r
    }

    #[test]
    fn the_signed_text_matches_what_ego_desktop_signs() {
        let r = HostingNodeRecord {
            node_id: "egot1abc".into(),
            endpoint: "http://1.2.3.4:5".into(),
            sites: vec!["a".into(), "b".into()],
            domains: vec!["x.com".into(), "y.org".into()],
            last_seen: 7,
            pubkey: String::new(),
            signature_v2: String::new(),
            signature: String::new(),
        };
        assert_eq!(signing_bytes(&r), b"ego/hosting/v2\negot1abc\nhttp://1.2.3.4:5\n7\na,b\nx.com,y.org".to_vec());
    }

    #[test]
    fn a_key_signed_by_ego_desktop_maps_to_the_same_address() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let pk = key.verifying_key().to_bytes();
        assert_eq!(crate::ed25519_pubkey_to_address(&pk).as_deref(), Some(crate::gateways::address_of(&pk).as_str()));
    }

    #[test]
    fn only_a_record_signed_by_the_node_itself_is_accepted() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let now = 1_800_000_000;
        let r = signed(&key, "http://57.1.2.3:47395", now, &["myshop.com"]);
        assert_eq!(verify(&r, now), Ok(()));

        let mut moved = r.clone();
        moved.domains = vec!["bank.com".to_string()];
        assert!(verify(&moved, now).is_err(), "changing the domains breaks the signature");

        let mut other = r.clone();
        other.node_id = crate::gateways::address_of(&[9; 32]);
        assert!(verify(&other, now).is_err(), "a key cannot sign for another node's name");

        let mut legacy = r.clone();
        legacy.pubkey.clear();
        legacy.signature_v2.clear();
        assert!(verify(&legacy, now).is_err(), "an unsigned record from an old app is refused");

        assert!(verify(&r, now + 3600).is_err(), "an old record cannot be replayed an hour later");
    }

    #[test]
    fn domains_must_be_plain_lowercase_names() {
        for good in ["myshop.com", "blog.example.co.uk", "a-b.io"] {
            assert!(valid_domain(good), "{good}");
        }
        for bad in ["", "net", "MyShop.com", "myshop.com.", "-a.com", "a..com", "a,b.com", "xn--\n.com"] {
            assert!(!valid_domain(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_first_owner_keeps_a_domain_and_its_subdomains() {
        let mut b: HashMap<String, String> = HashMap::new();
        let c = claim(&b, "alice", &["myshop.com".to_string(), "blog.myshop.com".to_string()], 20);
        assert_eq!(c.domains, vec!["myshop.com", "blog.myshop.com"]);
        assert_eq!(c.new_bindings, vec!["myshop.com"]);
        for nb in c.new_bindings {
            b.insert(nb, "alice".to_string());
        }

        let m = claim(&b, "mallory", &["myshop.com".to_string(), "www.myshop.com".to_string()], 20);
        assert!(m.domains.is_empty() && m.new_bindings.is_empty(), "nobody else can take it or a subdomain");

        let again = claim(&b, "alice", &["myshop.com".to_string()], 0);
        assert_eq!(again.domains, vec!["myshop.com"], "the owner keeps it without spending new claims");
        assert_eq!(owner_of(&b, "www.myshop.com"), Some("alice"));
    }

    #[test]
    fn only_the_owner_gets_a_certificate_and_it_covers_www() {
        let b = HashMap::from([("myshop.com".to_string(), "alice".to_string())]);
        assert_eq!(cert_names(&b, "myshop.com", "alice"), Ok(vec!["myshop.com".to_string(), "www.myshop.com".to_string()]));
        assert_eq!(cert_names(&b, "blog.myshop.com", "alice").unwrap()[1], "www.blog.myshop.com");
        assert!(cert_names(&b, "myshop.com", "mallory").is_err());
        assert!(cert_names(&b, "www.myshop.com", "alice").is_err());
        assert!(cert_names(&b, "unclaimed.org", "alice").is_err());
        let listed = vec!["myshop.com".to_string()];
        assert!(serves(&listed, "myshop.com") && serves(&listed, "www.myshop.com"));
        assert!(!serves(&listed, "blog.myshop.com") && !serves(&listed, "www.www.myshop.com"));
    }

    #[test]
    fn a_public_suffix_can_never_be_claimed() {
        let b: HashMap<String, String> = HashMap::new();
        let c = claim(&b, "mallory", &["co.uk".to_string(), "github.io".to_string()], 20);
        assert!(c.domains.is_empty(), "claiming co.uk or github.io would lock out everyone under it");
        assert_eq!(registrable("example.co.uk"), Some("example.co.uk"));
        assert_eq!(registrable("me.github.io"), Some("me.github.io"));
    }

    #[test]
    fn new_claims_are_limited_per_address_and_per_connection() {
        let b: HashMap<String, String> = HashMap::new();
        let wanted: Vec<String> = (0..30).map(|i| format!("site{i}.com")).collect();
        assert_eq!(claim(&b, "bob", &wanted, 5).new_bindings.len(), 5);

        let mut counts = HashMap::new();
        let now = 1_800_000_000;
        assert_eq!(allow_new_bindings(&mut counts, "1.2.3.4", now), NEW_BINDINGS_PER_IP_PER_DAY);
        spend_new_bindings(&mut counts, "1.2.3.4", now, NEW_BINDINGS_PER_IP_PER_DAY);
        assert_eq!(allow_new_bindings(&mut counts, "1.2.3.4", now), 0);
        assert_eq!(allow_new_bindings(&mut counts, "5.6.7.8", now), NEW_BINDINGS_PER_IP_PER_DAY);
        assert_eq!(allow_new_bindings(&mut counts, "1.2.3.4", now + 86_400), NEW_BINDINGS_PER_IP_PER_DAY);
    }

    #[test]
    fn bindings_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("ego-oracle-bindings-{}", std::process::id()));
        let path = dir.join("hosting-domains.json");
        let b = HashMap::from([("myshop.com".to_string(), "alice".to_string())]);
        save_bindings(&path, &b).unwrap();
        assert_eq!(load_bindings(&path), b);
        let _ = std::fs::remove_dir_all(dir);
    }
}
