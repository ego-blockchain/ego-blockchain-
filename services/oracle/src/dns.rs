use std::{collections::HashMap, sync::Arc};
use tokio::{net::UdpSocket, sync::RwLock};
use crate::{acme::ChallengeMap, HostingNodeRecord};

type HostingNodes = HashMap<String, HostingNodeRecord>;
type Owners = Arc<RwLock<HashMap<String, String>>>;

const QTYPE_A:   u16 = 1;
const QTYPE_TXT: u16 = 16;
const RCODE_OK:      u8 = 0;
const RCODE_REFUSED: u8 = 5;

pub async fn run_dns_server(
    relay_ip: [u8; 4],
    hosting_nodes: Arc<RwLock<HostingNodes>>,
    owners: Owners,
    challenges: ChallengeMap,
) {
    match UdpSocket::bind("0.0.0.0:53").await {
        Ok(sock) => {
            tracing::info!("[DNS] Listening on 0.0.0.0:53, answering only for Ego names and hosted domains");
            let sock = Arc::new(sock);
            loop {
                let mut buf = [0u8; 512];
                let Ok((len, src)) = sock.recv_from(&mut buf).await else { continue };
                let query      = buf[..len].to_vec();
                let sock2      = sock.clone();
                let nodes      = hosting_nodes.clone();
                let owners     = owners.clone();
                let challenges = challenges.clone();
                let ip         = relay_ip;
                tokio::spawn(async move {
                    if let Some(resp) = handle_dns_query(query, ip, nodes, owners, challenges).await {
                        let _ = sock2.send_to(&resp, src).await;
                    }
                });
            }
        }
        Err(e) => {
            tracing::warn!("[DNS] Cannot bind port 53: {}. Grant CAP_NET_BIND_SERVICE or run as root.", e);
        }
    }
}

async fn handle_dns_query(
    query: Vec<u8>,
    relay_ip: [u8; 4],
    hosting_nodes: Arc<RwLock<HostingNodes>>,
    owners: Owners,
    challenges: ChallengeMap,
) -> Option<Vec<u8>> {
    let (domain, qtype) = parse_query(&query)?;
    tracing::debug!("[DNS] query: {} (type {})", domain, qtype);

    if qtype == QTYPE_TXT {
        if let Some(txt) = challenges.read().await.get(&domain).cloned() {
            return Some(build_txt_response(&query, &txt));
        }
    }

    if is_ego_name(&domain) {
        return Some(if qtype == QTYPE_A { build_a_response(&query, relay_ip) } else { build_empty_response(&query, RCODE_OK) });
    }

    if crate::gateways::gateway_label(&domain).is_some() {
        if qtype == QTYPE_A {
            if let Some(ip) = crate::gateways::ip_for_name(&domain).await {
                return Some(build_a_response(&query, ip));
            }
        }
        return Some(build_empty_response(&query, RCODE_OK));
    }

    let Some(owner) = crate::hosting::owner_of(&*owners.read().await, &domain).map(str::to_string) else {
        return Some(build_empty_response(&query, RCODE_REFUSED));
    };
    if qtype == QTYPE_A {
        let now = chrono::Utc::now().timestamp();
        let ip = hosting_nodes.read().await.get(&owner).and_then(|n| {
            (n.last_seen >= now - crate::hosting::ONLINE_SECS && n.domains.iter().any(|d| d == &domain))
                .then(|| extract_ip(&n.endpoint))
                .flatten()
        });
        if let Some(ip) = ip {
            tracing::info!("[DNS] {} → {}", domain, owner);
            return Some(build_a_response(&query, ip));
        }
    }
    Some(build_empty_response(&query, RCODE_OK))
}

fn is_ego_name(domain: &str) -> bool {
    domain == "ego" || domain.ends_with(".ego") || domain == "eo" || domain.ends_with(".eo")
}

fn extract_ip(endpoint: &str) -> Option<[u8; 4]> {
    let host = endpoint
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()?
        .split(':')
        .next()?;
    let parts: Vec<u8> = host.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() == 4 { Some([parts[0], parts[1], parts[2], parts[3]]) } else { None }
}

fn parse_query(query: &[u8]) -> Option<(String, u16)> {
    if query.len() < 12 { return None; }
    if query[2] & 0x80 != 0 { return None; }
    let mut pos = 12usize;
    let mut parts = Vec::new();
    loop {
        if pos >= query.len() { return None; }
        let len = query[pos] as usize;
        if len == 0 { pos += 1; break; }
        if len & 0xC0 == 0xC0 { return None; }
        pos += 1;
        if pos + len > query.len() { return None; }
        parts.push(String::from_utf8_lossy(&query[pos..pos + len]).to_lowercase());
        pos += len;
    }
    if pos + 4 > query.len() { return None; }
    let qtype = u16::from_be_bytes([query[pos], query[pos + 1]]);
    Some((parts.join("."), qtype))
}

fn response_head(query: &[u8], answers: u16, rcode: u8) -> Vec<u8> {
    let q_end = question_end(query).unwrap_or(query.len());
    let authoritative = if rcode == RCODE_OK { 0x04 } else { 0x00 };
    let mut r = Vec::with_capacity(q_end + 16 * answers as usize);
    r.extend_from_slice(&query[0..2]);
    r.push(0x80 | authoritative | (query[2] & 0x01));
    r.push(rcode);
    r.extend_from_slice(&[0x00, 0x01]);
    r.extend_from_slice(&answers.to_be_bytes());
    r.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    r.extend_from_slice(&query[12..q_end]);
    r
}

fn build_empty_response(query: &[u8], rcode: u8) -> Vec<u8> {
    response_head(query, 0, rcode)
}

fn build_a_response(query: &[u8], ip: [u8; 4]) -> Vec<u8> {
    build_multi_a_response(query, &[ip])
}

fn build_multi_a_response(query: &[u8], ips: &[[u8; 4]]) -> Vec<u8> {
    let count = ips.len().min(8) as u16;
    let mut r = response_head(query, count, RCODE_OK);
    for ip in ips.iter().take(8) {
        r.extend_from_slice(&[0xC0, 0x0C]);
        r.extend_from_slice(&[0x00, 0x01]);
        r.extend_from_slice(&[0x00, 0x01]);
        r.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]);
        r.extend_from_slice(&[0x00, 0x04]);
        r.extend_from_slice(ip);
    }
    r
}

fn build_txt_response(query: &[u8], txt: &str) -> Vec<u8> {
    let txt_bytes = &txt.as_bytes()[..txt.len().min(255)];
    let rdlength  = (1 + txt_bytes.len()) as u16;
    let mut r = response_head(query, 1, RCODE_OK);
    r.extend_from_slice(&[0xC0, 0x0C]);
    r.extend_from_slice(&[0x00, 0x10]);
    r.extend_from_slice(&[0x00, 0x01]);
    r.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]);
    r.extend_from_slice(&rdlength.to_be_bytes());
    r.push(txt_bytes.len() as u8);
    r.extend_from_slice(txt_bytes);
    r
}

fn question_end(query: &[u8]) -> Option<usize> {
    let mut pos = 12usize;
    loop {
        if pos >= query.len() { return None; }
        let len = query[pos] as usize;
        if len == 0 { pos += 1; break; }
        if len & 0xC0 == 0xC0 { pos += 2; break; }
        pos += 1 + len;
    }
    if pos + 4 <= query.len() { Some(pos + 4) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0x00, 0x01]);
        q
    }

    fn node(id: &str, endpoint: &str, domains: &[&str], last_seen: i64) -> (String, HostingNodeRecord) {
        (id.to_string(), HostingNodeRecord {
            node_id: id.to_string(),
            endpoint: endpoint.to_string(),
            sites: Vec::new(),
            domains: domains.iter().map(|d| d.to_string()).collect(),
            last_seen,
            pubkey: String::new(),
            signature_v2: String::new(),
            signature: String::new(),
        })
    }

    struct World {
        nodes: HostingNodes,
        owners: HashMap<String, String>,
        challenges: HashMap<String, String>,
    }

    fn world() -> World {
        let now = chrono::Utc::now().timestamp();
        World {
            nodes: [
                node("alice", "http://57.1.2.3:47395", &["kosovacoin.net", "blog.kosovacoin.net"], now),
                node("mallory", "http://6.6.6.6:47395", &["kosovacoin.net", "old-site.org"], now),
                node("bob", "http://57.1.2.4:47395", &["old-site.org"], now - 10_000),
            ]
            .into_iter()
            .collect(),
            owners: HashMap::from([
                ("kosovacoin.net".to_string(), "alice".to_string()),
                ("old-site.org".to_string(), "bob".to_string()),
            ]),
            challenges: HashMap::new(),
        }
    }

    async fn ask(name: &str, qtype: u16, w: World) -> Vec<u8> {
        handle_dns_query(
            query(name, qtype),
            [9, 9, 9, 9],
            Arc::new(RwLock::new(w.nodes)),
            Arc::new(RwLock::new(w.owners)),
            Arc::new(RwLock::new(w.challenges)),
        )
        .await
        .expect("a reply")
    }

    fn rcode(r: &[u8]) -> u8 { r[3] & 0x0F }
    fn answers(r: &[u8]) -> u16 { u16::from_be_bytes([r[6], r[7]]) }
    fn authoritative(r: &[u8]) -> bool { r[2] & 0x04 != 0 }

    #[tokio::test]
    async fn a_domain_nobody_owns_on_ego_is_refused_without_asking_anyone_else() {
        let r = ask("example.org", QTYPE_A, world()).await;
        assert_eq!(rcode(&r), RCODE_REFUSED);
        assert_eq!(answers(&r), 0);
        assert!(!authoritative(&r));
        assert!(r.len() <= query("example.org", QTYPE_A).len(), "a refusal is never bigger than the question");
    }

    #[tokio::test]
    async fn a_domain_answers_only_with_its_owners_node() {
        let r = ask("kosovacoin.net", QTYPE_A, world()).await;
        assert_eq!(rcode(&r), RCODE_OK);
        assert!(authoritative(&r));
        assert_eq!(answers(&r), 1, "another node claiming the same domain is never answered");
        assert_eq!(&r[r.len() - 4..], &[57, 1, 2, 3]);
        let r = ask("blog.kosovacoin.net", QTYPE_A, world()).await;
        assert_eq!(&r[r.len() - 4..], &[57, 1, 2, 3]);
    }

    #[tokio::test]
    async fn an_owned_domain_whose_owner_is_offline_gets_an_empty_answer_not_a_loop() {
        let r = ask("old-site.org", QTYPE_A, world()).await;
        assert_eq!((rcode(&r), answers(&r)), (RCODE_OK, 0));
        assert!(authoritative(&r));
    }

    #[tokio::test]
    async fn other_record_types_and_unlisted_subdomains_of_an_owned_domain_get_an_empty_answer() {
        for (name, qtype) in [("kosovacoin.net", 28), ("kosovacoin.net", 257), ("www.kosovacoin.net", QTYPE_A), ("_acme-challenge.kosovacoin.net", QTYPE_TXT)] {
            let r = ask(name, qtype, world()).await;
            assert_eq!((rcode(&r), answers(&r)), (RCODE_OK, 0), "{name} type {qtype}");
        }
        let r = ask("notkosovacoin.net", QTYPE_A, world()).await;
        assert_eq!(rcode(&r), RCODE_REFUSED, "a name that only ends with the same letters is not covered");
    }

    #[tokio::test]
    async fn ego_names_answer_a_with_the_relay_and_nothing_else() {
        let r = ask("mysite.ego", QTYPE_A, world()).await;
        assert_eq!(answers(&r), 1);
        assert_eq!(&r[r.len() - 4..], &[9, 9, 9, 9]);
        let r = ask("mysite.ego", 28, world()).await;
        assert_eq!((rcode(&r), answers(&r)), (RCODE_OK, 0));
    }

    #[tokio::test]
    async fn an_acme_challenge_is_answered_even_for_a_domain_nobody_owns_yet() {
        let mut w = world();
        w.challenges.insert("_acme-challenge.new.example".to_string(), "token123".to_string());
        let r = ask("_acme-challenge.new.example", QTYPE_TXT, w).await;
        assert_eq!((rcode(&r), answers(&r)), (RCODE_OK, 1));
        assert!(r.ends_with(b"\x08token123"));
    }

    #[tokio::test]
    async fn an_unknown_gateway_name_gets_an_empty_answer() {
        let r = ask("nobody.gw.egoblockchain.com", QTYPE_A, world()).await;
        assert_eq!((rcode(&r), answers(&r)), (RCODE_OK, 0));
    }

    #[tokio::test]
    async fn replies_and_junk_are_ignored() {
        let mut reply = query("example.org", QTYPE_A);
        reply[2] |= 0x80;
        let w = world();
        let nodes = Arc::new(RwLock::new(w.nodes));
        let owners = Arc::new(RwLock::new(w.owners));
        let challenges: ChallengeMap = Arc::new(RwLock::new(HashMap::new()));
        assert!(handle_dns_query(reply, [0; 4], nodes.clone(), owners.clone(), challenges.clone()).await.is_none());
        assert!(handle_dns_query(vec![0; 5], [0; 4], nodes, owners, challenges).await.is_none());
    }
}
