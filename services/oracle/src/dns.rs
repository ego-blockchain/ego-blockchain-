use std::{collections::HashMap, sync::Arc};
use tokio::{net::UdpSocket, sync::RwLock};
use crate::{acme::ChallengeMap, HostingNodeRecord};

type HostingNodes = HashMap<String, HostingNodeRecord>;

const QTYPE_A:   u16 = 1;
const QTYPE_TXT: u16 = 16;

pub async fn run_dns_server(
    relay_ip: [u8; 4],
    upstream: String,
    hosting_nodes: Arc<RwLock<HostingNodes>>,
    challenges: ChallengeMap,
) {
    match UdpSocket::bind("0.0.0.0:53").await {
        Ok(sock) => {
            tracing::info!("[DNS] Listening on 0.0.0.0:53 (upstream: {})", upstream);
            let sock = Arc::new(sock);
            loop {
                let mut buf = [0u8; 512];
                let Ok((len, src)) = sock.recv_from(&mut buf).await else { continue };
                let query      = buf[..len].to_vec();
                let sock2      = sock.clone();
                let up2        = upstream.clone();
                let nodes      = hosting_nodes.clone();
                let challenges = challenges.clone();
                let ip         = relay_ip;
                tokio::spawn(async move {
                    if let Some(resp) = handle_dns_query(query, ip, &up2, nodes, challenges).await {
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
    upstream: &str,
    hosting_nodes: Arc<RwLock<HostingNodes>>,
    challenges: ChallengeMap,
) -> Option<Vec<u8>> {
    let (domain, qtype) = parse_query(&query)?;
    tracing::debug!("[DNS] query: {} (type {})", domain, qtype);

    if qtype == QTYPE_TXT {
        if let Some(txt) = challenges.read().await.get(&domain).cloned() {
            return Some(build_txt_response(&query, &txt));
        }
        return forward_upstream(&query, upstream).await;
    }

    if domain == "ego" || domain.ends_with(".ego") || domain == "eo" || domain.ends_with(".eo") {
        return Some(build_a_response(&query, relay_ip));
    }

    let ips = resolve_hosting(&domain, &hosting_nodes).await;
    if !ips.is_empty() {
        tracing::info!("[DNS] {} → {} node(s)", domain, ips.len());
        return Some(build_multi_a_response(&query, &ips));
    }

    forward_upstream(&query, upstream).await
}

async fn resolve_hosting(domain: &str, hosting_nodes: &Arc<RwLock<HostingNodes>>) -> Vec<[u8; 4]> {
    let now = chrono::Utc::now().timestamp();
    let nodes = hosting_nodes.read().await;
    let mut ips = Vec::new();
    for node in nodes.values() {
        if node.last_seen < now - 900 { continue; }
        let serves = node.domains.iter().any(|d| d == domain)
            || node.sites.iter().any(|s| s == domain);
        if serves {
            if let Some(ip) = extract_ip(&node.endpoint) {
                ips.push(ip);
            }
        }
    }
    ips
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
    if pos + 2 > query.len() { return None; }
    let qtype = u16::from_be_bytes([query[pos], query[pos + 1]]);
    Some((parts.join("."), qtype))
}

fn build_a_response(query: &[u8], ip: [u8; 4]) -> Vec<u8> {
    build_multi_a_response(query, &[ip])
}

fn build_multi_a_response(query: &[u8], ips: &[[u8; 4]]) -> Vec<u8> {
    let q_end = question_end(query).unwrap_or(query.len());
    let count = ips.len().min(8) as u16;
    let mut r = Vec::new();
    r.extend_from_slice(&query[0..2]);
    r.extend_from_slice(&[0x81, 0x80]);
    r.extend_from_slice(&[0x00, 0x01]);
    r.extend_from_slice(&count.to_be_bytes());
    r.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    r.extend_from_slice(&query[12..q_end]);
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
    let q_end     = question_end(query).unwrap_or(query.len());
    let txt_bytes = txt.as_bytes();
    let rdlength  = (1 + txt_bytes.len()) as u16;
    let mut r = Vec::new();
    r.extend_from_slice(&query[0..2]);
    r.extend_from_slice(&[0x81, 0x80]);
    r.extend_from_slice(&[0x00, 0x01]);
    r.extend_from_slice(&[0x00, 0x01]);
    r.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    r.extend_from_slice(&query[12..q_end]);
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

async fn forward_upstream(query: &[u8], upstream: &str) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    sock.send_to(query, upstream).await.ok()?;
    let mut buf = [0u8; 512];
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        sock.recv_from(&mut buf),
    )
    .await
    .ok()?
    .ok()?;
    Some(buf[..result.0].to_vec())
}
