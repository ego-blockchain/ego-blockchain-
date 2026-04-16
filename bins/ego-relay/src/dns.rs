use std::sync::Arc;
use tokio::net::UdpSocket;

pub async fn run_dns_server(relay_ip: [u8; 4], upstream: &str) {
    let upstream = upstream.to_string();
    match UdpSocket::bind("0.0.0.0:53").await {
        Ok(sock) => {
            tracing::info!("[DNS] Ego authoritative resolver on 0.0.0.0:53 (upstream: {})", upstream);
            let sock = Arc::new(sock);
            loop {
                let mut buf = [0u8; 512];
                let Ok((len, src)) = sock.recv_from(&mut buf).await else { continue };
                let query = buf[..len].to_vec();
                let sock2 = sock.clone();
                let up2   = upstream.clone();
                tokio::spawn(async move {
                    if let Some(resp) = handle_dns_query(query, relay_ip, &up2).await {
                        let _ = sock2.send_to(&resp, src).await;
                    }
                });
            }
        }
        Err(e) => {
            tracing::warn!("[DNS] Could not bind port 53 ({}). Run as root or grant CAP_NET_BIND_SERVICE.", e);
        }
    }
}

async fn handle_dns_query(query: Vec<u8>, relay_ip: [u8; 4], upstream: &str) -> Option<Vec<u8>> {
    let domain = parse_query_domain(&query)?;
    tracing::debug!("[DNS] query: {}", domain);

    if domain == "ego" || domain.ends_with(".ego") {
        return Some(build_a_response(&query, relay_ip));
    }

    if let Some(ips) = resolve_from_network(&domain).await {
        if !ips.is_empty() {
            tracing::info!("[DNS] {} → {} node(s) from Ego network", domain, ips.len());
            return Some(build_multi_a_response(&query, &ips));
        }
    }

    forward_to_upstream(&query, upstream).await
}

async fn resolve_from_network(domain: &str) -> Option<Vec<[u8; 4]>> {
    let known_nodes = crate::chain::get_known_ego_nodes();
    if known_nodes.is_empty() {
        return None;
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .ok()?;

    for node_url in &known_nodes {
        let url = format!("{}/hosting/nodes/{}", node_url.trim_end_matches('/'), domain);
        let Ok(resp) = client.get(&url).send().await else { continue };
        let Ok(json) = resp.json::<serde_json::Value>().await else { continue };
        let nodes = json["nodes"].as_array()?;
        if nodes.is_empty() { continue; }

        let mut ips: Vec<[u8; 4]> = Vec::new();
        for node in nodes {
            let endpoint = node["endpoint"].as_str().unwrap_or("");
            if let Some(ip) = extract_ip(endpoint) {
                ips.push(ip);
            }
        }
        if !ips.is_empty() {
            return Some(ips);
        }
    }
    None
}

fn extract_ip(endpoint: &str) -> Option<[u8; 4]> {
    let host = endpoint
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()?
        .split(':')
        .next()?;

    let parts: Vec<u8> = host.split('.')
        .filter_map(|p| p.parse().ok())
        .collect();
    if parts.len() == 4 {
        Some([parts[0], parts[1], parts[2], parts[3]])
    } else {
        None
    }
}

fn parse_query_domain(query: &[u8]) -> Option<String> {
    if query.len() < 12 { return None; }
    let mut pos = 12usize;
    let mut parts = Vec::new();
    loop {
        if pos >= query.len() { return None; }
        let len = query[pos] as usize;
        if len == 0 { break; }
        if len & 0xC0 == 0xC0 { return None; }
        pos += 1;
        if pos + len > query.len() { return None; }
        parts.push(String::from_utf8_lossy(&query[pos..pos + len]).to_lowercase());
        pos += len;
    }
    Some(parts.join("."))
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
        r.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]);
        r.extend_from_slice(&[0x00, 0x04]);
        r.extend_from_slice(ip);
    }
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

async fn forward_to_upstream(query: &[u8], upstream: &str) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    sock.send_to(query, upstream).await.ok()?;
    let mut buf = [0u8; 512];
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        sock.recv_from(&mut buf),
    ).await.ok()?.ok()?;
    Some(buf[..result.0].to_vec())
}
