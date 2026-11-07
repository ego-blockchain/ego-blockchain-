use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const LEASE_SECS: u32 = 3600;
pub const TCP: u8 = 6;
pub const UDP: u8 = 17;
const PCP_PORT: u16 = 5351;
const PCP_VERSION: u8 = 2;
const PCP_MAP: u8 = 1;
const PCP_TRIES: usize = 3;
const SOAP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REPLY: usize = 64 * 1024;
const FIREWALL_SERVICE: &str = "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1";

#[derive(Debug, Clone, PartialEq)]
struct Pinhole {
    target: SocketAddr,
    local: Option<IpAddr>,
    path: String,
    client: Ipv6Addr,
    protocol: u8,
    id: String,
}

static PINHOLES: Mutex<Vec<Pinhole>> = Mutex::new(Vec::new());
static PCP_NONCES: Mutex<Vec<(u8, [u8; 12])>> = Mutex::new(Vec::new());

pub fn pcp_map_request(client: Ipv6Addr, nonce: [u8; 12], protocol: u8, port: u16, lifetime: u32) -> [u8; 60] {
    let mut out = [0u8; 60];
    out[0] = PCP_VERSION;
    out[1] = PCP_MAP;
    out[4..8].copy_from_slice(&lifetime.to_be_bytes());
    out[8..24].copy_from_slice(&client.octets());
    out[24..36].copy_from_slice(&nonce);
    out[36] = protocol;
    out[40..42].copy_from_slice(&port.to_be_bytes());
    out[42..44].copy_from_slice(&port.to_be_bytes());
    out
}

pub fn pcp_map_granted(response: &[u8], nonce: &[u8; 12], protocol: u8, port: u16) -> Option<u32> {
    if response.len() < 60 || response[0] != PCP_VERSION || response[1] != (0x80 | PCP_MAP) || response[3] != 0 {
        return None;
    }
    if &response[24..36] != nonce || response[36] != protocol || response[40..42] != port.to_be_bytes() {
        return None;
    }
    Some(u32::from_be_bytes(response[4..8].try_into().ok()?))
}

pub fn firewall_control_url(description: &str, router: SocketAddr) -> Option<String> {
    let at = description.find(FIREWALL_SERVICE)?;
    let block_end = description[at..].find("</service>").map(|e| at + e).unwrap_or(description.len());
    let open = description[at..block_end].find("<controlURL>")? + at + "<controlURL>".len();
    let close = description[open..block_end].find("</controlURL>")? + open;
    let path = description[open..close].trim();
    if path.starts_with("http://") || path.starts_with("https://") {
        return Some(path.to_string());
    }
    let base = tag_value(description, "URLBase")
        .map(|b| b.trim_end_matches('/').to_string())
        .unwrap_or_else(|| format!("http://{router}"));
    Some(if path.starts_with('/') { format!("{base}{path}") } else { format!("{base}/{path}") })
}

pub fn split_http_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, after) = v6.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if after.is_empty() => 80,
            None => return None,
        };
        (h.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().ok()?),
            None => (authority.to_string(), 80),
        }
    };
    (!host.is_empty()).then_some((host, port, path))
}

pub fn tag_value(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].trim().to_string())
}

fn soap_envelope(action: &str, args: &[(&str, String)]) -> String {
    let fields: String = args.iter().map(|(k, v)| format!("<{k}>{v}</{k}>")).collect();
    format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{action} xmlns:u=\"{FIREWALL_SERVICE}\">{fields}</u:{action}></s:Body></s:Envelope>"
    )
}

pub fn add_pinhole_body(client: Ipv6Addr, port: u16, protocol: u8, lease: u32) -> String {
    soap_envelope(
        "AddPinhole",
        &[
            ("RemoteHost", String::new()),
            ("RemotePort", "0".into()),
            ("InternalClient", client.to_string()),
            ("InternalPort", port.to_string()),
            ("Protocol", protocol.to_string()),
            ("LeaseTime", lease.to_string()),
        ],
    )
}

pub fn update_pinhole_body(id: &str, lease: u32) -> String {
    soap_envelope("UpdatePinhole", &[("UniqueID", id.to_string()), ("NewLeaseTime", lease.to_string())])
}

pub fn delete_pinhole_body(id: &str) -> String {
    soap_envelope("DeletePinhole", &[("UniqueID", id.to_string())])
}

pub fn soap_request(target: SocketAddr, path: &str, action: &str, body: &str) -> String {
    let host = match target {
        SocketAddr::V4(a) => a.to_string(),
        SocketAddr::V6(a) => format!("[{}]:{}", a.ip(), a.port()),
    };
    format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nSOAPAction: \"{FIREWALL_SERVICE}#{action}\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

pub fn http_response(raw: &str) -> Option<(u16, String)> {
    let (head, body) = raw.split_once("\r\n\r\n")?;
    let status: u16 = head.lines().next()?.split_whitespace().nth(1)?.parse().ok()?;
    let chunked = head.lines().any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    });
    Some((status, if chunked { dechunk(body) } else { body.to_string() }))
}

fn dechunk(body: &str) -> String {
    let mut out = String::new();
    let mut rest = body;
    while let Some((size_line, after)) = rest.split_once("\r\n") {
        let Ok(size) = usize::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16) else { break };
        if size == 0 || after.len() < size {
            break;
        }
        out.push_str(&after[..size]);
        rest = after[size..].strip_prefix("\r\n").unwrap_or(&after[size..]);
    }
    out
}

pub fn parse_proc_ipv6_route(text: &str) -> Option<(Ipv6Addr, String)> {
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 || f[0] != "00000000000000000000000000000000" || f[1] != "00" {
            continue;
        }
        let hop = u128::from_str_radix(f[4], 16).ok()?;
        if hop == 0 {
            continue;
        }
        return Some((Ipv6Addr::from(hop), f[9].to_string()));
    }
    None
}

pub fn parse_route_print(text: &str) -> Option<(Ipv6Addr, u32)> {
    let mut best: Option<(u32, Ipv6Addr, u32)> = None;
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 || f[2] != "::/0" {
            continue;
        }
        let (Ok(index), Ok(metric), Ok(hop)) = (f[0].parse::<u32>(), f[1].parse::<u32>(), f[3].parse::<Ipv6Addr>()) else { continue };
        if best.map(|(m, _, _)| metric < m).unwrap_or(true) {
            best = Some((metric, hop, index));
        }
    }
    best.map(|(_, hop, index)| (hop, index))
}

pub fn parse_route_get(text: &str) -> Option<(Ipv6Addr, String)> {
    let gateway = text.lines().find_map(|l| l.trim().strip_prefix("gateway:").map(str::trim))?;
    let (addr, zone) = match gateway.split_once('%') {
        Some((a, z)) => (a, Some(z.to_string())),
        None => (gateway, None),
    };
    let interface = zone.or_else(|| text.lines().find_map(|l| l.trim().strip_prefix("interface:").map(|s| s.trim().to_string())))?;
    Some((addr.parse().ok()?, interface))
}

#[cfg(unix)]
fn index_of(interface: &str) -> u32 {
    std::ffi::CString::new(interface).map(|n| unsafe { libc::if_nametoindex(n.as_ptr()) }).unwrap_or(0)
}

#[cfg(target_os = "linux")]
fn default_router() -> Option<SocketAddrV6> {
    let text = std::fs::read_to_string("/proc/net/ipv6_route").ok()?;
    let (hop, interface) = parse_proc_ipv6_route(&text)?;
    Some(SocketAddrV6::new(hop, PCP_PORT, 0, index_of(&interface)))
}

#[cfg(target_os = "macos")]
fn default_router() -> Option<SocketAddrV6> {
    let out = std::process::Command::new("route").args(["-n", "get", "-inet6", "default"]).output().ok()?;
    let (hop, interface) = parse_route_get(&String::from_utf8_lossy(&out.stdout))?;
    Some(SocketAddrV6::new(hop, PCP_PORT, 0, index_of(&interface)))
}

#[cfg(windows)]
fn default_router() -> Option<SocketAddrV6> {
    use std::os::windows::process::CommandExt;
    let out = std::process::Command::new("route").args(["print", "-6", "::/0"]).creation_flags(0x08000000).output().ok()?;
    let (hop, index) = parse_route_print(&String::from_utf8_lossy(&out.stdout))?;
    Some(SocketAddrV6::new(hop, PCP_PORT, 0, index))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn default_router() -> Option<SocketAddrV6> {
    None
}

fn nonce_for(protocol: u8) -> [u8; 12] {
    let mut guard = PCP_NONCES.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, n)) = guard.iter().find(|(p, _)| *p == protocol) {
        return *n;
    }
    let n: [u8; 12] = rand::random();
    guard.push((protocol, n));
    n
}

async fn pcp_map(router: SocketAddrV6, client: Ipv6Addr, protocol: u8, port: u16, lifetime: u32) -> Result<u32, String> {
    let socket = tokio::net::UdpSocket::bind(SocketAddrV6::new(client, 0, 0, 0)).await.map_err(|e| e.to_string())?;
    let nonce = nonce_for(protocol);
    let request = pcp_map_request(client, nonce, protocol, port, lifetime);
    let mut buf = [0u8; 1100];
    for attempt in 0..PCP_TRIES {
        socket.send_to(&request, router).await.map_err(|e| e.to_string())?;
        let wait = Duration::from_secs(1 << attempt);
        if let Ok(Ok((n, from))) = tokio::time::timeout(wait, socket.recv_from(&mut buf)).await {
            if from.ip() != IpAddr::V6(*router.ip()) {
                continue;
            }
            if let Some(granted) = pcp_map_granted(&buf[..n], &nonce, protocol, port) {
                return Ok(granted);
            }
            if n >= 4 && buf[3] != 0 {
                return Err(format!("the router refused the PCP request (result {})", buf[3]));
            }
        }
    }
    Err("no PCP answer from the router".into())
}

async fn soap_to(target: SocketAddr, local: Option<IpAddr>, path: &str, action: &str, body: String) -> Result<String, String> {
    let exchange = async {
        let socket = if target.is_ipv6() { tokio::net::TcpSocket::new_v6() } else { tokio::net::TcpSocket::new_v4() }
            .map_err(|e| e.to_string())?;
        if let Some(ip) = local {
            socket.bind(SocketAddr::new(ip, 0)).map_err(|e| e.to_string())?;
        }
        let mut stream = socket.connect(target).await.map_err(|e| e.to_string())?;
        stream.write_all(soap_request(target, path, action, &body).as_bytes()).await.map_err(|e| e.to_string())?;
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = stream.read(&mut buf).await.map_err(|e| e.to_string())?;
            if n == 0 || raw.len() > MAX_REPLY {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
        }
        Ok::<String, String>(String::from_utf8_lossy(&raw).into_owned())
    };
    let raw = tokio::time::timeout(SOAP_TIMEOUT, exchange).await.map_err(|_| format!("{action} timed out"))??;
    let (status, text) = http_response(&raw).ok_or_else(|| format!("{action}: unreadable answer"))?;
    if (200..300).contains(&status) {
        Ok(text)
    } else {
        Err(tag_value(&text, "errorDescription").unwrap_or_else(|| format!("{action} failed ({status})")))
    }
}

async fn upnp_pinholes(router: SocketAddr, root_url: &str, v6_router: Option<SocketAddrV6>, client_v6: Ipv6Addr, port: u16) -> Result<(), String> {
    let http = reqwest::Client::builder().timeout(SOAP_TIMEOUT).build().map_err(|e| e.to_string())?;
    let description_url = if root_url.starts_with("http") { root_url.to_string() } else { format!("http://{router}{root_url}") };
    let description = http.get(&description_url).send().await.map_err(|e| e.to_string())?.text().await.map_err(|e| e.to_string())?;
    let control = firewall_control_url(&description, router).ok_or("the router has no IPv6 firewall control")?;
    let (host, control_port, path) = split_http_url(&control).ok_or("the router gave an unusable control address")?;
    let mut targets: Vec<(SocketAddr, Option<IpAddr>)> = Vec::new();
    if let Some(v6) = v6_router {
        targets.push((SocketAddr::V6(SocketAddrV6::new(*v6.ip(), control_port, 0, v6.scope_id())), Some(IpAddr::V6(client_v6))));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        targets.push((SocketAddr::new(ip, control_port), None));
    }
    for protocol in [TCP, UDP] {
        let existing = PINHOLES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|p| p.path == path && p.client == client_v6 && p.protocol == protocol)
            .cloned();
        if let Some(hole) = existing {
            if soap_to(hole.target, hole.local, &hole.path, "UpdatePinhole", update_pinhole_body(&hole.id, LEASE_SECS)).await.is_ok() {
                continue;
            }
            PINHOLES.lock().unwrap_or_else(|e| e.into_inner()).retain(|p| p != &hole);
        }
        let mut last = String::from("no way to reach the router");
        let mut added = false;
        for (target, local) in &targets {
            match soap_to(*target, *local, &path, "AddPinhole", add_pinhole_body(client_v6, port, protocol, LEASE_SECS)).await {
                Ok(reply) => {
                    if let Some(id) = tag_value(&reply, "UniqueID") {
                        PINHOLES.lock().unwrap_or_else(|e| e.into_inner()).push(Pinhole {
                            target: *target,
                            local: *local,
                            path: path.clone(),
                            client: client_v6,
                            protocol,
                            id,
                        });
                        added = true;
                        break;
                    }
                    last = "the router answered without a pinhole id".into();
                }
                Err(e) => last = e,
            }
        }
        if !added && protocol == TCP {
            return Err(last);
        }
    }
    Ok(())
}

pub async fn open(router: Option<(SocketAddr, String)>, client_v6: Ipv6Addr, port: u16) -> Result<&'static str, String> {
    let v6_router = tokio::task::spawn_blocking(default_router).await.ok().flatten();
    let mut problems = Vec::new();
    if let Some((addr, root_url)) = router {
        match upnp_pinholes(addr, &root_url, v6_router, client_v6, port).await {
            Ok(()) => return Ok("UPnP"),
            Err(e) => problems.push(format!("UPnP: {e}")),
        }
    }
    let Some(pcp_router) = v6_router else {
        problems.push("PCP: no IPv6 router found".into());
        return Err(problems.join("; "));
    };
    match pcp_map(pcp_router, client_v6, TCP, port, LEASE_SECS).await {
        Ok(_) => {
            let _ = pcp_map(pcp_router, client_v6, UDP, port, LEASE_SECS).await;
            Ok("PCP")
        }
        Err(e) => {
            problems.push(format!("PCP: {e}"));
            Err(problems.join("; "))
        }
    }
}

pub async fn close(client_v6: Option<Ipv6Addr>, port: u16) {
    let holes: Vec<Pinhole> = std::mem::take(&mut *PINHOLES.lock().unwrap_or_else(|e| e.into_inner()));
    for hole in holes {
        let _ = soap_to(hole.target, hole.local, &hole.path, "DeletePinhole", delete_pinhole_body(&hole.id)).await;
    }
    let known: Vec<u8> = PCP_NONCES.lock().unwrap_or_else(|e| e.into_inner()).iter().map(|(p, _)| *p).collect();
    if let (Some(client), false) = (client_v6, known.is_empty()) {
        if let Some(router) = tokio::task::spawn_blocking(default_router).await.ok().flatten() {
            for protocol in known {
                let _ = pcp_map(router, client, protocol, port, 0).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me() -> Ipv6Addr {
        "2001:56a:7d8e:d100:8887:919c:b5e8:944".parse().unwrap()
    }

    #[test]
    fn a_pcp_map_request_has_the_rfc_6887_layout() {
        let nonce = [7u8; 12];
        let r = pcp_map_request(me(), nonce, TCP, 47398, 3600);
        assert_eq!(r.len(), 60);
        assert_eq!(&r[..4], &[2, 1, 0, 0]);
        assert_eq!(&r[4..8], &3600u32.to_be_bytes());
        assert_eq!(&r[8..24], &me().octets());
        assert_eq!(&r[24..36], &nonce);
        assert_eq!(r[36], 6);
        assert_eq!(&r[37..40], &[0, 0, 0]);
        assert_eq!(&r[40..42], &47398u16.to_be_bytes());
        assert_eq!(&r[42..44], &47398u16.to_be_bytes());
        assert!(r[44..60].iter().all(|b| *b == 0), "no preferred outside address");
    }

    #[test]
    fn only_a_successful_answer_to_our_own_request_counts() {
        let nonce = [9u8; 12];
        let mut answer = pcp_map_request(me(), nonce, TCP, 47398, 1800);
        answer[1] = 0x81;
        assert_eq!(pcp_map_granted(&answer, &nonce, TCP, 47398), Some(1800));
        assert_eq!(pcp_map_granted(&answer, &[1u8; 12], TCP, 47398), None, "someone else's nonce");
        assert_eq!(pcp_map_granted(&answer, &nonce, UDP, 47398), None);
        assert_eq!(pcp_map_granted(&answer, &nonce, TCP, 47399), None);
        let mut refused = answer;
        refused[3] = 2;
        assert_eq!(pcp_map_granted(&refused, &nonce, TCP, 47398), None);
        let mut request = answer;
        request[1] = 0x01;
        assert_eq!(pcp_map_granted(&request, &nonce, TCP, 47398), None, "our own request echoed back");
        assert_eq!(pcp_map_granted(&answer[..40], &nonce, TCP, 47398), None);
    }

    #[test]
    fn the_ipv6_firewall_control_is_found_in_the_router_description() {
        let router: SocketAddr = "192.168.1.254:49000".parse().unwrap();
        let fritz = "<root><device><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType><controlURL>/igd2upnp/control/WANIPConn1</controlURL></service><service><serviceType>urn:schemas-upnp-org:service:WANIPv6FirewallControl:1</serviceType><serviceId>urn:upnp-org:serviceId:WANIPv6Firewall1</serviceId><controlURL>/igd2upnp/control/WANIPv6Firewall1</controlURL></service></serviceList></device></root>";
        assert_eq!(firewall_control_url(fritz, router).as_deref(), Some("http://192.168.1.254:49000/igd2upnp/control/WANIPv6Firewall1"));
        let relative = "<root><URLBase>http://10.0.0.1:5000/</URLBase><service><serviceType>urn:schemas-upnp-org:service:WANIPv6FirewallControl:1</serviceType><controlURL>ctl/IP6FCtl</controlURL></service></root>";
        assert_eq!(firewall_control_url(relative, router).as_deref(), Some("http://10.0.0.1:5000/ctl/IP6FCtl"));
        let v1_only = "<root><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl/IPConn</controlURL></service></root>";
        assert_eq!(firewall_control_url(v1_only, router), None);
        let next_block = "<root><service><serviceType>urn:schemas-upnp-org:service:WANIPv6FirewallControl:1</serviceType></service><service><controlURL>/wrong</controlURL></service></root>";
        assert_eq!(firewall_control_url(next_block, router), None, "a control URL from another service is not used");
    }

    #[test]
    fn control_addresses_split_into_host_port_and_path() {
        assert_eq!(split_http_url("http://192.168.1.254:52569/ctl/IP6FCtl"), Some(("192.168.1.254".into(), 52569, "/ctl/IP6FCtl".into())));
        assert_eq!(split_http_url("http://[fe80::1]:5000/ctl"), Some(("fe80::1".into(), 5000, "/ctl".into())));
        assert_eq!(split_http_url("http://router.home/ctl"), Some(("router.home".into(), 80, "/ctl".into())));
        assert_eq!(split_http_url("http://10.0.0.1:5000"), Some(("10.0.0.1".into(), 5000, "/".into())));
        assert_eq!(split_http_url("https://10.0.0.1/ctl"), None);
        assert_eq!(split_http_url("http://[fe80::1]x/ctl"), None);
        assert_eq!(split_http_url("http://:80/ctl"), None);
    }

    #[test]
    fn pinhole_requests_name_this_computer_and_the_gateway_port() {
        let body = add_pinhole_body(me(), 47398, TCP, 3600);
        assert!(body.contains("<u:AddPinhole xmlns:u=\"urn:schemas-upnp-org:service:WANIPv6FirewallControl:1\">"));
        assert!(body.contains("<RemoteHost></RemoteHost><RemotePort>0</RemotePort>"));
        assert!(body.contains(&format!("<InternalClient>{}</InternalClient>", me())));
        assert!(body.contains("<InternalPort>47398</InternalPort><Protocol>6</Protocol><LeaseTime>3600</LeaseTime>"));
        assert!(update_pinhole_body("17", 3600).contains("<UniqueID>17</UniqueID><NewLeaseTime>3600</NewLeaseTime>"));
        assert!(delete_pinhole_body("17").contains("<u:DeletePinhole"));
        assert_eq!(tag_value("<s:Body><u:AddPinholeResponse><UniqueID> 42 </UniqueID></u:AddPinholeResponse>", "UniqueID").as_deref(), Some("42"));
    }

    #[test]
    fn the_request_goes_out_as_plain_http_with_the_soap_action() {
        let target = SocketAddr::V6(SocketAddrV6::new("fe80::c2d7:aaff:fe29:c8ee".parse().unwrap(), 52569, 0, 14));
        let r = soap_request(target, "/ctl/IP6FCtl", "AddPinhole", "<x/>");
        assert!(r.starts_with("POST /ctl/IP6FCtl HTTP/1.1\r\nHost: [fe80::c2d7:aaff:fe29:c8ee]:52569\r\n"));
        assert!(r.contains("SOAPAction: \"urn:schemas-upnp-org:service:WANIPv6FirewallControl:1#AddPinhole\"\r\n"));
        assert!(r.contains("Content-Length: 4\r\nConnection: close\r\n\r\n<x/>"));
        let v4: SocketAddr = "192.168.1.254:52569".parse().unwrap();
        assert!(soap_request(v4, "/c", "DeletePinhole", "").contains("Host: 192.168.1.254:52569\r\n"));
    }

    #[test]
    fn router_answers_are_read_plain_or_chunked() {
        let plain = "HTTP/1.1 200 OK\r\nContent-Length: 30\r\n\r\n<UniqueID>1</UniqueID>";
        assert_eq!(http_response(plain), Some((200, "<UniqueID>1</UniqueID>".into())));
        let chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nb\r\n<UniqueID>7\r\nb\r\n</UniqueID>\r\n0\r\n\r\n";
        let (status, body) = http_response(chunked).unwrap();
        assert_eq!(status, 200);
        assert_eq!(tag_value(&body, "UniqueID").as_deref(), Some("7"));
        let refused = "HTTP/1.1 500 Internal Server Error\r\n\r\n<errorDescription>Action not authorized</errorDescription>";
        assert_eq!(http_response(refused).map(|(s, _)| s), Some(500));
        assert_eq!(http_response("garbage"), None);
    }

    #[test]
    fn the_default_ipv6_router_is_read_from_each_systems_route_table() {
        let linux = "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 wlan0\n00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000003 00000000 00450003 wlan0\n";
        assert_eq!(parse_proc_ipv6_route(linux), Some(("fe80::1".parse().unwrap(), "wlan0".to_string())));
        let windows = "===========================================================================\nActive Routes:\n If Metric Network Destination      Gateway\n 21    281 ::/0                     fe80::a2b5:3cff:fe11:2233\n 13     45 ::/0                     fe80::1\n===========================================================================\nPersistent Routes:\n  None\n";
        assert_eq!(parse_route_print(windows), Some(("fe80::1".parse().unwrap(), 13)), "the route with the lowest metric");
        let mac = "   route to: default\ndestination: default\n       mask: default\n    gateway: fe80::1%en0\n  interface: en0\n";
        assert_eq!(parse_route_get(mac), Some(("fe80::1".parse().unwrap(), "en0".to_string())));
        assert_eq!(parse_route_print("Active Routes:\n  None\n"), None);
    }

    #[tokio::test]
    #[ignore]
    async fn opens_and_closes_a_real_pinhole_on_this_network() {
        let socket = std::net::UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).unwrap();
        socket.connect((Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888), 53)).unwrap();
        let IpAddr::V6(me) = socket.local_addr().unwrap().ip() else { panic!("no IPv6") };
        let router = igd_next::aio::tokio::search_gateway(Default::default()).await.ok().map(|g| (g.addr, g.root_url.clone()));
        let how = open(router, me, 47398).await.expect("the router opened the port");
        eprintln!("opened with {how}, pinholes: {:?}", PINHOLES.lock().unwrap());
        assert!(!PINHOLES.lock().unwrap().is_empty() || how == "PCP");
        close(Some(me), 47398).await;
        assert!(PINHOLES.lock().unwrap().is_empty());
    }
}
