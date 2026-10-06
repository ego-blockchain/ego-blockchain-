use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use bech32::{ToBase32, Variant};
use blake2::{Blake2s256, Digest as _};
use ed25519_dalek::{Signature, VerifyingKey};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use tokio::sync::RwLock;

const ANNOUNCE_DOMAIN: &str = "ego/gateway/v1";
const FRESH_SECS: i64 = 2 * 60 * 60;
const CLOCK_SKEW_SECS: i64 = 300;
const ANNOUNCE_GAP_SECS: i64 = 10 * 60;
const MAX_GATEWAYS: usize = 10_000;
const LIST_LIMIT: usize = 100;
const LIST_REBUILD_SECS: i64 = 30;
const CACHE_CONTROL: &str = "public, max-age=300, stale-while-revalidate=3600";

#[derive(Debug, Clone, Deserialize)]
pub struct Announcement {
    pub endpoint: String,
    pub cert_sha256: String,
    pub node: String,
    pub ts: i64,
    pub pubkey: String,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Listed {
    pub endpoint: String,
    pub cert_sha256: String,
    pub node: String,
    pub ts: i64,
    pub pubkey: String,
    pub sig: String,
}

static GATEWAYS: Lazy<RwLock<HashMap<String, Listed>>> = Lazy::new(|| RwLock::new(HashMap::new()));
static LIST_CACHE: Lazy<RwLock<(i64, String)>> = Lazy::new(|| RwLock::new((0, String::new())));

fn is_public(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() || ip.is_broadcast()
        || ip.is_multicast() || ip.is_documentation() || o[0] == 0 || (o[0] == 100 && (64..128).contains(&o[1])) || o[0] >= 240)
}

pub fn parse_endpoint(endpoint: &str) -> Option<(Ipv4Addr, u16)> {
    let rest = endpoint.strip_prefix("https://")?.strip_suffix("/rpc")?;
    let (host, port) = rest.rsplit_once(':')?;
    let ip: Ipv4Addr = host.parse().ok()?;
    let port: u16 = port.parse().ok()?;
    (is_public(&ip) && port >= 1024 && format!("https://{ip}:{port}/rpc") == endpoint).then_some((ip, port))
}

pub fn announcement_bytes(endpoint: &str, cert_sha256: &str, ts: i64) -> Vec<u8> {
    format!("{ANNOUNCE_DOMAIN}\n{endpoint}\n{cert_sha256}\n{ts}").into_bytes()
}

pub fn address_of(pubkey: &[u8; 32]) -> String {
    let mut hasher = Blake2s256::new();
    hasher.update(b"ego/addr/v1");
    hasher.update(1u32.to_le_bytes());
    hasher.update(pubkey);
    let digest = hasher.finalize();
    let mut payload = vec![0b001u8 << 5];
    payload.extend_from_slice(&digest[..20]);
    bech32::encode("egot", payload.to_base32(), Variant::Bech32m).unwrap_or_default()
}

pub fn check(a: &Announcement, now: i64) -> Result<(), &'static str> {
    if parse_endpoint(&a.endpoint).is_none() {
        return Err("The endpoint must be https://<public IPv4>:<port>/rpc.");
    }
    if (a.ts - now).abs() > CLOCK_SKEW_SECS {
        return Err("The announcement's time is off by more than five minutes.");
    }
    if a.cert_sha256.len() != 64 || !a.cert_sha256.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) {
        return Err("cert_sha256 must be 64 lowercase hex characters.");
    }
    let pk: [u8; 32] = hex::decode(&a.pubkey).ok().and_then(|v| v.try_into().ok()).ok_or("pubkey must be 32 bytes of hex.")?;
    let sig: [u8; 64] = hex::decode(&a.sig).ok().and_then(|v| v.try_into().ok()).ok_or("sig must be 64 bytes of hex.")?;
    let key = VerifyingKey::from_bytes(&pk).map_err(|_| "pubkey is not a valid Ed25519 key.")?;
    key.verify_strict(&announcement_bytes(&a.endpoint, &a.cert_sha256, a.ts), &Signature::from_bytes(&sig))
        .map_err(|_| "The signature doesn't match the announcement.")?;
    if address_of(&pk) != a.node {
        return Err("node isn't the address of pubkey.");
    }
    Ok(())
}

pub async fn handle_register(Json(a): Json<Announcement>) -> impl IntoResponse {
    let now = chrono::Utc::now().timestamp();
    if let Err(e) = check(&a, now) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": e })));
    }
    let mut gateways = GATEWAYS.write().await;
    if let Some(prev) = gateways.get(&a.endpoint) {
        if prev.pubkey == a.pubkey && now - prev.ts < ANNOUNCE_GAP_SECS {
            return (StatusCode::OK, Json(json!({ "listed": true, "next_in": ANNOUNCE_GAP_SECS - (now - prev.ts) })));
        }
    }
    if gateways.len() >= MAX_GATEWAYS && !gateways.contains_key(&a.endpoint) {
        gateways.retain(|_, g| now - g.ts < FRESH_SECS);
        if gateways.len() >= MAX_GATEWAYS {
            return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": "The bootstrap list is full. Phones still find this gateway through other gateways." })));
        }
    }
    gateways.insert(
        a.endpoint.clone(),
        Listed { endpoint: a.endpoint, cert_sha256: a.cert_sha256, node: a.node, ts: a.ts, pubkey: a.pubkey, sig: a.sig },
    );
    (StatusCode::OK, Json(json!({ "listed": true })))
}

async fn rebuild(now: i64) -> String {
    let mut gateways = GATEWAYS.write().await;
    gateways.retain(|_, g| now - g.ts < FRESH_SECS);
    let mut fresh: Vec<Listed> = gateways.values().cloned().collect();
    drop(gateways);
    fresh.sort_by(|a, b| b.ts.cmp(&a.ts));
    fresh.truncate(LIST_LIMIT);
    json!({ "gateways": fresh, "updated_at": now }).to_string()
}

pub async fn handle_list() -> Response {
    let now = chrono::Utc::now().timestamp();
    let cached = {
        let cache = LIST_CACHE.read().await;
        (now.saturating_sub(cache.0) < LIST_REBUILD_SECS && !cache.1.is_empty()).then(|| cache.1.clone())
    };
    let body = match cached {
        Some(body) => body,
        None => {
            let body = rebuild(now).await;
            *LIST_CACHE.write().await = (now, body.clone());
            body
        }
    };
    ([(header::CONTENT_TYPE, "application/json"), (header::CACHE_CONTROL, CACHE_CONTROL)], body).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn announcement(key: &SigningKey, endpoint: &str, ts: i64) -> Announcement {
        let cert = "ab".repeat(32);
        let pk = key.verifying_key().to_bytes();
        Announcement {
            endpoint: endpoint.into(),
            cert_sha256: cert.clone(),
            node: address_of(&pk),
            ts,
            pubkey: hex::encode(pk),
            sig: hex::encode(key.sign(&announcement_bytes(endpoint, &cert, ts)).to_bytes()),
        }
    }

    #[test]
    fn a_signed_announcement_for_a_public_address_is_accepted() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        assert_eq!(check(&announcement(&key, "https://8.8.8.8:47398/rpc", 1_000), 1_000), Ok(()));
    }

    #[test]
    fn private_odd_or_unsigned_endpoints_are_refused() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        for bad in ["https://192.168.1.5:47398/rpc", "https://127.0.0.1:47398/rpc", "http://8.8.8.8:47398/rpc", "https://8.8.8.8:80/rpc", "https://example.com:47398/rpc", "https://8.8.8.8:47398/rpc/x"] {
            assert!(check(&announcement(&key, bad, 1_000), 1_000).is_err(), "{bad}");
        }
        let mut forged = announcement(&key, "https://8.8.8.8:47398/rpc", 1_000);
        forged.endpoint = "https://8.8.4.4:47398/rpc".into();
        assert!(check(&forged, 1_000).is_err());
        let mut wrong_node = announcement(&key, "https://8.8.8.8:47398/rpc", 1_000);
        wrong_node.node = address_of(&[9u8; 32]);
        assert!(check(&wrong_node, 1_000).is_err());
        assert!(check(&announcement(&key, "https://8.8.8.8:47398/rpc", 1_000), 2_000).is_err());
    }

    #[test]
    fn the_address_matches_the_wallet_derivation() {
        let pk = SigningKey::from_bytes(&[0u8; 32]).verifying_key().to_bytes();
        assert_eq!(address_of(&pk), "egot1yzwkx349luk82ksl0xe2tm6rfwj26t7pg5apncg2");
    }

    #[tokio::test]
    async fn the_list_is_built_once_and_served_from_cache() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let now = chrono::Utc::now().timestamp();
        let _ = handle_register(Json(announcement(&key, "https://9.9.9.9:47398/rpc", now))).await.into_response();
        let first = handle_list().await;
        assert_eq!(first.headers()[header::CACHE_CONTROL], CACHE_CONTROL);
        let stamp = LIST_CACHE.read().await.0;
        let _ = handle_list().await;
        assert_eq!(LIST_CACHE.read().await.0, stamp, "a second request within 30 s reuses the cached list");
        assert!(LIST_CACHE.read().await.1.contains("9.9.9.9"));
    }
}
