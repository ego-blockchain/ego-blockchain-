//! Chat alerts for Ego Wallet on iPhone, through Apple's push service.
//!
//! A phone registers its push token for its wallet, signed by that wallet.
//! When someone sends it a chat message, the sender's app asks here, signed by
//! the sender's wallet, and this server tells Apple to show an alert. The
//! message text travels as a preview encrypted with a key only the two
//! contacts have, so neither this server nor Apple can read it: the phone's
//! notification extension opens it.
//!
//! Apple's key lives next to the chain data: `apns.p8` and `apns.json`
//! (`{"key_id": "...", "team_id": "...", "topic": "com.egoblockchain.wallet"}`).
//! Without them, registering still works and alerts are skipped.

use axum::{http::StatusCode, response::IntoResponse, Json};
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use tokio::sync::{Mutex, RwLock};

pub const REGISTER_DOMAIN: &str = "ego/push-register/v1";
pub const NOTIFY_DOMAIN: &str = "ego/push-notify/v1";
const SKEW_SECS: i64 = 600;
const MAX_DEVICES: usize = 5;
const MAX_MUTED: usize = 500;
const MAX_PREVIEW: usize = 1_024;
const MAX_OWNERS: usize = 200_000;
const SENDS_PER_MINUTE: usize = 30;
/// A device not registered again for this long is dropped.
const STALE_SECS: i64 = 60 * 86_400;
const JWT_SECS: i64 = 40 * 60;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Device {
    pub token: String,
    /// "sandbox" for apps run from Xcode, "production" for TestFlight and the App Store.
    pub env: String,
    #[serde(default)]
    pub muted: Vec<String>,
    pub at: i64,
}

#[derive(Debug, Deserialize)]
pub struct Register {
    pub owner: String,
    pub token: String,
    /// "sandbox", "production", or "off" to stop alerts on this device.
    pub env: String,
    #[serde(default)]
    pub muted: Vec<String>,
    pub ts: i64,
    pub pubkey: String,
    pub sig: String,
}

#[derive(Debug, Deserialize)]
pub struct Notify {
    pub from: String,
    pub to: String,
    /// The message's id: each message alerts once, however many apps ask.
    pub id: String,
    /// "message" or "request".
    #[serde(default = "message_kind")]
    pub kind: String,
    #[serde(default)]
    pub preview: String,
    pub ts: i64,
    pub pubkey: String,
    pub sig: String,
}

fn message_kind() -> String {
    "message".into()
}

static DEVICES: Lazy<RwLock<HashMap<String, Vec<Device>>>> = Lazy::new(|| RwLock::new(HashMap::new()));
static PATH: Lazy<std::sync::Mutex<Option<PathBuf>>> = Lazy::new(|| std::sync::Mutex::new(None));
static SEEN: Lazy<Mutex<(HashMap<String, i64>, VecDeque<(String, i64)>)>> = Lazy::new(|| Mutex::new((HashMap::new(), VecDeque::new())));
static SENDS: Lazy<Mutex<HashMap<String, VecDeque<i64>>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static JWT: Lazy<Mutex<Option<(String, i64)>>> = Lazy::new(|| Mutex::new(None));
static HTTP: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default()
});

pub fn register_bytes(owner: &str, token: &str, env: &str, ts: i64, muted: &[String]) -> Vec<u8> {
    format!("{REGISTER_DOMAIN}\n{owner}\n{token}\n{env}\n{ts}\n{}", muted.join(",")).into_bytes()
}

pub fn notify_bytes(from: &str, to: &str, id: &str, kind: &str, ts: i64, preview: &str) -> Vec<u8> {
    format!("{NOTIFY_DOMAIN}\n{from}\n{to}\n{id}\n{kind}\n{ts}\n{preview}").into_bytes()
}

fn valid_address(a: &str) -> bool {
    a.starts_with("egot1") && a.len() <= 90 && a.bytes().all(|c| c.is_ascii_alphanumeric())
}

fn signer(pubkey: &str, sig: &str, message: &[u8]) -> Option<String> {
    let pk: [u8; 32] = hex::decode(pubkey).ok()?.try_into().ok()?;
    let sig: [u8; 64] = hex::decode(sig).ok()?.try_into().ok()?;
    VerifyingKey::from_bytes(&pk).ok()?.verify_strict(message, &Signature::from_bytes(&sig)).ok()?;
    Some(crate::gateways::address_of(&pk))
}

pub fn check_register(r: &Register, now: i64) -> Result<(), &'static str> {
    if !valid_address(&r.owner) {
        return Err("owner must be a wallet address");
    }
    if r.token.len() < 32 || r.token.len() > 200 || !r.token.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("token must be the device's push token in hex");
    }
    if !matches!(r.env.as_str(), "sandbox" | "production" | "off") {
        return Err("env must be sandbox, production or off");
    }
    if r.muted.len() > MAX_MUTED || !r.muted.iter().all(|m| valid_address(m)) {
        return Err("muted must be wallet addresses");
    }
    if (r.ts - now).abs() > SKEW_SECS {
        return Err("The request's time is off. Check the phone's date and time.");
    }
    if signer(&r.pubkey, &r.sig, &register_bytes(&r.owner, &r.token, &r.env, r.ts, &r.muted)).as_deref() != Some(r.owner.as_str()) {
        return Err("This request isn't signed by the wallet it names.");
    }
    Ok(())
}

pub fn check_notify(n: &Notify, now: i64) -> Result<(), &'static str> {
    if !valid_address(&n.from) || !valid_address(&n.to) || n.from == n.to {
        return Err("from and to must be two wallet addresses");
    }
    if n.id.is_empty() || n.id.len() > 128 || !n.id.bytes().all(|c| c.is_ascii_graphic()) {
        return Err("id must name the message");
    }
    if !matches!(n.kind.as_str(), "message" | "request") {
        return Err("kind must be message or request");
    }
    if n.preview.len() > MAX_PREVIEW
        || !n.preview.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=')
    {
        return Err("preview must be base64, at most 1 KB");
    }
    if (n.ts - now).abs() > SKEW_SECS {
        return Err("The request's time is off.");
    }
    if signer(&n.pubkey, &n.sig, &notify_bytes(&n.from, &n.to, &n.id, &n.kind, n.ts, &n.preview)).as_deref() != Some(n.from.as_str()) {
        return Err("This request isn't signed by the wallet it names.");
    }
    Ok(())
}

/// Adds or replaces a device for its owner. A token belongs to one wallet only.
pub fn apply_register(map: &mut HashMap<String, Vec<Device>>, r: &Register, now: i64) {
    for list in map.values_mut() {
        list.retain(|d| d.token != r.token);
    }
    if r.env != "off" {
        let list = map.entry(r.owner.clone()).or_default();
        list.retain(|d| now - d.at < STALE_SECS);
        list.push(Device { token: r.token.clone(), env: r.env.clone(), muted: r.muted.clone(), at: now });
        if list.len() > MAX_DEVICES {
            let over = list.len() - MAX_DEVICES;
            list.drain(..over);
        }
    }
    map.retain(|_, l| !l.is_empty());
}

pub fn targets(map: &HashMap<String, Vec<Device>>, to: &str, from: &str) -> Vec<Device> {
    map.get(to).map(|l| l.iter().filter(|d| !d.muted.iter().any(|m| m == from)).cloned().collect()).unwrap_or_default()
}

async fn first_time(id: &str, now: i64) -> bool {
    let mut guard = SEEN.lock().await;
    let (set, order) = &mut *guard;
    while order.front().map(|(_, t)| now - t > 3_600).unwrap_or(false) || order.len() > 100_000 {
        if let Some((old, _)) = order.pop_front() {
            set.remove(&old);
        }
    }
    if set.contains_key(id) {
        return false;
    }
    set.insert(id.to_string(), now);
    order.push_back((id.to_string(), now));
    true
}

async fn allowed(from: &str, now: i64) -> bool {
    let mut map = SENDS.lock().await;
    if map.len() > 50_000 {
        map.retain(|_, q| q.back().map(|t| now - t < 60).unwrap_or(false));
    }
    let q = map.entry(from.to_string()).or_default();
    while q.front().map(|t| now - t >= 60).unwrap_or(false) {
        q.pop_front();
    }
    if q.len() >= SENDS_PER_MINUTE {
        return false;
    }
    q.push_back(now);
    true
}

fn store_path() -> Option<PathBuf> {
    PATH.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

pub async fn init(path: PathBuf) {
    if let Ok(bytes) = tokio::fs::read(&path).await {
        if let Ok(map) = serde_json::from_slice::<HashMap<String, Vec<Device>>>(&bytes) {
            *DEVICES.write().await = map;
        }
    }
    *PATH.lock().unwrap_or_else(|e| e.into_inner()) = Some(path);
}

async fn save(map: &HashMap<String, Vec<Device>>) {
    let Some(path) = store_path() else { return };
    let Ok(bytes) = serde_json::to_vec(map) else { return };
    let tmp = path.with_extension("json.tmp");
    if tokio::fs::write(&tmp, &bytes).await.is_ok() {
        let _ = tokio::fs::rename(&tmp, &path).await;
    }
}

pub async fn handle_register(Json(r): Json<Register>) -> impl IntoResponse {
    let now = chrono::Utc::now().timestamp();
    if let Err(e) = check_register(&r, now) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": e })));
    }
    let mut map = DEVICES.write().await;
    if !map.contains_key(&r.owner) && map.len() >= MAX_OWNERS {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": "Too many phones registered right now." })));
    }
    apply_register(&mut map, &r, now);
    save(&map).await;
    (StatusCode::OK, Json(json!({ "registered": r.env != "off", "alerts": apple().is_some() })))
}

pub async fn handle_notify(Json(n): Json<Notify>) -> impl IntoResponse {
    let now = chrono::Utc::now().timestamp();
    if let Err(e) = check_notify(&n, now) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": e })));
    }
    let devices = targets(&*DEVICES.read().await, &n.to, &n.from);
    if devices.is_empty() || !first_time(&format!("{}/{}", n.from, n.id), now).await {
        return (StatusCode::OK, Json(json!({ "sent": 0 })));
    }
    if !allowed(&n.from, now).await {
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({ "error": "Too many alerts in a minute." })));
    }
    let Some(apple) = apple() else {
        return (StatusCode::OK, Json(json!({ "sent": 0, "alerts": false })));
    };
    let payload = alert_payload(&n);
    let mut sent = 0;
    let mut gone = Vec::new();
    for d in devices {
        match deliver(&apple, &d, &payload).await {
            Ok(()) => sent += 1,
            Err(Gone) => gone.push(d.token),
        }
    }
    if !gone.is_empty() {
        let mut map = DEVICES.write().await;
        for list in map.values_mut() {
            list.retain(|d| !gone.contains(&d.token));
        }
        map.retain(|_, l| !l.is_empty());
        save(&map).await;
    }
    (StatusCode::OK, Json(json!({ "sent": sent })))
}

/// What Apple shows if the phone's extension can't open the preview.
pub fn alert_payload(n: &Notify) -> serde_json::Value {
    let body = if n.kind == "request" { "New contact request" } else { "New message" };
    json!({
        "aps": {
            "alert": { "title": "Ego Chat", "body": body },
            "sound": "default",
            "mutable-content": 1,
            "thread-id": format!("chat/{}", n.from),
        },
        "ego": { "from": n.from, "id": n.id, "kind": n.kind, "preview": n.preview },
    })
}

/// Older transactions arriving (a desktop filling in history) don't alert.
const PAYMENT_FRESH_SECS: i64 = 15 * 60;

fn short_address(a: &str) -> String {
    if a.len() > 16 { format!("{}…{}", &a[..10], &a[a.len() - 4..]) } else { a.to_string() }
}

fn egoc_text(uegoc: u64) -> String {
    let whole = uegoc / 1_000_000;
    let frac = format!("{:06}", uegoc % 1_000_000);
    let frac = frac.trim_end_matches('0');
    if frac.is_empty() { whole.to_string() } else { format!("{whole}.{frac}") }
}

/// "5 EGOC", or "1.99 EGUSD" for a payment in EGUSD credits; None for anything else.
pub fn payment_amount(tx: &serde_json::Value) -> Option<String> {
    match tx["tx_type"].as_str().unwrap_or("") {
        "" | "transfer" => {
            let amount = tx["amount"].as_u64().filter(|a| *a > 0)?;
            Some(format!("{} EGOC", egoc_text(amount)))
        }
        "credits_pay" => {
            let memo = tx["memo"].as_str().unwrap_or("");
            let cents: u64 = memo.strip_prefix("credits_pay:")?.split(':').next()?.parse().ok().filter(|c| *c > 0)?;
            Some(format!("{}.{:02} EGUSD", cents / 100, cents % 100))
        }
        _ => None,
    }
}

/// The alerts a confirmed payment makes: (wallet, the other side, payload) for the
/// receiver and the sender. The phone's extension puts a contact's name in place
/// of the address.
pub fn payment_alerts(tx: &serde_json::Value, now: i64) -> Vec<(String, String, serde_json::Value)> {
    let field = |k: &str| tx[k].as_str().unwrap_or("").to_string();
    let (hash, from, to) = (field("hash"), field("from"), field("to"));
    let ts = tx["timestamp"].as_i64().unwrap_or(0);
    let Some(amount) = payment_amount(tx) else { return vec![] };
    if hash.is_empty() || !valid_address(&from) || !valid_address(&to) || from == to || (now - ts).abs() > PAYMENT_FRESH_SECS {
        return vec![];
    }
    let make = |dir: &str, title: String, body: String| {
        json!({
            "aps": {
                "alert": { "title": title, "body": body },
                "sound": "default",
                "mutable-content": 1,
                "thread-id": "wallet",
            },
            "open": "wallet",
            "ego": { "kind": "payment", "dir": dir, "hash": hash, "from": from, "to": to },
        })
    };
    vec![
        (to.clone(), from.clone(), make("received", format!("Received {amount}"), format!("From {}", short_address(&from)))),
        (from.clone(), to.clone(), make("sent", format!("Sent {amount}"), format!("To {}. Confirmed on the network.", short_address(&to)))),
    ]
}

/// Sends the alerts for newly confirmed payments, in the background.
pub fn payments(txs: Vec<serde_json::Value>) {
    if txs.is_empty() {
        return;
    }
    tokio::spawn(async move {
        let now = chrono::Utc::now().timestamp();
        let mut gone = Vec::new();
        let mut apple_cfg = None;
        for tx in &txs {
            for (owner, other, payload) in payment_alerts(tx, now) {
                let devices = targets(&*DEVICES.read().await, &owner, &other);
                let dir = payload["ego"]["dir"].as_str().unwrap_or("").to_string();
                let hash = payload["ego"]["hash"].as_str().unwrap_or("").to_string();
                if devices.is_empty() || !first_time(&format!("tx/{hash}/{dir}"), now).await {
                    continue;
                }
                if apple_cfg.is_none() {
                    apple_cfg = apple();
                }
                let Some(apple) = apple_cfg.as_ref() else { return };
                for d in devices {
                    if deliver(apple, &d, &payload).await.is_err() {
                        gone.push(d.token);
                    }
                }
            }
        }
        if !gone.is_empty() {
            let mut map = DEVICES.write().await;
            for list in map.values_mut() {
                list.retain(|d| !gone.contains(&d.token));
            }
            map.retain(|_, l| !l.is_empty());
            save(&map).await;
        }
    });
}

struct Apple {
    key_id: String,
    team_id: String,
    topic: String,
    pem: String,
}

#[derive(Deserialize)]
struct AppleFile {
    key_id: String,
    team_id: String,
    #[serde(default = "default_topic")]
    topic: String,
}

fn default_topic() -> String {
    "com.egoblockchain.wallet".into()
}

fn apple() -> Option<Apple> {
    let dir = store_path()?.parent()?.to_path_buf();
    let pem = std::fs::read_to_string(dir.join("apns.p8")).ok()?;
    let file: AppleFile = serde_json::from_slice(&std::fs::read(dir.join("apns.json")).ok()?).ok()?;
    Some(Apple { key_id: file.key_id, team_id: file.team_id, topic: file.topic, pem })
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn make_jwt(key_id: &str, team_id: &str, pem: &str, now: i64) -> Option<String> {
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use p256::pkcs8::DecodePrivateKey;
    let key = SigningKey::from_pkcs8_pem(pem.trim()).ok()?;
    let header = b64url(json!({ "alg": "ES256", "kid": key_id }).to_string().as_bytes());
    let claims = b64url(json!({ "iss": team_id, "iat": now }).to_string().as_bytes());
    let signing_input = format!("{header}.{claims}");
    let sig: Signature = key.sign(signing_input.as_bytes());
    Some(format!("{signing_input}.{}", b64url(&sig.to_bytes())))
}

async fn jwt(apple: &Apple) -> Option<String> {
    let now = chrono::Utc::now().timestamp();
    let mut cached = JWT.lock().await;
    if let Some((token, at)) = cached.as_ref() {
        if now - at < JWT_SECS {
            return Some(token.clone());
        }
    }
    let token = make_jwt(&apple.key_id, &apple.team_id, &apple.pem, now)?;
    *cached = Some((token.clone(), now));
    Some(token)
}

struct Gone;

async fn deliver(apple: &Apple, d: &Device, payload: &serde_json::Value) -> Result<(), Gone> {
    let Some(token) = jwt(apple).await else { return Ok(()) };
    let host = if d.env == "sandbox" { "api.sandbox.push.apple.com" } else { "api.push.apple.com" };
    let answer = HTTP
        .post(format!("https://{host}/3/device/{}", d.token))
        .header("authorization", format!("bearer {token}"))
        .header("apns-topic", &apple.topic)
        .header("apns-push-type", "alert")
        .header("apns-priority", "10")
        .json(payload)
        .send()
        .await;
    match answer {
        Ok(r) if r.status().is_success() => Ok(()),
        Ok(r) => {
            let status = r.status().as_u16();
            let reason = r.text().await.unwrap_or_default();
            tracing::warn!("[Push] Apple said {status}: {reason}");
            if status == 410 || reason.contains("BadDeviceToken") || reason.contains("Unregistered") {
                Err(Gone)
            } else {
                if status == 403 {
                    *JWT.lock().await = None;
                }
                Ok(())
            }
        }
        Err(e) => {
            tracing::warn!("[Push] Apple unreachable: {e}");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn wallet(n: u8) -> (SigningKey, String) {
        let key = SigningKey::from_bytes(&[n; 32]);
        let addr = crate::gateways::address_of(&key.verifying_key().to_bytes());
        (key, addr)
    }

    fn register(key: &SigningKey, owner: &str, token: &str, env: &str, muted: Vec<String>, ts: i64) -> Register {
        let sig = key.sign(&register_bytes(owner, token, env, ts, &muted));
        Register {
            owner: owner.into(),
            token: token.into(),
            env: env.into(),
            muted,
            ts,
            pubkey: hex::encode(key.verifying_key().to_bytes()),
            sig: hex::encode(sig.to_bytes()),
        }
    }

    fn notify(key: &SigningKey, from: &str, to: &str, id: &str, preview: &str, ts: i64) -> Notify {
        let sig = key.sign(&notify_bytes(from, to, id, "message", ts, preview));
        Notify {
            from: from.into(),
            to: to.into(),
            id: id.into(),
            kind: "message".into(),
            preview: preview.into(),
            ts,
            pubkey: hex::encode(key.verifying_key().to_bytes()),
            sig: hex::encode(sig.to_bytes()),
        }
    }

    #[test]
    fn only_the_wallet_itself_registers_its_phone() {
        let (key, owner) = wallet(1);
        let (other, _) = wallet(2);
        let token = "ab".repeat(32);
        assert!(check_register(&register(&key, &owner, &token, "sandbox", vec![], 1_000), 1_000).is_ok());
        assert!(check_register(&register(&other, &owner, &token, "sandbox", vec![], 1_000), 1_000).is_err());
        assert!(check_register(&register(&key, &owner, &token, "sandbox", vec![], 1_000), 5_000).is_err(), "old requests are refused");
        let mut r = register(&key, &owner, &token, "sandbox", vec![], 1_000);
        r.muted = vec![wallet(3).1];
        assert!(check_register(&r, 1_000).is_err(), "the muted list is signed too");
    }

    #[test]
    fn an_alert_names_its_real_sender() {
        let (alice, a) = wallet(1);
        let (bob, b) = wallet(2);
        assert!(check_notify(&notify(&alice, &a, &b, "m1", "cHJldmlldw==", 1_000), 1_000).is_ok());
        assert!(check_notify(&notify(&bob, &a, &b, "m1", "", 1_000), 1_000).is_err(), "Bob can't alert as Alice");
        let mut n = notify(&alice, &a, &b, "m1", "", 1_000);
        n.preview = "dGFtcGVyZWQ=".into();
        assert!(check_notify(&n, 1_000).is_err(), "the preview can't be swapped");
    }

    #[test]
    fn a_token_moves_with_its_wallet_and_muted_senders_get_nothing() {
        let (k1, w1) = wallet(1);
        let (k2, w2) = wallet(2);
        let (_, spam) = wallet(3);
        let token = "cd".repeat(32);
        let mut map = HashMap::new();
        apply_register(&mut map, &register(&k1, &w1, &token, "sandbox", vec![], 1), 1);
        apply_register(&mut map, &register(&k2, &w2, &token, "production", vec![spam.clone()], 2), 2);
        assert!(map.get(&w1).is_none(), "a phone gets alerts for the wallet that registered last");
        assert_eq!(targets(&map, &w2, &w1).len(), 1);
        assert!(targets(&map, &w2, &spam).is_empty());
        apply_register(&mut map, &register(&k2, &w2, &token, "off", vec![], 3), 3);
        assert!(map.is_empty());
    }

    #[test]
    fn apple_tokens_are_signed_es256() {
        let pem = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8KkrkZ2KWVp1CuVJ\nHTqre1q3W/g4WUepZedlgFo4k8ChRANCAARejjuh8HZE9MoC1KTLpMX0uU8OIdjs\naxnaU16GXrLMaWaZH6kOnsYjv0hddfaciObpIVzY/nlVqSDnKo+AfwcE\n-----END PRIVATE KEY-----";
        let jwt = make_jwt("ABC123DEFG", "L6V6UNMLXM", pem, 1_700_000_000).expect("a JWT");
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[2]).unwrap().len(), 64);
    }

    #[test]
    fn a_fresh_payment_alerts_both_sides_and_old_ones_do_not() {
        let now = 1_800_000_000;
        let tx = json!({"hash": "0xab", "from": "egot1alice", "to": "egot1bob", "amount": 2_500_000u64,
                        "tx_type": "transfer", "timestamp": now - 5, "block_height": 9});
        let alerts = payment_alerts(&tx, now);
        assert_eq!(alerts.len(), 2);
        assert_eq!(alerts[0].0, "egot1bob");
        assert_eq!(alerts[0].2["aps"]["alert"]["title"], "Received 2.5 EGOC");
        assert_eq!(alerts[1].0, "egot1alice");
        assert_eq!(alerts[1].2["ego"]["dir"], "sent");
        assert_eq!(alerts[1].2["open"], "wallet");

        let mut old = tx.clone();
        old["timestamp"] = json!(now - 3_600);
        assert!(payment_alerts(&old, now).is_empty(), "history being filled in");

        let egusd = json!({"hash": "0xcd", "from": "egot1alice", "to": "egot1bob", "amount": 0,
                           "tx_type": "credits_pay", "memo": "credits_pay:199", "timestamp": now});
        assert_eq!(payment_alerts(&egusd, now)[0].2["aps"]["alert"]["title"], "Received 1.99 EGUSD");
        let stake = json!({"hash": "0xef", "from": "egot1alice", "to": "egot1bob", "amount": 5, "tx_type": "stake", "timestamp": now});
        assert!(payment_alerts(&stake, now).is_empty());
    }
}
