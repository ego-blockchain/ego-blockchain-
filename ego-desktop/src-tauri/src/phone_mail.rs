use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

pub const GET_DOMAIN: &str = "ego/mail-get/v1";
pub const PUT_DOMAIN: &str = "ego/mail-put/v1";
pub const SEND_DOMAIN: &str = "ego/mail-send/v1";
pub const PEEK_DOMAIN: &str = "ego/mail-peek/v1";
pub const READER_DOMAIN: &str = "ego/mail-reader/v1";
pub const METHODS: &[&str] = &["mail.get", "mail.put", "mail.send", "mail.peek"];
pub const ALERT_CHAT: &str = "chat";
pub const ALERT_REQUEST: &str = "request";

const KEEP_MS: i64 = 30 * 86_400_000;
const MAX_PER_OWNER: usize = 500;
const MAX_PER_SENDER: usize = 200;
const MAX_OWNER_BYTES: usize = 8 * 1024 * 1024;
const MAX_CT_HEX: usize = 256 * 1024;
const SENDS_PER_MINUTE: usize = 60;
const HISTORY_PER_CONTACT: usize = 200;
const HISTORY_MAX: usize = 1_500;
const HISTORY_CHUNK_BYTES: usize = 40 * 1024;
const HISTORY_AVATARS: usize = 20;
const PAGE_ITEMS: usize = 200;
const PAGE_BYTES: usize = 1024 * 1024;
const SKEW_SECS: i64 = 600;
const STORE_CAP_BYTES: u64 = 128 * 1024 * 1024;
const HOLD_CACHE_SECS: i64 = 600;
const HOLD_CACHE_MAX: usize = 20_000;
const CATCH_UP_FIRST_SECS: u64 = 90;
const CATCH_UP_EVERY_SECS: u64 = 600;
const CATCH_UP_LOOK_BACK_MS: i64 = 2 * 86_400_000;
const CATCH_UP_PAGES: usize = 5;
const BOOTSTRAP_EVERY_SECS: i64 = 6 * 3600;
const READER_GRANT_MAX_SECS: i64 = 120 * 86_400;
const PEEK_ITEMS: usize = 50;

type RpcResult = Result<Value, (i32, String)>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Sealed {
    pub to: String,
    pub eph_pub: String,
    pub nonce: String,
    pub ct: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub alert: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Kept {
    #[serde(flatten)]
    pub sealed: Sealed,
    pub at: i64,
    #[serde(default)]
    pub by: String,
}

static LOCK: Mutex<()> = Mutex::new(());
static USAGE: Mutex<Option<u64>> = Mutex::new(None);
static HOLDS: Mutex<Option<HashMap<String, (bool, i64)>>> = Mutex::new(None);
static SENDS: Mutex<Option<HashMap<String, std::collections::VecDeque<i64>>>> = Mutex::new(None);
static BOOTSTRAPPED_AT: Mutex<i64> = Mutex::new(0);

fn is_hex(s: &str, len: Option<usize>) -> bool {
    len.map_or(s.len() % 2 == 0, |l| s.len() == l) && s.bytes().all(|c| c.is_ascii_hexdigit())
}

pub fn id_of(ct_hex: &str) -> String {
    hex::encode(&blake3::hash(ct_hex.as_bytes()).as_bytes()[..16])
}

pub fn valid(s: &Sealed) -> bool {
    crate::account_record::valid_owner(&s.to)
        && is_hex(&s.eph_pub, Some(64))
        && is_hex(&s.nonce, Some(24))
        && s.ct.len() >= 32
        && s.ct.len() <= MAX_CT_HEX
        && is_hex(&s.ct, None)
        && s.id == id_of(&s.ct)
        && (s.alert.is_empty() || s.alert == ALERT_CHAT || s.alert == ALERT_REQUEST)
}

fn dir() -> PathBuf {
    crate::ledger::base_data_dir().join("mailbox")
}

fn path(owner: &str) -> PathBuf {
    dir().join(format!("{owner}.json"))
}

fn load(owner: &str) -> Vec<Kept> {
    std::fs::read(path(owner)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn size(k: &Kept) -> usize {
    k.sealed.ct.len() + 200
}

fn trim(list: &mut Vec<Kept>, owner: &str) {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for k in list.iter().filter(|k| k.by != owner) {
        *counts.entry(k.by.clone()).or_default() += 1;
    }
    let mut excess: HashMap<String, usize> = counts
        .into_iter()
        .filter(|(_, n)| *n > MAX_PER_SENDER)
        .map(|(by, n)| (by, n - MAX_PER_SENDER))
        .collect();
    list.retain(|k| match excess.get_mut(&k.by) {
        Some(n) if *n > 0 => {
            *n -= 1;
            false
        }
        _ => true,
    });
    if list.len() > MAX_PER_OWNER {
        let over = list.len() - MAX_PER_OWNER;
        list.drain(..over);
    }
    let mut bytes: usize = list.iter().map(size).sum();
    while bytes > MAX_OWNER_BYTES && !list.is_empty() {
        bytes -= size(&list[0]);
        list.remove(0);
    }
}

fn scan() -> Vec<(PathBuf, u64, std::time::SystemTime)> {
    std::fs::read_dir(dir())
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter_map(|e| {
                    let m = e.metadata().ok()?;
                    Some((e.path(), m.len(), m.modified().unwrap_or(std::time::UNIX_EPOCH)))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn evict_if_full(added: u64, keep: &std::path::Path) {
    let mut usage = USAGE.lock().unwrap_or_else(|e| e.into_inner());
    let total = usage.get_or_insert_with(|| scan().iter().map(|f| f.1).sum());
    *total = total.saturating_add(added);
    if *total <= STORE_CAP_BYTES {
        return;
    }
    let mut files = scan();
    files.sort_by_key(|f| f.2);
    let mut now_total: u64 = files.iter().map(|f| f.1).sum();
    for (p, len, _) in files {
        if now_total <= STORE_CAP_BYTES * 9 / 10 {
            break;
        }
        if p == keep {
            continue;
        }
        if std::fs::remove_file(&p).is_ok() {
            now_total = now_total.saturating_sub(len);
        }
    }
    *total = now_total;
}

pub fn keep(s: &Sealed, by: &str, now_ms: i64) -> bool {
    if !valid(s) {
        return false;
    }
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut list = load(&s.to);
    list.retain(|k| now_ms.saturating_sub(k.at) < KEEP_MS);
    if list.iter().any(|k| k.sealed.id == s.id) {
        return false;
    }
    let at = list.last().map_or(now_ms, |k| k.at.saturating_add(1).max(now_ms));
    list.push(Kept { sealed: s.clone(), at, by: by.to_string() });
    trim(&mut list, &s.to);
    if std::fs::create_dir_all(dir()).is_err() {
        return false;
    }
    let Ok(bytes) = serde_json::to_vec(&list) else { return false };
    let p = path(&s.to);
    if crate::utils::atomic_write(&p, &bytes).is_err() {
        return false;
    }
    evict_if_full(bytes.len() as u64, &p);
    list.iter().any(|k| k.sealed.id == s.id)
}

pub fn since(owner: &str, since_ms: i64, now_ms: i64) -> (Vec<Kept>, bool) {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let fresh: Vec<Kept> = load(owner)
        .into_iter()
        .filter(|k| k.at > since_ms && now_ms.saturating_sub(k.at) < KEEP_MS)
        .collect();
    let mut out = Vec::new();
    let mut bytes = 0usize;
    for k in fresh.iter() {
        if out.len() >= PAGE_ITEMS || (bytes > 0 && bytes + size(k) > PAGE_BYTES) {
            break;
        }
        bytes += size(k);
        out.push(k.clone());
    }
    let more = out.len() < fresh.len();
    (out, more)
}

pub fn alerts_since(owner: &str, since_ms: i64, now_ms: i64) -> (Vec<Value>, i64) {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    alerts_in(load(owner), since_ms, now_ms)
}

fn alerts_in(list: Vec<Kept>, since_ms: i64, now_ms: i64) -> (Vec<Value>, i64) {
    let fresh: Vec<Kept> = list
        .into_iter()
        .filter(|k| k.at > since_ms && now_ms.saturating_sub(k.at) < KEEP_MS)
        .collect();
    let latest = fresh.iter().map(|k| k.at).max().unwrap_or(since_ms).max(since_ms);
    let alerts = fresh
        .iter()
        .rev()
        .filter(|k| !k.sealed.alert.is_empty())
        .take(PEEK_ITEMS)
        .map(|k| json!({ "id": k.sealed.id, "at": k.at, "alert": k.sealed.alert }))
        .collect();
    (alerts, latest)
}

pub fn reader_bytes(owner: &str, reader: &str, until: i64) -> Vec<u8> {
    format!("{READER_DOMAIN}\n{owner}\n{reader}\n{until}").into_bytes()
}

pub fn peek_bytes(owner: &str, reader: &str, ts: i64, since: i64) -> Vec<u8> {
    format!("{PEEK_DOMAIN}\n{owner}\n{reader}\n{ts}\n{since}").into_bytes()
}

fn reader_allowed(params: &Value, owner: &str, now: i64) -> Result<(), (i32, String)> {
    use ed25519_dalek::{Signature, VerifyingKey};
    let reader = params["reader"].as_str().unwrap_or_default();
    let until = params["until"].as_i64().unwrap_or_default();
    let ts = params["ts"].as_i64().unwrap_or_default();
    let since = params["since"].as_i64().unwrap_or(0);
    if until <= now || until > now + READER_GRANT_MAX_SECS {
        return Err((-32003, "This alert key has expired. Open Ego Wallet once to renew it.".into()));
    }
    let granted = crate::account_record::signer_of(
        params["pubkey"].as_str().unwrap_or_default(),
        params["grant"].as_str().unwrap_or_default(),
        &reader_bytes(owner, reader, until),
    )
    .map_err(|_| (-32003, "This alert key wasn't given by the wallet it names.".to_string()))?;
    if granted != owner {
        return Err((-32003, "This alert key wasn't given by the wallet it names.".into()));
    }
    let bad = || (-32003, "This request isn't signed by the alert key.".to_string());
    let pk: [u8; 32] = hex::decode(reader).ok().and_then(|v| v.try_into().ok()).ok_or_else(bad)?;
    let sig: [u8; 64] = hex::decode(params["sig"].as_str().unwrap_or_default()).ok().and_then(|v| v.try_into().ok()).ok_or_else(bad)?;
    VerifyingKey::from_bytes(&pk)
        .map_err(|_| bad())?
        .verify_strict(&peek_bytes(owner, reader, ts, since), &Signature::from_bytes(&sig))
        .map_err(|_| bad())
}

pub fn get_bytes(owner: &str, ts: i64) -> Vec<u8> {
    format!("{GET_DOMAIN}\n{owner}\n{ts}").into_bytes()
}

pub fn put_bytes(by: &str, to: &str, ts: i64, id: &str) -> Vec<u8> {
    format!("{PUT_DOMAIN}\n{by}\n{to}\n{ts}\n{id}").into_bytes()
}

pub fn send_bytes(by: &str, to: &str, ts: i64, id: &str) -> Vec<u8> {
    format!("{SEND_DOMAIN}\n{by}\n{to}\n{ts}\n{id}").into_bytes()
}

fn send_allowed(by: &str, now: i64) -> bool {
    let mut guard = SENDS.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    if map.len() > 50_000 {
        map.retain(|_, q| q.back().map(|t| now - t < 60).unwrap_or(false));
    }
    let q = map.entry(by.to_string()).or_default();
    while q.front().map(|t| now - t >= 60).unwrap_or(false) {
        q.pop_front();
    }
    if q.len() >= SENDS_PER_MINUTE {
        return false;
    }
    q.push_back(now);
    true
}

fn signed_by(params: &Value, message: &[u8], who: &str) -> Result<(), (i32, String)> {
    let signer = crate::account_record::signer_of(
        params["pubkey"].as_str().unwrap_or_default(),
        params["sig"].as_str().unwrap_or_default(),
        message,
    )
    .map_err(|_| (-32003, "This request isn't signed by the wallet it names.".to_string()))?;
    if signer != who {
        return Err((-32003, "This request isn't signed by the wallet it names.".into()));
    }
    Ok(())
}

fn fresh(ts: i64, now: i64) -> Result<(), (i32, String)> {
    if (ts - now).abs() > SKEW_SECS {
        return Err((-32003, "The request's time is off. Check your phone's date and time.".into()));
    }
    Ok(())
}

pub fn holds(to: &str, me: &str, now: i64) -> bool {
    if to == me {
        return true;
    }
    if me.is_empty() || !crate::gateway::serving() {
        return false;
    }
    {
        let guard = HOLDS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((held, at)) = guard.as_ref().and_then(|m| m.get(to)) {
            if now - at < HOLD_CACHE_SECS {
                return *held;
            }
        }
    }
    let others: Vec<String> = crate::account_record::listed_nodes(now).into_iter().map(|(n, _)| n).collect();
    let held = crate::account_record::should_hold(to, me, &others);
    let mut guard = HOLDS.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    if map.len() >= HOLD_CACHE_MAX {
        map.retain(|_, (_, at)| now - *at < HOLD_CACHE_SECS);
        if map.len() >= HOLD_CACHE_MAX {
            map.clear();
        }
    }
    map.insert(to.to_string(), (held, now));
    held
}

pub fn on_gossip(sealed: Sealed, me: &str) {
    let now = chrono::Utc::now();
    if sealed.to == me {
        if !me.is_empty() && phone_present(me) {
            keep(&sealed, "", now.timestamp_millis());
        }
        return;
    }
    if holds(&sealed.to, me, now.timestamp()) {
        keep(&sealed, "", now.timestamp_millis());
    }
}

pub fn from_p2p(msg: &crate::p2p::P2PMessage) -> Option<Sealed> {
    match msg {
        crate::p2p::P2PMessage::SealedDm { to, eph_pub, nonce, ct, id, alert } => Some(Sealed {
            to: to.clone(),
            eph_pub: eph_pub.clone(),
            nonce: nonce.clone(),
            ct: ct.clone(),
            id: id.clone(),
            alert: alert.clone(),
        }),
        _ => None,
    }
}

async fn get(params: &Value) -> RpcResult {
    let owner = params["owner"].as_str().unwrap_or_default().to_string();
    let ts = params["ts"].as_i64().unwrap_or_default();
    let since_ms = params["since"].as_i64().unwrap_or(0);
    if !crate::account_record::valid_owner(&owner) {
        return Err((-32602, "owner must be a wallet address".into()));
    }
    let now = chrono::Utc::now();
    fresh(ts, now.timestamp())?;
    signed_by(params, &get_bytes(&owner, ts), &owner)?;
    let now_ms = now.timestamp_millis();
    let (mail, more) = tokio::task::spawn_blocking(move || since(&owner, since_ms, now_ms))
        .await
        .map_err(|e| (-32603, e.to_string()))?;
    Ok(json!({ "mail": mail, "more": more }))
}

async fn peek(params: &Value) -> RpcResult {
    let owner = params["owner"].as_str().unwrap_or_default().to_string();
    let ts = params["ts"].as_i64().unwrap_or_default();
    let since_ms = params["since"].as_i64().unwrap_or(0);
    if !crate::account_record::valid_owner(&owner) {
        return Err((-32602, "owner must be a wallet address".into()));
    }
    let now = chrono::Utc::now();
    fresh(ts, now.timestamp())?;
    reader_allowed(params, &owner, now.timestamp())?;
    let now_ms = now.timestamp_millis();
    let (alerts, latest) = tokio::task::spawn_blocking(move || alerts_since(&owner, since_ms, now_ms))
        .await
        .map_err(|e| (-32603, e.to_string()))?;
    Ok(json!({ "alerts": alerts, "latest": latest }))
}

async fn put(params: &Value) -> RpcResult {
    let sealed: Sealed = serde_json::from_value(params["mail"].clone())
        .map_err(|_| (-32602, "mail must be a sealed message".to_string()))?;
    let by = params["by"].as_str().unwrap_or_default().to_string();
    let ts = params["ts"].as_i64().unwrap_or_default();
    if !valid(&sealed) || !crate::account_record::valid_owner(&by) {
        return Err((-32602, "mail must be a sealed message".into()));
    }
    let now = chrono::Utc::now();
    fresh(ts, now.timestamp())?;
    signed_by(params, &put_bytes(&by, &sealed.to, ts, &sealed.id), &by)?;
    tokio::task::spawn_blocking(move || {
        let me = crate::account_record::own_node();
        if !holds(&sealed.to, &me, now.timestamp()) {
            return Err((-32004, "This gateway is not one of the places that keep this wallet's mail.".to_string()));
        }
        Ok(json!({ "kept": keep(&sealed, &by, now.timestamp_millis()) }))
    })
    .await
    .map_err(|e| (-32603, e.to_string()))?
}

async fn send(params: &Value) -> RpcResult {
    let sealed: Sealed = serde_json::from_value(params["mail"].clone())
        .map_err(|_| (-32602, "mail must be a sealed message".to_string()))?;
    let by = params["by"].as_str().unwrap_or_default().to_string();
    let ts = params["ts"].as_i64().unwrap_or_default();
    if !valid(&sealed) || !crate::account_record::valid_owner(&by) {
        return Err((-32602, "mail must be a sealed message".into()));
    }
    let now = chrono::Utc::now();
    fresh(ts, now.timestamp())?;
    signed_by(params, &send_bytes(&by, &sealed.to, ts, &sealed.id), &by)?;
    if !send_allowed(&by, now.timestamp()) {
        return Err((-32005, "Too many messages in a minute. Wait a moment and try again.".into()));
    }
    let wire = crate::p2p::P2PMessage::SealedDm {
        to: sealed.to.clone(),
        eph_pub: sealed.eph_pub.clone(),
        nonce: sealed.nonce.clone(),
        ct: sealed.ct.clone(),
        id: sealed.id.clone(),
        alert: sealed.alert.clone(),
    };
    if let Ok(data) = serde_json::to_vec(&wire) {
        crate::p2p::publish_gossip(crate::p2p::DM_TOPIC, data).await;
    }
    let local = sealed.clone();
    let me = tokio::task::spawn_blocking(move || {
        let me = crate::account_record::own_node();
        on_gossip(local, &me);
        me
    })
    .await
    .unwrap_or_default();
    if !me.is_empty() && me == sealed.to {
        if let Some(inner) = crate::p2p::open_dm(&sealed.eph_pub, &sealed.nonce, &sealed.ct) {
            crate::p2p::handle_incoming(inner, crate::p2p::APP_HANDLE.get()).await;
        }
    }
    Ok(json!({ "sent": true }))
}

pub async fn dispatch(method: &str, params: &Value) -> Option<RpcResult> {
    Some(match method {
        "mail.get" => get(params).await,
        "mail.put" => put(params).await,
        "mail.send" => send(params).await,
        "mail.peek" => peek(params).await,
        _ => return None,
    })
}

fn phone_present(me: &str) -> bool {
    crate::account_record::stored(me, crate::account_record::SLOT_PHONE).is_some()
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HistoryMessage {
    pub id: String,
    pub from: String,
    pub to: String,
    pub ts: i64,
    #[serde(rename = "type")]
    pub kind: String,
    pub content: String,
    pub reply_to: Option<String>,
    pub reactions: Vec<crate::commands::messenger::Reaction>,
    pub edited_at: Option<i64>,
    pub delivered: bool,
    pub read: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HistoryProfile {
    pub address: String,
    pub name: String,
    pub avatar: String,
}

pub fn history_messages(all: &[crate::commands::messenger::Message]) -> Vec<HistoryMessage> {
    let mut by_peer: HashMap<&str, Vec<&crate::commands::messenger::Message>> = HashMap::new();
    for m in all.iter().filter(|m| !crate::commands::messenger::is_control_type(&m.message_type)) {
        let peer = if m.outgoing { m.to.as_str() } else { m.from.as_str() };
        by_peer.entry(peer).or_default().push(m);
    }
    let mut picked: Vec<&crate::commands::messenger::Message> = by_peer
        .into_values()
        .flat_map(|mut list| {
            list.sort_by_key(|m| m.timestamp);
            let skip = list.len().saturating_sub(HISTORY_PER_CONTACT);
            list.into_iter().skip(skip)
        })
        .collect();
    picked.sort_by(|a, b| b.timestamp.cmp(&a.timestamp).then_with(|| a.id.cmp(&b.id)));
    picked.truncate(HISTORY_MAX);
    picked.reverse();
    picked
        .into_iter()
        .map(|m| HistoryMessage {
            id: m.id.clone(),
            from: m.from.clone(),
            to: m.to.clone(),
            ts: m.timestamp,
            kind: m.message_type.clone(),
            content: m.content.clone(),
            reply_to: m.reply_to.clone(),
            reactions: m.reactions.clone(),
            edited_at: m.edited_at,
            delivered: m.delivered || m.read_by_recipient,
            read: m.read_by_recipient,
        })
        .collect()
}

pub fn history_chunks(messages: &[HistoryMessage], profiles: &[HistoryProfile]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut batch: Vec<&HistoryMessage> = Vec::new();
    let mut size = 0usize;
    for m in messages {
        let len = serde_json::to_vec(m).map(|v| v.len()).unwrap_or(0) + 1;
        if !batch.is_empty() && size + len > HISTORY_CHUNK_BYTES {
            out.push(json!({ "type": "history", "messages": batch, "profiles": [] }));
            batch.clear();
            size = 0;
        }
        batch.push(m);
        size += len;
    }
    if !batch.is_empty() {
        out.push(json!({ "type": "history", "messages": batch, "profiles": [] }));
    }
    for p in profiles {
        out.push(json!({ "type": "history", "messages": [], "profiles": [p] }));
    }
    out.into_iter().filter_map(|v| serde_json::to_vec(&v).ok()).collect()
}

fn backfill_marker(owner: &str) -> PathBuf {
    dir().join(format!("{owner}.history"))
}

pub async fn backfill_if_asked(want: i64) {
    if want <= 0 {
        return;
    }
    let Ok(Some((me, seed, messages, profiles))) = tokio::task::spawn_blocking(move || {
        let ledger = crate::ledger::Ledger::load();
        let me = ledger.address.clone();
        if me.is_empty() {
            return None;
        }
        let served: i64 = std::fs::read_to_string(backfill_marker(&me)).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
        if served >= want {
            return None;
        }
        let seed = crate::ledger::load_seed().ok().flatten()?;
        let messages = history_messages(&crate::commands::messenger::load_messages());
        let mut recent: HashMap<String, i64> = HashMap::new();
        for m in &messages {
            let peer = if m.from == me { m.to.clone() } else { m.from.clone() };
            let t = recent.entry(peer).or_default();
            *t = (*t).max(m.ts);
        }
        let mut contacts: Vec<crate::commands::messenger::Contact> = crate::commands::messenger::load_contacts()
            .into_iter()
            .filter(|c| c.status == "approved" && !c.avatar.is_empty())
            .collect();
        contacts.sort_by_key(|c| std::cmp::Reverse(recent.get(&c.address).copied().unwrap_or(0)));
        contacts.truncate(HISTORY_AVATARS);
        let mut profiles: Vec<HistoryProfile> = contacts
            .into_iter()
            .map(|c| HistoryProfile { address: c.address, name: c.name, avatar: c.avatar })
            .collect();
        if !ledger.avatar.is_empty() {
            profiles.push(HistoryProfile { address: me.clone(), name: crate::commands::messenger::my_display_name(), avatar: ledger.avatar.clone() });
        }
        let _ = std::fs::create_dir_all(dir());
        let _ = std::fs::write(backfill_marker(&me), want.to_string());
        Some((me, seed, messages, profiles))
    })
    .await
    else {
        return;
    };
    let Ok(key) = crate::account_record::signing_key(&seed) else { return };
    let my_ed = hex::encode(key.verifying_key().to_bytes());
    for chunk in history_chunks(&messages, &profiles) {
        if let Some(sealed) = crate::p2p::seal_plain(&me, &my_ed, &chunk).as_ref().and_then(from_p2p) {
            push_own(&me, &key, &my_ed, sealed).await;
        }
    }
    tracing::info!("[Mail] sent {} older messages and {} pictures to this wallet's phone", messages.len(), profiles.len());
}

async fn push_own(me: &str, key: &ed25519_dalek::SigningKey, my_ed: &str, sealed: Sealed) {
    let now = chrono::Utc::now();
    let local = sealed.clone();
    let owner = me.to_string();
    let _ = tokio::task::spawn_blocking(move || keep(&local, &owner, now.timestamp_millis())).await;
    put_at_places(me, key, my_ed, sealed).await;
}

/// Hands `sealed` to the gateways that keep mail for its addressee, signed by `me`.
async fn put_at_places(me: &str, key: &ed25519_dalek::SigningKey, my_ed: &str, sealed: Sealed) {
    use ed25519_dalek::Signer;
    let ts = chrono::Utc::now().timestamp();
    let sig = key.sign(&put_bytes(me, &sealed.to, ts, &sealed.id));
    let to = sealed.to.clone();
    let body = json!({
        "mail": sealed,
        "by": me,
        "ts": ts,
        "pubkey": my_ed,
        "sig": hex::encode(sig.to_bytes()),
    });
    let nodes = crate::account_record::listed_nodes(ts);
    let names: Vec<String> = nodes.iter().map(|(n, _)| n.clone()).collect();
    let own = tokio::task::spawn_blocking(crate::account_record::own_node).await.unwrap_or_default();
    let targets: Vec<String> = crate::account_record::places(&to, &names, crate::account_record::PLACES)
        .into_iter()
        .filter(|n| n != me && n != &own)
        .filter_map(|n| nodes.iter().find(|(m, _)| m == &n).map(|(_, e)| e.clone()))
        .collect();
    let pushes = targets.iter().map(|t| crate::account_record::call_peer(t, "mail.put", body.clone()));
    futures::future::join_all(pushes).await;
}

/// Leaves mail you send with the gateways that keep the addressee's mail, and here
/// too if this computer is one of them. Gossip alone reaches only the computers
/// connected at that moment and isn't kept by the one sending it, so a phone whose
/// own desktop was off had nowhere to collect it from.
pub async fn deposit(sealed: Sealed) {
    let Ok(Some((me, seed))) = tokio::task::spawn_blocking(|| {
        let me = crate::ledger::Ledger::load().address;
        if me.is_empty() {
            return None;
        }
        let seed = crate::ledger::load_seed().ok().flatten()?;
        Some((me, seed))
    })
    .await
    else {
        return;
    };
    let Ok(key) = crate::account_record::signing_key(&seed) else { return };
    if crate::market_chain::address_of(&key.verifying_key().to_bytes()) != me || sealed.to == me {
        return;
    }
    let my_ed = hex::encode(key.verifying_key().to_bytes());
    let local = sealed.clone();
    let by = me.clone();
    let _ = tokio::task::spawn_blocking(move || {
        let now = chrono::Utc::now();
        let own = crate::account_record::own_node();
        if holds(&local.to, &own, now.timestamp()) {
            keep(&local, &by, now.timestamp_millis());
        }
    })
    .await;
    put_at_places(&me, &key, &my_ed, sealed).await;
}

pub async fn mirror(inner: crate::p2p::P2PMessage) {
    let Ok(Some((me, seed))) = tokio::task::spawn_blocking(|| {
        let me = crate::ledger::Ledger::load().address;
        if me.is_empty() || !phone_present(&me) {
            return None;
        }
        let seed = crate::ledger::load_seed().ok().flatten()?;
        Some((me, seed))
    })
    .await
    else {
        return;
    };
    let Ok(key) = crate::account_record::signing_key(&seed) else { return };
    if crate::market_chain::address_of(&key.verifying_key().to_bytes()) != me {
        return;
    }
    let my_ed = hex::encode(key.verifying_key().to_bytes());
    let Some(sealed) = crate::p2p::seal_dm(&me, &my_ed, &inner).as_ref().and_then(from_p2p) else { return };
    push_own(&me, &key, &my_ed, sealed).await;
}

fn cursor_path(owner: &str) -> PathBuf {
    dir().join(format!("{owner}.cursors.json"))
}

fn load_cursors(owner: &str) -> HashMap<String, i64> {
    std::fs::read(cursor_path(owner)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn save_cursors(owner: &str, cursors: &HashMap<String, i64>) {
    let _ = std::fs::create_dir_all(dir());
    if let Ok(bytes) = serde_json::to_vec(cursors) {
        let _ = crate::utils::atomic_write(&cursor_path(owner), &bytes);
    }
}

async fn bootstrap_gateways(now: i64) {
    {
        let mut at = BOOTSTRAPPED_AT.lock().unwrap_or_else(|e| e.into_inner());
        if now - *at < BOOTSTRAP_EVERY_SECS {
            return;
        }
        *at = now;
    }
    let Some(client) = reqwest::Client::builder().timeout(std::time::Duration::from_secs(10)).build().ok() else { return };
    let Ok(resp) = client.get(format!("{}/gateways", crate::p2p::ORACLE_RPC)).send().await else { return };
    let Ok(body) = resp.json::<Value>().await else { return };
    for a in body["gateways"].as_array().cloned().unwrap_or_default() {
        if let Ok(a) = serde_json::from_value::<crate::gateway::Announcement>(a) {
            crate::gateway::learn(a, now);
        }
    }
}

fn own_places(me: &str, now: i64) -> Vec<(String, String)> {
    let nodes = crate::account_record::listed_nodes(now);
    let names: Vec<String> = nodes.iter().map(|(n, _)| n.clone()).collect();
    crate::account_record::places(me, &names, crate::account_record::PLACES)
        .into_iter()
        .filter(|n| n != me)
        .filter_map(|n| nodes.iter().find(|(m, _)| m == &n).cloned())
        .collect()
}

pub fn worth_opening(kept: &Kept, me: &str, since: i64) -> bool {
    kept.at > since && kept.sealed.to == me && kept.by != me && valid(&kept.sealed)
}

pub async fn catch_up() {
    let Ok(Some((me, seed))) = tokio::task::spawn_blocking(|| {
        let me = crate::ledger::Ledger::load().address;
        if me.is_empty() {
            return None;
        }
        Some((me, crate::ledger::load_seed().ok().flatten()?))
    })
    .await
    else {
        return;
    };
    let Ok(key) = crate::account_record::signing_key(&seed) else { return };
    if crate::market_chain::address_of(&key.verifying_key().to_bytes()) != me {
        return;
    }
    let now = chrono::Utc::now();
    let mut places = own_places(&me, now.timestamp());
    if places.is_empty() {
        bootstrap_gateways(now.timestamp()).await;
        places = own_places(&me, now.timestamp());
    }
    if places.is_empty() {
        return;
    }
    use ed25519_dalek::Signer;
    let pubkey = hex::encode(key.verifying_key().to_bytes());
    let owner = me.clone();
    let mut cursors = tokio::task::spawn_blocking(move || load_cursors(&owner)).await.unwrap_or_default();
    let floor = now.timestamp_millis() - CATCH_UP_LOOK_BACK_MS;
    let mut opened = 0usize;
    for (node, endpoint) in places {
        let mut since = cursors.get(&node).copied().unwrap_or(floor).max(floor);
        for _ in 0..CATCH_UP_PAGES {
            let ts = chrono::Utc::now().timestamp();
            let sig = key.sign(&get_bytes(&me, ts));
            let params = json!({ "owner": me, "ts": ts, "since": since, "pubkey": pubkey, "sig": hex::encode(sig.to_bytes()) });
            let Some(answer) = crate::account_record::call_peer(&endpoint, "mail.get", params).await else { break };
            let mail: Vec<Kept> = serde_json::from_value(answer["mail"].clone()).unwrap_or_default();
            if mail.is_empty() {
                break;
            }
            for kept in &mail {
                if !worth_opening(kept, &me, since) || crate::p2p::dm_already_seen(&kept.sealed.id) {
                    continue;
                }
                if let Some(inner) = crate::p2p::open_dm(&kept.sealed.eph_pub, &kept.sealed.nonce, &kept.sealed.ct) {
                    crate::p2p::handle_incoming(inner, crate::p2p::APP_HANDLE.get()).await;
                    opened += 1;
                }
            }
            since = mail.iter().map(|k| k.at).max().unwrap_or(since).max(since);
            if !answer["more"].as_bool().unwrap_or(false) {
                break;
            }
        }
        cursors.insert(node, since);
    }
    let owner = me.clone();
    let _ = tokio::task::spawn_blocking(move || save_cursors(&owner, &cursors)).await;
    if opened > 0 {
        tracing::info!("[Mail] picked up {opened} messages sent while this computer was away");
    }
}

pub async fn run_catch_up() {
    tokio::time::sleep(std::time::Duration::from_secs(CATCH_UP_FIRST_SECS)).await;
    loop {
        catch_up().await;
        tokio::time::sleep(std::time::Duration::from_secs(CATCH_UP_EVERY_SECS)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealed(to: &str, n: u8) -> Sealed {
        let ct = hex::encode([n; 40]);
        Sealed { to: to.into(), eph_pub: "ab".repeat(32), nonce: "cd".repeat(12), id: id_of(&ct), ct, alert: String::new() }
    }

    fn kept(to: &str, n: u8, by: &str, at: i64) -> Kept {
        Kept { sealed: sealed(to, n), at, by: by.into() }
    }

    #[test]
    fn only_well_formed_sealed_mail_is_kept() {
        let good = sealed("egot1phone", 1);
        assert!(valid(&good));
        assert!(!valid(&Sealed { id: "00".repeat(16), ..good.clone() }), "the id must be the ciphertext's");
        assert!(!valid(&Sealed { eph_pub: "zz".repeat(32), ..good.clone() }));
        assert!(!valid(&Sealed { to: "not an address".into(), ..good.clone() }));
        let huge = "ab".repeat(MAX_CT_HEX);
        assert!(!valid(&Sealed { id: id_of(&huge), ct: huge, ..good }));
    }

    #[test]
    fn a_noisy_sender_cannot_push_everyone_else_out_of_a_mailbox() {
        let owner = "egot1phone";
        let mut list: Vec<Kept> = (0..10).map(|i| kept(owner, i, "egot1friend", i as i64)).collect();
        list.extend((0..(MAX_PER_SENDER + 50)).map(|i| kept(owner, (i % 250) as u8, "", 100 + i as i64)));
        list.extend((0..(MAX_PER_SENDER + 5)).map(|i| kept(owner, 3, owner, 1_000 + i as i64)));
        trim(&mut list, owner);
        assert_eq!(list.iter().filter(|k| k.by == "egot1friend").count(), 10);
        assert_eq!(list.iter().filter(|k| k.by.is_empty()).count(), MAX_PER_SENDER);
        assert_eq!(list.iter().filter(|k| k.by == owner).count(), MAX_PER_SENDER + 5, "a wallet's own copies are only held to the mailbox size");
        assert!(list.len() <= MAX_PER_OWNER);
    }

    fn message(id: &str, from: &str, to: &str, ts: i64, outgoing: bool, kind: &str) -> crate::commands::messenger::Message {
        crate::commands::messenger::Message {
            id: id.into(),
            from: from.into(),
            to: to.into(),
            content: format!("text {id}"),
            message_type: kind.into(),
            timestamp: ts,
            outgoing,
            read: true,
            read_by_recipient: false,
            delivered: true,
            reply_to: None,
            reactions: Vec::new(),
            edited_at: None,
        }
    }

    #[test]
    fn history_keeps_the_latest_messages_of_each_conversation_without_reactions_or_edits() {
        let mut all = Vec::new();
        for i in 0..(HISTORY_PER_CONTACT as i64 + 30) {
            all.push(message(&format!("a{i}"), "egot1me", "egot1ann", i, true, "text"));
        }
        all.push(message("b1", "egot1bob", "egot1me", 5, false, "text"));
        all.push(message("r1", "egot1bob", "egot1me", 6, false, "reaction"));
        let kept = history_messages(&all);
        assert_eq!(kept.iter().filter(|m| m.to == "egot1ann").count(), HISTORY_PER_CONTACT);
        assert!(kept.iter().any(|m| m.id == "b1"));
        assert!(!kept.iter().any(|m| m.id == "r1"));
        assert!(!kept.iter().any(|m| m.id == "a0"), "the oldest of a long conversation is left out");
        assert!(kept.windows(2).all(|w| w[0].ts <= w[1].ts));

        let chunks = history_chunks(&kept, &[HistoryProfile { address: "egot1bob".into(), name: "Bob".into(), avatar: "data:image/png;base64,AA".into() }]);
        assert!(chunks.len() >= 2);
        let total: usize = chunks
            .iter()
            .map(|c| serde_json::from_slice::<Value>(c).unwrap()["messages"].as_array().unwrap().len())
            .sum();
        assert_eq!(total, kept.len());
        assert!(chunks.iter().all(|c| c.len() <= HISTORY_CHUNK_BYTES + 2_048));
    }

    #[test]
    fn a_desktop_only_opens_new_mail_others_sent_it() {
        let me = "egot1me";
        let fresh = kept(me, 1, "egot1friend", 500);
        assert!(worth_opening(&fresh, me, 400));
        assert!(!worth_opening(&fresh, me, 500), "already read up to here");
        assert!(!worth_opening(&kept(me, 2, me, 600), me, 400), "its own copies are for the phone");
        assert!(!worth_opening(&kept("egot1other", 3, "egot1friend", 600), me, 400));
    }

    #[test]
    fn an_alert_key_the_wallet_gave_can_see_that_mail_waits_and_nothing_else() {
        use ed25519_dalek::Signer;
        let wallet = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let owner = crate::market_chain::address_of(&wallet.verifying_key().to_bytes());
        let reader = ed25519_dalek::SigningKey::from_bytes(&[6u8; 32]);
        let reader_hex = hex::encode(reader.verifying_key().to_bytes());
        let now = 1_000_000;
        let until = now + 90 * 86_400;
        let grant = hex::encode(wallet.sign(&reader_bytes(&owner, &reader_hex, until)).to_bytes());
        let params = |reader_key: &ed25519_dalek::SigningKey, until: i64, grant: &str| {
            let sig = reader_key.sign(&peek_bytes(&owner, &reader_hex, now, 7));
            json!({
                "owner": owner, "ts": now, "since": 7, "reader": reader_hex, "until": until,
                "grant": grant, "pubkey": hex::encode(wallet.verifying_key().to_bytes()),
                "sig": hex::encode(sig.to_bytes()),
            })
        };
        assert!(reader_allowed(&params(&reader, until, &grant), &owner, now).is_ok());
        let stranger = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        assert!(reader_allowed(&params(&stranger, until, &grant), &owner, now).is_err(), "only the key the wallet named");
        assert!(reader_allowed(&params(&reader, until + 1, &grant), &owner, now).is_err(), "the grant covers its end date");
        assert!(reader_allowed(&params(&reader, until, &grant), &owner, until + 1).is_err(), "an old grant stops working");
        let self_made = hex::encode(stranger.sign(&reader_bytes(&owner, &reader_hex, until)).to_bytes());
        assert!(reader_allowed(&params(&reader, until, &self_made), &owner, now).is_err(), "nobody else can grant one");
        let long = now + READER_GRANT_MAX_SECS + 10;
        let long_grant = hex::encode(wallet.sign(&reader_bytes(&owner, &reader_hex, long)).to_bytes());
        assert!(reader_allowed(&params(&reader, long, &long_grant), &owner, now).is_err());
    }

    #[test]
    fn a_peek_names_only_new_alerting_mail_and_moves_past_the_rest() {
        let owner = "egot1phone";
        let mut list: Vec<Kept> = (1..=6).map(|i| kept(owner, i, "", i as i64 * 100)).collect();
        list[1].sealed.alert = ALERT_CHAT.into();
        list[3].sealed.alert = ALERT_REQUEST.into();
        list[4].sealed.alert = ALERT_CHAT.into();
        let (alerts, latest) = alerts_in(list.clone(), 250, 1_000);
        assert_eq!(latest, 600, "receipts and profile changes still move the cursor");
        let ids: Vec<&str> = alerts.iter().map(|a| a["id"].as_str().unwrap()).collect();
        assert_eq!(ids, vec![list[4].sealed.id.as_str(), list[3].sealed.id.as_str()]);
        assert_eq!(alerts[1]["alert"], ALERT_REQUEST);
        assert!(alerts[0].get("ct").is_none(), "a peek carries no message");
        let (none, same) = alerts_in(list, 600, 1_000);
        assert!(none.is_empty());
        assert_eq!(same, 600);
    }

    #[test]
    fn only_known_alert_kinds_are_kept() {
        let mut s = sealed("egot1phone", 1);
        s.alert = ALERT_CHAT.into();
        assert!(valid(&s));
        s.alert = ALERT_REQUEST.into();
        assert!(valid(&s));
        s.alert = "x".repeat(5000);
        assert!(!valid(&s));
    }

    #[test]
    fn requests_are_bound_to_the_wallet_and_the_message() {
        assert_eq!(get_bytes("egot1a", 5), b"ego/mail-get/v1\negot1a\n5".to_vec());
        assert_eq!(put_bytes("egot1a", "egot1b", 5, "ff"), b"ego/mail-put/v1\negot1a\negot1b\n5\nff".to_vec());
        assert_eq!(send_bytes("egot1a", "egot1b", 5, "ff"), b"ego/mail-send/v1\negot1a\negot1b\n5\nff".to_vec());
    }
}
