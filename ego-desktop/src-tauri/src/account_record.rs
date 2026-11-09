use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Mutex;

pub const DOMAIN: &str = "ego/account-record/v1";
pub const DELIVER_DOMAIN: &str = "ego/messenger-deliver/v1";
pub const SLOT_DESKTOP: &str = "desktop";
pub const SLOT_PHONE: &str = "phone";
pub const MAX_DATA_BYTES: usize = 256 * 1024;
pub const PLACES: usize = 4;
const ACCEPT_RANK: usize = PLACES * 2;
const FUTURE_SKEW_MS: i64 = 5 * 60 * 1000;
const STORE_CAP_BYTES: u64 = 128 * 1024 * 1024;
const REPUBLISH_SECS: i64 = 6 * 3600;
const LOOP_SECS: u64 = 600;
const FIRST_RUN_SECS: u64 = 45;
const MAX_CONTACTS: usize = 500;
const MAX_FILES: usize = 1000;
const MAX_PAYMENTS: usize = 300;
const MAX_SENT: usize = 300;
const MAX_BUNDLE_BYTES: usize = 32 * 1024;
const DELIVER_SKEW_SECS: i64 = 600;
const DELIVERIES_PER_MINUTE: usize = 30;

type RpcResult = Result<Value, (i32, String)>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Envelope {
    pub owner: String,
    pub pubkey: String,
    pub slot: String,
    pub ver: i64,
    pub data: String,
    pub sig: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SyncContact {
    pub address: String,
    pub name: String,
    pub ed25519: String,
    pub shared_key_hex: String,
    #[serde(default)]
    pub endpoint: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SyncFile {
    pub cid: String,
    pub name: String,
    pub size: u64,
    pub key_nonce_hex: String,
    pub stored_at: i64,
    #[serde(default)]
    pub received: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SyncPayment {
    pub hash: String,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub timestamp: i64,
    #[serde(default)]
    pub memo: Option<String>,
    #[serde(default)]
    pub tx_type: Option<String>,
    #[serde(default)]
    pub block_height: Option<u64>,
    #[serde(default)]
    pub fee_uegoc: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SyncSent {
    pub id: String,
    pub to: String,
    pub content: String,
    pub message_type: String,
    pub ts: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Content {
    #[serde(default)]
    pub v: u32,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub bundle: String,
    #[serde(default)]
    pub contacts: Vec<SyncContact>,
    #[serde(default)]
    pub files: Vec<SyncFile>,
    #[serde(default)]
    pub payments: Vec<SyncPayment>,
    #[serde(default)]
    pub sent: Vec<SyncSent>,
    #[serde(default)]
    pub want_history: i64,
    #[serde(default)]
    pub avatar: String,
    #[serde(default)]
    pub avatar_at: i64,
    #[serde(default)]
    pub token: String,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn signing_bytes(owner: &str, slot: &str, ver: i64, data: &str) -> Vec<u8> {
    format!("{DOMAIN}\n{owner}\n{slot}\n{ver}\n{}", sha256_hex(data.as_bytes())).into_bytes()
}

pub fn deliver_bytes(owner: &str, to: &str, ts: i64, bundle: &str) -> Vec<u8> {
    format!("{DELIVER_DOMAIN}\n{owner}\n{to}\n{ts}\n{}", sha256_hex(bundle.as_bytes())).into_bytes()
}

pub fn record_key(seed: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(format!("{DOMAIN}/key\n").as_bytes());
    h.update(seed);
    h.finalize().into()
}

pub(crate) fn signing_key(seed: &[u8]) -> Result<ed25519_dalek::SigningKey, String> {
    let bytes: [u8; 32] = seed.try_into().map_err(|_| "The wallet seed is not 32 bytes.".to_string())?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&bytes))
}

pub fn seal(content: &Content, seed: &[u8], slot: &str, ver: i64) -> Result<Envelope, String> {
    use ed25519_dalek::Signer;
    let plain = serde_json::to_vec(content).map_err(|e| e.to_string())?;
    let cipher = Aes256Gcm::new_from_slice(&record_key(seed)).map_err(|e| e.to_string())?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher.encrypt(Nonce::from_slice(&nonce), plain.as_ref()).map_err(|e| e.to_string())?;
    let mut sealed = nonce.to_vec();
    sealed.extend_from_slice(&ct);
    if sealed.len() > MAX_DATA_BYTES {
        return Err("The account record is too large.".into());
    }
    let key = signing_key(seed)?;
    let pk = key.verifying_key().to_bytes();
    let owner = crate::market_chain::address_of(&pk);
    let data = STANDARD.encode(&sealed);
    let sig = key.sign(&signing_bytes(&owner, slot, ver, &data));
    Ok(Envelope { owner, pubkey: hex::encode(pk), slot: slot.to_string(), ver, data, sig: hex::encode(sig.to_bytes()) })
}

pub fn open(env: &Envelope, seed: &[u8]) -> Result<Content, String> {
    let sealed = STANDARD.decode(&env.data).map_err(|_| "The account record isn't valid base64.".to_string())?;
    if sealed.len() <= 12 {
        return Err("The account record is empty.".into());
    }
    let cipher = Aes256Gcm::new_from_slice(&record_key(seed)).map_err(|e| e.to_string())?;
    let plain = cipher
        .decrypt(Nonce::from_slice(&sealed[..12]), &sealed[12..])
        .map_err(|_| "This account record was not written by this wallet.".to_string())?;
    serde_json::from_slice(&plain).map_err(|e| e.to_string())
}

pub(crate) fn valid_owner(owner: &str) -> bool {
    owner.starts_with("ego") && owner.len() <= 90 && owner.bytes().all(|c| c.is_ascii_alphanumeric())
}

fn valid_slot(slot: &str) -> bool {
    slot == SLOT_DESKTOP || slot == SLOT_PHONE
}

pub(crate) fn signer_of(pubkey: &str, sig: &str, message: &[u8]) -> Result<String, String> {
    use ed25519_dalek::{Signature, VerifyingKey};
    let bad = || "This record isn't signed by the wallet it names.".to_string();
    let pk: [u8; 32] = hex::decode(pubkey).ok().and_then(|v| v.try_into().ok()).ok_or_else(bad)?;
    let sig: [u8; 64] = hex::decode(sig).ok().and_then(|v| v.try_into().ok()).ok_or_else(bad)?;
    VerifyingKey::from_bytes(&pk)
        .map_err(|_| bad())?
        .verify_strict(message, &Signature::from_bytes(&sig))
        .map_err(|_| bad())?;
    Ok(crate::market_chain::address_of(&pk))
}

pub fn check(env: &Envelope, now_ms: i64) -> Result<(), String> {
    if !valid_owner(&env.owner) || !valid_slot(&env.slot) {
        return Err("This isn't an account record.".into());
    }
    if env.ver <= 0 || env.ver > now_ms + FUTURE_SKEW_MS {
        return Err("The record's time is off. Check the device's date and time.".into());
    }
    if env.data.len() > MAX_DATA_BYTES * 4 / 3 + 4 {
        return Err("The account record is too large.".into());
    }
    if signer_of(&env.pubkey, &env.sig, &signing_bytes(&env.owner, &env.slot, env.ver, &env.data))? != env.owner {
        return Err("This record isn't signed by the wallet it names.".into());
    }
    Ok(())
}

pub fn score(owner: &str, node: &str) -> [u8; 32] {
    Sha256::digest(format!("{owner}\n{node}").as_bytes()).into()
}

pub fn places(owner: &str, nodes: &[String], k: usize) -> Vec<String> {
    let mut ranked: Vec<(&String, [u8; 32])> = nodes.iter().map(|n| (n, score(owner, n))).collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    ranked.dedup_by(|a, b| a.0 == b.0);
    ranked.into_iter().take(k).map(|(n, _)| n.clone()).collect()
}

pub fn should_hold(owner: &str, me: &str, others: &[String]) -> bool {
    if owner == me {
        return true;
    }
    let mut all: Vec<String> = others.iter().filter(|n| n.as_str() != me).cloned().collect();
    all.sort();
    all.dedup();
    all.push(me.to_string());
    all.len() <= ACCEPT_RANK || places(owner, &all, ACCEPT_RANK).iter().any(|n| n == me)
}

fn dir() -> PathBuf {
    crate::ledger::base_data_dir().join("account_records")
}

fn path(owner: &str, slot: &str) -> PathBuf {
    dir().join(format!("{owner}.{slot}.json"))
}

pub fn stored(owner: &str, slot: &str) -> Option<Envelope> {
    if !valid_owner(owner) || !valid_slot(slot) {
        return None;
    }
    std::fs::read(path(owner, slot)).ok().and_then(|b| serde_json::from_slice(&b).ok())
}

static USAGE: Mutex<Option<u64>> = Mutex::new(None);

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

pub fn store(env: &Envelope) -> Result<bool, String> {
    if let Some(prev) = stored(&env.owner, &env.slot) {
        if prev.ver >= env.ver {
            return Ok(false);
        }
    }
    std::fs::create_dir_all(dir()).map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec(env).map_err(|e| e.to_string())?;
    let p = path(&env.owner, &env.slot);
    crate::utils::atomic_write(&p, &bytes).map_err(|e| e.to_string())?;
    evict_if_full(bytes.len() as u64, &p);
    Ok(true)
}

pub fn newest(candidates: Vec<Envelope>, owner: &str, slot: &str, now_ms: i64) -> Option<Envelope> {
    candidates
        .into_iter()
        .filter(|e| e.owner == owner && e.slot == slot && check(e, now_ms).is_ok())
        .max_by_key(|e| e.ver)
}

pub(crate) fn own_node() -> String {
    crate::ledger::Ledger::load().address
}

pub(crate) fn listed_nodes(now: i64) -> Vec<(String, String)> {
    crate::gateway::share(now).into_iter().map(|a| (a.node, a.endpoint)).collect()
}

async fn get(params: &Value) -> RpcResult {
    let owner = params["owner"].as_str().unwrap_or_default().to_string();
    let slot = params["slot"].as_str().unwrap_or(SLOT_DESKTOP).to_string();
    if !valid_owner(&owner) || !valid_slot(&slot) {
        return Err((-32602, "owner must be a wallet address and slot desktop or phone".into()));
    }
    let found = tokio::task::spawn_blocking(move || stored(&owner, &slot)).await.map_err(|e| (-32603, e.to_string()))?;
    Ok(json!({ "record": found }))
}

async fn put(params: &Value) -> RpcResult {
    let env: Envelope = serde_json::from_value(params["record"].clone())
        .map_err(|_| (-32602, "record must be an account record".to_string()))?;
    let now = chrono::Utc::now();
    check(&env, now.timestamp_millis()).map_err(|e| (-32003, e))?;
    let others: Vec<String> = listed_nodes(now.timestamp()).into_iter().map(|(n, _)| n).collect();
    tokio::task::spawn_blocking(move || {
        let me = own_node();
        if !should_hold(&env.owner, &me, &others) {
            return Err((-32004, "This gateway is not one of the places that keep this wallet's record.".to_string()));
        }
        let saved = store(&env).map_err(|e| (-32603, e))?;
        let ver = stored(&env.owner, &env.slot).map(|e| e.ver).unwrap_or(env.ver);
        Ok(json!({ "stored": saved, "ver": ver }))
    })
    .await
    .map_err(|e| (-32603, e.to_string()))?
}

static DELIVERIES: Mutex<Option<HashMap<String, VecDeque<i64>>>> = Mutex::new(None);

fn delivery_allowed(owner: &str, now: i64) -> bool {
    let mut guard = DELIVERIES.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    if map.len() > 50_000 {
        map.retain(|_, q| q.back().map(|t| now - t < 60).unwrap_or(false));
    }
    let q = map.entry(owner.to_string()).or_default();
    while q.front().map(|t| now - t >= 60).unwrap_or(false) {
        q.pop_front();
    }
    if q.len() >= DELIVERIES_PER_MINUTE {
        return false;
    }
    q.push_back(now);
    true
}

pub fn bundle_parties(bundle: &str) -> Option<(String, String, i64)> {
    let s = bundle.strip_prefix("egomsg1:")?;
    let parts: Vec<&str> = s.splitn(6, ':').collect();
    if parts.len() != 6 {
        return None;
    }
    Some((parts[0].to_string(), parts[1].to_string(), parts[2].parse().ok()?))
}

pub fn deliver_check(params: &Value, now: i64) -> Result<(String, String, String, String), (i32, String)> {
    let owner = params["owner"].as_str().unwrap_or_default().to_string();
    let to = params["to"].as_str().unwrap_or_default().to_string();
    let to_ed25519 = params["to_ed25519"].as_str().unwrap_or_default().to_string();
    let bundle = params["bundle"].as_str().unwrap_or_default().to_string();
    let ts = params["ts"].as_i64().unwrap_or_default();
    if !valid_owner(&owner) || !valid_owner(&to) || owner == to {
        return Err((-32602, "owner and to must be two wallet addresses".into()));
    }
    if bundle.is_empty() || bundle.len() > MAX_BUNDLE_BYTES || to_ed25519.is_empty() || to_ed25519.len() > 100 {
        return Err((-32602, "The message is empty or too large.".into()));
    }
    if (ts - now).abs() > DELIVER_SKEW_SECS {
        return Err((-32003, "The request's time is off. Check your phone's date and time.".into()));
    }
    let signer = signer_of(
        params["pubkey"].as_str().unwrap_or_default(),
        params["sig"].as_str().unwrap_or_default(),
        &deliver_bytes(&owner, &to, ts, &bundle),
    )
    .map_err(|e| (-32003, e))?;
    if signer != owner {
        return Err((-32003, "This request isn't signed by the wallet it names.".into()));
    }
    match bundle_parties(&bundle) {
        Some((from, dest, at)) if from == owner && dest == to && (at - now).abs() <= DELIVER_SKEW_SECS => {}
        _ => return Err((-32602, "The message doesn't match who sends it, who gets it or when.".into())),
    }
    Ok((owner, to, to_ed25519, bundle))
}

async fn deliver(params: &Value) -> RpcResult {
    let now = chrono::Utc::now().timestamp();
    let (owner, to, to_ed25519, bundle) = deliver_check(params, now)?;
    if !delivery_allowed(&owner, now) {
        return Err((-32005, "Too many messages in a minute. Wait a moment and try again.".into()));
    }
    let msg = crate::p2p::P2PMessage::ChatMessage { bundle, seq: 0 };
    let Some(sealed) = crate::p2p::seal_dm(&to, &to_ed25519, &msg) else {
        return Err((-32602, "The contact's key couldn't be used to seal the message.".into()));
    };
    if let Ok(data) = serde_json::to_vec(&sealed) {
        crate::p2p::publish_gossip(crate::p2p::DM_TOPIC, data).await;
    }
    if let Some(mail) = crate::phone_mail::from_p2p(&sealed) {
        let _ = tokio::task::spawn_blocking(move || crate::phone_mail::on_gossip(mail, &own_node())).await;
    }
    crate::p2p::dht_inbox_deposit(&owner, &to, &msg).await;
    if tokio::task::spawn_blocking(own_node).await.unwrap_or_default() == to {
        crate::p2p::handle_incoming(msg, crate::p2p::APP_HANDLE.get()).await;
    }
    Ok(json!({ "sent": true }))
}

pub const METHODS: &[&str] = &["account.get", "account.put", "messenger.deliver"];

pub async fn dispatch(method: &str, params: &Value) -> Option<RpcResult> {
    Some(match method {
        "account.get" => get(params).await,
        "account.put" => put(params).await,
        "messenger.deliver" => deliver(params).await,
        _ => return None,
    })
}

static WAKE: tokio::sync::Notify = tokio::sync::Notify::const_new();

pub fn changed() {
    WAKE.notify_one();
}

struct Published {
    fingerprint: String,
    at: i64,
    owner: String,
}

static LAST: Mutex<Option<Published>> = Mutex::new(None);

static PEER_CLIENT: once_cell::sync::Lazy<Option<reqwest::Client>> = once_cell::sync::Lazy::new(|| {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .ok()
});

fn big_endpoint(rpc_endpoint: &str) -> String {
    rpc_endpoint.strip_suffix("/rpc").map(|b| format!("{b}/storage")).unwrap_or_else(|| rpc_endpoint.to_string())
}

pub(crate) async fn call_peer(endpoint: &str, method: &str, params: Value) -> Option<Value> {
    let client = PEER_CLIENT.as_ref()?;
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let resp = client.post(big_endpoint(endpoint)).json(&body).send().await.ok()?;
    let v: Value = resp.json().await.ok()?;
    v.get("result").cloned()
}

fn payment_of(tx: &crate::ledger::LedgerTx) -> SyncPayment {
    SyncPayment {
        hash: tx.hash.clone(),
        from: tx.from.clone(),
        to: tx.to.clone(),
        amount: tx.amount,
        timestamp: tx.timestamp,
        memo: tx.memo.clone(),
        tx_type: Some(tx.tx_type.clone()),
        block_height: tx.block_height,
        fee_uegoc: Some(tx.fee_uegoc),
    }
}

fn build_content(ledger: &crate::ledger::Ledger, bundle: String) -> Content {
    use crate::chain_db::TxKind;
    let me = ledger.address.clone();
    let mut contacts: Vec<SyncContact> = crate::commands::messenger::load_contacts()
        .into_iter()
        .filter(|c| c.status == "approved" && !c.shared_key_hex.is_empty())
        .map(|c| SyncContact {
            address: c.address,
            name: c.name,
            ed25519: c.ed25519_pubkey,
            shared_key_hex: c.shared_key_hex,
            endpoint: c.endpoint,
        })
        .collect();
    contacts.sort_by(|a, b| a.address.cmp(&b.address));
    contacts.truncate(MAX_CONTACTS);

    let mut files: Vec<SyncFile> = ledger
        .stored_files
        .iter()
        .filter(|f| (f.owner.is_empty() || f.owner == me) && (f.status == "Active" || f.status == "Received"))
        .filter(|f| !f.key_nonce_hex.is_empty())
        .filter_map(|f| {
            let key = crate::ledger::unprotect_key_bytes(&f.key_nonce_hex);
            (key.len() >= 32).then(|| SyncFile {
                cid: f.cid.clone(),
                name: f.name.clone(),
                size: f.original_size,
                key_nonce_hex: hex::encode(key),
                stored_at: f.stored_at,
                received: f.from_egosafe,
            })
        })
        .collect();
    files.sort_by(|a, b| b.stored_at.cmp(&a.stored_at).then_with(|| a.cid.cmp(&b.cid)));
    files.dedup_by(|a, b| a.cid == b.cid);
    files.truncate(MAX_FILES);

    let mut payments: Vec<SyncPayment> = crate::chain_db::get_address_txs_of_kind(&me, MAX_PAYMENTS, Some(TxKind::Sent))
        .iter()
        .chain(crate::chain_db::get_address_txs_of_kind(&me, MAX_PAYMENTS, Some(TxKind::Received)).iter())
        .map(payment_of)
        .collect();
    payments.sort_by(|a, b| b.timestamp.cmp(&a.timestamp).then_with(|| a.hash.cmp(&b.hash)));
    payments.dedup_by(|a, b| a.hash == b.hash);
    payments.truncate(MAX_PAYMENTS);

    Content {
        v: 1,
        name: crate::commands::messenger::my_display_name(),
        bundle,
        contacts,
        files,
        payments,
        sent: Vec::new(),
        ..Content::default()
    }
}

const MAX_PHONE_AVATAR_BYTES: usize = 96 * 1024;

fn avatar_marker(owner: &str) -> PathBuf {
    dir().join(format!("{owner}.avatar_at"))
}

pub fn merge_phone(content: &Content, me: &str) -> usize {
    use crate::commands::messenger::{load_contacts, save_contacts, Contact, CONTACTS_LOCK};
    let mut changed = 0;
    {
        let _cg = CONTACTS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut contacts = load_contacts();
        for c in content.contacts.iter().take(MAX_CONTACTS) {
            if c.address == me || !valid_owner(&c.address) || c.shared_key_hex.len() != 64 || c.ed25519.is_empty() {
                continue;
            }
            match contacts.iter_mut().find(|k| k.address == c.address) {
                Some(k) if k.status == "pending_in" || (k.status == "pending_out" && k.shared_key_hex == c.shared_key_hex) => {
                    k.status = "approved".into();
                    k.shared_key_hex = c.shared_key_hex.clone();
                    changed += 1;
                }
                Some(_) => {}
                None => {
                    contacts.push(Contact {
                        address: c.address.clone(),
                        name: c.name.clone(),
                        ed25519_pubkey: c.ed25519.clone(),
                        kyber_pubkey: String::new(),
                        shared_key_hex: c.shared_key_hex.clone(),
                        status: "approved".into(),
                        added_at: chrono::Utc::now().timestamp(),
                        endpoint: c.endpoint.clone(),
                        all_endpoints: Vec::new(),
                        ratchet_send_chain: String::new(),
                        ratchet_recv_chain: String::new(),
                        ratchet_send_count: 0,
                        ratchet_recv_count: 0,
                        bundle_token: None,
                        avatar: String::new(),
                        last_request_at: 0,
                    });
                    changed += 1;
                }
            }
        }
        if changed > 0 {
            let _ = save_contacts(&contacts);
        }
    }
    let applied: i64 = std::fs::read_to_string(avatar_marker(me)).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
    if content.avatar_at > applied
        && content.avatar.len() <= MAX_PHONE_AVATAR_BYTES
        && (content.avatar.is_empty() || (content.avatar.starts_with("data:image/") && content.avatar.contains(";base64,")))
    {
        let mut ledger = crate::ledger::Ledger::load();
        if ledger.address == me {
            ledger.avatar = content.avatar.clone();
            if ledger.save().is_ok() {
                let _ = std::fs::create_dir_all(dir());
                let _ = std::fs::write(avatar_marker(me), content.avatar_at.to_string());
                changed += 1;
            }
        }
    }
    changed
}

pub fn merge_sent(sent: &[SyncSent], me: &str) -> usize {
    use crate::commands::messenger::{load_contacts, load_messages, save_messages, Message};
    let contacts = load_contacts();
    let mut msgs = load_messages();
    let mut added = 0;
    for s in sent.iter().take(MAX_SENT) {
        if !contacts.iter().any(|c| c.address == s.to) || msgs.iter().any(|m| m.id == s.id) {
            continue;
        }
        msgs.push(Message {
            id: s.id.clone(),
            from: me.to_string(),
            to: s.to.clone(),
            content: s.content.clone(),
            message_type: s.message_type.clone(),
            timestamp: s.ts,
            outgoing: true,
            read: true,
            read_by_recipient: false,
            delivered: false,
            reply_to: None,
            reactions: Vec::new(),
            edited_at: None,
        });
        added += 1;
    }
    if added > 0 {
        msgs.sort_by_key(|m| m.timestamp);
        let _ = save_messages(&msgs);
    }
    added
}

async fn once() {
    let Ok(Some(seed)) = tokio::task::spawn_blocking(crate::ledger::load_seed).await.unwrap_or(Ok(None)) else {
        return;
    };
    let endpoint = crate::p2p::get_public_endpoint().await;
    let now = chrono::Utc::now();
    let seed_for_build = seed.clone();
    let built = tokio::task::spawn_blocking(move || {
        let ledger = crate::ledger::Ledger::load();
        if ledger.address.is_empty() {
            return None;
        }
        let key = signing_key(&seed_for_build).ok()?;
        if crate::market_chain::address_of(&key.verifying_key().to_bytes()) != ledger.address {
            return None;
        }
        let bundle = if endpoint.is_empty() {
            stored(&ledger.address, SLOT_DESKTOP)
                .and_then(|e| open(&e, &seed_for_build).ok())
                .map(|c| c.bundle)
                .unwrap_or_default()
        } else {
            crate::commands::messenger::contact_card(
                &ledger.address,
                &STANDARD.encode(key.verifying_key().to_bytes()),
                &crate::commands::messenger::my_display_name(),
                &endpoint,
                &crate::commands::messenger::ensure_bundle_token(),
            )
        };
        Some((ledger.address.clone(), build_content(&ledger, bundle)))
    })
    .await
    .ok()
    .flatten();
    let Some((owner, content)) = built else { return };

    let fingerprint = sha256_hex(&serde_json::to_vec(&content).unwrap_or_default());
    let due = {
        let last = LAST.lock().unwrap_or_else(|e| e.into_inner());
        match last.as_ref() {
            Some(p) => p.owner != owner || p.fingerprint != fingerprint || now.timestamp() - p.at >= REPUBLISH_SECS,
            None => true,
        }
    };
    let nodes = listed_nodes(now.timestamp());
    let names: Vec<String> = nodes.iter().map(|(n, _)| n.clone()).collect();
    let targets: Vec<String> = places(&owner, &names, PLACES)
        .into_iter()
        .filter(|n| n != &owner)
        .filter_map(|n| nodes.iter().find(|(m, _)| m == &n).map(|(_, e)| e.clone()))
        .collect();

    if due {
        match seal(&content, &seed, SLOT_DESKTOP, now.timestamp_millis()) {
            Ok(env) => {
                let e = env.clone();
                let _ = tokio::task::spawn_blocking(move || store(&e)).await;
                let record = serde_json::to_value(&env).unwrap_or(Value::Null);
                let pushes = targets.iter().map(|t| call_peer(t, "account.put", json!({ "record": record })));
                let answers = futures::future::join_all(pushes).await;
                let kept = answers.iter().filter(|a| a.is_some()).count();
                tracing::info!("[Account] record saved here and on {kept} of {} gateways", targets.len());
                *LAST.lock().unwrap_or_else(|e| e.into_inner()) = Some(Published { fingerprint, at: now.timestamp(), owner: owner.clone() });
            }
            Err(e) => tracing::warn!("[Account] record not saved: {e}"),
        }
    }

    let mut found: Vec<Envelope> = Vec::new();
    if let Some(e) = stored(&owner, SLOT_PHONE) {
        found.push(e);
    }
    let asks = targets.iter().map(|t| call_peer(t, "account.get", json!({ "owner": owner, "slot": SLOT_PHONE })));
    for answer in futures::future::join_all(asks).await.into_iter().flatten() {
        if let Ok(e) = serde_json::from_value::<Envelope>(answer["record"].clone()) {
            found.push(e);
        }
    }
    let Some(phone) = newest(found, &owner, SLOT_PHONE, now.timestamp_millis()) else { return };
    let p = phone.clone();
    let _ = tokio::task::spawn_blocking(move || store(&p)).await;
    if let Ok(content) = open(&phone, &seed) {
        let me = owner.clone();
        let want = content.want_history;
        let added = tokio::task::spawn_blocking(move || merge_sent(&content.sent, &me) + merge_phone(&content, &me)).await.unwrap_or(0);
        tokio::spawn(crate::phone_mail::backfill_if_asked(want));
        if added > 0 {
            if let Some(h) = crate::p2p::APP_HANDLE.get() {
                use tauri::Manager;
                let _ = h.emit_all("ego://message-sent", json!({ "from_phone": added }));
            }
        }
    }
}

pub async fn run() {
    tokio::time::sleep(std::time::Duration::from_secs(FIRST_RUN_SECS)).await;
    loop {
        once().await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(LOOP_SECS), WAKE.notified()).await;
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn content() -> Content {
        Content {
            v: 1,
            name: "Artit".into(),
            bundle: "egocontact1:egot1x:a:b:c:d".into(),
            contacts: vec![SyncContact { address: "egot1you".into(), name: "You".into(), ed25519: "k".into(), shared_key_hex: "00".repeat(32), endpoint: String::new() }],
            files: vec![SyncFile { cid: "egomfd1aa".into(), name: "cat.jpg".into(), size: 5, key_nonce_hex: "11".repeat(44), stored_at: 7, received: false }],
            payments: Vec::new(),
            sent: Vec::new(),
            ..Content::default()
        }
    }

    #[test]
    fn only_the_same_wallet_can_open_its_record_and_anyone_can_check_who_wrote_it() {
        let seed = [9u8; 32];
        let now = 1_800_000_000_000;
        let env = seal(&content(), &seed, SLOT_DESKTOP, now).unwrap();
        assert_eq!(env.owner, crate::market_chain::address_of(&SigningKey::from_bytes(&seed).verifying_key().to_bytes()));
        assert!(check(&env, now).is_ok());
        assert_eq!(open(&env, &seed).unwrap(), content());
        assert!(open(&env, &[8u8; 32]).is_err(), "another wallet's seed can't read it");
        assert!(!env.data.contains("cat.jpg"));

        let mut forged = env.clone();
        forged.ver += 1;
        assert!(check(&forged, now + 10).is_err(), "a new version needs a new signature");
        let mut other = env.clone();
        other.owner = seal(&content(), &[8u8; 32], SLOT_DESKTOP, now).unwrap().owner;
        assert!(check(&other, now).is_err(), "it can't be filed under someone else");
        let mut slot = env.clone();
        slot.slot = SLOT_PHONE.into();
        assert!(check(&slot, now).is_err(), "the slot is signed too");
        assert!(check(&env, now - FUTURE_SKEW_MS - 1).is_err(), "a version from the future is refused");
    }

    #[test]
    fn the_phone_and_the_desktop_derive_the_same_record_key() {
        let seed: Vec<u8> = (0u8..32).collect();
        let mut h = Sha256::new();
        h.update(b"ego/account-record/v1/key\n");
        h.update(&seed);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(record_key(&seed), expected);
        assert_eq!(
            String::from_utf8(signing_bytes("egot1me", "phone", 12, "QUJD")).unwrap(),
            format!("ego/account-record/v1\negot1me\nphone\n12\n{}", sha256_hex(b"QUJD"))
        );
    }

    #[test]
    fn the_newest_valid_version_wins() {
        let seed = [3u8; 32];
        let now = 1_800_000_000_000;
        let a = seal(&content(), &seed, SLOT_PHONE, now - 5000).unwrap();
        let b = seal(&content(), &seed, SLOT_PHONE, now - 1000).unwrap();
        let mut junk = b.clone();
        junk.ver = now;
        let owner = a.owner.clone();
        assert_eq!(newest(vec![a.clone(), junk, b.clone()], &owner, SLOT_PHONE, now).unwrap().ver, b.ver);
        assert!(newest(vec![a], &owner, SLOT_DESKTOP, now).is_none());
    }

    #[test]
    fn each_wallet_is_kept_by_a_few_gateways_and_every_node_agrees_which() {
        let nodes: Vec<String> = (0..50).map(|i| format!("egot1node{i}")).collect();
        let picked = places("egot1owner", &nodes, PLACES);
        assert_eq!(picked.len(), PLACES);
        let mut shuffled = nodes.clone();
        shuffled.reverse();
        assert_eq!(places("egot1owner", &shuffled, PLACES), picked);
        assert_ne!(places("egot1other", &nodes, PLACES), picked);

        let holders = nodes.iter().filter(|me| should_hold("egot1owner", me, &nodes)).count();
        assert_eq!(holders, ACCEPT_RANK);
        assert!(should_hold("egot1owner", "egot1owner", &nodes), "a wallet's own computer always keeps its record");
        assert!(should_hold("egot1owner", "egot1node3", &nodes[..5]), "a small network keeps everything");
    }

    fn deliver_params(seed: u8, to: &str, ts: i64, bundle: &str) -> Value {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let pk = key.verifying_key().to_bytes();
        let owner = crate::market_chain::address_of(&pk);
        let bundle = bundle.replace("{me}", &owner);
        let sig = key.sign(&deliver_bytes(&owner, to, ts, &bundle));
        json!({ "owner": owner, "pubkey": hex::encode(pk), "sig": hex::encode(sig.to_bytes()), "ts": ts, "to": to, "to_ed25519": "k", "bundle": bundle })
    }

    #[test]
    fn a_phone_can_only_send_messages_in_its_own_name() {
        let now = 1_800_000_000;
        let to = "egot1yqp37chf4jtrmsvxypnyvvjr43mashjuhukltzz8";
        let ok = deliver_params(4, to, now, &format!("egomsg1:{{me}}:{to}:{now}:file_bundle:00:11"));
        assert!(deliver_check(&ok, now).is_ok());

        let mut forged = ok.clone();
        forged["bundle"] = json!(format!("egomsg1:egot1someoneelse:{to}:{now}:text:00:11"));
        assert!(deliver_check(&forged, now).is_err());

        let elsewhere = deliver_params(4, to, now, &format!("egomsg1:{{me}}:egot1elsewhere:{now}:text:00:11"));
        assert!(deliver_check(&elsewhere, now).is_err(), "the message must go to who the request names");

        let old = deliver_params(4, to, now - DELIVER_SKEW_SECS - 1, &format!("egomsg1:{{me}}:{to}:{now}:text:00:11"));
        assert!(deliver_check(&old, now).is_err());

        let mut other_signer = ok.clone();
        other_signer["owner"] = deliver_params(5, to, now, "x")["owner"].clone();
        assert!(deliver_check(&other_signer, now).is_err());
    }

    #[test]
    fn deliveries_are_limited_per_wallet() {
        let now = 1_800_000_000;
        for _ in 0..DELIVERIES_PER_MINUTE {
            assert!(delivery_allowed("egot1ratelimited", now));
        }
        assert!(!delivery_allowed("egot1ratelimited", now + 30));
        assert!(delivery_allowed("egot1ratelimited", now + 61));
        assert!(delivery_allowed("egot1someoneelse", now));
    }

    const FIXTURE: &str = r#"{"owner":"egot1yq4xhaep9ne54m33sc9dj0lh2k7mam5zmc6s5max","pubkey":"fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618","slot":"desktop","ver":1800000000000,"data":"jiuR5E0D659H1HmDJTI1PIRUj6EIVsFLkHvCqijT8PeKR4Kcdpzou1Q2uX/LIF8MlHxbQAtAwQgHCwl9MZt2qQe3a1DK9uq2LuLthTFzjGjTDcaQjUUQy0fe9WjG7btBiOUJk3hRkfzIPDRiUJsvGFv/GaRKxuEsO0NAOc1Boh5zzL+yCTqP06jXVWbFbW/GAQK007OJn/yUAVCePGU1gqSoiq3kzgbKhWF8yyRAqbhsqWh1rnqFhSDGLCIrNzNnogA74itAoLiDFHagOYNvpA3mQlr000FEIOFFKCtPqvSGVUXC5TlHzAVf1JlKi0efujHd8y0si7E8hykAGxuM+mzMSQcAAwUA4+GMDm5QMjVlULxExoSv/g/xK8ShP3NCIS0YFt6DOJEYOUffEzqiH5uXnLKyZykU+mq1xH/SDXkPpSZYxEEEcfvYZ8g6mo2KqhwFi5DxXKIj7mn/YqqGKbm3hiL3MRusE4DGjJBXSqiP7gXAheTu72ekLfddUVWlOW09ltoBUMuTb4zDMiqD+l0x5usKBlDLQUvvEf7zioX5v14ts4fcajNQoUkthQsDB8FnY9QX7czpfgrqwV3fC42W5JOH0zpNiIn9o/QQa+7ShAx18KvJVX5wJfnZntJ4laABMlVvUOOAO3X9HCWtAmsQRWkxriWWCiPdF4rdgnkyDm7xHbXm4rpQ2Z8d6MJZl7x/as+gs7DGSTIJo/m43redFAS+KMVVFnjyNDKx49XuB7fLucVxb0AbPffbVXWykA1JplDrzHVxx0H6ljULe3Y5p+4qZELcdSpu5nkvnwTmlidpxg==","sig":"d0fd8a5020ad6cb4705a9e592a4935064736f976063a72f2f15f664ecf2fa57624bd4ba2722f3426720ae00042ab02642f539e7d3114567b7a897bde53c6910c"}"#;

    #[test]
    fn a_record_written_once_still_opens_the_same_way() {
        let env: Envelope = serde_json::from_str(FIXTURE).unwrap();
        assert!(check(&env, env.ver).is_ok());
        let c = open(&env, &[9u8; 32]).unwrap();
        assert_eq!(c.bundle, "egocontact1:egot1x:a:b:c:d");
        assert_eq!(c.files[0].name, "cat.jpg");
        assert_eq!(c.payments[0].block_height, Some(85459));
        let nodes: Vec<String> = (0..50).map(|i| format!("egot1node{i}")).collect();
        assert_eq!(places("egot1owner", &nodes, PLACES), ["egot1node31", "egot1node48", "egot1node10", "egot1node28"]);
        assert_eq!(hex::encode(record_key(&(0u8..32).collect::<Vec<u8>>())), "be1be4f26b8d319885ee05cca56d4e0935d07bde67ddc25d9fafc0e7dd15a769");
    }
}


#[cfg(test)]
mod phone_merge_tests {
    use super::*;

    #[test]
    fn a_phone_record_from_before_messenger_still_opens() {
        let old = r#"{"v":1,"name":"","bundle":"","contacts":[],"files":[],"payments":[],"sent":[]}"#;
        let content: Content = serde_json::from_str(old).unwrap();
        assert_eq!(content.want_history, 0);
        assert!(content.avatar.is_empty());
        let newer = r#"{"v":1,"want_history":5,"avatar":"data:image/jpeg;base64,AA","avatar_at":9,"token":"ab"}"#;
        let content: Content = serde_json::from_str(newer).unwrap();
        assert_eq!((content.want_history, content.avatar_at, content.token.as_str()), (5, 9, "ab"));
    }
}
