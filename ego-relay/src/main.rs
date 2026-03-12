//! Ego Relay Server — libp2p circuit relay v2 + HTTP chain/peer API.
//!
//! HTTP endpoints:
//!   GET  /chain                   — full global blockchain
//!   POST /chain/tx                — submit a confirmed transaction
//!   POST /chain/block             — submit a mined block
//!   GET  /peers                   — list all known peer endpoints
//!   POST /peers                   — register/update your relay circuit address
//!   POST /inbox/:address          — store a message for an offline peer
//!   GET  /inbox/:address          — fetch and clear pending messages (called on startup)
//!   GET  /health                  — liveness probe
//!   POST /users/register          — register name + email, send verification email
//!   GET  /users/verify/:token     — verify email (browser link)
//!   GET  /users/:address          — get registration/verification status
//!   POST /users/reset-pin         — send PIN reset email
//!   POST /tx/pending              — hold a tx, send email confirmation to user
//!   GET  /tx/confirm/:token       — user clicks → tx executes
//!   GET  /tx/cancel/:token        — user clicks → tx cancelled
//!   GET  /tx/status/:token        — desktop polls for confirmation status

use axum::{
    extract::{Path, State},
    http::{HeaderValue, Method, StatusCode},
    routing::{get, post},
    Json, Router,
};
use tower_http::cors::{Any, CorsLayer};
use futures::StreamExt;
use lettre::{
    message::header::ContentType,
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use libp2p::{
    identify, noise, ping, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, SwarmBuilder,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    sync::{Arc, RwLock},
    time::Duration,
};
use uuid::Uuid;

// ── SMTP config (loaded from .env / environment) ──────────────────────────────

#[derive(Clone)]
struct Config {
    smtp_host:     String,
    smtp_port:     u16,
    smtp_user:     String,
    smtp_pass:     String,
    smtp_from:     String,
    support_email: String,
    base_url:      String,
}

impl Config {
    fn from_env() -> Self {
        Self {
            smtp_host:     std::env::var("SMTP_HOST").expect("SMTP_HOST not set"),
            smtp_port:     std::env::var("SMTP_PORT").ok()
                               .and_then(|p| p.parse().ok()).unwrap_or(465),
            smtp_user:     std::env::var("SMTP_USER").expect("SMTP_USER not set"),
            smtp_pass:     std::env::var("SMTP_PASS").expect("SMTP_PASS not set"),
            smtp_from:     std::env::var("SMTP_FROM").expect("SMTP_FROM not set"),
            support_email: std::env::var("SUPPORT_EMAIL").expect("SUPPORT_EMAIL not set"),
            base_url:      std::env::var("BASE_URL").expect("BASE_URL not set"),
        }
    }
}

// ── Chain data model ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SharedChain {
    blocks:       Vec<LedgerBlock>,
    transactions: Vec<LedgerTx>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerBlock {
    height:     u64,
    hash:       String,
    prev_hash:  String,
    timestamp:  i64,
    miner:      String,
    tx_count:   u32,
    size_bytes: u64,
    reward:     u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerTx {
    hash:         String,
    from:         String,
    to:           String,
    amount:       u64,
    memo:         Option<String>,
    timestamp:    i64,
    signature:    String,
    status:       String,
    block_height: Option<u64>,
    #[serde(default)]
    nonce: u64,
}

// ── Persistent chain storage ──────────────────────────────────────────────────

const CHAIN_PATH: &str = "chain.json";

fn load_chain() -> SharedChain {
    if let Ok(data) = fs::read_to_string(CHAIN_PATH) {
        if let Ok(c) = serde_json::from_str::<SharedChain>(&data) {
            return c;
        }
    }
    SharedChain::default()
}

fn save_chain(chain: &SharedChain) {
    if let Ok(data) = serde_json::to_string_pretty(chain) {
        let _ = fs::write(CHAIN_PATH, data);
    }
}

// ── Peer directory ────────────────────────────────────────────────────────────

const PEERS_PATH: &str = "peers.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PeerEntry {
    address:   String,
    name:      String,
    endpoint:  String,
    last_seen: i64,
    #[serde(default)]
    city:    Option<String>,
    #[serde(default)]
    country: Option<String>,
}

fn load_peers() -> Vec<PeerEntry> {
    if let Ok(data) = fs::read_to_string(PEERS_PATH) {
        if let Ok(p) = serde_json::from_str::<Vec<PeerEntry>>(&data) {
            return p;
        }
    }
    Vec::new()
}

fn save_peers(peers: &[PeerEntry]) {
    if let Ok(data) = serde_json::to_string_pretty(peers) {
        let _ = fs::write(PEERS_PATH, data);
    }
}

// ── Inbox (store-and-forward) ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InboxMessage {
    /// JSON-serialised P2PMessage, base64-encoded
    payload:   String,
    deposited: i64,
    from_addr: String,
}

// ── User registration ─────────────────────────────────────────────────────────

const USERS_PATH: &str = "users.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserRecord {
    address:          String,
    name:             String,
    email:            String,
    email_verified:   bool,
    verify_token:     Option<String>,
    pin_reset_token:  Option<String>,
    pin_reset_expiry: Option<i64>,
    registered_at:    i64,
    #[serde(default)]
    pending_email:       Option<String>,
    #[serde(default)]
    email_change_token:  Option<String>,
}

fn load_users() -> Vec<UserRecord> {
    fs::read_to_string(USERS_PATH)
        .ok()
        .and_then(|d| serde_json::from_str(&d).ok())
        .unwrap_or_default()
}

fn save_users(users: &[UserRecord]) {
    if let Ok(data) = serde_json::to_string_pretty(users) {
        let _ = fs::write(USERS_PATH, data);
    }
}

// ── Pending transactions ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingTx {
    token:      String,
    address:    String,
    email:      String,
    tx_json:    String,
    block_json: String,
    created_at: i64,
    tx_type:    String,
    amount:     u64,
    to:         String,
}

// ── Shared HTTP state ─────────────────────────────────────────────────────────

type ChainState   = Arc<RwLock<SharedChain>>;
type PeersState   = Arc<RwLock<Vec<PeerEntry>>>;
type InboxState   = Arc<RwLock<HashMap<String, Vec<InboxMessage>>>>;
type UsersState   = Arc<RwLock<Vec<UserRecord>>>;
type PendingState = Arc<RwLock<Vec<PendingTx>>>;

#[derive(Clone)]
struct AppState {
    chain:   ChainState,
    peers:   PeersState,
    inbox:   InboxState,
    users:   UsersState,
    pending: PendingState,
    mailer:  Arc<AsyncSmtpTransport<Tokio1Executor>>,
    config:  Arc<Config>,
}

// ── Email helpers ─────────────────────────────────────────────────────────────

async fn send_email(
    mailer:  &AsyncSmtpTransport<Tokio1Executor>,
    from:    &str,
    to:      &str,
    subject: &str,
    body:    String,
) {
    let msg = match Message::builder()
        .from(from.parse().unwrap())
        .to(match to.parse() { Ok(m) => m, Err(_) => return })
        .subject(subject)
        .header(ContentType::TEXT_HTML)
        .body(body)
    {
        Ok(m)  => m,
        Err(e) => { eprintln!("[email] build error: {}", e); return; }
    };
    match mailer.send(msg).await {
        Ok(_)  => println!("[email] Sent to {}", to),
        Err(e) => eprintln!("[email] Send error to {}: {}", to, e),
    }
}

fn email_html(title: &str, body: &str) -> String {
    format!(r#"<!DOCTYPE html><html><head><meta charset="utf-8">
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:0}}
.wrap{{max-width:560px;margin:40px auto;background:#1e293b;border-radius:16px;overflow:hidden;border:1px solid #334155}}
.hdr{{background:linear-gradient(135deg,#3b82f6,#8b5cf6);padding:32px;text-align:center}}
.logo{{width:56px;height:56px;background:rgba(255,255,255,.2);border-radius:14px;display:inline-block;
       font-size:28px;font-weight:900;color:#fff;line-height:56px;margin-bottom:12px}}
.hdr h1{{color:#fff;margin:0;font-size:20px}}
.body{{padding:32px}}
.btn{{display:inline-block;background:#3b82f6;color:#fff!important;text-decoration:none;
      padding:14px 28px;border-radius:10px;font-weight:600;font-size:15px;margin:20px 0}}
.btn-red{{background:#ef4444}}
.foot{{padding:20px 32px;border-top:1px solid #334155;text-align:center;font-size:12px;color:#64748b}}
p{{line-height:1.6;color:#cbd5e1}}
.code{{background:#0f172a;border-radius:8px;padding:16px;font-family:monospace;font-size:13px;
       color:#34d399;word-break:break-all;margin:12px 0;border:1px solid #334155}}
table td{{padding:10px;font-size:14px}}
</style></head><body><div class="wrap">
<div class="hdr"><div class="logo">E</div><h1>{title}</h1></div>
<div class="body">{body}</div>
<div class="foot">Ego Blockchain · Quantum-Safe Decentralized Network<br>
<a href="https://egoblockchain.com" style="color:#3b82f6">egoblockchain.com</a></div>
</div></body></html>"#, title = title, body = body)
}

fn mask_email(email: &str) -> String {
    if let Some(at) = email.find('@') {
        let local = &email[..at];
        let domain = &email[at..];
        let show = if local.len() <= 2 { 1 } else { 2 };
        format!("{}***{}", &local[..show], domain)
    } else {
        "***".into()
    }
}

// ── HTTP handlers — unchanged originals ──────────────────────────────────────

async fn get_chain(State(s): State<AppState>) -> Json<SharedChain> {
    Json(s.chain.read().unwrap().clone())
}

async fn health() -> &'static str { "ok" }

async fn get_peers(State(s): State<AppState>) -> Json<Vec<PeerEntry>> {
    Json(s.peers.read().unwrap().clone())
}

async fn post_peer(
    State(s): State<AppState>,
    Json(entry): Json<PeerEntry>,
) -> StatusCode {
    if entry.address.is_empty() || entry.endpoint.is_empty() {
        return StatusCode::BAD_REQUEST;
    }
    let mut list = s.peers.write().unwrap();
    let now = chrono::Utc::now().timestamp();
    if let Some(existing) = list.iter_mut().find(|p| p.address == entry.address) {
        existing.endpoint  = entry.endpoint.clone();
        existing.name      = entry.name.clone();
        existing.last_seen = now;
        if entry.city.is_some()    { existing.city    = entry.city.clone(); }
        if entry.country.is_some() { existing.country = entry.country.clone(); }
        println!("[peers] Updated endpoint for {} → {}", entry.address, entry.endpoint);
    } else {
        println!("[peers] New peer {} → {}", entry.address, entry.endpoint);
        list.push(PeerEntry { last_seen: now, ..entry });
    }
    let cutoff = now - 600;
    list.retain(|p| p.last_seen >= cutoff);
    save_peers(&list);
    StatusCode::OK
}

async fn post_tx(
    State(s): State<AppState>,
    Json(tx): Json<LedgerTx>,
) -> StatusCode {
    let mut chain = s.chain.write().unwrap();
    if !chain.transactions.iter().any(|t| t.hash == tx.hash) {
        println!("[chain] New tx {} from {} → {} ({} uEGOC)", tx.hash, tx.from, tx.to, tx.amount);
        chain.transactions.push(tx);
        save_chain(&chain);
    }
    StatusCode::OK
}

async fn post_block(
    State(s): State<AppState>,
    Json(block): Json<LedgerBlock>,
) -> StatusCode {
    let mut chain = s.chain.write().unwrap();
    if !chain.blocks.iter().any(|b| b.hash == block.hash) {
        println!("[chain] New block #{} hash {}", block.height, block.hash);
        chain.blocks.push(block);
        chain.blocks.sort_by_key(|b| b.height);
        save_chain(&chain);
    }
    StatusCode::OK
}

/// POST /inbox/:address — deposit a message for an offline peer.
async fn post_inbox(
    Path(address): Path<String>,
    State(s): State<AppState>,
    Json(msg): Json<InboxMessage>,
) -> StatusCode {
    if address.is_empty() || msg.payload.is_empty() {
        return StatusCode::BAD_REQUEST;
    }
    let mut map = s.inbox.write().unwrap();
    let bucket = map.entry(address.clone()).or_default();
    if !bucket.iter().any(|m| m.payload == msg.payload) {
        println!("[inbox] Stored message for {} from {}", address, msg.from_addr);
        bucket.push(msg);
    }
    StatusCode::OK
}

/// GET /inbox/:address — fetch and clear all pending messages.
async fn get_inbox(
    Path(address): Path<String>,
    State(s): State<AppState>,
) -> Json<Vec<InboxMessage>> {
    let mut map = s.inbox.write().unwrap();
    let msgs = map.remove(&address).unwrap_or_default();
    if !msgs.is_empty() {
        println!("[inbox] Delivered {} message(s) to {}", msgs.len(), address);
    }
    Json(msgs)
}

// ── HTTP handlers — new email/user/tx endpoints ───────────────────────────────

#[derive(Debug, Deserialize)]
struct RegisterRequest {
    address: String,
    name:    String,
    email:   String,
}

#[derive(Debug, Serialize)]
struct ApiResponse {
    success: bool,
    message: String,
}

async fn post_register(
    State(s): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    if req.address.is_empty() || req.name.is_empty() || req.email.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(ApiResponse {
            success: false, message: "address, name and email required".into(),
        }));
    }
    let token = Uuid::new_v4().to_string();
    let now   = chrono::Utc::now().timestamp();
    {
        let mut users = s.users.write().unwrap();
        if let Some(u) = users.iter_mut().find(|u| u.address == req.address) {
            u.name = req.name.clone(); u.email = req.email.clone();
            u.verify_token = Some(token.clone()); u.email_verified = false;
        } else {
            users.push(UserRecord {
                address: req.address.clone(), name: req.name.clone(),
                email: req.email.clone(), email_verified: false,
                verify_token: Some(token.clone()), pin_reset_token: None,
                pin_reset_expiry: None, registered_at: now, pending_email: None, email_change_token: None,
            });
        }
        save_users(&users);
    }
    let verify_url = format!("{}/users/verify/{}", s.config.base_url, token);
    let user_body  = email_html("Verify Your Email", &format!(
        r#"<p>Hi <strong>{name}</strong>,</p>
        <p>Welcome to Ego Blockchain! Click below to verify your email and see your recovery phrase.</p>
        <p style="text-align:center"><a href="{url}" class="btn">✓ Verify Email Address</a></p>
        <p style="font-size:13px;color:#94a3b8">Or paste this link in your browser:<br>
        <span class="code">{url}</span></p>"#,
        name = req.name, url = verify_url,
    ));
    send_email(&s.mailer, &s.config.smtp_from, &req.email, "Verify your Ego Blockchain email", user_body).await;

    println!("[users] Registered {} <{}>", req.name, req.email);
    (StatusCode::OK, Json(ApiResponse { success: true, message: "Verification email sent.".into() }))
}

async fn get_verify(
    Path(token): Path<String>,
    State(s): State<AppState>,
) -> (StatusCode, axum::response::Html<String>) {
    let mut users = s.users.write().unwrap();
    if let Some(user) = users.iter_mut().find(|u| u.verify_token.as_deref() == Some(&token)) {
        user.email_verified = true;
        user.verify_token   = None;
        let name = user.name.clone();
        save_users(&users);
        return (StatusCode::OK, axum::response::Html(format!(r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Email Verified</title>
<style>body{{font-family:sans-serif;background:#0f172a;color:#e2e8f0;display:flex;
align-items:center;justify-content:center;min-height:100vh;margin:0}}
.card{{background:#1e293b;border-radius:16px;padding:48px;text-align:center;
max-width:400px;border:1px solid #334155}}
.icon{{font-size:64px;margin-bottom:16px}}h1{{color:#34d399;margin:0 0 12px}}
p{{color:#94a3b8}}a{{color:#3b82f6}}</style></head>
<body><div class="card"><div class="icon">✅</div>
<h1>Email Verified!</h1>
<p>Welcome, <strong style="color:#e2e8f0">{name}</strong>!</p>
<p>Your wallet is now fully activated. Return to the Ego Desktop app to see your recovery phrase.</p>
<p style="margin-top:24px"><a href="https://egoblockchain.com">egoblockchain.com</a></p>
</div></body></html>"#, name = name)));
    }
    (StatusCode::BAD_REQUEST,
     axum::response::Html("<h1>Invalid or expired verification link.</h1>".into()))
}

#[derive(Debug, Serialize)]
struct UserStatusResponse {
    registered:     bool,
    email_verified: bool,
    name:           String,
    email_masked:   String,
}

async fn get_user(
    Path(address): Path<String>,
    State(s): State<AppState>,
) -> Json<UserStatusResponse> {
    let users = s.users.read().unwrap();
    if let Some(u) = users.iter().find(|u| u.address == address) {
        Json(UserStatusResponse {
            registered: true, email_verified: u.email_verified,
            name: u.name.clone(), email_masked: mask_email(&u.email),
        })
    } else {
        Json(UserStatusResponse {
            registered: false, email_verified: false,
            name: String::new(), email_masked: String::new(),
        })
    }
}

#[derive(Debug, Deserialize)]
struct ChangeEmailRequest { address: String, new_email: String }

async fn post_change_email(
    State(s): State<AppState>,
    Json(req): Json<ChangeEmailRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    let new_email = req.new_email.trim().to_lowercase();
    if !new_email.contains('@') {
        return (StatusCode::BAD_REQUEST, Json(ApiResponse {
            success: false, message: "Invalid email address".into(),
        }));
    }

    let token = uuid::Uuid::new_v4().to_string();
    let base_url = s.config.base_url.clone();
    let (mailer_clone, from_clone, name_clone) = {
        let mut users = s.users.write().unwrap();
        let user = match users.iter_mut().find(|u| u.address == req.address) {
            Some(u) => u,
            None => return (StatusCode::NOT_FOUND, Json(ApiResponse {
                success: false, message: "Address not registered".into(),
            })),
        };
        if !user.email_verified {
            return (StatusCode::BAD_REQUEST, Json(ApiResponse {
                success: false, message: "Current email is not verified".into(),
            }));
        }
        if user.email == new_email {
            return (StatusCode::BAD_REQUEST, Json(ApiResponse {
                success: false, message: "New email is the same as current email".into(),
            }));
        }
        user.pending_email      = Some(new_email.clone());
        user.email_change_token = Some(token.clone());
        let name = user.name.clone();
        save_users(&users);
        (s.mailer.clone(), s.config.smtp_from.clone(), name)
    };

    let verify_url = format!("{}/users/verify-email-change/{}", base_url, token);
    let body = format!(
        "Hi {name},\n\nClick the link below to confirm your new email address for Ego Desktop:\n\n{url}\n\nIf you did not request this change, ignore this email — your current address stays active.\n\nEgo Blockchain Team",
        name = name_clone, url = verify_url
    );
    let _ = send_email(&mailer_clone, &from_clone, &new_email, "Confirm your new Ego email", body).await;

    (StatusCode::OK, Json(ApiResponse { success: true, message: "Verification email sent to new address.".into() }))
}

async fn get_verify_email_change(
    Path(token): Path<String>,
    State(s): State<AppState>,
) -> (StatusCode, axum::response::Html<String>) {
    let mut users = s.users.write().unwrap();
    if let Some(user) = users.iter_mut().find(|u| u.email_change_token.as_deref() == Some(&token)) {
        if let Some(new_email) = user.pending_email.take() {
            user.email              = new_email;
            user.email_change_token = None;
            save_users(&users);
            return (StatusCode::OK, axum::response::Html(r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Email Updated</title>
<style>body{font-family:sans-serif;background:#0f172a;color:#e2e8f0;display:flex;
align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#1e293b;border-radius:16px;padding:48px;text-align:center;
max-width:400px;border:1px solid #334155}
.icon{font-size:64px;margin-bottom:16px}h1{color:#34d399;margin:0 0 12px}
p{color:#94a3b8}a{color:#3b82f6}</style></head>
<body><div class="card"><div class="icon">✅</div>
<h1>Email Updated!</h1>
<p>Your Ego Desktop email address has been changed successfully.</p>
<p style="margin-top:24px"><a href="https://egoblockchain.com">egoblockchain.com</a></p>
</div></body></html>"#.into()));
        }
    }
    (StatusCode::BAD_REQUEST,
     axum::response::Html("<h1>Invalid or expired email change link.</h1>".into()))
}

#[derive(Debug, Deserialize)]
struct ResetPinRequest { address: String }

async fn post_reset_pin(
    State(s): State<AppState>,
    Json(req): Json<ResetPinRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    let result = {
        let mut users = s.users.write().unwrap();
        if let Some(user) = users.iter_mut().find(|u| u.address == req.address) {
            if !user.email_verified {
                return (StatusCode::BAD_REQUEST, Json(ApiResponse {
                    success: false, message: "Email not verified".into(),
                }));
            }
            let token  = Uuid::new_v4().to_string();
            let expiry = chrono::Utc::now().timestamp() + 3600;
            let email  = user.email.clone();
            let name   = user.name.clone();
            user.pin_reset_token  = Some(token.clone());
            user.pin_reset_expiry = Some(expiry);
            save_users(&users);
            Some((email, name, token))
        } else {
            None
        }
    }; // lock dropped here

    match result {
        None => (StatusCode::NOT_FOUND, Json(ApiResponse {
            success: false, message: "Address not registered".into(),
        })),
        Some((email, name, token)) => {
            let reset_url = format!("{}/users/pin-reset/{}", s.config.base_url, token);
            let body = email_html("Reset Your PIN", &format!(
                r#"<p>Hi <strong>{name}</strong>,</p>
                <p>Click below to reset your Ego Blockchain security PIN. This link expires in 1 hour.</p>
                <p style="text-align:center"><a href="{url}" class="btn">Reset My PIN</a></p>
                <p style="font-size:13px;color:#94a3b8">If you did not request this, ignore this email.</p>"#,
                name = name, url = reset_url,
            ));
            send_email(&s.mailer, &s.config.smtp_from, &email, "Reset your Ego Blockchain PIN", body).await;
            (StatusCode::OK, Json(ApiResponse { success: true, message: "PIN reset email sent.".into() }))
        }
    }
}

#[derive(Debug, Deserialize)]
struct PendingTxRequest {
    address:    String,
    tx_json:    String,
    block_json: String,
    tx_type:    String,
    amount:     u64,
    to:         String,
}

async fn post_pending_tx(
    State(s): State<AppState>,
    Json(req): Json<PendingTxRequest>,
) -> (StatusCode, Json<ApiResponse>) {
    let (email, name) = {
        let users = s.users.read().unwrap();
        match users.iter().find(|u| u.address == req.address && u.email_verified) {
            Some(u) => (u.email.clone(), u.name.clone()),
            None    => return (StatusCode::BAD_REQUEST, Json(ApiResponse {
                success: false, message: "No verified email for this address".into(),
            })),
        }
    };
    let token    = Uuid::new_v4().to_string();
    let now      = chrono::Utc::now().timestamp();
    let amount_f = format!("{:.4}", req.amount as f64 / 1_000_000.0);
    {
        let mut pending = s.pending.write().unwrap();
        pending.retain(|p| p.address != req.address);
        pending.push(PendingTx {
            token: token.clone(), address: req.address.clone(), email: email.clone(),
            tx_json: req.tx_json, block_json: req.block_json, created_at: now,
            tx_type: req.tx_type.clone(), amount: req.amount, to: req.to.clone(),
        });
    }
    let confirm_url = format!("{}/tx/confirm/{}", s.config.base_url, token);
    let cancel_url  = format!("{}/tx/cancel/{}", s.config.base_url, token);
    let action = match req.tx_type.as_str() {
        "stake" => format!("Stake {} EGOC", amount_f),
        _       => format!("Send {} EGOC", amount_f),
    };
    let body = email_html("Confirm Your Transaction", &format!(
        r#"<p>Hi <strong>{name}</strong>,</p>
        <p>A transaction is waiting for your confirmation:</p>
        <table style="width:100%;border-collapse:collapse;margin:16px 0">
          <tr style="background:#0f172a"><td style="color:#94a3b8">Action</td><td><strong>{action}</strong></td></tr>
          <tr><td style="color:#94a3b8">Amount</td><td style="color:#34d399;font-weight:700">{amount} EGOC</td></tr>
          <tr style="background:#0f172a"><td style="color:#94a3b8">From</td>
              <td style="font-family:monospace;font-size:11px">{from}</td></tr>
        </table>
        <p style="text-align:center">
          <a href="{confirm}" class="btn" style="margin-right:12px">✓ Confirm</a>
          <a href="{cancel}" class="btn btn-red">✕ Cancel</a>
        </p>
        <p style="font-size:12px;color:#64748b">This link expires in 30 minutes.</p>"#,
        name = name, action = action, amount = amount_f,
        from = req.address, confirm = confirm_url, cancel = cancel_url,
    ));
    send_email(&s.mailer, &s.config.smtp_from, &email, &format!("Confirm: {}", action), body).await;
    println!("[tx] Pending tx for {} — awaiting email confirm", req.address);
    // Return the token as the message so the desktop can poll /tx/status/:token
    (StatusCode::OK, Json(ApiResponse { success: true, message: token }))
}

async fn get_confirm_tx(
    Path(token): Path<String>,
    State(s): State<AppState>,
) -> (StatusCode, axum::response::Html<String>) {
    let ptx = {
        let mut pending = s.pending.write().unwrap();
        match pending.iter().position(|p| p.token == token) {
            Some(i) => {
                let tx = pending.remove(i);
                if chrono::Utc::now().timestamp() - tx.created_at > 1800 {
                    return (StatusCode::BAD_REQUEST,
                        axum::response::Html("<h1>This confirmation link has expired.</h1>".into()));
                }
                tx
            }
            None => return (StatusCode::NOT_FOUND,
                axum::response::Html("<h1>Transaction not found or already processed.</h1>".into())),
        }
    };
    let tx: LedgerTx = match serde_json::from_str(&ptx.tx_json) {
        Ok(t)  => t,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR,
            axum::response::Html("<h1>Invalid tx data.</h1>".into())),
    };
    let block: LedgerBlock = match serde_json::from_str(&ptx.block_json) {
        Ok(b)  => b,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR,
            axum::response::Html("<h1>Invalid block data.</h1>".into())),
    };
    {
        let mut chain = s.chain.write().unwrap();
        if !chain.transactions.iter().any(|t| t.hash == tx.hash) {
            chain.transactions.push(tx.clone());
            chain.blocks.push(block);
            chain.blocks.sort_by_key(|b| b.height);
            save_chain(&chain);
            println!("[tx] Confirmed tx {} for {}", tx.hash, ptx.address);
        }
    }
    let amount_f = format!("{:.4}", ptx.amount as f64 / 1_000_000.0);
    (StatusCode::OK, axum::response::Html(format!(r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Transaction Confirmed</title>
<style>body{{font-family:sans-serif;background:#0f172a;color:#e2e8f0;display:flex;
align-items:center;justify-content:center;min-height:100vh;margin:0}}
.card{{background:#1e293b;border-radius:16px;padding:48px;text-align:center;
max-width:440px;border:1px solid #334155}}
.icon{{font-size:64px;margin-bottom:16px}}h1{{color:#34d399;margin:0 0 12px}}
.amount{{color:#34d399;font-size:28px;font-weight:700;margin:16px 0}}
p{{color:#94a3b8;line-height:1.6}}
.hash{{font-family:monospace;font-size:11px;word-break:break-all;background:#0f172a;
padding:12px;border-radius:8px;margin-top:16px}}</style></head>
<body><div class="card"><div class="icon">✅</div>
<h1>Transaction Confirmed!</h1>
<div class="amount">{amount} EGOC</div>
<p>Your transaction has been recorded on the Ego Blockchain.</p>
<div class="hash">{hash}</div>
<p style="margin-top:24px">You can close this page and return to Ego Desktop.</p>
</div></body></html>"#, amount = amount_f, hash = tx.hash)))
}

async fn get_cancel_tx(
    Path(token): Path<String>,
    State(s): State<AppState>,
) -> (StatusCode, axum::response::Html<String>) {
    let mut pending = s.pending.write().unwrap();
    if pending.iter().position(|p| p.token == token).map(|i| pending.remove(i)).is_some() {
        println!("[tx] Cancelled pending tx token {}", &token[..8]);
        return (StatusCode::OK, axum::response::Html(r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Cancelled</title>
<style>body{font-family:sans-serif;background:#0f172a;color:#e2e8f0;display:flex;
align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#1e293b;border-radius:16px;padding:48px;text-align:center;
max-width:400px;border:1px solid #334155}
.icon{font-size:64px;margin-bottom:16px}h1{color:#ef4444;margin:0 0 12px}
p{color:#94a3b8}</style></head>
<body><div class="card"><div class="icon">❌</div>
<h1>Transaction Cancelled</h1>
<p>Your transaction has been cancelled. No funds were moved.</p>
</div></body></html>"#.into()));
    }
    (StatusCode::NOT_FOUND, axum::response::Html("<h1>Transaction not found.</h1>".into()))
}

#[derive(Debug, Serialize)]
struct TxStatusResponse { status: String }

async fn get_tx_status(
    Path(token): Path<String>,
    State(s): State<AppState>,
) -> Json<TxStatusResponse> {
    let pending = s.pending.read().unwrap();
    if let Some(p) = pending.iter().find(|p| p.token == token) {
        let age = chrono::Utc::now().timestamp() - p.created_at;
        return Json(TxStatusResponse {
            status: if age > 1800 { "expired".into() } else { "pending".into() },
        });
    }
    Json(TxStatusResponse { status: "confirmed".into() })
}

// ── libp2p relay behaviour ────────────────────────────────────────────────────

#[derive(NetworkBehaviour)]
struct RelayBehaviour {
    relay:    relay::Behaviour,
    identify: identify::Behaviour,
    ping:     ping::Behaviour,
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok(); // load .env if present (silent if missing)

    let cfg = Config::from_env();

    let identity = load_or_create_identity();
    let peer_id  = identity.public().to_peer_id();

    let p2p_port = std::env::var("EGO_RELAY_PORT")
        .ok().and_then(|p| p.parse::<u16>().ok()).unwrap_or(4001);
    let http_port = std::env::var("EGO_HTTP_PORT")
        .ok().and_then(|p| p.parse::<u16>().ok()).unwrap_or(8080);

    // Build SMTP mailer
    let creds  = Credentials::new(cfg.smtp_user.clone(), cfg.smtp_pass.clone());
    let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.smtp_host)
        .unwrap()
        .port(cfg.smtp_port)
        .credentials(creds)
        .build();

    let state = AppState {
        chain:   Arc::new(RwLock::new(load_chain())),
        peers:   Arc::new(RwLock::new(load_peers())),
        inbox:   Arc::new(RwLock::new(HashMap::new())),
        users:   Arc::new(RwLock::new(load_users())),
        pending: Arc::new(RwLock::new(Vec::new())),
        mailer:  Arc::new(mailer),
        config:  Arc::new(cfg),
    };
    {
        let c = state.chain.read().unwrap();
        let p = state.peers.read().unwrap();
        let u = state.users.read().unwrap();
        println!("[chain] Loaded {} blocks, {} txs from {}", c.blocks.len(), c.transactions.len(), CHAIN_PATH);
        println!("[peers] Loaded {} known peers from {}", p.len(), PEERS_PATH);
        println!("[users] Loaded {} registered users", u.len());
    }

    let http_addr   = format!("0.0.0.0:{}", http_port);
    let state_clone = state.clone();
    tokio::spawn(async move {
        let app = Router::new()
            .route("/chain",                get(get_chain))
            .route("/chain/tx",             post(post_tx))
            .route("/chain/block",          post(post_block))
            .route("/peers",                get(get_peers).post(post_peer))
            .route("/inbox/:address",       get(get_inbox).post(post_inbox))
            .route("/health",               get(health))
            // ── new endpoints ──
            .route("/users/register",                  post(post_register))
            .route("/users/verify/:token",             get(get_verify))
            .route("/users/verify-email-change/:token",get(get_verify_email_change))
            .route("/users/change-email",              post(post_change_email))
            .route("/users/confirm-email-change/:token", get(get_confirm_email_change))
            .route("/users/reset-pin",                 post(post_reset_pin))
            .route("/users/pin-reset/:token",          get(get_pin_reset))
            .route("/users/pin-reset-status/:address", get(get_pin_reset_status))
            .route("/users/:address",                  get(get_user))
            .route("/tx/pending",           post(post_pending_tx))
            .route("/tx/confirm/:token",    get(get_confirm_tx))
            .route("/tx/cancel/:token",     get(get_cancel_tx))
            .route("/tx/status/:token",     get(get_tx_status))
            .with_state(state_clone)
            .layer(
                CorsLayer::new()
                    .allow_origin(Any)
                    .allow_methods([Method::GET, Method::POST])
                    .allow_headers(Any),
            );

        let listener = tokio::net::TcpListener::bind(&http_addr).await
            .expect("HTTP bind failed");
        println!("[http] Listening on {}", http_addr);
        axum::serve(listener, app).await.expect("HTTP server error");
    });

    let mut swarm = SwarmBuilder::with_existing_identity(identity.clone())
        .with_tokio()
        .with_tcp(tcp::Config::default().nodelay(true), noise::Config::new, yamux::Config::default)
        .expect("TCP transport")
        .with_behaviour(|key| RelayBehaviour {
            relay: relay::Behaviour::new(
                peer_id,
                relay::Config {
                    max_reservations:          1024,
                    max_reservations_per_peer: 32,
                    reservation_duration:      Duration::from_secs(3600),
                    max_circuits:              2048,
                    max_circuits_per_peer:     128,
                    max_circuit_duration:      Duration::from_secs(7200),
                    max_circuit_bytes:         0,
                    ..Default::default()
                },
            ),
            identify: identify::Behaviour::new(
                identify::Config::new("/ego/identify/1.0.0".to_string(), key.public())
                    .with_interval(Duration::from_secs(60)),
            ),
            ping: ping::Behaviour::new(
                ping::Config::new().with_interval(Duration::from_secs(30)),
            ),
        })
        .expect("behaviour")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(3600)))
        .build();

    let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", p2p_port).parse().unwrap();
    swarm.listen_on(listen_addr).expect("listen");

    println!("╔═══════════════════════════════════════════╗");
    println!("║       Ego Relay + Chain Seed v0.4.0       ║");
    println!("╚═══════════════════════════════════════════╝");
    println!("Peer ID   : {}", peer_id);
    println!("P2P port  : {}", p2p_port);
    println!("HTTP port : {}", http_port);

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                println!("[relay] Listening on {}", address);
            }
            SwarmEvent::ConnectionEstablished { peer_id: pid, .. } => {
                println!("[relay] Peer connected: {}", pid);
            }
            SwarmEvent::ConnectionClosed { peer_id: pid, .. } => {
                println!("[relay] Peer disconnected: {}", pid);
            }
            SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(
                relay::Event::ReservationReqAccepted { src_peer_id, .. },
            )) => {
                println!("[relay] Reservation accepted for {}", src_peer_id);
            }
            SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(
                relay::Event::CircuitReqAccepted { src_peer_id, dst_peer_id, .. },
            )) => {
                println!("[relay] Circuit: {} -> {}", src_peer_id, dst_peer_id);
            }
            _ => {}
        }
    }
}


async fn get_confirm_email_change(
    Path(token): Path<String>,
    State(s): State<AppState>,
) -> (StatusCode, axum::response::Html<String>) {
    let mut users = s.users.write().unwrap();
    let result = users.iter_mut().find(|u| {
        u.verify_token.as_deref()
            .map(|t| t.starts_with(&format!("email_change:{}:", token)))
            .unwrap_or(false)
    }).map(|u| {
        let new_email = u.verify_token.as_deref().unwrap_or("")
            .splitn(3, ':').nth(2).unwrap_or("").to_string();
        u.email = new_email.clone();
        u.verify_token = None;
        new_email
    });
    save_users(&users);
    drop(users);
    match result {
        Some(new_email) => (StatusCode::OK, axum::response::Html(format!(r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Email Updated</title>
<style>body{{font-family:sans-serif;background:#0f172a;color:#e2e8f0;display:flex;
align-items:center;justify-content:center;min-height:100vh;margin:0}}
.card{{background:#1e293b;border-radius:16px;padding:48px;text-align:center;max-width:400px}}
.icon{{font-size:64px}}h1{{color:#34d399}}</style></head>
<body><div class="card"><div class="icon">✅</div>
<h1>Email Updated!</h1>
<p>Your account email is now <strong>{}</strong>.</p>
</div></body></html>"#, new_email))),
        None => (StatusCode::BAD_REQUEST,
            axum::response::Html("<h1>Invalid or expired link.</h1>".into())),
    }
}


async fn get_pin_reset(
    Path(token): Path<String>,
    State(s): State<AppState>,
) -> (StatusCode, axum::response::Html<String>) {
    let now = chrono::Utc::now().timestamp();
    let mut users = s.users.write().unwrap();
    let valid = users.iter_mut().find(|u| {
        u.pin_reset_token.as_deref() == Some(&token)
            && u.pin_reset_expiry.map(|e| e > now).unwrap_or(false)
    }).map(|u| {
        u.pin_reset_token  = Some(format!("confirmed:{}", token));
        u.pin_reset_expiry = Some(now + 300);
        true
    }).unwrap_or(false);
    if valid { save_users(&users); }
    drop(users);
    if valid {
        (StatusCode::OK, axum::response::Html(format!(r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>PIN Reset Confirmed</title>
<style>body{{font-family:sans-serif;background:#0f172a;color:#e2e8f0;display:flex;
align-items:center;justify-content:center;min-height:100vh;margin:0}}
.card{{background:#1e293b;border-radius:16px;padding:48px;text-align:center;max-width:400px}}
.icon{{font-size:64px}}h1{{color:#34d399}}</style></head>
<body><div class="card"><div class="icon">✅</div>
<h1>PIN Reset Confirmed!</h1>
<p>Return to the Ego Desktop app — you will be prompted to set a new PIN.</p>
<p style="color:#94a3b8;font-size:13px">This window can be closed.</p>
</div></body></html>"#)))
    } else {
        (StatusCode::BAD_REQUEST, axum::response::Html(
            "<h1>Invalid or expired reset link.</h1>".into()
        ))
    }
}

async fn get_pin_reset_status(
    Path(address): Path<String>,
    State(s): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    let users = s.users.read().unwrap();
    let confirmed = users.iter().find(|u| u.address == address)
        .map(|u| u.pin_reset_token.as_deref()
            .map(|t| t.starts_with("confirmed:"))
            .unwrap_or(false))
        .unwrap_or(false);
    drop(users);
    if confirmed {
        // Clear the token so it can only be used once
        let mut users = s.users.write().unwrap();
        if let Some(u) = users.iter_mut().find(|u| u.address == address) {
            u.pin_reset_token  = None;
            u.pin_reset_expiry = None;
            save_users(&users);
        }
    }
    (StatusCode::OK, Json(serde_json::json!({ "confirmed": confirmed })))
}

fn load_or_create_identity() -> libp2p::identity::Keypair {
    let path = "relay_identity.bin";
    if let Ok(bytes) = fs::read(path) {
        if let Ok(kp) = libp2p::identity::Keypair::from_protobuf_encoding(&bytes) {
            return kp;
        }
    }
    let kp = libp2p::identity::Keypair::generate_ed25519();
    if let Ok(bytes) = kp.to_protobuf_encoding() {
        fs::write(path, bytes).expect("write identity");
    }
    kp
}
