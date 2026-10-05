use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

pub const TOPIC: &str = "ego-dao-chat-v1";
pub const MAX_BODY_CHARS: usize = 500;
pub const MAX_NAME_CHARS: usize = 24;
pub const BAN_VOTES: usize = 5;
pub const BAN_SECS: i64 = 14 * 86_400;
pub const VOTE_WINDOW_SECS: i64 = 14 * 86_400;
pub const MIN_POST_GAP_SECS: i64 = 2;
pub const SYNC_MAX_POSTS: usize = 500;
pub const SYNC_MAX_VOTES: usize = 5_000;
pub const SYNC_MAX_REQUEST_BYTES: usize = 4 * 1024;
pub const SYNC_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
pub const CHANGE_WINDOW_SECS: i64 = 3_600;

const MAX_LINES: usize = 12;
const LATE_GOSSIP_SECS: i64 = 600;
const KEEP_POSTS_SECS: i64 = 30 * 86_400;
const KEEP_VOTES_SECS: i64 = KEEP_POSTS_SECS + VOTE_WINDOW_SECS;
const MAX_KEPT_POSTS: usize = 20_000;
const FUTURE_SKEW_SECS: i64 = 300;
const BURST_WINDOW_SECS: i64 = 600;
const BURST_MAX: usize = 30;
const PRUNE_EVERY: u32 = 200;

const POST_DOMAIN: &str = "ego/dao-chat/post/v1";
const VOTE_DOMAIN: &str = "ego/dao-chat/vote/v1";
const NAME_DOMAIN: &str = "ego/dao-chat/name/v1";
const EDIT_DOMAIN: &str = "ego/dao-chat/edit/v1";
const DELETE_DOMAIN: &str = "ego/dao-chat/delete/v1";

const POSTS: &str = "dchat/p/";
const VOTES: &str = "dchat/v/";
const VOTES_BY_TIME: &str = "dchat/vt/";
const NAMES: &str = "dchat/n/";
const EDITS: &str = "dchat/e/";
const DELETES: &str = "dchat/x/";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Post {
    pub from: String,
    pub name: String,
    pub body: String,
    pub ts: i64,
    pub pubkey: String,
    pub sig: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Vote {
    pub voter: String,
    pub target: String,
    pub ts: i64,
    pub pubkey: String,
    pub sig: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Name {
    pub from: String,
    pub name: String,
    pub ts: i64,
    pub pubkey: String,
    pub sig: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Edit {
    pub from: String,
    pub post_id: String,
    pub post_ts: i64,
    pub body: String,
    pub ts: i64,
    pub pubkey: String,
    pub sig: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Delete {
    pub from: String,
    pub post_id: String,
    pub post_ts: i64,
    pub ts: i64,
    pub pubkey: String,
    pub sig: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Wire {
    Post(Post),
    Vote(Vote),
    Name(Name),
    Edit(Edit),
    Delete(Delete),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequest {
    pub since: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncResponse {
    pub posts: Vec<Post>,
    pub votes: Vec<Vote>,
    pub names: Vec<Name>,
    #[serde(default)]
    pub edits: Vec<Edit>,
    #[serde(default)]
    pub deletes: Vec<Delete>,
}

impl Post {
    pub fn signing_bytes(&self) -> Vec<u8> {
        format!("{POST_DOMAIN}\n{}\n{}\n{}\n{}", self.from, self.ts, self.name, self.body).into_bytes()
    }

    pub fn id(&self) -> String {
        ego_core::hash_data(&self.signing_bytes()).to_hex()[..32].to_string()
    }
}

impl Vote {
    pub fn signing_bytes(&self) -> Vec<u8> {
        format!("{VOTE_DOMAIN}\n{}\n{}\n{}", self.voter, self.target, self.ts).into_bytes()
    }
}

impl Name {
    pub fn signing_bytes(&self) -> Vec<u8> {
        format!("{NAME_DOMAIN}\n{}\n{}\n{}", self.from, self.ts, self.name).into_bytes()
    }
}

impl Edit {
    pub fn signing_bytes(&self) -> Vec<u8> {
        format!("{EDIT_DOMAIN}\n{}\n{}\n{}\n{}\n{}", self.from, self.post_id, self.post_ts, self.ts, self.body).into_bytes()
    }
}

impl Delete {
    pub fn signing_bytes(&self) -> Vec<u8> {
        format!("{DELETE_DOMAIN}\n{}\n{}\n{}\n{}", self.from, self.post_id, self.post_ts, self.ts).into_bytes()
    }
}

pub fn can_change(post_ts: i64, now: i64) -> bool {
    now >= post_ts && now - post_ts < CHANGE_WINDOW_SECS
}

pub fn clean_name(raw: &str) -> Result<String, String> {
    let name = raw.trim();
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(format!("A name can be at most {MAX_NAME_CHARS} characters."));
    }
    if name.chars().any(char::is_control) {
        return Err("A name can only contain letters, numbers, spaces and punctuation.".into());
    }
    Ok(name.to_string())
}

pub fn clean_body(raw: &str) -> Result<String, String> {
    let body = raw.trim();
    if body.is_empty() {
        return Err("Write something first.".into());
    }
    if body.chars().count() > MAX_BODY_CHARS {
        return Err(format!("A message can be at most {MAX_BODY_CHARS} characters."));
    }
    if body.chars().any(|c| c.is_control() && c != '\n') {
        return Err("A message can only contain text.".into());
    }
    if body.lines().count() > MAX_LINES {
        return Err(format!("A message can have at most {MAX_LINES} lines."));
    }
    Ok(body.to_string())
}

pub fn is_address(s: &str) -> bool {
    let rest = s.strip_prefix("egot1").or_else(|| s.strip_prefix("ego1"));
    match rest {
        Some(r) => (20..=90).contains(&r.len()) && r.chars().all(|c| "qpzry9x8gf2tvdw0s3jn54khce6mua7l".contains(c)),
        None => false,
    }
}

fn signed_by(pubkey_hex: &str, claimed: &str, msg: &[u8], sig_hex: &str) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    let Some(pk) = hex::decode(pubkey_hex).ok().and_then(|v| <[u8; 32]>::try_from(v).ok()) else { return false };
    if crate::market_chain::address_of(&pk) != claimed {
        return false;
    }
    let Some(sig) = hex::decode(sig_hex).ok().and_then(|v| <[u8; 64]>::try_from(v).ok()) else { return false };
    VerifyingKey::from_bytes(&pk)
        .map(|vk| vk.verify_strict(msg, &Signature::from_bytes(&sig)).is_ok())
        .unwrap_or(false)
}

fn sign(kp: &ego_core::KeyPair, msg: &[u8]) -> (String, String) {
    (hex::encode(kp.ed25519_public_key().as_bytes()), hex::encode(kp.sign_ed25519(msg).as_bytes()))
}

pub fn address_of_key(kp: &ego_core::KeyPair) -> String {
    let pk: [u8; 32] = kp.ed25519_public_key().as_bytes()[..32].try_into().unwrap_or([0; 32]);
    crate::market_chain::address_of(&pk)
}

pub fn sign_post(kp: &ego_core::KeyPair, name: &str, body: &str, ts: i64) -> Post {
    let mut p = Post { from: address_of_key(kp), name: name.into(), body: body.into(), ts, pubkey: String::new(), sig: String::new() };
    (p.pubkey, p.sig) = sign(kp, &p.signing_bytes());
    p
}

pub fn sign_vote(kp: &ego_core::KeyPair, target: &str, ts: i64) -> Vote {
    let mut v = Vote { voter: address_of_key(kp), target: target.into(), ts, pubkey: String::new(), sig: String::new() };
    (v.pubkey, v.sig) = sign(kp, &v.signing_bytes());
    v
}

pub fn sign_name(kp: &ego_core::KeyPair, name: &str, ts: i64) -> Name {
    let mut n = Name { from: address_of_key(kp), name: name.into(), ts, pubkey: String::new(), sig: String::new() };
    (n.pubkey, n.sig) = sign(kp, &n.signing_bytes());
    n
}

pub fn sign_edit(kp: &ego_core::KeyPair, post: &Post, body: &str, ts: i64) -> Edit {
    let mut e = Edit {
        from: address_of_key(kp),
        post_id: post.id(),
        post_ts: post.ts,
        body: body.into(),
        ts,
        pubkey: String::new(),
        sig: String::new(),
    };
    (e.pubkey, e.sig) = sign(kp, &e.signing_bytes());
    e
}

pub fn sign_delete(kp: &ego_core::KeyPair, post: &Post, ts: i64) -> Delete {
    let mut d = Delete { from: address_of_key(kp), post_id: post.id(), post_ts: post.ts, ts, pubkey: String::new(), sig: String::new() };
    (d.pubkey, d.sig) = sign(kp, &d.signing_bytes());
    d
}

fn is_post_id(id: &str) -> bool {
    id.len() == 32 && id.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

fn in_change_window(post_ts: i64, ts: i64) -> bool {
    ts >= post_ts && ts - post_ts < CHANGE_WINDOW_SECS
}

pub fn check_edit(e: &Edit, now: i64) -> Result<(), &'static str> {
    if e.ts > now + FUTURE_SKEW_SECS || !in_change_window(e.post_ts, e.ts) || e.post_ts < now - KEEP_POSTS_SECS {
        return Err("time");
    }
    if !is_post_id(&e.post_id) || clean_body(&e.body).as_deref() != Ok(e.body.as_str()) {
        return Err("text");
    }
    if !signed_by(&e.pubkey, &e.from, &e.signing_bytes(), &e.sig) {
        return Err("signature");
    }
    Ok(())
}

pub fn check_delete(d: &Delete, now: i64) -> Result<(), &'static str> {
    if d.ts > now + FUTURE_SKEW_SECS || !in_change_window(d.post_ts, d.ts) || d.post_ts < now - KEEP_POSTS_SECS {
        return Err("time");
    }
    if !is_post_id(&d.post_id) {
        return Err("text");
    }
    if !signed_by(&d.pubkey, &d.from, &d.signing_bytes(), &d.sig) {
        return Err("signature");
    }
    Ok(())
}

pub fn check_post(p: &Post, now: i64) -> Result<(), &'static str> {
    if p.ts > now + FUTURE_SKEW_SECS || p.ts < now - KEEP_POSTS_SECS {
        return Err("time");
    }
    if clean_body(&p.body).as_deref() != Ok(p.body.as_str()) || clean_name(&p.name).as_deref() != Ok(p.name.as_str()) {
        return Err("text");
    }
    if !signed_by(&p.pubkey, &p.from, &p.signing_bytes(), &p.sig) {
        return Err("signature");
    }
    Ok(())
}

pub fn check_vote(v: &Vote, now: i64) -> Result<(), &'static str> {
    if v.ts > now + FUTURE_SKEW_SECS || v.ts < now - KEEP_VOTES_SECS {
        return Err("time");
    }
    if !is_address(&v.target) || v.target == v.voter {
        return Err("target");
    }
    if !signed_by(&v.pubkey, &v.voter, &v.signing_bytes(), &v.sig) {
        return Err("signature");
    }
    Ok(())
}

pub fn check_name(n: &Name, now: i64) -> Result<(), &'static str> {
    if n.ts > now + FUTURE_SKEW_SECS {
        return Err("time");
    }
    if clean_name(&n.name).as_deref() != Ok(n.name.as_str()) {
        return Err("text");
    }
    if !signed_by(&n.pubkey, &n.from, &n.signing_bytes(), &n.sig) {
        return Err("signature");
    }
    Ok(())
}

pub fn bans(votes: &[(i64, String)]) -> Vec<(i64, i64)> {
    let mut sorted = votes.to_vec();
    sorted.sort();
    let mut floor = i64::MIN;
    let mut open: BTreeMap<String, i64> = BTreeMap::new();
    let mut out = Vec::new();
    for (ts, voter) in sorted {
        if ts < floor {
            continue;
        }
        open.retain(|_, t| ts - *t < VOTE_WINDOW_SECS);
        open.insert(voter, ts);
        if open.len() >= BAN_VOTES {
            out.push((ts, ts.saturating_add(BAN_SECS)));
            floor = ts.saturating_add(BAN_SECS);
            open.clear();
        }
    }
    out
}

pub fn open_votes(votes: &[(i64, String)], now: i64) -> Vec<String> {
    let floor = bans(votes).last().map(|b| b.1).unwrap_or(i64::MIN);
    let mut open: BTreeMap<String, i64> = BTreeMap::new();
    for (ts, voter) in votes {
        if *ts >= floor && *ts <= now && now - *ts < VOTE_WINDOW_SECS {
            open.insert(voter.clone(), *ts);
        }
    }
    open.into_keys().collect()
}

pub fn banned_until(bans: &[(i64, i64)], now: i64) -> Option<i64> {
    bans.iter().find(|(start, end)| *start <= now && now < *end).map(|b| b.1)
}

pub fn hidden(post_ts: i64, bans: &[(i64, i64)]) -> bool {
    bans.iter().any(|(start, end)| start - VOTE_WINDOW_SECS <= post_ts && post_ts < *end)
}

fn post_key(p: &Post) -> Vec<u8> {
    post_key_of(p.ts, &p.id())
}

fn post_key_of(ts: i64, id: &str) -> Vec<u8> {
    format!("{POSTS}{:020}/{}", ts.max(0), id).into_bytes()
}

fn edit_key(post_ts: i64, post_id: &str, author: &str) -> Vec<u8> {
    format!("{EDITS}{:020}/{}/{}", post_ts.max(0), post_id, author).into_bytes()
}

fn delete_key(post_ts: i64, post_id: &str, author: &str) -> Vec<u8> {
    format!("{DELETES}{:020}/{}/{}", post_ts.max(0), post_id, author).into_bytes()
}

pub fn post_by_id(post_ts: i64, post_id: &str) -> Option<Post> {
    crate::chain_db::dao_get(&post_key_of(post_ts, post_id)).and_then(|b| decode(&b))
}

pub fn deletion_of(post: &Post) -> Option<Delete> {
    crate::chain_db::dao_get(&delete_key(post.ts, &post.id(), &post.from)).and_then(|b| decode(&b))
}

pub fn edit_of(post: &Post) -> Option<Edit> {
    crate::chain_db::dao_get(&edit_key(post.ts, &post.id(), &post.from)).and_then(|b| decode(&b))
}

fn scan_since<T: for<'de> Deserialize<'de>>(prefix: &str, since: i64, limit: usize) -> Vec<T> {
    let from = format!("{prefix}{:020}", since.max(0)).into_bytes();
    crate::chain_db::dao_scan(prefix.as_bytes(), &from, false, limit)
        .into_iter()
        .filter_map(|(_, v)| decode(&v))
        .collect()
}

fn vote_key(v: &Vote) -> Vec<u8> {
    format!("{VOTES}{}/{:020}/{}", v.target, v.ts.max(0), v.voter).into_bytes()
}

fn vote_time_key(v: &Vote) -> Vec<u8> {
    format!("{VOTES_BY_TIME}{:020}/{}/{}", v.ts.max(0), v.target, v.voter).into_bytes()
}

fn name_key(addr: &str) -> Vec<u8> {
    format!("{NAMES}{addr}").into_bytes()
}

fn upper(prefix: &str) -> Vec<u8> {
    let mut k = prefix.as_bytes().to_vec();
    k.push(0xff);
    k
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Option<T> {
    serde_json::from_slice(bytes).ok()
}

pub fn votes_against(target: &str) -> Vec<Vote> {
    let prefix = format!("{VOTES}{target}/");
    crate::chain_db::dao_scan(prefix.as_bytes(), prefix.as_bytes(), false, usize::MAX)
        .into_iter()
        .filter_map(|(_, v)| decode(&v))
        .collect()
}

pub fn ban_record(target: &str) -> (Vec<(i64, String)>, Vec<(i64, i64)>) {
    let votes: Vec<(i64, String)> = votes_against(target).into_iter().map(|v| (v.ts, v.voter)).collect();
    let b = bans(&votes);
    (votes, b)
}

pub fn name_of(addr: &str) -> Option<Name> {
    crate::chain_db::dao_get(&name_key(addr)).and_then(|b| decode(&b))
}

pub fn recent_posts(before: Option<i64>, limit: usize) -> Vec<Post> {
    let from = match before {
        Some(ts) => format!("{POSTS}{:020}", ts.max(0)).into_bytes(),
        None => upper(POSTS),
    };
    let mut posts: Vec<Post> = crate::chain_db::dao_scan(POSTS.as_bytes(), &from, true, limit)
        .into_iter()
        .filter_map(|(_, v)| decode(&v))
        .filter(|p: &Post| before.map(|b| p.ts < b).unwrap_or(true))
        .collect();
    posts.reverse();
    posts
}

pub fn posts_since(since: i64, limit: usize) -> Vec<Post> {
    let mut posts = recent_posts(None, limit);
    posts.retain(|p| p.ts >= since);
    posts
}

pub fn votes_since(since: i64, limit: usize) -> Vec<Vote> {
    let from = upper(VOTES_BY_TIME);
    let mut out = Vec::new();
    for (k, _) in crate::chain_db::dao_scan(VOTES_BY_TIME.as_bytes(), &from, true, limit) {
        let key = String::from_utf8_lossy(&k).to_string();
        let mut parts = key[VOTES_BY_TIME.len()..].splitn(3, '/');
        let (Some(ts), Some(target), Some(voter)) = (parts.next(), parts.next(), parts.next()) else { continue };
        let Ok(ts) = ts.parse::<i64>() else { continue };
        if ts < since {
            break;
        }
        let vk = format!("{VOTES}{target}/{:020}/{voter}", ts);
        if let Some(v) = crate::chain_db::dao_get(vk.as_bytes()).and_then(|b| decode::<Vote>(&b)) {
            out.push(v);
        }
    }
    out.reverse();
    out
}

static INSERTS: Mutex<u32> = Mutex::new(0);
static ARRIVALS: Mutex<Option<HashMap<String, Vec<i64>>>> = Mutex::new(None);

fn note_insert() {
    let due = {
        let mut n = INSERTS.lock().unwrap_or_else(|e| e.into_inner());
        *n += 1;
        *n % PRUNE_EVERY == 0
    };
    if due {
        prune(chrono::Utc::now().timestamp());
    }
}

pub fn prune(now: i64) {
    let old_posts: Vec<Vec<u8>> = {
        let all = crate::chain_db::dao_scan(POSTS.as_bytes(), POSTS.as_bytes(), false, usize::MAX);
        let excess = all.len().saturating_sub(MAX_KEPT_POSTS);
        all.into_iter()
            .enumerate()
            .filter(|(i, (_, v))| *i < excess || decode::<Post>(v).map(|p| p.ts < now - KEEP_POSTS_SECS).unwrap_or(true))
            .map(|(_, (k, _))| k)
            .collect()
    };
    crate::chain_db::dao_delete(&old_posts);

    let cutoff = format!("{VOTES_BY_TIME}{:020}", (now - KEEP_VOTES_SECS).max(0));
    let mut stale = Vec::new();
    for (k, _) in crate::chain_db::dao_scan(VOTES_BY_TIME.as_bytes(), VOTES_BY_TIME.as_bytes(), false, usize::MAX) {
        if k.as_slice() >= cutoff.as_bytes() {
            break;
        }
        let key = String::from_utf8_lossy(&k).to_string();
        let mut parts = key[VOTES_BY_TIME.len()..].splitn(3, '/');
        if let (Some(ts), Some(target), Some(voter)) = (parts.next(), parts.next(), parts.next()) {
            stale.push(format!("{VOTES}{target}/{ts}/{voter}").into_bytes());
        }
        stale.push(k);
    }
    crate::chain_db::dao_delete(&stale);

    for prefix in [EDITS, DELETES] {
        let cutoff = format!("{prefix}{:020}", (now - KEEP_POSTS_SECS).max(0));
        let old: Vec<Vec<u8>> = crate::chain_db::dao_scan(prefix.as_bytes(), prefix.as_bytes(), false, usize::MAX)
            .into_iter()
            .map(|(k, _)| k)
            .take_while(|k| k.as_slice() < cutoff.as_bytes())
            .collect();
        crate::chain_db::dao_delete(&old);
    }
}

fn within_burst(author: &str, now: i64, min_gap: i64) -> bool {
    let mut guard = ARRIVALS.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    if map.len() > 50_000 {
        map.retain(|_, times| times.last().map(|t| now - *t < BURST_WINDOW_SECS).unwrap_or(false));
    }
    let times = map.entry(author.to_string()).or_default();
    times.retain(|t| now - *t < BURST_WINDOW_SECS);
    if times.len() >= BURST_MAX || times.last().map(|t| now - *t < min_gap).unwrap_or(false) {
        return false;
    }
    times.push(now);
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Local,
    Gossip,
    Sync,
}

pub fn accept(wire: &Wire, now: i64, source: Source) -> Result<bool, &'static str> {
    match wire {
        Wire::Post(p) => {
            check_post(p, now)?;
            if banned_until(&ban_record(&p.from).1, p.ts).is_some() {
                return Err("banned");
            }
            let key = post_key(p);
            if crate::chain_db::dao_get(&key).is_some() || deletion_of(p).is_some() {
                return Ok(false);
            }
            if source == Source::Gossip && !within_burst(&p.from, now, MIN_POST_GAP_SECS) {
                return Err("rate");
            }
            let bytes = serde_json::to_vec(p).map_err(|_| "encode")?;
            crate::chain_db::dao_put(&key, &bytes).map_err(|_| "store")?;
            note_insert();
            Ok(true)
        }
        Wire::Vote(v) => {
            check_vote(v, now)?;
            let key = vote_key(v);
            if crate::chain_db::dao_get(&key).is_some() {
                return Ok(false);
            }
            let bytes = serde_json::to_vec(v).map_err(|_| "encode")?;
            crate::chain_db::dao_put(&key, &bytes).map_err(|_| "store")?;
            crate::chain_db::dao_put(&vote_time_key(v), b"").map_err(|_| "store")?;
            note_insert();
            Ok(true)
        }
        Wire::Name(n) => {
            check_name(n, now)?;
            if name_of(&n.from).map(|old| old.ts >= n.ts).unwrap_or(false) {
                return Ok(false);
            }
            let bytes = serde_json::to_vec(n).map_err(|_| "encode")?;
            crate::chain_db::dao_put(&name_key(&n.from), &bytes).map_err(|_| "store")?;
            Ok(true)
        }
        Wire::Edit(e) => {
            check_edit(e, now)?;
            if source == Source::Gossip && e.ts < now - LATE_GOSSIP_SECS {
                return Err("time");
            }
            if post_by_id(e.post_ts, &e.post_id).map(|p| p.from != e.from).unwrap_or(false) {
                return Err("author");
            }
            if crate::chain_db::dao_get(&delete_key(e.post_ts, &e.post_id, &e.from)).is_some() {
                return Ok(false);
            }
            let key = edit_key(e.post_ts, &e.post_id, &e.from);
            let newer = crate::chain_db::dao_get(&key)
                .and_then(|b| decode::<Edit>(&b))
                .map(|old| (e.ts, &e.sig) > (old.ts, &old.sig))
                .unwrap_or(true);
            if !newer {
                return Ok(false);
            }
            if source == Source::Gossip && !within_burst(&e.from, now, 0) {
                return Err("rate");
            }
            let bytes = serde_json::to_vec(e).map_err(|_| "encode")?;
            crate::chain_db::dao_put(&key, &bytes).map_err(|_| "store")?;
            Ok(true)
        }
        Wire::Delete(d) => {
            check_delete(d, now)?;
            let post = post_by_id(d.post_ts, &d.post_id);
            if post.as_ref().map(|p| p.from != d.from).unwrap_or(false) {
                return Err("author");
            }
            let key = delete_key(d.post_ts, &d.post_id, &d.from);
            if crate::chain_db::dao_get(&key).is_some() {
                return Ok(false);
            }
            if source == Source::Gossip && !within_burst(&d.from, now, 0) {
                return Err("rate");
            }
            let bytes = serde_json::to_vec(d).map_err(|_| "encode")?;
            crate::chain_db::dao_put(&key, &bytes).map_err(|_| "store")?;
            if post.is_some() {
                crate::chain_db::dao_delete(&[post_key_of(d.post_ts, &d.post_id), edit_key(d.post_ts, &d.post_id, &d.from)]);
            }
            Ok(true)
        }
    }
}

pub fn sync_response(req: &SyncRequest, now: i64) -> SyncResponse {
    let since = req.since.max(now - KEEP_POSTS_SECS);
    let posts = posts_since(since, SYNC_MAX_POSTS);
    let vote_floor = since.min(now - BAN_SECS - VOTE_WINDOW_SECS);
    let votes = votes_since(vote_floor, SYNC_MAX_VOTES);
    let mut authors: Vec<&str> = posts.iter().map(|p| p.from.as_str()).collect();
    authors.sort();
    authors.dedup();
    let names = authors.into_iter().filter_map(name_of).collect();
    let edits = scan_since(EDITS, since, SYNC_MAX_POSTS);
    let deletes = scan_since(DELETES, since, SYNC_MAX_POSTS);
    SyncResponse { posts, votes, names, edits, deletes }
}

pub fn ingest(resp: SyncResponse, now: i64) -> usize {
    let mut fresh = 0;
    for d in resp.deletes.into_iter().take(SYNC_MAX_POSTS) {
        if accept(&Wire::Delete(d), now, Source::Sync) == Ok(true) {
            fresh += 1;
        }
    }
    for n in resp.names {
        if accept(&Wire::Name(n), now, Source::Sync) == Ok(true) {
            fresh += 1;
        }
    }
    for v in resp.votes.into_iter().take(SYNC_MAX_VOTES) {
        if accept(&Wire::Vote(v), now, Source::Sync) == Ok(true) {
            fresh += 1;
        }
    }
    for p in resp.posts.into_iter().take(SYNC_MAX_POSTS) {
        if accept(&Wire::Post(p), now, Source::Sync) == Ok(true) {
            fresh += 1;
        }
    }
    for e in resp.edits.into_iter().take(SYNC_MAX_POSTS) {
        if accept(&Wire::Edit(e), now, Source::Sync) == Ok(true) {
            fresh += 1;
        }
    }
    fresh
}

pub fn latest_post_ts() -> Option<i64> {
    recent_posts(None, 1).first().map(|p| p.ts)
}

pub async fn receive_gossip(data: Vec<u8>, app: Option<tauri::AppHandle>) {
    let Ok(wire) = serde_json::from_slice::<Wire>(&data) else { return };
    let now = chrono::Utc::now().timestamp();
    let fresh = tokio::task::spawn_blocking(move || accept(&wire, now, Source::Gossip))
        .await
        .unwrap_or(Err("join"));
    if fresh == Ok(true) {
        notify(app.as_ref());
    }
}

pub fn notify(app: Option<&tauri::AppHandle>) {
    use tauri::Manager;
    if let Some(app) = app {
        let _ = app.emit_all("ego://dao-chat", serde_json::json!({}));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> ego_core::KeyPair {
        ego_core::KeyPair::generate()
    }

    fn votes(entries: &[(i64, &str)]) -> Vec<(i64, String)> {
        entries.iter().map(|(t, v)| (*t, v.to_string())).collect()
    }

    const DAY: i64 = 86_400;

    #[test]
    fn signed_messages_verify_and_tampering_breaks_them() {
        let kp = key();
        let now = 1_800_000_000;
        let p = sign_post(&kp, "Artit", "hello ego", now);
        assert_eq!(check_post(&p, now), Ok(()));
        let mut changed = p.clone();
        changed.body = "hello ego!".into();
        assert_eq!(check_post(&changed, now), Err("signature"));
        let mut stolen = p.clone();
        stolen.from = address_of_key(&key());
        assert_eq!(check_post(&stolen, now), Err("signature"));

        let v = sign_vote(&kp, &address_of_key(&key()), now);
        assert_eq!(check_vote(&v, now), Ok(()));
        let mut redirected = v.clone();
        redirected.target = address_of_key(&key());
        assert_eq!(check_vote(&redirected, now), Err("signature"));

        let n = sign_name(&kp, "New name", now);
        assert_eq!(check_name(&n, now), Ok(()));
    }

    #[test]
    fn signing_bytes_and_ids_match_the_phone_app() {
        let from = "egot1yzwkx349luk82ksl0xe2tm6rfwj26t7pg5apncg2";
        let p = Post { from: from.into(), name: "Artit".into(), body: "hello\nego".into(), ts: 1_800_000_000, pubkey: String::new(), sig: String::new() };
        assert_eq!(p.signing_bytes(), format!("ego/dao-chat/post/v1\n{from}\n1800000000\nArtit\nhello\nego").into_bytes());
        assert_eq!(p.id(), "cb73b6f6aed5d28c2e7546f860543c1e");
        let e = Edit { from: from.into(), post_id: p.id(), post_ts: p.ts, body: "hello again".into(), ts: 1_800_000_003, pubkey: String::new(), sig: String::new() };
        assert_eq!(e.signing_bytes(), format!("ego/dao-chat/edit/v1\n{from}\ncb73b6f6aed5d28c2e7546f860543c1e\n1800000000\n1800000003\nhello again").into_bytes());
        let d = Delete { from: from.into(), post_id: p.id(), post_ts: p.ts, ts: 1_800_000_004, pubkey: String::new(), sig: String::new() };
        assert_eq!(d.signing_bytes(), format!("ego/dao-chat/delete/v1\n{from}\ncb73b6f6aed5d28c2e7546f860543c1e\n1800000000\n1800000004").into_bytes());
    }

    #[test]
    fn nobody_can_vote_against_themselves() {
        let kp = key();
        let v = sign_vote(&kp, &address_of_key(&kp), 1_800_000_000);
        assert_eq!(check_vote(&v, 1_800_000_000), Err("target"));
    }

    #[test]
    fn text_rules_hold_on_both_sides() {
        assert!(clean_body("   ").is_err());
        assert!(clean_body(&"x".repeat(MAX_BODY_CHARS + 1)).is_err());
        assert!(clean_body("bell\u{7}").is_err());
        assert_eq!(clean_body("  two\nlines  ").unwrap(), "two\nlines");
        assert!(clean_name(&"n".repeat(MAX_NAME_CHARS + 1)).is_err());
        assert!(clean_name("tab\there").is_err());
        assert_eq!(clean_name("  Artit ").unwrap(), "Artit");

        let kp = key();
        let padded = sign_post(&kp, "", "  padded  ", 1_800_000_000);
        assert_eq!(check_post(&padded, 1_800_000_000), Err("text"));
    }

    #[test]
    fn messages_from_the_future_or_too_old_are_refused() {
        let kp = key();
        let now = 1_800_000_000;
        assert_eq!(check_post(&sign_post(&kp, "", "hi", now + 3_600), now), Err("time"));
        assert_eq!(check_post(&sign_post(&kp, "", "hi", now - 40 * DAY), now), Err("time"));
    }

    #[test]
    fn four_votes_are_not_enough_and_five_ban_for_two_weeks() {
        let t = 1_800_000_000;
        assert!(bans(&votes(&[(t, "a"), (t + 1, "b"), (t + 2, "c"), (t + 3, "d")])).is_empty());
        let b = bans(&votes(&[(t, "a"), (t + 1, "b"), (t + 2, "c"), (t + 3, "d"), (t + 4, "e")]));
        assert_eq!(b, vec![(t + 4, t + 4 + BAN_SECS)]);
        assert_eq!(banned_until(&b, t + 5), Some(t + 4 + BAN_SECS));
        assert_eq!(banned_until(&b, t + 4 + BAN_SECS), None);
    }

    #[test]
    fn one_address_counts_once() {
        let t = 1_800_000_000;
        let v = votes(&[(t, "a"), (t + 1, "a"), (t + 2, "a"), (t + 3, "b"), (t + 4, "c"), (t + 5, "d")]);
        assert!(bans(&v).is_empty());
        assert_eq!(open_votes(&v, t + 10).len(), 4);
    }

    #[test]
    fn votes_spread_over_more_than_two_weeks_do_not_ban() {
        let t = 1_800_000_000;
        let v = votes(&[(t, "a"), (t + 4 * DAY, "b"), (t + 8 * DAY, "c"), (t + 12 * DAY, "d"), (t + 15 * DAY, "e")]);
        assert!(bans(&v).is_empty());
    }

    #[test]
    fn a_ban_ends_and_needs_five_fresh_votes_to_return() {
        let t = 1_800_000_000;
        let mut v = votes(&[(t, "a"), (t + 1, "b"), (t + 2, "c"), (t + 3, "d"), (t + 4, "e")]);
        v.extend(votes(&[(t + DAY, "f"), (t + 2 * DAY, "g")]));
        let b = bans(&v);
        assert_eq!(b.len(), 1, "votes cast during a ban do not count toward the next one");
        assert!(open_votes(&v, t + 4 + BAN_SECS + 1).is_empty());

        let end = t + 4 + BAN_SECS;
        v.extend(votes(&[(end + 1, "a"), (end + 2, "b"), (end + 3, "c"), (end + 4, "d"), (end + 5, "e")]));
        assert_eq!(bans(&v).len(), 2);
    }

    #[test]
    fn a_voter_cannot_lift_a_ban_by_voting_again() {
        let t = 1_800_000_000;
        let mut v = votes(&[(t, "a"), (t + 1, "b"), (t + 2, "c"), (t + 3, "d"), (t + 4, "e")]);
        let before = bans(&v);
        v.push((t + DAY, "a".to_string()));
        assert_eq!(bans(&v), before);
    }

    #[test]
    fn a_removed_user_disappears_including_recent_posts() {
        let t = 1_800_000_000;
        let b = vec![(t, t + BAN_SECS)];
        assert!(hidden(t - DAY, &b), "a post shortly before the ban goes too");
        assert!(hidden(t + DAY, &b));
        assert!(!hidden(t - 20 * DAY, &b), "old posts stay");
        assert!(!hidden(t + BAN_SECS, &b), "posts after the ban show again");
    }

    #[test]
    fn stored_chat_rejects_posts_from_a_removed_user_and_counts_votes() {
        let now = chrono::Utc::now().timestamp();
        let bad = key();
        let target = address_of_key(&bad);
        assert_eq!(accept(&Wire::Post(sign_post(&bad, "Spammer", "first", now - 60)), now, Source::Local), Ok(true));
        assert_eq!(accept(&Wire::Post(sign_post(&bad, "Spammer", "first", now - 60)), now, Source::Local), Ok(false));

        let voters: Vec<_> = (0..5).map(|_| key()).collect();
        for (i, kp) in voters.iter().enumerate() {
            assert_eq!(accept(&Wire::Vote(sign_vote(kp, &target, now - 50 + i as i64)), now, Source::Local), Ok(true));
        }
        let (_, b) = ban_record(&target);
        assert_eq!(b.len(), 1);
        assert!(banned_until(&b, now).is_some());
        assert_eq!(accept(&Wire::Post(sign_post(&bad, "Spammer", "back again", now)), now, Source::Local), Err("banned"));

        let names = recent_posts(None, 2_000);
        let mine: Vec<_> = names.iter().filter(|p| p.from == target).collect();
        assert_eq!(mine.len(), 1);
        assert!(hidden(mine[0].ts, &b));
    }

    #[test]
    fn gossip_floods_from_one_address_are_cut_off() {
        let now = chrono::Utc::now().timestamp();
        let kp = key();
        assert_eq!(accept(&Wire::Post(sign_post(&kp, "", "one", now)), now, Source::Gossip), Ok(true));
        assert_eq!(accept(&Wire::Post(sign_post(&kp, "", "two", now)), now, Source::Gossip), Err("rate"));
    }

    #[test]
    fn a_newer_name_replaces_an_older_one_only() {
        let now = chrono::Utc::now().timestamp();
        let kp = key();
        assert_eq!(accept(&Wire::Name(sign_name(&kp, "First", now - 10)), now, Source::Local), Ok(true));
        assert_eq!(accept(&Wire::Name(sign_name(&kp, "Older", now - 20)), now, Source::Local), Ok(false));
        assert_eq!(accept(&Wire::Name(sign_name(&kp, "Second", now)), now, Source::Local), Ok(true));
        assert_eq!(name_of(&address_of_key(&kp)).unwrap().name, "Second");
    }

    #[test]
    fn the_author_can_edit_within_an_hour_and_nobody_else_can() {
        let now = chrono::Utc::now().timestamp();
        let kp = key();
        let p = sign_post(&kp, "Ed", "frist", now - 120);
        accept(&Wire::Post(p.clone()), now, Source::Local).unwrap();
        assert_eq!(accept(&Wire::Edit(sign_edit(&kp, &p, "first", now - 60)), now, Source::Gossip), Ok(true));
        assert_eq!(edit_of(&p).unwrap().body, "first");

        let stranger = key();
        let fake = sign_edit(&stranger, &p, "I said something else", now - 30);
        assert_eq!(accept(&Wire::Edit(fake), now, Source::Gossip), Err("author"));
        assert_eq!(edit_of(&p).unwrap().body, "first");

        assert_eq!(accept(&Wire::Edit(sign_edit(&kp, &p, "older text", now - 90)), now, Source::Sync), Ok(false));
        assert_eq!(edit_of(&p).unwrap().body, "first");
    }

    #[test]
    fn edits_and_deletes_after_the_hour_are_refused() {
        let now = chrono::Utc::now().timestamp();
        let kp = key();
        let p = sign_post(&kp, "Late", "said this", now - 2 * 3_600);
        accept(&Wire::Post(p.clone()), now, Source::Local).unwrap();
        assert_eq!(check_edit(&sign_edit(&kp, &p, "changed", now), now), Err("time"));
        assert_eq!(check_delete(&sign_delete(&kp, &p, now), now), Err("time"));
        let backdated = sign_edit(&kp, &p, "changed", p.ts + 60);
        assert_eq!(accept(&Wire::Edit(backdated), now, Source::Gossip), Err("time"));
        assert!(!can_change(p.ts, now));
        assert!(can_change(now - 10, now));
    }

    #[test]
    fn a_deleted_message_is_gone_and_cannot_come_back_through_sync() {
        let now = chrono::Utc::now().timestamp();
        let kp = key();
        let p = sign_post(&kp, "Oops", "wrong chat", now - 30);
        accept(&Wire::Post(p.clone()), now, Source::Local).unwrap();
        assert_eq!(accept(&Wire::Delete(sign_delete(&key(), &p, now)), now, Source::Gossip), Err("author"));
        assert!(post_by_id(p.ts, &p.id()).is_some());

        assert_eq!(accept(&Wire::Delete(sign_delete(&kp, &p, now - 1)), now, Source::Gossip), Ok(true));
        assert!(post_by_id(p.ts, &p.id()).is_none());
        assert_eq!(accept(&Wire::Post(p.clone()), now, Source::Sync), Ok(false));
        assert!(post_by_id(p.ts, &p.id()).is_none());
        let resp = sync_response(&SyncRequest { since: now - 3_600 }, now);
        assert!(resp.deletes.iter().any(|d| d.post_id == p.id() && d.from == p.from));
    }

    #[test]
    fn a_stranger_cannot_delete_a_post_this_node_has_not_seen_yet() {
        let now = chrono::Utc::now().timestamp();
        let author = key();
        let p = sign_post(&author, "Later", "arrives late", now - 30);
        let _ = accept(&Wire::Delete(sign_delete(&key(), &p, now)), now, Source::Sync);
        assert_eq!(accept(&Wire::Post(p.clone()), now, Source::Sync), Ok(true));
        assert!(post_by_id(p.ts, &p.id()).is_some());
        assert!(deletion_of(&p).is_none());
    }

    #[test]
    fn deleting_right_after_posting_is_not_mistaken_for_flooding() {
        let now = chrono::Utc::now().timestamp();
        let kp = key();
        let p = sign_post(&kp, "", "typo", now);
        assert_eq!(accept(&Wire::Post(p.clone()), now, Source::Gossip), Ok(true));
        assert_eq!(accept(&Wire::Delete(sign_delete(&kp, &p, now)), now, Source::Gossip), Ok(true));
    }

    #[test]
    fn sync_carries_posts_votes_and_names() {
        let now = chrono::Utc::now().timestamp();
        let kp = key();
        let p = sign_post(&kp, "Syncer", "synced message", now - 5);
        accept(&Wire::Name(sign_name(&kp, "Syncer", now - 6)), now, Source::Local).unwrap();
        accept(&Wire::Post(p.clone()), now, Source::Local).unwrap();
        let resp = sync_response(&SyncRequest { since: now - 3_600 }, now);
        assert!(resp.posts.contains(&p));
        assert!(resp.names.iter().any(|n| n.from == p.from && n.name == "Syncer"));
        let json = serde_json::to_vec(&resp).unwrap();
        assert!(json.len() < SYNC_MAX_RESPONSE_BYTES);
        let wire = serde_json::to_string(&Wire::Post(p.clone())).unwrap();
        assert!(wire.contains("\"kind\":\"post\""));
        assert_eq!(serde_json::from_str::<Wire>(&wire).unwrap(), Wire::Post(p));
    }
}
