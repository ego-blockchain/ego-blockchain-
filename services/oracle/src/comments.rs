use axum::extract::Path;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use once_cell::sync::{Lazy, OnceCell};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tracing::{error, info};

pub const MAX_NAME_CHARS: usize = 32;
pub const MAX_BODY_CHARS: usize = 1_000;
pub const MAX_PER_SLUG: usize = 2_000;
pub const MAX_SLUGS: usize = 1_000;
pub const MAX_SLUG_LEN: usize = 120;
const RATE_WINDOW_MS: i64 = 10 * 60 * 1_000;
const POSTS_PER_WINDOW: usize = 6;
const POSTS_PER_WINDOW_SHARED: usize = 60;
const LIKES_PER_WINDOW: usize = 120;
const EARLIEST_TS_MS: i64 = 1_700_000_000_000;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Comment {
    pub id: String,
    pub name: String,
    pub body: String,
    pub ts: i64,
    #[serde(default)]
    pub edited: bool,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub likers: Vec<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct View {
    pub id: String,
    pub name: String,
    pub body: String,
    pub ts: i64,
    pub edited: bool,
    pub likes: usize,
}

impl Comment {
    pub fn view(&self) -> View {
        View {
            id: self.id.clone(),
            name: self.name.clone(),
            body: self.body.clone(),
            ts: self.ts,
            edited: self.edited,
            likes: self.likers.len(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Store {
    pub articles: HashMap<String, Vec<Comment>>,
}

pub fn digest(secret: &str) -> String {
    let h = blake3::hash(format!("ego/blog/owner/v1:{secret}").as_bytes());
    hex::encode(&h.as_bytes()[..16])
}

pub fn valid_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= MAX_SLUG_LEN
        && slug.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn valid_secret(secret: &str) -> bool {
    (8..=128).contains(&secret.len()) && secret.bytes().all(|b| b.is_ascii_graphic())
}

pub fn clean(text: &str, max_chars: usize) -> Result<String, &'static str> {
    let kept: String = text
        .chars()
        .filter(|c| *c == '\n' || !c.is_control())
        .collect();
    let trimmed = kept.trim();
    if trimmed.is_empty() {
        return Err("empty");
    }
    if trimmed.chars().count() > max_chars {
        return Err("too long");
    }
    Ok(trimmed.to_string())
}

impl Store {
    pub fn list(&self, slug: &str) -> Vec<View> {
        let mut out: Vec<View> = self
            .articles
            .get(slug)
            .map(|v| v.iter().map(Comment::view).collect())
            .unwrap_or_default();
        out.sort_by(|a, b| b.ts.cmp(&a.ts).then_with(|| b.id.cmp(&a.id)));
        out
    }

    pub fn create(
        &mut self,
        slug: &str,
        name: &str,
        body: &str,
        owner: &str,
        ts_hint: Option<i64>,
        now_ms: i64,
    ) -> Result<View, &'static str> {
        if !valid_slug(slug) {
            return Err("unknown article");
        }
        if !valid_secret(owner) {
            return Err("missing owner token");
        }
        let name = clean(name, MAX_NAME_CHARS)?;
        let body = clean(body, MAX_BODY_CHARS)?;
        if !self.articles.contains_key(slug) && self.articles.len() >= MAX_SLUGS {
            return Err("too many articles");
        }
        let list = self.articles.entry(slug.to_string()).or_default();
        if list.len() >= MAX_PER_SLUG {
            return Err("this article has reached its comment limit");
        }
        let ts = ts_hint
            .filter(|t| (EARLIEST_TS_MS..=now_ms).contains(t))
            .unwrap_or(now_ms);
        let seed = format!("{slug}:{ts}:{name}:{body}:{owner}:{now_ms}:{}", list.len());
        let id = hex::encode(&blake3::hash(seed.as_bytes()).as_bytes()[..8]);
        let comment = Comment { id, name, body, ts, edited: false, owner: digest(owner), likers: Vec::new() };
        let view = comment.view();
        list.push(comment);
        Ok(view)
    }

    fn find(&mut self, slug: &str, id: &str) -> Result<&mut Comment, &'static str> {
        self.articles
            .get_mut(slug)
            .and_then(|l| l.iter_mut().find(|c| c.id == id))
            .ok_or("no such comment")
    }

    pub fn edit(&mut self, slug: &str, id: &str, body: &str, owner: &str) -> Result<View, &'static str> {
        let body = clean(body, MAX_BODY_CHARS)?;
        let c = self.find(slug, id)?;
        if c.owner != digest(owner) {
            return Err("not your comment");
        }
        c.body = body;
        c.edited = true;
        Ok(c.view())
    }

    pub fn delete(&mut self, slug: &str, id: &str, owner: Option<&str>, admin: bool) -> Result<(), &'static str> {
        let owner_ok = {
            let c = self.find(slug, id)?;
            owner.map_or(false, |o| c.owner == digest(o))
        };
        if !owner_ok && !admin {
            return Err("not your comment");
        }
        if let Some(list) = self.articles.get_mut(slug) {
            list.retain(|c| c.id != id);
            if list.is_empty() {
                self.articles.remove(slug);
            }
        }
        Ok(())
    }

    pub fn like(&mut self, slug: &str, id: &str, voter: &str, liked: bool) -> Result<usize, &'static str> {
        if !valid_secret(voter) {
            return Err("missing voter token");
        }
        let key = digest(voter);
        let c = self.find(slug, id)?;
        let present = c.likers.iter().any(|k| *k == key);
        if liked && !present {
            c.likers.push(key);
        } else if !liked && present {
            c.likers.retain(|k| *k != key);
        }
        Ok(c.likers.len())
    }
}

static PATH: OnceCell<std::path::PathBuf> = OnceCell::new();
static STORE: Lazy<RwLock<Store>> = Lazy::new(|| RwLock::new(Store::default()));
static RATE: Lazy<RwLock<HashMap<String, Vec<i64>>>> = Lazy::new(|| RwLock::new(HashMap::new()));

pub async fn init(path: std::path::PathBuf) {
    let loaded = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice::<Store>(&b).ok())
        .unwrap_or_default();
    let count: usize = loaded.articles.values().map(Vec::len).sum();
    info!("Blog comments: {} loaded from {}", count, path.display());
    *STORE.write().await = loaded;
    let _ = PATH.set(path);
}

async fn persist(store: &Store) {
    let Some(path) = PATH.get().cloned() else { return };
    let data = match serde_json::to_vec(store) {
        Ok(d) => d,
        Err(e) => {
            error!("Blog comments: cannot encode: {e}");
            return;
        }
    };
    let result = tokio::task::spawn_blocking(move || {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &data)?;
        std::fs::rename(&tmp, &path)
    })
    .await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => error!("Blog comments: saving FAILED: {e}"),
        Err(e) => error!("Blog comments: saving task failed: {e}"),
    }
}

fn client_key(headers: &HeaderMap) -> Option<String> {
    let forwarded = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    forwarded.or_else(|| {
        headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    })
}

pub fn rate_ok(log: &mut Vec<i64>, now_ms: i64, limit: usize) -> bool {
    log.retain(|t| now_ms - *t < RATE_WINDOW_MS);
    if log.len() >= limit {
        return false;
    }
    log.push(now_ms);
    true
}

async fn allow(headers: &HeaderMap, kind: &str, per_client: usize, shared: usize) -> bool {
    let now = chrono::Utc::now().timestamp_millis();
    let (key, limit) = match client_key(headers) {
        Some(ip) => (format!("{kind}:{ip}"), per_client),
        None => (format!("{kind}:shared"), shared),
    };
    let mut rate = RATE.write().await;
    if rate.len() > 50_000 {
        rate.retain(|_, v| v.last().map_or(false, |t| now - *t < RATE_WINDOW_MS));
    }
    rate_ok(rate.entry(key).or_default(), now, limit)
}

fn admin_ok(token: Option<&str>) -> bool {
    match (std::env::var("BLOG_ADMIN_TOKEN").ok(), token) {
        (Some(expected), Some(given)) => !expected.is_empty() && expected == given,
        _ => false,
    }
}

fn refuse(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

#[derive(Deserialize)]
pub struct CreateReq {
    pub name: String,
    pub body: String,
    pub owner: String,
    #[serde(default)]
    pub ts: Option<i64>,
}

#[derive(Deserialize)]
pub struct EditReq {
    pub body: String,
    pub owner: String,
}

#[derive(Deserialize)]
pub struct DeleteReq {
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub admin: Option<String>,
}

#[derive(Deserialize)]
pub struct LikeReq {
    pub voter: String,
    pub liked: bool,
}

pub async fn handle_list(Path(slug): Path<String>) -> Response {
    if !valid_slug(&slug) {
        return refuse(StatusCode::BAD_REQUEST, "unknown article");
    }
    let comments = STORE.read().await.list(&slug);
    Json(json!({ "comments": comments })).into_response()
}

pub async fn handle_create(Path(slug): Path<String>, headers: HeaderMap, Json(req): Json<CreateReq>) -> Response {
    if !allow(&headers, "post", POSTS_PER_WINDOW, POSTS_PER_WINDOW_SHARED).await {
        return refuse(StatusCode::TOO_MANY_REQUESTS, "too many comments, try again in a few minutes");
    }
    let now = chrono::Utc::now().timestamp_millis();
    let mut store = STORE.write().await;
    match store.create(&slug, &req.name, &req.body, &req.owner, req.ts, now) {
        Ok(view) => {
            persist(&store).await;
            Json(json!({ "comment": view })).into_response()
        }
        Err(e) => refuse(StatusCode::BAD_REQUEST, e),
    }
}

pub async fn handle_edit(Path((slug, id)): Path<(String, String)>, Json(req): Json<EditReq>) -> Response {
    let mut store = STORE.write().await;
    match store.edit(&slug, &id, &req.body, &req.owner) {
        Ok(view) => {
            persist(&store).await;
            Json(json!({ "comment": view })).into_response()
        }
        Err(e) => refuse(StatusCode::FORBIDDEN, e),
    }
}

pub async fn handle_delete(Path((slug, id)): Path<(String, String)>, Json(req): Json<DeleteReq>) -> Response {
    let admin = admin_ok(req.admin.as_deref());
    let mut store = STORE.write().await;
    match store.delete(&slug, &id, req.owner.as_deref(), admin) {
        Ok(()) => {
            persist(&store).await;
            Json(json!({ "ok": true })).into_response()
        }
        Err(e) => refuse(StatusCode::FORBIDDEN, e),
    }
}

pub async fn handle_like(Path((slug, id)): Path<(String, String)>, headers: HeaderMap, Json(req): Json<LikeReq>) -> Response {
    if !allow(&headers, "like", LIKES_PER_WINDOW, LIKES_PER_WINDOW * 10).await {
        return refuse(StatusCode::TOO_MANY_REQUESTS, "too many likes, try again in a few minutes");
    }
    let mut store = STORE.write().await;
    match store.like(&slug, &id, &req.voter, req.liked) {
        Ok(likes) => {
            persist(&store).await;
            Json(json!({ "likes": likes })).into_response()
        }
        Err(e) => refuse(StatusCode::BAD_REQUEST, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_792_000_000_000;
    const ME: &str = "c-1761000000000-abcdefgh";
    const YOU: &str = "c-1761000000000-zyxwvuts";

    #[test]
    fn a_comment_is_stored_and_listed_newest_first() {
        let mut s = Store::default();
        s.create("post-a", "Ana", "first", ME, None, NOW).unwrap();
        s.create("post-a", "Ben", "second", YOU, None, NOW + 5).unwrap();
        let list = s.list("post-a");
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].body, "second");
        assert!(s.list("post-b").is_empty());
    }

    #[test]
    fn only_the_author_can_edit_or_delete_but_an_admin_can_remove_anything() {
        let mut s = Store::default();
        let v = s.create("post-a", "Ana", "hello", ME, None, NOW).unwrap();
        assert!(s.edit("post-a", &v.id, "changed", YOU).is_err());
        let edited = s.edit("post-a", &v.id, "changed", ME).unwrap();
        assert!(edited.edited);
        assert_eq!(edited.body, "changed");
        assert!(s.delete("post-a", &v.id, Some(YOU), false).is_err());
        assert!(s.delete("post-a", &v.id, None, true).is_ok());
        assert!(s.list("post-a").is_empty());
    }

    #[test]
    fn a_like_counts_once_per_reader_and_can_be_taken_back() {
        let mut s = Store::default();
        let v = s.create("post-a", "Ana", "hello", ME, None, NOW).unwrap();
        assert_eq!(s.like("post-a", &v.id, YOU, true).unwrap(), 1);
        assert_eq!(s.like("post-a", &v.id, YOU, true).unwrap(), 1);
        assert_eq!(s.like("post-a", &v.id, ME, true).unwrap(), 2);
        assert_eq!(s.like("post-a", &v.id, YOU, false).unwrap(), 1);
    }

    #[test]
    fn bad_input_is_refused() {
        let mut s = Store::default();
        assert!(s.create("Post A", "Ana", "x", ME, None, NOW).is_err(), "slugs are lowercase words and dashes");
        assert!(s.create("post-a", "   ", "x", ME, None, NOW).is_err());
        assert!(s.create("post-a", "Ana", "", ME, None, NOW).is_err());
        assert!(s.create("post-a", &"n".repeat(MAX_NAME_CHARS + 1), "x", ME, None, NOW).is_err());
        assert!(s.create("post-a", "Ana", &"b".repeat(MAX_BODY_CHARS + 1), ME, None, NOW).is_err());
        assert!(s.create("post-a", "Ana", "x", "short", None, NOW).is_err(), "the owner token proves authorship");
        assert_eq!(clean("  hi\u{7}\nthere  ", 100).unwrap(), "hi\nthere");
    }

    #[test]
    fn an_old_timestamp_is_kept_when_moving_comments_but_never_one_from_the_future() {
        let mut s = Store::default();
        let old = NOW - 86_400_000;
        assert_eq!(s.create("post-a", "Ana", "moved", ME, Some(old), NOW).unwrap().ts, old);
        assert_eq!(s.create("post-a", "Ana", "future", ME, Some(NOW + 1), NOW).unwrap().ts, NOW);
        assert_eq!(s.create("post-a", "Ana", "ancient", ME, Some(1), NOW).unwrap().ts, NOW);
    }

    #[test]
    fn the_store_survives_a_round_trip_through_its_file_format() {
        let mut s = Store::default();
        let v = s.create("post-a", "Ana", "hello", ME, None, NOW).unwrap();
        s.like("post-a", &v.id, YOU, true).unwrap();
        let back: Store = serde_json::from_slice(&serde_json::to_vec(&s).unwrap()).unwrap();
        assert_eq!(back, s);
        assert_eq!(back.list("post-a")[0].likes, 1);
    }

    #[test]
    fn posting_is_rate_limited_per_window() {
        let mut log = Vec::new();
        for i in 0..POSTS_PER_WINDOW {
            assert!(rate_ok(&mut log, NOW + i as i64, POSTS_PER_WINDOW));
        }
        assert!(!rate_ok(&mut log, NOW + 100, POSTS_PER_WINDOW));
        assert!(rate_ok(&mut log, NOW + RATE_WINDOW_MS + 1_000, POSTS_PER_WINDOW));
    }
}
