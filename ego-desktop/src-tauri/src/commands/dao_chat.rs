use crate::app::AppState;
use crate::dao_chat::{self, Source, Wire};
use crate::error::EgoDesktopError;
use crate::ledger::Ledger;
use ego_core::KeyPair;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Mutex;
use tauri::{AppHandle, State};

const FEED_PAGE: usize = 200;

static LAST_OWN_POST: Mutex<i64> = Mutex::new(0);

#[derive(Debug, Clone, Serialize)]
pub struct PostView {
    pub id: String,
    pub from: String,
    pub name: String,
    pub body: String,
    pub ts: i64,
    pub mine: bool,
    pub edited: bool,
    pub change_until: Option<i64>,
    pub removal_votes: usize,
    pub my_vote: bool,
    pub removed_until: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChatFeed {
    pub me: String,
    pub my_name: String,
    pub my_removed_until: Option<i64>,
    pub threshold: usize,
    pub ban_days: i64,
    pub posts: Vec<PostView>,
    pub oldest: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VoteStatus {
    pub removal_votes: usize,
    pub threshold: usize,
    pub removed_until: Option<i64>,
}

fn keypair(state: &State<'_, AppState>) -> Result<KeyPair, EgoDesktopError> {
    state
        .get_keypair()
        .ok_or_else(|| EgoDesktopError::WalletError("Unlock your wallet to use the chat.".into()))
}

fn refusal(reason: &str) -> EgoDesktopError {
    let text = match reason {
        "banned" => "You were removed from the chat by community votes and can't post yet.",
        "time" => "Your computer's clock looks wrong. Fix the date and time, then try again.",
        "text" => "That message has characters the chat doesn't allow.",
        "target" => "That isn't someone you can vote on.",
        "author" => "You can only change your own messages.",
        _ => "The chat couldn't save that. Try again.",
    };
    EgoDesktopError::InvalidInput(text.into())
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, EgoDesktopError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))
}

async fn publish(wire: &Wire) {
    if let Ok(data) = serde_json::to_vec(wire) {
        crate::p2p::publish_gossip(dao_chat::TOPIC, data).await;
    }
}

pub(crate) fn feed(me: String, before: Option<i64>, now: i64) -> ChatFeed {
    let posts = dao_chat::recent_posts(before, FEED_PAGE);
    let oldest = posts.first().map(|p| p.ts);
    let mut records: HashMap<String, (Vec<(i64, String)>, Vec<(i64, i64)>)> = HashMap::new();
    let mut names: HashMap<String, Option<String>> = HashMap::new();
    let mut views = Vec::with_capacity(posts.len());
    for p in posts {
        let (votes, bans) = records.entry(p.from.clone()).or_insert_with(|| dao_chat::ban_record(&p.from)).clone();
        let mine = p.from == me;
        if !mine && dao_chat::hidden(p.ts, &bans) {
            continue;
        }
        let name = names
            .entry(p.from.clone())
            .or_insert_with(|| dao_chat::name_of(&p.from).map(|n| n.name))
            .clone()
            .unwrap_or_else(|| p.name.clone());
        let open = dao_chat::open_votes(&votes, now);
        let edit = dao_chat::edit_of(&p);
        views.push(PostView {
            id: p.id(),
            from: p.from.clone(),
            name,
            edited: edit.is_some(),
            body: edit.map(|e| e.body).unwrap_or_else(|| p.body.clone()),
            ts: p.ts,
            mine,
            change_until: (mine && dao_chat::can_change(p.ts, now)).then_some(p.ts + dao_chat::CHANGE_WINDOW_SECS),
            removal_votes: open.len(),
            my_vote: open.iter().any(|v| *v == me),
            removed_until: dao_chat::banned_until(&bans, now),
        });
    }
    let my_removed_until = if me.is_empty() { None } else { dao_chat::banned_until(&dao_chat::ban_record(&me).1, now) };
    let my_name = dao_chat::name_of(&me).map(|n| n.name).unwrap_or_default();
    ChatFeed {
        me,
        my_name,
        my_removed_until,
        threshold: dao_chat::BAN_VOTES,
        ban_days: dao_chat::BAN_SECS / 86_400,
        posts: views,
        oldest,
    }
}

#[tauri::command]
pub async fn dao_chat_feed(before: Option<i64>) -> Result<ChatFeed, EgoDesktopError> {
    blocking(move || {
        let me = Ledger::load().address;
        feed(me, before, chrono::Utc::now().timestamp())
    })
    .await
}

#[tauri::command]
pub async fn dao_chat_post(body: String, state: State<'_, AppState>, app: AppHandle) -> Result<(), EgoDesktopError> {
    let kp = keypair(&state)?;
    let body = dao_chat::clean_body(&body).map_err(EgoDesktopError::InvalidInput)?;
    let now = chrono::Utc::now().timestamp();
    {
        let mut last = LAST_OWN_POST.lock().unwrap_or_else(|e| e.into_inner());
        if now - *last < dao_chat::MIN_POST_GAP_SECS {
            return Err(EgoDesktopError::InvalidInput("Slow down a little before sending again.".into()));
        }
        *last = now;
    }
    let me = dao_chat::address_of_key(&kp);
    let name = blocking(move || dao_chat::name_of(&me).map(|n| n.name).unwrap_or_default()).await?;
    let wire = Wire::Post(dao_chat::sign_post(&kp, &name, &body, now));
    let local = wire.clone();
    blocking(move || dao_chat::accept(&local, now, Source::Local)).await?.map_err(refusal)?;
    publish(&wire).await;
    dao_chat::notify(Some(&app));
    Ok(())
}

#[tauri::command]
pub async fn dao_chat_set_name(name: String, state: State<'_, AppState>, app: AppHandle) -> Result<String, EgoDesktopError> {
    let kp = keypair(&state)?;
    let name = dao_chat::clean_name(&name).map_err(EgoDesktopError::InvalidInput)?;
    let now = chrono::Utc::now().timestamp();
    let wire = Wire::Name(dao_chat::sign_name(&kp, &name, now));
    let local = wire.clone();
    blocking(move || dao_chat::accept(&local, now, Source::Local)).await?.map_err(refusal)?;
    publish(&wire).await;
    dao_chat::notify(Some(&app));
    Ok(name)
}

#[tauri::command]
pub async fn dao_chat_vote(target: String, state: State<'_, AppState>, app: AppHandle) -> Result<VoteStatus, EgoDesktopError> {
    let kp = keypair(&state)?;
    let me = dao_chat::address_of_key(&kp);
    let target = target.trim().to_string();
    if !dao_chat::is_address(&target) || target == me {
        return Err(refusal("target"));
    }
    let now = chrono::Utc::now().timestamp();
    let (who, me2) = (target.clone(), me.clone());
    let (votes, bans) = blocking(move || dao_chat::ban_record(&who)).await?;
    if let Some(until) = dao_chat::banned_until(&bans, now) {
        let date = chrono::DateTime::from_timestamp(until, 0).map(|d| d.format("%d %b %Y").to_string()).unwrap_or_default();
        return Err(EgoDesktopError::InvalidInput(format!("They are already removed until {date}.")));
    }
    if dao_chat::open_votes(&votes, now).contains(&me2) {
        return Err(EgoDesktopError::InvalidInput("You already voted to remove them.".into()));
    }
    let wire = Wire::Vote(dao_chat::sign_vote(&kp, &target, now));
    let local = wire.clone();
    blocking(move || dao_chat::accept(&local, now, Source::Local)).await?.map_err(refusal)?;
    publish(&wire).await;
    dao_chat::notify(Some(&app));
    let (votes, bans) = blocking(move || dao_chat::ban_record(&target)).await?;
    Ok(VoteStatus {
        removal_votes: dao_chat::open_votes(&votes, now).len(),
        threshold: dao_chat::BAN_VOTES,
        removed_until: dao_chat::banned_until(&bans, now),
    })
}

async fn own_post(kp: &KeyPair, post_id: String, post_ts: i64, now: i64) -> Result<dao_chat::Post, EgoDesktopError> {
    let post = blocking(move || dao_chat::post_by_id(post_ts, &post_id))
        .await?
        .ok_or_else(|| EgoDesktopError::NotFound("That message is no longer in the chat.".into()))?;
    if post.from != dao_chat::address_of_key(kp) {
        return Err(EgoDesktopError::PermissionDenied("You can only change your own messages.".into()));
    }
    if !dao_chat::can_change(post.ts, now) {
        return Err(EgoDesktopError::InvalidInput("Messages can only be changed in the first hour after posting.".into()));
    }
    Ok(post)
}

#[tauri::command]
pub async fn dao_chat_edit(
    post_id: String,
    post_ts: i64,
    body: String,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<(), EgoDesktopError> {
    let kp = keypair(&state)?;
    let body = dao_chat::clean_body(&body).map_err(EgoDesktopError::InvalidInput)?;
    let now = chrono::Utc::now().timestamp();
    let post = own_post(&kp, post_id, post_ts, now).await?;
    let wire = Wire::Edit(dao_chat::sign_edit(&kp, &post, &body, now));
    let local = wire.clone();
    blocking(move || dao_chat::accept(&local, now, Source::Local)).await?.map_err(refusal)?;
    publish(&wire).await;
    dao_chat::notify(Some(&app));
    Ok(())
}

#[tauri::command]
pub async fn dao_chat_delete(post_id: String, post_ts: i64, state: State<'_, AppState>, app: AppHandle) -> Result<(), EgoDesktopError> {
    let kp = keypair(&state)?;
    let now = chrono::Utc::now().timestamp();
    let post = own_post(&kp, post_id, post_ts, now).await?;
    let wire = Wire::Delete(dao_chat::sign_delete(&kp, &post, now));
    let local = wire.clone();
    blocking(move || dao_chat::accept(&local, now, Source::Local)).await?.map_err(refusal)?;
    publish(&wire).await;
    dao_chat::notify(Some(&app));
    Ok(())
}

#[tauri::command]
pub async fn dao_chat_sync(app: AppHandle) -> Result<usize, EgoDesktopError> {
    Ok(crate::p2p::dao_chat_sync_now(Some(app)).await)
}
