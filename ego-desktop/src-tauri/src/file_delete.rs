//! Deleting a stored file everywhere it's kept.
//!
//! A file lives on its master and on every slave that took a copy. Deleting
//! it on one node alone isn't enough: the slaves keep their copies, and once
//! the master goes quiet one of them promotes itself and replicates the file
//! all over again. So a delete is a notice signed by the file's owner, the
//! same message a phone signs for storage.delete. It travels three ways:
//! gossip to every node online now, a direct send to the file's replicas, and
//! a DHT record for nodes that were offline. The node that sent it repeats it
//! for a week. Every node that sees it removes the file, keeps a tombstone so
//! the file is never pinned or fetched again, and a slave checks for a
//! tombstone before it ever promotes itself.
//!
//! A tombstone belongs to an owner and a file together. File IDs aren't
//! secret, so anyone can sign a valid notice for someone else's file ID with
//! their own key; it only ever counts against copies that signer owns.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

use crate::ledger::Ledger;
use crate::phone_storage::{request_bytes, DELETE_DOMAIN};

/// How long the node that issued a delete keeps repeating it.
const REPEAT_SECS: i64 = 7 * 86_400;
/// How long any node remembers a deleted file.
const KEEP_SECS: i64 = 180 * 86_400;
/// A slave whose master went quiet waits this long for a tombstone from the DHT before promoting.
pub const TOMBSTONE_WAIT_SECS: i64 = 90;
/// Past this many, the oldest tombstones issued elsewhere are forgotten first.
const MAX_TOMBSTONES: usize = 50_000;

/// Where a tombstone is kept: one owner's file, never the file ID alone.
fn key(owner: &str, cid: &str) -> String {
    format!("{owner}/{cid}")
}

/// The DHT record holding an owner's delete for a file. Owned the same way, so a
/// stranger's record can't overwrite the real owner's.
pub fn dht_key(owner: &str, cid: &str) -> String {
    format!("ego-deleted:{owner}:{cid}")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeleteNotice {
    pub cid: String,
    pub owner: String,
    pub pubkey: String,
    pub sig: String,
    pub ts: i64,
}

impl DeleteNotice {
    pub fn sign(kp: &ego_core::KeyPair, cid: &str, ts: i64) -> Self {
        let owner = crate::dao_chat::address_of_key(kp);
        let sig = kp.sign_ed25519(&request_bytes(DELETE_DOMAIN, &owner, cid, ts));
        DeleteNotice {
            cid: cid.to_string(),
            owner,
            pubkey: hex::encode(kp.ed25519_public_key().as_bytes()),
            sig: hex::encode(sig.as_bytes()),
            ts,
        }
    }

    /// Signed by the wallet it names. Replaying one is harmless: it can only
    /// delete that owner's copy of that one file.
    pub fn is_authentic(&self) -> bool {
        use ed25519_dalek::{Signature, VerifyingKey};
        let Some(pk) = hex::decode(&self.pubkey).ok().and_then(|v| <[u8; 32]>::try_from(v).ok()) else { return false };
        let Some(sig) = hex::decode(&self.sig).ok().and_then(|v| <[u8; 64]>::try_from(v).ok()) else { return false };
        !self.cid.is_empty()
            && crate::market_chain::address_of(&pk) == self.owner
            && VerifyingKey::from_bytes(&pk)
                .map(|vk| vk.verify_strict(&request_bytes(DELETE_DOMAIN, &self.owner, &self.cid, self.ts), &Signature::from_bytes(&sig)).is_ok())
                .unwrap_or(false)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Tombstone {
    notice: Option<DeleteNotice>,
    seen_at: i64,
    /// Issued here (by this node's wallet or for a phone through this gateway), so repeated from here.
    #[serde(default)]
    mine: bool,
}

static TOMBSTONES: Mutex<Option<HashMap<String, Tombstone>>> = Mutex::new(None);
/// When a slave first asked the DHT for a tombstone, per CID.
static ASKED: Mutex<Option<HashMap<String, i64>>> = Mutex::new(None);

fn path() -> std::path::PathBuf {
    crate::ledger::base_data_dir().join("deleted_files.json")
}

/// Reads saved tombstones, rekeying any kept by file ID alone (and dropping those with no notice).
fn parse(json: &str) -> HashMap<String, Tombstone> {
    serde_json::from_str::<HashMap<String, Tombstone>>(json).unwrap_or_default()
        .into_values()
        .filter_map(|t| Some((t.notice.as_ref().map(|n| key(&n.owner, &n.cid))?, t)))
        .collect()
}

fn with_tombstones<T>(f: impl FnOnce(&mut HashMap<String, Tombstone>) -> T) -> T {
    let mut guard = TOMBSTONES.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(|| parse(&std::fs::read_to_string(path()).unwrap_or_default()));
    f(map)
}

fn save(map: &HashMap<String, Tombstone>) {
    if let Ok(json) = serde_json::to_string(map) {
        let _ = std::fs::write(path(), json);
    }
}

/// Whether `owner` deleted their file `cid`. Someone else's delete for the same ID doesn't count.
pub fn is_deleted(owner: &str, cid: &str) -> bool {
    with_tombstones(|m| m.contains_key(&key(owner, cid)))
}

/// Whether every copy of `cid` this node holds was deleted by its owner. A file held here
/// for no one isn't.
pub fn deleted_here(ledger: &Ledger, cid: &str) -> bool {
    let mut owners = ledger.stored_files.iter()
        .filter(|f| f.cid == cid)
        .map(|f| if f.owner.is_empty() { ledger.address.as_str() } else { f.owner.as_str() })
        .peekable();
    owners.peek().is_some() && owners.all(|o| is_deleted(o, cid))
}

/// Adds a notice to `map`. True when it's new.
fn record(map: &mut HashMap<String, Tombstone>, notice: &DeleteNotice, mine: bool, now: i64) -> bool {
    map.retain(|_, t| now - t.seen_at < KEEP_SECS);
    let k = key(&notice.owner, &notice.cid);
    let fresh = !map.contains_key(&k);
    let entry = map.entry(k).or_insert_with(|| Tombstone { notice: Some(notice.clone()), seen_at: now, mine });
    if mine && !entry.mine {
        entry.mine = true;
        entry.seen_at = now;
    }
    while map.len() > MAX_TOMBSTONES {
        let Some(oldest) = map.iter().filter(|(_, t)| !t.mine).min_by_key(|(_, t)| t.seen_at).map(|(k, _)| k.clone()) else { break };
        map.remove(&oldest);
    }
    fresh
}

/// Remembers a notice. True when it's new here.
fn remember(notice: &DeleteNotice, mine: bool, now: i64) -> bool {
    with_tombstones(|m| {
        let fresh = record(m, notice, mine, now);
        save(m);
        fresh
    })
}

/// Removes every copy of `cid` the owner has on this node, and any of its blocks no other file uses.
/// Slaves get their collateral back: the owner ended the deal, they didn't walk away from it.
fn remove_local(notice: &DeleteNotice) -> Vec<(String, u64)> {
    let mut ledger = Ledger::load();
    let me = ledger.address.clone();
    let owned = |f: &crate::ledger::StoredFile| {
        f.cid == notice.cid && (f.owner == notice.owner || (f.owner.is_empty() && me == notice.owner))
    };
    let removed: Vec<crate::ledger::StoredFile> = ledger.stored_files.iter().filter(|f| owned(f)).cloned().collect();
    ledger.stored_files.retain(|f| !owned(f));

    // Blocks are content-addressed, so another file can share one: keep those.
    let mut still_used = std::collections::HashSet::new();
    for f in &ledger.stored_files {
        if let Ok(m) = crate::blocks::load_manifest(&f.cid) {
            still_used.extend(m.blocks.into_iter().map(|b| b.block_cid));
        }
    }
    if let Ok(m) = crate::blocks::load_manifest(&notice.cid) {
        for b in m.blocks.iter().filter(|b| !still_used.contains(&b.block_cid)) {
            let _ = std::fs::remove_file(crate::blocks::block_path(&b.block_cid));
        }
    }
    if !ledger.stored_files.iter().any(|f| f.cid == notice.cid) {
        let _ = std::fs::remove_file(crate::blocks::manifest_path(&notice.cid));
    }
    for f in &removed {
        if !f.local_path.is_empty() && !f.local_path.starts_with("sender:") && !f.local_path.ends_with(".mfd") {
            let _ = std::fs::remove_file(&f.local_path);
        }
    }
    if !removed.is_empty() {
        let _ = ledger.save();
    }
    removed.iter()
        .filter(|f| f.collateral_locked_uegoc > 0)
        .map(|f| (f.cid.clone(), f.collateral_locked_uegoc))
        .collect()
}

/// Applies a delete notice from anywhere: checks it, remembers it, removes the file here.
pub async fn handle(notice: DeleteNotice, mine: bool) {
    if !notice.is_authentic() {
        return;
    }
    let now = chrono::Utc::now().timestamp();
    let fresh = remember(&notice, mine, now);
    let _guard = crate::ledger::TX_MUTEX.lock().await;
    let n = notice.clone();
    let refunds = tokio::task::spawn_blocking(move || remove_local(&n)).await.unwrap_or_default();
    drop(_guard);
    let me = tokio::task::spawn_blocking(|| Ledger::load().address).await.unwrap_or_default();
    for (cid, collateral) in refunds {
        crate::proof::return_collateral(&me, &cid, collateral).await;
    }
    if fresh {
        eprintln!("[Storage] {} deleted by its owner {}", &notice.cid[..16.min(notice.cid.len())], &notice.owner[..16.min(notice.owner.len())]);
    }
}

/// Sends a notice every way it can travel.
pub async fn broadcast(notice: &DeleteNotice) {
    let msg = crate::p2p::P2PMessage::FileDelete { notice: notice.clone() };
    if let Ok(data) = serde_json::to_vec(&msg) {
        crate::p2p::publish_gossip("ego-shards-v1", data).await;
    }
    if let (Some(tx), Ok(value)) = (crate::p2p::DHT_CMD_TX.get(), serde_json::to_vec(notice)) {
        let _ = tx.try_send(crate::p2p::DhtCommand::PutPeer { key: dht_key(&notice.owner, &notice.cid), value });
    }
    // Directly to every peer we know: replicas may not be in the gossip mesh yet.
    let peers = tokio::task::spawn_blocking(crate::p2p::load_peer_cache).await.unwrap_or_default();
    for peer in peers.into_iter().filter(|p| !p.endpoint.is_empty()) {
        let msg = msg.clone();
        tokio::spawn(async move {
            let _ = crate::p2p::send_message_any(&[peer.endpoint], &msg).await;
        });
    }
}

/// Deletes a file everywhere on its owner's word: here first, then on every other node.
pub async fn delete_everywhere(notice: DeleteNotice) {
    handle(notice.clone(), true).await;
    broadcast(&notice).await;
}

/// Repeats the deletes issued here during the past week, for nodes that were offline.
pub async fn repeat_mine() {
    let now = chrono::Utc::now().timestamp();
    let due: Vec<DeleteNotice> = with_tombstones(|m| {
        m.values().filter(|t| t.mine && now - t.seen_at < REPEAT_SECS).filter_map(|t| t.notice.clone()).collect()
    });
    for notice in due {
        broadcast(&notice).await;
    }
}

/// Applies every remembered delete to this node's files, for copies that arrived after the notice.
pub async fn sweep() {
    let notices: Vec<DeleteNotice> = with_tombstones(|m| m.values().filter_map(|t| t.notice.clone()).collect());
    if notices.is_empty() {
        return;
    }
    let held: std::collections::HashSet<String> = tokio::task::spawn_blocking(|| {
        let ledger = Ledger::load();
        ledger.stored_files.iter()
            .map(|f| key(if f.owner.is_empty() { &ledger.address } else { &f.owner }, &f.cid))
            .collect()
    }).await.unwrap_or_default();
    for notice in notices.into_iter().filter(|n| held.contains(&key(&n.owner, &n.cid))) {
        handle(notice, false).await;
    }
}

/// Whether a slave may promote itself for `owner`'s file `cid` now that its master is quiet:
/// only after it has asked the DHT for the owner's tombstone and waited long enough for one to arrive.
pub fn may_promote(owner: &str, cid: &str, now: i64) -> bool {
    if is_deleted(owner, cid) {
        return false;
    }
    let k = key(owner, cid);
    let mut guard = ASKED.lock().unwrap_or_else(|e| e.into_inner());
    let asked = guard.get_or_insert_with(HashMap::new);
    match asked.get(&k) {
        Some(at) if now - at >= TOMBSTONE_WAIT_SECS => {
            asked.remove(&k);
            true
        }
        Some(_) => false,
        None => {
            asked.insert(k, now);
            if let Some(tx) = crate::p2p::DHT_CMD_TX.get() {
                let _ = tx.try_send(crate::p2p::DhtCommand::GetPeers { key: dht_key(owner, cid) });
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notice(seed: u8, cid: &str) -> DeleteNotice {
        let kp = ego_core::KeyPair::from_bytes(&[seed; 32]).unwrap();
        DeleteNotice::sign(&kp, cid, 1_800_000_000)
    }

    #[test]
    fn only_the_owners_signature_deletes() {
        let good = notice(11, "egomfd1abc");
        assert!(good.is_authentic());
        // Same signature for another file, or claiming another owner: refused.
        let mut other_file = good.clone();
        other_file.cid = "egomfd1xyz".into();
        assert!(!other_file.is_authentic());
        let mut other_owner = good.clone();
        other_owner.owner = notice(12, "egomfd1abc").owner;
        assert!(!other_owner.is_authentic());
        let mut bad_sig = good.clone();
        bad_sig.sig = "00".repeat(64);
        assert!(!bad_sig.is_authentic());
    }

    #[test]
    fn a_phone_signed_delete_is_a_valid_notice() {
        // The iPhone signs storage.delete with this exact message, so the gateway can pass it on as is.
        use ed25519_dalek::{Signer, SigningKey};
        let key = SigningKey::from_bytes(&[13; 32]);
        let pk = key.verifying_key().to_bytes();
        let owner = crate::market_chain::address_of(&pk);
        let sig = key.sign(&request_bytes(DELETE_DOMAIN, &owner, "egomfd1phone", 42));
        let n = DeleteNotice { cid: "egomfd1phone".into(), owner, pubkey: hex::encode(pk), sig: hex::encode(sig.to_bytes()), ts: 42 };
        assert!(n.is_authentic());
    }

    #[test]
    fn slaves_wait_for_a_tombstone_before_promoting() {
        let (owner, cid) = ("egot1promoteowner", "egomfd1promotetest");
        assert!(!may_promote(owner, cid, 1_000));
        assert!(!may_promote(owner, cid, 1_000 + TOMBSTONE_WAIT_SECS - 1));
        assert!(may_promote(owner, cid, 1_000 + TOMBSTONE_WAIT_SECS));
    }

    #[test]
    fn a_strangers_delete_for_your_file_is_ignored() {
        let mine = notice(15, "egomfd1yours");
        let stranger = notice(16, "egomfd1yours");
        // The stranger really signed it, for your file's ID, as themselves.
        assert!(stranger.is_authentic());
        assert_ne!(stranger.owner, mine.owner);

        let mut map = HashMap::new();
        assert!(record(&mut map, &stranger, false, 100));
        assert!(!map.contains_key(&key(&mine.owner, &mine.cid)));
        assert!(map.contains_key(&key(&stranger.owner, &stranger.cid)));
        assert_ne!(dht_key(&mine.owner, &mine.cid), dht_key(&stranger.owner, &stranger.cid));

        // Your own delete still counts, alongside theirs.
        assert!(record(&mut map, &mine, false, 101));
        assert!(map.contains_key(&key(&mine.owner, &mine.cid)));
        assert!(!record(&mut map, &mine, false, 102));
    }

    #[test]
    fn tombstones_saved_by_file_id_alone_move_under_their_owner() {
        let n = notice(17, "egomfd1old");
        let old = serde_json::json!({
            "egomfd1old": { "notice": n, "seen_at": 5, "mine": true },
            "egomfd1empty": { "notice": null, "seen_at": 5 },
        });
        let map = parse(&old.to_string());
        assert_eq!(map.len(), 1);
        assert!(map[&key(&n.owner, "egomfd1old")].mine);
        assert!(parse("not json").is_empty());
    }

    #[test]
    fn the_oldest_tombstones_from_elsewhere_go_first() {
        let mut map = HashMap::new();
        let mine = notice(18, "egomfd1keep");
        record(&mut map, &mine, true, 0);
        for i in 1..MAX_TOMBSTONES as i64 {
            map.insert(format!("someone/egomfd1n{i}"), Tombstone { notice: None, seen_at: i, mine: false });
        }
        assert!(record(&mut map, &notice(19, "egomfd1newest"), false, MAX_TOMBSTONES as i64));
        assert_eq!(map.len(), MAX_TOMBSTONES);
        assert!(map.contains_key(&key(&mine.owner, &mine.cid)));
        assert!(!map.contains_key("someone/egomfd1n1"));
        assert!(map.contains_key("someone/egomfd1n2"));
    }

    #[test]
    fn notices_survive_the_wire() {
        let n = notice(14, "egomfd1wire");
        let msg = crate::p2p::P2PMessage::FileDelete { notice: n.clone() };
        let back: crate::p2p::P2PMessage = serde_json::from_slice(&serde_json::to_vec(&msg).unwrap()).unwrap();
        match back {
            crate::p2p::P2PMessage::FileDelete { notice } => assert_eq!(notice, n),
            _ => panic!("wrong message"),
        }
    }
}
