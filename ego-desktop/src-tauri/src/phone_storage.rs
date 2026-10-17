//! Ego Storage for phones, served by the gateway.
//!
//! A phone can't join the DHT, so it hands its files to a gateway: encrypted
//! 256 KB blocks first, then the manifest that lists them. The gateway keeps
//! them like any hosted file (owner = the phone's wallet), publishes them to
//! the DHT, and lets the replication loop copy them to other nodes. Blocks are
//! named by their encrypted bytes, so the gateway checks every one it takes and
//! never sees what's inside. Writes are signed by the owner and count against
//! the storage plan that wallet paid for on chain.

use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;

use crate::blocks::{BlockEntry, FileManifest, BLOCK_SIZE};
use crate::ledger::{Ledger, StoredFile};

pub const BLOCK_DOMAIN: &str = "ego/storage-block/v1";
pub const MANIFEST_DOMAIN: &str = "ego/storage-manifest/v1";
pub const DELETE_DOMAIN: &str = "ego/storage-delete/v1";
const CLOCK_SKEW_SECS: i64 = 300;
const MAX_FILE_BYTES: u64 = 250 * 1024 * 1024;
/// AES-GCM adds a 16-byte tag to each block.
const MAX_SEALED_BLOCK: usize = BLOCK_SIZE + 16;
/// Blocks uploaded but not yet claimed by a manifest are forgotten after this.
const PENDING_TTL_SECS: i64 = 6 * 3600;

type RpcResult = Result<Value, (i32, String)>;

/// Bytes each owner has uploaded in blocks that no manifest claims yet, so the
/// plan can't be overrun by blocks alone.
static PENDING: Mutex<Option<HashMap<String, HashMap<String, (u64, i64)>>>> = Mutex::new(None);

fn pending_bytes(owner: &str, now: i64) -> u64 {
    let mut guard = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    let Some(blocks) = map.get_mut(owner) else { return 0 };
    blocks.retain(|_, (_, at)| now - *at < PENDING_TTL_SECS);
    blocks.values().map(|(n, _)| *n).sum()
}

fn note_pending(owner: &str, cid: &str, size: u64, now: i64) {
    let mut guard = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    guard.get_or_insert_with(HashMap::new)
        .entry(owner.to_string()).or_default()
        .insert(cid.to_string(), (size, now));
}

fn clear_pending(owner: &str, cids: &[String]) {
    let mut guard = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(blocks) = guard.get_or_insert_with(HashMap::new).get_mut(owner) {
        for cid in cids { blocks.remove(cid); }
    }
}

pub fn request_bytes(domain: &str, owner: &str, cid: &str, ts: i64) -> Vec<u8> {
    format!("{domain}\n{owner}\n{cid}\n{ts}").into_bytes()
}

/// The wallet that signed this request for `cid`, if the signature and time check out.
fn signed_owner(params: &Value, domain: &str, cid: &str, now: i64) -> Result<String, (i32, String)> {
    use ed25519_dalek::{Signature, VerifyingKey};
    let bad = || (-32003, "This request isn't signed by the wallet it names.".to_string());
    let owner = params["owner"].as_str().unwrap_or_default();
    let ts = params["ts"].as_i64().ok_or_else(bad)?;
    if (ts - now).abs() > CLOCK_SKEW_SECS {
        return Err((-32003, "The request's time is off. Check your phone's date and time.".into()));
    }
    let pk: [u8; 32] = hex::decode(params["pubkey"].as_str().unwrap_or_default()).ok()
        .and_then(|v| v.try_into().ok()).ok_or_else(bad)?;
    let sig: [u8; 64] = hex::decode(params["sig"].as_str().unwrap_or_default()).ok()
        .and_then(|v| v.try_into().ok()).ok_or_else(bad)?;
    let key = VerifyingKey::from_bytes(&pk).map_err(|_| bad())?;
    key.verify_strict(&request_bytes(domain, owner, cid, ts), &Signature::from_bytes(&sig)).map_err(|_| bad())?;
    if crate::market_chain::address_of(&pk) != owner {
        return Err(bad());
    }
    Ok(owner.to_string())
}

fn used_by(ledger: &Ledger, owner: &str) -> u64 {
    ledger.stored_files.iter()
        .filter(|f| f.owner == owner && (f.status == "Active" || f.status == "PendingSync"))
        .map(|f| f.original_size)
        .sum()
}

fn full(used: u64, quota: u64) -> (i32, String) {
    (-32010, format!(
        "Your storage plan is full: {:.2} GB of {:.0} GB used. Choose a bigger plan or delete some files.",
        used as f64 / 1e9, quota as f64 / 1e9
    ))
}

fn block_cid_of(sealed: &[u8]) -> String {
    format!("egoblk1{}", ego_core::hash_data(sealed).to_hex())
}

fn publish(key: String, value: Vec<u8>) {
    if let Some(tx) = crate::p2p::DHT_CMD_TX.get() {
        let _ = tx.try_send(crate::p2p::DhtCommand::PutPeer { key, value });
    }
}

/// storage.putBlock: one encrypted block, checked against its name.
async fn put_block(params: &Value) -> RpcResult {
    use base64::Engine as _;
    let now = chrono::Utc::now().timestamp();
    let cid = params["cid"].as_str().unwrap_or_default().to_string();
    let owner = signed_owner(params, BLOCK_DOMAIN, &cid, now)?;
    let sealed = base64::engine::general_purpose::STANDARD
        .decode(params["data"].as_str().unwrap_or_default())
        .map_err(|_| (-32602, "The block isn't valid base64.".to_string()))?;
    if sealed.len() <= 16 || sealed.len() > MAX_SEALED_BLOCK {
        return Err((-32602, "A block is at most 256 KB.".into()));
    }
    if block_cid_of(&sealed) != cid {
        return Err((-32602, "The block doesn't match its ID.".into()));
    }
    if !crate::blocks::have_block(&cid) {
        let who = owner.clone();
        let (used, quota) = tokio::task::spawn_blocking(move || {
            (used_by(&Ledger::load(), &who), crate::commands::storage::storage_quota_bytes(&who, now))
        }).await.map_err(|e| (-32603, e.to_string()))?;
        let pending = pending_bytes(&owner, now);
        if used + pending + sealed.len() as u64 > quota {
            return Err(full(used + pending, quota));
        }
        crate::blocks::save_block(&cid, &sealed).map_err(|e| (-32603, e))?;
        note_pending(&owner, &cid, sealed.len() as u64, now);
        publish(format!("ego-block:{cid}"), sealed);
    }
    Ok(json!({ "stored": true }))
}

#[derive(serde::Deserialize)]
struct PhoneManifest {
    #[serde(default)]
    file_name: String,
    total_size: u64,
    blocks: Vec<BlockEntry>,
}

/// storage.putManifest: the file, once all its blocks are here. Hosted and replicated from then on.
async fn put_manifest(params: &Value) -> RpcResult {
    use base64::Engine as _;
    let now = chrono::Utc::now().timestamp();
    let cid = params["cid"].as_str().unwrap_or_default().to_string();
    let owner = signed_owner(params, MANIFEST_DOMAIN, &cid, now)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(params["manifest"].as_str().unwrap_or_default())
        .map_err(|_| (-32602, "The manifest isn't valid base64.".to_string()))?;
    if format!("egomfd1{}", ego_core::hash_data(&bytes).to_hex()) != cid {
        return Err((-32602, "The manifest doesn't match its ID.".into()));
    }
    if crate::file_delete::is_deleted(&owner, &cid) {
        return Err((-32602, "This file was deleted by its owner.".into()));
    }
    let phone: PhoneManifest = serde_json::from_slice(&bytes)
        .map_err(|e| (-32602, format!("The manifest couldn't be read: {e}")))?;
    if phone.blocks.is_empty() || phone.total_size == 0 || phone.total_size > MAX_FILE_BYTES
        || phone.blocks.iter().map(|b| b.size).sum::<u64>() != phone.total_size
        || phone.blocks.iter().any(|b| b.size > BLOCK_SIZE as u64)
    {
        return Err((-32602, "The manifest's sizes don't add up.".into()));
    }
    let missing: Vec<String> = phone.blocks.iter()
        .filter(|b| !crate::blocks::have_block(&b.block_cid))
        .map(|b| b.block_cid.clone())
        .collect();
    if !missing.is_empty() {
        return Ok(json!({ "stored": false, "missing": missing }));
    }

    let manifest = FileManifest {
        manifest_cid: cid.clone(),
        file_name: phone.file_name,
        total_size: phone.total_size,
        blocks: phone.blocks,
    };
    let encrypted_size: u64 = manifest.blocks.iter()
        .filter_map(|b| std::fs::metadata(crate::blocks::block_path(&b.block_cid)).ok())
        .map(|m| m.len())
        .sum();

    let _guard = crate::ledger::TX_MUTEX.lock().await;
    let who = owner.clone();
    let m = manifest.clone();
    let c = cid.clone();
    let added = tokio::task::spawn_blocking(move || -> Result<bool, (i32, String)> {
        let mut ledger = Ledger::load();
        if ledger.stored_files.iter().any(|f| f.cid == c && f.owner == who) {
            return Ok(false);
        }
        let used = used_by(&ledger, &who);
        let quota = crate::commands::storage::storage_quota_bytes(&who, now);
        if used + m.total_size > quota {
            return Err(full(used, quota));
        }
        // This node holds the blocks, so its PoRep commitment is bound to its own address.
        let prover = ledger.address.clone();
        let mut proved = m.clone();
        for b in proved.blocks.iter_mut() {
            if let Ok(enc) = crate::blocks::load_block(&b.block_cid) {
                b.comm_r = crate::blocks::compute_block_comm_r(&enc, &prover, &b.block_cid);
            }
        }
        let manifest_path = crate::blocks::save_manifest(&proved).map_err(|e| (-32603, e))?;
        let blocks_total = proved.blocks.len() as u32;
        ledger.stored_files.insert(0, StoredFile {
            cid: c.clone(),
            name: String::new(),
            original_size: m.total_size,
            encrypted_size,
            duration_months: 0,
            stored_at: now,
            expiry: i64::MAX,
            status: "Active".into(),
            key_nonce_hex: String::new(),
            local_path: manifest_path.to_string_lossy().into(),
            owner: who.clone(),
            manifest_cid: c.clone(),
            blocks_total,
            blocks_received: blocks_total,
            comm_r: crate::blocks::compute_porep_root(&proved.blocks),
            ..Default::default()
        });
        ledger.save().map_err(|e| (-32603, e.to_string()))?;
        Ok(true)
    }).await.map_err(|e| (-32603, e.to_string()))??;
    drop(_guard);

    clear_pending(&owner, &manifest.blocks.iter().map(|b| b.block_cid.clone()).collect::<Vec<_>>());
    if added {
        if let Ok(mfd) = serde_json::to_vec(&manifest) {
            publish(format!("ego-manifest:{cid}"), mfd);
        }
        let endpoint = crate::p2p::get_public_endpoint().await;
        if !endpoint.is_empty() {
            crate::p2p::register_cid_on_relay(&cid, &owner, &endpoint).await;
        }
    }
    Ok(json!({ "stored": true }))
}

/// storage.getBlock: a block by its ID, from this node or, failing that, asked for on the DHT.
async fn get_block(params: &Value) -> RpcResult {
    use base64::Engine as _;
    let cid = params["cid"].as_str().unwrap_or_default().to_string();
    if !cid.starts_with("egoblk1") || cid.len() > 80 {
        return Err((-32602, "That isn't a block ID.".into()));
    }
    let c = cid.clone();
    let found = tokio::task::spawn_blocking(move || crate::blocks::load_block(&c).ok())
        .await.map_err(|e| (-32603, e.to_string()))?;
    match found {
        Some(sealed) => Ok(json!({ "data": base64::engine::general_purpose::STANDARD.encode(sealed) })),
        None => {
            if let Some(tx) = crate::p2p::DHT_CMD_TX.get() {
                let _ = tx.try_send(crate::p2p::DhtCommand::GetPeers { key: format!("ego-block:{cid}") });
            }
            Ok(json!({ "pending": true }))
        }
    }
}

/// storage.getManifest: a stored file's list of blocks, so anyone with its share link can open it
/// (the key in the link decrypts it; the list alone reveals nothing). Asks the DHT when it isn't here.
async fn get_manifest(params: &Value) -> RpcResult {
    let cid = params["cid"].as_str().unwrap_or_default().to_string();
    if !cid.starts_with("egomfd1") || cid.len() > 80 {
        return Err((-32602, "That isn't a file ID.".into()));
    }
    let c = cid.clone();
    let found = tokio::task::spawn_blocking(move || crate::blocks::load_manifest(&c).ok())
        .await.map_err(|e| (-32603, e.to_string()))?;
    match found {
        Some(m) if m.manifest_cid == cid || m.manifest_cid.is_empty() => Ok(json!({
            "total_size": m.total_size,
            "blocks": m.blocks.iter().map(|b| json!({ "block_cid": b.block_cid, "nonce_hex": b.nonce_hex, "size": b.size })).collect::<Vec<_>>(),
        })),
        _ => {
            if let Some(tx) = crate::p2p::DHT_CMD_TX.get() {
                let _ = tx.try_send(crate::p2p::DhtCommand::GetPeers { key: format!("ego-manifest:{cid}") });
            }
            Ok(json!({ "pending": true }))
        }
    }
}

/// storage.delete: the owner drops a file everywhere. The phone's signed request is
/// itself the delete notice, so this node removes its copy and passes it to every other.
async fn delete(params: &Value) -> RpcResult {
    let now = chrono::Utc::now().timestamp();
    let cid = params["cid"].as_str().unwrap_or_default().to_string();
    let owner = signed_owner(params, DELETE_DOMAIN, &cid, now)?;
    let held = {
        let (c, o) = (cid.clone(), owner.clone());
        tokio::task::spawn_blocking(move || Ledger::load().stored_files.iter().any(|f| f.cid == c && f.owner == o))
            .await.map_err(|e| (-32603, e.to_string()))?
    };
    let notice = crate::file_delete::DeleteNotice {
        cid,
        owner,
        pubkey: params["pubkey"].as_str().unwrap_or_default().to_string(),
        sig: params["sig"].as_str().unwrap_or_default().to_string(),
        ts: params["ts"].as_i64().unwrap_or_default(),
    };
    crate::file_delete::delete_everywhere(notice).await;
    Ok(json!({ "removed": held }))
}

/// storage.usage: what an owner has stored on this node, and their plan's space.
async fn usage(params: &Value) -> RpcResult {
    let owner = params["owner"].as_str().unwrap_or_default().to_string();
    let now = chrono::Utc::now().timestamp();
    tokio::task::spawn_blocking(move || {
        let ledger = Ledger::load();
        let files: Vec<&str> = ledger.stored_files.iter()
            .filter(|f| f.owner == owner && f.status == "Active")
            .map(|f| f.cid.as_str())
            .collect();
        json!({
            "used_bytes": used_by(&ledger, &owner),
            "quota_bytes": crate::commands::storage::storage_quota_bytes(&owner, now),
            "files": files,
        })
    }).await.map_err(|e| (-32603, e.to_string()))
}

pub const METHODS: &[&str] = &["storage.putBlock", "storage.putManifest", "storage.getBlock", "storage.getManifest", "storage.delete", "storage.usage"];

pub async fn dispatch(method: &str, params: &Value) -> Option<RpcResult> {
    Some(match method {
        "storage.putBlock" => put_block(params).await,
        "storage.putManifest" => put_manifest(params).await,
        "storage.getBlock" => get_block(params).await,
        "storage.getManifest" => get_manifest(params).await,
        "storage.delete" => delete(params).await,
        "storage.usage" => usage(params).await,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed(domain: &str, cid: &str, ts: i64, seed: u8) -> (Value, String) {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let pk = key.verifying_key().to_bytes();
        let owner = crate::market_chain::address_of(&pk);
        let sig = key.sign(&request_bytes(domain, &owner, cid, ts));
        (json!({ "owner": owner, "pubkey": hex::encode(pk), "sig": hex::encode(sig.to_bytes()), "ts": ts, "cid": cid }), owner)
    }

    #[test]
    fn owner_signatures_are_checked() {
        let now = 1_800_000_000;
        let (params, owner) = signed(BLOCK_DOMAIN, "egoblk1abc", now, 7);
        assert_eq!(signed_owner(&params, BLOCK_DOMAIN, "egoblk1abc", now).unwrap(), owner);
        // Signed for another block, another action, too long ago, or naming someone else: refused.
        assert!(signed_owner(&params, BLOCK_DOMAIN, "egoblk1other", now).is_err());
        assert!(signed_owner(&params, DELETE_DOMAIN, "egoblk1abc", now).is_err());
        assert!(signed_owner(&params, BLOCK_DOMAIN, "egoblk1abc", now + CLOCK_SKEW_SECS + 1).is_err());
        let mut forged = params.clone();
        forged["owner"] = json!(signed(BLOCK_DOMAIN, "x", now, 8).1);
        assert!(signed_owner(&forged, BLOCK_DOMAIN, "egoblk1abc", now).is_err());
    }

    #[test]
    fn blocks_are_named_by_their_encrypted_bytes() {
        let sealed = vec![42u8; 100];
        let cid = block_cid_of(&sealed);
        assert!(cid.starts_with("egoblk1"));
        assert_eq!(cid.len(), "egoblk1".len() + 64);
        assert_ne!(block_cid_of(&[43u8; 100]), cid);
    }

    #[test]
    fn pending_blocks_count_until_claimed_or_stale() {
        let owner = "egot1pendingtestowner";
        note_pending(owner, "b1", 1000, 100);
        note_pending(owner, "b2", 500, 100);
        assert_eq!(pending_bytes(owner, 200), 1500);
        clear_pending(owner, &["b1".to_string()]);
        assert_eq!(pending_bytes(owner, 200), 500);
        assert_eq!(pending_bytes(owner, 100 + PENDING_TTL_SECS + 1), 0);
    }

    #[test]
    fn phone_manifests_parse() {
        // Exactly what the iPhone sends: sorted keys, no file name.
        let json = br#"{"blocks":[{"block_cid":"egoblk1aa","comm_r":"","nonce_hex":"000102030405060708090a0b","size":5}],"file_name":"","total_size":5}"#;
        let m: PhoneManifest = serde_json::from_slice(json).unwrap();
        assert_eq!(m.total_size, 5);
        assert_eq!(m.blocks[0].block_cid, "egoblk1aa");
        assert!(m.file_name.is_empty());
    }
}
