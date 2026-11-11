//! Asks rpc.egoblockchain.com to alert a contact's iPhone about a message sent
//! from here (services/oracle/src/push.rs). Signed by this wallet so the alert
//! can't name a false sender. The preview is encrypted with a key made from the
//! contact's shared chat key, the same way Ego Wallet does (Shared/ChatAlerts.swift
//! in ego-ios), so only the two contacts can read it.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use ed25519_dalek::Signer;
use rand::RngCore;
use sha2::{Digest, Sha256};

pub const NOTIFY_DOMAIN: &str = "ego/push-notify/v1";
pub const PREVIEW_DOMAIN: &str = "ego/push-preview/v1";
const PREVIEW_CHARS: usize = 100;

pub fn notify_bytes(from: &str, to: &str, id: &str, kind: &str, ts: i64, preview: &str) -> Vec<u8> {
    format!("{NOTIFY_DOMAIN}\n{from}\n{to}\n{id}\n{kind}\n{ts}\n{preview}").into_bytes()
}

pub fn preview_key(shared_key_hex: &str) -> Option<[u8; 32]> {
    let shared = hex::decode(shared_key_hex).ok().filter(|k| k.len() == 32)?;
    let mut h = Sha256::new();
    h.update(PREVIEW_DOMAIN.as_bytes());
    h.update(&shared);
    Some(h.finalize().into())
}

pub fn short(text: &str) -> String {
    if text.chars().count() > PREVIEW_CHARS {
        format!("{}…", text.chars().take(PREVIEW_CHARS).collect::<String>())
    } else {
        text.to_string()
    }
}

/// Nonce, ciphertext and tag in base64: what CryptoKit's AES.GCM `combined` reads.
pub fn seal_preview(text: &str, shared_key_hex: &str) -> Option<String> {
    let key = preview_key(shared_key_hex)?;
    let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = cipher.encrypt(Nonce::from_slice(&nonce), short(text).as_bytes()).ok()?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Some(base64::engine::general_purpose::STANDARD.encode(out))
}

/// Fire and forget: an alert that doesn't go out never stops the message.
pub fn message_sent(to: String, id: String, text: String, is_file: bool, shared_key_hex: String) {
    tokio::spawn(async move {
        let preview = seal_preview(if is_file { "📎 Photo or file" } else { &text }, &shared_key_hex).unwrap_or_default();
        notify(&to, &id, "message", &preview).await;
    });
}

async fn notify(to: &str, id: &str, kind: &str, preview: &str) {
    let Ok(Some(seed)) = tokio::task::spawn_blocking(crate::ledger::load_seed).await.unwrap_or(Ok(None)) else { return };
    let Ok(key) = crate::account_record::signing_key(&seed) else { return };
    let pubkey = key.verifying_key().to_bytes();
    let from = crate::market_chain::address_of(&pubkey);
    if from.is_empty() || from == to {
        return;
    }
    let ts = chrono::Utc::now().timestamp();
    let sig = key.sign(&notify_bytes(&from, to, id, kind, ts, preview));
    let body = serde_json::json!({
        "from": from, "to": to, "id": id, "kind": kind, "preview": preview, "ts": ts,
        "pubkey": hex::encode(pubkey), "sig": hex::encode(sig.to_bytes()),
    });
    let Ok(client) = reqwest::Client::builder().timeout(std::time::Duration::from_secs(10)).build() else { return };
    if let Err(e) = client.post(format!("{}/push/notify", crate::p2p::ORACLE_RPC)).json(&body).send().await {
        tracing::debug!("[Push] alert for {to} not sent: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_preview_opens_with_the_contacts_preview_key_only() {
        let shared = "11".repeat(32);
        let sealed = seal_preview("Hello there", &shared).unwrap();
        let raw = base64::engine::general_purpose::STANDARD.decode(sealed).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&preview_key(&shared).unwrap()).unwrap();
        let plain = cipher.decrypt(Nonce::from_slice(&raw[..12]), &raw[12..]).unwrap();
        assert_eq!(plain, b"Hello there");
        let other = Aes256Gcm::new_from_slice(&preview_key(&"22".repeat(32)).unwrap()).unwrap();
        assert!(other.decrypt(Nonce::from_slice(&raw[..12]), &raw[12..]).is_err());
    }

    #[test]
    fn the_preview_key_matches_ego_wallet() {
        // SHA-256("ego/push-preview/v1" || 32 bytes of 0x11), as Ego Wallet computes it.
        assert_eq!(
            hex::encode(preview_key(&"11".repeat(32)).unwrap()),
            hex::encode(Sha256::new().chain_update(b"ego/push-preview/v1").chain_update([0x11u8; 32]).finalize())
        );
        assert_eq!(short(&"a".repeat(150)).chars().count(), PREVIEW_CHARS + 1);
    }
}
