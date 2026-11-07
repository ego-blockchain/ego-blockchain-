use crate::error::EgoDesktopError;
use crate::ledger::Ledger;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::Serialize;
use sha1::Sha1;
use std::collections::HashMap;
use std::sync::Mutex;

pub const STEP_SECS: i64 = 30;
const DIGITS: u32 = 6;
const SECRET_BYTES: usize = 20;
const GRANT_SECS: i64 = 120;
const SETUP_SECS: i64 = 600;
const MAX_FAILS: u32 = 5;
const LOCK_SECS: i64 = 300;
pub const ACTIONS: [&str; 4] = ["send", "reveal", "pin", "export"];

pub fn needs_password(action: &str) -> bool {
    action != "reveal"
}

static PENDING: Mutex<Option<(String, Vec<u8>, i64)>> = Mutex::new(None);
static GRANTS: Mutex<Vec<(String, String, i64)>> = Mutex::new(Vec::new());
static FAILS: Mutex<Option<HashMap<String, (u32, i64)>>> = Mutex::new(None);

pub fn code_at(secret: &[u8], step: i64) -> u32 {
    let Ok(mut mac) = <Hmac<Sha1> as Mac>::new_from_slice(secret) else { return u32::MAX };
    mac.update(&(step as u64).to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = (h[19] & 0x0f) as usize;
    let bin = ((h[off] as u32 & 0x7f) << 24) | ((h[off + 1] as u32) << 16) | ((h[off + 2] as u32) << 8) | h[off + 3] as u32;
    bin % 10u32.pow(DIGITS)
}

pub fn matching_step(secret: &[u8], code: &str, now: i64) -> Option<i64> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if code.len() != DIGITS as usize || !code.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let want: u32 = code.parse().ok()?;
    let t = now.div_euclid(STEP_SECS);
    [t, t - 1, t + 1].into_iter().find(|s| code_at(secret, *s) == want)
}

pub fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for b in bytes {
        buffer = (buffer << 8) | *b as u32;
        bits += 8;
        while bits >= 5 {
            out.push(ALPHABET[((buffer >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn account_label(address: &str) -> String {
    if address.len() > 16 {
        format!("{}...{}", &address[..10], &address[address.len() - 4..])
    } else {
        address.to_string()
    }
}

pub fn otpauth_uri(secret: &[u8], address: &str) -> String {
    format!(
        "otpauth://totp/Ego%20Desktop:{}?secret={}&issuer=Ego%20Desktop&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        account_label(address),
        base32(secret)
    )
}

fn seal_key(seed: &[u8]) -> [u8; 32] {
    use blake2::{Blake2s256, Digest};
    let mut h = Blake2s256::new();
    h.update(b"ego/totp/v1");
    h.update(seed);
    h.finalize().into()
}

pub fn seal(seed: &[u8], secret: &[u8]) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(&seal_key(seed)).map_err(|e| e.to_string())?;
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = cipher.encrypt(Nonce::from_slice(&nonce), secret).map_err(|e| e.to_string())?;
    Ok(hex::encode([nonce.as_slice(), ct.as_slice()].concat()))
}

pub fn unseal(seed: &[u8], sealed: &str) -> Result<Vec<u8>, String> {
    let raw = hex::decode(sealed).map_err(|e| e.to_string())?;
    if raw.len() < 12 + 16 {
        return Err("the stored authenticator secret is damaged".into());
    }
    let cipher = Aes256Gcm::new_from_slice(&seal_key(seed)).map_err(|e| e.to_string())?;
    cipher
        .decrypt(Nonce::from_slice(&raw[..12]), &raw[12..])
        .map_err(|_| "the stored authenticator secret does not belong to this wallet".to_string())
}

fn wallet_seed() -> Result<Vec<u8>, EgoDesktopError> {
    crate::ledger::load_seed()
        .map_err(|e| EgoDesktopError::CryptoError(format!("Failed to load seed: {e}")))?
        .ok_or_else(|| EgoDesktopError::CryptoError("Wallet not initialised".into()))
}

fn locked_out(address: &str, now: i64) -> Option<i64> {
    let mut g = FAILS.lock().unwrap_or_else(|e| e.into_inner());
    let map = g.get_or_insert_with(HashMap::new);
    match map.get(address) {
        Some((n, until)) if *n >= MAX_FAILS && *until > now => Some(*until - now),
        Some((n, until)) if *n >= MAX_FAILS && *until <= now => {
            map.remove(address);
            None
        }
        _ => None,
    }
}

fn note_result(address: &str, ok: bool, now: i64) {
    let mut g = FAILS.lock().unwrap_or_else(|e| e.into_inner());
    let map = g.get_or_insert_with(HashMap::new);
    if ok {
        map.remove(address);
        return;
    }
    let e = map.entry(address.to_string()).or_insert((0, 0));
    e.0 += 1;
    if e.0 >= MAX_FAILS {
        e.1 = now + LOCK_SECS;
    }
}

fn check_code(ledger: &mut Ledger, code: &str, now: i64) -> Result<(), EgoDesktopError> {
    let address = ledger.address.clone();
    if let Some(wait) = locked_out(&address, now) {
        return Err(EgoDesktopError::PermissionDenied(format!(
            "Too many wrong authenticator codes. Try again in {} min.",
            (wait + 59) / 60
        )));
    }
    let seed = wallet_seed()?;
    let secret = unseal(&seed, &ledger.totp_secret_sealed).map_err(EgoDesktopError::CryptoError)?;
    match matching_step(&secret, code, now) {
        Some(step) if step > ledger.totp_last_step => {
            note_result(&address, true, now);
            ledger.totp_last_step = step;
            ledger.save().map_err(EgoDesktopError::WalletError)?;
            Ok(())
        }
        Some(_) => Err(EgoDesktopError::PermissionDenied(
            "That code was already used. Wait for the next one in your authenticator app.".into(),
        )),
        None => {
            note_result(&address, false, now);
            Err(EgoDesktopError::PermissionDenied("Wrong authenticator code.".into()))
        }
    }
}

pub fn enabled() -> bool {
    !Ledger::load().totp_secret_sealed.is_empty()
}

pub fn consume(action: &str) -> Result<(), EgoDesktopError> {
    let ledger = Ledger::load();
    let password = needs_password(action) && !ledger.security_pin_hash.is_empty();
    if ledger.totp_secret_sealed.is_empty() && !password {
        return Ok(());
    }
    let now = chrono::Utc::now().timestamp();
    let mut grants = GRANTS.lock().unwrap_or_else(|e| e.into_inner());
    grants.retain(|(_, _, until)| *until > now);
    match grants.iter().position(|(a, act, _)| *a == ledger.address && act == action) {
        Some(i) => {
            grants.remove(i);
            Ok(())
        }
        None => Err(EgoDesktopError::PermissionDenied(
            "Confirm with your password and authenticator code to continue.".into(),
        )),
    }
}

#[derive(Serialize)]
pub struct TotpStatus {
    pub enabled: bool,
}

#[derive(Serialize)]
pub struct TotpSetup {
    pub secret: String,
    pub uri: String,
}

#[tauri::command]
pub async fn totp_status() -> Result<TotpStatus, EgoDesktopError> {
    Ok(TotpStatus { enabled: enabled() })
}

#[tauri::command]
pub async fn totp_begin_setup() -> Result<TotpSetup, EgoDesktopError> {
    let ledger = Ledger::load();
    if ledger.address.is_empty() {
        return Err(EgoDesktopError::WalletError("Wallet not initialised".into()));
    }
    if !ledger.totp_secret_sealed.is_empty() {
        return Err(EgoDesktopError::InvalidInput("The authenticator is already on for this wallet.".into()));
    }
    let mut secret = vec![0u8; SECRET_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let setup = TotpSetup { secret: base32(&secret), uri: otpauth_uri(&secret, &ledger.address) };
    *PENDING.lock().unwrap_or_else(|e| e.into_inner()) = Some((ledger.address, secret, chrono::Utc::now().timestamp()));
    Ok(setup)
}

#[tauri::command]
pub async fn totp_confirm_setup(code: String) -> Result<bool, EgoDesktopError> {
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let now = chrono::Utc::now().timestamp();
    let mut ledger = Ledger::load();
    let pending = PENDING.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let Some((address, secret, started)) = pending.filter(|(a, _, t)| *a == ledger.address && now - *t < SETUP_SECS) else {
        return Err(EgoDesktopError::InvalidInput("Setup expired. Start again to get a new QR code.".into()));
    };
    let _ = started;
    let Some(step) = matching_step(&secret, &code, now) else {
        return Err(EgoDesktopError::PermissionDenied(
            "That code does not match. Check the time on your phone and try the newest code.".into(),
        ));
    };
    let seed = wallet_seed()?;
    ledger.totp_secret_sealed = seal(&seed, &secret).map_err(EgoDesktopError::CryptoError)?;
    ledger.totp_last_step = step;
    ledger.save().map_err(EgoDesktopError::WalletError)?;
    *PENDING.lock().unwrap_or_else(|e| e.into_inner()) = None;
    note_result(&address, true, now);
    Ok(true)
}

#[tauri::command]
pub async fn totp_disable(code: String) -> Result<bool, EgoDesktopError> {
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let now = chrono::Utc::now().timestamp();
    let mut ledger = Ledger::load();
    if ledger.totp_secret_sealed.is_empty() {
        return Ok(true);
    }
    check_code(&mut ledger, &code, now)?;
    ledger.totp_secret_sealed.clear();
    ledger.totp_last_step = 0;
    ledger.save().map_err(EgoDesktopError::WalletError)?;
    Ok(true)
}

#[derive(Serialize)]
pub struct ConfirmStatus {
    pub password: bool,
    pub code: bool,
}

#[tauri::command]
pub async fn confirm_status() -> Result<ConfirmStatus, EgoDesktopError> {
    let ledger = Ledger::load();
    Ok(ConfirmStatus { password: !ledger.security_pin_hash.is_empty(), code: !ledger.totp_secret_sealed.is_empty() })
}

#[tauri::command]
pub async fn authorize_action(password: Option<String>, code: Option<String>, action: String) -> Result<bool, EgoDesktopError> {
    if !ACTIONS.contains(&action.as_str()) {
        return Err(EgoDesktopError::InvalidInput(format!("Unknown action {action}")));
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let now = chrono::Utc::now().timestamp();
    let mut ledger = Ledger::load();
    if needs_password(&action) && !ledger.security_pin_hash.is_empty() {
        let pw = password.unwrap_or_default();
        tokio::task::spawn_blocking(move || crate::commands::auth::check_wallet_password(&pw))
            .await
            .map_err(|e| EgoDesktopError::WalletError(format!("Password check: {e}")))??;
        ledger = Ledger::load();
    }
    if !ledger.totp_secret_sealed.is_empty() {
        check_code(&mut ledger, &code.unwrap_or_default(), now)?;
    }
    let mut grants = GRANTS.lock().unwrap_or_else(|e| e.into_inner());
    grants.retain(|(_, _, until)| *until > now);
    grants.push((ledger.address, action, now + GRANT_SECS));
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn codes_match_the_rfc_6238_test_vectors() {
        for (t, code) in [(59i64, 287_082u32), (1_111_111_109, 81_804), (1_111_111_111, 50_471), (1_234_567_890, 5_924), (2_000_000_000, 279_037)] {
            assert_eq!(code_at(RFC_SECRET, t / STEP_SECS), code, "time {t}");
        }
    }

    #[test]
    fn a_code_is_accepted_for_one_step_either_side_and_never_beyond() {
        let now = 1_234_567_890i64;
        let code = |t: i64| format!("{:06}", code_at(RFC_SECRET, t.div_euclid(STEP_SECS)));
        assert_eq!(matching_step(RFC_SECRET, &code(now), now), Some(now / STEP_SECS));
        assert!(matching_step(RFC_SECRET, &code(now - STEP_SECS), now).is_some());
        assert!(matching_step(RFC_SECRET, &code(now + STEP_SECS), now).is_some());
        assert!(matching_step(RFC_SECRET, &code(now - 3 * STEP_SECS), now).is_none());
        assert!(matching_step(RFC_SECRET, "12345", now).is_none());
        assert!(matching_step(RFC_SECRET, "12a456", now).is_none());
        assert_eq!(matching_step(RFC_SECRET, &format!("{} {}", &code(now)[..3], &code(now)[3..]), now), Some(now / STEP_SECS), "spaces are ignored");
    }

    #[test]
    fn base32_matches_the_rfc_4648_vectors() {
        assert_eq!(base32(b""), "");
        assert_eq!(base32(b"f"), "MY");
        assert_eq!(base32(b"fo"), "MZXQ");
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32(RFC_SECRET), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }

    #[test]
    fn the_secret_only_opens_with_the_wallet_that_sealed_it() {
        let sealed = seal(&[7u8; 32], RFC_SECRET).unwrap();
        assert_eq!(unseal(&[7u8; 32], &sealed).unwrap(), RFC_SECRET);
        assert!(unseal(&[8u8; 32], &sealed).is_err());
        assert_ne!(seal(&[7u8; 32], RFC_SECRET).unwrap(), sealed, "a fresh nonce every time");
    }

    #[test]
    fn the_setup_link_is_what_authenticator_apps_read() {
        let uri = otpauth_uri(RFC_SECRET, "egot1ypxxgvy0y5g8gynm3y2tkegzggs64rcts5dq7sl8");
        assert!(uri.starts_with("otpauth://totp/Ego%20Desktop:egot1ypxxg...7sl8?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
        assert!(uri.contains("issuer=Ego%20Desktop") && uri.contains("digits=6") && uri.contains("period=30"));
    }

    #[test]
    fn five_wrong_codes_lock_the_wallet_for_a_while() {
        let a = "egot1locktest";
        for _ in 0..MAX_FAILS {
            assert!(locked_out(a, 1_000).is_none());
            note_result(a, false, 1_000);
        }
        assert_eq!(locked_out(a, 1_000), Some(LOCK_SECS));
        assert!(locked_out(a, 1_000 + LOCK_SECS).is_none(), "the lock lifts");
    }
}
