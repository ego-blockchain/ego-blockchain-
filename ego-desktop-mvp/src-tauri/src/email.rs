//! SMTP email helpers.
//! Credentials are stored as XOR-encoded byte arrays so they do not appear
//! as plain text in the compiled binary.

use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;

// ── XOR obfuscation ───────────────────────────────────────────────────────────

fn xd(data: &[u8]) -> String {
    let k = b"EgoNet";
    String::from_utf8(
        data.iter().enumerate().map(|(i, &b)| b ^ k[i % k.len()]).collect(),
    ).unwrap_or_default()
}

// mail.egoblockchain.com
const SH: &[u8] = &[
    0x28,0x06,0x06,0x22,0x4B,0x11,0x22,0x08,0x0D,0x22,0x0A,0x17,
    0x2E,0x04,0x07,0x2F,0x0C,0x1A,0x6B,0x04,0x00,0x23,
];
// noreply@egoblockchain.com
const SU: &[u8] = &[
    0x2B,0x08,0x1D,0x2B,0x15,0x18,0x3C,0x27,0x0A,0x29,0x0A,0x16,
    0x29,0x08,0x0C,0x25,0x06,0x1C,0x24,0x0E,0x01,0x60,0x06,0x1B,0x28,
];
// Artit18+
const SP: &[u8] = &[0x04,0x15,0x1B,0x27,0x11,0x45,0x7D,0x4C];

// ── OTP store (email → (code, expiry unix ts)) ────────────────────────────────

static OTP_STORE: Lazy<Mutex<HashMap<String, (String, i64)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub fn store_otp(email: &str, code: &str) {
    let expiry = chrono::Utc::now().timestamp() + 600; // 10 minutes
    let mut map = OTP_STORE.lock().unwrap();
    map.insert(email.to_lowercase(), (code.to_string(), expiry));
}

pub fn verify_otp(email: &str, code: &str) -> bool {
    let mut map = OTP_STORE.lock().unwrap();
    let key = email.to_lowercase();
    if let Some((stored_code, expiry)) = map.get(&key) {
        let now = chrono::Utc::now().timestamp();
        if now <= *expiry && stored_code == code {
            map.remove(&key);
            return true;
        }
    }
    false
}

// ── Core SMTP sender ──────────────────────────────────────────────────────────

async fn send_smtp(to: &str, subject: &str, body: &str) -> Result<(), String> {
    let host = xd(SH);
    let user = xd(SU);
    let pass = xd(SP);

    let from_addr = format!("Ego Blockchain <{}>", user)
        .parse::<lettre::message::Mailbox>()
        .map_err(|e| format!("From parse error: {e}"))?;
    let to_addr = to
        .parse::<lettre::message::Mailbox>()
        .map_err(|e| format!("To parse error: {e}"))?;

    let email = Message::builder()
        .from(from_addr.clone())
        .reply_to(from_addr)
        .to(to_addr)
        .subject(subject)
        .header(ContentType::TEXT_PLAIN)
        .body(body.to_string())
        .map_err(|e| format!("Email build error: {e}"))?;

    let tls = TlsParameters::new(host.clone())
        .map_err(|e| format!("TLS params error: {e}"))?;

    let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&host)
        .map_err(|e| format!("Relay error: {e}"))?
        .port(465)
        .tls(Tls::Wrapper(tls))
        .credentials(Credentials::new(user, pass))
        .authentication(vec![Mechanism::Login, Mechanism::Plain])
        .build();

    mailer.send(email).await.map_err(|e| format!("SMTP send error: {e}"))?;
    Ok(())
}

// ── Public helpers ────────────────────────────────────────────────────────────

pub async fn send_otp_email(to: &str, name: &str, code: &str) -> Result<(), String> {
    let body = format!(
        "Hello {name},\n\n\
        Your Ego Blockchain verification code is:\n\n\
        \t{code}\n\n\
        This code expires in 10 minutes. Do not share it with anyone.\n\n\
        — Ego Blockchain Team"
    );
    send_smtp(to, "Your Ego Blockchain Verification Code", &body).await
}

pub async fn send_tx_code_email(
    to: &str,
    code: &str,
    amount_egoc: &str,
    recipient: &str,
) -> Result<(), String> {
    let short_addr = if recipient.len() > 12 {
        format!("{}…{}", &recipient[..8], &recipient[recipient.len()-4..])
    } else {
        recipient.to_string()
    };
    let body = format!(
        "You requested to send {amount_egoc} to {short_addr}.\n\n\
        Your transaction confirmation code is:\n\n\
        \t{code}\n\n\
        This code expires in 10 minutes. Enter it in the Ego Desktop app to complete the transaction.\n\
        If you did not initiate this, ignore this email — the transaction will not be processed.\n\n\
        — Ego Blockchain Team"
    );
    send_smtp(to, "Ego Blockchain — Confirm Your Transaction", &body).await
}

pub async fn send_tx_confirmation(
    to: &str,
    amount_egoc: &str,
    recipient: &str,
    tx_hash: &str,
) -> Result<(), String> {
    let body = format!(
        "Your transaction has been submitted to the Ego Blockchain network.\n\n\
        Amount:    {amount_egoc}\n\
        Recipient: {recipient}\n\
        TX Hash:   {tx_hash}\n\n\
        If you did not authorize this transaction, contact support immediately.\n\n\
        — Ego Blockchain Team"
    );
    send_smtp(to, "Ego Blockchain — Transaction Sent", &body).await
}
