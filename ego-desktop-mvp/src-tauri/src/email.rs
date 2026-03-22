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

// Ego logo embedded at compile time — avoids needing a hosted image URL.
static LOGO_B64: Lazy<String> = Lazy::new(|| {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.encode(include_bytes!("../icons/ego_square.png"))
});

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

// ── Send-attempt limiter (email → (count, window_start_unix_ts)) ─────────────
// Max 3 sends per email per hour.  Resets automatically after the window passes.

const MAX_SEND_ATTEMPTS: u32 = 3;
const ATTEMPT_WINDOW_SECS: i64 = 3600; // 1 hour

static SEND_ATTEMPTS: Lazy<Mutex<HashMap<String, (u32, i64)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Returns Ok(()) if the email is within the send limit, or a user-facing
/// error string if the limit has been reached.
pub fn check_send_limit(email: &str) -> Result<(), String> {
    let key = email.to_lowercase();
    let now = chrono::Utc::now().timestamp();
    let mut map = SEND_ATTEMPTS.lock().unwrap();
    if let Some((count, window_start)) = map.get(&key) {
        if now - window_start < ATTEMPT_WINDOW_SECS && *count >= MAX_SEND_ATTEMPTS {
            return Err(
                "Too many code requests. Please check your inbox, change your email address, or try again later.".into()
            );
        }
    }
    Ok(())
}

/// Record a successful send attempt.  Call this only after the email is sent.
pub fn record_send_attempt(email: &str) {
    let key = email.to_lowercase();
    let now = chrono::Utc::now().timestamp();
    let mut map = SEND_ATTEMPTS.lock().unwrap();
    let entry = map.entry(key).or_insert((0, now));
    // Reset window if the previous window has expired
    if now - entry.1 >= ATTEMPT_WINDOW_SECS {
        *entry = (0, now);
    }
    entry.0 += 1;
}

/// Reset the send counter for an email (called on successful verification
/// so the user isn't blocked after confirming their code).
pub fn reset_send_attempts(email: &str) {
    SEND_ATTEMPTS.lock().unwrap().remove(&email.to_lowercase());
}

// ── OTP store (email → (code, expiry unix ts)) ────────────────────────────────

static OTP_STORE: Lazy<Mutex<HashMap<String, (String, i64)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Generate a confirmation code: 4 digits + 2 uppercase letters at random positions.
/// Example: "3A8S97", "4E9Q72", "7K2395" — letters can appear anywhere in the 6 chars.
/// Entropy: 10^4 × 26^2 × C(6,2) = 101,400,000 combinations.
pub fn gen_otp_code() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    // Pick 2 distinct positions (0..6) for the letters
    let pos1 = rng.gen_range(0usize..6);
    let pos2 = loop {
        let p = rng.gen_range(0usize..6);
        if p != pos1 { break p; }
    };

    let mut chars = ['0'; 6];
    for (i, c) in chars.iter_mut().enumerate() {
        if i == pos1 || i == pos2 {
            *c = (b'A' + rng.gen_range(0u8..26)) as char;
        } else {
            *c = (b'0' + rng.gen_range(0u8..10)) as char;
        }
    }
    chars.iter().collect()
}

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

// ── HTML email template ───────────────────────────────────────────────────────

fn html_template(title: &str, body_html: &str) -> String {
    let logo_src = format!("data:image/png;base64,{}", &*LOGO_B64);
    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>{title}</title>
</head>
<body style="margin:0;padding:0;background-color:#0f1117;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#0f1117;padding:40px 20px;">
    <tr>
      <td align="center">
        <table width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background-color:#1a1d27;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.4);">

          <!-- Header / Logo -->
          <tr>
            <td align="center" style="padding:36px 40px 28px;border-bottom:1px solid #2a2d3a;">
              <img src="{logo_src}" alt="Ego Blockchain" width="80" height="80" style="display:block;margin:0 auto;border-radius:50%;"/>
              <div style="margin-top:16px;font-size:20px;font-weight:700;color:#ffffff;letter-spacing:0.3px;">Ego Blockchain</div>
              <div style="margin-top:4px;font-size:12px;color:#6b7280;">Quantum-Safe Blockchain Network</div>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:36px 40px;">
              {body_html}
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td align="center" style="padding:24px 40px 32px;border-top:1px solid #2a2d3a;">
              <p style="margin:0 0 8px;font-size:13px;color:#6b7280;">
                This email was sent by <strong style="color:#9ca3af;">Ego Blockchain</strong>.
              </p>
              <a href="https://www.egoblockchain.com" style="display:inline-block;margin-top:4px;font-size:13px;color:#3b82f6;text-decoration:none;font-weight:500;">
                www.egoblockchain.com
              </a>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>"#, title = title, body_html = body_html, logo_src = logo_src)
}

// ── Core SMTP sender ──────────────────────────────────────────────────────────

async fn send_smtp(to: &str, subject: &str, html: &str) -> Result<(), String> {
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
        .header(ContentType::TEXT_HTML)
        .body(html.to_string())
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
    let body_html = format!(r#"
      <p style="margin:0 0 20px;font-size:16px;color:#d1d5db;">Hello <strong style="color:#ffffff;">{name}</strong>,</p>
      <p style="margin:0 0 24px;font-size:15px;color:#9ca3af;line-height:1.6;">Your Ego Blockchain verification code is:</p>
      <div style="text-align:center;margin:0 0 28px;">
        <span style="display:inline-block;padding:16px 40px;background-color:#111827;border:2px solid #3b82f6;border-radius:12px;font-size:32px;font-weight:700;letter-spacing:10px;color:#ffffff;font-family:'Courier New',Courier,monospace;">{code}</span>
      </div>
      <p style="margin:0;font-size:13px;color:#6b7280;line-height:1.6;">This code expires in <strong style="color:#9ca3af;">10 minutes</strong>. Do not share it with anyone.</p>
    "#, name = name, code = code);
    let html = html_template("Your Ego Blockchain Verification Code", &body_html);
    send_smtp(to, "Your Ego Blockchain Verification Code", &html).await
}

pub async fn send_tx_code_email(
    to: &str,
    code: &str,
    amount_egoc: &str,
    recipient: &str,
) -> Result<(), String> {
    let short_addr = if recipient.len() > 12 {
        format!("{}&#8230;{}", &recipient[..8], &recipient[recipient.len()-4..])
    } else {
        recipient.to_string()
    };
    let body_html = format!(r#"
      <p style="margin:0 0 20px;font-size:15px;color:#9ca3af;line-height:1.6;">You requested to send:</p>
      <div style="background-color:#111827;border-radius:12px;padding:20px 24px;margin:0 0 24px;">
        <table width="100%" cellpadding="0" cellspacing="0">
          <tr>
            <td style="font-size:13px;color:#6b7280;padding-bottom:10px;">Amount</td>
            <td align="right" style="font-size:15px;font-weight:700;color:#ffffff;padding-bottom:10px;">{amount_egoc}</td>
          </tr>
          <tr>
            <td style="font-size:13px;color:#6b7280;">Recipient</td>
            <td align="right" style="font-size:13px;color:#d1d5db;font-family:'Courier New',Courier,monospace;">{short_addr}</td>
          </tr>
        </table>
      </div>
      <p style="margin:0 0 16px;font-size:15px;color:#9ca3af;">Your confirmation code is:</p>
      <div style="text-align:center;margin:0 0 28px;">
        <span style="display:inline-block;padding:16px 40px;background-color:#111827;border:2px solid #3b82f6;border-radius:12px;font-size:32px;font-weight:700;letter-spacing:10px;color:#ffffff;font-family:'Courier New',Courier,monospace;">{code}</span>
      </div>
      <p style="margin:0;font-size:13px;color:#6b7280;line-height:1.6;">Enter this code in the Ego Desktop app to complete the transaction. It expires in <strong style="color:#9ca3af;">10 minutes</strong>.<br/>If you did not initiate this, ignore this email — the transaction will not be processed.</p>
    "#, amount_egoc = amount_egoc, short_addr = short_addr, code = code);
    let html = html_template("Confirm Your Transaction", &body_html);
    send_smtp(to, "Ego Blockchain — Confirm Your Transaction", &html).await
}

pub async fn send_tx_confirmation(
    to: &str,
    amount_egoc: &str,
    recipient: &str,
    tx_hash: &str,
) -> Result<(), String> {
    let short_hash = if tx_hash.len() > 16 {
        format!("{}&#8230;{}", &tx_hash[..8], &tx_hash[tx_hash.len()-8..])
    } else {
        tx_hash.to_string()
    };
    let body_html = format!(r#"
      <p style="margin:0 0 8px;font-size:18px;font-weight:700;color:#ffffff;">Transaction Submitted</p>
      <p style="margin:0 0 24px;font-size:14px;color:#9ca3af;">Your transaction has been submitted to the Ego Blockchain network.</p>
      <div style="background-color:#111827;border-radius:12px;padding:20px 24px;margin:0 0 24px;">
        <table width="100%" cellpadding="0" cellspacing="0">
          <tr>
            <td style="font-size:13px;color:#6b7280;padding-bottom:12px;">Amount</td>
            <td align="right" style="font-size:15px;font-weight:700;color:#ffffff;padding-bottom:12px;">{amount_egoc}</td>
          </tr>
          <tr>
            <td style="font-size:13px;color:#6b7280;padding-bottom:12px;">Recipient</td>
            <td align="right" style="font-size:13px;color:#d1d5db;font-family:'Courier New',Courier,monospace;padding-bottom:12px;">{recipient}</td>
          </tr>
          <tr>
            <td style="font-size:13px;color:#6b7280;">TX Hash</td>
            <td align="right" style="font-size:12px;color:#6b7280;font-family:'Courier New',Courier,monospace;">{short_hash}</td>
          </tr>
        </table>
      </div>
      <p style="margin:0;font-size:13px;color:#6b7280;line-height:1.6;">You can track this transaction in the Explorer section of the Ego Desktop app.</p>
    "#, amount_egoc = amount_egoc, recipient = recipient, short_hash = short_hash);
    let html = html_template("Transaction Sent", &body_html);
    send_smtp(to, "Ego Blockchain — Transaction Sent", &html).await
}
