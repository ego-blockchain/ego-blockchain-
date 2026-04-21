use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;

static LOGO_B64: Lazy<String> = Lazy::new(|| {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.encode(include_bytes!("../icons/ego_square.png"))
});

macro_rules! env_or_empty {
    ($key:literal) => { match option_env!($key) { Some(v) => v, None => "" } };
}

const SH: &str = env_or_empty!("EGO_SMTP_HOST");
const SU: &str = env_or_empty!("EGO_SMTP_USER");
const SP: &str = env_or_empty!("EGO_SMTP_PASS");

const MAX_SEND_ATTEMPTS: u32 = 3;
const ATTEMPT_WINDOW_SECS: i64 = 3600;

static SEND_ATTEMPTS: Lazy<Mutex<HashMap<String, (u32, i64)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

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

pub fn record_send_attempt(email: &str) {
    let key = email.to_lowercase();
    let now = chrono::Utc::now().timestamp();
    let mut map = SEND_ATTEMPTS.lock().unwrap();
    let entry = map.entry(key).or_insert((0, now));

    if now - entry.1 >= ATTEMPT_WINDOW_SECS {
        *entry = (0, now);
    }
    entry.0 += 1;
}

pub fn reset_send_attempts(email: &str) {
    SEND_ATTEMPTS.lock().unwrap().remove(&email.to_lowercase());
}

static OTP_STORE: Lazy<Mutex<HashMap<String, (String, i64)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub fn gen_otp_code() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();

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
    let expiry = chrono::Utc::now().timestamp() + 600;
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

async fn send_smtp(to: &str, subject: &str, html: &str) -> Result<(), String> {
    let host = SH.to_string();
    let user = SU.to_string();
    let pass = SP.to_string();

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
      <p style="margin:0 0 8px;font-size:18px;font-weight:700;color:#ffffff;">Transaction Confirmed</p>
      <p style="margin:0 0 24px;font-size:14px;color:#9ca3af;">Your transaction has been confirmed on the Ego Blockchain — the recipient has received the coins.</p>
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
    let html = html_template("Transaction Confirmed", &body_html);
    send_smtp(to, "Ego Blockchain — Transaction Confirmed", &html).await
}

pub fn send_tx_confirmation_when_mined(
    to: String,
    amount_egoc: String,
    recipient: String,
    tx_hash: String,
) {
    tauri::async_runtime::spawn(async move {
        for _ in 0..24u8 {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            if let Some(tx) = crate::chain_db::get_tx_by_hash(&tx_hash) {
                if tx.status == "Confirmed" {
                    if let Err(e) = send_tx_confirmation(&to, &amount_egoc, &recipient, &tx_hash).await {
                        eprintln!("[Email] TX confirmation failed: {e}");
                    }
                    return;
                }
            }
        }
        eprintln!("[Email] TX {} not confirmed within 120s — skipping confirmation email", &tx_hash[..12.min(tx_hash.len())]);
    });
}
