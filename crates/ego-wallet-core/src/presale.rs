//! Pre-sale IOU files, written and read exactly as Ego Desktop's
//! presale_create_iou / presale_stripe_create_iou / presale_verify_iou do, so
//! an IOU made on either opens on the other. The allocation is encrypted with
//! AES-256-GCM under BLAKE3(password ‖ salt).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use serde_json::{json, Value};

pub const GENESIS_NOTE: &str = "This allocation will be credited in the Ego Chain Genesis Block upon mainnet launch. Keep this file and your password — they are your proof of purchase.";

/// The Ego team's pre-sale treasury for each payment coin, as in Ego Desktop.
pub fn deposit_address(pay_symbol: &str) -> Option<&'static str> {
    Some(match pay_symbol {
        "BTC" => "bc1qaqx0xf9sv0ktmtcxlzzh7t7kf59nwu8c0vlqhg",
        "ETH" | "USDT" | "USDC" | "BNB" => "0xD4f2B1fA44668B806290A4c3CB758ABb7EF35C64",
        "ADA" => "addr1qyp35j52jw8tmg85wvll3p5krsgkpttxa65kxav4mc56g73fmcra587acj9n8zsqm8u55zvumpff3mrkt9865jswu4gql452dd",
        "SOL" => "9PZzHQYohiR9fTKTJXUaRYKv6doM4NQPJZKcrVvTJbbW",
        "TRX" => "TSZnnQGN8idN6vEU66NX1ek1AtwmHbYLRx",
        _ => return None,
    })
}

fn random<const N: usize>() -> Result<[u8; N], String> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|e| e.to_string())?;
    Ok(b)
}

fn uuid_v4() -> Result<String, String> {
    let mut b: [u8; 16] = random()?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    Ok(format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..]))
}

fn cipher_for(password: &str, salt: &[u8]) -> Aes256Gcm {
    let kdf: Vec<u8> = password.as_bytes().iter().chain(salt).copied().collect();
    let derived = blake3::hash(&kdf);
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(derived.as_bytes()))
}

fn seal(plain: &Value, password: &str, salt: [u8; 32], nonce: [u8; 12]) -> Result<Value, String> {
    let bytes = serde_json::to_vec(plain).map_err(|e| e.to_string())?;
    let ciphertext = cipher_for(password, &salt).encrypt(Nonce::from_slice(&nonce), bytes.as_slice()).map_err(|e| e.to_string())?;
    Ok(json!({
        "cipher": "aes-256-gcm",
        "kdf": "blake3",
        "salt": hex::encode(salt),
        "nonce": hex::encode(nonce),
        "ciphertext": hex::encode(ciphertext),
    }))
}

pub struct Buyer<'a> {
    pub mainnet_address: &'a str,
    pub testnet_address: &'a str,
}

/// An IOU for a crypto payment still to be sent to the treasury.
pub fn crypto_iou(buyer: &Buyer, pay_symbol: &str, pay_amount: f64, pay_usd_price: f64, presale_price: f64, password: &str, now: i64) -> Result<Value, String> {
    if password.trim().is_empty() {
        return Err("Password cannot be empty".into());
    }
    if !(presale_price.is_finite() && presale_price > 0.0) {
        return Err("Pre-sale price not loaded yet".into());
    }
    if !(pay_amount.is_finite() && pay_amount > 0.0 && pay_usd_price.is_finite() && pay_usd_price > 0.0) {
        return Err("Enter an amount to pay".into());
    }
    let deposit = deposit_address(pay_symbol).ok_or("That coin isn't accepted in the pre-sale")?;
    let usd_value = pay_amount * pay_usd_price;
    let egoc_amount = usd_value / presale_price;
    let id = uuid_v4()?;
    let plain = json!({
        "id": id,
        "mainnet_address": buyer.mainnet_address,
        "testnet_address": buyer.testnet_address,
        "egoc_amount": egoc_amount,
        "usd_value": usd_value,
        "price_per_egoc": presale_price,
        "pay_coin": pay_symbol,
        "pay_amount": pay_amount,
        "deposit_address": deposit,
        "timestamp": now,
        "round": "Seed Round",
    });
    Ok(json!({
        "version": 1,
        "id": id,
        "ego_presale": true,
        "network": "ego-mainnet",
        "issued_at": now,
        "round": "Seed Round",
        "payment": { "coin": pay_symbol, "deposit_address": deposit, "amount": pay_amount },
        "allocation": { "egoc_amount": egoc_amount, "usd_value": usd_value, "price_per_egoc_usd": presale_price },
        "genesis_note": GENESIS_NOTE,
        "crypto": seal(&plain, password, random()?, random()?)?,
    }))
}

/// An IOU for a card payment Stripe has confirmed.
pub fn stripe_iou(buyer: &Buyer, session_id: &str, egoc_amount: f64, usd_amount: f64, password: &str, now: i64) -> Result<Value, String> {
    if password.trim().is_empty() {
        return Err("Password cannot be empty".into());
    }
    if !(egoc_amount.is_finite() && egoc_amount > 0.0 && usd_amount.is_finite() && usd_amount > 0.0) {
        return Err("Invalid EGOC amount for this purchase".into());
    }
    let presale_price = usd_amount / egoc_amount;
    let id = uuid_v4()?;
    let plain = json!({
        "id": id,
        "mainnet_address": buyer.mainnet_address,
        "testnet_address": buyer.testnet_address,
        "egoc_amount": egoc_amount,
        "usd_value": usd_amount,
        "price_per_egoc": presale_price,
        "pay_method": "stripe",
        "stripe_session": session_id,
        "timestamp": now,
        "round": "Seed Round",
    });
    Ok(json!({
        "version": 1,
        "id": id,
        "ego_presale": true,
        "network": "ego-mainnet",
        "issued_at": now,
        "round": "Seed Round",
        "payment": { "method": "stripe", "stripe_session": session_id, "status": "paid" },
        "allocation": { "egoc_amount": egoc_amount, "usd_value": usd_amount, "price_per_egoc_usd": presale_price },
        "genesis_note": GENESIS_NOTE,
        "crypto": seal(&plain, password, random()?, random()?)?,
    }))
}

/// The private allocation record inside an IOU, given its password.
pub fn open_iou(iou: &Value, password: &str) -> Result<Value, String> {
    let c = &iou["crypto"];
    let field = |name: &str| hex::decode(c[name].as_str().unwrap_or("")).map_err(|_| format!("Bad {name}"));
    let (salt, nonce, ciphertext) = (field("salt")?, field("nonce")?, field("ciphertext")?);
    if nonce.len() != 12 {
        return Err("Bad nonce".into());
    }
    let plain = cipher_for(password, &salt)
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_slice())
        .map_err(|_| "Wrong password or corrupted IOU file".to_string())?;
    serde_json::from_slice(&plain).map_err(|e| format!("Corrupted record: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUYER: Buyer = Buyer { mainnet_address: "ego1example", testnet_address: "egot1example" };

    #[test]
    fn a_crypto_iou_records_the_allocation_and_opens_with_its_password() {
        let iou = crypto_iou(&BUYER, "ETH", 0.5, 3000.0, 0.02, "correct horse", 1_800_000_000).unwrap();
        assert_eq!(iou["allocation"]["usd_value"], 1500.0);
        assert_eq!(iou["allocation"]["egoc_amount"], 75_000.0);
        assert_eq!(iou["payment"]["deposit_address"], "0xD4f2B1fA44668B806290A4c3CB758ABb7EF35C64");
        assert_eq!(iou["crypto"]["kdf"], "blake3");
        let plain = open_iou(&iou, "correct horse").unwrap();
        assert_eq!(plain["mainnet_address"], "ego1example");
        assert_eq!(plain["pay_coin"], "ETH");
        assert_eq!(plain["id"], iou["id"]);
        assert!(open_iou(&iou, "wrong").is_err());
        assert!(crypto_iou(&BUYER, "DOGE", 1.0, 1.0, 0.02, "p", 0).is_err(), "not a pre-sale coin");
        assert!(crypto_iou(&BUYER, "ETH", 1.0, 1.0, 0.0, "p", 0).is_err(), "no price, no IOU");
        assert!(crypto_iou(&BUYER, "ETH", 1.0, 1.0, 0.02, " ", 0).is_err());
    }

    #[test]
    fn a_stripe_iou_takes_its_price_from_what_was_paid() {
        let iou = stripe_iou(&BUYER, "cs_live_123", 5_000.0, 100.0, "pw", 1).unwrap();
        assert_eq!(iou["allocation"]["price_per_egoc_usd"], 0.02);
        assert_eq!(iou["payment"]["status"], "paid");
        assert_eq!(open_iou(&iou, "pw").unwrap()["stripe_session"], "cs_live_123");
    }

    /// Sealed the way Ego Desktop seals, with a fixed salt and nonce, so a file
    /// from either side opens on the other.
    #[test]
    fn the_encryption_matches_ego_desktops() {
        let plain = json!({"egoc_amount": 1.5});
        let sealed = seal(&plain, "pw", [1u8; 32], [2u8; 12]).unwrap();
        let mut kdf = b"pw".to_vec();
        kdf.extend_from_slice(&[1u8; 32]);
        let key = blake3::hash(&kdf);
        let expected = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()))
            .encrypt(Nonce::from_slice(&[2u8; 12]), serde_json::to_vec(&plain).unwrap().as_slice())
            .unwrap();
        assert_eq!(sealed["ciphertext"], hex::encode(expected));
        assert_eq!(open_iou(&json!({ "crypto": sealed }), "pw").unwrap(), plain);
    }

    #[test]
    fn ids_are_version_4_uuids() {
        let id = uuid_v4().unwrap();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
        assert!(matches!(&id[19..20], "8" | "9" | "a" | "b"));
    }
}
