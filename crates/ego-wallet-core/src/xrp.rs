//! XRP Ledger payments, serialized and signed as Ego Desktop's send_xrp_tx
//! does, plus an optional destination tag (exchanges need one; without it a
//! deposit can be lost) and checked addresses. The caller supplies the
//! account's sequence and the ledger index, and submits.

use k256::ecdsa::SigningKey;
use sha2::{Digest, Sha256, Sha512};

pub const KEY_PATH: &str = "ego:xrp:0";
/// Ego Desktop's fee: 12 drops, a little over the 10-drop minimum.
pub const FEE_DROPS: u64 = 12;

/// The 20-byte account id of a classic address, with its checksum checked.
pub fn account_id(address: &str) -> Result<[u8; 20], String> {
    let wrong = || "That isn't an XRP address.".to_string();
    let full = bs58::decode(address.trim()).with_alphabet(bs58::Alphabet::RIPPLE).into_vec().map_err(|_| wrong())?;
    if full.len() != 25 || full[0] != 0 {
        return Err(wrong());
    }
    let check = Sha256::digest(Sha256::digest(&full[..21]));
    if check[..4] != full[21..] {
        return Err(wrong());
    }
    full[1..21].try_into().map_err(|_| wrong())
}

fn field_id(type_code: u8, field_code: u8) -> Vec<u8> {
    match (type_code < 16, field_code < 16) {
        (true, true) => vec![(type_code << 4) | field_code],
        (true, false) => vec![type_code << 4, field_code],
        (false, true) => vec![field_code, type_code],
        (false, false) => vec![0x00, type_code, field_code],
    }
}

fn uint16(t: u8, f: u8, v: u16) -> Vec<u8> {
    [field_id(t, f), v.to_be_bytes().to_vec()].concat()
}

fn uint32(t: u8, f: u8, v: u32) -> Vec<u8> {
    [field_id(t, f), v.to_be_bytes().to_vec()].concat()
}

fn drops(t: u8, f: u8, d: u64) -> Vec<u8> {
    [field_id(t, f), ((d & 0x3FFF_FFFF_FFFF_FFFF) | 0x4000_0000_0000_0000).to_be_bytes().to_vec()].concat()
}

fn blob(t: u8, f: u8, data: &[u8]) -> Vec<u8> {
    [field_id(t, f), vec![data.len() as u8], data.to_vec()].concat()
}

pub struct Payment<'a> {
    pub to: &'a str,
    pub drops: u64,
    pub sequence: u32,
    pub last_ledger: u32,
    pub destination_tag: Option<u32>,
}

pub struct Signed {
    /// Hex tx_blob for submit.
    pub raw: String,
    /// The transaction hash as the ledger shows it.
    pub hash: String,
}

/// Fields in canonical order (by type, then field code), with or without the signature.
fn serialize(p: &Payment, from: &[u8; 20], to: &[u8; 20], pubkey: &[u8], signature: Option<&[u8]>) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend(uint16(1, 2, 0)); // TransactionType: Payment
    t.extend(uint32(2, 2, 0x8000_0000)); // Flags: tfFullyCanonicalSig
    t.extend(uint32(2, 4, p.sequence));
    if let Some(tag) = p.destination_tag {
        t.extend(uint32(2, 14, tag));
    }
    t.extend(uint32(2, 27, p.last_ledger));
    t.extend(drops(6, 1, p.drops));
    t.extend(drops(6, 8, FEE_DROPS));
    t.extend(blob(7, 3, pubkey));
    if let Some(sig) = signature {
        t.extend(blob(7, 4, sig));
    }
    t.extend(blob(8, 1, from));
    t.extend(blob(8, 3, to));
    t
}

fn sha512_half(prefix: &[u8], data: &[u8]) -> [u8; 32] {
    let full = Sha512::new().chain_update(prefix).chain_update(data).finalize();
    full[..32].try_into().expect("32 bytes")
}

pub fn sign_payment(privkey: &[u8; 32], p: &Payment) -> Result<Signed, String> {
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    let key = SigningKey::from_slice(privkey).map_err(|e| e.to_string())?;
    let pubkey = key.verifying_key().to_encoded_point(true);
    let from_address = {
        let h = crate::derive::hash160(pubkey.as_bytes());
        let mut id = [0u8; 20];
        id.copy_from_slice(&h);
        id
    };
    let to = account_id(p.to)?;
    if to == from_address {
        return Err("That's your own address.".into());
    }
    let unsigned = serialize(p, &from_address, &to, pubkey.as_bytes(), None);
    let hash = sha512_half(&[0x53, 0x54, 0x58, 0x00], &unsigned);
    let sig: k256::ecdsa::Signature = key.sign_prehash(&hash).map_err(|e| e.to_string())?;
    let sig = sig.normalize_s().unwrap_or(sig);
    let der = sig.to_der();
    let signed = serialize(p, &from_address, &to, pubkey.as_bytes(), Some(der.as_bytes()));
    let id = sha512_half(&[0x54, 0x58, 0x4E, 0x00], &signed);
    Ok(Signed { raw: hex::encode_upper(&signed), hash: hex::encode_upper(id) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashVerifier;

    #[test]
    fn addresses_are_checked_and_ours_round_trips() {
        let seed = [7u8; 32];
        let ours = crate::derive::addr_xrp(&seed).unwrap();
        let key = SigningKey::from_slice(&crate::derive::secp_privkey(&seed, KEY_PATH)).unwrap();
        let h = crate::derive::hash160(key.verifying_key().to_encoded_point(true).as_bytes());
        assert_eq!(account_id(&ours).unwrap().as_slice(), h.as_slice());
        assert!(account_id("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh").is_ok(), "the genesis account");
        assert!(account_id("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTi").is_err(), "checksum");
        assert!(account_id("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").is_err());
    }

    #[test]
    fn a_payment_is_canonical_and_verifies() {
        let key = [5u8; 32];
        let p = Payment { to: "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh", drops: 2_500_000, sequence: 7, last_ledger: 1_000, destination_tag: Some(123_456) };
        let signed = sign_payment(&key, &p).unwrap();
        let blob = hex::decode(&signed.raw).unwrap();
        assert_eq!(&blob[..3], &[0x12, 0x00, 0x00], "Payment");
        assert!(blob.windows(5).any(|w| w == [0x2e, 0x00, 0x01, 0xe2, 0x40]), "DestinationTag 123456 after Sequence");
        // Re-derive the signing hash from the blob without the signature and verify.
        let sk = SigningKey::from_slice(&key).unwrap();
        let pubkey = sk.verifying_key().to_encoded_point(true);
        let mut from = [0u8; 20];
        from.copy_from_slice(&crate::derive::hash160(pubkey.as_bytes()));
        let unsigned = serialize(&p, &from, &account_id(p.to).unwrap(), pubkey.as_bytes(), None);
        let hash = sha512_half(&[0x53, 0x54, 0x58, 0x00], &unsigned);
        // The signature blob sits just before the two 22-byte account fields.
        let at = unsigned.len() - 44;
        assert_eq!(&blob[..at], &unsigned[..at]);
        assert_eq!(blob[at], 0x74, "TxnSignature");
        let (sig_start, sig_len) = (at + 2, blob[at + 1] as usize);
        assert_eq!(&blob[sig_start + sig_len..], &unsigned[at..]);
        let sig = k256::ecdsa::Signature::from_der(&blob[sig_start..sig_start + sig_len]).unwrap();
        sk.verifying_key().verify_prehash(&hash, &sig).expect("verifies");
        assert!(sig.normalize_s().is_none(), "low S, as the ledger requires");
        assert_eq!(signed.hash.len(), 64);
        let no_tag = sign_payment(&key, &Payment { destination_tag: None, ..p }).unwrap();
        assert!(no_tag.raw.len() < signed.raw.len());
    }
}
