use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};

pub type AccountId = [u8; 20];

const ALPHABET: &[u8; 58] = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

pub const TT_PAYMENT: u16 = 0;
pub const TT_ESCROW_CREATE: u16 = 1;
pub const TT_ESCROW_FINISH: u16 = 2;
pub const TT_ACCOUNT_SET: u16 = 3;
pub const TT_ESCROW_CANCEL: u16 = 4;
pub const TT_SIGNER_LIST_SET: u16 = 12;
pub const ASF_DISABLE_MASTER: u32 = 4;
pub const TF_FULLY_CANONICAL_SIG: u32 = 0x8000_0000;
pub const RIPPLE_EPOCH: i64 = 946_684_800;

const T_UINT16: u8 = 1;
const T_UINT32: u8 = 2;
const T_AMOUNT: u8 = 6;
const T_BLOB: u8 = 7;
const T_ACCOUNT: u8 = 8;
const T_OBJECT: u8 = 14;
const T_ARRAY: u8 = 15;

pub const F_TRANSACTION_TYPE: (u8, u8) = (T_UINT16, 2);
pub const F_SIGNER_WEIGHT: (u8, u8) = (T_UINT16, 3);
pub const F_FLAGS: (u8, u8) = (T_UINT32, 2);
pub const F_SEQUENCE: (u8, u8) = (T_UINT32, 4);
pub const F_DESTINATION_TAG: (u8, u8) = (T_UINT32, 14);
pub const F_OFFER_SEQUENCE: (u8, u8) = (T_UINT32, 25);
pub const F_LAST_LEDGER_SEQUENCE: (u8, u8) = (T_UINT32, 27);
pub const F_SET_FLAG: (u8, u8) = (T_UINT32, 33);
pub const F_SIGNER_QUORUM: (u8, u8) = (T_UINT32, 35);
pub const F_CANCEL_AFTER: (u8, u8) = (T_UINT32, 36);
pub const F_FINISH_AFTER: (u8, u8) = (T_UINT32, 37);
pub const F_AMOUNT: (u8, u8) = (T_AMOUNT, 1);
pub const F_FEE: (u8, u8) = (T_AMOUNT, 8);
pub const F_SIGNING_PUB_KEY: (u8, u8) = (T_BLOB, 3);
pub const F_TXN_SIGNATURE: (u8, u8) = (T_BLOB, 4);
pub const F_ACCOUNT: (u8, u8) = (T_ACCOUNT, 1);
pub const F_OWNER: (u8, u8) = (T_ACCOUNT, 2);
pub const F_DESTINATION: (u8, u8) = (T_ACCOUNT, 3);
const F_SIGNER_ENTRY: (u8, u8) = (T_OBJECT, 11);
const F_SIGNER: (u8, u8) = (T_OBJECT, 16);
const F_SIGNERS: (u8, u8) = (T_ARRAY, 3);
pub const F_SIGNER_ENTRIES: (u8, u8) = (T_ARRAY, 4);

fn sha512_half(b: &[u8]) -> [u8; 32] {
    let full = Sha512::digest(b);
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    out
}

fn sha256d(b: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(b)).into()
}

pub fn account_id(pubkey: &[u8; 33]) -> AccountId {
    Ripemd160::digest(Sha256::digest(pubkey)).into()
}

pub fn pubkey_of(key: &SigningKey) -> [u8; 33] {
    let point = VerifyingKey::from(key).to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(point.as_bytes());
    out
}

fn b58_encode(data: &[u8]) -> String {
    let mut digits: Vec<u8> = Vec::new();
    for &byte in data {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let zeros = data.iter().take_while(|b| **b == 0).count();
    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push(ALPHABET[0] as char);
    }
    for d in digits.iter().rev() {
        out.push(ALPHABET[*d as usize] as char);
    }
    out
}

fn b58_decode(s: &str) -> Option<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::new();
    for c in s.bytes() {
        let mut carry = ALPHABET.iter().position(|a| *a == c)? as u32;
        for b in bytes.iter_mut() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let zeros = s.bytes().take_while(|c| *c == ALPHABET[0]).count();
    let mut out = vec![0u8; zeros];
    out.extend(bytes.iter().rev());
    Some(out)
}

pub fn encode_address(id: &AccountId) -> String {
    let mut payload = vec![0u8];
    payload.extend_from_slice(id);
    let check = sha256d(&payload);
    payload.extend_from_slice(&check[..4]);
    b58_encode(&payload)
}

pub fn decode_address(s: &str) -> Result<AccountId, String> {
    let raw = b58_decode(s.trim()).ok_or("that is not an XRP address")?;
    if raw.len() != 25 || raw[0] != 0 || sha256d(&raw[..21])[..4] != raw[21..] {
        return Err("that is not an XRP address".into());
    }
    let mut id = [0u8; 20];
    id.copy_from_slice(&raw[1..21]);
    Ok(id)
}

pub fn valid_address(s: &str) -> bool {
    s.starts_with('r') && decode_address(s).is_ok()
}

pub fn address_of(key: &SigningKey) -> String {
    encode_address(&account_id(&pubkey_of(key)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    U16(u16),
    U32(u32),
    Drops(u64),
    Blob(Vec<u8>),
    Account(AccountId),
    Signers(Vec<(AccountId, Vec<u8>, Vec<u8>)>),
    SignerEntries(Vec<(AccountId, u16)>),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tx {
    pub fields: Vec<((u8, u8), Value)>,
}

impl Tx {
    pub fn set(&mut self, field: (u8, u8), value: Value) {
        self.fields.retain(|(f, _)| *f != field);
        self.fields.push((field, value));
    }

    pub fn get_u32(&self, field: (u8, u8)) -> Option<u32> {
        self.fields.iter().find_map(|(f, v)| match v {
            Value::U32(n) if *f == field => Some(*n),
            _ => None,
        })
    }
}

fn header(out: &mut Vec<u8>, (t, f): (u8, u8)) {
    match (t < 16, f < 16) {
        (true, true) => out.push((t << 4) | f),
        (true, false) => {
            out.push(t << 4);
            out.push(f);
        }
        (false, true) => {
            out.push(f);
            out.push(t);
        }
        (false, false) => {
            out.push(0);
            out.push(t);
            out.push(f);
        }
    }
}

fn vl(out: &mut Vec<u8>, b: &[u8]) {
    let n = b.len();
    if n <= 192 {
        out.push(n as u8);
    } else if n <= 12_480 {
        let m = n - 193;
        out.push(193 + (m >> 8) as u8);
        out.push((m & 0xff) as u8);
    } else {
        let m = n - 12_481;
        out.push(241 + (m >> 16) as u8);
        out.push(((m >> 8) & 0xff) as u8);
        out.push((m & 0xff) as u8);
    }
    out.extend_from_slice(b);
}

fn value(out: &mut Vec<u8>, v: &Value) {
    match v {
        Value::U16(n) => out.extend_from_slice(&n.to_be_bytes()),
        Value::U32(n) => out.extend_from_slice(&n.to_be_bytes()),
        Value::Drops(d) => out.extend_from_slice(&(0x4000_0000_0000_0000u64 | d).to_be_bytes()),
        Value::Blob(b) => vl(out, b),
        Value::Account(a) => vl(out, a),
        Value::Signers(list) => {
            let mut sorted = list.clone();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            for (acct, sig, pk) in sorted {
                header(out, F_SIGNER);
                header(out, F_SIGNING_PUB_KEY);
                vl(out, &pk);
                header(out, F_TXN_SIGNATURE);
                vl(out, &sig);
                header(out, F_ACCOUNT);
                vl(out, &acct);
                out.push(0xe1);
            }
            out.push(0xf1);
        }
        Value::SignerEntries(list) => {
            for (acct, weight) in list {
                header(out, F_SIGNER_ENTRY);
                header(out, F_SIGNER_WEIGHT);
                out.extend_from_slice(&weight.to_be_bytes());
                header(out, F_ACCOUNT);
                vl(out, acct);
                out.push(0xe1);
            }
            out.push(0xf1);
        }
    }
}

fn signing_field(f: (u8, u8)) -> bool {
    f != F_TXN_SIGNATURE && f != F_SIGNERS
}

pub fn serialize(tx: &Tx, signing_only: bool) -> Vec<u8> {
    let mut fields: Vec<&((u8, u8), Value)> = tx.fields.iter().filter(|(f, _)| !signing_only || signing_field(*f)).collect();
    fields.sort_by_key(|(f, _)| *f);
    let mut out = Vec::new();
    for (f, v) in fields {
        header(&mut out, *f);
        value(&mut out, v);
    }
    out
}

pub fn signing_hash(tx: &Tx) -> [u8; 32] {
    let mut m = vec![0x53, 0x54, 0x58, 0x00];
    m.extend(serialize(tx, true));
    sha512_half(&m)
}

pub fn multisign_hash(tx: &Tx, signer: &AccountId) -> [u8; 32] {
    let mut m = vec![0x53, 0x4d, 0x54, 0x00];
    m.extend(serialize(tx, true));
    m.extend_from_slice(signer);
    sha512_half(&m)
}

pub fn tx_hash(blob: &[u8]) -> String {
    let mut m = vec![0x54, 0x58, 0x4e, 0x00];
    m.extend_from_slice(blob);
    hex::encode_upper(sha512_half(&m))
}

fn sign_prehash(key: &SigningKey, hash: &[u8; 32]) -> Result<Vec<u8>, String> {
    let sig: Signature = key.sign_prehash(hash).map_err(|e| e.to_string())?;
    let sig = sig.normalize_s().unwrap_or(sig);
    Ok(sig.to_der().as_bytes().to_vec())
}

pub fn verify(pubkey: &[u8; 33], hash: &[u8; 32], der: &[u8]) -> bool {
    let (Ok(vk), Ok(sig)) = (VerifyingKey::from_sec1_bytes(pubkey), Signature::from_der(der)) else { return false };
    sig.normalize_s().is_none() && vk.verify_prehash(hash, &sig).is_ok()
}

pub fn sign_single(tx: &mut Tx, key: &SigningKey) -> Result<Vec<u8>, String> {
    tx.set(F_SIGNING_PUB_KEY, Value::Blob(pubkey_of(key).to_vec()));
    let sig = sign_prehash(key, &signing_hash(tx))?;
    tx.set(F_TXN_SIGNATURE, Value::Blob(sig));
    Ok(serialize(tx, false))
}

pub fn sign_multi(tx: &Tx, key: &SigningKey) -> Result<(AccountId, Vec<u8>, Vec<u8>), String> {
    let pk = pubkey_of(key);
    let id = account_id(&pk);
    let mut unsigned = tx.clone();
    unsigned.set(F_SIGNING_PUB_KEY, Value::Blob(Vec::new()));
    let sig = sign_prehash(key, &multisign_hash(&unsigned, &id))?;
    Ok((id, sig, pk.to_vec()))
}

pub fn verify_multi(tx: &Tx, signer: &(AccountId, Vec<u8>, Vec<u8>)) -> bool {
    let Ok(pk) = <[u8; 33]>::try_from(signer.2.as_slice()) else { return false };
    if account_id(&pk) != signer.0 {
        return false;
    }
    let mut unsigned = tx.clone();
    unsigned.set(F_SIGNING_PUB_KEY, Value::Blob(Vec::new()));
    verify(&pk, &multisign_hash(&unsigned, &signer.0), &signer.1)
}

pub fn combine(tx: &Tx, signers: Vec<(AccountId, Vec<u8>, Vec<u8>)>) -> Vec<u8> {
    let mut done = tx.clone();
    done.set(F_SIGNING_PUB_KEY, Value::Blob(Vec::new()));
    done.set(F_SIGNERS, Value::Signers(signers));
    serialize(&done, false)
}

pub fn base_tx(kind: u16, account: &AccountId, sequence: u32, fee_drops: u64, last_ledger: u32) -> Tx {
    let mut tx = Tx::default();
    tx.set(F_TRANSACTION_TYPE, Value::U16(kind));
    tx.set(F_FLAGS, Value::U32(TF_FULLY_CANONICAL_SIG));
    tx.set(F_SEQUENCE, Value::U32(sequence));
    tx.set(F_FEE, Value::Drops(fee_drops));
    tx.set(F_ACCOUNT, Value::Account(*account));
    if last_ledger > 0 {
        tx.set(F_LAST_LEDGER_SEQUENCE, Value::U32(last_ledger));
    }
    tx
}

pub fn ripple_time(unix: i64) -> u32 {
    (unix - RIPPLE_EPOCH).clamp(0, u32::MAX as i64) as u32
}

pub fn escrow_key(seller: &SigningKey, trade_id: &[u8; 32]) -> Result<SigningKey, String> {
    let mut m = b"ego/xrp/escrow/v1".to_vec();
    m.extend_from_slice(&seller.to_bytes());
    m.extend_from_slice(trade_id);
    let mut seed: [u8; 32] = Sha256::digest(&m).into();
    for _ in 0..16 {
        if let Ok(k) = SigningKey::from_slice(&seed) {
            return Ok(k);
        }
        seed = Sha256::digest(seed).into();
    }
    Err("could not derive the escrow account key".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_slice(&[n; 32]).unwrap()
    }

    #[test]
    fn addresses_round_trip_and_reject_damage() {
        let a = address_of(&key(4));
        assert!(a.starts_with('r'));
        assert_eq!(encode_address(&decode_address(&a).unwrap()), a);
        let mut damaged = a.clone().into_bytes();
        let last = damaged.len() - 1;
        damaged[last] = if damaged[last] == b'r' { b'p' } else { b'r' };
        assert!(decode_address(std::str::from_utf8(&damaged).unwrap()).is_err());
        assert!(valid_address("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"));
    }

    #[test]
    fn multisignatures_verify_only_for_their_signer() {
        let e = account_id(&pubkey_of(&key(9)));
        let mut tx = base_tx(TT_PAYMENT, &e, 7, 36, 0);
        tx.set(F_AMOUNT, Value::Drops(1_000_000));
        tx.set(F_DESTINATION, Value::Account(account_id(&pubkey_of(&key(2)))));
        let s = sign_multi(&tx, &key(1)).unwrap();
        assert!(verify_multi(&tx, &s));
        let mut other = tx.clone();
        other.set(F_AMOUNT, Value::Drops(1_000_001));
        assert!(!verify_multi(&other, &s));
    }

    #[test]
    fn write_cross_check_vectors() {
        let Ok(path) = std::env::var("EGO_XRP_VECTORS") else { return };
        let (s, b, a, e) = (key(1), key(2), key(3), key(9));
        let ids = [account_id(&pubkey_of(&s)), account_id(&pubkey_of(&b)), account_id(&pubkey_of(&a))];
        let eid = account_id(&pubkey_of(&e));
        let mut out = serde_json::Map::new();
        for (n, k) in [("seller", &s), ("buyer", &b), ("arbiter", &a), ("escrow", &e)] {
            out.insert(format!("{n}_pub"), hex::encode_upper(pubkey_of(k)).into());
            out.insert(format!("{n}_address"), address_of(k).into());
        }
        let mut list = base_tx(TT_SIGNER_LIST_SET, &eid, 90_000_000, 12, 90_000_100);
        list.set(F_SIGNER_QUORUM, Value::U32(2));
        list.set(F_SIGNER_ENTRIES, Value::SignerEntries(ids.iter().map(|i| (*i, 1u16)).collect()));
        let blob = sign_single(&mut list, &e).unwrap();
        out.insert("signer_list_blob".into(), hex::encode_upper(&blob).into());
        out.insert("signer_list_hash".into(), tx_hash(&blob).into());
        let mut create = base_tx(TT_ESCROW_CREATE, &ids[0], 5, 12, 0);
        create.set(F_AMOUNT, Value::Drops(25_000_000));
        create.set(F_DESTINATION, Value::Account(eid));
        create.set(F_FINISH_AFTER, Value::U32(ripple_time(1_800_000_000)));
        create.set(F_CANCEL_AFTER, Value::U32(ripple_time(1_802_592_000)));
        out.insert("escrow_create_blob".into(), hex::encode_upper(sign_single(&mut create, &s).unwrap()).into());
        let mut pay = base_tx(TT_PAYMENT, &eid, 90_000_003, 36, 90_000_200);
        pay.set(F_AMOUNT, Value::Drops(24_750_000));
        pay.set(F_DESTINATION, Value::Account(ids[1]));
        let sigs = vec![sign_multi(&pay, &b).unwrap(), sign_multi(&pay, &s).unwrap()];
        out.insert("multisig_blob".into(), hex::encode_upper(combine(&pay, sigs)).into());
        std::fs::write(path, serde_json::to_string_pretty(&out).unwrap()).unwrap();
    }
}
