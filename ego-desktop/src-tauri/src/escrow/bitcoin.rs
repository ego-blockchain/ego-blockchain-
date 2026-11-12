use bech32::{FromBase32, ToBase32, Variant};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

pub type Pubkey = [u8; 33];

pub const SEQUENCE_LOCKED: u32 = 0xffff_fffe;
pub const SIGHASH_ALL: u8 = 0x01;
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

const OP_0: u8 = 0x00;
const OP_1: u8 = 0x51;
const OP_2: u8 = 0x52;
const OP_3: u8 = 0x53;
const OP_IF: u8 = 0x63;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
const OP_DROP: u8 = 0x75;
const OP_DUP: u8 = 0x76;
const OP_EQUAL: u8 = 0x87;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_HASH160: u8 = 0xa9;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKMULTISIG: u8 = 0xae;
const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coin {
    Bitcoin,
    Dogecoin,
}

impl Coin {
    pub fn segwit(self) -> bool {
        matches!(self, Coin::Bitcoin)
    }

    fn p2pkh_version(self) -> u8 {
        match self {
            Coin::Bitcoin => 0x00,
            Coin::Dogecoin => 0x1e,
        }
    }

    fn p2sh_version(self) -> u8 {
        match self {
            Coin::Bitcoin => 0x05,
            Coin::Dogecoin => 0x16,
        }
    }

    pub fn dust(self) -> u64 {
        match self {
            Coin::Bitcoin => 546,
            Coin::Dogecoin => 1_000_000,
        }
    }
}

pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

pub fn sha256d(b: &[u8]) -> [u8; 32] {
    sha256(&sha256(b))
}

pub fn hash160(b: &[u8]) -> [u8; 20] {
    Ripemd160::digest(sha256(b)).into()
}

pub fn pubkey_of(key: &SigningKey) -> Pubkey {
    let point = VerifyingKey::from(key).to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(point.as_bytes());
    out
}

pub fn parse_pubkey(hex_str: &str) -> Result<Pubkey, String> {
    let raw = hex::decode(hex_str.trim()).map_err(|_| "the key is not hex".to_string())?;
    let key: Pubkey = raw.try_into().map_err(|_| "a public key is 33 bytes".to_string())?;
    VerifyingKey::from_sec1_bytes(&key).map_err(|_| "that is not a valid public key".to_string())?;
    Ok(key)
}

fn push(script: &mut Vec<u8>, data: &[u8]) {
    let n = data.len();
    if n < 0x4c {
        script.push(n as u8);
    } else if n <= 0xff {
        script.push(0x4c);
        script.push(n as u8);
    } else {
        script.push(0x4d);
        script.extend_from_slice(&(n as u16).to_le_bytes());
    }
    script.extend_from_slice(data);
}

fn script_num(n: u32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut v = n as u64;
    while v > 0 {
        out.push((v & 0xff) as u8);
        v >>= 8;
    }
    if out.last().is_some_and(|b| b & 0x80 != 0) {
        out.push(0);
    }
    out
}

pub fn escrow_script(seller: &Pubkey, buyer: &Pubkey, arbiter: &Pubkey, locktime: u32) -> Vec<u8> {
    let mut s = vec![OP_IF, OP_2];
    push(&mut s, seller);
    push(&mut s, buyer);
    push(&mut s, arbiter);
    s.extend_from_slice(&[OP_3, OP_CHECKMULTISIG, OP_ELSE]);
    push(&mut s, &script_num(locktime));
    s.extend_from_slice(&[OP_CHECKLOCKTIMEVERIFY, OP_DROP]);
    push(&mut s, seller);
    s.extend_from_slice(&[OP_CHECKSIG, OP_ENDIF]);
    s
}

pub fn escrow_script_pubkey(coin: Coin, script: &[u8]) -> Vec<u8> {
    match coin {
        Coin::Bitcoin => {
            let mut s = vec![OP_0];
            push(&mut s, &sha256(script));
            s
        }
        Coin::Dogecoin => p2sh_script(&hash160(script)),
    }
}

fn p2sh_script(h: &[u8; 20]) -> Vec<u8> {
    let mut s = vec![OP_HASH160];
    push(&mut s, h);
    s.push(OP_EQUAL);
    s
}

fn p2pkh_script(h: &[u8; 20]) -> Vec<u8> {
    let mut s = vec![OP_DUP, OP_HASH160];
    push(&mut s, h);
    s.extend_from_slice(&[OP_EQUALVERIFY, OP_CHECKSIG]);
    s
}

fn segwit_address(version: u8, program: &[u8]) -> String {
    let mut data = vec![bech32::u5::try_from_u8(version).unwrap_or(bech32::u5::try_from_u8(0).unwrap())];
    data.extend(program.to_base32());
    let variant = if version == 0 { Variant::Bech32 } else { Variant::Bech32m };
    bech32::encode("bc", data, variant).unwrap_or_default()
}

pub(crate) fn base58check(version: u8, h: &[u8; 20]) -> String {
    let mut payload = vec![version];
    payload.extend_from_slice(h);
    let check = sha256d(&payload);
    payload.extend_from_slice(&check[..4]);
    bs58::encode(payload).into_string()
}

fn base58check_decode(s: &str) -> Option<Vec<u8>> {
    let raw = bs58::decode(s).into_vec().ok()?;
    if raw.len() < 5 {
        return None;
    }
    let (payload, check) = raw.split_at(raw.len() - 4);
    (sha256d(payload)[..4] == *check).then(|| payload.to_vec())
}

pub fn escrow_address(coin: Coin, script: &[u8]) -> String {
    match coin {
        Coin::Bitcoin => segwit_address(0, &sha256(script)),
        Coin::Dogecoin => base58check(coin.p2sh_version(), &hash160(script)),
    }
}

pub fn payout_address(coin: Coin, key: &Pubkey) -> String {
    match coin {
        Coin::Bitcoin => segwit_address(0, &hash160(key)),
        Coin::Dogecoin => base58check(coin.p2pkh_version(), &hash160(key)),
    }
}

pub fn wallet_script_pubkey(coin: Coin, key: &Pubkey) -> Vec<u8> {
    match coin {
        Coin::Bitcoin => {
            let mut s = vec![OP_0];
            push(&mut s, &hash160(key));
            s
        }
        Coin::Dogecoin => p2pkh_script(&hash160(key)),
    }
}

pub fn script_pubkey_for_address(coin: Coin, address: &str) -> Result<Vec<u8>, String> {
    let a = address.trim();
    if coin == Coin::Bitcoin && a.to_ascii_lowercase().starts_with("bc1") {
        let (hrp, data, variant) = bech32::decode(a).map_err(|_| "that is not a valid Bitcoin address".to_string())?;
        if hrp != "bc" || data.is_empty() {
            return Err("that is not a Bitcoin main network address".into());
        }
        let version = data[0].to_u8();
        let program = Vec::<u8>::from_base32(&data[1..]).map_err(|_| "that is not a valid Bitcoin address".to_string())?;
        let expected = if version == 0 { Variant::Bech32 } else { Variant::Bech32m };
        if variant != expected || version > 16 || !(2..=40).contains(&program.len()) {
            return Err("that is not a valid Bitcoin address".into());
        }
        if version == 0 && program.len() != 20 && program.len() != 32 {
            return Err("that is not a valid Bitcoin address".into());
        }
        let mut s = vec![if version == 0 { OP_0 } else { OP_1 + version - 1 }];
        push(&mut s, &program);
        return Ok(s);
    }
    let raw = base58check_decode(a).ok_or_else(|| "that address is not valid".to_string())?;
    if raw.len() != 21 {
        return Err("that address is not valid".into());
    }
    let mut h = [0u8; 20];
    h.copy_from_slice(&raw[1..]);
    if raw[0] == coin.p2pkh_version() {
        Ok(p2pkh_script(&h))
    } else if raw[0] == coin.p2sh_version() {
        Ok(p2sh_script(&h))
    } else {
        Err(format!("that is not a {coin:?} address"))
    }
}

pub fn valid_address(coin: Coin, address: &str) -> bool {
    script_pubkey_for_address(coin, address).is_ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIn {
    pub txid: [u8; 32],
    pub vout: u32,
    pub value: u64,
    pub sequence: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tx {
    pub version: i32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub locktime: u32,
}

pub fn txid_from_hex(s: &str) -> Result<[u8; 32], String> {
    let mut raw: [u8; 32] = hex::decode(s.trim())
        .map_err(|_| "the transaction id is not hex".to_string())?
        .try_into()
        .map_err(|_| "a transaction id is 32 bytes".to_string())?;
    raw.reverse();
    Ok(raw)
}

pub fn txid_hex(internal: &[u8; 32]) -> String {
    let mut b = *internal;
    b.reverse();
    hex::encode(b)
}

fn varint(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

fn var_bytes(out: &mut Vec<u8>, b: &[u8]) {
    varint(out, b.len() as u64);
    out.extend_from_slice(b);
}

fn ser_outputs(out: &mut Vec<u8>, outputs: &[TxOut]) {
    varint(out, outputs.len() as u64);
    for o in outputs {
        out.extend_from_slice(&o.value.to_le_bytes());
        var_bytes(out, &o.script_pubkey);
    }
}

pub fn serialize(tx: &Tx, script_sigs: &[Vec<u8>], witnesses: &[Vec<Vec<u8>>]) -> Vec<u8> {
    let segwit = witnesses.iter().any(|w| !w.is_empty());
    let mut out = Vec::new();
    out.extend_from_slice(&tx.version.to_le_bytes());
    if segwit {
        out.extend_from_slice(&[0x00, 0x01]);
    }
    varint(&mut out, tx.inputs.len() as u64);
    for (i, input) in tx.inputs.iter().enumerate() {
        out.extend_from_slice(&input.txid);
        out.extend_from_slice(&input.vout.to_le_bytes());
        var_bytes(&mut out, script_sigs.get(i).map(Vec::as_slice).unwrap_or(&[]));
        out.extend_from_slice(&input.sequence.to_le_bytes());
    }
    ser_outputs(&mut out, &tx.outputs);
    if segwit {
        for i in 0..tx.inputs.len() {
            let w = witnesses.get(i).cloned().unwrap_or_default();
            varint(&mut out, w.len() as u64);
            for item in w {
                var_bytes(&mut out, &item);
            }
        }
    }
    out.extend_from_slice(&tx.locktime.to_le_bytes());
    out
}

pub fn txid(tx: &Tx, script_sigs: &[Vec<u8>]) -> String {
    txid_hex(&sha256d(&serialize(tx, script_sigs, &[])))
}

pub fn sighash_segwit(tx: &Tx, index: usize, script_code: &[u8], value: u64) -> [u8; 32] {
    let mut prevouts = Vec::new();
    let mut sequences = Vec::new();
    for i in &tx.inputs {
        prevouts.extend_from_slice(&i.txid);
        prevouts.extend_from_slice(&i.vout.to_le_bytes());
        sequences.extend_from_slice(&i.sequence.to_le_bytes());
    }
    let mut outputs = Vec::new();
    for o in &tx.outputs {
        outputs.extend_from_slice(&o.value.to_le_bytes());
        var_bytes(&mut outputs, &o.script_pubkey);
    }
    let input = &tx.inputs[index];
    let mut m = Vec::new();
    m.extend_from_slice(&tx.version.to_le_bytes());
    m.extend_from_slice(&sha256d(&prevouts));
    m.extend_from_slice(&sha256d(&sequences));
    m.extend_from_slice(&input.txid);
    m.extend_from_slice(&input.vout.to_le_bytes());
    var_bytes(&mut m, script_code);
    m.extend_from_slice(&value.to_le_bytes());
    m.extend_from_slice(&input.sequence.to_le_bytes());
    m.extend_from_slice(&sha256d(&outputs));
    m.extend_from_slice(&tx.locktime.to_le_bytes());
    m.extend_from_slice(&(SIGHASH_ALL as u32).to_le_bytes());
    sha256d(&m)
}

pub fn sighash_legacy(tx: &Tx, index: usize, script_code: &[u8]) -> [u8; 32] {
    let sigs: Vec<Vec<u8>> = (0..tx.inputs.len()).map(|i| if i == index { script_code.to_vec() } else { Vec::new() }).collect();
    let mut m = serialize(tx, &sigs, &[]);
    m.extend_from_slice(&(SIGHASH_ALL as u32).to_le_bytes());
    sha256d(&m)
}

pub fn sighash(coin: Coin, tx: &Tx, index: usize, script_code: &[u8], value: u64) -> [u8; 32] {
    if coin.segwit() {
        sighash_segwit(tx, index, script_code, value)
    } else {
        sighash_legacy(tx, index, script_code)
    }
}

pub fn sign_hash(key: &SigningKey, hash: &[u8; 32]) -> Result<Vec<u8>, String> {
    let sig: Signature = key.sign_prehash(hash).map_err(|e| e.to_string())?;
    let sig = sig.normalize_s().unwrap_or(sig);
    let mut der = sig.to_der().as_bytes().to_vec();
    der.push(SIGHASH_ALL);
    Ok(der)
}

pub fn verify_sig(key: &Pubkey, hash: &[u8; 32], sig_with_type: &[u8]) -> bool {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    let Some((&kind, der)) = sig_with_type.split_last() else { return false };
    if kind != SIGHASH_ALL {
        return false;
    }
    let (Ok(vk), Ok(sig)) = (VerifyingKey::from_sec1_bytes(key), Signature::from_der(der)) else { return false };
    sig.normalize_s().is_none() && vk.verify_prehash(hash, &sig).is_ok()
}

pub fn wallet_script_code(coin: Coin, key: &Pubkey) -> Vec<u8> {
    let _ = coin;
    p2pkh_script(&hash160(key))
}

pub fn sign_wallet_input(coin: Coin, tx: &Tx, index: usize, key: &SigningKey) -> Result<(Vec<u8>, Vec<Vec<u8>>), String> {
    let pk = pubkey_of(key);
    let code = wallet_script_code(coin, &pk);
    let sig = sign_hash(key, &sighash(coin, tx, index, &code, tx.inputs[index].value))?;
    if coin.segwit() {
        Ok((Vec::new(), vec![sig, pk.to_vec()]))
    } else {
        let mut s = Vec::new();
        push(&mut s, &sig);
        push(&mut s, &pk);
        Ok((s, Vec::new()))
    }
}

pub fn escrow_sighash(coin: Coin, tx: &Tx, index: usize, script: &[u8]) -> [u8; 32] {
    sighash(coin, tx, index, script, tx.inputs[index].value)
}

pub fn escrow_multisig_unlock(coin: Coin, script: &[u8], first: &[u8], second: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
    if coin.segwit() {
        (Vec::new(), vec![Vec::new(), first.to_vec(), second.to_vec(), vec![0x01], script.to_vec()])
    } else {
        let mut s = vec![OP_0];
        push(&mut s, first);
        push(&mut s, second);
        s.push(OP_1);
        push(&mut s, script);
        (s, Vec::new())
    }
}

pub fn escrow_timeout_unlock(coin: Coin, script: &[u8], seller_sig: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
    if coin.segwit() {
        (Vec::new(), vec![seller_sig.to_vec(), Vec::new(), script.to_vec()])
    } else {
        let mut s = Vec::new();
        push(&mut s, seller_sig);
        s.push(OP_0);
        push(&mut s, script);
        (s, Vec::new())
    }
}

pub fn escrow_spend_vbytes(coin: Coin, outputs: usize) -> u64 {
    let base = 10 + 41 + outputs as u64 * 34;
    if coin.segwit() {
        base + (2 + 1 + 73 + 73 + 2 + 1 + 108) / 4 + 1
    } else {
        base + 1 + 73 + 73 + 1 + 3 + 108
    }
}

pub fn wallet_input_vbytes(coin: Coin) -> u64 {
    if coin.segwit() { 68 } else { 148 }
}

pub fn output_vbytes() -> u64 {
    34
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_slice(&[n; 32]).unwrap()
    }

    #[test]
    fn the_escrow_script_has_the_expected_shape() {
        let (s, b, a) = (pubkey_of(&key(1)), pubkey_of(&key(2)), pubkey_of(&key(3)));
        let script = escrow_script(&s, &b, &a, 1_800_000_000);
        assert_eq!(script[0], OP_IF);
        assert_eq!(script[1], OP_2);
        assert_eq!(script.len(), 2 + 3 * 34 + 3 + 5 + 2 + 34 + 2);
        assert_eq!(*script.last().unwrap(), OP_ENDIF);
        assert!(escrow_address(Coin::Bitcoin, &script).starts_with("bc1q"));
        let doge = escrow_address(Coin::Dogecoin, &script);
        assert!(doge.starts_with('9') || doge.starts_with('A'), "{doge}");
        assert!(payout_address(Coin::Dogecoin, &b).starts_with('D'));
        assert_eq!(script_pubkey_for_address(Coin::Bitcoin, &escrow_address(Coin::Bitcoin, &script)).unwrap(), escrow_script_pubkey(Coin::Bitcoin, &script));
        assert_eq!(script_pubkey_for_address(Coin::Dogecoin, &doge).unwrap(), escrow_script_pubkey(Coin::Dogecoin, &script));
    }

    #[test]
    fn script_numbers_are_minimal() {
        assert_eq!(script_num(1_800_000_000), 1_800_000_000u32.to_le_bytes().to_vec());
        assert_eq!(script_num(0x80), vec![0x80, 0x00]);
        assert_eq!(script_num(0x7f), vec![0x7f]);
    }

    #[test]
    fn signatures_verify_and_are_low_s() {
        let k = key(7);
        let h = sha256d(b"ego");
        let sig = sign_hash(&k, &h).unwrap();
        assert!(verify_sig(&pubkey_of(&k), &h, &sig));
        assert!(!verify_sig(&pubkey_of(&key(8)), &h, &sig));
    }

    #[test]
    fn known_bitcoin_addresses_decode() {
        assert!(valid_address(Coin::Bitcoin, "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"));
        assert!(valid_address(Coin::Bitcoin, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"));
        assert!(valid_address(Coin::Bitcoin, "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"));
        assert!(!valid_address(Coin::Bitcoin, "tb1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"));
        assert!(!valid_address(Coin::Dogecoin, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"));
    }

    #[test]
    fn write_cross_check_vectors() {
        let Ok(path) = std::env::var("EGO_BTC_VECTORS") else { return };
        let (sk, bk, ak) = (key(1), key(2), key(3));
        let (s, b, a) = (pubkey_of(&sk), pubkey_of(&bk), pubkey_of(&ak));
        let script = escrow_script(&s, &b, &a, 1_800_000_000);
        let mut out = serde_json::Map::new();
        out.insert("script".into(), hex::encode(&script).into());
        for coin in [Coin::Bitcoin, Coin::Dogecoin] {
            let fee_to = if coin == Coin::Bitcoin { "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string() } else { payout_address(coin, &a) };
            let tx = Tx {
                version: 2,
                inputs: vec![TxIn { txid: sha256(b"fund"), vout: 1, value: 100_000_000, sequence: SEQUENCE_LOCKED }],
                outputs: vec![
                    TxOut { value: 98_000_000, script_pubkey: wallet_script_pubkey(coin, &b) },
                    TxOut { value: 1_000_000, script_pubkey: script_pubkey_for_address(coin, &fee_to).unwrap() },
                ],
                locktime: 0,
            };
            let h = escrow_sighash(coin, &tx, 0, &script);
            let s1 = sign_hash(&sk, &h).unwrap();
            let s2 = sign_hash(&bk, &h).unwrap();
            let (ss, wit) = escrow_multisig_unlock(coin, &script, &s1, &s2);
            let raw = serialize(&tx, &[ss.clone()], &[wit]);
            let timeout_tx = Tx { locktime: 1_800_000_000, ..tx.clone() };
            let th = escrow_sighash(coin, &timeout_tx, 0, &script);
            let name = format!("{coin:?}").to_lowercase();
            out.insert(format!("{name}_escrow_address"), escrow_address(coin, &script).into());
            out.insert(format!("{name}_buyer_address"), payout_address(coin, &b).into());
            out.insert(format!("{name}_fee_address"), fee_to.into());
            out.insert(format!("{name}_sighash"), hex::encode(h).into());
            out.insert(format!("{name}_timeout_sighash"), hex::encode(th).into());
            out.insert(format!("{name}_tx"), hex::encode(&raw).into());
            out.insert(format!("{name}_txid"), txid(&tx, &[ss]).into());
        }
        for (n, k) in [("seller", &s), ("buyer", &b), ("arbiter", &a)] {
            out.insert(format!("{n}_pub"), hex::encode(k).into());
        }
        std::fs::write(path, serde_json::to_string_pretty(&out).unwrap()).unwrap();
    }
}
