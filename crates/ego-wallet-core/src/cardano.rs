//! Cardano ADA transfers from the wallet's enterprise address, built and signed
//! as Ego Desktop's send_ada_tx does, with three fixes: the fee follows the
//! size (Ego Desktop paid a flat 0.2 ADA), coins carrying native tokens are
//! never spent (spending one without passing its tokens on is invalid), and
//! amounts below the ledger's minimum output are refused before signing.

use blake2::{digest::consts::U32, Blake2b, Digest};
use ed25519_dalek::{Signer, SigningKey};

type Blake2b256 = Blake2b<U32>;

pub const KEY_PATH: &str = "ego:cardano:0";
/// An ADA-only output must hold about 1 ADA; below this the ledger refuses it.
pub const MIN_OUTPUT: u64 = 1_000_000;
/// Mainnet fee parameters: fee = A × size + B.
pub const FEE_A: u64 = 44;
pub const FEE_B: u64 = 155_381;

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Utxo {
    pub tx_hash: String,
    pub tx_index: u64,
    /// Lovelace.
    pub value: u64,
}

fn cbor_major_len(major: u8, len: u64) -> Vec<u8> {
    let m = major << 5;
    match len {
        0..=23 => vec![m | len as u8],
        24..=0xff => vec![m | 24, len as u8],
        0x100..=0xffff => [vec![m | 25], (len as u16).to_be_bytes().to_vec()].concat(),
        0x1_0000..=0xffff_ffff => [vec![m | 26], (len as u32).to_be_bytes().to_vec()].concat(),
        _ => [vec![m | 27], len.to_be_bytes().to_vec()].concat(),
    }
}
fn cbor_uint(n: u64) -> Vec<u8> {
    cbor_major_len(0, n)
}
fn cbor_bytes(d: &[u8]) -> Vec<u8> {
    [cbor_major_len(2, d.len() as u64), d.to_vec()].concat()
}
fn cbor_array(items: &[Vec<u8>]) -> Vec<u8> {
    [cbor_major_len(4, items.len() as u64), items.concat()].concat()
}
fn cbor_map(pairs: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = cbor_major_len(5, pairs.len() as u64);
    for (k, v) in pairs {
        out.extend_from_slice(k);
        out.extend_from_slice(v);
    }
    out
}

/// The raw bytes of a mainnet Shelley address; Byron and testnet addresses are refused.
pub fn address_bytes(address: &str) -> Result<Vec<u8>, String> {
    use bech32::FromBase32;
    let wrong = || "That isn't a Cardano address.".to_string();
    let (hrp, data, variant) = bech32::decode(address.trim()).map_err(|_| wrong())?;
    if hrp != "addr" || variant != bech32::Variant::Bech32 {
        return Err(wrong());
    }
    let bytes = Vec::<u8>::from_base32(&data).map_err(|_| wrong())?;
    let header = *bytes.first().ok_or_else(wrong)?;
    let kind = header >> 4;
    if header & 0x0f != 1 || kind > 7 || bytes.len() < 29 {
        return Err(wrong());
    }
    Ok(bytes)
}

pub struct Signed {
    /// CBOR transaction, hex, for koios submittx.
    pub raw: String,
    /// Blake2b-256 of the body: the transaction id.
    pub hash: String,
    pub fee: u64,
    pub change: u64,
}

fn body(inputs: &[&Utxo], to: &[u8], amount: u64, own: &[u8], change: u64, fee: u64, ttl: u64) -> Result<Vec<u8>, String> {
    let mut ins = Vec::new();
    for u in inputs {
        let hash = hex::decode(&u.tx_hash).map_err(|_| "A coin's hash isn't hex.")?;
        if hash.len() != 32 {
            return Err("A coin's hash isn't 32 bytes.".into());
        }
        ins.push(cbor_array(&[cbor_bytes(&hash), cbor_uint(u.tx_index)]));
    }
    let mut outs = vec![cbor_array(&[cbor_bytes(to), cbor_uint(amount)])];
    if change > 0 {
        outs.push(cbor_array(&[cbor_bytes(own), cbor_uint(change)]));
    }
    Ok(cbor_map(&[
        (cbor_uint(0), cbor_array(&ins)),
        (cbor_uint(1), cbor_array(&outs)),
        (cbor_uint(2), cbor_uint(fee)),
        (cbor_uint(3), cbor_uint(ttl)),
    ]))
}

fn assemble(body: &[u8], key: &SigningKey) -> (Vec<u8>, [u8; 32]) {
    let id: [u8; 32] = Blake2b256::digest(body).into();
    let sig = key.sign(&id).to_bytes();
    let witness = cbor_map(&[(cbor_uint(0), cbor_array(&[cbor_array(&[cbor_bytes(&key.verifying_key().to_bytes()), cbor_bytes(&sig)])]))]);
    (cbor_array(&[body.to_vec(), witness, vec![0xf5], vec![0xf6]]), id)
}

/// `utxos` must hold only ADA; the caller leaves out coins carrying tokens.
pub fn sign_transfer(seed32: &[u8; 32], own_address: &str, to: &str, amount: u64, utxos: &[Utxo], ttl: u64) -> Result<Signed, String> {
    if amount < MIN_OUTPUT {
        return Err("Cardano needs at least 1 ADA in each payment.".into());
    }
    let key = SigningKey::from_bytes(seed32);
    let to = address_bytes(to)?;
    let own = address_bytes(own_address)?;
    if to == own {
        return Err("That's your own address.".into());
    }
    let mut sorted: Vec<&Utxo> = utxos.iter().collect();
    sorted.sort_by(|a, b| b.value.cmp(&a.value).then(a.tx_hash.cmp(&b.tx_hash)).then(a.tx_index.cmp(&b.tx_index)));

    let mut chosen: Vec<&Utxo> = Vec::new();
    for u in sorted {
        chosen.push(u);
        let total: u64 = chosen.iter().map(|u| u.value).sum();
        // Size the fee on a draft with change, then settle the change.
        let mut fee = 200_000;
        for _ in 0..3 {
            let change = total.saturating_sub(amount + fee);
            let draft = assemble(&body(&chosen, &to, amount, &own, change.max(MIN_OUTPUT), fee, ttl)?, &key).0;
            fee = FEE_A * (draft.len() as u64 + 8) + FEE_B;
        }
        if total < amount + fee {
            continue;
        }
        let mut change = total - amount - fee;
        if change < MIN_OUTPUT {
            fee += change; // Too small for its own output: it goes to the fee.
            change = 0;
        }
        let (tx, id) = assemble(&body(&chosen, &to, amount, &own, change, fee, ttl)?, &key);
        return Ok(Signed { raw: hex::encode(tx), hash: hex::encode(id), fee, change });
    }
    Err("Not enough ADA to cover this and the network fee.".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    fn coins() -> Vec<Utxo> {
        vec![
            Utxo { tx_hash: "aa".repeat(32), tx_index: 0, value: 3_000_000 },
            Utxo { tx_hash: "bb".repeat(32), tx_index: 1, value: 10_000_000 },
        ]
    }

    #[test]
    fn cbor_lengths_follow_the_standard() {
        assert_eq!(cbor_uint(23), [0x17]);
        assert_eq!(cbor_uint(24), [0x18, 24]);
        assert_eq!(cbor_uint(1_000_000), [0x1a, 0x00, 0x0f, 0x42, 0x40]);
        assert_eq!(cbor_bytes(&[1, 2]), [0x42, 1, 2]);
        assert_eq!(cbor_array(&[]), [0x80]);
    }

    #[test]
    fn a_transfer_pays_a_size_based_fee_and_is_signed_over_the_body() {
        let seed = [7u8; 32];
        let own = crate::derive::addr_ada(&seed).unwrap();
        let to = crate::derive::addr_ada(&[8u8; 32]).unwrap();
        let s = sign_transfer(&crate::derive::ed25519_seed32(&seed, KEY_PATH), &own, &to, 5_000_000, &coins(), 1_000).unwrap();
        let tx = hex::decode(&s.raw).unwrap();
        assert!(s.fee > FEE_B && s.fee < 200_000, "fee {} follows the size", s.fee);
        assert!(s.fee >= FEE_A * tx.len() as u64 + FEE_B, "the fee covers the final size");
        assert_eq!(s.change, 10_000_000 - 5_000_000 - s.fee);
        // The body is the first item after the array header; its hash is signed.
        let key = SigningKey::from_bytes(&crate::derive::ed25519_seed32(&seed, KEY_PATH));
        // Witness set: a1 00 81 82, then 32-byte key and 64-byte signature with 2-byte headers.
        let witness_len = 4 + 2 + 32 + 2 + 64;
        let body_end = tx.len() - witness_len - 2;
        let body = &tx[1..body_end];
        assert_eq!(hex::encode(Blake2b256::digest(body)), s.hash);
        let sig = Signature::from_bytes(tx[tx.len() - 66..tx.len() - 2].try_into().unwrap());
        key.verifying_key().verify(&hex::decode(&s.hash).unwrap(), &sig).expect("verifies");
    }

    #[test]
    fn small_amounts_and_bad_addresses_are_refused() {
        let seed = [7u8; 32];
        let own = crate::derive::addr_ada(&seed).unwrap();
        let k = crate::derive::ed25519_seed32(&seed, KEY_PATH);
        let to = crate::derive::addr_ada(&[8u8; 32]).unwrap();
        assert!(sign_transfer(&k, &own, &to, 999_999, &coins(), 1).is_err());
        assert!(sign_transfer(&k, &own, &to, 13_000_000, &coins(), 1).is_err(), "can't cover the fee");
        assert!(sign_transfer(&k, &own, &own, 2_000_000, &coins(), 1).is_err());
        assert!(address_bytes("addr_test1vz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzerspjrlsz").is_err(), "testnet");
        assert!(address_bytes("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").is_err());
        assert!(address_bytes("addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x").is_ok());
    }
}
