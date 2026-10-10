//! Tron TRX transfers. Ego Desktop asked trongrid to build the transaction and
//! signed whatever came back; here it's built locally from a recent block
//! reference, so only what the person asked for gets signed. A test checks the
//! encoding against a transaction trongrid built.

use k256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};

pub const KEY_PATH: &str = "ego:tron:0";

/// The 21-byte address (0x41 prefix) of a base58 Tron address, checksum checked.
pub fn address_bytes(address: &str) -> Result<[u8; 21], String> {
    let wrong = || "That isn't a Tron address.".to_string();
    let full = bs58::decode(address.trim()).into_vec().map_err(|_| wrong())?;
    if full.len() != 25 || full[0] != 0x41 {
        return Err(wrong());
    }
    if Sha256::digest(Sha256::digest(&full[..21]))[..4] != full[21..] {
        return Err(wrong());
    }
    full[..21].try_into().map_err(|_| wrong())
}

fn varint(mut n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn bytes_field(tag: u8, data: &[u8]) -> Vec<u8> {
    [vec![tag], varint(data.len() as u64), data.to_vec()].concat()
}

fn int_field(tag: u8, n: u64) -> Vec<u8> {
    [vec![tag], varint(n)].concat()
}

/// A recent block the transaction refers to, from /wallet/getnowblock.
pub struct BlockRef {
    /// Bytes 6..8 of the block number.
    pub ref_block_bytes: [u8; 2],
    /// Bytes 8..16 of the block id.
    pub ref_block_hash: [u8; 8],
    /// Milliseconds.
    pub expiration: u64,
    /// Milliseconds.
    pub timestamp: u64,
}

impl BlockRef {
    /// From a block's number, id (hex) and time; valid for a minute.
    pub fn from_block(number: u64, block_id_hex: &str, block_time_ms: u64, now_ms: u64) -> Result<Self, String> {
        let id = hex::decode(block_id_hex).map_err(|_| "Bad block id.")?;
        if id.len() != 32 {
            return Err("Bad block id.".into());
        }
        let n = number.to_be_bytes();
        Ok(BlockRef {
            ref_block_bytes: [n[6], n[7]],
            ref_block_hash: id[8..16].try_into().expect("8 bytes"),
            expiration: block_time_ms + 60_000,
            timestamp: now_ms,
        })
    }
}

/// The transaction's raw_data protobuf for a TransferContract.
pub fn raw_data(block: &BlockRef, owner: &[u8; 21], to: &[u8; 21], sun: u64) -> Vec<u8> {
    let transfer = [bytes_field(0x0a, owner), bytes_field(0x12, to), int_field(0x18, sun)].concat();
    let any = [bytes_field(0x0a, b"type.googleapis.com/protocol.TransferContract"), bytes_field(0x12, &transfer)].concat();
    let contract = [int_field(0x08, 1), bytes_field(0x12, &any)].concat();
    [
        bytes_field(0x0a, &block.ref_block_bytes),
        bytes_field(0x22, &block.ref_block_hash),
        int_field(0x40, block.expiration),
        bytes_field(0x5a, &contract),
        int_field(0x70, block.timestamp),
    ]
    .concat()
}

pub struct Signed {
    /// The whole Transaction protobuf, hex, for /wallet/broadcasthex.
    pub raw: String,
    pub hash: String,
}

pub fn sign_transfer(privkey: &[u8; 32], to: &str, sun: u64, block: &BlockRef) -> Result<Signed, String> {
    let key = SigningKey::from_slice(privkey).map_err(|e| e.to_string())?;
    let owner = {
        let point = key.verifying_key().to_encoded_point(false);
        let h = sha3::Keccak256::digest(&point.as_bytes()[1..]);
        let mut a = [0u8; 21];
        a[0] = 0x41;
        a[1..].copy_from_slice(&h[12..]);
        a
    };
    let to = address_bytes(to)?;
    if to == owner {
        return Err("That's your own address.".into());
    }
    if sun == 0 {
        return Err("Enter an amount above zero.".into());
    }
    let raw = raw_data(block, &owner, &to, sun);
    let txid = Sha256::digest(&raw);
    let (sig, recid) = key.sign_prehash_recoverable(&txid).map_err(|e| e.to_string())?;
    let mut signature = sig.to_bytes().to_vec();
    signature.push(recid.to_byte());
    let tx = [bytes_field(0x0a, &raw), bytes_field(0x12, &signature)].concat();
    Ok(Signed { raw: hex::encode(tx), hash: hex::encode(txid) })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Built by trongrid's /wallet/createtransaction on 2026-10-10 for 1 TRX
    /// from TNXoiAJ3dct8Fjg4M9fkLFh9S2v9TXc32G to TY6pvrSqsNM4cR5vpqvoTW4DPCob4krzip.
    #[test]
    fn encodes_exactly_what_trongrid_builds() {
        let block = BlockRef {
            ref_block_bytes: [0x26, 0xce],
            ref_block_hash: hex::decode("f55dbf085b9f1669").unwrap().try_into().unwrap(),
            expiration: 1_791_601_536_000,
            timestamp: 1_791_601_477_269,
        };
        let owner = address_bytes("TNXoiAJ3dct8Fjg4M9fkLFh9S2v9TXc32G").unwrap();
        let to = address_bytes("TY6pvrSqsNM4cR5vpqvoTW4DPCob4krzip").unwrap();
        let raw = raw_data(&block, &owner, &to, 1_000_000);
        assert_eq!(
            hex::encode(&raw),
            "0a0226ce2208f55dbf085b9f16694080d8979e92345a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a154189cbcb2372e1c2fbc00f24895a406a0c722c89f3121541f2c3ab7398d8ee56e09947d1604eea21dc903a6f18c0843d70958d949e9234"
        );
        assert_eq!(hex::encode(Sha256::digest(&raw)), "ff80c0954122f6f8eea99eaef4a472ecd20a497498e9f0c69b2c6564202338b1");
    }

    #[test]
    fn the_block_reference_comes_from_the_latest_block() {
        let b = BlockRef::from_block(86_976_223, "00000000052f26df25a3ef2c7e9b9e3a653218ed512e731e280370ebd5bea240", 1_791_601_473_000, 5).unwrap();
        assert_eq!(b.ref_block_bytes, [0x26, 0xdf]);
        assert_eq!(hex::encode(b.ref_block_hash), "25a3ef2c7e9b9e3a");
        assert_eq!(b.expiration, 1_791_601_533_000);
    }

    #[test]
    fn a_transfer_is_signed_by_our_key_and_addresses_are_checked() {
        let seed = [7u8; 32];
        let key = crate::derive::secp_privkey(&seed, KEY_PATH);
        let block = BlockRef { ref_block_bytes: [1, 2], ref_block_hash: [3; 8], expiration: 10, timestamp: 5 };
        // TY6pvrSq… is this seed's own address; pay someone else.
        let signed = sign_transfer(&key, "TNXoiAJ3dct8Fjg4M9fkLFh9S2v9TXc32G", 2_000_000, &block).unwrap();
        let tx = hex::decode(&signed.raw).unwrap();
        let ours = address_bytes(&crate::derive::addr_trx(&seed).unwrap()).unwrap();
        assert!(tx.windows(21).any(|w| w == ours), "owner is our address");
        let sig = &tx[tx.len() - 65..];
        let rec = k256::ecdsa::RecoveryId::from_byte(sig[64]).unwrap();
        let s = k256::ecdsa::Signature::from_slice(&sig[..64]).unwrap();
        let recovered = k256::ecdsa::VerifyingKey::recover_from_prehash(&hex::decode(&signed.hash).unwrap(), &s, rec).unwrap();
        assert_eq!(recovered, *SigningKey::from_slice(&key).unwrap().verifying_key());
        assert!(address_bytes("TY6pvrSqsNM4cR5vpqvoTW4DPCob4krzia").is_err(), "checksum");
        assert!(sign_transfer(&key, &crate::derive::addr_trx(&seed).unwrap(), 1, &block).is_err());
    }
}
