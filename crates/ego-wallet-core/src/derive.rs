//! The addresses Ego Desktop derives for other chains, from the Ego seed.
//! Copied from ego-desktop's multichain.rs; a test there checks they agree.

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChainAddress {
    pub chain: &'static str,
    pub symbol: &'static str,
    pub address: String,
    pub address_type: &'static str,
    pub explorer_prefix: &'static str,
}

/// The built-in chains, in the order Ego Desktop lists them.
pub fn external_addresses(seed: &[u8]) -> Result<Vec<ChainAddress>, String> {
    let item = |chain, symbol, address: Result<String, String>, address_type, explorer_prefix| {
        address.map(|address| ChainAddress { chain, symbol, address, address_type, explorer_prefix })
    };
    Ok(vec![
        item("Bitcoin", "BTC", addr_btc_like(seed, "ego:bitcoin:0", "bc"), "P2WPKH", "https://blockstream.info/address/")?,
        item("Ethereum", "ETH", addr_evm(seed, "ego:ethereum:0"), "EVM", "https://etherscan.io/address/")?,
        item("BNB Chain", "BNB", addr_evm(seed, "ego:bnb:0"), "EVM", "https://bscscan.com/address/")?,
        item("Solana", "SOL", addr_sol(seed), "Ed25519", "https://solscan.io/account/")?,
        item("Cardano", "ADA", addr_ada(seed), "Shelley", "https://cardanoscan.io/address/")?,
        item("XRP", "XRP", addr_xrp(seed), "Classic", "https://xrpscan.com/account/")?,
        item("Tron", "TRX", addr_trx(seed), "TRC20", "https://tronscan.org/#/address/")?,
        item("Litecoin", "LTC", addr_btc_like(seed, "ego:litecoin:0", "ltc"), "P2WPKH", "https://litecoinspace.org/address/")?,
        item("Dogecoin", "DOGE", addr_doge(seed), "P2PKH", "https://dogechain.info/address/")?,
    ])
}

fn hmac_sha512(seed: &[u8], path: &str) -> [u8; 64] {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;
    let mut mac = HmacSha512::new_from_slice(seed).expect("HMAC any key");
    mac.update(path.as_bytes());
    mac.finalize().into_bytes().into()
}

pub fn secp_privkey(seed: &[u8], path: &str) -> [u8; 32] {
    let full = hmac_sha512(seed, path);
    let mut k = [0u8; 32];
    k.copy_from_slice(&full[..32]);
    k
}

pub fn ed25519_seed32(seed: &[u8], path: &str) -> [u8; 32] {
    let full = hmac_sha512(seed, path);
    let mut k = [0u8; 32];
    k.copy_from_slice(&full[..32]);
    k
}

pub fn hash160(data: &[u8]) -> [u8; 20] {
    use ripemd::Ripemd160;
    use sha2::{Digest, Sha256};
    let sha = Sha256::digest(data);
    let rmd = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&rmd);
    out
}

pub fn base58check(version: u8, payload: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut data = vec![version];
    data.extend_from_slice(payload);
    let cs = &Sha256::digest(Sha256::digest(&data))[..4];
    data.extend_from_slice(cs);
    bs58::encode(data).into_string()
}

pub fn eip55_checksum(addr: &[u8]) -> String {
    use sha3::{Digest, Keccak256};
    let hex_lower = hex::encode(addr);
    let hash_hex = hex::encode(Keccak256::digest(hex_lower.as_bytes()));
    let cs: String = hex_lower
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if c.is_ascii_alphabetic() && u8::from_str_radix(&hash_hex[i..i + 1], 16).unwrap_or(0) >= 8 {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect();
    format!("0x{cs}")
}

pub fn addr_btc_like(seed: &[u8], path: &str, hrp: &str) -> Result<String, String> {
    use bech32::{u5, ToBase32, Variant};
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::SecretKey;
    let sk = SecretKey::from_slice(&secp_privkey(seed, path)).map_err(|e| e.to_string())?;
    let pt = sk.public_key().to_encoded_point(true);
    let h = hash160(pt.as_bytes());
    let mut payload = vec![u5::try_from_u8(0).map_err(|e| e.to_string())?];
    payload.extend_from_slice(&h.to_base32());
    bech32::encode(hrp, payload, Variant::Bech32).map_err(|e| e.to_string())
}

pub fn addr_evm(seed: &[u8], path: &str) -> Result<String, String> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::SecretKey;
    use sha3::{Digest, Keccak256};
    let sk = SecretKey::from_slice(&secp_privkey(seed, path)).map_err(|e| e.to_string())?;
    let pt = sk.public_key().to_encoded_point(false);
    let raw = &pt.as_bytes()[1..];
    let h = Keccak256::digest(raw);
    Ok(eip55_checksum(&h[12..]))
}

pub fn addr_doge(seed: &[u8]) -> Result<String, String> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::SecretKey;
    let sk = SecretKey::from_slice(&secp_privkey(seed, "ego:dogecoin:0")).map_err(|e| e.to_string())?;
    let pt = sk.public_key().to_encoded_point(true);
    Ok(base58check(0x1E, &hash160(pt.as_bytes())))
}

pub fn addr_sol(seed: &[u8]) -> Result<String, String> {
    use ed25519_dalek::SigningKey;
    let sk = SigningKey::from_bytes(&ed25519_seed32(seed, "ego:solana:0"));
    Ok(bs58::encode(sk.verifying_key().to_bytes()).into_string())
}

pub fn addr_xrp(seed: &[u8]) -> Result<String, String> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::SecretKey;
    use sha2::{Digest, Sha256};
    let sk = SecretKey::from_slice(&secp_privkey(seed, "ego:xrp:0")).map_err(|e| e.to_string())?;
    let pt = sk.public_key().to_encoded_point(true);
    let h = hash160(pt.as_bytes());
    let mut data = vec![0x00u8];
    data.extend_from_slice(&h);
    let cs = &Sha256::digest(Sha256::digest(&data))[..4];
    data.extend_from_slice(cs);
    Ok(bs58::encode(data).with_alphabet(bs58::Alphabet::RIPPLE).into_string())
}

pub fn addr_trx(seed: &[u8]) -> Result<String, String> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::SecretKey;
    use sha3::{Digest, Keccak256};
    let sk = SecretKey::from_slice(&secp_privkey(seed, "ego:tron:0")).map_err(|e| e.to_string())?;
    let pt = sk.public_key().to_encoded_point(false);
    let raw = &pt.as_bytes()[1..];
    let h = Keccak256::digest(raw);
    Ok(base58check(0x41, &h[12..]))
}

pub fn addr_ada(seed: &[u8]) -> Result<String, String> {
    use bech32::{ToBase32, Variant};
    use blake2::{digest::consts::U28, Blake2b, Digest};
    use ed25519_dalek::SigningKey;
    type Blake2b224 = Blake2b<U28>;
    let sk = SigningKey::from_bytes(&ed25519_seed32(seed, "ego:cardano:0"));
    let pubkey = sk.verifying_key().to_bytes();
    let hash = Blake2b224::digest(pubkey);
    let mut payload = vec![0x61u8];
    payload.extend_from_slice(&hash);
    bech32::encode("addr", payload.to_base32(), Variant::Bech32).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_chain_gets_a_well_formed_address() {
        let list = external_addresses(&[7u8; 32]).unwrap();
        let symbols: Vec<_> = list.iter().map(|a| a.symbol).collect();
        assert_eq!(symbols, ["BTC", "ETH", "BNB", "SOL", "ADA", "XRP", "TRX", "LTC", "DOGE"]);
        let by = |s: &str| list.iter().find(|a| a.symbol == s).unwrap().address.clone();
        assert!(by("BTC").starts_with("bc1q"));
        assert!(by("LTC").starts_with("ltc1q"));
        assert!(by("ETH").starts_with("0x") && by("ETH").len() == 42);
        assert_ne!(by("ETH"), by("BNB"), "ETH and BNB use separate keys");
        assert!(by("TRX").starts_with('T'));
        assert!(by("XRP").starts_with('r'));
        assert!(by("DOGE").starts_with('D'));
        assert!(by("ADA").starts_with("addr1"));
    }

    #[test]
    fn the_same_seed_always_gives_the_same_addresses() {
        assert_eq!(external_addresses(&[1u8; 32]), external_addresses(&[1u8; 32]));
        assert_ne!(external_addresses(&[1u8; 32]), external_addresses(&[2u8; 32]));
    }
}
