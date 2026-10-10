//! Bitcoin and Litecoin transfers from the wallet's P2WPKH address, built and
//! signed as Ego Desktop's send_p2wpkh does (BIP143, largest coins first,
//! change back to the same address). Fetching coins and broadcasting stay with
//! the caller.
//!
//! Unlike Ego Desktop, the recipient can be any standard address of the right
//! network: Ego Desktop read every address as a v0 20-byte witness program, so
//! a taproot or legacy address would have produced an output nobody can spend.

use k256::ecdsa::SigningKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    pub symbol: &'static str,
    pub key_path: &'static str,
    pub hrp: &'static str,
    pub p2pkh_versions: &'static [u8],
    pub p2sh_versions: &'static [u8],
}

pub const BITCOIN: Network = Network {
    symbol: "BTC",
    key_path: "ego:bitcoin:0",
    hrp: "bc",
    p2pkh_versions: &[0x00],
    p2sh_versions: &[0x05],
};

pub const LITECOIN: Network = Network {
    symbol: "LTC",
    key_path: "ego:litecoin:0",
    hrp: "ltc",
    p2pkh_versions: &[0x30],
    p2sh_versions: &[0x32, 0x05],
};

pub fn network(symbol: &str) -> Option<Network> {
    match symbol {
        "BTC" => Some(BITCOIN),
        "LTC" => Some(LITECOIN),
        _ => None,
    }
}

/// Outputs below this are dust: nodes won't relay a transaction creating one.
pub const DUST_LIMIT: u64 = 546;

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
}

fn sha256d(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}

fn varint(n: u64) -> Vec<u8> {
    match n {
        0..=0xfc => vec![n as u8],
        0xfd..=0xffff => {
            let mut v = vec![0xfd];
            v.extend_from_slice(&(n as u16).to_le_bytes());
            v
        }
        0x1_0000..=0xffff_ffff => {
            let mut v = vec![0xfe];
            v.extend_from_slice(&(n as u32).to_le_bytes());
            v
        }
        _ => {
            let mut v = vec![0xff];
            v.extend_from_slice(&n.to_le_bytes());
            v
        }
    }
}

/// The locking script for an address of `net`: P2WPKH, P2WSH, P2TR, P2PKH or P2SH.
pub fn output_script(address: &str, net: Network) -> Result<Vec<u8>, String> {
    let address = address.trim();
    let wrong = || format!("That isn't a {} address.", if net.symbol == "BTC" { "Bitcoin" } else { "Litecoin" });
    if address.to_lowercase().starts_with(&format!("{}1", net.hrp)) {
        let (hrp, data, variant) = bech32::decode(address).map_err(|_| wrong())?;
        if hrp != net.hrp || data.is_empty() {
            return Err(wrong());
        }
        let version = data[0].to_u8();
        let program = bech32::convert_bits(&data[1..], 5, 8, false).map_err(|_| wrong())?;
        let ok = match (version, variant) {
            (0, bech32::Variant::Bech32) => program.len() == 20 || program.len() == 32,
            (1..=16, bech32::Variant::Bech32m) => (2..=40).contains(&program.len()),
            _ => false,
        };
        if !ok {
            return Err(wrong());
        }
        let mut script = vec![if version == 0 { 0x00 } else { 0x50 + version }, program.len() as u8];
        script.extend_from_slice(&program);
        return Ok(script);
    }
    let decoded = bs58::decode(address).with_check(None).into_vec().map_err(|_| wrong())?;
    if decoded.len() != 21 {
        return Err(wrong());
    }
    let (version, hash) = (decoded[0], &decoded[1..]);
    if net.p2pkh_versions.contains(&version) {
        let mut s = vec![0x76, 0xa9, 0x14];
        s.extend_from_slice(hash);
        s.extend_from_slice(&[0x88, 0xac]);
        Ok(s)
    } else if net.p2sh_versions.contains(&version) {
        let mut s = vec![0xa9, 0x14];
        s.extend_from_slice(hash);
        s.push(0x87);
        Ok(s)
    } else {
        Err(wrong())
    }
}

/// Virtual size Ego Desktop budgets: 68 vB per P2WPKH input, two outputs, overhead.
pub fn estimated_vsize(inputs: usize) -> u64 {
    inputs as u64 * 68 + 2 * 31 + 10
}

#[derive(Debug)]
pub struct Signed {
    pub raw: String,
    pub txid: String,
    pub fee: u64,
    pub change: u64,
    pub inputs: usize,
}

/// Largest coins first until the amount and the fee for that many inputs are covered.
fn select(utxos: &[Utxo], amount: u64, fee_rate: u64) -> Result<(Vec<&Utxo>, u64), String> {
    let mut sorted: Vec<&Utxo> = utxos.iter().collect();
    sorted.sort_by(|a, b| b.value.cmp(&a.value).then(a.txid.cmp(&b.txid)).then(a.vout.cmp(&b.vout)));
    let mut chosen = Vec::new();
    let mut total = 0u64;
    for u in sorted {
        chosen.push(u);
        total = total.saturating_add(u.value);
        let fee = estimated_vsize(chosen.len()) * fee_rate;
        if total >= amount.saturating_add(fee) {
            return Ok((chosen, fee));
        }
    }
    let fee = estimated_vsize(chosen.len().max(1)) * fee_rate;
    Err(format!("Not enough to cover this and the network fee of {fee} sats."))
}

/// Signs a transfer of `amount` sats from the wallet's P2WPKH address.
pub fn sign_p2wpkh(privkey: &[u8; 32], net: Network, to: &str, amount: u64, utxos: &[Utxo], fee_rate: u64) -> Result<Signed, String> {
    if amount < DUST_LIMIT {
        return Err(format!("The smallest amount the network relays is {DUST_LIMIT} sats."));
    }
    let to_script = output_script(to, net)?;
    let key = SigningKey::from_slice(privkey).map_err(|e| e.to_string())?;
    let pubkey = key.verifying_key().to_encoded_point(true);
    let pubkey_hash = crate::derive::hash160(pubkey.as_bytes());
    let mut change_script = vec![0x00, 0x14];
    change_script.extend_from_slice(&pubkey_hash);

    let (chosen, mut fee) = select(utxos, amount, fee_rate)?;
    let total_in: u64 = chosen.iter().map(|u| u.value).sum();
    let mut change = total_in - amount - fee;
    if change <= DUST_LIMIT {
        fee += change; // Too small to keep: it goes to the miners, as in Ego Desktop.
        change = 0;
    }

    let mut outpoints = Vec::new();
    for u in &chosen {
        let mut txid = hex::decode(&u.txid).map_err(|_| "A coin's txid isn't hex.")?;
        if txid.len() != 32 {
            return Err("A coin's txid isn't 32 bytes.".into());
        }
        txid.reverse();
        txid.extend_from_slice(&u.vout.to_le_bytes());
        outpoints.push(txid);
    }
    let mut outputs = Vec::new();
    for (value, script) in [(amount, &to_script), (change, &change_script)] {
        if value == 0 {
            continue;
        }
        outputs.extend_from_slice(&value.to_le_bytes());
        outputs.extend(varint(script.len() as u64));
        outputs.extend_from_slice(script);
    }
    let output_count = if change > 0 { 2 } else { 1 };

    let hash_prevouts = sha256d(&outpoints.concat());
    let hash_sequence = sha256d(&[0xffu8; 4].repeat(chosen.len()));
    let hash_outputs = sha256d(&outputs);
    let mut script_code = vec![0x76, 0xa9, 0x14];
    script_code.extend_from_slice(&pubkey_hash);
    script_code.extend_from_slice(&[0x88, 0xac]);

    let mut witnesses = Vec::new();
    for (u, outpoint) in chosen.iter().zip(&outpoints) {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&2u32.to_le_bytes());
        preimage.extend_from_slice(&hash_prevouts);
        preimage.extend_from_slice(&hash_sequence);
        preimage.extend_from_slice(outpoint);
        preimage.extend(varint(script_code.len() as u64));
        preimage.extend_from_slice(&script_code);
        preimage.extend_from_slice(&u.value.to_le_bytes());
        preimage.extend_from_slice(&[0xff; 4]);
        preimage.extend_from_slice(&hash_outputs);
        preimage.extend_from_slice(&0u32.to_le_bytes());
        preimage.extend_from_slice(&1u32.to_le_bytes());
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let sig: k256::ecdsa::Signature = key.sign_prehash(&sha256d(&preimage)).map_err(|e| e.to_string())?;
        let sig = sig.normalize_s().unwrap_or(sig);
        let mut der = sig.to_der().as_bytes().to_vec();
        der.push(0x01);
        witnesses.push([der, pubkey.as_bytes().to_vec()]);
    }

    let mut base = Vec::new(); // without witnesses, for the txid
    base.extend_from_slice(&2u32.to_le_bytes());
    base.extend(varint(chosen.len() as u64));
    for outpoint in &outpoints {
        base.extend_from_slice(outpoint);
        base.push(0x00);
        base.extend_from_slice(&[0xff; 4]);
    }
    base.extend(varint(output_count));
    base.extend_from_slice(&outputs);
    let locktime = 0u32.to_le_bytes();

    let mut raw = base[..4].to_vec();
    raw.extend_from_slice(&[0x00, 0x01]);
    raw.extend_from_slice(&base[4..]);
    for w in &witnesses {
        raw.extend(varint(w.len() as u64));
        for item in w {
            raw.extend(varint(item.len() as u64));
            raw.extend_from_slice(item);
        }
    }
    raw.extend_from_slice(&locktime);
    base.extend_from_slice(&locktime);

    let mut txid = sha256d(&base);
    txid.reverse();
    Ok(Signed { raw: hex::encode(raw), txid: hex::encode(txid), fee, change, inputs: chosen.len() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::Hash;
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};
    use bitcoin::{Amount, ScriptBuf, Transaction};

    fn coins() -> Vec<Utxo> {
        vec![
            Utxo { txid: "aa".repeat(32), vout: 1, value: 30_000 },
            Utxo { txid: "bb".repeat(32), vout: 0, value: 120_000 },
            Utxo { txid: "cc".repeat(32), vout: 7, value: 9_000 },
        ]
    }

    /// Every input's signature is checked with the bitcoin crate, independently
    /// of the code above.
    fn verify(raw: &str, key: &[u8; 32], utxos: &[Utxo]) -> Transaction {
        let tx: Transaction = deserialize(&hex::decode(raw).unwrap()).expect("parses as a Bitcoin transaction");
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(key).unwrap();
        let pk = bitcoin::PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&bitcoin::secp256k1::Secp256k1::new(), &sk));
        let wpkh = pk.wpubkey_hash().unwrap();
        let spk = ScriptBuf::new_p2wpkh(&wpkh);
        let mut cache = SighashCache::new(&tx);
        for (i, input) in tx.input.iter().enumerate() {
            let prev = utxos.iter().find(|u| u.txid == input.previous_output.txid.to_string() && u.vout == input.previous_output.vout).unwrap();
            let hash = cache.p2wpkh_signature_hash(i, &spk, Amount::from_sat(prev.value), EcdsaSighashType::All).unwrap();
            let w = input.witness.to_vec();
            assert_eq!(w.len(), 2);
            assert_eq!(*w[0].last().unwrap(), 0x01, "SIGHASH_ALL");
            let sig = bitcoin::secp256k1::ecdsa::Signature::from_der(&w[0][..w[0].len() - 1]).unwrap();
            let msg = bitcoin::secp256k1::Message::from_digest(hash.to_byte_array());
            secp.verify_ecdsa(&msg, &sig, &pk.inner).expect("signature verifies");
            assert_eq!(w[1], pk.to_bytes());
        }
        tx
    }

    #[test]
    fn a_bitcoin_send_verifies_and_pays_change_back() {
        let key = [9u8; 32];
        let to = "bc1qz5fsxpk6s5y92dcn73j84drhrrdh2rjlu2efqh";
        let signed = sign_p2wpkh(&key, BITCOIN, to, 100_000, &coins(), 2).unwrap();
        let tx = verify(&signed.raw, &key, &coins());
        assert_eq!(tx.input.len(), 1, "the 120,000 coin covers it");
        assert_eq!(tx.output.len(), 2);
        assert_eq!(tx.output[0].value.to_sat(), 100_000);
        assert_eq!(tx.output[0].script_pubkey.as_bytes(), output_script(to, BITCOIN).unwrap().as_slice());
        assert_eq!(signed.fee, estimated_vsize(1) * 2);
        assert_eq!(tx.output[1].value.to_sat(), 120_000 - 100_000 - signed.fee);
        assert_eq!(tx.compute_txid().to_string(), signed.txid);
    }

    #[test]
    fn several_coins_are_combined_when_needed() {
        let key = [9u8; 32];
        let signed = sign_p2wpkh(&key, BITCOIN, "bc1qz5fsxpk6s5y92dcn73j84drhrrdh2rjlu2efqh", 140_000, &coins(), 2).unwrap();
        let tx = verify(&signed.raw, &key, &coins());
        assert_eq!(tx.input.len(), 2);
        assert!(sign_p2wpkh(&key, BITCOIN, "bc1qz5fsxpk6s5y92dcn73j84drhrrdh2rjlu2efqh", 159_000, &coins(), 2).is_err(), "can't pay the fee");
    }

    #[test]
    fn dust_change_goes_to_the_fee() {
        let key = [9u8; 32];
        let fee = estimated_vsize(1) * 2;
        let signed = sign_p2wpkh(&key, BITCOIN, "bc1qz5fsxpk6s5y92dcn73j84drhrrdh2rjlu2efqh", 120_000 - fee - 300, &coins(), 2).unwrap();
        let tx = verify(&signed.raw, &key, &coins());
        assert_eq!(tx.output.len(), 1);
        assert_eq!(signed.fee, fee + 300);
    }

    #[test]
    fn every_standard_bitcoin_address_gets_the_script_the_bitcoin_crate_gives() {
        for address in [
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
            "bc1qz5fsxpk6s5y92dcn73j84drhrrdh2rjlu2efqh",
        ] {
            let ours = output_script(address, BITCOIN).unwrap_or_else(|e| panic!("{address}: {e}"));
            let theirs = bitcoin::Address::from_str(address).unwrap().assume_checked().script_pubkey();
            assert_eq!(ours, theirs.as_bytes(), "{address}");
        }
    }

    #[test]
    fn litecoin_addresses_are_read_and_other_networks_refused() {
        let ltc_p2pkh = crate::derive::base58check(0x30, &[1u8; 20]);
        let ltc_p2sh = crate::derive::base58check(0x32, &[2u8; 20]);
        assert_eq!(output_script(&ltc_p2pkh, LITECOIN).unwrap(), [&[0x76, 0xa9, 0x14][..], &[1u8; 20], &[0x88, 0xac]].concat());
        assert_eq!(output_script(&ltc_p2sh, LITECOIN).unwrap(), [&[0xa9, 0x14][..], &[2u8; 20], &[0x87]].concat());
        assert!(output_script("ltc1qr07zu594qf63xm7l7x6pu3a2v39m2z6hh5pp4t", LITECOIN).is_ok());
        for (address, net) in [
            ("ltc1qr07zu594qf63xm7l7x6pu3a2v39m2z6hh5pp4t".to_string(), BITCOIN),
            ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(), LITECOIN),
            ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5".to_string(), BITCOIN),
            ("0x13cCB7A7f8d13151382CD793992bA54aFF5b7A43".to_string(), BITCOIN),
            (ltc_p2pkh.clone(), BITCOIN),
            ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(), LITECOIN),
        ] {
            assert!(output_script(&address, net).is_err(), "{address} on {}", net.symbol);
        }
    }

    #[test]
    fn our_own_address_pays_to_our_key() {
        let seed = [7u8; 32];
        let ours = crate::derive::addr_btc_like(&seed, BITCOIN.key_path, "bc").unwrap();
        let key = crate::derive::secp_privkey(&seed, BITCOIN.key_path);
        let pubkey = SigningKey::from_slice(&key).unwrap().verifying_key().to_encoded_point(true);
        let expected = [&[0x00, 0x14][..], &crate::derive::hash160(pubkey.as_bytes())].concat();
        assert_eq!(output_script(&ours, BITCOIN).unwrap(), expected);
    }

    use std::str::FromStr;
}
