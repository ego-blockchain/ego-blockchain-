//! C functions for the iPhone wallet. Results are JSON strings the caller
//! frees with `ego_wallet_string_free`; on failure the JSON is
//! `{"error": "..."}`. Declared in include/ego_wallet_core.h.

use std::ffi::{c_char, CString};

fn to_c(json: serde_json::Value) -> *mut c_char {
    CString::new(json.to_string()).map(CString::into_raw).unwrap_or(std::ptr::null_mut())
}

fn error(message: &str) -> *mut c_char {
    to_c(serde_json::json!({ "error": message }))
}

/// # Safety
/// `seed` must point to `seed_len` readable bytes.
unsafe fn seed_from<'a>(seed: *const u8, seed_len: usize) -> Option<&'a [u8]> {
    (!seed.is_null() && seed_len == 32).then(|| std::slice::from_raw_parts(seed, seed_len))
}

/// The addresses of every built-in chain for a 32-byte Ego seed, as a JSON
/// array of {chain, symbol, address, address_type, explorer_prefix}.
///
/// # Safety
/// `seed` must point to `seed_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn ego_wallet_addresses(seed: *const u8, seed_len: usize) -> *mut c_char {
    let Some(seed) = seed_from(seed, seed_len) else {
        return error("The seed must be 32 bytes.");
    };
    match crate::derive::external_addresses(seed) {
        Ok(list) => to_c(serde_json::to_value(list).unwrap_or_default()),
        Err(e) => error(&e),
    }
}

#[derive(serde::Deserialize)]
struct EvmRequest {
    chain: String,
    nonce: u64,
    /// The node's eth_gasPrice in wei, as a decimal string; Ego Desktop's 20% is added here.
    gas_price: String,
    to: String,
    /// What the person typed, like "0.25".
    amount: String,
    decimals: u32,
    /// The token contract for USDT, USDC and other tokens.
    contract: Option<String>,
}

fn sign_evm(seed: &[u8], request: &str) -> Result<serde_json::Value, String> {
    use crate::evm;
    let r: EvmRequest = serde_json::from_str(request).map_err(|e| format!("Bad request: {e}"))?;
    let path = evm::key_path(&r.chain).ok_or("That chain isn't supported.")?;
    let chain_id = evm::chain_id(&r.chain).ok_or("That chain isn't supported.")?;
    let node_price: u128 = r.gas_price.parse().map_err(|_| "Bad gas price.")?;
    let gas_price = evm::gas_price_with_buffer(node_price);
    let amount = evm::parse_amount(&r.amount, r.decimals)?;
    if amount == 0 {
        return Err("Enter an amount above zero.".into());
    }
    let recipient = evm::parse_address(&r.to)?;
    let (to, value, data, gas_limit) = match &r.contract {
        Some(contract) => (evm::parse_address(contract)?, 0, evm::erc20_transfer_calldata(&r.to, amount)?, evm::gas_limit(true)),
        None => (recipient, amount, Vec::new(), evm::gas_limit(false)),
    };
    let key = crate::derive::secp_privkey(seed, path);
    let signed = evm::sign_legacy(&key, chain_id, r.nonce, gas_price, gas_limit, &to, value, &data)?;
    Ok(serde_json::json!({
        "raw": signed.raw,
        "hash": signed.hash,
        "from": crate::derive::addr_evm(seed, path)?,
        "gas_price": gas_price.to_string(),
        "gas_limit": gas_limit.to_string(),
        "fee": (gas_price * gas_limit).to_string(),
        "amount_units": amount.to_string(),
    }))
}

/// Signs an Ethereum or BNB Chain transfer as Ego Desktop would. `request` is
/// JSON: {chain, nonce, gas_price, to, amount, decimals, contract?}. Returns
/// {raw, hash, from, gas_price, gas_limit, fee, amount_units}; amounts in wei
/// or token units as decimal strings. Nothing is sent.
///
/// # Safety
/// `seed` must point to `seed_len` readable bytes; `request` must be a
/// NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn ego_wallet_sign_evm(seed: *const u8, seed_len: usize, request: *const c_char) -> *mut c_char {
    let Some(seed) = seed_from(seed, seed_len) else {
        return error("The seed must be 32 bytes.");
    };
    if request.is_null() {
        return error("No request.");
    }
    let request = std::ffi::CStr::from_ptr(request).to_string_lossy();
    match sign_evm(seed, &request) {
        Ok(v) => to_c(v),
        Err(e) => error(&e),
    }
}

#[derive(serde::Deserialize)]
struct UtxoRequest {
    chain: String,
    to: String,
    amount: String,
    /// Satoshis per virtual byte.
    fee_rate: u64,
    utxos: Vec<crate::utxo::Utxo>,
}

fn sign_utxo(seed: &[u8], request: &str) -> Result<serde_json::Value, String> {
    use crate::utxo;
    let r: UtxoRequest = serde_json::from_str(request).map_err(|e| format!("Bad request: {e}"))?;
    let net = utxo::network(&r.chain).ok_or("That chain isn't supported.")?;
    if r.fee_rate == 0 || r.fee_rate > 1_000 {
        return Err("Bad fee rate.".into());
    }
    let amount = crate::evm::parse_amount(&r.amount, 8)?;
    let amount = u64::try_from(amount).map_err(|_| "That amount is too large.")?;
    let key = crate::derive::secp_privkey(seed, net.key_path);
    let (signed, from) = if net == utxo::DOGECOIN {
        (utxo::sign_doge(&key, &r.to, amount, &r.utxos)?, crate::derive::addr_doge(seed)?)
    } else {
        (utxo::sign_p2wpkh(&key, net, &r.to, amount, &r.utxos, r.fee_rate)?, crate::derive::addr_btc_like(seed, net.key_path, net.hrp)?)
    };
    Ok(serde_json::json!({
        "raw": signed.raw,
        "hash": signed.txid,
        "from": from,
        "fee": signed.fee.to_string(),
        "change": signed.change.to_string(),
        "inputs": signed.inputs,
        "amount_units": amount.to_string(),
    }))
}

/// Signs a Bitcoin or Litecoin transfer from the wallet's P2WPKH address.
/// `request` is JSON: {chain, to, amount, fee_rate, utxos: [{txid, vout, value}]}.
/// Returns {raw, hash, from, fee, change, inputs, amount_units}; sats as
/// decimal strings. Nothing is sent.
///
/// # Safety
/// `seed` must point to `seed_len` readable bytes; `request` must be a
/// NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn ego_wallet_sign_utxo(seed: *const u8, seed_len: usize, request: *const c_char) -> *mut c_char {
    let Some(seed) = seed_from(seed, seed_len) else {
        return error("The seed must be 32 bytes.");
    };
    if request.is_null() {
        return error("No request.");
    }
    let request = std::ffi::CStr::from_ptr(request).to_string_lossy();
    match sign_utxo(seed, &request) {
        Ok(v) => to_c(v),
        Err(e) => error(&e),
    }
}

#[derive(serde::Deserialize)]
struct TransferRequest {
    chain: String,
    to: String,
    amount: String,
    // Solana
    recent_blockhash: Option<String>,
    // XRP
    sequence: Option<u32>,
    last_ledger: Option<u32>,
    destination_tag: Option<u32>,
    // Tron
    block_number: Option<u64>,
    block_id: Option<String>,
    block_time: Option<u64>,
    now_ms: Option<u64>,
    // Cardano
    utxos: Option<Vec<crate::cardano::Utxo>>,
    ttl: Option<u64>,
}

fn sign_transfer(seed: &[u8], request: &str) -> Result<serde_json::Value, String> {
    use crate::{cardano, derive, solana, tron, xrp};
    let r: TransferRequest = serde_json::from_str(request).map_err(|e| format!("Bad request: {e}"))?;
    let missing = |what: &str| format!("Missing {what}.");
    let decimals = match r.chain.as_str() { "SOL" => 9, "XRP" | "TRX" | "ADA" => 6, _ => return Err("That chain isn't supported.".into()) };
    let units = crate::evm::parse_amount(&r.amount, decimals)?;
    let units = u64::try_from(units).map_err(|_| "That amount is too large.")?;
    if units == 0 {
        return Err("Enter an amount above zero.".into());
    }
    let (raw, hash, fee, from, change) = match r.chain.as_str() {
        "SOL" => {
            let s = solana::sign_transfer(&derive::ed25519_seed32(seed, solana::KEY_PATH), &r.to, units, r.recent_blockhash.as_deref().ok_or_else(|| missing("blockhash"))?)?;
            (s.raw, s.hash, solana::FEE, derive::addr_sol(seed)?, 0)
        }
        "XRP" => {
            let p = xrp::Payment {
                to: &r.to,
                drops: units,
                sequence: r.sequence.ok_or_else(|| missing("sequence"))?,
                last_ledger: r.last_ledger.ok_or_else(|| missing("ledger"))?,
                destination_tag: r.destination_tag,
            };
            let s = xrp::sign_payment(&derive::secp_privkey(seed, xrp::KEY_PATH), &p)?;
            (s.raw, s.hash, xrp::FEE_DROPS, derive::addr_xrp(seed)?, 0)
        }
        "TRX" => {
            let block = tron::BlockRef::from_block(
                r.block_number.ok_or_else(|| missing("block"))?,
                r.block_id.as_deref().ok_or_else(|| missing("block"))?,
                r.block_time.ok_or_else(|| missing("block"))?,
                r.now_ms.ok_or_else(|| missing("time"))?,
            )?;
            let s = tron::sign_transfer(&derive::secp_privkey(seed, tron::KEY_PATH), &r.to, units, &block)?;
            (s.raw, s.hash, 0, derive::addr_trx(seed)?, 0)
        }
        _ => {
            let own = derive::addr_ada(seed)?;
            let utxos = r.utxos.ok_or_else(|| missing("coins"))?;
            let s = cardano::sign_transfer(&derive::ed25519_seed32(seed, cardano::KEY_PATH), &own, &r.to, units, &utxos, r.ttl.ok_or_else(|| missing("ttl"))?)?;
            (s.raw, s.hash, s.fee, own, s.change)
        }
    };
    Ok(serde_json::json!({
        "raw": raw, "hash": hash, "from": from,
        "fee": fee.to_string(), "change": change.to_string(), "amount_units": units.to_string(),
    }))
}

/// Signs a Solana, XRP, Tron or Cardano transfer. `request` is JSON with
/// {chain, to, amount} and what that chain needs: Solana {recent_blockhash};
/// XRP {sequence, last_ledger, destination_tag?}; Tron {block_number,
/// block_id, block_time, now_ms}; Cardano {utxos: [{tx_hash, tx_index, value}],
/// ttl}. Returns {raw, hash, from, fee, change, amount_units}. Nothing is sent.
///
/// # Safety
/// `seed` must point to `seed_len` readable bytes; `request` must be a
/// NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn ego_wallet_sign_transfer(seed: *const u8, seed_len: usize, request: *const c_char) -> *mut c_char {
    let Some(seed) = seed_from(seed, seed_len) else {
        return error("The seed must be 32 bytes.");
    };
    if request.is_null() {
        return error("No request.");
    }
    let request = std::ffi::CStr::from_ptr(request).to_string_lossy();
    match sign_transfer(seed, &request) {
        Ok(v) => to_c(v),
        Err(e) => error(&e),
    }
}

/// Frees a string returned by this library.
///
/// # Safety
/// `s` must come from this library and not be freed twice.
#[no_mangle]
pub unsafe extern "C" fn ego_wallet_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    fn call(seed: &[u8]) -> serde_json::Value {
        unsafe {
            let raw = ego_wallet_addresses(seed.as_ptr(), seed.len());
            let value = serde_json::from_str(CStr::from_ptr(raw).to_str().unwrap()).unwrap();
            ego_wallet_string_free(raw);
            value
        }
    }

    #[test]
    fn addresses_come_back_as_json() {
        let list = call(&[7u8; 32]);
        assert_eq!(list.as_array().unwrap().len(), 9);
        assert_eq!(list[0]["symbol"], "BTC");
        assert_eq!(list[0]["address"], crate::derive::external_addresses(&[7u8; 32]).unwrap()[0].address);
    }

    #[test]
    fn evm_transfers_are_signed_from_the_seed() {
        let seed = [7u8; 32];
        let to = "0x00000000000000000000000000000000000000ab";
        let eth = sign_evm(&seed, &format!(r#"{{"chain":"ETH","nonce":3,"gas_price":"10","to":"{to}","amount":"0.5","decimals":18}}"#)).unwrap();
        assert_eq!(eth["from"], crate::derive::addr_evm(&seed, "ego:ethereum:0").unwrap());
        assert_eq!(eth["gas_price"], "12", "Ego Desktop adds 20%");
        assert_eq!(eth["gas_limit"], "21000");
        assert_eq!(eth["fee"], "252000");
        assert_eq!(eth["amount_units"], "500000000000000000");
        assert!(eth["raw"].as_str().unwrap().starts_with("0xf8"));

        let usdt = sign_evm(&seed, &format!(r#"{{"chain":"ETH","nonce":3,"gas_price":"10","to":"{to}","amount":"1","decimals":6,"contract":"0xdAC17F958D2ee523a2206206994597C13D831ec7"}}"#)).unwrap();
        assert_eq!(usdt["gas_limit"], "120000");
        assert_eq!(usdt["amount_units"], "1000000");
        assert!(usdt["raw"].as_str().unwrap().contains("a9059cbb"), "token transfers call transfer()");

        let bnb = sign_evm(&seed, &format!(r#"{{"chain":"BNB","nonce":0,"gas_price":"10","to":"{to}","amount":"1","decimals":18}}"#)).unwrap();
        assert_eq!(bnb["from"], crate::derive::addr_evm(&seed, "ego:bnb:0").unwrap(), "BNB has its own key");

        for bad in [
            format!(r#"{{"chain":"ETH","nonce":0,"gas_price":"10","to":"0x12","amount":"1","decimals":18}}"#),
            format!(r#"{{"chain":"ETH","nonce":0,"gas_price":"10","to":"{to}","amount":"0","decimals":18}}"#),
            format!(r#"{{"chain":"DOGE","nonce":0,"gas_price":"10","to":"{to}","amount":"1","decimals":8}}"#),
        ] {
            assert!(sign_evm(&seed, &bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn bitcoin_and_litecoin_transfers_are_signed_from_the_seed() {
        let seed = [7u8; 32];
        let utxos = r#"[{"txid":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","vout":0,"value":120000}]"#;
        let btc = sign_utxo(&seed, &format!(r#"{{"chain":"BTC","to":"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4","amount":"0.001","fee_rate":2,"utxos":{utxos}}}"#)).unwrap();
        assert_eq!(btc["from"], crate::derive::addr_btc_like(&seed, "ego:bitcoin:0", "bc").unwrap());
        assert_eq!(btc["amount_units"], "100000");
        assert_eq!(btc["fee"], (crate::utxo::estimated_vsize(1) * 2).to_string());
        assert_eq!(btc["inputs"], 1);
        let ltc = sign_utxo(&seed, &format!(r#"{{"chain":"LTC","to":"ltc1qr07zu594qf63xm7l7x6pu3a2v39m2z6hh5pp4t","amount":"0.001","fee_rate":2,"utxos":{utxos}}}"#)).unwrap();
        assert_eq!(ltc["from"], crate::derive::addr_btc_like(&seed, "ego:litecoin:0", "ltc").unwrap());
        assert!(sign_utxo(&seed, &format!(r#"{{"chain":"BTC","to":"ltc1qr07zu594qf63xm7l7x6pu3a2v39m2z6hh5pp4t","amount":"0.001","fee_rate":2,"utxos":{utxos}}}"#)).is_err());
        assert!(sign_utxo(&seed, &format!(r#"{{"chain":"BTC","to":"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4","amount":"0.000000001","fee_rate":2,"utxos":{utxos}}}"#)).is_err());
    }

    #[test]
    fn every_other_chain_signs_from_the_seed() {
        let seed = [7u8; 32];
        let sol_to = bs58::encode([8u8; 32]).into_string();
        let bh = bs58::encode([9u8; 32]).into_string();
        let sol = sign_transfer(&seed, &format!(r#"{{"chain":"SOL","to":"{sol_to}","amount":"0.25","recent_blockhash":"{bh}"}}"#)).unwrap();
        assert_eq!(sol["amount_units"], "250000000");
        assert_eq!(sol["from"], crate::derive::addr_sol(&seed).unwrap());
        let xrp = sign_transfer(&seed, r#"{"chain":"XRP","to":"rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh","amount":"2","sequence":3,"last_ledger":100,"destination_tag":42}"#).unwrap();
        assert_eq!(xrp["amount_units"], "2000000");
        assert_eq!(xrp["fee"], "12");
        let trx = sign_transfer(&seed, r#"{"chain":"TRX","to":"TY6pvrSqsNM4cR5vpqvoTW4DPCob4krzip","amount":"1.5","block_number":86976223,"block_id":"00000000052f26df25a3ef2c7e9b9e3a653218ed512e731e280370ebd5bea240","block_time":1791601473000,"now_ms":1791601474000}"#).unwrap();
        assert_eq!(trx["amount_units"], "1500000");
        let ada_to = crate::derive::addr_ada(&[8u8; 32]).unwrap();
        let ada = sign_transfer(&seed, &format!(r#"{{"chain":"ADA","to":"{ada_to}","amount":"2","ttl":5,"utxos":[{{"tx_hash":"{}","tx_index":0,"value":9000000}}]}}"#, "cc".repeat(32))).unwrap();
        assert_eq!(ada["from"], crate::derive::addr_ada(&seed).unwrap());
        assert!(sign_transfer(&seed, r#"{"chain":"XRP","to":"rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh","amount":"2"}"#).is_err(), "needs a sequence");
        assert!(sign_transfer(&seed, r#"{"chain":"XRP","to":"rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh","amount":"0.0000001","sequence":1,"last_ledger":2}"#).is_err());
        let doge_to = crate::derive::base58check(0x1e, &[4u8; 20]);
        let doge = sign_utxo(&seed, &format!(r#"{{"chain":"DOGE","to":"{doge_to}","amount":"5","fee_rate":1,"utxos":[{{"txid":"{}","vout":0,"value":2000000000}}]}}"#, "dd".repeat(32))).unwrap();
        assert_eq!(doge["from"], crate::derive::addr_doge(&seed).unwrap());
        assert_eq!(doge["fee"], "1000000");
    }

    #[test]
    fn a_wrong_size_seed_is_an_error() {
        assert!(call(&[7u8; 16])["error"].is_string());
        unsafe { ego_wallet_string_free(std::ptr::null_mut()) };
    }
}
