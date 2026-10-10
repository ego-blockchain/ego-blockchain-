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
    let signed = utxo::sign_p2wpkh(&key, net, &r.to, amount, &r.utxos, r.fee_rate)?;
    Ok(serde_json::json!({
        "raw": signed.raw,
        "hash": signed.txid,
        "from": crate::derive::addr_btc_like(seed, net.key_path, net.hrp)?,
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
    fn a_wrong_size_seed_is_an_error() {
        assert!(call(&[7u8; 16])["error"].is_string());
        unsafe { ego_wallet_string_free(std::ptr::null_mut()) };
    }
}
