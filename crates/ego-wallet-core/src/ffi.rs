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
    fn a_wrong_size_seed_is_an_error() {
        assert!(call(&[7u8; 16])["error"].is_string());
        unsafe { ego_wallet_string_free(std::ptr::null_mut()) };
    }
}
