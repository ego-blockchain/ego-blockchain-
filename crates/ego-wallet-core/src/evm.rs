//! Ethereum and BNB Chain transfers: EIP-155 legacy transactions, built and
//! signed as Ego Desktop's send_evm_tx does. Fetching the nonce and gas price
//! and broadcasting stay with the caller.

use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};

/// The seed path for each EVM chain's key. Tokens use their chain's key.
pub fn key_path(chain: &str) -> Option<&'static str> {
    match chain {
        "ETH" => Some("ego:ethereum:0"),
        "BNB" => Some("ego:bnb:0"),
        "MATIC" => Some("ego:polygon:0"),
        "AVAX" => Some("ego:avalanche:0"),
        "ARB" => Some("ego:arbitrum:0"),
        "OP" => Some("ego:optimism:0"),
        _ => None,
    }
}

pub fn chain_id(chain: &str) -> Option<u64> {
    match chain {
        "ETH" => Some(1),
        "BNB" => Some(56),
        "MATIC" => Some(137),
        "AVAX" => Some(43114),
        "ARB" => Some(42161),
        "OP" => Some(10),
        _ => None,
    }
}

/// Gas Ego Desktop allows: a plain transfer, or a token transfer.
pub fn gas_limit(is_token: bool) -> u128 {
    if is_token { 120_000 } else { 21_000 }
}

/// Ego Desktop pays the node's gas price plus 20%.
pub fn gas_price_with_buffer(node_gas_price: u128) -> u128 {
    node_gas_price * 12 / 10
}

fn uint_to_be_bytes_nonempty(n: u128) -> Vec<u8> {
    if n == 0 {
        return vec![];
    }
    let b = n.to_be_bytes();
    let start = b.iter().position(|&x| x != 0).unwrap_or(15);
    b[start..].to_vec()
}

pub fn rlp_item(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 {
        return data.to_vec();
    }
    let mut out = Vec::new();
    if data.len() < 56 {
        out.push(0x80 + data.len() as u8);
    } else {
        let len_enc = uint_to_be_bytes_nonempty(data.len() as u128);
        out.push(0xb7 + len_enc.len() as u8);
        out.extend(len_enc);
    }
    out.extend_from_slice(data);
    out
}

pub fn rlp_uint(n: u128) -> Vec<u8> {
    rlp_item(&uint_to_be_bytes_nonempty(n))
}

pub fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.iter().flat_map(|i| i.iter().copied()).collect();
    let mut out = Vec::new();
    if payload.len() < 56 {
        out.push(0xc0 + payload.len() as u8);
    } else {
        let len_enc = uint_to_be_bytes_nonempty(payload.len() as u128);
        out.push(0xf7 + len_enc.len() as u8);
        out.extend(len_enc);
    }
    out.extend(payload);
    out
}

/// keccak256("transfer(address,uint256)")[..4] followed by the arguments.
pub fn erc20_transfer_calldata(to: &str, amount: u128) -> Result<Vec<u8>, String> {
    let addr_bytes = parse_address(to)?;
    let mut data = vec![0xa9u8, 0x05, 0x9c, 0xbb];
    data.extend(std::iter::repeat(0u8).take(12));
    data.extend_from_slice(&addr_bytes);
    data.extend_from_slice(&[0u8; 16]);
    data.extend_from_slice(&amount.to_be_bytes());
    Ok(data)
}

/// A 0x-prefixed 20-byte address. Ego Desktop accepted any hex; a typo that
/// still decodes would send coins nowhere, so the length is checked here.
pub fn parse_address(address: &str) -> Result<[u8; 20], String> {
    let hex_part = address.trim().strip_prefix("0x").ok_or("An address starts with 0x.")?;
    let bytes = hex::decode(hex_part).map_err(|_| "That address isn't hex.".to_string())?;
    bytes.try_into().map_err(|_| "An address is 40 hex characters after 0x.".to_string())
}

pub struct Signed {
    /// 0x-prefixed raw transaction for eth_sendRawTransaction.
    pub raw: String,
    /// 0x-prefixed transaction hash.
    pub hash: String,
}

/// Signs an EIP-155 legacy transaction.
#[allow(clippy::too_many_arguments)]
pub fn sign_legacy(
    privkey: &[u8; 32],
    chain_id: u64,
    nonce: u64,
    gas_price: u128,
    gas_limit: u128,
    to: &[u8; 20],
    value: u128,
    data: &[u8],
) -> Result<Signed, String> {
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    let signing_key = SigningKey::from_slice(privkey).map_err(|e| e.to_string())?;
    let pre_tx = rlp_list(&[
        rlp_uint(nonce as u128),
        rlp_uint(gas_price),
        rlp_uint(gas_limit),
        rlp_item(to),
        rlp_uint(value),
        rlp_item(data),
        rlp_uint(chain_id as u128),
        rlp_item(&[]),
        rlp_item(&[]),
    ]);
    let hash = Keccak256::digest(&pre_tx);
    let (sig, recid) = signing_key.sign_prehash_recoverable(hash.as_ref()).map_err(|e| e.to_string())?;
    let v = chain_id * 2 + 35 + recid.to_byte() as u64;
    let signed = rlp_list(&[
        rlp_uint(nonce as u128),
        rlp_uint(gas_price),
        rlp_uint(gas_limit),
        rlp_item(to),
        rlp_uint(value),
        rlp_item(data),
        rlp_uint(v as u128),
        rlp_item(strip_leading_zeros(sig.r().to_bytes().as_slice())),
        rlp_item(strip_leading_zeros(sig.s().to_bytes().as_slice())),
    ]);
    Ok(Signed {
        raw: format!("0x{}", hex::encode(&signed)),
        hash: format!("0x{}", hex::encode(Keccak256::digest(&signed))),
    })
}

/// RLP integers have no leading zero bytes. Ego Desktop encoded r and s as
/// fixed 32 bytes, which nodes reject in the 1 in 256 signatures where the
/// top byte is zero.
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

/// A decimal amount like "1.5" in units with `decimals` places, without
/// floating point. More decimals than the asset has is an error rather than
/// silently dropped.
pub fn parse_amount(text: &str, decimals: u32) -> Result<u128, String> {
    let s = text.trim();
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if (whole.is_empty() && frac.is_empty()) || !whole.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) {
        return Err("Enter an amount like 0.25.".into());
    }
    if frac.len() > decimals as usize {
        return Err(format!("This coin has at most {decimals} decimals."));
    }
    let scale = 10u128.checked_pow(decimals).ok_or("Too many decimals.")?;
    let whole: u128 = if whole.is_empty() { 0 } else { whole.parse().map_err(|_| "That amount is too large.")? };
    let frac: u128 = if frac.is_empty() { 0 } else { format!("{frac:0<width$}", width = decimals as usize).parse().map_err(|_| "Bad amount.")? };
    whole.checked_mul(scale).and_then(|w| w.checked_add(frac)).ok_or_else(|| "That amount is too large.".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example in EIP-155 itself.
    #[test]
    fn signs_the_eip155_example_exactly() {
        let key = [0x46u8; 32];
        let to = [0x35u8; 20];
        let signed = sign_legacy(&key, 1, 9, 20_000_000_000, 21_000, &to, 1_000_000_000_000_000_000, &[]).unwrap();
        assert_eq!(
            signed.raw,
            "0xf86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
        );
        assert_eq!(signed.hash, "0x33469b22e9f636356c4160a87eb19df52b7412e8eac32a4a55ffe88ea8350788");
    }

    #[test]
    fn token_transfers_call_transfer_with_padded_arguments() {
        let data = erc20_transfer_calldata("0x00000000000000000000000000000000000000ab", 1_000_000).unwrap();
        assert_eq!(
            hex::encode(&data),
            "a9059cbb00000000000000000000000000000000000000000000000000000000000000ab00000000000000000000000000000000000000000000000000000000000f4240"
        );
        assert!(erc20_transfer_calldata("0x1234", 1).is_err(), "a short address would send to nobody");
    }

    #[test]
    fn amounts_are_exact_and_refuse_extra_decimals() {
        assert_eq!(parse_amount("1.5", 18), Ok(1_500_000_000_000_000_000));
        assert_eq!(parse_amount("0.000001", 6), Ok(1));
        assert_eq!(parse_amount(".5", 6), Ok(500_000));
        assert_eq!(parse_amount("2", 8), Ok(200_000_000));
        assert!(parse_amount("0.0000001", 6).is_err());
        assert!(parse_amount("", 6).is_err());
        assert!(parse_amount("1,5", 6).is_err());
        assert!(parse_amount("-1", 6).is_err());
    }

    #[test]
    fn signature_numbers_drop_leading_zero_bytes() {
        assert_eq!(strip_leading_zeros(&[0, 0, 1, 2]), &[1, 2]);
        assert_eq!(strip_leading_zeros(&[3, 0]), &[3, 0]);
        assert_eq!(rlp_item(strip_leading_zeros(&[0, 0x7f])), vec![0x7f]);
    }
}
