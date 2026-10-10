//! Solana transfers: a SystemProgram transfer in a legacy message, built and
//! signed as Ego Desktop's send_sol_tx does. The caller supplies a recent
//! blockhash and broadcasts.

use ed25519_dalek::{Signer, SigningKey};

pub const KEY_PATH: &str = "ego:solana:0";
/// Lamports per signature; a transfer has one.
pub const FEE: u64 = 5_000;

fn compact_u16(n: u16) -> Vec<u8> {
    if n < 128 {
        return vec![n as u8];
    }
    vec![(n & 0x7f) as u8 | 0x80, ((n >> 7) & 0x7f) as u8]
}

pub fn parse_address(address: &str) -> Result<[u8; 32], String> {
    let bytes = bs58::decode(address.trim()).into_vec().map_err(|_| "That isn't a Solana address.".to_string())?;
    bytes.try_into().map_err(|_| "That isn't a Solana address.".to_string())
}

pub struct Signed {
    /// Base64 transaction for sendTransaction.
    pub raw: String,
    /// The signature, base58: Solana's transaction id.
    pub hash: String,
}

pub fn sign_transfer(seed32: &[u8; 32], to: &str, lamports: u64, recent_blockhash: &str) -> Result<Signed, String> {
    let key = SigningKey::from_bytes(seed32);
    let from = key.verifying_key().to_bytes();
    let to = parse_address(to)?;
    if to == from {
        return Err("That's your own address.".into());
    }
    let blockhash: [u8; 32] = bs58::decode(recent_blockhash)
        .into_vec()
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("Bad blockhash.")?;
    let mut msg = vec![1u8, 0, 1];
    msg.extend(compact_u16(3));
    msg.extend_from_slice(&from);
    msg.extend_from_slice(&to);
    msg.extend_from_slice(&[0u8; 32]);
    msg.extend_from_slice(&blockhash);
    msg.extend(compact_u16(1));
    msg.push(2);
    msg.extend(compact_u16(2));
    msg.extend_from_slice(&[0, 1]);
    let mut data = vec![2u8, 0, 0, 0];
    data.extend_from_slice(&lamports.to_le_bytes());
    msg.extend(compact_u16(data.len() as u16));
    msg.extend(data);
    let sig = key.sign(&msg).to_bytes();
    let mut tx = compact_u16(1);
    tx.extend_from_slice(&sig);
    tx.extend(msg);
    Ok(Signed { raw: base64_encode(&tx), hash: bs58::encode(sig).into_string() })
}

pub(crate) fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    fn base64_decode(s: &str) -> Vec<u8> {
        let t = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut bits = 0u32;
        let mut n = 0;
        let mut out = Vec::new();
        for c in s.bytes().filter(|&c| c != b'=') {
            bits = bits << 6 | t.iter().position(|&x| x == c).unwrap() as u32;
            n += 6;
            if n >= 8 {
                n -= 8;
                out.push((bits >> n) as u8);
            }
        }
        out
    }

    #[test]
    fn base64_matches_the_standard() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn a_transfer_is_signed_by_the_sender_and_moves_the_lamports() {
        let seed = [3u8; 32];
        let to = bs58::encode([8u8; 32]).into_string();
        let blockhash = bs58::encode([9u8; 32]).into_string();
        let signed = sign_transfer(&seed, &to, 1_500_000, &blockhash).unwrap();
        let tx = base64_decode(&signed.raw);
        assert_eq!(tx[0], 1, "one signature");
        let sig = Signature::from_bytes(tx[1..65].try_into().unwrap());
        let msg = &tx[65..];
        let from = SigningKey::from_bytes(&seed).verifying_key();
        from.verify(msg, &sig).expect("signed by the sender");
        assert_eq!(&msg[..3], &[1, 0, 1], "one signer, the system program read-only");
        assert_eq!(&msg[4..36], from.as_bytes());
        assert_eq!(&msg[36..68], &[8u8; 32]);
        assert_eq!(&msg[100..132], &[9u8; 32], "blockhash");
        assert_eq!(&msg[msg.len() - 8..], &1_500_000u64.to_le_bytes());
        assert_eq!(signed.hash, bs58::encode(&tx[1..65]).into_string());
        assert!(sign_transfer(&seed, "not-an-address", 1, &blockhash).is_err());
        let own = bs58::encode(from.as_bytes()).into_string();
        assert!(sign_transfer(&seed, &own, 1, &blockhash).is_err());
    }
}
