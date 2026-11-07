use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha512;
use unicode_normalization::UnicodeNormalization;

pub const ITERATIONS: u32 = 210_000;
const SALT_PREFIX: &[u8] = b"ego/wallet-passphrase/v1:";
const ENTROPY_FILE: &str = "recovery_words.bin";

pub fn pbkdf2_sha512_32(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mac = <Hmac<Sha512> as Mac>::new_from_slice(password).expect("HMAC accepts any key length");
    let mut first = mac.clone();
    first.update(salt);
    first.update(&1u32.to_be_bytes());
    let mut u = first.finalize().into_bytes();
    let mut t = u;
    for _ in 1..iterations {
        let mut next = mac.clone();
        next.update(&u);
        u = next.finalize().into_bytes();
        for (a, b) in t.iter_mut().zip(u.iter()) {
            *a ^= b;
        }
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&t[..32]);
    out
}

pub fn wallet_seed(entropy: &[u8; 32], extra: &str) -> [u8; 32] {
    if extra.is_empty() {
        return *entropy;
    }
    let password: String = extra.nfkd().collect();
    let mut salt = SALT_PREFIX.to_vec();
    salt.extend_from_slice(entropy);
    pbkdf2_sha512_32(password.as_bytes(), &salt, ITERATIONS)
}

fn seal_key(seed: &[u8]) -> [u8; 32] {
    use blake2::{Blake2s256, Digest};
    let mut h = Blake2s256::new();
    h.update(b"ego/phrase-entropy/v1");
    h.update(seed);
    h.finalize().into()
}

pub fn seal_entropy(seed: &[u8], entropy: &[u8; 32]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(&seal_key(seed)).map_err(|e| e.to_string())?;
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = cipher.encrypt(Nonce::from_slice(&nonce), entropy.as_slice()).map_err(|e| e.to_string())?;
    Ok([nonce.as_slice(), ct.as_slice()].concat())
}

pub fn open_entropy(seed: &[u8], sealed: &[u8]) -> Option<[u8; 32]> {
    if sealed.len() < 12 + 16 {
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(&seal_key(seed)).ok()?;
    let plain = cipher.decrypt(Nonce::from_slice(&sealed[..12]), &sealed[12..]).ok()?;
    plain.try_into().ok()
}

pub fn store_entropy(seed: &[u8], entropy: &[u8; 32]) -> Result<(), String> {
    let sealed = seal_entropy(seed, entropy)?;
    crate::utils::atomic_write(&crate::ledger::data_dir().join(ENTROPY_FILE), &sealed).map_err(|e| e.to_string())
}

pub fn phrase_entropy(seed: &[u8]) -> Option<[u8; 32]> {
    let sealed = std::fs::read(crate::ledger::data_dir().join(ENTROPY_FILE)).ok()?;
    open_entropy(seed, &sealed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    #[test]
    fn pbkdf2_matches_the_reference_implementation() {
        assert_eq!(pbkdf2_sha512_32(b"password", b"salt", 1), hex32("867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252"));
        assert_eq!(pbkdf2_sha512_32(b"password", b"salt", 2), hex32("e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53c"));
    }

    #[test]
    fn the_words_alone_give_a_different_wallet_than_words_and_password() {
        let entropy: [u8; 32] = core::array::from_fn(|i| i as u8);
        assert_eq!(wallet_seed(&entropy, ""), entropy, "no extra password keeps every existing wallet as it is");
        assert_eq!(wallet_seed(&entropy, "correct horse"), hex32("2ae0d5fc9e607d663521f7e937881b1191f821386b7d82cc99e39d6c52f86f7c"));
        assert_ne!(wallet_seed(&entropy, "correct horse"), wallet_seed(&entropy, "correct horse "), "every character counts");
    }

    #[test]
    fn accented_passwords_give_the_same_key_on_every_device() {
        let entropy = [0xffu8; 32];
        let composed = "p\u{e4}ssw\u{f6}rd";
        let decomposed = "pa\u{308}sswo\u{308}rd";
        let expected = hex32("4f37ba0a7afa6986ce298d71f64d6490c4dbade5bec7c6339196f2d010a0dfa8");
        assert_eq!(wallet_seed(&entropy, composed), expected);
        assert_eq!(wallet_seed(&entropy, decomposed), expected);
    }

    #[test]
    fn the_words_are_kept_sealed_under_the_wallet_key() {
        let entropy = [7u8; 32];
        let sealed = seal_entropy(&[1u8; 32], &entropy).unwrap();
        assert_eq!(open_entropy(&[1u8; 32], &sealed), Some(entropy));
        assert_eq!(open_entropy(&[2u8; 32], &sealed), None);
    }
}
