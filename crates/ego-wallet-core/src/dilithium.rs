//! The wallet's ML-DSA-44 (Dilithium) key, made from the 32-byte Ego seed
//! exactly as Ego Desktop makes it (ego-core `derive_dilithium_keypair`), so
//! the same 24 words pin the same Dilithium key on either side.

use blake2::{Blake2s256, Digest};
use ml_dsa::{KeyGen, KeyPair, MlDsa44};

const WALLET_TAG: &[u8] = b"ego/ml-dsa-44/wallet/v1";

fn keypair(seed: &[u8]) -> Result<KeyPair<MlDsa44>, String> {
    if seed.len() != 32 {
        return Err("The seed must be 32 bytes.".into());
    }
    let mut h = Blake2s256::new();
    h.update(WALLET_TAG);
    h.update(seed);
    let xi: [u8; 32] = h.finalize().into();
    Ok(MlDsa44::key_gen_internal(&xi.into()))
}

/// The encoded ML-DSA-44 public key (1312 bytes).
pub fn public_key(seed: &[u8]) -> Result<Vec<u8>, String> {
    Ok(keypair(seed)?.verifying_key().encode().to_vec())
}

/// A deterministic ML-DSA-44 signature (2420 bytes) with an empty context,
/// as Ego Desktop signs transactions.
pub fn sign(seed: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let sig = keypair(seed)?
        .signing_key()
        .sign_deterministic(message, &[])
        .map_err(|_| "Dilithium signing failed.".to_string())?;
    Ok(sig.encode().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::signature::Verifier;
    use ml_dsa::{EncodedSignature, EncodedVerifyingKey, Signature, VerifyingKey};

    #[test]
    fn signatures_verify_and_repeat() {
        let seed = [7u8; 32];
        let pk = public_key(&seed).unwrap();
        let sig = sign(&seed, b"ego/tx/v3:hello").unwrap();
        assert_eq!((pk.len(), sig.len()), (1312, 2420));
        assert_eq!(sig, sign(&seed, b"ego/tx/v3:hello").unwrap());
        let vk = VerifyingKey::<MlDsa44>::decode(&EncodedVerifyingKey::<MlDsa44>::try_from(pk.as_slice()).unwrap());
        let s = Signature::<MlDsa44>::decode(&EncodedSignature::<MlDsa44>::try_from(sig.as_slice()).unwrap()).unwrap();
        assert!(vk.verify(b"ego/tx/v3:hello", &s).is_ok());
        assert!(vk.verify(b"ego/tx/v3:other", &s).is_err());
        assert_ne!(pk, public_key(&[8u8; 32]).unwrap());
        assert!(public_key(&[0u8; 31]).is_err());
    }
}
