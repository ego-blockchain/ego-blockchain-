//! EGO-17 Typed Structured Data Signing
//! Ego equivalent of EIP-712. Enables off-chain signing of structured data
//! with human-readable wallet display and on-chain verification.

use blake2::{Blake2s256, Digest};

/// Magic prefix prepended to the final digest.
/// `EGO17` + `\x19\x01` ensures the digest cannot be confused with a raw
/// transaction hash or any other protocol message.
pub const EGO17_PREFIX: &[u8] = b"EGO17\x19\x01";

/// Canonical type string for the domain struct.
pub const DOMAIN_TYPE_STRING: &str =
    "EGoDomain(uint64 chainId,address verifyingContract,string version)";

/// Canonical type string for the EGO-20 Permit struct.
pub const PERMIT_TYPE_STRING: &str =
    "Permit(address owner,address spender,uint128 value,uint64 nonce,uint64 deadline)";

// ─── Core Hashing Helpers ─────────────────────────────────────────────────────

/// Compute a Blake2s-256 hash of the provided bytes.
#[inline]
fn blake2s(data: &[u8]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(data);
    h.finalize().into()
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Compute the type hash for a given type string.
///
/// The type hash is `blake2s(type_string_utf8_bytes)`. It is used as the first
/// field when hashing a struct of that type, binding the struct hash to the
/// type declaration.
///
/// # Example
/// ```
/// use ego_typed_signing::{type_hash, PERMIT_TYPE_STRING};
/// let h = type_hash(PERMIT_TYPE_STRING);
/// assert_eq!(h.len(), 32);
/// ```
pub fn type_hash(type_string: &str) -> [u8; 32] {
    blake2s(type_string.as_bytes())
}

/// Compute the domain separator hash.
///
/// The domain separator binds a signature to a specific chain and contract,
/// preventing cross-chain and cross-contract replay.
///
/// Encoding:
/// ```text
/// domain_type_hash = blake2s(DOMAIN_TYPE_STRING)
/// domain_separator = blake2s(
///     domain_type_hash         [32 bytes]
///     || chain_id (big-endian) [ 8 bytes]
///     || contract_address      [20 bytes]
///     || blake2s("1")          [32 bytes]  -- version string hash
/// )
/// ```
pub fn domain_separator(chain_id: u64, contract_address: [u8; 20]) -> [u8; 32] {
    let dt_hash = type_hash(DOMAIN_TYPE_STRING);
    let version_hash = blake2s(b"1");

    let mut buf = Vec::with_capacity(32 + 8 + 20 + 32);
    buf.extend_from_slice(&dt_hash);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&contract_address);
    buf.extend_from_slice(&version_hash);

    blake2s(&buf)
}

/// Compute the struct hash for a Permit.
///
/// Encoding:
/// ```text
/// permit_type_hash = blake2s(PERMIT_TYPE_STRING)
/// struct_hash = blake2s(
///     permit_type_hash          [32 bytes]
///     || owner                  [20 bytes]
///     || spender                [20 bytes]
///     || value (big-endian)     [16 bytes]
///     || nonce (big-endian)     [ 8 bytes]
///     || deadline (big-endian)  [ 8 bytes]
/// )
/// ```
pub fn permit_struct_hash(
    owner: [u8; 20],
    spender: [u8; 20],
    value: u128,
    nonce: u64,
    deadline: u64,
) -> [u8; 32] {
    let pt_hash = type_hash(PERMIT_TYPE_STRING);

    let mut buf = Vec::with_capacity(32 + 20 + 20 + 16 + 8 + 8);
    buf.extend_from_slice(&pt_hash);
    buf.extend_from_slice(&owner);
    buf.extend_from_slice(&spender);
    buf.extend_from_slice(&value.to_be_bytes());
    buf.extend_from_slice(&nonce.to_be_bytes());
    buf.extend_from_slice(&deadline.to_be_bytes());

    blake2s(&buf)
}

/// Compute the final EGO-17 digest for a Permit struct.
///
/// This is the 32-byte value that the user's Ed25519 private key signs.
///
/// ```text
/// digest = blake2s(EGO17_PREFIX || domain_sep || struct_hash)
/// ```
///
/// # Arguments
/// * `domain_sep` — computed by [`domain_separator`]
/// * `owner`, `spender` — 20-byte addresses
/// * `value` — token amount (u128, big-endian encoded)
/// * `nonce` — current nonce for `owner` from on-chain state
/// * `deadline` — block timestamp after which the permit is invalid
pub fn permit_digest(
    domain_sep: [u8; 32],
    owner: [u8; 20],
    spender: [u8; 20],
    value: u128,
    nonce: u64,
    deadline: u64,
) -> [u8; 32] {
    let s_hash = permit_struct_hash(owner, spender, value, nonce, deadline);

    let mut buf = Vec::with_capacity(EGO17_PREFIX.len() + 32 + 32);
    buf.extend_from_slice(EGO17_PREFIX);
    buf.extend_from_slice(&domain_sep);
    buf.extend_from_slice(&s_hash);

    blake2s(&buf)
}

/// Verify an Ed25519 signature over an EGO-17 digest.
///
/// Returns `true` if the signature was produced by the holder of
/// `expected_signer_pubkey` over `digest`.
///
/// # Production note
/// This stub returns `true` unconditionally. The real implementation should
/// call `ego_core::verify_ed25519(pubkey, digest, signature)` once ego-core
/// exposes a stable verify API.
///
/// # Arguments
/// * `digest` — 32-byte digest from [`permit_digest`] or equivalent
/// * `signature` — 64-byte Ed25519 signature
/// * `expected_signer_pubkey` — 32-byte Ed25519 public key of the expected signer
pub fn verify_signature(
    digest: [u8; 32],
    signature: &[u8; 64],
    expected_signer_pubkey: &[u8; 32],
) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};
    let Ok(vk) = VerifyingKey::from_bytes(expected_signer_pubkey) else { return false; };
    let sig = Signature::from_bytes(signature);
    vk.verify(&digest, &sig).is_ok()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_hash_is_deterministic() {
        let h1 = type_hash(PERMIT_TYPE_STRING);
        let h2 = type_hash(PERMIT_TYPE_STRING);
        assert_eq!(h1, h2);
    }

    #[test]
    fn domain_separator_varies_by_chain() {
        let addr = [0u8; 20];
        let sep1 = domain_separator(1, addr);
        let sep2 = domain_separator(2, addr);
        assert_ne!(sep1, sep2);
    }

    #[test]
    fn domain_separator_varies_by_contract() {
        let addr1 = [1u8; 20];
        let addr2 = [2u8; 20];
        let sep1 = domain_separator(1, addr1);
        let sep2 = domain_separator(1, addr2);
        assert_ne!(sep1, sep2);
    }

    #[test]
    fn permit_digest_varies_by_nonce() {
        let domain_sep = domain_separator(1, [0u8; 20]);
        let owner = [1u8; 20];
        let spender = [2u8; 20];
        let d1 = permit_digest(domain_sep, owner, spender, 1000, 0, 9999);
        let d2 = permit_digest(domain_sep, owner, spender, 1000, 1, 9999);
        assert_ne!(d1, d2);
    }

    #[test]
    fn permit_digest_varies_by_value() {
        let domain_sep = domain_separator(1, [0u8; 20]);
        let owner = [1u8; 20];
        let spender = [2u8; 20];
        let d1 = permit_digest(domain_sep, owner, spender, 100, 0, 9999);
        let d2 = permit_digest(domain_sep, owner, spender, 200, 0, 9999);
        assert_ne!(d1, d2);
    }

    #[test]
    fn permit_digest_is_32_bytes() {
        let domain_sep = domain_separator(1, [0u8; 20]);
        let digest = permit_digest(domain_sep, [0u8; 20], [0u8; 20], 0, 0, 0);
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn verify_signature_real_ed25519() {
        use ed25519_dalek::{SigningKey, Signer};
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let digest = [0xABu8; 32];
        let sig_obj = sk.sign(&digest);
        let sig_bytes: [u8; 64] = sig_obj.to_bytes();
        let pubkey: [u8; 32] = sk.verifying_key().to_bytes();
        assert!(verify_signature(digest, &sig_bytes, &pubkey));
        // Wrong pubkey → reject
        let wrong_sk = SigningKey::from_bytes(&[0x99u8; 32]);
        let wrong_pk: [u8; 32] = wrong_sk.verifying_key().to_bytes();
        assert!(!verify_signature(digest, &sig_bytes, &wrong_pk));
    }
}
