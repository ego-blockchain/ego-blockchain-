use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    constants::ED25519_BASEPOINT_POINT,
    traits::IsIdentity,
};
use sha2::{Sha512, Digest};

const SUITE: u8 = 0x04;

fn hash_to_try_and_increment(pk_bytes: &[u8; 32], alpha: &[u8]) -> Option<EdwardsPoint> {
    for ctr in 0u8..=255 {
        let hash = Sha512::new()
            .chain_update([SUITE, 0x01])
            .chain_update(pk_bytes)
            .chain_update(alpha)
            .chain_update([ctr, 0x00])
            .finalize();
        let mut candidate = [0u8; 32];
        candidate.copy_from_slice(&hash[..32]);
        if let Some(point) = CompressedEdwardsY(candidate).decompress() {
            let cleared = point.mul_by_cofactor();
            if !cleared.is_identity() {
                return Some(cleared);
            }
        }
    }
    None
}

fn challenge(
    pk: &EdwardsPoint,
    h:  &EdwardsPoint,
    g:  &EdwardsPoint,
    u:  &EdwardsPoint,
    v:  &EdwardsPoint,
) -> Scalar {
    let hash = Sha512::new()
        .chain_update([SUITE, 0x02])
        .chain_update(pk.compress().as_bytes())
        .chain_update(h.compress().as_bytes())
        .chain_update(g.compress().as_bytes())
        .chain_update(u.compress().as_bytes())
        .chain_update(v.compress().as_bytes())
        .finalize();
    let mut c = [0u8; 32];
    c[..16].copy_from_slice(&hash[..16]);
    Scalar::from_bytes_mod_order(c)
}

pub fn ecvrf_prove(seed_32: &[u8; 32], alpha: &[u8]) -> Option<[u8; 80]> {
    let sk_hash = Sha512::new().chain_update(seed_32).finalize();

    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&sk_hash[..32]);
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 127;
    scalar_bytes[31] |= 64;
    let secret = Scalar::from_bytes_mod_order(scalar_bytes);

    let pk_point = secret * ED25519_BASEPOINT_POINT;
    let pk_bytes: [u8; 32] = pk_point.compress().to_bytes();

    let h = hash_to_try_and_increment(&pk_bytes, alpha)?;

    let gamma = secret * h;

    let mut nonce_bytes = [0u8; 32];
    nonce_bytes.copy_from_slice(&sk_hash[32..64]);
    let k_raw = Sha512::new()
        .chain_update(&nonce_bytes)
        .chain_update(h.compress().as_bytes())
        .finalize();
    let mut k_wide = [0u8; 64];
    k_wide.copy_from_slice(&k_raw);
    let k = Scalar::from_bytes_mod_order_wide(&k_wide);

    let u = k * ED25519_BASEPOINT_POINT;
    let v = k * h;

    let c = challenge(&pk_point, &h, &gamma, &u, &v);
    let s = k - c * secret;

    let mut proof = [0u8; 80];
    proof[..32].copy_from_slice(gamma.compress().as_bytes());
    proof[32..48].copy_from_slice(&c.to_bytes()[..16]);
    proof[48..80].copy_from_slice(s.to_bytes().as_ref());
    Some(proof)
}

pub fn ecvrf_verify(pk_bytes: &[u8; 32], alpha: &[u8], proof: &[u8]) -> bool {
    if proof.len() < 80 { return false; }

    let mut gamma_b = [0u8; 32];
    let mut c16 = [0u8; 16];
    let mut s_b = [0u8; 32];
    gamma_b.copy_from_slice(&proof[..32]);
    c16.copy_from_slice(&proof[32..48]);
    s_b.copy_from_slice(&proof[48..80]);

    let gamma = match CompressedEdwardsY(gamma_b).decompress() {
        Some(p) => p,
        None => return false,
    };

    let s_opt: Option<Scalar> = Scalar::from_canonical_bytes(s_b).into();
    let s = match s_opt {
        Some(v) => v,
        None => {
            let mut s_wide = [0u8; 64];
            s_wide[..32].copy_from_slice(&s_b);
            Scalar::from_bytes_mod_order_wide(&s_wide)
        }
    };

    let mut c32 = [0u8; 32];
    c32[..16].copy_from_slice(&c16);
    let c = Scalar::from_bytes_mod_order(c32);

    let pk_point = match CompressedEdwardsY(*pk_bytes).decompress() {
        Some(p) => p,
        None => return false,
    };

    let u = s * ED25519_BASEPOINT_POINT + c * pk_point;

    let h = match hash_to_try_and_increment(pk_bytes, alpha) {
        Some(p) => p,
        None => return false,
    };

    let v = s * h + c * gamma;

    let c_prime = challenge(&pk_point, &h, &gamma, &u, &v);
    c_prime.to_bytes()[..16] == c16
}

pub fn ecvrf_proof_to_hash(proof: &[u8]) -> [u8; 32] {
    let gamma_bytes = if proof.len() >= 32 { &proof[..32] } else { return [0u8; 32] };
    let hash = Sha512::new()
        .chain_update([SUITE, 0x03])
        .chain_update(gamma_bytes)
        .finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash[..32]);
    out
}
