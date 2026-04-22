use blst::min_pk::{AggregateSignature, PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;

const DST: &[u8] = b"EGO-BFT-VOTE-BLS12381-v1";

pub fn derive_bls_key(seed_bytes: &[u8]) -> SecretKey {
    SecretKey::key_gen(seed_bytes, &[]).expect("BLS key derivation failed")
}

pub fn bls_sign(sk: &SecretKey, msg: &[u8]) -> Vec<u8> {
    sk.sign(msg, DST, &[]).to_bytes().to_vec()
}

pub fn bls_pubkey(sk: &SecretKey) -> Vec<u8> {
    sk.sk_to_pk().to_bytes().to_vec()
}

pub fn aggregate_signatures(sig_bytes_list: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    let sigs: Vec<Signature> = sig_bytes_list
        .iter()
        .map(|b| Signature::from_bytes(b).map_err(|_| "bad sig".to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let sig_refs: Vec<&Signature> = sigs.iter().collect();
    let agg = AggregateSignature::aggregate(&sig_refs, true)
        .map_err(|e| format!("{:?}", e))?;
    Ok(agg.to_signature().to_bytes().to_vec())
}

pub fn verify_aggregate(agg_sig_bytes: &[u8], pubkey_bytes_list: &[Vec<u8>], msg: &[u8]) -> bool {
    let agg_sig = match Signature::from_bytes(agg_sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let pks: Vec<PublicKey> = pubkey_bytes_list
        .iter()
        .filter_map(|b| PublicKey::from_bytes(b).ok())
        .collect();
    if pks.is_empty() {
        return false;
    }
    let pk_refs: Vec<&PublicKey> = pks.iter().collect();
    let result = agg_sig.fast_aggregate_verify(true, msg, DST, &pk_refs);
    result == BLST_ERROR::BLST_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(n: u8) -> Vec<u8> { vec![n; 32] }

    #[test]
    fn single_sign_verify() {
        let sk = derive_bls_key(&seed(1));
        let msg = b"test-block-hash-00000000000000";
        let sig = bls_sign(&sk, msg);
        let pk  = bls_pubkey(&sk);
        assert!(verify_aggregate(&sig, &[pk], msg));
    }

    #[test]
    fn wrong_key_fails() {
        let sk1 = derive_bls_key(&seed(1));
        let sk2 = derive_bls_key(&seed(2));
        let msg = b"block";
        let sig = bls_sign(&sk1, msg);
        assert!(!verify_aggregate(&sig, &[bls_pubkey(&sk2)], msg));
    }

    #[test]
    fn aggregate_three_validators() {
        let msg = b"quorum-block-hash-0000000000000";
        let sks: Vec<_> = (1u8..=3).map(|n| derive_bls_key(&seed(n))).collect();
        let sigs: Vec<_> = sks.iter().map(|sk| bls_sign(sk, msg)).collect();
        let pks:  Vec<_> = sks.iter().map(|sk| bls_pubkey(sk)).collect();
        let agg = aggregate_signatures(&sigs).unwrap();
        assert!(verify_aggregate(&agg, &pks, msg));
    }
}
