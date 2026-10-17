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

const POP_DST: &[u8] = b"EGO-BLS-POP-v1";
const SHARED_DST: &[u8] = b"EGO-BLS-SHARED-v1";

pub fn pop_sign(sk: &SecretKey) -> Vec<u8> {
    let pk = sk.sk_to_pk().to_bytes();
    sk.sign(&pk, POP_DST, &[]).to_bytes().to_vec()
}

pub fn pop_verify(pk_bytes: &[u8], sig_bytes: &[u8]) -> bool {
    let (Ok(pk), Ok(sig)) = (PublicKey::from_bytes(pk_bytes), Signature::from_bytes(sig_bytes)) else {
        return false;
    };
    if pk.validate().is_err() {
        return false;
    }
    sig.verify(true, &pk.to_bytes(), POP_DST, &[], &pk, true) == BLST_ERROR::BLST_SUCCESS
}

pub fn sign_shared(sk: &SecretKey, msg: &[u8]) -> Vec<u8> {
    sk.sign(msg, SHARED_DST, &[]).to_bytes().to_vec()
}

pub fn verify_shared(sig_bytes: &[u8], pk_bytes: &[u8], msg: &[u8]) -> bool {
    let (Ok(pk), Ok(sig)) = (PublicKey::from_bytes(pk_bytes), Signature::from_bytes(sig_bytes)) else {
        return false;
    };
    sig.verify(true, msg, SHARED_DST, &[], &pk, false) == BLST_ERROR::BLST_SUCCESS
}

pub fn aggregate_shared(sigs: &[Vec<u8>]) -> Option<Vec<u8>> {
    if sigs.is_empty() {
        return None;
    }
    let parsed: Vec<Signature> = sigs.iter().map(|b| Signature::from_bytes(b).ok()).collect::<Option<_>>()?;
    let refs: Vec<&Signature> = parsed.iter().collect();
    let agg = AggregateSignature::aggregate(&refs, true).ok()?;
    Some(agg.to_signature().to_bytes().to_vec())
}

pub fn verify_shared_aggregate(agg_sig: &[u8], pks: &[Vec<u8>], msg: &[u8]) -> bool {
    if pks.is_empty() {
        return false;
    }
    let Ok(sig) = Signature::from_bytes(agg_sig) else { return false };
    let Some(parsed) = pks.iter().map(|b| PublicKey::from_bytes(b).ok()).collect::<Option<Vec<_>>>() else {
        return false;
    };
    let refs: Vec<&PublicKey> = parsed.iter().collect();
    sig.fast_aggregate_verify(true, msg, SHARED_DST, &refs) == BLST_ERROR::BLST_SUCCESS
}

pub fn verify_unique(sig_bytes: &[u8], pk_bytes: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    if sig_bytes.len() != 96 {
        return None;
    }
    let sig = Signature::from_bytes(sig_bytes).ok()?;
    let pk = PublicKey::from_bytes(pk_bytes).ok()?;
    (sig.verify(true, msg, DST, &[], &pk, true) == BLST_ERROR::BLST_SUCCESS).then(|| sig.to_bytes().to_vec())
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
    fn possession_proofs_bind_the_key_and_aggregates_need_every_signer() {
        let sks: Vec<_> = (1u8..=4).map(|n| derive_bls_key(&seed(n))).collect();
        let pks: Vec<Vec<u8>> = sks.iter().map(bls_pubkey).collect();
        let pop = pop_sign(&sks[0]);
        assert!(pop_verify(&pks[0], &pop));
        assert!(!pop_verify(&pks[1], &pop));
        let msg = b"ego/checkin/v1:anchor";
        let sigs: Vec<Vec<u8>> = sks.iter().map(|sk| sign_shared(sk, msg)).collect();
        assert!(verify_shared(&sigs[2], &pks[2], msg));
        let agg = aggregate_shared(&sigs).unwrap();
        assert!(verify_shared_aggregate(&agg, &pks, msg));
        assert!(!verify_shared_aggregate(&agg, &pks[..3], msg));
        assert!(!verify_shared_aggregate(&agg, &pks, b"another message"));
        let vote_style = bls_sign(&sks[0], msg);
        assert!(!verify_shared(&vote_style, &pks[0], msg));
    }

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
