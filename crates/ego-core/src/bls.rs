use blst::min_pk::{PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;
use thiserror::Error;

pub const BLS_DST: &[u8] = b"ego/bls/validator/v1";

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BlsError {
    #[error("BLS signature invalid: {0}")]
    InvalidSignature(String),
    #[error("BLS public key invalid: {0}")]
    InvalidPublicKey(String),
    #[error("BLS secret key invalid: {0}")]
    InvalidSecretKey(String),
    #[error("BLS aggregation failed: {0}")]
    AggregationFailed(String),
    #[error("BLS verification failed")]
    VerificationFailed,
    #[error("Empty inputs: {0}")]
    EmptyInputs(String),
    #[error("Input length mismatch: {0}")]
    LengthMismatch(String),
}

fn blst_err_to_string(e: BLST_ERROR) -> String {
    format!("{:?}", e)
}

pub struct BlsKeypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl BlsKeypair {

    pub fn generate() -> Self {
        use rand::RngCore;
        let mut ikm = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ikm);
        Self::from_seed(&ikm)
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {

        let secret = SecretKey::key_gen(seed, &[]).expect("BLS key_gen failed with valid 32-byte IKM");
        let public = secret.sk_to_pk();
        Self { secret, public }
    }

    pub fn public_key_bytes(&self) -> [u8; 48] {
        self.public.compress()
    }

    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    pub fn sign(&self, msg: &[u8]) -> BlsSignature {
        let sig = self.secret.sign(msg, BLS_DST, &[]);
        BlsSignature(sig)
    }
}

pub struct BlsSignature(pub Signature);

impl BlsSignature {

    pub fn to_bytes(&self) -> [u8; 96] {
        self.0.compress()
    }

    pub fn from_bytes(b: &[u8; 96]) -> Result<Self, BlsError> {
        Signature::uncompress(b)
            .map(BlsSignature)
            .map_err(|e| BlsError::InvalidSignature(blst_err_to_string(e)))
    }

    pub fn verify(&self, pubkey: &PublicKey, msg: &[u8]) -> bool {
        let err = self.0.verify(true, msg, BLS_DST, &[], pubkey, true);
        err == BLST_ERROR::BLST_SUCCESS
    }
}

pub struct BlsAggregateSignature;

impl BlsAggregateSignature {

    pub fn aggregate(sigs: &[BlsSignature]) -> Result<BlsSignature, BlsError> {
        if sigs.is_empty() {
            return Err(BlsError::EmptyInputs("aggregate requires at least one signature".into()));
        }
        let refs: Vec<&Signature> = sigs.iter().map(|s| &s.0).collect();
        let agg = blst::min_pk::AggregateSignature::aggregate(&refs, true)
            .map_err(|e| BlsError::AggregationFailed(blst_err_to_string(e)))?;
        Ok(BlsSignature(agg.to_signature()))
    }

    pub fn verify_aggregate(
        agg_sig: &BlsSignature,
        pubkeys: &[PublicKey],
        msg: &[u8],
    ) -> bool {
        if pubkeys.is_empty() {
            return false;
        }

        let pk_refs: Vec<&PublicKey> = pubkeys.iter().collect();
        let agg_pk = match blst::min_pk::AggregatePublicKey::aggregate(&pk_refs, true) {
            Ok(apk) => apk.to_public_key(),
            Err(_) => return false,
        };
        let err = agg_sig.0.verify(true, msg, BLS_DST, &[], &agg_pk, true);
        err == BLST_ERROR::BLST_SUCCESS
    }

    pub fn verify_batch(
        sigs: &[BlsSignature],
        pubkeys: &[PublicKey],
        msgs: &[&[u8]],
    ) -> bool {
        if sigs.is_empty() || pubkeys.len() != sigs.len() || msgs.len() != sigs.len() {
            return false;
        }

        sigs.iter()
            .zip(pubkeys.iter())
            .zip(msgs.iter())
            .all(|((sig, pk), msg)| {
                let err = sig.0.verify(true, msg, BLS_DST, &[], pk, true);
                err == BLST_ERROR::BLST_SUCCESS
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(n: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = n;
        s[1] = 0xde;
        s[2] = 0xad;
        s
    }

    #[test]
    fn test_keypair_generation_deterministic() {
        let kp1 = BlsKeypair::from_seed(&seed(1));
        let kp2 = BlsKeypair::from_seed(&seed(1));
        assert_eq!(kp1.public_key_bytes(), kp2.public_key_bytes());
        assert_eq!(kp1.secret_key_bytes(), kp2.secret_key_bytes());
    }

    #[test]
    fn test_keypair_different_seeds_differ() {
        let kp1 = BlsKeypair::from_seed(&seed(1));
        let kp2 = BlsKeypair::from_seed(&seed(2));
        assert_ne!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn test_keypair_random_generates() {
        let kp = BlsKeypair::generate();

        assert_ne!(kp.public_key_bytes(), [0u8; 48]);
    }

    #[test]
    fn test_sign_and_verify_single() {
        let kp = BlsKeypair::from_seed(&seed(10));
        let msg = b"hello ego-blockchain";
        let sig = kp.sign(msg);
        assert!(sig.verify(&kp.public, msg), "single-sig verify must pass");
    }

    #[test]
    fn test_verify_rejects_wrong_message() {
        let kp = BlsKeypair::from_seed(&seed(11));
        let sig = kp.sign(b"correct");
        assert!(!sig.verify(&kp.public, b"wrong"), "must reject wrong message");
    }

    #[test]
    fn test_verify_rejects_wrong_key() {
        let kp1 = BlsKeypair::from_seed(&seed(12));
        let kp2 = BlsKeypair::from_seed(&seed(13));
        let sig = kp1.sign(b"message");
        assert!(!sig.verify(&kp2.public, b"message"), "must reject wrong pubkey");
    }

    #[test]
    fn test_signature_round_trip_bytes() {
        let kp = BlsKeypair::from_seed(&seed(14));
        let sig = kp.sign(b"round trip");
        let bytes = sig.to_bytes();
        let recovered = BlsSignature::from_bytes(&bytes).expect("must deserialize");
        assert!(recovered.verify(&kp.public, b"round trip"));
    }

    #[test]
    fn test_invalid_signature_bytes_rejected() {
        let bad = [0xffu8; 96];

        let result = BlsSignature::from_bytes(&bad);
        assert!(result.is_err(), "all-0xFF is not a valid BLS signature");
    }

    #[test]
    fn test_aggregate_100_signatures_same_message() {
        let msg = b"ego/bls/quorum/test";
        let n = 100usize;

        let keypairs: Vec<BlsKeypair> = (0..n as u8).map(|i| BlsKeypair::from_seed(&seed(i))).collect();
        let sigs: Vec<BlsSignature> = keypairs.iter().map(|kp| kp.sign(msg)).collect();
        let pubkeys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public.clone()).collect();

        let agg = BlsAggregateSignature::aggregate(&sigs).expect("aggregation must succeed");
        assert!(
            BlsAggregateSignature::verify_aggregate(&agg, &pubkeys, msg),
            "100-validator aggregate must verify"
        );

        let agg_bytes = agg.to_bytes();
        assert_eq!(agg_bytes.len(), 96);
        println!(
            "[bls] 100 validators: agg_sig={}B  (vs Dilithium: {}B)",
            96,
            100 * 2420
        );
    }

    #[test]
    fn test_aggregate_empty_returns_error() {
        let result = BlsAggregateSignature::aggregate(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_aggregate_rejects_wrong_message() {
        let n = 5usize;
        let msg = b"correct message";
        let keypairs: Vec<BlsKeypair> = (0..n as u8).map(|i| BlsKeypair::from_seed(&seed(i + 50))).collect();
        let sigs: Vec<BlsSignature> = keypairs.iter().map(|kp| kp.sign(msg)).collect();
        let pubkeys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public.clone()).collect();

        let agg = BlsAggregateSignature::aggregate(&sigs).unwrap();
        assert!(!BlsAggregateSignature::verify_aggregate(&agg, &pubkeys, b"wrong message"));
    }

    #[test]
    fn test_verify_batch_different_messages() {
        let n = 5usize;
        let keypairs: Vec<BlsKeypair> = (0..n as u8).map(|i| BlsKeypair::from_seed(&seed(i + 100))).collect();
        let raw_msgs: Vec<Vec<u8>> = (0..n).map(|i| format!("msg-{}", i).into_bytes()).collect();
        let msgs: Vec<&[u8]> = raw_msgs.iter().map(|m| m.as_slice()).collect();
        let sigs: Vec<BlsSignature> = keypairs.iter().zip(msgs.iter()).map(|(kp, m)| kp.sign(m)).collect();
        let pubkeys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public.clone()).collect();

        assert!(BlsAggregateSignature::verify_batch(&sigs, &pubkeys, &msgs));
    }

    #[test]
    fn test_verify_batch_rejects_one_bad_sig() {
        let n = 5usize;
        let keypairs: Vec<BlsKeypair> = (0..n as u8).map(|i| BlsKeypair::from_seed(&seed(i + 150))).collect();
        let raw_msgs: Vec<Vec<u8>> = (0..n).map(|i| format!("msg-{}", i).into_bytes()).collect();
        let msgs: Vec<&[u8]> = raw_msgs.iter().map(|m| m.as_slice()).collect();
        let mut sigs: Vec<BlsSignature> = keypairs.iter().zip(msgs.iter()).map(|(kp, m)| kp.sign(m)).collect();
        let pubkeys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public.clone()).collect();

        sigs[2] = keypairs[0].sign(b"tampered");

        assert!(!BlsAggregateSignature::verify_batch(&sigs, &pubkeys, &msgs));
    }
}
