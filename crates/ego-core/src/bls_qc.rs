use crate::bls::{BlsAggregateSignature, BlsError, BlsKeypair, BlsSignature};
use blst::min_pk::PublicKey;
use chrono::Utc;

#[derive(Debug, Clone)]
pub struct BlsQuorumCertificate {

    pub block_hash: [u8; 32],

    pub height: u64,

    pub epoch: u64,

    pub round: u32,

    pub voter_pubkeys: Vec<[u8; 48]>,

    pub voter_bitmap: Vec<u8>,

    pub agg_signature: [u8; 96],

    pub formed_at_ms: i64,
}

impl BlsQuorumCertificate {

    pub fn vote_msg(block_hash: &[u8; 32], height: u64, epoch: u64, round: u32) -> Vec<u8> {
        let mut msg = b"ego/bls/vote/v1:".to_vec();
        msg.extend_from_slice(block_hash);
        msg.extend_from_slice(&height.to_le_bytes());
        msg.extend_from_slice(&epoch.to_le_bytes());
        msg.extend_from_slice(&round.to_le_bytes());
        msg
    }

    pub fn form(
        block_hash: [u8; 32],
        height: u64,
        epoch: u64,
        round: u32,
        keypairs: &[(&BlsKeypair, usize)],
        total_validators: usize,
    ) -> Result<Self, BlsError> {
        if keypairs.is_empty() {
            return Err(BlsError::EmptyInputs("QC requires at least one voter".into()));
        }

        let msg = Self::vote_msg(&block_hash, height, epoch, round);

        let mut sigs: Vec<BlsSignature> = Vec::with_capacity(keypairs.len());
        let mut voter_pubkeys: Vec<[u8; 48]> = Vec::with_capacity(keypairs.len());

        let bitmap_len = total_validators.div_ceil(8);
        let mut voter_bitmap = vec![0u8; bitmap_len];

        for (kp, idx) in keypairs {
            if *idx >= total_validators {
                return Err(BlsError::LengthMismatch(format!(
                    "validator index {} >= total_validators {}",
                    idx, total_validators
                )));
            }
            sigs.push(kp.sign(&msg));
            voter_pubkeys.push(kp.public_key_bytes());

            voter_bitmap[idx / 8] |= 1 << (idx % 8);
        }

        let agg = BlsAggregateSignature::aggregate(&sigs)?;

        Ok(Self {
            block_hash,
            height,
            epoch,
            round,
            voter_pubkeys,
            voter_bitmap,
            agg_signature: agg.to_bytes(),
            formed_at_ms: Utc::now().timestamp_millis(),
        })
    }

    pub fn verify(&self) -> bool {
        if self.voter_pubkeys.is_empty() {
            return false;
        }

        let agg_sig = match BlsSignature::from_bytes(&self.agg_signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let mut pubkeys: Vec<PublicKey> = Vec::with_capacity(self.voter_pubkeys.len());
        for pk_bytes in &self.voter_pubkeys {
            match PublicKey::uncompress(pk_bytes) {
                Ok(pk) => pubkeys.push(pk),
                Err(_) => return false,
            }
        }

        let msg = Self::vote_msg(&self.block_hash, self.height, self.epoch, self.round);
        BlsAggregateSignature::verify_aggregate(&agg_sig, &pubkeys, &msg)
    }

    pub fn voter_count(&self) -> usize {
        self.voter_pubkeys.len()
    }

    pub fn byte_size(&self) -> usize {
        let n = self.voter_pubkeys.len();
        32 + 8 + 8 + 4 + 48 * n + self.voter_bitmap.len() + 96 + 8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::BlsKeypair;

    fn make_qc(n: usize) -> (BlsQuorumCertificate, Vec<BlsKeypair>) {
        let block_hash = [0xabu8; 32];
        let keypairs: Vec<BlsKeypair> = (0..n as u8)
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[0] = i;
                seed[1] = 0xbe;
                BlsKeypair::from_seed(&seed)
            })
            .collect();
        let pairs: Vec<(&BlsKeypair, usize)> = keypairs.iter().enumerate().map(|(i, kp)| (kp, i)).collect();
        let qc = BlsQuorumCertificate::form(block_hash, 42, 3, 0, &pairs, n).unwrap();
        (qc, keypairs)
    }

    #[test]
    fn test_qc_forms_and_verifies() {
        let (qc, _) = make_qc(10);
        assert!(qc.verify(), "QC with 10 voters must verify");
        assert_eq!(qc.voter_count(), 10);
    }

    #[test]
    fn test_qc_100_validators_verifies() {
        let (qc, _) = make_qc(100);
        assert!(qc.verify(), "QC with 100 voters must verify");
        assert_eq!(qc.voter_count(), 100);
    }

    #[test]
    fn test_qc_single_voter() {
        let (qc, _) = make_qc(1);
        assert!(qc.verify());
    }

    #[test]
    fn test_qc_empty_voters_returns_error() {
        let result = BlsQuorumCertificate::form([0u8; 32], 1, 0, 0, &[], 4);
        assert!(result.is_err());
    }

    #[test]
    fn test_qc_size_vs_dilithium() {
        for n in [1, 10, 67, 100] {
            let (qc, _) = make_qc(n);
            let bls_size = qc.byte_size();
            let dilithium_size = n * 2420;
            println!(
                "[bls_qc] n={:3} validators — BLS QC: {:6} B  |  Dilithium QC: {:7} B  |  reduction: {:.1}x",
                n,
                bls_size,
                dilithium_size,
                dilithium_size as f64 / bls_size as f64,
            );
            assert!(bls_size < dilithium_size, "BLS QC must be smaller than Dilithium QC");
        }
    }

    #[test]
    fn test_qc_bitmap_correctness() {

        let block_hash = [0x11u8; 32];
        let keypairs: Vec<BlsKeypair> = (0..5u8)
            .map(|i| {
                let mut s = [0u8; 32];
                s[0] = i;
                BlsKeypair::from_seed(&s)
            })
            .collect();
        let pairs: Vec<(&BlsKeypair, usize)> = vec![
            (&keypairs[0], 0),
            (&keypairs[2], 2),
            (&keypairs[4], 4),
        ];
        let qc = BlsQuorumCertificate::form(block_hash, 1, 0, 0, &pairs, 5).unwrap();

        assert_eq!(qc.voter_bitmap[0] & 0b00000001, 0b00000001, "bit 0");
        assert_eq!(qc.voter_bitmap[0] & 0b00000010, 0b00000000, "bit 1 must be 0");
        assert_eq!(qc.voter_bitmap[0] & 0b00000100, 0b00000100, "bit 2");
        assert_eq!(qc.voter_bitmap[0] & 0b00001000, 0b00000000, "bit 3 must be 0");
        assert_eq!(qc.voter_bitmap[0] & 0b00010000, 0b00010000, "bit 4");
        assert!(qc.verify());
    }

    #[test]
    fn test_qc_tampered_block_hash_fails() {
        let (mut qc, _) = make_qc(5);
        qc.block_hash[0] ^= 0xff;
        assert!(!qc.verify(), "tampered block_hash must fail verification");
    }

    #[test]
    fn test_qc_tampered_height_fails() {
        let (mut qc, _) = make_qc(5);
        qc.height += 1;
        assert!(!qc.verify(), "tampered height must fail verification");
    }

    #[test]
    fn test_qc_tampered_agg_signature_fails() {
        let (mut qc, _) = make_qc(5);

        qc.agg_signature[0] ^= 0x01;

        let result = qc.verify();
        assert!(!result, "corrupted agg_signature must fail");
    }

    #[test]
    fn test_qc_wrong_pubkey_fails() {
        let (mut qc, _) = make_qc(5);

        let interloper = {
            let mut s = [0xffu8; 32];
            s[0] = 0x77;
            BlsKeypair::from_seed(&s)
        };
        qc.voter_pubkeys[0] = interloper.public_key_bytes();
        assert!(!qc.verify(), "wrong pubkey must fail verification");
    }

    #[test]
    fn test_qc_vote_msg_domain_separation() {

        let msg1 = BlsQuorumCertificate::vote_msg(&[0u8; 32], 1, 0, 0);
        let msg2 = BlsQuorumCertificate::vote_msg(&[1u8; 32], 1, 0, 0);
        assert_ne!(msg1, msg2);

        let msg3 = BlsQuorumCertificate::vote_msg(&[0u8; 32], 2, 0, 0);
        assert_ne!(msg1, msg3);
    }

    #[test]
    fn test_qc_out_of_bounds_index_returns_error() {
        let mut s = [0u8; 32];
        s[0] = 7;
        let kp = BlsKeypair::from_seed(&s);
        let pairs = vec![(&kp, 10usize)];
        let result = BlsQuorumCertificate::form([0u8; 32], 0, 0, 0, &pairs, 5);
        assert!(result.is_err());
    }
}
