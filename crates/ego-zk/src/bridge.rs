use crate::error::ZkError;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BridgeClaim {

    pub chain_id: u64,

    pub height: u64,

    pub sender: String,

    pub amount: u128,

    pub token: String,

    pub nonce: u64,
}

impl BridgeClaim {

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let sender_b = self.sender.as_bytes();
        let token_b = self.token.as_bytes();
        let mut out = Vec::with_capacity(44 + sender_b.len() + token_b.len());
        out.extend_from_slice(&self.chain_id.to_le_bytes());
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&(sender_b.len() as u32).to_le_bytes());
        out.extend_from_slice(sender_b);
        out.extend_from_slice(&(token_b.len() as u32).to_le_bytes());
        out.extend_from_slice(token_b);
        out
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BridgeProof {

    pub claim: BridgeClaim,

    pub state_root: [u8; 32],

    pub proof_bytes: Vec<u8>,
}

impl BridgeProof {

    pub fn claim_hash(&self) -> [u8; 32] {
        use blake2::{Blake2s256, Digest};
        let bytes = self.claim.to_canonical_bytes();
        let digest = Blake2s256::digest(&bytes);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    pub fn to_hex(&self) -> String {
        hex::encode(serde_json::to_vec(self).expect("BridgeProof serialization is infallible"))
    }

    pub fn from_hex(s: &str) -> Result<Self, ZkError> {
        let bytes = hex::decode(s)
            .map_err(|e| ZkError::SerializationError(format!("hex decode: {e}")))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| ZkError::SerializationError(format!("json decode: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_claim() -> BridgeClaim {
        BridgeClaim {
            chain_id: 1,
            height: 12_345_678,
            sender: "egot1qabcdefgh".to_string(),
            amount: 1_000_000,
            token: "USDC".to_string(),
            nonce: 42,
        }
    }

    #[test]
    fn test_claim_hash_is_deterministic() {
        let claim = sample_claim();
        let bp = BridgeProof {
            claim: claim.clone(),
            state_root: [0xab; 32],
            proof_bytes: vec![],
        };
        assert_eq!(bp.claim_hash(), bp.claim_hash());
    }

    #[test]
    fn test_bridge_proof_hex_roundtrip() {
        let bp = BridgeProof {
            claim: sample_claim(),
            state_root: [0x11; 32],
            proof_bytes: vec![1, 2, 3],
        };
        let hex = bp.to_hex();
        let decoded = BridgeProof::from_hex(&hex).expect("from_hex failed");
        assert_eq!(decoded.claim.nonce, bp.claim.nonce);
        assert_eq!(decoded.state_root, bp.state_root);
        assert_eq!(decoded.proof_bytes, bp.proof_bytes);
    }

    #[test]
    fn test_claim_canonical_bytes_deterministic() {
        let c = sample_claim();
        assert_eq!(c.to_canonical_bytes(), c.to_canonical_bytes());
    }
}
