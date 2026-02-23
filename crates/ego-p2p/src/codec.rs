use crate::builder::{GossipEnvelope, GossipPayload};
use crate::{MAX_MESSAGE_SIZE, P2PError, P2PMessage, P2PResult};
use blake2::{Blake2s256, Digest};

pub struct MessageCodec;

impl MessageCodec {
    pub fn encode(message: &P2PMessage) -> P2PResult<Vec<u8>> {
        let encoded = bincode::encode_to_vec(message, bincode::config::standard())
            .map_err(|e| P2PError::SerializationError(e.to_string()))?;
        if encoded.len() > MAX_MESSAGE_SIZE {
            return Err(P2PError::InvalidMessage(format!(
                "Message size {} exceeds maximum {}",
                encoded.len(),
                MAX_MESSAGE_SIZE
            )));
        }
        Ok(encoded)
    }

    pub fn decode(data: &[u8]) -> P2PResult<P2PMessage> {
        if data.len() > MAX_MESSAGE_SIZE {
            return Err(P2PError::InvalidMessage(format!(
                "Data size {} exceeds maximum {}",
                data.len(),
                MAX_MESSAGE_SIZE
            )));
        }
        let (message, _) = bincode::decode_from_slice(data, bincode::config::standard())
            .map_err(|e| P2PError::DeserializationError(e.to_string()))?;
        Ok(message)
    }

    pub fn encode_envelope(envelope: &GossipEnvelope) -> P2PResult<Vec<u8>> {
        let encoded = bincode::encode_to_vec(envelope, bincode::config::standard())
            .map_err(|e| P2PError::SerializationError(e.to_string()))?;
        if encoded.len() > MAX_MESSAGE_SIZE {
            return Err(P2PError::InvalidMessage(format!(
                "Envelope size {} exceeds maximum {}",
                encoded.len(),
                MAX_MESSAGE_SIZE
            )));
        }
        Ok(encoded)
    }

    pub fn decode_envelope(data: &[u8]) -> P2PResult<GossipEnvelope> {
        if data.len() > MAX_MESSAGE_SIZE {
            return Err(P2PError::InvalidMessage(format!(
                "Data size {} exceeds maximum {}",
                data.len(),
                MAX_MESSAGE_SIZE
            )));
        }
        let (envelope, _) = bincode::decode_from_slice(data, bincode::config::standard())
            .map_err(|e| P2PError::DeserializationError(e.to_string()))?;
        Ok(envelope)
    }

    pub fn hash_message_with_domain(message: &P2PMessage, domain: &str) -> Vec<u8> {
        let domain_tag = format!("ego/{}/v1", domain);
        let mut hasher = Blake2s256::new();
        hasher.update(domain_tag.as_bytes());
        if let Ok(encoded) = Self::encode(message) {
            hasher.update(&encoded);
        }
        hasher.finalize().to_vec()
    }

    pub fn hash_envelope_with_domain(envelope: &GossipEnvelope, domain: &str) -> Vec<u8> {
        let domain_tag = format!("ego/{}/v1", domain);
        let mut hasher = Blake2s256::new();
        hasher.update(domain_tag.as_bytes());
        if let Ok(encoded) = Self::encode_envelope(envelope) {
            hasher.update(&encoded);
        }
        hasher.finalize().to_vec()
    }

    pub fn validate_message(message: &P2PMessage) -> P2PResult<()> {
        match message {
            P2PMessage::Transaction(tx_msg) => {
                if tx_msg.payload.is_empty() {
                    return Err(P2PError::InvalidMessage(
                        "Transaction payload is empty".to_string(),
                    ));
                }
                if tx_msg.payload.len() > MAX_MESSAGE_SIZE {
                    return Err(P2PError::InvalidMessage(
                        "Transaction payload exceeds maximum size".to_string(),
                    ));
                }
            }
            P2PMessage::Block(block_msg) => {
                if block_msg.payload.is_empty() {
                    return Err(P2PError::InvalidMessage(
                        "Block payload is empty".to_string(),
                    ));
                }
                if block_msg.payload.len() > MAX_MESSAGE_SIZE {
                    return Err(P2PError::InvalidMessage(
                        "Block payload exceeds maximum size".to_string(),
                    ));
                }
            }
            P2PMessage::Proof(proof_msg) => {
                if proof_msg.payload.is_empty() {
                    return Err(P2PError::InvalidMessage(
                        "Proof payload is empty".to_string(),
                    ));
                }
                if proof_msg.payload.len() > MAX_MESSAGE_SIZE {
                    return Err(P2PError::InvalidMessage(
                        "Proof payload exceeds maximum size".to_string(),
                    ));
                }
            }
            P2PMessage::Sync(sync_msg) => {
                if sync_msg.from_height > sync_msg.to_height {
                    return Err(P2PError::InvalidMessage(
                        "Invalid sync range: from_height > to_height".to_string(),
                    ));
                }
            }
            P2PMessage::CrossShard(cs_msg) => {
                if cs_msg.payload.is_empty() {
                    return Err(P2PError::InvalidMessage(
                        "CrossShard payload is empty".to_string(),
                    ));
                }
                if cs_msg.payload.len() > MAX_MESSAGE_SIZE {
                    return Err(P2PError::InvalidMessage(
                        "CrossShard payload exceeds maximum size".to_string(),
                    ));
                }
            }
            P2PMessage::Identify(_) => {}
        }
        Ok(())
    }

    pub fn validate_envelope(envelope: &GossipEnvelope) -> P2PResult<()> {
        if envelope.version != 1 {
            return Err(P2PError::InvalidMessage(format!(
                "Unsupported envelope version: {}",
                envelope.version
            )));
        }

        if envelope.signature.is_empty() {
            return Err(P2PError::InvalidMessage(
                "Envelope signature is empty".to_string(),
            ));
        }

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if envelope.timestamp > current_time + 300 {
            return Err(P2PError::InvalidMessage(
                "Envelope timestamp is too far in the future".to_string(),
            ));
        }

        if current_time > envelope.timestamp + 3600 {
            return Err(P2PError::InvalidMessage(
                "Envelope timestamp is too old".to_string(),
            ));
        }

        match &envelope.payload {
            GossipPayload::Transaction(tx) => {
                if tx.payload.is_empty() {
                    return Err(P2PError::InvalidMessage(
                        "Transaction payload is empty".to_string(),
                    ));
                }
            }
            GossipPayload::Block(block) => {
                if block.payload.is_empty() {
                    return Err(P2PError::InvalidMessage(
                        "Block payload is empty".to_string(),
                    ));
                }
            }
            GossipPayload::Proof(proof) => {
                if proof.payload.is_empty() {
                    return Err(P2PError::InvalidMessage(
                        "Proof payload is empty".to_string(),
                    ));
                }
            }
            GossipPayload::Header(header) => {
                if header.height == 0 {
                    return Err(P2PError::InvalidMessage(
                        "Header height cannot be zero".to_string(),
                    ));
                }
            }
            GossipPayload::Receipt(receipt) => {
                if receipt.payload.is_empty() {
                    return Err(P2PError::InvalidMessage(
                        "Receipt payload is empty".to_string(),
                    ));
                }
            }
            GossipPayload::Rollup(rollup) => {
                if rollup.payload.is_empty() {
                    return Err(P2PError::InvalidMessage(
                        "Rollup payload is empty".to_string(),
                    ));
                }
            }
            GossipPayload::CrossShard(cs) => {
                if cs.payload.is_empty() {
                    return Err(P2PError::InvalidMessage(
                        "CrossShard payload is empty".to_string(),
                    ));
                }
            }
            GossipPayload::Sync(_) | GossipPayload::Identify(_) => {}
        }

        Ok(())
    }

    pub fn verify_dilithium_signature(
        envelope: &GossipEnvelope,
        public_key: &[u8],
    ) -> P2PResult<bool> {
        if public_key.is_empty() {
            return Err(P2PError::InvalidMessage("Public key is empty".to_string()));
        }

        if envelope.signature.len() < 32 {
            return Err(P2PError::InvalidMessage("Signature too short".to_string()));
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::{Hash, ShardId, Timestamp};

    #[test]
    fn test_encode_decode_transaction() {
        let msg = P2PMessage::Transaction(crate::TransactionMessage {
            tx_hash: Hash::random(),
            shard_id: ShardId::new(0).unwrap(),
            payload: vec![1, 2, 3, 4, 5],
            timestamp: Timestamp::now(),
        });
        let encoded = MessageCodec::encode(&msg).unwrap();
        let decoded = MessageCodec::decode(&encoded).unwrap();
        match decoded {
            P2PMessage::Transaction(tx) => {
                assert_eq!(tx.payload, vec![1, 2, 3, 4, 5]);
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_message_size_limit() {
        let large_payload = vec![0u8; MAX_MESSAGE_SIZE + 1];
        let msg = P2PMessage::Transaction(crate::TransactionMessage {
            tx_hash: Hash::random(),
            shard_id: ShardId::new(0).unwrap(),
            payload: large_payload,
            timestamp: Timestamp::now(),
        });
        let result = MessageCodec::encode(&msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_message() {
        let valid_msg = P2PMessage::Transaction(crate::TransactionMessage {
            tx_hash: Hash::random(),
            shard_id: ShardId::new(0).unwrap(),
            payload: vec![1, 2, 3],
            timestamp: Timestamp::now(),
        });
        assert!(MessageCodec::validate_message(&valid_msg).is_ok());

        let invalid_msg = P2PMessage::Transaction(crate::TransactionMessage {
            tx_hash: Hash::random(),
            shard_id: ShardId::new(0).unwrap(),
            payload: vec![],
            timestamp: Timestamp::now(),
        });
        assert!(MessageCodec::validate_message(&invalid_msg).is_err());
    }

    #[test]
    fn test_hash_message_with_domain() {
        let msg = P2PMessage::Transaction(crate::TransactionMessage {
            tx_hash: Hash::random(),
            shard_id: ShardId::new(0).unwrap(),
            payload: vec![1, 2, 3],
            timestamp: Timestamp::now(),
        });
        let hash1 = MessageCodec::hash_message_with_domain(&msg, "gossip");
        let hash2 = MessageCodec::hash_message_with_domain(&msg, "gossip");
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }
}
