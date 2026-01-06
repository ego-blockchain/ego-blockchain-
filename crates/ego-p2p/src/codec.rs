use crate::{MAX_MESSAGE_SIZE, P2PError, P2PMessage, P2PResult};

pub struct MessageCodec;

impl MessageCodec {
    pub fn encode(message: &P2PMessage) -> P2PResult<Vec<u8>> {
        let encoded =
            serde_json::to_vec(message).map_err(|e| P2PError::SerializationError(e.to_string()))?;

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

        let message = serde_json::from_slice(data)
            .map_err(|e| P2PError::DeserializationError(e.to_string()))?;

        Ok(message)
    }

    pub fn validate_message(message: &P2PMessage) -> P2PResult<()> {
        match message {
            P2PMessage::Transaction(tx_msg) => {
                if tx_msg.payload.is_empty() {
                    return Err(P2PError::InvalidMessage(
                        "Transaction payload is empty".to_string(),
                    ));
                }
            }
            P2PMessage::Block(block_msg) => {
                if block_msg.payload.is_empty() {
                    return Err(P2PError::InvalidMessage(
                        "Block payload is empty".to_string(),
                    ));
                }
            }
            P2PMessage::Proof(proof_msg) => {
                if proof_msg.payload.is_empty() {
                    return Err(P2PError::InvalidMessage(
                        "Proof payload is empty".to_string(),
                    ));
                }
            }
            P2PMessage::Sync(_) => {}
            P2PMessage::CrossShard(cs_msg) => {
                if cs_msg.payload.is_empty() {
                    return Err(P2PError::InvalidMessage(
                        "CrossShard payload is empty".to_string(),
                    ));
                }
            }
            P2PMessage::Identify(_) => {}
        }

        Ok(())
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
}
