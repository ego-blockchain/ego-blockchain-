use crate::{
    BlockMessage, CrossShardMessage, IdentifyMessage, NodeCapabilities, P2PMessage, ProofMessage,
    ProofType, SyncMessage, SyncType, TransactionMessage,
};
use ego_core::{Address, Hash, ShardId, Timestamp};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct GossipEnvelope {
    pub version: u8,
    pub timestamp: u64,
    pub signature: Vec<u8>,
    pub payload: GossipPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum GossipPayload {
    Transaction(TransactionMessage),
    Block(BlockMessage),
    Proof(ProofMessage),
    CrossShard(CrossShardMessage),
    Sync(SyncMessage),
    Identify(IdentifyMessage),
    Header(HeaderMessage),
    Receipt(ReceiptMessage),
    Rollup(RollupMessage),
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct HeaderMessage {
    pub block_hash: Hash,
    pub height: u64,
    pub shard_id: ShardId,
    pub parent_hash: Hash,
    pub state_root: Hash,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ReceiptMessage {
    pub receipt_hash: Hash,
    pub block_hash: Hash,
    pub shard_id: ShardId,
    pub payload: Vec<u8>,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct RollupMessage {
    pub rollup_hash: Hash,
    pub batch_index: u64,
    pub state_root: Hash,
    pub payload: Vec<u8>,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PeerCaps {
    pub address: Address,
    pub capabilities: NodeCapabilities,
    pub protocols: Vec<String>,
    pub agent_version: String,
    pub attestation: Option<Vec<u8>>,
    pub dilithium_pubkey: Option<Vec<u8>>,
}

pub struct MessageBuilder;

impl MessageBuilder {
    pub fn domain_tag(context: &str) -> Vec<u8> {
        format!("ego/{}/v1", context).into_bytes()
    }

    pub fn hash_with_domain(data: &[u8], domain: &[u8]) -> Hash {
        use blake2::{Blake2s256, Digest};
        let mut hasher = Blake2s256::new();
        hasher.update(domain);
        hasher.update(data);
        Hash::from_slice(&hasher.finalize()).unwrap_or_else(|_| Hash::new([0u8; 32]))
    }

    pub fn wrap_envelope(payload: GossipPayload, signature: Vec<u8>) -> GossipEnvelope {
        GossipEnvelope {
            version: 1,
            timestamp: Timestamp::now().as_secs(),
            signature,
            payload,
        }
    }

    pub fn transaction(tx_hash: Hash, shard_id: ShardId, payload: Vec<u8>) -> P2PMessage {
        P2PMessage::Transaction(TransactionMessage {
            tx_hash,
            shard_id,
            payload,
            timestamp: Timestamp::now(),
        })
    }

    pub fn block(block_hash: Hash, height: u64, shard_id: ShardId, payload: Vec<u8>) -> P2PMessage {
        P2PMessage::Block(BlockMessage {
            block_hash,
            height,
            shard_id,
            payload,
            timestamp: Timestamp::now(),
        })
    }

    pub fn header(
        block_hash: Hash,
        height: u64,
        shard_id: ShardId,
        parent_hash: Hash,
        state_root: Hash,
    ) -> HeaderMessage {
        HeaderMessage {
            block_hash,
            height,
            shard_id,
            parent_hash,
            state_root,
            timestamp: Timestamp::now(),
        }
    }

    pub fn receipt(
        receipt_hash: Hash,
        block_hash: Hash,
        shard_id: ShardId,
        payload: Vec<u8>,
    ) -> ReceiptMessage {
        ReceiptMessage {
            receipt_hash,
            block_hash,
            shard_id,
            payload,
            timestamp: Timestamp::now(),
        }
    }

    pub fn rollup(
        rollup_hash: Hash,
        batch_index: u64,
        state_root: Hash,
        payload: Vec<u8>,
    ) -> RollupMessage {
        RollupMessage {
            rollup_hash,
            batch_index,
            state_root,
            payload,
            timestamp: Timestamp::now(),
        }
    }

    pub fn post_proof(prover: Address, payload: Vec<u8>) -> P2PMessage {
        P2PMessage::Proof(ProofMessage {
            proof_type: ProofType::PoSt,
            prover,
            payload,
            timestamp: Timestamp::now(),
        })
    }

    pub fn poc_proof(prover: Address, payload: Vec<u8>) -> P2PMessage {
        P2PMessage::Proof(ProofMessage {
            proof_type: ProofType::PoC,
            prover,
            payload,
            timestamp: Timestamp::now(),
        })
    }

    pub fn porep_proof(prover: Address, payload: Vec<u8>) -> P2PMessage {
        P2PMessage::Proof(ProofMessage {
            proof_type: ProofType::PoRep,
            prover,
            payload,
            timestamp: Timestamp::now(),
        })
    }

    pub fn sync_headers(from_height: u64, to_height: u64, shard_id: ShardId) -> P2PMessage {
        P2PMessage::Sync(SyncMessage {
            sync_type: SyncType::Headers,
            from_height,
            to_height,
            shard_id,
        })
    }

    pub fn sync_blocks(from_height: u64, to_height: u64, shard_id: ShardId) -> P2PMessage {
        P2PMessage::Sync(SyncMessage {
            sync_type: SyncType::Blocks,
            from_height,
            to_height,
            shard_id,
        })
    }

    pub fn sync_state(from_height: u64, to_height: u64, shard_id: ShardId) -> P2PMessage {
        P2PMessage::Sync(SyncMessage {
            sync_type: SyncType::State,
            from_height,
            to_height,
            shard_id,
        })
    }

    pub fn cross_shard(
        source_shard: ShardId,
        target_shard: ShardId,
        receipt_hash: Hash,
        payload: Vec<u8>,
    ) -> P2PMessage {
        P2PMessage::CrossShard(CrossShardMessage {
            source_shard,
            target_shard,
            receipt_hash,
            payload,
            timestamp: Timestamp::now(),
        })
    }

    pub fn identify(
        address: Address,
        capabilities: NodeCapabilities,
        listen_addrs: Vec<String>,
        protocols: Vec<String>,
        agent_version: String,
    ) -> P2PMessage {
        P2PMessage::Identify(IdentifyMessage {
            address,
            capabilities,
            listen_addrs,
            protocols,
            agent_version,
        })
    }

    pub fn peer_caps(
        address: Address,
        capabilities: NodeCapabilities,
        protocols: Vec<String>,
        agent_version: String,
        attestation: Option<Vec<u8>>,
        dilithium_pubkey: Option<Vec<u8>>,
    ) -> PeerCaps {
        PeerCaps {
            address,
            capabilities,
            protocols,
            agent_version,
            attestation,
            dilithium_pubkey,
        }
    }
}
