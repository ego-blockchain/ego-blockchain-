use crate::{
    BlockMessage, CrossShardMessage, IdentifyMessage, NodeCapabilities, P2PMessage, ProofMessage,
    ProofType, SyncMessage, SyncType, TransactionMessage,
};
use ego_core::{Address, Hash, ShardId, Timestamp};

pub struct MessageBuilder;

impl MessageBuilder {
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
}
