//! Light client commands — block headers + Merkle inclusion proofs.
//!
//! Full nodes store every block with every transaction.  Light clients (mobile,
//! browser, low-storage devices) only need block headers plus a Merkle proof to
//! verify that a specific transaction is in a specific block.
//!
//! The Merkle tree uses Blake3 for speed.  Leaf = blake3(tx_hash).
//! Internal node = blake3(left_hex ++ right_hex).

use crate::chain_db::{self, LightBlockHeader, MerkleProof};
use crate::error::EgoDesktopError;
use serde::{Deserialize, Serialize};

// ── get_block_headers ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct GetBlockHeadersArgs {
    /// First block height to return (inclusive).
    #[serde(default)]
    pub from_height: u64,
    /// Maximum number of headers to return (capped at 10,000).
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 { 100 }

/// Return packed block headers without transaction data.
/// Suitable for light clients that only need to verify chain integrity and
/// perform Merkle inclusion proofs.
#[tauri::command]
pub async fn get_block_headers(args: GetBlockHeadersArgs) -> Result<Vec<LightBlockHeader>, EgoDesktopError> {
    Ok(chain_db::get_block_headers(args.from_height, args.limit))
}

// ── get_tx_proof ──────────────────────────────────────────────────────────────

/// Return a Merkle inclusion proof for `tx_hash` in its block.
/// The proof can be verified client-side with `verify_tx_proof` without
/// trusting any full node.
#[tauri::command]
pub async fn get_tx_proof(tx_hash: String) -> Result<Option<MerkleProof>, EgoDesktopError> {
    // Locate the block that contains this TX.
    let tx = match chain_db::get_tx_by_hash(&tx_hash) {
        Some(t) => t,
        None    => return Ok(None),
    };
    let height = match tx.block_height {
        Some(h) => h,
        None    => return Ok(None),
    };

    // Fetch all TX hashes in that block.
    let txs = chain_db::get_txs_for_block(height);
    if txs.is_empty() { return Ok(None); }

    let hashes: Vec<&str> = txs.iter().map(|t| t.hash.as_str()).collect();
    Ok(chain_db::prove_tx_inclusion(&hashes, &tx_hash))
}

// ── verify_tx_proof ───────────────────────────────────────────────────────────

/// Verify a Merkle inclusion proof client-side.
/// Returns true if the proof is cryptographically valid — the TX is in the block
/// without needing to trust or download full block contents.
#[tauri::command]
pub async fn verify_tx_proof(proof: MerkleProof) -> Result<bool, EgoDesktopError> {
    Ok(chain_db::verify_merkle_proof(&proof))
}

// ── request_headers_from_peer ─────────────────────────────────────────────────

/// Ask a random peer to send us block headers starting at `from_height`.
/// Results arrive asynchronously via the `ego://headers-received` event.
#[tauri::command]
pub async fn request_headers_from_peer(from_height: u64, limit: u32) -> Result<(), EgoDesktopError> {
    let msg = crate::p2p::P2PMessage::HeaderSyncRequest { from_height, limit: limit.min(10_000) };
    let peers = crate::p2p::load_peer_cache();
    for peer in peers.iter().take(3) {
        if peer.endpoint.is_empty() { continue; }
        let endpoint = peer.endpoint.clone();
        let msg_clone = msg.clone();
        tokio::spawn(async move {
            let _ = crate::p2p::send_message(&endpoint, &msg_clone).await;
        });
    }
    Ok(())
}
