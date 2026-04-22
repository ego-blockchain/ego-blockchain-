use crate::chain_db::{self, LightBlockHeader, MerkleProof};
use crate::error::EgoDesktopError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountProofResponse {
    pub state_root: String,
    pub proof: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetBlockHeadersArgs {

    #[serde(default)]
    pub from_height: u64,

    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 { 100 }

#[tauri::command]
pub async fn get_block_headers(args: GetBlockHeadersArgs) -> Result<Vec<LightBlockHeader>, EgoDesktopError> {
    Ok(chain_db::get_block_headers(args.from_height, args.limit))
}

#[tauri::command]
pub async fn get_tx_proof(tx_hash: String) -> Result<Option<MerkleProof>, EgoDesktopError> {

    let tx = match chain_db::get_tx_by_hash(&tx_hash) {
        Some(t) => t,
        None    => return Ok(None),
    };
    let height = match tx.block_height {
        Some(h) => h,
        None    => return Ok(None),
    };

    let txs = chain_db::get_txs_for_block(height);
    if txs.is_empty() { return Ok(None); }

    let hashes: Vec<&str> = txs.iter().map(|t| t.hash.as_str()).collect();
    Ok(chain_db::prove_tx_inclusion(&hashes, &tx_hash))
}

#[tauri::command]
pub async fn verify_tx_proof(proof: MerkleProof) -> Result<bool, EgoDesktopError> {
    Ok(chain_db::verify_merkle_proof(&proof))
}

#[tauri::command]
pub async fn get_account_proof(address: String) -> Result<AccountProofResponse, EgoDesktopError> {
    let state_root = chain_db::compute_full_state_root();
    let proof = chain_db::get_state_merkle_proof(&address);
    Ok(AccountProofResponse { state_root, proof })
}

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
