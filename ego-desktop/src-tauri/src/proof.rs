use serde::{Deserialize, Serialize};

pub const CHUNK_SIZE: usize = 1024;

pub const POST_N_CHALLENGES: usize = 8;

pub const POREP_TAG: &[u8] = b"ego/porep/v1";

pub const POST_WINDOW_SECS: i64 = 30 * 60;

fn hash_bytes(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

pub struct MerkleTree {
    pub root: [u8; 32],
    nodes: Vec<[u8; 32]>,
    pub n_padded: usize,
    pub n_real: usize,
}

impl MerkleTree {

    pub fn build(data: &[u8]) -> Self {
        let leaves: Vec<[u8; 32]> = data
            .chunks(CHUNK_SIZE)
            .map(|chunk| hash_bytes(chunk))
            .collect();
        Self::from_leaves(leaves)
    }

    pub fn build_from_path(path: &std::path::Path) -> std::io::Result<Self> {
        use std::io::Read;
        let file   = std::fs::File::open(path)?;
        let mut reader = std::io::BufReader::with_capacity(CHUNK_SIZE * 64, file);
        let mut leaves = Vec::new();
        let mut chunk  = vec![0u8; CHUNK_SIZE];
        loop {
            let mut filled = 0usize;
            while filled < CHUNK_SIZE {
                match reader.read(&mut chunk[filled..]) {
                    Ok(0)  => break,
                    Ok(n)  => filled += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
            if filled == 0 { break; }
            leaves.push(hash_bytes(&chunk[..filled]));
        }
        Ok(Self::from_leaves(leaves))
    }

    fn from_leaves(leaves: Vec<[u8; 32]>) -> Self {
        let n_real   = leaves.len().max(1);
        let n_padded = n_real.next_power_of_two();

        let mut nodes = vec![[0u8; 32]; 2 * n_padded + 1];

        for (i, leaf) in leaves.iter().enumerate() {
            nodes[n_padded + i] = *leaf;
        }

        for i in (1..n_padded).rev() {
            nodes[i] = hash_pair(&nodes[2 * i], &nodes[2 * i + 1]);
        }

        MerkleTree { root: nodes[1], nodes, n_padded, n_real }
    }

    pub fn proof(&self, leaf_idx: usize) -> MerkleProof {
        let mut path = Vec::new();
        let mut pos  = self.n_padded + leaf_idx;
        let leaf     = self.nodes[pos];

        while pos > 1 {

            let sibling = if pos % 2 == 0 { pos + 1 } else { pos - 1 };
            path.push(self.nodes[sibling]);
            pos /= 2;
        }

        MerkleProof { leaf_index: leaf_idx as u64, leaf, path }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {

    pub leaf_index: u64,

    pub leaf: [u8; 32],

    pub path: Vec<[u8; 32]>,
}

impl MerkleProof {

    pub fn verify(&self, root: &[u8; 32], n_padded: usize) -> bool {
        let mut current = self.leaf;
        let mut pos     = n_padded as u64 + self.leaf_index;

        for sibling in &self.path {
            current = if pos % 2 == 0 {
                hash_pair(&current, sibling)
            } else {
                hash_pair(sibling, &current)
            };
            pos /= 2;
        }

        &current == root
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoRepCommitment {

    pub comm_d: [u8; 32],

    pub comm_r: [u8; 32],

    pub replica_id: [u8; 32],

    pub n_real_leaves: usize,

    pub n_padded_leaves: usize,
}

pub fn compute_porep_commitment(
    enc_bytes:   &[u8],
    prover_addr: &str,
    cid:         &str,
) -> PoRepCommitment {
    let tree = MerkleTree::build(enc_bytes);
    let comm_d = tree.root;

    let replica_id = {
        let mut h = blake3::Hasher::new();
        h.update(prover_addr.as_bytes());
        h.update(b":");
        h.update(cid.as_bytes());
        *h.finalize().as_bytes()
    };

    let comm_r = {
        let mut h = blake3::Hasher::new();
        h.update(&comm_d);
        h.update(&replica_id);
        h.update(POREP_TAG);
        *h.finalize().as_bytes()
    };

    PoRepCommitment {
        comm_d,
        comm_r,
        replica_id,
        n_real_leaves:   tree.n_real,
        n_padded_leaves: tree.n_padded,
    }
}

pub fn derive_challenge_indices(
    challenge_seed: &[u8; 32],
    n_real_leaves:  usize,
) -> Vec<usize> {
    (0..POST_N_CHALLENGES)
        .map(|i| {
            let mut h = blake3::Hasher::new();
            h.update(challenge_seed);
            h.update(&(i as u64).to_le_bytes());
            let raw = u64::from_le_bytes(
                h.finalize().as_bytes()[..8].try_into().unwrap(),
            );
            (raw % n_real_leaves as u64) as usize
        })
        .collect()
}

pub fn generate_post_proofs(
    enc_bytes:      &[u8],
    challenge_seed: &[u8; 32],
    n_real_leaves:  usize,
) -> Vec<MerkleProof> {
    let tree    = MerkleTree::build(enc_bytes);
    let indices = derive_challenge_indices(challenge_seed, n_real_leaves);
    indices.iter().map(|&idx| tree.proof(idx)).collect()
}

pub fn generate_post_proofs_from_path(
    path:           &std::path::Path,
    challenge_seed: &[u8; 32],
    n_real_leaves:  usize,
) -> std::io::Result<Vec<MerkleProof>> {
    let tree    = MerkleTree::build_from_path(path)?;
    let indices = derive_challenge_indices(challenge_seed, n_real_leaves);
    Ok(indices.iter().map(|&idx| tree.proof(idx)).collect())
}

pub fn verify_post_proofs(
    proofs:          &[MerkleProof],
    comm_d:          &[u8; 32],
    challenge_seed:  &[u8; 32],
    n_real_leaves:   usize,
    n_padded_leaves: usize,
) -> bool {
    if proofs.len() != POST_N_CHALLENGES { return false; }
    let expected = derive_challenge_indices(challenge_seed, n_real_leaves);
    for (proof, &expected_idx) in proofs.iter().zip(expected.iter()) {
        if proof.leaf_index != expected_idx as u64 { return false; }
        if !proof.verify(comm_d, n_padded_leaves)  { return false; }
    }
    true
}

// ── PoSt enforcement loop ─────────────────────────────────────────────────────
//
// Every POST_CHECK_INTERVAL_SECS (6 h) we challenge each locally-owned active file:
//   1. Pick a deterministic random block: blake3(cid || time_slot)[0..8] % n_blocks
//   2. Load the encrypted block from disk.
//   3. Decrypt with the per-file AES-256-GCM key stored in the ledger.
//   4. Hash the plaintext and compare against the block_cid  (egoblk1{blake3_hex}).
//      This is a cryptographic proof — faking it requires the actual data.
//
// On failure:
//   strike 1 — warning only (grace period: file may be re-downloading)
//   strike 2+ — storage rewards for this file withheld for POST_SUSPEND_SECS
//              — slash_storage tx written on-chain

pub const POST_CHECK_INTERVAL_SECS: i64 = 6 * 3600;
pub const POST_SUSPEND_SECS:        i64 = 7 * 24 * 3600;

/// Called from the background 30-second loop; runs the full check every 6 h.
/// Pass in the Tauri app handle so we can fire a desktop notification on slash.
pub async fn run_post_checks(app: Option<&tauri::AppHandle<tauri::Wry>>) {
    let now = chrono::Utc::now().timestamp();
    let mut ledger = crate::ledger::Ledger::load();
    let my_addr = ledger.address.clone();
    if my_addr.is_empty() { return; }

    let mut need_save = false;

    // Collect slash info: (cid, name, strikes, collateral, block_cid, comm_r, challenge_slot)
    let mut to_slash: Vec<(String, String, u32, u64, String, String, i64)> = Vec::new();
    let mut to_return_collateral: Vec<(String, u64)> = Vec::new();

    for file in ledger.stored_files.iter_mut() {
        // Only prove active files we locally own (master or unassigned role).
        if file.status != "Active" { continue; }
        if file.replication_role == "slave" { continue; }
        if file.local_path.is_empty() || file.local_path.starts_with("sender:") { continue; }
        if file.key_nonce_hex == "public" { continue; }

        // Not time for another challenge yet?
        let last = file.last_proved.unwrap_or(0);
        if now - last < POST_CHECK_INTERVAL_SECS { continue; }

        let proof_ok = challenge_file(file, now);

        if proof_ok {
            file.last_proved           = Some(now);
            file.proof_strikes         = 0;
            file.proof_suspended_until = 0;
            need_save = true;
            eprintln!("[PoSt] ✓  {} proved at slot {}", &file.cid[..16.min(file.cid.len())], now / POST_CHECK_INTERVAL_SECS);

            // Deal expiry: if slave's hosting deal has ended and file is still good,
            // return locked collateral in full.
            let is_slave_deal = file.replication_role == "slave"
                && file.collateral_locked_uegoc > 0
                && file.expiry > 0
                && file.expiry <= now;
            if is_slave_deal {
                to_return_collateral.push((file.cid.clone(), file.collateral_locked_uegoc));
                file.collateral_locked_uegoc = 0;
            }
        } else {
            file.proof_strikes += 1;
            need_save = true;
            eprintln!("[PoSt] ✗  {} FAILED — strike {} of 2", &file.cid[..16.min(file.cid.len())], file.proof_strikes);

            if file.proof_strikes >= 2 {
                file.proof_suspended_until = now + POST_SUSPEND_SECS;

                // Re-derive which block was challenged so we can include it in the broadcast.
                let slot = now / POST_CHECK_INTERVAL_SECS;
                let (challenged_block_cid, challenged_comm_r) = if file.cid.starts_with("egomfd1") {
                    if let Ok(manifest) = crate::blocks::load_manifest(&file.cid) {
                        if !manifest.blocks.is_empty() {
                            let challenge_epoch = (slot * POST_CHECK_INTERVAL_SECS) as u64 / 100;
                            let challenge_block_hash = crate::chain_db::get_block_hash_at(challenge_epoch)
                                .unwrap_or_else(|| crate::chain_db::get_tip_hash());
                            let mut h = blake3::Hasher::new();
                            h.update(file.cid.as_bytes());
                            h.update(&slot.to_le_bytes());
                            h.update(challenge_block_hash.as_bytes());
                            let digest = h.finalize();
                            let idx = u64::from_le_bytes(
                                digest.as_bytes()[..8].try_into().unwrap_or([0; 8]),
                            ) as usize % manifest.blocks.len();
                            let entry = &manifest.blocks[idx];
                            (entry.block_cid.clone(), entry.comm_r.clone())
                        } else { (String::new(), String::new()) }
                    } else { (String::new(), String::new()) }
                } else { (String::new(), String::new()) };

                to_slash.push((
                    file.cid.clone(), file.name.clone(), file.proof_strikes,
                    file.collateral_locked_uegoc, challenged_block_cid, challenged_comm_r, slot,
                ));
                file.collateral_locked_uegoc = 0; // collateral consumed
            }
        }
    }

    if need_save {
        let _ = ledger.save();
    }

    for (cid, name, strikes, collateral, block_cid, comm_r, slot) in to_slash {
        record_slash_tx(&my_addr, &cid, strikes).await;
        burn_collateral(&my_addr, &cid, collateral).await;

        // Broadcast SlashChallenge so all peers independently verify and record the slash.
        if !block_cid.is_empty() {
            let sign_input = format!("slash:{}:{}:{}:{}", my_addr, cid, block_cid, slot);
            let reporter_sig = crate::ledger::load_seed().ok().flatten()
                .and_then(|s| {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&s[..32]);
                    ego_core::KeyPair::from_bytes(&a).ok()
                })
                .map(|kp| hex::encode(kp.sign_ed25519(sign_input.as_bytes()).as_bytes()))
                .unwrap_or_default();

            let msg = crate::p2p::P2PMessage::SlashChallenge {
                accused_addr:   my_addr.clone(),
                cid:            cid.clone(),
                block_cid:      block_cid.clone(),
                challenge_slot: slot,
                comm_r:         comm_r.clone(),
                reporter_addr:  my_addr.clone(),
                reporter_sig,
            };
            let peers = crate::p2p::get_known_peers();
            for ep in peers.into_iter().filter(|p| !p.is_empty()).take(50) {
                let msg2 = msg.clone();
                tokio::spawn(async move {
                    let _ = crate::p2p::send_message(&ep, &msg2).await;
                });
            }
            eprintln!("[PoSt] SlashChallenge broadcast to peers: cid={} block={}", &cid[..16.min(cid.len())], &block_cid[..16.min(block_cid.len())]);
        }

        if let Some(h) = app {
            crate::commands::notifications::notify(
                h,
                "Storage Proof Failed",
                &format!("\"{}\" — rewards suspended 7 days (strike {}). Check your storage folder.", name, strikes),
            );
        }
    }
    for (cid, collateral) in to_return_collateral {
        return_collateral(&my_addr, &cid, collateral).await;
    }
}

/// Sample one block from `file` using a deterministic challenge and verify it.
/// Returns true if the file passes, false if data is missing or corrupt.
fn challenge_file(file: &crate::ledger::StoredFile, now: i64) -> bool {
    if !file.cid.starts_with("egomfd1") {
        return false;
    }

    let manifest = match crate::blocks::load_manifest(&file.cid) {
        Ok(m) => m,
        Err(_) => return false,  // manifest gone — fail
    };
    if manifest.blocks.is_empty() { return true; }

    // Unpredictable block selection: blake3(cid || slot || challenge_block_hash)
    let slot = now / POST_CHECK_INTERVAL_SECS;
    let challenge_epoch = (slot * POST_CHECK_INTERVAL_SECS) as u64 / 100;
    let challenge_block_hash = crate::chain_db::get_block_hash_at(challenge_epoch)
        .unwrap_or_else(|| crate::chain_db::get_tip_hash());
        
    let mut h = blake3::Hasher::new();
    h.update(file.cid.as_bytes());
    h.update(&slot.to_le_bytes());
    h.update(challenge_block_hash.as_bytes());
    let digest = h.finalize();
    let idx = u64::from_le_bytes(digest.as_bytes()[..8].try_into().unwrap_or([0; 8]))
        as usize % manifest.blocks.len();

    let entry = &manifest.blocks[idx];

    // Load encrypted block from disk.
    let enc_bytes = match crate::blocks::load_block(&entry.block_cid) {
        Ok(b) => b,
        Err(_) => return false,  // block file missing — fail
    };

    // ── PoRep verification ────────────────────────────────────────────────────
    // If the block has a stored comm_r, verify it matches what we'd compute from
    // the enc_bytes on disk.  This proves the bytes are the SAME ones we sealed
    // at upload time and are bound to our address — a node can't fake this by
    // fetching blocks on demand unless they also have the exact enc_bytes.
    if !entry.comm_r.is_empty() {
        let my_addr = crate::ledger::Ledger::load().address;
        let expected_comm_r = crate::blocks::compute_block_comm_r(&enc_bytes, &my_addr, &entry.block_cid);
        if expected_comm_r != entry.comm_r {
            return false;  // replica commitment mismatch — data replaced or corrupted
        }
        return true;  // comm_r verified — data is intact and bound to this prover
    }

    // ── Legacy fallback: decrypt + hash verify (no comm_r stored) ────────────
    let key_vec = crate::ledger::unprotect_key_bytes(&file.key_nonce_hex);
    if key_vec.len() < 32 { return false; }

    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
    let key_arr: [u8; 32] = match key_vec[..32].try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let nonce_bytes = match hex::decode(&entry.nonce_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    if nonce_bytes.len() != 12 { return false; }

    let cipher = match Aes256Gcm::new_from_slice(&key_arr) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = match cipher.decrypt(nonce, enc_bytes.as_ref()) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let expected_hash = match entry.block_cid.strip_prefix("egoblk1") {
        Some(h) => h,
        None     => return false,
    };
    let actual_hash = ego_core::hash_data(&plaintext).to_hex();
    actual_hash.as_str() == expected_hash
}

/// Burn collateral for a file that failed PoSt or was early-deleted.
/// Burns `SLASH_BURN_BPS` (10%) of locked collateral; returns the rest.
pub async fn burn_collateral(addr: &str, cid: &str, collateral: u64) {
    if collateral == 0 { return; }
    use crate::ledger::LedgerTx;
    const SLASH_BURN_BPS: u64 = 1_000; // 10%
    let burn_amount   = collateral * SLASH_BURN_BPS / 10_000;
    let return_amount = collateral.saturating_sub(burn_amount);
    let now   = chrono::Utc::now().timestamp();
    let mut ledger = crate::ledger::Ledger::load();
    let burn_nonce   = ledger.nonce + 1;
    let return_nonce = ledger.nonce + 2;

    let sign_input  = format!("burn_collateral:{}:{}:{}", addr, cid, burn_nonce);
    let sig_hex     = crate::ledger::load_seed()
        .ok()
        .flatten()
        .and_then(|s| { let mut a = [0u8;32]; a.copy_from_slice(&s[..32]); ego_core::KeyPair::from_bytes(&a).ok() })
        .map(|kp| hex::encode(kp.sign_ed25519(sign_input.as_bytes()).as_bytes()))
        .unwrap_or_default();
    let burn_hash   = format!("0x{}", ego_core::hash_data(sign_input.as_bytes()).to_hex());
    let return_hash = format!("0x{}", ego_core::hash_data(format!("return_collateral:{}:{}:{}", addr, cid, return_nonce).as_bytes()).to_hex());

    crate::p2p::push_protocol_tx(LedgerTx {
        hash: burn_hash.clone(), from: "egot1collateral000000000000000000000000000000".into(),
        to:   "egot1burn0000000000000000000000000000000000000".into(),
        amount: burn_amount,
        memo:   Some(format!("slash_burn 10%: cid {}", &cid[..16.min(cid.len())])),
        timestamp: now, signature: sig_hex.clone(), status: "Confirmed".into(),
        block_height: None, nonce: burn_nonce, tx_type: "burn_collateral".into(),
        cid: cid.to_string(), ..LedgerTx::default()
    });
    if return_amount > 0 {
        crate::p2p::push_protocol_tx(LedgerTx {
            hash: return_hash, from: "egot1collateral000000000000000000000000000000".into(),
            to:   addr.to_string(), amount: return_amount,
            memo: Some(format!("collateral_return 90%: cid {}", &cid[..16.min(cid.len())])),
            timestamp: now, signature: sig_hex, status: "Confirmed".into(),
            block_height: None, nonce: return_nonce, tx_type: "unlock_collateral".into(),
            cid: cid.to_string(), ..LedgerTx::default()
        });
    }
    ledger.nonce = return_nonce;
    let _ = ledger.save();
    eprintln!("[Collateral] Burned {} uEGOC, returned {} uEGOC for cid={}", burn_amount, return_amount, &cid[..16.min(cid.len())]);
}

/// Return full collateral when a hosting deal expires in good standing.
pub async fn return_collateral(addr: &str, cid: &str, collateral: u64) {
    if collateral == 0 { return; }
    use crate::ledger::LedgerTx;
    let now   = chrono::Utc::now().timestamp();
    let mut ledger = crate::ledger::Ledger::load();
    let nonce = ledger.nonce + 1;
    let sign_input = format!("return_collateral:{}:{}:{}", addr, cid, nonce);
    let sig_hex    = crate::ledger::load_seed()
        .ok()
        .flatten()
        .and_then(|s| { let mut a = [0u8;32]; a.copy_from_slice(&s[..32]); ego_core::KeyPair::from_bytes(&a).ok() })
        .map(|kp| hex::encode(kp.sign_ed25519(sign_input.as_bytes()).as_bytes()))
        .unwrap_or_default();
    let tx_hash = format!("0x{}", ego_core::hash_data(sign_input.as_bytes()).to_hex());
    let _ = crate::mempool::get_mempool().push(LedgerTx {
        hash: tx_hash.clone(), from: "egot1collateral000000000000000000000000000000".into(),
        to: addr.to_string(), amount: collateral,
        memo: Some(format!("collateral_return full: cid {}", &cid[..16.min(cid.len())])),
        timestamp: now, signature: sig_hex, status: "Pending".into(),
        block_height: None, nonce, tx_type: "unlock_collateral".into(),
        cid: cid.to_string(), ..LedgerTx::default()
    });
    ledger.nonce = nonce;
    let _ = ledger.save();
    eprintln!("[Collateral] Returned {} uEGOC (deal complete) for cid={}", collateral, &cid[..16.min(cid.len())]);
}

/// Write a `slash_storage` tx on-chain so the penalty is public and verifiable.
async fn record_slash_tx(addr: &str, cid: &str, strikes: u32) {
    use crate::ledger::LedgerTx;
    let now   = chrono::Utc::now().timestamp();
    let mut ledger = crate::ledger::Ledger::load();
    let nonce = ledger.nonce + 1;
    let sign_input = format!("slash_storage:{}:{}:{}", addr, cid, nonce);
    let signature_hex = crate::ledger::load_seed()
        .ok()
        .flatten()
        .and_then(|s| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&s[..32]);
            ego_core::KeyPair::from_bytes(&arr).ok()
        })
        .map(|kp| hex::encode(kp.sign_ed25519(sign_input.as_bytes()).as_bytes()))
        .unwrap_or_default();
    let tx_hash = format!("0x{}", ego_core::hash_data(sign_input.as_bytes()).to_hex());

    crate::p2p::push_protocol_tx(LedgerTx {
        hash:            tx_hash.clone(),
        from:            addr.to_string(),
        to:              "egot1slashpool0000000000000000000000000000000".into(),
        amount:          0,  // no token burn yet — rewards just withheld
        memo:            Some(format!("slash_storage: strike {} | cid {}", strikes, &cid[..16.min(cid.len())])),
        timestamp:       now,
        signature:       signature_hex,
        status:          "Pending".into(),
        block_height:    None,
        nonce,
        tx_type:         "slash_storage".into(),
        cid:             cid.to_string(),
        commitment_hash: String::new(),
        ..LedgerTx::default()
    });
    ledger.nonce = nonce;
    let _ = ledger.save();
    eprintln!("[PoSt] slash_storage tx {} | cid={} | strike={}", &tx_hash[..18], &cid[..16.min(cid.len())], strikes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::OsRng, RngCore};

    #[test]
    fn roundtrip_merkle_proof() {
        let mut data = vec![0u8; 4096];
        OsRng.fill_bytes(&mut data);
        let tree = MerkleTree::build(&data);
        for idx in 0..tree.n_real {
            let proof = tree.proof(idx);
            assert!(proof.verify(&tree.root, tree.n_padded), "proof failed for leaf {idx}");
        }
    }

    #[test]
    fn post_proof_roundtrip() {
        let mut data = vec![0u8; 32 * 1024];
        OsRng.fill_bytes(&mut data);
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let tree   = MerkleTree::build(&data);
        let proofs = generate_post_proofs(&data, &seed, tree.n_real);
        assert!(verify_post_proofs(&proofs, &tree.root, &seed, tree.n_real, tree.n_padded));
    }

    #[test]
    fn tampered_proof_fails() {
        let mut data = vec![0u8; 8 * 1024];
        OsRng.fill_bytes(&mut data);
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let tree   = MerkleTree::build(&data);
        let mut proofs = generate_post_proofs(&data, &seed, tree.n_real);

        proofs[0].leaf[0] ^= 0xFF;
        assert!(!verify_post_proofs(&proofs, &tree.root, &seed, tree.n_real, tree.n_padded));
    }
}
