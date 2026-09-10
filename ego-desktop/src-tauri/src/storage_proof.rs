use crate::ledger::LedgerTx;
use serde::{Deserialize, Serialize};

pub const POST_PROOF_TX: &str = "post_proof";

const SEED_DOMAIN: &[u8] = b"ego/post-challenge/v1:";

/// How far back a proof may reach for its challenge block. The challenge has to be old
/// enough that every node already has the block, and new enough that a prover cannot have
/// prepared the answer before the data was theirs to store.
pub const CHALLENGE_MAX_AGE: u64 = 100;
pub const CHALLENGE_MIN_AGE: u64 = 1;

/// How long a proof keeps counting once it is committed. Storage is a claim about the
/// present, so a proof from a year ago says nothing about whether the data is still held.
pub const PROOF_VALID_FOR: u64 = 5_000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProofLeaf {
    pub leaf_index: u64,
    pub leaf: String,
    pub path: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostProofBody {
    pub cid: String,
    pub comm_d: String,
    pub n_real_leaves: u64,
    pub n_padded_leaves: u64,
    /// Height of the block whose hash seeds the challenge. Naming it rather than carrying
    /// the seed is what stops a prover choosing which leaves they will be asked for.
    pub challenge_height: u64,
    pub proofs: Vec<ProofLeaf>,
}

impl PostProofBody {
    pub fn bytes_proven(&self) -> u64 {
        self.n_real_leaves.saturating_mul(crate::proof::CHUNK_SIZE as u64)
    }
}

/// The challenge every node derives independently. Seeding it from a committed block hash
/// is what makes the proof checkable without an oracle handing out challenges, and what
/// stops the prover picking easy questions: the answer cannot be known before that block
/// existed.
pub fn challenge_seed(block_hash: &str, cid: &str, prover: &str) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(SEED_DOMAIN);
    h.update(block_hash.as_bytes());
    h.update(b":");
    h.update(cid.as_bytes());
    h.update(b":");
    h.update(prover.as_bytes());
    *h.finalize().as_bytes()
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s.trim()).ok()?.try_into().ok()
}

pub fn parse_body(call_args: &str) -> Result<PostProofBody, String> {
    let body: PostProofBody =
        serde_json::from_str(call_args).map_err(|e| format!("proof body is not readable: {e}"))?;
    if body.cid.trim().is_empty() {
        return Err("proof names no file".into());
    }
    if body.n_real_leaves == 0 || body.n_padded_leaves < body.n_real_leaves {
        return Err(format!(
            "proof claims {} real leaves inside {} padded",
            body.n_real_leaves, body.n_padded_leaves
        ));
    }
    if body.proofs.len() != crate::proof::POST_N_CHALLENGES {
        return Err(format!(
            "proof answers {} challenges, not {}",
            body.proofs.len(),
            crate::proof::POST_N_CHALLENGES
        ));
    }
    Ok(body)
}

fn to_merkle_proofs(body: &PostProofBody) -> Result<Vec<crate::proof::MerkleProof>, String> {
    body.proofs
        .iter()
        .map(|p| {
            let leaf = hex32(&p.leaf).ok_or("a proof leaf is not 32 bytes of hex")?;
            let path = p
                .path
                .iter()
                .map(|h| hex32(h).ok_or("a proof path entry is not 32 bytes of hex"))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(crate::proof::MerkleProof { leaf_index: p.leaf_index, leaf, path })
        })
        .collect()
}

/// Check a storage proof against the chain, returning how many bytes it proves.
///
/// `block_hash_at` is passed in rather than read here so the rule can be tested without a
/// database, and so callers inside a write batch use the same committed view they are
/// validating against.
pub fn validate_against_chain(
    tx: &LedgerTx,
    tip: u64,
    block_hash_at: impl Fn(u64) -> Option<String>,
) -> Result<u64, String> {
    if tx.tx_type != POST_PROOF_TX {
        return Err("not a storage proof".into());
    }
    if tx.from.trim().is_empty() {
        return Err("proof names no prover".into());
    }
    if tx.amount != 0 {
        return Err("a storage proof moves no coins".into());
    }
    let body = parse_body(&tx.call_args)?;

    let age = tip.saturating_sub(body.challenge_height);
    if body.challenge_height > tip || age < CHALLENGE_MIN_AGE {
        return Err(format!(
            "proof answers a challenge from block {} but the chain is only at {tip}",
            body.challenge_height
        ));
    }
    if age > CHALLENGE_MAX_AGE {
        return Err(format!(
            "proof answers a challenge {age} blocks old; only the last {CHALLENGE_MAX_AGE} count"
        ));
    }

    let block_hash = block_hash_at(body.challenge_height)
        .ok_or_else(|| format!("this node has no block {} to check the challenge against", body.challenge_height))?;
    let comm_d = hex32(&body.comm_d).ok_or("comm_d is not 32 bytes of hex")?;
    let seed = challenge_seed(&block_hash, &body.cid, &tx.from);
    let proofs = to_merkle_proofs(&body)?;

    if !crate::proof::verify_post_proofs(
        &proofs,
        &comm_d,
        &seed,
        body.n_real_leaves as usize,
        body.n_padded_leaves as usize,
    ) {
        return Err("the proof does not answer this chain's challenge".into());
    }
    Ok(body.bytes_proven())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::{generate_post_proofs, MerkleTree};

    fn body_for(data: &[u8], cid: &str, prover: &str, block_hash: &str, height: u64) -> PostProofBody {
        let tree = MerkleTree::build(data);
        let seed = challenge_seed(block_hash, cid, prover);
        let n_real = tree.n_real;
        let proofs = generate_post_proofs(data, &seed, n_real);
        PostProofBody {
            cid: cid.into(),
            comm_d: hex::encode(tree.root),
            n_real_leaves: n_real as u64,
            n_padded_leaves: tree.n_padded as u64,
            challenge_height: height,
            proofs: proofs
                .iter()
                .map(|p| ProofLeaf {
                    leaf_index: p.leaf_index,
                    leaf: hex::encode(p.leaf),
                    path: p.path.iter().map(hex::encode).collect(),
                })
                .collect(),
        }
    }

    fn tx_for(body: &PostProofBody, prover: &str) -> LedgerTx {
        LedgerTx {
            from: prover.into(),
            tx_type: POST_PROOF_TX.into(),
            call_args: serde_json::to_string(body).unwrap(),
            ..LedgerTx::default()
        }
    }

    const HASH: &str = "0000feed";
    const PROVER: &str = "egot1prover";
    const CID: &str = "egocid1abc";

    fn at(h: u64) -> Option<String> {
        if h == 10 { Some(HASH.to_string()) } else { Some(format!("otherhash{h}")) }
    }

    #[test]
    fn an_honest_proof_of_held_data_is_accepted_and_counted() {
        let data = vec![7u8; 32 * 1024];
        let body = body_for(&data, CID, PROVER, HASH, 10);
        let bytes = validate_against_chain(&tx_for(&body, PROVER), 20, at).unwrap();
        assert_eq!(bytes, 32 * 1024, "proven bytes are the real leaves, not the padding");
    }

    #[test]
    fn answering_a_challenge_meant_for_someone_else_fails() {
        let data = vec![7u8; 32 * 1024];
        let body = body_for(&data, CID, "egot1someoneelse", HASH, 10);
        let err = validate_against_chain(&tx_for(&body, PROVER), 20, at).unwrap_err();
        assert!(err.contains("does not answer"), "{err}");
    }

    #[test]
    fn a_proof_for_a_different_file_does_not_count_for_this_one() {
        let data = vec![7u8; 32 * 1024];
        let mut body = body_for(&data, "egocid1other", PROVER, HASH, 10);
        body.cid = CID.into();
        let err = validate_against_chain(&tx_for(&body, PROVER), 20, at).unwrap_err();
        assert!(err.contains("does not answer"), "{err}");
    }

    #[test]
    fn a_proof_built_against_a_different_block_does_not_count() {
        let data = vec![7u8; 32 * 1024];
        let mut body = body_for(&data, CID, PROVER, "someotherblockhash", 10);
        body.challenge_height = 10;
        let err = validate_against_chain(&tx_for(&body, PROVER), 20, at).unwrap_err();
        assert!(err.contains("does not answer"), "{err}");
    }

    #[test]
    fn a_stale_challenge_stops_counting() {
        let data = vec![7u8; 32 * 1024];
        let body = body_for(&data, CID, PROVER, HASH, 10);
        let err = validate_against_chain(&tx_for(&body, PROVER), 10 + CHALLENGE_MAX_AGE + 1, at)
            .unwrap_err();
        assert!(err.contains("blocks old"), "{err}");
    }

    #[test]
    fn a_challenge_from_the_future_is_refused() {
        let data = vec![7u8; 32 * 1024];
        let body = body_for(&data, CID, PROVER, HASH, 10);
        let err = validate_against_chain(&tx_for(&body, PROVER), 9, at).unwrap_err();
        assert!(err.contains("only at"), "{err}");
    }

    #[test]
    fn claiming_more_data_than_is_held_is_refused() {
        // 20 KB is 20 leaves padded to 32, leaving room to overstate without exceeding the
        // tree — the case that matters, because the obvious overstatement is caught by shape
        // alone and would not exercise the challenge at all.
        let data = vec![7u8; 20 * 1024];
        let honest = body_for(&data, CID, PROVER, HASH, 10);
        assert_eq!(honest.n_real_leaves, 20);
        assert!(honest.n_padded_leaves > honest.n_real_leaves, "the test needs slack to inflate into");
        assert_eq!(
            validate_against_chain(&tx_for(&honest, PROVER), 20, at).unwrap(),
            20 * 1024,
        );

        let mut inflated = honest.clone();
        inflated.n_real_leaves = 30;
        let err = validate_against_chain(&tx_for(&inflated, PROVER), 20, at).unwrap_err();
        assert!(
            err.contains("does not answer"),
            "size feeds the challenge, so overstating it asks for leaves the proof does not cover: {err}",
        );

        let mut absurd = honest;
        absurd.n_real_leaves *= 100;
        let err = validate_against_chain(&tx_for(&absurd, PROVER), 20, at).unwrap_err();
        assert!(err.contains("padded"), "an impossible shape is refused before any hashing: {err}");
    }

    #[test]
    fn a_proof_that_moves_coins_is_refused() {
        let data = vec![7u8; 32 * 1024];
        let body = body_for(&data, CID, PROVER, HASH, 10);
        let mut tx = tx_for(&body, PROVER);
        tx.amount = 1;
        assert!(validate_against_chain(&tx, 20, at).unwrap_err().contains("moves no coins"));
    }

    #[test]
    fn malformed_bodies_are_refused_rather_than_panicking() {
        for bad in ["", "{}", "not json", r#"{"cid":"","comm_d":"","n_real_leaves":0,"n_padded_leaves":0,"challenge_height":0,"proofs":[]}"#] {
            let tx = LedgerTx {
                from: PROVER.into(),
                tx_type: POST_PROOF_TX.into(),
                call_args: bad.into(),
                ..LedgerTx::default()
            };
            assert!(validate_against_chain(&tx, 20, at).is_err(), "{bad}");
        }
    }
}
