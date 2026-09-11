use crate::ledger::LedgerTx;
use serde::{Deserialize, Serialize};

pub const POC_PROOF_TX: &str = "poc_proof";

const BEACON_DOMAIN: &[u8] = b"ego/poc-beacon-seed/v1:";

/// Same shape as a storage challenge: old enough that every node has the block, new
/// enough that the beacon could not have been answered before the chain reached it.
pub const CHALLENGE_MAX_AGE: u64 = 100;
pub const CHALLENGE_MIN_AGE: u64 = 1;

/// How long a coverage proof keeps counting. Coverage is a claim about now, so a proof
/// from last week says nothing about whether the node is still reachable.
pub const PROOF_VALID_FOR: u64 = 5_000;

/// The most witnesses one proof can be worth. Without a ceiling a node that can reach a
/// thousand peers would carry the committee on its own, which is the concentration the
/// weight cap exists to prevent.
pub const MAX_WITNESSES: usize = 32;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoverageWitness {
    pub address: String,
    pub ed25519_pubkey: String,
    pub machine_id: String,
    pub cell: String,
    pub latency_ms: u32,
    pub rssi_dbm: i32,
    pub timestamp: i64,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PocProofBody {
    /// Height of the block whose hash seeds the beacon. Naming it rather than carrying
    /// the beacon id is what stops a prover choosing a beacon it prepared answers for.
    pub challenge_height: u64,
    pub cell: String,
    pub witnesses: Vec<CoverageWitness>,
}

/// The beacon every node derives independently from committed chain state. A prover
/// cannot pick it, and cannot know it before that block existed.
pub fn beacon_id_for(block_hash: &str, prover: &str) -> String {
    let mut h = blake3::Hasher::new();
    h.update(BEACON_DOMAIN);
    h.update(block_hash.as_bytes());
    h.update(b":");
    h.update(prover.as_bytes());
    hex::encode(&h.finalize().as_bytes()[..16])
}

fn address_of(ed25519_pubkey_hex: &str, chain_id: u32) -> Option<String> {
    let pk = hex::decode(ed25519_pubkey_hex).ok()?;
    if pk.len() != 32 {
        return None;
    }
    let hrp = if chain_id == 1 { "egot" } else { "ego" };
    ego_core::EgoAddress::from_public_key_bytes(&pk, chain_id, ego_core::AddressType::EOA)
        .to_bech32(hrp)
        .ok()
}

fn signature_holds(w: &CoverageWitness, beacon_id: &str, prover: &str) -> bool {
    let bytes = crate::poc::witness_signing_bytes(
        beacon_id,
        prover,
        &w.address,
        &w.machine_id,
        &w.cell,
        w.latency_ms,
        w.rssi_dbm,
        w.timestamp,
    );
    let (Ok(pk), Ok(sig)) = (hex::decode(&w.ed25519_pubkey), hex::decode(&w.signature)) else {
        return false;
    };
    let (Ok(pk), Ok(sig)) = (<[u8; 32]>::try_from(pk.as_slice()), <[u8; 64]>::try_from(sig.as_slice()))
    else {
        return false;
    };
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else { return false };
    vk.verify(&bytes, &Signature::from_bytes(&sig)).is_ok()
}

pub fn parse_body(call_args: &str) -> Result<PocProofBody, String> {
    let body: PocProofBody = serde_json::from_str(call_args)
        .map_err(|e| format!("coverage proof is not readable: {e}"))?;
    if body.witnesses.is_empty() {
        return Err("coverage proof names no witnesses".into());
    }
    if body.witnesses.len() > MAX_WITNESSES {
        return Err(format!(
            "coverage proof carries {} witnesses; at most {MAX_WITNESSES} count",
            body.witnesses.len()
        ));
    }
    Ok(body)
}

/// Check a coverage proof against the chain, returning how many distinct peers witnessed
/// the prover's beacon.
///
/// `block_hash_at` is passed in so the rule can be tested without a database and so a
/// caller inside a write batch checks against the same committed view it is validating.
pub fn validate_against_chain(
    tx: &LedgerTx,
    tip: u64,
    block_hash_at: impl Fn(u64) -> Option<String>,
) -> Result<u64, String> {
    if tx.tx_type != POC_PROOF_TX {
        return Err("not a coverage proof".into());
    }
    if tx.from.trim().is_empty() {
        return Err("coverage proof names no prover".into());
    }
    if tx.amount != 0 {
        return Err("a coverage proof moves no coins".into());
    }
    let body = parse_body(&tx.call_args)?;

    let age = tip.saturating_sub(body.challenge_height);
    if body.challenge_height > tip || age < CHALLENGE_MIN_AGE {
        return Err(format!(
            "proof answers a beacon from block {} but the chain is only at {tip}",
            body.challenge_height
        ));
    }
    if age > CHALLENGE_MAX_AGE {
        return Err(format!(
            "proof answers a beacon {age} blocks old; only the last {CHALLENGE_MAX_AGE} count"
        ));
    }

    let block_hash = block_hash_at(body.challenge_height).ok_or_else(|| {
        format!(
            "this node has no block {} to derive the beacon from",
            body.challenge_height
        )
    })?;
    let beacon_id = beacon_id_for(&block_hash, &tx.from);

    let mut addresses: Vec<&str> = Vec::new();
    let mut machines: Vec<&str> = Vec::new();
    for w in &body.witnesses {
        if w.address == tx.from {
            return Err("a node cannot witness its own beacon".into());
        }
        match address_of(&w.ed25519_pubkey, tx.chain_id as u32) {
            Some(derived) if derived == w.address => {}
            _ => return Err(format!("witness {} does not own the key it signed with", w.address)),
        }
        if !signature_holds(w, &beacon_id, &tx.from) {
            return Err(format!("witness {} did not sign this chain's beacon", w.address));
        }
        // Distinct addresses are free to mint; distinct machines are not. Counting a
        // machine once is the only Sybil cost available without radio physics to lean on.
        if addresses.contains(&w.address.as_str()) {
            return Err(format!("witness {} is counted twice", w.address));
        }
        if !w.machine_id.trim().is_empty() && machines.contains(&w.machine_id.as_str()) {
            return Err("two witnesses share a machine, so they are one witness".into());
        }
        addresses.push(&w.address);
        if !w.machine_id.trim().is_empty() {
            machines.push(&w.machine_id);
        }
    }
    Ok(addresses.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const PROVER: &str = "egot1prover";
    const HASH: &str = "0000feed";

    fn at(h: u64) -> Option<String> {
        if h == 10 { Some(HASH.to_string()) } else { Some(format!("otherhash{h}")) }
    }

    fn witness(seed: u8, machine: &str, beacon_id: &str, prover: &str) -> CoverageWitness {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = sk.verifying_key().to_bytes();
        let address = address_of(&hex::encode(pk), 1).unwrap();
        let mut w = CoverageWitness {
            address,
            ed25519_pubkey: hex::encode(pk),
            machine_id: machine.into(),
            cell: "cell-1".into(),
            latency_ms: 12,
            rssi_dbm: -70,
            timestamp: 1_700_000_000,
            signature: String::new(),
        };
        let bytes = crate::poc::witness_signing_bytes(
            beacon_id, prover, &w.address, &w.machine_id, &w.cell, w.latency_ms, w.rssi_dbm,
            w.timestamp,
        );
        w.signature = hex::encode(sk.sign(&bytes).to_bytes());
        w
    }

    fn tx_for(body: &PocProofBody) -> LedgerTx {
        LedgerTx {
            from: PROVER.into(),
            tx_type: POC_PROOF_TX.into(),
            chain_id: 1,
            call_args: serde_json::to_string(body).unwrap(),
            ..LedgerTx::default()
        }
    }

    fn honest() -> PocProofBody {
        let beacon = beacon_id_for(HASH, PROVER);
        PocProofBody {
            challenge_height: 10,
            cell: "cell-1".into(),
            witnesses: vec![
                witness(1, "m1", &beacon, PROVER),
                witness(2, "m2", &beacon, PROVER),
            ],
        }
    }

    #[test]
    fn peers_that_really_heard_the_beacon_are_counted() {
        assert_eq!(validate_against_chain(&tx_for(&honest()), 20, at).unwrap(), 2);
    }

    #[test]
    fn a_beacon_the_prover_chose_itself_does_not_count() {
        let mut body = honest();
        body.witnesses = vec![witness(1, "m1", "a-beacon-i-picked", PROVER)];
        let err = validate_against_chain(&tx_for(&body), 20, at).unwrap_err();
        assert!(err.contains("did not sign this chain's beacon"), "{err}");
    }

    #[test]
    fn a_witness_signing_for_someone_elses_beacon_does_not_count() {
        let beacon = beacon_id_for(HASH, "egot1someoneelse");
        let mut body = honest();
        body.witnesses = vec![witness(1, "m1", &beacon, PROVER)];
        assert!(validate_against_chain(&tx_for(&body), 20, at).is_err());
    }

    #[test]
    fn a_witness_that_does_not_own_its_key_is_refused() {
        let mut body = honest();
        body.witnesses[0].address = "egot1someoneelse".into();
        let err = validate_against_chain(&tx_for(&body), 20, at).unwrap_err();
        assert!(err.contains("does not own the key"), "{err}");
    }

    #[test]
    fn witnessing_your_own_beacon_is_refused() {
        let beacon = beacon_id_for(HASH, PROVER);
        let mut w = witness(1, "m1", &beacon, PROVER);
        w.address = PROVER.into();
        let body = PocProofBody { challenge_height: 10, cell: "c".into(), witnesses: vec![w] };
        let err = validate_against_chain(&tx_for(&body), 20, at).unwrap_err();
        assert!(err.contains("witness its own beacon"), "{err}");
    }

    #[test]
    fn one_machine_answering_twice_counts_once() {
        let beacon = beacon_id_for(HASH, PROVER);
        let body = PocProofBody {
            challenge_height: 10,
            cell: "c".into(),
            witnesses: vec![
                witness(1, "same-box", &beacon, PROVER),
                witness(2, "same-box", &beacon, PROVER),
            ],
        };
        let err = validate_against_chain(&tx_for(&body), 20, at).unwrap_err();
        assert!(err.contains("share a machine"), "{err}");
    }

    #[test]
    fn the_same_witness_listed_twice_is_refused() {
        let beacon = beacon_id_for(HASH, PROVER);
        let w = witness(1, "m1", &beacon, PROVER);
        let body = PocProofBody {
            challenge_height: 10,
            cell: "c".into(),
            witnesses: vec![w.clone(), w],
        };
        let err = validate_against_chain(&tx_for(&body), 20, at).unwrap_err();
        assert!(err.contains("counted twice"), "{err}");
    }

    #[test]
    fn a_stale_beacon_stops_counting() {
        let err = validate_against_chain(&tx_for(&honest()), 10 + CHALLENGE_MAX_AGE + 1, at)
            .unwrap_err();
        assert!(err.contains("blocks old"), "{err}");
    }

    #[test]
    fn a_beacon_from_the_future_is_refused() {
        let err = validate_against_chain(&tx_for(&honest()), 9, at).unwrap_err();
        assert!(err.contains("only at"), "{err}");
    }

    #[test]
    fn a_proof_that_moves_coins_is_refused() {
        let mut tx = tx_for(&honest());
        tx.amount = 1;
        assert!(validate_against_chain(&tx, 20, at).unwrap_err().contains("moves no coins"));
    }

    #[test]
    fn malformed_bodies_are_refused_rather_than_panicking() {
        for bad in ["", "{}", "not json", r#"{"challenge_height":10,"cell":"c","witnesses":[]}"#] {
            let tx = LedgerTx {
                from: PROVER.into(),
                tx_type: POC_PROOF_TX.into(),
                chain_id: 1,
                call_args: bad.into(),
                ..LedgerTx::default()
            };
            assert!(validate_against_chain(&tx, 20, at).is_err(), "{bad}");
        }
    }
}
