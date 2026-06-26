//! Phase 2 boundary — the adapter between the desktop's `LedgerBlock` world and the
//! deterministic, harness-verified `ego_consensus_core::BftEngine` (the engine that
//! will replace the hand-rolled inline BFT in `p2p.rs`).
//!
//! This module is intentionally a thin, self-contained wrapper: it owns a `BftEngine`
//! and converts between the desktop's hex/bech32 representations and the engine's
//! `ego_core` types. It is NOT yet wired into the live gossip path — the cutover
//! (routing `ego-proposals-v1` / `ego-votes-v1` / `ego-viewchange-v1` through these
//! methods and persisting the finalized `LedgerBlock`) is the next Phase 2 step.
//! See CONSENSUS_REPLACEMENT_SCOPE.md.

use crate::ledger::LedgerBlock;
use ego_consensus_core::bft::{BftEngine, BlockHeader, BlockRoots, QuorumCertificate, Vote};
use ego_core::{Address, Hash, KeyPair, PublicKey};

/// Parse a hex hash string (desktop `LedgerBlock` hashes are lowercase hex). An empty
/// or malformed value maps to the zero hash — a valid, agreed placeholder.
pub fn hash_from_hex(s: &str) -> Hash {
    if s.is_empty() {
        return Hash::new([0u8; 32]);
    }
    Hash::from_hex(s).unwrap_or_else(|_| Hash::new([0u8; 32]))
}

/// The consensus address of a validator. `BftEngine` votes carry
/// `Address::from_public_key(kp.public_key())`, so the `validator_set` MUST be derived
/// the same way for `vote.voter` to match a set member.
///
/// `BftEngine` signs consensus messages with **ed25519** (chosen over Dilithium for
/// bandwidth at scale — 64 B/vote vs ~2.4 KB; post-quantum security is provided at the
/// QC/BLS finality layer). Votes therefore carry
/// `Address::from_public_key(kp.ed25519_public_key())`, so the `validator_set` MUST be
/// built from each validator's **ed25519** public key. Self:
/// `Address::from_public_key(&local_kp.ed25519_public_key())`; peers:
/// [`address_from_ed25519`]`(p2p::get_peer_ed25519_pubkey(addr)?)` — the desktop already
/// keeps that registry for its inline BFT vote verification, so no new plumbing.
/// (The desktop's bech32 address is also ed25519-derived but via `EgoAddress`, a
/// SEPARATE encoding — map bech32 <-> engine-`Address` via the per-validator pubkey
/// lookup, never by re-deriving.)
pub fn consensus_address(pk: &PublicKey) -> Address {
    Address::from_public_key(pk)
}

/// Build an engine `Address` from a validator's raw 32-byte ed25519 public key (as
/// returned by `p2p::get_peer_ed25519_pubkey`, or the local keypair's verifying key).
pub fn address_from_ed25519(ed25519_pk: [u8; 32]) -> Address {
    Address::from_public_key(&PublicKey::ed25519(ed25519_pk))
}

/// Map a desktop `LedgerBlock`'s committed roots into the engine's `BlockRoots`. Only
/// `tx_root` + `state_root` are populated today (the desktop block has no distinct
/// receipts/rollup/da roots yet); zero is the agreed placeholder for the rest.
pub fn roots_from_ledger_block(b: &LedgerBlock) -> BlockRoots {
    BlockRoots {
        tx_root: hash_from_hex(&b.tx_merkle_root),
        state_root: hash_from_hex(&b.state_root),
        ..BlockRoots::empty()
    }
}

/// Build the engine `validator_set` (and a reverse `Address -> bech32` map for mapping
/// finalized headers back to `LedgerBlock.miner`) from each validator's **ed25519 public
/// key**. `validators` must list every registered validator INCLUDING self, as
/// `(bech32_address, ed25519_pk_bytes)`.
///
/// The result is sorted by `Address` and de-duplicated, so every node that sees the
/// same registered set produces the byte-identical ordered set — the prerequisite for
/// all engines agreeing on the per-round proposer `(height + round) % n`.
pub fn build_validator_set(
    validators: &[(String, [u8; 32])],
) -> (Vec<Address>, std::collections::HashMap<Address, String>) {
    let mut pairs: Vec<(Address, String)> = validators
        .iter()
        .map(|(bech32, ed)| (address_from_ed25519(*ed), bech32.clone()))
        .collect();
    pairs.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    pairs.dedup_by(|a, b| a.0 == b.0);
    let set: Vec<Address> = pairs.iter().map(|(a, _)| a.clone()).collect();
    let map: std::collections::HashMap<Address, String> = pairs.into_iter().collect();
    (set, map)
}

/// Owns the local node's `BftEngine` plus the validator set it agrees on. The p2p
/// layer routes gossip through these methods instead of the inline vote/proposal/
/// view-change statics.
pub struct ConsensusHost {
    engine: BftEngine,
    validator_set: Vec<Address>,
}

impl ConsensusHost {
    /// `validator_set` must be the SAME ordered list on every node (e.g. the on-chain
    /// registered set, each mapped via [`consensus_address`]/[`address_from_ed25519`]),
    /// so all engines agree on the per-round proposer = `(height + round) % n`.
    pub fn new(local: KeyPair, validator_set: Vec<Address>) -> Self {
        let engine = BftEngine::new(local, validator_set.clone());
        Self { engine, validator_set }
    }

    pub fn quorum_size(&self) -> usize {
        self.engine.quorum_size()
    }

    /// Whether this node is the elected leader for the current (height, round).
    pub fn is_proposer(&self) -> bool {
        self.engine.is_proposer()
    }

    pub fn current_height(&self) -> u64 {
        self.engine.get_current_height()
    }

    pub fn validator_set(&self) -> &[Address] {
        &self.validator_set
    }

    /// Local node is the leader: produce a header committing to `block`'s roots, to be
    /// gossiped alongside the full `LedgerBlock`.
    pub fn propose(&self, block: &LedgerBlock) -> Option<BlockHeader> {
        self.engine.propose_block(roots_from_ledger_block(block)).ok()
    }

    /// A proposal arrived. Returns this node's `Vote` iff it is safe to vote (correct
    /// proposer for the round, valid signature, fork-choice safe, no equivocation).
    pub fn on_proposal(&self, header: &BlockHeader) -> Option<Vote> {
        self.engine.receive_proposal(header).ok().flatten()
    }

    /// A vote arrived. Returns a `QuorumCertificate` the first time ⅔+1 votes for the
    /// current proposed block are seen.
    pub fn on_vote(&self, vote: &Vote) -> Option<QuorumCertificate> {
        self.engine.receive_vote(vote).ok().flatten()
    }

    /// Commit a finalized `header` + `qc`, advancing the engine to the next height.
    pub fn finalize(&self, header: BlockHeader, qc: QuorumCertificate) -> bool {
        self.engine.finalize_block(header, qc).is_ok()
    }

    /// The local proposal/vote timeout fired — produce a `ViewChangeMsg` to rotate to
    /// the next proposer.
    pub fn trigger_view_change(&self) -> Option<ego_consensus_core::fork_choice::ViewChangeMsg> {
        self.engine.trigger_view_change().ok()
    }

    /// A peer's view-change arrived. Returns the new round once a quorum of
    /// view-changes is collected (the engine then resets to that round).
    pub fn on_view_change(
        &self,
        msg: ego_consensus_core::fork_choice::ViewChangeMsg,
    ) -> Option<u32> {
        self.engine.receive_view_change(msg).ok().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roots_map_from_ledger_block_fields() {
        let mut b = LedgerBlock::default();
        b.tx_merkle_root = Hash::new([3u8; 32]).to_hex();
        b.state_root = Hash::new([5u8; 32]).to_hex();
        let r = roots_from_ledger_block(&b);
        assert_eq!(r.tx_root, Hash::new([3u8; 32]));
        assert_eq!(r.state_root, Hash::new([5u8; 32]));
        assert_eq!(r.receipts_root, Hash::new([0u8; 32]));
    }

    #[test]
    fn empty_and_bad_hex_map_to_zero() {
        assert_eq!(hash_from_hex(""), Hash::new([0u8; 32]));
        assert_eq!(hash_from_hex("not-hex"), Hash::new([0u8; 32]));
    }

    /// LINCHPIN: pins that the engine derives `vote.voter` from the **ed25519** key. The
    /// engine was switched to ed25519 signing; the `validator_set` must match. If the
    /// engine's signing key ever changes algorithm, this fails loudly.
    #[test]
    fn engine_address_is_ed25519_derived() {
        let kp = KeyPair::generate();
        // What BftEngine now uses for vote.voter (ed25519):
        let engine_addr = consensus_address(&kp.ed25519_public_key());
        assert_ne!(engine_addr, consensus_address(&kp.dilithium_public_key()));
        // The helper we use for peers (raw 32-byte ed25519 key) agrees.
        let ed_raw: [u8; 32] = kp.ed25519_public_key().as_bytes().try_into().unwrap();
        assert_eq!(engine_addr, address_from_ed25519(ed_raw));
    }

    #[test]
    fn validator_set_is_deterministic_and_dedup() {
        let kps: Vec<KeyPair> = (0..3).map(|_| KeyPair::generate()).collect();
        let raw: Vec<(String, [u8; 32])> = kps
            .iter()
            .enumerate()
            .map(|(i, k)| {
                (format!("egot1node{i}"), k.ed25519_public_key().as_bytes().try_into().unwrap())
            })
            .collect();

        // Same inputs in DIFFERENT orders must yield the byte-identical ordered set.
        let (set_a, map_a) = build_validator_set(&raw);
        let mut shuffled = raw.clone();
        shuffled.reverse();
        let (set_b, _) = build_validator_set(&shuffled);
        assert_eq!(set_a, set_b, "validator_set order must not depend on input order");
        assert_eq!(set_a.len(), 3);

        // The set members are exactly the engine addresses of those keypairs, and the
        // reverse map recovers the bech32.
        for (i, k) in kps.iter().enumerate() {
            let addr = consensus_address(&k.ed25519_public_key());
            assert!(set_a.contains(&addr));
            assert_eq!(map_a.get(&addr).map(|s| s.as_str()), Some(format!("egot1node{i}").as_str()));
        }

        // A duplicate validator entry collapses to one.
        let mut dup = raw.clone();
        dup.push(raw[0].clone());
        let (set_dup, _) = build_validator_set(&dup);
        assert_eq!(set_dup.len(), 3, "duplicates must be removed");
    }

    /// Two hosts sharing one validator set must agree on the proposer, finalize the
    /// same block, and advance in lockstep — a host-level sanity check that the
    /// adapter wraps the engine correctly (the full BFT properties are proven in
    /// `ego-consensus-core/tests/harness.rs`).
    #[test]
    fn two_hosts_finalize_in_lockstep() {
        let kps: Vec<KeyPair> = (0..2).map(|_| KeyPair::generate()).collect();
        let set: Vec<Address> = kps.iter().map(|k| consensus_address(&k.ed25519_public_key())).collect();
        let hosts: Vec<ConsensusHost> =
            kps.into_iter().map(|kp| ConsensusHost::new(kp, set.clone())).collect();

        for h in 0..10u64 {
            let p = hosts.iter().position(|x| x.is_proposer()).expect("a proposer");
            let header = hosts[p].propose(&LedgerBlock::default()).expect("propose");

            let votes: Vec<Vote> =
                hosts.iter().filter_map(|x| x.on_proposal(&header)).collect();

            for x in &hosts {
                for v in &votes {
                    if let Some(qc) = x.on_vote(v) {
                        assert!(x.finalize(header.clone(), qc));
                        break;
                    }
                }
            }
            for x in &hosts {
                assert_eq!(x.current_height(), h + 1);
            }
        }
    }
}
