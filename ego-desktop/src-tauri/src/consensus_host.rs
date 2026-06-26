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
use ego_consensus_core::bft::{BftEngine, BlockHeader, BlockRoots, QuorumCertificate, SigScheme, Vote};
use ego_core::{Address, Hash, KeyPair, PublicKey};

/// Re-exported so the p2p layer can name the consensus signature scheme. Default is
/// post-quantum Dilithium2; ed25519 is the lighter (non-PQ) option for dev/testnet.
pub use ego_consensus_core::bft::SigScheme as ConsensusSigScheme;

/// Parse a hex hash string (desktop `LedgerBlock` hashes are lowercase hex). An empty
/// or malformed value maps to the zero hash — a valid, agreed placeholder.
pub fn hash_from_hex(s: &str) -> Hash {
    if s.is_empty() {
        return Hash::new([0u8; 32]);
    }
    Hash::from_hex(s).unwrap_or_else(|_| Hash::new([0u8; 32]))
}

/// The consensus address of a validator = `blake3(public_key)[..20]` (=
/// `Address::from_public_key`). `BftEngine` derives `vote.voter` this way, so the
/// `validator_set` MUST be built from the SAME public key the engine signs with.
///
/// The engine's scheme is pluggable ([`ConsensusSigScheme`]) and defaults to
/// **post-quantum Dilithium2** (chosen for security; it does NOT bloat the chain — the
/// QC stores only a Merkle root of sigs + a voter bitmap, consensus runs over a bounded
/// committee, and the path to light historical verification is SNARK-aggregated
/// finality). For the default, build addresses from each validator's Dilithium key
/// ([`address_from_dilithium`]); for the ed25519 option, from the ed25519 key
/// ([`address_from_ed25519`]). Self: `scheme.address(&local_kp)`; peers: the matching
/// desktop registry (Dilithium → `register_validator_pubkey`; ed25519 →
/// `get_peer_ed25519_pubkey`). The desktop's bech32 address is a SEPARATE encoding — map
/// bech32 <-> engine-`Address` via the per-validator pubkey lookup, never re-derive.
pub fn consensus_address(pk: &PublicKey) -> Address {
    Address::from_public_key(pk)
}

/// Engine `Address` from a validator's RAW Dilithium2 key_data (`PublicKey::as_bytes()`,
/// NOT the tagged `to_vec()`) — the default post-quantum scheme's identity.
pub fn address_from_dilithium(dilithium_key_data: Vec<u8>) -> Address {
    Address::from_public_key(&PublicKey::dilithium2(dilithium_key_data))
}

/// Engine `Address` from a validator's raw 32-byte ed25519 public key (the ed25519
/// scheme option; `p2p::get_peer_ed25519_pubkey` returns these).
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
/// finalized headers back to `LedgerBlock.miner`) from each validator's pre-computed
/// engine `Address` (use [`address_from_dilithium`] for the default scheme, or
/// [`address_from_ed25519`]). `validators` must list every registered validator
/// INCLUDING self, as `(bech32_address, engine_address)`.
///
/// The result is sorted by `Address` and de-duplicated, so every node that sees the
/// same registered set produces the byte-identical ordered set — the prerequisite for
/// all engines agreeing on the per-round proposer `(height + round) % n`.
pub fn build_validator_set(
    validators: &[(String, Address)],
) -> (Vec<Address>, std::collections::HashMap<Address, String>) {
    let mut pairs: Vec<(Address, String)> = validators
        .iter()
        .map(|(bech32, addr)| (addr.clone(), bech32.clone()))
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
    /// Create a host with the default (post-quantum **Dilithium**) scheme. `validator_set`
    /// must be the SAME ordered list on every node (the registered set mapped via
    /// [`address_from_dilithium`]) so all engines agree on the proposer `(height+round)%n`.
    pub fn new(local: KeyPair, validator_set: Vec<Address>) -> Self {
        Self::with_scheme(local, validator_set, SigScheme::default())
    }

    /// Create a host with an explicit signature scheme. Every node on the network must
    /// use the same scheme, and `validator_set` must be derived from the matching keys.
    pub fn with_scheme(local: KeyPair, validator_set: Vec<Address>, scheme: SigScheme) -> Self {
        let engine = BftEngine::with_scheme(local, validator_set.clone(), scheme);
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

    /// LINCHPIN: the engine's DEFAULT scheme is post-quantum Dilithium, and the
    /// `validator_set` must be derived from the SAME key. If the default scheme or its
    /// address derivation ever changes, this fails loudly so the set construction is
    /// revisited (a mismatched set silently never matches `vote.voter`).
    #[test]
    fn engine_default_address_is_dilithium() {
        let kp = KeyPair::generate();
        // The default scheme's address == derived from the Dilithium key, != ed25519.
        let engine_addr = SigScheme::default().address(&kp);
        assert_eq!(engine_addr, consensus_address(&kp.dilithium_public_key()));
        assert_ne!(engine_addr, consensus_address(&kp.ed25519_public_key()));
        // The Dilithium helper (RAW key_data) agrees with the default-scheme address.
        let dil_raw = kp.dilithium_public_key().as_bytes().to_vec();
        assert_eq!(engine_addr, address_from_dilithium(dil_raw));
        // The ed25519 helper agrees with the ed25519-scheme address (the option).
        let ed_raw: [u8; 32] = kp.ed25519_public_key().as_bytes().try_into().unwrap();
        assert_eq!(consensus_address(&kp.ed25519_public_key()), address_from_ed25519(ed_raw));
    }

    #[test]
    fn validator_set_is_deterministic_and_dedup() {
        let kps: Vec<KeyPair> = (0..3).map(|_| KeyPair::generate()).collect();
        // Default (Dilithium) scheme addresses, paired with bech32.
        let raw: Vec<(String, Address)> = kps
            .iter()
            .enumerate()
            .map(|(i, k)| (format!("egot1node{i}"), consensus_address(&k.dilithium_public_key())))
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
            let addr = consensus_address(&k.dilithium_public_key());
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
        // Default (Dilithium) scheme — exercises the real production signing path.
        let set: Vec<Address> = kps.iter().map(|k| consensus_address(&k.dilithium_public_key())).collect();
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
