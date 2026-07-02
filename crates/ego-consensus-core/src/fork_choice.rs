use crate::bft::{BlockHeader, QuorumCertificate, SigScheme};
use crate::error::{PoCError, PoCResult};
use ego_core::{Address, Hash, KeyPair, Signature, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct ViewChangeMsg {

    pub new_round: u32,
    pub height: u64,
    pub epoch: u64,

    pub high_qc: Option<QuorumCertificate>,
    pub sender: Address,
    pub sender_pk: ego_core::PublicKey,
    pub signature: Signature,
    pub timestamp: Timestamp,
}

impl ViewChangeMsg {
    pub fn new(
        new_round: u32,
        height: u64,
        epoch: u64,
        high_qc: Option<QuorumCertificate>,
        kp: &KeyPair,
        scheme: SigScheme,
    ) -> PoCResult<Self> {
        let sender = scheme.address(kp);
        let msg = Self::signing_bytes(new_round, height, epoch);
        Ok(Self {
            new_round,
            height,
            epoch,
            high_qc,
            sender,
            sender_pk: scheme.public_key(kp),
            signature: scheme.sign(kp, &msg),
            timestamp: Timestamp::now(),
        })
    }

    fn signing_bytes(new_round: u32, height: u64, epoch: u64) -> Vec<u8> {
        let mut d = b"ego/viewchange/v1:".to_vec();
        d.extend_from_slice(&new_round.to_le_bytes());
        d.extend_from_slice(&height.to_le_bytes());
        d.extend_from_slice(&epoch.to_le_bytes());
        d
    }

    pub fn verify(&self) -> PoCResult<bool> {
        ego_core::verify_signature(
            &self.sender_pk,
            &Self::signing_bytes(self.new_round, self.height, self.epoch),
            &self.signature,
        )
        .map_err(|e| PoCError::SignatureVerificationFailed(e.to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct ForkChoiceStore {

    pub blocks: HashMap<u64, HashMap<Hash, BlockHeader>>,

    pub qcs: HashMap<Hash, QuorumCertificate>,

    pub high_qc: Option<QuorumCertificate>,

    pub locked_qc: Option<QuorumCertificate>,

    pub view_changes: HashMap<(u64, u32), Vec<ViewChangeMsg>>,

    pub canonical_head: Option<Hash>,
}

impl Default for ForkChoiceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ForkChoiceStore {
    pub fn new() -> Self {
        Self {
            blocks: HashMap::new(),
            qcs: HashMap::new(),
            high_qc: None,
            locked_qc: None,
            view_changes: HashMap::new(),
            canonical_head: None,
        }
    }

    pub fn add_block(&mut self, header: BlockHeader) {
        self.blocks
            .entry(header.height)
            .or_default()
            .insert(header.block_hash(), header);
    }

    pub fn add_qc(&mut self, qc: QuorumCertificate) {
        let higher = self.high_qc.as_ref().map_or(true, |hq| {
            qc.epoch > hq.epoch || (qc.epoch == hq.epoch && qc.round > hq.round)
        });
        if higher {
            debug!(
                "🔼 New high_qc: epoch={} round={} block={}",
                qc.epoch,
                qc.round,
                qc.block_hash
            );
            self.high_qc = Some(qc.clone());
        }
        self.qcs.insert(qc.block_hash, qc);
    }

    pub fn update_locked_qc(&mut self, qc: QuorumCertificate) {
        let higher = self.locked_qc.as_ref().map_or(true, |lq| {
            qc.epoch > lq.epoch || (qc.epoch == lq.epoch && qc.round > lq.round)
        });
        if higher {
            info!(
                "🔒 Locking QC: epoch={} round={} block={}",
                qc.epoch,
                qc.round,
                qc.block_hash
            );
            self.locked_qc = Some(qc.clone());
            self.canonical_head = Some(qc.block_hash);
        }
    }

    pub fn is_safe_to_vote(&self, block: &BlockHeader) -> bool {
        let locked = match &self.locked_qc {
            None => return true,
            Some(l) => l,
        };

        if block.epoch > locked.epoch {
            return true;
        }

        if block.epoch == locked.epoch {
            return self.extends_locked(block, locked.block_hash);
        }

        warn!(
            "⚠️  Unsafe vote: block epoch {} < locked epoch {}",
            block.epoch, locked.epoch
        );
        false
    }

    fn extends_locked(&self, block: &BlockHeader, ancestor_hash: Hash) -> bool {
        if block.block_hash() == ancestor_hash {
            return true;
        }
        let mut current_hash = block.prev_hash;
        for _ in 0..64 {
            if current_hash == ancestor_hash {
                return true;
            }

            let found = self
                .blocks
                .values()
                .find_map(|m| m.get(&current_hash));
            match found {
                Some(b) => current_hash = b.prev_hash,
                None => break,
            }
        }
        false
    }

    pub fn resolve_fork(&self, height: u64) -> Option<Hash> {
        let candidates = self.blocks.get(&height)?;

        if candidates.len() == 1 {
            return candidates.keys().next().copied();
        }

        let mut with_qc: Vec<(&Hash, &QuorumCertificate)> = candidates
            .keys()
            .filter_map(|h| self.qcs.get(h).map(|qc| (h, qc)))
            .collect();

        if with_qc.len() == 1 {
            return Some(*with_qc[0].0);
        }

        if with_qc.is_empty() {

            warn!("⚠️  Fork at height {} with no QCs — picking lex-smallest hash", height);
            return candidates.keys().min_by_key(|h| h.as_bytes()).copied();
        }

        warn!(
            "🚨 Byzantine equivocation detected at height {}: {} QCs",
            height,
            with_qc.len()
        );
        with_qc.sort_by(|a, b| {
            b.1.voter_count()
                .cmp(&a.1.voter_count())
                .then_with(|| a.0.as_bytes().cmp(b.0.as_bytes()))
        });
        Some(*with_qc[0].0)
    }

    pub fn get_canonical_head(&self) -> Option<&BlockHeader> {
        let head_hash = self.canonical_head?;
        self.blocks
            .values()
            .find_map(|m| m.get(&head_hash))
    }

    pub fn add_view_change(
        &mut self,
        msg: ViewChangeMsg,
        quorum: usize,
    ) -> PoCResult<Option<Option<QuorumCertificate>>> {
        if !msg.verify()? {
            return Err(PoCError::SignatureVerificationFailed(
                "ViewChangeMsg signature invalid".into(),
            ));
        }

        let msgs = self.view_changes.entry((msg.height, msg.new_round)).or_default();

        if msgs.iter().any(|m| m.sender == msg.sender) {
            return Ok(None);
        }

        debug!(
            "📩 ViewChange from {} for round {} ({}/{})",
            msg.sender,
            msg.new_round,
            msgs.len() + 1,
            quorum
        );
        msgs.push(msg);

        if msgs.len() >= quorum {
            let new_round = msgs[0].new_round;

            let best_qc = msgs
                .iter()
                .filter_map(|m| m.high_qc.as_ref())
                .max_by_key(|qc| (qc.epoch, qc.round))
                .cloned();

            info!(
                "🔄 View-change quorum for round {} — best high_qc: {:?}",
                new_round,
                best_qc.as_ref().map(|q| (q.epoch, q.round))
            );

            if let Some(ref qc) = best_qc {
                self.add_qc(qc.clone());
            }

            return Ok(Some(best_qc));
        }

        Ok(None)
    }

    pub fn prune_view_changes(&mut self, min_height: u64) {
        self.view_changes.retain(|&(h, _), _| h >= min_height);
    }

    pub fn highest_view_change_round(&self, height: u64) -> u32 {
        self.view_changes
            .keys()
            .filter(|&&(h, _)| h == height)
            .map(|&(_, r)| r)
            .max()
            .unwrap_or(0)
    }

    pub fn prune_blocks(&mut self, keep_from_height: u64) {
        self.blocks.retain(|&h, _| h >= keep_from_height);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bft::{BlockRoots, merkle_root};
    use ego_core::{Hash, KeyPair};

    fn make_header(height: u64, epoch: u64, round: u32, prev: Hash) -> BlockHeader {
        let kp = KeyPair::generate();
        let addr = ego_core::Address::from_public_key(&kp.ed25519_public_key());
        let mut h = BlockHeader::new(
            height, epoch, round as u64, prev, addr,
            BlockRoots::empty(),
            Hash::new([0u8; 32]),
            vec![],
        );
        h.sign(&kp, SigScheme::Ed25519).unwrap();
        h
    }

    fn make_qc(block_hash: Hash, height: u64, epoch: u64, round: u32, n_votes: usize) -> QuorumCertificate {
        use crate::bft::Vote;
        let votes: Vec<Vote> = (0..n_votes)
            .map(|_| {
                let kp = KeyPair::generate();
                Vote::new(block_hash, height, epoch, round, &kp, SigScheme::Ed25519).unwrap()
            })
            .collect();
        QuorumCertificate::new(block_hash, height, epoch, round, &votes)
    }

    #[test]
    fn test_is_safe_to_vote_no_lock() {
        let store = ForkChoiceStore::new();
        let h = make_header(1, 0, 0, Hash::new([0u8; 32]));
        assert!(store.is_safe_to_vote(&h));
    }

    #[test]
    fn test_is_safe_higher_epoch() {
        let mut store = ForkChoiceStore::new();
        let h1 = make_header(1, 2, 0, Hash::new([0u8; 32]));
        let qc = make_qc(h1.block_hash(), 1, 2, 0, 3);
        store.update_locked_qc(qc);

        let h2 = make_header(2, 3, 0, h1.block_hash());
        assert!(store.is_safe_to_vote(&h2));

        let h3 = make_header(2, 2, 0, Hash::new([9u8; 32]));
        assert!(!store.is_safe_to_vote(&h3));
    }

    #[test]
    fn test_resolve_fork_one_with_qc() {
        let mut store = ForkChoiceStore::new();
        let h1 = make_header(5, 1, 0, Hash::new([0u8; 32]));
        let h2 = make_header(5, 1, 0, Hash::new([1u8; 32]));
        store.add_block(h1.clone());
        store.add_block(h2.clone());

        let qc = make_qc(h1.block_hash(), 5, 1, 0, 3);
        store.add_qc(qc);

        assert_eq!(store.resolve_fork(5), Some(h1.block_hash()));
    }

    #[test]
    fn test_view_change_quorum() {
        let mut store = ForkChoiceStore::new();
        let quorum = 3;
        let kps: Vec<KeyPair> = (0..4).map(|_| KeyPair::generate()).collect();

        let mut result = None;
        for kp in &kps {
            let msg = ViewChangeMsg::new(1, 10, 2, None, kp, SigScheme::Ed25519).unwrap();
            result = store.add_view_change(msg, quorum).unwrap();
            if result.is_some() { break; }
        }
        assert!(result.is_some(), "quorum should be reached after 3 messages");
    }

    #[test]
    fn test_view_change_dedup() {
        let mut store = ForkChoiceStore::new();
        let kp = KeyPair::generate();
        let msg1 = ViewChangeMsg::new(1, 10, 2, None, &kp, SigScheme::Ed25519).unwrap();
        let msg2 = ViewChangeMsg::new(1, 10, 2, None, &kp, SigScheme::Ed25519).unwrap();
        let _ = store.add_view_change(msg1, 3).unwrap();
        let r = store.add_view_change(msg2, 3).unwrap();
        assert!(r.is_none(), "duplicate from same sender must be ignored");
    }
}
