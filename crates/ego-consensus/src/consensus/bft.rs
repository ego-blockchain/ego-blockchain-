use crate::consensus::fork_choice::{ForkChoiceStore, ViewChangeMsg};
use crate::error::{PoCError, PoCResult};
use ego_core::{Address, Hash, KeyPair, PublicKey, Signature, Timestamp};
use ego_core::crypto::{hash_data, hash_multiple};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{debug, info, warn};

pub const MICRO_SLOT_MS: u64 = 100;
pub const PROPOSE_TIMEOUT_MS: u64 = 500;
pub const VOTE_TIMEOUT_MS: u64 = 1_000;
pub const COMMIT_TIMEOUT_MS: u64 = 1_500;

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct BlockHeader {
    pub height: u64,
    pub epoch: u64,
    pub slot: u64,
    pub prev_hash: Hash,
    pub proposer: Address,
    pub tx_root: Hash,
    pub state_root: Hash,
    pub receipts_root: Hash,
    pub events_root_post: Hash,
    pub events_root_poc: Hash,
    pub rollup_root: Hash,
    pub da_root: Hash,
    pub vrf_output: Hash,
    pub vrf_proof: Vec<u8>,
    pub timestamp: Timestamp,
    pub signature: Signature,
    pub proposer_public_key: PublicKey,
}

#[derive(Debug, Clone)]
pub struct BlockRoots {
    pub tx_root: Hash,
    pub state_root: Hash,
    pub receipts_root: Hash,
    pub events_root_post: Hash,
    pub events_root_poc: Hash,
    pub rollup_root: Hash,
    pub da_root: Hash,
}

impl BlockRoots {
    pub fn empty() -> Self {
        let z = Hash::new([0u8; 32]);
        Self { tx_root: z, state_root: z, receipts_root: z, events_root_post: z, events_root_poc: z, rollup_root: z, da_root: z }
    }
    pub fn from_events(poc: &[Hash], post: &[Hash]) -> Self {
        Self { events_root_poc: merkle_root(poc), events_root_post: merkle_root(post), ..Self::empty() }
    }
}

impl BlockHeader {
    pub fn new(height: u64, epoch: u64, slot: u64, prev_hash: Hash, proposer: Address, r: BlockRoots, vrf_output: Hash, vrf_proof: Vec<u8>) -> Self {
        Self {
            height, epoch, slot, prev_hash, proposer,
            tx_root: r.tx_root, state_root: r.state_root, receipts_root: r.receipts_root,
            events_root_post: r.events_root_post, events_root_poc: r.events_root_poc,
            rollup_root: r.rollup_root, da_root: r.da_root,
            vrf_output, vrf_proof,
            timestamp: Timestamp::now(),
            signature: Signature::ed25519([0u8; 64]),
            proposer_public_key: PublicKey::ed25519([0u8; 32]),
        }
    }

    pub fn block_hash(&self) -> Hash {
        hash_multiple(&[
            &self.height.to_le_bytes(), &self.epoch.to_le_bytes(), &self.slot.to_le_bytes(),
            self.prev_hash.as_bytes(), self.proposer.as_bytes(),
            self.tx_root.as_bytes(), self.state_root.as_bytes(), self.receipts_root.as_bytes(),
            self.events_root_post.as_bytes(), self.events_root_poc.as_bytes(),
            self.rollup_root.as_bytes(), self.da_root.as_bytes(),
            self.vrf_output.as_bytes(), &self.timestamp.as_millis().to_le_bytes(),
        ])
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut d = b"ego/block/v1:".to_vec();
        d.extend_from_slice(self.block_hash().as_bytes());
        d
    }

    pub fn sign(&mut self, kp: &KeyPair) -> PoCResult<()> {
        self.proposer_public_key = kp.public_key();
        self.signature = kp.sign(&self.signing_bytes());
        Ok(())
    }

    pub fn verify_signature(&self) -> PoCResult<bool> {
        ego_core::verify_signature(&self.proposer_public_key, &self.signing_bytes(), &self.signature)
            .map_err(|e| PoCError::SignatureVerificationFailed(e.to_string()))
    }

    pub fn epoch_randomness(&self, region_id: &str) -> Hash {
        hash_multiple(&[self.vrf_output.as_bytes(), region_id.as_bytes(), &self.epoch.to_le_bytes(), &self.slot.to_le_bytes()])
    }

    pub fn compute_vrf_output(kp: &KeyPair, epoch: u64, slot: u64) -> (Hash, Vec<u8>) {
        let input = hash_multiple(&[kp.public_key().as_bytes(), &epoch.to_le_bytes(), &slot.to_le_bytes()]);
        let output = hash_multiple(&[b"ego/vrf/v1:", kp.public_key().as_bytes(), input.as_bytes()]);
        let proof = kp.sign(input.as_bytes()).as_bytes().to_vec();
        (output, proof)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct Vote {
    pub block_hash: Hash,
    pub height: u64,
    pub epoch: u64,
    pub round: u32,
    pub voter: Address,
    pub voter_public_key: PublicKey,
    pub signature: Signature,
    pub timestamp: Timestamp,
}

impl Vote {
    pub fn new(block_hash: Hash, height: u64, epoch: u64, round: u32, kp: &KeyPair) -> PoCResult<Self> {
        let msg = Self::msg(block_hash, height, epoch, round);
        Ok(Self {
            block_hash, height, epoch, round,
            voter: Address::from_public_key(&kp.public_key()),
            voter_public_key: kp.public_key(),
            signature: kp.sign(&msg),
            timestamp: Timestamp::now(),
        })
    }
    fn msg(block_hash: Hash, height: u64, epoch: u64, round: u32) -> Vec<u8> {
        let mut d = b"ego/vote/v1:".to_vec();
        d.extend_from_slice(block_hash.as_bytes());
        d.extend_from_slice(&height.to_le_bytes());
        d.extend_from_slice(&epoch.to_le_bytes());
        d.extend_from_slice(&round.to_le_bytes());
        d
    }
    pub fn verify(&self) -> PoCResult<bool> {
        ego_core::verify_signature(&self.voter_public_key, &Self::msg(self.block_hash, self.height, self.epoch, self.round), &self.signature)
            .map_err(|e| PoCError::SignatureVerificationFailed(e.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct QuorumCertificate {
    pub block_hash: Hash,
    pub height: u64,
    pub epoch: u64,
    pub round: u32,
    pub voters_bitmap: Vec<bool>,
    pub sigs_root: Hash,
    pub formed_at: Timestamp,
}

impl QuorumCertificate {
    pub fn new(block_hash: Hash, height: u64, epoch: u64, round: u32, votes: &[Vote]) -> Self {
        let sig_hashes: Vec<Hash> = votes.iter().map(|v| hash_data(v.signature.as_bytes())).collect();
        Self {
            block_hash, height, epoch, round,
            voters_bitmap: votes.iter().map(|_| true).collect(),
            sigs_root: merkle_root(&sig_hashes),
            formed_at: Timestamp::now(),
        }
    }
    pub fn voter_count(&self) -> usize { self.voters_bitmap.iter().filter(|&&v| v).count() }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoundPhase { Propose, Vote, Commit, Finalized, ViewChange }

#[derive(Debug, Clone)]
pub struct RoundState {
    pub height: u64,
    pub epoch: u64,
    pub round: u32,
    pub phase: RoundPhase,
    pub proposed_block: Option<BlockHeader>,
    pub votes: HashMap<Address, Vote>,
    pub qc: Option<QuorumCertificate>,
    pub phase_started_at: Timestamp,
}

impl RoundState {
    pub fn new(height: u64, epoch: u64, round: u32) -> Self {
        Self { height, epoch, round, phase: RoundPhase::Propose, proposed_block: None, votes: HashMap::new(), qc: None, phase_started_at: Timestamp::now() }
    }
    pub fn is_phase_timed_out(&self) -> bool {
        let elapsed = Timestamp::now().as_millis().saturating_sub(self.phase_started_at.as_millis());
        let t = match self.phase { RoundPhase::Propose => PROPOSE_TIMEOUT_MS, RoundPhase::Vote => VOTE_TIMEOUT_MS, RoundPhase::Commit => COMMIT_TIMEOUT_MS, _ => u64::MAX };
        elapsed > t
    }
    pub fn advance_phase(&mut self, next: RoundPhase) { self.phase = next; self.phase_started_at = Timestamp::now(); }
}

pub struct BftEngine {
    keypair: Arc<KeyPair>,
    address: Address,
    validator_set: Vec<Address>,
    finalized_blocks: Arc<RwLock<Vec<(BlockHeader, QuorumCertificate)>>>,
    current_round: Arc<RwLock<RoundState>>,
    current_epoch: Arc<RwLock<u64>>,
    current_height: Arc<RwLock<u64>>,
    vrf_outputs: Arc<RwLock<HashMap<u64, Hash>>>,

    fork_choice: Arc<RwLock<ForkChoiceStore>>,
}

impl BftEngine {
    pub fn new(keypair: KeyPair, validator_set: Vec<Address>) -> Self {
        let address = Address::from_public_key(&keypair.public_key());
        Self {
            keypair: Arc::new(keypair), address, validator_set,
            finalized_blocks: Arc::new(RwLock::new(Vec::new())),
            current_round: Arc::new(RwLock::new(RoundState::new(0, 0, 0))),
            current_epoch: Arc::new(RwLock::new(0)),
            current_height: Arc::new(RwLock::new(0)),
            vrf_outputs: Arc::new(RwLock::new(HashMap::new())),
            fork_choice: Arc::new(RwLock::new(ForkChoiceStore::new())),
        }
    }

    pub fn quorum_size(&self) -> usize { (2 * self.validator_set.len()) / 3 + 1 }

    pub fn is_proposer(&self) -> bool {
        if self.validator_set.is_empty() { return false; }
        let s = self.current_round.read().unwrap();
        let idx = ((s.height + s.round as u64) as usize) % self.validator_set.len();
        self.validator_set[idx] == self.address
    }

    pub fn propose_block(&self, roots: BlockRoots) -> PoCResult<BlockHeader> {
        let epoch = *self.current_epoch.read().unwrap();
        let height = *self.current_height.read().unwrap();
        let slot = Timestamp::now().as_millis() / MICRO_SLOT_MS;

        let prev_hash = {
            let fc = self.fork_choice.read().unwrap();
            fc.get_canonical_head()
                .map(|b| b.block_hash())
                .unwrap_or_else(|| {
                    self.finalized_blocks.read().unwrap()
                        .last()
                        .map(|(h, _)| h.block_hash())
                        .unwrap_or(Hash::new([0u8; 32]))
                })
        };

        let (vrf_output, vrf_proof) = BlockHeader::compute_vrf_output(&self.keypair, epoch, slot);
        self.vrf_outputs.write().unwrap().insert(epoch, vrf_output);
        let mut header = BlockHeader::new(height, epoch, slot, prev_hash, self.address, roots, vrf_output, vrf_proof);
        header.sign(&self.keypair)?;

        self.fork_choice.write().unwrap().add_block(header.clone());

        {
            let mut s = self.current_round.write().unwrap();
            s.proposed_block = Some(header.clone());
            s.advance_phase(RoundPhase::Vote);
        }
        info!("🗳️  Proposed block h={} epoch={} (proposer {})", height, epoch, self.address);
        Ok(header)
    }

    pub fn receive_proposal(&self, header: &BlockHeader) -> PoCResult<Option<Vote>> {
        let height = *self.current_height.read().unwrap();
        if header.height != height { return Ok(None); }

        let round = self.current_round.read().unwrap().round;
        let idx = ((height + round as u64) as usize) % self.validator_set.len().max(1);
        if self.validator_set.get(idx) != Some(&header.proposer) {
            warn!("Unexpected proposer {}", header.proposer);
            return Ok(None);
        }
        if !header.verify_signature()? { return Ok(None); }
        if Timestamp::now().as_millis().saturating_sub(header.timestamp.as_millis()) > 30_000 { return Ok(None); }

        {
            let mut fc = self.fork_choice.write().unwrap();
            fc.add_block(header.clone());
            if !fc.is_safe_to_vote(header) {
                warn!("🛑 Refusing to vote: block h={} epoch={} violates safety rule", header.height, header.epoch);
                return Ok(None);
            }
        }

        let round = {
            let mut s = self.current_round.write().unwrap();
            s.proposed_block = Some(header.clone());
            s.advance_phase(RoundPhase::Vote);
            s.round
        };
        let vote = Vote::new(header.block_hash(), header.height, header.epoch, round, &self.keypair)?;
        debug!("✅ Cast vote for h={} (voter {})", header.height, self.address);
        Ok(Some(vote))
    }

    pub fn receive_vote(&self, vote: &Vote) -> PoCResult<Option<QuorumCertificate>> {
        if !vote.verify()? { return Ok(None); }

        let (state_h, state_bh) = {
            let s = self.current_round.read().unwrap();
            let bh = s.proposed_block.as_ref().map(|b| b.block_hash()).unwrap_or(Hash::new([0u8; 32]));
            (s.height, bh)
        };
        if vote.height != state_h || vote.block_hash != state_bh { return Ok(None); }

        let mut s = self.current_round.write().unwrap();
        s.votes.insert(vote.voter, vote.clone());
        if s.votes.len() >= self.quorum_size() && s.qc.is_none() {
            let votes: Vec<Vote> = s.votes.values().cloned().collect();
            let qc = QuorumCertificate::new(vote.block_hash, vote.height, vote.epoch, vote.round, &votes);
            s.qc = Some(qc.clone());
            s.advance_phase(RoundPhase::Commit);
            info!("🏆 QC formed h={} {}/{} votes", vote.height, qc.voter_count(), self.validator_set.len());

            self.fork_choice.write().unwrap().add_qc(qc.clone());
            return Ok(Some(qc));
        }
        Ok(None)
    }

    pub fn finalize_block(&self, header: BlockHeader, qc: QuorumCertificate) -> PoCResult<()> {
        if qc.block_hash != header.block_hash() {
            return Err(PoCError::ValidationFailed("QC block_hash mismatch".to_string()));
        }
        if qc.voter_count() < self.quorum_size() {
            return Err(PoCError::ValidationFailed(format!("QC insufficient votes {}/{}", qc.voter_count(), self.validator_set.len())));
        }
        let new_height = header.height + 1;
        let new_epoch = header.epoch + 1;
        {
            let mut f = self.finalized_blocks.write().unwrap();
            f.push((header.clone(), qc.clone()));
            if f.len() > 1024 { f.remove(0); }
        }

        {
            let mut fc = self.fork_choice.write().unwrap();
            fc.update_locked_qc(qc.clone());

            fc.prune_blocks(header.height.saturating_sub(64));
            fc.prune_view_changes(0);
        }

        *self.current_height.write().unwrap() = new_height;
        *self.current_epoch.write().unwrap() = new_epoch;
        *self.current_round.write().unwrap() = RoundState::new(new_height, new_epoch, 0);
        info!("✅ Finalized block h={} epoch={}", header.height, header.epoch);
        Ok(())
    }

    pub fn trigger_view_change(&self) -> PoCResult<ViewChangeMsg> {
        let (new_round, height, epoch, high_qc) = {
            let s = self.current_round.read().unwrap();
            let fc = self.fork_choice.read().unwrap();
            (s.round + 1, s.height, s.epoch, fc.high_qc.clone())
        };
        let msg = ViewChangeMsg::new(new_round, height, epoch, high_qc, &self.keypair)?;
        warn!("⏱️  View change triggered: round {} → {}", new_round - 1, new_round);
        Ok(msg)
    }

    pub fn receive_view_change(&self, msg: ViewChangeMsg) -> PoCResult<Option<u32>> {
        let quorum = self.quorum_size();
        let new_round = msg.new_round;
        let result = self.fork_choice.write().unwrap().add_view_change(msg, quorum)?;

        if let Some(best_high_qc) = result {

            {
                let mut s = self.current_round.write().unwrap();
                let height = s.height;
                let epoch = s.epoch;
                *s = RoundState::new(height, epoch, new_round);
            }

            if let Some(qc) = best_high_qc {
                self.fork_choice.write().unwrap().add_qc(qc);
            }
            info!("🚀 Starting new round {} after view change", new_round);
            return Ok(Some(new_round));
        }
        Ok(None)
    }

    pub fn get_canonical_head(&self) -> Option<BlockHeader> {
        self.fork_choice.read().unwrap().get_canonical_head().cloned()
    }

    pub fn resolve_fork(&self, height: u64) -> Option<Hash> {
        self.fork_choice.read().unwrap().resolve_fork(height)
    }

    pub fn get_vrf_output(&self, epoch: u64) -> Option<Hash> { self.vrf_outputs.read().unwrap().get(&epoch).copied() }
    pub fn get_current_height(&self) -> u64 { *self.current_height.read().unwrap() }
    pub fn get_current_epoch(&self) -> u64 { *self.current_epoch.read().unwrap() }
    pub fn get_latest_finalized_block(&self) -> Option<(BlockHeader, QuorumCertificate)> { self.finalized_blocks.read().unwrap().last().cloned() }
}

pub fn merkle_root(hashes: &[Hash]) -> Hash {
    if hashes.is_empty() { return Hash::new([0u8; 32]); }
    if hashes.len() == 1 { return hashes[0]; }
    let mut layer = hashes.to_vec();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity((layer.len() + 1) / 2);
        let mut i = 0;
        while i < layer.len() {
            let l = layer[i];
            let r = if i + 1 < layer.len() { layer[i + 1] } else { layer[i] };
            next.push(hash_multiple(&[l.as_bytes(), r.as_bytes()]));
            i += 2;
        }
        layer = next;
    }
    layer[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::KeyPair;

    fn make_engine(n: usize) -> (BftEngine, Vec<KeyPair>) {
        let kps: Vec<KeyPair> = (0..n).map(|_| KeyPair::generate()).collect();
        let vals: Vec<Address> = kps.iter().map(|kp| Address::from_public_key(&kp.public_key())).collect();
        (BftEngine::new(kps[0].clone(), vals), kps)
    }

    #[test] fn test_quorum_size() { let (e, _) = make_engine(4); assert_eq!(e.quorum_size(), 3); }

    #[test] fn test_block_hash_stable() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public_key());
        let h = BlockHeader::new(1, 0, 0, Hash::new([0u8; 32]), addr, BlockRoots::empty(), Hash::new([1u8; 32]), vec![]);
        assert_eq!(h.block_hash(), h.block_hash());
    }

    #[test] fn test_sign_verify() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public_key());
        let mut h = BlockHeader::new(1, 0, 0, Hash::new([0u8; 32]), addr, BlockRoots::empty(), Hash::new([1u8; 32]), vec![]);
        h.sign(&kp).unwrap();
        assert!(h.verify_signature().unwrap());
    }

    #[test] fn test_vote_verify() {
        let kp = KeyPair::generate();
        let v = Vote::new(Hash::new([1u8; 32]), 1, 0, 0, &kp).unwrap();
        assert!(v.verify().unwrap());
    }

    #[test] fn test_epoch_randomness() {
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public_key());
        let h = BlockHeader::new(1, 5, 3, Hash::new([0u8; 32]), addr, BlockRoots::empty(), Hash::new([7u8; 32]), vec![]);
        assert_eq!(h.epoch_randomness("r1"), h.epoch_randomness("r1"));
        assert_ne!(h.epoch_randomness("r1"), h.epoch_randomness("r2"));
    }

    #[test] fn test_merkle_root() {
        assert_eq!(merkle_root(&[]), Hash::new([0u8; 32]));
        let h = Hash::new([1u8; 32]);
        assert_eq!(merkle_root(&[h]), h);
        let hs = vec![Hash::new([1u8; 32]), Hash::new([2u8; 32]), Hash::new([3u8; 32])];
        assert_eq!(merkle_root(&hs), merkle_root(&hs));
    }

    #[test] fn test_full_bft_round() {
        let (engine, kps) = make_engine(4);
        assert!(engine.is_proposer());
        let header = engine.propose_block(BlockRoots::empty()).unwrap();
        let mut qc_opt = None;
        for kp in &kps {
            let vote = Vote::new(header.block_hash(), header.height, header.epoch, 0, kp).unwrap();
            qc_opt = engine.receive_vote(&vote).unwrap();
            if qc_opt.is_some() { break; }
        }
        let qc = qc_opt.unwrap();
        assert!(qc.voter_count() >= engine.quorum_size());
        engine.finalize_block(header, qc).unwrap();
        assert_eq!(engine.get_current_height(), 1);
    }
}
