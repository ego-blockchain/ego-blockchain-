use ego_stark::merkle::{MerklePath, MerkleTree};
use ego_stark::note::leaf_for as stark_leaf_for;
use ego_stark::prove::{default_options, prove_withdrawal as stark_prove, verify_withdrawal};
use ego_stark::{digest_from_bytes, digest_to_bytes, Digest};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use winterfell::Proof;

pub use ego_stark::air::POOL_TREE_DEPTH;

pub const ROOT_HISTORY: usize = 100;

pub const DENOMINATIONS_UEGOC: [u64; 5] = [
    1_000_000,
    10_000_000,
    100_000_000,
    1_000_000_000,
    10_000_000_000,
];

pub fn is_denomination(value_uegoc: u64) -> bool {
    DENOMINATIONS_UEGOC.contains(&value_uegoc)
}

pub fn denominate(amount_uegoc: u64) -> (Vec<u64>, u64) {
    let mut notes = Vec::new();
    let mut left = amount_uegoc;
    for d in DENOMINATIONS_UEGOC.iter().rev() {
        while left >= *d {
            notes.push(*d);
            left -= d;
        }
    }
    (notes, left)
}

pub fn to_digest(bytes: &[u8; 32]) -> Result<Digest, String> {
    digest_from_bytes(bytes).ok_or_else(|| "not a canonical field digest".to_string())
}

pub fn from_digest(d: &Digest) -> [u8; 32] {
    digest_to_bytes(d)
}

pub fn leaf_for(commitment: &[u8; 32], amount_uegoc: u64) -> [u8; 32] {
    let c = to_digest(commitment).expect("a stored commitment is canonical");
    from_digest(&stark_leaf_for(&c, amount_uegoc).expect("a denominated amount fits the field"))
}

pub fn recipient_digest(address: &str) -> [u8; 32] {
    *ego_core::hash_data(address.as_bytes()).as_bytes()
}

pub fn withdrawal_binding(recipient: &[u8; 32], fee_uegoc: u64) -> [u8; 32] {
    from_digest(
        &ego_stark::note::withdrawal_binding(recipient, fee_uegoc)
            .expect("a fee below a denomination fits the field"),
    )
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Note {
    inner: ego_stark::Note,
}

impl Note {
    pub fn new(value_uegoc: u64, owner_secret: [u8; 32], rho: [u8; 32]) -> Self {
        Self { inner: ego_stark::Note { value_uegoc, owner_secret, rho } }
    }

    pub fn random<R: RngCore + CryptoRng>(value_uegoc: u64, rng: &mut R) -> Self {
        Self { inner: ego_stark::Note::random(value_uegoc, rng) }
    }

    pub fn value_uegoc(&self) -> u64 {
        self.inner.value_uegoc
    }

    pub fn inner(&self) -> &ego_stark::Note {
        &self.inner
    }

    pub fn commitment(&self) -> [u8; 32] {
        from_digest(&self.inner.commitment().expect("a note's value is denominated"))
    }

    pub fn nullifier(&self) -> [u8; 32] {
        from_digest(&self.inner.nullifier())
    }

    pub fn leaf(&self) -> [u8; 32] {
        from_digest(&self.inner.leaf().expect("a note's value is denominated"))
    }
}

#[derive(Debug, PartialEq)]
pub enum PoolError {
    NullifierAlreadySeen,
    UnknownRoot,
    InvalidProof,
    PoolUnderfunded { balance: u64, requested: u64 },
    InvalidAmount,
    DuplicateCommitment,
    TreeFull,
}

#[derive(Debug, Clone)]
pub struct ShieldedPool {
    depth: usize,
    leaves: Vec<[u8; 32]>,
    commitment_set: HashSet<[u8; 32]>,
    tree: MerkleTree,
    nullifiers: HashSet<[u8; 32]>,
    balance_uegoc: u64,
    recent_roots: Vec<[u8; 32]>,
}

impl Default for ShieldedPool {
    fn default() -> Self {
        Self::new(POOL_TREE_DEPTH)
    }
}

impl ShieldedPool {
    pub fn new(depth: usize) -> Self {
        let tree = MerkleTree::new(depth);
        let empty_root = from_digest(&tree.root());
        let mut pool = Self {
            depth,
            leaves: Vec::new(),
            commitment_set: HashSet::new(),
            tree,
            nullifiers: HashSet::new(),
            balance_uegoc: 0,
            recent_roots: Vec::new(),
        };
        pool.remember_root(empty_root);
        pool
    }

    pub fn from_leaves(depth: usize, leaves: &[[u8; 32]]) -> Result<Self, String> {
        let mut pool = Self::new(depth);
        for leaf in leaves {
            pool.append_leaf(*leaf)?;
        }
        Ok(pool)
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn balance(&self) -> u64 {
        self.balance_uegoc
    }

    pub fn commitment_count(&self) -> usize {
        self.leaves.len()
    }

    pub fn nullifier_count(&self) -> usize {
        self.nullifiers.len()
    }

    pub fn leaves(&self) -> &[[u8; 32]] {
        &self.leaves
    }

    pub fn contains_commitment(&self, c: &[u8; 32]) -> bool {
        self.commitment_set.contains(c)
    }

    pub fn is_spent(&self, nf: &[u8; 32]) -> bool {
        self.nullifiers.contains(nf)
    }

    pub fn current_root(&self) -> [u8; 32] {
        *self.recent_roots.last().expect("a pool always has its empty root")
    }

    pub fn is_known_root(&self, root: &[u8; 32]) -> bool {
        self.recent_roots.contains(root)
    }

    fn remember_root(&mut self, root: [u8; 32]) {
        self.recent_roots.push(root);
        if self.recent_roots.len() > ROOT_HISTORY {
            self.recent_roots.remove(0);
        }
    }

    fn append_leaf(&mut self, leaf: [u8; 32]) -> Result<usize, String> {
        let index = self.tree.insert(to_digest(&leaf)?)?;
        self.leaves.push(leaf);
        let root = from_digest(&self.tree.root());
        self.remember_root(root);
        Ok(index)
    }

    pub fn extend_from_leaves(&mut self, leaves: &[[u8; 32]]) -> Result<(), String> {
        if leaves.len() < self.leaves.len() || leaves[..self.leaves.len()] != self.leaves[..] {
            return Err("leaf history diverged from this pool".into());
        }
        for leaf in &leaves[self.leaves.len()..] {
            self.append_leaf(*leaf)?;
        }
        Ok(())
    }

    pub fn merkle_path(&self, index: usize) -> Result<MerklePath, String> {
        self.tree.path(index)
    }

    pub fn deposit(&mut self, commitment: [u8; 32], value_uegoc: u64) -> Result<usize, PoolError> {
        if value_uegoc == 0 {
            return Err(PoolError::InvalidAmount);
        }
        let new_balance = self
            .balance_uegoc
            .checked_add(value_uegoc)
            .ok_or(PoolError::InvalidAmount)?;
        if self.commitment_set.contains(&commitment) {
            return Err(PoolError::DuplicateCommitment);
        }
        if self.leaves.len() >= (1usize << self.depth) {
            return Err(PoolError::TreeFull);
        }
        let index = self
            .append_leaf(leaf_for(&commitment, value_uegoc))
            .map_err(|_| PoolError::TreeFull)?;
        self.commitment_set.insert(commitment);
        self.balance_uegoc = new_balance;
        Ok(index)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn withdraw(
        &mut self,
        proof_bytes: &[u8],
        root: [u8; 32],
        nullifier: [u8; 32],
        amount_uegoc: u64,
        recipient: [u8; 32],
        fee_uegoc: u64,
    ) -> Result<(), PoolError> {
        if amount_uegoc == 0 {
            return Err(PoolError::InvalidAmount);
        }
        if !self.is_known_root(&root) {
            return Err(PoolError::UnknownRoot);
        }
        if self.nullifiers.contains(&nullifier) {
            return Err(PoolError::NullifierAlreadySeen);
        }
        if !verify_proof_bytes(proof_bytes, root, nullifier, amount_uegoc, recipient, fee_uegoc) {
            return Err(PoolError::InvalidProof);
        }
        if amount_uegoc > self.balance_uegoc {
            return Err(PoolError::PoolUnderfunded {
                balance: self.balance_uegoc,
                requested: amount_uegoc,
            });
        }
        self.nullifiers.insert(nullifier);
        self.balance_uegoc -= amount_uegoc;
        Ok(())
    }

    pub fn apply_withdrawal(&mut self, w: &Withdrawal) -> Result<(), PoolError> {
        self.withdraw(&w.proof, w.root, w.nullifier, w.amount_uegoc, w.recipient, w.fee_uegoc)
    }
}

pub const MAX_PROOF_BYTES: usize = 256 * 1024;

fn decode_proof(bytes: &[u8]) -> Option<Proof> {
    if bytes.is_empty() || bytes.len() > MAX_PROOF_BYTES {
        return None;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| Proof::from_bytes(bytes).ok()))
        .ok()
        .flatten()
}

pub fn verify_proof_bytes(
    proof_bytes: &[u8],
    root: [u8; 32],
    nullifier: [u8; 32],
    amount_uegoc: u64,
    recipient: [u8; 32],
    fee_uegoc: u64,
) -> bool {
    let (Ok(root_d), Ok(nullifier_d)) = (to_digest(&root), to_digest(&nullifier)) else {
        return false;
    };
    let Ok(binding) = ego_stark::note::withdrawal_binding(&recipient, fee_uegoc) else {
        return false;
    };
    let Some(proof) = decode_proof(proof_bytes) else {
        return false;
    };
    let public = ego_stark::air::PublicInputs {
        root: root_d,
        nullifier: nullifier_d,
        amount: amount_uegoc,
        binding,
    };
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_withdrawal(proof, public, &default_options()).is_ok()
    }))
    .unwrap_or(false)
}

#[derive(Debug, Clone)]
pub struct Withdrawal {
    pub proof: Vec<u8>,
    pub root: [u8; 32],
    pub nullifier: [u8; 32],
    pub amount_uegoc: u64,
    pub recipient: [u8; 32],
    pub fee_uegoc: u64,
}

pub fn prove_withdrawal(
    pool: &ShieldedPool,
    note: &Note,
    leaf_index: usize,
    recipient: [u8; 32],
    fee_uegoc: u64,
) -> Result<Withdrawal, String> {
    if pool.leaves().get(leaf_index) != Some(&note.leaf()) {
        return Err(format!(
            "leaf {leaf_index} does not hold this note; it was not deposited at its own value"
        ));
    }
    if fee_uegoc >= note.value_uegoc() {
        return Err(format!(
            "fee {fee_uegoc} uEGOC would consume the whole {} uEGOC note",
            note.value_uegoc()
        ));
    }
    let path = pool.merkle_path(leaf_index)?;
    let w = stark_prove(note.inner(), &path, &recipient, fee_uegoc, default_options())?;
    Ok(Withdrawal {
        proof: w.proof.to_bytes(),
        root: from_digest(&w.public.root),
        nullifier: from_digest(&w.public.nullifier),
        amount_uegoc: w.public.amount,
        recipient,
        fee_uegoc,
    })
}

pub fn is_enabled() -> bool {
    match std::env::var("EGO_SHIELDED_POOL") {
        Ok(v) => {
            let v = v.trim();
            !(v == "0" || v.eq_ignore_ascii_case("off") || v.eq_ignore_ascii_case("false"))
        }
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const DEPTH: usize = POOL_TREE_DEPTH;
    const AMOUNT: u64 = 1_000_000;
    const FEE: u64 = 1_000;

    fn rng() -> StdRng {
        StdRng::from_entropy()
    }

    fn note(value: u64, s: u8, r: u8) -> Note {
        Note::new(value, [s; 32], [r; 32])
    }

    fn recipient() -> [u8; 32] {
        [0xAB; 32]
    }

    fn funded(value: u64) -> (ShieldedPool, Note, usize) {
        let mut pool = ShieldedPool::new(DEPTH);
        pool.deposit(note(AMOUNT, 0x11, 0x11).commitment(), AMOUNT).unwrap();
        pool.deposit(note(AMOUNT, 0x22, 0x22).commitment(), AMOUNT).unwrap();
        let n = note(value, 1, 1);
        let index = pool.deposit(n.commitment(), value).unwrap();
        (pool, n, index)
    }

    fn withdrawal(pool: &ShieldedPool, n: &Note, index: usize) -> Withdrawal {
        prove_withdrawal(pool, n, index, recipient(), FEE).unwrap()
    }

    #[test]
    fn a_commitment_hides_its_owner() {
        assert_ne!(note(AMOUNT, 1, 1).commitment(), note(AMOUNT, 2, 1).commitment());
        assert_ne!(note(AMOUNT, 1, 1).commitment(), note(AMOUNT, 1, 2).commitment());
    }

    #[test]
    fn the_leaf_binds_the_commitment_to_one_amount() {
        let c = note(AMOUNT, 3, 4).commitment();
        assert_ne!(leaf_for(&c, AMOUNT), leaf_for(&c, AMOUNT * 10));
        assert_ne!(leaf_for(&c, AMOUNT), c);
        assert_eq!(leaf_for(&c, AMOUNT), note(AMOUNT, 3, 4).leaf());
    }

    #[test]
    fn the_nullifier_does_not_depend_on_the_value() {
        assert_eq!(note(AMOUNT, 1, 1).nullifier(), note(AMOUNT * 10, 1, 1).nullifier());
    }

    #[test]
    fn digests_round_trip_through_bytes() {
        let c = note(AMOUNT, 5, 6).commitment();
        assert_eq!(from_digest(&to_digest(&c).unwrap()), c);
        assert!(to_digest(&[0xFF; 32]).is_err());
    }

    #[test]
    fn denominate_splits_largest_first_and_reports_the_remainder() {
        let (notes, left) = denominate(1_234_500_000);
        assert_eq!(notes.iter().sum::<u64>(), 1_234_000_000);
        assert_eq!(left, 500_000);
        assert_eq!(denominate(999_999), (vec![], 999_999));
        for d in DENOMINATIONS_UEGOC {
            assert!(is_denomination(d));
            assert!(!is_denomination(d + 1));
        }
    }

    #[test]
    fn a_new_pool_knows_its_empty_root() {
        let pool = ShieldedPool::new(DEPTH);
        assert!(pool.is_known_root(&pool.current_root()));
        assert_eq!(pool.balance(), 0);
    }

    #[test]
    fn a_deposit_returns_its_index_and_moves_the_root() {
        let mut pool = ShieldedPool::new(DEPTH);
        let before = pool.current_root();
        assert_eq!(pool.deposit(note(AMOUNT, 1, 1).commitment(), AMOUNT).unwrap(), 0);
        assert_eq!(pool.deposit(note(AMOUNT, 2, 2).commitment(), AMOUNT).unwrap(), 1);
        assert_ne!(pool.current_root(), before);
        assert!(pool.is_known_root(&before));
    }

    #[test]
    fn the_same_commitment_cannot_be_deposited_twice() {
        let mut pool = ShieldedPool::new(DEPTH);
        let c = note(AMOUNT, 1, 1).commitment();
        pool.deposit(c, AMOUNT).unwrap();
        assert_eq!(pool.deposit(c, AMOUNT), Err(PoolError::DuplicateCommitment));
        assert_eq!(pool.balance(), AMOUNT);
    }

    #[test]
    fn zero_is_not_a_deposit() {
        let mut pool = ShieldedPool::new(DEPTH);
        assert_eq!(pool.deposit([1u8; 32], 0), Err(PoolError::InvalidAmount));
    }

    #[test]
    fn a_pool_rebuilt_from_leaves_has_the_same_root() {
        let (pool, _, _) = funded(AMOUNT);
        let rebuilt = ShieldedPool::from_leaves(DEPTH, pool.leaves()).unwrap();
        assert_eq!(rebuilt.current_root(), pool.current_root());
        assert_eq!(rebuilt.commitment_count(), 3);
    }

    #[test]
    fn a_proving_pool_extends_instead_of_rebuilding() {
        let (full, _, _) = funded(AMOUNT);
        let mut partial = ShieldedPool::from_leaves(DEPTH, &full.leaves()[..1]).unwrap();
        partial.extend_from_leaves(full.leaves()).unwrap();
        assert_eq!(partial.current_root(), full.current_root());
        partial.extend_from_leaves(full.leaves()).unwrap();
        assert!(partial.extend_from_leaves(&full.leaves()[..1]).is_err());
        let mut forked = full.leaves().to_vec();
        forked[0] = note(AMOUNT, 9, 9).leaf();
        assert!(partial.extend_from_leaves(&forked).is_err());
    }

    #[test]
    fn an_honest_withdrawal_verifies_and_pays_out_the_whole_note() {
        let (mut pool, n, i) = funded(AMOUNT);
        let w = withdrawal(&pool, &n, i);
        assert_eq!(w.amount_uegoc, AMOUNT);
        assert_eq!(w.nullifier, n.nullifier());
        assert_eq!(pool.apply_withdrawal(&w), Ok(()));
        assert_eq!(pool.balance(), AMOUNT * 2);
        assert!(pool.is_spent(&w.nullifier));
    }

    #[test]
    fn the_same_proof_cannot_be_replayed() {
        let (mut pool, n, i) = funded(AMOUNT);
        let w = withdrawal(&pool, &n, i);
        assert_eq!(pool.apply_withdrawal(&w), Ok(()));
        assert_eq!(pool.apply_withdrawal(&w), Err(PoolError::NullifierAlreadySeen));
        assert_eq!(pool.balance(), AMOUNT * 2);
    }

    #[test]
    fn a_proof_against_a_recent_root_survives_a_later_deposit() {
        let (mut pool, n, i) = funded(AMOUNT);
        let w = withdrawal(&pool, &n, i);
        pool.deposit(note(AMOUNT, 0x33, 0x33).commitment(), AMOUNT).unwrap();
        assert_ne!(pool.current_root(), w.root);
        assert_eq!(pool.apply_withdrawal(&w), Ok(()));
    }

    #[test]
    fn a_root_the_pool_never_had_is_refused() {
        let (mut pool, n, i) = funded(AMOUNT);
        let mut w = withdrawal(&pool, &n, i);
        w.root = note(AMOUNT, 0xEE, 0xEE).leaf();
        assert_eq!(pool.apply_withdrawal(&w), Err(PoolError::UnknownRoot));
    }

    #[test]
    fn changing_the_amount_after_proving_is_refused() {
        let (mut pool, n, i) = funded(AMOUNT);
        let mut w = withdrawal(&pool, &n, i);
        w.amount_uegoc = AMOUNT * 10;
        assert_eq!(pool.apply_withdrawal(&w), Err(PoolError::InvalidProof));
        assert!(!pool.is_spent(&w.nullifier));
    }

    #[test]
    fn changing_the_recipient_after_proving_is_refused() {
        let (mut pool, n, i) = funded(AMOUNT);
        let mut w = withdrawal(&pool, &n, i);
        w.recipient = [0xCD; 32];
        assert_eq!(pool.apply_withdrawal(&w), Err(PoolError::InvalidProof));
    }

    #[test]
    fn changing_the_fee_after_proving_is_refused() {
        let (mut pool, n, i) = funded(AMOUNT);
        let mut w = withdrawal(&pool, &n, i);
        w.fee_uegoc = FEE + 1;
        assert_eq!(pool.apply_withdrawal(&w), Err(PoolError::InvalidProof));
        w.fee_uegoc = FEE;
        assert_eq!(pool.apply_withdrawal(&w), Ok(()));
    }

    #[test]
    fn a_nullifier_for_a_different_note_is_refused() {
        let (mut pool, n, i) = funded(AMOUNT);
        let mut w = withdrawal(&pool, &n, i);
        w.nullifier = note(AMOUNT, 0x11, 0x11).nullifier();
        assert_eq!(pool.apply_withdrawal(&w), Err(PoolError::InvalidProof));
    }

    #[test]
    fn a_malformed_proof_is_refused_rather_than_panicking() {
        let (mut pool, n, i) = funded(AMOUNT);
        let mut w = withdrawal(&pool, &n, i);
        w.proof = vec![0u8; 64];
        assert_eq!(pool.apply_withdrawal(&w), Err(PoolError::InvalidProof));
        w.proof = Vec::new();
        assert_eq!(pool.apply_withdrawal(&w), Err(PoolError::InvalidProof));
    }

    #[test]
    fn the_prover_refuses_a_leaf_that_does_not_hold_the_note() {
        let (pool, n, _) = funded(AMOUNT);
        assert!(prove_withdrawal(&pool, &n, 0, recipient(), FEE).is_err());
    }

    #[test]
    fn the_prover_refuses_a_fee_that_eats_the_note() {
        let (pool, n, i) = funded(AMOUNT);
        assert!(prove_withdrawal(&pool, &n, i, recipient(), AMOUNT).is_err());
    }

    #[test]
    fn a_note_deposited_for_less_than_it_claims_cannot_be_proven() {
        let mut pool = ShieldedPool::new(DEPTH);
        let n = note(10_000_000, 5, 5);
        let index = pool.deposit(n.commitment(), AMOUNT).unwrap();
        assert_eq!(pool.balance(), AMOUNT);
        assert_ne!(pool.leaves()[index], n.leaf());
        assert!(prove_withdrawal(&pool, &n, index, recipient(), FEE).is_err());
    }

    #[test]
    fn spending_leaves_the_commitment_in_place() {
        let (mut pool, n, i) = funded(AMOUNT);
        let before = pool.commitment_count();
        let w = withdrawal(&pool, &n, i);
        pool.apply_withdrawal(&w).unwrap();
        assert_eq!(pool.commitment_count(), before);
        assert!(pool.contains_commitment(&n.commitment()));
    }

    #[test]
    fn the_client_pool_is_available_by_default_and_can_be_switched_off() {
        std::env::remove_var("EGO_SHIELDED_POOL");
        assert!(is_enabled(), "shielding must be reachable without setting an env var");

        for off in ["0", "off", "OFF", "false", "False", " off "] {
            std::env::set_var("EGO_SHIELDED_POOL", off);
            assert!(!is_enabled(), "{off:?} must switch the pool off");
        }
        for on in ["1", "on", "yes", "unaudited-testnet-only"] {
            std::env::set_var("EGO_SHIELDED_POOL", on);
            assert!(is_enabled(), "{on:?} must leave the pool on");
        }
        std::env::remove_var("EGO_SHIELDED_POOL");
    }

    #[test]
    fn the_consensus_rule_is_not_switched_on_by_the_client_flag() {
        std::env::remove_var("EGO_SHIELDED_POOL");
        std::env::remove_var("EGO_SHIELDED_POOL_HEIGHT");
        assert!(is_enabled(), "client gate is on");
        assert!(
            !crate::shielded_chain::rule_active(u64::MAX),
            "the consensus rule must stay off until activated network-wide: a node that              accepts shield transactions while its peers reject them forks the chain",
        );
    }

    #[test]
    fn random_notes_do_not_repeat() {
        let mut r = rng();
        let a = Note::random(AMOUNT, &mut r);
        let b = Note::random(AMOUNT, &mut r);
        assert_ne!(a.commitment(), b.commitment());
        assert_ne!(a.nullifier(), b.nullifier());
    }

    #[test]
    fn there_is_no_trusted_setup_to_get_wrong() {
        let (pool, n, i) = funded(AMOUNT);
        let w = prove_withdrawal(&pool, &n, i, recipient(), FEE).unwrap();
        assert!(
            verify_proof_bytes(&w.proof, w.root, w.nullifier, w.amount_uegoc, w.recipient, w.fee_uegoc),
            "proving and verifying take no key material at all"
        );
    }
}
