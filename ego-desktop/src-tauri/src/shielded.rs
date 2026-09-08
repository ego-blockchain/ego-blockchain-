use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, PrimeField};
use ego_zk::merkle::{MerklePath, MerkleTree, POOL_TREE_DEPTH};
use ego_zk::withdraw_circuit::{self, Proof, ProvingKey, VerifyingKey, WithdrawCircuit};
use light_poseidon::{Poseidon, PoseidonHasher};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const COMMITMENT_DOMAIN: u64 = ego_zk::poseidon_gadget::SHIELDED_COMMITMENT_DOMAIN;
const NULLIFIER_DOMAIN: u64 = ego_zk::poseidon_gadget::SHIELDED_NULLIFIER_DOMAIN;
const BINDING_DOMAIN: u64 = ego_zk::poseidon_gadget::SHIELDED_BINDING_DOMAIN;
const LEAF_DOMAIN: u64 = ego_zk::poseidon_gadget::SHIELDED_LEAF_DOMAIN;

pub const ROOT_HISTORY: usize = 100;

pub const DENOMINATIONS_UEGOC: [u64; 5] = [
    1_000_000,
    10_000_000,
    100_000_000,
    1_000_000_000,
    10_000_000_000,
];

pub const SECRET_BITS: usize = 248;

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

fn to_field(bytes: &[u8; 32]) -> Fr {
    let mut masked = *bytes;
    for b in masked.iter_mut().skip(SECRET_BITS / 8) {
        *b = 0;
    }
    Fr::from_le_bytes_mod_order(&masked)
}

pub fn public_to_field(bytes: &[u8; 32]) -> Fr {
    Fr::from_le_bytes_mod_order(bytes)
}

pub fn field_to_bytes(f: Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let repr = f.into_bigint().to_bytes_le();
    let n = repr.len().min(32);
    out[..n].copy_from_slice(&repr[..n]);
    out
}

fn poseidon(domain: u64, inputs: &[Fr]) -> Result<Fr, String> {
    let mut h = Poseidon::<Fr>::with_domain_tag_circom(inputs.len(), Fr::from(domain))
        .map_err(|e| format!("poseidon config: {e}"))?;
    h.hash(inputs).map_err(|e| format!("poseidon hash: {e}"))
}

pub fn leaf_for(commitment: &[u8; 32], amount_uegoc: u64) -> [u8; 32] {
    field_to_bytes(
        poseidon(LEAF_DOMAIN, &[public_to_field(commitment), Fr::from(amount_uegoc)])
            .expect("two inputs for width 3"),
    )
}

pub fn recipient_digest(address: &str) -> [u8; 32] {
    *ego_core::hash_data(address.as_bytes()).as_bytes()
}

pub fn withdrawal_binding(recipient: &[u8; 32], fee_uegoc: u64) -> Fr {
    poseidon(BINDING_DOMAIN, &[public_to_field(recipient), Fr::from(fee_uegoc)])
        .expect("two inputs for width 3")
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Note {
    pub value_uegoc: u64,
    pub owner_secret: [u8; 32],
    pub rho: [u8; 32],
}

impl Note {
    pub fn random<R: RngCore + CryptoRng>(value_uegoc: u64, rng: &mut R) -> Self {
        let mut owner_secret = [0u8; 32];
        let mut rho = [0u8; 32];
        rng.fill_bytes(&mut owner_secret);
        rng.fill_bytes(&mut rho);
        Self { value_uegoc, owner_secret, rho }
    }

    pub fn as_witness(&self) -> (Fr, Fr, Fr) {
        (Fr::from(self.value_uegoc), to_field(&self.owner_secret), to_field(&self.rho))
    }

    pub fn commitment(&self) -> [u8; 32] {
        let (value, secret, rho) = self.as_witness();
        field_to_bytes(poseidon(COMMITMENT_DOMAIN, &[value, secret, rho]).expect("poseidon commitment"))
    }

    pub fn leaf(&self) -> [u8; 32] {
        leaf_for(&self.commitment(), self.value_uegoc)
    }

    pub fn nullifier(&self) -> [u8; 32] {
        let (_, secret, rho) = self.as_witness();
        field_to_bytes(poseidon(NULLIFIER_DOMAIN, &[secret, rho]).expect("poseidon nullifier"))
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
        let empty_root = field_to_bytes(tree.root());
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
        *self.recent_roots.last().expect("a pool always has at least its empty root")
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
        let index = self.tree.insert(public_to_field(&leaf))?;
        self.leaves.push(leaf);
        let root = field_to_bytes(self.tree.root());
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

    pub fn withdraw(
        &mut self,
        vk: &VerifyingKey<Bn254>,
        proof: &Proof<Bn254>,
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
        let public_inputs = WithdrawCircuit::public_inputs(
            public_to_field(&root),
            public_to_field(&nullifier),
            Fr::from(amount_uegoc),
            withdrawal_binding(&recipient, fee_uegoc),
        );
        match withdraw_circuit::verify(vk, &public_inputs, proof) {
            Ok(true) => {}
            _ => return Err(PoolError::InvalidProof),
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

    pub fn apply_withdrawal(
        &mut self,
        vk: &VerifyingKey<Bn254>,
        w: &Withdrawal,
    ) -> Result<(), PoolError> {
        self.withdraw(vk, &w.proof, w.root, w.nullifier, w.amount_uegoc, w.recipient, w.fee_uegoc)
    }
}

#[derive(Debug, Clone)]
pub struct Withdrawal {
    pub proof: Proof<Bn254>,
    pub root: [u8; 32],
    pub nullifier: [u8; 32],
    pub amount_uegoc: u64,
    pub recipient: [u8; 32],
    pub fee_uegoc: u64,
}

pub fn prove_withdrawal<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    pool: &ShieldedPool,
    note: &Note,
    leaf_index: usize,
    recipient: [u8; 32],
    fee_uegoc: u64,
    rng: &mut R,
) -> Result<Withdrawal, String> {
    if pool.leaves().get(leaf_index) != Some(&note.leaf()) {
        return Err(format!(
            "leaf {leaf_index} does not hold this note; it was not deposited at its own value"
        ));
    }
    if fee_uegoc >= note.value_uegoc {
        return Err(format!(
            "fee {fee_uegoc} uEGOC would consume the whole {} uEGOC note",
            note.value_uegoc
        ));
    }
    let depth = pool.depth();
    let path = pool.merkle_path(leaf_index)?;
    let root = public_to_field(&pool.current_root());
    let (value, secret, rho) = note.as_witness();
    let nullifier = poseidon(NULLIFIER_DOMAIN, &[secret, rho])?;

    let circuit = WithdrawCircuit {
        depth,
        root: Some(root),
        nullifier: Some(nullifier),
        amount: Some(value),
        recipient: Some(withdrawal_binding(&recipient, fee_uegoc)),
        value: Some(value),
        secret: Some(secret),
        rho: Some(rho),
        siblings: Some(path.siblings),
        is_right: Some(path.is_right),
    };
    let proof = withdraw_circuit::prove(pk, circuit, rng)?;
    Ok(Withdrawal {
        proof,
        root: field_to_bytes(root),
        nullifier: field_to_bytes(nullifier),
        amount_uegoc: note.value_uegoc,
        recipient,
        fee_uegoc,
    })
}

pub fn is_enabled() -> bool {
    std::env::var("EGO_SHIELDED_POOL").as_deref() == Ok("unaudited-testnet-only")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::sync::OnceLock;

    const DEPTH: usize = 4;
    const FEE: u64 = 7;

    fn keys() -> &'static (ProvingKey<Bn254>, VerifyingKey<Bn254>) {
        static KEYS: OnceLock<(ProvingKey<Bn254>, VerifyingKey<Bn254>)> = OnceLock::new();
        KEYS.get_or_init(|| withdraw_circuit::setup(DEPTH, &mut StdRng::seed_from_u64(1)).unwrap())
    }

    fn rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

    fn note(value: u64, secret: u8, rho: u8) -> Note {
        Note { value_uegoc: value, owner_secret: [secret; 32], rho: [rho; 32] }
    }

    fn recipient() -> [u8; 32] {
        [0xAB; 32]
    }

    fn funded(value: u64) -> (ShieldedPool, Note, usize) {
        let mut pool = ShieldedPool::new(DEPTH);
        pool.deposit(note(50, 0x11, 0x11).commitment(), 50).unwrap();
        pool.deposit(note(60, 0x22, 0x22).commitment(), 60).unwrap();
        let n = note(value, 1, 1);
        let index = pool.deposit(n.commitment(), value).unwrap();
        (pool, n, index)
    }

    fn withdrawal(pool: &ShieldedPool, n: &Note, index: usize) -> Withdrawal {
        prove_withdrawal(&keys().0, pool, n, index, recipient(), FEE, &mut rng()).unwrap()
    }

    #[test]
    fn a_commitment_reveals_neither_value_nor_owner() {
        assert_ne!(note(100, 1, 1).commitment(), note(100, 2, 1).commitment());
        assert_ne!(note(100, 1, 1).commitment(), note(100, 1, 2).commitment());
    }

    #[test]
    fn a_nullifier_cannot_be_derived_from_the_commitment() {
        let n = note(100, 1, 1);
        assert_ne!(n.commitment(), n.nullifier());
    }

    #[test]
    fn the_same_note_always_nullifies_the_same_way() {
        assert_eq!(note(100, 1, 1).nullifier(), note(100, 1, 1).nullifier());
        assert_eq!(note(100, 1, 1).nullifier(), note(999, 1, 1).nullifier());
    }

    #[test]
    fn the_value_changes_the_commitment_but_not_the_nullifier() {
        let a = note(100, 1, 1);
        let b = note(200, 1, 1);
        assert_ne!(a.commitment(), b.commitment());
        assert_eq!(a.nullifier(), b.nullifier());
    }

    #[test]
    fn a_full_width_secret_cannot_collide_with_a_smaller_one() {
        let big = note(100, 0xFF, 0xFF);
        let near = Note { value_uegoc: 100, owner_secret: [0xFE; 32], rho: [0xFF; 32] };
        assert_ne!(big.commitment(), near.commitment());
        assert_ne!(big.nullifier(), near.nullifier());
    }

    #[test]
    fn masking_only_touches_the_top_bits() {
        let mut a = [3u8; 32];
        let mut b = [3u8; 32];
        a[0] = 1;
        b[0] = 2;
        let na = Note { value_uegoc: 1, owner_secret: a, rho: [1; 32] };
        let nb = Note { value_uegoc: 1, owner_secret: b, rho: [1; 32] };
        assert_ne!(na.commitment(), nb.commitment());
    }

    #[test]
    fn a_commitment_is_a_full_width_value() {
        let c = note(100, 1, 1).commitment();
        assert!(c.iter().any(|b| *b != 0));
    }

    #[test]
    fn random_notes_do_not_repeat() {
        let mut r = rng();
        let a = Note::random(1_000_000, &mut r);
        let b = Note::random(1_000_000, &mut r);
        assert_ne!(a.commitment(), b.commitment());
        assert_ne!(a.nullifier(), b.nullifier());
    }

    #[test]
    fn public_values_round_trip_through_bytes_exactly() {
        for f in [Fr::from(0u64), Fr::from(1u64), Fr::from(u64::MAX), public_to_field(&note(7, 7, 7).commitment())] {
            assert_eq!(public_to_field(&field_to_bytes(f)), f);
        }
    }

    #[test]
    fn the_binding_depends_on_both_recipient_and_fee() {
        let a = withdrawal_binding(&recipient(), FEE);
        assert_ne!(a, withdrawal_binding(&[0xAC; 32], FEE));
        assert_ne!(a, withdrawal_binding(&recipient(), FEE + 1));
        assert_eq!(a, withdrawal_binding(&recipient(), FEE));
    }

    #[test]
    fn a_recipient_digest_is_stable_and_distinct() {
        assert_eq!(recipient_digest("egot1abc"), recipient_digest("egot1abc"));
        assert_ne!(recipient_digest("egot1abc"), recipient_digest("egot1abd"));
    }

    #[test]
    fn denominations_are_recognised_exactly() {
        for d in DENOMINATIONS_UEGOC {
            assert!(is_denomination(d));
            assert!(!is_denomination(d + 1));
            assert!(!is_denomination(d - 1));
        }
        assert!(!is_denomination(0));
    }

    #[test]
    fn denominate_splits_largest_first_and_reports_the_remainder() {
        let (notes, left) = denominate(1_234_500_000);
        assert_eq!(
            notes,
            vec![
                1_000_000_000,
                100_000_000, 100_000_000,
                10_000_000, 10_000_000, 10_000_000,
                1_000_000, 1_000_000, 1_000_000, 1_000_000,
            ]
        );
        assert_eq!(left, 500_000);
        assert_eq!(denominate(999_999), (vec![], 999_999));
        assert_eq!(denominate(0), (vec![], 0));
        let (big, left) = denominate(25_000_000_000);
        assert_eq!(big, vec![10_000_000_000, 10_000_000_000, 1_000_000_000, 1_000_000_000, 1_000_000_000, 1_000_000_000, 1_000_000_000]);
        assert_eq!(left, 0);
    }

    #[test]
    fn a_new_pool_knows_its_empty_root() {
        let pool = ShieldedPool::new(DEPTH);
        assert!(pool.is_known_root(&pool.current_root()));
        assert_eq!(pool.balance(), 0);
    }

    #[test]
    fn a_deposit_returns_its_leaf_index_and_moves_the_root() {
        let mut pool = ShieldedPool::new(DEPTH);
        let before = pool.current_root();
        assert_eq!(pool.deposit(note(1, 1, 1).commitment(), 1).unwrap(), 0);
        assert_eq!(pool.deposit(note(2, 2, 2).commitment(), 2).unwrap(), 1);
        assert_ne!(pool.current_root(), before);
        assert!(pool.is_known_root(&before), "the old root stays in the window");
    }

    #[test]
    fn a_pool_rebuilt_from_leaves_has_the_same_root() {
        let (pool, _, _) = funded(1_000);
        let rebuilt = ShieldedPool::from_leaves(DEPTH, pool.leaves()).unwrap();
        assert_eq!(rebuilt.current_root(), pool.current_root());
        assert_eq!(rebuilt.commitment_count(), 3);
    }

    #[test]
    fn a_deposit_cannot_overflow_the_pool() {
        let mut pool = ShieldedPool::new(DEPTH);
        pool.deposit(note(u64::MAX, 1, 1).commitment(), u64::MAX).unwrap();
        assert_eq!(pool.deposit(note(1, 2, 2).commitment(), 1), Err(PoolError::InvalidAmount));
        assert_eq!(pool.balance(), u64::MAX);
    }

    #[test]
    fn zero_is_not_a_deposit() {
        let mut pool = ShieldedPool::new(DEPTH);
        assert_eq!(pool.deposit([1u8; 32], 0), Err(PoolError::InvalidAmount));
    }

    #[test]
    fn the_same_commitment_cannot_be_deposited_twice() {
        let mut pool = ShieldedPool::new(DEPTH);
        let c = note(100, 1, 1).commitment();
        pool.deposit(c, 100).unwrap();
        assert_eq!(pool.deposit(c, 100), Err(PoolError::DuplicateCommitment));
        assert_eq!(pool.balance(), 100);
    }

    #[test]
    fn the_tree_refuses_to_overflow() {
        let mut pool = ShieldedPool::new(2);
        for i in 0..4u8 {
            pool.deposit(note(1, i + 1, i + 1).commitment(), 1).unwrap();
        }
        assert_eq!(pool.deposit(note(1, 9, 9).commitment(), 1), Err(PoolError::TreeFull));
        assert_eq!(pool.balance(), 4);
    }

    #[test]
    fn an_honest_withdrawal_verifies_and_pays_out_the_whole_note() {
        let (mut pool, n, i) = funded(1_000);
        let w = withdrawal(&pool, &n, i);
        assert_eq!(w.amount_uegoc, 1_000);
        assert_eq!(w.fee_uegoc, FEE);
        assert_eq!(pool.apply_withdrawal(&keys().1, &w), Ok(()));
        assert_eq!(pool.balance(), 50 + 60);
        assert!(pool.is_spent(&w.nullifier));
        assert_eq!(w.nullifier, n.nullifier(), "the proof's nullifier is the note's");
    }

    #[test]
    fn the_same_proof_cannot_be_replayed() {
        let (mut pool, n, i) = funded(1_000);
        let w = withdrawal(&pool, &n, i);
        assert_eq!(pool.apply_withdrawal(&keys().1, &w), Ok(()));
        assert_eq!(pool.apply_withdrawal(&keys().1, &w), Err(PoolError::NullifierAlreadySeen));
        assert_eq!(pool.balance(), 110, "deducted exactly once");
    }

    #[test]
    fn a_second_proof_for_the_same_note_is_refused() {
        let (mut pool, n, i) = funded(1_000);
        let first = withdrawal(&pool, &n, i);
        assert_eq!(pool.apply_withdrawal(&keys().1, &first), Ok(()));
        let second = withdrawal(&pool, &n, i);
        assert_eq!(pool.apply_withdrawal(&keys().1, &second), Err(PoolError::NullifierAlreadySeen));
        assert_eq!(pool.balance(), 110);
    }

    #[test]
    fn a_proof_against_a_recent_root_survives_a_later_deposit() {
        let (mut pool, n, i) = funded(1_000);
        let w = withdrawal(&pool, &n, i);
        pool.deposit(note(5, 0x33, 0x33).commitment(), 5).unwrap();
        assert_ne!(pool.current_root(), w.root, "the root has moved");
        assert_eq!(pool.apply_withdrawal(&keys().1, &w), Ok(()));
    }

    #[test]
    fn a_root_the_pool_never_had_is_refused() {
        let (mut pool, n, i) = funded(1_000);
        let mut w = withdrawal(&pool, &n, i);
        w.root = [0xEE; 32];
        assert_eq!(pool.apply_withdrawal(&keys().1, &w), Err(PoolError::UnknownRoot));
        assert_eq!(pool.balance(), 1_110);
    }

    #[test]
    fn a_root_that_has_aged_out_of_the_window_is_refused() {
        let depth = 8;
        let (pk, vk) = withdraw_circuit::setup(depth, &mut StdRng::seed_from_u64(2)).unwrap();
        let mut pool = ShieldedPool::new(depth);
        let n = note(1_000, 1, 1);
        let i = pool.deposit(n.commitment(), 1_000).unwrap();
        let w = prove_withdrawal(&pk, &pool, &n, i, recipient(), FEE, &mut rng()).unwrap();
        let mut r = rng();
        for _ in 0..ROOT_HISTORY {
            pool.deposit(Note::random(1, &mut r).commitment(), 1).unwrap();
        }
        assert!(!pool.is_known_root(&w.root));
        assert_eq!(pool.apply_withdrawal(&vk, &w), Err(PoolError::UnknownRoot));
    }

    #[test]
    fn changing_the_amount_after_proving_is_refused() {
        let (mut pool, n, i) = funded(1_000);
        let mut w = withdrawal(&pool, &n, i);
        w.amount_uegoc = 999;
        assert_eq!(pool.apply_withdrawal(&keys().1, &w), Err(PoolError::InvalidProof));
        assert_eq!(pool.balance(), 1_110);
        assert!(!pool.is_spent(&w.nullifier), "a refused withdrawal marks nothing");
    }

    #[test]
    fn changing_the_recipient_after_proving_is_refused() {
        let (mut pool, n, i) = funded(1_000);
        let mut w = withdrawal(&pool, &n, i);
        w.recipient = [0xCD; 32];
        assert_eq!(pool.apply_withdrawal(&keys().1, &w), Err(PoolError::InvalidProof));
        assert_eq!(pool.balance(), 1_110);
    }

    #[test]
    fn changing_the_fee_after_proving_is_refused() {
        let (mut pool, n, i) = funded(1_000);
        let mut w = withdrawal(&pool, &n, i);
        w.fee_uegoc = FEE + 1;
        assert_eq!(pool.apply_withdrawal(&keys().1, &w), Err(PoolError::InvalidProof));
        w.fee_uegoc = FEE;
        assert_eq!(pool.apply_withdrawal(&keys().1, &w), Ok(()));
    }

    #[test]
    fn a_nullifier_for_a_different_note_is_refused() {
        let (mut pool, n, i) = funded(1_000);
        let mut w = withdrawal(&pool, &n, i);
        w.nullifier = note(1, 0x11, 0x11).nullifier();
        assert_eq!(pool.apply_withdrawal(&keys().1, &w), Err(PoolError::InvalidProof));
    }

    #[test]
    fn zero_is_not_a_withdrawal() {
        let (mut pool, n, i) = funded(1_000);
        let mut w = withdrawal(&pool, &n, i);
        w.amount_uegoc = 0;
        assert_eq!(pool.apply_withdrawal(&keys().1, &w), Err(PoolError::InvalidAmount));
        assert!(!pool.is_spent(&w.nullifier));
    }

    #[test]
    fn the_prover_refuses_a_leaf_that_does_not_hold_the_note() {
        let (pool, n, _) = funded(1_000);
        let err = prove_withdrawal(&keys().0, &pool, &n, 0, recipient(), FEE, &mut rng());
        assert!(err.is_err());
    }

    #[test]
    fn the_prover_refuses_a_fee_that_eats_the_note() {
        let (pool, n, i) = funded(1_000);
        let err = prove_withdrawal(&keys().0, &pool, &n, i, recipient(), 1_000, &mut rng());
        assert!(err.is_err());
    }

    #[test]
    fn a_note_deposited_for_less_than_it_claims_cannot_be_proven() {
        let mut pool = ShieldedPool::new(DEPTH);
        let n = note(10_000, 5, 5);
        let index = pool.deposit(n.commitment(), 1).unwrap();
        assert_eq!(pool.balance(), 1, "the pool only ever credited what arrived");
        assert_ne!(pool.leaves()[index], n.leaf(), "the leaf binds the amount received");
        let err = prove_withdrawal(&keys().0, &pool, &n, index, recipient(), FEE, &mut rng());
        assert!(err.is_err(), "no proof can be built for a note that is not in the tree");
    }

    #[test]
    fn the_leaf_binds_the_commitment_to_one_amount_only() {
        let c = note(1_000, 7, 7).commitment();
        assert_ne!(leaf_for(&c, 1_000), leaf_for(&c, 1_001));
        assert_ne!(leaf_for(&c, 1_000), c, "the leaf is never the bare commitment");
        assert_eq!(leaf_for(&c, 1_000), note(1_000, 7, 7).leaf());
    }

    #[test]
    fn a_proving_pool_extends_instead_of_rebuilding() {
        let (full, _, _) = funded(1_000);
        let mut partial = ShieldedPool::from_leaves(DEPTH, &full.leaves()[..1]).unwrap();
        partial.extend_from_leaves(full.leaves()).unwrap();
        assert_eq!(partial.current_root(), full.current_root());
        assert_eq!(partial.commitment_count(), full.commitment_count());
        partial.extend_from_leaves(full.leaves()).unwrap();
        assert_eq!(partial.current_root(), full.current_root());
        assert!(partial.extend_from_leaves(&full.leaves()[..1]).is_err());
        let mut forked = full.leaves().to_vec();
        forked[0] = [0x99; 32];
        assert!(partial.extend_from_leaves(&forked).is_err());
    }

    #[test]
    fn spending_leaves_the_commitment_in_place() {
        let (mut pool, n, i) = funded(1_000);
        let before = pool.commitment_count();
        let w = withdrawal(&pool, &n, i);
        pool.apply_withdrawal(&keys().1, &w).unwrap();
        assert_eq!(pool.commitment_count(), before);
        assert!(pool.contains_commitment(&n.commitment()));
    }

    #[test]
    fn the_pool_is_off_unless_deliberately_and_explicitly_enabled() {
        assert!(!is_enabled());
    }

    #[test]
    fn the_pool_and_the_circuit_share_one_domain_table() {
        assert_eq!(COMMITMENT_DOMAIN, ego_zk::poseidon_gadget::SHIELDED_COMMITMENT_DOMAIN);
        assert_eq!(NULLIFIER_DOMAIN, ego_zk::poseidon_gadget::SHIELDED_NULLIFIER_DOMAIN);
        assert_eq!(BINDING_DOMAIN, ego_zk::poseidon_gadget::SHIELDED_BINDING_DOMAIN);
        let all = [COMMITMENT_DOMAIN, NULLIFIER_DOMAIN, BINDING_DOMAIN, ego_zk::merkle::MERKLE_NODE_DOMAIN];
        let distinct: HashSet<u64> = all.iter().copied().collect();
        assert_eq!(distinct.len(), all.len());
    }
}
