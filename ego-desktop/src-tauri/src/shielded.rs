//! Shielded pool: notes, commitments, nullifiers, and proof-checked withdrawals.
//!
//! # How value moves
//!
//! Value enters the pool as a *note* and is recorded only as a commitment, a
//! Poseidon hash that reveals nothing about who owns it or how much it holds.
//! Commitments live in a Merkle tree. Spending publishes a *nullifier* derived
//! from the note's secret, marking it spent without revealing which commitment
//! it came from, together with a zero-knowledge proof that the note is in the
//! tree, that the nullifier is that note's, and that the amount withdrawn does
//! not exceed the note's value.
//!
//! The pool never sees the note. It sees a root, a nullifier, an amount, a
//! recipient, and a proof, and it checks four things: the root is one it has
//! had recently, the nullifier is new, the proof verifies against those public
//! inputs, and it holds enough to pay.
//!
//! # Why the accounting still checks anything
//!
//! The proof decides what a spender may *claim*. The accounting still decides
//! what may be *paid*. Solvency and the nullifier set are enforced here
//! independently of the circuit, so a flaw in the proof system does not on its
//! own turn into coins leaving the pool. The Liquid incident began with a range
//! proof accepting a value it should have rejected, but the loss happened
//! because the accounting downstream then let unbacked value be redeemed. Two
//! layers, each assuming the other might be wrong.
//!
//! # Root history
//!
//! A proof is built against the root at proving time. If a deposit lands before
//! the withdrawal is applied, the root moves and the proof would be refused for
//! a reason that has nothing to do with the spender. So the pool keeps the last
//! `ROOT_HISTORY` roots and accepts any of them, the way Tornado's contract does.
//!
//! # What is and is not established
//!
//! The circuit rejects every dishonest witness its author could construct, and
//! that is what the tests in `ego-zk` show. It is not an audit, and a green
//! suite must not be read as one: soundness is the claim that *no* dishonest
//! witness passes, which enumeration cannot reach. The proving and verifying
//! keys also come from a circuit-specific trusted setup, and whoever runs it
//! holds material that would let them forge proofs. A single-party setup is
//! fine for a testnet and unacceptable for mainnet, which needs a multi-party
//! ceremony. Both of those are why `is_enabled` stays off by default.

use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, PrimeField};
use ego_zk::merkle::{MerklePath, MerkleTree, POOL_TREE_DEPTH};
use ego_zk::withdraw_circuit::{self, Proof, ProvingKey, VerifyingKey, WithdrawCircuit};
use light_poseidon::{Poseidon, PoseidonHasher};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Domain tags, taken from the circuit crate so the pool and the proof cannot
/// disagree about them. A commitment must never be reinterpretable as a
/// nullifier or the reverse: if one hash could serve as both, a note could be
/// made to nullify itself, or a nullifier forged from public data.
const COMMITMENT_DOMAIN: u64 = ego_zk::poseidon_gadget::SHIELDED_COMMITMENT_DOMAIN;
const NULLIFIER_DOMAIN: u64 = ego_zk::poseidon_gadget::SHIELDED_NULLIFIER_DOMAIN;

/// How many recent roots a withdrawal may be proven against.
pub const ROOT_HISTORY: usize = 30;

/// Bits of randomness in a secret or rho.
///
/// Deliberately below the 254-bit BN254 scalar field. Converting bytes to a
/// field element reduces them modulo the field order, so a full 32-byte value
/// and that value minus the order collapse to the same element — two different
/// secrets producing one commitment and one nullifier. Keeping the material
/// under the modulus makes the mapping injective and removes the question.
pub const SECRET_BITS: usize = 248;

/// Reduce a secret's 32 bytes to a field element, having first ensured they fit.
fn to_field(bytes: &[u8; 32]) -> Fr {
    let mut masked = *bytes;
    // Clear the high bytes so the value is always below the field order.
    //
    // from_le_bytes_mod_order reads little-endian, so the most significant byte
    // is the LAST one. Clearing from the front instead throws away the low bits
    // and makes any two secrets that differ only in their first byte collide,
    // which is a forged note rather than a lost bit of entropy.
    for b in masked.iter_mut().skip(SECRET_BITS / 8) {
        *b = 0;
    }
    Fr::from_le_bytes_mod_order(&masked)
}

/// Bytes of a public value (a commitment, root, nullifier, or recipient) as a
/// field element. No masking: commitments, roots and nullifiers are canonical
/// field elements already and round-trip exactly, and a recipient is reduced
/// modulo the field order identically on the proving and verifying sides,
/// which is all binding needs.
fn public_to_field(bytes: &[u8; 32]) -> Fr {
    Fr::from_le_bytes_mod_order(bytes)
}

fn field_to_bytes(f: Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let repr = f.into_bigint().to_bytes_le();
    let n = repr.len().min(32);
    out[..n].copy_from_slice(&repr[..n]);
    out
}

/// Poseidon over BN254 with circom-compatible parameters — the same
/// construction Tornado Cash uses, and the same one `ego-zk` replicates
/// in-circuit and proves equal to this.
fn poseidon(domain: u64, inputs: &[Fr]) -> Result<Fr, String> {
    let mut h = Poseidon::<Fr>::with_domain_tag_circom(inputs.len(), Fr::from(domain))
        .map_err(|e| format!("poseidon config: {e}"))?;
    h.hash(inputs).map_err(|e| format!("poseidon hash: {e}"))
}

/// A note is value held inside the pool.
///
/// `rho` makes two notes of the same value, owned by the same person, produce
/// different commitments. Without it, paying somebody 10 EGOC twice would write
/// the same commitment twice and link the payments.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Note {
    pub value_uegoc: u64,
    /// Owner's spending secret. Whoever knows this can spend the note.
    pub owner_secret: [u8; 32],
    /// Per-note randomness.
    pub rho: [u8; 32],
}

impl Note {
    /// The field elements this note hashes over: `(value, secret, rho)`.
    ///
    /// The single source of that encoding. `commitment()` uses it and so does
    /// the prover, so the masked secret the pool hashed is by construction the
    /// one the circuit is given. If they were derived separately and drifted,
    /// every honest proof would fail to verify with nothing to say why.
    pub fn as_witness(&self) -> (Fr, Fr, Fr) {
        (Fr::from(self.value_uegoc), to_field(&self.owner_secret), to_field(&self.rho))
    }

    /// The public record of this note. Reveals neither value nor owner.
    pub fn commitment(&self) -> [u8; 32] {
        let (value, secret, rho) = self.as_witness();
        // The inputs are fixed in number and range, so failure here is a bug
        // rather than a condition a caller can act on.
        field_to_bytes(poseidon(COMMITMENT_DOMAIN, &[value, secret, rho]).expect("poseidon commitment"))
    }

    /// The marker published when this note is spent.
    ///
    /// Derived from the secret and rho but not the value, so it is unlinkable to
    /// the commitment without knowing the secret. Deterministic, so the same
    /// note can never be spent twice under two different markers.
    pub fn nullifier(&self) -> [u8; 32] {
        let (_, secret, rho) = self.as_witness();
        field_to_bytes(poseidon(NULLIFIER_DOMAIN, &[secret, rho]).expect("poseidon nullifier"))
    }
}

#[derive(Debug, PartialEq)]
pub enum PoolError {
    /// This note has already been spent, or this exact withdrawal is being
    /// replayed. Either way the nullifier is known.
    NullifierAlreadySeen,
    /// The proof was built against a root the pool has never had, or one that
    /// has aged out of the history window.
    UnknownRoot,
    /// The proof does not verify against the public inputs supplied.
    InvalidProof,
    /// The pool does not hold enough to honour this, which should be
    /// unreachable if the other rules hold and is treated as corruption.
    PoolUnderfunded { balance: u64, requested: u64 },
    /// A deposit or withdrawal of nothing, or a deposit that would overflow.
    InvalidAmount,
    /// Two deposits produced the same commitment, so one would be unspendable.
    DuplicateCommitment,
    /// The commitment tree has no free leaves.
    TreeFull,
}

/// The pool's public state.
///
/// Everything here is visible on-chain. Privacy comes from what is absent: no
/// value, no owner, and no link between a commitment and the nullifier that
/// eventually spends it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldedPool {
    depth: usize,
    /// Every commitment ever deposited, in leaf order. Append-only: a leaf is
    /// never removed, because removing one would reveal which note was spent.
    /// This is the serialised source of truth; the tree is rebuilt from it.
    commitments: Vec<[u8; 32]>,
    #[serde(default)]
    commitment_set: HashSet<[u8; 32]>,
    /// Spent markers. Grows forever, by design.
    nullifiers: HashSet<[u8; 32]>,
    /// Total value the pool holds and must be able to pay out.
    balance_uegoc: u64,
    /// The last `ROOT_HISTORY` roots, oldest first.
    #[serde(default)]
    recent_roots: Vec<[u8; 32]>,
}

impl Default for ShieldedPool {
    fn default() -> Self {
        Self::new(POOL_TREE_DEPTH)
    }
}

impl ShieldedPool {
    pub fn new(depth: usize) -> Self {
        let mut pool = Self {
            depth,
            commitments: Vec::new(),
            commitment_set: HashSet::new(),
            nullifiers: HashSet::new(),
            balance_uegoc: 0,
            recent_roots: Vec::new(),
        };
        // The empty tree's root counts as known, as it does in Tornado.
        pool.remember_root(field_to_bytes(MerkleTree::new(depth).root()));
        pool
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn balance(&self) -> u64 {
        self.balance_uegoc
    }

    pub fn commitment_count(&self) -> usize {
        self.commitments.len()
    }

    pub fn nullifier_count(&self) -> usize {
        self.nullifiers.len()
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

    /// The commitment tree, rebuilt from the leaf list.
    ///
    /// O(n) hashes per call, so `deposit` costs O(n) and a pool of n notes
    /// costs O(n²) to fill. Correct, and the reference the circuit is tested
    /// against, but a pool with a million notes wants an incremental tree that
    /// caches filled subtrees. That is an optimisation to be checked for
    /// equality against this, not a replacement for it.
    fn tree(&self) -> MerkleTree {
        let mut tree = MerkleTree::new(self.depth);
        for c in &self.commitments {
            tree.insert(public_to_field(c)).expect("leaf count is bounded on deposit");
        }
        tree
    }

    /// The Merkle path for the leaf at `index`, for building a proof.
    pub fn merkle_path(&self, index: usize) -> Result<MerklePath, String> {
        self.tree().path(index)
    }

    /// Move value into the pool. The caller must already have taken the same
    /// amount from the depositor's transparent balance; this only records it.
    /// Returns the leaf index, which the depositor needs to prove a withdrawal.
    pub fn deposit(&mut self, commitment: [u8; 32], value_uegoc: u64) -> Result<usize, PoolError> {
        if value_uegoc == 0 {
            return Err(PoolError::InvalidAmount);
        }
        // A pool that can overflow is a pool that can be emptied.
        let new_balance = self
            .balance_uegoc
            .checked_add(value_uegoc)
            .ok_or(PoolError::InvalidAmount)?;
        if self.commitment_set.contains(&commitment) {
            return Err(PoolError::DuplicateCommitment);
        }
        if self.commitments.len() >= (1usize << self.depth) {
            return Err(PoolError::TreeFull);
        }
        self.commitments.push(commitment);
        self.commitment_set.insert(commitment);
        let root = field_to_bytes(self.tree().root());
        self.remember_root(root);
        self.balance_uegoc = new_balance;
        Ok(self.commitments.len() - 1)
    }

    /// Take value out of the pool on the strength of a proof.
    ///
    /// Every check precedes every mutation, so a refused withdrawal leaves the
    /// pool exactly as it was.
    pub fn withdraw(
        &mut self,
        vk: &VerifyingKey<Bn254>,
        proof: &Proof<Bn254>,
        root: [u8; 32],
        nullifier: [u8; 32],
        amount_uegoc: u64,
        recipient: [u8; 32],
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
            public_to_field(&recipient),
        );
        // A malformed proof and a false one are refused alike. Neither is a
        // condition the pool should try to distinguish.
        match withdraw_circuit::verify(vk, &public_inputs, proof) {
            Ok(true) => {}
            _ => return Err(PoolError::InvalidProof),
        }
        // Belt and braces. A verifying proof already bounds the amount by the
        // note's value and the note's value by what was deposited, so if this
        // fires the pool is already corrupt, and paying out would turn an
        // accounting bug into stolen coins.
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
        self.withdraw(vk, &w.proof, w.root, w.nullifier, w.amount_uegoc, w.recipient)
    }
}

/// Everything a withdrawal submits. The proof is bound to all four public
/// values, so changing any of them after proving invalidates it.
#[derive(Debug, Clone)]
pub struct Withdrawal {
    pub proof: Proof<Bn254>,
    pub root: [u8; 32],
    pub nullifier: [u8; 32],
    pub amount_uegoc: u64,
    pub recipient: [u8; 32],
}

/// Build a withdrawal proof for `note`, which sits at `leaf_index`.
///
/// Prover side: this is the only place the private note meets the circuit.
/// The witness encoding comes from `Note::as_witness`, the same function the
/// pool hashed with, so the two cannot disagree.
pub fn prove_withdrawal<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    pool: &ShieldedPool,
    note: &Note,
    leaf_index: usize,
    amount_uegoc: u64,
    recipient: [u8; 32],
    rng: &mut R,
) -> Result<Withdrawal, String> {
    // Refuse to build a proof that could not verify. A wrong index is far
    // likelier to be a bookkeeping mistake than an attack, and a clear error
    // here beats an opaque InvalidProof later.
    if pool.commitments.get(leaf_index) != Some(&note.commitment()) {
        return Err(format!("leaf {leaf_index} does not hold this note's commitment"));
    }
    let tree = pool.tree();
    let path = tree.path(leaf_index)?;
    let root = tree.root();
    let (value, secret, rho) = note.as_witness();
    let nullifier = poseidon(NULLIFIER_DOMAIN, &[secret, rho])?;

    let circuit = WithdrawCircuit {
        depth: pool.depth,
        root: Some(root),
        nullifier: Some(nullifier),
        amount: Some(Fr::from(amount_uegoc)),
        recipient: Some(public_to_field(&recipient)),
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
        amount_uegoc,
        recipient,
    })
}

/// Whether the shielded pool may be used.
///
/// Off, and it stays off until two things are true that are not yet. The
/// circuit has been reviewed by somebody who does this for a living; it
/// rejects every dishonest witness its author could think of, which is not the
/// same thing. And the proving keys come from a multi-party setup rather than
/// a single machine, because whoever runs a single-party setup can forge
/// proofs. Shipping it enabled before then would invite people to trust it.
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

    /// Groth16 keys are circuit-specific and take a moment to generate, so the
    /// tests share one pair.
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

    /// A pool holding two other people's notes and then ours.
    fn funded(value: u64) -> (ShieldedPool, Note, usize) {
        let mut pool = ShieldedPool::new(DEPTH);
        pool.deposit(note(50, 0x11, 0x11).commitment(), 50).unwrap();
        pool.deposit(note(60, 0x22, 0x22).commitment(), 60).unwrap();
        let n = note(value, 1, 1);
        let index = pool.deposit(n.commitment(), value).unwrap();
        (pool, n, index)
    }

    fn withdrawal(pool: &ShieldedPool, n: &Note, index: usize, amount: u64) -> Withdrawal {
        prove_withdrawal(&keys().0, pool, n, index, amount, recipient(), &mut rng()).unwrap()
    }

    // ── Hash properties ──────────────────────────────────────────────────

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
    fn public_values_round_trip_through_bytes_exactly() {
        // Roots, nullifiers and commitments cross the byte boundary and back.
        // Any loss here would make the pool reject its own roots.
        for f in [Fr::from(0u64), Fr::from(1u64), Fr::from(u64::MAX), public_to_field(&note(7, 7, 7).commitment())] {
            assert_eq!(public_to_field(&field_to_bytes(f)), f);
        }
    }

    // ── Deposits ─────────────────────────────────────────────────────────

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

    // ── Withdrawals ──────────────────────────────────────────────────────

    #[test]
    fn an_honest_withdrawal_verifies_and_pays_out() {
        let (mut pool, n, i) = funded(1_000);
        let w = withdrawal(&pool, &n, i, 400);
        assert_eq!(pool.apply_withdrawal(&keys().1, &w), Ok(()));
        assert_eq!(pool.balance(), 50 + 60 + 600);
        assert!(pool.is_spent(&w.nullifier));
        assert_eq!(w.nullifier, n.nullifier(), "the proof's nullifier is the note's");
    }

    #[test]
    fn withdrawing_exactly_the_full_value_is_allowed() {
        let (mut pool, n, i) = funded(1_000);
        let w = withdrawal(&pool, &n, i, 1_000);
        assert_eq!(pool.apply_withdrawal(&keys().1, &w), Ok(()));
        assert_eq!(pool.balance(), 110);
    }

    /// The double-spend guard. Replaying the very same proof is the simplest
    /// attack there is, and the nullifier set is what stops it.
    #[test]
    fn the_same_proof_cannot_be_replayed() {
        let (mut pool, n, i) = funded(1_000);
        let w = withdrawal(&pool, &n, i, 300);
        assert_eq!(pool.apply_withdrawal(&keys().1, &w), Ok(()));
        assert_eq!(pool.apply_withdrawal(&keys().1, &w), Err(PoolError::NullifierAlreadySeen));
        assert_eq!(pool.balance(), 110 + 700, "deducted exactly once");
    }

    /// A fresh proof for an already-spent note carries the same nullifier, so
    /// it is refused the same way. Spending part of a note burns the rest until
    /// change notes exist; losing value is survivable, releasing it twice is not.
    #[test]
    fn a_second_proof_for_the_same_note_is_refused() {
        let (mut pool, n, i) = funded(1_000);
        let first = withdrawal(&pool, &n, i, 100);
        assert_eq!(pool.apply_withdrawal(&keys().1, &first), Ok(()));
        let second = withdrawal(&pool, &n, i, 100);
        assert_eq!(pool.apply_withdrawal(&keys().1, &second), Err(PoolError::NullifierAlreadySeen));
        assert_eq!(pool.balance(), 110 + 900);
    }

    /// The reason for the root window: a deposit between proving and applying
    /// must not invalidate an honest withdrawal.
    #[test]
    fn a_proof_against_a_recent_root_survives_a_later_deposit() {
        let (mut pool, n, i) = funded(1_000);
        let w = withdrawal(&pool, &n, i, 250);
        pool.deposit(note(5, 0x33, 0x33).commitment(), 5).unwrap();
        assert_ne!(pool.current_root(), w.root, "the root has moved");
        assert_eq!(pool.apply_withdrawal(&keys().1, &w), Ok(()));
    }

    #[test]
    fn a_root_the_pool_never_had_is_refused() {
        let (mut pool, n, i) = funded(1_000);
        let mut w = withdrawal(&pool, &n, i, 250);
        w.root = [0xEE; 32];
        assert_eq!(pool.apply_withdrawal(&keys().1, &w), Err(PoolError::UnknownRoot));
        assert_eq!(pool.balance(), 1_110);
    }

    #[test]
    fn a_root_that_has_aged_out_of_the_window_is_refused() {
        // Deep enough to take more deposits than the window keeps.
        let depth = 6;
        let (pk, vk) = withdraw_circuit::setup(depth, &mut StdRng::seed_from_u64(2)).unwrap();
        let mut pool = ShieldedPool::new(depth);
        let n = note(1_000, 1, 1);
        let i = pool.deposit(n.commitment(), 1_000).unwrap();
        let w = prove_withdrawal(&pk, &pool, &n, i, 100, recipient(), &mut rng()).unwrap();
        for k in 0..ROOT_HISTORY as u8 {
            pool.deposit(note(1, 0x40 + k, 0x40 + k).commitment(), 1).unwrap();
        }
        assert!(!pool.is_known_root(&w.root));
        assert_eq!(pool.apply_withdrawal(&vk, &w), Err(PoolError::UnknownRoot));
    }

    /// The proof is bound to the amount: no taking more than was proved.
    #[test]
    fn changing_the_amount_after_proving_is_refused() {
        let (mut pool, n, i) = funded(1_000);
        let mut w = withdrawal(&pool, &n, i, 100);
        w.amount_uegoc = 1_000;
        assert_eq!(pool.apply_withdrawal(&keys().1, &w), Err(PoolError::InvalidProof));
        assert_eq!(pool.balance(), 1_110);
        assert!(!pool.is_spent(&w.nullifier), "a refused withdrawal marks nothing");
    }

    /// The proof is bound to the recipient: a relayer cannot redirect it.
    #[test]
    fn changing_the_recipient_after_proving_is_refused() {
        let (mut pool, n, i) = funded(1_000);
        let mut w = withdrawal(&pool, &n, i, 100);
        w.recipient = [0xCD; 32];
        assert_eq!(pool.apply_withdrawal(&keys().1, &w), Err(PoolError::InvalidProof));
        assert_eq!(pool.balance(), 1_110);
    }

    #[test]
    fn a_nullifier_for_a_different_note_is_refused() {
        let (mut pool, n, i) = funded(1_000);
        let mut w = withdrawal(&pool, &n, i, 100);
        w.nullifier = note(1, 0x11, 0x11).nullifier();
        assert_eq!(pool.apply_withdrawal(&keys().1, &w), Err(PoolError::InvalidProof));
    }

    #[test]
    fn zero_is_not_a_withdrawal() {
        let (mut pool, n, i) = funded(1_000);
        let w = withdrawal(&pool, &n, i, 0);
        assert_eq!(pool.apply_withdrawal(&keys().1, &w), Err(PoolError::InvalidAmount));
        assert!(!pool.is_spent(&w.nullifier));
    }

    /// The prover refuses to build a proof for a leaf that is not this note.
    /// The circuit would refuse it too, which `ego-zk`'s tests establish; this
    /// is the clearer error the honest path gets first.
    #[test]
    fn the_prover_refuses_a_leaf_that_does_not_hold_the_note() {
        let (pool, n, _) = funded(1_000);
        let err = prove_withdrawal(&keys().0, &pool, &n, 0, 100, recipient(), &mut rng());
        assert!(err.is_err());
    }

    #[test]
    fn spending_leaves_the_commitment_in_place() {
        let (mut pool, n, i) = funded(1_000);
        let before = pool.commitment_count();
        let w = withdrawal(&pool, &n, i, 1_000);
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
        assert_ne!(COMMITMENT_DOMAIN, ego_zk::merkle::MERKLE_NODE_DOMAIN);
        assert_ne!(NULLIFIER_DOMAIN, ego_zk::merkle::MERKLE_NODE_DOMAIN);
    }
}
