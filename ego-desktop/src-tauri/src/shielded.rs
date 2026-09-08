//! Shielded pool: notes, commitments, nullifiers, and proof-checked withdrawals.
//!
//! # How value moves
//!
//! Value enters the pool as a *note* and is recorded only as a commitment, a
//! Poseidon hash that reveals nothing about who owns it or how much it holds.
//! Commitments live in a Merkle tree. Spending publishes a *nullifier* derived
//! from the note's secret, marking it spent without revealing which commitment
//! it came from, together with a zero-knowledge proof that the note is in the
//! tree, that the nullifier is that note's, and that the amount withdrawn is
//! the note's value.
//!
//! The pool never sees the note. It sees a root, a nullifier, an amount, a
//! recipient, a fee and a proof, and it checks four things: the root is one it
//! has had recently, the nullifier is new, the proof verifies against those
//! public values, and it holds enough to pay.
//!
//! # Denominations
//!
//! A note is spent whole, so the amount going out equals the amount that came
//! in, and an amount that appears once on each side of the pool would link the
//! two. Notes therefore come only in fixed denominations. A deposit of 1,234
//! EGOC becomes one note of 1,000, two of 100, three of 10 and four of 1, and
//! each of them is indistinguishable from every other note of its size. The
//! chain enforces this on both deposit and withdrawal; `denominate` is how a
//! wallet splits an amount to fit.
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
const BINDING_DOMAIN: u64 = ego_zk::poseidon_gadget::SHIELDED_BINDING_DOMAIN;

/// How many recent roots a withdrawal may be proven against.
///
/// A withdrawal proven against the root at height h stays valid until this
/// many deposits have landed after it. Tornado shipped with 30 and later
/// raised it; 100 costs three kilobytes of state and buys a busy chain room.
pub const ROOT_HISTORY: usize = 100;

/// Note sizes, in micro-EGOC: 1, 10, 100, 1,000 and 10,000 EGOC.
pub const DENOMINATIONS_UEGOC: [u64; 5] = [
    1_000_000,
    10_000_000,
    100_000_000,
    1_000_000_000,
    10_000_000_000,
];

/// Bits of randomness in a secret or rho.
///
/// Deliberately below the 254-bit BN254 scalar field. Converting bytes to a
/// field element reduces them modulo the field order, so a full 32-byte value
/// and that value minus the order collapse to the same element — two different
/// secrets producing one commitment and one nullifier. Keeping the material
/// under the modulus makes the mapping injective and removes the question.
pub const SECRET_BITS: usize = 248;

pub fn is_denomination(value_uegoc: u64) -> bool {
    DENOMINATIONS_UEGOC.contains(&value_uegoc)
}

/// Split an amount into notes, largest first. Whatever is left below the
/// smallest denomination stays transparent; it is returned separately so the
/// caller can say so.
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

/// Bytes of a public value (a commitment, root, nullifier, or recipient digest)
/// as a field element. No masking: commitments, roots and nullifiers are
/// canonical field elements already and round-trip exactly, and a recipient
/// digest is reduced modulo the field order identically on the proving and
/// verifying sides, which is all binding needs.
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

/// Poseidon over BN254 with circom-compatible parameters — the same
/// construction Tornado Cash uses, and the same one `ego-zk` replicates
/// in-circuit and proves equal to this.
fn poseidon(domain: u64, inputs: &[Fr]) -> Result<Fr, String> {
    let mut h = Poseidon::<Fr>::with_domain_tag_circom(inputs.len(), Fr::from(domain))
        .map_err(|e| format!("poseidon config: {e}"))?;
    h.hash(inputs).map_err(|e| format!("poseidon hash: {e}"))
}

/// The 32-byte form of a recipient address, for binding.
pub fn recipient_digest(address: &str) -> [u8; 32] {
    *ego_core::hash_data(address.as_bytes()).as_bytes()
}

/// The circuit has one public slot for binding, and it holds
/// `Poseidon(BINDING, recipient, fee)`. A relayer who changes either the
/// payee or the fee changes this value, and the proof no longer verifies.
pub fn withdrawal_binding(recipient: &[u8; 32], fee_uegoc: u64) -> Fr {
    poseidon(BINDING_DOMAIN, &[public_to_field(recipient), Fr::from(fee_uegoc)])
        .expect("two inputs for width 3")
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
    /// A fresh note of `value` with secrets drawn from `rng`.
    pub fn random<R: RngCore + CryptoRng>(value_uegoc: u64, rng: &mut R) -> Self {
        let mut owner_secret = [0u8; 32];
        let mut rho = [0u8; 32];
        rng.fill_bytes(&mut owner_secret);
        rng.fill_bytes(&mut rho);
        Self { value_uegoc, owner_secret, rho }
    }

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

/// The pool's public state, held in memory.
///
/// Everything here is visible on-chain. Privacy comes from what is absent: no
/// value, no owner, and no link between a commitment and the nullifier that
/// eventually spends it. Consensus keeps its own persisted copy of the same
/// rules in `chain_db`; this is the model those are checked against, and what
/// a wallet builds from the chain's leaves to prove with.
#[derive(Debug, Clone)]
pub struct ShieldedPool {
    depth: usize,
    /// Every commitment ever deposited, in leaf order. Append-only: a leaf is
    /// never removed, because removing one would reveal which note was spent.
    commitments: Vec<[u8; 32]>,
    commitment_set: HashSet<[u8; 32]>,
    tree: MerkleTree,
    /// Spent markers. Grows forever, by design.
    nullifiers: HashSet<[u8; 32]>,
    /// Total value the pool holds and must be able to pay out.
    balance_uegoc: u64,
    /// The last `ROOT_HISTORY` roots, oldest first.
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
            commitments: Vec::new(),
            commitment_set: HashSet::new(),
            tree,
            nullifiers: HashSet::new(),
            balance_uegoc: 0,
            recent_roots: Vec::new(),
        };
        // The empty tree's root counts as known, as it does in Tornado.
        pool.remember_root(empty_root);
        pool
    }

    /// A pool rebuilt from the chain's leaves, for proving against. Values and
    /// nullifiers are not needed for that and are left empty.
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
        self.commitments.len()
    }

    pub fn nullifier_count(&self) -> usize {
        self.nullifiers.len()
    }

    pub fn leaves(&self) -> &[[u8; 32]] {
        &self.commitments
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

    fn append_leaf(&mut self, commitment: [u8; 32]) -> Result<usize, String> {
        if self.commitment_set.contains(&commitment) {
            return Err("duplicate commitment".into());
        }
        let index = self.tree.insert(public_to_field(&commitment))?;
        self.commitments.push(commitment);
        self.commitment_set.insert(commitment);
        let root = field_to_bytes(self.tree.root());
        self.remember_root(root);
        Ok(index)
    }

    /// The Merkle path for the leaf at `index`, for building a proof.
    pub fn merkle_path(&self, index: usize) -> Result<MerklePath, String> {
        self.tree.path(index)
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
        let index = self.append_leaf(commitment).map_err(|_| PoolError::TreeFull)?;
        self.balance_uegoc = new_balance;
        Ok(index)
    }

    /// Take value out of the pool on the strength of a proof.
    ///
    /// Every check precedes every mutation, so a refused withdrawal leaves the
    /// pool exactly as it was. The fee is not the pool's concern beyond the
    /// binding: the whole amount leaves the pool, and the chain decides how
    /// much of it the recipient keeps.
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
        self.withdraw(vk, &w.proof, w.root, w.nullifier, w.amount_uegoc, w.recipient, w.fee_uegoc)
    }
}

/// Everything a withdrawal submits. The proof is bound to all of it, so
/// changing any field after proving invalidates it.
#[derive(Debug, Clone)]
pub struct Withdrawal {
    pub proof: Proof<Bn254>,
    pub root: [u8; 32],
    pub nullifier: [u8; 32],
    pub amount_uegoc: u64,
    pub recipient: [u8; 32],
    pub fee_uegoc: u64,
}

/// Build a withdrawal proof for `note`, which sits at `leaf_index` among
/// `leaves`, paying `note.value_uegoc` less `fee_uegoc` to `recipient`.
///
/// Prover side: this is the only place the private note meets the circuit.
/// The witness encoding comes from `Note::as_witness`, the same function the
/// pool hashed with, so the two cannot disagree.
pub fn prove_withdrawal<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    depth: usize,
    leaves: &[[u8; 32]],
    note: &Note,
    leaf_index: usize,
    recipient: [u8; 32],
    fee_uegoc: u64,
    rng: &mut R,
) -> Result<Withdrawal, String> {
    // Refuse to build a proof that could not verify. A wrong index is far
    // likelier to be a bookkeeping mistake than an attack, and a clear error
    // here beats an opaque InvalidProof later.
    if leaves.get(leaf_index) != Some(&note.commitment()) {
        return Err(format!("leaf {leaf_index} does not hold this note's commitment"));
    }
    if fee_uegoc >= note.value_uegoc {
        return Err(format!(
            "fee {fee_uegoc} uEGOC would consume the whole {} uEGOC note",
            note.value_uegoc
        ));
    }
    let pool = ShieldedPool::from_leaves(depth, leaves)?;
    let path = pool.merkle_path(leaf_index)?;
    let root = pool.tree.root();
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

/// Whether this wallet will offer the shielded pool.
///
/// Off, and it stays off until two things are true that are not yet. The
/// circuit has been reviewed by somebody who does this for a living; it
/// rejects every dishonest witness its author could think of, which is not the
/// same thing. And the proving keys come from a multi-party setup rather than
/// a single machine, because whoever runs a single-party setup can forge
/// proofs. Shipping it enabled before then would invite people to trust it.
///
/// This is the local opt-in. Whether the chain accepts shielded transactions
/// at all is a separate, consensus-wide switch in `chain_db`.
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

    fn withdrawal(pool: &ShieldedPool, n: &Note, index: usize) -> Withdrawal {
        prove_withdrawal(&keys().0, DEPTH, pool.leaves(), n, index, recipient(), FEE, &mut rng()).unwrap()
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
    fn random_notes_do_not_repeat() {
        let mut r = rng();
        let a = Note::random(1_000_000, &mut r);
        let b = Note::random(1_000_000, &mut r);
        assert_ne!(a.commitment(), b.commitment());
        assert_ne!(a.nullifier(), b.nullifier());
    }

    #[test]
    fn public_values_round_trip_through_bytes_exactly() {
        // Roots, nullifiers and commitments cross the byte boundary and back.
        // Any loss here would make the pool reject its own roots.
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

    // ── Denominations ────────────────────────────────────────────────────

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

    // ── Withdrawals ──────────────────────────────────────────────────────

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

    /// The double-spend guard. Replaying the very same proof is the simplest
    /// attack there is, and the nullifier set is what stops it.
    #[test]
    fn the_same_proof_cannot_be_replayed() {
        let (mut pool, n, i) = funded(1_000);
        let w = withdrawal(&pool, &n, i);
        assert_eq!(pool.apply_withdrawal(&keys().1, &w), Ok(()));
        assert_eq!(pool.apply_withdrawal(&keys().1, &w), Err(PoolError::NullifierAlreadySeen));
        assert_eq!(pool.balance(), 110, "deducted exactly once");
    }

    /// A fresh proof for an already-spent note carries the same nullifier, so
    /// it is refused the same way.
    #[test]
    fn a_second_proof_for_the_same_note_is_refused() {
        let (mut pool, n, i) = funded(1_000);
        let first = withdrawal(&pool, &n, i);
        assert_eq!(pool.apply_withdrawal(&keys().1, &first), Ok(()));
        let second = withdrawal(&pool, &n, i);
        assert_eq!(pool.apply_withdrawal(&keys().1, &second), Err(PoolError::NullifierAlreadySeen));
        assert_eq!(pool.balance(), 110);
    }

    /// The reason for the root window: a deposit between proving and applying
    /// must not invalidate an honest withdrawal.
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
        // Deep enough to take more deposits than the window keeps.
        let depth = 8;
        let (pk, vk) = withdraw_circuit::setup(depth, &mut StdRng::seed_from_u64(2)).unwrap();
        let mut pool = ShieldedPool::new(depth);
        let n = note(1_000, 1, 1);
        let i = pool.deposit(n.commitment(), 1_000).unwrap();
        let w = prove_withdrawal(&pk, depth, pool.leaves(), &n, i, recipient(), FEE, &mut rng()).unwrap();
        let mut r = rng();
        for _ in 0..ROOT_HISTORY {
            pool.deposit(Note::random(1, &mut r).commitment(), 1).unwrap();
        }
        assert!(!pool.is_known_root(&w.root));
        assert_eq!(pool.apply_withdrawal(&vk, &w), Err(PoolError::UnknownRoot));
    }

    /// The proof is bound to the amount: no taking more, or less, than proved.
    #[test]
    fn changing_the_amount_after_proving_is_refused() {
        let (mut pool, n, i) = funded(1_000);
        let mut w = withdrawal(&pool, &n, i);
        w.amount_uegoc = 999;
        assert_eq!(pool.apply_withdrawal(&keys().1, &w), Err(PoolError::InvalidProof));
        assert_eq!(pool.balance(), 1_110);
        assert!(!pool.is_spent(&w.nullifier), "a refused withdrawal marks nothing");
    }

    /// The proof is bound to the recipient: a relayer cannot redirect it.
    #[test]
    fn changing_the_recipient_after_proving_is_refused() {
        let (mut pool, n, i) = funded(1_000);
        let mut w = withdrawal(&pool, &n, i);
        w.recipient = [0xCD; 32];
        assert_eq!(pool.apply_withdrawal(&keys().1, &w), Err(PoolError::InvalidProof));
        assert_eq!(pool.balance(), 1_110);
    }

    /// The proof is bound to the fee: a relayer cannot keep more of the note.
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

    /// The prover refuses to build a proof for a leaf that is not this note.
    /// The circuit would refuse it too, which `ego-zk`'s tests establish; this
    /// is the clearer error the honest path gets first.
    #[test]
    fn the_prover_refuses_a_leaf_that_does_not_hold_the_note() {
        let (pool, n, _) = funded(1_000);
        let err = prove_withdrawal(&keys().0, DEPTH, pool.leaves(), &n, 0, recipient(), FEE, &mut rng());
        assert!(err.is_err());
    }

    #[test]
    fn the_prover_refuses_a_fee_that_eats_the_note() {
        let (pool, n, i) = funded(1_000);
        let err = prove_withdrawal(&keys().0, DEPTH, pool.leaves(), &n, i, recipient(), 1_000, &mut rng());
        assert!(err.is_err());
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
