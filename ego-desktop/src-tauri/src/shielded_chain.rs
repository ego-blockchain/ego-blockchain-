//! The shielded pool as consensus state.
//!
//! `shielded.rs` is the model: an in-memory pool that every rule is written
//! against and tested on. This module is the same rules applied to the chain:
//! how a deposit and a withdrawal look as transactions, what a validator
//! checks before a block is accepted, what gets written when it is, and how
//! that is undone in a reorg. Every validator runs exactly this, so the pool's
//! state is identical on all of them.
//!
//! # The two transactions
//!
//! A deposit is an ordinary signed transfer to `SHIELDED_POOL_ADDR` whose memo
//! is `shield:<commitment>`. The memo is under the sender's signature, so a
//! relayer cannot swap the commitment for their own and take the deposit. The
//! amount must be one of the fixed denominations.
//!
//! A withdrawal is a transaction *from* the pool address, authorised by a
//! Groth16 proof rather than a signature. Its body, in `call_args`, carries the
//! root, nullifier, amount, recipient, fee and proof; the transaction hash is
//! a hash of that body, and the proof is bound to every field a relayer could
//! want to change. The whole note leaves the pool: the recipient receives the
//! amount less the fee, and the fee is treated like any other fee.
//!
//! # What is persisted
//!
//! Only the frontier of the commitment tree, the root history, the balance
//! and a counter, together with one key per leaf, one per commitment (for
//! duplicate checks and so a wallet can find its leaf), and one per spent
//! nullifier. The frontier means a deposit costs a validator one Poseidon
//! hash per tree level however many notes the pool holds. A copy of the state
//! is kept per block that changed it, so a reorg restores the state from just
//! before the first removed block in one read instead of replaying.
//!
//! All of it lives in the meta column family, which the checkpoint snapshot
//! already ships, so a fast-synced node validates withdrawals like any other.
//!
//! # Activation
//!
//! Nothing here is accepted until `rule_active` says so for the block's
//! height: a governance vote on `FEATURE_SHIELDED_POOL`, or the
//! `EGO_SHIELDED_POOL_HEIGHT` override for a testnet. A block carrying shielded
//! transactions before then is invalid, so nodes that predate this code and
//! nodes that have it agree on every block until the switch is thrown, and by
//! then every validator must be running it.

use crate::chain_db::{self, decode, encode, read_u64_le, u64_le, CF_META};
use crate::ledger::LedgerTx;
use crate::shielded::{
    field_to_bytes, is_denomination, public_to_field, recipient_digest, withdrawal_binding,
    ROOT_HISTORY,
};
use ark_bn254::{Bn254, Fr};
use ego_zk::merkle::{IncrementalTree, POOL_TREE_DEPTH};
use ego_zk::withdraw_circuit::{self, CanonicalDeserialize, Proof, WithdrawCircuit};
use rocksdb::{Direction, IteratorMode, WriteBatch, DB};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Where deposits go and withdrawals come from. A reserved system address:
/// nothing can sign for it, so nothing but a verified proof moves value out.
pub const SHIELDED_POOL_ADDR: &str = "egot1shieldedpool000000000000000000000000000";
pub const FEATURE_SHIELDED_POOL: &str = "shielded_pool";
pub const TX_SHIELD: &str = "shield";
pub const TX_UNSHIELD: &str = "unshield";

const MEMO_PREFIX: &str = "shield:";
const HASH_PREFIX: &[u8] = b"ego/unshield/v1:";
const KEY_STATE: &[u8] = b"shielded:state";
const KEY_LEAF: &[u8] = b"shielded:leaf:";
const KEY_CIDX: &[u8] = b"shielded:cidx:";
const KEY_NF: &[u8] = b"shielded:nf:";
const KEY_HIST: &[u8] = b"shielded:hist:";

pub fn rule_active(height: u64) -> bool {
    if let Ok(v) = std::env::var("EGO_SHIELDED_POOL_HEIGHT") {
        if let Ok(h) = v.parse::<u64>() {
            return height >= h;
        }
    }
    chain_db::is_feature_enabled(FEATURE_SHIELDED_POOL)
}

pub fn rule_active_at_tip() -> bool {
    rule_active(chain_db::local_chain_height().saturating_add(1))
}

// ── Persisted state ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PoolState {
    pub depth: u8,
    pub next_index: u64,
    pub frontier: Vec<[u8; 32]>,
    pub root: [u8; 32],
    /// Oldest first, at most `ROOT_HISTORY`.
    pub recent_roots: Vec<[u8; 32]>,
    pub balance_uegoc: u64,
}

impl PoolState {
    pub fn empty() -> Self {
        let t = IncrementalTree::new(POOL_TREE_DEPTH);
        let root = field_to_bytes(t.root());
        Self {
            depth: POOL_TREE_DEPTH as u8,
            next_index: 0,
            frontier: t.frontier().iter().map(|f| field_to_bytes(*f)).collect(),
            root,
            recent_roots: vec![root],
            balance_uegoc: 0,
        }
    }

    pub fn capacity(&self) -> u64 {
        1u64 << self.depth
    }

    pub fn is_full(&self) -> bool {
        self.next_index >= self.capacity()
    }

    pub fn is_known_root(&self, root: &[u8; 32]) -> bool {
        self.recent_roots.contains(root)
    }

    fn tree(&self) -> Result<IncrementalTree, String> {
        IncrementalTree::from_parts(
            self.depth as usize,
            self.next_index as usize,
            self.frontier.iter().map(public_to_field).collect(),
            public_to_field(&self.root),
        )
    }

    /// Append a commitment: one hash per level. Returns its leaf index.
    pub fn insert(&mut self, commitment: [u8; 32]) -> Result<u64, String> {
        let mut t = self.tree()?;
        let index = t.insert(public_to_field(&commitment))?;
        let (_, next, frontier, root) = t.parts();
        self.next_index = next as u64;
        self.frontier = frontier.iter().map(|f| field_to_bytes(*f)).collect();
        self.root = field_to_bytes(root);
        self.recent_roots.push(self.root);
        if self.recent_roots.len() > ROOT_HISTORY {
            self.recent_roots.remove(0);
        }
        Ok(index as u64)
    }
}

fn key(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(prefix.len() + suffix.len());
    k.extend_from_slice(prefix);
    k.extend_from_slice(suffix);
    k
}

fn leaf_key(index: u64) -> Vec<u8> {
    key(KEY_LEAF, &index.to_be_bytes())
}

fn cidx_key(commitment: &[u8; 32]) -> Vec<u8> {
    key(KEY_CIDX, commitment)
}

fn nf_key(nullifier: &[u8; 32]) -> Vec<u8> {
    key(KEY_NF, nullifier)
}

fn hist_key(height: u64) -> Vec<u8> {
    key(KEY_HIST, &height.to_be_bytes())
}

fn read_state(db: &DB) -> PoolState {
    db.cf_handle(CF_META)
        .and_then(|cf| db.get_cf(cf, KEY_STATE).ok().flatten())
        .and_then(|v| decode::<PoolState>(&v))
        .unwrap_or_else(PoolState::empty)
}

fn leaf_index_in(db: &DB, commitment: &[u8; 32]) -> Option<u64> {
    let cf = db.cf_handle(CF_META)?;
    let v = db.get_cf(cf, cidx_key(commitment)).ok().flatten()?;
    let bytes: [u8; 8] = v.as_slice().try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

fn nullifier_spent_in(db: &DB, nullifier: &[u8; 32]) -> bool {
    db.cf_handle(CF_META)
        .and_then(|cf| db.get_cf(cf, nf_key(nullifier)).ok().flatten())
        .is_some()
}

pub fn state() -> PoolState {
    let db = chain_db::get_db().lock().unwrap_or_else(|e| e.into_inner());
    read_state(db)
}

pub fn leaf_index_of(commitment: &[u8; 32]) -> Option<u64> {
    let db = chain_db::get_db().lock().unwrap_or_else(|e| e.into_inner());
    leaf_index_in(db, commitment)
}

pub fn is_nullifier_spent(nullifier: &[u8; 32]) -> bool {
    let db = chain_db::get_db().lock().unwrap_or_else(|e| e.into_inner());
    nullifier_spent_in(db, nullifier)
}

/// Every commitment in leaf order. The big-endian index key makes the
/// column family's own ordering the leaf ordering.
pub fn leaves() -> Vec<[u8; 32]> {
    let db = chain_db::get_db().lock().unwrap_or_else(|e| e.into_inner());
    let Some(cf) = db.cf_handle(CF_META) else { return vec![] };
    let mut out = Vec::new();
    for item in db.iterator_cf(cf, IteratorMode::From(KEY_LEAF, Direction::Forward)) {
        let Ok((k, v)) = item else { break };
        if !k.starts_with(KEY_LEAF) {
            break;
        }
        if let Ok(leaf) = <[u8; 32]>::try_from(v.as_ref()) {
            out.push(leaf);
        }
    }
    out
}

// ── Transaction shapes ────────────────────────────────────────────────────

pub fn is_deposit(tx: &LedgerTx) -> bool {
    tx.to == SHIELDED_POOL_ADDR
}

pub fn is_unshield(tx: &LedgerTx) -> bool {
    tx.from == SHIELDED_POOL_ADDR
}

pub fn touches_pool(tx: &LedgerTx) -> bool {
    is_deposit(tx) || is_unshield(tx)
}

/// What the recipient's balance gains: the whole note for a deposit's pool
/// credit, the note less the fee for a withdrawal.
pub fn credited_to_recipient(tx: &LedgerTx) -> u64 {
    if is_unshield(tx) {
        tx.amount.saturating_sub(tx.fee_uegoc)
    } else {
        tx.amount
    }
}

pub fn shield_memo(commitment: &[u8; 32]) -> String {
    format!("{MEMO_PREFIX}{}", hex::encode(commitment))
}

pub fn parse_shield_memo(memo: &Option<String>) -> Option<[u8; 32]> {
    let hex_part = memo.as_deref()?.strip_prefix(MEMO_PREFIX)?;
    if hex_part.len() != 64 {
        return None;
    }
    hex::decode(hex_part).ok()?.try_into().ok()
}

/// The body of a withdrawal, carried in `call_args` as JSON in this field
/// order. The hash is over the re-serialised struct, not the bytes received,
/// so two encodings of the same body are the same transaction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnshieldBody {
    pub root: String,
    pub nullifier: String,
    pub amount_uegoc: u64,
    pub recipient: String,
    pub fee_uegoc: u64,
    pub proof: String,
}

impl UnshieldBody {
    pub fn canonical_json(&self) -> String {
        serde_json::to_string(self).expect("a struct of strings and integers")
    }

    pub fn tx_hash(&self) -> String {
        let mut m = HASH_PREFIX.to_vec();
        m.extend_from_slice(self.canonical_json().as_bytes());
        format!("0x{}", ego_core::hash_data(&m).to_hex())
    }

    fn bytes32(field: &str, value: &str) -> Result<[u8; 32], String> {
        hex::decode(value)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| format!("unshield {field} is not 32 hex bytes"))
    }

    pub fn root_bytes(&self) -> Result<[u8; 32], String> {
        Self::bytes32("root", &self.root)
    }

    pub fn nullifier_bytes(&self) -> Result<[u8; 32], String> {
        Self::bytes32("nullifier", &self.nullifier)
    }

    pub fn proof(&self) -> Result<Proof<Bn254>, String> {
        let bytes = hex::decode(&self.proof).map_err(|_| "unshield proof is not hex".to_string())?;
        Proof::<Bn254>::deserialize_compressed(bytes.as_slice())
            .map_err(|e| format!("unshield proof does not decode: {e}"))
    }
}

pub fn parse_unshield_body(call_args: &str) -> Result<UnshieldBody, String> {
    serde_json::from_str::<UnshieldBody>(call_args).map_err(|e| format!("unshield body: {e}"))
}

pub fn unshield_nullifier(tx: &LedgerTx) -> Option<[u8; 32]> {
    if !is_unshield(tx) {
        return None;
    }
    parse_unshield_body(&tx.call_args).ok()?.nullifier_bytes().ok()
}

fn recipient_is_acceptable(addr: &str) -> Result<(), String> {
    if addr != addr.trim() || addr.is_empty() {
        return Err("unshield recipient is empty or padded".into());
    }
    if !addr.starts_with("egot1") || addr.len() < 10 || addr.len() > 100 {
        return Err("unshield recipient is not a testnet address".into());
    }
    if !addr.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) {
        return Err("unshield recipient has characters outside bech32".into());
    }
    if crate::ledger::is_reserved_system_source(addr) {
        return Err("unshield recipient is a system address".into());
    }
    Ok(())
}

// ── Validation ────────────────────────────────────────────────────────────

fn validate_deposit_in(
    db: &DB,
    state: &PoolState,
    tx: &LedgerTx,
    seen_commitments: &mut HashSet<[u8; 32]>,
) -> Result<(), String> {
    let commitment = parse_shield_memo(&tx.memo)
        .ok_or_else(|| format!("transfer {} to the shielded pool carries no shield:<commitment> memo", tx.hash))?;
    if !is_denomination(tx.amount) {
        return Err(format!("shield {} of {} uEGOC is not a denomination", tx.hash, tx.amount));
    }
    if state.is_full() {
        return Err(format!("shield {} refused: the commitment tree is full", tx.hash));
    }
    if leaf_index_in(db, &commitment).is_some() || !seen_commitments.insert(commitment) {
        return Err(format!("shield {} repeats a commitment already in the tree", tx.hash));
    }
    Ok(())
}

fn validate_unshield_in(
    db: &DB,
    state: &PoolState,
    tx: &LedgerTx,
    seen_nullifiers: &mut HashSet<[u8; 32]>,
) -> Result<(), String> {
    if tx.tx_type != TX_UNSHIELD {
        return Err(format!("tx {} from the shielded pool is not an unshield", tx.hash));
    }
    let body = parse_unshield_body(&tx.call_args)?;
    if tx.hash != body.tx_hash() {
        return Err(format!("unshield {} body/hash mismatch", tx.hash));
    }
    if tx.to != body.recipient || tx.amount != body.amount_uegoc || tx.fee_uegoc != body.fee_uegoc {
        return Err(format!("unshield {} fields disagree with its body", tx.hash));
    }
    if !tx.signature.is_empty() || !tx.public_key_ed25519.is_empty() || tx.nonce != 0 {
        return Err(format!("unshield {} must carry no signature and no nonce", tx.hash));
    }
    if !is_denomination(tx.amount) {
        return Err(format!("unshield {} of {} uEGOC is not a denomination", tx.hash, tx.amount));
    }
    if tx.fee_uegoc < crate::mempool::MIN_FEE_UEGOC || tx.fee_uegoc >= tx.amount {
        return Err(format!("unshield {} fee {} uEGOC is out of range", tx.hash, tx.fee_uegoc));
    }
    recipient_is_acceptable(&tx.to)?;
    let root = body.root_bytes()?;
    if !state.is_known_root(&root) {
        return Err(format!("unshield {} proves against a root the pool does not have", tx.hash));
    }
    let nullifier = body.nullifier_bytes()?;
    if nullifier_spent_in(db, &nullifier) || !seen_nullifiers.insert(nullifier) {
        return Err(format!("unshield {} spends a note that is already spent", tx.hash));
    }
    // Belt and braces. A verifying proof already means this note was
    // deposited, so the pool holds it; if this fires the state is corrupt and
    // paying out would compound it.
    if tx.amount > state.balance_uegoc {
        return Err(format!(
            "unshield {} of {} uEGOC exceeds the pool's {} uEGOC",
            tx.hash, tx.amount, state.balance_uegoc
        ));
    }
    let proof = body.proof()?;
    let inputs = WithdrawCircuit::public_inputs(
        public_to_field(&root),
        public_to_field(&nullifier),
        Fr::from(tx.amount),
        withdrawal_binding(&recipient_digest(&tx.to), tx.fee_uegoc),
    );
    match withdraw_circuit::verify(ego_zk::withdraw_params::verifying_key(), &inputs, &proof) {
        Ok(true) => Ok(()),
        _ => Err(format!("unshield {} proof does not verify", tx.hash)),
    }
}

/// Mempool and proposal entry for a deposit: no block context, so only the
/// current state is consulted.
pub fn verify_incoming_deposit(tx: &LedgerTx) -> Result<(), String> {
    if !rule_active_at_tip() {
        return Err("the shielded pool is not active on this chain".into());
    }
    let db = chain_db::get_db().lock().unwrap_or_else(|e| e.into_inner());
    let state = read_state(db);
    validate_deposit_in(db, &state, tx, &mut HashSet::new())
}

/// Mempool and proposal entry for a withdrawal.
pub fn verify_incoming_unshield(tx: &LedgerTx) -> Result<(), String> {
    if !rule_active_at_tip() {
        return Err("the shielded pool is not active on this chain".into());
    }
    let db = chain_db::get_db().lock().unwrap_or_else(|e| e.into_inner());
    let state = read_state(db);
    validate_unshield_in(db, &state, tx, &mut HashSet::new())
}

/// Block-context validation: the same checks, plus no two transactions in
/// one block may share a commitment or a nullifier, and the pool's capacity
/// and balance are tracked across the block.
pub fn validate_block_shielded_txs(height: u64, txs: &[LedgerTx]) -> Result<(), String> {
    if !txs.iter().any(touches_pool) {
        return Ok(());
    }
    if !rule_active(height) {
        return Err(format!(
            "block {height} carries shielded transactions but the shielded pool is not active"
        ));
    }
    let db = chain_db::get_db().lock().unwrap_or_else(|e| e.into_inner());
    let mut state = read_state(db);
    let mut seen_nullifiers = HashSet::new();
    let mut seen_commitments = HashSet::new();
    for tx in txs {
        if is_deposit(tx) {
            validate_deposit_in(db, &state, tx, &mut seen_commitments)?;
            state.next_index += 1;
            state.balance_uegoc = state.balance_uegoc.saturating_add(tx.amount);
        } else if is_unshield(tx) {
            validate_unshield_in(db, &state, tx, &mut seen_nullifiers)?;
            state.balance_uegoc = state.balance_uegoc.saturating_sub(tx.amount);
        }
    }
    Ok(())
}

// ── Application and reorg ─────────────────────────────────────────────────

/// Record a block's shielded transactions in the same batch as its balances.
/// The block has already been validated; anything malformed here is skipped
/// rather than trusted.
pub fn apply_block(db: &DB, batch: &mut WriteBatch, height: u64, txs: &[&LedgerTx]) {
    let Some(cf) = db.cf_handle(CF_META) else { return };
    let mut state = read_state(db);
    let mut changed = false;
    for tx in txs {
        if is_deposit(tx) {
            let Some(commitment) = parse_shield_memo(&tx.memo) else { continue };
            match state.insert(commitment) {
                Ok(index) => {
                    batch.put_cf(cf, leaf_key(index), commitment);
                    batch.put_cf(cf, cidx_key(&commitment), index.to_be_bytes());
                    state.balance_uegoc = state.balance_uegoc.saturating_add(tx.amount);
                    changed = true;
                }
                Err(e) => tracing::error!("[Shielded] block #{height}: deposit {} not recorded: {e}", tx.hash),
            }
        } else if is_unshield(tx) {
            let Some(nullifier) = unshield_nullifier(tx) else { continue };
            batch.put_cf(cf, nf_key(&nullifier), u64_le(height));
            state.balance_uegoc = state.balance_uegoc.saturating_sub(tx.amount);
            changed = true;
        }
    }
    if changed {
        let encoded = encode(&state);
        batch.put_cf(cf, KEY_STATE, &encoded);
        batch.put_cf(cf, hist_key(height), &encoded);
    }
}

/// Undo every block from `from_height` up: restore the state saved by the
/// last surviving block that touched the pool, drop the leaves those blocks
/// appended and the nullifiers they spent.
pub fn rollback(db: &DB, batch: &mut WriteBatch, from_height: u64, removed: &[LedgerTx]) {
    let Some(cf) = db.cf_handle(CF_META) else { return };
    let current = read_state(db);

    let mut restored: Option<PoolState> = None;
    if from_height > 0 {
        let upper = hist_key(from_height - 1);
        for item in db.iterator_cf(cf, IteratorMode::From(&upper, Direction::Reverse)) {
            let Ok((k, v)) = item else { break };
            if k.starts_with(KEY_HIST) {
                restored = decode::<PoolState>(&v);
            }
            break;
        }
    }
    let restored = restored.unwrap_or_else(PoolState::empty);

    let start = hist_key(from_height);
    for item in db.iterator_cf(cf, IteratorMode::From(&start, Direction::Forward)) {
        let Ok((k, _)) = item else { break };
        if !k.starts_with(KEY_HIST) {
            break;
        }
        batch.delete_cf(cf, k.as_ref());
    }

    for index in restored.next_index..current.next_index {
        if let Some(v) = db.get_cf(cf, leaf_key(index)).ok().flatten() {
            if let Ok(c) = <[u8; 32]>::try_from(v.as_slice()) {
                batch.delete_cf(cf, cidx_key(&c));
            }
        }
        batch.delete_cf(cf, leaf_key(index));
    }

    for tx in removed {
        if let Some(nullifier) = unshield_nullifier(tx) {
            batch.delete_cf(cf, nf_key(&nullifier));
        }
    }

    if current != restored {
        batch.put_cf(cf, KEY_STATE, encode(&restored));
    }
}

/// Undo a block's balance movements for the pool's transactions, the mirror
/// of the credit and debit `write_block_batch` applied.
pub fn reverse_balance_delta(tx: &LedgerTx, out: &mut std::collections::HashMap<String, i128>) -> bool {
    if !is_unshield(tx) {
        return false;
    }
    *out.entry(tx.to.clone()).or_insert(0) -= credited_to_recipient(tx) as i128;
    *out.entry(SHIELDED_POOL_ADDR.to_string()).or_insert(0) += tx.amount as i128;
    true
}

pub fn read_nullifier_height(nullifier: &[u8; 32]) -> Option<u64> {
    let db = chain_db::get_db().lock().unwrap_or_else(|e| e.into_inner());
    let cf = db.cf_handle(CF_META)?;
    db.get_cf(cf, nf_key(nullifier)).ok().flatten().map(|v| read_u64_le(&v))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shielded::{Note, ShieldedPool};
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};
    use std::sync::Mutex;

    static DB_TESTS: Mutex<()> = Mutex::new(());

    fn note(value: u64, tag: u8) -> Note {
        Note { value_uegoc: value, owner_secret: [tag; 32], rho: [tag.wrapping_add(1); 32] }
    }

    fn deposit_tx(n: &Note) -> LedgerTx {
        LedgerTx {
            hash: format!("0x{}", hex::encode(n.commitment())),
            from: "egot1depositor".into(),
            to: SHIELDED_POOL_ADDR.into(),
            amount: n.value_uegoc,
            memo: Some(shield_memo(&n.commitment())),
            tx_type: TX_SHIELD.into(),
            fee_uegoc: 1_000,
            ..LedgerTx::default()
        }
    }

    #[test]
    fn the_memo_round_trips_and_rejects_the_rest() {
        let c = note(1_000_000, 1).commitment();
        assert_eq!(parse_shield_memo(&Some(shield_memo(&c))), Some(c));
        assert_eq!(parse_shield_memo(&Some("shield:abcd".into())), None);
        assert_eq!(parse_shield_memo(&Some(format!("shield:{}", "zz".repeat(32)))), None);
        assert_eq!(parse_shield_memo(&Some("hello".into())), None);
        assert_eq!(parse_shield_memo(&None), None);
    }

    #[test]
    fn the_persisted_state_grows_the_same_tree_as_the_model() {
        let mut state = PoolState::empty();
        let mut model = ShieldedPool::new(POOL_TREE_DEPTH);
        assert_eq!(state.root, model.current_root());
        for i in 1..=5u8 {
            let c = note(1_000_000, i).commitment();
            let index = state.insert(c).unwrap();
            assert_eq!(index, model.deposit(c, 1_000_000).unwrap() as u64);
            assert_eq!(state.root, model.current_root(), "leaf {i}");
            assert!(state.is_known_root(&state.root));
        }
        assert_eq!(state.next_index, 5);
        let again: PoolState = decode(&encode(&state)).unwrap();
        assert_eq!(again, state);
    }

    #[test]
    fn the_unshield_hash_is_over_the_canonical_body() {
        let body = UnshieldBody {
            root: "00".repeat(32),
            nullifier: "11".repeat(32),
            amount_uegoc: 1_000_000,
            recipient: "egot1someone".into(),
            fee_uegoc: 1_000,
            proof: "22".repeat(8),
        };
        let reordered = r#"{"proof":"2222222222222222","fee_uegoc":1000,"recipient":"egot1someone","amount_uegoc":1000000,"nullifier":"1111111111111111111111111111111111111111111111111111111111111111","root":"0000000000000000000000000000000000000000000000000000000000000000"}"#;
        let parsed = parse_unshield_body(reordered).unwrap();
        assert_eq!(parsed, body);
        assert_eq!(parsed.tx_hash(), body.tx_hash());
        let mut other = body.clone();
        other.fee_uegoc += 1;
        assert_ne!(other.tx_hash(), body.tx_hash());
    }

    #[test]
    fn a_withdrawal_credits_the_recipient_net_of_the_fee() {
        let tx = LedgerTx {
            from: SHIELDED_POOL_ADDR.into(),
            to: "egot1someone".into(),
            amount: 1_000_000,
            fee_uegoc: 1_000,
            tx_type: TX_UNSHIELD.into(),
            ..LedgerTx::default()
        };
        assert_eq!(credited_to_recipient(&tx), 999_000);
        let mut out = std::collections::HashMap::new();
        assert!(reverse_balance_delta(&tx, &mut out));
        assert_eq!(out["egot1someone"], -999_000);
        assert_eq!(out[SHIELDED_POOL_ADDR], 1_000_000);
        assert!(!reverse_balance_delta(&deposit_tx(&note(1_000_000, 3)), &mut out));
    }

    #[test]
    fn recipients_are_checked_for_shape_and_reservation() {
        assert!(recipient_is_acceptable("egot1qw508d6qejxtdg4y5r3zarvary0c5xw7k").is_ok());
        assert!(recipient_is_acceptable(SHIELDED_POOL_ADDR).is_err());
        assert!(recipient_is_acceptable("egot1staking000000000000000000000000000000000").is_err());
        assert!(recipient_is_acceptable(" egot1qw508d6qejxtdg4y5r3zarvary0c5xw7k").is_err());
        assert!(recipient_is_acceptable("ego1qw508d6qejxtdg4y5r3zarvary0c5xw7k").is_err());
        assert!(recipient_is_acceptable("egot1QW508").is_err());
        assert!(recipient_is_acceptable("").is_err());
    }

    #[test]
    fn a_block_with_shielded_txs_is_refused_while_the_pool_is_inactive() {
        let _g = DB_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("EGO_SHIELDED_POOL_HEIGHT", "1000000000");
        let txs = vec![deposit_tx(&note(1_000_000, 9))];
        let err = validate_block_shielded_txs(5, &txs).unwrap_err();
        assert!(err.contains("not active"), "{err}");
        std::env::set_var("EGO_SHIELDED_POOL_HEIGHT", "0");
        assert!(validate_block_shielded_txs(5, &[]).is_ok());
        std::env::remove_var("EGO_SHIELDED_POOL_HEIGHT");
    }

    #[test]
    fn deposits_are_validated_applied_and_rolled_back() {
        let _g = DB_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("EGO_SHIELDED_POOL_HEIGHT", "0");
        let mut rng = StdRng::seed_from_u64(0xB10C);
        let a = Note::random(1_000_000, &mut rng);
        let b = Note::random(10_000_000, &mut rng);
        let bad_amount = LedgerTx { amount: 1_500_000, ..deposit_tx(&a) };
        let no_memo = LedgerTx { memo: None, ..deposit_tx(&a) };
        let height = 900_000_000 + (rng.next_u64() % 1_000_000);

        let before = state();
        assert!(validate_block_shielded_txs(height, &[bad_amount]).is_err());
        assert!(validate_block_shielded_txs(height, &[no_memo]).is_err());
        assert!(validate_block_shielded_txs(height, &[deposit_tx(&a), deposit_tx(&a)]).is_err(), "twice in one block");
        assert!(validate_block_shielded_txs(height, &[deposit_tx(&a), deposit_tx(&b)]).is_ok());

        {
            let db = chain_db::get_db().lock().unwrap_or_else(|e| e.into_inner());
            let mut batch = WriteBatch::default();
            let txs = [deposit_tx(&a), deposit_tx(&b)];
            apply_block(db, &mut batch, height, &txs.iter().collect::<Vec<_>>());
            db.write(batch).unwrap();
        }
        let after = state();
        assert_eq!(after.next_index, before.next_index + 2);
        assert_eq!(after.balance_uegoc, before.balance_uegoc + 11_000_000);
        assert_eq!(leaf_index_of(&a.commitment()), Some(before.next_index));
        assert_eq!(leaf_index_of(&b.commitment()), Some(before.next_index + 1));
        assert_eq!(leaves().len() as u64, after.next_index);
        assert!(validate_block_shielded_txs(height + 1, &[deposit_tx(&a)]).is_err(), "already in the tree");

        {
            let db = chain_db::get_db().lock().unwrap_or_else(|e| e.into_inner());
            let mut batch = WriteBatch::default();
            rollback(db, &mut batch, height, &[deposit_tx(&a), deposit_tx(&b)]);
            db.write(batch).unwrap();
        }
        let restored = state();
        assert_eq!(restored.next_index, before.next_index);
        assert_eq!(restored.root, before.root);
        assert_eq!(restored.balance_uegoc, before.balance_uegoc);
        assert_eq!(leaf_index_of(&a.commitment()), None);
        assert_eq!(leaves().len() as u64, before.next_index);
        std::env::remove_var("EGO_SHIELDED_POOL_HEIGHT");
    }

    #[test]
    fn a_withdrawal_needs_a_real_proof_and_spends_once() {
        let _g = DB_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("EGO_SHIELDED_POOL_HEIGHT", "0");
        let mut rng = StdRng::seed_from_u64(0x5EED);
        let n = Note::random(1_000_000, &mut rng);
        let height = 950_000_000 + (rng.next_u64() % 1_000_000);
        let recipient = "egot1qw508d6qejxtdg4y5r3zarvary0c5xw7k".to_string();
        let fee = 1_000u64;

        let before = state();
        {
            let db = chain_db::get_db().lock().unwrap_or_else(|e| e.into_inner());
            let mut batch = WriteBatch::default();
            let txs = [deposit_tx(&n)];
            apply_block(db, &mut batch, height, &txs.iter().collect::<Vec<_>>());
            db.write(batch).unwrap();
        }
        let index = leaf_index_of(&n.commitment()).unwrap() as usize;
        let all = leaves();
        let w = crate::shielded::prove_withdrawal(
            ego_zk::withdraw_params::proving_key(),
            POOL_TREE_DEPTH,
            &all,
            &n,
            index,
            recipient_digest(&recipient),
            fee,
            &mut rng,
        )
        .unwrap();
        let mut proof_bytes = Vec::new();
        ego_zk::withdraw_circuit::CanonicalSerialize::serialize_compressed(&w.proof, &mut proof_bytes).unwrap();
        let body = UnshieldBody {
            root: hex::encode(w.root),
            nullifier: hex::encode(w.nullifier),
            amount_uegoc: w.amount_uegoc,
            recipient: recipient.clone(),
            fee_uegoc: fee,
            proof: hex::encode(&proof_bytes),
        };
        let tx = LedgerTx {
            hash: body.tx_hash(),
            from: SHIELDED_POOL_ADDR.into(),
            to: recipient.clone(),
            amount: w.amount_uegoc,
            fee_uegoc: fee,
            tx_type: TX_UNSHIELD.into(),
            call_args: body.canonical_json(),
            ..LedgerTx::default()
        };
        assert!(verify_incoming_unshield(&tx).is_ok());
        assert!(validate_block_shielded_txs(height + 1, &[tx.clone(), tx.clone()]).is_err(), "twice in one block");

        let redirected = LedgerTx { to: "egot1qw508d6qejxtdg4y5r3zarvary0c5xw7l".into(), ..tx.clone() };
        assert!(verify_incoming_unshield(&redirected).is_err(), "fields disagree with the body");
        let mut rebodied = body.clone();
        rebodied.recipient = "egot1qw508d6qejxtdg4y5r3zarvary0c5xw7l".into();
        let redirected = LedgerTx {
            hash: rebodied.tx_hash(),
            to: rebodied.recipient.clone(),
            call_args: rebodied.canonical_json(),
            ..tx.clone()
        };
        assert!(verify_incoming_unshield(&redirected).unwrap_err().contains("does not verify"));
        let mut pricier = body.clone();
        pricier.fee_uegoc = fee + 1;
        let pricier_tx = LedgerTx {
            hash: pricier.tx_hash(),
            fee_uegoc: fee + 1,
            call_args: pricier.canonical_json(),
            ..tx.clone()
        };
        assert!(verify_incoming_unshield(&pricier_tx).unwrap_err().contains("does not verify"));
        let signed = LedgerTx { signature: "ab".into(), ..tx.clone() };
        assert!(verify_incoming_unshield(&signed).is_err());

        {
            let db = chain_db::get_db().lock().unwrap_or_else(|e| e.into_inner());
            let mut batch = WriteBatch::default();
            let txs = [tx.clone()];
            apply_block(db, &mut batch, height + 1, &txs.iter().collect::<Vec<_>>());
            db.write(batch).unwrap();
        }
        assert!(is_nullifier_spent(&w.nullifier));
        assert_eq!(read_nullifier_height(&w.nullifier), Some(height + 1));
        assert_eq!(state().balance_uegoc, before.balance_uegoc);
        assert!(verify_incoming_unshield(&tx).unwrap_err().contains("already spent"));

        {
            let db = chain_db::get_db().lock().unwrap_or_else(|e| e.into_inner());
            let mut batch = WriteBatch::default();
            rollback(db, &mut batch, height, &[deposit_tx(&n), tx.clone()]);
            db.write(batch).unwrap();
        }
        assert!(!is_nullifier_spent(&w.nullifier));
        assert_eq!(state(), before);
        std::env::remove_var("EGO_SHIELDED_POOL_HEIGHT");
    }
}
