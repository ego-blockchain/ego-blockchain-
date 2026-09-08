use crate::chain_db::{self, decode, encode, read_u64_le, u64_le, CF_BALANCES, CF_META};
use crate::ledger::LedgerTx;
use crate::shielded::{
    from_digest, is_denomination, leaf_for, recipient_digest, to_digest, verify_proof_bytes,
    DENOMINATIONS_UEGOC, POOL_TREE_DEPTH, ROOT_HISTORY,
};
use ego_stark::merkle::IncrementalTree;
use rocksdb::{Direction, IteratorMode, WriteBatch, DB};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

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
    if chain_db::is_feature_enabled(FEATURE_SHIELDED_POOL) {
        return true;
    }
    !matches!(
        std::env::var("EGO_SHIELDED_POOL").as_deref().map(str::trim),
        Ok("0") | Ok("off") | Ok("OFF") | Ok("false") | Ok("False")
    )
}

pub fn rule_active_at_tip() -> bool {
    rule_active(chain_db::local_chain_height().saturating_add(1))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PoolState {
    pub depth: u8,
    pub next_index: u64,
    pub frontier: Vec<[u8; 32]>,
    pub root: [u8; 32],
    pub recent_roots: Vec<[u8; 32]>,
    pub balance_uegoc: u64,
    #[serde(default)]
    pub outstanding: Vec<u64>,
}

pub fn denomination_index(amount_uegoc: u64) -> Option<usize> {
    DENOMINATIONS_UEGOC.iter().position(|d| *d == amount_uegoc)
}

impl PoolState {
    pub fn empty() -> Self {
        let t = IncrementalTree::new(POOL_TREE_DEPTH);
        let root = from_digest(&t.root());
        Self {
            depth: POOL_TREE_DEPTH as u8,
            next_index: 0,
            frontier: t.frontier().iter().map(from_digest).collect(),
            root,
            recent_roots: vec![root],
            balance_uegoc: 0,
            outstanding: vec![0; DENOMINATIONS_UEGOC.len()],
        }
    }

    fn normalise(&mut self) {
        if self.outstanding.len() != DENOMINATIONS_UEGOC.len() {
            self.outstanding.resize(DENOMINATIONS_UEGOC.len(), 0);
        }
    }

    pub fn note_added(&mut self, amount_uegoc: u64) {
        self.normalise();
        if let Some(i) = denomination_index(amount_uegoc) {
            self.outstanding[i] = self.outstanding[i].saturating_add(1);
        }
    }

    pub fn note_spent(&mut self, amount_uegoc: u64) -> bool {
        self.normalise();
        match denomination_index(amount_uegoc) {
            Some(i) if self.outstanding[i] > 0 => {
                self.outstanding[i] -= 1;
                true
            }
            _ => false,
        }
    }

    pub fn has_note(&self, amount_uegoc: u64) -> bool {
        denomination_index(amount_uegoc)
            .and_then(|i| self.outstanding.get(i))
            .is_some_and(|n| *n > 0)
    }

    pub fn counted_uegoc(&self) -> u128 {
        self.outstanding
            .iter()
            .zip(DENOMINATIONS_UEGOC.iter())
            .map(|(n, d)| *n as u128 * *d as u128)
            .sum()
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
            self.frontier.iter().map(|f| to_digest(f)).collect::<Result<Vec<_>, _>>()?,
            to_digest(&self.root)?,
        )
    }

    pub fn insert(&mut self, leaf: [u8; 32]) -> Result<u64, String> {
        let mut t = self.tree()?;
        let index = t.insert(to_digest(&leaf)?)?;
        let (_, next, frontier, root) = t.parts();
        self.next_index = next as u64;
        self.frontier = frontier.iter().map(from_digest).collect();
        self.root = from_digest(&root);
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
    let mut state = db
        .cf_handle(CF_META)
        .and_then(|cf| db.get_cf(cf, KEY_STATE).ok().flatten())
        .and_then(|v| decode::<PoolState>(&v))
        .unwrap_or_else(PoolState::empty);
    state.normalise();
    state
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

pub fn is_deposit(tx: &LedgerTx) -> bool {
    tx.to == SHIELDED_POOL_ADDR
}

pub fn is_unshield(tx: &LedgerTx) -> bool {
    tx.from == SHIELDED_POOL_ADDR
}

pub fn touches_pool(tx: &LedgerTx) -> bool {
    is_deposit(tx) || is_unshield(tx)
}

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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnshieldSpend {
    pub root: String,
    pub nullifier: String,
    pub amount_uegoc: u64,
    pub fee_uegoc: u64,
    pub proof: String,
}

impl UnshieldSpend {
    pub fn root_bytes(&self) -> Result<[u8; 32], String> {
        UnshieldBody::bytes32("root", &self.root)
    }
    pub fn nullifier_bytes(&self) -> Result<[u8; 32], String> {
        UnshieldBody::bytes32("nullifier", &self.nullifier)
    }
    pub fn proof_bytes(&self) -> Result<Vec<u8>, String> {
        hex::decode(&self.proof).map_err(|_| "unshield proof is not hex".to_string())
    }
}

pub const MAX_UNSHIELD_SPENDS: usize = 16;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnshieldBody {
    pub spends: Vec<UnshieldSpend>,
    pub recipient: String,
    pub amount_uegoc: u64,
    pub fee_uegoc: u64,
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

    pub(crate) fn bytes32(field: &str, value: &str) -> Result<[u8; 32], String> {
        hex::decode(value)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| format!("unshield {field} is not 32 hex bytes"))
    }

    pub fn totals(&self) -> (u64, u64) {
        self.spends.iter().fold((0u64, 0u64), |(a, f), sp| {
            (a.saturating_add(sp.amount_uegoc), f.saturating_add(sp.fee_uegoc))
        })
    }
}

pub fn parse_unshield_body(call_args: &str) -> Result<UnshieldBody, String> {
    serde_json::from_str::<UnshieldBody>(call_args).map_err(|e| format!("unshield body: {e}"))
}

pub fn unshield_nullifiers(tx: &LedgerTx) -> Vec<[u8; 32]> {
    if !is_unshield(tx) {
        return Vec::new();
    }
    let Ok(body) = parse_unshield_body(&tx.call_args) else { return Vec::new() };
    body.spends.iter().filter_map(|sp| sp.nullifier_bytes().ok()).collect()
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
    if body.spends.is_empty() {
        return Err(format!("unshield {} spends nothing", tx.hash));
    }
    if body.spends.len() > MAX_UNSHIELD_SPENDS {
        return Err(format!(
            "unshield {} spends {} notes, over the {} limit",
            tx.hash, body.spends.len(), MAX_UNSHIELD_SPENDS
        ));
    }
    let (total_amount, total_fee) = body.totals();
    if total_amount != tx.amount {
        return Err(format!(
            "unshield {} spends {} uEGOC but claims {}",
            tx.hash, total_amount, tx.amount
        ));
    }
    if total_fee != tx.fee_uegoc {
        return Err(format!(
            "unshield {} fee shares total {} uEGOC but the tx charges {}",
            tx.hash, total_fee, tx.fee_uegoc
        ));
    }
    if tx.fee_uegoc < crate::mempool::MIN_FEE_UEGOC || tx.fee_uegoc >= tx.amount {
        return Err(format!("unshield {} fee {} uEGOC is out of range", tx.hash, tx.fee_uegoc));
    }
    recipient_is_acceptable(&tx.to)?;
    let mut wanted: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
    let recipient = recipient_digest(&tx.to);
    for sp in &body.spends {
        if !is_denomination(sp.amount_uegoc) {
            return Err(format!(
                "unshield {} spends {} uEGOC, which is not a denomination",
                tx.hash, sp.amount_uegoc
            ));
        }
        let root = sp.root_bytes()?;
        if !state.is_known_root(&root) {
            return Err(format!("unshield {} proves against a root the pool does not have", tx.hash));
        }
        let nullifier = sp.nullifier_bytes()?;
        if nullifier_spent_in(db, &nullifier) || !seen_nullifiers.insert(nullifier) {
            return Err(format!("unshield {} spends a note that is already spent", tx.hash));
        }
        let held = denomination_index(sp.amount_uegoc)
            .and_then(|i| state.outstanding.get(i).copied())
            .unwrap_or(0);
        let want = wanted.entry(sp.amount_uegoc).or_insert(0);
        *want += 1;
        if *want > held {
            return Err(if held == 0 {
                format!(
                    "unshield {} claims a {} uEGOC note but the pool holds none of that size",
                    tx.hash, sp.amount_uegoc
                )
            } else {
                format!(
                    "unshield {} spends {} notes of {} uEGOC but the pool holds only {}",
                    tx.hash, want, sp.amount_uegoc, held
                )
            });
        }
        let proof = sp.proof_bytes()?;
        if !verify_proof_bytes(&proof, root, nullifier, sp.amount_uegoc, recipient, sp.fee_uegoc) {
            return Err(format!("unshield {} proof does not verify", tx.hash));
        }
    }
    if tx.amount > state.balance_uegoc {
        return Err(format!(
            "unshield {} of {} uEGOC exceeds the pool's {} uEGOC",
            tx.hash, tx.amount, state.balance_uegoc
        ));
    }
    Ok(())
}

pub fn verify_incoming_deposit(tx: &LedgerTx) -> Result<(), String> {
    if !rule_active_at_tip() {
        return Err("the shielded pool is not active on this chain".into());
    }
    let db = chain_db::get_db().lock().unwrap_or_else(|e| e.into_inner());
    let state = read_state(db);
    validate_deposit_in(db, &state, tx, &mut HashSet::new())
}

pub fn verify_incoming_unshield(tx: &LedgerTx) -> Result<(), String> {
    if !rule_active_at_tip() {
        return Err("the shielded pool is not active on this chain".into());
    }
    let db = chain_db::get_db().lock().unwrap_or_else(|e| e.into_inner());
    let state = read_state(db);
    validate_unshield_in(db, &state, tx, &mut HashSet::new())
}

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
            state.note_added(tx.amount);
        } else if is_unshield(tx) {
            validate_unshield_in(db, &state, tx, &mut seen_nullifiers)?;
            state.balance_uegoc = state.balance_uegoc.saturating_sub(tx.amount);
            if let Ok(body) = parse_unshield_body(&tx.call_args) {
                for sp in &body.spends {
                    state.note_spent(sp.amount_uegoc);
                }
            }
        }
    }
    Ok(())
}

pub fn apply_block(db: &DB, batch: &mut WriteBatch, height: u64, txs: &[&LedgerTx]) {
    let Some(cf) = db.cf_handle(CF_META) else { return };
    let mut state = read_state(db);
    let mut changed = false;
    let mut seen_commitments: HashSet<[u8; 32]> = HashSet::new();
    let mut seen_nullifiers: HashSet<[u8; 32]> = HashSet::new();
    for tx in txs {
        if is_deposit(tx) {
            let Some(commitment) = parse_shield_memo(&tx.memo) else { continue };
            if leaf_index_in(db, &commitment).is_some() || !seen_commitments.insert(commitment) {
                tracing::error!(
                    "[Shielded] block #{height}: deposit {} repeats a commitment, not recorded",
                    tx.hash
                );
                continue;
            }
            match state.insert(leaf_for(&commitment, tx.amount)) {
                Ok(index) => {
                    batch.put_cf(cf, leaf_key(index), leaf_for(&commitment, tx.amount));
                    batch.put_cf(cf, cidx_key(&commitment), index.to_be_bytes());
                    state.balance_uegoc = state.balance_uegoc.saturating_add(tx.amount);
                    state.note_added(tx.amount);
                    changed = true;
                }
                Err(e) => tracing::error!("[Shielded] block #{height}: deposit {} not recorded: {e}", tx.hash),
            }
        } else if is_unshield(tx) {
            let Ok(body) = parse_unshield_body(&tx.call_args) else { continue };
            let nullifiers = unshield_nullifiers(tx);
            if nullifiers.len() != body.spends.len() {
                tracing::error!(
                    "[Shielded] block #{height}: withdrawal {} has unreadable nullifiers, not recorded",
                    tx.hash
                );
                continue;
            }
            if nullifiers.iter().any(|n| nullifier_spent_in(db, n) || seen_nullifiers.contains(n)) {
                tracing::error!(
                    "[Shielded] block #{height}: withdrawal {} spends a spent note, not recorded",
                    tx.hash
                );
                continue;
            }
            for n in &nullifiers {
                seen_nullifiers.insert(*n);
                batch.put_cf(cf, nf_key(n), u64_le(height));
            }
            state.balance_uegoc = state.balance_uegoc.saturating_sub(tx.amount);
            for sp in &body.spends {
                if !state.note_spent(sp.amount_uegoc) {
                    crate::invariants::report(crate::invariants::Violation::OutstandingNotes {
                        height,
                        detail: format!(
                            "withdrawal {} spent a {} uEGOC note the pool never held",
                            tx.hash, sp.amount_uegoc
                        ),
                    });
                }
            }
            changed = true;
        }
    }
    if changed {
        let encoded = encode(&state);
        batch.put_cf(cf, KEY_STATE, &encoded);
        batch.put_cf(cf, hist_key(height), &encoded);
        prune_history(db, batch, crate::chain_db::finality_floor_height(db));
    }
}

fn prune_history(db: &DB, batch: &mut WriteBatch, floor: u64) {
    if floor == 0 {
        return;
    }
    let Some(cf) = db.cf_handle(CF_META) else { return };
    let mut newest_below: Option<Box<[u8]>> = None;
    for item in db.iterator_cf(cf, IteratorMode::From(KEY_HIST, Direction::Forward)) {
        let Ok((k, _)) = item else { break };
        if !k.starts_with(KEY_HIST) || k.len() < KEY_HIST.len() + 8 {
            break;
        }
        let mut hb = [0u8; 8];
        hb.copy_from_slice(&k[KEY_HIST.len()..KEY_HIST.len() + 8]);
        if u64::from_be_bytes(hb) > floor {
            break;
        }
        if let Some(older) = newest_below.replace(k) {
            batch.delete_cf(cf, older.as_ref());
        }
    }
}

pub fn check_invariants(db: &DB, height: u64) {
    let state = read_state(db);
    if state.next_index == 0 && state.balance_uegoc == 0 {
        return;
    }
    let on_chain = db
        .cf_handle(CF_BALANCES)
        .and_then(|cf| db.get_cf(cf, SHIELDED_POOL_ADDR.as_bytes()).ok().flatten())
        .map(|v| read_u64_le(&v))
        .unwrap_or(0);
    if on_chain != state.balance_uegoc {
        crate::invariants::report(crate::invariants::Violation::ShieldedPoolMismatch {
            height,
            recorded_uegoc: state.balance_uegoc,
            on_chain_uegoc: on_chain,
        });
    }
    let counted = state.counted_uegoc();
    if counted != state.balance_uegoc as u128 {
        crate::invariants::report(crate::invariants::Violation::OutstandingNotes {
            height,
            detail: format!(
                "{} unspent notes are worth {counted} uEGOC but the pool holds {}",
                state.outstanding.iter().sum::<u64>(),
                state.balance_uegoc
            ),
        });
    }
}

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
        batch.delete_cf(cf, leaf_key(index));
    }

    for tx in removed {
        if is_deposit(tx) {
            if let Some(commitment) = parse_shield_memo(&tx.memo) {
                batch.delete_cf(cf, cidx_key(&commitment));
            }
        }
        for nullifier in unshield_nullifiers(tx) {
            batch.delete_cf(cf, nf_key(&nullifier));
        }
    }

    if current != restored {
        batch.put_cf(cf, KEY_STATE, encode(&restored));
    }
}

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
        Note::new(value, [tag; 32], [tag.wrapping_add(1); 32])
    }

    fn deposit_tx(n: &Note) -> LedgerTx {
        LedgerTx {
            hash: format!("0x{}", hex::encode(n.commitment())),
            from: "egot1depositor".into(),
            to: SHIELDED_POOL_ADDR.into(),
            amount: n.value_uegoc(),
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
            let index = state.insert(leaf_for(&c, 1_000_000)).unwrap();
            assert_eq!(index, model.deposit(c, 1_000_000).unwrap() as u64);
            assert_eq!(state.root, model.current_root(), "leaf {i}");
            assert!(state.is_known_root(&state.root));
        }
        assert_eq!(state.next_index, 5);
        let again: PoolState = decode(&encode(&state)).unwrap();
        assert_eq!(again, state);
    }

    #[test]
    fn note_counts_track_deposits_and_refuse_to_go_negative() {
        let mut st = PoolState::empty();
        assert_eq!(st.counted_uegoc(), 0);
        assert!(!st.has_note(1_000_000));

        st.note_added(1_000_000);
        st.note_added(1_000_000);
        st.note_added(10_000_000_000);
        assert!(st.has_note(1_000_000));
        assert!(st.has_note(10_000_000_000));
        assert!(!st.has_note(100_000_000), "nobody deposited one of those");
        assert_eq!(st.counted_uegoc(), 2 * 1_000_000 + 10_000_000_000);

        assert!(st.note_spent(1_000_000));
        assert!(st.note_spent(1_000_000));
        assert!(!st.note_spent(1_000_000), "the third spend has nothing to spend");
        assert!(!st.has_note(1_000_000));
        assert_eq!(st.counted_uegoc(), 10_000_000_000);

        assert!(!st.note_spent(12_345));
        assert!(!st.has_note(12_345));
    }

    #[test]
    fn note_counts_survive_a_state_written_before_they_existed() {
        let mut st = PoolState::empty();
        st.outstanding.clear();
        st.note_added(1_000_000);
        assert!(st.has_note(1_000_000));
        assert_eq!(st.outstanding.len(), DENOMINATIONS_UEGOC.len());
    }

    #[test]
    fn a_withdrawal_of_a_size_nobody_deposited_is_refused() {
        let _g = DB_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("EGO_SHIELDED_POOL_HEIGHT", "0");
        let mut rng = StdRng::from_entropy();
        let recipient = "egot1qw508d6qejxtdg4y5r3zarvary0c5xw7k".to_string();
        let fee = 1_000u64;
        let state = state();

        let mut nullifier = [0u8; 32];
        rng.fill_bytes(&mut nullifier);
        let body = UnshieldBody {
            spends: vec![UnshieldSpend {
                root: hex::encode(state.root),
                nullifier: hex::encode(nullifier),
                amount_uegoc: 10_000_000_000,
                fee_uegoc: fee,
                proof: hex::encode([0u8; 128]),
            }],
            recipient: recipient.clone(),
            amount_uegoc: 10_000_000_000,
            fee_uegoc: fee,
        };
        let tx = LedgerTx {
            hash: body.tx_hash(),
            from: SHIELDED_POOL_ADDR.into(),
            to: recipient,
            amount: body.amount_uegoc,
            fee_uegoc: fee,
            tx_type: TX_UNSHIELD.into(),
            call_args: body.canonical_json(),
            ..LedgerTx::default()
        };
        let err = verify_incoming_unshield(&tx).unwrap_err();
        assert!(
            err.contains("holds none of that size"),
            "expected the note count to refuse it, got: {err}"
        );
        std::env::remove_var("EGO_SHIELDED_POOL_HEIGHT");
    }

    fn random_denomination(rng: &mut StdRng) -> u64 {
        DENOMINATIONS_UEGOC[(rng.next_u64() % DENOMINATIONS_UEGOC.len() as u64) as usize]
    }

    #[test]
    fn the_frontier_and_the_full_tree_agree_over_random_deposits() {
        let mut rng = StdRng::from_entropy();
        let mut model = ShieldedPool::new(POOL_TREE_DEPTH);
        let mut state = PoolState::empty();
        assert_eq!(state.root, model.current_root());

        for step in 0..64u64 {
            let amount = random_denomination(&mut rng);
            let n = Note::random(amount, &mut rng);
            let c = n.commitment();

            let model_index = model.deposit(c, amount).unwrap() as u64;
            let state_index = state.insert(leaf_for(&c, amount)).unwrap();
            state.balance_uegoc = state.balance_uegoc.saturating_add(amount);
            state.note_added(amount);

            assert_eq!(state_index, model_index, "leaf index at step {step}");
            assert_eq!(state.root, model.current_root(), "root at step {step}");
            assert_eq!(state.balance_uegoc, model.balance(), "balance at step {step}");
            assert_eq!(
                state.counted_uegoc(),
                state.balance_uegoc as u128,
                "counted notes at step {step}"
            );
            assert!(state.is_known_root(&state.root));
            assert!(model.is_known_root(&model.current_root()));
        }
        assert_eq!(state.next_index, 64);
    }

    #[test]
    fn the_root_windows_age_identically() {
        let mut rng = StdRng::from_entropy();
        let mut model = ShieldedPool::new(POOL_TREE_DEPTH);
        let mut state = PoolState::empty();
        let mut roots = Vec::new();
        for _ in 0..(ROOT_HISTORY + 5) {
            let amount = random_denomination(&mut rng);
            let n = Note::random(amount, &mut rng);
            model.deposit(n.commitment(), amount).unwrap();
            state.insert(leaf_for(&n.commitment(), amount)).unwrap();
            roots.push(state.root);
        }
        assert_eq!(state.recent_roots.len(), ROOT_HISTORY);
        for r in roots.iter().rev().take(ROOT_HISTORY) {
            assert!(state.is_known_root(r), "a recent root must still be accepted");
            assert!(model.is_known_root(r));
        }
        for r in roots.iter().take(5) {
            assert!(!state.is_known_root(r), "an aged root must be refused");
            assert!(!model.is_known_root(r));
        }
    }

    #[test]
    fn a_rollback_lands_where_a_fresh_pool_would() {
        let _g = DB_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("EGO_SHIELDED_POOL_HEIGHT", "0");
        let mut rng = StdRng::from_entropy();
        let base = 700_000_000 + (rng.next_u64() % 1_000_000);

        let before_leaves = leaves();
        let before_state = state();

        let mut blocks: Vec<Vec<LedgerTx>> = Vec::new();
        for b in 0..3u64 {
            let mut txs = Vec::new();
            for _ in 0..=(rng.next_u64() % 3) {
                let amount = random_denomination(&mut rng);
                txs.push(deposit_tx(&Note::random(amount, &mut rng)));
            }
            {
                let db = chain_db::get_db().lock().unwrap_or_else(|e| e.into_inner());
                let mut batch = WriteBatch::default();
                apply_block(db, &mut batch, base + b, &txs.iter().collect::<Vec<_>>());
                db.write(batch).unwrap();
            }
            blocks.push(txs);
        }

        let grown = state();
        assert!(grown.next_index > before_state.next_index);
        let rebuilt = ShieldedPool::from_leaves(POOL_TREE_DEPTH, &leaves()).unwrap();
        assert_eq!(grown.root, rebuilt.current_root(), "frontier disagrees with the full tree");

        let removed: Vec<LedgerTx> = blocks[1..].iter().flatten().cloned().collect();
        {
            let db = chain_db::get_db().lock().unwrap_or_else(|e| e.into_inner());
            let mut batch = WriteBatch::default();
            rollback(db, &mut batch, base + 1, &removed);
            db.write(batch).unwrap();
        }

        let after = state();
        let surviving = leaves();
        let fresh = ShieldedPool::from_leaves(POOL_TREE_DEPTH, &surviving).unwrap();
        assert_eq!(after.root, fresh.current_root(), "rollback root");
        assert_eq!(after.next_index as usize, surviving.len(), "rollback leaf count");
        assert_eq!(
            after.counted_uegoc(),
            after.balance_uegoc as u128,
            "note counts must still add up after a rollback"
        );
        let expected_balance: u64 = before_state.balance_uegoc
            + blocks[0].iter().map(|t| t.amount).sum::<u64>();
        assert_eq!(after.balance_uegoc, expected_balance, "rollback balance");
        for tx in &removed {
            let c = parse_shield_memo(&tx.memo).unwrap();
            assert_eq!(leaf_index_of(&c), None, "a rolled-back commitment must be forgotten");
        }
        for tx in &blocks[0] {
            let c = parse_shield_memo(&tx.memo).unwrap();
            assert!(leaf_index_of(&c).is_some(), "a surviving commitment must stay indexed");
        }

        {
            let db = chain_db::get_db().lock().unwrap_or_else(|e| e.into_inner());
            let mut batch = WriteBatch::default();
            rollback(db, &mut batch, base, &blocks[0].clone());
            db.write(batch).unwrap();
        }
        assert_eq!(leaves(), before_leaves);
        assert_eq!(state().root, before_state.root);
        std::env::remove_var("EGO_SHIELDED_POOL_HEIGHT");
    }

    #[test]
    fn the_unshield_hash_is_over_the_canonical_body() {
        let body = UnshieldBody {
            spends: vec![UnshieldSpend {
                root: "00".repeat(32),
                nullifier: "11".repeat(32),
                amount_uegoc: 1_000_000,
                fee_uegoc: 1_000,
                proof: "22".repeat(8),
            }],
            recipient: "egot1someone".into(),
            amount_uegoc: 1_000_000,
            fee_uegoc: 1_000,
        };
        let reordered = r#"{"fee_uegoc":1000,"recipient":"egot1someone","amount_uegoc":1000000,"spends":[{"proof":"2222222222222222","fee_uegoc":1000,"amount_uegoc":1000000,"nullifier":"1111111111111111111111111111111111111111111111111111111111111111","root":"0000000000000000000000000000000000000000000000000000000000000000"}]}"#;
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
        let mut rng = StdRng::from_entropy();
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
    fn one_withdrawal_can_spend_several_notes_at_once() {
        let _g = DB_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("EGO_SHIELDED_POOL_HEIGHT", "0");
        let mut rng = StdRng::from_entropy();
        let recipient = "egot1qw508d6qejxtdg4y5r3zarvary0c5xw7k".to_string();
        let height = 950_000_000 + (rng.next_u64() % 1_000_000);

        let notes: Vec<Note> = vec![
            Note::random(100_000_000, &mut rng),
            Note::random(100_000_000, &mut rng),
            Note::random(10_000_000, &mut rng),
        ];
        {
            let db = chain_db::get_db().lock().unwrap_or_else(|e| e.into_inner());
            let mut batch = WriteBatch::default();
            let txs: Vec<LedgerTx> = notes.iter().map(deposit_tx).collect();
            apply_block(db, &mut batch, height, &txs.iter().collect::<Vec<_>>());
            db.write(batch).unwrap();
        }

        let pool = ShieldedPool::from_leaves(POOL_TREE_DEPTH, &leaves()).unwrap();
        let shares = [400u64, 400, 200];
        let total_fee: u64 = shares.iter().sum();
        let spends: Vec<UnshieldSpend> = notes
            .iter()
            .zip(shares.iter())
            .map(|(n, share)| {
                let index = leaf_index_of(&n.commitment()).unwrap() as usize;
                let w = crate::shielded::prove_withdrawal(
                    &pool, n, index, recipient_digest(&recipient), *share,
                ).unwrap();
                UnshieldSpend {
                    root: hex::encode(w.root),
                    nullifier: hex::encode(w.nullifier),
                    amount_uegoc: w.amount_uegoc,
                    fee_uegoc: *share,
                    proof: hex::encode(&w.proof),
                }
            })
            .collect();
        let total: u64 = spends.iter().map(|sp| sp.amount_uegoc).sum();
        assert_eq!(total, 210_000_000, "three notes make an amount no single note could");

        let body = UnshieldBody {
            spends,
            recipient: recipient.clone(),
            amount_uegoc: total,
            fee_uegoc: total_fee,
        };
        let tx = LedgerTx {
            hash: body.tx_hash(),
            from: SHIELDED_POOL_ADDR.into(),
            to: recipient.clone(),
            amount: total,
            fee_uegoc: total_fee,
            tx_type: TX_UNSHIELD.into(),
            call_args: body.canonical_json(),
            ..LedgerTx::default()
        };
        assert!(verify_incoming_unshield(&tx).is_ok(), "a three-note withdrawal must verify");

        let mut repeated = body.clone();
        repeated.spends[1] = repeated.spends[0].clone();
        let repeated_tx = LedgerTx {
            hash: repeated.tx_hash(),
            call_args: repeated.canonical_json(),
            ..tx.clone()
        };
        assert!(
            verify_incoming_unshield(&repeated_tx).unwrap_err().contains("already spent"),
            "spending the same note twice inside one withdrawal must be refused",
        );

        let mut skimmed = body.clone();
        skimmed.spends.pop();
        let skimmed_tx = LedgerTx {
            hash: skimmed.tx_hash(),
            call_args: skimmed.canonical_json(),
            ..tx.clone()
        };
        assert!(
            verify_incoming_unshield(&skimmed_tx).unwrap_err().contains("claims"),
            "the spends must add up to the amount the transaction moves",
        );

        {
            let db = chain_db::get_db().lock().unwrap_or_else(|e| e.into_inner());
            let mut batch = WriteBatch::default();
            apply_block(db, &mut batch, height + 1, &[&tx]);
            db.write(batch).unwrap();
        }
        for n in &notes {
            assert!(is_nullifier_spent(&n.nullifier()), "every note in the withdrawal is spent");
        }
        assert!(
            verify_incoming_unshield(&tx).unwrap_err().contains("already spent"),
            "the withdrawal cannot be replayed",
        );
        std::env::remove_var("EGO_SHIELDED_POOL_HEIGHT");
    }

    #[test]
    fn a_withdrawal_needs_a_real_proof_and_spends_once() {
        let _g = DB_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("EGO_SHIELDED_POOL_HEIGHT", "0");
        let mut rng = StdRng::from_entropy();
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
        let pool = ShieldedPool::from_leaves(POOL_TREE_DEPTH, &leaves()).unwrap();
        let w = crate::shielded::prove_withdrawal(
            &pool,
            &n,
            index,
            recipient_digest(&recipient),
            fee,
        )
        .unwrap();
        let proof_bytes = w.proof.clone();
        let body = UnshieldBody {
            spends: vec![UnshieldSpend {
                root: hex::encode(w.root),
                nullifier: hex::encode(w.nullifier),
                amount_uegoc: w.amount_uegoc,
                fee_uegoc: fee,
                proof: hex::encode(&proof_bytes),
            }],
            recipient: recipient.clone(),
            amount_uegoc: w.amount_uegoc,
            fee_uegoc: fee,
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
        pricier.spends[0].fee_uegoc = fee + 1;
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
