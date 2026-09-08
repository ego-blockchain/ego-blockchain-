//! Wallet side of the shielded pool: keeping notes, shielding, unshielding.
//!
//! A note's secret is the money. Anyone holding it can withdraw the note, and
//! nobody without it ever can, the wallet included. So notes are written to
//! disk before the deposit is broadcast, never after, and the file is
//! encrypted under a key derived from the wallet seed: a seed backup restores
//! the ability to read it, and nothing else does.
//!
//! Shielding splits the amount into fixed denominations and sends one deposit
//! per note. Unshielding spends one whole note to one recipient, less the
//! network fee, and takes a second or two because the proof is built here.

use crate::app::AppState;
use crate::error::EgoDesktopError;
use crate::ledger::{data_dir, tx_human_summary, tx_signing_bytes_v2, Ledger, LedgerTx};
use crate::shielded::{self, denominate, Note, ShieldedPool, DENOMINATIONS_UEGOC};
use crate::shielded_chain::{self, UnshieldBody, SHIELDED_POOL_ADDR, TX_SHIELD, TX_UNSHIELD};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use ego_zk::withdraw_circuit::CanonicalSerialize;
use once_cell::sync::Lazy;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tauri::State;

const NOTES_FILE: &str = "shielded_notes.bin";
const NOTES_KEY_LABEL: &[u8] = b"ego/shielded-notes/v1:";
const CHAIN_ID: u8 = 1;

static NOTES_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

/// The tree a proof is built against, kept between withdrawals.
///
/// Building it costs one Poseidon hash per level per leaf, so rebuilding from
/// scratch every time would make a withdrawal from a pool with a million notes
/// take tens of seconds. The pool is append-only, so the tree is extended with
/// whatever arrived since it was last used, and only a reorg that rewrote an
/// existing leaf forces a rebuild.
static PROVER_POOL: Lazy<Mutex<Option<ShieldedPool>>> = Lazy::new(|| Mutex::new(None));

/// The current commitment tree, reusing the cached one where possible.
fn prover_pool() -> Result<ShieldedPool, String> {
    let leaves = shielded_chain::leaves();
    let mut cached = PROVER_POOL.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(pool) = cached.as_mut() {
        if pool.extend_from_leaves(&leaves).is_ok() {
            return Ok(pool.clone());
        }
        tracing::warn!("[Shielded] the commitment tree diverged, rebuilding it from the chain");
    }
    let pool = ShieldedPool::from_leaves(ego_zk::withdraw_params::DEPTH, &leaves)?;
    *cached = Some(pool.clone());
    Ok(pool)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredNote {
    pub note: Note,
    pub commitment: String,
    pub created_at: i64,
    pub deposit_tx: String,
    #[serde(default)]
    pub spent_tx: Option<String>,
    #[serde(default)]
    pub spent_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NoteView {
    pub commitment: String,
    pub value_uegoc: u64,
    pub leaf_index: Option<u64>,
    /// `pending` (deposit not yet in a block), `ready`, `spending`
    /// (withdrawal sent, not yet in a block) or `spent`.
    pub status: String,
    pub deposit_tx: String,
    pub spent_tx: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShieldedStatus {
    /// This wallet has opted in (`EGO_SHIELDED_POOL=unaudited-testnet-only`).
    pub enabled: bool,
    /// The chain accepts shielded transactions at the next height.
    pub active: bool,
    pub pool_address: String,
    pub pool_balance_uegoc: u64,
    pub leaf_count: u64,
    pub denominations_uegoc: Vec<u64>,
    pub min_fee_uegoc: u64,
    pub current_fee_uegoc: u64,
    pub verifying_key_digest: String,
    pub notes: Vec<NoteView>,
    pub ready_balance_uegoc: u64,
    pub pending_balance_uegoc: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShieldResult {
    pub tx_hashes: Vec<String>,
    pub notes: Vec<u64>,
    pub shielded_uegoc: u64,
    pub remainder_uegoc: u64,
    pub fee_total_uegoc: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct UnshieldResult {
    pub hash: String,
    pub amount_uegoc: u64,
    pub fee_uegoc: u64,
    pub payout_uegoc: u64,
    pub recipient: String,
}

// ── Note storage ──────────────────────────────────────────────────────────

fn notes_path() -> std::path::PathBuf {
    data_dir().join(NOTES_FILE)
}

fn notes_key() -> Result<[u8; 32], EgoDesktopError> {
    let seed = crate::ledger::load_seed()
        .map_err(EgoDesktopError::WalletError)?
        .ok_or_else(|| EgoDesktopError::WalletError("Wallet not initialized".into()))?;
    let mut material = NOTES_KEY_LABEL.to_vec();
    material.extend_from_slice(&seed);
    Ok(*ego_core::hash_data(&material).as_bytes())
}

fn load_notes() -> Result<Vec<StoredNote>, EgoDesktopError> {
    let path = notes_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = std::fs::read(&path).map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?;
    if data.len() < 28 {
        return Err(EgoDesktopError::DatabaseError("shielded notes file is truncated".into()));
    }
    let key = notes_key()?;
    let (nonce, ct) = data.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("32-byte key");
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| EgoDesktopError::CryptoError("shielded notes do not decrypt under this seed".into()))?;
    serde_json::from_slice(&plain).map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))
}

fn save_notes(notes: &[StoredNote]) -> Result<(), EgoDesktopError> {
    let key = notes_key()?;
    let plain = serde_json::to_vec(notes).map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("32-byte key");
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plain.as_slice())
        .map_err(|_| EgoDesktopError::CryptoError("could not encrypt shielded notes".into()))?;
    let mut out = nonce.to_vec();
    out.extend(ct);
    crate::utils::atomic_write(&notes_path(), &out).map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))
}

fn note_status(n: &StoredNote) -> (String, Option<u64>) {
    let commitment: Option<[u8; 32]> = hex::decode(&n.commitment).ok().and_then(|v| v.try_into().ok());
    let leaf_index = commitment.and_then(|c| shielded_chain::leaf_index_of(&c));
    let status = if n.spent_tx.is_some() {
        if shielded_chain::is_nullifier_spent(&n.note.nullifier()) { "spent" } else { "spending" }
    } else if leaf_index.is_some() {
        "ready"
    } else {
        "pending"
    };
    (status.to_string(), leaf_index)
}

fn require_open() -> Result<(), EgoDesktopError> {
    if !shielded::is_enabled() {
        return Err(EgoDesktopError::InvalidInput(
            "The shielded pool is a testnet preview. Start Ego Desktop with EGO_SHIELDED_POOL=unaudited-testnet-only to use it.".into(),
        ));
    }
    if !shielded_chain::rule_active_at_tip() {
        return Err(EgoDesktopError::InvalidInput(
            "This chain has not activated the shielded pool yet.".into(),
        ));
    }
    Ok(())
}

fn current_fee() -> u64 {
    crate::chain_db::get_current_base_fee().max(crate::mempool::MIN_FEE_UEGOC)
}

// ── Commands ──────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn shielded_status() -> Result<ShieldedStatus, EgoDesktopError> {
    tokio::task::spawn_blocking(|| {
        let _g = NOTES_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let enabled = shielded::is_enabled();
        let active = shielded_chain::rule_active_at_tip();
        let state = shielded_chain::state();
        let notes = if enabled { load_notes().unwrap_or_default() } else { Vec::new() };
        let mut views = Vec::with_capacity(notes.len());
        let mut ready = 0u64;
        let mut pending = 0u64;
        for n in &notes {
            let (status, leaf_index) = note_status(n);
            match status.as_str() {
                "ready" => ready = ready.saturating_add(n.note.value_uegoc),
                "pending" => pending = pending.saturating_add(n.note.value_uegoc),
                _ => {}
            }
            views.push(NoteView {
                commitment: n.commitment.clone(),
                value_uegoc: n.note.value_uegoc,
                leaf_index,
                status,
                deposit_tx: n.deposit_tx.clone(),
                spent_tx: n.spent_tx.clone(),
                created_at: n.created_at,
            });
        }
        views.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(ShieldedStatus {
            enabled,
            active,
            pool_address: SHIELDED_POOL_ADDR.to_string(),
            pool_balance_uegoc: state.balance_uegoc,
            leaf_count: state.next_index,
            denominations_uegoc: DENOMINATIONS_UEGOC.to_vec(),
            min_fee_uegoc: crate::mempool::MIN_FEE_UEGOC,
            current_fee_uegoc: current_fee(),
            verifying_key_digest: ego_zk::withdraw_params::verifying_key_digest(),
            notes: views,
            ready_balance_uegoc: ready,
            pending_balance_uegoc: pending,
        })
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

/// Move `amount_uegoc` into the pool as fixed-denomination notes, one signed
/// deposit each. The part below the smallest denomination stays transparent.
#[tauri::command]
pub async fn shield_deposit(
    amount_uegoc: u64,
    state: State<'_, AppState>,
) -> Result<ShieldResult, EgoDesktopError> {
    require_open()?;
    let _guard = crate::ledger::TX_MUTEX.lock().await;
    let kp = state
        .get_keypair()
        .ok_or_else(|| EgoDesktopError::WalletError("Wallet not initialized – call init_wallet first".into()))?;
    let mut ledger = Ledger::load();
    let from = ledger.address.clone();
    if from.is_empty() {
        return Err(EgoDesktopError::WalletError("Wallet not initialized – call init_wallet first".into()));
    }

    let (values, remainder) = denominate(amount_uegoc);
    if values.is_empty() {
        return Err(EgoDesktopError::InvalidInput(format!(
            "Shield at least {} EGOC; notes come in fixed sizes",
            DENOMINATIONS_UEGOC[0] / 1_000_000
        )));
    }
    let is_staker = ledger.staked_amount > 0;
    let fee = crate::tokenomics::fee_for_tx_with_staking("transfer", is_staker);
    let shielded_total: u64 = values.iter().sum();
    let fee_total = fee.saturating_mul(values.len() as u64);

    let confirmed_bal = crate::chain_db::balance_of(&from);
    let pending_out: u64 = crate::mempool::get_mempool()
        .peek_all()
        .into_iter()
        .filter(|tx| tx.from.trim() == from.trim())
        .map(|tx| tx.amount.saturating_add(tx.fee_uegoc))
        .sum();
    let balance = confirmed_bal.saturating_sub(pending_out);
    let needed = shielded_total.saturating_add(fee_total);
    if needed > balance {
        return Err(EgoDesktopError::InvalidInput(format!(
            "Insufficient balance: have {} uEGOC, need {} ({} in notes + {} in fees for {} deposits)",
            balance, needed, shielded_total, fee_total, values.len()
        )));
    }

    let confirmed_nonce = crate::ledger::last_confirmed_nonce(&from);
    let mut nonce = ledger.nonce.max(confirmed_nonce);
    let now = chrono::Utc::now().timestamp();
    let ed_pk = hex::encode(kp.ed25519_public_key().as_bytes());
    let dil_pk = hex::encode(&kp.dilithium_public_key().key_data);

    let mut txs = Vec::with_capacity(values.len());
    let mut stored = Vec::with_capacity(values.len());
    for value in &values {
        nonce += 1;
        let note = Note::random(*value, &mut OsRng);
        let commitment = note.commitment();
        let memo = shielded_chain::shield_memo(&commitment);
        let sign_bytes = tx_signing_bytes_v2(&from, SHIELDED_POOL_ADDR, *value, nonce, now, CHAIN_ID, &memo);
        let ed_sig = kp.sign_ed25519(&sign_bytes);
        let dil_sig = kp.sign_dilithium(&sign_bytes);
        let hash = format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex());
        let summary = tx_human_summary(&from, SHIELDED_POOL_ADDR, *value, &memo, CHAIN_ID, nonce, fee);
        txs.push(LedgerTx {
            hash: hash.clone(),
            from: from.clone(),
            to: SHIELDED_POOL_ADDR.to_string(),
            amount: *value,
            memo: Some(memo),
            timestamp: now,
            signature: hex::encode(ed_sig.as_bytes()),
            status: "Pending".into(),
            block_height: None,
            nonce,
            public_key_ed25519: ed_pk.clone(),
            dilithium_pubkey: dil_pk.clone(),
            dilithium_signature: hex::encode(&dil_sig.signature_data),
            tx_type: TX_SHIELD.to_string(),
            fee_uegoc: fee,
            tx_version: 2,
            chain_id: CHAIN_ID,
            signed_summary: summary,
            ..LedgerTx::default()
        });
        stored.push(StoredNote {
            note,
            commitment: hex::encode(commitment),
            created_at: now,
            deposit_tx: hash,
            spent_tx: None,
            spent_at: None,
        });
    }

    // The notes are the money. They go to disk before anything leaves this
    // machine, so a crash between here and the broadcast loses nothing.
    {
        let _g = NOTES_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut all = load_notes()?;
        all.extend(stored);
        save_notes(&all)?;
    }

    // Reserve the nonces now rather than after the broadcast. They are already
    // signed into the transactions above, so if one push fails partway the
    // rest are still in flight and the next send must not reuse their numbers.
    ledger.nonce = nonce;
    let _ = ledger.save();

    let mut hashes = Vec::with_capacity(txs.len());
    for tx in txs {
        crate::mempool::get_mempool()
            .push(tx.clone())
            .map_err(|e| EgoDesktopError::WalletError(format!("deposit refused: {e}")))?;
        crate::commands::tx_pending::add(&tx);
        hashes.push(tx.hash.clone());
        let gossip = tx.clone();
        tauri::async_runtime::spawn(async move {
            crate::p2p::broadcast_pending_tx(gossip).await;
        });
    }

    Ok(ShieldResult {
        tx_hashes: hashes,
        notes: values,
        shielded_uegoc: shielded_total,
        remainder_uegoc: remainder,
        fee_total_uegoc: fee_total,
    })
}

/// Spend one whole note to `recipient`. The recipient receives the note's
/// value less the current network fee.
#[tauri::command]
pub async fn shield_withdraw(
    commitment: String,
    recipient: String,
) -> Result<UnshieldResult, EgoDesktopError> {
    require_open()?;
    let recipient = recipient.trim().to_string();
    crate::commands::wallet::validate_ego_address(&recipient)?;
    if crate::ledger::is_reserved_system_source(&recipient) {
        return Err(EgoDesktopError::InvalidInput("Cannot unshield to a system address".into()));
    }
    let _guard = crate::ledger::TX_MUTEX.lock().await;

    let (stored, leaf_index) = {
        let _g = NOTES_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let notes = load_notes()?;
        let n = notes
            .iter()
            .find(|n| n.commitment == commitment)
            .cloned()
            .ok_or_else(|| EgoDesktopError::InvalidInput("No such note in this wallet".into()))?;
        if n.spent_tx.is_some() {
            return Err(EgoDesktopError::InvalidInput("This note has already been spent".into()));
        }
        let c: [u8; 32] = hex::decode(&n.commitment)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| EgoDesktopError::DatabaseError("stored commitment is malformed".into()))?;
        let index = shielded_chain::leaf_index_of(&c).ok_or_else(|| {
            EgoDesktopError::InvalidInput("This note's deposit has not been confirmed yet".into())
        })?;
        (n, index)
    };
    if shielded_chain::is_nullifier_spent(&stored.note.nullifier()) {
        return Err(EgoDesktopError::InvalidInput("This note has already been spent on-chain".into()));
    }

    let fee = current_fee();
    let note = stored.note.clone();
    let recipient_for_proof = recipient.clone();
    let withdrawal = tokio::task::spawn_blocking(move || {
        let pool = prover_pool()?;
        shielded::prove_withdrawal(
            ego_zk::withdraw_params::proving_key(),
            &pool,
            &note,
            leaf_index as usize,
            shielded::recipient_digest(&recipient_for_proof),
            fee,
            &mut OsRng,
        )
    })
    .await
    .map_err(|e| EgoDesktopError::CryptoError(format!("proving task: {e}")))?
    .map_err(EgoDesktopError::CryptoError)?;

    let mut proof_bytes = Vec::new();
    withdrawal
        .proof
        .serialize_compressed(&mut proof_bytes)
        .map_err(|e| EgoDesktopError::CryptoError(format!("proof encoding: {e}")))?;
    let body = UnshieldBody {
        root: hex::encode(withdrawal.root),
        nullifier: hex::encode(withdrawal.nullifier),
        amount_uegoc: withdrawal.amount_uegoc,
        recipient: recipient.clone(),
        fee_uegoc: fee,
        proof: hex::encode(&proof_bytes),
    };
    let now = chrono::Utc::now().timestamp();
    let tx = LedgerTx {
        hash: body.tx_hash(),
        from: SHIELDED_POOL_ADDR.to_string(),
        to: recipient.clone(),
        amount: withdrawal.amount_uegoc,
        memo: None,
        timestamp: now,
        status: "Pending".into(),
        tx_type: TX_UNSHIELD.to_string(),
        fee_uegoc: fee,
        call_args: body.canonical_json(),
        signed_summary: format!(
            "Unshield {:.6} EGOC\n  To:      {}\n  Fee:     {:.6} EGOC\n  Payout:  {:.6} EGOC",
            withdrawal.amount_uegoc as f64 / 1_000_000.0,
            recipient,
            fee as f64 / 1_000_000.0,
            withdrawal.amount_uegoc.saturating_sub(fee) as f64 / 1_000_000.0,
        ),
        ..LedgerTx::default()
    };

    // Mark the note spent before the withdrawal can leave, so a crash cannot
    // leave a note that looks fresh while its nullifier is in flight.
    {
        let _g = NOTES_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut notes = load_notes()?;
        if let Some(n) = notes.iter_mut().find(|n| n.commitment == commitment) {
            n.spent_tx = Some(tx.hash.clone());
            n.spent_at = Some(now);
        }
        save_notes(&notes)?;
    }
    if let Err(e) = crate::mempool::get_mempool().push(tx.clone()) {
        let _g = NOTES_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if let Ok(mut notes) = load_notes() {
            if let Some(n) = notes.iter_mut().find(|n| n.commitment == commitment) {
                n.spent_tx = None;
                n.spent_at = None;
            }
            let _ = save_notes(&notes);
        }
        return Err(EgoDesktopError::WalletError(format!("withdrawal refused: {e}")));
    }
    crate::commands::tx_pending::add(&tx);
    let gossip = tx.clone();
    tauri::async_runtime::spawn(async move {
        crate::p2p::broadcast_pending_tx(gossip).await;
    });

    Ok(UnshieldResult {
        hash: tx.hash,
        amount_uegoc: withdrawal.amount_uegoc,
        fee_uegoc: fee,
        payout_uegoc: withdrawal.amount_uegoc.saturating_sub(fee),
        recipient,
    })
}

/// What the node has recorded about its own accounting.
///
/// A healthy chain reports nothing here. Anything at all means a block was
/// written whose balance changes did not add up, or whose shielded note counts
/// were impossible, and the detail says which. Surfaced as a command so an
/// operator can see it without reading logs, since by default a violation is
/// recorded rather than fatal.
#[derive(Debug, Clone, Serialize)]
pub struct InvariantReport {
    pub healthy: bool,
    pub strict: bool,
    pub violations: Vec<String>,
}

#[tauri::command]
pub async fn invariant_report() -> Result<InvariantReport, EgoDesktopError> {
    let violations: Vec<String> = crate::invariants::violations()
        .iter()
        .map(|v| v.describe())
        .collect();
    Ok(InvariantReport {
        healthy: violations.is_empty(),
        strict: crate::invariants::strict(),
        violations,
    })
}
