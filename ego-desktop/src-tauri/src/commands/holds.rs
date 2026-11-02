use crate::app::AppState;
use crate::drs::Ov;
use crate::error::EgoDesktopError;
use crate::hold_chain::{self as hc, Phase, Tally};
use crate::ledger::{Ledger, LedgerTx};
use serde::Serialize;
use tauri::State;

fn err(e: impl std::fmt::Display) -> EgoDesktopError {
    EgoDesktopError::InvalidInput(e.to_string())
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

#[derive(Debug, Serialize)]
pub struct HoldView {
    pub id: String,
    pub requester: String,
    pub victim: String,
    pub case: String,
    pub bond: u64,
    pub theft: Vec<String>,
    pub hops: Vec<String>,
    pub created: i64,
    pub phase: Phase,
    pub amounts: Vec<(String, u64)>,
    pub held_at: i64,
    pub vote_ends: i64,
    pub return_opened: i64,
    pub return_ends: i64,
    pub appeals: Vec<(String, String)>,
    pub confirm: Tally,
    pub ret: Tally,
    pub my_stake_vote: Option<bool>,
    pub my_node_vote: Option<bool>,
    pub my_return_stake_vote: Option<bool>,
    pub my_return_node_vote: Option<bool>,
    pub stake_total: u64,
    pub node_total: u64,
    pub committee: usize,
    pub paid: bool,
}

#[derive(Debug, Serialize)]
pub struct HoldsStatus {
    pub active: bool,
    pub me: String,
    pub is_node: bool,
    pub my_stake: u64,
    pub my_locked: u64,
    pub node_pool: u64,
    pub min_node_pool: u64,
    pub request_fee: u64,
    pub min_bond: u64,
    pub holds: Vec<HoldView>,
}

fn status_now() -> HoldsStatus {
    let me = Ledger::load().address;
    let ov = Ov::new(crate::chain_db::global_db());
    let at = now();
    let mut holds: Vec<HoldView> = hc::live(&ov)
        .iter()
        .filter_map(|id| hc::load_hold(&ov, id))
        .map(|h| HoldView {
            phase: hc::phase(&ov, &h, at),
            confirm: hc::tally(&ov, &h.id, hc::PHASE_CONFIRM),
            ret: hc::tally(&ov, &h.id, hc::PHASE_RETURN),
            my_stake_vote: hc::my_vote(&ov, &h.id, hc::PHASE_CONFIRM, false, &me),
            my_node_vote: hc::my_vote(&ov, &h.id, hc::PHASE_CONFIRM, true, &me),
            my_return_stake_vote: hc::my_vote(&ov, &h.id, hc::PHASE_RETURN, false, &me),
            my_return_node_vote: hc::my_vote(&ov, &h.id, hc::PHASE_RETURN, true, &me),
            vote_ends: if h.held_at > 0 { hc::vote_end(&h) } else { h.created + hc::SIGN_WINDOW_SECS },
            return_ends: if h.return_opened > 0 { h.return_opened + hc::VOTE_SECS } else { 0 },
            id: h.id,
            requester: h.requester,
            victim: h.request.victim,
            case: h.request.case,
            bond: h.request.bond,
            theft: h.request.theft,
            hops: h.request.hops,
            created: h.created,
            amounts: h.amounts,
            held_at: h.held_at,
            return_opened: h.return_opened,
            appeals: h.appeals,
            stake_total: h.stake_total,
            node_total: h.node_total,
            committee: h.keys.len(),
            paid: h.paid,
        })
        .collect();
    holds.sort_by(|a, b| b.created.cmp(&a.created));
    HoldsStatus {
        active: hc::rule_active_at_tip(),
        is_node: crate::drs::load_rec(&ov, &me).is_some(),
        my_stake: crate::dao_chain::stake_of(&ov, &me),
        my_locked: hc::locked(&ov, &me, at),
        node_pool: crate::drs::node_count(&ov),
        min_node_pool: hc::MIN_NODE_POOL,
        request_fee: hc::REQUEST_FEE_UEGOC,
        min_bond: hc::MIN_BOND_UEGOC,
        me,
        holds,
    }
}

#[tauri::command]
pub async fn get_holds() -> Result<HoldsStatus, EgoDesktopError> {
    tokio::task::spawn_blocking(status_now).await.map_err(err)
}

async fn submit(state: &AppState, tx_type: &str, body: &impl Serialize, fee_floor: u64) -> Result<String, EgoDesktopError> {
    if !hc::rule_active_at_tip() {
        return Err(err("Theft holds are not switched on in the network yet"));
    }
    let _guard = crate::ledger::TX_MUTEX.lock().await;
    let mut ledger = Ledger::load();
    if ledger.address.is_empty() {
        return Err(EgoDesktopError::WalletError("wallet not initialized".into()));
    }
    let call_args = serde_json::to_string(body).map_err(err)?;
    let memo = hc::memo_for(tx_type, &call_args).ok_or(err(format!("{tx_type} is not a hold transaction")))?;
    let fee = crate::tokenomics::fee_for_tx_with_staking("transfer", ledger.staked_amount > 0).max(fee_floor);
    let kp = state.get_keypair().ok_or(EgoDesktopError::WalletError("wallet not initialized".into()))?;
    let mut tx = LedgerTx {
        from: ledger.address.clone(),
        to: ledger.address.clone(),
        amount: 0,
        memo: Some(memo),
        timestamp: now(),
        status: "Pending".into(),
        nonce: crate::ledger::next_nonce_for(&ledger.address, ledger.nonce),
        fee_uegoc: fee,
        chain_id: 1,
        tx_type: tx_type.to_string(),
        call_args,
        ..LedgerTx::default()
    };
    crate::ledger::seal_tx(&mut tx, &kp, true);
    crate::ledger::verify_incoming_tx(&tx).map_err(err)?;
    ledger.nonce = tx.nonce;
    let hash = tx.hash.clone();
    crate::commands::credits::queue_tx(tx, ledger).await;
    Ok(hash)
}

#[tauri::command]
pub async fn hold_request(
    victim: String,
    theft: Vec<String>,
    hops: Vec<String>,
    case: String,
    bond: u64,
    state: State<'_, AppState>,
) -> Result<String, EgoDesktopError> {
    let me = Ledger::load().address;
    let body = hc::RequestBody {
        victim: victim.trim().to_string(),
        theft: theft.into_iter().map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect(),
        hops: hops.into_iter().map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect(),
        case: case.trim().to_string(),
        bond,
    };
    hc::check_request(&me, &body).map_err(err)?;
    let hash = submit(&state, hc::TX_REQUEST, &body, hc::REQUEST_FEE_UEGOC).await?;
    Ok(hc::hold_id(&hash))
}

#[tauri::command]
pub async fn hold_vote(id: String, phase: String, yes: bool, as_node: bool, state: State<'_, AppState>) -> Result<String, EgoDesktopError> {
    let tx_type = if as_node { hc::TX_NODE_VOTE } else { hc::TX_VOTE };
    submit(&state, tx_type, &hc::VoteBody { id, phase, yes }, 0).await
}

#[tauri::command]
pub async fn hold_appeal(id: String, text: String, state: State<'_, AppState>) -> Result<String, EgoDesktopError> {
    submit(&state, hc::TX_APPEAL, &hc::AppealBody { id, text: text.trim().to_string() }, 0).await
}

#[tauri::command]
pub async fn hold_open_return(id: String, state: State<'_, AppState>) -> Result<String, EgoDesktopError> {
    submit(&state, hc::TX_RETURN, &hc::IdBody { id }, 0).await
}
