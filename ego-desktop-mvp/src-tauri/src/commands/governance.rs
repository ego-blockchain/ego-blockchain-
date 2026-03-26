use tauri::State;
use crate::app::AppState;
use crate::error::EgoDesktopError;
use crate::chain_db::{
    GovernanceProposal, FEATURE_DILITHIUM_DISABLED, FEATURE_DILITHIUM_REQUIRED,
    DaoProposalPublic, DaoProposalResults,
    store_dao_proposal, get_dao_proposal_public, list_dao_proposals,
    cast_dao_stake_vote, grade_dao_knowledge_test, cast_dao_knowledge_vote, get_dao_results,
    DaoProposal, DaoKnowledgeTest, DaoTestQuestion,
};
use crate::ledger::{tx_signing_bytes, LedgerTx, Ledger};
use crate::mempool;

// ── Legacy feature-flag governance ────────────────────────────────────────────

#[tauri::command]
pub async fn submit_governance_vote(
    feature:     String,
    action:      String,
    activate_at: u64,
    state:       State<'_, AppState>,
) -> Result<String, EgoDesktopError> {
    if action != "enable" && action != "disable" {
        return Err(EgoDesktopError::InvalidInput("action must be 'enable' or 'disable'".into()));
    }
    let known = [FEATURE_DILITHIUM_DISABLED, FEATURE_DILITHIUM_REQUIRED];
    if !known.contains(&feature.as_str()) {
        return Err(EgoDesktopError::InvalidInput(
            format!("unknown feature '{}'. Known: {:?}", feature, known)
        ));
    }
    let ledger = Ledger::load();
    let from = ledger.address.clone();
    if from.is_empty() {
        return Err(EgoDesktopError::WalletError("wallet not initialized".into()));
    }
    let nonce      = ledger.nonce + 1;
    let ts         = chrono::Utc::now().timestamp();
    let sign_bytes = tx_signing_bytes(
        &from, "egot1governance000000000000000000000000000000", activate_at, nonce, ts,
    );
    let (ed_sig, dil_pk, dil_sig) = match state.get_keypair() {
        Some(kp) => (
            hex::encode(kp.sign_ed25519(&sign_bytes).as_bytes()),
            hex::encode(kp.dilithium_public_key().key_data),
            hex::encode(kp.sign_dilithium(&sign_bytes).as_bytes()),
        ),
        None => return Err(EgoDesktopError::WalletError("wallet not initialized".into())),
    };
    let tx_hash = format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex());
    let tx = LedgerTx {
        hash: tx_hash.clone(), from: from.clone(),
        to:   "egot1governance000000000000000000000000000000".into(),
        amount: activate_at, timestamp: ts, signature: ed_sig,
        dilithium_pubkey: dil_pk, dilithium_signature: dil_sig,
        status: "Pending".into(), nonce, tx_type: "governance".into(),
        contract_addr: feature.clone(), entrypoint: action.clone(),
        ..LedgerTx::default()
    };
    mempool::get_mempool().push(tx);
    let mut l = Ledger::load();
    l.nonce = nonce;
    let _ = l.save();
    Ok(format!("Governance vote submitted: {} '{}' at block {} (tx {})", action, feature, activate_at, tx_hash))
}

#[tauri::command]
pub fn get_governance_proposals() -> Result<Vec<GovernanceProposal>, EgoDesktopError> {
    Ok(crate::chain_db::get_all_governance_proposals())
}

#[tauri::command]
pub fn is_feature_active(feature: String, action: String) -> bool {
    match action.as_str() {
        "enable"  => crate::chain_db::is_feature_enabled(&feature),
        "disable" => crate::chain_db::is_feature_disabled(&feature),
        _         => false,
    }
}

// ── DAO Proposal System ────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct NewTestQuestion {
    pub question:      String,
    pub options:       Vec<String>,
    pub correct_index: usize,
}

fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Create a new community DAO proposal. Any wallet holder can submit.
#[tauri::command]
pub async fn create_dao_proposal(
    title:         String,
    description:   String,
    proposal_type: String,
    options:       Vec<String>,
    duration_days: Option<u32>,
    questions:     Option<Vec<NewTestQuestion>>,
) -> Result<String, EgoDesktopError> {
    let ledger = Ledger::load();
    let creator = ledger.address.clone();
    if creator.is_empty() {
        return Err(EgoDesktopError::WalletError("wallet not initialized".into()));
    }
    if title.trim().is_empty() {
        return Err(EgoDesktopError::InvalidInput("Title is required".into()));
    }
    if options.len() < 2 {
        return Err(EgoDesktopError::InvalidInput("At least 2 options required".into()));
    }
    let known_types = ["protocol", "resource", "feature", "parameter", "tender"];
    if !known_types.contains(&proposal_type.as_str()) {
        return Err(EgoDesktopError::InvalidInput(
            format!("Unknown type '{}'. Use: {}", proposal_type, known_types.join(", "))
        ));
    }
    if let Some(ref qs) = questions {
        for (i, q) in qs.iter().enumerate() {
            if q.options.len() < 2 {
                return Err(EgoDesktopError::InvalidInput(
                    format!("Question {} needs at least 2 options", i + 1)
                ));
            }
            if q.correct_index >= q.options.len() {
                return Err(EgoDesktopError::InvalidInput(
                    format!("Question {} correct_index out of range", i + 1)
                ));
            }
        }
    }

    let now = now_ts();
    let id_input = format!("{}{}{}", creator, title.trim(), now);
    let id = format!("dao{}", &ego_core::hash_data(id_input.as_bytes()).to_hex()[..16]);

    let knowledge_test = questions.map(|qs| DaoKnowledgeTest {
        questions: qs.into_iter().enumerate().map(|(i, q)| DaoTestQuestion {
            id: format!("q{}", i), question: q.question,
            options: q.options, correct_index: q.correct_index,
        }).collect(),
        created_by: creator.clone(),
    });

    let duration_secs = duration_days.map(|d| d as i64 * 86_400).unwrap_or(7 * 86_400);

    let proposal = DaoProposal {
        id: id.clone(), title, description, proposal_type, options, creator,
        created_at: now, voting_ends_at: now + duration_secs,
        status: "active".to_string(), knowledge_test,
        stake_votes:     Default::default(),
        knowledge_votes: Default::default(),
    };

    store_dao_proposal(proposal).map_err(|e| EgoDesktopError::WalletError(e))?;
    Ok(id)
}

/// List proposals. status_filter: "all" | "active" | "passed" | "failed" | "expired"
#[tauri::command]
pub fn get_dao_proposals(status_filter: Option<String>) -> Result<Vec<DaoProposalPublic>, EgoDesktopError> {
    let ledger = Ledger::load();
    let voter = if ledger.address.is_empty() { None } else { Some(ledger.address) };
    Ok(list_dao_proposals(status_filter.as_deref(), voter.as_deref()))
}

/// Get a single proposal with questions (no correct answers) and your vote status.
#[tauri::command]
pub fn get_dao_proposal(proposal_id: String) -> Result<DaoProposalPublic, EgoDesktopError> {
    let ledger = Ledger::load();
    let voter = if ledger.address.is_empty() { None } else { Some(ledger.address) };
    get_dao_proposal_public(&proposal_id, voter.as_deref())
        .ok_or(EgoDesktopError::WalletError("Proposal not found".into()))
}

/// Cast a stake-weighted vote. Power = your EGOC balance / total voting balance.
#[tauri::command]
pub async fn cast_stake_vote(
    proposal_id:  String,
    option_index: usize,
) -> Result<(), EgoDesktopError> {
    let ledger = Ledger::load();
    let voter = ledger.address.clone();
    if voter.is_empty() {
        return Err(EgoDesktopError::WalletError("wallet not initialized".into()));
    }
    let balance = crate::chain_db::balance_of(&voter);
    if balance == 0 {
        return Err(EgoDesktopError::InvalidInput(
            "You need EGOC balance to participate in stake voting".into()
        ));
    }
    cast_dao_stake_vote(&proposal_id, option_index, &voter, balance)
        .map_err(|e| EgoDesktopError::InvalidInput(e))
}

/// Grade a knowledge test without casting a vote. Returns score 0.0–1.0.
#[tauri::command]
pub fn grade_knowledge_test(
    proposal_id: String,
    answers:     Vec<usize>,
) -> Result<f64, EgoDesktopError> {
    grade_dao_knowledge_test(&proposal_id, &answers)
        .map_err(|e| EgoDesktopError::InvalidInput(e))
}

/// Submit knowledge test answers and cast a knowledge vote. Returns your score.
#[tauri::command]
pub async fn cast_knowledge_vote(
    proposal_id:  String,
    option_index: usize,
    answers:      Vec<usize>,
) -> Result<f64, EgoDesktopError> {
    let ledger = Ledger::load();
    let voter = ledger.address.clone();
    if voter.is_empty() {
        return Err(EgoDesktopError::WalletError("wallet not initialized".into()));
    }
    cast_dao_knowledge_vote(&proposal_id, option_index, &voter, &answers)
        .map_err(|e| EgoDesktopError::InvalidInput(e))
}

/// Get combined stake + knowledge results for a proposal.
#[tauri::command]
pub fn get_proposal_results(proposal_id: String) -> Result<DaoProposalResults, EgoDesktopError> {
    get_dao_results(&proposal_id)
        .ok_or(EgoDesktopError::WalletError("Proposal not found".into()))
}
