use tauri::State;
use crate::app::AppState;
use crate::error::EgoDesktopError;
use crate::chain_db::{
    GovernanceProposal, FEATURE_DILITHIUM_DISABLED, FEATURE_DILITHIUM_REQUIRED,
    DaoProposalPublic, DaoProposalResults, ProposerBanStatus,
    store_dao_proposal, get_dao_proposal_public, list_dao_proposals,
    cast_dao_stake_vote, grade_dao_knowledge_test, cast_dao_knowledge_vote, get_dao_results,
    vote_remove_proposer, get_proposer_ban_status, is_proposer_banned,
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
pub async fn get_governance_proposals() -> Result<Vec<GovernanceProposal>, EgoDesktopError> {
    tokio::task::spawn_blocking(|| Ok::<_, EgoDesktopError>(crate::chain_db::get_all_governance_proposals()))
        .await
        .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

#[tauri::command]
pub async fn is_feature_active(feature: String, action: String) -> Result<bool, EgoDesktopError> {
    tokio::task::spawn_blocking(move || {
        Ok::<_, EgoDesktopError>(match action.as_str() {
            "enable"  => crate::chain_db::is_feature_enabled(&feature),
            "disable" => crate::chain_db::is_feature_disabled(&feature),
            _         => false,
        })
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
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

const MAX_PROPOSALS_PER_WINDOW: usize = 5;
const WINDOW_SECS: i64 = 4 * 3600; // 4 hours

/// Minimum stake required to create a proposal — Sybil/spam resistance: a
/// proposer must have real skin in the game. 100 EGOC.
const MIN_PROPOSAL_STAKE_UEGOC: u64 = 100_000_000;

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
    if ledger.staked_amount < MIN_PROPOSAL_STAKE_UEGOC {
        return Err(EgoDesktopError::InvalidInput(format!(
            "You must stake at least {} EGOC to create a proposal (you currently have {} EGOC staked). Stake on the Stake page first.",
            MIN_PROPOSAL_STAKE_UEGOC / 1_000_000,
            ledger.staked_amount / 1_000_000
        )));
    }
    if title.trim().is_empty() {
        return Err(EgoDesktopError::InvalidInput("Title is required".into()));
    }
    if options.len() < 2 {
        return Err(EgoDesktopError::InvalidInput("At least 2 options required".into()));
    }

    // Enforce 4-hour sliding window rate limit (max 5 proposals per window)
    let now_ts_val = now_ts();
    let window_start = now_ts_val - WINDOW_SECS;
    let creator_clone = creator.clone();
    let (recent_times, banned) = tokio::task::spawn_blocking(move || {
        let all = list_dao_proposals(Some("all"), None);
        let times: Vec<i64> = all.iter()
            .filter(|p| p.creator == creator_clone && p.created_at >= window_start)
            .map(|p| p.created_at)
            .collect();
        let banned = is_proposer_banned(&creator_clone);
        (times, banned)
    }).await.map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?;

    if recent_times.len() >= MAX_PROPOSALS_PER_WINDOW {
        let oldest = recent_times.iter().copied().min().unwrap_or(now_ts_val);
        let resets_in = (oldest + WINDOW_SECS) - now_ts_val;
        let h = resets_in / 3600;
        let m = (resets_in % 3600) / 60;
        return Err(EgoDesktopError::InvalidInput(format!(
            "Rate limit: {} proposals per 4 hours. Next slot opens in {}h {}m.",
            MAX_PROPOSALS_PER_WINDOW, h, m
        )));
    }

    // Enforce proposer ban
    if banned {
        return Err(EgoDesktopError::InvalidInput(
            "Your address has been banned from submitting proposals by community vote.".into()
        ));
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

    tokio::task::spawn_blocking(move || store_dao_proposal(proposal))
        .await
        .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
        .map_err(EgoDesktopError::WalletError)?;
    Ok(id)
}

/// Delete a proposal you created. Only the original creator can remove it, and
/// it can be withdrawn at any time while it is still yours.
#[tauri::command]
pub async fn delete_dao_proposal(proposal_id: String) -> Result<(), EgoDesktopError> {
    let ledger = Ledger::load();
    let requester = ledger.address.clone();
    if requester.is_empty() {
        return Err(EgoDesktopError::WalletError("wallet not initialized".into()));
    }
    tokio::task::spawn_blocking(move || {
        crate::chain_db::delete_dao_proposal(&proposal_id, &requester)
            .map_err(EgoDesktopError::InvalidInput)
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

/// List proposals. status_filter: "all" | "active" | "passed" | "failed" | "expired"
#[tauri::command]
pub async fn get_dao_proposals(status_filter: Option<String>) -> Result<Vec<DaoProposalPublic>, EgoDesktopError> {
    tokio::task::spawn_blocking(move || {
        let ledger = Ledger::load();
        let voter = if ledger.address.is_empty() { None } else { Some(ledger.address) };
        Ok::<_, EgoDesktopError>(list_dao_proposals(status_filter.as_deref(), voter.as_deref()))
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

/// Get a single proposal with questions (no correct answers) and your vote status.
#[tauri::command]
pub async fn get_dao_proposal(proposal_id: String) -> Result<DaoProposalPublic, EgoDesktopError> {
    tokio::task::spawn_blocking(move || {
        let ledger = Ledger::load();
        let voter = if ledger.address.is_empty() { None } else { Some(ledger.address) };
        get_dao_proposal_public(&proposal_id, voter.as_deref())
            .ok_or(EgoDesktopError::WalletError("Proposal not found".into()))
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

/// Cast a stake-weighted vote. Power = your EGOC balance / total voting balance.
#[tauri::command]
pub async fn cast_stake_vote(
    proposal_id:  String,
    option_index: usize,
) -> Result<(), EgoDesktopError> {
    tokio::task::spawn_blocking(move || {
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
            .map_err(EgoDesktopError::InvalidInput)
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

/// Grade a knowledge test without casting a vote. Returns score 0.0–1.0.
#[tauri::command]
pub async fn grade_knowledge_test(
    proposal_id: String,
    answers:     Vec<usize>,
) -> Result<f64, EgoDesktopError> {
    tokio::task::spawn_blocking(move || {
        grade_dao_knowledge_test(&proposal_id, &answers)
            .map_err(EgoDesktopError::InvalidInput)
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

/// Submit knowledge test answers and cast a knowledge vote. Returns your score.
#[tauri::command]
pub async fn cast_knowledge_vote(
    proposal_id:  String,
    option_index: usize,
    answers:      Vec<usize>,
) -> Result<f64, EgoDesktopError> {
    tokio::task::spawn_blocking(move || {
        let ledger = Ledger::load();
        let voter = ledger.address.clone();
        if voter.is_empty() {
            return Err(EgoDesktopError::WalletError("wallet not initialized".into()));
        }
        cast_dao_knowledge_vote(&proposal_id, option_index, &voter, &answers)
            .map_err(EgoDesktopError::InvalidInput)
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

/// Get combined stake + knowledge results for a proposal.
#[tauri::command]
pub async fn get_proposal_results(proposal_id: String) -> Result<DaoProposalResults, EgoDesktopError> {
    tokio::task::spawn_blocking(move || {
        get_dao_results(&proposal_id)
            .ok_or(EgoDesktopError::WalletError("Proposal not found".into()))
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

/// Cast a removal vote against a proposer's address (max 1 per voter).
/// Once 10 unique voters flag an address, it is banned from creating proposals.
#[tauri::command]
pub fn vote_ban_proposer(target_address: String) -> Result<ProposerBanStatus, EgoDesktopError> {
    let ledger = Ledger::load();
    let voter = ledger.address.clone();
    if voter.is_empty() {
        return Err(EgoDesktopError::WalletError("Wallet not initialized".into()));
    }
    vote_remove_proposer(&target_address, &voter)
        .map_err(EgoDesktopError::InvalidInput)
}

/// Get the ban status for a proposer address (vote count, threshold, whether banned).
#[tauri::command]
pub async fn get_ban_status(target_address: String) -> Result<ProposerBanStatus, EgoDesktopError> {
    tokio::task::spawn_blocking(move || {
        let ledger = Ledger::load();
        let viewer = if ledger.address.is_empty() { None } else { Some(ledger.address) };
        Ok::<_, EgoDesktopError>(get_proposer_ban_status(&target_address, viewer.as_deref()))
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

#[derive(serde::Serialize)]
pub struct ProposalRateLimit {
    pub used:          usize,
    pub max:           usize,
    pub window_hours:  u32,
    pub resets_in_secs: i64, // seconds until oldest submission leaves the window; 0 if not at limit
}

/// Returns the current user's proposal rate-limit status for the 4-hour window.
#[tauri::command]
pub async fn get_proposal_rate_limit() -> Result<ProposalRateLimit, EgoDesktopError> {
    tokio::task::spawn_blocking(|| {
        let ledger = Ledger::load();
        if ledger.address.is_empty() {
            return Ok::<_, EgoDesktopError>(ProposalRateLimit {
                used: 0,
                max: MAX_PROPOSALS_PER_WINDOW,
                window_hours: 4,
                resets_in_secs: 0,
            });
        }

        let creator = ledger.address;
        let now = now_ts();
        let window_start = now - WINDOW_SECS;
        let all = list_dao_proposals(Some("all"), None);
        let recent_times: Vec<i64> = all.iter()
            .filter(|p| p.creator == creator && p.created_at >= window_start)
            .map(|p| p.created_at)
            .collect();
        let used = recent_times.len();
        let resets_in = if used >= MAX_PROPOSALS_PER_WINDOW {
            let oldest = recent_times.iter().copied().min().unwrap_or(now);
            ((oldest + WINDOW_SECS) - now).max(0)
        } else {
            0
        };

        Ok(ProposalRateLimit {
            used,
            max: MAX_PROPOSALS_PER_WINDOW,
            window_hours: 4,
            resets_in_secs: resets_in,
        })
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}
