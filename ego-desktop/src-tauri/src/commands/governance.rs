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
    let nonce      = crate::ledger::next_nonce_for(&ledger.address, ledger.nonce);
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

// Anyone can create a proposal (no stake required) — but at most 5 per month,
// and that count is based on CREATIONS, not currently-live proposals, so
// deleting one does not give the slot back.
const MAX_PROPOSALS_PER_WINDOW: usize = 5;
const WINDOW_SECS: i64 = 30 * 86_400; // 30 days (~1 month)

/// Create a new community DAO proposal. Any wallet holder can submit.
#[tauri::command]
pub async fn create_dao_proposal(
    title:         String,
    description:   String,
    proposal_type: String,
    options:       Vec<String>,
    duration_days: Option<u32>,
    questions:     Option<Vec<NewTestQuestion>>,
    target:        Option<String>,
    state:         State<'_, AppState>,
) -> Result<String, EgoDesktopError> {
    if crate::dao_chain::rule_active_at_tip() {
        return chain_propose(&state, title, description, proposal_type, options, duration_days, questions.unwrap_or_default(), target.unwrap_or_default()).await;
    }
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

    // Enforce the monthly creation cap. The count comes from a persistent
    // creation log (not live proposals), so deleting a proposal does NOT free a
    // slot — preventing create→delete→repeat spam.
    let now_ts_val = now_ts();
    let window_start = now_ts_val - WINDOW_SECS;
    let creator_clone = creator.clone();
    let (recent_times, banned) = tokio::task::spawn_blocking(move || {
        let times = crate::chain_db::get_proposal_creation_times(&creator_clone, window_start);
        let banned = is_proposer_banned(&creator_clone);
        (times, banned)
    }).await.map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?;

    if recent_times.len() >= MAX_PROPOSALS_PER_WINDOW {
        let oldest = recent_times.iter().copied().min().unwrap_or(now_ts_val);
        let resets_in = (oldest + WINDOW_SECS) - now_ts_val;
        let d = resets_in / 86_400;
        let h = (resets_in % 86_400) / 3600;
        return Err(EgoDesktopError::InvalidInput(format!(
            "Rate limit: {} proposals per month (deleting one does not free a slot). Next slot opens in {}d {}h.",
            MAX_PROPOSALS_PER_WINDOW, d, h
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

    let creator_for_log = creator.clone();
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

    // Record the creation in the persistent per-creator log AFTER a successful
    // store, so it counts against the monthly cap even if the proposal is later
    // deleted.
    let _ = tokio::task::spawn_blocking(move || {
        crate::chain_db::record_proposal_creation(&creator_for_log, now, now - WINDOW_SECS)
    }).await;
    Ok(id)
}

/// Delete a proposal you created. Only the original creator can remove it, and
/// it can be withdrawn at any time while it is still yours.
#[tauri::command]
pub async fn delete_dao_proposal(proposal_id: String, state: State<'_, AppState>) -> Result<(), EgoDesktopError> {
    if crate::dao_chain::rule_active_at_tip() {
        return chain_withdraw(&state, proposal_id).await;
    }
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
pub async fn get_dao_proposals(status_filter: Option<String>, state: State<'_, AppState>) -> Result<Vec<DaoProposalPublic>, EgoDesktopError> {
    if crate::dao_chain::rule_active_at_tip() {
        send_due_reveals(&state).await;
        return tokio::task::spawn_blocking(move || {
            let me = Ledger::load().address;
            let me = (!me.is_empty()).then_some(me);
            with_chain(|ov| crate::dao_chain::list(ov, status_filter.as_deref(), me.as_deref(), now_ts()))
        })
        .await
        .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()));
    }
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
        if crate::dao_chain::rule_active_at_tip() {
            let me = Ledger::load().address;
            let me = (!me.is_empty()).then_some(me);
            return with_chain(|ov| {
                crate::dao_chain::load_proposal(ov, &proposal_id)
                    .map(|p| crate::dao_chain::to_public(ov, &p, me.as_deref(), now_ts()))
            })
            .ok_or(EgoDesktopError::WalletError("Proposal not found".into()));
        }
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
    state:        State<'_, AppState>,
) -> Result<(), EgoDesktopError> {
    if crate::dao_chain::rule_active_at_tip() {
        return chain_stake_vote(&state, proposal_id, option_index).await;
    }
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
    if crate::dao_chain::rule_active_at_tip() {
        return Err(EgoDesktopError::InvalidInput(
            "The answers stay hidden until voting ends, so there is no score preview. Your score appears once the creator reveals the answers.".into(),
        ));
    }
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
    state:        State<'_, AppState>,
) -> Result<f64, EgoDesktopError> {
    if crate::dao_chain::rule_active_at_tip() {
        return chain_knowledge_vote(&state, proposal_id, option_index, answers).await;
    }
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
        if crate::dao_chain::rule_active_at_tip() {
            let network_stake = crate::ledger::total_network_stake();
            return with_chain(|ov| {
                crate::dao_chain::load_proposal(ov, &proposal_id)
                    .map(|p| crate::dao_chain::results(ov, &p, now_ts(), network_stake))
            })
            .ok_or(EgoDesktopError::WalletError("Proposal not found".into()));
        }
        get_dao_results(&proposal_id)
            .ok_or(EgoDesktopError::WalletError("Proposal not found".into()))
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

/// Cast a removal vote against a proposer's address (max 1 per voter).
/// Once 10 unique voters flag an address, it is banned from creating proposals.
#[tauri::command]
pub async fn vote_ban_proposer(target_address: String, state: State<'_, AppState>) -> Result<ProposerBanStatus, EgoDesktopError> {
    if crate::dao_chain::rule_active_at_tip() {
        return chain_report(&state, target_address).await;
    }
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
        if crate::dao_chain::rule_active_at_tip() {
            return Ok(chain_ban_status(&target_address, viewer.as_deref()));
        }
        Ok::<_, EgoDesktopError>(get_proposer_ban_status(&target_address, viewer.as_deref()))
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

#[derive(serde::Serialize)]
pub struct ProposalRateLimit {
    pub used:          usize,
    pub max:           usize,
    pub window_days:   u32,
    pub resets_in_secs: i64, // seconds until oldest submission leaves the window; 0 if not at limit
}

/// Returns the current user's proposal rate-limit status for the monthly window.
#[tauri::command]
pub async fn get_proposal_rate_limit() -> Result<ProposalRateLimit, EgoDesktopError> {
    tokio::task::spawn_blocking(|| {
        let ledger = Ledger::load();
        if ledger.address.is_empty() {
            return Ok::<_, EgoDesktopError>(ProposalRateLimit {
                used: 0,
                max: MAX_PROPOSALS_PER_WINDOW,
                window_days: (WINDOW_SECS / 86_400) as u32,
                resets_in_secs: 0,
            });
        }

        let creator = ledger.address;
        let now = now_ts();
        let window_start = now - WINDOW_SECS;
        let recent_times = if crate::dao_chain::rule_active_at_tip() {
            with_chain(|ov| crate::dao_chain::created_in_window(ov, &creator, now))
        } else {
            crate::chain_db::get_proposal_creation_times(&creator, window_start)
        };
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
            window_days: (WINDOW_SECS / 86_400) as u32,
            resets_in_secs: resets_in,
        })
    })
    .await
    .map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?
}

const REVEAL_PREFIX: &[u8] = b"dreveal/";
const VOTE_REVEAL_PREFIX: &[u8] = b"dkreveal/";
const REVEAL_RETRY_SECS: i64 = 600;

#[derive(serde::Serialize, serde::Deserialize)]
struct RevealSecret {
    salt:    String,
    answers: Vec<u8>,
}

fn reveal_key(id: &str) -> Vec<u8> {
    [REVEAL_PREFIX, id.as_bytes()].concat()
}

fn reveal_sent() -> &'static std::sync::Mutex<std::collections::HashMap<String, i64>> {
    static SENT: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, i64>>> = std::sync::OnceLock::new();
    SENT.get_or_init(Default::default)
}

fn with_chain<T>(f: impl FnOnce(&crate::drs::Ov) -> T) -> T {
    f(&crate::drs::Ov::new(crate::chain_db::global_db()))
}

fn open_chain_proposal(id: &str) -> Result<crate::dao_chain::Proposal, EgoDesktopError> {
    let p = with_chain(|ov| crate::dao_chain::load_proposal(ov, id))
        .ok_or(EgoDesktopError::InvalidInput("Proposal not found on the chain yet".into()))?;
    if crate::dao_chain::status(&p, now_ts()) != "active" {
        return Err(EgoDesktopError::InvalidInput("Voting on this proposal has ended".into()));
    }
    Ok(p)
}

fn build_dao_tx(
    state:   &AppState,
    ledger:  &mut Ledger,
    tx_type: &str,
    body:    &impl serde::Serialize,
) -> Result<LedgerTx, EgoDesktopError> {
    if ledger.address.is_empty() {
        return Err(EgoDesktopError::WalletError("wallet not initialized".into()));
    }
    let call_args = serde_json::to_string(body).map_err(|e| EgoDesktopError::InvalidInput(e.to_string()))?;
    let memo = crate::dao_chain::memo_for(tx_type, &call_args)
        .ok_or(EgoDesktopError::InvalidInput(format!("{tx_type} is not a DAO transaction")))?;
    let fee = crate::tokenomics::fee_for_tx_with_staking("transfer", ledger.staked_amount > 0);
    if crate::chain_db::balance_of(&ledger.address) < fee {
        return Err(EgoDesktopError::InvalidInput(format!(
            "You need {:.6} EGOC for the network fee", fee as f64 / 1_000_000.0
        )));
    }
    let kp = state.get_keypair().ok_or(EgoDesktopError::WalletError("wallet not initialized".into()))?;
    let mut tx = LedgerTx {
        from:      ledger.address.clone(),
        to:        ledger.address.clone(),
        amount:    0,
        memo:      Some(memo),
        timestamp: chrono::Utc::now().timestamp(),
        status:    "Pending".into(),
        nonce:     crate::ledger::next_nonce_for(&ledger.address, ledger.nonce),
        fee_uegoc: fee,
        chain_id:  1,
        tx_type:   tx_type.to_string(),
        call_args,
        ..LedgerTx::default()
    };
    crate::ledger::seal_tx(&mut tx, &kp, true);
    crate::ledger::verify_incoming_tx(&tx).map_err(EgoDesktopError::InvalidInput)?;
    ledger.nonce = tx.nonce;
    Ok(tx)
}

async fn send_dao_tx(state: &AppState, tx_type: &str, body: &impl serde::Serialize) -> Result<LedgerTx, EgoDesktopError> {
    let _guard = crate::ledger::TX_MUTEX.lock().await;
    let mut ledger = Ledger::load();
    let tx = build_dao_tx(state, &mut ledger, tx_type, body)?;
    crate::commands::credits::queue_tx(tx.clone(), ledger).await;
    Ok(tx)
}

async fn chain_propose(
    state:         &AppState,
    title:         String,
    description:   String,
    proposal_type: String,
    options:       Vec<String>,
    duration_days: Option<u32>,
    questions:     Vec<NewTestQuestion>,
    target:        String,
) -> Result<String, EgoDesktopError> {
    for (i, q) in questions.iter().enumerate() {
        if q.correct_index >= q.options.len() {
            return Err(EgoDesktopError::InvalidInput(format!("Question {} correct_index out of range", i + 1)));
        }
    }
    let answers: Vec<u8> = questions.iter().map(|q| q.correct_index as u8).collect();
    let salt = hex::encode(rand::random::<[u8; 32]>());
    let body = crate::dao_chain::ProposeBody {
        title: title.trim().to_string(),
        description,
        kind: proposal_type,
        options: options.into_iter().map(|o| o.trim().to_string()).collect(),
        duration_days: duration_days.unwrap_or(crate::dao_chain::DEFAULT_DAYS),
        questions: questions
            .iter()
            .map(|q| crate::dao_chain::Question { question: q.question.clone(), options: q.options.clone() })
            .collect(),
        answers_commit: if questions.is_empty() { String::new() } else { crate::dao_chain::answers_commit(&salt, &answers) },
        target: target.trim().to_string(),
    };
    crate::dao_chain::check_propose(&body).map_err(EgoDesktopError::InvalidInput)?;

    let _guard = crate::ledger::TX_MUTEX.lock().await;
    let mut ledger = Ledger::load();
    if chain_ban_status(&ledger.address, None).banned {
        return Err(EgoDesktopError::InvalidInput(
            "Your address has been reported by staked holders and cannot create proposals for now.".into(),
        ));
    }
    let used = with_chain(|ov| crate::dao_chain::created_in_window(ov, &ledger.address, now_ts())).len();
    if used >= crate::dao_chain::PROPOSALS_PER_WINDOW {
        return Err(EgoDesktopError::InvalidInput(format!(
            "Rate limit: {} proposals per 30 days", crate::dao_chain::PROPOSALS_PER_WINDOW
        )));
    }
    let tx = build_dao_tx(state, &mut ledger, crate::dao_chain::TX_PROPOSE, &body)?;
    let id = crate::dao_chain::proposal_id(&tx.hash);
    if !questions.is_empty() {
        let secret = serde_json::to_vec(&RevealSecret { salt, answers }).map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?;
        crate::chain_db::dao_put(&reveal_key(&id), &secret).map_err(EgoDesktopError::DatabaseError)?;
    }
    crate::commands::credits::queue_tx(tx, ledger).await;
    Ok(id)
}

async fn chain_stake_vote(state: &AppState, proposal_id: String, option_index: usize) -> Result<(), EgoDesktopError> {
    let p = open_chain_proposal(&proposal_id)?;
    if option_index >= p.options.len() {
        return Err(EgoDesktopError::InvalidInput("Invalid option index".into()));
    }
    let me = Ledger::load().address;
    if with_chain(|ov| crate::dao_chain::stake_of(ov, &me)) == 0 {
        return Err(EgoDesktopError::InvalidInput(
            "Only staked EGOC can vote. Stake EGOC on the Staking page first; it stays locked until this vote ends.".into(),
        ));
    }
    let body = crate::dao_chain::VoteBody { id: proposal_id, option: option_index as u32 };
    send_dao_tx(state, crate::dao_chain::TX_VOTE, &body).await.map(|_| ())
}

async fn chain_knowledge_vote(
    state:        &AppState,
    proposal_id:  String,
    option_index: usize,
    answers:      Vec<usize>,
) -> Result<f64, EgoDesktopError> {
    let p = open_chain_proposal(&proposal_id)?;
    if p.questions.is_empty() {
        return Err(EgoDesktopError::InvalidInput("No knowledge test on this proposal".into()));
    }
    if option_index >= p.options.len() {
        return Err(EgoDesktopError::InvalidInput("Invalid option index".into()));
    }
    if answers.len() != p.questions.len() || p.questions.iter().zip(&answers).any(|(q, a)| *a >= q.options.len()) {
        return Err(EgoDesktopError::InvalidInput(format!("Answer all {} questions", p.questions.len())));
    }
    let answers: Vec<u8> = answers.into_iter().map(|a| a as u8).collect();
    let salt = hex::encode(rand::random::<[u8; 32]>());
    let _guard = crate::ledger::TX_MUTEX.lock().await;
    let mut ledger = Ledger::load();
    let me = ledger.address.clone();
    let body = crate::dao_chain::KnowBody {
        id: proposal_id.clone(),
        option: option_index as u32,
        commit: crate::dao_chain::vote_commit(&proposal_id, &me, &salt, &answers),
    };
    let tx = build_dao_tx(state, &mut ledger, crate::dao_chain::TX_KNOW, &body)?;
    let secret = serde_json::to_vec(&RevealSecret { salt, answers }).map_err(|e| EgoDesktopError::DatabaseError(e.to_string()))?;
    crate::chain_db::dao_put(&vote_reveal_key(&proposal_id, &me), &secret).map_err(EgoDesktopError::DatabaseError)?;
    crate::commands::credits::queue_tx(tx, ledger).await;
    Ok(-1.0)
}

fn vote_reveal_key(id: &str, voter: &str) -> Vec<u8> {
    [VOTE_REVEAL_PREFIX, id.as_bytes(), b"/", voter.as_bytes()].concat()
}

async fn send_due_vote_reveals(state: &AppState, now: i64, me: &str) {
    for (k, v) in crate::chain_db::dao_scan(VOTE_REVEAL_PREFIX, VOTE_REVEAL_PREFIX, false, 256) {
        let rest = String::from_utf8_lossy(&k[VOTE_REVEAL_PREFIX.len()..]).to_string();
        let Some((id, voter)) = rest.split_once('/') else { continue };
        if voter != me {
            continue;
        }
        let Ok(secret) = serde_json::from_slice::<RevealSecret>(&v) else { continue };
        let (p, vote) = with_chain(|ov| (crate::dao_chain::load_proposal(ov, id), crate::dao_chain::know_vote(ov, id, me)));
        let Some(p) = p else { continue };
        let done = vote.as_ref().map_or(false, |v| v.answers.is_some());
        let tallied = crate::dao_chain::tally_active(p.height);
        let closes = match (tallied, p.revealed_at) {
            (true, Some(at)) => at,
            _ => p.ends_at,
        } + crate::dao_chain::REVEAL_WINDOW_SECS;
        let creator_gave_up = tallied && p.answers.is_none() && now >= p.ends_at + crate::dao_chain::REVEAL_WINDOW_SECS;
        if done || now >= closes || creator_gave_up {
            crate::chain_db::dao_delete(&[k]);
            continue;
        }
        if vote.is_none() || now < p.ends_at || (tallied && p.answers.is_none()) || !reveal_due(&format!("vote/{id}"), now) {
            continue;
        }
        let body = crate::dao_chain::RevealBody { id: id.to_string(), salt: secret.salt, answers: secret.answers };
        if let Err(e) = send_dao_tx(state, crate::dao_chain::TX_KNOW_REVEAL, &body).await {
            eprintln!("[DAO] could not reveal your answers for {id}: {e}");
        }
    }
}

fn reveal_due(key: &str, now: i64) -> bool {
    let mut sent = reveal_sent().lock().unwrap_or_else(|e| e.into_inner());
    if now - sent.get(key).copied().unwrap_or(0) < REVEAL_RETRY_SECS {
        return false;
    }
    sent.insert(key.to_string(), now);
    true
}

async fn chain_report(state: &AppState, target: String) -> Result<ProposerBanStatus, EgoDesktopError> {
    let me = Ledger::load().address;
    if target == me {
        return Err(EgoDesktopError::InvalidInput("You cannot report yourself".into()));
    }
    if with_chain(|ov| crate::dao_chain::stake_of(ov, &me)) == 0 {
        return Err(EgoDesktopError::InvalidInput(
            "Only staked EGOC can report a proposer; the stake stays locked for 30 days.".into(),
        ));
    }
    send_dao_tx(state, crate::dao_chain::TX_REPORT, &crate::dao_chain::ReportBody { target: target.clone() }).await?;
    Ok(chain_ban_status(&target, Some(&me)))
}

fn chain_ban_status(target: &str, viewer: Option<&str>) -> ProposerBanStatus {
    let staked = crate::chain_db::balance_of(crate::chain_db::STAKING_ADDR);
    with_chain(|ov| crate::dao_chain::ban_status(ov, target, viewer, now_ts(), staked))
}

async fn chain_withdraw(state: &AppState, proposal_id: String) -> Result<(), EgoDesktopError> {
    let p = open_chain_proposal(&proposal_id)?;
    if p.creator != Ledger::load().address {
        return Err(EgoDesktopError::InvalidInput("Only the proposal's creator can withdraw it".into()));
    }
    let body = crate::dao_chain::WithdrawBody { id: proposal_id };
    send_dao_tx(state, crate::dao_chain::TX_WITHDRAW, &body).await.map(|_| ())
}

async fn send_due_reveals(state: &AppState) {
    let now = now_ts();
    let me = Ledger::load().address;
    for (k, v) in crate::chain_db::dao_scan(REVEAL_PREFIX, REVEAL_PREFIX, false, 64) {
        let id = String::from_utf8_lossy(&k[REVEAL_PREFIX.len()..]).to_string();
        let Ok(secret) = serde_json::from_slice::<RevealSecret>(&v) else { continue };
        let Some(p) = with_chain(|ov| crate::dao_chain::load_proposal(ov, &id)) else { continue };
        if p.creator != me {
            continue;
        }
        if p.answers.is_some() || now >= p.ends_at + crate::dao_chain::REVEAL_WINDOW_SECS {
            crate::chain_db::dao_delete(&[k]);
            continue;
        }
        if now < p.ends_at || !reveal_due(&format!("own/{id}"), now) {
            continue;
        }
        let body = crate::dao_chain::RevealBody { id: id.clone(), salt: secret.salt, answers: secret.answers };
        if let Err(e) = send_dao_tx(state, crate::dao_chain::TX_REVEAL, &body).await {
            eprintln!("[DAO] could not reveal the answers of {id}: {e}");
        }
    }
    send_due_vote_reveals(state, now, &me).await;
}

pub async fn dao_reveal_tick() {
    if !crate::dao_chain::rule_active_at_tip() {
        return;
    }
    let Some(app) = crate::p2p::APP_HANDLE.get() else { return };
    use tauri::Manager;
    let state = app.state::<AppState>();
    send_due_reveals(&state).await;
}
