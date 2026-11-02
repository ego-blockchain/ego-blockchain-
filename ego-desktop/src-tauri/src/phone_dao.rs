//! Staking and DAO state for phones, served by the gateway. Everything here is
//! read from the chain, so any gateway answers the same; the phone builds and
//! signs the transactions itself.

use serde_json::{json, Value};

use crate::drs::Ov;

type RpcResult = Result<Value, (i32, String)>;

pub const METHODS: &[&str] = &["staking.status", "dao.list", "dao.proposal", "dao.banStatus", "dao.limits", "holds.status"];

pub async fn dispatch(method: &str, params: &Value) -> Option<RpcResult> {
    let params = params.clone();
    let method = method.to_string();
    let run = move || match method.as_str() {
        "staking.status" => staking_status(&params),
        "dao.list" => dao_list(&params),
        "dao.proposal" => dao_proposal(&params),
        "dao.banStatus" => dao_ban_status(&params),
        "dao.limits" => dao_limits(&params),
        "holds.status" => holds_status(&params),
        _ => Err((-32601, crate::gateway::NOT_HERE.to_string())),
    };
    Some(tokio::task::spawn_blocking(run).await.unwrap_or_else(|e| Err((-32603, e.to_string()))))
}

fn with_chain<T>(f: impl FnOnce(&Ov) -> T) -> T {
    f(&Ov::new(crate::chain_db::global_db()))
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn address(params: &Value, key: &str) -> Result<String, (i32, String)> {
    let a = params[key].as_str().unwrap_or_default().trim().to_string();
    if crate::dao_chat::is_address(&a) {
        Ok(a)
    } else {
        Err((-32602, "That isn't an Ego address.".to_string()))
    }
}

fn optional_address(params: &Value, key: &str) -> Result<Option<String>, (i32, String)> {
    match params[key].as_str().map(str::trim) {
        None | Some("") => Ok(None),
        Some(_) => address(params, key).map(Some),
    }
}

fn dao_active() -> Result<(), (i32, String)> {
    if crate::dao_chain::rule_active_at_tip() {
        Ok(())
    } else {
        Err((-32602, "DAO voting isn't on the chain yet.".to_string()))
    }
}

fn to_value<T: serde::Serialize>(v: T) -> RpcResult {
    serde_json::to_value(v).map_err(|e| (-32603, e.to_string()))
}

/// What an address has staked, its lock, the reward it has earned so far, and
/// whether a vote keeps it from unstaking. The unstake rules are the chain's:
/// unstaking inside the lock costs 10%, and a stake or theft-hold vote blocks it
/// until the vote ends.
fn staking_status(params: &Value) -> RpcResult {
    let addr = address(params, "address")?;
    let now = now();
    let staked = crate::ledger::get_validator_stake(&addr);
    let (started_at, lock_days) = crate::chain_db::stake_meta(&addr).unwrap_or((0, 0));
    let unlock_at = if staked > 0 && started_at > 0 { started_at + lock_days as i64 * crate::dao_chain::DAY_SECS } else { 0 };
    let pool = crate::chain_db::balance_of(crate::chain_db::STAKING_POOL_ADDR);
    let accrued = if staked > 0 && started_at > 0 {
        crate::tokenomics::staking_reward_uegoc(staked, lock_days, (now - started_at).max(0) as u64).min(pool)
    } else {
        0
    };
    let (dao_lock, hold_lock) = with_chain(|ov| {
        (crate::dao_chain::locked_until(ov, &addr), crate::hold_chain::stake_locked_until(ov, &addr))
    });
    let vote_locked_until = dao_lock.max(hold_lock);
    let apr = |days: u32| crate::tokenomics::effective_apr_bps(days) as f64 / 100.0;
    let lock_options: Vec<Value> = [30u32, 90, 180, 365].iter().map(|d| json!({ "days": d, "apr": apr(*d) })).collect();
    Ok(json!({
        "address": addr,
        "staked": staked,
        "started_at": started_at,
        "lock_days": lock_days,
        "unlock_at": unlock_at,
        "locked": staked > 0 && unlock_at > now,
        "apr": apr(lock_days),
        "accrued": accrued,
        "early_fee": staked / 10,
        "vote_locked_until": vote_locked_until,
        "can_unstake": staked > 0 && vote_locked_until <= now,
        "network_stake": crate::ledger::total_network_stake(),
        "staking_address": crate::chain_db::STAKING_ADDR,
        "lock_options": lock_options,
        "max_lock_days": 1825,
    }))
}

/// Proposals newest first. filter: "all" | "active" | "passed" | "failed" | "expired".
fn dao_list(params: &Value) -> RpcResult {
    dao_active()?;
    let filter = params["filter"].as_str().map(str::to_string);
    let voter = optional_address(params, "voter")?;
    to_value(with_chain(|ov| crate::dao_chain::list(ov, filter.as_deref(), voter.as_deref(), now())))
}

/// One proposal with the asker's own votes, and its results.
fn dao_proposal(params: &Value) -> RpcResult {
    dao_active()?;
    let id = params["id"].as_str().unwrap_or_default().to_string();
    let voter = optional_address(params, "voter")?;
    let network_stake = crate::ledger::total_network_stake();
    let now = now();
    let found = with_chain(|ov| {
        crate::dao_chain::load_proposal(ov, &id).map(|p| {
            (crate::dao_chain::to_public(ov, &p, voter.as_deref(), now), crate::dao_chain::results(ov, &p, now, network_stake))
        })
    });
    let (proposal, results) = found.ok_or((-32602, "No proposal with that id on the chain.".to_string()))?;
    Ok(json!({ "proposal": to_value(proposal)?, "results": to_value(results)? }))
}

fn dao_ban_status(params: &Value) -> RpcResult {
    dao_active()?;
    let target = address(params, "target")?;
    let viewer = optional_address(params, "viewer")?;
    let staked = crate::chain_db::balance_of(crate::chain_db::STAKING_ADDR);
    to_value(with_chain(|ov| crate::dao_chain::ban_status(ov, &target, viewer.as_deref(), now(), staked)))
}

/// How many proposals an address may still create, and what a proposal may hold.
fn dao_limits(params: &Value) -> RpcResult {
    use crate::dao_chain as d;
    let addr = address(params, "address")?;
    let now = now();
    let active = d::rule_active_at_tip();
    let used = if active { with_chain(|ov| d::created_in_window(ov, &addr, now)) } else { Vec::new() };
    let resets_at = if used.len() >= d::PROPOSALS_PER_WINDOW {
        used.iter().copied().min().unwrap_or(now) + d::WINDOW_SECS
    } else {
        0
    };
    let staked = crate::chain_db::balance_of(crate::chain_db::STAKING_ADDR);
    let banned = active && with_chain(|ov| d::ban_status(ov, &addr, None, now, staked)).banned;
    Ok(json!({
        "active": active,
        "activation_height": d::ACTIVATION_HEIGHT,
        "used": used.len(),
        "max": d::PROPOSALS_PER_WINDOW,
        "window_days": d::WINDOW_SECS / d::DAY_SECS,
        "resets_at": resets_at,
        "banned": banned,
        "kinds": d::KINDS,
        "min_days": d::MIN_DAYS,
        "max_days": d::MAX_DAYS,
        "default_days": d::DEFAULT_DAYS,
        "max_title_bytes": d::MAX_TITLE_BYTES,
        "max_description_bytes": d::MAX_DESCRIPTION_BYTES,
        "max_options": d::MAX_OPTIONS,
        "max_option_bytes": d::MAX_OPTION_BYTES,
        "max_questions": d::MAX_QUESTIONS,
        "max_question_bytes": d::MAX_QUESTION_BYTES,
        "max_question_options": d::MAX_QUESTION_OPTIONS,
        "reveal_window_secs": d::REVEAL_WINDOW_SECS,
    }))
}

/// Theft holds as an address sees them: each hold, its tallies and this address's
/// votes. Holds stay off until the network switches them on; `active` says so.
fn holds_status(params: &Value) -> RpcResult {
    let addr = address(params, "address")?;
    to_value(crate::commands::holds::status_for(addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDR: &str = "egot1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";

    #[test]
    fn requests_name_a_real_address() {
        assert_eq!(staking_status(&json!({ "address": "nobody" })).unwrap_err().0, -32602);
        assert_eq!(dao_limits(&json!({})).unwrap_err().0, -32602);
        assert_eq!(dao_list(&json!({ "voter": "nobody" })).unwrap_err().0, -32602);
    }

    #[test]
    fn an_address_with_nothing_staked_can_still_see_its_options() {
        let s = staking_status(&json!({ "address": ADDR })).unwrap();
        assert_eq!(s["staked"], 0);
        assert_eq!(s["can_unstake"], false);
        assert_eq!(s["lock_options"].as_array().unwrap().len(), 4);
        assert!(s["lock_options"][3]["apr"].as_f64().unwrap() > s["lock_options"][0]["apr"].as_f64().unwrap());
    }

    /// The same values EgoKit's DaoTests compute on the iPhone, so the phone's DAO
    /// transactions commit to exactly what the node checks.
    #[test]
    fn the_phone_builds_the_same_dao_commitments() {
        use crate::dao_chain as d;
        let vote = r#"{"id":"dao0123456789abcdef","option":2}"#;
        assert!(serde_json::from_str::<d::VoteBody>(vote).is_ok());
        assert_eq!(d::memo_for(d::TX_VOTE, vote).unwrap(), "dao:vote:92ef34a3cb53bf14d7f3f90430b3077795aa48b7b50ce49bcb9e4abd1001a640");
        assert_eq!(d::proposal_id("0xabc123"), "daoa402c11f3ed2d394");
        assert_eq!(d::answers_commit(&"a".repeat(64), &[1, 0, 3]), "0c9a6f058fe1d5569b31ad647926b791a725a6c4138ce45c1e1a400969be5fdb");
        assert_eq!(
            d::vote_commit("dao0123456789abcdef", "egot1alice", &"b".repeat(64), &[2, 1]),
            "2812021084b55f67fe43e144e0ed51f01b3443498bd3859c639a2183f10a90a5"
        );
        let reveal = format!(r#"{{"answers":[0,1,2],"id":"dao0123456789abcdef","salt":"{}"}}"#, "c".repeat(64));
        let parsed: d::RevealBody = serde_json::from_str(&reveal).unwrap();
        assert_eq!(parsed.answers, vec![0, 1, 2]);
        let hold_vote = r#"{"id":"hold0123456789abcdef","phase":"confirm","yes":true}"#;
        assert!(serde_json::from_str::<crate::hold_chain::VoteBody>(hold_vote).is_ok());
        assert_eq!(
            crate::hold_chain::memo_for(crate::hold_chain::TX_VOTE, hold_vote).unwrap(),
            "hold:vote:b1345742d18521913f54d3a1bc0302c71d10471f8bbcaa67b30a03b4abfca2e0"
        );
    }

    #[test]
    fn holds_answer_even_while_switched_off() {
        let h = holds_status(&json!({ "address": ADDR })).unwrap();
        assert_eq!(h["me"], ADDR);
        assert!(h["holds"].is_array());
        assert_eq!(h["min_bond"], crate::hold_chain::MIN_BOND_UEGOC);
    }

    #[test]
    fn limits_carry_the_proposal_rules() {
        let l = dao_limits(&json!({ "address": ADDR })).unwrap();
        assert_eq!(l["max"], crate::dao_chain::PROPOSALS_PER_WINDOW);
        assert_eq!(l["kinds"].as_array().unwrap().len(), crate::dao_chain::KINDS.len());
        assert_eq!(l["max_question_options"], crate::dao_chain::MAX_QUESTION_OPTIONS);
    }
}
