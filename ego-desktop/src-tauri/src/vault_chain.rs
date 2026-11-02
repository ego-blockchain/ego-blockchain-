use crate::dao_chain::Fit;
use crate::drs::Ov;
use crate::ledger::{LedgerBlock, LedgerTx};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const ACTIVATION_HEIGHT: Option<u64> = Some(67922);

pub const TX_SET: &str = "vault_set";
pub const TX_OFF: &str = "vault_off";
pub const TX_FREEZE: &str = "vault_freeze";
pub const TX_UNFREEZE: &str = "vault_unfreeze";
pub const TX_CANCEL: &str = "vault_cancel";
pub const TX_QUEUE: &str = "vault_queue";
pub const VAULT_TYPES: [&str; 6] = [TX_SET, TX_OFF, TX_FREEZE, TX_UNFREEZE, TX_CANCEL, TX_QUEUE];

pub const SWEEP_MEMO: &str = "vault:sweep";
pub const EXEC_PREFIX: &str = "vault:exec:";
pub const CANCEL_CHANGE: &str = "change";

pub const DAY_SECS: i64 = 86_400;
pub const MIN_DELAY_SECS: i64 = 3_600;
pub const MAX_DELAY_SECS: i64 = 30 * DAY_SECS;
pub const MAX_GUARDIANS: usize = 5;
pub const MAX_QUEUED: u64 = 32;
pub const FEE_ALLOWANCE_UEGOC: u64 = 100_000;
pub const MAX_BODY_BYTES: usize = 4_096;
pub const LIST_LIMIT: usize = 256;

const BODY_DOMAIN: &[u8] = b"ego/vault/body/v1:";
const COSIGN_DOMAIN: &[u8] = b"ego/vault/cosign/v1:";
const QUEUE_DOMAIN: &[u8] = b"ego/vault/queue/v1:";
const PASSWORD_DOMAIN: &str = "ego/vault/password-key/v1:";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    pub limit: u64,
    pub delay: i64,
    #[serde(default)]
    pub high_limit: u64,
    #[serde(default)]
    pub high_delay: i64,
    #[serde(default)]
    pub recovery: String,
    #[serde(default)]
    pub second_key: String,
    #[serde(default)]
    pub guardians: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Change {
    Set { settings: Settings },
    Off,
    Unfreeze,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    pub change: Change,
    pub at: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vault {
    pub settings: Settings,
    #[serde(default)]
    pub frozen: bool,
    #[serde(default)]
    pub pending: Option<Pending>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Queued {
    pub id: String,
    pub to: String,
    pub amount: u64,
    pub at: i64,
    pub created: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Spent {
    pub day: i64,
    pub amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetBody {
    pub settings: Settings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnerBody {
    pub owner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelBody {
    pub owner: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueBody {
    pub to: String,
    pub amount: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmptyBody {}

pub fn rule_active(height: u64) -> bool {
    ACTIVATION_HEIGHT.is_some_and(|h| height >= h)
}

pub fn rule_active_at_tip() -> bool {
    rule_active(crate::chain_db::local_chain_height().saturating_add(1))
}

pub fn is_vault_op(tx: &LedgerTx) -> bool {
    VAULT_TYPES.contains(&tx.tx_type.as_str())
}

pub fn body_hash(call_args: &str) -> String {
    let mut m = BODY_DOMAIN.to_vec();
    m.extend_from_slice(call_args.as_bytes());
    blake3::hash(&m).to_hex().to_string()
}

pub fn memo_for(tx_type: &str, call_args: &str) -> Option<String> {
    if !VAULT_TYPES.contains(&tx_type) {
        return None;
    }
    let op = tx_type.strip_prefix("vault_")?;
    Some(format!("vault:{op}:{}", body_hash(call_args)))
}

pub fn queue_id(tx_hash: &str) -> String {
    let mut m = QUEUE_DOMAIN.to_vec();
    m.extend_from_slice(tx_hash.as_bytes());
    blake3::hash(&m).to_hex()[..16].to_string()
}

pub fn exec_memo(id: &str) -> String {
    format!("{EXEC_PREFIX}{id}")
}

fn exec_id(tx: &LedgerTx) -> Option<&str> {
    tx.memo.as_deref()?.strip_prefix(EXEC_PREFIX)
}

pub fn cosign_message(tx: &LedgerTx) -> Vec<u8> {
    let mut m = COSIGN_DOMAIN.to_vec();
    m.extend_from_slice(&crate::ledger::tx_signing_bytes_for(tx));
    m
}

pub fn address_of(pk: &[u8; 32], chain_id: u8) -> String {
    let hrp = if chain_id == 1 { "egot" } else { "ego" };
    ego_core::EgoAddress::from_public_key_bytes(pk, chain_id as u32, ego_core::AddressType::EOA)
        .to_bech32(hrp)
        .unwrap_or_default()
}

pub fn cosign_with(tx: &LedgerTx, key: &ed25519_dalek::SigningKey) -> String {
    use ed25519_dalek::Signer;
    let sig = key.sign(&cosign_message(tx));
    format!("{}:{}", hex::encode(key.verifying_key().as_bytes()), hex::encode(sig.to_bytes()))
}

pub fn cosign_signer(tx: &LedgerTx) -> Option<String> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let (pk, sig) = tx.vault_cosig.split_once(':')?;
    let pk: [u8; 32] = hex::decode(pk).ok()?.try_into().ok()?;
    let sig: [u8; 64] = hex::decode(sig).ok()?.try_into().ok()?;
    let vk = VerifyingKey::from_bytes(&pk).ok()?;
    vk.verify(&cosign_message(tx), &Signature::from_bytes(&sig)).ok()?;
    Some(address_of(&pk, tx.chain_id))
}

pub fn password_key(owner: &str, password: &str) -> Result<ed25519_dalek::SigningKey, String> {
    if password.chars().count() < 10 {
        return Err("use a password of at least 10 characters".into());
    }
    let params = argon2::Params::new(65_536, 3, 1, Some(32)).map_err(|e| e.to_string())?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let salt = format!("{PASSWORD_DOMAIN}{owner}");
    let mut seed = [0u8; 32];
    argon
        .hash_password_into(password.as_bytes(), salt.as_bytes(), &mut seed)
        .map_err(|e| e.to_string())?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

fn valid_addr(s: &str) -> bool {
    (s.starts_with("egot1") || s.starts_with("ego1"))
        && (20..=100).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

pub fn check_settings(owner: &str, s: &Settings) -> Result<(), String> {
    if !(MIN_DELAY_SECS..=MAX_DELAY_SECS).contains(&s.delay) {
        return Err("the delay is between 1 hour and 30 days".into());
    }
    if s.high_limit == 0 {
        if s.high_delay != 0 {
            return Err("a longer delay needs a higher limit".into());
        }
    } else if s.high_limit <= s.limit || s.high_delay <= s.delay || s.high_delay > MAX_DELAY_SECS {
        return Err("the higher limit and its delay must both be above the first ones, at most 30 days".into());
    }
    for (name, a) in [("recovery address", &s.recovery), ("second key", &s.second_key)] {
        if !a.is_empty() && (!valid_addr(a) || a == owner) {
            return Err(format!("the {name} must be another valid address"));
        }
    }
    if s.guardians.len() > MAX_GUARDIANS {
        return Err(format!("at most {MAX_GUARDIANS} guardians"));
    }
    let mut seen = BTreeSet::new();
    for g in &s.guardians {
        if !valid_addr(g) || g == owner || !seen.insert(g.as_str()) {
            return Err("each guardian must be a different valid address".into());
        }
    }
    Ok(())
}

pub fn longest_delay(s: &Settings) -> i64 {
    s.delay.max(s.high_delay)
}

pub fn delay_for(s: &Settings, amount: u64) -> i64 {
    if s.high_limit > 0 && amount > s.high_limit {
        s.high_delay
    } else {
        s.delay
    }
}

pub fn tighter(new: &Settings, old: &Settings) -> bool {
    let high_ok = if old.high_limit == 0 {
        new.high_limit == 0 || new.high_delay >= old.delay
    } else {
        new.high_limit > 0 && new.high_limit <= old.high_limit && new.high_delay >= old.high_delay
    };
    new.limit <= old.limit
        && new.delay >= old.delay
        && high_ok
        && new.recovery == old.recovery
        && new.second_key == old.second_key
        && old.guardians.iter().all(|g| new.guardians.contains(g))
}

pub fn effective(mut v: Vault, now: i64) -> Option<Vault> {
    let Some(p) = v.pending.clone() else { return Some(v) };
    if p.at > now {
        return Some(v);
    }
    v.pending = None;
    match p.change {
        Change::Set { settings } => v.settings = settings,
        Change::Off => return None,
        Change::Unfreeze => v.frozen = false,
    }
    Some(v)
}

fn key(parts: std::fmt::Arguments) -> Vec<u8> {
    format!("vault:{parts}").into_bytes()
}

fn vault_key(owner: &str) -> Vec<u8> {
    key(format_args!("v:{owner}"))
}

fn queue_prefix(owner: &str) -> Vec<u8> {
    key(format_args!("q:{owner}:"))
}

fn queue_key(owner: &str, id: &str) -> Vec<u8> {
    key(format_args!("q:{owner}:{id}"))
}

fn queue_count_key(owner: &str) -> Vec<u8> {
    key(format_args!("qn:{owner}"))
}

fn spent_key(owner: &str) -> Vec<u8> {
    key(format_args!("sp:{owner}"))
}

fn helper_prefix(helper: &str) -> Vec<u8> {
    key(format_args!("h:{helper}:"))
}

fn helper_key(helper: &str, owner: &str) -> Vec<u8> {
    key(format_args!("h:{helper}:{owner}"))
}

fn load<T: for<'de> Deserialize<'de>>(ov: &Ov, k: &[u8]) -> Option<T> {
    ov.get(k).and_then(|v| serde_json::from_slice(&v).ok())
}

fn save<T: Serialize>(ov: &mut Ov, k: Vec<u8>, v: &T) {
    ov.put(k, serde_json::to_vec(v).unwrap_or_default());
}

fn u64_at(ov: &Ov, k: &[u8]) -> u64 {
    ov.get(k).and_then(|v| v.get(..8).and_then(|b| b.try_into().ok()).map(u64::from_le_bytes)).unwrap_or(0)
}

fn put_u64(ov: &mut Ov, k: Vec<u8>, v: u64) {
    if v == 0 {
        ov.del(k);
    } else {
        ov.put(k, v.to_le_bytes().to_vec());
    }
}

pub fn raw_vault(ov: &Ov, owner: &str) -> Option<Vault> {
    load(ov, &vault_key(owner))
}

pub fn load_vault(ov: &Ov, owner: &str, now: i64) -> Option<Vault> {
    raw_vault(ov, owner).and_then(|v| effective(v, now))
}

pub fn queued(ov: &Ov, owner: &str, id: &str) -> Option<Queued> {
    load(ov, &queue_key(owner, id))
}

pub fn queue_of(ov: &Ov, owner: &str) -> Vec<Queued> {
    ov.committed_keys(&queue_prefix(owner), LIST_LIMIT, |_| false)
        .iter()
        .filter_map(|k| load::<Queued>(ov, k))
        .collect()
}

pub fn spent_today(ov: &Ov, owner: &str, now: i64) -> u64 {
    let s: Spent = load(ov, &spent_key(owner)).unwrap_or_default();
    if s.day == now.div_euclid(DAY_SECS) {
        s.amount
    } else {
        0
    }
}

pub fn helped_owners(ov: &Ov, helper: &str) -> Vec<String> {
    let prefix = helper_prefix(helper);
    ov.committed_keys(&prefix, LIST_LIMIT, |_| false)
        .iter()
        .filter_map(|k| String::from_utf8(k[prefix.len()..].to_vec()).ok())
        .collect()
}

fn helpers(s: &Settings) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = s.guardians.iter().cloned().collect();
    if !s.second_key.is_empty() {
        out.insert(s.second_key.clone());
    }
    out
}

fn all_helpers(v: &Vault) -> BTreeSet<String> {
    let mut out = helpers(&v.settings);
    if let Some(Pending { change: Change::Set { settings }, .. }) = &v.pending {
        out.extend(helpers(settings));
    }
    out
}

fn store(ov: &mut Ov, owner: &str, before: Option<&Vault>, after: Option<&Vault>) {
    let old = before.map(all_helpers).unwrap_or_default();
    let new = after.map(all_helpers).unwrap_or_default();
    for h in old.difference(&new) {
        ov.del(helper_key(h, owner));
    }
    for h in new.difference(&old) {
        ov.put(helper_key(h, owner), b"1".to_vec());
    }
    match after {
        Some(v) => save(ov, vault_key(owner), v),
        None => ov.del(vault_key(owner)),
    }
}

pub fn can_help(v: &Vault, owner: &str, sender: &str) -> bool {
    sender == owner || helpers(&v.settings).contains(sender)
}

fn cosigned(v: &Vault, tx: &LedgerTx) -> bool {
    !v.settings.second_key.is_empty() && cosign_signer(tx).as_deref() == Some(v.settings.second_key.as_str())
}

pub fn outflow(tx: &LedgerTx) -> u64 {
    let fee = tx.fee_uegoc.saturating_sub(FEE_ALLOWANCE_UEGOC);
    if crate::chain_db::is_unstake_tx(tx) || tx.to == tx.from {
        fee
    } else {
        tx.amount.saturating_add(fee)
    }
}

pub fn well_formed(tx: &LedgerTx) -> Result<(), String> {
    if !is_vault_op(tx) {
        return Err(format!("{} is not a vault transaction", tx.tx_type));
    }
    if tx.from.is_empty() || tx.to != tx.from || tx.amount != 0 {
        return Err("a vault transaction is a zero-amount transaction to the sender itself".into());
    }
    if tx.call_args.len() > MAX_BODY_BYTES {
        return Err(format!("the body is longer than {MAX_BODY_BYTES} bytes"));
    }
    if tx.memo != memo_for(&tx.tx_type, &tx.call_args) {
        return Err("the memo does not commit to the body".into());
    }
    let unreadable = |e: serde_json::Error| format!("the body is not readable: {e}");
    match tx.tx_type.as_str() {
        TX_SET => {
            let b: SetBody = serde_json::from_str(&tx.call_args).map_err(unreadable)?;
            check_settings(&tx.from, &b.settings)
        }
        TX_FREEZE => {
            let b: OwnerBody = serde_json::from_str(&tx.call_args).map_err(unreadable)?;
            if !valid_addr(&b.owner) {
                return Err("the freeze names no wallet".into());
            }
            Ok(())
        }
        TX_CANCEL => {
            let b: CancelBody = serde_json::from_str(&tx.call_args).map_err(unreadable)?;
            let id_ok = b.target.len() == 16 && b.target.bytes().all(|c| c.is_ascii_hexdigit());
            if !valid_addr(&b.owner) || !(b.target == CANCEL_CHANGE || id_ok) {
                return Err("the cancel names no wallet or waiting item".into());
            }
            Ok(())
        }
        TX_QUEUE => {
            let b: QueueBody = serde_json::from_str(&tx.call_args).map_err(unreadable)?;
            if !valid_addr(&b.to) || b.to == tx.from || b.amount == 0 {
                return Err("a waiting send names another address and an amount".into());
            }
            Ok(())
        }
        _ => {
            serde_json::from_str::<EmptyBody>(&tx.call_args).map_err(unreadable)?;
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    Free,
    Counted(u64),
    Exec(String),
    Refused(String, bool),
}

pub fn gate(v: &Vault, ov: &Ov, tx: &LedgerTx, now: i64) -> Gate {
    let owner = tx.from.as_str();
    if is_vault_op(tx) {
        return Gate::Counted(outflow(tx));
    }
    if tx.memo.as_deref() == Some(SWEEP_MEMO) && !v.settings.recovery.is_empty() && tx.to == v.settings.recovery {
        return Gate::Free;
    }
    if v.frozen {
        return Gate::Refused("this wallet is frozen; only a sweep to its recovery address can leave it".into(), true);
    }
    if let Some(id) = exec_id(tx) {
        let Some(q) = queued(ov, owner, id) else {
            return Gate::Refused(format!("no waiting send {id}"), false);
        };
        if q.to != tx.to || q.amount != tx.amount || tx.tx_type != "transfer" {
            return Gate::Refused(format!("the transfer does not match waiting send {id}"), false);
        }
        if now < q.at {
            return Gate::Refused(format!("waiting send {id} can go out at {}", q.at), true);
        }
        return Gate::Exec(id.to_string());
    }
    if cosigned(v, tx) {
        return Gate::Free;
    }
    Gate::Counted(outflow(tx))
}

fn fits_limit(v: &Vault, already: u64, more: u64) -> bool {
    more == 0 || already.saturating_add(more) <= v.settings.limit
}

fn subject(tx: &LedgerTx) -> bool {
    !tx.from.is_empty()
        && !crate::ledger::is_reserved_system_source(&tx.from)
        && tx.signature != "coinbase"
        && !crate::hold_chain::is_settle(tx)
}

pub struct Planner {
    vaults: BTreeMap<String, Option<Vault>>,
    counted: BTreeMap<String, u64>,
    execs: BTreeSet<(String, String)>,
    now: i64,
    height: u64,
}

impl Planner {
    pub fn new(height: u64, now: i64) -> Self {
        Self { vaults: BTreeMap::new(), counted: BTreeMap::new(), execs: BTreeSet::new(), now, height }
    }

    pub fn fit(&mut self, ov: &Ov, tx: &LedgerTx) -> Fit {
        if is_vault_op(tx) {
            if !rule_active(self.height) {
                return Fit::Later(format!("vault transactions start at block {:?}", ACTIVATION_HEIGHT));
            }
            if let Err(e) = well_formed(tx) {
                return Fit::Never(e);
            }
        }
        if !rule_active(self.height) {
            return Fit::Yes;
        }
        self.judge(ov, tx)
    }

    fn judge(&mut self, ov: &Ov, tx: &LedgerTx) -> Fit {
        if !subject(tx) {
            return Fit::Yes;
        }
        let now = self.now;
        let v = self.vaults.entry(tx.from.clone()).or_insert_with(|| load_vault(ov, &tx.from, now)).clone();
        let Some(v) = v else { return Fit::Yes };
        match gate(&v, ov, tx, now) {
            Gate::Free => Fit::Yes,
            Gate::Exec(id) => {
                if self.execs.insert((tx.from.clone(), id.clone())) {
                    Fit::Yes
                } else {
                    Fit::Never(format!("waiting send {id} is already in this block"))
                }
            }
            Gate::Counted(more) => {
                let already = spent_today(ov, &tx.from, now) + self.counted.get(&tx.from).copied().unwrap_or(0);
                if fits_limit(&v, already, more) {
                    *self.counted.entry(tx.from.clone()).or_insert(0) += more;
                    Fit::Yes
                } else {
                    Fit::Later("over the wallet's vault limit for today".into())
                }
            }
            Gate::Refused(e, true) => Fit::Later(e),
            Gate::Refused(e, false) => Fit::Never(e),
        }
    }
}

pub fn validate(ov: &Ov, block: &LedgerBlock, txs: &[LedgerTx]) -> Result<(), String> {
    let active = rule_active(block.height);
    for tx in txs.iter().filter(|t| is_vault_op(t)) {
        if !active {
            return Err(format!("{} {} refused: vault transactions are not active at block {}", tx.tx_type, tx.hash, block.height));
        }
        well_formed(tx).map_err(|e| format!("{} {} rejected: {e}", tx.tx_type, tx.hash))?;
    }
    if !active {
        return Ok(());
    }
    let mut plan = Planner::new(block.height, block.timestamp);
    for tx in txs {
        match plan.fit(ov, tx) {
            Fit::Yes => {}
            Fit::Later(e) | Fit::Never(e) => {
                return Err(format!("{} {} refused by the sender's vault: {e}", tx.tx_type, tx.hash));
            }
        }
    }
    Ok(())
}

fn op_set(ov: &mut Ov, tx: &LedgerTx, now: i64) -> Result<(), String> {
    let b: SetBody = serde_json::from_str(&tx.call_args).map_err(|e| e.to_string())?;
    check_settings(&tx.from, &b.settings)?;
    let before = raw_vault(ov, &tx.from);
    let current = before.clone().and_then(|v| effective(v, now));
    let after = match current {
        None => Vault { settings: b.settings, frozen: false, pending: None },
        Some(mut v) => {
            if tighter(&b.settings, &v.settings) || cosigned(&v, tx) {
                v.settings = b.settings;
            } else {
                let at = now.saturating_add(longest_delay(&v.settings));
                v.pending = Some(Pending { change: Change::Set { settings: b.settings }, at });
            }
            v
        }
    };
    store(ov, &tx.from, before.as_ref(), Some(&after));
    Ok(())
}

fn op_off(ov: &mut Ov, tx: &LedgerTx, now: i64) -> Result<(), String> {
    let before = raw_vault(ov, &tx.from);
    let mut v = before.clone().and_then(|v| effective(v, now)).ok_or("this wallet has no vault")?;
    if cosigned(&v, tx) {
        store(ov, &tx.from, before.as_ref(), None);
        for q in queue_of(ov, &tx.from) {
            ov.del(queue_key(&tx.from, &q.id));
        }
        put_u64(ov, queue_count_key(&tx.from), 0);
        ov.del(spent_key(&tx.from));
        return Ok(());
    }
    v.pending = Some(Pending { change: Change::Off, at: now.saturating_add(longest_delay(&v.settings)) });
    store(ov, &tx.from, before.as_ref(), Some(&v));
    Ok(())
}

fn op_unfreeze(ov: &mut Ov, tx: &LedgerTx, now: i64) -> Result<(), String> {
    let before = raw_vault(ov, &tx.from);
    let mut v = before.clone().and_then(|v| effective(v, now)).ok_or("this wallet has no vault")?;
    if !v.frozen {
        return Err("the wallet is not frozen".into());
    }
    if cosigned(&v, tx) {
        v.frozen = false;
    } else {
        v.pending = Some(Pending { change: Change::Unfreeze, at: now.saturating_add(longest_delay(&v.settings)) });
    }
    store(ov, &tx.from, before.as_ref(), Some(&v));
    Ok(())
}

fn op_freeze(ov: &mut Ov, tx: &LedgerTx, now: i64) -> Result<(), String> {
    let b: OwnerBody = serde_json::from_str(&tx.call_args).map_err(|e| e.to_string())?;
    let before = raw_vault(ov, &b.owner);
    let mut v = before.clone().and_then(|v| effective(v, now)).ok_or("that wallet has no vault")?;
    if !can_help(&v, &b.owner, &tx.from) {
        return Err("only the owner, its second key or a guardian can freeze a wallet".into());
    }
    v.frozen = true;
    if matches!(v.pending, Some(Pending { change: Change::Unfreeze, .. })) {
        v.pending = None;
    }
    store(ov, &b.owner, before.as_ref(), Some(&v));
    Ok(())
}

fn op_cancel(ov: &mut Ov, tx: &LedgerTx, now: i64) -> Result<(), String> {
    let b: CancelBody = serde_json::from_str(&tx.call_args).map_err(|e| e.to_string())?;
    let before = raw_vault(ov, &b.owner);
    let mut v = before.clone().and_then(|v| effective(v, now)).ok_or("that wallet has no vault")?;
    if !can_help(&v, &b.owner, &tx.from) {
        return Err("only the owner, its second key or a guardian can cancel".into());
    }
    if b.target == CANCEL_CHANGE {
        if v.pending.take().is_none() {
            return Err("there is no waiting change".into());
        }
        store(ov, &b.owner, before.as_ref(), Some(&v));
        return Ok(());
    }
    if queued(ov, &b.owner, &b.target).is_none() {
        return Err(format!("no waiting send {}", b.target));
    }
    ov.del(queue_key(&b.owner, &b.target));
    let n = u64_at(ov, &queue_count_key(&b.owner));
    put_u64(ov, queue_count_key(&b.owner), n.saturating_sub(1));
    Ok(())
}

fn op_queue(ov: &mut Ov, tx: &LedgerTx, now: i64) -> Result<(), String> {
    let b: QueueBody = serde_json::from_str(&tx.call_args).map_err(|e| e.to_string())?;
    let v = load_vault(ov, &tx.from, now).ok_or("this wallet has no vault")?;
    let n = u64_at(ov, &queue_count_key(&tx.from));
    if n >= MAX_QUEUED {
        return Err(format!("at most {MAX_QUEUED} sends can wait at once"));
    }
    let id = queue_id(&tx.hash);
    if queued(ov, &tx.from, &id).is_some() {
        return Err("this send is already waiting".into());
    }
    let at = now.saturating_add(delay_for(&v.settings, b.amount));
    save(ov, queue_key(&tx.from, &id), &Queued { id: id.clone(), to: b.to, amount: b.amount, at, created: now });
    put_u64(ov, queue_count_key(&tx.from), n + 1);
    Ok(())
}

pub fn apply_op(ov: &mut Ov, block: &LedgerBlock, tx: &LedgerTx) -> Result<(), String> {
    well_formed(tx)?;
    let now = block.timestamp;
    match tx.tx_type.as_str() {
        TX_SET => op_set(ov, tx, now),
        TX_OFF => op_off(ov, tx, now),
        TX_UNFREEZE => op_unfreeze(ov, tx, now),
        TX_FREEZE => op_freeze(ov, tx, now),
        TX_CANCEL => op_cancel(ov, tx, now),
        _ => op_queue(ov, tx, now),
    }
}

pub fn apply_block(ov: &mut Ov, block: &LedgerBlock, txs: &[&LedgerTx]) {
    if rule_active(block.height) {
        apply_effects(ov, block, txs);
    }
}

pub(crate) fn apply_effects(ov: &mut Ov, block: &LedgerBlock, txs: &[&LedgerTx]) {
    let now = block.timestamp;
    let day = now.div_euclid(DAY_SECS);
    let mut counted: BTreeMap<String, u64> = BTreeMap::new();
    let mut execs: Vec<(String, String)> = Vec::new();
    let mut cache: BTreeMap<String, Option<Vault>> = BTreeMap::new();
    for tx in txs.iter().filter(|t| subject(t)) {
        let v = cache.entry(tx.from.clone()).or_insert_with(|| load_vault(ov, &tx.from, now)).clone();
        let Some(v) = v else { continue };
        match gate(&v, ov, tx, now) {
            Gate::Counted(n) if n > 0 => *counted.entry(tx.from.clone()).or_insert(0) += n,
            Gate::Exec(id) => execs.push((tx.from.clone(), id)),
            _ => {}
        }
    }
    for (owner, n) in counted {
        let total = spent_today(ov, &owner, now).saturating_add(n);
        save(ov, spent_key(&owner), &Spent { day, amount: total });
    }
    for (owner, id) in execs {
        if queued(ov, &owner, &id).is_some() {
            ov.del(queue_key(&owner, &id));
            let n = u64_at(ov, &queue_count_key(&owner));
            put_u64(ov, queue_count_key(&owner), n.saturating_sub(1));
        }
    }
    for tx in txs.iter().filter(|t| is_vault_op(t)) {
        if let Err(e) = apply_op(ov, block, tx) {
            tracing::debug!("[VAULT] {} {} had no effect: {e}", tx.tx_type, tx.hash);
        }
    }
}

pub fn admit(tx: &LedgerTx) -> Result<(), String> {
    let active = rule_active_at_tip();
    if is_vault_op(tx) {
        if !active {
            return Err(format!("{} refused: the wallet vault is not active yet", tx.tx_type));
        }
        well_formed(tx)?;
    }
    if !active || !subject(tx) {
        return Ok(());
    }
    let db = crate::chain_db::global_db();
    let ov = Ov::new(db);
    let now = chrono::Utc::now().timestamp();
    let Some(v) = load_vault(&ov, &tx.from, now) else { return Ok(()) };
    match gate(&v, &ov, tx, now) {
        Gate::Free | Gate::Exec(_) => Ok(()),
        Gate::Counted(more) => {
            let already = spent_today(&ov, &tx.from, now);
            if fits_limit(&v, already, more) {
                Ok(())
            } else {
                Err(format!(
                    "VAULT_LIMIT: this wallet's vault lets {} uEGOC out today without the second key; send it with a delay or approve it with the second key",
                    v.settings.limit.saturating_sub(already)
                ))
            }
        }
        Gate::Refused(e, _) => Err(format!("VAULT_REFUSED: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: &str = "egot1owner000000000000000000000000000000000000";
    const FRIEND: &str = "egot1friend00000000000000000000000000000000000";
    const SAFE: &str = "egot1safe0000000000000000000000000000000000000";
    const THIEF: &str = "egot1thief000000000000000000000000000000000000";
    const EGOC: u64 = 1_000_000;

    fn block(height: u64, ts: i64) -> LedgerBlock {
        LedgerBlock { height, timestamp: ts, ..LedgerBlock::default() }
    }

    fn op(from: &str, tx_type: &str, body: &impl Serialize, n: u64) -> LedgerTx {
        let call_args = serde_json::to_string(body).unwrap();
        LedgerTx {
            hash: format!("0x{tx_type}{n}"),
            from: from.into(),
            to: from.into(),
            memo: memo_for(tx_type, &call_args),
            tx_type: tx_type.into(),
            call_args,
            nonce: n,
            fee_uegoc: 1_000,
            chain_id: 1,
            signature: "ab".into(),
            ..LedgerTx::default()
        }
    }

    fn send(from: &str, to: &str, amount: u64, memo: Option<&str>, n: u64) -> LedgerTx {
        LedgerTx {
            hash: format!("0xsend{n}"),
            from: from.into(),
            to: to.into(),
            amount,
            memo: memo.map(str::to_string),
            tx_type: "transfer".into(),
            nonce: n,
            fee_uegoc: 1_000,
            chain_id: 1,
            signature: "ab".into(),
            ..LedgerTx::default()
        }
    }

    fn settings(second_key: &str) -> Settings {
        Settings {
            limit: 100 * EGOC,
            delay: DAY_SECS,
            high_limit: 0,
            high_delay: 0,
            recovery: SAFE.into(),
            second_key: second_key.into(),
            guardians: vec![FRIEND.into()],
        }
    }

    fn setup(ov: &mut Ov<'static>, s: Settings) {
        op_set(ov, &op(OWNER, TX_SET, &SetBody { settings: s }, 1), 1_000).unwrap();
        ov.commit_memory();
    }

    fn check(ov: &Ov, txs: &[LedgerTx], ts: i64) -> Result<(), String> {
        let mut plan = Planner::new(10, ts);
        for tx in txs {
            match plan.judge(ov, tx) {
                Fit::Yes => {}
                Fit::Later(e) | Fit::Never(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn run(ov: &mut Ov<'static>, txs: &[LedgerTx], ts: i64) {
        let refs: Vec<&LedgerTx> = txs.iter().collect();
        apply_effects(ov, &block(10, ts), &refs);
        ov.commit_memory();
    }

    #[test]
    fn small_sends_pass_and_the_daily_limit_holds_across_a_block() {
        let mut ov = Ov::memory();
        setup(&mut ov, settings(""));
        let t = 2_000;
        assert!(check(&ov, &[send(OWNER, THIEF, 60 * EGOC, None, 2)], t).is_ok());
        assert!(check(&ov, &[send(OWNER, THIEF, 60 * EGOC, None, 2), send(OWNER, THIEF, 60 * EGOC, None, 3)], t).is_err());
        run(&mut ov, &[send(OWNER, THIEF, 60 * EGOC, None, 2)], t);
        assert!(check(&ov, &[send(OWNER, THIEF, 60 * EGOC, None, 3)], t).is_err(), "the day's limit is used up");
        assert!(check(&ov, &[send(OWNER, THIEF, 60 * EGOC, None, 3)], t + DAY_SECS).is_ok(), "a new day starts again");
    }

    #[test]
    fn a_large_send_waits_and_can_be_cancelled_by_a_guardian() {
        let mut ov = Ov::memory();
        setup(&mut ov, settings(""));
        let q = op(OWNER, TX_QUEUE, &QueueBody { to: THIEF.into(), amount: 5_000 * EGOC }, 2);
        run(&mut ov, std::slice::from_ref(&q), 2_000);
        let id = queue_id(&q.hash);
        let exec = send(OWNER, THIEF, 5_000 * EGOC, Some(&exec_memo(&id)), 3);
        assert!(check(&ov, std::slice::from_ref(&exec), 2_000 + DAY_SECS - 1).is_err(), "too early");
        assert!(check(&ov, std::slice::from_ref(&exec), 2_000 + DAY_SECS).is_ok());
        assert!(check(&ov, &[exec.clone(), exec.clone()], 2_000 + DAY_SECS).is_err(), "one waiting send leaves once");
        let mut changed = send(OWNER, FRIEND, 5_000 * EGOC, Some(&exec_memo(&id)), 3);
        changed.hash = "0xchanged".into();
        assert!(check(&ov, &[changed], 2_000 + DAY_SECS).is_err(), "the waiting send fixes its recipient");
        run(&mut ov, &[op(FRIEND, TX_CANCEL, &CancelBody { owner: OWNER.into(), target: id.clone() }, 1)], 3_000);
        assert!(check(&ov, &[exec], 2_000 + DAY_SECS).is_err(), "a cancelled send never leaves");
        assert_eq!(u64_at(&ov, &queue_count_key(OWNER)), 0);
    }

    #[test]
    fn a_thief_cannot_cancel_or_freeze_someone_elses_vault() {
        let mut ov = Ov::memory();
        setup(&mut ov, settings(""));
        let mut tx = op(THIEF, TX_FREEZE, &OwnerBody { owner: OWNER.into() }, 1);
        assert!(op_freeze(&mut ov, &tx, 2_000).is_err());
        tx = op(FRIEND, TX_FREEZE, &OwnerBody { owner: OWNER.into() }, 1);
        assert!(op_freeze(&mut ov, &tx, 2_000).is_ok());
    }

    #[test]
    fn a_frozen_wallet_only_sweeps_to_its_recovery_address() {
        let mut ov = Ov::memory();
        setup(&mut ov, settings(""));
        run(&mut ov, &[op(FRIEND, TX_FREEZE, &OwnerBody { owner: OWNER.into() }, 1)], 2_000);
        assert!(check(&ov, &[send(OWNER, THIEF, EGOC, None, 2)], 2_100).is_err());
        assert!(check(&ov, &[send(OWNER, THIEF, 9_000 * EGOC, Some(SWEEP_MEMO), 2)], 2_100).is_err(), "a sweep goes only to the recovery address");
        assert!(check(&ov, &[send(OWNER, SAFE, 9_000 * EGOC, Some(SWEEP_MEMO), 2)], 2_100).is_ok());
        run(&mut ov, &[op(OWNER, TX_UNFREEZE, &EmptyBody {}, 2)], 2_200);
        assert!(load_vault(&ov, OWNER, 2_300).unwrap().frozen, "lifting a freeze waits out the delay");
        assert!(!load_vault(&ov, OWNER, 2_200 + DAY_SECS).unwrap().frozen);
    }

    #[test]
    fn loosening_waits_and_tightening_is_instant() {
        let mut ov = Ov::memory();
        setup(&mut ov, settings(""));
        let mut s = settings("");
        s.limit = 10 * EGOC;
        run(&mut ov, &[op(OWNER, TX_SET, &SetBody { settings: s.clone() }, 2)], 2_000);
        assert_eq!(load_vault(&ov, OWNER, 2_001).unwrap().settings.limit, 10 * EGOC);
        let mut loose = s.clone();
        loose.recovery = THIEF.into();
        run(&mut ov, &[op(OWNER, TX_SET, &SetBody { settings: loose }, 3)], 3_000);
        assert_eq!(load_vault(&ov, OWNER, 3_001).unwrap().settings.recovery, SAFE, "a new recovery address waits");
        assert_eq!(load_vault(&ov, OWNER, 3_000 + DAY_SECS).unwrap().settings.recovery, THIEF);
        run(&mut ov, &[op(OWNER, TX_CANCEL, &CancelBody { owner: OWNER.into(), target: CANCEL_CHANGE.into() }, 4)], 4_000);
        assert_eq!(load_vault(&ov, OWNER, 3_000 + DAY_SECS).unwrap().settings.recovery, SAFE, "a cancelled change never lands");
        run(&mut ov, &[op(OWNER, TX_OFF, &EmptyBody {}, 5)], 5_000);
        assert!(load_vault(&ov, OWNER, 5_001).is_some());
        assert!(load_vault(&ov, OWNER, 5_000 + DAY_SECS).is_none(), "turning the vault off waits too");
    }

    #[test]
    fn the_second_key_lets_a_large_send_through_at_once() {
        let mut ov = Ov::memory();
        let second = password_key(OWNER, "correct horse battery staple").unwrap();
        let second_addr = address_of(second.verifying_key().as_bytes(), 1);
        setup(&mut ov, settings(&second_addr));
        let mut tx = send(OWNER, FRIEND, 5_000 * EGOC, None, 2);
        assert!(check(&ov, std::slice::from_ref(&tx), 2_000).is_err());
        tx.vault_cosig = cosign_with(&tx, &second);
        assert!(check(&ov, std::slice::from_ref(&tx), 2_000).is_ok());
        let mut redirected = tx.clone();
        redirected.to = THIEF.into();
        assert!(check(&ov, &[redirected], 2_000).is_err(), "the approval covers this exact send only");
        let other = password_key(OWNER, "a different long password").unwrap();
        let mut forged = send(OWNER, FRIEND, 5_000 * EGOC, None, 2);
        forged.vault_cosig = cosign_with(&forged, &other);
        assert!(check(&ov, &[forged], 2_000).is_err(), "only the registered second key counts");
    }

    #[test]
    fn the_second_key_cannot_be_added_or_swapped_without_waiting() {
        let mut ov = Ov::memory();
        setup(&mut ov, settings(""));
        let thief_key = password_key(OWNER, "thief chosen password").unwrap();
        let thief_addr = address_of(thief_key.verifying_key().as_bytes(), 1);
        run(&mut ov, &[op(OWNER, TX_SET, &SetBody { settings: settings(&thief_addr) }, 2)], 2_000);
        assert!(load_vault(&ov, OWNER, 2_001).unwrap().settings.second_key.is_empty());
        let mut tx = send(OWNER, THIEF, 5_000 * EGOC, None, 3);
        tx.vault_cosig = cosign_with(&tx, &thief_key);
        assert!(check(&ov, &[tx], 2_001).is_err());
    }

    #[test]
    fn a_large_fee_counts_against_the_limit() {
        let mut ov = Ov::memory();
        setup(&mut ov, settings(""));
        let mut tx = send(OWNER, OWNER, 0, None, 2);
        tx.fee_uegoc = 500 * EGOC;
        assert!(check(&ov, &[tx], 2_000).is_err());
    }

    #[test]
    fn settings_are_bounded() {
        let mut s = settings("");
        assert!(check_settings(OWNER, &s).is_ok());
        s.delay = 60;
        assert!(check_settings(OWNER, &s).is_err());
        s = settings("");
        s.recovery = OWNER.into();
        assert!(check_settings(OWNER, &s).is_err());
        s = settings("");
        s.high_limit = 50 * EGOC;
        s.high_delay = 3 * DAY_SECS;
        assert!(check_settings(OWNER, &s).is_err(), "the higher limit sits above the first");
        s.high_limit = 1_000 * EGOC;
        assert!(check_settings(OWNER, &s).is_ok());
        assert_eq!(delay_for(&s, 500 * EGOC), DAY_SECS);
        assert_eq!(delay_for(&s, 2_000 * EGOC), 3 * DAY_SECS);
    }

    #[test]
    fn ops_need_the_memo_that_commits_to_the_body() {
        let mut tx = op(OWNER, TX_FREEZE, &OwnerBody { owner: OWNER.into() }, 1);
        assert!(well_formed(&tx).is_ok());
        tx.call_args = serde_json::to_string(&OwnerBody { owner: FRIEND.into() }).unwrap();
        assert!(well_formed(&tx).is_err());
    }
}
