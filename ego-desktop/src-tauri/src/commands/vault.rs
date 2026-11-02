use crate::app::AppState;
use crate::drs::Ov;
use crate::error::EgoDesktopError;
use crate::ledger::{Ledger, LedgerTx};
use crate::vault_chain::{self as vc, Change, Settings, Vault};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::Mutex;
use tauri::{Manager, State};

const REQUEST_PREFIX: &str = "egovault1:";
const APPROVAL_PREFIX: &str = "egocosig1:";

static PREPARED: Mutex<Option<LedgerTx>> = Mutex::new(None);

#[derive(Debug, Default, Serialize, Deserialize)]
struct Local {
    #[serde(default)]
    mine: Vec<String>,
    #[serde(default)]
    seen: Vec<String>,
    #[serde(default)]
    key_file: String,
    #[serde(default)]
    key_file_address: String,
}

const KEY_FILE_KIND: &str = "ego-vault-second-key";

#[derive(Debug, Serialize, Deserialize)]
struct KeyFile {
    v: u8,
    kind: String,
    owner: String,
    address: String,
    salt: String,
    data: String,
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    b
}

fn file_cipher_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let params = argon2::Params::new(65_536, 3, 1, Some(32)).map_err(|e| e.to_string())?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; 32];
    argon.hash_password_into(password.as_bytes(), salt, &mut key).map_err(|e| e.to_string())?;
    Ok(key)
}

fn seal_key_file(owner: &str, sk: &ed25519_dalek::SigningKey, password: &str) -> Result<KeyFile, String> {
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
    let salt: [u8; 16] = random();
    let nonce: [u8; 12] = random();
    let key = file_cipher_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), sk.to_bytes().as_ref())
        .map_err(|_| "could not encrypt the key".to_string())?;
    let mut data = nonce.to_vec();
    data.extend(ct);
    Ok(KeyFile {
        v: 1,
        kind: KEY_FILE_KIND.into(),
        owner: owner.into(),
        address: vc::address_of(sk.verifying_key().as_bytes(), 1),
        salt: hex::encode(salt),
        data: hex::encode(data),
    })
}

fn open_key_file(kf: &KeyFile, password: &str) -> Result<ed25519_dalek::SigningKey, String> {
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
    let salt = hex::decode(&kf.salt).map_err(|_| "the key file is damaged".to_string())?;
    let data = hex::decode(&kf.data).map_err(|_| "the key file is damaged".to_string())?;
    if data.len() < 12 + 32 {
        return Err("the key file is damaged".into());
    }
    let (nonce, ct) = data.split_at(12);
    let key = file_cipher_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| "wrong password for the second-key file".to_string())?;
    let seed: [u8; 32] = plain.try_into().map_err(|_| "the key file is damaged".to_string())?;
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    if vc::address_of(sk.verifying_key().as_bytes(), 1) != kf.address {
        return Err("the key file is damaged".into());
    }
    Ok(sk)
}

fn read_key_file(path: &str) -> Result<KeyFile, String> {
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let kf: KeyFile = serde_json::from_slice(&bytes).map_err(|_| "this is not an Ego second-key file".to_string())?;
    if kf.kind != KEY_FILE_KIND {
        return Err("this is not an Ego second-key file".into());
    }
    Ok(kf)
}

pub fn second_key(owner: &str, password: &str) -> Result<ed25519_dalek::SigningKey, String> {
    let want = vc::load_vault(&Ov::new(crate::chain_db::global_db()), owner, now())
        .map(|v| v.settings.second_key)
        .unwrap_or_default();
    let local = load_local();
    if !local.key_file.is_empty() && (want.is_empty() || want == local.key_file_address) {
        match read_key_file(&local.key_file) {
            Ok(kf) if kf.owner == owner => return open_key_file(&kf, password),
            Ok(_) => {}
            Err(e) if want == local.key_file_address => {
                return Err(format!(
                    "the second-key file can't be read at {} ({e}). Connect the drive that holds it, or choose it again in Wallet → Vault",
                    local.key_file
                ));
            }
            Err(_) => {}
        }
    }
    vc::password_key(owner, password)
}

fn local_path() -> std::path::PathBuf {
    crate::ledger::wallet_dir(&crate::ledger::get_active_wallet_id()).join("vault.json")
}

fn load_local() -> Local {
    std::fs::read(local_path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn save_local(l: &Local) {
    if let Ok(b) = serde_json::to_vec_pretty(l) {
        let _ = crate::utils::atomic_write(&local_path(), &b);
    }
}

fn remember_seen(key: String) {
    let mut l = load_local();
    if !l.seen.contains(&key) {
        l.seen.push(key);
        if l.seen.len() > 512 {
            l.seen.drain(..l.seen.len() - 512);
        }
        save_local(&l);
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Approval {
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct QueuedView {
    pub id: String,
    pub to: String,
    pub amount: u64,
    pub at: i64,
    pub mine: bool,
}

#[derive(Debug, Serialize)]
pub struct PendingView {
    pub kind: String,
    pub at: i64,
    pub settings: Option<Settings>,
}

#[derive(Debug, Serialize)]
pub struct VaultView {
    pub owner: String,
    pub settings: Settings,
    pub frozen: bool,
    pub pending: Option<PendingView>,
    pub queue: Vec<QueuedView>,
    pub spent_today: u64,
}

#[derive(Debug, Serialize)]
pub struct VaultStatus {
    pub active: bool,
    pub address: String,
    pub vault: Option<VaultView>,
    pub helping: Vec<VaultView>,
    pub key_file: String,
}

#[derive(Debug, Serialize)]
pub struct RequestPreview {
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub kind: String,
    pub memo: String,
    pub i_am_second_key: bool,
}

fn err(e: impl std::fmt::Display) -> EgoDesktopError {
    EgoDesktopError::InvalidInput(e.to_string())
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn view(ov: &Ov, owner: &str, v: Vault, at: i64, mine: &[String]) -> VaultView {
    let pending = v.pending.as_ref().map(|p| match &p.change {
        Change::Set { settings } => PendingView { kind: "settings".into(), at: p.at, settings: Some(settings.clone()) },
        Change::Off => PendingView { kind: "off".into(), at: p.at, settings: None },
        Change::Unfreeze => PendingView { kind: "unfreeze".into(), at: p.at, settings: None },
    });
    let mut queue: Vec<QueuedView> = vc::queue_of(ov, owner)
        .into_iter()
        .map(|q| QueuedView { mine: mine.contains(&q.id), id: q.id, to: q.to, amount: q.amount, at: q.at })
        .collect();
    queue.sort_by_key(|q| q.at);
    VaultView {
        owner: owner.to_string(),
        spent_today: vc::spent_today(ov, owner, at),
        settings: v.settings,
        frozen: v.frozen,
        pending,
        queue,
    }
}

fn status_now() -> VaultStatus {
    let address = Ledger::load().address;
    let local = load_local();
    status_of(address, &local.mine, local.key_file)
}

pub fn public_status(address: &str) -> VaultStatus {
    status_of(address.to_string(), &[], String::new())
}

fn status_of(address: String, mine: &[String], key_file: String) -> VaultStatus {
    let db = crate::chain_db::global_db();
    let ov = Ov::new(db);
    let at = now();
    let vault = vc::raw_vault(&ov, &address).map(|v| view(&ov, &address, v, at, mine));
    let helping = vc::helped_owners(&ov, &address)
        .into_iter()
        .filter_map(|owner| {
            let v = vc::raw_vault(&ov, &owner)?;
            let current = vc::effective(v.clone(), at)?;
            let pending_helper = matches!(&v.pending, Some(vc::Pending { change: Change::Set { settings }, .. })
                if settings.guardians.contains(&address) || settings.second_key == address);
            if !vc::can_help(&current, &owner, &address) && !pending_helper {
                return None;
            }
            Some(view(&ov, &owner, v, at, &[]))
        })
        .collect();
    VaultStatus { active: vc::rule_active_at_tip(), address, vault, helping, key_file }
}

fn keypair(state: &AppState) -> Result<ego_core::KeyPair, EgoDesktopError> {
    state.get_keypair().ok_or(EgoDesktopError::WalletError("wallet not initialized".into()))
}

fn base_tx(ledger: &Ledger, to: &str, amount: u64, memo: Option<String>, tx_type: &str, call_args: String) -> Result<LedgerTx, EgoDesktopError> {
    if ledger.address.is_empty() {
        return Err(EgoDesktopError::WalletError("wallet not initialized".into()));
    }
    let fee = crate::tokenomics::fee_for_tx_with_staking("transfer", ledger.staked_amount > 0);
    if crate::chain_db::balance_of(&ledger.address) < amount.saturating_add(fee) {
        return Err(err(format!("You need {:.6} EGOC for this, including the network fee", amount.saturating_add(fee) as f64 / 1_000_000.0)));
    }
    Ok(LedgerTx {
        from: ledger.address.clone(),
        to: to.to_string(),
        amount,
        memo,
        timestamp: now(),
        status: "Pending".into(),
        nonce: crate::ledger::next_nonce_for(&ledger.address, ledger.nonce),
        fee_uegoc: fee,
        chain_id: 1,
        tx_type: tx_type.to_string(),
        call_args,
        ..LedgerTx::default()
    })
}

fn op_tx(ledger: &Ledger, tx_type: &str, body: &impl Serialize) -> Result<LedgerTx, EgoDesktopError> {
    let call_args = serde_json::to_string(body).map_err(err)?;
    let memo = vc::memo_for(tx_type, &call_args).ok_or(err(format!("{tx_type} is not a vault transaction")))?;
    let addr = ledger.address.clone();
    base_tx(ledger, &addr, 0, Some(memo), tx_type, call_args)
}

async fn approve_with_password(tx: &mut LedgerTx, approval: &Option<Approval>) -> Result<(), EgoDesktopError> {
    let Some(pw) = approval.as_ref().and_then(|a| a.password.clone()).filter(|p| !p.is_empty()) else { return Ok(()) };
    let owner = tx.from.clone();
    let key = tokio::task::spawn_blocking(move || second_key(&owner, &pw))
        .await
        .map_err(err)?
        .map_err(err)?;
    tx.vault_cosig = vc::cosign_with(tx, &key);
    Ok(())
}

async fn submit(state: &AppState, tx_type: &str, body: &impl Serialize, approval: Option<Approval>) -> Result<String, EgoDesktopError> {
    let _guard = crate::ledger::TX_MUTEX.lock().await;
    let mut ledger = Ledger::load();
    let mut tx = op_tx(&ledger, tx_type, body)?;
    crate::ledger::seal_tx(&mut tx, &keypair(state)?, true);
    approve_with_password(&mut tx, &approval).await?;
    finish(tx, &mut ledger).await
}

async fn finish(tx: LedgerTx, ledger: &mut Ledger) -> Result<String, EgoDesktopError> {
    crate::ledger::verify_incoming_tx(&tx).map_err(err)?;
    ledger.nonce = tx.nonce;
    let hash = tx.hash.clone();
    crate::commands::credits::queue_tx(tx, ledger.clone()).await;
    Ok(hash)
}

fn need_active() -> Result<(), EgoDesktopError> {
    if vc::rule_active_at_tip() {
        Ok(())
    } else {
        Err(err("The wallet vault is not switched on in the network yet"))
    }
}

fn mark_own_change(owner: &str) {
    let db = crate::chain_db::global_db();
    let ov = Ov::new(db);
    if let Some(p) = vc::raw_vault(&ov, owner).and_then(|v| v.pending) {
        remember_seen(format!("{owner}:change:{}", p.at));
    }
}

#[tauri::command]
pub async fn get_vault_status() -> Result<VaultStatus, EgoDesktopError> {
    tokio::task::spawn_blocking(status_now).await.map_err(err)
}

#[tauri::command]
pub async fn vault_password_address(password: String) -> Result<String, EgoDesktopError> {
    let owner = Ledger::load().address;
    tokio::task::spawn_blocking(move || {
        let key = vc::password_key(&owner, &password)?;
        Ok::<_, String>(vc::address_of(key.verifying_key().as_bytes(), 1))
    })
    .await
    .map_err(err)?
    .map_err(err)
}

#[tauri::command]
pub async fn vault_save_settings(settings: Settings, approval: Option<Approval>, state: State<'_, AppState>) -> Result<String, EgoDesktopError> {
    need_active()?;
    let owner = Ledger::load().address;
    vc::check_settings(&owner, &settings).map_err(err)?;
    let hash = submit(&state, vc::TX_SET, &vc::SetBody { settings }, approval).await?;
    Ok(hash)
}

#[tauri::command]
pub async fn vault_freeze(owner: Option<String>, state: State<'_, AppState>) -> Result<String, EgoDesktopError> {
    need_active()?;
    let owner = owner.filter(|o| !o.is_empty()).unwrap_or_else(|| Ledger::load().address);
    submit(&state, vc::TX_FREEZE, &vc::OwnerBody { owner }, None).await
}

#[tauri::command]
pub async fn vault_unfreeze(approval: Option<Approval>, state: State<'_, AppState>) -> Result<String, EgoDesktopError> {
    need_active()?;
    submit(&state, vc::TX_UNFREEZE, &vc::EmptyBody {}, approval).await
}

#[tauri::command]
pub async fn vault_turn_off(approval: Option<Approval>, state: State<'_, AppState>) -> Result<String, EgoDesktopError> {
    need_active()?;
    submit(&state, vc::TX_OFF, &vc::EmptyBody {}, approval).await
}

#[tauri::command]
pub async fn vault_cancel(owner: Option<String>, target: String, state: State<'_, AppState>) -> Result<String, EgoDesktopError> {
    need_active()?;
    let owner = owner.filter(|o| !o.is_empty()).unwrap_or_else(|| Ledger::load().address);
    submit(&state, vc::TX_CANCEL, &vc::CancelBody { owner, target }, None).await
}

#[derive(Debug, Serialize)]
pub struct QueuedSend {
    pub id: String,
    pub hash: String,
    pub wait_secs: i64,
}

#[tauri::command]
pub async fn vault_queue_send(to: String, amount: u64, state: State<'_, AppState>) -> Result<QueuedSend, EgoDesktopError> {
    need_active()?;
    let owner = Ledger::load().address;
    let db = crate::chain_db::global_db();
    let v = vc::load_vault(&Ov::new(db), &owner, now()).ok_or(err("This wallet has no vault"))?;
    if crate::chain_db::balance_of(&owner) < amount {
        return Err(err("The balance is too low for this send"));
    }
    let hash = submit(&state, vc::TX_QUEUE, &vc::QueueBody { to, amount }, None).await?;
    let id = vc::queue_id(&hash);
    let mut l = load_local();
    l.mine.push(id.clone());
    save_local(&l);
    remember_seen(format!("{owner}:{id}"));
    Ok(QueuedSend { id, hash, wait_secs: vc::delay_for(&v.settings, amount) })
}

#[tauri::command]
pub async fn vault_sweep(state: State<'_, AppState>) -> Result<String, EgoDesktopError> {
    need_active()?;
    let _guard = crate::ledger::TX_MUTEX.lock().await;
    let mut ledger = Ledger::load();
    let db = crate::chain_db::global_db();
    let v = vc::load_vault(&Ov::new(db), &ledger.address, now()).ok_or(err("This wallet has no vault"))?;
    if v.settings.recovery.is_empty() {
        return Err(err("Set a recovery address first"));
    }
    let fee = crate::tokenomics::fee_for_tx_with_staking("transfer", ledger.staked_amount > 0);
    let amount = crate::chain_db::balance_of(&ledger.address).saturating_sub(fee);
    if amount == 0 {
        return Err(err("There is nothing to sweep"));
    }
    let mut tx = base_tx(&ledger, &v.settings.recovery, amount, Some(vc::SWEEP_MEMO.into()), "transfer", String::new())?;
    crate::ledger::seal_tx(&mut tx, &keypair(&state)?, true);
    finish(tx, &mut ledger).await
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApprovalRequest {
    tx_version: u8,
    chain_id: u8,
    from: String,
    to: String,
    amount: u64,
    nonce: u64,
    timestamp: i64,
    fee: u64,
    #[serde(default)]
    priority_fee: u64,
    tx_type: String,
    #[serde(default)]
    memo: Option<String>,
    #[serde(default)]
    call_args: String,
}

impl ApprovalRequest {
    fn of(tx: &LedgerTx) -> Self {
        Self {
            tx_version: tx.tx_version,
            chain_id: tx.chain_id,
            from: tx.from.clone(),
            to: tx.to.clone(),
            amount: tx.amount,
            nonce: tx.nonce,
            timestamp: tx.timestamp,
            fee: tx.fee_uegoc,
            priority_fee: tx.priority_fee_uegoc,
            tx_type: tx.tx_type.clone(),
            memo: tx.memo.clone(),
            call_args: tx.call_args.clone(),
        }
    }

    fn tx(&self) -> LedgerTx {
        LedgerTx {
            tx_version: self.tx_version,
            chain_id: self.chain_id,
            from: self.from.clone(),
            to: self.to.clone(),
            amount: self.amount,
            nonce: self.nonce,
            timestamp: self.timestamp,
            fee_uegoc: self.fee,
            priority_fee_uegoc: self.priority_fee,
            tx_type: self.tx_type.clone(),
            memo: self.memo.clone(),
            call_args: self.call_args.clone(),
            ..LedgerTx::default()
        }
    }
}

fn encode_request(tx: &LedgerTx) -> Result<String, EgoDesktopError> {
    Ok(format!("{REQUEST_PREFIX}{}", STANDARD.encode(serde_json::to_vec(&ApprovalRequest::of(tx)).map_err(err)?)))
}

fn decode_request(code: &str) -> Result<LedgerTx, EgoDesktopError> {
    let raw = code.trim().strip_prefix(REQUEST_PREFIX).ok_or(err("This is not an Ego vault approval request"))?;
    let bytes = STANDARD.decode(raw).map_err(|_| err("The approval request is damaged"))?;
    let req: ApprovalRequest = serde_json::from_slice(&bytes).map_err(|_| err("The approval request is damaged"))?;
    if req.tx_version != 3 {
        return Err(err("The approval request is from an older Ego version"));
    }
    Ok(req.tx())
}

#[derive(Debug, Default, Deserialize)]
pub struct RequestInput {
    pub kind: String,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub amount: Option<u64>,
    #[serde(default)]
    pub memo: Option<String>,
    #[serde(default)]
    pub settings: Option<Settings>,
}

#[tauri::command]
pub async fn vault_request_code(request: RequestInput, state: State<'_, AppState>) -> Result<String, EgoDesktopError> {
    let ledger = Ledger::load();
    let mut tx = match request.kind.as_str() {
        "send" => {
            let to = request.to.clone().ok_or(err("The send has no recipient"))?;
            let amount = request.amount.filter(|a| *a > 0).ok_or(err("The send has no amount"))?;
            base_tx(&ledger, &to, amount, request.memo.clone().filter(|m| !m.is_empty()), "transfer", String::new())?
        }
        "settings" => {
            let settings = request.settings.clone().ok_or(err("No settings to approve"))?;
            vc::check_settings(&ledger.address, &settings).map_err(err)?;
            op_tx(&ledger, vc::TX_SET, &vc::SetBody { settings })?
        }
        "unfreeze" => op_tx(&ledger, vc::TX_UNFREEZE, &vc::EmptyBody {})?,
        "off" => op_tx(&ledger, vc::TX_OFF, &vc::EmptyBody {})?,
        other => return Err(err(format!("Unknown approval kind {other}"))),
    };
    crate::ledger::seal_tx(&mut tx, &keypair(&state)?, true);
    let code = encode_request(&tx)?;
    *PREPARED.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
    Ok(code)
}

#[tauri::command]
pub async fn vault_preview_request(code: String) -> Result<RequestPreview, EgoDesktopError> {
    let tx = decode_request(&code)?;
    let me = Ledger::load().address;
    let db = crate::chain_db::global_db();
    let second = vc::load_vault(&Ov::new(db), &tx.from, now()).map(|v| v.settings.second_key).unwrap_or_default();
    let kind = match tx.tx_type.as_str() {
        vc::TX_SET => "change the vault settings",
        vc::TX_UNFREEZE => "unfreeze the wallet",
        vc::TX_OFF => "turn the vault off",
        _ => "send",
    };
    Ok(RequestPreview {
        from: tx.from.clone(),
        to: tx.to.clone(),
        amount: tx.amount,
        kind: kind.into(),
        memo: tx.memo.clone().unwrap_or_default(),
        i_am_second_key: !second.is_empty() && second == me,
    })
}

#[tauri::command]
pub async fn vault_approve_request(code: String, state: State<'_, AppState>) -> Result<String, EgoDesktopError> {
    let tx = decode_request(&code)?;
    let me = Ledger::load().address;
    let db = crate::chain_db::global_db();
    let second = vc::load_vault(&Ov::new(db), &tx.from, now()).map(|v| v.settings.second_key).unwrap_or_default();
    if second != me {
        return Err(err("This wallet is not the second key of that vault"));
    }
    let kp = keypair(&state)?;
    let msg = vc::cosign_message(&tx);
    let sig = kp.sign_ed25519(&msg);
    Ok(format!(
        "{APPROVAL_PREFIX}{}:{}",
        hex::encode(kp.ed25519_public_key().as_bytes()),
        hex::encode(sig.as_bytes())
    ))
}

#[tauri::command]
pub async fn vault_submit_approved(approval: String) -> Result<String, EgoDesktopError> {
    let cosig = approval.trim().strip_prefix(APPROVAL_PREFIX).ok_or(err("This is not an Ego vault approval"))?.to_string();
    let mut tx = PREPARED.lock().unwrap_or_else(|e| e.into_inner()).take().ok_or(err("Create the approval request again on this device"))?;
    tx.vault_cosig = cosig;
    let db = crate::chain_db::global_db();
    let second = vc::load_vault(&Ov::new(db), &tx.from, now()).map(|v| v.settings.second_key).unwrap_or_default();
    if second.is_empty() || vc::cosign_signer(&tx).as_deref() != Some(second.as_str()) {
        *PREPARED.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
        return Err(err("That approval does not come from this vault's second key for this request"));
    }
    let _guard = crate::ledger::TX_MUTEX.lock().await;
    let mut ledger = Ledger::load();
    let owner = tx.from.clone();
    let hash = finish(tx, &mut ledger).await?;
    mark_own_change(&owner);
    Ok(hash)
}

pub async fn vault_tick() {
    if !vc::rule_active_at_tip() {
        return;
    }
    let Some(app) = crate::p2p::APP_HANDLE.get() else { return };
    let ledger = Ledger::load();
    let owner = ledger.address.clone();
    if owner.is_empty() {
        return;
    }
    let status = match tokio::task::spawn_blocking(status_now).await {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut local = load_local();
    let mut alerts: Vec<(String, String)> = Vec::new();
    let mut seen: BTreeSet<String> = local.seen.iter().cloned().collect();
    let views = status.vault.iter().map(|v| (true, v)).chain(status.helping.iter().map(|v| (false, v)));
    for (own, v) in views {
        let whose = if own { "your wallet".to_string() } else { format!("wallet {:.14}…", v.owner) };
        for q in &v.queue {
            let k = format!("{}:{}", v.owner, q.id);
            if !q.mine && seen.insert(k) {
                alerts.push((
                    "Vault: a send is waiting".into(),
                    format!("{:.6} EGOC to {:.14}… is waiting on {whose}. Cancel it in Wallet → Vault if it is not expected.", q.amount as f64 / 1_000_000.0, q.to),
                ));
            }
        }
        if let Some(p) = &v.pending {
            let k = format!("{}:change:{}", v.owner, p.at);
            if seen.insert(k) {
                alerts.push((
                    "Vault: a change is waiting".into(),
                    format!("A request to {} {whose} is waiting. Cancel it in Wallet → Vault if it is not expected.", match p.kind.as_str() {
                        "off" => "turn off the vault on",
                        "unfreeze" => "unfreeze",
                        _ => "loosen the vault settings of",
                    }),
                ));
            }
        }
    }
    local.seen = seen.into_iter().collect();
    let live: BTreeSet<String> = status.vault.as_ref().map(|v| v.queue.iter().map(|q| q.id.clone()).collect()).unwrap_or_default();
    local.mine.retain(|id| live.contains(id));
    save_local(&local);
    for (title, body) in alerts {
        crate::commands::notifications::notify(app, &title, &body);
    }
    let Some(v) = status.vault else { return };
    if v.frozen {
        return;
    }
    let pending = crate::mempool::get_mempool().peek_all();
    let at = now();
    for q in v.queue.iter().filter(|q| q.mine && q.at <= at) {
        let memo = vc::exec_memo(&q.id);
        if pending.iter().any(|t| t.from == owner && t.memo.as_deref() == Some(memo.as_str())) {
            continue;
        }
        let Some(kp) = app.state::<AppState>().get_keypair() else { return };
        let _guard = crate::ledger::TX_MUTEX.lock().await;
        let mut ledger = Ledger::load();
        let Ok(mut tx) = base_tx(&ledger, &q.to, q.amount, Some(memo), "transfer", String::new()) else { continue };
        crate::ledger::seal_tx(&mut tx, &kp, true);
        if let Err(e) = finish(tx, &mut ledger).await {
            tracing::warn!("[VAULT] waiting send {} could not go out: {e:?}", q.id);
        }
    }
}

#[derive(Debug, Serialize)]
pub struct KeyFileInfo {
    pub path: String,
    pub address: String,
}

#[tauri::command]
pub async fn vault_create_key_file(folder: String, password: String) -> Result<KeyFileInfo, EgoDesktopError> {
    let owner = Ledger::load().address;
    if owner.is_empty() {
        return Err(EgoDesktopError::WalletError("wallet not initialized".into()));
    }
    if password.chars().count() < 10 {
        return Err(err("Use a password of at least 10 characters"));
    }
    let dir = std::path::PathBuf::from(folder.trim());
    if !dir.is_dir() {
        return Err(err("That folder does not exist"));
    }
    tokio::task::spawn_blocking(move || {
        let sk = ed25519_dalek::SigningKey::from_bytes(&random::<32>());
        let kf = seal_key_file(&owner, &sk, &password)?;
        let tag = owner.get(5..13).unwrap_or("wallet").to_string();
        let mut path = dir.join(format!("ego-second-key-{tag}.json"));
        let mut n = 2;
        while path.exists() {
            path = dir.join(format!("ego-second-key-{tag}-{n}.json"));
            n += 1;
        }
        let bytes = serde_json::to_vec_pretty(&kf).map_err(|e| e.to_string())?;
        std::fs::write(&path, bytes).map_err(|e| format!("could not write the key file: {e}"))?;
        let mut l = load_local();
        l.key_file = path.to_string_lossy().to_string();
        l.key_file_address = kf.address.clone();
        save_local(&l);
        Ok::<_, String>(KeyFileInfo { path: l.key_file, address: kf.address })
    })
    .await
    .map_err(err)?
    .map_err(err)
}

#[tauri::command]
pub async fn vault_use_key_file(path: String) -> Result<String, EgoDesktopError> {
    let owner = Ledger::load().address;
    let kf = read_key_file(&path).map_err(err)?;
    if kf.owner != owner {
        return Err(err("That key file belongs to another wallet"));
    }
    let mut l = load_local();
    l.key_file = path;
    l.key_file_address = kf.address.clone();
    save_local(&l);
    Ok(kf.address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_approval_request_fits_a_qr_code_and_signs_the_same_bytes() {
        let kp = ego_core::KeyPair::from_bytes(&[3u8; 32]).unwrap();
        let mut tx = LedgerTx {
            from: "egot1ownerownerownerownerownerownerownerowner".into(),
            to: "egot1friendfriendfriendfriendfriendfriendfri".into(),
            amount: 5_000_000_000,
            memo: Some("rent".into()),
            timestamp: 1_800_000_000,
            nonce: 42,
            fee_uegoc: 1_000,
            chain_id: 1,
            tx_type: "transfer".into(),
            tx_version: 3,
            ..LedgerTx::default()
        };
        crate::ledger::seal_tx(&mut tx, &kp, true);
        let code = encode_request(&tx).unwrap();
        assert!(code.len() < 1_000, "the request is {} characters", code.len());
        let back = decode_request(&code).unwrap();
        assert_eq!(vc::cosign_message(&back), vc::cosign_message(&tx));
    }

    #[test]
    fn a_key_file_opens_only_with_its_password() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let kf = seal_key_file("egot1owner", &sk, "a long file password").unwrap();
        assert!(!serde_json::to_string(&kf).unwrap().contains(&hex::encode(sk.to_bytes())), "the key is not stored in the clear");
        assert_eq!(open_key_file(&kf, "a long file password").unwrap().to_bytes(), sk.to_bytes());
        assert!(open_key_file(&kf, "the wrong password!!").is_err());
        assert_eq!(kf.address, vc::address_of(sk.verifying_key().as_bytes(), 1));
    }
}
