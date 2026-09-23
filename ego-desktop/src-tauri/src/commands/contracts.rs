use crate::app::AppState;
use crate::error::EgoDesktopError;
use crate::ledger::{
    contract_commit_memo, contracts_dir, load_chain, save_chain, tx_signing_bytes_v2,
    Ledger, LedgerTx,
};
use ego_vm::{CallResult, DeployResult, Executor};
use serde::{Deserialize, Serialize};
use tauri::State;

const CHAIN_ID: u8 = 1;

/// Sign a contract transaction and hand it to the network.
///
/// Everything a contract transaction says beyond the plain transfer fields lives
/// outside the signed bytes, so the memo carries a commitment to the entrypoint and
/// the arguments and the verifier checks it. Until this existed the dApp IDE ran
/// contracts on the machine that typed them and told nobody, which is why a contract
/// deployed on one node was invisible everywhere else.
fn sign_and_queue_contract_tx(
    state: &State<'_, AppState>,
    ledger: &mut Ledger,
    tx_type: &str,
    contract_addr: &str,
    entrypoint: &str,
    args_hex: &str,
    wasm_hex: &str,
    code_hash: &str,
    fee: u64,
) -> Result<LedgerTx, EgoDesktopError> {
    let from = ledger.address.clone();
    let confirmed = crate::ledger::last_confirmed_nonce(&from);
    let nonce = ledger.nonce.max(confirmed) + 1;
    let ts = chrono::Utc::now().timestamp();
    let memo = contract_commit_memo(tx_type, entrypoint, args_hex, code_hash);

    let sign_bytes = tx_signing_bytes_v2(&from, contract_addr, 0, nonce, ts, CHAIN_ID, &memo);
    let kp = state.get_keypair().ok_or_else(|| {
        EgoDesktopError::WalletError("Wallet not initialized - call init_wallet first".into())
    })?;
    let ed_sig  = kp.sign_ed25519(&sign_bytes);
    let dil_sig = kp.sign_dilithium(&sign_bytes);

    let tx = LedgerTx {
        hash: format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex()),
        from,
        to: contract_addr.to_string(),
        amount: 0,
        memo: Some(memo),
        timestamp: ts,
        signature: hex::encode(ed_sig.as_bytes()),
        status: "Pending".into(),
        block_height: None,
        nonce,
        public_key_ed25519: hex::encode(kp.ed25519_public_key().as_bytes()),
        dilithium_pubkey: hex::encode(&kp.dilithium_public_key().key_data),
        dilithium_signature: hex::encode(&dil_sig.signature_data),
        fee_uegoc: fee,
        tx_version: 2,
        chain_id: CHAIN_ID,
        tx_type: tx_type.to_string(),
        contract_addr: contract_addr.to_string(),
        entrypoint: entrypoint.to_string(),
        call_args: args_hex.to_string(),
        wasm_code: wasm_hex.to_string(),
        ..LedgerTx::default()
    };

    ledger.nonce = nonce;
    let _ = ledger.save();

    crate::mempool::get_mempool()
        .push(tx.clone())
        .map_err(EgoDesktopError::WalletError)?;
    crate::commands::tx_pending::add(&tx);

    let gossip = tx.clone();
    tauri::async_runtime::spawn(async move {
        crate::p2p::broadcast_pending_tx(gossip).await;
    });

    Ok(tx)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CompileResult {
    pub wasm_hex: String,
    pub size: usize,
}

#[tauri::command]
pub async fn compile_urego(source: String) -> Result<CompileResult, EgoDesktopError> {
    let wasm = urego_compiler::compile(&source)
        .map_err(|e| EgoDesktopError::WalletError(e.to_string()))?;
    let size = wasm.len();
    Ok(CompileResult { wasm_hex: hex::encode(&wasm), size })
}

fn vm() -> Result<Executor, EgoDesktopError> {
    Executor::new(contracts_dir())
        .map_err(|e| EgoDesktopError::WalletError(e.to_string()))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeployContractArgs {

    pub wasm_hex: String,

    pub init_args_hex: String,

    #[serde(default)]
    pub name: String,

    #[serde(default)]
    pub abi: Vec<String>,
}

#[tauri::command]
pub async fn deploy_contract(
    state: State<'_, AppState>,
    args: DeployContractArgs,
) -> Result<DeployResult, EgoDesktopError> {
    let mut ledger = Ledger::load();
    if ledger.address.is_empty() {
        return Err(EgoDesktopError::WalletError("No wallet".into()));
    }

    let wasm_bytes = hex::decode(&args.wasm_hex)
        .map_err(|e| EgoDesktopError::WalletError(format!("Invalid wasm hex: {e}")))?;
    let init_args = hex::decode(&args.init_args_hex).unwrap_or_default();

    let mut chain = load_chain();
    let height    = chain.blocks.last().map(|b| b.height).unwrap_or(0);
    let ts        = chrono::Utc::now().timestamp();

    let exec   = vm()?;
    let result = exec.deploy(&wasm_bytes, &ledger.address, &init_args, height, ts,
                             ego_vm::types::DEFAULT_DEPLOY_FUEL)
        .map_err(|e| EgoDesktopError::WalletError(e.to_string()))?;

    let state_path = contracts_dir()
        .join("contracts")
        .join(&result.contract_address)
        .join("state.json");
    if let Ok(state_json) = std::fs::read_to_string(&state_path) {
        crate::chain_db::save_contract_state(&result.contract_address, &state_json);
    }

    if !args.name.is_empty() {
        let manifest_path = contracts_dir()
            .join("contracts")
            .join(&result.contract_address)
            .join("manifest.json");
        if let Ok(existing) = std::fs::read_to_string(&manifest_path) {
            if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(&existing) {
                json["name"] = serde_json::Value::String(args.name.clone());
                let _ = std::fs::write(
                    &manifest_path,
                    serde_json::to_string_pretty(&json).unwrap_or_default(),
                );
            }
        }
    }

    if !args.abi.is_empty() {
        let abi_path = contracts_dir()
            .join("contracts")
            .join(&result.contract_address)
            .join("abi.json");
        let _ = std::fs::write(&abi_path, serde_json::to_string(&args.abi).unwrap_or_default());
    }

    let is_staker   = ledger.staked_amount > 0;
    let deploy_fee  = crate::tokenomics::deploy_fee_with_staking(is_staker);
    let nonce       = chain.last_nonce(&ledger.address) + 1;
    let tx_data     = format!("deploy:{}:{}:{}", ledger.address, result.contract_address, nonce);
    let tx_hash     = hex::encode(ego_core::hash_data(tx_data.as_bytes()).as_bytes());

    // The fee rides on the deploy transaction itself and is burned by the network
    // when the block applies it. Checked here only so the user is told now rather
    // than discovering it when the transaction is dropped.
    if deploy_fee > 0 {
        let bal = crate::chain_db::balance_of(&ledger.address);
        if deploy_fee > bal {
            return Err(EgoDesktopError::WalletError(format!(
                "Insufficient balance for deploy fee: need {} uEGOC, have {}",
                deploy_fee, bal
            )));
        }
    }

    let _ = (tx_hash, nonce, ts);
    save_chain(&chain).ok();

    // The local run above is a preview so the IDE can show a result immediately.
    // This is the authoritative one: every node deploys it when the block lands.
    sign_and_queue_contract_tx(
        &state, &mut ledger, "deploy",
        &result.contract_address, "init", &args.init_args_hex,
        &args.wasm_hex, &result.code_hash, deploy_fee,
    )?;

    Ok(result)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CallContractArgs {
    pub contract_addr: String,
    pub entrypoint:    String,
    pub args_hex:      String,
}

#[tauri::command]
pub async fn call_contract(
    state: State<'_, AppState>,
    args: CallContractArgs,
) -> Result<CallResult, EgoDesktopError> {
    if !args.contract_addr.starts_with("egot1") || args.contract_addr.len() > 100 {
        return Err(EgoDesktopError::WalletError("Invalid contract address".into()));
    }
    if args.entrypoint.is_empty()
        || args.entrypoint.len() > 64
        || !args.entrypoint.chars().all(|c| c.is_alphanumeric() || c == '_')
    {
        return Err(EgoDesktopError::WalletError("Invalid entrypoint name".into()));
    }

    let ledger = Ledger::load();
    if ledger.address.is_empty() {
        return Err(EgoDesktopError::WalletError("No wallet".into()));
    }

    let call_args = hex::decode(&args.args_hex).unwrap_or_default();
    let mut chain = load_chain();
    let height    = chain.blocks.last().map(|b| b.height).unwrap_or(0);
    let ts        = chrono::Utc::now().timestamp();

    let exec   = vm()?;
    let result = exec.call(&args.contract_addr, &ledger.address,
                           &args.entrypoint, &call_args,
                           height, ts, ego_vm::types::DEFAULT_CALL_FUEL)
        .map_err(|e| EgoDesktopError::WalletError(e.to_string()))?;

    if result.success {
        let state_path = contracts_dir()
            .join("contracts")
            .join(&args.contract_addr)
            .join("state.json");
        if let Ok(state_json) = std::fs::read_to_string(&state_path) {
            crate::chain_db::save_contract_state(&args.contract_addr, &state_json);
        }

        if !result.events.is_empty() {
            let events_path = contracts_dir()
                .join("contracts")
                .join(&args.contract_addr)
                .join("events.json");
            let mut stored: Vec<StoredEvent> = std::fs::read_to_string(&events_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            for ev in &result.events {
                stored.push(StoredEvent {
                    topic:        ev.topic.clone(),
                    payload_hex:  hex::encode(&ev.payload),
                    timestamp:    ev.timestamp,
                    block_height: ev.height,
                    entrypoint:   args.entrypoint.clone(),
                });
            }
            if stored.len() > 500 {
                let drop = stored.len() - 500;
                stored.drain(0..drop);
            }
            let _ = std::fs::write(
                &events_path,
                serde_json::to_string_pretty(&stored).unwrap_or_default(),
            );
        }

        let nonce   = chain.last_nonce(&ledger.address) + 1;
        let tx_data = format!("call:{}:{}:{}:{}", ledger.address,
                              args.contract_addr, args.entrypoint, nonce);
        let tx_hash = hex::encode(ego_core::hash_data(tx_data.as_bytes()).as_bytes());

        let _ = (tx_data, tx_hash, ts, nonce);
    }

    let mut ledger = Ledger::load();
    let fee = crate::tokenomics::CALL_FEE_BASE_UEGOC;
    sign_and_queue_contract_tx(
        &state, &mut ledger, "call",
        &args.contract_addr, &args.entrypoint, &args.args_hex, "", "", fee,
    )?;

    Ok(result)
}

#[tauri::command]
pub async fn get_contract_state(
    contract_addr: String,
    prefix: String,
    key: String,
) -> Result<Option<String>, EgoDesktopError> {
    if !contract_addr.starts_with("egot1") || contract_addr.len() > 100 {
        return Err(EgoDesktopError::WalletError("Invalid contract address".into()));
    }
    let exec = vm()?;

    let state_path = contracts_dir()
        .join("contracts")
        .join(&contract_addr)
        .join("state.json");
    if !state_path.exists() {
        if let Some(json) = crate::chain_db::load_contract_state(&contract_addr) {
            let _ = std::fs::create_dir_all(state_path.parent().unwrap());
            let _ = std::fs::write(&state_path, &json);
        }
    }

    let state = exec.store.load_state(&contract_addr);
    let val   = state.get(&prefix, &key).map(hex::encode);
    Ok(val)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContractInfo {
    pub address:     String,
    pub name:        String,
    pub deployer:    String,
    pub deployed_at: i64,
    pub code_hash:   String,

    pub abi:         Vec<String>,
}

#[tauri::command]
pub async fn list_deployed_contracts() -> Result<Vec<ContractInfo>, EgoDesktopError> {
    let contracts_path = contracts_dir().join("contracts");
    if !contracts_path.exists() { return Ok(vec![]); }

    let exec = vm()?;
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&contracts_path) {
        for entry in entries.flatten() {
            let addr = entry.file_name().to_string_lossy().to_string();
            if let Some(manifest) = exec.store.load_manifest(&addr) {
                let abi_path = contracts_dir()
                    .join("contracts")
                    .join(&addr)
                    .join("abi.json");
                let abi: Vec<String> = std::fs::read_to_string(&abi_path)
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_default();
                out.push(ContractInfo {
                    address:     addr,
                    name:        manifest.name,
                    deployer:    manifest.deployer,
                    deployed_at: manifest.deployed_at,
                    code_hash:   manifest.code_hash,
                    abi,
                });
            }
        }
    }
    Ok(out)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StoredEvent {
    pub topic:        String,
    pub payload_hex:  String,
    pub timestamp:    i64,
    pub block_height: u64,
    pub entrypoint:   String,
}

#[tauri::command]
pub async fn get_contract_events(
    contract_addr: String,
    limit: u32,
) -> Result<Vec<StoredEvent>, EgoDesktopError> {
    if !contract_addr.starts_with("egot1") || contract_addr.len() > 100 {
        return Err(EgoDesktopError::WalletError("Invalid contract address".into()));
    }
    let events_path = contracts_dir()
        .join("contracts")
        .join(&contract_addr)
        .join("events.json");
    let mut events: Vec<StoredEvent> = std::fs::read_to_string(&events_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    events.reverse();
    if limit > 0 {
        events.truncate(limit as usize);
    }
    Ok(events)
}
