//! Urego smart contract commands — deploy, call, query state.

use crate::error::EgoDesktopError;
use crate::ledger::{contracts_dir, load_chain, save_chain, Ledger, LedgerTx};
use ego_vm::{CallResult, DeployResult, Executor};
use serde::{Deserialize, Serialize};

fn vm() -> Result<Executor, EgoDesktopError> {
    Executor::new(contracts_dir())
        .map_err(|e| EgoDesktopError::WalletError(e.to_string()))
}

// ── deploy_contract ───────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct DeployContractArgs {
    /// Hex-encoded WASM bytecode.
    pub wasm_hex: String,
    /// Hex-encoded ABI-encoded init() arguments (empty = "").
    pub init_args_hex: String,
}

#[tauri::command]
pub async fn deploy_contract(args: DeployContractArgs) -> Result<DeployResult, EgoDesktopError> {
    let ledger = Ledger::load();
    if ledger.address.is_empty() {
        return Err(EgoDesktopError::WalletError("No wallet".into()));
    }

    let wasm_bytes = hex::decode(&args.wasm_hex)
        .map_err(|e| EgoDesktopError::WalletError(format!("Invalid wasm hex: {e}")))?;
    let init_args = hex::decode(&args.init_args_hex).unwrap_or_default();

    let chain  = load_chain();
    let height = chain.blocks.last().map(|b| b.height).unwrap_or(0);
    let ts     = chrono::Utc::now().timestamp();

    let exec   = vm()?;
    let result = exec.deploy(&wasm_bytes, &ledger.address, &init_args, height, ts,
                             ego_vm::types::DEFAULT_DEPLOY_FUEL)
        .map_err(|e| EgoDesktopError::WalletError(e.to_string()))?;

    // Build a Deploy TX and broadcast it so all nodes replicate the contract
    let mut chain2 = load_chain();
    let nonce      = chain2.last_nonce(&ledger.address) + 1;
    let tx_data    = format!("deploy:{}:{}:{}", ledger.address, result.contract_address, nonce);
    let tx_hash    = hex::encode(ego_core::hash_data(tx_data.as_bytes()).as_bytes());

    let tx = LedgerTx {
        hash:          tx_hash,
        from:          ledger.address.clone(),
        to:            result.contract_address.clone(),
        amount:        0,
        memo:          Some(format!("deploy:{}", result.code_hash)),
        timestamp:     ts,
        status:        "Confirmed".to_string(),
        nonce,
        tx_type:       "deploy".to_string(),
        wasm_code:     args.wasm_hex.clone(),
        contract_addr: result.contract_address.clone(),
        entrypoint:    "init".to_string(),
        call_args:     args.init_args_hex.clone(),
        ..LedgerTx::default()
    };

    chain2.transactions.push(tx.clone());
    let _ = save_chain(&chain2);

    // Broadcast to peers
    if let Some(block) = chain2.blocks.last().cloned() {
        tokio::spawn(async move {
            crate::p2p::push_tx_to_relay(&tx, &block).await;
        });
    }

    Ok(result)
}

// ── call_contract ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct CallContractArgs {
    pub contract_addr: String,
    pub entrypoint:    String,
    pub args_hex:      String,
}

#[tauri::command]
pub async fn call_contract(args: CallContractArgs) -> Result<CallResult, EgoDesktopError> {
    let ledger = Ledger::load();
    if ledger.address.is_empty() {
        return Err(EgoDesktopError::WalletError("No wallet".into()));
    }

    let call_args = hex::decode(&args.args_hex).unwrap_or_default();
    let chain     = load_chain();
    let height    = chain.blocks.last().map(|b| b.height).unwrap_or(0);
    let ts        = chrono::Utc::now().timestamp();

    let exec   = vm()?;
    let result = exec.call(&args.contract_addr, &ledger.address,
                           &args.entrypoint, &call_args,
                           height, ts, ego_vm::types::DEFAULT_CALL_FUEL)
        .map_err(|e| EgoDesktopError::WalletError(e.to_string()))?;

    if result.success {
        // Build a Call TX and broadcast it
        let mut chain2 = load_chain();
        let nonce      = chain2.last_nonce(&ledger.address) + 1;
        let tx_data    = format!("call:{}:{}:{}:{}", ledger.address,
                                 args.contract_addr, args.entrypoint, nonce);
        let tx_hash    = hex::encode(ego_core::hash_data(tx_data.as_bytes()).as_bytes());

        let tx = LedgerTx {
            hash:          tx_hash,
            from:          ledger.address.clone(),
            to:            args.contract_addr.clone(),
            amount:        0,
            memo:          Some(format!("call:{}", args.entrypoint)),
            timestamp:     ts,
            status:        "Confirmed".to_string(),
            nonce,
            tx_type:       "call".to_string(),
            contract_addr: args.contract_addr.clone(),
            entrypoint:    args.entrypoint.clone(),
            call_args:     args.args_hex.clone(),
            ..LedgerTx::default()
        };

        chain2.transactions.push(tx.clone());
        let _ = save_chain(&chain2);

        if let Some(block) = chain2.blocks.last().cloned() {
            tokio::spawn(async move {
                crate::p2p::push_tx_to_relay(&tx, &block).await;
            });
        }
    }

    Ok(result)
}

// ── get_contract_state ────────────────────────────────────────────────────────

#[tauri::command]
pub async fn get_contract_state(
    contract_addr: String,
    prefix: String,
    key: String,
) -> Result<Option<String>, EgoDesktopError> {
    let exec  = vm()?;
    let state = exec.store.load_state(&contract_addr);
    let val   = state.get(&prefix, &key).map(hex::encode);
    Ok(val)
}

// ── list_deployed_contracts ───────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct ContractInfo {
    pub address:     String,
    pub name:        String,
    pub deployer:    String,
    pub deployed_at: i64,
    pub code_hash:   String,
}

#[tauri::command]
pub async fn list_deployed_contracts() -> Result<Vec<ContractInfo>, EgoDesktopError> {
    let contracts_path = contracts_dir().join("contracts");
    if !contracts_path.exists() { return Ok(vec![]); }

    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&contracts_path) {
        for entry in entries.flatten() {
            let addr = entry.file_name().to_string_lossy().to_string();
            let exec = vm()?;
            if let Some(manifest) = exec.store.load_manifest(&addr) {
                out.push(ContractInfo {
                    address:     addr,
                    name:        manifest.name,
                    deployer:    manifest.deployer,
                    deployed_at: manifest.deployed_at,
                    code_hash:   manifest.code_hash,
                });
            }
        }
    }
    Ok(out)
}
