use crate::app::AppState;
use crate::error::EgoDesktopError;
use crate::ledger::{contract_commit_memo, contracts_dir, tx_signing_bytes_v2, Ledger, LedgerTx};
use ego_vm::{CallResult, VmError};
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
    let kp = state.get_keypair().ok_or_else(|| {
        EgoDesktopError::WalletError("Wallet not initialized - call init_wallet first".into())
    })?;
    let tx = build_contract_tx(
        &kp, &from, nonce, chrono::Utc::now().timestamp(),
        tx_type, contract_addr, entrypoint, args_hex, wasm_hex, code_hash, fee,
    );

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

pub(crate) fn build_contract_tx(
    kp: &ego_core::KeyPair,
    from: &str,
    nonce: u64,
    ts: i64,
    tx_type: &str,
    contract_addr: &str,
    entrypoint: &str,
    args_hex: &str,
    wasm_hex: &str,
    code_hash: &str,
    fee: u64,
) -> LedgerTx {
    let memo = contract_commit_memo(tx_type, entrypoint, args_hex, code_hash);
    let sign_bytes = tx_signing_bytes_v2(from, contract_addr, 0, nonce, ts, CHAIN_ID, &memo);
    let ed_sig  = kp.sign_ed25519(&sign_bytes);
    let dil_sig = kp.sign_dilithium(&sign_bytes);

    LedgerTx {
        hash: format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex()),
        from: from.to_string(),
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
    }
}

fn err(msg: impl Into<String>) -> EgoDesktopError {
    EgoDesktopError::WalletError(msg.into())
}

fn is_contract_address(addr: &str) -> bool {
    (addr.len() == 40 && addr.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        || (addr.starts_with("egot1") && addr.len() <= 100)
}

fn check_address(addr: &str) -> Result<(), EgoDesktopError> {
    if is_contract_address(addr) {
        Ok(())
    } else {
        Err(err("That is not a contract address. Contract addresses are 40 characters of 0-9 and a-f."))
    }
}

fn check_entrypoint(entrypoint: &str) -> Result<(), EgoDesktopError> {
    if entrypoint.is_empty()
        || entrypoint.len() > 64
        || !entrypoint.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(err("Invalid function name"));
    }
    Ok(())
}

fn normalized_hex(raw: &str, what: &str) -> Result<(String, Vec<u8>), EgoDesktopError> {
    let hex_str = raw.trim().trim_start_matches("0x").to_ascii_lowercase();
    let bytes = hex::decode(&hex_str).map_err(|_| err(format!("{what} must be hex")))?;
    Ok((hex_str, bytes))
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, EgoDesktopError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| err(format!("the contract engine stopped unexpectedly: {e}")))
}

const NOT_LIVE_YET: &str =
    "There is no contract at that address on this node yet. A new deploy goes live once its block is final, usually within a minute.";

#[derive(Debug, Serialize, Deserialize, Default)]
struct Label {
    #[serde(default)]
    name: String,
    #[serde(default)]
    abi: Vec<String>,
}

fn label_path(addr: &str) -> std::path::PathBuf {
    contracts_dir().join("labels").join(format!("{addr}.json"))
}

fn load_label(addr: &str) -> Label {
    if let Some(label) = std::fs::read_to_string(label_path(addr))
        .ok()
        .and_then(|s| serde_json::from_str::<Label>(&s).ok())
    {
        return label;
    }
    let old = contracts_dir().join("contracts").join(addr);
    let abi = std::fs::read_to_string(old.join("abi.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let name = std::fs::read_to_string(old.join("manifest.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v["name"].as_str().map(str::to_string))
        .filter(|n| !n.starts_with("contract_"))
        .unwrap_or_default();
    Label { name, abi }
}

fn save_label(addr: &str, label: &Label) {
    let path = label_path(addr);
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(path, serde_json::to_string_pretty(label).unwrap_or_default());
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

#[derive(Debug, Serialize, Deserialize)]
pub struct DeployContractArgs {

    pub wasm_hex: String,

    pub init_args_hex: String,

    #[serde(default)]
    pub name: String,

    #[serde(default)]
    pub abi: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DeployPreview {
    pub contract_address: String,
    pub code_hash: String,
    pub ru_used: u64,
    pub already_deployed: bool,
}

#[derive(Debug, Serialize)]
pub struct DeploySubmitted {
    pub contract_address: String,
    pub code_hash: String,
    pub ru_used: u64,
    pub tx_hash: String,
    pub status: &'static str,
}

async fn preview_deploy_for(address: String, wasm_hex: &str, init_args_hex: &str)
    -> Result<ego_vm::DeployEffects, EgoDesktopError>
{
    let (_, wasm) = normalized_hex(wasm_hex, "The contract code")?;
    let (_, init_args) = normalized_hex(init_args_hex, "Init arguments")?;
    blocking(move || crate::contract_exec::preview_deploy(&wasm, &address, &init_args))
        .await?
        .map_err(|e| err(format!("init() failed, so nothing was sent: {e}")))
}

#[tauri::command]
pub async fn preview_contract_deploy(args: DeployContractArgs) -> Result<DeployPreview, EgoDesktopError> {
    let ledger = Ledger::load();
    if ledger.address.is_empty() {
        return Err(err("No wallet"));
    }
    let fx = preview_deploy_for(ledger.address, &args.wasm_hex, &args.init_args_hex).await?;
    Ok(DeployPreview {
        contract_address: fx.result.contract_address,
        code_hash: fx.result.code_hash,
        ru_used: fx.result.ru_used,
        already_deployed: fx.existed,
    })
}

#[tauri::command]
pub async fn deploy_contract(
    state: State<'_, AppState>,
    args: DeployContractArgs,
) -> Result<DeploySubmitted, EgoDesktopError> {
    let mut ledger = Ledger::load();
    if ledger.address.is_empty() {
        return Err(err("No wallet"));
    }

    let (init_args_hex, _) = normalized_hex(&args.init_args_hex, "Init arguments")?;
    let fx = preview_deploy_for(ledger.address.clone(), &args.wasm_hex, &init_args_hex).await?;
    let addr = fx.result.contract_address.clone();
    if fx.existed {
        return Err(err(format!("You already deployed this exact contract. It is live at {addr}.")));
    }

    let is_staker  = ledger.staked_amount > 0;
    let deploy_fee = crate::tokenomics::deploy_fee_with_staking(is_staker)
        .max(crate::tokenomics::FEE_FLOOR_UEGOC);
    let bal = crate::chain_db::balance_of(&ledger.address);
    if deploy_fee > bal {
        return Err(err(format!(
            "Insufficient balance for deploy fee: need {} uEGOC, have {}",
            deploy_fee, bal
        )));
    }

    save_label(&addr, &Label { name: args.name.clone(), abi: args.abi.clone() });

    let tx = sign_and_queue_contract_tx(
        &state, &mut ledger, "deploy",
        &addr, "init", &init_args_hex,
        &hex::encode(&fx.code), &fx.result.code_hash, deploy_fee,
    )?;

    Ok(DeploySubmitted {
        contract_address: addr,
        code_hash: fx.result.code_hash,
        ru_used: fx.result.ru_used,
        tx_hash: tx.hash,
        status: "pending",
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CallContractArgs {
    pub contract_addr: String,
    pub entrypoint:    String,
    pub args_hex:      String,
}

#[derive(Debug, Serialize)]
pub struct CallSubmitted {
    #[serde(flatten)]
    pub result: CallResult,
    pub tx_hash: String,
    pub status: &'static str,
}

async fn preview_call_for(caller: String, args: &CallContractArgs)
    -> Result<(String, ego_vm::CallEffects), EgoDesktopError>
{
    check_address(&args.contract_addr)?;
    check_entrypoint(&args.entrypoint)?;
    let (args_hex, call_args) = normalized_hex(&args.args_hex, "Arguments")?;
    let addr = args.contract_addr.clone();
    let entrypoint = args.entrypoint.clone();
    let fx = blocking(move || crate::contract_exec::preview_call(&addr, &caller, &entrypoint, &call_args))
        .await?
        .map_err(|e| match e {
            VmError::StorageError(_) => err(NOT_LIVE_YET),
            other => err(other.to_string()),
        })?;
    Ok((args_hex, fx))
}

#[tauri::command]
pub async fn call_contract(
    state: State<'_, AppState>,
    args: CallContractArgs,
) -> Result<CallSubmitted, EgoDesktopError> {
    let mut ledger = Ledger::load();
    if ledger.address.is_empty() {
        return Err(err("No wallet"));
    }

    let (args_hex, fx) = preview_call_for(ledger.address.clone(), &args).await?;
    if !fx.result.success {
        return Err(err(format!(
            "This call would fail, so it was not sent: {}",
            fx.result.error.unwrap_or_else(|| "unknown error".into())
        )));
    }

    let fee = crate::tokenomics::CALL_FEE_BASE_UEGOC;
    let tx = sign_and_queue_contract_tx(
        &state, &mut ledger, "call",
        &args.contract_addr, &args.entrypoint, &args_hex, "", "", fee,
    )?;

    Ok(CallSubmitted { result: fx.result, tx_hash: tx.hash, status: "pending" })
}

#[tauri::command]
pub async fn query_contract(args: CallContractArgs) -> Result<CallResult, EgoDesktopError> {
    let caller = Ledger::load().address;
    let (_, fx) = preview_call_for(caller, &args).await?;
    Ok(fx.result)
}

#[tauri::command]
pub async fn get_contract_state(
    contract_addr: String,
    prefix: String,
    key: String,
) -> Result<Option<String>, EgoDesktopError> {
    check_address(&contract_addr)?;
    let state = blocking(move || crate::contract_exec::state(&contract_addr))
        .await?
        .ok_or_else(|| err(NOT_LIVE_YET))?;
    Ok(state.get(&prefix, &key).map(hex::encode))
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

fn contract_info(addr: String, manifest: ego_vm::ContractManifest) -> ContractInfo {
    let label = load_label(&addr);
    let abi = if label.abi.is_empty() {
        crate::contract_exec::code(&addr)
            .and_then(|code| ego_vm::exported_functions(&code).ok())
            .unwrap_or_default()
    } else {
        label.abi
    };
    ContractInfo {
        name: if label.name.is_empty() { manifest.name } else { label.name },
        address: addr,
        deployer: manifest.deployer,
        deployed_at: manifest.deployed_at,
        code_hash: manifest.code_hash,
        abi,
    }
}

#[tauri::command]
pub async fn get_contract(contract_addr: String) -> Result<Option<ContractInfo>, EgoDesktopError> {
    check_address(&contract_addr)?;
    blocking(move || {
        crate::contract_exec::manifest(&contract_addr).map(|m| contract_info(contract_addr, m))
    })
    .await
}

#[tauri::command]
pub async fn list_deployed_contracts() -> Result<Vec<ContractInfo>, EgoDesktopError> {
    let me = Ledger::load().address;
    blocking(move || {
        let mut out: Vec<ContractInfo> = crate::contract_exec::list(500)
            .into_iter()
            .map(|(addr, m)| contract_info(addr, m))
            .collect();
        out.sort_by(|a, b| (b.deployer == me, b.deployed_at).cmp(&(a.deployer == me, a.deployed_at)));
        out
    })
    .await
}

#[tauri::command]
pub async fn get_contract_activity(
    contract_addr: String,
    limit: u32,
) -> Result<Vec<crate::contract_exec::ActivityEntry>, EgoDesktopError> {
    check_address(&contract_addr)?;
    let limit = if limit == 0 { 100 } else { limit.min(1_000) } as usize;
    blocking(move || crate::contract_exec::activity(&contract_addr, limit)).await
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
    check_address(&contract_addr)?;
    let limit = if limit == 0 { 500 } else { limit.min(1_000) } as usize;
    blocking(move || {
        crate::contract_exec::activity(&contract_addr, limit)
            .into_iter()
            .filter(|a| a.ok)
            .flat_map(|a| {
                let (ts, h, ep) = (a.timestamp, a.height, a.entrypoint.clone());
                a.events.into_iter().rev().map(move |e| StoredEvent {
                    topic: e.topic,
                    payload_hex: e.payload_hex,
                    timestamp: ts,
                    block_height: h,
                    entrypoint: ep.clone(),
                })
            })
            .take(limit)
            .collect()
    })
    .await
}

#[cfg(test)]
mod live_two_node {
    use super::*;
    use serde_json::{json, Value};
    use std::future::Future;
    use std::pin::Pin;

    const GUESTBOOK: &str = r#"contract Guestbook {
        pub fn init() {
            storage.set("entries", 0);
        }
        pub fn sign(message: String) {
            let n: u64 = storage.get_u64("entries");
            storage.set("entries", n + 1);
            events.emit("signed", n + 1);
        }
        pub fn entries() -> u64 {
            return storage.get_u64("entries");
        }
    }"#;

    fn node(var: &str) -> String {
        std::env::var(var)
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| panic!("set {var} to a node's RPC url, e.g. http://127.0.0.1:47498"))
    }

    fn address_of(kp: &ego_core::KeyPair) -> String {
        ego_core::EgoAddress::from_public_key_bytes(
            &kp.ed25519_public_key().key_data,
            CHAIN_ID as u32,
            ego_core::AddressType::EOA,
        )
        .to_bech32("egot")
        .unwrap()
    }

    async fn rpc(client: &reqwest::Client, url: &str, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let resp: Value = client
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        match resp.get("error") {
            Some(e) if !e.is_null() => Err(e.to_string()),
            _ => Ok(resp["result"].clone()),
        }
    }

    type Check<'a> = Box<dyn FnMut() -> Pin<Box<dyn Future<Output = bool> + 'a>> + 'a>;

    async fn wait_until(what: &str, secs: u64, mut ready: Check<'_>) {
        let start = std::time::Instant::now();
        loop {
            if ready().await {
                eprintln!("[live] {what}: yes after {}s", start.elapsed().as_secs());
                return;
            }
            if start.elapsed().as_secs() > secs {
                panic!("[live] gave up waiting for: {what}");
            }
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
    }

    async fn funded(client: &reqwest::Client, url: &str, addr: &str, secs: u64) -> bool {
        let asked: Value = match client.get(format!("{url}/faucet?to={addr}&amount=5")).send().await {
            Ok(r) => r.json().await.unwrap_or(Value::Null),
            Err(_) => Value::Null,
        };
        eprintln!("[live] faucet on {url} for {addr}: {asked}");
        let start = std::time::Instant::now();
        while start.elapsed().as_secs() < secs {
            let bal = rpc(client, url, "wallet.getBalance", json!({ "address": addr })).await
                .map(|r| r["uegoc"].as_u64().unwrap_or(0))
                .unwrap_or(0);
            if bal >= 2_000_000 {
                eprintln!("[live] {addr} funded after {}s", start.elapsed().as_secs());
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
        eprintln!("[live] {addr} not funded within {secs}s");
        false
    }

    async fn next_nonce(client: &reqwest::Client, url: &str, addr: &str) -> u64 {
        rpc(client, url, "wallet.getNonce", json!({ "address": addr })).await.unwrap()["next"]
            .as_u64()
            .unwrap_or(1)
    }

    fn balance_at_least<'a>(client: &'a reqwest::Client, url: String, addr: String, min: u64) -> Check<'a> {
        Box::new(move || {
            let (url, addr) = (url.clone(), addr.clone());
            Box::pin(async move {
                rpc(client, &url, "wallet.getBalance", json!({ "address": addr })).await
                    .map(|r| r["uegoc"].as_u64().unwrap_or(0) >= min)
                    .unwrap_or(false)
            })
        })
    }

    fn contract_listed<'a>(client: &'a reqwest::Client, url: String, contract: String) -> Check<'a> {
        Box::new(move || {
            let (url, contract) = (url.clone(), contract.clone());
            Box::pin(async move {
                rpc(client, &url, "contract.listDeployed", json!({})).await
                    .map(|r| r.as_array().map(|l| l.iter().any(|c| c["address"] == contract.as_str())).unwrap_or(false))
                    .unwrap_or(false)
            })
        })
    }

    fn signed_with<'a>(client: &'a reqwest::Client, url: String, contract: String, args_hex: String) -> Check<'a> {
        Box::new(move || {
            let (url, contract, args_hex) = (url.clone(), contract.clone(), args_hex.clone());
            Box::pin(async move {
                rpc(client, &url, "contract.getActivity", json!({ "contractAddr": contract, "limit": 10 })).await
                    .map(|r| r.as_array().map(|l| l.iter().any(|e| {
                        e["entrypoint"] == "sign" && e["ok"] == true && e["args_hex"] == args_hex.as_str()
                    })).unwrap_or(false))
                    .unwrap_or(false)
            })
        })
    }

    #[test]
    #[ignore]
    fn a_contract_deployed_on_one_node_is_used_from_another() {
        let a = node("EGO_LIVE_A");
        let b = node("EGO_LIVE_B");
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let client = reqwest::Client::new();
            let first = ego_core::KeyPair::generate();
            let second = ego_core::KeyPair::generate();
            let first_addr = address_of(&first);
            let second_addr = address_of(&second);
            let first_ok = funded(&client, &a, &first_addr, 300).await;
            let second_ok = funded(&client, &b, &second_addr, 300).await;
            let ((alice, alice_addr), (bob, bob_addr)) = match (first_ok, second_ok) {
                (true, true) => ((&first, first_addr.clone()), (&second, second_addr.clone())),
                (true, false) => ((&first, first_addr.clone()), (&first, first_addr.clone())),
                (false, true) => ((&second, second_addr.clone()), (&second, second_addr.clone())),
                (false, false) => panic!("[live] neither test identity could be funded"),
            };
            eprintln!("[live] deployer {alice_addr} submits through {a}");
            eprintln!("[live] caller   {bob_addr} submits through {b}");
            for (url, addr) in [(&a, &alice_addr), (&b, &bob_addr)] {
                wait_until(
                    &format!("{url} sees the coins of {addr}"),
                    300,
                    balance_at_least(&client, url.clone(), addr.clone(), 2_000_000),
                ).await;
            }

            let wasm = urego_compiler::compile(GUESTBOOK).unwrap();
            let (contract, code_hash) = ego_vm::contract_address_for(&alice_addr, &wasm);
            let deploy = build_contract_tx(
                &alice, &alice_addr, next_nonce(&client, &a, &alice_addr).await,
                chrono::Utc::now().timestamp(), "deploy", &contract, "init", "",
                &hex::encode(&wasm), &code_hash, crate::tokenomics::deploy_fee_with_staking(false),
            );
            let sent = rpc(&client, &a, "tx.submit", json!({ "tx": deploy })).await.expect("deploy accepted");
            eprintln!("[live] deploy {} sent to A for contract {contract}", sent["tx_hash"]);

            for url in [&a, &b] {
                wait_until(
                    &format!("{url} runs the deploy"),
                    900,
                    contract_listed(&client, url.clone(), contract.clone()),
                ).await;
            }

            let message = format!("hello from node B at {}", chrono::Utc::now().to_rfc3339());
            let args_hex = hex::encode(message.as_bytes());
            let call = build_contract_tx(
                &bob, &bob_addr, next_nonce(&client, &b, &bob_addr).await,
                chrono::Utc::now().timestamp(), "call", &contract, "sign",
                &args_hex, "", "", crate::tokenomics::CALL_FEE_BASE_UEGOC,
            );
            let sent = rpc(&client, &b, "tx.submit", json!({ "tx": call })).await.expect("call accepted");
            eprintln!("[live] sign() {} sent to B", sent["tx_hash"]);

            for url in [&a, &b] {
                wait_until(
                    &format!("{url} runs B's sign()"),
                    900,
                    signed_with(&client, url.clone(), contract.clone(), args_hex.clone()),
                ).await;
            }

            let mut seen = Vec::new();
            for url in [&a, &b] {
                let state = rpc(&client, url, "contract.getState",
                    json!({ "contractAddr": contract, "prefix": "", "key": "entries" })).await.unwrap();
                let activity = rpc(&client, url, "contract.getActivity",
                    json!({ "contractAddr": contract, "limit": 10 })).await.unwrap();
                eprintln!("[live] {url}: entries = {}, activity = {activity}", state["value"]);
                assert_eq!(state["value"], hex::encode(1u64.to_le_bytes()).as_str());
                seen.push(activity);
            }
            assert_eq!(seen[0], seen[1], "both nodes must hold the same record of what ran");
            eprintln!("[live] both nodes agree: deployed on A, signed from B, one entry, identical activity");
        });
    }
}
