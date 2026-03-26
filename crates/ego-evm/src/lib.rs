use anyhow::{anyhow, Result};
use revm::{
    primitives::{
        Account, AccountInfo, Address, Bytecode, CfgEnv, CreateScheme, Env, ExecutionResult,
        Output, TransactTo, TxEnv, B256, U256,
    },
    Database, DatabaseCommit, Evm,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const EGO_CHAIN_ID: u64 = 1399;

pub const GAS_TO_RU_RATIO: u64 = 10;

pub const MAX_GAS_PER_BLOCK: u64 = 1_000_000;

pub const UEGOC_TO_WEI: u128 = 10_000_000_000;

#[inline]
pub fn gas_to_ru(gas: u64) -> u64 {
    gas * GAS_TO_RU_RATIO
}

#[inline]
pub fn ru_to_gas(ru: u64) -> u64 {
    ru / GAS_TO_RU_RATIO
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmLog {

    pub address: [u8; 20],

    pub topics: Vec<[u8; 32]>,

    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmResult {

    pub success: bool,

    pub output: Vec<u8>,

    pub gas_used: u64,

    pub ru_used: u64,

    pub logs: Vec<EvmLog>,

    pub deployed_address: Option<[u8; 20]>,
}

#[derive(Debug, Clone, Default)]
struct EvmAccount {
    balance_wei: U256,
    nonce: u64,
    code: Option<Bytecode>,
    code_hash: B256,
    storage: HashMap<U256, U256>,
}

pub struct EgoEvmState {

    accounts: HashMap<[u8; 20], EvmAccount>,

    storage_writes: Vec<(Address, U256, U256)>,
}

impl EgoEvmState {

    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
            storage_writes: Vec::new(),
        }
    }

    pub fn set_balance_uegoc(&mut self, address: [u8; 20], uegoc: u128) {
        let acc = self.accounts.entry(address).or_default();
        acc.balance_wei = U256::from(uegoc) * U256::from(UEGOC_TO_WEI);
    }

    pub fn set_nonce(&mut self, address: [u8; 20], nonce: u64) {
        self.accounts.entry(address).or_default().nonce = nonce;
    }

    pub fn set_code(&mut self, address: [u8; 20], bytecode: Vec<u8>) {
        let code = Bytecode::new_raw(bytecode.into());
        let code_hash = code.hash_slow();
        let acc = self.accounts.entry(address).or_default();
        acc.code_hash = code_hash;
        acc.code = Some(code);
    }

    pub fn get_storage(&self, address: [u8; 20], slot: U256) -> U256 {
        self.accounts
            .get(&address)
            .and_then(|a| a.storage.get(&slot))
            .copied()
            .unwrap_or(U256::ZERO)
    }

    pub fn drain_writes(&mut self) -> Vec<(Address, U256, U256)> {
        std::mem::take(&mut self.storage_writes)
    }
}

impl Default for EgoEvmState {
    fn default() -> Self {
        Self::new()
    }
}

impl Database for EgoEvmState {
    type Error = anyhow::Error;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let raw: [u8; 20] = address.into();
        let acc = self.accounts.get(&raw);
        Ok(acc.map(|a| AccountInfo {
            balance: a.balance_wei,
            nonce: a.nonce,
            code_hash: a.code_hash,
            code: a.code.clone(),
        }))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {

        for acc in self.accounts.values() {
            if acc.code_hash == code_hash {
                if let Some(code) = &acc.code {
                    return Ok(code.clone());
                }
            }
        }

        Ok(Bytecode::new())
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let raw: [u8; 20] = address.into();
        let value = self
            .accounts
            .get(&raw)
            .and_then(|a| a.storage.get(&index))
            .copied()
            .unwrap_or(U256::ZERO);
        Ok(value)
    }

    fn block_hash(&mut self, _number: U256) -> Result<B256, Self::Error> {
        Ok(B256::ZERO)
    }
}

impl DatabaseCommit for EgoEvmState {
    fn commit(&mut self, changes: std::collections::HashMap<Address, Account>) {
        for (addr, account) in changes {
            let raw: [u8; 20] = addr.into();
            if account.is_selfdestructed() {
                self.accounts.remove(&raw);
                continue;
            }
            let entry = self.accounts.entry(raw).or_default();
            entry.balance_wei = account.info.balance;
            entry.nonce = account.info.nonce;
            entry.code_hash = account.info.code_hash;
            if let Some(code) = account.info.code {
                entry.code = Some(code);
            }
            for (slot, storage_slot) in account.storage {
                entry.storage.insert(slot, storage_slot.present_value());
            }
        }
    }
}

pub struct EgoEvm;

impl EgoEvm {

    pub fn execute(
        state: &mut EgoEvmState,
        caller: [u8; 20],
        to: Option<[u8; 20]>,
        value: u128,
        data: Vec<u8>,
        gas_limit: u64,
        chain_id: u64,
    ) -> Result<EvmResult> {

        let gas_limit = gas_limit.min(MAX_GAS_PER_BLOCK);

        let value_wei = U256::from(value) * U256::from(UEGOC_TO_WEI);

        let transact_to = match to {
            Some(addr) => TransactTo::Call(Address::from(addr)),
            None => TransactTo::Create(CreateScheme::Create),
        };

        let mut env = Env::default();

        env.cfg = CfgEnv::default();
        env.cfg.chain_id = chain_id;

        env.cfg.disable_balance_check = true;

        env.block.basefee = U256::ZERO;

        env.tx = TxEnv {
            caller: Address::from(caller),
            gas_limit,
            gas_price: U256::ZERO,
            transact_to,
            value: value_wei,
            data: data.into(),
            nonce: None,
            chain_id: Some(chain_id),
            access_list: vec![],
            gas_priority_fee: None,
            blob_hashes: vec![],
            max_fee_per_blob_gas: None,
        };

        let mut evm = Evm::builder()
            .with_db(state)
            .with_env(Box::new(env))
            .build();

        let result = evm.transact_commit().map_err(|e| anyhow!("EVM execution error: {:?}", e))?;

        let (success, gas_used, output_bytes, logs_raw, deployed_address) = match result {
            ExecutionResult::Success {
                gas_used,
                output,
                logs,
                ..
            } => {
                let (out_bytes, deployed) = match output {
                    Output::Call(bytes) => (bytes.to_vec(), None),
                    Output::Create(bytes, maybe_addr) => (
                        bytes.to_vec(),
                        maybe_addr.map(|a| <[u8; 20]>::from(a)),
                    ),
                };
                (true, gas_used, out_bytes, logs, deployed)
            }
            ExecutionResult::Revert { gas_used, output } => {
                (false, gas_used, output.to_vec(), vec![], None)
            }
            ExecutionResult::Halt { gas_used, .. } => (false, gas_used, vec![], vec![], None),
        };

        let logs: Vec<EvmLog> = logs_raw
            .into_iter()
            .map(|log| EvmLog {
                address: <[u8; 20]>::from(log.address),
                topics: log
                    .data
                    .topics()
                    .iter()
                    .map(|t| t.0)
                    .collect(),
                data: log.data.data.to_vec(),
            })
            .collect();

        Ok(EvmResult {
            success,
            output: output_bytes,
            gas_used,
            ru_used: gas_to_ru(gas_used),
            logs,
            deployed_address,
        })
    }
}

pub mod eth_rpc {
    use serde_json::{json, Value};

    pub fn eth_chain_id(chain_id: u64) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": format!("0x{:x}", chain_id)
        })
    }

    pub fn eth_get_balance_response(balance_wei: u128) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": format!("0x{:x}", balance_wei)
        })
    }

    pub fn net_version(chain_id: u64) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": chain_id.to_string()
        })
    }

    pub fn eth_block_number(block_height: u64) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": format!("0x{:x}", block_height)
        })
    }

    pub fn eth_estimate_gas(gas: u64) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": format!("0x{:x}", gas)
        })
    }

    pub fn eth_get_transaction_count(nonce: u64) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": format!("0x{:x}", nonce)
        })
    }

    pub fn eth_get_code(bytecode_hex: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": format!("0x{}", bytecode_hex)
        })
    }

    pub fn rpc_error(id: u64, code: i64, message: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": code,
                "message": message
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gas_ru_roundtrip() {
        assert_eq!(gas_to_ru(1_000), 10_000);
        assert_eq!(ru_to_gas(10_000), 1_000);

        assert_eq!(ru_to_gas(10_005), 1_000);
    }

    #[test]
    fn uegoc_to_wei_scaling() {

        let uegoc: u128 = 100_000_000;
        let wei = uegoc * UEGOC_TO_WEI;
        assert_eq!(wei, 1_000_000_000_000_000_000u128);
    }

    #[test]
    fn state_balance_roundtrip() {
        let mut state = EgoEvmState::new();
        let addr = [0xabu8; 20];
        state.set_balance_uegoc(addr, 100_000_000);
        let info = state.basic(Address::from(addr)).unwrap().unwrap();
        let expected = U256::from(100_000_000u128) * U256::from(UEGOC_TO_WEI);
        assert_eq!(info.balance, expected);
    }

    #[test]
    fn eth_rpc_chain_id() {
        let resp = eth_rpc::eth_chain_id(EGO_CHAIN_ID);
        assert_eq!(resp["result"], "0x577");
    }

    #[test]
    fn eth_rpc_balance() {

        let wei = 100_000_000u128 * UEGOC_TO_WEI;
        let resp = eth_rpc::eth_get_balance_response(wei);
        assert_eq!(resp["result"], "0xde0b6b3a7640000");
    }

    #[test]
    fn evm_deploy_simple_contract() {

        let runtime = hex::decode("604260005260206000f3").unwrap();

        let runtime_len = runtime.len() as u8;
        let mut initcode: Vec<u8> = vec![
            0x60, runtime_len,
            0x60, 0x0c,
            0x60, 0x00,
            0x39,
            0x60, runtime_len,
            0x60, 0x00,
            0xf3,
        ];
        initcode.extend_from_slice(&runtime);

        let mut state = EgoEvmState::new();
        let caller = [0x01u8; 20];
        state.set_balance_uegoc(caller, 1_000_000_000);
        state.set_nonce(caller, 0);

        let result = EgoEvm::execute(
            &mut state,
            caller,
            None,
            0,
            initcode,
            100_000,
            EGO_CHAIN_ID,
        )
        .expect("execute should not error");

        assert!(result.success, "deploy should succeed");
        assert!(
            result.deployed_address.is_some(),
            "deployed_address must be set"
        );
        assert!(result.ru_used > 0, "ru_used must be positive");
        assert_eq!(result.ru_used, gas_to_ru(result.gas_used));
    }

    #[test]
    fn evm_call_reverts() {

        let revert_code = hex::decode("6000600080fd").unwrap();

        let runtime_len = revert_code.len() as u8;
        let mut initcode: Vec<u8> = vec![
            0x60, runtime_len,
            0x60, 0x0c,
            0x60, 0x00,
            0x39,
            0x60, runtime_len,
            0x60, 0x00,
            0xf3,
        ];
        initcode.extend_from_slice(&revert_code);

        let mut state = EgoEvmState::new();
        let caller = [0x02u8; 20];
        state.set_balance_uegoc(caller, 1_000_000_000);

        let deploy = EgoEvm::execute(
            &mut state, caller, None, 0, initcode, 100_000, EGO_CHAIN_ID,
        )
        .unwrap();
        assert!(deploy.success);
        let contract_addr = deploy.deployed_address.unwrap();

        let call = EgoEvm::execute(
            &mut state,
            caller,
            Some(contract_addr),
            0,
            vec![],
            50_000,
            EGO_CHAIN_ID,
        )
        .unwrap();
        assert!(!call.success, "call to revert contract must fail");
    }
}
