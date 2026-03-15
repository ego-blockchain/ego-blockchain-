//! Ego EVM compatibility layer.
//! Wraps `revm` with an Ego state adapter so EVM bytecode runs on Ego.
//!
//! # Architecture
//!
//! - [`EgoEvmState`] implements `revm::Database` — bridges revm's account/storage
//!   queries to Ego's `StateManager`.
//! - [`EgoEvm`] is the entry point: call [`EgoEvm::execute`] to run any EVM
//!   transaction (deploy or call).
//! - [`EvmResult`] carries the execution outcome, logs, and RU cost.
//! - [`eth_rpc`] provides JSON shapes for MetaMask-compatible JSON-RPC responses.

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

// ─── constants ──────────────────────────────────────────────────────────────

/// EVM chain ID for Ego testnet.
pub const EGO_CHAIN_ID: u64 = 1399; // 0x577

/// `1 EVM gas = 10 Ego RU`  (per EGO-12 §4)
pub const GAS_TO_RU_RATIO: u64 = 10;

/// `MAX_RU_PER_BLOCK / GAS_TO_RU_RATIO` — hard gas cap per block.
pub const MAX_GAS_PER_BLOCK: u64 = 1_000_000;

/// Scale factor from uEGOC (8-decimal) to EVM wei-scale (18-decimal).
/// 1 uEGOC = 10^10 wei  →  1 EGOC = 10^18 wei  (matches ETH decimals).
pub const UEGOC_TO_WEI: u128 = 10_000_000_000; // 10^10

// ─── gas / RU conversion helpers ────────────────────────────────────────────

/// Convert EVM gas units to Ego Resource Units.
#[inline]
pub fn gas_to_ru(gas: u64) -> u64 {
    gas * GAS_TO_RU_RATIO
}

/// Convert Ego Resource Units to EVM gas units (truncating).
#[inline]
pub fn ru_to_gas(ru: u64) -> u64 {
    ru / GAS_TO_RU_RATIO
}

// ─── result types ───────────────────────────────────────────────────────────

/// An EVM event log emitted during contract execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmLog {
    /// Contract address that emitted the log.
    pub address: [u8; 20],
    /// Indexed topics (up to 4; topic[0] is the event signature hash).
    pub topics: Vec<[u8; 32]>,
    /// Non-indexed ABI-encoded data.
    pub data: Vec<u8>,
}

/// The outcome of a single EVM execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmResult {
    /// Whether the execution succeeded (reverts → `false`).
    pub success: bool,
    /// Return data: ABI-encoded return value on call, or deployed bytecode
    /// address indicator on deploy (use `deployed_address` field instead).
    pub output: Vec<u8>,
    /// EVM gas consumed by this execution.
    pub gas_used: u64,
    /// Ego Resource Units consumed (`gas_used * 10`, per EGO-12 §4).
    pub ru_used: u64,
    /// Event logs emitted during execution.
    pub logs: Vec<EvmLog>,
    /// For CREATE/CREATE2 transactions: the address of the newly deployed
    /// contract. `None` for CALL transactions.
    pub deployed_address: Option<[u8; 20]>,
}

// ─── Ego state adapter ──────────────────────────────────────────────────────

/// In-memory EVM account record used by [`EgoEvmState`].
#[derive(Debug, Clone, Default)]
struct EvmAccount {
    balance_wei: U256,
    nonce: u64,
    code: Option<Bytecode>,
    code_hash: B256,
    storage: HashMap<U256, U256>,
}

/// Ego state adapter that implements `revm::Database`.
///
/// In production this would hold a reference to `ego_core::StateManager` and
/// perform real state lookups.  For v1 the struct owns an in-memory map so the
/// crate compiles and is testable without a running node — the integration glue
/// (reading from StateManager) lives in `bins/ego-node`.
///
/// # State key conventions (per EGO-12 §8)
///
/// | Data | Key |
/// |------|-----|
/// | EVM bytecode | `evm_code:{addr_hex}` |
/// | EVM storage slot | `evm:{addr_hex}:{slot_hex}` |
pub struct EgoEvmState {
    /// In-memory account table (address → account).
    accounts: HashMap<[u8; 20], EvmAccount>,
    /// Pending storage writes accumulated during execution (committed on
    /// success, discarded on revert by the caller).
    storage_writes: Vec<(Address, U256, U256)>,
}

impl EgoEvmState {
    /// Create a new, empty state (useful for tests and isolated executions).
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
            storage_writes: Vec::new(),
        }
    }

    /// Seed an account with a balance (in uEGOC — converted to wei internally).
    pub fn set_balance_uegoc(&mut self, address: [u8; 20], uegoc: u128) {
        let acc = self.accounts.entry(address).or_default();
        acc.balance_wei = U256::from(uegoc) * U256::from(UEGOC_TO_WEI);
    }

    /// Seed an account's nonce.
    pub fn set_nonce(&mut self, address: [u8; 20], nonce: u64) {
        self.accounts.entry(address).or_default().nonce = nonce;
    }

    /// Install bytecode for an existing contract account.
    pub fn set_code(&mut self, address: [u8; 20], bytecode: Vec<u8>) {
        let code = Bytecode::new_raw(bytecode.into());
        let code_hash = code.hash_slow();
        let acc = self.accounts.entry(address).or_default();
        acc.code_hash = code_hash;
        acc.code = Some(code);
    }

    /// Read a storage slot directly (used for RPC `eth_getStorageAt`).
    pub fn get_storage(&self, address: [u8; 20], slot: U256) -> U256 {
        self.accounts
            .get(&address)
            .and_then(|a| a.storage.get(&slot))
            .copied()
            .unwrap_or(U256::ZERO)
    }

    /// Drain pending storage writes (called by [`EgoEvm::execute`] after
    /// a successful run to persist them).
    pub fn drain_writes(&mut self) -> Vec<(Address, U256, U256)> {
        std::mem::take(&mut self.storage_writes)
    }
}

impl Default for EgoEvmState {
    fn default() -> Self {
        Self::new()
    }
}

/// `revm::Database` implementation for `EgoEvmState`.
///
/// All methods must be infallible from revm's perspective (errors are wrapped
/// in `Self::Error = anyhow::Error` which revm surfaces as an execution
/// failure).
impl Database for EgoEvmState {
    type Error = anyhow::Error;

    /// Return basic account information for `address`.
    ///
    /// Maps Ego account fields → revm `AccountInfo`:
    /// - balance: uEGOC × 10^10 → wei-scale U256
    /// - nonce: direct copy
    /// - code_hash: KECCAK of bytecode (computed once on insert)
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

    /// Return bytecode by its KECCAK hash.
    ///
    /// revm calls this when it already resolved the account (has the hash) but
    /// needs the full bytecode object.
    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        // Scan accounts for matching code hash.  In production this would be an
        // indexed lookup; the linear scan is acceptable for v1 test scenarios.
        for acc in self.accounts.values() {
            if acc.code_hash == code_hash {
                if let Some(code) = &acc.code {
                    return Ok(code.clone());
                }
            }
        }
        // Unknown hash → return empty bytecode (EVM will treat as EOA).
        Ok(Bytecode::new())
    }

    /// Return the value of storage slot `index` for `address`.
    ///
    /// Key convention (EGO-12 §8): `evm:{addr_hex}:{slot_hex}`
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

    /// Return the block hash for block `number`.
    ///
    /// The block hash oracle is not critical for v1.  We return B256::ZERO
    /// (all zeros) which causes `BLOCKHASH` opcode to return 0 — safe because
    /// no contract should rely on block hash availability on a fresh chain.
    fn block_hash(&mut self, _number: U256) -> Result<B256, Self::Error> {
        Ok(B256::ZERO)
    }
}

/// `revm::DatabaseCommit` implementation — applies state changes from a
/// completed EVM execution back into `EgoEvmState`.
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

// ─── EgoEvm executor ────────────────────────────────────────────────────────

/// The Ego EVM executor.
///
/// Wraps `revm::Evm` with Ego-specific configuration:
/// - Gas price always 0 (feeless per EGO-5)
/// - London spec (Berlin opcodes + EIP-1559 fields with base_fee=0)
/// - Chain ID from parameter (defaults to [`EGO_CHAIN_ID`])
pub struct EgoEvm;

impl EgoEvm {
    /// Execute an EVM transaction against `state`.
    ///
    /// # Parameters
    ///
    /// | Name | Description |
    /// |------|-------------|
    /// | `state` | Mutable reference to the Ego state adapter |
    /// | `caller` | 20-byte address of the transaction sender |
    /// | `to` | `Some(addr)` for CALL; `None` for CREATE (contract deploy) |
    /// | `value` | Amount of uEGOC to transfer with the call |
    /// | `data` | Calldata (for CALL) or initcode (for CREATE) |
    /// | `gas_limit` | Maximum EVM gas; capped at [`MAX_GAS_PER_BLOCK`] |
    /// | `chain_id` | EVM chain ID to enforce in CfgEnv |
    ///
    /// # Returns
    ///
    /// [`EvmResult`] containing success flag, output bytes, gas/RU consumed,
    /// emitted logs, and (for deploys) the newly created contract address.
    pub fn execute(
        state: &mut EgoEvmState,
        caller: [u8; 20],
        to: Option<[u8; 20]>,
        value: u128,
        data: Vec<u8>,
        gas_limit: u64,
        chain_id: u64,
    ) -> Result<EvmResult> {
        // Clamp gas_limit to block cap.
        let gas_limit = gas_limit.min(MAX_GAS_PER_BLOCK);

        // Convert value from uEGOC to wei-scale U256.
        let value_wei = U256::from(value) * U256::from(UEGOC_TO_WEI);

        // Build the transact-to target.
        let transact_to = match to {
            Some(addr) => TransactTo::Call(Address::from(addr)),
            None => TransactTo::Create(CreateScheme::Create),
        };

        // Configure the EVM environment.
        let mut env = Env::default();

        // CfgEnv — chain settings.
        env.cfg = CfgEnv::default();
        env.cfg.chain_id = chain_id;
        // Disable balance checks so feeless execution works without seeding the
        // caller with a wei balance matching exact gas cost (gas price = 0 so
        // effective cost is always 0 anyway).
        env.cfg.disable_balance_check = true;

        // BlockEnv — use London spec defaults (base_fee = 0).
        // revm's BlockEnv::default() is safe here; base_fee defaults to 0.
        env.block.basefee = U256::ZERO;

        // TxEnv — transaction parameters.
        env.tx = TxEnv {
            caller: Address::from(caller),
            gas_limit,
            gas_price: U256::ZERO,   // feeless per EGO-5
            transact_to,
            value: value_wei,
            data: data.into(),
            nonce: None, // revm will read nonce from state
            chain_id: Some(chain_id),
            access_list: vec![],
            gas_priority_fee: None,
            blob_hashes: vec![],
            max_fee_per_blob_gas: None,
        };

        // Build and run the EVM.
        let mut evm = Evm::builder()
            .with_db(state)
            .with_env(Box::new(env))
            .build();

        let result = evm.transact_commit().map_err(|e| anyhow!("EVM execution error: {:?}", e))?;

        // Destructure the execution result.
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

        // Convert revm log types to our `EvmLog`.
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

// ─── MetaMask-compatible JSON-RPC helpers ────────────────────────────────────

/// JSON shapes for MetaMask-compatible JSON-RPC responses.
///
/// All functions return `serde_json::Value` objects ready to be serialised into
/// a standard JSON-RPC 2.0 response body.
pub mod eth_rpc {
    use serde_json::{json, Value};

    /// Build an `eth_chainId` response.
    ///
    /// Returns the chain ID as a `0x`-prefixed hex string, as required by
    /// MetaMask.
    ///
    /// # Example
    /// ```
    /// let resp = ego_evm::eth_rpc::eth_chain_id(1399);
    /// assert_eq!(resp["result"], "0x577");
    /// ```
    pub fn eth_chain_id(chain_id: u64) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": format!("0x{:x}", chain_id)
        })
    }

    /// Build an `eth_getBalance` response.
    ///
    /// `balance_wei` should be the account's balance **in wei** (uEGOC × 10^10).
    /// The value is returned as a `0x`-prefixed hex string per the Ethereum
    /// JSON-RPC spec.
    ///
    /// # Conversion note
    ///
    /// Ego stores balances in uEGOC (8 decimals).  To obtain `balance_wei`:
    /// ```text
    /// balance_wei = uegoc_balance * 10_000_000_000  // multiply by 10^10
    /// ```
    /// This maps 1 EGOC (= 10^8 uEGOC) → 10^18 wei, matching Ethereum's 18-
    /// decimal ETH convention so MetaMask displays amounts correctly.
    ///
    /// # Example
    /// ```
    /// // 1 EGOC = 100_000_000 uEGOC → 10^18 wei
    /// let resp = ego_evm::eth_rpc::eth_get_balance_response(1_000_000_000_000_000_000u128);
    /// assert_eq!(resp["result"], "0xde0b6b3a7640000");
    /// ```
    pub fn eth_get_balance_response(balance_wei: u128) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": format!("0x{:x}", balance_wei)
        })
    }

    /// Build a `net_version` response (returns chain ID as decimal string).
    pub fn net_version(chain_id: u64) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": chain_id.to_string()
        })
    }

    /// Build an `eth_blockNumber` response.
    pub fn eth_block_number(block_height: u64) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": format!("0x{:x}", block_height)
        })
    }

    /// Build an `eth_estimateGas` response.
    pub fn eth_estimate_gas(gas: u64) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": format!("0x{:x}", gas)
        })
    }

    /// Build an `eth_getTransactionCount` (nonce) response.
    pub fn eth_get_transaction_count(nonce: u64) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": format!("0x{:x}", nonce)
        })
    }

    /// Build an `eth_getCode` response.
    pub fn eth_get_code(bytecode_hex: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": format!("0x{}", bytecode_hex)
        })
    }

    /// Build a standard JSON-RPC error response.
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

// ─── unit tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gas_ru_roundtrip() {
        assert_eq!(gas_to_ru(1_000), 10_000);
        assert_eq!(ru_to_gas(10_000), 1_000);
        // truncating division
        assert_eq!(ru_to_gas(10_005), 1_000);
    }

    #[test]
    fn uegoc_to_wei_scaling() {
        // 1 EGOC = 100_000_000 uEGOC → should equal 10^18 wei
        let uegoc: u128 = 100_000_000;
        let wei = uegoc * UEGOC_TO_WEI;
        assert_eq!(wei, 1_000_000_000_000_000_000u128); // 10^18
    }

    #[test]
    fn state_balance_roundtrip() {
        let mut state = EgoEvmState::new();
        let addr = [0xabu8; 20];
        state.set_balance_uegoc(addr, 100_000_000); // 1 EGOC
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
        // 1 EGOC worth of wei
        let wei = 100_000_000u128 * UEGOC_TO_WEI;
        let resp = eth_rpc::eth_get_balance_response(wei);
        assert_eq!(resp["result"], "0xde0b6b3a7640000");
    }

    #[test]
    fn evm_deploy_simple_contract() {
        // Minimal EVM bytecode that just returns 0x42 from a CALL.
        // PUSH1 0x42, PUSH1 0x00, MSTORE, PUSH1 0x20, PUSH1 0x00, RETURN
        // initcode: deploy the above runtime via a constructor
        // Runtime bytecode: 60 42 60 00 52 60 20 60 00 f3
        let runtime = hex::decode("604260005260206000f3").unwrap();
        // Constructor: copy runtime to memory and return it
        // PUSH10 <runtime_len> PUSH1 0x00 PUSH1 0x0a ... simplified
        // Use a known working minimal deploy pattern:
        // 0x60 <len> 0x60 0x0c 0x60 0x00 0x39 0x60 <len> 0x60 0x00 0xf3 <runtime>
        let runtime_len = runtime.len() as u8;
        let mut initcode: Vec<u8> = vec![
            0x60, runtime_len, // PUSH1 <runtime_len>  — size
            0x60, 0x0c,        // PUSH1 12             — offset in this initcode
            0x60, 0x00,        // PUSH1 0              — dest in memory
            0x39,              // CODECOPY
            0x60, runtime_len, // PUSH1 <runtime_len>  — size
            0x60, 0x00,        // PUSH1 0              — offset in memory
            0xf3,              // RETURN
        ];
        initcode.extend_from_slice(&runtime);

        let mut state = EgoEvmState::new();
        let caller = [0x01u8; 20];
        state.set_balance_uegoc(caller, 1_000_000_000); // 10 EGOC
        state.set_nonce(caller, 0);

        let result = EgoEvm::execute(
            &mut state,
            caller,
            None, // deploy
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
        // REVERT opcode: 0x60 0x00 0x60 0x00 0xfd
        let revert_code = hex::decode("6000600080fd").unwrap();
        // Deploy first
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

        // Deploy
        let deploy = EgoEvm::execute(
            &mut state, caller, None, 0, initcode, 100_000, EGO_CHAIN_ID,
        )
        .unwrap();
        assert!(deploy.success);
        let contract_addr = deploy.deployed_address.unwrap();

        // Call (should revert)
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
