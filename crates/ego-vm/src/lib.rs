pub mod abi;
pub mod error;
pub mod evm;
pub mod executor;
pub mod host;
pub mod parallel;
pub mod state;
pub mod types;

pub use abi::{AbiDecoder, AbiEncoder, AbiError, AbiType, AbiValue, FunctionSelector};
pub use evm::{EvmCallResult, EvmExecutor};

pub fn evm_with_contracts_dir(dir: &std::path::Path) -> EvmExecutor {
    EvmExecutor::with_state_path(dir.join("evm_state.json"))
}
pub use executor::{
    call_on, contract_address_for, deploy_on, exported_functions, CallEffects, DeployEffects,
    ExecEnv, Executor, TRANSFERS_DISABLED,
};
pub use host::CrossCallRequest;
pub use state::{ContractSource, ContractState};
pub use types::{CallResult, ContractAddress, ContractEvent, ContractManifest, DeployResult};
pub use error::VmError;
pub use parallel::{PendingTx, AccessSet, BatchResult, schedule_batch};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executor_new() {
        let tmp = std::env::temp_dir().join("ego_vm_test");
        let exec = Executor::new(tmp);
        assert!(exec.is_ok());
    }

    #[test]
    fn test_deploy_i64_init_with_empty_args() {
        let src = r#"contract MyToken {
            pub fn init(supply: u64) {
                storage.set("supply", supply);
            }
            pub fn total_supply() -> u64 {
                return storage.get_u64("supply");
            }
        }"#;
        let wasm = urego_compiler::compile(src).expect("template must compile");
        let tmp = std::env::temp_dir().join(format!("ego_vm_test_deploy_{}", std::process::id()));
        let exec = Executor::new(tmp.clone()).unwrap();

        let r = exec.deploy(&wasm, "egot1deployer", &[], 1, 0, types::DEFAULT_DEPLOY_FUEL);
        assert!(r.is_ok(), "deploy with empty init args failed: {:?}", r.err());

        let supply: u64 = 1_000_000;
        let r2 = exec.deploy(&wasm, "egot1deployer2", &supply.to_le_bytes(), 1, 0, types::DEFAULT_DEPLOY_FUEL);
        assert!(r2.is_ok(), "deploy with u64 init arg failed: {:?}", r2.err());

        let _ = std::fs::remove_dir_all(tmp);
    }

    #[derive(Default)]
    struct MemSource {
        code:   std::collections::BTreeMap<String, Vec<u8>>,
        states: std::collections::BTreeMap<String, ContractState>,
    }

    impl ContractSource for MemSource {
        fn code(&self, addr: &str) -> Option<Vec<u8>> { self.code.get(addr).cloned() }
        fn state(&self, addr: &str) -> ContractState { self.states.get(addr).cloned().unwrap_or_default() }
    }

    fn env(height: u64, ts: i64, allow_transfers: bool) -> ExecEnv {
        ExecEnv { block_height: height, timestamp: ts, fuel: types::DEFAULT_CALL_FUEL, allow_transfers }
    }

    const COUNTER: &str = r#"contract Counter {
        pub fn init() {
            storage.set("count", 0);
        }
        pub fn bump() {
            let v: u64 = storage.get_u64("count");
            storage.set("count", v + 1);
        }
        pub fn count() -> u64 {
            return storage.get_u64("count");
        }
    }"#;

    fn deployed_counter() -> (MemSource, String) {
        let wasm = urego_compiler::compile(COUNTER).unwrap();
        let mut src = MemSource::default();
        let fx = deploy_on(&src, &wasm, "egot1alice", &[], env(7, 1_700_000_000, false)).unwrap();
        let addr = fx.result.contract_address.clone();
        src.code.insert(addr.clone(), fx.code);
        src.states.insert(addr.clone(), fx.state);
        (src, addr)
    }

    #[test]
    fn working_against_a_source_writes_nothing_until_the_caller_commits() {
        let (src, addr) = deployed_counter();
        let before = src.state(&addr);
        let fx = call_on(&src, &addr, "egot1bob", "bump", &[], env(8, 1_700_000_010, false)).unwrap();
        assert!(fx.result.success, "{:?}", fx.result.error);
        assert_eq!(src.state(&addr), before, "a call must only describe its effects");
        assert_eq!(fx.states[&addr].get("", "count"), Some(1u64.to_le_bytes().to_vec()));
    }

    #[test]
    fn the_same_inputs_give_the_same_effects() {
        let (a, addr) = deployed_counter();
        let (b, addr_b) = deployed_counter();
        assert_eq!(addr, addr_b);
        let fa = call_on(&a, &addr, "egot1bob", "bump", &[], env(8, 5, false)).unwrap();
        let fb = call_on(&b, &addr, "egot1bob", "bump", &[], env(8, 5, false)).unwrap();
        assert_eq!(serde_json::to_string(&fa.states).unwrap(), serde_json::to_string(&fb.states).unwrap());
        assert_eq!(fa.result.ru_used, fb.result.ru_used);
    }

    #[test]
    fn deploy_records_the_block_time_not_the_clock() {
        let wasm = urego_compiler::compile(COUNTER).unwrap();
        let fx = deploy_on(&MemSource::default(), &wasm, "egot1alice", &[], env(7, 1_234, false)).unwrap();
        assert_eq!(fx.manifest.unwrap().deployed_at, 1_234);
    }

    #[test]
    fn a_view_returns_its_value() {
        let (mut src, addr) = deployed_counter();
        let fx = call_on(&src, &addr, "egot1bob", "bump", &[], env(8, 5, false)).unwrap();
        src.states.extend(fx.states);
        let view = call_on(&src, &addr, "egot1bob", "count", &[], env(9, 6, false)).unwrap();
        assert_eq!(view.result.return_val, 1i64.to_le_bytes().to_vec());
    }

    #[test]
    fn moving_egoc_is_refused_when_transfers_are_off() {
        let wat = r#"(module
            (import "env" "egoc_transfer" (func $t (param i32 i32 i64)))
            (memory (export "memory") 1)
            (data (i32.const 0) "egot1thief")
            (func (export "init"))
            (func (export "drain") (call $t (i32.const 0) (i32.const 10) (i64.const 5))))"#;
        let wasm = wat::parse_str(wat).unwrap();
        let mut src = MemSource::default();
        let fx = deploy_on(&src, &wasm, "egot1alice", &[], env(1, 1, false)).unwrap();
        let addr = fx.result.contract_address.clone();
        src.code.insert(addr.clone(), fx.code);

        let off = call_on(&src, &addr, "egot1bob", "drain", &[], env(2, 2, false)).unwrap();
        assert!(!off.result.success);
        assert_eq!(off.result.error.as_deref(), Some(TRANSFERS_DISABLED));
        assert!(off.states.is_empty(), "a refused call must change nothing");

        let on = call_on(&src, &addr, "egot1bob", "drain", &[], env(2, 2, true)).unwrap();
        assert!(on.result.success);
        assert_eq!(on.result.transfers, vec![("egot1thief".to_string(), 5)]);
    }

    #[test]
    fn redeploying_the_same_code_is_a_no_op() {
        let (src, addr) = deployed_counter();
        let wasm = urego_compiler::compile(COUNTER).unwrap();
        let fx = deploy_on(&src, &wasm, "egot1alice", &[], env(9, 9, false)).unwrap();
        assert!(fx.existed);
        assert_eq!(fx.result.contract_address, addr);
    }

    #[test]
    fn reading_a_key_never_written_gives_zero() {
        let src_code = r#"contract Stale {
            pub fn init() {
                storage.set("a", 5);
            }
            pub fn missing_after_a() -> u64 {
                let a: u64 = storage.get_u64("a");
                return storage.get_u64("never_set");
            }
        }"#;
        let wasm = urego_compiler::compile(src_code).unwrap();
        let mut src = MemSource::default();
        let fx = deploy_on(&src, &wasm, "egot1alice", &[], env(1, 1, false)).unwrap();
        let addr = fx.result.contract_address.clone();
        src.code.insert(addr.clone(), fx.code);
        src.states.insert(addr.clone(), fx.state);
        let view = call_on(&src, &addr, "egot1bob", "missing_after_a", &[], env(2, 2, false)).unwrap();
        assert_eq!(view.result.return_val, 0i64.to_le_bytes().to_vec(),
            "a missing key must read as 0, not whatever the previous read left behind");
    }

    #[test]
    fn a_failing_assert_fails_the_call_instead_of_the_process() {
        let src_code = r#"contract Picky {
            pub fn init() {
                storage.set("a", 1);
            }
            pub fn refuse() {
                assert(1 == 2, "never");
            }
        }"#;
        let wasm = urego_compiler::compile(src_code).unwrap();
        let mut src = MemSource::default();
        let fx = deploy_on(&src, &wasm, "egot1alice", &[], env(1, 1, false)).unwrap();
        let addr = fx.result.contract_address.clone();
        src.code.insert(addr.clone(), fx.code);
        let call = call_on(&src, &addr, "egot1bob", "refuse", &[], env(2, 2, false)).unwrap();
        assert!(!call.result.success);
        assert!(call.states.is_empty());
    }

    #[test]
    fn running_out_of_fuel_fails_the_call_instead_of_the_process() {
        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "init"))
            (func (export "spin") (loop $l (br $l))))"#;
        let wasm = wat::parse_str(wat).unwrap();
        let mut src = MemSource::default();
        let fx = deploy_on(&src, &wasm, "egot1alice", &[], env(1, 1, false)).unwrap();
        let addr = fx.result.contract_address.clone();
        src.code.insert(addr.clone(), fx.code);
        let call = call_on(&src, &addr, "egot1bob", "spin", &[], env(2, 2, false)).unwrap();
        assert!(!call.result.success);
        assert_eq!(call.result.error.as_deref(), Some("Fuel exhausted"));
    }

    #[test]
    fn exports_describe_the_callable_functions() {
        let wasm = urego_compiler::compile(COUNTER).unwrap();
        let abi = exported_functions(&wasm).unwrap();
        assert!(abi.contains(&"bump()".to_string()), "{abi:?}");
        assert!(abi.contains(&"count() \u{2192} u64".to_string()), "{abi:?}");
    }
}
