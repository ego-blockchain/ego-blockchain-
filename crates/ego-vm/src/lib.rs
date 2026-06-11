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
pub use executor::Executor;
pub use host::CrossCallRequest;
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
}
