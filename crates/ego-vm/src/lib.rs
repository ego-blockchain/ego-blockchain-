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
}
