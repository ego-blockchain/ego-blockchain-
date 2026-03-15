pub mod error;
pub mod executor;
pub mod host;
pub mod state;
pub mod types;

pub use executor::Executor;
pub use types::{CallResult, ContractAddress, ContractEvent, ContractManifest, DeployResult};
pub use error::VmError;

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
