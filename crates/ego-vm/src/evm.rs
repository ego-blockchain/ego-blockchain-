use revm::{
    primitives::{
        AccountInfo, Address, Bytecode, Bytes, CreateScheme, ExecutionResult, Output,
        TransactTo, U256,
    },
    Evm, InMemoryDB,
};

#[derive(Debug)]
pub struct EvmCallResult {
    pub success:    bool,
    pub return_val: Vec<u8>,
    pub gas_used:   u64,
    pub error:      Option<String>,
}

pub struct EvmExecutor {
    db: InMemoryDB,
}

impl EvmExecutor {
    pub fn new() -> Self {
        Self { db: InMemoryDB::default() }
    }

    pub fn deploy_bytecode(&mut self, bytecode: &[u8], deployer: [u8; 20]) -> Result<[u8; 20], String> {
        let deployer_addr = Address::from(deployer);
        self.db.insert_account_info(
            deployer_addr,
            AccountInfo { balance: U256::from(u64::MAX), nonce: 0, ..Default::default() },
        );

        let result = Evm::builder()
            .with_db(&mut self.db)
            .modify_tx_env(|tx| {
                tx.caller      = deployer_addr;
                tx.transact_to = TransactTo::Create(CreateScheme::Create);
                tx.data        = Bytes::copy_from_slice(bytecode);
                tx.value       = U256::ZERO;
                tx.gas_limit   = 30_000_000;
            })
            .build()
            .transact_commit()
            .map_err(|e| format!("EVM deploy error: {e:?}"))?;

        match result {
            ExecutionResult::Success { output: Output::Create(_, Some(addr)), .. } => Ok(addr.into()),
            ExecutionResult::Success { .. } => Err("deploy succeeded but no address returned".into()),
            ExecutionResult::Revert { output, .. } => Err(format!("revert: 0x{}", hex::encode(output))),
            ExecutionResult::Halt { reason, .. } => Err(format!("halt: {reason:?}")),
        }
    }

    pub fn call(
        &mut self,
        contract: [u8; 20],
        caller:   [u8; 20],
        calldata: &[u8],
        value:    u64,
    ) -> EvmCallResult {
        let caller_addr   = Address::from(caller);
        let contract_addr = Address::from(contract);

        self.db.insert_account_info(
            caller_addr,
            AccountInfo { balance: U256::from(u64::MAX), nonce: 0, ..Default::default() },
        );

        let result = match Evm::builder()
            .with_db(&mut self.db)
            .modify_tx_env(|tx| {
                tx.caller      = caller_addr;
                tx.transact_to = TransactTo::Call(contract_addr);
                tx.data        = Bytes::copy_from_slice(calldata);
                tx.value       = U256::from(value);
                tx.gas_limit   = 30_000_000;
            })
            .build()
            .transact_commit()
        {
            Ok(r)  => r,
            Err(e) => return EvmCallResult { success: false, return_val: vec![], gas_used: 0, error: Some(format!("{e:?}")) },
        };

        match result {
            ExecutionResult::Success { output, gas_used, .. } => {
                let bytes = match output {
                    Output::Call(b)       => b.to_vec(),
                    Output::Create(b, _)  => b.to_vec(),
                };
                EvmCallResult { success: true, return_val: bytes, gas_used, error: None }
            }
            ExecutionResult::Revert { output, gas_used } => {
                EvmCallResult { success: false, return_val: output.to_vec(), gas_used, error: Some("reverted".into()) }
            }
            ExecutionResult::Halt { reason, gas_used } => {
                EvmCallResult { success: false, return_val: vec![], gas_used, error: Some(format!("{reason:?}")) }
            }
        }
    }

    pub fn load_contract(&mut self, address: [u8; 20], deployed_bytecode: &[u8]) {
        let addr = Address::from(address);
        self.db.insert_account_info(
            addr,
            AccountInfo {
                code: Some(Bytecode::new_raw(Bytes::copy_from_slice(deployed_bytecode))),
                ..Default::default()
            },
        );
    }
}

impl Default for EvmExecutor {
    fn default() -> Self { Self::new() }
}
