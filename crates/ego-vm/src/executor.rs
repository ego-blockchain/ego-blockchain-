use wasmtime::{Caller, Config, Engine, Linker, Module, Store, Trap};
use crate::error::VmError;
use crate::host::{HostCtx, ru_cost};
use crate::state::{ContractState, StateStore};
use crate::types::*;

/// The VM executor. One instance per relay/node process.
/// Holds the Wasmtime Engine (compilation cache shared across calls).
pub struct Executor {
    engine: Engine,
    pub store: StateStore,
}

impl Executor {
    pub fn new(data_dir: std::path::PathBuf) -> Result<Self, VmError> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.max_wasm_stack(512 * 1024); // 512 KB stack
        let engine = Engine::new(&config)
            .map_err(|e| VmError::CompileError(e.to_string()))?;
        Ok(Self {
            engine,
            store: StateStore::new(data_dir),
        })
    }

    /// Deploy a new contract.
    /// 1. Validate WASM size
    /// 2. Compile module (checks WASM validity)
    /// 3. Run init() entrypoint with args
    /// 4. Store code + initial state
    pub fn deploy(
        &self,
        wasm_bytes:    &[u8],
        deployer_addr: &str,
        init_args:     &[u8],    // raw bytes passed to init()
        block_height:  u64,
        timestamp:     i64,
        fuel:          u64,
    ) -> Result<DeployResult, VmError> {
        // Size check
        if wasm_bytes.len() > MAX_CODE_SIZE {
            return Err(VmError::InvalidAbi(format!(
                "Code too large: {} bytes (max {})", wasm_bytes.len(), MAX_CODE_SIZE
            )));
        }

        // Derive contract address: blake3(deployer_addr + code)[0..20]
        let hash_input = format!("{}{}", deployer_addr, hex::encode(wasm_bytes));
        let code_hash_bytes = blake3::hash(hash_input.as_bytes());
        let code_hash = hex::encode(code_hash_bytes.as_bytes());
        let contract_addr = hex::encode(&code_hash_bytes.as_bytes()[..20]);

        if self.store.contract_exists(&contract_addr) {
            // Identical code already deployed — return existing address
            return Ok(DeployResult {
                contract_address: contract_addr,
                code_hash,
                ru_used: 0,
                events: vec![],
            });
        }

        // Compile WASM
        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(|e| VmError::CompileError(e.to_string()))?;

        // Run init()
        let ctx = HostCtx::new(
            contract_addr.clone(),
            deployer_addr.to_string(),
            block_height,
            timestamp,
            ContractState::default(),
        );

        let (ctx_out, ru_used) = self.run_entrypoint(
            &module, ctx, "init", init_args, fuel
        )?;

        // Persist code + state + manifest
        self.store.store_code(&contract_addr, wasm_bytes)?;
        self.store.save_state(&contract_addr, &ctx_out.state)?;
        self.store.store_manifest(&contract_addr, &ContractManifest {
            name:           format!("contract_{}", &contract_addr[..8]),
            version:        "0.1.0".into(),
            code_hash:      code_hash.clone(),
            deployer:       deployer_addr.to_string(),
            deployed_at:    timestamp,
            upgrade_policy: UpgradePolicy::Immutable,
        })?;

        Ok(DeployResult {
            contract_address: contract_addr,
            code_hash,
            ru_used,
            events: ctx_out.events,
        })
    }

    /// Call an entrypoint on an already-deployed contract.
    pub fn call(
        &self,
        contract_addr: &str,
        caller_addr:   &str,
        entrypoint:    &str,
        args:          &[u8],
        block_height:  u64,
        timestamp:     i64,
        fuel:          u64,
    ) -> Result<CallResult, VmError> {
        // Load code
        let wasm_bytes = self.store.load_code(contract_addr)?;
        let module = Module::new(&self.engine, &wasm_bytes)
            .map_err(|e| VmError::CompileError(e.to_string()))?;

        // Load state
        let state = self.store.load_state(contract_addr);
        let ctx = HostCtx::new(
            contract_addr.to_string(),
            caller_addr.to_string(),
            block_height,
            timestamp,
            state,
        );

        match self.run_entrypoint(&module, ctx, entrypoint, args, fuel) {
            Ok((ctx_out, ru_used)) => {
                // Persist updated state
                self.store.save_state(contract_addr, &ctx_out.state)?;
                Ok(CallResult {
                    success:    true,
                    return_val: vec![],
                    ru_used,
                    events:     ctx_out.events,
                    error:      None,
                })
            }
            Err(VmError::FuelExhausted) => Ok(CallResult {
                success:    false,
                return_val: vec![],
                ru_used:    fuel,
                events:     vec![],
                error:      Some("Fuel exhausted".into()),
            }),
            Err(e) => Ok(CallResult {
                success:    false,
                return_val: vec![],
                ru_used:    0,
                events:     vec![],
                error:      Some(e.to_string()),
            }),
        }
    }

    /// Internal: instantiate module, wire host functions, run one entrypoint.
    fn run_entrypoint(
        &self,
        module:     &Module,
        ctx:        HostCtx,
        entrypoint: &str,
        args:       &[u8],
        fuel:       u64,
    ) -> Result<(HostCtx, u64), VmError> {
        let mut store = Store::new(&self.engine, ctx);
        store.set_fuel(fuel)
            .map_err(|e| VmError::ExecutionError(e.to_string()))?;

        // Wire memory limiter — HostCtx holds a StoreLimits field
        store.limiter(|ctx| &mut ctx.limiter);

        // Build linker with host functions
        let linker = build_linker(&self.engine)?;

        let instance = linker.instantiate(&mut store, module)
            .map_err(|e| VmError::InstantiationError(e.to_string()))?;

        // Write args into contract memory via __set_args if it exists
        if let Ok(set_args) = instance.get_typed_func::<(i32, i32), ()>(&mut store, "__set_args") {
            let mem = instance.get_memory(&mut store, "memory")
                .ok_or_else(|| VmError::ExecutionError("No memory export".into()))?;
            let offset = 0i32;
            let args_len = args.len() as i32;
            mem.write(&mut store, offset as usize, args)
                .map_err(|e| VmError::ExecutionError(e.to_string()))?;
            set_args.call(&mut store, (offset, args_len))
                .map_err(|e| VmError::ExecutionError(e.to_string()))?;
        }

        // Call the entrypoint
        let func = instance.get_func(&mut store, entrypoint)
            .ok_or_else(|| VmError::InvalidAbi(format!("Entrypoint '{}' not found", entrypoint)))?;

        let result = func.call(&mut store, &[], &mut []);

        let fuel_remaining = store.get_fuel().unwrap_or(0);
        let ru_used = fuel.saturating_sub(fuel_remaining);

        match result {
            Ok(_) => {
                let ctx_out = store.into_data();
                Ok((ctx_out, ru_used))
            }
            Err(ref e) => {
                // Detect OutOfFuel trap via downcast_ref on the anyhow::Error
                if e.downcast_ref::<Trap>() == Some(&Trap::OutOfFuel) {
                    return Err(VmError::FuelExhausted);
                }
                Err(VmError::ExecutionError(e.to_string()))
            }
        }
    }
}

/// Build a Wasmtime Linker with all Urego host functions.
fn build_linker(engine: &Engine) -> Result<Linker<HostCtx>, VmError> {
    let mut linker = Linker::<HostCtx>::new(engine);

    // ── storage.get(prefix_ptr, prefix_len, key_ptr, key_len, out_ptr) → i32 (value_len) ──
    linker.func_wrap("env", "storage_get", |mut caller: Caller<'_, HostCtx>,
        prefix_ptr: i32, prefix_len: i32,
        key_ptr: i32, key_len: i32,
        out_ptr: i32|
    -> i32 {
        caller.data_mut().host_ru += ru_cost::STORAGE_GET;
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m, None => return -1,
        };
        let data = mem.data(&caller).to_vec();
        let prefix = match read_str(&data, prefix_ptr, prefix_len) {
            Some(s) => s, None => return -1,
        };
        let key = match read_str(&data, key_ptr, key_len) {
            Some(s) => s, None => return -1,
        };
        match caller.data().state.get(&prefix, &key) {
            Some(val) => {
                let len = val.len() as i32;
                let mem_mut = caller.get_export("memory").and_then(|e| e.into_memory()).unwrap();
                let _ = mem_mut.write(&mut caller, out_ptr as usize, &val);
                len
            }
            None => -1,
        }
    }).map_err(|e| VmError::ExecutionError(e.to_string()))?;

    // ── storage.set(prefix_ptr, prefix_len, key_ptr, key_len, val_ptr, val_len) ──
    linker.func_wrap("env", "storage_set", |mut caller: Caller<'_, HostCtx>,
        prefix_ptr: i32, prefix_len: i32,
        key_ptr: i32, key_len: i32,
        val_ptr: i32, val_len: i32|
    {
        caller.data_mut().host_ru += ru_cost::STORAGE_SET;
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m, None => return,
        };
        let data = mem.data(&caller).to_vec();
        let prefix = match read_str(&data, prefix_ptr, prefix_len) { Some(s) => s, None => return };
        let key    = match read_str(&data, key_ptr,    key_len)    { Some(s) => s, None => return };
        let val    = read_bytes(&data, val_ptr, val_len).unwrap_or_default();
        caller.data_mut().state.set(&prefix, &key, val);
    }).map_err(|e| VmError::ExecutionError(e.to_string()))?;

    // ── storage.del(prefix_ptr, prefix_len, key_ptr, key_len) ──
    linker.func_wrap("env", "storage_del", |mut caller: Caller<'_, HostCtx>,
        prefix_ptr: i32, prefix_len: i32,
        key_ptr: i32, key_len: i32|
    {
        caller.data_mut().host_ru += ru_cost::STORAGE_DEL;
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m, None => return,
        };
        let data = mem.data(&caller).to_vec();
        let prefix = match read_str(&data, prefix_ptr, prefix_len) { Some(s) => s, None => return };
        let key    = match read_str(&data, key_ptr,    key_len)    { Some(s) => s, None => return };
        caller.data_mut().state.del(&prefix, &key);
    }).map_err(|e| VmError::ExecutionError(e.to_string()))?;

    // ── events.emit(topic_ptr, topic_len, payload_ptr, payload_len) ──
    linker.func_wrap("env", "events_emit", |mut caller: Caller<'_, HostCtx>,
        topic_ptr: i32, topic_len: i32,
        payload_ptr: i32, payload_len: i32|
    {
        caller.data_mut().host_ru += ru_cost::EVENTS_EMIT;
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m, None => return,
        };
        let data = mem.data(&caller).to_vec();
        let topic   = read_str(&data, topic_ptr, topic_len).unwrap_or_default();
        let payload = read_bytes(&data, payload_ptr, payload_len).unwrap_or_default();
        let ctx = caller.data_mut();
        ctx.events.push(crate::types::ContractEvent {
            contract:  ctx.contract_addr.clone(),
            topic,
            payload,
            height:    ctx.block_height,
            timestamp: ctx.timestamp,
        });
    }).map_err(|e| VmError::ExecutionError(e.to_string()))?;

    // ── blake3(data_ptr, data_len, out_ptr) — writes 32 bytes ──
    linker.func_wrap("env", "blake3_hash", |mut caller: Caller<'_, HostCtx>,
        data_ptr: i32, data_len: i32, out_ptr: i32|
    {
        caller.data_mut().host_ru += ru_cost::BLAKE3;
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m, None => return,
        };
        let raw = mem.data(&caller).to_vec();
        let input = read_bytes(&raw, data_ptr, data_len).unwrap_or_default();
        let hash = blake3::hash(&input);
        let mem2 = caller.get_export("memory").and_then(|e| e.into_memory()).unwrap();
        let _ = mem2.write(&mut caller, out_ptr as usize, hash.as_bytes());
    }).map_err(|e| VmError::ExecutionError(e.to_string()))?;

    // ── sys.caller(out_ptr) → i32 (len) — writes caller address string ──
    linker.func_wrap("env", "sys_caller", |mut caller: Caller<'_, HostCtx>, out_ptr: i32| -> i32 {
        caller.data_mut().host_ru += ru_cost::SYSVAR;
        let addr = caller.data().caller.clone();
        let bytes = addr.as_bytes().to_vec();
        let len = bytes.len() as i32;
        let mem = caller.get_export("memory").and_then(|e| e.into_memory()).unwrap();
        let _ = mem.write(&mut caller, out_ptr as usize, &bytes);
        len
    }).map_err(|e| VmError::ExecutionError(e.to_string()))?;

    // ── sys.block_height() → i64 ──
    linker.func_wrap("env", "sys_block_height", |caller: Caller<'_, HostCtx>| -> i64 {
        caller.data().block_height as i64
    }).map_err(|e| VmError::ExecutionError(e.to_string()))?;

    // ── sys.timestamp() → i64 ──
    linker.func_wrap("env", "sys_timestamp", |caller: Caller<'_, HostCtx>| -> i64 {
        caller.data().timestamp
    }).map_err(|e| VmError::ExecutionError(e.to_string()))?;

    // ── sys.contract_addr(out_ptr) → i32 (len) ──
    linker.func_wrap("env", "sys_contract_addr", |mut caller: Caller<'_, HostCtx>, out_ptr: i32| -> i32 {
        caller.data_mut().host_ru += ru_cost::SYSVAR;
        let addr = caller.data().contract_addr.clone();
        let bytes = addr.as_bytes().to_vec();
        let len = bytes.len() as i32;
        let mem = caller.get_export("memory").and_then(|e| e.into_memory()).unwrap();
        let _ = mem.write(&mut caller, out_ptr as usize, &bytes);
        len
    }).map_err(|e| VmError::ExecutionError(e.to_string()))?;

    // ── egoc.transfer(to_ptr, to_len, amount) ──
    linker.func_wrap("env", "egoc_transfer", |mut caller: Caller<'_, HostCtx>,
        to_ptr: i32, to_len: i32, amount: i64|
    {
        caller.data_mut().host_ru += ru_cost::EGOC_TRANSFER;
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m, None => return,
        };
        let data = mem.data(&caller).to_vec();
        let to = read_str(&data, to_ptr, to_len).unwrap_or_default();
        if !to.is_empty() && amount > 0 {
            caller.data_mut().transfers.push((to, amount as u64));
        }
    }).map_err(|e| VmError::ExecutionError(e.to_string()))?;

    // ── assert(cond) — traps if cond == 0 ──
    linker.func_wrap("env", "urego_assert", |_caller: Caller<'_, HostCtx>, cond: i32| {
        if cond == 0 {
            panic!("assertion failed");
        }
    }).map_err(|e| VmError::ExecutionError(e.to_string()))?;

    Ok(linker)
}

/// Read a UTF-8 string from WASM memory.
fn read_str(mem: &[u8], ptr: i32, len: i32) -> Option<String> {
    let bytes = read_bytes(mem, ptr, len)?;
    String::from_utf8(bytes).ok()
}

/// Read raw bytes from WASM memory.
fn read_bytes(mem: &[u8], ptr: i32, len: i32) -> Option<Vec<u8>> {
    if ptr < 0 || len < 0 { return None; }
    let start = ptr as usize;
    let end   = start + len as usize;
    if end > mem.len() { return None; }
    Some(mem[start..end].to_vec())
}
