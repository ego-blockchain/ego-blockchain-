use std::collections::BTreeMap;
use wasmtime::{Caller, Config, Engine, Linker, Module, Store, Trap};
use crate::error::VmError;
use crate::host::{HostCtx, ru_cost};
use crate::state::{ContractSource, ContractState, StateStore};
use crate::types::*;

// ── Constants ─────────────────────────────────────────────────────────────────
/// Max bytes for a storage key prefix or key string.
const MAX_STORAGE_KEY_LEN: i32   = 256;
/// Max bytes for a single storage value.
const MAX_STORAGE_VAL_LEN: i32   = 65_536; // 64 KB
/// Cross-calls cannot request more fuel than a full top-level call.
const MAX_CROSS_CALL_FUEL: u64   = DEFAULT_CALL_FUEL;

// ── Shared WASM engine + compiled-module cache ────────────────────────────────
static WASM_ENGINE: std::sync::OnceLock<Engine> = std::sync::OnceLock::new();
static MODULE_CACHE: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<String, Module>>
> = std::sync::OnceLock::new();

fn default_val(vt: &wasmtime::ValType) -> wasmtime::Val {
    if vt.is_i64()      { wasmtime::Val::I64(0) }
    else if vt.is_f32() { wasmtime::Val::F32(0) }
    else if vt.is_f64() { wasmtime::Val::F64(0) }
    else                { wasmtime::Val::I32(0) }
}

fn get_engine() -> &'static Engine {
    WASM_ENGINE.get_or_init(|| {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.cranelift_nan_canonicalization(true);
        config.max_wasm_stack(512 * 1024);
        Engine::new(&config).expect("Wasmtime engine init failed")
    })
}

/// Returns a compiled Module for the given WASM bytes, reusing a cached
/// version when the blake3 code-hash matches (avoids re-JIT per call).
fn get_or_compile(wasm_bytes: &[u8]) -> Result<Module, VmError> {
    let code_hash = hex::encode(blake3::hash(wasm_bytes).as_bytes());
    let cache = MODULE_CACHE
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    {
        if let Some(m) = cache.lock().unwrap().get(&code_hash) {
            return Ok(m.clone());
        }
    }
    let module = Module::new(get_engine(), wasm_bytes)
        .map_err(|e| VmError::CompileError(e.to_string()))?;
    cache.lock().unwrap().insert(code_hash, module.clone());
    Ok(module)
}

pub const TRANSFERS_DISABLED: &str =
    "this contract tried to move EGOC, which contracts cannot do yet";

#[derive(Debug, Clone, Copy)]
pub struct ExecEnv {
    pub block_height:    u64,
    pub timestamp:       i64,
    pub fuel:            u64,
    pub allow_transfers: bool,
}

#[derive(Debug, Clone)]
pub struct DeployEffects {
    pub result:   DeployResult,
    pub existed:  bool,
    pub code:     Vec<u8>,
    pub state:    ContractState,
    pub manifest: Option<ContractManifest>,
}

#[derive(Debug, Clone)]
pub struct CallEffects {
    pub result: CallResult,
    pub states: BTreeMap<String, ContractState>,
}

pub fn contract_address_for(deployer_addr: &str, wasm_bytes: &[u8]) -> (String, String) {
    let hash_input = format!("{}{}", deployer_addr, hex::encode(wasm_bytes));
    let code_hash_bytes = blake3::hash(hash_input.as_bytes());
    let code_hash = hex::encode(code_hash_bytes.as_bytes());
    let contract_addr = hex::encode(&code_hash_bytes.as_bytes()[..20]);
    (contract_addr, code_hash)
}

pub fn deploy_on(
    src:           &dyn ContractSource,
    wasm_bytes:    &[u8],
    deployer_addr: &str,
    init_args:     &[u8],
    env:           ExecEnv,
) -> Result<DeployEffects, VmError> {
    if wasm_bytes.len() > MAX_CODE_SIZE {
        return Err(VmError::InvalidAbi(format!(
            "Code too large: {} bytes (max {})", wasm_bytes.len(), MAX_CODE_SIZE
        )));
    }

    let (contract_addr, code_hash) = contract_address_for(deployer_addr, wasm_bytes);

    if src.code(&contract_addr).is_some() {
        return Ok(DeployEffects {
            result: DeployResult {
                contract_address: contract_addr,
                code_hash,
                ru_used: 0,
                events: vec![],
                transfers: vec![],
            },
            existed:  true,
            code:     vec![],
            state:    ContractState::default(),
            manifest: None,
        });
    }

    let module = get_or_compile(wasm_bytes)?;
    let ctx = HostCtx::new(
        contract_addr.clone(),
        deployer_addr.to_string(),
        env.block_height,
        env.timestamp,
        ContractState::default(),
    );
    let (ctx_out, ru_used, _) = run_entrypoint(&module, ctx, "init", init_args, env.fuel)?;

    if !env.allow_transfers && !ctx_out.transfers.is_empty() {
        return Err(VmError::ExecutionError(TRANSFERS_DISABLED.into()));
    }

    let manifest = ContractManifest {
        name:           format!("contract_{}", &contract_addr[..8]),
        version:        "0.1.0".into(),
        code_hash:      code_hash.clone(),
        deployer:       deployer_addr.to_string(),
        deployed_at:    env.timestamp,
        upgrade_policy: UpgradePolicy::Immutable,
    };

    Ok(DeployEffects {
        result: DeployResult {
            contract_address: contract_addr,
            code_hash,
            ru_used,
            events: ctx_out.events,
            transfers: ctx_out.transfers,
        },
        existed:  false,
        code:     wasm_bytes.to_vec(),
        state:    ctx_out.state,
        manifest: Some(manifest),
    })
}

fn failed_call(ru_used: u64, error: String) -> CallEffects {
    CallEffects {
        result: CallResult {
            success:    false,
            return_val: vec![],
            ru_used,
            events:     vec![],
            error:      Some(error),
            transfers:  vec![],
        },
        states: BTreeMap::new(),
    }
}

pub fn call_on(
    src:           &dyn ContractSource,
    contract_addr: &str,
    caller_addr:   &str,
    entrypoint:    &str,
    args:          &[u8],
    env:           ExecEnv,
) -> Result<CallEffects, VmError> {
    let wasm_bytes = src.code(contract_addr)
        .ok_or_else(|| VmError::StorageError(format!("Code not found for {}", contract_addr)))?;
    let module = get_or_compile(&wasm_bytes)?;

    let ctx = HostCtx::new(
        contract_addr.to_string(),
        caller_addr.to_string(),
        env.block_height,
        env.timestamp,
        src.state(contract_addr),
    );

    let (ctx_out, ru_used, return_val) = match run_entrypoint(&module, ctx, entrypoint, args, env.fuel) {
        Ok(out) => out,
        Err(VmError::FuelExhausted) => return Ok(failed_call(env.fuel, "Fuel exhausted".into())),
        Err(e) => return Ok(failed_call(0, e.to_string())),
    };

    let mut touched: BTreeMap<String, ContractState> = BTreeMap::new();
    touched.insert(contract_addr.to_string(), ctx_out.state);
    let mut all_events = ctx_out.events;
    let mut all_transfers = ctx_out.transfers;
    let mut all_ru = ru_used;
    let mut pending = ctx_out.pending_cross_calls;
    let mut depth = 1u32;

    while !pending.is_empty() && depth < 8 {
        let current_pending = std::mem::take(&mut pending);
        for cross_req in current_pending {
            let Some(cross_wasm) = src.code(&cross_req.contract_addr) else { continue };
            let Ok(cross_module) = get_or_compile(&cross_wasm) else { continue };
            let cross_state = touched.get(&cross_req.contract_addr).cloned()
                .unwrap_or_else(|| src.state(&cross_req.contract_addr));
            let mut cross_ctx = HostCtx::new(
                cross_req.contract_addr.clone(),
                contract_addr.to_string(),
                env.block_height,
                env.timestamp,
                cross_state,
            );
            cross_ctx.call_depth = depth;
            let cross_fuel = cross_req.fuel.min(MAX_CROSS_CALL_FUEL);

            if let Ok((cross_out, cross_ru, _)) = run_entrypoint(
                &cross_module,
                cross_ctx,
                &cross_req.entrypoint,
                &cross_req.args,
                cross_fuel,
            ) {
                all_events.extend(cross_out.events);
                all_transfers.extend(cross_out.transfers);
                all_ru += cross_ru;
                touched.insert(cross_req.contract_addr.clone(), cross_out.state);
                pending.extend(cross_out.pending_cross_calls);
            }
        }
        depth += 1;
    }

    if !env.allow_transfers && !all_transfers.is_empty() {
        return Ok(failed_call(all_ru, TRANSFERS_DISABLED.into()));
    }

    Ok(CallEffects {
        result: CallResult {
            success:    true,
            return_val,
            ru_used:    all_ru,
            events:     all_events,
            error:      None,
            transfers:  all_transfers,
        },
        states: touched,
    })
}

fn val_type_name(vt: &wasmtime::ValType) -> &'static str {
    if vt.is_i64()      { "u64" }
    else if vt.is_i32() { "u32" }
    else if vt.is_f32() { "f32" }
    else if vt.is_f64() { "f64" }
    else                { "?" }
}

pub fn exported_functions(wasm_bytes: &[u8]) -> Result<Vec<String>, VmError> {
    let module = get_or_compile(wasm_bytes)?;
    let mut out = Vec::new();
    for export in module.exports() {
        let wasmtime::ExternType::Func(ft) = export.ty() else { continue };
        let name = export.name();
        if name.starts_with("__") { continue; }
        let params: Vec<&str> = ft.params().map(|t| val_type_name(&t)).collect();
        let results: Vec<&str> = ft.results().map(|t| val_type_name(&t)).collect();
        out.push(if results.is_empty() {
            format!("{}({})", name, params.join(", "))
        } else {
            format!("{}({}) \u{2192} {}", name, params.join(", "), results.join(", "))
        });
    }
    Ok(out)
}

pub struct Executor {
    pub store: StateStore,
}

impl Executor {
    pub fn new(data_dir: std::path::PathBuf) -> Result<Self, VmError> {
        let _ = get_engine(); // ensure static engine is initialized
        Ok(Self {
            store: StateStore::new(data_dir),
        })
    }

    pub fn deploy(
        &self,
        wasm_bytes:    &[u8],
        deployer_addr: &str,
        init_args:     &[u8],
        block_height:  u64,
        timestamp:     i64,
        fuel:          u64,
    ) -> Result<DeployResult, VmError> {
        let env = ExecEnv { block_height, timestamp, fuel, allow_transfers: true };
        let fx = deploy_on(&self.store, wasm_bytes, deployer_addr, init_args, env)?;
        if !fx.existed {
            let addr = &fx.result.contract_address;
            self.store.store_code(addr, &fx.code)?;
            self.store.save_state(addr, &fx.state)?;
            if let Some(manifest) = &fx.manifest {
                self.store.store_manifest(addr, manifest)?;
            }
        }
        Ok(fx.result)
    }

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
        let env = ExecEnv { block_height, timestamp, fuel, allow_transfers: true };
        let fx = call_on(&self.store, contract_addr, caller_addr, entrypoint, args, env)?;
        for (addr, state) in &fx.states {
            self.store.save_state(addr, state)?;
        }
        Ok(fx.result)
    }
}

fn result_bytes(results: &[wasmtime::Val]) -> Vec<u8> {
    match results.first() {
        Some(wasmtime::Val::I64(v)) => v.to_le_bytes().to_vec(),
        Some(wasmtime::Val::I32(v)) => v.to_le_bytes().to_vec(),
        Some(wasmtime::Val::F32(bits)) => bits.to_le_bytes().to_vec(),
        Some(wasmtime::Val::F64(bits)) => bits.to_le_bytes().to_vec(),
        _ => vec![],
    }
}

fn run_entrypoint(
    module:     &Module,
    ctx:        HostCtx,
    entrypoint: &str,
    args:       &[u8],
    fuel:       u64,
) -> Result<(HostCtx, u64, Vec<u8>), VmError> {
    let mut store = Store::new(get_engine(), ctx);
    store.set_fuel(fuel)
        .map_err(|e| VmError::ExecutionError(e.to_string()))?;

    store.limiter(|ctx| &mut ctx.limiter);

    let linker = build_linker(get_engine())?;

    let instance = linker.instantiate(&mut store, module)
        .map_err(|e| VmError::InstantiationError(e.to_string()))?;

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

    let func = instance.get_func(&mut store, entrypoint)
        .ok_or_else(|| VmError::InvalidAbi(format!("Entrypoint '{}' not found", entrypoint)))?;

    let param_types: Vec<wasmtime::ValType> = func.ty(&store).params().collect();
    let wasm_args: Vec<wasmtime::Val> = if param_types.is_empty() {
        vec![]
    } else {
        let mut decoded = Vec::with_capacity(param_types.len());
        let mut off = 0usize;
        for vt in &param_types {
            if vt.is_i32() {
                if off + 4 > args.len() { break; }
                let v = i32::from_le_bytes(args[off..off+4].try_into().unwrap());
                decoded.push(wasmtime::Val::I32(v));
                off += 4;
            } else if vt.is_i64() {
                if off + 8 > args.len() { break; }
                let v = i64::from_le_bytes(args[off..off+8].try_into().unwrap());
                decoded.push(wasmtime::Val::I64(v));
                off += 8;
            } else if vt.is_f32() {
                if off + 4 > args.len() { break; }
                let bits = u32::from_le_bytes(args[off..off+4].try_into().unwrap());
                decoded.push(wasmtime::Val::F32(bits));
                off += 4;
            } else if vt.is_f64() {
                if off + 8 > args.len() { break; }
                let bits = u64::from_le_bytes(args[off..off+8].try_into().unwrap());
                decoded.push(wasmtime::Val::F64(bits));
                off += 8;
            } else {
                decoded.push(default_val(vt));
            }
        }

        while decoded.len() < param_types.len() {
            decoded.push(default_val(&param_types[decoded.len()]));
        }
        decoded
    };

    let result_types: Vec<wasmtime::ValType> = func.ty(&store).results().collect();
    let mut results: Vec<wasmtime::Val> = result_types.iter().map(default_val).collect();

    let result = func.call(&mut store, &wasm_args, &mut results);

    let fuel_remaining = store.get_fuel().unwrap_or(0);
    let ru_used = fuel.saturating_sub(fuel_remaining);

    match result {
        Ok(_) => {
            let ctx_out = store.into_data();
            Ok((ctx_out, ru_used, result_bytes(&results)))
        }
        Err(ref e) => {

            if e.downcast_ref::<Trap>() == Some(&Trap::OutOfFuel) {
                return Err(VmError::FuelExhausted);
            }
            Err(VmError::ExecutionError(e.to_string()))
        }
    }
}

fn build_linker(engine: &Engine) -> Result<Linker<HostCtx>, VmError> {
    let _ = engine; // use static engine
    let mut linker = Linker::<HostCtx>::new(get_engine());

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
        // Enforce key and value size limits to prevent DoS via state bloat.
        if prefix_len < 0 || prefix_len > MAX_STORAGE_KEY_LEN { return; }
        if key_len    < 0 || key_len    > MAX_STORAGE_KEY_LEN { return; }
        if val_len    < 0 || val_len    > MAX_STORAGE_VAL_LEN { return; }
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

    linker.func_wrap("env", "sys_block_height", |caller: Caller<'_, HostCtx>| -> i64 {
        caller.data().block_height as i64
    }).map_err(|e| VmError::ExecutionError(e.to_string()))?;

    // ── sys.timestamp() → i64 ──
    linker.func_wrap("env", "sys_timestamp", |caller: Caller<'_, HostCtx>| -> i64 {
        caller.data().timestamp
    }).map_err(|e| VmError::ExecutionError(e.to_string()))?;

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

    // Returns Result so a failing assertion raises a Wasmtime trap instead of
    // panicking the host process.
    linker.func_wrap("env", "urego_assert", |_caller: Caller<'_, HostCtx>, cond: i32|
        -> Result<(), anyhow::Error>
    {
        if cond == 0 {
            anyhow::bail!("urego assertion failed");
        }
        Ok(())
    }).map_err(|e| VmError::ExecutionError(e.to_string()))?;

    // ════════════════════════════════════════════════════════════════════════
    // EGO-20 Token Standard Host Functions
    // Defined by EGO-20 (see /eips/EGO-20.md).
    // These helpers emit standardised events and access token storage so that
    // any EGO-20 contract can use the canonical topics/layouts without
    // re-implementing encoding in Urego bytecode.
    // ════════════════════════════════════════════════════════════════════════

    // ── ego20.emit_transfer(from_ptr, from_len, to_ptr, to_len, amount_lo, amount_hi) ──
    // Emits topic "EGO20:Transfer" with payload "<from>:<to>:<amount_u128>"
    linker.func_wrap("env", "ego20_emit_transfer", |mut caller: Caller<'_, HostCtx>,
        from_ptr: i32, from_len: i32,
        to_ptr:   i32, to_len:   i32,
        amount_lo: i64, amount_hi: i64|
    {
        caller.data_mut().host_ru += ru_cost::EGO20_EMIT_EVENT;
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m, None => return,
        };
        let data = mem.data(&caller).to_vec();
        let from   = read_str(&data, from_ptr, from_len).unwrap_or_default();
        let to     = read_str(&data, to_ptr, to_len).unwrap_or_default();
        let amount = ((amount_hi as u128) << 64) | (amount_lo as u64 as u128);
        let payload = format!("{}:{}:{}", from, to, amount).into_bytes();
        let ctx = caller.data_mut();
        ctx.events.push(crate::types::ContractEvent {
            contract:  ctx.contract_addr.clone(),
            topic:     "EGO20:Transfer".into(),
            payload,
            height:    ctx.block_height,
            timestamp: ctx.timestamp,
        });
    }).map_err(|e| VmError::ExecutionError(e.to_string()))?;

    linker.func_wrap("env", "ego20_emit_approval", |mut caller: Caller<'_, HostCtx>,
        owner_ptr:   i32, owner_len:   i32,
        spender_ptr: i32, spender_len: i32,
        amount_lo: i64, amount_hi: i64|
    {
        caller.data_mut().host_ru += ru_cost::EGO20_EMIT_EVENT;
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m, None => return,
        };
        let data    = mem.data(&caller).to_vec();
        let owner   = read_str(&data, owner_ptr, owner_len).unwrap_or_default();
        let spender = read_str(&data, spender_ptr, spender_len).unwrap_or_default();
        let amount  = ((amount_hi as u128) << 64) | (amount_lo as u64 as u128);
        let payload = format!("{}:{}:{}", owner, spender, amount).into_bytes();
        let ctx = caller.data_mut();
        ctx.events.push(crate::types::ContractEvent {
            contract:  ctx.contract_addr.clone(),
            topic:     "EGO20:Approval".into(),
            payload,
            height:    ctx.block_height,
            timestamp: ctx.timestamp,
        });
    }).map_err(|e| VmError::ExecutionError(e.to_string()))?;

    // ── ego20.balance_get(addr_ptr, addr_len) → i64 (low 64 bits of u128) ──
    // Reads storage prefix "ego20:bal", key = address → u128 LE bytes.
    // Returns the low 64 bits; use ego20_balance_get_hi for the high 64 bits.
    // (Most token supplies fit in u64; the split allows u128 without multi-value returns.)
    linker.func_wrap("env", "ego20_balance_get", |mut caller: Caller<'_, HostCtx>,
        addr_ptr: i32, addr_len: i32|
    -> i64 {
        caller.data_mut().host_ru += ru_cost::STORAGE_GET;
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m, None => return 0,
        };
        let data = mem.data(&caller).to_vec();
        let addr = match read_str(&data, addr_ptr, addr_len) { Some(s) => s, None => return 0 };
        match caller.data().state.get("ego20:bal", &addr) {
            Some(v) if v.len() == 16 => {
                let lo = u64::from_le_bytes(v[0..8].try_into().unwrap_or([0u8;8]));
                lo as i64
            }
            _ => 0,
        }
    }).map_err(|e| VmError::ExecutionError(e.to_string()))?;

    linker.func_wrap("env", "ego20_balance_get_hi", |mut caller: Caller<'_, HostCtx>,
        addr_ptr: i32, addr_len: i32|
    -> i64 {
        caller.data_mut().host_ru += ru_cost::STORAGE_GET;
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m, None => return 0,
        };
        let data = mem.data(&caller).to_vec();
        let addr = match read_str(&data, addr_ptr, addr_len) { Some(s) => s, None => return 0 };
        match caller.data().state.get("ego20:bal", &addr) {
            Some(v) if v.len() == 16 => {
                let hi = u64::from_le_bytes(v[8..16].try_into().unwrap_or([0u8;8]));
                hi as i64
            }
            _ => 0,
        }
    }).map_err(|e| VmError::ExecutionError(e.to_string()))?;

    // ── ego20.balance_set(addr_ptr, addr_len, amount_lo, amount_hi) ──
    // Writes 16 LE bytes to storage prefix "ego20:bal", key = address.
    linker.func_wrap("env", "ego20_balance_set", |mut caller: Caller<'_, HostCtx>,
        addr_ptr: i32, addr_len: i32,
        amount_lo: i64, amount_hi: i64|
    {
        caller.data_mut().host_ru += ru_cost::STORAGE_SET;
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m, None => return,
        };
        let data = mem.data(&caller).to_vec();
        let addr = match read_str(&data, addr_ptr, addr_len) { Some(s) => s, None => return };
        let lo = amount_lo as u64;
        let hi = amount_hi as u64;
        let mut bytes = [0u8; 16];
        bytes[0..8].copy_from_slice(&lo.to_le_bytes());
        bytes[8..16].copy_from_slice(&hi.to_le_bytes());
        caller.data_mut().state.set("ego20:bal", &addr, bytes.to_vec());
    }).map_err(|e| VmError::ExecutionError(e.to_string()))?;

    linker.func_wrap("env", "ego20_allowance_get", |mut caller: Caller<'_, HostCtx>,
        owner_ptr: i32, owner_len: i32,
        spender_ptr: i32, spender_len: i32|
    -> i64 {
        caller.data_mut().host_ru += ru_cost::STORAGE_GET;
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m, None => return 0,
        };
        let data    = mem.data(&caller).to_vec();
        let owner   = match read_str(&data, owner_ptr, owner_len)   { Some(s) => s, None => return 0 };
        let spender = match read_str(&data, spender_ptr, spender_len) { Some(s) => s, None => return 0 };
        let key = format!("{}:{}", owner, spender);
        match caller.data().state.get("ego20:alw", &key) {
            Some(v) if v.len() == 16 => {
                let lo = u64::from_le_bytes(v[0..8].try_into().unwrap_or([0u8;8]));
                lo as i64
            }
            _ => 0,
        }
    }).map_err(|e| VmError::ExecutionError(e.to_string()))?;

    // ── ego20.allowance_set(owner_ptr, owner_len, spender_ptr, spender_len, amount_lo, amount_hi) ──
    linker.func_wrap("env", "ego20_allowance_set", |mut caller: Caller<'_, HostCtx>,
        owner_ptr: i32, owner_len: i32,
        spender_ptr: i32, spender_len: i32,
        amount_lo: i64, amount_hi: i64|
    {
        caller.data_mut().host_ru += ru_cost::STORAGE_SET;
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m, None => return,
        };
        let data    = mem.data(&caller).to_vec();
        let owner   = match read_str(&data, owner_ptr, owner_len)     { Some(s) => s, None => return };
        let spender = match read_str(&data, spender_ptr, spender_len) { Some(s) => s, None => return };
        let lo = amount_lo as u64;
        let hi = amount_hi as u64;
        let mut bytes = [0u8; 16];
        bytes[0..8].copy_from_slice(&lo.to_le_bytes());
        bytes[8..16].copy_from_slice(&hi.to_le_bytes());
        let key = format!("{}:{}", owner, spender);
        caller.data_mut().state.set("ego20:alw", &key, bytes.to_vec());
    }).map_err(|e| VmError::ExecutionError(e.to_string()))?;

    linker.func_wrap("env", "ego_cross_call", |mut caller: Caller<'_, HostCtx>,
        contract_ptr: i32, contract_len: i32,
        fn_ptr: i32, fn_len: i32,
        args_ptr: i32, args_len: i32,
        fuel: i64|
    -> i32 {
        caller.data_mut().host_ru += ru_cost::CROSS_CALL;
        if caller.data().call_depth >= 8 {
            return 0; // depth limit exceeded
        }
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m, None => return 0,
        };
        let data = mem.data(&caller).to_vec();
        let contract = match read_str(&data, contract_ptr, contract_len) { Some(s) => s, None => return 0 };
        let entrypoint = match read_str(&data, fn_ptr, fn_len) { Some(s) => s, None => return 0 };
        let args = read_bytes(&data, args_ptr, args_len).unwrap_or_default();
        // Cap fuel to prevent contracts from injecting unlimited compute budgets.
        let capped_fuel = (fuel as u64).min(MAX_CROSS_CALL_FUEL);
        caller.data_mut().pending_cross_calls.push(crate::host::CrossCallRequest {
            contract_addr: contract,
            entrypoint,
            args,
            fuel: capped_fuel,
        });
        1
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
    let end   = start.checked_add(len as usize)?; // overflow-safe
    if end > mem.len() { return None; }
    Some(mem[start..end].to_vec())
}
