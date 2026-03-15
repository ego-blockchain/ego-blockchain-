use wasmtime::{StoreLimits, StoreLimitsBuilder};
use crate::state::ContractState;
use crate::types::{ContractEvent, MAX_MEMORY_PAGES};

/// A pending cross-contract call queued by the `ego_cross_call` host function.
/// Executed breadth-first after the current WASM frame returns.
#[derive(Debug, Clone)]
pub struct CrossCallRequest {
    pub contract_addr: String,
    pub entrypoint: String,
    pub args: Vec<u8>,
    pub fuel: u64,
}

/// All mutable context passed into host functions during a single call.
/// Wasmtime host functions get a `&mut HostCtx` via the Store's data.
pub struct HostCtx {
    /// The contract being executed right now.
    pub contract_addr: String,
    /// Caller's Ego address (empty for init/deploy).
    pub caller: String,
    /// Current block height (sysvar).
    pub block_height: u64,
    /// Current block timestamp (sysvar).
    pub timestamp: i64,
    /// Mutable contract state (loaded before call, saved after).
    pub state: ContractState,
    /// Events emitted during this call.
    pub events: Vec<ContractEvent>,
    /// Native EGOC transfer requests queued during call (processed after execution).
    pub transfers: Vec<(String, u64)>, // (to_addr, amount_uegoc)
    /// RU consumed by host calls (added to Wasmtime fuel tracking).
    pub host_ru: u64,
    /// Memory/resource limiter used by Wasmtime's store.limiter().
    pub limiter: StoreLimits,
    /// Call depth to prevent infinite recursion. Max 8.
    pub call_depth: u32,
    /// Pending sub-call requests queued by ego_cross_call host func.
    /// Each entry: (contract_addr, entrypoint, args_bytes, fuel_limit)
    pub pending_cross_calls: Vec<CrossCallRequest>,
}

impl HostCtx {
    pub fn new(
        contract_addr: String,
        caller: String,
        block_height: u64,
        timestamp: i64,
        state: ContractState,
    ) -> Self {
        let limiter = StoreLimitsBuilder::new()
            .memory_size(MAX_MEMORY_PAGES as usize * 65536)
            .instances(1)
            .tables(10)
            .memories(1)
            .build();
        Self {
            contract_addr,
            caller,
            block_height,
            timestamp,
            state,
            events: Vec::new(),
            transfers: Vec::new(),
            host_ru: 0,
            limiter,
            call_depth: 0,
            pending_cross_calls: Vec::new(),
        }
    }
}

/// Host RU costs for each operation.
pub mod ru_cost {
    pub const STORAGE_GET:      u64 = 100;
    pub const STORAGE_SET:      u64 = 500;
    pub const STORAGE_DEL:      u64 = 200;
    pub const EVENTS_EMIT:      u64 = 300;
    pub const BLAKE2S:          u64 = 200;
    pub const BLAKE3:           u64 = 200;
    pub const EGOC_BALANCE:     u64 = 50;
    pub const EGOC_TRANSFER:    u64 = 1_000;
    pub const SYSVAR:           u64 = 10;
    // EGO-20 specific costs (EGO-20 spec §5)
    pub const EGO20_EMIT_EVENT: u64 = 400;   // slightly more than generic emit (canonical encoding)
    pub const CROSS_CALL:       u64 = 5_000; // base cost per cross-contract call
}
