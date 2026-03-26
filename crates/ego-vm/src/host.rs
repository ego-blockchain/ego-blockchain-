use wasmtime::{StoreLimits, StoreLimitsBuilder};
use crate::state::ContractState;
use crate::types::{ContractEvent, MAX_MEMORY_PAGES};

#[derive(Debug, Clone)]
pub struct CrossCallRequest {
    pub contract_addr: String,
    pub entrypoint: String,
    pub args: Vec<u8>,
    pub fuel: u64,
}

pub struct HostCtx {

    pub contract_addr: String,

    pub caller: String,

    pub block_height: u64,

    pub timestamp: i64,

    pub state: ContractState,

    pub events: Vec<ContractEvent>,

    pub transfers: Vec<(String, u64)>,

    pub host_ru: u64,

    pub limiter: StoreLimits,

    pub call_depth: u32,

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

    pub const EGO20_EMIT_EVENT: u64 = 400;
    pub const CROSS_CALL:       u64 = 5_000;
}
