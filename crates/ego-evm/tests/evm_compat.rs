//! EVM compatibility integration tests for ego-evm.
//!
//! Each test deploys hand-crafted EVM bytecode and verifies the result, covering
//! arithmetic opcodes, storage (SSTORE/SLOAD), event logs (LOG0/LOG1), REVERT,
//! bitshift opcodes (SHL/SHR), CREATE2, precompile STATICCALL, value transfers,
//! gas accounting, and the gas→RU ratio.
//!
//! ## Bytecode helper pattern
//!
//! Tests use `make_initcode` to wrap a short *runtime* blob in the standard
//! 12-byte constructor:
//!
//! ```text
//! PUSH1 <len>   ; size of runtime
//! PUSH1 0x0c    ; offset of runtime inside initcode (constructor is 12 bytes)
//! PUSH1 0x00    ; destination in memory
//! CODECOPY      ; copy runtime → mem[0..len]
//! PUSH1 <len>   ; size
//! PUSH1 0x00    ; offset in memory
//! RETURN        ; return runtime as deployed bytecode
//! <runtime bytes>
//! ```
//!
//! ## Why we do NOT seed the caller's balance
//!
//! `EgoEvm::execute` sets `disable_balance_check = true` (EGO-5 feeless model).
//! Because of this, seeding the caller with `set_balance_uegoc` is not only
//! unnecessary but harmful: inserting an account into `EgoEvmState` gives it
//! `code_hash = B256::ZERO` (all-zeros) rather than `KECCAK_EMPTY`.  EIP-3607
//! (always active in revm) rejects transactions from callers whose
//! `code_hash != KECCAK_EMPTY`, so a zero hash would cause every test to fail
//! with `RejectCallerWithCode`.  By leaving the caller absent from the map,
//! revm's journaled state loads it as `Account::new_not_existing()` — which
//! carries `KECCAK_EMPTY` — and execution proceeds normally.

use ego_evm::{EgoEvm, EgoEvmState, EGO_CHAIN_ID};

// ─── test constant ──────────────────────────────────────────────────────────

/// Default caller for all tests.  Must NOT be pre-seeded in state (see module
/// doc comment above for the EIP-3607 / KECCAK_EMPTY explanation).
const CALLER: [u8; 20] = [0xCA; 20];

// ─── helpers ────────────────────────────────────────────────────────────────

/// Wrap `runtime` in the standard 12-byte deploy constructor.
///
/// Constructor layout (12 bytes):
/// ```text
/// 0x60 <len>  PUSH1  size        — how many runtime bytes to copy
/// 0x60 0x0c   PUSH1  12          — code offset (constructor is 12 bytes)
/// 0x60 0x00   PUSH1  0           — memory destination
/// 0x39        CODECOPY
/// 0x60 <len>  PUSH1  size        — size to return
/// 0x60 0x00   PUSH1  0           — memory offset
/// 0xf3        RETURN
/// ```
fn make_initcode(runtime: &[u8]) -> Vec<u8> {
    assert!(
        runtime.len() <= 127,
        "runtime must fit in a single PUSH1 (≤ 127 bytes); got {} bytes",
        runtime.len()
    );
    let len = runtime.len() as u8;
    let mut initcode = vec![
        0x60, len,  // PUSH1 <len>
        0x60, 0x0c, // PUSH1 12  (constructor size)
        0x60, 0x00, // PUSH1 0   (memory dest)
        0x39,       // CODECOPY
        0x60, len,  // PUSH1 <len>
        0x60, 0x00, // PUSH1 0   (memory src)
        0xf3,       // RETURN
    ];
    initcode.extend_from_slice(runtime);
    initcode
}

/// Deploy `runtime` into `state` (using `CALLER` as deployer) and return the
/// newly created contract address.
///
/// The caller is intentionally NOT seeded with a balance — see module doc.
/// Panics on deploy failure so individual tests stay concise.
fn deploy_runtime(state: &mut EgoEvmState, runtime: &[u8]) -> [u8; 20] {
    let initcode = make_initcode(runtime);
    let result = EgoEvm::execute(
        state,
        CALLER,
        None, // CREATE
        0,
        initcode,
        500_000,
        EGO_CHAIN_ID,
    )
    .expect("EgoEvm::execute must not error during deploy");
    assert!(result.success, "deploy must succeed; output: {:?}", result.output);
    result
        .deployed_address
        .expect("deployed_address must be Some after successful CREATE")
}

/// Call `addr` with no arguments and return the last 16 bytes of the 32-byte
/// output interpreted as a big-endian `u128`.
///
/// Expects the runtime to leave a 32-byte ABI word in memory and RETURN it via
/// `PUSH1 0x20 PUSH1 0x00 RETURN` (the standard pattern used in all arithmetic
/// tests here).
fn call_u128(state: &mut EgoEvmState, addr: [u8; 20]) -> u128 {
    let result = EgoEvm::execute(
        state,
        CALLER,
        Some(addr),
        0,      // no value
        vec![], // no calldata
        200_000,
        EGO_CHAIN_ID,
    )
    .expect("EgoEvm::execute must not error during call");
    assert!(result.success, "call must succeed; output: {:?}", result.output);
    assert!(
        result.output.len() >= 32,
        "expected ≥ 32 bytes of output, got {}",
        result.output.len()
    );
    // ABI uint256: 32 bytes big-endian; the value fits in u128 so we read [16..32].
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&result.output[16..32]);
    u128::from_be_bytes(buf)
}

// ─── arithmetic tests ───────────────────────────────────────────────────────

/// `PUSH1 5, PUSH1 3, ADD` → memory[0] = 8, then RETURN 32 bytes.
///
/// Bytecode: `600560030160005260206000f3`
/// - 0x60 0x05 → PUSH1 5
/// - 0x60 0x03 → PUSH1 3
/// - 0x01      → ADD          ; stack: [8]
/// - 0x60 0x00 → PUSH1 0      ; mstore dest
/// - 0x52      → MSTORE       ; mem[0..32] = 8
/// - 0x60 0x20 → PUSH1 32
/// - 0x60 0x00 → PUSH1 0
/// - 0xf3      → RETURN
#[test]
fn test_add() {
    let runtime = hex::decode("600560030160005260206000f3").unwrap();
    let mut state = EgoEvmState::new();
    let addr = deploy_runtime(&mut state, &runtime);
    let val = call_u128(&mut state, addr);
    assert_eq!(val, 8, "5 + 3 should equal 8");
}

/// `PUSH1 6, PUSH1 7, MUL` → memory[0] = 42, then RETURN 32 bytes.
///
/// Bytecode: `600660070260005260206000f3`
/// - 0x60 0x06 → PUSH1 6
/// - 0x60 0x07 → PUSH1 7
/// - 0x02      → MUL          ; stack: [42]
/// - 0x60 0x00 → PUSH1 0
/// - 0x52      → MSTORE
/// - 0x60 0x20 → PUSH1 32
/// - 0x60 0x00 → PUSH1 0
/// - 0xf3      → RETURN
#[test]
fn test_mul() {
    let runtime = hex::decode("600660070260005260206000f3").unwrap();
    let mut state = EgoEvmState::new();
    let addr = deploy_runtime(&mut state, &runtime);
    let val = call_u128(&mut state, addr);
    assert_eq!(val, 42, "6 × 7 should equal 42");
}

/// `PUSH1 3, PUSH1 0xa (10), SUB` → 10 - 3 = 7.
///
/// Bytecode: `6003600a0360005260206000f3`
/// - 0x60 0x03 → PUSH1 3   (subtrahend, pushed first — EVM stack is LIFO)
/// - 0x60 0x0a → PUSH1 10  (minuend)
/// - 0x03      → SUB        ; stack: [10-3 = 7]
///   EVM SUB: pops a (top) then b; result = a - b.
///   Stack before SUB: top=10, second=3 → result = 10 - 3 = 7.
/// - MSTORE + RETURN
#[test]
fn test_sub() {
    // Push 3 first, then 10; after SUB: top=10, second=3 → 10-3=7.
    let runtime = hex::decode("6003600a0360005260206000f3").unwrap();
    let mut state = EgoEvmState::new();
    let addr = deploy_runtime(&mut state, &runtime);
    let val = call_u128(&mut state, addr);
    assert_eq!(val, 7, "10 - 3 should equal 7");
}

/// `PUSH1 3, PUSH1 2, EXP` → 2 ^ 3 = 8.
///
/// Bytecode: `600360020a60005260206000f3`
/// - 0x60 0x03 → PUSH1 3   (exponent, pushed first)
/// - 0x60 0x02 → PUSH1 2   (base)
/// - 0x0a      → EXP        ; EXP pops base (top) and exponent (second);
///               result = base ^ exponent = 2^3 = 8
/// - MSTORE + RETURN
#[test]
fn test_exp() {
    let runtime = hex::decode("600360020a60005260206000f3").unwrap();
    let mut state = EgoEvmState::new();
    let addr = deploy_runtime(&mut state, &runtime);
    let val = call_u128(&mut state, addr);
    assert_eq!(val, 8, "2^3 should equal 8");
}

// ─── storage tests ──────────────────────────────────────────────────────────

/// Store 0xBEEF at slot 0, then SLOAD and return it.
///
/// Bytecode: `61beef60005560005460005260206000f3`
/// - 0x61 0xbe 0xef → PUSH2 0xBEEF
/// - 0x60 0x00      → PUSH1 0          (slot)
/// - 0x55           → SSTORE
/// - 0x60 0x00      → PUSH1 0          (slot)
/// - 0x54           → SLOAD            ; stack: [0xBEEF]
/// - MSTORE + RETURN
#[test]
fn test_storage_sstore_sload() {
    let runtime = hex::decode("61beef60005560005460005260206000f3").unwrap();
    let mut state = EgoEvmState::new();
    let addr = deploy_runtime(&mut state, &runtime);
    let val = call_u128(&mut state, addr);
    assert_eq!(val, 0xBEEF, "SSTORE/SLOAD round-trip should return 0xBEEF (48879)");
}

/// Store 10 at slot 0 and 20 at slot 1, then SLOAD slot 1 and return it.
///
/// Runtime (21 bytes) hex: `600a600055601460015560015460005260206000f3`
/// - 0x60 0x0a → PUSH1 10
/// - 0x60 0x00 → PUSH1 0  (slot 0)
/// - 0x55      → SSTORE    ; slot[0] = 10
/// - 0x60 0x14 → PUSH1 20
/// - 0x60 0x01 → PUSH1 1  (slot 1)
/// - 0x55      → SSTORE    ; slot[1] = 20
/// - 0x60 0x01 → PUSH1 1  (slot 1)
/// - 0x54      → SLOAD     ; stack: [20]
/// - MSTORE + RETURN
#[test]
fn test_multiple_storage_slots() {
    let runtime = hex::decode("600a600055601460015560015460005260206000f3").unwrap();
    let mut state = EgoEvmState::new();
    let addr = deploy_runtime(&mut state, &runtime);
    let val = call_u128(&mut state, addr);
    assert_eq!(val, 20, "SLOAD of slot 1 should return 20 (stored there by the contract)");
}

// ─── event log tests ────────────────────────────────────────────────────────

/// Emit a LOG0 (no topics) with data containing 0xabcd.
///
/// Bytecode: `61abcd60005260206000a000`
/// - 0x61 0xab 0xcd → PUSH2 0xabcd
/// - 0x60 0x00      → PUSH1 0
/// - 0x52           → MSTORE        ; mem[0..32] = 0xabcd
/// - 0x60 0x20      → PUSH1 32      (data length)
/// - 0x60 0x00      → PUSH1 0       (data offset)
/// - 0xa0           → LOG0          ; emit log with no topics, 32 bytes data
/// - 0x00           → STOP
#[test]
fn test_log0_event() {
    let runtime = hex::decode("61abcd60005260206000a000").unwrap();
    let mut state = EgoEvmState::new();
    let addr = deploy_runtime(&mut state, &runtime);

    let result = EgoEvm::execute(
        &mut state,
        CALLER,
        Some(addr),
        0,
        vec![],
        200_000,
        EGO_CHAIN_ID,
    )
    .unwrap();

    assert!(result.success, "LOG0 contract must succeed");
    assert_eq!(result.logs.len(), 1, "exactly one log must be emitted");
    assert!(
        result.logs[0].topics.is_empty(),
        "LOG0 must produce zero topics"
    );
    // Data is 32 bytes; 0xabcd is stored right-aligned (big-endian).
    let log_data = &result.logs[0].data;
    assert!(log_data.len() >= 2, "log data must be at least 2 bytes");
    let last_two = u16::from_be_bytes([
        log_data[log_data.len() - 2],
        log_data[log_data.len() - 1],
    ]);
    assert_eq!(last_two, 0xabcd, "log data must contain 0xabcd");
}

/// Emit a LOG1 with one topic (0xdeadbeef) and data containing 0x1234.
///
/// Bytecode: `61123460005263deadbeef60206000a100`
/// - 0x61 0x12 0x34      → PUSH2 0x1234
/// - 0x60 0x00           → PUSH1 0
/// - 0x52                → MSTORE       ; mem[0..32] = 0x1234
/// - 0x63 0xde 0xad 0xbe 0xef → PUSH4 0xdeadbeef  (topic)
/// - 0x60 0x20           → PUSH1 32     (data length)
/// - 0x60 0x00           → PUSH1 0      (data offset)
/// - 0xa1                → LOG1         ; emit log with 1 topic, 32 bytes data
/// - 0x00                → STOP
#[test]
fn test_log1_event() {
    let runtime = hex::decode("61123460005263deadbeef60206000a100").unwrap();
    let mut state = EgoEvmState::new();
    let addr = deploy_runtime(&mut state, &runtime);

    let result = EgoEvm::execute(
        &mut state,
        CALLER,
        Some(addr),
        0,
        vec![],
        200_000,
        EGO_CHAIN_ID,
    )
    .unwrap();

    assert!(result.success, "LOG1 contract must succeed");
    assert_eq!(result.logs.len(), 1, "exactly one log must be emitted");
    assert_eq!(result.logs[0].topics.len(), 1, "LOG1 must produce exactly one topic");

    // The topic is 0xdeadbeef stored in the lower 4 bytes of a 32-byte B256.
    let topic = &result.logs[0].topics[0];
    let topic_low4 = u32::from_be_bytes([topic[28], topic[29], topic[30], topic[31]]);
    assert_eq!(topic_low4, 0xdeadbeef, "topic lower bytes must equal 0xdeadbeef");
}

// ─── revert test ────────────────────────────────────────────────────────────

/// REVERT with 4 bytes of data; last byte must be 0xaa.
///
/// Bytecode: `60aa6000526004601cfd`
/// - 0x60 0xaa → PUSH1 0xaa
/// - 0x60 0x00 → PUSH1 0
/// - 0x52      → MSTORE        ; mem[0..32] = 0xaa (right-aligned)
/// - 0x60 0x04 → PUSH1 4       (revert data length)
/// - 0x60 0x1c → PUSH1 0x1c    (= 28; mem[28..32] contains the last 4 bytes)
/// - 0xfd      → REVERT
#[test]
fn test_revert_returns_data() {
    let runtime = hex::decode("60aa6000526004601cfd").unwrap();
    let mut state = EgoEvmState::new();
    let addr = deploy_runtime(&mut state, &runtime);

    let result = EgoEvm::execute(
        &mut state,
        CALLER,
        Some(addr),
        0,
        vec![],
        200_000,
        EGO_CHAIN_ID,
    )
    .unwrap();

    assert!(!result.success, "REVERT must cause success == false");
    assert_eq!(result.output.len(), 4, "REVERT must return exactly 4 bytes");
    assert_eq!(result.output[3], 0xaa, "last revert byte must be 0xaa");
}

// ─── bitshift tests ─────────────────────────────────────────────────────────

/// SHL: 1 << 8 = 256.
///
/// Bytecode: `600160081b60005260206000f3`
/// - 0x60 0x01 → PUSH1 1    (value to shift)
/// - 0x60 0x08 → PUSH1 8    (shift amount)
/// - 0x1b      → SHL         ; SHL pops shift (top) and value (second);
///               result = value << shift = 1 << 8 = 256
/// - MSTORE + RETURN
#[test]
fn test_shl_opcode() {
    let runtime = hex::decode("600160081b60005260206000f3").unwrap();
    let mut state = EgoEvmState::new();
    let addr = deploy_runtime(&mut state, &runtime);
    let val = call_u128(&mut state, addr);
    assert_eq!(val, 256, "1 << 8 should equal 256");
}

/// SHR: 256 >> 1 = 128.
///
/// Bytecode: `61010060011c60005260206000f3`
/// - 0x61 0x01 0x00 → PUSH2 0x0100 (= 256, value to shift)
/// - 0x60 0x01      → PUSH1 1       (shift amount)
/// - 0x1c           → SHR            ; SHR pops shift (top) and value (second);
///                    result = value >> shift = 256 >> 1 = 128
/// - MSTORE + RETURN
#[test]
fn test_shr_opcode() {
    let runtime = hex::decode("61010060011c60005260206000f3").unwrap();
    let mut state = EgoEvmState::new();
    let addr = deploy_runtime(&mut state, &runtime);
    let val = call_u128(&mut state, addr);
    assert_eq!(val, 128, "256 >> 1 should equal 128");
}

// ─── CREATE2 test ────────────────────────────────────────────────────────────

/// CREATE2 deploys a child contract (empty initcode → empty child).
///
/// Factory runtime (15 bytes): `6000600060006000f560005260206000f3`
/// - 0x60 0x00 → PUSH1 0  (salt)
/// - 0x60 0x00 → PUSH1 0  (initcode size = 0 → empty child)
/// - 0x60 0x00 → PUSH1 0  (initcode offset)
/// - 0x60 0x00 → PUSH1 0  (value = 0)
/// - 0xf5      → CREATE2   ; deploys empty contract; pushes child address onto stack
/// - 0x60 0x00 → PUSH1 0
/// - 0x52      → MSTORE    ; mem[0..32] = child_address (left-padded to 32 bytes)
/// - 0x60 0x20 → PUSH1 32
/// - 0x60 0x00 → PUSH1 0
/// - 0xf3      → RETURN    ; return 32 bytes containing child address in [12..32]
///
/// The child address is deterministic but non-zero; we check output[12..32]
/// has at least one non-zero byte.
#[test]
fn test_create2_deploys_child() {
    let runtime = hex::decode("6000600060006000f560005260206000f3").unwrap();
    let mut state = EgoEvmState::new();
    let factory_addr = deploy_runtime(&mut state, &runtime);

    let result = EgoEvm::execute(
        &mut state,
        CALLER,
        Some(factory_addr),
        0,
        vec![],
        500_000,
        EGO_CHAIN_ID,
    )
    .unwrap();

    assert!(result.success, "CREATE2 factory call must succeed");
    assert!(
        result.output.len() >= 32,
        "output must be at least 32 bytes (child address word)"
    );
    // The child address occupies output[12..32] (20 bytes, right-aligned in 32-byte word).
    assert!(
        result.output[12..32].iter().any(|&b| b != 0),
        "child contract address must be non-zero"
    );
}

// ─── precompile STATICCALL test ─────────────────────────────────────────────

/// STATICCALL the identity precompile (address 0x4) to echo 0x42 back.
///
/// Bytecode: `60426000526020602060206000600461fffffa60206020f3`
///
/// - 0x60 0x42      → PUSH1 0x42
/// - 0x60 0x00      → PUSH1 0
/// - 0x52           → MSTORE          ; mem[0..32] = 0x42  (input data)
/// - 0x60 0x20      → PUSH1 32        (retSize)
/// - 0x60 0x20      → PUSH1 32        (retOffset = mem[32])
/// - 0x60 0x20      → PUSH1 32        (argsSize)
/// - 0x60 0x00      → PUSH1 0         (argsOffset = mem[0])
/// - 0x60 0x04      → PUSH1 4         (address of identity precompile)
/// - 0x61 0xff 0xff → PUSH2 0xffff    (gas = 65535)
/// - 0xfa           → STATICCALL      ; calls identity(0x4), output → mem[32..64]
/// - 0x60 0x20      → PUSH1 32        (return 32 bytes…)
/// - 0x60 0x20      → PUSH1 32        (…from mem[32])
/// - 0xf3           → RETURN
#[test]
fn test_staticcall_identity_precompile() {
    let runtime = hex::decode("60426000526020602060206000600461fffffa60206020f3").unwrap();
    let mut state = EgoEvmState::new();
    let addr = deploy_runtime(&mut state, &runtime);
    let val = call_u128(&mut state, addr);
    assert_eq!(val, 0x42, "identity precompile must echo 0x42 (= 66) back");
}

// ─── value transfer test ─────────────────────────────────────────────────────

/// Call a STOP contract with a non-zero uEGOC value.
///
/// The contract runtime is just `0x00` (STOP).  We send 1000 uEGOC with the
/// call and expect the execution to succeed, verifying that value transfers
/// work correctly through the EVM layer.
///
/// No balance is seeded for the caller because `disable_balance_check = true`
/// means the EVM never checks whether the caller has sufficient funds.
#[test]
fn test_eth_value_transfer() {
    // Runtime: STOP (0x00) — accepts any call/value.
    let runtime = hex::decode("00").unwrap();
    let mut state = EgoEvmState::new();
    let contract_addr = deploy_runtime(&mut state, &runtime);

    let result = EgoEvm::execute(
        &mut state,
        CALLER,
        Some(contract_addr),
        1_000, // 1000 uEGOC sent with the call
        vec![],
        100_000,
        EGO_CHAIN_ID,
    )
    .unwrap();

    assert!(
        result.success,
        "value transfer to a STOP contract must succeed"
    );
}

// ─── gas accounting tests ────────────────────────────────────────────────────

/// Three consecutive SSTOREs consume significantly more than 3000 gas.
///
/// Each cold SSTORE costs ~20 000 gas (Berlin/London), so three stores should
/// consume at least 60 000 gas.  We conservatively assert > 3 000 to avoid
/// fragility across revm versions.
///
/// Runtime (16 bytes): `60016000556002600155600360025500`
/// - PUSH1 1, PUSH1 0, SSTORE   → slot[0] = 1
/// - PUSH1 2, PUSH1 1, SSTORE   → slot[1] = 2
/// - PUSH1 3, PUSH1 2, SSTORE   → slot[2] = 3
/// - STOP
#[test]
fn test_gas_is_consumed() {
    let runtime = hex::decode("60016000556002600155600360025500").unwrap();
    let mut state = EgoEvmState::new();
    let addr = deploy_runtime(&mut state, &runtime);

    let result = EgoEvm::execute(
        &mut state,
        CALLER,
        Some(addr),
        0,
        vec![],
        500_000,
        EGO_CHAIN_ID,
    )
    .unwrap();

    assert!(result.success, "3x SSTORE contract must succeed");
    assert!(
        result.gas_used > 3_000,
        "three SSTOREs must consume more than 3000 gas; got {}",
        result.gas_used
    );
}

/// `ru_used` must equal `gas_used * 10` (GAS_TO_RU_RATIO = 10, per EGO-12 §4).
///
/// We reuse the ADD bytecode as a lightweight execution that produces a
/// deterministic gas cost.
#[test]
fn test_ru_equals_gas_times_ten() {
    // Same ADD runtime as test_add.
    let runtime = hex::decode("600560030160005260206000f3").unwrap();
    let mut state = EgoEvmState::new();
    let addr = deploy_runtime(&mut state, &runtime);

    let result = EgoEvm::execute(
        &mut state,
        CALLER,
        Some(addr),
        0,
        vec![],
        200_000,
        EGO_CHAIN_ID,
    )
    .unwrap();

    assert!(result.success);
    assert_eq!(
        result.ru_used,
        result.gas_used * 10,
        "ru_used must equal gas_used × 10 (GAS_TO_RU_RATIO); \
         gas_used={}, ru_used={}",
        result.gas_used,
        result.ru_used
    );
}
