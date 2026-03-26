use ego_evm::{EgoEvm, EgoEvmState, EGO_CHAIN_ID};

const CALLER: [u8; 20] = [0xCA; 20];

fn make_initcode(runtime: &[u8]) -> Vec<u8> {
    assert!(
        runtime.len() <= 127,
        "runtime must fit in a single PUSH1 (≤ 127 bytes); got {} bytes",
        runtime.len()
    );
    let len = runtime.len() as u8;
    let mut initcode = vec![
        0x60, len,
        0x60, 0x0c,
        0x60, 0x00,
        0x39,
        0x60, len,
        0x60, 0x00,
        0xf3,
    ];
    initcode.extend_from_slice(runtime);
    initcode
}

fn deploy_runtime(state: &mut EgoEvmState, runtime: &[u8]) -> [u8; 20] {
    let initcode = make_initcode(runtime);
    let result = EgoEvm::execute(
        state,
        CALLER,
        None,
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

fn call_u128(state: &mut EgoEvmState, addr: [u8; 20]) -> u128 {
    let result = EgoEvm::execute(
        state,
        CALLER,
        Some(addr),
        0,
        vec![],
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

    let mut buf = [0u8; 16];
    buf.copy_from_slice(&result.output[16..32]);
    u128::from_be_bytes(buf)
}

#[test]
fn test_add() {
    let runtime = hex::decode("600560030160005260206000f3").unwrap();
    let mut state = EgoEvmState::new();
    let addr = deploy_runtime(&mut state, &runtime);
    let val = call_u128(&mut state, addr);
    assert_eq!(val, 8, "5 + 3 should equal 8");
}

#[test]
fn test_mul() {
    let runtime = hex::decode("600660070260005260206000f3").unwrap();
    let mut state = EgoEvmState::new();
    let addr = deploy_runtime(&mut state, &runtime);
    let val = call_u128(&mut state, addr);
    assert_eq!(val, 42, "6 × 7 should equal 42");
}

#[test]
fn test_sub() {

    let runtime = hex::decode("6003600a0360005260206000f3").unwrap();
    let mut state = EgoEvmState::new();
    let addr = deploy_runtime(&mut state, &runtime);
    let val = call_u128(&mut state, addr);
    assert_eq!(val, 7, "10 - 3 should equal 7");
}

#[test]
fn test_exp() {
    let runtime = hex::decode("600360020a60005260206000f3").unwrap();
    let mut state = EgoEvmState::new();
    let addr = deploy_runtime(&mut state, &runtime);
    let val = call_u128(&mut state, addr);
    assert_eq!(val, 8, "2^3 should equal 8");
}

#[test]
fn test_storage_sstore_sload() {
    let runtime = hex::decode("61beef60005560005460005260206000f3").unwrap();
    let mut state = EgoEvmState::new();
    let addr = deploy_runtime(&mut state, &runtime);
    let val = call_u128(&mut state, addr);
    assert_eq!(val, 0xBEEF, "SSTORE/SLOAD round-trip should return 0xBEEF (48879)");
}

#[test]
fn test_multiple_storage_slots() {
    let runtime = hex::decode("600a600055601460015560015460005260206000f3").unwrap();
    let mut state = EgoEvmState::new();
    let addr = deploy_runtime(&mut state, &runtime);
    let val = call_u128(&mut state, addr);
    assert_eq!(val, 20, "SLOAD of slot 1 should return 20 (stored there by the contract)");
}

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

    let log_data = &result.logs[0].data;
    assert!(log_data.len() >= 2, "log data must be at least 2 bytes");
    let last_two = u16::from_be_bytes([
        log_data[log_data.len() - 2],
        log_data[log_data.len() - 1],
    ]);
    assert_eq!(last_two, 0xabcd, "log data must contain 0xabcd");
}

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

    let topic = &result.logs[0].topics[0];
    let topic_low4 = u32::from_be_bytes([topic[28], topic[29], topic[30], topic[31]]);
    assert_eq!(topic_low4, 0xdeadbeef, "topic lower bytes must equal 0xdeadbeef");
}

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

#[test]
fn test_shl_opcode() {
    let runtime = hex::decode("600160081b60005260206000f3").unwrap();
    let mut state = EgoEvmState::new();
    let addr = deploy_runtime(&mut state, &runtime);
    let val = call_u128(&mut state, addr);
    assert_eq!(val, 256, "1 << 8 should equal 256");
}

#[test]
fn test_shr_opcode() {
    let runtime = hex::decode("61010060011c60005260206000f3").unwrap();
    let mut state = EgoEvmState::new();
    let addr = deploy_runtime(&mut state, &runtime);
    let val = call_u128(&mut state, addr);
    assert_eq!(val, 128, "256 >> 1 should equal 128");
}

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

    assert!(
        result.output[12..32].iter().any(|&b| b != 0),
        "child contract address must be non-zero"
    );
}

#[test]
fn test_staticcall_identity_precompile() {
    let runtime = hex::decode("60426000526020602060206000600461fffffa60206020f3").unwrap();
    let mut state = EgoEvmState::new();
    let addr = deploy_runtime(&mut state, &runtime);
    let val = call_u128(&mut state, addr);
    assert_eq!(val, 0x42, "identity precompile must echo 0x42 (= 66) back");
}

#[test]
fn test_eth_value_transfer() {

    let runtime = hex::decode("00").unwrap();
    let mut state = EgoEvmState::new();
    let contract_addr = deploy_runtime(&mut state, &runtime);

    let result = EgoEvm::execute(
        &mut state,
        CALLER,
        Some(contract_addr),
        1_000,
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

#[test]
fn test_ru_equals_gas_times_ten() {

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
