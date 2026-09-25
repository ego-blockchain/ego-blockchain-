use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

use ego_vm::{ContractEvent, ContractManifest, ContractSource, ContractState, ExecEnv};
use serde::{Deserialize, Serialize};

use crate::ledger::LedgerTx;

pub const WATERMARK_KEY: &[u8] = b"contract_exec_height";
const EXEC_DEPTH: u64 = 2;
const UNDO_KEEP: u64 = 5_000;
const BLOCKS_PER_PASS: u64 = 2_000;
const LOG_ARGS_MAX_HEX: usize = 8_192;
const MAX_ADDR_LEN: usize = 128;

pub trait Kv {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
}

impl Kv for BTreeMap<Vec<u8>, Vec<u8>> {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        BTreeMap::get(self, key).cloned()
    }
}

fn keyed(tag: &str, addr: &str) -> Vec<u8> {
    format!("{tag}:{addr}").into_bytes()
}

pub fn code_key(addr: &str) -> Vec<u8> { keyed("c", addr) }
pub fn state_key(addr: &str) -> Vec<u8> { keyed("s", addr) }
pub fn manifest_key(addr: &str) -> Vec<u8> { keyed("m", addr) }
fn count_key(addr: &str) -> Vec<u8> { keyed("n", addr) }
fn sender_key(from: &str) -> Vec<u8> { keyed("q", from) }

pub fn activity_prefix(addr: &str) -> Vec<u8> {
    format!("l:{addr}:").into_bytes()
}

fn activity_key(addr: &str, seq: u64) -> Vec<u8> {
    let mut k = activity_prefix(addr);
    k.extend_from_slice(&seq.to_be_bytes());
    k
}

pub fn undo_key(height: u64) -> Vec<u8> {
    let mut k = b"u:".to_vec();
    k.extend_from_slice(&height.to_be_bytes());
    k
}

fn read_u64(b: &[u8]) -> u64 {
    <[u8; 8]>::try_from(b).map(u64::from_le_bytes).unwrap_or(0)
}

pub struct Overlay<'a> {
    base: &'a dyn Kv,
    writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl<'a> Overlay<'a> {
    pub fn new(base: &'a dyn Kv) -> Self {
        Self { base, writes: BTreeMap::new() }
    }

    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        match self.writes.get(key) {
            Some(v) => v.clone(),
            None => self.base.get(key),
        }
    }

    fn put(&mut self, key: Vec<u8>, val: Vec<u8>) {
        self.writes.insert(key, Some(val));
    }
}

impl ContractSource for Overlay<'_> {
    fn code(&self, addr: &str) -> Option<Vec<u8>> {
        self.get(&code_key(addr))
    }

    fn state(&self, addr: &str) -> ContractState {
        self.get(&state_key(addr))
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityEvent {
    pub topic: String,
    pub payload_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityEntry {
    pub seq: u64,
    pub height: u64,
    pub timestamp: i64,
    pub tx_hash: String,
    pub from: String,
    pub kind: String,
    pub entrypoint: String,
    pub args_hex: String,
    #[serde(default)]
    pub args_truncated: bool,
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    pub ru_used: u64,
    #[serde(default)]
    pub events: Vec<ActivityEvent>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UndoRecord {
    pub hash: String,
    pub prev: Vec<(String, Option<String>)>,
}

impl UndoRecord {
    fn entries(&self) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
        self.prev
            .iter()
            .filter_map(|(k, v)| {
                let key = hex::decode(k).ok()?;
                let val = match v {
                    Some(v) => Some(hex::decode(v).ok()?),
                    None => None,
                };
                Some((key, val))
            })
            .collect()
    }
}

pub struct BlockRef<'a> {
    pub height: u64,
    pub hash: &'a str,
    pub timestamp: i64,
}

pub struct BlockOutcome {
    pub writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    pub undo: UndoRecord,
    pub ran: usize,
    pub refused: Vec<String>,
}

pub fn is_contract_tx(tx: &LedgerTx) -> bool {
    matches!(tx.tx_type.as_str(), "deploy" | "call")
}

type TxResult = Result<(u64, Vec<ContractEvent>), String>;

fn env(block: &BlockRef, fuel: u64) -> ExecEnv {
    ExecEnv { block_height: block.height, timestamp: block.timestamp, fuel, allow_transfers: false }
}

pub fn execute_block(base: &dyn Kv, block: &BlockRef, txs: &[LedgerTx]) -> BlockOutcome {
    let mut ov = Overlay::new(base);
    let mut ordered: Vec<&LedgerTx> = txs.iter().filter(|t| is_contract_tx(t)).collect();
    ordered.sort_by(|a, b| {
        (a.from.as_str(), a.nonce, a.hash.as_str()).cmp(&(b.from.as_str(), b.nonce, b.hash.as_str()))
    });

    let mut ran = 0;
    let mut refused = Vec::new();
    for tx in ordered {
        if tx.from.is_empty() || tx.from.len() > MAX_ADDR_LEN || tx.contract_addr.len() > MAX_ADDR_LEN {
            continue;
        }
        let nonce_key = sender_key(&tx.from);
        let last = ov.get(&nonce_key).map(|b| read_u64(&b)).unwrap_or(0);
        if tx.nonce <= last {
            continue;
        }
        ov.put(nonce_key, tx.nonce.to_le_bytes().to_vec());

        let (addr, result) = if let Err(e) = crate::ledger::check_contract_commitment(tx) {
            (String::new(), Err(format!("its payload does not match what the sender signed ({e})")))
        } else if tx.tx_type == "deploy" {
            run_deploy(&mut ov, block, tx)
        } else {
            run_call(&mut ov, block, tx)
        };

        ran += 1;
        if let Err(e) = &result {
            refused.push(format!("{} {} from {}: {}", tx.tx_type, short(&tx.hash), short(&tx.from), e));
        }
        if !addr.is_empty() {
            record_activity(&mut ov, &addr, block, tx, &result);
        }
    }

    let undo = UndoRecord {
        hash: block.hash.to_string(),
        prev: ov
            .writes
            .keys()
            .map(|k| (hex::encode(k), base.get(k).map(hex::encode)))
            .collect(),
    };
    BlockOutcome { writes: ov.writes, undo, ran, refused }
}

fn short(s: &str) -> &str {
    s.get(..14).unwrap_or(s)
}

fn run_deploy(ov: &mut Overlay, block: &BlockRef, tx: &LedgerTx) -> (String, TxResult) {
    let wasm = match hex::decode(&tx.wasm_code) {
        Ok(w) if !w.is_empty() => w,
        _ => return (String::new(), Err("it carries no readable contract code".into())),
    };
    let (addr, _) = ego_vm::contract_address_for(&tx.from, &wasm);
    let init_args = match hex::decode(&tx.call_args) {
        Ok(a) => a,
        Err(_) => return (addr, Err("its init arguments are not valid hex".into())),
    };
    let fuel = ego_vm::types::DEFAULT_DEPLOY_FUEL;
    match ego_vm::deploy_on(&*ov, &wasm, &tx.from, &init_args, env(block, fuel)) {
        Ok(fx) if fx.existed => {
            (addr, Err("this sender already deployed this exact code at this address".into()))
        }
        Ok(fx) => {
            ov.put(code_key(&addr), fx.code);
            ov.put(state_key(&addr), serde_json::to_vec(&fx.state).unwrap_or_default());
            if let Some(m) = &fx.manifest {
                ov.put(manifest_key(&addr), serde_json::to_vec(m).unwrap_or_default());
            }
            (addr, Ok((fx.result.ru_used, fx.result.events)))
        }
        Err(e) => (addr, Err(e.to_string())),
    }
}

fn run_call(ov: &mut Overlay, block: &BlockRef, tx: &LedgerTx) -> (String, TxResult) {
    let addr = tx.contract_addr.clone();
    if ov.get(&code_key(&addr)).is_none() {
        return (String::new(), Err(format!("there is no contract at {}", short(&addr))));
    }
    let args = match hex::decode(&tx.call_args) {
        Ok(a) => a,
        Err(_) => return (addr, Err("its arguments are not valid hex".into())),
    };
    let fuel = ego_vm::types::DEFAULT_CALL_FUEL;
    match ego_vm::call_on(&*ov, &addr, &tx.from, &tx.entrypoint, &args, env(block, fuel)) {
        Err(e) => (addr, Err(e.to_string())),
        Ok(fx) if !fx.result.success => {
            (addr, Err(fx.result.error.unwrap_or_else(|| "the call failed".into())))
        }
        Ok(fx) => {
            for (a, st) in &fx.states {
                ov.put(state_key(a), serde_json::to_vec(st).unwrap_or_default());
            }
            (addr, Ok((fx.result.ru_used, fx.result.events)))
        }
    }
}

fn record_activity(ov: &mut Overlay, addr: &str, block: &BlockRef, tx: &LedgerTx, result: &TxResult) {
    let seq = ov.get(&count_key(addr)).map(|b| read_u64(&b)).unwrap_or(0);
    let (args_hex, args_truncated) = match tx.call_args.char_indices().nth(LOG_ARGS_MAX_HEX) {
        Some((cut, _)) => (tx.call_args[..cut].to_string(), true),
        None => (tx.call_args.clone(), false),
    };
    let (ok, error, ru_used, events) = match result {
        Ok((ru, evs)) => (
            true,
            None,
            *ru,
            evs.iter()
                .map(|e| ActivityEvent { topic: e.topic.clone(), payload_hex: hex::encode(&e.payload) })
                .collect(),
        ),
        Err(e) => (false, Some(e.clone()), 0, vec![]),
    };
    let entry = ActivityEntry {
        seq,
        height: block.height,
        timestamp: block.timestamp,
        tx_hash: tx.hash.clone(),
        from: tx.from.clone(),
        kind: tx.tx_type.clone(),
        entrypoint: tx.entrypoint.clone(),
        args_hex,
        args_truncated,
        ok,
        error,
        ru_used,
        events,
    };
    ov.put(activity_key(addr, seq), serde_json::to_vec(&entry).unwrap_or_default());
    ov.put(count_key(addr), (seq + 1).to_le_bytes().to_vec());
}

static STARTED: AtomicBool = AtomicBool::new(false);
static WORKER: OnceLock<std::thread::Thread> = OnceLock::new();
static EXEC_LOCK: Mutex<()> = Mutex::new(());
static LAST_WAIT_NOTED: AtomicU64 = AtomicU64::new(0);
static FETCHED: Mutex<BTreeMap<u64, (String, Vec<LedgerTx>)>> = Mutex::new(BTreeMap::new());
static FETCH_FAILS: AtomicU64 = AtomicU64::new(0);
const FETCH_GIVE_UP: u64 = 200;
const FETCH_BATCH_TXS: usize = 5_000;

pub fn exclusive() -> MutexGuard<'static, ()> {
    EXEC_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn start() {
    if STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("contract-exec".into())
        .spawn(|| {
            std::thread::sleep(std::time::Duration::from_secs(5));
            loop {
                let ran = std::panic::catch_unwind(|| catch_up(BLOCKS_PER_PASS)).unwrap_or_else(|_| {
                    eprintln!("[Contracts] the contract executor hit an internal error; trying again shortly");
                    0
                });
                if ran < BLOCKS_PER_PASS {
                    std::thread::park_timeout(std::time::Duration::from_secs(3));
                }
            }
        });
    match spawned {
        Ok(h) => {
            let _ = WORKER.set(h.thread().clone());
        }
        Err(e) => eprintln!("[Contracts] could not start the contract executor: {e}"),
    }
}

pub fn wake() {
    if let Some(t) = WORKER.get() {
        t.unpark();
    }
}

enum Step {
    Advanced,
    Rewound,
    Idle,
    Fetch(u64),
}

pub fn catch_up(max_blocks: u64) -> u64 {
    let mut work = 0;
    while work < max_blocks {
        match step() {
            Step::Advanced | Step::Rewound => work += 1,
            Step::Fetch(h) if backfill(h) => work += 1,
            Step::Fetch(_) | Step::Idle => break,
        }
    }
    work
}

pub(crate) fn verify_block_txs(block: &crate::ledger::LedgerBlock, txs: Vec<LedgerTx>) -> Option<Vec<LedgerTx>> {
    if block.tx_merkle_root.is_empty() {
        return None;
    }
    let mut seen = std::collections::HashSet::new();
    let txs: Vec<LedgerTx> = txs.into_iter().filter(|t| seen.insert(t.hash.clone())).collect();
    let hashes: Vec<&str> = txs.iter().map(|t| t.hash.as_str()).collect();
    if crate::chain_db::compute_merkle_root(&hashes) != block.tx_merkle_root {
        return None;
    }
    Some(
        txs.into_iter()
            .filter(|t| {
                let bound = !is_contract_tx(t) || t.hash == crate::ledger::expected_standard_tx_hash(t);
                if !bound {
                    eprintln!(
                        "[Contracts] block #{}: {} does not match its own content, so it will not run",
                        block.height,
                        short(&t.hash)
                    );
                }
                bound
            })
            .collect(),
    )
}

fn fetch_verified_from(from: u64) -> Result<BTreeMap<u64, (String, Vec<LedgerTx>)>, String> {
    if crate::p2p::offline_mode() {
        return Err("this node is offline".into());
    }
    let floor = crate::chain_db::pruned_below();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let mut last_err = String::from("no archive answered");
    for base in crate::p2p::ORACLE_RPCS {
        let url = format!("{base}/chain/transactions?fromHeight={from}&limit={FETCH_BATCH_TXS}");
        let fetched: Result<Vec<serde_json::Value>, String> = rt.block_on(async {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(20))
                .build()
                .map_err(|e| e.to_string())?;
            let resp = client.get(&url).send().await.map_err(|e| e.to_string())?;
            if !resp.status().is_success() {
                return Err(format!("HTTP {}", resp.status()));
            }
            resp.json().await.map_err(|e| e.to_string())
        });
        let values = match fetched {
            Ok(v) => v,
            Err(e) => {
                last_err = format!("{base}: {e}");
                continue;
            }
        };
        let mut by_height: BTreeMap<u64, Vec<LedgerTx>> = BTreeMap::new();
        for v in values {
            let Ok(tx) = serde_json::from_value::<LedgerTx>(v) else { continue };
            if let Some(h) = tx.block_height.filter(|h| *h >= from && *h < floor) {
                by_height.entry(h).or_default().push(tx);
            }
        }
        let mut proven = BTreeMap::new();
        for (h, txs) in by_height {
            let Some(block) = crate::chain_db::get_block_by_height(h) else { continue };
            if let Some(txs) = verify_block_txs(&block, txs) {
                proven.insert(h, (block.hash.clone(), txs));
            }
        }
        if proven.contains_key(&from) {
            return Ok(proven);
        }
        last_err = format!("{base} could not prove the transactions of block #{from}");
    }
    Err(last_err)
}

fn backfill(from: u64) -> bool {
    match fetch_verified_from(from) {
        Ok(proven) => {
            FETCHED.lock().unwrap_or_else(|e| e.into_inner()).extend(proven);
            FETCH_FAILS.store(0, Ordering::Relaxed);
            true
        }
        Err(why) => {
            let fails = FETCH_FAILS.fetch_add(1, Ordering::Relaxed) + 1;
            if fails == 1 {
                eprintln!(
                    "[Contracts] block #{from} arrived in a snapshot without its transactions; fetching them from the archive: {why}"
                );
            }
            if fails < FETCH_GIVE_UP {
                return false;
            }
            FETCH_FAILS.store(0, Ordering::Relaxed);
            skip_height(from, &why);
            true
        }
    }
}

fn take_fetched(height: u64, hash: &str) -> Option<Vec<LedgerTx>> {
    let mut cache = FETCHED.lock().unwrap_or_else(|e| e.into_inner());
    let entry = cache.remove(&height);
    cache.retain(|h, _| *h > height);
    entry.filter(|(cached_hash, _)| cached_hash == hash).map(|(_, txs)| txs)
}

fn skip_height(height: u64, why: &str) {
    let _guard = exclusive();
    if crate::chain_db::contract_exec_height() != Some(height.saturating_sub(1)) {
        return;
    }
    let Some(block) = crate::chain_db::get_block_by_height(height) else { return };
    let undo = serde_json::to_vec(&UndoRecord { hash: block.hash.clone(), prev: vec![] }).unwrap_or_default();
    if crate::chain_db::commit_contract_block(height, &BTreeMap::new(), &undo, height.checked_sub(UNDO_KEEP)).is_ok() {
        eprintln!(
            "[Contracts] gave up on the transactions of block #{height} ({why}); contract calls in it did not run on this node"
        );
    }
}

fn read_undo(height: u64) -> Option<UndoRecord> {
    crate::chain_db::ContractDb
        .get(&undo_key(height))
        .and_then(|b| serde_json::from_slice(&b).ok())
}

fn first_run() -> u64 {
    let purged = crate::chain_db::purge_legacy_contract_entries();
    if purged > 0 {
        eprintln!("[Contracts] cleared {purged} record(s) left by the old local-only contract preview");
    }
    let floor = crate::chain_db::pruned_below().max(1);
    let start = floor - 1;
    if start > 0 {
        eprintln!(
            "[Contracts] this node's full history starts at block #{floor}; contracts deployed before it are not known here"
        );
    }
    crate::chain_db::set_contract_exec_height(start);
    start
}

fn step() -> Step {
    let _guard = exclusive();
    let (tip, _) = crate::chain_db::latest_block_info();
    let done = match crate::chain_db::contract_exec_height() {
        Some(h) => h,
        None => first_run(),
    };

    if done > 0 {
        match read_undo(done) {
            Some(undo) => {
                let still_ours = done <= tip
                    && crate::chain_db::get_block_by_height(done).map(|b| b.hash == undo.hash).unwrap_or(false);
                if !still_ours {
                    return match crate::chain_db::unwind_contract_block(done, &undo.entries()) {
                        Ok(()) => {
                            eprintln!("[Contracts] block #{done} is no longer on this chain; undid its contract changes");
                            Step::Rewound
                        }
                        Err(e) => {
                            eprintln!("[Contracts] could not undo block #{done}: {e}");
                            Step::Idle
                        }
                    };
                }
            }
            None if done > tip => {
                eprintln!(
                    "[Contracts] the chain fell back below block #{done} with no record to undo it; continuing from #{tip}"
                );
                crate::chain_db::set_contract_exec_height(tip);
                return Step::Rewound;
            }
            None => {}
        }
    }

    let target = crate::chain_db::finalized_height().max(tip.saturating_sub(EXEC_DEPTH)).min(tip);
    if done >= target {
        return Step::Idle;
    }
    let h = done + 1;
    let Some(block) = crate::chain_db::get_block_by_height(h) else {
        if LAST_WAIT_NOTED.swap(h, Ordering::Relaxed) != h {
            eprintln!("[Contracts] waiting for block #{h}: this node does not have it yet");
        }
        return Step::Idle;
    };
    let mut txs = crate::chain_db::get_txs_for_block(h);
    if (txs.len() as u32) < block.tx_count {
        if h < crate::chain_db::pruned_below() {
            match take_fetched(h, &block.hash) {
                Some(fetched) => txs = fetched,
                None => return Step::Fetch(h),
            }
        } else {
            if LAST_WAIT_NOTED.swap(h, Ordering::Relaxed) != h {
                eprintln!(
                    "[Contracts] waiting for block #{h}: it says it carries {} transaction(s) and {} are here",
                    block.tx_count,
                    txs.len()
                );
            }
            return Step::Idle;
        }
    }

    let outcome = execute_block(
        &crate::chain_db::ContractDb,
        &BlockRef { height: h, hash: &block.hash, timestamp: block.timestamp },
        &txs,
    );
    let undo = serde_json::to_vec(&outcome.undo).unwrap_or_default();
    if let Err(e) = crate::chain_db::commit_contract_block(h, &outcome.writes, &undo, h.checked_sub(UNDO_KEEP)) {
        eprintln!("[Contracts] could not save the contract changes of block #{h}: {e}");
        return Step::Idle;
    }
    if outcome.ran > 0 {
        eprintln!("[Contracts] block #{h}: ran {} contract transaction(s)", outcome.ran);
        for r in &outcome.refused {
            eprintln!("[Contracts]   refused {r}");
        }
    }
    Step::Advanced
}

pub fn export_for_snapshot(height: u64) -> (Option<u64>, Vec<(String, String)>, Vec<(u64, LedgerTx)>) {
    let _paused = exclusive();
    let Some(done) = crate::chain_db::contract_exec_height() else {
        return (None, vec![], vec![]);
    };
    let done = done.min(height);
    let mut txs = Vec::new();
    for h in (done + 1)..=height {
        let Some(block) = crate::chain_db::get_block_by_height(h) else {
            return (None, vec![], vec![]);
        };
        let held = crate::chain_db::get_txs_for_block(h);
        if (held.len() as u32) < block.tx_count {
            return (None, vec![], vec![]);
        }
        txs.extend(held.into_iter().filter(is_contract_tx).map(|tx| (h, tx)));
    }
    let entries = crate::chain_db::contract_scan(b"", usize::MAX, false)
        .into_iter()
        .filter(|(k, _)| !k.starts_with(b"u:"))
        .map(|(k, v)| (hex::encode(k), hex::encode(v)))
        .collect();
    (Some(done), entries, txs)
}

pub fn install_from_snapshot(snap: &crate::chain_db::StateSnapshot) {
    let Some(from) = snap.contract_height else {
        crate::chain_db::purge_legacy_contract_entries();
        let Some(done) = crate::chain_db::contract_exec_height() else { return };
        let lowest = snap.blocks.iter().map(|b| b.height).min().unwrap_or(snap.height);
        if done + 1 >= lowest {
            eprintln!(
                "[Contracts] the snapshot carries no contract data; blocks #{}..#{} will be fetched and run here",
                done + 1,
                snap.height
            );
        } else {
            eprintln!(
                "[Contracts] the snapshot carries no contract data and starts at block #{lowest}; contract history before it is not known here"
            );
            crate::chain_db::set_contract_exec_height(lowest - 1);
        }
        return;
    };
    let from = from.min(snap.height);
    let entries: Vec<(Vec<u8>, Vec<u8>)> = snap
        .contracts
        .iter()
        .filter_map(|(k, v)| Some((hex::decode(k).ok()?, hex::decode(v).ok()?)))
        .collect();
    if let Err(e) = crate::chain_db::replace_contract_entries(&entries, from) {
        eprintln!("[Contracts] could not install the snapshot's contract state: {e}");
        return;
    }
    for h in (from + 1)..=snap.height {
        let Some(block) = snap.blocks.iter().find(|b| b.height == h) else {
            eprintln!("[Contracts] the snapshot is missing block #{h}; its contract transactions cannot run here");
            continue;
        };
        let txs: Vec<LedgerTx> = snap
            .contract_txs
            .iter()
            .filter(|(bh, _)| *bh == h)
            .map(|(_, tx)| tx.clone())
            .collect();
        let outcome = execute_block(
            &crate::chain_db::ContractDb,
            &BlockRef { height: h, hash: &block.hash, timestamp: block.timestamp },
            &txs,
        );
        let undo = serde_json::to_vec(&outcome.undo).unwrap_or_default();
        if let Err(e) = crate::chain_db::commit_contract_block(h, &outcome.writes, &undo, None) {
            eprintln!("[Contracts] could not save the contract changes of block #{h}: {e}");
        }
    }
    crate::chain_db::set_contract_exec_height(snap.height);
    eprintln!("[Contracts] installed {} contract record(s) from the snapshot", entries.len());
}

fn preview_env(fuel: u64) -> ExecEnv {
    let (tip, _) = crate::chain_db::latest_block_info();
    ExecEnv {
        block_height: tip + 1,
        timestamp: chrono::Utc::now().timestamp(),
        fuel,
        allow_transfers: false,
    }
}

pub fn preview_deploy(wasm: &[u8], deployer: &str, init_args: &[u8]) -> Result<ego_vm::DeployEffects, ego_vm::VmError> {
    let base = crate::chain_db::ContractDb;
    let ov = Overlay::new(&base);
    ego_vm::deploy_on(&ov, wasm, deployer, init_args, preview_env(ego_vm::types::DEFAULT_DEPLOY_FUEL))
}

pub fn preview_call(
    addr: &str,
    caller: &str,
    entrypoint: &str,
    args: &[u8],
) -> Result<ego_vm::CallEffects, ego_vm::VmError> {
    let base = crate::chain_db::ContractDb;
    let ov = Overlay::new(&base);
    ego_vm::call_on(&ov, addr, caller, entrypoint, args, preview_env(ego_vm::types::DEFAULT_CALL_FUEL))
}

pub fn code(addr: &str) -> Option<Vec<u8>> {
    crate::chain_db::ContractDb.get(&code_key(addr))
}

pub fn state(addr: &str) -> Option<ContractState> {
    crate::chain_db::ContractDb
        .get(&state_key(addr))
        .and_then(|b| serde_json::from_slice(&b).ok())
}

pub fn manifest(addr: &str) -> Option<ContractManifest> {
    crate::chain_db::ContractDb
        .get(&manifest_key(addr))
        .and_then(|b| serde_json::from_slice(&b).ok())
}

pub fn list(limit: usize) -> Vec<(String, ContractManifest)> {
    crate::chain_db::contract_scan(b"m:", limit, false)
        .into_iter()
        .filter_map(|(k, v)| {
            let addr = std::str::from_utf8(k.get(2..)?).ok()?.to_string();
            Some((addr, serde_json::from_slice(&v).ok()?))
        })
        .collect()
}

pub fn activity(addr: &str, limit: usize) -> Vec<ActivityEntry> {
    crate::chain_db::contract_scan(&activity_prefix(addr), limit, true)
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::contract_commit_memo;

    const GUESTBOOK: &str = r#"contract Guestbook {
        pub fn init() {
            storage.set("entries", 0);
        }
        pub fn sign(message: String) {
            let n: u64 = storage.get_u64("entries");
            storage.set("entries", n + 1);
            events.emit("signed", n + 1);
        }
        pub fn entries() -> u64 {
            return storage.get_u64("entries");
        }
    }"#;

    type Store = BTreeMap<Vec<u8>, Vec<u8>>;

    fn wasm() -> Vec<u8> {
        urego_compiler::compile(GUESTBOOK).expect("guestbook compiles")
    }

    fn deploy_tx(from: &str, nonce: u64, wasm: &[u8]) -> LedgerTx {
        let wasm_hex = hex::encode(wasm);
        let (addr, code_hash) = ego_vm::contract_address_for(from, wasm);
        LedgerTx {
            hash: format!("0xdeploy{from}{nonce}"),
            from: from.into(),
            to: addr.clone(),
            nonce,
            tx_type: "deploy".into(),
            contract_addr: addr,
            entrypoint: "init".into(),
            call_args: String::new(),
            wasm_code: wasm_hex,
            memo: Some(contract_commit_memo("deploy", "init", "", &code_hash)),
            ..LedgerTx::default()
        }
    }

    fn call_tx(from: &str, nonce: u64, addr: &str, entrypoint: &str, text: &str) -> LedgerTx {
        let args_hex = hex::encode(text.as_bytes());
        LedgerTx {
            hash: format!("0xcall{from}{nonce}"),
            from: from.into(),
            to: addr.into(),
            nonce,
            tx_type: "call".into(),
            contract_addr: addr.into(),
            entrypoint: entrypoint.into(),
            memo: Some(contract_commit_memo("call", entrypoint, &args_hex, "")),
            call_args: args_hex,
            ..LedgerTx::default()
        }
    }

    fn apply(store: &mut Store, height: u64, txs: &[LedgerTx]) -> BlockOutcome {
        let hash = format!("block{height}");
        let outcome = execute_block(&*store, &BlockRef { height, hash: &hash, timestamp: 1_000 + height as i64 }, txs);
        for (k, v) in &outcome.writes {
            match v {
                Some(v) => { store.insert(k.clone(), v.clone()); }
                None => { store.remove(k); }
            }
        }
        outcome
    }

    fn undo(store: &mut Store, outcome: &BlockOutcome) {
        for (k, v) in outcome.undo.entries() {
            match v {
                Some(v) => { store.insert(k, v); }
                None => { store.remove(&k); }
            }
        }
    }

    fn entries(store: &Store, addr: &str) -> u64 {
        let st: ContractState = serde_json::from_slice(&store[&state_key(addr)]).unwrap();
        st.get("", "entries").map(|b| read_u64(&b)).unwrap_or(0)
    }

    fn log(store: &Store, addr: &str) -> Vec<ActivityEntry> {
        let prefix = activity_prefix(addr);
        store
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(_, v)| serde_json::from_slice(v).unwrap())
            .collect()
    }

    #[test]
    fn two_nodes_fed_the_same_blocks_hold_the_same_contract_state() {
        let code = wasm();
        let deploy = deploy_tx("egot1alice", 1, &code);
        let addr = deploy.contract_addr.clone();
        let blocks = vec![
            vec![deploy],
            vec![call_tx("egot1bob", 4, &addr, "sign", "hello from bob")],
            vec![
                call_tx("egot1carol", 2, &addr, "sign", "carol was here"),
                call_tx("egot1alice", 2, &addr, "sign", "first!"),
            ],
        ];
        let mut a = Store::new();
        let mut b = Store::new();
        for (i, txs) in blocks.iter().enumerate() {
            apply(&mut a, i as u64 + 1, txs);
            let mut reversed = txs.clone();
            reversed.reverse();
            apply(&mut b, i as u64 + 1, &reversed);
        }
        assert_eq!(a, b, "the order transactions were stored in must not matter");
        assert_eq!(entries(&a, &addr), 3);
        let messages: Vec<String> = log(&a, &addr)
            .iter()
            .filter(|e| e.entrypoint == "sign" && e.ok)
            .map(|e| String::from_utf8(hex::decode(&e.args_hex).unwrap()).unwrap())
            .collect();
        assert_eq!(messages.len(), 3);
        assert!(messages.contains(&"hello from bob".to_string()));
    }

    #[test]
    fn a_transaction_seen_twice_runs_once() {
        let code = wasm();
        let deploy = deploy_tx("egot1alice", 1, &code);
        let addr = deploy.contract_addr.clone();
        let sign = call_tx("egot1bob", 1, &addr, "sign", "once");
        let mut s = Store::new();
        apply(&mut s, 1, &[deploy]);
        apply(&mut s, 2, &[sign.clone()]);
        apply(&mut s, 3, &[sign]);
        assert_eq!(entries(&s, &addr), 1);
    }

    #[test]
    fn undoing_a_block_puts_back_exactly_what_was_there() {
        let code = wasm();
        let deploy = deploy_tx("egot1alice", 1, &code);
        let addr = deploy.contract_addr.clone();
        let mut s = Store::new();
        apply(&mut s, 1, &[deploy]);
        let before = s.clone();
        let outcome = apply(&mut s, 2, &[call_tx("egot1bob", 1, &addr, "sign", "gone after a reorg")]);
        assert_ne!(s, before);
        undo(&mut s, &outcome);
        assert_eq!(s, before);
    }

    #[test]
    fn a_rewritten_payload_does_not_run() {
        let code = wasm();
        let deploy = deploy_tx("egot1alice", 1, &code);
        let addr = deploy.contract_addr.clone();
        let mut forged = call_tx("egot1bob", 1, &addr, "sign", "what bob signed");
        forged.call_args = hex::encode("what a relay swapped in");
        let mut s = Store::new();
        apply(&mut s, 1, &[deploy]);
        let outcome = apply(&mut s, 2, &[forged]);
        assert_eq!(entries(&s, &addr), 0);
        assert_eq!(outcome.refused.len(), 1);
    }

    #[test]
    fn deploys_are_stamped_with_the_block_time() {
        let code = wasm();
        let deploy = deploy_tx("egot1alice", 1, &code);
        let addr = deploy.contract_addr.clone();
        let mut s = Store::new();
        apply(&mut s, 7, &[deploy]);
        let m: ContractManifest = serde_json::from_slice(&s[&manifest_key(&addr)]).unwrap();
        assert_eq!(m.deployed_at, 1_007);
        assert_eq!(m.deployer, "egot1alice");
    }

    #[test]
    fn a_contract_that_moves_egoc_is_refused_and_changes_nothing() {
        let wat = r#"(module
            (import "env" "egoc_transfer" (func $t (param i32 i32 i64)))
            (import "env" "storage_set" (func $set (param i32 i32 i32 i32 i32 i32)))
            (memory (export "memory") 1)
            (data (i32.const 0) "egot1thief")
            (func (export "init"))
            (func (export "drain")
                (call $set (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 4) (i32.const 0) (i32.const 4))
                (call $t (i32.const 0) (i32.const 10) (i64.const 5))))"#;
        let code = wat::parse_str(wat).unwrap();
        let deploy = deploy_tx("egot1alice", 1, &code);
        let addr = deploy.contract_addr.clone();
        let mut s = Store::new();
        apply(&mut s, 1, &[deploy]);
        let state_before = s[&state_key(&addr)].clone();
        let outcome = apply(&mut s, 2, &[call_tx("egot1bob", 1, &addr, "drain", "")]);
        assert_eq!(s[&state_key(&addr)], state_before, "a refused call must not keep its storage writes");
        assert_eq!(outcome.refused.len(), 1);
        assert!(outcome.refused[0].contains("cannot do yet"), "{:?}", outcome.refused);
        let last = log(&s, &addr).pop().unwrap();
        assert!(!last.ok);
    }

    #[test]
    fn calling_an_address_with_no_contract_leaves_no_trace_there() {
        let mut s = Store::new();
        let outcome = apply(&mut s, 1, &[call_tx("egot1bob", 1, "00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff", "sign", "x")]);
        assert_eq!(outcome.refused.len(), 1);
        assert!(log(&s, "00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff").is_empty());
    }

    #[test]
    fn the_chain_database_commits_scans_newest_first_and_unwinds() {
        let run = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let deployer = format!("egot1rocks{run}");
        let deploy = deploy_tx(&deployer, 1, &wasm());
        let addr = deploy.contract_addr.clone();
        let height = 3_000_000_000 + (run % 1_000_000) as u64 * 10;
        let blocks = vec![
            vec![deploy],
            vec![call_tx(&format!("egot1one{run}"), 1, &addr, "sign", "first")],
            vec![call_tx(&format!("egot1two{run}"), 1, &addr, "sign", "second")],
        ];
        let mut outcomes = Vec::new();
        for (i, txs) in blocks.iter().enumerate() {
            let h = height + i as u64;
            let hash = format!("rocks{h}");
            let outcome = execute_block(
                &crate::chain_db::ContractDb,
                &BlockRef { height: h, hash: &hash, timestamp: 50 + i as i64 },
                txs,
            );
            let undo_bytes = serde_json::to_vec(&outcome.undo).unwrap();
            crate::chain_db::commit_contract_block(h, &outcome.writes, &undo_bytes, None).unwrap();
            outcomes.push(outcome);
        }

        assert_eq!(crate::chain_db::contract_exec_height(), Some(height + 2));
        let newest: Vec<String> = activity(&addr, 10).iter().map(|e| e.entrypoint.clone() + ":" + &e.args_hex).collect();
        assert_eq!(
            newest,
            vec![
                format!("sign:{}", hex::encode("second")),
                format!("sign:{}", hex::encode("first")),
                "init:".to_string(),
            ],
            "activity must come back newest first"
        );
        assert_eq!(activity(&addr, 1).len(), 1);
        assert!(list(10_000).iter().any(|(a, m)| a == &addr && m.deployer == deployer));

        let before_last = state(&addr).unwrap();
        crate::chain_db::unwind_contract_block(height + 2, &outcomes[2].undo.entries()).unwrap();
        assert_eq!(crate::chain_db::contract_exec_height(), Some(height + 1));
        assert_eq!(activity(&addr, 10).len(), 2, "the undone call must leave the log");
        assert_ne!(state(&addr).unwrap(), before_last);
        assert_eq!(state(&addr).unwrap().get("", "entries"), Some(1u64.to_le_bytes().to_vec()));

        for (i, outcome) in outcomes.iter().enumerate().take(2).rev() {
            crate::chain_db::unwind_contract_block(height + i as u64, &outcome.undo.entries()).unwrap();
        }
        assert!(code(&addr).is_none(), "undoing the deploy block removes the contract");
        assert!(activity(&addr, 10).is_empty());
    }

    fn standard(mut tx: LedgerTx) -> LedgerTx {
        tx.hash = crate::ledger::expected_standard_tx_hash(&tx);
        tx
    }

    #[test]
    fn fetched_transactions_must_prove_they_belong_to_the_block() {
        let deploy = standard(deploy_tx("egot1alice", 1, &wasm()));
        let addr = deploy.contract_addr.clone();
        let call = standard(call_tx("egot1bob", 1, &addr, "sign", "hi"));
        let reward = LedgerTx { hash: "0xreward".into(), tx_type: "reward".into(), ..LedgerTx::default() };
        let txs = vec![deploy, call, reward];
        let hashes: Vec<&str> = txs.iter().map(|t| t.hash.as_str()).collect();
        let block = crate::ledger::LedgerBlock {
            height: 9,
            hash: "b9".into(),
            tx_count: 3,
            tx_merkle_root: crate::chain_db::compute_merkle_root(&hashes),
            ..crate::ledger::LedgerBlock::default()
        };

        assert_eq!(verify_block_txs(&block, txs.clone()).map(|t| t.len()), Some(3));

        let mut doubled = txs.clone();
        doubled.push(txs[1].clone());
        assert_eq!(verify_block_txs(&block, doubled).map(|t| t.len()), Some(3), "a repeated copy is ignored");

        let mut reordered = txs.clone();
        reordered.swap(0, 1);
        assert!(verify_block_txs(&block, reordered).is_none(), "another order is another block");
        assert!(verify_block_txs(&block, txs[..2].to_vec()).is_none(), "a missing transaction is caught");

        let mut forged = txs.clone();
        forged[1].from = "egot1mallory".into();
        let kept = verify_block_txs(&block, forged).unwrap();
        assert_eq!(kept.len(), 2, "a transaction whose content no longer matches its hash is dropped");
        assert!(kept.iter().all(|t| t.from != "egot1mallory"));

        let unrooted = crate::ledger::LedgerBlock { tx_merkle_root: String::new(), ..block };
        assert!(verify_block_txs(&unrooted, txs).is_none(), "a block with no root proves nothing");
    }

    #[test]
    fn a_failed_init_deploys_nothing() {
        let src = r#"contract Picky {
            pub fn init() {
                assert(1 == 2, "never");
            }
        }"#;
        let code = urego_compiler::compile(src).unwrap();
        let deploy = deploy_tx("egot1alice", 1, &code);
        let addr = deploy.contract_addr.clone();
        let mut s = Store::new();
        let outcome = apply(&mut s, 1, &[deploy]);
        assert_eq!(outcome.refused.len(), 1);
        assert!(!s.contains_key(&code_key(&addr)));
        assert!(!log(&s, &addr)[0].ok);
    }
}
