use axum::{Json, Router, extract::State, routing::get};
use chrono::Utc;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tower_http::cors::CorsLayer;
use tracing::{error, info, warn};

const EGO_RPC: &str = "http://127.0.0.1:8545";

const EGO_BRIDGE_ADDR: &str = "0x000000000000000000000000000000000000C003";

const CONFIRMATIONS_REQUIRED: u64 = 12;

const POLL_INTERVAL_SECS: u64 = 15;

const RELAYER_API_PORT: u16 = 8548;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    pub chain_id:      u64,
    pub name:          String,

    pub rpc_url:       String,

    pub lock_contract: String,

    pub start_block:   u64,
}

static SUPPORTED_CHAINS: Lazy<Vec<ChainConfig>> = Lazy::new(|| {
    vec![
        ChainConfig {
            chain_id:      1,
            name:          "Ethereum".into(),
            rpc_url:       std::env::var("ETH_RPC").unwrap_or_else(|_| "https://eth.llamarpc.com".into()),
            lock_contract: std::env::var("ETH_LOCK_CONTRACT").unwrap_or_default(),
            start_block:   0,
        },
        ChainConfig {
            chain_id:      56,
            name:          "BNB Chain".into(),
            rpc_url:       std::env::var("BSC_RPC").unwrap_or_else(|_| "https://bsc-dataseed.binance.org".into()),
            lock_contract: std::env::var("BSC_LOCK_CONTRACT").unwrap_or_default(),
            start_block:   0,
        },
        ChainConfig {
            chain_id:      137,
            name:          "Polygon".into(),
            rpc_url:       std::env::var("POLYGON_RPC").unwrap_or_else(|_| "https://polygon-rpc.com".into()),
            lock_contract: std::env::var("POLYGON_LOCK_CONTRACT").unwrap_or_default(),
            start_block:   0,
        },
    ]
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeEvent {
    pub id:           String,
    pub direction:    String,
    pub chain_id:     u64,
    pub tx_hash:      String,
    pub block_number: u64,
    pub sender:       String,
    pub ego_dest:     String,
    pub token:        String,
    pub amount:       u64,
    pub claim_hash:   String,
    pub status:       String,
    pub retries:      u32,
    pub last_attempt: i64,
    pub error:        Option<String>,
}

#[derive(Clone)]
pub struct RelayerState {
    pub events:          Arc<Mutex<HashMap<String, BridgeEvent>>>,
    pub processed_count: Arc<Mutex<u64>>,
    pub start_time:      i64,
    pub client:          reqwest::Client,
}

impl RelayerState {
    fn new() -> Self {
        Self {
            events:          Arc::new(Mutex::new(HashMap::new())),
            processed_count: Arc::new(Mutex::new(0)),
            start_time:      Utc::now().timestamp(),
            client:          reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
        }
    }
}

async fn eth_block_number(rpc: &str, client: &reqwest::Client) -> anyhow::Result<u64> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "eth_blockNumber", "params": []
    });
    let resp: serde_json::Value = client.post(rpc).json(&body).send().await?.json().await?;
    let hex = resp["result"].as_str().unwrap_or("0x0").trim_start_matches("0x");
    Ok(u64::from_str_radix(hex, 16).unwrap_or(0))
}

async fn eth_get_lock_logs(
    rpc:      &str,
    contract: &str,
    from:     u64,
    to:       u64,
    client:   &reqwest::Client,
) -> anyhow::Result<Vec<serde_json::Value>> {
    if contract.is_empty() {
        return Ok(vec![]);
    }

    const LOCKED_TOPIC: &str =
        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "eth_getLogs",
        "params": [{
            "fromBlock": format!("0x{:x}", from),
            "toBlock":   format!("0x{:x}", to),
            "address":   contract,
            "topics":    [LOCKED_TOPIC]
        }]
    });
    let resp: serde_json::Value = client.post(rpc).json(&body).send().await?.json().await?;
    Ok(resp["result"].as_array().cloned().unwrap_or_default())
}

fn compute_claim_hash(chain_id: u64, block: u64, tx_hash: &str, log_index: u64) -> String {
    use sha2::{Digest, Sha256};
    let input = format!("{chain_id}:{block}:{tx_hash}:{log_index}");
    let hash = Sha256::digest(input.as_bytes());
    hex::encode(hash)
}

fn parse_lock_log(log: &serde_json::Value, chain_id: u64) -> Option<BridgeEvent> {
    let tx_hash    = log["transactionHash"].as_str()?.to_string();
    let block_hex  = log["blockNumber"].as_str()?.trim_start_matches("0x");
    let block      = u64::from_str_radix(block_hex, 16).ok()?;
    let li_hex     = log["logIndex"].as_str()?.trim_start_matches("0x");
    let log_index  = u64::from_str_radix(li_hex, 16).unwrap_or(0);

    let data_hex = log["data"].as_str()?.trim_start_matches("0x");
    let data     = hex::decode(data_hex).ok()?;
    if data.len() < 160 { return None; }

    let sender = format!("0x{}", hex::encode(&data[12..32]));

    let amount = u64::from_be_bytes(data[56..64].try_into().ok()?);

    let token  = format!("0x{}", hex::encode(&data[76..96]));

    let ego_dest_raw = &data[128..160];
    let ego_dest = String::from_utf8_lossy(
        ego_dest_raw.iter().take_while(|&&b| b != 0).cloned().collect::<Vec<_>>().as_slice()
    ).to_string();

    let claim_hash = compute_claim_hash(chain_id, block, &tx_hash, log_index);
    let id = claim_hash.clone();

    Some(BridgeEvent {
        id,
        direction:    "in".into(),
        chain_id,
        tx_hash,
        block_number: block,
        sender,
        ego_dest,
        token,
        amount,
        claim_hash,
        status:       "pending".into(),
        retries:      0,
        last_attempt: 0,
        error:        None,
    })
}

async fn submit_verify_and_mint(
    event:  &BridgeEvent,
    client: &reqwest::Client,
) -> anyhow::Result<String> {

    let relayer_key = std::env::var("RELAYER_PRIVATE_KEY")
        .unwrap_or_else(|_| "0000000000000000000000000000000000000000000000000000000000000001".into());

    let tx = serde_json::json!({
        "tx": {
            "from":        derive_address_from_key(&relayer_key),
            "to":          EGO_BRIDGE_ADDR,
            "amount":      0,
            "memo":        format!("bridge_in:{}:{}", event.chain_id, event.claim_hash),
            "nonce":       0,
            "data": {
                "function":    "verify_and_mint",
                "claim_hash":  event.claim_hash,
                "source_chain": event.chain_id,
                "source_addr":  event.sender,
                "ego_dest":     event.ego_dest,
                "token":        event.token,
                "amount_lo":    event.amount,
                "amount_hi":    0u64,
                "proof_bytes":  ""
            }
        }
    });

    let resp: serde_json::Value = client
        .post(format!("{EGO_RPC}/tx/submit"))
        .json(&tx)
        .send()
        .await?
        .json()
        .await?;

    if let Some(hash) = resp["tx_hash"].as_str() {
        Ok(hash.to_string())
    } else {
        anyhow::bail!("No tx_hash in response: {resp}")
    }
}

fn derive_address_from_key(key_hex: &str) -> String {
    use sha2::{Digest, Sha256};
    let key_bytes = hex::decode(key_hex.trim_start_matches("0x")).unwrap_or_default();
    let hash = Sha256::digest(&key_bytes);
    format!("0x{}", hex::encode(&hash[12..]))
}

async fn poll_chain(chain: &ChainConfig, state: &RelayerState) {
    if chain.lock_contract.is_empty() {
        return;
    }

    let latest = match eth_block_number(&chain.rpc_url, &state.client).await {
        Ok(n)  => n,
        Err(e) => { warn!("[{}] block_number failed: {e}", chain.name); return; }
    };

    let from = chain.start_block.max(latest.saturating_sub(100));
    let to   = latest.saturating_sub(CONFIRMATIONS_REQUIRED);

    if from > to { return; }

    let logs = match eth_get_lock_logs(&chain.rpc_url, &chain.lock_contract, from, to, &state.client).await {
        Ok(l)  => l,
        Err(e) => { warn!("[{}] getLogs failed: {e}", chain.name); return; }
    };

    for log in &logs {
        let Some(event) = parse_lock_log(log, chain.chain_id) else { continue };
        let id = event.id.clone();

        {
            let mut events = state.events.lock().unwrap();
            if events.contains_key(&id) { continue; }
            events.insert(id.clone(), event);
        }

        info!("[{}] New lock event: {id}", chain.name);
    }
}

async fn process_pending(state: &RelayerState) {
    let pending: Vec<BridgeEvent> = {
        let events = state.events.lock().unwrap();
        events.values()
            .filter(|e| e.status == "pending" && e.retries < 5)
            .cloned()
            .collect()
    };

    for mut event in pending {
        match submit_verify_and_mint(&event, &state.client).await {
            Ok(tx_hash) => {
                info!("Submitted verify_and_mint for {} → tx {tx_hash}", event.id);
                event.status       = "confirmed".into();
                event.last_attempt = Utc::now().timestamp();
                *state.processed_count.lock().unwrap() += 1;
            }
            Err(e) => {
                error!("verify_and_mint failed for {}: {e}", event.id);
                event.status       = if event.retries >= 4 { "failed".into() } else { "pending".into() };
                event.retries     += 1;
                event.last_attempt = Utc::now().timestamp();
                event.error        = Some(e.to_string());
            }
        }
        state.events.lock().unwrap().insert(event.id.clone(), event);
    }
}

async fn health(State(s): State<Arc<RelayerState>>) -> Json<serde_json::Value> {
    let processed = *s.processed_count.lock().unwrap();
    let pending   = s.events.lock().unwrap().values().filter(|e| e.status == "pending").count();
    let failed    = s.events.lock().unwrap().values().filter(|e| e.status == "failed").count();
    let uptime    = Utc::now().timestamp() - s.start_time;
    Json(serde_json::json!({
        "status":          "ok",
        "processed_locks": processed,
        "pending":         pending,
        "failed":          failed,
        "uptime_secs":     uptime,
        "ego_rpc":         EGO_RPC,
        "chains":          SUPPORTED_CHAINS.iter().map(|c| &c.name).collect::<Vec<_>>(),
    }))
}

async fn pending_events(State(s): State<Arc<RelayerState>>) -> Json<Vec<BridgeEvent>> {
    let events = s.events.lock().unwrap();
    let mut v: Vec<BridgeEvent> = events.values()
        .filter(|e| e.status == "pending" || e.status == "failed")
        .cloned().collect();
    v.sort_by(|a, b| b.block_number.cmp(&a.block_number));
    Json(v)
}

async fn processed_events(State(s): State<Arc<RelayerState>>) -> Json<Vec<BridgeEvent>> {
    let events = s.events.lock().unwrap();
    let mut v: Vec<BridgeEvent> = events.values()
        .filter(|e| e.status == "confirmed")
        .cloned().collect();
    v.sort_by(|a, b| b.block_number.cmp(&a.block_number));
    v.truncate(100);
    Json(v)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("ego_bridge_relayer=info,tower_http=warn")
        .init();

    info!("Ego Bridge Relayer v1.0 starting — EGO-10 Phase 1 (trusted relayer)");
    info!("Ego RPC: {EGO_RPC}  |  Bridge contract: {EGO_BRIDGE_ADDR}");
    info!("API port: {RELAYER_API_PORT}");

    for chain in SUPPORTED_CHAINS.iter() {
        if chain.lock_contract.is_empty() {
            warn!("Chain {} lock contract not set — set {}_LOCK_CONTRACT env var", chain.name, chain.name.to_uppercase().replace(' ', "_"));
        } else {
            info!("Chain {}: lock contract = {}", chain.name, chain.lock_contract);
        }
    }

    let state = Arc::new(RelayerState::new());

    let poll_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(POLL_INTERVAL_SECS));
        loop {
            interval.tick().await;
            for chain in SUPPORTED_CHAINS.iter() {
                poll_chain(chain, &poll_state).await;
            }
            process_pending(&poll_state).await;
        }
    });

    let app = Router::new()
        .route("/health",    get(health))
        .route("/pending",   get(pending_events))
        .route("/processed", get(processed_events))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = format!("0.0.0.0:{RELAYER_API_PORT}");
    info!("Bridge relayer API listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
