// ── Multi-Chain Wallet ────────────────────────────────────────────────────────
//
// • Derives deterministic addresses for BTC/ETH/BNB/LTC/DOGE/SOL/ADA/XRP/TRX from seed
// • Fetches live balances from public chain APIs (no API key needed)
// • Fetches recent transaction history per chain / token
// • Manages user-added ERC-20 / BEP-20 / SPL custom tokens
//   stored in: %LOCALAPPDATA%/EgoDesktop/custom_tokens.json

use crate::error::EgoDesktopError;
use crate::ledger::{data_dir, seed_path};
use serde::{Deserialize, Serialize};
use std::fs;

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExternalAddress {
    pub chain:           String,
    pub symbol:          String,
    pub address:         String,
    pub network:         String,
    pub address_type:    String,
    pub explorer_prefix: String,
    pub color:           String,
    pub icon:            String,
    #[serde(default)]
    pub contract:        Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CustomToken {
    pub id:           String,   // uuid4
    pub symbol:       String,
    pub name:         String,
    pub chain:        String,   // "Ethereum", "BNB Chain", …
    pub chain_symbol: String,   // "ETH", "BNB", … (picks the right address)
    pub contract:     Option<String>,
    pub decimals:     u8,
    pub color:        String,
    pub icon:         String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenInfo {
    pub symbol:   String,
    pub name:     String,
    pub decimals: u8,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExternalTx {
    pub hash:         String,
    pub from:         String,
    pub to:           String,
    pub value:        String,   // human-readable  e.g. "0.015 ETH"
    pub symbol:       String,
    pub timestamp:    u64,
    pub block:        u64,
    pub status:       String,   // "Confirmed" | "Failed" | "Pending"
    pub explorer_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BalanceResult {
    pub raw:       String,   // raw units (e.g. wei / satoshi)
    pub formatted: String,   // "0.0015 ETH"
    pub usd:       f64,      // 0.0 if price unavailable offline
}

// ─────────────────────────────────────────────────────────────────────────────
// Custom-token persistence
// ─────────────────────────────────────────────────────────────────────────────

fn tokens_path() -> std::path::PathBuf {
    data_dir().join("custom_tokens.json")
}

fn load_tokens() -> Vec<CustomToken> {
    match fs::read_to_string(tokens_path()) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => vec![],
    }
}

fn save_tokens(tokens: &[CustomToken]) -> Result<(), String> {
    let s = serde_json::to_string_pretty(tokens).map_err(|e| e.to_string())?;
    fs::write(tokens_path(), s).map_err(|e| e.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Chain config
// ─────────────────────────────────────────────────────────────────────────────

fn evm_rpc(chain_symbol: &str) -> &'static str {
    match chain_symbol {
        "ETH"  => "https://eth.llamarpc.com",
        "BNB"  => "https://bsc-dataseed.binance.org",
        "MATIC"=> "https://polygon.llamarpc.com",
        "AVAX" => "https://api.avax.network/ext/bc/C/rpc",
        "ARB"  => "https://arb1.arbitrum.io/rpc",
        "OP"   => "https://mainnet.optimism.io",
        _      => "https://eth.llamarpc.com",
    }
}

fn evm_scan_api(chain_symbol: &str) -> &'static str {
    match chain_symbol {
        "ETH"   => "https://api.etherscan.io/api",
        "BNB"   => "https://api.bscscan.com/api",
        "MATIC" => "https://api.polygonscan.com/api",
        "AVAX"  => "https://api.snowtrace.io/api",
        "ARB"   => "https://api.arbiscan.io/api",
        "OP"    => "https://api-optimistic.etherscan.io/api",
        _       => "https://api.etherscan.io/api",
    }
}

fn evm_explorer(chain_symbol: &str) -> &'static str {
    match chain_symbol {
        "ETH"   => "https://etherscan.io/tx/",
        "BNB"   => "https://bscscan.com/tx/",
        "MATIC" => "https://polygonscan.com/tx/",
        "AVAX"  => "https://snowtrace.io/tx/",
        "ARB"   => "https://arbiscan.io/tx/",
        "OP"    => "https://optimistic.etherscan.io/tx/",
        _       => "https://etherscan.io/tx/",
    }
}

fn is_evm(chain_symbol: &str) -> bool {
    matches!(chain_symbol, "ETH" | "BNB" | "MATIC" | "AVAX" | "ARB" | "OP")
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP client helper
// ─────────────────────────────────────────────────────────────────────────────

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default()
}

// ─────────────────────────────────────────────────────────────────────────────
// EVM JSON-RPC
// ─────────────────────────────────────────────────────────────────────────────

async fn evm_call(rpc: &str, method: &str, params: serde_json::Value)
    -> Result<serde_json::Value, String>
{
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params
    });
    let resp = http_client().post(rpc).json(&body).send().await
        .map_err(|e| e.to_string())?;
    let json: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    if let Some(err) = json.get("error") {
        return Err(err.to_string());
    }
    Ok(json["result"].clone())
}

// ABI: encode a 32-byte-padded address parameter
fn abi_address_param(addr: &str) -> String {
    let stripped = addr.trim_start_matches("0x").to_lowercase();
    format!("{:0>64}", stripped)
}

// ABI decode: string return (offset + length + bytes)
fn abi_decode_string(hex: &str) -> String {
    let h = hex.trim_start_matches("0x");
    if h.len() < 128 { return String::new(); }
    let len = usize::from_str_radix(&h[64..128], 16).unwrap_or(0);
    if len == 0 || h.len() < 128 + len * 2 { return String::new(); }
    hex::decode(&h[128..128 + len * 2])
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .map(|s| s.trim_end_matches('\0').to_string())
        .unwrap_or_default()
}

// ABI decode: uint256 → u64
fn abi_decode_u64(hex: &str) -> u64 {
    let h = hex.trim_start_matches("0x");
    u64::from_str_radix(h, 16).unwrap_or(0)
}

// ABI decode: uint256 → u128
fn abi_decode_u128(hex: &str) -> u128 {
    let h = hex.trim_start_matches("0x");
    u128::from_str_radix(h, 16).unwrap_or(0)
}

// Human-readable token amount
fn fmt_amount(raw: u128, decimals: u8) -> String {
    if decimals == 0 { return raw.to_string(); }
    let d = decimals as u32;
    let div = 10u128.pow(d);
    let whole = raw / div;
    let frac  = raw % div;
    if frac == 0 { return whole.to_string(); }
    let frac_str = format!("{:0>width$}", frac, width = d as usize);
    let trimmed  = frac_str.trim_end_matches('0');
    // Keep at most 6 significant decimal digits
    let shown = if trimmed.len() > 6 { &trimmed[..6] } else { trimmed };
    format!("{whole}.{shown}")
}

// ─────────────────────────────────────────────────────────────────────────────
// EVM balance
// ─────────────────────────────────────────────────────────────────────────────

async fn fetch_evm_native_balance(chain: &str, address: &str) -> Result<BalanceResult, String> {
    let rpc = evm_rpc(chain);
    let result = evm_call(rpc, "eth_getBalance",
        serde_json::json!([address, "latest"])).await?;

    let hex = result.as_str().unwrap_or("0x0");
    let wei = abi_decode_u128(hex);
    let eth = wei as f64 / 1e18;
    Ok(BalanceResult {
        raw: wei.to_string(),
        formatted: format!("{:.6} {chain}", eth),
        usd: 0.0,
    })
}

async fn fetch_erc20_balance(rpc: &str, contract: &str, wallet: &str, symbol: &str, decimals: u8)
    -> Result<BalanceResult, String>
{
    let data = format!("0x70a08231{}", abi_address_param(wallet)); // balanceOf(address)
    let result = evm_call(rpc, "eth_call",
        serde_json::json!([{ "to": contract, "data": data }, "latest"])).await?;

    let raw = abi_decode_u128(result.as_str().unwrap_or("0x0"));
    let formatted = format!("{} {symbol}", fmt_amount(raw, decimals));
    Ok(BalanceResult { raw: raw.to_string(), formatted, usd: 0.0 })
}

// ─────────────────────────────────────────────────────────────────────────────
// Non-EVM balances
// ─────────────────────────────────────────────────────────────────────────────

async fn fetch_btc_balance(address: &str) -> Result<BalanceResult, String> {
    let url  = format!("https://blockstream.info/api/address/{address}");
    let json: serde_json::Value = http_client().get(&url).send().await
        .map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;

    let funded  = json["chain_stats"]["funded_txo_sum"].as_u64().unwrap_or(0);
    let spent   = json["chain_stats"]["spent_txo_sum"].as_u64().unwrap_or(0);
    let sats    = funded.saturating_sub(spent);
    let btc     = sats as f64 / 1e8;
    Ok(BalanceResult {
        raw: sats.to_string(),
        formatted: format!("{btc:.8} BTC"),
        usd: 0.0,
    })
}

async fn fetch_ltc_balance(address: &str) -> Result<BalanceResult, String> {
    let url = format!("https://api.blockcypher.com/v1/ltc/main/addrs/{address}/balance");
    let json: serde_json::Value = http_client().get(&url).send().await
        .map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
    let sats = json["balance"].as_u64().unwrap_or(0);
    Ok(BalanceResult {
        raw: sats.to_string(),
        formatted: format!("{:.8} LTC", sats as f64 / 1e8),
        usd: 0.0,
    })
}

async fn fetch_doge_balance(address: &str) -> Result<BalanceResult, String> {
    let url = format!("https://api.blockcypher.com/v1/doge/main/addrs/{address}/balance");
    let json: serde_json::Value = http_client().get(&url).send().await
        .map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
    let sats = json["balance"].as_u64().unwrap_or(0);
    Ok(BalanceResult {
        raw: sats.to_string(),
        formatted: format!("{:.4} DOGE", sats as f64 / 1e8),
        usd: 0.0,
    })
}

async fn fetch_sol_balance(address: &str) -> Result<BalanceResult, String> {
    let rpc  = "https://api.mainnet-beta.solana.com";
    let result = evm_call(rpc, "getBalance", serde_json::json!([address])).await?;
    let lamports = result["value"].as_u64().unwrap_or(0);
    Ok(BalanceResult {
        raw: lamports.to_string(),
        formatted: format!("{:.6} SOL", lamports as f64 / 1e9),
        usd: 0.0,
    })
}

async fn fetch_xrp_balance(address: &str) -> Result<BalanceResult, String> {
    let body = serde_json::json!({
        "method": "account_info",
        "params": [{ "account": address, "ledger_index": "current" }]
    });
    let json: serde_json::Value = http_client()
        .post("https://xrplcluster.com")
        .json(&body).send().await
        .map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
    let drops: u64 = json["result"]["account_data"]["Balance"]
        .as_str().and_then(|s| s.parse().ok()).unwrap_or(0);
    Ok(BalanceResult {
        raw: drops.to_string(),
        formatted: format!("{:.6} XRP", drops as f64 / 1e6),
        usd: 0.0,
    })
}

async fn fetch_trx_balance(address: &str) -> Result<BalanceResult, String> {
    let url = format!("https://api.trongrid.io/v1/accounts/{address}");
    let json: serde_json::Value = http_client().get(&url).send().await
        .map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
    let sun: u64 = json["data"].as_array()
        .and_then(|a| a.first())
        .and_then(|o| o["balance"].as_u64())
        .unwrap_or(0);
    Ok(BalanceResult {
        raw: sun.to_string(),
        formatted: format!("{:.6} TRX", sun as f64 / 1e6),
        usd: 0.0,
    })
}

async fn fetch_ada_balance(address: &str) -> Result<BalanceResult, String> {
    let url = format!("https://api.koios.rest/api/v1/address_info?_address={address}");
    let json: serde_json::Value = http_client().get(&url).send().await
        .map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;

    let lovelace: u64 = json.as_array()
        .and_then(|a| a.first())
        .and_then(|o| o["balance"].as_str())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Ok(BalanceResult {
        raw: lovelace.to_string(),
        formatted: format!("{:.6} ADA", lovelace as f64 / 1e6),
        usd: 0.0,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// EVM transaction history (Etherscan-compatible Scan APIs)
// ─────────────────────────────────────────────────────────────────────────────

async fn fetch_evm_txs(chain: &str, address: &str, contract: Option<&str>)
    -> Result<Vec<ExternalTx>, String>
{
    let base  = evm_scan_api(chain);
    let expl  = evm_explorer(chain);
    let laddr = address.to_lowercase();

    // Native txs or ERC-20 token txs
    let (action, extra) = match contract {
        Some(c) => ("tokentx", format!("&contractaddress={c}")),
        None    => ("txlist",  String::new()),
    };

    let url = format!(
        "{base}?module=account&action={action}&address={address}&sort=desc&offset=10&page=1{extra}&apikey="
    );

    let resp: serde_json::Value = http_client().get(&url).send().await
        .map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;

    let items = match resp["result"].as_array() {
        Some(a) => a.clone(),
        None    => return Ok(vec![]),
    };

    let symbol = match contract {
        Some(_) => items.first()
            .and_then(|t| t["tokenSymbol"].as_str())
            .unwrap_or(chain)
            .to_string(),
        None    => chain.to_string(),
    };

    let decimals: u8 = match contract {
        Some(_) => items.first()
            .and_then(|t| t["tokenDecimal"].as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(18),
        None    => 18,
    };

    let mut txs = Vec::new();
    for item in &items {
        let hash = item["hash"].as_str().unwrap_or("").to_string();
        let from = item["from"].as_str().unwrap_or("").to_string();
        let to   = item["to"].as_str().unwrap_or("").to_string();
        let raw_val = item["value"].as_str().unwrap_or("0");
        let raw_u128 = u128::from_str_radix(raw_val.trim_start_matches("0x"), 16)
            .or_else(|_| raw_val.parse::<u128>())
            .unwrap_or(0);
        let dir = if from.to_lowercase() == laddr { "-" } else { "+" };
        let value = format!("{dir}{} {symbol}", fmt_amount(raw_u128, decimals));
        let ts = item["timeStamp"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0u64);
        let block = item["blockNumber"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0u64);
        let status = if item["isError"].as_str() == Some("1") {
            "Failed"
        } else {
            "Confirmed"
        };
        txs.push(ExternalTx {
            hash: hash.clone(), from, to, value, symbol: symbol.clone(),
            timestamp: ts, block,
            status: status.to_string(),
            explorer_url: format!("{expl}{hash}"),
        });
    }
    Ok(txs)
}

// ─────────────────────────────────────────────────────────────────────────────
// BTC transaction history (Blockstream Esplora)
// ─────────────────────────────────────────────────────────────────────────────

async fn fetch_btc_txs(address: &str) -> Result<Vec<ExternalTx>, String> {
    let url  = format!("https://blockstream.info/api/address/{address}/txs");
    let laddr = address.to_lowercase();
    let json: serde_json::Value = http_client().get(&url).send().await
        .map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;

    let txs_raw = json.as_array().cloned().unwrap_or_default();
    let mut txs = Vec::new();
    for tx in txs_raw.iter().take(10) {
        let hash  = tx["txid"].as_str().unwrap_or("").to_string();
        let ts    = tx["status"]["block_time"].as_u64().unwrap_or(0);
        let block = tx["status"]["block_height"].as_u64().unwrap_or(0);
        let confirmed = tx["status"]["confirmed"].as_bool().unwrap_or(false);

        // Net value = outputs to this address − inputs from this address (sats)
        let out_total: i64 = tx["vout"].as_array().unwrap_or(&vec![])
            .iter()
            .filter(|o| o["scriptpubkey_address"].as_str().unwrap_or("").to_lowercase() == laddr)
            .map(|o| o["value"].as_i64().unwrap_or(0))
            .sum();
        let in_total: i64 = tx["vin"].as_array().unwrap_or(&vec![])
            .iter()
            .filter(|i| i["prevout"]["scriptpubkey_address"].as_str().unwrap_or("").to_lowercase() == laddr)
            .map(|i| i["prevout"]["value"].as_i64().unwrap_or(0))
            .sum();

        let net_sats = out_total - in_total;
        let dir   = if net_sats >= 0 { "+" } else { "-" };
        let value = format!("{dir}{:.8} BTC", net_sats.unsigned_abs() as f64 / 1e8);

        let from = tx["vin"].as_array()
            .and_then(|v| v.first())
            .and_then(|i| i["prevout"]["scriptpubkey_address"].as_str())
            .unwrap_or("coinbase")
            .to_string();

        txs.push(ExternalTx {
            hash: hash.clone(), from, to: address.to_string(), value,
            symbol: "BTC".into(),
            timestamp: ts, block,
            status: if confirmed { "Confirmed" } else { "Pending" }.into(),
            explorer_url: format!("https://blockstream.info/tx/{hash}"),
        });
    }
    Ok(txs)
}

// ─────────────────────────────────────────────────────────────────────────────
// Solana transaction history
// ─────────────────────────────────────────────────────────────────────────────

async fn fetch_sol_txs(address: &str) -> Result<Vec<ExternalTx>, String> {
    let rpc = "https://api.mainnet-beta.solana.com";
    let sigs_result = evm_call(rpc, "getSignaturesForAddress",
        serde_json::json!([address, { "limit": 10 }])).await?;

    let sigs = sigs_result.as_array().cloned().unwrap_or_default();
    let mut txs = Vec::new();
    for sig_info in sigs.iter().take(10) {
        let hash = sig_info["signature"].as_str().unwrap_or("").to_string();
        let ts   = sig_info["blockTime"].as_u64().unwrap_or(0);
        let err  = sig_info["err"].is_null().then_some("Confirmed").unwrap_or("Failed");
        let slot = sig_info["slot"].as_u64().unwrap_or(0);

        txs.push(ExternalTx {
            hash: hash.clone(),
            from: address.to_string(),
            to:   String::new(),
            value: "— SOL".into(),
            symbol: "SOL".into(),
            timestamp: ts, block: slot,
            status: err.into(),
            explorer_url: format!("https://solscan.io/tx/{hash}"),
        });
    }
    Ok(txs)
}

// ─────────────────────────────────────────────────────────────────────────────
// DOGE / LTC transaction history (BlockCypher)
// ─────────────────────────────────────────────────────────────────────────────

async fn fetch_blockcypher_txs(coin: &str, address: &str) -> Result<Vec<ExternalTx>, String> {
    let url = format!("https://api.blockcypher.com/v1/{coin}/main/addrs/{address}/full?limit=5");
    let json: serde_json::Value = http_client().get(&url).send().await
        .map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;

    let txs_raw = json["txs"].as_array().cloned().unwrap_or_default();
    let sym = coin.to_uppercase();
    let laddr = address.to_lowercase();
    let mut txs = Vec::new();

    for tx in txs_raw.iter().take(10) {
        let hash  = tx["hash"].as_str().unwrap_or("").to_string();
        let ts    = tx["confirmed"].as_str()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.timestamp() as u64)
            .unwrap_or(0);
        let block = tx["block_height"].as_u64().unwrap_or(0);
        let confirmed = tx["confirmations"].as_u64().unwrap_or(0) > 0;

        // Sum outputs to / from our address
        let recv: i64 = tx["outputs"].as_array().unwrap_or(&vec![])
            .iter()
            .filter(|o| o["addresses"].as_array().map_or(false,
                |a| a.iter().any(|x| x.as_str().unwrap_or("").to_lowercase() == laddr)))
            .map(|o| o["value"].as_i64().unwrap_or(0))
            .sum();
        let sent: i64 = tx["inputs"].as_array().unwrap_or(&vec![])
            .iter()
            .filter(|i| i["addresses"].as_array().map_or(false,
                |a| a.iter().any(|x| x.as_str().unwrap_or("").to_lowercase() == laddr)))
            .map(|i| i["output_value"].as_i64().unwrap_or(0))
            .sum();

        let net = recv - sent;
        let dir = if net >= 0 { "+" } else { "-" };
        let value = format!("{dir}{:.4} {sym}", net.unsigned_abs() as f64 / 1e8);

        txs.push(ExternalTx {
            hash: hash.clone(), from: address.to_string(), to: String::new(),
            value, symbol: sym.clone(), timestamp: ts, block,
            status: if confirmed { "Confirmed" } else { "Pending" }.into(),
            explorer_url: format!("https://blockchair.com/{}/transaction/{hash}",
                if coin == "doge" { "dogecoin" } else { "litecoin" }),
        });
    }
    Ok(txs)
}

// ─────────────────────────────────────────────────────────────────────────────
// XRP transaction history (Ripple Data API v2)
// ─────────────────────────────────────────────────────────────────────────────

async fn fetch_xrp_txs(address: &str) -> Result<Vec<ExternalTx>, String> {
    let url = format!(
        "https://data.ripple.com/v2/accounts/{address}/transactions?type=Payment&limit=10&result=tesSUCCESS"
    );
    let json: serde_json::Value = http_client().get(&url).send().await
        .map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
    let items = json["transactions"].as_array().cloned().unwrap_or_default();
    let mut txs = Vec::new();
    for item in items.iter().take(10) {
        let tx   = &item["tx"];
        let meta = &item["meta"];
        let hash = tx["hash"].as_str().unwrap_or("").to_string();
        let from = tx["Account"].as_str().unwrap_or("").to_string();
        let to   = tx["Destination"].as_str().unwrap_or("").to_string();
        let drops: u64 = tx["Amount"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0);
        let dir   = if from == address { "-" } else { "+" };
        let value = format!("{dir}{:.6} XRP", drops as f64 / 1e6);
        let ts    = item["date"].as_str()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.timestamp() as u64).unwrap_or(0);
        let result = meta["TransactionResult"].as_str().unwrap_or("tesSUCCESS");
        txs.push(ExternalTx {
            hash: hash.clone(), from, to, value, symbol: "XRP".into(),
            timestamp: ts, block: 0,
            status: if result == "tesSUCCESS" { "Confirmed" } else { "Failed" }.into(),
            explorer_url: format!("https://xrpscan.com/tx/{hash}"),
        });
    }
    Ok(txs)
}

// ─────────────────────────────────────────────────────────────────────────────
// TRX transaction history (Tronscan API)
// ─────────────────────────────────────────────────────────────────────────────

async fn fetch_trx_txs(address: &str) -> Result<Vec<ExternalTx>, String> {
    let url = format!(
        "https://apilist.tronscanapi.com/api/transaction?sort=-timestamp&count=true&limit=10&address={address}"
    );
    let json: serde_json::Value = http_client().get(&url).send().await
        .map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
    let items = json["data"].as_array().cloned().unwrap_or_default();
    let mut txs = Vec::new();
    for item in items.iter().take(10) {
        let hash  = item["hash"].as_str().unwrap_or("").to_string();
        let from  = item["ownerAddress"].as_str().unwrap_or("").to_string();
        let to    = item["toAddress"].as_str().unwrap_or("").to_string();
        let sun: u64 = item["contractData"]["amount"].as_u64().unwrap_or(0);
        let dir   = if from == address { "-" } else { "+" };
        let value = format!("{dir}{:.6} TRX", sun as f64 / 1e6);
        let ts    = item["timestamp"].as_u64().unwrap_or(0) / 1000;
        let ok    = item["contractRet"].as_str().unwrap_or("SUCCESS") == "SUCCESS";
        txs.push(ExternalTx {
            hash: hash.clone(), from, to, value, symbol: "TRX".into(),
            timestamp: ts, block: 0,
            status: if ok { "Confirmed" } else { "Failed" }.into(),
            explorer_url: format!("https://tronscan.org/#/transaction/{hash}"),
        });
    }
    Ok(txs)
}

// ─────────────────────────────────────────────────────────────────────────────
// Key derivation (unchanged from previous version)
// ─────────────────────────────────────────────────────────────────────────────

fn hmac_sha512(seed: &[u8], path: &str) -> [u8; 64] {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;
    let mut mac = HmacSha512::new_from_slice(seed).expect("HMAC any key");
    mac.update(path.as_bytes());
    mac.finalize().into_bytes().into()
}

fn secp_privkey(seed: &[u8], path: &str) -> [u8; 32] {
    let full = hmac_sha512(seed, path);
    let mut k = [0u8; 32]; k.copy_from_slice(&full[..32]); k
}

fn ed25519_seed32(seed: &[u8], path: &str) -> [u8; 32] {
    let full = hmac_sha512(seed, path);
    let mut k = [0u8; 32]; k.copy_from_slice(&full[..32]); k
}

fn hash160(data: &[u8]) -> [u8; 20] {
    use ripemd::Ripemd160;
    use sha2::{Digest, Sha256};
    let sha = Sha256::digest(data);
    let rmd = Ripemd160::digest(sha);
    let mut out = [0u8; 20]; out.copy_from_slice(&rmd); out
}

fn base58check(version: u8, payload: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut data = vec![version];
    data.extend_from_slice(payload);
    let cs = &Sha256::digest(Sha256::digest(&data))[..4];
    data.extend_from_slice(cs);
    bs58::encode(data).into_string()
}

fn eip55_checksum(addr: &[u8]) -> String {
    use sha3::{Digest, Keccak256};
    let hex_lower = hex::encode(addr);
    let hash_hex  = hex::encode(Keccak256::digest(hex_lower.as_bytes()));
    let cs: String = hex_lower.chars().enumerate().map(|(i, c)| {
        if c.is_ascii_alphabetic() {
            if u8::from_str_radix(&hash_hex[i..i+1], 16).unwrap_or(0) >= 8 {
                c.to_ascii_uppercase()
            } else { c }
        } else { c }
    }).collect();
    format!("0x{cs}")
}

fn addr_btc_like(seed: &[u8], path: &str, hrp: &str) -> Result<String, String> {
    use bech32::{u5, ToBase32, Variant};
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::SecretKey;
    let sk = SecretKey::from_slice(&secp_privkey(seed, path)).map_err(|e| e.to_string())?;
    let pt = sk.public_key().to_encoded_point(true);
    let h  = hash160(pt.as_bytes());
    let mut payload = vec![u5::try_from_u8(0).map_err(|e| e.to_string())?];
    payload.extend_from_slice(&h.to_base32());
    bech32::encode(hrp, payload, Variant::Bech32).map_err(|e| e.to_string())
}

fn addr_evm(seed: &[u8], path: &str) -> Result<String, String> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::SecretKey;
    use sha3::{Digest, Keccak256};
    let sk  = SecretKey::from_slice(&secp_privkey(seed, path)).map_err(|e| e.to_string())?;
    let pt  = sk.public_key().to_encoded_point(false);
    let raw = &pt.as_bytes()[1..];
    let h   = Keccak256::digest(raw);
    Ok(eip55_checksum(&h[12..]))
}

fn addr_doge(seed: &[u8]) -> Result<String, String> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::SecretKey;
    let sk = SecretKey::from_slice(&secp_privkey(seed, "ego:dogecoin:0")).map_err(|e| e.to_string())?;
    let pt = sk.public_key().to_encoded_point(true);
    Ok(base58check(0x1E, &hash160(pt.as_bytes())))
}

fn addr_sol(seed: &[u8]) -> Result<String, String> {
    use ed25519_dalek::SigningKey;
    let sk = SigningKey::from_bytes(&ed25519_seed32(seed, "ego:solana:0"));
    Ok(bs58::encode(sk.verifying_key().to_bytes()).into_string())
}

fn addr_xrp(seed: &[u8]) -> Result<String, String> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::SecretKey;
    use sha2::{Digest, Sha256};
    let sk = SecretKey::from_slice(&secp_privkey(seed, "ego:xrp:0")).map_err(|e| e.to_string())?;
    let pt = sk.public_key().to_encoded_point(true);
    let h  = hash160(pt.as_bytes());            // RIPEMD160(SHA256(pubkey))
    let mut data = vec![0x00u8];                // version byte for XRP classic address
    data.extend_from_slice(&h);
    let cs = &Sha256::digest(Sha256::digest(&data))[..4];
    data.extend_from_slice(cs);
    Ok(bs58::encode(data).with_alphabet(bs58::Alphabet::RIPPLE).into_string())
}

fn addr_trx(seed: &[u8]) -> Result<String, String> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::SecretKey;
    use sha3::{Digest, Keccak256};
    let sk  = SecretKey::from_slice(&secp_privkey(seed, "ego:tron:0")).map_err(|e| e.to_string())?;
    let pt  = sk.public_key().to_encoded_point(false); // uncompressed
    let raw = &pt.as_bytes()[1..];              // strip 0x04 prefix
    let h   = Keccak256::digest(raw);
    Ok(base58check(0x41, &h[12..]))             // 0x41 prefix → starts with 'T'
}

fn addr_ada(seed: &[u8]) -> Result<String, String> {
    use bech32::{ToBase32, Variant};
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};
    let sk     = SigningKey::from_bytes(&ed25519_seed32(seed, "ego:cardano:0"));
    let pubkey = sk.verifying_key().to_bytes();
    let hash   = Sha256::digest(pubkey);
    let mut payload = vec![0x61u8];
    payload.extend_from_slice(&hash[..28]);
    bech32::encode("addr", payload.to_base32(), Variant::Bech32).map_err(|e| e.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tauri commands
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the 9 built-in chain addresses derived from the Ego seed.
#[tauri::command]
pub fn get_external_addresses() -> Result<Vec<ExternalAddress>, EgoDesktopError> {
    let seed = fs::read(seed_path())
        .map_err(|_| EgoDesktopError::FileSystemError("Wallet not initialised".into()))?;
    if seed.len() < 32 {
        return Err(EgoDesktopError::FileSystemError("Seed too short".into()));
    }

    macro_rules! push {
        ($chain:expr, $sym:expr, $icon:expr, $color:expr, $result:expr,
         $atype:expr, $explorer:expr) => {
            ExternalAddress {
                chain: $chain.into(), symbol: $sym.into(),
                address: $result.unwrap_or_else(|e| format!("Error: {e}")),
                network: "Mainnet".into(), address_type: $atype.into(),
                explorer_prefix: $explorer.into(),
                color: $color.into(), icon: $icon.into(),
                contract: None,
            }
        };
    }

    // Derive shared addresses once
    let eth_addr = addr_evm(&seed, "ego:ethereum:0");
    let bnb_addr = addr_evm(&seed, "ego:bnb:0");

    Ok(vec![
        push!("Bitcoin",   "BTC",  "₿", "#F7931A", addr_btc_like(&seed,"ego:bitcoin:0","bc"),  "P2WPKH", "https://blockstream.info/address/"),
        push!("Ethereum",  "ETH",  "Ξ", "#627EEA", eth_addr.clone(),                            "EVM",    "https://etherscan.io/address/"),
        push!("BNB Chain", "BNB",  "◆", "#F3BA2F", bnb_addr.clone(),                            "EVM",    "https://bscscan.com/address/"),
        push!("Solana",    "SOL",  "◎", "#9945FF", addr_sol(&seed),                             "Ed25519","https://solscan.io/account/"),
        push!("Cardano",   "ADA",  "₳", "#3CC8C8", addr_ada(&seed),                             "Shelley","https://cardanoscan.io/address/"),
        push!("XRP",       "XRP",  "✕", "#00AAE4", addr_xrp(&seed),                             "Classic","https://xrpscan.com/account/"),
        push!("Tron",      "TRX",  "🔴","#EF0027", addr_trx(&seed),                             "TRC20",  "https://tronscan.org/#/address/"),
        push!("Litecoin",  "LTC",  "Ł", "#A5A5A5", addr_btc_like(&seed,"ego:litecoin:0","ltc"), "P2WPKH", "https://litecoinspace.org/address/"),
        push!("Dogecoin",  "DOGE", "Ð", "#C2A633", addr_doge(&seed),                            "P2PKH",  "https://dogechain.info/address/"),
        ExternalAddress {
            chain: "USDT".into(), symbol: "ETH".into(),
            address: eth_addr.clone().unwrap_or_else(|e| format!("Error: {e}")),
            network: "Mainnet".into(), address_type: "ERC-20".into(),
            explorer_prefix: "https://etherscan.io/address/".into(),
            color: "#26A17B".into(), icon: "$".into(),
            contract: Some("0xdAC17F958D2ee523a2206206994597C13D831ec7".into()),
        },
        ExternalAddress {
            chain: "USDC".into(), symbol: "ETH".into(),
            address: eth_addr.unwrap_or_else(|e| format!("Error: {e}")),
            network: "Mainnet".into(), address_type: "ERC-20".into(),
            explorer_prefix: "https://etherscan.io/address/".into(),
            color: "#2775CA".into(), icon: "$".into(),
            contract: Some("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".into()),
        },
    ])
}

/// Fetch live balance for a chain address (native coin or ERC-20 token).
#[tauri::command]
pub async fn fetch_chain_balance(
    chain_symbol: String,
    address:      String,
    contract:     Option<String>,
) -> Result<BalanceResult, EgoDesktopError> {
    let res = match chain_symbol.as_str() {
        c if is_evm(c) => {
            match &contract {
                Some(addr) => {
                    // Get token decimals first (default 18)
                    let rpc  = evm_rpc(c);
                    let dec_data = "0x313ce567"; // decimals()
                    let dec_res  = evm_call(rpc, "eth_call",
                        serde_json::json!([{"to": addr, "data": dec_data}, "latest"])).await
                        .ok();
                    let decimals = dec_res.as_ref()
                        .and_then(|v| v.as_str())
                        .map(|s| abi_decode_u64(s) as u8)
                        .unwrap_or(18);
                    fetch_erc20_balance(rpc, addr, &address, &chain_symbol, decimals).await
                }
                None => fetch_evm_native_balance(&chain_symbol, &address).await,
            }
        }
        "BTC"  => fetch_btc_balance(&address).await,
        "LTC"  => fetch_ltc_balance(&address).await,
        "DOGE" => fetch_doge_balance(&address).await,
        "SOL"  => fetch_sol_balance(&address).await,
        "ADA"  => fetch_ada_balance(&address).await,
        "XRP"  => fetch_xrp_balance(&address).await,
        "TRX"  => fetch_trx_balance(&address).await,
        _      => Err(format!("Unsupported chain: {chain_symbol}")),
    };
    res.map_err(EgoDesktopError::NetworkError)
}

/// Fetch recent transactions for a chain address.
#[tauri::command]
pub async fn fetch_chain_transactions(
    chain_symbol: String,
    address:      String,
    contract:     Option<String>,
) -> Result<Vec<ExternalTx>, EgoDesktopError> {
    let res = match chain_symbol.as_str() {
        c if is_evm(c) => {
            fetch_evm_txs(c, &address, contract.as_deref()).await
        }
        "BTC"  => fetch_btc_txs(&address).await,
        "LTC"  => fetch_blockcypher_txs("ltc",  &address).await,
        "DOGE" => fetch_blockcypher_txs("doge", &address).await,
        "SOL"  => fetch_sol_txs(&address).await,
        "ADA"  => Ok(vec![]),
        "XRP"  => fetch_xrp_txs(&address).await,
        "TRX"  => fetch_trx_txs(&address).await,
        _      => Err(format!("Unsupported chain: {chain_symbol}")),
    };
    res.map_err(EgoDesktopError::NetworkError)
}

/// Auto-detect symbol, name and decimals of an ERC-20 / BEP-20 contract.
#[tauri::command]
pub async fn lookup_token_info(
    chain_symbol:     String,
    contract_address: String,
) -> Result<TokenInfo, EgoDesktopError> {
    if !is_evm(&chain_symbol) {
        return Err(EgoDesktopError::InvalidInput(
            "Token lookup is only supported for EVM chains".into()
        ));
    }
    let rpc = evm_rpc(&chain_symbol);
    let contract = &contract_address;

    async fn call_str(rpc: &str, contract: &str, selector: &str) -> String {
        let res = evm_call(rpc, "eth_call",
            serde_json::json!([{"to": contract, "data": selector}, "latest"])).await;
        res.ok().and_then(|v| v.as_str().map(abi_decode_string)).unwrap_or_default()
    }

    let symbol   = call_str(rpc, contract, "0x95d89b41").await; // symbol()
    let name     = call_str(rpc, contract, "0x06fdde03").await; // name()
    let dec_res  = evm_call(rpc, "eth_call",
        serde_json::json!([{"to": contract, "data": "0x313ce567"}, "latest"])).await
        .ok();
    let decimals: u8 = dec_res.as_ref()
        .and_then(|v| v.as_str())
        .map(|s| abi_decode_u64(s) as u8)
        .unwrap_or(18);

    if symbol.is_empty() && name.is_empty() {
        return Err(EgoDesktopError::NetworkError(
            "Contract did not respond — is this a valid ERC-20 address?".into()
        ));
    }
    Ok(TokenInfo {
        symbol: if symbol.is_empty() { "UNKNOWN".into() } else { symbol },
        name:   if name.is_empty()   { "Unknown Token".into() } else { name },
        decimals,
    })
}

/// Save a custom token to custom_tokens.json.
#[tauri::command]
pub fn add_custom_token(
    symbol:       String,
    name:         String,
    chain:        String,
    chain_symbol: String,
    decimals:     u8,
    contract:     Option<String>,
    color:        Option<String>,
    icon:         Option<String>,
) -> Result<CustomToken, EgoDesktopError> {
    let color = color.unwrap_or_else(|| "#6366f1".into());
    let icon  = icon.unwrap_or_else(|| "🪙".into());
    let mut tokens = load_tokens();

    // Deduplicate: same chain_symbol + contract
    if tokens.iter().any(|t| {
        t.chain_symbol == chain_symbol
            && t.contract.as_deref().map(|s| s.to_lowercase())
                == contract.as_deref().map(|s| s.to_lowercase())
    }) {
        return Err(EgoDesktopError::InvalidInput(
            "This token is already in your list".into()
        ));
    }

    let token = CustomToken {
        id: uuid::Uuid::new_v4().to_string(),
        symbol, name, chain, chain_symbol, contract, decimals, color, icon,
    };
    tokens.push(token.clone());
    save_tokens(&tokens).map_err(EgoDesktopError::FileSystemError)?;
    Ok(token)
}

/// Load all saved custom tokens.
#[tauri::command]
pub fn get_custom_tokens() -> Result<Vec<CustomToken>, EgoDesktopError> {
    Ok(load_tokens())
}

/// Remove a custom token by id.
#[tauri::command]
pub fn remove_custom_token(id: String) -> Result<(), EgoDesktopError> {
    let mut tokens = load_tokens();
    tokens.retain(|t| t.id != id);
    save_tokens(&tokens).map_err(EgoDesktopError::FileSystemError)
}
