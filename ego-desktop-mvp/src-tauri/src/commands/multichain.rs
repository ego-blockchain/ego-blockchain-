use crate::error::EgoDesktopError;
use crate::ledger::{data_dir, seed_path};
use serde::{Deserialize, Serialize};
use std::fs;

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
    pub id:           String,
    pub symbol:       String,
    pub name:         String,
    pub chain:        String,
    pub chain_symbol: String,
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
    pub value:        String,
    pub symbol:       String,
    pub timestamp:    u64,
    pub block:        u64,
    pub status:       String,
    pub explorer_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BalanceResult {
    pub raw:       String,
    pub formatted: String,
    pub usd:       f64,
}

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
// Cardano transaction history (Koios API)
// ─────────────────────────────────────────────────────────────────────────────

async fn fetch_ada_txs(address: &str) -> Result<Vec<ExternalTx>, String> {
    let url = format!(
        "https://api.koios.rest/api/v1/address_txs?_address={address}&_after_block_height=0"
    );
    let json: serde_json::Value = http_client()
        .get(&url)
        .header("accept", "application/json")
        .send().await
        .map_err(|e| e.to_string())?
        .json().await
        .map_err(|e| e.to_string())?;

    let items = json.as_array().cloned().unwrap_or_default();
    let mut txs = Vec::new();
    for item in items.iter().take(10) {
        let hash       = item["tx_hash"].as_str().unwrap_or("").to_string();
        let block_height = item["block_height"].as_u64().unwrap_or(0);
        let epoch_no   = item["epoch_no"].as_u64().unwrap_or(0);
        // Koios address_txs returns minimal info; we record what's available.
        // Direction is unknown without a full tx lookup, so we show as received.
        txs.push(ExternalTx {
            hash:         hash.clone(),
            from:         String::new(),
            to:           address.to_string(),
            value:        format!("block {block_height} / epoch {epoch_no}"),
            symbol:       "ADA".into(),
            timestamp:    0,
            block:        block_height,
            status:       "Confirmed".into(),
            explorer_url: format!("https://cardanoscan.io/transaction/{hash}"),
        });
    }
    Ok(txs)
}

// ─────────────────────────────────────────────────────────────────────────────
// EVM transaction history — Scan API primary, Blockchair fallback
// ─────────────────────────────────────────────────────────────────────────────

fn blockchair_chain(chain: &str) -> Option<&'static str> {
    match chain {
        "ETH"   => Some("ethereum"),
        "BNB"   => Some("binance-smart-chain"),
        "MATIC" => Some("polygon"),
        _       => None,
    }
}

async fn fetch_evm_txs_blockchair(chain: &str, address: &str) -> Result<Vec<ExternalTx>, String> {
    let bc_chain = blockchair_chain(chain).ok_or_else(|| format!("Blockchair not supported for {chain}"))?;
    let url = format!(
        "https://api.blockchair.com/{bc_chain}/dashboards/address/{address}?transaction_details=true&limit=10"
    );
    let resp = http_client().get(&url).send().await.map_err(|e| e.to_string())?;
    let text = resp.text().await.map_err(|e| e.to_string())?;
    let json: serde_json::Value = serde_json::from_str(&text)
        .map_err(|_| "Blockchair returned non-JSON response".to_string())?;

    let addr_lower = address.to_lowercase();
    let data = &json["data"][&addr_lower];
    let calls = data["calls"].as_array().cloned().unwrap_or_default();
    if calls.is_empty() {
        // Also try "transactions" array (some chains use this)
        let txs_arr = data["transactions"].as_array().cloned().unwrap_or_default();
        if txs_arr.is_empty() { return Ok(vec![]); }
    }

    let expl    = evm_explorer(chain);
    let native  = match chain { "BNB" => "BNB", "MATIC" => "MATIC", _ => "ETH" };
    let laddr   = address.to_lowercase();

    let mut txs = Vec::new();
    for call in calls.iter().take(10) {
        let hash = call["transaction_hash"].as_str().unwrap_or("").to_string();
        if hash.is_empty() { continue; }
        let from = call["sender"].as_str().unwrap_or("").to_string();
        let to   = call["recipient"].as_str().unwrap_or("").to_string();
        let wei  = call["value"].as_str().and_then(|s| s.parse::<u128>().ok()).unwrap_or(0);
        let dir  = if from.to_lowercase() == laddr { "-" } else { "+" };
        let val  = format!("{dir}{:.6} {native}", wei as f64 / 1e18);
        let ts   = call["time"].as_str()
            .and_then(|s| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").ok())
            .map(|d| d.and_utc().timestamp() as u64).unwrap_or(0);
        let block = call["block_id"].as_u64().unwrap_or(0);
        txs.push(ExternalTx {
            hash: hash.clone(), from, to, value: val, symbol: native.into(),
            timestamp: ts, block,
            status: "Confirmed".into(),
            explorer_url: format!("{expl}{hash}"),
        });
    }
    Ok(txs)
}

async fn fetch_evm_txs(chain: &str, address: &str, contract: Option<&str>)
    -> Result<Vec<ExternalTx>, String>
{
    let base  = evm_scan_api(chain);
    let expl  = evm_explorer(chain);
    let laddr = address.to_lowercase();

    let (action, extra) = match contract {
        Some(c) => ("tokentx", format!("&contractaddress={c}")),
        None    => ("txlist",  String::new()),
    };

    let url = format!(
        "{base}?module=account&action={action}&address={address}&sort=desc&offset=10&page=1{extra}"
    );

    let scan_result = async {
        let resp: serde_json::Value = http_client().get(&url).send().await
            .map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
        match resp["result"].as_array() {
            Some(a) if !a.is_empty() => Ok(a.clone()),
            Some(_) => Err("empty".to_string()),
            None => Err(resp["result"].as_str().unwrap_or("scan error").to_string()),
        }
    }.await;

    // If scan API failed/rate-limited/empty and it's a native tx request, try Blockchair
    let items = match scan_result {
        Ok(items) => items,
        Err(_) if contract.is_none() && blockchair_chain(chain).is_some() => {
            // Blockchair as fallback — if it also fails, return empty (user can use explorer link)
            return Ok(fetch_evm_txs_blockchair(chain, address).await.unwrap_or_default());
        }
        Err(_) => return Ok(vec![]),
    };

    let symbol = match contract {
        Some(_) => items.first()
            .and_then(|t| t["tokenSymbol"].as_str())
            .unwrap_or(chain).to_string(),
        None    => chain.to_string(),
    };
    let decimals: u8 = match contract {
        Some(_) => items.first()
            .and_then(|t| t["tokenDecimal"].as_str())
            .and_then(|s| s.parse().ok()).unwrap_or(18),
        None    => 18,
    };

    let mut txs = Vec::new();
    for item in &items {
        let hash    = item["hash"].as_str().unwrap_or("").to_string();
        let from    = item["from"].as_str().unwrap_or("").to_string();
        let to      = item["to"].as_str().unwrap_or("").to_string();
        let raw_val = item["value"].as_str().unwrap_or("0");
        let raw_u128 = u128::from_str_radix(raw_val.trim_start_matches("0x"), 16)
            .or_else(|_| raw_val.parse::<u128>()).unwrap_or(0);
        let dir    = if from.to_lowercase() == laddr { "-" } else { "+" };
        let value  = format!("{dir}{} {symbol}", fmt_amount(raw_u128, decimals));
        let ts     = item["timeStamp"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0u64);
        let block  = item["blockNumber"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0u64);
        let status = if item["isError"].as_str() == Some("1") { "Failed" } else { "Confirmed" };
        txs.push(ExternalTx {
            hash: hash.clone(), from, to, value, symbol: symbol.clone(),
            timestamp: ts, block, status: status.to_string(),
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
    use blake2::{digest::consts::U28, Blake2b, Digest};
    use ed25519_dalek::SigningKey;
    type Blake2b224 = Blake2b<U28>;
    let sk     = SigningKey::from_bytes(&ed25519_seed32(seed, "ego:cardano:0"));
    let pubkey = sk.verifying_key().to_bytes();
    let hash   = Blake2b224::digest(pubkey); // 28-byte payment key hash (standard Cardano)
    let mut payload = vec![0x61u8];          // enterprise address, mainnet
    payload.extend_from_slice(&hash);
    bech32::encode("addr", payload.to_base32(), Variant::Bech32).map_err(|e| e.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// CBOR encoding (for Cardano)
// ─────────────────────────────────────────────────────────────────────────────

fn cbor_major_len(major: u8, len: u64) -> Vec<u8> {
    let mt = major << 5;
    if len <= 23 { return vec![mt | len as u8]; }
    if len <= 0xff { return vec![mt | 24, len as u8]; }
    if len <= 0xffff {
        let mut v = vec![mt | 25]; v.extend_from_slice(&(len as u16).to_be_bytes()); return v;
    }
    if len <= 0xffff_ffff {
        let mut v = vec![mt | 26]; v.extend_from_slice(&(len as u32).to_be_bytes()); return v;
    }
    let mut v = vec![mt | 27]; v.extend_from_slice(&len.to_be_bytes()); v
}

fn cbor_uint(n: u64) -> Vec<u8> { cbor_major_len(0, n) }
fn cbor_bytes(data: &[u8]) -> Vec<u8> {
    let mut v = cbor_major_len(2, data.len() as u64);
    v.extend_from_slice(data); v
}
fn cbor_array(items: &[Vec<u8>]) -> Vec<u8> {
    let mut v = cbor_major_len(4, items.len() as u64);
    for item in items { v.extend_from_slice(item); }
    v
}
fn cbor_map(pairs: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut v = cbor_major_len(5, pairs.len() as u64);
    for (k, val) in pairs { v.extend_from_slice(k); v.extend_from_slice(val); }
    v
}
// CBOR tag 258 = definite set (used for Cardano tx inputs)
fn cbor_set(items: &[Vec<u8>]) -> Vec<u8> {
    let mut v = vec![0xd9u8, 0x01, 0x02]; // tag(258)
    v.extend(cbor_array(items));
    v
}

// ─────────────────────────────────────────────────────────────────────────────
// Cardano / ADA send
// ─────────────────────────────────────────────────────────────────────────────

async fn send_ada_tx(seed: &[u8], to_address: &str, lovelace: u64) -> Result<String, String> {
    use blake2::{digest::consts::U32, Blake2b, Digest};
    use ed25519_dalek::{Signer, SigningKey};
    type Blake2b256 = Blake2b<U32>;

    let seed32 = ed25519_seed32(seed, "ego:cardano:0");
    let signing_key = SigningKey::from_bytes(&seed32);
    let pub_bytes   = signing_key.verifying_key().to_bytes();
    let from_addr   = addr_ada(seed)?;

    // Current slot for TTL
    let tip: serde_json::Value = http_client()
        .get("https://api.koios.rest/api/v1/tip")
        .send().await.map_err(|e| e.to_string())?
        .json().await.map_err(|e| e.to_string())?;
    let current_slot = tip.as_array().and_then(|a| a.first())
        .and_then(|b| b["abs_slot"].as_u64()).unwrap_or(0);
    let ttl = current_slot + 7_200; // ~2 hours

    // Fetch UTxOs
    let utxo_url = format!("https://api.koios.rest/api/v1/address_utxos?_address={from_addr}");
    let utxos_json: serde_json::Value = http_client().get(&utxo_url)
        .send().await.map_err(|e| e.to_string())?
        .json().await.map_err(|e| e.to_string())?;
    let utxos = utxos_json.as_array().cloned().unwrap_or_default();
    if utxos.is_empty() {
        return Err("No UTxOs found — make sure ADA has been sent to your address first".into());
    }

    // Largest-first selection
    const FEE: u64 = 200_000; // 0.2 ADA
    let needed = lovelace + FEE;
    let mut sorted: Vec<_> = utxos.iter().collect();
    sorted.sort_by(|a, b| {
        let av = a["value"].as_str().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
        let bv = b["value"].as_str().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
        bv.cmp(&av)
    });

    let mut selected: Vec<(String, u64, u64)> = Vec::new(); // (tx_hash, tx_index, value)
    let mut total_in = 0u64;
    for u in &sorted {
        let hash  = u["tx_hash"].as_str().unwrap_or("").to_string();
        let index = u["tx_index"].as_u64().unwrap_or(0);
        let val   = u["value"].as_str().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
        if hash.is_empty() { continue; }
        selected.push((hash, index, val));
        total_in += val;
        if total_in >= needed { break; }
    }
    if total_in < needed {
        return Err(format!("Insufficient ADA: have {:.6} ADA, need {:.6} ADA",
            total_in as f64 / 1e6, needed as f64 / 1e6));
    }

    let change = total_in - lovelace - FEE;

    // Decode addresses to raw bytes
    let (_, from_p5, _) = bech32::decode(&from_addr).map_err(|e| e.to_string())?;
    let from_bytes = bech32::convert_bits(&from_p5, 5, 8, false).map_err(|e| e.to_string())?;
    let (_, to_p5, _)   = bech32::decode(to_address).map_err(|e| e.to_string())?;
    let to_bytes   = bech32::convert_bits(&to_p5, 5, 8, false).map_err(|e| e.to_string())?;

    // Inputs (CBOR set)
    let input_items: Vec<Vec<u8>> = selected.iter().map(|(hash_hex, index, _)| {
        let hash_bytes = hex::decode(hash_hex).unwrap_or_default();
        cbor_array(&[cbor_bytes(&hash_bytes), cbor_uint(*index)])
    }).collect();
    let inputs_cbor = cbor_set(&input_items);

    // Outputs
    let out_to = cbor_array(&[cbor_bytes(&to_bytes), cbor_uint(lovelace)]);
    let mut output_items = vec![out_to];
    if change >= 1_000_000 { // skip change if < 1 ADA (below min UTxO)
        output_items.push(cbor_array(&[cbor_bytes(&from_bytes), cbor_uint(change)]));
    }
    let outputs_cbor = cbor_array(&output_items);

    // Transaction body map: {0: inputs, 1: outputs, 2: fee, 3: ttl}
    let tx_body = cbor_map(&[
        (cbor_uint(0), inputs_cbor),
        (cbor_uint(1), outputs_cbor),
        (cbor_uint(2), cbor_uint(FEE)),
        (cbor_uint(3), cbor_uint(ttl)),
    ]);

    // Body hash → sign with Ed25519
    let body_hash = Blake2b256::digest(&tx_body);
    let sig = signing_key.sign(body_hash.as_ref());

    // Witness set: {0: [[pubkey, sig]]}
    let vkey_witness = cbor_array(&[cbor_bytes(&pub_bytes), cbor_bytes(&sig.to_bytes())]);
    let witness_set  = cbor_map(&[(cbor_uint(0), cbor_array(&[vkey_witness]))]);

    // Full transaction: [tx_body, witness_set, true, null]
    let tx_cbor = cbor_array(&[tx_body, witness_set, vec![0xf5u8], vec![0xf6u8]]);

    // Submit via Koios
    let resp = http_client()
        .post("https://api.koios.rest/api/v1/submittx")
        .header("Content-Type", "application/cbor")
        .body(tx_cbor)
        .send().await.map_err(|e| e.to_string())?;

    let status = resp.status();
    let body   = resp.text().await.unwrap_or_default();
    if status.is_success() {
        Ok(body.trim_matches('"').to_string())
    } else {
        Err(format!("Cardano submit failed ({status}): {body}"))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tauri commands
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the 9 built-in chain addresses derived from the Ego seed.
#[tauri::command]
pub fn get_external_addresses() -> Result<Vec<ExternalAddress>, EgoDesktopError> {
    let seed = crate::ledger::load_seed()
        .ok_or_else(|| EgoDesktopError::FileSystemError("Wallet not initialised".into()))?;

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
/// Maps a coin symbol to its CoinGecko price ID.
fn coingecko_id(symbol: &str) -> Option<&'static str> {
    match symbol {
        "BTC"  => Some("bitcoin"),
        "ETH"  => Some("ethereum"),
        "BNB"  => Some("binancecoin"),
        "SOL"  => Some("solana"),
        "ADA"  => Some("cardano"),
        "XRP"  => Some("ripple"),
        "TRX"  => Some("tron"),
        "LTC"  => Some("litecoin"),
        "DOGE" => Some("dogecoin"),
        "USDT" => Some("tether"),
        "USDC" => Some("usd-coin"),
        "MATIC"=> Some("matic-network"),
        "AVAX" => Some("avalanche-2"),
        "ARB"  => Some("arbitrum"),
        "OP"   => Some("optimism"),
        _      => None,
    }
}

/// Fetch USD price for a symbol via CoinGecko. Returns 0.0 on any error.
async fn fetch_usd_price(symbol: &str) -> f64 {
    let id = match coingecko_id(symbol) {
        Some(id) => id,
        None => return 0.0,
    };
    let url = format!(
        "https://api.coingecko.com/api/v3/simple/price?ids={}&vs_currencies=usd",
        id
    );
    let Ok(resp) = http_client().get(&url).send().await else { return 0.0; };
    let Ok(json) = resp.json::<serde_json::Value>().await else { return 0.0; };
    json.get(id)
        .and_then(|v| v.get("usd"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0)
}

#[tauri::command]
pub async fn fetch_chain_balance(
    chain_symbol: String,
    address:      String,
    contract:     Option<String>,
) -> Result<BalanceResult, EgoDesktopError> {
    let mut res = match chain_symbol.as_str() {
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
    }.map_err(EgoDesktopError::NetworkError)?;

    Ok(res)
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
        "ADA"  => fetch_ada_txs(&address).await,
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

// ─────────────────────────────────────────────────────────────────────────────
// Send helpers
// ─────────────────────────────────────────────────────────────────────────────

fn parse_human_amount(amount_str: &str, decimals: u32) -> Result<u128, String> {
    let s = amount_str.trim();
    let (whole_str, frac_str) = match s.find('.') {
        None      => (s, ""),
        Some(pos) => (&s[..pos], &s[pos + 1..]),
    };
    let whole: u128 = if whole_str.is_empty() { 0 } else {
        whole_str.parse::<u128>().map_err(|e| e.to_string())?
    };
    let frac: u128 = if decimals == 0 {
        0
    } else {
        let d = decimals as usize;
        let padded: String = if frac_str.len() >= d {
            frac_str[..d].to_string()
        } else {
            format!("{:0<width$}", frac_str, width = d)
        };
        padded.parse::<u128>().unwrap_or(0)
    };
    Ok(whole * 10u128.pow(decimals) + frac)
}

fn sha256d(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(Sha256::digest(data)).to_vec()
}

fn varint(n: u64) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else if n <= 0xffff {
        let mut v = vec![0xfdu8]; v.extend_from_slice(&(n as u16).to_le_bytes()); v
    } else if n <= 0xffff_ffff {
        let mut v = vec![0xfeu8]; v.extend_from_slice(&(n as u32).to_le_bytes()); v
    } else {
        let mut v = vec![0xffu8]; v.extend_from_slice(&n.to_le_bytes()); v
    }
}

fn p2wpkh_script(pubkey_hash: &[u8]) -> Vec<u8> {
    let mut s = vec![0x00u8, 0x14];
    s.extend_from_slice(pubkey_hash);
    s
}

fn p2pkh_script_from_hash(pubkey_hash: &[u8]) -> Vec<u8> {
    let mut s = vec![0x76u8, 0xa9, 0x14];
    s.extend_from_slice(pubkey_hash);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

fn encode_der_sig(r: &[u8], s_bytes: &[u8]) -> Vec<u8> {
    fn der_int(raw: &[u8]) -> Vec<u8> {
        let trimmed: Vec<u8> = raw.iter().skip_while(|&&b| b == 0).cloned().collect();
        let mut v: Vec<u8> = if trimmed.first().map_or(true, |&b| b >= 0x80) {
            vec![0x00]
        } else {
            vec![]
        };
        if trimmed.is_empty() { v.push(0x00); } else { v.extend(trimmed); }
        v
    }
    let r_int = der_int(r);
    let s_int = der_int(s_bytes);
    let payload_len = 2 + r_int.len() + 2 + s_int.len();
    let mut out = vec![0x30u8, payload_len as u8];
    out.push(0x02); out.push(r_int.len() as u8); out.extend(r_int);
    out.push(0x02); out.push(s_int.len() as u8); out.extend(s_int);
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// RLP encoding (EVM)
// ─────────────────────────────────────────────────────────────────────────────

fn uint_to_be_bytes_nonempty(n: u128) -> Vec<u8> {
    if n == 0 { return vec![]; }
    let b = n.to_be_bytes();
    let start = b.iter().position(|&x| x != 0).unwrap_or(15);
    b[start..].to_vec()
}

fn rlp_item(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 { return data.to_vec(); }
    let mut out = Vec::new();
    if data.len() < 56 {
        out.push(0x80 + data.len() as u8);
    } else {
        let len_enc = uint_to_be_bytes_nonempty(data.len() as u128);
        out.push(0xb7 + len_enc.len() as u8);
        out.extend(len_enc);
    }
    out.extend_from_slice(data);
    out
}

fn rlp_uint(n: u128) -> Vec<u8> { rlp_item(&uint_to_be_bytes_nonempty(n)) }

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.iter().flat_map(|i| i.iter().copied()).collect();
    let mut out = Vec::new();
    if payload.len() < 56 {
        out.push(0xc0 + payload.len() as u8);
    } else {
        let len_enc = uint_to_be_bytes_nonempty(payload.len() as u128);
        out.push(0xf7 + len_enc.len() as u8);
        out.extend(len_enc);
    }
    out.extend(payload);
    out
}

fn evm_chain_id_num(chain: &str) -> u64 {
    match chain {
        "ETH"   => 1,
        "BNB"   => 56,
        "MATIC" => 137,
        "AVAX"  => 43114,
        "ARB"   => 42161,
        "OP"    => 10,
        _       => 1,
    }
}

fn erc20_transfer_calldata(to: &str, amount: u128) -> Vec<u8> {
    // keccak256("transfer(address,uint256)")[..4] = 0xa9059cbb
    let mut data = vec![0xa9u8, 0x05, 0x9c, 0xbb];
    let addr_bytes = hex::decode(to.trim_start_matches("0x")).unwrap_or_default();
    data.extend(std::iter::repeat(0u8).take(32_usize.saturating_sub(addr_bytes.len())));
    data.extend_from_slice(&addr_bytes);
    data.extend_from_slice(&[0u8; 16]); // pad u128 → 32 bytes
    data.extend_from_slice(&amount.to_be_bytes());
    data
}

// ─────────────────────────────────────────────────────────────────────────────
// EVM send (EIP-155 legacy transaction)
// ─────────────────────────────────────────────────────────────────────────────

async fn send_evm_tx(
    chain: &str,
    privkey_bytes: &[u8],
    to: &str,
    value_wei: u128,
    data: Vec<u8>,
) -> Result<String, String> {
    use k256::ecdsa::SigningKey;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use sha3::{Digest, Keccak256};

    let rpc = evm_rpc(chain);
    let chain_id = evm_chain_id_num(chain);

    let signing_key = SigningKey::from_slice(privkey_bytes).map_err(|e| e.to_string())?;
    let uncompressed = signing_key.verifying_key().to_encoded_point(false);
    let keccak = Keccak256::digest(&uncompressed.as_bytes()[1..]);
    let from_addr = eip55_checksum(&keccak[12..]);

    let nonce_res = evm_call(rpc, "eth_getTransactionCount",
        serde_json::json!([&from_addr, "pending"])).await?;
    let nonce = u64::from_str_radix(
        nonce_res.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16).unwrap_or(0);

    let gp_res = evm_call(rpc, "eth_gasPrice", serde_json::json!([])).await?;
    let gas_price = u128::from_str_radix(
        gp_res.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16).unwrap_or(1_000_000_000)
        * 12 / 10; // +20% buffer

    let gas_limit: u128 = if data.is_empty() { 21_000 } else { 120_000 };

    let to_bytes = hex::decode(to.trim_start_matches("0x"))
        .map_err(|_| format!("Invalid address: {to}"))?;

    // Pre-sign RLP (EIP-155)
    let pre_tx = rlp_list(&[
        rlp_uint(nonce as u128),
        rlp_uint(gas_price),
        rlp_uint(gas_limit),
        rlp_item(&to_bytes),
        rlp_uint(value_wei),
        rlp_item(&data),
        rlp_uint(chain_id as u128),
        rlp_item(&[]),
        rlp_item(&[]),
    ]);
    let hash = Keccak256::digest(&pre_tx);

    use k256::ecdsa::signature::hazmat::PrehashSigner;
    let (sig, recid) = signing_key.sign_prehash_recoverable(hash.as_ref())
        .map_err(|e| e.to_string())?;

    let v = chain_id * 2 + 35 + recid.to_byte() as u64;
    let signed_tx = rlp_list(&[
        rlp_uint(nonce as u128),
        rlp_uint(gas_price),
        rlp_uint(gas_limit),
        rlp_item(&to_bytes),
        rlp_uint(value_wei),
        rlp_item(&data),
        rlp_uint(v as u128),
        rlp_item(sig.r().to_bytes().as_slice()),
        rlp_item(sig.s().to_bytes().as_slice()),
    ]);

    let raw_hex = format!("0x{}", hex::encode(&signed_tx));
    let result = evm_call(rpc, "eth_sendRawTransaction", serde_json::json!([raw_hex])).await?;
    Ok(result.as_str().map(|s| s.to_string())
        .unwrap_or_else(|| result.to_string()))
}

// ─────────────────────────────────────────────────────────────────────────────
// BTC / LTC — P2WPKH segwit send
// ─────────────────────────────────────────────────────────────────────────────

struct Utxo { txid: String, vout: u32, value: u64 }

async fn fetch_btc_utxos(address: &str) -> Result<Vec<Utxo>, String> {
    let url = format!("https://blockstream.info/api/address/{address}/utxo");
    let json: serde_json::Value = http_client().get(&url).send().await
        .map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
    Ok(json.as_array().unwrap_or(&vec![]).iter().map(|u| Utxo {
        txid:  u["txid"].as_str().unwrap_or("").to_string(),
        vout:  u["vout"].as_u64().unwrap_or(0) as u32,
        value: u["value"].as_u64().unwrap_or(0),
    }).collect())
}

async fn fetch_blockcypher_utxos(coin: &str, address: &str) -> Result<Vec<Utxo>, String> {
    let url = format!("https://api.blockcypher.com/v1/{coin}/main/addrs/{address}?unspentOnly=true");
    let json: serde_json::Value = http_client().get(&url).send().await
        .map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
    let refs = json["txrefs"].as_array().cloned().unwrap_or_default();
    Ok(refs.iter().filter(|u| !u["spent"].as_bool().unwrap_or(false)).map(|u| Utxo {
        txid:  u["tx_hash"].as_str().unwrap_or("").to_string(),
        vout:  u["tx_output_n"].as_u64().unwrap_or(0) as u32,
        value: u["value"].as_u64().unwrap_or(0),
    }).collect())
}

fn select_utxos(utxos: &[Utxo], needed: u64) -> Result<Vec<usize>, String> {
    let mut sorted: Vec<usize> = (0..utxos.len()).collect();
    sorted.sort_by(|&a, &b| utxos[b].value.cmp(&utxos[a].value));
    let mut selected = Vec::new();
    let mut total = 0u64;
    for idx in sorted {
        selected.push(idx);
        total += utxos[idx].value;
        if total >= needed { return Ok(selected); }
    }
    Err(format!("Insufficient balance: have {} sats, need {} sats", total, needed))
}

async fn send_p2wpkh(
    seed: &[u8],
    deriv_path: &str,
    to_address: &str,   // bech32 P2WPKH
    amount_sats: u64,
    utxos: Vec<Utxo>,
    broadcast_fn: impl AsyncBroadcast,
) -> Result<String, String> {
    use k256::ecdsa::SigningKey;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::ecdsa::signature::hazmat::PrehashSigner;

    let privkey = secp_privkey(seed, deriv_path);
    let signing_key = SigningKey::from_slice(&privkey).map_err(|e| e.to_string())?;
    let compressed_pub = signing_key.verifying_key().to_encoded_point(true);
    let compressed_pub_bytes = compressed_pub.as_bytes();
    let pubkey_hash = hash160(compressed_pub_bytes);

    // Decode recipient bech32
    let (_, to_data, _) = bech32::decode(to_address).map_err(|e| e.to_string())?;
    let to_hash = bech32::convert_bits(&to_data[1..], 5, 8, false)
        .map_err(|e| e.to_string())?;
    let to_script = p2wpkh_script(&to_hash);
    let change_script = p2wpkh_script(&pubkey_hash);

    const FEE_SAT_VB: u64 = 15; // conservative
    // Estimate: n_inputs*68 + 2_outputs*31 + 10 overhead (segwit discount applied)
    let fee_est = |n: usize| -> u64 { (n as u64 * 68 + 2 * 31 + 10) * FEE_SAT_VB };
    let fee_rough = fee_est(3); // generous initial estimate
    let needed = amount_sats + fee_rough;
    let selected_idxs = select_utxos(&utxos, needed)?;
    let selected: Vec<&Utxo> = selected_idxs.iter().map(|&i| &utxos[i]).collect();
    let fee = fee_est(selected.len());
    let total_in: u64 = selected.iter().map(|u| u.value).sum();
    if total_in < amount_sats + fee {
        return Err(format!("Insufficient funds after fee: {} < {}", total_in, amount_sats + fee));
    }
    let change = total_in - amount_sats - fee;
    let has_change = change > 546;

    // hashPrevouts
    let mut prevouts_buf = Vec::new();
    for u in &selected {
        let txid = hex::decode(&u.txid).map_err(|e| e.to_string())?;
        prevouts_buf.extend(txid.iter().rev());
        prevouts_buf.extend_from_slice(&u.vout.to_le_bytes());
    }
    let hash_prevouts = sha256d(&prevouts_buf);

    // hashSequence
    let seq_buf: Vec<u8> = selected.iter()
        .flat_map(|_| 0xffffffffu32.to_le_bytes()) .collect();
    let hash_sequence = sha256d(&seq_buf);

    // hashOutputs
    let mut out_buf = Vec::new();
    out_buf.extend_from_slice(&amount_sats.to_le_bytes());
    out_buf.extend(varint(to_script.len() as u64));
    out_buf.extend_from_slice(&to_script);
    if has_change {
        out_buf.extend_from_slice(&change.to_le_bytes());
        out_buf.extend(varint(change_script.len() as u64));
        out_buf.extend_from_slice(&change_script);
    }
    let hash_outputs = sha256d(&out_buf);

    // Sign each input (BIP143)
    let mut witnesses: Vec<Vec<Vec<u8>>> = Vec::new();
    for u in &selected {
        let txid = hex::decode(&u.txid).map_err(|e| e.to_string())?;
        let script_code = p2pkh_script_from_hash(&pubkey_hash);
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&1u32.to_le_bytes()); // nVersion
        preimage.extend_from_slice(&hash_prevouts);
        preimage.extend_from_slice(&hash_sequence);
        preimage.extend(txid.iter().rev());
        preimage.extend_from_slice(&u.vout.to_le_bytes());
        preimage.push(script_code.len() as u8); // scriptCode length (single byte for P2WPKH)
        preimage.extend_from_slice(&script_code);
        preimage.extend_from_slice(&u.value.to_le_bytes());
        preimage.extend_from_slice(&0xffffffffu32.to_le_bytes());
        preimage.extend_from_slice(&hash_outputs);
        preimage.extend_from_slice(&0u32.to_le_bytes()); // locktime
        preimage.extend_from_slice(&1u32.to_le_bytes()); // SIGHASH_ALL

        let sighash = sha256d(&preimage);
        let (sig, _) = signing_key.sign_prehash_recoverable(&sighash)
            .map_err(|e| e.to_string())?;

        let mut der_sig = encode_der_sig(sig.r().to_bytes().as_slice(), sig.s().to_bytes().as_slice());
        der_sig.push(0x01); // SIGHASH_ALL
        witnesses.push(vec![der_sig, compressed_pub_bytes.to_vec()]);
    }

    // Serialize
    let mut raw = Vec::new();
    raw.extend_from_slice(&1u32.to_le_bytes()); // version
    raw.push(0x00); raw.push(0x01);              // marker + flag (segwit)
    raw.extend(varint(selected.len() as u64));
    for u in &selected {
        let txid = hex::decode(&u.txid).map_err(|e| e.to_string())?;
        raw.extend(txid.iter().rev());
        raw.extend_from_slice(&u.vout.to_le_bytes());
        raw.push(0x00); // empty scriptSig
        raw.extend_from_slice(&0xffffffffu32.to_le_bytes());
    }
    let num_outs: u64 = if has_change { 2 } else { 1 };
    raw.extend(varint(num_outs));
    raw.extend_from_slice(&amount_sats.to_le_bytes());
    raw.extend(varint(to_script.len() as u64));
    raw.extend_from_slice(&to_script);
    if has_change {
        raw.extend_from_slice(&change.to_le_bytes());
        raw.extend(varint(change_script.len() as u64));
        raw.extend_from_slice(&change_script);
    }
    for witness in &witnesses {
        raw.extend(varint(witness.len() as u64));
        for item in witness {
            raw.extend(varint(item.len() as u64));
            raw.extend_from_slice(item);
        }
    }
    raw.extend_from_slice(&0u32.to_le_bytes()); // locktime

    broadcast_fn.broadcast(hex::encode(&raw)).await
}

// Trait workaround so we can pass different broadcast functions
trait AsyncBroadcast {
    fn broadcast(self, raw_hex: String) -> impl std::future::Future<Output = Result<String, String>> + Send;
}

struct BtcBroadcast;
impl AsyncBroadcast for BtcBroadcast {
    async fn broadcast(self, raw_hex: String) -> Result<String, String> {
        let resp = http_client()
            .post("https://blockstream.info/api/tx")
            .body(raw_hex)
            .send().await.map_err(|e| e.to_string())?;
        let text = resp.text().await.map_err(|e| e.to_string())?;
        if text.len() == 64 { Ok(text) } else { Err(text) }
    }
}

struct BlockcypherBroadcast { coin: String }
impl AsyncBroadcast for BlockcypherBroadcast {
    async fn broadcast(self, raw_hex: String) -> Result<String, String> {
        let url = format!("https://api.blockcypher.com/v1/{}/main/txs/push", self.coin);
        let body = serde_json::json!({ "tx": raw_hex });
        let json: serde_json::Value = http_client().post(&url).json(&body)
            .send().await.map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
        json["tx"]["hash"].as_str().map(|s| s.to_string())
            .ok_or_else(|| json.to_string())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DOGE — P2PKH legacy send
// ─────────────────────────────────────────────────────────────────────────────

async fn send_doge_tx(seed: &[u8], to_address: &str, amount_sats: u64) -> Result<String, String> {
    use k256::ecdsa::SigningKey;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::ecdsa::signature::hazmat::PrehashSigner;

    let privkey = secp_privkey(seed, "ego:dogecoin:0");
    let signing_key = SigningKey::from_slice(&privkey).map_err(|e| e.to_string())?;
    let compressed_pub = signing_key.verifying_key().to_encoded_point(true);
    let compressed_pub_bytes = compressed_pub.as_bytes();
    let pubkey_hash = hash160(compressed_pub_bytes);

    // Decode P2PKH recipient (base58check, version 0x1E)
    let to_decoded = bs58::decode(to_address).into_vec().map_err(|e| e.to_string())?;
    if to_decoded.len() < 21 { return Err("Invalid DOGE address".into()); }
    let to_hash = &to_decoded[1..21];
    let to_script = p2pkh_script_from_hash(to_hash);
    let change_script = p2pkh_script_from_hash(&pubkey_hash);

    let utxos = fetch_blockcypher_utxos("doge", &addr_doge(seed)?).await?;
    const FEE_SAT: u64 = 1_000_000; // 0.01 DOGE fixed fee (very conservative)
    let needed = amount_sats + FEE_SAT;
    let selected_idxs = select_utxos(&utxos, needed)?;
    let selected: Vec<&Utxo> = selected_idxs.iter().map(|&i| &utxos[i]).collect();
    let total_in: u64 = selected.iter().map(|u| u.value).sum();
    let change = total_in.saturating_sub(amount_sats + FEE_SAT);
    let has_change = change > 100_000; // > 0.001 DOGE dust

    // Build a signing template for each input (P2PKH scriptSig template)
    let mut signed_inputs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new(); // (txid_rev, scriptSig)
    for u in &selected {
        let txid = hex::decode(&u.txid).map_err(|e| e.to_string())?;
        // Serialize tx with scriptPubKey in place of this input's scriptSig, others empty
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&1u32.to_le_bytes()); // version
        preimage.extend(varint(selected.len() as u64));
        for u2 in &selected {
            let txid2 = hex::decode(&u2.txid).map_err(|e| e.to_string())?;
            preimage.extend(txid2.iter().rev());
            preimage.extend_from_slice(&u2.vout.to_le_bytes());
            if u2.txid == u.txid && u2.vout == u.vout {
                preimage.extend(varint(change_script.len() as u64)); // our scriptPubKey as scriptSig
                preimage.extend_from_slice(&change_script);
            } else {
                preimage.push(0x00); // empty
            }
            preimage.extend_from_slice(&0xffffffffu32.to_le_bytes());
        }
        let n_out: u64 = if has_change { 2 } else { 1 };
        preimage.extend(varint(n_out));
        preimage.extend_from_slice(&amount_sats.to_le_bytes());
        preimage.extend(varint(to_script.len() as u64));
        preimage.extend_from_slice(&to_script);
        if has_change {
            preimage.extend_from_slice(&change.to_le_bytes());
            preimage.extend(varint(change_script.len() as u64));
            preimage.extend_from_slice(&change_script);
        }
        preimage.extend_from_slice(&0u32.to_le_bytes()); // locktime
        preimage.extend_from_slice(&1u32.to_le_bytes()); // SIGHASH_ALL

        let sighash = sha256d(&preimage);
        let (sig, _) = signing_key.sign_prehash_recoverable(&sighash)
            .map_err(|e| e.to_string())?;
        let mut der_sig = encode_der_sig(sig.r().to_bytes().as_slice(), sig.s().to_bytes().as_slice());
        der_sig.push(0x01);
        // scriptSig = OP_DATA<sig> OP_DATA<pubkey>
        let mut script_sig = Vec::new();
        script_sig.push(der_sig.len() as u8);
        script_sig.extend(&der_sig);
        script_sig.push(compressed_pub_bytes.len() as u8);
        script_sig.extend(compressed_pub_bytes);
        signed_inputs.push((txid, script_sig));
    }

    // Final tx
    let mut raw = Vec::new();
    raw.extend_from_slice(&1u32.to_le_bytes());
    raw.extend(varint(selected.len() as u64));
    for (i, u) in selected.iter().enumerate() {
        raw.extend(signed_inputs[i].0.iter().rev());
        raw.extend_from_slice(&u.vout.to_le_bytes());
        raw.extend(varint(signed_inputs[i].1.len() as u64));
        raw.extend_from_slice(&signed_inputs[i].1);
        raw.extend_from_slice(&0xffffffffu32.to_le_bytes());
    }
    let n_out: u64 = if has_change { 2 } else { 1 };
    raw.extend(varint(n_out));
    raw.extend_from_slice(&amount_sats.to_le_bytes());
    raw.extend(varint(to_script.len() as u64));
    raw.extend_from_slice(&to_script);
    if has_change {
        raw.extend_from_slice(&change.to_le_bytes());
        raw.extend(varint(change_script.len() as u64));
        raw.extend_from_slice(&change_script);
    }
    raw.extend_from_slice(&0u32.to_le_bytes());

    let url = "https://api.blockcypher.com/v1/doge/main/txs/push";
    let body = serde_json::json!({ "tx": hex::encode(&raw) });
    let json: serde_json::Value = http_client().post(url).json(&body)
        .send().await.map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
    json["tx"]["hash"].as_str().map(|s| s.to_string())
        .ok_or_else(|| json.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Solana — SystemProgram.transfer
// ─────────────────────────────────────────────────────────────────────────────

fn compact_u16(n: u16) -> Vec<u8> {
    // Solana compact-u16 encoding
    if n < 128 { return vec![n as u8]; }
    vec![(n & 0x7f) as u8 | 0x80, ((n >> 7) & 0x7f) as u8]
}

async fn send_sol_tx(seed: &[u8], to_address: &str, lamports: u64) -> Result<String, String> {
    use ed25519_dalek::{SigningKey, Signer};

    let seed32 = ed25519_seed32(seed, "ego:solana:0");
    let signing_key = SigningKey::from_bytes(&seed32);
    let from_pub = signing_key.verifying_key().to_bytes();
    let to_pub = bs58::decode(to_address).into_vec()
        .map_err(|e| format!("Invalid SOL address: {e}"))?;
    if to_pub.len() != 32 { return Err("Invalid SOL address length".into()); }
    let system_prog = [0u8; 32];

    // Get recent blockhash
    let rpc = "https://api.mainnet-beta.solana.com";
    let bh_res = evm_call(rpc, "getLatestBlockhash", serde_json::json!([{"commitment":"finalized"}])).await?;
    let blockhash_b58 = bh_res["value"]["blockhash"].as_str()
        .ok_or("No blockhash")?;
    let blockhash = bs58::decode(blockhash_b58).into_vec().map_err(|e| e.to_string())?;
    if blockhash.len() != 32 { return Err("Invalid blockhash".into()); }

    // Message: header [1, 0, 1] + accounts [from, to, sys] + blockhash + instruction
    let mut msg = Vec::new();
    msg.extend_from_slice(&[1u8, 0, 1]); // header
    msg.extend(compact_u16(3)); // 3 accounts
    msg.extend_from_slice(&from_pub);
    msg.extend_from_slice(&to_pub);
    msg.extend_from_slice(&system_prog);
    msg.extend_from_slice(&blockhash);
    msg.extend(compact_u16(1)); // 1 instruction
    msg.push(2u8); // program index = 2 (system_prog)
    msg.extend(compact_u16(2)); // 2 account indices
    msg.push(0u8); // from
    msg.push(1u8); // to
    // data: discriminant=2 (Transfer) + lamports as u64 LE
    let mut ix_data = vec![2u8, 0, 0, 0];
    ix_data.extend_from_slice(&lamports.to_le_bytes());
    msg.extend(compact_u16(ix_data.len() as u16));
    msg.extend(ix_data);

    // Sign the message
    let sig = signing_key.sign(&msg);

    // Serialize transaction: [compact_u16(1)] [64-byte sig] [message]
    let mut tx = Vec::new();
    tx.extend(compact_u16(1));
    tx.extend_from_slice(&sig.to_bytes());
    tx.extend(&msg);

    let tx_b64 = base64::encode(&tx);
    let result = evm_call(rpc, "sendTransaction",
        serde_json::json!([tx_b64, {"encoding": "base64", "skipPreflight": false}])).await?;
    Ok(result.as_str().map(|s| s.to_string()).unwrap_or_else(|| result.to_string()))
}

// ─────────────────────────────────────────────────────────────────────────────
// XRP — Payment transaction
// ─────────────────────────────────────────────────────────────────────────────

fn xrp_account_id(address: &str) -> Result<[u8; 20], String> {
    // XRP classic address → account ID (20 bytes)
    let decoded = bs58::decode(address)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .into_vec()
        .map_err(|e| e.to_string())?;
    if decoded.len() < 21 { return Err("Invalid XRP address".into()); }
    let mut id = [0u8; 20];
    id.copy_from_slice(&decoded[1..21]);
    Ok(id)
}

fn xrp_field_id(type_code: u8, field_code: u8) -> Vec<u8> {
    match (type_code < 16, field_code < 16) {
        (true, true)   => vec![(type_code << 4) | field_code],
        (true, false)  => vec![type_code << 4, field_code],
        (false, true)  => vec![field_code, type_code],
        (false, false) => vec![0x00, type_code, field_code],
    }
}

fn xrp_encode_uint16(type_c: u8, field_c: u8, val: u16) -> Vec<u8> {
    let mut v = xrp_field_id(type_c, field_c);
    v.extend_from_slice(&val.to_be_bytes()); v
}

fn xrp_encode_uint32(type_c: u8, field_c: u8, val: u32) -> Vec<u8> {
    let mut v = xrp_field_id(type_c, field_c);
    v.extend_from_slice(&val.to_be_bytes()); v
}

fn xrp_encode_amount_drops(type_c: u8, field_c: u8, drops: u64) -> Vec<u8> {
    let mut v = xrp_field_id(type_c, field_c);
    // XRP native amount: clear top 2 bits, set bit 62 (positive flag)
    let encoded = (drops & 0x3FFF_FFFF_FFFF_FFFF) | 0x4000_0000_0000_0000;
    v.extend_from_slice(&encoded.to_be_bytes()); v
}

fn xrp_encode_blob(type_c: u8, field_c: u8, data: &[u8]) -> Vec<u8> {
    let mut v = xrp_field_id(type_c, field_c);
    v.push(data.len() as u8); // VL length (single byte if < 193)
    v.extend_from_slice(data); v
}

fn xrp_encode_account(type_c: u8, field_c: u8, account_id: &[u8; 20]) -> Vec<u8> {
    let mut v = xrp_field_id(type_c, field_c);
    v.push(20u8); // VL length
    v.extend_from_slice(account_id); v
}

async fn send_xrp_tx(seed: &[u8], to_address: &str, drops: u64) -> Result<String, String> {
    use k256::ecdsa::SigningKey;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use sha2::{Digest, Sha512};

    let privkey = secp_privkey(seed, "ego:xrp:0");
    let signing_key = SigningKey::from_slice(&privkey).map_err(|e| e.to_string())?;
    let compressed_pub = signing_key.verifying_key().to_encoded_point(true);
    let pub_bytes = compressed_pub.as_bytes();

    let from_addr = addr_xrp(seed)?;
    let from_id = xrp_account_id(&from_addr)?;
    let to_id = xrp_account_id(to_address)?;

    // Fetch account sequence
    let body = serde_json::json!({
        "method": "account_info",
        "params": [{"account": &from_addr, "ledger_index": "current"}]
    });
    let json: serde_json::Value = http_client()
        .post("https://xrplcluster.com").json(&body).send().await
        .map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
    let sequence: u32 = json["result"]["account_data"]["Sequence"]
        .as_u64().unwrap_or(1) as u32;
    let ledger_current: u32 = json["result"]["ledger_current_index"]
        .as_u64().unwrap_or(1000) as u32;
    let last_ledger = ledger_current + 10;

    const FEE_DROPS: u64 = 12;

    // Serialize tx (WITHOUT signature) — fields must be in canonical order
    let mut tx_bytes = Vec::new();
    tx_bytes.extend(xrp_encode_uint16(1, 2, 0));            // TransactionType = Payment
    tx_bytes.extend(xrp_encode_uint32(2, 2, 0x8000_0000));  // Flags
    tx_bytes.extend(xrp_encode_uint32(2, 4, sequence));      // Sequence
    tx_bytes.extend(xrp_encode_uint32(2, 27, last_ledger)); // LastLedgerSequence (field 27 ≥ 16)
    tx_bytes.extend(xrp_encode_amount_drops(6, 1, drops));   // Amount
    tx_bytes.extend(xrp_encode_amount_drops(6, 8, FEE_DROPS)); // Fee
    tx_bytes.extend(xrp_encode_blob(7, 3, pub_bytes));       // SigningPubKey
    // TxnSignature omitted for pre-signing
    tx_bytes.extend(xrp_encode_account(8, 1, &from_id));     // Account
    tx_bytes.extend(xrp_encode_account(8, 3, &to_id));       // Destination

    // Hash prefix for signing: 0x53545800
    let mut preimage = vec![0x53u8, 0x54, 0x58, 0x00];
    preimage.extend(&tx_bytes);

    // SHA512 half
    let hash512 = Sha512::digest(&preimage);
    let signing_hash = &hash512[..32];

    let (sig, _) = signing_key.sign_prehash_recoverable(signing_hash)
        .map_err(|e| e.to_string())?;
    let der_sig = encode_der_sig(sig.r().to_bytes().as_slice(), sig.s().to_bytes().as_slice());

    // Re-serialize WITH TxnSignature
    let mut signed_tx = Vec::new();
    signed_tx.extend(xrp_encode_uint16(1, 2, 0));
    signed_tx.extend(xrp_encode_uint32(2, 2, 0x8000_0000));
    signed_tx.extend(xrp_encode_uint32(2, 4, sequence));
    signed_tx.extend(xrp_encode_uint32(2, 27, last_ledger));
    signed_tx.extend(xrp_encode_amount_drops(6, 1, drops));
    signed_tx.extend(xrp_encode_amount_drops(6, 8, FEE_DROPS));
    signed_tx.extend(xrp_encode_blob(7, 3, pub_bytes));      // SigningPubKey
    signed_tx.extend(xrp_encode_blob(7, 4, &der_sig));       // TxnSignature
    signed_tx.extend(xrp_encode_account(8, 1, &from_id));
    signed_tx.extend(xrp_encode_account(8, 3, &to_id));

    let tx_hex = hex::encode(&signed_tx);

    let submit_body = serde_json::json!({
        "method": "submit",
        "params": [{"tx_blob": tx_hex}]
    });
    let res: serde_json::Value = http_client()
        .post("https://xrplcluster.com").json(&submit_body).send().await
        .map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
    let engine_result = res["result"]["engine_result"].as_str().unwrap_or("");
    let tx_hash = res["result"]["tx_json"]["hash"].as_str().unwrap_or("");
    if engine_result == "tesSUCCESS" || engine_result == "terQUEUED" {
        Ok(tx_hash.to_string())
    } else {
        Err(format!("XRP submit failed: {engine_result} — {}",
            res["result"]["engine_result_message"].as_str().unwrap_or("")))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tron — TransferContract via trongrid createtransaction
// ─────────────────────────────────────────────────────────────────────────────

fn trx_addr_to_hex(addr: &str) -> Result<String, String> {
    // base58check → 21 bytes → strip 4-byte checksum → hex
    let decoded = bs58::decode(addr).into_vec().map_err(|e| e.to_string())?;
    if decoded.len() < 25 { return Err("Invalid TRX address".into()); }
    Ok(hex::encode(&decoded[..21]).to_uppercase())
}

async fn send_trx_tx(seed: &[u8], to_address: &str, sun: u64) -> Result<String, String> {
    use k256::ecdsa::SigningKey;
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use sha2::{Digest, Sha256};

    let privkey = secp_privkey(seed, "ego:tron:0");
    let signing_key = SigningKey::from_slice(&privkey).map_err(|e| e.to_string())?;
    let from_addr = addr_trx(seed)?;

    let from_hex = trx_addr_to_hex(&from_addr)?;
    let to_hex   = trx_addr_to_hex(to_address)?;

    // Build transaction via trongrid
    let build_body = serde_json::json!({
        "owner_address": from_hex,
        "to_address":    to_hex,
        "amount":        sun,
        "visible":       false
    });
    let build_res: serde_json::Value = http_client()
        .post("https://api.trongrid.io/wallet/createtransaction")
        .json(&build_body).send().await.map_err(|e| e.to_string())?
        .json().await.map_err(|e| e.to_string())?;

    if build_res["Error"].is_string() {
        return Err(build_res["Error"].as_str().unwrap_or("Build failed").to_string());
    }

    let raw_data_hex = build_res["raw_data_hex"].as_str()
        .ok_or("No raw_data_hex in response")?;
    let raw_data_bytes = hex::decode(raw_data_hex).map_err(|e| e.to_string())?;

    // Sign SHA256 of raw_data_hex bytes (single hash)
    let hash = Sha256::digest(&raw_data_bytes);
    let (sig, recid) = signing_key.sign_prehash_recoverable(hash.as_ref())
        .map_err(|e| e.to_string())?;

    // TRX signature = r(32) + s(32) + v(1)
    let mut tron_sig = Vec::new();
    tron_sig.extend_from_slice(sig.r().to_bytes().as_slice());
    tron_sig.extend_from_slice(sig.s().to_bytes().as_slice());
    tron_sig.push(recid.to_byte());
    let sig_hex = hex::encode(&tron_sig);

    // Broadcast
    let mut broadcast_body = build_res.clone();
    broadcast_body["signature"] = serde_json::json!([sig_hex]);
    let bcast: serde_json::Value = http_client()
        .post("https://api.trongrid.io/wallet/broadcasttransaction")
        .json(&broadcast_body).send().await.map_err(|e| e.to_string())?
        .json().await.map_err(|e| e.to_string())?;

    if bcast["result"].as_bool().unwrap_or(false) {
        Ok(bcast["txid"].as_str().unwrap_or("").to_string())
    } else {
        Err(bcast["message"].as_str().unwrap_or("Broadcast failed").to_string())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Fee estimation
// ─────────────────────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn estimate_external_fee(
    chain_symbol: String,
    contract:     Option<String>,
) -> Result<String, EgoDesktopError> {
    let fee = match chain_symbol.as_str() {
        c if is_evm(c) => {
            let rpc = evm_rpc(c);
            let gp_res = evm_call(rpc, "eth_gasPrice", serde_json::json!([])).await
                .unwrap_or(serde_json::json!("0x77359400")); // 2 Gwei default
            let gas_price = u128::from_str_radix(
                gp_res.as_str().unwrap_or("0x77359400").trim_start_matches("0x"), 16).unwrap_or(2_000_000_000);
            let gas_limit: u128 = if contract.is_some() { 120_000 } else { 21_000 };
            let fee_wei = gas_price * 12 / 10 * gas_limit;
            let fee_eth = fee_wei as f64 / 1e18;
            let native = match c { "BNB" => "BNB", "MATIC" => "MATIC", "AVAX" => "AVAX", _ => "ETH" };
            format!("{fee_eth:.6} {native}")
        }
        "BTC"  => "~0.00003 BTC".into(),
        "LTC"  => "~0.0005 LTC".into(),
        "DOGE" => "~0.01 DOGE".into(),
        "SOL"  => "~0.000005 SOL".into(),
        "XRP"  => "0.000012 XRP".into(),
        "TRX"  => "~1 TRX".into(),
        "ADA"  => "~0.2 ADA".into(),
        _      => "Unknown".into(),
    };
    Ok(fee)
}

// ─────────────────────────────────────────────────────────────────────────────
// Main send command
// ─────────────────────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn send_external_tx(
    chain_symbol: String,
    to_address:   String,
    amount_str:   String,
    contract:     Option<String>,
    decimals:     Option<u8>,
) -> Result<String, EgoDesktopError> {
    let seed = crate::ledger::load_seed()
        .ok_or_else(|| EgoDesktopError::FileSystemError("Wallet not initialised".into()))?;

    let to = to_address.trim().to_string();

    let txid = match chain_symbol.as_str() {
        c if is_evm(c) => {
            let privkey = secp_privkey(&seed, &format!("ego:{}:0",
                match c { "ETH" => "ethereum", "BNB" => "bnb", "MATIC" => "polygon",
                    "AVAX" => "avalanche", "ARB" => "arbitrum", "OP" => "optimism", _ => "ethereum" }));
            match &contract {
                Some(caddr) => {
                    let dec = decimals.unwrap_or(18) as u32;
                    let amount = parse_human_amount(&amount_str, dec)
                        .map_err(EgoDesktopError::NetworkError)?;
                    let data = erc20_transfer_calldata(&to, amount);
                    send_evm_tx(c, &privkey, caddr, 0, data).await
                }
                None => {
                    let amount = parse_human_amount(&amount_str, 18)
                        .map_err(EgoDesktopError::NetworkError)?;
                    send_evm_tx(c, &privkey, &to, amount, vec![]).await
                }
            }
        }

        "BTC" => {
            let amount_sats = parse_human_amount(&amount_str, 8)
                .map_err(EgoDesktopError::NetworkError)? as u64;
            let my_addr = addr_btc_like(&seed, "ego:bitcoin:0", "bc")
                .map_err(EgoDesktopError::NetworkError)?;
            let utxos = fetch_btc_utxos(&my_addr).await
                .map_err(EgoDesktopError::NetworkError)?;
            send_p2wpkh(&seed, "ego:bitcoin:0", &to, amount_sats, utxos, BtcBroadcast).await
        }

        "LTC" => {
            let amount_sats = parse_human_amount(&amount_str, 8)
                .map_err(EgoDesktopError::NetworkError)? as u64;
            let my_addr = addr_btc_like(&seed, "ego:litecoin:0", "ltc")
                .map_err(EgoDesktopError::NetworkError)?;
            let utxos = fetch_blockcypher_utxos("ltc", &my_addr).await
                .map_err(EgoDesktopError::NetworkError)?;
            send_p2wpkh(&seed, "ego:litecoin:0", &to, amount_sats, utxos,
                BlockcypherBroadcast { coin: "ltc".into() }).await
        }

        "DOGE" => {
            let amount_sats = parse_human_amount(&amount_str, 8)
                .map_err(EgoDesktopError::NetworkError)? as u64;
            send_doge_tx(&seed, &to, amount_sats).await
        }

        "SOL" => {
            let lamports = parse_human_amount(&amount_str, 9)
                .map_err(EgoDesktopError::NetworkError)? as u64;
            send_sol_tx(&seed, &to, lamports).await
        }

        "XRP" => {
            let drops = parse_human_amount(&amount_str, 6)
                .map_err(EgoDesktopError::NetworkError)? as u64;
            send_xrp_tx(&seed, &to, drops).await
        }

        "TRX" => {
            let sun = parse_human_amount(&amount_str, 6)
                .map_err(EgoDesktopError::NetworkError)? as u64;
            send_trx_tx(&seed, &to, sun).await
        }

        "ADA" => {
            let lovelace = parse_human_amount(&amount_str, 6)
                .map_err(EgoDesktopError::NetworkError)? as u64;
            send_ada_tx(&seed, &to, lovelace).await
        }

        _ => Err(format!("Unsupported chain: {chain_symbol}")),
    }
    .map_err(EgoDesktopError::NetworkError)?;

    Ok(txid)
}

/// Map CoinGecko coin ID to Binance USDT trading pair symbol.
fn cgid_to_binance(coin_id: &str) -> Option<&'static str> {
    match coin_id {
        "bitcoin"      => Some("BTCUSDT"),
        "ethereum"     => Some("ETHUSDT"),
        "binancecoin"  => Some("BNBUSDT"),
        "solana"       => Some("SOLUSDT"),
        "cardano"      => Some("ADAUSDT"),
        "ripple"       => Some("XRPUSDT"),
        "tron"         => Some("TRXUSDT"),
        "litecoin"     => Some("LTCUSDT"),
        "dogecoin"     => Some("DOGEUSDT"),
        "matic-network"=> Some("MATICUSDT"),
        "avalanche-2"  => Some("AVAXUSDT"),
        "arbitrum"     => Some("ARBUSDT"),
        "optimism"     => Some("OPUSDT"),
        "polkadot"     => Some("DOTUSDT"),
        "chainlink"    => Some("LINKUSDT"),
        "shiba-inu"    => Some("SHIBUSDT"),
        _ => None,
    }
}

/// Parse close prices from a Binance klines JSON array.
fn parse_klines(arr: &[serde_json::Value]) -> Vec<f64> {
    arr.iter()
        .filter_map(|k| k.get(4)?.as_str()?.parse::<f64>().ok())
        .collect()
}

/// Fetch close prices for a coin using Binance klines.
/// When `limit == 0` (All Time mode) paginates from the very first candle.
#[tauri::command]
pub async fn fetch_coin_chart(
    coin_id:        String,
    kline_interval: String,
    limit:          u32,
) -> Result<Vec<f64>, EgoDesktopError> {
    if coin_id == "tether" || coin_id == "usd-coin" {
        return Ok(vec![1.0; if limit == 0 { 200 } else { limit as usize }]);
    }

    let symbol = cgid_to_binance(&coin_id)
        .ok_or_else(|| EgoDesktopError::NetworkError(format!("No Binance pair for {coin_id}")))?;

    let client = http_client();

    // All Time: paginate from the coin's first candle forward
    if limit == 0 {
        // Jan 1 2017 00:00 UTC in ms — before any Binance listing
        let mut start_ms: u64 = 1_483_228_800_000;
        let mut all: Vec<f64> = Vec::new();

        loop {
            let url = format!(
                "https://api.binance.com/api/v3/klines?symbol={}&interval={}&limit=1000&startTime={}",
                symbol, kline_interval, start_ms
            );
            let json: serde_json::Value = client.get(&url).send().await
                .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?
                .json().await
                .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?;

            let arr = match json.as_array() {
                Some(a) if !a.is_empty() => a,
                _ => break,
            };

            let batch = parse_klines(arr);
            let got = arr.len();

            // Next page starts after the last candle's close time (index 6)
            let last_close = arr.last()
                .and_then(|k| k.get(6))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            all.extend(batch);

            if got < 1000 || last_close == 0 {
                break; // no more pages
            }
            start_ms = last_close + 1;
        }

        return Ok(all);
    }

    // Normal fetch: most recent `limit` candles
    let url = format!(
        "https://api.binance.com/api/v3/klines?symbol={}&interval={}&limit={}",
        symbol, kline_interval, limit.min(1000)
    );
    let json: serde_json::Value = client.get(&url).send().await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?
        .json().await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?;

    let prices = json.as_array()
        .map(|a| parse_klines(a))
        .unwrap_or_default();
    Ok(prices)
}

/// Fetch the current price of a single coin from Binance (lightweight, for live polling).
#[tauri::command]
pub async fn fetch_single_price(coin_id: String) -> Result<f64, EgoDesktopError> {
    // Stablecoins
    if coin_id == "tether" || coin_id == "usd-coin" {
        return Ok(1.0);
    }
    let symbol = cgid_to_binance(&coin_id)
        .ok_or_else(|| EgoDesktopError::NetworkError(format!("No Binance pair for {coin_id}")))?;
    let url = format!("https://api.binance.com/api/v3/ticker/price?symbol={}", symbol);
    let json: serde_json::Value = http_client()
        .get(&url)
        .send()
        .await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?
        .json()
        .await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?;
    json["price"]
        .as_str()
        .and_then(|s| s.parse::<f64>().ok())
        .ok_or_else(|| EgoDesktopError::NetworkError("No price field".into()))
}

/// Fetch OHLC candle data. Returns Vec of [open, high, low, close] arrays.
/// limit=0 triggers all-time paginated fetch (same logic as fetch_coin_chart).
#[tauri::command]
pub async fn fetch_coin_candles(
    coin_id:        String,
    kline_interval: String,
    limit:          u32,
) -> Result<Vec<[f64; 4]>, EgoDesktopError> {
    if coin_id == "tether" || coin_id == "usd-coin" {
        return Ok(vec![[1.0, 1.0, 1.0, 1.0]; if limit == 0 { 200 } else { limit as usize }]);
    }

    let symbol = cgid_to_binance(&coin_id)
        .ok_or_else(|| EgoDesktopError::NetworkError(format!("No Binance pair for {coin_id}")))?;

    let client = http_client();

    fn parse_ohlc(arr: &[serde_json::Value]) -> Vec<[f64; 4]> {
        arr.iter().filter_map(|k| {
            let o = k.get(1)?.as_str()?.parse::<f64>().ok()?;
            let h = k.get(2)?.as_str()?.parse::<f64>().ok()?;
            let l = k.get(3)?.as_str()?.parse::<f64>().ok()?;
            let c = k.get(4)?.as_str()?.parse::<f64>().ok()?;
            Some([o, h, l, c])
        }).collect()
    }

    if limit == 0 {
        let mut start_ms: u64 = 1_483_228_800_000;
        let mut all: Vec<[f64; 4]> = Vec::new();
        loop {
            let url = format!(
                "https://api.binance.com/api/v3/klines?symbol={}&interval={}&limit=1000&startTime={}",
                symbol, kline_interval, start_ms
            );
            let json: serde_json::Value = client.get(&url).send().await
                .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?
                .json().await
                .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?;
            let arr = match json.as_array() {
                Some(a) if !a.is_empty() => a,
                _ => break,
            };
            let last_close = arr.last()
                .and_then(|k| k.get(6)).and_then(|v| v.as_u64()).unwrap_or(0);
            let got = arr.len();
            all.extend(parse_ohlc(arr));
            if got < 1000 || last_close == 0 { break; }
            start_ms = last_close + 1;
        }
        return Ok(all);
    }

    let url = format!(
        "https://api.binance.com/api/v3/klines?symbol={}&interval={}&limit={}",
        symbol, kline_interval, limit.min(1000)
    );
    let json: serde_json::Value = client.get(&url).send().await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?
        .json().await
        .map_err(|e| EgoDesktopError::NetworkError(e.to_string()))?;
    Ok(json.as_array().map(|a| parse_ohlc(a)).unwrap_or_default())
}

// ── External-send email 2FA ───────────────────────────────────────────────────

#[derive(Clone)]
struct PendingExtTx {
    chain_symbol: String,
    to_address:   String,
    amount_str:   String,
    contract:     Option<String>,
    decimals:     Option<u8>,
    expiry:       i64,
}

static PENDING_EXT_TXS: once_cell::sync::Lazy<std::sync::Mutex<std::collections::HashMap<String, PendingExtTx>>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

static EXT_TX_ATTEMPTS: once_cell::sync::Lazy<std::sync::Mutex<std::collections::HashMap<String, u32>>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

#[derive(Debug, serde::Serialize)]
pub struct ExtTxCodeResponse {
    pub tx_id:        String,
    pub masked_email: String,
}

#[tauri::command]
pub async fn request_ext_tx_code(
    chain_symbol: String,
    to_address:   String,
    amount_str:   String,
    contract:     Option<String>,
    decimals:     Option<u8>,
) -> Result<ExtTxCodeResponse, EgoDesktopError> {
    let ledger = crate::ledger::Ledger::load();
    let email  = ledger.registered_email.clone();
    if email.is_empty() {
        return Err(EgoDesktopError::InvalidInput(
            "No email on file. Set an email in Settings to use 2FA.".into(),
        ));
    }

    crate::email::check_send_limit(&email)
        .map_err(EgoDesktopError::InvalidInput)?;

    let tx_id  = uuid::Uuid::new_v4().to_string();
    let code   = crate::email::gen_otp_code();
    let expiry = chrono::Utc::now().timestamp() + 600;

    crate::email::store_otp(&format!("ext:{}", tx_id), &code);
    {
        let mut map = PENDING_EXT_TXS.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        map.retain(|_, v| v.expiry > now);
        map.insert(tx_id.clone(), PendingExtTx {
            chain_symbol: chain_symbol.clone(),
            to_address:   to_address.clone(),
            amount_str:   amount_str.clone(),
            contract,
            decimals,
            expiry,
        });
    }

    let display = format!("{} {}", amount_str, chain_symbol);
    crate::email::send_tx_code_email(&email, &code, &display, &to_address)
        .await
        .map_err(|e| EgoDesktopError::NetworkError(format!("Failed to send code: {e}")))?;

    crate::email::record_send_attempt(&email);

    let masked = if let Some(at) = email.find('@') {
        let local = &email[..at];
        let domain = &email[at..];
        if local.len() > 3 { format!("{}***{}", &local[..2], domain) }
        else                { format!("{}***{}", &local[..1], domain) }
    } else { "***".to_string() };

    Ok(ExtTxCodeResponse { tx_id, masked_email: masked })
}

#[tauri::command]
pub async fn confirm_ext_tx(
    tx_id: String,
    code:  String,
) -> Result<String, EgoDesktopError> {
    let valid = crate::email::verify_otp(&format!("ext:{}", tx_id), code.trim());
    if !valid {
        let attempts = {
            let mut map = EXT_TX_ATTEMPTS.lock().unwrap();
            let count = map.entry(tx_id.clone()).or_insert(0);
            *count += 1;
            *count
        };
        if attempts >= 3 {
            PENDING_EXT_TXS.lock().unwrap().remove(&tx_id);
            EXT_TX_ATTEMPTS.lock().unwrap().remove(&tx_id);
            return Err(EgoDesktopError::InvalidInput(
                "Too many failed attempts. Transaction has been cancelled.".into(),
            ));
        }
        return Err(EgoDesktopError::InvalidInput(format!(
            "Incorrect code. {} attempt{} remaining.",
            3 - attempts, if 3 - attempts == 1 { "" } else { "s" }
        )));
    }

    EXT_TX_ATTEMPTS.lock().unwrap().remove(&tx_id);
    let email = crate::ledger::Ledger::load().registered_email;
    if !email.is_empty() { crate::email::reset_send_attempts(&email); }

    let pending = {
        let mut map = PENDING_EXT_TXS.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        match map.remove(&tx_id) {
            Some(p) if p.expiry > now => p,
            Some(_) => return Err(EgoDesktopError::InvalidInput(
                "Transaction request expired. Please start over.".into(),
            )),
            None => return Err(EgoDesktopError::InvalidInput(
                "Transaction not found. It may have already been submitted or expired.".into(),
            )),
        }
    };

    // Execute the actual external send now that 2FA is verified
    send_external_tx(
        pending.chain_symbol,
        pending.to_address,
        pending.amount_str,
        pending.contract,
        pending.decimals,
    ).await
}
