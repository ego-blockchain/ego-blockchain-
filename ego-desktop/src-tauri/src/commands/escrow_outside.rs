use crate::commands::escrow_chains::{self as chains, ChainClient, ChainNet, NativeEscrow, TokenCfg, FALLBACK_DELAY_SECS};
use crate::commands::multichain::http_client;
use crate::escrow::{cardano as ada, solana as sol};
use crate::market_chain::{EscrowRef, Family, Trade};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

const CONFIRM_TIMEOUT_SECS: u64 = 150;
const CARDANO_MAINNET_MAGIC: u64 = 764_824_073;
const CARDANO_TTL_SLOTS: u64 = 1_800;
const CARDANO_FALLBACK_SLACK_SECS: u64 = 2 * 3_600;
const ESCROW_SEARCH_OUTPUTS: u64 = 4;

pub type Progress<'a> = &'a (dyn Fn(&str) + Send + Sync);

pub fn wallet_ed25519(path: &str) -> Result<SigningKey, String> {
    let seed = crate::ledger::load_seed()?.ok_or("the wallet is not set up yet")?;
    Ok(SigningKey::from_bytes(&crate::commands::multichain::ed25519_seed32(&seed, path)))
}

pub fn cardano_network(net: &ChainNet) -> u8 {
    u8::from(net.chain_id == CARDANO_MAINNET_MAGIC)
}

pub fn cardano_script_address(network: u8) -> String {
    ada::format_address(&ada::script_address(network, &ada::script_hash()))
}

pub fn cardano_key_address(network: u8, key: &SigningKey) -> Vec<u8> {
    ada::key_address(network, &ada::blake2b_224(&key.verifying_key().to_bytes()))
}

pub fn fee_receiver(net: &ChainNet) -> Result<String, String> {
    if !net.fee_receiver.trim().is_empty() {
        return Ok(net.fee_receiver.trim().to_string());
    }
    let height = crate::chain_db::local_chain_height().saturating_add(1);
    let first = crate::market_chain::arbiters_at(height).first().ok_or("the market has no arbiter")?;
    crate::market_chain::arbiter_addresses(first)
        .and_then(|r| r.for_family(net.family).map(str::to_string))
        .ok_or_else(|| format!("the Ego arbiter has not published its {} address yet, so the market fee has nowhere to go", net.label))
}

pub fn arbiter_key_path(net: &ChainNet) -> String {
    match net.family {
        Family::Evm => chains::ARBITER_KEY_PATH.to_string(),
        _ => net.key_path.clone(),
    }
}

pub fn address_for(net: &ChainNet, path: &str) -> Result<String, String> {
    match net.family {
        Family::Evm | Family::Tron => chains::address_from_key(net.family, &chains::wallet_key(path)?),
        Family::Solana => Ok(sol::b58(&wallet_ed25519(path)?.verifying_key().to_bytes())),
        Family::Cardano => Ok(ada::format_address(&cardano_key_address(cardano_network(net), &wallet_ed25519(path)?))),
        Family::Ego => Err("Ego has no outside address".into()),
    }
}

pub fn wallet_address(net: &ChainNet) -> Result<String, String> {
    address_for(net, &net.key_path)
}

pub fn same_address(family: Family, a: &str, b: &str) -> bool {
    match family {
        Family::Evm | Family::Tron => chains::same_address(family, a, b),
        Family::Solana => matches!((sol::parse_key(a), sol::parse_key(b)), (Ok(x), Ok(y)) if x == y),
        Family::Cardano => matches!((ada::parse_address(a), ada::parse_address(b)), (Ok(x), Ok(y)) if x == y),
        Family::Ego => a == b,
    }
}

fn trade_id(trade: &Trade) -> Result<[u8; 32], String> {
    chains::trade_id_bytes(&trade.id)
}

fn base_units(micro: u64, tok: &TokenCfg) -> Result<u64, String> {
    u64::try_from(chains::to_base_units(micro, tok.decimals)).map_err(|_| "the amount is too large for this chain".into())
}

const ESCROW_TEXT: [&str; 11] = [
    "the escrow does not exist",
    "the escrow is already settled",
    "an escrow for this trade already exists",
    "the buyer, seller and arbiter must be three different addresses",
    "the amount does not match what was sent",
    "the safety delay is out of range",
    "this wallet may not do that",
    "the safety delay has not passed yet",
    "the signature is not valid for this escrow",
    "an account in the transaction is not the one the escrow expects",
    "the escrow program did not understand the request",
];

fn digits_after(s: &str, marker: &str, radix: u32) -> Option<u64> {
    let at = s.find(marker)? + marker.len();
    let text: String = s[at..].chars().take_while(|c| c.is_digit(radix)).collect();
    u64::from_str_radix(&text, radix).ok()
}

pub fn failed_instruction(err: &str) -> Option<(usize, u32)> {
    if let Some(at) = err.find("Error processing Instruction ") {
        let rest = &err[at..];
        let index = digits_after(rest, "Error processing Instruction ", 10)?;
        let code = digits_after(rest, "custom program error: 0x", 16)?;
        return Some((index as usize, code as u32));
    }
    let at = err.find("\"InstructionError\":[")?;
    let rest = &err[at..];
    let index = digits_after(rest, "\"InstructionError\":[", 10)?;
    let code = digits_after(rest, "\"Custom\":", 10)?;
    Some((index as usize, code as u32))
}

pub fn explain_solana_error(ixs: &[sol::Ix], err: String) -> String {
    if let Some((index, code)) = failed_instruction(&err) {
        match ixs.get(index).map(|ix| ix.program) {
            Some(p) if p == sol::ED25519_PROGRAM => return "the buyer's signature is not valid for this escrow".into(),
            Some(p) if p == sol::TOKEN_PROGRAM && code == 1 => return "this wallet does not hold enough of the coin".into(),
            Some(p) if ![sol::SYSTEM_PROGRAM, sol::TOKEN_PROGRAM, sol::ATA_PROGRAM, sol::COMPUTE_BUDGET_PROGRAM].contains(&p) => {
                if let Some(text) = ESCROW_TEXT.get(code as usize) {
                    return text.to_string();
                }
            }
            _ => {}
        }
    }
    if err.contains("Attempt to debit an account but found no record of a prior credit") || err.contains("insufficient lamports") {
        return "this wallet does not have enough SOL for the network fee".into();
    }
    err
}

pub struct SolanaClient<'a> {
    pub net: &'a ChainNet,
}

impl<'a> SolanaClient<'a> {
    pub fn new(net: &'a ChainNet) -> Self {
        Self { net }
    }

    async fn rpc(&self, method: &str, params: Value) -> Result<Value, String> {
        let mut last = format!("no RPC endpoint is configured for {}", self.net.label);
        for url in &self.net.rpc {
            let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
            let v: Value = match http_client().post(url).json(&body).send().await {
                Ok(r) => match r.json().await {
                    Ok(v) => v,
                    Err(e) => {
                        last = e.to_string();
                        continue;
                    }
                },
                Err(e) => {
                    last = e.to_string();
                    continue;
                }
            };
            if let Some(err) = v.get("error") {
                let logs = err["data"]["logs"].as_array().map(|l| {
                    l.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" | ")
                });
                let message = err["message"].as_str().unwrap_or("").to_string();
                return Err(match logs {
                    Some(l) if !l.is_empty() => format!("{message} {l}"),
                    _ => message,
                });
            }
            return Ok(v["result"].clone());
        }
        Err(last)
    }

    pub fn program(&self) -> Result<sol::Key, String> {
        sol::parse_key(&self.net.escrow).map_err(|_| format!("no escrow program is configured for {}", self.net.label))
    }

    pub async fn account(&self, key: &sol::Key) -> Result<Option<(u64, Vec<u8>)>, String> {
        let r = self
            .rpc("getAccountInfo", json!([sol::b58(key), { "encoding": "base64", "commitment": "confirmed" }]))
            .await?;
        let v = &r["value"];
        if v.is_null() {
            return Ok(None);
        }
        let data = v["data"][0].as_str().unwrap_or("");
        let bytes = B64.decode(data).map_err(|e| e.to_string())?;
        Ok(Some((v["lamports"].as_u64().unwrap_or(0), bytes)))
    }

    pub async fn balance(&self, owner: &sol::Key) -> Result<u64, String> {
        let r = self.rpc("getBalance", json!([sol::b58(owner), { "commitment": "confirmed" }])).await?;
        Ok(r["value"].as_u64().unwrap_or(0))
    }

    pub async fn token_balance(&self, mint: &sol::Key, owner: &sol::Key) -> Result<u64, String> {
        Ok(self
            .account(&sol::token_account_address(owner, mint))
            .await?
            .and_then(|(_, d)| sol::token_account_amount(&d))
            .map(|(_, _, amount)| amount)
            .unwrap_or(0))
    }

    pub async fn rent_exempt(&self, len: usize) -> Result<u64, String> {
        let r = self.rpc("getMinimumBalanceForRentExemption", json!([len])).await?;
        r.as_u64().ok_or_else(|| "the network returned no rent figure".into())
    }

    pub async fn airdrop(&self, to: &sol::Key, lamports: u64) -> Result<String, String> {
        let r = self.rpc("requestAirdrop", json!([sol::b58(to), lamports])).await?;
        let sig = r.as_str().ok_or("the faucet returned no signature")?.to_string();
        self.confirm(&sig).await?;
        Ok(sig)
    }

    async fn blockhash(&self) -> Result<sol::Key, String> {
        let r = self.rpc("getLatestBlockhash", json!([{ "commitment": "confirmed" }])).await?;
        sol::parse_key(r["value"]["blockhash"].as_str().unwrap_or("")).map_err(|_| "the network returned no blockhash".into())
    }

    pub async fn send(&self, payer: &SigningKey, others: &[&SigningKey], ixs: Vec<sol::Ix>) -> Result<String, String> {
        let blockhash = self.blockhash().await?;
        let compiled = sol::compile(&payer.verifying_key().to_bytes(), &ixs, &blockhash)?;
        let mut keys = vec![payer];
        keys.extend_from_slice(others);
        let tx = sol::sign(&compiled, &keys)?;
        let sig = sol::first_signature(&tx).ok_or("the transaction has no signature")?;
        self.rpc(
            "sendTransaction",
            json!([B64.encode(&tx), { "encoding": "base64", "preflightCommitment": "confirmed", "maxRetries": 5 }]),
        )
        .await
        .map_err(|e| explain_solana_error(&ixs, e))?;
        self.confirm(&sig).await.map_err(|e| explain_solana_error(&ixs, e))?;
        Ok(sig)
    }

    pub async fn confirm(&self, sig: &str) -> Result<(), String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(CONFIRM_TIMEOUT_SECS);
        loop {
            let r = self
                .rpc("getSignatureStatuses", json!([[sig], { "searchTransactionHistory": true }]))
                .await
                .unwrap_or(Value::Null);
            let s = &r["value"][0];
            if !s.is_null() {
                if !s["err"].is_null() {
                    return Err(format!("the transaction failed on {}: {}", self.net.label, s["err"]));
                }
                if matches!(s["confirmationStatus"].as_str(), Some("confirmed" | "finalized")) {
                    return Ok(());
                }
            }
            if std::time::Instant::now() > deadline {
                return Err(format!("{} has not confirmed {sig:.20} yet; check the explorer", self.net.label));
            }
            tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        }
    }

    pub async fn first_signature_for(&self, key: &sol::Key) -> Result<Option<String>, String> {
        let r = self.rpc("getSignaturesForAddress", json!([sol::b58(key), { "limit": 20 }])).await?;
        Ok(r.as_array().and_then(|l| l.last()).and_then(|e| e["signature"].as_str()).map(str::to_string))
    }

    pub async fn read_escrow(&self, program: &sol::Key, trade_id: &[u8; 32], seller: &sol::Key) -> Result<Option<sol::EscrowAccount>, String> {
        let (at, _) = sol::escrow_address(program, trade_id, seller);
        match self.account(&at).await? {
            Some((_, data)) => sol::decode_escrow(&at, &data).map(Some),
            None => Ok(None),
        }
    }

    pub async fn open(&self, seller: &SigningKey, program: &sol::Key, args: &sol::OpenArgs, progress: Progress<'_>) -> Result<String, String> {
        let me = seller.verifying_key().to_bytes();
        let (escrow_at, _) = sol::escrow_address(program, &args.trade_id, &me);
        if self.account(&escrow_at).await?.is_some() {
            return self
                .first_signature_for(&escrow_at)
                .await?
                .ok_or_else(|| "an escrow for this trade exists but its funding transaction was not found".into());
        }
        let have = match args.mint {
            Some(m) => self.token_balance(&m, &me).await?,
            None => self.balance(&me).await?,
        };
        if have < args.total {
            return Err(format!("this wallet holds {have} base units but the escrow needs {}", args.total));
        }
        progress("open");
        self.send(seller, &[], vec![sol::open_ix(program, &me, args)]).await
    }

    pub async fn release(&self, seller: &SigningKey, program: &sol::Key, e: &sol::EscrowAccount) -> Result<String, String> {
        let mut ixs = sol::payout_token_accounts(&seller.verifying_key().to_bytes(), e, true);
        ixs.push(sol::release_ix(program, e));
        self.send(seller, &[], ixs).await
    }

    pub async fn resolve(&self, arbiter: &SigningKey, program: &sol::Key, e: &sol::EscrowAccount, to_buyer: bool) -> Result<String, String> {
        let me = arbiter.verifying_key().to_bytes();
        let mut ixs = sol::payout_token_accounts(&me, e, to_buyer);
        ixs.push(sol::resolve_ix(program, e, &me, to_buyer));
        self.send(arbiter, &[], ixs).await
    }

    pub async fn cancel_for(&self, relayer: &SigningKey, program: &sol::Key, e: &sol::EscrowAccount, signature: &[u8; 64]) -> Result<String, String> {
        let mut ixs = sol::payout_token_accounts(&relayer.verifying_key().to_bytes(), e, false);
        ixs.extend(sol::cancel_for_ixs(program, e, signature));
        self.send(relayer, &[], ixs).await
    }
}

pub struct CardanoClient<'a> {
    pub net: &'a ChainNet,
}

#[derive(Debug, Clone)]
pub struct FoundEscrow {
    pub utxo: ada::Utxo,
    pub datum: ada::EscrowDatum,
    pub spent: bool,
    pub block_time: u64,
}

fn rational(x: f64) -> (u64, u64) {
    let den = 10_000_000u64;
    ((x * den as f64).round() as u64, den)
}

pub fn released_outputs(d: &ada::EscrowDatum) -> Vec<ada::Output> {
    let mut outputs = vec![ada::Output { address: d.buyer.clone(), lovelace: d.total - d.fee, datum: None }];
    if d.fee >= ada::MIN_FEE_OUTPUT {
        outputs.push(ada::Output { address: d.fee_receiver.clone(), lovelace: d.fee, datum: None });
    }
    outputs
}

pub fn refunded_outputs(d: &ada::EscrowDatum) -> Vec<ada::Output> {
    vec![ada::Output { address: d.seller.clone(), lovelace: d.total, datum: None }]
}

pub fn cardano_open_plan(seller: &[u8], script: &[u8], datum: &ada::EscrowDatum, funding: Vec<ada::Utxo>, ttl: u64) -> Result<ada::Plan, String> {
    Ok(ada::Plan {
        spend: None,
        outputs: vec![ada::Output { address: script.to_vec(), lovelace: datum.total, datum: Some(datum.to_data()?) }],
        funding,
        change: seller.to_vec(),
        required_signers: vec![],
        valid_from: None,
        ttl,
        witnesses: 1,
    })
}

pub fn cardano_spend_plan(
    me: &[u8],
    found: &FoundEscrow,
    action: ada::Action,
    outputs: Vec<ada::Output>,
    required_signers: Vec<ada::Pkh>,
    funding: Vec<ada::Utxo>,
    ttl: u64,
) -> ada::Plan {
    ada::Plan {
        spend: Some(ada::ScriptSpend { utxo: found.utxo.clone(), action, ex_units: (ada::SPEND_MEM, ada::SPEND_STEPS) }),
        outputs,
        funding: funding.into_iter().filter(|u| u.tx_hash != found.utxo.tx_hash || u.index != found.utxo.index).collect(),
        change: me.to_vec(),
        required_signers,
        valid_from: None,
        ttl,
        witnesses: 1,
    }
}

impl<'a> CardanoClient<'a> {
    pub fn new(net: &'a ChainNet) -> Self {
        Self { net }
    }

    fn network(&self) -> u8 {
        cardano_network(self.net)
    }

    async fn call(&self, path: &str, body: Option<Value>) -> Result<Value, String> {
        let mut last = format!("no API endpoint is configured for {}", self.net.label);
        for base in &self.net.rpc {
            let url = format!("{}{}", base.trim_end_matches('/'), path);
            let req = match &body {
                Some(b) => http_client().post(&url).json(b),
                None => http_client().get(&url),
            };
            match req.send().await {
                Ok(r) if r.status().is_success() => match r.json::<Value>().await {
                    Ok(v) => return Ok(v),
                    Err(e) => last = e.to_string(),
                },
                Ok(r) => last = format!("{} answered {}: {}", self.net.label, r.status(), r.text().await.unwrap_or_default()),
                Err(e) => last = e.to_string(),
            }
        }
        Err(last)
    }

    pub async fn tip_slot(&self) -> Result<u64, String> {
        let v = self.call("/tip", None).await?;
        v[0]["abs_slot"].as_u64().ok_or_else(|| format!("{} returned no tip", self.net.label))
    }

    pub async fn params(&self) -> Result<ada::Params, String> {
        let v = self.call("/cli_protocol_params", None).await?;
        params_of(&v)
    }

    pub async fn utxos(&self, address: &str) -> Result<Vec<ada::Utxo>, String> {
        let v = self.call("/address_utxos", Some(json!({ "_addresses": [address], "_extended": true }))).await?;
        Ok(v.as_array().map(|list| list.iter().filter_map(utxo_of).collect()).unwrap_or_default())
    }

    pub async fn balance(&self, address: &str) -> Result<u64, String> {
        Ok(self.utxos(address).await?.iter().map(|u| u.lovelace).sum())
    }

    pub async fn submit(&self, tx: &[u8]) -> Result<String, String> {
        let mut last = format!("no API endpoint is configured for {}", self.net.label);
        for base in &self.net.rpc {
            let url = format!("{}/submittx", base.trim_end_matches('/'));
            match http_client().post(&url).header("Content-Type", "application/cbor").body(tx.to_vec()).send().await {
                Ok(r) => {
                    let ok = r.status().is_success();
                    let text = r.text().await.unwrap_or_default();
                    if ok {
                        return Ok(text.trim().trim_matches('"').to_string());
                    }
                    return Err(cardano_friendly(&text));
                }
                Err(e) => last = e.to_string(),
            }
        }
        Err(last)
    }

    pub async fn wait(&self, tx_hash: &str) -> Result<(), String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(CONFIRM_TIMEOUT_SECS * 2);
        loop {
            let v = self.call("/tx_status", Some(json!({ "_tx_hashes": [tx_hash] }))).await.unwrap_or(Value::Null);
            if v[0]["num_confirmations"].as_u64().is_some_and(|n| n >= 1) {
                return Ok(());
            }
            if std::time::Instant::now() > deadline {
                return Err(format!("{} has not confirmed {tx_hash:.16} yet; check the explorer", self.net.label));
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }

    pub async fn find_escrow(&self, reference: &EscrowRef, trade_id: &[u8; 32]) -> Result<Option<FoundEscrow>, String> {
        let script = ada::parse_address(&reference.contract)?;
        let refs: Vec<String> = (0..ESCROW_SEARCH_OUTPUTS).map(|i| format!("{}#{i}", reference.tx)).collect();
        let v = self.call("/utxo_info", Some(json!({ "_utxo_refs": refs, "_extended": true }))).await?;
        for entry in v.as_array().cloned().unwrap_or_default() {
            let at_script = entry["address"].as_str().and_then(|a| ada::parse_address(a).ok()).is_some_and(|a| a == script);
            if !at_script {
                continue;
            }
            let Some(bytes) = entry["inline_datum"]["bytes"].as_str().and_then(|h| hex::decode(h).ok()) else { continue };
            let Ok(data) = ada::Data::from_cbor(&bytes) else { continue };
            let Ok(datum) = ada::EscrowDatum::from_data(&data, self.network()) else { continue };
            if &datum.trade_id != trade_id {
                continue;
            }
            let Some(utxo) = utxo_of(&entry) else { continue };
            return Ok(Some(FoundEscrow {
                utxo,
                datum,
                spent: entry["is_spent"].as_bool().unwrap_or(false),
                block_time: entry["block_time"].as_u64().unwrap_or(0),
            }));
        }
        Ok(None)
    }

    async fn sign_submit(&self, key: &SigningKey, plan: &ada::Plan) -> Result<String, String> {
        let params = self.params().await?;
        let unsigned = ada::build(plan, &params)?;
        let tx = unsigned.sign(&[key]);
        let hash = hex::encode(unsigned.tx_hash());
        self.submit(&tx).await?;
        self.wait(&hash).await?;
        Ok(hash)
    }

    pub async fn pay(&self, from: &SigningKey, to: &[u8], lovelace: u64) -> Result<String, String> {
        let me = cardano_key_address(self.network(), from);
        let funding = self.utxos(&ada::format_address(&me)).await?;
        let tip = self.tip_slot().await?;
        let plan = ada::Plan {
            spend: None,
            outputs: vec![ada::Output { address: to.to_vec(), lovelace, datum: None }],
            funding,
            change: me,
            required_signers: vec![],
            valid_from: None,
            ttl: tip + CARDANO_TTL_SLOTS,
            witnesses: 1,
        };
        self.sign_submit(from, &plan).await
    }

    pub async fn open(&self, seller: &SigningKey, script: &[u8], datum: &ada::EscrowDatum, progress: Progress<'_>) -> Result<String, String> {
        let me = cardano_key_address(self.network(), seller);
        let funding = self.utxos(&ada::format_address(&me)).await?;
        let tip = self.tip_slot().await?;
        let plan = cardano_open_plan(&me, script, datum, funding, tip + CARDANO_TTL_SLOTS)?;
        progress("open");
        self.sign_submit(seller, &plan).await
    }

    async fn spend(
        &self,
        key: &SigningKey,
        found: &FoundEscrow,
        action: ada::Action,
        outputs: Vec<ada::Output>,
        required_signers: Vec<ada::Pkh>,
    ) -> Result<String, String> {
        if found.spent {
            return Err("the escrow on Cardano is already settled".into());
        }
        let me = cardano_key_address(self.network(), key);
        let funding = self.utxos(&ada::format_address(&me)).await?;
        let tip = self.tip_slot().await?;
        let plan = cardano_spend_plan(&me, found, action, outputs, required_signers, funding, tip + CARDANO_TTL_SLOTS);
        self.sign_submit(key, &plan).await
    }

    pub async fn release(&self, seller: &SigningKey, found: &FoundEscrow) -> Result<String, String> {
        let seller_pkh = ada::payment_key_hash(&found.datum.seller).ok_or("the escrow's seller is not a key address")?;
        self.spend(seller, found, ada::Action::Release, released_outputs(&found.datum), vec![seller_pkh]).await
    }

    pub async fn resolve(&self, arbiter: &SigningKey, found: &FoundEscrow, to_buyer: bool) -> Result<String, String> {
        let outputs = if to_buyer { released_outputs(&found.datum) } else { refunded_outputs(&found.datum) };
        self.spend(arbiter, found, ada::Action::Resolve { to_buyer }, outputs, vec![found.datum.arbiter]).await
    }

    pub async fn cancel_for(&self, relayer: &SigningKey, found: &FoundEscrow, vkey: [u8; 32], signature: [u8; 64]) -> Result<String, String> {
        let action = ada::Action::CancelFor { vkey, signature };
        self.spend(relayer, found, action, refunded_outputs(&found.datum), vec![]).await
    }
}

pub fn params_of(v: &Value) -> Result<ada::Params, String> {
    let n = |k: &str| v[k].as_u64().ok_or_else(|| format!("the protocol parameters lack {k}"));
    let prices = &v["executionUnitPrices"];
    let cost_model_v3: Vec<i64> = v["costModels"]["PlutusV3"]
        .as_array()
        .ok_or("the protocol parameters lack the PlutusV3 cost model")?
        .iter()
        .map(|c| c.as_i64().unwrap_or(0))
        .collect();
    Ok(ada::Params {
        min_fee_a: n("txFeePerByte")?,
        min_fee_b: n("txFeeFixed")?,
        coins_per_utxo_byte: n("utxoCostPerByte")?,
        price_mem: rational(prices["priceMemory"].as_f64().ok_or("no memory price")?),
        price_step: rational(prices["priceSteps"].as_f64().ok_or("no step price")?),
        collateral_percent: n("collateralPercentage")?,
        max_tx_size: n("maxTxSize")?,
        cost_model_v3,
    })
}

fn utxo_of(entry: &Value) -> Option<ada::Utxo> {
    let tx_hash: [u8; 32] = hex::decode(entry["tx_hash"].as_str()?).ok()?.try_into().ok()?;
    let lovelace = entry["value"].as_str().and_then(|s| s.parse().ok()).or_else(|| entry["value"].as_u64())?;
    let pure_ada = entry["asset_list"].as_array().is_none_or(|a| a.is_empty()) && entry["reference_script"].is_null();
    Some(ada::Utxo { tx_hash, index: entry["tx_index"].as_u64()?, lovelace, pure_ada })
}

fn cardano_friendly(text: &str) -> String {
    if text.contains("ValueNotConservedUTxO") || text.contains("InsufficientCollateral") {
        return "the wallet's ADA changed while the transaction was built; try again".into();
    }
    if text.contains("BadInputsUTxO") {
        return "a coin in the transaction was already spent; try again in a minute".into();
    }
    if text.contains("MissingVKeyWitnessesUTXOW") || text.contains("MissingRequiredSigners") {
        return "this wallet may not do that".into();
    }
    if text.contains("ScriptFailure") || text.contains("ValidationTagMismatch") || text.contains("PlutusFailure") {
        return "the Cardano escrow refused this step".into();
    }
    if text.contains("OutsideValidityIntervalUTxO") {
        return "the transaction expired before it reached the network; try again".into();
    }
    format!("Cardano refused the transaction: {}", text.chars().take(300).collect::<String>())
}

pub struct Outside<'a> {
    pub net: &'a ChainNet,
    pub tok: &'a TokenCfg,
}

impl<'a> Outside<'a> {
    pub fn new(net: &'a ChainNet, tok: &'a TokenCfg) -> Self {
        Self { net, tok }
    }

    pub fn explorer_tx(&self, tx: &str) -> String {
        format!("{}{}{}", self.net.explorer_tx, tx, self.net.explorer_suffix)
    }

    pub fn explorer_address(&self, address: &str) -> String {
        format!("{}{}{}", self.net.explorer_address, address, self.net.explorer_suffix)
    }

    fn reference<'t>(&self, trade: &'t Trade) -> Result<&'t EscrowRef, String> {
        trade.escrow.as_ref().ok_or_else(|| "the escrow is not funded yet".to_string())
    }

    fn sol_parts(&self, trade: &Trade) -> Result<(sol::Key, [u8; 32], sol::Key), String> {
        let r = self.reference(trade)?;
        Ok((sol::parse_key(&r.contract)?, trade_id(trade)?, sol::parse_key(&r.funder)?))
    }

    async fn sol_escrow(&self, trade: &Trade) -> Result<(sol::Key, sol::EscrowAccount), String> {
        let (program, id, seller) = self.sol_parts(trade)?;
        let e = SolanaClient::new(self.net)
            .read_escrow(&program, &id, &seller)
            .await?
            .ok_or("the escrow on Solana is already closed")?;
        Ok((program, e))
    }

    async fn ada_escrow(&self, trade: &Trade) -> Result<FoundEscrow, String> {
        match CardanoClient::new(self.net).find_escrow(self.reference(trade)?, &trade_id(trade)?).await? {
            Some(f) if !f.spent => Ok(f),
            Some(_) => Err("the escrow on Cardano is already settled".into()),
            None => Err("no Cardano escrow was found for this trade".into()),
        }
    }

    fn evm_key(&self, trade: &Trade) -> Result<[u8; 32], String> {
        let r = self.reference(trade)?;
        let funder = chains::parse_address(self.net.family, &r.funder)?;
        Ok(chains::escrow_key(&trade_id(trade)?, &funder))
    }

    pub async fn balances(&self, owner: &str) -> (Option<u128>, Option<u128>) {
        match self.net.family {
            Family::Evm | Family::Tron => {
                let c = ChainClient::new(self.net);
                let native = c.native_balance(owner).await.ok();
                let token = if self.tok.native {
                    native
                } else if self.tok.token.is_empty() {
                    None
                } else {
                    c.token_balance(&self.tok.token, owner).await.ok()
                };
                (native, token)
            }
            Family::Solana => {
                let c = SolanaClient::new(self.net);
                let Ok(o) = sol::parse_key(owner) else { return (None, None) };
                let native = c.balance(&o).await.ok().map(u128::from);
                let token = if self.tok.native {
                    native
                } else {
                    match sol::parse_key(&self.tok.token) {
                        Ok(mint) => c.token_balance(&mint, &o).await.ok().map(u128::from),
                        Err(_) => None,
                    }
                };
                (native, token)
            }
            Family::Cardano => {
                let native = CardanoClient::new(self.net).balance(owner).await.ok().map(u128::from);
                (native, native)
            }
            Family::Ego => (None, None),
        }
    }

    pub async fn open(&self, trade: &Trade, progress: Progress<'_>) -> Result<EscrowRef, String> {
        let buyer = trade.buyer_payout.clone().ok_or("the buyer named no payout address")?;
        let arbiter = trade.arbiter_payout.clone().ok_or("no arbiter holds this trade yet")?;
        let id = trade_id(trade)?;
        match self.net.family {
            Family::Evm | Family::Tron => {
                let key = chains::wallet_key(&self.net.key_path)?;
                let total = chains::to_base_units(trade.locked_micro, self.tok.decimals);
                let fee = chains::to_base_units(trade.maker_fee_micro, self.tok.decimals);
                let (funder, tx) = ChainClient::new(self.net)
                    .open_escrow(&key, self.tok, &id, &buyer, &arbiter, total, fee, progress)
                    .await?;
                Ok(EscrowRef { contract: self.net.escrow.clone(), funder, tx })
            }
            Family::Solana => {
                let c = SolanaClient::new(self.net);
                let program = c.program()?;
                let key = wallet_ed25519(&self.net.key_path)?;
                let args = sol::OpenArgs {
                    trade_id: id,
                    buyer: sol::parse_key(&buyer)?,
                    arbiter: sol::parse_key(&arbiter)?,
                    fee_receiver: sol::parse_key(&fee_receiver(self.net)?)?,
                    mint: if self.tok.native { None } else { Some(sol::parse_key(&self.tok.token)?) },
                    total: base_units(trade.locked_micro, self.tok)?,
                    fee: base_units(trade.maker_fee_micro, self.tok)?,
                    fallback_delay: FALLBACK_DELAY_SECS,
                };
                let tx = c.open(&key, &program, &args, progress).await?;
                Ok(EscrowRef { contract: sol::b58(&program), funder: sol::b58(&key.verifying_key().to_bytes()), tx })
            }
            Family::Cardano => {
                let network = cardano_network(self.net);
                let script = ada::parse_address(&self.net.escrow)?;
                if ada::payment_script_hash(&script) != Some(ada::script_hash()) {
                    return Err(format!("the configured {} escrow is not this app's escrow script", self.net.label));
                }
                let key = wallet_ed25519(&self.net.key_path)?;
                let seller = cardano_key_address(network, &key);
                let buyer_raw = ada::parse_address(&buyer)?;
                if ada::payment_key_hash(&buyer_raw).is_none() {
                    return Err("the buyer's payout is not a Cardano key address".into());
                }
                let datum = ada::EscrowDatum {
                    trade_id: id,
                    seller: seller.clone(),
                    buyer: buyer_raw,
                    arbiter: ada::payment_key_hash(&ada::parse_address(&arbiter)?).ok_or("the arbiter's address is not a key address")?,
                    fee_receiver: ada::parse_address(&fee_receiver(self.net)?)?,
                    total: base_units(trade.locked_micro, self.tok)?,
                    fee: base_units(trade.maker_fee_micro, self.tok)?,
                    fallback_at: chrono::Utc::now().timestamp_millis()
                        + ((FALLBACK_DELAY_SECS + CARDANO_FALLBACK_SLACK_SECS) * 1_000) as i64,
                    frozen: false,
                };
                let tx = CardanoClient::new(self.net).open(&key, &script, &datum, progress).await?;
                Ok(EscrowRef { contract: self.net.escrow.clone(), funder: ada::format_address(&seller), tx })
            }
            Family::Ego => Err("EGOC is escrowed on Ego".into()),
        }
    }

    pub async fn read(&self, trade: &Trade) -> Result<NativeEscrow, String> {
        match self.net.family {
            Family::Evm | Family::Tron => ChainClient::new(self.net).read_escrow(&self.evm_key(trade)?).await,
            Family::Solana => {
                let (program, id, seller) = self.sol_parts(trade)?;
                Ok(match SolanaClient::new(self.net).read_escrow(&program, &id, &seller).await? {
                    Some(e) => solana_view(&e),
                    None => closed_escrow(),
                })
            }
            Family::Cardano => {
                let found = CardanoClient::new(self.net).find_escrow(self.reference(trade)?, &trade_id(trade)?).await?;
                Ok(match found {
                    Some(f) if !f.spent => cardano_view(&f),
                    _ => closed_escrow(),
                })
            }
            Family::Ego => Err("EGOC is escrowed on Ego".into()),
        }
    }

    pub async fn release(&self, trade: &Trade) -> Result<String, String> {
        match self.net.family {
            Family::Evm | Family::Tron => {
                let key = chains::wallet_key(&self.net.key_path)?;
                ChainClient::new(self.net).release(&key, &self.evm_key(trade)?).await
            }
            Family::Solana => {
                let (program, e) = self.sol_escrow(trade).await?;
                SolanaClient::new(self.net).release(&wallet_ed25519(&self.net.key_path)?, &program, &e).await
            }
            Family::Cardano => {
                let found = self.ada_escrow(trade).await?;
                CardanoClient::new(self.net).release(&wallet_ed25519(&self.net.key_path)?, &found).await
            }
            Family::Ego => Err("EGOC is escrowed on Ego".into()),
        }
    }

    pub async fn resolve(&self, trade: &Trade, to_buyer: bool) -> Result<String, String> {
        let path = arbiter_key_path(self.net);
        match self.net.family {
            Family::Evm | Family::Tron => {
                let key = chains::wallet_key(&path)?;
                ChainClient::new(self.net).resolve(&key, &self.evm_key(trade)?, to_buyer).await
            }
            Family::Solana => {
                let (program, e) = self.sol_escrow(trade).await?;
                SolanaClient::new(self.net).resolve(&wallet_ed25519(&path)?, &program, &e, to_buyer).await
            }
            Family::Cardano => {
                let found = self.ada_escrow(trade).await?;
                CardanoClient::new(self.net).resolve(&wallet_ed25519(&path)?, &found, to_buyer).await
            }
            Family::Ego => Err("EGOC is escrowed on Ego".into()),
        }
    }

    pub async fn buyer_cancel(&self, trade: &Trade) -> Result<String, String> {
        let mine = wallet_address(self.net)?;
        if !trade.buyer_payout.as_deref().is_some_and(|b| same_address(self.net.family, b, &mine)) {
            return Err("the payout address on this trade is not this wallet's, so the cancel has to go through the arbiter".into());
        }
        match self.net.family {
            Family::Evm | Family::Tron => {
                let key = chains::wallet_key(&self.net.key_path)?;
                ChainClient::new(self.net).sign_action(&key, &self.evm_key(trade)?, chains::ACTION_CANCEL).await
            }
            Family::Solana => {
                let (program, id, seller) = self.sol_parts(trade)?;
                let (escrow_at, _) = sol::escrow_address(&program, &id, &seller);
                let key = wallet_ed25519(&self.net.key_path)?;
                Ok(hex::encode(sol::buyer_signature(&key, &program, &escrow_at, sol::ACTION_CANCEL)))
            }
            Family::Cardano => {
                let r = self.reference(trade)?;
                let script = ada::payment_script_hash(&ada::parse_address(&r.contract)?).ok_or("the escrow is not a script address")?;
                let key = wallet_ed25519(&self.net.key_path)?;
                let (vkey, sig) = ada::sign_auth(&key, &script, &trade_id(trade)?, ada::ACTION_CANCEL);
                Ok(format!("{}{}", hex::encode(vkey), hex::encode(sig)))
            }
            Family::Ego => Err("EGOC is escrowed on Ego".into()),
        }
    }

    pub async fn relay_cancel(&self, trade: &Trade, sig_hex: &str) -> Result<String, String> {
        let raw = hex::decode(sig_hex).map_err(|_| "the buyer's signature is not hex".to_string())?;
        match self.net.family {
            Family::Evm | Family::Tron => {
                let key = chains::wallet_key(&self.net.key_path)?;
                ChainClient::new(self.net).cancel_for(&key, &self.evm_key(trade)?, sig_hex).await
            }
            Family::Solana => {
                let signature: [u8; 64] = raw.try_into().map_err(|_| "the buyer's Solana signature is not 64 bytes")?;
                let (program, e) = self.sol_escrow(trade).await?;
                SolanaClient::new(self.net).cancel_for(&wallet_ed25519(&self.net.key_path)?, &program, &e, &signature).await
            }
            Family::Cardano => {
                if raw.len() != 96 {
                    return Err("the buyer's Cardano signature is not 96 bytes".into());
                }
                let vkey: [u8; 32] = raw[..32].try_into().map_err(|_| "bad key")?;
                let signature: [u8; 64] = raw[32..].try_into().map_err(|_| "bad signature")?;
                let found = self.ada_escrow(trade).await?;
                CardanoClient::new(self.net).cancel_for(&wallet_ed25519(&self.net.key_path)?, &found, vkey, signature).await
            }
            Family::Ego => Err("EGOC is escrowed on Ego".into()),
        }
    }

    pub fn verify(&self, trade: &Trade, funder: &str, e: &NativeEscrow) -> Vec<String> {
        match self.net.family {
            Family::Evm | Family::Tron => chains::verify_escrow(trade, self.net, self.tok, funder, e),
            _ => verify_ed25519_chain(trade, self.net, self.tok, funder, e),
        }
    }
}

pub fn solana_view(e: &sol::EscrowAccount) -> NativeEscrow {
    NativeEscrow {
        seller: sol::b58(&e.seller),
        opened_at: e.opened_at.max(0) as u64,
        state: e.state,
        frozen: e.frozen,
        buyer: sol::b58(&e.buyer),
        fallback_at: e.fallback_at.max(0) as u64,
        arbiter: sol::b58(&e.arbiter),
        token: e.mint.map(|m| sol::b58(&m)).unwrap_or_default(),
        total: e.total as u128,
        fee: e.fee as u128,
        fee_receiver: Some(sol::b58(&e.fee_receiver)),
    }
}

pub fn cardano_view(f: &FoundEscrow) -> NativeEscrow {
    NativeEscrow {
        seller: ada::format_address(&f.datum.seller),
        opened_at: f.block_time,
        state: chains::STATE_FUNDED,
        frozen: f.datum.frozen,
        buyer: ada::format_address(&f.datum.buyer),
        fallback_at: (f.datum.fallback_at.max(0) / 1_000) as u64,
        arbiter: hex::encode(f.datum.arbiter),
        token: String::new(),
        total: f.utxo.lovelace.min(f.datum.total) as u128,
        fee: f.datum.fee as u128,
        fee_receiver: Some(ada::format_address(&f.datum.fee_receiver)),
    }
}

fn closed_escrow() -> NativeEscrow {
    NativeEscrow {
        seller: String::new(),
        opened_at: 0,
        state: 0,
        frozen: false,
        buyer: String::new(),
        fallback_at: 0,
        arbiter: String::new(),
        token: String::new(),
        total: 0,
        fee: 0,
        fee_receiver: None,
    }
}

pub fn verify_ed25519_chain(trade: &Trade, net: &ChainNet, tok: &TokenCfg, funder: &str, e: &NativeEscrow) -> Vec<String> {
    let f = net.family;
    let mut problems = Vec::new();
    if e.state != chains::STATE_FUNDED {
        problems.push(format!("no open escrow exists on {} for this trade", net.label));
        return problems;
    }
    if !same_address(f, &e.seller, funder) {
        problems.push("the escrow was funded by a different wallet".into());
    }
    match trade.buyer_payout.as_deref() {
        Some(b) if same_address(f, &e.buyer, b) => {}
        _ => problems.push("the escrow pays a different buyer address".into()),
    }
    let arbiter_ok = match (f, trade.arbiter_payout.as_deref()) {
        (Family::Cardano, Some(a)) => ada::parse_address(a)
            .ok()
            .and_then(|raw| ada::payment_key_hash(&raw))
            .is_some_and(|pkh| hex::encode(pkh) == e.arbiter),
        (_, Some(a)) => same_address(f, &e.arbiter, a),
        _ => false,
    };
    if !arbiter_ok {
        problems.push("the escrow names a different arbiter".into());
    }
    match fee_receiver(net) {
        Ok(expected) if e.fee_receiver.as_deref().is_some_and(|r| same_address(f, r, &expected)) => {}
        Ok(_) => problems.push("the escrow sends the fee to an address this app does not recognise".into()),
        Err(e) => problems.push(e),
    }
    let token_ok = if tok.native { e.token.is_empty() } else { same_address(f, &e.token, &tok.token) };
    if !token_ok {
        problems.push(format!("the escrow holds a different coin than {}", tok.asset));
    }
    if e.total != chains::to_base_units(trade.locked_micro, tok.decimals) {
        problems.push("the escrow holds a different amount than the trade".into());
    }
    if e.fee != chains::to_base_units(trade.maker_fee_micro, tok.decimals) {
        problems.push("the escrow charges a different fee than the trade".into());
    }
    if e.fallback_at.saturating_sub(e.opened_at) < FALLBACK_DELAY_SECS {
        problems.push("the seller's safety delay is too short".into());
    }
    if e.frozen {
        problems.push("the escrow is frozen pending the arbiter".into());
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::escrow_chains::default_networks;

    fn random_key() -> SigningKey {
        use rand::RngCore;
        let mut b = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut b);
        SigningKey::from_bytes(&b)
    }

    fn pk(k: &SigningKey) -> sol::Key {
        k.verifying_key().to_bytes()
    }

    fn trade_for(id: &[u8; 32], asset: &str, locked: u64, fee: u64, buyer: &str, arbiter: &str, escrow: Option<EscrowRef>) -> Trade {
        let mut t: Trade = serde_json::from_value(json!({
            "id": format!("0x{}", hex::encode(id)),
            "offer_id": "0x00",
            "maker": "egot1seller",
            "taker": "egot1buyer",
            "seller": "egot1seller",
            "buyer": "egot1buyer",
            "asset": asset,
            "amount_micro": locked - fee,
            "maker_fee_micro": fee,
            "locked_micro": locked,
            "fiat": "USD",
            "fiat_micro": locked - fee,
            "price_micro": 1_000_000,
            "method": "wise",
            "payment_window_secs": 900,
            "state": "locked",
            "opened_height": 1,
            "opened_at": 1,
        }))
        .unwrap();
        t.buyer_payout = Some(buyer.to_string());
        t.arbiter_payout = Some(arbiter.to_string());
        t.escrow = escrow;
        t
    }

    #[test]
    fn cardano_rejections_read_as_sentences() {
        let missing = r#"{"error":["ConwayUtxowFailure (MissingVKeyWitnessesUTXOW (NonEmptySet (fromList [KeyHash {unKeyHash = \"a8d2\"}])))"]}"#;
        assert_eq!(cardano_friendly(missing), "this wallet may not do that");
        assert_eq!(cardano_friendly("PlutusFailure: the validator crashed"), "the Cardano escrow refused this step");
        assert!(cardano_friendly("something new").starts_with("Cardano refused the transaction"));
    }

    #[test]
    fn solana_errors_are_read_against_the_instruction_that_failed() {
        let program = [0x42; 32];
        let ixs = vec![
            sol::create_token_account_ix(&[1; 32], &[1; 32], &[2; 32]),
            sol::ed25519_ix(&[3; 32], &[0; 64], b"m"),
            sol::Ix { program, accounts: vec![], data: vec![sol::IX_CANCEL_FOR] },
        ];
        let at = |i: usize, code: u32| format!("Transaction simulation failed: Error processing Instruction {i}: custom program error: 0x{code:x}");
        assert_eq!(explain_solana_error(&ixs, at(1, 2)), "the buyer's signature is not valid for this escrow");
        assert_eq!(explain_solana_error(&ixs, at(2, 2)), "an escrow for this trade already exists");
        assert_eq!(explain_solana_error(&ixs, at(2, 6)), "this wallet may not do that");
        assert!(explain_solana_error(&ixs, at(0, 2)).contains("Instruction 0"), "an ATA error is passed through");
        let status = "the transaction failed on Solana devnet: {\"InstructionError\":[2,{\"Custom\":9}]}".to_string();
        assert_eq!(failed_instruction(&status), Some((2, 9)));
        assert_eq!(explain_solana_error(&ixs, status), "an account in the transaction is not the one the escrow expects");
    }

    #[test]
    fn a_cardano_view_reports_seconds_and_the_arbiter_key_hash() {
        let datum = ada::EscrowDatum {
            trade_id: [1; 32],
            seller: ada::key_address(0, &[1; 28]),
            buyer: ada::key_address(0, &[2; 28]),
            arbiter: [3; 28],
            fee_receiver: ada::key_address(0, &[4; 28]),
            total: 20_200_000,
            fee: 200_000,
            fallback_at: 1_800_000_000_000 + (FALLBACK_DELAY_SECS as i64 + 10) * 1_000,
            frozen: false,
        };
        let found = FoundEscrow {
            utxo: ada::Utxo { tx_hash: [9; 32], index: 0, lovelace: 20_200_000, pure_ada: true },
            datum: datum.clone(),
            spent: false,
            block_time: 1_800_000_000,
        };
        let view = cardano_view(&found);
        assert_eq!(view.fallback_at - view.opened_at, FALLBACK_DELAY_SECS + 10);
        assert_eq!(view.arbiter, hex::encode([3u8; 28]));
        let mut net = default_networks().net("cardano").unwrap().clone();
        net.fee_receiver = ada::format_address(&datum.fee_receiver);
        let tok = default_networks().token("ADA").unwrap().clone();
        let arbiter = ada::format_address(&ada::key_address(0, &[3; 28]));
        let reference = EscrowRef { contract: net.escrow.clone(), funder: view.seller.clone(), tx: "ab".repeat(32) };
        let trade = trade_for(&[1; 32], "ADA", 20_200_000, 200_000, &view.buyer, &arbiter, Some(reference));
        assert!(verify_ed25519_chain(&trade, &net, &tok, &view.seller, &view).is_empty());
        let wrong = trade_for(&[1; 32], "ADA", 20_200_000, 200_000, &view.seller, &view.buyer, None);
        assert_eq!(verify_ed25519_chain(&wrong, &net, &tok, &view.seller, &view).len(), 2);
        assert!(released_outputs(&datum).len() == 1, "a fee under one ADA has no output of its own");
    }

    #[test]
    #[ignore]
    fn the_solana_adapter_drives_a_real_escrow() {
        let (Ok(rpc), Ok(program_b58)) = (std::env::var("EGO_SOL_RPC"), std::env::var("EGO_SOL_PROGRAM")) else {
            return;
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let (seller, buyer, arbiter, fee, mint_key) = (random_key(), random_key(), random_key(), random_key(), random_key());
            let mut net = default_networks().net("solana").unwrap().clone();
            net.rpc = vec![rpc];
            net.escrow = program_b58.clone();
            net.fee_receiver = sol::b58(&pk(&fee));
            let program = sol::parse_key(&program_b58).unwrap();
            let c = SolanaClient::new(&net);
            let funder = std::env::var("EGO_SOL_FUNDER").ok().map(|path| {
                let raw: Vec<u8> = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
                SigningKey::from_bytes(&raw[..32].try_into().unwrap())
            });
            let small = funder.is_some();
            for (k, lamports) in [(&seller, 400_000_000u64), (&arbiter, 50_000_000), (&fee, 10_000_000)] {
                match &funder {
                    Some(f) => {
                        let mut data = 2u32.to_le_bytes().to_vec();
                        data.extend_from_slice(&lamports.to_le_bytes());
                        let ix = sol::Ix { program: sol::SYSTEM_PROGRAM, accounts: vec![sol::Meta::sw(pk(f)), sol::Meta::w(pk(k))], data };
                        c.send(f, &[], vec![ix]).await.unwrap();
                    }
                    None => {
                        c.airdrop(&pk(k), lamports * 50).await.unwrap();
                    }
                }
            }
            let (native_locked, native_fee) = if small { (101_000u64, 1_000u64) } else { (1_010_000, 10_000) };

            let mint = pk(&mint_key);
            let rent = c.rent_exempt(82).await.unwrap();
            let mut create = 0u32.to_le_bytes().to_vec();
            create.extend_from_slice(&rent.to_le_bytes());
            create.extend_from_slice(&82u64.to_le_bytes());
            create.extend_from_slice(&sol::TOKEN_PROGRAM);
            let mut init = vec![20u8, 6];
            init.extend_from_slice(&pk(&seller));
            init.push(0);
            let mut mint_to = vec![7u8];
            mint_to.extend_from_slice(&1_000_000_000u64.to_le_bytes());
            let seller_ata = sol::token_account_address(&pk(&seller), &mint);
            c.send(
                &seller,
                &[&mint_key],
                vec![
                    sol::Ix { program: sol::SYSTEM_PROGRAM, accounts: vec![sol::Meta::sw(pk(&seller)), sol::Meta::sw(mint)], data: create },
                    sol::Ix { program: sol::TOKEN_PROGRAM, accounts: vec![sol::Meta::w(mint)], data: init },
                    sol::create_token_account_ix(&pk(&seller), &pk(&seller), &mint),
                    sol::Ix {
                        program: sol::TOKEN_PROGRAM,
                        accounts: vec![sol::Meta::w(mint), sol::Meta::w(seller_ata), sol::Meta::sr(pk(&seller))],
                        data: mint_to,
                    },
                ],
            )
            .await
            .unwrap();

            let sol_tok = TokenCfg { asset: "SOL".into(), network: "solana".into(), native: true, token: String::new(), decimals: 9 };
            let usdc = TokenCfg { asset: "USDC-SPL".into(), network: "solana".into(), native: false, token: sol::b58(&mint), decimals: 6 };
            let buyer_b58 = sol::b58(&pk(&buyer));
            let arbiter_b58 = sol::b58(&pk(&arbiter));
            let steps = std::sync::Mutex::new(Vec::<String>::new());
            let progress = |s: &str| steps.lock().unwrap().push(s.to_string());

            let mut opened = Vec::new();
            for (id, tok, locked, fee_micro) in [([1u8; 32], &sol_tok, native_locked, native_fee), ([2u8; 32], &usdc, 101_000_000, 1_000_000), ([3u8; 32], &usdc, 101_000_000, 1_000_000)] {
                let args = sol::OpenArgs {
                    trade_id: id,
                    buyer: pk(&buyer),
                    arbiter: pk(&arbiter),
                    fee_receiver: pk(&fee),
                    mint: if tok.native { None } else { Some(mint) },
                    total: chains::to_base_units(locked, tok.decimals) as u64,
                    fee: chains::to_base_units(fee_micro, tok.decimals) as u64,
                    fallback_delay: FALLBACK_DELAY_SECS,
                };
                let tx = c.open(&seller, &program, &args, &progress).await.unwrap();
                let reference = EscrowRef { contract: sol::b58(&program), funder: sol::b58(&pk(&seller)), tx };
                let trade = trade_for(&id, &tok.asset, locked, fee_micro, &buyer_b58, &arbiter_b58, Some(reference.clone()));
                let e = c.read_escrow(&program, &id, &pk(&seller)).await.unwrap().expect("the escrow is open");
                let problems = verify_ed25519_chain(&trade, &net, tok, &reference.funder, &solana_view(&e));
                assert!(problems.is_empty(), "{problems:?}");
                let reopened = c.open(&seller, &program, &args, &progress).await.unwrap();
                assert_eq!(reopened, reference.tx, "opening twice finds the first funding transaction");
                opened.push((trade, e));
            }
            assert_eq!(c.token_balance(&mint, &pk(&seller)).await.unwrap(), 1_000_000_000 - 2 * 101_000_000);

            let e1 = &opened[0].1;
            let buyer_before = c.balance(&pk(&buyer)).await.unwrap();
            let fee_before = c.balance(&pk(&fee)).await.unwrap();
            c.release(&seller, &program, e1).await.unwrap();
            assert_eq!(c.balance(&pk(&buyer)).await.unwrap() - buyer_before, (native_locked - native_fee) * 1_000);
            assert_eq!(c.balance(&pk(&fee)).await.unwrap() - fee_before, native_fee * 1_000);
            assert!(c.read_escrow(&program, &[1u8; 32], &pk(&seller)).await.unwrap().is_none());
            let again = c.release(&seller, &program, e1).await.unwrap_err();
            assert!(again.contains("does not exist"), "{again}");

            let (trade2, e2) = &opened[1];
            let sig = sol::buyer_signature(&buyer, &program, &e2.address, sol::ACTION_CANCEL);
            crate::market_chain::verify_native_cancel(trade2, &hex::encode(sig)).unwrap();
            let forged = sol::buyer_signature(&arbiter, &program, &e2.address, sol::ACTION_CANCEL);
            assert!(crate::market_chain::verify_native_cancel(trade2, &hex::encode(forged)).is_err());
            let refused = c.cancel_for(&seller, &program, e2, &forged).await.unwrap_err();
            assert!(refused.contains("signature is not valid"), "{refused}");
            c.cancel_for(&seller, &program, e2, &sig).await.unwrap();
            assert_eq!(c.token_balance(&mint, &pk(&seller)).await.unwrap(), 1_000_000_000 - 101_000_000);

            let e3 = &opened[2].1;
            let not_arbiter = c.resolve(&seller, &program, e3, true).await.unwrap_err();
            assert!(not_arbiter.contains("may not do that"), "{not_arbiter}");
            c.resolve(&arbiter, &program, e3, true).await.unwrap();
            assert_eq!(c.token_balance(&mint, &pk(&buyer)).await.unwrap(), 100_000_000);
            assert_eq!(c.token_balance(&mint, &pk(&fee)).await.unwrap(), 1_000_000);
            assert!(steps.lock().unwrap().iter().all(|s| s == "open"));
        });
    }

    #[test]
    #[ignore]
    fn the_cardano_adapter_drives_a_real_escrow() {
        let (Ok(koios), Ok(skey)) = (std::env::var("EGO_ADA_KOIOS"), std::env::var("EGO_ADA_SKEY")) else { return };
        let magic: u64 = std::env::var("EGO_ADA_MAGIC").ok().and_then(|m| m.parse().ok()).unwrap_or(1);
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let envelope: Value = serde_json::from_slice(&std::fs::read(&skey).unwrap()).unwrap();
            let cbor = hex::decode(envelope["cborHex"].as_str().unwrap()).unwrap();
            let seller = SigningKey::from_bytes(&cbor[2..34].try_into().unwrap());
            let (buyer, arbiter, fee_key) = (random_key(), random_key(), random_key());
            let mut net = default_networks().net("cardano").unwrap().clone();
            net.rpc = vec![koios];
            net.chain_id = magic;
            let c = CardanoClient::new(&net);
            let addr = |k: &SigningKey| cardano_key_address(0, k);
            let script = ada::script_address(0, &ada::script_hash());
            let steps = std::sync::Mutex::new(Vec::<String>::new());
            let progress = |s: &str| steps.lock().unwrap().push(s.to_string());
            let ada_of = |l: u64| l as f64 / 1e6;
            println!("seller {} holds {} ADA", ada::format_address(&addr(&seller)), ada_of(c.balance(&ada::format_address(&addr(&seller))).await.unwrap()));

            let funded = c.pay(&seller, &addr(&arbiter), 25_000_000).await.unwrap();
            println!("arbiter funded in {funded}");

            let find = |id: [u8; 32], tx: String| {
                let c = &c;
                let reference = EscrowRef { contract: ada::format_address(&script), funder: ada::format_address(&addr(&seller)), tx };
                async move {
                    for _ in 0..24 {
                        if let Some(f) = c.find_escrow(&reference, &id).await.unwrap() {
                            return (reference, f);
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                    panic!("the escrow never appeared");
                }
            };
            let datum = |id: [u8; 32], total: u64, fee: u64| ada::EscrowDatum {
                trade_id: id,
                seller: addr(&seller),
                buyer: addr(&buyer),
                arbiter: ada::blake2b_224(&arbiter.verifying_key().to_bytes()),
                fee_receiver: addr(&fee_key),
                total,
                fee,
                fallback_at: chrono::Utc::now().timestamp_millis() + ((FALLBACK_DELAY_SECS + 7_200) * 1_000) as i64,
                frozen: false,
            };
            let mut ids = [[0u8; 32]; 3];
            for (i, id) in ids.iter_mut().enumerate() {
                use rand::RngCore;
                rand::thread_rng().fill_bytes(id);
                id[0] = i as u8;
            }

            let d1 = datum(ids[0], 101_000_000, 1_000_000);
            let tx1 = c.open(&seller, &script, &d1, &progress).await.unwrap();
            let (_, e1) = find(ids[0], tx1.clone()).await;
            assert!(!e1.spent);
            assert_eq!(e1.datum, d1);
            assert_eq!(e1.utxo.lovelace, d1.total);
            let release = c.release(&seller, &e1).await.unwrap();
            println!("released {tx1} in {release}");
            assert_eq!(c.balance(&ada::format_address(&addr(&buyer))).await.unwrap(), 100_000_000);
            assert_eq!(c.balance(&ada::format_address(&addr(&fee_key))).await.unwrap(), 1_000_000);
            let (_, gone) = find(ids[0], tx1).await;
            assert!(gone.spent, "a released escrow is spent");

            let d2 = datum(ids[1], 20_000_000, 0);
            let tx2 = c.open(&seller, &script, &d2, &progress).await.unwrap();
            let (r2, e2) = find(ids[1], tx2.clone()).await;
            let (vkey, sig) = ada::sign_auth(&buyer, &ada::script_hash(), &ids[1], ada::ACTION_CANCEL);
            let trade2 = trade_for(&ids[1], "ADA", 20_000_000, 0, &ada::format_address(&addr(&buyer)), &ada::format_address(&addr(&arbiter)), Some(r2));
            crate::market_chain::verify_native_cancel(&trade2, &format!("{}{}", hex::encode(vkey), hex::encode(sig))).unwrap();
            let (svkey, ssig) = ada::sign_auth(&fee_key, &ada::script_hash(), &ids[1], ada::ACTION_CANCEL);
            let forged = c.cancel_for(&seller, &e2, svkey, ssig).await.unwrap_err();
            println!("forged cancel refused: {forged}");
            let cancel = c.cancel_for(&seller, &e2, vkey, sig).await.unwrap();
            println!("cancelled {tx2} in {cancel}");
            assert!(find(ids[1], tx2).await.1.spent);

            let d3 = datum(ids[2], 30_000_000, 0);
            let tx3 = c.open(&seller, &script, &d3, &progress).await.unwrap();
            let (_, e3) = find(ids[2], tx3.clone()).await;
            let not_arbiter = c.resolve(&buyer, &e3, true).await.unwrap_err();
            println!("stranger ruling refused: {not_arbiter}");
            let ruling = c.resolve(&arbiter, &e3, true).await.unwrap();
            println!("resolved {tx3} in {ruling}");
            assert_eq!(c.balance(&ada::format_address(&addr(&buyer))).await.unwrap(), 130_000_000);
            assert!(steps.lock().unwrap().iter().all(|s| s == "open"));
        });
    }

    #[test]
    #[ignore]
    fn dump_cardano_transactions_for_an_outside_check() {
        let Ok(dir) = std::env::var("EGO_ADA_DUMP") else { return };
        let dir = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cost_model_v3: Vec<i64> = (0..297).map(|i| i * 7 + 3).collect();
        let params = ada::Params {
            min_fee_a: 44,
            min_fee_b: 155_381,
            coins_per_utxo_byte: 4_310,
            price_mem: (577, 10_000),
            price_step: (721, 10_000_000),
            collateral_percent: 150,
            max_tx_size: 16_384,
            cost_model_v3: cost_model_v3.clone(),
        };
        let key = |b: u8| SigningKey::from_bytes(&[b; 32]);
        let (seller, buyer, stranger) = (key(1), key(2), key(5));
        let addr = |k: &SigningKey| cardano_key_address(0, k);
        let datum = ada::EscrowDatum {
            trade_id: [0x11; 32],
            seller: addr(&seller),
            buyer: addr(&buyer),
            arbiter: [3; 28],
            fee_receiver: ada::key_address(0, &[4; 28]),
            total: 151_500_000,
            fee: 1_500_000,
            fallback_at: 1_900_000_000_000,
            frozen: false,
        };
        let coins = |tag: u8| vec![
            ada::Utxo { tx_hash: [tag; 32], index: 0, lovelace: 9_000_000, pure_ada: true },
            ada::Utxo { tx_hash: [tag.wrapping_add(1); 32], index: 3, lovelace: 200_000_000, pure_ada: true },
        ];
        let script = ada::script_address(0, &ada::script_hash());
        let open = cardano_open_plan(&addr(&seller), &script, &datum, coins(0x30), 90_000_000).unwrap();
        let found = FoundEscrow {
            utxo: ada::Utxo { tx_hash: [0xaa; 32], index: 0, lovelace: datum.total, pure_ada: true },
            datum: datum.clone(),
            spent: false,
            block_time: 0,
        };
        let seller_pkh = ada::blake2b_224(&seller.verifying_key().to_bytes());
        let release = cardano_spend_plan(&addr(&seller), &found, ada::Action::Release, released_outputs(&datum), vec![seller_pkh], coins(0x40), 90_000_000);
        let (vkey, sig) = ada::sign_auth(&buyer, &ada::script_hash(), &datum.trade_id, ada::ACTION_CANCEL);
        let cancel = cardano_spend_plan(&addr(&stranger), &found, ada::Action::CancelFor { vkey, signature: sig }, refunded_outputs(&datum), vec![], coins(0x50), 90_000_000);
        let mut index = Vec::new();
        for (name, plan, signer) in [("open", open, &seller), ("release", release, &seller), ("cancel_for", cancel, &stranger)] {
            let unsigned = ada::build(&plan, &params).unwrap();
            let tx = unsigned.sign(&[signer]);
            let inputs: u64 = unsigned.inputs.iter().map(|u| u.lovelace).sum();
            std::fs::write(dir.join(format!("{name}.tx")), hex::encode(&tx)).unwrap();
            index.push(json!({
                "name": name,
                "fee": unsigned.fee,
                "inputs": inputs,
                "tx_hash": hex::encode(unsigned.tx_hash()),
                "signer": hex::encode(signer.verifying_key().to_bytes()),
                "ex_units": if plan.spend.is_some() { json!([ada::SPEND_MEM, ada::SPEND_STEPS]) } else { Value::Null },
            }));
        }
        let meta = json!({
            "cost_model_v3": cost_model_v3,
            "script_hash": hex::encode(ada::script_hash()),
            "script_cbor": ada::SCRIPT_HEX.trim(),
            "datum_cbor": hex::encode(datum.to_data().unwrap().to_cbor()),
            "txs": index,
        });
        std::fs::write(dir.join("meta.json"), serde_json::to_vec_pretty(&meta).unwrap()).unwrap();
    }

    #[test]
    #[ignore]
    fn the_cardano_transactions_pass_the_validator() {
        let Ok(aiken) = std::env::var("EGO_AIKEN") else { return };
        let dir = std::env::temp_dir().join(format!("ego-ada-sim-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let params = ada::Params {
            min_fee_a: 44,
            min_fee_b: 155_381,
            coins_per_utxo_byte: 4_310,
            price_mem: (577, 10_000),
            price_step: (721, 10_000_000),
            collateral_percent: 150,
            max_tx_size: 16_384,
            cost_model_v3: vec![0; 297],
        };
        let key = |b: u8| SigningKey::from_bytes(&[b; 32]);
        let (seller, buyer, arbiter, stranger) = (key(1), key(2), key(3), key(5));
        let addr = |k: &SigningKey| cardano_key_address(0, k);
        let datum = ada::EscrowDatum {
            trade_id: [0x11; 32],
            seller: addr(&seller),
            buyer: addr(&buyer),
            arbiter: ada::blake2b_224(&arbiter.verifying_key().to_bytes()),
            fee_receiver: ada::key_address(0, &[4; 28]),
            total: 151_500_000,
            fee: 1_500_000,
            fallback_at: 1_900_000_000_000,
            frozen: false,
        };
        let script = ada::script_address(0, &ada::script_hash());
        let found = FoundEscrow {
            utxo: ada::Utxo { tx_hash: [0xaa; 32], index: 0, lovelace: datum.total, pure_ada: true },
            datum: datum.clone(),
            spent: false,
            block_time: 0,
        };
        let funding = |tag: u8| vec![ada::Utxo { tx_hash: [tag; 32], index: 1, lovelace: 40_000_000, pure_ada: true }];
        let simulate = |name: &str, actor: &SigningKey, plan: ada::Plan| -> (bool, String) {
            let unsigned = ada::build(&plan, &params).unwrap();
            let tx = unsigned.sign(&[actor]);
            let mut inputs = plan.funding.clone();
            inputs.push(found.utxo.clone());
            let outputs: Vec<ada::Output> = inputs
                .iter()
                .map(|u| {
                    if u.tx_hash == [0xaa; 32] {
                        ada::Output { address: script.clone(), lovelace: u.lovelace, datum: Some(datum.to_data().unwrap()) }
                    } else {
                        ada::Output { address: plan.change.clone(), lovelace: u.lovelace, datum: None }
                    }
                })
                .collect();
            let files = [
                ("tx", hex::encode(&tx)),
                ("in", hex::encode(ada::inputs_cbor(&inputs))),
                ("out", hex::encode(ada::outputs_cbor(&outputs))),
            ];
            for (f, body) in &files {
                std::fs::write(dir.join(format!("{name}.{f}")), body).unwrap();
            }
            let out = std::process::Command::new(&aiken)
                .args(["tx", "simulate"])
                .arg(dir.join(format!("{name}.tx")))
                .arg(dir.join(format!("{name}.in")))
                .arg(dir.join(format!("{name}.out")))
                .args(["--zero-time", "1655769600000", "--zero-slot", "86400"])
                .output()
                .unwrap();
            let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
            println!("{name}: {}", text.trim());
            (out.status.success() && !text.to_lowercase().contains("error"), text)
        };
        let seller_pkh = ada::blake2b_224(&seller.verifying_key().to_bytes());
        let short = vec![
            ada::Output { address: datum.buyer.clone(), lovelace: datum.total - datum.fee - 1, datum: None },
            released_outputs(&datum)[1].clone(),
        ];
        let cases: Vec<(&str, &SigningKey, ada::Action, Vec<ada::Output>, Vec<ada::Pkh>, bool)> = vec![
            ("release", &seller, ada::Action::Release, released_outputs(&datum), vec![seller_pkh], true),
            ("resolve_buyer", &arbiter, ada::Action::Resolve { to_buyer: true }, released_outputs(&datum), vec![datum.arbiter], true),
            ("resolve_seller", &arbiter, ada::Action::Resolve { to_buyer: false }, refunded_outputs(&datum), vec![datum.arbiter], true),
            ("release_unsigned", &seller, ada::Action::Release, released_outputs(&datum), vec![], false),
            ("release_short", &seller, ada::Action::Release, short, vec![seller_pkh], false),
        ];
        for (name, actor, action, outputs, signers, should_pass) in cases {
            let plan = cardano_spend_plan(&addr(actor), &found, action, outputs, signers, funding(0x0b), 90_000_000);
            let (passed, text) = simulate(name, actor, plan);
            assert_eq!(passed, should_pass, "{name}: {text}");
        }
        let (vkey, sig) = ada::sign_auth(&buyer, &ada::script_hash(), &datum.trade_id, ada::ACTION_CANCEL);
        let relayed = cardano_spend_plan(
            &addr(&stranger),
            &found,
            ada::Action::CancelFor { vkey, signature: sig },
            refunded_outputs(&datum),
            vec![],
            funding(0x0c),
            90_000_000,
        );
        let (passed, text) = simulate("cancel_for", &stranger, relayed);
        assert!(passed, "cancel_for: {text}");
        let (fvkey, fsig) = ada::sign_auth(&stranger, &ada::script_hash(), &datum.trade_id, ada::ACTION_CANCEL);
        let forged = cardano_spend_plan(
            &addr(&stranger),
            &found,
            ada::Action::CancelFor { vkey: fvkey, signature: fsig },
            refunded_outputs(&datum),
            vec![],
            funding(0x0c),
            90_000_000,
        );
        let (passed, text) = simulate("cancel_forged", &stranger, forged);
        assert!(!passed, "a stranger's signature must fail: {text}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
