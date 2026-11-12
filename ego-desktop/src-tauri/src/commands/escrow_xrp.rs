use crate::commands::escrow_chains::{self as chains, ChainNet, NativeEscrow, TokenCfg, FALLBACK_DELAY_SECS};
use crate::commands::multichain::http_client;
use crate::escrow::xrp::{self as x, AccountId, Tx, Value};
use crate::market_chain::{xrp_payout, xrp_sig_payload, EscrowRef, Role, Trade, TradeState};
use k256::ecdsa::SigningKey;
use serde_json::{json, Value as J};

pub const ESCROW_RESERVE_DROPS: u64 = 1_500_000;
pub const LOCK_MARGIN_SECS: i64 = 86_400;
const LSF_DISABLE_MASTER: u64 = 0x0010_0000;
const SINGLE_FEE_DROPS: u64 = 15;
const MULTI_FEE_DROPS: u64 = 45;

pub fn signing_key(path: &str) -> Result<SigningKey, String> {
    #[cfg(test)]
    if let Some(h) = path.strip_prefix("hex:") {
        return SigningKey::from_slice(&hex::decode(h).map_err(|e| e.to_string())?).map_err(|e| e.to_string());
    }
    SigningKey::from_slice(&chains::wallet_key(path)?).map_err(|e| e.to_string())
}

pub fn wallet_address(path: &str) -> Result<String, String> {
    Ok(x::address_of(&signing_key(path)?))
}

pub fn payout_entry(path: &str, to: Option<&str>) -> Result<String, String> {
    let me = wallet_address(path)?;
    let dest = match to.map(str::trim).filter(|a| !a.is_empty()) {
        Some(a) if x::valid_address(a) => a.to_string(),
        Some(a) => return Err(format!("{a:.60} is not an XRP address")),
        None => me.clone(),
    };
    Ok(format!("{me}@{dest}"))
}

pub fn same(a: &str, b: &str) -> bool {
    let signer = |s: &str| xrp_payout(s).map(|(k, _)| k);
    match (signer(a), signer(b)) {
        (Some(x), Some(y)) => x == y,
        _ => a.trim() == b.trim(),
    }
}

pub fn cancel_after(trade: &Trade) -> i64 {
    trade.opened_at + FALLBACK_DELAY_SECS as i64 + LOCK_MARGIN_SECS
}

struct Parties {
    seller: String,
    buyer: String,
    buyer_to: String,
    arbiter: String,
}

fn parties(trade: &Trade) -> Result<Parties, String> {
    let r = trade.escrow.as_ref().ok_or("the trade names no escrow yet")?;
    let (buyer, buyer_to) = xrp_payout(trade.buyer_payout.as_deref().unwrap_or("")).ok_or("the trade names no buyer XRP account")?;
    let (arbiter, _) = xrp_payout(trade.arbiter_payout.as_deref().unwrap_or("")).ok_or("the trade names no arbiter XRP account")?;
    Ok(Parties { seller: r.funder.clone(), buyer, buyer_to, arbiter })
}

fn id(a: &str) -> Result<AccountId, String> {
    x::decode_address(a)
}

fn fee_address(net: &ChainNet) -> Result<String, String> {
    let raw = crate::commands::escrow_outside::fee_receiver(net)?;
    Ok(xrp_payout(&raw).map(|(_, d)| d).unwrap_or(raw))
}

pub struct Rpc<'a> {
    net: &'a ChainNet,
}

pub struct Account {
    pub sequence: u32,
    pub balance: u64,
    pub flags: u64,
    pub signers: Vec<String>,
    pub quorum: u32,
}

impl<'a> Rpc<'a> {
    pub fn new(net: &'a ChainNet) -> Self {
        Self { net }
    }

    async fn call(&self, method: &str, params: J) -> Result<J, String> {
        let mut last = format!("no XRP server is configured for {}", self.net.label);
        for url in &self.net.rpc {
            let body = json!({ "method": method, "params": [params] });
            match http_client().post(url).json(&body).send().await {
                Ok(r) => match r.json::<J>().await {
                    Ok(v) => return Ok(v["result"].clone()),
                    Err(e) => last = e.to_string(),
                },
                Err(e) => last = e.to_string(),
            }
        }
        Err(last)
    }

    pub async fn account(&self, address: &str) -> Result<Option<Account>, String> {
        let r = self.call("account_info", json!({ "account": address, "ledger_index": "current", "signer_lists": true })).await?;
        if r["error"].as_str() == Some("actNotFound") {
            return Ok(None);
        }
        if let Some(e) = r["error_message"].as_str().or(r["error"].as_str()) {
            return Err(format!("the XRP server said: {e}"));
        }
        let d = &r["account_data"];
        let lists = if r["signer_lists"].is_array() { &r["signer_lists"] } else { &d["signer_lists"] };
        let list = &lists[0];
        let signers = list["SignerEntries"]
            .as_array()
            .map(|v| v.iter().filter_map(|e| e["SignerEntry"]["Account"].as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        Ok(Some(Account {
            sequence: d["Sequence"].as_u64().unwrap_or(0) as u32,
            balance: d["Balance"].as_str().and_then(|b| b.parse().ok()).unwrap_or(0),
            flags: d["Flags"].as_u64().unwrap_or(0),
            signers,
            quorum: list["SignerQuorum"].as_u64().unwrap_or(0) as u32,
        }))
    }

    pub async fn balance(&self, address: &str) -> Result<u64, String> {
        Ok(self.account(address).await?.map_or(0, |a| a.balance))
    }

    async fn ledger_now(&self) -> Result<u32, String> {
        let r = self.call("ledger_current", json!({})).await?;
        r["ledger_current_index"].as_u64().map(|n| n as u32).ok_or_else(|| "the XRP server gave no ledger index".into())
    }

    pub async fn submit(&self, blob: &[u8]) -> Result<String, String> {
        let r = self.call("submit", json!({ "tx_blob": hex::encode_upper(blob) })).await?;
        let result = r["engine_result"].as_str().unwrap_or("");
        if !(result == "tesSUCCESS" || result.starts_with("ter")) {
            let why = r["engine_result_message"].as_str().or(r["error_message"].as_str()).unwrap_or(result);
            return Err(format!("the XRP Ledger refused the transaction: {result} {why}"));
        }
        Ok(x::tx_hash(blob))
    }

    pub async fn wait(&self, hash: &str) -> Result<(), String> {
        for _ in 0..30 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let r = self.call("tx", json!({ "transaction": hash })).await?;
            if r["validated"].as_bool() == Some(true) {
                let code = r["meta"]["TransactionResult"].as_str().unwrap_or("");
                return if code == "tesSUCCESS" { Ok(()) } else { Err(format!("the XRP Ledger kept the transaction but it failed: {code}")) };
            }
        }
        Err("the XRP Ledger did not confirm the transaction within a minute; check again shortly".into())
    }

    pub async fn sequence_of(&self, hash: &str) -> Result<u32, String> {
        let r = self.call("tx", json!({ "transaction": hash })).await?;
        r["Sequence"].as_u64().or(r["tx_json"]["Sequence"].as_u64()).map(|n| n as u32).ok_or_else(|| "the escrow transaction was not found on the XRP Ledger".into())
    }

    pub async fn escrow_object(&self, owner: &str, destination: &str) -> Result<Option<(u64, u32, String)>, String> {
        let r = self.call("account_objects", json!({ "account": owner, "type": "escrow", "ledger_index": "validated" })).await?;
        Ok(r["account_objects"].as_array().and_then(|list| {
            list.iter().find(|o| o["Destination"].as_str() == Some(destination)).map(|o| {
                (
                    o["Amount"].as_str().and_then(|a| a.parse().ok()).unwrap_or(0),
                    o["CancelAfter"].as_u64().unwrap_or(0) as u32,
                    o["PreviousTxnID"].as_str().unwrap_or("").to_string(),
                )
            })
        }))
    }

    pub async fn escrow_amount(&self, owner: &str, destination: &str) -> Result<Option<(u64, u32)>, String> {
        Ok(self.escrow_object(owner, destination).await?.map(|(a, c, _)| (a, c)))
    }
}

fn payment(from: &AccountId, sequence: u32, fee: u64, to: &AccountId, drops: u64) -> Tx {
    let mut tx = x::base_tx(x::TT_PAYMENT, from, sequence, fee, 0);
    tx.set(x::F_AMOUNT, Value::Drops(drops));
    tx.set(x::F_DESTINATION, Value::Account(*to));
    tx
}

fn encode_payload(sequence: u32, fee: u64, sigs: &[Vec<u8>]) -> String {
    let mut v = sequence.to_be_bytes().to_vec();
    v.extend_from_slice(&fee.to_be_bytes());
    for s in sigs {
        v.push(s.len() as u8);
        v.extend_from_slice(s);
    }
    hex::encode(v)
}

async fn single(rpc: &Rpc<'_>, key: &SigningKey, mut tx: Tx) -> Result<String, String> {
    let blob = x::sign_single(&mut tx, key)?;
    let hash = rpc.submit(&blob).await?;
    rpc.wait(&hash).await?;
    Ok(hash)
}

fn base_for(rpc_ledger: u32, kind: u16, from: &AccountId, sequence: u32) -> Tx {
    x::base_tx(kind, from, sequence, SINGLE_FEE_DROPS, rpc_ledger + 20)
}

pub async fn open(net: &ChainNet, tok: &TokenCfg, trade: &Trade, progress: crate::commands::escrow_outside::Progress<'_>) -> Result<EscrowRef, String> {
    let rpc = Rpc::new(net);
    let seller_key = signing_key(&net.key_path)?;
    let seller = x::address_of(&seller_key);
    let trade_id = chains::trade_id_bytes(&trade.id)?;
    let escrow_key = x::escrow_key(&seller_key, &trade_id)?;
    let escrow = x::address_of(&escrow_key);
    let (buyer, _) = xrp_payout(trade.buyer_payout.as_deref().unwrap_or("")).ok_or("the trade names no buyer XRP account")?;
    let (arbiter, _) = xrp_payout(trade.arbiter_payout.as_deref().unwrap_or("")).ok_or("the trade names no arbiter XRP account")?;
    let total = u64::try_from(chains::to_base_units(trade.locked_micro, tok.decimals)).map_err(|_| "the amount is too large")?;
    let me = rpc.account(&seller).await?.ok_or_else(|| format!("send XRP to {seller} first: this wallet has no XRP account yet"))?;
    let need = total + ESCROW_RESERVE_DROPS + 400_000;
    if me.balance < need + 1_000_000 {
        return Err(format!("this wallet holds {} drops but the escrow, its account reserve and fees need about {}", me.balance, need + 1_000_000));
    }
    progress("approve");
    let mut seq = me.sequence;
    if rpc.account(&escrow).await?.is_none() {
        let ledger = rpc.ledger_now().await?;
        let mut tx = payment(&id(&seller)?, seq, SINGLE_FEE_DROPS, &id(&escrow)?, ESCROW_RESERVE_DROPS);
        tx.set(x::F_LAST_LEDGER_SEQUENCE, Value::U32(ledger + 20));
        single(&rpc, &seller_key, tx).await?;
        seq += 1;
    }
    let e = rpc.account(&escrow).await?.ok_or("the escrow account did not appear on the XRP Ledger")?;
    let mut eseq = e.sequence;
    let want: Vec<String> = vec![seller.clone(), buyer.clone(), arbiter.clone()];
    if e.quorum != 2 || !want.iter().all(|w| e.signers.contains(w)) {
        let ledger = rpc.ledger_now().await?;
        let mut tx = base_for(ledger, x::TT_SIGNER_LIST_SET, &id(&escrow)?, eseq);
        tx.set(x::F_SIGNER_QUORUM, Value::U32(2));
        let entries = want.iter().map(|a| id(a).map(|i| (i, 1u16))).collect::<Result<Vec<_>, _>>()?;
        tx.set(x::F_SIGNER_ENTRIES, Value::SignerEntries(entries));
        single(&rpc, &escrow_key, tx).await?;
        eseq += 1;
    }
    if e.flags & LSF_DISABLE_MASTER == 0 {
        let ledger = rpc.ledger_now().await?;
        let mut tx = base_for(ledger, x::TT_ACCOUNT_SET, &id(&escrow)?, eseq);
        tx.set(x::F_SET_FLAG, Value::U32(x::ASF_DISABLE_MASTER));
        single(&rpc, &escrow_key, tx).await?;
    }
    progress("open");
    if let Some((_, _, made)) = rpc.escrow_object(&seller, &escrow).await? {
        if !made.is_empty() {
            return Ok(EscrowRef { contract: escrow, funder: seller, tx: made });
        }
    }
    let ledger = rpc.ledger_now().await?;
    let mut tx = base_for(ledger, x::TT_ESCROW_CREATE, &id(&seller)?, seq);
    tx.set(x::F_AMOUNT, Value::Drops(total));
    tx.set(x::F_DESTINATION, Value::Account(id(&escrow)?));
    tx.set(x::F_FINISH_AFTER, Value::U32(x::ripple_time(chrono::Utc::now().timestamp() + 60)));
    tx.set(x::F_CANCEL_AFTER, Value::U32(x::ripple_time(cancel_after(trade))));
    let hash = single(&rpc, &seller_key, tx).await?;
    Ok(EscrowRef { contract: escrow, funder: seller, tx: hash })
}

struct Holding {
    in_escrow: Option<(u64, u32)>,
    in_account: u64,
    account: Option<Account>,
}

async fn holding(rpc: &Rpc<'_>, trade: &Trade) -> Result<Holding, String> {
    let r = trade.escrow.as_ref().ok_or("the trade names no escrow yet")?;
    let account = rpc.account(&r.contract).await?;
    let in_escrow = rpc.escrow_amount(&r.funder, &r.contract).await?;
    let in_account = account.as_ref().map_or(0, |a| a.balance.saturating_sub(ESCROW_RESERVE_DROPS));
    Ok(Holding { in_escrow, in_account, account })
}

pub async fn read(net: &ChainNet, tok: &TokenCfg, trade: &Trade) -> Result<NativeEscrow, String> {
    let rpc = Rpc::new(net);
    let p = parties(trade)?;
    let h = holding(&rpc, trade).await?;
    let total = chains::to_base_units(trade.locked_micro, tok.decimals) as u64;
    let frozen = h.in_escrow.is_none() && h.in_account >= total.saturating_sub(MULTI_FEE_DROPS * 4);
    let held = h.in_escrow.map(|(a, _)| a).unwrap_or(if frozen { total } else { 0 });
    let signed = h.account.as_ref().is_some_and(|a| {
        a.flags & LSF_DISABLE_MASTER != 0 && a.quorum == 2 && [&p.seller, &p.buyer, &p.arbiter].iter().all(|w| a.signers.contains(w))
    });
    Ok(NativeEscrow {
        seller: p.seller.clone(),
        opened_at: trade.opened_at.max(0) as u64,
        state: if held > 0 && signed { chains::STATE_FUNDED } else if held > 0 { 0 } else { 2 },
        frozen,
        buyer: p.buyer,
        fallback_at: cancel_after(trade).max(0) as u64,
        arbiter: p.arbiter,
        token: String::new(),
        total: held as u128,
        fee: chains::to_base_units(trade.maker_fee_micro, tok.decimals),
        fee_receiver: fee_address(net).ok(),
    })
}

pub fn verify(net: &ChainNet, tok: &TokenCfg, trade: &Trade, funder: &str, e: &NativeEscrow) -> Vec<String> {
    let mut problems = Vec::new();
    if e.state != chains::STATE_FUNDED {
        problems.push(format!("no locked escrow with the right signers exists on {} for this trade", net.label));
        return problems;
    }
    if e.seller != funder {
        problems.push("the escrow was funded by a different wallet".into());
    }
    if e.total != chains::to_base_units(trade.locked_micro, tok.decimals) {
        problems.push("the escrow holds a different amount than the trade".into());
    }
    if e.fallback_at.saturating_sub(e.opened_at) < FALLBACK_DELAY_SECS {
        problems.push("the seller's safety delay is too short".into());
    }
    problems
}

async fn finish_into_account(rpc: &Rpc<'_>, trade: &Trade, key: &SigningKey) -> Result<(), String> {
    let r = trade.escrow.as_ref().ok_or("the trade names no escrow yet")?;
    if rpc.escrow_amount(&r.funder, &r.contract).await?.is_none() {
        return Ok(());
    }
    let me = x::address_of(key);
    let acct = rpc.account(&me).await?.ok_or_else(|| format!("send at least 1.1 XRP to {me} to pay the network fee"))?;
    let ledger = rpc.ledger_now().await?;
    let mut tx = base_for(ledger, x::TT_ESCROW_FINISH, &id(&me)?, acct.sequence);
    tx.set(x::F_OWNER, Value::Account(id(&r.funder)?));
    tx.set(x::F_OFFER_SEQUENCE, Value::U32(rpc.sequence_of(&r.tx).await?));
    single(rpc, key, tx).await.map(|_| ())
}

fn release_txs(trade: &Trade, tok: &TokenCfg, p: &Parties, net: &ChainNet, escrow: &AccountId, sequence: u32, fee: u64) -> Result<Vec<Tx>, String> {
    let total = chains::to_base_units(trade.locked_micro, tok.decimals) as u64;
    let cut = chains::to_base_units(trade.maker_fee_micro, tok.decimals) as u64;
    let mut out = vec![payment(escrow, sequence, fee, &id(&p.buyer_to)?, total - cut)];
    if cut > 0 {
        out.push(payment(escrow, sequence + 1, fee, &id(&fee_address(net)?)?, cut));
    }
    Ok(out)
}

fn refund_tx(trade: &Trade, tok: &TokenCfg, p: &Parties, escrow: &AccountId, sequence: u32, fee: u64) -> Result<Tx, String> {
    let total = chains::to_base_units(trade.locked_micro, tok.decimals) as u64;
    Ok(payment(escrow, sequence, fee, &id(&p.seller)?, total))
}

fn escrow_id(trade: &Trade) -> Result<AccountId, String> {
    id(&trade.escrow.as_ref().ok_or("the trade names no escrow yet")?.contract)
}

pub async fn release_signature(net: &ChainNet, tok: &TokenCfg, trade: &Trade) -> Result<String, String> {
    let rpc = Rpc::new(net);
    let p = parties(trade)?;
    let key = signing_key(&net.key_path)?;
    if x::address_of(&key) != p.buyer {
        return Err("this wallet is not the buyer named in the escrow".into());
    }
    let e = rpc.account(&trade.escrow.as_ref().map(|r| r.contract.clone()).unwrap_or_default()).await?.ok_or("the escrow account was not found")?;
    let txs = release_txs(trade, tok, &p, net, &escrow_id(trade)?, e.sequence, MULTI_FEE_DROPS)?;
    let sigs = txs.iter().map(|t| x::sign_multi(t, &key).map(|s| s.1)).collect::<Result<Vec<_>, _>>()?;
    let mut payload = hex::decode(encode_payload(e.sequence, MULTI_FEE_DROPS, &sigs)).unwrap_or_default();
    payload.extend_from_slice(&x::pubkey_of(&key));
    Ok(hex::encode(payload))
}

async fn submit_multi(rpc: &Rpc<'_>, txs: &[Tx], theirs: &[(AccountId, Vec<u8>, Vec<u8>)], key: &SigningKey) -> Result<String, String> {
    let mut last = String::new();
    for (tx, their) in txs.iter().zip(theirs) {
        if !x::verify_multi(tx, their) {
            return Err("the other party's XRP signature does not match this payout".into());
        }
        let mine = x::sign_multi(tx, key)?;
        let blob = x::combine(tx, vec![their.clone(), mine]);
        last = rpc.submit(&blob).await?;
        rpc.wait(&last).await?;
    }
    Ok(last)
}

fn with_keys(sigs: Vec<Vec<u8>>, who: &str, pubkey_hint: Option<[u8; 33]>) -> Result<Vec<(AccountId, Vec<u8>, Vec<u8>)>, String> {
    let pk = pubkey_hint.ok_or("the signer's public key is not known")?;
    let acct = id(who)?;
    Ok(sigs.into_iter().map(|s| (acct, s, pk.to_vec())).collect())
}

async fn pubkey_from_sig_tx(rpc: &Rpc<'_>, who: &str) -> Option<[u8; 33]> {
    let r = rpc.call("account_tx", json!({ "account": who, "limit": 20 })).await.ok()?;
    r["transactions"].as_array()?.iter().find_map(|t| {
        let tx = if t["tx"].is_object() { &t["tx"] } else { &t["tx_json"] };
        if tx["Account"].as_str() != Some(who) {
            return None;
        }
        let pk = hex::decode(tx["SigningPubKey"].as_str()?).ok()?;
        let pk: [u8; 33] = pk.try_into().ok()?;
        (x::encode_address(&x::account_id(&pk)) == who).then_some(pk)
    })
}

async fn known_pubkey(rpc: &Rpc<'_>, who: &str, payload_key: Option<[u8; 33]>) -> Option<[u8; 33]> {
    match payload_key {
        Some(k) if x::encode_address(&x::account_id(&k)) == who => Some(k),
        _ => pubkey_from_sig_tx(rpc, who).await,
    }
}

async fn release_with(net: &ChainNet, tok: &TokenCfg, trade: &Trade, key_path: &str) -> Result<String, String> {
    let rpc = Rpc::new(net);
    let p = parties(trade)?;
    let key = signing_key(key_path)?;
    let (sequence, fee, sigs, buyer_pk) = xrp_sig_payload(trade.release_sig.as_deref().ok_or("the buyer has not signed the release yet")?)?;
    finish_into_account(&rpc, trade, &key).await?;
    let txs = release_txs(trade, tok, &p, net, &escrow_id(trade)?, sequence, fee)?;
    if sigs.len() != txs.len() {
        return Err("the buyer's release signatures do not match this payout".into());
    }
    let theirs = with_keys(sigs, &p.buyer, known_pubkey(&rpc, &p.buyer, buyer_pk).await)?;
    submit_multi(&rpc, &txs, &theirs, &key).await
}

pub async fn release(net: &ChainNet, tok: &TokenCfg, trade: &Trade) -> Result<String, String> {
    release_with(net, tok, trade, &net.key_path).await
}

pub async fn resolve(net: &ChainNet, tok: &TokenCfg, trade: &Trade, to_buyer: bool, arbiter_path: &str) -> Result<String, String> {
    if to_buyer {
        return release_with(net, tok, trade, arbiter_path).await;
    }
    let rpc = Rpc::new(net);
    let p = parties(trade)?;
    let key = signing_key(arbiter_path)?;
    if x::address_of(&key) != p.arbiter {
        return Err("this wallet is not the arbiter named in the escrow".into());
    }
    finish_into_account(&rpc, trade, &key).await?;
    let e = rpc.account(&trade.escrow.as_ref().map(|r| r.contract.clone()).unwrap_or_default()).await?.ok_or("the escrow account was not found")?;
    let tx = refund_tx(trade, tok, &p, &escrow_id(trade)?, e.sequence, MULTI_FEE_DROPS)?;
    let (_, sig, pk) = x::sign_multi(&tx, &key)?;
    let mut payload = hex::decode(encode_payload(e.sequence, MULTI_FEE_DROPS, &[sig])).unwrap_or_default();
    payload.extend_from_slice(&pk);
    Ok(hex::encode(payload))
}

pub async fn buyer_cancel(net: &ChainNet, tok: &TokenCfg, trade: &Trade) -> Result<String, String> {
    let rpc = Rpc::new(net);
    let p = parties(trade)?;
    let key = signing_key(&net.key_path)?;
    if x::address_of(&key) != p.buyer {
        return Err("this wallet is not the buyer named in the escrow".into());
    }
    let e = rpc.account(&trade.escrow.as_ref().map(|r| r.contract.clone()).unwrap_or_default()).await?.ok_or("the escrow account was not found")?;
    let tx = refund_tx(trade, tok, &p, &escrow_id(trade)?, e.sequence, MULTI_FEE_DROPS)?;
    let (_, sig, pk) = x::sign_multi(&tx, &key)?;
    let mut payload = hex::decode(encode_payload(e.sequence, MULTI_FEE_DROPS, &[sig])).unwrap_or_default();
    payload.extend_from_slice(&pk);
    Ok(hex::encode(payload))
}

async fn refund_with(net: &ChainNet, tok: &TokenCfg, trade: &Trade, other: &str, sig_hex: &str) -> Result<String, String> {
    let rpc = Rpc::new(net);
    let p = parties(trade)?;
    let key = signing_key(&net.key_path)?;
    if x::address_of(&key) != p.seller {
        return Err("this wallet is not the seller named in the escrow".into());
    }
    let (sequence, fee, sigs, pk) = xrp_sig_payload(sig_hex)?;
    finish_into_account(&rpc, trade, &key).await?;
    let tx = refund_tx(trade, tok, &p, &escrow_id(trade)?, sequence, fee)?;
    let theirs = with_keys(sigs, other, known_pubkey(&rpc, other, pk).await)?;
    submit_multi(&rpc, &[tx], &theirs[..1], &key).await
}

pub async fn relay_cancel(net: &ChainNet, tok: &TokenCfg, trade: &Trade, sig_hex: &str) -> Result<String, String> {
    let p = parties(trade)?;
    refund_with(net, tok, trade, &p.buyer, sig_hex).await
}

pub async fn freeze(net: &ChainNet, trade: &Trade) -> Result<String, String> {
    let rpc = Rpc::new(net);
    let p = parties(trade)?;
    let key = signing_key(&net.key_path)?;
    if x::address_of(&key) != p.buyer {
        return Err("this wallet is not the buyer named in the escrow".into());
    }
    let r = trade.escrow.as_ref().ok_or("the trade names no escrow yet")?;
    if rpc.escrow_amount(&r.funder, &r.contract).await?.is_none() {
        return Err("the escrow is already frozen or settled".into());
    }
    finish_into_account(&rpc, trade, &key).await?;
    Ok(r.tx.clone())
}

pub async fn reclaim(net: &ChainNet, tok: &TokenCfg, trade: &Trade) -> Result<String, String> {
    if trade.state == TradeState::Refunded && trade.closed_by == Some(Role::Arbiter) {
        if let Some(sig) = trade.native_sig.as_deref() {
            let p = parties(trade)?;
            return refund_with(net, tok, trade, &p.arbiter, sig).await;
        }
    }
    let rpc = Rpc::new(net);
    let r = trade.escrow.as_ref().ok_or("the trade names no escrow yet")?;
    let Some((_, cancel_at)) = rpc.escrow_amount(&r.funder, &r.contract).await? else {
        return Err("the buyer froze this escrow, so only the arbiter can decide where the XRP goes".into());
    };
    let now = x::ripple_time(chrono::Utc::now().timestamp());
    if now <= cancel_at {
        let unix = cancel_at as i64 + x::RIPPLE_EPOCH;
        let when = chrono::DateTime::from_timestamp(unix, 0).map(|d| d.format("%d %b %Y, %H:%M UTC").to_string()).unwrap_or_default();
        return Err(format!("you can take the XRP back from {when}, or as soon as the arbiter decides for you"));
    }
    let key = signing_key(&net.key_path)?;
    let me = x::address_of(&key);
    let acct = rpc.account(&me).await?.ok_or("this wallet has no XRP account")?;
    let ledger = rpc.ledger_now().await?;
    let mut tx = base_for(ledger, x::TT_ESCROW_CANCEL, &id(&me)?, acct.sequence);
    tx.set(x::F_OWNER, Value::Account(id(&r.funder)?));
    tx.set(x::F_OFFER_SEQUENCE, Value::U32(rpc.sequence_of(&r.tx).await?));
    single(&rpc, &key, tx).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_round_trip_through_the_market_check() {
        let key = SigningKey::from_slice(&[5; 32]).unwrap();
        let e = x::account_id(&x::pubkey_of(&SigningKey::from_slice(&[9; 32]).unwrap()));
        let tx = payment(&e, 77, MULTI_FEE_DROPS, &x::account_id(&x::pubkey_of(&key)), 10_000_000);
        let (_, sig, pk) = x::sign_multi(&tx, &key).unwrap();
        let mut raw = hex::decode(encode_payload(77, MULTI_FEE_DROPS, &[sig.clone(), sig.clone()])).unwrap();
        raw.extend_from_slice(&pk);
        let (seq, fee, sigs, key_back) = xrp_sig_payload(&hex::encode(raw)).unwrap();
        assert_eq!((seq, fee, sigs.len()), (77, MULTI_FEE_DROPS, 2));
        assert_eq!(key_back.map(|k| k.to_vec()), Some(pk));
        let (seq, _, sigs, none) = xrp_sig_payload(&encode_payload(5, MULTI_FEE_DROPS, &[sig])).unwrap();
        assert_eq!((seq, sigs.len(), none), (5, 1, None));
    }

    fn random_hex() -> String {
        loop {
            let b: [u8; 32] = rand::random();
            if SigningKey::from_slice(&b).is_ok() {
                return hex::encode(b);
            }
        }
    }

    async fn faucet(addr: &str) {
        let r = http_client()
            .post("https://faucet.altnet.rippletest.net/accounts")
            .json(&json!({ "destination": addr }))
            .send()
            .await
            .expect("the faucet answers");
        assert!(r.status().is_success(), "faucet: {}", r.status());
    }

    #[test]
    #[ignore]
    fn a_real_xrp_testnet_trade_locks_and_releases() {
        if std::env::var("EGO_XRP_LIVE").is_err() {
            return;
        }
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let (s, b, a) = (random_hex(), random_hex(), random_hex());
            let addr = |h: &str| x::address_of(&SigningKey::from_slice(&hex::decode(h).unwrap()).unwrap());
            let (sa, ba, aa) = (addr(&s), addr(&b), addr(&a));
            for who in [&sa, &ba, &aa] {
                faucet(who).await;
            }
            tokio::time::sleep(std::time::Duration::from_secs(12)).await;
            let mut net = chains::default_networks().net("xrp").unwrap().clone();
            net.rpc = vec!["https://s.altnet.rippletest.net:51234".into()];
            net.key_path = format!("hex:{s}");
            net.fee_receiver = aa.clone();
            let tok = chains::default_networks().token("XRP").unwrap().clone();
            let now = chrono::Utc::now().timestamp();
            let id: [u8; 32] = rand::random();
            let mut trade: Trade = serde_json::from_value(json!({
                "id": format!("0x{}", hex::encode(id)), "offer_id": "0xo", "maker": "m", "taker": "t",
                "seller": "s", "buyer": "b", "asset": "XRP", "amount_micro": 20_000_000u64,
                "maker_fee_micro": 200_000u64, "locked_micro": 20_200_000u64, "fiat": "USD",
                "fiat_micro": 1_000_000u64, "price_micro": 1_000_000u64, "method": "wise",
                "payment_window_secs": 900, "state": "locked", "opened_height": 1, "opened_at": now,
                "buyer_payout": format!("{ba}@{ba}"), "arbiter_payout": aa.clone(),
            }))
            .unwrap();
            let progress = |step: &str| eprintln!("[xrp live] {step}");
            let r = open(&net, &tok, &trade, &progress).await.expect("the seller locks the XRP");
            eprintln!("[xrp live] escrow account {} create {}", r.contract, r.tx);
            trade.escrow = Some(r.clone());
            let view = read(&net, &tok, &trade).await.unwrap();
            assert_eq!(view.state, chains::STATE_FUNDED, "the escrow is locked with the right signers");
            assert!(verify(&net, &tok, &trade, &sa, &view).is_empty(), "the buyer's checks pass: {:?}", verify(&net, &tok, &trade, &sa, &view));
            let mut buyer_net = net.clone();
            buyer_net.key_path = format!("hex:{b}");
            let rpc = Rpc::new(&net);
            let before = rpc.balance(&ba).await.unwrap();
            let fee_before = rpc.balance(&aa).await.unwrap();
            trade.release_sig = Some(release_signature(&buyer_net, &tok, &trade).await.expect("the buyer signs the release"));
            tokio::time::sleep(std::time::Duration::from_secs(75)).await;
            let done = release(&net, &tok, &trade).await.expect("the seller releases");
            eprintln!("[xrp live] released in {done}");
            let after = rpc.balance(&ba).await.unwrap();
            let fee_after = rpc.balance(&aa).await.unwrap();
            assert_eq!(after - before, 20_000_000, "the buyer receives the amount");
            assert_eq!(fee_after - fee_before, 200_000, "the fee reaches the fee address");
        });
    }
}

