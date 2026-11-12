use crate::commands::escrow_chains::{self as chains, ChainNet, NativeEscrow, TokenCfg, FALLBACK_DELAY_SECS};
use crate::commands::multichain::http_client;
use crate::escrow::bitcoin::{self as btc, Coin, Pubkey, Tx, TxIn, TxOut};
use crate::market_chain::{btc_payout, btc_sig_payload, EscrowRef, Family, Role, Trade, TradeState};
use k256::ecdsa::SigningKey;
use serde_json::{json, Value};

pub const LOCK_MARGIN_SECS: i64 = 86_400;
const SELLER: usize = 0;
const BUYER: usize = 1;
const ARBITER: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utxo {
    pub txid: [u8; 32],
    pub vout: u32,
    pub value: u64,
}

pub fn coin_of(net: &ChainNet) -> Result<Coin, String> {
    net.family.coin().ok_or_else(|| format!("{} is not a Bitcoin-style network", net.label))
}

pub fn signing_key(path: &str) -> Result<SigningKey, String> {
    SigningKey::from_slice(&chains::wallet_key(path)?).map_err(|e| e.to_string())
}

pub fn wallet_pubkey(net: &ChainNet) -> Result<Pubkey, String> {
    Ok(btc::pubkey_of(&signing_key(&net.key_path)?))
}

pub fn wallet_address(net: &ChainNet, path: &str) -> Result<String, String> {
    Ok(btc::payout_address(coin_of(net)?, &btc::pubkey_of(&signing_key(path)?)))
}

pub fn payout_entry(net: &ChainNet, path: &str, to: Option<&str>) -> Result<String, String> {
    let coin = coin_of(net)?;
    let key = btc::pubkey_of(&signing_key(path)?);
    let address = match to.map(str::trim).filter(|a| !a.is_empty()) {
        Some(a) if btc::valid_address(coin, a) => a.to_string(),
        Some(a) => return Err(format!("{a:.60} is not a {} address", net.label)),
        None => btc::payout_address(coin, &key),
    };
    Ok(format!("{}@{address}", hex::encode(key)))
}

pub fn same(family: Family, a: &str, b: &str) -> bool {
    let key = |s: &str| btc_payout(family, s).map(|(k, _)| k);
    match (key(a), key(b)) {
        (Some(x), Some(y)) => x == y,
        _ => a.trim().eq_ignore_ascii_case(b.trim()),
    }
}

pub fn locktime_of(trade: &Trade) -> u32 {
    (trade.opened_at + FALLBACK_DELAY_SECS as i64 + LOCK_MARGIN_SECS).clamp(btc::LOCKTIME_THRESHOLD as i64, u32::MAX as i64) as u32
}

struct Parties {
    keys: [Pubkey; 3],
    buyer_to: String,
    script: Vec<u8>,
    locktime: u32,
}

fn parties(trade: &Trade, family: Family, seller: Pubkey) -> Result<Parties, String> {
    let (buyer, buyer_to) = btc_payout(family, trade.buyer_payout.as_deref().unwrap_or("")).ok_or("the trade names no buyer key")?;
    let (arbiter, _) = btc_payout(family, trade.arbiter_payout.as_deref().unwrap_or("")).ok_or("the trade names no arbiter key")?;
    let locktime = locktime_of(trade);
    Ok(Parties { keys: [seller, buyer, arbiter], buyer_to, script: btc::escrow_script(&seller, &buyer, &arbiter, locktime), locktime })
}

fn seller_of(trade: &Trade) -> Result<Pubkey, String> {
    let r = trade.escrow.as_ref().ok_or("the trade names no escrow yet")?;
    btc::parse_pubkey(r.funder.split('@').next().unwrap_or(""))
}

fn fee_address(net: &ChainNet) -> Result<String, String> {
    let raw = crate::commands::escrow_outside::fee_receiver(net)?;
    Ok(btc_payout(net.family, &raw).map(|(_, a)| a).unwrap_or(raw))
}

pub struct UtxoClient<'a> {
    net: &'a ChainNet,
    coin: Coin,
}

impl<'a> UtxoClient<'a> {
    pub fn new(net: &'a ChainNet) -> Result<Self, String> {
        Ok(Self { net, coin: coin_of(net)? })
    }

    async fn get(&self, path: &str) -> Result<Value, String> {
        let mut last = format!("no API is configured for {}", self.net.label);
        for base in &self.net.rpc {
            match http_client().get(format!("{}{path}", base.trim_end_matches('/'))).send().await {
                Ok(r) if r.status().is_success() => match r.json::<Value>().await {
                    Ok(v) => return Ok(v),
                    Err(e) => last = e.to_string(),
                },
                Ok(r) => last = format!("{} answered {}", self.net.label, r.status()),
                Err(e) => last = e.to_string(),
            }
        }
        Err(last)
    }

    pub async fn utxos(&self, address: &str) -> Result<Vec<Utxo>, String> {
        let mut out = Vec::new();
        if self.coin == Coin::Bitcoin {
            let v = self.get(&format!("/address/{address}/utxo")).await?;
            for u in v.as_array().cloned().unwrap_or_default() {
                let (Some(txid), Some(vout), Some(value)) = (u["txid"].as_str(), u["vout"].as_u64(), u["value"].as_u64()) else { continue };
                out.push(Utxo { txid: btc::txid_from_hex(txid)?, vout: vout as u32, value });
            }
        } else {
            let v = self.get(&format!("/addrs/{address}?unspentOnly=true&limit=200")).await?;
            for key in ["txrefs", "unconfirmed_txrefs"] {
                for u in v[key].as_array().cloned().unwrap_or_default() {
                    let (Some(txid), Some(vout), Some(value)) = (u["tx_hash"].as_str(), u["tx_output_n"].as_i64(), u["value"].as_u64()) else { continue };
                    if vout < 0 || u["spent"].as_bool() == Some(true) {
                        continue;
                    }
                    let utxo = Utxo { txid: btc::txid_from_hex(txid)?, vout: vout as u32, value };
                    if !out.contains(&utxo) {
                        out.push(utxo);
                    }
                }
            }
        }
        Ok(out)
    }

    pub async fn balance(&self, address: &str) -> Result<u64, String> {
        Ok(self.utxos(address).await?.iter().map(|u| u.value).sum())
    }

    pub async fn fee_rate(&self) -> u32 {
        if self.coin == Coin::Bitcoin {
            if let Ok(v) = self.get("/v1/fees/recommended").await {
                if let Some(r) = v["halfHourFee"].as_u64() {
                    return r.clamp(1, 500) as u32;
                }
            }
            if let Ok(v) = self.get("/fee-estimates").await {
                if let Some(r) = v["3"].as_f64() {
                    return (r.ceil() as u64).clamp(1, 500) as u32;
                }
            }
            return 5;
        }
        match self.get("").await {
            Ok(v) => (v["medium_fee_per_kb"].as_u64().unwrap_or(1_000_000) / 1_000).clamp(1_000, 100_000) as u32,
            Err(_) => 1_000,
        }
    }

    pub async fn broadcast(&self, raw: &[u8]) -> Result<String, String> {
        let hex_tx = hex::encode(raw);
        let mut last = format!("no API is configured for {}", self.net.label);
        for base in &self.net.rpc {
            let base = base.trim_end_matches('/');
            let sent = if self.coin == Coin::Bitcoin {
                http_client().post(format!("{base}/tx")).header("Content-Type", "text/plain").body(hex_tx.clone()).send().await
            } else {
                http_client().post(format!("{base}/txs/push")).json(&json!({ "tx": hex_tx })).send().await
            };
            match sent {
                Ok(r) => {
                    let ok = r.status().is_success();
                    let text = r.text().await.unwrap_or_default();
                    if !ok {
                        last = format!("{} refused the transaction: {}", self.net.label, text.chars().take(300).collect::<String>());
                        continue;
                    }
                    if self.coin == Coin::Bitcoin {
                        return Ok(text.trim().to_string());
                    }
                    let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                    return v["tx"]["hash"].as_str().map(str::to_string).ok_or_else(|| format!("{} gave no transaction id", self.net.label));
                }
                Err(e) => last = e.to_string(),
            }
        }
        Err(last)
    }

    pub async fn escrow_utxo(&self, address: &str, funding_tx: &str) -> Result<Option<Utxo>, String> {
        let want = btc::txid_from_hex(funding_tx)?;
        Ok(self.utxos(address).await?.into_iter().find(|u| u.txid == want))
    }
}

fn spend_tx(escrow: &Utxo, outputs: Vec<TxOut>, locktime: u32) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn { txid: escrow.txid, vout: escrow.vout, value: escrow.value, sequence: btc::SEQUENCE_LOCKED }],
        outputs,
        locktime,
    }
}

fn release_outputs(coin: Coin, p: &Parties, escrow: &Utxo, fee_base: u64, fee_to: &str, rate: u32) -> Result<Vec<TxOut>, String> {
    let with_fee = fee_base >= coin.dust();
    let miner = rate as u64 * btc::escrow_spend_vbytes(coin, if with_fee { 2 } else { 1 });
    let keep = miner + if with_fee { fee_base } else { 0 };
    let buyer_gets = escrow.value.checked_sub(keep).filter(|v| *v >= coin.dust()).ok_or("the escrow is too small to pay out after the network fee")?;
    let mut outputs = vec![TxOut { value: buyer_gets, script_pubkey: btc::script_pubkey_for_address(coin, &p.buyer_to)? }];
    if with_fee {
        outputs.push(TxOut { value: fee_base, script_pubkey: btc::script_pubkey_for_address(coin, fee_to)? });
    }
    Ok(outputs)
}

fn refund_outputs(coin: Coin, p: &Parties, escrow: &Utxo, rate: u32) -> Result<Vec<TxOut>, String> {
    let miner = rate as u64 * btc::escrow_spend_vbytes(coin, 1);
    let back = escrow.value.checked_sub(miner).filter(|v| *v >= coin.dust()).ok_or("the escrow is too small to return after the network fee")?;
    Ok(vec![TxOut { value: back, script_pubkey: btc::wallet_script_pubkey(coin, &p.keys[SELLER]) }])
}

fn sign_escrow(coin: Coin, tx: &Tx, p: &Parties, key: &SigningKey) -> Result<Vec<u8>, String> {
    btc::sign_hash(key, &btc::escrow_sighash(coin, tx, 0, &p.script))
}

fn check_sig(coin: Coin, tx: &Tx, p: &Parties, who: usize, sig: &[u8]) -> Result<(), String> {
    if btc::verify_sig(&p.keys[who], &btc::escrow_sighash(coin, tx, 0, &p.script), sig) {
        Ok(())
    } else {
        Err("the other party's signature does not match this payout".into())
    }
}

fn finish(coin: Coin, tx: &Tx, p: &Parties, mut sigs: Vec<(usize, Vec<u8>)>) -> Vec<u8> {
    sigs.sort_by_key(|(i, _)| *i);
    let (ss, wit) = btc::escrow_multisig_unlock(coin, &p.script, &sigs[0].1, &sigs[1].1);
    btc::serialize(tx, &[ss], &[wit])
}

fn payload(rate: u32, sig: &[u8]) -> String {
    let mut v = rate.to_le_bytes().to_vec();
    v.extend_from_slice(sig);
    hex::encode(v)
}

fn when(unix: u32) -> String {
    chrono::DateTime::from_timestamp(unix as i64, 0).map(|d| d.format("%d %b %Y, %H:%M UTC").to_string()).unwrap_or_default()
}

async fn context<'n>(net: &'n ChainNet, trade: &Trade) -> Result<(Coin, Parties, Utxo, UtxoClient<'n>), String> {
    let coin = coin_of(net)?;
    let p = parties(trade, net.family, seller_of(trade)?)?;
    let r = trade.escrow.as_ref().ok_or("the trade names no escrow yet")?;
    let client = UtxoClient::new(net)?;
    let address = btc::escrow_address(coin, &p.script);
    if !address.eq_ignore_ascii_case(r.contract.trim()) {
        return Err("the recorded escrow address does not match this trade".into());
    }
    let utxo = client.escrow_utxo(&address, &r.tx).await?.ok_or_else(|| format!("the escrow on {} is already settled or not confirmed yet", net.label))?;
    Ok((coin, p, utxo, client))
}

pub async fn open(net: &ChainNet, tok: &TokenCfg, trade: &Trade, progress: crate::commands::escrow_outside::Progress<'_>) -> Result<EscrowRef, String> {
    let coin = coin_of(net)?;
    let key = signing_key(&net.key_path)?;
    let seller = btc::pubkey_of(&key);
    let p = parties(trade, net.family, seller)?;
    let client = UtxoClient::new(net)?;
    let escrow_at = btc::escrow_address(coin, &p.script);
    let total = u64::try_from(chains::to_base_units(trade.locked_micro, tok.decimals)).map_err(|_| "the amount is too large")?;
    let wallet = btc::payout_address(coin, &seller);
    progress("approve");
    let mut coins = client.utxos(&wallet).await?;
    coins.sort_by(|a, b| b.value.cmp(&a.value));
    let rate = client.fee_rate().await as u64;
    let mut picked = Vec::new();
    let mut have = 0u64;
    let base = 10 + 2 * btc::output_vbytes();
    let mut need = total + rate * base;
    for c in coins {
        have += c.value;
        picked.push(c);
        need = total + rate * (base + picked.len() as u64 * btc::wallet_input_vbytes(coin));
        if have >= need {
            break;
        }
    }
    if have < need {
        return Err(format!("this wallet holds {have} of the {need} base units the escrow and its network fee need; send {} to {wallet}", tok.asset));
    }
    let change = have - need;
    let mut outputs = vec![TxOut { value: total, script_pubkey: btc::escrow_script_pubkey(coin, &p.script) }];
    if change >= coin.dust() {
        outputs.push(TxOut { value: change, script_pubkey: btc::wallet_script_pubkey(coin, &seller) });
    }
    let tx = Tx {
        version: 2,
        inputs: picked.iter().map(|u| TxIn { txid: u.txid, vout: u.vout, value: u.value, sequence: 0xffff_ffff }).collect(),
        outputs,
        locktime: 0,
    };
    let mut sigs = Vec::new();
    let mut wits = Vec::new();
    for i in 0..tx.inputs.len() {
        let (s, w) = btc::sign_wallet_input(coin, &tx, i, &key)?;
        sigs.push(s);
        wits.push(w);
    }
    progress("open");
    let raw = btc::serialize(&tx, &sigs, &wits);
    let txid = client.broadcast(&raw).await?;
    Ok(EscrowRef { contract: escrow_at, funder: hex::encode(seller), tx: txid })
}

pub async fn read(net: &ChainNet, tok: &TokenCfg, trade: &Trade) -> Result<NativeEscrow, String> {
    let coin = coin_of(net)?;
    let p = parties(trade, net.family, seller_of(trade)?)?;
    let r = trade.escrow.as_ref().ok_or("the trade names no escrow yet")?;
    let found = UtxoClient::new(net)?.escrow_utxo(&btc::escrow_address(coin, &p.script), &r.tx).await?;
    Ok(NativeEscrow {
        seller: hex::encode(p.keys[SELLER]),
        opened_at: trade.opened_at.max(0) as u64,
        state: if found.is_some() { chains::STATE_FUNDED } else { 2 },
        frozen: false,
        buyer: hex::encode(p.keys[BUYER]),
        fallback_at: p.locktime as u64,
        arbiter: hex::encode(p.keys[ARBITER]),
        token: String::new(),
        total: found.as_ref().map_or(0, |u| u.value as u128),
        fee: chains::to_base_units(trade.maker_fee_micro, tok.decimals),
        fee_receiver: fee_address(net).ok(),
    })
}

pub fn verify(net: &ChainNet, tok: &TokenCfg, trade: &Trade, funder: &str, e: &NativeEscrow) -> Vec<String> {
    let mut problems = Vec::new();
    if e.state != chains::STATE_FUNDED {
        problems.push(format!("no open escrow exists on {} for this trade", net.label));
        return problems;
    }
    if !same(net.family, &e.seller, funder) {
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

pub async fn release_signature(net: &ChainNet, tok: &TokenCfg, trade: &Trade) -> Result<String, String> {
    let (coin, p, utxo, client) = context(net, trade).await?;
    let key = signing_key(&net.key_path)?;
    if btc::pubkey_of(&key) != p.keys[BUYER] {
        return Err("this wallet is not the buyer named in the escrow".into());
    }
    let rate = client.fee_rate().await;
    let fee_base = u64::try_from(chains::to_base_units(trade.maker_fee_micro, tok.decimals)).unwrap_or(0);
    let tx = spend_tx(&utxo, release_outputs(coin, &p, &utxo, fee_base, &fee_address(net)?, rate)?, 0);
    Ok(payload(rate, &sign_escrow(coin, &tx, &p, &key)?))
}

async fn release_with(net: &ChainNet, tok: &TokenCfg, trade: &Trade, signer: usize, key_path: &str) -> Result<String, String> {
    let (coin, p, utxo, client) = context(net, trade).await?;
    let (rate, buyer_sig) = btc_sig_payload(trade.release_sig.as_deref().ok_or("the buyer has not signed the release yet")?)?;
    let key = signing_key(key_path)?;
    if btc::pubkey_of(&key) != p.keys[signer] {
        return Err("this wallet is not named in the escrow".into());
    }
    let fee_base = u64::try_from(chains::to_base_units(trade.maker_fee_micro, tok.decimals)).unwrap_or(0);
    let tx = spend_tx(&utxo, release_outputs(coin, &p, &utxo, fee_base, &fee_address(net)?, rate)?, 0);
    check_sig(coin, &tx, &p, BUYER, &buyer_sig)?;
    let mine = sign_escrow(coin, &tx, &p, &key)?;
    client.broadcast(&finish(coin, &tx, &p, vec![(BUYER, buyer_sig), (signer, mine)])).await
}

pub async fn release(net: &ChainNet, tok: &TokenCfg, trade: &Trade) -> Result<String, String> {
    release_with(net, tok, trade, SELLER, &net.key_path).await
}

pub async fn resolve(net: &ChainNet, tok: &TokenCfg, trade: &Trade, to_buyer: bool, arbiter_path: &str) -> Result<String, String> {
    if to_buyer {
        return release_with(net, tok, trade, ARBITER, arbiter_path).await;
    }
    let (coin, p, utxo, client) = context(net, trade).await?;
    let key = signing_key(arbiter_path)?;
    if btc::pubkey_of(&key) != p.keys[ARBITER] {
        return Err("this wallet is not the arbiter named in the escrow".into());
    }
    let rate = client.fee_rate().await;
    let tx = spend_tx(&utxo, refund_outputs(coin, &p, &utxo, rate)?, 0);
    Ok(payload(rate, &sign_escrow(coin, &tx, &p, &key)?))
}

pub async fn buyer_cancel(net: &ChainNet, trade: &Trade) -> Result<String, String> {
    let (coin, p, utxo, client) = context(net, trade).await?;
    let key = signing_key(&net.key_path)?;
    if btc::pubkey_of(&key) != p.keys[BUYER] {
        return Err("this wallet is not the buyer named in the escrow".into());
    }
    let rate = client.fee_rate().await;
    let tx = spend_tx(&utxo, refund_outputs(coin, &p, &utxo, rate)?, 0);
    Ok(payload(rate, &sign_escrow(coin, &tx, &p, &key)?))
}

async fn refund_with(net: &ChainNet, trade: &Trade, other: usize, sig_hex: &str) -> Result<String, String> {
    let (coin, p, utxo, client) = context(net, trade).await?;
    let (rate, their_sig) = btc_sig_payload(sig_hex)?;
    let key = signing_key(&net.key_path)?;
    if btc::pubkey_of(&key) != p.keys[SELLER] {
        return Err("this wallet is not the seller named in the escrow".into());
    }
    let tx = spend_tx(&utxo, refund_outputs(coin, &p, &utxo, rate)?, 0);
    check_sig(coin, &tx, &p, other, &their_sig)?;
    let mine = sign_escrow(coin, &tx, &p, &key)?;
    client.broadcast(&finish(coin, &tx, &p, vec![(other, their_sig), (SELLER, mine)])).await
}

pub async fn relay_cancel(net: &ChainNet, trade: &Trade, sig_hex: &str) -> Result<String, String> {
    refund_with(net, trade, BUYER, sig_hex).await
}

pub async fn reclaim(net: &ChainNet, trade: &Trade) -> Result<String, String> {
    if trade.state == TradeState::Refunded && trade.closed_by == Some(Role::Arbiter) {
        if let Some(sig) = trade.native_sig.as_deref() {
            return refund_with(net, trade, ARBITER, sig).await;
        }
    }
    let (coin, p, utxo, client) = context(net, trade).await?;
    if (chrono::Utc::now().timestamp() as u32) < p.locktime {
        return Err(format!("you can take the coins back from {}, or as soon as the arbiter decides for you", when(p.locktime)));
    }
    let key = signing_key(&net.key_path)?;
    if btc::pubkey_of(&key) != p.keys[SELLER] {
        return Err("this wallet is not the seller named in the escrow".into());
    }
    let rate = client.fee_rate().await;
    let tx = spend_tx(&utxo, refund_outputs(coin, &p, &utxo, rate)?, p.locktime);
    let sig = sign_escrow(coin, &tx, &p, &key)?;
    let (ss, wit) = btc::escrow_timeout_unlock(coin, &p.script, &sig);
    client.broadcast(&btc::serialize(&tx, &[ss], &[wit])).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_slice(&[n; 32]).unwrap()
    }

    fn parties_for(coin: Coin) -> Parties {
        let keys = [btc::pubkey_of(&key(1)), btc::pubkey_of(&key(2)), btc::pubkey_of(&key(3))];
        let script = btc::escrow_script(&keys[0], &keys[1], &keys[2], 1_900_000_000);
        Parties { keys, buyer_to: btc::payout_address(coin, &keys[1]), script, locktime: 1_900_000_000 }
    }

    #[test]
    fn a_buyer_presigned_release_completes_with_the_seller_or_the_arbiter() {
        for coin in [Coin::Bitcoin, Coin::Dogecoin] {
            let p = parties_for(coin);
            let escrow = Utxo { txid: btc::sha256(b"f"), vout: 0, value: 50_000_000 };
            let fee_to = btc::payout_address(coin, &p.keys[2]);
            let rate = if coin == Coin::Bitcoin { 5 } else { 1_000 };
            let tx = spend_tx(&escrow, release_outputs(coin, &p, &escrow, 2_000_000, &fee_to, rate).unwrap(), 0);
            let buyer_sig = sign_escrow(coin, &tx, &p, &key(2)).unwrap();
            let (r, back) = btc_sig_payload(&payload(rate, &buyer_sig)).unwrap();
            assert_eq!((r, &back), (rate, &buyer_sig));
            assert!(check_sig(coin, &tx, &p, BUYER, &buyer_sig).is_ok());
            assert!(check_sig(coin, &tx, &p, SELLER, &buyer_sig).is_err());
            let seller_sig = sign_escrow(coin, &tx, &p, &key(1)).unwrap();
            let raw = finish(coin, &tx, &p, vec![(BUYER, buyer_sig.clone()), (SELLER, seller_sig.clone())]);
            let raw2 = finish(coin, &tx, &p, vec![(SELLER, seller_sig), (BUYER, buyer_sig)]);
            assert_eq!(raw, raw2, "signatures are always placed in key order");
            let paid: u64 = tx.outputs.iter().map(|o| o.value).sum();
            assert_eq!(escrow.value - paid, rate as u64 * btc::escrow_spend_vbytes(coin, 2));
            assert_eq!(tx.outputs[1].value, 2_000_000);
        }
    }

    #[test]
    fn payouts_name_a_key_and_an_address() {
        let k = hex::encode(btc::pubkey_of(&key(2)));
        let (_, a) = btc_payout(Family::Bitcoin, &k).unwrap();
        assert!(a.starts_with("bc1q"));
        let doge = btc::payout_address(Coin::Dogecoin, &btc::pubkey_of(&key(5)));
        let (_, d) = btc_payout(Family::Dogecoin, &format!("{k}@{doge}")).unwrap();
        assert_eq!(d, doge);
        assert!(btc_payout(Family::Bitcoin, &format!("{k}@{doge}")).is_none());
        assert!(same(Family::Bitcoin, &k, &format!("{k}@bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")));
    }
    struct Node {
        url: String,
        coin: Coin,
    }

    impl Node {
        async fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
            let body = json!({ "jsonrpc": "1.0", "id": "ego", "method": method, "params": params });
            let r = http_client().post(&self.url).basic_auth("ego", Some("ego")).json(&body).send().await.map_err(|e| e.to_string())?;
            let v: serde_json::Value = r.json().await.map_err(|e| e.to_string())?;
            if !v["error"].is_null() {
                return Err(v["error"].to_string());
            }
            Ok(v["result"].clone())
        }

        async fn mine(&self, n: u64) {
            let to = self.call("getnewaddress", json!([])).await.unwrap();
            self.call("generatetoaddress", json!([n, to])).await.unwrap();
        }

        async fn wallet_address(&self, key: &Pubkey) -> String {
            match self.coin {
                Coin::Bitcoin => {
                    let d = self.call("getdescriptorinfo", json!([format!("wpkh({})", hex::encode(key))])).await.unwrap();
                    let a = self.call("deriveaddresses", json!([d["descriptor"].as_str().unwrap()])).await.unwrap();
                    a[0].as_str().unwrap().to_string()
                }
                Coin::Dogecoin => btc::base58check(0x6f, &btc::hash160(key)),
            }
        }

        async fn output_of(&self, txid: &str, script_pubkey: &[u8]) -> Utxo {
            let raw = self.call("getrawtransaction", json!([txid, true])).await.unwrap();
            let want = hex::encode(script_pubkey);
            let out = raw["vout"]
                .as_array()
                .unwrap()
                .iter()
                .find(|o| o["scriptPubKey"]["hex"].as_str() == Some(want.as_str()))
                .expect("the output");
            Utxo {
                txid: btc::txid_from_hex(txid).unwrap(),
                vout: out["n"].as_u64().unwrap() as u32,
                value: (out["value"].as_f64().unwrap() * 1e8).round() as u64,
            }
        }

        async fn pay(&self, to: &str, coins: f64, script_pubkey: &[u8]) -> Utxo {
            let txid = self.call("sendtoaddress", json!([to, coins])).await.unwrap();
            let txid = txid.as_str().unwrap().to_string();
            self.mine(1).await;
            self.output_of(&txid, script_pubkey).await
        }

        async fn send(&self, raw: &[u8]) -> Result<String, String> {
            self.call("sendrawtransaction", json!([hex::encode(raw)])).await.map(|v| v.as_str().unwrap_or("").to_string())
        }
    }

    fn escrow_for(keys: [Pubkey; 3], locktime: u32) -> Parties {
        let script = btc::escrow_script(&keys[0], &keys[1], &keys[2], locktime);
        Parties { keys, buyer_to: String::new(), script, locktime }
    }

    fn fund_tx(coin: Coin, rate: u64, p: &Parties, amount: u64, from: &Utxo, seller: &SigningKey) -> (Vec<u8>, u64) {
        let seller_spk = btc::wallet_script_pubkey(coin, &btc::pubkey_of(seller));
        let miner = rate * (10 + btc::wallet_input_vbytes(coin) + 2 * btc::output_vbytes());
        let change = from.value - amount - miner;
        let tx = Tx {
            version: 2,
            inputs: vec![TxIn { txid: from.txid, vout: from.vout, value: from.value, sequence: 0xffff_ffff }],
            outputs: vec![
                TxOut { value: amount, script_pubkey: btc::escrow_script_pubkey(coin, &p.script) },
                TxOut { value: change, script_pubkey: seller_spk },
            ],
            locktime: 0,
        };
        let (ss, wit) = btc::sign_wallet_input(coin, &tx, 0, seller).unwrap();
        (btc::serialize(&tx, &[ss], &[wit]), change)
    }

    async fn regtest_round(node: &Node) {
        let coin = node.coin;
        let rate: u64 = if coin == Coin::Bitcoin { 5 } else { 1_000 };
        let (sk, bk, ak) = (key(11), key(12), key(13));
        let keys = [btc::pubkey_of(&sk), btc::pubkey_of(&bk), btc::pubkey_of(&ak)];
        let tip = node.call("getblockchaininfo", json!([])).await.unwrap()["mediantime"].as_i64().unwrap();
        let now = (chrono::Utc::now().timestamp()).max(tip + 3_600);
        node.call("setmocktime", json!([now])).await.unwrap();
        if coin == Coin::Dogecoin {
            let height = node.call("getblockcount", json!([])).await.unwrap().as_u64().unwrap();
            if height < 1_500 {
                node.mine(1_500 - height).await;
            }
        }
        let seller_spk = btc::wallet_script_pubkey(coin, &keys[0]);
        let seller_addr = node.wallet_address(&keys[0]).await;
        let mut coins = node.pay(&seller_addr, 300.0, &seller_spk).await;
        let amount = 50 * 100_000_000u64;

        let release = escrow_for(keys, now as u32 + 30 * 86_400);
        let (raw, change) = fund_tx(coin, rate, &release, amount, &coins, &sk);
        let txid = node.send(&raw).await.expect("the seller's wallet pays into the escrow");
        node.mine(1).await;
        coins = Utxo { txid: btc::txid_from_hex(&txid).unwrap(), vout: 1, value: change };
        let held = node.output_of(&txid, &btc::escrow_script_pubkey(coin, &release.script)).await;
        assert_eq!(held.value, amount);
        let miner = rate * btc::escrow_spend_vbytes(coin, 2);
        let pay = spend_tx(
            &held,
            vec![
                TxOut { value: amount - 1_000_000 - miner, script_pubkey: btc::wallet_script_pubkey(coin, &keys[1]) },
                TxOut { value: 1_000_000, script_pubkey: btc::wallet_script_pubkey(coin, &keys[2]) },
            ],
            0,
        );
        let b = sign_escrow(coin, &pay, &release, &bk).unwrap();
        let s = sign_escrow(coin, &pay, &release, &sk).unwrap();
        node.send(&finish(coin, &pay, &release, vec![(BUYER, b), (SELLER, s)])).await.expect("seller and buyer release the escrow");
        node.mine(1).await;

        let refund = escrow_for(keys, now as u32 + 30 * 86_400 + 1);
        let (raw, change) = fund_tx(coin, rate, &refund, amount, &coins, &sk);
        let txid = node.send(&raw).await.expect("a second escrow is funded");
        node.mine(1).await;
        coins = Utxo { txid: btc::txid_from_hex(&txid).unwrap(), vout: 1, value: change };
        let held = node.output_of(&txid, &btc::escrow_script_pubkey(coin, &refund.script)).await;
        let back = spend_tx(&held, refund_outputs(coin, &refund, &held, rate as u32).unwrap(), 0);
        let a = sign_escrow(coin, &back, &refund, &ak).unwrap();
        let s = sign_escrow(coin, &back, &refund, &sk).unwrap();
        node.send(&finish(coin, &back, &refund, vec![(ARBITER, a), (SELLER, s)])).await.expect("the arbiter and the seller refund the escrow");
        node.mine(1).await;

        let lock_at = now as u32 + 2 * 86_400;
        let timeout = escrow_for(keys, lock_at);
        let (raw, _) = fund_tx(coin, rate, &timeout, amount, &coins, &sk);
        let txid = node.send(&raw).await.expect("a third escrow is funded");
        node.mine(1).await;
        let held = node.output_of(&txid, &btc::escrow_script_pubkey(coin, &timeout.script)).await;
        let take = spend_tx(&held, refund_outputs(coin, &timeout, &held, rate as u32).unwrap(), lock_at);
        let sig = sign_escrow(coin, &take, &timeout, &sk).unwrap();
        let (ss, wit) = btc::escrow_timeout_unlock(coin, &timeout.script, &sig);
        let raw = btc::serialize(&take, &[ss], &[wit]);
        let early = node.send(&raw).await;
        assert!(early.is_err(), "taking the coins back before the deadline is refused: {early:?}");
        eprintln!("[regtest] {:?} early take-back refused: {}", coin, early.unwrap_err());
        node.call("setmocktime", json!([lock_at as i64 + 3 * 86_400])).await.unwrap();
        node.mine(12).await;
        let sneaky = spend_tx(&held, refund_outputs(coin, &timeout, &held, rate as u32).unwrap(), 0);
        let sig0 = sign_escrow(coin, &sneaky, &timeout, &sk).unwrap();
        let (ss0, wit0) = btc::escrow_timeout_unlock(coin, &timeout.script, &sig0);
        let no_date = node.send(&btc::serialize(&sneaky, &[ss0], &[wit0])).await;
        assert!(no_date.is_err(), "the lock itself refuses a take-back that does not name the deadline: {no_date:?}");
        eprintln!("[regtest] {:?} take-back without the deadline refused by the script: {}", coin, no_date.unwrap_err());
        node.send(&raw).await.expect("after the deadline the seller takes the coins back alone");
        node.mine(1).await;
    }

    #[test]
    #[ignore]
    fn real_bitcoin_and_dogecoin_nodes_accept_the_escrow() {
        if std::env::var("EGO_REGTEST").is_err() {
            return;
        }
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let doge = Node { url: "http://127.0.0.1:18556".into(), coin: Coin::Dogecoin };
            for node in [Node { url: "http://127.0.0.1:18443/wallet/ego".into(), coin: Coin::Bitcoin }, doge] {
                eprintln!("[regtest] {:?}", node.coin);
                regtest_round(&node).await;
                eprintln!("[regtest] {:?} passed", node.coin);
            }
        });
    }
}
