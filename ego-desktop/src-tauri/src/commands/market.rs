use crate::app::AppState;
use crate::error::EgoDesktopError;
use crate::ledger::{data_dir, tx_human_summary, tx_signing_bytes_v2, Ledger, LedgerTx};
use crate::market_chain::{
    self as market, ArbiterBody, DisputeBody, EscrowRef, Family, FeedbackBody, LockBody, OfferBody, OfferRef,
    Outcome, Price, Rating, Role, SettleBody, Side, Trade, TradeOpenBody, TradeRef, TradeState, MARKET_CHAIN_ID,
    MARKET_ESCROW_ADDR,
};
use crate::commands::escrow_chains as chains;
use crate::commands::escrow_outside::{self as outside, Outside};
use crate::p2p::P2PMessage;
use ego_core::KeyPair;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Mutex;
use tauri::{AppHandle, Manager, State};

const CHAT_FILE: &str = "market_chat.json";
const FUNDING_FILE: &str = "market_funding.json";
const MIN_FUNDING_WINDOW_SECS: i64 = 5 * 60;
const RELAY_EVERY_SECS: i64 = 120;
const SEEN_FILE: &str = "market_seen.json";
const CHAT_DOMAIN: &str = "ego/market/chat/v1";
pub const MAX_CHAT_TEXT: usize = 2_000;
const MAX_CHAT_PER_TRADE: usize = 500;
const RETRY_FOR_SECS: i64 = 48 * 3_600;
const FIRST_RETRY_SECS: i64 = 20;
const MAX_RETRY_GAP_SECS: i64 = 600;
const WATCH_EVERY_SECS: u64 = 15;
const KIND_TEXT: &str = "text";
const KIND_ACK: &str = "ack";
const KIND_PAYMENT: &str = "payment";
const MAX_PAYER_NAME: usize = 70;

fn text_kind() -> String {
    KIND_TEXT.to_string()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentNote {
    pub name: String,
    pub reference: String,
}

pub fn clean_payer_name(name: &str) -> Option<String> {
    let n = name.split_whitespace().collect::<Vec<_>>().join(" ");
    let ok = !n.is_empty() && n.chars().count() <= MAX_PAYER_NAME && !n.chars().any(char::is_control);
    ok.then_some(n)
}

pub fn payment_note_body(trade: &Trade, name: &str) -> Option<String> {
    let note = PaymentNote { name: clean_payer_name(name)?, reference: market::payment_reference(&trade.id) };
    serde_json::to_string(&note).ok()
}

pub fn read_payment_note(trade: &Trade, body: &str) -> Option<PaymentNote> {
    let note: PaymentNote = serde_json::from_str(body).ok()?;
    let clean = clean_payer_name(&note.name)?;
    (clean == note.name && note.reference == market::payment_reference(&trade.id)).then_some(note)
}

static CHAT_LOCK: Mutex<()> = Mutex::new(());
static SEEN_LOCK: Mutex<()> = Mutex::new(());
static ARBITER_KEYS: Mutex<BTreeMap<String, String>> = Mutex::new(BTreeMap::new());
static FUNDING_LOCK: Mutex<()> = Mutex::new(());
static RELAYED: Mutex<BTreeMap<String, i64>> = Mutex::new(BTreeMap::new());

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireChat {
    pub trade_id: String,
    pub from: String,
    pub kind: String,
    pub body: String,
    pub ts: i64,
    pub id: String,
    pub pubkey: String,
    pub sig: String,
}

impl WireChat {
    fn into_message(self) -> P2PMessage {
        P2PMessage::MarketChat {
            trade_id: self.trade_id,
            from: self.from,
            kind: self.kind,
            body: self.body,
            ts: self.ts,
            id: self.id,
            pubkey: self.pubkey,
            sig: self.sig,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChatMsg {
    pub id: String,
    pub from: String,
    #[serde(default = "text_kind")]
    pub kind: String,
    pub text: String,
    pub ts: i64,
    pub outgoing: bool,
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub pending_to: Vec<String>,
    #[serde(default)]
    pub attempts: u32,
    #[serde(default)]
    pub next_try: i64,
    #[serde(default)]
    pub pubkey: String,
    #[serde(default)]
    pub sig: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ChatStore {
    #[serde(default)]
    trades: BTreeMap<String, Vec<ChatMsg>>,
}

impl ChatStore {
    fn add(&mut self, trade_id: &str, msg: ChatMsg) -> bool {
        let list = self.trades.entry(trade_id.to_string()).or_default();
        if list.iter().any(|m| m.id == msg.id) {
            return false;
        }
        list.push(msg);
        list.sort_by(|a, b| a.ts.cmp(&b.ts).then_with(|| a.id.cmp(&b.id)));
        if list.len() > MAX_CHAT_PER_TRADE {
            let drop = list.len() - MAX_CHAT_PER_TRADE;
            list.drain(0..drop);
        }
        true
    }

    fn acknowledge(&mut self, trade_id: &str, id: &str, by: &str) -> bool {
        let Some(list) = self.trades.get_mut(trade_id) else { return false };
        let Some(m) = list.iter_mut().find(|m| m.outgoing && m.id == id) else { return false };
        let before = m.pending_to.len();
        m.pending_to.retain(|a| a != by);
        before != m.pending_to.len()
    }

    fn unread(&self) -> BTreeMap<String, usize> {
        self.trades
            .iter()
            .map(|(t, list)| (t.clone(), list.iter().filter(|m| !m.outgoing && !m.read).count()))
            .filter(|(_, n)| *n > 0)
            .collect()
    }
}

fn chat_path() -> std::path::PathBuf {
    data_dir().join(CHAT_FILE)
}

fn load_chat() -> ChatStore {
    std::fs::read(chat_path())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save_chat(store: &ChatStore) -> Result<(), EgoDesktopError> {
    let bytes = serde_json::to_vec(store).map_err(|e| EgoDesktopError::SerializationError(e.to_string()))?;
    crate::utils::atomic_write(&chat_path(), &bytes).map_err(|e| EgoDesktopError::FileSystemError(e.to_string()))
}

pub fn chat_signing_bytes(c: &WireChat) -> Vec<u8> {
    format!(
        "{CHAT_DOMAIN}:{}:{}:{}:{}:{}:{}",
        c.trade_id, c.from, c.kind, c.ts, c.id, c.body
    )
    .into_bytes()
}

pub fn sign_chat(kp: &KeyPair, mut c: WireChat) -> WireChat {
    c.pubkey = hex::encode(kp.ed25519_public_key().as_bytes());
    let sig = kp.sign_ed25519(&chat_signing_bytes(&c));
    c.sig = hex::encode(sig.as_bytes());
    c
}

fn decode32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok().and_then(|v| v.try_into().ok())
}

pub fn chat_is_authentic(c: &WireChat) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    let Some(pk) = decode32(&c.pubkey) else { return false };
    if market::address_of(&pk) != c.from {
        return false;
    }
    let Some(sig) = hex::decode(&c.sig).ok().and_then(|v| <[u8; 64]>::try_from(v).ok()) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else { return false };
    vk.verify_strict(&chat_signing_bytes(c), &Signature::from_bytes(&sig)).is_ok()
}

fn fresh_id() -> String {
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

pub fn retry_gap(attempts: u32) -> i64 {
    FIRST_RETRY_SECS
        .saturating_mul(1i64 << attempts.min(16))
        .min(MAX_RETRY_GAP_SECS)
}

fn arbiter_key(addr: &str) -> Option<String> {
    if let Some(k) = ARBITER_KEYS.lock().unwrap_or_else(|e| e.into_inner()).get(addr) {
        return Some(k.clone());
    }
    let key = crate::chain_db::get_address_txs(addr, 500)
        .into_iter()
        .filter(|t| t.from == addr)
        .map(|t| t.public_key_ed25519)
        .find(|k| decode32(k).is_some_and(|pk| market::address_of(&pk) == addr))?;
    ARBITER_KEYS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(addr.to_string(), key.clone());
    Some(key)
}

pub fn participants(trade: &Trade) -> Vec<(String, String)> {
    let mut out = vec![
        (trade.buyer.clone(), trade.buyer_key.clone()),
        (trade.seller.clone(), trade.seller_key.clone()),
    ];
    if let Some(a) = &trade.arbiter {
        out.push((a.clone(), arbiter_key(a).unwrap_or_default()));
    }
    out
}

fn role_label(trade: &Trade, addr: &str) -> Option<&'static str> {
    if addr == trade.buyer {
        Some("buyer")
    } else if addr == trade.seller {
        Some("seller")
    } else if trade.arbiter.as_deref() == Some(addr) {
        Some("arbiter")
    } else {
        None
    }
}

async fn deliver(wire: &WireChat, to: &[(String, String)]) {
    let peers = crate::p2p::load_peer_cache();
    for (addr, key) in to {
        let msg = wire.clone().into_message();
        if let Some(ep) = peers.iter().find(|p| p.address == *addr).map(|p| p.endpoint.clone()) {
            if !ep.is_empty() {
                let _ = crate::p2p::send_message(&ep, &msg).await;
            }
        }
        if !key.is_empty() {
            crate::p2p::gossip_sealed_dm(addr, key, &msg).await;
        }
    }
}

fn require_active() -> Result<(), EgoDesktopError> {
    if market::rule_active_at_tip() {
        Ok(())
    } else {
        Err(EgoDesktopError::InvalidInput(
            "The P2P market is not switched on for this chain yet.".into(),
        ))
    }
}

fn my_address() -> Result<String, EgoDesktopError> {
    let a = Ledger::load().address;
    if a.is_empty() {
        Err(EgoDesktopError::WalletError("Create or unlock a wallet first".into()))
    } else {
        Ok(a)
    }
}

fn keypair(state: &State<'_, AppState>) -> Result<KeyPair, EgoDesktopError> {
    state
        .get_keypair()
        .ok_or_else(|| EgoDesktopError::WalletError("Unlock your wallet first".into()))
}

fn fmt_egoc(uegoc: u64) -> String {
    format!("{:.2} EGOC", uegoc as f64 / 1_000_000.0)
}

fn pending_outflow(addr: &str) -> u64 {
    crate::mempool::get_mempool()
        .peek_all()
        .into_iter()
        .filter(|t| t.from.trim() == addr)
        .map(|t| t.amount.saturating_add(t.fee_uegoc))
        .fold(0u64, |a, v| a.saturating_add(v))
}

fn network_fee(is_staker: bool) -> u64 {
    crate::tokenomics::fee_for_tx_with_staking("transfer", is_staker)
        .max(crate::chain_db::get_current_base_fee())
        .max(crate::mempool::MIN_FEE_UEGOC)
}

#[allow(clippy::too_many_arguments)]
pub fn build_op_tx(
    kp: &KeyPair,
    from: &str,
    tx_type: &str,
    call_args: String,
    amount: u64,
    nonce: u64,
    fee: u64,
    now: i64,
) -> Result<LedgerTx, String> {
    let memo = market::op_memo(tx_type, &call_args).ok_or_else(|| format!("{tx_type} is not a market operation"))?;
    let sign_bytes = tx_signing_bytes_v2(from, MARKET_ESCROW_ADDR, amount, nonce, now, MARKET_CHAIN_ID, &memo);
    let ed_sig = kp.sign_ed25519(&sign_bytes);
    let dil_sig = kp.sign_dilithium(&sign_bytes);
    Ok(LedgerTx {
        hash: format!("0x{}", ego_core::hash_data(&sign_bytes).to_hex()),
        from: from.to_string(),
        to: MARKET_ESCROW_ADDR.to_string(),
        amount,
        memo: Some(memo.clone()),
        timestamp: now,
        signature: hex::encode(ed_sig.as_bytes()),
        status: "Pending".into(),
        block_height: None,
        nonce,
        public_key_ed25519: hex::encode(kp.ed25519_public_key().as_bytes()),
        dilithium_pubkey: hex::encode(&kp.dilithium_public_key().key_data),
        dilithium_signature: hex::encode(&dil_sig.signature_data),
        tx_type: tx_type.to_string(),
        fee_uegoc: fee,
        call_args,
        tx_version: 2,
        chain_id: MARKET_CHAIN_ID,
        signed_summary: tx_human_summary(from, MARKET_ESCROW_ADDR, amount, &memo, MARKET_CHAIN_ID, nonce, fee),
        ..LedgerTx::default()
    })
}

async fn submit_op(
    state: &State<'_, AppState>,
    tx_type: &str,
    body: &impl Serialize,
    amount: u64,
) -> Result<String, EgoDesktopError> {
    require_active()?;
    let call_args = serde_json::to_string(body).map_err(|e| EgoDesktopError::SerializationError(e.to_string()))?;
    let _guard = crate::ledger::TX_MUTEX.lock().await;
    let kp = keypair(state)?;
    let mut ledger = Ledger::load();
    let from = ledger.address.clone();
    if from.is_empty() {
        return Err(EgoDesktopError::WalletError("Create or unlock a wallet first".into()));
    }
    let fee = network_fee(ledger.staked_amount > 0);
    let available = crate::chain_db::balance_of(&from).saturating_sub(pending_outflow(&from));
    let needed = amount.saturating_add(fee);
    if needed > available {
        return Err(EgoDesktopError::InvalidInput(format!(
            "Not enough EGOC: this needs {} and {} is available",
            fmt_egoc(needed),
            fmt_egoc(available)
        )));
    }
    let nonce = ledger.nonce.max(crate::ledger::last_confirmed_nonce(&from)) + 1;
    let tx = build_op_tx(&kp, &from, tx_type, call_args, amount, nonce, fee, chrono::Utc::now().timestamp())
        .map_err(EgoDesktopError::InvalidInput)?;
    crate::ledger::verify_incoming_tx(&tx).map_err(EgoDesktopError::InvalidInput)?;
    crate::mempool::get_mempool()
        .push(tx.clone())
        .map_err(|e| EgoDesktopError::WalletError(format!("The network refused it: {e}")))?;
    crate::commands::tx_pending::add(&tx);
    ledger.nonce = nonce;
    let _ = ledger.save();
    let hash = tx.hash.clone();
    tauri::async_runtime::spawn(async move {
        crate::p2p::broadcast_pending_tx(tx).await;
    });
    Ok(hash)
}

fn known_trade(id: &str) -> Result<Trade, EgoDesktopError> {
    market::get_trade(id.trim()).ok_or_else(|| {
        EgoDesktopError::NotFound("This trade is not on this node yet. Wait for the next block.".into())
    })
}

pub fn margin_price_micro(fiat: &str, bps: i32, egoc_usd: f64) -> Result<u64, String> {
    if fiat != "USD" {
        return Err("Market-linked prices are available for USD offers only".into());
    }
    let micro = egoc_usd * 1_000_000.0 * (1.0 + bps as f64 / 10_000.0);
    if !micro.is_finite() || micro < 1.0 {
        return Err("The market price is not available right now".into());
    }
    Ok(micro.round() as u64)
}

pub fn quote(offer: &market::Offer, amount_micro: u64, egoc_usd: f64) -> Result<Value, String> {
    let price_micro = match offer.price {
        Price::Fixed(p) => p,
        Price::MarginBps(_) if !market::is_egoc(&offer.asset) => {
            return Err(format!("this offer follows a {} market price this app cannot read yet", offer.asset));
        }
        Price::MarginBps(bps) => margin_price_micro(&offer.fiat, bps, egoc_usd)?,
    };
    if amount_micro < offer.min_micro || amount_micro > offer.max_micro {
        return Err(format!(
            "Choose between {} and {}",
            fmt_egoc(offer.min_micro),
            fmt_egoc(offer.max_micro)
        ));
    }
    let fiat_micro = market::fiat_for(amount_micro, price_micro).filter(|f| *f > 0).ok_or("That amount is too large")?;
    let fee = market::trade_fee(&offer.asset, amount_micro);
    let (lock_uegoc, buyer_receives_micro) = match offer.side {
        Side::Sell => (0, amount_micro),
        Side::Buy => (amount_micro, amount_micro.saturating_sub(fee)),
    };
    Ok(json!({
        "offer_id": offer.id,
        "fiat": offer.fiat,
        "amount_micro": amount_micro,
        "price_micro": price_micro,
        "fiat_micro": fiat_micro,
        "maker_fee_micro": fee,
        "taker_locks_micro": lock_uegoc,
        "buyer_receives_micro": buyer_receives_micro,
        "taker_side": if offer.side == Side::Sell { "buy" } else { "sell" },
    }))
}

fn annotate(mut view: Value, me: &str, unread: &BTreeMap<String, usize>) -> Value {
    if let Some(list) = view["trades"].as_array_mut() {
        for entry in list.iter_mut() {
            let Ok(trade) = serde_json::from_value::<Trade>(entry["trade"].clone()) else { continue };
            entry["my_role"] = json!(role_label(&trade, me));
            entry["unread"] = json!(unread.get(&trade.id).copied().unwrap_or(0));
        }
    }
    view
}

#[tauri::command]
pub async fn market_params() -> Result<Value, EgoDesktopError> {
    let mut v = market::params_view();
    v["egoc_usd"] = json!(crate::p2p::get_egoc_price_usd());
    v["my_address"] = json!(Ledger::load().address);
    Ok(v)
}

#[tauri::command]
pub async fn market_offers(
    asset: Option<String>,
    fiat: String,
    side: String,
    method: Option<String>,
    country: Option<String>,
    amount_micro: Option<u64>,
    cursor: Option<String>,
) -> Result<Value, EgoDesktopError> {
    let side = Side::parse(&side).ok_or_else(|| EgoDesktopError::InvalidInput("side is buy or sell".into()))?;
    let method = method.filter(|m| !m.trim().is_empty());
    let country = country.filter(|c| !c.trim().is_empty());
    let filter = market::OfferFilter {
        method: method.as_deref(),
        country: country.as_deref(),
        amount_micro,
    };
    let asset = asset.unwrap_or_else(|| market::EGOC.to_string()).trim().to_ascii_uppercase();
    Ok(market::offers_view(
        &asset,
        &fiat.trim().to_ascii_uppercase(),
        side,
        50,
        cursor.as_deref(),
        &filter,
    ))
}

#[tauri::command]
pub async fn market_offer(id: String) -> Result<Value, EgoDesktopError> {
    market::offer_by_id_view(id.trim()).ok_or_else(|| EgoDesktopError::NotFound("Offer not found".into()))
}

#[tauri::command]
pub async fn market_quote(offer_id: String, amount_micro: u64) -> Result<Value, EgoDesktopError> {
    let offer = market::get_offer(offer_id.trim()).ok_or_else(|| EgoDesktopError::NotFound("Offer not found".into()))?;
    quote(&offer, amount_micro, crate::p2p::get_egoc_price_usd()).map_err(EgoDesktopError::InvalidInput)
}

#[tauri::command]
pub async fn market_trade(id: String) -> Result<Value, EgoDesktopError> {
    let trade = known_trade(&id)?;
    let me = my_address()?;
    let mut v = market::trade_by_id_view(&trade.id)
        .ok_or_else(|| EgoDesktopError::NotFound("Trade not found".into()))?;
    let counterparty = match role_label(&trade, &me) {
        Some("buyer") => trade.seller.clone(),
        Some("seller") => trade.buyer.clone(),
        _ => String::new(),
    };
    v["my_role"] = json!(role_label(&trade, &me));
    v["my_address"] = json!(me);
    v["offer"] = market::offer_by_id_view(&trade.offer_id).unwrap_or(Value::Null);
    v["buyer_profile"] = json!(market::get_profile(&trade.buyer));
    v["seller_profile"] = json!(market::get_profile(&trade.seller));
    v["counterparty"] = json!(counterparty);
    v["can_chat_arbiter"] = json!(trade.arbiter.as_deref().map(arbiter_key).is_some_and(|k| k.is_some()));
    v["payment_note"] = payment_note_of(&trade).unwrap_or(Value::Null);
    v["active"] = json!(market::rule_active_at_tip());
    Ok(v)
}

#[tauri::command]
pub async fn market_my_trades(cursor: Option<String>) -> Result<Value, EgoDesktopError> {
    let me = my_address()?;
    let unread = {
        let _g = CHAT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        load_chat().unread()
    };
    Ok(annotate(market::trades_of_view(&me, 50, cursor.as_deref()), &me, &unread))
}

#[tauri::command]
pub async fn market_my_cases(cursor: Option<String>) -> Result<Value, EgoDesktopError> {
    let me = my_address()?;
    let unread = {
        let _g = CHAT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        load_chat().unread()
    };
    Ok(annotate(market::cases_of_view(&me, 50, cursor.as_deref()), &me, &unread))
}

#[tauri::command]
pub async fn market_my_offers() -> Result<Value, EgoDesktopError> {
    Ok(market::offers_by_maker_view(&my_address()?))
}

#[tauri::command]
pub async fn market_profile(address: String) -> Result<Value, EgoDesktopError> {
    Ok(market::profile_view(address.trim()))
}

#[tauri::command]
pub async fn market_leaderboard() -> Result<Value, EgoDesktopError> {
    Ok(market::leaderboard_view(25))
}

#[tauri::command]
pub async fn market_post_offer(offer: OfferBody, state: State<'_, AppState>) -> Result<String, EgoDesktopError> {
    market::validate_offer_body(&offer).map_err(EgoDesktopError::InvalidInput)?;
    if matches!(offer.price, Price::MarginBps(_)) && !market::is_egoc(&offer.asset) {
        return Err(EgoDesktopError::InvalidInput("Market-linked prices are available for EGOC offers only".into()));
    }
    if !market::is_egoc(&offer.asset) {
        chains::networks().for_asset(&offer.asset).map_err(EgoDesktopError::InvalidInput)?;
    }
    if let Price::MarginBps(bps) = offer.price {
        margin_price_micro(&offer.fiat, bps, crate::p2p::get_egoc_price_usd()).map_err(EgoDesktopError::InvalidInput)?;
    }
    submit_op(&state, market::TX_OFFER, &offer, 0).await
}

#[tauri::command]
pub async fn market_close_offer(offer_id: String, state: State<'_, AppState>) -> Result<String, EgoDesktopError> {
    submit_op(&state, market::TX_OFFER_CLOSE, &OfferRef { offer_id: offer_id.trim().to_string() }, 0).await
}

#[tauri::command]
pub async fn market_open_trade(
    offer_id: String,
    amount_micro: u64,
    method: String,
    payout_address: Option<String>,
    state: State<'_, AppState>,
) -> Result<String, EgoDesktopError> {
    let offer = market::get_offer(offer_id.trim()).ok_or_else(|| EgoDesktopError::NotFound("Offer not found".into()))?;
    if !offer.methods.iter().any(|m| *m == method) {
        return Err(EgoDesktopError::InvalidInput("Pick one of the offer's payment methods".into()));
    }
    let q = quote(&offer, amount_micro, crate::p2p::get_egoc_price_usd()).map_err(EgoDesktopError::InvalidInput)?;
    let body = TradeOpenBody {
        offer_id: offer.id.clone(),
        amount_micro,
        price_micro: q["price_micro"].as_u64().unwrap_or(0),
        fiat_micro: q["fiat_micro"].as_u64().unwrap_or(0),
        method,
        payout_address: payout_address.map(|a| a.trim().to_string()).filter(|a| !a.is_empty()),
    };
    let lock = q["taker_locks_micro"].as_u64().unwrap_or(0);
    submit_op(&state, market::TX_TRADE_OPEN, &body, lock).await
}

fn chain_err(e: String) -> EgoDesktopError {
    EgoDesktopError::NetworkError(e)
}

fn funding_path() -> std::path::PathBuf {
    data_dir().join(FUNDING_FILE)
}

fn load_funding() -> BTreeMap<String, EscrowRef> {
    std::fs::read(funding_path())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn remember_funding(trade_id: &str, r: &EscrowRef) {
    let _g = FUNDING_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut all = load_funding();
    all.insert(trade_id.to_string(), r.clone());
    if let Ok(bytes) = serde_json::to_vec(&all) {
        let _ = crate::utils::atomic_write(&funding_path(), &bytes);
    }
}

fn progress(app: &AppHandle, trade_id: &str, step: &str) {
    let _ = app.emit_all("ego://market-progress", json!({ "trade_id": trade_id, "step": step }));
}

#[tauri::command]
pub async fn market_fund(trade_id: String, app: AppHandle, state: State<'_, AppState>) -> Result<String, EgoDesktopError> {
    let trade = known_trade(&trade_id)?;
    if trade.is_egoc() {
        let body = LockBody { trade_id: trade.id.clone(), escrow: None };
        return submit_op(&state, market::TX_LOCK, &body, trade.locked_micro).await;
    }
    require_active()?;
    let me = my_address()?;
    if trade.seller != me {
        return Err(EgoDesktopError::PermissionDenied("Only the seller funds the escrow".into()));
    }
    if trade.state != TradeState::AwaitingLock {
        return Err(EgoDesktopError::InvalidInput("This trade is not waiting for the escrow".into()));
    }
    let view = market::trade_by_id_view(&trade.id).unwrap_or(Value::Null);
    let chain_now = view["chain_time"].as_i64().unwrap_or(0);
    let recorded = load_funding().get(&trade.id).cloned();
    if recorded.is_none() && trade.lock_expires_at() - chain_now < MIN_FUNDING_WINDOW_SECS {
        return Err(EgoDesktopError::InvalidInput(
            "Less than five minutes are left to fund this trade, so the escrow would not be recorded in time".into(),
        ));
    }
    let n = chains::networks();
    let (net, tok) = n.for_asset(&trade.asset).map_err(EgoDesktopError::InvalidInput)?;
    let reference = match recorded {
        Some(r) => r,
        None => {
            let app2 = app.clone();
            let tid = trade.id.clone();
            let report = move |step: &str| progress(&app2, &tid, step);
            let r = Outside::new(net, tok).open(&trade, &report).await.map_err(chain_err)?;
            remember_funding(&trade.id, &r);
            r
        }
    };
    progress(&app, &trade.id, "record");
    let body = LockBody { trade_id: trade.id.clone(), escrow: Some(reference.clone()) };
    submit_op(&state, market::TX_LOCK, &body, 0).await.map_err(|e| {
        EgoDesktopError::WalletError(format!(
            "Your {} is locked on {} (transaction {}), but recording it on Ego failed: {e}. Try again; the escrow is kept.",
            trade.asset, net.label, reference.tx
        ))
    })
}

#[tauri::command]
pub async fn market_escrow_status(trade_id: String) -> Result<Value, EgoDesktopError> {
    let trade = known_trade(&trade_id)?;
    if trade.is_egoc() {
        return Ok(json!({ "kind": "ego" }));
    }
    let n = chains::networks();
    let (net, tok) = match n.for_asset(&trade.asset) {
        Ok(v) => v,
        Err(e) => return Ok(json!({ "kind": "outside", "configured": false, "reason": e })),
    };
    let Some(r) = trade.escrow.clone() else {
        return Ok(json!({ "kind": "outside", "configured": true, "funded": false, "network": net.label }));
    };
    let mut problems = Vec::new();
    if !outside::same_address(net.family, &r.contract, &net.escrow) {
        problems.push(format!("the seller used an escrow contract this app does not recognise on {}", net.label));
    }
    let chain = Outside::new(net, tok);
    let escrow = chain.read(&trade).await.map_err(chain_err)?;
    if problems.is_empty() {
        problems = chain.verify(&trade, &r.funder, &escrow);
    }
    Ok(json!({
        "kind": "outside",
        "configured": true,
        "funded": true,
        "network": net.label,
        "family": net.family,
        "native_symbol": net.native_symbol,
        "decimals": tok.decimals,
        "escrow": escrow,
        "contract": r.contract,
        "funder": r.funder,
        "funding_tx": r.tx,
        "explorer_tx": chain.explorer_tx(&r.tx),
        "explorer_contract": chain.explorer_address(&r.contract),
        "verified": problems.is_empty() && escrow.state == chains::STATE_FUNDED,
        "problems": problems,
    }))
}

#[tauri::command]
pub async fn market_chain_address(asset: String) -> Result<Value, EgoDesktopError> {
    let asset = asset.trim().to_ascii_uppercase();
    let info = market::asset_info(&asset).ok_or_else(|| EgoDesktopError::InvalidInput(format!("{asset} is not traded here")))?;
    if info.family == Family::Ego {
        return Ok(json!({ "asset": asset, "address": my_address()?, "network": "Ego" }));
    }
    let n = chains::networks();
    let token = n.token(&asset).cloned();
    let net = token
        .as_ref()
        .and_then(|t| n.net(&t.network))
        .cloned()
        .ok_or_else(|| EgoDesktopError::InvalidInput(format!("{asset} is not set up on this computer")))?;
    let address = outside::wallet_address(&net).map_err(EgoDesktopError::WalletError)?;
    let tok = token.clone().ok_or_else(|| EgoDesktopError::InvalidInput(format!("{asset} is not set up on this computer")))?;
    let chain = Outside::new(&net, &tok);
    let (native, token_balance) = chain.balances(&address).await;
    Ok(json!({
        "asset": asset,
        "address": address,
        "network": net.label,
        "family": net.family,
        "native_symbol": net.native_symbol,
        "native_balance": native.map(|v| v.to_string()),
        "token_balance": token_balance.map(|v| v.to_string()),
        "decimals": tok.decimals,
        "native_decimals": native_decimals(net.family),
        "escrow_ready": n.for_asset(&asset).is_ok(),
        "explorer_address": chain.explorer_address(&address),
    }))
}

#[tauri::command]
pub async fn market_networks() -> Result<chains::Networks, EgoDesktopError> {
    Ok(chains::networks())
}

#[tauri::command]
pub async fn market_save_networks(networks: chains::Networks) -> Result<(), EgoDesktopError> {
    chains::save_networks(&networks).map_err(EgoDesktopError::FileSystemError)
}

fn native_decimals(family: Family) -> u8 {
    match family {
        Family::Evm => 18,
        Family::Solana => 9,
        _ => 6,
    }
}

pub fn arbiter_addresses_here() -> Result<ArbiterBody, String> {
    let n = chains::networks();
    let first = |family: Family| n.networks.iter().find(|net| net.family == family);
    let address = |family: Family| -> Result<Option<String>, String> {
        match first(family) {
            Some(net) => outside::address_for(net, &outside::arbiter_key_path(net)).map(Some),
            None => Ok(None),
        }
    };
    Ok(ArbiterBody {
        evm: address(Family::Evm)?,
        tron: address(Family::Tron)?,
        sol: address(Family::Solana)?,
        ada: address(Family::Cardano)?,
    })
}

#[tauri::command]
pub async fn market_publish_arbiter(state: State<'_, AppState>) -> Result<String, EgoDesktopError> {
    let body = arbiter_addresses_here().map_err(EgoDesktopError::WalletError)?;
    submit_op(&state, market::TX_ARBITER, &body, 0).await
}

#[tauri::command]
pub async fn market_cancel(trade_id: String, state: State<'_, AppState>) -> Result<String, EgoDesktopError> {
    let trade = known_trade(&trade_id)?;
    submit_op(&state, market::TX_TRADE_CANCEL, &TradeRef { trade_id: trade.id }, 0).await
}

#[tauri::command]
pub async fn market_mark_paid(
    trade_id: String,
    payer_name: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<String, EgoDesktopError> {
    require_active()?;
    let trade = known_trade(&trade_id)?;
    let me = my_address()?;
    if trade.buyer != me {
        return Err(EgoDesktopError::PermissionDenied("Only the buyer marks a trade paid".into()));
    }
    let body = payment_note_body(&trade, &payer_name).ok_or_else(|| {
        EgoDesktopError::InvalidInput(format!(
            "Enter the name on the account you paid from, up to {MAX_PAYER_NAME} characters"
        ))
    })?;
    let kp = keypair(&state)?;
    post_chat(&trade, &me, &kp, KIND_PAYMENT, body, &app).await?;
    submit_op(&state, market::TX_PAID, &TradeRef { trade_id: trade.id }, 0).await
}

pub fn payment_note_of(trade: &Trade) -> Option<Value> {
    let _g = CHAT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let store = load_chat();
    let list = store.trades.get(&trade.id)?;
    list.iter()
        .rev()
        .filter(|m| m.kind == KIND_PAYMENT && m.from == trade.buyer)
        .find_map(|m| read_payment_note(trade, &m.text).map(|n| json!({ "name": n.name, "reference": n.reference, "ts": m.ts })))
}

#[tauri::command]
pub async fn market_dispute(trade_id: String, reason: String, state: State<'_, AppState>) -> Result<String, EgoDesktopError> {
    let trade = known_trade(&trade_id)?;
    let body = DisputeBody { trade_id: trade.id, reason: reason.trim().to_string() };
    submit_op(&state, market::TX_DISPUTE, &body, 0).await
}

#[tauri::command]
pub async fn market_feedback(
    trade_id: String,
    rating: Rating,
    comment: String,
    state: State<'_, AppState>,
) -> Result<String, EgoDesktopError> {
    let trade = known_trade(&trade_id)?;
    let body = FeedbackBody { trade_id: trade.id, rating, comment: comment.trim().to_string() };
    submit_op(&state, market::TX_FEEDBACK, &body, 0).await
}

#[tauri::command]
pub async fn market_settle(trade_id: String, outcome: String, state: State<'_, AppState>) -> Result<String, EgoDesktopError> {
    require_active()?;
    let outcome = Outcome::parse(outcome.trim())
        .ok_or_else(|| EgoDesktopError::InvalidInput("outcome is release or refund".into()))?;
    let trade = known_trade(&trade_id)?;
    let me = my_address()?;
    let by = if trade.arbiter.as_deref() == Some(me.as_str()) && trade.state == TradeState::Disputed {
        Role::Arbiter
    } else {
        trade
            .role_of(&me)
            .ok_or_else(|| EgoDesktopError::PermissionDenied("You are not part of this trade".into()))?
    };
    let native_sig = if trade.is_egoc() { None } else { settle_outside(&trade, outcome, by).await? };
    settle_on_ego(&state, &trade, outcome, by, native_sig)
}

async fn settle_outside(trade: &Trade, outcome: Outcome, by: Role) -> Result<Option<String>, EgoDesktopError> {
    let n = chains::networks();
    let (net, tok) = n.for_asset(&trade.asset).map_err(EgoDesktopError::InvalidInput)?;
    let chain = Outside::new(net, tok);
    let current = chain.read(trade).await.map_err(chain_err)?;
    let closes_accounts = matches!(net.family, Family::Solana | Family::Cardano);
    if current.state != chains::STATE_FUNDED {
        let target = match outcome {
            Outcome::Release => chains::STATE_RELEASED,
            Outcome::Refund => chains::STATE_REFUNDED,
        };
        if current.state == target || closes_accounts {
            return Ok(None);
        }
        return Err(EgoDesktopError::InvalidInput(format!(
            "The escrow on {} is already settled the other way",
            net.label
        )));
    }
    match (by, outcome) {
        (Role::Seller, Outcome::Release) => {
            chain.release(trade).await.map_err(chain_err)?;
            Ok(None)
        }
        (Role::Buyer, Outcome::Refund) => Ok(Some(chain.buyer_cancel(trade).await.map_err(EgoDesktopError::InvalidInput)?)),
        (Role::Arbiter, _) => {
            chain.resolve(trade, outcome == Outcome::Release).await.map_err(chain_err)?;
            Ok(None)
        }
        _ => Err(EgoDesktopError::PermissionDenied("That settlement is not yours to make".into())),
    }
}

fn settle_on_ego(
    state: &State<'_, AppState>,
    trade: &Trade,
    outcome: Outcome,
    by: Role,
    native_sig: Option<String>,
) -> Result<String, EgoDesktopError> {
    let kp = keypair(state)?;
    let message = market::settle_auth_message(&trade.id, outcome, by, native_sig.as_deref());
    let sig = kp.sign_ed25519(message.as_bytes());
    let body = SettleBody {
        trade_id: trade.id.clone(),
        outcome,
        by,
        pubkey: hex::encode(kp.ed25519_public_key().as_bytes()),
        signature: hex::encode(sig.as_bytes()),
        native_sig,
    };
    let tx = market::settle_tx(&body, trade, chrono::Utc::now().timestamp());
    crate::ledger::verify_incoming_tx(&tx).map_err(EgoDesktopError::InvalidInput)?;
    crate::mempool::get_mempool()
        .push(tx.clone())
        .map_err(|e| EgoDesktopError::WalletError(format!("The network refused it: {e}")))?;
    let hash = tx.hash.clone();
    tauri::async_runtime::spawn(async move {
        crate::p2p::broadcast_pending_tx(tx).await;
    });
    Ok(hash)
}

#[tauri::command]
pub async fn market_chat(trade_id: String) -> Result<Vec<ChatMsg>, EgoDesktopError> {
    let _g = CHAT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    Ok(load_chat().trades.get(trade_id.trim()).cloned().unwrap_or_default())
}

#[tauri::command]
pub async fn market_chat_read(trade_id: String) -> Result<(), EgoDesktopError> {
    let _g = CHAT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut store = load_chat();
    let mut changed = false;
    if let Some(list) = store.trades.get_mut(trade_id.trim()) {
        for m in list.iter_mut().filter(|m| !m.outgoing && !m.read) {
            m.read = true;
            changed = true;
        }
    }
    if changed {
        save_chat(&store)?;
    }
    Ok(())
}

#[tauri::command]
pub async fn market_chat_unread() -> Result<BTreeMap<String, usize>, EgoDesktopError> {
    let _g = CHAT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    Ok(load_chat().unread())
}

#[tauri::command]
pub async fn market_chat_send(
    trade_id: String,
    text: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<ChatMsg, EgoDesktopError> {
    let text = text.trim().to_string();
    if text.is_empty() || text.chars().count() > MAX_CHAT_TEXT {
        return Err(EgoDesktopError::InvalidInput(format!(
            "A message is 1 to {MAX_CHAT_TEXT} characters"
        )));
    }
    let trade = known_trade(&trade_id)?;
    let me = my_address()?;
    if role_label(&trade, &me).is_none() {
        return Err(EgoDesktopError::PermissionDenied("You are not part of this trade".into()));
    }
    let kp = keypair(&state)?;
    post_chat(&trade, &me, &kp, KIND_TEXT, text, &app).await
}

async fn post_chat(
    trade: &Trade,
    me: &str,
    kp: &KeyPair,
    kind: &str,
    text: String,
    app: &AppHandle,
) -> Result<ChatMsg, EgoDesktopError> {
    let me = me.to_string();
    let now = chrono::Utc::now().timestamp();
    let wire = sign_chat(
        kp,
        WireChat {
            trade_id: trade.id.clone(),
            from: me.clone(),
            kind: kind.into(),
            body: text.clone(),
            ts: now,
            id: fresh_id(),
            pubkey: String::new(),
            sig: String::new(),
        },
    );
    let recipients: Vec<(String, String)> = participants(&trade)
        .into_iter()
        .filter(|(a, k)| *a != me && !k.is_empty())
        .collect();
    let msg = ChatMsg {
        id: wire.id.clone(),
        from: me,
        kind: kind.to_string(),
        text,
        ts: now,
        outgoing: true,
        read: true,
        pending_to: recipients.iter().map(|(a, _)| a.clone()).collect(),
        attempts: 1,
        next_try: now + retry_gap(1),
        pubkey: wire.pubkey.clone(),
        sig: wire.sig.clone(),
    };
    {
        let _g = CHAT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut store = load_chat();
        store.add(&trade.id, msg.clone());
        save_chat(&store)?;
    }
    deliver(&wire, &recipients).await;
    let _ = app.emit_all("ego://market-chat", json!({ "trade_id": trade.id }));
    Ok(msg)
}

pub async fn receive_chat(c: WireChat, app: Option<&AppHandle>) {
    if !chat_is_authentic(&c) {
        return;
    }
    let Some(trade) = market::get_trade(&c.trade_id) else { return };
    let me = Ledger::load().address;
    if me.is_empty() || role_label(&trade, &me).is_none() || role_label(&trade, &c.from).is_none() || c.from == me {
        return;
    }
    match c.kind.as_str() {
        KIND_TEXT | KIND_PAYMENT => {
            if c.body.chars().count() > MAX_CHAT_TEXT {
                return;
            }
            let note = if c.kind == KIND_PAYMENT {
                if c.from != trade.buyer {
                    return;
                }
                match read_payment_note(&trade, &c.body) {
                    Some(n) => Some(n),
                    None => return,
                }
            } else {
                None
            };
            let fresh = {
                let _g = CHAT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
                let mut store = load_chat();
                let fresh = store.add(
                    &trade.id,
                    ChatMsg {
                        id: c.id.clone(),
                        from: c.from.clone(),
                        kind: c.kind.clone(),
                        text: c.body.clone(),
                        ts: c.ts,
                        outgoing: false,
                        read: false,
                        pending_to: Vec::new(),
                        attempts: 0,
                        next_try: 0,
                        pubkey: c.pubkey.clone(),
                        sig: c.sig.clone(),
                    },
                );
                if fresh {
                    let _ = save_chat(&store);
                }
                fresh
            };
            let Some(app) = app else { return };
            if let Some(kp) = app.state::<AppState>().get_keypair() {
                let ack = sign_chat(
                    &kp,
                    WireChat {
                        trade_id: trade.id.clone(),
                        from: me.clone(),
                        kind: KIND_ACK.into(),
                        body: c.id.clone(),
                        ts: chrono::Utc::now().timestamp(),
                        id: fresh_id(),
                        pubkey: String::new(),
                        sig: String::new(),
                    },
                );
                deliver(&ack, &[(c.from.clone(), c.pubkey.clone())]).await;
            }
            if fresh {
                let _ = app.emit_all("ego://market-chat", json!({ "trade_id": trade.id }));
                let who = role_label(&trade, &c.from).unwrap_or("trader");
                match note {
                    Some(n) => crate::commands::notifications::notify(
                        app,
                        "P2P trade: the buyer's payment details",
                        &format!("Paid from {}, reference {}", n.name, n.reference),
                    ),
                    None => {
                        let preview: String = c.body.chars().take(80).collect();
                        crate::commands::notifications::notify(app, &format!("P2P trade: message from the {who}"), &preview);
                    }
                }
            }
        }
        KIND_ACK => {
            let changed = {
                let _g = CHAT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
                let mut store = load_chat();
                let changed = store.acknowledge(&trade.id, &c.body, &c.from);
                if changed {
                    let _ = save_chat(&store);
                }
                changed
            };
            if changed {
                if let Some(app) = app {
                    let _ = app.emit_all("ego://market-chat", json!({ "trade_id": trade.id }));
                }
            }
        }
        _ => {}
    }
}

async fn retry_pending_chat() {
    let now = chrono::Utc::now().timestamp();
    let due: Vec<(String, ChatMsg)> = {
        let _g = CHAT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut store = load_chat();
        let mut due = Vec::new();
        for (trade_id, list) in store.trades.iter_mut() {
            for m in list.iter_mut() {
                if m.outgoing && !m.pending_to.is_empty() && m.next_try <= now && now - m.ts < RETRY_FOR_SECS {
                    m.attempts = m.attempts.saturating_add(1);
                    m.next_try = now + retry_gap(m.attempts);
                    due.push((trade_id.clone(), m.clone()));
                }
            }
        }
        if !due.is_empty() {
            let _ = save_chat(&store);
        }
        due
    };
    for (trade_id, m) in due {
        let Some(trade) = market::get_trade(&trade_id) else { continue };
        let to: Vec<(String, String)> = participants(&trade)
            .into_iter()
            .filter(|(a, k)| m.pending_to.contains(a) && !k.is_empty())
            .collect();
        let wire = WireChat {
            trade_id,
            from: m.from.clone(),
            kind: m.kind.clone(),
            body: m.text.clone(),
            ts: m.ts,
            id: m.id.clone(),
            pubkey: m.pubkey.clone(),
            sig: m.sig.clone(),
        };
        deliver(&wire, &to).await;
    }
}

fn seen_path() -> std::path::PathBuf {
    data_dir().join(SEEN_FILE)
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Seen {
    #[serde(default)]
    primed: bool,
    #[serde(default)]
    status: BTreeMap<String, String>,
}

pub fn status_notice(trade: &Trade, status: &str, me: &str, before: Option<&str>) -> Option<(String, String)> {
    let role = role_label(trade, me)?;
    let amount = fmt_egoc(trade.amount_micro);
    let fiat = format!("{:.2} {}", trade.fiat_micro as f64 / 1_000_000.0, trade.fiat);
    let n = |t: &str, b: String| Some((t.to_string(), b));
    match (role, status, before) {
        ("seller", "awaiting_lock", None) => n(
            "New P2P trade on your offer",
            format!("Someone wants {amount} for {fiat}. Fund the escrow within 30 minutes."),
        ),
        ("buyer", "locked", Some("awaiting_lock")) => n(
            "Escrow funded",
            format!("Pay the seller {fiat} with {} and mark the trade paid.", trade.method),
        ),
        ("buyer", "locked", None) if trade.maker == me => n(
            "New P2P trade on your offer",
            format!("A seller locked {amount}. Pay {fiat} with {} and mark the trade paid.", trade.method),
        ),
        ("seller", "paid", _) => n(
            "The buyer marked the trade paid",
            format!("Check that {fiat} arrived, then release {amount}."),
        ),
        ("seller", "payment_overdue", _) => n(
            "Payment window passed",
            format!("The buyer did not mark the trade paid. You can reclaim {amount}."),
        ),
        ("buyer", "expired", _) => n("Trade expired", "The seller did not fund the escrow in time.".to_string()),
        (_, "disputed", _) if role != "arbiter" => n(
            "Trade in dispute",
            "An arbiter will review the trade. Keep your payment proof ready.".to_string(),
        ),
        ("arbiter", "disputed", _) => n("New dispute to review", format!("{amount} for {fiat} is waiting for your ruling.")),
        ("buyer", "released", _) => n("EGOC received", format!("{amount} from your P2P trade is in your wallet.")),
        ("seller", "released", _) => n("Trade complete", format!("You released {amount}.")),
        ("seller", "refunded", _) => n("Escrow returned", format!("{} came back to your wallet.", fmt_egoc(trade.locked_micro))),
        ("buyer", "refunded", _) => n("Trade closed", "The escrow went back to the seller.".to_string()),
        (_, "cancelled", Some(_)) => n("Trade cancelled", format!("The trade for {amount} was cancelled.")),
        _ => None,
    }
}

async fn watch_trades(app: &AppHandle) {
    let Ok(me) = my_address() else { return };
    let mut views: Vec<Value> = Vec::new();
    for v in [market::trades_of_view(&me, 50, None), market::cases_of_view(&me, 50, None)] {
        if let Some(list) = v["trades"].as_array() {
            views.extend(list.iter().cloned());
        }
    }
    let mut notices: Vec<(String, String, String, String)> = Vec::new();
    {
        let _g = SEEN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut seen: Seen = std::fs::read(seen_path())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let mut changed = !seen.primed;
        for entry in &views {
            let Ok(trade) = serde_json::from_value::<Trade>(entry["trade"].clone()) else { continue };
            let status = entry["status"].as_str().unwrap_or_default().to_string();
            let before = seen.status.get(&trade.id).cloned();
            if before.as_deref() == Some(status.as_str()) {
                continue;
            }
            if seen.primed {
                if let Some((title, body)) = status_notice(&trade, &status, &me, before.as_deref()) {
                    notices.push((trade.id.clone(), status.clone(), title, body));
                }
            }
            seen.status.insert(trade.id.clone(), status);
            changed = true;
        }
        let current: std::collections::HashSet<String> = views
            .iter()
            .filter_map(|e| e["trade"]["id"].as_str().map(str::to_string))
            .collect();
        let before_len = seen.status.len();
        seen.status.retain(|id, _| current.contains(id));
        changed |= seen.status.len() != before_len;
        seen.primed = true;
        if changed {
            if let Ok(bytes) = serde_json::to_vec(&seen) {
                let _ = crate::utils::atomic_write(&seen_path(), &bytes);
            }
        }
    }
    for (trade_id, status, title, body) in notices {
        let _ = app.emit_all("ego://market-trade", json!({ "trade_id": trade_id, "status": status }));
        crate::commands::notifications::notify(app, &title, &body);
    }
}

async fn relay_buyer_cancels() {
    let Ok(me) = my_address() else { return };
    let view = market::trades_of_view(&me, 50, None);
    let Some(list) = view["trades"].as_array() else { return };
    let now = chrono::Utc::now().timestamp();
    let n = chains::networks();
    for entry in list {
        let Ok(trade) = serde_json::from_value::<Trade>(entry["trade"].clone()) else { continue };
        if trade.is_egoc()
            || trade.seller != me
            || trade.state != TradeState::Refunded
            || trade.closed_by != Some(Role::Buyer)
        {
            continue;
        }
        let Some(sig) = trade.native_sig.clone() else { continue };
        {
            let mut seen = RELAYED.lock().unwrap_or_else(|e| e.into_inner());
            if seen.get(&trade.id).is_some_and(|t| now - *t < RELAY_EVERY_SECS) {
                continue;
            }
            seen.insert(trade.id.clone(), now);
        }
        let Ok((net, tok)) = n.for_asset(&trade.asset) else { continue };
        let chain = Outside::new(net, tok);
        match chain.read(&trade).await {
            Ok(e) if e.state == chains::STATE_FUNDED => {}
            _ => continue,
        }
        match chain.relay_cancel(&trade, &sig).await {
            Ok(tx) => tracing::info!("[Market] returned the escrow of trade {} on {} ({tx})", trade.id, net.label),
            Err(e) => tracing::warn!("[Market] could not return the escrow of trade {} yet: {e}", trade.id),
        }
    }
}

pub async fn run_market_loop(app: AppHandle) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(WATCH_EVERY_SECS)).await;
        if !market::rule_active_at_tip() {
            continue;
        }
        retry_pending_chat().await;
        watch_trades(&app).await;
        relay_buyer_cancels().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp(tag: u8) -> KeyPair {
        KeyPair::from_bytes(&[tag; 32]).unwrap()
    }

    fn addr(k: &KeyPair) -> String {
        market::address_of(k.ed25519_public_key().as_bytes().try_into().unwrap())
    }

    fn wire(k: &KeyPair, body: &str) -> WireChat {
        sign_chat(
            k,
            WireChat {
                trade_id: format!("0x{}", "ab".repeat(32)),
                from: addr(k),
                kind: KIND_TEXT.into(),
                body: body.into(),
                ts: 1_800_000_000,
                id: "00ff".into(),
                pubkey: String::new(),
                sig: String::new(),
            },
        )
    }

    #[test]
    fn chat_messages_prove_who_wrote_them() {
        let alice = kp(1);
        let c = wire(&alice, "IBAN DE00 0000");
        assert!(chat_is_authentic(&c));

        let mut edited = c.clone();
        edited.body = "IBAN DE99 9999".into();
        assert!(!chat_is_authentic(&edited), "a relay cannot change the payment details");

        let mut impostor = c.clone();
        impostor.from = addr(&kp(2));
        assert!(!chat_is_authentic(&impostor), "a key only speaks for its own address");

        let mut other_trade = c;
        other_trade.trade_id = format!("0x{}", "cd".repeat(32));
        assert!(!chat_is_authentic(&other_trade), "a message cannot be replayed into another trade");
    }

    #[test]
    fn the_store_keeps_one_copy_and_tracks_who_still_owes_an_ack() {
        let mut store = ChatStore::default();
        let t = "0xtrade";
        let m = ChatMsg {
            id: "a".into(),
            from: "me".into(),
            kind: KIND_TEXT.into(),
            text: "hi".into(),
            ts: 2,
            outgoing: true,
            read: true,
            pending_to: vec!["buyer".into(), "arbiter".into()],
            attempts: 1,
            next_try: 0,
            pubkey: String::new(),
            sig: String::new(),
        };
        assert!(store.add(t, m.clone()));
        assert!(!store.add(t, m), "a retried message is stored once");
        assert!(store.acknowledge(t, "a", "buyer"));
        assert!(!store.acknowledge(t, "a", "buyer"));
        assert_eq!(store.trades[t][0].pending_to, vec!["arbiter".to_string()]);
        assert!(store.acknowledge(t, "a", "arbiter"));
        assert!(store.trades[t][0].pending_to.is_empty());

        let incoming = ChatMsg { id: "b".into(), outgoing: false, read: false, ts: 1, ..store.trades[t][0].clone() };
        store.add(t, incoming);
        assert_eq!(store.trades[t][0].id, "b", "messages sort by time");
        assert_eq!(store.unread().get(t), Some(&1));
    }

    #[test]
    fn a_long_conversation_keeps_the_newest_messages() {
        let mut store = ChatStore::default();
        for i in 0..(MAX_CHAT_PER_TRADE + 10) {
            store.add(
                "t",
                ChatMsg {
                    id: format!("{i:05}"),
                    from: "x".into(),
                    kind: KIND_TEXT.into(),
                    text: "m".into(),
                    ts: i as i64,
                    outgoing: false,
                    read: true,
                    pending_to: vec![],
                    attempts: 0,
                    next_try: 0,
                    pubkey: String::new(),
                    sig: String::new(),
                },
            );
        }
        let list = &store.trades["t"];
        assert_eq!(list.len(), MAX_CHAT_PER_TRADE);
        assert_eq!(list[0].id, "00010");
    }

    #[test]
    fn retries_back_off_to_a_ceiling() {
        assert_eq!(retry_gap(0), 20);
        assert_eq!(retry_gap(1), 40);
        assert_eq!(retry_gap(3), 160);
        assert_eq!(retry_gap(10), MAX_RETRY_GAP_SECS);
        assert_eq!(retry_gap(u32::MAX), MAX_RETRY_GAP_SECS);
    }

    #[test]
    fn market_linked_prices_follow_the_oracle_in_micro_units() {
        assert_eq!(margin_price_micro("USD", 0, 0.008), Ok(8_000));
        assert_eq!(margin_price_micro("USD", 250, 0.008), Ok(8_200));
        assert_eq!(margin_price_micro("USD", -500, 0.008), Ok(7_600));
        assert!(margin_price_micro("EUR", 0, 0.008).is_err());
        assert!(margin_price_micro("USD", 0, 0.0).is_err());
    }

    fn offer(side: Side, price: Price) -> market::Offer {
        market::Offer {
            id: format!("0x{}", "11".repeat(32)),
            maker: "egot1maker".into(),
            side,
            asset: "EGOC".into(),
            fiat: "USD".into(),
            price,
            min_micro: 1_000_000,
            max_micro: 1_000_000_000,
            methods: vec!["wise".into()],
            country: None,
            terms: String::new(),
            payment_window_secs: 1_800,
            created_height: 1,
            created_at: 0,
            expires_at: i64::MAX,
            closed_height: None,
            maker_key: String::new(),
            payout_address: None,
        }
    }

    #[test]
    fn a_quote_shows_what_each_side_pays_and_gets() {
        let q = quote(&offer(Side::Sell, Price::Fixed(8_000)), 100_000_000, 1.0).unwrap();
        assert_eq!(q["fiat_micro"], 800_000);
        assert_eq!(q["taker_locks_micro"], 0);
        assert_eq!(q["buyer_receives_micro"], 100_000_000);
        assert_eq!(q["taker_side"], "buy");

        let q = quote(&offer(Side::Buy, Price::MarginBps(100)), 100_000_000, 0.008).unwrap();
        assert_eq!(q["price_micro"], 8_080);
        assert_eq!(q["taker_locks_micro"], 100_000_000);
        assert_eq!(q["buyer_receives_micro"], 99_000_000);
        assert_eq!(q["taker_side"], "sell");

        assert!(quote(&offer(Side::Sell, Price::Fixed(8_000)), 999, 1.0).is_err());
    }

    #[test]
    fn the_desktop_signs_market_operations_the_chain_accepts() {
        let k = kp(5);
        let from = addr(&k);
        let body = TradeRef { trade_id: format!("0x{}", "ee".repeat(32)) };
        let tx = build_op_tx(&k, &from, market::TX_PAID, serde_json::to_string(&body).unwrap(), 0, 7, 1_000, 1_800_000_000).unwrap();
        assert!(crate::ledger::verify_confirmed_tx_sig(&tx).is_ok());
        assert_eq!(tx.memo.as_deref(), market::op_memo(market::TX_PAID, &tx.call_args).as_deref());
        let reader = market::MemReader::default();
        let mut planner = market::Planner::new(&reader, 1, 1_800_000_000);
        let refusal = planner.admit(&tx).unwrap_err();
        assert!(matches!(refusal, market::Refusal::Unknown(_)), "shape passes, only the trade is missing: {refusal}");
        assert!(build_op_tx(&k, &from, "transfer", "{}".into(), 0, 1, 1_000, 0).is_err());
    }

    #[test]
    #[ignore]
    fn desktop_operations_ride_the_real_block_pipeline() {
        if std::env::var("EGO_MARKET_E2E").is_err() {
            return;
        }
        let _g = crate::shielded::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("EGO_MARKET_HEIGHT", "0");
        let db = crate::chain_db::get_db().lock().unwrap_or_else(|e| e.into_inner());
        let seller = kp(21);
        let buyer = kp(22);
        let (sa, ba) = (addr(&seller), addr(&buyer));
        let cf_bal = db.cf_handle(crate::chain_db::CF_BALANCES).unwrap();
        db.put_cf(cf_bal, sa.as_bytes(), crate::chain_db::u64_le(200_000_000)).unwrap();
        db.put_cf(cf_bal, ba.as_bytes(), crate::chain_db::u64_le(5_000_000)).unwrap();

        let now = chrono::Utc::now().timestamp();
        let tip = crate::chain_db::local_chain_height();
        for i in 1..=12u64 {
            let h = tip + i;
            let b = crate::ledger::LedgerBlock {
                height: h,
                hash: format!("{:0>64x}", h),
                prev_hash: format!("{:0>64x}", h - 1),
                miner: "egot1miner".into(),
                timestamp: now - 7_200 + i as i64,
                ..crate::ledger::LedgerBlock::default()
            };
            crate::chain_db::append_peer_block_with_votes(&b, &[], 0);
        }
        let mine = |txs: Vec<LedgerTx>| -> Vec<String> {
            let (block, stamped) = crate::chain_db::build_block_proposal(&txs, "egot1miner", "", 0);
            crate::chain_db::append_peer_block_with_votes(&block, &stamped, 0);
            stamped.into_iter().map(|t| t.hash).collect()
        };
        let mut nonces: BTreeMap<String, u64> = BTreeMap::new();
        let mut op = |k: &KeyPair, tx_type: &str, body: Value, amount: u64| -> LedgerTx {
            let from = addr(k);
            let n = nonces.entry(from.clone()).or_insert(0);
            *n += 1;
            let tx = build_op_tx(k, &from, tx_type, body.to_string(), amount, *n, network_fee(false), now).unwrap();
            crate::ledger::verify_incoming_tx(&tx).unwrap_or_else(|e| panic!("{tx_type} refused: {e}"));
            tx
        };

        let offer = op(&seller, market::TX_OFFER, json!({
            "side": "sell", "asset": "EGOC", "fiat": "USD", "price": { "fixed": 8_000 },
            "min_micro": 1_000_000, "max_micro": 100_000_000, "methods": ["wise"],
            "terms": "Wise only", "payment_window_secs": 900
        }), 0);
        assert!(mine(vec![offer.clone()]).contains(&offer.hash));
        assert!(market::get_offer(&offer.hash).is_some());

        let q = quote(&market::get_offer(&offer.hash).unwrap(), 50_000_000, 0.008).unwrap();
        let open = op(&buyer, market::TX_TRADE_OPEN, json!({
            "offer_id": offer.hash, "amount_micro": 50_000_000, "price_micro": q["price_micro"],
            "fiat_micro": q["fiat_micro"], "method": "wise"
        }), 0);
        assert!(mine(vec![open.clone()]).contains(&open.hash));
        let trade = market::get_trade(&open.hash).unwrap();
        assert_eq!(trade.state, TradeState::AwaitingLock);
        assert_eq!(trade.buyer_key, hex::encode(buyer.ed25519_public_key().as_bytes()));

        let lock = op(&seller, market::TX_LOCK, json!({ "trade_id": open.hash }), trade.locked_micro);
        assert!(mine(vec![lock.clone()]).contains(&lock.hash));
        assert_eq!(crate::chain_db::balance_of(MARKET_ESCROW_ADDR), 50_500_000);

        for _ in 0..12 {
            mine(Vec::new());
        }
        let trade = market::get_trade(&open.hash).unwrap();
        let auth = |k: &KeyPair, outcome: Outcome, by: Role| {
            let sig = k.sign_ed25519(market::settle_message(&trade.id, outcome, by).as_bytes());
            market::settle_tx(
                &SettleBody {
                    trade_id: trade.id.clone(),
                    outcome,
                    by,
                    pubkey: hex::encode(k.ed25519_public_key().as_bytes()),
                    signature: hex::encode(sig.as_bytes()),
                    native_sig: None,
                },
                &trade,
                now,
            )
        };
        let reclaim = auth(&seller, Outcome::Refund, Role::Seller);
        crate::ledger::verify_incoming_tx(&reclaim).expect("the window has passed, so the seller may reclaim");
        let paid = op(&buyer, market::TX_PAID, json!({ "trade_id": open.hash }), 0);
        let included = mine(vec![reclaim.clone(), paid.clone()]);
        assert!(included.contains(&paid.hash), "a late payment mark wins the tie");
        assert!(!included.contains(&reclaim.hash));
        assert!(
            crate::mempool::get_mempool().peek_all().iter().any(|t| t.hash == reclaim.hash),
            "the held-back settlement goes back to the mempool instead of vanishing"
        );
        assert_eq!(market::get_trade(&open.hash).unwrap().state, TradeState::Paid);
        assert!(crate::ledger::verify_incoming_tx(&reclaim).is_err(), "and it is no longer valid");
        crate::mempool::get_mempool().remove_txs(&[reclaim.hash.clone()]);

        let release = auth(&seller, Outcome::Release, Role::Seller);
        assert!(mine(vec![release.clone()]).contains(&release.hash));
        assert_eq!(market::get_trade(&open.hash).unwrap().state, TradeState::Released);
        assert_eq!(crate::chain_db::balance_of(MARKET_ESCROW_ADDR), 0);
        assert_eq!(crate::chain_db::balance_of(&ba), 5_000_000 - open.fee_uegoc - paid.fee_uegoc + 50_000_000);
        assert_eq!(market::get_profile(&sa).completed, 1);
        std::env::remove_var("EGO_MARKET_HEIGHT");
    }

    #[test]
    fn notices_speak_to_the_person_who_has_to_act() {
        let t = Trade {
            id: "0xt".into(),
            offer_id: "0xo".into(),
            maker: "egot1seller".into(),
            taker: "egot1buyer".into(),
            seller: "egot1seller".into(),
            buyer: "egot1buyer".into(),
            seller_key: String::new(),
            buyer_key: String::new(),
            asset: market::EGOC.into(),
            amount_micro: 5_000_000,
            maker_fee_micro: 50_000,
            locked_micro: 5_050_000,
            fiat: "USD".into(),
            fiat_micro: 40_000,
            price_micro: 8_000,
            method: "wise".into(),
            payment_window_secs: 1_800,
            state: TradeState::Locked,
            opened_height: 1,
            opened_at: 0,
            locked_at: Some(0),
            paid_at: None,
            disputed_at: None,
            disputed_by: None,
            dispute_reason: String::new(),
            arbiter: Some("egot1judge".into()),
            closed_at: None,
            closed_height: None,
            closed_by: None,
            settle_tx: None,
            buyer_payout: None,
            arbiter_payout: None,
            escrow: None,
            native_sig: None,
        };
        let (title, _) = status_notice(&t, "awaiting_lock", "egot1seller", None).unwrap();
        assert!(title.contains("New P2P trade"));
        let (_, body) = status_notice(&t, "locked", "egot1buyer", Some("awaiting_lock")).unwrap();
        assert!(body.contains("0.04 USD") && body.contains("wise"));
        assert!(status_notice(&t, "locked", "egot1seller", Some("awaiting_lock")).is_none());
        assert!(status_notice(&t, "paid", "egot1seller", Some("locked")).unwrap().1.contains("release"));
        assert!(status_notice(&t, "disputed", "egot1judge", Some("paid")).unwrap().0.contains("review"));
        assert!(status_notice(&t, "paid", "egot1stranger", None).is_none());
    }

    #[test]
    fn a_payment_note_names_the_payer_and_binds_the_trade_reference() {
        let t: Trade = serde_json::from_value(json!({
            "id": format!("0x{}", "ab".repeat(32)), "offer_id": "0xo", "maker": "s", "taker": "b", "seller": "s",
            "buyer": "b", "amount_micro": 1, "maker_fee_micro": 0, "locked_micro": 1, "fiat": "EUR", "fiat_micro": 1,
            "price_micro": 1, "method": "sepa", "payment_window_secs": 900, "state": "paid", "opened_height": 1, "opened_at": 1,
        }))
        .unwrap();
        assert_eq!(clean_payer_name("  Jane   van  Doe "), Some("Jane van Doe".into()));
        assert_eq!(clean_payer_name("   "), None);
        assert_eq!(clean_payer_name(&"x".repeat(71)), None);
        assert_eq!(clean_payer_name("Jane\u{0007}Doe"), None);
        let body = payment_note_body(&t, " Jane  Doe ").unwrap();
        let note = read_payment_note(&t, &body).unwrap();
        assert_eq!(note.name, "Jane Doe");
        assert_eq!(note.reference, market::payment_reference(&t.id));
        let other: Trade = Trade { id: format!("0x{}", "cd".repeat(32)), ..t.clone() };
        assert!(read_payment_note(&other, &body).is_none(), "a note for another trade is refused");
        assert!(read_payment_note(&t, r#"{"name":"Jane","reference":"EGO-AAAAAAAA"}"#).is_none());
        let padded = format!(r#"{{"name":" Jane","reference":"{}"}}"#, note.reference);
        assert!(read_payment_note(&t, &padded).is_none(), "names arrive already cleaned");
        let extra = format!(r#"{{"name":"Jane","reference":"{}","iban":"x"}}"#, note.reference);
        assert!(read_payment_note(&t, &extra).is_none());
    }
}
