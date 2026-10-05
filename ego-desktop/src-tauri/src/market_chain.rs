use crate::chain_db::{self, decode, encode, read_u64_le, CF_BALANCES, CF_META};
use crate::ledger::LedgerTx;
use rocksdb::{Direction, IteratorMode, WriteBatch, DB};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};

pub const MARKET_ESCROW_ADDR: &str = "egot1marketescrow000000000000000000000000000";
pub const MARKET_CHAIN_ID: u8 = 1;
pub const ACTIVATION_HEIGHT: Option<u64> = None;

pub const TX_OFFER: &str = "market_offer";
pub const TX_OFFER_CLOSE: &str = "market_offer_close";
pub const TX_TRADE_OPEN: &str = "market_trade_open";
pub const TX_LOCK: &str = "market_lock";
pub const TX_TRADE_CANCEL: &str = "market_trade_cancel";
pub const TX_PAID: &str = "market_paid";
pub const TX_DISPUTE: &str = "market_dispute";
pub const TX_FEEDBACK: &str = "market_feedback";
pub const TX_SETTLE: &str = "market_settle";
pub const TX_ARBITER: &str = "market_arbiter";

pub const SIGNED_OPS: [&str; 9] = [
    TX_OFFER,
    TX_OFFER_CLOSE,
    TX_TRADE_OPEN,
    TX_LOCK,
    TX_TRADE_CANCEL,
    TX_PAID,
    TX_DISPUTE,
    TX_FEEDBACK,
    TX_ARBITER,
];

pub const MAKER_FEE_BPS: u64 = 100;
pub const MIN_TRADE_UEGOC: u64 = 1_000_000;
pub const MAX_TRADE_UEGOC: u64 = 10_000_000_000_000;
pub const MAX_OPEN_OFFERS_PER_MAKER: usize = 20;
pub const MAX_PENDING_TRADES_PER_TAKER: usize = 5;
pub const MAX_METHODS: usize = 8;
pub const MAX_METHOD_LEN: usize = 32;
pub const MAX_TERMS_BYTES: usize = 1_000;
pub const MAX_NOTE_BYTES: usize = 280;
pub const MAX_BODY_BYTES: usize = 4_096;
pub const MIN_PAYMENT_WINDOW_SECS: i64 = 15 * 60;
pub const MAX_PAYMENT_WINDOW_SECS: i64 = 24 * 60 * 60;
pub const ACCEPT_WINDOW_SECS: i64 = 30 * 60;
pub const BUYER_DISPUTE_DELAY_SECS: i64 = 60 * 60;
pub const OFFER_TTL_SECS: i64 = 30 * 24 * 60 * 60;
pub const FEEDBACK_WINDOW_SECS: i64 = 30 * 24 * 60 * 60;
pub const MAX_MARGIN_BPS: i32 = 5_000;
pub const MAX_PRICE_MICRO: u64 = 1_000_000_000_000;
pub const MAX_TRADE_MICRO: u64 = 1_000_000_000_000_000;
pub const EGOC: &str = "EGOC";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Ego,
    Evm,
    Tron,
    Solana,
    Cardano,
}

impl Family {
    pub fn as_str(self) -> &'static str {
        match self {
            Family::Ego => "ego",
            Family::Evm => "evm",
            Family::Tron => "tron",
            Family::Solana => "solana",
            Family::Cardano => "cardano",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AssetInfo {
    pub id: &'static str,
    pub symbol: &'static str,
    pub network: &'static str,
    pub family: Family,
    pub min_micro: u64,
}

const fn asset(id: &'static str, symbol: &'static str, network: &'static str, family: Family, min_micro: u64) -> AssetInfo {
    AssetInfo { id, symbol, network, family, min_micro }
}

pub const ASSETS: &[AssetInfo] = &[
    asset("EGOC", "EGOC", "ego", Family::Ego, MIN_TRADE_UEGOC),
    asset("USDT-TRC20", "USDT", "tron", Family::Tron, 1),
    asset("TRX", "TRX", "tron", Family::Tron, 1),
    asset("USDT-ERC20", "USDT", "ethereum", Family::Evm, 1),
    asset("USDC-ERC20", "USDC", "ethereum", Family::Evm, 1),
    asset("ETH", "ETH", "ethereum", Family::Evm, 1),
    asset("USDT-BEP20", "USDT", "bsc", Family::Evm, 1),
    asset("USDC-BEP20", "USDC", "bsc", Family::Evm, 1),
    asset("BNB", "BNB", "bsc", Family::Evm, 1),
    asset("USDT-POLYGON", "USDT", "polygon", Family::Evm, 1),
    asset("USDC-POLYGON", "USDC", "polygon", Family::Evm, 1),
    asset("POL", "POL", "polygon", Family::Evm, 1),
    asset("USDC-SPL", "USDC", "solana", Family::Solana, 1),
    asset("USDT-SPL", "USDT", "solana", Family::Solana, 1),
    asset("SOL", "SOL", "solana", Family::Solana, 10_000),
    asset("ADA", "ADA", "cardano", Family::Cardano, 10_000_000),
];

pub const CARDANO_NETWORK_ID: u8 = 0;

pub fn asset_info(id: &str) -> Option<&'static AssetInfo> {
    ASSETS.iter().find(|a| a.id == id)
}

pub fn is_egoc(asset: &str) -> bool {
    asset == EGOC
}

pub fn trade_limits(asset: &str) -> (u64, u64) {
    if is_egoc(asset) {
        (MIN_TRADE_UEGOC, MAX_TRADE_UEGOC)
    } else {
        (asset_info(asset).map(|a| a.min_micro).unwrap_or(1), MAX_TRADE_MICRO)
    }
}

fn base58_len(s: &str, len: usize) -> bool {
    s.len() <= 90 && bs58::decode(s).into_vec().is_ok_and(|v| v.len() == len)
}

fn cardano_address(s: &str) -> Option<Vec<u8>> {
    crate::escrow::cardano::parse_address(s)
        .ok()
        .filter(|raw| crate::escrow::cardano::network_of(raw) == CARDANO_NETWORK_ID)
}

pub fn valid_chain_address(family: Family, s: &str) -> bool {
    match family {
        Family::Ego => false,
        Family::Evm => s.len() == 42 && s.starts_with("0x") && s[2..].bytes().all(|b| b.is_ascii_hexdigit()),
        Family::Tron => {
            s.len() == 34
                && s.starts_with('T')
                && s.bytes().all(|b| b.is_ascii_alphanumeric() && !matches!(b, b'0' | b'O' | b'I' | b'l'))
        }
        Family::Solana => base58_len(s, 32),
        Family::Cardano => cardano_address(s).is_some_and(|raw| crate::escrow::cardano::payment_key_hash(&raw).is_some()),
    }
}

pub fn valid_escrow_contract(family: Family, s: &str) -> bool {
    match family {
        Family::Cardano => cardano_address(s).is_some_and(|raw| crate::escrow::cardano::payment_script_hash(&raw).is_some()),
        other => valid_chain_address(other, s),
    }
}

pub fn valid_chain_tx(family: Family, s: &str) -> bool {
    let digits = match family {
        Family::Evm => s.strip_prefix("0x"),
        Family::Tron | Family::Cardano => Some(s),
        Family::Solana => return base58_len(s, 64),
        Family::Ego => None,
    };
    digits.is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

pub fn native_sig_len(family: Family) -> Option<usize> {
    match family {
        Family::Evm | Family::Tron => Some(65),
        Family::Solana => Some(64),
        Family::Cardano => Some(96),
        Family::Ego => None,
    }
}

pub fn verify_native_cancel(trade: &Trade, sig_hex: &str) -> Result<(), String> {
    let info = asset_info(&trade.asset).ok_or("the trade's asset is not listed")?;
    let len = native_sig_len(info.family).ok_or("an EGOC settlement carries no outside signature")?;
    let sig = hex::decode(sig_hex)
        .ok()
        .filter(|v| v.len() == len)
        .ok_or_else(|| format!("the outside signature for {} is {len} hex bytes", info.network))?;
    if !matches!(info.family, Family::Solana | Family::Cardano) {
        return Ok(());
    }
    let escrow = trade.escrow.as_ref().ok_or("the trade names no outside escrow")?;
    let payout = trade.buyer_payout.as_deref().ok_or("the trade names no buyer payout address")?;
    let trade_id: [u8; 32] = hex::decode(trade.id.trim_start_matches("0x"))
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("the trade id is not 32 bytes")?;
    if info.family == Family::Solana {
        use crate::escrow::solana as sol;
        let program = sol::parse_key(&escrow.contract)?;
        let seller = sol::parse_key(&escrow.funder)?;
        let buyer = sol::parse_key(payout)?;
        let (escrow_at, _) = sol::escrow_address(&program, &trade_id, &seller);
        let signature: [u8; 64] = sig.try_into().map_err(|_| "bad signature length")?;
        if !sol::verify_buyer_signature(&program, &escrow_at, &buyer, sol::ACTION_CANCEL, &signature) {
            return Err("the outside signature is not the buyer's cancel for this Solana escrow".into());
        }
        return Ok(());
    }
    use crate::escrow::cardano as ada;
    let script = cardano_address(&escrow.contract)
        .and_then(|raw| ada::payment_script_hash(&raw))
        .ok_or("the escrow is not a Cardano script address")?;
    let buyer = cardano_address(payout)
        .and_then(|raw| ada::payment_key_hash(&raw))
        .ok_or("the buyer payout is not a Cardano key address")?;
    let vkey: [u8; 32] = sig[..32].try_into().map_err(|_| "bad key length")?;
    let signature: [u8; 64] = sig[32..].try_into().map_err(|_| "bad signature length")?;
    if !ada::verify_auth(&vkey, &signature, &buyer, &script, &trade_id, ada::ACTION_CANCEL) {
        return Err("the outside signature is not the buyer's cancel for this Cardano escrow".into());
    }
    Ok(())
}

fn egoc_id() -> String {
    EGOC.to_string()
}

const CHAIN_TIME_WINDOW: u64 = 11;
const OWNER_SCAN_LIMIT: usize = 512;
const PENDING_SCAN_LIMIT: usize = 64;

const ARBITER_SCHEDULE: &[(u64, &[&str])] =
    &[(0, &["egot1ypxxgvy0y5g8gynm3y2tkegzggs64rcts5dq7sl8"])];

const BODY_DOMAIN: &[u8] = b"ego/market/body/v1:";
const SETTLE_DOMAIN: &[u8] = b"ego/market/settle/v1:";
const AUTH_DOMAIN: &str = "ego/market/auth/v1";
const ARBITER_DOMAIN: &[u8] = b"ego/market/arbiter/v1:";
const PAYREF_DOMAIN: &[u8] = b"ego/market/payref/v1:";
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const OFFER_PREFIX: &str = "market:o:";
const TRADE_PREFIX: &str = "market:t:";
const PROFILE_PREFIX: &str = "market:p:";
const FEEDBACK_PREFIX: &str = "market:fb:";
const PAIR_PREFIX: &str = "market:pair:";
const BOOK_PREFIX: &str = "market:ob:";
const MAKER_OFFERS_PREFIX: &str = "market:mo:";
const USER_TRADES_PREFIX: &str = "market:ut:";
const ARBITER_CASES_PREFIX: &str = "market:arb:";
const ARBITER_ADDR_PREFIX: &str = "market:arbaddr:";
const LEADERBOARD_PREFIX: &[u8] = b"market:lb:";
const UNDO_PREFIX: &[u8] = b"market:undo:";
const ESCROW_KEY: &[u8] = b"market:escrow";

pub fn rule_active(height: u64) -> bool {
    if let Ok(v) = std::env::var("EGO_MARKET_HEIGHT") {
        if let Ok(h) = v.trim().parse::<u64>() {
            return height >= h;
        }
    }
    ACTIVATION_HEIGHT.is_some_and(|h| height >= h)
}

pub fn rule_active_at_tip() -> bool {
    rule_active(chain_db::local_chain_height().saturating_add(1))
}

pub fn arbiters_at(height: u64) -> &'static [&'static str] {
    ARBITER_SCHEDULE
        .iter()
        .rev()
        .find(|(from, _)| height >= *from)
        .map(|(_, list)| *list)
        .unwrap_or(&[])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Side {
    Sell,
    Buy,
}

impl Side {
    pub fn as_str(self) -> &'static str {
        match self {
            Side::Sell => "sell",
            Side::Buy => "buy",
        }
    }

    pub fn parse(s: &str) -> Option<Side> {
        match s {
            "sell" => Some(Side::Sell),
            "buy" => Some(Side::Buy),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Price {
    Fixed(u64),
    MarginBps(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Buyer,
    Seller,
    Arbiter,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Buyer => "buyer",
            Role::Seller => "seller",
            Role::Arbiter => "arbiter",
        }
    }

    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "buyer" => Some(Role::Buyer),
            "seller" => Some(Role::Seller),
            "arbiter" => Some(Role::Arbiter),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Release,
    Refund,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Release => "release",
            Outcome::Refund => "refund",
        }
    }

    pub fn past(self) -> &'static str {
        match self {
            Outcome::Release => "released",
            Outcome::Refund => "refunded",
        }
    }

    pub fn parse(s: &str) -> Option<Outcome> {
        match s {
            "release" => Some(Outcome::Release),
            "refund" => Some(Outcome::Refund),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Rating {
    Positive,
    Neutral,
    Negative,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TradeState {
    AwaitingLock,
    Locked,
    Paid,
    Disputed,
    Cancelled,
    Released,
    Refunded,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferBody {
    pub side: Side,
    pub asset: String,
    pub fiat: String,
    pub price: Price,
    pub min_micro: u64,
    pub max_micro: u64,
    pub methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default)]
    pub terms: String,
    pub payment_window_secs: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payout_address: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferRef {
    pub offer_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TradeOpenBody {
    pub offer_id: String,
    pub amount_micro: u64,
    pub price_micro: u64,
    pub fiat_micro: u64,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payout_address: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TradeRef {
    pub trade_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscrowRef {
    pub contract: String,
    pub funder: String,
    pub tx: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockBody {
    pub trade_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escrow: Option<EscrowRef>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArbiterBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tron: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ada: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArbiterAddresses {
    #[serde(default)]
    pub evm: Option<String>,
    #[serde(default)]
    pub tron: Option<String>,
    #[serde(default)]
    pub sol: Option<String>,
    #[serde(default)]
    pub ada: Option<String>,
    #[serde(default)]
    pub height: u64,
}

impl ArbiterAddresses {
    pub fn for_family(&self, family: Family) -> Option<&str> {
        match family {
            Family::Evm => self.evm.as_deref(),
            Family::Tron => self.tron.as_deref(),
            Family::Solana => self.sol.as_deref(),
            Family::Cardano => self.ada.as_deref(),
            Family::Ego => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisputeBody {
    pub trade_id: String,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackBody {
    pub trade_id: String,
    pub rating: Rating,
    #[serde(default)]
    pub comment: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettleBody {
    pub trade_id: String,
    pub outcome: Outcome,
    pub by: Role,
    pub pubkey: String,
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_sig: Option<String>,
}

impl SettleBody {
    pub fn canonical_json(&self) -> String {
        serde_json::to_string(self).expect("a struct of strings")
    }

    pub fn tx_hash(&self) -> String {
        let mut m = SETTLE_DOMAIN.to_vec();
        m.extend_from_slice(self.canonical_json().as_bytes());
        format!("0x{}", ego_core::hash_data(&m).to_hex())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Offer {
    pub id: String,
    pub maker: String,
    pub side: Side,
    pub asset: String,
    pub fiat: String,
    pub price: Price,
    pub min_micro: u64,
    pub max_micro: u64,
    pub methods: Vec<String>,
    #[serde(default)]
    pub country: Option<String>,
    pub terms: String,
    pub payment_window_secs: i64,
    pub created_height: u64,
    pub created_at: i64,
    pub expires_at: i64,
    #[serde(default)]
    pub closed_height: Option<u64>,
    #[serde(default)]
    pub maker_key: String,
    #[serde(default)]
    pub payout_address: Option<String>,
}

impl Offer {
    pub fn is_open(&self, now: i64) -> bool {
        self.closed_height.is_none() && now < self.expires_at
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Trade {
    pub id: String,
    pub offer_id: String,
    pub maker: String,
    pub taker: String,
    pub seller: String,
    pub buyer: String,
    #[serde(default)]
    pub seller_key: String,
    #[serde(default)]
    pub buyer_key: String,
    #[serde(default = "egoc_id")]
    pub asset: String,
    pub amount_micro: u64,
    pub maker_fee_micro: u64,
    pub locked_micro: u64,
    pub fiat: String,
    pub fiat_micro: u64,
    pub price_micro: u64,
    pub method: String,
    pub payment_window_secs: i64,
    pub state: TradeState,
    pub opened_height: u64,
    pub opened_at: i64,
    #[serde(default)]
    pub locked_at: Option<i64>,
    #[serde(default)]
    pub paid_at: Option<i64>,
    #[serde(default)]
    pub disputed_at: Option<i64>,
    #[serde(default)]
    pub disputed_by: Option<Role>,
    #[serde(default)]
    pub dispute_reason: String,
    #[serde(default)]
    pub arbiter: Option<String>,
    #[serde(default)]
    pub closed_at: Option<i64>,
    #[serde(default)]
    pub closed_height: Option<u64>,
    #[serde(default)]
    pub closed_by: Option<Role>,
    #[serde(default)]
    pub settle_tx: Option<String>,
    #[serde(default)]
    pub buyer_payout: Option<String>,
    #[serde(default)]
    pub arbiter_payout: Option<String>,
    #[serde(default)]
    pub escrow: Option<EscrowRef>,
    #[serde(default)]
    pub native_sig: Option<String>,
}

impl Trade {
    pub fn is_egoc(&self) -> bool {
        is_egoc(&self.asset)
    }

    pub fn settle_amount(&self) -> u64 {
        if self.is_egoc() {
            self.locked_micro
        } else {
            0
        }
    }

    pub fn settle_fee(&self, outcome: Outcome) -> u64 {
        if self.is_egoc() {
            self.payout_fee(outcome)
        } else {
            0
        }
    }

    pub fn payout_to(&self, outcome: Outcome) -> &str {
        match outcome {
            Outcome::Release => &self.buyer,
            Outcome::Refund => &self.seller,
        }
    }

    pub fn payout_fee(&self, outcome: Outcome) -> u64 {
        match outcome {
            Outcome::Release => self.maker_fee_micro,
            Outcome::Refund => 0,
        }
    }

    pub fn role_of(&self, addr: &str) -> Option<Role> {
        if addr == self.buyer {
            Some(Role::Buyer)
        } else if addr == self.seller {
            Some(Role::Seller)
        } else {
            None
        }
    }

    pub fn counterparty(&self, role: Role) -> &str {
        match role {
            Role::Buyer => &self.seller,
            _ => &self.buyer,
        }
    }

    pub fn lock_expires_at(&self) -> i64 {
        self.opened_at.saturating_add(ACCEPT_WINDOW_SECS)
    }

    pub fn payment_due_at(&self) -> Option<i64> {
        self.locked_at.map(|t| t.saturating_add(self.payment_window_secs))
    }

    pub fn buyer_may_dispute_at(&self) -> Option<i64> {
        self.paid_at.map(|t| t.saturating_add(BUYER_DISPUTE_DELAY_SECS))
    }

    pub fn is_lock_expired(&self, now: i64) -> bool {
        self.state == TradeState::AwaitingLock && now >= self.lock_expires_at()
    }

    pub fn status(&self, now: i64) -> &'static str {
        match self.state {
            TradeState::AwaitingLock if self.is_lock_expired(now) => "expired",
            TradeState::AwaitingLock => "awaiting_lock",
            TradeState::Locked if self.payment_due_at().is_some_and(|d| now >= d) => "payment_overdue",
            TradeState::Locked => "locked",
            TradeState::Paid => "paid",
            TradeState::Disputed => "disputed",
            TradeState::Cancelled => "cancelled",
            TradeState::Released => "released",
            TradeState::Refunded => "refunded",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Feedback {
    pub trade_id: String,
    pub from: String,
    pub about: String,
    pub rating: Rating,
    pub comment: String,
    pub height: u64,
    pub at: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    #[serde(default)]
    pub completed: u64,
    #[serde(default)]
    pub as_buyer: u64,
    #[serde(default)]
    pub as_seller: u64,
    #[serde(default)]
    pub volume_uegoc: u64,
    #[serde(default)]
    pub partners: u64,
    #[serde(default)]
    pub cancelled: u64,
    #[serde(default)]
    pub timed_out: u64,
    #[serde(default)]
    pub disputes_opened: u64,
    #[serde(default)]
    pub disputes_won: u64,
    #[serde(default)]
    pub disputes_lost: u64,
    #[serde(default)]
    pub positive: u64,
    #[serde(default)]
    pub neutral: u64,
    #[serde(default)]
    pub negative: u64,
    #[serde(default)]
    pub first_trade_at: Option<i64>,
    #[serde(default)]
    pub last_trade_at: Option<i64>,
}

impl Profile {
    fn absorb(&mut self, d: &Profile) {
        self.completed = self.completed.saturating_add(d.completed);
        self.as_buyer = self.as_buyer.saturating_add(d.as_buyer);
        self.as_seller = self.as_seller.saturating_add(d.as_seller);
        self.volume_uegoc = self.volume_uegoc.saturating_add(d.volume_uegoc);
        self.partners = self.partners.saturating_add(d.partners);
        self.cancelled = self.cancelled.saturating_add(d.cancelled);
        self.timed_out = self.timed_out.saturating_add(d.timed_out);
        self.disputes_opened = self.disputes_opened.saturating_add(d.disputes_opened);
        self.disputes_won = self.disputes_won.saturating_add(d.disputes_won);
        self.disputes_lost = self.disputes_lost.saturating_add(d.disputes_lost);
        self.positive = self.positive.saturating_add(d.positive);
        self.neutral = self.neutral.saturating_add(d.neutral);
        self.negative = self.negative.saturating_add(d.negative);
        self.first_trade_at = match (self.first_trade_at, d.first_trade_at) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        self.last_trade_at = match (self.last_trade_at, d.last_trade_at) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
    }

    fn traded(volume: u64, at: i64, as_buyer: bool) -> Profile {
        Profile {
            completed: 1,
            as_buyer: as_buyer as u64,
            as_seller: (!as_buyer) as u64,
            volume_uegoc: volume,
            first_trade_at: Some(at),
            last_trade_at: Some(at),
            ..Profile::default()
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowTotals {
    pub held_uegoc: u64,
    pub active_trades: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Invalid(String),
    Unknown(String),
    Conflict(String),
}

impl Refusal {
    pub fn is_transient(&self) -> bool {
        !matches!(self, Refusal::Invalid(_))
    }

    pub fn reason(&self) -> &str {
        match self {
            Refusal::Invalid(s) | Refusal::Unknown(s) | Refusal::Conflict(s) => s,
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}

fn invalid<T>(msg: impl Into<String>) -> Result<T, Refusal> {
    Err(Refusal::Invalid(msg.into()))
}

pub fn is_escrow_deposit(tx: &LedgerTx) -> bool {
    tx.to == MARKET_ESCROW_ADDR
}

pub fn is_settle(tx: &LedgerTx) -> bool {
    tx.from == MARKET_ESCROW_ADDR
}

pub fn touches_market(tx: &LedgerTx) -> bool {
    is_escrow_deposit(tx) || is_settle(tx)
}

pub fn body_hash(call_args: &str) -> String {
    let mut m = BODY_DOMAIN.to_vec();
    m.extend_from_slice(call_args.as_bytes());
    ego_core::hash_data(&m).to_hex()
}

pub fn op_memo(tx_type: &str, call_args: &str) -> Option<String> {
    let op = tx_type.strip_prefix("market_")?;
    if !SIGNED_OPS.contains(&tx_type) {
        return None;
    }
    Some(format!("market:{op}:{}", body_hash(call_args)))
}

pub fn settle_message(trade_id: &str, outcome: Outcome, by: Role) -> String {
    format!(
        "{AUTH_DOMAIN}:{MARKET_CHAIN_ID}:{trade_id}:{}:{}",
        outcome.as_str(),
        by.as_str()
    )
}

pub fn settle_auth_message(trade_id: &str, outcome: Outcome, by: Role, native_sig: Option<&str>) -> String {
    match native_sig {
        Some(sig) => format!("{}:{sig}", settle_message(trade_id, outcome, by)),
        None => settle_message(trade_id, outcome, by),
    }
}

pub fn payment_reference(trade_id: &str) -> String {
    let mut m = PAYREF_DOMAIN.to_vec();
    m.extend_from_slice(trade_id.trim().to_ascii_lowercase().as_bytes());
    let digest = hex::decode(ego_core::hash_data(&m).to_hex()).unwrap_or_default();
    let v = digest.iter().take(5).fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
    let code: String = (0..8).rev().map(|i| CROCKFORD[((v >> (i * 5)) & 31) as usize] as char).collect();
    format!("EGO-{code}")
}

pub fn maker_fee(amount_micro: u64) -> u64 {
    ((amount_micro as u128 * MAKER_FEE_BPS as u128).div_ceil(10_000)) as u64
}

pub const CARDANO_MIN_FEE_MICRO: u64 = 1_000_000;

pub fn trade_fee(asset: &str, amount_micro: u64) -> u64 {
    let fee = maker_fee(amount_micro);
    let cardano = asset_info(asset).is_some_and(|a| a.family == Family::Cardano);
    if cardano && fee < CARDANO_MIN_FEE_MICRO {
        0
    } else {
        fee
    }
}

pub fn fiat_for(amount_micro: u64, price_micro: u64) -> Option<u64> {
    let v = (amount_micro as u128 * price_micro as u128 + 500_000) / 1_000_000;
    u64::try_from(v).ok()
}

pub(crate) fn address_of(pubkey: &[u8; 32]) -> String {
    ego_core::EgoAddress::from_public_key_bytes(pubkey, MARKET_CHAIN_ID as u32, ego_core::AddressType::EOA)
        .to_bech32("egot")
        .unwrap_or_default()
}

fn verify_auth(body: &SettleBody) -> Result<String, String> {
    use ed25519_dalek::{Signature, VerifyingKey};
    let pk: [u8; 32] = hex::decode(&body.pubkey)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("the settlement key is not 32 hex bytes")?;
    let sig: [u8; 64] = hex::decode(&body.signature)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("the settlement signature is not 64 hex bytes")?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|_| "the settlement key is not a valid Ed25519 key")?;
    vk.verify_strict(
        settle_auth_message(&body.trade_id, body.outcome, body.by, body.native_sig.as_deref()).as_bytes(),
        &Signature::from_bytes(&sig),
    )
    .map_err(|_| "the settlement signature does not verify".to_string())?;
    Ok(address_of(&pk))
}

fn valid_id(id: &str) -> bool {
    id.len() == 66
        && id.starts_with("0x")
        && id[2..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_fiat(f: &str) -> bool {
    f.len() == 3 && f.bytes().all(|b| b.is_ascii_uppercase())
}

fn valid_country(c: &str) -> bool {
    c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase())
}

fn valid_method(m: &str) -> bool {
    !m.is_empty()
        && m.len() <= MAX_METHOD_LEN
        && m.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

fn valid_text(s: &str, max: usize) -> bool {
    s.len() <= max && !s.chars().any(|c| c.is_control() && c != '\n')
}

fn be8(v: u64) -> [u8; 8] {
    v.to_be_bytes()
}

fn offer_key(id: &str) -> Vec<u8> {
    format!("{OFFER_PREFIX}{id}").into_bytes()
}

fn trade_key(id: &str) -> Vec<u8> {
    format!("{TRADE_PREFIX}{id}").into_bytes()
}

fn profile_key(addr: &str) -> Vec<u8> {
    format!("{PROFILE_PREFIX}{addr}").into_bytes()
}

fn feedback_key(trade_id: &str, role: Role) -> Vec<u8> {
    format!("{FEEDBACK_PREFIX}{trade_id}:{}", role.as_str()).into_bytes()
}

fn pair_key(a: &str, b: &str) -> Vec<u8> {
    let (x, y) = if a <= b { (a, b) } else { (b, a) };
    format!("{PAIR_PREFIX}{x}:{y}").into_bytes()
}

fn book_prefix(asset: &str, fiat: &str, side: Side) -> Vec<u8> {
    format!("{BOOK_PREFIX}{asset}:{fiat}:{}:", side.as_str()).into_bytes()
}

fn book_key(asset: &str, fiat: &str, side: Side, height: u64, id: &str) -> Vec<u8> {
    let mut k = book_prefix(asset, fiat, side);
    k.extend_from_slice(&be8(height));
    k.extend_from_slice(id.as_bytes());
    k
}

fn maker_offers_prefix(maker: &str) -> Vec<u8> {
    format!("{MAKER_OFFERS_PREFIX}{maker}:").into_bytes()
}

fn maker_offer_key(maker: &str, id: &str) -> Vec<u8> {
    let mut k = maker_offers_prefix(maker);
    k.extend_from_slice(id.as_bytes());
    k
}

fn user_trades_prefix(addr: &str) -> Vec<u8> {
    format!("{USER_TRADES_PREFIX}{addr}:").into_bytes()
}

fn user_trade_key(addr: &str, height: u64, id: &str) -> Vec<u8> {
    let mut k = user_trades_prefix(addr);
    k.extend_from_slice(&be8(height));
    k.extend_from_slice(id.as_bytes());
    k
}

fn arbiter_addr_key(arbiter: &str) -> Vec<u8> {
    format!("{ARBITER_ADDR_PREFIX}{arbiter}").into_bytes()
}

fn arbiter_cases_prefix(arbiter: &str) -> Vec<u8> {
    format!("{ARBITER_CASES_PREFIX}{arbiter}:").into_bytes()
}

fn arbiter_case_key(arbiter: &str, height: u64, id: &str) -> Vec<u8> {
    let mut k = arbiter_cases_prefix(arbiter);
    k.extend_from_slice(&be8(height));
    k.extend_from_slice(id.as_bytes());
    k
}

fn leaderboard_key(completed: u64, addr: &str) -> Vec<u8> {
    let mut k = LEADERBOARD_PREFIX.to_vec();
    k.extend_from_slice(&be8(completed));
    k.extend_from_slice(addr.as_bytes());
    k
}

fn undo_key(height: u64) -> Vec<u8> {
    let mut k = UNDO_PREFIX.to_vec();
    k.extend_from_slice(&be8(height));
    k
}

fn id_after(key: &[u8], prefix_len: usize) -> Option<String> {
    String::from_utf8(key.get(prefix_len..)?.to_vec()).ok()
}

fn id_after_height(key: &[u8], prefix_len: usize) -> Option<String> {
    id_after(key, prefix_len + 8)
}

fn prefix_ceiling(prefix: &[u8]) -> Vec<u8> {
    let mut c = prefix.to_vec();
    c.extend_from_slice(&[0xFF; 64]);
    c
}

pub trait Reader {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
    fn scan(&self, prefix: &[u8], newest_first: bool, limit: usize) -> Vec<(Vec<u8>, Vec<u8>)>;
}

pub struct DbReader<'a>(pub &'a DB);

impl Reader for DbReader<'_> {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let cf = self.0.cf_handle(CF_META)?;
        self.0.get_cf(cf, key).ok().flatten()
    }

    fn scan(&self, prefix: &[u8], newest_first: bool, limit: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        let Some(cf) = self.0.cf_handle(CF_META) else { return Vec::new() };
        let ceiling = prefix_ceiling(prefix);
        let mode = if newest_first {
            IteratorMode::From(&ceiling, Direction::Reverse)
        } else {
            IteratorMode::From(prefix, Direction::Forward)
        };
        let mut out = Vec::new();
        for item in self.0.iterator_cf(cf, mode) {
            if out.len() >= limit {
                break;
            }
            let Ok((k, v)) = item else { break };
            if !k.starts_with(prefix) {
                break;
            }
            out.push((k.to_vec(), v.to_vec()));
        }
        out
    }
}

#[cfg(test)]
#[derive(Debug, Default, Clone)]
pub struct MemReader(pub BTreeMap<Vec<u8>, Vec<u8>>);

#[cfg(test)]
impl MemReader {
    pub fn apply(&mut self, plan: &Plan) {
        for (k, v) in &plan.writes {
            match v {
                Some(v) => {
                    self.0.insert(k.clone(), v.clone());
                }
                None => {
                    self.0.remove(k);
                }
            }
        }
    }
}

#[cfg(test)]
impl Reader for MemReader {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.0.get(key).cloned()
    }

    fn scan(&self, prefix: &[u8], newest_first: bool, limit: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        let ceiling = prefix_ceiling(prefix);
        let range = self.0.range(prefix.to_vec()..ceiling);
        let pick = |(k, v): (&Vec<u8>, &Vec<u8>)| (k.clone(), v.clone());
        if newest_first {
            range.rev().take(limit).map(pick).collect()
        } else {
            range.take(limit).map(pick).collect()
        }
    }
}

fn read<T: for<'de> Deserialize<'de>>(reader: &(impl Reader + ?Sized), key: &[u8]) -> Option<T> {
    reader.get(key).and_then(|v| decode::<T>(&v))
}

#[derive(Debug, Default, Clone)]
pub struct Plan {
    pub writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    pub rejected: Vec<String>,
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty() && self.rejected.is_empty()
    }

    pub fn takes_effect(&self, hash: &str) -> bool {
        !self.rejected.iter().any(|h| h == hash)
    }
}

#[derive(Default)]
struct Effects {
    touches: Vec<String>,
    writes: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    profiles: Vec<(String, Profile)>,
    new_offer: Option<(String, usize)>,
    new_pending: Option<(String, usize)>,
    pairs: Vec<(Vec<u8>, String, String)>,
    escrow_in: u64,
    escrow_out: u64,
    opened: u64,
    closed: u64,
}

pub struct Planner<'r, R: Reader + ?Sized> {
    reader: &'r R,
    pub height: u64,
    pub now: i64,
    pub arbiters: Vec<String>,
    touched: HashSet<String>,
    offers_by_maker: HashMap<String, usize>,
    pending_by_taker: HashMap<String, usize>,
    pairs: HashSet<Vec<u8>>,
    writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    profiles: BTreeMap<String, Profile>,
    escrow_in: u64,
    escrow_out: u64,
    opened: u64,
    closed: u64,
    admitted: Vec<String>,
}

impl<'r, R: Reader + ?Sized> Planner<'r, R> {
    pub fn new(reader: &'r R, height: u64, now: i64) -> Self {
        Self {
            reader,
            height,
            now,
            arbiters: arbiters_at(height).iter().map(|a| a.to_string()).collect(),
            touched: HashSet::new(),
            offers_by_maker: HashMap::new(),
            pending_by_taker: HashMap::new(),
            pairs: HashSet::new(),
            writes: BTreeMap::new(),
            profiles: BTreeMap::new(),
            escrow_in: 0,
            escrow_out: 0,
            opened: 0,
            closed: 0,
            admitted: Vec::new(),
        }
    }

    pub fn was_admitted(&self, tx: &LedgerTx) -> bool {
        self.admitted.iter().any(|h| *h == tx.hash)
    }

    pub fn admit(&mut self, tx: &LedgerTx) -> Result<(), Refusal> {
        let fx = if is_settle(tx) {
            self.settle_effects(tx)?
        } else if is_escrow_deposit(tx) {
            self.signed_effects(tx)?
        } else {
            return Ok(());
        };
        if let Some(t) = fx.touches.iter().find(|t| self.touched.contains(*t)) {
            return Err(Refusal::Conflict(format!(
                "{t} is already changed by another transaction in this block"
            )));
        }
        if let Some((maker, existing)) = &fx.new_offer {
            let in_block = self.offers_by_maker.get(maker).copied().unwrap_or(0);
            if existing + in_block >= MAX_OPEN_OFFERS_PER_MAKER {
                return Err(Refusal::Conflict(format!(
                    "{maker} would pass {MAX_OPEN_OFFERS_PER_MAKER} open offers in this block"
                )));
            }
        }
        if let Some((taker, existing)) = &fx.new_pending {
            let in_block = self.pending_by_taker.get(taker).copied().unwrap_or(0);
            if existing + in_block >= MAX_PENDING_TRADES_PER_TAKER {
                return Err(Refusal::Conflict(format!(
                    "{taker} would pass {MAX_PENDING_TRADES_PER_TAKER} trades waiting for a seller in this block"
                )));
            }
        }
        self.merge(fx);
        self.admitted.push(tx.hash.clone());
        Ok(())
    }

    fn merge(&mut self, fx: Effects) {
        self.touched.extend(fx.touches);
        for (k, v) in fx.writes {
            self.writes.insert(k, v);
        }
        for (addr, d) in fx.profiles {
            self.profiles.entry(addr).or_default().absorb(&d);
        }
        if let Some((maker, _)) = fx.new_offer {
            *self.offers_by_maker.entry(maker).or_insert(0) += 1;
        }
        if let Some((taker, _)) = fx.new_pending {
            *self.pending_by_taker.entry(taker).or_insert(0) += 1;
        }
        for (key, a, b) in fx.pairs {
            if self.pairs.insert(key.clone()) {
                self.writes.insert(key, Some(self.height.to_le_bytes().to_vec()));
                let one = Profile { partners: 1, ..Profile::default() };
                self.profiles.entry(a).or_default().absorb(&one);
                self.profiles.entry(b).or_default().absorb(&one);
            }
        }
        self.escrow_in = self.escrow_in.saturating_add(fx.escrow_in);
        self.escrow_out = self.escrow_out.saturating_add(fx.escrow_out);
        self.opened = self.opened.saturating_add(fx.opened);
        self.closed = self.closed.saturating_add(fx.closed);
    }

    pub fn finish(self) -> Plan {
        let mut writes = self.writes;
        for (addr, delta) in &self.profiles {
            let before: Profile = read(self.reader, &profile_key(addr)).unwrap_or_default();
            let mut after = before.clone();
            after.absorb(delta);
            if after == before {
                continue;
            }
            writes.insert(profile_key(addr), Some(encode(&after)));
            if before.completed != after.completed {
                if before.completed > 0 {
                    writes.insert(leaderboard_key(before.completed, addr), None);
                }
                if after.completed > 0 {
                    writes.insert(leaderboard_key(after.completed, addr), Some(Vec::new()));
                }
            }
        }
        if self.escrow_in > 0 || self.escrow_out > 0 || self.opened > 0 || self.closed > 0 {
            let mut totals: EscrowTotals = read(self.reader, ESCROW_KEY).unwrap_or_default();
            totals.held_uegoc = totals
                .held_uegoc
                .saturating_add(self.escrow_in)
                .saturating_sub(self.escrow_out);
            totals.active_trades = totals
                .active_trades
                .saturating_add(self.opened)
                .saturating_sub(self.closed);
            writes.insert(ESCROW_KEY.to_vec(), Some(encode(&totals)));
        }
        Plan { writes, rejected: Vec::new() }
    }

    fn offer(&self, id: &str) -> Option<Offer> {
        read(self.reader, &offer_key(id))
    }

    fn trade(&self, id: &str) -> Option<Trade> {
        read(self.reader, &trade_key(id))
    }

    fn known_trade(&self, id: &str) -> Result<Trade, Refusal> {
        if !valid_id(id) {
            return invalid(format!("{id:.80} is not a trade id"));
        }
        self.trade(id)
            .ok_or_else(|| Refusal::Unknown(format!("trade {id} is not on this chain")))
    }

    fn open_offer_count(&self, maker: &str) -> usize {
        let prefix = maker_offers_prefix(maker);
        self.reader
            .scan(&prefix, false, OWNER_SCAN_LIMIT)
            .iter()
            .filter_map(|(k, _)| id_after(k, prefix.len()))
            .filter_map(|id| self.offer(&id))
            .filter(|o| o.is_open(self.now))
            .count()
    }

    fn pending_count(&self, taker: &str) -> usize {
        let prefix = user_trades_prefix(taker);
        self.reader
            .scan(&prefix, true, PENDING_SCAN_LIMIT)
            .iter()
            .filter_map(|(k, _)| id_after_height(k, prefix.len()))
            .filter_map(|id| self.trade(&id))
            .filter(|t| {
                t.taker == taker && t.state == TradeState::AwaitingLock && !t.is_lock_expired(self.now)
            })
            .count()
    }

    fn assign_arbiter(&self, trade: &Trade) -> Option<(String, Option<String>)> {
        let family = asset_info(&trade.asset).map(|a| a.family).unwrap_or(Family::Ego);
        let candidates: Vec<(String, Option<String>)> = self
            .arbiters
            .iter()
            .filter(|a| **a != trade.buyer && **a != trade.seller)
            .filter_map(|a| {
                if family == Family::Ego {
                    return Some((a.clone(), None));
                }
                let record: ArbiterAddresses = read(self.reader, &arbiter_addr_key(a))?;
                let payout = record.for_family(family)?.to_string();
                Some((a.clone(), Some(payout)))
            })
            .collect();
        if candidates.is_empty() {
            return None;
        }
        let mut m = ARBITER_DOMAIN.to_vec();
        m.extend_from_slice(trade.id.as_bytes());
        let digest = ego_core::hash_data(&m);
        let mut first = [0u8; 8];
        first.copy_from_slice(&digest.as_bytes()[..8]);
        let pick = (u64::from_le_bytes(first) % candidates.len() as u64) as usize;
        Some(candidates[pick].clone())
    }

    fn signed_effects(&self, tx: &LedgerTx) -> Result<Effects, Refusal> {
        check_signed_shape(tx).map_err(Refusal::Invalid)?;
        match tx.tx_type.as_str() {
            TX_OFFER => self.offer_effects(tx),
            TX_OFFER_CLOSE => self.offer_close_effects(tx),
            TX_TRADE_OPEN => self.trade_open_effects(tx),
            TX_LOCK => self.lock_effects(tx),
            TX_TRADE_CANCEL => self.cancel_effects(tx),
            TX_PAID => self.paid_effects(tx),
            TX_DISPUTE => self.dispute_effects(tx),
            TX_FEEDBACK => self.feedback_effects(tx),
            TX_ARBITER => self.arbiter_effects(tx),
            other => invalid(format!("{other:.40} is not a market operation")),
        }
    }

    fn offer_effects(&self, tx: &LedgerTx) -> Result<Effects, Refusal> {
        let b: OfferBody = body(tx)?;
        validate_offer_body(&b).map_err(Refusal::Invalid)?;
        if tx.amount != 0 {
            return invalid("publishing an offer moves no funds");
        }
        let id = tx.hash.clone();
        if self.reader.get(&offer_key(&id)).is_some() {
            return invalid(format!("offer {id} already exists"));
        }
        let maker = tx.from.clone();
        let existing = self.open_offer_count(&maker);
        if existing >= MAX_OPEN_OFFERS_PER_MAKER {
            return invalid(format!(
                "{maker} already has {MAX_OPEN_OFFERS_PER_MAKER} open offers; close one first"
            ));
        }
        let offer = Offer {
            id: id.clone(),
            maker: maker.clone(),
            side: b.side,
            asset: b.asset,
            fiat: b.fiat,
            price: b.price,
            min_micro: b.min_micro,
            max_micro: b.max_micro,
            methods: b.methods,
            country: b.country,
            terms: b.terms,
            payment_window_secs: b.payment_window_secs,
            created_height: self.height,
            created_at: self.now,
            expires_at: self.now.saturating_add(OFFER_TTL_SECS),
            closed_height: None,
            maker_key: tx.public_key_ed25519.clone(),
            payout_address: b.payout_address,
        };
        let mut fx = Effects::default();
        fx.touches.push(format!("offer:{id}"));
        fx.writes.push((book_key(&offer.asset, &offer.fiat, offer.side, self.height, &id), Some(Vec::new())));
        fx.writes.push((maker_offer_key(&maker, &id), Some(Vec::new())));
        fx.writes.push((offer_key(&id), Some(encode(&offer))));
        fx.new_offer = Some((maker, existing));
        Ok(fx)
    }

    fn offer_close_effects(&self, tx: &LedgerTx) -> Result<Effects, Refusal> {
        let b: OfferRef = body(tx)?;
        if !valid_id(&b.offer_id) {
            return invalid("that is not an offer id");
        }
        if tx.amount != 0 {
            return invalid("closing an offer moves no funds");
        }
        let offer = self
            .offer(&b.offer_id)
            .ok_or_else(|| Refusal::Unknown(format!("offer {} is not on this chain", b.offer_id)))?;
        if offer.maker != tx.from {
            return invalid("only the maker can close an offer");
        }
        if offer.closed_height.is_some() {
            return invalid(format!("offer {} is already closed", offer.id));
        }
        let mut closed = offer.clone();
        closed.closed_height = Some(self.height);
        let mut fx = Effects::default();
        fx.touches.push(format!("offer:{}", offer.id));
        fx.writes.push((offer_key(&offer.id), Some(encode(&closed))));
        fx.writes.push((maker_offer_key(&offer.maker, &offer.id), None));
        fx.writes.push((book_key(&offer.asset, &offer.fiat, offer.side, offer.created_height, &offer.id), None));
        Ok(fx)
    }

    fn trade_open_effects(&self, tx: &LedgerTx) -> Result<Effects, Refusal> {
        let b: TradeOpenBody = body(tx)?;
        if !valid_id(&b.offer_id) {
            return invalid("that is not an offer id");
        }
        if !valid_method(&b.method) {
            return invalid("the payment method is not a method id");
        }
        let offer = self
            .offer(&b.offer_id)
            .ok_or_else(|| Refusal::Unknown(format!("offer {} is not on this chain", b.offer_id)))?;
        if !offer.is_open(self.now) {
            return invalid(format!("offer {} is closed or has expired", offer.id));
        }
        if tx.from == offer.maker {
            return invalid("a maker cannot take their own offer");
        }
        let info = asset_info(&offer.asset)
            .ok_or_else(|| Refusal::Invalid(format!("{:.16} is not traded on this market", offer.asset)))?;
        let (lo, hi) = trade_limits(&offer.asset);
        if b.amount_micro < offer.min_micro.max(lo) || b.amount_micro > offer.max_micro.min(hi) {
            return invalid(format!(
                "{} is outside the offer's {}..={} limits",
                b.amount_micro, offer.min_micro, offer.max_micro
            ));
        }
        if !offer.methods.iter().any(|m| *m == b.method) {
            return invalid(format!("the offer does not accept {}", b.method));
        }
        match offer.price {
            Price::Fixed(p) if b.price_micro != p => {
                return invalid(format!("the offer's price is {p}, not {}", b.price_micro));
            }
            Price::MarginBps(_) if b.price_micro == 0 || b.price_micro > MAX_PRICE_MICRO => {
                return invalid("the quoted price is out of range");
            }
            _ => {}
        }
        let fiat = fiat_for(b.amount_micro, b.price_micro).unwrap_or(0);
        if fiat == 0 || fiat != b.fiat_micro {
            return invalid(format!(
                "{} at {} comes to {fiat}, not {}",
                b.amount_micro, b.price_micro, b.fiat_micro
            ));
        }
        let fee = trade_fee(&offer.asset, b.amount_micro);
        let id = tx.hash.clone();
        if self.reader.get(&trade_key(&id)).is_some() {
            return invalid(format!("trade {id} already exists"));
        }
        let egoc = info.family == Family::Ego;
        let taker_key = tx.public_key_ed25519.clone();
        let (seller, buyer, seller_key, buyer_key, locked) = match offer.side {
            Side::Sell => (
                offer.maker.clone(),
                tx.from.clone(),
                offer.maker_key.clone(),
                taker_key,
                b.amount_micro.saturating_add(fee),
            ),
            Side::Buy => (
                tx.from.clone(),
                offer.maker.clone(),
                taker_key,
                offer.maker_key.clone(),
                b.amount_micro,
            ),
        };
        let buyer_payout = if egoc {
            if b.payout_address.is_some() {
                return invalid("EGOC trades pay out on the Ego chain, so they take no payout address");
            }
            None
        } else {
            let address = match offer.side {
                Side::Sell => b.payout_address.clone(),
                Side::Buy => {
                    if b.payout_address.is_some() {
                        return invalid("the buyer of this offer already named their payout address");
                    }
                    offer.payout_address.clone()
                }
            };
            let address = address.ok_or_else(|| {
                Refusal::Invalid(format!("the buyer must say where to receive {} on {}", info.symbol, info.network))
            })?;
            if !valid_chain_address(info.family, &address) {
                return invalid(format!("{address:.64} is not a {} address", info.network));
            }
            Some(address)
        };
        let state = if egoc && offer.side == Side::Buy {
            TradeState::Locked
        } else {
            TradeState::AwaitingLock
        };
        let locked_at = (state == TradeState::Locked).then_some(self.now);
        let expected_amount = if state == TradeState::Locked { locked } else { 0 };
        if tx.amount != expected_amount {
            return invalid(format!(
                "opening this trade must move {expected_amount} uEGOC into escrow, not {}",
                tx.amount
            ));
        }
        let mut trade = Trade {
            id: id.clone(),
            offer_id: offer.id.clone(),
            maker: offer.maker.clone(),
            taker: tx.from.clone(),
            seller: seller.clone(),
            buyer: buyer.clone(),
            seller_key,
            buyer_key,
            asset: offer.asset.clone(),
            amount_micro: b.amount_micro,
            maker_fee_micro: fee,
            locked_micro: locked,
            fiat: offer.fiat.clone(),
            fiat_micro: b.fiat_micro,
            price_micro: b.price_micro,
            method: b.method,
            payment_window_secs: offer.payment_window_secs,
            state,
            opened_height: self.height,
            opened_at: self.now,
            locked_at,
            paid_at: None,
            disputed_at: None,
            disputed_by: None,
            dispute_reason: String::new(),
            arbiter: None,
            closed_at: None,
            closed_height: None,
            closed_by: None,
            settle_tx: None,
            buyer_payout,
            arbiter_payout: None,
            escrow: None,
            native_sig: None,
        };
        match self.assign_arbiter(&trade) {
            Some((arbiter, payout)) => {
                trade.arbiter = Some(arbiter);
                trade.arbiter_payout = payout;
            }
            None if !egoc => {
                return invalid(format!(
                    "no arbiter has published a {} address yet, so {} trades cannot open",
                    info.family.as_str(),
                    offer.asset
                ));
            }
            None => {}
        }
        let mut fx = Effects::default();
        fx.touches.push(format!("trade:{id}"));
        fx.writes.push((trade_key(&id), Some(encode(&trade))));
        fx.writes.push((user_trade_key(&seller, self.height, &id), Some(Vec::new())));
        fx.writes.push((user_trade_key(&buyer, self.height, &id), Some(Vec::new())));
        if state == TradeState::Locked {
            fx.escrow_in = locked;
            fx.opened = 1;
        } else {
            let existing = self.pending_count(&tx.from);
            if existing >= MAX_PENDING_TRADES_PER_TAKER {
                return invalid(format!(
                    "{} already has {MAX_PENDING_TRADES_PER_TAKER} trades waiting for a seller",
                    tx.from
                ));
            }
            fx.new_pending = Some((tx.from.clone(), existing));
        }
        Ok(fx)
    }

    fn lock_effects(&self, tx: &LedgerTx) -> Result<Effects, Refusal> {
        let b: LockBody = body(tx)?;
        let trade = self.known_trade(&b.trade_id)?;
        if trade.state != TradeState::AwaitingLock {
            return invalid(format!("trade {} is not waiting for the seller", trade.id));
        }
        if trade.is_lock_expired(self.now) {
            return invalid(format!("the time to fund trade {} has passed", trade.id));
        }
        if tx.from != trade.seller {
            return invalid("only the seller funds the escrow");
        }
        let mut next = trade.clone();
        let mut fx = Effects::default();
        if trade.is_egoc() {
            if b.escrow.is_some() {
                return invalid("EGOC is escrowed on the Ego chain itself, so no outside escrow applies");
            }
            if tx.amount != trade.locked_micro {
                return invalid(format!(
                    "trade {} needs exactly {} uEGOC in escrow, not {}",
                    trade.id, trade.locked_micro, tx.amount
                ));
            }
            fx.escrow_in = trade.locked_micro;
            fx.opened = 1;
        } else {
            let info = asset_info(&trade.asset)
                .ok_or_else(|| Refusal::Invalid(format!("{:.16} is not traded on this market", trade.asset)))?;
            if tx.amount != 0 {
                return invalid(format!(
                    "the escrow for {} lives on {}, so this lock moves no EGOC",
                    trade.asset, info.network
                ));
            }
            let reference = b.escrow.ok_or_else(|| {
                Refusal::Invalid("say where the escrow was funded: contract, funder and transaction".to_string())
            })?;
            if !valid_escrow_contract(info.family, &reference.contract)
                || !valid_chain_address(info.family, &reference.funder)
                || !valid_chain_tx(info.family, &reference.tx)
            {
                return invalid(format!(
                    "the escrow reference is not a {} contract, address and transaction",
                    info.network
                ));
            }
            next.escrow = Some(reference);
        }
        next.state = TradeState::Locked;
        next.locked_at = Some(self.now);
        fx.touches.push(format!("trade:{}", trade.id));
        fx.writes.push((trade_key(&trade.id), Some(encode(&next))));
        Ok(fx)
    }

    fn cancel_effects(&self, tx: &LedgerTx) -> Result<Effects, Refusal> {
        let b: TradeRef = body(tx)?;
        let trade = self.known_trade(&b.trade_id)?;
        if trade.state != TradeState::AwaitingLock {
            return invalid(format!(
                "trade {} already holds funds; it ends by release or refund",
                trade.id
            ));
        }
        let role = trade.role_of(&tx.from).ok_or_else(|| {
            Refusal::Invalid("only the buyer or the seller can cancel".to_string())
        })?;
        if tx.amount != 0 {
            return invalid("cancelling moves no funds");
        }
        let mut next = trade.clone();
        next.state = TradeState::Cancelled;
        next.closed_at = Some(self.now);
        next.closed_height = Some(self.height);
        next.closed_by = Some(role);
        let mut fx = Effects::default();
        fx.touches.push(format!("trade:{}", trade.id));
        fx.writes.push((trade_key(&trade.id), Some(encode(&next))));
        Ok(fx)
    }

    fn paid_effects(&self, tx: &LedgerTx) -> Result<Effects, Refusal> {
        let b: TradeRef = body(tx)?;
        let trade = self.known_trade(&b.trade_id)?;
        if trade.state != TradeState::Locked {
            return invalid(format!("trade {} is not waiting for payment", trade.id));
        }
        if tx.from != trade.buyer {
            return invalid("only the buyer marks a trade paid");
        }
        if tx.amount != 0 {
            return invalid("marking a trade paid moves no funds");
        }
        let mut next = trade.clone();
        next.state = TradeState::Paid;
        next.paid_at = Some(self.now);
        let mut fx = Effects::default();
        fx.touches.push(format!("trade:{}", trade.id));
        fx.writes.push((trade_key(&trade.id), Some(encode(&next))));
        Ok(fx)
    }

    fn dispute_effects(&self, tx: &LedgerTx) -> Result<Effects, Refusal> {
        let b: DisputeBody = body(tx)?;
        if !valid_text(&b.reason, MAX_NOTE_BYTES) {
            return invalid(format!("a dispute reason is at most {MAX_NOTE_BYTES} bytes of text"));
        }
        let trade = self.known_trade(&b.trade_id)?;
        let role = trade.role_of(&tx.from).ok_or_else(|| {
            Refusal::Invalid("only the buyer or the seller can open a dispute".to_string())
        })?;
        let no_show = !trade.is_egoc()
            && trade.state == TradeState::Locked
            && role == Role::Seller
            && trade.payment_due_at().is_some_and(|due| self.now >= due);
        if trade.state != TradeState::Paid && !no_show {
            return invalid(format!(
                "trade {} can be disputed only after the buyer marks it paid",
                trade.id
            ));
        }
        if tx.amount != 0 {
            return invalid("opening a dispute moves no funds");
        }
        if role == Role::Buyer {
            let allowed = trade.buyer_may_dispute_at().unwrap_or(i64::MAX);
            if self.now < allowed {
                return invalid(format!(
                    "the seller has until {allowed} to release before the buyer can dispute"
                ));
            }
        }
        let arbiter = match &trade.arbiter {
            Some(a) => a.clone(),
            None => self
                .assign_arbiter(&trade)
                .map(|(a, _)| a)
                .ok_or_else(|| Refusal::Invalid("no impartial arbiter is available".to_string()))?,
        };
        let mut next = trade.clone();
        next.state = TradeState::Disputed;
        next.disputed_at = Some(self.now);
        next.disputed_by = Some(role);
        next.dispute_reason = b.reason;
        next.arbiter = Some(arbiter.clone());
        let mut fx = Effects::default();
        fx.touches.push(format!("trade:{}", trade.id));
        fx.writes.push((trade_key(&trade.id), Some(encode(&next))));
        fx.writes.push((arbiter_case_key(&arbiter, self.height, &trade.id), Some(Vec::new())));
        fx.profiles.push((
            tx.from.clone(),
            Profile { disputes_opened: 1, ..Profile::default() },
        ));
        Ok(fx)
    }

    fn feedback_effects(&self, tx: &LedgerTx) -> Result<Effects, Refusal> {
        let b: FeedbackBody = body(tx)?;
        if !valid_text(&b.comment, MAX_NOTE_BYTES) {
            return invalid(format!("feedback is at most {MAX_NOTE_BYTES} bytes of text"));
        }
        let trade = self.known_trade(&b.trade_id)?;
        if !matches!(trade.state, TradeState::Released | TradeState::Refunded) {
            return invalid(format!("trade {} has not finished", trade.id));
        }
        let role = trade.role_of(&tx.from).ok_or_else(|| {
            Refusal::Invalid("only the buyer or the seller can leave feedback".to_string())
        })?;
        if tx.amount != 0 {
            return invalid("feedback moves no funds");
        }
        let closed = trade.closed_at.unwrap_or(trade.opened_at);
        if self.now > closed.saturating_add(FEEDBACK_WINDOW_SECS) {
            return invalid("the time to leave feedback on this trade has passed");
        }
        let key = feedback_key(&trade.id, role);
        if self.reader.get(&key).is_some() {
            return invalid(format!("the {} already left feedback on {}", role.as_str(), trade.id));
        }
        let about = trade.counterparty(role).to_string();
        let record = Feedback {
            trade_id: trade.id.clone(),
            from: tx.from.clone(),
            about: about.clone(),
            rating: b.rating,
            comment: b.comment,
            height: self.height,
            at: self.now,
        };
        let delta = match b.rating {
            Rating::Positive => Profile { positive: 1, ..Profile::default() },
            Rating::Neutral => Profile { neutral: 1, ..Profile::default() },
            Rating::Negative => Profile { negative: 1, ..Profile::default() },
        };
        let mut fx = Effects::default();
        fx.touches.push(format!("feedback:{}:{}", trade.id, role.as_str()));
        fx.writes.push((key, Some(encode(&record))));
        fx.profiles.push((about, delta));
        Ok(fx)
    }

    fn settle_effects(&self, tx: &LedgerTx) -> Result<Effects, Refusal> {
        let b = check_settle_shape(tx).map_err(Refusal::Invalid)?;
        let trade = self.known_trade(&b.trade_id)?;
        let signer = verify_auth(&b).map_err(Refusal::Invalid)?;
        let entitled = match b.by {
            Role::Seller => signer == trade.seller,
            Role::Buyer => signer == trade.buyer,
            Role::Arbiter => trade.arbiter.as_deref() == Some(signer.as_str()),
        };
        if !entitled {
            return invalid(format!(
                "the settlement is not signed by the trade's {}",
                b.by.as_str()
            ));
        }
        use TradeState::{Disputed, Locked, Paid};
        let allowed = match (b.outcome, b.by) {
            (Outcome::Release, Role::Seller) => matches!(trade.state, Locked | Paid | Disputed),
            (Outcome::Release, Role::Arbiter) => trade.state == Disputed,
            (Outcome::Release, Role::Buyer) => {
                return invalid("only the seller or an arbiter can release the escrow");
            }
            (Outcome::Refund, Role::Buyer) => matches!(trade.state, Locked | Paid | Disputed),
            (Outcome::Refund, Role::Arbiter) => trade.state == Disputed,
            (Outcome::Refund, Role::Seller) => {
                if !trade.is_egoc() {
                    return invalid(format!(
                        "{} escrow goes back to the seller through the buyer or the arbiter",
                        trade.asset
                    ));
                }
                if trade.state != Locked {
                    return invalid(format!(
                        "the seller can reclaim trade {} only while it is unpaid",
                        trade.id
                    ));
                }
                let due = trade.payment_due_at().unwrap_or(i64::MAX);
                if self.now < due {
                    return invalid(format!(
                        "the buyer has until {due} to pay before the seller can reclaim"
                    ));
                }
                true
            }
        };
        if !allowed {
            return invalid(format!(
                "trade {} cannot be {} by the {} while it is {}",
                trade.id,
                b.outcome.past(),
                b.by.as_str(),
                trade.status(self.now)
            ));
        }
        if let Some(native) = b.native_sig.as_deref() {
            if trade.is_egoc() {
                return invalid("an EGOC settlement carries no outside signature");
            }
            if (b.outcome, b.by) != (Outcome::Refund, Role::Buyer) {
                return invalid("only the buyer's refund carries an outside signature");
            }
            verify_native_cancel(&trade, native).map_err(Refusal::Invalid)?;
        }
        if tx.to != trade.payout_to(b.outcome)
            || tx.amount != trade.settle_amount()
            || tx.fee_uegoc != trade.settle_fee(b.outcome)
        {
            return invalid(format!(
                "settlement {} must pay {} uEGOC to {} with a {} uEGOC fee",
                tx.hash,
                trade.settle_amount(),
                trade.payout_to(b.outcome),
                trade.settle_fee(b.outcome)
            ));
        }
        let mut next = trade.clone();
        next.state = match b.outcome {
            Outcome::Release => TradeState::Released,
            Outcome::Refund => TradeState::Refunded,
        };
        next.closed_at = Some(self.now);
        next.closed_height = Some(self.height);
        next.closed_by = Some(b.by);
        next.settle_tx = Some(tx.hash.clone());
        next.native_sig = b.native_sig.clone();
        let mut fx = Effects::default();
        fx.touches.push(format!("trade:{}", trade.id));
        fx.writes.push((trade_key(&trade.id), Some(encode(&next))));
        if trade.is_egoc() {
            fx.escrow_out = trade.locked_micro;
            fx.closed = 1;
        }
        let volume = if trade.is_egoc() { trade.amount_micro } else { 0 };
        let by_arbiter = b.by == Role::Arbiter;
        match b.outcome {
            Outcome::Release => {
                fx.profiles.push((trade.seller.clone(), Profile::traded(volume, self.now, false)));
                fx.profiles.push((trade.buyer.clone(), Profile::traded(volume, self.now, true)));
                if by_arbiter {
                    fx.profiles.push((trade.buyer.clone(), Profile { disputes_won: 1, ..Profile::default() }));
                    fx.profiles.push((trade.seller.clone(), Profile { disputes_lost: 1, ..Profile::default() }));
                }
                let pk = pair_key(&trade.seller, &trade.buyer);
                if self.reader.get(&pk).is_none() {
                    fx.pairs.push((pk, trade.seller.clone(), trade.buyer.clone()));
                }
            }
            Outcome::Refund => match b.by {
                Role::Buyer => fx
                    .profiles
                    .push((trade.buyer.clone(), Profile { cancelled: 1, ..Profile::default() })),
                Role::Seller => fx
                    .profiles
                    .push((trade.buyer.clone(), Profile { timed_out: 1, ..Profile::default() })),
                Role::Arbiter => {
                    fx.profiles.push((trade.seller.clone(), Profile { disputes_won: 1, ..Profile::default() }));
                    fx.profiles.push((trade.buyer.clone(), Profile { disputes_lost: 1, ..Profile::default() }));
                }
            },
        }
        Ok(fx)
    }

    fn arbiter_effects(&self, tx: &LedgerTx) -> Result<Effects, Refusal> {
        let b: ArbiterBody = body(tx)?;
        if tx.amount != 0 {
            return invalid("publishing arbiter addresses moves no funds");
        }
        if !self.arbiters.iter().any(|a| *a == tx.from) {
            return invalid("only an arbiter publishes arbiter addresses");
        }
        if b.evm.is_none() && b.tron.is_none() && b.sol.is_none() && b.ada.is_none() {
            return invalid("publish at least one address");
        }
        if b.evm.as_deref().is_some_and(|a| !valid_chain_address(Family::Evm, a)) {
            return invalid("the EVM address is not 0x followed by 40 hex digits");
        }
        if b.tron.as_deref().is_some_and(|a| !valid_chain_address(Family::Tron, a)) {
            return invalid("the Tron address is not a T address");
        }
        if b.sol.as_deref().is_some_and(|a| !valid_chain_address(Family::Solana, a)) {
            return invalid("the Solana address is not a 32-byte base58 key");
        }
        if b.ada.as_deref().is_some_and(|a| !valid_chain_address(Family::Cardano, a)) {
            return invalid("the Cardano address is not a testnet key address");
        }
        let record = ArbiterAddresses { evm: b.evm, tron: b.tron, sol: b.sol, ada: b.ada, height: self.height };
        let mut fx = Effects::default();
        fx.touches.push(format!("arbiter:{}", tx.from));
        fx.writes.push((arbiter_addr_key(&tx.from), Some(encode(&record))));
        Ok(fx)
    }
}

fn body<T: for<'de> Deserialize<'de>>(tx: &LedgerTx) -> Result<T, Refusal> {
    serde_json::from_str::<T>(&tx.call_args)
        .map_err(|e| Refusal::Invalid(format!("{} body: {e}", tx.tx_type)))
}

fn check_signed_shape(tx: &LedgerTx) -> Result<(), String> {
    if !SIGNED_OPS.contains(&tx.tx_type.as_str()) {
        return Err(format!(
            "transfer {} to the market escrow is not a market operation",
            tx.hash
        ));
    }
    if tx.from.is_empty() || crate::ledger::is_reserved_system_source(&tx.from) {
        return Err("market operations come from user accounts".into());
    }
    let key: [u8; 32] = hex::decode(&tx.public_key_ed25519)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("market operations carry the sender's Ed25519 key")?;
    if address_of(&key) != tx.from {
        return Err("market trading needs an account whose address comes from its Ed25519 key".into());
    }
    if tx.tx_version < 2 || tx.chain_id != MARKET_CHAIN_ID {
        return Err("market operations must be signed as testnet v2 transactions".into());
    }
    if tx.nonce == 0 {
        return Err("market operations carry a nonce".into());
    }
    if tx.call_args.len() > MAX_BODY_BYTES {
        return Err(format!("a market body is at most {MAX_BODY_BYTES} bytes"));
    }
    let expected = op_memo(&tx.tx_type, &tx.call_args).unwrap_or_default();
    if tx.memo.as_deref() != Some(expected.as_str()) {
        return Err(format!(
            "{} does not commit to its body: the memo must be {expected}",
            tx.hash
        ));
    }
    Ok(())
}

fn check_settle_shape(tx: &LedgerTx) -> Result<SettleBody, String> {
    if tx.tx_type != TX_SETTLE {
        return Err(format!("tx {} from the market escrow is not a settlement", tx.hash));
    }
    if !tx.signature.is_empty()
        || !tx.public_key_ed25519.is_empty()
        || !tx.dilithium_signature.is_empty()
        || tx.nonce != 0
    {
        return Err(format!(
            "settlement {} carries its authority in the body, not a signature or nonce",
            tx.hash
        ));
    }
    if tx.call_args.len() > 1_024 {
        return Err("a settlement body is at most 1024 bytes".into());
    }
    let b: SettleBody = serde_json::from_str(&tx.call_args).map_err(|e| format!("settlement body: {e}"))?;
    if tx.call_args != b.canonical_json() {
        return Err(format!("settlement {} body is not in canonical form", tx.hash));
    }
    if tx.hash != b.tx_hash() {
        return Err(format!("settlement {} body/hash mismatch", tx.hash));
    }
    if !valid_id(&b.trade_id) {
        return Err("the settlement names no trade".into());
    }
    if b
        .native_sig
        .as_deref()
        .is_some_and(|s| !matches!(s.len(), 128 | 130 | 192) || !s.bytes().all(|c| c.is_ascii_hexdigit()))
    {
        return Err("the outside signature is not 64, 65 or 96 hex bytes".into());
    }
    Ok(b)
}

pub fn settle_is_well_formed(tx: &LedgerTx) -> bool {
    is_settle(tx) && check_settle_shape(tx).is_ok()
}

pub fn validate_offer_body(b: &OfferBody) -> Result<(), String> {
    let info = asset_info(&b.asset).ok_or_else(|| format!("{:.16} is not traded on this market yet", b.asset))?;
    if !valid_fiat(&b.fiat) {
        return Err("the fiat currency must be a three-letter ISO code".into());
    }
    match b.price {
        Price::Fixed(p) if p == 0 || p > MAX_PRICE_MICRO => {
            return Err("the fixed price is out of range".into());
        }
        Price::MarginBps(m) if m.abs() > MAX_MARGIN_BPS => {
            return Err(format!("the margin is limited to +/-{MAX_MARGIN_BPS} basis points"));
        }
        _ => {}
    }
    let (lo, hi) = trade_limits(&b.asset);
    if b.min_micro < lo || b.max_micro > hi || b.min_micro > b.max_micro {
        return Err(format!("trade limits must sit within {lo}..={hi} micro-units with min <= max"));
    }
    match (info.family, b.side, b.payout_address.as_deref()) {
        (Family::Ego, _, Some(_)) => return Err("EGOC offers take no payout address".into()),
        (_, Side::Sell, Some(_)) => {
            return Err("on a sell offer the buyer names the payout address when taking it".into());
        }
        (family, Side::Buy, None) if family != Family::Ego => {
            return Err(format!("say where you receive {} on {}", info.symbol, info.network));
        }
        (family, Side::Buy, Some(a)) if family != Family::Ego && !valid_chain_address(family, a) => {
            return Err(format!("{a:.64} is not a {} address", info.network));
        }
        _ => {}
    }
    if b.methods.is_empty() || b.methods.len() > MAX_METHODS {
        return Err(format!("an offer lists 1 to {MAX_METHODS} payment methods"));
    }
    if !b.methods.iter().all(|m| valid_method(m)) {
        return Err("payment methods are lowercase ids like bank_transfer".into());
    }
    let unique: HashSet<&String> = b.methods.iter().collect();
    if unique.len() != b.methods.len() {
        return Err("a payment method is listed twice".into());
    }
    if let Some(c) = &b.country {
        if !valid_country(c) {
            return Err("the country must be a two-letter ISO code".into());
        }
    }
    if !valid_text(&b.terms, MAX_TERMS_BYTES) {
        return Err(format!("terms are at most {MAX_TERMS_BYTES} bytes of text"));
    }
    if b.payment_window_secs < MIN_PAYMENT_WINDOW_SECS || b.payment_window_secs > MAX_PAYMENT_WINDOW_SECS {
        return Err(format!(
            "the payment window is {MIN_PAYMENT_WINDOW_SECS}..={MAX_PAYMENT_WINDOW_SECS} seconds"
        ));
    }
    Ok(())
}

pub fn chain_time(db: &DB, height: u64) -> i64 {
    let from = height.saturating_sub(CHAIN_TIME_WINDOW).max(1);
    let mut stamps: Vec<i64> = (from..height).filter_map(|h| chain_db::block_timestamp(db, h)).collect();
    median(&mut stamps)
}

fn median(stamps: &mut [i64]) -> i64 {
    if stamps.is_empty() {
        return 0;
    }
    stamps.sort_unstable();
    stamps[stamps.len() / 2]
}

pub fn proposal_planner(db: &DB, height: u64) -> (DbReader<'_>, i64) {
    (DbReader(db), chain_time(db, height))
}

fn already_committed(db: &DB, hash: &str) -> bool {
    chain_db::tx_is_committed(db, hash)
}

pub fn plan_block(db: &DB, height: u64, txs: &[&LedgerTx]) -> Plan {
    let mut market: Vec<&LedgerTx> = txs.iter().copied().filter(|t| touches_market(t)).collect();
    if market.is_empty() {
        return Plan::default();
    }
    if !rule_active(height) {
        tracing::error!(
            "[Market] block #{height} carries {} market transaction(s) before the market is active; none take effect",
            market.len()
        );
        return Plan {
            rejected: market.iter().map(|t| t.hash.clone()).collect(),
            ..Plan::default()
        };
    }
    market.sort_by(|a, b| a.hash.cmp(&b.hash));
    let reader = DbReader(db);
    let mut planner = Planner::new(&reader, height, chain_time(db, height));
    let mut rejected = Vec::new();
    for tx in market {
        if let Err(r) = planner.admit(tx) {
            tracing::error!("[Market] block #{height}: {} takes no effect: {r}", tx.hash);
            rejected.push(tx.hash.clone());
        }
    }
    let mut plan = planner.finish();
    plan.rejected = rejected;
    plan
}

pub fn validate_block_market_txs(height: u64, txs: &[LedgerTx]) -> Result<(), String> {
    if !txs.iter().any(touches_market) {
        return Ok(());
    }
    if !rule_active(height) {
        return Err(format!(
            "block {height} carries market transactions but the P2P market is not active"
        ));
    }
    let db = chain_db::get_db().lock().unwrap_or_else(|e| e.into_inner());
    let reader = DbReader(db);
    let mut planner = Planner::new(&reader, height, chain_time(db, height));
    for tx in txs.iter().filter(|t| touches_market(t)) {
        if already_committed(db, &tx.hash) {
            continue;
        }
        planner
            .admit(tx)
            .map_err(|r| format!("market tx {} refused: {r}", tx.hash))?;
    }
    Ok(())
}

fn verify_incoming(tx: &LedgerTx) -> Result<(), String> {
    if !rule_active_at_tip() {
        return Err("the P2P market is not active on this chain".into());
    }
    let db = chain_db::get_db().lock().unwrap_or_else(|e| e.into_inner());
    let height = chain_db::local_chain_height().saturating_add(1);
    let reader = DbReader(db);
    let mut planner = Planner::new(&reader, height, chain_time(db, height));
    match planner.admit(tx) {
        Ok(()) => Ok(()),
        Err(Refusal::Unknown(e)) => {
            if crate::p2p::network_tip() > chain_db::local_chain_height() {
                Ok(())
            } else {
                Err(e)
            }
        }
        Err(r) => Err(r.to_string()),
    }
}

pub fn verify_incoming_op(tx: &LedgerTx) -> Result<(), String> {
    verify_incoming(tx)
}

pub fn verify_incoming_settle(tx: &LedgerTx) -> Result<(), String> {
    verify_incoming(tx)
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Journal {
    prior: Vec<(String, Option<String>)>,
    #[serde(default)]
    rejected: Vec<String>,
}

pub fn apply_plan(db: &DB, batch: &mut WriteBatch, height: u64, plan: &Plan) {
    if plan.is_empty() {
        return;
    }
    let Some(cf) = db.cf_handle(CF_META) else { return };
    let mut journal = Journal::default();
    for (k, v) in &plan.writes {
        let prior = db.get_cf(cf, k).ok().flatten();
        journal.prior.push((hex::encode(k), prior.map(hex::encode)));
        match v {
            Some(v) => batch.put_cf(cf, k, v),
            None => batch.delete_cf(cf, k),
        }
    }
    journal.rejected = plan.rejected.clone();
    batch.put_cf(cf, undo_key(height), encode(&journal));
    prune_journals(db, batch, chain_db::finality_floor_height(db));
}

fn prune_journals(db: &DB, batch: &mut WriteBatch, floor: u64) {
    if floor == 0 {
        return;
    }
    let Some(cf) = db.cf_handle(CF_META) else { return };
    for item in db.iterator_cf(cf, IteratorMode::From(UNDO_PREFIX, Direction::Forward)) {
        let Ok((k, _)) = item else { break };
        if !k.starts_with(UNDO_PREFIX) || k.len() < UNDO_PREFIX.len() + 8 {
            break;
        }
        let mut hb = [0u8; 8];
        hb.copy_from_slice(&k[UNDO_PREFIX.len()..UNDO_PREFIX.len() + 8]);
        if u64::from_be_bytes(hb) > floor {
            break;
        }
        batch.delete_cf(cf, k.as_ref());
    }
}

fn journals_since(db: &DB, from_height: u64) -> Vec<(Vec<u8>, Journal)> {
    let Some(cf) = db.cf_handle(CF_META) else { return Vec::new() };
    let start = undo_key(from_height);
    let mut out = Vec::new();
    for item in db.iterator_cf(cf, IteratorMode::From(&start, Direction::Forward)) {
        let Ok((k, v)) = item else { break };
        if !k.starts_with(UNDO_PREFIX) {
            break;
        }
        out.push((k.to_vec(), decode::<Journal>(&v).unwrap_or_default()));
    }
    out
}

pub fn rejected_since(db: &DB, from_height: u64) -> HashSet<String> {
    journals_since(db, from_height)
        .into_iter()
        .flat_map(|(_, j)| j.rejected)
        .collect()
}

pub fn rollback(db: &DB, batch: &mut WriteBatch, from_height: u64) {
    let Some(cf) = db.cf_handle(CF_META) else { return };
    for (key, journal) in journals_since(db, from_height).iter().rev() {
        for (k, prior) in &journal.prior {
            let Ok(k) = hex::decode(k) else { continue };
            match prior.as_ref().and_then(|p| hex::decode(p).ok()) {
                Some(v) => batch.put_cf(cf, &k, v),
                None => batch.delete_cf(cf, &k),
            }
        }
        batch.delete_cf(cf, key);
    }
}

pub fn reverse_balance_delta(tx: &LedgerTx, out: &mut HashMap<String, i128>) -> bool {
    if !is_settle(tx) {
        return false;
    }
    *out.entry(tx.to.clone()).or_insert(0) -= tx.amount.saturating_sub(tx.fee_uegoc) as i128;
    *out.entry(MARKET_ESCROW_ADDR.to_string()).or_insert(0) += tx.amount as i128;
    true
}

fn escrow_address_balance(db: &DB) -> u64 {
    db.cf_handle(CF_BALANCES)
        .and_then(|cf| db.get_cf(cf, MARKET_ESCROW_ADDR.as_bytes()).ok().flatten())
        .map(|v| read_u64_le(&v))
        .unwrap_or(0)
}

pub fn check_invariants(db: &DB, height: u64) {
    let totals: EscrowTotals = read(&DbReader(db), ESCROW_KEY).unwrap_or_default();
    let on_chain = escrow_address_balance(db);
    static REPORTED: std::sync::Mutex<Option<(u64, u64)>> = std::sync::Mutex::new(None);
    let pair = (totals.held_uegoc, on_chain);
    let mut last = REPORTED.lock().unwrap_or_else(|e| e.into_inner());
    if totals.held_uegoc != on_chain {
        if *last != Some(pair) {
            *last = Some(pair);
            crate::invariants::report(crate::invariants::Violation::MarketEscrowMismatch {
                height,
                held_uegoc: totals.held_uegoc,
                on_chain_uegoc: on_chain,
            });
        }
    } else if last.take().is_some() {
        tracing::info!("[Market] the escrow and its trades agree again at {on_chain} uEGOC");
    }
}

pub fn settle_tx(body: &SettleBody, trade: &Trade, timestamp: i64) -> LedgerTx {
    LedgerTx {
        hash: body.tx_hash(),
        from: MARKET_ESCROW_ADDR.to_string(),
        to: trade.payout_to(body.outcome).to_string(),
        amount: trade.settle_amount(),
        fee_uegoc: trade.settle_fee(body.outcome),
        tx_type: TX_SETTLE.to_string(),
        call_args: body.canonical_json(),
        timestamp,
        status: "Pending".to_string(),
        chain_id: MARKET_CHAIN_ID,
        ..LedgerTx::default()
    }
}

fn with_db<T>(f: impl FnOnce(&DB) -> T) -> T {
    let db = chain_db::get_db().lock().unwrap_or_else(|e| e.into_inner());
    f(db)
}

fn now_on_chain(db: &DB) -> (u64, i64) {
    let height = chain_db::local_chain_height().saturating_add(1);
    (height, chain_time(db, height))
}

fn profile_summary(p: &Profile) -> Value {
    json!({
        "completed": p.completed,
        "partners": p.partners,
        "positive": p.positive,
        "neutral": p.neutral,
        "negative": p.negative,
        "volume_uegoc": p.volume_uegoc,
        "disputes_lost": p.disputes_lost,
        "first_trade_at": p.first_trade_at,
    })
}

pub fn get_offer(id: &str) -> Option<Offer> {
    with_db(|db| read(&DbReader(db), &offer_key(id)))
}

pub fn get_trade(id: &str) -> Option<Trade> {
    with_db(|db| read(&DbReader(db), &trade_key(id)))
}

pub fn get_profile(addr: &str) -> Profile {
    with_db(|db| read(&DbReader(db), &profile_key(addr)).unwrap_or_default())
}

pub fn params_view() -> Value {
    with_db(|db| {
        let (height, now) = now_on_chain(db);
        let totals: EscrowTotals = read(&DbReader(db), ESCROW_KEY).unwrap_or_default();
        json!({
            "active": rule_active(height),
            "escrow_address": MARKET_ESCROW_ADDR,
            "chain_id": MARKET_CHAIN_ID,
            "height": height,
            "chain_time": now,
            "wall_time": chrono::Utc::now().timestamp(),
            "assets": ASSETS,
            "arbiter_addresses": arbiters_at(height)
                .iter()
                .map(|a| (a.to_string(), read::<ArbiterAddresses>(&DbReader(db), &arbiter_addr_key(a))))
                .collect::<BTreeMap<String, Option<ArbiterAddresses>>>(),
            "maker_fee_bps": MAKER_FEE_BPS,
            "min_trade_uegoc": MIN_TRADE_UEGOC,
            "max_trade_uegoc": MAX_TRADE_UEGOC,
            "max_open_offers_per_maker": MAX_OPEN_OFFERS_PER_MAKER,
            "max_pending_trades_per_taker": MAX_PENDING_TRADES_PER_TAKER,
            "max_methods": MAX_METHODS,
            "max_terms_bytes": MAX_TERMS_BYTES,
            "max_note_bytes": MAX_NOTE_BYTES,
            "payment_window_secs": [MIN_PAYMENT_WINDOW_SECS, MAX_PAYMENT_WINDOW_SECS],
            "accept_window_secs": ACCEPT_WINDOW_SECS,
            "buyer_dispute_delay_secs": BUYER_DISPUTE_DELAY_SECS,
            "offer_ttl_secs": OFFER_TTL_SECS,
            "feedback_window_secs": FEEDBACK_WINDOW_SECS,
            "max_margin_bps": MAX_MARGIN_BPS,
            "arbiters": arbiters_at(height),
            "escrow_held_uegoc": totals.held_uegoc,
            "active_trades": totals.active_trades,
            "ops": SIGNED_OPS,
        })
    })
}

pub fn offer_view(offer: &Offer, maker: &Profile, now: i64) -> Value {
    json!({
        "offer": offer,
        "open": offer.is_open(now),
        "maker_profile": profile_summary(maker),
    })
}

pub fn offer_by_id_view(id: &str) -> Option<Value> {
    with_db(|db| {
        let (_, now) = now_on_chain(db);
        let reader = DbReader(db);
        let offer: Offer = read(&reader, &offer_key(id))?;
        let maker: Profile = read(&reader, &profile_key(&offer.maker)).unwrap_or_default();
        Some(offer_view(&offer, &maker, now))
    })
}

pub struct OfferFilter<'a> {
    pub method: Option<&'a str>,
    pub country: Option<&'a str>,
    pub amount_micro: Option<u64>,
}

pub fn arbiter_addresses(addr: &str) -> Option<ArbiterAddresses> {
    with_db(|db| read(&DbReader(db), &arbiter_addr_key(addr)))
}

pub fn offers_view(
    asset: &str,
    fiat: &str,
    side: Side,
    limit: usize,
    cursor: Option<&str>,
    filter: &OfferFilter,
) -> Value {
    with_db(|db| {
        let (_, now) = now_on_chain(db);
        let Some(cf) = db.cf_handle(CF_META) else { return json!({ "offers": [], "next": null }) };
        let prefix = book_prefix(asset, fiat, side);
        let start = cursor
            .and_then(|c| hex::decode(c).ok())
            .filter(|c| c.starts_with(&prefix))
            .unwrap_or_else(|| prefix_ceiling(&prefix));
        let reader = DbReader(db);
        let mut offers = Vec::new();
        let mut next = None;
        let mut scanned = 0usize;
        for item in db.iterator_cf(cf, IteratorMode::From(&start, Direction::Reverse)) {
            let Ok((k, _)) = item else { break };
            if !k.starts_with(&prefix) {
                break;
            }
            if cursor.is_some() && k.as_ref() == start.as_slice() {
                continue;
            }
            scanned += 1;
            if offers.len() >= limit || scanned > 2_000 {
                break;
            }
            next = Some(hex::encode(&k));
            let Some(id) = id_after_height(&k, prefix.len()) else { continue };
            let Some(offer) = read::<Offer>(&reader, &offer_key(&id)) else { continue };
            if !offer.is_open(now) {
                if offer.closed_height.is_none() {
                    break;
                }
                continue;
            }
            if filter.method.is_some_and(|m| !offer.methods.iter().any(|x| x == m)) {
                continue;
            }
            if filter.country.is_some_and(|c| offer.country.as_deref() != Some(c)) {
                continue;
            }
            if filter
                .amount_micro
                .is_some_and(|a| a < offer.min_micro || a > offer.max_micro)
            {
                continue;
            }
            let maker: Profile = read(&reader, &profile_key(&offer.maker)).unwrap_or_default();
            offers.push(offer_view(&offer, &maker, now));
        }
        if offers.len() < limit {
            next = None;
        }
        json!({ "offers": offers, "next": next, "chain_time": now })
    })
}

pub fn trade_view(trade: &Trade, now: i64, reader: &impl Reader) -> Value {
    let fb = |role: Role| read::<Feedback>(reader, &feedback_key(&trade.id, role));
    json!({
        "trade": trade,
        "status": trade.status(now),
        "lock_expires_at": (trade.state == TradeState::AwaitingLock).then(|| trade.lock_expires_at()),
        "payment_due_at": trade.payment_due_at(),
        "buyer_may_dispute_at": trade.buyer_may_dispute_at(),
        "payment_reference": payment_reference(&trade.id),
        "feedback": { "buyer": fb(Role::Buyer), "seller": fb(Role::Seller) },
        "chain_time": now,
    })
}

pub fn trade_by_id_view(id: &str) -> Option<Value> {
    with_db(|db| {
        let (_, now) = now_on_chain(db);
        let reader = DbReader(db);
        let trade: Trade = read(&reader, &trade_key(id))?;
        Some(trade_view(&trade, now, &reader))
    })
}

pub fn trades_of_view(addr: &str, limit: usize, cursor: Option<&str>) -> Value {
    trade_index_view(user_trades_prefix(addr), limit, cursor)
}

pub fn cases_of_view(arbiter: &str, limit: usize, cursor: Option<&str>) -> Value {
    trade_index_view(arbiter_cases_prefix(arbiter), limit, cursor)
}

pub fn offers_by_maker_view(maker: &str) -> Value {
    with_db(|db| {
        let (_, now) = now_on_chain(db);
        let reader = DbReader(db);
        let prefix = maker_offers_prefix(maker);
        let profile: Profile = read(&reader, &profile_key(maker)).unwrap_or_default();
        let offers: Vec<Value> = reader
            .scan(&prefix, false, OWNER_SCAN_LIMIT)
            .iter()
            .filter_map(|(k, _)| id_after(k, prefix.len()))
            .filter_map(|id| read::<Offer>(&reader, &offer_key(&id)))
            .map(|o| offer_view(&o, &profile, now))
            .collect();
        json!({ "offers": offers, "chain_time": now })
    })
}

fn trade_index_view(prefix: Vec<u8>, limit: usize, cursor: Option<&str>) -> Value {
    with_db(|db| {
        let (_, now) = now_on_chain(db);
        let Some(cf) = db.cf_handle(CF_META) else { return json!({ "trades": [], "next": null }) };
        let start = cursor
            .and_then(|c| hex::decode(c).ok())
            .filter(|c| c.starts_with(&prefix))
            .unwrap_or_else(|| prefix_ceiling(&prefix));
        let reader = DbReader(db);
        let mut trades = Vec::new();
        let mut next = None;
        for item in db.iterator_cf(cf, IteratorMode::From(&start, Direction::Reverse)) {
            let Ok((k, _)) = item else { break };
            if !k.starts_with(&prefix) {
                break;
            }
            if cursor.is_some() && k.as_ref() == start.as_slice() {
                continue;
            }
            if trades.len() >= limit {
                break;
            }
            next = Some(hex::encode(&k));
            let Some(id) = id_after_height(&k, prefix.len()) else { continue };
            if let Some(trade) = read::<Trade>(&reader, &trade_key(&id)) {
                trades.push(trade_view(&trade, now, &reader));
            }
        }
        if trades.len() < limit {
            next = None;
        }
        json!({ "trades": trades, "next": next, "chain_time": now })
    })
}

pub fn profile_view(addr: &str) -> Value {
    let p = get_profile(addr);
    json!({ "address": addr, "profile": p })
}

pub fn leaderboard_view(limit: usize) -> Value {
    with_db(|db| {
        let reader = DbReader(db);
        let rows: Vec<Value> = reader
            .scan(LEADERBOARD_PREFIX, true, limit)
            .iter()
            .filter_map(|(k, _)| id_after(k, LEADERBOARD_PREFIX.len() + 8))
            .map(|addr| {
                let p: Profile = read(&reader, &profile_key(&addr)).unwrap_or_default();
                json!({ "address": addr, "profile": profile_summary(&p) })
            })
            .collect();
        json!({ "leaders": rows })
    })
}

pub fn build_settle_view(
    trade_id: &str,
    outcome: Outcome,
    by: Role,
    pubkey: &str,
    signature: &str,
) -> Result<Value, String> {
    let trade = get_trade(trade_id).ok_or_else(|| format!("trade {trade_id} is not on this chain"))?;
    let body = SettleBody {
        trade_id: trade_id.to_string(),
        outcome,
        by,
        pubkey: pubkey.to_string(),
        signature: signature.to_string(),
        native_sig: None,
    };
    let signer = verify_auth(&body)?;
    let tx = settle_tx(&body, &trade, chrono::Utc::now().timestamp());
    Ok(json!({ "tx": tx, "signer": signer }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    struct Who {
        key: SigningKey,
        addr: String,
    }

    impl Who {
        fn new(tag: u8) -> Who {
            let key = SigningKey::from_bytes(&[tag; 32]);
            let addr = address_of(&key.verifying_key().to_bytes());
            Who { key, addr }
        }

        fn auth(&self, trade_id: &str, outcome: Outcome, by: Role) -> SettleBody {
            let sig = self.key.sign(settle_message(trade_id, outcome, by).as_bytes());
            SettleBody {
                trade_id: trade_id.to_string(),
                outcome,
                by,
                pubkey: hex::encode(self.key.verifying_key().to_bytes()),
                signature: hex::encode(sig.to_bytes()),
                native_sig: None,
            }
        }
    }

    fn signed(who: &Who, tx_type: &str, body: &impl Serialize, amount: u64, nonce: u64) -> LedgerTx {
        let from = who.addr.as_str();
        let call_args = serde_json::to_string(body).unwrap();
        let memo = op_memo(tx_type, &call_args).unwrap();
        let mut m = from.as_bytes().to_vec();
        m.extend_from_slice(tx_type.as_bytes());
        m.extend_from_slice(call_args.as_bytes());
        m.extend_from_slice(&nonce.to_le_bytes());
        LedgerTx {
            hash: format!("0x{}", ego_core::hash_data(&m).to_hex()),
            from: from.to_string(),
            to: MARKET_ESCROW_ADDR.to_string(),
            amount,
            fee_uegoc: 1_000,
            nonce,
            memo: Some(memo),
            tx_type: tx_type.to_string(),
            call_args,
            tx_version: 2,
            chain_id: MARKET_CHAIN_ID,
            public_key_ed25519: hex::encode(who.key.verifying_key().to_bytes()),
            ..LedgerTx::default()
        }
    }

    fn sell_offer() -> OfferBody {
        OfferBody {
            side: Side::Sell,
            asset: "EGOC".into(),
            fiat: "EUR".into(),
            price: Price::Fixed(250),
            min_micro: 1_000_000,
            max_micro: 500_000_000,
            methods: vec!["sepa".into(), "revolut".into()],
            country: Some("DE".into()),
            terms: "SEPA instant only.\nNo third-party payments.".into(),
            payment_window_secs: 3_600,
            payout_address: None,
        }
    }

    struct World {
        store: MemReader,
        height: u64,
        now: i64,
        arbiters: Vec<String>,
        nonce: u64,
    }

    impl World {
        fn new() -> World {
            World { store: MemReader::default(), height: 100, now: 1_800_000_000, arbiters: Vec::new(), nonce: 0 }
        }

        fn planner(&self) -> Planner<'_, MemReader> {
            let mut p = Planner::new(&self.store, self.height, self.now);
            if !self.arbiters.is_empty() {
                p.arbiters = self.arbiters.clone();
            }
            p
        }

        fn block(&mut self, txs: &[&LedgerTx]) -> Result<Plan, Refusal> {
            let mut p = self.planner();
            for tx in txs {
                p.admit(tx)?;
            }
            let plan = p.finish();
            self.store.apply(&plan);
            self.height += 1;
            self.now += 10;
            Ok(plan)
        }

        fn one(&mut self, tx: &LedgerTx) -> Result<Plan, Refusal> {
            self.block(&[tx])
        }

        fn next_nonce(&mut self) -> u64 {
            self.nonce += 1;
            self.nonce
        }

        fn op(&mut self, from: &Who, tx_type: &str, body: &impl Serialize, amount: u64) -> LedgerTx {
            let n = self.next_nonce();
            signed(from, tx_type, body, amount, n)
        }

        fn trade(&self, id: &str) -> Trade {
            read(&self.store, &trade_key(id)).unwrap()
        }

        fn offer(&self, id: &str) -> Offer {
            read(&self.store, &offer_key(id)).unwrap()
        }

        fn profile(&self, addr: &str) -> Profile {
            read(&self.store, &profile_key(addr)).unwrap_or_default()
        }

        fn escrow(&self) -> EscrowTotals {
            read(&self.store, ESCROW_KEY).unwrap_or_default()
        }

        fn post_offer(&mut self, maker: &Who, body: &OfferBody) -> String {
            let tx = self.op(maker, TX_OFFER, body, 0);
            self.one(&tx).unwrap();
            tx.hash
        }

        fn open(&mut self, taker: &Who, offer_id: &str, amount: u64) -> LedgerTx {
            let offer = self.offer(offer_id);
            let price = match offer.price {
                Price::Fixed(p) => p,
                Price::MarginBps(_) => 300,
            };
            let body = TradeOpenBody {
                offer_id: offer_id.into(),
                amount_micro: amount,
                price_micro: price,
                fiat_micro: fiat_for(amount, price).unwrap(),
                method: offer.methods[0].clone(),
                payout_address: None,
            };
            let lock = if offer.side == Side::Buy { amount } else { 0 };
            self.op(taker, TX_TRADE_OPEN, &body, lock)
        }

        fn settle(&self, signer: &Who, trade_id: &str, outcome: Outcome, by: Role) -> LedgerTx {
            let trade = self.trade(trade_id);
            settle_tx(&signer.auth(trade_id, outcome, by), &trade, self.now)
        }

        fn locked_trade(&mut self, seller: &Who, buyer: &Who) -> (String, String) {
            let offer = self.post_offer(seller, &sell_offer());
            let open = self.open(buyer, &offer, 100_000_000);
            self.one(&open).unwrap();
            let fund = self.trade(&open.hash).locked_micro;
            let lock = self.op(seller, TX_LOCK, &TradeRef { trade_id: open.hash.clone() }, fund);
            self.one(&lock).unwrap();
            (offer, open.hash)
        }
    }

    fn refused(r: Result<Plan, Refusal>, needle: &str) {
        match r {
            Ok(_) => panic!("expected a refusal containing {needle:?}"),
            Err(e) => assert!(e.reason().contains(needle), "{needle:?} not in {:?}", e.reason()),
        }
    }

    #[test]
    fn the_escrow_address_is_reserved_and_shaped_like_the_pool() {
        assert_eq!(MARKET_ESCROW_ADDR.len(), crate::shielded_chain::SHIELDED_POOL_ADDR.len());
        assert!(MARKET_ESCROW_ADDR.starts_with("egot1"));
        assert!(crate::ledger::is_reserved_system_source(MARKET_ESCROW_ADDR));
    }

    #[test]
    fn every_trade_gets_a_short_stable_payment_reference() {
        let a = payment_reference(&format!("0x{}", "ab".repeat(32)));
        let b = payment_reference(&format!("0x{}", "ac".repeat(32)));
        assert_eq!(a, payment_reference(&format!("0x{}", "AB".repeat(32))));
        assert_ne!(a, b);
        assert_eq!(a.len(), 12);
        assert!(a.starts_with("EGO-"));
        assert!(a[4..].bytes().all(|c| CROCKFORD.contains(&c)));
        assert!(!a[4..].contains(['I', 'L', 'O', 'U']));
    }

    #[test]
    fn fees_round_up_and_fiat_rounds_half_up() {
        assert_eq!(maker_fee(1_000_000), 10_000);
        assert_eq!(maker_fee(1_000_001), 10_001);
        assert_eq!(maker_fee(99), 1);
        assert_eq!(fiat_for(1_000_000, 250), Some(250));
        assert_eq!(fiat_for(1_500_000, 3), Some(5));
        assert_eq!(fiat_for(1_400_000, 3), Some(4));
        assert_eq!(fiat_for(u64::MAX, u64::MAX), None);
    }

    #[test]
    fn a_valid_offer_is_listed_and_counted_against_its_maker() {
        let mut w = World::new();
        let maker = Who::new(1);
        let id = w.post_offer(&maker, &sell_offer());
        let offer = w.offer(&id);
        assert_eq!(offer.maker, maker.addr);
        assert_eq!(offer.created_height, 100);
        assert!(offer.is_open(w.now));
        assert!(w.store.get(&book_key(EGOC, "EUR", Side::Sell, 100, &id)).is_some());
        assert!(w.store.get(&maker_offer_key(&maker.addr, &id)).is_some());
        assert_eq!(w.planner().open_offer_count(&maker.addr), 1);
    }

    #[test]
    fn malformed_offers_are_refused() {
        let maker = Who::new(1);
        let cases: Vec<(Box<dyn Fn(&mut OfferBody)>, &str)> = vec![
            (Box::new(|b| b.asset = "BTC".into()), "not traded"),
            (Box::new(|b| b.fiat = "eur".into()), "three-letter"),
            (Box::new(|b| b.price = Price::Fixed(0)), "fixed price"),
            (Box::new(|b| b.price = Price::MarginBps(5_001)), "margin"),
            (Box::new(|b| b.min_micro = 999_999), "trade limits"),
            (Box::new(|b| b.min_micro = b.max_micro + 1), "trade limits"),
            (Box::new(|b| b.methods.clear()), "payment methods"),
            (Box::new(|b| b.methods = vec!["Bank Transfer".into()]), "lowercase ids"),
            (Box::new(|b| b.methods = vec!["sepa".into(), "sepa".into()]), "listed twice"),
            (Box::new(|b| b.country = Some("Germany".into())), "two-letter"),
            (Box::new(|b| b.terms = "x".repeat(MAX_TERMS_BYTES + 1)), "terms"),
            (Box::new(|b| b.terms = "bell\u{7}".into()), "terms"),
            (Box::new(|b| b.payment_window_secs = 60), "payment window"),
        ];
        for (mutate, needle) in cases {
            let mut w = World::new();
            let mut b = sell_offer();
            mutate(&mut b);
            let tx = w.op(&maker, TX_OFFER, &b, 0);
            refused(w.one(&tx), needle);
        }
    }

    #[test]
    fn an_offer_must_commit_to_its_body_and_be_a_testnet_v2_transaction() {
        let maker = Who::new(1);
        let mut w = World::new();
        let mut tx = w.op(&maker, TX_OFFER, &sell_offer(), 0);
        tx.call_args = tx.call_args.replace("250", "1");
        refused(w.one(&tx), "does not commit to its body");

        let mut tx = w.op(&maker, TX_OFFER, &sell_offer(), 0);
        tx.tx_version = 1;
        refused(w.one(&tx), "testnet v2");

        let mut tx = w.op(&maker, TX_OFFER, &sell_offer(), 0);
        tx.chain_id = 2;
        refused(w.one(&tx), "testnet v2");

        let tx = w.op(&maker, TX_OFFER, &sell_offer(), 5);
        refused(w.one(&tx), "moves no funds");

        let mut tx = w.op(&maker, TX_OFFER, &sell_offer(), 0);
        tx.tx_type = "transfer".into();
        refused(w.one(&tx), "not a market operation");

        let mut tx = w.op(&maker, TX_OFFER, &sell_offer(), 0);
        tx.public_key_ed25519 = hex::encode(Who::new(9).key.verifying_key().to_bytes());
        refused(w.one(&tx), "comes from its Ed25519 key");

        let mut tx = w.op(&maker, TX_OFFER, &sell_offer(), 0);
        tx.public_key_ed25519.clear();
        refused(w.one(&tx), "carry the sender's Ed25519 key");
    }

    #[test]
    fn trades_remember_both_parties_keys_for_the_chat() {
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        let (offer, trade) = w.locked_trade(&seller, &buyer);
        let key = |who: &Who| hex::encode(who.key.verifying_key().to_bytes());
        assert_eq!(w.offer(&offer).maker_key, key(&seller));
        let t = w.trade(&trade);
        assert_eq!((t.seller_key.clone(), t.buyer_key.clone()), (key(&seller), key(&buyer)));

        let mut b = sell_offer();
        b.side = Side::Buy;
        let buy_offer = w.post_offer(&buyer, &b);
        let open = w.open(&seller, &buy_offer, 2_000_000);
        w.one(&open).unwrap();
        let t = w.trade(&open.hash);
        assert_eq!((t.seller_key.clone(), t.buyer_key.clone()), (key(&seller), key(&buyer)));
    }

    #[test]
    fn a_dispute_files_the_case_with_its_arbiter() {
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        let arbiter = Who::new(7);
        w.arbiters = vec![arbiter.addr.clone()];
        let (_, trade) = w.locked_trade(&seller, &buyer);
        let paid = w.op(&buyer, TX_PAID, &TradeRef { trade_id: trade.clone() }, 0);
        w.one(&paid).unwrap();
        let dispute = w.op(&seller, TX_DISPUTE, &DisputeBody { trade_id: trade.clone(), reason: "no money".into() }, 0);
        let height = w.height;
        w.one(&dispute).unwrap();
        assert!(w.store.get(&arbiter_case_key(&arbiter.addr, height, &trade)).is_some());
        let cases = w.store.scan(&arbiter_cases_prefix(&arbiter.addr), true, 10);
        assert_eq!(cases.len(), 1);
    }

    #[test]
    fn a_maker_is_held_to_the_open_offer_limit_even_inside_one_block() {
        let mut w = World::new();
        let maker = Who::new(1);
        for _ in 0..MAX_OPEN_OFFERS_PER_MAKER - 1 {
            w.post_offer(&maker, &sell_offer());
        }
        let a = w.op(&maker, TX_OFFER, &sell_offer(), 0);
        let b = w.op(&maker, TX_OFFER, &sell_offer(), 0);
        let mut p = w.planner();
        p.admit(&a).unwrap();
        assert!(matches!(p.admit(&b), Err(Refusal::Conflict(_))));
        w.one(&a).unwrap();
        refused(w.one(&b), "already has");
    }

    #[test]
    fn only_the_maker_closes_an_offer_and_only_once() {
        let mut w = World::new();
        let maker = Who::new(1);
        let other = Who::new(2);
        let id = w.post_offer(&maker, &sell_offer());
        let by_other = w.op(&other, TX_OFFER_CLOSE, &OfferRef { offer_id: id.clone() }, 0);
        refused(w.one(&by_other), "only the maker");
        let close = w.op(&maker, TX_OFFER_CLOSE, &OfferRef { offer_id: id.clone() }, 0);
        w.one(&close).unwrap();
        assert!(!w.offer(&id).is_open(w.now));
        assert!(w.store.get(&book_key(EGOC, "EUR", Side::Sell, 100, &id)).is_none());
        assert_eq!(w.planner().open_offer_count(&maker.addr), 0);
        let again = w.op(&maker, TX_OFFER_CLOSE, &OfferRef { offer_id: id }, 0);
        refused(w.one(&again), "already closed");
    }

    #[test]
    fn closing_an_offer_and_taking_it_in_the_same_block_both_stand() {
        let mut w = World::new();
        let maker = Who::new(1);
        let buyer = Who::new(2);
        let id = w.post_offer(&maker, &sell_offer());
        let open = w.open(&buyer, &id, 2_000_000);
        let close = w.op(&maker, TX_OFFER_CLOSE, &OfferRef { offer_id: id.clone() }, 0);
        let forward = w.block(&[&open, &close]).unwrap();
        let mut again = World::new();
        again.post_offer(&maker, &sell_offer());
        again.nonce = w.nonce;
        let backward = again.block(&[&close, &open]).unwrap();
        assert_eq!(forward.writes, backward.writes);
        assert_eq!(w.trade(&open.hash).state, TradeState::AwaitingLock);
        assert!(w.offer(&id).closed_height.is_some());
        let late = w.open(&buyer, &id, 2_000_000);
        refused(w.one(&late), "closed or has expired");
    }

    #[test]
    fn taking_a_sell_offer_waits_for_the_seller_to_fund_amount_plus_the_maker_fee() {
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        let id = w.post_offer(&seller, &sell_offer());
        let open = w.open(&buyer, &id, 100_000_000);
        w.one(&open).unwrap();
        let t = w.trade(&open.hash);
        assert_eq!(t.state, TradeState::AwaitingLock);
        assert_eq!((t.seller.as_str(), t.buyer.as_str()), (seller.addr.as_str(), buyer.addr.as_str()));
        assert_eq!(t.maker_fee_micro, 1_000_000);
        assert_eq!(t.locked_micro, 101_000_000);
        assert_eq!(t.fiat_micro, 25_000);
        assert_eq!(w.escrow(), EscrowTotals::default());

        let short = w.op(&seller, TX_LOCK, &TradeRef { trade_id: open.hash.clone() }, 100_000_000);
        refused(w.one(&short), "needs exactly");
        let by_buyer = w.op(&buyer, TX_LOCK, &TradeRef { trade_id: open.hash.clone() }, 101_000_000);
        refused(w.one(&by_buyer), "only the seller");
        let lock = w.op(&seller, TX_LOCK, &TradeRef { trade_id: open.hash.clone() }, 101_000_000);
        w.one(&lock).unwrap();
        let t = w.trade(&open.hash);
        assert_eq!(t.state, TradeState::Locked);
        assert!(t.locked_at.is_some());
        assert_eq!(w.escrow(), EscrowTotals { held_uegoc: 101_000_000, active_trades: 1 });
    }

    #[test]
    fn a_trade_open_is_checked_against_the_offer() {
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        let id = w.post_offer(&seller, &sell_offer());

        let own = w.open(&seller, &id, 2_000_000);
        refused(w.one(&own), "own offer");

        let big = w.open(&buyer, &id, 600_000_000);
        refused(w.one(&big), "outside the offer");

        let mut wrong_fiat = w.open(&buyer, &id, 2_000_000);
        let mut b: TradeOpenBody = serde_json::from_str(&wrong_fiat.call_args).unwrap();
        b.fiat_micro += 1;
        wrong_fiat = w.op(&buyer, TX_TRADE_OPEN, &b, 0);
        refused(w.one(&wrong_fiat), "comes to");

        b.fiat_micro -= 1;
        b.method = "paypal".into();
        let tx = w.op(&buyer, TX_TRADE_OPEN, &b, 0);
        refused(w.one(&tx), "does not accept");

        b.method = "sepa".into();
        b.price_micro = 251;
        b.fiat_micro = fiat_for(2_000_000, 251).unwrap();
        let tx = w.op(&buyer, TX_TRADE_OPEN, &b, 0);
        refused(w.one(&tx), "price is 250");

        let paying = w.open(&buyer, &id, 2_000_000);
        let mut paying = paying;
        paying.amount = 5;
        refused(w.one(&paying), "must move 0");

        let unknown = TradeOpenBody {
            offer_id: format!("0x{}", "ab".repeat(32)),
            amount_micro: 2_000_000,
            price_micro: 250,
            fiat_micro: 500,
            method: "sepa".into(),
            payout_address: None,
        };
        let tx = w.op(&buyer, TX_TRADE_OPEN, &unknown, 0);
        assert!(matches!(w.one(&tx), Err(Refusal::Unknown(_))));
    }

    #[test]
    fn an_offer_expires_after_its_lifetime() {
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        let id = w.post_offer(&seller, &sell_offer());
        w.now += OFFER_TTL_SECS;
        let open = w.open(&buyer, &id, 2_000_000);
        refused(w.one(&open), "expired");
        assert_eq!(w.planner().open_offer_count(&seller.addr), 0);
    }

    #[test]
    fn a_taker_may_keep_only_a_few_trades_waiting_for_sellers() {
        let mut w = World::new();
        let buyer = Who::new(9);
        let mut makers = Vec::new();
        for i in 0..=MAX_PENDING_TRADES_PER_TAKER as u8 {
            let m = Who::new(20 + i);
            let id = w.post_offer(&m, &sell_offer());
            makers.push((m, id));
        }
        for (_, id) in makers.iter().take(MAX_PENDING_TRADES_PER_TAKER) {
            let open = w.open(&buyer, id, 2_000_000);
            w.one(&open).unwrap();
        }
        let extra = w.open(&buyer, &makers[MAX_PENDING_TRADES_PER_TAKER].1, 2_000_000);
        refused(w.one(&extra), "waiting for a seller");
        w.now += ACCEPT_WINDOW_SECS;
        let later = w.open(&buyer, &makers[MAX_PENDING_TRADES_PER_TAKER].1, 2_000_000);
        w.one(&later).unwrap();
    }

    #[test]
    fn a_seller_who_never_funds_lets_the_trade_lapse() {
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        let id = w.post_offer(&seller, &sell_offer());
        let open = w.open(&buyer, &id, 2_000_000);
        w.one(&open).unwrap();
        w.now += ACCEPT_WINDOW_SECS;
        assert_eq!(w.trade(&open.hash).status(w.now), "expired");
        let fund = w.trade(&open.hash).locked_micro;
        let lock = w.op(&seller, TX_LOCK, &TradeRef { trade_id: open.hash.clone() }, fund);
        refused(w.one(&lock), "has passed");
        let cancel = w.op(&buyer, TX_TRADE_CANCEL, &TradeRef { trade_id: open.hash.clone() }, 0);
        w.one(&cancel).unwrap();
        assert_eq!(w.trade(&open.hash).state, TradeState::Cancelled);
        assert_eq!(w.trade(&open.hash).closed_by, Some(Role::Buyer));
    }

    #[test]
    fn a_funded_trade_cannot_be_cancelled_only_settled() {
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        let (_, trade) = w.locked_trade(&seller, &buyer);
        let cancel = w.op(&seller, TX_TRADE_CANCEL, &TradeRef { trade_id: trade }, 0);
        refused(w.one(&cancel), "already holds funds");
    }

    #[test]
    fn taking_a_buy_offer_funds_the_escrow_at_once_and_the_buyer_pays_the_fee() {
        let mut w = World::new();
        let buyer = Who::new(1);
        let seller = Who::new(2);
        let mut b = sell_offer();
        b.side = Side::Buy;
        let id = w.post_offer(&buyer, &b);
        let mut open = w.open(&seller, &id, 10_000_000);
        open.amount = 0;
        refused(w.one(&open), "must move 10000000");
        let open = w.open(&seller, &id, 10_000_000);
        w.one(&open).unwrap();
        let t = w.trade(&open.hash);
        assert_eq!(t.state, TradeState::Locked);
        assert_eq!((t.seller.as_str(), t.buyer.as_str()), (seller.addr.as_str(), buyer.addr.as_str()));
        assert_eq!(t.locked_micro, 10_000_000);
        assert_eq!(t.maker_fee_micro, 100_000);
        assert_eq!(w.escrow().held_uegoc, 10_000_000);

        let release = w.settle(&seller, &open.hash, Outcome::Release, Role::Seller);
        assert_eq!(release.to, buyer.addr);
        assert_eq!(release.amount, 10_000_000);
        assert_eq!(release.fee_uegoc, 100_000);
        assert_eq!(crate::ledger::credited_to_recipient(&release), 9_900_000);
        w.one(&release).unwrap();
        assert_eq!(w.escrow(), EscrowTotals::default());
    }

    #[test]
    fn the_happy_path_pays_the_buyer_exactly_the_amount_and_burns_the_fee() {
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        let (_, trade) = w.locked_trade(&seller, &buyer);
        let paid = w.op(&buyer, TX_PAID, &TradeRef { trade_id: trade.clone() }, 0);
        w.one(&paid).unwrap();
        assert_eq!(w.trade(&trade).state, TradeState::Paid);

        let by_buyer = w.settle(&buyer, &trade, Outcome::Release, Role::Buyer);
        refused(w.one(&by_buyer), "only the seller or an arbiter");

        let release = w.settle(&seller, &trade, Outcome::Release, Role::Seller);
        assert_eq!(crate::ledger::credited_to_recipient(&release), 100_000_000);
        assert_eq!(release.fee_uegoc, 1_000_000);
        w.one(&release).unwrap();
        let t = w.trade(&trade);
        assert_eq!(t.state, TradeState::Released);
        assert_eq!(t.settle_tx.as_deref(), Some(release.hash.as_str()));
        assert_eq!(w.escrow(), EscrowTotals::default());

        let s = w.profile(&seller.addr);
        let b = w.profile(&buyer.addr);
        assert_eq!((s.completed, s.as_seller, s.partners, s.volume_uegoc), (1, 1, 1, 100_000_000));
        assert_eq!((b.completed, b.as_buyer, b.partners), (1, 1, 1));
        assert!(w.store.get(&leaderboard_key(1, &seller.addr)).is_some());

        let twice = w.settle(&seller, &trade, Outcome::Release, Role::Seller);
        refused(w.one(&twice), "while it is released");
    }

    #[test]
    fn a_settlement_cannot_be_redirected_or_reshaped() {
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        let thief = Who::new(3);
        let (_, trade) = w.locked_trade(&seller, &buyer);
        let honest = w.settle(&seller, &trade, Outcome::Release, Role::Seller);

        let mut redirected = honest.clone();
        redirected.to = thief.addr.clone();
        refused(w.block(&[&redirected]), "must pay");

        let mut skimmed = honest.clone();
        skimmed.fee_uegoc = 0;
        refused(w.block(&[&skimmed]), "must pay");

        let mut rehashed = honest.clone();
        rehashed.hash = format!("0x{}", "00".repeat(32));
        refused(w.block(&[&rehashed]), "body/hash");

        let mut padded = honest.clone();
        padded.call_args = format!(" {}", honest.call_args);
        refused(w.block(&[&padded]), "canonical");

        let mut signed_tx = honest.clone();
        signed_tx.signature = "00".into();
        refused(w.block(&[&signed_tx]), "not a signature");

        let forged = w.settle(&thief, &trade, Outcome::Release, Role::Seller);
        refused(w.block(&[&forged]), "not signed by the trade's seller");

        let mut swapped = seller.auth(&trade, Outcome::Release, Role::Seller);
        swapped.outcome = Outcome::Refund;
        let swapped = settle_tx(&swapped, &w.trade(&trade), w.now);
        refused(w.block(&[&swapped]), "does not verify");

        w.block(&[&honest]).unwrap();
    }

    #[test]
    fn the_seller_reclaims_only_an_unpaid_trade_after_the_window() {
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        let (_, trade) = w.locked_trade(&seller, &buyer);
        let early = w.settle(&seller, &trade, Outcome::Refund, Role::Seller);
        refused(w.one(&early), "has until");
        w.now += 3_600;
        assert_eq!(w.trade(&trade).status(w.now), "payment_overdue");
        let reclaim = w.settle(&seller, &trade, Outcome::Refund, Role::Seller);
        assert_eq!(reclaim.to, seller.addr);
        assert_eq!(reclaim.fee_uegoc, 0);
        assert_eq!(reclaim.amount, 101_000_000);
        w.one(&reclaim).unwrap();
        assert_eq!(w.trade(&trade).state, TradeState::Refunded);
        assert_eq!(w.profile(&buyer.addr).timed_out, 1);
        assert_eq!(w.profile(&seller.addr).completed, 0);
    }

    #[test]
    fn once_paid_the_seller_cannot_reclaim_even_after_the_window() {
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        let (_, trade) = w.locked_trade(&seller, &buyer);
        w.now += 3_000;
        let paid = w.op(&buyer, TX_PAID, &TradeRef { trade_id: trade.clone() }, 0);
        w.one(&paid).unwrap();
        w.now += 10_000;
        let reclaim = w.settle(&seller, &trade, Outcome::Refund, Role::Seller);
        refused(w.one(&reclaim), "only while it is unpaid");
    }

    #[test]
    fn the_buyer_may_always_hand_the_funds_back() {
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        let (_, trade) = w.locked_trade(&seller, &buyer);
        let back = w.settle(&buyer, &trade, Outcome::Refund, Role::Buyer);
        w.one(&back).unwrap();
        assert_eq!(w.trade(&trade).state, TradeState::Refunded);
        assert_eq!(w.profile(&buyer.addr).cancelled, 1);
    }

    #[test]
    fn disputes_wait_for_payment_and_the_buyer_waits_longer() {
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        let arbiter = Who::new(7);
        w.arbiters = vec![arbiter.addr.clone()];
        let (_, trade) = w.locked_trade(&seller, &buyer);
        let reason = |s: &str| DisputeBody { trade_id: trade.clone(), reason: s.into() };
        let too_soon = w.op(&seller, TX_DISPUTE, &reason("no payment"), 0);
        refused(w.one(&too_soon), "only after the buyer marks it paid");

        let paid = w.op(&buyer, TX_PAID, &TradeRef { trade_id: trade.clone() }, 0);
        w.one(&paid).unwrap();
        let impatient = w.op(&buyer, TX_DISPUTE, &reason("seller silent"), 0);
        refused(w.one(&impatient), "before the buyer can dispute");
        w.now += BUYER_DISPUTE_DELAY_SECS;
        let dispute = w.op(&buyer, TX_DISPUTE, &reason("seller silent"), 0);
        w.one(&dispute).unwrap();
        let t = w.trade(&trade);
        assert_eq!(t.state, TradeState::Disputed);
        assert_eq!(t.arbiter.as_deref(), Some(arbiter.addr.as_str()));
        assert_eq!(t.disputed_by, Some(Role::Buyer));
        assert_eq!(w.profile(&buyer.addr).disputes_opened, 1);

        let stranger = Who::new(8);
        let fake = w.settle(&stranger, &trade, Outcome::Release, Role::Arbiter);
        refused(w.one(&fake), "not signed by the trade's arbiter");
        let ruling = w.settle(&arbiter, &trade, Outcome::Release, Role::Arbiter);
        w.one(&ruling).unwrap();
        assert_eq!(w.trade(&trade).state, TradeState::Released);
        assert_eq!(w.profile(&buyer.addr).disputes_won, 1);
        assert_eq!(w.profile(&seller.addr).disputes_lost, 1);
    }

    #[test]
    fn an_arbiter_never_judges_their_own_trade() {
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        w.arbiters = vec![seller.addr.clone()];
        let (_, trade) = w.locked_trade(&seller, &buyer);
        let paid = w.op(&buyer, TX_PAID, &TradeRef { trade_id: trade.clone() }, 0);
        w.one(&paid).unwrap();
        let dispute = w.op(&seller, TX_DISPUTE, &DisputeBody { trade_id: trade.clone(), reason: String::new() }, 0);
        refused(w.one(&dispute), "no impartial arbiter");

        let fair = Who::new(7);
        w.arbiters = vec![seller.addr.clone(), fair.addr.clone()];
        w.one(&dispute).unwrap();
        assert_eq!(w.trade(&trade).arbiter.as_deref(), Some(fair.addr.as_str()));
    }

    #[test]
    fn an_arbiter_refund_returns_everything_to_the_seller() {
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        let arbiter = Who::new(7);
        w.arbiters = vec![arbiter.addr.clone()];
        let (_, trade) = w.locked_trade(&seller, &buyer);
        let paid = w.op(&buyer, TX_PAID, &TradeRef { trade_id: trade.clone() }, 0);
        w.one(&paid).unwrap();
        let dispute = w.op(&seller, TX_DISPUTE, &DisputeBody { trade_id: trade.clone(), reason: "nothing arrived".into() }, 0);
        w.one(&dispute).unwrap();
        let early_ruling_by_seller = w.settle(&seller, &trade, Outcome::Refund, Role::Seller);
        refused(w.one(&early_ruling_by_seller), "only while it is unpaid");
        let ruling = w.settle(&arbiter, &trade, Outcome::Refund, Role::Arbiter);
        assert_eq!(ruling.to, seller.addr);
        assert_eq!(ruling.amount, 101_000_000);
        assert_eq!(ruling.fee_uegoc, 0);
        w.one(&ruling).unwrap();
        assert_eq!(w.profile(&seller.addr).disputes_won, 1);
        assert_eq!(w.profile(&buyer.addr).disputes_lost, 1);
    }

    #[test]
    fn one_change_per_trade_per_block() {
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        let (_, trade) = w.locked_trade(&seller, &buyer);
        w.now += 3_600;
        let paid = w.op(&buyer, TX_PAID, &TradeRef { trade_id: trade.clone() }, 0);
        let reclaim = w.settle(&seller, &trade, Outcome::Refund, Role::Seller);
        let mut p = w.planner();
        p.admit(&paid).unwrap();
        assert!(matches!(p.admit(&reclaim), Err(Refusal::Conflict(_))));
        let release = w.settle(&seller, &trade, Outcome::Release, Role::Seller);
        let mut p = w.planner();
        p.admit(&release).unwrap();
        assert!(matches!(p.admit(&reclaim), Err(Refusal::Conflict(_))));
    }

    #[test]
    fn feedback_follows_a_finished_trade_once_per_side() {
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        let (_, trade) = w.locked_trade(&seller, &buyer);
        let early = w.op(&buyer, TX_FEEDBACK, &FeedbackBody { trade_id: trade.clone(), rating: Rating::Positive, comment: String::new() }, 0);
        refused(w.one(&early), "has not finished");
        let release = w.settle(&seller, &trade, Outcome::Release, Role::Seller);
        w.one(&release).unwrap();

        let from_buyer = w.op(&buyer, TX_FEEDBACK, &FeedbackBody { trade_id: trade.clone(), rating: Rating::Positive, comment: "fast release".into() }, 0);
        let from_seller = w.op(&seller, TX_FEEDBACK, &FeedbackBody { trade_id: trade.clone(), rating: Rating::Negative, comment: "late payment".into() }, 0);
        w.block(&[&from_buyer, &from_seller]).unwrap();
        assert_eq!(w.profile(&seller.addr).positive, 1);
        assert_eq!(w.profile(&buyer.addr).negative, 1);

        let again = w.op(&buyer, TX_FEEDBACK, &FeedbackBody { trade_id: trade.clone(), rating: Rating::Negative, comment: String::new() }, 0);
        refused(w.one(&again), "already left feedback");
        let stranger = Who::new(5);
        let meddling = w.op(&stranger, TX_FEEDBACK, &FeedbackBody { trade_id: trade.clone(), rating: Rating::Negative, comment: String::new() }, 0);
        refused(w.one(&meddling), "only the buyer or the seller");
    }

    #[test]
    fn two_trades_between_the_same_pair_in_one_block_count_one_partner() {
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        let (_, first) = w.locked_trade(&seller, &buyer);
        let (_, second) = w.locked_trade(&seller, &buyer);
        let a = w.settle(&seller, &first, Outcome::Release, Role::Seller);
        let b = w.settle(&seller, &second, Outcome::Release, Role::Seller);
        w.block(&[&a, &b]).unwrap();
        let p = w.profile(&seller.addr);
        assert_eq!((p.completed, p.partners), (2, 1));
        assert!(w.store.get(&leaderboard_key(1, &seller.addr)).is_none());
        assert!(w.store.get(&leaderboard_key(2, &seller.addr)).is_some());
    }

    #[test]
    fn a_block_means_the_same_in_any_order() {
        let mut base = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        let other = Who::new(3);
        base.arbiters = vec![Who::new(7).addr];
        let (offer, t1) = base.locked_trade(&seller, &buyer);
        let (_, t2) = base.locked_trade(&seller, &other);
        let paid = base.op(&other, TX_PAID, &TradeRef { trade_id: t2.clone() }, 0);
        base.one(&paid).unwrap();

        let txs = vec![
            base.settle(&seller, &t1, Outcome::Release, Role::Seller),
            base.settle(&other, &t2, Outcome::Refund, Role::Buyer),
            base.op(&seller, TX_OFFER, &sell_offer(), 0),
            base.op(&seller, TX_OFFER_CLOSE, &OfferRef { offer_id: offer.clone() }, 0),
            base.open(&other, &offer, 3_000_000),
        ];
        let orders: [[usize; 5]; 4] = [[0, 1, 2, 3, 4], [4, 3, 2, 1, 0], [2, 0, 4, 1, 3], [3, 4, 0, 2, 1]];
        let mut results = Vec::new();
        for order in orders {
            let mut p = base.planner();
            for i in order {
                p.admit(&txs[i]).unwrap();
            }
            results.push(p.finish().writes);
        }
        assert!(results.windows(2).all(|w| w[0] == w[1]));
    }

    #[test]
    fn the_lenient_plan_drops_what_does_not_hold_and_keeps_the_rest() {
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        let (_, trade) = w.locked_trade(&seller, &buyer);
        let release = w.settle(&seller, &trade, Outcome::Release, Role::Seller);
        let refund = w.settle(&buyer, &trade, Outcome::Refund, Role::Buyer);
        let mut both = [&release, &refund];
        both.sort_by(|a, b| a.hash.cmp(&b.hash));
        let mut p = w.planner();
        let mut rejected = Vec::new();
        for tx in both {
            if p.admit(tx).is_err() {
                rejected.push(tx.hash.clone());
            }
        }
        assert_eq!(rejected, vec![both[1].hash.clone()]);
    }

    #[test]
    fn the_chain_clock_is_the_median_of_recent_blocks() {
        assert_eq!(median(&mut []), 0);
        assert_eq!(median(&mut [5]), 5);
        assert_eq!(median(&mut [9, 1, 5]), 5);
        assert_eq!(median(&mut [1, 100, 2, 3]), 3);
        assert_eq!(median(&mut [i64::MAX, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]), 15);
    }

    #[test]
    fn the_settle_message_names_the_chain_trade_outcome_and_role() {
        let id = format!("0x{}", "cd".repeat(32));
        assert_eq!(
            settle_message(&id, Outcome::Refund, Role::Seller),
            format!("ego/market/auth/v1:1:{id}:refund:seller")
        );
    }

    #[test]
    fn op_memos_bind_the_body_and_only_market_types() {
        let m = op_memo(TX_PAID, "{\"trade_id\":\"x\"}").unwrap();
        assert!(m.starts_with("market:paid:"));
        assert_eq!(m.len(), "market:paid:".len() + 64);
        assert!(m.len() <= 256);
        assert_ne!(m, op_memo(TX_PAID, "{\"trade_id\":\"y\"}").unwrap());
        assert_eq!(op_memo("market_settle", "{}"), None);
        assert_eq!(op_memo("transfer", "{}"), None);
        let longest = SIGNED_OPS.iter().map(|op| op_memo(op, "").unwrap().len()).max().unwrap();
        assert!(longest <= 256);
    }

    #[test]
    fn the_journal_undoes_a_block_exactly() {
        let _g = crate::shielded::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let db = chain_db::get_db().lock().unwrap_or_else(|e| e.into_inner());
        let cf = db.cf_handle(CF_META).unwrap();
        let base = chain_db::finality_floor_height(db).max(930_000_000) + 1 + (std::process::id() as u64 % 997) * 1_000;
        let tag = format!("{base:x}");
        let kept = format!("market:test:{tag}:kept").into_bytes();
        let changed = format!("market:test:{tag}:changed").into_bytes();
        let created = format!("market:test:{tag}:created").into_bytes();
        db.put_cf(cf, &kept, b"k").unwrap();
        db.put_cf(cf, &changed, b"before").unwrap();

        let mut first = Plan::default();
        first.writes.insert(changed.clone(), Some(b"middle".to_vec()));
        first.writes.insert(created.clone(), Some(b"new".to_vec()));
        first.rejected.push("0xdead".into());
        let mut batch = WriteBatch::default();
        apply_plan(db, &mut batch, base, &first);
        db.write(batch).unwrap();

        let mut second = Plan::default();
        second.writes.insert(changed.clone(), Some(b"after".to_vec()));
        second.writes.insert(kept.clone(), None);
        let mut batch = WriteBatch::default();
        apply_plan(db, &mut batch, base + 1, &second);
        db.write(batch).unwrap();
        assert_eq!(db.get_cf(cf, &changed).unwrap().as_deref(), Some(&b"after"[..]));
        assert!(rejected_since(db, base).contains("0xdead"));
        assert!(!rejected_since(db, base + 1).contains("0xdead"));

        let mut batch = WriteBatch::default();
        rollback(db, &mut batch, base + 1);
        db.write(batch).unwrap();
        assert_eq!(db.get_cf(cf, &changed).unwrap().as_deref(), Some(&b"middle"[..]));
        assert_eq!(db.get_cf(cf, &kept).unwrap().as_deref(), Some(&b"k"[..]));

        let mut batch = WriteBatch::default();
        apply_plan(db, &mut batch, base + 1, &second);
        db.write(batch).unwrap();
        let mut batch = WriteBatch::default();
        rollback(db, &mut batch, base);
        db.write(batch).unwrap();
        assert_eq!(db.get_cf(cf, &changed).unwrap().as_deref(), Some(&b"before"[..]));
        assert_eq!(db.get_cf(cf, &kept).unwrap().as_deref(), Some(&b"k"[..]));
        assert!(db.get_cf(cf, &created).unwrap().is_none());
        assert!(journals_since(db, base)
            .iter()
            .all(|(k, _)| *k != undo_key(base) && *k != undo_key(base + 1)));
        for k in [&kept, &changed, &created] {
            db.delete_cf(cf, k).unwrap();
        }
    }

    #[test]
    fn a_reversed_settlement_puts_the_money_back_in_escrow() {
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        let (_, trade) = w.locked_trade(&seller, &buyer);
        let release = w.settle(&seller, &trade, Outcome::Release, Role::Seller);
        let mut out = HashMap::new();
        assert!(reverse_balance_delta(&release, &mut out));
        assert_eq!(out[&buyer.addr], -100_000_000);
        assert_eq!(out[MARKET_ESCROW_ADDR], 101_000_000);
        let lock = w.op(&seller, TX_LOCK, &TradeRef { trade_id: trade }, 1);
        assert!(!reverse_balance_delta(&lock, &mut HashMap::new()));
    }

    #[test]
    fn the_market_stays_off_unless_switched_on() {
        let _g = crate::shielded::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("EGO_MARKET_HEIGHT");
        assert_eq!(rule_active(5), ACTIVATION_HEIGHT.is_some_and(|h| 5 >= h));
        std::env::set_var("EGO_MARKET_HEIGHT", "10");
        assert!(!rule_active(9));
        assert!(rule_active(10));
        std::env::remove_var("EGO_MARKET_HEIGHT");
    }


    const TRON_BUYER: &str = "TJRabPrwbZy45sbavfcjinPJC18kjpRTv8";
    const TRON_JUDGE: &str = "TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7";
    const TRON_ESCROW: &str = "TQn9Y2khEsLJW1ChVWFMSMeRDow5KcbLSE";
    const TRON_SELLER: &str = "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf";
    const EVM_JUDGE: &str = "0x8Ba1f109551bD432803012645Ac136ddd64DBA72";

    fn usdt_offer(side: Side, payout: Option<&str>) -> OfferBody {
        OfferBody {
            side,
            asset: "USDT-TRC20".into(),
            fiat: "USD".into(),
            price: Price::Fixed(1_000_000),
            min_micro: 10_000_000,
            max_micro: 1_000_000_000,
            methods: vec!["wise".into()],
            country: None,
            terms: String::new(),
            payment_window_secs: 900,
            payout_address: payout.map(str::to_string),
        }
    }

    fn publish_judge(w: &mut World, judge: &Who) {
        w.arbiters = vec![judge.addr.clone()];
        let tx = w.op(
            judge,
            TX_ARBITER,
            &ArbiterBody { evm: Some(EVM_JUDGE.into()), tron: Some(TRON_JUDGE.into()), ..Default::default() },
            0,
        );
        w.one(&tx).unwrap();
    }

    fn open_usdt(w: &mut World, taker: &Who, offer_id: &str, amount: u64, payout: Option<&str>) -> LedgerTx {
        let body = TradeOpenBody {
            offer_id: offer_id.into(),
            amount_micro: amount,
            price_micro: 1_000_000,
            fiat_micro: fiat_for(amount, 1_000_000).unwrap(),
            method: "wise".into(),
            payout_address: payout.map(str::to_string),
        };
        w.op(taker, TX_TRADE_OPEN, &body, 0)
    }

    fn tron_escrow() -> EscrowRef {
        EscrowRef { contract: TRON_ESCROW.into(), funder: TRON_SELLER.into(), tx: "ab".repeat(32) }
    }

    fn usdt_locked(w: &mut World, seller: &Who, buyer: &Who) -> String {
        let offer = w.post_offer(seller, &usdt_offer(Side::Sell, None));
        let open = open_usdt(w, buyer, &offer, 100_000_000, Some(TRON_BUYER));
        w.one(&open).unwrap();
        let lock = w.op(seller, TX_LOCK, &LockBody { trade_id: open.hash.clone(), escrow: Some(tron_escrow()) }, 0);
        w.one(&lock).unwrap();
        open.hash
    }

    #[test]
    fn usdt_offers_name_a_payout_address_only_when_buying() {
        let maker = Who::new(1);
        let cases: Vec<(OfferBody, &str)> = vec![
            (usdt_offer(Side::Sell, Some(TRON_BUYER)), "names the payout address when taking"),
            (usdt_offer(Side::Buy, None), "say where you receive USDT on tron"),
            (usdt_offer(Side::Buy, Some(EVM_JUDGE)), "is not a tron address"),
            (usdt_offer(Side::Buy, Some("T0000000000000000000000000000000O")), "is not a tron address"),
            (OfferBody { payout_address: Some(TRON_BUYER.into()), ..sell_offer() }, "EGOC offers take no payout"),
            (OfferBody { asset: "DOGE".into(), ..sell_offer() }, "not traded on this market"),
        ];
        for (body, needle) in cases {
            let mut w = World::new();
            let tx = w.op(&maker, TX_OFFER, &body, 0);
            refused(w.one(&tx), needle);
        }
        let mut w = World::new();
        let id = w.post_offer(&maker, &usdt_offer(Side::Buy, Some(TRON_BUYER)));
        assert_eq!(w.offer(&id).payout_address.as_deref(), Some(TRON_BUYER));
        assert!(w.store.get(&book_key("USDT-TRC20", "USD", Side::Buy, 100, &id)).is_some());
        assert!(w.store.get(&book_key(EGOC, "USD", Side::Buy, 100, &id)).is_none());
    }

    #[test]
    fn small_foreign_amounts_are_fine_where_egoc_keeps_its_minimum() {
        let maker = Who::new(1);
        let mut w = World::new();
        let body = OfferBody { min_micro: 1, max_micro: 5, ..usdt_offer(Side::Buy, Some(TRON_BUYER)) };
        let tx = w.op(&maker, TX_OFFER, &body, 0);
        w.one(&tx).unwrap();
        let egoc = OfferBody { min_micro: 1, ..sell_offer() };
        let tx = w.op(&maker, TX_OFFER, &egoc, 0);
        refused(w.one(&tx), "trade limits");
    }

    #[test]
    fn foreign_trades_open_only_once_an_arbiter_can_hold_the_escrow() {
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        let judge = Who::new(7);
        w.arbiters = vec![judge.addr.clone()];
        let offer = w.post_offer(&seller, &usdt_offer(Side::Sell, None));
        let open = open_usdt(&mut w, &buyer, &offer, 100_000_000, Some(TRON_BUYER));
        refused(w.one(&open), "no arbiter has published a tron address");

        publish_judge(&mut w, &judge);
        let missing = open_usdt(&mut w, &buyer, &offer, 100_000_000, None);
        refused(w.one(&missing), "must say where to receive USDT on tron");
        let wrong = open_usdt(&mut w, &buyer, &offer, 100_000_000, Some(EVM_JUDGE));
        refused(w.one(&wrong), "is not a tron address");
        let mut paying = open_usdt(&mut w, &buyer, &offer, 100_000_000, Some(TRON_BUYER));
        paying.amount = 1;
        refused(w.one(&paying), "must move 0");

        let open = open_usdt(&mut w, &buyer, &offer, 100_000_000, Some(TRON_BUYER));
        w.one(&open).unwrap();
        let t = w.trade(&open.hash);
        assert_eq!(t.asset, "USDT-TRC20");
        assert_eq!(t.state, TradeState::AwaitingLock);
        assert_eq!(t.buyer_payout.as_deref(), Some(TRON_BUYER));
        assert_eq!(t.arbiter.as_deref(), Some(judge.addr.as_str()));
        assert_eq!(t.arbiter_payout.as_deref(), Some(TRON_JUDGE));
        assert_eq!(t.locked_micro, 101_000_000);
        assert_eq!(t.fiat_micro, 100_000_000);
    }

    #[test]
    fn only_arbiters_publish_their_outside_addresses() {
        let mut w = World::new();
        let judge = Who::new(7);
        let stranger = Who::new(8);
        w.arbiters = vec![judge.addr.clone()];
        let by_stranger = w.op(&stranger, TX_ARBITER, &ArbiterBody { evm: Some(EVM_JUDGE.into()), tron: None, ..Default::default() }, 0);
        refused(w.one(&by_stranger), "only an arbiter");
        let empty = w.op(&judge, TX_ARBITER, &ArbiterBody { evm: None, tron: None, ..Default::default() }, 0);
        refused(w.one(&empty), "at least one address");
        let bad = w.op(&judge, TX_ARBITER, &ArbiterBody { evm: Some("0x123".into()), tron: None, ..Default::default() }, 0);
        refused(w.one(&bad), "40 hex digits");
        let good = w.op(&judge, TX_ARBITER, &ArbiterBody { evm: Some(EVM_JUDGE.into()), tron: Some(TRON_JUDGE.into()), ..Default::default() }, 0);
        w.one(&good).unwrap();
        let only_evm = w.op(&judge, TX_ARBITER, &ArbiterBody { evm: Some(EVM_JUDGE.into()), tron: None, ..Default::default() }, 0);
        w.one(&only_evm).unwrap();
        let rec: ArbiterAddresses = read(&w.store, &arbiter_addr_key(&judge.addr)).unwrap();
        assert_eq!(rec.evm.as_deref(), Some(EVM_JUDGE));
        assert_eq!(rec.tron, None, "a new record replaces the old one whole");
    }

    #[test]
    fn a_foreign_lock_records_the_outside_escrow_and_moves_no_egoc() {
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        publish_judge(&mut w, &Who::new(7));
        let offer = w.post_offer(&seller, &usdt_offer(Side::Sell, None));
        let open = open_usdt(&mut w, &buyer, &offer, 100_000_000, Some(TRON_BUYER));
        w.one(&open).unwrap();
        let lock = |w: &mut World, escrow: Option<EscrowRef>, amount: u64| {
            w.op(&seller, TX_LOCK, &LockBody { trade_id: open.hash.clone(), escrow }, amount)
        };
        let tx = lock(&mut w, Some(tron_escrow()), 101_000_000);
        refused(w.one(&tx), "moves no EGOC");
        let tx = lock(&mut w, None, 0);
        refused(w.one(&tx), "say where the escrow was funded");
        let tx = lock(&mut w, Some(EscrowRef { tx: "0x".to_string() + &"ab".repeat(32), ..tron_escrow() }), 0);
        refused(w.one(&tx), "is not a tron contract");
        let tx = lock(&mut w, Some(tron_escrow()), 0);
        w.one(&tx).unwrap();
        let t = w.trade(&open.hash);
        assert_eq!(t.state, TradeState::Locked);
        assert_eq!(t.escrow, Some(tron_escrow()));
        assert_eq!(w.escrow(), EscrowTotals::default(), "the Ego escrow holds nothing for outside coins");
    }

    #[test]
    fn an_egoc_lock_refuses_an_outside_escrow() {
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        let offer = w.post_offer(&seller, &sell_offer());
        let open = w.open(&buyer, &offer, 100_000_000);
        w.one(&open).unwrap();
        let lock = w.op(&seller, TX_LOCK, &LockBody { trade_id: open.hash.clone(), escrow: Some(tron_escrow()) }, 101_000_000);
        refused(w.one(&lock), "no outside escrow applies");
    }

    #[test]
    fn foreign_settlements_move_no_egoc_and_count_no_egoc_volume() {
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        publish_judge(&mut w, &Who::new(7));
        let trade = usdt_locked(&mut w, &seller, &buyer);
        let release = w.settle(&seller, &trade, Outcome::Release, Role::Seller);
        assert_eq!((release.amount, release.fee_uegoc), (0, 0));
        let mut paying = release.clone();
        paying.amount = 101_000_000;
        refused(w.one(&paying), "must pay 0 uEGOC");
        w.one(&release).unwrap();
        assert_eq!(w.trade(&trade).state, TradeState::Released);
        let p = w.profile(&seller.addr);
        assert_eq!((p.completed, p.volume_uegoc), (1, 0));
        assert_eq!(w.escrow(), EscrowTotals::default());
    }

    #[test]
    fn foreign_escrow_has_no_seller_timer_but_a_no_show_can_be_disputed() {
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        let judge = Who::new(7);
        publish_judge(&mut w, &judge);
        let trade = usdt_locked(&mut w, &seller, &buyer);
        let early = w.op(&seller, TX_DISPUTE, &DisputeBody { trade_id: trade.clone(), reason: "no payment".into() }, 0);
        refused(w.one(&early), "only after the buyer marks it paid");
        w.now += 900;
        let reclaim = w.settle(&seller, &trade, Outcome::Refund, Role::Seller);
        refused(w.one(&reclaim), "through the buyer or the arbiter");
        let late = w.op(&seller, TX_DISPUTE, &DisputeBody { trade_id: trade.clone(), reason: "no payment".into() }, 0);
        w.one(&late).unwrap();
        let t = w.trade(&trade);
        assert_eq!(t.state, TradeState::Disputed);
        assert_eq!(t.arbiter.as_deref(), Some(judge.addr.as_str()));
        let ruling = w.settle(&judge, &trade, Outcome::Refund, Role::Arbiter);
        w.one(&ruling).unwrap();
        assert_eq!(w.trade(&trade).state, TradeState::Refunded);
    }

    #[test]
    fn an_outside_signature_rides_only_on_foreign_settlements_and_is_signed_over() {
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        publish_judge(&mut w, &Who::new(7));
        let native = "11".repeat(65);
        let with_sig = |who: &Who, trade_id: &str, outcome: Outcome, by: Role, sig: &str| {
            let message = settle_auth_message(trade_id, outcome, by, Some(sig));
            let signature = who.key.sign(message.as_bytes());
            SettleBody {
                trade_id: trade_id.to_string(),
                outcome,
                by,
                pubkey: hex::encode(who.key.verifying_key().to_bytes()),
                signature: hex::encode(signature.to_bytes()),
                native_sig: Some(sig.to_string()),
            }
        };

        let egoc_trade = {
            let (_, t) = w.locked_trade(&seller, &buyer);
            t
        };
        let body = with_sig(&buyer, &egoc_trade, Outcome::Refund, Role::Buyer, &native);
        let tx = settle_tx(&body, &w.trade(&egoc_trade), w.now);
        refused(w.one(&tx), "carries no outside signature");

        let trade = usdt_locked(&mut w, &seller, &buyer);
        let mut swapped = with_sig(&buyer, &trade, Outcome::Refund, Role::Buyer, &native);
        swapped.native_sig = Some("22".repeat(65));
        let tx = settle_tx(&swapped, &w.trade(&trade), w.now);
        refused(w.one(&tx), "does not verify");
        let mut short = with_sig(&buyer, &trade, Outcome::Refund, Role::Buyer, "ab");
        short.native_sig = Some("ab".into());
        let tx = settle_tx(&short, &w.trade(&trade), w.now);
        refused(w.one(&tx), "hex bytes");

        let body = with_sig(&buyer, &trade, Outcome::Refund, Role::Buyer, &native);
        let tx = settle_tx(&body, &w.trade(&trade), w.now);
        w.one(&tx).unwrap();
        let t = w.trade(&trade);
        assert_eq!(t.state, TradeState::Refunded);
        assert_eq!(t.native_sig.as_deref(), Some(native.as_str()));
    }

    #[test]
    fn a_foreign_buy_offer_pays_the_makers_named_address() {
        let mut w = World::new();
        let buyer = Who::new(1);
        let seller = Who::new(2);
        publish_judge(&mut w, &Who::new(7));
        let offer = w.post_offer(&buyer, &usdt_offer(Side::Buy, Some(TRON_BUYER)));
        let named = open_usdt(&mut w, &seller, &offer, 50_000_000, Some(TRON_SELLER));
        refused(w.one(&named), "already named their payout address");
        let open = open_usdt(&mut w, &seller, &offer, 50_000_000, None);
        w.one(&open).unwrap();
        let t = w.trade(&open.hash);
        assert_eq!((t.seller.as_str(), t.buyer.as_str()), (seller.addr.as_str(), buyer.addr.as_str()));
        assert_eq!(t.state, TradeState::AwaitingLock, "the seller still has to fund the outside escrow");
        assert_eq!(t.buyer_payout.as_deref(), Some(TRON_BUYER));
        assert_eq!(t.locked_micro, 50_000_000);
        assert_eq!(t.maker_fee_micro, 500_000);
    }

    fn sol_key(tag: u8) -> SigningKey {
        SigningKey::from_bytes(&[tag; 32])
    }

    fn sol_addr(tag: u8) -> String {
        crate::escrow::solana::b58(&sol_key(tag).verifying_key().to_bytes())
    }

    fn ada_addr(tag: u8) -> String {
        use crate::escrow::cardano as ada;
        let pkh = ada::blake2b_224(&sol_key(tag).verifying_key().to_bytes());
        ada::format_address(&ada::key_address(0, &pkh))
    }

    fn ada_script() -> String {
        use crate::escrow::cardano as ada;
        ada::format_address(&ada::script_address(0, &ada::script_hash()))
    }

    const SOL_PROGRAM: [u8; 32] = [0x42; 32];

    fn coin_offer(asset: &str, side: Side, payout: Option<String>, min_micro: u64) -> OfferBody {
        OfferBody {
            side,
            asset: asset.into(),
            fiat: "USD".into(),
            price: Price::Fixed(1_000_000),
            min_micro,
            max_micro: 1_000_000_000_000,
            methods: vec!["wise".into()],
            country: None,
            terms: String::new(),
            payment_window_secs: 900,
            payout_address: payout,
        }
    }

    fn publish_everywhere(w: &mut World, judge: &Who) {
        w.arbiters = vec![judge.addr.clone()];
        let body = ArbiterBody {
            evm: Some(EVM_JUDGE.into()),
            tron: Some(TRON_JUDGE.into()),
            sol: Some(sol_addr(70)),
            ada: Some(ada_addr(70)),
        };
        let tx = w.op(judge, TX_ARBITER, &body, 0);
        w.one(&tx).unwrap();
    }

    fn open_coin(w: &mut World, taker: &Who, offer_id: &str, amount: u64, payout: Option<String>) -> LedgerTx {
        let body = TradeOpenBody {
            offer_id: offer_id.into(),
            amount_micro: amount,
            price_micro: 1_000_000,
            fiat_micro: fiat_for(amount, 1_000_000).unwrap(),
            method: "wise".into(),
            payout_address: payout,
        };
        w.op(taker, TX_TRADE_OPEN, &body, 0)
    }

    fn refund_with(w: &World, buyer: &Who, trade_id: &str, native: &str) -> LedgerTx {
        let message = settle_auth_message(trade_id, Outcome::Refund, Role::Buyer, Some(native));
        let body = SettleBody {
            trade_id: trade_id.to_string(),
            outcome: Outcome::Refund,
            by: Role::Buyer,
            pubkey: hex::encode(buyer.key.verifying_key().to_bytes()),
            signature: hex::encode(buyer.key.sign(message.as_bytes()).to_bytes()),
            native_sig: Some(native.to_string()),
        };
        settle_tx(&body, &w.trade(trade_id), w.now)
    }

    fn id_bytes(trade_id: &str) -> [u8; 32] {
        hex::decode(trade_id.trim_start_matches("0x")).unwrap().try_into().unwrap()
    }

    #[test]
    fn solana_and_cardano_payouts_follow_their_own_address_rules() {
        let maker = Who::new(1);
        let mainnet = {
            use crate::escrow::cardano as ada;
            ada::format_address(&ada::key_address(1, &[9; 28]))
        };
        let cases: Vec<(OfferBody, &str)> = vec![
            (coin_offer("SOL", Side::Buy, Some(EVM_JUDGE.into()), 10_000), "is not a solana address"),
            (coin_offer("SOL", Side::Buy, Some("1111".into()), 10_000), "is not a solana address"),
            (coin_offer("SOL", Side::Buy, Some(sol_addr(3)), 9_999), "trade limits"),
            (coin_offer("USDC-SPL", Side::Buy, None, 1), "say where you receive USDC on solana"),
            (coin_offer("ADA", Side::Buy, Some(mainnet), 10_000_000), "is not a cardano address"),
            (coin_offer("ADA", Side::Buy, Some(ada_script()), 10_000_000), "is not a cardano address"),
            (coin_offer("ADA", Side::Buy, Some(sol_addr(3)), 10_000_000), "is not a cardano address"),
            (coin_offer("ADA", Side::Buy, Some(ada_addr(3)), 9_999_999), "trade limits"),
        ];
        for (body, needle) in cases {
            let mut w = World::new();
            let tx = w.op(&maker, TX_OFFER, &body, 0);
            refused(w.one(&tx), needle);
        }
        let mut w = World::new();
        for body in [
            coin_offer("SOL", Side::Buy, Some(sol_addr(3)), 10_000),
            coin_offer("USDT-SPL", Side::Buy, Some(sol_addr(3)), 1),
            coin_offer("ADA", Side::Buy, Some(ada_addr(3)), 10_000_000),
            coin_offer("ADA", Side::Sell, None, 10_000_000),
        ] {
            let tx = w.op(&maker, TX_OFFER, &body, 0);
            w.one(&tx).unwrap();
        }
    }

    #[test]
    fn arbiters_publish_solana_and_cardano_addresses_for_their_trades() {
        let mut w = World::new();
        let judge = Who::new(7);
        w.arbiters = vec![judge.addr.clone()];
        let bad_sol = w.op(&judge, TX_ARBITER, &ArbiterBody { sol: Some("0xabc".into()), ..Default::default() }, 0);
        refused(w.one(&bad_sol), "32-byte base58");
        let bad_ada = w.op(&judge, TX_ARBITER, &ArbiterBody { ada: Some(ada_script()), ..Default::default() }, 0);
        refused(w.one(&bad_ada), "testnet key address");
        let only_ada = w.op(&judge, TX_ARBITER, &ArbiterBody { ada: Some(ada_addr(70)), ..Default::default() }, 0);
        w.one(&only_ada).unwrap();

        let seller = Who::new(1);
        let buyer = Who::new(2);
        let sol_offer = w.post_offer(&seller, &coin_offer("SOL", Side::Sell, None, 10_000));
        let open = open_coin(&mut w, &buyer, &sol_offer, 2_000_000, Some(sol_addr(2)));
        refused(w.one(&open), "no arbiter has published a solana address");

        publish_everywhere(&mut w, &judge);
        let open = open_coin(&mut w, &buyer, &sol_offer, 2_000_000, Some(sol_addr(2)));
        w.one(&open).unwrap();
        let t = w.trade(&open.hash);
        assert_eq!(t.arbiter_payout, Some(sol_addr(70)));
        assert_eq!(t.buyer_payout, Some(sol_addr(2)));

        let ada_offer = w.post_offer(&seller, &coin_offer("ADA", Side::Sell, None, 10_000_000));
        let open = open_coin(&mut w, &buyer, &ada_offer, 25_000_000, Some(ada_addr(2)));
        w.one(&open).unwrap();
        assert_eq!(w.trade(&open.hash).arbiter_payout, Some(ada_addr(70)));
    }

    #[test]
    fn a_solana_refund_needs_the_buyers_signature_for_this_escrow() {
        use crate::escrow::solana as sol;
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        publish_everywhere(&mut w, &Who::new(7));
        let offer = w.post_offer(&seller, &coin_offer("USDC-SPL", Side::Sell, None, 1));
        let open = open_coin(&mut w, &buyer, &offer, 40_000_000, Some(sol_addr(2)));
        w.one(&open).unwrap();
        let trade = open.hash.clone();
        let reference = EscrowRef {
            contract: sol::b58(&SOL_PROGRAM),
            funder: sol_addr(1),
            tx: bs58::encode([5u8; 64]).into_string(),
        };
        let lock = |w: &mut World, r: EscrowRef| w.op(&seller, TX_LOCK, &LockBody { trade_id: trade.clone(), escrow: Some(r) }, 0);
        let tx = lock(&mut w, EscrowRef { tx: "ab".repeat(32), ..reference.clone() });
        refused(w.one(&tx), "is not a solana contract");
        let tx = lock(&mut w, EscrowRef { funder: TRON_SELLER.into(), ..reference.clone() });
        refused(w.one(&tx), "is not a solana contract");
        let tx = lock(&mut w, reference.clone());
        w.one(&tx).unwrap();

        let (escrow_at, _) = sol::escrow_address(&SOL_PROGRAM, &id_bytes(&trade), &sol_key(1).verifying_key().to_bytes());
        let stranger = hex::encode(sol::buyer_signature(&sol_key(9), &SOL_PROGRAM, &escrow_at, sol::ACTION_CANCEL));
        refused(w.one(&refund_with(&w, &buyer, &trade, &stranger)), "not the buyer's cancel for this Solana escrow");
        let (other_escrow, _) = sol::escrow_address(&[0x43; 32], &id_bytes(&trade), &sol_key(1).verifying_key().to_bytes());
        let elsewhere = hex::encode(sol::buyer_signature(&sol_key(2), &SOL_PROGRAM, &other_escrow, sol::ACTION_CANCEL));
        refused(w.one(&refund_with(&w, &buyer, &trade, &elsewhere)), "not the buyer's cancel");
        let freeze = hex::encode(sol::buyer_signature(&sol_key(2), &SOL_PROGRAM, &escrow_at, sol::ACTION_FREEZE));
        refused(w.one(&refund_with(&w, &buyer, &trade, &freeze)), "not the buyer's cancel");
        refused(w.one(&refund_with(&w, &buyer, &trade, &"11".repeat(65))), "is 64 hex bytes");

        let good = hex::encode(sol::buyer_signature(&sol_key(2), &SOL_PROGRAM, &escrow_at, sol::ACTION_CANCEL));
        let message = settle_auth_message(&trade, Outcome::Release, Role::Seller, Some(&good));
        let on_release = SettleBody {
            trade_id: trade.clone(),
            outcome: Outcome::Release,
            by: Role::Seller,
            pubkey: hex::encode(seller.key.verifying_key().to_bytes()),
            signature: hex::encode(seller.key.sign(message.as_bytes()).to_bytes()),
            native_sig: Some(good.clone()),
        };
        let tx = settle_tx(&on_release, &w.trade(&trade), w.now);
        refused(w.one(&tx), "only the buyer's refund carries");

        w.one(&refund_with(&w, &buyer, &trade, &good)).unwrap();
        let t = w.trade(&trade);
        assert_eq!(t.state, TradeState::Refunded);
        assert_eq!(t.native_sig.as_deref(), Some(good.as_str()));
    }

    #[test]
    fn a_cardano_refund_carries_the_buyers_key_and_signature() {
        use crate::escrow::cardano as ada;
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        publish_everywhere(&mut w, &Who::new(7));
        let offer = w.post_offer(&seller, &coin_offer("ADA", Side::Sell, None, 10_000_000));
        let open = open_coin(&mut w, &buyer, &offer, 150_000_000, Some(ada_addr(2)));
        w.one(&open).unwrap();
        let trade = open.hash.clone();
        let reference = EscrowRef { contract: ada_script(), funder: ada_addr(1), tx: "cd".repeat(32) };
        let lock = |w: &mut World, r: EscrowRef| w.op(&seller, TX_LOCK, &LockBody { trade_id: trade.clone(), escrow: Some(r) }, 0);
        let tx = lock(&mut w, EscrowRef { contract: ada_addr(5), ..reference.clone() });
        refused(w.one(&tx), "is not a cardano contract");
        let tx = lock(&mut w, EscrowRef { funder: ada_script(), ..reference.clone() });
        refused(w.one(&tx), "is not a cardano contract");
        let tx = lock(&mut w, EscrowRef { tx: "0x".to_string() + &"cd".repeat(32), ..reference.clone() });
        refused(w.one(&tx), "is not a cardano contract");
        let tx = lock(&mut w, reference.clone());
        w.one(&tx).unwrap();

        let script = ada::script_hash();
        let native = |key: &SigningKey, script: &[u8; 28], action: u8| {
            let (vkey, sig) = ada::sign_auth(key, script, &id_bytes(&trade), action);
            format!("{}{}", hex::encode(vkey), hex::encode(sig))
        };
        refused(w.one(&refund_with(&w, &buyer, &trade, &native(&sol_key(9), &script, ada::ACTION_CANCEL))), "not the buyer's cancel for this Cardano escrow");
        refused(w.one(&refund_with(&w, &buyer, &trade, &native(&sol_key(2), &[0xee; 28], ada::ACTION_CANCEL))), "not the buyer's cancel");
        refused(w.one(&refund_with(&w, &buyer, &trade, &native(&sol_key(2), &script, ada::ACTION_FREEZE))), "not the buyer's cancel");
        refused(w.one(&refund_with(&w, &buyer, &trade, &"11".repeat(64))), "is 96 hex bytes");

        let good = native(&sol_key(2), &script, ada::ACTION_CANCEL);
        w.one(&refund_with(&w, &buyer, &trade, &good)).unwrap();
        let t = w.trade(&trade);
        assert_eq!(t.state, TradeState::Refunded);
        assert_eq!(t.native_sig.as_deref(), Some(good.as_str()));
    }

    #[test]
    fn small_ada_trades_carry_no_fee_because_cardano_cannot_pay_it_out() {
        assert_eq!(trade_fee("ADA", 99_000_000), 0);
        assert_eq!(trade_fee("ADA", 100_000_000), 1_000_000);
        assert_eq!(trade_fee("SOL", 10_000), 100);
        let mut w = World::new();
        let seller = Who::new(1);
        let buyer = Who::new(2);
        publish_everywhere(&mut w, &Who::new(7));
        let offer = w.post_offer(&seller, &coin_offer("ADA", Side::Sell, None, 10_000_000));
        let small = open_coin(&mut w, &buyer, &offer, 50_000_000, Some(ada_addr(2)));
        w.one(&small).unwrap();
        let t = w.trade(&small.hash);
        assert_eq!((t.maker_fee_micro, t.locked_micro), (0, 50_000_000));
        let large = open_coin(&mut w, &buyer, &offer, 300_000_000, Some(ada_addr(2)));
        w.one(&large).unwrap();
        let t = w.trade(&large.hash);
        assert_eq!((t.maker_fee_micro, t.locked_micro), (3_000_000, 303_000_000));
    }

    #[test]
    fn escrow_references_use_each_chains_transaction_format() {
        assert!(valid_chain_tx(Family::Solana, &bs58::encode([7u8; 64]).into_string()));
        assert!(!valid_chain_tx(Family::Solana, &bs58::encode([7u8; 32]).into_string()));
        assert!(!valid_chain_tx(Family::Solana, &"ab".repeat(32)));
        assert!(valid_chain_tx(Family::Cardano, &"ab".repeat(32)));
        assert!(!valid_chain_tx(Family::Cardano, &format!("0x{}", "ab".repeat(32))));
        assert!(valid_escrow_contract(Family::Cardano, &ada_script()));
        assert!(!valid_escrow_contract(Family::Cardano, &ada_addr(1)));
        assert!(valid_escrow_contract(Family::Solana, &sol_addr(1)));
        assert_eq!(native_sig_len(Family::Evm), Some(65));
        assert_eq!(native_sig_len(Family::Solana), Some(64));
        assert_eq!(native_sig_len(Family::Cardano), Some(96));
        assert_eq!(trade_limits("SOL").0, 10_000);
        assert_eq!(trade_limits("ADA").0, 10_000_000);
        assert_eq!(trade_limits("USDT-ERC20").0, 1);
    }

    #[test]
    fn the_default_arbiter_list_is_not_empty() {
        assert!(!arbiters_at(0).is_empty());
        assert!(arbiters_at(u64::MAX).iter().all(|a| a.starts_with("egot1")));
    }

    #[test]
    #[ignore]
    fn end_to_end_through_blocks_and_a_reorg() {
        if std::env::var("EGO_MARKET_E2E").is_err() {
            return;
        }
        let _g = crate::shielded::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("EGO_MARKET_HEIGHT", "0");
        let db = chain_db::get_db().lock().unwrap_or_else(|e| e.into_inner());
        let cf_bal = db.cf_handle(CF_BALANCES).unwrap();
        let base = chain_db::finality_floor_height(db).max(chain_db::local_chain_height()) + 100;
        let t0 = 1_800_000_000i64;
        let block = |h: u64, n: u32| crate::ledger::LedgerBlock {
            height: h,
            hash: format!("{:0>64x}", h),
            prev_hash: format!("{:0>64x}", h - 1),
            miner: "egot1miner".into(),
            timestamp: t0 + (h - base) as i64 * 60,
            tx_count: n,
            ..crate::ledger::LedgerBlock::default()
        };
        for h in base..base + 12 {
            chain_db::append_peer_block_with_votes(&block(h, 0), &[], 0);
        }
        let seller = Who::new(41);
        let buyer = Who::new(42);
        let thief = Who::new(43);
        let fund = 50_000_000u64;
        let pocket = 1_000_000u64;
        db.put_cf(cf_bal, seller.addr.as_bytes(), chain_db::u64_le(fund)).unwrap();
        db.put_cf(cf_bal, buyer.addr.as_bytes(), chain_db::u64_le(pocket)).unwrap();
        let bal = |a: &str| chain_db::balance_of(a);

        let mut h = base + 12;
        let mut nonce = 0u64;
        let mut next = || {
            nonce += 1;
            nonce
        };
        let offer = signed(&seller, TX_OFFER, &sell_offer(), 0, next());
        chain_db::append_peer_block_with_votes(&block(h, 1), std::slice::from_ref(&offer), 0);
        h += 1;
        let open_body = TradeOpenBody {
            offer_id: offer.hash.clone(),
            amount_micro: 10_000_000,
            price_micro: 250,
            fiat_micro: 2_500,
            method: "sepa".into(),
            payout_address: None,
        };
        let open = signed(&buyer, TX_TRADE_OPEN, &open_body, 0, next());
        assert!(crate::ledger::verify_confirmed_tx_sig(&open).is_err(), "the test tx is unsigned");
        validate_block_market_txs(h, std::slice::from_ref(&open)).unwrap();
        chain_db::append_peer_block_with_votes(&block(h, 1), std::slice::from_ref(&open), 0);
        h += 1;
        let lock = signed(&seller, TX_LOCK, &TradeRef { trade_id: open.hash.clone() }, 10_100_000, next());
        chain_db::append_peer_block_with_votes(&block(h, 1), std::slice::from_ref(&lock), 0);
        let lock_height = h;
        h += 1;
        assert_eq!(bal(MARKET_ESCROW_ADDR), 10_100_000);
        assert_eq!(bal(&seller.addr), fund - 10_100_000 - 2_000);

        let trade = get_trade(&open.hash).unwrap();
        assert_eq!(trade.state, TradeState::Locked);
        let release = settle_tx(&seller.auth(&open.hash, Outcome::Release, Role::Seller), &trade, t0);
        let refund = settle_tx(&buyer.auth(&open.hash, Outcome::Refund, Role::Buyer), &trade, t0);
        let forged = settle_tx(&thief.auth(&open.hash, Outcome::Release, Role::Seller), &trade, t0);
        assert!(crate::ledger::verify_confirmed_tx_sig(&release).is_ok());
        assert!(crate::ledger::verify_incoming_tx(&release).is_ok());
        assert!(crate::ledger::verify_incoming_tx(&forged).unwrap_err().contains("not signed by"));
        assert!(validate_block_market_txs(h, &[release.clone(), refund.clone()]).is_err());
        assert!(validate_block_market_txs(h, std::slice::from_ref(&forged)).is_err());

        chain_db::append_peer_block_with_votes(&block(h, 1), std::slice::from_ref(&forged), 0);
        let forged_height = h;
        h += 1;
        assert_eq!(bal(MARKET_ESCROW_ADDR), 10_100_000, "a forged settlement moves nothing");
        assert_eq!(bal(&thief.addr), 0);
        assert!(rejected_since(db, forged_height).contains(&forged.hash));

        chain_db::append_peer_block_with_votes(&block(h, 1), std::slice::from_ref(&release), 0);
        let release_height = h;
        assert_eq!(bal(&buyer.addr), pocket - 1_000 + 10_000_000);
        assert_eq!(bal(MARKET_ESCROW_ADDR), 0);
        assert_eq!(get_trade(&open.hash).unwrap().state, TradeState::Released);
        assert_eq!(get_profile(&seller.addr).completed, 1);

        chain_db::truncate_from(release_height);
        assert_eq!(bal(&buyer.addr), pocket - 1_000);
        assert_eq!(bal(MARKET_ESCROW_ADDR), 10_100_000);
        assert_eq!(get_trade(&open.hash).unwrap().state, TradeState::Locked);
        assert_eq!(get_profile(&seller.addr).completed, 0);

        chain_db::truncate_from(forged_height);
        assert_eq!(bal(MARKET_ESCROW_ADDR), 10_100_000, "undoing a rejected settlement moves nothing either");

        chain_db::truncate_from(lock_height);
        assert_eq!(bal(MARKET_ESCROW_ADDR), 0);
        assert_eq!(bal(&seller.addr), fund - 1_000);
        assert_eq!(get_trade(&open.hash).unwrap().state, TradeState::AwaitingLock);
        let totals: EscrowTotals = read(&DbReader(db), ESCROW_KEY).unwrap_or_default();
        assert_eq!(totals, EscrowTotals::default());
        std::env::remove_var("EGO_MARKET_HEIGHT");
    }
}
