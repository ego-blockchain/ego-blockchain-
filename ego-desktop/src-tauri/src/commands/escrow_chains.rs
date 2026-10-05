use crate::commands::multichain::{base58check, eip55_checksum, http_client, rlp_item, rlp_list, rlp_uint};
use crate::market_chain::{Family, Trade};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};

pub const FALLBACK_DELAY_SECS: u64 = 30 * 24 * 60 * 60;
pub const ARBITER_KEY_PATH: &str = "ego:ethereum:0";
pub const ACTION_CANCEL: u8 = 2;
pub const STATE_FUNDED: u8 = 1;
pub const STATE_RELEASED: u8 = 2;
pub const STATE_REFUNDED: u8 = 3;
const NETWORKS_FILE: &str = "market_networks.json";
const TRON_FEE_LIMIT_SUN: u64 = 300_000_000;
const RECEIPT_TIMEOUT_SECS: u64 = 180;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChainNet {
    pub network: String,
    pub family: Family,
    pub label: String,
    #[serde(default)]
    pub chain_id: u64,
    pub rpc: Vec<String>,
    pub explorer_tx: String,
    pub explorer_address: String,
    #[serde(default)]
    pub escrow: String,
    pub key_path: String,
    pub native_symbol: String,
    #[serde(default)]
    pub fee_receiver: String,
    #[serde(default)]
    pub explorer_suffix: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TokenCfg {
    pub asset: String,
    pub network: String,
    #[serde(default)]
    pub native: bool,
    #[serde(default)]
    pub token: String,
    pub decimals: u8,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Networks {
    pub mode: String,
    pub networks: Vec<ChainNet>,
    pub tokens: Vec<TokenCfg>,
}

impl Networks {
    pub fn net(&self, network: &str) -> Option<&ChainNet> {
        self.networks.iter().find(|n| n.network == network)
    }

    pub fn token(&self, asset: &str) -> Option<&TokenCfg> {
        self.tokens.iter().find(|t| t.asset == asset)
    }

    pub fn for_asset(&self, asset: &str) -> Result<(&ChainNet, &TokenCfg), String> {
        let token = self.token(asset).ok_or_else(|| format!("{asset} is not set up on this computer"))?;
        let net = self
            .net(&token.network)
            .ok_or_else(|| format!("the {} network is not set up on this computer", token.network))?;
        if net.escrow.is_empty() {
            return Err(format!("no escrow contract is configured for {} yet", net.label));
        }
        if !token.native && token.token.is_empty() {
            return Err(format!("no {asset} token contract is configured for {} yet", net.label));
        }
        Ok((net, token))
    }
}

fn net(network: &str, family: Family, label: &str, chain_id: u64, rpc: &[&str], tx: &str, addr: &str, key: &str, native: &str) -> ChainNet {
    ChainNet {
        network: network.into(),
        family,
        label: label.into(),
        chain_id,
        rpc: rpc.iter().map(|s| s.to_string()).collect(),
        explorer_tx: tx.into(),
        explorer_address: addr.into(),
        escrow: String::new(),
        key_path: key.into(),
        native_symbol: native.into(),
        fee_receiver: String::new(),
        explorer_suffix: String::new(),
    }
}

fn token(asset: &str, network: &str, native: bool, address: &str, decimals: u8) -> TokenCfg {
    TokenCfg { asset: asset.into(), network: network.into(), native, token: address.into(), decimals }
}

pub fn default_networks() -> Networks {
    Networks {
        mode: "testnet".into(),
        networks: vec![
            net(
                "ethereum",
                Family::Evm,
                "Ethereum Sepolia",
                11_155_111,
                &["https://ethereum-sepolia-rpc.publicnode.com", "https://sepolia.drpc.org", "https://rpc.sepolia.org"],
                "https://sepolia.etherscan.io/tx/",
                "https://sepolia.etherscan.io/address/",
                "ego:ethereum:0",
                "ETH",
            ),
            net(
                "bsc",
                Family::Evm,
                "BNB Chain testnet",
                97,
                &["https://bsc-testnet-rpc.publicnode.com", "https://data-seed-prebsc-1-s1.bnbchain.org:8545"],
                "https://testnet.bscscan.com/tx/",
                "https://testnet.bscscan.com/address/",
                "ego:bnb:0",
                "BNB",
            ),
            net(
                "polygon",
                Family::Evm,
                "Polygon Amoy",
                80_002,
                &["https://rpc-amoy.polygon.technology", "https://polygon-amoy-bor-rpc.publicnode.com"],
                "https://amoy.polygonscan.com/tx/",
                "https://amoy.polygonscan.com/address/",
                "ego:polygon:0",
                "POL",
            ),
            net(
                "tron",
                Family::Tron,
                "Tron Nile",
                0,
                &["https://nile.trongrid.io"],
                "https://nile.tronscan.org/#/transaction/",
                "https://nile.tronscan.org/#/address/",
                "ego:tron:0",
                "TRX",
            ),
            ChainNet {
                explorer_suffix: "?cluster=devnet".into(),
                escrow: "DqKnhXNbMnj2WCUVtiUiK3FmfvpiR6LRKP5vZ4h5Huik".into(),
                ..net(
                    "solana",
                    Family::Solana,
                    "Solana devnet",
                    0,
                    &["https://api.devnet.solana.com"],
                    "https://explorer.solana.com/tx/",
                    "https://explorer.solana.com/address/",
                    "ego:solana:0",
                    "SOL",
                )
            },
            ChainNet {
                escrow: crate::commands::escrow_outside::cardano_script_address(0),
                ..net(
                    "cardano",
                    Family::Cardano,
                    "Cardano preprod",
                    1,
                    &["https://preprod.koios.rest/api/v1"],
                    "https://preprod.cardanoscan.io/transaction/",
                    "https://preprod.cardanoscan.io/address/",
                    "ego:cardano:0",
                    "ADA",
                )
            },
        ],
        tokens: vec![
            token("USDT-TRC20", "tron", false, "", 6),
            token("TRX", "tron", true, "", 6),
            token("USDT-ERC20", "ethereum", false, "", 6),
            token("USDC-ERC20", "ethereum", false, "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238", 6),
            token("ETH", "ethereum", true, "", 18),
            token("USDT-BEP20", "bsc", false, "", 18),
            token("USDC-BEP20", "bsc", false, "", 18),
            token("BNB", "bsc", true, "", 18),
            token("USDT-POLYGON", "polygon", false, "", 6),
            token("USDC-POLYGON", "polygon", false, "0x41E94Eb019C0762f9Bfcf9Fb1E58725BfB0e7582", 6),
            token("POL", "polygon", true, "", 18),
            token("USDC-SPL", "solana", false, "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU", 6),
            token("USDT-SPL", "solana", false, "69ZabgyzozhShyLJZc35N4C5uQcXmTqZXKdRqZByLJgG", 6),
            token("SOL", "solana", true, "", 9),
            token("ADA", "cardano", true, "", 6),
        ],
    }
}

pub fn networks_path() -> std::path::PathBuf {
    crate::ledger::base_data_dir().join(NETWORKS_FILE)
}

pub fn networks() -> Networks {
    std::fs::read(networks_path())
        .ok()
        .and_then(|b| serde_json::from_slice::<Networks>(&b).ok())
        .unwrap_or_else(default_networks)
}

pub fn save_networks(n: &Networks) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(n).map_err(|e| e.to_string())?;
    crate::utils::atomic_write(&networks_path(), &bytes).map_err(|e| e.to_string())
}

pub fn keccak(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

pub fn selector(signature: &str) -> [u8; 4] {
    let h = keccak(signature.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

#[derive(Debug, Clone, PartialEq)]
pub enum Arg {
    Word([u8; 32]),
    Bytes(Vec<u8>),
}

pub fn word_u128(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

pub fn word_u64(v: u64) -> [u8; 32] {
    word_u128(v as u128)
}

pub fn word_bool(b: bool) -> [u8; 32] {
    word_u128(b as u128)
}

pub fn word_addr(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

pub fn encode_args(args: &[Arg]) -> Vec<u8> {
    let head_len = 32 * args.len();
    let mut head = Vec::with_capacity(head_len);
    let mut tail = Vec::new();
    for a in args {
        match a {
            Arg::Word(w) => head.extend_from_slice(w),
            Arg::Bytes(b) => {
                head.extend_from_slice(&word_u64((head_len + tail.len()) as u64));
                tail.extend_from_slice(&word_u64(b.len() as u64));
                tail.extend_from_slice(b);
                let pad = (32 - b.len() % 32) % 32;
                tail.extend(std::iter::repeat(0u8).take(pad));
            }
        }
    }
    head.extend_from_slice(&tail);
    head
}

pub fn encode_call(signature: &str, args: &[Arg]) -> Vec<u8> {
    let mut out = selector(signature).to_vec();
    out.extend_from_slice(&encode_args(args));
    out
}

fn sha256d(data: &[u8]) -> [u8; 32] {
    use sha2::Sha256;
    let once = sha2::Sha256::digest(data);
    Sha256::digest(once).into()
}

pub fn parse_address(family: Family, s: &str) -> Result<[u8; 20], String> {
    let s = s.trim();
    match family {
        Family::Evm => {
            let digits = s.strip_prefix("0x").ok_or_else(|| format!("{s:.48} is not a 0x address"))?;
            hex::decode(digits)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| format!("{s:.48} is not a 20-byte address"))
        }
        Family::Tron => {
            let raw = bs58::decode(s).into_vec().map_err(|_| format!("{s:.48} is not a Tron address"))?;
            if raw.len() != 25 || raw[0] != 0x41 || sha256d(&raw[..21])[..4] != raw[21..] {
                return Err(format!("{s:.48} is not a Tron address"));
            }
            let mut a = [0u8; 20];
            a.copy_from_slice(&raw[1..21]);
            Ok(a)
        }
        Family::Solana | Family::Cardano => Err(format!("{s:.48} is not an EVM or Tron address")),
        Family::Ego => Err("Ego addresses have no outside form".into()),
    }
}

pub fn format_address(family: Family, a: &[u8; 20]) -> String {
    match family {
        Family::Tron => base58check(0x41, a),
        _ => eip55_checksum(a),
    }
}

pub fn same_address(family: Family, a: &str, b: &str) -> bool {
    match (parse_address(family, a), parse_address(family, b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

fn tron_hex41(family_addr: &[u8; 20]) -> String {
    format!("41{}", hex::encode(family_addr))
}

pub fn address_from_key(family: Family, key: &[u8; 32]) -> Result<String, String> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let sk = k256::SecretKey::from_slice(key).map_err(|e| e.to_string())?;
    let point = sk.public_key().to_encoded_point(false);
    let h = keccak(&point.as_bytes()[1..]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..]);
    Ok(format_address(family, &a))
}

pub fn wallet_key(path: &str) -> Result<[u8; 32], String> {
    let seed = crate::ledger::load_seed()?.ok_or("the wallet is not set up yet")?;
    Ok(crate::commands::multichain::secp_privkey(&seed, path))
}

pub fn trade_id_bytes(id: &str) -> Result<[u8; 32], String> {
    hex::decode(id.trim().trim_start_matches("0x"))
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| format!("{id:.70} is not a trade id"))
}

pub fn escrow_key(trade_id: &[u8; 32], seller: &[u8; 20]) -> [u8; 32] {
    let mut m = trade_id.to_vec();
    m.extend_from_slice(&word_addr(seller));
    keccak(&m)
}

pub fn to_base_units(micro: u64, decimals: u8) -> u128 {
    if decimals >= 6 {
        micro as u128 * 10u128.pow((decimals - 6) as u32)
    } else {
        micro as u128 / 10u128.pow((6 - decimals) as u32)
    }
}

fn as_string<S: Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&v.to_string())
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NativeEscrow {
    pub seller: String,
    pub opened_at: u64,
    pub state: u8,
    pub frozen: bool,
    pub buyer: String,
    pub fallback_at: u64,
    pub arbiter: String,
    pub token: String,
    #[serde(serialize_with = "as_string")]
    pub total: u128,
    #[serde(serialize_with = "as_string")]
    pub fee: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_receiver: Option<String>,
}

fn word_at(data: &[u8], i: usize) -> Result<&[u8], String> {
    data.get(i * 32..(i + 1) * 32).ok_or_else(|| "the escrow contract answered too briefly".to_string())
}

fn u128_of(w: &[u8]) -> u128 {
    let mut b = [0u8; 16];
    b.copy_from_slice(&w[16..32]);
    u128::from_be_bytes(b)
}

fn addr_of(w: &[u8]) -> [u8; 20] {
    let mut a = [0u8; 20];
    a.copy_from_slice(&w[12..32]);
    a
}

pub fn decode_escrow(family: Family, data: &[u8]) -> Result<NativeEscrow, String> {
    let w = |i| word_at(data, i);
    Ok(NativeEscrow {
        seller: format_address(family, &addr_of(w(0)?)),
        opened_at: u128_of(w(1)?) as u64,
        state: u128_of(w(2)?) as u8,
        frozen: u128_of(w(3)?) != 0,
        buyer: format_address(family, &addr_of(w(4)?)),
        fallback_at: u128_of(w(5)?) as u64,
        arbiter: format_address(family, &addr_of(w(6)?)),
        token: format_address(family, &addr_of(w(7)?)),
        total: u128_of(w(8)?),
        fee: u128_of(w(9)?),
        fee_receiver: None,
    })
}

const ESCROW_ERRORS: [(&str, &str); 11] = [
    ("UnknownEscrow()", "the escrow does not exist"),
    ("NotFunded()", "the escrow is already settled"),
    ("AlreadyUsed()", "an escrow for this trade already exists"),
    ("BadParty()", "the buyer, seller and arbiter must be three different addresses"),
    ("BadAmount()", "the amount does not match what was sent"),
    ("BadFallback()", "the safety delay is out of range"),
    ("NotAllowed()", "this wallet may not do that"),
    ("TooEarly()", "the safety delay has not passed yet"),
    ("BadSignature()", "the signature is not valid for this escrow"),
    ("TransferFailed()", "the token refused the transfer"),
    ("Reentrant()", "the call re-entered the escrow"),
];

pub fn explain_revert(data_hex: &str) -> Option<&'static str> {
    let raw = hex::decode(data_hex.trim().trim_start_matches("0x")).ok()?;
    if raw.len() < 4 {
        return None;
    }
    ESCROW_ERRORS
        .iter()
        .find(|(sig, _)| selector(sig) == raw[..4])
        .map(|(_, text)| *text)
}

fn friendly(err: String) -> String {
    let parsed = serde_json::from_str::<Value>(&err).ok();
    let data = parsed.as_ref().and_then(|v| v.get("data")).and_then(|d| {
        d.as_str()
            .map(str::to_string)
            .or_else(|| d.get("data").and_then(|x| x.as_str()).map(str::to_string))
    });
    if let Some(text) = data.as_deref().and_then(explain_revert) {
        return text.to_string();
    }
    ESCROW_ERRORS
        .iter()
        .find(|(sig, _)| err.contains(sig))
        .map(|(_, text)| text.to_string())
        .unwrap_or(err)
}

fn sign_recoverable(key: &[u8; 32], hash: &[u8; 32]) -> Result<([u8; 64], u8), String> {
    use k256::ecdsa::SigningKey;
    let sk = SigningKey::from_slice(key).map_err(|e| e.to_string())?;
    let (sig, recid) = sk.sign_prehash_recoverable(hash).map_err(|e| e.to_string())?;
    let (sig, recid) = match sig.normalize_s() {
        Some(low) => (low, recid.to_byte() ^ 1),
        None => (sig, recid.to_byte()),
    };
    let mut out = [0u8; 64];
    out.copy_from_slice(&sig.to_bytes());
    Ok((out, recid))
}

fn hex_u128(v: &Value) -> u128 {
    v.as_str()
        .and_then(|s| u128::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0)
}

fn trim_zeros(b: &[u8]) -> &[u8] {
    let first = b.iter().position(|x| *x != 0).unwrap_or(b.len());
    &b[first..]
}

pub struct ChainClient<'a> {
    pub net: &'a ChainNet,
}

impl<'a> ChainClient<'a> {
    pub fn new(net: &'a ChainNet) -> Self {
        Self { net }
    }

    async fn evm_rpc(&self, method: &str, params: Value) -> Result<Value, String> {
        let mut last = format!("no RPC endpoint is configured for {}", self.net.label);
        for url in &self.net.rpc {
            let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
            let resp = match http_client().post(url).json(&body).send().await {
                Ok(r) => r,
                Err(e) => {
                    last = e.to_string();
                    continue;
                }
            };
            let v: Value = match resp.json().await {
                Ok(v) => v,
                Err(e) => {
                    last = e.to_string();
                    continue;
                }
            };
            if let Some(err) = v.get("error") {
                return Err(err.to_string());
            }
            return Ok(v["result"].clone());
        }
        Err(last)
    }

    async fn tron_post(&self, path: &str, body: Value) -> Result<Value, String> {
        let mut last = format!("no API endpoint is configured for {}", self.net.label);
        for base in &self.net.rpc {
            let url = format!("{}{}", base.trim_end_matches('/'), path);
            match http_client().post(&url).json(&body).send().await {
                Ok(r) => match r.json::<Value>().await {
                    Ok(v) => return Ok(v),
                    Err(e) => last = e.to_string(),
                },
                Err(e) => last = e.to_string(),
            }
        }
        Err(last)
    }

    fn address(&self, s: &str) -> Result<[u8; 20], String> {
        parse_address(self.net.family, s)
    }

    pub async fn view(&self, contract: &str, signature: &str, args: &[Arg]) -> Result<Vec<u8>, String> {
        let to = self.address(contract)?;
        match self.net.family {
            Family::Evm => {
                let data = format!("0x{}", hex::encode(encode_call(signature, args)));
                let out = self
                    .evm_rpc("eth_call", json!([{ "to": format_address(Family::Evm, &to), "data": data }, "latest"]))
                    .await
                    .map_err(friendly)?;
                hex::decode(out.as_str().unwrap_or("0x").trim_start_matches("0x")).map_err(|e| e.to_string())
            }
            Family::Tron => {
                let body = json!({
                    "owner_address": tron_hex41(&to),
                    "contract_address": tron_hex41(&to),
                    "function_selector": signature,
                    "parameter": hex::encode(encode_args(args)),
                    "visible": false,
                });
                let res = self.tron_post("/wallet/triggerconstantcontract", body).await?;
                if res["result"]["result"].as_bool() != Some(true) {
                    return Err(tron_message(&res));
                }
                let out = res["constant_result"][0].as_str().unwrap_or("");
                hex::decode(out).map_err(|e| e.to_string())
            }
            _ => Err("not an EVM or Tron chain".into()),
        }
    }

    pub async fn send(
        &self,
        key: &[u8; 32],
        contract: &str,
        signature: &str,
        args: &[Arg],
        value: u128,
    ) -> Result<String, String> {
        let to = self.address(contract)?;
        match self.net.family {
            Family::Evm => self.send_evm(key, &to, &encode_call(signature, args), value).await,
            Family::Tron => self.send_tron(key, &to, signature, args, value).await,
            _ => Err("not an EVM or Tron chain".into()),
        }
    }

    async fn send_evm(&self, key: &[u8; 32], to: &[u8; 20], data: &[u8], value: u128) -> Result<String, String> {
        let from = address_from_key(Family::Evm, key)?;
        let to_hex = format_address(Family::Evm, to);
        let nonce = hex_u128(&self.evm_rpc("eth_getTransactionCount", json!([from, "pending"])).await?);
        let gas_price = (hex_u128(&self.evm_rpc("eth_gasPrice", json!([])).await?) * 12 / 10).max(1_000_000_000);
        let call = json!({
            "from": from,
            "to": to_hex,
            "data": format!("0x{}", hex::encode(data)),
            "value": format!("0x{value:x}"),
        });
        let gas = hex_u128(&self.evm_rpc("eth_estimateGas", json!([call])).await.map_err(friendly)?) * 13 / 10;
        let chain = self.net.chain_id as u128;
        let unsigned = rlp_list(&[
            rlp_uint(nonce),
            rlp_uint(gas_price),
            rlp_uint(gas),
            rlp_item(to),
            rlp_uint(value),
            rlp_item(data),
            rlp_uint(chain),
            rlp_item(&[]),
            rlp_item(&[]),
        ]);
        let hash = keccak(&unsigned);
        let (sig, recid) = sign_recoverable(key, &hash)?;
        let v = chain * 2 + 35 + recid as u128;
        let (r, s) = sig.split_at(32);
        let signed = rlp_list(&[
            rlp_uint(nonce),
            rlp_uint(gas_price),
            rlp_uint(gas),
            rlp_item(to),
            rlp_uint(value),
            rlp_item(data),
            rlp_uint(v),
            rlp_item(trim_zeros(r)),
            rlp_item(trim_zeros(s)),
        ]);
        let out = self
            .evm_rpc("eth_sendRawTransaction", json!([format!("0x{}", hex::encode(signed))]))
            .await
            .map_err(friendly)?;
        out.as_str().map(str::to_string).ok_or_else(|| "the network returned no transaction hash".into())
    }

    async fn send_tron(
        &self,
        key: &[u8; 32],
        to: &[u8; 20],
        signature: &str,
        args: &[Arg],
        value: u128,
    ) -> Result<String, String> {
        let owner = parse_address(Family::Tron, &address_from_key(Family::Tron, key)?)?;
        let body = json!({
            "owner_address": tron_hex41(&owner),
            "contract_address": tron_hex41(to),
            "function_selector": signature,
            "parameter": hex::encode(encode_args(args)),
            "fee_limit": TRON_FEE_LIMIT_SUN,
            "call_value": u64::try_from(value).map_err(|_| "the amount is too large for Tron".to_string())?,
            "visible": false,
        });
        let res = self.tron_post("/wallet/triggersmartcontract", body).await?;
        if res["result"]["result"].as_bool() != Some(true) {
            return Err(tron_message(&res));
        }
        let mut tx = res["transaction"].clone();
        let raw = hex::decode(tx["raw_data_hex"].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
        let hash: [u8; 32] = sha2::Sha256::digest(&raw).into();
        let (sig, recid) = sign_recoverable(key, &hash)?;
        let mut sig65 = sig.to_vec();
        sig65.push(recid);
        tx["signature"] = json!([hex::encode(sig65)]);
        let txid = tx["txID"].as_str().unwrap_or("").to_string();
        let sent = self.tron_post("/wallet/broadcasttransaction", tx).await?;
        if sent["result"].as_bool() == Some(true) {
            Ok(txid)
        } else {
            Err(tron_message(&sent))
        }
    }

    pub async fn wait(&self, tx: &str) -> Result<(), String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(RECEIPT_TIMEOUT_SECS);
        loop {
            match self.net.family {
                Family::Evm => {
                    let r = self.evm_rpc("eth_getTransactionReceipt", json!([tx])).await.unwrap_or(Value::Null);
                    if !r.is_null() {
                        return match r["status"].as_str() {
                            Some("0x1") => Ok(()),
                            _ => Err(format!("the transaction {tx:.18} failed on {}", self.net.label)),
                        };
                    }
                }
                Family::Tron => {
                    let r = self
                        .tron_post("/wallet/gettransactioninfobyid", json!({ "value": tx }))
                        .await
                        .unwrap_or(Value::Null);
                    if r.get("id").is_some() {
                        let failed = r["result"].as_str() == Some("FAILED");
                        let receipt = r["receipt"]["result"].as_str();
                        return if !failed && matches!(receipt, None | Some("SUCCESS")) {
                            Ok(())
                        } else {
                            Err(format!(
                                "the transaction {tx:.18} failed on {}: {}",
                                self.net.label,
                                receipt.unwrap_or("FAILED")
                            ))
                        };
                    }
                }
                _ => return Err("not an EVM or Tron chain".into()),
            }
            if std::time::Instant::now() > deadline {
                return Err(format!("{} has not confirmed {tx:.18} yet; check the explorer", self.net.label));
            }
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
    }

    pub async fn native_balance(&self, owner: &str) -> Result<u128, String> {
        let a = self.address(owner)?;
        match self.net.family {
            Family::Evm => Ok(hex_u128(
                &self.evm_rpc("eth_getBalance", json!([format_address(Family::Evm, &a), "latest"])).await?,
            )),
            Family::Tron => {
                let r = self.tron_post("/wallet/getaccount", json!({ "address": tron_hex41(&a) })).await?;
                Ok(r["balance"].as_u64().unwrap_or(0) as u128)
            }
            _ => Err("not an EVM or Tron chain".into()),
        }
    }

    pub async fn token_balance(&self, token: &str, owner: &str) -> Result<u128, String> {
        let a = self.address(owner)?;
        let out = self.view(token, "balanceOf(address)", &[Arg::Word(word_addr(&a))]).await?;
        Ok(word_at(&out, 0).map(u128_of).unwrap_or(0))
    }

    pub async fn allowance(&self, token: &str, owner: &str, spender: &str) -> Result<u128, String> {
        let o = self.address(owner)?;
        let s = self.address(spender)?;
        let out = self
            .view(token, "allowance(address,address)", &[Arg::Word(word_addr(&o)), Arg::Word(word_addr(&s))])
            .await?;
        Ok(word_at(&out, 0).map(u128_of).unwrap_or(0))
    }

    pub async fn read_escrow(&self, key: &[u8; 32]) -> Result<NativeEscrow, String> {
        let out = self.view(&self.net.escrow, "escrows(bytes32)", &[Arg::Word(*key)]).await?;
        decode_escrow(self.net.family, &out)
    }

    pub async fn action_digest(&self, key: &[u8; 32], action: u8) -> Result<[u8; 32], String> {
        let out = self
            .view(&self.net.escrow, "actionDigest(bytes32,uint8)", &[Arg::Word(*key), Arg::Word(word_u64(action as u64))])
            .await?;
        out.get(..32)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| "the escrow contract returned no digest".to_string())
    }

    pub async fn sign_action(&self, signer: &[u8; 32], key: &[u8; 32], action: u8) -> Result<String, String> {
        let digest = self.action_digest(key, action).await?;
        Ok(hex::encode(sign_digest(signer, &digest)?))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn open_escrow(
        &self,
        seller_key: &[u8; 32],
        token: &TokenCfg,
        trade_id: &[u8; 32],
        buyer: &str,
        arbiter: &str,
        total: u128,
        fee: u128,
        progress: &(dyn Fn(&str) + Send + Sync),
    ) -> Result<(String, String), String> {
        let funder = address_from_key(self.net.family, seller_key)?;
        let buyer20 = self.address(buyer)?;
        let arbiter20 = self.address(arbiter)?;
        let token20 = if token.native { [0u8; 20] } else { self.address(&token.token)? };
        if !token.native {
            let have = self.token_balance(&token.token, &funder).await?;
            if have < total {
                return Err(format!("this wallet holds {have} base units of {} but the escrow needs {total}", token.asset));
            }
            if self.allowance(&token.token, &funder, &self.net.escrow).await? < total {
                progress("approve");
                let escrow20 = self.address(&self.net.escrow)?;
                let tx = self
                    .send(
                        seller_key,
                        &token.token,
                        "approve(address,uint256)",
                        &[Arg::Word(word_addr(&escrow20)), Arg::Word(word_u128(total))],
                        0,
                    )
                    .await?;
                self.wait(&tx).await?;
            }
        }
        progress("open");
        let args = [
            Arg::Word(*trade_id),
            Arg::Word(word_addr(&buyer20)),
            Arg::Word(word_addr(&arbiter20)),
            Arg::Word(word_addr(&token20)),
            Arg::Word(word_u128(total)),
            Arg::Word(word_u128(fee)),
            Arg::Word(word_u64(FALLBACK_DELAY_SECS)),
        ];
        let value = if token.native { total } else { 0 };
        let tx = self
            .send(
                seller_key,
                &self.net.escrow,
                "open(bytes32,address,address,address,uint128,uint128,uint64)",
                &args,
                value,
            )
            .await?;
        self.wait(&tx).await?;
        Ok((funder, tx))
    }

    pub async fn release(&self, seller_key: &[u8; 32], key: &[u8; 32]) -> Result<String, String> {
        let tx = self.send(seller_key, &self.net.escrow, "release(bytes32)", &[Arg::Word(*key)], 0).await?;
        self.wait(&tx).await?;
        Ok(tx)
    }

    pub async fn resolve(&self, arbiter_key: &[u8; 32], key: &[u8; 32], to_buyer: bool) -> Result<String, String> {
        let tx = self
            .send(arbiter_key, &self.net.escrow, "resolve(bytes32,bool)", &[Arg::Word(*key), Arg::Word(word_bool(to_buyer))], 0)
            .await?;
        self.wait(&tx).await?;
        Ok(tx)
    }

    pub async fn cancel_for(&self, relayer_key: &[u8; 32], key: &[u8; 32], sig_hex: &str) -> Result<String, String> {
        let sig = hex::decode(sig_hex).map_err(|_| "the buyer's signature is not hex".to_string())?;
        let tx = self
            .send(relayer_key, &self.net.escrow, "cancelFor(bytes32,bytes)", &[Arg::Word(*key), Arg::Bytes(sig)], 0)
            .await?;
        self.wait(&tx).await?;
        Ok(tx)
    }
}

pub fn sign_digest(signer: &[u8; 32], digest: &[u8; 32]) -> Result<[u8; 65], String> {
    let (sig, recid) = sign_recoverable(signer, digest)?;
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&sig);
    out[64] = 27 + recid;
    Ok(out)
}

fn tron_message(v: &Value) -> String {
    let raw = v["result"]["message"]
        .as_str()
        .or_else(|| v["message"].as_str())
        .or_else(|| v["Error"].as_str())
        .unwrap_or("");
    let text = hex::decode(raw)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_else(|| raw.to_string());
    if text.is_empty() {
        format!("Tron refused the request: {}", v)
    } else {
        text
    }
}

pub fn verify_escrow(trade: &Trade, net: &ChainNet, token: &TokenCfg, funder: &str, e: &NativeEscrow) -> Vec<String> {
    let f = net.family;
    let mut problems = Vec::new();
    if e.state == 0 {
        problems.push(format!("no escrow exists on {} for this trade yet", net.label));
        return problems;
    }
    if !same_address(f, &e.seller, funder) {
        problems.push("the escrow was funded by a different wallet".into());
    }
    match trade.buyer_payout.as_deref() {
        Some(b) if same_address(f, &e.buyer, b) => {}
        _ => problems.push("the escrow pays a different buyer address".into()),
    }
    match trade.arbiter_payout.as_deref() {
        Some(a) if same_address(f, &e.arbiter, a) => {}
        _ => problems.push("the escrow names a different arbiter".into()),
    }
    let expected_token = if token.native { format_address(f, &[0u8; 20]) } else { token.token.clone() };
    if !same_address(f, &e.token, &expected_token) {
        problems.push(format!("the escrow holds a different token than {}", token.asset));
    }
    if e.total != to_base_units(trade.locked_micro, token.decimals) {
        problems.push("the escrow holds a different amount than the trade".into());
    }
    if e.fee != to_base_units(trade.maker_fee_micro, token.decimals) {
        problems.push("the escrow charges a different fee than the trade".into());
    }
    if e.fallback_at.saturating_sub(e.opened_at) < FALLBACK_DELAY_SECS {
        problems.push("the seller's safety delay is too short".into());
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_match_the_solidity_signatures() {
        assert_eq!(hex::encode(selector("transfer(address,uint256)")), "a9059cbb");
        assert_eq!(hex::encode(selector("transferFrom(address,address,uint256)")), "23b872dd");
        assert_eq!(hex::encode(selector("approve(address,uint256)")), "095ea7b3");
    }

    #[test]
    fn dynamic_bytes_get_an_offset_length_and_padding() {
        let key = [7u8; 32];
        let sig = vec![9u8; 65];
        let enc = encode_args(&[Arg::Word(key), Arg::Bytes(sig.clone())]);
        assert_eq!(enc.len(), 32 * 2 + 32 + 96);
        assert_eq!(&enc[..32], &key);
        assert_eq!(enc[32..64], word_u64(64));
        assert_eq!(enc[64..96], word_u64(65));
        assert_eq!(&enc[96..161], sig.as_slice());
        assert!(enc[161..].iter().all(|b| *b == 0));
        let three = encode_args(&[Arg::Word(key), Arg::Word(word_bool(true)), Arg::Bytes(vec![1, 2])]);
        assert_eq!(three[64..96], word_u64(96));
    }

    #[test]
    fn tron_addresses_round_trip_through_their_hex_form() {
        let a = parse_address(Family::Tron, "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t").unwrap();
        assert_eq!(hex::encode(a), "a614f803b6fd780986a42c78ec9c7f77e6ded13c");
        assert_eq!(format_address(Family::Tron, &a), "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t");
        assert!(parse_address(Family::Tron, "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6u").is_err(), "a checksum typo is caught");
        assert!(same_address(Family::Evm, "0x8ba1f109551bd432803012645ac136ddd64dba72", "0x8Ba1f109551bD432803012645Ac136ddd64DBA72"));
    }

    #[test]
    fn the_escrow_key_matches_the_contracts_key_of() {
        let id = trade_id_bytes(&format!("0x{}", "01".repeat(32))).unwrap();
        let seller = parse_address(Family::Evm, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8").unwrap();
        assert_eq!(
            hex::encode(escrow_key(&id, &seller)),
            "385e9bb6687fb4eda8fa220834d3d34d5569365a6f914da5c0ec700728fc8010"
        );
    }

    #[test]
    fn micro_units_scale_to_each_tokens_decimals() {
        assert_eq!(to_base_units(1_500_000, 6), 1_500_000);
        assert_eq!(to_base_units(1_500_000, 18), 1_500_000_000_000_000_000);
        assert_eq!(to_base_units(1_500_000, 2), 150);
    }

    #[test]
    fn custom_errors_read_as_sentences() {
        let data = format!("0x{}", hex::encode(selector("NotFunded()")));
        assert_eq!(explain_revert(&data), Some("the escrow is already settled"));
        let rpc_err = json!({ "code": 3, "message": "execution reverted", "data": data }).to_string();
        assert_eq!(friendly(rpc_err), "the escrow is already settled");
        assert_eq!(explain_revert("0x12"), None);
    }

    #[test]
    fn a_signed_action_recovers_to_the_signer_with_low_s() {
        use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
        let key = [3u8; 32];
        let digest = keccak(b"some action");
        let sig = sign_digest(&key, &digest).unwrap();
        let s = Signature::from_slice(&sig[..64]).unwrap();
        assert!(s.normalize_s().is_none(), "the signature is already low-s");
        let recovered = VerifyingKey::recover_from_prehash(&digest, &s, RecoveryId::from_byte(sig[64] - 27).unwrap()).unwrap();
        let h = keccak(&recovered.to_encoded_point(false).as_bytes()[1..]);
        let mut a = [0u8; 20];
        a.copy_from_slice(&h[12..]);
        assert_eq!(format_address(Family::Evm, &a), address_from_key(Family::Evm, &key).unwrap());
    }

    fn sample_trade() -> Trade {
        serde_json::from_value(json!({
            "id": format!("0x{}", "01".repeat(32)), "offer_id": "0xo", "maker": "m", "taker": "t",
            "seller": "s", "buyer": "b", "asset": "USDT-ERC20", "amount_micro": 100_000_000u64,
            "maker_fee_micro": 1_000_000u64, "locked_micro": 101_000_000u64, "fiat": "USD",
            "fiat_micro": 100_000_000u64, "price_micro": 1_000_000u64, "method": "wise",
            "payment_window_secs": 900, "state": "locked", "opened_height": 1, "opened_at": 0,
            "buyer_payout": "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
            "arbiter_payout": "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
        }))
        .unwrap()
    }

    #[test]
    fn verification_names_every_mismatch() {
        let n = default_networks();
        let net = n.net("ethereum").unwrap().clone();
        let mut tok = n.token("USDT-ERC20").unwrap().clone();
        tok.token = "0x5FbDB2315678afecb367f032d93F642f64180aa3".into();
        let trade = sample_trade();
        let funder = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
        let good = NativeEscrow {
            seller: funder.into(),
            opened_at: 100,
            state: 1,
            frozen: false,
            buyer: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC".into(),
            fallback_at: 100 + FALLBACK_DELAY_SECS,
            arbiter: "0x90F79bf6EB2c4f870365E785982E1f101E93b906".into(),
            token: tok.token.clone(),
            total: 101_000_000,
            fee: 1_000_000,
            fee_receiver: None,
        };
        assert!(verify_escrow(&trade, &net, &tok, funder, &good).is_empty());
        let bad = NativeEscrow {
            buyer: funder.into(),
            total: 1,
            fee: 0,
            fallback_at: 101,
            ..good.clone()
        };
        let problems = verify_escrow(&trade, &net, &tok, funder, &bad);
        assert_eq!(problems.len(), 4, "{problems:?}");
        let missing = NativeEscrow { state: 0, ..good };
        assert_eq!(verify_escrow(&trade, &net, &tok, funder, &missing).len(), 1);
    }

    #[test]
    #[ignore]
    fn the_evm_adapter_drives_a_real_escrow() {
        let (Ok(rpc), Ok(escrow), Ok(token_addr)) = (
            std::env::var("EGO_HH_RPC"),
            std::env::var("EGO_HH_ESCROW"),
            std::env::var("EGO_HH_TOKEN"),
        ) else {
            return;
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let hex_key = |s: &str| -> [u8; 32] { hex::decode(s).unwrap().try_into().unwrap() };
            let seller = hex_key("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
            let buyer = hex_key("5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a");
            let arbiter = hex_key("7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6");
            let mut net = default_networks().net("ethereum").unwrap().clone();
            net.chain_id = 31_337;
            net.rpc = vec![rpc];
            net.escrow = escrow;
            let tok = TokenCfg { asset: "USDT-ERC20".into(), network: "ethereum".into(), native: false, token: token_addr, decimals: 6 };
            let c = ChainClient::new(&net);
            let buyer_addr = address_from_key(Family::Evm, &buyer).unwrap();
            let arbiter_addr = address_from_key(Family::Evm, &arbiter).unwrap();
            let seller_addr = address_from_key(Family::Evm, &seller).unwrap();
            let seller20 = parse_address(Family::Evm, &seller_addr).unwrap();
            let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
            let mut trade = sample_trade();
            trade.buyer_payout = Some(buyer_addr.clone());
            trade.arbiter_payout = Some(arbiter_addr.clone());
            let steps = std::sync::Mutex::new(Vec::<String>::new());
            let progress = |s: &str| steps.lock().unwrap().push(s.to_string());

            let mut ids = Vec::new();
            for i in 0..3u8 {
                let mut id = keccak(format!("{nonce}:{i}").as_bytes());
                id[0] = i;
                let (funder, tx) = c
                    .open_escrow(&seller, &tok, &id, &buyer_addr, &arbiter_addr, 101_000_000, 1_000_000, &progress)
                    .await
                    .unwrap();
                assert_eq!(funder, seller_addr);
                assert!(tx.starts_with("0x"));
                let key = escrow_key(&id, &seller20);
                let e = c.read_escrow(&key).await.unwrap();
                assert_eq!(e.state, STATE_FUNDED);
                assert!(verify_escrow(&trade, &net, &tok, &funder, &e).is_empty(), "{:?}", verify_escrow(&trade, &net, &tok, &funder, &e));
                ids.push(key);
            }
            assert!(steps.lock().unwrap().contains(&"approve".to_string()));

            let before = c.token_balance(&tok.token, &buyer_addr).await.unwrap();
            c.release(&seller, &ids[0]).await.unwrap();
            assert_eq!(c.read_escrow(&ids[0]).await.unwrap().state, STATE_RELEASED);
            assert_eq!(c.token_balance(&tok.token, &buyer_addr).await.unwrap(), before + 100_000_000);

            let sig = c.sign_action(&buyer, &ids[1], ACTION_CANCEL).await.unwrap();
            c.cancel_for(&seller, &ids[1], &sig).await.unwrap();
            assert_eq!(c.read_escrow(&ids[1]).await.unwrap().state, STATE_REFUNDED);

            c.resolve(&arbiter, &ids[2], true).await.unwrap();
            assert_eq!(c.read_escrow(&ids[2]).await.unwrap().state, STATE_RELEASED);

            let again = c.release(&seller, &ids[0]).await.unwrap_err();
            assert!(again.contains("already settled"), "{again}");
        });
    }
}
