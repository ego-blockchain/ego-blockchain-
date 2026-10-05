use blake2::digest::consts::{U28, U32};
use blake2::{Blake2b, Digest};
use ed25519_dalek::{Signer, SigningKey};

pub const SCRIPT_HEX: &str = include_str!("cardano_escrow.hex");
pub const AUTH_DOMAIN: &[u8] = b"ego-escrow/cardano/v1";
pub const ACTION_CANCEL: u8 = 2;
pub const ACTION_FREEZE: u8 = 5;
pub const MIN_FEE_OUTPUT: u64 = 1_000_000;
pub const SPEND_MEM: u64 = 1_000_000;
pub const SPEND_STEPS: u64 = 400_000_000;
pub const MAX_INPUTS: usize = 20;

pub type Pkh = [u8; 28];

pub fn blake2b_224(data: &[u8]) -> Pkh {
    Blake2b::<U28>::digest(data).into()
}

pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    Blake2b::<U32>::digest(data).into()
}

pub fn script_bytes() -> Vec<u8> {
    hex::decode(SCRIPT_HEX.trim()).unwrap_or_default()
}

pub fn script_hash() -> Pkh {
    let mut tagged = vec![0x03u8];
    tagged.extend_from_slice(&script_bytes());
    blake2b_224(&tagged)
}

pub fn auth_message(script: &Pkh, trade_id: &[u8; 32], action: u8) -> Vec<u8> {
    let mut m = AUTH_DOMAIN.to_vec();
    m.extend_from_slice(script);
    m.extend_from_slice(trade_id);
    m.push(action);
    m
}

pub fn sign_auth(key: &SigningKey, script: &Pkh, trade_id: &[u8; 32], action: u8) -> ([u8; 32], [u8; 64]) {
    (key.verifying_key().to_bytes(), key.sign(&auth_message(script, trade_id, action)).to_bytes())
}

pub fn verify_auth(vkey: &[u8; 32], signature: &[u8; 64], who: &Pkh, script: &Pkh, trade_id: &[u8; 32], action: u8) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    if &blake2b_224(vkey) != who {
        return false;
    }
    let Ok(vk) = VerifyingKey::from_bytes(vkey) else { return false };
    vk.verify(&auth_message(script, trade_id, action), &Signature::from_bytes(signature)).is_ok()
}

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | n as u8),
        24..=0xff => out.extend_from_slice(&[m | 24, n as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}

pub fn cbor_uint(out: &mut Vec<u8>, n: u64) {
    head(out, 0, n);
}

pub fn cbor_bytes(out: &mut Vec<u8>, b: &[u8]) {
    head(out, 2, b.len() as u64);
    out.extend_from_slice(b);
}

pub fn cbor_array(out: &mut Vec<u8>, len: usize) {
    head(out, 4, len as u64);
}

pub fn cbor_map(out: &mut Vec<u8>, len: usize) {
    head(out, 5, len as u64);
}

pub fn cbor_tag(out: &mut Vec<u8>, tag: u64) {
    head(out, 6, tag);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Data {
    Constr(u64, Vec<Data>),
    Map(Vec<(Data, Data)>),
    List(Vec<Data>),
    Int(i128),
    Bytes(Vec<u8>),
}

impl Data {
    pub fn constr(i: u64, fields: Vec<Data>) -> Data {
        Data::Constr(i, fields)
    }

    pub fn bytes(b: &[u8]) -> Data {
        Data::Bytes(b.to_vec())
    }

    pub fn int(n: i128) -> Data {
        Data::Int(n)
    }

    pub fn bool(b: bool) -> Data {
        Data::Constr(b as u64, vec![])
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Data::Constr(i, fields) => {
                match *i {
                    0..=6 => cbor_tag(out, 121 + i),
                    7..=127 => cbor_tag(out, 1280 + i - 7),
                    _ => {
                        cbor_tag(out, 102);
                        cbor_array(out, 2);
                        cbor_uint(out, *i);
                    }
                }
                cbor_array(out, fields.len());
                for f in fields {
                    f.encode(out);
                }
            }
            Data::Map(pairs) => {
                cbor_map(out, pairs.len());
                for (k, v) in pairs {
                    k.encode(out);
                    v.encode(out);
                }
            }
            Data::List(items) => {
                cbor_array(out, items.len());
                for item in items {
                    item.encode(out);
                }
            }
            Data::Int(n) => {
                if *n >= 0 && *n <= u64::MAX as i128 {
                    head(out, 0, *n as u64);
                } else if *n < 0 && -(n + 1) <= u64::MAX as i128 {
                    head(out, 1, (-(n + 1)) as u64);
                } else {
                    let (tag, mag) = if *n >= 0 { (2, *n as u128) } else { (3, (-(n + 1)) as u128) };
                    cbor_tag(out, tag);
                    let raw = mag.to_be_bytes();
                    let first = raw.iter().position(|b| *b != 0).unwrap_or(raw.len() - 1);
                    cbor_bytes(out, &raw[first..]);
                }
            }
            Data::Bytes(b) => {
                if b.len() <= 64 {
                    cbor_bytes(out, b);
                } else {
                    out.push(0x5f);
                    for chunk in b.chunks(64) {
                        cbor_bytes(out, chunk);
                    }
                    out.push(0xff);
                }
            }
        }
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Data, String> {
        Self::read(bytes, false)
    }

    pub fn from_any_cbor(bytes: &[u8]) -> Result<Data, String> {
        Self::read(bytes, true)
    }

    fn read(bytes: &[u8], any_tag: bool) -> Result<Data, String> {
        let mut r = Reader { b: bytes, at: 0, any_tag };
        let d = r.data(0)?;
        if r.at != bytes.len() {
            return Err("trailing bytes after the datum".into());
        }
        Ok(d)
    }

    pub fn as_constr(&self, expected_fields: usize) -> Result<(u64, &[Data]), String> {
        match self {
            Data::Constr(i, f) if f.len() == expected_fields => Ok((*i, f)),
            _ => Err("unexpected datum shape".into()),
        }
    }

    pub fn as_bytes(&self) -> Result<&[u8], String> {
        match self {
            Data::Bytes(b) => Ok(b),
            _ => Err("expected bytes in the datum".into()),
        }
    }

    pub fn as_int(&self) -> Result<i128, String> {
        match self {
            Data::Int(n) => Ok(*n),
            _ => Err("expected an integer in the datum".into()),
        }
    }

    pub fn as_bool(&self) -> Result<bool, String> {
        match self {
            Data::Constr(0, f) if f.is_empty() => Ok(false),
            Data::Constr(1, f) if f.is_empty() => Ok(true),
            _ => Err("expected a boolean in the datum".into()),
        }
    }
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
    any_tag: bool,
}

impl Reader<'_> {
    fn byte(&mut self) -> Result<u8, String> {
        let v = *self.b.get(self.at).ok_or("the datum ends early")?;
        self.at += 1;
        Ok(v)
    }

    fn arg(&mut self, info: u8) -> Result<Option<u64>, String> {
        Ok(Some(match info {
            0..=23 => info as u64,
            24 => self.byte()? as u64,
            25 => u16::from_be_bytes([self.byte()?, self.byte()?]) as u64,
            26 => u32::from_be_bytes([self.byte()?, self.byte()?, self.byte()?, self.byte()?]) as u64,
            27 => {
                let mut v = [0u8; 8];
                for x in v.iter_mut() {
                    *x = self.byte()?;
                }
                u64::from_be_bytes(v)
            }
            31 => return Ok(None),
            _ => return Err("bad length in the datum".into()),
        }))
    }

    fn take(&mut self, n: u64) -> Result<&[u8], String> {
        let end = self.at.checked_add(n as usize).filter(|e| *e <= self.b.len()).ok_or("the datum ends early")?;
        let s = &self.b[self.at..end];
        self.at = end;
        Ok(s)
    }

    fn bytes(&mut self, info: u8) -> Result<Vec<u8>, String> {
        match self.arg(info)? {
            Some(n) => Ok(self.take(n)?.to_vec()),
            None => {
                let mut out = Vec::new();
                loop {
                    let h = self.byte()?;
                    if h == 0xff {
                        return Ok(out);
                    }
                    if h >> 5 != 2 {
                        return Err("bad chunk in the datum".into());
                    }
                    let n = self.arg(h & 0x1f)?.ok_or("nested indefinite bytes")?;
                    out.extend_from_slice(self.take(n)?);
                }
            }
        }
    }

    fn items(&mut self, info: u8, depth: usize) -> Result<Vec<Data>, String> {
        let mut out = Vec::new();
        match self.arg(info)? {
            Some(n) => {
                for _ in 0..n {
                    out.push(self.data(depth + 1)?);
                }
            }
            None => loop {
                if self.b.get(self.at) == Some(&0xff) {
                    self.at += 1;
                    break;
                }
                out.push(self.data(depth + 1)?);
            },
        }
        Ok(out)
    }

    fn data(&mut self, depth: usize) -> Result<Data, String> {
        if depth > 64 {
            return Err("the datum nests too deeply".into());
        }
        let h = self.byte()?;
        let (major, info) = (h >> 5, h & 0x1f);
        match major {
            0 => Ok(Data::Int(self.arg(info)?.ok_or("bad integer")? as i128)),
            1 => Ok(Data::Int(-1 - self.arg(info)?.ok_or("bad integer")? as i128)),
            2 => Ok(Data::Bytes(self.bytes(info)?)),
            4 => Ok(Data::List(self.items(info, depth)?)),
            5 => {
                let mut pairs = Vec::new();
                match self.arg(info)? {
                    Some(n) => {
                        for _ in 0..n {
                            pairs.push((self.data(depth + 1)?, self.data(depth + 1)?));
                        }
                    }
                    None => loop {
                        if self.b.get(self.at) == Some(&0xff) {
                            self.at += 1;
                            break;
                        }
                        pairs.push((self.data(depth + 1)?, self.data(depth + 1)?));
                    },
                }
                Ok(Data::Map(pairs))
            }
            6 => {
                let tag = self.arg(info)?.ok_or("bad tag")?;
                match tag {
                    121..=127 => {
                        let h = self.byte()?;
                        if h >> 5 != 4 {
                            return Err("a constructor needs a field list".into());
                        }
                        Ok(Data::Constr(tag - 121, self.items(h & 0x1f, depth)?))
                    }
                    1280..=1400 => {
                        let h = self.byte()?;
                        if h >> 5 != 4 {
                            return Err("a constructor needs a field list".into());
                        }
                        Ok(Data::Constr(tag - 1280 + 7, self.items(h & 0x1f, depth)?))
                    }
                    102 => {
                        let h = self.byte()?;
                        if h != 0x82 {
                            return Err("a general constructor is a pair".into());
                        }
                        let i = match self.data(depth + 1)? {
                            Data::Int(i) if i >= 0 => i as u64,
                            _ => return Err("bad constructor index".into()),
                        };
                        match self.data(depth + 1)? {
                            Data::List(f) => Ok(Data::Constr(i, f)),
                            _ => Err("bad constructor fields".into()),
                        }
                    }
                    2 | 3 => {
                        let h = self.byte()?;
                        let raw = self.bytes(h & 0x1f)?;
                        if raw.len() > 16 {
                            return Err("an integer in the datum is too large".into());
                        }
                        let mut v: u128 = 0;
                        for b in raw {
                            v = (v << 8) | b as u128;
                        }
                        let v = i128::try_from(v).map_err(|_| "an integer in the datum is too large")?;
                        Ok(Data::Int(if tag == 2 { v } else { -1 - v }))
                    }
                    _ if self.any_tag => self.data(depth + 1),
                    _ => Err(format!("unexpected tag {tag} in the datum")),
                }
            }
            _ => Err("unexpected item in the datum".into()),
        }
    }
}

pub fn parse_address(s: &str) -> Result<Vec<u8>, String> {
    let (hrp, data, _) = bech32::decode(s.trim()).map_err(|_| format!("{s:.64} is not a Cardano address"))?;
    let raw = bech32::convert_bits(&data, 5, 8, false).map_err(|_| format!("{s:.64} is not a Cardano address"))?;
    let network = match hrp.as_str() {
        "addr" => 1,
        "addr_test" => 0,
        _ => return Err(format!("{s:.64} is not a Cardano address")),
    };
    let ok_len = match raw.first().map(|h| h >> 4) {
        Some(0..=3) => raw.len() == 57,
        Some(6 | 7) => raw.len() == 29,
        _ => false,
    };
    if !ok_len || raw[0] & 0x0f != network {
        return Err(format!("{s:.64} is not a Cardano payment address"));
    }
    Ok(raw)
}

pub fn format_address(raw: &[u8]) -> String {
    use bech32::ToBase32;
    let hrp = if raw.first().is_some_and(|h| h & 0x0f == 1) { "addr" } else { "addr_test" };
    bech32::encode(hrp, raw.to_base32(), bech32::Variant::Bech32).unwrap_or_default()
}

pub fn network_of(raw: &[u8]) -> u8 {
    raw.first().map(|h| h & 0x0f).unwrap_or(0)
}

pub fn payment_key_hash(raw: &[u8]) -> Option<Pkh> {
    match raw.first().map(|h| h >> 4) {
        Some(0 | 2 | 6) => raw.get(1..29)?.try_into().ok(),
        _ => None,
    }
}

pub fn payment_script_hash(raw: &[u8]) -> Option<Pkh> {
    match raw.first().map(|h| h >> 4) {
        Some(1 | 3 | 7) => raw.get(1..29)?.try_into().ok(),
        _ => None,
    }
}

pub fn key_address(network: u8, pkh: &Pkh) -> Vec<u8> {
    let mut v = vec![0x60 | network];
    v.extend_from_slice(pkh);
    v
}

pub fn script_address(network: u8, hash: &Pkh) -> Vec<u8> {
    let mut v = vec![0x70 | network];
    v.extend_from_slice(hash);
    v
}

fn credential(is_script: bool, hash: &[u8]) -> Data {
    Data::constr(is_script as u64, vec![Data::bytes(hash)])
}

pub fn address_data(raw: &[u8]) -> Result<Data, String> {
    let kind = raw.first().map(|h| h >> 4).ok_or("empty address")?;
    let pay = raw.get(1..29).ok_or("short address")?;
    let stake = |is_script: bool| -> Result<Data, String> {
        let s = raw.get(29..57).ok_or("short address")?;
        Ok(Data::constr(0, vec![Data::constr(0, vec![credential(is_script, s)])]))
    };
    let none = Data::constr(1, vec![]);
    let (pay_script, stake_part) = match kind {
        0 => (false, stake(false)?),
        1 => (true, stake(false)?),
        2 => (false, stake(true)?),
        3 => (true, stake(true)?),
        6 => (false, none),
        7 => (true, none),
        _ => return Err("pointer and reward addresses cannot hold an escrow payout".into()),
    };
    Ok(Data::constr(0, vec![credential(pay_script, pay), stake_part]))
}

pub fn address_from_data(d: &Data, network: u8) -> Result<Vec<u8>, String> {
    let (_, f) = d.as_constr(2)?;
    let (pay_kind, pay) = f[0].as_constr(1)?;
    let pay = pay[0].as_bytes()?;
    if pay.len() != 28 || pay_kind > 1 {
        return Err("bad payment credential".into());
    }
    let mut raw = Vec::with_capacity(57);
    match f[1].as_constr(1) {
        Ok((0, inner)) => {
            let (ref_kind, cred) = inner[0].as_constr(1)?;
            if ref_kind != 0 {
                return Err("pointer addresses are not supported".into());
            }
            let (stake_kind, stake) = cred[0].as_constr(1)?;
            let stake = stake[0].as_bytes()?;
            if stake.len() != 28 || stake_kind > 1 {
                return Err("bad stake credential".into());
            }
            raw.push(((pay_kind as u8) | ((stake_kind as u8) << 1)) << 4 | network);
            raw.extend_from_slice(pay);
            raw.extend_from_slice(stake);
        }
        _ => {
            f[1].as_constr(0)?;
            raw.push((6 + pay_kind as u8) << 4 | network);
            raw.extend_from_slice(pay);
        }
    }
    Ok(raw)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowDatum {
    pub trade_id: [u8; 32],
    pub seller: Vec<u8>,
    pub buyer: Vec<u8>,
    pub arbiter: Pkh,
    pub fee_receiver: Vec<u8>,
    pub total: u64,
    pub fee: u64,
    pub fallback_at: i64,
    pub frozen: bool,
}

impl EscrowDatum {
    pub fn to_data(&self) -> Result<Data, String> {
        Ok(Data::constr(
            0,
            vec![
                Data::bytes(&self.trade_id),
                address_data(&self.seller)?,
                address_data(&self.buyer)?,
                Data::bytes(&self.arbiter),
                address_data(&self.fee_receiver)?,
                Data::int(self.total as i128),
                Data::int(self.fee as i128),
                Data::int(self.fallback_at as i128),
                Data::bool(self.frozen),
            ],
        ))
    }

    pub fn from_data(d: &Data, network: u8) -> Result<EscrowDatum, String> {
        let (tag, f) = d.as_constr(9)?;
        if tag != 0 {
            return Err("not an escrow datum".into());
        }
        let num = |x: &Data| -> Result<u64, String> {
            u64::try_from(x.as_int()?).map_err(|_| "a datum amount is out of range".to_string())
        };
        Ok(EscrowDatum {
            trade_id: f[0].as_bytes()?.try_into().map_err(|_| "bad trade id in the datum")?,
            seller: address_from_data(&f[1], network)?,
            buyer: address_from_data(&f[2], network)?,
            arbiter: f[3].as_bytes()?.try_into().map_err(|_| "bad arbiter in the datum")?,
            fee_receiver: address_from_data(&f[4], network)?,
            total: num(&f[5])?,
            fee: num(&f[6])?,
            fallback_at: i64::try_from(f[7].as_int()?).map_err(|_| "bad fallback time")?,
            frozen: f[8].as_bool()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Release,
    Cancel,
    CancelFor { vkey: [u8; 32], signature: [u8; 64] },
    Resolve { to_buyer: bool },
    Freeze,
    FreezeFor { vkey: [u8; 32], signature: [u8; 64] },
    Reclaim,
}

impl Action {
    pub fn to_data(&self) -> Data {
        match self {
            Action::Release => Data::constr(0, vec![]),
            Action::Cancel => Data::constr(1, vec![]),
            Action::CancelFor { vkey, signature } => Data::constr(2, vec![Data::bytes(vkey), Data::bytes(signature)]),
            Action::Resolve { to_buyer } => Data::constr(3, vec![Data::bool(*to_buyer)]),
            Action::Freeze => Data::constr(4, vec![]),
            Action::FreezeFor { vkey, signature } => Data::constr(5, vec![Data::bytes(vkey), Data::bytes(signature)]),
            Action::Reclaim => Data::constr(6, vec![]),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utxo {
    pub tx_hash: [u8; 32],
    pub index: u64,
    pub lovelace: u64,
    pub pure_ada: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub address: Vec<u8>,
    pub lovelace: u64,
    pub datum: Option<Data>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Params {
    pub min_fee_a: u64,
    pub min_fee_b: u64,
    pub coins_per_utxo_byte: u64,
    pub price_mem: (u64, u64),
    pub price_step: (u64, u64),
    pub collateral_percent: u64,
    pub max_tx_size: u64,
    pub cost_model_v3: Vec<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotConfig {
    pub zero_time_ms: i64,
    pub zero_slot: u64,
    pub slot_ms: i64,
}

impl SlotConfig {
    pub fn for_network(name: &str) -> SlotConfig {
        match name {
            "mainnet" => SlotConfig { zero_time_ms: 1_596_059_091_000, zero_slot: 4_492_800, slot_ms: 1_000 },
            "preview" => SlotConfig { zero_time_ms: 1_666_656_000_000, zero_slot: 0, slot_ms: 1_000 },
            _ => SlotConfig { zero_time_ms: 1_655_769_600_000, zero_slot: 86_400, slot_ms: 1_000 },
        }
    }

    pub fn slot_at_or_after(&self, unix_ms: i64) -> u64 {
        let since = (unix_ms - self.zero_time_ms).max(0);
        self.zero_slot + ((since + self.slot_ms - 1) / self.slot_ms) as u64
    }

    pub fn time_of(&self, slot: u64) -> i64 {
        self.zero_time_ms + (slot.saturating_sub(self.zero_slot) as i64) * self.slot_ms
    }
}

fn encode_output(out: &mut Vec<u8>, o: &Output) {
    cbor_map(out, if o.datum.is_some() { 3 } else { 2 });
    cbor_uint(out, 0);
    cbor_bytes(out, &o.address);
    cbor_uint(out, 1);
    cbor_uint(out, o.lovelace);
    if let Some(d) = &o.datum {
        cbor_uint(out, 2);
        cbor_array(out, 2);
        cbor_uint(out, 1);
        cbor_tag(out, 24);
        cbor_bytes(out, &d.to_cbor());
    }
}

pub fn outputs_cbor(outputs: &[Output]) -> Vec<u8> {
    let mut out = Vec::new();
    cbor_array(&mut out, outputs.len());
    for o in outputs {
        encode_output(&mut out, o);
    }
    out
}

pub fn inputs_cbor(inputs: &[Utxo]) -> Vec<u8> {
    let mut out = Vec::new();
    cbor_array(&mut out, inputs.len());
    for u in inputs {
        cbor_array(&mut out, 2);
        cbor_bytes(&mut out, &u.tx_hash);
        cbor_uint(&mut out, u.index);
    }
    out
}

pub fn min_lovelace(o: &Output, p: &Params) -> u64 {
    let mut probe = Vec::new();
    encode_output(&mut probe, &Output { lovelace: u64::MAX, ..o.clone() });
    (160 + probe.len() as u64) * p.coins_per_utxo_byte
}

fn encode_inputs(out: &mut Vec<u8>, inputs: &[Utxo]) {
    cbor_tag(out, 258);
    cbor_array(out, inputs.len());
    for u in inputs {
        cbor_array(out, 2);
        cbor_bytes(out, &u.tx_hash);
        cbor_uint(out, u.index);
    }
}

fn sorted(mut inputs: Vec<Utxo>) -> Vec<Utxo> {
    inputs.sort_by(|a, b| a.tx_hash.cmp(&b.tx_hash).then(a.index.cmp(&b.index)));
    inputs.dedup_by(|a, b| a.tx_hash == b.tx_hash && a.index == b.index);
    inputs
}

pub struct ScriptSpend {
    pub utxo: Utxo,
    pub action: Action,
    pub ex_units: (u64, u64),
}

pub struct Plan {
    pub spend: Option<ScriptSpend>,
    pub outputs: Vec<Output>,
    pub funding: Vec<Utxo>,
    pub change: Vec<u8>,
    pub required_signers: Vec<Pkh>,
    pub valid_from: Option<u64>,
    pub ttl: u64,
    pub witnesses: usize,
}

#[derive(Debug, Clone)]
pub struct Unsigned {
    pub body: Vec<u8>,
    pub witness_parts: Vec<(u64, Vec<u8>)>,
    pub fee: u64,
    pub inputs: Vec<Utxo>,
}

impl Unsigned {
    pub fn tx_hash(&self) -> [u8; 32] {
        blake2b_256(&self.body)
    }

    pub fn sign(&self, keys: &[&SigningKey]) -> Vec<u8> {
        let hash = self.tx_hash();
        let mut ws = Vec::new();
        cbor_map(&mut ws, self.witness_parts.len() + 1);
        cbor_uint(&mut ws, 0);
        cbor_tag(&mut ws, 258);
        cbor_array(&mut ws, keys.len());
        for k in keys {
            cbor_array(&mut ws, 2);
            cbor_bytes(&mut ws, &k.verifying_key().to_bytes());
            cbor_bytes(&mut ws, &k.sign(&hash).to_bytes());
        }
        for (key, bytes) in &self.witness_parts {
            cbor_uint(&mut ws, *key);
            ws.extend_from_slice(bytes);
        }
        let mut tx = Vec::with_capacity(self.body.len() + ws.len() + 3);
        cbor_array(&mut tx, 4);
        tx.extend_from_slice(&self.body);
        tx.extend_from_slice(&ws);
        tx.push(0xf5);
        tx.push(0xf6);
        tx
    }
}

pub fn redeemers_cbor(index: u64, action: &Action, ex_units: (u64, u64)) -> Vec<u8> {
    let mut out = Vec::new();
    cbor_map(&mut out, 1);
    cbor_array(&mut out, 2);
    cbor_uint(&mut out, 0);
    cbor_uint(&mut out, index);
    cbor_array(&mut out, 2);
    action.to_data().encode(&mut out);
    cbor_array(&mut out, 2);
    cbor_uint(&mut out, ex_units.0);
    cbor_uint(&mut out, ex_units.1);
    out
}

pub fn language_views(cost_model_v3: &[i64]) -> Vec<u8> {
    let mut out = Vec::new();
    cbor_map(&mut out, 1);
    cbor_uint(&mut out, 2);
    cbor_array(&mut out, cost_model_v3.len());
    for c in cost_model_v3 {
        if *c >= 0 {
            head(&mut out, 0, *c as u64);
        } else {
            head(&mut out, 1, (-1 - *c) as u64);
        }
    }
    out
}

pub fn script_data_hash(redeemers: &[u8], cost_model_v3: &[i64]) -> [u8; 32] {
    let mut m = redeemers.to_vec();
    m.extend_from_slice(&language_views(cost_model_v3));
    blake2b_256(&m)
}

fn ceil_ratio(n: u128, num: u64, den: u64) -> u128 {
    (n * num as u128).div_ceil(den.max(1) as u128)
}

pub fn exec_fee(ex_units: (u64, u64), p: &Params) -> u64 {
    let mem = ex_units.0 as u128 * p.price_mem.0 as u128 * p.price_step.1 as u128;
    let steps = ex_units.1 as u128 * p.price_step.0 as u128 * p.price_mem.1 as u128;
    ((mem + steps).div_ceil(p.price_mem.1 as u128 * p.price_step.1 as u128)) as u64
}

fn assemble(plan: &Plan, inputs: &[Utxo], fee: u64, change: u64, p: &Params) -> Result<Unsigned, String> {
    let mut outputs = plan.outputs.clone();
    if change > 0 {
        outputs.push(Output { address: plan.change.clone(), lovelace: change, datum: None });
    }
    let mut parts: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut fields: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut v = Vec::new();
    encode_inputs(&mut v, inputs);
    fields.push((0, v));
    let mut v = Vec::new();
    cbor_array(&mut v, outputs.len());
    for o in &outputs {
        encode_output(&mut v, o);
    }
    fields.push((1, v));
    let mut v = Vec::new();
    cbor_uint(&mut v, fee);
    fields.push((2, v));
    let mut v = Vec::new();
    cbor_uint(&mut v, plan.ttl);
    fields.push((3, v));
    if let Some(from) = plan.valid_from {
        let mut v = Vec::new();
        cbor_uint(&mut v, from);
        fields.push((8, v));
    }
    if let Some(spend) = &plan.spend {
        let index = inputs
            .iter()
            .position(|u| u.tx_hash == spend.utxo.tx_hash && u.index == spend.utxo.index)
            .ok_or("the escrow is missing from the inputs")? as u64;
        let redeemers = redeemers_cbor(index, &spend.action, spend.ex_units);
        let mut v = Vec::new();
        cbor_bytes(&mut v, &script_data_hash(&redeemers, &p.cost_model_v3));
        fields.push((11, v));
        let collateral = plan
            .funding
            .iter()
            .filter(|u| u.pure_ada)
            .max_by_key(|u| u.lovelace)
            .ok_or("add a plain ADA coin to cover the script collateral")?;
        let total_collateral = ceil_ratio(fee as u128, p.collateral_percent, 100) as u64;
        let back = collateral
            .lovelace
            .checked_sub(total_collateral)
            .filter(|b| *b >= MIN_FEE_OUTPUT)
            .ok_or("the largest ADA coin is too small to post the script collateral")?;
        let mut v = Vec::new();
        encode_inputs(&mut v, std::slice::from_ref(collateral));
        fields.push((13, v));
        if !plan.required_signers.is_empty() {
            let mut v = Vec::new();
            cbor_tag(&mut v, 258);
            cbor_array(&mut v, plan.required_signers.len());
            for s in &plan.required_signers {
                cbor_bytes(&mut v, s);
            }
            fields.push((14, v));
        }
        let mut v = Vec::new();
        encode_output(&mut v, &Output { address: plan.change.clone(), lovelace: back, datum: None });
        fields.push((16, v));
        let mut v = Vec::new();
        cbor_uint(&mut v, total_collateral);
        fields.push((17, v));
        parts.push((5, redeemers));
        let mut v = Vec::new();
        cbor_tag(&mut v, 258);
        cbor_array(&mut v, 1);
        cbor_bytes(&mut v, &script_bytes());
        parts.push((7, v));
    }
    let mut body = Vec::new();
    cbor_map(&mut body, fields.len());
    for (k, v) in fields {
        cbor_uint(&mut body, k);
        body.extend_from_slice(&v);
    }
    Ok(Unsigned { body, witness_parts: parts, fee, inputs: inputs.to_vec() })
}

fn signed_size(u: &Unsigned, witnesses: usize) -> u64 {
    let mut parts = 0usize;
    for (_, bytes) in &u.witness_parts {
        parts += 1 + bytes.len();
    }
    let vkeys = 3 + 3 + witnesses * (1 + 2 + 32 + 2 + 64);
    (1 + u.body.len() + 1 + parts + vkeys + 2) as u64
}

fn needed_fee(draft: &Unsigned, plan: &Plan, p: &Params, exec: u64) -> Result<u64, String> {
    let size = signed_size(draft, plan.witnesses.max(1));
    if size > p.max_tx_size {
        return Err("the transaction is larger than Cardano allows".into());
    }
    Ok(p.min_fee_a * size + p.min_fee_b + exec)
}

pub fn build(plan: &Plan, p: &Params) -> Result<Unsigned, String> {
    for o in &plan.outputs {
        let need = min_lovelace(o, p);
        if o.lovelace < need {
            return Err(format!(
                "an output of {} ADA is below the Cardano minimum of {} ADA",
                o.lovelace as f64 / 1e6,
                need as f64 / 1e6
            ));
        }
    }
    let exec = plan.spend.as_ref().map(|s| exec_fee(s.ex_units, p)).unwrap_or(0);
    let pay: u64 = plan.outputs.iter().map(|o| o.lovelace).sum();
    let from_script = plan.spend.as_ref().map(|s| s.utxo.lovelace).unwrap_or(0);
    let change_min = min_lovelace(&Output { address: plan.change.clone(), lovelace: 0, datum: None }, p);
    let mut coins: Vec<Utxo> = plan.funding.clone();
    coins.sort_by(|a, b| b.pure_ada.cmp(&a.pure_ada).then(b.lovelace.cmp(&a.lovelace)));
    let mut fee = p.min_fee_b + exec + 200 * p.min_fee_a;
    for _ in 0..8 {
        let mut chosen: Vec<Utxo> = Vec::new();
        let mut have = from_script;
        for c in coins.iter().filter(|c| c.pure_ada) {
            if have >= pay + fee + change_min && !chosen.is_empty() {
                break;
            }
            if chosen.len() >= MAX_INPUTS {
                break;
            }
            have += c.lovelace;
            chosen.push(c.clone());
        }
        if have < pay + fee {
            return Err(format!(
                "not enough ADA: {} ADA available, {} ADA needed including the network fee",
                have as f64 / 1e6,
                (pay + fee) as f64 / 1e6
            ));
        }
        let mut change = have - pay - fee;
        let mut paid_fee = fee;
        if change < change_min {
            paid_fee += change;
            change = 0;
        }
        let mut inputs = chosen.clone();
        if let Some(s) = &plan.spend {
            inputs.push(s.utxo.clone());
        }
        let inputs = sorted(inputs);
        let draft = assemble(plan, &inputs, paid_fee, change, p)?;
        let needed = needed_fee(&draft, plan, p, exec)?;
        if needed <= paid_fee {
            if change > 0 && paid_fee > needed + 1_000 {
                let leaner = assemble(plan, &inputs, needed + 200, change + paid_fee - needed - 200, p)?;
                if needed_fee(&leaner, plan, p, exec)? <= needed + 200 {
                    return Ok(leaner);
                }
            }
            return Ok(draft);
        }
        fee = needed + 1_000;
    }
    Err("the network fee did not settle".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> Params {
        Params {
            min_fee_a: 44,
            min_fee_b: 155_381,
            coins_per_utxo_byte: 4_310,
            price_mem: (577, 10_000),
            price_step: (721, 10_000_000),
            collateral_percent: 150,
            max_tx_size: 16_384,
            cost_model_v3: (0..297).map(|i| (i * 7 + 3) as i64).collect(),
        }
    }

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    fn pkh(k: &SigningKey) -> Pkh {
        blake2b_224(&k.verifying_key().to_bytes())
    }

    fn coin(b: u8, lovelace: u64) -> Utxo {
        Utxo { tx_hash: [b; 32], index: b as u64, lovelace, pure_ada: true }
    }

    fn datum() -> EscrowDatum {
        EscrowDatum {
            trade_id: [0x11; 32],
            seller: key_address(0, &pkh(&key(1))),
            buyer: key_address(0, &pkh(&key(2))),
            arbiter: pkh(&key(3)),
            fee_receiver: key_address(0, &pkh(&key(4))),
            total: 101_000_000,
            fee: 1_000_000,
            fallback_at: 1_800_000_000_000,
            frozen: false,
        }
    }

    #[test]
    fn the_embedded_script_matches_the_aiken_build() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts/p2p-cardano/plutus.json");
        let blueprint: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let v = &blueprint["validators"][0];
        assert_eq!(v["compiledCode"].as_str().unwrap(), SCRIPT_HEX.trim());
        assert_eq!(hex::encode(script_hash()), v["hash"].as_str().unwrap());
    }

    #[test]
    fn the_buyer_signature_matches_the_validator_test_vector() {
        let (vkey, sig) = sign_auth(&key(2), &[0xee; 28], &[0x11; 32], ACTION_CANCEL);
        assert_eq!(hex::encode(vkey), "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394");
        assert_eq!(
            hex::encode(sig),
            "18113fa96978187fd31385401f806ff9d745421410ab3fadc77cf05041d4237b99a84b0f10e16b5f8e65b5f1572246b32fa6873be8e18366649f9f532f49db02"
        );
        let buyer = blake2b_224(&vkey);
        assert!(verify_auth(&vkey, &sig, &buyer, &[0xee; 28], &[0x11; 32], ACTION_CANCEL));
        assert!(!verify_auth(&vkey, &sig, &buyer, &[0xee; 28], &[0x11; 32], ACTION_FREEZE));
        assert!(!verify_auth(&vkey, &sig, &[0; 28], &[0xee; 28], &[0x11; 32], ACTION_CANCEL));
    }

    #[test]
    fn a_datum_survives_a_round_trip_through_cbor() {
        let mut d = datum();
        d.buyer = {
            let mut base = vec![0x00];
            base.extend_from_slice(&[7; 28]);
            base.extend_from_slice(&[8; 28]);
            base
        };
        let cbor = d.to_data().unwrap().to_cbor();
        let back = EscrowDatum::from_data(&Data::from_cbor(&cbor).unwrap(), 0).unwrap();
        assert_eq!(back, d);
        assert_eq!(&cbor[..3], &[0xd8, 0x79, 0x89]);
    }

    #[test]
    fn indefinite_and_chunked_encodings_decode_the_same() {
        let indefinite = hex::decode("d8799f4101d87a80ff").unwrap();
        assert_eq!(
            Data::from_cbor(&indefinite).unwrap(),
            Data::constr(0, vec![Data::bytes(&[1]), Data::bool(true)])
        );
        let long = Data::Bytes((0..100).collect());
        assert_eq!(Data::from_cbor(&long.to_cbor()).unwrap(), long);
        let big = Data::Int(-(1i128 << 70));
        assert_eq!(Data::from_cbor(&big.to_cbor()).unwrap(), big);
    }

    #[test]
    fn addresses_round_trip_and_reject_the_wrong_kind() {
        let raw = key_address(0, &[9; 28]);
        let s = format_address(&raw);
        assert!(s.starts_with("addr_test1"));
        assert_eq!(parse_address(&s).unwrap(), raw);
        assert_eq!(payment_key_hash(&raw), Some([9; 28]));
        let script = script_address(0, &script_hash());
        assert_eq!(payment_script_hash(&script), Some(script_hash()));
        assert_eq!(payment_key_hash(&script), None);
        assert!(parse_address("addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x").is_ok());
        assert!(parse_address("stake_test1uqehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gssrtvn").is_err());
        let mainnet = format_address(&key_address(1, &[9; 28]));
        assert!(mainnet.starts_with("addr1"));
        assert_eq!(address_from_data(&address_data(&raw).unwrap(), 0).unwrap(), raw);
    }

    #[test]
    fn a_spend_balances_and_pays_its_own_fee() {
        let p = params();
        let d = datum();
        let seller = key(1);
        let escrow = Utxo { tx_hash: [0xaa; 32], index: 0, lovelace: d.total, pure_ada: true };
        let plan = Plan {
            spend: Some(ScriptSpend { utxo: escrow.clone(), action: Action::Release, ex_units: (SPEND_MEM, SPEND_STEPS) }),
            outputs: vec![
                Output { address: d.buyer.clone(), lovelace: d.total - d.fee, datum: None },
                Output { address: d.fee_receiver.clone(), lovelace: d.fee, datum: None },
            ],
            funding: vec![coin(0x01, 3_000_000), coin(0xfe, 9_000_000)],
            change: d.seller.clone(),
            required_signers: vec![pkh(&seller)],
            valid_from: None,
            ttl: 90_000_000,
            witnesses: 1,
        };
        let u = build(&plan, &p).unwrap();
        let tx = u.sign(&[&seller]);
        let size = tx.len() as u64;
        let exec = exec_fee((SPEND_MEM, SPEND_STEPS), &p);
        assert!(u.fee >= p.min_fee_a * size + p.min_fee_b + exec, "fee {} for {size} bytes", u.fee);
        assert!(u.fee < p.min_fee_a * size + p.min_fee_b + exec + 20_000);
        let inputs: u64 = u.inputs.iter().map(|i| i.lovelace).sum();
        let body = Data::from_any_cbor(&u.body).unwrap();
        let Data::Map(fields) = body else { panic!("the body is a map") };
        let outputs = fields.iter().find(|(k, _)| *k == Data::Int(1)).unwrap();
        let Data::List(outs) = &outputs.1 else { panic!() };
        let paid: u64 = outs
            .iter()
            .map(|o| match o {
                Data::Map(m) => m.iter().find(|(k, _)| *k == Data::Int(1)).map(|(_, v)| v.as_int().unwrap() as u64).unwrap(),
                _ => 0,
            })
            .sum();
        assert_eq!(inputs, paid + u.fee, "inputs equal outputs plus the fee");
        let sdh = fields.iter().find(|(k, _)| *k == Data::Int(11)).unwrap();
        let index = u.inputs.iter().position(|i| i.tx_hash == [0xaa; 32]).unwrap() as u64;
        let expected = script_data_hash(&redeemers_cbor(index, &Action::Release, (SPEND_MEM, SPEND_STEPS)), &p.cost_model_v3);
        assert_eq!(sdh.1, Data::Bytes(expected.to_vec()));
        assert!(fields.iter().any(|(k, _)| *k == Data::Int(13)));
        assert!(fields.iter().any(|(k, _)| *k == Data::Int(14)));
    }

    #[test]
    fn an_open_puts_the_datum_inline_at_the_script() {
        let p = params();
        let d = datum();
        let seller = key(1);
        let escrow = Output { address: script_address(0, &script_hash()), lovelace: d.total, datum: Some(d.to_data().unwrap()) };
        assert!(min_lovelace(&escrow, &p) < 3_000_000);
        let plan = Plan {
            spend: None,
            outputs: vec![escrow],
            funding: vec![coin(3, 60_000_000), coin(4, 60_000_000)],
            change: d.seller.clone(),
            required_signers: vec![],
            valid_from: None,
            ttl: 90_000_000,
            witnesses: 1,
        };
        let u = build(&plan, &p).unwrap();
        let tx = u.sign(&[&seller]);
        assert!(u.fee >= p.min_fee_a * tx.len() as u64 + p.min_fee_b);
        assert!(u.witness_parts.is_empty());
        let short = Plan { funding: vec![coin(3, 50_000_000)], ..plan };
        assert!(build(&short, &p).unwrap_err().contains("not enough ADA"));
    }

    #[test]
    fn slots_convert_to_and_from_posix_time() {
        let c = SlotConfig::for_network("preprod");
        assert_eq!(c.time_of(86_400), 1_655_769_600_000);
        let t = 1_800_000_000_500;
        let s = c.slot_at_or_after(t);
        assert!(c.time_of(s) >= t && c.time_of(s - 1) < t);
    }
}
