use serde::{Deserialize, Serialize};

pub const DISPUTE_WINDOW_BLOCKS: u64 = 7;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChannel {
    pub channel_id: String,
    pub party_a: String,
    pub party_b: String,
    pub collateral_a: u64,
    pub collateral_b: u64,
    pub balance_a: u64,
    pub balance_b: u64,
    pub nonce: u64,
    pub status: ChannelStatus,
    pub open_l1_height: u64,
    pub close_l1_height: Option<u64>,
    pub dispute_deadline: Option<u64>,
    pub latest_sig_a: String,
    pub latest_sig_b: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChannelStatus {
    Open,
    Closing,
    Closed,
    Disputed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelUpdate {
    pub channel_id: String,
    pub balance_a: u64,
    pub balance_b: u64,
    pub nonce: u64,
    pub sig_from: String,
    pub signed_by: String,
}

pub fn channel_update_hash(channel_id: &str, balance_a: u64, balance_b: u64, nonce: u64) -> String {
    let data = format!("l2channel:{}:{}:{}:{}", channel_id, balance_a, balance_b, nonce);
    format!("0x{}", blake3::hash(data.as_bytes()).to_hex())
}

pub fn open_channel(
    party_a: &str,
    party_b: &str,
    collateral_a: u64,
    collateral_b: u64,
    l1_height: u64,
) -> StateChannel {
    let id_data = format!("channel:{}:{}:{}:{}", party_a, party_b, collateral_a, l1_height);
    let channel_id = format!("egochan1{}", blake3::hash(id_data.as_bytes()).to_hex());
    StateChannel {
        channel_id,
        party_a: party_a.to_string(),
        party_b: party_b.to_string(),
        collateral_a,
        collateral_b,
        balance_a: collateral_a,
        balance_b: collateral_b,
        nonce: 0,
        status: ChannelStatus::Open,
        open_l1_height: l1_height,
        close_l1_height: None,
        dispute_deadline: None,
        latest_sig_a: String::new(),
        latest_sig_b: String::new(),
    }
}

pub fn apply_update(channel: &mut StateChannel, update: &ChannelUpdate) -> Result<(), String> {
    if update.nonce <= channel.nonce {
        return Err(format!("stale nonce: {} <= {}", update.nonce, channel.nonce));
    }
    if update.balance_a + update.balance_b != channel.collateral_a + channel.collateral_b {
        return Err("balances must sum to total collateral".into());
    }
    channel.balance_a = update.balance_a;
    channel.balance_b = update.balance_b;
    channel.nonce = update.nonce;
    if update.signed_by == channel.party_a {
        channel.latest_sig_a = update.sig_from.clone();
    } else if update.signed_by == channel.party_b {
        channel.latest_sig_b = update.sig_from.clone();
    }
    Ok(())
}

pub fn initiate_close(channel: &mut StateChannel, l1_height: u64) {
    channel.status = ChannelStatus::Closing;
    channel.close_l1_height = Some(l1_height);
    channel.dispute_deadline = Some(l1_height + DISPUTE_WINDOW_BLOCKS);
}

pub fn finalize_close(channel: &mut StateChannel) -> (u64, u64) {
    channel.status = ChannelStatus::Closed;
    (channel.balance_a, channel.balance_b)
}
