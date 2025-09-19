use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    bincode::Encode,
    bincode::Decode,
)]
pub struct Hash([u8; 32]);

impl Hash {
    pub const ZERO: Self = Hash([0u8; 32]);

    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, crate::EgoError> {
        if slice.len() != 32 {
            return Err(crate::EgoError::CryptoError(format!(
                "Invalid hash length: expected 32, got {}",
                slice.len()
            )));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    pub fn random() -> Self {
        Self(rand::random())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl From<[u8; 32]> for Hash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    bincode::Encode,
    bincode::Decode,
)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, crate::EgoError> {
        if slice.len() != 32 {
            return Err(crate::EgoError::CryptoError(format!(
                "Invalid public key length: expected 32, got {}",
                slice.len()
            )));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, bincode::Encode, bincode::Decode)]
pub struct Signature([u8; 64]);

impl Signature {
    pub fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, crate::EgoError> {
        if slice.len() != 64 {
            return Err(crate::EgoError::CryptoError(format!(
                "Invalid signature length: expected 64, got {}",
                slice.len()
            )));
        }
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }
}

impl serde::Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SignatureVisitor;

        impl<'de> serde::de::Visitor<'de> for SignatureVisitor {
            type Value = Signature;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("64 bytes")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() == 64 {
                    let mut bytes = [0u8; 64];
                    bytes.copy_from_slice(v);
                    Ok(Signature(bytes))
                } else {
                    Err(E::invalid_length(v.len(), &self))
                }
            }
        }

        deserializer.deserialize_bytes(SignatureVisitor)
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    bincode::Encode,
    bincode::Decode,
)]
pub struct Address([u8; 20]);

impl Address {
    pub fn new(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn from_public_key(pubkey: &PublicKey) -> Self {
        let hash = blake3::hash(pubkey.as_bytes());
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&hash.as_bytes()[..20]);
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, crate::EgoError> {
        if slice.len() != 20 {
            return Err(crate::EgoError::CryptoError(format!(
                "Invalid address length: expected 20, got {}",
                slice.len()
            )));
        }
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    pub fn random() -> Self {
        Self(rand::random())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ego{}", hex::encode(self.0))
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    bincode::Encode,
    bincode::Decode,
)]
pub struct Timestamp(pub u64);

impl Default for Timestamp {
    fn default() -> Self {
        Self::now()
    }
}

impl Timestamp {
    pub fn now() -> Self {
        Self(chrono::Utc::now().timestamp_millis() as u64)
    }

    pub fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    pub fn from_secs(secs: u64) -> Self {
        Self(secs * 1000)
    }

    pub fn as_millis(&self) -> u64 {
        self.0
    }

    pub fn as_secs(&self) -> u64 {
        self.0 / 1000
    }

    pub fn elapsed_millis(&self) -> u64 {
        Self::now().0.saturating_sub(self.0)
    }

    pub fn elapsed_secs(&self) -> u64 {
        self.elapsed_millis() / 1000
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let datetime = chrono::DateTime::from_timestamp_millis(self.0 as i64).unwrap_or_default();
        write!(f, "{}", datetime.format("%Y-%m-%d %H:%M:%S UTC"))
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    bincode::Encode,
    bincode::Decode,
)]
pub struct ShardId(pub u32);

impl ShardId {
    pub fn new(id: u32) -> Result<Self, crate::EgoError> {
        if id >= crate::MAX_SHARD_COUNT {
            return Err(crate::EgoError::InvalidShardId { shard_id: id });
        }
        Ok(Self(id))
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }

    pub fn from_u32(id: u32) -> Self {
        Self(id)
    }
}

impl fmt::Display for ShardId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "shard-{}", self.0)
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    bincode::Encode,
    bincode::Decode,
)]
pub struct BlockHeight(pub u64);

impl BlockHeight {
    pub const GENESIS: Self = BlockHeight(0);

    pub fn new(height: u64) -> Self {
        Self(height)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn next(&self) -> Self {
        Self(self.0 + 1)
    }

    pub fn prev(&self) -> Self {
        Self(self.0.saturating_sub(1))
    }

    pub fn is_genesis(&self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for BlockHeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    bincode::Encode,
    bincode::Decode,
)]
pub struct EpochNumber(pub u64);

impl EpochNumber {
    pub const GENESIS: Self = EpochNumber(0);

    pub fn new(epoch: u64) -> Self {
        Self(epoch)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn next(&self) -> Self {
        Self(self.0 + 1)
    }

    pub fn prev(&self) -> Self {
        Self(self.0.saturating_sub(1))
    }
}

impl fmt::Display for EpochNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "epoch-{}", self.0)
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    bincode::Encode,
    bincode::Decode,
)]
pub struct Balance(pub u128);

impl Default for Balance {
    fn default() -> Self {
        Self::ZERO
    }
}

impl Balance {
    pub const ZERO: Self = Balance(0);

    pub fn new(amount: u128) -> Self {
        Self(amount)
    }

    pub fn from_egoc(egoc: u64) -> Self {
        Self(egoc as u128 * crate::EGOC_BASE_UNIT)
    }

    pub fn from_uegoc(uegoc: u128) -> Self {
        Self(uegoc)
    }

    pub fn as_u128(&self) -> u128 {
        self.0
    }

    pub fn to_egoc(&self) -> f64 {
        self.0 as f64 / crate::EGOC_BASE_UNIT as f64
    }

    pub fn to_uegoc(&self) -> u128 {
        self.0
    }

    pub fn checked_add(&self, other: Balance) -> Option<Balance> {
        self.0.checked_add(other.0).map(Balance)
    }

    pub fn checked_sub(&self, other: Balance) -> Option<Balance> {
        self.0.checked_sub(other.0).map(Balance)
    }

    pub fn checked_mul(&self, multiplier: u128) -> Option<Balance> {
        self.0.checked_mul(multiplier).map(Balance)
    }

    pub fn checked_div(&self, divisor: u128) -> Option<Balance> {
        if divisor == 0 {
            None
        } else {
            Some(Balance(self.0 / divisor))
        }
    }

    pub fn saturating_add(&self, other: Balance) -> Balance {
        Balance(self.0.saturating_add(other.0))
    }

    pub fn saturating_sub(&self, other: Balance) -> Balance {
        Balance(self.0.saturating_sub(other.0))
    }

    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for Balance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.8} EGOC", self.to_egoc())
    }
}

impl From<u128> for Balance {
    fn from(amount: u128) -> Self {
        Self(amount)
    }
}

impl From<u64> for Balance {
    fn from(amount: u64) -> Self {
        Self(amount as u128)
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, bincode::Encode, bincode::Decode,
)]
pub struct SliceId(pub String);

impl SliceId {
    pub fn new(id: String) -> Self {
        Self(id)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    pub fn is_valid(&self) -> bool {
        !self.0.is_empty()
            && self.0.len() <= 64
            && self
                .0
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    }
}

impl fmt::Display for SliceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for SliceId {
    fn from(id: String) -> Self {
        Self(id)
    }
}

impl From<&str> for SliceId {
    fn from(id: &str) -> Self {
        Self(id.to_string())
    }
}

// Additional types for better node integration
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(pub String);

impl PeerId {
    pub fn new(id: String) -> Self {
        Self(id)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<libp2p::PeerId> for PeerId {
    fn from(peer_id: libp2p::PeerId) -> Self {
        Self(peer_id.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeId(pub PeerId);

impl NodeId {
    pub fn new(peer_id: PeerId) -> Self {
        Self(peer_id)
    }

    pub fn from_libp2p(peer_id: libp2p::PeerId) -> Self {
        Self(PeerId::from(peer_id))
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkQuality {
    pub latency_ms: u32,
    pub bandwidth_mbps: u64,
    pub reliability_score: u8,
    pub cost_per_gb_usd: f64,
}

impl Default for NetworkQuality {
    fn default() -> Self {
        Self {
            latency_ms: 100,
            bandwidth_mbps: 100,
            reliability_score: 80,
            cost_per_gb_usd: 0.0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeoLocation {
    pub latitude: f64,
    pub longitude: f64,
    pub h3_index: Option<String>,
    pub country_code: Option<String>,
    pub region: Option<String>,
}

impl GeoLocation {
    pub fn new(latitude: f64, longitude: f64) -> Self {
        Self {
            latitude,
            longitude,
            h3_index: None,
            country_code: None,
            region: None,
        }
    }

    pub fn distance_to(&self, other: &GeoLocation) -> f64 {
        let r = 6371.0;
        let lat1 = self.latitude.to_radians();
        let lat2 = other.latitude.to_radians();
        let delta_lat = (other.latitude - self.latitude).to_radians();
        let delta_lon = (other.longitude - self.longitude).to_radians();

        let a = (delta_lat / 2.0).sin().powi(2)
            + lat1.cos() * lat2.cos() * (delta_lon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

        r * c
    }
}
