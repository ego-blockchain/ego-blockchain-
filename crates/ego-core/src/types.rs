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

    pub fn as_millis(&self) -> u64 {
        self.0
    }

    pub fn as_secs(&self) -> u64 {
        self.0 / 1000
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

    pub fn as_u128(&self) -> u128 {
        self.0
    }

    pub fn to_egoc(&self) -> f64 {
        self.0 as f64 / crate::EGOC_BASE_UNIT as f64
    }

    pub fn checked_add(&self, other: Balance) -> Option<Balance> {
        self.0.checked_add(other.0).map(Balance)
    }

    pub fn checked_sub(&self, other: Balance) -> Option<Balance> {
        self.0.checked_sub(other.0).map(Balance)
    }
}

impl fmt::Display for Balance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.6} EGOC", self.to_egoc())
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
}

impl fmt::Display for SliceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
