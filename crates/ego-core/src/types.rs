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
pub enum AlgorithmId {
    Ed25519 = 1,
    MlDsa2 = 2,
    SlhDsa = 3,
    X25519 = 4,
    MlKem768 = 5,
    XChaCha20Poly1305 = 6,
    Blake2s = 7,
    HkdfBlake2s = 8,
}

impl AlgorithmId {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Ed25519),
            2 => Some(Self::MlDsa2),
            3 => Some(Self::SlhDsa),
            4 => Some(Self::X25519),
            5 => Some(Self::MlKem768),
            6 => Some(Self::XChaCha20Poly1305),
            7 => Some(Self::Blake2s),
            8 => Some(Self::HkdfBlake2s),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, bincode::Encode, bincode::Decode)]
pub struct PublicKey {
    pub algorithm: AlgorithmId,
    pub key_data: [u8; 64],
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("PublicKey", 2)?;
        state.serialize_field("algorithm", &self.algorithm)?;
        state.serialize_field("key_data", &self.key_data.as_slice())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct PublicKeyHelper {
            algorithm: AlgorithmId,
            key_data: Vec<u8>,
        }

        let helper = PublicKeyHelper::deserialize(deserializer)?;
        if helper.key_data.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "Expected 64 bytes, got {}",
                helper.key_data.len()
            )));
        }

        let mut key_data = [0u8; 64];
        key_data.copy_from_slice(&helper.key_data);

        Ok(PublicKey {
            algorithm: helper.algorithm,
            key_data,
        })
    }
}

impl PublicKey {
    pub fn new(algorithm: AlgorithmId, key_data: &[u8]) -> Self {
        let mut data = [0u8; 64];
        let len = key_data.len().min(64);
        data[..len].copy_from_slice(&key_data[..len]);
        Self {
            algorithm,
            key_data: data,
        }
    }

    pub fn ed25519(bytes: [u8; 32]) -> Self {
        let mut data = [0u8; 64];
        data[..32].copy_from_slice(&bytes);
        Self {
            algorithm: AlgorithmId::Ed25519,
            key_data: data,
        }
    }

    pub fn dilithium2(key_data: &[u8]) -> Self {
        let mut data = [0u8; 64];
        let len = key_data.len().min(64);
        data[..len].copy_from_slice(&key_data[..len]);
        Self {
            algorithm: AlgorithmId::MlDsa2,
            key_data: data,
        }
    }

    pub fn kyber768(key_data: &[u8]) -> Self {
        let mut data = [0u8; 64];
        let len = key_data.len().min(64);
        data[..len].copy_from_slice(&key_data[..len]);
        Self {
            algorithm: AlgorithmId::MlKem768,
            key_data: data,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.key_data
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(self.algorithm.as_u8());
        result.extend_from_slice(&self.key_data);
        result
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, crate::EgoError> {
        if slice.len() < 1 {
            return Err(crate::EgoError::CryptoError(
                "Invalid public key format: too short".to_string(),
            ));
        }

        let algorithm = AlgorithmId::from_u8(slice[0])
            .ok_or_else(|| crate::EgoError::CryptoError("Invalid algorithm ID".to_string()))?;

        let mut key_data = [0u8; 64];
        let len = (slice.len() - 1).min(64);
        if len > 0 {
            key_data[..len].copy_from_slice(&slice[1..1 + len]);
        }

        Ok(Self {
            algorithm,
            key_data,
        })
    }

    pub fn ed25519_bytes(&self) -> Option<[u8; 32]> {
        if self.algorithm == AlgorithmId::Ed25519 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&self.key_data[..32]);
            Some(bytes)
        } else {
            None
        }
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?}:{}",
            self.algorithm,
            hex::encode(&self.key_data[..32])
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct Signature {
    pub algorithm: AlgorithmId,
    pub signature_data: Vec<u8>,
}

impl Signature {
    pub fn new(algorithm: AlgorithmId, signature_data: Vec<u8>) -> Self {
        Self {
            algorithm,
            signature_data,
        }
    }

    pub fn ed25519(bytes: [u8; 64]) -> Self {
        Self {
            algorithm: AlgorithmId::Ed25519,
            signature_data: bytes.to_vec(),
        }
    }

    pub fn dilithium2(signature_data: Vec<u8>) -> Self {
        Self {
            algorithm: AlgorithmId::MlDsa2,
            signature_data,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.signature_data
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(self.algorithm.as_u8());
        result.extend_from_slice(&(self.signature_data.len() as u32).to_le_bytes());
        result.extend_from_slice(&self.signature_data);
        result
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, crate::EgoError> {
        if slice.len() < 5 {
            return Err(crate::EgoError::CryptoError(
                "Invalid signature format: too short".to_string(),
            ));
        }

        let algorithm = AlgorithmId::from_u8(slice[0])
            .ok_or_else(|| crate::EgoError::CryptoError("Invalid algorithm ID".to_string()))?;

        let len = u32::from_le_bytes([slice[1], slice[2], slice[3], slice[4]]) as usize;

        if slice.len() != 5 + len {
            return Err(crate::EgoError::CryptoError(
                "Invalid signature format: length mismatch".to_string(),
            ));
        }

        let signature_data = slice[5..].to_vec();

        Ok(Self {
            algorithm,
            signature_data,
        })
    }

    pub fn ed25519_bytes(&self) -> Option<[u8; 64]> {
        if self.algorithm == AlgorithmId::Ed25519 && self.signature_data.len() == 64 {
            let mut bytes = [0u8; 64];
            bytes.copy_from_slice(&self.signature_data);
            Some(bytes)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DualSignature {
    pub ed25519_sig: Option<Signature>,
    pub dilithium_sig: Option<Signature>,
}

impl DualSignature {
    pub fn new(ed25519_sig: Option<Signature>, dilithium_sig: Option<Signature>) -> Self {
        Self {
            ed25519_sig,
            dilithium_sig,
        }
    }

    pub fn ed25519_only(sig: Signature) -> Self {
        Self {
            ed25519_sig: Some(sig),
            dilithium_sig: None,
        }
    }

    pub fn dilithium_only(sig: Signature) -> Self {
        Self {
            ed25519_sig: None,
            dilithium_sig: Some(sig),
        }
    }

    pub fn hybrid(ed25519_sig: Signature, dilithium_sig: Signature) -> Self {
        Self {
            ed25519_sig: Some(ed25519_sig),
            dilithium_sig: Some(dilithium_sig),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct SessionRecord {
    pub x25519_pubkey: Option<Vec<u8>>,
    pub kyber_ciphertext: Vec<u8>,
    pub nonce: [u8; 24],
    pub aead_tag: Vec<u8>,
}

impl SessionRecord {
    pub fn new(
        x25519_pubkey: Option<Vec<u8>>,
        kyber_ciphertext: Vec<u8>,
        nonce: [u8; 24],
        aead_tag: Vec<u8>,
    ) -> Self {
        Self {
            x25519_pubkey,
            kyber_ciphertext,
            nonce,
            aead_tag,
        }
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
        let hash = blake3::hash(&pubkey.to_vec());
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
