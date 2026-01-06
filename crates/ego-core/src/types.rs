use serde::{Deserialize, Serialize};
use std::fmt;
pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_SHARD_COUNT: u32 = 256;
pub const EGOC_BASE_UNIT: u128 = 1_000_000_000;

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
    Ed25519 = 0xED01,
    MlDsa2 = 0x0202,
    SlhDsa = 0x0303,
    X25519 = 0x0101,
    MlKem768 = 0x0302,
    XChaCha20Poly1305 = 0x0401,
    Blake2s256 = 0x0501,
    HkdfBlake2s = 0x0502,
}

impl AlgorithmId {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0xED01 => Some(Self::Ed25519),
            0x0202 => Some(Self::MlDsa2),
            0x0303 => Some(Self::SlhDsa),
            0x0101 => Some(Self::X25519),
            0x0302 => Some(Self::MlKem768),
            0x0401 => Some(Self::XChaCha20Poly1305),
            0x0501 => Some(Self::Blake2s256),
            0x0502 => Some(Self::HkdfBlake2s),
            _ => None,
        }
    }

    pub fn as_u16(&self) -> u16 {
        *self as u16
    }

    pub fn is_signature_algorithm(&self) -> bool {
        matches!(self, Self::Ed25519 | Self::MlDsa2 | Self::SlhDsa)
    }

    pub fn is_kem_algorithm(&self) -> bool {
        matches!(self, Self::MlKem768 | Self::X25519)
    }

    pub fn is_pq_algorithm(&self) -> bool {
        matches!(self, Self::MlDsa2 | Self::SlhDsa | Self::MlKem768)
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::MlDsa2 => "ML-DSA-2 (Dilithium-2)",
            Self::SlhDsa => "SLH-DSA (SPHINCS+)",
            Self::X25519 => "X25519",
            Self::MlKem768 => "ML-KEM-768 (Kyber-768)",
            Self::XChaCha20Poly1305 => "XChaCha20-Poly1305",
            Self::Blake2s256 => "BLAKE2s-256",
            Self::HkdfBlake2s => "HKDF-BLAKE2s",
        }
    }
}

impl fmt::Display for AlgorithmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
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

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, crate::EgoError> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| crate::EgoError::CryptoError(format!("Invalid hex string: {}", e)))?;
        Self::from_slice(&bytes)
    }

    pub fn short_display(&self) -> String {
        format!("{}...{}", &self.to_hex()[..8], &self.to_hex()[56..])
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

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, bincode::Encode, bincode::Decode)]
pub struct PublicKey {
    pub algorithm: AlgorithmId,
    pub key_data: Vec<u8>,
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("PublicKey", 2)?;
        state.serialize_field("algorithm", &self.algorithm)?;
        state.serialize_field("key_data", &self.key_data)?;
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
        Ok(PublicKey {
            algorithm: helper.algorithm,
            key_data: helper.key_data,
        })
    }
}

impl PublicKey {
    pub fn new(algorithm: AlgorithmId, key_data: Vec<u8>) -> Self {
        Self {
            algorithm,
            key_data,
        }
    }

    pub fn ed25519(bytes: [u8; 32]) -> Self {
        Self {
            algorithm: AlgorithmId::Ed25519,
            key_data: bytes.to_vec(),
        }
    }

    pub fn dilithium2(key_data: Vec<u8>) -> Self {
        Self {
            algorithm: AlgorithmId::MlDsa2,
            key_data,
        }
    }

    pub fn kyber768(key_data: Vec<u8>) -> Self {
        Self {
            algorithm: AlgorithmId::MlKem768,
            key_data,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.key_data
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.algorithm.as_u16().to_le_bytes());
        result.extend_from_slice(&(self.key_data.len() as u32).to_le_bytes());
        result.extend_from_slice(&self.key_data);
        result
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, crate::EgoError> {
        if slice.len() < 6 {
            return Err(crate::EgoError::CryptoError(
                "Invalid public key format: too short".to_string(),
            ));
        }

        let alg_bytes = [slice[0], slice[1]];
        let algorithm = AlgorithmId::from_u16(u16::from_le_bytes(alg_bytes))
            .ok_or_else(|| crate::EgoError::CryptoError("Invalid algorithm ID".to_string()))?;

        let len_bytes = [slice[2], slice[3], slice[4], slice[5]];
        let len = u32::from_le_bytes(len_bytes) as usize;

        if slice.len() != 6 + len {
            return Err(crate::EgoError::CryptoError(
                "Invalid public key format: length mismatch".to_string(),
            ));
        }

        let key_data = slice[6..].to_vec();

        Ok(Self {
            algorithm,
            key_data,
        })
    }

    pub fn ed25519_bytes(&self) -> Option<[u8; 32]> {
        if self.algorithm == AlgorithmId::Ed25519 && self.key_data.len() == 32 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&self.key_data);
            Some(bytes)
        } else {
            None
        }
    }

    pub fn size(&self) -> usize {
        6 + self.key_data.len()
    }

    pub fn validate(&self) -> Result<(), crate::EgoError> {
        match self.algorithm {
            AlgorithmId::Ed25519 => {
                if self.key_data.len() != 32 {
                    return Err(crate::EgoError::CryptoError(
                        "Ed25519 key must be 32 bytes".to_string(),
                    ));
                }
            }
            AlgorithmId::MlDsa2 => {
                if self.key_data.len() != 1312 {
                    return Err(crate::EgoError::CryptoError(
                        "ML-DSA-2 key must be 1312 bytes".to_string(),
                    ));
                }
            }
            AlgorithmId::MlKem768 => {
                if self.key_data.len() != 1184 {
                    return Err(crate::EgoError::CryptoError(
                        "ML-KEM-768 key must be 1184 bytes".to_string(),
                    ));
                }
            }
            _ => {}
        }
        Ok(())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}...",
            self.algorithm,
            hex::encode(&self.key_data[..self.key_data.len().min(16)])
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

    pub fn slh_dsa(signature_data: Vec<u8>) -> Self {
        Self {
            algorithm: AlgorithmId::SlhDsa,
            signature_data,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.signature_data
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.algorithm.as_u16().to_le_bytes());
        result.extend_from_slice(&(self.signature_data.len() as u32).to_le_bytes());
        result.extend_from_slice(&self.signature_data);
        result
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, crate::EgoError> {
        if slice.len() < 6 {
            return Err(crate::EgoError::CryptoError(
                "Invalid signature format: too short".to_string(),
            ));
        }

        let alg_bytes = [slice[0], slice[1]];
        let algorithm = AlgorithmId::from_u16(u16::from_le_bytes(alg_bytes))
            .ok_or_else(|| crate::EgoError::CryptoError("Invalid algorithm ID".to_string()))?;

        let len_bytes = [slice[2], slice[3], slice[4], slice[5]];
        let len = u32::from_le_bytes(len_bytes) as usize;

        if slice.len() != 6 + len {
            return Err(crate::EgoError::CryptoError(
                "Invalid signature format: length mismatch".to_string(),
            ));
        }

        let signature_data = slice[6..].to_vec();

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

    pub fn size(&self) -> usize {
        6 + self.signature_data.len()
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({}B)", self.algorithm, self.signature_data.len())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DualSignature {
    pub ed25519_sig: Option<Signature>,
    pub dilithium_sig: Option<Signature>,
    pub protocol_version: u32,
}

impl DualSignature {
    pub fn new(ed25519_sig: Option<Signature>, dilithium_sig: Option<Signature>) -> Self {
        Self {
            ed25519_sig,
            dilithium_sig,
            protocol_version: PROTOCOL_VERSION,
        }
    }

    pub fn ed25519_only(sig: Signature) -> Self {
        Self {
            ed25519_sig: Some(sig),
            dilithium_sig: None,
            protocol_version: PROTOCOL_VERSION,
        }
    }

    pub fn dilithium_only(sig: Signature) -> Self {
        Self {
            ed25519_sig: None,
            dilithium_sig: Some(sig),
            protocol_version: PROTOCOL_VERSION,
        }
    }

    pub fn hybrid(ed25519_sig: Signature, dilithium_sig: Signature) -> Self {
        Self {
            ed25519_sig: Some(ed25519_sig),
            dilithium_sig: Some(dilithium_sig),
            protocol_version: PROTOCOL_VERSION,
        }
    }

    pub fn is_pq_only(&self) -> bool {
        self.dilithium_sig.is_some() && self.ed25519_sig.is_none()
    }

    pub fn is_hybrid(&self) -> bool {
        self.dilithium_sig.is_some() && self.ed25519_sig.is_some()
    }

    pub fn algorithms_used(&self) -> Vec<AlgorithmId> {
        let mut algs = Vec::new();
        if self.ed25519_sig.is_some() {
            algs.push(AlgorithmId::Ed25519);
        }
        if self.dilithium_sig.is_some() {
            algs.push(AlgorithmId::MlDsa2);
        }
        algs
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct SessionRecord {
    pub x25519_pubkey: Option<Vec<u8>>,
    pub kyber_ciphertext: Vec<u8>,
    pub nonce: [u8; 24],
    pub aead_tag: Vec<u8>,
    pub alg_kem_id: u16,
    pub alg_dh_legacy_id: Option<u16>,
    pub protocol_version: u32,
}

impl SessionRecord {
    pub fn new(
        x25519_pubkey: Option<Vec<u8>>,
        kyber_ciphertext: Vec<u8>,
        nonce: [u8; 24],
        aead_tag: Vec<u8>,
    ) -> Self {
        let alg_dh_legacy_id = x25519_pubkey.as_ref().map(|_| AlgorithmId::X25519.as_u16());
        Self {
            x25519_pubkey,
            kyber_ciphertext,
            nonce,
            aead_tag,
            alg_kem_id: AlgorithmId::MlKem768.as_u16(),
            alg_dh_legacy_id,
            protocol_version: PROTOCOL_VERSION,
        }
    }

    pub fn hybrid(
        x25519_pubkey: Vec<u8>,
        kyber_ciphertext: Vec<u8>,
        nonce: [u8; 24],
        aead_tag: Vec<u8>,
    ) -> Self {
        Self {
            x25519_pubkey: Some(x25519_pubkey),
            kyber_ciphertext,
            nonce,
            aead_tag,
            alg_kem_id: AlgorithmId::MlKem768.as_u16(),
            alg_dh_legacy_id: Some(AlgorithmId::X25519.as_u16()),
            protocol_version: PROTOCOL_VERSION,
        }
    }

    pub fn kyber_only(kyber_ciphertext: Vec<u8>, nonce: [u8; 24], aead_tag: Vec<u8>) -> Self {
        Self {
            x25519_pubkey: None,
            kyber_ciphertext,
            nonce,
            aead_tag,
            alg_kem_id: AlgorithmId::MlKem768.as_u16(),
            alg_dh_legacy_id: None,
            protocol_version: PROTOCOL_VERSION,
        }
    }

    pub fn is_pq_only(&self) -> bool {
        self.x25519_pubkey.is_none()
    }

    pub fn is_hybrid(&self) -> bool {
        self.x25519_pubkey.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct HandshakeInit {
    pub version: u32,
    pub alg_kem: u16,
    pub alg_dh_legacy: Option<u16>,
    pub x25519_c_pk: Option<Vec<u8>>,
    pub ct_pq_c2s: Vec<u8>,
    pub stream_kind: String,
    pub stream_nonce: [u8; 32],
    pub caps: Vec<u8>,
    pub chain_id: Vec<u8>,
}

impl HandshakeInit {
    pub fn new(
        alg_kem: u16,
        ct_pq_c2s: Vec<u8>,
        stream_kind: String,
        stream_nonce: [u8; 32],
        caps: Vec<u8>,
        chain_id: Vec<u8>,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            alg_kem,
            alg_dh_legacy: None,
            x25519_c_pk: None,
            ct_pq_c2s,
            stream_kind,
            stream_nonce,
            caps,
            chain_id,
        }
    }

    pub fn hybrid(
        alg_kem: u16,
        alg_dh_legacy: u16,
        x25519_c_pk: Vec<u8>,
        ct_pq_c2s: Vec<u8>,
        stream_kind: String,
        stream_nonce: [u8; 32],
        caps: Vec<u8>,
        chain_id: Vec<u8>,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            alg_kem,
            alg_dh_legacy: Some(alg_dh_legacy),
            x25519_c_pk: Some(x25519_c_pk),
            ct_pq_c2s,
            stream_kind,
            stream_nonce,
            caps,
            chain_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PeerCapabilities {
    pub alg_sig_supported: Vec<u16>,
    pub alg_kem_supported: Vec<u16>,
    pub pq_required: bool,
    pub mlkem_pk: Vec<u8>,
    pub x25519_pk: Option<Vec<u8>>,
    pub account_addr: Address,
    pub supported_topics: Vec<String>,
    pub max_bandwidth: u64,
    pub cellular_safe: bool,
}

impl Default for PeerCapabilities {
    fn default() -> Self {
        Self {
            alg_sig_supported: vec![AlgorithmId::MlDsa2.as_u16(), AlgorithmId::Ed25519.as_u16()],
            alg_kem_supported: vec![AlgorithmId::MlKem768.as_u16()],
            pq_required: false,
            mlkem_pk: vec![0u8; 1184],
            x25519_pk: Some(vec![0u8; 32]),
            account_addr: Address::new([0u8; 20]),
            supported_topics: Vec::new(),
            max_bandwidth: 100_000_000,
            cellular_safe: true,
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

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, crate::EgoError> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| crate::EgoError::CryptoError(format!("Invalid hex string: {}", e)))?;
        Self::from_slice(&bytes)
    }

    pub fn short_display(&self) -> String {
        let hex = self.to_hex();
        format!("ego{}...{}", &hex[..6], &hex[34..])
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ego{}", hex::encode(self.0))
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
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

    pub fn is_expired(&self, duration_millis: u64) -> bool {
        self.elapsed_millis() > duration_millis
    }

    pub fn add_millis(&self, millis: u64) -> Self {
        Self(self.0.saturating_add(millis))
    }

    pub fn add_secs(&self, secs: u64) -> Self {
        self.add_millis(secs * 1000)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let datetime = chrono::DateTime::from_timestamp_millis(self.0 as i64)
            .unwrap_or_else(|| chrono::DateTime::UNIX_EPOCH);
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
        if id >= MAX_SHARD_COUNT {
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

    pub fn next(&self) -> Result<Self, crate::EgoError> {
        Self::new(self.0 + 1)
    }

    pub fn is_valid(&self) -> bool {
        self.0 < MAX_SHARD_COUNT
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

    pub fn distance_to(&self, other: Self) -> u64 {
        if self.0 >= other.0 {
            self.0 - other.0
        } else {
            other.0 - self.0
        }
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

    pub fn is_genesis(&self) -> bool {
        self.0 == 0
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
    pub const MAX: Self = Balance(u128::MAX);

    pub fn new(amount: u128) -> Self {
        Self(amount)
    }

    pub fn from_egoc(egoc: u64) -> Self {
        Self(egoc as u128 * EGOC_BASE_UNIT)
    }

    pub fn from_uegoc(uegoc: u128) -> Self {
        Self(uegoc)
    }

    pub fn as_u128(&self) -> u128 {
        self.0
    }

    pub fn to_egoc(&self) -> f64 {
        self.0 as f64 / EGOC_BASE_UNIT as f64
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

    pub fn saturating_mul(&self, multiplier: u128) -> Balance {
        Balance(self.0.saturating_mul(multiplier))
    }

    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }

    pub fn is_positive(&self) -> bool {
        self.0 > 0
    }

    pub fn percent_of(&self, total: Balance) -> f64 {
        if total.is_zero() {
            0.0
        } else {
            (self.0 as f64 / total.0 as f64) * 100.0
        }
    }

    pub fn apply_multiplier(&self, multiplier: f64) -> Balance {
        let result = (self.0 as f64 * multiplier).round() as u128;
        Balance(result.min(u128::MAX))
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

impl std::ops::Add for Balance {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        self.saturating_add(other)
    }
}

impl std::ops::Sub for Balance {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        self.saturating_sub(other)
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

    pub fn validate(&self) -> Result<(), crate::EgoError> {
        if !self.is_valid() {
            return Err(crate::EgoError::InvalidTransaction(format!(
                "Invalid slice ID: {}",
                self.0
            )));
        }
        Ok(())
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

    pub fn into_string(self) -> String {
        self.0
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

    pub fn as_str(&self) -> &str {
        self.0.as_str()
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
    pub jitter_ms: u16,
    pub packet_loss_percent: f32,
}

impl Default for NetworkQuality {
    fn default() -> Self {
        Self {
            latency_ms: 100,
            bandwidth_mbps: 100,
            reliability_score: 80,
            cost_per_gb_usd: 0.0,
            jitter_ms: 5,
            packet_loss_percent: 0.1,
        }
    }
}

impl NetworkQuality {
    pub fn is_acceptable(&self, min_reliability: u8, max_latency_ms: u32) -> bool {
        self.reliability_score >= min_reliability && self.latency_ms <= max_latency_ms
    }

    pub fn quality_score(&self) -> f64 {
        let latency_score = (1000.0 / (self.latency_ms as f64 + 1.0)).min(100.0);
        let reliability_score = self.reliability_score as f64;
        let jitter_score = (100.0 / (self.jitter_ms as f64 + 1.0)).min(100.0);
        let loss_score = (100.0 - self.packet_loss_percent as f64 * 10.0).max(0.0);

        (latency_score * 0.3 + reliability_score * 0.4 + jitter_score * 0.15 + loss_score * 0.15)
            .min(100.0)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeoLocation {
    pub latitude: f64,
    pub longitude: f64,
    pub altitude_m: Option<f32>,
    pub h3_index: Option<String>,
    pub h3_resolution: Option<u8>,
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
}

impl GeoLocation {
    pub fn new(latitude: f64, longitude: f64) -> Self {
        Self {
            latitude,
            longitude,
            altitude_m: None,
            h3_index: None,
            h3_resolution: None,
            country_code: None,
            region: None,
            city: None,
        }
    }

    pub fn with_h3(mut self, h3_index: String, resolution: u8) -> Self {
        self.h3_index = Some(h3_index);
        self.h3_resolution = Some(resolution);
        self
    }

    pub fn with_region(mut self, country: String, region: String, city: Option<String>) -> Self {
        self.country_code = Some(country);
        self.region = Some(region);
        self.city = city;
        self
    }

    pub fn distance_to(&self, other: &GeoLocation) -> f64 {
        haversine_distance(
            (self.latitude, self.longitude),
            (other.latitude, other.longitude),
        )
    }

    pub fn is_within_radius(&self, other: &GeoLocation, radius_km: f64) -> bool {
        self.distance_to(other) <= radius_km
    }

    pub fn validate(&self) -> Result<(), crate::EgoError> {
        if self.latitude < -90.0 || self.latitude > 90.0 {
            return Err(crate::EgoError::InvalidTransaction(
                "Invalid latitude".to_string(),
            ));
        }
        if self.longitude < -180.0 || self.longitude > 180.0 {
            return Err(crate::EgoError::InvalidTransaction(
                "Invalid longitude".to_string(),
            ));
        }
        Ok(())
    }
}

fn haversine_distance(coord1: (f64, f64), coord2: (f64, f64)) -> f64 {
    let (lat1, lon1) = coord1;
    let (lat2, lon2) = coord2;

    let r = 6371.0;
    let lat1_rad = lat1.to_radians();
    let lat2_rad = lat2.to_radians();
    let delta_lat = (lat2 - lat1).to_radians();
    let delta_lon = (lon2 - lon1).to_radians();

    let a = (delta_lat / 2.0).sin().powi(2)
        + lat1_rad.cos() * lat2_rad.cos() * (delta_lon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

    r * c
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ResourceUnits(pub u64);

impl ResourceUnits {
    pub const ZERO: Self = ResourceUnits(0);

    pub fn new(units: u64) -> Self {
        Self(units)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn checked_add(&self, other: ResourceUnits) -> Option<ResourceUnits> {
        self.0.checked_add(other.0).map(ResourceUnits)
    }

    pub fn saturating_add(&self, other: ResourceUnits) -> ResourceUnits {
        ResourceUnits(self.0.saturating_add(other.0))
    }

    pub fn saturating_sub(&self, other: ResourceUnits) -> ResourceUnits {
        ResourceUnits(self.0.saturating_sub(other.0))
    }
}

impl fmt::Display for ResourceUnits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} RU", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct StorageCredits(pub u64);

impl StorageCredits {
    pub const ZERO: Self = StorageCredits(0);

    pub fn new(credits: u64) -> Self {
        Self(credits)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn for_size_duration(size_bytes: u64, duration_epochs: u64) -> Self {
        let byte_months = (size_bytes * duration_epochs) / (30 * 24 * 60 * 3);
        Self(byte_months)
    }

    pub fn checked_add(&self, other: StorageCredits) -> Option<StorageCredits> {
        self.0.checked_add(other.0).map(StorageCredits)
    }

    pub fn saturating_sub(&self, other: StorageCredits) -> StorageCredits {
        StorageCredits(self.0.saturating_sub(other.0))
    }
}

impl fmt::Display for StorageCredits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} credits", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeployCredits(pub u64);

impl DeployCredits {
    pub const ZERO: Self = DeployCredits(0);

    pub fn new(credits: u64) -> Self {
        Self(credits)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn for_code_size(size_kb: u32, ru_estimate: u64) -> Self {
        let size_credits = size_kb as u64 * 100;
        let ru_credits = ru_estimate / 100;
        Self(size_credits + ru_credits)
    }

    pub fn saturating_sub(&self, other: DeployCredits) -> DeployCredits {
        DeployCredits(self.0.saturating_sub(other.0))
    }
}

impl fmt::Display for DeployCredits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} deploy credits", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl ProtocolVersion {
    pub fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub fn current() -> Self {
        Self::from_u32(PROTOCOL_VERSION)
    }

    pub fn from_u32(version: u32) -> Self {
        let major = ((version >> 16) & 0xFFFF) as u16;
        let minor = ((version >> 8) & 0xFF) as u16;
        let patch = (version & 0xFF) as u16;
        Self {
            major,
            minor,
            patch,
        }
    }

    pub fn as_u32(&self) -> u32 {
        ((self.major as u32) << 16) | ((self.minor as u32) << 8) | (self.patch as u32)
    }

    pub fn is_compatible_with(&self, other: &ProtocolVersion) -> bool {
        self.major == other.major && self.minor >= other.minor
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChainId(pub u32);

impl ChainId {
    pub const MAINNET: Self = ChainId(1);
    pub const TESTNET: Self = ChainId(2);
    pub const DEVNET: Self = ChainId(3);

    pub fn new(id: u32) -> Self {
        Self(id)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }

    pub fn is_mainnet(&self) -> bool {
        self.0 == Self::MAINNET.0
    }

    pub fn is_testnet(&self) -> bool {
        self.0 == Self::TESTNET.0
    }

    pub fn network_name(&self) -> &'static str {
        match self.0 {
            1 => "mainnet",
            2 => "testnet",
            3 => "devnet",
            _ => "custom",
        }
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "chain-{} ({})", self.0, self.network_name())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkId(pub u32);

impl NetworkId {
    pub const MAINNET: Self = NetworkId(1);
    pub const TESTNET: Self = NetworkId(2);
    pub const DEVNET: Self = NetworkId(3);

    pub fn new(id: u32) -> Self {
        Self(id)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "network-{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_id_conversion() {
        assert_eq!(AlgorithmId::from_u16(0xED01), Some(AlgorithmId::Ed25519));
        assert_eq!(AlgorithmId::from_u16(0x0202), Some(AlgorithmId::MlDsa2));
        assert_eq!(AlgorithmId::from_u16(0x9999), None);

        assert_eq!(AlgorithmId::Ed25519.as_u16(), 0xED01);
        assert_eq!(AlgorithmId::MlDsa2.as_u16(), 0x0202);
    }

    #[test]
    fn test_hash_operations() {
        let hash1 = Hash::new([1u8; 32]);
        let hash2 = Hash::new([2u8; 32]);

        assert_eq!(hash1, hash1);
        assert_ne!(hash1, hash2);
        assert_eq!(hash1.as_bytes(), &[1u8; 32]);

        let hex = hash1.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(Hash::from_hex(&hex).unwrap(), hash1);
    }

    #[test]
    fn test_balance_operations() {
        let balance1 = Balance::from_egoc(10);
        let balance2 = Balance::from_egoc(5);

        assert_eq!(balance1.to_egoc(), 10.0);
        assert_eq!(balance1.checked_add(balance2), Some(Balance::from_egoc(15)));
        assert_eq!(balance1.checked_sub(balance2), Some(Balance::from_egoc(5)));
        assert!(balance2.checked_sub(balance1).is_none());

        let multiplied = balance1.apply_multiplier(1.3);
        assert!(multiplied > balance1);
    }

    #[test]
    fn test_timestamp() {
        let ts1 = Timestamp::now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let ts2 = Timestamp::now();

        assert!(ts2 > ts1);
        assert!(ts1.elapsed_millis() >= 10);

        let future = ts1.add_secs(3600);
        assert_eq!(future.as_secs(), ts1.as_secs() + 3600);
    }

    #[test]
    fn test_shard_id() {
        let shard = ShardId::new(0).unwrap();
        assert_eq!(shard.as_u32(), 0);
        assert!(shard.is_valid());

        assert!(ShardId::new(MAX_SHARD_COUNT).is_err());

        let next = shard.next().unwrap();
        assert_eq!(next.as_u32(), 1);
    }

    #[test]
    fn test_block_height() {
        let genesis = BlockHeight::GENESIS;
        assert!(genesis.is_genesis());
        assert_eq!(genesis.as_u64(), 0);

        let next = genesis.next();
        assert_eq!(next.as_u64(), 1);
        assert!(!next.is_genesis());

        assert_eq!(next.prev(), genesis);
    }

    #[test]
    fn test_address_from_public_key() {
        let pubkey = PublicKey::new(AlgorithmId::Ed25519, vec![1u8; 32]);
        let addr1 = Address::from_public_key(&pubkey);
        let addr2 = Address::from_public_key(&pubkey);

        assert_eq!(addr1, addr2);
        assert_eq!(addr1.as_bytes().len(), 20);
    }

    #[test]
    fn test_geo_location_distance() {
        let london = GeoLocation::new(51.5074, -0.1278);
        let paris = GeoLocation::new(48.8566, 2.3522);

        let distance = london.distance_to(&paris);
        assert!(distance > 300.0 && distance < 400.0);

        assert!(!london.is_within_radius(&paris, 100.0));
        assert!(london.is_within_radius(&paris, 500.0));
    }

    #[test]
    fn test_slice_id_validation() {
        let valid = SliceId::new("my-slice_123".to_string());
        assert!(valid.is_valid());

        let invalid1 = SliceId::new("my slice".to_string());
        assert!(!invalid1.is_valid());

        let invalid2 = SliceId::new("a".repeat(65));
        assert!(!invalid2.is_valid());
    }

    #[test]
    fn test_protocol_version() {
        let v1 = ProtocolVersion::new(1, 0, 0);
        let v1_1 = ProtocolVersion::new(1, 1, 0);
        let v2 = ProtocolVersion::new(2, 0, 0);

        assert!(v1.is_compatible_with(&v1));
        assert!(v1_1.is_compatible_with(&v1));
        assert!(!v1.is_compatible_with(&v2));

        let as_u32 = v1.as_u32();
        let from_u32 = ProtocolVersion::from_u32(as_u32);
        assert_eq!(v1, from_u32);
    }

    #[test]
    fn test_storage_credits_calculation() {
        let credits = StorageCredits::for_size_duration(1_000_000_000, 100);
        assert!(credits.as_u64() > 0);

        let remaining = credits.saturating_sub(StorageCredits::new(100));
        assert_eq!(remaining.as_u64(), credits.as_u64() - 100);
    }

    #[test]
    fn test_deploy_credits_calculation() {
        let credits = DeployCredits::for_code_size(100, 10000);
        assert!(credits.as_u64() > 0);
        assert_eq!(credits.as_u64(), 100 * 100 + 10000 / 100);
    }
}
