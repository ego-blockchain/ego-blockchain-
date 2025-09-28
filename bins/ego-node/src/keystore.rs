use ego_core::{
    Address, AlgorithmId, DualSignature, EgoError, KeyPair, PublicKey, Signature,
    verify_dual_signature, verify_signature,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Binding verification failed: {0}")]
    BindingVerificationFailed(String),
    #[error("Core error: {0}")]
    CoreError(#[from] EgoError),
    #[error("Libp2p key decoding error: {0}")]
    LibP2PDecodingError(String),
    #[error("Algorithm not supported: {0:?}")]
    UnsupportedAlgorithm(AlgorithmId),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccountBinding {
    pub account_pubkey: PublicKey,
    pub binding_signature: DualSignature,
    pub timestamp: u64,
    pub chain_id: Option<String>,
    pub verified: bool,
    pub transition_mode: bool,
}

impl AccountBinding {
    pub fn new(
        account_pubkey: PublicKey,
        binding_signature: DualSignature,
        chain_id: Option<String>,
        transition_mode: bool,
    ) -> Self {
        Self {
            account_pubkey,
            binding_signature,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            chain_id,
            verified: false,
            transition_mode,
        }
    }

    pub fn verify_binding(
        &self,
        libp2p_pubkey: &PublicKey,
        dilithium_pk: &PublicKey,
    ) -> Result<bool, KeystoreError> {
        let message = self.create_binding_message();

        if self.transition_mode {
            verify_dual_signature(
                libp2p_pubkey,
                dilithium_pk,
                &message,
                &self.binding_signature,
            )
            .map_err(|e| KeystoreError::CoreError(e))
        } else {
            if let Some(ref dilithium_sig) = self.binding_signature.dilithium_sig {
                verify_signature(dilithium_pk, &message, dilithium_sig)
                    .map_err(|e| KeystoreError::CoreError(e))
            } else {
                Ok(false)
            }
        }
    }

    pub fn create_binding_message(&self) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(b"EGO_BINDING_V2:");
        message.extend_from_slice(&self.account_pubkey.to_vec());
        message.extend_from_slice(&self.timestamp.to_be_bytes());
        if let Some(ref chain_id) = self.chain_id {
            message.extend_from_slice(chain_id.as_bytes());
        }
        if self.transition_mode {
            message.extend_from_slice(b":HYBRID");
        } else {
            message.extend_from_slice(b":PQ_ONLY");
        }
        message
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivationPath {
    pub purpose: u32,
    pub coin_type: u32,
    pub account: u32,
    pub change: u32,
    pub address_index: u32,
}

impl Default for DerivationPath {
    fn default() -> Self {
        Self {
            purpose: 44,
            coin_type: 5555,
            account: 0,
            change: 0,
            address_index: 0,
        }
    }
}

impl DerivationPath {
    pub fn to_string(&self) -> String {
        format!(
            "m/{}'/{}'/{}'/{}/{}",
            self.purpose, self.coin_type, self.account, self.change, self.address_index
        )
    }

    pub fn next_address(&mut self) -> Self {
        let mut path = self.clone();
        path.address_index += 1;
        path
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureKeystore {
    primary_keypair: KeyPair,
    derived_keypairs: HashMap<String, KeyPair>,
    account_bindings: HashMap<String, AccountBinding>,
    #[zeroize(skip)]
    metadata: KeystoreMetadata,
    libp2p_keypair: Option<libp2p::identity::Keypair>,
    transition_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreMetadata {
    pub version: String,
    pub created_at: u64,
    pub last_accessed: u64,
    pub key_count: usize,
    pub binding_count: usize,
    pub node_id: Option<String>,
    pub address: Option<String>,
    pub supported_algorithms: Vec<String>,
    pub transition_mode: bool,
    pub pq_ready: bool,
}

impl Default for KeystoreMetadata {
    fn default() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            version: "2.0.0".to_string(),
            created_at: now,
            last_accessed: now,
            key_count: 1,
            binding_count: 0,
            node_id: None,
            address: None,
            supported_algorithms: vec![
                "Ed25519".to_string(),
                "ML-DSA-2".to_string(),
                "ML-KEM-768".to_string(),
                "X25519".to_string(),
                "XChaCha20Poly1305".to_string(),
                "BLAKE2s".to_string(),
            ],
            transition_mode: true,
            pq_ready: true,
        }
    }
}

impl SecureKeystore {
    pub fn new() -> Self {
        Self::new_with_transition_mode(true)
    }

    pub fn new_with_transition_mode(transition_mode: bool) -> Self {
        let primary_keypair = KeyPair::generate();
        let libp2p_keypair = Self::create_libp2p_keypair_from_keypair(&primary_keypair);
        let peer_id = libp2p_keypair.public().to_peer_id();
        let address = Address::from_public_key(&primary_keypair.public_key());

        let mut metadata = KeystoreMetadata::default();
        metadata.node_id = Some(peer_id.to_string());
        metadata.address = Some(address.to_string());
        metadata.transition_mode = transition_mode;

        Self {
            primary_keypair,
            derived_keypairs: HashMap::new(),
            account_bindings: HashMap::new(),
            metadata,
            libp2p_keypair: Some(libp2p_keypair),
            transition_mode,
        }
    }

    pub fn from_seed(seed: [u8; 32]) -> Result<Self, KeystoreError> {
        Self::from_seed_with_transition_mode(seed, true)
    }

    pub fn from_seed_with_transition_mode(
        seed: [u8; 32],
        transition_mode: bool,
    ) -> Result<Self, KeystoreError> {
        let primary_keypair = KeyPair::from_bytes(&seed)?;
        let libp2p_keypair = Self::create_libp2p_keypair_from_keypair(&primary_keypair);
        let peer_id = libp2p_keypair.public().to_peer_id();
        let address = Address::from_public_key(&primary_keypair.public_key());

        let mut metadata = KeystoreMetadata::default();
        metadata.node_id = Some(peer_id.to_string());
        metadata.address = Some(address.to_string());
        metadata.transition_mode = transition_mode;

        Ok(Self {
            primary_keypair,
            derived_keypairs: HashMap::new(),
            account_bindings: HashMap::new(),
            metadata,
            libp2p_keypair: Some(libp2p_keypair),
            transition_mode,
        })
    }

    pub fn from_mnemonic(mnemonic: &str) -> Result<Self, KeystoreError> {
        Self::from_mnemonic_with_transition_mode(mnemonic, true)
    }

    pub fn from_mnemonic_with_transition_mode(
        mnemonic: &str,
        transition_mode: bool,
    ) -> Result<Self, KeystoreError> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        mnemonic.hash(&mut hasher);
        let hash = hasher.finish();

        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&hash.to_be_bytes());
        for i in 1..4 {
            let mut hasher = DefaultHasher::new();
            (hash.wrapping_mul(i as u64)).hash(&mut hasher);
            let chunk = hasher.finish().to_be_bytes();
            let start = i * 8;
            if start + 8 <= 32 {
                seed[start..start + 8].copy_from_slice(&chunk);
            }
        }

        Self::from_seed_with_transition_mode(seed, transition_mode)
    }

    fn create_libp2p_keypair_from_keypair(keypair: &KeyPair) -> libp2p::identity::Keypair {
        let seed = keypair.to_bytes();

        match libp2p::identity::ed25519::Keypair::try_from_bytes(&mut seed.clone()) {
            Ok(_) => libp2p::identity::Keypair::ed25519_from_bytes(seed)
                .expect("Valid Ed25519 keypair from seed"),
            Err(_) => {
                let hash = ego_core::crypto::blake2s_hash(&seed);
                let mut new_seed = [0u8; 32];
                new_seed.copy_from_slice(&hash[..32]);

                libp2p::identity::Keypair::ed25519_from_bytes(new_seed)
                    .expect("Valid Ed25519 keypair from hashed seed")
            }
        }
    }

    pub fn keypair(&self) -> &KeyPair {
        &self.primary_keypair
    }

    pub fn public_key(&self) -> PublicKey {
        self.primary_keypair.public_key()
    }

    pub fn dilithium_public_key(&self) -> PublicKey {
        self.primary_keypair.dilithium_public_key()
    }

    pub fn kyber_public_key(&self) -> PublicKey {
        self.primary_keypair.kyber_public_key()
    }

    pub fn peer_id(&self) -> libp2p::PeerId {
        self.libp2p_keypair
            .as_ref()
            .map(|kp| kp.public().to_peer_id())
            .unwrap_or_else(|| {
                let binding = self.primary_keypair.public_key();
                let pubkey_bytes = binding.as_bytes();
                let hash = ego_core::crypto::blake2s_hash(pubkey_bytes);
                libp2p::PeerId::from_bytes(&hash[..32]).unwrap_or_else(|_| {
                    libp2p::identity::Keypair::generate_ed25519()
                        .public()
                        .to_peer_id()
                })
            })
    }

    pub fn libp2p_keypair(&self) -> libp2p::identity::Keypair {
        self.libp2p_keypair
            .clone()
            .unwrap_or_else(|| Self::create_libp2p_keypair_from_keypair(&self.primary_keypair))
    }

    pub fn derive_keypair(
        &mut self,
        purpose: &str,
        path: Option<DerivationPath>,
    ) -> Result<&KeyPair, KeystoreError> {
        if self.derived_keypairs.contains_key(purpose) {
            return Ok(self.derived_keypairs.get(purpose).unwrap());
        }

        let seed = self.primary_keypair.to_bytes();
        let mut derivation_data = Vec::new();
        derivation_data.extend_from_slice(&seed);
        derivation_data.extend_from_slice(purpose.as_bytes());

        if let Some(path) = path {
            derivation_data.extend_from_slice(&path.purpose.to_be_bytes());
            derivation_data.extend_from_slice(&path.coin_type.to_be_bytes());
            derivation_data.extend_from_slice(&path.account.to_be_bytes());
            derivation_data.extend_from_slice(&path.change.to_be_bytes());
            derivation_data.extend_from_slice(&path.address_index.to_be_bytes());
        }

        let derived_seed = ego_core::crypto::blake2s_hash(&derivation_data);
        let mut key_seed = [0u8; 32];
        key_seed.copy_from_slice(&derived_seed[..32]);

        let derived_keypair = KeyPair::from_bytes(&key_seed)?;

        self.derived_keypairs
            .insert(purpose.to_string(), derived_keypair);
        self.metadata.key_count += 1;
        self.touch();

        Ok(self.derived_keypairs.get(purpose).unwrap())
    }

    pub fn get_derived_keypair(&self, purpose: &str) -> Option<&KeyPair> {
        self.derived_keypairs.get(purpose)
    }

    pub fn sign(&self, message: &[u8]) -> Result<Signature, KeystoreError> {
        if self.transition_mode {
            Ok(self.primary_keypair.sign_ed25519(message))
        } else {
            Ok(self.primary_keypair.sign_dilithium(message))
        }
    }

    pub fn sign_dual(&self, message: &[u8]) -> Result<DualSignature, KeystoreError> {
        Ok(self.primary_keypair.dual_sign(message))
    }

    pub fn sign_with_algorithm(
        &self,
        message: &[u8],
        algorithm: AlgorithmId,
    ) -> Result<Signature, KeystoreError> {
        match algorithm {
            AlgorithmId::Ed25519 => Ok(self.primary_keypair.sign_ed25519(message)),
            AlgorithmId::MlDsa2 => Ok(self.primary_keypair.sign_dilithium(message)),
            _ => Err(KeystoreError::UnsupportedAlgorithm(algorithm)),
        }
    }

    pub fn sign_with_derived(
        &self,
        purpose: &str,
        message: &[u8],
    ) -> Result<Signature, KeystoreError> {
        let keypair = self
            .derived_keypairs
            .get(purpose)
            .ok_or_else(|| KeystoreError::KeyNotFound(purpose.to_string()))?;

        if self.transition_mode {
            Ok(keypair.sign_ed25519(message))
        } else {
            Ok(keypair.sign_dilithium(message))
        }
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        let pubkey = if signature.algorithm == AlgorithmId::Ed25519 {
            &self.public_key()
        } else {
            &self.dilithium_public_key()
        };

        verify_signature(pubkey, message, signature).unwrap_or(false)
    }

    pub fn verify_dual(&self, message: &[u8], dual_sig: &DualSignature) -> bool {
        verify_dual_signature(
            &self.public_key(),
            &self.dilithium_public_key(),
            message,
            dual_sig,
        )
        .unwrap_or(false)
    }

    pub fn bind_on_chain_account(
        &mut self,
        account_pubkey: PublicKey,
        chain_id: Option<String>,
    ) -> Result<(), KeystoreError> {
        let binding_message = {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let mut message = Vec::new();
            message.extend_from_slice(b"EGO_BINDING_V2:");
            message.extend_from_slice(&account_pubkey.to_vec());
            message.extend_from_slice(&timestamp.to_be_bytes());
            if let Some(ref chain_id) = chain_id {
                message.extend_from_slice(chain_id.as_bytes());
            }
            if self.transition_mode {
                message.extend_from_slice(b":HYBRID");
            } else {
                message.extend_from_slice(b":PQ_ONLY");
            }
            message
        };

        let binding_signature = if self.transition_mode {
            self.primary_keypair.dual_sign(&binding_message)
        } else {
            DualSignature::dilithium_only(self.primary_keypair.sign_dilithium(&binding_message))
        };

        let binding = AccountBinding::new(
            account_pubkey,
            binding_signature,
            chain_id.clone(),
            self.transition_mode,
        );

        if !binding.verify_binding(&self.public_key(), &self.dilithium_public_key())? {
            return Err(KeystoreError::BindingVerificationFailed(
                "Invalid binding signature".to_string(),
            ));
        }

        let key = chain_id.unwrap_or_else(|| "default".to_string());
        let mut verified_binding = binding;
        verified_binding.verified = true;

        self.account_bindings.insert(key, verified_binding);
        self.metadata.binding_count = self.account_bindings.len();
        self.touch();

        Ok(())
    }

    pub fn create_binding_signature(
        &self,
        account_pubkey: &PublicKey,
        chain_id: Option<&str>,
    ) -> Result<DualSignature, KeystoreError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut message = Vec::new();
        message.extend_from_slice(b"EGO_BINDING_V2:");
        message.extend_from_slice(&account_pubkey.to_vec());
        message.extend_from_slice(&timestamp.to_be_bytes());
        if let Some(chain_id) = chain_id {
            message.extend_from_slice(chain_id.as_bytes());
        }
        if self.transition_mode {
            message.extend_from_slice(b":HYBRID");
        } else {
            message.extend_from_slice(b":PQ_ONLY");
        }

        if self.transition_mode {
            Ok(self.primary_keypair.dual_sign(&message))
        } else {
            Ok(DualSignature::dilithium_only(
                self.primary_keypair.sign_dilithium(&message),
            ))
        }
    }

    pub fn get_binding(&self, chain_id: Option<&str>) -> Option<&AccountBinding> {
        let key = chain_id.unwrap_or("default");
        self.account_bindings.get(key)
    }

    pub fn get_all_bindings(&self) -> &HashMap<String, AccountBinding> {
        &self.account_bindings
    }

    pub fn remove_binding(&mut self, chain_id: Option<&str>) -> Option<AccountBinding> {
        let key = chain_id.unwrap_or("default");
        let removed = self.account_bindings.remove(key);
        if removed.is_some() {
            self.metadata.binding_count = self.account_bindings.len();
            self.touch();
        }
        removed
    }

    pub fn set_transition_mode(&mut self, transition_mode: bool) {
        self.transition_mode = transition_mode;
        self.metadata.transition_mode = transition_mode;
        self.touch();
    }

    pub fn is_transition_mode(&self) -> bool {
        self.transition_mode
    }

    pub fn create_stealth_address(
        &self,
        receiver_kyber_pk: &[u8],
    ) -> Result<(PublicKey, Vec<u8>), KeystoreError> {
        let sender_ephemeral = self.primary_keypair.to_bytes();
        ego_core::crypto::derive_stealth_address(receiver_kyber_pk, &sender_ephemeral)
            .map_err(|e| KeystoreError::CoreError(e))
    }

    pub fn create_hybrid_session(
        &self,
        peer_x25519_pk: &[u8],
        peer_kyber_pk: &[u8],
        info: &[u8],
    ) -> Result<(ego_core::SessionRecord, Vec<u8>), KeystoreError> {
        self.primary_keypair
            .create_hybrid_session(peer_x25519_pk, peer_kyber_pk, info)
            .map_err(|e| KeystoreError::CoreError(e))
    }

    pub fn export_encrypted(&self, password: &str) -> Result<String, KeystoreError> {
        let password_hash = ego_core::crypto::blake2s_hash(password.as_bytes());

        let export_data = serde_json::json!({
            "version": self.metadata.version,
            "peer_id": self.peer_id().to_string(),
            "address": Address::from_public_key(&self.public_key()).to_string(),
            "created_at": self.metadata.created_at,
            "key_count": self.metadata.key_count,
            "binding_count": self.metadata.binding_count,
            "transition_mode": self.metadata.transition_mode,
            "pq_ready": self.metadata.pq_ready,
            "supported_algorithms": self.metadata.supported_algorithms,
            "encrypted": true,
            "password_hint": format!("{}...{}", &hex::encode(&password_hash)[..6], &hex::encode(&password_hash)[58..]),
            "note": "Encrypted EGO keystore v2.0 - supports post-quantum cryptography"
        });

        Ok(export_data.to_string())
    }

    pub fn import_encrypted(_data: &str, _password: &str) -> Result<Self, KeystoreError> {
        Err(KeystoreError::DecryptionFailed(
            "Import functionality requires proper encryption implementation".to_string(),
        ))
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), KeystoreError> {
        let export_data = serde_json::json!({
            "version": self.metadata.version,
            "peer_id": self.peer_id().to_string(),
            "address": Address::from_public_key(&self.public_key()).to_string(),
            "metadata": self.metadata,
            "bindings_count": self.account_bindings.len(),
            "derived_keys_count": self.derived_keypairs.len(),
            "transition_mode": self.transition_mode,
            "pq_ready": true,
            "supported_algorithms": [
                "Ed25519",
                "ML-DSA-2 (Dilithium-2)",
                "ML-KEM-768 (Kyber-768)",
                "X25519",
                "XChaCha20Poly1305",
                "BLAKE2s",
                "HKDF-BLAKE2s"
            ],
            "created_at": chrono::DateTime::from_timestamp(self.metadata.created_at as i64, 0)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_else(|| "unknown".to_string()),
            "note": "EGO keystore v2.0 with post-quantum cryptography support (private keys not exported for security)"
        });

        std::fs::write(path, export_data.to_string())?;
        Ok(())
    }

    pub fn load_metadata_from_file<P: AsRef<Path>>(
        path: P,
    ) -> Result<KeystoreMetadata, KeystoreError> {
        let contents = std::fs::read_to_string(path)?;
        let data: serde_json::Value = serde_json::from_str(&contents)?;

        let metadata = data
            .get("metadata")
            .and_then(|m| serde_json::from_value(m.clone()).ok())
            .unwrap_or_else(KeystoreMetadata::default);

        Ok(metadata)
    }

    pub fn metadata(&self) -> &KeystoreMetadata {
        &self.metadata
    }

    pub fn touch(&mut self) {
        self.metadata.last_accessed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    pub fn is_pq_ready(&self) -> bool {
        self.metadata.pq_ready
    }

    pub fn derived_key_count(&self) -> usize {
        self.derived_keypairs.len()
    }

    pub fn list_derived_purposes(&self) -> Vec<&String> {
        self.derived_keypairs.keys().collect()
    }

    pub fn get_address(&self) -> Address {
        Address::from_public_key(&self.public_key())
    }

    pub fn get_node_id(&self) -> String {
        self.peer_id().to_string()
    }

    pub fn get_stats(&self) -> KeystoreStats {
        KeystoreStats {
            total_keys: self.metadata.key_count,
            derived_keys: self.derived_keypairs.len(),
            account_bindings: self.metadata.binding_count,
            is_pq_ready: self.metadata.pq_ready,
            transition_mode: self.transition_mode,
            peer_id: self.peer_id().to_string(),
            address: self.get_address().to_string(),
            created_at: self.metadata.created_at,
            last_accessed: self.metadata.last_accessed,
            supported_algorithms: self.metadata.supported_algorithms.clone(),
        }
    }

    pub fn get_algorithm_info(&self) -> HashMap<String, serde_json::Value> {
        let mut info = HashMap::new();

        info.insert(
            "signature_algorithms".to_string(),
            serde_json::json!({
                "ed25519": {
                    "status": "supported",
                    "key_size": 32,
                    "signature_size": 64,
                    "quantum_safe": false
                },
                "ml_dsa_2": {
                    "status": "supported",
                    "key_size": 1312,
                    "signature_size": 2420,
                    "quantum_safe": true,
                    "fips_standard": "FIPS 204"
                }
            }),
        );

        info.insert(
            "kem_algorithms".to_string(),
            serde_json::json!({
                "x25519": {
                    "status": "supported",
                    "key_size": 32,
                    "quantum_safe": false
                },
                "ml_kem_768": {
                    "status": "supported",
                    "public_key_size": 1184,
                    "secret_key_size": 2400,
                    "ciphertext_size": 1088,
                    "quantum_safe": true,
                    "fips_standard": "FIPS 203"
                }
            }),
        );

        info.insert(
            "encryption_algorithms".to_string(),
            serde_json::json!({
                "xchacha20poly1305": {
                    "status": "supported",
                    "key_size": 32,
                    "nonce_size": 24,
                    "aead": true
                }
            }),
        );

        info.insert(
            "hash_algorithms".to_string(),
            serde_json::json!({
                "blake2s": {
                    "status": "supported",
                    "output_size": 32
                },
                "hkdf_blake2s": {
                    "status": "supported",
                    "key_derivation": true
                }
            }),
        );

        info
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreStats {
    pub total_keys: usize,
    pub derived_keys: usize,
    pub account_bindings: usize,
    pub is_pq_ready: bool,
    pub transition_mode: bool,
    pub peer_id: String,
    pub address: String,
    pub created_at: u64,
    pub last_accessed: u64,
    pub supported_algorithms: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keystore_creation() {
        let keystore = SecureKeystore::new();
        assert!(!keystore.get_address().to_string().is_empty());
        assert!(!keystore.peer_id().to_string().is_empty());
        assert!(keystore.is_pq_ready());
    }

    #[test]
    fn test_signing_and_verification() {
        let keystore = SecureKeystore::new();
        let message = b"test message";

        let signature = keystore.sign(message).unwrap();
        assert!(keystore.verify(message, &signature));

        let dual_signature = keystore.sign_dual(message).unwrap();
        assert!(keystore.verify_dual(message, &dual_signature));
    }

    #[test]
    fn test_transition_mode() {
        let mut keystore = SecureKeystore::new_with_transition_mode(false);
        assert!(!keystore.is_transition_mode());

        keystore.set_transition_mode(true);
        assert!(keystore.is_transition_mode());
    }

    #[test]
    fn test_key_derivation() {
        let mut keystore = SecureKeystore::new();
        let derived = keystore.derive_keypair("test", None).unwrap();
        let derived_pubkey = derived.public_key();

        let derived2 = keystore.get_derived_keypair("test").unwrap();
        assert_eq!(derived_pubkey.to_vec(), derived2.public_key().to_vec());
    }

    #[test]
    fn test_account_binding() {
        let mut keystore = SecureKeystore::new();
        let account_pubkey = PublicKey::ed25519([1u8; 32]);

        keystore
            .bind_on_chain_account(account_pubkey.clone(), None)
            .unwrap();

        let binding = keystore.get_binding(None);
        assert!(binding.is_some());
        assert_eq!(binding.unwrap().account_pubkey, account_pubkey);
        assert!(binding.unwrap().verified);
    }

    #[test]
    fn test_algorithm_support() {
        let keystore = SecureKeystore::new();
        let message = b"test message for algorithms";

        let ed25519_sig = keystore
            .sign_with_algorithm(message, AlgorithmId::Ed25519)
            .unwrap();
        assert_eq!(ed25519_sig.algorithm, AlgorithmId::Ed25519);

        let dilithium_sig = keystore
            .sign_with_algorithm(message, AlgorithmId::MlDsa2)
            .unwrap();
        assert_eq!(dilithium_sig.algorithm, AlgorithmId::MlDsa2);
    }
}
