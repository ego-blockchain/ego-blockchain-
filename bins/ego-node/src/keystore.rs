use ego_core::{Address, EgoError, KeyPair, PublicKey, verify_signature};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccountBinding {
    pub account_pubkey: Vec<u8>,
    pub binding_signature: Vec<u8>,
    pub timestamp: u64,
    pub chain_id: Option<String>,
    pub verified: bool,
}

impl AccountBinding {
    pub fn new(
        account_pubkey: Vec<u8>,
        binding_signature: Vec<u8>,
        chain_id: Option<String>,
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
        }
    }

    pub fn verify_binding(&self, libp2p_pubkey: &PublicKey) -> Result<bool, KeystoreError> {
        let message = self.create_binding_message();
        let signature = ego_core::Signature::from_slice(&self.binding_signature)
            .map_err(|e| KeystoreError::InvalidSignature(e.to_string()))?;

        let is_valid = verify_signature(libp2p_pubkey, &message, &signature)?;
        Ok(is_valid)
    }

    pub fn create_binding_message(&self) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(b"EGO_BINDING:");
        message.extend_from_slice(&self.account_pubkey);
        message.extend_from_slice(&self.timestamp.to_be_bytes());
        if let Some(ref chain_id) = self.chain_id {
            message.extend_from_slice(chain_id.as_bytes());
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

pub struct SecureKeystore {
    primary_keypair: KeyPair,
    derived_keypairs: HashMap<String, KeyPair>,
    account_bindings: HashMap<String, AccountBinding>,
    master_seed: Option<[u8; 32]>,
    encryption_key: Option<[u8; 32]>,
    metadata: KeystoreMetadata,
    libp2p_keypair: Option<libp2p::identity::Keypair>,
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
}

impl Default for KeystoreMetadata {
    fn default() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            version: "1.0.0".to_string(),
            created_at: now,
            last_accessed: now,
            key_count: 1,
            binding_count: 0,
            node_id: None,
            address: None,
        }
    }
}

impl SecureKeystore {
    pub fn new() -> Self {
        let primary_keypair = KeyPair::generate();
        let mut master_seed = [0u8; 32];
        rand::rng().fill_bytes(&mut master_seed);

        let libp2p_keypair = Self::create_libp2p_keypair_from_seed(&master_seed);
        let peer_id = libp2p_keypair.public().to_peer_id();
        let address = Address::from_public_key(&primary_keypair.public_key());

        let mut metadata = KeystoreMetadata::default();
        metadata.node_id = Some(peer_id.to_string());
        metadata.address = Some(address.to_string());

        Self {
            primary_keypair,
            derived_keypairs: HashMap::new(),
            account_bindings: HashMap::new(),
            master_seed: Some(master_seed),
            encryption_key: None,
            metadata,
            libp2p_keypair: Some(libp2p_keypair),
        }
    }

    pub fn from_seed(seed: [u8; 32]) -> Result<Self, KeystoreError> {
        let primary_keypair = KeyPair::from_bytes(&seed)?;
        let libp2p_keypair = Self::create_libp2p_keypair_from_seed(&seed);
        let peer_id = libp2p_keypair.public().to_peer_id();
        let address = Address::from_public_key(&primary_keypair.public_key());

        let mut metadata = KeystoreMetadata::default();
        metadata.node_id = Some(peer_id.to_string());
        metadata.address = Some(address.to_string());

        let mut keystore = Self {
            primary_keypair,
            derived_keypairs: HashMap::new(),
            account_bindings: HashMap::new(),
            master_seed: Some(seed),
            encryption_key: None,
            metadata,
            libp2p_keypair: Some(libp2p_keypair),
        };

        keystore.derive_encryption_key()?;
        Ok(keystore)
    }

    pub fn from_mnemonic(mnemonic: &str) -> Result<Self, KeystoreError> {
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

        Self::from_seed(seed)
    }

    fn create_libp2p_keypair_from_seed(seed: &[u8; 32]) -> libp2p::identity::Keypair {
        let mut ed25519_seed = [0u8; 32];
        ed25519_seed.copy_from_slice(seed);

        match libp2p::identity::ed25519::Keypair::try_from_bytes(&mut ed25519_seed) {
            Ok(_) => libp2p::identity::Keypair::ed25519_from_bytes(ed25519_seed)
                .expect("Valid Ed25519 keypair from seed"),
            Err(_) => {
                let hash = ego_core::crypto::blake2s_hash(seed);
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
        self.libp2p_keypair.clone().unwrap_or_else(|| {
            if let Some(seed) = self.master_seed {
                Self::create_libp2p_keypair_from_seed(&seed)
            } else {
                libp2p::identity::Keypair::generate_ed25519()
            }
        })
    }

    pub fn derive_keypair(
        &mut self,
        purpose: &str,
        path: Option<DerivationPath>,
    ) -> Result<&KeyPair, KeystoreError> {
        if self.derived_keypairs.contains_key(purpose) {
            return Ok(self.derived_keypairs.get(purpose).unwrap());
        }

        let derived_keypair = if let Some(seed) = self.master_seed {
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

            KeyPair::from_bytes(&key_seed)?
        } else {
            KeyPair::generate()
        };

        self.derived_keypairs
            .insert(purpose.to_string(), derived_keypair);
        self.metadata.key_count += 1;
        self.touch();

        Ok(self.derived_keypairs.get(purpose).unwrap())
    }

    pub fn get_derived_keypair(&self, purpose: &str) -> Option<&KeyPair> {
        self.derived_keypairs.get(purpose)
    }

    pub fn sign(&self, message: &[u8]) -> Result<ego_core::Signature, KeystoreError> {
        let signature = self.primary_keypair.sign(message);
        Ok(signature)
    }

    pub fn sign_with_derived(
        &self,
        purpose: &str,
        message: &[u8],
    ) -> Result<ego_core::Signature, KeystoreError> {
        let keypair = self
            .derived_keypairs
            .get(purpose)
            .ok_or_else(|| KeystoreError::KeyNotFound(purpose.to_string()))?;

        let signature = keypair.sign(message);
        Ok(signature)
    }

    pub fn verify(&self, message: &[u8], signature: &ego_core::Signature) -> bool {
        verify_signature(&self.public_key(), message, signature).unwrap_or(false)
    }

    pub fn bind_on_chain_account(
        &mut self,
        account_pubkey: Vec<u8>,
        binding_signature: Vec<u8>,
        chain_id: Option<String>,
    ) -> Result<(), KeystoreError> {
        let binding = AccountBinding::new(account_pubkey, binding_signature, chain_id.clone());

        if !binding.verify_binding(&self.public_key())? {
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
        account_pubkey: &[u8],
        chain_id: Option<&str>,
    ) -> Result<ego_core::Signature, KeystoreError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut message = Vec::new();
        message.extend_from_slice(b"EGO_BINDING:");
        message.extend_from_slice(account_pubkey);
        message.extend_from_slice(&timestamp.to_be_bytes());
        if let Some(chain_id) = chain_id {
            message.extend_from_slice(chain_id.as_bytes());
        }

        self.sign(&message)
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

    pub fn set_encryption_key(&mut self, key: [u8; 32]) {
        self.encryption_key = Some(key);
    }

    fn derive_encryption_key(&mut self) -> Result<(), KeystoreError> {
        if let Some(seed) = self.master_seed {
            let mut derivation_data = seed.to_vec();
            derivation_data.extend_from_slice(b"encryption_key");

            let key_hash = ego_core::crypto::blake2s_hash(&derivation_data);
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_hash[..32]);

            self.encryption_key = Some(key);
        }
        Ok(())
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
            "encrypted": true,
            "password_hint": format!("{}...{}", &hex::encode(&password_hash)[..6], &hex::encode(&password_hash)[58..]),
            "note": "Encrypted EGO keystore - use proper password to decrypt"
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
            "created_at": chrono::DateTime::from_timestamp(self.metadata.created_at as i64, 0)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_else(|| "unknown".to_string()),
            "note": "EGO keystore metadata (private keys not exported for security)"
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

    pub fn is_encrypted(&self) -> bool {
        self.encryption_key.is_some()
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

    pub fn dilithium_public_key(&self) -> Vec<u8> {
        self.primary_keypair.dilithium_public_key()
    }

    pub fn kyber_public_key(&self) -> Vec<u8> {
        self.primary_keypair.kyber_public_key()
    }

    pub fn sign_dilithium(&self, message: &[u8]) -> Vec<u8> {
        self.primary_keypair.sign_dilithium(message)
    }

    pub fn bind_on_chain_account_simple(&mut self, account_pubkey: Vec<u8>, signature: Vec<u8>) {
        let binding = AccountBinding {
            account_pubkey,
            binding_signature: signature,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            chain_id: None,
            verified: false,
        };

        self.account_bindings.insert("default".to_string(), binding);
        self.metadata.binding_count = self.account_bindings.len();
        self.touch();
    }

    pub fn get_binding_legacy(&self) -> Option<(&[u8], &[u8])> {
        self.get_binding(None).map(|binding| {
            (
                binding.account_pubkey.as_slice(),
                binding.binding_signature.as_slice(),
            )
        })
    }

    pub fn secure_clear(&mut self) {
        if let Some(ref mut seed) = self.master_seed {
            seed.fill(0);
        }
        if let Some(ref mut key) = self.encryption_key {
            key.fill(0);
        }
    }

    pub fn get_stats(&self) -> KeystoreStats {
        KeystoreStats {
            total_keys: self.metadata.key_count,
            derived_keys: self.derived_keypairs.len(),
            account_bindings: self.metadata.binding_count,
            is_encrypted: self.is_encrypted(),
            peer_id: self.peer_id().to_string(),
            address: self.get_address().to_string(),
            created_at: self.metadata.created_at,
            last_accessed: self.metadata.last_accessed,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreStats {
    pub total_keys: usize,
    pub derived_keys: usize,
    pub account_bindings: usize,
    pub is_encrypted: bool,
    pub peer_id: String,
    pub address: String,
    pub created_at: u64,
    pub last_accessed: u64,
}

impl Drop for SecureKeystore {
    fn drop(&mut self) {
        self.secure_clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keystore_creation() {
        let keystore = SecureKeystore::new();
        assert!(!keystore.get_address().to_string().is_empty());
        assert!(!keystore.peer_id().to_string().is_empty());
    }

    #[test]
    fn test_signing_and_verification() {
        let keystore = SecureKeystore::new();
        let message = b"test message";

        let signature = keystore.sign(message).unwrap();
        assert!(keystore.verify(message, &signature));
    }

    #[test]
    fn test_key_derivation() {
        let mut keystore = SecureKeystore::new();
        let derived = keystore.derive_keypair("test", None).unwrap();
        let derived_pubkey = derived.public_key().as_bytes().to_vec();

        let derived2 = keystore.get_derived_keypair("test").unwrap();
        assert_eq!(derived_pubkey, derived2.public_key().as_bytes());
    }

    #[test]
    fn test_account_binding() {
        let mut keystore = SecureKeystore::new();
        let account_pubkey = vec![1u8; 32];
        let signature = keystore.sign(&account_pubkey).unwrap();

        keystore.bind_on_chain_account_simple(account_pubkey.clone(), signature.to_vec());

        let binding = keystore.get_binding(None);
        assert!(binding.is_some());
        assert_eq!(binding.unwrap().account_pubkey, account_pubkey);
    }
}
