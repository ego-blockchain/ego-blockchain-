use libp2p::identity::{Keypair, PublicKey};
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

        let is_valid = libp2p_pubkey.verify(&message, &self.binding_signature);
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
}

pub struct SecureKeystore {
    primary_keypair: Keypair,
    derived_keypairs: HashMap<String, Keypair>,
    account_bindings: HashMap<String, AccountBinding>,
    master_seed: Option<[u8; 32]>,
    encryption_key: Option<[u8; 32]>,
    metadata: KeystoreMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreMetadata {
    pub version: String,
    pub created_at: u64,
    pub last_accessed: u64,
    pub key_count: usize,
    pub binding_count: usize,
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
        }
    }
}

impl SecureKeystore {
    pub fn new() -> Self {
        let primary_keypair = Keypair::generate_ed25519();
        let mut master_seed = [0u8; 32];
        rand::rng().fill_bytes(&mut master_seed);

        Self {
            primary_keypair,
            derived_keypairs: HashMap::new(),
            account_bindings: HashMap::new(),
            master_seed: Some(master_seed),
            encryption_key: None,
            metadata: KeystoreMetadata::default(),
        }
    }

    pub fn from_seed(seed: [u8; 32]) -> Result<Self, KeystoreError> {
        let primary_keypair = Keypair::generate_ed25519();

        let mut keystore = Self {
            primary_keypair,
            derived_keypairs: HashMap::new(),
            account_bindings: HashMap::new(),
            master_seed: Some(seed),
            encryption_key: None,
            metadata: KeystoreMetadata::default(),
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

        Self::from_seed(seed)
    }

    pub fn keypair(&self) -> &Keypair {
        &self.primary_keypair
    }

    pub fn public_key(&self) -> PublicKey {
        self.primary_keypair.public()
    }

    pub fn peer_id(&self) -> libp2p::PeerId {
        self.primary_keypair.public().to_peer_id()
    }

    pub fn derive_keypair(
        &mut self,
        purpose: &str,
        _path: Option<DerivationPath>,
    ) -> Result<&Keypair, KeystoreError> {
        if self.derived_keypairs.contains_key(purpose) {
            return Ok(self.derived_keypairs.get(purpose).unwrap());
        }

        let derived_keypair = Keypair::generate_ed25519();
        self.derived_keypairs
            .insert(purpose.to_string(), derived_keypair);
        self.metadata.key_count += 1;

        Ok(self.derived_keypairs.get(purpose).unwrap())
    }

    pub fn get_derived_keypair(&self, purpose: &str) -> Option<&Keypair> {
        self.derived_keypairs.get(purpose)
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        self.primary_keypair
            .sign(message)
            .map_err(|e| KeystoreError::InvalidSignature(e.to_string()))
    }

    pub fn sign_with_derived(
        &self,
        purpose: &str,
        message: &[u8],
    ) -> Result<Vec<u8>, KeystoreError> {
        let keypair = self
            .derived_keypairs
            .get(purpose)
            .ok_or_else(|| KeystoreError::KeyNotFound(purpose.to_string()))?;

        keypair
            .sign(message)
            .map_err(|e| KeystoreError::InvalidSignature(e.to_string()))
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        self.primary_keypair.public().verify(message, signature)
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

        Ok(())
    }

    pub fn create_binding_signature(
        &self,
        account_pubkey: &[u8],
        chain_id: Option<&str>,
    ) -> Result<Vec<u8>, KeystoreError> {
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
        }
        removed
    }

    pub fn set_encryption_key(&mut self, key: [u8; 32]) {
        self.encryption_key = Some(key);
    }

    fn derive_encryption_key(&mut self) -> Result<(), KeystoreError> {
        if let Some(seed) = self.master_seed {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};

            let mut hasher = DefaultHasher::new();
            seed.hash(&mut hasher);
            b"encryption_key".hash(&mut hasher);
            let hash = hasher.finish();

            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&hash.to_be_bytes());
            key[8..16].copy_from_slice(&hash.to_le_bytes());
            for i in 16..32 {
                key[i] = (hash.wrapping_mul(i as u64) % 256) as u8;
            }

            self.encryption_key = Some(key);
        }
        Ok(())
    }

    pub fn export_encrypted(&self, _password: &str) -> Result<String, KeystoreError> {
        let export_data = serde_json::json!({
            "version": self.metadata.version,
            "peer_id": self.peer_id().to_string(),
            "created_at": self.metadata.created_at,
            "key_count": self.metadata.key_count,
            "binding_count": self.metadata.binding_count,
            "encrypted": true,
            "note": "This is a placeholder - implement proper encryption in production"
        });

        Ok(export_data.to_string())
    }

    pub fn import_encrypted(_data: &str, _password: &str) -> Result<Self, KeystoreError> {
        Err(KeystoreError::DecryptionFailed(
            "Import functionality not yet implemented".to_string(),
        ))
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), KeystoreError> {
        let export_data = serde_json::json!({
            "version": self.metadata.version,
            "peer_id": self.peer_id().to_string(),
            "metadata": self.metadata,
            "note": "Development keystore - do not use in production"
        });

        std::fs::write(path, export_data.to_string()).map_err(|e| KeystoreError::IoError(e))?;
        Ok(())
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

    pub fn secure_clear(&mut self) {
        if let Some(ref mut seed) = self.master_seed {
            seed.fill(0);
        }
        if let Some(ref mut key) = self.encryption_key {
            key.fill(0);
        }
    }
}

impl Drop for SecureKeystore {
    fn drop(&mut self) {
        self.secure_clear();
    }
}

impl SecureKeystore {
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
    }

    pub fn get_binding_legacy(&self) -> Option<(&[u8], &[u8])> {
        self.get_binding(None).map(|binding| {
            (
                binding.account_pubkey.as_slice(),
                binding.binding_signature.as_slice(),
            )
        })
    }
}
