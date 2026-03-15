use crate::{
    AlgorithmId, DualSignature, EgoError, EgoResult, HandshakeInit, Hash, PeerCapabilities,
    PublicKey, SessionRecord, Signature,
};
use bech32::{decode, encode, Hrp};
use blake2::{Blake2s256, Digest};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber768;
use pqcrypto_sphincsplus::sphincssha256128ssimple;
use pqcrypto_traits::kem::{
    Ciphertext as PqKemCiphertext, PublicKey as PqKemPublicKey, SecretKey as PqKemSecretKey,
    SharedSecret as PqSharedSecret,
};
use pqcrypto_traits::sign::{
    DetachedSignature as PqDetachedSignature, PublicKey as PqSignPublicKey,
    SecretKey as PqSignSecretKey,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAX_NONCE_HISTORY: usize = 10000;
const DOMAIN_TAG_HEADER: &[u8] = b"ego/core/v1";
const DOMAIN_TAG_TX: &[u8] = b"ego/tx/v1";
const DOMAIN_TAG_STREAM: &[u8] = b"ego/stream";
const DOMAIN_TAG_TXOUT_BASE: &[u8] = b"ego/txout/base";
const DOMAIN_TAG_TXOUT_SEED_OTSK: &[u8] = b"ego/txout/seed_otsk";
const DOMAIN_TAG_TXOUT_AEAD: &[u8] = b"ego/txout/aead";
const DOMAIN_TAG_PEERBIND: &[u8] = b"ego/peerbind";
const DOMAIN_TAG_POC_BEACON: &[u8] = b"ego/poc/beacon";
const DOMAIN_TAG_POC_WITNESS: &[u8] = b"ego/poc/witness";
const DOMAIN_TAG_POST_PROOF: &[u8] = b"ego/post/proof";
const DOMAIN_TAG_OTS_KEYGEN: &[u8] = b"ego/ots/keygen/v1";
const DOMAIN_TAG_ADDRESS: &[u8] = b"ego/addr/v1";

const HRP_MAINNET: &str = "ego";
const HRP_TESTNET: &str = "egot";
const HRP_DEVNET: &str = "egod";

const ADDRESS_VERSION: u8 = 0b001;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressType {
    EOA = 0,
    Contract = 1,
    Device = 2,
    Validator = 3,
}

impl AddressType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(AddressType::EOA),
            1 => Some(AddressType::Contract),
            2 => Some(AddressType::Device),
            3 => Some(AddressType::Validator),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgoAddress {
    version_type: u8,
    payload: [u8; 20],
}

impl EgoAddress {
    pub fn from_dilithium_pk(
        dilithium_pk: &[u8],
        chain_id: u32,
        address_type: AddressType,
    ) -> Self {
        let mut hasher = Blake2s256::new();
        hasher.update(DOMAIN_TAG_ADDRESS);
        hasher.update(chain_id.to_le_bytes());
        hasher.update(dilithium_pk);
        let digest = hasher.finalize();

        let version_bits = ADDRESS_VERSION << 5;
        let type_bits = address_type.as_u8() & 0b1_1111;
        let version_type = version_bits | type_bits;

        let mut payload = [0u8; 20];
        payload.copy_from_slice(&digest[..20]);

        Self {
            version_type,
            payload,
        }
    }

    pub fn to_bech32(&self, hrp_str: &str) -> EgoResult<String> {
        let mut full_payload = Vec::with_capacity(21);
        full_payload.push(self.version_type);
        full_payload.extend_from_slice(&self.payload);

        let hrp = Hrp::parse(hrp_str)
            .map_err(|e| EgoError::CryptoError(format!("Invalid HRP: {}", e)))?;

        encode::<bech32::Bech32m>(hrp, &full_payload)
            .map_err(|e| EgoError::CryptoError(format!("Bech32m encoding failed: {}", e)))
    }

    pub fn from_bech32(address: &str, expected_hrp: &str) -> EgoResult<Self> {
        let (hrp, data) = decode(address)
            .map_err(|e| EgoError::CryptoError(format!("Bech32m decoding failed: {}", e)))?;

        if hrp.as_str() != expected_hrp {
            return Err(EgoError::CryptoError(format!(
                "HRP mismatch: expected {}, got {}",
                expected_hrp, hrp
            )));
        }

        if data.len() != 21 {
            return Err(EgoError::CryptoError(format!(
                "Invalid payload length: expected 21, got {}",
                data.len()
            )));
        }

        let version_type = data[0];
        let version = version_type >> 5;

        if version != ADDRESS_VERSION {
            return Err(EgoError::CryptoError(format!(
                "Invalid version: expected {}, got {}",
                ADDRESS_VERSION, version
            )));
        }

        let mut payload = [0u8; 20];
        payload.copy_from_slice(&data[1..21]);

        Ok(Self {
            version_type,
            payload,
        })
    }

    pub fn address_type(&self) -> Option<AddressType> {
        let type_bits = self.version_type & 0b1_1111;
        AddressType::from_u8(type_bits)
    }

    pub fn version(&self) -> u8 {
        self.version_type >> 5
    }

    pub fn payload(&self) -> &[u8; 20] {
        &self.payload
    }

    pub fn as_bytes(&self) -> [u8; 21] {
        let mut bytes = [0u8; 21];
        bytes[0] = self.version_type;
        bytes[1..21].copy_from_slice(&self.payload);
        bytes
    }
}

#[derive(Debug, Clone)]
pub struct KeyPair {
    ed25519_signing_key: SigningKey,
    ed25519_verifying_key: VerifyingKey,
    dilithium_pk: Vec<u8>,
    dilithium_sk: Vec<u8>,
    kyber_pk: Vec<u8>,
    kyber_sk: Vec<u8>,
    x25519_secret: [u8; 32],
    x25519_public: X25519PublicKey,
    slh_dsa_pk: Option<Vec<u8>>,
    slh_dsa_sk: Option<Vec<u8>>,
    seed: [u8; 32],
    transition_mode: bool,
}

impl Zeroize for KeyPair {
    fn zeroize(&mut self) {
        self.dilithium_pk.zeroize();
        self.dilithium_sk.zeroize();
        self.kyber_pk.zeroize();
        self.kyber_sk.zeroize();
        if let Some(ref mut pk) = self.slh_dsa_pk {
            pk.zeroize();
        }
        if let Some(ref mut sk) = self.slh_dsa_sk {
            sk.zeroize();
        }
        self.x25519_secret.zeroize();
        self.seed.zeroize();
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for KeyPair {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedKeys {
    pub ed25519_public: Vec<u8>,
    pub ed25519_secret: Vec<u8>,
    pub dilithium_public: Vec<u8>,
    pub dilithium_secret: Vec<u8>,
    pub kyber_public: Vec<u8>,
    pub kyber_secret: Vec<u8>,
    pub x25519_public: Vec<u8>,
    pub x25519_secret: Vec<u8>,
    pub slh_dsa_public: Option<Vec<u8>>,
    pub slh_dsa_secret: Option<Vec<u8>>,
    pub seed: Vec<u8>,
    pub transition_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedKeysHex {
    pub ed25519_public: String,
    pub ed25519_secret: String,
    pub dilithium_public: String,
    pub dilithium_secret: String,
    pub kyber_public: String,
    pub kyber_secret: String,
    pub x25519_public: String,
    pub x25519_secret: String,
    pub slh_dsa_public: Option<String>,
    pub slh_dsa_secret: Option<String>,
    pub seed: String,
    pub transition_mode: bool,
}

impl KeyPair {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(seed, false)
    }

    pub fn generate_with_transition() -> Self {
        let mut rng = OsRng;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(seed, true)
    }

    pub fn generate_with_slh_dsa() -> Self {
        let mut keypair = Self::generate();
        let (slh_pk, slh_sk) = derive_slh_dsa_keypair().unwrap();
        keypair.slh_dsa_pk = Some(slh_pk);
        keypair.slh_dsa_sk = Some(slh_sk);
        keypair.transition_mode = false;
        keypair
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> EgoResult<Self> {
        Ok(Self::from_seed(*bytes, false))
    }

    fn from_seed(seed: [u8; 32], transition_mode: bool) -> Self {
        let ed25519_signing_key = SigningKey::from_bytes(&seed);
        let ed25519_verifying_key = ed25519_signing_key.verifying_key();

        let (dilithium_pk, dilithium_sk) = derive_dilithium_keypair().unwrap();
        let (kyber_pk, kyber_sk) = derive_kyber_keypair().unwrap();

        let x25519_secret = seed;
        let x25519_public = X25519PublicKey::from(x25519_secret);

        Self {
            ed25519_signing_key,
            ed25519_verifying_key,
            dilithium_pk,
            dilithium_sk,
            kyber_pk,
            kyber_sk,
            x25519_secret,
            x25519_public,
            slh_dsa_pk: None,
            slh_dsa_sk: None,
            seed,
            transition_mode,
        }
    }

    pub fn derive_address(&self, chain_id: u32, address_type: AddressType) -> EgoAddress {
        EgoAddress::from_dilithium_pk(&self.dilithium_pk, chain_id, address_type)
    }

    pub fn derive_bech32_address(
        &self,
        chain_id: u32,
        address_type: AddressType,
        hrp: &str,
    ) -> EgoResult<String> {
        let address = self.derive_address(chain_id, address_type);
        address.to_bech32(hrp)
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::dilithium2(self.dilithium_pk.clone())
    }

    pub fn ed25519_public_key(&self) -> PublicKey {
        PublicKey::ed25519(self.ed25519_verifying_key.to_bytes())
    }

    pub fn dilithium_public_key(&self) -> PublicKey {
        PublicKey::dilithium2(self.dilithium_pk.clone())
    }

    pub fn kyber_public_key(&self) -> PublicKey {
        PublicKey::kyber768(self.kyber_pk.clone())
    }

    pub fn slh_dsa_public_key(&self) -> Option<PublicKey> {
        self.slh_dsa_pk
            .as_ref()
            .map(|pk| PublicKey::new(AlgorithmId::SlhDsa, pk.clone()))
    }

    pub fn x25519_public_key(&self) -> Vec<u8> {
        self.x25519_public.as_bytes().to_vec()
    }

    pub fn get_peer_capabilities(&self, account_addr: crate::Address) -> PeerCapabilities {
        let mut sig_algs = vec![AlgorithmId::MlDsa2.as_u16()];
        if self.transition_mode {
            sig_algs.push(AlgorithmId::Ed25519.as_u16());
        }

        PeerCapabilities {
            alg_sig_supported: sig_algs,
            alg_kem_supported: vec![AlgorithmId::MlKem768.as_u16()],
            pq_required: !self.transition_mode,
            mlkem_pk: self.kyber_pk.clone(),
            x25519_pk: if self.transition_mode {
                Some(self.x25519_public_key())
            } else {
                None
            },
            account_addr,
            supported_topics: vec![
                "consensus".to_string(),
                "storage".to_string(),
                "compute".to_string(),
            ],
            max_bandwidth: 1_000_000_000,
            cellular_safe: true,
        }
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.sign_dilithium(message)
    }

    pub fn sign_dilithium(&self, message: &[u8]) -> Signature {
        let signature_data = dilithium_sign(&self.dilithium_sk, message).unwrap();
        Signature::dilithium2(signature_data)
    }

    pub fn sign_ed25519(&self, message: &[u8]) -> Signature {
        let signature = self.ed25519_signing_key.sign(message);
        Signature::ed25519(signature.to_bytes())
    }

    pub fn sign_slh_dsa(&self, message: &[u8]) -> EgoResult<Signature> {
        if let Some(ref sk) = self.slh_dsa_sk {
            let signature_data = slh_dsa_sign(sk, message)?;
            Ok(Signature::slh_dsa(signature_data))
        } else {
            Err(EgoError::CryptoError(
                "SLH-DSA keys not available".to_string(),
            ))
        }
    }

    pub fn dual_sign(&self, message: &[u8]) -> DualSignature {
        if self.transition_mode {
            let ed25519_sig = self.sign_ed25519(message);
            let dilithium_sig = self.sign_dilithium(message);
            DualSignature::hybrid(ed25519_sig, dilithium_sig)
        } else {
            DualSignature::dilithium_only(self.sign_dilithium(message))
        }
    }

    pub fn sign_hybrid(&self, message: &[u8], force_transition: bool) -> DualSignature {
        if force_transition || self.transition_mode {
            let ed25519_sig = self.sign_ed25519(message);
            let dilithium_sig = self.sign_dilithium(message);
            DualSignature::hybrid(ed25519_sig, dilithium_sig)
        } else {
            DualSignature::dilithium_only(self.sign_dilithium(message))
        }
    }

    pub fn is_transition_mode(&self) -> bool {
        self.transition_mode
    }

    pub fn set_transition_mode(&mut self, enabled: bool) {
        self.transition_mode = enabled;
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.seed
    }

    pub fn derive_session_key(&self, peer_public_key: &[u8], info: &[u8]) -> EgoResult<Vec<u8>> {
        let x25519_peer_pubkey =
            X25519PublicKey::from(<[u8; 32]>::try_from(peer_public_key).map_err(|_| {
                EgoError::CryptoError("Invalid X25519 public key length".to_string())
            })?);

        let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
        let shared_secret = ephemeral_secret.diffie_hellman(&x25519_peer_pubkey);

        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut okm = [0u8; 32];
        hk.expand(info, &mut okm)
            .map_err(|e| EgoError::CryptoError(format!("HKDF expand failed: {}", e)))?;

        Ok(okm.to_vec())
    }

    pub fn encapsulate_kyber(&self, peer_kyber_pk: &[u8]) -> EgoResult<(Vec<u8>, Vec<u8>)> {
        kyber_encapsulate(peer_kyber_pk)
    }

    pub fn decapsulate_kyber(&self, ciphertext: &[u8]) -> EgoResult<Vec<u8>> {
        kyber_decapsulate(&self.kyber_sk, ciphertext)
    }

    pub fn create_hybrid_session(
        &self,
        peer_x25519_pk: &[u8],
        peer_kyber_pk: &[u8],
        stream_kind: &str,
        stream_nonce: &[u8; 32],
        chain_id: &[u8],
        network_id: u32,
        version: u32,
    ) -> EgoResult<(SessionRecord, Vec<u8>)> {
        let x25519_shared = self.derive_session_key(peer_x25519_pk, b"x25519_component")?;
        let (kyber_ct, kyber_shared) = self.encapsulate_kyber(peer_kyber_pk)?;

        let mut combined_secret = Vec::new();
        combined_secret.extend_from_slice(&kyber_shared);
        combined_secret.extend_from_slice(&x25519_shared);

        let salt = blake2s_hash_domain(&[
            DOMAIN_TAG_STREAM,
            stream_kind.as_bytes(),
            stream_nonce,
            chain_id,
            &network_id.to_le_bytes(),
            &version.to_le_bytes(),
        ]);
        let session_key = hkdf_blake2s(&combined_secret, &salt, chain_id, 32);

        let mut nonce = [0u8; 24];
        let mut rng = OsRng;
        rng.fill_bytes(&mut nonce);

        let session_record = SessionRecord::hybrid(
            self.x25519_public.as_bytes().to_vec(),
            kyber_ct,
            nonce,
            vec![],
        );

        Ok((session_record, session_key))
    }

    pub fn create_kyber_only_session(
        &self,
        peer_kyber_pk: &[u8],
        stream_kind: &str,
        stream_nonce: &[u8; 32],
        chain_id: &[u8],
        network_id: u32,
        version: u32,
    ) -> EgoResult<(SessionRecord, Vec<u8>)> {
        let (kyber_ct, kyber_shared) = self.encapsulate_kyber(peer_kyber_pk)?;

        let salt = blake2s_hash_domain(&[
            DOMAIN_TAG_STREAM,
            stream_kind.as_bytes(),
            stream_nonce,
            chain_id,
            &network_id.to_le_bytes(),
            &version.to_le_bytes(),
        ]);
        let session_key = hkdf_blake2s(&kyber_shared, &salt, chain_id, 32);

        let mut nonce = [0u8; 24];
        let mut rng = OsRng;
        rng.fill_bytes(&mut nonce);

        let session_record = SessionRecord::kyber_only(kyber_ct, nonce, vec![]);

        Ok((session_record, session_key))
    }

    pub fn create_identity_binding(
        &self,
        peer_id: &str,
        caps: &[u8],
        chain_id: &[u8],
        network_id: u32,
        version: u32,
        include_ed25519: bool,
    ) -> EgoResult<Vec<u8>> {
        let mut combined = peer_id.as_bytes().to_vec();
        combined.extend_from_slice(&self.kyber_pk);
        combined.extend_from_slice(caps);
        combined.extend_from_slice(chain_id);
        combined.extend_from_slice(&network_id.to_le_bytes());
        combined.extend_from_slice(&version.to_le_bytes());

        let mut nonce = [0u8; 32];
        let mut rng = OsRng;
        rng.fill_bytes(&mut nonce);
        combined.extend_from_slice(&nonce);

        let data_to_sign = blake2s_hash_domain(&[DOMAIN_TAG_PEERBIND, &combined]);

        if include_ed25519 {
            let ed25519_sig = self.sign_ed25519(&data_to_sign);
            let dilithium_sig = self.sign_dilithium(&data_to_sign);
            let dual_sig = DualSignature::hybrid(ed25519_sig, dilithium_sig);

            let config = bincode::config::standard();
            let mut result = bincode::encode_to_vec(&dual_sig, config)
                .map_err(|e| EgoError::SerializationError(e.to_string()))?;
            result.extend_from_slice(&nonce);
            Ok(result)
        } else {
            let mut result = self.sign_dilithium(&data_to_sign).signature_data;
            result.extend_from_slice(&nonce);
            Ok(result)
        }
    }

    pub fn sign_poc_beacon(
        &self,
        beacon_data: &[u8],
        chain_id: &[u8],
        network_id: u32,
    ) -> Signature {
        let msg = blake2s_hash_domain(&[
            DOMAIN_TAG_POC_BEACON,
            beacon_data,
            chain_id,
            &network_id.to_le_bytes(),
        ]);
        self.sign_dilithium(&msg)
    }

    pub fn sign_poc_witness(
        &self,
        witness_data: &[u8],
        chain_id: &[u8],
        network_id: u32,
    ) -> Signature {
        let msg = blake2s_hash_domain(&[
            DOMAIN_TAG_POC_WITNESS,
            witness_data,
            chain_id,
            &network_id.to_le_bytes(),
        ]);
        self.sign_dilithium(&msg)
    }

    pub fn sign_post_proof(
        &self,
        proof_data: &[u8],
        chain_id: &[u8],
        network_id: u32,
    ) -> Signature {
        let msg = blake2s_hash_domain(&[
            DOMAIN_TAG_POST_PROOF,
            proof_data,
            chain_id,
            &network_id.to_le_bytes(),
        ]);
        self.sign_dilithium(&msg)
    }

    pub fn derive_ots_keypair_from_seed(_seed: &[u8; 32]) -> EgoResult<(Vec<u8>, Vec<u8>)> {
        derive_dilithium_keypair()
    }

    pub fn export_keys(&self) -> ExportedKeys {
        ExportedKeys {
            ed25519_public: self.ed25519_verifying_key.to_bytes().to_vec(),
            ed25519_secret: self.ed25519_signing_key.to_bytes().to_vec(),
            dilithium_public: self.dilithium_pk.clone(),
            dilithium_secret: self.dilithium_sk.clone(),
            kyber_public: self.kyber_pk.clone(),
            kyber_secret: self.kyber_sk.clone(),
            x25519_public: self.x25519_public.as_bytes().to_vec(),
            x25519_secret: self.x25519_secret.to_vec(),
            slh_dsa_public: self.slh_dsa_pk.clone(),
            slh_dsa_secret: self.slh_dsa_sk.clone(),
            seed: self.seed.to_vec(),
            transition_mode: self.transition_mode,
        }
    }

    pub fn export_keys_hex(&self) -> ExportedKeysHex {
        ExportedKeysHex {
            ed25519_public: hex::encode(self.ed25519_verifying_key.to_bytes()),
            ed25519_secret: hex::encode(self.ed25519_signing_key.to_bytes()),
            dilithium_public: hex::encode(&self.dilithium_pk),
            dilithium_secret: hex::encode(&self.dilithium_sk),
            kyber_public: hex::encode(&self.kyber_pk),
            kyber_secret: hex::encode(&self.kyber_sk),
            x25519_public: hex::encode(self.x25519_public.as_bytes()),
            x25519_secret: hex::encode(&self.x25519_secret),
            slh_dsa_public: self.slh_dsa_pk.as_ref().map(|pk| hex::encode(pk)),
            slh_dsa_secret: self.slh_dsa_sk.as_ref().map(|sk| hex::encode(sk)),
            seed: hex::encode(&self.seed),
            transition_mode: self.transition_mode,
        }
    }

    pub fn get_dilithium_secret_key(&self) -> &[u8] {
        &self.dilithium_sk
    }

    pub fn get_kyber_secret_key(&self) -> &[u8] {
        &self.kyber_sk
    }

    pub fn get_ed25519_secret_key(&self) -> &[u8] {
        self.ed25519_signing_key.as_bytes()
    }

    pub fn get_x25519_secret_key(&self) -> &[u8; 32] {
        &self.x25519_secret
    }

    pub fn get_seed(&self) -> &[u8; 32] {
        &self.seed
    }

    pub fn get_slh_dsa_secret_key(&self) -> Option<&[u8]> {
        self.slh_dsa_sk.as_ref().map(|sk| sk.as_slice())
    }
}

#[derive(Clone)]
pub struct StreamCipher {
    cipher: XChaCha20Poly1305,
    tx_counter: u64,
    rx_counter: u64,
    stream_id: Vec<u8>,
    chain_id: Vec<u8>,
    network_id: u32,
    alg_ids: (u16, u16),
    nonce_history: Arc<Mutex<HashSet<Vec<u8>>>>,
}

impl std::fmt::Debug for StreamCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamCipher")
            .field("tx_counter", &self.tx_counter)
            .field("rx_counter", &self.rx_counter)
            .field("stream_id", &self.stream_id)
            .field("chain_id", &self.chain_id)
            .field("network_id", &self.network_id)
            .field("alg_ids", &self.alg_ids)
            .finish_non_exhaustive()
    }
}

impl StreamCipher {
    pub fn new(
        key: &[u8; 32],
        stream_id: Vec<u8>,
        chain_id: Vec<u8>,
        network_id: u32,
        alg_ids: (u16, u16),
    ) -> EgoResult<Self> {
        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| EgoError::CryptoError(format!("Cipher initialization failed: {}", e)))?;

        Ok(Self {
            cipher,
            tx_counter: 0,
            rx_counter: 0,
            stream_id,
            chain_id,
            network_id,
            alg_ids,
            nonce_history: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    pub fn encrypt_frame(&mut self, plaintext: &[u8], direction: u8) -> EgoResult<Vec<u8>> {
        let mut nonce = [0u8; 24];
        let mut rng = OsRng;
        rng.fill_bytes(&mut nonce);

        {
            let mut history = self.nonce_history.lock().unwrap();
            if history.contains(&nonce.to_vec()) {
                return Err(EgoError::CryptoError(
                    "Duplicate nonce detected".to_string(),
                ));
            }
            history.insert(nonce.to_vec());
            if history.len() > MAX_NONCE_HISTORY {
                history.clear();
            }
        }

        let aad = self.create_aad(direction, self.tx_counter)?;
        let xnonce = XNonce::from_slice(&nonce);

        let payload = chacha20poly1305::aead::Payload {
            msg: plaintext,
            aad: &aad,
        };

        let ciphertext = self
            .cipher
            .encrypt(xnonce, payload)
            .map_err(|e| EgoError::CryptoError(format!("Encryption failed: {}", e)))?;

        self.tx_counter = self.tx_counter.wrapping_add(1);

        let mut frame = Vec::new();
        frame.extend_from_slice(&nonce);
        frame.extend_from_slice(&(aad.len() as u32).to_le_bytes());
        frame.extend_from_slice(&aad);
        frame.extend_from_slice(&ciphertext);

        Ok(frame)
    }

    pub fn decrypt_frame(&mut self, frame: &[u8], direction: u8) -> EgoResult<Vec<u8>> {
        if frame.len() < 28 {
            return Err(EgoError::CryptoError("Frame too short".to_string()));
        }

        let nonce = &frame[..24];

        {
            let mut history = self.nonce_history.lock().unwrap();
            if history.contains(&nonce.to_vec()) {
                return Err(EgoError::CryptoError(
                    "Duplicate nonce detected - replay attack".to_string(),
                ));
            }
            history.insert(nonce.to_vec());
            if history.len() > MAX_NONCE_HISTORY {
                history.clear();
            }
        }

        let aad_len_bytes = [frame[24], frame[25], frame[26], frame[27]];
        let aad_len = u32::from_le_bytes(aad_len_bytes) as usize;

        if frame.len() < 28 + aad_len {
            return Err(EgoError::CryptoError("Frame too short for AAD".to_string()));
        }

        let actual_aad = &frame[28..28 + aad_len];
        let expected_aad = self.create_aad(direction, self.rx_counter)?;

        if expected_aad != actual_aad {
            return Err(EgoError::CryptoError("AAD mismatch".to_string()));
        }

        let ciphertext = &frame[28 + aad_len..];
        let xnonce = XNonce::from_slice(nonce);

        let payload = chacha20poly1305::aead::Payload {
            msg: ciphertext,
            aad: actual_aad,
        };

        let plaintext = self
            .cipher
            .decrypt(xnonce, payload)
            .map_err(|e| EgoError::CryptoError(format!("Decryption failed: {}", e)))?;

        self.rx_counter = self.rx_counter.wrapping_add(1);
        Ok(plaintext)
    }

    fn create_aad(&self, direction: u8, counter: u64) -> EgoResult<Vec<u8>> {
        let mut aad = Vec::new();
        aad.extend_from_slice(&self.stream_id);
        aad.push(direction);
        aad.extend_from_slice(&counter.to_le_bytes());
        aad.extend_from_slice(&self.alg_ids.0.to_le_bytes());
        aad.extend_from_slice(&self.alg_ids.1.to_le_bytes());
        aad.extend_from_slice(&self.chain_id);
        aad.extend_from_slice(&self.network_id.to_le_bytes());

        Ok(blake2s_hash(&aad))
    }

    pub fn detect_duplicate_nonce(&self, nonce: &[u8; 24], _counter: u64) -> bool {
        let history = self.nonce_history.lock().unwrap();
        history.contains(&nonce.to_vec())
    }
}

#[derive(Debug, Clone)]
pub struct BatchVerifier {
    signatures: Vec<(PublicKey, Vec<u8>, Signature)>,
    max_batch_size: usize,
    cpu_budget_remaining: u64,
}

impl BatchVerifier {
    pub fn new(cpu_budget: u64, max_batch_size: usize) -> Self {
        Self {
            signatures: Vec::new(),
            max_batch_size,
            cpu_budget_remaining: cpu_budget,
        }
    }

    pub fn add_signature(
        &mut self,
        public_key: PublicKey,
        message: Vec<u8>,
        signature: Signature,
    ) -> EgoResult<()> {
        if self.signatures.len() >= self.max_batch_size {
            return Err(EgoError::CryptoError(
                "Batch size limit exceeded".to_string(),
            ));
        }

        let estimated_cost = match signature.algorithm {
            AlgorithmId::MlDsa2 => 5000,
            AlgorithmId::Ed25519 => 1000,
            AlgorithmId::SlhDsa => 10000,
            _ => 2000,
        };

        if self.cpu_budget_remaining < estimated_cost {
            return Err(EgoError::CryptoError(
                "CPU budget exceeded - backpressure triggered".to_string(),
            ));
        }

        self.cpu_budget_remaining -= estimated_cost;
        self.signatures.push((public_key, message, signature));
        Ok(())
    }

    pub fn verify_batch(&self) -> EgoResult<Vec<bool>> {
        let mut results = Vec::new();

        for (public_key, message, signature) in &self.signatures {
            let result = verify_signature(public_key, message, signature)?;
            results.push(result);
        }

        Ok(results)
    }

    pub fn clear(&mut self) {
        self.signatures.clear();
    }

    pub fn is_full(&self) -> bool {
        self.signatures.len() >= self.max_batch_size
    }

    pub fn has_budget(&self) -> bool {
        self.cpu_budget_remaining > 1000
    }
}

pub fn verify_signature(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
) -> EgoResult<bool> {
    match (public_key.algorithm, signature.algorithm) {
        (AlgorithmId::Ed25519, AlgorithmId::Ed25519) => {
            if public_key.key_data.len() < 32 {
                return Ok(false);
            }

            let mut ed25519_pubkey = [0u8; 32];
            ed25519_pubkey.copy_from_slice(&public_key.key_data[..32]);

            let ed25519_sig = signature
                .ed25519_bytes()
                .ok_or_else(|| EgoError::CryptoError("Invalid Ed25519 signature".to_string()))?;

            let verifying_key = VerifyingKey::from_bytes(&ed25519_pubkey)
                .map_err(|e| EgoError::CryptoError(format!("Invalid public key: {}", e)))?;

            let sig = ed25519_dalek::Signature::from_bytes(&ed25519_sig);

            match verifying_key.verify(message, &sig) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        }
        (AlgorithmId::MlDsa2, AlgorithmId::MlDsa2) => {
            verify_dilithium_signature(&public_key.key_data, message, &signature.signature_data)
        }
        (AlgorithmId::SlhDsa, AlgorithmId::SlhDsa) => {
            verify_slh_dsa_signature(&public_key.key_data, message, &signature.signature_data)
        }
        _ => Err(EgoError::CryptoError(
            "Algorithm mismatch between public key and signature".to_string(),
        )),
    }
}

pub fn verify_dual_signature(
    ed25519_pk: &PublicKey,
    dilithium_pk: &PublicKey,
    message: &[u8],
    dual_sig: &DualSignature,
) -> EgoResult<bool> {
    let mut ed25519_valid = false;
    let mut dilithium_valid = false;

    if let Some(ref ed25519_sig) = dual_sig.ed25519_sig {
        ed25519_valid = verify_signature(ed25519_pk, message, ed25519_sig)?;
    }

    if let Some(ref dilithium_sig) = dual_sig.dilithium_sig {
        dilithium_valid = verify_signature(dilithium_pk, message, dilithium_sig)?;
    }

    if dual_sig.ed25519_sig.is_some() && dual_sig.dilithium_sig.is_some() {
        Ok(ed25519_valid && dilithium_valid)
    } else if dual_sig.ed25519_sig.is_some() {
        Ok(ed25519_valid)
    } else if dual_sig.dilithium_sig.is_some() {
        Ok(dilithium_valid)
    } else {
        Ok(false)
    }
}

pub fn verify_dilithium_signature(
    dilithium_pk: &[u8],
    message: &[u8],
    signature: &[u8],
) -> EgoResult<bool> {
    dilithium_verify(dilithium_pk, message, signature)
}

pub fn verify_slh_dsa_signature(
    slh_dsa_pk: &[u8],
    message: &[u8],
    signature: &[u8],
) -> EgoResult<bool> {
    slh_dsa_verify(slh_dsa_pk, message, signature)
}

pub fn blake2s_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Blake2s256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

pub fn blake2s_hash_domain(pieces: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Blake2s256::new();
    for piece in pieces {
        hasher.update(piece);
    }
    hasher.finalize().to_vec()
}

pub fn hash_data(data: &[u8]) -> Hash {
    let hash_bytes = blake2s_hash(data);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash_bytes[..32]);
    Hash::new(result)
}

pub fn hash_multiple(pieces: &[&[u8]]) -> Hash {
    let mut hasher = Blake2s256::new();
    for piece in pieces {
        hasher.update(piece);
    }
    let result = hasher.finalize();
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&result[..32]);
    Hash::new(hash_bytes)
}

pub fn hkdf_blake2s(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    hkdf_sha256(ikm, salt, info, length)
}

pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .expect("HKDF expand should not fail");
    okm
}

pub fn xchacha20poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    plaintext: &[u8],
    associated_data: &[u8],
) -> EgoResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| EgoError::CryptoError(format!("Cipher initialization failed: {}", e)))?;

    let xnonce = XNonce::from_slice(nonce);
    let payload = chacha20poly1305::aead::Payload {
        msg: plaintext,
        aad: associated_data,
    };

    cipher
        .encrypt(xnonce, payload)
        .map_err(|e| EgoError::CryptoError(format!("Encryption failed: {}", e)))
}

pub fn xchacha20poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> EgoResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| EgoError::CryptoError(format!("Cipher initialization failed: {}", e)))?;

    let xnonce = XNonce::from_slice(nonce);
    let payload = chacha20poly1305::aead::Payload {
        msg: ciphertext,
        aad: associated_data,
    };

    cipher
        .decrypt(xnonce, payload)
        .map_err(|e| EgoError::CryptoError(format!("Decryption failed: {}", e)))
}

pub fn create_handshake_init(
    keypair: &KeyPair,
    peer_kyber_pk: &[u8],
    stream_kind: &str,
    caps: &[u8],
    chain_id: &[u8],
    network_id: u32,
    version: u32,
    hybrid_mode: bool,
) -> EgoResult<HandshakeInit> {
    let mut stream_nonce = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut stream_nonce);

    let (kyber_ct, _) = keypair.encapsulate_kyber(peer_kyber_pk)?;

    if hybrid_mode {
        Ok(HandshakeInit::hybrid(
            AlgorithmId::MlKem768.as_u16(),
            AlgorithmId::X25519.as_u16(),
            keypair.x25519_public_key(),
            kyber_ct,
            stream_kind.to_string(),
            stream_nonce,
            caps.to_vec(),
            chain_id.to_vec(),
        ))
    } else {
        Ok(HandshakeInit::new(
            AlgorithmId::MlKem768.as_u16(),
            kyber_ct,
            stream_kind.to_string(),
            stream_nonce,
            caps.to_vec(),
            chain_id.to_vec(),
        ))
    }
}

pub fn verify_identity_binding(
    peer_id: &str,
    mlkem_pk: &[u8],
    caps: &[u8],
    chain_id: &[u8],
    _network_id: u32,
    _version: u32,
    nonce: &[u8],
    signature: &[u8],
    dilithium_pk: &[u8],
    ed25519_pk: Option<&[u8]>,
) -> EgoResult<bool> {
    let mut combined = peer_id.as_bytes().to_vec();
    combined.extend_from_slice(mlkem_pk);
    combined.extend_from_slice(caps);
    combined.extend_from_slice(chain_id);
    combined.extend_from_slice(&_network_id.to_le_bytes());
    combined.extend_from_slice(&_version.to_le_bytes());
    combined.extend_from_slice(nonce);
    let data_to_verify = blake2s_hash_domain(&[DOMAIN_TAG_PEERBIND, &combined]);

    if let Some(ed25519_key) = ed25519_pk {
        let nonce_len = 32;
        if signature.len() < nonce_len {
            return Ok(false);
        }
        let (sig_bytes, _) = signature.split_at(signature.len() - nonce_len);

        let config = bincode::config::standard();
        let (dual_sig, _): (DualSignature, usize) =
            bincode::decode_from_slice(sig_bytes, config)
                .map_err(|e| EgoError::SerializationError(e.to_string()))?;

        let ed25519_pk_obj =
            PublicKey::ed25519(<[u8; 32]>::try_from(ed25519_key).map_err(|_| {
                EgoError::CryptoError("Invalid Ed25519 public key length".to_string())
            })?);
        let dilithium_pk_obj = PublicKey::dilithium2(dilithium_pk.to_vec());

        verify_dual_signature(
            &ed25519_pk_obj,
            &dilithium_pk_obj,
            &data_to_verify,
            &dual_sig,
        )
    } else {
        let nonce_len = 32;
        if signature.len() < nonce_len {
            return Ok(false);
        }
        let (sig_bytes, _) = signature.split_at(signature.len() - nonce_len);
        verify_dilithium_signature(dilithium_pk, &data_to_verify, sig_bytes)
    }
}

pub fn derive_stealth_address(
    receiver_kyber_pk: &[u8],
    sender_ephemeral: &[u8; 32],
) -> EgoResult<(PublicKey, Vec<u8>)> {
    let (kyber_ct, shared_secret) = kyber_encapsulate(receiver_kyber_pk)?;

    let mut derivation_input = Vec::new();
    derivation_input.extend_from_slice(&shared_secret);
    derivation_input.extend_from_slice(sender_ephemeral);
    derivation_input.extend_from_slice(DOMAIN_TAG_TXOUT_SEED_OTSK);

    let derived_seed = blake2s_hash(&derivation_input);
    let mut key_seed = [0u8; 32];
    key_seed.copy_from_slice(&derived_seed[..32]);

    let (ots_pk, ots_sk) = KeyPair::derive_ots_keypair_from_seed(&key_seed)?;

    let one_time_pubkey = PublicKey::dilithium2(ots_pk);
    let mut spend_key = ots_sk;
    spend_key.extend_from_slice(&kyber_ct);

    Ok((one_time_pubkey, spend_key))
}

pub fn create_authenticated_transcript(handshake_data: &[Vec<u8>]) -> Vec<u8> {
    let mut combined = Vec::new();
    for data in handshake_data {
        combined.extend_from_slice(data);
    }
    blake2s_hash(&combined)
}

pub fn verify_downgrade_protection(
    _transcript_hash: &[u8],
    pq_required: bool,
    peer_supports_pq: bool,
) -> EgoResult<bool> {
    if pq_required && !peer_supports_pq {
        return Err(EgoError::CryptoError(
            "Downgrade attack detected: PQ required but peer doesn't support it".to_string(),
        ));
    }

    Ok(true)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleNode {
    pub hash: Hash,
    pub left: Option<Box<MerkleNode>>,
    pub right: Option<Box<MerkleNode>>,
}

impl MerkleNode {
    pub fn leaf(data: &[u8]) -> Self {
        Self {
            hash: hash_data(data),
            left: None,
            right: None,
        }
    }

    pub fn internal(left: MerkleNode, right: MerkleNode) -> Self {
        let hash = hash_multiple(&[left.hash.as_bytes(), right.hash.as_bytes()]);
        Self {
            hash,
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
        }
    }

    pub fn hash(&self) -> Hash {
        self.hash
    }

    pub fn is_leaf(&self) -> bool {
        self.left.is_none() && self.right.is_none()
    }
}

#[derive(Debug, Clone)]
pub struct MerkleTree {
    root: Option<MerkleNode>,
    leaves: Vec<Vec<u8>>,
}

impl MerkleTree {
    pub fn build(items: Vec<Vec<u8>>) -> Self {
        if items.is_empty() {
            return Self {
                root: None,
                leaves: items,
            };
        }

        let mut nodes: Vec<MerkleNode> = items.iter().map(|data| MerkleNode::leaf(data)).collect();

        while nodes.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in nodes.chunks(2) {
                if chunk.len() == 2 {
                    let left = chunk[0].clone();
                    let right = chunk[1].clone();
                    next_level.push(MerkleNode::internal(left, right));
                } else {
                    let node = chunk[0].clone();
                    let duplicate = node.clone();
                    next_level.push(MerkleNode::internal(node, duplicate));
                }
            }

            nodes = next_level;
        }

        Self {
            root: nodes.into_iter().next(),
            leaves: items,
        }
    }

    pub fn root_hash(&self) -> Option<Hash> {
        self.root.as_ref().map(|node| node.hash)
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Generate an inclusion proof for the leaf at `leaf_index`.
    /// Returns `None` if the index is out of bounds or the tree is empty.
    pub fn generate_proof(&self, leaf_index: usize) -> Option<MerkleProof> {
        if self.leaves.is_empty() || leaf_index >= self.leaves.len() {
            return None;
        }

        let leaf_hash = hash_data(&self.leaves[leaf_index]);
        let tree_size = self.leaves.len();

        // Rebuild the level-by-level hash list so we can walk sibling paths.
        // Level 0 = leaf hashes; each subsequent level halves the count.
        let mut levels: Vec<Vec<Hash>> = Vec::new();
        let leaf_level: Vec<Hash> = self
            .leaves
            .iter()
            .map(|data| hash_data(data))
            .collect();
        levels.push(leaf_level);

        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let mut next = Vec::new();
            for chunk in prev.chunks(2) {
                if chunk.len() == 2 {
                    next.push(hash_multiple(&[chunk[0].as_bytes(), chunk[1].as_bytes()]));
                } else {
                    // Odd node: duplicated (mirrors MerkleNode::internal logic)
                    next.push(hash_multiple(&[chunk[0].as_bytes(), chunk[0].as_bytes()]));
                }
            }
            levels.push(next);
        }

        // Collect one sibling hash per level (bottom-up, excluding root level).
        let mut proof_hashes = Vec::new();
        let mut idx = leaf_index;
        for level in levels.iter().take(levels.len() - 1) {
            let sibling_idx = if idx % 2 == 0 {
                // Right sibling; if it doesn't exist the node was duplicated.
                (idx + 1).min(level.len() - 1)
            } else {
                idx - 1
            };
            proof_hashes.push(level[sibling_idx]);
            idx /= 2;
        }

        Some(MerkleProof {
            leaf_index,
            leaf_hash,
            proof_hashes,
            tree_size,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub leaf_hash: Hash,
    pub proof_hashes: Vec<Hash>,
    pub tree_size: usize,
}

impl MerkleProof {
    pub fn verify(&self, root_hash: Hash) -> EgoResult<bool> {
        if self.proof_hashes.is_empty() && self.tree_size == 1 {
            return Ok(self.leaf_hash == root_hash);
        }

        let mut current_hash = self.leaf_hash;
        let mut index = self.leaf_index;

        for proof_hash in &self.proof_hashes {
            if index % 2 == 0 {
                current_hash = hash_multiple(&[current_hash.as_bytes(), proof_hash.as_bytes()]);
            } else {
                current_hash = hash_multiple(&[proof_hash.as_bytes(), current_hash.as_bytes()]);
            }
            index /= 2;
        }

        Ok(current_hash == root_hash)
    }
}

fn derive_dilithium_keypair() -> EgoResult<(Vec<u8>, Vec<u8>)> {
    let (pk, sk) = dilithium2::keypair();
    Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
}

fn derive_kyber_keypair() -> EgoResult<(Vec<u8>, Vec<u8>)> {
    let (pk, sk) = kyber768::keypair();
    Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
}

fn derive_slh_dsa_keypair() -> EgoResult<(Vec<u8>, Vec<u8>)> {
    let (pk, sk): (sphincssha256128ssimple::PublicKey, sphincssha256128ssimple::SecretKey) = sphincssha256128ssimple::keypair();
    Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
}

pub fn dilithium_sign(secret_key: &[u8], message: &[u8]) -> EgoResult<Vec<u8>> {
    let sk = dilithium2::SecretKey::from_bytes(secret_key)
        .map_err(|_| EgoError::CryptoError("Invalid Dilithium2 secret key".to_string()))?;
    let sig = dilithium2::detached_sign(message, &sk);
    Ok(sig.as_bytes().to_vec())
}

pub fn dilithium_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> EgoResult<bool> {
    let pk = dilithium2::PublicKey::from_bytes(public_key)
        .map_err(|_| EgoError::CryptoError("Invalid Dilithium2 public key".to_string()))?;
    let sig = dilithium2::DetachedSignature::from_bytes(signature)
        .map_err(|_| EgoError::CryptoError("Invalid Dilithium2 signature".to_string()))?;
    match dilithium2::verify_detached_signature(&sig, message, &pk) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

fn slh_dsa_sign(secret_key: &[u8], message: &[u8]) -> EgoResult<Vec<u8>> {
    let sk = sphincssha256128ssimple::SecretKey::from_bytes(secret_key)
        .map_err(|_| EgoError::CryptoError("Invalid SPHINCS+ secret key".to_string()))?;
    let sig = sphincssha256128ssimple::detached_sign(message, &sk);
    Ok(sig.as_bytes().to_vec())
}

fn slh_dsa_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> EgoResult<bool> {
    let pk = sphincssha256128ssimple::PublicKey::from_bytes(public_key)
        .map_err(|_| EgoError::CryptoError("Invalid SPHINCS+ public key".to_string()))?;
    let sig = sphincssha256128ssimple::DetachedSignature::from_bytes(signature)
        .map_err(|_| EgoError::CryptoError("Invalid SPHINCS+ signature".to_string()))?;
    match sphincssha256128ssimple::verify_detached_signature(&sig, message, &pk) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

fn kyber_encapsulate(public_key: &[u8]) -> EgoResult<(Vec<u8>, Vec<u8>)> {
    let pk = kyber768::PublicKey::from_bytes(public_key)
        .map_err(|_| EgoError::CryptoError("Invalid Kyber768 public key".to_string()))?;
    let (ct, ss) = kyber768::encapsulate(&pk);
    Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
}

fn kyber_decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> EgoResult<Vec<u8>> {
    let sk = kyber768::SecretKey::from_bytes(secret_key)
        .map_err(|_| EgoError::CryptoError("Invalid Kyber768 secret key".to_string()))?;
    let ct = kyber768::Ciphertext::from_bytes(ciphertext)
        .map_err(|_| EgoError::CryptoError("Invalid Kyber768 ciphertext".to_string()))?;
    let ss = kyber768::decapsulate(&ct, &sk);
    Ok(ss.as_bytes().to_vec())
}
