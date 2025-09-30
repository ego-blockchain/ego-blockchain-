use crate::{
    AlgorithmId, DualSignature, EgoError, EgoResult, HandshakeInit, Hash, PeerCapabilities,
    PublicKey, SessionRecord, Signature,
};
use blake2::{Blake2s256, Digest};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::PublicKey as X25519PublicKey;
use zeroize::Zeroize;

const ML_KEM_768_PUBLIC_KEY_SIZE: usize = 1184;
const ML_KEM_768_SECRET_KEY_SIZE: usize = 2400;
const ML_KEM_768_CIPHERTEXT_SIZE: usize = 1088;
const ML_KEM_768_SHARED_SECRET_SIZE: usize = 32;

const ML_DSA_2_PUBLIC_KEY_SIZE: usize = 1312;
const ML_DSA_2_SECRET_KEY_SIZE: usize = 2528;
const ML_DSA_2_SIGNATURE_SIZE: usize = 2420;

const SLH_DSA_SIGNATURE_MIN_SIZE: usize = 8192;
const SLH_DSA_SIGNATURE_MAX_SIZE: usize = 17408;

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
}

impl Zeroize for KeyPair {
    fn zeroize(&mut self) {
        self.dilithium_pk.zeroize();
        self.dilithium_sk.zeroize();
        self.kyber_pk.zeroize();
        self.kyber_sk.zeroize();
        self.x25519_secret.zeroize();
        if let Some(ref mut pk) = self.slh_dsa_pk {
            pk.zeroize();
        }
        if let Some(ref mut sk) = self.slh_dsa_sk {
            sk.zeroize();
        }
        self.seed.zeroize();
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl KeyPair {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(seed)
    }

    pub fn generate_with_slh_dsa() -> Self {
        let mut keypair = Self::generate();
        let (slh_pk, slh_sk) = derive_slh_dsa_keypair_from_seed(&keypair.seed);
        keypair.slh_dsa_pk = Some(slh_pk);
        keypair.slh_dsa_sk = Some(slh_sk);
        keypair
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> EgoResult<Self> {
        Ok(Self::from_seed(*bytes))
    }

    fn from_seed(seed: [u8; 32]) -> Self {
        let ed25519_signing_key = SigningKey::from_bytes(&seed);
        let ed25519_verifying_key = ed25519_signing_key.verifying_key();

        let (dilithium_pk, dilithium_sk) = derive_dilithium_keypair_from_seed(&seed);
        let (kyber_pk, kyber_sk) = derive_kyber_keypair_from_seed(&seed);

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
        }
    }

    pub fn public_key(&self) -> PublicKey {
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
        PeerCapabilities {
            alg_sig_supported: vec![AlgorithmId::MlDsa2.as_u16(), AlgorithmId::Ed25519.as_u16()],
            alg_kem_supported: vec![AlgorithmId::MlKem768.as_u16()],
            pq_required: false,
            mlkem_pk: self.kyber_pk.clone(),
            x25519_pk: Some(self.x25519_public_key()),
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
        let signature = self.ed25519_signing_key.sign(message);
        Signature::ed25519(signature.to_bytes())
    }

    pub fn sign_dilithium(&self, message: &[u8]) -> Signature {
        let signature_data = mock_dilithium_sign(&self.seed, message);
        Signature::dilithium2(signature_data)
    }

    pub fn sign_ed25519(&self, message: &[u8]) -> Signature {
        let signature = self.ed25519_signing_key.sign(message);
        Signature::ed25519(signature.to_bytes())
    }

    pub fn sign_slh_dsa(&self, message: &[u8]) -> EgoResult<Signature> {
        if let Some(_) = &self.slh_dsa_sk {
            let signature_data = mock_slh_dsa_sign(&self.seed, message);
            Ok(Signature::slh_dsa(signature_data))
        } else {
            Err(EgoError::CryptoError(
                "SLH-DSA keys not available".to_string(),
            ))
        }
    }

    pub fn dual_sign(&self, message: &[u8]) -> DualSignature {
        let ed25519_sig = self.sign_ed25519(message);
        let dilithium_sig = self.sign_dilithium(message);
        DualSignature::hybrid(ed25519_sig, dilithium_sig)
    }

    pub fn sign_hybrid(&self, message: &[u8], transition_mode: bool) -> DualSignature {
        if transition_mode {
            self.dual_sign(message)
        } else {
            DualSignature::dilithium_only(self.sign_dilithium(message))
        }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.seed
    }

    pub fn derive_session_key(&self, peer_public_key: &[u8], info: &[u8]) -> EgoResult<Vec<u8>> {
        let x25519_peer_pubkey =
            X25519PublicKey::from(<[u8; 32]>::try_from(peer_public_key).map_err(|_| {
                EgoError::CryptoError("Invalid X25519 public key length".to_string())
            })?);

        let shared_secret = x25519_dalek::x25519(self.x25519_secret, x25519_peer_pubkey.to_bytes());

        let hk = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut okm = [0u8; 32];
        hk.expand(info, &mut okm)
            .map_err(|e| EgoError::CryptoError(format!("HKDF expand failed: {}", e)))?;

        Ok(okm.to_vec())
    }

    pub fn encapsulate_kyber(&self, peer_kyber_pk: &[u8]) -> EgoResult<(Vec<u8>, Vec<u8>)> {
        mock_kyber_encapsulate(peer_kyber_pk, &self.seed)
    }

    pub fn decapsulate_kyber(&self, ciphertext: &[u8]) -> EgoResult<Vec<u8>> {
        mock_kyber_decapsulate(&self.seed, ciphertext)
    }

    pub fn create_hybrid_session(
        &self,
        peer_x25519_pk: &[u8],
        peer_kyber_pk: &[u8],
        stream_kind: &str,
        stream_nonce: &[u8; 32],
        chain_id: &[u8],
    ) -> EgoResult<(SessionRecord, Vec<u8>)> {
        let x25519_shared = self.derive_session_key(peer_x25519_pk, b"x25519_component")?;
        let (kyber_shared, kyber_ct) = self.encapsulate_kyber(peer_kyber_pk)?;

        let mut combined_secret = Vec::new();
        combined_secret.extend_from_slice(&kyber_shared);
        combined_secret.extend_from_slice(&x25519_shared);

        let salt = blake2s_hash_domain(&[b"ego/stream", stream_kind.as_bytes(), stream_nonce]);
        let session_key = hkdf_sha256(&combined_secret, &salt, chain_id, 32);

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
    ) -> EgoResult<(SessionRecord, Vec<u8>)> {
        let (kyber_shared, kyber_ct) = self.encapsulate_kyber(peer_kyber_pk)?;

        let salt = blake2s_hash_domain(&[b"ego/stream", stream_kind.as_bytes(), stream_nonce]);
        let session_key = hkdf_sha256(&kyber_shared, &salt, chain_id, 32);

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
        include_ed25519: bool,
    ) -> EgoResult<Vec<u8>> {
        let mut combined = peer_id.as_bytes().to_vec();
        combined.extend_from_slice(&self.kyber_pk);
        combined.extend_from_slice(caps);
        combined.extend_from_slice(chain_id);

        let mut nonce = [0u8; 32];
        let mut rng = OsRng;
        rng.fill_bytes(&mut nonce);
        combined.extend_from_slice(&nonce);

        let data_to_sign = blake2s_hash_domain(&[b"ego/peerbind", &combined]);

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
}

#[derive(Clone)]
pub struct StreamCipher {
    cipher: XChaCha20Poly1305,
    tx_counter: u64,
    rx_counter: u64,
    stream_id: Vec<u8>,
    chain_id: Vec<u8>,
    alg_ids: (u16, u16),
}

impl std::fmt::Debug for StreamCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamCipher")
            .field("tx_counter", &self.tx_counter)
            .field("rx_counter", &self.rx_counter)
            .field("stream_id", &self.stream_id)
            .field("chain_id", &self.chain_id)
            .field("alg_ids", &self.alg_ids)
            .finish_non_exhaustive()
    }
}

impl StreamCipher {
    pub fn new(
        key: &[u8; 32],
        stream_id: Vec<u8>,
        chain_id: Vec<u8>,
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
            alg_ids,
        })
    }

    pub fn encrypt_frame(&mut self, plaintext: &[u8], direction: u8) -> EgoResult<Vec<u8>> {
        let mut nonce = [0u8; 24];
        let mut rng = OsRng;
        rng.fill_bytes(&mut nonce);

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

        self.tx_counter += 1;

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

        self.rx_counter += 1;
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

        Ok(blake2s_hash(&aad))
    }

    pub fn detect_duplicate_nonce(&self, _nonce: &[u8; 24], _counter: u64) -> bool {
        false
    }
}

#[derive(Debug, Clone)]
pub struct BatchVerifier {
    signatures: Vec<(PublicKey, Vec<u8>, Signature)>,
    max_batch_size: usize,
}

impl BatchVerifier {
    pub fn new(_cpu_budget: u64, max_batch_size: usize) -> Self {
        Self {
            signatures: Vec::new(),
            max_batch_size,
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
    mock_dilithium_verify(dilithium_pk, message, signature)
}

pub fn verify_slh_dsa_signature(
    slh_dsa_pk: &[u8],
    message: &[u8],
    signature: &[u8],
) -> EgoResult<bool> {
    mock_slh_dsa_verify(slh_dsa_pk, message, signature)
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
    hybrid_mode: bool,
) -> EgoResult<HandshakeInit> {
    let mut stream_nonce = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut stream_nonce);

    let (_, kyber_ct) = keypair.encapsulate_kyber(peer_kyber_pk)?;

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
    nonce: &[u8],
    signature: &[u8],
    dilithium_pk: &[u8],
    ed25519_pk: Option<&[u8]>,
) -> EgoResult<bool> {
    let mut combined = peer_id.as_bytes().to_vec();
    combined.extend_from_slice(mlkem_pk);
    combined.extend_from_slice(caps);
    combined.extend_from_slice(chain_id);
    combined.extend_from_slice(nonce);
    let data_to_verify = blake2s_hash_domain(&[b"ego/peerbind", &combined]);

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
    let (shared_secret, _) = mock_kyber_encapsulate(receiver_kyber_pk, sender_ephemeral)?;

    let mut derivation_input = shared_secret;
    derivation_input.extend_from_slice(sender_ephemeral);

    let derived_seed = blake2s_hash(&derivation_input);
    let mut key_seed = [0u8; 32];
    key_seed.copy_from_slice(&derived_seed[..32]);

    let one_time_keypair = KeyPair::from_bytes(&key_seed)?;
    let one_time_pubkey = one_time_keypair.public_key();

    let spend_key = one_time_keypair.to_bytes().to_vec();

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

fn derive_dilithium_keypair_from_seed(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let mut pk_combined = seed.to_vec();
    pk_combined.extend_from_slice(b"dilithium_pk_v1");
    let pk_hash = blake2s_hash(&pk_combined);

    let mut pk = vec![0u8; ML_DSA_2_PUBLIC_KEY_SIZE];
    let mut pk_seed = pk_hash;
    for i in 0..ML_DSA_2_PUBLIC_KEY_SIZE {
        if i > 0 && i % 32 == 0 {
            pk_seed = blake2s_hash(&pk_seed);
        }
        pk[i] = pk_seed[i % 32];
    }

    let mut pk_with_seed = pk.clone();
    pk_with_seed.extend_from_slice(seed);

    let mut sk_combined = seed.to_vec();
    sk_combined.extend_from_slice(b"dilithium_sk_v1");
    let sk_hash = blake2s_hash(&sk_combined);

    let mut sk = vec![0u8; ML_DSA_2_SECRET_KEY_SIZE];
    let mut sk_seed = sk_hash;
    for i in 0..ML_DSA_2_SECRET_KEY_SIZE {
        if i > 0 && i % 32 == 0 {
            sk_seed = blake2s_hash(&sk_seed);
        }
        sk[i] = sk_seed[i % 32];
    }

    (pk_with_seed, sk)
}

fn derive_kyber_keypair_from_seed(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let mut pk_combined = seed.to_vec();
    pk_combined.extend_from_slice(b"kyber_pk_v1");
    let pk_hash = blake2s_hash(&pk_combined);

    let mut pk = vec![0u8; ML_KEM_768_PUBLIC_KEY_SIZE];
    let mut pk_seed = pk_hash;
    for i in 0..ML_KEM_768_PUBLIC_KEY_SIZE {
        if i > 0 && i % 32 == 0 {
            pk_seed = blake2s_hash(&pk_seed);
        }
        pk[i] = pk_seed[i % 32];
    }

    let mut sk = seed.to_vec();
    sk.resize(ML_KEM_768_SECRET_KEY_SIZE, 0);

    (pk, sk)
}

fn derive_slh_dsa_keypair_from_seed(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let mut pk_combined = seed.to_vec();
    pk_combined.extend_from_slice(b"slhdsa_pk_v1");
    let pk_hash = blake2s_hash(&pk_combined);

    let mut pk = vec![0u8; 64];
    for i in 0..64 {
        pk[i] = pk_hash[i % pk_hash.len()];
    }

    let mut pk_with_seed = pk.clone();
    pk_with_seed.extend_from_slice(seed);

    let mut sk = seed.to_vec();
    sk.resize(128, 0);

    (pk_with_seed, sk)
}

fn mock_dilithium_sign(seed: &[u8; 32], message: &[u8]) -> Vec<u8> {
    let mut combined = Vec::new();
    combined.extend_from_slice(seed);
    combined.extend_from_slice(message);
    combined.extend_from_slice(b"ego/dilithium/v1");

    let hash = blake2s_hash(&combined);
    let mut signature = vec![0u8; ML_DSA_2_SIGNATURE_SIZE];
    let mut sig_seed = hash;

    for i in 0..ML_DSA_2_SIGNATURE_SIZE {
        if i > 0 && i % 32 == 0 {
            sig_seed = blake2s_hash(&sig_seed);
        }
        signature[i] = sig_seed[i % 32];
    }

    signature
}

fn mock_dilithium_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> EgoResult<bool> {
    if signature.len() != ML_DSA_2_SIGNATURE_SIZE {
        return Ok(false);
    }

    if public_key.len() < ML_DSA_2_PUBLIC_KEY_SIZE {
        return Ok(false);
    }

    let seed_start = public_key.len() - 32;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&public_key[seed_start..]);

    let expected_signature = mock_dilithium_sign(&seed, message);
    Ok(expected_signature == signature)
}

fn mock_slh_dsa_sign(seed: &[u8; 32], message: &[u8]) -> Vec<u8> {
    let mut combined = Vec::new();
    combined.extend_from_slice(seed);
    combined.extend_from_slice(message);
    combined.extend_from_slice(b"ego/slhdsa/v1");

    let hash = blake2s_hash(&combined);
    let mut signature = vec![0u8; SLH_DSA_SIGNATURE_MIN_SIZE];
    let mut sig_seed = hash;

    for i in 0..SLH_DSA_SIGNATURE_MIN_SIZE {
        if i > 0 && i % 32 == 0 {
            sig_seed = blake2s_hash(&sig_seed);
        }
        signature[i] = sig_seed[i % 32];
    }

    signature
}

fn mock_slh_dsa_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> EgoResult<bool> {
    if signature.len() < SLH_DSA_SIGNATURE_MIN_SIZE || signature.len() > SLH_DSA_SIGNATURE_MAX_SIZE
    {
        return Ok(false);
    }

    if public_key.len() < 64 {
        return Ok(false);
    }

    let seed_start = public_key.len() - 32;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&public_key[seed_start..]);

    let expected_signature = mock_slh_dsa_sign(&seed, message);
    Ok(expected_signature[..SLH_DSA_SIGNATURE_MIN_SIZE] == signature[..SLH_DSA_SIGNATURE_MIN_SIZE])
}

fn mock_kyber_encapsulate(
    public_key: &[u8],
    sender_seed: &[u8; 32],
) -> EgoResult<(Vec<u8>, Vec<u8>)> {
    if public_key.len() != ML_KEM_768_PUBLIC_KEY_SIZE {
        return Err(EgoError::CryptoError(
            "Invalid Kyber public key size".to_string(),
        ));
    }

    let mut shared_input = public_key.to_vec();
    shared_input.extend_from_slice(sender_seed);
    shared_input.extend_from_slice(b"ego/kyber/ss/v1");
    let shared_secret_hash = blake2s_hash(&shared_input);
    let shared_secret = shared_secret_hash[..ML_KEM_768_SHARED_SECRET_SIZE].to_vec();

    let pk_hash = blake2s_hash(public_key);
    let mut ciphertext = vec![0u8; ML_KEM_768_CIPHERTEXT_SIZE];

    for i in 0..32 {
        ciphertext[i] = sender_seed[i] ^ pk_hash[i];
    }

    let mut padding_seed = ciphertext[..32].to_vec();
    for i in 32..ML_KEM_768_CIPHERTEXT_SIZE {
        if i % 32 == 0 {
            padding_seed = blake2s_hash(&padding_seed);
        }
        ciphertext[i] = padding_seed[i % 32];
    }

    Ok((shared_secret, ciphertext))
}

fn mock_kyber_decapsulate(receiver_seed: &[u8; 32], ciphertext: &[u8]) -> EgoResult<Vec<u8>> {
    if ciphertext.len() != ML_KEM_768_CIPHERTEXT_SIZE {
        return Err(EgoError::CryptoError(
            "Invalid Kyber ciphertext size".to_string(),
        ));
    }

    let (receiver_pk, _) = derive_kyber_keypair_from_seed(receiver_seed);

    let pk_hash = blake2s_hash(&receiver_pk);
    let mut sender_seed = [0u8; 32];
    for i in 0..32 {
        sender_seed[i] = ciphertext[i] ^ pk_hash[i];
    }

    let mut shared_input = receiver_pk;
    shared_input.extend_from_slice(&sender_seed);
    shared_input.extend_from_slice(b"ego/kyber/ss/v1");
    let shared_secret_hash = blake2s_hash(&shared_input);

    Ok(shared_secret_hash[..ML_KEM_768_SHARED_SECRET_SIZE].to_vec())
}
