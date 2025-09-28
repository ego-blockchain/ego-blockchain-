use crate::{
    AlgorithmId, DualSignature, EgoError, EgoResult, Hash, PublicKey, SessionRecord, Signature,
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
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
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
}

impl Zeroize for KeyPair {
    fn zeroize(&mut self) {
        self.dilithium_pk.zeroize();
        self.dilithium_sk.zeroize();
        self.kyber_pk.zeroize();
        self.kyber_sk.zeroize();
        self.x25519_secret.zeroize();
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

        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);
        let ed25519_signing_key = SigningKey::from_bytes(&secret_bytes);
        let ed25519_verifying_key = ed25519_signing_key.verifying_key();

        let dilithium_pk = generate_dilithium_public_key();
        let dilithium_sk = generate_dilithium_secret_key();

        let kyber_pk = generate_kyber_public_key();
        let kyber_sk = generate_kyber_secret_key();

        let mut x25519_secret = [0u8; 32];
        rng.fill_bytes(&mut x25519_secret);
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
        }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> EgoResult<Self> {
        let ed25519_signing_key = SigningKey::from_bytes(bytes);
        let ed25519_verifying_key = ed25519_signing_key.verifying_key();

        let dilithium_pk = derive_dilithium_public_key_from_seed(bytes);
        let dilithium_sk = derive_dilithium_secret_key_from_seed(bytes);

        let kyber_pk = derive_kyber_public_key_from_seed(bytes);
        let kyber_sk = derive_kyber_secret_key_from_seed(bytes);

        let x25519_secret = *bytes;
        let x25519_public = X25519PublicKey::from(x25519_secret);

        Ok(Self {
            ed25519_signing_key,
            ed25519_verifying_key,
            dilithium_pk,
            dilithium_sk,
            kyber_pk,
            kyber_sk,
            x25519_secret,
            x25519_public,
        })
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::ed25519(self.ed25519_verifying_key.to_bytes())
    }

    pub fn dilithium_public_key(&self) -> PublicKey {
        PublicKey::dilithium2(&self.dilithium_pk)
    }

    pub fn kyber_public_key(&self) -> PublicKey {
        PublicKey::kyber768(&self.kyber_pk)
    }

    pub fn x25519_public_key(&self) -> Vec<u8> {
        self.x25519_public.as_bytes().to_vec()
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        let signature = self.ed25519_signing_key.sign(message);
        Signature::ed25519(signature.to_bytes())
    }

    pub fn sign_dilithium(&self, message: &[u8]) -> Signature {
        let signature_data = mock_dilithium_sign(&self.dilithium_sk, message);
        Signature::dilithium2(signature_data)
    }

    pub fn sign_ed25519(&self, message: &[u8]) -> Signature {
        let signature = self.ed25519_signing_key.sign(message);
        Signature::ed25519(signature.to_bytes())
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
        self.ed25519_signing_key.to_bytes()
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
        mock_kyber_encapsulate(peer_kyber_pk)
    }

    pub fn decapsulate_kyber(&self, ciphertext: &[u8]) -> EgoResult<Vec<u8>> {
        mock_kyber_decapsulate(&self.kyber_sk, ciphertext)
    }

    pub fn create_hybrid_session(
        &self,
        peer_x25519_pk: &[u8],
        peer_kyber_pk: &[u8],
        info: &[u8],
    ) -> EgoResult<(SessionRecord, Vec<u8>)> {
        let x25519_shared = self.derive_session_key(peer_x25519_pk, b"x25519_component")?;
        let (kyber_shared, kyber_ct) = self.encapsulate_kyber(peer_kyber_pk)?;

        let mut combined_secret = Vec::new();
        combined_secret.extend_from_slice(&x25519_shared);
        combined_secret.extend_from_slice(&kyber_shared);

        let session_key = hkdf_sha256(&combined_secret, b"hybrid_session", info, 32);

        let mut nonce = [0u8; 24];
        let mut rng = OsRng;
        rng.fill_bytes(&mut nonce);

        let session_record = SessionRecord::new(
            Some(self.x25519_public.as_bytes().to_vec()),
            kyber_ct,
            nonce,
            vec![],
        );

        Ok((session_record, session_key))
    }
}

pub fn verify_signature(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
) -> EgoResult<bool> {
    match (public_key.algorithm, signature.algorithm) {
        (AlgorithmId::Ed25519, AlgorithmId::Ed25519) => {
            let ed25519_pubkey = public_key
                .ed25519_bytes()
                .ok_or_else(|| EgoError::CryptoError("Invalid Ed25519 public key".to_string()))?;

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
        (AlgorithmId::MlDsa2, AlgorithmId::MlDsa2) => verify_dilithium_signature(
            &public_key.key_data.to_vec(),
            message,
            &signature.signature_data,
        ),
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

pub fn blake2s_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Blake2s256::new();
    hasher.update(data);
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
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .expect("HKDF expand should not fail");
    okm
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
    _associated_data: &[u8],
) -> EgoResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| EgoError::CryptoError(format!("Cipher initialization failed: {}", e)))?;

    let xnonce = XNonce::from_slice(nonce);

    cipher
        .encrypt(xnonce, plaintext)
        .map_err(|e| EgoError::CryptoError(format!("Encryption failed: {}", e)))
}

pub fn xchacha20poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
    _associated_data: &[u8],
) -> EgoResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| EgoError::CryptoError(format!("Cipher initialization failed: {}", e)))?;

    let xnonce = XNonce::from_slice(nonce);

    cipher
        .decrypt(xnonce, ciphertext)
        .map_err(|e| EgoError::CryptoError(format!("Decryption failed: {}", e)))
}

pub fn create_identity_binding(
    peer_id: &str,
    mlkem_pk: &[u8],
    caps: &[u8],
    keypair: &KeyPair,
) -> Vec<u8> {
    let mut combined = peer_id.as_bytes().to_vec();
    combined.extend_from_slice(mlkem_pk);
    combined.extend_from_slice(caps);
    let data_to_sign = blake2s_hash(&combined);

    keypair.sign_dilithium(&data_to_sign).signature_data
}

pub fn verify_identity_binding(
    peer_id: &str,
    mlkem_pk: &[u8],
    caps: &[u8],
    signature: &[u8],
    dilithium_pk: &[u8],
) -> EgoResult<bool> {
    let mut combined = peer_id.as_bytes().to_vec();
    combined.extend_from_slice(mlkem_pk);
    combined.extend_from_slice(caps);
    let data_to_verify = blake2s_hash(&combined);

    verify_dilithium_signature(dilithium_pk, &data_to_verify, signature)
}

pub fn derive_stealth_address(
    receiver_kyber_pk: &[u8],
    sender_ephemeral: &[u8; 32],
) -> EgoResult<(PublicKey, Vec<u8>)> {
    let (shared_secret, _) = mock_kyber_encapsulate(receiver_kyber_pk)?;

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

fn generate_dilithium_public_key() -> Vec<u8> {
    let mut pk = vec![0u8; ML_DSA_2_PUBLIC_KEY_SIZE];
    let mut rng = OsRng;
    rng.fill_bytes(&mut pk);
    pk
}

fn generate_dilithium_secret_key() -> Vec<u8> {
    let mut sk = vec![0u8; ML_DSA_2_SECRET_KEY_SIZE];
    let mut rng = OsRng;
    rng.fill_bytes(&mut sk);
    sk
}

fn generate_kyber_public_key() -> Vec<u8> {
    let mut pk = vec![0u8; ML_KEM_768_PUBLIC_KEY_SIZE];
    let mut rng = OsRng;
    rng.fill_bytes(&mut pk);
    pk
}

fn generate_kyber_secret_key() -> Vec<u8> {
    let mut sk = vec![0u8; ML_KEM_768_SECRET_KEY_SIZE];
    let mut rng = OsRng;
    rng.fill_bytes(&mut sk);
    sk
}

fn derive_dilithium_public_key_from_seed(seed: &[u8; 32]) -> Vec<u8> {
    let mut combined = seed.to_vec();
    combined.extend_from_slice(b"dilithium_pk_v1");
    let derived = blake2s_hash(&combined);

    let mut pk = vec![0u8; ML_DSA_2_PUBLIC_KEY_SIZE];
    for i in 0..ML_DSA_2_PUBLIC_KEY_SIZE {
        pk[i] = derived[i % derived.len()];
    }
    pk
}

fn derive_dilithium_secret_key_from_seed(seed: &[u8; 32]) -> Vec<u8> {
    let mut combined = seed.to_vec();
    combined.extend_from_slice(b"dilithium_sk_v1");
    let derived = blake2s_hash(&combined);

    let mut sk = vec![0u8; ML_DSA_2_SECRET_KEY_SIZE];
    for i in 0..ML_DSA_2_SECRET_KEY_SIZE {
        sk[i] = derived[i % derived.len()];
    }
    sk
}

fn derive_kyber_public_key_from_seed(seed: &[u8; 32]) -> Vec<u8> {
    let mut combined = seed.to_vec();
    combined.extend_from_slice(b"kyber_pk_v1");
    let derived = blake2s_hash(&combined);

    let mut pk = vec![0u8; ML_KEM_768_PUBLIC_KEY_SIZE];
    for i in 0..ML_KEM_768_PUBLIC_KEY_SIZE {
        pk[i] = derived[i % derived.len()];
    }
    pk
}

fn derive_kyber_secret_key_from_seed(seed: &[u8; 32]) -> Vec<u8> {
    let mut combined = seed.to_vec();
    combined.extend_from_slice(b"kyber_sk_v1");
    let derived = blake2s_hash(&combined);

    let mut sk = vec![0u8; ML_KEM_768_SECRET_KEY_SIZE];
    for i in 0..ML_KEM_768_SECRET_KEY_SIZE {
        sk[i] = derived[i % derived.len()];
    }
    sk
}

fn mock_dilithium_sign(secret_key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut combined = secret_key.to_vec();
    combined.extend_from_slice(message);
    combined.extend_from_slice(b"dilithium_sig_v1");

    let hash = blake2s_hash(&combined);
    let mut signature = vec![0u8; ML_DSA_2_SIGNATURE_SIZE];

    for i in 0..ML_DSA_2_SIGNATURE_SIZE {
        signature[i] = hash[i % hash.len()];
    }

    signature
}

fn mock_dilithium_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> EgoResult<bool> {
    if signature.len() != ML_DSA_2_SIGNATURE_SIZE {
        return Ok(false);
    }

    let mut combined = public_key.to_vec();
    combined.extend_from_slice(message);

    let pk_hash = blake2s_hash(&combined);
    let sig_hash = blake2s_hash(signature);

    Ok(pk_hash[..16] == sig_hash[..16])
}

fn mock_kyber_encapsulate(public_key: &[u8]) -> EgoResult<(Vec<u8>, Vec<u8>)> {
    if public_key.len() != ML_KEM_768_PUBLIC_KEY_SIZE {
        return Err(EgoError::CryptoError(
            "Invalid Kyber public key size".to_string(),
        ));
    }

    let mut shared_secret = vec![0u8; ML_KEM_768_SHARED_SECRET_SIZE];
    let mut rng = OsRng;
    rng.fill_bytes(&mut shared_secret);

    let mut combined = public_key.to_vec();
    combined.extend_from_slice(&shared_secret);
    combined.extend_from_slice(b"kyber_ct_v1");

    let ct_seed = blake2s_hash(&combined);
    let mut ciphertext = vec![0u8; ML_KEM_768_CIPHERTEXT_SIZE];

    for i in 0..ML_KEM_768_CIPHERTEXT_SIZE {
        ciphertext[i] = ct_seed[i % ct_seed.len()];
    }

    Ok((shared_secret, ciphertext))
}

fn mock_kyber_decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> EgoResult<Vec<u8>> {
    if secret_key.len() != ML_KEM_768_SECRET_KEY_SIZE {
        return Err(EgoError::CryptoError(
            "Invalid Kyber secret key size".to_string(),
        ));
    }

    if ciphertext.len() != ML_KEM_768_CIPHERTEXT_SIZE {
        return Err(EgoError::CryptoError(
            "Invalid Kyber ciphertext size".to_string(),
        ));
    }

    let mut combined = secret_key.to_vec();
    combined.extend_from_slice(ciphertext);
    combined.extend_from_slice(b"kyber_shared_v1");

    let shared_secret = blake2s_hash(&combined);
    Ok(shared_secret[..ML_KEM_768_SHARED_SECRET_SIZE].to_vec())
}
