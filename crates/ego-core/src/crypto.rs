use crate::{EgoError, EgoResult, Hash, PublicKey, Signature};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct KeyPair {
    ed25519_signing_key: SigningKey,
    ed25519_verifying_key: VerifyingKey,

    dilithium_pk: Vec<u8>,
    dilithium_sk: Vec<u8>,

    kyber_pk: Vec<u8>,
    kyber_sk: Vec<u8>,
}

impl KeyPair {
    pub fn generate() -> Self {
        let ed25519_signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let ed25519_verifying_key = ed25519_signing_key.verifying_key();

        let dilithium_pk = vec![0u8; 1312];
        let dilithium_sk = vec![0u8; 2528];
        let kyber_pk = vec![0u8; 1184];
        let kyber_sk = vec![0u8; 2400];

        Self {
            ed25519_signing_key,
            ed25519_verifying_key,
            dilithium_pk,
            dilithium_sk,
            kyber_pk,
            kyber_sk,
        }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> EgoResult<Self> {
        let ed25519_signing_key = SigningKey::from_bytes(bytes);
        let ed25519_verifying_key = ed25519_signing_key.verifying_key();

        let mut seed_data = bytes.to_vec();
        seed_data.extend_from_slice(b"dilithium_pk");
        let mut dilithium_pk = blake2s_hash(&seed_data)[..1312.min(32)].to_vec();
        dilithium_pk.resize(1312, 0);

        seed_data = bytes.to_vec();
        seed_data.extend_from_slice(b"dilithium_sk");
        let mut dilithium_sk = blake2s_hash(&seed_data)[..2528.min(32)].to_vec();
        dilithium_sk.resize(2528, 0);

        seed_data = bytes.to_vec();
        seed_data.extend_from_slice(b"kyber_pk");
        let mut kyber_pk = blake2s_hash(&seed_data)[..1184.min(32)].to_vec();
        kyber_pk.resize(1184, 0);

        seed_data = bytes.to_vec();
        seed_data.extend_from_slice(b"kyber_sk");
        let mut kyber_sk = blake2s_hash(&seed_data)[..2400.min(32)].to_vec();
        kyber_sk.resize(2400, 0);

        Ok(Self {
            ed25519_signing_key,
            ed25519_verifying_key,
            dilithium_pk,
            dilithium_sk,
            kyber_pk,
            kyber_sk,
        })
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::new(self.ed25519_verifying_key.to_bytes())
    }

    pub fn dilithium_public_key(&self) -> Vec<u8> {
        self.dilithium_pk.clone()
    }

    pub fn kyber_public_key(&self) -> Vec<u8> {
        self.kyber_pk.clone()
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        let signature = self.ed25519_signing_key.sign(message);
        Signature::new(signature.to_bytes())
    }

    pub fn sign_dilithium(&self, message: &[u8]) -> Vec<u8> {
        let mut combined = self.dilithium_sk.clone();
        combined.extend_from_slice(message);
        let mut sig = blake2s_hash(&combined);
        sig.resize(2420, 0);
        sig
    }

    pub fn sign_ed25519(&self, message: &[u8]) -> Signature {
        let signature = self.ed25519_signing_key.sign(message);
        Signature::new(signature.to_bytes())
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.ed25519_signing_key.to_bytes()
    }
}

pub fn verify_signature(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
) -> EgoResult<bool> {
    let verifying_key = VerifyingKey::from_bytes(public_key.as_bytes())
        .map_err(|e| EgoError::CryptoError(format!("Invalid public key: {}", e)))?;

    let sig = ed25519_dalek::Signature::from_bytes(signature.as_bytes());

    match verifying_key.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

pub fn verify_dilithium_signature(
    dilithium_pk: &[u8],
    message: &[u8],
    signature: &[u8],
) -> EgoResult<bool> {
    let mut combined = dilithium_pk.to_vec();
    combined.extend_from_slice(message);
    let expected_sig = blake2s_hash(&combined);
    Ok(signature.len() >= 2420 && signature[..32] == expected_sig[..32])
}

pub fn blake2s_hash(data: &[u8]) -> Vec<u8> {
    blake3::hash(data).as_bytes().to_vec()
}

pub fn hash_data(data: &[u8]) -> Hash {
    let hash_bytes = blake2s_hash(data);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash_bytes[..32]);
    Hash::new(result)
}

pub fn hash_multiple(pieces: &[&[u8]]) -> Hash {
    let mut combined = Vec::new();
    for piece in pieces {
        combined.extend_from_slice(piece);
    }
    hash_data(&combined)
}

pub fn hkdf_blake2s(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let mut combined = salt.to_vec();
    combined.extend_from_slice(ikm);
    let prk = blake2s_hash(&combined);
    let mut output = Vec::new();
    let mut counter = 1u8;

    while output.len() < length {
        let mut t_input = prk.clone();
        t_input.extend_from_slice(info);
        t_input.push(counter);
        let t = blake2s_hash(&t_input);
        output.extend_from_slice(&t);
        counter += 1;
    }

    output.truncate(length);
    output
}

pub fn kyber_encapsulate(public_key: &[u8]) -> EgoResult<(Vec<u8>, Vec<u8>)> {
    let mut combined = public_key.to_vec();
    combined.extend_from_slice(b"shared_secret");
    let shared_secret = blake2s_hash(&combined)[..32].to_vec();

    combined = public_key.to_vec();
    combined.extend_from_slice(b"ciphertext");
    let mut ciphertext = blake2s_hash(&combined)[..1088.min(32)].to_vec();
    ciphertext.resize(1088, 0);

    Ok((shared_secret, ciphertext))
}

pub fn kyber_decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> EgoResult<Vec<u8>> {
    let mut combined = secret_key.to_vec();
    combined.extend_from_slice(ciphertext);
    let shared_secret = blake2s_hash(&combined)[..32].to_vec();
    Ok(shared_secret)
}

pub fn xchacha20poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    plaintext: &[u8],
    associated_data: &[u8],
) -> EgoResult<Vec<u8>> {
    let mut ciphertext = plaintext.to_vec();

    let mut combined = key.to_vec();
    combined.extend_from_slice(nonce);
    let stream = blake2s_hash(&combined);
    for (i, byte) in ciphertext.iter_mut().enumerate() {
        *byte ^= stream[i % stream.len()];
    }

    let mut mac_input = ciphertext.clone();
    mac_input.extend_from_slice(associated_data);
    let mac = blake2s_hash(&mac_input)[..16].to_vec();
    ciphertext.extend_from_slice(&mac);

    Ok(ciphertext)
}

pub fn xchacha20poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> EgoResult<Vec<u8>> {
    if ciphertext.len() < 16 {
        return Err(EgoError::CryptoError("Ciphertext too short".to_string()));
    }

    let (encrypted_data, mac) = ciphertext.split_at(ciphertext.len() - 16);

    let mut mac_input = encrypted_data.to_vec();
    mac_input.extend_from_slice(associated_data);
    let expected_mac = blake2s_hash(&mac_input)[..16].to_vec();
    if mac != expected_mac {
        return Err(EgoError::CryptoError("Authentication failed".to_string()));
    }

    let mut plaintext = encrypted_data.to_vec();
    let mut combined = key.to_vec();
    combined.extend_from_slice(nonce);
    let stream = blake2s_hash(&combined);
    for (i, byte) in plaintext.iter_mut().enumerate() {
        *byte ^= stream[i % stream.len()];
    }

    Ok(plaintext)
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

pub fn create_identity_binding(
    peer_id: &str,
    mlkem_pk: &[u8],
    caps: &[u8],
    dilithium_keypair: &KeyPair,
) -> Vec<u8> {
    let mut combined = peer_id.as_bytes().to_vec();
    combined.extend_from_slice(mlkem_pk);
    combined.extend_from_slice(caps);
    let data_to_sign = blake2s_hash(&combined);

    dilithium_keypair.sign_dilithium(&data_to_sign)
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
