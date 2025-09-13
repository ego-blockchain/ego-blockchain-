use crate::{EgoError, EgoResult, Hash, PublicKey, Signature};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct KeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let verifying_key = signing_key.verifying_key();

        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> EgoResult<Self> {
        let signing_key = SigningKey::from_bytes(bytes);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::new(self.verifying_key.to_bytes())
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        let signature = self.signing_key.sign(message);
        Signature::new(signature.to_bytes())
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
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

pub fn hash_data(data: &[u8]) -> Hash {
    let hash = blake3::hash(data);
    Hash::new(*hash.as_bytes())
}

pub fn hash_multiple(pieces: &[&[u8]]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    for piece in pieces {
        hasher.update(piece);
    }
    let hash = hasher.finalize();
    Hash::new(*hash.as_bytes())
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
