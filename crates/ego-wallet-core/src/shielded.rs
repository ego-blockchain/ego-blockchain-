//! Shielded EGOC, as Ego Desktop's shielded.rs and shielded_chain.rs do it:
//! notes of fixed sizes derived from the seed, deposited with a
//! "shield:<commitment>" memo, and withdrawn with a STARK proof (ego-stark)
//! against the pool's leaves, in an unsigned "unshield" transaction.
//!
//! The phone derives its notes under its own domain, "ios", the way the
//! browser extension uses "ext", so two devices never pick the same note; it
//! scans every domain so it sees the whole shielded balance.

use blake2::{Blake2s256, Digest as _};
use ego_stark::merkle::MerkleTree;
use ego_stark::prove::{default_options, prove_withdrawal};
use ego_stark::{digest_from_bytes, digest_to_bytes, Digest};
use serde::{Deserialize, Serialize};

pub use ego_stark::air::POOL_TREE_DEPTH;

pub const POOL_ADDRESS: &str = "egot1shieldedpool000000000000000000000000000";
pub const TX_SHIELD: &str = "shield";
pub const TX_UNSHIELD: &str = "unshield";
pub const MAX_UNSHIELD_SPENDS: usize = 16;
pub const PHONE_DOMAIN: &str = "ios";
/// Every device's notes: Ego Desktop's, the browser extension's and the phone's.
pub const DOMAINS: [&str; 3] = ["desktop", "ext", PHONE_DOMAIN];
pub const DENOMINATIONS_UEGOC: [u64; 5] = [1_000_000, 10_000_000, 100_000_000, 1_000_000_000, 10_000_000_000];

pub fn denominate(amount_uegoc: u64) -> (Vec<u64>, u64) {
    let mut notes = Vec::new();
    let mut left = amount_uegoc;
    for d in DENOMINATIONS_UEGOC.iter().rev() {
        while left >= *d {
            notes.push(*d);
            left -= d;
        }
    }
    (notes, left)
}

fn blake2s(data: &[u8]) -> [u8; 32] {
    Blake2s256::digest(data).into()
}

fn to_digest(bytes: &[u8; 32]) -> Result<Digest, String> {
    digest_from_bytes(bytes).ok_or_else(|| "not a canonical field digest".to_string())
}

fn from_digest(d: &Digest) -> [u8; 32] {
    digest_to_bytes(d)
}

pub fn derive_note(seed: &[u8], domain: &str, index: u32, value_uegoc: u64) -> ego_stark::Note {
    let part = |role: &str| -> [u8; 32] {
        let mut material = format!("ego/shielded-note/v1/{domain}/{role}:").into_bytes();
        material.extend_from_slice(seed);
        material.extend_from_slice(&index.to_le_bytes());
        blake2s(&material)
    };
    ego_stark::Note { value_uegoc, owner_secret: part("secret"), rho: part("rho") }
}

/// A note's commitment and nullifier; neither depends on its value.
pub fn note_ids(seed: &[u8], domain: &str, index: u32) -> Result<([u8; 32], [u8; 32]), String> {
    let note = derive_note(seed, domain, index, DENOMINATIONS_UEGOC[0]);
    Ok((from_digest(&note.commitment().map_err(|e| format!("{e:?}"))?), from_digest(&note.nullifier())))
}

/// The value a deposited note holds, read from its leaf.
pub fn value_of(commitment: &[u8; 32], leaf: &[u8; 32]) -> Option<u64> {
    let c = to_digest(commitment).ok()?;
    DENOMINATIONS_UEGOC
        .into_iter()
        .find(|v| ego_stark::note::leaf_for(&c, *v).map(|l| from_digest(&l) == *leaf).unwrap_or(false))
}

pub fn shield_memo(commitment: &[u8; 32]) -> String {
    format!("shield:{}", hex::encode(commitment))
}

pub fn recipient_digest(address: &str) -> [u8; 32] {
    blake2s(address.as_bytes())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnshieldSpend {
    pub root: String,
    pub nullifier: String,
    pub amount_uegoc: u64,
    pub fee_uegoc: u64,
    pub proof: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnshieldBody {
    pub spends: Vec<UnshieldSpend>,
    pub recipient: String,
    pub amount_uegoc: u64,
    pub fee_uegoc: u64,
}

impl UnshieldBody {
    pub fn canonical_json(&self) -> String {
        serde_json::to_string(self).expect("a struct of strings and integers")
    }

    pub fn tx_hash(&self) -> String {
        let mut m = b"ego/unshield/v1:".to_vec();
        m.extend_from_slice(self.canonical_json().as_bytes());
        format!("0x{}", hex::encode(blake2s(&m)))
    }
}

/// A note to spend: which domain and index derived it, its value, and where its leaf is.
#[derive(Debug, Clone, Deserialize)]
pub struct Spend {
    pub domain: String,
    pub index: u32,
    pub value_uegoc: u64,
    pub leaf_index: usize,
}

/// Proves each spend against the pool's leaves and builds the withdrawal,
/// splitting the fee across the spends as Ego Desktop does.
pub fn unshield(seed: &[u8], leaves: &[[u8; 32]], spends: &[Spend], recipient: &str, total_fee: u64) -> Result<UnshieldBody, String> {
    if spends.is_empty() || spends.len() > MAX_UNSHIELD_SPENDS {
        return Err(format!("A withdrawal spends between 1 and {MAX_UNSHIELD_SPENDS} notes."));
    }
    if spends.iter().any(|s| !DOMAINS.contains(&s.domain.as_str())) {
        return Err("Unknown note domain.".into());
    }
    let mut tree = MerkleTree::new(POOL_TREE_DEPTH);
    for leaf in leaves {
        tree.insert(to_digest(leaf)?)?;
    }
    let rd = recipient_digest(recipient);
    let n = spends.len() as u64;
    let (base, remainder) = (total_fee / n, total_fee % n);
    let mut out = Vec::with_capacity(spends.len());
    for (i, s) in spends.iter().enumerate() {
        let note = derive_note(seed, &s.domain, s.index, s.value_uegoc);
        let leaf = from_digest(&note.leaf().map_err(|e| format!("{e:?}"))?);
        if leaves.get(s.leaf_index) != Some(&leaf) {
            return Err("A note isn't in the pool where expected; refresh and try again.".into());
        }
        let share = base + u64::from((i as u64) < remainder);
        let path = tree.path(s.leaf_index)?;
        let w = prove_withdrawal(&note, &path, &rd, share, default_options())?;
        out.push(UnshieldSpend {
            root: hex::encode(from_digest(&w.public.root)),
            nullifier: hex::encode(from_digest(&w.public.nullifier)),
            amount_uegoc: w.public.amount,
            fee_uegoc: share,
            proof: hex::encode(w.proof.to_bytes()),
        });
    }
    let amount: u64 = out.iter().map(|s| s.amount_uegoc).sum();
    Ok(UnshieldBody { spends: out, recipient: recipient.to_string(), amount_uegoc: amount, fee_uegoc: total_fee })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_stark::prove::verify_withdrawal;

    #[test]
    fn amounts_split_into_fixed_notes() {
        assert_eq!(denominate(12_500_000), (vec![10_000_000, 1_000_000, 1_000_000], 500_000));
        assert_eq!(denominate(999_999), (vec![], 999_999));
    }

    #[test]
    fn notes_differ_by_domain_and_index_and_their_value_reads_back_from_the_leaf() {
        let seed = [7u8; 32];
        let (c_ios, _) = note_ids(&seed, "ios", 0).unwrap();
        let (c_desktop, _) = note_ids(&seed, "desktop", 0).unwrap();
        let (c_ios1, _) = note_ids(&seed, "ios", 1).unwrap();
        assert_ne!(c_ios, c_desktop);
        assert_ne!(c_ios, c_ios1);
        let note = derive_note(&seed, "ios", 0, 100_000_000);
        let leaf = from_digest(&note.leaf().unwrap());
        assert_eq!(value_of(&c_ios, &leaf), Some(100_000_000));
        assert_eq!(value_of(&c_desktop, &leaf), None);
        assert_eq!(shield_memo(&c_ios), format!("shield:{}", hex::encode(c_ios)));
    }

    #[test]
    fn a_withdrawal_proves_and_verifies_against_the_pool() {
        let seed = [7u8; 32];
        let other = derive_note(&[9u8; 32], "desktop", 0, 1_000_000);
        let mine = derive_note(&seed, "ios", 2, 10_000_000);
        let leaves = vec![from_digest(&other.leaf().unwrap()), from_digest(&mine.leaf().unwrap())];
        let body = unshield(&seed, &leaves, &[Spend { domain: "ios".into(), index: 2, value_uegoc: 10_000_000, leaf_index: 1 }], "egot1someone", 1_000).unwrap();
        assert_eq!(body.amount_uegoc, 10_000_000);
        assert_eq!(body.spends[0].nullifier, hex::encode(from_digest(&mine.nullifier())));
        assert!(body.tx_hash().starts_with("0x") && body.tx_hash().len() == 66);
        let json = body.canonical_json();
        assert!(json.starts_with(r#"{"spends":[{"root":"#), "field order is Ego Desktop's");
        // The proof verifies as a validator would check it.
        let spend = &body.spends[0];
        let public = ego_stark::air::PublicInputs {
            root: to_digest(&hex::decode(&spend.root).unwrap().try_into().unwrap()).unwrap(),
            nullifier: mine.nullifier(),
            amount: 10_000_000,
            binding: ego_stark::note::withdrawal_binding(&recipient_digest("egot1someone"), 1_000).unwrap(),
        };
        let proof = winterfell::Proof::from_bytes(&hex::decode(&spend.proof).unwrap()).unwrap();
        verify_withdrawal(proof, public, &default_options()).expect("proof verifies");
        assert!(unshield(&seed, &leaves, &[Spend { domain: "ios".into(), index: 2, value_uegoc: 10_000_000, leaf_index: 0 }], "egot1someone", 1_000).is_err(), "wrong leaf");
    }
}
