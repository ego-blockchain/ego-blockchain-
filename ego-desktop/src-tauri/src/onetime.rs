use ego_core::KeyPair;
use serde::{Deserialize, Serialize};


const DERIVATION_DOMAIN: &[u8] = b"ego/onetime/v1";

/// How many unused addresses a wallet keeps ready to hand out.
pub const DEFAULT_BATCH: u32 = 32;

pub const SCAN_GAP: u32 = 64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OneTimeAddress {
    pub index: u32,
    pub address: String,
}

fn child_seed(master: &[u8; 32], index: u32) -> [u8; 32] {
    let mut input = Vec::with_capacity(DERIVATION_DOMAIN.len() + 32 + 4);
    input.extend_from_slice(DERIVATION_DOMAIN);
    input.extend_from_slice(master);
    input.extend_from_slice(&index.to_le_bytes());
    let digest = ego_core::hash_data(&input);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest.as_bytes()[..32]);
    seed
}

pub fn keypair_at(master: &[u8; 32], index: u32) -> Result<KeyPair, String> {
    KeyPair::from_bytes(&child_seed(master, index)).map_err(|e| e.to_string())
}

fn hrp() -> &'static str {
    if crate::tokenomics::CHAIN_ID == 1 { "egot" } else { "ego" }
}

pub fn address_at(master: &[u8; 32], index: u32) -> Result<String, String> {
    let kp = keypair_at(master, index)?;
    ego_core::EgoAddress::from_public_key_bytes(
        kp.ed25519_public_key().as_bytes(),
        crate::tokenomics::CHAIN_ID as u32,
        ego_core::AddressType::EOA,
    )
    .to_bech32(hrp())
    .map_err(|e| e.to_string())
}

/// A batch of fresh addresses to hand to one payer.
pub fn batch(master: &[u8; 32], start: u32, count: u32) -> Result<Vec<OneTimeAddress>, String> {
    (start..start.saturating_add(count))
        .map(|index| Ok(OneTimeAddress { index, address: address_at(master, index)? }))
        .collect()
}

pub fn watch_list(master: &[u8; 32], highest_used: u32) -> Result<Vec<OneTimeAddress>, String> {
    batch(master, 0, highest_used.saturating_add(SCAN_GAP))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: [u8; 32] = [7u8; 32];
    const OTHER: [u8; 32] = [9u8; 32];

    #[test]
    fn the_same_seed_and_index_always_give_the_same_address() {
        // The wallet must find its own money again after a restart or a restore
        // from the recovery phrase.
        let a = address_at(&MASTER, 5).unwrap();
        let b = address_at(&MASTER, 5).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn every_index_gives_a_different_address() {
        let mut seen = std::collections::HashSet::new();
        for i in 0..64 {
            assert!(seen.insert(address_at(&MASTER, i).unwrap()), "index {i} repeated an address");
        }
    }

    #[test]
    fn a_different_wallet_never_derives_the_same_address() {
        for i in 0..16 {
            assert_ne!(address_at(&MASTER, i).unwrap(), address_at(&OTHER, i).unwrap());
        }
    }

    /// The whole point: an observer holding one address learns nothing about the
    /// next, so payments cannot be linked to each other or to a person.
    #[test]
    fn one_address_reveals_nothing_about_the_others() {
        let first = address_at(&MASTER, 0).unwrap();
        let second = address_at(&MASTER, 1).unwrap();
        assert_ne!(first, second);
        // No shared structure beyond the human-readable prefix every Ego address has.
        let prefix = hrp();
        let a = first.trim_start_matches(prefix);
        let b = second.trim_start_matches(prefix);
        let shared = a.chars().zip(b.chars()).take_while(|(x, y)| x == y).count();
        assert!(shared < 8, "addresses share a {shared} character prefix, which links them");
    }

    #[test]
    fn a_one_time_address_is_not_the_wallets_main_address() {
        // Domain separation: reusing the master seed directly would defeat the
        // entire feature by paying to the address everyone already knows.
        let kp = KeyPair::from_bytes(&MASTER).unwrap();
        let main = ego_core::EgoAddress::from_public_key_bytes(
            kp.ed25519_public_key().as_bytes(),
            crate::tokenomics::CHAIN_ID as u32,
            ego_core::AddressType::EOA,
        )
        .to_bech32(hrp())
        .unwrap();
        for i in 0..16 {
            assert_ne!(address_at(&MASTER, i).unwrap(), main);
        }
    }

    /// The address must be the one the chain derives from the same key, or a
    /// payment into it could never be spent back out.
    #[test]
    fn the_address_matches_how_the_chain_derives_it() {
        let kp = keypair_at(&MASTER, 3).unwrap();
        let expected = ego_core::EgoAddress::from_public_key_bytes(
            kp.ed25519_public_key().as_bytes(),
            crate::tokenomics::CHAIN_ID as u32,
            ego_core::AddressType::EOA,
        )
        .to_bech32(hrp())
        .unwrap();
        assert_eq!(address_at(&MASTER, 3).unwrap(), expected);
    }

    #[test]
    fn the_scan_window_reaches_past_unused_addresses() {
        // A payer given thirty-two addresses may use only the last one.
        let list = watch_list(&MASTER, 0).unwrap();
        assert!(list.len() as u32 >= DEFAULT_BATCH, "a whole handed-out batch must be watched");
        assert!(list.len() as u32 >= SCAN_GAP);
    }

    #[test]
    fn a_batch_starts_where_the_last_one_ended() {
        let first = batch(&MASTER, 0, 4).unwrap();
        let second = batch(&MASTER, 4, 4).unwrap();
        assert_eq!(first.last().unwrap().index, 3);
        assert_eq!(second.first().unwrap().index, 4);
        for a in &first {
            assert!(!second.iter().any(|b| b.address == a.address), "batches must not overlap");
        }
    }
}
