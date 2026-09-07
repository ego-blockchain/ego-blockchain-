use ego_core::KeyPair;
use serde::{Deserialize, Serialize};

/// One-time receiving addresses derived from the wallet's own seed.
///
/// The privacy here does not come from hiding anything. Every payment is on the
/// chain in full view, with the address, the amount and the sender all readable
/// by anyone. It comes from the address meaning nothing: it is used once, never
/// again, and nothing on the chain ties it to a person.
///
/// That is the opposite of the is_private flag, which leaves the data in the
/// chain and asks Ego's own UI not to display it. Anyone reading the chain by
/// another route sees straight through that. Nobody sees through this, because
/// there is nothing to see through.
///
/// The receiver derives these from their seed, so they hold every private key
/// and can spend normally. The sender is simply told an address, which is why
/// this needs no new cryptography, no consensus change, and cannot affect what
/// a validator checks. Coins cannot be forged through a feature that changes
/// nothing about validation.
///
/// The limit is real and worth stating: the addresses have to reach the payer
/// over a channel an observer cannot read, which means somebody you have
/// exchanged contact keys with. Publishing a batch openly would defeat it, as
/// an observer would see a payment land on an address from your published list
/// and the link is back.
const DERIVATION_DOMAIN: &[u8] = b"ego/onetime/v1";

/// How many unused addresses a wallet keeps ready to hand out.
pub const DEFAULT_BATCH: u32 = 32;

/// How far past the last used index to keep scanning for payments.
///
/// A payer may use any address they were given, in any order, or never use some
/// at all, so scanning must not stop at the first gap.
pub const SCAN_GAP: u32 = 64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OneTimeAddress {
    pub index: u32,
    pub address: String,
}

/// Deterministically derive the seed for one-time address `index`.
///
/// Domain-separated so a one-time key can never collide with the wallet's main
/// key or with any other seed-derived material added later.
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

/// The keypair for one-time address `index`. The caller can sign with it, so a
/// payment received here is spendable exactly like any other.
pub fn keypair_at(master: &[u8; 32], index: u32) -> Result<KeyPair, String> {
    KeyPair::from_bytes(&child_seed(master, index)).map_err(|e| e.to_string())
}

/// Human-readable prefix for the chain we are on, matching verify_incoming_tx.
fn hrp() -> &'static str {
    if crate::tokenomics::CHAIN_ID == 1 { "egot" } else { "ego" }
}

/// Derived exactly as verify_incoming_tx expects an address to be derived, from
/// the Ed25519 key as an EOA. Anything else would produce an address the chain
/// refuses to accept a spend from, stranding whatever was paid into it.
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

/// Every address worth checking for incoming payments.
///
/// Scans past the highest index known to have been used, because a payer may
/// skip addresses or use them out of order and a payment to a skipped one must
/// still be found.
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
