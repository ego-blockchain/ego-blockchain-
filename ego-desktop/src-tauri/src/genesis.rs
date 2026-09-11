use serde::{Deserialize, Serialize};

pub const GENESIS_FILE_ENV: &str = "EGO_GENESIS_VALIDATORS_FILE";
pub const GENESIS_INLINE_ENV: &str = "EGO_GENESIS_VALIDATORS";

const BAKED_IN: &str = include_str!("../genesis_validators.json");

/// One member of the committee the network starts with. Two nodes cannot agree on whose
/// turn it is to propose unless they already agree on who is playing, and that agreement
/// has to come from somewhere outside consensus: before any block exists there is nothing
/// on-chain to read. Every BFT chain answers this the same way, with a starting list that
/// ships identically to every node.
///
/// The Dilithium key travels with the address because the engine identifies a validator by
/// `blake3(dilithium_pubkey)`, which cannot be recovered from the bech32 address. Carrying
/// it here means the committee is complete from block zero instead of waiting for every
/// member to announce itself, so a member that is offline costs a vote rather than
/// blocking the network from ever starting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisValidator {
    pub address: String,
    pub dilithium_pubkey: String,
}

impl GenesisValidator {
    fn is_well_formed(&self) -> bool {
        !self.address.trim().is_empty()
            && !self.dilithium_pubkey.trim().is_empty()
            && self.dilithium_pubkey.len() % 2 == 0
            && hex::decode(self.dilithium_pubkey.trim()).is_ok()
    }
}

pub fn parse(raw: &str) -> Vec<GenesisValidator> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let mut parsed: Vec<GenesisValidator> = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("[Genesis] the validator list could not be read ({e}); starting without one");
            return Vec::new();
        }
    };
    parsed.retain(|v| {
        let ok = v.is_well_formed();
        if !ok {
            tracing::error!("[Genesis] ignoring a malformed entry for {}", v.address);
        }
        ok
    });
    for v in parsed.iter_mut() {
        v.address = v.address.trim().to_string();
        v.dilithium_pubkey = v.dilithium_pubkey.trim().to_ascii_lowercase();
    }
    parsed.sort_by(|a, b| a.address.cmp(&b.address));
    parsed.dedup_by(|a, b| a.address == b.address);
    parsed
}

fn source() -> String {
    if let Ok(path) = std::env::var(GENESIS_FILE_ENV) {
        if !path.trim().is_empty() {
            return std::fs::read_to_string(path.trim()).unwrap_or_else(|e| {
                tracing::error!("[Genesis] {GENESIS_FILE_ENV} could not be read ({e}); starting without one");
                String::new()
            });
        }
    }
    if let Ok(inline) = std::env::var(GENESIS_INLINE_ENV) {
        if !inline.trim().is_empty() {
            return inline;
        }
    }
    BAKED_IN.to_string()
}

pub fn validators() -> Vec<GenesisValidator> {
    static CACHE: std::sync::OnceLock<Vec<GenesisValidator>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| parse(&source())).clone()
}

/// Membership test that does not rebuild the list. Every block arriving over sync is
/// checked against the starting committee, so this runs far too often to re-read and
/// re-parse the file each time.
pub fn is_member(address: &str) -> bool {
    validators().iter().any(|v| v.address == address)
}

/// The starting committee, by wallet address, in the order every node will agree on.
pub fn addresses() -> Vec<String> {
    validators().into_iter().map(|v| v.address).collect()
}

/// The starting committee as the consensus engine identifies them. The engine knows a
/// validator by `blake3(dilithium_pubkey)`, which the bech32 address cannot be turned into,
/// so anything comparing against a proposal's author needs this form.
pub fn engine_addresses() -> Vec<ego_core::Address> {
    static CACHE: std::sync::OnceLock<Vec<ego_core::Address>> = std::sync::OnceLock::new();
    CACHE
        .get_or_init(|| {
            validators()
                .iter()
                .filter_map(|v| hex::decode(&v.dilithium_pubkey).ok())
                .filter(|k| !k.is_empty())
                .map(crate::consensus_host::address_from_dilithium)
                .collect()
        })
        .clone()
}

pub fn is_engine_member(addr: &ego_core::Address) -> bool {
    engine_addresses().iter().any(|a| a == addr)
}

pub fn dilithium_pubkey_for(address: &str) -> Option<Vec<u8>> {
    validators()
        .into_iter()
        .find(|v| v.address == address)
        .and_then(|v| hex::decode(v.dilithium_pubkey).ok())
        .filter(|b| !b.is_empty())
}

/// This node's own entry, ready to paste into `genesis_validators.json`.
pub fn local_entry() -> Option<GenesisValidator> {
    let address = crate::ledger::Ledger::load().address;
    if address.is_empty() {
        return None;
    }
    let seed = crate::p2p::get_ed25519_seed()?;
    let kp = ego_core::KeyPair::from_bytes(&seed).ok()?;
    Some(GenesisValidator {
        address,
        dilithium_pubkey: hex::encode(kp.dilithium_public_key().key_data),
    })
}

pub fn announce_on_start() {
    let list = validators();
    match list.len() {
        0 => tracing::warn!(
            "[Genesis] no starting validator list is baked into this build, so the committee falls back to whichever peers each node has heard from. Nodes will disagree about whose turn it is to propose and the chain may not start. Run the app on each node, copy the [Genesis] entry line below into genesis_validators.json, and rebuild every node with the same file."
        ),
        n => {
            tracing::info!("[Genesis] starting committee of {n}:");
            for (i, v) in list.iter().enumerate() {
                tracing::info!("[Genesis]   [{i}] {}", v.address);
            }
            let mine = crate::ledger::Ledger::load().address;
            if !mine.is_empty() && !list.iter().any(|v| v.address == mine) {
                tracing::warn!(
                    "[Genesis] this node ({mine}) is NOT in the starting committee, so it will follow the chain without proposing or voting."
                );
            }
        }
    }
    if let Some(entry) = local_entry() {
        tracing::info!(
            "[Genesis] this node's entry: {{\"address\": \"{}\", \"dilithium_pubkey\": \"{}\"}}",
            entry.address, entry.dilithium_pubkey
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(addr: &str, key: &str) -> String {
        format!("{{\"address\": \"{addr}\", \"dilithium_pubkey\": \"{key}\"}}")
    }

    #[test]
    fn the_shipped_file_parses_so_a_build_can_never_carry_a_broken_list() {
        let _ = parse(BAKED_IN);
    }

    #[test]
    fn every_shipped_seat_is_one_a_real_node_can_fill() {
        let list = parse(BAKED_IN);
        if list.is_empty() {
            return;
        }
        const DILITHIUM2_PUBKEY_BYTES: usize = 1312;
        let mut engine = Vec::new();
        for v in &list {
            let key = hex::decode(&v.dilithium_pubkey).expect("checked by parse");
            assert_eq!(
                key.len(),
                DILITHIUM2_PUBKEY_BYTES,
                "seat {} carries a {}-byte key, so no node can ever prove it owns that seat and                  the committee is permanently one vote short of quorum",
                v.address,
                key.len(),
            );
            assert!(v.address.starts_with("egot1") || v.address.starts_with("ego1"), "{}", v.address);
            engine.push(format!("{}", crate::consensus_host::address_from_dilithium(key)));
        }
        let mut distinct = engine.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            engine.len(),
            "two seats resolve to the same engine identity, so the committee is smaller than it              counts itself and quorum is unreachable",
        );
    }

    #[test]
    fn an_empty_list_means_no_starting_committee() {
        assert!(parse("").is_empty());
        assert!(parse("[]").is_empty());
        assert!(parse("   \n ").is_empty());
    }

    #[test]
    fn every_node_orders_the_committee_identically() {
        let a = entry("egot1aaa", "aabb");
        let b = entry("egot1bbb", "ccdd");
        let c = entry("egot1ccc", "eeff");
        let one = parse(&format!("[{a},{b},{c}]"));
        let another = parse(&format!("[{c},{a},{b}]"));
        assert_eq!(one, another, "the rota must not depend on the order in the file");
        assert_eq!(
            one.iter().map(|v| v.address.as_str()).collect::<Vec<_>>(),
            vec!["egot1aaa", "egot1bbb", "egot1ccc"],
        );
    }

    #[test]
    fn a_repeated_address_is_seated_once() {
        let list = parse(&format!("[{},{}]", entry("egot1aaa", "aabb"), entry("egot1aaa", "aabb")));
        assert_eq!(list.len(), 1, "a duplicate would give one node two turns in the rota");
    }

    #[test]
    fn entries_that_cannot_be_used_are_dropped_rather_than_seated() {
        let good = entry("egot1aaa", "aabb");
        let list = parse(&format!(
            "[{good},{},{},{}]",
            entry("", "aabb"),
            entry("egot1bbb", ""),
            entry("egot1ccc", "nothex"),
        ));
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].address, "egot1aaa");
    }

    #[test]
    fn a_broken_file_starts_without_a_committee_instead_of_a_wrong_one() {
        assert!(parse("{not json").is_empty());
        assert!(parse("{\"address\": \"egot1aaa\"}").is_empty(), "an object is not a list");
    }

    #[test]
    fn surrounding_whitespace_and_case_do_not_create_a_different_validator() {
        let list = parse("[{\"address\": \"  egot1aaa \", \"dilithium_pubkey\": \" AABB \"}]");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].address, "egot1aaa");
        assert_eq!(list[0].dilithium_pubkey, "aabb");
    }
}




