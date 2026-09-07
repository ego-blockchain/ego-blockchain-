use crate::ledger::data_dir;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// How each transaction this node handled actually travelled.
///
/// Kept beside the chain rather than inside it. The route is not a property of
/// the transaction, it is a property of this node's encounter with it: the same
/// payment reaches one node over radio and the next over gossip, and both are
/// telling the truth. It is also not signed, so it could never be trusted from
/// anyone else even if it were carried along.
///
/// Written when the node observes the delivery, read back when the wallet lists
/// history. Losing this file loses the labels and nothing else.
fn path() -> std::path::PathBuf {
    data_dir().join("tx_transport.json")
}

/// Entries are only useful while the transaction is still worth showing, so the
/// map is capped rather than kept forever.
const MAX_TRACKED: usize = 5_000;

fn cache() -> &'static Mutex<Option<HashMap<String, String>>> {
    static C: OnceLock<Mutex<Option<HashMap<String, String>>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

fn load_from_disk() -> HashMap<String, String> {
    std::fs::read_to_string(path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn all() -> HashMap<String, String> {
    let mut guard = match cache().lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    if guard.is_none() {
        *guard = Some(load_from_disk());
    }
    guard.clone().unwrap_or_default()
}

pub fn get(hash: &str) -> Option<String> {
    all().get(hash).cloned()
}

pub const INTERNET: &str = "internet";

/// Record how a transaction travelled.
///
/// Crossing a radio link wins over the internet, whichever is seen first. A
/// payment can legitimately go out both ways: sent over gossip, then pushed
/// over the air by hand because the sender suspects the connection is
/// filtered. Both happened, but the notable one is the radio hop, and it stays
/// true afterwards. The internet is the unremarkable default and must never
/// overwrite a radio label.
///
/// Between two radio links the first is kept, since there is nothing to choose
/// between them.
pub fn record(hash: &str, transport: &str) {
    if hash.is_empty() || transport.is_empty() {
        return;
    }
    let mut guard = match cache().lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    if guard.is_none() {
        *guard = Some(load_from_disk());
    }
    let map = guard.as_mut().expect("cache initialised above");
    if let Some(existing) = map.get(hash) {
        let existing_is_radio = existing != INTERNET;
        let incoming_is_radio = transport != INTERNET;
        // Keep what we have unless this is a radio hop displacing the default.
        if existing_is_radio || !incoming_is_radio {
            return;
        }
    }
    if map.len() >= MAX_TRACKED && !map.contains_key(hash) {
        map.clear();
    }
    map.insert(hash.to_string(), transport.to_string());

    if let Ok(data) = serde_json::to_string(map) {
        let _ = crate::utils::atomic_write(&path(), data.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique(tag: &str) -> String {
        format!("tx-{tag}-{}-{:?}", std::process::id(), std::time::SystemTime::now())
    }

    #[test]
    fn a_radio_hop_displaces_the_internet_default() {
        let h = unique("displace");
        record(&h, INTERNET);
        record(&h, "radio");
        assert_eq!(get(&h).as_deref(), Some("radio"),
            "pushing a sent transaction over the air must show as radio");
    }

    #[test]
    fn the_internet_never_overwrites_a_radio_hop() {
        let h = unique("keep");
        record(&h, "radio");
        record(&h, INTERNET);
        assert_eq!(get(&h).as_deref(), Some("radio"),
            "seeing it later on gossip must not erase the radio hop");
    }

    #[test]
    fn between_two_radio_links_the_first_is_kept() {
        let h = unique("two");
        record(&h, "spool");
        record(&h, "lora");
        assert_eq!(get(&h).as_deref(), Some("spool"));
    }

    #[test]
    fn an_empty_transport_is_not_recorded() {
        // Asserts about this hash only. Counting the whole map raced the other
        // tests in this module, which write to the same global store while
        // cargo runs them in parallel, and passed or failed by timing.
        let h = unique("empty");
        record(&h, "");
        assert!(get(&h).is_none(), "an empty label must never be stored");
    }
}
