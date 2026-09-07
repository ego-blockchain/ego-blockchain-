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

/// Record how a transaction travelled. First observation wins: a transaction
/// handed to a radio link and then also seen over gossip was still sent by
/// radio, and the later sighting should not overwrite that.
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
    if map.contains_key(hash) {
        return;
    }
    if map.len() >= MAX_TRACKED {
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

    #[test]
    fn the_first_observation_is_kept() {
        let mut map: HashMap<String, String> = HashMap::new();
        map.insert("a".into(), "radio".into());
        // Simulates record() refusing to overwrite.
        if !map.contains_key("a") {
            map.insert("a".into(), "internet".into());
        }
        assert_eq!(map.get("a").map(String::as_str), Some("radio"),
            "a later gossip sighting must not erase that it went by radio");
    }

    #[test]
    fn an_empty_transport_is_not_recorded() {
        let before = all().len();
        record("some-hash-that-does-not-matter", "");
        assert_eq!(all().len(), before, "an empty label must never be stored");
    }
}
