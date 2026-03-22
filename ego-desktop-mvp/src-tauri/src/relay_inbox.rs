//! Relay inbox — fully replaced by DHT-based P2P inbox in p2p.rs.
//! This module is kept as a stub so existing call sites compile without changes.
//! All traffic now flows through `crate::p2p::dht_inbox_deposit` /
//! `crate::p2p::dht_inbox_poll` — no central server is contacted.

/// No-op: DHT inbox handles deposit via `p2p::dht_inbox_deposit`.
pub async fn deposit(_to_addr: &str, _ciphertext: Vec<u8>) -> bool { true }

/// No-op: DHT inbox handles polling via `p2p::dht_inbox_poll`.
pub async fn fetch(_my_addr: &str) -> Vec<(String, Vec<u8>)> { vec![] }

/// No-op: tombstoning is done inside `p2p.rs` after DHT delivery.
pub async fn delete(_my_addr: &str, _msg_id: &str) {}
