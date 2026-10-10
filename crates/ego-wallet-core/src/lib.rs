//! Wallet keys and addresses shared by Ego Desktop and the iPhone wallet.
//!
//! Every coin's key comes from the 32-byte Ego seed, so a wallet restored on
//! either side shows the same addresses. The iPhone reaches this through the
//! C functions in [`ffi`].

pub mod derive;
pub mod ffi;

pub use derive::{external_addresses, ChainAddress};
