//! Wallet keys and addresses shared by Ego Desktop and the iPhone wallet.
//!
//! Every coin's key comes from the 32-byte Ego seed, so a wallet restored on
//! either side shows the same addresses. The iPhone reaches this through the
//! C functions in [`ffi`].

pub mod cardano;
pub mod derive;
pub mod evm;
pub mod ffi;
pub mod presale;
pub mod shielded;
pub mod solana;
pub mod tron;
pub mod utxo;
pub mod xrp;

pub use derive::{external_addresses, ChainAddress};
