//! `ego-consensus-core` — the deterministic BFT state machine, extracted from
//! `ego-consensus` with no heavy dependencies so it can be unit-tested with a
//! deterministic multi-node harness (see `tests/harness.rs`) and later wired into
//! the desktop node to replace the hand-rolled inline BFT in `p2p.rs`.
//!
//! Phase 1 of CONSENSUS_REPLACEMENT_SCOPE.md.

pub mod error;
pub mod bft;
pub mod fork_choice;

pub use bft::{BftEngine, BlockHeader, BlockRoots, QuorumCertificate, Vote};
pub use fork_choice::{ForkChoiceStore, ViewChangeMsg};
