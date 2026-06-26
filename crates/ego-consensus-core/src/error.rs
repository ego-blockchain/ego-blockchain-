//! Minimal error type for the consensus core. The full `ego-consensus` crate has
//! a much larger `PoCError`; the BFT state machine only ever constructs these two
//! variants, so the core keeps its own self-contained copy (no cross-crate coupling).

use std::fmt;

#[derive(Debug, Clone)]
pub enum PoCError {
    ValidationFailed(String),
    SignatureVerificationFailed(String),
}

impl fmt::Display for PoCError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PoCError::ValidationFailed(s) => write!(f, "Validation failed: {s}"),
            PoCError::SignatureVerificationFailed(s) => write!(f, "Signature verification failed: {s}"),
        }
    }
}

impl std::error::Error for PoCError {}

pub type PoCResult<T> = Result<T, PoCError>;
