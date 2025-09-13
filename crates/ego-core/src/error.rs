use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum EgoError {
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("Invalid block: {0}")]
    InvalidBlock(String),

    #[error("Invalid shard ID: {shard_id}")]
    InvalidShardId { shard_id: u32 },

    #[error("Shard not found: {shard_id}")]
    ShardNotFound { shard_id: u32 },

    #[error("Account not found: {account_id}")]
    AccountNotFound { account_id: String },

    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: u128, available: u128 },

    #[error("Invalid nonce: expected {expected}, got {got}")]
    InvalidNonce { expected: u64, got: u64 },

    #[error("Rollup verification failed: {reason}")]
    RollupVerificationFailed { reason: String },

    #[error("Merkle proof verification failed")]
    MerkleProofFailed,

    #[error("State root mismatch: expected {expected}, got {actual}")]
    StateRootMismatch { expected: String, actual: String },

    #[error("Cross-shard receipt invalid: {reason}")]
    InvalidCrossShardReceipt { reason: String },

    #[error("Network slice not authorized: {slice_id}")]
    UnauthorizedSlice { slice_id: String },

    #[error("Storage quota exceeded: used {used}, limit {limit}")]
    StorageQuotaExceeded { used: u64, limit: u64 },

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("JSON error: {0}")]
    JsonError(String),

    #[error("IO error: {0}")]
    IoError(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Protocol version mismatch: expected {expected}, got {got}")]
    ProtocolVersionMismatch { expected: u32, got: u32 },

    #[error("Operation timeout")]
    Timeout,

    #[error("Resource limit exceeded: {resource}")]
    ResourceLimitExceeded { resource: String },
}

impl From<bincode::error::EncodeError> for EgoError {
    fn from(err: bincode::error::EncodeError) -> Self {
        EgoError::SerializationError(err.to_string())
    }
}

impl From<bincode::error::DecodeError> for EgoError {
    fn from(err: bincode::error::DecodeError) -> Self {
        EgoError::SerializationError(err.to_string())
    }
}

impl From<serde_json::Error> for EgoError {
    fn from(err: serde_json::Error) -> Self {
        EgoError::JsonError(err.to_string())
    }
}

impl From<std::io::Error> for EgoError {
    fn from(err: std::io::Error) -> Self {
        EgoError::IoError(err.to_string())
    }
}

impl PartialEq for EgoError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (EgoError::InvalidSignature(a), EgoError::InvalidSignature(b)) => a == b,
            (EgoError::InvalidTransaction(a), EgoError::InvalidTransaction(b)) => a == b,
            (EgoError::InvalidBlock(a), EgoError::InvalidBlock(b)) => a == b,
            (
                EgoError::InvalidShardId { shard_id: a },
                EgoError::InvalidShardId { shard_id: b },
            ) => a == b,
            (EgoError::ShardNotFound { shard_id: a }, EgoError::ShardNotFound { shard_id: b }) => {
                a == b
            }
            (
                EgoError::AccountNotFound { account_id: a },
                EgoError::AccountNotFound { account_id: b },
            ) => a == b,
            (
                EgoError::InsufficientBalance {
                    required: a1,
                    available: a2,
                },
                EgoError::InsufficientBalance {
                    required: b1,
                    available: b2,
                },
            ) => a1 == b1 && a2 == b2,
            (
                EgoError::InvalidNonce {
                    expected: a1,
                    got: a2,
                },
                EgoError::InvalidNonce {
                    expected: b1,
                    got: b2,
                },
            ) => a1 == b1 && a2 == b2,
            (
                EgoError::RollupVerificationFailed { reason: a },
                EgoError::RollupVerificationFailed { reason: b },
            ) => a == b,
            (EgoError::MerkleProofFailed, EgoError::MerkleProofFailed) => true,
            (
                EgoError::StateRootMismatch {
                    expected: a1,
                    actual: a2,
                },
                EgoError::StateRootMismatch {
                    expected: b1,
                    actual: b2,
                },
            ) => a1 == b1 && a2 == b2,
            (
                EgoError::InvalidCrossShardReceipt { reason: a },
                EgoError::InvalidCrossShardReceipt { reason: b },
            ) => a == b,
            (
                EgoError::UnauthorizedSlice { slice_id: a },
                EgoError::UnauthorizedSlice { slice_id: b },
            ) => a == b,
            (
                EgoError::StorageQuotaExceeded {
                    used: a1,
                    limit: a2,
                },
                EgoError::StorageQuotaExceeded {
                    used: b1,
                    limit: b2,
                },
            ) => a1 == b1 && a2 == b2,
            (EgoError::SerializationError(a), EgoError::SerializationError(b)) => a == b,
            (EgoError::JsonError(a), EgoError::JsonError(b)) => a == b,
            (EgoError::IoError(a), EgoError::IoError(b)) => a == b,
            (EgoError::CryptoError(a), EgoError::CryptoError(b)) => a == b,
            (
                EgoError::ProtocolVersionMismatch {
                    expected: a1,
                    got: a2,
                },
                EgoError::ProtocolVersionMismatch {
                    expected: b1,
                    got: b2,
                },
            ) => a1 == b1 && a2 == b2,
            (EgoError::Timeout, EgoError::Timeout) => true,
            (
                EgoError::ResourceLimitExceeded { resource: a },
                EgoError::ResourceLimitExceeded { resource: b },
            ) => a == b,
            _ => false,
        }
    }
}

pub type EgoResult<T> = Result<T, EgoError>;
