use crate::fraud::RollupError as FraudRollupError;
use thiserror::Error;

pub type RollupResult<T> = Result<T, RollupError>;

#[derive(Error, Debug, Clone)]
pub enum RollupError {
    #[error("Invalid batch: {0}")]
    InvalidBatch(String),

    #[error("Invalid commitment: {0}")]
    InvalidCommitment(String),

    #[error("Data availability error: {0}")]
    DataAvailability(String),

    #[error("Fraud proof error: {0}")]
    FraudProof(String),

    #[error("State error: {0}")]
    StateError(String),

    #[error("Operator error: {0}")]
    OperatorError(String),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Challenge period expired")]
    ChallengePeriodExpired,

    #[error("Insufficient bond: required {required}, available {available}")]
    InsufficientBond { required: u128, available: u128 },

    #[error("Rate limit exceeded: {operation}")]
    RateLimitExceeded { operation: String },

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Timeout: {operation}")]
    Timeout { operation: String },

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Core blockchain error: {0}")]
    CoreError(#[from] ego_core::EgoError),

    #[error("Consensus error: {0}")]
    ConsensusError(String),

    #[error("Invalid challenge: {0}")]
    InvalidChallenge(String),
}

impl From<bincode::error::EncodeError> for RollupError {
    fn from(err: bincode::error::EncodeError) -> Self {
        RollupError::SerializationError(err.to_string())
    }
}

impl From<bincode::error::DecodeError> for RollupError {
    fn from(err: bincode::error::DecodeError) -> Self {
        RollupError::SerializationError(err.to_string())
    }
}

impl From<FraudRollupError> for RollupError {
    fn from(err: FraudRollupError) -> Self {
        match err {
            FraudRollupError::FraudProof(s) => RollupError::FraudProof(s),
            FraudRollupError::SerializationError(s) => RollupError::SerializationError(s),
            FraudRollupError::InvalidCommitment(s) => RollupError::InvalidCommitment(s),
            FraudRollupError::ValidationError(s) => RollupError::ValidationError(s),
            FraudRollupError::InsufficientBond(s) => RollupError::FraudProof(s),
            FraudRollupError::ChallengeExpired(s) => RollupError::ChallengePeriodExpired,
            FraudRollupError::UnauthorizedChallenger(s) => RollupError::InvalidChallenge(s),
        }
    }
}
