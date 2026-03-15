use thiserror::Error;

#[derive(Debug, Error)]
pub enum ZkError {
    #[error("proof generation failed: {0}")]
    ProvingError(String),
    #[error("proof verification failed")]
    VerificationError,
    #[error("setup error: {0}")]
    SetupError(String),
    #[error("serialization error: {0}")]
    SerializationError(String),
}
