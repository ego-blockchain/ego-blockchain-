use thiserror::Error;

#[derive(Error, Debug)]
pub enum EgoDesktopError {
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("File system error: {0}")]
    FileSystemError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Wallet error: {0}")]
    WalletError(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Operation not permitted: {0}")]
    PermissionDenied(String),

    #[error("Resource not found: {0}")]
    NotFound(String),
}

pub type EgoResult<T> = Result<T, EgoDesktopError>;

impl serde::Serialize for EgoDesktopError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(self.to_string().as_ref())
    }
}
