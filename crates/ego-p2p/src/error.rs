use thiserror::Error;

#[derive(Error, Debug)]
pub enum P2PError {
    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Message serialization error: {0}")]
    SerializationError(String),

    #[error("Message deserialization error: {0}")]
    DeserializationError(String),

    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    #[error("Topic error: {0}")]
    TopicError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Authentication error: {0}")]
    AuthenticationError(String),

    #[error("Timeout error: {0}")]
    TimeoutError(String),

    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    #[error("Resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Libp2p error: {0}")]
    Libp2pError(String),

    #[error("Bincode encode error: {0}")]
    BincodeEncodeError(String),

    #[error("Bincode decode error: {0}")]
    BincodeDecodeError(String),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Noise error: {0}")]
    NoiseError(String),

    #[error("Transport error: {0}")]
    TransportError(String),
}

impl From<libp2p::noise::Error> for P2PError {
    fn from(err: libp2p::noise::Error) -> Self {
        P2PError::NoiseError(err.to_string())
    }
}

impl From<Box<dyn std::error::Error>> for P2PError {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        P2PError::Libp2pError(err.to_string())
    }
}

pub type P2PResult<T> = Result<T, P2PError>;
