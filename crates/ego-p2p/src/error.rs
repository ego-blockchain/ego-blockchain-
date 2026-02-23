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

    #[error("Provider not found: {0}")]
    ProviderNotFound(String),

    #[error("DHT error: {0}")]
    DhtError(String),

    #[error("Request error: {0}")]
    RequestError(String),

    #[error("Response error: {0}")]
    ResponseError(String),

    #[error("Signature verification failed: {0}")]
    SignatureVerificationError(String),

    #[error("Invalid attestation: {0}")]
    InvalidAttestation(String),

    #[error("Backpressure limit reached: {0}")]
    BackpressureError(String),

    #[error("Queue full: {0}")]
    QueueFullError(String),

    #[error("Authorization failed: {0}")]
    AuthorizationError(String),

    #[error("gRPC bridge error: {0}")]
    GrpcBridgeError(String),

    #[error("Metrics error: {0}")]
    MetricsError(String),

    #[error("Invalid peer capabilities: {0}")]
    InvalidCapabilities(String),

    #[error("Stream error: {0}")]
    StreamError(String),

    #[error("Codec error: {0}")]
    CodecError(String),

    #[error("Invalid CID: {0}")]
    InvalidCid(String),

    #[error("Chunk not found: {0}")]
    ChunkNotFound(String),

    #[error("Evidence bundle error: {0}")]
    EvidenceBundleError(String),
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

impl From<bincode::error::EncodeError> for P2PError {
    fn from(err: bincode::error::EncodeError) -> Self {
        P2PError::BincodeEncodeError(err.to_string())
    }
}

impl From<bincode::error::DecodeError> for P2PError {
    fn from(err: bincode::error::DecodeError) -> Self {
        P2PError::BincodeDecodeError(err.to_string())
    }
}

impl From<String> for P2PError {
    fn from(err: String) -> Self {
        P2PError::Libp2pError(err)
    }
}

pub type P2PResult<T> = Result<T, P2PError>;
