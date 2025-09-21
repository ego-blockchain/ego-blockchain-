use ego_core::EgoError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PoCError {
    #[error("Invalid beacon: {0}")]
    InvalidBeacon(String),

    #[error("Invalid witness report: {0}")]
    InvalidWitnessReport(String),

    #[error("Invalid RF metrics: {0}")]
    InvalidRFMetrics(String),

    #[error("Invalid location data: {0}")]
    InvalidLocation(String),

    #[error("Time window violation: {0}")]
    TimeWindowViolation(String),

    #[error("Insufficient witnesses: got {got}, need at least {min}")]
    InsufficientWitnesses { got: usize, min: usize },

    #[error("Excessive witnesses: got {got}, max allowed {max}")]
    ExcessiveWitnesses { got: usize, max: usize },

    #[error("Fraud detected: {fraud_type:?} - {details}")]
    FraudDetected {
        fraud_type: super::FraudType,
        details: String,
    },

    #[error("Aggregation failed: {0}")]
    AggregationFailed(String),

    #[error("Validation failed: {0}")]
    ValidationFailed(String),

    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Compression error: {0}")]
    CompressionError(String),

    #[error("H3 indexing error: {0}")]
    H3Error(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Node not authorized for slice: {slice_id}")]
    UnauthorizedSlice { slice_id: String },

    #[error("Rate limit exceeded: {operation} - {limit} per hour")]
    RateLimitExceeded { operation: String, limit: u32 },

    #[error("DRS score too low: {score} < {threshold}")]
    InsufficientDRSScore { score: f64, threshold: f64 },

    #[error("Cellular safety violation: {0}")]
    CellularSafetyViolation(String),

    #[error("Path loss validation failed: expected {expected_db} dB, got {actual_db} dB")]
    PathLossValidationFailed { expected_db: f32, actual_db: f32 },

    #[error("Distance validation failed: {distance_km} km exceeds maximum {max_km} km")]
    DistanceValidationFailed { distance_km: f32, max_km: f32 },

    #[error("Timing validation failed: {0}")]
    TimingValidationFailed(String),

    #[error("Bundle creation failed: {0}")]
    BundleCreationFailed(String),

    #[error("Evidence storage failed: {0}")]
    EvidenceStorageFailed(String),

    #[error("CID computation failed: {0}")]
    CIDComputationFailed(String),

    #[error("Insufficient collateral: need {required}, have {available}")]
    InsufficientCollateral { required: u128, available: u128 },

    #[error("Node not found: {node_id}")]
    NodeNotFound { node_id: String },

    #[error("Challenge not found: {challenge_hash}")]
    ChallengeNotFound { challenge_hash: String },

    #[error("Duplicate submission: {0}")]
    DuplicateSubmission(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<EgoError> for PoCError {
    fn from(error: EgoError) -> Self {
        match error {
            EgoError::InvalidSignature(msg) => PoCError::SignatureVerificationFailed(msg),
            EgoError::SerializationError(msg) => PoCError::SerializationError(msg),
            EgoError::InvalidTransaction(msg) => PoCError::ValidationFailed(msg),
            _ => PoCError::InternalError(format!("EgoError: {}", error)),
        }
    }
}

impl From<bincode::error::EncodeError> for PoCError {
    fn from(error: bincode::error::EncodeError) -> Self {
        PoCError::SerializationError(format!("Encoding error: {}", error))
    }
}

impl From<bincode::error::DecodeError> for PoCError {
    fn from(error: bincode::error::DecodeError) -> Self {
        PoCError::SerializationError(format!("Decoding error: {}", error))
    }
}

impl From<serde_json::Error> for PoCError {
    fn from(error: serde_json::Error) -> Self {
        PoCError::SerializationError(format!("JSON error: {}", error))
    }
}

impl From<std::io::Error> for PoCError {
    fn from(error: std::io::Error) -> Self {
        PoCError::InternalError(format!("IO error: {}", error))
    }
}

impl From<libp2p::swarm::DialError> for PoCError {
    fn from(error: libp2p::swarm::DialError) -> Self {
        PoCError::NetworkError(format!("P2P dial error: {}", error))
    }
}

pub type PoCResult<T> = Result<T, PoCError>;

impl PoCError {
    pub fn recovery_suggestion(&self) -> &'static str {
        match self {
            PoCError::InvalidBeacon(_) => "Check beacon configuration and authorization",
            PoCError::InvalidWitnessReport(_) => "Verify RF metrics and location data",
            PoCError::TimeWindowViolation(_) => "Ensure system clock is synchronized",
            PoCError::InsufficientWitnesses { .. } => {
                "Wait for more witness reports or reduce requirements"
            }
            PoCError::FraudDetected { .. } => "Investigate node behavior and consider slashing",
            PoCError::NetworkError(_) => "Check network connectivity and peer status",
            PoCError::RateLimitExceeded { .. } => "Reduce submission frequency or wait for reset",
            PoCError::CellularSafetyViolation(_) => "Enable cellular-safe mode and reduce rates",
            PoCError::UnauthorizedSlice { .. } => {
                "Request slice authorization from network operator"
            }
            _ => "Check logs for detailed error information",
        }
    }

    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            PoCError::NetworkError(_)
                | PoCError::TimeWindowViolation(_)
                | PoCError::InsufficientWitnesses { .. }
                | PoCError::RateLimitExceeded { .. }
                | PoCError::SerializationError(_)
        )
    }

    pub fn should_retry(&self) -> bool {
        matches!(
            self,
            PoCError::NetworkError(_)
                | PoCError::InsufficientWitnesses { .. }
                | PoCError::SerializationError(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_recovery_suggestions() {
        let error = PoCError::InvalidBeacon("test".to_string());
        assert!(!error.recovery_suggestion().is_empty());

        let error = PoCError::NetworkError("connection lost".to_string());
        assert!(error.is_recoverable());
        assert!(error.should_retry());
    }

    #[test]
    fn test_error_conversion() {
        let ego_error = EgoError::InvalidSignature("test".to_string());
        let poc_error: PoCError = ego_error.into();

        assert!(matches!(
            poc_error,
            PoCError::SignatureVerificationFailed(_)
        ));
    }
}
