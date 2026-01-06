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

    #[error("Validator not found: {validator_id}")]
    ValidatorNotFound { validator_id: String },

    #[error("Invalid validator status: {status}")]
    InvalidValidatorStatus { status: String },

    #[error("Validator already exists: {validator_id}")]
    ValidatorAlreadyExists { validator_id: String },

    #[error("Insufficient stake: required {required}, available {available}")]
    InsufficientStake { required: u128, available: u128 },

    #[error("Storage provider not found: {provider_id}")]
    StorageProviderNotFound { provider_id: String },

    #[error("Storage entry not found: {chunk_id}")]
    StorageEntryNotFound { chunk_id: String },

    #[error("Triad placement invalid: {reason}")]
    InvalidTriadPlacement { reason: String },

    #[error("Proof verification failed: {proof_type}")]
    ProofVerificationFailed { proof_type: String },

    #[error("PoSt challenge failed: {reason}")]
    PostChallengeFailed { reason: String },

    #[error("PoC verification failed: {reason}")]
    PoCVerificationFailed { reason: String },

    #[error("Slice not found: {slice_id}")]
    SliceNotFound { slice_id: String },

    #[error("Slice quota exceeded: {slice_id}")]
    SliceQuotaExceeded { slice_id: String },

    #[error("Invalid slice configuration: {reason}")]
    InvalidSliceConfig { reason: String },

    #[error("Deploy policy violation: {reason}")]
    DeployPolicyViolation { reason: String },

    #[error("Deploy credits insufficient: required {required}, available {available}")]
    InsufficientDeployCredits { required: u64, available: u64 },

    #[error("Deploy quota exceeded: {reason}")]
    DeployQuotaExceeded { reason: String },

    #[error("Blacklisted contract: {code_hash}")]
    BlacklistedContract { code_hash: String },

    #[error("AI pattern detected: {reason}")]
    AiPatternDetected { reason: String },

    #[error("Human verification required")]
    HumanVerificationRequired,

    #[error("Anti-spam check failed: {reason}")]
    AntiSpamCheckFailed { reason: String },

    #[error("DRS calculation failed: {reason}")]
    DrsCalculationFailed { reason: String },

    #[error("DRS score invalid: {score}")]
    InvalidDrsScore { score: f64 },

    #[error("DRS configuration invalid: {reason}")]
    InvalidDrsConfig { reason: String },

    #[error("Evidence bundle invalid: {reason}")]
    InvalidEvidenceBundle { reason: String },

    #[error("Epoch finalization failed: {epoch}")]
    EpochFinalizationFailed { epoch: u64 },

    #[error("PQ transition error: {reason}")]
    PqTransitionError { reason: String },

    #[error("Algorithm not supported: {algorithm_id}")]
    UnsupportedAlgorithm { algorithm_id: u16 },

    #[error("Downgrade attack detected: {reason}")]
    DowngradeAttackDetected { reason: String },

    #[error("Cellular data limit exceeded: {usage_gb}")]
    CellularDataLimitExceeded { usage_gb: u64 },

    #[error("WiFi required for operation: {operation}")]
    WifiRequired { operation: String },

    #[error("Device capabilities invalid: {reason}")]
    InvalidDeviceCapabilities { reason: String },

    #[error("Contract not found: {contract_address}")]
    ContractNotFound { contract_address: String },

    #[error("Contract execution failed: {reason}")]
    ContractExecutionFailed { reason: String },

    #[error("Contract deployment failed: {reason}")]
    ContractDeploymentFailed { reason: String },

    #[error("State transition invalid: {reason}")]
    InvalidStateTransition { reason: String },

    #[error("Pruning failed: {reason}")]
    PruningFailed { reason: String },

    #[error("Snapshot creation failed: {reason}")]
    SnapshotCreationFailed { reason: String },

    #[error("Cross-shard communication failed: {reason}")]
    CrossShardCommunicationFailed { reason: String },

    #[error("Receipt deadline expired: {deadline_epoch}")]
    ReceiptDeadlineExpired { deadline_epoch: u64 },

    #[error("Receipt processing failed: {reason}")]
    ReceiptProcessingFailed { reason: String },

    #[error("Block validation failed: {reason}")]
    BlockValidationFailed { reason: String },

    #[error("Block proposal failed: {reason}")]
    BlockProposalFailed { reason: String },

    #[error("Quorum not reached: {voting_power}/{required}")]
    QuorumNotReached { voting_power: u64, required: u64 },

    #[error("Transaction pool full")]
    TransactionPoolFull,

    #[error("Transaction rejected: {reason}")]
    TransactionRejected { reason: String },

    #[error("Transaction expired")]
    TransactionExpired,

    #[error("RU limit exceeded: {used}/{limit}")]
    RuLimitExceeded { used: u64, limit: u64 },

    #[error("Fraud proof invalid: {reason}")]
    InvalidFraudProof { reason: String },

    #[error("Fraud challenge failed: {reason}")]
    FraudChallengeFailed { reason: String },

    #[error("Rollup state invalid: {rollup_id}")]
    InvalidRollupState { rollup_id: String },

    #[error("Rollup not found: {rollup_id}")]
    RollupNotFound { rollup_id: String },

    #[error("Batch processing failed: {reason}")]
    BatchProcessingFailed { reason: String },

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Peer connection failed: {peer_id}")]
    PeerConnectionFailed { peer_id: String },

    #[error("Sync error: {reason}")]
    SyncError { reason: String },

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("Emergency mode active")]
    EmergencyModeActive,

    #[error("Whitelist only mode active")]
    WhitelistOnlyMode,

    #[error("Jail violation: {reason}")]
    JailViolation { reason: String },

    #[error("Slashing event: {reason}")]
    SlashingEvent { reason: String },

    #[error("Collateral insufficient: required {required}, available {available}")]
    InsufficientCollateral { required: u128, available: u128 },

    #[error("Sector not found: {sector_id}")]
    SectorNotFound { sector_id: String },

    #[error("Health check failed: {reason}")]
    HealthCheckFailed { reason: String },

    #[error("Audit failed: {reason}")]
    AuditFailed { reason: String },

    #[error("Replication failed: {reason}")]
    ReplicationFailed { reason: String },

    #[error("Erasure coding failed: {reason}")]
    ErasureCodingFailed { reason: String },

    #[error("Encryption failed: {reason}")]
    EncryptionFailed { reason: String },

    #[error("Decryption failed: {reason}")]
    DecryptionFailed { reason: String },

    #[error("Key derivation failed: {reason}")]
    KeyDerivationFailed { reason: String },

    #[error("Session establishment failed: {reason}")]
    SessionEstablishmentFailed { reason: String },

    #[error("Handshake failed: {reason}")]
    HandshakeFailed { reason: String },

    #[error("Replay attack detected")]
    ReplayAttackDetected,

    #[error("Nonce reuse detected")]
    NonceReuseDetected,

    #[error("Invalid chain ID: expected {expected}, got {got}")]
    InvalidChainId { expected: u32, got: u32 },

    #[error("Invalid network ID: expected {expected}, got {got}")]
    InvalidNetworkId { expected: u32, got: u32 },

    #[error("Consensus failure: {reason}")]
    ConsensusFailure { reason: String },

    #[error("Epoch transition failed: {reason}")]
    EpochTransitionFailed { reason: String },

    #[error("Reward distribution failed: {reason}")]
    RewardDistributionFailed { reason: String },

    #[error("Commission rate invalid: {rate}")]
    InvalidCommissionRate { rate: u16 },

    #[error("Delegation failed: {reason}")]
    DelegationFailed { reason: String },

    #[error("Undelegation failed: {reason}")]
    UndelegationFailed { reason: String },

    #[error("Unbonding period not elapsed")]
    UnbondingPeriodNotElapsed,

    #[error("DAO proposal invalid: {reason}")]
    InvalidDaoProposal { reason: String },

    #[error("DAO vote invalid: {reason}")]
    InvalidDaoVote { reason: String },

    #[error("Governance action failed: {reason}")]
    GovernanceActionFailed { reason: String },

    #[error("Metrics update failed: {reason}")]
    MetricsUpdateFailed { reason: String },

    #[error("Performance degradation detected: {metric}")]
    PerformanceDegradation { metric: String },

    #[error("Anomaly detected: {anomaly_type}")]
    AnomalyDetected { anomaly_type: String },

    #[error("Internal error: {0}")]
    InternalError(String),
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
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

pub type EgoResult<T> = Result<T, EgoError>;
