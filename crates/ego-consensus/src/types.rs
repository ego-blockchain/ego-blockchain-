use ego_core::{Address, Hash, Timestamp};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct Challenge {
    pub challenge_hash: Hash,
    pub h3_cell: String,
    pub nonce: Vec<u8>,
    pub timestamp: Timestamp,
    pub difficulty: u8,
    pub reward_scale: f64,
}

impl PartialEq for Challenge {
    fn eq(&self, other: &Self) -> bool {
        self.challenge_hash == other.challenge_hash
            && self.h3_cell == other.h3_cell
            && self.nonce == other.nonce
            && self.timestamp == other.timestamp
            && self.difficulty == other.difficulty
    }
}

impl Eq for Challenge {}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct RFMetrics {
    pub rsrp: i16,
    pub rsrq: i16,
    pub sinr: i16,
    pub timing_advance: u32,
    pub pci: u16,
    pub beam_index: Option<u8>,
    pub frequency: u32,
    pub rx_timestamp: u64,
}

impl PartialEq for RFMetrics {
    fn eq(&self, other: &Self) -> bool {
        self.rsrp == other.rsrp
            && self.rsrq == other.rsrq
            && self.sinr == other.sinr
            && self.timing_advance == other.timing_advance
            && self.pci == other.pci
            && self.beam_index == other.beam_index
            && self.frequency == other.frequency
    }
}

impl Eq for RFMetrics {}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct LocationData {
    pub latitude: f64,
    pub longitude: f64,
    pub altitude: Option<f32>,
    pub accuracy: Option<f32>,
    pub timestamp: u64,
    pub h3_index: String,
}

impl PartialEq for LocationData {
    fn eq(&self, other: &Self) -> bool {
        (self.latitude - other.latitude).abs() < f64::EPSILON
            && (self.longitude - other.longitude).abs() < f64::EPSILON
            && self.h3_index == other.h3_index
    }
}

impl Eq for LocationData {}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct BeaconTxLog {
    pub tx_timestamp: u64,
    pub tx_power_dbm: i16,
    pub frequency: u32,
    pub pci: u16,
    pub beam_pattern: Option<Vec<u8>>,
    pub duration_ms: u32,
}

impl PartialEq for BeaconTxLog {
    fn eq(&self, other: &Self) -> bool {
        self.tx_timestamp == other.tx_timestamp
            && self.tx_power_dbm == other.tx_power_dbm
            && self.frequency == other.frequency
            && self.pci == other.pci
            && self.duration_ms == other.duration_ms
    }
}

impl Eq for BeaconTxLog {}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct CoverageQuality {
    pub witness_count: u32,
    pub avg_rsrp: f32,
    pub coverage_radius_km: f32,
    pub interference_level: f32,
    pub quality_score: f64,
    pub density_penalty: f64,
}

impl PartialEq for CoverageQuality {
    fn eq(&self, other: &Self) -> bool {
        self.witness_count == other.witness_count
            && (self.avg_rsrp - other.avg_rsrp).abs() < f32::EPSILON
            && (self.coverage_radius_km - other.coverage_radius_km).abs() < f32::EPSILON
    }
}

impl Eq for CoverageQuality {}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct CompressionInfo {
    pub algorithm: CompressionAlgorithm,
    pub original_size: u32,
    pub compressed_size: u32,
    pub compression_ratio: f32,
}

impl PartialEq for CompressionInfo {
    fn eq(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm
            && self.original_size == other.original_size
            && self.compressed_size == other.compressed_size
    }
}

impl Eq for CompressionInfo {}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum CompressionAlgorithm {
    None,
    LZ4,
    Flate2,
    Blake3Delta,
}

impl PartialEq for CompressionAlgorithm {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (CompressionAlgorithm::None, CompressionAlgorithm::None) => true,
            (CompressionAlgorithm::LZ4, CompressionAlgorithm::LZ4) => true,
            (CompressionAlgorithm::Flate2, CompressionAlgorithm::Flate2) => true,
            (CompressionAlgorithm::Blake3Delta, CompressionAlgorithm::Blake3Delta) => true,
            _ => false,
        }
    }
}

impl Eq for CompressionAlgorithm {}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum FraudType {
    InvalidGeometry,
    ReplayAttack,
    LocationSpoof,
    ClusteredFarm,
    RelayAttack,
    InvalidSignature,
    TimeWindowViolation,
    DensityManipulation,
}

impl PartialEq for FraudType {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (FraudType::InvalidGeometry, FraudType::InvalidGeometry) => true,
            (FraudType::ReplayAttack, FraudType::ReplayAttack) => true,
            (FraudType::LocationSpoof, FraudType::LocationSpoof) => true,
            (FraudType::ClusteredFarm, FraudType::ClusteredFarm) => true,
            (FraudType::RelayAttack, FraudType::RelayAttack) => true,
            (FraudType::InvalidSignature, FraudType::InvalidSignature) => true,
            (FraudType::TimeWindowViolation, FraudType::TimeWindowViolation) => true,
            (FraudType::DensityManipulation, FraudType::DensityManipulation) => true,
            _ => false,
        }
    }
}

impl Eq for FraudType {}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct SliceContext {
    pub slice_id: String,
    pub network_type: NetworkType,
    pub qos_requirements: QoSRequirements,
    pub authorized_nodes: Vec<Address>,
}

impl PartialEq for SliceContext {
    fn eq(&self, other: &Self) -> bool {
        self.slice_id == other.slice_id
            && self.network_type == other.network_type
            && self.qos_requirements == other.qos_requirements
            && self.authorized_nodes == other.authorized_nodes
    }
}

impl Eq for SliceContext {}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum NetworkType {
    FiveG,
    LTE,
    WiFi,
    PrivateNetwork,
}

impl PartialEq for NetworkType {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (NetworkType::FiveG, NetworkType::FiveG) => true,
            (NetworkType::LTE, NetworkType::LTE) => true,
            (NetworkType::WiFi, NetworkType::WiFi) => true,
            (NetworkType::PrivateNetwork, NetworkType::PrivateNetwork) => true,
            _ => false,
        }
    }
}

impl Eq for NetworkType {}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct QoSRequirements {
    pub max_latency_ms: u32,
    pub min_bandwidth_mbps: u32,
    pub reliability_percentage: f32,
    pub priority_level: u8,
}

impl PartialEq for QoSRequirements {
    fn eq(&self, other: &Self) -> bool {
        self.max_latency_ms == other.max_latency_ms
            && self.min_bandwidth_mbps == other.min_bandwidth_mbps
            && (self.reliability_percentage - other.reliability_percentage).abs() < f32::EPSILON
            && self.priority_level == other.priority_level
    }
}

impl Eq for QoSRequirements {}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PoCBatch {
    pub batch_id: String,
    pub operations: Vec<PoCOperation>,
    pub created_at: Timestamp,
    pub compressed_data: Option<Vec<u8>>,
    pub compression_info: Option<CompressionInfo>,
}

impl PartialEq for PoCBatch {
    fn eq(&self, other: &Self) -> bool {
        self.batch_id == other.batch_id
            && self.operations == other.operations
            && self.created_at == other.created_at
    }
}

impl Eq for PoCBatch {}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum PoCOperation {
    BeaconTransmission {
        beacon_id: String,
        h3_cell: String,
        tx_power: i16,
        frequency: u32,
    },
    WitnessObservation {
        witness_id: String,
        beacon_id: String,
        metrics: RFMetrics,
    },
    CoverageVerification {
        area_id: String,
        quality_score: f64,
        witness_count: u32,
    },
}

impl PartialEq for PoCOperation {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                PoCOperation::BeaconTransmission {
                    beacon_id: b1,
                    h3_cell: h1,
                    tx_power: p1,
                    frequency: f1,
                },
                PoCOperation::BeaconTransmission {
                    beacon_id: b2,
                    h3_cell: h2,
                    tx_power: p2,
                    frequency: f2,
                },
            ) => b1 == b2 && h1 == h2 && p1 == p2 && f1 == f2,
            (
                PoCOperation::WitnessObservation {
                    witness_id: w1,
                    beacon_id: b1,
                    metrics: m1,
                },
                PoCOperation::WitnessObservation {
                    witness_id: w2,
                    beacon_id: b2,
                    metrics: m2,
                },
            ) => w1 == w2 && b1 == b2 && m1 == m2,
            (
                PoCOperation::CoverageVerification {
                    area_id: a1,
                    quality_score: q1,
                    witness_count: w1,
                },
                PoCOperation::CoverageVerification {
                    area_id: a2,
                    quality_score: q2,
                    witness_count: w2,
                },
            ) => a1 == a2 && (q1 - q2).abs() < f64::EPSILON && w1 == w2,
            _ => false,
        }
    }
}

impl Eq for PoCOperation {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoCNetworkStats {
    pub active_beacons: u32,
    pub active_witnesses: u32,
    pub total_coverage_hexes: u32,
    pub avg_witnesses_per_beacon: f32,
    pub network_quality_score: f64,
    pub fraud_detection_rate: f32,
    pub last_updated: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DRSMetrics {
    pub node_id: Address,
    pub uptime_score: f64,
    pub proof_success_rate: f64,
    pub witness_accuracy: f64,
    pub coverage_contribution: f64,
    pub fraud_incidents: u32,
    pub reputation_score: f64,
    pub last_updated: Timestamp,
}

impl PartialEq for DRSMetrics {
    fn eq(&self, other: &Self) -> bool {
        self.node_id == other.node_id
            && (self.uptime_score - other.uptime_score).abs() < f64::EPSILON
            && (self.reputation_score - other.reputation_score).abs() < f64::EPSILON
    }
}

impl Eq for DRSMetrics {}

impl Default for CompressionInfo {
    fn default() -> Self {
        Self {
            algorithm: CompressionAlgorithm::None,
            original_size: 0,
            compressed_size: 0,
            compression_ratio: 1.0,
        }
    }
}

impl Default for QoSRequirements {
    fn default() -> Self {
        Self {
            max_latency_ms: 10,
            min_bandwidth_mbps: 100,
            reliability_percentage: 99.9,
            priority_level: 1,
        }
    }
}

impl Default for CoverageQuality {
    fn default() -> Self {
        Self {
            witness_count: 0,
            avg_rsrp: -100.0,
            coverage_radius_km: 0.0,
            interference_level: 0.0,
            quality_score: 0.0,
            density_penalty: 0.0,
        }
    }
}
