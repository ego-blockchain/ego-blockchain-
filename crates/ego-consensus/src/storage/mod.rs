use crate::error::PoCResult;
use ego_core::{Address, Hash, Timestamp};
use serde::{Deserialize, Serialize};
use std::future::Future;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProvider {
    pub provider_id: Address,
    pub total_capacity: u64,
    pub used_capacity: u64,
    pub sector_count: u32,
    pub reputation_score: f64,
    pub geographic_region: String,
    pub storage_type: StorageType,
    pub performance_tier: PerformanceTier,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageType {
    NVMe,
    SSD,
    HDD,
    Hybrid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PerformanceTier {
    Enterprise,
    Consumer,
    Archive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageMetrics {
    pub read_iops: u64,
    pub write_iops: u64,
    pub read_latency_ms: f64,
    pub write_latency_ms: f64,
    pub throughput_mbps: f64,
    pub error_rate: f64,
    pub uptime_percentage: f64,
    pub last_updated: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectorInfo {
    pub sector_id: u64,
    pub size_bytes: u64,
    pub replica_id: Hash,
    pub deal_ids: Vec<Hash>,
    pub sealed_cid: Hash,
    pub unsealed_cid: Hash,
    pub created_at: Timestamp,
    pub last_accessed: Timestamp,
    pub health_status: SectorHealth,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SectorHealth {
    Healthy,
    Degraded,
    Failed,
    Recovering,
}

pub trait Storage: Send + Sync {
    fn provider_id(&self) -> Address;

    fn get_capacity(&self) -> (u64, u64);

    fn store_sector(
        &mut self,
        sector_id: u64,
        data: Vec<u8>,
    ) -> impl Future<Output = PoCResult<Hash>> + Send;

    fn retrieve_sector(&self, sector_id: u64) -> impl Future<Output = PoCResult<Vec<u8>>> + Send;

    fn delete_sector(&mut self, sector_id: u64) -> impl Future<Output = PoCResult<()>> + Send;

    fn get_sector_info(
        &self,
        sector_id: u64,
    ) -> impl Future<Output = PoCResult<Option<SectorInfo>>> + Send;

    fn get_storage_metrics(&self) -> StorageMetrics;

    fn health_check(&self) -> impl Future<Output = PoCResult<bool>> + Send;
}

impl StorageProvider {
    pub fn new(
        provider_id: Address,
        total_capacity: u64,
        geographic_region: String,
        storage_type: StorageType,
        performance_tier: PerformanceTier,
    ) -> Self {
        Self {
            provider_id,
            total_capacity,
            used_capacity: 0,
            sector_count: 0,
            reputation_score: 1.0,
            geographic_region,
            storage_type,
            performance_tier,
        }
    }

    pub fn utilization(&self) -> f64 {
        if self.total_capacity == 0 {
            0.0
        } else {
            self.used_capacity as f64 / self.total_capacity as f64
        }
    }

    pub fn available_capacity(&self) -> u64 {
        self.total_capacity.saturating_sub(self.used_capacity)
    }

    pub fn can_store(&self, size_bytes: u64) -> bool {
        self.available_capacity() >= size_bytes
    }

    pub fn add_sector(&mut self, size_bytes: u64) -> PoCResult<()> {
        if !self.can_store(size_bytes) {
            return Err(crate::error::PoCError::ValidationFailed(
                "Insufficient storage capacity".to_string(),
            ));
        }

        self.used_capacity += size_bytes;
        self.sector_count += 1;
        Ok(())
    }

    pub fn remove_sector(&mut self, size_bytes: u64) {
        self.used_capacity = self.used_capacity.saturating_sub(size_bytes);
        self.sector_count = self.sector_count.saturating_sub(1);
    }

    pub fn update_reputation(&mut self, score_delta: f64) {
        self.reputation_score = (self.reputation_score + score_delta).clamp(0.0, 1.0);
    }
}

impl SectorInfo {
    pub fn new(
        sector_id: u64,
        size_bytes: u64,
        replica_id: Hash,
        deal_ids: Vec<Hash>,
        sealed_cid: Hash,
        unsealed_cid: Hash,
    ) -> Self {
        let now = Timestamp::now();

        Self {
            sector_id,
            size_bytes,
            replica_id,
            deal_ids,
            sealed_cid,
            unsealed_cid,
            created_at: now,
            last_accessed: now,
            health_status: SectorHealth::Healthy,
        }
    }

    pub fn update_access_time(&mut self) {
        self.last_accessed = Timestamp::now();
    }

    pub fn set_health_status(&mut self, status: SectorHealth) {
        self.health_status = status;
    }

    pub fn is_healthy(&self) -> bool {
        matches!(self.health_status, SectorHealth::Healthy)
    }

    pub fn age_hours(&self) -> u64 {
        (Timestamp::now().as_millis() - self.created_at.as_millis()) / 3_600_000
    }
}

impl Default for StorageMetrics {
    fn default() -> Self {
        Self {
            read_iops: 0,
            write_iops: 0,
            read_latency_ms: 0.0,
            write_latency_ms: 0.0,
            throughput_mbps: 0.0,
            error_rate: 0.0,
            uptime_percentage: 100.0,
            last_updated: Timestamp::now(),
        }
    }
}

impl PartialEq for StorageProvider {
    fn eq(&self, other: &Self) -> bool {
        self.provider_id == other.provider_id
            && self.total_capacity == other.total_capacity
            && self.geographic_region == other.geographic_region
    }
}

impl Eq for StorageProvider {}

impl PartialEq for SectorInfo {
    fn eq(&self, other: &Self) -> bool {
        self.sector_id == other.sector_id
            && self.replica_id == other.replica_id
            && self.sealed_cid == other.sealed_cid
    }
}

impl Eq for SectorInfo {}

impl PartialEq for StorageType {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (StorageType::NVMe, StorageType::NVMe) => true,
            (StorageType::SSD, StorageType::SSD) => true,
            (StorageType::HDD, StorageType::HDD) => true,
            (StorageType::Hybrid, StorageType::Hybrid) => true,
            _ => false,
        }
    }
}

impl Eq for StorageType {}

impl PartialEq for PerformanceTier {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (PerformanceTier::Enterprise, PerformanceTier::Enterprise) => true,
            (PerformanceTier::Consumer, PerformanceTier::Consumer) => true,
            (PerformanceTier::Archive, PerformanceTier::Archive) => true,
            _ => false,
        }
    }
}

impl Eq for PerformanceTier {}

impl PartialEq for SectorHealth {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (SectorHealth::Healthy, SectorHealth::Healthy) => true,
            (SectorHealth::Degraded, SectorHealth::Degraded) => true,
            (SectorHealth::Failed, SectorHealth::Failed) => true,
            (SectorHealth::Recovering, SectorHealth::Recovering) => true,
            _ => false,
        }
    }
}

impl Eq for SectorHealth {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_provider_creation() {
        let provider = StorageProvider::new(
            Address::new([1u8; 20]),
            1024 * 1024 * 1024 * 1024,
            "us-west-1".to_string(),
            StorageType::NVMe,
            PerformanceTier::Enterprise,
        );

        assert_eq!(provider.total_capacity, 1024 * 1024 * 1024 * 1024);
        assert_eq!(provider.utilization(), 0.0);
        assert!(provider.can_store(1024 * 1024));
    }

    #[test]
    fn test_sector_management() {
        let mut provider = StorageProvider::new(
            Address::new([1u8; 20]),
            1024 * 1024 * 1024,
            "us-west-1".to_string(),
            StorageType::SSD,
            PerformanceTier::Consumer,
        );

        assert!(provider.add_sector(512 * 1024 * 1024).is_ok());
        assert_eq!(provider.sector_count, 1);
        assert_eq!(provider.used_capacity, 512 * 1024 * 1024);

        provider.remove_sector(512 * 1024 * 1024);
        assert_eq!(provider.sector_count, 0);
        assert_eq!(provider.used_capacity, 0);
    }

    #[test]
    fn test_sector_info() {
        let sector = SectorInfo::new(
            1,
            32 * 1024 * 1024 * 1024,
            Hash::new([1u8; 32]),
            vec![Hash::new([2u8; 32])],
            Hash::new([3u8; 32]),
            Hash::new([4u8; 32]),
        );

        assert_eq!(sector.sector_id, 1);
        assert!(sector.is_healthy());
        assert_eq!(sector.deal_ids.len(), 1);
    }
}
