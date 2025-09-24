use super::{
    PerformanceTier, SectorHealth, SectorInfo, Storage, StorageMetrics, StorageProvider,
    StorageType,
};
use crate::error::{PoCError, PoCResult};
use ego_core::{Address, Hash, KeyPair, Timestamp};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::time::{Duration, interval};
use tracing::{debug, info, warn};

pub struct StorageProviderNode {
    keypair: Arc<KeyPair>,
    provider: StorageProvider,
    sectors: Arc<RwLock<HashMap<u64, SectorInfo>>>,
    storage_metrics: Arc<RwLock<StorageMetrics>>,
    data_store: Arc<RwLock<HashMap<u64, Vec<u8>>>>,
    health_monitor: HealthMonitor,
}

#[derive(Debug, Clone)]
struct HealthMonitor {
    check_interval_secs: u64,
    error_threshold: f64,
    recovery_time_secs: u64,
    last_check: Timestamp,
}

impl StorageProviderNode {
    pub fn new(
        keypair: KeyPair,
        total_capacity: u64,
        geographic_region: String,
        storage_type: StorageType,
        performance_tier: PerformanceTier,
    ) -> Self {
        let provider_id = Address::from_public_key(&keypair.public_key());
        let provider = StorageProvider::new(
            provider_id,
            total_capacity,
            geographic_region,
            storage_type,
            performance_tier,
        );

        let health_monitor = HealthMonitor {
            check_interval_secs: 300,
            error_threshold: 0.05,
            recovery_time_secs: 3600,
            last_check: Timestamp::now(),
        };

        Self {
            keypair: Arc::new(keypair),
            provider,
            sectors: Arc::new(RwLock::new(HashMap::new())),
            storage_metrics: Arc::new(RwLock::new(StorageMetrics::default())),
            data_store: Arc::new(RwLock::new(HashMap::new())),
            health_monitor,
        }
    }

    pub async fn start(&mut self) -> PoCResult<()> {
        info!(
            "Starting storage provider {} with {} GB capacity",
            self.provider.provider_id,
            self.provider.total_capacity / (1024 * 1024 * 1024)
        );

        self.start_health_monitoring().await?;
        self.start_metrics_collection().await?;

        info!(
            "✅ Storage provider {} started successfully",
            self.provider.provider_id
        );
        Ok(())
    }

    pub async fn stop(&mut self) -> PoCResult<()> {
        info!("Stopping storage provider {}", self.provider.provider_id);

        self.finalize_sectors().await?;

        info!("✅ Storage provider {} stopped", self.provider.provider_id);
        Ok(())
    }

    async fn start_health_monitoring(&self) -> PoCResult<()> {
        let sectors = self.sectors.clone();
        let storage_metrics = self.storage_metrics.clone();
        let provider_id = self.provider.provider_id;
        let check_interval = self.health_monitor.check_interval_secs;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(check_interval));

            loop {
                interval.tick().await;

                let sector_count = {
                    let sectors_lock = sectors.read().unwrap();
                    sectors_lock.len()
                };

                debug!(
                    "Health check for {} sectors (provider {})",
                    sector_count, provider_id
                );

                let mut failed_sectors = 0;
                {
                    let mut sectors_lock = sectors.write().unwrap();

                    for (sector_id, sector_info) in sectors_lock.iter_mut() {
                        if rand::random::<f64>() < 0.001 {
                            sector_info.set_health_status(SectorHealth::Failed);
                            failed_sectors += 1;
                            warn!(
                                "Sector {} marked as failed (provider {})",
                                sector_id, provider_id
                            );
                        }
                    }
                }

                {
                    let mut metrics = storage_metrics.write().unwrap();
                    if sector_count > 0 {
                        metrics.error_rate = failed_sectors as f64 / sector_count as f64;
                    }
                    metrics.last_updated = Timestamp::now();
                }
            }
        });

        Ok(())
    }

    async fn start_metrics_collection(&self) -> PoCResult<()> {
        let storage_metrics = self.storage_metrics.clone();
        let provider_id = self.provider.provider_id;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60));

            loop {
                interval.tick().await;

                let mut metrics = storage_metrics.write().unwrap();

                metrics.read_iops = rand::random::<u64>() % 10000 + 1000;
                metrics.write_iops = rand::random::<u64>() % 5000 + 500;
                metrics.read_latency_ms = (rand::random::<f64>() * 10.0) + 1.0;
                metrics.write_latency_ms = (rand::random::<f64>() * 20.0) + 5.0;
                metrics.throughput_mbps = (rand::random::<f64>() * 1000.0) + 100.0;
                metrics.uptime_percentage = 99.0 + (rand::random::<f64>() * 1.0);
                metrics.last_updated = Timestamp::now();

                debug!(
                    "Updated storage metrics (provider {}): IOPS R/W {}/{}, Latency {:.1}/{:.1}ms",
                    provider_id,
                    metrics.read_iops,
                    metrics.write_iops,
                    metrics.read_latency_ms,
                    metrics.write_latency_ms
                );
            }
        });

        Ok(())
    }

    async fn finalize_sectors(&mut self) -> PoCResult<()> {
        let sectors: Vec<SectorInfo> = {
            let mut sectors_lock = self.sectors.write().unwrap();
            sectors_lock.drain().map(|(_, info)| info).collect()
        };

        for sector in sectors {
            if !sector.is_healthy() {
                warn!(
                    "Sector {} was unhealthy during shutdown (provider {})",
                    sector.sector_id, self.provider.provider_id
                );
            }
        }

        Ok(())
    }

    pub fn get_provider_info(&self) -> StorageProvider {
        self.provider.clone()
    }

    pub fn get_sector_count(&self) -> u32 {
        self.sectors.read().unwrap().len() as u32
    }

    pub fn get_healthy_sectors(&self) -> Vec<u64> {
        self.sectors
            .read()
            .unwrap()
            .iter()
            .filter(|(_, info)| info.is_healthy())
            .map(|(sector_id, _)| *sector_id)
            .collect()
    }

    pub fn get_failed_sectors(&self) -> Vec<u64> {
        self.sectors
            .read()
            .unwrap()
            .iter()
            .filter(|(_, info)| matches!(info.health_status, SectorHealth::Failed))
            .map(|(sector_id, _)| *sector_id)
            .collect()
    }

    async fn simulate_storage_operation(
        &self,
        operation: &str,
        size_bytes: u64,
    ) -> PoCResult<Duration> {
        let base_latency_ms = match self.provider.storage_type {
            StorageType::NVMe => 1,
            StorageType::SSD => 5,
            StorageType::HDD => 50,
            StorageType::Hybrid => 10,
        };

        let size_factor = (size_bytes / (1024 * 1024)).max(1);
        let operation_multiplier = match operation {
            "read" => 1.0,
            "write" => 1.5,
            "delete" => 0.5,
            _ => 1.0,
        };

        let total_latency_ms =
            (base_latency_ms as f64 * size_factor as f64 * operation_multiplier) as u64;
        let duration = Duration::from_millis(total_latency_ms.min(5000));

        tokio::time::sleep(duration).await;
        Ok(duration)
    }
}

impl Storage for StorageProviderNode {
    fn provider_id(&self) -> Address {
        self.provider.provider_id
    }

    fn get_capacity(&self) -> (u64, u64) {
        (self.provider.total_capacity, self.provider.used_capacity)
    }

    async fn store_sector(&mut self, sector_id: u64, data: Vec<u8>) -> PoCResult<Hash> {
        debug!(
            "Storing sector {} with {} bytes (provider {})",
            sector_id,
            data.len(),
            self.provider.provider_id
        );

        if !self.provider.can_store(data.len() as u64) {
            return Err(PoCError::ValidationFailed(
                "Insufficient storage capacity".to_string(),
            ));
        }

        let duration = self
            .simulate_storage_operation("write", data.len() as u64)
            .await?;

        let unsealed_cid = ego_core::crypto::hash_data(&data);
        let sealed_cid =
            ego_core::crypto::hash_multiple(&[unsealed_cid.as_bytes(), &sector_id.to_le_bytes()]);

        let replica_id = Hash::new([sector_id as u8; 32]);
        let sector_info = SectorInfo::new(
            sector_id,
            data.len() as u64,
            replica_id,
            vec![],
            sealed_cid,
            unsealed_cid,
        );

        {
            let mut sectors_lock = self.sectors.write().unwrap();
            sectors_lock.insert(sector_id, sector_info);
        }

        {
            let mut data_store = self.data_store.write().unwrap();
            data_store.insert(sector_id, data);
        }

        self.provider.add_sector(data.len() as u64)?;

        {
            let mut metrics = self.storage_metrics.write().unwrap();
            metrics.write_iops += 1;
            metrics.write_latency_ms = duration.as_millis() as f64;
            metrics.last_updated = Timestamp::now();
        }

        info!(
            "✅ Stored sector {} (provider {})",
            sector_id, self.provider.provider_id
        );
        Ok(sealed_cid)
    }

    async fn retrieve_sector(&self, sector_id: u64) -> PoCResult<Vec<u8>> {
        debug!(
            "Retrieving sector {} (provider {})",
            sector_id, self.provider.provider_id
        );

        let sector_info = {
            let sectors_lock = self.sectors.read().unwrap();
            sectors_lock.get(&sector_id).cloned()
        };

        let sector_info = sector_info
            .ok_or_else(|| PoCError::ValidationFailed("Sector not found".to_string()))?;

        if !sector_info.is_healthy() {
            return Err(PoCError::ValidationFailed(
                "Sector is not healthy".to_string(),
            ));
        }

        let duration = self
            .simulate_storage_operation("read", sector_info.size_bytes)
            .await?;

        let data = {
            let data_store = self.data_store.read().unwrap();
            data_store.get(&sector_id).cloned()
        };

        let data =
            data.ok_or_else(|| PoCError::ValidationFailed("Sector data not found".to_string()))?;

        {
            let mut sectors_lock = self.sectors.write().unwrap();
            if let Some(info) = sectors_lock.get_mut(&sector_id) {
                info.update_access_time();
            }
        }

        {
            let mut metrics = self.storage_metrics.write().unwrap();
            metrics.read_iops += 1;
            metrics.read_latency_ms = duration.as_millis() as f64;
            metrics.last_updated = Timestamp::now();
        }

        info!(
            "✅ Retrieved sector {} (provider {})",
            sector_id, self.provider.provider_id
        );
        Ok(data)
    }

    async fn delete_sector(&mut self, sector_id: u64) -> PoCResult<()> {
        debug!(
            "Deleting sector {} (provider {})",
            sector_id, self.provider.provider_id
        );

        let sector_info = {
            let mut sectors_lock = self.sectors.write().unwrap();
            sectors_lock.remove(&sector_id)
        };

        if let Some(info) = sector_info {
            let duration = self
                .simulate_storage_operation("delete", info.size_bytes)
                .await?;

            {
                let mut data_store = self.data_store.write().unwrap();
                data_store.remove(&sector_id);
            }

            self.provider.remove_sector(info.size_bytes);

            {
                let mut metrics = self.storage_metrics.write().unwrap();
                metrics.write_iops += 1;
                metrics.write_latency_ms = duration.as_millis() as f64;
                metrics.last_updated = Timestamp::now();
            }

            info!(
                "✅ Deleted sector {} (provider {})",
                sector_id, self.provider.provider_id
            );
        }

        Ok(())
    }

    async fn get_sector_info(&self, sector_id: u64) -> PoCResult<Option<SectorInfo>> {
        let sectors_lock = self.sectors.read().unwrap();
        Ok(sectors_lock.get(&sector_id).cloned())
    }

    fn get_storage_metrics(&self) -> StorageMetrics {
        self.storage_metrics.read().unwrap().clone()
    }

    async fn health_check(&self) -> PoCResult<bool> {
        debug!(
            "Performing health check (provider {})",
            self.provider.provider_id
        );

        let sectors_lock = self.sectors.read().unwrap();
        let total_sectors = sectors_lock.len();
        let failed_sectors = sectors_lock
            .values()
            .filter(|info| matches!(info.health_status, SectorHealth::Failed))
            .count();

        let failure_rate = if total_sectors > 0 {
            failed_sectors as f64 / total_sectors as f64
        } else {
            0.0
        };

        let is_healthy = failure_rate < self.health_monitor.error_threshold;

        if !is_healthy {
            warn!(
                "Storage provider {} health check failed: {:.1}% sectors failed",
                self.provider.provider_id,
                failure_rate * 100.0
            );
        }

        Ok(is_healthy)
    }

    pub async fn repair_sector(&mut self, sector_id: u64) -> PoCResult<()> {
        info!(
            "Starting repair for sector {} (provider {})",
            sector_id, self.provider.provider_id
        );

        {
            let mut sectors_lock = self.sectors.write().unwrap();
            if let Some(sector_info) = sectors_lock.get_mut(&sector_id) {
                sector_info.set_health_status(SectorHealth::Recovering);
            }
        }

        let repair_duration = match self.provider.performance_tier {
            PerformanceTier::Enterprise => Duration::from_secs(1800),
            PerformanceTier::Consumer => Duration::from_secs(3600),
            PerformanceTier::Archive => Duration::from_secs(7200),
        };

        tokio::time::sleep(repair_duration).await;

        {
            let mut sectors_lock = self.sectors.write().unwrap();
            if let Some(sector_info) = sectors_lock.get_mut(&sector_id) {
                sector_info.set_health_status(SectorHealth::Healthy);
            }
        }

        info!(
            "✅ Completed repair for sector {} (provider {})",
            sector_id, self.provider.provider_id
        );
        Ok(())
    }

    pub fn get_storage_summary(&self) -> StorageSummary {
        let sectors_lock = self.sectors.read().unwrap();
        let metrics = self.storage_metrics.read().unwrap();

        let healthy_sectors = sectors_lock
            .values()
            .filter(|info| info.is_healthy())
            .count() as u32;

        let failed_sectors = sectors_lock
            .values()
            .filter(|info| matches!(info.health_status, SectorHealth::Failed))
            .count() as u32;

        StorageSummary {
            provider_id: self.provider.provider_id,
            total_capacity: self.provider.total_capacity,
            used_capacity: self.provider.used_capacity,
            total_sectors: sectors_lock.len() as u32,
            healthy_sectors,
            failed_sectors,
            reputation_score: self.provider.reputation_score,
            avg_read_latency_ms: metrics.read_latency_ms,
            avg_write_latency_ms: metrics.write_latency_ms,
            uptime_percentage: metrics.uptime_percentage,
            last_updated: Timestamp::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageSummary {
    pub provider_id: Address,
    pub total_capacity: u64,
    pub used_capacity: u64,
    pub total_sectors: u32,
    pub healthy_sectors: u32,
    pub failed_sectors: u32,
    pub reputation_score: f64,
    pub avg_read_latency_ms: f64,
    pub avg_write_latency_ms: f64,
    pub uptime_percentage: f64,
    pub last_updated: Timestamp,
}

impl Storage for StorageProviderNode {
    fn provider_id(&self) -> Address {
        self.provider.provider_id
    }

    fn get_capacity(&self) -> (u64, u64) {
        (self.provider.total_capacity, self.provider.used_capacity)
    }

    async fn store_sector(&mut self, sector_id: u64, data: Vec<u8>) -> PoCResult<Hash> {
        self.store_sector(sector_id, data).await
    }

    async fn retrieve_sector(&self, sector_id: u64) -> PoCResult<Vec<u8>> {
        self.retrieve_sector(sector_id).await
    }

    async fn delete_sector(&mut self, sector_id: u64) -> PoCResult<()> {
        self.delete_sector(sector_id).await
    }

    async fn get_sector_info(&self, sector_id: u64) -> PoCResult<Option<SectorInfo>> {
        self.get_sector_info(sector_id).await
    }

    fn get_storage_metrics(&self) -> StorageMetrics {
        self.get_storage_metrics()
    }

    async fn health_check(&self) -> PoCResult<bool> {
        self.health_check().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::KeyPair;

    #[tokio::test]
    async fn test_storage_provider_creation() {
        let keypair = KeyPair::generate();
        let provider = StorageProviderNode::new(
            keypair,
            1024 * 1024 * 1024 * 1024,
            "us-west-1".to_string(),
            StorageType::NVMe,
            PerformanceTier::Enterprise,
        );

        assert_eq!(provider.provider.total_capacity, 1024 * 1024 * 1024 * 1024);
        assert_eq!(provider.get_sector_count(), 0);
    }

    #[tokio::test]
    async fn test_sector_storage_lifecycle() {
        let keypair = KeyPair::generate();
        let mut provider = StorageProviderNode::new(
            keypair,
            1024 * 1024 * 1024,
            "us-west-1".to_string(),
            StorageType::SSD,
            PerformanceTier::Consumer,
        );

        let test_data = vec![1u8; 1024 * 1024];
        let sector_id = 1;

        let sealed_cid = provider
            .store_sector(sector_id, test_data.clone())
            .await
            .unwrap();
        assert!(!sealed_cid.as_bytes().iter().all(|&b| b == 0));

        let retrieved_data = provider.retrieve_sector(sector_id).await.unwrap();
        assert_eq!(retrieved_data, test_data);

        let sector_info = provider.get_sector_info(sector_id).await.unwrap();
        assert!(sector_info.is_some());
        assert!(sector_info.unwrap().is_healthy());

        assert!(provider.delete_sector(sector_id).await.is_ok());

        let deleted_info = provider.get_sector_info(sector_id).await.unwrap();
        assert!(deleted_info.is_none());
    }

    #[tokio::test]
    async fn test_health_monitoring() {
        let keypair = KeyPair::generate();
        let provider = StorageProviderNode::new(
            keypair,
            1024 * 1024 * 1024,
            "us-west-1".to_string(),
            StorageType::NVMe,
            PerformanceTier::Enterprise,
        );

        let health_result = provider.health_check().await.unwrap();
        assert!(health_result);
    }

    #[tokio::test]
    async fn test_capacity_management() {
        let keypair = KeyPair::generate();
        let mut provider = StorageProviderNode::new(
            keypair,
            1024 * 1024,
            "us-west-1".to_string(),
            StorageType::SSD,
            PerformanceTier::Consumer,
        );

        let large_data = vec![0u8; 2 * 1024 * 1024];
        let result = provider.store_sector(1, large_data).await;
        assert!(result.is_err());

        let small_data = vec![0u8; 512 * 1024];
        let result = provider.store_sector(1, small_data).await;
        assert!(result.is_ok());
    }
}
