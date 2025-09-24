use super::{Deal, DealHandler, DealMetrics, DealStatus, StorageProof};
use crate::error::{PoCError, PoCResult};
use crate::porep::PoRepProof;
use crate::post::PoStProof;
use ego_core::{Address, Hash, KeyPair, Timestamp};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

pub struct DealManager {
    keypair: Arc<KeyPair>,
    address: Address,
    active_deals: Arc<RwLock<HashMap<Hash, Deal>>>,
    deal_metrics: Arc<RwLock<DealMetrics>>,
    porep_sender: Option<mpsc::UnboundedSender<PoRepProof>>,
    post_sender: Option<mpsc::UnboundedSender<PoStProof>>,
    storage_verifier: Arc<StorageVerifier>,
}

pub struct StorageVerifier {
    sector_size: u64,
    replica_count: u32,
    proof_timeout_ms: u64,
}

impl DealManager {
    pub fn new(keypair: KeyPair, sector_size: u64, replica_count: u32) -> Self {
        let address = Address::from_public_key(&keypair.public_key());

        Self {
            keypair: Arc::new(keypair),
            address,
            active_deals: Arc::new(RwLock::new(HashMap::new())),
            deal_metrics: Arc::new(RwLock::new(DealMetrics::default())),
            porep_sender: None,
            post_sender: None,
            storage_verifier: Arc::new(StorageVerifier {
                sector_size,
                replica_count,
                proof_timeout_ms: 300_000,
            }),
        }
    }

    pub async fn start(&mut self) -> PoCResult<()> {
        info!("Starting deal manager {}", self.address);

        let (porep_sender, _porep_receiver) = mpsc::unbounded_channel();
        let (post_sender, _post_receiver) = mpsc::unbounded_channel();

        self.porep_sender = Some(porep_sender);
        self.post_sender = Some(post_sender);

        self.start_deal_monitor().await?;
        self.start_storage_verification().await?;

        info!("✅ Deal manager {} started successfully", self.address);
        Ok(())
    }

    pub async fn stop(&mut self) -> PoCResult<()> {
        info!("Stopping deal manager {}", self.address);

        self.porep_sender = None;
        self.post_sender = None;

        info!("✅ Deal manager {} stopped", self.address);
        Ok(())
    }

    async fn start_deal_monitor(&self) -> PoCResult<()> {
        let active_deals = self.active_deals.clone();
        let deal_metrics = self.deal_metrics.clone();
        let address = self.address;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));

            loop {
                interval.tick().await;

                let expired_deals: Vec<Hash> = {
                    let deals = active_deals.read().unwrap();
                    let now = Timestamp::now();

                    deals
                        .iter()
                        .filter(|(_, deal)| now.as_millis() > deal.end_epoch)
                        .map(|(deal_id, _)| *deal_id)
                        .collect()
                };

                for deal_id in expired_deals {
                    debug!("Deal {} expired for manager {}", deal_id, address);

                    let mut deals = active_deals.write().unwrap();
                    if let Some(mut deal) = deals.remove(&deal_id) {
                        deal.status = DealStatus::Expired;
                        deals.insert(deal_id, deal);
                    }
                }

                let mut metrics = deal_metrics.write().unwrap();
                let deals = active_deals.read().unwrap();
                metrics.active_deals = deals.len() as u64;
                metrics.last_updated = Timestamp::now();
            }
        });

        Ok(())
    }

    async fn start_storage_verification(&self) -> PoCResult<()> {
        let active_deals = self.active_deals.clone();
        let storage_verifier = self.storage_verifier.clone();
        let address = self.address;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1800));

            loop {
                interval.tick().await;

                let deals_to_verify: Vec<(Hash, Deal)> = {
                    let deals = active_deals.read().unwrap();
                    deals
                        .iter()
                        .filter(|(_, deal)| deal.status == DealStatus::Active)
                        .map(|(id, deal)| (*id, deal.clone()))
                        .collect()
                };

                for (deal_id, deal) in deals_to_verify {
                    debug!(
                        "Verifying storage for deal {} (manager {})",
                        deal_id, address
                    );

                    if let Err(e) = storage_verifier.verify_deal_storage(&deal).await {
                        warn!("Storage verification failed for deal {}: {}", deal_id, e);

                        let mut deals = active_deals.write().unwrap();
                        if let Some(deal) = deals.get_mut(&deal_id) {
                            deal.status = DealStatus::Failed;
                        }
                    }
                }
            }
        });

        Ok(())
    }

    pub fn get_metrics(&self) -> DealMetrics {
        self.deal_metrics.read().unwrap().clone()
    }

    pub fn get_active_deals(&self) -> Vec<Deal> {
        self.active_deals
            .read()
            .unwrap()
            .values()
            .cloned()
            .collect()
    }

    fn update_metrics_after_deal_creation(&self, deal: &Deal) {
        let mut metrics = self.deal_metrics.write().unwrap();
        metrics.active_deals += 1;
        metrics.total_storage_bytes += deal.size_bytes;
        metrics.last_updated = Timestamp::now();
    }

    fn update_metrics_after_proof(&self, success: bool) {
        let mut metrics = self.deal_metrics.write().unwrap();
        if success {
            metrics.successful_proofs += 1;
        } else {
            metrics.failed_proofs += 1;
        }
        metrics.last_updated = Timestamp::now();
    }
}

impl DealHandler for DealManager {
    async fn create_deal(&mut self, mut deal: Deal) -> PoCResult<Hash> {
        debug!(
            "Creating deal with client {} (manager {})",
            deal.client_addr, self.address
        );

        deal.validate()?;

        if deal.triad.len() != 3 {
            return Err(PoCError::ValidationFailed(
                "Deal must have exactly 3 storage providers".to_string(),
            ));
        }

        deal.status = DealStatus::Pending;
        let deal_id = deal.deal_id;

        {
            let mut deals = self.active_deals.write().unwrap();
            deals.insert(deal_id, deal.clone());
        }

        self.update_metrics_after_deal_creation(&deal);

        info!(
            "✅ Created deal {} with {} bytes (manager {})",
            deal_id, deal.size_bytes, self.address
        );

        Ok(deal_id)
    }

    async fn activate_deal(&mut self, deal_id: Hash) -> PoCResult<()> {
        debug!("Activating deal {} (manager {})", deal_id, self.address);

        let mut deals = self.active_deals.write().unwrap();
        if let Some(deal) = deals.get_mut(&deal_id) {
            if deal.status == DealStatus::Pending {
                deal.status = DealStatus::Active;
                info!("✅ Activated deal {} (manager {})", deal_id, self.address);
            }
        }

        Ok(())
    }

    async fn verify_storage(&self, deal_id: Hash) -> PoCResult<bool> {
        debug!(
            "Verifying storage for deal {} (manager {})",
            deal_id, self.address
        );

        let deal = {
            let deals = self.active_deals.read().unwrap();
            deals.get(&deal_id).cloned()
        };

        if let Some(deal) = deal {
            self.storage_verifier.verify_deal_storage(&deal).await
        } else {
            Ok(false)
        }
    }

    async fn handle_storage_failure(&mut self, deal_id: Hash, node_addr: Address) -> PoCResult<()> {
        warn!(
            "Handling storage failure for deal {} node {} (manager {})",
            deal_id, node_addr, self.address
        );

        let mut deals = self.active_deals.write().unwrap();
        if let Some(deal) = deals.get_mut(&deal_id) {
            deal.status = DealStatus::Failed;
        }

        let mut metrics = self.deal_metrics.write().unwrap();
        metrics.repair_events += 1;
        metrics.last_updated = Timestamp::now();

        Ok(())
    }

    async fn calculate_rewards(&self, deal_id: Hash) -> PoCResult<u128> {
        let deal = {
            let deals = self.active_deals.read().unwrap();
            deals.get(&deal_id).cloned()
        };

        if let Some(deal) = deal {
            let current_epoch = Timestamp::now().as_secs() / 3600;
            let epochs_completed = current_epoch
                .saturating_sub(deal.start_epoch)
                .min(deal.duration_epochs);
            Ok(deal.price_rate as u128 * epochs_completed as u128)
        } else {
            Ok(0)
        }
    }
}

impl StorageVerifier {
    async fn verify_deal_storage(&self, deal: &Deal) -> PoCResult<bool> {
        for provider in &deal.triad {
            if !self.verify_provider_storage(provider).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn verify_provider_storage(&self, provider: &StorageProvider) -> PoCResult<bool> {
        if provider.sector_ids.is_empty() {
            return Ok(false);
        }

        let total_capacity = provider.sector_ids.len() as u64 * self.sector_size;
        let used_capacity = (total_capacity as f64 * provider.utilization) as u64;

        Ok(used_capacity <= total_capacity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::KeyPair;

    #[tokio::test]
    async fn test_deal_manager_creation() {
        let keypair = KeyPair::generate();
        let manager = DealManager::new(keypair, 1024 * 1024 * 32, 3);

        assert_eq!(manager.storage_verifier.replica_count, 3);
        assert_eq!(manager.storage_verifier.sector_size, 1024 * 1024 * 32);
    }

    #[tokio::test]
    async fn test_deal_lifecycle() {
        let keypair = KeyPair::generate();
        let mut manager = DealManager::new(keypair, 1024 * 1024 * 32, 3);

        let client_addr = Address::new([1u8; 20]);
        let triad = [
            super::StorageProvider {
                node_addr: Address::new([2u8; 20]),
                sector_ids: vec![1, 2],
                capacity_bytes: 1024 * 1024 * 64,
                utilization: 0.5,
            },
            super::StorageProvider {
                node_addr: Address::new([3u8; 20]),
                sector_ids: vec![3, 4],
                capacity_bytes: 1024 * 1024 * 64,
                utilization: 0.6,
            },
            super::StorageProvider {
                node_addr: Address::new([4u8; 20]),
                sector_ids: vec![5, 6],
                capacity_bytes: 1024 * 1024 * 64,
                utilization: 0.4,
            },
        ];

        let deal = Deal::new(client_addr, 1024 * 1024, 100, 1000, triad);
        let deal_id = manager.create_deal(deal).await.unwrap();

        assert!(manager.activate_deal(deal_id).await.is_ok());
        assert!(manager.verify_storage(deal_id).await.is_ok());
    }
}
