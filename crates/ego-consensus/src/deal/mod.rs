use crate::error::PoCResult;
use ego_core::{Address, Hash, Timestamp};
use serde::{Deserialize, Serialize};
use std::future::Future;

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct Deal {
    pub deal_id: Hash,
    pub client_addr: Address,
    pub size_bytes: u64,
    pub duration_epochs: u64,
    pub price_rate: u64,
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub triad: [StorageProvider; 3],
    pub escrow: u128,
    pub params_hash: Hash,
    pub status: DealStatus,
    pub created_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct StorageProvider {
    pub node_addr: Address,
    pub sector_ids: Vec<u64>,
    pub capacity_bytes: u64,
    pub utilization: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum DealStatus {
    Pending,
    Active,
    Completed,
    Failed,
    Expired,
    Slashed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DealMetrics {
    pub active_deals: u64,
    pub total_storage_bytes: u64,
    pub successful_proofs: u64,
    pub failed_proofs: u64,
    pub repair_events: u32,
    pub slash_events: u32,
    pub last_updated: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProof {
    pub sector_id: u64,
    pub proof_type: StorageProofType,
    pub proof_data: Vec<u8>,
    pub timestamp: Timestamp,
    pub node_addr: Address,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageProofType {
    PoRep,
    PoSt,
    Repair,
}

pub trait DealHandler: Send + Sync {
    fn create_deal(&mut self, deal: Deal) -> impl Future<Output = PoCResult<Hash>> + Send;
    fn activate_deal(&mut self, deal_id: Hash) -> impl Future<Output = PoCResult<()>> + Send;
    fn verify_storage(&self, deal_id: Hash) -> impl Future<Output = PoCResult<bool>> + Send;
    fn handle_storage_failure(
        &mut self,
        deal_id: Hash,
        node_addr: Address,
    ) -> impl Future<Output = PoCResult<()>> + Send;
    fn calculate_rewards(&self, deal_id: Hash) -> impl Future<Output = PoCResult<u128>> + Send;
}

impl Deal {
    pub fn new(
        client_addr: Address,
        size_bytes: u64,
        duration_epochs: u64,
        price_rate: u64,
        triad: [StorageProvider; 3],
    ) -> Self {
        let start_epoch = Timestamp::now().as_secs() / 3600;
        let end_epoch = start_epoch + duration_epochs;
        let escrow = (price_rate as u128) * (duration_epochs as u128);

        let deal_id = Self::compute_deal_id(client_addr, size_bytes, start_epoch, &triad);
        let params_hash = Self::compute_params_hash(size_bytes, duration_epochs, price_rate);

        Self {
            deal_id,
            client_addr,
            size_bytes,
            duration_epochs,
            price_rate,
            start_epoch,
            end_epoch,
            triad,
            escrow,
            params_hash,
            status: DealStatus::Pending,
            created_at: Timestamp::now(),
        }
    }

    pub fn validate(&self) -> PoCResult<()> {
        if self.size_bytes == 0 {
            return Err(crate::error::PoCError::ValidationFailed(
                "Deal size cannot be zero".to_string(),
            ));
        }

        if self.duration_epochs == 0 {
            return Err(crate::error::PoCError::ValidationFailed(
                "Deal duration cannot be zero".to_string(),
            ));
        }

        if self.start_epoch >= self.end_epoch {
            return Err(crate::error::PoCError::ValidationFailed(
                "Invalid epoch range".to_string(),
            ));
        }

        if self.triad.len() != 3 {
            return Err(crate::error::PoCError::ValidationFailed(
                "Deal must have exactly 3 storage providers".to_string(),
            ));
        }

        Ok(())
    }

    fn compute_deal_id(
        client_addr: Address,
        size_bytes: u64,
        start_epoch: u64,
        triad: &[StorageProvider; 3],
    ) -> Hash {
        use ego_core::crypto::hash_data;

        let mut data = Vec::new();
        data.extend_from_slice(client_addr.as_bytes());
        data.extend_from_slice(&size_bytes.to_le_bytes());
        data.extend_from_slice(&start_epoch.to_le_bytes());

        for provider in triad {
            data.extend_from_slice(provider.node_addr.as_bytes());
        }

        hash_data(&data)
    }

    fn compute_params_hash(size_bytes: u64, duration_epochs: u64, price_rate: u64) -> Hash {
        use ego_core::crypto::hash_data;

        let mut data = Vec::new();
        data.extend_from_slice(&size_bytes.to_le_bytes());
        data.extend_from_slice(&duration_epochs.to_le_bytes());
        data.extend_from_slice(&price_rate.to_le_bytes());

        hash_data(&data)
    }
}

impl Default for DealMetrics {
    fn default() -> Self {
        Self {
            active_deals: 0,
            total_storage_bytes: 0,
            successful_proofs: 0,
            failed_proofs: 0,
            repair_events: 0,
            slash_events: 0,
            last_updated: Timestamp::now(),
        }
    }
}

impl PartialEq for Deal {
    fn eq(&self, other: &Self) -> bool {
        self.deal_id == other.deal_id
            && self.client_addr == other.client_addr
            && self.size_bytes == other.size_bytes
    }
}

impl Eq for Deal {}

impl PartialEq for StorageProvider {
    fn eq(&self, other: &Self) -> bool {
        self.node_addr == other.node_addr && self.sector_ids == other.sector_ids
    }
}

impl Eq for StorageProvider {}

impl PartialEq for DealStatus {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (DealStatus::Pending, DealStatus::Pending) => true,
            (DealStatus::Active, DealStatus::Active) => true,
            (DealStatus::Completed, DealStatus::Completed) => true,
            (DealStatus::Failed, DealStatus::Failed) => true,
            (DealStatus::Expired, DealStatus::Expired) => true,
            (DealStatus::Slashed, DealStatus::Slashed) => true,
            _ => false,
        }
    }
}

impl Eq for DealStatus {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deal_creation() {
        let client_addr = Address::new([1u8; 20]);
        let triad = [
            StorageProvider {
                node_addr: Address::new([2u8; 20]),
                sector_ids: vec![1, 2, 3],
                capacity_bytes: 1024 * 1024 * 1024,
                utilization: 0.5,
            },
            StorageProvider {
                node_addr: Address::new([3u8; 20]),
                sector_ids: vec![4, 5, 6],
                capacity_bytes: 1024 * 1024 * 1024,
                utilization: 0.6,
            },
            StorageProvider {
                node_addr: Address::new([4u8; 20]),
                sector_ids: vec![7, 8, 9],
                capacity_bytes: 1024 * 1024 * 1024,
                utilization: 0.4,
            },
        ];

        let deal = Deal::new(client_addr, 1024 * 1024, 100, 1000, triad);

        assert_eq!(deal.client_addr, client_addr);
        assert_eq!(deal.size_bytes, 1024 * 1024);
        assert_eq!(deal.triad.len(), 3);
        assert!(deal.validate().is_ok());
    }

    #[test]
    fn test_deal_validation() {
        let client_addr = Address::new([1u8; 20]);
        let triad = [
            StorageProvider {
                node_addr: Address::new([2u8; 20]),
                sector_ids: vec![1],
                capacity_bytes: 1024,
                utilization: 0.0,
            },
            StorageProvider {
                node_addr: Address::new([3u8; 20]),
                sector_ids: vec![2],
                capacity_bytes: 1024,
                utilization: 0.0,
            },
            StorageProvider {
                node_addr: Address::new([4u8; 20]),
                sector_ids: vec![3],
                capacity_bytes: 1024,
                utilization: 0.0,
            },
        ];

        let mut deal = Deal::new(client_addr, 1024, 100, 1000, triad);
        assert!(deal.validate().is_ok());

        deal.size_bytes = 0;
        assert!(deal.validate().is_err());
    }
}
