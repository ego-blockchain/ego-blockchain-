use crate::error::PoCResult;
use ego_core::{Address, Hash, Timestamp};
use serde::{Deserialize, Serialize};
use std::future::Future;

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct RepairEvent {
    pub event_id: Hash,
    pub failed_node: Address,
    pub sector_id: u64,
    pub repair_node: Address,
    pub repair_type: RepairType,
    pub repair_duration_hours: f64,
    pub success: bool,
    pub evidence_hash: Hash,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum RepairType {
    SectorRecovery,
    DataReconstruction,
    NodePromotion,
    EmergencyBackup,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairJob {
    pub job_id: Hash,
    pub failed_node: Address,
    pub affected_sectors: Vec<u64>,
    pub assigned_repair_node: Option<Address>,
    pub status: RepairStatus,
    pub priority: RepairPriority,
    pub created_at: Timestamp,
    pub deadline: Timestamp,
    pub repair_progress: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RepairStatus {
    Queued,
    InProgress,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RepairPriority {
    Critical,
    High,
    Normal,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairMetrics {
    pub total_repairs: u64,
    pub successful_repairs: u64,
    pub failed_repairs: u64,
    pub avg_repair_time_hours: f64,
    pub nodes_promoted: u32,
    pub sectors_recovered: u64,
    pub last_updated: Timestamp,
}

pub trait RepairManager: Send + Sync {
    fn manager_id(&self) -> Address;

    fn schedule_repair(
        &mut self,
        failed_node: Address,
        sector_ids: Vec<u64>,
    ) -> impl Future<Output = PoCResult<Hash>> + Send;

    fn execute_repair(
        &mut self,
        job_id: Hash,
    ) -> impl Future<Output = PoCResult<RepairEvent>> + Send;

    fn promote_node(
        &mut self,
        candidate_node: Address,
        failed_node: Address,
    ) -> impl Future<Output = PoCResult<()>> + Send;

    fn get_repair_queue(&self) -> Vec<RepairJob>;

    fn get_repair_metrics(&self) -> RepairMetrics;
}

impl RepairEvent {
    pub fn new(
        failed_node: Address,
        sector_id: u64,
        repair_node: Address,
        repair_type: RepairType,
        repair_duration_hours: f64,
        success: bool,
    ) -> Self {
        let event_id = Self::compute_event_id(failed_node, sector_id, repair_node);
        let evidence_hash = Self::compute_evidence_hash(&event_id, success);

        Self {
            event_id,
            failed_node,
            sector_id,
            repair_node,
            repair_type,
            repair_duration_hours,
            success,
            evidence_hash,
            timestamp: Timestamp::now(),
        }
    }

    pub fn validate(&self) -> PoCResult<()> {
        if self.failed_node == self.repair_node {
            return Err(crate::error::PoCError::ValidationFailed(
                "Failed node cannot be the same as repair node".to_string(),
            ));
        }

        if self.repair_duration_hours < 0.0 {
            return Err(crate::error::PoCError::ValidationFailed(
                "Invalid repair duration".to_string(),
            ));
        }

        if self.sector_id == 0 {
            return Err(crate::error::PoCError::ValidationFailed(
                "Invalid sector ID".to_string(),
            ));
        }

        Ok(())
    }

    fn compute_event_id(failed_node: Address, sector_id: u64, repair_node: Address) -> Hash {
        use ego_core::crypto::hash_multiple;

        let failed_node_bytes = failed_node.as_bytes();
        let sector_id_bytes = sector_id.to_le_bytes();
        let repair_node_bytes = repair_node.as_bytes();
        let timestamp_bytes = Timestamp::now().as_millis().to_le_bytes();

        hash_multiple(&[
            failed_node_bytes,
            &sector_id_bytes,
            repair_node_bytes,
            &timestamp_bytes,
        ])
    }

    fn compute_evidence_hash(event_id: &Hash, success: bool) -> Hash {
        use ego_core::crypto::hash_multiple;

        hash_multiple(&[event_id.as_bytes(), &[if success { 1u8 } else { 0u8 }]])
    }
}

impl RepairJob {
    pub fn new(failed_node: Address, affected_sectors: Vec<u64>, priority: RepairPriority) -> Self {
        let job_id = Self::compute_job_id(failed_node, &affected_sectors);
        let deadline = Self::calculate_deadline(&priority);

        Self {
            job_id,
            failed_node,
            affected_sectors,
            assigned_repair_node: None,
            status: RepairStatus::Queued,
            priority,
            created_at: Timestamp::now(),
            deadline,
            repair_progress: 0.0,
        }
    }

    pub fn assign_repair_node(&mut self, repair_node: Address) {
        self.assigned_repair_node = Some(repair_node);
        self.status = RepairStatus::InProgress;
    }

    pub fn update_progress(&mut self, progress: f64) {
        self.repair_progress = progress.clamp(0.0, 1.0);

        if progress >= 1.0 {
            self.status = RepairStatus::Completed;
        }
    }

    pub fn is_expired(&self) -> bool {
        Timestamp::now() > self.deadline
    }

    pub fn sectors_count(&self) -> usize {
        self.affected_sectors.len()
    }

    fn compute_job_id(failed_node: Address, affected_sectors: &[u64]) -> Hash {
        use ego_core::crypto::hash_multiple;

        let failed_node_bytes = failed_node.as_bytes();
        let timestamp_bytes = Timestamp::now().as_millis().to_le_bytes();

        let mut inputs: Vec<&[u8]> = Vec::new();
        inputs.push(failed_node_bytes);

        let sector_bytes: Vec<[u8; 8]> = affected_sectors
            .iter()
            .map(|&sector_id| sector_id.to_le_bytes())
            .collect();

        for sector_byte_array in &sector_bytes {
            inputs.push(sector_byte_array);
        }

        inputs.push(&timestamp_bytes);

        hash_multiple(&inputs)
    }

    fn calculate_deadline(priority: &RepairPriority) -> Timestamp {
        let deadline_hours = match priority {
            RepairPriority::Critical => 4,
            RepairPriority::High => 12,
            RepairPriority::Normal => 24,
            RepairPriority::Low => 72,
        };

        Timestamp::from_millis(Timestamp::now().as_millis() + deadline_hours * 3_600_000)
    }
}

impl Default for RepairMetrics {
    fn default() -> Self {
        Self {
            total_repairs: 0,
            successful_repairs: 0,
            failed_repairs: 0,
            avg_repair_time_hours: 0.0,
            nodes_promoted: 0,
            sectors_recovered: 0,
            last_updated: Timestamp::now(),
        }
    }
}

impl PartialEq for RepairEvent {
    fn eq(&self, other: &Self) -> bool {
        self.event_id == other.event_id
            && self.failed_node == other.failed_node
            && self.sector_id == other.sector_id
            && self.repair_node == other.repair_node
    }
}

impl Eq for RepairEvent {}

impl PartialEq for RepairType {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (RepairType::SectorRecovery, RepairType::SectorRecovery) => true,
            (RepairType::DataReconstruction, RepairType::DataReconstruction) => true,
            (RepairType::NodePromotion, RepairType::NodePromotion) => true,
            (RepairType::EmergencyBackup, RepairType::EmergencyBackup) => true,
            _ => false,
        }
    }
}

impl Eq for RepairType {}

impl PartialEq for RepairStatus {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (RepairStatus::Queued, RepairStatus::Queued) => true,
            (RepairStatus::InProgress, RepairStatus::InProgress) => true,
            (RepairStatus::Completed, RepairStatus::Completed) => true,
            (RepairStatus::Failed, RepairStatus::Failed) => true,
            (RepairStatus::Cancelled, RepairStatus::Cancelled) => true,
            _ => false,
        }
    }
}

impl Eq for RepairStatus {}

impl PartialEq for RepairPriority {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (RepairPriority::Critical, RepairPriority::Critical) => true,
            (RepairPriority::High, RepairPriority::High) => true,
            (RepairPriority::Normal, RepairPriority::Normal) => true,
            (RepairPriority::Low, RepairPriority::Low) => true,
            _ => false,
        }
    }
}

impl Eq for RepairPriority {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repair_event_creation() {
        let event = RepairEvent::new(
            Address::new([1u8; 20]),
            1,
            Address::new([2u8; 20]),
            RepairType::SectorRecovery,
            2.5,
            true,
        );

        assert_eq!(event.sector_id, 1);
        assert_eq!(event.repair_duration_hours, 2.5);
        assert!(event.success);
        assert!(event.validate().is_ok());
    }

    #[test]
    fn test_repair_job_lifecycle() {
        let mut job = RepairJob::new(Address::new([1u8; 20]), vec![1, 2, 3], RepairPriority::High);

        assert_eq!(job.status, RepairStatus::Queued);
        assert_eq!(job.sectors_count(), 3);

        job.assign_repair_node(Address::new([2u8; 20]));
        assert_eq!(job.status, RepairStatus::InProgress);
        assert!(job.assigned_repair_node.is_some());

        job.update_progress(0.5);
        assert_eq!(job.repair_progress, 0.5);
        assert_eq!(job.status, RepairStatus::InProgress);

        job.update_progress(1.0);
        assert_eq!(job.status, RepairStatus::Completed);
    }

    #[test]
    fn test_repair_priority_deadlines() {
        let critical_job =
            RepairJob::new(Address::new([1u8; 20]), vec![1], RepairPriority::Critical);

        let normal_job = RepairJob::new(Address::new([2u8; 20]), vec![2], RepairPriority::Normal);

        assert!(critical_job.deadline < normal_job.deadline);
    }
}
