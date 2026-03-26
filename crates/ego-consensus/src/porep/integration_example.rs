use super::{
    PoRepProver, ProverConfig, SealingJob, SealingStatus, SectorCommitment,
    persistence::{PoRepPersistence, PoRepStorageStats},
    prover::SectorState,
};
use crate::error::PoCResult;
use ego_core::{Address, Hash, KeyPair, Timestamp};
use std::collections::HashMap;
use tokio::time::{sleep, Duration};
use tracing::{info, warn, debug};

pub struct PoRepLifecycleExample {
    prover: PoRepProver,
    backup_shutdown: Option<tokio::sync::mpsc::UnboundedSender<()>>,
}

impl PoRepLifecycleExample {

    pub async fn new(db_path: &str, sector_size: u64) -> PoCResult<Self> {
        let keypair = KeyPair::generate();

        let config = ProverConfig {
            sector_size,
            gpu_available: true,
            nvme_path: "/tmp/nvme".to_string(),
            params_version: 1,
        };

        let prover = PoRepProver::new_with_persistence(keypair, config, db_path)?;

        info!("🚀 PoRep lifecycle example initialized with persistence at: {}", db_path);

        Ok(Self {
            prover,
            backup_shutdown: None,
        })
    }

    pub async fn start_lifecycle(&mut self) -> PoCResult<()> {
        info!("▶️ Starting PoRep lifecycle with persistence...");

        let backup_shutdown = self.prover.start_periodic_backup();
        self.backup_shutdown = Some(backup_shutdown);

        self.demonstrate_sector_lifecycle().await?;

        info!("✅ PoRep lifecycle demonstration completed");
        Ok(())
    }

    async fn demonstrate_sector_lifecycle(&mut self) -> PoCResult<()> {
        info!("📋 Demonstrating sector lifecycle with persistence...");

        for sector_id in 1..=5 {
            self.create_demo_sector(sector_id).await?;
            sleep(Duration::from_millis(100)).await;
        }

        self.display_current_state().await?;

        info!("💾 Performing manual backup...");
        self.prover.backup_current_state()?;

        self.update_sector_data().await?;

        self.display_persistence_stats().await?;

        self.cleanup_old_sectors().await?;

        Ok(())
    }

    async fn create_demo_sector(&mut self, sector_id: u64) -> PoCResult<()> {
        info!("🏗️ Creating demo sector {}", sector_id);

        let sector_state = SectorState {
            sector_id,
            replica_id: Hash::new([sector_id as u8; 32]),
            comm_d: Hash::new([(sector_id + 10) as u8; 32]),
            comm_r: Hash::new([(sector_id + 20) as u8; 32]),
            sealed_path: format!("/storage/sectors/sealed_{}", sector_id),
            cache_path: format!("/storage/sectors/cache_{}", sector_id),
            deal_ids: vec![Hash::new([(sector_id + 30) as u8; 32])],
            created_at: Timestamp::now(),
            proof_count: 0,
            last_challenged_at: None,
        };

        info!("🏗️ Demo sector {} created (simulated)", sector_id);

        let deal_ids = vec![Hash::new([(sector_id + 30) as u8; 32])];
        if let Err(e) = self.prover.register_deal_ids(sector_id, deal_ids) {
            warn!("Failed to register deal IDs for sector {}: {}", sector_id, e);
        }

        if let Err(e) = self.prover.backup_current_state() {
            warn!("Failed to persist demo sector state {}: {}", sector_id, e);
        }

        debug!("✅ Demo sector {} created and persisted", sector_id);
        Ok(())
    }

    async fn display_current_state(&self) -> PoCResult<()> {
        let metrics = self.prover.get_sealing_metrics();
        let commitments = self.prover.get_all_commitments();

        info!("📊 Current PoRep State:");
        info!("   Active sectors: {}", metrics.sectors_active);
        info!("   Commitments: {}", commitments.len());
        info!("   Queue length: {}", metrics.queue_length);
        info!("   Submitted proofs: {}", metrics.proofs_submitted);

        for commitment in commitments.iter().take(3) {
            info!("   Sector {}: registered={}",
                  commitment.sector_id, commitment.registered_at);
        }

        Ok(())
    }

    async fn update_sector_data(&mut self) -> PoCResult<()> {
        info!("🔄 Simulating sector updates...");

        let commitments = self.prover.get_all_commitments();
        let sector_ids: Vec<u64> = commitments.iter().take(3).map(|c| c.sector_id).collect();

        for sector_id in sector_ids {

            let deal_ids = vec![
                Hash::new([(sector_id + 40) as u8; 32]),
                Hash::new([(sector_id + 50) as u8; 32]),
            ];

            if let Err(e) = self.prover.register_deal_ids(sector_id, deal_ids) {
                warn!("Failed to register deal IDs for sector {}: {}", sector_id, e);
            } else {
                info!("✅ Updated deal IDs for sector {}", sector_id);
            }
        }

        if let Err(e) = self.prover.backup_current_state() {
            warn!("Failed to persist sector updates: {}", e);
        }

        info!("✅ Sector updates completed");
        Ok(())
    }

    async fn display_persistence_stats(&self) -> PoCResult<()> {
        let stats = self.prover.get_persistence_stats()?;

        info!("📈 Persistence Statistics:");
        info!("   Total sectors in storage: {}", stats.total_sectors);
        info!("   Total commitments in storage: {}", stats.total_commitments);
        info!("   Database size: {} bytes", stats.database_size_bytes);
        info!("   Last backup: {}", stats.last_backup);

        Ok(())
    }

    async fn cleanup_old_sectors(&mut self) -> PoCResult<()> {
        info!("🧹 Running sector cleanup (retention policy)...");

        let retention_days = 30;
        let deleted_count = self.prover.cleanup_old_sectors(retention_days)?;

        info!("🧹 Cleanup completed: {} old sectors removed", deleted_count);
        Ok(())
    }

    pub async fn shutdown(&mut self) -> PoCResult<()> {
        info!("🛑 Shutting down PoRep lifecycle...");

        self.prover.backup_current_state()?;

        if let Some(shutdown_tx) = self.backup_shutdown.take() {
            let _ = shutdown_tx.send(());
        }

        sleep(Duration::from_millis(500)).await;

        info!("✅ PoRep lifecycle shutdown completed");
        Ok(())
    }
}

pub async fn demonstrate_recovery_scenario(db_path: &str) -> PoCResult<()> {
    info!("🔄 Demonstrating recovery scenario...");

    let keypair = KeyPair::generate();
    let config = ProverConfig {
        sector_size: 32 * 1024 * 1024 * 1024,
        gpu_available: true,
        nvme_path: "/tmp/nvme".to_string(),
        params_version: 1,
    };

    let restored_prover = PoRepProver::new_with_persistence(keypair, config, db_path)?;

    let metrics = restored_prover.get_sealing_metrics();
    let commitments = restored_prover.get_all_commitments();

    info!("🔄 Recovery Results:");
    info!("   Restored sectors: {}", metrics.sectors_active);
    info!("   Restored commitments: {}", commitments.len());

    if !commitments.is_empty() {
        info!("   Sample restored commitment:");
        if let Some(commitment) = commitments.iter().next() {
            info!("     Sector ID: {}", commitment.sector_id);
            info!("     Prover ID: {}", commitment.prover_id);
            info!("     Registered at: {}", commitment.registered_at);
            info!("     Deal IDs: {} deals", commitment.deal_ids.len());
        }
    }

    info!("✅ Recovery demonstration completed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_porep_lifecycle_with_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().to_str().unwrap();

        let mut lifecycle = PoRepLifecycleExample::new(db_path, 32 * 1024 * 1024).await.unwrap();

        lifecycle.start_lifecycle().await.unwrap();

        lifecycle.shutdown().await.unwrap();

        demonstrate_recovery_scenario(db_path).await.unwrap();
    }
}
