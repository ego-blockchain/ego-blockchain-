// porep/integration_example.rs — Example of PoRep with sector lifecycle persistence
//
// This example demonstrates how to use the PoRepProver with persistent storage
// for sector lifecycle state management.

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

/// Complete example of PoRep lifecycle with persistence
pub struct PoRepLifecycleExample {
    prover: PoRepProver,
    backup_shutdown: Option<tokio::sync::mpsc::UnboundedSender<()>>,
}

impl PoRepLifecycleExample {
    /// Initialize a new PoRep prover with persistence
    pub async fn new(db_path: &str, sector_size: u64) -> PoCResult<Self> {
        let keypair = KeyPair::generate();

        let config = ProverConfig {
            sector_size,
            gpu_available: true,
            nvme_path: "/tmp/nvme".to_string(),
            params_version: 1,
        };

        // Create prover with persistent storage
        let prover = PoRepProver::new_with_persistence(keypair, config, db_path)?;

        info!("🚀 PoRep lifecycle example initialized with persistence at: {}", db_path);

        Ok(Self {
            prover,
            backup_shutdown: None,
        })
    }

    /// Start the complete PoRep lifecycle with periodic backups
    pub async fn start_lifecycle(&mut self) -> PoCResult<()> {
        info!("▶️ Starting PoRep lifecycle with persistence...");

        // Start periodic backup task (every 5 minutes)
        let backup_shutdown = self.prover.start_periodic_backup();
        self.backup_shutdown = Some(backup_shutdown);

        // Simulate sector lifecycle operations
        self.demonstrate_sector_lifecycle().await?;

        info!("✅ PoRep lifecycle demonstration completed");
        Ok(())
    }

    /// Demonstrate complete sector lifecycle with persistence
    async fn demonstrate_sector_lifecycle(&mut self) -> PoCResult<()> {
        info!("📋 Demonstrating sector lifecycle with persistence...");

        // 1. Simulate creating sectors (normally done by sealing pipeline)
        for sector_id in 1..=5 {
            self.create_demo_sector(sector_id).await?;
            sleep(Duration::from_millis(100)).await; // Simulate processing time
        }

        // 2. Show current state
        self.display_current_state().await?;

        // 3. Perform manual backup
        info!("💾 Performing manual backup...");
        self.prover.backup_current_state()?;

        // 4. Simulate some sector updates
        self.update_sector_data().await?;

        // 5. Show persistence statistics
        self.display_persistence_stats().await?;

        // 6. Simulate sector cleanup (retention policy)
        self.cleanup_old_sectors().await?;

        Ok(())
    }

    /// Create a demo sector for testing persistence
    async fn create_demo_sector(&mut self, sector_id: u64) -> PoCResult<()> {
        info!("🏗️ Creating demo sector {}", sector_id);

        // Simulate sector creation (this would normally be done by the sealing pipeline)
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

        // For demo purposes, we'll simulate the sector creation process
        // In real usage, sectors are created through the seal_sector() method

        info!("🏗️ Demo sector {} created (simulated)", sector_id);

        // Register deal IDs for the sector (this creates internal state)
        let deal_ids = vec![Hash::new([(sector_id + 30) as u8; 32])];
        if let Err(e) = self.prover.register_deal_ids(sector_id, deal_ids) {
            warn!("Failed to register deal IDs for sector {}: {}", sector_id, e);
        }

        // Perform a backup to persist any state changes
        if let Err(e) = self.prover.backup_current_state() {
            warn!("Failed to persist demo sector state {}: {}", sector_id, e);
        }

        debug!("✅ Demo sector {} created and persisted", sector_id);
        Ok(())
    }

    /// Display current state information
    async fn display_current_state(&self) -> PoCResult<()> {
        let metrics = self.prover.get_sealing_metrics();
        let commitments = self.prover.get_all_commitments();

        info!("📊 Current PoRep State:");
        info!("   Active sectors: {}", metrics.sectors_active);
        info!("   Commitments: {}", commitments.len());
        info!("   Queue length: {}", metrics.queue_length);
        info!("   Submitted proofs: {}", metrics.proofs_submitted);

        // Show details for first few commitments
        for commitment in commitments.iter().take(3) {
            info!("   Sector {}: registered={}",
                  commitment.sector_id, commitment.registered_at);
        }

        Ok(())
    }

    /// Simulate sector updates (e.g., adding proofs)
    async fn update_sector_data(&mut self) -> PoCResult<()> {
        info!("🔄 Simulating sector updates...");

        // Get list of existing sectors via commitments
        let commitments = self.prover.get_all_commitments();
        let sector_ids: Vec<u64> = commitments.iter().take(3).map(|c| c.sector_id).collect();

        for sector_id in sector_ids {
            // Simulate adding deal IDs (this is a real API call)
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

        // Perform a backup to persist any updates
        if let Err(e) = self.prover.backup_current_state() {
            warn!("Failed to persist sector updates: {}", e);
        }

        info!("✅ Sector updates completed");
        Ok(())
    }

    /// Display persistence statistics
    async fn display_persistence_stats(&self) -> PoCResult<()> {
        let stats = self.prover.get_persistence_stats()?;

        info!("📈 Persistence Statistics:");
        info!("   Total sectors in storage: {}", stats.total_sectors);
        info!("   Total commitments in storage: {}", stats.total_commitments);
        info!("   Database size: {} bytes", stats.database_size_bytes);
        info!("   Last backup: {}", stats.last_backup);

        Ok(())
    }

    /// Simulate cleanup of old sectors
    async fn cleanup_old_sectors(&mut self) -> PoCResult<()> {
        info!("🧹 Running sector cleanup (retention policy)...");

        // Clean up sectors older than 30 days (for demo purposes, use a very short time)
        let retention_days = 30;
        let deleted_count = self.prover.cleanup_old_sectors(retention_days)?;

        info!("🧹 Cleanup completed: {} old sectors removed", deleted_count);
        Ok(())
    }

    /// Gracefully shutdown the lifecycle manager
    pub async fn shutdown(&mut self) -> PoCResult<()> {
        info!("🛑 Shutting down PoRep lifecycle...");

        // Perform final backup
        self.prover.backup_current_state()?;

        // Stop periodic backup task
        if let Some(shutdown_tx) = self.backup_shutdown.take() {
            let _ = shutdown_tx.send(());
        }

        // Allow time for background tasks to complete
        sleep(Duration::from_millis(500)).await;

        info!("✅ PoRep lifecycle shutdown completed");
        Ok(())
    }
}

/// Demonstrate recovery scenario - simulating node restart
pub async fn demonstrate_recovery_scenario(db_path: &str) -> PoCResult<()> {
    info!("🔄 Demonstrating recovery scenario...");

    // Create a new prover instance that will restore from existing database
    let keypair = KeyPair::generate();
    let config = ProverConfig {
        sector_size: 32 * 1024 * 1024 * 1024, // 32GB
        gpu_available: true,
        nvme_path: "/tmp/nvme".to_string(),
        params_version: 1,
    };

    // This will automatically restore state from persistence
    let restored_prover = PoRepProver::new_with_persistence(keypair, config, db_path)?;

    // Show restored state using public methods
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

        // Run the complete lifecycle
        lifecycle.start_lifecycle().await.unwrap();

        // Shutdown gracefully
        lifecycle.shutdown().await.unwrap();

        // Test recovery
        demonstrate_recovery_scenario(db_path).await.unwrap();
    }
}