use super::engine::SlashingEngine;
use crate::aggregator::DensityEvent;
use crate::error::{PoCError, PoCResult};
use ego_core::{Address, KeyPair};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Bridge that connects DensityEvents from aggregator to slashing engine
/// This is what actually triggers slashing when co-location is detected
#[derive(Debug)]
pub struct SlashingBridge {
    slash_engine: SlashingEngine,
    reporter_address: Address,
}

impl SlashingBridge {
    /// Create new slashing bridge with the engine and reporter identity
    pub fn new(slash_engine: SlashingEngine, reporter_address: Address) -> Self {
        Self {
            slash_engine,
            reporter_address,
        }
    }

    /// Start the slashing bridge to process density events from aggregator
    pub async fn start_density_processor(
        &self,
        mut density_receiver: mpsc::UnboundedReceiver<DensityEvent>,
    ) {
        info!("🔥 Starting slashing bridge for density violations");

        while let Some(density_event) = density_receiver.recv().await {
            if let Err(e) = self.process_density_violation(density_event).await {
                error!("Failed to process density violation: {}", e);
            }
        }

        warn!("Slashing bridge density processor stopped");
    }

    /// Process a density violation and potentially trigger slashing
    async fn process_density_violation(&self, density_event: DensityEvent) -> PoCResult<()> {
        debug!("Processing density violation for node {} in cell {} (LDM: {:.3}, devices: {})",
               density_event.node_id, density_event.h3_cell, density_event.ldm, density_event.device_count);

        // Only process violations that meet minimum thresholds
        if density_event.ldm < 0.3 || density_event.device_count < 2 {
            debug!("Density violation below threshold, ignoring");
            return Ok(());
        }

        match self.slash_engine.report_invalid_poc(&density_event, self.reporter_address) {
            Ok(Some(slash_event)) => {
                warn!("⚡ Slashing executed for density violation: node {} slashed {} tokens",
                      density_event.node_id, slash_event.slash_amount);

                // TODO: Emit slash event to chain via BFT bridge
                info!("Slash event {} created for node {} (confidence: {:.2})",
                      format!("{:?}", slash_event.event_id), slash_event.slashed_node, slash_event.confidence);

                Ok(())
            },
            Ok(None) => {
                info!("Density violation reported but no immediate slashing (low confidence or cooldown)");
                Ok(())
            },
            Err(e) => {
                error!("Failed to report density violation to slashing engine: {}", e);
                Err(e)
            }
        }
    }
}

/// Factory function to create slashing bridge with density event processing
pub fn create_slashing_bridge(
    slash_engine: SlashingEngine,
    reporter_address: Address,
) -> (SlashingBridge, mpsc::UnboundedSender<DensityEvent>) {
    let bridge = SlashingBridge::new(slash_engine, reporter_address);
    let (density_tx, density_rx) = mpsc::unbounded_channel();

    // Start the density processor in background
    let bridge_clone = SlashingBridge::new(
        SlashingEngine::new(KeyPair::generate()), // TODO: Use proper keypair
        reporter_address,
    );

    tokio::spawn(async move {
        bridge_clone.start_density_processor(density_rx).await;
    });

    (bridge, density_tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::{Hash, Timestamp};

    #[tokio::test]
    async fn test_density_violation_processing() {
        let reporter_keypair = ego_core::KeyPair::generate();
        let reporter = Address::from_public_key(&reporter_keypair.public_key());
        let slash_engine = SlashingEngine::new(reporter_keypair);
        let bridge = SlashingBridge::new(slash_engine, reporter);

        let density_event = DensityEvent {
            node_id: Address::new([2u8; 20]),
            h3_cell: "8c2a1e0d0b5ffff".to_string(),
            device_count: 5,
            ldm: 0.85, // High LDM indicates clear co-location
            evidence_root: Hash::new([3u8; 32]),
            epoch: 100,
            timestamp: Timestamp::now(),
        };

        // Should process without error
        assert!(bridge.process_density_violation(density_event).await.is_ok());
    }

    #[tokio::test]
    async fn test_low_threshold_ignored() {
        let reporter_keypair = ego_core::KeyPair::generate();
        let reporter = Address::from_public_key(&reporter_keypair.public_key());
        let slash_engine = SlashingEngine::new(reporter_keypair);
        let bridge = SlashingBridge::new(slash_engine, reporter);

        let density_event = DensityEvent {
            node_id: Address::new([2u8; 20]),
            h3_cell: "8c2a1e0d0b5ffff".to_string(),
            device_count: 1, // Below threshold
            ldm: 0.2, // Below threshold
            evidence_root: Hash::new([3u8; 32]),
            epoch: 100,
            timestamp: Timestamp::now(),
        };

        // Should be ignored
        assert!(bridge.process_density_violation(density_event).await.is_ok());
    }
}