use super::WitnessReport;
use crate::error::{PoCError, PoCResult};
use ego_core::Address;
use std::collections::HashMap;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

#[derive(Debug)]
pub struct WitnessAggregatorBridge {

    aggregator_routes: HashMap<String, mpsc::UnboundedSender<WitnessReport>>,

    fallback_sender: Option<mpsc::UnboundedSender<WitnessReport>>,
}

impl WitnessAggregatorBridge {

    pub fn new() -> Self {
        Self {
            aggregator_routes: HashMap::new(),
            fallback_sender: None,
        }
    }

    pub fn register_aggregator(
        &mut self,
        h3_regions: Vec<String>,
        sender: mpsc::UnboundedSender<WitnessReport>,
    ) {
        for region in h3_regions {
            debug!("Registering aggregator for region {}", region);
            self.aggregator_routes.insert(region, sender.clone());
        }
    }

    pub fn set_fallback_aggregator(&mut self, sender: mpsc::UnboundedSender<WitnessReport>) {
        info!("Setting fallback aggregator");
        self.fallback_sender = Some(sender);
    }

    pub async fn route_report(&self, report: WitnessReport) -> PoCResult<()> {

        let h3_region = if let Some(ref location) = report.beacon_location {

            location.h3_index.chars().take(7).collect::<String>()
        } else {
            warn!("Witness report {} missing beacon location, using fallback",
                  format!("{:?}", report.report_id));
            return self.send_to_fallback(report).await;
        };

        if let Some(aggregator_sender) = self.aggregator_routes.get(&h3_region) {
            match aggregator_sender.send(report.clone()) {
                Ok(()) => {
                    debug!("Routed witness report {} to aggregator for region {}",
                           format!("{:?}", report.report_id), h3_region);
                    Ok(())
                }
                Err(e) => {
                    warn!("Failed to send to aggregator for region {}: {}", h3_region, e);

                    self.send_to_fallback(report).await
                }
            }
        } else {
            debug!("No aggregator found for region {}, using fallback", h3_region);
            self.send_to_fallback(report).await
        }
    }

    async fn send_to_fallback(&self, report: WitnessReport) -> PoCResult<()> {
        if let Some(ref fallback) = self.fallback_sender {
            fallback.send(report).map_err(|e| {
                PoCError::NetworkError(format!("Failed to send to fallback aggregator: {}", e))
            })?;
            debug!("Sent witness report to fallback aggregator");
            Ok(())
        } else {
            error!("No fallback aggregator available for witness report");
            Err(PoCError::NetworkError(
                "No aggregator available to receive witness report".to_string()
            ))
        }
    }

    pub fn get_route_stats(&self) -> RouteStats {
        RouteStats {
            total_routes: self.aggregator_routes.len(),
            has_fallback: self.fallback_sender.is_some(),
            covered_regions: self.aggregator_routes.keys().cloned().collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RouteStats {
    pub total_routes: usize,
    pub has_fallback: bool,
    pub covered_regions: Vec<String>,
}

static GLOBAL_BRIDGE: std::sync::LazyLock<std::sync::Mutex<WitnessAggregatorBridge>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(WitnessAggregatorBridge::new()));

pub fn with_global_bridge<T, F>(f: F) -> T
where
    F: FnOnce(&mut WitnessAggregatorBridge) -> T,
{
    let mut bridge = GLOBAL_BRIDGE.lock().unwrap();
    f(&mut *bridge)
}

async fn route_report_async(
    report: WitnessReport,
    aggregator_routes: std::collections::HashMap<String, mpsc::UnboundedSender<WitnessReport>>,
    fallback_sender: Option<mpsc::UnboundedSender<WitnessReport>>,
) -> PoCResult<()> {

    let h3_region = if let Some(ref location) = report.beacon_location {

        location.h3_index.chars().take(7).collect::<String>()
    } else {
        warn!("Witness report {} missing beacon location, using fallback",
              format!("{:?}", report.report_id));
        if let Some(fallback) = fallback_sender {
            fallback.send(report).map_err(|_| PoCError::NetworkError("Fallback send failed".to_string()))?;
        }
        return Ok(());
    };

    if let Some(sender) = aggregator_routes.get(&h3_region) {
        debug!("Routing witness report to aggregator for region {}", h3_region);
        sender.send(report).map_err(|_| PoCError::NetworkError("Aggregator send failed".to_string()))?;
    } else {

        debug!("No aggregator for region {}, using fallback", h3_region);
        if let Some(fallback) = fallback_sender {
            fallback.send(report).map_err(|_| PoCError::NetworkError("Fallback send failed".to_string()))?;
        }
    }
    Ok(())
}

pub fn create_witness_sender() -> mpsc::UnboundedSender<WitnessReport> {
    let (sender, mut receiver) = mpsc::unbounded_channel();

    tokio::spawn(async move {
        while let Some(report) = receiver.recv().await {

            let (aggregator_routes, fallback_sender) = {
                let bridge = GLOBAL_BRIDGE.lock().unwrap();
                (bridge.aggregator_routes.clone(), bridge.fallback_sender.clone())
            };

            if let Err(e) = route_report_async(report, aggregator_routes, fallback_sender).await {
                error!("Failed to route witness report: {}", e);
            }
        }
        warn!("Witness report router stopped");
    });

    sender
}

pub fn register_global_aggregator(
    h3_regions: Vec<String>,
    sender: mpsc::UnboundedSender<WitnessReport>,
) {
    with_global_bridge(|bridge| {
        bridge.register_aggregator(h3_regions, sender);
    });
}

pub fn set_global_fallback_aggregator(sender: mpsc::UnboundedSender<WitnessReport>) {
    with_global_bridge(|bridge| {
        bridge.set_fallback_aggregator(sender);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness::report::*;
    use ego_core::{Hash, Timestamp};

    fn create_test_report(h3_region: &str) -> WitnessReport {
        use crate::types::*;
        use crate::witness::report::*;

        let beacon_location = Some(LocationData {
            latitude: 40.7128,
            longitude: -74.0060,
            altitude: Some(10.0),
            accuracy: Some(5.0),
            timestamp: Timestamp::now().as_millis(),
            h3_index: format!("{}abcdefg", h3_region),
        });

        let witness_location = LocationData {
            latitude: 40.7128,
            longitude: -74.0060,
            altitude: Some(10.0),
            accuracy: Some(5.0),
            timestamp: Timestamp::now().as_millis(),
            h3_index: format!("{}abcdefg", h3_region),
        };

        let rf_metrics = RFMetrics {
            rsrp: -85,
            rsrq: -10,
            sinr: 15,
            timing_advance: 100,
            pci: 123,
            beam_index: Some(0),
            frequency: 2100,
            rx_timestamp: Timestamp::now().as_millis(),
        };

        let time_sync = TimeSyncData {
            rx_timestamp_ms: rf_metrics.rx_timestamp,
            tx_timestamp_ms: Timestamp::now().as_millis(),
            time_of_flight_ns: 0,
            clock_offset_ms: 0,
            gps_timestamp: Some(witness_location.timestamp),
            ntp_synced: true,
        };

        WitnessReport {
            report_id: Hash::new([1u8; 32]),
            witness_id: Address::new([2u8; 20]),
            beacon_id: Address::new([3u8; 20]),
            challenge_hash: Hash::new([4u8; 32]),
            rf_metrics,
            beacon_location,
            witness_location,
            co_beacon_verification: None,
            time_sync,
            slice_context: None,
            timestamp: Timestamp::now(),
            signature: ego_core::Signature::ed25519([0u8; 64]),
            public_key: ego_core::PublicKey::ed25519([0u8; 32]),
            metadata: Vec::new(),
        }
    }

    #[tokio::test]
    async fn test_report_routing() {
        let mut bridge = WitnessAggregatorBridge::new();
        let (sender, mut receiver) = mpsc::unbounded_channel();

        bridge.register_aggregator(vec!["8c2a1e0".to_string()], sender);

        let report = create_test_report("8c2a1e0");

        assert!(bridge.route_report(report).await.is_ok());

        assert!(receiver.try_recv().is_ok());
    }

    #[tokio::test]
    async fn test_fallback_routing() {
        let mut bridge = WitnessAggregatorBridge::new();
        let (fallback_sender, mut fallback_receiver) = mpsc::unbounded_channel();

        bridge.set_fallback_aggregator(fallback_sender);

        let report = create_test_report("9999999");

        assert!(bridge.route_report(report).await.is_ok());

        assert!(fallback_receiver.try_recv().is_ok());
    }
}
