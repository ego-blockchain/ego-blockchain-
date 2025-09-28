use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, Hash)]
pub enum NetworkType {
    WiFi,
    FiveG,
    Ethernet,
    Cellular4G,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub interface_type: NetworkType,
    pub is_available: bool,
    pub signal_strength: u8,
    pub cost_per_gb_usd: f64,
    pub data_limit_gb: Option<f64>,
    pub data_used_gb: f64,
    pub last_updated: u64,
}

impl Default for NetworkInterface {
    fn default() -> Self {
        Self {
            interface_type: NetworkType::WiFi,
            is_available: false,
            signal_strength: 0,
            cost_per_gb_usd: 0.0,
            data_limit_gb: None,
            data_used_gb: 0.0,
            last_updated: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum NetworkEvent {
    InterfaceChanged(NetworkType),
    DataThresholdReached(f64),
    CostThresholdReached(f64),
    SignalStrengthChanged(NetworkType, u8),
    InterfaceAvailabilityChanged(NetworkType, bool),
}

pub struct NetworkManager {
    pub current_interface: NetworkType,
    pub interfaces: HashMap<NetworkType, NetworkInterface>,
    pub cost_threshold_usd: f64,
    pub data_threshold_gb: f64,
    pub monthly_cost_usd: f64,
    pub monthly_data_gb: f64,
    pub optimization_enabled: bool,
    pub event_sender: mpsc::UnboundedSender<NetworkEvent>,
    pub event_receiver: mpsc::UnboundedReceiver<NetworkEvent>,
}

impl NetworkManager {
    pub fn new() -> Self {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();

        let mut interfaces = HashMap::new();

        interfaces.insert(
            NetworkType::WiFi,
            NetworkInterface {
                interface_type: NetworkType::WiFi,
                is_available: true,
                signal_strength: 80,
                cost_per_gb_usd: 0.0,
                data_limit_gb: None,
                data_used_gb: 0.0,
                last_updated: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            },
        );

        interfaces.insert(
            NetworkType::FiveG,
            NetworkInterface {
                interface_type: NetworkType::FiveG,
                is_available: false,
                signal_strength: 0,
                cost_per_gb_usd: 5.0,
                data_limit_gb: Some(50.0),
                data_used_gb: 0.0,
                last_updated: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            },
        );

        interfaces.insert(
            NetworkType::Ethernet,
            NetworkInterface {
                interface_type: NetworkType::Ethernet,
                is_available: false,
                signal_strength: 100,
                cost_per_gb_usd: 0.0,
                data_limit_gb: None,
                data_used_gb: 0.0,
                last_updated: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            },
        );

        interfaces.insert(
            NetworkType::Cellular4G,
            NetworkInterface {
                interface_type: NetworkType::Cellular4G,
                is_available: true,
                signal_strength: 60,
                cost_per_gb_usd: 2.0,
                data_limit_gb: Some(20.0),
                data_used_gb: 0.0,
                last_updated: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            },
        );

        Self {
            current_interface: NetworkType::WiFi,
            interfaces,
            cost_threshold_usd: 100.0,
            data_threshold_gb: 40.0,
            monthly_cost_usd: 0.0,
            monthly_data_gb: 0.0,
            optimization_enabled: true,
            event_sender,
            event_receiver,
        }
    }

    pub fn update_interface_status(
        &mut self,
        interface_type: NetworkType,
        available: bool,
        signal_strength: Option<u8>,
    ) {
        if let Some(interface) = self.interfaces.get_mut(&interface_type) {
            let previous_availability = interface.is_available;
            interface.is_available = available;
            if let Some(strength) = signal_strength {
                interface.signal_strength = strength;
            }
            interface.last_updated = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            if previous_availability != available {
                let _ = self
                    .event_sender
                    .send(NetworkEvent::InterfaceAvailabilityChanged(
                        interface_type.clone(),
                        available,
                    ));
            }

            if let Some(strength) = signal_strength {
                let _ = self.event_sender.send(NetworkEvent::SignalStrengthChanged(
                    interface_type.clone(),
                    strength,
                ));
            }

            debug!(
                "Updated interface {:?}: available={}, signal={}",
                interface_type, available, interface.signal_strength
            );
        }
    }

    pub fn switch_to_best_interface(&mut self) -> Option<NetworkType> {
        if !self.optimization_enabled {
            return None;
        }

        let best_interface = self.find_best_interface();
        if let Some(new_interface) = best_interface {
            if new_interface != self.current_interface {
                let previous = self.current_interface.clone();
                self.current_interface = new_interface.clone();

                let _ = self
                    .event_sender
                    .send(NetworkEvent::InterfaceChanged(new_interface.clone()));

                info!(
                    "Switched network interface from {:?} to {:?}",
                    previous, new_interface
                );
                return Some(new_interface);
            }
        }
        None
    }

    pub fn find_best_interface(&self) -> Option<NetworkType> {
        let available_interfaces: Vec<_> = self
            .interfaces
            .values()
            .filter(|interface| interface.is_available)
            .collect();

        if available_interfaces.is_empty() {
            return None;
        }

        let mut best: Option<&NetworkInterface> = None;
        for interface in available_interfaces {
            if let Some(current_best) = best {
                let interface_score = self.calculate_interface_score(interface);
                let best_score = self.calculate_interface_score(current_best);

                if interface_score > best_score {
                    best = Some(interface);
                }
            } else {
                best = Some(interface);
            }
        }

        best.map(|interface| interface.interface_type.clone())
    }

    fn calculate_interface_score(&self, interface: &NetworkInterface) -> f64 {
        let mut score = 0.0;

        if interface.cost_per_gb_usd == 0.0 {
            score += 100.0;
        } else {
            score += (10.0 / interface.cost_per_gb_usd).min(50.0);
        }

        score += interface.signal_strength as f64 * 0.5;

        if let Some(limit) = interface.data_limit_gb {
            let usage_ratio = interface.data_used_gb / limit;
            if usage_ratio > 0.8 {
                score *= 0.5;
            } else if usage_ratio > 0.6 {
                score *= 0.8;
            }
        }

        match interface.interface_type {
            NetworkType::Ethernet => score += 20.0,
            NetworkType::WiFi => score += 15.0,
            NetworkType::FiveG => score += 10.0,
            NetworkType::Cellular4G => score += 5.0,
        }

        score
    }

    pub fn record_data_usage(&mut self, bytes: u64) {
        let gb = bytes as f64 / 1_000_000_000.0;
        self.monthly_data_gb += gb;

        if let Some(interface) = self.interfaces.get_mut(&self.current_interface) {
            interface.data_used_gb += gb;
            self.monthly_cost_usd += gb * interface.cost_per_gb_usd;

            if self.monthly_data_gb > self.data_threshold_gb {
                let _ = self
                    .event_sender
                    .send(NetworkEvent::DataThresholdReached(self.monthly_data_gb));
            }

            if self.monthly_cost_usd > self.cost_threshold_usd {
                let _ = self
                    .event_sender
                    .send(NetworkEvent::CostThresholdReached(self.monthly_cost_usd));
            }
        }
    }

    pub fn is_cost_effective_time(&self) -> bool {
        self.is_off_peak_hours()
    }

    pub fn is_off_peak_hours(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let seconds_in_day = now % 86400;
        let off_peak_start = 23 * 3600;
        let off_peak_end = 6 * 3600;

        seconds_in_day >= off_peak_start || seconds_in_day < off_peak_end
    }

    pub fn get_current_interface(&self) -> &NetworkInterface {
        self.interfaces
            .get(&self.current_interface)
            .unwrap_or_else(|| self.interfaces.values().next().unwrap())
    }

    pub fn get_data_usage_summary(&self) -> String {
        format!(
            "Data: {:.2}GB/${:.2} (threshold: {:.0}GB/${:.0})",
            self.monthly_data_gb,
            self.monthly_cost_usd,
            self.data_threshold_gb,
            self.cost_threshold_usd
        )
    }

    pub fn reset_monthly_stats(&mut self) {
        self.monthly_cost_usd = 0.0;
        self.monthly_data_gb = 0.0;
        for interface in self.interfaces.values_mut() {
            interface.data_used_gb = 0.0;
        }
        info!("Monthly network statistics reset");
    }

    pub fn set_optimization_enabled(&mut self, enabled: bool) {
        self.optimization_enabled = enabled;
        info!("Network optimization enabled: {}", enabled);
    }

    pub fn get_interface_stats(&self) -> HashMap<NetworkType, (f64, f64, bool)> {
        self.interfaces
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    (v.data_used_gb, v.cost_per_gb_usd, v.is_available),
                )
            })
            .collect()
    }
}
