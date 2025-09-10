use chrono::Timelike;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
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
    pub signal_strength: Option<u8>,
    pub bandwidth_mbps: Option<u64>,
    pub cost_per_gb: Option<f64>,
    pub latency_ms: Option<u32>,
    pub data_usage_gb: f64,
    pub monthly_limit_gb: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataUsageStats {
    pub total_usage_gb: f64,
    pub monthly_usage_gb: f64,
    pub daily_usage_gb: f64,
    pub last_reset: u64,
    pub cost_this_month: f64,
}

#[derive(Debug, Clone)]
pub enum NetworkEvent {
    InterfaceChanged(NetworkType),
    DataThresholdReached(f64),
    CostThresholdReached(f64),
    OffPeakHoursStarted,
    OffPeakHoursEnded,
}

pub struct NetworkManager {
    pub interfaces: HashMap<NetworkType, NetworkInterface>,
    pub current_interface: NetworkType,
    pub data_usage: DataUsageStats,
    pub event_sender: mpsc::UnboundedSender<NetworkEvent>,
    pub event_receiver: mpsc::UnboundedReceiver<NetworkEvent>,
    pub auto_switch_enabled: bool,
    pub cost_threshold_usd: f64,
    pub data_threshold_gb: f64,
    pub off_peak_hours: (u8, u8),
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
                signal_strength: Some(80),
                bandwidth_mbps: Some(100),
                cost_per_gb: Some(0.0),
                latency_ms: Some(20),
                data_usage_gb: 0.0,
                monthly_limit_gb: None,
            },
        );

        interfaces.insert(
            NetworkType::FiveG,
            NetworkInterface {
                interface_type: NetworkType::FiveG,
                is_available: false,
                signal_strength: None,
                bandwidth_mbps: Some(1000),
                cost_per_gb: Some(10.0),
                latency_ms: Some(5),
                data_usage_gb: 0.0,
                monthly_limit_gb: Some(50.0),
            },
        );

        Self {
            interfaces,
            current_interface: NetworkType::WiFi,
            data_usage: DataUsageStats {
                total_usage_gb: 0.0,
                monthly_usage_gb: 0.0,
                daily_usage_gb: 0.0,
                last_reset: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                cost_this_month: 0.0,
            },
            event_sender,
            event_receiver,
            auto_switch_enabled: true,
            cost_threshold_usd: 100.0,
            data_threshold_gb: 40.0,
            off_peak_hours: (23, 6),
        }
    }

    pub fn update_interface_status(
        &mut self,
        interface_type: NetworkType,
        is_available: bool,
        signal_strength: Option<u8>,
    ) {
        if let Some(interface) = self.interfaces.get_mut(&interface_type) {
            interface.is_available = is_available;
            interface.signal_strength = signal_strength;

            if self.auto_switch_enabled {
                self.evaluate_best_interface();
            }
        }
    }

    pub fn evaluate_best_interface(&mut self) -> NetworkType {
        let mut best_interface = self.current_interface.clone();
        let mut best_score = 0.0;

        for (interface_type, interface) in &self.interfaces {
            if !interface.is_available {
                continue;
            }

            let mut score = 0.0;

            match interface_type {
                NetworkType::WiFi | NetworkType::Ethernet => score += 100.0,
                NetworkType::FiveG => {
                    if self.is_mobility_required() || self.is_low_latency_required() {
                        score += 80.0;
                    } else {
                        score += 20.0;
                    }
                }
                NetworkType::Cellular4G => score += 40.0,
            }

            if let Some(strength) = interface.signal_strength {
                score += strength as f64 * 0.5;
            }

            if let Some(cost) = interface.cost_per_gb {
                if cost == 0.0 {
                    score += 50.0;
                } else {
                    score += 50.0 / cost.max(1.0);
                }
            }

            if let Some(limit) = interface.monthly_limit_gb {
                let usage_ratio = interface.data_usage_gb / limit;
                if usage_ratio > 0.8 {
                    score *= 0.5;
                }
            }

            if score > best_score {
                best_score = score;
                best_interface = interface_type.clone();
            }
        }

        if best_interface != self.current_interface {
            info!(
                "Switching network interface from {:?} to {:?}",
                self.current_interface, best_interface
            );
            self.current_interface = best_interface.clone();
            let _ = self
                .event_sender
                .send(NetworkEvent::InterfaceChanged(best_interface.clone()));
        }

        best_interface
    }

    pub fn record_data_usage(&mut self, bytes: u64) {
        let gb = bytes as f64 / 1_000_000_000.0;

        self.data_usage.total_usage_gb += gb;
        self.data_usage.monthly_usage_gb += gb;
        self.data_usage.daily_usage_gb += gb;

        if let Some(interface) = self.interfaces.get_mut(&self.current_interface) {
            interface.data_usage_gb += gb;

            if let Some(cost_per_gb) = interface.cost_per_gb {
                let cost = gb * cost_per_gb;
                self.data_usage.cost_this_month += cost;

                if self.data_usage.cost_this_month > self.cost_threshold_usd {
                    let _ = self.event_sender.send(NetworkEvent::CostThresholdReached(
                        self.data_usage.cost_this_month,
                    ));
                }
            }
        }

        if self.data_usage.monthly_usage_gb > self.data_threshold_gb {
            let _ = self.event_sender.send(NetworkEvent::DataThresholdReached(
                self.data_usage.monthly_usage_gb,
            ));
        }
    }

    pub fn is_off_peak_hours(&self) -> bool {
        let now = chrono::Utc::now();
        let hour = now.hour() as u8;

        if self.off_peak_hours.0 > self.off_peak_hours.1 {
            hour >= self.off_peak_hours.0 || hour < self.off_peak_hours.1
        } else {
            hour >= self.off_peak_hours.0 && hour < self.off_peak_hours.1
        }
    }

    pub fn should_use_5g(&self) -> bool {
        if !self
            .interfaces
            .get(&NetworkType::FiveG)
            .map_or(false, |i| i.is_available)
        {
            return false;
        }

        if let Some(wifi) = self.interfaces.get(&NetworkType::WiFi) {
            if wifi.is_available && wifi.signal_strength.unwrap_or(0) > 50 {
                return false;
            }
        }

        self.is_mobility_required() || self.is_low_latency_required()
    }

    pub fn get_recommended_interface_for_operation(
        &self,
        operation_type: &str,
        data_size_gb: f64,
    ) -> NetworkType {
        match operation_type {
            "shard_download" | "post_upload" => {
                if self
                    .interfaces
                    .get(&NetworkType::WiFi)
                    .map_or(false, |i| i.is_available)
                {
                    NetworkType::WiFi
                } else if self
                    .interfaces
                    .get(&NetworkType::Ethernet)
                    .map_or(false, |i| i.is_available)
                {
                    NetworkType::Ethernet
                } else if self.is_off_peak_hours() && data_size_gb < 1.0 {
                    NetworkType::FiveG
                } else {
                    self.current_interface.clone()
                }
            }
            "consensus" | "validation" => {
                if self.should_use_5g() {
                    NetworkType::FiveG
                } else {
                    self.current_interface.clone()
                }
            }
            _ => self.current_interface.clone(),
        }
    }

    pub fn get_data_usage_summary(&self) -> String {
        format!(
            "Data Usage - Total: {:.2} GB, Monthly: {:.2} GB, Daily: {:.2} GB, Cost: ${:.2}",
            self.data_usage.total_usage_gb,
            self.data_usage.monthly_usage_gb,
            self.data_usage.daily_usage_gb,
            self.data_usage.cost_this_month
        )
    }

    pub fn reset_monthly_stats(&mut self) {
        self.data_usage.monthly_usage_gb = 0.0;
        self.data_usage.cost_this_month = 0.0;
        self.data_usage.last_reset = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        for interface in self.interfaces.values_mut() {
            interface.data_usage_gb = 0.0;
        }

        info!("Monthly data usage stats reset");
    }

    fn is_mobility_required(&self) -> bool {
        false
    }

    fn is_low_latency_required(&self) -> bool {
        false
    }
}
