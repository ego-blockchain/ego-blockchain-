use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{debug, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthSharingConfig {
    pub enabled: bool,
    pub max_shared_bandwidth_mbps: u64,
    pub price_per_mb_egoc: f64,
    pub daily_limit_mb: u64,
    pub allowed_devices: Vec<String>,
    pub rate_limiting_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedConnection {
    pub device_id: String,
    pub device_name: Option<String>,
    pub connected_at: u64,
    pub data_used_mb: f64,
    pub egoc_earned: f64,
    pub rate_limit_mbps: u64,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthTier {
    pub name: String,
    pub daily_limit_mb: u64,
    pub price_per_mb_egoc: f64,
    pub max_speed_mbps: u64,
}

pub struct BandwidthSharingManager {
    pub config: BandwidthSharingConfig,
    pub active_connections: HashMap<String, SharedConnection>,
    pub bandwidth_tiers: Vec<BandwidthTier>,
    pub total_earned_egoc: f64,
    pub daily_shared_mb: f64,
    pub last_reset: u64,
    pub event_sender: mpsc::UnboundedSender<BandwidthSharingEvent>,
    pub event_receiver: mpsc::UnboundedReceiver<BandwidthSharingEvent>,
}

#[derive(Debug, Clone)]
pub enum BandwidthSharingEvent {
    DeviceConnected(String),
    DeviceDisconnected(String),
    DataLimitReached(String),
    EgocEarned(f64),
    DailyLimitReached,
}

impl Default for BandwidthSharingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_shared_bandwidth_mbps: 50,
            price_per_mb_egoc: 0.01,
            daily_limit_mb: 1024,
            allowed_devices: Vec::new(),
            rate_limiting_enabled: true,
        }
    }
}

impl BandwidthSharingManager {
    pub fn new(config: BandwidthSharingConfig) -> Self {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();

        let bandwidth_tiers = vec![
            BandwidthTier {
                name: "Basic".to_string(),
                daily_limit_mb: 50,
                price_per_mb_egoc: 0.005,
                max_speed_mbps: 5,
            },
            BandwidthTier {
                name: "Standard".to_string(),
                daily_limit_mb: 200,
                price_per_mb_egoc: 0.01,
                max_speed_mbps: 20,
            },
            BandwidthTier {
                name: "Premium".to_string(),
                daily_limit_mb: 500,
                price_per_mb_egoc: 0.02,
                max_speed_mbps: 50,
            },
        ];

        Self {
            config,
            active_connections: HashMap::new(),
            bandwidth_tiers,
            total_earned_egoc: 0.0,
            daily_shared_mb: 0.0,
            last_reset: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            event_sender,
            event_receiver,
        }
    }

    pub fn enable_sharing(&mut self, max_bandwidth_mbps: u64, daily_limit_mb: u64) {
        self.config.enabled = true;
        self.config.max_shared_bandwidth_mbps = max_bandwidth_mbps;
        self.config.daily_limit_mb = daily_limit_mb;
        info!(
            "Bandwidth sharing enabled: {} Mbps, {} MB daily limit",
            max_bandwidth_mbps, daily_limit_mb
        );
    }

    pub fn disable_sharing(&mut self) {
        self.config.enabled = false;
        for (device_id, _) in self.active_connections.clone() {
            self.disconnect_device(&device_id);
        }
        info!("Bandwidth sharing disabled");
    }

    pub fn connect_device(
        &mut self,
        device_id: String,
        device_name: Option<String>,
        tier_name: &str,
    ) -> Result<(), String> {
        if !self.config.enabled {
            return Err("Bandwidth sharing is disabled".to_string());
        }

        if self.daily_shared_mb >= self.config.daily_limit_mb as f64 {
            return Err("Daily sharing limit reached".to_string());
        }

        let tier = self
            .bandwidth_tiers
            .iter()
            .find(|t| t.name == tier_name)
            .ok_or_else(|| "Invalid tier".to_string())?;

        if !self.config.allowed_devices.is_empty()
            && !self.config.allowed_devices.contains(&device_id)
        {
            return Err("Device not in allowlist".to_string());
        }

        let connection = SharedConnection {
            device_id: device_id.clone(),
            device_name,
            connected_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            data_used_mb: 0.0,
            egoc_earned: 0.0,
            rate_limit_mbps: tier.max_speed_mbps,
            is_active: true,
        };

        self.active_connections
            .insert(device_id.clone(), connection);
        let _ = self
            .event_sender
            .send(BandwidthSharingEvent::DeviceConnected(device_id.clone()));

        info!(
            "Device connected for bandwidth sharing: {} (tier: {})",
            device_id, tier_name
        );
        Ok(())
    }

    pub fn disconnect_device(&mut self, device_id: &str) {
        if let Some(mut connection) = self.active_connections.remove(device_id) {
            connection.is_active = false;
            let _ = self
                .event_sender
                .send(BandwidthSharingEvent::DeviceDisconnected(
                    device_id.to_string(),
                ));
            info!(
                "Device disconnected: {} (earned: {:.4} EGOC)",
                device_id, connection.egoc_earned
            );
        }
    }

    pub fn record_data_usage(&mut self, device_id: &str, bytes_used: u64) -> Result<f64, String> {
        let mb_used = bytes_used as f64 / 1_000_000.0;

        let connection = self
            .active_connections
            .get_mut(device_id)
            .ok_or_else(|| "Device not connected".to_string())?;

        let tier = self
            .bandwidth_tiers
            .iter()
            .find(|t| t.max_speed_mbps == connection.rate_limit_mbps)
            .ok_or_else(|| "Invalid tier configuration".to_string())?;

        if connection.data_used_mb + mb_used > tier.daily_limit_mb as f64 {
            let _ = self
                .event_sender
                .send(BandwidthSharingEvent::DataLimitReached(
                    device_id.to_string(),
                ));
            return Err("Device daily limit exceeded".to_string());
        }

        if self.daily_shared_mb + mb_used > self.config.daily_limit_mb as f64 {
            let _ = self
                .event_sender
                .send(BandwidthSharingEvent::DailyLimitReached);
            return Err("Global daily limit exceeded".to_string());
        }

        let egoc_earned = mb_used * tier.price_per_mb_egoc;

        connection.data_used_mb += mb_used;
        connection.egoc_earned += egoc_earned;

        self.daily_shared_mb += mb_used;
        self.total_earned_egoc += egoc_earned;

        let _ = self
            .event_sender
            .send(BandwidthSharingEvent::EgocEarned(egoc_earned));

        debug!(
            "Data usage recorded for {}: {:.2} MB, earned {:.4} EGOC",
            device_id, mb_used, egoc_earned
        );
        Ok(egoc_earned)
    }

    pub fn get_available_bandwidth(&self) -> u64 {
        if !self.config.enabled {
            return 0;
        }

        let used_bandwidth: u64 = self
            .active_connections
            .values()
            .map(|conn| conn.rate_limit_mbps)
            .sum();

        self.config
            .max_shared_bandwidth_mbps
            .saturating_sub(used_bandwidth)
    }

    pub fn get_sharing_stats(&self) -> BandwidthSharingStats {
        BandwidthSharingStats {
            enabled: self.config.enabled,
            active_connections: self.active_connections.len(),
            daily_shared_mb: self.daily_shared_mb,
            daily_limit_mb: self.config.daily_limit_mb,
            total_earned_egoc: self.total_earned_egoc,
            available_bandwidth_mbps: self.get_available_bandwidth(),
            max_shared_bandwidth_mbps: self.config.max_shared_bandwidth_mbps,
        }
    }

    pub fn reset_daily_stats(&mut self) {
        self.daily_shared_mb = 0.0;
        self.last_reset = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        for connection in self.active_connections.values_mut() {
            connection.data_used_mb = 0.0;
        }

        info!("Daily bandwidth sharing stats reset");
    }

    pub fn add_allowed_device(&mut self, device_id: String) {
        if !self.config.allowed_devices.contains(&device_id) {
            self.config.allowed_devices.push(device_id.clone());
            info!("Added device to allowlist: {}", device_id);
        }
    }

    pub fn remove_allowed_device(&mut self, device_id: &str) {
        self.config.allowed_devices.retain(|id| id != device_id);
        self.disconnect_device(device_id);
        info!("Removed device from allowlist: {}", device_id);
    }

    pub fn get_bandwidth_tiers(&self) -> &Vec<BandwidthTier> {
        &self.bandwidth_tiers
    }

    pub fn update_pricing(&mut self, tier_name: &str, new_price_per_mb: f64) -> Result<(), String> {
        let tier = self
            .bandwidth_tiers
            .iter_mut()
            .find(|t| t.name == tier_name)
            .ok_or_else(|| "Tier not found".to_string())?;

        tier.price_per_mb_egoc = new_price_per_mb;
        info!(
            "Updated pricing for tier {}: {:.4} EGOC per MB",
            tier_name, new_price_per_mb
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthSharingStats {
    pub enabled: bool,
    pub active_connections: usize,
    pub daily_shared_mb: f64,
    pub daily_limit_mb: u64,
    pub total_earned_egoc: f64,
    pub available_bandwidth_mbps: u64,
    pub max_shared_bandwidth_mbps: u64,
}
