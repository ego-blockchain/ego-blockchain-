use ego_core::{Address, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub const DEFAULT_WITNESS_RATE_HZ: f64 = 0.5;
pub const DEFAULT_WITNESS_BATCH_INTERVAL_MS: u64 = 5_000;
pub const DEFAULT_MAX_MESSAGE_SIZE_BYTES: usize = 50_000;
pub const DEFAULT_MAX_BUNDLE_SIZE_BYTES: usize = 5_000_000;

pub const DEFAULT_MESSAGES_PER_PEER_PER_MINUTE: u32 = 60;
pub const DEFAULT_BYTES_PER_PEER_PER_MINUTE: usize = 1_000_000;

pub const HIGH_DRS_THRESHOLD: f64 = 0.8;
pub const LOW_DRS_THRESHOLD: f64 = 0.5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub witness_rate_hz: f64,
    pub witness_batch_interval_ms: u64,
    pub max_message_size_bytes: usize,
    pub max_bundle_size_bytes: usize,
    pub messages_per_peer_per_minute: u32,
    pub bytes_per_peer_per_minute: usize,
    pub enable_backpressure: bool,
    pub cellular_safe_mode: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            witness_rate_hz: DEFAULT_WITNESS_RATE_HZ,
            witness_batch_interval_ms: DEFAULT_WITNESS_BATCH_INTERVAL_MS,
            max_message_size_bytes: DEFAULT_MAX_MESSAGE_SIZE_BYTES,
            max_bundle_size_bytes: DEFAULT_MAX_BUNDLE_SIZE_BYTES,
            messages_per_peer_per_minute: DEFAULT_MESSAGES_PER_PEER_PER_MINUTE,
            bytes_per_peer_per_minute: DEFAULT_BYTES_PER_PEER_PER_MINUTE,
            enable_backpressure: true,
            cellular_safe_mode: false,
        }
    }
}

#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimitConfig,
    peer_buckets: Arc<RwLock<HashMap<Address, TokenBucket>>>,
    global_stats: Arc<RwLock<RateLimitStats>>,
}

#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    last_refill: Timestamp,
    message_count: u32,
    byte_count: usize,
    window_start: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitStats {
    pub total_messages: u64,
    pub total_bytes: u64,
    pub messages_dropped: u64,
    pub bytes_dropped: u64,
    pub backpressure_events: u32,
    pub last_updated: Timestamp,
}

impl Default for RateLimitStats {
    fn default() -> Self {
        Self {
            total_messages: 0,
            total_bytes: 0,
            messages_dropped: 0,
            bytes_dropped: 0,
            backpressure_events: 0,
            last_updated: Timestamp::now(),
        }
    }
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            peer_buckets: Arc::new(RwLock::new(HashMap::new())),
            global_stats: Arc::new(RwLock::new(RateLimitStats::default())),
        }
    }

    pub fn check_rate_limit(&self, peer_id: Address, message_size: usize) -> bool {

        if message_size > self.config.max_message_size_bytes {
            self.record_drop(message_size);
            return false;
        }

        let mut buckets = self.peer_buckets.write().unwrap();
        let now = Timestamp::now();

        let bucket = buckets.entry(peer_id).or_insert_with(|| TokenBucket {
            tokens: self.config.messages_per_peer_per_minute as f64,
            last_refill: now,
            message_count: 0,
            byte_count: 0,
            window_start: now,
        });

        let elapsed_secs = (now.as_millis() - bucket.last_refill.as_millis()) as f64 / 1000.0;
        let refill_rate = self.config.messages_per_peer_per_minute as f64 / 60.0;
        bucket.tokens = (bucket.tokens + elapsed_secs * refill_rate)
            .min(self.config.messages_per_peer_per_minute as f64);
        bucket.last_refill = now;

        if (now.as_millis() - bucket.window_start.as_millis()) >= 60_000 {
            bucket.message_count = 0;
            bucket.byte_count = 0;
            bucket.window_start = now;
        }

        if bucket.tokens < 1.0 {
            self.record_drop(message_size);
            return false;
        }

        if bucket.message_count >= self.config.messages_per_peer_per_minute {
            self.record_drop(message_size);
            return false;
        }

        if bucket.byte_count + message_size > self.config.bytes_per_peer_per_minute {
            self.record_drop(message_size);
            return false;
        }

        bucket.tokens -= 1.0;
        bucket.message_count += 1;
        bucket.byte_count += message_size;

        self.record_accept(message_size);
        true
    }

    pub fn check_bundle_size(&self, bundle_size: usize) -> bool {
        if bundle_size > self.config.max_bundle_size_bytes {
            self.record_drop(bundle_size);
            return false;
        }
        true
    }

    pub fn record_backpressure(&self) {
        let mut stats = self.global_stats.write().unwrap();
        stats.backpressure_events += 1;
        stats.last_updated = Timestamp::now();
    }

    pub fn get_stats(&self) -> RateLimitStats {
        self.global_stats.read().unwrap().clone()
    }

    pub fn reset_stats(&self) {
        let mut stats = self.global_stats.write().unwrap();
        *stats = RateLimitStats::default();
    }

    pub fn update_config(&mut self, config: RateLimitConfig) {
        self.config = config;
    }

    fn record_accept(&self, message_size: usize) {
        let mut stats = self.global_stats.write().unwrap();
        stats.total_messages += 1;
        stats.total_bytes += message_size as u64;
        stats.last_updated = Timestamp::now();
    }

    fn record_drop(&self, message_size: usize) {
        let mut stats = self.global_stats.write().unwrap();
        stats.messages_dropped += 1;
        stats.bytes_dropped += message_size as u64;
        stats.last_updated = Timestamp::now();
    }

    pub fn cleanup_old_buckets(&self, max_age_secs: u64) {
        let mut buckets = self.peer_buckets.write().unwrap();
        let now = Timestamp::now();

        buckets.retain(|_, bucket| {
            (now.as_millis() - bucket.last_refill.as_millis()) < (max_age_secs * 1000)
        });
    }
}

#[derive(Debug)]
pub struct DRSQuotaManager {
    quotas: Arc<RwLock<HashMap<Address, DRSQuota>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DRSQuota {
    pub node_id: Address,
    pub drs_score: f64,
    pub quota_band: QuotaBand,
    pub ru_limit: u64,
    pub publish_rate_limit: u32,
    pub audit_frequency: f64,
    pub last_updated: Timestamp,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum QuotaBand {
    High,
    Mid,
    Low,
}

impl DRSQuotaManager {
    pub fn new() -> Self {
        Self {
            quotas: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn update_quota(&self, node_id: Address, drs_score: f64) {
        let quota_band = if drs_score >= HIGH_DRS_THRESHOLD {
            QuotaBand::High
        } else if drs_score >= LOW_DRS_THRESHOLD {
            QuotaBand::Mid
        } else {
            QuotaBand::Low
        };

        let (ru_limit, publish_rate_limit, audit_frequency) = match quota_band {
            QuotaBand::High => (
                100_000,
                100,
                0.1,
            ),
            QuotaBand::Mid => (
                50_000,
                50,
                0.25,
            ),
            QuotaBand::Low => (
                20_000,
                20,
                0.5,
            ),
        };

        let quota = DRSQuota {
            node_id,
            drs_score,
            quota_band,
            ru_limit,
            publish_rate_limit,
            audit_frequency,
            last_updated: Timestamp::now(),
        };

        let mut quotas = self.quotas.write().unwrap();
        quotas.insert(node_id, quota);
    }

    pub fn get_quota(&self, node_id: Address) -> Option<DRSQuota> {
        let quotas = self.quotas.read().unwrap();
        quotas.get(&node_id).cloned()
    }

    pub fn can_publish(&self, node_id: Address) -> bool {
        let quotas = self.quotas.read().unwrap();
        quotas.get(&node_id).map_or(true, |q| {

            q.quota_band == QuotaBand::High
        })
    }

    pub fn should_audit(&self, node_id: Address) -> bool {
        let quotas = self.quotas.read().unwrap();
        quotas.get(&node_id).map_or(false, |q| {

            let random = (Timestamp::now().as_millis() % 100) as f64 / 100.0;
            random < q.audit_frequency
        })
    }

    pub fn get_all_quotas(&self) -> Vec<DRSQuota> {
        let quotas = self.quotas.read().unwrap();
        quotas.values().cloned().collect()
    }
}

impl Default for DRSQuotaManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct CellularSafeMode {
    enabled: Arc<RwLock<bool>>,
    stats: Arc<RwLock<CellularStats>>,
    buffered_bundles: Arc<RwLock<Vec<Vec<u8>>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellularStats {
    pub meta_events_sent: u64,
    pub heavy_bundles_buffered: u64,
    pub bundles_uploaded_over_wifi: u64,
    pub cellular_bytes_used: u64,
    pub wifi_bytes_used: u64,
    pub last_updated: Timestamp,
}

impl Default for CellularStats {
    fn default() -> Self {
        Self {
            meta_events_sent: 0,
            heavy_bundles_buffered: 0,
            bundles_uploaded_over_wifi: 0,
            cellular_bytes_used: 0,
            wifi_bytes_used: 0,
            last_updated: Timestamp::now(),
        }
    }
}

impl CellularSafeMode {
    pub fn new() -> Self {
        Self {
            enabled: Arc::new(RwLock::new(false)),
            stats: Arc::new(RwLock::new(CellularStats::default())),
            buffered_bundles: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn set_enabled(&self, enabled: bool) {
        let mut mode = self.enabled.write().unwrap();
        *mode = enabled;
    }

    pub fn is_enabled(&self) -> bool {
        *self.enabled.read().unwrap()
    }

    pub fn can_send_over_cellular(&self, data_size: usize) -> bool {
        if !self.is_enabled() {
            return true;
        }

        const META_EVENT_THRESHOLD: usize = 10_000;
        data_size <= META_EVENT_THRESHOLD
    }

    pub fn buffer_for_wifi(&self, data: Vec<u8>) {
        let mut bundles = self.buffered_bundles.write().unwrap();
        bundles.push(data);

        let mut stats = self.stats.write().unwrap();
        stats.heavy_bundles_buffered += 1;
        stats.last_updated = Timestamp::now();
    }

    pub fn get_buffered_data(&self) -> Vec<Vec<u8>> {
        let mut bundles = self.buffered_bundles.write().unwrap();
        bundles.drain(..).collect()
    }

    pub fn record_cellular_usage(&self, bytes: usize) {
        let mut stats = self.stats.write().unwrap();
        stats.meta_events_sent += 1;
        stats.cellular_bytes_used += bytes as u64;
        stats.last_updated = Timestamp::now();
    }

    pub fn record_wifi_usage(&self, bytes: usize, bundle_count: usize) {
        let mut stats = self.stats.write().unwrap();
        stats.bundles_uploaded_over_wifi += bundle_count as u64;
        stats.wifi_bytes_used += bytes as u64;
        stats.last_updated = Timestamp::now();
    }

    pub fn get_stats(&self) -> CellularStats {
        self.stats.read().unwrap().clone()
    }

    pub fn reset_stats(&self) {
        let mut stats = self.stats.write().unwrap();
        *stats = CellularStats::default();
    }

    pub fn buffered_count(&self) -> usize {
        self.buffered_bundles.read().unwrap().len()
    }
}

impl Default for CellularSafeMode {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_basic() {
        let config = RateLimitConfig::default();
        let limiter = RateLimiter::new(config);
        let peer = Address::new([1u8; 20]);

        assert!(limiter.check_rate_limit(peer, 1000));

        for _ in 0..50 {
            assert!(limiter.check_rate_limit(peer, 1000));
        }

        let stats = limiter.get_stats();
        assert_eq!(stats.total_messages, 51);
        assert_eq!(stats.total_bytes, 51_000);
    }

    #[test]
    fn test_rate_limiter_oversized_message() {
        let config = RateLimitConfig::default();
        let limiter = RateLimiter::new(config);
        let peer = Address::new([1u8; 20]);

        assert!(!limiter.check_rate_limit(peer, 100_000));

        let stats = limiter.get_stats();
        assert_eq!(stats.messages_dropped, 1);
        assert_eq!(stats.bytes_dropped, 100_000);
    }

    #[test]
    fn test_rate_limiter_per_peer() {
        let config = RateLimitConfig::default();
        let limiter = RateLimiter::new(config);
        let peer1 = Address::new([1u8; 20]);
        let peer2 = Address::new([2u8; 20]);

        for _ in 0..30 {
            assert!(limiter.check_rate_limit(peer1, 1000));
            assert!(limiter.check_rate_limit(peer2, 1000));
        }

        let stats = limiter.get_stats();
        assert_eq!(stats.total_messages, 60);
    }

    #[test]
    fn test_bundle_size_check() {
        let config = RateLimitConfig::default();
        let limiter = RateLimiter::new(config);

        assert!(limiter.check_bundle_size(1_000_000));

        assert!(!limiter.check_bundle_size(10_000_000));
    }

    #[test]
    fn test_drs_quota_manager() {
        let manager = DRSQuotaManager::new();
        let node = Address::new([1u8; 20]);

        manager.update_quota(node, 0.9);
        let quota = manager.get_quota(node).unwrap();
        assert_eq!(quota.quota_band, QuotaBand::High);
        assert_eq!(quota.ru_limit, 100_000);
        assert!(manager.can_publish(node));

        manager.update_quota(node, 0.6);
        let quota = manager.get_quota(node).unwrap();
        assert_eq!(quota.quota_band, QuotaBand::Mid);
        assert_eq!(quota.ru_limit, 50_000);

        manager.update_quota(node, 0.3);
        let quota = manager.get_quota(node).unwrap();
        assert_eq!(quota.quota_band, QuotaBand::Low);
        assert_eq!(quota.ru_limit, 20_000);
        assert_eq!(quota.audit_frequency, 0.5);
    }

    #[test]
    fn test_cellular_safe_mode() {
        let mode = CellularSafeMode::new();

        assert!(!mode.is_enabled());
        assert!(mode.can_send_over_cellular(100_000));

        mode.set_enabled(true);
        assert!(mode.is_enabled());

        assert!(mode.can_send_over_cellular(5_000));

        assert!(!mode.can_send_over_cellular(100_000));

        mode.buffer_for_wifi(vec![1, 2, 3]);
        assert_eq!(mode.buffered_count(), 1);

        let buffered = mode.get_buffered_data();
        assert_eq!(buffered.len(), 1);
        assert_eq!(mode.buffered_count(), 0);
    }

    #[test]
    fn test_cellular_stats() {
        let mode = CellularSafeMode::new();

        mode.record_cellular_usage(1000);
        mode.record_cellular_usage(2000);
        mode.record_wifi_usage(50_000, 5);

        let stats = mode.get_stats();
        assert_eq!(stats.meta_events_sent, 2);
        assert_eq!(stats.cellular_bytes_used, 3_000);
        assert_eq!(stats.wifi_bytes_used, 50_000);
        assert_eq!(stats.bundles_uploaded_over_wifi, 5);
    }

    #[test]
    fn test_backpressure_recording() {
        let config = RateLimitConfig::default();
        let limiter = RateLimiter::new(config);

        limiter.record_backpressure();
        limiter.record_backpressure();

        let stats = limiter.get_stats();
        assert_eq!(stats.backpressure_events, 2);
    }

    #[test]
    fn test_bucket_cleanup() {
        let config = RateLimitConfig::default();
        let limiter = RateLimiter::new(config);

        let peer1 = Address::new([1u8; 20]);
        let peer2 = Address::new([2u8; 20]);

        limiter.check_rate_limit(peer1, 1000);
        limiter.check_rate_limit(peer2, 1000);

        {
            let buckets = limiter.peer_buckets.read().unwrap();
            assert_eq!(buckets.len(), 2);
        }

        limiter.cleanup_old_buckets(0);

        {
            let buckets = limiter.peer_buckets.read().unwrap();
            assert_eq!(buckets.len(), 0);
        }
    }
}
