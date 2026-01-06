use crate::{EgoError, EgoResult, Hash, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub struct Utils;

impl Utils {
    pub fn random_hash() -> Hash {
        Hash::new(rand::random())
    }

    pub fn generate_id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    pub fn format_bytes(bytes: u64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        const THRESHOLD: u64 = 1024;

        if bytes < THRESHOLD {
            return format!("{} B", bytes);
        }

        let mut size = bytes as f64;
        let mut unit_index = 0;

        while size >= THRESHOLD as f64 && unit_index < UNITS.len() - 1 {
            size /= THRESHOLD as f64;
            unit_index += 1;
        }

        format!("{:.2} {}", size, UNITS[unit_index])
    }

    pub fn format_duration(duration_ms: u64) -> String {
        if duration_ms < 1000 {
            format!("{}ms", duration_ms)
        } else if duration_ms < 60_000 {
            format!("{:.1}s", duration_ms as f64 / 1000.0)
        } else if duration_ms < 3_600_000 {
            format!("{:.1}m", duration_ms as f64 / 60_000.0)
        } else {
            format!("{:.1}h", duration_ms as f64 / 3_600_000.0)
        }
    }

    pub fn percentage(part: u64, total: u64) -> f64 {
        if total == 0 {
            0.0
        } else {
            (part as f64 / total as f64) * 100.0
        }
    }

    pub fn validate_geohash(geohash: &str) -> bool {
        if geohash.len() < 4 || geohash.len() > 12 {
            return false;
        }

        const VALID_CHARS: &str = "0123456789bcdefghjkmnpqrstuvwxyz";
        geohash.chars().all(|c| VALID_CHARS.contains(c))
    }

    pub fn time_since(timestamp: Timestamp) -> u64 {
        let now = Timestamp::now();
        now.as_millis().saturating_sub(timestamp.as_millis())
    }

    pub fn is_timestamp_valid(timestamp: Timestamp, max_drift_ms: u64) -> bool {
        let now = Timestamp::now();
        let diff = if now.as_millis() >= timestamp.as_millis() {
            now.as_millis() - timestamp.as_millis()
        } else {
            timestamp.as_millis() - now.as_millis()
        };

        diff <= max_drift_ms
    }

    pub fn truncate_string(s: &str, max_len: usize) -> String {
        if s.len() <= max_len {
            s.to_string()
        } else {
            format!("{}...", &s[..max_len.saturating_sub(3)])
        }
    }

    pub fn hex_to_bytes(hex: &str) -> EgoResult<Vec<u8>> {
        if hex.len() % 2 != 0 {
            return Err(EgoError::InvalidTransaction(
                "Hex string must have even length".to_string(),
            ));
        }

        let hex = hex.strip_prefix("0x").unwrap_or(hex);

        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|e| EgoError::InvalidTransaction(format!("Invalid hex: {}", e)))
    }

    pub fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn validate_slice_id(slice_id: &str) -> bool {
        if slice_id.is_empty() || slice_id.len() > 64 {
            return false;
        }

        slice_id
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    }

    pub fn moving_average(values: &[f64], window: usize) -> Vec<f64> {
        if values.len() < window || window == 0 {
            return Vec::new();
        }

        let mut averages = Vec::new();

        for i in window - 1..values.len() {
            let sum: f64 = values[i + 1 - window..=i].iter().sum();
            averages.push(sum / window as f64);
        }

        averages
    }

    pub fn exponential_moving_average(values: &[f64], alpha: f64) -> Vec<f64> {
        if values.is_empty() || alpha <= 0.0 || alpha > 1.0 {
            return Vec::new();
        }

        let mut ema_values = Vec::with_capacity(values.len());
        ema_values.push(values[0]);

        for i in 1..values.len() {
            let ema = alpha * values[i] + (1.0 - alpha) * ema_values[i - 1];
            ema_values.push(ema);
        }

        ema_values
    }

    pub fn standard_deviation(values: &[f64]) -> f64 {
        if values.is_empty() {
            return 0.0;
        }

        let mean: f64 = values.iter().sum::<f64>() / values.len() as f64;
        let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / values.len() as f64;
        variance.sqrt()
    }

    pub fn percentile(values: &[f64], percentile: f64) -> f64 {
        if values.is_empty() || percentile < 0.0 || percentile > 100.0 {
            return 0.0;
        }

        let mut sorted = values.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let index = (percentile / 100.0 * (sorted.len() - 1) as f64).round() as usize;
        sorted[index.min(sorted.len() - 1)]
    }

    pub fn median(values: &[f64]) -> f64 {
        Self::percentile(values, 50.0)
    }

    pub fn sanitize_input(input: &str, max_len: usize) -> String {
        input
            .chars()
            .filter(|c| c.is_alphanumeric() || c.is_whitespace() || *c == '-' || *c == '_')
            .take(max_len)
            .collect()
    }

    pub fn validate_url(url: &str) -> bool {
        if url.is_empty() || url.len() > 2048 {
            return false;
        }

        url.starts_with("http://") || url.starts_with("https://")
    }

    pub fn validate_email(email: &str) -> bool {
        if email.is_empty() || email.len() > 256 {
            return false;
        }

        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() != 2 {
            return false;
        }

        !parts[0].is_empty() && !parts[1].is_empty() && parts[1].contains('.')
    }

    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    pub fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
        if a.len() != b.len() {
            return usize::MAX;
        }

        a.iter()
            .zip(b.iter())
            .map(|(x, y)| (x ^ y).count_ones() as usize)
            .sum()
    }

    pub fn levenshtein_distance(a: &str, b: &str) -> usize {
        let a_len = a.len();
        let b_len = b.len();

        if a_len == 0 {
            return b_len;
        }
        if b_len == 0 {
            return a_len;
        }

        let mut matrix = vec![vec![0usize; b_len + 1]; a_len + 1];

        for i in 0..=a_len {
            matrix[i][0] = i;
        }
        for j in 0..=b_len {
            matrix[0][j] = j;
        }

        let a_chars: Vec<char> = a.chars().collect();
        let b_chars: Vec<char> = b.chars().collect();

        for i in 1..=a_len {
            for j in 1..=b_len {
                let cost = if a_chars[i - 1] == b_chars[j - 1] {
                    0
                } else {
                    1
                };
                matrix[i][j] = (matrix[i - 1][j] + 1)
                    .min(matrix[i][j - 1] + 1)
                    .min(matrix[i - 1][j - 1] + cost);
            }
        }

        matrix[a_len][b_len]
    }

    pub fn merkle_root(leaves: &[Hash]) -> Hash {
        if leaves.is_empty() {
            return Hash::ZERO;
        }
        if leaves.len() == 1 {
            return leaves[0];
        }

        let mut level = leaves.to_vec();

        while level.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in level.chunks(2) {
                if chunk.len() == 2 {
                    let mut combined = Vec::with_capacity(64);
                    combined.extend_from_slice(chunk[0].as_bytes());
                    combined.extend_from_slice(chunk[1].as_bytes());
                    let hash_result = blake3::hash(&combined);
                    next_level.push(Hash::new(*hash_result.as_bytes()));
                } else {
                    next_level.push(chunk[0]);
                }
            }

            level = next_level;
        }

        level[0]
    }

    pub fn verify_merkle_proof(leaf: Hash, proof: &[Hash], root: Hash, index: usize) -> bool {
        let mut current = leaf;
        let mut idx = index;

        for proof_element in proof {
            let mut combined = Vec::with_capacity(64);
            if idx % 2 == 0 {
                combined.extend_from_slice(current.as_bytes());
                combined.extend_from_slice(proof_element.as_bytes());
            } else {
                combined.extend_from_slice(proof_element.as_bytes());
                combined.extend_from_slice(current.as_bytes());
            }
            let hash_result = blake3::hash(&combined);
            current = Hash::new(*hash_result.as_bytes());
            idx /= 2;
        }

        current == root
    }

    pub fn generate_nonce() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64
    }

    pub fn is_power_of_two(n: u64) -> bool {
        n > 0 && (n & (n - 1)) == 0
    }

    pub fn next_power_of_two(n: u64) -> u64 {
        if n == 0 {
            return 1;
        }
        let mut p = 1u64;
        while p < n {
            p = p.checked_shl(1).unwrap_or(u64::MAX);
        }
        p
    }

    pub fn checksum(data: &[u8]) -> u32 {
        let mut checksum = 0u32;
        for &byte in data {
            checksum = checksum.wrapping_add(byte as u32);
        }
        checksum
    }

    pub fn rate_limit_key(prefix: &str, identifier: &str, window_secs: u64) -> String {
        let now = Timestamp::now().as_secs();
        let window = now / window_secs;
        format!("{}:{}:{}", prefix, identifier, window)
    }

    pub fn exponential_backoff(attempt: u32, base_ms: u64, max_ms: u64) -> u64 {
        let backoff = base_ms * 2u64.saturating_pow(attempt);
        backoff.min(max_ms)
    }

    pub fn jitter(value: u64, jitter_percent: u32) -> u64 {
        if jitter_percent == 0 || jitter_percent > 100 {
            return value;
        }

        let jitter_amount = (value as f64 * jitter_percent as f64 / 100.0) as u64;
        let random_jitter = rand::random::<u64>() % (jitter_amount * 2 + 1);
        value
            .saturating_add(random_jitter)
            .saturating_sub(jitter_amount)
    }

    pub fn extract_domain(url: &str) -> Option<String> {
        let url = url
            .strip_prefix("http://")
            .or_else(|| url.strip_prefix("https://"))?;
        let domain = url.split('/').next()?;
        Some(domain.to_string())
    }

    pub fn is_valid_ipv4(ip: &str) -> bool {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() != 4 {
            return false;
        }

        parts.iter().all(|part| part.parse::<u8>().is_ok())
    }

    pub fn is_valid_ipv6(ip: &str) -> bool {
        let parts: Vec<&str> = ip.split(':').collect();
        if parts.len() < 3 || parts.len() > 8 {
            return false;
        }

        parts.iter().all(|part| {
            part.is_empty() || part.len() <= 4 && part.chars().all(|c| c.is_ascii_hexdigit())
        })
    }

    pub fn normalize_path(path: &str) -> String {
        path.replace('\\', "/")
            .split('/')
            .filter(|s| !s.is_empty() && *s != ".")
            .collect::<Vec<_>>()
            .join("/")
    }

    pub fn circular_buffer_index(index: usize, capacity: usize) -> usize {
        if capacity == 0 {
            0
        } else {
            index % capacity
        }
    }

    pub fn safe_divide(numerator: u64, denominator: u64) -> f64 {
        if denominator == 0 {
            0.0
        } else {
            numerator as f64 / denominator as f64
        }
    }

    pub fn clamp<T: PartialOrd>(value: T, min: T, max: T) -> T {
        if value < min {
            min
        } else if value > max {
            max
        } else {
            value
        }
    }

    pub fn interpolate(start: f64, end: f64, t: f64) -> f64 {
        start + (end - start) * t.clamp(0.0, 1.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigManager {
    params: HashMap<String, ConfigValue>,
    file_path: Option<String>,
    last_updated: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConfigValue {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Array(Vec<ConfigValue>),
    Object(HashMap<String, ConfigValue>),
}

impl ConfigManager {
    pub fn new() -> Self {
        Self {
            params: HashMap::new(),
            file_path: None,
            last_updated: Timestamp::now(),
        }
    }

    pub fn load_from_file(path: &str) -> EgoResult<Self> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| EgoError::IoError(format!("Failed to read config file: {}", e)))?;

        let params: HashMap<String, ConfigValue> =
            serde_json::from_str(&contents).map_err(|e| EgoError::JsonError(e.to_string()))?;

        Ok(Self {
            params,
            file_path: Some(path.to_string()),
            last_updated: Timestamp::now(),
        })
    }

    pub fn save_to_file(&self, path: &str) -> EgoResult<()> {
        let contents = serde_json::to_string_pretty(&self.params)
            .map_err(|e| EgoError::JsonError(e.to_string()))?;

        std::fs::write(path, contents)
            .map_err(|e| EgoError::IoError(format!("Failed to write config file: {}", e)))?;

        Ok(())
    }

    pub fn reload(&mut self) -> EgoResult<()> {
        if let Some(path) = &self.file_path.clone() {
            let contents = std::fs::read_to_string(path)
                .map_err(|e| EgoError::IoError(format!("Failed to read config file: {}", e)))?;

            self.params =
                serde_json::from_str(&contents).map_err(|e| EgoError::JsonError(e.to_string()))?;
            self.last_updated = Timestamp::now();
            Ok(())
        } else {
            Err(EgoError::ConfigurationError("No file path set".to_string()))
        }
    }

    pub fn get_string(&self, key: &str) -> Option<&String> {
        match self.params.get(key) {
            Some(ConfigValue::String(value)) => Some(value),
            _ => None,
        }
    }

    pub fn get_integer(&self, key: &str) -> Option<i64> {
        match self.params.get(key) {
            Some(ConfigValue::Integer(value)) => Some(*value),
            _ => None,
        }
    }

    pub fn get_float(&self, key: &str) -> Option<f64> {
        match self.params.get(key) {
            Some(ConfigValue::Float(value)) => Some(*value),
            _ => None,
        }
    }

    pub fn get_boolean(&self, key: &str) -> Option<bool> {
        match self.params.get(key) {
            Some(ConfigValue::Boolean(value)) => Some(*value),
            _ => None,
        }
    }

    pub fn get_array(&self, key: &str) -> Option<&Vec<ConfigValue>> {
        match self.params.get(key) {
            Some(ConfigValue::Array(values)) => Some(values),
            _ => None,
        }
    }

    pub fn get_object(&self, key: &str) -> Option<&HashMap<String, ConfigValue>> {
        match self.params.get(key) {
            Some(ConfigValue::Object(map)) => Some(map),
            _ => None,
        }
    }

    pub fn set(&mut self, key: String, value: ConfigValue) {
        self.params.insert(key, value);
        self.last_updated = Timestamp::now();
    }

    pub fn set_string(&mut self, key: String, value: String) {
        self.set(key, ConfigValue::String(value));
    }

    pub fn set_integer(&mut self, key: String, value: i64) {
        self.set(key, ConfigValue::Integer(value));
    }

    pub fn set_float(&mut self, key: String, value: f64) {
        self.set(key, ConfigValue::Float(value));
    }

    pub fn set_boolean(&mut self, key: String, value: bool) {
        self.set(key, ConfigValue::Boolean(value));
    }

    pub fn get_all(&self) -> &HashMap<String, ConfigValue> {
        &self.params
    }

    pub fn contains(&self, key: &str) -> bool {
        self.params.contains_key(key)
    }

    pub fn remove(&mut self, key: &str) -> Option<ConfigValue> {
        let result = self.params.remove(key);
        if result.is_some() {
            self.last_updated = Timestamp::now();
        }
        result
    }

    pub fn clear(&mut self) {
        self.params.clear();
        self.last_updated = Timestamp::now();
    }

    pub fn keys(&self) -> Vec<&String> {
        self.params.keys().collect()
    }

    pub fn len(&self) -> usize {
        self.params.len()
    }

    pub fn is_empty(&self) -> bool {
        self.params.is_empty()
    }

    pub fn merge(&mut self, other: ConfigManager) {
        for (key, value) in other.params {
            self.params.insert(key, value);
        }
        self.last_updated = Timestamp::now();
    }

    pub fn get_with_default_string(&self, key: &str, default: String) -> String {
        self.get_string(key).cloned().unwrap_or(default)
    }

    pub fn get_with_default_integer(&self, key: &str, default: i64) -> i64 {
        self.get_integer(key).unwrap_or(default)
    }

    pub fn get_with_default_float(&self, key: &str, default: f64) -> f64 {
        self.get_float(key).unwrap_or(default)
    }

    pub fn get_with_default_boolean(&self, key: &str, default: bool) -> bool {
        self.get_boolean(key).unwrap_or(default)
    }
}

#[derive(Debug)]
pub struct PerformanceMonitor {
    metrics: HashMap<String, Vec<MetricSample>>,
    max_samples: usize,
    start_time: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSample {
    pub timestamp: Timestamp,
    pub value: f64,
    pub labels: HashMap<String, String>,
}

impl PerformanceMonitor {
    pub fn new(max_samples: usize) -> Self {
        Self {
            metrics: HashMap::new(),
            max_samples,
            start_time: Timestamp::now(),
        }
    }

    pub fn record(
        &mut self,
        metric_name: &str,
        value: f64,
        labels: Option<HashMap<String, String>>,
    ) {
        let sample = MetricSample {
            timestamp: Timestamp::now(),
            value,
            labels: labels.unwrap_or_default(),
        };

        let samples = self
            .metrics
            .entry(metric_name.to_string())
            .or_insert_with(Vec::new);
        samples.push(sample);

        if samples.len() > self.max_samples {
            samples.remove(0);
        }
    }

    pub fn record_increment(&mut self, metric_name: &str, labels: Option<HashMap<String, String>>) {
        let current = self.get_latest_value(metric_name).unwrap_or(0.0);
        self.record(metric_name, current + 1.0, labels);
    }

    pub fn record_decrement(&mut self, metric_name: &str, labels: Option<HashMap<String, String>>) {
        let current = self.get_latest_value(metric_name).unwrap_or(0.0);
        self.record(metric_name, (current - 1.0).max(0.0), labels);
    }

    pub fn get_stats(&self, metric_name: &str) -> Option<MetricStats> {
        let samples = self.metrics.get(metric_name)?;

        if samples.is_empty() {
            return None;
        }

        let values: Vec<f64> = samples.iter().map(|s| s.value).collect();
        let count = values.len() as f64;
        let sum: f64 = values.iter().sum();
        let mean = sum / count;

        let mut sorted_values = values.clone();
        sorted_values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let min = sorted_values[0];
        let max = sorted_values[sorted_values.len() - 1];

        let median = if sorted_values.len() % 2 == 0 {
            let mid = sorted_values.len() / 2;
            (sorted_values[mid - 1] + sorted_values[mid]) / 2.0
        } else {
            sorted_values[sorted_values.len() / 2]
        };

        let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / count;
        let std_dev = variance.sqrt();

        let p95_index =
            ((sorted_values.len() as f64 * 0.95).ceil() as usize).min(sorted_values.len() - 1);
        let p95 = sorted_values[p95_index];

        let p99_index =
            ((sorted_values.len() as f64 * 0.99).ceil() as usize).min(sorted_values.len() - 1);
        let p99 = sorted_values[p99_index];

        Some(MetricStats {
            count: count as u64,
            mean,
            median,
            min,
            max,
            std_dev,
            sum,
            p95,
            p99,
            last_value: samples.last().unwrap().value,
            last_updated: samples.last().unwrap().timestamp,
        })
    }

    pub fn get_metric_names(&self) -> Vec<&String> {
        self.metrics.keys().collect()
    }

    pub fn get_samples(&self, metric_name: &str) -> Option<&Vec<MetricSample>> {
        self.metrics.get(metric_name)
    }

    pub fn get_latest_value(&self, metric_name: &str) -> Option<f64> {
        self.metrics
            .get(metric_name)
            .and_then(|samples| samples.last())
            .map(|sample| sample.value)
    }

    pub fn get_samples_since(&self, metric_name: &str, since: Timestamp) -> Vec<MetricSample> {
        self.metrics
            .get(metric_name)
            .map(|samples| {
                samples
                    .iter()
                    .filter(|s| s.timestamp.as_millis() >= since.as_millis())
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn uptime_ms(&self) -> u64 {
        Timestamp::now().as_millis() - self.start_time.as_millis()
    }

    pub fn uptime_secs(&self) -> u64 {
        self.uptime_ms() / 1000
    }

    pub fn clear(&mut self) {
        self.metrics.clear();
    }

    pub fn clear_metric(&mut self, metric_name: &str) {
        self.metrics.remove(metric_name);
    }

    pub fn trim_old_samples(&mut self, older_than_ms: u64) {
        let cutoff = Timestamp::now().as_millis().saturating_sub(older_than_ms);

        for samples in self.metrics.values_mut() {
            samples.retain(|s| s.timestamp.as_millis() >= cutoff);
        }
    }

    pub fn export_json(&self) -> EgoResult<String> {
        serde_json::to_string_pretty(&self.metrics).map_err(|e| EgoError::JsonError(e.to_string()))
    }

    pub fn set_max_samples(&mut self, max_samples: usize) {
        self.max_samples = max_samples;

        for samples in self.metrics.values_mut() {
            while samples.len() > max_samples {
                samples.remove(0);
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricStats {
    pub count: u64,
    pub mean: f64,
    pub median: f64,
    pub min: f64,
    pub max: f64,
    pub std_dev: f64,
    pub sum: f64,
    pub p95: f64,
    pub p99: f64,
    pub last_value: f64,
    pub last_updated: Timestamp,
}

#[derive(Debug, Clone)]
pub struct RateLimiter {
    limits: HashMap<String, RateLimitConfig>,
    counters: HashMap<String, RateLimitCounter>,
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub max_requests: u64,
    pub window_ms: u64,
}

#[derive(Debug, Clone)]
struct RateLimitCounter {
    count: u64,
    window_start: Timestamp,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            limits: HashMap::new(),
            counters: HashMap::new(),
        }
    }

    pub fn add_limit(&mut self, key: String, max_requests: u64, window_ms: u64) {
        self.limits.insert(
            key,
            RateLimitConfig {
                max_requests,
                window_ms,
            },
        );
    }

    pub fn check_rate_limit(&mut self, key: &str) -> bool {
        let config = match self.limits.get(key) {
            Some(c) => c.clone(),
            None => return true,
        };

        let now = Timestamp::now();
        let counter = self
            .counters
            .entry(key.to_string())
            .or_insert(RateLimitCounter {
                count: 0,
                window_start: now,
            });

        let elapsed = now.as_millis() - counter.window_start.as_millis();

        if elapsed >= config.window_ms {
            counter.count = 1;
            counter.window_start = now;
            true
        } else if counter.count < config.max_requests {
            counter.count += 1;
            true
        } else {
            false
        }
    }

    pub fn get_remaining(&self, key: &str) -> Option<u64> {
        let config = self.limits.get(key)?;
        let counter = self.counters.get(key)?;

        Some(config.max_requests.saturating_sub(counter.count))
    }

    pub fn reset(&mut self, key: &str) {
        self.counters.remove(key);
    }

    pub fn reset_all(&mut self) {
        self.counters.clear();
    }
}

#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    failure_threshold: u32,
    success_threshold: u32,
    timeout_ms: u64,
    state: CircuitBreakerState,
    failure_count: u32,
    success_count: u32,
    last_failure_time: Option<Timestamp>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitBreakerState {
    Closed,
    Open,
    HalfOpen,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, success_threshold: u32, timeout_ms: u64) -> Self {
        Self {
            failure_threshold,
            success_threshold,
            timeout_ms,
            state: CircuitBreakerState::Closed,
            failure_count: 0,
            success_count: 0,
            last_failure_time: None,
        }
    }

    pub fn call<F, T, E>(&mut self, f: F) -> Result<T, E>
    where
        F: FnOnce() -> Result<T, E>,
    {
        if self.state == CircuitBreakerState::Open {
            if let Some(last_failure) = self.last_failure_time {
                let elapsed = Timestamp::now().as_millis() - last_failure.as_millis();
                if elapsed >= self.timeout_ms {
                    self.state = CircuitBreakerState::HalfOpen;
                    self.success_count = 0;
                } else {
                    return Err(unsafe { std::mem::zeroed() });
                }
            }
        }

        match f() {
            Ok(result) => {
                self.on_success();
                Ok(result)
            }
            Err(error) => {
                self.on_failure();
                Err(error)
            }
        }
    }

    pub fn on_success(&mut self) {
        self.failure_count = 0;

        if self.state == CircuitBreakerState::HalfOpen {
            self.success_count += 1;
            if self.success_count >= self.success_threshold {
                self.state = CircuitBreakerState::Closed;
                self.success_count = 0;
            }
        }
    }

    pub fn on_failure(&mut self) {
        self.failure_count += 1;
        self.last_failure_time = Some(Timestamp::now());

        if self.failure_count >= self.failure_threshold {
            self.state = CircuitBreakerState::Open;
        }
    }

    pub fn is_open(&self) -> bool {
        self.state == CircuitBreakerState::Open
    }

    pub fn reset(&mut self) {
        self.state = CircuitBreakerState::Closed;
        self.failure_count = 0;
        self.success_count = 0;
        self.last_failure_time = None;
    }

    pub fn get_state(&self) -> &CircuitBreakerState {
        &self.state
    }
}

#[derive(Debug, Clone)]
pub struct Retry {
    max_attempts: u32,
    base_delay_ms: u64,
    max_delay_ms: u64,
    jitter: bool,
}

impl Retry {
    pub fn new(max_attempts: u32, base_delay_ms: u64, max_delay_ms: u64, jitter: bool) -> Self {
        Self {
            max_attempts,
            base_delay_ms,
            max_delay_ms,
            jitter,
        }
    }

    pub fn execute<F, T, E>(&self, mut f: F) -> Result<T, E>
    where
        F: FnMut() -> Result<T, E>,
    {
        let mut attempt = 0;

        loop {
            match f() {
                Ok(result) => return Ok(result),
                Err(error) => {
                    attempt += 1;
                    if attempt >= self.max_attempts {
                        return Err(error);
                    }

                    let delay = Utils::exponential_backoff(
                        attempt - 1,
                        self.base_delay_ms,
                        self.max_delay_ms,
                    );
                    let delay = if self.jitter {
                        Utils::jitter(delay, 20)
                    } else {
                        delay
                    };

                    std::thread::sleep(std::time::Duration::from_millis(delay));
                }
            }
        }
    }

    pub fn with_predicate<F, T, E, P>(&self, mut f: F, mut should_retry: P) -> Result<T, E>
    where
        F: FnMut() -> Result<T, E>,
        P: FnMut(&E) -> bool,
    {
        let mut attempt = 0;

        loop {
            match f() {
                Ok(result) => return Ok(result),
                Err(error) => {
                    if !should_retry(&error) || attempt >= self.max_attempts {
                        return Err(error);
                    }

                    attempt += 1;
                    let delay = Utils::exponential_backoff(
                        attempt - 1,
                        self.base_delay_ms,
                        self.max_delay_ms,
                    );
                    let delay = if self.jitter {
                        Utils::jitter(delay, 20)
                    } else {
                        delay
                    };

                    std::thread::sleep(std::time::Duration::from_millis(delay));
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct BloomFilter {
    bits: Vec<bool>,
    num_hash_functions: usize,
}

impl BloomFilter {
    pub fn new(size: usize, num_hash_functions: usize) -> Self {
        Self {
            bits: vec![false; size],
            num_hash_functions,
        }
    }

    pub fn insert(&mut self, item: &[u8]) {
        for i in 0..self.num_hash_functions {
            let hash = self.hash(item, i);
            let index = hash % self.bits.len();
            self.bits[index] = true;
        }
    }

    pub fn contains(&self, item: &[u8]) -> bool {
        for i in 0..self.num_hash_functions {
            let hash = self.hash(item, i);
            let index = hash % self.bits.len();
            if !self.bits[index] {
                return false;
            }
        }
        true
    }

    fn hash(&self, item: &[u8], seed: usize) -> usize {
        let mut hash = seed;
        for &byte in item {
            hash = hash.wrapping_mul(31).wrapping_add(byte as usize);
        }
        hash
    }

    pub fn clear(&mut self) {
        self.bits.fill(false);
    }

    pub fn estimated_count(&self) -> usize {
        let set_bits = self.bits.iter().filter(|&&b| b).count();
        let m = self.bits.len() as f64;
        let k = self.num_hash_functions as f64;
        let x = set_bits as f64;

        if x == 0.0 {
            return 0;
        }

        let estimate = -(m / k) * (1.0 - x / m).ln();
        estimate.round() as usize
    }
}

impl Default for ConfigManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}
