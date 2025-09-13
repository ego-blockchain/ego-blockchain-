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

    pub fn set(&mut self, key: String, value: ConfigValue) {
        self.params.insert(key, value);
        self.last_updated = Timestamp::now();
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

        Some(MetricStats {
            count: count as u64,
            mean,
            median,
            min,
            max,
            std_dev,
            sum,
            last_value: samples.last().unwrap().value,
            last_updated: samples.last().unwrap().timestamp,
        })
    }

    pub fn get_metric_names(&self) -> Vec<&String> {
        self.metrics.keys().collect()
    }

    pub fn uptime_ms(&self) -> u64 {
        Timestamp::now().as_millis() - self.start_time.as_millis()
    }

    pub fn clear(&mut self) {
        self.metrics.clear();
    }

    pub fn clear_metric(&mut self, metric_name: &str) {
        self.metrics.remove(metric_name);
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
    pub last_value: f64,
    pub last_updated: Timestamp,
}

impl Default for ConfigManager {
    fn default() -> Self {
        Self::new()
    }
}
