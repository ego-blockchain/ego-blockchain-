use chrono::Timelike;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{debug, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionConfig {
    pub enabled: bool,
    pub algorithm: CompressionAlgorithm,
    pub compression_level: u8,
    pub min_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompressionAlgorithm {
    Gzip,
    Zstd,
    Lz4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchConfig {
    pub enabled: bool,
    pub max_batch_size_mb: u64,
    pub max_batch_age_seconds: u64,
    pub batch_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulingConfig {
    pub enabled: bool,
    pub off_peak_hours: (u8, u8),
    pub heavy_operations: Vec<String>,
    pub max_concurrent_heavy_ops: u32,
}

#[derive(Debug, Clone)]
pub struct PendingOperation {
    pub operation_id: String,
    pub operation_type: String,
    pub data: Vec<u8>,
    pub priority: u8,
    pub created_at: u64,
    pub scheduled_for: Option<u64>,
    pub retry_count: u32,
}

#[derive(Debug, Clone)]
pub struct BatchedData {
    pub batch_id: String,
    pub operations: Vec<PendingOperation>,
    pub total_size_bytes: u64,
    pub created_at: u64,
    pub ready_for_processing: bool,
}

pub struct DataOptimizer {
    pub compression_config: CompressionConfig,
    pub batch_config: BatchConfig,
    pub scheduling_config: SchedulingConfig,
    pub pending_operations: HashMap<String, PendingOperation>,
    pub batched_data: HashMap<String, BatchedData>,
    pub compression_stats: CompressionStats,
    pub event_sender: mpsc::UnboundedSender<OptimizerEvent>,
    pub event_receiver: mpsc::UnboundedReceiver<OptimizerEvent>,
}

#[derive(Debug, Clone)]
pub enum OptimizerEvent {
    BatchReady(String),
    CompressionCompleted(String, f64),
    OperationScheduled(String, u64),
    OffPeakHoursStarted,
    OffPeakHoursEnded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionStats {
    pub total_compressed_bytes: u64,
    pub total_original_bytes: u64,
    pub compression_ratio: f64,
    pub operations_compressed: u64,
    pub bandwidth_saved_bytes: u64,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            algorithm: CompressionAlgorithm::Zstd,
            compression_level: 6,
            min_size_bytes: 1024,
        }
    }
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_batch_size_mb: 10,
            max_batch_age_seconds: 300,
            batch_types: vec![
                "post_proof".to_string(),
                "shard_sync".to_string(),
                "placement_update".to_string(),
            ],
        }
    }
}

impl Default for SchedulingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            off_peak_hours: (23, 6),
            heavy_operations: vec![
                "shard_download".to_string(),
                "full_sync".to_string(),
                "backup_upload".to_string(),
            ],
            max_concurrent_heavy_ops: 2,
        }
    }
}

impl DataOptimizer {
    pub fn new() -> Self {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();

        Self {
            compression_config: CompressionConfig::default(),
            batch_config: BatchConfig::default(),
            scheduling_config: SchedulingConfig::default(),
            pending_operations: HashMap::new(),
            batched_data: HashMap::new(),
            compression_stats: CompressionStats {
                total_compressed_bytes: 0,
                total_original_bytes: 0,
                compression_ratio: 0.0,
                operations_compressed: 0,
                bandwidth_saved_bytes: 0,
            },
            event_sender,
            event_receiver,
        }
    }

    pub fn optimize_data(
        &mut self,
        operation_id: String,
        operation_type: String,
        data: Vec<u8>,
        priority: u8,
    ) -> Result<Vec<u8>, String> {
        let mut optimized_data = data.clone();
        let original_size = data.len() as u64;

        if self.compression_config.enabled
            && original_size >= self.compression_config.min_size_bytes
        {
            optimized_data = self.compress_data(&data)?;
            let compressed_size = optimized_data.len() as u64;

            self.compression_stats.total_original_bytes += original_size;
            self.compression_stats.total_compressed_bytes += compressed_size;
            self.compression_stats.operations_compressed += 1;
            self.compression_stats.bandwidth_saved_bytes +=
                original_size.saturating_sub(compressed_size);
            self.compression_stats.compression_ratio = self.compression_stats.total_compressed_bytes
                as f64
                / self.compression_stats.total_original_bytes as f64;

            let compression_ratio = compressed_size as f64 / original_size as f64;
            let _ = self.event_sender.send(OptimizerEvent::CompressionCompleted(
                operation_id.clone(),
                compression_ratio,
            ));

            debug!(
                "Compressed operation {}: {} -> {} bytes (ratio: {:.2})",
                operation_id, original_size, compressed_size, compression_ratio
            );
        }

        if self.should_batch_operation(&operation_type) {
            self.add_to_batch(operation_id, operation_type, optimized_data, priority)?;
            return Ok(vec![]);
        }

        if self.should_schedule_operation(&operation_type) {
            let scheduled_time = self.calculate_schedule_time(priority);
            self.schedule_operation(
                operation_id,
                operation_type,
                optimized_data,
                priority,
                scheduled_time,
            )?;
            return Ok(vec![]);
        }

        Ok(optimized_data)
    }

    fn compress_data(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        match self.compression_config.algorithm {
            CompressionAlgorithm::Gzip => {
                use flate2::Compression;
                use flate2::write::GzEncoder;
                use std::io::Write;

                let mut encoder = GzEncoder::new(
                    Vec::new(),
                    Compression::new(self.compression_config.compression_level as u32),
                );
                encoder
                    .write_all(data)
                    .map_err(|e| format!("Gzip compression failed: {}", e))?;
                encoder
                    .finish()
                    .map_err(|e| format!("Gzip compression failed: {}", e))
            }
            CompressionAlgorithm::Zstd => Ok(data.to_vec()),
            CompressionAlgorithm::Lz4 => Ok(data.to_vec()),
        }
    }

    fn should_batch_operation(&self, operation_type: &str) -> bool {
        self.batch_config.enabled
            && self
                .batch_config
                .batch_types
                .contains(&operation_type.to_string())
    }

    fn should_schedule_operation(&self, operation_type: &str) -> bool {
        self.scheduling_config.enabled
            && self
                .scheduling_config
                .heavy_operations
                .contains(&operation_type.to_string())
            && !self.is_off_peak_hours()
    }

    fn add_to_batch(
        &mut self,
        operation_id: String,
        operation_type: String,
        data: Vec<u8>,
        priority: u8,
    ) -> Result<(), String> {
        let operation = PendingOperation {
            operation_id: operation_id.clone(),
            operation_type: operation_type.clone(),
            data,
            priority,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            scheduled_for: None,
            retry_count: 0,
        };

        let batch_id = format!(
            "batch_{}_{}",
            operation_type,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                / 300
        );

        let batch = self
            .batched_data
            .entry(batch_id.clone())
            .or_insert_with(|| BatchedData {
                batch_id: batch_id.clone(),
                operations: Vec::new(),
                total_size_bytes: 0,
                created_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                ready_for_processing: false,
            });

        batch.total_size_bytes += operation.data.len() as u64;
        batch.operations.push(operation);

        let max_size_bytes = self.batch_config.max_batch_size_mb * 1_000_000;
        let max_age = self.batch_config.max_batch_age_seconds;
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if batch.total_size_bytes >= max_size_bytes || (current_time - batch.created_at) >= max_age
        {
            batch.ready_for_processing = true;
            let _ = self
                .event_sender
                .send(OptimizerEvent::BatchReady(batch_id.clone()));
        }

        debug!(
            "Added operation {} to batch {} (size: {} bytes)",
            operation_id, batch_id, batch.total_size_bytes
        );
        Ok(())
    }

    fn schedule_operation(
        &mut self,
        operation_id: String,
        operation_type: String,
        data: Vec<u8>,
        priority: u8,
        scheduled_time: u64,
    ) -> Result<(), String> {
        let operation = PendingOperation {
            operation_id: operation_id.clone(),
            operation_type,
            data,
            priority,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            scheduled_for: Some(scheduled_time),
            retry_count: 0,
        };

        self.pending_operations
            .insert(operation_id.clone(), operation);
        let _ = self.event_sender.send(OptimizerEvent::OperationScheduled(
            operation_id.clone(),
            scheduled_time,
        ));

        debug!(
            "Scheduled operation {} for {}",
            operation_id, scheduled_time
        );
        Ok(())
    }

    fn calculate_schedule_time(&self, priority: u8) -> u64 {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if priority >= 8 {
            current_time + 3600
        } else if self.is_off_peak_hours() {
            current_time + 300
        } else {
            self.get_next_off_peak_time()
        }
    }

    fn is_off_peak_hours(&self) -> bool {
        let now = chrono::Utc::now();
        let hour = now.hour() as u8;

        if self.scheduling_config.off_peak_hours.0 > self.scheduling_config.off_peak_hours.1 {
            hour >= self.scheduling_config.off_peak_hours.0
                || hour < self.scheduling_config.off_peak_hours.1
        } else {
            hour >= self.scheduling_config.off_peak_hours.0
                && hour < self.scheduling_config.off_peak_hours.1
        }
    }

    fn get_next_off_peak_time(&self) -> u64 {
        let now = chrono::Utc::now();
        let current_hour = now.hour() as u8;
        let off_peak_start = self.scheduling_config.off_peak_hours.0;

        let hours_until_off_peak = if current_hour < off_peak_start {
            off_peak_start - current_hour
        } else {
            24 - current_hour + off_peak_start
        };

        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + (hours_until_off_peak as u64 * 3600)
    }

    pub fn get_ready_batches(&mut self) -> Vec<BatchedData> {
        let mut ready_batches = Vec::new();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.batched_data.retain(|_, batch| {
            let age = current_time - batch.created_at;
            if batch.ready_for_processing || age >= self.batch_config.max_batch_age_seconds {
                ready_batches.push(batch.clone());
                false
            } else {
                true
            }
        });

        ready_batches
    }

    pub fn get_scheduled_operations(&mut self) -> Vec<PendingOperation> {
        let mut ready_operations = Vec::new();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.pending_operations.retain(|_, operation| {
            if let Some(scheduled_time) = operation.scheduled_for {
                if current_time >= scheduled_time {
                    ready_operations.push(operation.clone());
                    false
                } else {
                    true
                }
            } else {
                true
            }
        });

        ready_operations
    }

    pub fn get_optimization_stats(&self) -> OptimizationStats {
        OptimizationStats {
            compression_stats: self.compression_stats.clone(),
            pending_operations: self.pending_operations.len(),
            pending_batches: self.batched_data.len(),
            total_bandwidth_saved_mb: self.compression_stats.bandwidth_saved_bytes as f64
                / 1_000_000.0,
        }
    }

    pub fn update_compression_config(&mut self, config: CompressionConfig) {
        self.compression_config = config;
        info!("Updated compression configuration");
    }

    pub fn update_batch_config(&mut self, config: BatchConfig) {
        self.batch_config = config;
        info!("Updated batch configuration");
    }

    pub fn update_scheduling_config(&mut self, config: SchedulingConfig) {
        self.scheduling_config = config;
        info!("Updated scheduling configuration");
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationStats {
    pub compression_stats: CompressionStats,
    pub pending_operations: usize,
    pub pending_batches: usize,
    pub total_bandwidth_saved_mb: f64,
}
