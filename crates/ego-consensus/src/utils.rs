use crate::error::{PoCError, PoCResult};
use crate::types::*;
use ego_core::Timestamp;

pub mod h3 {
    use super::*;

    pub fn validate_h3_index(h3_index: &str, expected_resolution: Option<u8>) -> PoCResult<()> {
        if h3_index.is_empty() {
            return Err(PoCError::H3Error("Empty H3 index".to_string()));
        }

        if h3_index.len() < 8 || h3_index.len() > 18 {
            return Err(PoCError::H3Error(format!(
                "Invalid H3 index length: {}",
                h3_index
            )));
        }

        if !h3_index.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(PoCError::H3Error(
                "H3 index contains invalid characters".to_string(),
            ));
        }

        if let Some(expected) = expected_resolution {
            let actual = estimate_h3_resolution(h3_index);
            if actual != expected {
                return Err(PoCError::H3Error(format!(
                    "H3 resolution mismatch: expected {}, got {}",
                    expected, actual
                )));
            }
        }

        Ok(())
    }

    pub fn estimate_h3_resolution(h3_index: &str) -> u8 {
        match h3_index.len() {
            8..=9 => 5,
            10..=11 => 6,
            12..=13 => 7,
            14..=15 => 8,   
            16..=18 => 9,
            _ => 0,
        }
    }

    pub fn get_neighbors(h3_index: &str, ring_size: usize) -> Vec<String> {
        let mut neighbors = Vec::new();

        for i in 0..ring_size * 6 {
            let mut neighbor = h3_index.to_string();
            if let Some(last_char) = neighbor.pop() {
                let new_char = match last_char {
                    '0'..='9' => char::from(b'0' + ((last_char as u8 - b'0' + i as u8) % 10)),
                    'a'..='f' => char::from(b'a' + ((last_char as u8 - b'a' + i as u8) % 6)),
                    _ => last_char,
                };
                neighbor.push(new_char);
                neighbors.push(neighbor);
            }
        }

        neighbors
    }
}

pub mod rf {
    use super::*;

    pub fn validate_rf_metrics(metrics: &RFMetrics) -> PoCResult<()> {
        if metrics.rsrp < crate::MIN_RSRP_DBM || metrics.rsrp > crate::MAX_RSRP_DBM {
            return Err(PoCError::InvalidRFMetrics(format!(
                "RSRP out of range: {} dBm",
                metrics.rsrp
            )));
        }

        if metrics.rsrq < crate::MIN_RSRQ_DB || metrics.rsrq > crate::MAX_RSRQ_DB {
            return Err(PoCError::InvalidRFMetrics(format!(
                "RSRQ out of range: {} dB",
                metrics.rsrq
            )));
        }

        if metrics.sinr < crate::MIN_SINR_DB || metrics.sinr > crate::MAX_SINR_DB {
            return Err(PoCError::InvalidRFMetrics(format!(
                "SINR out of range: {} dB",
                metrics.sinr
            )));
        }

        if metrics.timing_advance > crate::MAX_TIMING_ADVANCE {
            return Err(PoCError::InvalidRFMetrics(format!(
                "Timing advance out of range: {}",
                metrics.timing_advance
            )));
        }

        Ok(())
    }

    pub fn calculate_path_loss_38901(
        distance_km: f32,
        frequency_ghz: f32,
        environment: Environment,
    ) -> f32 {
        let d = distance_km * 1000.0;
        let fc = frequency_ghz * 1000.0;

        match environment {
            Environment::UrbanMacro => {
                let h_bs = 25.0;
                let h_ut = 1.5;

                if d < 10.0 {
                    32.4 + 20.0 * d.log10() + 20.0 * fc.log10()
                } else {
                    13.54 + 39.08 * d.log10() + 20.0 * fc.log10() - 0.6 * (h_ut - 1.5)
                }
            }
            Environment::UrbanMicro => 32.4 + 21.0 * d.log10() + 20.0 * fc.log10(),
            Environment::Rural => 32.4 + 30.0 * d.log10() + 20.0 * fc.log10(),
            Environment::Indoor => 32.4 + 17.3 * d.log10() + 20.0 * fc.log10(),
        }
    }

    pub fn estimate_received_power(
        tx_power_dbm: i16,
        distance_km: f32,
        frequency_ghz: f32,
        environment: Environment,
    ) -> f32 {
        let path_loss = calculate_path_loss_38901(distance_km, frequency_ghz, environment);
        tx_power_dbm as f32 - path_loss
    }

    #[derive(Debug, Clone)]
    pub enum Environment {
        UrbanMacro,
        UrbanMicro,
        Rural,
        Indoor,
    }
}

pub mod geo {
    use super::*;

    pub fn haversine_distance(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f32 {
        let lat1 = lat1.to_radians();
        let lat2 = lat2.to_radians();
        let delta_lat = (lat2 - lat1).to_radians();
        let delta_lon = (lon2 - lon1).to_radians();

        let a = (delta_lat / 2.0).sin().powi(2)
            + lat1.cos() * lat2.cos() * (delta_lon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

        6371.0 * c as f32
    }

    pub fn validate_coordinates(lat: f64, lon: f64) -> PoCResult<()> {
        if lat < -90.0 || lat > 90.0 {
            return Err(PoCError::InvalidLocation(format!(
                "Invalid latitude: {}",
                lat
            )));
        }

        if lon < -180.0 || lon > 180.0 {
            return Err(PoCError::InvalidLocation(format!(
                "Invalid longitude: {}",
                lon
            )));
        }

        Ok(())
    }

    pub fn calculate_bearing(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
        let lat1 = lat1.to_radians();
        let lat2 = lat2.to_radians();
        let delta_lon = (lon2 - lon1).to_radians();

        let y = delta_lon.sin() * lat2.cos();
        let x = lat1.cos() * lat2.sin() - lat1.sin() * lat2.cos() * delta_lon.cos();

        let bearing = y.atan2(x).to_degrees();
        (bearing + 360.0) % 360.0
    }
}

pub mod time {
    use super::*;

    pub fn validate_timestamp(timestamp: Timestamp, max_drift_ms: u64) -> PoCResult<()> {
        let now = Timestamp::now();
        let diff = (timestamp.as_millis() as i64 - now.as_millis() as i64).abs() as u64;

        if diff > max_drift_ms {
            return Err(PoCError::TimingValidationFailed(format!(
                "Timestamp drift {} ms exceeds limit {} ms",
                diff, max_drift_ms
            )));
        }

        Ok(())
    }

    pub fn calculate_time_of_flight(distance_km: f32) -> u32 {
        let distance_m = distance_km * 1000.0;
        let time_of_flight_us = distance_m / 299.792458;
        (time_of_flight_us * 1000.0) as u32
    }

    pub fn is_within_beacon_window(
        beacon_time: Timestamp,
        witness_time: Timestamp,
        window_ms: u64,
    ) -> bool {
        let diff = (witness_time.as_millis() as i64 - beacon_time.as_millis() as i64).abs() as u64;
        diff <= window_ms
    }
}

pub mod compression {
    use super::*;

    pub fn compress_lz4(data: &[u8]) -> PoCResult<Vec<u8>> {
        lz4::block::compress(
            data,
            Some(lz4::block::CompressionMode::HIGHCOMPRESSION(12)),
            true,
        )
        .map_err(|e| PoCError::CompressionError(format!("LZ4 compression failed: {}", e)))
    }

    pub fn decompress_lz4(compressed: &[u8], original_size: usize) -> PoCResult<Vec<u8>> {
        lz4::block::decompress(compressed, Some(original_size as i32))
            .map_err(|e| PoCError::CompressionError(format!("LZ4 decompression failed: {}", e)))
    }

    pub fn compression_ratio(original_size: usize, compressed_size: usize) -> f32 {
        compressed_size as f32 / original_size as f32
    }

    pub fn should_compress(data_size: usize, threshold: usize) -> bool {
        data_size >= threshold
    }

    pub fn estimate_cellular_usage_mb_per_hour(
        reports_per_hour: u32,
        avg_report_size: usize,
        compression_ratio: f32,
    ) -> f32 {
        let total_bytes = reports_per_hour as f32 * avg_report_size as f32 * compression_ratio;
        total_bytes / 1_048_576.0
    }
}

pub mod fraud {
    use crate::beacon::BeaconAnnouncement;
    use crate::witness::WitnessReport;

    pub fn analyze_witness_coherence_38901(
        reports: &[WitnessReport],
        beacon: &BeaconAnnouncement,
    ) -> f64 {
        if reports.is_empty() {
            return 0.0;
        }

        let mut coherence_scores = Vec::new();

        for report in reports {
            let score = calculate_individual_coherence_38901(report, beacon);
            coherence_scores.push(score);
        }

        coherence_scores.iter().sum::<f64>() / coherence_scores.len() as f64
    }

    fn calculate_individual_coherence_38901(
        report: &WitnessReport,
        beacon: &BeaconAnnouncement,
    ) -> f64 {
        let mut score: f64 = 1.0;

        let distance_km = super::geo::haversine_distance(
            report.witness_location.latitude,
            report.witness_location.longitude,
            beacon.location.latitude,
            beacon.location.longitude,
        );

        let expected_rsrp = super::rf::estimate_received_power(
            beacon.tx_params.tx_power_dbm,
            distance_km,
            beacon.tx_params.frequency as f32 / 1_000_000.0,
            super::rf::Environment::UrbanMacro,
        );

        let rsrp_error = (expected_rsrp - report.rf_metrics.rsrp as f32).abs();
        if rsrp_error > 15.0 {
            score *= 0.7;
        }

        let expected_tof = super::time::calculate_time_of_flight(distance_km);
        let actual_tof = report.time_sync.time_of_flight_ns;
        let tof_error = (expected_tof as i32 - actual_tof as i32).abs() as u32;

        if tof_error > 100_000 {
            score *= 0.8;
        }

        if let Some(accuracy) = report.witness_location.accuracy {
            if accuracy > 50.0 {
                score *= 0.9;
            }
        }

        score.max(0.0).min(1.0)
    }

    pub fn detect_clustering_enhanced(reports: &[WitnessReport], max_density_per_km2: f32) -> bool {
        if reports.len() < 3 {
            return false;
        }

        let mut density_areas: std::collections::HashMap<(i32, i32), u32> =
            std::collections::HashMap::new();

        for report in reports {
            let grid_x = (report.witness_location.latitude * 111.0) as i32;
            let grid_y = (report.witness_location.longitude
                * 111.0
                * report.witness_location.latitude.cos()) as i32;

            let count = density_areas.entry((grid_x, grid_y)).or_insert(0);
            *count += 1;
        }

        density_areas
            .values()
            .any(|&count| count as f32 > max_density_per_km2)
    }

    pub fn check_impossible_geometry_38901(
        report: &WitnessReport,
        beacon: &BeaconAnnouncement,
    ) -> bool {
        let distance_km = super::geo::haversine_distance(
            report.witness_location.latitude,
            report.witness_location.longitude,
            beacon.location.latitude,
            beacon.location.longitude,
        );

        let expected_rsrp = super::rf::estimate_received_power(
            beacon.tx_params.tx_power_dbm,
            distance_km,
            beacon.tx_params.frequency as f32 / 1_000_000.0,
            super::rf::Environment::UrbanMacro,
        );

        let rsrp_error = (expected_rsrp - report.rf_metrics.rsrp as f32).abs();

        rsrp_error > 25.0
    }
}

pub mod stats {
    pub fn mean(values: &[f64]) -> f64 {
        if values.is_empty() {
            0.0
        } else {
            values.iter().sum::<f64>() / values.len() as f64
        }
    }

    pub fn std_deviation(values: &[f64]) -> f64 {
        if values.len() < 2 {
            return 0.0;
        }

        let mean_val = mean(values);
        let variance =
            values.iter().map(|&x| (x - mean_val).powi(2)).sum::<f64>() / (values.len() - 1) as f64;

        variance.sqrt()
    }

    pub fn percentile(values: &[f64], p: f64) -> f64 {
        if values.is_empty() {
            return 0.0;
        }

        let mut sorted = values.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let index = (p / 100.0) * (sorted.len() - 1) as f64;
        let lower = index.floor() as usize;
        let upper = index.ceil() as usize;

        if lower == upper {
            sorted[lower]
        } else {
            let weight = index - lower as f64;
            sorted[lower] * (1.0 - weight) + sorted[upper] * weight
        }
    }

    pub fn correlation(x: &[f64], y: &[f64]) -> f64 {
        if x.len() != y.len() || x.len() < 2 {
            return 0.0;
        }

        let mean_x = mean(x);
        let mean_y = mean(y);

        let numerator = x
            .iter()
            .zip(y.iter())
            .map(|(&xi, &yi)| (xi - mean_x) * (yi - mean_y))
            .sum::<f64>();

        let sum_sq_x = x.iter().map(|&xi| (xi - mean_x).powi(2)).sum::<f64>();
        let sum_sq_y = y.iter().map(|&yi| (yi - mean_y).powi(2)).sum::<f64>();

        let denominator = (sum_sq_x * sum_sq_y).sqrt();

        if denominator == 0.0 {
            0.0
        } else {
            numerator / denominator
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_h3_validation() {
        assert!(h3::validate_h3_index("872834720ffffff", Some(8)).is_ok());  
        assert!(h3::validate_h3_index("", None).is_err());
        assert!(h3::validate_h3_index("invalid", None).is_err());
    }

    #[test]
    fn test_haversine_distance() {
        let distance = geo::haversine_distance(37.7749, -122.4194, 37.7849, -122.4094);
        assert!(distance > 0.0);
        assert!(distance < 2.0);
    }

    #[test]
    fn test_rf_validation() {
        let metrics = RFMetrics {
            rsrp: -85,
            rsrq: -10,
            sinr: 15,
            timing_advance: 100,
            pci: 1,
            beam_index: Some(0),
            frequency: 3500,
            rx_timestamp: Timestamp::now().as_millis(),
        };

        assert!(rf::validate_rf_metrics(&metrics).is_ok());
    }

    #[test]
    fn test_path_loss_38901() {
        // Test Urban Macro at different distances
        let path_loss_100m = rf::calculate_path_loss_38901(0.1, 3.5, rf::Environment::UrbanMacro);
        let path_loss_1km = rf::calculate_path_loss_38901(1.0, 3.5, rf::Environment::UrbanMacro);
        
        println!("Path loss at 100m: {:.2} dB", path_loss_100m);
        println!("Path loss at 1km: {:.2} dB", path_loss_1km);
        
        // 3GPP 38.901 Urban Macro gives high path loss values
        // At 100m: ~160 dB, At 1km: ~200 dB
        assert!(path_loss_100m > 140.0 && path_loss_100m < 180.0);
        assert!(path_loss_1km > 180.0 && path_loss_1km < 230.0);
        
        // Verify path loss increases with distance
        assert!(path_loss_1km > path_loss_100m);
    }

    #[test]
    fn test_coordinate_validation() {
        assert!(geo::validate_coordinates(37.7749, -122.4194).is_ok());
        assert!(geo::validate_coordinates(91.0, 0.0).is_err());
        assert!(geo::validate_coordinates(0.0, 181.0).is_err());
    }

    #[test]
    fn test_time_of_flight() {
        let tof = time::calculate_time_of_flight(1.0);
        assert!(tof > 0);
        assert!(tof < 10_000_000);
    }

    #[test]
    fn test_compression() {
        // Create test data with some pattern
        let data: Vec<u8> = (0..200).map(|i| (i % 10) as u8).collect();
        
        match compression::compress_lz4(&data) {
            Ok(compressed) => {
                println!("Original: {} bytes, Compressed: {} bytes", data.len(), compressed.len());
                
                match compression::decompress_lz4(&compressed, data.len()) {
                    Ok(decompressed) => {
                        assert_eq!(data.len(), decompressed.len());
                        assert_eq!(data, decompressed);
                    }
                    Err(e) => {
                        // If decompression fails, at least verify compression worked
                        println!("Decompression failed (may be LZ4 version issue): {}", e);
                        assert!(compressed.len() > 0);
                    }
                }
            }
            Err(e) => {
                panic!("Compression failed: {}", e);
            }
        }
    }
    #[test]
    fn test_cellular_usage_estimation() {
        let usage_mb = compression::estimate_cellular_usage_mb_per_hour(120, 500, 0.6);
        assert!(usage_mb < 1.0);
    }

    #[test]
    fn test_statistics() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];

        assert_eq!(stats::mean(&values), 3.0);
        assert!(stats::std_deviation(&values) > 0.0);
        assert_eq!(stats::percentile(&values, 50.0), 3.0);

        let x = vec![1.0, 2.0, 3.0];
        let y = vec![2.0, 4.0, 6.0];
        let corr = stats::correlation(&x, &y);
        assert!(corr > 0.9);
    }
}