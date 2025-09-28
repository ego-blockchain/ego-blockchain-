use crate::error::{PoCError, PoCResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct H3CoverageMap {
    pub resolution: u8,
    pub covered_hexes: HashSet<String>,
    pub hex_quality: HashMap<String, f64>,
    pub neighbor_cache: HashMap<String, Vec<String>>,
    pub density_map: HashMap<String, u32>,
}

impl H3CoverageMap {
    pub fn new(resolution: u8) -> Self {
        Self {
            resolution,
            covered_hexes: HashSet::new(),
            hex_quality: HashMap::new(),
            neighbor_cache: HashMap::new(),
            density_map: HashMap::new(),
        }
    }

    pub fn add_coverage(&mut self, h3_index: String, quality: f64) {
        self.covered_hexes.insert(h3_index.clone());
        self.hex_quality.insert(h3_index.clone(), quality);

        let count = self.density_map.entry(h3_index).or_insert(0);
        *count += 1;
    }

    pub fn get_neighbors(&mut self, h3_index: &str) -> PoCResult<Vec<String>> {
        if let Some(neighbors) = self.neighbor_cache.get(h3_index) {
            return Ok(neighbors.clone());
        }

        let neighbors = self.calculate_neighbors(h3_index)?;
        self.neighbor_cache
            .insert(h3_index.to_string(), neighbors.clone());
        Ok(neighbors)
    }

    pub fn detect_clustering(&self, h3_index: &str, threshold: u32) -> bool {
        self.density_map.get(h3_index).unwrap_or(&0) > &threshold
    }

    pub fn calculate_density_penalty(&self, h3_index: &str) -> f64 {
        let density = self.density_map.get(h3_index).unwrap_or(&0);

        match *density {
            0..=2 => 1.0,
            3..=5 => 0.8,
            6..=10 => 0.6,
            11..=20 => 0.4,
            _ => 0.2,
        }
    }

    fn calculate_neighbors(&self, h3_index: &str) -> PoCResult<Vec<String>> {
        let mut neighbors = Vec::new();

        for i in 0..6 {
            let mut neighbor = h3_index.to_string();
            if let Some(last_char) = neighbor.pop() {
                let new_char = match last_char {
                    '0'..='9' => char::from(b'0' + ((last_char as u8 - b'0' + i) % 10)),
                    'a'..='f' => char::from(b'a' + ((last_char as u8 - b'a' + i) % 6)),
                    _ => last_char,
                };
                neighbor.push(new_char);
                neighbors.push(neighbor);
            }
        }

        Ok(neighbors)
    }

    pub fn coverage_percentage(&self, total_hexes: usize) -> f64 {
        if total_hexes == 0 {
            return 0.0;
        }
        (self.covered_hexes.len() as f64 / total_hexes as f64) * 100.0
    }

    pub fn average_quality(&self) -> f64 {
        if self.hex_quality.is_empty() {
            return 0.0;
        }

        let sum: f64 = self.hex_quality.values().sum();
        sum / self.hex_quality.len() as f64
    }

    pub fn get_adjusted_quality(&self, h3_index: &str) -> f64 {
        let base_quality = self.hex_quality.get(h3_index).unwrap_or(&0.0);
        let density_penalty = self.calculate_density_penalty(h3_index);
        base_quality * density_penalty
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_h3_coverage_map() {
        let mut coverage_map = H3CoverageMap::new(9);
        coverage_map.add_coverage("872834720ffffff".to_string(), 0.8);

        assert_eq!(coverage_map.covered_hexes.len(), 1);
        assert_eq!(coverage_map.average_quality(), 0.8);
        assert_eq!(coverage_map.coverage_percentage(10), 10.0);
    }

    #[test]
    fn test_h3_validation() {
        assert!(validate_h3_index("872834720ffffff", Some(9)).is_ok());
        assert!(validate_h3_index("", None).is_err());
        assert!(validate_h3_index("invalid", None).is_err());
    }

    #[test]
    fn test_h3_resolution_estimation() {
        assert_eq!(estimate_h3_resolution("872834720ffffff"), 9);
        assert_eq!(estimate_h3_resolution("872834"), 0);
    }

    #[test]
    fn test_clustering_detection() {
        let mut coverage_map = H3CoverageMap::new(9);
        let h3_index = "872834720ffffff";

        for _ in 0..5 {
            coverage_map.add_coverage(h3_index.to_string(), 0.8);
        }

        assert!(coverage_map.detect_clustering(h3_index, 3));
        assert!(coverage_map.calculate_density_penalty(h3_index) < 1.0);
    }
}
