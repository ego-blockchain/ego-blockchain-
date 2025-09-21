use crate::error::{PoCError, PoCResult};
use crate::types::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct H3CoverageMap {
    pub resolution: u8,
    pub covered_hexes: HashSet<String>,
    pub hex_quality: HashMap<String, f64>,
    pub neighbor_cache: HashMap<String, Vec<String>>,
}

impl H3CoverageMap {
    pub fn new(resolution: u8) -> Self {
        Self {
            resolution,
            covered_hexes: HashSet::new(),
            hex_quality: HashMap::new(),
            neighbor_cache: HashMap::new(),
        }
    }

    pub fn add_coverage(&mut self, h3_index: String, quality: f64) {
        self.covered_hexes.insert(h3_index.clone());
        self.hex_quality.insert(h3_index, quality);
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
}

pub fn validate_h3_index(h3_index: &str, expected_resolution: Option<u8>) -> PoCResult<()> {
    if h3_index.is_empty() {
        return Err(PoCError::H3Error("Empty H3 index".to_string()));
    }

    if h3_index.len() < 8 || h3_index.len() > 15 {
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
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_h3_coverage_map() {
        let mut coverage_map = H3CoverageMap::new(7);
        coverage_map.add_coverage("87283472bffffff".to_string(), 0.8);

        assert_eq!(coverage_map.covered_hexes.len(), 1);
        assert_eq!(coverage_map.average_quality(), 0.8);
        assert_eq!(coverage_map.coverage_percentage(10), 10.0);
    }

    #[test]
    fn test_h3_validation() {
        assert!(validate_h3_index("87283472bffffff", Some(7)).is_ok());
        assert!(validate_h3_index("", None).is_err());
        assert!(validate_h3_index("invalid", None).is_err());
    }

    #[test]
    fn test_h3_resolution_estimation() {
        assert_eq!(estimate_h3_resolution("87283472bffffff"), 7);
        assert_eq!(estimate_h3_resolution("872834"), 0);
    }
}
