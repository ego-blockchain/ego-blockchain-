use crate::{Address, EgoResult, Hash, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DRSManager {
    pub current_epoch: u64,
    pub node_scores: HashMap<Address, DRSScore>,
    pub epoch_stats: HashMap<u64, EpochStats>,
    pub config: DRSConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DRSConfig {
    pub uptime_weight: f64,
    pub proof_success_weight: f64,
    pub witness_quality_weight: f64,
    pub coverage_value_weight: f64,
    pub utility_weight: f64,
    pub density_penalty_rate: f64,
    pub density_min_multiplier: f64,
    pub score_bounds: (f64, f64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DRSScore {
    pub node_id: Address,
    pub epoch: u64,
    pub total_score: f64,
    pub components: DRSComponents,
    pub multipliers: DRSMultipliers,
    pub last_updated: Timestamp,
    pub evidence_hash: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DRSComponents {
    pub uptime_score: f64,
    pub proof_success_rate: f64,
    pub witness_quality: f64,
    pub coverage_value: f64,
    pub utility_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DRSMultipliers {
    pub location_density_multiplier: f64,
    pub scarcity_offset: f64,
    pub bounded_multiplier: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochStats {
    pub epoch: u64,
    pub total_nodes: u32,
    pub avg_score: f64,
    pub score_distribution: Vec<(f64, u32)>,
    pub top_performers: Vec<Address>,
    pub penalized_nodes: Vec<(Address, String)>,
    pub density_events: Vec<DensityEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DensityEvent {
    pub node_id: Address,
    pub h3_cell: String,
    pub device_count: u32,
    pub density_multiplier: f64,
    pub evidence_root: Hash,
    pub epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct NodeMetrics {
    pub node_id: Address,
    pub epoch: u64,
    pub uptime_ms: u64,
    pub total_epoch_ms: u64,
    pub proofs_submitted: u32,
    pub proofs_successful: u32,
    pub witnesses_provided: u32,
    pub witness_accuracy: f64,
    pub coverage_areas: Vec<String>,
    pub proposer_blocks: u32,
    pub validator_participation: f64,
    pub location: Option<GeospatialData>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct GeospatialData {
    pub h3_cell: String,
    pub lat: f64,
    pub lon: f64,
    pub altitude: Option<f64>,
    pub witness_count: u32,
    pub dwell_time_pct: f64,
}

impl Default for DRSConfig {
    fn default() -> Self {
        Self {
            uptime_weight: 0.25,
            proof_success_weight: 0.25,
            witness_quality_weight: 0.20,
            coverage_value_weight: 0.20,
            utility_weight: 0.10,
            density_penalty_rate: 0.10,
            density_min_multiplier: 0.40,
            score_bounds: (0.0, 100.0),
        }
    }
}

impl DRSManager {
    pub fn new(config: DRSConfig) -> Self {
        Self {
            current_epoch: 0,
            node_scores: HashMap::new(),
            epoch_stats: HashMap::new(),
            config,
        }
    }

    pub fn calculate_drs_score(
        &mut self,
        _metrics: &NodeMetrics,
        density_data: Option<DensityData>,
    ) -> EgoResult<DRSScore> {
        let components = self.calculate_components(_metrics)?;
        let multipliers = self.calculate_multipliers(_metrics, density_data)?;

        let total_score = self.calculate_weighted_score(&components);

        let final_score = self.apply_multipliers(total_score, &multipliers);

        let bounded_score = self.bound_score(final_score);

        let score = DRSScore {
            node_id: _metrics.node_id,
            epoch: _metrics.epoch,
            total_score: bounded_score,
            components,
            multipliers,
            last_updated: Timestamp::now(),
            evidence_hash: self.compute_evidence_hash(_metrics),
        };

        self.node_scores.insert(_metrics.node_id, score.clone());

        Ok(score)
    }

    fn calculate_components(&self, metrics: &NodeMetrics) -> EgoResult<DRSComponents> {
        let uptime_score = if metrics.total_epoch_ms > 0 {
            (metrics.uptime_ms as f64 / metrics.total_epoch_ms as f64) * 100.0
        } else {
            0.0
        };

        let proof_success_rate = if metrics.proofs_submitted > 0 {
            (metrics.proofs_successful as f64 / metrics.proofs_submitted as f64) * 100.0
        } else {
            100.0
        };

        let witness_quality = if metrics.witnesses_provided > 0 {
            metrics.witness_accuracy * 100.0
        } else {
            0.0
        };

        let coverage_value = self.calculate_coverage_value(&metrics.coverage_areas);

        let utility_score = self.calculate_utility_score(metrics);

        Ok(DRSComponents {
            uptime_score,
            proof_success_rate,
            witness_quality,
            coverage_value,
            utility_score,
        })
    }

    fn calculate_multipliers(
        &self,
        _metrics: &NodeMetrics,
        density_data: Option<DensityData>,
    ) -> EgoResult<DRSMultipliers> {
        let location_density_multiplier = if let Some(density) = density_data {
            self.calculate_location_density_multiplier(density.device_count)
        } else {
            1.0
        };

        let scarcity_offset = 0.0;

        let bounded_multiplier =
            (location_density_multiplier + scarcity_offset).max(self.config.density_min_multiplier);

        Ok(DRSMultipliers {
            location_density_multiplier,
            scarcity_offset,
            bounded_multiplier,
        })
    }

    fn calculate_location_density_multiplier(&self, device_count: u32) -> f64 {
        if device_count <= 1 {
            1.0
        } else {
            let penalty = self.config.density_penalty_rate * (device_count - 1) as f64;
            (1.0 - penalty).max(self.config.density_min_multiplier)
        }
    }

    fn calculate_coverage_value(&self, coverage_areas: &[String]) -> f64 {
        let unique_areas = coverage_areas.len() as f64;
        (unique_areas * 10.0).min(100.0)
    }

    fn calculate_utility_score(&self, metrics: &NodeMetrics) -> f64 {
        let proposer_score = (metrics.proposer_blocks as f64 * 5.0).min(50.0);
        let validator_score = metrics.validator_participation * 50.0;

        (proposer_score + validator_score).min(100.0)
    }

    fn calculate_weighted_score(&self, components: &DRSComponents) -> f64 {
        self.config.uptime_weight * components.uptime_score
            + self.config.proof_success_weight * components.proof_success_rate
            + self.config.witness_quality_weight * components.witness_quality
            + self.config.coverage_value_weight * components.coverage_value
            + self.config.utility_weight * components.utility_score
    }

    fn apply_multipliers(&self, score: f64, multipliers: &DRSMultipliers) -> f64 {
        score * multipliers.bounded_multiplier
    }

    fn bound_score(&self, score: f64) -> f64 {
        score
            .max(self.config.score_bounds.0)
            .min(self.config.score_bounds.1)
    }

    fn compute_evidence_hash(&self, metrics: &NodeMetrics) -> Hash {
        let config = bincode::config::standard();
        let evidence_bytes = bincode::encode_to_vec(metrics, config).unwrap_or_default();
        crate::crypto::hash_data(&evidence_bytes)
    }

    pub fn get_node_score(&self, node_id: &Address) -> Option<&DRSScore> {
        self.node_scores.get(node_id)
    }

    pub fn get_epoch_stats(&self, epoch: u64) -> Option<&EpochStats> {
        self.epoch_stats.get(&epoch)
    }

    pub fn finalize_epoch(&mut self, epoch: u64) -> EgoResult<EpochStats> {
        let scores: Vec<&DRSScore> = self
            .node_scores
            .values()
            .filter(|score| score.epoch == epoch)
            .collect();

        let total_nodes = scores.len() as u32;
        let avg_score = if !scores.is_empty() {
            scores.iter().map(|s| s.total_score).sum::<f64>() / total_nodes as f64
        } else {
            0.0
        };

        let mut distribution = vec![(0.0, 0u32); 10];
        for score in &scores {
            let bucket = (score.total_score / 10.0).floor() as usize;
            let bucket = bucket.min(9);
            distribution[bucket].1 += 1;
        }

        let mut sorted_scores = scores.clone();
        sorted_scores.sort_by(|a, b| b.total_score.partial_cmp(&a.total_score).unwrap());
        let top_count = (total_nodes as f64 * 0.1).max(1.0) as usize;
        let top_performers = sorted_scores
            .iter()
            .take(top_count)
            .map(|s| s.node_id)
            .collect();

        let penalized_nodes = scores
            .iter()
            .filter(|s| s.multipliers.location_density_multiplier < 1.0)
            .map(|s| (s.node_id, "Location density penalty".to_string()))
            .collect();

        let density_events = self.generate_density_events(epoch, &scores);

        let stats = EpochStats {
            epoch,
            total_nodes,
            avg_score,
            score_distribution: distribution,
            top_performers,
            penalized_nodes,
            density_events,
        };

        self.epoch_stats.insert(epoch, stats.clone());
        self.current_epoch = epoch + 1;

        Ok(stats)
    }

    fn generate_density_events(&self, epoch: u64, scores: &[&DRSScore]) -> Vec<DensityEvent> {
        let mut events = Vec::new();

        for score in scores {
            if score.multipliers.location_density_multiplier < 1.0 {
                let penalty = 1.0 - score.multipliers.location_density_multiplier;
                let device_count = ((penalty / self.config.density_penalty_rate) + 1.0) as u32;

                events.push(DensityEvent {
                    node_id: score.node_id,
                    h3_cell: "simulated_cell".to_string(),
                    device_count,
                    density_multiplier: score.multipliers.location_density_multiplier,
                    evidence_root: score.evidence_hash,
                    epoch,
                });
            }
        }

        events
    }

    pub fn apply_reward_multiplier(&self, base_reward: u128, node_id: &Address) -> u128 {
        if let Some(score) = self.get_node_score(node_id) {
            let multiplier = score.multipliers.bounded_multiplier;
            ((base_reward as f64) * multiplier) as u128
        } else {
            base_reward
        }
    }

    pub fn qualifies_for_quota(&self, node_id: &Address, min_score: f64) -> bool {
        if let Some(score) = self.get_node_score(node_id) {
            score.total_score >= min_score
        } else {
            false
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DensityData {
    pub h3_cell: String,
    pub device_count: u32,
    pub dwell_time_pct: f64,
    pub witnesses: Vec<Address>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DRSScoreEvent {
    pub node_id: Address,
    pub epoch: u64,
    pub score: u64,
    pub evidence_hash: Hash,
    pub timestamp: Timestamp,
}

impl DRSScoreEvent {
    pub fn from_drs_score(score: &DRSScore) -> Self {
        Self {
            node_id: score.node_id,
            epoch: score.epoch,
            score: (score.total_score * 1000.0) as u64,
            evidence_hash: score.evidence_hash,
            timestamp: score.last_updated,
        }
    }

    pub fn get_score_f64(&self) -> f64 {
        self.score as f64 / 1000.0
    }
}
