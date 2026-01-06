use crate::{Account, Address, Balance, EgoError, EgoResult, Hash, Timestamp};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

pub const DEFAULT_WEIGHTS_VERSION: u32 = 1;
pub const MAX_SCORE: f64 = 1.0;
pub const MIN_SCORE: f64 = 0.0;
pub const BASELINE_MULTIPLIER: f64 = 1.0;
pub const SMOOTHING_WINDOW_EPOCHS: usize = 10;
pub const EPSILON: f64 = 0.000001;

#[derive(Debug, Clone)]
pub struct DRSManager {
    node_scores: Arc<DashMap<Address, DRSScore>>,
    historical_scores: Arc<DashMap<Address, VecDeque<DRSScore>>>,
    epoch_stats: Arc<DashMap<u64, EpochStats>>,
    config: Arc<Mutex<DRSManagerConfig>>,
    weights_version: Arc<Mutex<u32>>,
    params_digest: Arc<Mutex<Hash>>,
    current_epoch: Arc<Mutex<u64>>,
    evidence_cache: Arc<DashMap<Hash, EvidenceBundle>>,
}

#[derive(Debug, Clone)]
pub struct DRSManagerConfig {
    pub drs_config: DRSConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DRSConfig {
    pub w_uptime: f64,
    pub w_post_pass: f64,
    pub w_inv_latency: f64,
    pub w_poc: f64,
    pub w_serve: f64,

    pub a1_failed_post: f64,
    pub a2_replay_incoherence: f64,
    pub a3_equivocation: f64,
    pub p_max: f64,

    pub sla_ms: u64,

    pub smoothing_alpha: f64,

    pub multiplier_slope_beta: f64,
    pub m_min: f64,
    pub m_max: f64,

    pub density_penalty_rate: f64,
    pub density_min_multiplier: f64,

    pub high_band_threshold: f64,
    pub mid_band_threshold: f64,
}

impl Default for DRSConfig {
    fn default() -> Self {
        Self {
            w_uptime: 0.20,
            w_post_pass: 0.40,
            w_inv_latency: 0.10,
            w_poc: 0.20,
            w_serve: 0.10,

            a1_failed_post: 0.10,
            a2_replay_incoherence: 0.20,
            a3_equivocation: 0.40,
            p_max: 0.5,

            sla_ms: 600_000,

            smoothing_alpha: 0.3,

            multiplier_slope_beta: 0.6,
            m_min: 0.7,
            m_max: 1.3,

            density_penalty_rate: 0.10,
            density_min_multiplier: 0.40,

            high_band_threshold: 0.8,
            mid_band_threshold: 0.5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DRSScore {
    pub node_id: Address,
    pub epoch: u64,
    pub score_raw: f64,
    pub score_smoothed: f64,
    pub multiplier: f64,
    pub components: DRSComponents,
    pub penalties: DRSPenalties,
    pub quota_band: QuotaBand,
    pub evidence_root: Hash,
    pub weights_version: u32,
    pub params_digest: Hash,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DRSComponents {
    pub uptime: f64,
    pub post_pass: f64,
    pub inv_latency: f64,
    pub poc_quality: f64,
    pub serve_ratio: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DRSPenalties {
    pub failed_post: u32,
    pub replay_or_incoherence: u32,
    pub equivocation: u32,
    pub total_penalty: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum QuotaBand {
    High,
    Mid,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct EpochStats {
    pub epoch: u64,
    pub total_nodes: u32,
    pub avg_score: f64,
    pub median_score: f64,
    pub std_dev: f64,
    pub score_distribution: Vec<(f64, u32)>,
    pub top_performers: Vec<(Address, f64)>,
    pub penalized_nodes: Vec<(Address, String, f64)>,
    pub density_events: Vec<DensityEvent>,
    pub total_rewards_distributed: Balance,
    pub avg_multiplier: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DensityEvent {
    pub node_id: Address,
    pub h3_cell: String,
    pub device_count: u32,
    pub density_multiplier: f64,
    pub epoch: u64,
    pub timestamp: Timestamp,
    pub evidence_root: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct EvidenceBundle {
    pub node_id: Address,
    pub epoch: u64,
    pub uptime_slots_seen: u64,
    pub uptime_slots_expected: u64,
    pub post_challenges: u64,
    pub post_passes: u64,
    pub post_latency_sum_ms: u64,
    pub post_latency_count: u64,
    pub poc_events: Vec<PoCEventData>,
    pub serve_bytes_ok: u64,
    pub serve_bytes_requested: u64,
    pub failed_post_count: u32,
    pub replay_or_incoherence_count: u32,
    pub equivocation_count: u32,
    pub density_data: Option<DensityData>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct PoCEventData {
    pub event_id: Hash,
    pub q_after_ldm: f64,
    pub witness_confidence: f64,
    pub h3_cell: String,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DensityData {
    pub h3_cell: String,
    pub device_count: u32,
    pub dwell_time_pct: f64,
    pub witnesses: Vec<Address>,
    pub vertical_separation_m: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DRSScoreEvent {
    pub node_id: Address,
    pub epoch: u64,
    pub score_u32: u32,
    pub multiplier_fp16: u16,
    pub evidence_root: Hash,
    pub weights_version: u32,
    pub params_digest: Hash,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardDistribution {
    pub node_id: Address,
    pub epoch: u64,
    pub base_storage_reward: Balance,
    pub base_consensus_reward: Balance,
    pub base_coverage_reward: Balance,
    pub drs_multiplier: f64,
    pub final_storage_reward: Balance,
    pub final_consensus_reward: Balance,
    pub final_coverage_reward: Balance,
    pub total_reward: Balance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaAllocation {
    pub node_id: Address,
    pub quota_band: QuotaBand,
    pub ru_limit: u64,
    pub proof_batch_size: u32,
    pub audit_frequency: u64,
    pub publish_rate_limit: u32,
}

impl DRSManager {
    pub fn new(config: DRSConfig) -> Self {
        let params_digest = Self::compute_params_digest(&config);

        Self {
            node_scores: Arc::new(DashMap::new()),
            historical_scores: Arc::new(DashMap::new()),
            epoch_stats: Arc::new(DashMap::new()),
            config: Arc::new(Mutex::new(DRSManagerConfig { drs_config: config })),
            weights_version: Arc::new(Mutex::new(DEFAULT_WEIGHTS_VERSION)),
            params_digest: Arc::new(Mutex::new(params_digest)),
            current_epoch: Arc::new(Mutex::new(0)),
            evidence_cache: Arc::new(DashMap::new()),
        }
    }

    pub fn calculate_drs_score(&self, evidence: EvidenceBundle) -> EgoResult<DRSScore> {
        let config = self.config.lock().unwrap();
        let drs_config = &config.drs_config;

        let components = self.calculate_components(&evidence, drs_config)?;

        let penalties = self.calculate_penalties(&evidence, drs_config);

        let score_raw = self.calculate_raw_score(&components, &penalties, drs_config);

        let previous_score = self.get_previous_score(&evidence.node_id);
        let score_smoothed = self.apply_smoothing(score_raw, previous_score, drs_config);

        let multiplier = self.calculate_multiplier(score_smoothed, drs_config);

        let quota_band = self.determine_quota_band(score_smoothed, drs_config);

        let evidence_root = self.compute_evidence_hash(&evidence)?;

        let weights_version = *self.weights_version.lock().unwrap();
        let params_digest = *self.params_digest.lock().unwrap();

        let score = DRSScore {
            node_id: evidence.node_id,
            epoch: evidence.epoch,
            score_raw,
            score_smoothed,
            multiplier,
            components,
            penalties,
            quota_band,
            evidence_root,
            weights_version,
            params_digest,
            timestamp: Timestamp::now(),
        };

        self.node_scores.insert(evidence.node_id, score.clone());

        self.update_historical_scores(evidence.node_id, score.clone());

        self.evidence_cache.insert(evidence_root, evidence);

        Ok(score)
    }

    fn calculate_components(
        &self,
        evidence: &EvidenceBundle,
        config: &DRSConfig,
    ) -> EgoResult<DRSComponents> {
        let uptime = if evidence.uptime_slots_expected > 0 {
            (evidence.uptime_slots_seen as f64 / evidence.uptime_slots_expected as f64).min(1.0)
        } else {
            0.0
        };

        let post_pass = if evidence.post_challenges > 0 {
            (evidence.post_passes as f64 / evidence.post_challenges as f64).min(1.0)
        } else {
            0.0
        };

        let avg_post_latency_ms = if evidence.post_latency_count > 0 {
            evidence.post_latency_sum_ms / evidence.post_latency_count
        } else {
            0
        };

        let inv_latency = if avg_post_latency_ms == 0 {
            1.0
        } else {
            let post_latency_norm = (avg_post_latency_ms as f64 / config.sla_ms as f64).min(1.0);
            (1.0 - post_latency_norm).max(0.0)
        };

        let poc_quality = if !evidence.poc_events.is_empty() {
            let total_weight: f64 = evidence
                .poc_events
                .iter()
                .map(|e| e.witness_confidence)
                .sum();

            if total_weight > EPSILON {
                let weighted_sum: f64 = evidence
                    .poc_events
                    .iter()
                    .map(|e| e.q_after_ldm * e.witness_confidence)
                    .sum();
                (weighted_sum / total_weight).clamp(0.0, 1.0)
            } else {
                0.0
            }
        } else {
            0.0
        };

        let serve_ratio = if evidence.serve_bytes_requested > 0 {
            (evidence.serve_bytes_ok as f64 / evidence.serve_bytes_requested as f64).min(1.0)
        } else {
            0.0
        };

        Ok(DRSComponents {
            uptime,
            post_pass,
            inv_latency,
            poc_quality,
            serve_ratio,
        })
    }

    fn calculate_penalties(&self, evidence: &EvidenceBundle, config: &DRSConfig) -> DRSPenalties {
        let failed_post = evidence.failed_post_count;
        let replay_or_incoherence = evidence.replay_or_incoherence_count;
        let equivocation = evidence.equivocation_count;

        let total_penalty = (config.a1_failed_post * failed_post as f64
            + config.a2_replay_incoherence * replay_or_incoherence as f64
            + config.a3_equivocation * equivocation as f64)
            .min(config.p_max);

        DRSPenalties {
            failed_post,
            replay_or_incoherence,
            equivocation,
            total_penalty,
        }
    }

    fn calculate_raw_score(
        &self,
        components: &DRSComponents,
        penalties: &DRSPenalties,
        config: &DRSConfig,
    ) -> f64 {
        let weighted_sum = config.w_uptime * components.uptime
            + config.w_post_pass * components.post_pass
            + config.w_inv_latency * components.inv_latency
            + config.w_poc * components.poc_quality
            + config.w_serve * components.serve_ratio;

        (weighted_sum - penalties.total_penalty).clamp(MIN_SCORE, MAX_SCORE)
    }

    fn get_previous_score(&self, node_id: &Address) -> Option<f64> {
        self.node_scores
            .get(node_id)
            .map(|score| score.score_smoothed)
    }

    fn apply_smoothing(
        &self,
        score_raw: f64,
        previous_score: Option<f64>,
        config: &DRSConfig,
    ) -> f64 {
        if let Some(prev) = previous_score {
            ((1.0 - config.smoothing_alpha) * prev + config.smoothing_alpha * score_raw)
                .clamp(MIN_SCORE, MAX_SCORE)
        } else {
            score_raw
        }
    }

    fn calculate_multiplier(&self, score: f64, config: &DRSConfig) -> f64 {
        let m = BASELINE_MULTIPLIER + config.multiplier_slope_beta * (score - 0.5);
        m.clamp(config.m_min, config.m_max)
    }

    fn determine_quota_band(&self, score: f64, config: &DRSConfig) -> QuotaBand {
        if score >= config.high_band_threshold {
            QuotaBand::High
        } else if score >= config.mid_band_threshold {
            QuotaBand::Mid
        } else {
            QuotaBand::Low
        }
    }

    fn compute_evidence_hash(&self, evidence: &EvidenceBundle) -> EgoResult<Hash> {
        let config = bincode::config::standard();
        let evidence_bytes = bincode::encode_to_vec(evidence, config)
            .map_err(|e| EgoError::SerializationError(e.to_string()))?;
        Ok(crate::crypto::hash_data(&evidence_bytes))
    }

    fn update_historical_scores(&self, node_id: Address, score: DRSScore) {
        let mut history = self
            .historical_scores
            .entry(node_id)
            .or_insert_with(VecDeque::new);

        history.push_back(score);

        while history.len() > SMOOTHING_WINDOW_EPOCHS {
            history.pop_front();
        }
    }

    pub fn calculate_location_density_multiplier(&self, density_data: &DensityData) -> f64 {
        let config = self.config.lock().unwrap();

        if density_data.device_count <= 1 {
            return 1.0;
        }

        let n = density_data.device_count;
        let penalty = config.drs_config.density_penalty_rate * (n - 1) as f64;
        let ldm = (1.0_f64 - penalty).max(config.drs_config.density_min_multiplier);

        if density_data.dwell_time_pct < 0.10 {
            1.0
        } else {
            ldm
        }
    }

    pub fn apply_density_penalty(
        &self,
        base_score: f64,
        density_data: Option<&DensityData>,
    ) -> f64 {
        if let Some(density) = density_data {
            let ldm = self.calculate_location_density_multiplier(density);
            base_score * ldm
        } else {
            base_score
        }
    }

    pub fn get_node_score(&self, node_id: &Address) -> Option<DRSScore> {
        self.node_scores.get(node_id).map(|score| score.clone())
    }

    pub fn get_node_multiplier(&self, node_id: &Address) -> f64 {
        self.node_scores
            .get(node_id)
            .map(|score| score.multiplier)
            .unwrap_or(BASELINE_MULTIPLIER)
    }

    pub fn get_historical_scores(&self, node_id: &Address) -> Vec<DRSScore> {
        self.historical_scores
            .get(node_id)
            .map(|history| history.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn get_epoch_stats(&self, epoch: u64) -> Option<EpochStats> {
        self.epoch_stats.get(&epoch).map(|stats| stats.clone())
    }

    pub fn get_current_epoch(&self) -> u64 {
        *self.current_epoch.lock().unwrap()
    }

    pub fn finalize_epoch(&self, epoch: u64) -> EgoResult<EpochStats> {
        let scores: Vec<DRSScore> = self
            .node_scores
            .iter()
            .filter(|entry| entry.epoch == epoch)
            .map(|entry| entry.clone())
            .collect();

        let total_nodes = scores.len() as u32;

        if total_nodes == 0 {
            return Ok(EpochStats {
                epoch,
                total_nodes: 0,
                avg_score: 0.0,
                median_score: 0.0,
                std_dev: 0.0,
                score_distribution: vec![],
                top_performers: vec![],
                penalized_nodes: vec![],
                density_events: vec![],
                total_rewards_distributed: Balance::ZERO,
                avg_multiplier: BASELINE_MULTIPLIER,
            });
        }

        let avg_score = scores.iter().map(|s| s.score_smoothed).sum::<f64>() / total_nodes as f64;

        let mut sorted_scores: Vec<f64> = scores.iter().map(|s| s.score_smoothed).collect();
        sorted_scores.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median_score = if sorted_scores.len() % 2 == 0 {
            let mid = sorted_scores.len() / 2;
            (sorted_scores[mid - 1] + sorted_scores[mid]) / 2.0
        } else {
            sorted_scores[sorted_scores.len() / 2]
        };

        let variance = scores
            .iter()
            .map(|s| {
                let diff = s.score_smoothed - avg_score;
                diff * diff
            })
            .sum::<f64>()
            / total_nodes as f64;
        let std_dev = variance.sqrt();

        let mut distribution = vec![(0.0, 0u32); 10];
        for score in &scores {
            let bucket = (score.score_smoothed * 10.0).floor() as usize;
            let bucket = bucket.min(9);
            distribution[bucket].0 = bucket as f64 / 10.0;
            distribution[bucket].1 += 1;
        }

        let mut sorted_by_score = scores.clone();
        sorted_by_score.sort_by(|a, b| b.score_smoothed.partial_cmp(&a.score_smoothed).unwrap());
        let top_count = (total_nodes as f64 * 0.1).max(1.0) as usize;
        let top_performers: Vec<(Address, f64)> = sorted_by_score
            .iter()
            .take(top_count)
            .map(|s| (s.node_id, s.score_smoothed))
            .collect();

        let penalized_nodes: Vec<(Address, String, f64)> = scores
            .iter()
            .filter(|s| s.penalties.total_penalty > 0.0)
            .map(|s| {
                let reason = format!(
                    "FailedPost:{}, Replay:{}, Equivocation:{}",
                    s.penalties.failed_post,
                    s.penalties.replay_or_incoherence,
                    s.penalties.equivocation
                );
                (s.node_id, reason, s.penalties.total_penalty)
            })
            .collect();

        let density_events = self.generate_density_events(epoch, &scores);

        let avg_multiplier = scores.iter().map(|s| s.multiplier).sum::<f64>() / total_nodes as f64;

        let stats = EpochStats {
            epoch,
            total_nodes,
            avg_score,
            median_score,
            std_dev,
            score_distribution: distribution,
            top_performers,
            penalized_nodes,
            density_events,
            total_rewards_distributed: Balance::ZERO,
            avg_multiplier,
        };

        self.epoch_stats.insert(epoch, stats.clone());

        *self.current_epoch.lock().unwrap() = epoch + 1;

        Ok(stats)
    }

    fn generate_density_events(&self, epoch: u64, scores: &[DRSScore]) -> Vec<DensityEvent> {
        let mut events = Vec::new();

        for score in scores {
            if let Some(evidence) = self.evidence_cache.get(&score.evidence_root) {
                if let Some(ref density) = evidence.density_data {
                    if density.device_count > 1 {
                        let ldm = self.calculate_location_density_multiplier(density);

                        events.push(DensityEvent {
                            node_id: score.node_id,
                            h3_cell: density.h3_cell.clone(),
                            device_count: density.device_count,
                            density_multiplier: ldm,
                            epoch,
                            timestamp: Timestamp::now(),
                            evidence_root: score.evidence_root,
                        });
                    }
                }
            }
        }

        events
    }

    pub fn apply_reward_multiplier(
        &self,
        node_id: &Address,
        base_storage: Balance,
        base_consensus: Balance,
        base_coverage: Balance,
        epoch: u64,
    ) -> EgoResult<RewardDistribution> {
        let multiplier = self.get_node_multiplier(node_id);

        let final_storage =
            Balance::new(((base_storage.as_u128() as f64) * multiplier).round() as u128);
        let final_consensus =
            Balance::new(((base_consensus.as_u128() as f64) * multiplier).round() as u128);
        let final_coverage =
            Balance::new(((base_coverage.as_u128() as f64) * multiplier).round() as u128);

        let total_reward = final_storage
            .checked_add(final_consensus)
            .and_then(|sum| sum.checked_add(final_coverage))
            .unwrap_or(Balance::ZERO);

        Ok(RewardDistribution {
            node_id: *node_id,
            epoch,
            base_storage_reward: base_storage,
            base_consensus_reward: base_consensus,
            base_coverage_reward: base_coverage,
            drs_multiplier: multiplier,
            final_storage_reward: final_storage,
            final_consensus_reward: final_consensus,
            final_coverage_reward: final_coverage,
            total_reward,
        })
    }

    pub fn get_quota_allocation(&self, node_id: &Address) -> QuotaAllocation {
        let score = self.get_node_score(node_id);

        let quota_band = score
            .as_ref()
            .map(|s| s.quota_band.clone())
            .unwrap_or(QuotaBand::Low);

        let (ru_limit, proof_batch_size, audit_frequency, publish_rate_limit) = match quota_band {
            QuotaBand::High => (10_000_000, 500, 100, 1000),
            QuotaBand::Mid => (5_000_000, 250, 50, 500),
            QuotaBand::Low => (2_000_000, 100, 20, 200),
        };

        QuotaAllocation {
            node_id: *node_id,
            quota_band,
            ru_limit,
            proof_batch_size,
            audit_frequency,
            publish_rate_limit,
        }
    }

    pub fn qualifies_for_operation(&self, node_id: &Address, min_score: f64) -> bool {
        self.get_node_score(node_id)
            .map(|s| s.score_smoothed >= min_score)
            .unwrap_or(false)
    }

    pub fn create_drs_score_event(&self, score: &DRSScore, signature: Vec<u8>) -> DRSScoreEvent {
        let score_u32 = (score.score_smoothed * 1_000_000.0).round() as u32;
        let multiplier_fp16 = ((score.multiplier - score.multiplier.floor()) * 65536.0) as u16;

        DRSScoreEvent {
            node_id: score.node_id,
            epoch: score.epoch,
            score_u32,
            multiplier_fp16,
            evidence_root: score.evidence_root,
            weights_version: score.weights_version,
            params_digest: score.params_digest,
            signature,
        }
    }

    pub fn verify_drs_score_event(
        &self,
        event: &DRSScoreEvent,
        public_key: &crate::PublicKey,
    ) -> EgoResult<bool> {
        let mut data = Vec::new();
        data.extend_from_slice(event.node_id.as_bytes());
        data.extend_from_slice(&event.epoch.to_le_bytes());
        data.extend_from_slice(&event.score_u32.to_le_bytes());
        data.extend_from_slice(&event.multiplier_fp16.to_le_bytes());
        data.extend_from_slice(event.evidence_root.as_bytes());
        data.extend_from_slice(&event.weights_version.to_le_bytes());
        data.extend_from_slice(event.params_digest.as_bytes());

        let message_hash = crate::crypto::hash_data(&data);

        let signature = crate::Signature::dilithium2(event.signature.clone());

        crate::crypto::verify_signature(public_key, message_hash.as_bytes(), &signature)
    }

    pub fn update_config(&self, new_config: DRSConfig) -> EgoResult<()> {
        validate_drs_params(&new_config)?;

        let new_params_digest = Self::compute_params_digest(&new_config);

        *self.config.lock().unwrap() = DRSManagerConfig {
            drs_config: new_config,
        };
        *self.params_digest.lock().unwrap() = new_params_digest;

        let mut version = self.weights_version.lock().unwrap();
        *version = version.saturating_add(1);

        Ok(())
    }

    pub fn get_config(&self) -> DRSConfig {
        self.config.lock().unwrap().drs_config.clone()
    }

    pub fn get_weights_version(&self) -> u32 {
        *self.weights_version.lock().unwrap()
    }

    pub fn get_params_digest(&self) -> Hash {
        *self.params_digest.lock().unwrap()
    }

    fn compute_params_digest(config: &DRSConfig) -> Hash {
        let config_bytes =
            bincode::encode_to_vec(config, bincode::config::standard()).unwrap_or_default();
        crate::crypto::hash_data(&config_bytes)
    }

    pub fn audit_recompute_score(
        &self,
        evidence: &EvidenceBundle,
        expected_score: &DRSScore,
    ) -> EgoResult<bool> {
        let recomputed = self.calculate_drs_score(evidence.clone())?;

        let score_match = (recomputed.score_smoothed - expected_score.score_smoothed).abs() < 0.001;
        let multiplier_match = (recomputed.multiplier - expected_score.multiplier).abs() < 0.001;
        let evidence_match = recomputed.evidence_root == expected_score.evidence_root;

        Ok(score_match && multiplier_match && evidence_match)
    }

    pub fn get_all_nodes_in_epoch(&self, epoch: u64) -> Vec<(Address, DRSScore)> {
        self.node_scores
            .iter()
            .filter(|entry| entry.epoch == epoch)
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect()
    }

    pub fn get_nodes_by_quota_band(&self, band: QuotaBand) -> Vec<Address> {
        self.node_scores
            .iter()
            .filter(|entry| entry.quota_band == band)
            .map(|entry| *entry.key())
            .collect()
    }

    pub fn get_nodes_requiring_audit(&self, min_score: f64) -> Vec<Address> {
        self.node_scores
            .iter()
            .filter(|entry| entry.score_smoothed < min_score)
            .map(|entry| *entry.key())
            .collect()
    }

    pub fn calculate_aggregate_stats(&self, epoch: u64) -> EgoResult<AggregateStats> {
        let scores: Vec<DRSScore> = self
            .node_scores
            .iter()
            .filter(|entry| entry.epoch == epoch)
            .map(|entry| entry.clone())
            .collect();

        if scores.is_empty() {
            return Ok(AggregateStats::default());
        }

        let total_nodes = scores.len() as u32;
        let avg_uptime =
            scores.iter().map(|s| s.components.uptime).sum::<f64>() / total_nodes as f64;
        let avg_post_pass =
            scores.iter().map(|s| s.components.post_pass).sum::<f64>() / total_nodes as f64;
        let avg_poc_quality =
            scores.iter().map(|s| s.components.poc_quality).sum::<f64>() / total_nodes as f64;
        let avg_serve_ratio =
            scores.iter().map(|s| s.components.serve_ratio).sum::<f64>() / total_nodes as f64;

        let total_penalties = scores
            .iter()
            .map(|s| s.penalties.total_penalty)
            .sum::<f64>();
        let avg_penalty = total_penalties / total_nodes as f64;

        let high_band_count = scores
            .iter()
            .filter(|s| s.quota_band == QuotaBand::High)
            .count() as u32;
        let mid_band_count = scores
            .iter()
            .filter(|s| s.quota_band == QuotaBand::Mid)
            .count() as u32;
        let low_band_count = scores
            .iter()
            .filter(|s| s.quota_band == QuotaBand::Low)
            .count() as u32;

        let nodes_with_penalties = scores
            .iter()
            .filter(|s| s.penalties.total_penalty > 0.0)
            .count() as u32;

        Ok(AggregateStats {
            epoch,
            total_nodes,
            avg_uptime,
            avg_post_pass,
            avg_poc_quality,
            avg_serve_ratio,
            avg_penalty,
            high_band_count,
            mid_band_count,
            low_band_count,
            nodes_with_penalties,
        })
    }

    pub fn get_evidence_bundle(&self, evidence_root: &Hash) -> Option<EvidenceBundle> {
        self.evidence_cache.get(evidence_root).map(|e| e.clone())
    }

    pub fn prune_old_data(&self, keep_epochs: u64, current_epoch: u64) -> usize {
        let cutoff_epoch = current_epoch.saturating_sub(keep_epochs);
        let mut pruned = 0;

        self.epoch_stats.retain(|&epoch, _| {
            if epoch < cutoff_epoch {
                pruned += 1;
                false
            } else {
                true
            }
        });

        self.historical_scores.iter_mut().for_each(|mut entry| {
            let original_len = entry.len();
            entry.retain(|score| score.epoch >= cutoff_epoch);
            pruned += original_len - entry.len();
        });

        self.evidence_cache
            .retain(|_, evidence| evidence.epoch >= cutoff_epoch);

        pruned
    }

    pub fn export_scores_for_epoch(&self, epoch: u64) -> Vec<(Address, f64, f64)> {
        self.node_scores
            .iter()
            .filter(|entry| entry.epoch == epoch)
            .map(|entry| (entry.node_id, entry.score_smoothed, entry.multiplier))
            .collect()
    }

    pub fn import_score(&self, score: DRSScore) -> EgoResult<()> {
        let expected_params_digest = *self.params_digest.lock().unwrap();
        if score.params_digest != expected_params_digest {
            return Err(EgoError::InvalidTransaction(
                "Score params_digest mismatch".to_string(),
            ));
        }

        self.node_scores.insert(score.node_id, score);
        Ok(())
    }

    pub fn validate_score_consistency(&self, node_id: &Address, epochs: &[u64]) -> bool {
        let scores: Vec<Option<DRSScore>> = epochs
            .iter()
            .map(|&epoch| {
                self.historical_scores
                    .get(node_id)
                    .and_then(|history| history.iter().find(|s| s.epoch == epoch).cloned())
            })
            .collect();

        for i in 1..scores.len() {
            if let (Some(prev), Some(curr)) = (&scores[i - 1], &scores[i]) {
                let score_diff = (curr.score_smoothed - prev.score_smoothed).abs();
                if score_diff > 0.15 {
                    return false;
                }
            }
        }

        true
    }

    pub fn detect_anomalies(&self, node_id: &Address) -> Vec<AnomalyReport> {
        let mut anomalies = Vec::new();

        if let Some(score) = self.get_node_score(node_id) {
            if score.penalties.equivocation > 0 {
                anomalies.push(AnomalyReport {
                    node_id: *node_id,
                    anomaly_type: AnomalyType::Equivocation,
                    severity: Severity::Critical,
                    epoch: score.epoch,
                    description: format!(
                        "Equivocation detected: {} instances",
                        score.penalties.equivocation
                    ),
                });
            }

            if score.components.post_pass < 0.5 {
                anomalies.push(AnomalyReport {
                    node_id: *node_id,
                    anomaly_type: AnomalyType::LowPostPass,
                    severity: Severity::High,
                    epoch: score.epoch,
                    description: format!(
                        "Low PoSt pass rate: {:.2}%",
                        score.components.post_pass * 100.0
                    ),
                });
            }

            if score.components.uptime < 0.7 {
                anomalies.push(AnomalyReport {
                    node_id: *node_id,
                    anomaly_type: AnomalyType::LowUptime,
                    severity: Severity::Medium,
                    epoch: score.epoch,
                    description: format!("Low uptime: {:.2}%", score.components.uptime * 100.0),
                });
            }

            if score.penalties.replay_or_incoherence > 5 {
                anomalies.push(AnomalyReport {
                    node_id: *node_id,
                    anomaly_type: AnomalyType::ReplayAttack,
                    severity: Severity::High,
                    epoch: score.epoch,
                    description: format!(
                        "Replay/incoherence: {} instances",
                        score.penalties.replay_or_incoherence
                    ),
                });
            }
        }

        anomalies
    }

    pub fn generate_performance_report(&self, node_id: &Address, epochs: u64) -> PerformanceReport {
        let history = self.get_historical_scores(node_id);
        let recent: Vec<&DRSScore> = history.iter().rev().take(epochs as usize).collect();

        if recent.is_empty() {
            return PerformanceReport::default();
        }

        let avg_score = recent.iter().map(|s| s.score_smoothed).sum::<f64>() / recent.len() as f64;
        let avg_multiplier = recent.iter().map(|s| s.multiplier).sum::<f64>() / recent.len() as f64;

        let mut score_trend = 0.0;
        if recent.len() >= 2 {
            let first = recent.last().unwrap().score_smoothed;
            let last = recent.first().unwrap().score_smoothed;
            score_trend = last - first;
        }

        let total_penalties: u32 = recent
            .iter()
            .map(|s| {
                s.penalties.failed_post
                    + s.penalties.replay_or_incoherence
                    + s.penalties.equivocation
            })
            .sum();

        let uptime_trend = if recent.len() >= 2 {
            let first = recent.last().unwrap().components.uptime;
            let last = recent.first().unwrap().components.uptime;
            last - first
        } else {
            0.0
        };

        let post_pass_trend = if recent.len() >= 2 {
            let first = recent.last().unwrap().components.post_pass;
            let last = recent.first().unwrap().components.post_pass;
            last - first
        } else {
            0.0
        };

        PerformanceReport {
            node_id: *node_id,
            epochs_analyzed: recent.len() as u64,
            avg_score,
            avg_multiplier,
            score_trend,
            total_penalties,
            uptime_trend,
            post_pass_trend,
            current_quota_band: recent
                .first()
                .map(|s| s.quota_band.clone())
                .unwrap_or(QuotaBand::Low),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AggregateStats {
    pub epoch: u64,
    pub total_nodes: u32,
    pub avg_uptime: f64,
    pub avg_post_pass: f64,
    pub avg_poc_quality: f64,
    pub avg_serve_ratio: f64,
    pub avg_penalty: f64,
    pub high_band_count: u32,
    pub mid_band_count: u32,
    pub low_band_count: u32,
    pub nodes_with_penalties: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyReport {
    pub node_id: Address,
    pub anomaly_type: AnomalyType,
    pub severity: Severity,
    pub epoch: u64,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalyType {
    Equivocation,
    LowPostPass,
    LowUptime,
    ReplayAttack,
    SuddenScoreDrop,
    ConsistentFailures,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PerformanceReport {
    pub node_id: Address,
    pub epochs_analyzed: u64,
    pub avg_score: f64,
    pub avg_multiplier: f64,
    pub score_trend: f64,
    pub total_penalties: u32,
    pub uptime_trend: f64,
    pub post_pass_trend: f64,
    pub current_quota_band: QuotaBand,
}

impl Default for QuotaBand {
    fn default() -> Self {
        QuotaBand::Low
    }
}

impl Default for Address {
    fn default() -> Self {
        Address::new([0u8; 20])
    }
}

pub fn create_evidence_bundle_from_account(
    account: &Account,
    epoch: u64,
    poc_events: Vec<PoCEventData>,
    density_data: Option<DensityData>,
) -> EvidenceBundle {
    let provider_info = account.storage_provider_info.as_ref();

    let (
        uptime_slots_seen,
        uptime_slots_expected,
        post_challenges,
        post_passes,
        post_latency_sum_ms,
        post_latency_count,
    ) = if let Some(info) = provider_info {
        let stats = &info.postrep_stats;
        let uptime_pct = account
            .staking_info
            .as_ref()
            .map(|si| si.performance.uptime_percentage)
            .unwrap_or(100000);

        let expected_slots = 1000u64;
        let seen_slots = (expected_slots * uptime_pct as u64) / 100000;

        (
            seen_slots,
            expected_slots,
            stats.challenges_answered + stats.challenges_missed,
            stats.challenges_answered,
            stats.avg_post_latency_ms as u64 * stats.post_proofs_submitted,
            stats.post_proofs_submitted,
        )
    } else {
        (0, 0, 0, 0, 0, 0)
    };

    let serve_bytes_ok = provider_info
        .map(|info| info.earnings.retrieval_fees.as_u128() as u64)
        .unwrap_or(0);
    let serve_bytes_requested = if serve_bytes_ok > 0 {
        serve_bytes_ok.saturating_mul(100) / 95
    } else {
        0
    };

    let failed_post_count = provider_info
        .map(|info| info.postrep_stats.consecutive_misses)
        .unwrap_or(0);

    EvidenceBundle {
        node_id: account.address,
        epoch,
        uptime_slots_seen,
        uptime_slots_expected,
        post_challenges,
        post_passes,
        post_latency_sum_ms,
        post_latency_count,
        poc_events,
        serve_bytes_ok,
        serve_bytes_requested,
        failed_post_count,
        replay_or_incoherence_count: 0,
        equivocation_count: 0,
        density_data,
    }
}

pub fn apply_drs_to_rewards(
    drs_manager: &DRSManager,
    node_rewards: Vec<(Address, Balance, Balance, Balance)>,
    epoch: u64,
) -> EgoResult<Vec<RewardDistribution>> {
    let mut distributions = Vec::new();

    for (node_id, storage_reward, consensus_reward, coverage_reward) in node_rewards {
        let distribution = drs_manager.apply_reward_multiplier(
            &node_id,
            storage_reward,
            consensus_reward,
            coverage_reward,
            epoch,
        )?;
        distributions.push(distribution);
    }

    Ok(distributions)
}

pub fn calculate_epoch_drs_scores(
    drs_manager: &DRSManager,
    evidence_bundles: Vec<EvidenceBundle>,
) -> EgoResult<Vec<DRSScore>> {
    let mut scores = Vec::new();

    for evidence in evidence_bundles {
        let score = drs_manager.calculate_drs_score(evidence)?;
        scores.push(score);
    }

    Ok(scores)
}

pub fn validate_drs_params(config: &DRSConfig) -> EgoResult<()> {
    let weight_sum =
        config.w_uptime + config.w_post_pass + config.w_inv_latency + config.w_poc + config.w_serve;

    if (weight_sum - 1.0).abs() > 0.01 {
        return Err(EgoError::InvalidTransaction(format!(
            "Weight sum must equal 1.0, got {}",
            weight_sum
        )));
    }

    if config.m_min >= config.m_max {
        return Err(EgoError::InvalidTransaction(
            "m_min must be less than m_max".to_string(),
        ));
    }

    if config.smoothing_alpha < 0.0 || config.smoothing_alpha > 1.0 {
        return Err(EgoError::InvalidTransaction(
            "smoothing_alpha must be between 0 and 1".to_string(),
        ));
    }

    if config.p_max < 0.0 || config.p_max > 1.0 {
        return Err(EgoError::InvalidTransaction(
            "p_max must be between 0 and 1".to_string(),
        ));
    }

    if config.density_penalty_rate < 0.0 || config.density_penalty_rate > 1.0 {
        return Err(EgoError::InvalidTransaction(
            "density_penalty_rate must be between 0 and 1".to_string(),
        ));
    }

    if config.density_min_multiplier < 0.0 || config.density_min_multiplier > 1.0 {
        return Err(EgoError::InvalidTransaction(
            "density_min_multiplier must be between 0 and 1".to_string(),
        ));
    }

    if config.high_band_threshold <= config.mid_band_threshold {
        return Err(EgoError::InvalidTransaction(
            "high_band_threshold must be greater than mid_band_threshold".to_string(),
        ));
    }

    if config.mid_band_threshold <= 0.0 {
        return Err(EgoError::InvalidTransaction(
            "mid_band_threshold must be positive".to_string(),
        ));
    }

    Ok(())
}

pub fn calculate_bucket_rewards(
    total_emission: Balance,
    storage_pct: f64,
    consensus_pct: f64,
    coverage_pct: f64,
) -> (Balance, Balance, Balance) {
    let storage_reward =
        Balance::new(((total_emission.as_u128() as f64) * storage_pct).round() as u128);
    let consensus_reward =
        Balance::new(((total_emission.as_u128() as f64) * consensus_pct).round() as u128);
    let coverage_reward =
        Balance::new(((total_emission.as_u128() as f64) * coverage_pct).round() as u128);

    (storage_reward, consensus_reward, coverage_reward)
}

pub fn distribute_rewards_with_drs(
    drs_manager: &DRSManager,
    nodes: Vec<Address>,
    total_storage_bucket: Balance,
    total_consensus_bucket: Balance,
    total_coverage_bucket: Balance,
    epoch: u64,
    base_shares: &[(Address, f64, f64, f64)],
) -> EgoResult<Vec<RewardDistribution>> {
    let mut total_weighted_storage = 0.0;
    let mut total_weighted_consensus = 0.0;
    let mut total_weighted_coverage = 0.0;

    let mut weighted_shares = Vec::new();

    for (node_id, storage_share, consensus_share, coverage_share) in base_shares {
        let multiplier = drs_manager.get_node_multiplier(node_id);

        let w_storage = storage_share * multiplier;
        let w_consensus = consensus_share * multiplier;
        let w_coverage = coverage_share * multiplier;

        total_weighted_storage += w_storage;
        total_weighted_consensus += w_consensus;
        total_weighted_coverage += w_coverage;

        weighted_shares.push((*node_id, w_storage, w_consensus, w_coverage, multiplier));
    }

    let mut distributions = Vec::new();

    for (node_id, w_storage, w_consensus, w_coverage, multiplier) in weighted_shares {
        let storage_reward = if total_weighted_storage > EPSILON {
            Balance::new(
                ((total_storage_bucket.as_u128() as f64) * (w_storage / total_weighted_storage))
                    .round() as u128,
            )
        } else {
            Balance::ZERO
        };

        let consensus_reward = if total_weighted_consensus > EPSILON {
            Balance::new(
                ((total_consensus_bucket.as_u128() as f64)
                    * (w_consensus / total_weighted_consensus))
                    .round() as u128,
            )
        } else {
            Balance::ZERO
        };

        let coverage_reward = if total_weighted_coverage > EPSILON {
            Balance::new(
                ((total_coverage_bucket.as_u128() as f64) * (w_coverage / total_weighted_coverage))
                    .round() as u128,
            )
        } else {
            Balance::ZERO
        };

        let base_storage = if total_weighted_storage > EPSILON {
            Balance::new(
                ((total_storage_bucket.as_u128() as f64)
                    * (w_storage / multiplier / total_weighted_storage))
                    .round() as u128,
            )
        } else {
            Balance::ZERO
        };

        let base_consensus = if total_weighted_consensus > EPSILON {
            Balance::new(
                ((total_consensus_bucket.as_u128() as f64)
                    * (w_consensus / multiplier / total_weighted_consensus))
                    .round() as u128,
            )
        } else {
            Balance::ZERO
        };

        let base_coverage = if total_weighted_coverage > EPSILON {
            Balance::new(
                ((total_coverage_bucket.as_u128() as f64)
                    * (w_coverage / multiplier / total_weighted_coverage))
                    .round() as u128,
            )
        } else {
            Balance::ZERO
        };

        let total_reward = storage_reward
            .checked_add(consensus_reward)
            .and_then(|sum| sum.checked_add(coverage_reward))
            .unwrap_or(Balance::ZERO);

        distributions.push(RewardDistribution {
            node_id,
            epoch,
            base_storage_reward: base_storage,
            base_consensus_reward: base_consensus,
            base_coverage_reward: base_coverage,
            drs_multiplier: multiplier,
            final_storage_reward: storage_reward,
            final_consensus_reward: consensus_reward,
            final_coverage_reward: coverage_reward,
            total_reward,
        });
    }

    Ok(distributions)
}

pub fn apply_density_to_poc_quality(
    base_q: f64,
    device_count: u32,
    dwell_time_pct: f64,
    density_penalty_rate: f64,
    density_min_multiplier: f64,
) -> f64 {
    if device_count <= 1 || dwell_time_pct < 0.10 {
        return base_q;
    }

    let penalty = density_penalty_rate * (device_count - 1) as f64;
    let ldm = (1.0 - penalty).max(density_min_multiplier);

    base_q * ldm
}

pub fn compute_drs_event_signature(
    event: &DRSScoreEvent,
    keypair: &crate::crypto::KeyPair,
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(event.node_id.as_bytes());
    data.extend_from_slice(&event.epoch.to_le_bytes());
    data.extend_from_slice(&event.score_u32.to_le_bytes());
    data.extend_from_slice(&event.multiplier_fp16.to_le_bytes());
    data.extend_from_slice(event.evidence_root.as_bytes());
    data.extend_from_slice(&event.weights_version.to_le_bytes());
    data.extend_from_slice(event.params_digest.as_bytes());

    let message_hash = crate::crypto::hash_data(&data);
    let signature = keypair.sign_dilithium(message_hash.as_bytes());
    signature.signature_data
}
