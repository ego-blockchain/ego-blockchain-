use crate::error::{PoCError, PoCResult};
use ego_core::{Address, Hash, KeyPair, Signature, Timestamp};
use ego_core::crypto::hash_multiple;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};

pub const W_UPTIME: f64        = 0.20;
pub const W_POST_PASS: f64     = 0.40;
pub const W_INV_LATENCY: f64   = 0.10;
pub const W_POC_QUALITY: f64   = 0.20;
pub const W_SERVE_RATIO: f64   = 0.10;

pub const LATENCY_REF_MS: f64  = 5_000.0;

pub const LATENCY_MAX_MS: f64  = 60_000.0;

pub const MULTIPLIER_MIN: f64  = 0.70;
pub const MULTIPLIER_MAX: f64  = 1.30;
pub const MULTIPLIER_SLOPE: f64 = 0.60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DRSInputs {
    pub node_addr: Address,
    pub epoch: u64,

    pub uptime_fraction: f64,

    pub post_windows_assigned: u32,
    pub post_windows_passed: u32,

    pub post_latency_p50_ms: u64,

    pub consecutive_post_misses: u32,

    pub avg_poc_quality: f64,

    pub poc_event_count: u32,

    pub data_requests_received: u64,
    pub data_requests_served: u64,

    pub equivocations: u32,
    pub replay_attacks: u32,

    pub evidence_root: Hash,
}

impl DRSInputs {
    pub fn post_pass_rate(&self) -> f64 {
        if self.post_windows_assigned == 0 { return 1.0; }
        self.post_windows_passed as f64 / self.post_windows_assigned as f64
    }

    pub fn serve_ratio(&self) -> f64 {
        if self.data_requests_received == 0 { return 1.0; }
        self.data_requests_served as f64 / self.data_requests_received as f64
    }

    pub fn inv_latency_score(&self) -> f64 {
        if self.post_latency_p50_ms == 0 { return 1.0; }
        let ms = self.post_latency_p50_ms as f64;
        if ms >= LATENCY_MAX_MS { return 0.0; }
        ((LATENCY_MAX_MS - ms) / (LATENCY_MAX_MS - LATENCY_REF_MS)).clamp(0.0, 1.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct DRSScoreEvent {
    pub event_id: Hash,
    pub node_addr: Address,
    pub epoch: u64,

    pub raw_score: f64,

    pub score_u32: u32,

    pub multiplier: f64,

    pub multiplier_fp16: u16,

    pub uptime_component: f64,
    pub post_component: f64,
    pub latency_component: f64,
    pub poc_component: f64,
    pub serve_component: f64,
    pub total_penalty: f64,

    pub weights_version: u8,

    pub params_digest: Hash,

    pub evidence_root: Hash,
    pub computed_at: Timestamp,
    pub scorer_sig: Signature,
}

impl DRSScoreEvent {

    pub fn is_eligible(&self) -> bool { self.raw_score >= 0.5 }

    pub fn is_high_quota(&self) -> bool { self.raw_score >= 0.8 }
}

pub struct DRSScorer {
    weights_version: u8,
    params_digest: Hash,
}

impl DRSScorer {
    pub fn new() -> Self {
        let params_digest = Self::compute_params_digest(1);
        Self { weights_version: 1, params_digest }
    }

    pub fn compute(&self, inputs: &DRSInputs) -> (f64, f64) {

        let uptime     = inputs.uptime_fraction.clamp(0.0, 1.0);
        let post_pass  = inputs.post_pass_rate().clamp(0.0, 1.0);
        let inv_lat    = inputs.inv_latency_score();
        let poc_qual   = inputs.avg_poc_quality.clamp(0.0, 1.0);
        let serve      = inputs.serve_ratio().clamp(0.0, 1.0);

        let poc_adj = if inputs.poc_event_count == 0 { 0.0 } else { poc_qual };

        let base_score = W_UPTIME       * uptime
                       + W_POST_PASS    * post_pass
                       + W_INV_LATENCY  * inv_lat
                       + W_POC_QUALITY  * poc_adj
                       + W_SERVE_RATIO  * serve;

        let equivocation_penalty = if inputs.equivocations > 0 { 0.30 } else { 0.0 };

        let replay_penalty = (inputs.replay_attacks as f64 * 0.15).min(0.30);

        let miss_penalty = (inputs.consecutive_post_misses as f64 * 0.10).min(0.40);

        let total_penalty = (equivocation_penalty + replay_penalty + miss_penalty).min(1.0);

        let raw_score = (base_score - total_penalty).clamp(0.0, 1.0);

        let multiplier = (1.0 + MULTIPLIER_SLOPE * (raw_score - 0.5))
            .clamp(MULTIPLIER_MIN, MULTIPLIER_MAX);

        debug!(
            "DRS node={} epoch={} base={:.4} penalty={:.4} score={:.4} mult={:.3}",
            inputs.node_addr, inputs.epoch, base_score, total_penalty, raw_score, multiplier
        );

        (raw_score, multiplier)
    }

    pub fn score_event(
        &self,
        inputs: &DRSInputs,
        keypair: &ego_core::KeyPair,
    ) -> PoCResult<DRSScoreEvent> {
        let (raw_score, multiplier) = self.compute(inputs);

        let score_u32 = (raw_score * u32::MAX as f64) as u32;
        let multiplier_fp16 = (multiplier * 1000.0) as u16;

        let event_id = hash_multiple(&[
            inputs.node_addr.as_bytes(),
            &inputs.epoch.to_le_bytes(),
            &score_u32.to_le_bytes(),
        ]);

        let uptime_component    = W_UPTIME      * inputs.uptime_fraction.clamp(0.0, 1.0);
        let post_component      = W_POST_PASS   * inputs.post_pass_rate().clamp(0.0, 1.0);
        let latency_component   = W_INV_LATENCY * inputs.inv_latency_score();
        let poc_component       = W_POC_QUALITY * if inputs.poc_event_count == 0 { 0.0 } else { inputs.avg_poc_quality.clamp(0.0, 1.0) };
        let serve_component     = W_SERVE_RATIO * inputs.serve_ratio().clamp(0.0, 1.0);
        let equivocation_pen    = if inputs.equivocations > 0 { 0.30 } else { 0.0 };
        let replay_pen          = (inputs.replay_attacks as f64 * 0.15).min(0.30);
        let miss_pen            = (inputs.consecutive_post_misses as f64 * 0.10).min(0.40);
        let total_penalty       = (equivocation_pen + replay_pen + miss_pen).min(1.0);

        let signing_msg = hash_multiple(&[
            b"ego/drs/v1:",
            inputs.node_addr.as_bytes(),
            &inputs.epoch.to_le_bytes(),
            &score_u32.to_le_bytes(),
            &(multiplier_fp16 as u32).to_le_bytes(),
        ]);
        let scorer_sig = keypair.sign(signing_msg.as_bytes());

        let event = DRSScoreEvent {
            event_id,
            node_addr: inputs.node_addr,
            epoch: inputs.epoch,
            raw_score,
            score_u32,
            multiplier,
            multiplier_fp16,
            uptime_component,
            post_component,
            latency_component,
            poc_component,
            serve_component,
            total_penalty,
            weights_version: self.weights_version,
            params_digest: self.params_digest,
            evidence_root: inputs.evidence_root,
            computed_at: Timestamp::now(),
            scorer_sig,
        };

        info!(
            "📊 DRS epoch={} node={} score={:.4} mult={:.3} (eligible={})",
            inputs.epoch, inputs.node_addr, raw_score, multiplier, event.is_eligible()
        );

        Ok(event)
    }

    fn compute_params_digest(version: u8) -> Hash {
        hash_multiple(&[
            b"ego/drs/params/v1",
            &[version],
            &W_UPTIME.to_le_bytes(),
            &W_POST_PASS.to_le_bytes(),
            &W_INV_LATENCY.to_le_bytes(),
            &W_POC_QUALITY.to_le_bytes(),
            &W_SERVE_RATIO.to_le_bytes(),
        ])
    }
}

impl Default for DRSScorer {
    fn default() -> Self { Self::new() }
}

pub struct EpochDRSAggregator {
    epoch: u64,
    scorer: DRSScorer,
    pending_inputs: HashMap<Address, DRSInputs>,
}

impl EpochDRSAggregator {
    pub fn new(epoch: u64) -> Self {
        Self { epoch, scorer: DRSScorer::new(), pending_inputs: HashMap::new() }
    }

    pub fn ingest(&mut self, inputs: DRSInputs) {
        if inputs.epoch == self.epoch {
            self.pending_inputs.insert(inputs.node_addr, inputs);
        } else {
            warn!("DRS input epoch {} != aggregator epoch {}", inputs.epoch, self.epoch);
        }
    }

    pub fn score_all(&self, keypair: &ego_core::KeyPair) -> PoCResult<Vec<DRSScoreEvent>> {
        let mut events = Vec::with_capacity(self.pending_inputs.len());
        for inputs in self.pending_inputs.values() {
            let event = self.scorer.score_event(inputs, keypair)?;
            events.push(event);
        }

        events.sort_by_key(|e| e.node_addr.as_bytes().to_vec());
        Ok(events)
    }

    pub fn node_count(&self) -> usize { self.pending_inputs.len() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::{Address, Hash, KeyPair};

    fn perfect_inputs(addr: Address) -> DRSInputs {
        DRSInputs {
            node_addr: addr,
            epoch: 1,
            uptime_fraction: 1.0,
            post_windows_assigned: 48,
            post_windows_passed: 48,
            post_latency_p50_ms: 3_000,
            consecutive_post_misses: 0,
            avg_poc_quality: 1.0,
            poc_event_count: 10,
            data_requests_received: 100,
            data_requests_served: 100,
            equivocations: 0,
            replay_attacks: 0,
            evidence_root: Hash::new([0u8; 32]),
        }
    }

    fn zero_inputs(addr: Address) -> DRSInputs {
        DRSInputs {
            node_addr: addr,
            epoch: 1,
            uptime_fraction: 0.0,
            post_windows_assigned: 48,
            post_windows_passed: 0,
            post_latency_p50_ms: 60_001,
            consecutive_post_misses: 4,
            avg_poc_quality: 0.0,
            poc_event_count: 0,
            data_requests_received: 100,
            data_requests_served: 0,
            equivocations: 1,
            replay_attacks: 2,
            evidence_root: Hash::new([0u8; 32]),
        }
    }

    #[test]
    fn test_perfect_node_max_multiplier() {
        let scorer = DRSScorer::new();
        let addr = Address::new([1u8; 20]);
        let (score, mult) = scorer.compute(&perfect_inputs(addr));
        assert!(score > 0.99, "expected score ~1.0, got {}", score);
        assert!((mult - MULTIPLIER_MAX).abs() < 1e-9, "expected max multiplier, got {}", mult);
    }

    #[test]
    fn test_zero_node_min_multiplier() {
        let scorer = DRSScorer::new();
        let addr = Address::new([2u8; 20]);
        let (score, mult) = scorer.compute(&zero_inputs(addr));
        assert_eq!(score, 0.0, "expected score 0.0, got {}", score);
        assert!((mult - MULTIPLIER_MIN).abs() < 1e-9, "expected min multiplier, got {}", mult);
    }

    #[test]
    fn test_neutral_score_neutral_multiplier() {
        let scorer = DRSScorer::new();

        let addr = Address::new([3u8; 20]);
        let inputs = DRSInputs {
            node_addr: addr,
            epoch: 1,
            uptime_fraction: 0.5,
            post_windows_assigned: 48,
            post_windows_passed: 24,
            post_latency_p50_ms: 32_500,
            consecutive_post_misses: 0,
            avg_poc_quality: 0.5,
            poc_event_count: 5,
            data_requests_received: 100,
            data_requests_served: 50,
            equivocations: 0,
            replay_attacks: 0,
            evidence_root: Hash::new([0u8; 32]),
        };
        let (score, mult) = scorer.compute(&inputs);

        assert!((score - 0.5).abs() < 0.1, "score={}", score);
        assert!((mult - 1.0).abs() < 0.1, "mult={}", mult);
    }

    #[test]
    fn test_equivocation_penalty() {
        let scorer = DRSScorer::new();
        let addr = Address::new([4u8; 20]);
        let (score_clean, _) = scorer.compute(&perfect_inputs(addr));
        let mut inputs = perfect_inputs(addr);
        inputs.equivocations = 1;
        let (score_penalised, _) = scorer.compute(&inputs);
        assert!(score_penalised < score_clean - 0.25, "equivocation should drop score by ~0.30");
    }

    #[test]
    fn test_no_poc_events_zeroes_poc_component() {
        let scorer = DRSScorer::new();
        let addr = Address::new([5u8; 20]);
        let mut inputs = perfect_inputs(addr);
        inputs.poc_event_count = 0;
        let (score, _) = scorer.compute(&inputs);

        assert!((score - 0.80).abs() < 0.01, "score={}", score);
    }

    #[test]
    fn test_score_event_determinism() {
        let scorer = DRSScorer::new();
        let kp = KeyPair::generate();
        let addr = Address::from_public_key(&kp.public_key());
        let inputs = perfect_inputs(addr);
        let e1 = scorer.score_event(&inputs, &kp).unwrap();
        let e2 = scorer.score_event(&inputs, &kp).unwrap();
        assert_eq!(e1.score_u32, e2.score_u32);
        assert_eq!(e1.multiplier_fp16, e2.multiplier_fp16);
    }

    #[test]
    fn test_epoch_aggregator() {
        let kp = KeyPair::generate();
        let mut agg = EpochDRSAggregator::new(1);
        for i in 0..5u8 {
            let addr = Address::new([i; 20]);
            agg.ingest(perfect_inputs(addr));
        }
        assert_eq!(agg.node_count(), 5);
        let events = agg.score_all(&kp).unwrap();
        assert_eq!(events.len(), 5);

        assert!(events.iter().all(|e| e.is_eligible()));

        let addrs: Vec<_> = events.iter().map(|e| e.node_addr).collect();
        let mut sorted = addrs.clone();
        sorted.sort_by_key(|a| a.as_bytes().to_vec());
        assert_eq!(addrs, sorted);
    }

    #[test]
    fn test_weights_sum_to_one() {
        let sum = W_UPTIME + W_POST_PASS + W_INV_LATENCY + W_POC_QUALITY + W_SERVE_RATIO;
        assert!((sum - 1.0).abs() < 1e-10, "weights must sum to 1.0, got {}", sum);
    }
}
