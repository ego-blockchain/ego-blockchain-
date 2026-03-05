// consensus/engine.rs
//
// Wires BFT engine and DRS scorer.
// Method signatures match the actual bft.rs and drs.rs in this repo.

use crate::aggregator::PoCEvent;
use crate::challenge::{ChallengeService, ChallengeConfig};
use crate::config::epoch::EpochConfig;
use crate::consensus::bft::{BftEngine, BlockHeader, BlockRoots, QuorumCertificate, Vote};
use crate::consensus::drs::{DRSInputs, DRSScoreEvent, DRSScorer};
use crate::config::ValidationConfig;
use crate::error::PoCResult;
use ego_core::{Address, Hash, KeyPair, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

/// Engine-local validation result.
/// (validation::ValidationResult is a type alias for Result<(), ValidationError> — not a struct)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventValidationResult {
    pub event_hash: Hash,
    pub is_valid: bool,
    pub confidence: f64,
    pub validator_votes: HashMap<Address, bool>,
    pub fraud_indicators: Vec<String>,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    pub validation_config: ValidationConfig,
    pub min_consensus_threshold: f64,
    pub max_validation_time_ms: u64,
    pub fraud_detection_enabled: bool,
    pub batch_validation_size: usize,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            validation_config: ValidationConfig::default(),
            min_consensus_threshold: 0.67,
            max_validation_time_ms: 30_000,
            fraud_detection_enabled: true,
            batch_validation_size: 100,
        }
    }
}

pub struct ConsensusEngine {
    config: ConsensusConfig,
    validators: Vec<Address>,
    pending_events: RwLock<VecDeque<PoCEvent>>,
    /// DRS scorer — stateless, holds only weights version + params digest
    drs_scorer: DRSScorer,
    /// Keypair used by the DRS scorer to sign score events
    scorer_keypair: KeyPair,
    bft: BftEngine,
    validated_events: RwLock<HashMap<Hash, EventValidationResult>>,
    /// Latest DRS score per node — keyed by node_addr
    drs_scores: RwLock<HashMap<Address, DRSScoreEvent>>,
    /// Epoch-based configuration for dynamic thresholds
    epoch_config: EpochConfig,
    /// Challenge generation service
    challenge_service: Option<ChallengeService>,
    /// Block finalization event sender for challenge generation
    block_finalization_sender: Option<mpsc::UnboundedSender<(BlockHeader, QuorumCertificate)>>,
}

impl ConsensusEngine {
    pub fn new(config: ConsensusConfig, validators: Vec<Address>, keypair: KeyPair) -> Self {
        // DRSScorer::new() takes no args
        let drs_scorer = DRSScorer::new();
        // Keep a separate keypair for signing score events
        let scorer_keypair = KeyPair::generate();
        let bft = BftEngine::new(keypair, validators.clone());

        Self {
            config,
            validators,
            pending_events: RwLock::new(VecDeque::new()),
            drs_scorer,
            scorer_keypair,
            bft,
            validated_events: RwLock::new(HashMap::new()),
            drs_scores: RwLock::new(HashMap::new()),
            epoch_config: EpochConfig::new(),
            challenge_service: None,
            block_finalization_sender: None,
        }
    }

    pub fn new_observer(config: ConsensusConfig, validators: Vec<Address>) -> Self {
        Self::new(config, validators, KeyPair::generate())
    }

    pub async fn submit_event(&self, event: PoCEvent) -> PoCResult<()> {
        self.pending_events.write().await.push_back(event);
        Ok(())
    }

    pub async fn validate_events(&self) -> PoCResult<Vec<EventValidationResult>> {
        let mut pending = self.pending_events.write().await;
        let mut results = Vec::new();

        while let Some(event) = pending.pop_front() {
            let result = self.validate_single_event(&event).await?;
            results.push(result.clone());
            self.validated_events.write().await.insert(event.beacon_hash, result);
        }

        Ok(results)
    }

    async fn validate_single_event(&self, event: &PoCEvent) -> PoCResult<EventValidationResult> {
        debug!("Validating PoC event for beacon {}", event.beacon_hash);

        let mut validator_votes = HashMap::new();
        let mut fraud_indicators = Vec::new();

        for validator in &self.validators {
            let vote = self.drs_weighted_vote(event, validator).await;
            validator_votes.insert(*validator, vote);
        }

        let positive = validator_votes.values().filter(|&&v| v).count();
        let confidence = if self.validators.is_empty() {
            0.0
        } else {
            positive as f64 / self.validators.len() as f64
        };
        let is_valid = confidence >= self.config.min_consensus_threshold;

        // Use epoch-based thresholds for validation
        let current_epoch = Timestamp::now().as_secs() / 3600;
        let thresholds = self.epoch_config.get_config(current_epoch);

        if !is_valid { fraud_indicators.push("Consensus threshold not met".to_string()); }
        if event.quality_score < thresholds.quality_thresholds.min_quality_score {
            fraud_indicators.push("Low quality score".to_string());
        }
        if event.path_loss_rmse > thresholds.quality_thresholds.max_path_loss_rmse {
            fraud_indicators.push("High path-loss RMSE".to_string());
        }
        if event.nonce_binding_fraction < thresholds.quality_thresholds.min_nonce_binding_fraction {
            fraud_indicators.push("Insufficient nonce binding".to_string());
        }

        Ok(EventValidationResult {
            event_hash: event.beacon_hash,
            is_valid,
            confidence,
            validator_votes,
            fraud_indicators,
            timestamp: Timestamp::now(),
        })
    }

    /// DRS-aware vote — uses cached raw_score (f64 field on DRSScoreEvent).
    async fn drs_weighted_vote(&self, event: &PoCEvent, validator: &Address) -> bool {
        // Get epoch-based thresholds
        let current_epoch = Timestamp::now().as_secs() / 3600;
        let thresholds = self.epoch_config.get_config(current_epoch);

        let threshold = {
            let scores = self.drs_scores.read().await;
            scores.get(validator)
                .map(|s| s.raw_score * thresholds.consensus_thresholds.drs_vote_multiplier)
                .unwrap_or(0.42)
        };

        let mut score = event.quality_score;
        if event.path_loss_rmse > thresholds.quality_thresholds.max_path_loss_rmse {
            score *= 0.7;
        }
        if event.nonce_binding_fraction < thresholds.quality_thresholds.min_nonce_binding_fraction {
            score *= 0.8;
        }
        if event.witness_hashes.len() < thresholds.consensus_thresholds.min_witness_count {
            score *= 0.7;
        }

        if event.epoch + 24 < current_epoch  { score *= 0.3; }

        score >= threshold
    }

    /// Cache an externally-produced DRS score event.
    pub async fn update_drs_score(&self, event: DRSScoreEvent) {
        // node_addr is the correct field name (not node_id)
        self.drs_scores.write().await.insert(event.node_addr, event);
    }

    /// Score a batch of nodes for one epoch.
    /// DRSScorer::score_event takes (&DRSInputs, &KeyPair) — node_addr and epoch
    /// are embedded in DRSInputs, not separate args.
    pub async fn score_epoch(
        &self,
        inputs_batch: Vec<DRSInputs>,
    ) -> PoCResult<Vec<DRSScoreEvent>> {
        let mut events = Vec::with_capacity(inputs_batch.len());
        let mut scores = self.drs_scores.write().await;

        for inputs in inputs_batch {
            let event = self.drs_scorer.score_event(&inputs, &self.scorer_keypair)?;
            scores.insert(event.node_addr, event.clone());
            events.push(event);
        }

        Ok(events)
    }

    /// Propose a block — sync, takes only roots (BftEngine manages height/epoch internally).
    pub fn propose_block(&self, roots: BlockRoots) -> PoCResult<BlockHeader> {
        self.bft.propose_block(roots)
    }

    /// Process an incoming proposal — returns a Vote if this node accepts it.
    pub fn receive_proposal(&self, header: &BlockHeader) -> PoCResult<Option<Vote>> {
        self.bft.receive_proposal(header)
    }

    /// Receive a vote — sync, takes &Vote.
    pub fn receive_vote(&self, vote: &Vote) -> PoCResult<Option<QuorumCertificate>> {
        self.bft.receive_vote(vote)
    }

    /// Commit a finalized block (was commit_block — actual method is finalize_block).
    pub fn finalize_block(&self, header: BlockHeader, qc: QuorumCertificate) -> PoCResult<()> {
        // Finalize block in BFT engine
        self.bft.finalize_block(header.clone(), qc.clone())?;

        // Emit block finalization event for challenge generation
        if let Some(ref sender) = self.block_finalization_sender {
            if let Err(e) = sender.send((header.clone(), qc)) {
                warn!("Failed to send block finalization event for challenge generation: {}", e);
            } else {
                debug!("Emitted block finalization event for challenge generation: height={}, epoch={}",
                       header.height, header.epoch);
            }
        }

        Ok(())
    }

    /// VRF output for beacon challenge randomness.
    pub fn get_vrf_output(&self, epoch: u64) -> Option<Hash> {
        self.bft.get_vrf_output(epoch)
    }

    pub fn get_current_height(&self) -> u64 { self.bft.get_current_height() }
    pub fn get_current_epoch(&self) -> u64   { self.bft.get_current_epoch() }

    /// Update epoch configuration with new thresholds
    pub fn update_epoch_config(&mut self, config: EpochConfig) {
        self.epoch_config = config;
    }

    /// Get current epoch configuration
    pub fn get_epoch_config(&self) -> &EpochConfig {
        &self.epoch_config
    }

    /// Enable challenge generation from finalized blocks
    pub async fn enable_challenge_generation(&mut self, challenge_config: ChallengeConfig) -> PoCResult<()> {
        let (block_sender, block_receiver) = mpsc::unbounded_channel();
        let mut challenge_service = ChallengeService::new(challenge_config);

        // Start the challenge service
        challenge_service.start(block_receiver).await?;

        self.challenge_service = Some(challenge_service);
        self.block_finalization_sender = Some(block_sender);

        info!("✅ Challenge generation enabled from finalized blocks");
        Ok(())
    }

    /// Subscribe a beacon node to receive challenges for specific regions
    pub fn subscribe_to_challenges(
        &mut self,
        node_id: Address,
        regions: Vec<String>
    ) -> Option<mpsc::UnboundedReceiver<crate::types::Challenge>> {
        if let Some(ref mut challenge_service) = self.challenge_service {
            Some(challenge_service.subscribe_node(node_id, regions))
        } else {
            warn!("Challenge generation not enabled - call enable_challenge_generation() first");
            None
        }
    }

    /// Update regional beacon mapping for challenge generation
    pub fn update_region_beacons(&self, region_id: String, beacons: Vec<Address>) {
        if let Some(ref challenge_service) = self.challenge_service {
            challenge_service.update_region_beacons(region_id, beacons);
        }
    }

    /// Get challenge generation statistics
    pub fn get_challenge_stats(&self) -> Option<crate::challenge::GeneratorStats> {
        self.challenge_service.as_ref().map(|service| service.get_stats())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::{Hash, Address, Timestamp, Signature};

    fn make_engine() -> ConsensusEngine {
        ConsensusEngine::new(
            ConsensusConfig::default(),
            vec![Address::new([1u8; 20]), Address::new([2u8; 20]), Address::new([3u8; 20])],
            KeyPair::generate(),
        )
    }

    #[tokio::test]
    async fn test_event_validation() {
        let engine = make_engine();
        let event = PoCEvent {
            beacon_hash: Hash::new([1u8; 32]),
            witness_hashes: vec![Hash::new([2u8; 32]), Hash::new([3u8; 32]), Hash::new([4u8; 32])],
            agg_digest: Hash::new([5u8; 32]),
            quality_score: 0.85,
            region: "872834".to_string(),
            epoch: Timestamp::now().as_secs() / 3600,
            cid_hint: None,
            timestamp: Timestamp::now(),
            aggregator_signature: Signature::ed25519([0u8; 64]),
            path_loss_rmse: 8.0,
            diversity_score: 0.9,
            nonce_binding_fraction: 0.75,
            ldm_penalty: 0.0,
        };

        engine.submit_event(event).await.unwrap();
        let results = engine.validate_events().await.unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn test_drs_score_epoch() {
        let engine = make_engine();
        let node = Address::new([7u8; 20]);

        let inputs = DRSInputs {
            node_addr: node,
            epoch: 1,
            uptime_fraction: 1.0,
            post_windows_assigned: 48,
            post_windows_passed: 48,
            post_latency_p50_ms: 3_000,
            consecutive_post_misses: 0,
            avg_poc_quality: 0.9,
            poc_event_count: 10,
            data_requests_received: 100,
            data_requests_served: 98,
            equivocations: 0,
            replay_attacks: 0,
            evidence_root: Hash::new([0u8; 32]),
        };

        let events = engine.score_epoch(vec![inputs]).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].node_addr, node);
        assert!(events[0].raw_score > 0.9);

        let cached = engine.drs_scores.read().await;
        assert!(cached.contains_key(&node));
    }
}