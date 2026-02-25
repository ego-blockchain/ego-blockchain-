// slashing/engine.rs — Evidence-based slashing execution
//
// Connects fraud evidence (from aggregator/beacon layers) to SlashEvent
// and RepairEvent emission.  Works with the existing slashing/mod.rs types.
//
// Whitepaper §7 — slash conditions, cooldown periods, whistleblower rewards

use crate::error::{PoCError, PoCResult};
use crate::slashing::{PayoutReceipt, PayoutType, SlashEvent, SlashType, SlashingMetrics, SlashingRule};
use crate::repair::{RepairEvent, RepairJob, RepairPriority, RepairType};
use ego_core::{Address, Hash, KeyPair, Timestamp};
use ego_core::crypto::hash_multiple;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{debug, info, warn};

// ── Evidence types ────────────────────────────────────────────────────────────

/// Unified fraud / failure evidence fed to the slashing engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashEvidence {
    pub evidence_id: Hash,
    pub accused: Address,
    pub reporter: Address,
    pub evidence_type: EvidenceType,
    /// Serialised proof bytes (PoC fraud proof, PoSt miss record, etc.)
    pub proof_bytes: Vec<u8>,
    /// Confidence level from the source module (0.0–1.0)
    pub confidence: f64,
    /// Epoch in which the infraction occurred
    pub epoch: u64,
    /// Affected sector/deal IDs, if applicable
    pub affected_sectors: Vec<u64>,
    pub submitted_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceType {
    /// PoC fraud: invalid geometry, replay, insufficient diversity
    PoCFraud,
    /// PoSt consecutive misses beyond threshold
    StorageFailure,
    /// PoRep proof verification failure
    ProofFailure,
    /// Node offline for too long
    NodeOffline,
    /// On-chain data corruption detected
    DataCorruption,
    /// BFT equivocation (double-vote)
    ConsensusViolation,
}

impl EvidenceType {
    pub fn to_slash_type(&self) -> SlashType {
        match self {
            EvidenceType::PoCFraud           => SlashType::FraudDetected,
            EvidenceType::StorageFailure      => SlashType::StorageFailure,
            EvidenceType::ProofFailure        => SlashType::ProofFailure,
            EvidenceType::NodeOffline         => SlashType::NodeOffline,
            EvidenceType::DataCorruption      => SlashType::DataCorruption,
            EvidenceType::ConsensusViolation  => SlashType::ConsensusViolation,
        }
    }
    pub fn needs_repair(&self) -> bool {
        matches!(self, EvidenceType::StorageFailure | EvidenceType::DataCorruption | EvidenceType::NodeOffline)
    }
}

// ── Pending slash proposal ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PendingSlash {
    pub slash_id: Hash,
    pub evidence: SlashEvidence,
    pub proposed_amount: u128,
    pub proposed_at: Timestamp,
    pub status: PendingSlashStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingSlashStatus {
    Pending,
    Approved,
    Rejected,
    Executed,
    Expired,
}

// ── Engine ────────────────────────────────────────────────────────────────────

pub struct SlashingEngine {
    keypair: Arc<KeyPair>,
    manager_addr: Address,
    rules: HashMap<String, SlashingRule>,
    pending_slashes: Arc<RwLock<HashMap<Hash, PendingSlash>>>,
    slash_history: Arc<RwLock<HashMap<Address, Vec<SlashEvent>>>>,
    repair_queue: Arc<RwLock<Vec<RepairJob>>>,
    metrics: Arc<RwLock<SlashingMetrics>>,
    /// Cooldown tracking: last slash time per (node, slash_type)
    cooldowns: Arc<RwLock<HashMap<(Address, String), Timestamp>>>,
}

impl SlashingEngine {
    pub fn new(keypair: KeyPair) -> Self {
        let manager_addr = Address::from_public_key(&keypair.public_key());
        let rules = Self::default_rules();
        Self {
            keypair: Arc::new(keypair),
            manager_addr,
            rules,
            pending_slashes: Arc::new(RwLock::new(HashMap::new())),
            slash_history: Arc::new(RwLock::new(HashMap::new())),
            repair_queue: Arc::new(RwLock::new(Vec::new())),
            metrics: Arc::new(RwLock::new(SlashingMetrics::default())),
            cooldowns: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Validate evidence and queue a slash proposal.
    /// Returns None if confidence is below threshold or cooldown is active.
    pub fn propose_slash(&self, evidence: SlashEvidence) -> PoCResult<Option<Hash>> {
        // Minimum confidence gate
        if evidence.confidence < 0.8 {
            debug!("Evidence confidence {:.2} below 0.80 threshold, skipping", evidence.confidence);
            return Ok(None);
        }

        let slash_type = evidence.evidence_type.to_slash_type();
        let type_key = format!("{:?}", slash_type);

        // Cooldown check
        if self.is_in_cooldown(&evidence.accused, &type_key) {
            debug!("Node {} in cooldown for {:?}", evidence.accused, slash_type);
            return Ok(None);
        }

        let rule = self.rules.get(&type_key)
            .cloned()
            .unwrap_or_else(|| SlashingRule::new(slash_type.clone(), 0.8, 500, 1.0));

        let proposed_amount = rule.calculate_slash_amount(evidence.confidence, 1.0);
        if proposed_amount == 0 {
            return Ok(None);
        }

        let slash_id = hash_multiple(&[
            evidence.accused.as_bytes(),
            evidence.evidence_id.as_bytes(),
            &evidence.epoch.to_le_bytes(),
        ]);

        let pending = PendingSlash {
            slash_id,
            evidence: evidence.clone(),
            proposed_amount,
            proposed_at: Timestamp::now(),
            status: PendingSlashStatus::Pending,
        };

        self.pending_slashes.write().unwrap().insert(slash_id, pending);

        info!("⚠️  Slash proposed {} for {} (amount={} confidence={:.2})",
            slash_id, evidence.accused, proposed_amount, evidence.confidence);

        Ok(Some(slash_id))
    }

    /// Execute an approved pending slash, emit SlashEvent and optional RepairEvent.
    pub fn execute_slash(&self, slash_id: Hash) -> PoCResult<(SlashEvent, Option<RepairJob>)> {
        let pending = {
            let mut slashes = self.pending_slashes.write().unwrap();
            let p = slashes.get_mut(&slash_id)
                .ok_or_else(|| PoCError::ValidationFailed(format!("Slash {} not found", slash_id)))?;
            if p.status != PendingSlashStatus::Pending {
                return Err(PoCError::ValidationFailed(format!("Slash {} not in Pending state", slash_id)));
            }
            p.status = PendingSlashStatus::Executed;
            p.clone()
        };

        let slash_type = pending.evidence.evidence_type.to_slash_type();
        let evidence_hash = pending.evidence.evidence_id;

        let slash_event = SlashEvent::new(
            pending.evidence.accused,
            self.manager_addr,
            slash_type.clone(),
            evidence_hash,
            pending.proposed_amount,
            format!("Epoch {} | {:?}", pending.evidence.epoch, pending.evidence.evidence_type),
            pending.evidence.confidence,
        );

        // Update cooldown
        {
            let key = (pending.evidence.accused, format!("{:?}", slash_type));
            self.cooldowns.write().unwrap().insert(key, Timestamp::now());
        }

        // Record in history
        {
            let mut history = self.slash_history.write().unwrap();
            history.entry(pending.evidence.accused).or_default().push(slash_event.clone());
        }

        // Update metrics
        {
            let mut m = self.metrics.write().unwrap();
            m.total_slashes += 1;
            m.total_slashed_amount += pending.proposed_amount;
            *m.slashes_by_type.entry(format!("{:?}", slash_event.slash_type)).or_insert(0) += 1;
            m.avg_evidence_confidence = (m.avg_evidence_confidence * (m.total_slashes - 1) as f64
                + pending.evidence.confidence) / m.total_slashes as f64;
            m.last_updated = Timestamp::now();
        }

        // Schedule repair if needed
        let repair_job = if pending.evidence.evidence_type.needs_repair() && !pending.evidence.affected_sectors.is_empty() {
            let priority = match pending.evidence.evidence_type {
                EvidenceType::DataCorruption   => RepairPriority::Critical,
                EvidenceType::StorageFailure   => RepairPriority::High,
                _                              => RepairPriority::Normal,
            };
            let job = RepairJob::new(pending.evidence.accused, pending.evidence.affected_sectors.clone(), priority);
            self.repair_queue.write().unwrap().push(job.clone());
            Some(job)
        } else {
            None
        };

        info!("✅ Slash executed {} node={} amount={}", slash_id, pending.evidence.accused, pending.proposed_amount);

        Ok((slash_event, repair_job))
    }

    /// Process a PoC fraud proof directly — propose + auto-execute if confidence ≥ 0.95.
    pub fn process_poc_fraud(
        &self,
        accused: Address,
        reporter: Address,
        fraud_proof_hash: Hash,
        confidence: f64,
        epoch: u64,
    ) -> PoCResult<Option<SlashEvent>> {
        let evidence = SlashEvidence {
            evidence_id: fraud_proof_hash,
            accused,
            reporter,
            evidence_type: EvidenceType::PoCFraud,
            proof_bytes: fraud_proof_hash.as_bytes().to_vec(),
            confidence,
            epoch,
            affected_sectors: vec![],
            submitted_at: Timestamp::now(),
        };

        if let Some(slash_id) = self.propose_slash(evidence)? {
            if confidence >= 0.95 {
                // Auto-execute high-confidence PoC fraud
                let (event, _) = self.execute_slash(slash_id)?;
                return Ok(Some(event));
            }
        }
        Ok(None)
    }

    /// Process consecutive PoSt misses — auto-execute if misses ≥ threshold.
    pub fn process_post_failure(
        &self,
        node: Address,
        sector_ids: Vec<u64>,
        consecutive_misses: u32,
        epoch: u64,
    ) -> PoCResult<Option<(SlashEvent, Option<RepairJob>)>> {
        if consecutive_misses < 3 {
            return Ok(None);
        }

        let confidence = (0.70 + (consecutive_misses as f64 - 3.0) * 0.05).min(0.99);
        let evidence_id = hash_multiple(&[
            node.as_bytes(),
            &epoch.to_le_bytes(),
            &consecutive_misses.to_le_bytes(),
        ]);

        let evidence = SlashEvidence {
            evidence_id,
            accused: node,
            reporter: self.manager_addr,
            evidence_type: EvidenceType::StorageFailure,
            proof_bytes: evidence_id.as_bytes().to_vec(),
            confidence,
            epoch,
            affected_sectors: sector_ids,
            submitted_at: Timestamp::now(),
        };

        if let Some(slash_id) = self.propose_slash(evidence)? {
            let result = self.execute_slash(slash_id)?;
            return Ok(Some(result));
        }
        Ok(None)
    }

    /// Calculate payout receipt for a node in a given epoch.
    pub fn calculate_payout(&self, recipient: Address, epoch: u64, proof_quality: f64) -> PayoutReceipt {
        // Base reward: 1000 EGOC micro-units × quality score (stub — real impl queries deal table)
        let base_amount = 1_000u128;
        let amount = (base_amount as f64 * proof_quality).max(0.0) as u128;

        PayoutReceipt::new(
            recipient,
            amount,
            PayoutType::StorageReward,
            epoch,
            vec![],
            proof_quality,
        )
    }

    pub fn get_slash_history(&self, node: Address) -> Vec<SlashEvent> {
        self.slash_history.read().unwrap().get(&node).cloned().unwrap_or_default()
    }

    pub fn get_metrics(&self) -> SlashingMetrics {
        self.metrics.read().unwrap().clone()
    }

    pub fn get_repair_queue(&self) -> Vec<RepairJob> {
        self.repair_queue.read().unwrap().clone()
    }

    pub fn pending_slash_count(&self) -> usize {
        self.pending_slashes.read().unwrap().len()
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn is_in_cooldown(&self, node: &Address, type_key: &str) -> bool {
        let cooldowns = self.cooldowns.read().unwrap();
        if let Some(last) = cooldowns.get(&(*node, type_key.to_string())) {
            let rule = self.rules.get(type_key);
            let cooldown_ms = rule.map(|r| r.cooldown_period_hours * 3_600_000).unwrap_or(86_400_000);
            let elapsed = Timestamp::now().as_millis().saturating_sub(last.as_millis());
            return elapsed < cooldown_ms;
        }
        false
    }

    fn default_rules() -> HashMap<String, SlashingRule> {
        let mut rules = HashMap::new();
        let entries = [
            (SlashType::FraudDetected,      0.90, 2_000u128, 2.0),
            (SlashType::StorageFailure,     0.80, 500,       1.5),
            (SlashType::ProofFailure,       0.85, 750,       1.5),
            (SlashType::NodeOffline,        0.80, 250,       1.0),
            (SlashType::DataCorruption,     0.90, 1_500,     2.0),
            (SlashType::ConsensusViolation, 0.95, 5_000,     3.0),
        ];
        for (slash_type, threshold, base, multiplier) in entries {
            let key = format!("{:?}", slash_type);
            rules.insert(key, SlashingRule::new(slash_type, threshold, base, multiplier));
        }
        rules
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::{Address, Hash, KeyPair};

    fn make_engine() -> SlashingEngine {
        SlashingEngine::new(KeyPair::generate())
    }

    fn poc_evidence(accused: Address, reporter: Address, confidence: f64) -> SlashEvidence {
        SlashEvidence {
            evidence_id: Hash::new([1u8; 32]),
            accused,
            reporter,
            evidence_type: EvidenceType::PoCFraud,
            proof_bytes: vec![1, 2, 3],
            confidence,
            epoch: 1,
            affected_sectors: vec![],
            submitted_at: Timestamp::now(),
        }
    }

    #[test]
    fn test_propose_slash_high_confidence() {
        let engine = make_engine();
        let accused = Address::new([1u8; 20]);
        let reporter = Address::new([2u8; 20]);
        let evidence = poc_evidence(accused, reporter, 0.95);
        let result = engine.propose_slash(evidence).unwrap();
        assert!(result.is_some());
        assert_eq!(engine.pending_slash_count(), 1);
    }

    #[test]
    fn test_propose_slash_low_confidence_rejected() {
        let engine = make_engine();
        let accused = Address::new([1u8; 20]);
        let reporter = Address::new([2u8; 20]);
        let evidence = poc_evidence(accused, reporter, 0.50);
        let result = engine.propose_slash(evidence).unwrap();
        assert!(result.is_none());
        assert_eq!(engine.pending_slash_count(), 0);
    }

    #[test]
    fn test_execute_slash() {
        let engine = make_engine();
        let accused = Address::new([1u8; 20]);
        let reporter = Address::new([2u8; 20]);
        let evidence = poc_evidence(accused, reporter, 0.95);
        let slash_id = engine.propose_slash(evidence).unwrap().unwrap();
        let (event, _repair) = engine.execute_slash(slash_id).unwrap();
        assert_eq!(event.slashed_node, accused);
        assert!(event.slash_amount > 0);
        let history = engine.get_slash_history(accused);
        assert_eq!(history.len(), 1);
    }

    #[test]
    fn test_poc_fraud_auto_execute() {
        let engine = make_engine();
        let accused = Address::new([3u8; 20]);
        let reporter = Address::new([4u8; 20]);
        let result = engine.process_poc_fraud(accused, reporter, Hash::new([5u8; 32]), 0.97, 1).unwrap();
        assert!(result.is_some());
        let metrics = engine.get_metrics();
        assert_eq!(metrics.total_slashes, 1);
    }

    #[test]
    fn test_post_failure_below_threshold_no_slash() {
        let engine = make_engine();
        let node = Address::new([6u8; 20]);
        let result = engine.process_post_failure(node, vec![1, 2], 2, 1).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_post_failure_triggers_repair() {
        let engine = make_engine();
        let node = Address::new([7u8; 20]);
        let result = engine.process_post_failure(node, vec![1, 2, 3], 3, 1).unwrap();
        assert!(result.is_some());
        let (_slash, repair) = result.unwrap();
        assert!(repair.is_some());
        assert_eq!(engine.get_repair_queue().len(), 1);
    }

    #[test]
    fn test_execute_not_found() {
        let engine = make_engine();
        let result = engine.execute_slash(Hash::new([99u8; 32]));
        assert!(result.is_err());
    }
}