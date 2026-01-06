use crate::error::PoCResult;
use ego_core::{Address, Hash, Signature, Timestamp};
use serde::{Deserialize, Serialize};
use std::future::Future;

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct SlashEvent {
    pub event_id: Hash,
    pub slashed_node: Address,
    pub slasher: Address,
    pub slash_type: SlashType,
    pub evidence_hash: Hash,
    pub slash_amount: u128,
    pub reason: String,
    pub confidence: f64,
    pub timestamp: Timestamp,
    pub signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub enum SlashType {
    StorageFailure,
    ProofFailure,
    FraudDetected,
    NodeOffline,
    DataCorruption,
    ConsensusViolation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingRule {
    pub rule_id: Hash,
    pub slash_type: SlashType,
    pub threshold: f64,
    pub base_slash_amount: u128,
    pub multiplier: f64,
    pub cooldown_period_hours: u64,
    pub max_slash_per_day: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingMetrics {
    pub total_slashes: u64,
    pub total_slashed_amount: u128,
    pub false_positive_rate: f64,
    pub avg_evidence_confidence: f64,
    pub slashes_by_type: std::collections::HashMap<String, u64>,
    pub last_updated: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutReceipt {
    pub receipt_id: Hash,
    pub recipient: Address,
    pub amount: u128,
    pub payout_type: PayoutType,
    pub epoch: u64,
    pub deals_covered: Vec<Hash>,
    pub proof_quality_score: f64,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PayoutType {
    StorageReward,
    ProvingReward,
    RepairReward,
    WhistleblowerReward,
    ConsensusReward,
}

pub trait SlashingManager: Send + Sync {
    fn manager_id(&self) -> Address;

    fn propose_slash(
        &mut self,
        slashed_node: Address,
        slash_type: SlashType,
        evidence: Vec<u8>,
        confidence: f64,
    ) -> impl Future<Output = PoCResult<Hash>> + Send;

    fn execute_slash(
        &mut self,
        slash_id: Hash,
    ) -> impl Future<Output = PoCResult<SlashEvent>> + Send;

    fn calculate_payout(
        &self,
        recipient: Address,
        epoch: u64,
    ) -> impl Future<Output = PoCResult<PayoutReceipt>> + Send;

    fn validate_evidence(
        &self,
        evidence: &[u8],
        slash_type: &SlashType,
    ) -> impl Future<Output = PoCResult<f64>> + Send;

    fn get_slashing_history(&self, node: Address) -> Vec<SlashEvent>;
}

impl SlashEvent {
    pub fn new(
        slashed_node: Address,
        slasher: Address,
        slash_type: SlashType,
        evidence_hash: Hash,
        slash_amount: u128,
        reason: String,
        confidence: f64,
    ) -> Self {
        let event_id = Self::compute_event_id(slashed_node, slasher, &slash_type);

        Self {
            event_id,
            slashed_node,
            slasher,
            slash_type,
            evidence_hash,
            slash_amount,
            reason,
            confidence,
            timestamp: Timestamp::now(),
            signature: Signature::ed25519([0u8; 64]),
        }
    }

    pub fn validate(&self) -> PoCResult<()> {
        if self.slashed_node == self.slasher {
            return Err(crate::error::PoCError::ValidationFailed(
                "Cannot slash self".to_string(),
            ));
        }

        if self.slash_amount == 0 {
            return Err(crate::error::PoCError::ValidationFailed(
                "Slash amount cannot be zero".to_string(),
            ));
        }

        if self.confidence < 0.8 {
            return Err(crate::error::PoCError::ValidationFailed(
                "Insufficient confidence for slashing".to_string(),
            ));
        }

        Ok(())
    }

    fn compute_event_id(slashed_node: Address, slasher: Address, slash_type: &SlashType) -> Hash {
        use ego_core::crypto::hash_multiple;

        let slash_type_bytes = format!("{:?}", slash_type).into_bytes();

        hash_multiple(&[
            slashed_node.as_bytes(),
            slasher.as_bytes(),
            &slash_type_bytes,
            &Timestamp::now().as_millis().to_le_bytes(),
        ])
    }

    fn compute_evidence_hash(event_id: &Hash, success: bool) -> Hash {
        use ego_core::crypto::hash_multiple;

        hash_multiple(&[event_id.as_bytes(), &[if success { 1u8 } else { 0u8 }]])
    }
}

impl SlashingRule {
    pub fn new(
        slash_type: SlashType,
        threshold: f64,
        base_slash_amount: u128,
        multiplier: f64,
    ) -> Self {
        let rule_id = Self::compute_rule_id(&slash_type);

        Self {
            rule_id,
            slash_type,
            threshold,
            base_slash_amount,
            multiplier,
            cooldown_period_hours: 24,
            max_slash_per_day: base_slash_amount * 3,
        }
    }

    pub fn calculate_slash_amount(&self, confidence: f64, severity: f64) -> u128 {
        if confidence < self.threshold {
            return 0;
        }

        let adjusted_amount =
            (self.base_slash_amount as f64 * self.multiplier * confidence * severity) as u128;
        adjusted_amount.min(self.max_slash_per_day)
    }

    fn compute_rule_id(slash_type: &SlashType) -> Hash {
        use ego_core::crypto::hash_data;

        let slash_type_bytes = format!("{:?}", slash_type).into_bytes();
        hash_data(&slash_type_bytes)
    }
}

impl PayoutReceipt {
    pub fn new(
        recipient: Address,
        amount: u128,
        payout_type: PayoutType,
        epoch: u64,
        deals_covered: Vec<Hash>,
        proof_quality_score: f64,
    ) -> Self {
        let receipt_id = Self::compute_receipt_id(recipient, amount, epoch);

        Self {
            receipt_id,
            recipient,
            amount,
            payout_type,
            epoch,
            deals_covered,
            proof_quality_score,
            timestamp: Timestamp::now(),
        }
    }

    pub fn validate(&self) -> PoCResult<()> {
        if self.amount == 0 {
            return Err(crate::error::PoCError::ValidationFailed(
                "Payout amount cannot be zero".to_string(),
            ));
        }

        if self.proof_quality_score < 0.0 || self.proof_quality_score > 1.0 {
            return Err(crate::error::PoCError::ValidationFailed(
                "Invalid proof quality score".to_string(),
            ));
        }

        Ok(())
    }

    fn compute_receipt_id(recipient: Address, amount: u128, epoch: u64) -> Hash {
        use ego_core::crypto::hash_multiple;

        hash_multiple(&[
            recipient.as_bytes(),
            &amount.to_le_bytes(),
            &epoch.to_le_bytes(),
            &Timestamp::now().as_millis().to_le_bytes(),
        ])
    }
}

impl Default for SlashingMetrics {
    fn default() -> Self {
        Self {
            total_slashes: 0,
            total_slashed_amount: 0,
            false_positive_rate: 0.0,
            avg_evidence_confidence: 0.0,
            slashes_by_type: std::collections::HashMap::new(),
            last_updated: Timestamp::now(),
        }
    }
}

impl PartialEq for SlashEvent {
    fn eq(&self, other: &Self) -> bool {
        self.event_id == other.event_id
            && self.slashed_node == other.slashed_node
            && self.slasher == other.slasher
    }
}

impl Eq for SlashEvent {}

impl PartialEq for SlashType {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (SlashType::StorageFailure, SlashType::StorageFailure) => true,
            (SlashType::ProofFailure, SlashType::ProofFailure) => true,
            (SlashType::FraudDetected, SlashType::FraudDetected) => true,
            (SlashType::NodeOffline, SlashType::NodeOffline) => true,
            (SlashType::DataCorruption, SlashType::DataCorruption) => true,
            (SlashType::ConsensusViolation, SlashType::ConsensusViolation) => true,
            _ => false,
        }
    }
}

impl Eq for SlashType {}

impl PartialEq for PayoutType {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (PayoutType::StorageReward, PayoutType::StorageReward) => true,
            (PayoutType::ProvingReward, PayoutType::ProvingReward) => true,
            (PayoutType::RepairReward, PayoutType::RepairReward) => true,
            (PayoutType::WhistleblowerReward, PayoutType::WhistleblowerReward) => true,
            (PayoutType::ConsensusReward, PayoutType::ConsensusReward) => true,
            _ => false,
        }
    }
}

impl Eq for PayoutType {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slash_event_creation() {
        let event = SlashEvent::new(
            Address::new([1u8; 20]),
            Address::new([2u8; 20]),
            SlashType::StorageFailure,
            Hash::new([3u8; 32]),
            1000,
            "Storage proof failed".to_string(),
            0.95,
        );

        assert_eq!(event.slashed_node, Address::new([1u8; 20]));
        assert_eq!(event.slash_amount, 1000);
        assert!(event.validate().is_ok());
    }

    #[test]
    fn test_slashing_rule() {
        let rule = SlashingRule::new(SlashType::ProofFailure, 0.8, 1000, 1.5);

        let amount1 = rule.calculate_slash_amount(0.9, 1.0);
        assert!(amount1 > 0);

        let amount2 = rule.calculate_slash_amount(0.7, 1.0);
        assert_eq!(amount2, 0);

        let amount3 = rule.calculate_slash_amount(0.95, 2.0);
        assert!(amount3 > amount1);
    }

    #[test]
    fn test_payout_receipt() {
        let receipt = PayoutReceipt::new(
            Address::new([1u8; 20]),
            5000,
            PayoutType::StorageReward,
            100,
            vec![Hash::new([2u8; 32])],
            0.92,
        );

        assert_eq!(receipt.amount, 5000);
        assert_eq!(receipt.epoch, 100);
        assert!(receipt.validate().is_ok());
    }
}
