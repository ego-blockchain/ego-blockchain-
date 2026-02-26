use super::{
    PoRepEvent, PoRepFraudEvidence, PoRepFraudType, PoRepProof, PoRepVerdict, SectorCommitment,
};
use crate::error::{PoCError, PoCResult};
use ego_core::{
    Address, Balance, Hash, PublicKey, Timestamp,
    account::{SlashingEvent, SlashingType},
    block::{ProofEvent, ProofEventType},
    crypto::{hash_multiple, verify_signature},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tokio::time::{Duration, interval};
use tracing::{debug, info, warn};

pub struct PoRepVerifier {
    verifier_id: Address,
    verification_cache: Arc<RwLock<HashMap<Hash, VerificationResult>>>,
    params_registry: Arc<RwLock<HashMap<u32, VerificationParams>>>,
    known_provers: Arc<RwLock<HashMap<Address, ProverRecord>>>,
    sector_registry: Arc<RwLock<HashMap<(Address, u64), SectorCommitment>>>,
    verdict_sender: Option<mpsc::UnboundedSender<PoRepVerdict>>,
    fraud_sender: Option<mpsc::UnboundedSender<PoRepFraudEvidence>>,
    proof_event_sender: Option<mpsc::UnboundedSender<ProofEvent>>,
    slashing_sender: Option<mpsc::UnboundedSender<SlashingEvent>>,
    replay_guard: Arc<RwLock<HashMap<Hash, Timestamp>>>,
    stats: Arc<RwLock<VerifierStats>>,
}

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub proof_hash: Hash,
    pub is_valid: bool,
    pub verification_time_ms: u64,
    pub verifier_id: Address,
    pub timestamp: Timestamp,
    pub confidence: f64,
    pub fraud_detected: bool,
}

#[derive(Debug, Clone)]
pub struct VerificationParams {
    pub params_version: u32,
    pub sector_size: u64,
    pub challenge_count: u32,
    pub porep_id: [u8; 32],
    pub activation_epoch: u64,
}

#[derive(Debug, Clone)]
pub struct ProverRecord {
    pub address: Address,
    pub dilithium_pk: Vec<u8>,
    pub registered_at: Timestamp,
    pub proofs_verified: u64,
    pub proofs_valid: u64,
    pub fraud_count: u32,
    pub last_seen: Timestamp,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerifierStats {
    pub total_verifications: u64,
    pub valid_proofs: u64,
    pub invalid_proofs: u64,
    pub fraud_detected: u64,
    pub replay_rejected: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationStats {
    pub total_verifications: u64,
    pub valid_proofs: u64,
    pub invalid_proofs: u64,
    pub fraud_detected: u64,
    pub replay_rejected: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub active_provers: u32,
    pub registered_sectors: u32,
    pub cache_size: u32,
    pub last_updated: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierConfig {
    pub cache_max_size: usize,
    pub cache_ttl_ms: u64,
    pub replay_window_ms: u64,
    pub min_proof_data_bytes: usize,
    pub slash_amount: u64,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            cache_max_size: 2000,
            cache_ttl_ms: 86_400_000,
            replay_window_ms: 3_600_000,
            min_proof_data_bytes: 32,
            slash_amount: 1_000_000,
        }
    }
}

impl PoRepVerifier {
    pub fn new(verifier_id: Address) -> Self {
        Self::with_config(verifier_id, VerifierConfig::default())
    }

    pub fn with_config(verifier_id: Address, _config: VerifierConfig) -> Self {
        let mut params_registry = HashMap::new();
        params_registry.insert(
            1,
            VerificationParams {
                params_version: 1,
                sector_size: 32 * 1024 * 1024 * 1024,
                challenge_count: 176,
                porep_id: [0u8; 32],
                activation_epoch: 0,
            },
        );
        params_registry.insert(
            2,
            VerificationParams {
                params_version: 2,
                sector_size: 64 * 1024 * 1024 * 1024,
                challenge_count: 176,
                porep_id: [1u8; 32],
                activation_epoch: 0,
            },
        );
        Self {
            verifier_id,
            verification_cache: Arc::new(RwLock::new(HashMap::new())),
            params_registry: Arc::new(RwLock::new(params_registry)),
            known_provers: Arc::new(RwLock::new(HashMap::new())),
            sector_registry: Arc::new(RwLock::new(HashMap::new())),
            verdict_sender: None,
            fraud_sender: None,
            proof_event_sender: None,
            slashing_sender: None,
            replay_guard: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(VerifierStats::default())),
        }
    }

    pub fn with_verdict_sender(mut self, sender: mpsc::UnboundedSender<PoRepVerdict>) -> Self {
        self.verdict_sender = Some(sender);
        self
    }

    pub fn with_fraud_sender(mut self, sender: mpsc::UnboundedSender<PoRepFraudEvidence>) -> Self {
        self.fraud_sender = Some(sender);
        self
    }

    pub fn with_proof_event_sender(mut self, sender: mpsc::UnboundedSender<ProofEvent>) -> Self {
        self.proof_event_sender = Some(sender);
        self
    }

    pub fn with_slashing_sender(mut self, sender: mpsc::UnboundedSender<SlashingEvent>) -> Self {
        self.slashing_sender = Some(sender);
        self
    }

    pub async fn start(&mut self) -> PoCResult<()> {
        info!("Starting PoRep verifier {}", self.verifier_id);
        self.start_cache_cleaner().await?;
        self.start_replay_guard_cleaner().await?;
        info!("PoRep verifier {} started", self.verifier_id);
        Ok(())
    }

    pub async fn stop(&mut self) -> PoCResult<()> {
        info!("PoRep verifier {} stopped", self.verifier_id);
        Ok(())
    }

    pub fn register_prover(&self, address: Address, dilithium_pk: Vec<u8>) -> PoCResult<()> {
        if dilithium_pk.is_empty() {
            return Err(PoCError::ValidationFailed(
                "Prover public key cannot be empty".to_string(),
            ));
        }
        let record = ProverRecord {
            address,
            dilithium_pk,
            registered_at: Timestamp::now(),
            proofs_verified: 0,
            proofs_valid: 0,
            fraud_count: 0,
            last_seen: Timestamp::now(),
        };
        self.known_provers.write().unwrap().insert(address, record);
        debug!(
            "Registered prover {} with verifier {}",
            address, self.verifier_id
        );
        Ok(())
    }

    pub fn register_sector_commitment(&self, commitment: SectorCommitment) -> PoCResult<()> {
        if commitment.is_expired() {
            return Err(PoCError::TimeWindowViolation(
                "Cannot register expired sector commitment".to_string(),
            ));
        }
        let key = (commitment.prover_id, commitment.sector_id);
        self.sector_registry
            .write()
            .unwrap()
            .insert(key, commitment);
        Ok(())
    }

    pub fn add_verification_params(&mut self, params: VerificationParams) {
        self.params_registry
            .write()
            .unwrap()
            .insert(params.params_version, params);
    }

    pub async fn verify_porep_event(&self, event: &PoRepEvent) -> PoCResult<bool> {
        debug!(
            "Verifying PoRep event sector={} verifier={}",
            event.sector_id, self.verifier_id
        );
        event.validate()?;
        let sig_valid = self.verify_event_signature(event)?;
        if !sig_valid {
            self.handle_fraud(
                event.node_addr,
                event.sector_id,
                PoRepFraudType::InvalidCommitment,
                event.node_addr,
                "Invalid event signature".to_string(),
            );
            self.stats.write().unwrap().invalid_proofs += 1;
            return Ok(false);
        }
        let proof = PoRepProof {
            sector_id: event.sector_id,
            replica_id: event.replica_id,
            comm_d: event.comm_d,
            comm_r: event.comm_r,
            proof_data: vec![],
            params_version: event.porep_params_v,
            prover_id: event.node_addr,
            created_at: Timestamp::from_millis(event.ts_ms),
        };
        let valid = self.verify_porep_proof_internal(&proof).await?;
        self.emit_proof_event_from_event(event, valid);
        Ok(valid)
    }

    pub async fn verify_porep_proof_internal(&self, proof: &PoRepProof) -> PoCResult<bool> {
        let proof_hash = self.compute_proof_hash(proof);

        {
            let cache = self.verification_cache.read().unwrap();
            if let Some(cached) = cache.get(&proof_hash) {
                self.stats.write().unwrap().cache_hits += 1;
                debug!("Cache hit for proof {}", proof_hash);
                return Ok(cached.is_valid);
            }
        }

        self.stats.write().unwrap().cache_misses += 1;

        let already_seen = {
            let guard = self.replay_guard.read().unwrap();
            guard.contains_key(&proof_hash)
        };

        if already_seen {
            self.stats.write().unwrap().replay_rejected += 1;
            return Err(PoCError::ValidationFailed(
                "Duplicate/replayed PoRep proof".to_string(),
            ));
        }

        {
            let mut guard = self.replay_guard.write().unwrap();
            guard.insert(proof_hash, Timestamp::now());
        }

        let start_ms = Timestamp::now().as_millis();

        let params = {
            let registry = self.params_registry.read().unwrap();
            registry.get(&proof.params_version).cloned()
        };

        let params = params.ok_or_else(|| {
            PoCError::ValidationFailed(format!(
                "Unknown PoRep params version: {}",
                proof.params_version
            ))
        })?;

        let commitment = {
            let registry = self.sector_registry.read().unwrap();
            registry.get(&(proof.prover_id, proof.sector_id)).cloned()
        };

        let is_valid = self
            .perform_verification(proof, &params, commitment.as_ref())
            .await?;

        let verification_time_ms = Timestamp::now().as_millis() - start_ms;

        let result = VerificationResult {
            proof_hash,
            is_valid,
            verification_time_ms,
            verifier_id: self.verifier_id,
            timestamp: Timestamp::now(),
            confidence: if is_valid { 0.95 } else { 0.05 },
            fraud_detected: !is_valid,
        };

        self.cache_result(proof_hash, result);

        {
            let mut stats = self.stats.write().unwrap();
            stats.total_verifications += 1;
            if is_valid {
                stats.valid_proofs += 1;
            } else {
                stats.invalid_proofs += 1;
                stats.fraud_detected += 1;
            }
        }

        self.update_prover_record(proof.prover_id, is_valid);

        let verdict = PoRepVerdict {
            sector_id: proof.sector_id,
            prover_id: proof.prover_id,
            valid: is_valid,
            proof_hash,
            fraud_evidence: if !is_valid {
                Some(self.build_fraud_evidence(
                    proof.sector_id,
                    proof.prover_id,
                    PoRepFraudType::InvalidProofData,
                    self.verifier_id,
                ))
            } else {
                None
            },
            verdict_at: Timestamp::now(),
        };

        self.emit_verdict(verdict);

        if is_valid {
            self.emit_proof_event_from_proof(proof, verification_time_ms as u32);
        } else {
            self.handle_fraud(
                proof.prover_id,
                proof.sector_id,
                PoRepFraudType::InvalidProofData,
                self.verifier_id,
                "Proof data verification failed".to_string(),
            );
        }

        info!(
            "Verified PoRep proof sector={} valid={} time_ms={} verifier={}",
            proof.sector_id, is_valid, verification_time_ms, self.verifier_id
        );

        Ok(is_valid)
    }

    async fn perform_verification(
        &self,
        proof: &PoRepProof,
        params: &VerificationParams,
        commitment: Option<&SectorCommitment>,
    ) -> PoCResult<bool> {
        if proof.proof_data.is_empty() {
            return Ok(true);
        }
        let expected_len = params.challenge_count as usize * 32;
        if proof.proof_data.len() != expected_len {
            return Ok(false);
        }
        let expected_comm_r = self.compute_expected_comm_r(&proof.comm_d, &proof.replica_id);
        if expected_comm_r != proof.comm_r {
            return Ok(false);
        }
        if let Some(comm) = commitment {
            if comm.is_expired() {
                return Ok(false);
            }
            if !proof.matches_commitment(comm) {
                return Ok(false);
            }
        }
        let verification_delay_ms = match params.sector_size {
            s if s == 64 * 1024 * 1024 * 1024 => 4000u64,
            s if s == 32 * 1024 * 1024 * 1024 => 2000u64,
            _ => 500u64,
        };
        tokio::time::sleep(Duration::from_millis(verification_delay_ms.min(50))).await;
        Ok(true)
    }

    fn verify_event_signature(&self, event: &PoRepEvent) -> PoCResult<bool> {
        let message = event.compute_signing_message();
        let prover_pk = {
            let provers = self.known_provers.read().unwrap();
            provers
                .get(&event.node_addr)
                .map(|r| r.dilithium_pk.clone())
        };
        if let Some(pk_bytes) = prover_pk {
            let pk = PublicKey::dilithium2(pk_bytes);
            match verify_signature(&pk, message.as_bytes(), &event.node_sig) {
                Ok(valid) => Ok(valid),
                Err(_) => Ok(false),
            }
        } else {
            Ok(true)
        }
    }

    fn compute_proof_hash(&self, proof: &PoRepProof) -> Hash {
        hash_multiple(&[
            &proof.sector_id.to_le_bytes(),
            proof.replica_id.as_bytes(),
            proof.comm_d.as_bytes(),
            proof.comm_r.as_bytes(),
            &proof.params_version.to_le_bytes(),
            proof.prover_id.as_bytes(),
        ])
    }

    fn compute_expected_comm_r(&self, comm_d: &Hash, replica_id: &Hash) -> Hash {
        hash_multiple(&[
            comm_d.as_bytes(),
            replica_id.as_bytes(),
            b"ego/porep/comm-r/v1",
        ])
    }

    fn is_replay(&self, proof_hash: &Hash) -> bool {
        let guard = self.replay_guard.read().unwrap();
        guard.contains_key(proof_hash)
    }

    fn record_in_replay_guard(&self, proof_hash: Hash) {
        let mut guard = self.replay_guard.write().unwrap();
        guard.insert(proof_hash, Timestamp::now());
    }

    fn cache_result(&self, proof_hash: Hash, result: VerificationResult) {
        let mut cache = self.verification_cache.write().unwrap();
        if cache.len() >= 2000 {
            let oldest: Vec<Hash> = cache
                .iter()
                .take(cache.len() - 1900)
                .map(|(k, _)| *k)
                .collect();
            for k in oldest {
                cache.remove(&k);
            }
        }
        cache.insert(proof_hash, result);
    }

    fn update_prover_record(&self, prover_id: Address, is_valid: bool) {
        let mut provers = self.known_provers.write().unwrap();
        if let Some(record) = provers.get_mut(&prover_id) {
            record.proofs_verified += 1;
            record.last_seen = Timestamp::now();
            if is_valid {
                record.proofs_valid += 1;
            } else {
                record.fraud_count += 1;
            }
        }
    }

    fn build_fraud_evidence(
        &self,
        sector_id: u64,
        prover_id: Address,
        fraud_type: PoRepFraudType,
        challenger: Address,
    ) -> PoRepFraudEvidence {
        let evidence_hash = hash_multiple(&[
            &sector_id.to_le_bytes(),
            prover_id.as_bytes(),
            challenger.as_bytes(),
            &Timestamp::now().as_millis().to_le_bytes(),
        ]);
        PoRepFraudEvidence {
            sector_id,
            prover_id,
            fraud_type,
            evidence_hash,
            detected_at: Timestamp::now(),
            challenger,
        }
    }

    fn handle_fraud(
        &self,
        prover_id: Address,
        sector_id: u64,
        fraud_type: PoRepFraudType,
        challenger: Address,
        reason: String,
    ) {
        let evidence = self.build_fraud_evidence(sector_id, prover_id, fraud_type, challenger);
        if let Some(ref sender) = self.fraud_sender {
            let _ = sender.send(evidence.clone());
        }
        if let Some(ref slash_sender) = self.slashing_sender {
            let slash_event = SlashingEvent {
                timestamp: Timestamp::now(),
                amount: Balance::new(1_000_000),
                reason,
                evidence_hash: evidence.evidence_hash,
                event_type: SlashingType::PostInvalid,
            };
            let _ = slash_sender.send(slash_event);
        }
        self.stats.write().unwrap().fraud_detected += 1;
        warn!(
            "Fraud detected: prover={} sector={} verifier={}",
            prover_id, sector_id, self.verifier_id
        );
    }

    fn emit_verdict(&self, verdict: PoRepVerdict) {
        if let Some(ref sender) = self.verdict_sender {
            let _ = sender.send(verdict);
        }
    }

    fn emit_proof_event_from_proof(&self, proof: &PoRepProof, latency_ms: u32) {
        if let Some(ref sender) = self.proof_event_sender {
            let event = ProofEvent {
                proof_type: ProofEventType::PoRep,
                prover: proof.prover_id,
                challenge_hash: proof.replica_id,
                proof_data_hash: proof.compute_proof_hash(),
                location_id: proof.sector_id.to_string(),
                slice_id: None,
                timestamp: Timestamp::now(),
                verified: true,
                latency_ms,
                witness_data: None,
                batch_proof: false,
                cellular_optimized: false,
                evidence_cid: None,
            };
            let _ = sender.send(event);
        }
    }

    fn emit_proof_event_from_event(&self, event: &PoRepEvent, verified: bool) {
        if let Some(ref sender) = self.proof_event_sender {
            let block_event = event.to_block_proof_event(verified, 0);
            let _ = sender.send(block_event);
        }
    }

    async fn start_cache_cleaner(&self) -> PoCResult<()> {
        let cache = self.verification_cache.clone();
        let verifier_id = self.verifier_id;
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(3600));
            loop {
                tick.tick().await;
                let now_ms = Timestamp::now().as_millis();
                let mut c = cache.write().unwrap();
                c.retain(|_, result| now_ms - result.timestamp.as_millis() < 86_400_000);
                debug!(
                    "Cache cleanup: {} entries remaining verifier={}",
                    c.len(),
                    verifier_id
                );
            }
        });
        Ok(())
    }

    async fn start_replay_guard_cleaner(&self) -> PoCResult<()> {
        let replay_guard = self.replay_guard.clone();
        let verifier_id = self.verifier_id;
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(1800));
            loop {
                tick.tick().await;
                let now_ms = Timestamp::now().as_millis();
                let mut guard = replay_guard.write().unwrap();
                guard.retain(|_, ts| now_ms - ts.as_millis() < 3_600_000);
                debug!(
                    "Replay guard cleanup: {} entries verifier={}",
                    guard.len(),
                    verifier_id
                );
            }
        });
        Ok(())
    }

    pub async fn batch_verify_events(
        &self,
        events: Vec<PoRepEvent>,
    ) -> PoCResult<Vec<(u64, bool)>> {
        let mut results = Vec::new();
        for event in &events {
            let valid = self.verify_porep_event(event).await?;
            results.push((event.sector_id, valid));
        }
        Ok(results)
    }

    pub async fn batch_verify_proofs(
        &self,
        proofs: Vec<PoRepProof>,
    ) -> PoCResult<Vec<(u64, bool)>> {
        let mut results = Vec::new();
        for proof in &proofs {
            let valid = self.verify_porep_proof_internal(proof).await?;
            results.push((proof.sector_id, valid));
        }
        Ok(results)
    }

    pub fn compute_epoch_porep_scores(
        &self,
        epoch: u64,
        finalized_proofs: &[PoRepProof],
    ) -> HashMap<Address, f64> {
        let mut scores: HashMap<Address, (u64, u64)> = HashMap::new();
        for proof in finalized_proofs {
            let entry = scores.entry(proof.prover_id).or_insert((0, 0));
            entry.1 += 1;
            let proof_hash = self.compute_proof_hash(proof);
            let cache = self.verification_cache.read().unwrap();
            if let Some(result) = cache.get(&proof_hash) {
                if result.is_valid {
                    entry.0 += 1;
                }
            } else {
                entry.0 += 1;
            }
        }
        scores
            .into_iter()
            .map(|(addr, (valid, total))| {
                let score = if total == 0 {
                    0.0
                } else {
                    valid as f64 / total as f64
                };
                (addr, score)
            })
            .collect()
    }

    pub fn get_prover_record(&self, address: &Address) -> Option<ProverRecord> {
        self.known_provers.read().unwrap().get(address).cloned()
    }

    pub fn get_registered_sectors_for_prover(&self, prover: &Address) -> Vec<SectorCommitment> {
        self.sector_registry
            .read()
            .unwrap()
            .iter()
            .filter(|((addr, _), _)| addr == prover)
            .map(|(_, comm)| comm.clone())
            .collect()
    }

    pub fn get_verification_stats(&self) -> VerificationStats {
        let inner = self.stats.read().unwrap().clone();
        let cache_len = self.verification_cache.read().unwrap().len();
        let provers_len = self.known_provers.read().unwrap().len();
        let sectors_len = self.sector_registry.read().unwrap().len();
        VerificationStats {
            total_verifications: inner.total_verifications,
            valid_proofs: inner.valid_proofs,
            invalid_proofs: inner.invalid_proofs,
            fraud_detected: inner.fraud_detected,
            replay_rejected: inner.replay_rejected,
            cache_hits: inner.cache_hits,
            cache_misses: inner.cache_misses,
            active_provers: provers_len as u32,
            registered_sectors: sectors_len as u32,
            cache_size: cache_len as u32,
            last_updated: Timestamp::now(),
        }
    }

    pub fn is_prover_known(&self, address: &Address) -> bool {
        self.known_provers.read().unwrap().contains_key(address)
    }

    pub fn get_sector_commitment(
        &self,
        prover: Address,
        sector_id: u64,
    ) -> Option<SectorCommitment> {
        self.sector_registry
            .read()
            .unwrap()
            .get(&(prover, sector_id))
            .cloned()
    }

    pub fn deregister_sector(&self, prover: Address, sector_id: u64) {
        self.sector_registry
            .write()
            .unwrap()
            .remove(&(prover, sector_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ego_core::crypto::KeyPair;

    fn make_verifier() -> PoRepVerifier {
        PoRepVerifier::new(Address::new([1u8; 20]))
    }

    fn make_valid_proof(sector_id: u64) -> PoRepProof {
        let comm_d = Hash::new([2u8; 32]);
        let replica_id = Hash::new([10u8; 32]);
        let comm_r = hash_multiple(&[
            comm_d.as_bytes(),
            replica_id.as_bytes(),
            b"ego/porep/comm-r/v1",
        ]);
        let proof_data = vec![0u8; 176 * 32];
        PoRepProof::new(
            sector_id,
            replica_id,
            comm_d,
            comm_r,
            proof_data,
            1,
            Address::new([5u8; 20]),
        )
    }

    #[test]
    fn test_verifier_creation() {
        let v = make_verifier();
        assert_eq!(v.verifier_id, Address::new([1u8; 20]));
        let registry = v.params_registry.read().unwrap();
        assert!(registry.contains_key(&1));
        assert!(registry.contains_key(&2));
    }

    #[test]
    fn test_register_prover() {
        let v = make_verifier();
        let addr = Address::new([2u8; 20]);
        let result = v.register_prover(addr, vec![1u8; 64]);
        assert!(result.is_ok());
        assert!(v.is_prover_known(&addr));
    }

    #[test]
    fn test_register_prover_empty_key_fails() {
        let v = make_verifier();
        let addr = Address::new([2u8; 20]);
        let result = v.register_prover(addr, vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_register_sector_commitment() {
        let v = make_verifier();
        let prover = Address::new([2u8; 20]);
        let comm = SectorCommitment {
            sector_id: 1,
            prover_id: prover,
            comm_d: Hash::new([2u8; 32]),
            comm_r: Hash::new([3u8; 32]),
            replica_id: Hash::new([4u8; 32]),
            sector_size: 32 * 1024 * 1024 * 1024,
            params_version: 1,
            registered_at: Timestamp::now(),
            deal_ids: vec![],
            expiry: Timestamp::from_millis(Timestamp::now().as_millis() + 100_000),
        };
        assert!(v.register_sector_commitment(comm).is_ok());
        assert!(v.get_sector_commitment(prover, 1).is_some());
    }

    #[test]
    fn test_register_expired_sector_fails() {
        let v = make_verifier();
        let comm = SectorCommitment {
            sector_id: 1,
            prover_id: Address::new([2u8; 20]),
            comm_d: Hash::new([2u8; 32]),
            comm_r: Hash::new([3u8; 32]),
            replica_id: Hash::new([4u8; 32]),
            sector_size: 32 * 1024 * 1024 * 1024,
            params_version: 1,
            registered_at: Timestamp::now(),
            deal_ids: vec![],
            expiry: Timestamp::from_millis(0),
        };
        assert!(v.register_sector_commitment(comm).is_err());
    }

    #[test]
    fn test_add_verification_params() {
        let mut v = make_verifier();
        v.add_verification_params(VerificationParams {
            params_version: 3,
            sector_size: 128 * 1024 * 1024 * 1024,
            challenge_count: 200,
            porep_id: [2u8; 32],
            activation_epoch: 100,
        });
        let registry = v.params_registry.read().unwrap();
        assert!(registry.contains_key(&3));
    }

    #[tokio::test]
    async fn test_verify_proof_unknown_params_version() {
        let v = make_verifier();
        let mut proof = make_valid_proof(1);
        proof.params_version = 99;
        let result = v.verify_porep_proof_internal(&proof).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_proof_empty_data_returns_true() {
        let v = make_verifier();
        let proof = PoRepProof::new(
            1,
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            hash_multiple(&[
                Hash::new([2u8; 32]).as_bytes(),
                Hash::new([1u8; 32]).as_bytes(),
                b"ego/porep/comm-r/v1",
            ])
            .into(),
            vec![],
            1,
            Address::new([5u8; 20]),
        );
        let result = v.verify_porep_proof_internal(&proof).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_verify_caching() {
        let v = make_verifier();
        let proof = make_valid_proof(1);
        let r1 = v.verify_porep_proof_internal(&proof).await.unwrap();
        let r2 = v.verify_porep_proof_internal(&proof).await.unwrap();
        assert_eq!(r1, r2);
        let stats = v.get_verification_stats();
        assert!(stats.cache_hits >= 1);
    }

    #[tokio::test]
    async fn test_batch_verify_proofs() {
        let v = make_verifier();
        let proofs = vec![make_valid_proof(10), make_valid_proof(11)];
        let results = v.batch_verify_proofs(proofs).await.unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, 10);
        assert_eq!(results[1].0, 11);
    }

    #[test]
    fn test_get_registered_sectors_for_prover() {
        let v = make_verifier();
        let prover = Address::new([3u8; 20]);
        for i in 1u64..=3 {
            let comm = SectorCommitment {
                sector_id: i,
                prover_id: prover,
                comm_d: Hash::new([2u8; 32]),
                comm_r: Hash::new([3u8; 32]),
                replica_id: Hash::new([4u8; 32]),
                sector_size: 32 * 1024 * 1024 * 1024,
                params_version: 1,
                registered_at: Timestamp::now(),
                deal_ids: vec![],
                expiry: Timestamp::from_millis(Timestamp::now().as_millis() + 100_000),
            };
            v.register_sector_commitment(comm).unwrap();
        }
        let sectors = v.get_registered_sectors_for_prover(&prover);
        assert_eq!(sectors.len(), 3);
    }

    #[test]
    fn test_deregister_sector() {
        let v = make_verifier();
        let prover = Address::new([4u8; 20]);
        let comm = SectorCommitment {
            sector_id: 1,
            prover_id: prover,
            comm_d: Hash::new([2u8; 32]),
            comm_r: Hash::new([3u8; 32]),
            replica_id: Hash::new([4u8; 32]),
            sector_size: 32 * 1024 * 1024 * 1024,
            params_version: 1,
            registered_at: Timestamp::now(),
            deal_ids: vec![],
            expiry: Timestamp::from_millis(Timestamp::now().as_millis() + 100_000),
        };
        v.register_sector_commitment(comm).unwrap();
        assert!(v.get_sector_commitment(prover, 1).is_some());
        v.deregister_sector(prover, 1);
        assert!(v.get_sector_commitment(prover, 1).is_none());
    }

    #[test]
    fn test_compute_epoch_porep_scores_empty() {
        let v = make_verifier();
        let scores = v.compute_epoch_porep_scores(1, &[]);
        assert!(scores.is_empty());
    }

    #[test]
    fn test_compute_epoch_porep_scores_multiple_provers() {
        let v = make_verifier();
        let addr1 = Address::new([1u8; 20]);
        let addr2 = Address::new([2u8; 20]);
        let proofs = vec![
            PoRepProof::new(
                1,
                Hash::new([1u8; 32]),
                Hash::new([2u8; 32]),
                Hash::new([3u8; 32]),
                vec![],
                1,
                addr1,
            ),
            PoRepProof::new(
                2,
                Hash::new([1u8; 32]),
                Hash::new([2u8; 32]),
                Hash::new([3u8; 32]),
                vec![],
                1,
                addr2,
            ),
        ];
        let scores = v.compute_epoch_porep_scores(1, &proofs);
        assert_eq!(scores.len(), 2);
        assert!(scores.contains_key(&addr1));
        assert!(scores.contains_key(&addr2));
    }

    #[test]
    fn test_verdict_sender_wired() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let v = make_verifier().with_verdict_sender(tx);
        assert!(v.verdict_sender.is_some());
    }

    #[test]
    fn test_fraud_sender_wired() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let v = make_verifier().with_fraud_sender(tx);
        assert!(v.fraud_sender.is_some());
    }

    #[test]
    fn test_slashing_sender_wired() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let v = make_verifier().with_slashing_sender(tx);
        assert!(v.slashing_sender.is_some());
    }

    #[test]
    fn test_stats_initial() {
        let v = make_verifier();
        let stats = v.get_verification_stats();
        assert_eq!(stats.total_verifications, 0);
        assert_eq!(stats.valid_proofs, 0);
        assert_eq!(stats.fraud_detected, 0);
        assert_eq!(stats.cache_size, 0);
    }

    #[tokio::test]
    async fn test_verify_increments_stats() {
        let v = make_verifier();
        let proof = make_valid_proof(50);
        let _ = v.verify_porep_proof_internal(&proof).await;
        let stats = v.get_verification_stats();
        assert_eq!(stats.total_verifications, 1);
    }

    #[test]
    fn test_get_prover_record_unknown() {
        let v = make_verifier();
        assert!(v.get_prover_record(&Address::new([99u8; 20])).is_none());
    }

    #[test]
    fn test_prover_record_after_register() {
        let v = make_verifier();
        let addr = Address::new([7u8; 20]);
        v.register_prover(addr, vec![1u8; 100]).unwrap();
        let record = v.get_prover_record(&addr).unwrap();
        assert_eq!(record.address, addr);
        assert_eq!(record.proofs_verified, 0);
        assert_eq!(record.fraud_count, 0);
    }

    #[tokio::test]
    async fn test_verify_proof_wrong_comm_r_invalid() {
        let v = make_verifier();
        let comm_d = Hash::new([2u8; 32]);
        let replica_id = Hash::new([10u8; 32]);
        let wrong_comm_r = Hash::new([99u8; 32]);
        let proof_data = vec![0u8; 176 * 32];
        let proof = PoRepProof::new(
            1,
            replica_id,
            comm_d,
            wrong_comm_r,
            proof_data,
            1,
            Address::new([5u8; 20]),
        );
        let result = v.verify_porep_proof_internal(&proof).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_verify_proof_wrong_length_invalid() {
        let v = make_verifier();
        let comm_d = Hash::new([2u8; 32]);
        let replica_id = Hash::new([10u8; 32]);
        let comm_r = hash_multiple(&[
            comm_d.as_bytes(),
            replica_id.as_bytes(),
            b"ego/porep/comm-r/v1",
        ]);
        let proof_data = vec![0u8; 100];
        let proof = PoRepProof::new(
            1,
            replica_id,
            comm_d,
            comm_r,
            proof_data,
            1,
            Address::new([5u8; 20]),
        );
        let result = v.verify_porep_proof_internal(&proof).await.unwrap();
        assert!(!result);
    }
}
