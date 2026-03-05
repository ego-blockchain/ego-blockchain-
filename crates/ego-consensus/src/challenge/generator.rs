use crate::consensus::bft::{BftEngine, BlockHeader, QuorumCertificate};
use crate::beacon::{ChallengeSchedule, RandomnessSource};
use crate::error::{PoCError, PoCResult};
use crate::types::Challenge;
use ego_core::{Address, Hash, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration, Instant};
use tracing::{debug, info, warn, error};

/// Challenge generation service that creates PoC challenges from finalized blocks
/// Whitepaper: Challenges are derived from consensus randomness every epoch
#[derive(Debug)]
pub struct ChallengeGenerator {
    /// Challenge generation configuration
    config: ChallengeConfig,

    /// Active challenge schedules by region and epoch
    active_schedules: Arc<RwLock<BTreeMap<(String, u64), ChallengeSchedule>>>,

    /// Pending challenges awaiting distribution
    pending_challenges: Arc<RwLock<VecDeque<GeneratedChallenge>>>,

    /// Challenge subscribers by region
    challenge_senders: Arc<RwLock<HashMap<String, Vec<mpsc::UnboundedSender<Challenge>>>>>,

    /// Block finalization event receiver
    block_receiver: Option<mpsc::UnboundedReceiver<(BlockHeader, QuorumCertificate)>>,

    /// Challenge distribution sender
    challenge_sender: Option<mpsc::UnboundedSender<GeneratedChallenge>>,

    /// Service statistics
    stats: Arc<RwLock<GeneratorStats>>,

    /// Last processed epoch to avoid duplicates
    last_processed_epoch: Arc<RwLock<u64>>,

    /// Regional beacon distribution
    region_beacon_map: Arc<RwLock<HashMap<String, Vec<Address>>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeConfig {
    /// Number of challenges per epoch per region
    pub challenges_per_epoch: u32,

    /// Challenge window duration (whitepaper: W=10s)
    pub window_duration_ms: u64,

    /// Time between challenges in the same region (ms)
    pub challenge_interval_ms: u64,

    /// Maximum number of beacons to select per challenge
    pub max_beacons_per_challenge: u32,

    /// Challenge difficulty scaling factor
    pub difficulty_base: u32,

    /// Regional coverage requirements
    pub min_regions: u32,

    /// Challenge expiry time (for cleanup)
    pub challenge_expiry_hours: u64,

    /// Use VRF randomness from finalized blocks
    pub use_consensus_randomness: bool,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedChallenge {
    /// The challenge data structure
    pub challenge: Challenge,

    /// Target region for this challenge
    pub region_id: String,

    /// Selected beacon addresses for this challenge
    pub selected_beacons: Vec<Address>,

    /// Challenge schedule information
    pub schedule: ChallengeSchedule,

    /// Generation timestamp
    pub generated_at: Timestamp,

    /// Source randomness (VRF output from finalized block)
    pub randomness_source: Hash,

    /// Epoch this challenge belongs to
    pub epoch: u64,

    /// Slot within the epoch
    pub slot: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct GeneratorStats {
    /// Total challenges generated
    pub total_challenges: u64,

    /// Challenges generated per epoch
    pub challenges_per_epoch: BTreeMap<u64, u32>,

    /// Challenges generated per region
    pub challenges_per_region: HashMap<String, u64>,

    /// Failed challenge generations
    pub generation_failures: u64,

    /// Average challenge generation time (ms)
    pub avg_generation_time_ms: f64,

    /// Last epoch processed
    pub last_epoch_processed: u64,

    /// Service uptime
    pub service_start_time: Timestamp,

    /// Block finalization events processed
    pub blocks_processed: u64,
}

impl ChallengeGenerator {
    /// Create new challenge generator
    pub fn new(config: ChallengeConfig) -> Self {
        Self {
            config,
            active_schedules: Arc::new(RwLock::new(BTreeMap::new())),
            pending_challenges: Arc::new(RwLock::new(VecDeque::new())),
            challenge_senders: Arc::new(RwLock::new(HashMap::new())),
            block_receiver: None,
            challenge_sender: None,
            stats: Arc::new(RwLock::new(GeneratorStats {
                service_start_time: Timestamp::now(),
                ..Default::default()
            })),
            last_processed_epoch: Arc::new(RwLock::new(0)),
            region_beacon_map: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start the challenge generation service
    pub async fn start(&mut self,
                      block_receiver: mpsc::UnboundedReceiver<(BlockHeader, QuorumCertificate)>
    ) -> PoCResult<mpsc::UnboundedReceiver<GeneratedChallenge>> {
        info!("Starting challenge generator service with {} challenges per epoch",
              self.config.challenges_per_epoch);

        let (challenge_sender, challenge_receiver) = mpsc::unbounded_channel();

        self.block_receiver = Some(block_receiver);
        self.challenge_sender = Some(challenge_sender);

        // Start block processing task
        self.start_block_processor().await?;

        // Start challenge distribution task
        self.start_challenge_distributor().await?;

        // Start cleanup task
        self.start_cleanup_task().await?;

        info!("✅ Challenge generator service started successfully");
        Ok(challenge_receiver)
    }

    /// Start block finalization processor
    async fn start_block_processor(&self) -> PoCResult<()> {
        let active_schedules = self.active_schedules.clone();
        let pending_challenges = self.pending_challenges.clone();
        let challenge_sender = self.challenge_sender.as_ref().unwrap().clone();
        let stats = self.stats.clone();
        let last_processed_epoch = self.last_processed_epoch.clone();
        let region_beacon_map = self.region_beacon_map.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            // In a real implementation, we would receive from self.block_receiver
            // For now, simulate finalized blocks
            let mut interval = interval(Duration::from_secs(12)); // ~12s block time

            loop {
                interval.tick().await;

                let current_epoch = Timestamp::now().as_secs() / 3600; // 1-hour epochs
                let last_epoch = *last_processed_epoch.read().unwrap();

                if current_epoch > last_epoch {
                    info!("Processing new epoch {} for challenge generation", current_epoch);

                    // Simulate finalized block with VRF output
                    let vrf_output = Self::generate_mock_vrf_output(current_epoch);

                    // Generate challenges for this epoch
                    if let Err(e) = Self::generate_epoch_challenges(
                        current_epoch,
                        vrf_output,
                        &config,
                        &active_schedules,
                        &pending_challenges,
                        &challenge_sender,
                        &stats,
                        &region_beacon_map,
                    ).await {
                        error!("Failed to generate challenges for epoch {}: {}", current_epoch, e);
                        stats.write().unwrap().generation_failures += 1;
                    } else {
                        *last_processed_epoch.write().unwrap() = current_epoch;
                        stats.write().unwrap().blocks_processed += 1;
                        stats.write().unwrap().last_epoch_processed = current_epoch;
                    }
                }
            }
        });

        Ok(())
    }

    /// Generate challenges for a specific epoch
    async fn generate_epoch_challenges(
        epoch: u64,
        vrf_output: Hash,
        config: &ChallengeConfig,
        active_schedules: &Arc<RwLock<BTreeMap<(String, u64), ChallengeSchedule>>>,
        pending_challenges: &Arc<RwLock<VecDeque<GeneratedChallenge>>>,
        challenge_sender: &mpsc::UnboundedSender<GeneratedChallenge>,
        stats: &Arc<RwLock<GeneratorStats>>,
        region_beacon_map: &Arc<RwLock<HashMap<String, Vec<Address>>>>,
    ) -> PoCResult<()> {
        let generation_start = Instant::now();
        let regions = Self::get_active_regions(region_beacon_map);

        if regions.is_empty() {
            warn!("No active regions found for challenge generation in epoch {}", epoch);
            return Ok(());
        }

        let mut challenges_generated = 0u32;

        for region_id in &regions {
            let beacons = {
                let beacon_map = region_beacon_map.read().unwrap();
                beacon_map.get(region_id).cloned().unwrap_or_default()
            };

            if beacons.is_empty() {
                debug!("No beacons available in region {} for epoch {}", region_id, epoch);
                continue;
            }

            // Generate challenges for this region
            for slot in 0..config.challenges_per_epoch {
                let challenge = Self::create_challenge_from_vrf(
                    epoch,
                    slot as u64,
                    &region_id,
                    vrf_output,
                    &beacons,
                    config,
                )?;

                let selected_beacon = if !beacons.is_empty() {
                    let beacon_index = Self::deterministic_selection(challenge.challenge_hash, beacons.len());
                    beacons[beacon_index]
                } else {
                    Address::new([0u8; 20])
                };

                let schedule = ChallengeSchedule::new(
                    region_id.clone(),
                    epoch,
                    slot as u64,
                    vrf_output,
                    selected_beacon,
                );

                let generated_challenge = GeneratedChallenge {
                    challenge: challenge.clone(),
                    region_id: region_id.clone(),
                    selected_beacons: Self::select_beacons_for_challenge(
                        &beacons,
                        vrf_output,
                        epoch,
                        slot as u64,
                        config.max_beacons_per_challenge,
                    ),
                    schedule: schedule.clone(),
                    generated_at: Timestamp::now(),
                    randomness_source: vrf_output,
                    epoch,
                    slot: slot as u64,
                };

                // Store active schedule
                active_schedules.write().unwrap().insert((region_id.clone(), epoch), schedule);

                // Queue for distribution
                pending_challenges.write().unwrap().push_back(generated_challenge.clone());

                // Send immediately
                if let Err(e) = challenge_sender.send(generated_challenge) {
                    error!("Failed to send generated challenge: {}", e);
                } else {
                    challenges_generated += 1;
                    debug!("Generated challenge for region {} epoch {} slot {}",
                           region_id, epoch, slot);
                }
            }
        }

        // Update statistics
        let generation_time = generation_start.elapsed().as_millis() as f64;
        {
            let mut stats_guard = stats.write().unwrap();
            stats_guard.total_challenges += challenges_generated as u64;
            stats_guard.challenges_per_epoch.insert(epoch, challenges_generated);

            // Update average generation time
            let total_time = stats_guard.avg_generation_time_ms * stats_guard.blocks_processed as f64;
            stats_guard.avg_generation_time_ms =
                (total_time + generation_time) / (stats_guard.blocks_processed + 1) as f64;
        }

        info!("Generated {} challenges for epoch {} across {} regions in {:.2}ms",
              challenges_generated, epoch, regions.len(), generation_time);

        Ok(())
    }

    /// Create a challenge from VRF randomness
    fn create_challenge_from_vrf(
        epoch: u64,
        slot: u64,
        region_id: &str,
        vrf_output: Hash,
        beacons: &[Address],
        config: &ChallengeConfig,
    ) -> PoCResult<Challenge> {
        use ego_core::crypto::hash_multiple;

        // Whitepaper: R_e = H(vrf_output || region_id || epoch || slot)
        let challenge_hash = hash_multiple(&[
            vrf_output.as_bytes(),
            region_id.as_bytes(),
            &epoch.to_le_bytes(),
            &slot.to_le_bytes(),
        ]);

        // Beacon selection is handled separately in the calling function

        // Generate nonce from challenge randomness
        let nonce_hash = hash_multiple(&[
            challenge_hash.as_bytes(),
            b"challenge_nonce",
            &slot.to_le_bytes(),
        ]);
        let nonce = nonce_hash.as_bytes()[..16].to_vec();

        // Calculate difficulty based on epoch and region
        let difficulty = Self::calculate_challenge_difficulty(epoch, region_id, config);

        Ok(Challenge {
            challenge_hash,
            h3_cell: region_id.to_string(),
            nonce,
            timestamp: Timestamp::now(),
            difficulty: difficulty.min(255) as u8, // Convert u32 to u8
            reward_scale: 1.0, // Base reward scale
        })
    }

    /// Select beacons for a challenge using VRF randomness
    fn select_beacons_for_challenge(
        beacons: &[Address],
        vrf_output: Hash,
        epoch: u64,
        slot: u64,
        max_beacons: u32,
    ) -> Vec<Address> {
        use ego_core::crypto::hash_multiple;

        if beacons.is_empty() {
            return Vec::new();
        }

        let selection_seed = hash_multiple(&[
            vrf_output.as_bytes(),
            &epoch.to_le_bytes(),
            &slot.to_le_bytes(),
            b"beacon_selection",
        ]);

        let num_to_select = (max_beacons as usize).min(beacons.len());
        let mut selected = Vec::with_capacity(num_to_select);
        let mut used_indices = std::collections::HashSet::new();

        for i in 0..num_to_select {
            let selection_hash = hash_multiple(&[
                selection_seed.as_bytes(),
                &i.to_le_bytes(),
            ]);

            let mut index = Self::deterministic_selection(selection_hash, beacons.len());

            // Ensure we don't select the same beacon twice
            while used_indices.contains(&index) {
                let rehash = hash_multiple(&[selection_hash.as_bytes(), &index.to_le_bytes()]);
                index = Self::deterministic_selection(rehash, beacons.len());
            }

            used_indices.insert(index);
            selected.push(beacons[index]);
        }

        selected
    }

    /// Deterministic selection from array using hash
    fn deterministic_selection(hash: Hash, array_len: usize) -> usize {
        let hash_bytes = hash.as_bytes();
        let hash_u64 = u64::from_le_bytes([
            hash_bytes[0], hash_bytes[1], hash_bytes[2], hash_bytes[3],
            hash_bytes[4], hash_bytes[5], hash_bytes[6], hash_bytes[7],
        ]);
        (hash_u64 as usize) % array_len
    }

    /// Calculate challenge difficulty based on epoch and region
    pub fn calculate_challenge_difficulty(epoch: u64, region_id: &str, config: &ChallengeConfig) -> u32 {
        // Base difficulty increases slowly over time
        let epoch_factor = 1.0 + (epoch as f64 * 0.001); // 0.1% increase per epoch

        // Region-based difficulty adjustment (hash-based determinism)
        use ego_core::crypto::hash_data;
        let region_hash = hash_data(region_id.as_bytes());
        let region_factor = 1.0 + 0.2 * (region_hash.as_bytes()[0] as f64 / 255.0 - 0.5);

        ((config.difficulty_base as f64 * epoch_factor * region_factor) as u32).max(config.difficulty_base)
    }

    /// Start challenge distribution task
    async fn start_challenge_distributor(&self) -> PoCResult<()> {
        let pending_challenges = self.pending_challenges.clone();
        let challenge_senders = self.challenge_senders.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(100));

            loop {
                interval.tick().await;

                // Distribute pending challenges
                let challenge = {
                    let mut pending = pending_challenges.write().unwrap();
                    pending.pop_front()
                };

                if let Some(challenge) = challenge {
                    let senders = challenge_senders.read().unwrap();
                    if let Some(region_senders) = senders.get(&challenge.region_id) {
                        for sender in region_senders {
                            if let Err(e) = sender.send(challenge.challenge.clone()) {
                                warn!("Failed to distribute challenge to subscriber: {}", e);
                            }
                        }
                        debug!("Distributed challenge to {} subscribers in region {}",
                               region_senders.len(), challenge.region_id);
                    }
                }
            }
        });

        Ok(())
    }

    /// Start cleanup task for old schedules and challenges
    async fn start_cleanup_task(&self) -> PoCResult<()> {
        let active_schedules = self.active_schedules.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut cleanup_interval = interval(Duration::from_secs(3600)); // Hourly cleanup

            loop {
                cleanup_interval.tick().await;

                let current_time = Timestamp::now();
                let expiry_threshold = current_time.as_millis() -
                    (config.challenge_expiry_hours * 3600 * 1000) as u64;

                {
                    let mut schedules = active_schedules.write().unwrap();
                    let initial_count = schedules.len();

                    // Remove expired schedules
                    schedules.retain(|_, schedule| {
                        schedule.window_end.as_millis() > expiry_threshold
                    });

                    let removed_count = initial_count - schedules.len();
                    if removed_count > 0 {
                        info!("Cleaned up {} expired challenge schedules", removed_count);
                    }
                }
            }
        });

        Ok(())
    }

    /// Subscribe to challenges for a specific region
    pub fn subscribe_to_region(&self, region_id: String) -> mpsc::UnboundedReceiver<Challenge> {
        let (sender, receiver) = mpsc::unbounded_channel();

        self.challenge_senders.write().unwrap()
            .entry(region_id.clone())
            .or_insert_with(Vec::new)
            .push(sender);

        debug!("New subscriber for region {}", region_id);
        receiver
    }

    /// Register beacons for a region
    pub fn register_region_beacons(&self, region_id: String, beacons: Vec<Address>) {
        self.region_beacon_map.write().unwrap().insert(region_id.clone(), beacons.clone());
        info!("Registered {} beacons for region {}", beacons.len(), region_id);
    }

    /// Get service statistics
    pub fn get_stats(&self) -> GeneratorStats {
        self.stats.read().unwrap().clone()
    }

    /// Get active regions
    fn get_active_regions(region_beacon_map: &Arc<RwLock<HashMap<String, Vec<Address>>>>) -> Vec<String> {
        region_beacon_map.read().unwrap()
            .iter()
            .filter(|(_, beacons)| !beacons.is_empty())
            .map(|(region, _)| region.clone())
            .collect()
    }

    /// Generate mock VRF output for testing
    fn generate_mock_vrf_output(epoch: u64) -> Hash {
        use ego_core::crypto::hash_multiple;
        hash_multiple(&[
            b"mock_vrf_output",
            &epoch.to_le_bytes(),
            &Timestamp::now().as_millis().to_le_bytes(),
        ])
    }
}

impl Default for ChallengeConfig {
    fn default() -> Self {
        Self {
            challenges_per_epoch: 10,         // 10 challenges per hour per region
            window_duration_ms: 10_000,       // Whitepaper: W=10s
            challenge_interval_ms: 360_000,   // 6 minutes between challenges
            max_beacons_per_challenge: 3,     // Select up to 3 beacons
            difficulty_base: 1000,            // Base difficulty
            min_regions: 1,                   // At least 1 region must be active
            challenge_expiry_hours: 48,       // Clean up after 48 hours
            use_consensus_randomness: true,   // Use VRF from finalized blocks
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_challenge_generator_creation() {
        let config = ChallengeConfig::default();
        let generator = ChallengeGenerator::new(config);

        let stats = generator.get_stats();
        assert_eq!(stats.total_challenges, 0);
        assert!(stats.service_start_time.as_millis() > 0);
    }

    #[test]
    fn test_challenge_creation_from_vrf() {
        let config = ChallengeConfig::default();
        let vrf_output = Hash::new([1u8; 32]);
        let beacons = vec![Address::new([1u8; 20]), Address::new([2u8; 20])];

        let challenge = ChallengeGenerator::create_challenge_from_vrf(
            100,     // epoch
            5,       // slot
            "872834", // region
            vrf_output,
            &beacons,
            &config,
        ).unwrap();

        assert_eq!(challenge.h3_cell, "872834");
        assert_eq!(challenge.nonce.len(), 16);
        assert!(!challenge.challenge_hash.as_bytes().iter().all(|&b| b == 0));
        assert!(challenge.difficulty > 0);
    }

    #[test]
    fn test_beacon_selection() {
        let beacons = vec![
            Address::new([1u8; 20]),
            Address::new([2u8; 20]),
            Address::new([3u8; 20]),
            Address::new([4u8; 20]),
            Address::new([5u8; 20]),
        ];
        let vrf_output = Hash::new([42u8; 32]);

        let selected = ChallengeGenerator::select_beacons_for_challenge(
            &beacons,
            vrf_output,
            100,  // epoch
            1,    // slot
            3,    // max_beacons
        );

        assert_eq!(selected.len(), 3);

        // Ensure no duplicates
        let mut unique = std::collections::HashSet::new();
        for beacon in &selected {
            assert!(unique.insert(beacon));
        }
    }

    #[test]
    fn test_deterministic_selection() {
        let hash = Hash::new([1u8; 32]);

        // Same hash should always give same result
        let index1 = ChallengeGenerator::deterministic_selection(hash, 10);
        let index2 = ChallengeGenerator::deterministic_selection(hash, 10);
        assert_eq!(index1, index2);

        // Result should be within bounds
        assert!(index1 < 10);
    }

    #[test]
    fn test_challenge_difficulty_calculation() {
        let config = ChallengeConfig::default();

        let difficulty1 = ChallengeGenerator::calculate_challenge_difficulty(100, "872834", &config);
        let difficulty2 = ChallengeGenerator::calculate_challenge_difficulty(200, "872834", &config);

        // Difficulty should increase over time
        assert!(difficulty2 > difficulty1);
        assert!(difficulty1 >= config.difficulty_base);
    }

    #[tokio::test]
    async fn test_region_subscription() {
        let config = ChallengeConfig::default();
        let generator = ChallengeGenerator::new(config);

        let mut receiver = generator.subscribe_to_region("872834".to_string());

        // Verify subscription was created
        {
            let senders = generator.challenge_senders.read().unwrap();
            assert!(senders.contains_key("872834"));
            assert_eq!(senders.get("872834").unwrap().len(), 1);
        }
    }
}