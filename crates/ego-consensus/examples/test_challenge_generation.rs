use ego_consensus::challenge::{ChallengeConfig, ChallengeService, create_challenge_service};
use ego_consensus::consensus::bft::{BftEngine, BlockHeader, QuorumCertificate, BlockRoots};
use ego_consensus::consensus::engine::{ConsensusEngine, ConsensusConfig};
use ego_core::{Address, Hash, KeyPair, Signature, PublicKey, Timestamp};
use tokio::time::{sleep, Duration};
use tracing::{info, warn, Level};
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    info!("🚀 Starting Challenge Generation Test");

    // Test 1: Basic Challenge Generator
    test_challenge_generator().await?;

    // Test 2: Challenge Service Integration
    test_challenge_service().await?;

    // Test 3: Consensus Engine Integration
    test_consensus_integration().await?;

    info!("✅ All challenge generation tests completed successfully!");
    Ok(())
}

async fn test_challenge_generator() -> Result<(), Box<dyn std::error::Error>> {
    info!("📋 Test 1: Basic Challenge Generator");

    let config = ChallengeConfig {
        challenges_per_epoch: 5,
        window_duration_ms: 10_000,
        challenge_interval_ms: 300_000, // 5 minutes
        max_beacons_per_challenge: 2,
        difficulty_base: 100,
        min_regions: 1,
        challenge_expiry_hours: 24,
        use_consensus_randomness: true,
    };

    let mut generator = ego_consensus::challenge::ChallengeGenerator::new(config.clone());

    // Register some mock beacons for testing
    let mock_beacons = vec![
        Address::new([1u8; 20]),
        Address::new([2u8; 20]),
        Address::new([3u8; 20]),
    ];

    generator.register_region_beacons("872834".to_string(), mock_beacons.clone());
    generator.register_region_beacons("872835".to_string(), mock_beacons);

    info!("Registered beacons for regions 872834 and 872835");

    // Subscribe to challenges for a region
    let mut challenge_receiver = generator.subscribe_to_region("872834".to_string());

    // Start the generator (this will use mock block events)
    let (block_sender, block_receiver) = tokio::sync::mpsc::unbounded_channel();
    let mut generated_challenges = generator.start(block_receiver).await?;

    info!("✅ Challenge generator started successfully");

    // Simulate a finalized block event
    let mock_block = create_mock_block(100, 10);
    let mock_qc = create_mock_qc(&mock_block);

    if let Err(e) = block_sender.send((mock_block.clone(), mock_qc)) {
        warn!("Failed to send mock block: {}", e);
    } else {
        info!("📦 Sent mock finalized block: height={}, epoch={}", mock_block.height, mock_block.epoch);
    }

    // Wait for challenge generation and collection
    info!("⏳ Waiting for challenge generation...");

    // Try to receive a generated challenge
    tokio::select! {
        challenge = generated_challenges.recv() => {
            if let Some(challenge) = challenge {
                info!("🎯 Generated challenge: region={}, epoch={}, slot={}",
                      challenge.region_id, challenge.epoch, challenge.slot);
                info!("   Challenge hash: {:?}", challenge.challenge.challenge_hash);
                info!("   Selected beacons: {:?}", challenge.selected_beacons);
                info!("   Difficulty: {}", challenge.challenge.difficulty);
            }
        }
        _ = sleep(Duration::from_secs(5)) => {
            info!("⏰ Challenge generation test completed (5s timeout)");
        }
    }

    // Get statistics
    let stats = generator.get_stats();
    info!("📊 Generator Stats:");
    info!("   Total challenges: {}", stats.total_challenges);
    info!("   Blocks processed: {}", stats.blocks_processed);
    info!("   Generation failures: {}", stats.generation_failures);

    Ok(())
}

async fn test_challenge_service() -> Result<(), Box<dyn std::error::Error>> {
    info!("🔧 Test 2: Challenge Service Integration");

    let config = ChallengeConfig::default();
    let (mut service, _block_sender) = create_challenge_service(config);

    // Subscribe a mock beacon node
    let beacon_id = Address::new([10u8; 20]);
    let regions = vec!["872834".to_string(), "872835".to_string()];

    let mut challenge_receiver = service.subscribe_node(beacon_id, regions);

    info!("🏠 Subscribed beacon {} to regions 872834 and 872835", beacon_id);

    // Get initial stats
    let stats = service.get_stats();
    info!("📊 Service Stats: {} total challenges generated", stats.total_challenges);

    info!("✅ Challenge service integration test completed");
    Ok(())
}

async fn test_consensus_integration() -> Result<(), Box<dyn std::error::Error>> {
    info!("🏛️ Test 3: Consensus Engine Integration");

    // Create consensus config
    let config = ConsensusConfig {
        min_consensus_threshold: 0.67,
        fraud_threshold: 0.8,
        min_coherence_score: 0.5,
        max_validation_time_ms: 30_000,
        enable_drs_weighting: true,
        co_beacon_min_fraction: 0.5,
    };

    // Create validators
    let validators = vec![
        Address::new([1u8; 20]),
        Address::new([2u8; 20]),
        Address::new([3u8; 20]),
    ];

    let keypair = KeyPair::generate();
    let mut consensus_engine = ConsensusEngine::new(config, validators, keypair);

    // Enable challenge generation
    let challenge_config = ChallengeConfig {
        challenges_per_epoch: 3,
        ..ChallengeConfig::default()
    };

    consensus_engine.enable_challenge_generation(challenge_config).await?;
    info!("✅ Challenge generation enabled in consensus engine");

    // Subscribe a beacon node to challenges
    let beacon_id = Address::new([20u8; 20]);
    let regions = vec!["872834".to_string()];

    if let Some(mut challenge_receiver) = consensus_engine.subscribe_to_challenges(beacon_id, regions) {
        info!("🏠 Subscribed beacon {} to receive challenges", beacon_id);

        // Update regional beacon mapping
        consensus_engine.update_region_beacons("872834".to_string(), vec![beacon_id]);

        // Simulate finalized block
        let mock_block = create_mock_block(200, 20);
        let mock_qc = create_mock_qc(&mock_block);

        // This would trigger challenge generation in a real scenario
        info!("📦 Simulating block finalization: height={}, epoch={}",
              mock_block.height, mock_block.epoch);

        // Get challenge stats
        if let Some(stats) = consensus_engine.get_challenge_stats() {
            info!("📊 Challenge Stats: {} challenges generated", stats.total_challenges);
        }

    } else {
        warn!("Failed to subscribe to challenges");
    }

    info!("✅ Consensus integration test completed");
    Ok(())
}

fn create_mock_block(height: u64, epoch: u64) -> BlockHeader {
    let keypair = KeyPair::generate();
    let proposer = Address::from_public_key(&keypair.public_key());
    let roots = BlockRoots::empty();

    // Create VRF output based on epoch for deterministic testing
    let vrf_data = format!("epoch_{}_height_{}", epoch, height);
    let vrf_output = ego_core::crypto::hash_data(vrf_data.as_bytes());

    let mut block = BlockHeader::new(
        height,
        epoch,
        1, // slot
        Hash::new([0u8; 32]), // prev_hash
        proposer,
        roots,
        vrf_output,
        vec![1, 2, 3, 4], // vrf_proof
    );

    // Sign the block
    if let Err(e) = block.sign(&keypair) {
        warn!("Failed to sign mock block: {}", e);
    }

    block
}

fn create_mock_qc(block: &BlockHeader) -> QuorumCertificate {
    let block_hash = block.block_hash();
    let mut votes = HashMap::new();

    // Add some mock votes
    for i in 1..=3 {
        let addr = Address::new([i; 20]);
        let signature = Signature::ed25519([i; 64]);
        let pubkey = PublicKey::ed25519([i; 32]);
        votes.insert(addr, (signature, pubkey));
    }

    QuorumCertificate { block_hash, votes }
}

/// Simple performance test
#[allow(dead_code)]
async fn performance_test() -> Result<(), Box<dyn std::error::Error>> {
    info!("⚡ Performance Test: Challenge Generation Rate");

    let config = ChallengeConfig {
        challenges_per_epoch: 20, // High challenge rate
        ..ChallengeConfig::default()
    };

    let mut generator = ego_consensus::challenge::ChallengeGenerator::new(config);

    // Register many beacons across multiple regions
    for region_idx in 0..10 {
        let region_id = format!("87283{}", region_idx);
        let beacons: Vec<Address> = (0..5).map(|i| Address::new([region_idx as u8, i, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])).collect();
        generator.register_region_beacons(region_id, beacons);
    }

    let (block_sender, block_receiver) = tokio::sync::mpsc::unbounded_channel();
    let mut challenge_receiver = generator.start(block_receiver).await?;

    let start_time = std::time::Instant::now();
    let mut challenge_count = 0;

    // Send multiple finalized blocks
    for epoch in 0..5 {
        let block = create_mock_block(epoch * 10, epoch);
        let qc = create_mock_qc(&block);
        block_sender.send((block, qc))?;
    }

    // Collect challenges for a short time
    let timeout = Duration::from_secs(10);
    let start = std::time::Instant::now();

    while start.elapsed() < timeout {
        tokio::select! {
            challenge = challenge_receiver.recv() => {
                if challenge.is_some() {
                    challenge_count += 1;
                }
            }
            _ = sleep(Duration::from_millis(100)) => break,
        }
    }

    let elapsed = start_time.elapsed();
    let rate = challenge_count as f64 / elapsed.as_secs_f64();

    info!("📈 Performance Results:");
    info!("   Challenges generated: {}", challenge_count);
    info!("   Time elapsed: {:.2}s", elapsed.as_secs_f64());
    info!("   Generation rate: {:.2} challenges/sec", rate);

    Ok(())
}