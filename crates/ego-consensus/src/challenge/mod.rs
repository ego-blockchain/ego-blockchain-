pub mod generator;

pub use generator::{ChallengeGenerator, ChallengeConfig, GeneratedChallenge, GeneratorStats};

use crate::error::PoCResult;
use ego_core::{Address, Hash};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::mpsc;

#[derive(Debug)]
pub struct ChallengeService {

    generator: ChallengeGenerator,

    subscribers: HashMap<Address, mpsc::UnboundedSender<crate::types::Challenge>>,

    region_coverage: HashMap<String, Vec<Address>>,
}

impl ChallengeService {

    pub fn new(config: ChallengeConfig) -> Self {
        Self {
            generator: ChallengeGenerator::new(config),
            subscribers: HashMap::new(),
            region_coverage: HashMap::new(),
        }
    }

    pub async fn start(
        &mut self,
        block_receiver: mpsc::UnboundedReceiver<(crate::consensus::bft::BlockHeader, crate::consensus::bft::QuorumCertificate)>
    ) -> PoCResult<()> {

        let challenge_receiver = self.generator.start(block_receiver).await?;

        self.start_subscriber_distribution(challenge_receiver).await?;

        Ok(())
    }

    async fn start_subscriber_distribution(
        &self,
        mut challenge_receiver: mpsc::UnboundedReceiver<GeneratedChallenge>
    ) -> PoCResult<()> {
        tokio::spawn(async move {
            while let Some(generated_challenge) = challenge_receiver.recv().await {

                tracing::debug!(
                    "Received generated challenge for region {} epoch {} slot {}",
                    generated_challenge.region_id,
                    generated_challenge.epoch,
                    generated_challenge.slot
                );
            }
        });

        Ok(())
    }

    pub fn subscribe_node(&mut self, node_id: Address, regions: Vec<String>) -> mpsc::UnboundedReceiver<crate::types::Challenge> {
        let (sender, receiver) = mpsc::unbounded_channel();
        self.subscribers.insert(node_id, sender);

        for region in regions {
            self.region_coverage.entry(region.clone())
                .or_insert_with(Vec::new)
                .push(node_id);

            self.generator.register_region_beacons(region, vec![node_id]);
        }

        receiver
    }

    pub fn get_stats(&self) -> GeneratorStats {
        self.generator.get_stats()
    }

    pub fn update_region_beacons(&self, region_id: String, beacons: Vec<Address>) {
        self.generator.register_region_beacons(region_id, beacons);
    }
}

pub fn create_challenge_service(
    config: ChallengeConfig
) -> (ChallengeService, mpsc::UnboundedSender<(crate::consensus::bft::BlockHeader, crate::consensus::bft::QuorumCertificate)>) {
    let service = ChallengeService::new(config);
    let (block_sender, _block_receiver) = mpsc::unbounded_channel();

    (service, block_sender)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::bft::{BlockHeader, QuorumCertificate, BlockRoots};
    use ego_core::{Hash, Timestamp, KeyPair};

    #[tokio::test]
    async fn test_challenge_service_creation() {
        let config = ChallengeConfig::default();
        let service = ChallengeService::new(config);

        let stats = service.get_stats();
        assert_eq!(stats.total_challenges, 0);
    }

    #[test]
    fn test_factory_function() {
        let config = ChallengeConfig::default();
        let (service, _block_sender) = create_challenge_service(config);

        let stats = service.get_stats();
        assert_eq!(stats.total_challenges, 0);
    }

    #[tokio::test]
    async fn test_node_subscription() {
        let config = ChallengeConfig::default();
        let mut service = ChallengeService::new(config);

        let node_id = Address::new([1u8; 20]);
        let regions = vec!["872834".to_string(), "872835".to_string()];

        let _receiver = service.subscribe_node(node_id, regions);

        assert!(service.subscribers.contains_key(&node_id));

        assert!(service.region_coverage.contains_key("872834"));
        assert!(service.region_coverage.contains_key("872835"));
        assert!(service.region_coverage["872834"].contains(&node_id));
        assert!(service.region_coverage["872835"].contains(&node_id));
    }

    fn create_mock_block() -> BlockHeader {
        let keypair = KeyPair::generate();
        let proposer = Address::from_public_key(&keypair.public_key());
        let roots = BlockRoots::empty();
        let vrf_output = Hash::new([42u8; 32]);

        BlockHeader::new(
            100,
            10,
            1,
            Hash::new([0u8; 32]),
            proposer,
            roots,
            vrf_output,
            vec![1, 2, 3, 4],
        )
    }

    #[allow(dead_code)]
    fn create_mock_qc() -> crate::consensus::bft::QuorumCertificate {

        use crate::consensus::bft::{QuorumCertificate, Vote};
        use ego_core::{Hash, Address, Signature, PublicKey, Timestamp, KeyPair};

        let block_hash = Hash::new([1u8; 32]);

        let keypair = KeyPair::generate();

        let vote = Vote::new(block_hash, 1, 1, 1, &keypair).unwrap();

        QuorumCertificate::new(block_hash, 1, 1, 1, &[vote])
    }
}
