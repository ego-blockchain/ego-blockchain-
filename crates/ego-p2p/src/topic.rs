use crate::{P2PResult, TopicInfo};
use dashmap::DashMap;
use ego_core::{ShardId, Timestamp};
use libp2p::gossipsub::IdentTopic;
use std::sync::Arc;

pub struct TopicManager {
    topics: Arc<DashMap<String, TopicInfo>>,
    shard_topics: Arc<DashMap<u32, Vec<String>>>,
}

impl TopicManager {
    pub fn new() -> Self {
        Self {
            topics: Arc::new(DashMap::new()),
            shard_topics: Arc::new(DashMap::new()),
        }
    }

    pub fn register_topic(&self, name: String, shard_id: Option<ShardId>) -> P2PResult<()> {
        if self.topics.contains_key(&name) {
            return Ok(());
        }
        let topic_info = TopicInfo {
            name: name.clone(),
            shard_id,
            subscriber_count: 0,
            message_count: 0,
            created_at: Timestamp::now(),
        };
        self.topics.insert(name.clone(), topic_info);
        if let Some(shard) = shard_id {
            self.shard_topics
                .entry(shard.as_u32())
                .or_insert_with(Vec::new)
                .push(name);
        }
        Ok(())
    }

    pub fn get_topic(&self, name: &str) -> Option<TopicInfo> {
        self.topics.get(name).map(|entry| entry.clone())
    }

    pub fn increment_message_count(&self, topic_name: &str) {
        if let Some(mut entry) = self.topics.get_mut(topic_name) {
            entry.message_count += 1;
        }
    }

    pub fn update_subscriber_count(&self, topic_name: &str, count: usize) {
        if let Some(mut entry) = self.topics.get_mut(topic_name) {
            entry.subscriber_count = count;
        }
    }

    pub fn get_shard_topics(&self, shard_id: ShardId) -> Vec<String> {
        self.shard_topics
            .get(&shard_id.as_u32())
            .map(|entry| entry.clone())
            .unwrap_or_default()
    }

    pub fn get_all_topics(&self) -> Vec<TopicInfo> {
        self.topics
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn remove_topic(&self, name: &str) -> P2PResult<()> {
        if let Some((_, topic_info)) = self.topics.remove(name) {
            if let Some(shard_id) = topic_info.shard_id {
                if let Some(mut topics) = self.shard_topics.get_mut(&shard_id.as_u32()) {
                    topics.retain(|t| t != name);
                }
            }
        }
        Ok(())
    }

    pub fn build_topic_name(prefix: &str, shard_id: Option<u32>, suffix: &str) -> String {
        match shard_id {
            Some(shard) => format!("{}/shard/{}/{}", prefix, shard, suffix),
            None => format!("{}/global/{}", prefix, suffix),
        }
    }

    pub fn create_ident_topic(name: &str) -> IdentTopic {
        IdentTopic::new(name)
    }

    pub fn get_message_count(&self, topic_name: &str) -> u64 {
        self.topics
            .get(topic_name)
            .map(|entry| entry.message_count)
            .unwrap_or(0)
    }

    pub fn get_subscriber_count(&self, topic_name: &str) -> usize {
        self.topics
            .get(topic_name)
            .map(|entry| entry.subscriber_count)
            .unwrap_or(0)
    }
}

impl Default for TopicManager {
    fn default() -> Self {
        Self::new()
    }
}

pub fn get_standard_topics(shard_ids: &[u32]) -> Vec<(String, Option<ShardId>)> {
    let mut topics = Vec::new();
    topics.push(("ego/global/finality".to_string(), None));
    topics.push(("ego/global/consensus".to_string(), None));
    topics.push(("ego/global/storage".to_string(), None));
    topics.push(("ego/global/rollup".to_string(), None));
    for &shard_id in shard_ids {
        let shard = ShardId::new(shard_id).ok();
        topics.push((
            TopicManager::build_topic_name("ego", Some(shard_id), "tx"),
            shard,
        ));
        topics.push((
            TopicManager::build_topic_name("ego", Some(shard_id), "headers"),
            shard,
        ));
        topics.push((
            TopicManager::build_topic_name("ego", Some(shard_id), "receipts"),
            shard,
        ));
        topics.push((
            TopicManager::build_topic_name("ego", Some(shard_id), "proofs"),
            shard,
        ));
        topics.push((
            TopicManager::build_topic_name("ego", Some(shard_id), "consensus"),
            shard,
        ));
    }
    topics
}
