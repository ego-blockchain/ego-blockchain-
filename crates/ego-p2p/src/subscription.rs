use crate::P2PResult;
use dashmap::DashMap;
use ego_core::ShardId;
use libp2p::PeerId;
use std::collections::HashSet;
use std::sync::Arc;

pub struct SubscriptionManager {
    topic_subscribers: Arc<DashMap<String, HashSet<PeerId>>>,
    peer_subscriptions: Arc<DashMap<PeerId, HashSet<String>>>,
    topic_authorization: Arc<DashMap<String, HashSet<PeerId>>>,
    authorized_topics: Arc<DashMap<PeerId, HashSet<String>>>,
}

impl SubscriptionManager {
    pub fn new() -> Self {
        Self {
            topic_subscribers: Arc::new(DashMap::new()),
            peer_subscriptions: Arc::new(DashMap::new()),
            topic_authorization: Arc::new(DashMap::new()),
            authorized_topics: Arc::new(DashMap::new()),
        }
    }

    pub fn add_subscription(&self, topic: String, peer_id: PeerId) -> P2PResult<()> {
        self.topic_subscribers
            .entry(topic.clone())
            .or_insert_with(HashSet::new)
            .insert(peer_id);
        self.peer_subscriptions
            .entry(peer_id)
            .or_insert_with(HashSet::new)
            .insert(topic);
        Ok(())
    }

    pub fn remove_subscription(&self, topic: &str, peer_id: &PeerId) -> P2PResult<()> {
        if let Some(mut subscribers) = self.topic_subscribers.get_mut(topic) {
            subscribers.remove(peer_id);
        }
        if let Some(mut topics) = self.peer_subscriptions.get_mut(peer_id) {
            topics.remove(topic);
        }
        Ok(())
    }

    pub fn authorize_peer_for_topic(&self, topic: String, peer_id: PeerId) -> P2PResult<()> {
        self.topic_authorization
            .entry(topic.clone())
            .or_insert_with(HashSet::new)
            .insert(peer_id);
        self.authorized_topics
            .entry(peer_id)
            .or_insert_with(HashSet::new)
            .insert(topic);
        Ok(())
    }

    pub fn revoke_topic_authorization(&self, topic: &str, peer_id: &PeerId) -> P2PResult<()> {
        if let Some(mut authorized) = self.topic_authorization.get_mut(topic) {
            authorized.remove(peer_id);
        }
        if let Some(mut topics) = self.authorized_topics.get_mut(peer_id) {
            topics.remove(topic);
        }
        Ok(())
    }

    pub fn is_peer_authorized_for_topic(&self, topic: &str, peer_id: &PeerId) -> bool {
        self.topic_authorization
            .get(topic)
            .map(|authorized| authorized.contains(peer_id))
            .unwrap_or(false)
    }

    pub fn get_authorized_peers_for_topic(&self, topic: &str) -> Vec<PeerId> {
        self.topic_authorization
            .get(topic)
            .map(|authorized| authorized.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn get_peer_authorized_topics(&self, peer_id: &PeerId) -> Vec<String> {
        self.authorized_topics
            .get(peer_id)
            .map(|topics| topics.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn get_topic_subscribers(&self, topic: &str) -> Vec<PeerId> {
        self.topic_subscribers
            .get(topic)
            .map(|subscribers| subscribers.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn get_peer_subscriptions(&self, peer_id: &PeerId) -> Vec<String> {
        self.peer_subscriptions
            .get(peer_id)
            .map(|topics| topics.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn get_subscriber_count(&self, topic: &str) -> usize {
        self.topic_subscribers
            .get(topic)
            .map(|subscribers| subscribers.len())
            .unwrap_or(0)
    }

    pub fn remove_peer(&self, peer_id: &PeerId) {
        if let Some((_, topics)) = self.peer_subscriptions.remove(peer_id) {
            for topic in topics {
                if let Some(mut subscribers) = self.topic_subscribers.get_mut(&topic) {
                    subscribers.remove(peer_id);
                }
            }
        }
        if let Some((_, topics)) = self.authorized_topics.remove(peer_id) {
            for topic in topics {
                if let Some(mut authorized) = self.topic_authorization.get_mut(&topic) {
                    authorized.remove(peer_id);
                }
            }
        }
    }

    pub fn get_all_topics(&self) -> Vec<String> {
        self.topic_subscribers
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    pub fn get_shard_subscribers(&self, shard_id: ShardId) -> Vec<PeerId> {
        let mut subscribers = HashSet::new();
        for entry in self.topic_subscribers.iter() {
            if entry
                .key()
                .contains(&format!("/shard/{}/", shard_id.as_u32()))
            {
                subscribers.extend(entry.value().iter());
            }
        }
        subscribers.into_iter().collect()
    }

    pub fn clear(&self) {
        self.topic_subscribers.clear();
        self.peer_subscriptions.clear();
        self.topic_authorization.clear();
        self.authorized_topics.clear()
    }

    pub fn get_subscription_stats(&self) -> SubscriptionStats {
        SubscriptionStats {
            total_topics: self.topic_subscribers.len(),
            total_subscribers: self.peer_subscriptions.len(),
            total_authorizations: self.topic_authorization.len(),
        }
    }
}

impl Default for SubscriptionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct SubscriptionStats {
    pub total_topics: usize,
    pub total_subscribers: usize,
    pub total_authorizations: usize,
}
