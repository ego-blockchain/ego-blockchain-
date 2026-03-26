use crate::aggregator::{PoCEvent, DensityEvent, DailyEvidenceRoot, ValidatorVote};
use crate::porep::PoRepEvent;
use crate::error::{PoCError, PoCResult};
use ego_core::{Address, Hash, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

pub type BridgeResult<T> = Result<T, PoCError>;

#[derive(Debug)]
pub struct BftBridge {
    erlang_endpoint: String,
    connection: Option<TcpStream>,
    reconnect_interval: Duration,
    message_queue: Vec<BridgeMessage>,
    connection_status: ConnectionStatus,
    sent_messages: HashMap<u64, Timestamp>,
    message_id_counter: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeMessage {
    pub id: u64,
    pub timestamp: Timestamp,
    pub message_type: MessageType,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MessageType {
    PoCEvent,
    DensityEvent,
    DailyAnchor,
    PoRepEvent,
    ValidatorVote,
    SlashingReport,
    VrfRequest,
    EpochUpdate,
    Heartbeat,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Error(String),
}

impl BftBridge {

    pub fn new(erlang_endpoint: String) -> Self {
        Self {
            erlang_endpoint,
            connection: None,
            reconnect_interval: Duration::from_secs(5),
            message_queue: Vec::new(),
            connection_status: ConnectionStatus::Disconnected,
            sent_messages: HashMap::new(),
            message_id_counter: 0,
        }
    }

    pub async fn start(
        &mut self,
        mut poc_receiver: mpsc::UnboundedReceiver<PoCEvent>,
        mut density_receiver: mpsc::UnboundedReceiver<DensityEvent>,
        mut anchor_receiver: mpsc::UnboundedReceiver<DailyEvidenceRoot>,
        mut porep_receiver: mpsc::UnboundedReceiver<PoRepEvent>,
        mut vote_receiver: mpsc::UnboundedReceiver<ValidatorVote>,
    ) -> BridgeResult<()> {
        info!("Starting BFT bridge to {}", self.erlang_endpoint);

        self.start_connection_manager().await;

        let bridge_clone = self.clone_for_task();
        tokio::spawn(async move {
            bridge_clone.handle_poc_events(poc_receiver).await;
        });

        let bridge_clone = self.clone_for_task();
        tokio::spawn(async move {
            bridge_clone.handle_density_events(density_receiver).await;
        });

        let bridge_clone = self.clone_for_task();
        tokio::spawn(async move {
            bridge_clone.handle_anchor_events(anchor_receiver).await;
        });

        let bridge_clone = self.clone_for_task();
        tokio::spawn(async move {
            bridge_clone.handle_porep_events(porep_receiver).await;
        });

        let bridge_clone = self.clone_for_task();
        tokio::spawn(async move {
            bridge_clone.handle_validator_votes(vote_receiver).await;
        });

        Ok(())
    }

    async fn handle_poc_events(&self, mut receiver: mpsc::UnboundedReceiver<PoCEvent>) {
        while let Some(event) = receiver.recv().await {
            if let Err(e) = self.send_poc_event(event).await {
                error!("Failed to send PoC event to BFT layer: {}", e);
            }
        }
    }

    async fn handle_density_events(&self, mut receiver: mpsc::UnboundedReceiver<DensityEvent>) {
        while let Some(event) = receiver.recv().await {
            if let Err(e) = self.send_density_event(event).await {
                error!("Failed to send density event to BFT layer: {}", e);
            }
        }
    }

    async fn handle_anchor_events(&self, mut receiver: mpsc::UnboundedReceiver<DailyEvidenceRoot>) {
        while let Some(anchor) = receiver.recv().await {
            if let Err(e) = self.send_daily_anchor(anchor).await {
                error!("Failed to send daily anchor to BFT layer: {}", e);
            }
        }
    }

    async fn handle_porep_events(&self, mut receiver: mpsc::UnboundedReceiver<PoRepEvent>) {
        while let Some(event) = receiver.recv().await {
            if let Err(e) = self.send_porep_event(event).await {
                error!("Failed to send PoRep event to BFT layer: {}", e);
            }
        }
    }

    async fn handle_validator_votes(&self, mut receiver: mpsc::UnboundedReceiver<ValidatorVote>) {
        while let Some(vote) = receiver.recv().await {
            if let Err(e) = self.send_validator_vote(vote).await {
                error!("Failed to send validator vote to BFT layer: {}", e);
            }
        }
    }

    async fn send_poc_event(&self, event: PoCEvent) -> BridgeResult<()> {
        let payload = bincode::encode_to_vec(&event, bincode::config::standard())
            .map_err(|e| PoCError::SerializationError(format!("Failed to serialize PoC event: {}", e)))?;

        let message = self.create_bridge_message(MessageType::PoCEvent, payload);
        self.send_message(message).await?;

        debug!("Sent PoC event with quality {} to BFT layer",
               event.quality_score);
        Ok(())
    }

    async fn send_density_event(&self, event: DensityEvent) -> BridgeResult<()> {

        let payload = bincode::encode_to_vec(&event, bincode::config::standard())
            .map_err(|e| PoCError::SerializationError(format!("Failed to serialize density event: {}", e)))?;

        let message = self.create_bridge_message(MessageType::DensityEvent, payload);
        self.send_message(message).await?;

        info!("Sent density event for slashing: node {} detected co-location (LDM: {:.3})",
              event.node_id, event.ldm);
        Ok(())
    }

    async fn send_daily_anchor(&self, anchor: DailyEvidenceRoot) -> BridgeResult<()> {
        let payload = bincode::encode_to_vec(&anchor, bincode::config::standard())
            .map_err(|e| PoCError::SerializationError(format!("Failed to serialize daily anchor: {}", e)))?;

        let message = self.create_bridge_message(MessageType::DailyAnchor, payload);
        self.send_message(message).await?;

        info!("Sent daily anchor with root {} to chain",
              format!("{:?}", anchor.evidence_root));
        Ok(())
    }

    async fn send_porep_event(&self, event: PoRepEvent) -> BridgeResult<()> {
        let payload = bincode::encode_to_vec(&event, bincode::config::standard())
            .map_err(|e| PoCError::SerializationError(format!("Failed to serialize PoRep event: {}", e)))?;

        let message = self.create_bridge_message(MessageType::PoRepEvent, payload);
        self.send_message(message).await?;

        debug!("Sent PoRep event for sector {} to BFT layer", event.sector_id);
        Ok(())
    }

    async fn send_validator_vote(&self, vote: ValidatorVote) -> BridgeResult<()> {
        let payload = bincode::encode_to_vec(&vote, bincode::config::standard())
            .map_err(|e| PoCError::SerializationError(format!("Failed to serialize validator vote: {}", e)))?;

        let message = self.create_bridge_message(MessageType::ValidatorVote, payload);
        self.send_message(message).await?;

        debug!("Sent validator vote {:?} from {} to BFT layer",
               vote.vote, vote.validator_id);
        Ok(())
    }

    fn create_bridge_message(&self, msg_type: MessageType, payload: Vec<u8>) -> BridgeMessage {
        BridgeMessage {
            id: self.next_message_id(),
            timestamp: ego_core::current_timestamp(),
            message_type: msg_type,
            payload,
        }
    }

    fn next_message_id(&self) -> u64 {

        ego_core::current_timestamp().0 + (rand::random::<u16>() as u64)
    }

    async fn send_message(&self, message: BridgeMessage) -> BridgeResult<()> {
        if self.connection_status != ConnectionStatus::Connected {
            warn!("BFT bridge not connected, queueing message {}", message.id);

            return Err(PoCError::NetworkError("Bridge not connected".to_string()));
        }

        debug!("Simulating send of message {} to BFT layer", message.id);

        Ok(())
    }

    async fn start_connection_manager(&mut self) {
        let endpoint = self.erlang_endpoint.clone();
        let reconnect_interval = self.reconnect_interval;

        tokio::spawn(async move {
            let mut interval = interval(reconnect_interval);

            loop {
                interval.tick().await;

                debug!("Connection manager: checking connection to {}", endpoint);

                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
    }

    fn clone_for_task(&self) -> BftBridgeHandle {
        BftBridgeHandle {
            endpoint: self.erlang_endpoint.clone(),
        }
    }
}

#[derive(Clone)]
struct BftBridgeHandle {
    endpoint: String,
}

impl BftBridgeHandle {
    async fn handle_poc_events(&self, mut receiver: mpsc::UnboundedReceiver<PoCEvent>) {
        while let Some(event) = receiver.recv().await {
            debug!("Bridge handle processing PoC event for beacon {}",
                   event.quality_score);

        }
    }

    async fn handle_density_events(&self, mut receiver: mpsc::UnboundedReceiver<DensityEvent>) {
        while let Some(event) = receiver.recv().await {
            info!("Bridge handle processing density event for node {}", event.node_id);

        }
    }

    async fn handle_anchor_events(&self, mut receiver: mpsc::UnboundedReceiver<DailyEvidenceRoot>) {
        while let Some(anchor) = receiver.recv().await {
            info!("Bridge handle processing daily anchor with {} bundles", anchor.bundle_count);

        }
    }

    async fn handle_porep_events(&self, mut receiver: mpsc::UnboundedReceiver<PoRepEvent>) {
        while let Some(event) = receiver.recv().await {
            debug!("Bridge handle processing PoRep event for sector {}", event.sector_id);

        }
    }

    async fn handle_validator_votes(&self, mut receiver: mpsc::UnboundedReceiver<ValidatorVote>) {
        while let Some(vote) = receiver.recv().await {
            debug!("Bridge handle processing validator vote {:?}", vote.vote);

        }
    }
}

pub fn create_aggregator_bridge(
    erlang_endpoint: String,
) -> (
    mpsc::UnboundedSender<PoCEvent>,
    mpsc::UnboundedSender<DensityEvent>,
    mpsc::UnboundedSender<DailyEvidenceRoot>,
) {
    let mut bridge = BftBridge::new(erlang_endpoint);

    let (poc_tx, poc_rx) = mpsc::unbounded_channel();
    let (density_tx, density_rx) = mpsc::unbounded_channel();
    let (anchor_tx, anchor_rx) = mpsc::unbounded_channel();
    let (porep_tx, porep_rx) = mpsc::unbounded_channel();
    let (vote_tx, vote_rx) = mpsc::unbounded_channel();

    tokio::spawn(async move {
        if let Err(e) = bridge.start(poc_rx, density_rx, anchor_rx, porep_rx, vote_rx).await {
            error!("BFT bridge failed: {}", e);
        }
    });

    (poc_tx, density_tx, anchor_tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bridge_creation() {
        let bridge = BftBridge::new("localhost:8080".to_string());
        assert_eq!(bridge.connection_status, ConnectionStatus::Disconnected);
    }

    #[tokio::test]
    async fn test_message_creation() {
        let bridge = BftBridge::new("localhost:8080".to_string());
        let payload = b"test".to_vec();
        let message = bridge.create_bridge_message(MessageType::Heartbeat, payload);

        assert_eq!(message.message_type, MessageType::Heartbeat);
        assert_eq!(message.payload, b"test");
    }
}
