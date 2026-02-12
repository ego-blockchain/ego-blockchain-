use crate::P2PMessage;
use crate::behaviour::{DaRequest, DaResponse, EvidenceRequest, EvidenceResponse};
use libp2p::{Multiaddr, PeerId, autonat, gossipsub, identify, kad, mdns, ping, request_response};

#[derive(Debug)]
pub enum NetworkEvent {
    Message {
        peer_id: PeerId,
        message: P2PMessage,
        topic: String,
    },
    PeerConnected {
        peer_id: PeerId,
    },
    PeerDisconnected {
        peer_id: PeerId,
    },
    PeerIdentified {
        peer_id: PeerId,
        info: identify::Info,
    },
    NewListenAddr {
        address: Multiaddr,
    },
    ExpiredListenAddr {
        address: Multiaddr,
    },
    PeerDiscovered {
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
    },
    ConnectionEstablished {
        peer_id: PeerId,
        endpoint: libp2p::core::ConnectedPoint,
        num_established: u32,
    },
    ConnectionClosed {
        peer_id: PeerId,
        endpoint: libp2p::core::ConnectedPoint,
        num_established: u32,
        cause: Option<libp2p::swarm::ConnectionError>,
    },
    IncomingConnection {
        connection_id: libp2p::swarm::ConnectionId,
        local_addr: Multiaddr,
        send_back_addr: Multiaddr,
    },
    OutgoingConnectionError {
        peer_id: Option<PeerId>,
        error: libp2p::swarm::DialError,
    },
    NatStatusChanged {
        status: autonat::NatStatus,
    },
    PingSuccess {
        peer_id: PeerId,
        rtt: std::time::Duration,
    },
    PingFailure {
        peer_id: PeerId,
    },
    GossipsubMessage {
        peer_id: PeerId,
        message_id: gossipsub::MessageId,
        topic: gossipsub::TopicHash,
        data: Vec<u8>,
    },
    GossipsubSubscribed {
        peer_id: PeerId,
        topic: gossipsub::TopicHash,
    },
    GossipsubUnsubscribed {
        peer_id: PeerId,
        topic: gossipsub::TopicHash,
    },
    KademliaQueryResult {
        query_id: kad::QueryId,
        result: kad::QueryResult,
    },
    KademliaPutRecord {
        key: Vec<u8>,
    },
    KademliaGetRecord {
        key: Vec<u8>,
    },
    KademliaStartProviding {
        key: Vec<u8>,
    },
    KademliaStopProviding {
        key: Vec<u8>,
    },
    KademliaProviderFound {
        key: Vec<u8>,
        providers: Vec<PeerId>,
    },
    MdnsDiscovered {
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
    },
    MdnsExpired {
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
    },
    DaRequest {
        peer_id: PeerId,
        request_id: request_response::InboundRequestId,
        request: DaRequest,
    },
    DaResponse {
        peer_id: PeerId,
        request_id: request_response::OutboundRequestId,
        response: DaResponse,
    },
    DaRequestFailed {
        peer_id: PeerId,
        request_id: request_response::OutboundRequestId,
        error: String,
    },
    EvidenceRequest {
        peer_id: PeerId,
        request_id: request_response::InboundRequestId,
        request: EvidenceRequest,
    },
    EvidenceResponse {
        peer_id: PeerId,
        request_id: request_response::OutboundRequestId,
        response: EvidenceResponse,
    },
    EvidenceRequestFailed {
        peer_id: PeerId,
        request_id: request_response::OutboundRequestId,
        error: String,
    },
    MessageValidated {
        peer_id: PeerId,
        message_id: gossipsub::MessageId,
        accepted: bool,
        reason: Option<String>,
    },
    IdentifyHandshakeFailed {
        peer_id: PeerId,
        reason: String,
    },
    PublishQueued {
        topic: String,
        queue_size: usize,
    },
    PublishDequeued {
        topic: String,
        queue_size: usize,
    },
    BackpressureActivated {
        topic: String,
        queue_size: usize,
    },
    BackpressureDeactivated {
        topic: String,
        queue_size: usize,
    },
}

pub struct EventHandler {
    tx: tokio::sync::mpsc::UnboundedSender<NetworkEvent>,
}

impl EventHandler {
    pub fn new(tx: tokio::sync::mpsc::UnboundedSender<NetworkEvent>) -> Self {
        Self { tx }
    }

    pub fn emit(&self, event: NetworkEvent) {
        let _ = self.tx.send(event);
    }

    pub fn handle_gossipsub_event(&self, event: gossipsub::Event) {
        match event {
            gossipsub::Event::Message {
                propagation_source,
                message_id,
                message,
            } => {
                self.emit(NetworkEvent::GossipsubMessage {
                    peer_id: propagation_source,
                    message_id,
                    topic: message.topic,
                    data: message.data,
                });
            }
            gossipsub::Event::Subscribed { peer_id, topic } => {
                self.emit(NetworkEvent::GossipsubSubscribed { peer_id, topic });
            }
            gossipsub::Event::Unsubscribed { peer_id, topic } => {
                self.emit(NetworkEvent::GossipsubUnsubscribed { peer_id, topic });
            }
            gossipsub::Event::GossipsubNotSupported { peer_id } => {
                tracing::warn!("Peer {} does not support gossipsub", peer_id);
            }
            gossipsub::Event::SlowPeer { peer_id, .. } => {
                tracing::warn!("Slow peer detected: {}", peer_id);
            }
        }
    }

    pub fn handle_identify_event(&self, event: identify::Event) {
        match event {
            identify::Event::Received { peer_id, info, .. } => {
                self.emit(NetworkEvent::PeerIdentified { peer_id, info });
            }
            identify::Event::Sent { .. } => {}
            identify::Event::Pushed { .. } => {}
            identify::Event::Error { peer_id, error, .. } => {
                tracing::warn!("Identify error with peer {}: {:?}", peer_id, error);
            }
        }
    }

    pub fn handle_kademlia_event(&self, event: kad::Event) {
        match event {
            kad::Event::OutboundQueryProgressed { id, result, .. } => {
                match &result {
                    kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders {
                        key,
                        providers,
                        ..
                    })) => {
                        self.emit(NetworkEvent::KademliaProviderFound {
                            key: key.to_vec(),
                            providers: providers.iter().copied().collect(),
                        });
                    }
                    kad::QueryResult::StartProviding(Ok(kad::AddProviderOk { key })) => {
                        self.emit(NetworkEvent::KademliaStartProviding { key: key.to_vec() });
                    }
                    kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(record))) => {
                        self.emit(NetworkEvent::KademliaGetRecord {
                            key: record.record.key.to_vec(),
                        });
                    }
                    kad::QueryResult::PutRecord(Ok(kad::PutRecordOk { key })) => {
                        self.emit(NetworkEvent::KademliaPutRecord { key: key.to_vec() });
                    }
                    _ => {}
                }
                self.emit(NetworkEvent::KademliaQueryResult {
                    query_id: id,
                    result,
                });
            }
            kad::Event::RoutingUpdated {
                peer,
                is_new_peer,
                addresses,
                ..
            } => {
                if is_new_peer {
                    self.emit(NetworkEvent::PeerDiscovered {
                        peer_id: peer,
                        addresses: addresses.into_vec(),
                    });
                }
            }
            kad::Event::InboundRequest { .. } => {}
            kad::Event::RoutablePeer { .. } => {}
            kad::Event::PendingRoutablePeer { .. } => {}
            kad::Event::UnroutablePeer { .. } => {}
            kad::Event::ModeChanged { .. } => {}
        }
    }

    pub fn handle_mdns_event(&self, event: mdns::Event) {
        match event {
            mdns::Event::Discovered(list) => {
                for (peer_id, multiaddr) in list {
                    self.emit(NetworkEvent::MdnsDiscovered {
                        peer_id,
                        addresses: vec![multiaddr],
                    });
                }
            }
            mdns::Event::Expired(list) => {
                for (peer_id, multiaddr) in list {
                    self.emit(NetworkEvent::MdnsExpired {
                        peer_id,
                        addresses: vec![multiaddr],
                    });
                }
            }
        }
    }

    pub fn handle_ping_event(&self, event: ping::Event, peer_id: PeerId) {
        match event.result {
            Ok(rtt) => {
                self.emit(NetworkEvent::PingSuccess { peer_id, rtt });
            }
            Err(_) => {
                self.emit(NetworkEvent::PingFailure { peer_id });
            }
        }
    }

    pub fn handle_autonat_event(&self, event: autonat::Event) {
        match event {
            autonat::Event::StatusChanged { new, .. } => {
                self.emit(NetworkEvent::NatStatusChanged { status: new });
            }
            _ => {}
        }
    }

    pub fn emit_message_validated(
        &self,
        peer_id: PeerId,
        message_id: gossipsub::MessageId,
        accepted: bool,
        reason: Option<String>,
    ) {
        self.emit(NetworkEvent::MessageValidated {
            peer_id,
            message_id,
            accepted,
            reason,
        });
    }

    pub fn emit_identify_handshake_failed(&self, peer_id: PeerId, reason: String) {
        self.emit(NetworkEvent::IdentifyHandshakeFailed { peer_id, reason });
    }

    pub fn emit_publish_queued(&self, topic: String, queue_size: usize) {
        self.emit(NetworkEvent::PublishQueued { topic, queue_size });
    }

    pub fn emit_publish_dequeued(&self, topic: String, queue_size: usize) {
        self.emit(NetworkEvent::PublishDequeued { topic, queue_size });
    }

    pub fn emit_backpressure_activated(&self, topic: String, queue_size: usize) {
        self.emit(NetworkEvent::BackpressureActivated { topic, queue_size });
    }

    pub fn emit_backpressure_deactivated(&self, topic: String, queue_size: usize) {
        self.emit(NetworkEvent::BackpressureDeactivated { topic, queue_size });
    }
}
