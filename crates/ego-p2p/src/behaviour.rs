use async_trait::async_trait;
use bincode::config;
use futures::prelude::*;
use libp2p::request_response::{Codec, ProtocolSupport};
use libp2p::{
    autonat, gossipsub, identify, kad, mdns, ping, request_response, swarm::NetworkBehaviour,
};
use std::io;

#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub struct DaRequest {
    pub blob_id: Vec<u8>,
    pub chunk_index: u64,
}

#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub struct DaResponse {
    pub chunk_data: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub struct EvidenceRequest {
    pub cid: Vec<u8>,
}

#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub struct EvidenceResponse {
    pub bundle_data: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Default)]
pub struct DaCodec;

#[async_trait]
impl Codec for DaCodec {
    type Protocol = String;
    type Request = DaRequest;
    type Response = DaResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;
        bincode::decode_from_slice(&buf, config::standard())
            .map(|(req, _)| req)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;
        bincode::decode_from_slice(&buf, config::standard())
            .map(|(resp, _)| resp)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = bincode::encode_to_vec(&req, config::standard())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        io.write_all(&bytes).await?;
        io.close().await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = bincode::encode_to_vec(&res, config::standard())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        io.write_all(&bytes).await?;
        io.close().await
    }
}

#[derive(Clone, Default)]
pub struct EvidenceCodec;

#[async_trait]
impl Codec for EvidenceCodec {
    type Protocol = String;
    type Request = EvidenceRequest;
    type Response = EvidenceResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;
        bincode::decode_from_slice(&buf, config::standard())
            .map(|(req, _)| req)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;
        bincode::decode_from_slice(&buf, config::standard())
            .map(|(resp, _)| resp)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = bincode::encode_to_vec(&req, config::standard())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        io.write_all(&bytes).await?;
        io.close().await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = bincode::encode_to_vec(&res, config::standard())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        io.write_all(&bytes).await?;
        io.close().await
    }
}

#[derive(NetworkBehaviour)]
pub struct EgoBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub ping: ping::Behaviour,
    pub autonat: autonat::Behaviour,
    pub da_fetch: request_response::Behaviour<DaCodec>,
    pub evidence_fetch: request_response::Behaviour<EvidenceCodec>,
}

impl EgoBehaviour {
    pub fn new(
        keypair: &libp2p::identity::Keypair,
        peer_id: libp2p::PeerId,
        enable_mdns: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(std::time::Duration::from_secs(10))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .max_transmit_size(2 * 1024 * 1024)
            .duplicate_cache_time(std::time::Duration::from_secs(120))
            .message_id_fn(|message| {
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut hasher = DefaultHasher::new();
                message.data.hash(&mut hasher);
                gossipsub::MessageId::from(hasher.finish().to_string().into_bytes())
            })
            .build()
            .map_err(|e| format!("Gossipsub config error: {}", e))?;
        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(keypair.clone()),
            gossipsub_config,
        )
        .map_err(|e| format!("Gossipsub creation error: {}", e))?;
        let mut kademlia_config = kad::Config::default();
        kademlia_config.set_query_timeout(std::time::Duration::from_secs(60));
        kademlia_config.set_replication_factor(std::num::NonZeroUsize::new(5).unwrap());
        kademlia_config.set_parallelism(std::num::NonZeroUsize::new(3).unwrap());
        kademlia_config.set_record_ttl(Some(std::time::Duration::from_secs(24 * 60 * 60)));
        kademlia_config.set_provider_record_ttl(Some(std::time::Duration::from_secs(24 * 60 * 60)));
        kademlia_config
            .set_provider_publication_interval(Some(std::time::Duration::from_secs(12 * 60 * 60)));
        let store = kad::store::MemoryStore::new(peer_id);
        let kademlia = kad::Behaviour::with_config(peer_id, store, kademlia_config);
        let identify = identify::Behaviour::new(
            identify::Config::new("/ego/1.0.0".to_string(), keypair.public())
                .with_interval(std::time::Duration::from_secs(30))
                .with_push_listen_addr_updates(true),
        );
        let mdns = if enable_mdns {
            mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)?
        } else {
            mdns::tokio::Behaviour::new(
                mdns::Config {
                    ttl: std::time::Duration::from_secs(6 * 60),
                    query_interval: std::time::Duration::from_secs(5 * 60),
                    enable_ipv6: false,
                },
                peer_id,
            )?
        };
        let ping = ping::Behaviour::new(
            ping::Config::new()
                .with_interval(std::time::Duration::from_secs(30))
                .with_timeout(std::time::Duration::from_secs(10)),
        );
        let autonat = autonat::Behaviour::new(
            peer_id,
            autonat::Config {
                retry_interval: std::time::Duration::from_secs(30),
                refresh_interval: std::time::Duration::from_secs(300),
                boot_delay: std::time::Duration::from_secs(5),
                throttle_server_period: std::time::Duration::from_secs(1),
                only_global_ips: false,
                ..Default::default()
            },
        );
        let da_fetch = request_response::Behaviour::new(
            [("/ego/da/1.0".to_string(), ProtocolSupport::Full)],
            request_response::Config::default()
                .with_request_timeout(std::time::Duration::from_secs(30))
                .with_max_concurrent_streams(100),
        );
        let evidence_fetch = request_response::Behaviour::new(
            [("/ego/evidence/1.0".to_string(), ProtocolSupport::Full)],
            request_response::Config::default()
                .with_request_timeout(std::time::Duration::from_secs(30))
                .with_max_concurrent_streams(100),
        );
        Ok(Self {
            gossipsub,
            kademlia,
            identify,
            mdns,
            ping,
            autonat,
            da_fetch,
            evidence_fetch,
        })
    }

    pub fn connected_peers_count(&self) -> usize {
        self.gossipsub.all_peers().count()
    }

    pub fn gossipsub_peers_count(&self) -> usize {
        self.gossipsub.all_peers().count()
    }

    pub fn topic_peer_count(&self, topic: &gossipsub::TopicHash) -> usize {
        self.gossipsub.mesh_peers(topic).count()
    }
}
