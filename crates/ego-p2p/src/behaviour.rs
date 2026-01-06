use libp2p::{autonat, gossipsub, identify, kad, mdns, ping, swarm::NetworkBehaviour};

#[derive(NetworkBehaviour)]
pub struct EgoBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub ping: ping::Behaviour,
    pub autonat: autonat::Behaviour,
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

        Ok(Self {
            gossipsub,
            kademlia,
            identify,
            mdns,
            ping,
            autonat,
        })
    }
}
