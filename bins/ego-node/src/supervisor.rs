use serde::Serialize;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, RwLock};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum ComponentStatus {
    Healthy,
    Degraded,
    Failed,
    Restarting,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComponentHealth {
    pub name:      String,
    pub status:    ComponentStatus,
    pub restarts:  u32,
    pub last_seen: Option<std::time::SystemTime>,
    pub error:     Option<String>,
}

#[derive(Clone)]
pub struct Heartbeat {
    tx: mpsc::Sender<String>,
}

impl Heartbeat {
    pub async fn ping(&self, component: &str) {
        let _ = self.tx.send(component.to_string()).await;
    }
}

pub struct NodeSupervisor {
    components:   RwLock<Vec<ComponentHealth>>,
    #[allow(dead_code)]
    heartbeat_tx: mpsc::Sender<String>,
    start_time:   Instant,
}

impl NodeSupervisor {
    pub fn new() -> (Arc<Self>, Heartbeat) {
        let (tx, mut rx) = mpsc::channel::<String>(256);
        let supervisor = Arc::new(Self {
            components: RwLock::new(vec![
                ComponentHealth {
                    name:      "consensus".into(),
                    status:    ComponentStatus::Healthy,
                    restarts:  0,
                    last_seen: None,
                    error:     None,
                },
                ComponentHealth {
                    name:      "execution".into(),
                    status:    ComponentStatus::Healthy,
                    restarts:  0,
                    last_seen: None,
                    error:     None,
                },
                ComponentHealth {
                    name:      "p2p".into(),
                    status:    ComponentStatus::Healthy,
                    restarts:  0,
                    last_seen: None,
                    error:     None,
                },
                ComponentHealth {
                    name:      "rpc".into(),
                    status:    ComponentStatus::Healthy,
                    restarts:  0,
                    last_seen: None,
                    error:     None,
                },
                ComponentHealth {
                    name:      "storage".into(),
                    status:    ComponentStatus::Healthy,
                    restarts:  0,
                    last_seen: None,
                    error:     None,
                },
            ]),
            heartbeat_tx: tx.clone(),
            start_time:   Instant::now(),
        });

        let sup_clone = supervisor.clone();
        tokio::spawn(async move {
            while let Some(component_name) = rx.recv().await {
                let mut components = sup_clone.components.write().await;
                if let Some(c) = components.iter_mut().find(|c| c.name == component_name) {
                    c.status    = ComponentStatus::Healthy;
                    c.last_seen = Some(std::time::SystemTime::now());
                }
            }
        });

        let heartbeat = Heartbeat { tx };
        (supervisor, heartbeat)
    }

    pub async fn report_failure(&self, component: &str, error: String) {
        let mut components = self.components.write().await;
        if let Some(c) = components.iter_mut().find(|c| c.name == component) {
            c.status   = ComponentStatus::Failed;
            c.error    = Some(error);
            c.restarts += 1;
        }
    }

    pub async fn health(&self) -> NodeHealth {
        let components   = self.components.read().await;
        let any_failed   = components.iter().any(|c| c.status == ComponentStatus::Failed);
        let any_degraded = components.iter().any(|c| c.status == ComponentStatus::Degraded);
        NodeHealth {
            status: if any_failed || any_degraded {
                "degraded".into()
            } else {
                "healthy".into()
            },
            uptime_secs: self.start_time.elapsed().as_secs(),
            components:  components.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct NodeHealth {
    pub status:      String,
    pub uptime_secs: u64,
    pub components:  Vec<ComponentHealth>,
}
