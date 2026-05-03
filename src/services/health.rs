use std::collections::VecDeque;

use crate::utils::*;
use crate::{config::PortoConfig, services::proxy::PeerConnector, utils::*};

#[derive(Clone)]
pub struct HealthService {
    connector: PeerConnector,
    peers: PeerTable,
    alive_backends: Queue<PeerId>,
}

impl HealthService {
    pub fn new(peers: PeerTable) -> Self {
        HealthService {
            connector: PeerConnector::new(1),
            peers,
            alive_backends: Queue::new(100),
        }
    }
}

fn setup_health_service(config: &PortoConfig, peers: PeerTable) {
    // if svc enabled
    let svc = HealthService::new(peers);
    tokio::spawn(async {});
}
