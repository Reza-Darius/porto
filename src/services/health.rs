use std::collections::VecDeque;

use crate::{config::PortoConfig, services::proxy::PeerConnector, utils::*};

#[derive(Clone)]
pub struct HealthService {
    connector: PeerConnector,
    peers: PeerTable,
    alive_backends: VecDeque<PeerId>,
}

impl HealthService {
    pub fn new(peers: PeerTable) -> Self {
        HealthService {
            connector: PeerConnector::new(1),
            peers,
            alive_backends: VecDeque::new(),
        }
    }
}

fn setup_health_service(config: &PortoConfig, peers: PeerTable) {
    // if svc enabled
    let svc = HealthService::new(peers);
    tokio::spawn(async {});
}
