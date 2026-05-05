use std::collections::VecDeque;

use crate::utils::*;
use crate::{config::PortoConfig, services::proxy::Http1Connector, utils::*};

#[derive(Clone)]
pub struct HealthService {
    peers: PeerTable,

    alive: Queue<PeerId>,
    dead: Queue<PeerId>,
    int: u64,
}

impl HealthService {
    pub fn new(peers: PeerTable) -> Self {
        HealthService {
            peers,
            alive: Queue::new(100),
            dead: Queue::new(100),
            int: 0,
        }
    }
}

fn setup_health_service(config: &PortoConfig, peers: PeerTable) {
    // if svc enabled
    let svc = HealthService::new(peers);
    tokio::spawn(async {});
}
