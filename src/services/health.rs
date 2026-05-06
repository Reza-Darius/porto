#![allow(dead_code, unused_variables)]
use std::time::Duration;

use crate::utils::*;

// this is a singleton running in the background
pub struct HealthService {
    peers: PeerTable,

    /// this queue corresponds with the alive_backend table
    alive: Queue<PeerId>,
    /// this is a unique queue only the health worker cares about
    dead: Queue<PeerId>,
    /// health check interval
    alive_int: Duration,
    dead_int: Duration,
}

pub struct HealthServiceConfig {
    alive_check_interval: Duration,
    dead_check_interval: Duration,
}

impl Default for HealthServiceConfig {
    fn default() -> Self {
        HealthServiceConfig {
            alive_check_interval: Duration::from_secs(30),
            dead_check_interval: Duration::from_secs(60),
        }
    }
}

impl HealthService {
    pub fn new(peers: PeerTable, config: HealthServiceConfig) -> Self {
        HealthService {
            peers,
            alive: Queue::new(100),
            dead: Queue::new(100),
            alive_int: config.alive_check_interval,
            dead_int: config.dead_check_interval,
        }
    }
}

pub fn setup_health_service(peers: PeerTable, config: HealthServiceConfig) {
    let svc = HealthService::new(peers, config);
    tokio::spawn(async {});
}
