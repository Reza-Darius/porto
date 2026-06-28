use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Once};
use std::time::Duration;

use porto::config::{PortoConfig, ProxyConfig};
use porto::utils::{Domain, PeerAddr};
use tokio::task::JoinSet;

use crate::common::backend::run_backends;
use crate::common::proxy::run_proxy;

pub mod backend;
pub mod client;
pub mod proxy;

const CERT_PATH: &str = "credentials/testpeer.com+3.pem";
const KEY_PATH: &str = "credentials/testpeer.com+3-key.pem";
const PROXY_ADDR: &str = "127.0.0.1:4000";

pub static INIT: Once = Once::new();

pub fn setup_test_config(domains: &[&str], backends: &[&str]) -> PortoConfig {
    assert!(domains.len() == backends.len());

    let mut config = PortoConfig::default();
    config.global.bind = Some(PROXY_ADDR.parse().unwrap());
    config.tls.cert_path = Some(PathBuf::from_str(CERT_PATH).unwrap());
    config.tls.key_path = Some(PathBuf::from_str(KEY_PATH).unwrap());

    for i in 0..domains.len() {
        config.add_proxy(ProxyConfig {
            domain: Domain::parse(domains[i]).unwrap(),
            upstream: PeerAddr::parse(backends[i]).unwrap(),
            http2: false,
            config: Default::default(),
        });
    }
    config
}

pub fn setup_test_server(config: Arc<PortoConfig>) {
    // we spawn each server into their own thread to prevent server from going offline
    // when the runtime of each test shuts down
    INIT.call_once(|| {
        let cfg_clone = config.clone();

        std::thread::spawn(move || {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async move {
                    let mut handles = JoinSet::new();

                    handles.spawn(run_backends(cfg_clone));
                    handles.spawn(run_proxy(config));

                    handles.join_all().await;
                });
        });
    });
    // sleep to give servers time to setup
    std::thread::sleep(Duration::from_secs(5));
}
