use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Once};
use std::time::Duration;

use porto::config::{PortoConfig, ProxyConfig};
use porto::utils::{Domain, PeerAddr};

use crate::common::backend::run_backends;
use crate::common::proxy::run_proxy;

pub mod backend;
pub mod client;
pub mod proxy;

const CERT_PATH: &str = "credentials/testpeer.com+3.pem";
const KEY_PATH: &str = "credentials/testpeer.com+3-key.pem";
const PROXY_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 4000);

pub static INIT: Once = Once::new();

pub fn setup_test_config(domains: &[&str], backends: &[&str]) -> Arc<PortoConfig> {
    assert!(domains.len() == backends.len());

    let mut config = PortoConfig::default();
    config.global.bind = Some(PROXY_ADDR);
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

    eprintln!("config: {config:#?}");
    Arc::new(config)
}

pub async fn setup_test_server(config: Arc<PortoConfig>) {
    INIT.call_once(|| {
        tokio::spawn(run_backends(config.clone()));
        tokio::spawn(run_proxy(config));
    });
    // sleep to give servers time to setup
    tokio::time::sleep(Duration::from_secs(5)).await;
}
