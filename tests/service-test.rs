use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use porto::config::{PortoConfig, ProxyConfig};
use porto::utils::{Domain, PeerAddr, setup_tracing};

mod setup;

use setup::backend::run_backends;
use setup::client::get_client;
use setup::proxy::run_proxy;

const CERT_PATH: &str = "credentials/testpeer.com+3.pem";
const KEY_PATH: &str = "credentials/testpeer.com+3-key.pem";
const PROXY_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 4000);

fn setup_test_config(domains: &[&str], backends: &[&str]) -> Arc<PortoConfig> {
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

async fn setup_test_server(config: Arc<PortoConfig>) {
    tokio::spawn(run_backends(config.clone()));
    tokio::time::sleep(Duration::from_secs(1)).await;
    tokio::spawn(run_proxy(config));
    tokio::time::sleep(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn health_ping() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let domains = &["testpeer.com", "testpeeruds.com", "rezadarius.de"];
    let backends = &["127.0.0.2:8000", "127.0.0.3:8000", "/tmp/test_peer.sock"];

    let config = setup_test_config(domains, backends);
    let client = get_client(domains, config.addr());

    setup_test_server(config).await;

    for domain in domains.iter() {
        let res = client.get(format!("https://{}/", domain)).send().await;
        eprintln!("got message: {:?}", res.unwrap());
    }
}
