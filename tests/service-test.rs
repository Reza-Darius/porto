use porto::utils::{Domain, PeerAddr, setup_tracing};
use tikv_jemallocator::Jemalloc;

mod setup;

use porto::config::*;
use setup::backend::run_backends;
use setup::client::get_client;
use setup::proxy::run_proxy;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::test]
async fn health_ping() {
    setup_tracing();

    let mut config = PortoConfig::default();

    let domains = &["testpeer.com", "testpeeruds.com", "RezaDarius.de"];
    let backends = &["127.0.0.2:8000", "127.0.0.3:8000", "/tmp/test_peer.sock"];

    for i in 0..3 {
        config.add_proxy(ProxyConfig {
            domain: Domain::parse(domains[i]).unwrap(),
            upstream: PeerAddr::parse(backends[i]).unwrap(),
            http2: false,
            config: Default::default(),
        });
    }

    tokio::spawn(run_backends(backends));
    tokio::spawn(run_proxy(config));

    let client = get_client();

    for backend in backends.iter() {
        let res = client.get(format!("https://{}/", backend)).send().await;
        assert!(res.is_ok());
    }
}
