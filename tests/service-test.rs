use std::sync::Arc;

use test_log::test;

mod common;

use common::client::get_client;
use tracing::info;

use crate::common::*;

/*
* every test file should test an instance of porto and backends and not run different configurations
*/

#[test(tokio::test)]
async fn health_ping() {
    let domains = &["testpeer.com", "testpeeruds.com", "rezadarius.de"];
    let backends = &["127.0.0.2:8000", "127.0.0.3:8000", "/tmp/test_peer.sock"];

    let config = Arc::new(setup_test_config(domains, backends));
    let client = get_client(domains, config.addr());

    setup_test_server(config).await;

    for domain in domains.iter() {
        info!("trying to ping {domain}");
        client.get(format!("https://{}/", domain)).send().await.expect("the backend is available and should respond");
    }
}
