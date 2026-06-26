use std::{path::PathBuf, sync::Arc};

use http::StatusCode;
use porto::config::PortoConfig;
use test_log::test;

mod common;

use common::client::get_client;
use tracing::info;

use crate::common::*;

/*
* every test file should test an instance of porto and backends and not run different configurations
*/

// WARNING: configs are kinda broken because the servers run with the first config that spawns them

const DOMAINS: &[&str] = &["testpeer.com", "testpeeruds.com", "rezadarius.de"];
const BACKENDS: &[&str] = &["127.0.0.2:8000", "127.0.0.3:8000", "/tmp/test_peer.sock"];

fn adjust_settings(config: &mut PortoConfig) {
    config.internal.ctrl_sock_path = PathBuf::from("/tmp/porto-test-sock");
}

#[test(tokio::test)]
async fn proxying() {
    let mut config = setup_test_config(DOMAINS, BACKENDS);
    let client = get_client(DOMAINS, config.addr());

    adjust_settings(&mut config);
    setup_test_server(Arc::new(config));

    for domain in DOMAINS.iter() {
        info!("trying to ping {domain}");
        client
            .get(format!("https://{}/", domain))
            .send()
            .await
            .expect("the backend is available and should respond");
    }
}

#[test(tokio::test)]
async fn rate_limit() {
    let mut config = setup_test_config(DOMAINS, BACKENDS);
    adjust_settings(&mut config);
    config.global.limit = true;

    let client = get_client(DOMAINS, config.addr());

    // TODO: get rid of this hard coded value
    let bucket_size = 10;

    setup_test_server(Arc::new(config));

    let send = async || {
        client
            .get(format!("https://{}/", &DOMAINS[0]))
            .send()
            .await
            .expect("the backend is available and should respond")
    };

    eprintln!("sending {bucket_size} requests");

    let mut sent_msgs = 0;
    for _ in 0..bucket_size {
        send().await;
        sent_msgs += 1;
        eprintln!("sent {sent_msgs}");
    }

    eprintln!("expecing rate limiting now");

    let resp = send().await;

    eprintln!("got response {:?}", &resp);
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[test(tokio::test)]
async fn compression() {
    let mut config = setup_test_config(DOMAINS, BACKENDS);
    adjust_settings(&mut config);

    let client = get_client(DOMAINS, config.addr());

    setup_test_server(Arc::new(config));

    let res = client
        .get(format!("https://{}/comp", &DOMAINS[0]))
        .header(http::header::ACCEPT_ENCODING, "gzip")
        .send()
        .await
        .expect("the backend is available and should respond");

    assert_eq!(res.headers()["content-encoding"], "gzip");
    let body = res.bytes().await.unwrap();
    eprintln!("body length: {} bytes", body.len());
}
