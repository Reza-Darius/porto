use std::{path::PathBuf, sync::Arc};

use http::StatusCode;
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

fn setup() -> reqwest::Client {
    let mut config = setup_test_config(DOMAINS, BACKENDS);

    // for rate limit test
    config.global.limit = true;

    // make sure we dont get an error trying to bind to the socket in /run/
    config.internal.ctrl_sock_path = PathBuf::from("/tmp/porto-test-sock");

    let client = get_client(DOMAINS, config.addr());

    setup_test_server(Arc::new(config));
    client
}

#[test(tokio::test)]
async fn proxying() {
    let client = setup();

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
    let client = setup();

    // TODO: get rid of this hard coded value
    let bucket_size = 10;

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
    let client = setup();

    let res = client
        .get(format!("https://{}/comp", &DOMAINS[0]))
        .header(http::header::ACCEPT_ENCODING, "gzip")
        .send()
        .await
        .expect("the backend is available and should respond");

    eprintln!("response: {:?}", res);
    assert_eq!(res.headers()["content-encoding"], "gzip");
    let body = res.bytes().await.unwrap();
    eprintln!("body length: {} bytes", body.len());
}
