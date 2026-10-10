use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, anyhow};
use http::StatusCode;
use porto::errors::TraceError;
use porto::tls::{AcmeConfig, AcmeProvider, ChallStoreHandle, PortoACME, setup_chall_server};
use porto::utils::Domain;
use reqwest::dns::Resolve;
use reqwest::{Certificate, ClientBuilder};
use test_log::test;
use testcontainers::compose::DockerCompose;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tower::BoxError;
use tracing::{debug, info};

/// pebble sends challenges to port 5002
const CHALL_LISTEN_ADDR: &str = "0.0.0.0:5002";
const DIRECTORY_URL: &str = "https://localhost:14000/dir";
/// the host name we want to test for
const DEBUG_DNS: &str = "acmetest.com";

/// this CA too is used to talk to the pebble container
const PEBBLE_CLIENT_CA_PATH: &str = "tests/pebble/pebble.minica.pem";
/// the CA root with which ACME certs are signed by is regenerated every time, so we fetch it from
/// here:
const PEBBLE_CA_URL: &str = "https://localhost:15000/roots/0";

const TLS_LISTEN_ADDR: &str = "0.0.0.0:8000";
const CRED_DIR: &str = "credentials/test/";

async fn is_tls(stream: &TcpStream) -> bool {
    let mut peek_buf = [0u8; 1];
    match stream.peek(&mut peek_buf).await {
        // a https "client hello" starts with 0x16
        Ok(1) => peek_buf[0] == 0x16,
        _ => false,
    }
}

/// helper function to reset saved certificates
fn setup_dir() {
    let _ = std::fs::remove_dir_all(CRED_DIR);
    let _ = std::fs::create_dir(CRED_DIR);
}

/// tests are multi threaded, this makes sure we only use one container instance for all of them
static PEBBLE: tokio::sync::OnceCell<DockerCompose> = tokio::sync::OnceCell::const_new();
static PEBBLE_CA: tokio::sync::OnceCell<Certificate> = tokio::sync::OnceCell::const_new();

async fn setup_pebble() {
    PEBBLE
        .get_or_init(|| async {
            // for some reason calling "tests/docker-compose.yml" as an argument doesnt find it as
            // it searches in tests/tests/docker-compose.yml

            let compose_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/pebble/docker-compose.yml");
            let mut compose = DockerCompose::with_local_client(&[&compose_path])
                .with_project_name("porto-acme-test");

            // let mut compose = DockerCompose::with_local_client(&["tests/pebble/docker-compose.yml"])
            //     .with_project_name("porto-acme-test");

            compose.up().await.unwrap();

            // fetch the root CA from the docker container
            let file = std::fs::read(PEBBLE_CLIENT_CA_PATH).unwrap();
            let cert = reqwest::Certificate::from_pem(&file).unwrap();

            let root_pem = ClientBuilder::new()
                .tls_certs_only(std::iter::once(cert))
                .build()
                .unwrap()
                .get(PEBBLE_CA_URL)
                .send()
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap();

            PEBBLE_CA
                .set(Certificate::from_pem(&root_pem).unwrap())
                .unwrap();

            compose
        })
        .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
}

/// provided a client that resolves every domain to the proxy adress
pub async fn get_client(
    domains: impl Iterator<Item = &'static str>,
    proxy_addr: SocketAddr,
) -> reqwest::Client {
    let resolver = TestResolver {
        proxy: proxy_addr,
        set: domains.collect(),
    };

    let cert = PEBBLE_CA.get().unwrap().clone();

    ClientBuilder::new()
        .http1_only()
        .dns_resolver(resolver)
        .tls_certs_only(std::iter::once(cert))
        .build()
        .unwrap()
}

struct TestResolver {
    proxy: SocketAddr,
    set: HashSet<&'static str>,
}

impl Resolve for TestResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let b: Result<Box<dyn Iterator<Item = SocketAddr> + Send + 'static>, BoxError> =
            if self.set.contains(name.as_str()) {
                Ok(Box::new(std::iter::once(self.proxy)))
            } else {
                Err(anyhow!("couldnt resolve {:?}", name).into_boxed_dyn_error())
            };
        Box::pin(async move { b })
    }
}

#[test(tokio::test)]
async fn acme_test_init() -> Result<()> {
    const RES_TEXT: &str = "HTTP/1.1 200 OK\r\n\r\n";
    /*
    HOW TO TEST:

    - start acme server: docker compose up
    - curl --http1.1 --resolve acmetest.com:8000:127.0.0.1 https://acmetest.com:8000 -k -v

    */

    setup_dir();
    setup_pebble().await;

    // setup http1 chall server
    let chall_store = ChallStoreHandle::new();
    setup_chall_server(CHALL_LISTEN_ADDR.parse().unwrap(), chall_store.clone());

    // prevent race condition to make sure the chall server is up and running before
    // initilaizing ACME
    tokio::time::sleep(Duration::from_secs(1)).await;

    // setup TLS server
    let cfg = AcmeConfig {
        domains: vec![Domain::parse(DEBUG_DNS)?],
        cred_path: PathBuf::from(CRED_DIR),
        check_interval: 24,
    };
    let provider = AcmeProvider::Pebble(DIRECTORY_URL.to_string());
    let tls = PortoACME::init(cfg, provider, chall_store).await?;
    let tls_listener = tokio::net::TcpListener::bind(TLS_LISTEN_ADDR).await?;

    info!("listening for TLS requests on {TLS_LISTEN_ADDR}");

    let mut set = tokio::task::JoinSet::new();
    set.spawn(async move {
        while let Ok((con, _)) = tls_listener.accept().await.trace_err() {
            debug!("got connection");
            if is_tls(&con).await {
                let acceptor = tls.acceptor();
                match acceptor.accept(con).await {
                    Ok(mut s) => {
                        debug!("TLS accepted!");
                        s.write_all(RES_TEXT.as_bytes()).await?;
                        s.shutdown().await?;
                        break;
                    }
                    Err(e) => return Err(anyhow!("error when accepting TLS: {}", e)),
                };
            }
            // panic!("got non TLS request");
        }
        Ok::<(), anyhow::Error>(())
    });

    set.spawn(async {
        let client = get_client(std::iter::once(DEBUG_DNS), TLS_LISTEN_ADDR.parse().unwrap()).await;

        let res = client
            .get(format!("https://{}", DEBUG_DNS))
            .send()
            .await
            .unwrap();

        match res.status() {
            StatusCode::OK => Ok(()),
            _ => Err(anyhow!("got a bad response")),
        }
    });

    let res = set.join_all().await;
    assert!(res.iter().all(Result::is_ok));

    Ok(())
}
