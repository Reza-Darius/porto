use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Result, anyhow};
use instant_acme::{Account, KeyAuthorization, LetsEncrypt};
use parking_lot::Mutex;
use rustls::ServerConfig;
use serde::Deserialize;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, debug_span, error, info, instrument, warn};

use crate::errors::TraceErr;
use crate::tls::challenge::ChallStore;
use crate::{config::TlsConfig, utils::*};

use super::account::*;
use super::cert_types::*;
use super::helper::*;
use super::order::*;
use super::store::*;

const CHECK_INTERVAL_HOURS: u64 = 24;

pub const CERT_FILENAME: &str = "acme_cert.pem";
pub const KEY_FILENAME: &str = "acme_key.pem";

/// clonable handler to Porto's main TLS struct
#[derive(Clone)]
pub struct PortoACME {
    inner: Arc<PortoACMEInner>,
}

struct PortoACMEInner {
    cred_path: PathBuf,
    chall_store: ChallStore,

    // these need to be arcs
    config: Arc<ServerConfig>,
    cert_store: Arc<CertStore>,
}

impl PortoACME {
    pub async fn init(config: TlsConfig, provider: AcmeProvider) -> Result<Self> {
        let path = config
            .credentials
            .clone()
            .ok_or_else(|| anyhow!("no credentials path provided"))?;

        debug!(path = %path.display(), "initializing TLS Service");

        let cert_path = path.join(CERT_FILENAME);
        let key_path = path.join(KEY_FILENAME);

        let cert_store = Arc::new(CertStore::new(cert_path, key_path));
        let chall_store = ChallStore::new();
        let server_config = setup_rustls_config(&config, cert_store.clone());

        let store = PortoACME {
            inner: Arc::new(PortoACMEInner {
                cred_path: path,
                cert_store,
                chall_store,

                config: Arc::new(server_config),
            }),
        };

        let acc_path = store.inner.cred_path.join("account");
        let account = get_account(&acc_path, provider).await.unwrap();

        initialize_store(config.domains, &account, &store)
            .await
            .trace_err()?;

        tokio::spawn(acme_worker(account, store.clone()));

        Ok(store)
    }

    pub fn acceptor(&self) -> TlsAcceptor {
        TlsAcceptor::from(self.inner.config.clone())
    }
}

#[instrument(skip_all)]
async fn initialize_store(domains: Vec<Domain>, acc: &Account, store: &PortoACME) -> Result<()> {
    // can we initalize from file?
    if let Ok(n) = store
        .inner
        .cert_store
        .init_from_disk()
        .inspect_err(|e| warn!(%e, "coudlnt init store from disk"))
        && n as usize == domains.len()
    {
        return Ok(());
    };

    order_and_store(domains, acc, store).await
}

async fn order_and_store(domains: Vec<Domain>, acc: &Account, store: &PortoACME) -> Result<()> {
    issue_order(acc, &store.inner.chall_store, domains.iter())
        .await
        .and_then(|(cert, key)| store.inner.cert_store.store(domains.into_iter(), cert, key))
}

#[derive(Clone, Debug)]
pub enum AcmeProvider {
    Pebble(String),
    LetsEncrypt(LetsEncrypt),
}

#[instrument(skip_all)]
async fn acme_worker(acc: Account, store: PortoACME) {
    // let span = debug_span!(target: "ACME", "ACME_worker");
    // let _guard = span.enter();

    let mut timer = tokio::time::interval(Duration::from_hours(CHECK_INTERVAL_HOURS));

    loop {
        timer.tick().await;

        if let Some(domains) = store.inner.cert_store.expired(cert_should_renew) {
            match issue_order(&acc, &store.inner.chall_store, domains.iter()).await {
                Ok((cert, key)) => {
                    let _ = store
                        .inner
                        .cert_store
                        .store(domains.into_iter(), cert, key)
                        .inspect_err(|e| error!(%e, "ACME error, error when storing order"));
                }
                Err(e) => error!(%e, "ACME error"),
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use hyper::server::conn::http1::Builder;
    use hyper_util::rt::TokioIo;
    use hyper_util::service::TowerToHyperService;
    use test_log::test;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    use super::*;
    use crate::tls::challenge::*;

    const DIRECTORY_URL: &str = "https://localhost:14000/dir";
    const DEBUG_DNS: &str = "acmetest.com";

    // pebble sends challenges to port 5002
    const LISTENING_ADDR: &str = "0.0.0.0:5002";
    const CRED_DIR: &str = "credentials/test/";

    async fn is_tls(stream: &TcpStream) -> bool {
        let mut peek_buf = [0u8; 1];
        match stream.peek(&mut peek_buf).await {
            // a https "client hello" starts with 0x16
            Ok(1) => peek_buf[0] == 0x16,
            _ => false,
        }
    }

    #[test(tokio::test)]
    #[ignore]
    async fn acme_test() -> Result<()> {
        /*
        HOW TO TEST:

        - start acme server: docker compose up
        - curl with: curl --http1.1 --resolve acmetest.com:5002:127.0.0.1 https://acmetest.com:5002 -k -v

        */

        let tls_config = TlsConfig {
            domains: vec![Domain::parse(DEBUG_DNS)?],
            credentials: Some(PathBuf::from(CRED_DIR)),
            ..Default::default()
        };
        let provider = AcmeProvider::Pebble(DIRECTORY_URL.to_string());
        let tls = PortoACME::init(tls_config, provider).await?;

        let listener = tokio::net::TcpListener::bind(LISTENING_ADDR).await?;
        let service = TowerToHyperService::new(Http1ChallSvc::new(tls.inner.chall_store.clone()));

        while let Ok((con, _)) = listener.accept().await {
            if is_tls(&con).await {
                let acceptor = tls.acceptor();
                match acceptor.accept(con).await {
                    Ok(mut s) => {
                        let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
                        return Ok(());
                    }
                    Err(e) => panic!("error when accepting TLS: {}", e),
                };
            }

            let stream = TokioIo::new(con);
            let builder = Builder::new();
            builder.serve_connection(stream, service.clone()).await?;
        }
        Ok(())
    }
}
