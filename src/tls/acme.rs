use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Result, anyhow};
use instant_acme::{Account, LetsEncrypt};
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, instrument, warn};

use crate::errors::TraceError;
use crate::tls::challenge::ChallStoreHandle;
use crate::{config::TlsConfig, utils::*};

use super::account::*;
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
    chall_handle: ChallStoreHandle,

    // these need to be arcs
    config: Arc<ServerConfig>,
    cert_store: Arc<CertStore>,
}

impl PortoACME {
    /// initalizes the ACME engine, requires a service ready for HTTP challenges to be recieved
    pub async fn init(
        config: TlsConfig,
        provider: AcmeProvider,
        chall_handle: ChallStoreHandle,
    ) -> Result<Self> {
        let path = config
            .credentials
            .clone()
            .ok_or_else(|| anyhow!("no credentials path provided"))?;

        debug!(path = %path.display(), "initializing TLS Service");

        let cert_path = path.join(CERT_FILENAME);
        let key_path = path.join(KEY_FILENAME);

        let cert_store = Arc::new(CertStore::new(cert_path, key_path));
        let server_config = setup_rustls_config(&config, cert_store.clone());

        let store = PortoACME {
            inner: Arc::new(PortoACMEInner {
                cred_path: path,
                cert_store,
                chall_handle,

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
    issue_order(acc, &store.inner.chall_handle, domains.iter())
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
            match issue_order(&acc, &store.inner.chall_handle, domains.iter()).await {
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
    use test_log::test;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;
    use tracing::info;

    use super::*;
    use crate::tls::challenge::*;

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

        // pebble sends challenges to port 5002
        const CHALL_LISTEN_ADDR: &str = "0.0.0.0:5002";
        const DIRECTORY_URL: &str = "https://localhost:14000/dir";
        // the host name we want to test for
        const DEBUG_DNS: &str = "acmetest.com";

        const TLS_LISTEN_ADDR: &str = "0.0.0.0:8000";
        const CRED_DIR: &str = "credentials/test/";

        let tls_config = TlsConfig {
            domains: vec![Domain::parse(DEBUG_DNS)?],
            credentials: Some(PathBuf::from(CRED_DIR)),
            ..Default::default()
        };

        // setup http1 chall server
        let chall_store = ChallStoreHandle::new();

        setup_chall_server(CHALL_LISTEN_ADDR.parse().unwrap(), chall_store.clone());

        // prevent race condition to make sure the chall server is up and running before
        // initilaizing ACME
        tokio::time::sleep(Duration::from_secs(1)).await;

        // setup TLS server
        let provider = AcmeProvider::Pebble(DIRECTORY_URL.to_string());
        let tls = PortoACME::init(tls_config, provider, chall_store).await?;
        let tls_listener = tokio::net::TcpListener::bind(TLS_LISTEN_ADDR).await?;

        info!("listening for TLS requests on {TLS_LISTEN_ADDR}");

        while let Ok((con, _)) = tls_listener.accept().await.trace_err() {
            debug!("got connection");
            if is_tls(&con).await {
                let acceptor = tls.acceptor();
                match acceptor.accept(con).await {
                    Ok(mut s) => {
                        debug!("TLS accepted!");
                        s.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
                        s.shutdown().await?;
                        return Ok(());
                    }
                    Err(e) => panic!("error when accepting TLS: {}", e),
                };
            }
            // panic!("got non TLS request");
        }
        Ok(())
    }
}
