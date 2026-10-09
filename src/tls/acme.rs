use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::Result;
use instant_acme::{Account, LetsEncrypt};
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, instrument, warn};

use crate::errors::TraceError;
use crate::tls::challenge::ChallStoreHandle;
use crate::utils::*;

use super::account::*;
use super::helper::*;
use super::order::*;
use super::store::*;

pub const CERT_FILENAME: &str = "acme_cert.pem";
pub const KEY_FILENAME: &str = "acme_key.pem";

#[derive(Debug, Clone)]
pub struct AcmeConfig {
    pub domains: Vec<Domain>,
    pub credentials: PathBuf,

    // in hours
    pub check_interval: u64,
}

/// clonable handler to Porto's main TLS struct
#[derive(Clone)]
pub struct PortoACME {
    inner: Arc<PortoACMEInner>,
}

struct PortoACMEInner {
    cred_path: PathBuf,
    chall_handle: ChallStoreHandle,
    check_interval: u64,

    // these need to be arcs
    config: Arc<ServerConfig>,
    cert_store: Arc<CertStore>,
}

impl PortoACME {
    /// initalizes the ACME engine, requires a service ready for HTTP challenges to be recieved
    pub async fn init(
        config: AcmeConfig,
        provider: AcmeProvider,
        chall_handle: ChallStoreHandle,
    ) -> Result<Self> {
        let path = config.credentials;

        debug!(path = %path.display(), "initializing TLS Service");

        let cert_path = path.join(CERT_FILENAME);
        let key_path = path.join(KEY_FILENAME);

        let cert_store = Arc::new(CertStore::new(cert_path, key_path));
        let server_config = setup_rustls_config(cert_store.clone());

        let store = PortoACME {
            inner: Arc::new(PortoACMEInner {
                cred_path: path,
                cert_store,
                check_interval: config.check_interval,
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
    let mut timer = tokio::time::interval(Duration::from_hours(store.inner.check_interval));

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
