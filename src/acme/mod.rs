#![allow(dead_code)]
mod account;
mod cert_store;
mod challenge;
mod helper;
mod order;
mod resolver;

use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Result, anyhow};
use instant_acme::{Account, KeyAuthorization};
use parking_lot::{MappedMutexGuard, Mutex, MutexGuard};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    sign::CertifiedKey,
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::{
    config::{PortoConfig, TlsConfig},
    utils::*,
};
use account::*;
use helper::*;
use order::*;
use resolver::*;

const CHECK_INTERVAL_HOURS: u64 = 24;

const CERT_FILENAME: &str = "acme_cert.pem";
const KEY_FILENAME: &str = "acme_key.pem";

/// clonable handler to Porto's main TLS struct
#[derive(Clone)]
pub struct PortoTLS {
    inner: Arc<PortoTLSInner>,
}

struct PortoTLSInner {
    /// path to credentials
    cred_path: PathBuf,

    /// ACME account
    account: Account,

    /// table of registered domains in the proxy
    peers: RouteTable,

    /// in memory cache
    store: Mutex<HashMap<Domain, (CertChainPem, KeyPem)>>,

    /// tokens for ACME challenged
    pending_challenges: Mutex<HashMap<AcmeToken, KeyAuthorization>>,

    // these need to be arcs
    config: Arc<ServerConfig>,
    resolver: Arc<Resolver>,
}

impl PortoTLS {
    pub async fn init(config: &TlsConfig, peers: RouteTable) -> Result<Self> {
        let path = config
            .credentials
            .clone()
            .ok_or_else(|| anyhow!("no credentials path provided"))?;

        debug!("initializing TLS Service");
        debug!(path = %path.display());
        debug!(%peers);

        let resolver = Arc::new(Resolver::new());
        let server_config = setup_rustls_config(config, resolver.clone());
        let account = get_account(config.debug, &path).await?;

        let store = PortoTLS {
            inner: Arc::new(PortoTLSInner {
                cred_path: path,
                account,
                peers,
                store: Mutex::new(HashMap::new()),
                pending_challenges: Mutex::new(HashMap::new()),

                resolver,
                config: Arc::new(server_config),
            }),
        };

        tokio::spawn(acme_worker(
            store.clone(),
            if config.debug {
                AcmeWorkerMode::Debug
            } else {
                AcmeWorkerMode::Prod
            },
        ));

        Ok(store)
    }

    pub fn register_challenge(&self, token: AcmeToken, key: KeyAuthorization) {
        self.inner.pending_challenges.lock().insert(token, key);
    }

    pub fn get_chall_token(&self, token: &str) -> Option<MappedMutexGuard<'_, KeyAuthorization>> {
        let guard = self.inner.pending_challenges.lock();
        MutexGuard::try_map(guard, |map| map.get_mut(token)).ok()
    }

    pub fn remove_challenge(&self, token: &AcmeToken) {
        self.inner.pending_challenges.lock().remove(token);
    }

    /// check for expired certificates inside the in-memory cache
    fn check_certs(&self) -> Option<Vec<Domain>> {
        debug!("checking certs");

        let guard = self.inner.store.lock();

        let expired_domains: Vec<_> = guard
            .iter()
            .filter(|e| e.1.0.should_renew())
            .map(|e| e.0.clone())
            .collect();

        if !expired_domains.is_empty() {
            debug!(?expired_domains, "expired certs found");
            Some(expired_domains)
        } else {
            None
        }
    }

    /// checks the peer list to see if we need new certificates
    fn check_new_domains(&self) -> Option<Vec<Domain>> {
        debug!("checking for new domains");

        let guard = self.inner.store.lock();

        let new_domains: Vec<_> = self
            .inner
            .peers
            .get_domains()
            .into_iter()
            .filter(|d| !guard.contains_key(d))
            .collect();

        if !new_domains.is_empty() {
            debug!(?new_domains, "non registered domains found");
            Some(new_domains)
        } else {
            None
        }
    }

    fn add_to_resolver(&self, domain: &Domain, certs: CertChainPem, key: KeyPem) -> Result<()> {
        debug!(%domain, "adding domain to resolver");

        if certs.is_expired() {
            return Err(anyhow!("cant register expired certificates!"));
        }

        let certs = CertificateDer::pem_slice_iter(certs.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("could not read certificate: {e}"))?;

        let key = PrivateKeyDer::from_pem_slice(key.as_bytes())
            .map_err(|e| anyhow!("could not read key: {e}"))?;

        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let ck = CertifiedKey::from_der(certs, key, &provider)?;

        self.inner.resolver.add(domain, ck)?;
        Ok(())
    }

    pub fn get_acceptor(&self) -> TlsAcceptor {
        TlsAcceptor::from(self.inner.config.clone())
    }

    fn load_certs_from_file(&self) -> Result<()> {
        let path = &self.inner.cred_path;
        debug!(?path, "loading certs from file");

        // TODO: read existing certs from file and map them to domains

        let cert_pem = read_pem_file(path.join(CERT_FILENAME))?;
        let cert = cert_pem.parse_x509()?;

        let key_pem = read_pem_file(path.join(KEY_FILENAME))?;
        let key = key_pem.parse_x509()?;

        debug!(issuer = %cert.issuer(), "found certificate");

        todo!()
    }
}

enum AcmeWorkerMode {
    Debug,
    Prod,
}

async fn acme_worker(store: PortoTLS, mode: AcmeWorkerMode) {
    match mode {
        AcmeWorkerMode::Debug => {
            // maybe move this into init?
            match store.load_certs_from_file() {
                Ok(_) => info!("loaded certs from file"),
                Err(e) => warn!(%e, "couldnt load certs from file"),
            };

            if let Some(domains) = store.check_new_domains() {
                let _ = issue_order(store.clone(), &domains)
                    .await
                    .inspect_err(|e| error!(%e, "ACME error"));
            };
        }
        AcmeWorkerMode::Prod => {
            let mut timer = tokio::time::interval(Duration::from_hours(CHECK_INTERVAL_HOURS));

            loop {
                timer.tick().await;

                // TODO: some sort watcher channel for newly added domains when the server is running

                if let Some(domains) = store.check_new_domains()
                    && let Err(e) = issue_order(store.clone(), &domains).await
                {
                    error!(%e, "ACME error");
                };

                if let Some(domains) = store.check_certs()
                    && let Err(e) = issue_order(store.clone(), &domains).await
                {
                    error!(%e, "ACME error");
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use std::default;

    use hyper::server::conn::http1::Builder;
    use hyper_util::rt::TokioIo;
    use hyper_util::service::TowerToHyperService;
    use tokio::io::AsyncWriteExt;
    use tracing_subscriber::EnvFilter;

    use super::*;
    use challenge::*;

    #[tokio::test]
    async fn acme_test() -> Result<()> {
        /*
        HOW TO TEST:

        - start acme server: docker compose up
        - curl with: curl --http1.1 --resolve acmetest.com:5002:127.0.0.1 https://acmetest.com:5002 -k -v

        */
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .or_else(|_| EnvFilter::try_new("proxy=error,tower_http=warn"))?,
            )
            .init();

        let tls_config = TlsConfig {
            debug: true,
            credentials: Some(PathBuf::from("credentials")),
            ..Default::default()
        };

        let addr = "0.0.0.0:5002"; // port for pebble ACME server

        let domains = RouteTable::init_debug(&[("acmetest.com", "1.1.1.1:6767")])?;

        let listener = tokio::net::TcpListener::bind(addr).await?;
        let tls = PortoTLS::init(&tls_config, domains).await.unwrap();
        let service = TowerToHyperService::new(Http1ChallSvc::new(tls.clone()));

        info!("test ACME server listening on {addr}");

        while let Ok((con, _)) = listener.accept().await {
            if is_tls(&con).await {
                debug!("we got a TLS connection");
                let acceptor = tls.get_acceptor();
                match acceptor.accept(con).await {
                    Ok(mut s) => {
                        debug!("TLS established");
                        let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
                    }
                    Err(e) => error!(%e, "error when accepting TLS"),
                };
                continue;
            }

            let stream = TokioIo::new(con);
            let builder = Builder::new();
            builder.serve_connection(stream, service.clone()).await?;
        }
        Ok(())
    }
}
