use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Result, anyhow};
use instant_acme::{Account, KeyAuthorization};
use parking_lot::Mutex;
use rustls::ServerConfig;
use serde::Deserialize;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

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
    pub inner: Arc<PortoACMEInner>,
}

struct PortoACMEInner {
    pub cred_path: PathBuf,
    pub account: Account,

    chall_store: ChallStore,

    // these need to be arcs
    config: Arc<ServerConfig>,
    cert_store: Arc<CertStore>,
}

impl PortoACME {
    pub async fn init(config: &TlsConfig) -> Result<Self> {
        let path = config
            .credentials
            .clone()
            .ok_or_else(|| anyhow!("no credentials path provided"))?;

        debug!(path = %path.display(), "initializing TLS Service");

        let cert_path = path.join(CERT_FILENAME);
        let key_path = path.join(KEY_FILENAME);

        let cert_store = Arc::new(CertStore::new(cert_path, key_path));
        let chall_store = ChallStore::new();
        let server_config = setup_rustls_config(config, cert_store.clone());
        let account = get_account(config.acme_mode, &path).await?;

        let store = PortoACME {
            inner: Arc::new(PortoACMEInner {
                cred_path: path,
                account,
                cert_store,
                chall_store,

                config: Arc::new(server_config),
            }),
        };

        tokio::spawn(acme_worker(store.clone(), config.acme_mode));

        Ok(store)
    }

    pub fn acceptor(&self) -> TlsAcceptor {
        TlsAcceptor::from(self.inner.config.clone())
    }
}

#[derive(Clone, Copy, Deserialize, Debug, Default)]
pub enum AcmeMode {
    #[default]
    Debug,
    Staging,
    Prod,
}

async fn acme_worker(store: PortoACME, mode: AcmeMode) {
    // match mode {
    //     AcmeMode::Debug => {
    //         // maybe move this into init?
    //         match store.load_certs_from_file() {
    //             Ok(_) => info!("loaded certs from file"),
    //             Err(e) => warn!(%e, "couldnt load certs from file"),
    //         };
    //
    //         if let Some(domains) = store.check_new_domains() {
    //             let _ = issue_order(store.clone(), &domains)
    //                 .await
    //                 .inspect_err(|e| error!(%e, "ACME error"));
    //         };
    //     }
    //     AcmeMode::Prod => {
    //         let mut timer = tokio::time::interval(Duration::from_hours(CHECK_INTERVAL_HOURS));
    //
    //         loop {
    //             timer.tick().await;
    //
    //             // TODO: some sort watcher channel for newly added domains when the server is running
    //
    //             if let Some(domains) = store.check_new_domains()
    //                 && let Err(e) = issue_order(store.clone(), &domains).await
    //             {
    //                 error!(%e, "ACME error");
    //             };
    //
    //             if let Some(domains) = store.check_certs()
    //                 && let Err(e) = issue_order(store.clone(), &domains).await
    //             {
    //                 error!(%e, "ACME error");
    //             };
    //         }
    //     }
    // }
    todo!()
}

#[cfg(test)]
mod tests {
    use hyper::server::conn::http1::Builder;
    use hyper_util::rt::TokioIo;
    use hyper_util::service::TowerToHyperService;
    use test_log::test;
    use tokio::io::AsyncWriteExt;

    use super::*;
    use crate::tls::challenge::*;

    #[test(tokio::test)]
    #[ignore]
    async fn acme_test() -> Result<()> {
        /*
        HOW TO TEST:

        - start acme server: docker compose up
        - curl with: curl --http1.1 --resolve acmetest.com:5002:127.0.0.1 https://acmetest.com:5002 -k -v

        */
        // let tls_config = TlsConfig {
        //     credentials: Some(PathBuf::from("credentials")),
        //     ..Default::default()
        // };
        //
        // let addr = "0.0.0.0:5002"; // port for pebble ACME server
        //
        // let domains = RouteTable::init_debug(&[("acmetest.com", "1.1.1.1:6767")])?;
        //
        // let listener = tokio::net::TcpListener::bind(addr).await?;
        // let tls = PortoACME::init(&tls_config, domains).await.unwrap();
        // let service = TowerToHyperService::new(Http1ChallSvc::new(tls.clone()));
        //
        // info!("test ACME server listening on {addr}");
        //
        // while let Ok((con, _)) = listener.accept().await {
        //     if is_tls(&con).await {
        //         debug!("we got a TLS connection");
        //         let acceptor = tls.acceptor();
        //         match acceptor.accept(con).await {
        //             Ok(mut s) => {
        //                 debug!("TLS established");
        //                 let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
        //             }
        //             Err(e) => error!(%e, "error when accepting TLS"),
        //         };
        //         continue;
        //     }
        //
        //     let stream = TokioIo::new(con);
        //     let builder = Builder::new();
        //     builder.serve_connection(stream, service.clone()).await?;
        // }
        Ok(())
    }
}
