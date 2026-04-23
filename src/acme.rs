use std::{collections::HashMap, fs, future::Ready, path::PathBuf, sync::Arc, time::Duration};

use http_body_util::combinators::BoxBody;
use hyper::{Request, Response, StatusCode, body::Incoming};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, KeyAuthorization, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use parking_lot::Mutex;
use rcgen::{BasicConstraints, CertifiedIssuer, DistinguishedName, DnType, IsCa, KeyPair};
use time::OffsetDateTime;
use tower::Service;
use tracing::{error, info, warn};
use x509_parser::pem::parse_x509_pem;

use crate::utils::*;

const RENEWAL_THRESHOLD_DAYS: i64 = 30;
const RENEWAL_THRESHHOLD: i64 = (60 << 1) * 24 * RENEWAL_THRESHOLD_DAYS;
const CHECK_INTERVAL_HOURS: u64 = 24;

async fn issue_acme(store: CertStore, account: &Account, domains: &[impl AsRef<str>]) {
    // Create the ACME order based on the given domain names.
    // Note that this only needs an `&Account`, so the library will let you
    // process multiple orders in parallel for a single account.
    let domains: Vec<_> = domains.iter().map(|d| d.as_ref().to_string()).collect();
    let identifier: Vec<_> = domains.iter().map(|s| Identifier::Dns(s.clone())).collect();

    info!(?domains, "issuing new ACME order");

    let mut order = match account.new_order(&NewOrder::new(&identifier)).await {
        Ok(o) => o,
        Err(e) => {
            error!(%e, "error when creating order");
            return;
        }
    };

    tokio::spawn(async move {
        // Pick the desired challenge type and prepare the response.
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                _ => todo!(),
            }
            let mut challenge = authz
                .challenge(ChallengeType::Http01)
                .ok_or_else(|| anyhow::anyhow!("no http01 challenge found"))?;

            let token = challenge.token.clone();
            let key = challenge.key_authorization();
            store.inner.pending_order.lock().insert(token, key);

            challenge.set_ready().await?;
        }

        let state = order.state();
        assert!(matches!(state.status, OrderStatus::Pending));

        // Exponentially back off until the order becomes ready or invalid.
        let status = order.poll_ready(&RetryPolicy::default()).await?;
        if status != OrderStatus::Ready {
            return Err(anyhow::anyhow!("unexpected order status: {status:?}"));
        }

        // Finalize the order and print certificate chain, private key and account credentials.
        let private_key_pem = order.finalize().await?;
        let cert_chain_pem = order.poll_certificate(&RetryPolicy::default()).await?;

        info!("order completed\n{}\n{}", private_key_pem, cert_chain_pem);

        // insert inside the store
        let mut guard = store.inner.certs.lock();
        for domain in domains.into_iter() {
            guard.insert(domain, (private_key_pem.clone(), cert_chain_pem.clone()));
        }

        Ok(())
    });
}

#[derive(Debug, Clone)]
pub struct AcmeService {
    store: CertStore,
}

impl Service<Request<Incoming>> for AcmeService {
    type Response = Response<Body>;
    type Error = hyper::Error;

    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Incoming>) -> Self::Future {
        // http://<YOUR_DOMAIN>/.well-known/acme-challenge/<TOKEN>
        let Some(uri_token) = req
            .uri()
            .path()
            .strip_prefix("/.well-known/acme-challenge/")
        else {
            warn!(uri = req.uri().path(), "unknown URI");
            return std::future::ready(Ok(bad_request()));
        };

        info!(uri_token, "got ACME token");

        let resp = match self.store.inner.pending_order.lock().get(uri_token) {
            Some(key) => Response::new(full(key.as_str().to_string())),
            None => {
                warn!("no key authorization found for token!");
                response(StatusCode::NOT_FOUND)
            }
        };
        std::future::ready(Ok(resp))
    }
}

#[derive(Debug, Clone)]
pub struct CertStore {
    inner: Arc<CertStoreInner>,
}

#[derive(Debug)]
struct CertStoreInner {
    cache_path: PathBuf,
    // domain to (cert_pem, key_pem)
    certs: Mutex<HashMap<String, (String, String)>>,
    // token to key
    pending_order: Mutex<HashMap<String, KeyAuthorization>>,
}

fn setup_acme(store: CertStore) -> AcmeService {
    tokio::spawn(acme_worker(store.clone()));
    AcmeService { store }
}

async fn acme_worker(store: CertStore) {
    let (account, _) = Account::builder()
        .expect("account builder failed")
        .create(
            &NewAccount {
                contact: &[], // could be some email
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            // staging enviroment is for testing purposes
            LetsEncrypt::Staging.url().to_owned(),
            None,
        )
        .await
        .expect("account couldnt be created");

    let timer = tokio::time::sleep(Duration::from_secs(60));
    tokio::pin!(timer);

    loop {
        tokio::select! {
            _ = &mut timer => {
                issue_acme(store.clone(), &account, &["example.com"]).await;
            }
        }
    }
}

fn test_certs() -> anyhow::Result<()> {
    let ca_key = KeyPair::generate()?;
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "Pebble CA".to_owned());
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.distinguished_name = distinguished_name;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

    let issuer = CertifiedIssuer::self_signed(ca_params, ca_key)?;
    fs::write("tests/testdata/ca.pem", issuer.as_ref().pem())?;

    let ee_key = KeyPair::generate()?;
    fs::write("tests/testdata/server.key", ee_key.serialize_pem())?;

    let mut ee_params = rcgen::CertificateParams::new([
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
        "::1".to_owned(),
    ])?;
    ee_params.distinguished_name = DistinguishedName::new();
    let ee_cert = ee_params.signed_by(&ee_key, &issuer)?;
    fs::write("tests/testdata/server.pem", ee_cert.pem())?;

    Ok(())
}

fn should_renew(cert_pem: &str) -> bool {
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes()).unwrap();
    let cert = pem.parse_x509().unwrap();

    // expiration date
    let not_after = cert.validity().not_after.timestamp();
    let now = OffsetDateTime::now_utc().unix_timestamp();

    let threshhold = not_after - RENEWAL_THRESHHOLD;

    now >= threshhold
}
