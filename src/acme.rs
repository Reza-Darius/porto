#![allow(dead_code)]
use std::{
    collections::{HashMap, HashSet},
    future::Ready,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Result, anyhow};
use bincode::config::Configuration;
use hyper::{Request, Response, StatusCode, body::Incoming};
use instant_acme::{
    Account, AccountBuilder, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier,
    KeyAuthorization, LetsEncrypt, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use parking_lot::Mutex;
use rustls::{
    ServerConfig,
    client::verify_server_name,
    pki_types::{CertificateDer, DnsName, PrivateKeyDer, ServerName, pem::PemObject},
    server::{self, ClientHello, ParsedCertificate},
    sign::{self, CertifiedKey},
};
use time::OffsetDateTime;
use tokio_rustls::TlsAcceptor;
use tower::Service;
use tracing::{debug, error, info, warn};
use x509_parser::pem::parse_x509_pem;

use crate::utils::*;

const RENEWAL_THRESHOLD_DAYS: i64 = 30;
const RENEWAL_THRESHHOLD: i64 = 60 * 60 * 24 * RENEWAL_THRESHOLD_DAYS;
const CHECK_INTERVAL_HOURS: u64 = 24;

/// Create the ACME order based on the given domain names.
async fn issue_order(store: TlsService, account: &Account, domains: &[Domain]) -> Result<()> {
    let domains: Vec<_> = domains.to_vec();
    let identifier: Vec<_> = domains
        .iter()
        .map(|s| Identifier::Dns(s.to_string()))
        .collect();

    info!(?domains, "issuing new ACME order");

    let mut order = account.new_order(&NewOrder::new(&identifier)).await?;

    // Pick the desired challenge type and prepare the response.
    let mut authorizations = order.authorizations();
    let mut tokens: HashSet<AcmeToken> = HashSet::new();

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

        let token = AcmeToken::from_str(challenge.token.clone());

        store
            .inner
            .pending_challenges
            .lock()
            .insert(token.clone(), challenge.key_authorization());

        // remembering the token for removal later
        tokens.insert(token);

        challenge.set_ready().await?;
    }

    let state = order.state();
    if state.status != OrderStatus::Pending {
        return Err(anyhow::anyhow!("unexpected order state: {state:?}"));
    };

    // Exponentially back off until the order becomes ready or invalid.
    let status = order.poll_ready(&RetryPolicy::default()).await?;
    if status != OrderStatus::Ready {
        return Err(anyhow::anyhow!("unexpected order status: {status:?}"));
    }

    // Finalize the order and print certificate chain, private key and account credentials.
    let key = KeyPem::from_str(order.finalize().await?);
    let cert = CertChainPem::from_str(order.poll_certificate(&RetryPolicy::default()).await?);

    {
        // remove from pending tokens
        let mut guard = store.inner.pending_challenges.lock();
        for token in tokens.into_iter() {
            guard.remove(&token);
        }
    }

    tokio::fs::write(
        store.inner.cred_path.join("key.pem"),
        key.as_str().as_bytes(),
    )
    .await?;

    tokio::fs::write(
        store.inner.cred_path.join("cert.pem"),
        cert.as_str().as_bytes(),
    )
    .await?;

    {
        // insert inside in memory cache
        let mut guard = store.inner.certs.lock();

        for domain in domains.into_iter() {
            store.add_to_resolver(&domain, cert.clone(), key.clone())?;
            guard.insert(domain, (cert.clone(), key.clone()));
        }
    }

    info!("ACME order completed\n{}\n{}", cert, key);

    Ok(())
}

#[derive(Debug, Clone)]
pub struct AcmeService {
    store: TlsService,
}

impl AcmeService {
    fn new(store: TlsService) -> Self {
        tokio::spawn(acme_worker(store.clone()));
        AcmeService { store }
    }
}

impl Service<Request<Incoming>> for AcmeService {
    type Response = Response<Body>;
    type Error = hyper::Error;

    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
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

        let resp = match self.store.inner.pending_challenges.lock().get(uri_token) {
            Some(key) => Response::new(full(key.as_str().to_string())),
            None => {
                warn!("no key authorization found for token!");
                response(StatusCode::NOT_FOUND)
            }
        };
        std::future::ready(Ok(resp))
    }
}

/// clonable handler
#[derive(Debug, Clone)]
pub struct TlsService {
    inner: Arc<TlsServiceInner>,
}

#[derive(Debug)]
struct TlsServiceInner {
    cred_path: PathBuf,
    // table of registered domains in the proxy
    peers: UpstreamMap,
    // in memory cache
    certs: Mutex<HashMap<Domain, (CertChainPem, KeyPem)>>,
    pending_challenges: Mutex<HashMap<AcmeToken, KeyAuthorization>>,

    config: Arc<ServerConfig>,
    resolver: Arc<Resolver>,
}

impl TlsService {
    pub fn init(cred_path: impl Into<PathBuf>, peers: UpstreamMap) -> Result<Self> {
        let path = cred_path.into();

        debug!("initializing TLS Service");
        debug!(path = %path.display());
        debug!(%peers);

        // Build TLS configuration.

        // this should crash the program if called twice
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .map_err(|_| anyhow!("error when setting default crypto provider"))?;

        let resolver = Arc::new(Resolver::new());
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone());

        // Enable ALPN protocols to support both HTTP/2 and HTTP/1.1
        server_config.alpn_protocols =
            vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];

        Ok(TlsService {
            inner: Arc::new(TlsServiceInner {
                cred_path: path,
                peers,
                certs: Mutex::new(HashMap::new()),
                pending_challenges: Mutex::new(HashMap::new()),

                resolver,
                config: Arc::new(server_config),
            }),
        })
    }

    /// check for expired certificates
    fn check_certs(&self) -> Option<Vec<Domain>> {
        debug!("checking certs");

        let guard = self.inner.certs.lock();

        let expired_domains: Vec<_> = guard
            .iter()
            .filter(|e| should_renew(&e.1.0))
            .map(|e| e.0.clone())
            .collect();

        if !expired_domains.is_empty() {
            debug!(?expired_domains, "expired certs found");
            Some(expired_domains)
        } else {
            None
        }
    }

    /// checks the peer list to see if we have a certificate
    fn check_new_domains(&self) -> Option<Vec<Domain>> {
        debug!("checking for new domains");

        let guard = self.inner.certs.lock();

        let new_domains: Vec<_> = self
            .inner
            .peers
            .get_domains()
            .filter(|d| !guard.contains_key(*d))
            .cloned()
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

        if is_expired(&certs) {
            return Err(anyhow!("cant register expired certificates!"));
        }

        let certs = CertificateDer::pem_slice_iter(certs.as_str().as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("could not read certificate: {e}"))?;

        let key = PrivateKeyDer::from_pem_slice(key.as_str().as_bytes())
            .map_err(|e| anyhow!("could not read key: {e}"))?;

        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let ck = CertifiedKey::from_der(certs, key, &provider)?;

        self.inner.resolver.add(domain, ck)?;
        Ok(())
    }

    pub fn get_acceptor(&self) -> TlsAcceptor {
        TlsAcceptor::from(self.inner.config.clone())
    }
}

async fn acme_test_acc() -> Result<Account> {
    let acc = NewAccount {
        contact: &["test@email.com"],
        terms_of_service_agreed: true,
        only_return_existing: false,
    };

    let certs = CertificateDer::pem_file_iter("pebble/test/certs/pebble.minica.pem")?
        .collect::<Result<Vec<_>, _>>()?;

    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(certs);

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_only()
        .enable_http1()
        .build();

    let client = Box::new(
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(connector),
    );

    let acc = Account::builder_with_http(client)
        .create(&acc, LetsEncrypt::Production.url().to_string(), None)
        .await?;

    Ok(acc.0)
}

async fn get_acme_acc(cred_path: &Path) -> Result<Account> {
    let path = Path::new(cred_path).join("account");
    let config = bincode::config::standard();

    if path.exists() {
        info!("retrieving ACME acc credentials from file");

        if let Ok(file) = tokio::fs::read(&path)
            .await
            .inspect_err(|e| error!(%e, "couldnt retrieve acc credentials from disk"))
        {
            let (creds, _) = bincode::serde::decode_from_slice::<AccountCredentials, Configuration>(
                &file, config,
            )?;

            let acc = Account::builder()?.from_credentials(creds).await?;

            return Ok(acc);
        };
    }

    info!("requesting new ACME account");

    // we have to get a new account
    let (account, creds) = Account::builder()?
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
        .await?;

    let data = bincode::serde::encode_to_vec::<AccountCredentials, Configuration>(creds, config)?;
    tokio::fs::write(path, data).await?;

    Ok(account)
}

async fn acme_worker(store: TlsService) {
    let account = get_acme_acc(&store.inner.cred_path).await.unwrap();
    let mut timer = tokio::time::interval(Duration::from_hours(CHECK_INTERVAL_HOURS));

    loop {
        timer.tick().await;

        // TODO: some sort watcher channel for newly added domains when the server is running

        if let Some(domains) = store.check_new_domains() {
            let _ = issue_order(store.clone(), &account, &domains)
                .await
                .inspect_err(|e| error!(%e, "ACME error"));
        }

        if let Some(domains) = store.check_certs() {
            let _ = issue_order(store.clone(), &account, &domains)
                .await
                .inspect_err(|e| error!(%e, "ACME error"));
        }
    }
}

fn should_renew(cert_pem: &CertChainPem) -> bool {
    let (_, pem) = parse_x509_pem(cert_pem.as_str().as_bytes()).unwrap();
    let cert = pem.parse_x509().unwrap();

    let not_after = cert.validity().not_after.timestamp();
    let now = OffsetDateTime::now_utc().unix_timestamp();

    let threshhold = not_after - RENEWAL_THRESHHOLD;

    now >= threshhold
}

fn is_expired(cert_pem: &CertChainPem) -> bool {
    let (_, pem) = parse_x509_pem(cert_pem.as_str().as_bytes()).unwrap();
    let cert = pem.parse_x509().unwrap();

    let not_after = cert.validity().not_after.timestamp();
    let now = OffsetDateTime::now_utc().unix_timestamp();

    now >= not_after
}

/// Something that resolves do different cert chains/keys based
/// on client-supplied server name (via SNI).
#[derive(Debug)]
pub struct Resolver {
    inner: Mutex<HashMap<String, Arc<sign::CertifiedKey>>>,
}

impl Resolver {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Add a new `sign::CertifiedKey` to be used for the given SNI `name`.
    ///
    /// This function fails if `name` is not a valid DNS name, or if
    /// it's not valid for the supplied certificate, or if the certificate
    /// chain is syntactically faulty.
    pub fn add(&self, name: &Domain, ck: sign::CertifiedKey) -> Result<(), rustls::Error> {
        let server_name = {
            let checked_name = DnsName::try_from(name.as_str())
                .map_err(|_| rustls::Error::General("Bad DNS name".into()))
                .map(|name| name.to_lowercase_owned())?;
            ServerName::DnsName(checked_name)
        };

        // Check the certificate chain for validity:
        // - it should be non-empty list
        // - the first certificate should be parsable as a x509v3,
        // - the first certificate should quote the given server name
        //   (if provided)
        //
        // These checks are not security-sensitive.  They are the
        // *server* attempting to detect accidental misconfiguration.

        ck.end_entity_cert()
            .and_then(ParsedCertificate::try_from)
            .and_then(|cert| verify_server_name(&cert, &server_name))?;

        if let ServerName::DnsName(name) = server_name {
            self.inner
                .lock()
                .insert(name.as_ref().to_string(), Arc::new(ck));
        }
        Ok(())
    }
}

impl server::ResolvesServerCert for Resolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<sign::CertifiedKey>> {
        if let Some(name) = client_hello.server_name() {
            self.inner.lock().get(name).cloned()
        } else {
            // This kind of resolver requires SNI
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use hyper::server::conn::http1::Builder;
    use hyper_util::rt::TokioIo;
    use hyper_util::service::TowerToHyperService;
    use rcgen::{BasicConstraints, CertifiedIssuer, DistinguishedName, DnType, IsCa, KeyPair};
    use std::{fs, os::unix::net::SocketAddr as UdsSocketAddr};
    use tokio::io::AsyncWriteExt;
    use tracing_subscriber::EnvFilter;

    use super::*;

    fn test_certs() -> anyhow::Result<()> {
        let ca_key = KeyPair::generate()?;
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, "Pebble CA".to_owned());
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.distinguished_name = distinguished_name;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        let issuer = CertifiedIssuer::self_signed(ca_params, ca_key)?;
        fs::write("testdata/ca.pem", issuer.as_ref().pem())?;

        let ee_key = KeyPair::generate()?;
        fs::write("testdata/server.key", ee_key.serialize_pem())?;

        let mut ee_params = rcgen::CertificateParams::new([
            "localhost".to_owned(),
            "127.0.0.1".to_owned(),
            "::1".to_owned(),
        ])?;
        ee_params.distinguished_name = DistinguishedName::new();
        let ee_cert = ee_params.signed_by(&ee_key, &issuer)?;
        fs::write("testdata/server.pem", ee_cert.pem())?;

        Ok(())
    }

    #[tokio::test]
    async fn acme_test() -> Result<()> {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .or_else(|_| EnvFilter::try_new("proxy=error,tower_http=warn"))?,
            )
            .init();

        let addr = "127.0.0.1:4000";
        let cred_path = "credentials/";

        let domains = UpstreamMap::new(&[
            // (
            //     Domain::parse("darius.dev").unwrap(),
            //     PeerAddr::Uds(UdsSocketAddr::from_pathname("/tmp/darius_dev.sock").unwrap()),
            // ),
            (
                Domain::parse("RezaDarius.de").unwrap(),
                PeerAddr::Uds(UdsSocketAddr::from_pathname("/tmp/darius_art.sock").unwrap()),
            ),
        ]);

        let listener = tokio::net::TcpListener::bind(addr).await?;
        let tls = TlsService::init(cred_path, domains).unwrap();
        let service = TowerToHyperService::new(AcmeService::new(tls.clone()));

        info!("test ACME server listening on 127.0.0.1");

        while let Ok((con, _)) = listener.accept().await {
            if is_tls(&con).await {
                let acceptor = tls.get_acceptor();
                let mut s = acceptor.accept(con).await?;
                s.write_all(b"HTTP/1.1 200 OK\r\n").await?;
                continue;
            }

            let stream = TokioIo::new(con);
            let builder = Builder::new();
            builder.serve_connection(stream, service.clone()).await?;
        }
        Ok(())
    }
}
