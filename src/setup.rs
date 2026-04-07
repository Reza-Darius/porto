use anyhow::{Result, anyhow};
use hyper::body::Incoming;
use hyper_util::{client::legacy::Client, rt::TokioTimer};
use hyperlocal::UnixConnector;
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::{TcpListener, TcpSocket};

use tokio_rustls::TlsAcceptor;

pub async fn setup_tls(certs: &str, key: &str) -> Result<TlsAcceptor> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Load public certificate.
    let certs = CertificateDer::pem_file_iter(certs)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("could not read certificate file: {e}"))?;

    // Load private key.
    let key = PrivateKeyDer::from_pem_file(key)
        .map_err(|e| anyhow!("could not read private key file: {e}"))?;

    // TODO
    // let mut resolver = ResolvesServerCertUsingSni::new();
    // Build TLS configuration.

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("{e}"))?;

    // Enable ALPN protocols to support both HTTP/2 and HTTP/1.1
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

pub fn setup_client() -> Client<UnixConnector, Incoming> {
    Client::builder(hyper_util::rt::TokioExecutor::new())
        .pool_idle_timeout(std::time::Duration::from_secs(30))
        .pool_timer(TokioTimer::new())
        .pool_max_idle_per_host(32) // Tune based on your backend
        .build(UnixConnector)
}

pub fn setup_listener(addr: impl Into<SocketAddr>) -> TcpListener {
    let addr = addr.into();
    let socket = TcpSocket::new_v4().unwrap();

    socket.set_keepalive(true).unwrap();
    socket.set_reuseaddr(true).unwrap();
    socket.set_nodelay(true).unwrap();
    socket.bind(addr).unwrap();

    socket.listen(4096).unwrap()
}
