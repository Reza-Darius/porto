use anyhow::{Context, Result, anyhow};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use std::{net::SocketAddr, path::Path, sync::Arc};
use tokio::net::{TcpListener, TcpSocket};

use tokio_rustls::TlsAcceptor;

pub fn setup_tls_from_file(certs: impl AsRef<Path>, key: impl AsRef<Path>) -> Result<TlsAcceptor> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Load public certificate.
    let certs = CertificateDer::pem_file_iter(&certs)?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| {
            anyhow!(
                "could not read certificate file: {}",
                certs.as_ref().display()
            )
        })?;

    // Load private key.
    let key = PrivateKeyDer::from_pem_file(&key)
        .with_context(|| anyhow!("could not read key file: {}", key.as_ref().display()))?;

    // TODO
    // let mut resolver = ResolvesServerCertUsingSni::new();

    // Build TLS configuration.
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    // Enable ALPN protocols to support both HTTP/2 and HTTP/1.1
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(server_config)))
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
