use anyhow::{Context, Result, anyhow};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpSocket};
use tracing::instrument;

use tokio_rustls::TlsAcceptor;

use crate::config::{PortoConfig, TlsConfig};

pub fn setup_tracing() {
    // tracing_subscriber::fmt::init();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        // .with_target(false)
        .init();
}

#[tracing::instrument(skip_all)]
pub fn setup_tls_from_file(config: &TlsConfig) -> Result<TlsAcceptor> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let certs = config
        .cert_path
        .as_ref()
        .ok_or_else(|| anyhow!("cert path missing"))?;
    let key = config
        .key_path
        .as_ref()
        .ok_or_else(|| anyhow!("cert key missing"))?;

    // Load public certificate.
    let certs = CertificateDer::pem_file_iter(certs)
        .with_context(|| format!("could not read certificate file: {}", certs.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("could not read certificate file: {}", certs.display()))?;

    // Load private key.
    let key = PrivateKeyDer::from_pem_file(key)
        .with_context(|| format!("could not read key file: {}", key.display()))?;

    // Build TLS configuration.
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .with_context(|| "server config build error")?;

    // Enable ALPN protocols to support both HTTP/2 and HTTP/1.1
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

#[instrument(err, skip_all)]
pub fn setup_listener(config: &PortoConfig) -> Result<TcpListener> {
    let addr = config.addr();
    let socket = TcpSocket::new_v4().unwrap();

    socket.set_keepalive(true)?;
    socket.set_nodelay(true)?;
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;

    Ok(socket.listen(4096)?)
}
