use std::{path::Path, sync::Arc};

use anyhow::{Result, anyhow};
use rustls::{ServerConfig, server::ResolvesServerCert};
use tap::Pipe;
use time::OffsetDateTime;
use x509_parser::pem::{Pem, parse_x509_pem};

use crate::{acme::RENEWAL_THRESHHOLD, utils::CertChainPem};

pub fn should_renew(cert_pem: &CertChainPem) -> bool {
    let (_, pem) = parse_x509_pem(cert_pem.as_str().as_bytes()).unwrap();
    let cert = pem.parse_x509().unwrap();

    let not_after = cert.validity().not_after.timestamp();
    let now = OffsetDateTime::now_utc().unix_timestamp();

    let threshhold = not_after - RENEWAL_THRESHHOLD;

    now >= threshhold
}

pub fn is_expired(cert_pem: &CertChainPem) -> bool {
    let (_, pem) = parse_x509_pem(cert_pem.as_str().as_bytes()).unwrap();
    let cert = pem.parse_x509().unwrap();

    let not_after = cert.validity().not_after.timestamp();
    let now = OffsetDateTime::now_utc().unix_timestamp();

    now >= not_after
}

pub fn read_pem_file(path: impl AsRef<Path>) -> Result<Pem> {
    path.as_ref()
        .pipe(|path| {
            if path.exists() {
                Ok(path)
            } else {
                Err(anyhow!("couldnt find {}", path.display()))
            }
        })?
        .pipe(std::fs::read)?
        .pipe_as_ref(|file| parse_x509_pem(file).map(|(_, pem)| pem))
        .map_err(|e| anyhow!("{e}"))
}

pub fn setup_rustls_config(resolver: Arc<impl ResolvesServerCert + 'static>) -> ServerConfig {
    // this should crash the program if called twice
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("this can crash the program if called twice which should never happen");

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    // Enable ALPN protocols to support both HTTP/2 and HTTP/1.1
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];

    server_config
}
