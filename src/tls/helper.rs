use std::sync::Arc;

use rustls::{ServerConfig, server::ResolvesServerCert};
use time::OffsetDateTime;
use x509_parser::certificate::X509Certificate;

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

#[inline(always)]
pub fn cert_should_renew(cert: &X509Certificate) -> bool {
    // renew in the last 1/3 of lifetime
    const RENEW_LIFETIME_FRACTION: i64 = 3;
    const MAX_RENEW_WINDOW_SECS: i64 = 30 * 24 * 60 * 60;

    let validity = cert.validity();
    let not_before = validity.not_before.timestamp();
    let not_after = validity.not_after.timestamp();
    let now = OffsetDateTime::now_utc().unix_timestamp();

    let lifetime = (not_after - not_before).max(0);
    let window = (lifetime / RENEW_LIFETIME_FRACTION).min(MAX_RENEW_WINDOW_SECS);

    now >= (not_after - window)
}
