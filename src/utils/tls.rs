use std::borrow::Borrow;

use derive_more::{AsRef, Display, From};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::net::TcpStream;
use x509_parser::pem::parse_x509_pem;

/// checks for client hello
pub async fn is_tls(stream: &TcpStream) -> bool {
    let mut peek_buf = [0u8; 1];
    match stream.peek(&mut peek_buf).await {
        // a https "client hello" starts with 0x16
        Ok(1) => peek_buf[0] == 0x16,
        _ => false,
    }
}

const RENEWAL_THRESHOLD_DAYS: i64 = 30;
const RENEWAL_THRESHHOLD: i64 = 60 * 60 * 24 * RENEWAL_THRESHOLD_DAYS;

/// PEM encoded certificate chain
#[derive(Debug, Clone, Display, Hash, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CertChainPem(String);

impl CertChainPem {
    pub fn from_string(str: impl Into<String>) -> Self {
        CertChainPem(str.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn should_renew(&self) -> bool {
        let (_, pem) = parse_x509_pem(self.as_str().as_bytes()).unwrap();
        let cert = pem.parse_x509().unwrap();

        let not_after = cert.validity().not_after.timestamp();
        let now = OffsetDateTime::now_utc().unix_timestamp();

        let threshhold = not_after - RENEWAL_THRESHHOLD;

        now >= threshhold
    }

    pub fn is_expired(&self) -> bool {
        let (_, pem) = parse_x509_pem(self.as_str().as_bytes()).unwrap();
        let cert = pem.parse_x509().unwrap();

        let not_after = cert.validity().not_after.timestamp();
        let now = OffsetDateTime::now_utc().unix_timestamp();

        now >= not_after
    }
}

/// PEM encoded certificate key
#[derive(Debug, Clone, Display, Hash, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyPem(String);

impl KeyPem {
    pub fn from_string(str: impl Into<String>) -> Self {
        KeyPem(str.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// ACME token for HTTP1 challenge
#[derive(Debug, Clone, AsRef, Display, Hash, Eq, PartialEq, PartialOrd, Ord, From)]
pub struct AcmeToken(String);

impl AcmeToken {
    pub fn from_string(str: impl Into<String>) -> Self {
        AcmeToken(str.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for AcmeToken {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}
