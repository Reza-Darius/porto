use std::borrow::Borrow;

use derive_more::{AsRef, Display, From};
use serde::{Deserialize, Serialize};
use x509_parser::pem::parse_x509_pem;

use crate::tls::helper::cert_should_renew;

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

        cert_should_renew(cert)
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
