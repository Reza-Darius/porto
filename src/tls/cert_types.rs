use std::borrow::Borrow;

use anyhow::{Result, anyhow};
use derive_more::{AsRef, Display, From};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
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

    pub fn to_der(&self) -> Result<Vec<CertificateDer<'_>>> {
        CertificateDer::pem_slice_iter(self.0.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("could not read certificate: {e}"))
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

    pub fn to_der(&self) -> Result<PrivateKeyDer<'_>> {
        PrivateKeyDer::from_pem_slice(self.0.as_bytes())
            .map_err(|e| anyhow!("could not read key: {e}"))
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
