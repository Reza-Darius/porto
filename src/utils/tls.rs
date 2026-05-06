use std::borrow::Borrow;

use derive_more::{AsRef, Display, From};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;

pub async fn is_tls(stream: &TcpStream) -> bool {
    let mut peek_buf = [0u8; 1];
    match stream.peek(&mut peek_buf).await {
        // a https "client hello" starts with 0x16
        Ok(1) => peek_buf[0] == 0x16,
        _ => false,
    }
}

#[derive(Debug, Clone, Display, Hash, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CertChainPem(String);

impl CertChainPem {
    pub fn from_str(str: impl Into<String>) -> Self {
        CertChainPem(str.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Display, Hash, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyPem(String);

impl KeyPem {
    pub fn from_str(str: impl Into<String>) -> Self {
        KeyPem(str.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, AsRef, Display, Hash, Eq, PartialEq, PartialOrd, Ord, From)]
pub struct AcmeToken(String);

impl AcmeToken {
    pub fn from_str(str: impl Into<String>) -> Self {
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
