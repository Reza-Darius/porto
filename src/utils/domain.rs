use std::borrow::Borrow;
use std::fmt::{Debug, Display};
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use rustls::pki_types::{DnsName, ServerName};
use serde::Deserialize;

/// Represents a valid DNS name normalized to lower case
#[derive(Clone)]
pub struct Domain(Arc<DnsName<'static>>);

impl Display for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Debug for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Self as Display>::fmt(self, f)
    }
}

// rustls uses special hashing for dnsname, which we circumvent to hash against standard strings
impl std::hash::Hash for Domain {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // must match <str as Hash>::hash for Borrow<str> to be sound
        self.as_str().hash(state)
    }
}

impl PartialEq for Domain {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for Domain {}

// normalizing deserialization to lowercase
impl<'de> Deserialize<'de> for Domain {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Domain::parse(s).map_err(serde::de::Error::custom)
    }
}

impl Domain {
    pub fn parse(domain: impl AsRef<str>) -> Result<Self> {
        let domain = domain.as_ref();
        let dns = DnsName::try_from(domain)
            .map_err(|e| anyhow!("invalid DNS name {domain:?}: {e}"))?
            .to_lowercase_owned();
        Ok(Domain(Arc::from(dns)))
    }

    pub fn as_str(&self) -> &str {
        self.0.deref().as_ref()
    }

    /// helper conversion function for rustls
    pub fn as_server_name(&self) -> ServerName<'_> {
        ServerName::DnsName(self.0.deref().borrow())
    }
}

impl FromStr for Domain {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::prelude::v1::Result<Self, Self::Err> {
        let dns = DnsName::try_from(s)
            .map_err(|e| anyhow!("invalid DNS name {s:?}: {e}"))?
            .to_lowercase_owned();
        Ok(Domain(Arc::from(dns)))
    }
}

impl AsRef<str> for Domain {
    fn as_ref(&self) -> &str {
        self.0.deref().as_ref()
    }
}

impl Borrow<str> for Domain {
    fn borrow(&self) -> &str {
        self.0.deref().as_ref()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn domain_borrow_str_lookup() -> anyhow::Result<()> {
        use std::collections::HashMap;

        let mut m: HashMap<Domain, u32> = HashMap::new();
        m.insert(Domain::parse("Example.com")?, 1);

        assert_eq!(m.get("example.com"), Some(&1));
        assert_eq!(m.get("Example.com"), None); // &str is not case-folded
        Ok(())
    }

    #[test]
    fn domain_hash_matches_str() {
        use std::hash::{BuildHasher, RandomState};
        let s = RandomState::new();
        let d = Domain::parse("Example.com").unwrap();
        assert_eq!(s.hash_one(&d), s.hash_one("example.com"));
    }
}

