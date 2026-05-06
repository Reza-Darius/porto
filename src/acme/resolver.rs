use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use parking_lot::Mutex;
use rustls::{
    client::verify_server_name,
    pki_types::{DnsName, ServerName},
    server::{self, ClientHello, ParsedCertificate},
    sign::{self},
};
use tracing::debug;

use crate::utils::Domain;

/// Something that resolves do different cert chains/keys based
/// on client-supplied server name (via SNI).
#[derive(Debug, Default)]
pub struct Resolver {
    inner: Mutex<HashMap<String, Arc<sign::CertifiedKey>>>,
}

impl Resolver {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Add a new `sign::CertifiedKey` to be used for the given SNI `name`.
    ///
    /// This function fails if `name` is not a valid DNS name, or if
    /// it's not valid for the supplied certificate, or if the certificate
    /// chain is syntactically faulty.
    pub fn add(&self, name: &Domain, ck: sign::CertifiedKey) -> Result<(), rustls::Error> {
        let server_name = {
            let checked_name = DnsName::try_from(name.as_str())
                .map_err(|_| rustls::Error::General("Bad DNS name".into()))
                .map(|name| name.to_lowercase_owned())?;
            ServerName::DnsName(checked_name)
        };

        // Check the certificate chain for validity:
        // - it should be non-empty list
        // - the first certificate should be parsable as a x509v3,
        // - the first certificate should quote the given server name
        //   (if provided)
        //
        // These checks are not security-sensitive.  They are the
        // *server* attempting to detect accidental misconfiguration.

        ck.end_entity_cert()
            .and_then(ParsedCertificate::try_from)
            .and_then(|cert| verify_server_name(&cert, &server_name))?;

        if let ServerName::DnsName(name) = server_name {
            self.inner
                .lock()
                .insert(name.as_ref().to_string(), Arc::new(ck));
        }
        Ok(())
    }
}

impl server::ResolvesServerCert for Resolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<sign::CertifiedKey>> {
        if let Some(name) = client_hello.server_name() {
            debug!("resolving cert for {name} in ClientHello");
            self.inner.lock().get(name).cloned()
        } else {
            // This kind of resolver requires SNI
            None
        }
    }
}
