use std::{collections::HashMap, path::PathBuf, sync::Arc};

use anyhow::Result;
use anyhow::anyhow;
use parking_lot::Mutex;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::pem::PemObject;
use rustls::sign::CertifiedKey;
use rustls::{
    client::verify_server_name,
    pki_types::{CertificateDer, DnsName, ServerName},
    server::{self, ClientHello, ParsedCertificate},
    sign::{self},
};
use tracing::debug;
use x509_parser::nom::AsBytes;
use x509_parser::parse_x509_certificate;

use crate::tls::helper::cert_should_renew;
use crate::{
    tls::cert_types::{CertChainPem, KeyPem},
    utils::Domain,
};

/// Something that resolves do different cert chains/keys based
/// on client-supplied server name (via SNI).
#[derive(Debug, Default)]
pub struct CertStore {
    cert_path: PathBuf,
    key_path: PathBuf,
    map: Mutex<HashMap<Domain, Arc<sign::CertifiedKey>>>,
}

impl CertStore {
    pub fn new(cert_path: impl Into<PathBuf>, key_path: impl Into<PathBuf>) -> Self {
        Self {
            cert_path: cert_path.into(),
            key_path: key_path.into(),
            map: Mutex::new(HashMap::new()),
        }
    }

    pub fn store(
        &self,
        domains: impl Iterator<Item = Domain>,
        cert: CertChainPem,
        key: KeyPem,
    ) -> Result<()> {
        let mut map = self.map.lock();

        let certs_der = CertificateDer::pem_slice_iter(cert.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("could not read certificate: {e}"))?;

        let key_der = PrivateKeyDer::from_pem_slice(key.as_bytes())
            .map_err(|e| anyhow!("could not read key: {e}"))?;

        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let ck = Arc::new(CertifiedKey::from_der(certs_der, key_der, &provider)?);

        self.add_to_resolver(domains, ck.clone(), &mut map)?;

        // OPTIMIZE: better file handling down the line
        std::fs::write(&self.cert_path, cert.as_bytes())?;
        std::fs::write(&self.key_path, key.as_bytes())?;

        Ok(())
    }

    /// check for expired certificates and returns the corresponding domains
    pub fn check_for_expired(&self) -> Option<Vec<Domain>> {
        debug!("checking for renewing certs");

        // OPTIMIZE: come up with a better data structure to reduce redundant checks
        let guard = self.map.lock();
        let expired_domains = guard
            .iter()
            .filter_map(|entry| {
                needs_renewal(
                    entry
                        .1
                        .cert
                        .first()
                        .expect("we always need to have a leaf cert"),
                )
                .then_some(entry.0.clone())
            })
            .collect::<Vec<_>>();

        if !expired_domains.is_empty() {
            debug!(?expired_domains, "expired certs found");
            Some(expired_domains)
        } else {
            None
        }
    }

    pub fn init_from_disk(&self) -> Result<()> {
        debug!(cert_path = %self.cert_path.display(), key_path = %self.key_path.display(), "loading certs from disk");
        let mut map = self.map.lock();

        let certs = CertificateDer::pem_file_iter(&self.cert_path)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("could not read certificate: {e}"))?;
        let key = PrivateKeyDer::from_pem_file(&self.key_path)
            .map_err(|e| anyhow!("could not read key: {e}"))?;

        // retrieve domains from leaf certificate
        let leaf_cert = certs.first().ok_or_else(|| anyhow!("no cert found"))?;
        let domains = domain_from_cert(leaf_cert)?;

        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let ck = Arc::new(CertifiedKey::from_der(certs, key, &provider)?);

        self.add_to_resolver(domains.into_iter(), ck.clone(), &mut map)?;
        Ok(())
    }

    /// Add a new `sign::CertifiedKey` to be used for the given SNI `name`.
    ///
    /// This function fails if `name` is not a valid DNS name, or if
    /// it's not valid for the supplied certificate, or if the certificate
    /// chain is syntactically faulty.
    fn add_to_resolver(
        &self,
        domains: impl Iterator<Item = Domain>,
        ck: Arc<sign::CertifiedKey>,
        map: &mut HashMap<Domain, Arc<CertifiedKey>>
    ) -> Result<()> {
        // Check the certificate chain for validity:
        // - it should be non-empty list
        // - the first certificate should be parsable as a x509v3,
        // - the first certificate should quote the given server name
        //   (if provided)
        //
        // These checks are not security-sensitive.  They are the
        // *server* attempting to detect accidental misconfiguration.

        let domains = domains.collect::<Vec<_>>();
        if domains.is_empty() {
            return Err(anyhow!("domains list is empty"))
        }

        // end-entity cert = leaf cert
        let leaf_cert = ck.end_entity_cert().and_then(ParsedCertificate::try_from)?;

        for domain in domains.iter() {
            verify_server_name(&leaf_cert, &domain.as_server_name())?;
        }

        for domain in domains {
            debug!(%domain, "adding to resolver");
            map.insert(domain, ck.clone());
        }
        Ok(())
    }
}

impl server::ResolvesServerCert for CertStore {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<sign::CertifiedKey>> {
        if let Some(name) = client_hello.server_name() {
            debug!("resolving cert for {name} in ClientHello");
            self.map.lock().get(name).cloned()
        } else {
            // This kind of resolver requires SNI
            None
        }
    }
}

// pancs if the cert cant be parsed
fn needs_renewal(cert: &CertificateDer) -> bool {
    let (_, cert) = parse_x509_certificate(cert.as_bytes()).unwrap();
    cert_should_renew(cert)
}

fn domain_from_cert(cert: &CertificateDer<'_>) -> Result<Vec<Domain>> {
    let (_, cert) = parse_x509_certificate(cert.as_ref())?;

    // for modern TLS we use the subject alternative name (SAN) instead of the common name (CN)
    let san = cert
        .subject_alternative_name()?
        .ok_or_else(|| anyhow!("no SAN name found"))?;

    let domains = san
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            // wildcard certs can appear here
            x509_parser::extensions::GeneralName::DNSName(name) => {
                // TODO: better handling here, this is fine for getting the correctness right for now
                Some(Domain::parse(name).expect("parsing error when getting domain from cert"))
            }
            _ => None,
        })
        .collect::<Vec<_>>();

    if domains.is_empty() {
        return Err(anyhow!("couldnt extract any domain name from certificate"));
    }

    Ok(domains)
}

#[cfg(test)]
mod test {
    use crate::utils::Domain;

    #[test]
    fn dns_name_parsing() {
        let a = "*.foo.bar";
        let b = "foo.bar";
        assert!(Domain::parse(a).is_err());
        assert!(Domain::parse(b).is_ok());
    }
}
