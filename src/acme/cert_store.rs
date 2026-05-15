use std::{collections::HashMap, path::Path, sync::Arc};

use anyhow::Result;
use parking_lot::{MappedMutexGuard, Mutex, MutexGuard};
use tracing::debug;
use x509_parser::prelude::{GeneralName, X509Certificate};

use crate::{
    acme::{CERT_FILENAME, KEY_FILENAME, helper::read_pem_file},
    utils::{CertChainPem, Domain, KeyPem},
};

pub struct CertStore {
    inner: Arc<CertStoreInner>,
}

pub struct CertStoreInner {
    map: Mutex<HashMap<Domain, (CertChainPem, KeyPem)>>,
}

impl CertStore {
    pub fn new() -> Self {
        CertStore {
            inner: Arc::new(CertStoreInner {
                map: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// this will clone every cert and key, TODO: Cert IDs with a seperate map
    pub fn put(&self, domains: impl Iterator<Item = Domain>, cert: CertChainPem, key: KeyPem) {
        let mut guard = self.inner.map.lock();
        for domain in domains {
            guard.insert(domain, (cert.clone(), key.clone()));
        }
    }

    pub fn get(&self, domain: &Domain) -> Option<MappedMutexGuard<'_, (CertChainPem, KeyPem)>> {
        MutexGuard::try_map(self.inner.map.lock(), |map| map.get_mut(domain)).ok()
    }

    /// check for expired certificates inside the in-memory cache
    ///
    /// this function runs in O(n) time
    pub fn check_for_expired(&self) -> Option<Vec<Domain>> {
        debug!("checking certs");

        let guard = self.inner.map.lock();

        let expired_domains: Vec<_> = guard
            .iter()
            .filter(|e| e.1.0.should_renew())
            .map(|e| e.0.clone())
            .collect();

        if !expired_domains.is_empty() {
            debug!(?expired_domains, "expired certs found");
            Some(expired_domains)
        } else {
            None
        }
    }

    fn load_certs_from_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        debug!(?path, "loading certs from file");

        // TODO: read existing certs from file and map them to domains

        let cert_pem = read_pem_file(path.join(CERT_FILENAME))?;
        let cert = cert_pem.parse_x509()?;

        let key_pem = read_pem_file(path.join(KEY_FILENAME))?;

        debug!(issuer = %cert.issuer(), "found certificate");

        todo!()
    }
}

// fn domains(cert: &X509Certificate) -> Vec<&str> {
//     cert.subject_alternative_name()
//         .into_iter()
//         .flat_map(|san| san.value.general_names.iter())
//         .filter_map(|name| match name {
//             GeneralName::DNSName(dns) => Some(dns),
//             _ => None,
//         })
//         .collect()
// }
