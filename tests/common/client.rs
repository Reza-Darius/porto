use std::{collections::HashSet, net::SocketAddr};

use anyhow::anyhow;
use axum::BoxError;
use reqwest::{ClientBuilder, dns::Resolve};

/// provided address names resolve to proxy addr
pub fn get_client(domains: &[&'static str], proxy_addr: SocketAddr) -> reqwest::Client {
    let resolver = TestResolver {
        proxy: proxy_addr,
        set: domains.iter().copied().collect(),
    };
    ClientBuilder::new().dns_resolver(resolver).build().unwrap()
}

struct TestResolver {
    proxy: SocketAddr,
    set: HashSet<&'static str>,
}

impl Resolve for TestResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let b: Result<Box<dyn Iterator<Item = SocketAddr> + Send + 'static>, BoxError> =
            if self.set.contains(name.as_str()) {
                Ok(Box::new(std::iter::once(self.proxy)))
            } else {
                Err(anyhow!("couldnt resolve {:?}", name).into_boxed_dyn_error())
            };
        Box::pin(async move { b })
    }
}
