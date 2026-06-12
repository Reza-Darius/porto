use std::{collections::HashMap, net::SocketAddr};

use anyhow::anyhow;
use reqwest::{ClientBuilder, dns::Resolve};

pub fn get_client(domains: &[&'static str], proxy_addr: SocketAddr) -> reqwest::Client {
    let resolver = TestResolver {
        map: domains.iter().map(|domain| (*domain, proxy_addr)).collect(),
    };
    ClientBuilder::new().dns_resolver(resolver).build().unwrap()
}

struct TestResolver {
    map: HashMap<&'static str, SocketAddr>,
}

impl Resolve for TestResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let addr = self
            .map
            .get(name.as_str())
            .copied()
            .map(|addr| {
                let iter = std::iter::once(addr);
                let b: Box<dyn Iterator<Item = SocketAddr> + Send + 'static> = Box::new(iter);
                b
            })
            .ok_or_else(|| anyhow!("couldnt resolve domain").into_boxed_dyn_error());
        Box::pin(async move { addr })
    }
}
