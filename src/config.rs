use std::{
    collections::HashSet,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use http::Version;
use serde::Deserialize;
use tap::Pipe;
use tracing::{debug, instrument};

use crate::utils::{Domain, Peer, PeerAddr};

const CONFIG_FILENAME: &str = "porto.toml";

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// Addr and port for Porto to listen on, overrides config
    addr: Option<SocketAddr>,

    /// Sets path to the porto.toml config file.
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Default)]
pub struct PortoConfig {
    pub global: GlobalSettings,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    proxy: Vec<ProxyConfig>,
}

#[derive(Debug, Deserialize)]
pub struct GlobalSettings {
    pub bind: Option<SocketAddr>,
    pub limit: bool,
}

impl Default for GlobalSettings {
    fn default() -> Self {
        GlobalSettings {
            bind: None,
            limit: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct ProxyConfig {
    pub domain: Domain,
    pub upstream: PeerAddr,
    #[serde(default)]
    pub http2: bool,
    #[serde(default)]
    pub config: ServiceConfig,
}

impl PortoConfig {
    pub fn get_proxies(&self) -> impl Iterator<Item = Peer> {
        self.proxy.clone().into_iter().map(Into::into)
    }

    pub fn get_addr(&self) -> SocketAddr {
        self.global.bind.expect("config parsing fails without an address")
    }
}

impl From<ProxyConfig> for Peer {
    fn from(value: ProxyConfig) -> Self {
        Peer::new(
            value.domain,
            value.upstream,
            match value.http2 {
                true => Version::HTTP_2,
                false => Version::HTTP_11,
            },
            value.config,
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    #[serde(rename(deserialize = "tls"))]
    pub enabled: bool,
    pub auto_cert: bool,

    // for simple TLS
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,

    // for ACME
    pub credentials: Option<PathBuf>,

    #[serde(skip)]
    pub debug: bool, // for testing only
}

impl TlsConfig {
    pub fn validate(&mut self) -> Result<()> {
        if self.enabled && (self.cert_path.is_none() || self.key_path.is_none()) {
            return Err(anyhow!(
                "TLS set to true, but no cert or key path provided. If you wish to not use TLS pass \"tls = false\" inside the config"
            ));
        }

        // we cant have acme enabled and tls disabled, set both to disabled
        if self.auto_cert && !self.enabled {
            self.auto_cert = false;
        }

        Ok(())
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_cert: false,
            cert_path: None,
            key_path: None,
            credentials: None,
            debug: false,
        }
    }
}

/// defaults to everything enabled
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServiceConfig {
    pub health: bool,
    pub limit: bool,
    pub cache: bool,
    pub comp: bool,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        ServiceConfig {
            health: true,
            limit: true,
            cache: true,
            comp: true,
        }
    }
}

#[instrument(err)]
pub fn setup_config() -> Result<PortoConfig> {
    let args = Cli::parse();
    let path = args
        .config
        .unwrap_or_else(|| PathBuf::from(CONFIG_FILENAME));

    let mut config = parse_config_file(path)?;

    if let Some(addr) = args.addr {
        // command line argument overwrites config file
        config.global.bind = Some(addr);
    } else if config.global.bind.is_none() {
        return Err(anyhow!(
            "No listening address provided! Either pass a address as argument or set \"bind = [ADDR]\" inside the config"
        ));
    }

    Ok(config)
}

fn parse_config_file(path: impl AsRef<Path>) -> Result<PortoConfig> {
    debug!("loading config from \"{}\"", path.as_ref().display());
    let path = path.as_ref();

    let mut config: PortoConfig = path
        .pipe(std::fs::read)
        .with_context(|| anyhow!("path: {}", path.display()))?
        .pipe_as_ref(toml::from_slice)?;

    config.tls.validate()?;

    if config.proxy.is_empty() {
        return Err(anyhow!(
            "Config error: no upstream paths provided! Configure at least one Proxy"
        ));
    }

    if contains_duplicates(&config.proxy) {
        return Err(anyhow!("Config error: duplicate proxy entires"));
    }

    Ok(config)
}

fn contains_duplicates(proxies: &[ProxyConfig]) -> bool {
    let mut peers = HashSet::new();
    for proxy in proxies.iter() {
        if !peers.contains(&proxy.domain) {
            peers.insert(proxy.domain.clone());
        } else {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod config_tests {
    use super::*;

    fn setup_test_conf(path: &Path) {
        let config = r#"
            [global]
            bind = "127.0.0.1:3000"
            limit = true

            [tls]
            tls = true
            auto_cert = false
            cert_path = "credentials/example_cert.pem"
            key_path = "credentials/example_key.pem"

            [[proxy]]
            domain = "darius.dev"
            upstream = "10.0.0.0:67"

            [[proxy]]
            domain = "RezaDarius.de"
            upstream = "/tmp/darius_art.sock"

            "#;
        std::fs::write(path, config.as_bytes()).unwrap();
    }

    #[test]
    fn config_test() {
        let path = Path::new("testporto.toml");
        let _ = std::fs::remove_file(path);
        setup_test_conf(path);

        let config = parse_config_file("testporto.toml").unwrap();

        assert!(config.tls.enabled);
        assert!(!config.tls.auto_cert);
        assert_eq!(config.proxy.len(), 2);
        println!("{:?}", config);

        let _ = std::fs::remove_file(path);
    }
}
