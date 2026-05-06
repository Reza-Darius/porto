use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use serde::Deserialize;
use tap::Pipe;
use tracing::{debug, instrument};

use crate::utils::{Domain, PeerAddr};

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// Addr and port for Porto to listen on
    addr: Option<SocketAddr>,

    /// Sets path to a porto.toml config file
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Default)]
pub struct PortoConfig {
    pub bind: Option<SocketAddr>,
    #[serde(default = "default_tls")]
    pub tls: bool,
    #[serde(default)]
    pub auto_cert: bool,
    // for simple TLS
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    // for ACME
    pub credentials: Option<PathBuf>,
    proxy: Vec<ProxyConfig>,

    #[serde(skip)]
    pub debug: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    pub domain: Domain,
    pub upstream: PeerAddr,
    #[serde(default)]
    pub http2: bool,
}

impl PortoConfig {
    pub fn get_proxies(&self) -> impl Iterator<Item = ProxyConfig> {
        self.proxy.clone().into_iter()
    }

    pub fn get_addr(&self) -> SocketAddr {
        self.bind.expect("config parsing fails without an address")
    }
}

const CONFIG_FILENAME: &str = "porto.toml";

const fn default_tls() -> bool {
    true
}

#[instrument(err)]
pub fn setup_config() -> Result<PortoConfig> {
    let args = Cli::parse();
    let path = args
        .config
        .unwrap_or_else(|| PathBuf::from(CONFIG_FILENAME));

    let mut config = parse_config_file(path)?;

    if let Some(addr) = args.addr {
        // command line argument overwrites config
        config.bind = Some(addr);
    } else if config.bind.is_none() {
        return Err(anyhow!(
            "No listening address provided! Either pass a address as argument or set \"bind = [ADDR]\" inside the config"
        ));
    }

    Ok(config)
}

fn parse_config_file(path: impl AsRef<Path>) -> Result<PortoConfig> {
    debug!("loading config from \"{}\"", path.as_ref().display());

    let mut config: PortoConfig = path
        .as_ref()
        .pipe(std::fs::read)
        .with_context(|| anyhow!("path: {}", path.as_ref().display()))?
        .pipe_as_ref(toml::from_slice)?;

    if config.tls && (config.cert_path.is_none() || config.key_path.is_none()) {
        return Err(anyhow!(
            "TLS set to true, but no cert or key path provided. If you wish to not use TLS pass \"tls = false\" inside the config"
        ));
    }

    // we cant have acme enabled and tls disabled, set both to disabled
    if config.auto_cert && !config.tls {
        config.auto_cert = false;
    }

    if config.proxy.is_empty() {
        return Err(anyhow!(
            "No upstream paths provided! Configure at least one Proxy"
        ));
    }

    Ok(config)
}

#[cfg(test)]
mod config_tests {
    use super::*;

    fn setup_test_conf(path: &Path) {
        let config = r#"
            bind = "127.0.0.1:3000"
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

        assert!(config.tls);
        assert!(!config.auto_cert);
        assert_eq!(config.proxy.len(), 2);
        println!("{:?}", config);

        let _ = std::fs::remove_file(path);
    }
}
