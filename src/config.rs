use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Result, anyhow};
use clap::Parser;
use serde::Deserialize;
use tap::Pipe;
use tracing::{debug, instrument};

use crate::utils::{Domain, PeerAddr};

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Addr and port for Porto to listen on
    #[arg(short, long)]
    addr: Option<SocketAddr>,

    /// Sets path to a porto.toml config file
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
pub struct PortoConfig {
    pub bind: SocketAddr,
    pub tls: bool,
    pub auto_cert: bool,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    proxy: Vec<Proxy>,
}

#[derive(Debug, Deserialize)]
struct Proxy {
    domain: Domain,
    upstream: PeerAddr,
}

impl PortoConfig {
    pub fn get_proxies(&self) -> impl Iterator<Item = (&Domain, &PeerAddr)> {
        self.proxy.iter().map(|p| (&p.domain, &p.upstream))
    }

    pub fn get_addr(&self) -> SocketAddr {
        self.bind
    }
}

const CONFIG_FILENAME: &str = "porto.toml";

#[instrument(err)]
pub fn setup_config() -> Result<PortoConfig> {
    let args = Args::parse();
    let path = args
        .config
        .unwrap_or_else(|| PathBuf::from(CONFIG_FILENAME));

    let mut config = parse_config_file(path)?;

    // command line argument overwrites config
    if let Some(addr) = args.addr {
        config.bind = addr;
    }
    Ok(config)
}

fn parse_config_file(path: impl AsRef<Path>) -> Result<PortoConfig> {
    debug!("loading config from {}", path.as_ref().display());

    let mut config: PortoConfig = path
        .as_ref()
        .pipe(std::fs::read)?
        .pipe_as_ref(toml::from_slice)?;

    if config.tls && (config.cert_path.is_none() || config.key_path.is_none()) {
        return Err(anyhow!("TLS set to true, but no cert or key path provided"));
    }

    // we cant have acme enabled and tls disabled, set both to disabled
    if config.auto_cert && !config.tls {
        config.auto_cert = false;
    }

    if config.proxy.is_empty() {
        return Err(anyhow!("no proxy paths provided"));
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
