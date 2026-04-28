use std::{net::SocketAddr, path::PathBuf};

use anyhow::Result;
use clap::Parser;
use serde::Deserialize;
use tap::Pipe;
use tracing::{debug, info};

use crate::utils::{Domain, PeerAddr};

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// Addr and port for Porto to listen on
    #[arg(short, long)]
    addr: Option<SocketAddr>,

    /// Sets a custom config file
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
pub struct PortoConfig {
    bind: SocketAddr,
    tls: bool,
    acme: bool,
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
}

const CONFIG_FILENAME: &str = "porto.toml";

fn setup_config_with_args(args: Cli) -> Result<PortoConfig> {
    let config_path = args.config.unwrap_or_else(|| PathBuf::from("."));

    debug!("loading config from {}", config_path.display());

    let mut config: PortoConfig = config_path
        .join(CONFIG_FILENAME)
        .pipe(std::fs::read)?
        .pipe_as_ref(toml::from_slice)?;

    if let Some(addr) = args.addr {
        config.bind = addr;
    }

    Ok(config)
}

pub fn setup_config() -> Result<PortoConfig> {
    let args = Cli::parse();
    setup_config_with_args(args)
}

#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn config_test() {
        let args = Cli {
            addr: None,
            config: None,
        };

        let config = setup_config_with_args(args).unwrap();
        assert!(config.tls);
        assert!(!config.acme);
        assert_eq!(config.proxy.len(), 2);
        println!("{:?}", config);
    }
}
