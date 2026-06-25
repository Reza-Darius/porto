use std::{
    collections::HashSet,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, anyhow};
use http::Version;
use serde::Deserialize;
use tap::Pipe;
use tracing::{debug, error, info, instrument, warn};

use crate::{
    cli::RunArgs,
    utils::{Domain, Peer, PeerAddr},
};

const PORTO_CONFIG_ENV: &str = "PORTO_CONFIG";
pub const CONFIG_FILENAME: &str = "porto.toml";
pub const CONFIG_FOLDER: &str = "/etc/porto";

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
pub struct ProxyConfig {
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

    pub fn addr(&self) -> SocketAddr {
        self.global
            .bind
            .expect("config parsing fails without an address")
    }

    pub fn add_proxy(&mut self, proxy: ProxyConfig) {
        self.proxy.push(proxy);
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

/// parses command line arguments and the porto.toml config file
#[instrument(err)]
pub fn setup_config(cli_args: Option<&RunArgs>) -> Result<PortoConfig> {
    if let Some(cli) = cli_args {
        let path = search_config_path(cli.config.as_deref())?;

        let mut config = parse_config_file(path)?;

        // cli overwrites config
        if let Some(addr) = cli.addr {
            config.global.bind = Some(addr);
        }

        if config.global.bind.is_none() {
            // TODO: if there is no bind, bind to 0.0.0.0:80 or 443 ?
            return Err(anyhow!(
                "No listening address provided! Either pass a address as argument or set \"bind = [ADDR]\" inside the config"
            ));
        }
        Ok(config)
    } else {
        let path = search_config_path(None)?;
        parse_config_file(path)
    }
}

fn search_config_path(cli_path: Option<&Path>) -> Result<PathBuf> {
    // validate cli argument
    if let Some(p) = cli_path {
        if !p.exists() {
            return Err(anyhow!("provided path {} does not exist", p.display()));
        }
        if p.is_dir() {
            return search_directory(p).ok_or_else(|| {
                anyhow!("no porto.toml config found in directory: {}", p.display())
            });
        }
        if p.file_name().expect("we checked if its a dir") == CONFIG_FILENAME {
            return Ok(p.to_owned());
        }
        return Err(anyhow!("provided path {} is not valid", p.display()));
    }

    let env_val = std::env::var(PORTO_CONFIG_ENV);

    // fallback to CWD
    Ok(PathBuf::from(env_val.unwrap_or_else(|_| {
        warn!("no PORTO_CONFIG env variable set, searching cwd...");
        CONFIG_FILENAME.to_owned()
    })))
}

fn search_directory(path: impl AsRef<Path>) -> Option<PathBuf> {
    let path = path.as_ref();
    let iter = fs::read_dir(path)
        .inspect_err(|e| {
            error!(
                "directory iterator error {e} when searching for config for path {}",
                path.display()
            )
        })
        .ok()?;

    for entry in iter {
        let e = entry.inspect_err(|e| error!("entry error {e}")).ok()?;
        if e.file_name() == CONFIG_FILENAME {
            debug!("found config in directory");
            return Some(e.path());
        }
    }
    None
}

fn parse_config_file(path: impl AsRef<Path>) -> Result<PortoConfig> {
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

    info!("config loaded from {}", path.display());
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

pub fn write_help_config(path: impl AsRef<Path>) -> Result<()> {
    let conf = r#" 
        [global]
        # optional: address to listen on, will default to 0.0.0.0:80 or 0.0.0.0:443, depending on TLS settings
        bind = "127.0.0.1:3000"

        # enables the global rate limiter, default = true
        limit = true

        [tls]
        # toggles HTTPS, default = true
        tls = true

        # optional: enables ACME for automatic certificates, default = false
        auto_cert = false

        # if acme is disabled and tls enabled, you need to provide cert and key for TLS yourself using these settings
        # note that porto cant access user home directories, so it is recommended to place them in /etc/porto/
        cert_path = "/etc/porto/example_cert.pem"
        key_path = "/etc/porto/example_key.pem"

        # add any number of proxies
        [[proxy]]
        # proxies HTTP messages from domain to upstream
        domain = "mywebsite.com"

        # upstream support IPv4 addresses and unix domain socket paths
        upstream = "127.0.0.1:6767"

        # optional: enable HTTP2 if the backend supports it, default = false
        http2 = true
    "#;

    fs::write(path.as_ref(), conf)?;
    Ok(())
}

pub fn open_config_editor(path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();

    if !path.exists() {
        write_help_config(path)?;
    }

    let status = Command::new("sudoedit").arg(path).status()?;

    if !status.success() {
        return Err(anyhow!("failed to open editor"));
    }

    Ok(())
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
        eprintln!("{:#?}", config);

        let _ = std::fs::remove_file(path);
    }
}
