use std::{
    collections::HashSet,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use http::Version;
use serde::Deserialize;
use tap::Pipe;
use tracing::{debug, error, info, instrument, warn};

use crate::{
    cli::RunArgs,
    ctrl::SD_CTRL_SOCK_PATH,
    utils::{Domain, Peer, PeerAddr},
};

const PORTO_CONFIG_ENV: &str = "PORTO_CONFIG";
pub const CONFIG_FILENAME: &str = "porto.toml";
pub const CONFIG_FOLDER: &str = "/etc/porto";
pub const TMPL_CFG_URL: &str =
    "https://raw.githubusercontent.com/Reza-Darius/porto/main/scripts/help_porto.toml";

#[derive(Debug, Deserialize, Default)]
pub struct PortoConfig {
    pub global: GlobalSettings,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    proxy: Vec<ProxyConfig>,

    /// these settings arent exposed to the user
    #[serde(skip)]
    pub internal: InternalSettings,
}

#[derive(Debug)]
pub struct InternalSettings {
    pub ctrl_sock_path: PathBuf,
}

impl Default for InternalSettings {
    fn default() -> Self {
        Self {
            ctrl_sock_path: SD_CTRL_SOCK_PATH.into(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct GlobalSettings {
    pub bind: Option<SocketAddr>,
    pub limit: bool,
}

#[derive(Debug, Deserialize)]
pub struct RateLimitSettings {
    pub bucket_size: u16,
    pub refill_amount: u16,
    pub refill_interval: Duration,
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

    pub fn has_proxies(&self) -> bool {
        !self.proxy.is_empty()
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
                "TLS set to true, but no cert or key path provided. If you wish to not use TLS set \"tls = false\" inside the config under [global]."
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
#[instrument(skip_all)]
pub fn setup_config(cli_args: Option<&RunArgs>) -> Result<PortoConfig> {
    if let Some(cli) = cli_args {
        let path = search_config_path(cli.config.as_deref())?;

        let mut config = parse_config_file(path)?;

        // cli overwrites config
        if let Some(addr) = cli.addr {
            config.global.bind = Some(addr);
        }

        if config.global.bind.is_none() {
            if config.tls.enabled {
                config.global.bind =
                    Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 443))
            } else {
                config.global.bind =
                    Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 80))
            }
        }

        if cli.debug {
            let sock_path = PathBuf::from("/tmp/porto-debug.sock");
            if sock_path.exists() {
                std::fs::remove_file(&sock_path)?;
            }
            config.internal.ctrl_sock_path = sock_path;
        }

        info!(
            "attempting to bind to {}",
            config
                .global
                .bind
                .expect("something is there at this point")
        );

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
            "config error: no proxy provided! Configure at least one proxy"
        ));
    }

    if contains_duplicates(&config.proxy) {
        return Err(anyhow!("config error: duplicate proxy entires"));
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

pub fn open_config_editor(path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();

    if !path.exists() {
        return Err(anyhow!(
            "no config found, if you wish to restore the starter config run: sudo -E porto config -i"
        ));
    }

    let status = Command::new("sudoedit").arg(path).status()?;

    if !status.success() {
        return Err(anyhow!("failed to open editor"));
    }

    Ok(())
}

pub async fn write_tmpl_config(path: impl AsRef<Path>) -> Result<()> {
    let config = reqwest::get(TMPL_CFG_URL).await?.text().await?;
    fs::write(&path, config)?;

    println!("new config at: {}", path.as_ref().display());
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
