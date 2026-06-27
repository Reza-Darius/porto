use std::{net::SocketAddr, path::PathBuf};

use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: ServerCtrl,
}

#[derive(Subcommand)]
pub enum ServerCtrl {
    /// Starts the Porto proxy, it's generally recommended to start the proxy via "systemctl start porto"
    Start(RunArgs),
    /// Stops a running proxy
    Stop,
    /// Retrieve the status of a running Porto proxy
    Status,
    /// uninstalls porto
    Remove,
    /// opens the config file for editing, uses the editor from the $EDITOR env variable
    Config(ConfigCmdArgs),
}

#[derive(Args, Debug)]
pub struct RunArgs {
    /// Addr and port for Porto to listen on, overrides config file
    pub addr: Option<SocketAddr>,

    /// Sets path to the porto.toml config file.
    #[arg(short, long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Starts the server in the background
    #[arg(short, default_value_t = false)]
    pub background: bool,

    /// Runs Porto in debug mode
    #[arg(short, default_value_t = false)]
    pub debug: bool,
}

#[derive(Args, Debug)]
pub struct ConfigCmdArgs {
    /// initializes a config template
    #[arg(short, default_value_t = false)]
    pub init: bool
}

