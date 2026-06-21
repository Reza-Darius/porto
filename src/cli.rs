use std::{net::SocketAddr, path::PathBuf};

use clap::{Args, Subcommand, Parser};

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    command: ServerCtrl
}

#[derive(Subcommand)]
pub enum ServerCtrl {
    /// starts the portoy proxy
    Run(RunArgs),
    /// stops a running proxy
    Stop,
}

#[derive(Args)]
pub struct RunArgs {
    /// Addr and port for Porto to listen on, overrides config
    pub addr: Option<SocketAddr>,

    /// Sets path to the porto.toml config file.
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// runs the server in the background
    #[arg(short, default_value_t = false)]
    pub background: bool
}
