use anyhow::Result;
use clap::Parser;
use porto::cli::Cli;
use porto::server::run;
use tikv_jemallocator::Jemalloc;

use porto::config::*;
use porto::utils::*;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> Result<()> {
    let _ = Cli::parse();
    setup_tracing();
    let config = setup_config(None)?;
    run(&config).await?;

    Ok(())
}

