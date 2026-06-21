use anyhow::Result;
use porto::server::run;
use tikv_jemallocator::Jemalloc;

use porto::config::*;
use porto::utils::*;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> Result<()> {
    setup_tracing();
    let config = setup_config()?;
    run(&config).await?;

    Ok(())
}

