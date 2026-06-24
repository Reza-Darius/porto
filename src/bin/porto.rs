use anyhow::Result;
use clap::Parser;
use porto::cli::Cli;
use porto::cli::ServerCtrl;
use porto::ctrl::CtrlMsg;
use porto::ctrl::send_ctrl_msg;
use porto::server::run;
use porto::setup::setup_tracing;
use tikv_jemallocator::Jemalloc;

use porto::config::*;
use tracing::error;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    setup_tracing();

    match cli.command {
        ServerCtrl::Start(run_args) => {
            let config = setup_config(Some(&run_args))?;
            run(&config).await?;
        }
        ServerCtrl::Stop => {
            if let Err(e) = send_ctrl_msg(CtrlMsg::Stop).await {
                error!("{:#}", e);
                std::process::exit(-1);
            };
            println!("shutdown signal sent")
        }
        ServerCtrl::Status => {
            let res = send_ctrl_msg(CtrlMsg::Status).await;
            if res.is_ok() {
                println!("server is running!")
            }
        }
    }
    Ok(())
}
