use anyhow::Result;
use clap::Parser;
use porto::cli::Cli;
use porto::cli::ServerCtrl;
use porto::ctrl::CtrlMsg;
use porto::ctrl::send_ctrl_msg;
use porto::server::run;
use tikv_jemallocator::Jemalloc;

use porto::config::*;
use porto::utils::*;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    setup_tracing();

    match cli.command {
        ServerCtrl::Run(run_args) => {
            let config = setup_config(Some(&run_args))?;
            run(&config).await?;
        }
        ServerCtrl::Stop => {
            let res = send_ctrl_msg(CtrlMsg::Stop).await;
            if res.is_ok() {
                println!("shutdown signal sent")
            }
        },
        ServerCtrl::Status => {
            let res = send_ctrl_msg(CtrlMsg::Status).await;
            if res.is_ok() {
                println!("server is running!")
            }
        },
    }
    Ok(())
}
